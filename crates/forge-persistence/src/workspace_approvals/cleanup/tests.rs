use std::fs;

use forge_domain::{
    ActivityId, ApprovalRequestId, ApprovalRequestState, ApprovalRevision, AutoApprovalScope,
    AutoApprovalScopeId, AutoApprovalScopeRevision, AutoApprovalScopeState, AutoApprovalUseLimit,
    ExecutionActionClass, ExecutionAuthorizationRequest, ExecutionGrantState, ExecutionId,
    ExecutionPermissions, ExecutionRequestDigest, PolicyRevision, RegisteredApprovalRequest,
    RequestedExecutionPermissions, TimestampMillis, WorkspaceId,
};
use rusqlite::{Connection, params};
use uuid::Uuid;

use super::{
    ApprovalCleanupApplyOutcome, ApprovalCleanupAttemptId, ApprovalCleanupMode,
    ApprovalCleanupReadback, ApprovalCleanupSelector, apply_cleanup_plan, observe_cleanup_plan,
    prepare_cleanup_plan,
};
use crate::workspace_approvals::{
    ApprovalAuthorityCleanupReport, ApprovalStoreError, approve_once, create_auto_scope,
    decide_pending, ensure_policy, insert_pending,
};

fn fixture() -> Result<(Connection, WorkspaceId, ActivityId), Box<dyn std::error::Error>> {
    fixture_connection(Connection::open_in_memory()?)
}

fn fixture_connection(
    connection: Connection,
) -> Result<(Connection, WorkspaceId, ActivityId), Box<dyn std::error::Error>> {
    connection.execute_batch(
        "PRAGMA foreign_keys = ON;
         CREATE TABLE workspace(
            singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
            workspace_id BLOB NOT NULL UNIQUE
         );
         CREATE TABLE activities(
            activity_id BLOB PRIMARY KEY,
            workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id),
            state INTEGER NOT NULL
         );
         CREATE TABLE goal_evidence_refs(
            goal_id BLOB NOT NULL,
            evidence_kind INTEGER NOT NULL,
            evidence_id BLOB NOT NULL,
            associated_at_ms INTEGER NOT NULL,
            UNIQUE(evidence_kind, evidence_id)
         );
         CREATE TABLE agent_instances(id BLOB);
         CREATE TABLE agent_focus_events(id BLOB);
         CREATE TABLE agent_presence(id BLOB);
         CREATE TABLE agent_events(id BLOB);
         CREATE TABLE agent_inbox(id BLOB);
         CREATE TABLE activity_coordinators(id BLOB);
         CREATE TABLE agent_operations_delegations(migration_id BLOB, workspace_id BLOB);
         CREATE TABLE workspace_queue_settings(workspace_id BLOB);",
    )?;
    let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(1));
    let activity_id = ActivityId::from_uuid(Uuid::from_u128(2));
    connection.execute(
        "INSERT INTO workspace(singleton, workspace_id) VALUES (1, ?1)",
        params![workspace_id.into_uuid().as_bytes()],
    )?;
    connection.execute(
        "INSERT INTO activities(activity_id, workspace_id, state) VALUES (?1, ?2, 1)",
        params![
            activity_id.into_uuid().as_bytes(),
            workspace_id.into_uuid().as_bytes(),
        ],
    )?;
    crate::workspace_executions::create_schema(&connection)?;
    crate::workspace_execution_stops::create_schema(&connection)?;
    crate::workspace_verification::create_schema(&connection)?;
    crate::workspace_goal_deletion::create_schema(&connection)?;
    crate::workspace_approvals::create_schema(&connection)?;
    crate::workspace_semantic_events::create_schema(&connection)?;
    crate::workspace_admission_envelopes::create_schema(&connection)?;
    crate::workspace_agent_migration::create_schema(&connection)?;
    crate::workspace_work_cuts::create_schema(&connection)?;
    Ok((connection, workspace_id, activity_id))
}

fn authorization(
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    execution: u128,
    digest: u8,
) -> ExecutionAuthorizationRequest {
    ExecutionAuthorizationRequest::new(
        ExecutionId::from_uuid(Uuid::from_u128(execution)),
        workspace_id,
        activity_id,
        ExecutionRequestDigest::from_bytes([digest; 32]),
        ExecutionActionClass::DirectStructured,
        RequestedExecutionPermissions::new(ExecutionPermissions::new(true, false, false)),
    )
}

fn pending(
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    id: u128,
) -> Result<RegisteredApprovalRequest, Box<dyn std::error::Error>> {
    Ok(RegisteredApprovalRequest::pending(
        ApprovalRequestId::from_uuid(Uuid::from_u128(id)),
        authorization(workspace_id, activity_id, id + 100, u8::try_from(id)?),
        PolicyRevision::INITIAL,
        TimestampMillis::new(2)?,
        TimestampMillis::new(100)?,
    )?)
}

fn ensure_fixture_policy(
    connection: &mut Connection,
    workspace_id: WorkspaceId,
) -> Result<(), Box<dyn std::error::Error>> {
    let policy = ensure_policy(connection, workspace_id, TimestampMillis::new(1)?)?;
    assert_eq!(policy.workspace_id(), workspace_id);
    Ok(())
}

fn insert_fixture_pending(
    connection: &mut Connection,
    request: &RegisteredApprovalRequest,
) -> Result<(), Box<dyn std::error::Error>> {
    let persisted = insert_pending(connection, request)?;
    assert_eq!(&persisted, request);
    Ok(())
}

fn attempt(value: u128) -> ApprovalCleanupAttemptId {
    ApprovalCleanupAttemptId::from_uuid(Uuid::from_u128(value))
}

fn applied(
    outcome: &ApprovalCleanupApplyOutcome,
) -> Result<ApprovalAuthorityCleanupReport, Box<dyn std::error::Error>> {
    match outcome {
        ApprovalCleanupApplyOutcome::Applied(report) => Ok(*report),
        ApprovalCleanupApplyOutcome::RejectedBeforeWrite(_) => {
            Err("unexpected before-write rejection".into())
        }
    }
}

fn install_commit_guard(connection: &Connection) -> Result<(), rusqlite::Error> {
    connection.execute_batch(
        "PRAGMA foreign_keys = ON;
         CREATE TEMP TABLE approval_cleanup_commit_guard_parent (
             id INTEGER PRIMARY KEY
         );
         CREATE TEMP TABLE approval_cleanup_commit_guard_child (
             parent_id INTEGER REFERENCES approval_cleanup_commit_guard_parent(id)
                 DEFERRABLE INITIALLY DEFERRED
         );
         CREATE TEMP TRIGGER approval_cleanup_commit_guard
         AFTER UPDATE ON approval_requests
         BEGIN
             INSERT INTO approval_cleanup_commit_guard_child(parent_id) VALUES (99);
         END;",
    )
}

fn remove_commit_guard(connection: &Connection) -> Result<(), rusqlite::Error> {
    connection.execute_batch(
        "DROP TRIGGER approval_cleanup_commit_guard;
         DROP TABLE approval_cleanup_commit_guard_child;
         DROP TABLE approval_cleanup_commit_guard_parent;",
    )
}

#[test]
fn prepare_apply_and_readback_cover_all_authority_families()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut connection, workspace_id, activity_id) = fixture()?;
    ensure_fixture_policy(&mut connection, workspace_id)?;
    let pending_request = pending(workspace_id, activity_id, 30)?;
    insert_fixture_pending(&mut connection, &pending_request)?;
    let grant_pending = pending(workspace_id, activity_id, 31)?;
    insert_fixture_pending(&mut connection, &grant_pending)?;
    let (approved, grant) = approve_once(
        &mut connection,
        grant_pending.id(),
        grant_pending.revision(),
        forge_domain::ExecutionGrantId::from_uuid(Uuid::from_u128(32)),
        TimestampMillis::new(3)?,
        TimestampMillis::new(90)?,
    )?;
    assert_eq!(approved.id(), grant.approval_id());
    let scope = AutoApprovalScope::active(
        AutoApprovalScopeId::from_uuid(Uuid::from_u128(33)),
        workspace_id,
        Some(activity_id),
        ExecutionActionClass::DirectStructured,
        ExecutionPermissions::new(true, false, false),
        PolicyRevision::INITIAL,
        TimestampMillis::new(100)?,
        AutoApprovalUseLimit::new(2)?,
        AutoApprovalScopeRevision::INITIAL,
    )?;
    let stored_scope = create_auto_scope(&mut connection, &scope, TimestampMillis::new(3)?)?;
    assert_eq!(stored_scope, scope);

    let plan = prepare_cleanup_plan(
        &connection,
        workspace_id,
        ApprovalCleanupSelector::Activity(activity_id),
        TimestampMillis::new(13)?,
        forge_domain::ExecutionListLimit::new(10)?,
        ApprovalCleanupMode::AuthorityCancellation,
    )?;
    assert_eq!(plan.report().approvals(), 1);
    assert_eq!(plan.report().grants(), 1);
    assert_eq!(plan.report().auto_scopes(), 1);
    assert!(!plan.has_more());
    assert_eq!(
        observe_cleanup_plan(&connection, workspace_id, &plan)?,
        ApprovalCleanupReadback::Absent
    );

    let report = applied(&apply_cleanup_plan(
        &mut connection,
        workspace_id,
        &plan,
        attempt(1),
    )?)?;
    assert_eq!(report.total(), 3);
    assert_eq!(
        observe_cleanup_plan(&connection, workspace_id, &plan)?,
        ApprovalCleanupReadback::SettledTargetState
    );
    Ok(())
}

#[test]
fn expired_all_authority_families_freeze_exact_expire_transitions()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut connection, workspace_id, activity_id) = fixture()?;
    ensure_fixture_policy(&mut connection, workspace_id)?;

    let expiring_pending = RegisteredApprovalRequest::pending(
        ApprovalRequestId::from_uuid(Uuid::from_u128(70)),
        authorization(workspace_id, activity_id, 170, 70),
        PolicyRevision::INITIAL,
        TimestampMillis::new(2)?,
        TimestampMillis::new(10)?,
    )?;
    insert_fixture_pending(&mut connection, &expiring_pending)?;

    let grant_pending = RegisteredApprovalRequest::pending(
        ApprovalRequestId::from_uuid(Uuid::from_u128(71)),
        authorization(workspace_id, activity_id, 171, 71),
        PolicyRevision::INITIAL,
        TimestampMillis::new(2)?,
        TimestampMillis::new(10)?,
    )?;
    insert_fixture_pending(&mut connection, &grant_pending)?;
    let (_approved, grant) = approve_once(
        &mut connection,
        grant_pending.id(),
        grant_pending.revision(),
        forge_domain::ExecutionGrantId::from_uuid(Uuid::from_u128(72)),
        TimestampMillis::new(3)?,
        TimestampMillis::new(9)?,
    )?;

    let scope = AutoApprovalScope::active(
        AutoApprovalScopeId::from_uuid(Uuid::from_u128(73)),
        workspace_id,
        Some(activity_id),
        ExecutionActionClass::DirectStructured,
        ExecutionPermissions::new(true, false, false),
        PolicyRevision::INITIAL,
        TimestampMillis::new(10)?,
        AutoApprovalUseLimit::new(2)?,
        AutoApprovalScopeRevision::INITIAL,
    )?;
    let stored_scope = create_auto_scope(&mut connection, &scope, TimestampMillis::new(3)?)?;
    assert_eq!(stored_scope, scope);

    let plan = prepare_cleanup_plan(
        &connection,
        workspace_id,
        ApprovalCleanupSelector::Activity(activity_id),
        TimestampMillis::new(11)?,
        forge_domain::ExecutionListLimit::new(10)?,
        ApprovalCleanupMode::ExpiredOnly,
    )?;
    assert_eq!(plan.report().approvals(), 1);
    assert_eq!(plan.report().grants(), 1);
    assert_eq!(plan.report().auto_scopes(), 1);
    let report = applied(&apply_cleanup_plan(
        &mut connection,
        workspace_id,
        &plan,
        attempt(2),
    )?)?;
    assert_eq!(report.total(), 3);
    assert_eq!(
        observe_cleanup_plan(&connection, workspace_id, &plan)?,
        ApprovalCleanupReadback::SettledTargetState
    );

    let approval = super::super::get_approval(&connection, expiring_pending.id())?
        .ok_or("expired approval disappeared")?;
    assert_eq!(approval.state(), ApprovalRequestState::Expired);
    assert_eq!(approval.revision().get(), 2);
    assert_eq!(approval.decided_at(), Some(TimestampMillis::new(11)?));

    let grant = {
        let transaction = connection.unchecked_transaction()?;
        super::super::get_grant_tx(&transaction, grant.id())?.ok_or("expired grant disappeared")?
    };
    assert_eq!(grant.state(), ExecutionGrantState::Expired);
    assert_eq!(grant.revision().get(), 2);

    let scope = super::super::get_auto_scope(&connection, scope.id())?
        .ok_or("expired AutoScope disappeared")?;
    assert_eq!(scope.state(), AutoApprovalScopeState::Expired);
    assert_eq!(scope.revision().get(), 2);
    let (created_at, updated_at): (i64, i64) = connection.query_row(
        "SELECT created_at_ms, updated_at_ms FROM auto_approval_scopes WHERE scope_id = ?1",
        params![scope.id().into_uuid().as_bytes()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(created_at, 3);
    assert_eq!(updated_at, 11);
    Ok(())
}

#[test]
fn expired_only_leaves_nonexpired_active_authority_unchanged()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut connection, workspace_id, activity_id) = fixture()?;
    ensure_fixture_policy(&mut connection, workspace_id)?;

    let active_pending = pending(workspace_id, activity_id, 74)?;
    insert_fixture_pending(&mut connection, &active_pending)?;
    let active_grant_pending = pending(workspace_id, activity_id, 75)?;
    insert_fixture_pending(&mut connection, &active_grant_pending)?;
    let (_approved, active_grant) = approve_once(
        &mut connection,
        active_grant_pending.id(),
        active_grant_pending.revision(),
        forge_domain::ExecutionGrantId::from_uuid(Uuid::from_u128(76)),
        TimestampMillis::new(3)?,
        TimestampMillis::new(90)?,
    )?;
    let active_scope = AutoApprovalScope::active(
        AutoApprovalScopeId::from_uuid(Uuid::from_u128(77)),
        workspace_id,
        Some(activity_id),
        ExecutionActionClass::DirectStructured,
        ExecutionPermissions::new(true, false, false),
        PolicyRevision::INITIAL,
        TimestampMillis::new(100)?,
        AutoApprovalUseLimit::new(2)?,
        AutoApprovalScopeRevision::INITIAL,
    )?;
    let stored_scope = create_auto_scope(&mut connection, &active_scope, TimestampMillis::new(3)?)?;
    assert_eq!(stored_scope, active_scope);

    let plan = prepare_cleanup_plan(
        &connection,
        workspace_id,
        ApprovalCleanupSelector::Activity(activity_id),
        TimestampMillis::new(11)?,
        forge_domain::ExecutionListLimit::new(10)?,
        ApprovalCleanupMode::ExpiredOnly,
    )?;
    assert!(plan.is_empty());
    assert!(!plan.has_more());
    let report = applied(&apply_cleanup_plan(
        &mut connection,
        workspace_id,
        &plan,
        attempt(3),
    )?)?;
    assert_eq!(report.total(), 0);
    assert_eq!(
        observe_cleanup_plan(&connection, workspace_id, &plan)?,
        ApprovalCleanupReadback::Absent
    );

    let pending_after = super::super::get_approval(&connection, active_pending.id())?
        .ok_or("active pending approval disappeared")?;
    assert_eq!(pending_after, active_pending);
    let grant_after = {
        let transaction = connection.unchecked_transaction()?;
        super::super::get_grant_tx(&transaction, active_grant.id())?
            .ok_or("active grant disappeared")?
    };
    assert_eq!(grant_after, active_grant);
    let scope_after = super::super::get_auto_scope(&connection, active_scope.id())?
        .ok_or("active AutoScope disappeared")?;
    assert_eq!(scope_after, active_scope);
    let (created_at, updated_at): (i64, i64) = connection.query_row(
        "SELECT created_at_ms, updated_at_ms FROM auto_approval_scopes WHERE scope_id = ?1",
        params![active_scope.id().into_uuid().as_bytes()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!((created_at, updated_at), (3, 3));
    Ok(())
}

#[test]
fn commit_failure_is_unknown_until_same_plan_reads_back_absent_then_retries()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut connection, workspace_id, activity_id) = fixture()?;
    ensure_fixture_policy(&mut connection, workspace_id)?;
    let approval = pending(workspace_id, activity_id, 35)?;
    insert_fixture_pending(&mut connection, &approval)?;
    let plan = prepare_cleanup_plan(
        &connection,
        workspace_id,
        ApprovalCleanupSelector::Workspace,
        TimestampMillis::new(13)?,
        forge_domain::ExecutionListLimit::new(10)?,
        ApprovalCleanupMode::AuthorityCancellation,
    )?;
    install_commit_guard(&connection)?;
    let failed = apply_cleanup_plan(&mut connection, workspace_id, &plan, attempt(4));
    assert!(matches!(
        failed,
        Err(ApprovalStoreError::CleanupCommittedUnconfirmed { source })
            if matches!(source.as_ref(), rusqlite::Error::SqliteFailure(_, _))
    ));
    assert_eq!(
        observe_cleanup_plan(&connection, workspace_id, &plan)?,
        ApprovalCleanupReadback::Absent
    );
    let current = super::super::get_approval(&connection, approval.id())?
        .ok_or("approval disappeared after commit rollback")?;
    assert_eq!(current, approval);

    remove_commit_guard(&connection)?;
    let retry_report = applied(&apply_cleanup_plan(
        &mut connection,
        workspace_id,
        &plan,
        attempt(5),
    )?)?;
    assert_eq!(retry_report.total(), 1);
    assert_eq!(
        observe_cleanup_plan(&connection, workspace_id, &plan)?,
        ApprovalCleanupReadback::SettledTargetState
    );
    Ok(())
}

#[test]
fn expired_only_commit_failure_requires_readback_before_same_plan_retry()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut connection, workspace_id, activity_id) = fixture()?;
    ensure_fixture_policy(&mut connection, workspace_id)?;
    let approval = RegisteredApprovalRequest::pending(
        ApprovalRequestId::from_uuid(Uuid::from_u128(78)),
        authorization(workspace_id, activity_id, 178, 78),
        PolicyRevision::INITIAL,
        TimestampMillis::new(2)?,
        TimestampMillis::new(10)?,
    )?;
    insert_fixture_pending(&mut connection, &approval)?;
    let plan = prepare_cleanup_plan(
        &connection,
        workspace_id,
        ApprovalCleanupSelector::Activity(activity_id),
        TimestampMillis::new(11)?,
        forge_domain::ExecutionListLimit::new(10)?,
        ApprovalCleanupMode::ExpiredOnly,
    )?;
    install_commit_guard(&connection)?;
    let failed = apply_cleanup_plan(&mut connection, workspace_id, &plan, attempt(6));
    assert!(matches!(
        failed,
        Err(ApprovalStoreError::CleanupCommittedUnconfirmed { source })
            if matches!(source.as_ref(), rusqlite::Error::SqliteFailure(_, _))
    ));
    assert_eq!(
        observe_cleanup_plan(&connection, workspace_id, &plan)?,
        ApprovalCleanupReadback::Absent
    );
    remove_commit_guard(&connection)?;
    let report = applied(&apply_cleanup_plan(
        &mut connection,
        workspace_id,
        &plan,
        attempt(7),
    )?)?;
    assert_eq!(report.total(), 1);
    assert_eq!(
        observe_cleanup_plan(&connection, workspace_id, &plan)?,
        ApprovalCleanupReadback::SettledTargetState
    );
    Ok(())
}

#[test]
fn mixed_before_and_after_readback_is_mismatch() -> Result<(), Box<dyn std::error::Error>> {
    let (mut connection, workspace_id, activity_id) = fixture()?;
    ensure_fixture_policy(&mut connection, workspace_id)?;
    let first = pending(workspace_id, activity_id, 36)?;
    let second = pending(workspace_id, activity_id, 37)?;
    insert_fixture_pending(&mut connection, &first)?;
    insert_fixture_pending(&mut connection, &second)?;
    let plan = prepare_cleanup_plan(
        &connection,
        workspace_id,
        ApprovalCleanupSelector::Workspace,
        TimestampMillis::new(13)?,
        forge_domain::ExecutionListLimit::new(10)?,
        ApprovalCleanupMode::AuthorityCancellation,
    )?;
    let changed = decide_pending(
        &mut connection,
        first.id(),
        forge_domain::ApprovalDecision::Cancel,
        first.revision(),
        TimestampMillis::new(13)?,
    )?;
    assert_eq!(
        changed.state(),
        forge_domain::ApprovalRequestState::Cancelled
    );
    assert_eq!(
        observe_cleanup_plan(&connection, workspace_id, &plan)?,
        ApprovalCleanupReadback::Mismatch
    );
    Ok(())
}

#[test]
fn prepare_rejects_time_before_creation_and_revision_overflow()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut connection, workspace_id, activity_id) = fixture()?;
    ensure_fixture_policy(&mut connection, workspace_id)?;
    let normal = pending(workspace_id, activity_id, 38)?;
    insert_fixture_pending(&mut connection, &normal)?;
    assert!(matches!(
        prepare_cleanup_plan(
            &connection,
            workspace_id,
            ApprovalCleanupSelector::Workspace,
            TimestampMillis::new(1)?,
            forge_domain::ExecutionListLimit::new(10)?,
            ApprovalCleanupMode::AuthorityCancellation,
        ),
        Err(ApprovalStoreError::InvalidTransition)
    ));

    let overflow = RegisteredApprovalRequest::from_parts(
        ApprovalRequestId::from_uuid(Uuid::from_u128(39)),
        authorization(workspace_id, activity_id, 139, 39),
        PolicyRevision::INITIAL,
        ApprovalRequestState::Pending,
        TimestampMillis::new(2)?,
        TimestampMillis::new(10)?,
        None,
        ApprovalRevision::new(i64::MAX)?,
    )?;
    insert_fixture_pending(&mut connection, &overflow)?;
    assert!(matches!(
        prepare_cleanup_plan(
            &connection,
            workspace_id,
            ApprovalCleanupSelector::Activity(activity_id),
            TimestampMillis::new(13)?,
            forge_domain::ExecutionListLimit::new(10)?,
            ApprovalCleanupMode::ExpiredOnly,
        ),
        Err(ApprovalStoreError::RevisionOverflow)
    ));
    Ok(())
}

#[test]
fn stale_before_image_rolls_back_the_entire_cleanup_batch() -> Result<(), Box<dyn std::error::Error>>
{
    let (mut connection, workspace_id, activity_id) = fixture()?;
    ensure_fixture_policy(&mut connection, workspace_id)?;
    let first = pending(workspace_id, activity_id, 40)?;
    let second = pending(workspace_id, activity_id, 41)?;
    insert_fixture_pending(&mut connection, &first)?;
    insert_fixture_pending(&mut connection, &second)?;
    let plan = prepare_cleanup_plan(
        &connection,
        workspace_id,
        ApprovalCleanupSelector::Workspace,
        TimestampMillis::new(13)?,
        forge_domain::ExecutionListLimit::new(10)?,
        ApprovalCleanupMode::AuthorityCancellation,
    )?;
    let wrong_plan = prepare_cleanup_plan(
        &connection,
        workspace_id,
        ApprovalCleanupSelector::Workspace,
        TimestampMillis::new(13)?,
        forge_domain::ExecutionListLimit::new(10)?,
        ApprovalCleanupMode::ExpiredOnly,
    )?;
    let changed = decide_pending(
        &mut connection,
        first.id(),
        forge_domain::ApprovalDecision::Cancel,
        first.revision(),
        TimestampMillis::new(14)?,
    )?;
    assert_eq!(
        changed.state(),
        forge_domain::ApprovalRequestState::Cancelled
    );
    let rejection = match apply_cleanup_plan(&mut connection, workspace_id, &plan, attempt(8))? {
        ApprovalCleanupApplyOutcome::RejectedBeforeWrite(rejection) => rejection,
        ApprovalCleanupApplyOutcome::Applied(_) => return Err("expected rejection proof".into()),
    };
    assert!(rejection.matches(&plan, attempt(8)));
    assert!(!rejection.matches(&plan, attempt(9)));
    assert!(!rejection.matches(&wrong_plan, attempt(8)));
    let first_current = super::super::get_approval(&connection, first.id())?
        .ok_or("first approval disappeared after rejection")?;
    assert_eq!(
        first_current.state(),
        forge_domain::ApprovalRequestState::Cancelled
    );
    let second_current = super::super::get_approval(&connection, second.id())?
        .ok_or("second approval disappeared after rollback")?;
    assert_eq!(
        second_current.state(),
        forge_domain::ApprovalRequestState::Pending
    );
    Ok(())
}

#[test]
fn second_connection_rejection_proof_preserves_first_commit_and_attempt_fence()
-> Result<(), Box<dyn std::error::Error>> {
    fn run_case(
        mode: ApprovalCleanupMode,
        first_observed_at: TimestampMillis,
        second_observed_at: TimestampMillis,
        expected_state: ApprovalRequestState,
        first_attempt: ApprovalCleanupAttemptId,
        second_attempt: ApprovalCleanupAttemptId,
        approval_id: u128,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let path = std::env::temp_dir().join(format!(
            "forge-cleanup-two-connection-{}.sqlite",
            Uuid::now_v7()
        ));
        let (mut first, workspace_id, activity_id) = fixture_connection(Connection::open(&path)?)?;
        ensure_fixture_policy(&mut first, workspace_id)?;
        let approval = pending(workspace_id, activity_id, approval_id)?;
        insert_fixture_pending(&mut first, &approval)?;
        let mut second = Connection::open(&path)?;
        second.execute_batch("PRAGMA foreign_keys = ON;")?;

        let first_plan = prepare_cleanup_plan(
            &first,
            workspace_id,
            ApprovalCleanupSelector::Activity(activity_id),
            first_observed_at,
            forge_domain::ExecutionListLimit::new(10)?,
            mode,
        )?;
        let second_plan = prepare_cleanup_plan(
            &second,
            workspace_id,
            ApprovalCleanupSelector::Activity(activity_id),
            second_observed_at,
            forge_domain::ExecutionListLimit::new(10)?,
            mode,
        )?;
        let first_report = applied(&apply_cleanup_plan(
            &mut first,
            workspace_id,
            &first_plan,
            first_attempt,
        )?)?;
        assert_eq!(first_report.total(), 1);
        let rejection =
            match apply_cleanup_plan(&mut second, workspace_id, &second_plan, second_attempt)? {
                ApprovalCleanupApplyOutcome::RejectedBeforeWrite(rejection) => rejection,
                ApprovalCleanupApplyOutcome::Applied(_) => {
                    return Err("expected second-owner rejection".into());
                }
            };
        assert!(rejection.matches(&second_plan, second_attempt));
        assert!(!rejection.matches(&first_plan, second_attempt));
        assert!(!rejection.matches(&second_plan, first_attempt));
        let durable = super::super::get_approval(&second, approval.id())?
            .ok_or("first-owner approval disappeared")?;
        assert_eq!(durable.state(), expected_state);
        assert_eq!(durable.revision().get(), 2);
        assert_eq!(durable.decided_at(), Some(first_observed_at));
        drop(second);
        drop(first);
        fs::remove_file(path)?;
        Ok(())
    }

    run_case(
        ApprovalCleanupMode::AuthorityCancellation,
        TimestampMillis::new(10)?,
        TimestampMillis::new(11)?,
        ApprovalRequestState::Cancelled,
        attempt(82),
        attempt(83),
        82,
    )?;
    run_case(
        ApprovalCleanupMode::ExpiredOnly,
        TimestampMillis::new(101)?,
        TimestampMillis::new(102)?,
        ApprovalRequestState::Expired,
        attempt(84),
        attempt(85),
        86,
    )?;
    Ok(())
}

#[test]
fn later_target_cas_failure_rolls_back_earlier_update_without_rejection_proof()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut connection, workspace_id, activity_id) = fixture()?;
    ensure_fixture_policy(&mut connection, workspace_id)?;
    let first = pending(workspace_id, activity_id, 84)?;
    let second = pending(workspace_id, activity_id, 85)?;
    insert_fixture_pending(&mut connection, &first)?;
    insert_fixture_pending(&mut connection, &second)?;
    let plan = prepare_cleanup_plan(
        &connection,
        workspace_id,
        ApprovalCleanupSelector::Workspace,
        TimestampMillis::new(13)?,
        forge_domain::ExecutionListLimit::new(10)?,
        ApprovalCleanupMode::AuthorityCancellation,
    )?;
    connection.execute_batch(
        "CREATE TEMP TRIGGER approval_cleanup_late_cas
         AFTER UPDATE ON approval_requests
         WHEN NEW.state = 5
         BEGIN
             UPDATE approval_requests
             SET state = 5, decided_at_ms = 13, revision = revision + 1
             WHERE approval_id = (
                 SELECT approval_id FROM approval_requests
                 WHERE state = 0 ORDER BY approval_id LIMIT 1
             );
         END;",
    )?;
    let outcome = apply_cleanup_plan(&mut connection, workspace_id, &plan, attempt(84));
    assert!(matches!(outcome, Err(ApprovalStoreError::RevisionConflict)));
    let first_after = super::super::get_approval(&connection, first.id())?
        .ok_or("first target disappeared after CAS rollback")?;
    let second_after = super::super::get_approval(&connection, second.id())?
        .ok_or("second target disappeared after CAS rollback")?;
    assert_eq!(first_after, first);
    assert_eq!(second_after, second);
    connection.execute_batch("DROP TRIGGER approval_cleanup_late_cas;")?;
    Ok(())
}

#[test]
fn page_continuation_reports_more_rows_without_clamping_the_limit()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut connection, workspace_id, activity_id) = fixture()?;
    ensure_fixture_policy(&mut connection, workspace_id)?;
    for id in [50_u128, 51] {
        insert_fixture_pending(&mut connection, &pending(workspace_id, activity_id, id)?)?;
    }
    let first = prepare_cleanup_plan(
        &connection,
        workspace_id,
        ApprovalCleanupSelector::Workspace,
        TimestampMillis::new(13)?,
        forge_domain::ExecutionListLimit::new(1)?,
        ApprovalCleanupMode::AuthorityCancellation,
    )?;
    assert_eq!(first.report().approvals(), 1);
    assert!(first.has_more());
    let first_report = applied(&apply_cleanup_plan(
        &mut connection,
        workspace_id,
        &first,
        attempt(9),
    )?)?;
    assert_eq!(first_report.total(), 1);

    let second = prepare_cleanup_plan(
        &connection,
        workspace_id,
        ApprovalCleanupSelector::Workspace,
        TimestampMillis::new(13)?,
        forge_domain::ExecutionListLimit::new(1)?,
        ApprovalCleanupMode::AuthorityCancellation,
    )?;
    assert_eq!(second.report().approvals(), 1);
    assert!(!second.has_more());
    Ok(())
}

#[test]
fn foreign_workspace_cannot_apply_a_plan() -> Result<(), Box<dyn std::error::Error>> {
    let (mut connection, workspace_id, activity_id) = fixture()?;
    ensure_fixture_policy(&mut connection, workspace_id)?;
    insert_fixture_pending(&mut connection, &pending(workspace_id, activity_id, 60)?)?;
    let plan = prepare_cleanup_plan(
        &connection,
        workspace_id,
        ApprovalCleanupSelector::Workspace,
        TimestampMillis::new(13)?,
        forge_domain::ExecutionListLimit::new(10)?,
        ApprovalCleanupMode::AuthorityCancellation,
    )?;
    let foreign = WorkspaceId::from_uuid(Uuid::from_u128(61));
    assert!(matches!(
        apply_cleanup_plan(&mut connection, foreign, &plan, attempt(10)),
        Err(ApprovalStoreError::WorkspaceMismatch)
    ));
    Ok(())
}
