//! Delegated Agent departure reconciliation evidence: replay-exact receipts,
//! fail-closed caller fencing, Coordinator guards, atomic rollback, the
//! schema-39 migration, and the absence of every Orchestration-owned
//! participation write.

use std::error::Error;
use std::fs;
use std::path::PathBuf;

use forge_domain::{
    ActivityCoordinatorActor, ActivityCoordinatorRevision, ActivityId, AgentDeclaredRole,
    AgentDisplayName, AgentEventId, AgentHandoff, AgentInstanceId, AgentSessionId,
    AgentTransportKind, AuthenticatedPrincipal, BootstrapActivity, ClaimActivityCoordinator,
    CoordinationSnapshot, DetachAgent, EstablishWorkspace, RegisteredAgentInstance,
    RuntimeInstanceId, TimestampMillis, WorkspaceId, WorkspaceRevision, WorkspaceRoot,
};
use forge_workspace::WorkspaceStateLayout;
use rusqlite::{Connection, params};
use uuid::Uuid;

use crate::{
    AgentBindingActivationRequest, AgentBindingReservationRequest, AgentDepartureCommand,
    AgentDepartureKind, AgentDepartureReconciliationRequest, AgentOperationsFreezeRequest,
    WorkspaceStore,
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const IDENTITY_DIGEST: [u8; 32] = [0x77; 32];

struct Fixture {
    root: PathBuf,
    layout: WorkspaceStateLayout,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
}

fn id(value: u128) -> Uuid {
    Uuid::from_u128(value)
}

fn timestamp(value: i64) -> Result<TimestampMillis, Box<dyn Error>> {
    Ok(TimestampMillis::new(value)?)
}

fn fixture(label: &str) -> TestResult<Fixture> {
    let root = std::env::temp_dir().join(format!("forge-departure-{label}-{}", Uuid::now_v7()));
    fs::create_dir_all(&root)?;
    let layout = WorkspaceStateLayout::initialize(&root)?;
    let workspace_id = WorkspaceId::from_uuid(id(0xE700));
    let activity_id = ActivityId::from_uuid(id(0xE701));
    let command = EstablishWorkspace::new(
        workspace_id,
        forge_domain::LocationId::from_uuid(id(0xE702)),
        WorkspaceRoot::from_canonical(layout.workspace_root().to_path_buf())?,
        layout.root_fingerprint()?,
        timestamp(1)?,
    );
    let mut store = WorkspaceStore::open(&layout, &command)?;
    store.bootstrap_activity(&BootstrapActivity::new(
        activity_id,
        workspace_id,
        WorkspaceRevision::INITIAL,
        RuntimeInstanceId::from_uuid(id(0xE703)),
        timestamp(100)?,
        timestamp(2)?,
    ))?;
    drop(store);
    Ok(Fixture {
        root,
        layout,
        workspace_id,
        activity_id,
    })
}

fn reopen(fixture: &Fixture) -> TestResult<WorkspaceStore> {
    let existing = WorkspaceStateLayout::inspect_existing(fixture.layout.workspace_root())?
        .ok_or("Workspace state layout disappeared")?;
    Ok(WorkspaceStore::open_existing(&existing)?)
}

fn connection(fixture: &Fixture) -> TestResult<Connection> {
    let connection = Connection::open(fixture.layout.database_path())?;
    connection.pragma_update(None, "foreign_keys", true)?;
    Ok(connection)
}

fn count(connection: &Connection, query: &str) -> TestResult<i64> {
    Ok(connection.query_row(query, [], |row| row.get(0))?)
}

/// The durable delegation for the fixture Workspace; every reconciliation call
/// re-resolves it from the store exactly like the production control path.
fn delegation_of(
    store: &mut WorkspaceStore,
    fixture: &Fixture,
) -> TestResult<crate::AgentOperationsDelegation> {
    store
        .agent_operations_delegation()?
        .filter(|delegation| delegation.workspace_id() == fixture.workspace_id)
        .ok_or_else(|| "durable delegation missing".into())
}

fn reconcile(
    store: &mut WorkspaceStore,
    fixture: &Fixture,
    request: &AgentDepartureReconciliationRequest,
) -> TestResult<crate::AgentDepartureReconciliation> {
    let delegation = delegation_of(store, fixture)?;
    Ok(store.reconcile_agent_departure(&delegation, request, timestamp(99)?)?)
}

/// Freeze and delegate once per Workspace; every subsequent Agent reservation
/// and activation rides on this single migration identity.
fn delegate_workspace(
    store: &mut WorkspaceStore,
    freeze_migration: u128,
    delegated_at: i64,
) -> TestResult<crate::AgentOperationsDelegation> {
    let freeze = store.freeze_agent_operations(&AgentOperationsFreezeRequest::new(
        id(freeze_migration),
        id(freeze_migration + 1),
        timestamp(4)?,
    )?)?;
    Ok(store.delegate_agent_operations(&freeze, [0x71; 32], timestamp(delegated_at)?)?)
}

/// Reserve and activate one session-bound Agent under an existing delegation so
/// the departure reconciliation has a real delegated effect binding to operate on.
fn delegated_agent(
    fixture: &Fixture,
    store: &mut WorkspaceStore,
    delegation: &crate::AgentOperationsDelegation,
    agent_seed: u128,
    display_name: &str,
) -> TestResult<RegisteredAgentInstance> {
    let request = AgentBindingReservationRequest::new(
        id(agent_seed + 0x2000),
        fixture.activity_id,
        AgentInstanceId::from_uuid(id(agent_seed)),
        AgentSessionId::from_uuid(id(agent_seed + 0x1000)),
        AuthenticatedPrincipal::TrustedStdio,
        timestamp(11)?,
    )?;
    let _reservation = store.reserve_agent_binding(
        &store
            .agent_operations_freeze(delegation.migration_id())?
            .ok_or("durable freeze missing")?,
        &request,
        timestamp(12)?,
    )?;
    let activation = AgentBindingActivationRequest::new(
        request.request_id(),
        [0x72; 32],
        AgentDisplayName::new(display_name.to_owned())?,
        AgentDeclaredRole::new("worker".to_owned())?,
        AgentTransportKind::Stdio,
    )?;
    let _activated = store.activate_agent_binding(delegation, &activation, timestamp(21)?)?;
    Ok(store
        .get_agent(request.agent_id())?
        .ok_or("activated Agent missing")?)
}

fn detach_request(
    agent: &RegisteredAgentInstance,
    request_seed: u128,
    observed_at: i64,
) -> TestResult<AgentDepartureReconciliationRequest> {
    Ok(AgentDepartureReconciliationRequest::new(
        id(request_seed),
        AgentDepartureCommand::Detach(DetachAgent::new(
            agent.id(),
            agent.activity_id(),
            agent.revision(),
            timestamp(observed_at)?,
        )),
        agent.session_id().ok_or("Agent has no session")?,
        agent.principal(),
        IDENTITY_DIGEST,
    )?)
}

#[allow(clippy::too_many_arguments)]
fn handoff_request(
    request_seed: u128,
    actor: ActivityCoordinatorActor,
    source: &RegisteredAgentInstance,
    target: &RegisteredAgentInstance,
    expected_target_revision: forge_domain::AgentInstanceRevision,
    observed_at: i64,
) -> TestResult<AgentDepartureReconciliationRequest> {
    Ok(AgentDepartureReconciliationRequest::new(
        id(request_seed),
        AgentDepartureCommand::Handoff(Box::new(AgentHandoff::new(
            actor,
            source.revision(),
            target.id(),
            target.session_id().ok_or("target has no session")?,
            target.principal(),
            expected_target_revision,
            CoordinationSnapshot::empty(),
            AgentEventId::from_uuid(id(request_seed + 1)),
            timestamp(observed_at)?,
        ))),
        actor.session_id(),
        actor.principal(),
        IDENTITY_DIGEST,
    )?)
}

struct ParticipationBaselines {
    presence: i64,
    events: i64,
    inbox: i64,
    outbox: i64,
}

fn participation_baselines(fixture: &Fixture) -> TestResult<ParticipationBaselines> {
    let connection = connection(fixture)?;
    let baselines = ParticipationBaselines {
        presence: count(&connection, "SELECT COUNT(*) FROM agent_presence")?,
        events: count(&connection, "SELECT COUNT(*) FROM agent_events")?,
        inbox: count(&connection, "SELECT COUNT(*) FROM agent_inbox")?,
        outbox: count(
            &connection,
            "SELECT COUNT(*) FROM agent_effect_outbox_transitions",
        )?,
    };
    drop(connection);
    Ok(baselines)
}

fn assert_participation_unchanged(
    fixture: &Fixture,
    baselines: &ParticipationBaselines,
) -> TestResult {
    let connection = connection(fixture)?;
    assert_eq!(
        count(&connection, "SELECT COUNT(*) FROM agent_presence")?,
        baselines.presence,
        "presence is Orchestration-owned"
    );
    assert_eq!(
        count(&connection, "SELECT COUNT(*) FROM agent_events")?,
        baselines.events,
        "membership events are Orchestration-owned"
    );
    assert_eq!(
        count(&connection, "SELECT COUNT(*) FROM agent_inbox")?,
        baselines.inbox,
        "inbox receipts are Orchestration-owned"
    );
    assert_eq!(
        count(
            &connection,
            "SELECT COUNT(*) FROM agent_effect_outbox_transitions"
        )?,
        baselines.outbox,
        "membership transition facts are Orchestration-owned"
    );
    Ok(())
}

#[test]
fn delegated_detach_replays_exactly_and_writes_only_effect_state() -> TestResult {
    let fixture = fixture("detach")?;
    let mut store = reopen(&fixture)?;
    let delegation = delegate_workspace(&mut store, 0xE710, 20)?;
    let agent = delegated_agent(&fixture, &mut store, &delegation, 0xE720, "detach-worker")?;
    let baselines = participation_baselines(&fixture)?;
    let request = detach_request(&agent, 0xE730, 30)?;
    let receipt = reconcile(&mut store, &fixture, &request)?;
    assert_eq!(receipt.request_id(), id(0xE730));
    assert_eq!(receipt.kind(), AgentDepartureKind::Detach);
    assert_eq!(receipt.agent_id(), agent.id());
    assert_eq!(receipt.session_id(), agent.session_id().ok_or("session")?);
    assert_eq!(receipt.expected_agent_revision(), agent.revision());
    assert_eq!(
        receipt.result_agent_revision().get(),
        agent.revision().get() + 1
    );
    assert_eq!(receipt.target_agent_id(), None);
    assert_eq!(receipt.target_session_id(), None);
    assert_eq!(receipt.result_coordinator_revision(), None);
    assert_eq!(receipt.identity_digest(), IDENTITY_DIGEST);
    assert_eq!(receipt.reconciled_at(), timestamp(30)?);
    assert_eq!(
        store.agent_departure_reconciliation(id(0xE730))?,
        Some(receipt)
    );
    assert_eq!(reconcile(&mut store, &fixture, &request)?, receipt);

    let detached = store
        .get_agent(agent.id())?
        .ok_or("detached Agent missing")?;
    assert!(detached.attachment_state().is_detached());
    assert_eq!(detached.revision(), receipt.result_agent_revision());
    drop(store);

    let connection = connection(&fixture)?;
    assert_eq!(
        count(
            &connection,
            "SELECT COUNT(*) FROM agent_departure_reconciliations"
        )?,
        1
    );
    assert_eq!(
        count(&connection, "SELECT COUNT(*) FROM agent_focus_events")?,
        2,
        "attach plus the single terminal Detached focus fact"
    );
    drop(connection);

    let reopened = reopen(&fixture)?;
    assert_eq!(
        reopened.agent_departure_reconciliation(id(0xE730))?,
        Some(receipt)
    );
    drop(reopened);
    assert_participation_unchanged(&fixture, &baselines)?;
    fs::remove_dir_all(fixture.root)?;
    Ok(())
}

#[test]
fn delegated_detach_conflicts_fail_closed_without_partial_state() -> TestResult {
    let fixture = fixture("detach-conflict")?;
    let mut store = reopen(&fixture)?;
    let delegation = delegate_workspace(&mut store, 0xE740, 20)?;
    let agent = delegated_agent(&fixture, &mut store, &delegation, 0xE750, "conflict-worker")?;
    let committed = reconcile(&mut store, &fixture, &detach_request(&agent, 0xE760, 30)?)?;
    assert!(
        store
            .get_agent(agent.id())?
            .ok_or("Agent missing")?
            .attachment_state()
            .is_detached()
    );

    let wrong_session = AgentDepartureReconciliationRequest::new(
        id(0xE761),
        AgentDepartureCommand::Detach(DetachAgent::new(
            agent.id(),
            agent.activity_id(),
            agent.revision(),
            timestamp(30)?,
        )),
        AgentSessionId::from_uuid(id(0xE762)),
        agent.principal(),
        IDENTITY_DIGEST,
    )?;
    assert!(reconcile(&mut store, &fixture, &wrong_session).is_err());

    let wrong_principal = AgentDepartureReconciliationRequest::new(
        id(0xE763),
        AgentDepartureCommand::Detach(DetachAgent::new(
            agent.id(),
            agent.activity_id(),
            agent.revision(),
            timestamp(30)?,
        )),
        agent.session_id().ok_or("session missing")?,
        AuthenticatedPrincipal::DirectToken(forge_domain::DirectTokenId::from_uuid(id(0xE764))),
        IDENTITY_DIGEST,
    )?;
    assert!(reconcile(&mut store, &fixture, &wrong_principal).is_err());

    let stale_revision = AgentDepartureReconciliationRequest::new(
        id(0xE765),
        AgentDepartureCommand::Detach(DetachAgent::new(
            agent.id(),
            agent.activity_id(),
            agent.revision().checked_next()?,
            timestamp(30)?,
        )),
        agent.session_id().ok_or("session missing")?,
        agent.principal(),
        IDENTITY_DIGEST,
    )?;
    assert!(reconcile(&mut store, &fixture, &stale_revision).is_err());

    // The same request identity with different content is a conflict, never a
    // replay, and a different request identity for the same Agent is fenced by
    // the one-departure-per-Agent uniqueness.
    let replayed = detach_request(&agent, 0xE760, 31)?;
    assert!(reconcile(&mut store, &fixture, &replayed).is_err());
    let second_request = detach_request(&agent, 0xE766, 32)?;
    assert!(reconcile(&mut store, &fixture, &second_request).is_err());
    drop(store);

    let connection = connection(&fixture)?;
    assert_eq!(
        count(
            &connection,
            "SELECT COUNT(*) FROM agent_departure_reconciliations"
        )?,
        1,
        "failed reconciliations must not add receipts"
    );
    assert_eq!(
        count(&connection, "SELECT COUNT(*) FROM agent_focus_events")?,
        2
    );
    drop(connection);

    let reopened = reopen(&fixture)?;
    let unchanged = reopened
        .get_agent(agent.id())?
        .ok_or("detached Agent missing")?;
    assert!(unchanged.attachment_state().is_detached());
    assert_eq!(
        reopened.agent_departure_reconciliation(id(0xE760))?,
        Some(committed)
    );
    fs::remove_dir_all(fixture.root)?;
    Ok(())
}

#[test]
fn current_coordinator_cannot_reconcile_a_plain_detach() -> TestResult {
    let fixture = fixture("coordinator-detach")?;
    let mut store = reopen(&fixture)?;
    let delegation = delegate_workspace(&mut store, 0xE770, 20)?;
    let agent = delegated_agent(&fixture, &mut store, &delegation, 0xE780, "coordinator")?;
    let claimed = store.claim_activity_coordinator(
        ClaimActivityCoordinator::new(
            fixture.workspace_id,
            fixture.activity_id,
            agent.id(),
            agent.principal(),
            timestamp(25)?,
            agent.session_id().ok_or("session missing")?,
        ),
        timestamp(99)?,
    )?;
    let request = detach_request(&agent, 0xE790, 30)?;
    let delegation = delegation_of(&mut store, &fixture)?;
    let error = store
        .reconcile_agent_departure(&delegation, &request, timestamp(99)?)
        .err()
        .ok_or("a current Coordinator detach must be refused")?;
    assert!(matches!(
        error,
        crate::WorkspaceStoreError::AgentDepartureReconciliation(
            crate::AgentDepartureReconciliationError::Agent(
                crate::AgentStoreError::CurrentCoordinatorCannotDetach(_)
            )
        )
    ));
    assert_eq!(
        store.get_activity_coordinator(fixture.activity_id)?,
        Some(claimed)
    );
    assert!(
        store
            .get_agent(agent.id())?
            .ok_or("coordinator missing")?
            .attachment_state()
            .is_attached()
    );
    fs::remove_dir_all(fixture.root)?;
    Ok(())
}

#[test]
fn delegated_handoff_transfers_planning_and_writes_no_participation() -> TestResult {
    let fixture = fixture("handoff")?;
    let mut store = reopen(&fixture)?;
    let delegation = delegate_workspace(&mut store, 0xE7A0, 20)?;
    let source = delegated_agent(&fixture, &mut store, &delegation, 0xE7B0, "handoff-source")?;
    let target = delegated_agent(&fixture, &mut store, &delegation, 0xE7C0, "handoff-target")?;
    let claimed = store.claim_activity_coordinator(
        ClaimActivityCoordinator::new(
            fixture.workspace_id,
            fixture.activity_id,
            source.id(),
            source.principal(),
            timestamp(25)?,
            source.session_id().ok_or("source session missing")?,
        ),
        timestamp(99)?,
    )?;
    let baselines = participation_baselines(&fixture)?;

    let actor = ActivityCoordinatorActor::new(
        fixture.workspace_id,
        fixture.activity_id,
        source.id(),
        claimed.revision(),
        source.principal(),
        source.session_id().ok_or("source session missing")?,
    );
    let request = handoff_request(0xE7D0, actor, &source, &target, target.revision(), 30)?;
    let receipt = reconcile(&mut store, &fixture, &request)
        .map_err(|error| format!("first handoff failed: {error:?}"))?;
    assert_eq!(receipt.kind(), AgentDepartureKind::Handoff);
    assert_eq!(receipt.agent_id(), source.id());
    assert_eq!(receipt.target_agent_id(), Some(target.id()));
    assert_eq!(
        receipt.target_session_id(),
        Some(target.session_id().ok_or("target session missing")?)
    );
    assert_eq!(
        receipt.result_coordinator_revision(),
        Some(ActivityCoordinatorRevision::new(2)?)
    );
    assert_eq!(
        store.agent_departure_reconciliation(id(0xE7D0))?,
        Some(receipt)
    );
    assert_eq!(
        reconcile(&mut store, &fixture, &request)
            .map_err(|error| format!("handoff replay failed: {error:?}"))?,
        receipt
    );

    let binding = store
        .get_activity_coordinator(fixture.activity_id)?
        .ok_or("coordinator binding missing")?;
    assert_eq!(binding.agent_id(), target.id());
    assert_eq!(binding.revision(), ActivityCoordinatorRevision::new(2)?);
    let detached_source = store.get_agent(source.id())?.ok_or("source missing")?;
    assert!(detached_source.attachment_state().is_detached());
    assert!(detached_source.focus().is_unfocused());
    let transferred_target = store.get_agent(target.id())?.ok_or("target missing")?;
    assert!(transferred_target.attachment_state().is_attached());
    assert!(transferred_target.focus().is_unfocused());
    assert_eq!(transferred_target.revision().get(), 2);
    drop(store);

    let reopened = reopen(&fixture)?;
    assert_eq!(
        reopened.agent_departure_reconciliation(id(0xE7D0))?,
        Some(receipt)
    );
    drop(reopened);
    assert_participation_unchanged(&fixture, &baselines)?;
    fs::remove_dir_all(fixture.root)?;
    Ok(())
}

#[test]
fn expired_activity_rejects_coordinator_handoff_without_partial_facts() -> TestResult {
    let fixture = fixture("expired-handoff")?;
    let mut store = reopen(&fixture)?;
    let delegation = delegate_workspace(&mut store, 0xE8A0, 20)?;
    let source = delegated_agent(&fixture, &mut store, &delegation, 0xE8B0, "expired-source")?;
    let target = delegated_agent(&fixture, &mut store, &delegation, 0xE8C0, "expired-target")?;
    let claimed = store.claim_activity_coordinator(
        ClaimActivityCoordinator::new(
            fixture.workspace_id,
            fixture.activity_id,
            source.id(),
            source.principal(),
            timestamp(25)?,
            source.session_id().ok_or("source session missing")?,
        ),
        timestamp(99)?,
    )?;
    let actor = ActivityCoordinatorActor::new(
        fixture.workspace_id,
        fixture.activity_id,
        source.id(),
        claimed.revision(),
        source.principal(),
        source.session_id().ok_or("source session missing")?,
    );
    let request = handoff_request(0xE8D0, actor, &source, &target, target.revision(), 30)?;
    let baseline = participation_baselines(&fixture)?;
    let activity = store
        .get_activity(fixture.activity_id)?
        .ok_or("Activity missing before lease release")?;
    store.release_activity_lease(&forge_domain::ReleaseActivityLease::new(
        fixture.activity_id,
        RuntimeInstanceId::from_uuid(id(0xE703)),
        activity.lease_revision(),
        timestamp(99)?,
    ))?;

    let error = store
        .reconcile_agent_departure(&delegation, &request, timestamp(99)?)
        .err()
        .ok_or("expired Activity cannot transfer Coordinator authority by handoff")?;
    assert!(matches!(
        error,
        crate::WorkspaceStoreError::AgentDepartureReconciliation(
            crate::AgentDepartureReconciliationError::Coordinator(
                crate::CoordinatorStoreError::ActivityLeaseNotLive(activity_id)
            )
        ) if activity_id == fixture.activity_id
    ));
    assert_eq!(
        store.get_activity_coordinator(fixture.activity_id)?,
        Some(claimed),
        "failed handoff keeps the existing coordinator binding"
    );
    assert_eq!(
        store.agent_departure_reconciliation(request.request_id())?,
        None,
        "failed handoff writes no durable receipt"
    );
    assert_participation_unchanged(&fixture, &baseline)?;
    fs::remove_dir_all(fixture.root)?;
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn delegated_handoff_fences_roll_back_without_partial_facts() -> TestResult {
    let fixture = fixture("handoff-fence")?;
    let mut store = reopen(&fixture)?;
    let delegation = delegate_workspace(&mut store, 0xE7E0, 20)?;
    let source = delegated_agent(&fixture, &mut store, &delegation, 0xE7F0, "fence-source")?;
    let target = delegated_agent(&fixture, &mut store, &delegation, 0xE800, "fence-target")?;
    let claimed = store.claim_activity_coordinator(
        ClaimActivityCoordinator::new(
            fixture.workspace_id,
            fixture.activity_id,
            source.id(),
            source.principal(),
            timestamp(25)?,
            source.session_id().ok_or("source session missing")?,
        ),
        timestamp(99)?,
    )?;
    let baselines = participation_baselines(&fixture)?;
    let actor = ActivityCoordinatorActor::new(
        fixture.workspace_id,
        fixture.activity_id,
        source.id(),
        claimed.revision(),
        source.principal(),
        source.session_id().ok_or("source session missing")?,
    );

    // Same-session handoff is refused.
    let same_session = handoff_request(0xE812, actor, &source, &source, source.revision(), 30)?;
    assert!(reconcile(&mut store, &fixture, &same_session).is_err());

    // An active Writer Lease on the target rolls the whole departure back.
    {
        let connection = connection(&fixture)?;
        connection.execute(
            "INSERT INTO writer_leases (lease_id, workspace_id, activity_id, agent_id, state, acquired_at_ms, updated_at_ms, lease_until_ms, revision) VALUES (?1, ?2, ?3, ?4, 0, 29, 29, 29000, 1)",
            params![
                id(0xE900).as_bytes(),
                fixture.workspace_id.into_uuid().as_bytes(),
                fixture.activity_id.into_uuid().as_bytes(),
                target.id().into_uuid().as_bytes(),
            ],
        )?;
        drop(connection);
    }
    let leased = handoff_request(0xE816, actor, &source, &target, target.revision(), 30)?;
    assert!(reconcile(&mut store, &fixture, &leased).is_err());
    {
        let connection = connection(&fixture)?;
        connection.execute("DELETE FROM writer_leases", [])?;
        drop(connection);
    }

    // A stale timestamp is refused before any write.
    let stale_time = handoff_request(0xE817, actor, &source, &target, target.revision(), 24)?;
    assert!(reconcile(&mut store, &fixture, &stale_time).is_err());

    // A stale target revision is refused by the exact CAS.
    let stale_target = handoff_request(
        0xE818,
        actor,
        &source,
        &target,
        target.revision().checked_next()?,
        30,
    )?;
    assert!(reconcile(&mut store, &fixture, &stale_target).is_err());

    drop(store);
    let connection = connection(&fixture)?;
    assert_eq!(
        count(
            &connection,
            "SELECT COUNT(*) FROM agent_departure_reconciliations"
        )?,
        0,
        "fenced handoffs must not leave receipts"
    );
    assert_eq!(
        count(&connection, "SELECT COUNT(*) FROM agent_focus_events")?,
        2,
        "no target focus transfer may survive a fenced handoff"
    );
    drop(connection);

    let reopened = reopen(&fixture)?;
    assert!(
        reopened
            .get_agent(source.id())?
            .ok_or("source missing")?
            .attachment_state()
            .is_attached()
    );
    assert_eq!(
        reopened
            .get_activity_coordinator(fixture.activity_id)?
            .map(forge_domain::ActivityCoordinatorBinding::agent_id),
        Some(source.id())
    );
    drop(reopened);
    assert_participation_unchanged(&fixture, &baselines)?;
    fs::remove_dir_all(fixture.root)?;
    Ok(())
}

/// Drop every schema object that post-v38 migrations added so the fixture
/// matches the exact historical v38 shape. The later additions include
/// approval-authority freeze fences, Goal watermarks, Assignment offer seals,
/// and the work-cut and continuation journals.
fn drop_post_v38_schema_objects(conn: &Connection) -> Result<(), rusqlite::Error> {
    conn.execute_batch(
        "DROP TABLE IF EXISTS unstarted_activity_continuation_receipts;
        DROP TRIGGER IF EXISTS agent_binding_activations_block_rejection;
        DROP TRIGGER IF EXISTS agent_binding_rejections_block_activation;
        DROP TABLE IF EXISTS agent_binding_rejections;
        DROP TABLE IF EXISTS expired_activity_recovery_agents;
        DROP INDEX IF EXISTS expired_activity_recovery_receipts_successor_uidx;
        DROP TABLE IF EXISTS expired_activity_recovery_receipts;
        DROP TABLE root_recovery_delegation_receipts;
        DROP TABLE recovery_run_executions;
        DROP TABLE recovery_run_activities;
        DROP TABLE recovery_runs;
        DROP TABLE workspace_root_recovery_receipts;",
    )?;
    for (kind, name) in crate::workspace_effect_fact_outbox::base_schema_objects()
        .into_iter()
        .chain(crate::workspace_effect_fact_outbox::change_set_schema_objects())
        .chain(crate::workspace_effect_fact_outbox::work_credit_schema_objects())
        .chain(crate::workspace_effect_fact_outbox::assignment_offered_schema_objects())
        .chain(crate::workspace_effect_fact_outbox::assignment_submitted_schema_objects())
        .chain(crate::workspace_semantic_events::schema_objects())
        .chain(crate::workspace_admission_envelopes::schema_objects())
        .chain(crate::workspace_goal_mutations::schema_objects())
        .chain(crate::workspace_coordinator_recovery::schema_objects())
        .chain(crate::workspace_goal_creation_watermarks::schema_objects())
        .chain(crate::workspace_agent_assignments::offer_seal_schema_objects())
        .chain(crate::workspace_work_cuts::schema_objects())
        .chain(crate::workspace_work_cuts::continuation_schema_objects())
        .chain(crate::workspace_execution_stops::schema_objects())
        .chain(crate::workspace_approvals::cleanup::stop_receipts::schema_objects())
        .chain(crate::workspace_executions::native_closure::schema_objects())
        .chain(crate::workspace_execution_stops::settlement::schema_objects())
        .rev()
    {
        conn.execute_batch(&format!("DROP {kind} {name}"))?;
    }
    for (kind, name) in crate::workspace_agent_migration::approval_authority_schema_objects()
        .into_iter()
        .rev()
    {
        conn.execute_batch(&format!("DROP {kind} {name}"))?;
    }
    Ok(())
}

#[test]
fn departure_reconciliation_survives_v38_to_v39_upgrade() -> TestResult {
    let fixture = fixture("v38-upgrade")?;
    let mut store = reopen(&fixture)?;
    let delegation = delegate_workspace(&mut store, 0xE820, 20)?;
    let agent = delegated_agent(&fixture, &mut store, &delegation, 0xE830, "upgrade-worker")?;
    let delegation = delegation_of(&mut store, &fixture)?;
    drop(store);

    let conn = connection(&fixture)?;
    drop_post_v38_schema_objects(&conn)?;
    conn.execute_batch("ALTER TABLE agent_assignments DROP COLUMN credit_budget")?;
    conn.execute_batch("DROP TABLE agent_departure_reconciliations")?;
    crate::workspace_approvals::rebuild_v55_auto_scopes_fixture(&conn)?;
    conn.pragma_update(None, "user_version", 38_i64)?;
    drop(conn);

    let existing = WorkspaceStateLayout::inspect_existing(fixture.layout.workspace_root())?
        .ok_or("layout missing")?;
    let migrated = WorkspaceStore::open_existing(&existing)?;
    assert_eq!(
        migrated.health()?.schema_version(),
        crate::workspace_store::CURRENT_SCHEMA_VERSION
    );
    assert_eq!(
        migrated.agent_operations_delegation()?,
        Some(delegation),
        "the delegated v38 facts must survive the 38 -> current upgrade"
    );
    assert!(
        migrated
            .agent_departure_reconciliation(id(0xE840))?
            .is_none()
    );
    drop(migrated);

    let conn = connection(&fixture)?;
    let mut statement = conn.prepare("PRAGMA table_info(agent_departure_reconciliations)")?;
    let mut rows = statement.query([])?;
    let mut columns: Vec<(String, String, i64, i64)> = Vec::new();
    while let Some(row) = rows.next()? {
        columns.push((
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, i64>(5)?,
        ));
    }
    drop(rows);
    drop(statement);
    let expected_columns = [
        ("request_id", "BLOB", 1, 1),
        ("migration_id", "BLOB", 1, 0),
        ("workspace_id", "BLOB", 1, 0),
        ("destination_id", "BLOB", 1, 0),
        ("activity_id", "BLOB", 1, 0),
        ("agent_id", "BLOB", 1, 0),
        ("session_id", "BLOB", 1, 0),
        ("kind", "INTEGER", 1, 0),
        ("expected_agent_revision", "INTEGER", 1, 0),
        ("result_agent_revision", "INTEGER", 1, 0),
        ("target_agent_id", "BLOB", 0, 0),
        ("target_session_id", "BLOB", 0, 0),
        ("result_coordinator_revision", "INTEGER", 0, 0),
        ("identity_digest", "BLOB", 1, 0),
        ("reconciled_at_ms", "INTEGER", 1, 0),
    ];
    assert_eq!(columns.len(), expected_columns.len());
    for ((name, data_type, not_null, primary_key), expected) in columns.iter().zip(expected_columns)
    {
        assert_eq!(
            (name.as_str(), data_type.as_str(), *not_null, *primary_key),
            expected
        );
    }
    drop(conn);

    let mut migrated = reopen(&fixture)?;
    let request = detach_request(&agent, 0xE840, 30)?;
    let receipt = reconcile(&mut migrated, &fixture, &request)?;
    drop(migrated);

    let reopened = reopen(&fixture)?;
    assert_eq!(
        reopened.agent_departure_reconciliation(id(0xE840))?,
        Some(receipt),
        "a post-migration receipt must survive reopen"
    );
    assert!(
        reopened
            .get_agent(agent.id())?
            .ok_or("detached Agent missing")?
            .attachment_state()
            .is_detached()
    );
    drop(reopened);
    fs::remove_dir_all(fixture.root)?;
    Ok(())
}
