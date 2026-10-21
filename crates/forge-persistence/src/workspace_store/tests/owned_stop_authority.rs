//! Atomic stop journal/authority evidence through real Workspace SQLite.

use super::*;
use forge_domain::{
    ApprovalRequestId, AutoApprovalScope, AutoApprovalScopeId, AutoApprovalScopeRevision,
    AutoApprovalUseLimit, ExecutionActionClass, ExecutionAuthorizationRequest, ExecutionGrantId,
    ExecutionId, ExecutionPermissions, ExecutionRequestDigest, RegisteredApprovalRequest,
    RequestedExecutionPermissions,
};

fn seed_authority(
    store: &mut WorkspaceStore,
    activity: ActivityId,
) -> Result<ApprovalRequestId, Box<dyn std::error::Error>> {
    let workspace_id = store.workspace()?.id();
    let policy = store.ensure_workspace_policy(timestamp(3)?)?;
    let mut pending_id = None;
    for seed in [0x5801_u128, 0x5811] {
        let request = RegisteredApprovalRequest::pending(
            ApprovalRequestId::from_uuid(Uuid::from_u128(seed)),
            ExecutionAuthorizationRequest::new(
                ExecutionId::from_uuid(Uuid::from_u128(seed + 1)),
                workspace_id,
                activity,
                ExecutionRequestDigest::from_bytes([0x58; 32]),
                ExecutionActionClass::DirectStructured,
                RequestedExecutionPermissions::new(ExecutionPermissions::new(false, false, false)),
            ),
            policy.revision(),
            timestamp(3)?,
            timestamp(100)?,
        )?;
        let inserted = store.insert_pending_approval(&request)?;
        if seed == 0x5811 {
            let _approved = store.approve_once(
                inserted.id(),
                inserted.revision(),
                ExecutionGrantId::from_uuid(Uuid::from_u128(0x5813)),
                timestamp(4)?,
                timestamp(90)?,
            )?;
        } else {
            pending_id = Some(inserted.id());
        }
    }
    let scope = AutoApprovalScope::active(
        AutoApprovalScopeId::from_uuid(Uuid::from_u128(0x5821)),
        workspace_id,
        None,
        ExecutionActionClass::DiscoveredProjectCommand,
        ExecutionPermissions::new(false, false, false),
        policy.revision(),
        timestamp(100)?,
        AutoApprovalUseLimit::new(5)?,
        AutoApprovalScopeRevision::INITIAL,
    )?;
    let _scope = store.create_auto_approval_scope(&scope, timestamp(3)?)?;
    pending_id.ok_or_else(|| "pending id missing".into())
}

fn request(
    store: &WorkspaceStore,
) -> Result<crate::ExecutionStopRequest, Box<dyn std::error::Error>> {
    Ok(crate::ExecutionStopRequest::new(
        Uuid::from_u128(0x5831),
        store.workspace()?.id(),
        Uuid::from_u128(0x5832),
        RuntimeInstanceId::from_uuid(Uuid::from_u128(0x5833)),
        [0x58; 32],
        timestamp(20)?,
    ))
}

#[test]
fn owned_stop_atomically_captures_execution_and_three_authority_families_and_reopens()
-> Result<(), Box<dyn std::error::Error>> {
    let (root, layout, mut store, event) = journal_execution_fixture("owned-stop-atomic")?;
    let activity = store
        .get_execution(event.execution_id())?
        .ok_or("execution missing")?
        .activity_id();
    let pending = seed_authority(&mut store, activity)?;
    let request = request(&store)?;
    let captured = store.capture_owned_workspace_stop(&request)?;
    assert_eq!(captured.execution().record().targets().len(), 1);
    assert_eq!(captured.authority().target_count(), 3);
    assert_eq!(
        store
            .get_approval_request(pending)?
            .ok_or("pending missing")?
            .state(),
        forge_domain::ApprovalRequestState::Cancelled
    );
    let original = store
        .owned_workspace_stop_for_request(&request)?
        .ok_or("receipt missing")?;
    let replay = store.capture_owned_workspace_stop(&request)?;
    assert_eq!(replay.authority(), captured.authority());
    assert_eq!(replay.execution().record(), captured.execution().record());
    drop(store);
    let existing =
        WorkspaceStateLayout::inspect_existing(layout.workspace_root())?.ok_or("layout missing")?;
    let reopened = WorkspaceStore::open_existing(&existing)?;
    assert_eq!(
        reopened.owned_workspace_stop_for_request(&request)?,
        Some(original)
    );
    drop(reopened);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn owned_stop_commit_failure_rolls_back_authority_and_both_receipt_ledgers()
-> Result<(), Box<dyn std::error::Error>> {
    let (root, _layout, mut store, activity) = store_with_activity("owned-stop-commit")?;
    let pending = seed_authority(&mut store, activity)?;
    let before = store.get_approval_request(pending)?;
    let request = request(&store)?;
    store.connection.execute_batch("CREATE TEMP TABLE owned_stop_parent(id INTEGER PRIMARY KEY);
        CREATE TEMP TABLE owned_stop_child(parent_id INTEGER REFERENCES owned_stop_parent(id) DEFERRABLE INITIALLY DEFERRED);
        CREATE TEMP TRIGGER owned_stop_commit_guard AFTER INSERT ON authority_stop_batches
        BEGIN INSERT INTO owned_stop_child(parent_id) VALUES (99); END;")?;
    let result = store.capture_owned_workspace_stop(&request);
    assert!(matches!(
        result,
        Err(WorkspaceStoreError::ExecutionStopCommittedUnconfirmed { .. })
    ));
    assert_eq!(store.get_approval_request(pending)?, before);
    assert!(store.owned_workspace_stop_for_request(&request)?.is_none());
    let count: i64 = store.connection.query_row("SELECT (SELECT COUNT(*) FROM workspace_execution_stops)+(SELECT COUNT(*) FROM authority_stop_batches)+(SELECT COUNT(*) FROM authority_stop_targets)", [], |row| row.get(0))?;
    assert_eq!(count, 0);
    drop(store);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn owned_stop_rejects_execution_only_mode_upgrade() -> Result<(), Box<dyn std::error::Error>> {
    let (root, _layout, mut store, activity) = store_with_activity("owned-stop-mode")?;
    let pending = seed_authority(&mut store, activity)?;
    let request = request(&store)?;
    let before = store.get_approval_request(pending)?;
    let _execution_only = store.capture_execution_stop(&request)?;
    assert!(store.capture_owned_workspace_stop(&request).is_err());
    assert_eq!(store.get_approval_request(pending)?, before);
    drop(store);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn owned_stop_readback_rejects_changed_canonical_after_row_and_deleted_last_target()
-> Result<(), Box<dyn std::error::Error>> {
    let (root, _layout, mut store, activity) = store_with_activity("owned-stop-drift")?;
    let pending = seed_authority(&mut store, activity)?;
    let request = request(&store)?;
    let _capture = store.capture_owned_workspace_stop(&request)?;
    store.connection.execute(
        "UPDATE approval_requests SET request_digest = ?1 WHERE approval_id = ?2",
        params![[0x99_u8; 32].as_slice(), pending.into_uuid().as_bytes()],
    )?;
    assert!(store.owned_workspace_stop_for_request(&request).is_err());
    store.connection.execute(
        "UPDATE approval_requests SET request_digest = ?1 WHERE approval_id = ?2",
        params![[0x58_u8; 32].as_slice(), pending.into_uuid().as_bytes()],
    )?;
    assert!(store.owned_workspace_stop_for_request(&request)?.is_some());
    store
        .connection
        .execute("UPDATE authority_stop_batches SET observed_at_ms = 21", [])?;
    assert!(store.owned_workspace_stop_for_request(&request).is_err());
    store
        .connection
        .execute("UPDATE authority_stop_batches SET observed_at_ms = 20", [])?;
    assert!(store.owned_workspace_stop_for_request(&request)?.is_some());
    store.connection.execute("DELETE FROM authority_stop_targets WHERE ordinal = (SELECT MAX(ordinal) FROM authority_stop_targets)", [])?;
    assert!(store.owned_workspace_stop_for_request(&request).is_err());
    drop(store);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn owned_stop_fences_new_approval_grant_and_auto_scope_without_changing_existing_replay()
-> Result<(), Box<dyn std::error::Error>> {
    let (root, _layout, mut store, activity) = store_with_activity("owned-stop-fresh-authority")?;
    let workspace_id = store.workspace()?.id();
    let policy = store.ensure_workspace_policy(timestamp(3)?)?;
    let pending = RegisteredApprovalRequest::pending(
        ApprovalRequestId::from_uuid(Uuid::from_u128(0x58A1)),
        ExecutionAuthorizationRequest::new(
            ExecutionId::from_uuid(Uuid::from_u128(0x58A2)),
            workspace_id,
            activity,
            ExecutionRequestDigest::from_bytes([0x58; 32]),
            ExecutionActionClass::DirectStructured,
            RequestedExecutionPermissions::new(ExecutionPermissions::new(false, false, false)),
        ),
        policy.revision(),
        timestamp(3)?,
        timestamp(100)?,
    )?;
    let old = store.insert_pending_approval(&pending)?;
    let request = request(&store)?;
    let _capture = store.capture_owned_workspace_stop(&request)?;
    let replay = store.insert_pending_approval(&pending)?;
    assert_eq!(
        replay.state(),
        forge_domain::ApprovalRequestState::Cancelled
    );
    let fresh = RegisteredApprovalRequest::pending(
        ApprovalRequestId::from_uuid(Uuid::from_u128(0x58B1)),
        ExecutionAuthorizationRequest::new(
            ExecutionId::from_uuid(Uuid::from_u128(0x58B2)),
            workspace_id,
            activity,
            ExecutionRequestDigest::from_bytes([0x58; 32]),
            ExecutionActionClass::DirectStructured,
            RequestedExecutionPermissions::new(ExecutionPermissions::new(false, false, false)),
        ),
        policy.revision(),
        timestamp(21)?,
        timestamp(100)?,
    )?;
    assert!(store.insert_pending_approval(&fresh).is_err());
    assert!(
        store
            .approve_once(
                old.id(),
                old.revision(),
                ExecutionGrantId::from_uuid(Uuid::from_u128(0x58C1)),
                timestamp(22)?,
                timestamp(90)?
            )
            .is_err()
    );
    let scope = AutoApprovalScope::active(
        AutoApprovalScopeId::from_uuid(Uuid::from_u128(0x58D1)),
        workspace_id,
        None,
        ExecutionActionClass::DiscoveredProjectCommand,
        ExecutionPermissions::new(false, false, false),
        policy.revision(),
        timestamp(100)?,
        AutoApprovalUseLimit::new(5)?,
        AutoApprovalScopeRevision::INITIAL,
    )?;
    assert!(
        store
            .create_auto_approval_scope(&scope, timestamp(22)?)
            .is_err()
    );
    assert!(store.get_approval_request(fresh.id())?.is_none());
    assert!(store.get_auto_approval_scope(scope.id())?.is_none());
    drop(store);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn schema_v57_preserves_execution_only_stop_without_fabricating_authority_receipts()
-> Result<(), Box<dyn std::error::Error>> {
    let (root, layout, mut store, _activity) = store_with_activity("owned-stop-v57")?;
    let request = request(&store)?;
    let before = store.capture_execution_stop(&request)?.record().clone();
    drop(store);
    let connection = Connection::open(layout.database_path())?;
    remove_stop_settlement_schema(&connection)?;
    connection
        .execute_batch("DROP TABLE execution_native_closures; DROP TABLE authority_stop_targets; DROP TABLE authority_stop_batches;")?;
    connection.pragma_update(None, "user_version", 57)?;
    drop(connection);
    let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
    assert!(matches!(
        WorkspaceStore::inspect_existing_read_only(&existing),
        Err(WorkspaceStoreError::OutdatedSchema {
            actual: 57,
            current: CURRENT_SCHEMA_VERSION
        })
    ));
    let connection = Connection::open(layout.database_path())?;
    assert_eq!(super::super::schema_version(&connection)?, 57);
    drop(connection);
    let mut reopened = WorkspaceStore::open_existing(&existing)?;
    assert_eq!(reopened.execution_stop_for_request(&request)?, Some(before));
    let count: i64 = reopened.connection.query_row(
        "SELECT COUNT(*) FROM authority_stop_batches",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 0);
    assert!(reopened.capture_owned_workspace_stop(&request).is_err());
    drop(reopened);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn owned_stop_postcommit_state_move_requires_original_combined_receipt_readback()
-> Result<(), Box<dyn std::error::Error>> {
    let (root, layout, mut store, activity) = store_with_activity("owned-stop-postcommit")?;
    let pending = seed_authority(&mut store, activity)?;
    let request = request(&store)?;
    let moved = root.join("owned-stop-moved-state");
    let mut relocation = Ok(());
    let result = store.capture_owned_workspace_stop_with_postcommit_hook(&request, |store| {
        relocation = fs::rename(&store.state_root, &moved);
    });
    relocation?;
    fs::rename(&moved, &store.state_root)?;
    assert!(matches!(
        result,
        Err(WorkspaceStoreError::ExecutionStopCommittedUnconfirmed { .. })
    ));
    let observed = store
        .owned_workspace_stop_for_request(&request)?
        .ok_or("combined receipt missing")?;
    assert_eq!(observed.1.target_count(), 3);
    assert_eq!(
        store
            .get_approval_request(pending)?
            .ok_or("approval missing")?
            .state(),
        forge_domain::ApprovalRequestState::Cancelled
    );
    drop(store);
    let existing =
        WorkspaceStateLayout::inspect_existing(layout.workspace_root())?.ok_or("layout missing")?;
    let reopened = WorkspaceStore::open_existing(&existing)?;
    assert_eq!(
        reopened.owned_workspace_stop_for_request(&request)?,
        Some(observed)
    );
    drop(reopened);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn owned_stop_overflow_rejects_before_any_fence_or_authority_write()
-> Result<(), Box<dyn std::error::Error>> {
    let (root, _layout, mut store, activity) = store_with_activity("owned-stop-overflow")?;
    let pending = seed_authority(&mut store, activity)?;
    let before = store.get_approval_request(pending)?;
    let workspace_id = store.workspace()?.id();
    let policy = store.get_workspace_policy()?.ok_or("policy missing")?;
    for index in 0..256_u128 {
        let seed = 0x5900 + index * 2;
        let request = RegisteredApprovalRequest::pending(
            ApprovalRequestId::from_uuid(Uuid::from_u128(seed)),
            ExecutionAuthorizationRequest::new(
                ExecutionId::from_uuid(Uuid::from_u128(seed + 1)),
                workspace_id,
                activity,
                ExecutionRequestDigest::from_bytes([0x59; 32]),
                ExecutionActionClass::DirectStructured,
                RequestedExecutionPermissions::new(ExecutionPermissions::new(false, false, false)),
            ),
            policy.revision(),
            timestamp(3)?,
            timestamp(100)?,
        )?;
        let _pending = store.insert_pending_approval(&request)?;
    }
    let request = request(&store)?;
    assert!(matches!(
        store.capture_owned_workspace_stop(&request),
        Err(WorkspaceStoreError::Approval(
            crate::ApprovalStoreError::CleanupLimitExceeded
        ))
    ));
    assert!(store.owned_workspace_stop_for_request(&request)?.is_none());
    assert_eq!(store.get_approval_request(pending)?, before);
    let count: i64 = store.connection.query_row("SELECT (SELECT COUNT(*) FROM workspace_execution_stops)+(SELECT COUNT(*) FROM authority_stop_batches)+(SELECT COUNT(*) FROM authority_stop_targets)", [], |row| row.get(0))?;
    assert_eq!(count, 0);
    drop(store);
    fs::remove_dir_all(root)?;
    Ok(())
}
