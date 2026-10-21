//! Settlement is historical evidence plus an exact admission fence release.

use super::*;

fn stop_request(
    store: &WorkspaceStore,
    seed: u128,
) -> Result<crate::ExecutionStopRequest, Box<dyn std::error::Error>> {
    Ok(crate::ExecutionStopRequest::new(
        Uuid::from_u128(seed),
        store.workspace()?.id(),
        Uuid::from_u128(seed + 1),
        RuntimeInstanceId::from_uuid(Uuid::from_u128(seed + 2)),
        [0x60; 32],
        timestamp(20)?,
    ))
}

#[test]
fn settlement_v59_migration_preserves_pending_capture_and_read_only_bytes()
-> Result<(), Box<dyn std::error::Error>> {
    let (root, layout, mut store, _) = store_with_activity("stop-settlement-v59")?;
    let request = stop_request(&store, 0x6041)?;
    let capture = store.capture_owned_workspace_stop(&request)?;
    drop(store);
    let connection = Connection::open(layout.database_path())?;
    remove_stop_settlement_schema(&connection)?;
    connection.pragma_update(None, "user_version", 59)?;
    drop(connection);
    let paths = [
        layout.database_path(),
        super::super::sidecar_path(&layout.database_path(), "-wal"),
        super::super::sidecar_path(&layout.database_path(), "-shm"),
    ];
    let bytes = || -> Result<Vec<Option<Vec<u8>>>, std::io::Error> {
        paths
            .iter()
            .map(|path| match fs::read(path) {
                Ok(bytes) => Ok(Some(bytes)),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(error),
            })
            .collect()
    };
    let before = bytes()?;
    let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("state missing")?;
    assert!(matches!(
        WorkspaceStore::inspect_existing_read_only(&existing),
        Err(WorkspaceStoreError::OutdatedSchema {
            actual: 59,
            current: CURRENT_SCHEMA_VERSION
        })
    ));
    assert_eq!(bytes()?, before);
    let reopened = WorkspaceStore::open_existing(&existing)?;
    let observed = reopened
        .owned_workspace_stop_for_request(&request)?
        .ok_or("capture missing")?;
    assert_eq!(&observed.0, capture.execution().record());
    assert_eq!(&observed.1, capture.authority());
    assert_eq!(observed.0.status(), crate::ExecutionStopStatus::Pending);
    assert_eq!(
        reopened.connection.query_row(
            "SELECT COUNT(*) FROM workspace_execution_stop_settlements",
            [],
            |row| row.get::<_, i64>(0)
        )?,
        0
    );
    assert_eq!(reopened.health()?.schema_version(), CURRENT_SCHEMA_VERSION);
    drop(reopened);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn owned_empty_stop_requires_quiescence_and_supports_historical_replay_and_new_cycle()
-> Result<(), Box<dyn std::error::Error>> {
    let (root, _layout, mut store, _) = store_with_activity("stop-settlement-empty")?;
    let first = stop_request(&store, 0x6001)?;
    let _capture = store.capture_owned_workspace_stop(&first)?;
    let pending = store.settle_owned_workspace_stop(&first, false, timestamp(21)?)?;
    assert_eq!(pending.0.status(), crate::ExecutionStopStatus::Pending);
    let completed = store.settle_owned_workspace_stop(&first, true, timestamp(22)?)?;
    assert_eq!(completed.0.status(), crate::ExecutionStopStatus::Completed);
    let second = stop_request(&store, 0x6011)?;
    let _capture = store.capture_owned_workspace_stop(&second)?;
    assert_eq!(
        store.owned_workspace_stop_for_request(&first)?,
        Some(completed)
    );
    assert_eq!(
        store
            .owned_workspace_stop_for_request(&second)?
            .ok_or("second stop missing")?
            .0
            .status(),
        crate::ExecutionStopStatus::Pending
    );
    drop(store);
    let reopened = WorkspaceStore::open_existing(
        &WorkspaceStateLayout::inspect_existing(&root)?.ok_or("state missing")?,
    )?;
    assert_eq!(
        reopened
            .execution_stop_for_request(&first)?
            .ok_or("history missing")?
            .status(),
        crate::ExecutionStopStatus::Completed
    );
    drop(reopened);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn closed_target_progress_is_immutable_before_whole_fence_release()
-> Result<(), Box<dyn std::error::Error>> {
    let (root, _layout, mut store, event) = journal_execution_fixture("stop-partial-proof")?;
    let request = stop_request(&store, 0x6081)?;
    let _capture = store.capture_owned_workspace_stop(&request)?;
    let before = store
        .get_execution(event.execution_id())?
        .ok_or("execution missing")?;
    store.append_execution_output_events(std::slice::from_ref(&event))?;
    let fact = forge_domain::ExecutionNativeClosureFact::from_parts(
        forge_domain::ExecutionNativeClosureFactParts {
            attribution: forge_domain::ExecutionAttribution::new(
                before.id(),
                before.workspace_id(),
                before.activity_id(),
            ),
            request_digest: before.request_digest(),
            before_revision: before.revision(),
            after_revision: before.revision().checked_next()?,
            output_cursor: forge_domain::ExecutionOutputCursor::from_sequence(
                before.id(),
                event.sequence(),
            ),
            launch: forge_domain::NativeClosureLaunch::Baseline,
            process: forge_domain::NativeClosureProcess::ProcessGroupReaped,
            runtime: forge_domain::NativeClosureRuntime::NotApplicable,
            observed_at: timestamp(21)?,
        },
    )?;
    let _failed = store.fail_execution_with_native_closure(
        forge_domain::FailExecution::new(
            before.id(),
            before.revision(),
            timestamp(21)?,
            forge_domain::ExecutionFailureCode::Supervision,
        ),
        Some(fact),
    )?;
    let partial = store.settle_owned_workspace_stop(&request, false, timestamp(22)?)?;
    assert_eq!(partial.0.status(), crate::ExecutionStopStatus::Pending);
    assert_eq!(
        partial.0.targets()[0].status(),
        crate::ExecutionStopTargetStatus::Closed
    );
    assert_eq!(
        store.connection.query_row(
            "SELECT COUNT(*) FROM workspace_execution_stop_settlements",
            [],
            |row| row.get::<_, i64>(0)
        )?,
        0
    );
    drop(store);
    let layout = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("state missing")?;
    let mut store = WorkspaceStore::open_existing(&layout)?;
    assert_eq!(
        store.owned_workspace_stop_for_request(&request)?,
        Some(partial)
    );
    let completed = store.settle_owned_workspace_stop(&request, true, timestamp(23)?)?;
    assert_eq!(completed.0.status(), crate::ExecutionStopStatus::Completed);
    assert_eq!(
        store.settle_owned_workspace_stop(&request, true, timestamp(24)?)?,
        completed
    );
    store.connection.execute("UPDATE workspace_execution_stop_settlement_targets SET terminal_digest = zeroblob(32) WHERE stop_id = ?1",params![request.stop_id().as_bytes()])?;
    assert!(store.owned_workspace_stop_for_request(&request).is_err());
    drop(store);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn missing_active_fence_cannot_be_mistaken_for_released_stop()
-> Result<(), Box<dyn std::error::Error>> {
    let (root, _layout, mut store, _) = store_with_activity("stop-fence-corrupt")?;
    let request = stop_request(&store, 0x6051)?;
    let _capture = store.capture_owned_workspace_stop(&request)?;
    store.connection.execute(
        "DELETE FROM workspace_execution_stop_fences WHERE stop_id = ?1",
        params![request.stop_id().as_bytes()],
    )?;
    assert!(store.owned_workspace_stop_for_request(&request).is_err());
    assert!(
        store
            .capture_owned_workspace_stop(&stop_request(&store, 0x6061)?)
            .is_err()
    );
    drop(store);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn damaged_complete_settlement_digest_is_not_completed_readback()
-> Result<(), Box<dyn std::error::Error>> {
    let (root, _layout, mut store, _) = store_with_activity("stop-complete-corrupt")?;
    let request = stop_request(&store, 0x6071)?;
    let _capture = store.capture_owned_workspace_stop(&request)?;
    let _completed = store.settle_owned_workspace_stop(&request, true, timestamp(21)?)?;
    store.connection.execute("UPDATE workspace_execution_stop_settlements SET settlement_digest = zeroblob(32) WHERE stop_id = ?1", params![request.stop_id().as_bytes()])?;
    assert!(store.owned_workspace_stop_for_request(&request).is_err());
    drop(store);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn owned_active_target_keeps_fence_even_with_live_quiescence_claim()
-> Result<(), Box<dyn std::error::Error>> {
    let (root, _layout, mut store, event) = journal_execution_fixture("stop-settlement-active")?;
    let request = stop_request(&store, 0x6021)?;
    let _capture = store.capture_owned_workspace_stop(&request)?;
    let result = store.settle_owned_workspace_stop(&request, true, timestamp(21)?)?;
    assert_eq!(result.0.status(), crate::ExecutionStopStatus::Pending);
    assert_eq!(
        result.0.targets()[0].status(),
        crate::ExecutionStopTargetStatus::Pending
    );
    assert_eq!(
        store
            .get_execution(event.execution_id())?
            .ok_or("execution missing")?
            .state(),
        forge_domain::ExecutionState::Running
    );
    let different = stop_request(&store, 0x6031)?;
    assert!(store.capture_owned_workspace_stop(&different).is_err());
    drop(store);
    fs::remove_dir_all(root)?;
    Ok(())
}
