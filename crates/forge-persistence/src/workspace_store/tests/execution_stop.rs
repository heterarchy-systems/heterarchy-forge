//! Stop capture is durable admission evidence, never native terminal evidence.

use super::*;

fn stop_request(
    store: &WorkspaceStore,
) -> Result<crate::ExecutionStopRequest, Box<dyn std::error::Error>> {
    Ok(crate::ExecutionStopRequest::new(
        Uuid::from_u128(0x5701),
        store.workspace()?.id(),
        Uuid::from_u128(0x5702),
        RuntimeInstanceId::from_uuid(Uuid::from_u128(0x5703)),
        [0x57; 32],
        timestamp(20)?,
    ))
}

#[test]
fn stop_capture_survives_binding_loss_and_reopen_without_terminalizing_execution()
-> Result<(), Box<dyn std::error::Error>> {
    let (root, layout, mut store, event) = journal_execution_fixture("stop-postcommit-binding")?;
    let request = stop_request(&store)?;
    let before = store
        .get_execution(event.execution_id())?
        .ok_or("execution missing")?;
    let moved_state = root.join("stop-state-moved");
    let mut move_result = Ok(());
    let outcome = store.capture_execution_stop_with_postcommit_hook(&request, |store| {
        move_result = fs::rename(&store.state_root, &moved_state);
    });
    move_result?;
    fs::rename(&moved_state, &store.state_root)?;
    assert!(matches!(
        outcome,
        Err(WorkspaceStoreError::ExecutionStopCommittedUnconfirmed { .. })
    ));
    let record = store
        .execution_stop_for_request(&request)?
        .ok_or("captured stop missing")?;
    assert_eq!(record.targets().len(), 1);
    assert_eq!(record.targets()[0].execution_id(), event.execution_id());
    assert_eq!(
        store.get_execution(event.execution_id())?,
        Some(before.clone())
    );
    assert_eq!(
        store.state_removal_blocker(request.workspace_id())?,
        Some(WorkspaceStateRemovalBlocker::PendingExecutionStop)
    );
    drop(store);
    let existing =
        WorkspaceStateLayout::inspect_existing(layout.workspace_root())?.ok_or("layout missing")?;
    let reopened = WorkspaceStore::open_existing(&existing)?;
    assert_eq!(reopened.execution_stop_for_request(&request)?, Some(record));
    assert_eq!(reopened.get_execution(event.execution_id())?, Some(before));
    drop(reopened);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn stop_capture_commit_failure_requires_readback_and_preserves_empty_journal()
-> Result<(), Box<dyn std::error::Error>> {
    let (root, _layout, mut store, _) = store_with_activity("stop-commit-unknown")?;
    let request = stop_request(&store)?;
    store.connection.execute_batch(
        "CREATE TEMP TABLE stop_commit_parent(id INTEGER PRIMARY KEY);
         CREATE TEMP TABLE stop_commit_child(parent_id INTEGER REFERENCES stop_commit_parent(id)
             DEFERRABLE INITIALLY DEFERRED);
         CREATE TEMP TRIGGER stop_commit_guard AFTER INSERT ON workspace_execution_stops
         BEGIN INSERT INTO stop_commit_child(parent_id) VALUES (99); END;",
    )?;
    assert!(matches!(
        store.capture_execution_stop(&request),
        Err(WorkspaceStoreError::ExecutionStopCommittedUnconfirmed { .. })
    ));
    assert!(store.execution_stop_for_request(&request)?.is_none());
    drop(store);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn schema_v56_adds_empty_stop_journal_and_preserves_running_execution()
-> Result<(), Box<dyn std::error::Error>> {
    let (root, layout, store, event) = journal_execution_fixture("stop-v56-migration")?;
    let execution_id = event.execution_id();
    let before = store
        .get_execution(execution_id)?
        .ok_or("execution missing")?;
    drop(store);
    let connection = Connection::open(layout.database_path())?;
    remove_execution_stop_schema(&connection)?;
    connection.pragma_update(
        None,
        "user_version",
        super::super::PREVIOUS_EXECUTION_STOPS_SCHEMA_VERSION,
    )?;
    drop(connection);
    let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
    assert!(matches!(
        WorkspaceStore::inspect_existing_read_only(&existing),
        Err(WorkspaceStoreError::OutdatedSchema {
            actual: 56,
            current: CURRENT_SCHEMA_VERSION
        })
    ));
    let connection = Connection::open(layout.database_path())?;
    assert_eq!(super::super::schema_version(&connection)?, 56);
    drop(connection);
    let store = WorkspaceStore::open_existing(&existing)?;
    assert_eq!(store.health()?.schema_version(), CURRENT_SCHEMA_VERSION);
    assert_eq!(store.get_execution(execution_id)?, Some(before));
    let count: i64 = store.connection.query_row(
        "SELECT COUNT(*) FROM workspace_execution_stops",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 0, "migration cannot fabricate a stop owner");
    drop(store);
    let reopened = WorkspaceStore::open_existing(&existing)?;
    assert_eq!(reopened.health()?.schema_version(), CURRENT_SCHEMA_VERSION);
    drop(reopened);
    fs::remove_dir_all(root)?;
    Ok(())
}
