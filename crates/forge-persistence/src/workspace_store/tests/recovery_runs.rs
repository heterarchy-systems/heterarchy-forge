//! Recovery history migration must never invent a legacy classification.

use super::*;

#[test]
fn immutable_empty_recovery_history_reopens_and_corruption_fails_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let (root, _layout, mut store, _) = store_with_activity("recovery-history-corrupt")?;
    let binding = store.journal_binding()?;
    let request = crate::RecoveryRunRequest::new(
        (
            Uuid::now_v7(),
            binding.workspace_id(),
            RuntimeInstanceId::from_uuid(Uuid::now_v7()),
        ),
        [0x61; 32],
        binding.recovery_history_digest(),
        forge_domain::RecoveryLeaseDurationMillis::new(5_000)?,
        (timestamp(10)?, timestamp(10)?),
        (
            ActivityListLimit::DEFAULT,
            forge_domain::ExecutionListLimit::DEFAULT,
        ),
    )?;
    let operation = store.run_recovery_request(&binding, &request)?;
    let crate::RecoveryRunOperation::Recorded { receipt, .. } = operation else {
        return Err("new run was not recorded".into());
    };
    assert!(matches!(
        crate::workspace_recovery_runs::get_for_request(
            &store.connection,
            WorkspaceId::from_uuid(Uuid::now_v7()),
            request.request_id,
            request.request_digest,
            request.binding_digest
        ),
        Err(crate::RecoveryRunStoreError::Conflict)
    ));
    drop(store);
    let layout = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("state missing")?;
    let reopened = WorkspaceStore::open_existing(&layout)?;
    let binding = reopened.journal_binding()?;
    assert_eq!(
        reopened.recovery_run_for_request(&binding, request.request_id, request.request_digest)?,
        Some(receipt)
    );
    reopened.connection.execute(
        "UPDATE recovery_runs SET receipt_digest=zeroblob(32) WHERE request_id=?1",
        params![request.request_id.as_bytes()],
    )?;
    assert!(
        reopened
            .recovery_run_for_request(&binding, request.request_id, request.request_digest)
            .is_err()
    );
    drop(reopened);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn recovery_history_v60_migration_is_empty_and_readonly_preserves_bytes()
-> Result<(), Box<dyn std::error::Error>> {
    let (root, layout, store, _) = store_with_activity("recovery-history-v60")?;
    let original_lease = store.get_recovery_maintenance_lease()?;
    drop(store);
    let connection = Connection::open(layout.database_path())?;
    remove_recovery_runs_schema(&connection)?;
    connection.pragma_update(None, "user_version", 60)?;
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
            actual: 60,
            current: CURRENT_SCHEMA_VERSION
        })
    ));
    assert_eq!(bytes()?, before);
    let migrated = WorkspaceStore::open_existing(&existing)?;
    assert_eq!(migrated.health()?.schema_version(), CURRENT_SCHEMA_VERSION);
    assert_eq!(migrated.get_recovery_maintenance_lease()?, original_lease);
    assert_eq!(
        migrated
            .connection
            .query_row("SELECT COUNT(*) FROM recovery_runs", [], |row| row
                .get::<_, i64>(0))?,
        0
    );
    drop(migrated);
    fs::remove_dir_all(root)?;
    Ok(())
}
