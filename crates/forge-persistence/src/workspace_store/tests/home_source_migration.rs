//! The additive v70-to-v71 migration installs empty Home-source and approval
//! provenance journals without changing pre-existing Workspace data.

use super::*;

#[test]
fn schema_v70_migrates_with_empty_home_source_and_preserved_workspace_rows()
-> Result<(), Box<dyn std::error::Error>> {
    let root = unique_root("home-source-v70")?;
    let layout = WorkspaceStateLayout::initialize(&root)?;
    let workspace_command = command(&layout, workspace_id(0x7170), location_id(0x7171), 1)?;
    let mut store = WorkspaceStore::open(&layout, &workspace_command)?;
    let workspace_before = store.workspace()?;
    let activity_id = ActivityId::from_uuid(Uuid::from_u128(0x7172));
    store.create_activity(&CreateActivity::new(
        activity_id,
        workspace_before.id(),
        WorkspaceRevision::INITIAL,
        TimestampMillis::new(2)?,
    ))?;
    let activity_before: (i64, i64, i64) = store.connection.query_row(
        "SELECT created_at_ms, updated_at_ms, revision FROM activities WHERE activity_id=?1",
        params![activity_id.into_uuid().as_bytes()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;

    crate::evaluation_schema_fixture::remove_empty_home_transfer_schema(&store.connection)?;
    store.connection.pragma_update(
        None,
        "user_version",
        PREVIOUS_HOME_TRANSFER_SOURCE_SCHEMA_VERSION,
    )?;
    validate_schema_shape_for_version(&store.connection, WorkspaceSchemaShape::V70)?;
    drop(store);

    let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("Workspace missing")?;
    let migrated = WorkspaceStore::open_existing(&existing)?;
    assert_eq!(migrated.health()?.schema_version(), CURRENT_SCHEMA_VERSION);
    assert_eq!(migrated.workspace()?, workspace_before);
    let activity_after: (i64, i64, i64) = migrated.connection.query_row(
        "SELECT created_at_ms, updated_at_ms, revision FROM activities WHERE activity_id=?1",
        params![activity_id.into_uuid().as_bytes()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    assert_eq!(activity_after, activity_before);

    for (kind, name) in crate::workspace_home_transfers::schema::schema_objects() {
        if kind == "table" {
            let count: i64 = migrated.connection.query_row(
                &format!("SELECT COUNT(*) FROM {name}"),
                [],
                |row| row.get(0),
            )?;
            assert_eq!(count, 0, "migration fabricated rows in {name}");
        }
    }
    for (kind, name, _) in crate::workspace_approvals::agent_provenance::schema::schema_objects() {
        if kind == "table" {
            let count: i64 = migrated.connection.query_row(
                &format!("SELECT COUNT(*) FROM {name}"),
                [],
                |row| row.get(0),
            )?;
            assert_eq!(count, 0, "migration fabricated rows in {name}");
        }
    }
    assert!(
        validate_schema_shape_for_version(&migrated.connection, WorkspaceSchemaShape::V70).is_err(),
        "v70 validation must reject the added v71 objects"
    );
    let mut foreign_keys = migrated.connection.prepare("PRAGMA foreign_key_check")?;
    assert!(foreign_keys.query([])?.next()?.is_none());
    drop(foreign_keys);
    drop(migrated);

    let read_only_report = WorkspaceStore::doctor_existing_read_only(&existing)?;
    assert_eq!(read_only_report.schema_version(), CURRENT_SCHEMA_VERSION);
    fs::remove_dir_all(root)?;
    Ok(())
}
