//! v67 admission identity migration preserves existing durable records.

use super::*;

#[test]
fn schema_v67_admission_identity_migrates_without_changing_workspace_or_activity()
-> Result<(), Box<dyn std::error::Error>> {
    let (root, layout, store, activity_id) = store_with_activity("admission-identity-v67")?;
    let workspace = store.workspace()?;
    let activity = store.get_activity(activity_id)?.ok_or("Activity missing")?;
    drop(store);
    let connection = Connection::open(layout.database_path())?;
    downgrade_admission_identity(&connection)?;
    connection.pragma_update(
        None,
        "user_version",
        super::super::PREVIOUS_ADMISSION_IDENTITY_SCHEMA_VERSION,
    )?;
    drop(connection);
    let existing =
        WorkspaceStateLayout::inspect_existing(layout.workspace_root())?.ok_or("layout missing")?;
    let store = WorkspaceStore::open_existing(&existing)?;
    assert_eq!(store.health()?.schema_version(), CURRENT_SCHEMA_VERSION);
    assert_eq!(store.workspace()?, workspace);
    assert_eq!(store.get_activity(activity_id)?, Some(activity.clone()));
    crate::workspace_admission_envelopes::validate_schema(&store.connection)?;
    assert_eq!(
        store.connection.query_row(
            "SELECT COUNT(*) FROM execution_admission_consumptions",
            [],
            |row| row.get::<_, i64>(0)
        )?,
        0
    );
    drop(store);
    let reopened = WorkspaceStore::open_existing(&existing)?;
    assert_eq!(reopened.get_activity(activity_id)?, Some(activity));
    assert_eq!(reopened.workspace()?, workspace);
    drop(reopened);
    fs::remove_dir_all(root)?;
    Ok(())
}
