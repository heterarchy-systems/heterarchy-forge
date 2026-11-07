//! The additive v69-to-v70 migration creates empty source-evidence journals.

use super::*;

#[test]
fn schema_v69_migrates_without_fabricating_evaluation_provenance()
-> Result<(), Box<dyn std::error::Error>> {
    let root = unique_root("evaluation-evidence-v69")?;
    let layout = WorkspaceStateLayout::initialize(&root)?;
    let workspace_command = command(&layout, workspace_id(0xEE70), location_id(0xEE71), 1)?;
    let store = WorkspaceStore::open(&layout, &workspace_command)?;
    let workspace_before = store.workspace()?;

    crate::evaluation_schema_fixture::remove_empty_home_transfer_schema(&store.connection)?;
    for (kind, name) in crate::workspace_evaluation_evidence::schema_objects()
        .into_iter()
        .rev()
    {
        store
            .connection
            .execute_batch(&format!("DROP {kind} IF EXISTS {name}"))?;
    }
    store.connection.pragma_update(
        None,
        "user_version",
        PREVIOUS_EVALUATION_EVIDENCE_SCHEMA_VERSION,
    )?;
    drop(store);

    let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("Workspace missing")?;
    let migrated = WorkspaceStore::open_existing(&existing)?;
    assert_eq!(migrated.health()?.schema_version(), CURRENT_SCHEMA_VERSION);
    assert_eq!(migrated.workspace()?, workspace_before);

    for (kind, name) in crate::workspace_evaluation_evidence::schema_objects() {
        if kind != "table" {
            continue;
        }
        let count: i64 =
            migrated
                .connection
                .query_row(&format!("SELECT COUNT(*) FROM {name}"), [], |row| {
                    row.get(0)
                })?;
        assert_eq!(count, 0, "migration fabricated rows in {name}");
    }

    drop(migrated);
    fs::remove_dir_all(root)?;
    Ok(())
}
