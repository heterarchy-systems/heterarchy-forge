//! Schema v73 gains durable Home assignment lineage without fabricating it for
//! assignments that were already present.

use super::*;

fn downgrade_current_store_to_v73(
    store: &mut WorkspaceStore,
) -> Result<(), Box<dyn std::error::Error>> {
    crate::evaluation_schema_fixture::downgrade_home_assignment_origin_to_v73(&store.connection)?;
    validate_schema_shape_for_version(&store.connection, WorkspaceSchemaShape::V73)?;
    Ok(())
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "end-to-end migration test verifies downgrade, upgrade, foreign keys, and reopen"
)]
fn schema_v73_migration_preserves_ordinary_assignment_and_reopens()
-> Result<(), Box<dyn std::error::Error>> {
    let (root, _layout, mut store, activity_id) = store_with_live_activity("home-handoff-v73")?;
    let workspace_id = store.workspace()?.id();
    let offered = seed_assignment_for_offer_seal_migration(&mut store, workspace_id, activity_id)?;
    let assignment_id = offered.id();
    let running = store.claim_agent_assignment(
        &forge_domain::ClaimAgentAssignment::new(
            offered.id(),
            offered.target(),
            offered.revision(),
            timestamp(8)?,
        ),
        timestamp(99)?,
    )?;
    let agent = store
        .get_agent(running.target().agent_id())?
        .ok_or("target Agent disappeared after claim")?;
    let target = forge_domain::AgentAssignmentTarget::new(
        agent.id(),
        agent.session_id().ok_or("target Session disappeared")?,
        agent.principal(),
        agent.revision(),
    );
    let assignment = store.submit_agent_assignment(
        &forge_domain::SubmitAgentAssignment::new(
            running.id(),
            target,
            running.revision(),
            forge_domain::AgentAssignmentResult::new(
                "Retain the submitted source through migration".to_owned(),
                vec![forge_domain::AgentAssignmentSourceRef::Url(
                    forge_domain::AgentAssignmentSourceUrl::new(
                        "https://example.test/home-handoff-migration".to_owned(),
                    )?,
                )],
                None,
            )?,
            timestamp(9)?,
        ),
        timestamp(99)?,
    )?;
    assert_eq!(
        assignment
            .result()
            .ok_or("submission missing")?
            .sources()
            .len(),
        1
    );
    let legacy_alter_table_before: i64 =
        store
            .connection
            .pragma_query_value(None, "legacy_alter_table", |row| row.get(0))?;
    let dependency_trigger_before: String = store.connection.query_row(
        "SELECT sql FROM sqlite_schema
         WHERE type='trigger' AND name='home_transfer_reservation_retirements_require_unused'",
        [],
        |row| row.get(0),
    )?;

    downgrade_current_store_to_v73(&mut store)?;
    let legacy_alter_table_after_downgrade: i64 =
        store
            .connection
            .pragma_query_value(None, "legacy_alter_table", |row| row.get(0))?;
    assert_eq!(
        legacy_alter_table_after_downgrade,
        legacy_alter_table_before
    );
    let dependency_trigger_after_downgrade: String = store.connection.query_row(
        "SELECT sql FROM sqlite_schema
         WHERE type='trigger' AND name='home_transfer_reservation_retirements_require_unused'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        dependency_trigger_after_downgrade,
        dependency_trigger_before
    );
    drop(store);

    let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("Workspace disappeared")?;
    let migrated = WorkspaceStore::open_existing(&existing)?;
    assert_eq!(migrated.health()?.schema_version(), CURRENT_SCHEMA_VERSION);
    let legacy_alter_table_after_migration: i64 =
        migrated
            .connection
            .pragma_query_value(None, "legacy_alter_table", |row| row.get(0))?;
    assert_eq!(
        legacy_alter_table_after_migration,
        legacy_alter_table_before
    );
    let dependency_trigger_after_migration: String = migrated.connection.query_row(
        "SELECT sql FROM sqlite_schema
         WHERE type='trigger' AND name='home_transfer_reservation_retirements_require_unused'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        dependency_trigger_after_migration,
        dependency_trigger_before
    );
    assert_eq!(
        migrated.get_agent_assignment(assignment_id)?.as_ref(),
        Some(&assignment),
        "a legacy assignment retains its complete record and CoordinatorOffer origin"
    );
    let origin: (i64, Option<Vec<u8>>) = migrated.connection.query_row(
        "SELECT origin_kind, home_receipt_id FROM agent_assignments WHERE assignment_id=?1",
        params![assignment_id.into_uuid().as_bytes()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(origin, (0, None));

    for (kind, name) in crate::workspace_home_transfers::handoffs::schema_objects()
        .into_iter()
        .chain(crate::workspace_home_transfers::home_handoff_application_schema_objects())
    {
        if kind == "table" {
            let count: i64 = migrated.connection.query_row(
                &format!("SELECT COUNT(*) FROM {name}"),
                [],
                |row| row.get(0),
            )?;
            assert_eq!(count, 0, "migration fabricated rows in {name}");
        }
    }
    let mut foreign_keys = migrated.connection.prepare("PRAGMA foreign_key_check")?;
    assert!(foreign_keys.query([])?.next()?.is_none());
    drop(foreign_keys);
    drop(migrated);

    let reopened = WorkspaceStore::open_existing(&existing)?;
    assert_eq!(reopened.health()?.schema_version(), CURRENT_SCHEMA_VERSION);
    let legacy_alter_table_after_reopen: i64 =
        reopened
            .connection
            .pragma_query_value(None, "legacy_alter_table", |row| row.get(0))?;
    assert_eq!(legacy_alter_table_after_reopen, legacy_alter_table_before);
    let dependency_trigger_after_reopen: String = reopened.connection.query_row(
        "SELECT sql FROM sqlite_schema
         WHERE type='trigger' AND name='home_transfer_reservation_retirements_require_unused'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(dependency_trigger_after_reopen, dependency_trigger_before);
    assert_eq!(
        reopened.get_agent_assignment(assignment_id)?.as_ref(),
        Some(&assignment)
    );
    drop(reopened);
    fs::remove_dir_all(root)?;
    Ok(())
}
