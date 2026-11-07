//! Real legacy Source snapshot preservation across the additive artifact schema.
use super::*;

#[test]
fn populated_v72_source_migrates_without_inventing_artifacts()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = fixture("home-artifact-v72", 0xA730)?;
    let request = one_agent_request(&fixture, 0xA740, 0x71)?;
    let grant = source_grant(
        &request,
        fixture.issuer,
        HomeTransferSourceAction::Prepare,
        250,
        400,
    )?;
    let prepared = fixture.store.prepare_home_transfer_source(
        &request,
        grant,
        fixture.issuer,
        fixture.backend,
        fixture.delegation.destination_id(),
        || source_clock(300),
    )?;
    let original = prepared.record().to_snapshot_bytes()?;
    let workspace = fixture.store.workspace()?;
    crate::evaluation_schema_fixture::remove_empty_home_artifact_schema_objects(
        &fixture.store.connection,
    )?;
    fixture
        .store
        .connection
        .pragma_update(None, "user_version", 72_i64)?;
    validate_schema_shape_for_version(&fixture.store.connection, WorkspaceSchemaShape::V72)?;
    drop(fixture.store);

    let existing =
        WorkspaceStateLayout::inspect_existing(&fixture.root)?.ok_or("layout missing")?;
    let report = WorkspaceStore::doctor_existing_read_only(&existing)?;
    assert_eq!(report.schema_version(), 72);
    assert!(report.home_artifact_references().references().is_empty());
    let read_only = Connection::open(existing.database_path())?;
    assert_eq!(read_only.query_row(
        "SELECT COUNT(*) FROM sqlite_schema WHERE name IN ('home_transfer_artifact_stages','home_transfer_artifact_seals')",
        [], |row| row.get::<_, i64>(0),
    )?, 0);
    drop(read_only);

    let store = WorkspaceStore::open_existing(&existing)?;
    assert_eq!(store.health()?.schema_version(), CURRENT_SCHEMA_VERSION);
    assert_eq!(store.workspace()?, workspace);
    let record = store
        .get_home_transfer_source(
            request.witness().preparation_id(),
            fixture.issuer,
            fixture.backend,
            fixture.delegation.destination_id(),
        )?
        .ok_or("original Prepared missing")?;
    assert_eq!(record.to_snapshot_bytes()?, original);
    crate::workspace_home_transfers::artifacts::schema::validate_schema(&store.connection)?;
    let count: i64 = store.connection.query_row(
        "SELECT (SELECT COUNT(*) FROM home_transfer_artifact_stages)+(SELECT COUNT(*) FROM home_transfer_artifact_seals)",
        [], |row| row.get(0),
    )?;
    assert_eq!(count, 0, "migration must not fabricate a capture or seal");
    assert!(
        validate_schema_shape_for_version(&store.connection, WorkspaceSchemaShape::V72).is_err()
    );
    assert!(
        store
            .connection
            .prepare("PRAGMA foreign_key_check")?
            .query([])?
            .next()?
            .is_none()
    );
    drop(store);
    let reopened = WorkspaceStore::open_existing(&existing)?;
    assert_eq!(reopened.workspace()?, workspace);
    drop(reopened);
    fs::remove_dir_all(fixture.root)?;
    Ok(())
}
