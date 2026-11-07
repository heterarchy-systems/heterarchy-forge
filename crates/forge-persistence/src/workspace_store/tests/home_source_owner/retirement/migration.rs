use super::*;
use crate::workspace_store::{
    PREVIOUS_HOME_TRANSFER_RESERVATION_RETIREMENT_SCHEMA_VERSION, ReadOnlyDoctorDatabase,
    schema_version,
};

type BlobRows = Vec<Vec<Vec<u8>>>;

#[derive(Debug, PartialEq, Eq)]
struct SourceFenceRows {
    subjects: BlobRows,
    sessions: BlobRows,
    agents: BlobRows,
    activities: BlobRows,
}

fn blob_rows(
    connection: &rusqlite::Connection,
    sql: &str,
    column_count: usize,
) -> Result<BlobRows, rusqlite::Error> {
    let mut statement = connection.prepare(sql)?;
    let mut rows = statement.query([])?;
    let mut result = Vec::new();
    while let Some(row) = rows.next()? {
        result.push(
            (0..column_count)
                .map(|column| row.get::<_, Vec<u8>>(column))
                .collect::<Result<Vec<_>, _>>()?,
        );
    }
    Ok(result)
}

fn source_fences(connection: &rusqlite::Connection) -> Result<SourceFenceRows, rusqlite::Error> {
    Ok(SourceFenceRows {
        subjects: blob_rows(
            connection,
            "SELECT workspace_id,target_profile_id,target_participation_id,preparation_id
             FROM home_transfer_source_subjects
             ORDER BY workspace_id,target_profile_id,target_participation_id,preparation_id",
            4,
        )?,
        sessions: blob_rows(
            connection,
            "SELECT workspace_id,session_id,preparation_id
             FROM home_transfer_source_sessions
             ORDER BY workspace_id,session_id,preparation_id",
            3,
        )?,
        agents: blob_rows(
            connection,
            "SELECT workspace_id,agent_id,preparation_id
             FROM home_transfer_source_agents
             ORDER BY workspace_id,agent_id,preparation_id",
            3,
        )?,
        activities: blob_rows(
            connection,
            "SELECT workspace_id,activity_id,preparation_id
             FROM home_transfer_source_activities
             ORDER BY workspace_id,activity_id,preparation_id",
            3,
        )?,
    })
}

fn assert_foreign_keys_clean(connection: &rusqlite::Connection) -> TestResult<()> {
    let mut statement = connection.prepare("PRAGMA foreign_key_check")?;
    if statement.query([])?.next()?.is_some() {
        return Err("foreign_key_check reported a row".into());
    }
    Ok(())
}

fn source_parent(
    fixture: &Fixture,
    preparation_id: Uuid,
) -> TestResult<crate::HomeTransferSourceRecord> {
    fixture
        .store
        .get_home_transfer_source(
            preparation_id,
            fixture.issuer,
            fixture.backend,
            fixture.delegation.destination_id(),
        )?
        .ok_or_else(|| "original Prepared source disappeared".into())
}

#[allow(
    clippy::too_many_lines,
    reason = "One regression follows the durable record across schema boundaries."
)]
#[test]
fn populated_v71_to_v72_preserves_v1_prepared_source_and_allows_retirement() -> TestResult<()> {
    let mut fixture = fixture("home-source-v71-v72-populated", 0xA700)?;
    let selected = pending_reservation(&mut fixture, 0xA710, AuthenticatedPrincipal::TrustedStdio)?;
    let unrelated =
        pending_reservation(&mut fixture, 0xA720, AuthenticatedPrincipal::TrustedStdio)?;
    let current_parent = prepare_parent(&mut fixture, 0xA730, &selected, &[])?;
    let preparation_id = current_parent.request().witness().preparation_id();
    let workspace_before = fixture.store.workspace()?;
    let fences_before = source_fences(&fixture.store.connection)?;
    assert_eq!(
        fixture
            .store
            .agent_binding_reservation(selected.request().request_id())?,
        Some(selected.clone()),
    );
    assert_eq!(
        fixture
            .store
            .agent_binding_reservation(unrelated.request().request_id())?,
        Some(unrelated.clone()),
    );
    let parent = crate::workspace_home_transfers::legacy_fixture::install_v1_prepared_record(
        &mut fixture.store.connection,
        &current_parent,
    )?;

    assert_eq!(parent.state(), crate::HomeTransferSourceState::Prepared);
    let capsule = parent
        .inventory_payload()
        .ok_or("synthetic v1 Prepared record is missing its capsule")?;
    assert!(
        capsule.starts_with(b"FHTI\x01\x01"),
        "fixture must use inventory v1"
    );
    assert!(
        capsule.len() > 64,
        "fixture must contain a populated inventory"
    );
    assert_ne!(
        parent, current_parent,
        "fixture must not relabel the v2 record"
    );
    assert!(
        parent
            .captured_pending_binding_reservation_ids()?
            .contains(&selected.request().request_id()),
        "the historical v1 capsule must retain the selected Pending reservation",
    );
    let parent_bytes = parent.to_snapshot_bytes()?;
    assert_eq!(source_parent(&fixture, preparation_id)?, parent);
    assert_eq!(source_fences(&fixture.store.connection)?, fences_before);
    assert_eq!(
        fixture
            .store
            .agent_binding_reservation(selected.request().request_id())?,
        Some(selected.clone()),
        "v1 fixture substitution must preserve the native pending reservation",
    );
    assert_eq!(
        fixture
            .store
            .agent_binding_reservation(unrelated.request().request_id())?,
        Some(unrelated.clone()),
    );
    assert_eq!(fences_before.subjects.len(), 1);
    assert_eq!(fences_before.sessions.len(), 2);
    assert_eq!(fences_before.agents.len(), 1);
    assert_eq!(fences_before.activities.len(), 1);
    let source_agent_id = fixture.agent.id().into_uuid();
    assert!(
        fences_before.agents.iter().any(|row| {
            row.get(1)
                .is_some_and(|agent| agent.as_slice() == source_agent_id.as_bytes())
        }),
        "the existing Source Agent fence must be populated",
    );
    assert_eq!(
        fixture
            .store
            .agent_binding_reservation(selected.request().request_id())?,
        Some(selected.clone()),
    );
    assert_eq!(
        fixture
            .store
            .agent_binding_reservation(unrelated.request().request_id())?,
        Some(unrelated.clone()),
    );

    let retirement_table = crate::workspace_home_transfers::retirements::schema::RETIREMENTS_TABLE;
    let empty_retirements: i64 = fixture.store.connection.query_row(
        "SELECT COUNT(*) FROM home_transfer_reservation_retirements",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(empty_retirements, 0);
    crate::evaluation_schema_fixture::remove_empty_home_reservation_retirement_schema_objects(
        &fixture.store.connection,
    )?;
    fixture.store.connection.pragma_update(
        None,
        "user_version",
        PREVIOUS_HOME_TRANSFER_RESERVATION_RETIREMENT_SCHEMA_VERSION,
    )?;
    validate_schema_shape_for_version(&fixture.store.connection, WorkspaceSchemaShape::V71)?;
    assert!(
        validate_schema_shape_for_version(&fixture.store.connection, WorkspaceSchemaShape::Current)
            .is_err(),
        "the v71 fixture must not already contain v72 schema objects",
    );

    drop(fixture.store);
    let existing = WorkspaceStateLayout::inspect_existing(&fixture.root)?
        .ok_or("Workspace missing before v71 read-only check")?;
    let read_only_report = WorkspaceStore::doctor_existing_read_only(&existing)?;
    assert_eq!(read_only_report.schema_version(), 71);
    let read_only_database = ReadOnlyDoctorDatabase::open(&existing)?;
    let read_only_version = schema_version(&read_only_database.connection)?;
    assert_eq!(
        read_only_version, PREVIOUS_HOME_TRANSFER_RESERVATION_RETIREMENT_SCHEMA_VERSION,
        "read-only inspection must not migrate the Workspace",
    );
    validate_schema_shape_for_version(&read_only_database.connection, WorkspaceSchemaShape::V71)?;
    let retirement_schema_exists: bool = read_only_database.connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?1)",
        [retirement_table],
        |row| row.get(0),
    )?;
    assert!(!retirement_schema_exists);
    read_only_database.ensure_unchanged()?;
    drop(read_only_database);

    fixture.store = WorkspaceStore::open_existing(&existing)?;
    assert_eq!(
        fixture.store.health()?.schema_version(),
        CURRENT_SCHEMA_VERSION
    );
    assert_eq!(fixture.store.workspace()?, workspace_before);
    validate_schema_shape_for_version(&fixture.store.connection, WorkspaceSchemaShape::Current)?;
    crate::workspace_home_transfers::retirements::schema::validate_schema(
        &fixture.store.connection,
    )?;
    assert_foreign_keys_clean(&fixture.store.connection)?;
    assert_eq!(source_fences(&fixture.store.connection)?, fences_before);
    assert_eq!(source_parent(&fixture, preparation_id)?, parent);
    assert_eq!(
        source_parent(&fixture, preparation_id)?.to_snapshot_bytes()?,
        parent_bytes,
        "migration must preserve the exact historical v1 Prepared snapshot",
    );
    assert_eq!(
        fixture
            .store
            .agent_binding_reservation(selected.request().request_id())?,
        Some(selected.clone()),
        "migration must preserve the native pending reservation",
    );
    assert_eq!(
        fixture
            .store
            .agent_binding_reservation(unrelated.request().request_id())?,
        Some(unrelated.clone()),
    );
    let empty_retirements: i64 = fixture.store.connection.query_row(
        "SELECT COUNT(*) FROM home_transfer_reservation_retirements",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        empty_retirements, 0,
        "migration must not backfill retirements"
    );

    drop(fixture.store);
    fixture.store = WorkspaceStore::open_existing(&existing)?;
    assert_eq!(
        fixture.store.health()?.schema_version(),
        CURRENT_SCHEMA_VERSION
    );
    assert_eq!(source_fences(&fixture.store.connection)?, fences_before);
    assert_eq!(source_parent(&fixture, preparation_id)?, parent);
    assert_eq!(
        fixture
            .store
            .agent_binding_reservation(selected.request().request_id())?,
        Some(selected.clone()),
        "the v1 parent and native reservation must survive reopen",
    );
    assert_foreign_keys_clean(&fixture.store.connection)?;

    let request = retirement_request(&fixture, &parent, &selected)?;
    let grant = retirement_grant(&request, fixture.issuer)?;
    let created = retirement(&mut fixture, &request, grant, 400)?;
    let retired = match created {
        crate::HomeTransferReservationRetirementOutcome::Created(record) => record,
        other @ crate::HomeTransferReservationRetirementOutcome::Existing(_) => {
            return Err(format!("expected Created, received {other:?}").into());
        }
    };
    assert_eq!(retired.request(), &request);
    assert_eq!(
        crate::workspace_home_transfers::retirements::get_for_reservation(
            &fixture.store.connection,
            selected.request().request_id(),
        )?,
        Some(retired.clone()),
        "a valid unused reservation must be retireable from the preserved v1 parent",
    );
    assert_eq!(
        retired.source_inventory_digest(),
        parent
            .inventory_digest()
            .ok_or("preserved v1 parent is missing its inventory digest")?,
    );
    let retirement_rows: i64 = fixture.store.connection.query_row(
        "SELECT COUNT(*) FROM home_transfer_reservation_retirements",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(retirement_rows, 1);
    assert_eq!(source_fences(&fixture.store.connection)?, fences_before);
    assert_eq!(
        source_parent(&fixture, preparation_id)?.to_snapshot_bytes()?,
        parent_bytes,
        "retirement must leave the original v1 Prepared snapshot immutable",
    );
    assert_eq!(
        fixture
            .store
            .agent_binding_reservation(selected.request().request_id())?,
        Some(selected),
        "retirement must preserve the native reservation row",
    );
    assert_eq!(
        fixture
            .store
            .agent_binding_reservation(unrelated.request().request_id())?,
        Some(unrelated),
        "unrelated same-Activity work remains pending",
    );
    assert_foreign_keys_clean(&fixture.store.connection)?;

    drop(fixture.store);
    std::fs::remove_dir_all(&fixture.root)?;
    Ok(())
}
