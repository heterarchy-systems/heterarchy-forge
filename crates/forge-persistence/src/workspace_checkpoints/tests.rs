use std::path::PathBuf;

use forge_domain::{
    ActivityId, ChangeSetId, CheckpointAttribution, CheckpointFileMode, CheckpointId,
    CheckpointObservedPathState, CheckpointPathState, CheckpointRestoreAttribution,
    CheckpointRestoreFailureCode, CheckpointRestoreId, CheckpointRestoreState, CheckpointRevision,
    FileByteCount, FileContentHash, GitBlobId, GitCommitId, RegisteredCheckpoint,
    RegisteredCheckpointRestore, RuntimeInstanceId, TimestampMillis, WorkspaceId,
    WorkspaceRelativePath, WorkspaceRevision,
};
use uuid::Uuid;

use super::*;

fn fixture()
-> Result<(Connection, WorkspaceId, ActivityId, ChangeSetId), Box<dyn std::error::Error>> {
    let connection = Connection::open_in_memory()?;
    connection.execute_batch(
        "PRAGMA foreign_keys = ON;
         CREATE TABLE workspace(workspace_id BLOB PRIMARY KEY);
         CREATE TABLE activities(activity_id BLOB PRIMARY KEY, workspace_id BLOB REFERENCES workspace(workspace_id));
         CREATE TABLE change_sets(changeset_id BLOB PRIMARY KEY, workspace_id BLOB, activity_id BLOB, workspace_revision INTEGER, state INTEGER);
         CREATE TABLE file_mutations(
             mutation_id BLOB PRIMARY KEY,
             changeset_id BLOB UNIQUE REFERENCES change_sets(changeset_id),
             relative_path BLOB,
             pre_state INTEGER,
             pre_hash BLOB,
             pre_size INTEGER,
             post_state INTEGER,
             post_hash BLOB,
             post_size INTEGER
         );",
    )?;
    let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(1));
    let activity_id = ActivityId::from_uuid(Uuid::from_u128(2));
    let change_set_id = ChangeSetId::from_uuid(Uuid::from_u128(3));
    connection.execute(
        "INSERT INTO workspace(workspace_id) VALUES (?1)",
        params![workspace_id.into_uuid().as_bytes()],
    )?;
    connection.execute(
        "INSERT INTO activities(activity_id, workspace_id) VALUES (?1, ?2)",
        params![
            activity_id.into_uuid().as_bytes(),
            workspace_id.into_uuid().as_bytes()
        ],
    )?;
    connection.execute(
        "INSERT INTO change_sets(changeset_id, workspace_id, activity_id, workspace_revision, state)
         VALUES (?1, ?2, ?3, 4, 0)",
        params![
            change_set_id.into_uuid().as_bytes(),
            workspace_id.into_uuid().as_bytes(),
            activity_id.into_uuid().as_bytes()
        ],
    )?;
    connection.execute(
        "INSERT INTO file_mutations(
            mutation_id, changeset_id, relative_path, pre_state, pre_hash, pre_size,
            post_state, post_hash, post_size
         ) VALUES (?1, ?2, CAST('src/lib.rs' AS BLOB), 1, ?3, 3, NULL, NULL, NULL)",
        params![
            Uuid::from_u128(4).as_bytes(),
            change_set_id.into_uuid().as_bytes(),
            [2_u8; HASH_BYTES].as_slice(),
        ],
    )?;
    crate::workspace_approvals::create_schema(&connection)?;
    create_schema(&connection)?;
    Ok((connection, workspace_id, activity_id, change_set_id))
}

fn starting_checkpoint(
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    change_set_id: ChangeSetId,
) -> Result<RegisteredCheckpoint, Box<dyn std::error::Error>> {
    Ok(RegisteredCheckpoint::starting(
        CheckpointAttribution::new(
            CheckpointId::from_uuid(Uuid::from_u128(10)),
            change_set_id,
            workspace_id,
            WorkspaceRevision::new(4)?,
            activity_id,
        ),
        WorkspaceRelativePath::new(PathBuf::from("src/lib.rs"))?,
        CheckpointPathState::Regular {
            blob: GitBlobId::from_sha1_bytes([1; SHA1_BYTES]),
            hash: FileContentHash::from_bytes([2; HASH_BYTES]),
            size: FileByteCount::new(3),
            mode: CheckpointFileMode::new(0o640)?,
        },
        GitCommitId::from_sha1_bytes([4; SHA1_BYTES]),
        TimestampMillis::new(10)?,
    ))
}

fn restore_attribution(
    checkpoint: &RegisteredCheckpoint,
    plan: &forge_domain::RestorePlan,
    id: CheckpointRestoreId,
) -> CheckpointRestoreAttribution {
    CheckpointRestoreAttribution::new(
        id,
        plan,
        RuntimeInstanceId::from_uuid(Uuid::from_u128(0xCAFE)),
        checkpoint.activity_id(),
        None,
        forge_domain::CheckpointRestoreFence::Direct,
    )
}

fn persist_ready_checkpoint(
    connection: &mut Connection,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    change_set_id: ChangeSetId,
) -> Result<RegisteredCheckpoint, Box<dyn std::error::Error>> {
    let starting = starting_checkpoint(workspace_id, activity_id, change_set_id)?;
    let _ = insert_checkpoint(connection, &starting)?;
    connection.execute(
        "UPDATE change_sets SET state = 1 WHERE changeset_id = ?1",
        params![change_set_id.into_uuid().as_bytes()],
    )?;
    connection.execute(
        "UPDATE file_mutations SET post_state = 0, post_hash = NULL, post_size = NULL
         WHERE changeset_id = ?1",
        params![change_set_id.into_uuid().as_bytes()],
    )?;
    let ready = starting.complete(
        CheckpointRevision::INITIAL,
        CheckpointPathState::Absent,
        GitCommitId::from_sha1_bytes([5; SHA1_BYTES]),
        TimestampMillis::new(11)?,
    )?;
    Ok(complete_checkpoint(
        connection,
        &ready,
        CheckpointRevision::INITIAL,
    )?)
}

fn install_v11_restore_schema(connection: &Connection) -> Result<(), Box<dyn std::error::Error>> {
    connection.execute_batch("DROP TABLE checkpoint_restores")?;
    connection.execute_batch(schema::RESTORES_V11_TABLE_SQL)?;
    connection.execute_batch(schema::RESTORES_WORKSPACE_INDEX_SQL)?;
    connection.execute_batch(schema::RESTORES_STATE_INDEX_SQL)?;
    connection.pragma_update(None, "user_version", 11_i64)?;
    schema::validate_v11(connection)?;
    Ok(())
}

#[test]
fn schema_constants_match_created_sql_and_shape() -> Result<(), Box<dyn std::error::Error>> {
    let (connection, _, _, _) = fixture()?;
    for (kind, name, expected) in [
        ("table", "checkpoints", schema::CHECKPOINTS_TABLE_SQL),
        (
            "table",
            "checkpoint_restores",
            schema::RESTORES_V12_TABLE_SQL,
        ),
        (
            "index",
            "checkpoints_workspace_created_idx",
            schema::CHECKPOINTS_WORKSPACE_INDEX_SQL,
        ),
        (
            "index",
            "checkpoints_state_updated_idx",
            schema::CHECKPOINTS_STATE_INDEX_SQL,
        ),
        (
            "index",
            "checkpoint_restores_workspace_created_idx",
            schema::RESTORES_WORKSPACE_INDEX_SQL,
        ),
        (
            "index",
            "checkpoint_restores_state_updated_idx",
            schema::RESTORES_STATE_INDEX_SQL,
        ),
    ] {
        let actual: String = connection.query_row(
            "SELECT sql FROM sqlite_schema WHERE type = ?1 AND name = ?2",
            params![kind, name],
            |row| row.get(0),
        )?;
        assert_eq!(
            schema::normalize_sql(&actual),
            schema::normalize_sql(expected),
            "{name}"
        );
    }
    validate_schema(&connection)?;
    Ok(())
}

#[test]
fn checkpoint_starting_to_ready_is_cas_guarded() -> Result<(), Box<dyn std::error::Error>> {
    let (mut connection, workspace_id, activity_id, change_set_id) = fixture()?;
    let starting = starting_checkpoint(workspace_id, activity_id, change_set_id)?;
    let stored = insert_checkpoint(&mut connection, &starting)?;
    assert_eq!(stored, starting);
    let ready = starting.complete(
        CheckpointRevision::INITIAL,
        CheckpointPathState::Absent,
        GitCommitId::from_sha1_bytes([5; SHA1_BYTES]),
        TimestampMillis::new(11)?,
    )?;
    connection.execute(
        "UPDATE change_sets SET state = 1 WHERE changeset_id = ?1",
        params![change_set_id.into_uuid().as_bytes()],
    )?;
    connection.execute(
        "UPDATE file_mutations SET post_state = 0, post_hash = NULL, post_size = NULL
         WHERE changeset_id = ?1",
        params![change_set_id.into_uuid().as_bytes()],
    )?;
    let stored = complete_checkpoint(&mut connection, &ready, CheckpointRevision::INITIAL)?;
    assert_eq!(stored, ready);
    assert_eq!(
        list_checkpoints(&connection, workspace_id, 10)?,
        vec![ready.clone()]
    );
    assert_eq!(
        complete_checkpoint(&mut connection, &ready, CheckpointRevision::INITIAL)?,
        ready
    );
    let conflicting = starting.complete(
        CheckpointRevision::INITIAL,
        CheckpointPathState::Absent,
        GitCommitId::from_sha1_bytes([6; SHA1_BYTES]),
        TimestampMillis::new(12)?,
    )?;
    assert!(matches!(
        complete_checkpoint(&mut connection, &conflicting, CheckpointRevision::INITIAL),
        Err(CheckpointStoreError::IdentityConflict)
    ));
    assert!(matches!(
        complete_checkpoint(&mut connection, &ready, CheckpointRevision::new(2)?),
        Err(CheckpointStoreError::RevisionConflict)
    ));
    Ok(())
}

#[test]
fn restore_lifecycle_round_trips_failure_and_recovery() -> Result<(), Box<dyn std::error::Error>> {
    let (mut connection, workspace_id, activity_id, change_set_id) = fixture()?;
    let starting = starting_checkpoint(workspace_id, activity_id, change_set_id)?;
    let ready = starting.complete(
        CheckpointRevision::INITIAL,
        CheckpointPathState::Absent,
        GitCommitId::from_sha1_bytes([5; SHA1_BYTES]),
        TimestampMillis::new(11)?,
    )?;
    let _ = insert_checkpoint(&mut connection, &starting)?;
    connection.execute(
        "UPDATE change_sets SET state = 1 WHERE changeset_id = ?1",
        params![change_set_id.into_uuid().as_bytes()],
    )?;
    connection.execute(
        "UPDATE file_mutations SET post_state = 0, post_hash = NULL, post_size = NULL
         WHERE changeset_id = ?1",
        params![change_set_id.into_uuid().as_bytes()],
    )?;
    let _ = complete_checkpoint(&mut connection, &ready, CheckpointRevision::INITIAL)?;
    let plan = forge_domain::plan_restore(&ready, CheckpointObservedPathState::Absent)?;
    let restore = RegisteredCheckpointRestore::starting(
        restore_attribution(
            &ready,
            &plan,
            CheckpointRestoreId::from_uuid(Uuid::from_u128(20)),
        ),
        &plan,
        TimestampMillis::new(12)?,
    );
    let stored = insert_checkpoint_restore(&mut connection, &restore)?;
    assert_eq!(stored.state(), CheckpointRestoreState::Starting);
    let failed = restore.failed(
        restore.revision(),
        CheckpointRestoreFailureCode::PathConflict,
        TimestampMillis::new(13)?,
    )?;
    assert_eq!(
        complete_checkpoint_restore(&mut connection, &failed, restore.revision())?,
        failed
    );
    assert_eq!(
        complete_checkpoint_restore(&mut connection, &failed, restore.revision())?,
        failed
    );
    let conflicting = restore.failed(
        restore.revision(),
        CheckpointRestoreFailureCode::IoFailure,
        TimestampMillis::new(14)?,
    )?;
    assert!(matches!(
        complete_checkpoint_restore(&mut connection, &conflicting, restore.revision()),
        Err(CheckpointStoreError::IdentityConflict)
    ));
    assert!(matches!(
        complete_checkpoint_restore(&mut connection, &failed, CheckpointRestoreRevision::new(2)?),
        Err(CheckpointStoreError::RevisionConflict)
    ));
    assert_eq!(
        list_checkpoint_restores(&connection, workspace_id, 10)?,
        vec![failed.clone()]
    );
    connection.execute(
        "UPDATE change_sets SET activity_id = ?1 WHERE changeset_id = ?2",
        params![
            Uuid::from_u128(99).as_bytes(),
            change_set_id.into_uuid().as_bytes()
        ],
    )?;
    assert!(matches!(
        list_checkpoint_restores(&connection, workspace_id, 10),
        Err(CheckpointStoreError::AttributionMismatch)
    ));
    let recovery = failed.recovery_required(failed.revision(), TimestampMillis::new(14)?);
    assert!(
        recovery.is_err(),
        "terminal restore cannot be transitioned twice"
    );
    Ok(())
}

#[test]
fn restored_and_recovery_required_retries_are_idempotent() -> Result<(), Box<dyn std::error::Error>>
{
    let (mut connection, workspace_id, activity_id, change_set_id) = fixture()?;
    let starting = starting_checkpoint(workspace_id, activity_id, change_set_id)?;
    let ready = starting.complete(
        CheckpointRevision::INITIAL,
        CheckpointPathState::Absent,
        GitCommitId::from_sha1_bytes([5; SHA1_BYTES]),
        TimestampMillis::new(11)?,
    )?;
    let _ = insert_checkpoint(&mut connection, &starting)?;
    connection.execute(
        "UPDATE change_sets SET state = 1 WHERE changeset_id = ?1",
        params![change_set_id.into_uuid().as_bytes()],
    )?;
    connection.execute(
        "UPDATE file_mutations SET post_state = 0, post_hash = NULL, post_size = NULL
         WHERE changeset_id = ?1",
        params![change_set_id.into_uuid().as_bytes()],
    )?;
    let _ = complete_checkpoint(&mut connection, &ready, CheckpointRevision::INITIAL)?;
    let plan = forge_domain::plan_restore(&ready, CheckpointObservedPathState::Absent)?;

    let restored_start = RegisteredCheckpointRestore::starting(
        restore_attribution(
            &ready,
            &plan,
            CheckpointRestoreId::from_uuid(Uuid::from_u128(21)),
        ),
        &plan,
        TimestampMillis::new(12)?,
    );
    let _ = insert_checkpoint_restore(&mut connection, &restored_start)?;
    let restored = restored_start.restored(restored_start.revision(), TimestampMillis::new(13)?)?;
    assert_eq!(
        complete_checkpoint_restore(&mut connection, &restored, restored_start.revision())?,
        restored
    );
    assert_eq!(
        complete_checkpoint_restore(&mut connection, &restored, restored_start.revision())?,
        restored
    );

    let recovery_start = RegisteredCheckpointRestore::starting(
        restore_attribution(
            &ready,
            &plan,
            CheckpointRestoreId::from_uuid(Uuid::from_u128(22)),
        ),
        &plan,
        TimestampMillis::new(14)?,
    );
    let _ = insert_checkpoint_restore(&mut connection, &recovery_start)?;
    let recovery =
        recovery_start.recovery_required(recovery_start.revision(), TimestampMillis::new(15)?)?;
    assert_eq!(
        complete_checkpoint_restore(&mut connection, &recovery, recovery_start.revision())?,
        recovery
    );
    assert_eq!(
        complete_checkpoint_restore(&mut connection, &recovery, recovery_start.revision())?,
        recovery
    );
    Ok(())
}

#[test]
fn duplicate_change_set_and_stale_revision_are_rejected() -> Result<(), Box<dyn std::error::Error>>
{
    let (mut connection, workspace_id, activity_id, change_set_id) = fixture()?;
    let first = starting_checkpoint(workspace_id, activity_id, change_set_id)?;
    let _ = insert_checkpoint(&mut connection, &first)?;
    let duplicate = RegisteredCheckpoint::starting(
        CheckpointAttribution::new(
            CheckpointId::from_uuid(Uuid::from_u128(11)),
            change_set_id,
            workspace_id,
            WorkspaceRevision::new(4)?,
            activity_id,
        ),
        WorkspaceRelativePath::new(PathBuf::from("src/lib.rs"))?,
        first.pre().clone(),
        first.pre_commit(),
        TimestampMillis::new(10)?,
    );
    assert!(matches!(
        insert_checkpoint(&mut connection, &duplicate),
        Err(CheckpointStoreError::IdentityConflict)
    ));
    let ready = first.complete(
        CheckpointRevision::INITIAL,
        CheckpointPathState::Absent,
        GitCommitId::from_sha1_bytes([5; SHA1_BYTES]),
        TimestampMillis::new(11)?,
    )?;
    assert!(matches!(
        complete_checkpoint(&mut connection, &ready, CheckpointRevision::new(2)?),
        Err(CheckpointStoreError::RevisionConflict)
    ));
    Ok(())
}

#[test]
fn malformed_object_length_and_mode_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let (mut connection, workspace_id, activity_id, change_set_id) = fixture()?;
    let checkpoint = starting_checkpoint(workspace_id, activity_id, change_set_id)?;
    let _ = insert_checkpoint(&mut connection, &checkpoint)?;
    connection.execute_batch("PRAGMA ignore_check_constraints = ON")?;
    connection.execute(
        "UPDATE checkpoints SET pre_blob = zeroblob(1) WHERE checkpoint_id = ?1",
        params![checkpoint.id().into_uuid().as_bytes()],
    )?;
    assert!(matches!(
        get_checkpoint(&connection, checkpoint.id()),
        Err(CheckpointStoreError::PersistedFieldLengthInvalid { .. })
    ));
    connection.execute(
        "UPDATE checkpoints SET pre_blob = zeroblob(20), pre_mode = 1024 WHERE checkpoint_id = ?1",
        params![checkpoint.id().into_uuid().as_bytes()],
    )?;
    assert!(matches!(
        get_checkpoint(&connection, checkpoint.id()),
        Err(CheckpointStoreError::CorruptRecord("checkpoint.pre"))
    ));
    let _ = &mut connection;
    Ok(())
}

#[test]
fn checkpoint_binding_rejects_path_pre_post_and_changeset_lifecycle_mismatches()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut connection, workspace_id, activity_id, change_set_id) = fixture()?;
    let checkpoint = starting_checkpoint(workspace_id, activity_id, change_set_id)?;

    connection.execute(
        "UPDATE file_mutations SET relative_path = CAST('other.rs' AS BLOB)
         WHERE changeset_id = ?1",
        params![change_set_id.into_uuid().as_bytes()],
    )?;
    assert!(matches!(
        insert_checkpoint(&mut connection, &checkpoint),
        Err(CheckpointStoreError::AttributionMismatch)
    ));
    connection.execute(
        "UPDATE file_mutations SET relative_path = CAST('src/lib.rs' AS BLOB),
                pre_hash = zeroblob(32)
         WHERE changeset_id = ?1",
        params![change_set_id.into_uuid().as_bytes()],
    )?;
    assert!(matches!(
        insert_checkpoint(&mut connection, &checkpoint),
        Err(CheckpointStoreError::AttributionMismatch)
    ));

    connection.execute(
        "UPDATE file_mutations SET pre_hash = ?1, post_state = 0,
                post_hash = NULL, post_size = NULL
         WHERE changeset_id = ?2",
        params![
            [2_u8; HASH_BYTES].as_slice(),
            change_set_id.into_uuid().as_bytes()
        ],
    )?;
    let _ = insert_checkpoint(&mut connection, &checkpoint)?;
    let ready = checkpoint.complete(
        CheckpointRevision::INITIAL,
        CheckpointPathState::Regular {
            blob: GitBlobId::from_sha1_bytes([5; SHA1_BYTES]),
            hash: FileContentHash::from_bytes([6; HASH_BYTES]),
            size: FileByteCount::new(7),
            mode: CheckpointFileMode::new(0o640)?,
        },
        GitCommitId::from_sha1_bytes([8; SHA1_BYTES]),
        TimestampMillis::new(11)?,
    )?;
    connection.execute(
        "UPDATE change_sets SET state = 2 WHERE changeset_id = ?1",
        params![change_set_id.into_uuid().as_bytes()],
    )?;
    assert!(matches!(
        complete_checkpoint(&mut connection, &ready, CheckpointRevision::INITIAL),
        Err(CheckpointStoreError::AttributionMismatch)
    ));
    connection.execute(
        "UPDATE change_sets SET state = 1 WHERE changeset_id = ?1",
        params![change_set_id.into_uuid().as_bytes()],
    )?;
    connection.execute(
        "UPDATE file_mutations SET post_state = 0, post_hash = NULL, post_size = NULL
         WHERE changeset_id = ?1",
        params![change_set_id.into_uuid().as_bytes()],
    )?;
    assert!(matches!(
        complete_checkpoint(&mut connection, &ready, CheckpointRevision::INITIAL),
        Err(CheckpointStoreError::AttributionMismatch)
    ));
    Ok(())
}

#[test]
fn checkpoint_lifecycle_revision_and_timestamp_corruption_fails_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut connection, workspace_id, activity_id, change_set_id) = fixture()?;
    let checkpoint = starting_checkpoint(workspace_id, activity_id, change_set_id)?;
    let _ = insert_checkpoint(&mut connection, &checkpoint)?;
    connection.execute_batch("PRAGMA ignore_check_constraints = ON")?;
    connection.execute(
        "UPDATE checkpoints SET revision = 2, updated_at_ms = 11 WHERE checkpoint_id = ?1",
        params![checkpoint.id().into_uuid().as_bytes()],
    )?;
    assert!(matches!(
        get_checkpoint(&connection, checkpoint.id()),
        Err(CheckpointStoreError::CorruptRecord("checkpoint.lifecycle"))
    ));
    Ok(())
}

#[test]
fn bounded_checkpoint_list_preloads_attribution_for_multiple_rows()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut connection, workspace_id, activity_id, first_change_set_id) = fixture()?;
    let first = starting_checkpoint(workspace_id, activity_id, first_change_set_id)?;
    let _ = insert_checkpoint(&mut connection, &first)?;
    for (offset, change_set_number) in [(1_u128, 40_u128), (2_u128, 50_u128)] {
        let change_set_id = ChangeSetId::from_uuid(Uuid::from_u128(change_set_number));
        let mutation_id = Uuid::from_u128(change_set_number + 1);
        let path_text = format!("src/extra-{change_set_number}.rs");
        let path_bytes = path_text.as_bytes();
        let hash = [u8::try_from(change_set_number)?; HASH_BYTES];
        connection.execute(
            "INSERT INTO change_sets(
                changeset_id, workspace_id, activity_id, workspace_revision, state
             ) VALUES (?1, ?2, ?3, 4, 0)",
            params![
                change_set_id.into_uuid().as_bytes(),
                workspace_id.into_uuid().as_bytes(),
                activity_id.into_uuid().as_bytes()
            ],
        )?;
        connection.execute(
            "INSERT INTO file_mutations(
                mutation_id, changeset_id, relative_path, pre_state, pre_hash, pre_size,
                post_state, post_hash, post_size
             ) VALUES (?1, ?2, ?3, 1, ?4, 3, NULL, NULL, NULL)",
            params![
                mutation_id.as_bytes(),
                change_set_id.into_uuid().as_bytes(),
                path_bytes,
                hash.as_slice()
            ],
        )?;
        let checkpoint = RegisteredCheckpoint::starting(
            CheckpointAttribution::new(
                CheckpointId::from_uuid(Uuid::from_u128(100 + offset)),
                change_set_id,
                workspace_id,
                WorkspaceRevision::new(4)?,
                activity_id,
            ),
            WorkspaceRelativePath::new(PathBuf::from(path_text))?,
            CheckpointPathState::Regular {
                blob: GitBlobId::from_sha1_bytes([u8::try_from(change_set_number)?; SHA1_BYTES]),
                hash: FileContentHash::from_bytes(hash),
                size: FileByteCount::new(3),
                mode: CheckpointFileMode::new(0o640)?,
            },
            GitCommitId::from_sha1_bytes([u8::try_from(change_set_number + 1)?; SHA1_BYTES]),
            TimestampMillis::new(10 + i64::try_from(offset)?)?,
        );
        let _ = insert_checkpoint(&mut connection, &checkpoint)?;
    }
    let records = list_checkpoints(&connection, workspace_id, 10)?;
    assert_eq!(records.len(), 3);
    assert!(
        records
            .iter()
            .all(|record| record.state() == CheckpointState::Starting)
    );
    Ok(())
}

#[test]
fn checkpoint_list_preload_rejects_cached_revision_attribution_mismatch()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut connection, workspace_id, activity_id, change_set_id) = fixture()?;
    let checkpoint = starting_checkpoint(workspace_id, activity_id, change_set_id)?;
    let _ = insert_checkpoint(&mut connection, &checkpoint)?;
    connection.execute(
        "UPDATE change_sets SET workspace_revision = 5 WHERE changeset_id = ?1",
        params![change_set_id.into_uuid().as_bytes()],
    )?;
    assert!(matches!(
        list_checkpoints(&connection, workspace_id, 10),
        Err(CheckpointStoreError::AttributionMismatch)
    ));
    Ok(())
}
#[test]
fn v11_restore_migration_rebuilds_exact_v12_when_journal_is_empty()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut connection, _, _, _) = fixture()?;
    install_v11_restore_schema(&connection)?;

    migrate_v11_to_v12(&mut connection, 12)?;

    assert_eq!(
        connection.pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))?,
        12
    );
    validate_schema(&connection)?;
    let actual: String = connection.query_row(
        "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = 'checkpoint_restores'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        schema::normalize_sql(&actual),
        schema::normalize_sql(schema::RESTORES_V12_TABLE_SQL)
    );
    Ok(())
}

#[test]
fn v11_restore_migration_fails_closed_when_legacy_restore_rows_exist()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut connection, workspace_id, activity_id, change_set_id) = fixture()?;
    let ready =
        persist_ready_checkpoint(&mut connection, workspace_id, activity_id, change_set_id)?;
    install_v11_restore_schema(&connection)?;
    connection.execute(
        "INSERT INTO checkpoint_restores (
            restore_id, checkpoint_id, workspace_id, expected_checkpoint_revision,
            expected_post_state, expected_post_hash, expected_post_size, expected_post_mode,
            inverse_kind, inverse_blob, inverse_hash, inverse_size, inverse_mode, state,
            failure_code, created_at_ms, updated_at_ms, revision
         ) VALUES (?1, ?2, ?3, ?4, 0, NULL, NULL, NULL, 1, ?5, ?6, ?7, ?8, 0, NULL, 12, 12, 1)",
        params![
            Uuid::from_u128(0xBEEF).as_bytes(),
            ready.id().into_uuid().as_bytes(),
            workspace_id.into_uuid().as_bytes(),
            ready.revision().get(),
            [1_u8; SHA1_BYTES].as_slice(),
            [2_u8; HASH_BYTES].as_slice(),
            3_i64,
            i64::from(0o640),
        ],
    )?;

    assert!(matches!(
        migrate_v11_to_v12(&mut connection, 12),
        Err(CheckpointStoreError::LegacyRestoreProvenanceUnavailable)
    ));
    assert_eq!(
        connection.pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))?,
        11
    );
    schema::validate_v11(&connection)?;
    Ok(())
}

#[test]
fn restore_fence_pair_and_attribution_are_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let (mut connection, workspace_id, activity_id, change_set_id) = fixture()?;
    let ready =
        persist_ready_checkpoint(&mut connection, workspace_id, activity_id, change_set_id)?;
    let plan = forge_domain::plan_restore(&ready, CheckpointObservedPathState::Absent)?;
    let restore_id = CheckpointRestoreId::from_uuid(Uuid::from_u128(0xCA11));
    let starting = RegisteredCheckpointRestore::starting(
        restore_attribution(&ready, &plan, restore_id),
        &plan,
        TimestampMillis::new(12)?,
    );
    let _ = insert_checkpoint_restore(&mut connection, &starting)?;

    connection.execute_batch("PRAGMA foreign_keys = OFF")?;
    let invalid_pair = connection.execute(
        "UPDATE checkpoint_restores SET maintenance_owner = ?1, maintenance_lease_epoch = NULL
         WHERE restore_id = ?2",
        params![
            Uuid::from_u128(0xCA12).as_bytes(),
            restore_id.into_uuid().as_bytes()
        ],
    );
    assert!(invalid_pair.is_err());
    connection.execute_batch("PRAGMA foreign_keys = ON")?;

    let changed_attribution = CheckpointRestoreAttribution::new(
        restore_id,
        &plan,
        RuntimeInstanceId::from_uuid(Uuid::from_u128(0xCAFE)),
        activity_id,
        None,
        forge_domain::CheckpointRestoreFence::Maintenance {
            owner: RuntimeInstanceId::from_uuid(Uuid::from_u128(0xCA12)),
            lease_epoch: forge_domain::RecoveryLeaseEpoch::new(3)?,
        },
    );
    let conflicting = RegisteredCheckpointRestore::starting(
        changed_attribution,
        &plan,
        TimestampMillis::new(12)?,
    )
    .failed(
        CheckpointRestoreRevision::INITIAL,
        CheckpointRestoreFailureCode::IoFailure,
        TimestampMillis::new(13)?,
    )?;
    assert!(matches!(
        complete_checkpoint_restore(
            &mut connection,
            &conflicting,
            CheckpointRestoreRevision::INITIAL
        ),
        Err(CheckpointStoreError::IdentityConflict)
    ));
    Ok(())
}

#[test]
fn restore_optional_approval_must_be_approved_and_scope_exact()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut connection, workspace_id, activity_id, change_set_id) = fixture()?;
    let ready =
        persist_ready_checkpoint(&mut connection, workspace_id, activity_id, change_set_id)?;
    let approval_id = forge_domain::ApprovalRequestId::from_uuid(Uuid::from_u128(0xA001));
    connection.execute(
        "INSERT INTO approval_requests (
            approval_id, workspace_id, activity_id, execution_id, request_digest, action_class,
            workspace_read, workspace_write, network, policy_revision, state, created_at_ms,
            expires_at_ms, decided_at_ms, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, 0, 1, 1, 0, 1, 1, 1, 100, 2, 2)",
        params![
            approval_id.into_uuid().as_bytes(),
            workspace_id.into_uuid().as_bytes(),
            activity_id.into_uuid().as_bytes(),
            Uuid::from_u128(0xA002).as_bytes(),
            [0xA0_u8; 32].as_slice(),
        ],
    )?;
    let plan = forge_domain::plan_restore(&ready, CheckpointObservedPathState::Absent)?;
    let approved = RegisteredCheckpointRestore::starting(
        CheckpointRestoreAttribution::new(
            CheckpointRestoreId::from_uuid(Uuid::from_u128(0xA003)),
            &plan,
            RuntimeInstanceId::from_uuid(Uuid::from_u128(0xCAFE)),
            activity_id,
            Some(approval_id),
            forge_domain::CheckpointRestoreFence::Direct,
        ),
        &plan,
        TimestampMillis::new(12)?,
    );
    assert_eq!(
        insert_checkpoint_restore(&mut connection, &approved)?,
        approved
    );

    let foreign_workspace = WorkspaceId::from_uuid(Uuid::from_u128(0xA010));
    let foreign_activity = ActivityId::from_uuid(Uuid::from_u128(0xA011));
    connection.execute(
        "INSERT INTO workspace(workspace_id) VALUES (?1)",
        params![foreign_workspace.into_uuid().as_bytes()],
    )?;
    connection.execute(
        "INSERT INTO activities(activity_id, workspace_id) VALUES (?1, ?2)",
        params![
            foreign_activity.into_uuid().as_bytes(),
            foreign_workspace.into_uuid().as_bytes(),
        ],
    )?;
    let foreign_approval = forge_domain::ApprovalRequestId::from_uuid(Uuid::from_u128(0xA012));
    connection.execute(
        "INSERT INTO approval_requests (
            approval_id, workspace_id, activity_id, execution_id, request_digest, action_class,
            workspace_read, workspace_write, network, policy_revision, state, created_at_ms,
            expires_at_ms, decided_at_ms, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, 0, 1, 1, 0, 1, 1, 1, 100, 2, 2)",
        params![
            foreign_approval.into_uuid().as_bytes(),
            foreign_workspace.into_uuid().as_bytes(),
            foreign_activity.into_uuid().as_bytes(),
            Uuid::from_u128(0xA013).as_bytes(),
            [0xA1_u8; 32].as_slice(),
        ],
    )?;
    let mismatched = RegisteredCheckpointRestore::starting(
        CheckpointRestoreAttribution::new(
            CheckpointRestoreId::from_uuid(Uuid::from_u128(0xA014)),
            &plan,
            RuntimeInstanceId::from_uuid(Uuid::from_u128(0xCAFE)),
            activity_id,
            Some(foreign_approval),
            forge_domain::CheckpointRestoreFence::Direct,
        ),
        &plan,
        TimestampMillis::new(12)?,
    );
    assert!(matches!(
        insert_checkpoint_restore(&mut connection, &mismatched),
        Err(CheckpointStoreError::AttributionMismatch)
    ));
    Ok(())
}

#[test]
fn checkpoint_doctor_references_project_starting_and_ready_owned_store_expectations()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut connection, workspace_id, activity_id, change_set_id) = fixture()?;
    let starting = starting_checkpoint(workspace_id, activity_id, change_set_id)?;
    let _ = insert_checkpoint(&mut connection, &starting)?;

    let starting_report = doctor_references(&connection, workspace_id)?;
    assert!(!starting_report.truncated());
    assert_eq!(starting_report.references().len(), 1);
    let starting_reference = starting_report.references()[0];
    assert_eq!(starting_reference.checkpoint_id(), starting.id());
    assert_eq!(starting_reference.state(), CheckpointState::Starting);
    assert_eq!(starting_reference.pre().commit(), starting.pre_commit());
    assert_eq!(
        starting_reference.pre().blob(),
        match starting.pre() {
            CheckpointPathState::Regular { blob, .. } => Some(*blob),
            CheckpointPathState::Absent => None,
        }
    );
    assert!(starting_reference.post().is_none());

    connection.execute(
        "UPDATE change_sets SET state = 1 WHERE changeset_id = ?1",
        params![change_set_id.into_uuid().as_bytes()],
    )?;
    connection.execute(
        "UPDATE file_mutations SET post_state = 0, post_hash = NULL, post_size = NULL
         WHERE changeset_id = ?1",
        params![change_set_id.into_uuid().as_bytes()],
    )?;
    let ready = starting.complete(
        CheckpointRevision::INITIAL,
        CheckpointPathState::Absent,
        GitCommitId::from_sha1_bytes([5; SHA1_BYTES]),
        TimestampMillis::new(11)?,
    )?;
    let _ = complete_checkpoint(&mut connection, &ready, CheckpointRevision::INITIAL)?;

    let ready_report = doctor_references(&connection, workspace_id)?;
    let ready_reference = ready_report.references()[0];
    assert_eq!(ready_reference.state(), CheckpointState::Ready);
    assert_eq!(ready_reference.pre().commit(), ready.pre_commit());
    let post = ready_reference
        .post()
        .ok_or("ready POST expectation missing")?;
    assert_eq!(
        post.commit(),
        ready.post_commit().ok_or("ready POST commit missing")?
    );
    assert!(post.blob().is_none());
    Ok(())
}

#[test]
fn checkpoint_doctor_references_are_bounded_and_identity_ordered()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut connection, workspace_id, activity_id, first_change_set_id) = fixture()?;
    let first = starting_checkpoint(workspace_id, activity_id, first_change_set_id)?;
    let _ = insert_checkpoint(&mut connection, &first)?;

    for offset in 1..CHECKPOINT_DOCTOR_PROBE_REFERENCES {
        let seed = u128::from(offset);
        let change_set_id = ChangeSetId::from_uuid(Uuid::from_u128(0x1000 + seed));
        let mutation_id = Uuid::from_u128(0x2000 + seed);
        let checkpoint_id = CheckpointId::from_uuid(Uuid::from_u128(0x3000 + seed));
        let path_text = format!("src/doctor-{offset}.rs");
        let byte = u8::try_from((offset % 251) + 1)?;
        let hash = [byte; HASH_BYTES];
        connection.execute(
            "INSERT INTO change_sets(
                changeset_id, workspace_id, activity_id, workspace_revision, state
             ) VALUES (?1, ?2, ?3, 4, 0)",
            params![
                change_set_id.into_uuid().as_bytes(),
                workspace_id.into_uuid().as_bytes(),
                activity_id.into_uuid().as_bytes()
            ],
        )?;
        connection.execute(
            "INSERT INTO file_mutations(
                mutation_id, changeset_id, relative_path, pre_state, pre_hash, pre_size,
                post_state, post_hash, post_size
             ) VALUES (?1, ?2, ?3, 1, ?4, 3, NULL, NULL, NULL)",
            params![
                mutation_id.as_bytes(),
                change_set_id.into_uuid().as_bytes(),
                path_text.as_bytes(),
                hash.as_slice()
            ],
        )?;
        let checkpoint = RegisteredCheckpoint::starting(
            CheckpointAttribution::new(
                checkpoint_id,
                change_set_id,
                workspace_id,
                WorkspaceRevision::new(4)?,
                activity_id,
            ),
            WorkspaceRelativePath::new(PathBuf::from(path_text))?,
            CheckpointPathState::Regular {
                blob: GitBlobId::from_sha1_bytes([byte; SHA1_BYTES]),
                hash: FileContentHash::from_bytes(hash),
                size: FileByteCount::new(3),
                mode: CheckpointFileMode::new(0o640)?,
            },
            GitCommitId::from_sha1_bytes([byte.wrapping_add(1); SHA1_BYTES]),
            TimestampMillis::new(10 + i64::from(offset))?,
        );
        let _ = insert_checkpoint(&mut connection, &checkpoint)?;
    }

    let report = doctor_references(&connection, workspace_id)?;
    assert_eq!(report.references().len(), CHECKPOINT_DOCTOR_MAX_REFERENCES);
    assert!(report.truncated());
    assert!(
        report
            .references()
            .windows(2)
            .all(|window| { window[0].checkpoint_id() < window[1].checkpoint_id() })
    );
    Ok(())
}
