use std::ffi::OsString;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;

use forge_domain::{
    ActivityId, ActivityLeaseRevision, BeginFileMutation, BeginFileMutationResult,
    BeginFileMutationStatus, ChangeSetAttribution, ChangeSetId, ChangeSetRevision, ChangeSetState,
    ChangeSetTimestamps, CompleteFileMutation, FailFileMutation, FileByteCount, FileContentHash,
    FileMutationFailureCode, FileMutationId, FileMutationIdentity, FileMutationKind,
    FileMutationPlan, FileMutationRecord, FileMutationRevision, FilePathState, FilePrecondition,
    RegisteredChangeSet, RegisteredFileMutation, RuntimeInstanceId, TimestampMillis, WorkspaceId,
    WorkspaceRelativePath, WorkspaceRevision,
};
use rusqlite::{Connection, OptionalExtension, Row, Transaction, TransactionBehavior, params};
use thiserror::Error;
use uuid::Uuid;

pub(crate) const EXPECTED_CHANGE_SETS_TABLE_SQL: &str = "CREATE TABLE change_sets (changeset_id BLOB PRIMARY KEY NOT NULL CHECK(length(changeset_id) = 16), workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id), activity_id BLOB NOT NULL REFERENCES activities(activity_id), runtime_instance_id BLOB NOT NULL CHECK(length(runtime_instance_id) = 16), activity_lease_revision INTEGER NOT NULL CHECK(activity_lease_revision >= 1), workspace_revision INTEGER NOT NULL CHECK(workspace_revision >= 1), state INTEGER NOT NULL CHECK(state IN (0, 1, 2)), failure_code INTEGER CHECK(failure_code IS NULL OR failure_code IN (0, 1, 2, 3, 4, 5)), created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0), updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0), revision INTEGER NOT NULL CHECK(revision >= 1), CHECK((state = 2 AND failure_code IS NOT NULL) OR (state IN (0, 1) AND failure_code IS NULL)))";
pub(crate) const EXPECTED_FILE_MUTATIONS_TABLE_SQL: &str = "CREATE TABLE file_mutations (mutation_id BLOB PRIMARY KEY NOT NULL CHECK(length(mutation_id) = 16), changeset_id BLOB NOT NULL UNIQUE REFERENCES change_sets(changeset_id), ordinal INTEGER NOT NULL CHECK(ordinal = 0), relative_path BLOB NOT NULL CHECK(length(relative_path) BETWEEN 1 AND 4096), kind INTEGER NOT NULL CHECK(kind IN (0, 1, 2)), precondition INTEGER NOT NULL CHECK(precondition IN (0, 1)), expected_hash BLOB CHECK(expected_hash IS NULL OR length(expected_hash) = 32), intended_hash BLOB CHECK(intended_hash IS NULL OR length(intended_hash) = 32), pre_state INTEGER NOT NULL CHECK(pre_state IN (0, 1)), pre_hash BLOB CHECK(pre_hash IS NULL OR length(pre_hash) = 32), pre_size INTEGER CHECK(pre_size IS NULL OR pre_size >= 0), post_state INTEGER CHECK(post_state IS NULL OR post_state IN (0, 1)), post_hash BLOB CHECK(post_hash IS NULL OR length(post_hash) = 32), post_size INTEGER CHECK(post_size IS NULL OR post_size >= 0), revision INTEGER NOT NULL CHECK(revision >= 1), CHECK((precondition = 0 AND expected_hash IS NULL) OR (precondition = 1 AND expected_hash IS NOT NULL)), CHECK((kind IN (0, 1) AND intended_hash IS NOT NULL) OR (kind = 2 AND intended_hash IS NULL)), CHECK((pre_state = 0 AND pre_hash IS NULL AND pre_size IS NULL) OR (pre_state = 1 AND pre_hash IS NOT NULL AND pre_size IS NOT NULL)), CHECK((kind = 0 AND precondition = 0 AND pre_state = 0) OR (kind IN (1, 2) AND precondition = 1 AND pre_state = 1 AND expected_hash = pre_hash)), CHECK((post_state IS NULL AND post_hash IS NULL AND post_size IS NULL) OR (post_state = 0 AND post_hash IS NULL AND post_size IS NULL) OR (post_state = 1 AND post_hash IS NOT NULL AND post_size IS NOT NULL)))";
pub(crate) const EXPECTED_CHANGE_SETS_ACTIVITY_INDEX_SQL: &str = "CREATE INDEX change_sets_activity_created_idx ON change_sets(activity_id, created_at_ms DESC, changeset_id DESC)";
pub(crate) const EXPECTED_CHANGE_SETS_STATE_INDEX_SQL: &str =
    "CREATE INDEX change_sets_state_updated_idx ON change_sets(state, updated_at_ms, changeset_id)";

const MAX_PATH_BYTES: usize = 4_096;
const HASH_BYTES: usize = FileContentHash::BYTE_LEN;

const RECORD_QUERY: &str = "SELECT
        length(CAST(c.changeset_id AS BLOB)),
        length(CAST(c.workspace_id AS BLOB)),
        length(CAST(c.activity_id AS BLOB)),
        length(CAST(c.runtime_instance_id AS BLOB)),
        length(CAST(f.mutation_id AS BLOB)),
        length(CAST(f.relative_path AS BLOB)),
        length(CAST(f.expected_hash AS BLOB)),
        length(CAST(f.pre_hash AS BLOB)),
        length(CAST(f.post_hash AS BLOB)),
        c.changeset_id, c.workspace_id, c.activity_id, c.runtime_instance_id,
        c.activity_lease_revision, c.workspace_revision, c.state, c.failure_code,
        c.created_at_ms, c.updated_at_ms, c.revision,
        f.mutation_id, f.relative_path, f.kind, f.precondition, f.expected_hash,
        f.pre_state, f.pre_hash, f.pre_size, f.post_state, f.post_hash, f.post_size,
        f.revision, length(CAST(f.intended_hash AS BLOB)), f.intended_hash
    FROM change_sets AS c
    JOIN file_mutations AS f ON f.changeset_id = c.changeset_id";

pub(crate) fn create_schema(connection: &Connection) -> Result<(), ChangeSetStoreError> {
    connection.execute_batch(
        "CREATE TABLE change_sets (
            changeset_id BLOB PRIMARY KEY NOT NULL CHECK(length(changeset_id) = 16),
            workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id),
            activity_id BLOB NOT NULL REFERENCES activities(activity_id),
            runtime_instance_id BLOB NOT NULL CHECK(length(runtime_instance_id) = 16),
            activity_lease_revision INTEGER NOT NULL CHECK(activity_lease_revision >= 1),
            workspace_revision INTEGER NOT NULL CHECK(workspace_revision >= 1),
            state INTEGER NOT NULL CHECK(state IN (0, 1, 2)),
            failure_code INTEGER CHECK(failure_code IS NULL OR failure_code IN (0, 1, 2, 3, 4, 5)),
            created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
            updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0),
            revision INTEGER NOT NULL CHECK(revision >= 1),
            CHECK((state = 2 AND failure_code IS NOT NULL) OR (state IN (0, 1) AND failure_code IS NULL))
         );
         CREATE TABLE file_mutations (
            mutation_id BLOB PRIMARY KEY NOT NULL CHECK(length(mutation_id) = 16),
            changeset_id BLOB NOT NULL UNIQUE REFERENCES change_sets(changeset_id),
            ordinal INTEGER NOT NULL CHECK(ordinal = 0),
            relative_path BLOB NOT NULL CHECK(length(relative_path) BETWEEN 1 AND 4096),
            kind INTEGER NOT NULL CHECK(kind IN (0, 1, 2)),
            precondition INTEGER NOT NULL CHECK(precondition IN (0, 1)),
            expected_hash BLOB CHECK(expected_hash IS NULL OR length(expected_hash) = 32),
            intended_hash BLOB CHECK(intended_hash IS NULL OR length(intended_hash) = 32),
            pre_state INTEGER NOT NULL CHECK(pre_state IN (0, 1)),
            pre_hash BLOB CHECK(pre_hash IS NULL OR length(pre_hash) = 32),
            pre_size INTEGER CHECK(pre_size IS NULL OR pre_size >= 0),
            post_state INTEGER CHECK(post_state IS NULL OR post_state IN (0, 1)),
            post_hash BLOB CHECK(post_hash IS NULL OR length(post_hash) = 32),
            post_size INTEGER CHECK(post_size IS NULL OR post_size >= 0),
            revision INTEGER NOT NULL CHECK(revision >= 1),
            CHECK((precondition = 0 AND expected_hash IS NULL) OR (precondition = 1 AND expected_hash IS NOT NULL)),
            CHECK((kind IN (0, 1) AND intended_hash IS NOT NULL) OR (kind = 2 AND intended_hash IS NULL)),
            CHECK((pre_state = 0 AND pre_hash IS NULL AND pre_size IS NULL) OR (pre_state = 1 AND pre_hash IS NOT NULL AND pre_size IS NOT NULL)),
            CHECK((kind = 0 AND precondition = 0 AND pre_state = 0) OR (kind IN (1, 2) AND precondition = 1 AND pre_state = 1 AND expected_hash = pre_hash)),
            CHECK((post_state IS NULL AND post_hash IS NULL AND post_size IS NULL) OR (post_state = 0 AND post_hash IS NULL AND post_size IS NULL) OR (post_state = 1 AND post_hash IS NOT NULL AND post_size IS NOT NULL))
         );
         CREATE INDEX change_sets_activity_created_idx
            ON change_sets(activity_id, created_at_ms DESC, changeset_id DESC);
         CREATE INDEX change_sets_state_updated_idx
            ON change_sets(state, updated_at_ms, changeset_id);",
    )?;
    Ok(())
}

pub(crate) fn migrate_v2_to_v3(
    connection: &mut Connection,
    next_schema_version: i64,
) -> Result<(), ChangeSetStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    create_schema(&transaction)?;
    transaction.pragma_update(None, "user_version", next_schema_version)?;
    transaction.commit()?;
    Ok(())
}

pub(crate) fn begin(
    transaction: &Transaction<'_>,
    command: &BeginFileMutation,
) -> Result<BeginFileMutationResult, ChangeSetStoreError> {
    validate_scope_and_lease(transaction, command)?;
    let by_change_set = query_by_change_set(transaction, command.change_set_id())?;
    let by_mutation = query_by_mutation(transaction, command.mutation_id())?;
    if by_change_set.is_some() || by_mutation.is_some() {
        let Some(record) = same_existing_record(by_change_set, by_mutation)? else {
            return Err(ChangeSetStoreError::IdentityConflict);
        };
        if !record_matches_command(&record, command) {
            return Err(ChangeSetStoreError::IdentityConflict);
        }
        let status = match record.change_set().state() {
            ChangeSetState::Starting => BeginFileMutationStatus::RecoveryRequired,
            ChangeSetState::Applied => BeginFileMutationStatus::AlreadyApplied,
            ChangeSetState::Failed => BeginFileMutationStatus::TerminalFailed,
        };
        return Ok(BeginFileMutationResult::new(record, status));
    }

    let change_set_id = command.change_set_id().into_uuid().into_bytes();
    let workspace_id = command.workspace_id().into_uuid().into_bytes();
    let activity_id = command.activity_id().into_uuid().into_bytes();
    let runtime_id = command.runtime_instance_id().into_uuid().into_bytes();
    transaction.execute(
        "INSERT INTO change_sets (
            changeset_id, workspace_id, activity_id, runtime_instance_id,
            activity_lease_revision, workspace_revision, state, failure_code,
            created_at_ms, updated_at_ms, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, ?8, ?8, ?9)",
        params![
            change_set_id.as_slice(),
            workspace_id.as_slice(),
            activity_id.as_slice(),
            runtime_id.as_slice(),
            command.activity_lease_revision().get(),
            command.expected_workspace_revision().get(),
            encode_change_set_state(ChangeSetState::Starting),
            command.observed_at().get(),
            ChangeSetRevision::INITIAL.get(),
        ],
    )?;

    let mutation_id = command.mutation_id().into_uuid().into_bytes();
    let path = command.path().as_path().as_os_str().as_bytes();
    let (precondition, expected_hash) = encode_precondition(command.precondition());
    let pre = encode_path_state(command.observed_pre_state())?;
    transaction.execute(
        "INSERT INTO file_mutations (
            mutation_id, changeset_id, ordinal, relative_path, kind, precondition,
            expected_hash, intended_hash, pre_state, pre_hash, pre_size, post_state, post_hash,
            post_size, revision
         ) VALUES (?1, ?2, 0, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, NULL, NULL, NULL, ?11)",
        params![
            mutation_id.as_slice(),
            change_set_id.as_slice(),
            path,
            encode_mutation_kind(command.kind()),
            precondition,
            expected_hash.as_deref(),
            command
                .intended_content_hash()
                .map(|hash| hash.as_bytes().to_vec()),
            pre.state,
            pre.hash.as_deref(),
            pre.size,
            FileMutationRevision::INITIAL.get(),
        ],
    )?;
    let record = query_by_change_set(transaction, command.change_set_id())?
        .ok_or(ChangeSetStoreError::RecordMissing)?;
    Ok(BeginFileMutationResult::new(
        record,
        BeginFileMutationStatus::Started,
    ))
}

pub(crate) fn complete(
    transaction: &Transaction<'_>,
    command: &CompleteFileMutation,
) -> Result<FileMutationRecord, ChangeSetStoreError> {
    let current = require_record(transaction, command.identity())?;
    validate_starting_revisions(
        &current,
        command.expected_change_set_revision(),
        command.expected_mutation_revision(),
    )?;
    validate_post_state(current.mutation().kind(), command.post_state())?;
    if command.observed_at().get() < current.change_set().created_at().get() {
        return Err(ChangeSetStoreError::TimestampOrder);
    }
    let next_change_set = current
        .change_set()
        .revision()
        .checked_next()
        .map_err(|_| ChangeSetStoreError::RevisionOverflow)?;
    let next_mutation = current
        .mutation()
        .revision()
        .checked_next()
        .map_err(|_| ChangeSetStoreError::RevisionOverflow)?;
    let post = encode_path_state(command.post_state())?;
    let mutation_id = command.identity().mutation_id().into_uuid().into_bytes();
    let changed = transaction.execute(
        "UPDATE file_mutations
         SET post_state = ?1, post_hash = ?2, post_size = ?3, revision = ?4
         WHERE mutation_id = ?5 AND revision = ?6 AND post_state IS NULL",
        params![
            post.state,
            post.hash.as_deref(),
            post.size,
            next_mutation.get(),
            mutation_id.as_slice(),
            command.expected_mutation_revision().get(),
        ],
    )?;
    if changed != 1 {
        return Err(ChangeSetStoreError::RevisionConflict);
    }
    let change_set_id = command.identity().change_set_id().into_uuid().into_bytes();
    let changed = transaction.execute(
        "UPDATE change_sets
         SET state = ?1, updated_at_ms = ?2, revision = ?3
         WHERE changeset_id = ?4 AND state = ?5 AND revision = ?6",
        params![
            encode_change_set_state(ChangeSetState::Applied),
            command.observed_at().get(),
            next_change_set.get(),
            change_set_id.as_slice(),
            encode_change_set_state(ChangeSetState::Starting),
            command.expected_change_set_revision().get(),
        ],
    )?;
    if changed != 1 {
        return Err(ChangeSetStoreError::RevisionConflict);
    }
    query_by_change_set(transaction, command.identity().change_set_id())?
        .ok_or(ChangeSetStoreError::RecordMissing)
}

pub(crate) fn fail(
    transaction: &Transaction<'_>,
    command: &FailFileMutation,
) -> Result<FileMutationRecord, ChangeSetStoreError> {
    let current = require_record(transaction, command.identity())?;
    validate_starting_revisions(
        &current,
        command.expected_change_set_revision(),
        command.expected_mutation_revision(),
    )?;
    if command.observed_at().get() < current.change_set().created_at().get() {
        return Err(ChangeSetStoreError::TimestampOrder);
    }
    let next_change_set = current
        .change_set()
        .revision()
        .checked_next()
        .map_err(|_| ChangeSetStoreError::RevisionOverflow)?;
    let next_mutation = current
        .mutation()
        .revision()
        .checked_next()
        .map_err(|_| ChangeSetStoreError::RevisionOverflow)?;
    let mutation_id = command.identity().mutation_id().into_uuid().into_bytes();
    let changed = transaction.execute(
        "UPDATE file_mutations SET revision = ?1
         WHERE mutation_id = ?2 AND revision = ?3 AND post_state IS NULL",
        params![
            next_mutation.get(),
            mutation_id.as_slice(),
            command.expected_mutation_revision().get(),
        ],
    )?;
    if changed != 1 {
        return Err(ChangeSetStoreError::RevisionConflict);
    }
    let change_set_id = command.identity().change_set_id().into_uuid().into_bytes();
    let changed = transaction.execute(
        "UPDATE change_sets
         SET state = ?1, failure_code = ?2, updated_at_ms = ?3, revision = ?4
         WHERE changeset_id = ?5 AND state = ?6 AND revision = ?7",
        params![
            encode_change_set_state(ChangeSetState::Failed),
            encode_failure_code(command.failure_code()),
            command.observed_at().get(),
            next_change_set.get(),
            change_set_id.as_slice(),
            encode_change_set_state(ChangeSetState::Starting),
            command.expected_change_set_revision().get(),
        ],
    )?;
    if changed != 1 {
        return Err(ChangeSetStoreError::RevisionConflict);
    }
    query_by_change_set(transaction, command.identity().change_set_id())?
        .ok_or(ChangeSetStoreError::RecordMissing)
}

pub(crate) fn get(
    connection: &Connection,
    change_set_id: ChangeSetId,
) -> Result<Option<FileMutationRecord>, ChangeSetStoreError> {
    query_by_change_set(connection, change_set_id)
}

fn validate_scope_and_lease(
    transaction: &Transaction<'_>,
    command: &BeginFileMutation,
) -> Result<(), ChangeSetStoreError> {
    let workspace_id: Vec<u8> = transaction
        .query_row(
            "SELECT workspace_id FROM workspace WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .optional()?
        .ok_or(ChangeSetStoreError::WorkspaceMissing)?;
    let stored_workspace_id =
        decode_uuid("workspace.workspace_id", &workspace_id).map(WorkspaceId::from_uuid)?;
    if stored_workspace_id != command.workspace_id() {
        return Err(ChangeSetStoreError::WorkspaceMismatch);
    }
    let workspace_revision: i64 = transaction.query_row(
        "SELECT revision FROM workspace WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    if WorkspaceRevision::new(workspace_revision)
        .map_err(|_| ChangeSetStoreError::CorruptRecord("workspace.revision"))?
        != command.expected_workspace_revision()
    {
        return Err(ChangeSetStoreError::WorkspaceRevisionConflict);
    }

    let activity_id = command.activity_id().into_uuid().into_bytes();
    let activity = transaction
        .query_row(
            "SELECT workspace_id, state, lease_owner_id, lease_until_ms, lease_revision
             FROM activities WHERE activity_id = ?1",
            params![activity_id.as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Option<Vec<u8>>>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()?
        .ok_or(ChangeSetStoreError::ActivityMissing)?;
    if decode_uuid("activity.workspace_id", &activity.0).map(WorkspaceId::from_uuid)?
        != command.workspace_id()
    {
        return Err(ChangeSetStoreError::ActivityWorkspaceMismatch);
    }
    if activity.1 != 1 {
        return Err(ChangeSetStoreError::ActivityNotOpen);
    }
    let owner = activity
        .2
        .as_deref()
        .ok_or(ChangeSetStoreError::LeaseUnavailable)
        .and_then(|value| decode_uuid("activity.lease_owner_id", value))
        .map(RuntimeInstanceId::from_uuid)?;
    if owner != command.runtime_instance_id() {
        return Err(ChangeSetStoreError::LeaseOwnerMismatch);
    }
    let lease_until = activity.3.ok_or(ChangeSetStoreError::LeaseUnavailable)?;
    if lease_until <= command.observed_at().get() {
        return Err(ChangeSetStoreError::LeaseExpired);
    }
    let lease_revision = ActivityLeaseRevision::new(activity.4)
        .map_err(|_| ChangeSetStoreError::CorruptRecord("activity.lease_revision"))?;
    if lease_revision != command.activity_lease_revision() {
        return Err(ChangeSetStoreError::LeaseRevisionConflict);
    }
    Ok(())
}

fn query_by_change_set(
    connection: &Connection,
    id: ChangeSetId,
) -> Result<Option<FileMutationRecord>, ChangeSetStoreError> {
    let id = id.into_uuid().into_bytes();
    let query = format!("{RECORD_QUERY} WHERE c.changeset_id = ?1");
    connection
        .query_row(&query, params![id.as_slice()], decode_record)
        .optional()
        .map_err(ChangeSetStoreError::from)
}

fn query_by_mutation(
    connection: &Connection,
    id: FileMutationId,
) -> Result<Option<FileMutationRecord>, ChangeSetStoreError> {
    let id = id.into_uuid().into_bytes();
    let query = format!("{RECORD_QUERY} WHERE f.mutation_id = ?1");
    connection
        .query_row(&query, params![id.as_slice()], decode_record)
        .optional()
        .map_err(ChangeSetStoreError::from)
}

fn require_record(
    connection: &Connection,
    identity: FileMutationIdentity,
) -> Result<FileMutationRecord, ChangeSetStoreError> {
    let record = query_by_change_set(connection, identity.change_set_id())?
        .ok_or(ChangeSetStoreError::RecordMissing)?;
    if record.mutation().id() != identity.mutation_id() {
        return Err(ChangeSetStoreError::IdentityConflict);
    }
    Ok(record)
}

fn same_existing_record(
    by_change_set: Option<FileMutationRecord>,
    by_mutation: Option<FileMutationRecord>,
) -> Result<Option<FileMutationRecord>, ChangeSetStoreError> {
    match (by_change_set, by_mutation) {
        (Some(left), Some(right)) if left == right => Ok(Some(left)),
        (Some(_), Some(_)) => Err(ChangeSetStoreError::IdentityConflict),
        (Some(record), None) | (None, Some(record)) => Ok(Some(record)),
        (None, None) => Ok(None),
    }
}

fn record_matches_command(record: &FileMutationRecord, command: &BeginFileMutation) -> bool {
    record.change_set().id() == command.change_set_id()
        && record.change_set().workspace_id() == command.workspace_id()
        && record.change_set().workspace_revision() == command.expected_workspace_revision()
        && record.change_set().activity_id() == command.activity_id()
        && record.change_set().runtime_instance_id() == command.runtime_instance_id()
        && record.mutation().id() == command.mutation_id()
        && record.mutation().path() == command.path()
        && record.mutation().kind() == command.kind()
        && record.mutation().precondition() == command.precondition()
        && record.mutation().intended_content_hash() == command.intended_content_hash()
}

fn validate_starting_revisions(
    record: &FileMutationRecord,
    expected_change_set: ChangeSetRevision,
    expected_mutation: FileMutationRevision,
) -> Result<(), ChangeSetStoreError> {
    if record.change_set().state() != ChangeSetState::Starting {
        return Err(ChangeSetStoreError::Terminal);
    }
    if record.change_set().revision() != expected_change_set
        || record.mutation().revision() != expected_mutation
    {
        return Err(ChangeSetStoreError::RevisionConflict);
    }
    Ok(())
}

fn validate_post_state(
    kind: FileMutationKind,
    state: FilePathState,
) -> Result<(), ChangeSetStoreError> {
    if matches!(
        (kind, state),
        (
            FileMutationKind::Create | FileMutationKind::Replace,
            FilePathState::Regular { .. }
        ) | (FileMutationKind::Delete, FilePathState::Absent)
    ) {
        Ok(())
    } else {
        Err(ChangeSetStoreError::InvalidPostState)
    }
}

fn decode_record(row: &Row<'_>) -> rusqlite::Result<FileMutationRecord> {
    decode_record_inner(row).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Blob, Box::new(error))
    })
}

fn decode_record_inner(row: &Row<'_>) -> Result<FileMutationRecord, ChangeSetStoreError> {
    validate_record_lengths(row)?;
    let change_set = decode_change_set(row)?;
    let mutation = decode_file_mutation(row, change_set.id(), change_set.state())?;
    Ok(FileMutationRecord::new(change_set, mutation))
}

fn validate_record_lengths(row: &Row<'_>) -> Result<(), ChangeSetStoreError> {
    validate_exact_length("change_set.id", row.get(0)?, 16)?;
    validate_exact_length("change_set.workspace_id", row.get(1)?, 16)?;
    validate_exact_length("change_set.activity_id", row.get(2)?, 16)?;
    validate_exact_length("change_set.runtime_instance_id", row.get(3)?, 16)?;
    validate_exact_length("file_mutation.id", row.get(4)?, 16)?;
    validate_bounded_length("file_mutation.relative_path", row.get(5)?, MAX_PATH_BYTES)?;
    validate_optional_hash_length("file_mutation.expected_hash", row.get(6)?)?;
    validate_optional_hash_length("file_mutation.pre_hash", row.get(7)?)?;
    validate_optional_hash_length("file_mutation.post_hash", row.get(8)?)?;
    validate_optional_hash_length("file_mutation.intended_hash", row.get(32)?)
}

fn decode_change_set(row: &Row<'_>) -> Result<RegisteredChangeSet, ChangeSetStoreError> {
    let change_set_id =
        decode_uuid("change_set.id", &row.get::<_, Vec<u8>>(9)?).map(ChangeSetId::from_uuid)?;
    let workspace_id = decode_uuid("change_set.workspace_id", &row.get::<_, Vec<u8>>(10)?)
        .map(WorkspaceId::from_uuid)?;
    let activity_id = decode_uuid("change_set.activity_id", &row.get::<_, Vec<u8>>(11)?)
        .map(ActivityId::from_uuid)?;
    let runtime_id = decode_uuid(
        "change_set.runtime_instance_id",
        &row.get::<_, Vec<u8>>(12)?,
    )
    .map(RuntimeInstanceId::from_uuid)?;
    let lease_revision = ActivityLeaseRevision::new(row.get(13)?)
        .map_err(|_| ChangeSetStoreError::CorruptRecord("change_set.activity_lease_revision"))?;
    let workspace_revision = WorkspaceRevision::new(row.get(14)?)
        .map_err(|_| ChangeSetStoreError::CorruptRecord("change_set.workspace_revision"))?;
    let state = decode_change_set_state(row.get(15)?)?;
    let failure_code = row
        .get::<_, Option<i64>>(16)?
        .map(decode_failure_code)
        .transpose()?;
    validate_failure_shape(state, failure_code)?;
    let created_at = TimestampMillis::new(row.get(17)?)
        .map_err(|_| ChangeSetStoreError::CorruptRecord("change_set.created_at_ms"))?;
    let updated_at = TimestampMillis::new(row.get(18)?)
        .map_err(|_| ChangeSetStoreError::CorruptRecord("change_set.updated_at_ms"))?;
    if updated_at.get() < created_at.get() {
        return Err(ChangeSetStoreError::CorruptRecord(
            "change_set.updated_at_ms",
        ));
    }
    let change_set_revision = ChangeSetRevision::new(row.get(19)?)
        .map_err(|_| ChangeSetStoreError::CorruptRecord("change_set.revision"))?;
    Ok(RegisteredChangeSet::from_parts(
        ChangeSetAttribution::new(
            change_set_id,
            workspace_id,
            workspace_revision,
            activity_id,
            runtime_id,
            lease_revision,
        ),
        state,
        ChangeSetTimestamps::new(created_at, updated_at),
        change_set_revision,
        failure_code,
    ))
}

fn decode_file_mutation(
    row: &Row<'_>,
    change_set_id: ChangeSetId,
    change_set_state: ChangeSetState,
) -> Result<RegisteredFileMutation, ChangeSetStoreError> {
    let mutation_id = decode_uuid("file_mutation.id", &row.get::<_, Vec<u8>>(20)?)
        .map(FileMutationId::from_uuid)?;
    let path_bytes = row.get::<_, Vec<u8>>(21)?;
    let path = WorkspaceRelativePath::new(PathBuf::from(OsString::from_vec(path_bytes)))
        .map_err(|_| ChangeSetStoreError::CorruptRecord("file_mutation.relative_path"))?;
    let kind = decode_mutation_kind(row.get(22)?)?;
    let expected_hash = row
        .get::<_, Option<Vec<u8>>>(24)?
        .map(|value| decode_hash("file_mutation.expected_hash", &value))
        .transpose()?;
    let precondition = decode_precondition(row.get(23)?, expected_hash)?;
    let pre_state = decode_path_state(
        "file_mutation.pre",
        row.get(25)?,
        row.get(26)?,
        row.get(27)?,
    )?;
    let post_state = match row.get::<_, Option<i64>>(28)? {
        None => {
            if row.get::<_, Option<Vec<u8>>>(29)?.is_some()
                || row.get::<_, Option<i64>>(30)?.is_some()
            {
                return Err(ChangeSetStoreError::CorruptRecord(
                    "file_mutation.post_state",
                ));
            }
            None
        }
        Some(state) => Some(decode_path_state(
            "file_mutation.post",
            state,
            row.get(29)?,
            row.get(30)?,
        )?),
    };
    validate_record_state(change_set_state, kind, post_state)?;
    let mutation_revision = FileMutationRevision::new(row.get(31)?)
        .map_err(|_| ChangeSetStoreError::CorruptRecord("file_mutation.revision"))?;
    let intended_content_hash = row
        .get::<_, Option<Vec<u8>>>(33)?
        .map(|value| decode_hash("file_mutation.intended_hash", &value))
        .transpose()?;
    if !matches!(
        (kind, intended_content_hash),
        (
            FileMutationKind::Create | FileMutationKind::Replace,
            Some(_)
        ) | (FileMutationKind::Delete, None)
    ) {
        return Err(ChangeSetStoreError::CorruptRecord(
            "file_mutation.intended_hash",
        ));
    }
    Ok(RegisteredFileMutation::from_parts(
        FileMutationIdentity::new(change_set_id, mutation_id),
        FileMutationPlan::new(path, kind, precondition),
        intended_content_hash,
        pre_state,
        post_state,
        mutation_revision,
    ))
}

fn validate_record_state(
    state: ChangeSetState,
    kind: FileMutationKind,
    post_state: Option<FilePathState>,
) -> Result<(), ChangeSetStoreError> {
    match (state, post_state) {
        (ChangeSetState::Starting | ChangeSetState::Failed, None) => Ok(()),
        (ChangeSetState::Applied, Some(post)) => validate_post_state(kind, post),
        (ChangeSetState::Starting | ChangeSetState::Failed, Some(_))
        | (ChangeSetState::Applied, None) => Err(ChangeSetStoreError::CorruptRecord(
            "file_mutation.post_state",
        )),
    }
}

fn encode_precondition(value: FilePrecondition) -> (i64, Option<Vec<u8>>) {
    match value {
        FilePrecondition::Absent => (0, None),
        FilePrecondition::Matches(hash) => (1, Some(hash.as_bytes().to_vec())),
    }
}

fn decode_precondition(
    value: i64,
    hash: Option<FileContentHash>,
) -> Result<FilePrecondition, ChangeSetStoreError> {
    match (value, hash) {
        (0, None) => Ok(FilePrecondition::Absent),
        (1, Some(hash)) => Ok(FilePrecondition::Matches(hash)),
        _ => Err(ChangeSetStoreError::CorruptRecord(
            "file_mutation.precondition",
        )),
    }
}

struct EncodedPathState {
    state: i64,
    hash: Option<Vec<u8>>,
    size: Option<i64>,
}

fn encode_path_state(value: FilePathState) -> Result<EncodedPathState, ChangeSetStoreError> {
    match value {
        FilePathState::Absent => Ok(EncodedPathState {
            state: 0,
            hash: None,
            size: None,
        }),
        FilePathState::Regular { hash, size } => Ok(EncodedPathState {
            state: 1,
            hash: Some(hash.as_bytes().to_vec()),
            size: Some(i64::try_from(size.get()).map_err(|_| ChangeSetStoreError::SizeOverflow)?),
        }),
    }
}

fn decode_path_state(
    field: &'static str,
    state: i64,
    hash: Option<Vec<u8>>,
    size: Option<i64>,
) -> Result<FilePathState, ChangeSetStoreError> {
    match (state, hash, size) {
        (0, None, None) => Ok(FilePathState::Absent),
        (1, Some(hash), Some(size)) if size >= 0 => Ok(FilePathState::Regular {
            hash: decode_hash(field, &hash)?,
            size: FileByteCount::new(
                u64::try_from(size).map_err(|_| ChangeSetStoreError::SizeOverflow)?,
            ),
        }),
        _ => Err(ChangeSetStoreError::CorruptRecord(field)),
    }
}

const fn encode_mutation_kind(value: FileMutationKind) -> i64 {
    match value {
        FileMutationKind::Create => 0,
        FileMutationKind::Replace => 1,
        FileMutationKind::Delete => 2,
    }
}

const fn decode_mutation_kind(value: i64) -> Result<FileMutationKind, ChangeSetStoreError> {
    match value {
        0 => Ok(FileMutationKind::Create),
        1 => Ok(FileMutationKind::Replace),
        2 => Ok(FileMutationKind::Delete),
        _ => Err(ChangeSetStoreError::CorruptRecord("file_mutation.kind")),
    }
}

const fn encode_change_set_state(value: ChangeSetState) -> i64 {
    match value {
        ChangeSetState::Starting => 0,
        ChangeSetState::Applied => 1,
        ChangeSetState::Failed => 2,
    }
}

const fn decode_change_set_state(value: i64) -> Result<ChangeSetState, ChangeSetStoreError> {
    match value {
        0 => Ok(ChangeSetState::Starting),
        1 => Ok(ChangeSetState::Applied),
        2 => Ok(ChangeSetState::Failed),
        _ => Err(ChangeSetStoreError::CorruptRecord("change_set.state")),
    }
}

const fn encode_failure_code(value: FileMutationFailureCode) -> i64 {
    match value {
        FileMutationFailureCode::InvalidPath => 0,
        FileMutationFailureCode::ProtectedPath => 1,
        FileMutationFailureCode::PathConflict => 2,
        FileMutationFailureCode::StaleWrite => 3,
        FileMutationFailureCode::CapacityExceeded => 4,
        FileMutationFailureCode::IoFailure => 5,
    }
}

const fn decode_failure_code(value: i64) -> Result<FileMutationFailureCode, ChangeSetStoreError> {
    match value {
        0 => Ok(FileMutationFailureCode::InvalidPath),
        1 => Ok(FileMutationFailureCode::ProtectedPath),
        2 => Ok(FileMutationFailureCode::PathConflict),
        3 => Ok(FileMutationFailureCode::StaleWrite),
        4 => Ok(FileMutationFailureCode::CapacityExceeded),
        5 => Ok(FileMutationFailureCode::IoFailure),
        _ => Err(ChangeSetStoreError::CorruptRecord(
            "change_set.failure_code",
        )),
    }
}

fn validate_failure_shape(
    state: ChangeSetState,
    failure: Option<FileMutationFailureCode>,
) -> Result<(), ChangeSetStoreError> {
    if matches!(
        (state, failure),
        (ChangeSetState::Failed, Some(_))
            | (ChangeSetState::Starting | ChangeSetState::Applied, None)
    ) {
        Ok(())
    } else {
        Err(ChangeSetStoreError::CorruptRecord(
            "change_set.failure_code",
        ))
    }
}

fn decode_uuid(field: &'static str, value: &[u8]) -> Result<Uuid, ChangeSetStoreError> {
    Uuid::from_slice(value).map_err(|_| ChangeSetStoreError::CorruptRecord(field))
}

fn decode_hash(field: &'static str, value: &[u8]) -> Result<FileContentHash, ChangeSetStoreError> {
    let bytes = <[u8; HASH_BYTES]>::try_from(value)
        .map_err(|_| ChangeSetStoreError::CorruptRecord(field))?;
    Ok(FileContentHash::from_bytes(bytes))
}

fn validate_exact_length(
    field: &'static str,
    length: i64,
    expected: usize,
) -> Result<(), ChangeSetStoreError> {
    if usize::try_from(length).ok() == Some(expected) {
        Ok(())
    } else {
        Err(ChangeSetStoreError::CorruptRecord(field))
    }
}

fn validate_bounded_length(
    field: &'static str,
    length: i64,
    maximum: usize,
) -> Result<(), ChangeSetStoreError> {
    match usize::try_from(length) {
        Ok(actual) if (1..=maximum).contains(&actual) => Ok(()),
        Ok(_) | Err(_) => Err(ChangeSetStoreError::CorruptRecord(field)),
    }
}

fn validate_optional_hash_length(
    field: &'static str,
    length: Option<i64>,
) -> Result<(), ChangeSetStoreError> {
    match length {
        None => Ok(()),
        Some(actual) => validate_exact_length(field, actual, HASH_BYTES),
    }
}

#[derive(Debug, Error)]
pub enum ChangeSetStoreError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error("Workspace identity is missing")]
    WorkspaceMissing,
    #[error("Workspace identity does not match the file mutation")]
    WorkspaceMismatch,
    #[error("Workspace revision is stale")]
    WorkspaceRevisionConflict,
    #[error("Activity is missing")]
    ActivityMissing,
    #[error("Activity belongs to another Workspace")]
    ActivityWorkspaceMismatch,
    #[error("Activity is not open")]
    ActivityNotOpen,
    #[error("Activity lease is unavailable")]
    LeaseUnavailable,
    #[error("Activity lease owner does not match")]
    LeaseOwnerMismatch,
    #[error("Activity lease is expired")]
    LeaseExpired,
    #[error("Activity lease revision is stale")]
    LeaseRevisionConflict,
    #[error("ChangeSet or mutation identity conflicts with an existing record")]
    IdentityConflict,
    #[error("ChangeSet record is missing")]
    RecordMissing,
    #[error("ChangeSet is terminal")]
    Terminal,
    #[error("ChangeSet or file mutation revision is stale")]
    RevisionConflict,
    #[error("ChangeSet or file mutation revision overflowed")]
    RevisionOverflow,
    #[error("file mutation completion state does not match its kind")]
    InvalidPostState,
    #[error("file mutation timestamp precedes its durable intent")]
    TimestampOrder,
    #[error("file byte count exceeds SQLite integer range")]
    SizeOverflow,
    #[error("corrupt ChangeSet field {0}")]
    CorruptRecord(&'static str),
}

pub(crate) fn schema_objects() -> [(&'static str, &'static str); 4] {
    [
        ("table", "change_sets"),
        ("table", "file_mutations"),
        ("index", "change_sets_activity_created_idx"),
        ("index", "change_sets_state_updated_idx"),
    ]
}

pub(crate) fn validate_schema(connection: &Connection) -> Result<(), ChangeSetStoreError> {
    validate_schema_sql(
        connection,
        "table",
        "change_sets",
        EXPECTED_CHANGE_SETS_TABLE_SQL,
    )?;
    validate_schema_sql(
        connection,
        "table",
        "file_mutations",
        EXPECTED_FILE_MUTATIONS_TABLE_SQL,
    )?;
    validate_schema_sql(
        connection,
        "index",
        "change_sets_activity_created_idx",
        EXPECTED_CHANGE_SETS_ACTIVITY_INDEX_SQL,
    )?;
    validate_schema_sql(
        connection,
        "index",
        "change_sets_state_updated_idx",
        EXPECTED_CHANGE_SETS_STATE_INDEX_SQL,
    )?;
    validate_table_columns(
        connection,
        "change_sets",
        &[
            ("changeset_id", "BLOB", 1, 1),
            ("workspace_id", "BLOB", 1, 0),
            ("activity_id", "BLOB", 1, 0),
            ("runtime_instance_id", "BLOB", 1, 0),
            ("activity_lease_revision", "INTEGER", 1, 0),
            ("workspace_revision", "INTEGER", 1, 0),
            ("state", "INTEGER", 1, 0),
            ("failure_code", "INTEGER", 0, 0),
            ("created_at_ms", "INTEGER", 1, 0),
            ("updated_at_ms", "INTEGER", 1, 0),
            ("revision", "INTEGER", 1, 0),
        ],
    )?;
    validate_table_columns(
        connection,
        "file_mutations",
        &[
            ("mutation_id", "BLOB", 1, 1),
            ("changeset_id", "BLOB", 1, 0),
            ("ordinal", "INTEGER", 1, 0),
            ("relative_path", "BLOB", 1, 0),
            ("kind", "INTEGER", 1, 0),
            ("precondition", "INTEGER", 1, 0),
            ("expected_hash", "BLOB", 0, 0),
            ("intended_hash", "BLOB", 0, 0),
            ("pre_state", "INTEGER", 1, 0),
            ("pre_hash", "BLOB", 0, 0),
            ("pre_size", "INTEGER", 0, 0),
            ("post_state", "INTEGER", 0, 0),
            ("post_hash", "BLOB", 0, 0),
            ("post_size", "INTEGER", 0, 0),
            ("revision", "INTEGER", 1, 0),
        ],
    )?;
    validate_index_columns(
        connection,
        "change_sets_activity_created_idx",
        &["activity_id", "created_at_ms", "changeset_id"],
    )?;
    validate_index_columns(
        connection,
        "change_sets_state_updated_idx",
        &["state", "updated_at_ms", "changeset_id"],
    )?;
    validate_foreign_keys(connection, "change_sets", 2)?;
    validate_foreign_keys(connection, "file_mutations", 1)?;
    Ok(())
}

type ColumnShape = (&'static str, &'static str, i64, i64);

fn validate_table_columns(
    connection: &Connection,
    table: &'static str,
    expected: &[ColumnShape],
) -> Result<(), ChangeSetStoreError> {
    let query = format!("PRAGMA table_info({table})");
    let mut statement = connection.prepare(&query)?;
    let mut rows = statement.query([])?;
    let mut actual = Vec::new();
    while let Some(row) = rows.next()? {
        if actual.len() >= 32 {
            return Err(ChangeSetStoreError::CorruptRecord(table));
        }
        actual.push((
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, i64>(5)?,
        ));
    }
    let matches = actual.len() == expected.len()
        && actual.iter().zip(expected).all(|(actual, expected)| {
            actual.0 == expected.0
                && actual.1 == expected.1
                && actual.2 == expected.2
                && actual.3 == expected.3
        });
    if matches {
        Ok(())
    } else {
        Err(ChangeSetStoreError::CorruptRecord(table))
    }
}

fn validate_schema_sql(
    connection: &Connection,
    object_type: &'static str,
    name: &'static str,
    expected: &'static str,
) -> Result<(), ChangeSetStoreError> {
    let sql: Option<String> = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type = ?1 AND name = ?2",
            params![object_type, name],
            |row| row.get(0),
        )
        .optional()?;
    let sql = sql.ok_or(ChangeSetStoreError::CorruptRecord(name))?;
    if normalized_sql(&sql) == normalized_sql(expected) {
        Ok(())
    } else {
        Err(ChangeSetStoreError::CorruptRecord(name))
    }
}

fn normalized_sql(value: &str) -> String {
    value
        .chars()
        .filter(|value| !value.is_whitespace())
        .collect()
}

fn validate_index_columns(
    connection: &Connection,
    index: &'static str,
    expected: &[&str],
) -> Result<(), ChangeSetStoreError> {
    let query = format!("PRAGMA index_info({index})");
    let mut statement = connection.prepare(&query)?;
    let mut rows = statement.query([])?;
    let mut actual = Vec::new();
    while let Some(row) = rows.next()? {
        if actual.len() >= 16 {
            return Err(ChangeSetStoreError::CorruptRecord(index));
        }
        actual.push(row.get::<_, String>(2)?);
    }
    if actual
        .iter()
        .map(String::as_str)
        .eq(expected.iter().copied())
    {
        Ok(())
    } else {
        Err(ChangeSetStoreError::CorruptRecord(index))
    }
}

fn validate_foreign_keys(
    connection: &Connection,
    table: &'static str,
    expected_count: usize,
) -> Result<(), ChangeSetStoreError> {
    let query = format!("PRAGMA foreign_key_list({table})");
    let mut statement = connection.prepare(&query)?;
    let count = statement.query_map([], |_| Ok(()))?.count();
    if count == expected_count {
        Ok(())
    } else {
        Err(ChangeSetStoreError::CorruptRecord(table))
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use super::*;

    #[test]
    fn schema_constants_match_created_sql() -> Result<(), Box<dyn std::error::Error>> {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE workspace(workspace_id BLOB UNIQUE);
             CREATE TABLE activities(activity_id BLOB PRIMARY KEY);",
        )?;
        create_schema(&connection)?;
        for (kind, name, expected) in [
            ("table", "change_sets", EXPECTED_CHANGE_SETS_TABLE_SQL),
            ("table", "file_mutations", EXPECTED_FILE_MUTATIONS_TABLE_SQL),
            (
                "index",
                "change_sets_activity_created_idx",
                EXPECTED_CHANGE_SETS_ACTIVITY_INDEX_SQL,
            ),
            (
                "index",
                "change_sets_state_updated_idx",
                EXPECTED_CHANGE_SETS_STATE_INDEX_SQL,
            ),
        ] {
            let actual: String = connection.query_row(
                "SELECT sql FROM sqlite_schema WHERE type = ?1 AND name = ?2",
                params![kind, name],
                |row| row.get(0),
            )?;
            assert_eq!(normalized_sql(&actual), normalized_sql(expected), "{name}");
        }
        validate_schema(&connection)?;
        Ok(())
    }

    #[test]
    fn algorithm_qualified_hash_is_stored_as_full_raw_width()
    -> Result<(), Box<dyn std::error::Error>> {
        let value = FileContentHash::from_bytes([7; FileContentHash::BYTE_LEN]);
        let (_, encoded) = encode_precondition(FilePrecondition::Matches(value));
        let encoded = encoded.ok_or("expected hash bytes")?;
        assert_eq!(encoded.len(), FileContentHash::BYTE_LEN);
        assert_eq!(decode_hash("hash", &encoded)?, value);
        Ok(())
    }

    #[test]
    fn native_non_utf8_path_round_trips_through_domain_decoder()
    -> Result<(), Box<dyn std::error::Error>> {
        let path = WorkspaceRelativePath::new(PathBuf::from(OsStr::from_bytes(b"src/\xff.rs")))?;
        assert_eq!(path.as_path().as_os_str().as_bytes(), b"src/\xff.rs");
        Ok(())
    }
}
