use std::ffi::OsString;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;

use forge_domain::{
    ActivityId, ActivityLeaseRevision, BeginFileMutation, BeginFileMutationResult,
    BeginFileMutationStatus, ChangeSetAttribution, ChangeSetId, ChangeSetRevision, ChangeSetState,
    ChangeSetTimestamps, CompleteFileMutation, FailFileMutation, FileByteCount, FileContentHash,
    FileMutationFailureCode, FileMutationId, FileMutationIdentity, FileMutationKind,
    FileMutationPlan, FileMutationRecord, FileMutationRevision, FilePathState, FilePrecondition,
    MAX_TREE_CHANGESET_MUTATIONS, RegisteredChangeSet, RegisteredFileMutation, RuntimeInstanceId,
    SourceTreeRequestDigest, TimestampMillis, TreeChangeSetAdmission, TreeChangeSetAdmissionStatus,
    TreeChangeSetIntent, TreeMutationId, TreeMutationIntent, TreeMutationPlan, WorkspaceId,
    WorkspaceRelativePath, WorkspaceRevision,
};
use rusqlite::{Connection, OptionalExtension, Row, Transaction, params};
use thiserror::Error;
use uuid::Uuid;

pub(crate) const EXPECTED_CHANGE_SETS_TABLE_SQL: &str = "CREATE TABLE change_sets (changeset_id BLOB PRIMARY KEY NOT NULL CHECK(length(changeset_id) = 16), workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id), activity_id BLOB NOT NULL REFERENCES activities(activity_id), runtime_instance_id BLOB NOT NULL CHECK(length(runtime_instance_id) = 16), activity_lease_revision INTEGER NOT NULL CHECK(activity_lease_revision >= 1), workspace_revision INTEGER NOT NULL CHECK(workspace_revision >= 1), state INTEGER NOT NULL CHECK(state IN (0, 1, 2)), failure_code INTEGER CHECK(failure_code IS NULL OR failure_code IN (0, 1, 2, 3, 4, 5)), created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0), updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0), revision INTEGER NOT NULL CHECK(revision >= 1), CHECK((state = 2 AND failure_code IS NOT NULL) OR (state IN (0, 1) AND failure_code IS NULL)))";
pub(crate) const EXPECTED_FILE_MUTATIONS_TABLE_SQL: &str = "CREATE TABLE file_mutations (mutation_id BLOB PRIMARY KEY NOT NULL CHECK(length(mutation_id) = 16), changeset_id BLOB NOT NULL UNIQUE REFERENCES change_sets(changeset_id), ordinal INTEGER NOT NULL CHECK(ordinal = 0), relative_path BLOB NOT NULL CHECK(length(relative_path) BETWEEN 1 AND 4096), kind INTEGER NOT NULL CHECK(kind IN (0, 1, 2)), precondition INTEGER NOT NULL CHECK(precondition IN (0, 1)), expected_hash BLOB CHECK(expected_hash IS NULL OR length(expected_hash) = 32), intended_hash BLOB CHECK(intended_hash IS NULL OR length(intended_hash) = 32), pre_state INTEGER NOT NULL CHECK(pre_state IN (0, 1)), pre_hash BLOB CHECK(pre_hash IS NULL OR length(pre_hash) = 32), pre_size INTEGER CHECK(pre_size IS NULL OR pre_size >= 0), post_state INTEGER CHECK(post_state IS NULL OR post_state IN (0, 1)), post_hash BLOB CHECK(post_hash IS NULL OR length(post_hash) = 32), post_size INTEGER CHECK(post_size IS NULL OR post_size >= 0), revision INTEGER NOT NULL CHECK(revision >= 1), CHECK((precondition = 0 AND expected_hash IS NULL) OR (precondition = 1 AND expected_hash IS NOT NULL)), CHECK((kind IN (0, 1) AND intended_hash IS NOT NULL) OR (kind = 2 AND intended_hash IS NULL)), CHECK((pre_state = 0 AND pre_hash IS NULL AND pre_size IS NULL) OR (pre_state = 1 AND pre_hash IS NOT NULL AND pre_size IS NOT NULL)), CHECK((kind = 0 AND precondition = 0 AND pre_state = 0) OR (kind IN (1, 2) AND precondition = 1 AND pre_state = 1 AND expected_hash = pre_hash)), CHECK((post_state IS NULL AND post_hash IS NULL AND post_size IS NULL) OR (post_state = 0 AND post_hash IS NULL AND post_size IS NULL) OR (post_state = 1 AND post_hash IS NOT NULL AND post_size IS NOT NULL)))";
pub(crate) const EXPECTED_TREE_MUTATIONS_TABLE_SQL: &str = "CREATE TABLE tree_mutations (mutation_id BLOB PRIMARY KEY NOT NULL CHECK(length(mutation_id) = 16), changeset_id BLOB NOT NULL REFERENCES change_sets(changeset_id), ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 0 AND 255), kind INTEGER NOT NULL CHECK(kind BETWEEN 0 AND 6), primary_path BLOB NOT NULL CHECK(length(primary_path) BETWEEN 1 AND 4096), secondary_path BLOB CHECK(secondary_path IS NULL OR length(secondary_path) BETWEEN 1 AND 4096), expected_hash BLOB CHECK(expected_hash IS NULL OR length(expected_hash) = 32), intended_hash BLOB CHECK(intended_hash IS NULL OR length(intended_hash) = 32), applied INTEGER NOT NULL DEFAULT 0 CHECK(applied IN (0, 1)), revision INTEGER NOT NULL CHECK(revision >= 1), UNIQUE(changeset_id, ordinal), CHECK((kind = 0 AND secondary_path IS NULL AND expected_hash IS NULL AND intended_hash IS NULL) OR (kind = 1 AND secondary_path IS NULL AND expected_hash IS NULL AND intended_hash IS NOT NULL) OR (kind = 2 AND secondary_path IS NULL AND expected_hash IS NOT NULL AND intended_hash IS NOT NULL) OR (kind = 3 AND secondary_path IS NULL AND expected_hash IS NOT NULL AND intended_hash IS NULL) OR (kind = 4 AND secondary_path IS NOT NULL AND expected_hash IS NOT NULL AND intended_hash IS NULL) OR (kind = 5 AND secondary_path IS NOT NULL AND expected_hash IS NULL AND intended_hash IS NULL) OR (kind = 6 AND secondary_path IS NULL AND expected_hash IS NULL AND intended_hash IS NULL)))";
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
    for sql in [
        EXPECTED_CHANGE_SETS_TABLE_SQL,
        EXPECTED_FILE_MUTATIONS_TABLE_SQL,
        EXPECTED_TREE_MUTATIONS_TABLE_SQL,
        EXPECTED_CHANGE_SETS_ACTIVITY_INDEX_SQL,
        EXPECTED_CHANGE_SETS_STATE_INDEX_SQL,
    ] {
        connection.execute_batch(sql)?;
    }
    Ok(())
}

pub(crate) fn create_source_tree_request_schema(
    connection: &Connection,
) -> Result<(), ChangeSetStoreError> {
    crate::workspace_source_tree_requests::create_schema(connection)
        .map_err(map_source_tree_request_store_error)
}

pub(crate) fn validate_source_tree_request_schema(
    connection: &Connection,
) -> Result<(), ChangeSetStoreError> {
    crate::workspace_source_tree_requests::validate_schema(connection)
        .map_err(map_source_tree_request_store_error)
}

pub(crate) fn source_tree_request_schema_objects() -> [(&'static str, &'static str); 1] {
    crate::workspace_source_tree_requests::schema_objects()
}

pub(crate) fn insert_source_tree_request_digest(
    connection: &Connection,
    change_set_id: ChangeSetId,
    request_digest: SourceTreeRequestDigest,
) -> Result<(), ChangeSetStoreError> {
    crate::workspace_source_tree_requests::insert(connection, change_set_id, request_digest)
        .map_err(map_source_tree_request_store_error)
}

pub(crate) fn source_tree_request_digest_matches(
    connection: &Connection,
    change_set_id: ChangeSetId,
    request_digest: SourceTreeRequestDigest,
) -> Result<bool, ChangeSetStoreError> {
    crate::workspace_source_tree_requests::get(connection, change_set_id)
        .map(|stored| stored == Some(request_digest))
        .map_err(map_source_tree_request_store_error)
}

pub(crate) fn inspect_tree_change_set(
    transaction: &Transaction<'_>,
    intent: &TreeChangeSetIntent,
) -> Result<Option<TreeChangeSetAdmission>, ChangeSetStoreError> {
    let _current_activity_lease_revision =
        validate_change_set_scope(transaction, intent.attribution())?;
    existing_tree_change_set_admission(transaction, intent)
}

pub(crate) fn inspect_source_tree_request(
    transaction: &Transaction<'_>,
    attribution: ChangeSetAttribution,
    request_digest: SourceTreeRequestDigest,
) -> Result<Option<TreeChangeSetAdmission>, ChangeSetStoreError> {
    let _current_activity_lease_revision = validate_change_set_scope(transaction, attribution)?;
    let Some(existing) = query_change_set_header(transaction, attribution.id())? else {
        return Ok(None);
    };
    let stored_digest = crate::workspace_source_tree_requests::get(transaction, attribution.id())
        .map_err(map_source_tree_request_store_error)?;
    if !change_set_matches_attribution(&existing, attribution)
        || stored_digest != Some(request_digest)
    {
        return Err(ChangeSetStoreError::IdentityConflict);
    }
    let status = match existing.state() {
        ChangeSetState::Starting => TreeChangeSetAdmissionStatus::RecoveryRequired,
        ChangeSetState::Applied => TreeChangeSetAdmissionStatus::AlreadyApplied,
        ChangeSetState::Failed => TreeChangeSetAdmissionStatus::TerminalFailed,
    };
    Ok(Some(TreeChangeSetAdmission::new(existing, status)))
}

fn map_source_tree_request_store_error(
    error: crate::workspace_source_tree_requests::SourceTreeRequestStoreError,
) -> ChangeSetStoreError {
    match error {
        crate::workspace_source_tree_requests::SourceTreeRequestStoreError::Sqlite(source) => {
            ChangeSetStoreError::Sqlite(source)
        }
        crate::workspace_source_tree_requests::SourceTreeRequestStoreError::DamagedSchema => {
            ChangeSetStoreError::CorruptRecord("source_tree_requests.schema")
        }
        crate::workspace_source_tree_requests::SourceTreeRequestStoreError::CorruptDigest => {
            ChangeSetStoreError::CorruptRecord("source_tree_requests.request_digest")
        }
    }
}

pub(crate) fn begin_tree_change_set(
    transaction: &Transaction<'_>,
    intent: &TreeChangeSetIntent,
) -> Result<TreeChangeSetAdmission, ChangeSetStoreError> {
    let current_activity_lease_revision =
        validate_change_set_scope(transaction, intent.attribution())?;
    if let Some(admission) = existing_tree_change_set_admission(transaction, intent)? {
        return Ok(admission);
    }
    let requested_attribution = intent.attribution();
    let attribution = ChangeSetAttribution::new(
        requested_attribution.id(),
        requested_attribution.workspace_id(),
        requested_attribution.workspace_revision(),
        requested_attribution.activity_id(),
        requested_attribution.runtime_instance_id(),
        current_activity_lease_revision,
    );
    for mutation in intent.mutations() {
        let mutation_id = mutation.id().into_uuid().into_bytes();
        let exists: i64 = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM tree_mutations WHERE mutation_id = ?1)",
            params![mutation_id.as_slice()],
            |row| row.get(0),
        )?;
        if exists != 0 {
            return Err(ChangeSetStoreError::IdentityConflict);
        }
    }
    insert_change_set_header(transaction, attribution, intent.observed_at())?;
    for mutation in intent.mutations() {
        insert_tree_mutation(transaction, attribution.id(), mutation)?;
    }
    let change_set = query_change_set_header(transaction, attribution.id())?
        .ok_or(ChangeSetStoreError::RecordMissing)?;
    Ok(TreeChangeSetAdmission::new(
        change_set,
        TreeChangeSetAdmissionStatus::Started,
    ))
}

fn existing_tree_change_set_admission(
    connection: &Connection,
    intent: &TreeChangeSetIntent,
) -> Result<Option<TreeChangeSetAdmission>, ChangeSetStoreError> {
    let attribution = intent.attribution();
    let Some(existing) = query_change_set_header(connection, attribution.id())? else {
        return Ok(None);
    };
    if !change_set_matches_attribution(&existing, attribution)
        || !tree_mutations_match_intent(connection, intent)?
    {
        return Err(ChangeSetStoreError::IdentityConflict);
    }
    let status = match existing.state() {
        ChangeSetState::Starting => TreeChangeSetAdmissionStatus::RecoveryRequired,
        ChangeSetState::Applied => TreeChangeSetAdmissionStatus::AlreadyApplied,
        ChangeSetState::Failed => TreeChangeSetAdmissionStatus::TerminalFailed,
    };
    Ok(Some(TreeChangeSetAdmission::new(existing, status)))
}

fn insert_change_set_header(
    transaction: &Transaction<'_>,
    attribution: ChangeSetAttribution,
    observed_at: TimestampMillis,
) -> Result<(), ChangeSetStoreError> {
    let change_set_id = attribution.id().into_uuid().into_bytes();
    let workspace_id = attribution.workspace_id().into_uuid().into_bytes();
    let activity_id = attribution.activity_id().into_uuid().into_bytes();
    let runtime_id = attribution.runtime_instance_id().into_uuid().into_bytes();
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
            attribution.activity_lease_revision().get(),
            attribution.workspace_revision().get(),
            encode_change_set_state(ChangeSetState::Starting),
            observed_at.get(),
            ChangeSetRevision::INITIAL.get(),
        ],
    )?;
    Ok(())
}

fn insert_tree_mutation(
    transaction: &Transaction<'_>,
    change_set_id: ChangeSetId,
    mutation: &TreeMutationIntent,
) -> Result<(), ChangeSetStoreError> {
    let mutation_id = mutation.id().into_uuid().into_bytes();
    let change_set_id = change_set_id.into_uuid().into_bytes();
    let encoded = encode_tree_mutation(mutation.plan());
    transaction.execute(
        "INSERT INTO tree_mutations (
            mutation_id, changeset_id, ordinal, kind, primary_path, secondary_path,
            expected_hash, intended_hash, applied, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, 1)",
        params![
            mutation_id.as_slice(),
            change_set_id.as_slice(),
            i64::from(mutation.ordinal().get()),
            encoded.kind,
            encoded.primary_path,
            encoded.secondary_path,
            encoded.expected_hash,
            encoded.intended_hash,
        ],
    )?;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EncodedTreeMutation {
    kind: i64,
    primary_path: Vec<u8>,
    secondary_path: Option<Vec<u8>>,
    expected_hash: Option<Vec<u8>>,
    intended_hash: Option<Vec<u8>>,
}

impl EncodedTreeMutation {
    fn new(
        kind: i64,
        primary_path: Vec<u8>,
        secondary_path: Option<Vec<u8>>,
        expected_hash: Option<Vec<u8>>,
        intended_hash: Option<Vec<u8>>,
    ) -> Self {
        Self {
            kind,
            primary_path,
            secondary_path,
            expected_hash,
            intended_hash,
        }
    }
}

fn encode_tree_mutation(plan: &TreeMutationPlan) -> EncodedTreeMutation {
    let path = |value: &WorkspaceRelativePath| value.as_path().as_os_str().as_bytes().to_vec();
    let hash = |value: FileContentHash| value.as_bytes().to_vec();
    match plan {
        TreeMutationPlan::CreateDirectory { path: primary } => {
            EncodedTreeMutation::new(0, path(primary), None, None, None)
        }
        TreeMutationPlan::CreateFile {
            path: primary,
            intended_hash,
        } => EncodedTreeMutation::new(1, path(primary), None, None, Some(hash(*intended_hash))),
        TreeMutationPlan::UpdateFile {
            path: primary,
            expected_hash,
            intended_hash,
        } => EncodedTreeMutation::new(
            2,
            path(primary),
            None,
            Some(hash(*expected_hash)),
            Some(hash(*intended_hash)),
        ),
        TreeMutationPlan::DeleteFile {
            path: primary,
            expected_hash,
        } => EncodedTreeMutation::new(3, path(primary), None, Some(hash(*expected_hash)), None),
        TreeMutationPlan::MoveFile {
            source,
            destination,
            expected_hash,
        } => EncodedTreeMutation::new(
            4,
            path(source),
            Some(path(destination)),
            Some(hash(*expected_hash)),
            None,
        ),
        TreeMutationPlan::MoveDirectory {
            source,
            destination,
        } => EncodedTreeMutation::new(5, path(source), Some(path(destination)), None, None),
        TreeMutationPlan::DeleteDirectory { path: primary } => {
            EncodedTreeMutation::new(6, path(primary), None, None, None)
        }
    }
}

const CHANGE_SET_HEADER_QUERY: &str = "SELECT
    changeset_id, workspace_id, activity_id, runtime_instance_id,
    activity_lease_revision, workspace_revision, state, failure_code,
    created_at_ms, updated_at_ms, revision
    FROM change_sets";

/// Header existence covers both single-file and tree admissions.
pub(crate) fn has_change_set(
    connection: &Connection,
    change_set_id: ChangeSetId,
) -> Result<bool, ChangeSetStoreError> {
    let id = change_set_id.into_uuid().into_bytes();
    Ok(connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM change_sets WHERE changeset_id = ?1)",
        params![id.as_slice()],
        |row| row.get(0),
    )?)
}

fn query_change_set_header(
    connection: &Connection,
    change_set_id: ChangeSetId,
) -> Result<Option<RegisteredChangeSet>, ChangeSetStoreError> {
    let id = change_set_id.into_uuid().into_bytes();
    connection
        .query_row(
            &format!("{CHANGE_SET_HEADER_QUERY} WHERE changeset_id = ?1"),
            params![id.as_slice()],
            decode_change_set_header,
        )
        .optional()
        .map_err(ChangeSetStoreError::from)
}

fn decode_change_set_header(row: &Row<'_>) -> rusqlite::Result<RegisteredChangeSet> {
    decode_change_set_header_inner(row).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Blob, Box::new(error))
    })
}

fn decode_change_set_header_inner(
    row: &Row<'_>,
) -> Result<RegisteredChangeSet, ChangeSetStoreError> {
    let id =
        decode_uuid("change_set.id", &row.get::<_, Vec<u8>>(0)?).map(ChangeSetId::from_uuid)?;
    let workspace_id = decode_uuid("change_set.workspace_id", &row.get::<_, Vec<u8>>(1)?)
        .map(WorkspaceId::from_uuid)?;
    let activity_id = decode_uuid("change_set.activity_id", &row.get::<_, Vec<u8>>(2)?)
        .map(ActivityId::from_uuid)?;
    let runtime_id = decode_uuid("change_set.runtime_instance_id", &row.get::<_, Vec<u8>>(3)?)
        .map(RuntimeInstanceId::from_uuid)?;
    let lease_revision = ActivityLeaseRevision::new(row.get(4)?)
        .map_err(|_| ChangeSetStoreError::CorruptRecord("change_set.activity_lease_revision"))?;
    let workspace_revision = WorkspaceRevision::new(row.get(5)?)
        .map_err(|_| ChangeSetStoreError::CorruptRecord("change_set.workspace_revision"))?;
    let state = decode_change_set_state(row.get(6)?)?;
    let failure_code = row
        .get::<_, Option<i64>>(7)?
        .map(decode_failure_code)
        .transpose()?;
    validate_failure_shape(state, failure_code)?;
    let created_at = TimestampMillis::new(row.get(8)?)
        .map_err(|_| ChangeSetStoreError::CorruptRecord("change_set.created_at_ms"))?;
    let updated_at = TimestampMillis::new(row.get(9)?)
        .map_err(|_| ChangeSetStoreError::CorruptRecord("change_set.updated_at_ms"))?;
    if updated_at.get() < created_at.get() {
        return Err(ChangeSetStoreError::CorruptRecord(
            "change_set.updated_at_ms",
        ));
    }
    let revision = ChangeSetRevision::new(row.get(10)?)
        .map_err(|_| ChangeSetStoreError::CorruptRecord("change_set.revision"))?;
    Ok(RegisteredChangeSet::from_parts(
        ChangeSetAttribution::new(
            id,
            workspace_id,
            workspace_revision,
            activity_id,
            runtime_id,
            lease_revision,
        ),
        state,
        ChangeSetTimestamps::new(created_at, updated_at),
        revision,
        failure_code,
    ))
}

fn change_set_matches_attribution(
    change_set: &RegisteredChangeSet,
    attribution: ChangeSetAttribution,
) -> bool {
    change_set.id() == attribution.id()
        && change_set.workspace_id() == attribution.workspace_id()
        && change_set.workspace_revision() == attribution.workspace_revision()
        && change_set.activity_id() == attribution.activity_id()
        && change_set.runtime_instance_id() == attribution.runtime_instance_id()
}

fn tree_mutations_match_intent(
    connection: &Connection,
    intent: &TreeChangeSetIntent,
) -> Result<bool, ChangeSetStoreError> {
    let id = intent.attribution().id().into_uuid().into_bytes();
    let mut statement = connection.prepare(
        "SELECT mutation_id, ordinal, kind, primary_path, secondary_path, expected_hash, intended_hash
         FROM tree_mutations WHERE changeset_id = ?1 ORDER BY ordinal ASC",
    )?;
    let mut rows = statement.query(params![id.as_slice()])?;
    for expected in intent.mutations() {
        let Some(row) = rows.next()? else {
            return Ok(false);
        };
        let mutation_id = decode_uuid("tree_mutation.id", &row.get::<_, Vec<u8>>(0)?)?;
        if mutation_id != expected.id().into_uuid()
            || row.get::<_, i64>(1)? != i64::from(expected.ordinal().get())
        {
            return Ok(false);
        }
        let encoded = encode_tree_mutation(expected.plan());
        if row.get::<_, i64>(2)? != encoded.kind
            || row.get::<_, Vec<u8>>(3)? != encoded.primary_path
            || row.get::<_, Option<Vec<u8>>>(4)? != encoded.secondary_path
            || row.get::<_, Option<Vec<u8>>>(5)? != encoded.expected_hash
            || row.get::<_, Option<Vec<u8>>>(6)? != encoded.intended_hash
        {
            return Ok(false);
        }
    }
    Ok(rows.next()?.is_none())
}

pub(crate) fn mark_tree_mutation_applied(
    transaction: &Transaction<'_>,
    change_set_id: ChangeSetId,
    mutation_id: forge_domain::TreeMutationId,
) -> Result<(), ChangeSetStoreError> {
    let change_set = query_change_set_header(transaction, change_set_id)?
        .ok_or(ChangeSetStoreError::RecordMissing)?;
    if change_set.state() != ChangeSetState::Starting {
        return Err(ChangeSetStoreError::Terminal);
    }
    let mutation_bytes = mutation_id.into_uuid().into_bytes();
    let change_set_bytes = change_set_id.into_uuid().into_bytes();
    let current = transaction
        .query_row(
            "SELECT changeset_id, applied, revision FROM tree_mutations WHERE mutation_id = ?1",
            params![mutation_bytes.as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()?
        .ok_or(ChangeSetStoreError::RecordMissing)?;
    if current.0.as_slice() != change_set_bytes.as_slice() {
        return Err(ChangeSetStoreError::IdentityConflict);
    }
    if current.1 == 1 {
        return Ok(());
    }
    if current.1 != 0 || current.2 != 1 {
        return Err(ChangeSetStoreError::RevisionConflict);
    }
    let changed = transaction.execute(
        "UPDATE tree_mutations SET applied = 1, revision = 2
         WHERE mutation_id = ?1 AND changeset_id = ?2 AND applied = 0 AND revision = 1",
        params![mutation_bytes.as_slice(), change_set_bytes.as_slice()],
    )?;
    if changed != 1 {
        return Err(ChangeSetStoreError::RevisionConflict);
    }
    Ok(())
}

pub(crate) fn complete_tree_change_set(
    transaction: &Transaction<'_>,
    change_set_id: ChangeSetId,
    observed_at: TimestampMillis,
) -> Result<RegisteredChangeSet, ChangeSetStoreError> {
    let current = query_change_set_header(transaction, change_set_id)?
        .ok_or(ChangeSetStoreError::RecordMissing)?;
    if current.state() == ChangeSetState::Applied {
        return Ok(current);
    }
    if current.state() != ChangeSetState::Starting {
        return Err(ChangeSetStoreError::Terminal);
    }
    if observed_at.get() < current.created_at().get() {
        return Err(ChangeSetStoreError::TimestampOrder);
    }
    let id = change_set_id.into_uuid().into_bytes();
    let (total, applied): (i64, i64) = transaction.query_row(
        "SELECT COUNT(*), COALESCE(SUM(applied), 0) FROM tree_mutations WHERE changeset_id = ?1",
        params![id.as_slice()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if total <= 0 || applied != total {
        return Err(ChangeSetStoreError::RevisionConflict);
    }
    let next_revision = current
        .revision()
        .checked_next()
        .map_err(|_| ChangeSetStoreError::RevisionOverflow)?;
    let changed = transaction.execute(
        "UPDATE change_sets SET state = ?1, updated_at_ms = ?2, revision = ?3
         WHERE changeset_id = ?4 AND state = ?5 AND revision = ?6",
        params![
            encode_change_set_state(ChangeSetState::Applied),
            observed_at.get(),
            next_revision.get(),
            id.as_slice(),
            encode_change_set_state(ChangeSetState::Starting),
            current.revision().get(),
        ],
    )?;
    if changed != 1 {
        return Err(ChangeSetStoreError::RevisionConflict);
    }
    query_change_set_header(transaction, change_set_id)?.ok_or(ChangeSetStoreError::RecordMissing)
}

pub(crate) fn fail_tree_change_set_without_effect(
    transaction: &Transaction<'_>,
    change_set_id: ChangeSetId,
    failure_code: FileMutationFailureCode,
    observed_at: TimestampMillis,
) -> Result<RegisteredChangeSet, ChangeSetStoreError> {
    let current = query_change_set_header(transaction, change_set_id)?
        .ok_or(ChangeSetStoreError::RecordMissing)?;
    if current.state() != ChangeSetState::Starting {
        return Err(ChangeSetStoreError::Terminal);
    }
    if observed_at.get() < current.created_at().get() {
        return Err(ChangeSetStoreError::TimestampOrder);
    }
    let id = change_set_id.into_uuid().into_bytes();
    let applied: i64 = transaction.query_row(
        "SELECT COALESCE(SUM(applied), 0) FROM tree_mutations WHERE changeset_id = ?1",
        params![id.as_slice()],
        |row| row.get(0),
    )?;
    if applied != 0 {
        return Err(ChangeSetStoreError::RevisionConflict);
    }
    let next_revision = current
        .revision()
        .checked_next()
        .map_err(|_| ChangeSetStoreError::RevisionOverflow)?;
    let changed = transaction.execute(
        "UPDATE change_sets
         SET state = ?1, failure_code = ?2, updated_at_ms = ?3, revision = ?4
         WHERE changeset_id = ?5 AND state = ?6 AND revision = ?7",
        params![
            encode_change_set_state(ChangeSetState::Failed),
            encode_failure_code(failure_code),
            observed_at.get(),
            next_revision.get(),
            id.as_slice(),
            encode_change_set_state(ChangeSetState::Starting),
            current.revision().get(),
        ],
    )?;
    if changed != 1 {
        return Err(ChangeSetStoreError::RevisionConflict);
    }
    query_change_set_header(transaction, change_set_id)?.ok_or(ChangeSetStoreError::RecordMissing)
}

pub(crate) fn tree_change_set_applied_mutations(
    connection: &Connection,
    change_set_id: ChangeSetId,
) -> Result<Vec<forge_domain::TreeMutationId>, ChangeSetStoreError> {
    let id = change_set_id.into_uuid().into_bytes();
    let mut statement = connection.prepare(
        "SELECT mutation_id FROM tree_mutations
         WHERE changeset_id = ?1 AND applied = 1 ORDER BY ordinal ASC",
    )?;
    statement
        .query_map(params![id.as_slice()], |row| row.get::<_, Vec<u8>>(0))?
        .map(|row| {
            let raw = row?;
            decode_uuid("tree_mutation.id", &raw).map(forge_domain::TreeMutationId::from_uuid)
        })
        .collect()
}

pub(crate) struct SourceTreeReadData {
    pub(crate) change_set: RegisteredChangeSet,
    pub(crate) request_digest: SourceTreeRequestDigest,
    pub(crate) applied_mutations: Vec<TreeMutationId>,
    pub(crate) mutation_count: usize,
}

pub(crate) fn source_tree_read_data(
    connection: &Connection,
    change_set_id: ChangeSetId,
) -> Result<Option<SourceTreeReadData>, ChangeSetStoreError> {
    let Some(request_digest) =
        crate::workspace_source_tree_requests::get(connection, change_set_id)
            .map_err(map_source_tree_request_store_error)?
    else {
        return Ok(None);
    };
    let change_set = query_change_set_header(connection, change_set_id)?.ok_or(
        ChangeSetStoreError::CorruptRecord("source_tree_requests.change_set"),
    )?;
    let id = change_set_id.into_uuid().into_bytes();
    let bounded_limit = i64::try_from(MAX_TREE_CHANGESET_MUTATIONS + 1)
        .map_err(|_| ChangeSetStoreError::CorruptRecord("tree_mutations.limit"))?;
    let mut statement = connection.prepare(
        "SELECT mutation_id, applied FROM tree_mutations
         WHERE changeset_id = ?1 ORDER BY ordinal ASC LIMIT ?2",
    )?;
    let mut rows = statement.query(params![id.as_slice(), bounded_limit])?;
    let mut applied_mutations = Vec::new();
    let mut mutation_count = 0_usize;
    while let Some(row) = rows.next()? {
        mutation_count = mutation_count
            .checked_add(1)
            .ok_or(ChangeSetStoreError::CorruptRecord("tree_mutations.count"))?;
        if mutation_count > MAX_TREE_CHANGESET_MUTATIONS {
            return Err(ChangeSetStoreError::CorruptRecord("tree_mutations.count"));
        }
        let raw_mutation_id = row
            .get::<_, Option<Vec<u8>>>(0)
            .map_err(|_| ChangeSetStoreError::CorruptRecord("tree_mutation.id"))?
            .ok_or(ChangeSetStoreError::CorruptRecord("tree_mutation.id"))?;
        let mutation_id =
            decode_uuid("tree_mutation.id", &raw_mutation_id).map(TreeMutationId::from_uuid)?;
        match row
            .get::<_, Option<i64>>(1)
            .map_err(|_| ChangeSetStoreError::CorruptRecord("tree_mutation.applied"))?
        {
            Some(0) => {}
            Some(1) => applied_mutations.push(mutation_id),
            _ => return Err(ChangeSetStoreError::CorruptRecord("tree_mutation.applied")),
        }
    }
    if mutation_count == 0 {
        return Err(ChangeSetStoreError::CorruptRecord("tree_mutations.rows"));
    }
    Ok(Some(SourceTreeReadData {
        change_set,
        request_digest,
        applied_mutations,
        mutation_count,
    }))
}

pub(crate) fn begin(
    transaction: &Transaction<'_>,
    command: &BeginFileMutation,
) -> Result<BeginFileMutationResult, ChangeSetStoreError> {
    let current_activity_lease_revision = validate_scope(transaction, command)?;
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
            current_activity_lease_revision.get(),
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

fn validate_change_set_scope(
    transaction: &Transaction<'_>,
    attribution: ChangeSetAttribution,
) -> Result<ActivityLeaseRevision, ChangeSetStoreError> {
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
    if stored_workspace_id != attribution.workspace_id() {
        return Err(ChangeSetStoreError::WorkspaceMismatch);
    }
    let workspace_revision: i64 = transaction.query_row(
        "SELECT revision FROM workspace WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    if WorkspaceRevision::new(workspace_revision)
        .map_err(|_| ChangeSetStoreError::CorruptRecord("workspace.revision"))?
        != attribution.workspace_revision()
    {
        return Err(ChangeSetStoreError::WorkspaceRevisionConflict);
    }
    let activity_id = attribution.activity_id().into_uuid().into_bytes();
    let activity = transaction
        .query_row(
            "SELECT workspace_id, state, lease_revision
         FROM activities WHERE activity_id = ?1",
            params![activity_id.as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()?
        .ok_or(ChangeSetStoreError::ActivityMissing)?;
    if decode_uuid("activity.workspace_id", &activity.0).map(WorkspaceId::from_uuid)?
        != attribution.workspace_id()
    {
        return Err(ChangeSetStoreError::ActivityWorkspaceMismatch);
    }
    if activity.1 != 1 {
        return Err(ChangeSetStoreError::ActivityNotOpen);
    }
    ActivityLeaseRevision::new(activity.2)
        .map_err(|_| ChangeSetStoreError::CorruptRecord("activity.lease_revision"))
}

fn validate_scope(
    transaction: &Transaction<'_>,
    command: &BeginFileMutation,
) -> Result<ActivityLeaseRevision, ChangeSetStoreError> {
    validate_change_set_scope(
        transaction,
        ChangeSetAttribution::new(
            command.change_set_id(),
            command.workspace_id(),
            command.expected_workspace_revision(),
            command.activity_id(),
            command.runtime_instance_id(),
            command.activity_lease_revision(),
        ),
    )
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

pub(crate) fn schema_objects() -> [(&'static str, &'static str); 5] {
    [
        ("table", "change_sets"),
        ("table", "file_mutations"),
        ("table", "tree_mutations"),
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
        "table",
        "tree_mutations",
        EXPECTED_TREE_MUTATIONS_TABLE_SQL,
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
    validate_table_columns(
        connection,
        "tree_mutations",
        &[
            ("mutation_id", "BLOB", 1, 1),
            ("changeset_id", "BLOB", 1, 0),
            ("ordinal", "INTEGER", 1, 0),
            ("kind", "INTEGER", 1, 0),
            ("primary_path", "BLOB", 1, 0),
            ("secondary_path", "BLOB", 0, 0),
            ("expected_hash", "BLOB", 0, 0),
            ("intended_hash", "BLOB", 0, 0),
            ("applied", "INTEGER", 1, 0),
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
    validate_foreign_keys(connection, "tree_mutations", 1)?;
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
            ("table", "tree_mutations", EXPECTED_TREE_MUTATIONS_TABLE_SQL),
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

    fn tree_changeset_test_connection()
    -> Result<(Connection, ChangeSetAttribution), Box<dyn std::error::Error>> {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE workspace(
                singleton INTEGER PRIMARY KEY,
                workspace_id BLOB NOT NULL UNIQUE,
                revision INTEGER NOT NULL
             );
             CREATE TABLE activities(
                activity_id BLOB PRIMARY KEY,
                workspace_id BLOB NOT NULL,
                state INTEGER NOT NULL,
                lease_owner_id BLOB,
                lease_until_ms INTEGER,
                lease_revision INTEGER NOT NULL
             );",
        )?;
        create_schema(&connection)?;
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(0xC100));
        let activity_id = ActivityId::from_uuid(Uuid::from_u128(0xC101));
        let runtime_id = RuntimeInstanceId::from_uuid(Uuid::from_u128(0xC102));
        connection.execute(
            "INSERT INTO workspace(singleton, workspace_id, revision) VALUES(1, ?1, 1)",
            params![workspace_id.into_uuid().as_bytes()],
        )?;
        connection.execute(
            "INSERT INTO activities(
                activity_id, workspace_id, state, lease_owner_id, lease_until_ms, lease_revision
             ) VALUES(?1, ?2, 1, ?3, 1000, 1)",
            params![
                activity_id.into_uuid().as_bytes(),
                workspace_id.into_uuid().as_bytes(),
                runtime_id.into_uuid().as_bytes(),
            ],
        )?;
        Ok((
            connection,
            ChangeSetAttribution::new(
                ChangeSetId::from_uuid(Uuid::from_u128(0xC103)),
                workspace_id,
                WorkspaceRevision::INITIAL,
                activity_id,
                runtime_id,
                ActivityLeaseRevision::INITIAL,
            ),
        ))
    }

    fn tree_changeset_test_plan(
        create_hash: u8,
    ) -> Result<forge_domain::TreeChangeSetPlan, Box<dyn std::error::Error>> {
        let hash = |value| FileContentHash::from_bytes([value; FileContentHash::BYTE_LEN]);
        Ok(forge_domain::TreeChangeSetPlan::new(vec![
            TreeMutationPlan::create_file(
                WorkspaceRelativePath::new(PathBuf::from(".agents/rules.md"))?,
                hash(create_hash),
            ),
            TreeMutationPlan::create_directory(WorkspaceRelativePath::new(PathBuf::from(
                ".agents",
            ))?),
            TreeMutationPlan::update_file(
                WorkspaceRelativePath::new(PathBuf::from("src/lib.rs"))?,
                hash(2),
                hash(3),
            ),
        ])?)
    }

    fn tree_changeset_test_mutation_ids() -> Vec<forge_domain::TreeMutationId> {
        [0xC110_u128, 0xC111, 0xC112]
            .into_iter()
            .map(|value| forge_domain::TreeMutationId::from_uuid(Uuid::from_u128(value)))
            .collect()
    }

    #[test]
    fn tree_changeset_records_transaction_current_activity_revision_and_retries_across_heartbeat()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut connection, attribution) = tree_changeset_test_connection()?;
        let activity_id = attribution.activity_id().into_uuid().into_bytes();
        connection.execute(
            "UPDATE activities
             SET lease_revision = 2, lease_owner_id = zeroblob(16), lease_until_ms = 1
             WHERE activity_id = ?1",
            params![activity_id.as_slice()],
        )?;
        let intent = TreeChangeSetIntent::from_plan(
            attribution,
            tree_changeset_test_mutation_ids(),
            &tree_changeset_test_plan(1)?,
            TimestampMillis::new(20)?,
        )?;

        let transaction = connection.transaction()?;
        let started = begin_tree_change_set(&transaction, &intent)?;
        assert_eq!(started.status(), TreeChangeSetAdmissionStatus::Started);
        assert_eq!(started.change_set().activity_lease_revision().get(), 2);
        transaction.commit()?;

        connection.execute(
            "UPDATE activities SET lease_revision = 3 WHERE activity_id = ?1",
            params![activity_id.as_slice()],
        )?;
        let transaction = connection.transaction()?;
        let retry = begin_tree_change_set(&transaction, &intent)?;
        assert_eq!(
            retry.status(),
            TreeChangeSetAdmissionStatus::RecoveryRequired
        );
        assert_eq!(retry.change_set().activity_lease_revision().get(), 2);
        transaction.commit()?;
        Ok(())
    }

    #[test]
    fn tree_changeset_journal_is_ordered_idempotent_and_conflict_bound()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut connection, attribution) = tree_changeset_test_connection()?;
        let mutation_ids = tree_changeset_test_mutation_ids();
        let intent = TreeChangeSetIntent::from_plan(
            attribution,
            mutation_ids.clone(),
            &tree_changeset_test_plan(1)?,
            TimestampMillis::new(20)?,
        )?;
        let transaction = connection.transaction()?;
        let started = begin_tree_change_set(&transaction, &intent)?;
        assert_eq!(started.status(), TreeChangeSetAdmissionStatus::Started);
        transaction.commit()?;

        let observed = connection
            .prepare(
                "SELECT ordinal, kind FROM tree_mutations
                 WHERE changeset_id = ?1 ORDER BY ordinal ASC",
            )?
            .query_map(params![attribution.id().into_uuid().as_bytes()], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(observed, vec![(0, 0), (1, 1), (2, 2)]);

        let transaction = connection.transaction()?;
        let retry = begin_tree_change_set(&transaction, &intent)?;
        assert_eq!(
            retry.status(),
            TreeChangeSetAdmissionStatus::RecoveryRequired
        );
        transaction.commit()?;

        let conflicting = TreeChangeSetIntent::from_plan(
            attribution,
            mutation_ids,
            &tree_changeset_test_plan(9)?,
            TimestampMillis::new(20)?,
        )?;
        let transaction = connection.transaction()?;
        assert!(matches!(
            begin_tree_change_set(&transaction, &conflicting),
            Err(ChangeSetStoreError::IdentityConflict)
        ));
        drop(transaction);
        Ok(())
    }

    #[test]
    fn tree_changeset_partial_progress_stays_recovery_required_until_all_applied()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut connection, attribution) = tree_changeset_test_connection()?;
        create_source_tree_request_schema(&connection)?;
        let mutation_ids = tree_changeset_test_mutation_ids();
        let intent = TreeChangeSetIntent::from_plan(
            attribution,
            mutation_ids.clone(),
            &tree_changeset_test_plan(1)?,
            TimestampMillis::new(20)?,
        )?;
        let transaction = connection.transaction()?;
        assert_eq!(
            begin_tree_change_set(&transaction, &intent)?.status(),
            TreeChangeSetAdmissionStatus::Started
        );
        transaction.commit()?;
        let request_digest =
            SourceTreeRequestDigest::from_bytes([7; SourceTreeRequestDigest::BYTE_LEN]);
        insert_source_tree_request_digest(&connection, attribution.id(), request_digest)?;

        let transaction = connection.transaction()?;
        mark_tree_mutation_applied(&transaction, attribution.id(), mutation_ids[0])?;
        transaction.commit()?;
        let read = source_tree_read_data(&connection, attribution.id())?
            .ok_or("request journal missing")?;
        assert_eq!(read.change_set.id(), attribution.id());
        assert_eq!(read.request_digest, request_digest);
        assert_eq!(read.applied_mutations, vec![mutation_ids[0]]);
        assert_eq!(read.mutation_count, mutation_ids.len());
        assert_eq!(
            tree_change_set_applied_mutations(&connection, attribution.id())?,
            vec![mutation_ids[0]]
        );
        let transaction = connection.transaction()?;
        assert_eq!(
            begin_tree_change_set(&transaction, &intent)?.status(),
            TreeChangeSetAdmissionStatus::RecoveryRequired
        );
        assert!(matches!(
            complete_tree_change_set(&transaction, attribution.id(), TimestampMillis::new(21)?),
            Err(ChangeSetStoreError::RevisionConflict)
        ));
        drop(transaction);

        for mutation_id in &mutation_ids[1..] {
            let transaction = connection.transaction()?;
            mark_tree_mutation_applied(&transaction, attribution.id(), *mutation_id)?;
            transaction.commit()?;
        }
        let transaction = connection.transaction()?;
        let completed =
            complete_tree_change_set(&transaction, attribution.id(), TimestampMillis::new(22)?)?;
        assert_eq!(completed.state(), ChangeSetState::Applied);
        transaction.commit()?;
        let transaction = connection.transaction()?;
        assert_eq!(
            begin_tree_change_set(&transaction, &intent)?.status(),
            TreeChangeSetAdmissionStatus::AlreadyApplied
        );
        drop(transaction);
        Ok(())
    }

    #[test]
    fn tree_changeset_can_fail_terminally_only_before_any_applied_effect()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut connection, attribution) = tree_changeset_test_connection()?;
        let mutation_ids = tree_changeset_test_mutation_ids();
        let intent = TreeChangeSetIntent::from_plan(
            attribution,
            mutation_ids.clone(),
            &tree_changeset_test_plan(1)?,
            TimestampMillis::new(20)?,
        )?;
        let transaction = connection.transaction()?;
        let _started = begin_tree_change_set(&transaction, &intent)?;
        transaction.commit()?;
        let transaction = connection.transaction()?;
        let failed = fail_tree_change_set_without_effect(
            &transaction,
            attribution.id(),
            FileMutationFailureCode::PathConflict,
            TimestampMillis::new(21)?,
        )?;
        assert_eq!(failed.state(), ChangeSetState::Failed);
        transaction.commit()?;

        let (mut connection, attribution) = tree_changeset_test_connection()?;
        let intent = TreeChangeSetIntent::from_plan(
            attribution,
            mutation_ids.clone(),
            &tree_changeset_test_plan(1)?,
            TimestampMillis::new(20)?,
        )?;
        let transaction = connection.transaction()?;
        let _started = begin_tree_change_set(&transaction, &intent)?;
        transaction.commit()?;
        let transaction = connection.transaction()?;
        mark_tree_mutation_applied(&transaction, attribution.id(), mutation_ids[0])?;
        transaction.commit()?;
        let transaction = connection.transaction()?;
        assert!(matches!(
            fail_tree_change_set_without_effect(
                &transaction,
                attribution.id(),
                FileMutationFailureCode::IoFailure,
                TimestampMillis::new(21)?,
            ),
            Err(ChangeSetStoreError::RevisionConflict)
        ));
        drop(transaction);
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
