use std::ffi::OsString;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use forge_domain::{
    AbandonDiffEvidence, ActivityId, BeginDiffEvidence, BeginDiffPurge, BeginFileMutation,
    ChangeSetId, ChangeSetState, CompleteDiffEvidence, CompleteDiffPurge,
    DiffArtifactInventoryName, DiffArtifactRelativePath, DiffAttribution, DiffByteCount,
    DiffChangeKind, DiffContractVersions, DiffEvidenceState, DiffEvidenceTimestamps,
    DiffFileSummary, DiffId, DiffLineCount, DiffListLimit, DiffPayloadHash, DiffPayloadProjection,
    DiffPurgeRecord, DiffPurgeStatus, DiffRedactionPolicyVersion, DiffRenderKind,
    DiffRendererVersion, DiffRetentionKeepCount, DiffRetentionPlanLimit, DiffRevision,
    FileMutationId, RegisteredDiffEvidence, TimestampMillis, WorkspaceId, WorkspaceRelativePath,
};
use rusqlite::{Connection, OptionalExtension, Row, Transaction, TransactionBehavior, params};
use thiserror::Error;
use uuid::Uuid;

pub(crate) const EXPECTED_DIFF_EVIDENCE_TABLE_SQL: &str = "CREATE TABLE diff_evidence (diff_id BLOB PRIMARY KEY NOT NULL CHECK(length(diff_id) = 16), changeset_id BLOB NOT NULL UNIQUE REFERENCES change_sets(changeset_id), workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id), activity_id BLOB NOT NULL REFERENCES activities(activity_id), mutation_id BLOB NOT NULL UNIQUE REFERENCES file_mutations(mutation_id), state INTEGER NOT NULL CHECK(state IN (0, 1, 2, 3, 4, 5)), render_kind INTEGER NOT NULL CHECK(render_kind IN (0, 1, 2)), pending_relative_path BLOB CHECK(pending_relative_path IS NULL OR length(pending_relative_path) BETWEEN 1 AND 4096), artifact_relative_path BLOB CHECK(artifact_relative_path IS NULL OR length(artifact_relative_path) BETWEEN 1 AND 4096), compressed_hash BLOB CHECK(compressed_hash IS NULL OR length(compressed_hash) = 32), uncompressed_hash BLOB CHECK(uncompressed_hash IS NULL OR length(uncompressed_hash) = 32), compressed_size INTEGER CHECK(compressed_size IS NULL OR compressed_size >= 0), uncompressed_size INTEGER CHECK(uncompressed_size IS NULL OR uncompressed_size >= 0), renderer_version INTEGER NOT NULL CHECK(renderer_version >= 1), redaction_policy_version INTEGER NOT NULL CHECK(redaction_policy_version >= 1), created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0), updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0), revision INTEGER NOT NULL CHECK(revision >= 1), CHECK((state = 0 AND render_kind = 0 AND pending_relative_path IS NOT NULL AND artifact_relative_path IS NOT NULL AND compressed_hash IS NOT NULL AND uncompressed_hash IS NOT NULL AND compressed_size IS NOT NULL AND uncompressed_size IS NOT NULL) OR (state = 0 AND render_kind IN (1, 2) AND pending_relative_path IS NULL AND artifact_relative_path IS NULL AND compressed_hash IS NULL AND uncompressed_hash IS NULL AND compressed_size IS NULL AND uncompressed_size IS NULL) OR (state IN (1, 4) AND render_kind = 0 AND pending_relative_path IS NULL AND artifact_relative_path IS NOT NULL AND compressed_hash IS NOT NULL AND uncompressed_hash IS NOT NULL AND compressed_size IS NOT NULL AND uncompressed_size IS NOT NULL) OR (state = 2 AND render_kind IN (1, 2) AND pending_relative_path IS NULL AND artifact_relative_path IS NULL AND compressed_hash IS NULL AND uncompressed_hash IS NULL AND compressed_size IS NULL AND uncompressed_size IS NULL) OR (state IN (3, 5) AND pending_relative_path IS NULL AND artifact_relative_path IS NULL AND compressed_hash IS NULL AND uncompressed_hash IS NULL AND compressed_size IS NULL AND uncompressed_size IS NULL)))";
pub(crate) const EXPECTED_DIFF_FILES_TABLE_SQL: &str = "CREATE TABLE diff_files (diff_id BLOB PRIMARY KEY NOT NULL REFERENCES diff_evidence(diff_id), ordinal INTEGER NOT NULL CHECK(ordinal = 0), relative_path BLOB NOT NULL CHECK(length(relative_path) BETWEEN 1 AND 4096), kind INTEGER NOT NULL CHECK(kind IN (0, 1, 2)), additions INTEGER NOT NULL CHECK(additions >= 0), deletions INTEGER NOT NULL CHECK(deletions >= 0))";
pub(crate) const EXPECTED_DIFF_ACTIVITY_INDEX_SQL: &str = "CREATE INDEX diff_evidence_activity_created_idx ON diff_evidence(activity_id, created_at_ms DESC, diff_id DESC)";
pub(crate) const EXPECTED_DIFF_STATE_INDEX_SQL: &str =
    "CREATE INDEX diff_evidence_state_updated_idx ON diff_evidence(state, updated_at_ms, diff_id)";
pub(crate) const EXPECTED_DIFF_RETENTION_INDEX_SQL: &str = "CREATE INDEX diff_evidence_retention_idx ON diff_evidence(state, render_kind, created_at_ms DESC, diff_id DESC)";

const MAX_PATH_BYTES: usize = 4_096;
const HASH_BYTES: usize = 32;
/// Maximum number of durable Diff rows retained by one Doctor projection.
pub const DIFF_DOCTOR_MAX_REFERENCES: usize = 256;
const DIFF_DOCTOR_PROBE_REFERENCES: usize = DIFF_DOCTOR_MAX_REFERENCES + 1;

/// Bounded, metadata-only Diff reference projection for filesystem Doctor
/// composition.
///
/// The projection contains durable lifecycle facts and hash/size references,
/// never compressed or rendered payload bytes. It is deliberately separate
/// from the generic Workspace Doctor report so persistence can expose the
/// exact Diff/filesystem join boundary without making the aggregate report
/// carry a second variable-sized collection.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffDoctorReport {
    references: Vec<DiffDoctorReference>,
    truncated: bool,
}

impl DiffDoctorReport {
    const fn new(references: Vec<DiffDoctorReference>, truncated: bool) -> Self {
        Self {
            references,
            truncated,
        }
    }

    /// Durable Diff/legacy references in deterministic `DiffId` order.
    pub fn references(&self) -> &[DiffDoctorReference] {
        &self.references
    }

    /// Whether at least one durable reference existed beyond the 256-row
    /// Doctor bound.
    pub const fn truncated(&self) -> bool {
        self.truncated
    }
}

/// One current durable Diff row or one migrated legacy `ChangeSet` identity.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffDoctorReference {
    diff_id: DiffId,
    lifecycle: DiffDoctorLifecycle,
    pending_artifact: Option<DiffDoctorArtifactReference>,
    final_artifact: Option<DiffDoctorArtifactReference>,
}

impl DiffDoctorReference {
    pub const fn diff_id(&self) -> DiffId {
        self.diff_id
    }

    pub const fn lifecycle(&self) -> &DiffDoctorLifecycle {
        &self.lifecycle
    }

    /// Pending artifact expectation, present only for text Diff intents.
    pub const fn pending_artifact(&self) -> Option<&DiffDoctorArtifactReference> {
        self.pending_artifact.as_ref()
    }

    /// Final artifact expectation, present for text intents, Ready, and
    /// retention-pending rows.
    pub const fn final_artifact(&self) -> Option<&DiffDoctorArtifactReference> {
        self.final_artifact.as_ref()
    }

    pub const fn is_legacy(&self) -> bool {
        matches!(self.lifecycle, DiffDoctorLifecycle::Legacy { .. })
    }
}

/// Durable state carried by a Diff Doctor reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffDoctorLifecycle {
    Evidence {
        state: DiffEvidenceState,
        render_kind: DiffRenderKind,
    },
    Legacy {
        change_set_state: ChangeSetState,
    },
}

impl DiffDoctorLifecycle {
    pub const fn evidence_state(self) -> Option<DiffEvidenceState> {
        match self {
            Self::Evidence { state, .. } => Some(state),
            Self::Legacy { .. } => None,
        }
    }

    pub const fn render_kind(self) -> Option<DiffRenderKind> {
        match self {
            Self::Evidence { render_kind, .. } => Some(render_kind),
            Self::Legacy { .. } => None,
        }
    }

    pub const fn legacy_change_set_state(self) -> Option<ChangeSetState> {
        match self {
            Self::Evidence { .. } => None,
            Self::Legacy { change_set_state } => Some(change_set_state),
        }
    }
}

/// Hash/size/name metadata for one identity-derived Diff artifact.
///
/// The name is a single native path component so it can be compared directly
/// with `DiffArtifactInventoryEntry` without lossy UTF-8 conversion. Both
/// compressed and uncompressed metadata are retained because a filesystem
/// Doctor must be able to distinguish a byte mismatch from a valid compressed
/// envelope whose rendered payload is corrupt.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffDoctorArtifactReference {
    name: DiffArtifactInventoryName,
    compressed_hash: DiffPayloadHash,
    compressed_size: DiffByteCount,
    uncompressed_hash: DiffPayloadHash,
    uncompressed_size: DiffByteCount,
}

impl DiffDoctorArtifactReference {
    pub const fn name(&self) -> &DiffArtifactInventoryName {
        &self.name
    }

    pub const fn compressed_hash(&self) -> DiffPayloadHash {
        self.compressed_hash
    }

    pub const fn compressed_size(&self) -> DiffByteCount {
        self.compressed_size
    }

    pub const fn uncompressed_hash(&self) -> DiffPayloadHash {
        self.uncompressed_hash
    }

    pub const fn uncompressed_size(&self) -> DiffByteCount {
        self.uncompressed_size
    }
}

const RECORD_QUERY: &str = "SELECT
        length(CAST(e.diff_id AS BLOB)), length(CAST(e.workspace_id AS BLOB)),
        length(CAST(e.activity_id AS BLOB)), length(CAST(e.changeset_id AS BLOB)),
        length(CAST(e.mutation_id AS BLOB)), length(CAST(f.relative_path AS BLOB)),
        length(CAST(e.pending_relative_path AS BLOB)),
        length(CAST(e.artifact_relative_path AS BLOB)),
        length(CAST(e.compressed_hash AS BLOB)), length(CAST(e.uncompressed_hash AS BLOB)),
        e.diff_id, e.workspace_id, e.activity_id, e.changeset_id, e.mutation_id,
        e.state, e.render_kind, e.pending_relative_path, e.artifact_relative_path,
        e.compressed_hash, e.uncompressed_hash, e.compressed_size, e.uncompressed_size,
        e.renderer_version, e.redaction_policy_version, e.created_at_ms, e.updated_at_ms,
        e.revision, f.relative_path, f.kind, f.additions, f.deletions,
        e.workspace_id = c.workspace_id, e.activity_id = c.activity_id,
        e.changeset_id = m.changeset_id, c.state
    FROM diff_evidence AS e
    JOIN diff_files AS f ON f.diff_id = e.diff_id
    JOIN change_sets AS c ON c.changeset_id = e.changeset_id
    JOIN file_mutations AS m ON m.mutation_id = e.mutation_id";

const LEGACY_DOCTOR_QUERY: &str = "SELECT
        length(CAST(c.changeset_id AS BLOB)),
        length(CAST(c.workspace_id AS BLOB)),
        length(CAST(c.activity_id AS BLOB)),
        length(CAST(f.mutation_id AS BLOB)),
        length(CAST(f.relative_path AS BLOB)),
        c.changeset_id, c.workspace_id, c.activity_id, c.state,
        c.created_at_ms, c.updated_at_ms, c.revision,
        f.mutation_id, f.relative_path
    FROM change_sets AS c
    LEFT JOIN diff_evidence AS e ON e.changeset_id = c.changeset_id
    LEFT JOIN file_mutations AS f ON f.changeset_id = c.changeset_id
    WHERE e.diff_id IS NULL
    ORDER BY c.changeset_id ASC
    LIMIT 257";

pub(crate) fn create_schema(connection: &Connection) -> Result<(), DiffStoreError> {
    create_schema_v4(connection)?;
    create_retention_index(connection)
}

fn create_schema_v4(connection: &Connection) -> Result<(), DiffStoreError> {
    connection.execute_batch(
        "CREATE TABLE diff_evidence (
            diff_id BLOB PRIMARY KEY NOT NULL CHECK(length(diff_id) = 16),
            changeset_id BLOB NOT NULL UNIQUE REFERENCES change_sets(changeset_id),
            workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id),
            activity_id BLOB NOT NULL REFERENCES activities(activity_id),
            mutation_id BLOB NOT NULL UNIQUE REFERENCES file_mutations(mutation_id),
            state INTEGER NOT NULL CHECK(state IN (0, 1, 2, 3, 4, 5)),
            render_kind INTEGER NOT NULL CHECK(render_kind IN (0, 1, 2)),
            pending_relative_path BLOB CHECK(pending_relative_path IS NULL OR length(pending_relative_path) BETWEEN 1 AND 4096),
            artifact_relative_path BLOB CHECK(artifact_relative_path IS NULL OR length(artifact_relative_path) BETWEEN 1 AND 4096),
            compressed_hash BLOB CHECK(compressed_hash IS NULL OR length(compressed_hash) = 32),
            uncompressed_hash BLOB CHECK(uncompressed_hash IS NULL OR length(uncompressed_hash) = 32),
            compressed_size INTEGER CHECK(compressed_size IS NULL OR compressed_size >= 0),
            uncompressed_size INTEGER CHECK(uncompressed_size IS NULL OR uncompressed_size >= 0),
            renderer_version INTEGER NOT NULL CHECK(renderer_version >= 1),
            redaction_policy_version INTEGER NOT NULL CHECK(redaction_policy_version >= 1),
            created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
            updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0),
            revision INTEGER NOT NULL CHECK(revision >= 1),
            CHECK(
                (state = 0 AND render_kind = 0 AND pending_relative_path IS NOT NULL AND artifact_relative_path IS NOT NULL AND compressed_hash IS NOT NULL AND uncompressed_hash IS NOT NULL AND compressed_size IS NOT NULL AND uncompressed_size IS NOT NULL)
                OR (state = 0 AND render_kind IN (1, 2) AND pending_relative_path IS NULL AND artifact_relative_path IS NULL AND compressed_hash IS NULL AND uncompressed_hash IS NULL AND compressed_size IS NULL AND uncompressed_size IS NULL)
                OR (state IN (1, 4) AND render_kind = 0 AND pending_relative_path IS NULL AND artifact_relative_path IS NOT NULL AND compressed_hash IS NOT NULL AND uncompressed_hash IS NOT NULL AND compressed_size IS NOT NULL AND uncompressed_size IS NOT NULL)
                OR (state = 2 AND render_kind IN (1, 2) AND pending_relative_path IS NULL AND artifact_relative_path IS NULL AND compressed_hash IS NULL AND uncompressed_hash IS NULL AND compressed_size IS NULL AND uncompressed_size IS NULL)
                OR (state IN (3, 5) AND pending_relative_path IS NULL AND artifact_relative_path IS NULL AND compressed_hash IS NULL AND uncompressed_hash IS NULL AND compressed_size IS NULL AND uncompressed_size IS NULL)
            )
         );
         CREATE TABLE diff_files (
            diff_id BLOB PRIMARY KEY NOT NULL REFERENCES diff_evidence(diff_id),
            ordinal INTEGER NOT NULL CHECK(ordinal = 0),
            relative_path BLOB NOT NULL CHECK(length(relative_path) BETWEEN 1 AND 4096),
            kind INTEGER NOT NULL CHECK(kind IN (0, 1, 2)),
            additions INTEGER NOT NULL CHECK(additions >= 0),
            deletions INTEGER NOT NULL CHECK(deletions >= 0)
         );
         CREATE INDEX diff_evidence_activity_created_idx
            ON diff_evidence(activity_id, created_at_ms DESC, diff_id DESC);
         CREATE INDEX diff_evidence_state_updated_idx
            ON diff_evidence(state, updated_at_ms, diff_id);",
    )?;
    Ok(())
}

pub(crate) fn migrate_v3_to_v4(
    connection: &mut Connection,
    next_schema_version: i64,
) -> Result<(), DiffStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    create_schema_v4(&transaction)?;
    transaction.pragma_update(None, "user_version", next_schema_version)?;
    transaction.commit()?;
    Ok(())
}

pub(crate) fn migrate_v4_to_v5(
    connection: &mut Connection,
    next_schema_version: i64,
) -> Result<(), DiffStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    create_retention_index(&transaction)?;
    transaction.pragma_update(None, "user_version", next_schema_version)?;
    transaction.commit()?;
    Ok(())
}

fn create_retention_index(connection: &Connection) -> Result<(), DiffStoreError> {
    connection.execute_batch(
        "CREATE INDEX diff_evidence_retention_idx
            ON diff_evidence(state, render_kind, created_at_ms DESC, diff_id DESC);",
    )?;
    Ok(())
}

pub(crate) fn schema_objects() -> [(&'static str, &'static str); 5] {
    [
        ("table", "diff_evidence"),
        ("table", "diff_files"),
        ("index", "diff_evidence_activity_created_idx"),
        ("index", "diff_evidence_state_updated_idx"),
        ("index", "diff_evidence_retention_idx"),
    ]
}

pub(crate) fn schema_objects_v4() -> [(&'static str, &'static str); 4] {
    [
        ("table", "diff_evidence"),
        ("table", "diff_files"),
        ("index", "diff_evidence_activity_created_idx"),
        ("index", "diff_evidence_state_updated_idx"),
    ]
}

pub(crate) fn validate_schema(connection: &Connection) -> Result<(), DiffStoreError> {
    validate_schema_v4(connection)?;
    validate_schema_sql(
        connection,
        "index",
        "diff_evidence_retention_idx",
        EXPECTED_DIFF_RETENTION_INDEX_SQL,
    )?;
    validate_index_columns(
        connection,
        "diff_evidence_retention_idx",
        &["state", "render_kind", "created_at_ms", "diff_id"],
    )
}

pub(crate) fn validate_schema_v4(connection: &Connection) -> Result<(), DiffStoreError> {
    validate_schema_sql(
        connection,
        "table",
        "diff_evidence",
        EXPECTED_DIFF_EVIDENCE_TABLE_SQL,
    )?;
    validate_schema_sql(
        connection,
        "table",
        "diff_files",
        EXPECTED_DIFF_FILES_TABLE_SQL,
    )?;
    validate_schema_sql(
        connection,
        "index",
        "diff_evidence_activity_created_idx",
        EXPECTED_DIFF_ACTIVITY_INDEX_SQL,
    )?;
    validate_schema_sql(
        connection,
        "index",
        "diff_evidence_state_updated_idx",
        EXPECTED_DIFF_STATE_INDEX_SQL,
    )?;
    validate_table_columns(
        connection,
        "diff_evidence",
        &[
            ("diff_id", "BLOB", 1, 1),
            ("changeset_id", "BLOB", 1, 0),
            ("workspace_id", "BLOB", 1, 0),
            ("activity_id", "BLOB", 1, 0),
            ("mutation_id", "BLOB", 1, 0),
            ("state", "INTEGER", 1, 0),
            ("render_kind", "INTEGER", 1, 0),
            ("pending_relative_path", "BLOB", 0, 0),
            ("artifact_relative_path", "BLOB", 0, 0),
            ("compressed_hash", "BLOB", 0, 0),
            ("uncompressed_hash", "BLOB", 0, 0),
            ("compressed_size", "INTEGER", 0, 0),
            ("uncompressed_size", "INTEGER", 0, 0),
            ("renderer_version", "INTEGER", 1, 0),
            ("redaction_policy_version", "INTEGER", 1, 0),
            ("created_at_ms", "INTEGER", 1, 0),
            ("updated_at_ms", "INTEGER", 1, 0),
            ("revision", "INTEGER", 1, 0),
        ],
    )?;
    validate_table_columns(
        connection,
        "diff_files",
        &[
            ("diff_id", "BLOB", 1, 1),
            ("ordinal", "INTEGER", 1, 0),
            ("relative_path", "BLOB", 1, 0),
            ("kind", "INTEGER", 1, 0),
            ("additions", "INTEGER", 1, 0),
            ("deletions", "INTEGER", 1, 0),
        ],
    )?;
    validate_index_columns(
        connection,
        "diff_evidence_activity_created_idx",
        &["activity_id", "created_at_ms", "diff_id"],
    )?;
    validate_index_columns(
        connection,
        "diff_evidence_state_updated_idx",
        &["state", "updated_at_ms", "diff_id"],
    )?;
    validate_foreign_keys(connection, "diff_evidence", 4)?;
    validate_foreign_keys(connection, "diff_files", 1)
}

pub(crate) fn begin(
    transaction: &Transaction<'_>,
    file_command: &BeginFileMutation,
    command: &BeginDiffEvidence,
) -> Result<RegisteredDiffEvidence, DiffStoreError> {
    validate_begin_linkage(file_command, command)?;
    if let Some(existing) = get_by_change_set(transaction, file_command.change_set_id())? {
        return if record_matches_begin(&existing, command) {
            Ok(existing)
        } else {
            Err(DiffStoreError::IdentityConflict)
        };
    }
    if get_by_id(transaction, command.attribution().id())?.is_some() {
        return Err(DiffStoreError::IdentityConflict);
    }

    let attribution = command.attribution();
    let encoded = encode_payload(command.payload())?;
    let diff_id = attribution.id().into_uuid().into_bytes();
    let change_set_id = attribution.change_set_id().into_uuid().into_bytes();
    let workspace_id = attribution.workspace_id().into_uuid().into_bytes();
    let activity_id = attribution.activity_id().into_uuid().into_bytes();
    let mutation_id = attribution.mutation_id().into_uuid().into_bytes();
    transaction.execute(
        "INSERT INTO diff_evidence (
            diff_id, changeset_id, workspace_id, activity_id, mutation_id,
            state, render_kind, pending_relative_path, artifact_relative_path,
            compressed_hash, uncompressed_hash, compressed_size, uncompressed_size,
            renderer_version, redaction_policy_version, created_at_ms, updated_at_ms, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?16, ?17)",
        params![
            diff_id.as_slice(),
            change_set_id.as_slice(),
            workspace_id.as_slice(),
            activity_id.as_slice(),
            mutation_id.as_slice(),
            encoded.state,
            encoded.render_kind,
            encoded.pending_path.as_deref(),
            encoded.artifact_path.as_deref(),
            encoded.compressed_hash.as_deref(),
            encoded.uncompressed_hash.as_deref(),
            encoded.compressed_size,
            encoded.uncompressed_size,
            i64::from(command.versions().renderer().get()),
            i64::from(command.versions().redaction_policy().get()),
            command.observed_at().get(),
            DiffRevision::INITIAL.get(),
        ],
    )?;
    transaction.execute(
        "INSERT INTO diff_files (diff_id, ordinal, relative_path, kind, additions, deletions)
         VALUES (?1, 0, ?2, ?3, ?4, ?5)",
        params![
            diff_id.as_slice(),
            command.file().path().as_path().as_os_str().as_bytes(),
            encode_change_kind(command.file().kind()),
            i64::from(command.file().additions().get()),
            i64::from(command.file().deletions().get()),
        ],
    )?;
    get_by_id(transaction, attribution.id())?.ok_or(DiffStoreError::RecordMissing)
}

pub(crate) fn complete(
    transaction: &Transaction<'_>,
    command: &CompleteDiffEvidence,
) -> Result<(), DiffStoreError> {
    let current = get_by_id(transaction, command.id())?.ok_or(DiffStoreError::RecordMissing)?;
    if current.state() != DiffEvidenceState::Intent {
        return Err(DiffStoreError::Terminal);
    }
    if current.revision() != command.expected_revision() {
        return Err(DiffStoreError::RevisionConflict);
    }
    if command.observed_at().get() < current.created_at().get() {
        return Err(DiffStoreError::TimestampOrder);
    }
    if !valid_completion(current.payload(), command.payload()) {
        return Err(DiffStoreError::InvalidTransition);
    }
    let next_revision = current
        .revision()
        .checked_next()
        .map_err(|_| DiffStoreError::RevisionOverflow)?;
    let encoded = encode_payload(command.payload())?;
    let diff_id = command.id().into_uuid().into_bytes();
    let changed = transaction.execute(
        "UPDATE diff_evidence
         SET state = ?1, render_kind = ?2, pending_relative_path = ?3,
             artifact_relative_path = ?4, compressed_hash = ?5, uncompressed_hash = ?6,
             compressed_size = ?7, uncompressed_size = ?8, updated_at_ms = ?9, revision = ?10
         WHERE diff_id = ?11 AND state = 0 AND revision = ?12",
        params![
            encoded.state,
            encoded.render_kind,
            encoded.pending_path.as_deref(),
            encoded.artifact_path.as_deref(),
            encoded.compressed_hash.as_deref(),
            encoded.uncompressed_hash.as_deref(),
            encoded.compressed_size,
            encoded.uncompressed_size,
            command.observed_at().get(),
            next_revision.get(),
            diff_id.as_slice(),
            command.expected_revision().get(),
        ],
    )?;
    if changed != 1 {
        return Err(DiffStoreError::RevisionConflict);
    }
    Ok(())
}

pub(crate) fn abandon(
    transaction: &Transaction<'_>,
    command: AbandonDiffEvidence,
) -> Result<(), DiffStoreError> {
    let current = get_by_id(transaction, command.id())?.ok_or(DiffStoreError::RecordMissing)?;
    if current.state() != DiffEvidenceState::Intent {
        return Err(DiffStoreError::Terminal);
    }
    if current.revision() != command.expected_revision() {
        return Err(DiffStoreError::RevisionConflict);
    }
    if command.observed_at().get() < current.created_at().get() {
        return Err(DiffStoreError::TimestampOrder);
    }
    let next_revision = current
        .revision()
        .checked_next()
        .map_err(|_| DiffStoreError::RevisionOverflow)?;
    let diff_id = command.id().into_uuid().into_bytes();
    let changed = transaction.execute(
        "UPDATE diff_evidence
         SET state = 3, pending_relative_path = NULL, artifact_relative_path = NULL,
             compressed_hash = NULL, uncompressed_hash = NULL,
             compressed_size = NULL, uncompressed_size = NULL,
             updated_at_ms = ?1, revision = ?2
         WHERE diff_id = ?3 AND state = 0 AND revision = ?4",
        params![
            command.observed_at().get(),
            next_revision.get(),
            diff_id.as_slice(),
            command.expected_revision().get(),
        ],
    )?;
    if changed != 1 {
        return Err(DiffStoreError::RevisionConflict);
    }
    Ok(())
}

pub(crate) fn get_by_id(
    connection: &Connection,
    id: DiffId,
) -> Result<Option<RegisteredDiffEvidence>, DiffStoreError> {
    let id = id.into_uuid().into_bytes();
    query_one(connection, "WHERE e.diff_id = ?1", id.as_slice())
}

pub(crate) fn get_by_change_set(
    connection: &Connection,
    id: ChangeSetId,
) -> Result<Option<RegisteredDiffEvidence>, DiffStoreError> {
    let id = id.into_uuid().into_bytes();
    query_one(connection, "WHERE e.changeset_id = ?1", id.as_slice())
}

pub(crate) fn list_by_activity(
    connection: &Connection,
    activity_id: ActivityId,
    limit: DiffListLimit,
) -> Result<Vec<RegisteredDiffEvidence>, DiffStoreError> {
    let query = format!(
        "{RECORD_QUERY} WHERE e.activity_id = ?1
         ORDER BY e.created_at_ms DESC, e.diff_id DESC LIMIT ?2"
    );
    let activity_id = activity_id.into_uuid().into_bytes();
    let mut statement = connection.prepare(&query)?;
    let mut rows = statement.query(params![activity_id.as_slice(), i64::from(limit.get())])?;
    let mut records = Vec::new();
    while let Some(row) = rows.next()? {
        records.push(decode_record(row)?);
    }
    Ok(records)
}

/// Read a bounded, metadata-only inventory of current Diff expectations.
///
/// The current Diff query and the migrated legacy-without-Diff query are fixed
/// bounded scans. They are intentionally separate from the Activity list
/// query because a legacy `ChangeSet` has no `diff_evidence` row to decode. The
/// two result sets are merged and sorted by the stable Diff identity, then
/// capped at 256 rows. No artifact body or per-row follow-up query is issued.
pub(crate) fn doctor_references(
    connection: &Connection,
) -> Result<DiffDoctorReport, DiffStoreError> {
    validate_doctor_relationships(connection)?;
    let mut references = Vec::with_capacity(DIFF_DOCTOR_PROBE_REFERENCES.saturating_mul(2));

    let current_query =
        format!("{RECORD_QUERY}\nORDER BY e.diff_id ASC\nLIMIT {DIFF_DOCTOR_PROBE_REFERENCES}");
    let mut current_statement = connection.prepare(&current_query)?;
    let mut current_rows = current_statement.query([])?;
    while let Some(row) = current_rows.next()? {
        let evidence = decode_record_inner(row)?;
        references.push(doctor_reference_from_evidence(&evidence)?);
    }

    let mut legacy_statement = connection.prepare(LEGACY_DOCTOR_QUERY)?;
    let mut legacy_rows = legacy_statement.query([])?;
    while let Some(row) = legacy_rows.next()? {
        references.push(decode_legacy_doctor_reference(row)?);
    }

    references.sort_by_key(DiffDoctorReference::diff_id);
    let truncated = references.len() > DIFF_DOCTOR_MAX_REFERENCES;
    references.truncate(DIFF_DOCTOR_MAX_REFERENCES);
    Ok(DiffDoctorReport::new(references, truncated))
}

/// Ensure a malformed relationship cannot disappear from the inner-join
/// projection and be mistaken for an empty/healthy inventory.
fn validate_doctor_relationships(connection: &Connection) -> Result<(), DiffStoreError> {
    let malformed_current: i64 = connection.query_row(
        "SELECT EXISTS(
            SELECT 1
            FROM diff_evidence AS e
            LEFT JOIN diff_files AS f ON f.diff_id = e.diff_id
            LEFT JOIN change_sets AS c ON c.changeset_id = e.changeset_id
            LEFT JOIN file_mutations AS m ON m.mutation_id = e.mutation_id
            WHERE f.diff_id IS NULL
               OR c.changeset_id IS NULL
               OR m.mutation_id IS NULL
               OR e.workspace_id != c.workspace_id
               OR e.activity_id != c.activity_id
               OR e.changeset_id != m.changeset_id
        )",
        [],
        |row| row.get(0),
    )?;
    if malformed_current != 0 {
        return Err(DiffStoreError::CorruptRecord("diff.relationship"));
    }

    let orphaned_diff_files: i64 = connection.query_row(
        "SELECT EXISTS(
            SELECT 1
            FROM diff_files AS f
            LEFT JOIN diff_evidence AS e ON e.diff_id = f.diff_id
            WHERE e.diff_id IS NULL
        )",
        [],
        |row| row.get(0),
    )?;
    if orphaned_diff_files != 0 {
        return Err(DiffStoreError::CorruptRecord("diff.relationship"));
    }

    let malformed_legacy: i64 = connection.query_row(
        "SELECT EXISTS(
            SELECT 1
            FROM change_sets AS c
            LEFT JOIN diff_evidence AS e ON e.changeset_id = c.changeset_id
            LEFT JOIN file_mutations AS f ON f.changeset_id = c.changeset_id
            WHERE e.diff_id IS NULL AND f.mutation_id IS NULL
        )",
        [],
        |row| row.get(0),
    )?;
    if malformed_legacy != 0 {
        return Err(DiffStoreError::CorruptRecord("legacy.relationship"));
    }
    Ok(())
}

fn doctor_reference_from_evidence(
    evidence: &RegisteredDiffEvidence,
) -> Result<DiffDoctorReference, DiffStoreError> {
    let diff_id = evidence.id();
    let lifecycle = DiffDoctorLifecycle::Evidence {
        state: evidence.state(),
        render_kind: evidence.payload().render_kind(),
    };
    let (pending_artifact, final_artifact) = match evidence.payload() {
        DiffPayloadProjection::IntentText {
            pending_relative_path,
            final_relative_path,
            compressed_hash,
            uncompressed_hash,
            compressed_size,
            uncompressed_size,
        } => (
            Some(doctor_artifact_reference(
                diff_id,
                pending_relative_path,
                true,
                *compressed_hash,
                *compressed_size,
                *uncompressed_hash,
                *uncompressed_size,
            )?),
            Some(doctor_artifact_reference(
                diff_id,
                final_relative_path,
                false,
                *compressed_hash,
                *compressed_size,
                *uncompressed_hash,
                *uncompressed_size,
            )?),
        ),
        DiffPayloadProjection::Ready {
            relative_path,
            compressed_hash,
            uncompressed_hash,
            compressed_size,
            uncompressed_size,
        }
        | DiffPayloadProjection::PurgePending {
            relative_path,
            compressed_hash,
            uncompressed_hash,
            compressed_size,
            uncompressed_size,
        } => (
            None,
            Some(doctor_artifact_reference(
                diff_id,
                relative_path,
                false,
                *compressed_hash,
                *compressed_size,
                *uncompressed_hash,
                *uncompressed_size,
            )?),
        ),
        DiffPayloadProjection::IntentSummary { .. }
        | DiffPayloadProjection::SummaryOnly { .. }
        | DiffPayloadProjection::Abandoned { .. }
        | DiffPayloadProjection::Tombstoned { .. } => (None, None),
    };
    Ok(DiffDoctorReference {
        diff_id,
        lifecycle,
        pending_artifact,
        final_artifact,
    })
}

fn doctor_artifact_reference(
    diff_id: DiffId,
    path: &DiffArtifactRelativePath,
    pending: bool,
    compressed_hash: DiffPayloadHash,
    compressed_size: DiffByteCount,
    uncompressed_hash: DiffPayloadHash,
    uncompressed_size: DiffByteCount,
) -> Result<DiffDoctorArtifactReference, DiffStoreError> {
    let expected_name = if pending {
        format!(".diff-{diff_id}.pending")
    } else {
        format!("diff_{diff_id}.diff.zst")
    };
    let Some(parent) = path.as_path().parent() else {
        return Err(DiffStoreError::CorruptRecord("diff.artifact_relative_path"));
    };
    let Some(name) = path.as_path().file_name() else {
        return Err(DiffStoreError::CorruptRecord("diff.artifact_relative_path"));
    };
    if parent != Path::new("diffs") || name.as_bytes() != expected_name.as_bytes() {
        return Err(DiffStoreError::CorruptRecord("diff.artifact_relative_path"));
    }
    let name = DiffArtifactInventoryName::new(name.as_bytes().to_vec())
        .map_err(|_| DiffStoreError::CorruptRecord("diff.artifact_relative_path"))?;
    Ok(DiffDoctorArtifactReference {
        name,
        compressed_hash,
        compressed_size,
        uncompressed_hash,
        uncompressed_size,
    })
}

fn decode_legacy_doctor_reference(row: &Row<'_>) -> Result<DiffDoctorReference, DiffStoreError> {
    validate_exact_length("legacy.change_set.id", row.get(0)?, 16)?;
    validate_exact_length("legacy.workspace_id", row.get(1)?, 16)?;
    validate_exact_length("legacy.activity_id", row.get(2)?, 16)?;
    let mutation_length = row
        .get::<_, Option<i64>>(3)?
        .ok_or(DiffStoreError::CorruptRecord("legacy.file_mutation"))?;
    validate_exact_length("legacy.file_mutation.id", mutation_length, 16)?;
    let path_length = row
        .get::<_, Option<i64>>(4)?
        .ok_or(DiffStoreError::CorruptRecord("legacy.file_mutation.path"))?;
    validate_bounded_length("legacy.file_mutation.path", path_length, MAX_PATH_BYTES)?;

    let change_set_id = decode_uuid("legacy.change_set.id", &row.get::<_, Vec<u8>>(5)?)
        .map(ChangeSetId::from_uuid)?;
    // Validate the other durable identity columns even though they are not
    // retained in the metadata-only legacy projection.
    decode_uuid("legacy.workspace_id", &row.get::<_, Vec<u8>>(6)?)?;
    decode_uuid("legacy.activity_id", &row.get::<_, Vec<u8>>(7)?)?;
    let change_set_state = decode_legacy_change_set_state(row.get(8)?)?;
    let created_at = TimestampMillis::new(row.get(9)?)
        .map_err(|_| DiffStoreError::CorruptRecord("legacy.created_at_ms"))?;
    let updated_at = TimestampMillis::new(row.get(10)?)
        .map_err(|_| DiffStoreError::CorruptRecord("legacy.updated_at_ms"))?;
    if updated_at.get() < created_at.get() {
        return Err(DiffStoreError::CorruptRecord("legacy.updated_at_ms"));
    }
    if row.get::<_, i64>(11)? < 1 {
        return Err(DiffStoreError::CorruptRecord("legacy.revision"));
    }
    decode_uuid("legacy.file_mutation.id", &row.get::<_, Vec<u8>>(12)?)?;
    let path = row.get::<_, Vec<u8>>(13)?;
    WorkspaceRelativePath::new(PathBuf::from(OsString::from_vec(path)))
        .map_err(|_| DiffStoreError::CorruptRecord("legacy.file_mutation.path"))?;

    Ok(DiffDoctorReference {
        diff_id: DiffId::for_change_set(change_set_id),
        lifecycle: DiffDoctorLifecycle::Legacy { change_set_state },
        pending_artifact: None,
        final_artifact: None,
    })
}

const fn decode_legacy_change_set_state(value: i64) -> Result<ChangeSetState, DiffStoreError> {
    match value {
        0 => Ok(ChangeSetState::Starting),
        1 => Ok(ChangeSetState::Applied),
        2 => Ok(ChangeSetState::Failed),
        _ => Err(DiffStoreError::CorruptRecord("legacy.change_set.state")),
    }
}

pub(crate) fn list_retention_candidates(
    connection: &Connection,
    keep_recent: DiffRetentionKeepCount,
    limit: DiffRetentionPlanLimit,
) -> Result<Vec<RegisteredDiffEvidence>, DiffStoreError> {
    let query = format!(
        "{RECORD_QUERY} WHERE e.state = 1 AND e.render_kind = 0
         AND NOT EXISTS (
             SELECT 1 FROM goal_evidence_refs AS g
             WHERE g.evidence_kind = 0 AND g.evidence_id = e.changeset_id
         )
         ORDER BY e.created_at_ms DESC, e.diff_id DESC LIMIT ?1 OFFSET ?2"
    );
    let mut statement = connection.prepare(&query)?;
    let mut rows = statement.query(params![
        i64::from(limit.get()),
        i64::from(keep_recent.get())
    ])?;
    let mut records = Vec::new();
    while let Some(row) = rows.next()? {
        records.push(decode_record(row)?);
    }
    Ok(records)
}

pub(crate) fn begin_purge(
    transaction: &Transaction<'_>,
    command: BeginDiffPurge,
) -> Result<DiffPurgeRecord, DiffStoreError> {
    let current = get_by_id(transaction, command.id())?.ok_or(DiffStoreError::RecordMissing)?;
    ensure_not_goal_linked(transaction, current.change_set_id())?;
    if command.observed_at().get() < current.created_at().get() {
        return Err(DiffStoreError::TimestampOrder);
    }
    match current.state() {
        DiffEvidenceState::Ready => mark_purge_pending(transaction, &current, command),
        DiffEvidenceState::PurgePending
            if revision_matches_retry(current.revision(), command.expected_revision(), 1) =>
        {
            Ok(DiffPurgeRecord::new(
                current,
                DiffPurgeStatus::AlreadyPending,
            ))
        }
        DiffEvidenceState::Tombstoned
            if revision_matches_retry(current.revision(), command.expected_revision(), 2) =>
        {
            Ok(DiffPurgeRecord::new(
                current,
                DiffPurgeStatus::AlreadyTombstoned,
            ))
        }
        DiffEvidenceState::Intent
        | DiffEvidenceState::SummaryOnly
        | DiffEvidenceState::Abandoned
        | DiffEvidenceState::PurgePending
        | DiffEvidenceState::Tombstoned => Err(DiffStoreError::InvalidTransition),
    }
}

fn mark_purge_pending(
    transaction: &Transaction<'_>,
    current: &RegisteredDiffEvidence,
    command: BeginDiffPurge,
) -> Result<DiffPurgeRecord, DiffStoreError> {
    if current.revision() != command.expected_revision() {
        return Err(DiffStoreError::RevisionConflict);
    }
    let DiffPayloadProjection::Ready {
        relative_path,
        compressed_hash,
        uncompressed_hash,
        compressed_size,
        uncompressed_size,
    } = current.payload()
    else {
        return Err(DiffStoreError::InvalidTransition);
    };
    let next_revision = current
        .revision()
        .checked_next()
        .map_err(|_| DiffStoreError::RevisionOverflow)?;
    let diff_id = command.id().into_uuid().into_bytes();
    let changed = transaction.execute(
        "UPDATE diff_evidence SET state = 4, updated_at_ms = ?1, revision = ?2
         WHERE diff_id = ?3 AND state = 1 AND revision = ?4",
        params![
            command.observed_at().get(),
            next_revision.get(),
            diff_id.as_slice(),
            command.expected_revision().get(),
        ],
    )?;
    if changed != 1 {
        return Err(DiffStoreError::RevisionConflict);
    }
    let updated = get_by_id(transaction, command.id())?.ok_or(DiffStoreError::RecordMissing)?;
    if !matches!(
        updated.payload(),
        DiffPayloadProjection::PurgePending {
            relative_path: updated_path,
            compressed_hash: updated_compressed_hash,
            uncompressed_hash: updated_uncompressed_hash,
            compressed_size: updated_compressed_size,
            uncompressed_size: updated_uncompressed_size,
        } if updated_path == relative_path
            && updated_compressed_hash == compressed_hash
            && updated_uncompressed_hash == uncompressed_hash
            && updated_compressed_size == compressed_size
            && updated_uncompressed_size == uncompressed_size
    ) {
        return Err(DiffStoreError::CorruptRecord("diff.purge_payload"));
    }
    Ok(DiffPurgeRecord::new(
        updated,
        DiffPurgeStatus::MarkedPending,
    ))
}

pub(crate) fn complete_purge(
    transaction: &Transaction<'_>,
    command: CompleteDiffPurge,
) -> Result<DiffPurgeRecord, DiffStoreError> {
    let current = get_by_id(transaction, command.id())?.ok_or(DiffStoreError::RecordMissing)?;
    ensure_not_goal_linked(transaction, current.change_set_id())?;
    if command.observed_at().get() < current.created_at().get() {
        return Err(DiffStoreError::TimestampOrder);
    }
    match current.state() {
        DiffEvidenceState::PurgePending => {
            if current.revision() != command.expected_revision() {
                return Err(DiffStoreError::RevisionConflict);
            }
            let next_revision = current
                .revision()
                .checked_next()
                .map_err(|_| DiffStoreError::RevisionOverflow)?;
            let diff_id = command.id().into_uuid().into_bytes();
            let changed = transaction.execute(
                "UPDATE diff_evidence
                 SET state = 5, pending_relative_path = NULL, artifact_relative_path = NULL,
                     compressed_hash = NULL, uncompressed_hash = NULL,
                     compressed_size = NULL, uncompressed_size = NULL,
                     updated_at_ms = ?1, revision = ?2
                 WHERE diff_id = ?3 AND state = 4 AND revision = ?4",
                params![
                    command.observed_at().get(),
                    next_revision.get(),
                    diff_id.as_slice(),
                    command.expected_revision().get(),
                ],
            )?;
            if changed != 1 {
                return Err(DiffStoreError::RevisionConflict);
            }
            let updated =
                get_by_id(transaction, command.id())?.ok_or(DiffStoreError::RecordMissing)?;
            Ok(DiffPurgeRecord::new(updated, DiffPurgeStatus::Tombstoned))
        }
        DiffEvidenceState::Tombstoned
            if revision_matches_retry(current.revision(), command.expected_revision(), 1) =>
        {
            Ok(DiffPurgeRecord::new(
                current,
                DiffPurgeStatus::AlreadyTombstoned,
            ))
        }
        DiffEvidenceState::Intent
        | DiffEvidenceState::Ready
        | DiffEvidenceState::SummaryOnly
        | DiffEvidenceState::Abandoned
        | DiffEvidenceState::Tombstoned => Err(DiffStoreError::InvalidTransition),
    }
}

fn ensure_not_goal_linked(
    connection: &Connection,
    change_set_id: ChangeSetId,
) -> Result<(), DiffStoreError> {
    let goal_linked: bool = connection.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM goal_evidence_refs
            WHERE evidence_kind = 0 AND evidence_id = ?1
         )",
        params![change_set_id.into_uuid().as_bytes()],
        |row| row.get(0),
    )?;
    if goal_linked {
        Err(DiffStoreError::RetentionProtected)
    } else {
        Ok(())
    }
}

fn revision_matches_retry(current: DiffRevision, expected: DiffRevision, advances: u8) -> bool {
    let mut candidate = expected;
    for _ in 0..=advances {
        if current == candidate {
            return true;
        }
        let Ok(next) = candidate.checked_next() else {
            return false;
        };
        candidate = next;
    }
    false
}

fn query_one(
    connection: &Connection,
    clause: &str,
    id: &[u8],
) -> Result<Option<RegisteredDiffEvidence>, DiffStoreError> {
    let query = format!("{RECORD_QUERY} {clause}");
    connection
        .query_row(&query, params![id], decode_record)
        .optional()
        .map_err(DiffStoreError::from)
}

fn validate_begin_linkage(
    file_command: &BeginFileMutation,
    command: &BeginDiffEvidence,
) -> Result<(), DiffStoreError> {
    let attribution = command.attribution();
    let expected_kind = match file_command.kind() {
        forge_domain::FileMutationKind::Create => DiffChangeKind::Created,
        forge_domain::FileMutationKind::Replace => DiffChangeKind::Modified,
        forge_domain::FileMutationKind::Delete => DiffChangeKind::Deleted,
    };
    if attribution.id() != DiffId::for_change_set(file_command.change_set_id())
        || attribution.change_set_id() != file_command.change_set_id()
        || attribution.mutation_id() != file_command.mutation_id()
        || attribution.workspace_id() != file_command.workspace_id()
        || attribution.activity_id() != file_command.activity_id()
        || command.file().path() != file_command.path()
        || command.file().kind() != expected_kind
        || command.observed_at() != file_command.observed_at()
    {
        return Err(DiffStoreError::AttributionMismatch);
    }
    Ok(())
}

fn record_matches_begin(record: &RegisteredDiffEvidence, command: &BeginDiffEvidence) -> bool {
    record.id() == command.attribution().id()
        && record.workspace_id() == command.attribution().workspace_id()
        && record.activity_id() == command.attribution().activity_id()
        && record.change_set_id() == command.attribution().change_set_id()
        && record.mutation_id() == command.attribution().mutation_id()
        && record.file() == command.file()
        && record.created_at() == command.observed_at()
        && record.renderer_version() == command.versions().renderer()
        && record.redaction_policy_version() == command.versions().redaction_policy()
        && payload_matches_begin(record.payload(), command.payload())
}

fn payload_matches_begin(current: &DiffPayloadProjection, intent: &DiffPayloadProjection) -> bool {
    if current == intent {
        return true;
    }
    match (current, intent) {
        (
            DiffPayloadProjection::Ready {
                relative_path,
                compressed_hash,
                uncompressed_hash,
                compressed_size,
                uncompressed_size,
            }
            | DiffPayloadProjection::PurgePending {
                relative_path,
                compressed_hash,
                uncompressed_hash,
                compressed_size,
                uncompressed_size,
            },
            DiffPayloadProjection::IntentText {
                final_relative_path,
                compressed_hash: intended_compressed_hash,
                uncompressed_hash: intended_uncompressed_hash,
                compressed_size: intended_compressed_size,
                uncompressed_size: intended_uncompressed_size,
                ..
            },
        ) => {
            relative_path == final_relative_path
                && compressed_hash == intended_compressed_hash
                && uncompressed_hash == intended_uncompressed_hash
                && compressed_size == intended_compressed_size
                && uncompressed_size == intended_uncompressed_size
        }
        (
            DiffPayloadProjection::SummaryOnly { render_kind }
            | DiffPayloadProjection::Abandoned { render_kind }
            | DiffPayloadProjection::Tombstoned { render_kind },
            DiffPayloadProjection::IntentSummary {
                render_kind: intended,
            },
        ) => render_kind == intended,
        (
            DiffPayloadProjection::Abandoned { render_kind },
            DiffPayloadProjection::IntentText { .. },
        )
        | (
            DiffPayloadProjection::Tombstoned { render_kind },
            DiffPayloadProjection::IntentText { .. },
        ) => *render_kind == DiffRenderKind::Text,
        _ => false,
    }
}

fn valid_completion(intent: &DiffPayloadProjection, terminal: &DiffPayloadProjection) -> bool {
    match (intent, terminal) {
        (
            DiffPayloadProjection::IntentText {
                final_relative_path,
                compressed_hash,
                uncompressed_hash,
                compressed_size,
                uncompressed_size,
                ..
            },
            DiffPayloadProjection::Ready {
                relative_path,
                compressed_hash: terminal_compressed_hash,
                uncompressed_hash: terminal_uncompressed_hash,
                compressed_size: terminal_compressed_size,
                uncompressed_size: terminal_uncompressed_size,
            },
        ) => {
            final_relative_path == relative_path
                && compressed_hash == terminal_compressed_hash
                && uncompressed_hash == terminal_uncompressed_hash
                && compressed_size == terminal_compressed_size
                && uncompressed_size == terminal_uncompressed_size
        }
        (
            DiffPayloadProjection::IntentSummary { render_kind },
            DiffPayloadProjection::SummaryOnly {
                render_kind: terminal,
            },
        ) => render_kind == terminal,
        _ => false,
    }
}

#[derive(Debug)]
struct EncodedPayload {
    state: i64,
    render_kind: i64,
    pending_path: Option<Vec<u8>>,
    artifact_path: Option<Vec<u8>>,
    compressed_hash: Option<Vec<u8>>,
    uncompressed_hash: Option<Vec<u8>>,
    compressed_size: Option<i64>,
    uncompressed_size: Option<i64>,
}

fn encode_payload(value: &DiffPayloadProjection) -> Result<EncodedPayload, DiffStoreError> {
    let empty = || EncodedPayload {
        state: encode_state(value.state()),
        render_kind: encode_render_kind(value.render_kind()),
        pending_path: None,
        artifact_path: None,
        compressed_hash: None,
        uncompressed_hash: None,
        compressed_size: None,
        uncompressed_size: None,
    };
    match value {
        DiffPayloadProjection::IntentText {
            pending_relative_path,
            final_relative_path,
            compressed_hash,
            uncompressed_hash,
            compressed_size,
            uncompressed_size,
        } => Ok(EncodedPayload {
            state: encode_state(value.state()),
            render_kind: encode_render_kind(DiffRenderKind::Text),
            pending_path: Some(path_bytes(pending_relative_path)),
            artifact_path: Some(path_bytes(final_relative_path)),
            compressed_hash: Some(compressed_hash.as_bytes().to_vec()),
            uncompressed_hash: Some(uncompressed_hash.as_bytes().to_vec()),
            compressed_size: Some(size_to_i64(*compressed_size)?),
            uncompressed_size: Some(size_to_i64(*uncompressed_size)?),
        }),
        DiffPayloadProjection::Ready {
            relative_path,
            compressed_hash,
            uncompressed_hash,
            compressed_size,
            uncompressed_size,
        }
        | DiffPayloadProjection::PurgePending {
            relative_path,
            compressed_hash,
            uncompressed_hash,
            compressed_size,
            uncompressed_size,
        } => Ok(EncodedPayload {
            state: encode_state(value.state()),
            render_kind: encode_render_kind(DiffRenderKind::Text),
            pending_path: None,
            artifact_path: Some(path_bytes(relative_path)),
            compressed_hash: Some(compressed_hash.as_bytes().to_vec()),
            uncompressed_hash: Some(uncompressed_hash.as_bytes().to_vec()),
            compressed_size: Some(size_to_i64(*compressed_size)?),
            uncompressed_size: Some(size_to_i64(*uncompressed_size)?),
        }),
        DiffPayloadProjection::IntentSummary { .. }
        | DiffPayloadProjection::SummaryOnly { .. }
        | DiffPayloadProjection::Abandoned { .. }
        | DiffPayloadProjection::Tombstoned { .. } => Ok(empty()),
    }
}

fn path_bytes(path: &DiffArtifactRelativePath) -> Vec<u8> {
    path.as_path().as_os_str().as_bytes().to_vec()
}

fn size_to_i64(value: DiffByteCount) -> Result<i64, DiffStoreError> {
    i64::try_from(value.get()).map_err(|_| DiffStoreError::SizeOverflow)
}

fn decode_record(row: &Row<'_>) -> rusqlite::Result<RegisteredDiffEvidence> {
    decode_record_inner(row).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(10, rusqlite::types::Type::Blob, Box::new(error))
    })
}

fn decode_record_inner(row: &Row<'_>) -> Result<RegisteredDiffEvidence, DiffStoreError> {
    for (field, index) in [
        ("diff.id", 0),
        ("diff.workspace_id", 1),
        ("diff.activity_id", 2),
        ("diff.changeset_id", 3),
        ("diff.mutation_id", 4),
    ] {
        validate_exact_length(field, row.get(index)?, 16)?;
    }
    validate_bounded_length("diff.file.relative_path", row.get(5)?, MAX_PATH_BYTES)?;
    validate_optional_bounded_length("diff.pending_relative_path", row.get(6)?, MAX_PATH_BYTES)?;
    validate_optional_bounded_length("diff.artifact_relative_path", row.get(7)?, MAX_PATH_BYTES)?;
    validate_optional_exact_length("diff.compressed_hash", row.get(8)?, HASH_BYTES)?;
    validate_optional_exact_length("diff.uncompressed_hash", row.get(9)?, HASH_BYTES)?;

    let id = decode_uuid("diff.id", &row.get::<_, Vec<u8>>(10)?).map(DiffId::from_uuid)?;
    let workspace_id = decode_uuid("diff.workspace_id", &row.get::<_, Vec<u8>>(11)?)
        .map(WorkspaceId::from_uuid)?;
    let activity_id =
        decode_uuid("diff.activity_id", &row.get::<_, Vec<u8>>(12)?).map(ActivityId::from_uuid)?;
    let change_set_id = decode_uuid("diff.changeset_id", &row.get::<_, Vec<u8>>(13)?)
        .map(ChangeSetId::from_uuid)?;
    let mutation_id = decode_uuid("diff.mutation_id", &row.get::<_, Vec<u8>>(14)?)
        .map(FileMutationId::from_uuid)?;
    if id != DiffId::for_change_set(change_set_id)
        || row.get::<_, i64>(32)? != 1
        || row.get::<_, i64>(33)? != 1
        || row.get::<_, i64>(34)? != 1
    {
        return Err(DiffStoreError::CorruptRecord("diff.attribution"));
    }

    let state = decode_state(row.get(15)?)?;
    let render_kind = decode_render_kind(row.get(16)?)?;
    let payload = decode_payload(
        state,
        render_kind,
        RawPayloadFields {
            pending_path: row.get(17)?,
            artifact_path: row.get(18)?,
            compressed_hash: row.get(19)?,
            uncompressed_hash: row.get(20)?,
            compressed_size: row.get(21)?,
            uncompressed_size: row.get(22)?,
        },
    )?;
    validate_change_set_state(state, row.get(35)?)?;

    let renderer_version = decode_u32("diff.renderer_version", row.get(23)?).and_then(|value| {
        DiffRendererVersion::new(value)
            .map_err(|_| DiffStoreError::CorruptRecord("diff.renderer_version"))
    })?;
    let redaction_policy_version = decode_u32("diff.redaction_policy_version", row.get(24)?)
        .and_then(|value| {
            DiffRedactionPolicyVersion::new(value)
                .map_err(|_| DiffStoreError::CorruptRecord("diff.redaction_policy_version"))
        })?;
    let created_at = TimestampMillis::new(row.get(25)?)
        .map_err(|_| DiffStoreError::CorruptRecord("diff.created_at_ms"))?;
    let updated_at = TimestampMillis::new(row.get(26)?)
        .map_err(|_| DiffStoreError::CorruptRecord("diff.updated_at_ms"))?;
    if updated_at.get() < created_at.get() {
        return Err(DiffStoreError::CorruptRecord("diff.updated_at_ms"));
    }
    let revision = DiffRevision::new(row.get(27)?)
        .map_err(|_| DiffStoreError::CorruptRecord("diff.revision"))?;
    let path = WorkspaceRelativePath::new(PathBuf::from(OsString::from_vec(row.get(28)?)))
        .map_err(|_| DiffStoreError::CorruptRecord("diff.file.relative_path"))?;
    let kind = decode_change_kind(row.get(29)?)?;
    let additions = DiffLineCount::new(decode_u32("diff.file.additions", row.get(30)?)?);
    let deletions = DiffLineCount::new(decode_u32("diff.file.deletions", row.get(31)?)?);

    Ok(RegisteredDiffEvidence::from_parts(
        DiffAttribution::new(id, workspace_id, activity_id, change_set_id, mutation_id),
        DiffFileSummary::new(path, kind, additions, deletions),
        payload,
        DiffEvidenceTimestamps::new(created_at, updated_at),
        DiffContractVersions::new(renderer_version, redaction_policy_version),
        revision,
    ))
}

#[derive(Debug)]
struct RawPayloadFields {
    pending_path: Option<Vec<u8>>,
    artifact_path: Option<Vec<u8>>,
    compressed_hash: Option<Vec<u8>>,
    uncompressed_hash: Option<Vec<u8>>,
    compressed_size: Option<i64>,
    uncompressed_size: Option<i64>,
}

#[derive(Debug)]
struct DecodedPayloadFields {
    pending: Option<DiffArtifactRelativePath>,
    artifact: Option<DiffArtifactRelativePath>,
    compressed_hash: Option<DiffPayloadHash>,
    uncompressed_hash: Option<DiffPayloadHash>,
    compressed_size: Option<DiffByteCount>,
    uncompressed_size: Option<DiffByteCount>,
}

impl DecodedPayloadFields {
    fn decode(raw: RawPayloadFields) -> Result<Self, DiffStoreError> {
        Ok(Self {
            pending: raw.pending_path.map(decode_artifact_path).transpose()?,
            artifact: raw.artifact_path.map(decode_artifact_path).transpose()?,
            compressed_hash: raw
                .compressed_hash
                .map(|value| decode_payload_hash("diff.compressed_hash", &value))
                .transpose()?,
            uncompressed_hash: raw
                .uncompressed_hash
                .map(|value| decode_payload_hash("diff.uncompressed_hash", &value))
                .transpose()?,
            compressed_size: raw
                .compressed_size
                .map(|value| decode_size("diff.compressed_size", value))
                .transpose()?,
            uncompressed_size: raw
                .uncompressed_size
                .map(|value| decode_size("diff.uncompressed_size", value))
                .transpose()?,
        })
    }

    fn require_empty(&self) -> Result<(), DiffStoreError> {
        if self.pending.is_none()
            && self.artifact.is_none()
            && self.compressed_hash.is_none()
            && self.uncompressed_hash.is_none()
            && self.compressed_size.is_none()
            && self.uncompressed_size.is_none()
        {
            Ok(())
        } else {
            Err(DiffStoreError::CorruptRecord("diff.artifact_payload"))
        }
    }

    fn require_artifact(self) -> Result<ArtifactPayloadFields, DiffStoreError> {
        match (
            self.artifact,
            self.compressed_hash,
            self.uncompressed_hash,
            self.compressed_size,
            self.uncompressed_size,
        ) {
            (
                Some(path),
                Some(compressed_hash),
                Some(uncompressed_hash),
                Some(compressed_size),
                Some(uncompressed_size),
            ) => Ok(ArtifactPayloadFields {
                path,
                compressed_hash,
                uncompressed_hash,
                compressed_size,
                uncompressed_size,
            }),
            _ => Err(DiffStoreError::CorruptRecord("diff.artifact_payload")),
        }
    }
}

#[derive(Debug)]
struct ArtifactPayloadFields {
    path: DiffArtifactRelativePath,
    compressed_hash: DiffPayloadHash,
    uncompressed_hash: DiffPayloadHash,
    compressed_size: DiffByteCount,
    uncompressed_size: DiffByteCount,
}

fn decode_payload(
    state: DiffEvidenceState,
    render_kind: DiffRenderKind,
    raw: RawPayloadFields,
) -> Result<DiffPayloadProjection, DiffStoreError> {
    let fields = DecodedPayloadFields::decode(raw)?;
    match (state, render_kind) {
        (DiffEvidenceState::Intent, DiffRenderKind::Text) => decode_intent_text(fields),
        (DiffEvidenceState::Intent, DiffRenderKind::Binary | DiffRenderKind::Oversized) => {
            fields.require_empty()?;
            Ok(DiffPayloadProjection::IntentSummary { render_kind })
        }
        (DiffEvidenceState::Ready, DiffRenderKind::Text) => decode_ready(fields),
        (DiffEvidenceState::SummaryOnly, DiffRenderKind::Binary | DiffRenderKind::Oversized) => {
            fields.require_empty()?;
            Ok(DiffPayloadProjection::SummaryOnly { render_kind })
        }
        (DiffEvidenceState::Abandoned, _) => {
            fields.require_empty()?;
            Ok(DiffPayloadProjection::Abandoned { render_kind })
        }
        (DiffEvidenceState::PurgePending, DiffRenderKind::Text) => decode_purge_pending(fields),
        (DiffEvidenceState::Tombstoned, _) => {
            fields.require_empty()?;
            Ok(DiffPayloadProjection::Tombstoned { render_kind })
        }
        _ => Err(DiffStoreError::CorruptRecord("diff.state")),
    }
}

fn decode_intent_text(
    mut fields: DecodedPayloadFields,
) -> Result<DiffPayloadProjection, DiffStoreError> {
    let pending_relative_path = fields
        .pending
        .take()
        .ok_or(DiffStoreError::CorruptRecord("diff.pending_relative_path"))?;
    let artifact = fields.require_artifact()?;
    Ok(DiffPayloadProjection::IntentText {
        pending_relative_path,
        final_relative_path: artifact.path,
        compressed_hash: artifact.compressed_hash,
        uncompressed_hash: artifact.uncompressed_hash,
        compressed_size: artifact.compressed_size,
        uncompressed_size: artifact.uncompressed_size,
    })
}

fn decode_ready(fields: DecodedPayloadFields) -> Result<DiffPayloadProjection, DiffStoreError> {
    if fields.pending.is_some() {
        return Err(DiffStoreError::CorruptRecord("diff.pending_relative_path"));
    }
    let artifact = fields.require_artifact()?;
    Ok(DiffPayloadProjection::Ready {
        relative_path: artifact.path,
        compressed_hash: artifact.compressed_hash,
        uncompressed_hash: artifact.uncompressed_hash,
        compressed_size: artifact.compressed_size,
        uncompressed_size: artifact.uncompressed_size,
    })
}

fn decode_purge_pending(
    fields: DecodedPayloadFields,
) -> Result<DiffPayloadProjection, DiffStoreError> {
    if fields.pending.is_some() {
        return Err(DiffStoreError::CorruptRecord("diff.pending_relative_path"));
    }
    let artifact = fields.require_artifact()?;
    Ok(DiffPayloadProjection::PurgePending {
        relative_path: artifact.path,
        compressed_hash: artifact.compressed_hash,
        uncompressed_hash: artifact.uncompressed_hash,
        compressed_size: artifact.compressed_size,
        uncompressed_size: artifact.uncompressed_size,
    })
}

fn decode_artifact_path(value: Vec<u8>) -> Result<DiffArtifactRelativePath, DiffStoreError> {
    DiffArtifactRelativePath::new(PathBuf::from(OsString::from_vec(value)))
        .map_err(|_| DiffStoreError::CorruptRecord("diff.artifact_relative_path"))
}

fn decode_payload_hash(
    field: &'static str,
    value: &[u8],
) -> Result<DiffPayloadHash, DiffStoreError> {
    let bytes =
        <[u8; HASH_BYTES]>::try_from(value).map_err(|_| DiffStoreError::CorruptRecord(field))?;
    Ok(DiffPayloadHash::from_bytes(bytes))
}

fn decode_size(field: &'static str, value: i64) -> Result<DiffByteCount, DiffStoreError> {
    u64::try_from(value)
        .map(DiffByteCount::new)
        .map_err(|_| DiffStoreError::CorruptRecord(field))
}

fn decode_uuid(field: &'static str, value: &[u8]) -> Result<Uuid, DiffStoreError> {
    Uuid::from_slice(value).map_err(|_| DiffStoreError::CorruptRecord(field))
}

fn decode_u32(field: &'static str, value: i64) -> Result<u32, DiffStoreError> {
    u32::try_from(value).map_err(|_| DiffStoreError::CorruptRecord(field))
}

fn validate_exact_length(
    field: &'static str,
    length: i64,
    expected: usize,
) -> Result<(), DiffStoreError> {
    if usize::try_from(length).ok() == Some(expected) {
        Ok(())
    } else {
        Err(DiffStoreError::CorruptRecord(field))
    }
}

fn validate_bounded_length(
    field: &'static str,
    length: i64,
    maximum: usize,
) -> Result<(), DiffStoreError> {
    match usize::try_from(length) {
        Ok(actual) if (1..=maximum).contains(&actual) => Ok(()),
        Ok(_) | Err(_) => Err(DiffStoreError::CorruptRecord(field)),
    }
}

fn validate_optional_exact_length(
    field: &'static str,
    length: Option<i64>,
    expected: usize,
) -> Result<(), DiffStoreError> {
    match length {
        None => Ok(()),
        Some(length) => validate_exact_length(field, length, expected),
    }
}

fn validate_optional_bounded_length(
    field: &'static str,
    length: Option<i64>,
    maximum: usize,
) -> Result<(), DiffStoreError> {
    match length {
        None => Ok(()),
        Some(length) => validate_bounded_length(field, length, maximum),
    }
}

const fn encode_state(value: DiffEvidenceState) -> i64 {
    match value {
        DiffEvidenceState::Intent => 0,
        DiffEvidenceState::Ready => 1,
        DiffEvidenceState::SummaryOnly => 2,
        DiffEvidenceState::Abandoned => 3,
        DiffEvidenceState::PurgePending => 4,
        DiffEvidenceState::Tombstoned => 5,
    }
}

const fn decode_state(value: i64) -> Result<DiffEvidenceState, DiffStoreError> {
    match value {
        0 => Ok(DiffEvidenceState::Intent),
        1 => Ok(DiffEvidenceState::Ready),
        2 => Ok(DiffEvidenceState::SummaryOnly),
        3 => Ok(DiffEvidenceState::Abandoned),
        4 => Ok(DiffEvidenceState::PurgePending),
        5 => Ok(DiffEvidenceState::Tombstoned),
        _ => Err(DiffStoreError::CorruptRecord("diff.state")),
    }
}

const fn encode_render_kind(value: DiffRenderKind) -> i64 {
    match value {
        DiffRenderKind::Text => 0,
        DiffRenderKind::Binary => 1,
        DiffRenderKind::Oversized => 2,
    }
}

const fn decode_render_kind(value: i64) -> Result<DiffRenderKind, DiffStoreError> {
    match value {
        0 => Ok(DiffRenderKind::Text),
        1 => Ok(DiffRenderKind::Binary),
        2 => Ok(DiffRenderKind::Oversized),
        _ => Err(DiffStoreError::CorruptRecord("diff.render_kind")),
    }
}

const fn encode_change_kind(value: DiffChangeKind) -> i64 {
    match value {
        DiffChangeKind::Created => 0,
        DiffChangeKind::Modified => 1,
        DiffChangeKind::Deleted => 2,
    }
}

const fn decode_change_kind(value: i64) -> Result<DiffChangeKind, DiffStoreError> {
    match value {
        0 => Ok(DiffChangeKind::Created),
        1 => Ok(DiffChangeKind::Modified),
        2 => Ok(DiffChangeKind::Deleted),
        _ => Err(DiffStoreError::CorruptRecord("diff.file.kind")),
    }
}

fn validate_change_set_state(
    diff_state: DiffEvidenceState,
    change_set_state: i64,
) -> Result<(), DiffStoreError> {
    if matches!(
        (diff_state, change_set_state),
        (DiffEvidenceState::Intent, 0)
            | (DiffEvidenceState::Abandoned, 2)
            | (
                DiffEvidenceState::Ready
                    | DiffEvidenceState::SummaryOnly
                    | DiffEvidenceState::PurgePending
                    | DiffEvidenceState::Tombstoned,
                1
            )
    ) {
        Ok(())
    } else {
        Err(DiffStoreError::CorruptRecord("diff.changeset_state"))
    }
}

type ColumnShape = (&'static str, &'static str, i64, i64);

fn validate_table_columns(
    connection: &Connection,
    table: &'static str,
    expected: &[ColumnShape],
) -> Result<(), DiffStoreError> {
    let query = format!("PRAGMA table_info({table})");
    let mut statement = connection.prepare(&query)?;
    let mut rows = statement.query([])?;
    let mut actual = Vec::new();
    while let Some(row) = rows.next()? {
        if actual.len() >= 32 {
            return Err(DiffStoreError::CorruptRecord(table));
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
        Err(DiffStoreError::CorruptRecord(table))
    }
}

fn validate_schema_sql(
    connection: &Connection,
    object_type: &'static str,
    name: &'static str,
    expected: &'static str,
) -> Result<(), DiffStoreError> {
    let sql: Option<String> = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type = ?1 AND name = ?2",
            params![object_type, name],
            |row| row.get(0),
        )
        .optional()?;
    let sql = sql.ok_or(DiffStoreError::CorruptRecord(name))?;
    if normalized_sql(&sql) == normalized_sql(expected) {
        Ok(())
    } else {
        Err(DiffStoreError::CorruptRecord(name))
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
) -> Result<(), DiffStoreError> {
    let query = format!("PRAGMA index_info({index})");
    let mut statement = connection.prepare(&query)?;
    let mut rows = statement.query([])?;
    let mut actual = Vec::new();
    while let Some(row) = rows.next()? {
        if actual.len() >= 16 {
            return Err(DiffStoreError::CorruptRecord(index));
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
        Err(DiffStoreError::CorruptRecord(index))
    }
}

fn validate_foreign_keys(
    connection: &Connection,
    table: &'static str,
    expected_count: usize,
) -> Result<(), DiffStoreError> {
    let query = format!("PRAGMA foreign_key_list({table})");
    let mut statement = connection.prepare(&query)?;
    if statement.query_map([], |_| Ok(()))?.count() == expected_count {
        Ok(())
    } else {
        Err(DiffStoreError::CorruptRecord(table))
    }
}

#[derive(Debug, Error)]
pub enum DiffStoreError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error("Diff identity conflicts with an existing record")]
    IdentityConflict,
    #[error("Diff record is missing")]
    RecordMissing,
    #[error("Diff Evidence is terminal")]
    Terminal,
    #[error("Diff Evidence revision is stale")]
    RevisionConflict,
    #[error("Diff Evidence revision overflowed")]
    RevisionOverflow,
    #[error("Diff Evidence timestamp precedes its durable intent")]
    TimestampOrder,
    #[error("Diff Evidence attribution does not match its ChangeSet")]
    AttributionMismatch,
    #[error("Diff Evidence payload transition is invalid")]
    InvalidTransition,
    #[error("Diff Evidence is protected by a durable Goal association")]
    RetentionProtected,
    #[error("Diff byte count exceeds SQLite integer range")]
    SizeOverflow,
    #[error("corrupt Diff Evidence field {0}")]
    CorruptRecord(&'static str),
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use forge_domain::{
        ChangeSetState, DiffArtifactRelativePath, DiffByteCount, DiffEvidenceState,
        DiffPayloadHash, DiffRenderKind,
    };
    use rusqlite::params;
    use uuid::Uuid;

    use super::*;

    fn artifact(value: &str) -> Result<DiffArtifactRelativePath, Box<dyn std::error::Error>> {
        Ok(DiffArtifactRelativePath::new(PathBuf::from(value))?)
    }

    #[test]
    fn schema_constants_match_created_sql_and_shape() -> Result<(), Box<dyn std::error::Error>> {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE workspace(workspace_id BLOB UNIQUE);
             CREATE TABLE activities(activity_id BLOB PRIMARY KEY);
             CREATE TABLE change_sets(changeset_id BLOB PRIMARY KEY);
             CREATE TABLE file_mutations(mutation_id BLOB PRIMARY KEY);",
        )?;
        create_schema(&connection)?;
        for (kind, name, expected) in [
            ("table", "diff_evidence", EXPECTED_DIFF_EVIDENCE_TABLE_SQL),
            ("table", "diff_files", EXPECTED_DIFF_FILES_TABLE_SQL),
            (
                "index",
                "diff_evidence_activity_created_idx",
                EXPECTED_DIFF_ACTIVITY_INDEX_SQL,
            ),
            (
                "index",
                "diff_evidence_state_updated_idx",
                EXPECTED_DIFF_STATE_INDEX_SQL,
            ),
            (
                "index",
                "diff_evidence_retention_idx",
                EXPECTED_DIFF_RETENTION_INDEX_SQL,
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
    fn every_payload_lifecycle_shape_round_trips_through_raw_codec()
    -> Result<(), Box<dyn std::error::Error>> {
        let pending = artifact("diffs/.diff-id.pending")?;
        let final_path = artifact("diffs/diff_id.diff.zst")?;
        let compressed_hash = DiffPayloadHash::from_bytes([1; 32]);
        let uncompressed_hash = DiffPayloadHash::from_bytes([2; 32]);
        let compressed_size = DiffByteCount::new(30);
        let uncompressed_size = DiffByteCount::new(60);
        let payloads = [
            DiffPayloadProjection::IntentText {
                pending_relative_path: pending,
                final_relative_path: final_path.clone(),
                compressed_hash,
                uncompressed_hash,
                compressed_size,
                uncompressed_size,
            },
            DiffPayloadProjection::IntentSummary {
                render_kind: DiffRenderKind::Binary,
            },
            DiffPayloadProjection::Ready {
                relative_path: final_path.clone(),
                compressed_hash,
                uncompressed_hash,
                compressed_size,
                uncompressed_size,
            },
            DiffPayloadProjection::SummaryOnly {
                render_kind: DiffRenderKind::Oversized,
            },
            DiffPayloadProjection::Abandoned {
                render_kind: DiffRenderKind::Text,
            },
            DiffPayloadProjection::PurgePending {
                relative_path: final_path,
                compressed_hash,
                uncompressed_hash,
                compressed_size,
                uncompressed_size,
            },
            DiffPayloadProjection::Tombstoned {
                render_kind: DiffRenderKind::Text,
            },
        ];
        for payload in payloads {
            let encoded = encode_payload(&payload)?;
            let decoded = decode_payload(
                payload.state(),
                payload.render_kind(),
                RawPayloadFields {
                    pending_path: encoded.pending_path,
                    artifact_path: encoded.artifact_path,
                    compressed_hash: encoded.compressed_hash,
                    uncompressed_hash: encoded.uncompressed_hash,
                    compressed_size: encoded.compressed_size,
                    uncompressed_size: encoded.uncompressed_size,
                },
            )?;
            assert_eq!(decoded, payload);
        }
        Ok(())
    }

    fn doctor_connection() -> Result<Connection, Box<dyn std::error::Error>> {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE workspace (workspace_id BLOB PRIMARY KEY);
             CREATE TABLE activities (activity_id BLOB PRIMARY KEY);
             CREATE TABLE change_sets (
                 changeset_id BLOB PRIMARY KEY,
                 workspace_id BLOB NOT NULL,
                 activity_id BLOB NOT NULL,
                 state INTEGER NOT NULL,
                 created_at_ms INTEGER NOT NULL,
                 updated_at_ms INTEGER NOT NULL,
                 revision INTEGER NOT NULL
             );
             CREATE TABLE file_mutations (
                 mutation_id BLOB PRIMARY KEY,
                 changeset_id BLOB NOT NULL UNIQUE,
                 relative_path BLOB NOT NULL
             );",
        )?;
        create_schema(&connection)?;
        connection.execute(
            "INSERT INTO workspace(workspace_id) VALUES (?1)",
            params![Uuid::from_u128(0x100).as_bytes()],
        )?;
        connection.execute(
            "INSERT INTO activities(activity_id) VALUES (?1)",
            params![Uuid::from_u128(0x200).as_bytes()],
        )?;
        Ok(connection)
    }

    fn insert_change_set(
        connection: &Connection,
        seed: u128,
        state: ChangeSetState,
    ) -> Result<(Uuid, Uuid), Box<dyn std::error::Error>> {
        let change_set_id = Uuid::from_u128(seed);
        let mutation_id = Uuid::from_u128(seed.saturating_add(0x10_000));
        let encoded_state = match state {
            ChangeSetState::Starting => 0,
            ChangeSetState::Applied => 1,
            ChangeSetState::Failed => 2,
        };
        connection.execute(
            "INSERT INTO change_sets(
                changeset_id, workspace_id, activity_id, state,
                created_at_ms, updated_at_ms, revision
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?5, 1)",
            params![
                change_set_id.as_bytes(),
                Uuid::from_u128(0x100).as_bytes(),
                Uuid::from_u128(0x200).as_bytes(),
                encoded_state,
                i64::try_from(seed)?
            ],
        )?;
        connection.execute(
            "INSERT INTO file_mutations(mutation_id, changeset_id, relative_path)
             VALUES (?1, ?2, ?3)",
            params![
                mutation_id.as_bytes(),
                change_set_id.as_bytes(),
                format!("src/file-{seed}.rs").as_bytes()
            ],
        )?;
        Ok((change_set_id, mutation_id))
    }

    fn insert_current_diff(
        connection: &Connection,
        seed: u128,
        state: DiffEvidenceState,
        render_kind: DiffRenderKind,
    ) -> Result<DiffId, Box<dyn std::error::Error>> {
        let change_set_state = match state {
            DiffEvidenceState::Intent => ChangeSetState::Starting,
            DiffEvidenceState::Abandoned => ChangeSetState::Failed,
            DiffEvidenceState::Ready
            | DiffEvidenceState::SummaryOnly
            | DiffEvidenceState::PurgePending
            | DiffEvidenceState::Tombstoned => ChangeSetState::Applied,
        };
        let (change_set_id, mutation_id) = insert_change_set(connection, seed, change_set_state)?;
        let diff_id = DiffId::for_change_set(ChangeSetId::from_uuid(change_set_id));
        let marker = u8::try_from(seed % 251)?;
        let hash = vec![marker; HASH_BYTES];
        let uncompressed_hash = vec![marker.wrapping_add(1); HASH_BYTES];
        let (pending_path, artifact_path, compressed_size, uncompressed_size) = match state {
            DiffEvidenceState::Intent => (
                Some(format!("diffs/.diff-{diff_id}.pending").into_bytes()),
                Some(format!("diffs/diff_{diff_id}.diff.zst").into_bytes()),
                Some(4_i64),
                Some(8_i64),
            ),
            DiffEvidenceState::Ready | DiffEvidenceState::PurgePending => (
                None,
                Some(format!("diffs/diff_{diff_id}.diff.zst").into_bytes()),
                Some(4_i64),
                Some(8_i64),
            ),
            DiffEvidenceState::SummaryOnly
            | DiffEvidenceState::Abandoned
            | DiffEvidenceState::Tombstoned => (None, None, None, None),
        };
        let encoded_state = encode_state(state);
        let encoded_render_kind = encode_render_kind(render_kind);
        connection.execute(
            "INSERT INTO diff_evidence(
                diff_id, changeset_id, workspace_id, activity_id, mutation_id,
                state, render_kind, pending_relative_path, artifact_relative_path,
                compressed_hash, uncompressed_hash, compressed_size, uncompressed_size,
                renderer_version, redaction_policy_version, created_at_ms,
                updated_at_ms, revision
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
                       1, 1, ?14, ?14, 1)",
            params![
                diff_id.into_uuid().as_bytes(),
                change_set_id.as_bytes(),
                Uuid::from_u128(0x100).as_bytes(),
                Uuid::from_u128(0x200).as_bytes(),
                mutation_id.as_bytes(),
                encoded_state,
                encoded_render_kind,
                pending_path,
                artifact_path,
                (compressed_size.is_some()).then_some(hash),
                (uncompressed_size.is_some()).then_some(uncompressed_hash),
                compressed_size,
                uncompressed_size,
                i64::try_from(seed)?
            ],
        )?;
        connection.execute(
            "INSERT INTO diff_files(diff_id, ordinal, relative_path, kind, additions, deletions)
             VALUES (?1, 0, ?2, 0, 1, 0)",
            params![
                diff_id.into_uuid().as_bytes(),
                format!("src/file-{seed}.rs").as_bytes()
            ],
        )?;
        Ok(diff_id)
    }

    fn insert_legacy(
        connection: &Connection,
        seed: u128,
        state: ChangeSetState,
    ) -> Result<DiffId, Box<dyn std::error::Error>> {
        let (change_set_id, _) = insert_change_set(connection, seed, state)?;
        Ok(DiffId::for_change_set(ChangeSetId::from_uuid(
            change_set_id,
        )))
    }

    #[test]
    fn doctor_references_reports_empty_current_database() -> Result<(), Box<dyn std::error::Error>>
    {
        let connection = doctor_connection()?;
        let report = doctor_references(&connection)?;
        assert!(report.references().is_empty());
        assert!(!report.truncated());
        Ok(())
    }

    #[test]
    fn doctor_references_reports_lifecycle_and_artifact_metadata()
    -> Result<(), Box<dyn std::error::Error>> {
        let connection = doctor_connection()?;
        let pending = insert_current_diff(
            &connection,
            0x301,
            DiffEvidenceState::Intent,
            DiffRenderKind::Text,
        )?;
        let ready = insert_current_diff(
            &connection,
            0x302,
            DiffEvidenceState::Ready,
            DiffRenderKind::Text,
        )?;
        let summary = insert_current_diff(
            &connection,
            0x303,
            DiffEvidenceState::SummaryOnly,
            DiffRenderKind::Binary,
        )?;
        let purge_pending = insert_current_diff(
            &connection,
            0x304,
            DiffEvidenceState::PurgePending,
            DiffRenderKind::Text,
        )?;
        let legacy = insert_legacy(&connection, 0x305, ChangeSetState::Applied)?;

        let report = doctor_references(&connection)?;
        assert_eq!(report.references().len(), 5);
        assert!(!report.truncated());
        let pending_reference = report
            .references()
            .iter()
            .find(|reference| reference.diff_id() == pending)
            .ok_or("pending reference missing")?;
        assert_eq!(
            pending_reference.lifecycle().evidence_state(),
            Some(DiffEvidenceState::Intent)
        );
        assert_eq!(
            pending_reference
                .pending_artifact()
                .ok_or("pending artifact missing")?
                .name()
                .as_bytes(),
            format!(".diff-{pending}.pending").as_bytes()
        );
        assert_eq!(
            pending_reference
                .final_artifact()
                .ok_or("final artifact missing")?
                .name()
                .as_bytes(),
            format!("diff_{pending}.diff.zst").as_bytes()
        );
        let ready_reference = report
            .references()
            .iter()
            .find(|reference| reference.diff_id() == ready)
            .ok_or("ready reference missing")?;
        assert!(ready_reference.pending_artifact().is_none());
        assert!(ready_reference.final_artifact().is_some());
        let summary_reference = report
            .references()
            .iter()
            .find(|reference| reference.diff_id() == summary)
            .ok_or("summary reference missing")?;
        assert_eq!(
            summary_reference.lifecycle().evidence_state(),
            Some(DiffEvidenceState::SummaryOnly)
        );
        assert!(summary_reference.final_artifact().is_none());
        let purge_reference = report
            .references()
            .iter()
            .find(|reference| reference.diff_id() == purge_pending)
            .ok_or("purge reference missing")?;
        assert_eq!(
            purge_reference.lifecycle().evidence_state(),
            Some(DiffEvidenceState::PurgePending)
        );
        let legacy_reference = report
            .references()
            .iter()
            .find(|reference| reference.diff_id() == legacy)
            .ok_or("legacy reference missing")?;
        assert!(legacy_reference.is_legacy());
        assert_eq!(
            legacy_reference.lifecycle().legacy_change_set_state(),
            Some(ChangeSetState::Applied)
        );
        Ok(())
    }

    #[test]
    fn doctor_references_is_bounded_and_deterministically_ordered()
    -> Result<(), Box<dyn std::error::Error>> {
        let connection = doctor_connection()?;
        for seed in 0x400..0x400 + u128::try_from(DIFF_DOCTOR_PROBE_REFERENCES)? {
            insert_current_diff(
                &connection,
                seed,
                DiffEvidenceState::SummaryOnly,
                DiffRenderKind::Oversized,
            )?;
        }
        let report = doctor_references(&connection)?;
        assert_eq!(report.references().len(), DIFF_DOCTOR_MAX_REFERENCES);
        assert!(report.truncated());
        assert!(
            report
                .references()
                .windows(2)
                .all(|window| window[0].diff_id() < window[1].diff_id())
        );
        Ok(())
    }

    #[test]
    fn doctor_references_rejects_corrupted_persisted_artifact_metadata()
    -> Result<(), Box<dyn std::error::Error>> {
        let connection = doctor_connection()?;
        let diff_id = insert_current_diff(
            &connection,
            0x500,
            DiffEvidenceState::Ready,
            DiffRenderKind::Text,
        )?;
        connection.execute(
            "UPDATE diff_evidence SET artifact_relative_path = ?1 WHERE diff_id = ?2",
            params![
                b"diffs/not-the-identity-derived-name.diff.zst".as_slice(),
                diff_id.into_uuid().as_bytes()
            ],
        )?;
        assert!(matches!(
            doctor_references(&connection),
            Err(DiffStoreError::CorruptRecord("diff.artifact_relative_path"))
        ));
        Ok(())
    }
}
