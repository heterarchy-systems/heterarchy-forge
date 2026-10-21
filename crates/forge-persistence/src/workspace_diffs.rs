use std::ffi::OsString;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use forge_domain::{
    AbandonDiffEvidence, ActivityId, BeginDiffEvidence, BeginDiffPurge, BeginFileMutation,
    ChangeSetId, CompleteDiffEvidence, CompleteDiffPurge, DiffArtifactInventoryName,
    DiffArtifactRelativePath, DiffAttribution, DiffByteCount, DiffChangeKind, DiffContractVersions,
    DiffEntrySubject, DiffEntrySummary, DiffEvidenceState, DiffEvidenceTimestamps, DiffId,
    DiffLineCount, DiffListLimit, DiffOrigin, DiffPayloadHash, DiffPayloadProjection,
    DiffPurgeRecord, DiffPurgeStatus, DiffRedactionPolicyVersion, DiffRenderKind,
    DiffRendererVersion, DiffRetentionKeepCount, DiffRetentionPlanLimit, DiffRevision,
    FileMutationId, RegisteredDiffEvidence, TimestampMillis, TreeChangeSetIntent, WorkspaceId,
    WorkspaceRelativePath,
};
use rusqlite::{Connection, OptionalExtension, Row, Transaction, params};
use thiserror::Error;
use uuid::Uuid;

pub(crate) const EXPECTED_DIFF_EVIDENCE_TABLE_SQL: &str = "CREATE TABLE diff_evidence (diff_id BLOB PRIMARY KEY NOT NULL CHECK(length(diff_id) = 16), changeset_id BLOB NOT NULL UNIQUE REFERENCES change_sets(changeset_id), workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id), activity_id BLOB NOT NULL REFERENCES activities(activity_id), origin_kind INTEGER NOT NULL CHECK(origin_kind IN (0, 1)), mutation_id BLOB UNIQUE REFERENCES file_mutations(mutation_id) CHECK(mutation_id IS NULL OR length(mutation_id) = 16), state INTEGER NOT NULL CHECK(state IN (0, 1, 2, 3, 4, 5)), render_kind INTEGER NOT NULL CHECK(render_kind IN (0, 1, 2, 3)), pending_relative_path BLOB CHECK(pending_relative_path IS NULL OR length(pending_relative_path) BETWEEN 1 AND 4096), artifact_relative_path BLOB CHECK(artifact_relative_path IS NULL OR length(artifact_relative_path) BETWEEN 1 AND 4096), compressed_hash BLOB CHECK(compressed_hash IS NULL OR length(compressed_hash) = 32), uncompressed_hash BLOB CHECK(uncompressed_hash IS NULL OR length(uncompressed_hash) = 32), compressed_size INTEGER CHECK(compressed_size IS NULL OR compressed_size >= 0), uncompressed_size INTEGER CHECK(uncompressed_size IS NULL OR uncompressed_size >= 0), renderer_version INTEGER NOT NULL CHECK(renderer_version >= 1), redaction_policy_version INTEGER NOT NULL CHECK(redaction_policy_version >= 1), created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0), updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0), revision INTEGER NOT NULL CHECK(revision >= 1), CHECK((origin_kind = 0 AND mutation_id IS NOT NULL) OR (origin_kind = 1 AND mutation_id IS NULL)), CHECK((state = 0 AND render_kind = 0 AND pending_relative_path IS NOT NULL AND artifact_relative_path IS NOT NULL AND compressed_hash IS NOT NULL AND uncompressed_hash IS NOT NULL AND compressed_size IS NOT NULL AND uncompressed_size IS NOT NULL) OR (state = 0 AND render_kind IN (1, 2, 3) AND pending_relative_path IS NULL AND artifact_relative_path IS NULL AND compressed_hash IS NULL AND uncompressed_hash IS NULL AND compressed_size IS NULL AND uncompressed_size IS NULL) OR (state IN (1, 4) AND render_kind = 0 AND pending_relative_path IS NULL AND artifact_relative_path IS NOT NULL AND compressed_hash IS NOT NULL AND uncompressed_hash IS NOT NULL AND compressed_size IS NOT NULL AND uncompressed_size IS NOT NULL) OR (state = 2 AND render_kind IN (1, 2, 3) AND pending_relative_path IS NULL AND artifact_relative_path IS NULL AND compressed_hash IS NULL AND uncompressed_hash IS NULL AND compressed_size IS NULL AND uncompressed_size IS NULL) OR (state IN (3, 5) AND pending_relative_path IS NULL AND artifact_relative_path IS NULL AND compressed_hash IS NULL AND uncompressed_hash IS NULL AND compressed_size IS NULL AND uncompressed_size IS NULL)))";
pub(crate) const EXPECTED_DIFF_ENTRIES_TABLE_SQL: &str = "CREATE TABLE diff_entries (diff_id BLOB NOT NULL REFERENCES diff_evidence(diff_id), ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 0 AND 255), subject_kind INTEGER NOT NULL CHECK(subject_kind IN (0, 1)), primary_path BLOB NOT NULL CHECK(length(primary_path) BETWEEN 1 AND 4096), secondary_path BLOB CHECK(secondary_path IS NULL OR length(secondary_path) BETWEEN 1 AND 4096), kind INTEGER NOT NULL CHECK(kind IN (0, 1, 2, 3)), additions INTEGER NOT NULL CHECK(additions >= 0), deletions INTEGER NOT NULL CHECK(deletions >= 0), PRIMARY KEY(diff_id, ordinal), CHECK((kind = 3 AND secondary_path IS NOT NULL) OR (kind IN (0, 1, 2) AND secondary_path IS NULL)))";
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

    /// Durable Diff references in deterministic `DiffId` order.
    pub fn references(&self) -> &[DiffDoctorReference] {
        &self.references
    }

    /// Whether at least one durable reference existed beyond the 256-row
    /// Doctor bound.
    pub const fn truncated(&self) -> bool {
        self.truncated
    }
}

/// One current durable Diff row.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffDoctorReference {
    diff_id: DiffId,
    state: DiffEvidenceState,
    render_kind: DiffRenderKind,
    pending_artifact: Option<DiffDoctorArtifactReference>,
    final_artifact: Option<DiffDoctorArtifactReference>,
}

impl DiffDoctorReference {
    pub const fn diff_id(&self) -> DiffId {
        self.diff_id
    }

    pub const fn state(&self) -> DiffEvidenceState {
        self.state
    }

    pub const fn render_kind(&self) -> DiffRenderKind {
        self.render_kind
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

const HEADER_QUERY: &str = "SELECT
        length(CAST(e.diff_id AS BLOB)), length(CAST(e.workspace_id AS BLOB)),
        length(CAST(e.activity_id AS BLOB)), length(CAST(e.changeset_id AS BLOB)),
        length(CAST(e.mutation_id AS BLOB)),
        length(CAST(e.pending_relative_path AS BLOB)),
        length(CAST(e.artifact_relative_path AS BLOB)),
        length(CAST(e.compressed_hash AS BLOB)), length(CAST(e.uncompressed_hash AS BLOB)),
        e.diff_id, e.workspace_id, e.activity_id, e.changeset_id, e.origin_kind, e.mutation_id,
        e.state, e.render_kind, e.pending_relative_path, e.artifact_relative_path,
        e.compressed_hash, e.uncompressed_hash, e.compressed_size, e.uncompressed_size,
        e.renderer_version, e.redaction_policy_version, e.created_at_ms, e.updated_at_ms,
        e.revision, e.workspace_id = c.workspace_id, e.activity_id = c.activity_id,
        CASE WHEN e.origin_kind = 0 THEN m.mutation_id IS NOT NULL AND e.changeset_id = m.changeset_id
             ELSE e.mutation_id IS NULL END,
        c.state
    FROM diff_evidence AS e
    JOIN change_sets AS c ON c.changeset_id = e.changeset_id
    LEFT JOIN file_mutations AS m ON m.mutation_id = e.mutation_id";

pub(crate) fn create_schema(connection: &Connection) -> Result<(), DiffStoreError> {
    create_diff_core_schema(connection)?;
    create_retention_index(connection)
}

fn create_diff_core_schema(connection: &Connection) -> Result<(), DiffStoreError> {
    for sql in [
        EXPECTED_DIFF_EVIDENCE_TABLE_SQL,
        EXPECTED_DIFF_ENTRIES_TABLE_SQL,
        EXPECTED_DIFF_ACTIVITY_INDEX_SQL,
        EXPECTED_DIFF_STATE_INDEX_SQL,
    ] {
        connection.execute_batch(sql)?;
    }
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
        ("table", "diff_entries"),
        ("index", "diff_evidence_activity_created_idx"),
        ("index", "diff_evidence_state_updated_idx"),
        ("index", "diff_evidence_retention_idx"),
    ]
}

pub(crate) fn validate_schema(connection: &Connection) -> Result<(), DiffStoreError> {
    validate_diff_core_schema(connection)?;
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

pub(crate) fn validate_diff_core_schema(connection: &Connection) -> Result<(), DiffStoreError> {
    validate_schema_sql(
        connection,
        "table",
        "diff_evidence",
        EXPECTED_DIFF_EVIDENCE_TABLE_SQL,
    )?;
    validate_schema_sql(
        connection,
        "table",
        "diff_entries",
        EXPECTED_DIFF_ENTRIES_TABLE_SQL,
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
            ("origin_kind", "INTEGER", 1, 0),
            ("mutation_id", "BLOB", 0, 0),
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
        "diff_entries",
        &[
            ("diff_id", "BLOB", 1, 1),
            ("ordinal", "INTEGER", 1, 2),
            ("subject_kind", "INTEGER", 1, 0),
            ("primary_path", "BLOB", 1, 0),
            ("secondary_path", "BLOB", 0, 0),
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
    validate_foreign_keys(connection, "diff_entries", 1)
}

pub(crate) fn begin(
    transaction: &Transaction<'_>,
    file_command: &BeginFileMutation,
    command: &BeginDiffEvidence,
) -> Result<RegisteredDiffEvidence, DiffStoreError> {
    validate_file_begin_linkage(file_command, command)?;
    insert_begin(transaction, command)
}

pub(crate) fn begin_tree(
    transaction: &Transaction<'_>,
    tree_intent: &TreeChangeSetIntent,
    command: &BeginDiffEvidence,
) -> Result<RegisteredDiffEvidence, DiffStoreError> {
    validate_tree_begin_linkage(tree_intent, command)?;
    insert_begin(transaction, command)
}

pub(crate) fn inspect_tree(
    connection: &Connection,
    tree_intent: &TreeChangeSetIntent,
    command: &BeginDiffEvidence,
) -> Result<Option<RegisteredDiffEvidence>, DiffStoreError> {
    validate_tree_begin_linkage(tree_intent, command)?;
    let existing = get_by_change_set(connection, tree_intent.attribution().id())?;
    match existing {
        Some(record) if record_matches_begin(&record, command) => Ok(Some(record)),
        Some(_) => Err(DiffStoreError::IdentityConflict),
        None => Ok(None),
    }
}

fn insert_begin(
    transaction: &Transaction<'_>,
    command: &BeginDiffEvidence,
) -> Result<RegisteredDiffEvidence, DiffStoreError> {
    let attribution = command.attribution();
    if crate::workspace_goal_deletion::artifact_identity_is_pending(
        transaction,
        crate::workspace_goal_deletion::GoalDeletionArtifactIdentity::Diff(attribution.id()),
    )? {
        return Err(DiffStoreError::IdentityConflict);
    }
    if let Some(existing) = get_by_change_set(transaction, attribution.change_set_id())? {
        return if record_matches_begin(&existing, command) {
            Ok(existing)
        } else {
            Err(DiffStoreError::IdentityConflict)
        };
    }
    if get_by_id(transaction, attribution.id())?.is_some() {
        return Err(DiffStoreError::IdentityConflict);
    }

    let encoded = encode_payload(command.payload())?;
    let diff_id = attribution.id().into_uuid().into_bytes();
    let change_set_id = attribution.change_set_id().into_uuid().into_bytes();
    let workspace_id = attribution.workspace_id().into_uuid().into_bytes();
    let activity_id = attribution.activity_id().into_uuid().into_bytes();
    let (origin_kind, mutation_id) = match attribution.origin() {
        DiffOrigin::FileMutation(id) => (0_i64, Some(id.into_uuid().into_bytes())),
        DiffOrigin::TreeChangeSet => (1_i64, None),
    };
    transaction.execute(
        "INSERT INTO diff_evidence (
            diff_id, changeset_id, workspace_id, activity_id, origin_kind, mutation_id,
            state, render_kind, pending_relative_path, artifact_relative_path,
            compressed_hash, uncompressed_hash, compressed_size, uncompressed_size,
            renderer_version, redaction_policy_version, created_at_ms, updated_at_ms, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?17, ?18)",
        params![
            diff_id.as_slice(),
            change_set_id.as_slice(),
            workspace_id.as_slice(),
            activity_id.as_slice(),
            origin_kind,
            mutation_id.as_ref().map(<[u8; 16]>::as_slice),
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
    for (ordinal, entry) in command.entries().iter().enumerate() {
        let ordinal = i64::try_from(ordinal).map_err(|_| DiffStoreError::SizeOverflow)?;
        transaction.execute(
            "INSERT INTO diff_entries (
                diff_id, ordinal, subject_kind, primary_path, secondary_path, kind, additions, deletions
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                diff_id.as_slice(),
                ordinal,
                encode_entry_subject(entry.subject()),
                entry.primary_path().as_path().as_os_str().as_bytes(),
                entry.secondary_path().map(|path| path.as_path().as_os_str().as_bytes()),
                encode_change_kind(entry.kind()),
                i64::from(entry.additions().get()),
                i64::from(entry.deletions().get()),
            ],
        )?;
    }
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
    let activity_id = activity_id.into_uuid().into_bytes();
    let mut statement = connection.prepare(
        "SELECT diff_id FROM diff_evidence
         WHERE activity_id = ?1
         ORDER BY created_at_ms DESC, diff_id DESC LIMIT ?2",
    )?;
    let ids = statement
        .query_map(
            params![activity_id.as_slice(), i64::from(limit.get())],
            |row| row.get::<_, Vec<u8>>(0),
        )?
        .collect::<Result<Vec<_>, _>>()?;
    ids.into_iter()
        .map(|raw| {
            let id = decode_uuid("diff.id", &raw).map(DiffId::from_uuid)?;
            get_by_id(connection, id)?.ok_or(DiffStoreError::RecordMissing)
        })
        .collect()
}

/// Read a bounded, metadata-only inventory of current Diff expectations.
///
/// The query is a fixed bounded scan ordered by stable Diff identity. No
/// artifact body or per-row follow-up query is issued.
pub(crate) fn doctor_references(
    connection: &Connection,
) -> Result<DiffDoctorReport, DiffStoreError> {
    validate_doctor_relationships(connection)?;
    let mut references = Vec::with_capacity(DIFF_DOCTOR_PROBE_REFERENCES);
    let query = format!(
        "SELECT diff_id FROM diff_evidence ORDER BY diff_id ASC LIMIT {DIFF_DOCTOR_PROBE_REFERENCES}"
    );
    let mut statement = connection.prepare(&query)?;
    let ids = statement
        .query_map([], |row| row.get::<_, Vec<u8>>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    for raw in ids {
        let id = decode_uuid("diff.id", &raw).map(DiffId::from_uuid)?;
        let evidence = get_by_id(connection, id)?.ok_or(DiffStoreError::RecordMissing)?;
        references.push(doctor_reference_from_evidence(&evidence)?);
    }
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
            LEFT JOIN change_sets AS c ON c.changeset_id = e.changeset_id
            LEFT JOIN file_mutations AS m ON m.mutation_id = e.mutation_id
            WHERE c.changeset_id IS NULL
               OR NOT EXISTS (SELECT 1 FROM diff_entries AS d WHERE d.diff_id = e.diff_id)
               OR e.workspace_id != c.workspace_id
               OR e.activity_id != c.activity_id
               OR (e.origin_kind = 0 AND (m.mutation_id IS NULL OR e.changeset_id != m.changeset_id))
               OR (e.origin_kind = 1 AND e.mutation_id IS NOT NULL)
        )",
        [],
        |row| row.get(0),
    )?;
    if malformed_current != 0 {
        return Err(DiffStoreError::CorruptRecord("diff.relationship"));
    }

    let orphaned_entries: i64 = connection.query_row(
        "SELECT EXISTS(
            SELECT 1
            FROM diff_entries AS d
            LEFT JOIN diff_evidence AS e ON e.diff_id = d.diff_id
            WHERE e.diff_id IS NULL
        )",
        [],
        |row| row.get(0),
    )?;
    if orphaned_entries != 0 {
        return Err(DiffStoreError::CorruptRecord("diff.relationship"));
    }
    Ok(())
}

fn doctor_reference_from_evidence(
    evidence: &RegisteredDiffEvidence,
) -> Result<DiffDoctorReference, DiffStoreError> {
    let diff_id = evidence.id();
    let state = evidence.state();
    let render_kind = evidence.payload().render_kind();
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
        state,
        render_kind,
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

pub(crate) fn list_retention_candidates(
    connection: &Connection,
    keep_recent: DiffRetentionKeepCount,
    limit: DiffRetentionPlanLimit,
) -> Result<Vec<RegisteredDiffEvidence>, DiffStoreError> {
    let mut statement = connection.prepare(
        "SELECT e.diff_id FROM diff_evidence AS e
         WHERE e.state = 1 AND e.render_kind = 0
         AND NOT EXISTS (
             SELECT 1 FROM goal_evidence_refs AS g
             WHERE g.evidence_kind = 0 AND g.evidence_id = e.changeset_id
         )
         ORDER BY e.created_at_ms DESC, e.diff_id DESC LIMIT ?1 OFFSET ?2",
    )?;
    let ids = statement
        .query_map(
            params![i64::from(limit.get()), i64::from(keep_recent.get())],
            |row| row.get::<_, Vec<u8>>(0),
        )?
        .collect::<Result<Vec<_>, _>>()?;
    ids.into_iter()
        .map(|raw| {
            let id = decode_uuid("diff.id", &raw).map(DiffId::from_uuid)?;
            get_by_id(connection, id)?.ok_or(DiffStoreError::RecordMissing)
        })
        .collect()
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
    let query = format!("{HEADER_QUERY} {clause}");
    let header = connection
        .query_row(&query, params![id], decode_header)
        .optional()?;
    let Some(header) = header else {
        return Ok(None);
    };
    let entries = query_entries(connection, header.attribution.id())?;
    if entries.is_empty() || entries.len() > forge_domain::MAX_TREE_CHANGESET_MUTATIONS {
        return Err(DiffStoreError::CorruptRecord("diff.entries"));
    }
    Ok(Some(RegisteredDiffEvidence::from_parts(
        header.attribution,
        entries,
        header.payload,
        header.timestamps,
        header.versions,
        header.revision,
    )))
}

#[derive(Debug)]
struct DecodedDiffHeader {
    attribution: DiffAttribution,
    payload: DiffPayloadProjection,
    timestamps: DiffEvidenceTimestamps,
    versions: DiffContractVersions,
    revision: DiffRevision,
}

fn decode_header(row: &Row<'_>) -> rusqlite::Result<DecodedDiffHeader> {
    decode_header_inner(row).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(9, rusqlite::types::Type::Blob, Box::new(error))
    })
}

fn decode_header_inner(row: &Row<'_>) -> Result<DecodedDiffHeader, DiffStoreError> {
    for (field, index) in [
        ("diff.id", 0),
        ("diff.workspace_id", 1),
        ("diff.activity_id", 2),
        ("diff.changeset_id", 3),
    ] {
        validate_exact_length(field, row.get(index)?, 16)?;
    }
    validate_optional_exact_length("diff.mutation_id", row.get(4)?, 16)?;
    validate_optional_bounded_length("diff.pending_relative_path", row.get(5)?, MAX_PATH_BYTES)?;
    validate_optional_bounded_length("diff.artifact_relative_path", row.get(6)?, MAX_PATH_BYTES)?;
    validate_optional_exact_length("diff.compressed_hash", row.get(7)?, HASH_BYTES)?;
    validate_optional_exact_length("diff.uncompressed_hash", row.get(8)?, HASH_BYTES)?;

    let id = decode_uuid("diff.id", &row.get::<_, Vec<u8>>(9)?).map(DiffId::from_uuid)?;
    let workspace_id = decode_uuid("diff.workspace_id", &row.get::<_, Vec<u8>>(10)?)
        .map(WorkspaceId::from_uuid)?;
    let activity_id =
        decode_uuid("diff.activity_id", &row.get::<_, Vec<u8>>(11)?).map(ActivityId::from_uuid)?;
    let change_set_id = decode_uuid("diff.changeset_id", &row.get::<_, Vec<u8>>(12)?)
        .map(ChangeSetId::from_uuid)?;
    if id != DiffId::for_change_set(change_set_id)
        || row.get::<_, i64>(28)? != 1
        || row.get::<_, i64>(29)? != 1
        || row.get::<_, i64>(30)? != 1
    {
        return Err(DiffStoreError::CorruptRecord("diff.attribution"));
    }
    let origin = match (row.get::<_, i64>(13)?, row.get::<_, Option<Vec<u8>>>(14)?) {
        (0, Some(raw)) => DiffOrigin::FileMutation(
            decode_uuid("diff.mutation_id", &raw).map(FileMutationId::from_uuid)?,
        ),
        (1, None) => DiffOrigin::TreeChangeSet,
        _ => return Err(DiffStoreError::CorruptRecord("diff.origin")),
    };
    let attribution = match origin {
        DiffOrigin::FileMutation(mutation_id) => DiffAttribution::for_file_mutation(
            id,
            workspace_id,
            activity_id,
            change_set_id,
            mutation_id,
        ),
        DiffOrigin::TreeChangeSet => {
            DiffAttribution::for_tree_change_set(id, workspace_id, activity_id, change_set_id)
        }
    };
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
    validate_change_set_state(state, row.get(31)?)?;
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
    Ok(DecodedDiffHeader {
        attribution,
        payload,
        timestamps: DiffEvidenceTimestamps::new(created_at, updated_at),
        versions: DiffContractVersions::new(renderer_version, redaction_policy_version),
        revision,
    })
}

fn query_entries(
    connection: &Connection,
    id: DiffId,
) -> Result<Vec<DiffEntrySummary>, DiffStoreError> {
    let raw_id = id.into_uuid().into_bytes();
    let mut statement = connection.prepare(
        "SELECT ordinal, subject_kind, primary_path, secondary_path, kind, additions, deletions
         FROM diff_entries WHERE diff_id = ?1 ORDER BY ordinal ASC",
    )?;
    let mut rows = statement.query(params![raw_id.as_slice()])?;
    let mut entries = Vec::new();
    while let Some(row) = rows.next()? {
        let expected_ordinal =
            i64::try_from(entries.len()).map_err(|_| DiffStoreError::SizeOverflow)?;
        if row.get::<_, i64>(0)? != expected_ordinal {
            return Err(DiffStoreError::CorruptRecord("diff.entry.ordinal"));
        }
        let subject = match row.get::<_, i64>(1)? {
            0 => DiffEntrySubject::File,
            1 => DiffEntrySubject::Directory,
            _ => return Err(DiffStoreError::CorruptRecord("diff.entry.subject_kind")),
        };
        let primary_raw: Vec<u8> = row.get(2)?;
        validate_bounded_length(
            "diff.entry.primary_path",
            i64::try_from(primary_raw.len()).unwrap_or(i64::MAX),
            MAX_PATH_BYTES,
        )?;
        let primary = WorkspaceRelativePath::new(PathBuf::from(OsString::from_vec(primary_raw)))
            .map_err(|_| DiffStoreError::CorruptRecord("diff.entry.primary_path"))?;
        let secondary_raw: Option<Vec<u8>> = row.get(3)?;
        if let Some(raw) = secondary_raw.as_ref() {
            validate_bounded_length(
                "diff.entry.secondary_path",
                i64::try_from(raw.len()).unwrap_or(i64::MAX),
                MAX_PATH_BYTES,
            )?;
        }
        let secondary = secondary_raw
            .map(|raw| WorkspaceRelativePath::new(PathBuf::from(OsString::from_vec(raw))))
            .transpose()
            .map_err(|_| DiffStoreError::CorruptRecord("diff.entry.secondary_path"))?;
        let kind = decode_change_kind(row.get(4)?)?;
        let additions = DiffLineCount::new(decode_u32("diff.entry.additions", row.get(5)?)?);
        let deletions = DiffLineCount::new(decode_u32("diff.entry.deletions", row.get(6)?)?);
        entries.push(
            DiffEntrySummary::new(subject, primary, secondary, kind, additions, deletions)
                .map_err(|_| DiffStoreError::CorruptRecord("diff.entry.shape"))?,
        );
        if entries.len() > forge_domain::MAX_TREE_CHANGESET_MUTATIONS {
            return Err(DiffStoreError::CorruptRecord("diff.entries"));
        }
    }
    Ok(entries)
}

fn validate_file_begin_linkage(
    file_command: &BeginFileMutation,
    command: &BeginDiffEvidence,
) -> Result<(), DiffStoreError> {
    let attribution = command.attribution();
    let expected_kind = match file_command.kind() {
        forge_domain::FileMutationKind::Create => DiffChangeKind::Created,
        forge_domain::FileMutationKind::Replace => DiffChangeKind::Modified,
        forge_domain::FileMutationKind::Delete => DiffChangeKind::Deleted,
    };
    let expected_origin = DiffOrigin::FileMutation(file_command.mutation_id());
    let [entry] = command.entries() else {
        return Err(DiffStoreError::AttributionMismatch);
    };
    if attribution.id() != DiffId::for_change_set(file_command.change_set_id())
        || attribution.change_set_id() != file_command.change_set_id()
        || attribution.origin() != expected_origin
        || attribution.workspace_id() != file_command.workspace_id()
        || attribution.activity_id() != file_command.activity_id()
        || entry.subject() != DiffEntrySubject::File
        || entry.primary_path() != file_command.path()
        || entry.secondary_path().is_some()
        || entry.kind() != expected_kind
        || command.observed_at() != file_command.observed_at()
    {
        return Err(DiffStoreError::AttributionMismatch);
    }
    Ok(())
}

fn validate_tree_begin_linkage(
    tree_intent: &TreeChangeSetIntent,
    command: &BeginDiffEvidence,
) -> Result<(), DiffStoreError> {
    let attribution = command.attribution();
    let change_set = tree_intent.attribution();
    if attribution.id() != DiffId::for_change_set(change_set.id())
        || attribution.change_set_id() != change_set.id()
        || attribution.origin() != DiffOrigin::TreeChangeSet
        || attribution.workspace_id() != change_set.workspace_id()
        || attribution.activity_id() != change_set.activity_id()
        || command.observed_at() != tree_intent.observed_at()
        || command.entries() != tree_intent.diff_entries()
        || !valid_tree_begin_payload(command.versions(), command.payload(), command.entries())
    {
        return Err(DiffStoreError::AttributionMismatch);
    }
    Ok(())
}

/// Tree Diff text is truthful only when every entry is a file modification,
/// because one aggregate text artifact cannot describe directory, move, or
/// delete effects. V1 keeps the historical structured summary contract for
/// arbitrary validated tree plans. V2 adds text and its explicit oversized
/// fallback for patch-only plans.
fn valid_tree_begin_payload(
    versions: DiffContractVersions,
    payload: &DiffPayloadProjection,
    entries: &[DiffEntrySummary],
) -> bool {
    match (versions, payload) {
        (
            DiffContractVersions::V1,
            DiffPayloadProjection::IntentSummary {
                render_kind: DiffRenderKind::Structured,
            },
        ) => true,
        (
            DiffContractVersions::V2,
            DiffPayloadProjection::IntentText { .. }
            | DiffPayloadProjection::IntentSummary {
                render_kind: DiffRenderKind::Oversized,
            },
        ) => entries.iter().all(is_patch_only_file_modified_entry),
        _ => false,
    }
}

const fn is_patch_only_file_modified_entry(entry: &DiffEntrySummary) -> bool {
    matches!(entry.subject(), DiffEntrySubject::File)
        && entry.secondary_path().is_none()
        && matches!(entry.kind(), DiffChangeKind::Modified)
}

fn record_matches_begin(record: &RegisteredDiffEvidence, command: &BeginDiffEvidence) -> bool {
    record.id() == command.attribution().id()
        && record.workspace_id() == command.attribution().workspace_id()
        && record.activity_id() == command.attribution().activity_id()
        && record.change_set_id() == command.attribution().change_set_id()
        && record.origin() == command.attribution().origin()
        && record.entries() == command.entries()
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
        (
            DiffEvidenceState::Intent,
            DiffRenderKind::Binary | DiffRenderKind::Oversized | DiffRenderKind::Structured,
        ) => {
            fields.require_empty()?;
            Ok(DiffPayloadProjection::IntentSummary { render_kind })
        }
        (DiffEvidenceState::Ready, DiffRenderKind::Text) => decode_ready(fields),
        (
            DiffEvidenceState::SummaryOnly,
            DiffRenderKind::Binary | DiffRenderKind::Oversized | DiffRenderKind::Structured,
        ) => {
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
        DiffRenderKind::Structured => 3,
    }
}

const fn decode_render_kind(value: i64) -> Result<DiffRenderKind, DiffStoreError> {
    match value {
        0 => Ok(DiffRenderKind::Text),
        1 => Ok(DiffRenderKind::Binary),
        2 => Ok(DiffRenderKind::Oversized),
        3 => Ok(DiffRenderKind::Structured),
        _ => Err(DiffStoreError::CorruptRecord("diff.render_kind")),
    }
}

const fn encode_entry_subject(value: DiffEntrySubject) -> i64 {
    match value {
        DiffEntrySubject::File => 0,
        DiffEntrySubject::Directory => 1,
    }
}

const fn encode_change_kind(value: DiffChangeKind) -> i64 {
    match value {
        DiffChangeKind::Created => 0,
        DiffChangeKind::Modified => 1,
        DiffChangeKind::Deleted => 2,
        DiffChangeKind::Moved => 3,
    }
}

const fn decode_change_kind(value: i64) -> Result<DiffChangeKind, DiffStoreError> {
    match value {
        0 => Ok(DiffChangeKind::Created),
        1 => Ok(DiffChangeKind::Modified),
        2 => Ok(DiffChangeKind::Deleted),
        3 => Ok(DiffChangeKind::Moved),
        _ => Err(DiffStoreError::CorruptRecord("diff.entry.kind")),
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
        ActivityLeaseRevision, ChangeSetAttribution, ChangeSetState, DiffArtifactRelativePath,
        DiffAttribution, DiffByteCount, DiffChangeKind, DiffEntrySubject, DiffEvidenceState,
        DiffPayloadHash, DiffRenderKind, FileContentHash, RuntimeInstanceId, TimestampMillis,
        TreeChangeSetIntent, TreeChangeSetPlan, TreeMutationId, TreeMutationPlan,
        WorkspaceRelativePath, WorkspaceRevision,
    };
    use rusqlite::params;
    use uuid::Uuid;

    use super::*;

    fn artifact(value: &str) -> Result<DiffArtifactRelativePath, Box<dyn std::error::Error>> {
        Ok(DiffArtifactRelativePath::new(PathBuf::from(value))?)
    }

    fn tree_attribution(seed: u128) -> ChangeSetAttribution {
        ChangeSetAttribution::new(
            ChangeSetId::from_uuid(Uuid::from_u128(seed)),
            WorkspaceId::from_uuid(Uuid::from_u128(0x100)),
            WorkspaceRevision::INITIAL,
            ActivityId::from_uuid(Uuid::from_u128(0x200)),
            RuntimeInstanceId::from_uuid(Uuid::from_u128(seed + 1)),
            ActivityLeaseRevision::INITIAL,
        )
    }

    fn tree_plan(paths: &[&str]) -> Result<TreeChangeSetPlan, Box<dyn std::error::Error>> {
        let mutations = paths
            .iter()
            .map(|value| {
                Ok(TreeMutationPlan::update_file(
                    WorkspaceRelativePath::new(PathBuf::from(value))?,
                    FileContentHash::from_bytes([1; FileContentHash::BYTE_LEN]),
                    FileContentHash::from_bytes([2; FileContentHash::BYTE_LEN]),
                ))
            })
            .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
        Ok(TreeChangeSetPlan::new(mutations)?)
    }

    fn tree_intent(
        seed: u128,
        paths: &[&str],
    ) -> Result<TreeChangeSetIntent, Box<dyn std::error::Error>> {
        let plan = tree_plan(paths)?;
        let mutation_ids = (0..plan.mutations().len())
            .map(|offset| TreeMutationId::from_uuid(Uuid::from_u128(seed + offset as u128 + 10)))
            .collect();
        Ok(TreeChangeSetIntent::from_plan(
            tree_attribution(seed),
            mutation_ids,
            &plan,
            TimestampMillis::new(1)?,
        )?)
    }

    fn patch_intent_with_counts(
        seed: u128,
        additions: u32,
        deletions: u32,
    ) -> Result<TreeChangeSetIntent, Box<dyn std::error::Error>> {
        let plan = tree_plan(&["src/lib.rs"])?;
        let mutation_id = TreeMutationId::from_uuid(Uuid::from_u128(seed + 10));
        let entry = DiffEntrySummary::new(
            DiffEntrySubject::File,
            WorkspaceRelativePath::new(PathBuf::from("src/lib.rs"))?,
            None,
            DiffChangeKind::Modified,
            DiffLineCount::new(additions),
            DiffLineCount::new(deletions),
        )?;
        Ok(TreeChangeSetIntent::from_plan_with_diff_entries(
            tree_attribution(seed),
            vec![mutation_id],
            &plan,
            TimestampMillis::new(1)?,
            vec![entry],
        )?)
    }

    fn tree_connection(
        attribution: ChangeSetAttribution,
    ) -> Result<Connection, Box<dyn std::error::Error>> {
        let connection = doctor_connection()?;
        connection.execute(
            "INSERT INTO change_sets(
                changeset_id, workspace_id, activity_id, state,
                created_at_ms, updated_at_ms, revision
             ) VALUES (?1, ?2, ?3, 0, 1, 1, 1)",
            params![
                attribution.id().into_uuid().as_bytes(),
                attribution.workspace_id().into_uuid().as_bytes(),
                attribution.activity_id().into_uuid().as_bytes(),
            ],
        )?;
        Ok(connection)
    }

    fn mark_change_set_applied(
        connection: &Connection,
        id: ChangeSetId,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let changed = connection.execute(
            "UPDATE change_sets SET state = 1, updated_at_ms = 2, revision = 2
             WHERE changeset_id = ?1",
            params![id.into_uuid().as_bytes()],
        )?;
        if changed != 1 {
            return Err("tree ChangeSet fixture did not transition to Applied".into());
        }
        Ok(())
    }

    fn tree_command(
        intent: &TreeChangeSetIntent,
        versions: DiffContractVersions,
        payload: DiffPayloadProjection,
        entries: Vec<DiffEntrySummary>,
    ) -> Result<BeginDiffEvidence, Box<dyn std::error::Error>> {
        let attribution = intent.attribution();
        let diff_attribution = DiffAttribution::for_tree_change_set(
            DiffId::for_change_set(attribution.id()),
            attribution.workspace_id(),
            attribution.activity_id(),
            attribution.id(),
        );
        tree_command_with_attribution(
            diff_attribution,
            intent.observed_at(),
            versions,
            payload,
            entries,
        )
    }

    fn tree_command_with_attribution(
        attribution: DiffAttribution,
        observed_at: TimestampMillis,
        versions: DiffContractVersions,
        payload: DiffPayloadProjection,
        entries: Vec<DiffEntrySummary>,
    ) -> Result<BeginDiffEvidence, Box<dyn std::error::Error>> {
        Ok(BeginDiffEvidence::new(
            attribution,
            entries,
            payload,
            observed_at,
            versions,
        )?)
    }

    fn assert_tree_begin_rejected(
        connection: &mut Connection,
        intent: &TreeChangeSetIntent,
        command: &BeginDiffEvidence,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let transaction = connection.transaction()?;
        assert!(matches!(
            begin_tree(&transaction, intent, command),
            Err(DiffStoreError::AttributionMismatch)
        ));
        transaction.rollback()?;
        Ok(())
    }

    fn text_payload(diff_id: DiffId) -> Result<DiffPayloadProjection, Box<dyn std::error::Error>> {
        Ok(DiffPayloadProjection::IntentText {
            pending_relative_path: artifact(&format!("diffs/.diff-{diff_id}.pending"))?,
            final_relative_path: artifact(&format!("diffs/diff_{diff_id}.diff.zst"))?,
            compressed_hash: DiffPayloadHash::from_bytes([3; HASH_BYTES]),
            uncompressed_hash: DiffPayloadHash::from_bytes([4; HASH_BYTES]),
            compressed_size: DiffByteCount::new(3),
            uncompressed_size: DiffByteCount::new(4),
        })
    }

    fn ready_payload(diff_id: DiffId) -> Result<DiffPayloadProjection, Box<dyn std::error::Error>> {
        Ok(DiffPayloadProjection::Ready {
            relative_path: artifact(&format!("diffs/diff_{diff_id}.diff.zst"))?,
            compressed_hash: DiffPayloadHash::from_bytes([3; HASH_BYTES]),
            uncompressed_hash: DiffPayloadHash::from_bytes([4; HASH_BYTES]),
            compressed_size: DiffByteCount::new(3),
            uncompressed_size: DiffByteCount::new(4),
        })
    }

    #[test]
    fn tree_v2_text_begin_complete_and_reopen_preserves_counted_entries()
    -> Result<(), Box<dyn std::error::Error>> {
        let intent = patch_intent_with_counts(0x700, 8, 3)?;
        let attribution = intent.attribution();
        let mut connection = tree_connection(attribution)?;
        let diff_id = DiffId::for_change_set(attribution.id());
        let begin_command = tree_command(
            &intent,
            DiffContractVersions::V2,
            text_payload(diff_id)?,
            intent.diff_entries().to_vec(),
        )?;

        let transaction = connection.transaction()?;
        let started = begin_tree(&transaction, &intent, &begin_command)?;
        assert_eq!(started.state(), DiffEvidenceState::Intent);
        assert_eq!(started.entries(), intent.diff_entries());
        transaction.commit()?;

        let reopened_intent = get_by_change_set(&connection, attribution.id())?
            .ok_or("tree Diff intent was not durable")?;
        assert_eq!(reopened_intent.entries(), intent.diff_entries());
        assert_eq!(reopened_intent.renderer_version(), DiffRendererVersion::V2);
        assert_eq!(
            reopened_intent.redaction_policy_version(),
            DiffRedactionPolicyVersion::V2
        );
        assert!(matches!(
            reopened_intent.payload(),
            DiffPayloadProjection::IntentText { .. }
        ));

        let completion = CompleteDiffEvidence::new(
            diff_id,
            DiffRevision::INITIAL,
            ready_payload(diff_id)?,
            TimestampMillis::new(2)?,
        )?;
        let transaction = connection.transaction()?;
        complete(&transaction, &completion)?;
        transaction.commit()?;
        mark_change_set_applied(&connection, attribution.id())?;

        let reopened_ready = get_by_change_set(&connection, attribution.id())?
            .ok_or("completed tree Diff was not readable after reopen")?;
        assert_eq!(reopened_ready.state(), DiffEvidenceState::Ready);
        assert_eq!(reopened_ready.entries(), intent.diff_entries());
        assert!(matches!(
            reopened_ready.payload(),
            DiffPayloadProjection::Ready { .. }
        ));
        assert!(inspect_tree(&connection, &intent, &begin_command)?.is_some());
        Ok(())
    }

    #[test]
    fn tree_v1_structured_and_v2_oversized_summaries_keep_truthful_contract()
    -> Result<(), Box<dyn std::error::Error>> {
        let structured_intent = tree_intent(0x710, &["created.txt", "src/lib.rs"])?;
        let structured_attribution = structured_intent.attribution();
        let mut structured_connection = tree_connection(structured_attribution)?;
        let structured_begin = tree_command(
            &structured_intent,
            DiffContractVersions::V1,
            DiffPayloadProjection::IntentSummary {
                render_kind: DiffRenderKind::Structured,
            },
            structured_intent.diff_entries().to_vec(),
        )?;
        let transaction = structured_connection.transaction()?;
        let structured_started = begin_tree(&transaction, &structured_intent, &structured_begin)?;
        assert_eq!(structured_started.state(), DiffEvidenceState::Intent);
        assert_eq!(
            structured_started.entries(),
            structured_intent.diff_entries()
        );
        transaction.commit()?;
        let structured_completion = CompleteDiffEvidence::new(
            DiffId::for_change_set(structured_attribution.id()),
            DiffRevision::INITIAL,
            DiffPayloadProjection::SummaryOnly {
                render_kind: DiffRenderKind::Structured,
            },
            TimestampMillis::new(2)?,
        )?;
        let transaction = structured_connection.transaction()?;
        complete(&transaction, &structured_completion)?;
        transaction.commit()?;
        mark_change_set_applied(&structured_connection, structured_attribution.id())?;
        let structured = get_by_change_set(&structured_connection, structured_attribution.id())?
            .ok_or("V1 structured tree Diff was not readable")?;
        assert_eq!(structured.state(), DiffEvidenceState::SummaryOnly);
        assert_eq!(
            structured.payload().render_kind(),
            DiffRenderKind::Structured
        );

        let oversized_intent = patch_intent_with_counts(0x720, 0, 0)?;
        let oversized_attribution = oversized_intent.attribution();
        let mut oversized_connection = tree_connection(oversized_attribution)?;
        let oversized_begin = tree_command(
            &oversized_intent,
            DiffContractVersions::V2,
            DiffPayloadProjection::IntentSummary {
                render_kind: DiffRenderKind::Oversized,
            },
            oversized_intent.diff_entries().to_vec(),
        )?;
        let transaction = oversized_connection.transaction()?;
        let oversized_started = begin_tree(&transaction, &oversized_intent, &oversized_begin)?;
        assert_eq!(oversized_started.state(), DiffEvidenceState::Intent);
        assert_eq!(oversized_started.entries(), oversized_intent.diff_entries());
        transaction.commit()?;
        let oversized_completion = CompleteDiffEvidence::new(
            DiffId::for_change_set(oversized_attribution.id()),
            DiffRevision::INITIAL,
            DiffPayloadProjection::SummaryOnly {
                render_kind: DiffRenderKind::Oversized,
            },
            TimestampMillis::new(2)?,
        )?;
        let transaction = oversized_connection.transaction()?;
        complete(&transaction, &oversized_completion)?;
        transaction.commit()?;
        mark_change_set_applied(&oversized_connection, oversized_attribution.id())?;
        let oversized = get_by_change_set(&oversized_connection, oversized_attribution.id())?
            .ok_or("V2 oversized tree Diff was not readable")?;
        assert_eq!(oversized.state(), DiffEvidenceState::SummaryOnly);
        assert_eq!(oversized.payload().render_kind(), DiffRenderKind::Oversized);
        Ok(())
    }

    #[test]
    fn tree_begin_rejects_count_order_and_path_mismatch() -> Result<(), Box<dyn std::error::Error>>
    {
        let intent = tree_intent(0x730, &["src/a.rs", "src/b.rs"])?;
        let attribution = intent.attribution();

        let mut wrong_count = intent.diff_entries().to_vec();
        wrong_count[0] = DiffEntrySummary::new(
            DiffEntrySubject::File,
            WorkspaceRelativePath::new(PathBuf::from("src/a.rs"))?,
            None,
            DiffChangeKind::Modified,
            DiffLineCount::new(1),
            DiffLineCount::new(0),
        )?;
        let wrong_count_command = tree_command(
            &intent,
            DiffContractVersions::V1,
            DiffPayloadProjection::IntentSummary {
                render_kind: DiffRenderKind::Structured,
            },
            wrong_count,
        )?;
        let mut connection = tree_connection(attribution)?;
        assert_tree_begin_rejected(&mut connection, &intent, &wrong_count_command)?;

        let mut reversed = intent.diff_entries().to_vec();
        reversed.reverse();
        let reversed_command = tree_command(
            &intent,
            DiffContractVersions::V1,
            DiffPayloadProjection::IntentSummary {
                render_kind: DiffRenderKind::Structured,
            },
            reversed,
        )?;
        assert_tree_begin_rejected(&mut connection, &intent, &reversed_command)?;

        let mut wrong_path = intent.diff_entries().to_vec();
        wrong_path[0] = DiffEntrySummary::new(
            DiffEntrySubject::File,
            WorkspaceRelativePath::new(PathBuf::from("src/other.rs"))?,
            None,
            DiffChangeKind::Modified,
            DiffLineCount::new(0),
            DiffLineCount::new(0),
        )?;
        let wrong_path_command = tree_command(
            &intent,
            DiffContractVersions::V1,
            DiffPayloadProjection::IntentSummary {
                render_kind: DiffRenderKind::Structured,
            },
            wrong_path,
        )?;
        assert_tree_begin_rejected(&mut connection, &intent, &wrong_path_command)?;
        Ok(())
    }

    #[test]
    fn tree_begin_rejects_unsafe_payloads_and_mixed_text() -> Result<(), Box<dyn std::error::Error>>
    {
        let intent = tree_intent(0x735, &["src/a.rs", "src/b.rs"])?;
        let attribution = intent.attribution();
        let mut connection = tree_connection(attribution)?;
        let unsafe_payloads = [
            (
                DiffContractVersions::V1,
                DiffPayloadProjection::IntentText {
                    pending_relative_path: artifact("diffs/.diff-unsafe.pending")?,
                    final_relative_path: artifact("diffs/diff_unsafe.diff.zst")?,
                    compressed_hash: DiffPayloadHash::from_bytes([3; HASH_BYTES]),
                    uncompressed_hash: DiffPayloadHash::from_bytes([4; HASH_BYTES]),
                    compressed_size: DiffByteCount::new(3),
                    uncompressed_size: DiffByteCount::new(4),
                },
            ),
            (
                DiffContractVersions::V1,
                DiffPayloadProjection::IntentSummary {
                    render_kind: DiffRenderKind::Oversized,
                },
            ),
            (
                DiffContractVersions::V2,
                DiffPayloadProjection::IntentSummary {
                    render_kind: DiffRenderKind::Structured,
                },
            ),
            (
                DiffContractVersions::V2,
                DiffPayloadProjection::IntentSummary {
                    render_kind: DiffRenderKind::Binary,
                },
            ),
        ];
        for (versions, payload) in unsafe_payloads {
            let command = tree_command(&intent, versions, payload, intent.diff_entries().to_vec())?;
            assert_tree_begin_rejected(&mut connection, &intent, &command)?;
        }

        let mixed_plan = TreeChangeSetPlan::new(vec![
            TreeMutationPlan::create_directory(WorkspaceRelativePath::new(PathBuf::from(
                "generated",
            ))?),
            TreeMutationPlan::update_file(
                WorkspaceRelativePath::new(PathBuf::from("src/lib.rs"))?,
                FileContentHash::from_bytes([1; FileContentHash::BYTE_LEN]),
                FileContentHash::from_bytes([2; FileContentHash::BYTE_LEN]),
            ),
        ])?;
        let mixed_intent = TreeChangeSetIntent::from_plan(
            tree_attribution(0x740),
            vec![
                TreeMutationId::from_uuid(Uuid::from_u128(0x750)),
                TreeMutationId::from_uuid(Uuid::from_u128(0x751)),
            ],
            &mixed_plan,
            TimestampMillis::new(1)?,
        )?;
        let mixed_attribution = mixed_intent.attribution();
        let mut mixed_connection = tree_connection(mixed_attribution)?;
        let mixed_command = tree_command(
            &mixed_intent,
            DiffContractVersions::V2,
            text_payload(DiffId::for_change_set(mixed_attribution.id()))?,
            mixed_intent.diff_entries().to_vec(),
        )?;
        assert_tree_begin_rejected(&mut mixed_connection, &mixed_intent, &mixed_command)?;
        Ok(())
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
        crate::workspace_goal_deletion::create_schema(&connection)?;
        for (kind, name, expected) in [
            ("table", "diff_evidence", EXPECTED_DIFF_EVIDENCE_TABLE_SQL),
            ("table", "diff_entries", EXPECTED_DIFF_ENTRIES_TABLE_SQL),
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
        crate::workspace_goal_deletion::create_schema(&connection)?;
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
                diff_id, changeset_id, workspace_id, activity_id, origin_kind, mutation_id,
                state, render_kind, pending_relative_path, artifact_relative_path,
                compressed_hash, uncompressed_hash, compressed_size, uncompressed_size,
                renderer_version, redaction_policy_version, created_at_ms,
                updated_at_ms, revision
             ) VALUES (?1, ?2, ?3, ?4, 0, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
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
            "INSERT INTO diff_entries(
                diff_id, ordinal, subject_kind, primary_path, secondary_path, kind, additions, deletions
             ) VALUES (?1, 0, 0, ?2, NULL, 0, 1, 0)",
            params![
                diff_id.into_uuid().as_bytes(),
                format!("src/file-{seed}.rs").as_bytes()
            ],
        )?;
        Ok(diff_id)
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
        let report = doctor_references(&connection)?;
        assert_eq!(report.references().len(), 4);
        assert!(!report.truncated());
        let pending_reference = report
            .references()
            .iter()
            .find(|reference| reference.diff_id() == pending)
            .ok_or("pending reference missing")?;
        assert_eq!(pending_reference.state(), DiffEvidenceState::Intent);
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
        assert_eq!(summary_reference.state(), DiffEvidenceState::SummaryOnly);
        assert!(summary_reference.final_artifact().is_none());
        let purge_reference = report
            .references()
            .iter()
            .find(|reference| reference.diff_id() == purge_pending)
            .ok_or("purge reference missing")?;
        assert_eq!(purge_reference.state(), DiffEvidenceState::PurgePending);
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
