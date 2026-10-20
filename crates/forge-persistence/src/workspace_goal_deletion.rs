//! Durable permanent Goal/DAG deletion closure.
//!
//! This module deliberately stops at the `SQLite` boundary.  It stages a
//! bounded, identity-fenced cleanup manifest and journal in the caller's
//! `IMMEDIATE` transaction, removes rows in foreign-key leaf order, and lets a
//! filesystem owner prove the derived artifact outcomes through
//! [`finish_cleanup`].  No filesystem, Git, process, or network effect is
//! performed here.

use std::collections::HashSet;

use forge_domain::{
    ActivityId, AgentFocus, AgentFocusEvent, AgentFocusEventKind, AgentFocusEventSequence,
    AgentInstanceId, CheckpointId, DagHeadRevision, DiffId, ExecutionId, GoalDeletionRequest,
    GoalDeletionTarget, GoalId, GoalRevision, TimestampMillis, VerificationInputId, WorkspaceId,
    WorkspaceRootFingerprint,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use thiserror::Error;
use uuid::Uuid;

/// Hard upper bound for the complete target-owned artifact closure.
pub(crate) const MAX_GOAL_DELETION_ARTIFACTS: usize = 4_096;
const MAX_GOAL_DELETION_ARTIFACTS_I64: i64 = 4_096;
const MAX_GOAL_DELETION_PROBE: i64 = 4_097;
const ID_BYTES: usize = 16;

/// Canonical durable journal schema.  The journal intentionally has no
/// foreign key to `goals`: the goal row is removed in the same transaction.
pub(crate) const EXPECTED_GOAL_DELETION_JOURNAL_TABLE_SQL: &str = "CREATE TABLE goal_deletion_cleanup_journal (cleanup_id BLOB NOT NULL CHECK(length(cleanup_id) = 16), ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 0 AND 4095), workspace_id BLOB NOT NULL CHECK(length(workspace_id) = 16), activity_id BLOB NOT NULL CHECK(length(activity_id) = 16), goal_id BLOB NOT NULL CHECK(length(goal_id) = 16), goal_created_at_ms INTEGER NOT NULL CHECK(goal_created_at_ms >= 0), expected_goal_revision INTEGER NOT NULL CHECK(expected_goal_revision >= 1), expected_dag_head_revision INTEGER CHECK(expected_dag_head_revision IS NULL OR expected_dag_head_revision >= 1), target_kind INTEGER NOT NULL CHECK(target_kind IN (0, 1)), root_fingerprint BLOB NOT NULL CHECK(length(root_fingerprint) = 16), artifact_kind INTEGER NOT NULL CHECK(artifact_kind BETWEEN 0 AND 7), artifact_id BLOB NOT NULL CHECK(length(artifact_id) = 16), relative_path BLOB CHECK(relative_path IS NULL OR length(relative_path) BETWEEN 1 AND 4096), expected_hash BLOB CHECK(expected_hash IS NULL OR length(expected_hash) BETWEEN 1 AND 32), expected_size INTEGER CHECK(expected_size IS NULL OR expected_size >= 0), requires_filesystem INTEGER NOT NULL CHECK(requires_filesystem IN (0, 1)), created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0), PRIMARY KEY(cleanup_id, ordinal))";
pub(crate) const EXPECTED_GOAL_DELETION_JOURNAL_INDEX_SQL: &str = "CREATE INDEX goal_deletion_cleanup_identity_idx ON goal_deletion_cleanup_journal(workspace_id, activity_id, goal_id, cleanup_id)";

const JOURNAL_TABLE: &str = "goal_deletion_cleanup_journal";
const JOURNAL_INDEX: &str = "goal_deletion_cleanup_identity_idx";
const MAX_SCHEMA_SQL_BYTES: i64 = 16 * 1024;
const MAX_SCHEMA_METADATA_ROWS: usize = 64;
pub(crate) const MAX_CLEANUP_PROOFS_PER_CALL: usize = 24;

/// Filesystem or shared-object category in the bounded cleanup manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum GoalDeletionArtifactKind {
    DiffPending,
    DiffCompressed,
    VerificationInputSource,
    VerificationInputManifest,
    VerificationInputPending,
    CheckpointPre,
    CheckpointPost,
    GeneratedPackage,
}

/// Typed identity fence used before creating a new large artifact row.  A
/// pending cleanup for any physical representation of the identity blocks
/// reuse until its journal is durably cleared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum GoalDeletionArtifactIdentity {
    Diff(DiffId),
    VerificationInput(VerificationInputId),
    Checkpoint(CheckpointId),
    GeneratedPackage(ExecutionId),
}

impl GoalDeletionArtifactIdentity {
    fn id(self) -> [u8; ID_BYTES] {
        match self {
            Self::Diff(id) => id.into_uuid().into_bytes(),
            Self::VerificationInput(id) => id.into_uuid().into_bytes(),
            Self::Checkpoint(id) => id.into_uuid().into_bytes(),
            Self::GeneratedPackage(id) => id.into_uuid().into_bytes(),
        }
    }
}

impl GoalDeletionArtifactKind {
    const fn encode(self) -> i64 {
        match self {
            Self::DiffPending => 0,
            Self::DiffCompressed => 1,
            Self::VerificationInputSource => 2,
            Self::VerificationInputManifest => 3,
            Self::VerificationInputPending => 4,
            Self::CheckpointPre => 5,
            Self::CheckpointPost => 6,
            Self::GeneratedPackage => 7,
        }
    }

    fn decode(value: i64) -> Result<Self, GoalDeletionStoreError> {
        match value {
            0 => Ok(Self::DiffPending),
            1 => Ok(Self::DiffCompressed),
            2 => Ok(Self::VerificationInputSource),
            3 => Ok(Self::VerificationInputManifest),
            4 => Ok(Self::VerificationInputPending),
            5 => Ok(Self::CheckpointPre),
            6 => Ok(Self::CheckpointPost),
            7 => Ok(Self::GeneratedPackage),
            _ => Err(GoalDeletionStoreError::DamagedSchema(JOURNAL_TABLE)),
        }
    }
}

/// One server-derived artifact identity.  The caller receives metadata only;
/// it cannot supply an arbitrary path or hash to the deletion authority.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoalDeletionArtifact {
    ordinal: u16,
    kind: GoalDeletionArtifactKind,
    id: [u8; ID_BYTES],
    relative_path: Option<Vec<u8>>,
    expected_hash: Option<Vec<u8>>,
    expected_size: Option<u64>,
    requires_filesystem: bool,
}

impl GoalDeletionArtifact {
    pub const fn ordinal(&self) -> u16 {
        self.ordinal
    }

    pub const fn kind(&self) -> GoalDeletionArtifactKind {
        self.kind
    }

    pub const fn id(&self) -> &[u8; ID_BYTES] {
        &self.id
    }

    pub fn relative_path(&self) -> Option<&[u8]> {
        self.relative_path.as_deref()
    }

    pub fn expected_hash(&self) -> Option<&[u8]> {
        self.expected_hash.as_deref()
    }

    pub const fn expected_size(&self) -> Option<u64> {
        self.expected_size
    }

    pub const fn requires_filesystem(&self) -> bool {
        self.requires_filesystem
    }
}

/// Result reported by the filesystem owner for one journal ordinal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GoalDeletionArtifactStatus {
    Deleted,
    AlreadyMissing,
    Incomplete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GoalDeletionArtifactProof {
    ordinal: u16,
    status: GoalDeletionArtifactStatus,
}

impl GoalDeletionArtifactProof {
    pub const fn new(ordinal: u16, status: GoalDeletionArtifactStatus) -> Self {
        Self { ordinal, status }
    }
    pub const fn ordinal(self) -> u16 {
        self.ordinal
    }
    pub const fn status(self) -> GoalDeletionArtifactStatus {
        self.status
    }
}

/// SQLite-side result returned before external filesystem cleanup.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoalDeletionStage {
    cleanup_id: Option<Uuid>,
    target: GoalDeletionTarget,
    artifacts: Vec<GoalDeletionArtifact>,
    next_goal_revision: Option<GoalRevision>,
}

impl GoalDeletionStage {
    pub const fn cleanup_id(&self) -> Option<Uuid> {
        self.cleanup_id
    }
    pub const fn target(&self) -> GoalDeletionTarget {
        self.target
    }
    pub fn artifacts(&self) -> &[GoalDeletionArtifact] {
        &self.artifacts
    }
    pub const fn next_goal_revision(&self) -> Option<GoalRevision> {
        self.next_goal_revision
    }

    pub const fn cleanup_status(&self) -> GoalDeletionCleanupStatus {
        if self.cleanup_id.is_some() {
            GoalDeletionCleanupStatus::Pending { remaining: 0 }
        } else {
            GoalDeletionCleanupStatus::SqlOnlyComplete
        }
    }
}

/// Durable read-back of a committed cleanup journal.  This is the recovery
/// authority after an unknown post-commit filesystem outcome; callers must
/// derive effects from these server-persisted identities rather than retrying
/// an unobserved mutation from the original request.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoalDeletionCleanupReadback {
    cleanup_id: Uuid,
    request: GoalDeletionRequest,
    root_fingerprint: WorkspaceRootFingerprint,
    artifacts: Vec<GoalDeletionArtifact>,
}

/// Bounded restart/recovery metadata for one pending cleanup job. Artifact
/// payloads and paths are intentionally excluded from this projection.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoalDeletionPendingSummary {
    cleanup_id: Uuid,
    request: GoalDeletionRequest,
    remaining: u16,
}

impl GoalDeletionPendingSummary {
    pub const fn cleanup_id(&self) -> Uuid {
        self.cleanup_id
    }

    pub const fn request(&self) -> GoalDeletionRequest {
        self.request
    }

    pub const fn remaining(&self) -> u16 {
        self.remaining
    }
}

#[must_use]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GoalDeletionPendingInventory {
    summaries: Vec<GoalDeletionPendingSummary>,
    has_more: bool,
}

impl GoalDeletionPendingInventory {
    pub fn summaries(&self) -> &[GoalDeletionPendingSummary] {
        &self.summaries
    }

    pub const fn has_more(&self) -> bool {
        self.has_more
    }
}

impl GoalDeletionCleanupReadback {
    pub const fn cleanup_id(&self) -> Uuid {
        self.cleanup_id
    }

    pub const fn request(&self) -> GoalDeletionRequest {
        self.request
    }

    pub const fn root_fingerprint(&self) -> WorkspaceRootFingerprint {
        self.root_fingerprint
    }

    pub fn artifacts(&self) -> &[GoalDeletionArtifact] {
        &self.artifacts
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GoalDeletionCleanupStatus {
    SqlOnlyComplete,
    Complete,
    Pending { remaining: u16 },
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GoalDeletionCleanupOutcome {
    status: GoalDeletionCleanupStatus,
}

impl GoalDeletionCleanupOutcome {
    const fn new(status: GoalDeletionCleanupStatus) -> Self {
        Self { status }
    }
    pub const fn status(self) -> GoalDeletionCleanupStatus {
        self.status
    }
}

#[derive(Debug, Error)]
pub enum GoalDeletionStoreError {
    #[error(transparent)]
    Agent(#[from] crate::AgentStoreError),
    #[error(transparent)]
    OperationsMigration(#[from] crate::AgentOperationsMigrationError),
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Goal(#[from] crate::workspace_goals::GoalStoreError),
    #[error("Goal deletion schema object is damaged: {0}")]
    DamagedSchema(&'static str),
    #[error("Goal {goal_id} was not found")]
    GoalMissing { goal_id: GoalId },
    #[error("Goal {goal_id} Workspace identity does not match the request")]
    WorkspaceMismatch { goal_id: GoalId },
    #[error("Goal {goal_id} Activity identity does not match the request")]
    ActivityMismatch { goal_id: GoalId },
    #[error("Goal {goal_id} created_at fence does not match the request")]
    CreatedAtConflict { goal_id: GoalId },
    #[error("Goal {goal_id} revision fence does not match the request")]
    GoalRevisionConflict { goal_id: GoalId },
    #[error("Goal {goal_id} DAG head revision fence does not match the request")]
    DagHeadConflict { goal_id: GoalId },
    #[error("DAG deletion requires an explicit DAG head revision fence")]
    DagHeadFenceRequired,
    #[error("Goal {goal_id} has no current DAG head")]
    DagHeadMissing { goal_id: GoalId },
    #[error("Goal deletion cleanup journal is still pending for Goal {goal_id}")]
    CleanupJournalPending { goal_id: GoalId },
    #[error("Goal deletion artifact closure exceeds the {maximum}-artifact bound")]
    ArtifactOverflow { maximum: usize },
    #[error("Goal deletion found an unresolvable {kind} identity {id:?}")]
    UnresolvableOwnership { kind: &'static str, id: Vec<u8> },
    #[error("Goal deletion found an ownership conflict for {kind} identity {id:?}")]
    OwnershipConflict { kind: &'static str, id: Vec<u8> },
    #[error("Goal deletion found a shared Execution authority {id:?}")]
    SharedExecutionAuthorityConflict { id: Vec<u8> },
    #[error("Goal deletion found an active execution {id:?}")]
    ActiveExecution { id: Vec<u8> },
    #[error("Goal deletion found a pending approval for execution {id:?}")]
    PendingApproval { id: Vec<u8> },
    #[error("Goal deletion found an active execution grant for execution {id:?}")]
    ActiveGrant { id: Vec<u8> },
    #[error("Goal deletion found an active Writer Lease for Activity {activity_id}")]
    ActiveWriterLease { activity_id: ActivityId },
    #[error("Goal deletion found an active checkpoint restore {id:?}")]
    ActiveCheckpointRestore { id: Vec<u8> },
    #[error("Goal deletion found an active verification run {id:?}")]
    ActiveVerificationRun { id: Vec<u8> },
    #[error("Goal deletion found an unsettled Agent assignment {id:?}")]
    ActiveAgentAssignment { id: Vec<u8> },
    #[error("Goal deletion found an invalid Agent assignment projection {id:?}")]
    InvalidAgentAssignment { id: Vec<u8> },
    #[error("Goal deletion cannot bump the Goal revision")]
    GoalRevisionOverflow,
    #[error("Goal deletion cannot bump an Agent revision safely")]
    AgentRevisionOverflow,
    #[error("Goal deletion Agent {agent_id} changed while clearing focus")]
    AgentRevisionConflict { agent_id: AgentInstanceId },
    #[error("Goal deletion cleanup journal {cleanup_id} is missing")]
    CleanupJournalMissing { cleanup_id: Uuid },
    #[error("Goal deletion cleanup journal {cleanup_id} does not match the exact request fence")]
    CleanupRequestConflict { cleanup_id: Uuid },
    #[error("Goal deletion cleanup journal still owns artifact identity {kind:?} {id:?}")]
    ArtifactIdentityPending {
        kind: GoalDeletionArtifactKind,
        id: Vec<u8>,
    },
    #[error("Goal deletion cleanup proof is incomplete for ordinal {ordinal}")]
    CleanupProofMissing { ordinal: u16 },
    #[error("Goal deletion cleanup proof contains unknown ordinal {ordinal}")]
    CleanupProofUnknown { ordinal: u16 },
    #[error("Goal deletion cleanup proof contains duplicate ordinal {ordinal}")]
    CleanupProofDuplicate { ordinal: u16 },
    #[error("Goal deletion cleanup proof batch has {actual} entries; maximum is {maximum}")]
    CleanupProofBatchTooLarge { actual: usize, maximum: usize },
    #[error("Goal deletion pending cleanup limit {actual} exceeds {maximum}")]
    PendingCleanupLimitInvalid { actual: u32, maximum: u32 },
    #[error("Goal deletion cleanup evidence count is corrupt for Agent work update {id:?}")]
    AgentEvidenceCountCorrupt { id: Vec<u8> },
    #[error("Goal deletion cleanup manifest contains an invalid artifact path")]
    InvalidArtifactPath,
    #[error("Goal deletion cleanup manifest contains an invalid artifact hash")]
    InvalidArtifactHash,
    #[error("Goal deletion cleanup manifest contains an invalid artifact size")]
    InvalidArtifactSize,
}

pub(crate) fn create_schema(connection: &Connection) -> Result<(), GoalDeletionStoreError> {
    connection.execute_batch(EXPECTED_GOAL_DELETION_JOURNAL_TABLE_SQL)?;
    connection.execute_batch(EXPECTED_GOAL_DELETION_JOURNAL_INDEX_SQL)?;
    Ok(())
}

pub(crate) const fn schema_objects() -> [(&'static str, &'static str); 2] {
    [("table", JOURNAL_TABLE), ("index", JOURNAL_INDEX)]
}

pub(crate) fn validate_schema(connection: &Connection) -> Result<(), GoalDeletionStoreError> {
    for (kind, name, expected) in [
        (
            "table",
            JOURNAL_TABLE,
            EXPECTED_GOAL_DELETION_JOURNAL_TABLE_SQL,
        ),
        (
            "index",
            JOURNAL_INDEX,
            EXPECTED_GOAL_DELETION_JOURNAL_INDEX_SQL,
        ),
    ] {
        let actual = read_schema_sql(connection, kind, name)?;
        if actual.as_deref().map(normalize_sql) != Some(normalize_sql(expected)) {
            return Err(GoalDeletionStoreError::DamagedSchema(name));
        }
    }
    validate_columns(
        connection,
        JOURNAL_TABLE,
        &[
            ("cleanup_id", "BLOB", 1, 1),
            ("ordinal", "INTEGER", 1, 2),
            ("workspace_id", "BLOB", 1, 0),
            ("activity_id", "BLOB", 1, 0),
            ("goal_id", "BLOB", 1, 0),
            ("goal_created_at_ms", "INTEGER", 1, 0),
            ("expected_goal_revision", "INTEGER", 1, 0),
            ("expected_dag_head_revision", "INTEGER", 0, 0),
            ("target_kind", "INTEGER", 1, 0),
            ("root_fingerprint", "BLOB", 1, 0),
            ("artifact_kind", "INTEGER", 1, 0),
            ("artifact_id", "BLOB", 1, 0),
            ("relative_path", "BLOB", 0, 0),
            ("expected_hash", "BLOB", 0, 0),
            ("expected_size", "INTEGER", 0, 0),
            ("requires_filesystem", "INTEGER", 1, 0),
            ("created_at_ms", "INTEGER", 1, 0),
        ],
    )
}

fn normalize_sql(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn read_schema_sql(
    connection: &Connection,
    kind: &'static str,
    name: &'static str,
) -> Result<Option<String>, GoalDeletionStoreError> {
    let length: Option<i64> = connection
        .query_row(
            "SELECT length(CAST(sql AS BLOB)) FROM sqlite_schema
             WHERE type = ?1 AND name = ?2",
            params![kind, name],
            |row| row.get(0),
        )
        .optional()?;
    let Some(length) = length else {
        return Ok(None);
    };
    if !(0..=MAX_SCHEMA_SQL_BYTES).contains(&length) {
        return Err(GoalDeletionStoreError::DamagedSchema(name));
    }
    let actual: String = connection.query_row(
        "SELECT sql FROM sqlite_schema WHERE type = ?1 AND name = ?2",
        params![kind, name],
        |row| row.get(0),
    )?;
    if i64::try_from(actual.len()).ok() != Some(length) {
        return Err(GoalDeletionStoreError::DamagedSchema(name));
    }
    Ok(Some(actual))
}

fn validate_columns(
    connection: &Connection,
    table: &'static str,
    expected: &[(&str, &str, i64, i64)],
) -> Result<(), GoalDeletionStoreError> {
    let mut statement = connection.prepare(&format!("PRAGMA table_info({table})"))?;
    let mut rows = statement.query([])?;
    let mut actual = Vec::new();
    while let Some(row) = rows.next()? {
        if actual.len() >= MAX_SCHEMA_METADATA_ROWS {
            return Err(GoalDeletionStoreError::DamagedSchema(table));
        }
        actual.push((
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, i64>(5)?,
        ));
    }
    if actual.len() != expected.len()
        || !actual.iter().zip(expected).all(
            |((name, data_type, not_null, primary_key), expected)| {
                name == expected.0
                    && data_type.eq_ignore_ascii_case(expected.1)
                    && *not_null == expected.2
                    && *primary_key == expected.3
            },
        )
    {
        return Err(GoalDeletionStoreError::DamagedSchema(table));
    }
    Ok(())
}

/// Stage a permanent deletion in the caller-owned `IMMEDIATE` transaction.
///
/// The transaction is intentionally not committed by this function.  The
/// caller must commit the returned stage before invoking filesystem cleanup;
/// dropping the transaction rolls back the Goal/DAG closure and its journal.
pub(crate) fn stage_delete_in_transaction(
    transaction: &Transaction<'_>,
    request: GoalDeletionRequest,
    observed_at: TimestampMillis,
    root_fingerprint: WorkspaceRootFingerprint,
) -> Result<GoalDeletionStage, GoalDeletionStoreError> {
    let delegated = crate::workspace_agent_migration::delegation(transaction)?.is_some();
    crate::workspace_agent_migration::ensure_work_writes(transaction)?;
    let goal = validate_request(transaction, request)?;
    reject_pending_journal(transaction, request)?;
    reject_active_writer_lease(transaction, request.activity_id())?;

    let mut closure = Closure::new(request);
    load_goal_evidence(transaction, &mut closure)?;
    load_target_provenance(transaction, &mut closure)?;
    load_goal_assignments(transaction, &mut closure)?;
    load_derived_artifacts(transaction, &mut closure)?;
    reject_active_authority(transaction, &closure)?;
    load_cleanup_artifacts(transaction, &mut closure)?;
    closure.ensure_bound()?;

    create_temporary_manifest(transaction)?;
    insert_temporary_manifest(transaction, &closure.artifacts)?;
    let cleanup_id = closure
        .artifacts
        .iter()
        .any(GoalDeletionArtifact::requires_filesystem)
        .then(Uuid::now_v7);
    if let Some(cleanup_id) = cleanup_id {
        insert_journal_rows(
            transaction,
            cleanup_id,
            request,
            root_fingerprint,
            observed_at,
            &closure.artifacts,
        )?;
    }

    unlink_agent_work_evidence(transaction, &closure)?;
    clear_agent_focus(transaction, request, observed_at, delegated)?;
    if !delegated {
        redact_agent_events(transaction, request)?;
    }
    delete_execution_closure(transaction, &closure)?;
    delete_changeset_closure(transaction, &closure)?;
    delete_dag_closure(transaction, request.goal_id())?;
    delete_goal_evidence_links(transaction, &closure)?;
    let next_goal_revision = if request.target().deletes_goal() {
        delete_goal_closure(transaction, request.goal_id())?;
        None
    } else {
        let updated = goal
            .advance_after_dag_deletion(request.expected_goal_revision(), observed_at)
            .map_err(|_| GoalDeletionStoreError::GoalRevisionOverflow)?;
        let changed = transaction.execute(
            "UPDATE goals SET updated_at_ms = ?1, revision = ?2
             WHERE goal_id = ?3 AND revision = ?4",
            params![
                updated.timestamps().updated_at().get(),
                updated.revision().get(),
                request.goal_id().into_uuid().as_bytes(),
                request.expected_goal_revision().get(),
            ],
        )?;
        if changed != 1 {
            return Err(GoalDeletionStoreError::GoalRevisionConflict {
                goal_id: request.goal_id(),
            });
        }
        Some(updated.revision())
    };
    drop_temporary_manifest(transaction)?;

    Ok(GoalDeletionStage {
        cleanup_id,
        target: request.target(),
        artifacts: closure.artifacts,
        next_goal_revision,
    })
}

/// Finish the external cleanup proof.  Rows remain durable when any
/// filesystem artifact is incomplete; they are removed only after every
/// required ordinal is reported as deleted or already missing.
pub(crate) fn finish_cleanup(
    connection: &mut Connection,
    cleanup_id: Uuid,
    proofs: &[GoalDeletionArtifactProof],
) -> Result<GoalDeletionCleanupOutcome, GoalDeletionStoreError> {
    record_cleanup_progress(connection, cleanup_id, proofs)
}

/// Persist a bounded batch of filesystem cleanup proofs. Missing ordinals are
/// intentionally left pending so a caller can resume in a later Control step.
pub(crate) fn record_cleanup_progress(
    connection: &mut Connection,
    cleanup_id: Uuid,
    proofs: &[GoalDeletionArtifactProof],
) -> Result<GoalDeletionCleanupOutcome, GoalDeletionStoreError> {
    if proofs.len() > MAX_CLEANUP_PROOFS_PER_CALL {
        return Err(GoalDeletionStoreError::CleanupProofBatchTooLarge {
            actual: proofs.len(),
            maximum: MAX_CLEANUP_PROOFS_PER_CALL,
        });
    }
    let transaction =
        connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let rows = load_journal_ordinals(&transaction, cleanup_id)?;
    if rows.is_empty() {
        return Err(GoalDeletionStoreError::CleanupJournalMissing { cleanup_id });
    }
    let mut ordinals = HashSet::with_capacity(proofs.len());
    for proof in proofs {
        if !ordinals.insert(proof.ordinal()) {
            return Err(GoalDeletionStoreError::CleanupProofDuplicate {
                ordinal: proof.ordinal(),
            });
        }
        if !rows
            .iter()
            .any(|(candidate, _)| candidate == &proof.ordinal())
        {
            return Err(GoalDeletionStoreError::CleanupProofUnknown {
                ordinal: proof.ordinal(),
            });
        }
        if matches!(
            proof.status(),
            GoalDeletionArtifactStatus::Deleted | GoalDeletionArtifactStatus::AlreadyMissing
        ) {
            transaction.execute(
                "UPDATE goal_deletion_cleanup_journal
                 SET requires_filesystem = 0
                 WHERE cleanup_id = ?1 AND ordinal = ?2",
                params![cleanup_id.as_bytes(), i64::from(proof.ordinal())],
            )?;
        }
    }
    let remaining: i64 = transaction.query_row(
        "SELECT COUNT(*) FROM goal_deletion_cleanup_journal
         WHERE cleanup_id = ?1 AND requires_filesystem = 1",
        params![cleanup_id.as_bytes()],
        |row| row.get(0),
    )?;
    if remaining == 0 {
        transaction.execute(
            "DELETE FROM goal_deletion_cleanup_journal WHERE cleanup_id = ?1",
            params![cleanup_id.as_bytes()],
        )?;
        transaction.commit()?;
        return Ok(GoalDeletionCleanupOutcome::new(
            GoalDeletionCleanupStatus::Complete,
        ));
    }
    transaction.commit()?;
    Ok(GoalDeletionCleanupOutcome::new(
        GoalDeletionCleanupStatus::Pending {
            remaining: u16::try_from(remaining).unwrap_or(u16::MAX),
        },
    ))
}

/// Read one still-pending cleanup journal by its server-generated UUID.
#[allow(
    clippy::too_many_lines,
    reason = "bounded journal codec keeps identity and artifact validation atomic"
)]
pub(crate) fn load_pending_cleanup(
    connection: &Connection,
    cleanup_id: Uuid,
) -> Result<Option<GoalDeletionCleanupReadback>, GoalDeletionStoreError> {
    let mut statement = connection.prepare(
        "SELECT cleanup_id, ordinal, workspace_id, activity_id, goal_id,
                goal_created_at_ms, expected_goal_revision,
                expected_dag_head_revision, target_kind, root_fingerprint,
                artifact_kind, artifact_id, relative_path, expected_hash,
                expected_size, requires_filesystem
         FROM goal_deletion_cleanup_journal
         WHERE cleanup_id = ?1 ORDER BY ordinal ASC LIMIT ?2",
    )?;
    let rows = statement.query_map(
        params![cleanup_id.as_bytes(), MAX_GOAL_DELETION_PROBE],
        |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, Option<i64>>(7)?,
                row.get::<_, i64>(8)?,
                row.get::<_, Vec<u8>>(9)?,
                row.get::<_, i64>(10)?,
                row.get::<_, Vec<u8>>(11)?,
                row.get::<_, Option<Vec<u8>>>(12)?,
                row.get::<_, Option<Vec<u8>>>(13)?,
                row.get::<_, Option<i64>>(14)?,
                row.get::<_, i64>(15)?,
            ))
        },
    )?;
    let mut raw_rows = Vec::new();
    for row in rows {
        raw_rows.push(row?);
        if raw_rows.len() > MAX_GOAL_DELETION_ARTIFACTS {
            return Err(GoalDeletionStoreError::ArtifactOverflow {
                maximum: MAX_GOAL_DELETION_ARTIFACTS,
            });
        }
    }
    let Some(first) = raw_rows.first().cloned() else {
        return Ok(None);
    };
    let stored_cleanup_id =
        fixed_id(&first.0).ok_or(GoalDeletionStoreError::DamagedSchema(JOURNAL_TABLE))?;
    if stored_cleanup_id != *cleanup_id.as_bytes() {
        return Err(GoalDeletionStoreError::DamagedSchema(JOURNAL_TABLE));
    }
    let workspace_id =
        fixed_id(&first.2).ok_or(GoalDeletionStoreError::DamagedSchema(JOURNAL_TABLE))?;
    let activity_id =
        fixed_id(&first.3).ok_or(GoalDeletionStoreError::DamagedSchema(JOURNAL_TABLE))?;
    let goal_id = fixed_id(&first.4).ok_or(GoalDeletionStoreError::DamagedSchema(JOURNAL_TABLE))?;
    let root = fixed_id(&first.9).ok_or(GoalDeletionStoreError::DamagedSchema(JOURNAL_TABLE))?;
    let target = decode_target(first.8)?;
    let expected_goal_revision = GoalRevision::new(first.6)
        .map_err(|_| GoalDeletionStoreError::DamagedSchema(JOURNAL_TABLE))?;
    let expected_dag_head_revision = first
        .7
        .map(|value| {
            DagHeadRevision::new(value)
                .map_err(|_| GoalDeletionStoreError::DamagedSchema(JOURNAL_TABLE))
        })
        .transpose()?;
    let request = GoalDeletionRequest::new(
        target,
        WorkspaceId::from_uuid(Uuid::from_bytes(workspace_id)),
        ActivityId::from_uuid(Uuid::from_bytes(activity_id)),
        GoalId::from_uuid(Uuid::from_bytes(goal_id)),
        TimestampMillis::new(first.5)
            .map_err(|_| GoalDeletionStoreError::DamagedSchema(JOURNAL_TABLE))?,
        expected_goal_revision,
        expected_dag_head_revision,
    );
    let mut artifacts = Vec::with_capacity(raw_rows.len());
    for row in raw_rows {
        let row_cleanup_id =
            fixed_id(&row.0).ok_or(GoalDeletionStoreError::DamagedSchema(JOURNAL_TABLE))?;
        if row_cleanup_id != stored_cleanup_id
            || row.2 != workspace_id.to_vec()
            || row.3 != activity_id.to_vec()
            || row.4 != goal_id.to_vec()
            || row.9 != root.to_vec()
            || row.5 != first.5
            || row.6 != first.6
            || row.7 != first.7
            || row.8 != first.8
        {
            return Err(GoalDeletionStoreError::DamagedSchema(JOURNAL_TABLE));
        }
        let artifact_id =
            fixed_id(&row.11).ok_or(GoalDeletionStoreError::DamagedSchema(JOURNAL_TABLE))?;
        let kind = GoalDeletionArtifactKind::decode(row.10)?;
        if row
            .12
            .as_ref()
            .is_some_and(|path| path.is_empty() || path.len() > 4_096)
            || row
                .13
                .as_ref()
                .is_some_and(|hash| hash.is_empty() || hash.len() > 32)
        {
            return Err(GoalDeletionStoreError::DamagedSchema(JOURNAL_TABLE));
        }
        let expected_size = row
            .14
            .map(|value| {
                u64::try_from(value)
                    .map_err(|_| GoalDeletionStoreError::DamagedSchema(JOURNAL_TABLE))
            })
            .transpose()?;
        if !matches!(row.15, 0 | 1) {
            return Err(GoalDeletionStoreError::DamagedSchema(JOURNAL_TABLE));
        }
        artifacts.push(GoalDeletionArtifact {
            ordinal: u16::try_from(row.1)
                .map_err(|_| GoalDeletionStoreError::DamagedSchema(JOURNAL_TABLE))?,
            kind,
            id: artifact_id,
            relative_path: row.12,
            expected_hash: row.13,
            expected_size,
            requires_filesystem: row.15 == 1,
        });
    }
    Ok(Some(GoalDeletionCleanupReadback {
        cleanup_id,
        request,
        root_fingerprint: WorkspaceRootFingerprint::from_bytes(root),
        artifacts,
    }))
}

/// Resolve the pending cleanup for an exact Goal identity fence.
pub(crate) fn load_pending_cleanup_for_request(
    connection: &Connection,
    request: GoalDeletionRequest,
) -> Result<Option<GoalDeletionCleanupReadback>, GoalDeletionStoreError> {
    let mut statement = connection.prepare(
        "SELECT DISTINCT cleanup_id FROM goal_deletion_cleanup_journal
         WHERE workspace_id = ?1 AND activity_id = ?2 AND goal_id = ?3
         ORDER BY cleanup_id ASC LIMIT 2",
    )?;
    let ids = statement
        .query_map(
            params![
                request.workspace_id().into_uuid().as_bytes(),
                request.activity_id().into_uuid().as_bytes(),
                request.goal_id().into_uuid().as_bytes(),
            ],
            |row| row.get::<_, Vec<u8>>(0),
        )?
        .collect::<Result<Vec<_>, _>>()?;
    if ids.len() > 1 {
        return Err(GoalDeletionStoreError::DamagedSchema(JOURNAL_TABLE));
    }
    let Some(id) = ids.first() else {
        return Ok(None);
    };
    let cleanup_id =
        Uuid::from_slice(id).map_err(|_| GoalDeletionStoreError::DamagedSchema(JOURNAL_TABLE))?;
    let readback = load_pending_cleanup(connection, cleanup_id)?;
    let Some(readback) = readback else {
        return Err(GoalDeletionStoreError::CleanupJournalMissing { cleanup_id });
    };
    if readback.request() != request {
        return Err(GoalDeletionStoreError::CleanupRequestConflict { cleanup_id });
    }
    Ok(Some(readback))
}

/// List pending cleanup jobs by Workspace for restart/recovery discovery.
/// This reads one grouped header/count row per cleanup and probes one extra
/// row to produce a bounded `has_more` signal.
pub(crate) fn list_pending_cleanup(
    connection: &Connection,
    workspace_id: WorkspaceId,
    limit: u32,
) -> Result<GoalDeletionPendingInventory, GoalDeletionStoreError> {
    const MAX_LIMIT: u32 = 32;
    if limit == 0 || limit > MAX_LIMIT {
        return Err(GoalDeletionStoreError::PendingCleanupLimitInvalid {
            actual: limit,
            maximum: MAX_LIMIT,
        });
    }
    let probe_limit = i64::from(limit) + 1;
    let mut statement = connection.prepare(
        "SELECT cleanup_id, activity_id, goal_id, goal_created_at_ms,
                expected_goal_revision, expected_dag_head_revision, target_kind,
                root_fingerprint, SUM(requires_filesystem)
         FROM goal_deletion_cleanup_journal
         WHERE workspace_id = ?1
         GROUP BY cleanup_id, activity_id, goal_id, goal_created_at_ms,
                  expected_goal_revision, expected_dag_head_revision,
                  target_kind, root_fingerprint
         ORDER BY cleanup_id ASC LIMIT ?2",
    )?;
    let rows = statement.query_map(
        params![workspace_id.into_uuid().as_bytes(), probe_limit],
        |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, Option<i64>>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, Vec<u8>>(7)?,
                row.get::<_, i64>(8)?,
            ))
        },
    )?;
    let mut summaries = Vec::new();
    let mut cleanup_ids = HashSet::new();
    let limit_usize = usize::try_from(limit).unwrap_or(usize::MAX);
    for row in rows {
        if summaries.len() >= limit_usize {
            return Ok(GoalDeletionPendingInventory {
                summaries,
                has_more: true,
            });
        }
        let (
            cleanup_bytes,
            activity_bytes,
            goal_bytes,
            created_at,
            goal_revision,
            dag_head_revision,
            target_kind,
            root_bytes,
            remaining,
        ) = row?;
        let cleanup_id = Uuid::from_slice(&cleanup_bytes)
            .map_err(|_| GoalDeletionStoreError::DamagedSchema(JOURNAL_TABLE))?;
        if !cleanup_ids.insert(cleanup_id) {
            return Err(GoalDeletionStoreError::DamagedSchema(JOURNAL_TABLE));
        }
        let activity_id = ActivityId::from_uuid(
            Uuid::from_slice(&activity_bytes)
                .map_err(|_| GoalDeletionStoreError::DamagedSchema(JOURNAL_TABLE))?,
        );
        let goal_id = GoalId::from_uuid(
            Uuid::from_slice(&goal_bytes)
                .map_err(|_| GoalDeletionStoreError::DamagedSchema(JOURNAL_TABLE))?,
        );
        let root =
            fixed_id(&root_bytes).ok_or(GoalDeletionStoreError::DamagedSchema(JOURNAL_TABLE))?;
        let request = GoalDeletionRequest::new(
            decode_target(target_kind)?,
            workspace_id,
            activity_id,
            goal_id,
            TimestampMillis::new(created_at)
                .map_err(|_| GoalDeletionStoreError::DamagedSchema(JOURNAL_TABLE))?,
            GoalRevision::new(goal_revision)
                .map_err(|_| GoalDeletionStoreError::DamagedSchema(JOURNAL_TABLE))?,
            dag_head_revision
                .map(|value| {
                    DagHeadRevision::new(value)
                        .map_err(|_| GoalDeletionStoreError::DamagedSchema(JOURNAL_TABLE))
                })
                .transpose()?,
        );
        let remaining = u16::try_from(remaining)
            .map_err(|_| GoalDeletionStoreError::DamagedSchema(JOURNAL_TABLE))?;
        let _root_fingerprint = WorkspaceRootFingerprint::from_bytes(root);
        summaries.push(GoalDeletionPendingSummary {
            cleanup_id,
            request,
            remaining,
        });
    }
    Ok(GoalDeletionPendingInventory {
        summaries,
        has_more: false,
    })
}

/// Check whether any filesystem cleanup for a Goal UUID is still pending.
/// Goal creation calls this from its common insert transaction only after
/// checking for an exact live-row replay.
pub(crate) fn has_pending_goal_cleanup(
    connection: &Connection,
    goal_id: GoalId,
) -> Result<bool, rusqlite::Error> {
    connection.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM goal_deletion_cleanup_journal WHERE goal_id = ?1
         )",
        params![goal_id.into_uuid().as_bytes()],
        |row| row.get(0),
    )
}

/// Admission probe used inside artifact-creation transactions. Storage errors
/// propagate as storage errors; only a positive row is an identity conflict.
pub(crate) fn artifact_identity_is_pending(
    connection: &Connection,
    identity: GoalDeletionArtifactIdentity,
) -> rusqlite::Result<bool> {
    let (_, sql) = artifact_identity_query(identity);
    let id = identity.id();
    connection.query_row(sql, params![id.as_slice()], |row| row.get(0))
}

fn artifact_identity_query(
    identity: GoalDeletionArtifactIdentity,
) -> (GoalDeletionArtifactKind, &'static str) {
    let (kind, sql) = match identity {
        GoalDeletionArtifactIdentity::Diff(_) => (
            GoalDeletionArtifactKind::DiffCompressed,
            "SELECT EXISTS(
                 SELECT 1 FROM goal_deletion_cleanup_journal
                 WHERE artifact_kind IN (0, 1) AND artifact_id = ?1
             )",
        ),
        GoalDeletionArtifactIdentity::VerificationInput(_) => (
            GoalDeletionArtifactKind::VerificationInputSource,
            "SELECT EXISTS(
                 SELECT 1 FROM goal_deletion_cleanup_journal
                 WHERE artifact_kind IN (2, 3, 4) AND artifact_id = ?1
             )",
        ),
        GoalDeletionArtifactIdentity::Checkpoint(_) => (
            GoalDeletionArtifactKind::CheckpointPre,
            "SELECT EXISTS(
                 SELECT 1 FROM goal_deletion_cleanup_journal
                 WHERE artifact_kind IN (5, 6) AND artifact_id = ?1
             )",
        ),
        GoalDeletionArtifactIdentity::GeneratedPackage(_) => (
            GoalDeletionArtifactKind::GeneratedPackage,
            "SELECT EXISTS(
                 SELECT 1 FROM goal_deletion_cleanup_journal
                 WHERE artifact_kind = 7 AND artifact_id = ?1
             )",
        ),
    };
    (kind, sql)
}

fn load_journal_ordinals(
    transaction: &Transaction<'_>,
    cleanup_id: Uuid,
) -> Result<Vec<(u16, i64)>, GoalDeletionStoreError> {
    let mut statement = transaction.prepare(
        "SELECT ordinal, requires_filesystem FROM goal_deletion_cleanup_journal
         WHERE cleanup_id = ?1 ORDER BY ordinal ASC LIMIT ?2",
    )?;
    let rows = statement.query_map(
        params![cleanup_id.as_bytes(), MAX_GOAL_DELETION_PROBE],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
    )?;
    let mut result = Vec::new();
    for row in rows {
        if result.len() >= MAX_GOAL_DELETION_ARTIFACTS {
            return Err(GoalDeletionStoreError::ArtifactOverflow {
                maximum: MAX_GOAL_DELETION_ARTIFACTS,
            });
        }
        let (ordinal, required) = row?;
        result.push((
            u16::try_from(ordinal)
                .map_err(|_| GoalDeletionStoreError::DamagedSchema(JOURNAL_TABLE))?,
            required,
        ));
    }
    Ok(result)
}

#[derive(Debug)]
struct GoalRow {
    workspace_id: Vec<u8>,
    activity_id: Vec<u8>,
    created_at_ms: i64,
    revision: i64,
}

#[derive(Debug)]
struct Closure {
    request: GoalDeletionRequest,
    evidence: Vec<EvidenceRow>,
    owned_evidence: HashSet<(i64, Vec<u8>)>,
    executions: HashSet<Vec<u8>>,
    shared_executions: HashSet<Vec<u8>>,
    changesets: HashSet<Vec<u8>>,
    shared_changesets: HashSet<Vec<u8>>,
    diffs: HashSet<Vec<u8>>,
    shared_diffs: HashSet<Vec<u8>>,
    checkpoints: HashSet<Vec<u8>>,
    shared_checkpoints: HashSet<Vec<u8>>,
    verification_runs: HashSet<Vec<u8>>,
    verification_inputs: HashSet<Vec<u8>>,
    shared_verification_inputs: HashSet<Vec<u8>>,
    artifacts: Vec<GoalDeletionArtifact>,
    artifact_keys: HashSet<ArtifactKey>,
}

impl Closure {
    fn new(request: GoalDeletionRequest) -> Self {
        Self {
            request,
            evidence: Vec::new(),
            owned_evidence: HashSet::new(),
            executions: HashSet::new(),
            shared_executions: HashSet::new(),
            changesets: HashSet::new(),
            shared_changesets: HashSet::new(),
            diffs: HashSet::new(),
            shared_diffs: HashSet::new(),
            checkpoints: HashSet::new(),
            shared_checkpoints: HashSet::new(),
            verification_runs: HashSet::new(),
            verification_inputs: HashSet::new(),
            shared_verification_inputs: HashSet::new(),
            artifacts: Vec::new(),
            artifact_keys: HashSet::new(),
        }
    }

    fn ensure_bound(&self) -> Result<(), GoalDeletionStoreError> {
        if self.artifacts.len() > MAX_GOAL_DELETION_ARTIFACTS {
            Err(GoalDeletionStoreError::ArtifactOverflow {
                maximum: MAX_GOAL_DELETION_ARTIFACTS,
            })
        } else {
            Ok(())
        }
    }

    fn add_artifact(
        &mut self,
        kind: GoalDeletionArtifactKind,
        id: &[u8],
        relative_path: Option<Vec<u8>>,
        expected_hash: Option<Vec<u8>>,
        expected_size: Option<i64>,
        requires_filesystem: bool,
    ) -> Result<(), GoalDeletionStoreError> {
        let id = fixed_id(id).ok_or(GoalDeletionStoreError::UnresolvableOwnership {
            kind: "artifact",
            id: id.to_vec(),
        })?;
        if let Some(path) = &relative_path
            && (path.is_empty() || path.len() > 4_096)
        {
            return Err(GoalDeletionStoreError::InvalidArtifactPath);
        }
        if let Some(hash) = &expected_hash
            && (hash.is_empty() || hash.len() > 32)
        {
            return Err(GoalDeletionStoreError::InvalidArtifactHash);
        }
        let expected_size = expected_size
            .map(|value| {
                u64::try_from(value).map_err(|_| GoalDeletionStoreError::InvalidArtifactSize)
            })
            .transpose()?;
        let key = ArtifactKey {
            kind,
            id,
            relative_path: relative_path.clone(),
        };
        if !self.artifact_keys.insert(key) {
            return Ok(());
        }
        let ordinal = u16::try_from(self.artifacts.len()).map_err(|_| {
            GoalDeletionStoreError::ArtifactOverflow {
                maximum: MAX_GOAL_DELETION_ARTIFACTS,
            }
        })?;
        self.artifacts.push(GoalDeletionArtifact {
            ordinal,
            kind,
            id,
            relative_path,
            expected_hash,
            expected_size,
            requires_filesystem,
        });
        self.ensure_bound()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ArtifactKey {
    kind: GoalDeletionArtifactKind,
    id: [u8; ID_BYTES],
    relative_path: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
struct EvidenceRow {
    kind: i64,
    id: Vec<u8>,
    shared: bool,
}

fn validate_request(
    transaction: &Transaction<'_>,
    request: GoalDeletionRequest,
) -> Result<forge_domain::RegisteredGoal, GoalDeletionStoreError> {
    let raw = transaction
        .query_row(
            "SELECT workspace_id, activity_id, created_at_ms, revision
             FROM goals WHERE goal_id = ?1",
            params![request.goal_id().into_uuid().as_bytes()],
            |row| {
                Ok(GoalRow {
                    workspace_id: row.get(0)?,
                    activity_id: row.get(1)?,
                    created_at_ms: row.get(2)?,
                    revision: row.get(3)?,
                })
            },
        )
        .optional()?
        .ok_or(GoalDeletionStoreError::GoalMissing {
            goal_id: request.goal_id(),
        })?;
    if raw.workspace_id != request.workspace_id().into_uuid().as_bytes() {
        return Err(GoalDeletionStoreError::WorkspaceMismatch {
            goal_id: request.goal_id(),
        });
    }
    if raw.activity_id != request.activity_id().into_uuid().as_bytes() {
        return Err(GoalDeletionStoreError::ActivityMismatch {
            goal_id: request.goal_id(),
        });
    }
    if raw.created_at_ms != request.goal_created_at().get() {
        return Err(GoalDeletionStoreError::CreatedAtConflict {
            goal_id: request.goal_id(),
        });
    }
    if raw.revision != request.expected_goal_revision().get() {
        return Err(GoalDeletionStoreError::GoalRevisionConflict {
            goal_id: request.goal_id(),
        });
    }
    let head = transaction
        .query_row(
            "SELECT dag_revision, head_revision FROM goal_dag_heads WHERE goal_id = ?1",
            params![request.goal_id().into_uuid().as_bytes()],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()?;
    match (head, request.expected_dag_head_revision()) {
        (Some((_, actual)), Some(expected)) if actual == expected.get() => {}
        (Some(_), None) => return Err(GoalDeletionStoreError::DagHeadFenceRequired),
        (_, Some(_)) => {
            return Err(GoalDeletionStoreError::DagHeadConflict {
                goal_id: request.goal_id(),
            });
        }
        (None, None) => {}
    }
    crate::workspace_goals::get_goal(transaction, request.goal_id())?.ok_or(
        GoalDeletionStoreError::GoalMissing {
            goal_id: request.goal_id(),
        },
    )
}

fn reject_pending_journal(
    transaction: &Transaction<'_>,
    request: GoalDeletionRequest,
) -> Result<(), GoalDeletionStoreError> {
    let pending: bool = transaction.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM goal_deletion_cleanup_journal WHERE goal_id = ?1
        )",
        params![request.goal_id().into_uuid().as_bytes()],
        |row| row.get(0),
    )?;
    if pending {
        Err(GoalDeletionStoreError::CleanupJournalPending {
            goal_id: request.goal_id(),
        })
    } else {
        Ok(())
    }
}

fn reject_active_writer_lease(
    transaction: &Transaction<'_>,
    activity_id: ActivityId,
) -> Result<(), GoalDeletionStoreError> {
    let active: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM writer_leases WHERE activity_id = ?1 AND state = 0)",
        params![activity_id.into_uuid().as_bytes()],
        |row| row.get(0),
    )?;
    if active {
        Err(GoalDeletionStoreError::ActiveWriterLease { activity_id })
    } else {
        Ok(())
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "bounded evidence projection keeps Goal and DAG ownership selection together"
)]
fn load_goal_evidence(
    transaction: &Transaction<'_>,
    closure: &mut Closure,
) -> Result<(), GoalDeletionStoreError> {
    if closure.request.target() == GoalDeletionTarget::Dag {
        let orphan: bool = transaction.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM goal_dag_node_evidence_refs AS n
                 LEFT JOIN goal_evidence_refs AS e
                   ON e.goal_id = n.goal_id
                  AND e.evidence_kind = n.evidence_kind
                  AND e.evidence_id = n.evidence_id
                 WHERE n.goal_id = ?1 AND e.goal_id IS NULL
             )",
            params![closure.request.goal_id().into_uuid().as_bytes()],
            |row| row.get(0),
        )?;
        if orphan {
            return Err(GoalDeletionStoreError::UnresolvableOwnership {
                kind: "DAG evidence link",
                id: closure.request.goal_id().into_uuid().as_bytes().to_vec(),
            });
        }
    }
    let evidence_query = if closure.request.target() == GoalDeletionTarget::Dag {
        "SELECT DISTINCT e.evidence_kind, e.evidence_id
         FROM goal_dag_node_evidence_refs AS n
         JOIN goal_evidence_refs AS e
           ON e.goal_id = n.goal_id
          AND e.evidence_kind = n.evidence_kind
          AND e.evidence_id = n.evidence_id
         WHERE n.goal_id = ?1
         ORDER BY e.evidence_kind ASC, e.evidence_id ASC LIMIT ?2"
    } else {
        "SELECT evidence_kind, evidence_id
         FROM goal_evidence_refs WHERE goal_id = ?1
         ORDER BY evidence_kind ASC, evidence_id ASC LIMIT ?2"
    };
    let mut statement = transaction.prepare(evidence_query)?;
    let rows = statement.query_map(
        params![
            closure.request.goal_id().into_uuid().as_bytes(),
            MAX_GOAL_DELETION_PROBE,
        ],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
    )?;
    for row in rows {
        if closure.evidence.len() >= MAX_GOAL_DELETION_ARTIFACTS {
            return Err(GoalDeletionStoreError::ArtifactOverflow {
                maximum: MAX_GOAL_DELETION_ARTIFACTS,
            });
        }
        let (kind, id) = row?;
        if !(0..=3).contains(&kind) || fixed_id(&id).is_none() {
            return Err(GoalDeletionStoreError::UnresolvableOwnership {
                kind: "goal evidence",
                id,
            });
        }
        let shared: bool = transaction.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM goal_evidence_refs
                WHERE evidence_kind = ?1 AND evidence_id = ?2 AND goal_id != ?3
            )",
            params![
                kind,
                id.as_slice(),
                closure.request.goal_id().into_uuid().as_bytes()
            ],
            |row| row.get(0),
        )?;
        let evidence = EvidenceRow {
            kind,
            id: id.clone(),
            shared,
        };
        if !shared {
            closure.owned_evidence.insert((kind, id.clone()));
        }
        closure.evidence.push(evidence.clone());
        resolve_direct_evidence(transaction, closure, &evidence)?;
    }
    let count: i64 = if closure.request.target() == GoalDeletionTarget::Dag {
        transaction.query_row(
            "SELECT COUNT(DISTINCT e.evidence_kind || ':' || hex(e.evidence_id))
             FROM goal_dag_node_evidence_refs AS n
             JOIN goal_evidence_refs AS e
               ON e.goal_id = n.goal_id
              AND e.evidence_kind = n.evidence_kind
              AND e.evidence_id = n.evidence_id
             WHERE n.goal_id = ?1",
            params![closure.request.goal_id().into_uuid().as_bytes()],
            |row| row.get(0),
        )?
    } else {
        transaction.query_row(
            "SELECT COUNT(*) FROM goal_evidence_refs WHERE goal_id = ?1",
            params![closure.request.goal_id().into_uuid().as_bytes()],
            |row| row.get(0),
        )?
    };
    if count > MAX_GOAL_DELETION_ARTIFACTS_I64 {
        return Err(GoalDeletionStoreError::ArtifactOverflow {
            maximum: MAX_GOAL_DELETION_ARTIFACTS,
        });
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "four typed evidence kinds share one bounded ownership fence"
)]
fn resolve_direct_evidence(
    transaction: &Transaction<'_>,
    closure: &mut Closure,
    evidence: &EvidenceRow,
) -> Result<(), GoalDeletionStoreError> {
    match evidence.kind {
        0 => {
            let row = transaction
                .query_row(
                    "SELECT workspace_id, activity_id FROM change_sets WHERE changeset_id = ?1",
                    params![evidence.id.as_slice()],
                    |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
                )
                .optional()?
                .ok_or_else(|| GoalDeletionStoreError::UnresolvableOwnership {
                    kind: "ChangeSet",
                    id: evidence.id.clone(),
                })?;
            validate_workspace_activity(closure, &row.0, &row.1, "ChangeSet", &evidence.id)?;
            if !evidence.shared {
                closure.changesets.insert(evidence.id.clone());
                if has_other_evidence(transaction, 0, &evidence.id, closure.request.goal_id())? {
                    closure.shared_changesets.insert(evidence.id.clone());
                }
            }
        }
        1 => {
            let shared = evidence.shared
                || execution_has_other_goal_links(
                    transaction,
                    &evidence.id,
                    closure.request.goal_id(),
                )?;
            resolve_execution(transaction, closure, &evidence.id, shared)?;
        }
        2 => {
            let execution_id = transaction
                .query_row(
                    "SELECT workspace_id, activity_id, execution_id
                     FROM approval_requests WHERE approval_id = ?1",
                    params![evidence.id.as_slice()],
                    |row| {
                        Ok((
                            row.get::<_, Vec<u8>>(0)?,
                            row.get::<_, Vec<u8>>(1)?,
                            row.get::<_, Vec<u8>>(2)?,
                        ))
                    },
                )
                .optional()?
                .ok_or_else(|| GoalDeletionStoreError::UnresolvableOwnership {
                    kind: "Approval",
                    id: evidence.id.clone(),
                })?;
            validate_workspace_activity(
                closure,
                &execution_id.0,
                &execution_id.1,
                "Approval",
                &evidence.id,
            )?;
            if !evidence.shared {
                closure.owned_evidence.insert((2, evidence.id.clone()));
            }
            let execution_shared = execution_has_other_goal_links(
                transaction,
                &execution_id.2,
                closure.request.goal_id(),
            )?;
            resolve_execution(transaction, closure, &execution_id.2, execution_shared)?;
        }
        3 => {
            let row = transaction
                .query_row(
                    "SELECT workspace_id, activity_id, changeset_id, pre_commit,
                            post_commit, state
                     FROM checkpoints WHERE checkpoint_id = ?1",
                    params![evidence.id.as_slice()],
                    |row| {
                        Ok((
                            row.get::<_, Vec<u8>>(0)?,
                            row.get::<_, Vec<u8>>(1)?,
                            row.get::<_, Vec<u8>>(2)?,
                            row.get::<_, Vec<u8>>(3)?,
                            row.get::<_, Option<Vec<u8>>>(4)?,
                            row.get::<_, i64>(5)?,
                        ))
                    },
                )
                .optional()?
                .ok_or_else(|| GoalDeletionStoreError::UnresolvableOwnership {
                    kind: "Checkpoint",
                    id: evidence.id.clone(),
                })?;
            validate_workspace_activity(closure, &row.0, &row.1, "Checkpoint", &evidence.id)?;
            if !evidence.shared {
                closure.owned_evidence.insert((3, evidence.id.clone()));
                closure.checkpoints.insert(evidence.id.clone());
                closure.add_artifact(
                    GoalDeletionArtifactKind::CheckpointPre,
                    &evidence.id,
                    None,
                    Some(row.3),
                    None,
                    false,
                )?;
                if let Some(post) = row.4 {
                    closure.add_artifact(
                        GoalDeletionArtifactKind::CheckpointPost,
                        &evidence.id,
                        None,
                        Some(post),
                        None,
                        false,
                    )?;
                }
                if has_other_evidence(transaction, 0, &row.2, closure.request.goal_id())? {
                    closure.shared_changesets.insert(row.2);
                } else {
                    closure.changesets.insert(row.2);
                }
            }
        }
        _ => unreachable!("goal evidence kind was range checked"),
    }
    Ok(())
}

fn validate_workspace_activity(
    closure: &Closure,
    workspace: &[u8],
    activity: &[u8],
    kind: &'static str,
    id: &[u8],
) -> Result<(), GoalDeletionStoreError> {
    if workspace != closure.request.workspace_id().into_uuid().as_bytes() {
        return Err(GoalDeletionStoreError::OwnershipConflict {
            kind,
            id: id.to_vec(),
        });
    }
    if activity != closure.request.activity_id().into_uuid().as_bytes() {
        return Err(GoalDeletionStoreError::OwnershipConflict {
            kind,
            id: id.to_vec(),
        });
    }
    Ok(())
}

fn has_other_evidence(
    transaction: &Transaction<'_>,
    kind: i64,
    id: &[u8],
    goal_id: GoalId,
) -> Result<bool, GoalDeletionStoreError> {
    transaction
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM goal_evidence_refs
                WHERE evidence_kind = ?1 AND evidence_id = ?2 AND goal_id != ?3
            )",
            params![kind, id, goal_id.into_uuid().as_bytes()],
            |row| row.get(0),
        )
        .map_err(GoalDeletionStoreError::from)
}

fn execution_has_other_goal_links(
    transaction: &Transaction<'_>,
    execution_id: &[u8],
    goal_id: GoalId,
) -> Result<bool, GoalDeletionStoreError> {
    transaction
        .query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM goal_evidence_refs
                 WHERE evidence_kind = 1 AND evidence_id = ?1 AND goal_id != ?2
             ) OR EXISTS(
                 SELECT 1 FROM verification_requirement_links
                 WHERE execution_id = ?1 AND goal_id != ?2
             )",
            params![execution_id, goal_id.into_uuid().as_bytes()],
            |row| row.get(0),
        )
        .map_err(GoalDeletionStoreError::from)
}

fn resolve_execution(
    transaction: &Transaction<'_>,
    closure: &mut Closure,
    execution_id: &[u8],
    shared: bool,
) -> Result<(), GoalDeletionStoreError> {
    let row = transaction
        .query_row(
            "SELECT e.workspace_id, e.activity_id, p.goal_id
             FROM executions AS e
             LEFT JOIN execution_provenance AS p ON p.execution_id = e.execution_id
             WHERE e.execution_id = ?1",
            params![execution_id],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Option<Vec<u8>>>(2)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| GoalDeletionStoreError::UnresolvableOwnership {
            kind: "Execution",
            id: execution_id.to_vec(),
        })?;
    validate_workspace_activity(closure, &row.0, &row.1, "Execution", execution_id)?;
    if row.2.as_deref() != Some(closure.request.goal_id().into_uuid().as_bytes()) {
        return Err(GoalDeletionStoreError::OwnershipConflict {
            kind: "Execution provenance",
            id: execution_id.to_vec(),
        });
    }
    fixed_id(execution_id).ok_or_else(|| GoalDeletionStoreError::UnresolvableOwnership {
        kind: "Execution",
        id: execution_id.to_vec(),
    })?;
    if shared {
        closure.shared_executions.insert(execution_id.to_vec());
    } else {
        closure.executions.insert(execution_id.to_vec());
        closure.owned_evidence.insert((1, execution_id.to_vec()));
    }
    Ok(())
}

fn load_target_provenance(
    transaction: &Transaction<'_>,
    closure: &mut Closure,
) -> Result<(), GoalDeletionStoreError> {
    let mut statement = transaction.prepare(
        "SELECT p.execution_id, e.workspace_id, e.activity_id
         FROM execution_provenance AS p
         JOIN executions AS e ON e.execution_id = p.execution_id
         WHERE p.goal_id = ?1 ORDER BY p.execution_id ASC LIMIT ?2",
    )?;
    let rows = statement.query_map(
        params![
            closure.request.goal_id().into_uuid().as_bytes(),
            MAX_GOAL_DELETION_PROBE,
        ],
        |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        },
    )?;
    let mut count = 0_usize;
    for row in rows {
        count = count.saturating_add(1);
        if count > MAX_GOAL_DELETION_ARTIFACTS {
            return Err(GoalDeletionStoreError::ArtifactOverflow {
                maximum: MAX_GOAL_DELETION_ARTIFACTS,
            });
        }
        let (execution_id, workspace, activity) = row?;
        validate_workspace_activity(closure, &workspace, &activity, "Execution", &execution_id)?;
        if execution_has_other_goal_links(transaction, &execution_id, closure.request.goal_id())? {
            closure.shared_executions.insert(execution_id);
        } else {
            closure.executions.insert(execution_id.clone());
            closure.owned_evidence.insert((1, execution_id));
        }
    }
    Ok(())
}

/// Agent assignments are Goal/DAG-owned history. Only Running assignments are
/// active effect authority; Submitted and terminal rows are removable history.
fn load_goal_assignments(
    transaction: &Transaction<'_>,
    closure: &mut Closure,
) -> Result<(), GoalDeletionStoreError> {
    let mut statement = transaction.prepare(
        "SELECT assignment_id, workspace_id, activity_id, goal_created_at_ms,
                state, cancellation_requested
         FROM agent_assignments
         WHERE goal_id = ?1 ORDER BY assignment_id ASC LIMIT ?2",
    )?;
    let rows = statement.query_map(
        params![
            closure.request.goal_id().into_uuid().as_bytes(),
            MAX_GOAL_DELETION_PROBE,
        ],
        |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
            ))
        },
    )?;
    let mut count = 0_usize;
    for row in rows {
        count = count.saturating_add(1);
        if count > MAX_GOAL_DELETION_ARTIFACTS {
            return Err(GoalDeletionStoreError::ArtifactOverflow {
                maximum: MAX_GOAL_DELETION_ARTIFACTS,
            });
        }
        let (assignment_id, workspace_id, activity_id, goal_created_at, state, cancellation) = row?;
        if fixed_id(&assignment_id).is_none() {
            return Err(GoalDeletionStoreError::UnresolvableOwnership {
                kind: "AgentAssignment",
                id: assignment_id,
            });
        }
        validate_workspace_activity(
            closure,
            &workspace_id,
            &activity_id,
            "AgentAssignment",
            &assignment_id,
        )?;
        if goal_created_at != closure.request.goal_created_at().get() {
            return Err(GoalDeletionStoreError::OwnershipConflict {
                kind: "AgentAssignment goal identity",
                id: assignment_id,
            });
        }
        if !(0..=6).contains(&state)
            || !matches!(cancellation, 0 | 1)
            || (cancellation == 1 && !matches!(state, 1 | 5 | 6))
        {
            return Err(GoalDeletionStoreError::InvalidAgentAssignment { id: assignment_id });
        }
        // state 1 = Running. Cancellation-requested terminal rows (5/6) are
        // historical projections and may be removed with the user target.
        if state == 1 {
            return Err(GoalDeletionStoreError::ActiveAgentAssignment { id: assignment_id });
        }
    }
    Ok(())
}

fn load_derived_artifacts(
    transaction: &Transaction<'_>,
    closure: &mut Closure,
) -> Result<(), GoalDeletionStoreError> {
    let changesets = closure.changesets.clone();
    for changeset_id in changesets {
        if closure.shared_changesets.contains(&changeset_id) {
            continue;
        }
        for checkpoint_id in query_ids(
            transaction,
            "SELECT checkpoint_id FROM checkpoints WHERE changeset_id = ?1 ORDER BY checkpoint_id LIMIT ?2",
            &changeset_id,
        )? {
            if has_other_evidence(transaction, 3, &checkpoint_id, closure.request.goal_id())? {
                closure.shared_checkpoints.insert(checkpoint_id);
                // A checkpoint's provenance depends on its ChangeSet. Another
                // Goal can reference that checkpoint under a different evidence
                // kind even when only this Goal references the ChangeSet itself.
                closure.shared_changesets.insert(changeset_id.clone());
            } else {
                closure.checkpoints.insert(checkpoint_id);
            }
        }
        if closure.shared_changesets.contains(&changeset_id) {
            continue;
        }
        for diff_id in query_ids(
            transaction,
            "SELECT diff_id FROM diff_evidence WHERE changeset_id = ?1 ORDER BY diff_id LIMIT ?2",
            &changeset_id,
        )? {
            if has_other_evidence(transaction, 0, &changeset_id, closure.request.goal_id())? {
                closure.shared_diffs.insert(diff_id);
            } else {
                closure.diffs.insert(diff_id);
            }
        }
    }
    let execution_ids = closure.executions.clone();
    for execution_id in execution_ids {
        load_execution_children(transaction, closure, &execution_id)?;
    }
    Ok(())
}

fn query_ids(
    transaction: &Transaction<'_>,
    sql: &str,
    parent_id: &[u8],
) -> Result<Vec<Vec<u8>>, GoalDeletionStoreError> {
    let mut statement = transaction.prepare(sql)?;
    let rows = statement.query_map(params![parent_id, MAX_GOAL_DELETION_PROBE], |row| {
        row.get::<_, Vec<u8>>(0)
    })?;
    let mut ids = Vec::new();
    for row in rows {
        let id = row?;
        if fixed_id(&id).is_none() {
            return Err(GoalDeletionStoreError::UnresolvableOwnership {
                kind: "derived identity",
                id,
            });
        }
        ids.push(id);
        if ids.len() > MAX_GOAL_DELETION_ARTIFACTS {
            return Err(GoalDeletionStoreError::ArtifactOverflow {
                maximum: MAX_GOAL_DELETION_ARTIFACTS,
            });
        }
    }
    Ok(ids)
}

fn load_execution_children(
    transaction: &Transaction<'_>,
    closure: &mut Closure,
    execution_id: &[u8],
) -> Result<(), GoalDeletionStoreError> {
    if closure.shared_executions.contains(execution_id) {
        return Ok(());
    }
    if let Some((input_id, state, workspace_id)) = transaction
        .query_row(
            "SELECT input_id, state, workspace_id FROM verification_runs
             WHERE execution_id = ?1",
            params![execution_id],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            },
        )
        .optional()?
    {
        if state == 0 {
            return Err(GoalDeletionStoreError::ActiveVerificationRun {
                id: execution_id.to_vec(),
            });
        }
        if workspace_id != closure.request.workspace_id().into_uuid().as_bytes() {
            return Err(GoalDeletionStoreError::OwnershipConflict {
                kind: "VerificationRun",
                id: execution_id.to_vec(),
            });
        }
        if fixed_id(&input_id).is_none() {
            return Err(GoalDeletionStoreError::UnresolvableOwnership {
                kind: "VerificationInput",
                id: input_id,
            });
        }
        closure.verification_runs.insert(execution_id.to_vec());
        closure.verification_inputs.insert(input_id);
    }
    if let Some((workspace_id, hash, size)) = transaction
        .query_row(
            "SELECT workspace_id, content_hash, byte_count
             FROM execution_generated_artifacts WHERE execution_id = ?1",
            params![execution_id],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()?
    {
        if workspace_id != closure.request.workspace_id().into_uuid().as_bytes() {
            return Err(GoalDeletionStoreError::OwnershipConflict {
                kind: "GeneratedPackage",
                id: execution_id.to_vec(),
            });
        }
        closure.add_artifact(
            GoalDeletionArtifactKind::GeneratedPackage,
            execution_id,
            None,
            Some(hash),
            Some(size),
            true,
        )?;
    }
    Ok(())
}

fn reject_active_authority(
    transaction: &Transaction<'_>,
    closure: &Closure,
) -> Result<(), GoalDeletionStoreError> {
    for execution_id in closure
        .executions
        .iter()
        .chain(closure.shared_executions.iter())
    {
        let state = transaction
            .query_row(
                "SELECT state FROM executions WHERE execution_id = ?1",
                params![execution_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .ok_or_else(|| GoalDeletionStoreError::UnresolvableOwnership {
                kind: "Execution",
                id: execution_id.clone(),
            })?;
        if matches!(state, 0 | 1) {
            return Err(GoalDeletionStoreError::ActiveExecution {
                id: execution_id.clone(),
            });
        }
        let pending_approval: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT approval_id FROM approval_requests
                 WHERE execution_id = ?1 AND state = 0 LIMIT 1",
                params![execution_id],
                |row| row.get(0),
            )
            .optional()?
            .flatten();
        if pending_approval.is_some() {
            return Err(GoalDeletionStoreError::PendingApproval {
                id: execution_id.clone(),
            });
        }
        let active_grant: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM execution_grants WHERE execution_id = ?1 AND state = 0)",
            params![execution_id],
            |row| row.get(0),
        )?;
        if active_grant {
            return Err(GoalDeletionStoreError::ActiveGrant {
                id: execution_id.clone(),
            });
        }
    }
    if let Some(execution_id) = closure.shared_executions.iter().next() {
        return Err(GoalDeletionStoreError::SharedExecutionAuthorityConflict {
            id: execution_id.clone(),
        });
    }
    for checkpoint_id in closure
        .checkpoints
        .iter()
        .chain(closure.shared_checkpoints.iter())
    {
        let active: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM checkpoint_restores
             WHERE checkpoint_id = ?1 AND state = 0)",
            params![checkpoint_id],
            |row| row.get(0),
        )?;
        if active {
            return Err(GoalDeletionStoreError::ActiveCheckpointRestore {
                id: checkpoint_id.clone(),
            });
        }
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "artifact closure derives all filesystem identities under one bound"
)]
fn load_cleanup_artifacts(
    transaction: &Transaction<'_>,
    closure: &mut Closure,
) -> Result<(), GoalDeletionStoreError> {
    let diff_ids = closure.diffs.clone();
    for diff_id in diff_ids {
        if closure.shared_diffs.contains(&diff_id) {
            continue;
        }
        let row = transaction
            .query_row(
                "SELECT state, pending_relative_path, artifact_relative_path,
                        compressed_hash, compressed_size
                 FROM diff_evidence WHERE diff_id = ?1",
                params![diff_id.as_slice()],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Option<Vec<u8>>>(1)?,
                        row.get::<_, Option<Vec<u8>>>(2)?,
                        row.get::<_, Option<Vec<u8>>>(3)?,
                        row.get::<_, Option<i64>>(4)?,
                    ))
                },
            )
            .optional()?
            .ok_or_else(|| GoalDeletionStoreError::UnresolvableOwnership {
                kind: "Diff",
                id: diff_id.clone(),
            })?;
        let pending_path = row.1;
        let final_path = row.2;
        let has_pending = pending_path.is_some();
        let has_final = final_path.is_some();
        if let Some(path) = pending_path {
            closure.add_artifact(
                GoalDeletionArtifactKind::DiffPending,
                &diff_id,
                Some(path),
                row.3.clone(),
                row.4,
                true,
            )?;
        }
        if let Some(path) = final_path {
            closure.add_artifact(
                GoalDeletionArtifactKind::DiffCompressed,
                &diff_id,
                Some(path),
                row.3,
                row.4,
                true,
            )?;
        }
        if row.0 == 0 && !has_pending && !has_final {
            return Err(GoalDeletionStoreError::UnresolvableOwnership {
                kind: "Diff artifact",
                id: diff_id,
            });
        }
    }
    let input_ids = closure.verification_inputs.clone();
    for input_id in input_ids {
        let (workspace_id, fingerprint, _file_count, total_bytes) = transaction
            .query_row(
                "SELECT workspace_id, fingerprint, file_count, total_bytes
                 FROM verification_inputs WHERE input_id = ?1",
                params![input_id.as_slice()],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()?
            .ok_or_else(|| GoalDeletionStoreError::UnresolvableOwnership {
                kind: "VerificationInput",
                id: input_id.clone(),
            })?;
        if workspace_id != closure.request.workspace_id().into_uuid().as_bytes() {
            return Err(GoalDeletionStoreError::OwnershipConflict {
                kind: "VerificationInput",
                id: input_id,
            });
        }
        let mut run_statement = transaction.prepare(
            "SELECT execution_id FROM verification_runs
             WHERE input_id = ?1 ORDER BY execution_id LIMIT ?2",
        )?;
        let run_rows = run_statement.query_map(
            params![input_id.as_slice(), MAX_GOAL_DELETION_PROBE],
            |row| row.get::<_, Vec<u8>>(0),
        )?;
        let shared = run_rows
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .any(|execution_id| !closure.executions.contains(&execution_id));
        if shared {
            closure.shared_verification_inputs.insert(input_id);
            continue;
        }
        let (source_path, manifest_path, pending_path) = verification_artifact_paths(&input_id)?;
        closure.add_artifact(
            GoalDeletionArtifactKind::VerificationInputSource,
            &input_id,
            Some(source_path),
            Some(fingerprint.clone()),
            Some(total_bytes),
            true,
        )?;
        closure.add_artifact(
            GoalDeletionArtifactKind::VerificationInputManifest,
            &input_id,
            Some(manifest_path),
            Some(fingerprint.clone()),
            None,
            true,
        )?;
        closure.add_artifact(
            GoalDeletionArtifactKind::VerificationInputPending,
            &input_id,
            Some(pending_path),
            Some(fingerprint),
            Some(total_bytes),
            true,
        )?;
    }
    Ok(())
}

type VerificationArtifactPaths = (Vec<u8>, Vec<u8>, Vec<u8>);

fn verification_artifact_paths(
    input_id: &[u8],
) -> Result<VerificationArtifactPaths, GoalDeletionStoreError> {
    let uuid =
        Uuid::from_slice(input_id).map_err(|_| GoalDeletionStoreError::UnresolvableOwnership {
            kind: "VerificationInput",
            id: input_id.to_vec(),
        })?;
    let identity = uuid.to_string();
    Ok((
        format!("artifacts/verification/{identity}/source").into_bytes(),
        format!("artifacts/verification/{identity}/manifest").into_bytes(),
        format!("artifacts/verification/.pending-{identity}").into_bytes(),
    ))
}

fn create_temporary_manifest(transaction: &Transaction<'_>) -> Result<(), GoalDeletionStoreError> {
    transaction.execute_batch(
        "DROP TABLE IF EXISTS temp.goal_deletion_cleanup_manifest;
         CREATE TEMP TABLE goal_deletion_cleanup_manifest (
             ordinal INTEGER PRIMARY KEY,
             artifact_kind INTEGER NOT NULL,
             artifact_id BLOB NOT NULL,
             relative_path BLOB,
             expected_hash BLOB,
             expected_size INTEGER,
             requires_filesystem INTEGER NOT NULL
         )",
    )?;
    Ok(())
}

fn insert_temporary_manifest(
    transaction: &Transaction<'_>,
    artifacts: &[GoalDeletionArtifact],
) -> Result<(), GoalDeletionStoreError> {
    for artifact in artifacts {
        transaction.execute(
            "INSERT INTO temp.goal_deletion_cleanup_manifest (
                 ordinal, artifact_kind, artifact_id, relative_path,
                 expected_hash, expected_size, requires_filesystem
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                i64::from(artifact.ordinal),
                artifact.kind.encode(),
                artifact.id.as_slice(),
                artifact.relative_path.as_deref(),
                artifact.expected_hash.as_deref(),
                artifact
                    .expected_size
                    .map(|value| i64::try_from(value).unwrap_or(i64::MAX)),
                i64::from(artifact.requires_filesystem),
            ],
        )?;
    }
    Ok(())
}

fn insert_journal_rows(
    transaction: &Transaction<'_>,
    cleanup_id: Uuid,
    request: GoalDeletionRequest,
    root_fingerprint: WorkspaceRootFingerprint,
    observed_at: TimestampMillis,
    artifacts: &[GoalDeletionArtifact],
) -> Result<(), GoalDeletionStoreError> {
    for artifact in artifacts
        .iter()
        .filter(|artifact| artifact.requires_filesystem)
    {
        transaction.execute(
            "INSERT INTO goal_deletion_cleanup_journal (
                 cleanup_id, ordinal, workspace_id, activity_id, goal_id,
                 goal_created_at_ms, expected_goal_revision, expected_dag_head_revision,
                 target_kind, root_fingerprint, artifact_kind, artifact_id,
                 relative_path, expected_hash, expected_size, requires_filesystem,
                 created_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                       ?13, ?14, ?15, ?16, ?17)",
            params![
                cleanup_id.as_bytes(),
                i64::from(artifact.ordinal),
                request.workspace_id().into_uuid().as_bytes(),
                request.activity_id().into_uuid().as_bytes(),
                request.goal_id().into_uuid().as_bytes(),
                request.goal_created_at().get(),
                request.expected_goal_revision().get(),
                request
                    .expected_dag_head_revision()
                    .map(DagHeadRevision::get),
                encode_target(request.target()),
                root_fingerprint.as_bytes().as_slice(),
                artifact.kind.encode(),
                artifact.id.as_slice(),
                artifact.relative_path.as_deref(),
                artifact.expected_hash.as_deref(),
                artifact
                    .expected_size
                    .map(|value| i64::try_from(value).unwrap_or(i64::MAX)),
                1_i64,
                observed_at.get(),
            ],
        )?;
    }
    Ok(())
}

fn drop_temporary_manifest(transaction: &Transaction<'_>) -> Result<(), GoalDeletionStoreError> {
    transaction.execute_batch("DROP TABLE temp.goal_deletion_cleanup_manifest")?;
    Ok(())
}

fn unlink_agent_work_evidence(
    transaction: &Transaction<'_>,
    closure: &Closure,
) -> Result<(), GoalDeletionStoreError> {
    transaction.execute_batch(
        "DROP TABLE IF EXISTS temp.goal_deletion_owned_evidence;
         DROP TABLE IF EXISTS temp.goal_deletion_work_counts;
         CREATE TEMP TABLE goal_deletion_owned_evidence (
             evidence_kind INTEGER NOT NULL,
             evidence_id BLOB NOT NULL,
             PRIMARY KEY(evidence_kind, evidence_id)
         );
         CREATE TEMP TABLE goal_deletion_work_counts (
             update_id BLOB PRIMARY KEY,
             removed_count INTEGER NOT NULL
         )",
    )?;
    for (kind, id) in &closure.owned_evidence {
        transaction.execute(
            "INSERT OR IGNORE INTO temp.goal_deletion_owned_evidence
             (evidence_kind, evidence_id) VALUES (?1, ?2)",
            params![kind, id.as_slice()],
        )?;
    }
    transaction.execute(
        "INSERT INTO temp.goal_deletion_work_counts (update_id, removed_count)
         SELECT r.update_id, COUNT(*)
         FROM agent_work_update_evidence_refs AS r
         JOIN temp.goal_deletion_owned_evidence AS e
           ON e.evidence_kind = r.evidence_kind AND e.evidence_id = r.evidence_id
         GROUP BY r.update_id",
        [],
    )?;
    let invalid: Option<Vec<u8>> = transaction
        .query_row(
            "SELECT u.update_id FROM agent_work_updates AS u
             JOIN temp.goal_deletion_work_counts AS c ON c.update_id = u.update_id
             WHERE u.evidence_count < c.removed_count LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(id) = invalid {
        return Err(GoalDeletionStoreError::AgentEvidenceCountCorrupt { id });
    }
    transaction.execute(
        "UPDATE agent_work_updates
         SET evidence_count = evidence_count - (
             SELECT removed_count FROM temp.goal_deletion_work_counts
             WHERE update_id = agent_work_updates.update_id
         )
         WHERE update_id IN (SELECT update_id FROM temp.goal_deletion_work_counts)",
        [],
    )?;
    transaction.execute(
        "DELETE FROM agent_work_update_evidence_refs
         WHERE EXISTS (
             SELECT 1 FROM temp.goal_deletion_owned_evidence AS e
             WHERE e.evidence_kind = agent_work_update_evidence_refs.evidence_kind
               AND e.evidence_id = agent_work_update_evidence_refs.evidence_id
         )",
        [],
    )?;
    transaction.execute_batch(
        "DROP TABLE temp.goal_deletion_work_counts;
         DROP TABLE temp.goal_deletion_owned_evidence",
    )?;
    Ok(())
}

fn clear_agent_focus(
    transaction: &Transaction<'_>,
    request: GoalDeletionRequest,
    observed_at: TimestampMillis,
    delegated: bool,
) -> Result<(), GoalDeletionStoreError> {
    if delegated {
        return clear_delegated_agent_focus(transaction, request, observed_at);
    }
    let overflow: bool = transaction.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM agent_instances
             WHERE workspace_id = ?1 AND activity_id = ?2
               AND focus_goal_id = ?3 AND revision = 9223372036854775807
         )",
        params![
            request.workspace_id().into_uuid().as_bytes(),
            request.activity_id().into_uuid().as_bytes(),
            request.goal_id().into_uuid().as_bytes(),
        ],
        |row| row.get(0),
    )?;
    if overflow {
        return Err(GoalDeletionStoreError::AgentRevisionOverflow);
    }
    transaction.execute(
        "UPDATE agent_instances
         SET focus_goal_id = NULL, focus_goal_revision = NULL,
             focus_dag_revision = NULL, focus_node_id = NULL,
             focus_node_revision = NULL, updated_at_ms = ?1, revision = revision + 1
         WHERE workspace_id = ?2 AND activity_id = ?3 AND focus_goal_id = ?4",
        params![
            observed_at.get(),
            request.workspace_id().into_uuid().as_bytes(),
            request.activity_id().into_uuid().as_bytes(),
            request.goal_id().into_uuid().as_bytes(),
        ],
    )?;
    transaction.execute(
        "DELETE FROM agent_focus_events
         WHERE workspace_id = ?1 AND activity_id = ?2 AND focus_goal_id = ?3",
        params![
            request.workspace_id().into_uuid().as_bytes(),
            request.activity_id().into_uuid().as_bytes(),
            request.goal_id().into_uuid().as_bytes(),
        ],
    )?;
    Ok(())
}

/// Clear delegated Agent focus through the same immutable focus-event and
/// effect-outbox path used by normal work mutations.  The keyset page is
/// bounded so this transaction never buffers an unbounded set of focused
/// Agents; each row is then updated with an exact revision CAS.
fn clear_delegated_agent_focus(
    transaction: &Transaction<'_>,
    request: GoalDeletionRequest,
    observed_at: TimestampMillis,
) -> Result<(), GoalDeletionStoreError> {
    const PAGE_SIZE: i64 = 64;
    let mut cursor: Option<Vec<u8>> = None;
    loop {
        let mut statement = transaction.prepare(
            "SELECT substr(agent_id, 1, 17), revision
             FROM agent_instances
             WHERE workspace_id = ?1 AND activity_id = ?2
               AND focus_goal_id = ?3
               AND (?4 IS NULL OR agent_id > ?4)
             ORDER BY agent_id ASC LIMIT ?5",
        )?;
        let rows = statement.query_map(
            params![
                request.workspace_id().into_uuid().as_bytes(),
                request.activity_id().into_uuid().as_bytes(),
                request.goal_id().into_uuid().as_bytes(),
                cursor.as_deref(),
                PAGE_SIZE,
            ],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
        )?;
        let page = rows.collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        if page.is_empty() {
            break;
        }
        for (agent_bytes, raw_revision) in &page {
            clear_delegated_agent_row(
                transaction,
                request,
                observed_at,
                agent_bytes,
                *raw_revision,
            )?;
        }
        cursor = Some(page.last().map(|(id, _)| id.clone()).ok_or_else(|| {
            GoalDeletionStoreError::UnresolvableOwnership {
                kind: "focused Agent page",
                id: Vec::new(),
            }
        })?);
    }
    transaction.execute(
        "DELETE FROM agent_focus_events
         WHERE workspace_id = ?1 AND activity_id = ?2 AND focus_goal_id = ?3",
        params![
            request.workspace_id().into_uuid().as_bytes(),
            request.activity_id().into_uuid().as_bytes(),
            request.goal_id().into_uuid().as_bytes(),
        ],
    )?;
    Ok(())
}

fn clear_delegated_agent_row(
    transaction: &Transaction<'_>,
    request: GoalDeletionRequest,
    observed_at: TimestampMillis,
    agent_bytes: &[u8],
    raw_revision: i64,
) -> Result<(), GoalDeletionStoreError> {
    let agent_uuid = Uuid::from_slice(agent_bytes).map_err(|_| {
        GoalDeletionStoreError::UnresolvableOwnership {
            kind: "focused Agent",
            id: agent_bytes.to_vec(),
        }
    })?;
    let agent_id = AgentInstanceId::from_uuid(agent_uuid);
    let current =
        crate::workspace_agents::get_in_transaction(transaction, agent_id)?.ok_or_else(|| {
            GoalDeletionStoreError::UnresolvableOwnership {
                kind: "focused Agent",
                id: agent_bytes.to_vec(),
            }
        })?;
    if current.workspace_id() != request.workspace_id()
        || current.activity_id() != request.activity_id()
        || current
            .focus()
            .goal()
            .map(forge_domain::GoalAttribution::goal_id)
            != Some(request.goal_id())
    {
        return Err(GoalDeletionStoreError::UnresolvableOwnership {
            kind: "focused Agent projection",
            id: agent_bytes.to_vec(),
        });
    }
    if current.revision().get() != raw_revision {
        return Err(GoalDeletionStoreError::AgentRevisionConflict { agent_id });
    }
    let next_revision = current
        .revision()
        .checked_next()
        .map_err(|_| GoalDeletionStoreError::AgentRevisionOverflow)?;
    let event_sequence = AgentFocusEventSequence::new(next_revision.get())
        .map_err(|_| GoalDeletionStoreError::AgentRevisionOverflow)?;
    let changed = transaction.execute(
        "UPDATE agent_instances
         SET focus_goal_id = NULL, focus_goal_revision = NULL,
             focus_dag_revision = NULL, focus_node_id = NULL,
             focus_node_revision = NULL, updated_at_ms = ?1,
             revision = ?2
         WHERE agent_id = ?3 AND workspace_id = ?4 AND activity_id = ?5
           AND revision = ?6 AND focus_goal_id = ?7",
        params![
            observed_at.get(),
            next_revision.get(),
            agent_id.into_uuid().as_bytes(),
            request.workspace_id().into_uuid().as_bytes(),
            request.activity_id().into_uuid().as_bytes(),
            current.revision().get(),
            request.goal_id().into_uuid().as_bytes(),
        ],
    )?;
    if changed != 1 {
        return Err(GoalDeletionStoreError::AgentRevisionConflict { agent_id });
    }
    let event = AgentFocusEvent::from_parts(
        agent_id,
        request.workspace_id(),
        request.activity_id(),
        event_sequence,
        AgentFocusEventKind::Changed,
        AgentFocus::unfocused(),
        observed_at,
    );
    crate::workspace_agents::insert_focus_event(transaction, &event)?;
    Ok(())
}

fn redact_agent_events(
    transaction: &Transaction<'_>,
    request: GoalDeletionRequest,
) -> Result<(), GoalDeletionStoreError> {
    let goal_uuid = request.goal_id().into_uuid();
    let goal_id = goal_uuid.as_bytes();
    if request.target().deletes_goal() {
        transaction.execute(
            "UPDATE agent_events SET
                 before_goal_id = CASE WHEN before_goal_id = ?3 THEN NULL ELSE before_goal_id END,
                 before_goal_revision = CASE WHEN before_goal_id = ?3 THEN NULL ELSE before_goal_revision END,
                 before_dag_revision = CASE WHEN before_goal_id = ?3 THEN NULL ELSE before_dag_revision END,
                 before_dag_head_revision = CASE WHEN before_goal_id = ?3 THEN NULL ELSE before_dag_head_revision END,
                 before_head_id = CASE WHEN before_goal_id = ?3 THEN NULL ELSE before_head_id END,
                 before_head_revision = CASE WHEN before_goal_id = ?3 THEN NULL ELSE before_head_revision END,
                 after_goal_id = CASE WHEN after_goal_id = ?3 THEN NULL ELSE after_goal_id END,
                 after_goal_revision = CASE WHEN after_goal_id = ?3 THEN NULL ELSE after_goal_revision END,
                 after_dag_revision = CASE WHEN after_goal_id = ?3 THEN NULL ELSE after_dag_revision END,
                 after_dag_head_revision = CASE WHEN after_goal_id = ?3 THEN NULL ELSE after_dag_head_revision END,
                 after_head_id = CASE WHEN after_goal_id = ?3 THEN NULL ELSE after_head_id END,
                 after_head_revision = CASE WHEN after_goal_id = ?3 THEN NULL ELSE after_head_revision END
             WHERE workspace_id = ?1 AND activity_id = ?2
               AND (before_goal_id = ?3 OR after_goal_id = ?3)",
            params![
                request.workspace_id().into_uuid().as_bytes(),
                request.activity_id().into_uuid().as_bytes(),
                goal_id,
            ],
        )?;
    } else {
        transaction.execute(
            "UPDATE agent_events SET
                 before_dag_revision = CASE WHEN before_goal_id = ?3 THEN NULL ELSE before_dag_revision END,
                 before_dag_head_revision = CASE WHEN before_goal_id = ?3 THEN NULL ELSE before_dag_head_revision END,
                 before_head_id = CASE WHEN before_goal_id = ?3 THEN NULL ELSE before_head_id END,
                 before_head_revision = CASE WHEN before_goal_id = ?3 THEN NULL ELSE before_head_revision END,
                 after_dag_revision = CASE WHEN after_goal_id = ?3 THEN NULL ELSE after_dag_revision END,
                 after_dag_head_revision = CASE WHEN after_goal_id = ?3 THEN NULL ELSE after_dag_head_revision END,
                 after_head_id = CASE WHEN after_goal_id = ?3 THEN NULL ELSE after_head_id END,
                 after_head_revision = CASE WHEN after_goal_id = ?3 THEN NULL ELSE after_head_revision END
             WHERE workspace_id = ?1 AND activity_id = ?2
               AND (before_goal_id = ?3 OR after_goal_id = ?3)",
            params![
                request.workspace_id().into_uuid().as_bytes(),
                request.activity_id().into_uuid().as_bytes(),
                goal_id,
            ],
        )?;
    }
    Ok(())
}

fn delete_execution_closure(
    transaction: &Transaction<'_>,
    closure: &Closure,
) -> Result<(), GoalDeletionStoreError> {
    for execution_id in &closure.executions {
        transaction.execute(
            "DELETE FROM execution_grants WHERE execution_id = ?1",
            params![execution_id],
        )?;
        transaction.execute(
            "DELETE FROM approval_requests WHERE execution_id = ?1",
            params![execution_id],
        )?;
        transaction.execute(
            "DELETE FROM execution_output_events WHERE execution_id = ?1",
            params![execution_id],
        )?;
        transaction.execute(
            "DELETE FROM execution_command_evidence WHERE execution_id = ?1",
            params![execution_id],
        )?;
        transaction.execute(
            "DELETE FROM execution_generated_artifacts WHERE execution_id = ?1",
            params![execution_id],
        )?;
        transaction.execute(
            "DELETE FROM verification_requirement_links WHERE execution_id = ?1 AND goal_id = ?2",
            params![
                execution_id,
                closure.request.goal_id().into_uuid().as_bytes()
            ],
        )?;
        transaction.execute(
            "DELETE FROM verification_runs WHERE execution_id = ?1",
            params![execution_id],
        )?;
        transaction.execute(
            "DELETE FROM execution_provenance WHERE execution_id = ?1",
            params![execution_id],
        )?;
        transaction.execute(
            "DELETE FROM executions WHERE execution_id = ?1",
            params![execution_id],
        )?;
    }
    for input_id in &closure.verification_inputs {
        let referenced: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM verification_runs WHERE input_id = ?1)",
            params![input_id],
            |row| row.get(0),
        )?;
        if !referenced {
            transaction.execute(
                "DELETE FROM verification_inputs WHERE input_id = ?1",
                params![input_id],
            )?;
        }
    }
    Ok(())
}

fn delete_changeset_closure(
    transaction: &Transaction<'_>,
    closure: &Closure,
) -> Result<(), GoalDeletionStoreError> {
    for checkpoint_id in &closure.checkpoints {
        if closure.shared_checkpoints.contains(checkpoint_id) {
            continue;
        }
        transaction.execute(
            "DELETE FROM checkpoint_restores WHERE checkpoint_id = ?1",
            params![checkpoint_id],
        )?;
        transaction.execute(
            "DELETE FROM checkpoints WHERE checkpoint_id = ?1",
            params![checkpoint_id],
        )?;
    }
    for diff_id in &closure.diffs {
        if closure.shared_diffs.contains(diff_id) {
            continue;
        }
        transaction.execute(
            "DELETE FROM diff_entries WHERE diff_id = ?1",
            params![diff_id],
        )?;
        transaction.execute(
            "DELETE FROM diff_evidence WHERE diff_id = ?1",
            params![diff_id],
        )?;
    }
    for changeset_id in &closure.changesets {
        if closure.shared_changesets.contains(changeset_id) {
            continue;
        }
        transaction.execute(
            "DELETE FROM source_tree_requests WHERE changeset_id = ?1",
            params![changeset_id],
        )?;
        transaction.execute(
            "DELETE FROM tree_mutations WHERE changeset_id = ?1",
            params![changeset_id],
        )?;
        transaction.execute(
            "DELETE FROM file_mutations WHERE changeset_id = ?1",
            params![changeset_id],
        )?;
        transaction.execute(
            "DELETE FROM checkpoints WHERE changeset_id = ?1",
            params![changeset_id],
        )?;
        transaction.execute(
            "DELETE FROM change_sets WHERE changeset_id = ?1",
            params![changeset_id],
        )?;
    }
    Ok(())
}

fn delete_goal_evidence_links(
    transaction: &Transaction<'_>,
    closure: &Closure,
) -> Result<(), GoalDeletionStoreError> {
    let mut links = closure
        .evidence
        .iter()
        .map(|evidence| (evidence.kind, evidence.id.clone()))
        .collect::<HashSet<_>>();
    links.extend(closure.owned_evidence.iter().cloned());
    for (kind, id) in links {
        transaction.execute(
            "DELETE FROM goal_evidence_refs
             WHERE goal_id = ?1 AND evidence_kind = ?2 AND evidence_id = ?3",
            params![
                closure.request.goal_id().into_uuid().as_bytes(),
                kind,
                id.as_slice(),
            ],
        )?;
    }
    Ok(())
}

fn delete_dag_closure(
    transaction: &Transaction<'_>,
    goal_id: GoalId,
) -> Result<(), GoalDeletionStoreError> {
    transaction.execute(
        "DELETE FROM agent_assignment_sources
         WHERE assignment_id IN (
             SELECT assignment_id FROM agent_assignments WHERE goal_id = ?1
         )",
        params![goal_id.into_uuid().as_bytes()],
    )?;
    transaction.execute(
        "DELETE FROM agent_assignments WHERE goal_id = ?1",
        params![goal_id.into_uuid().as_bytes()],
    )?;
    transaction.execute(
        "DELETE FROM agent_dag_plan_sessions
         WHERE request_id IN (
             SELECT request_id FROM agent_dag_plan_ledger WHERE goal_id = ?1
         )",
        params![goal_id.into_uuid().as_bytes()],
    )?;
    transaction.execute(
        "DELETE FROM agent_dag_plan_ledger WHERE goal_id = ?1",
        params![goal_id.into_uuid().as_bytes()],
    )?;
    transaction.execute(
        "DELETE FROM goal_dag_node_evidence_refs WHERE goal_id = ?1",
        params![goal_id.into_uuid().as_bytes()],
    )?;
    transaction.execute(
        "DELETE FROM goal_dag_node_acceptance WHERE goal_id = ?1",
        params![goal_id.into_uuid().as_bytes()],
    )?;
    transaction.execute(
        "DELETE FROM goal_dag_edges WHERE goal_id = ?1",
        params![goal_id.into_uuid().as_bytes()],
    )?;
    transaction.execute(
        "DELETE FROM goal_dag_node_lineage WHERE goal_id = ?1",
        params![goal_id.into_uuid().as_bytes()],
    )?;
    transaction.execute(
        "DELETE FROM goal_dag_nodes WHERE goal_id = ?1",
        params![goal_id.into_uuid().as_bytes()],
    )?;
    transaction.execute(
        "DELETE FROM goal_dag_heads WHERE goal_id = ?1",
        params![goal_id.into_uuid().as_bytes()],
    )?;
    transaction.execute(
        "DELETE FROM goal_dag_revisions WHERE goal_id = ?1",
        params![goal_id.into_uuid().as_bytes()],
    )?;
    Ok(())
}

fn delete_goal_closure(
    transaction: &Transaction<'_>,
    goal_id: GoalId,
) -> Result<(), GoalDeletionStoreError> {
    // Completed Goals and their review rows reference each other. Keep FK
    // enforcement enabled and validate this cycle at the caller's commit;
    // SQLite resets the deferral on commit/rollback. Never turn it off early.
    transaction.pragma_update(None, "defer_foreign_keys", true)?;
    transaction.execute(
        "DELETE FROM goal_completion_reviews WHERE goal_id = ?1",
        params![goal_id.into_uuid().as_bytes()],
    )?;
    transaction.execute(
        "DELETE FROM verification_requirement_links WHERE goal_id = ?1",
        params![goal_id.into_uuid().as_bytes()],
    )?;
    transaction.execute(
        "DELETE FROM goal_evidence_refs WHERE goal_id = ?1",
        params![goal_id.into_uuid().as_bytes()],
    )?;
    transaction.execute(
        "DELETE FROM goal_verification_requirements WHERE goal_id = ?1",
        params![goal_id.into_uuid().as_bytes()],
    )?;
    transaction.execute(
        "DELETE FROM goal_statements WHERE goal_id = ?1",
        params![goal_id.into_uuid().as_bytes()],
    )?;
    transaction.execute(
        "DELETE FROM goals WHERE goal_id = ?1",
        params![goal_id.into_uuid().as_bytes()],
    )?;
    Ok(())
}

fn fixed_id(value: &[u8]) -> Option<[u8; ID_BYTES]> {
    value.try_into().ok()
}

const fn encode_target(target: GoalDeletionTarget) -> i64 {
    match target {
        GoalDeletionTarget::Goal => 0,
        GoalDeletionTarget::Dag => 1,
    }
}

fn decode_target(value: i64) -> Result<GoalDeletionTarget, GoalDeletionStoreError> {
    match value {
        0 => Ok(GoalDeletionTarget::Goal),
        1 => Ok(GoalDeletionTarget::Dag),
        _ => Err(GoalDeletionStoreError::DamagedSchema(JOURNAL_TABLE)),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use std::error::Error;

    use super::*;
    use forge_domain::{
        ActivityId, AgentEvent, AgentEventId, AgentEventKind, AgentFocus, AgentFocusEvent,
        AgentFocusEventKind, AgentFocusEventSequence, AgentFocusNode, AgentInstanceId,
        AgentMembershipRevision, CoordinationSnapshot, CoordinatorSnapshot, CreateActivity,
        DagHeadRevision, DagNodeId, DagNodeRevision, DagRevisionNumber, EstablishWorkspace,
        GoalAttribution, GoalContract, GoalDeletionRequest, GoalDeletionTarget, GoalId,
        GoalObjective, GoalRevision, GoalStatement, LocationId, RegisteredGoal, TimestampMillis,
        WorkspaceId, WorkspaceRevision, WorkspaceRoot,
    };
    use forge_workspace::WorkspaceStateLayout;
    use rusqlite::TransactionBehavior;

    fn setup() -> Result<Connection, Box<dyn Error>> {
        let connection = Connection::open_in_memory()?;
        connection
            .execute_batch(
                "PRAGMA foreign_keys = ON;
                 CREATE TABLE workspace(workspace_id BLOB PRIMARY KEY);
                 CREATE TABLE activities(activity_id BLOB PRIMARY KEY, workspace_id BLOB);
                 CREATE TABLE goals(goal_id BLOB PRIMARY KEY, workspace_id BLOB, activity_id BLOB, created_at_ms INTEGER, revision INTEGER);
                 CREATE TABLE goal_dag_heads(goal_id BLOB PRIMARY KEY, dag_revision INTEGER, head_revision INTEGER);
                 CREATE TABLE goal_evidence_refs(goal_id BLOB, evidence_kind INTEGER, evidence_id BLOB);
                 CREATE TABLE goal_dag_revisions(goal_id BLOB, dag_revision INTEGER);
                 CREATE TABLE goal_dag_heads_dummy(goal_id BLOB);
                 CREATE TABLE goal_dag_node_evidence_refs(goal_id BLOB);
                 CREATE TABLE goal_dag_node_acceptance(goal_id BLOB);
                 CREATE TABLE goal_dag_edges(goal_id BLOB);
                 CREATE TABLE goal_dag_node_lineage(goal_id BLOB);
                 CREATE TABLE goal_dag_nodes(goal_id BLOB);
                 CREATE TABLE agent_dag_plan_ledger(request_id BLOB PRIMARY KEY, goal_id BLOB);
                 CREATE TABLE agent_dag_plan_sessions(
                     request_id BLOB PRIMARY KEY REFERENCES agent_dag_plan_ledger(request_id),
                     session_id BLOB NOT NULL);
                 CREATE TABLE goal_completion_reviews(goal_id BLOB);
                 CREATE TABLE verification_requirement_links(execution_id BLOB, goal_id BLOB);
                 CREATE TABLE goal_verification_requirements(goal_id BLOB);
                 CREATE TABLE goal_statements(goal_id BLOB);
                 CREATE TABLE agent_instances(agent_id BLOB, workspace_id BLOB, activity_id BLOB, focus_goal_id BLOB, focus_goal_revision INTEGER, focus_dag_revision INTEGER, focus_node_id BLOB, focus_node_revision INTEGER, updated_at_ms INTEGER, revision INTEGER);
                 CREATE TABLE agent_focus_events(agent_id BLOB, workspace_id BLOB, activity_id BLOB, event_sequence INTEGER, focus_goal_id BLOB);
                 CREATE TABLE agent_events(event_id BLOB PRIMARY KEY, workspace_id BLOB, activity_id BLOB, before_goal_id BLOB, before_goal_revision INTEGER, before_dag_revision INTEGER, before_dag_head_revision INTEGER, before_head_id BLOB, before_head_revision INTEGER, after_goal_id BLOB, after_goal_revision INTEGER, after_dag_revision INTEGER, after_dag_head_revision INTEGER, after_head_id BLOB, after_head_revision INTEGER);
                 CREATE TABLE agent_work_updates(update_id BLOB PRIMARY KEY, evidence_count INTEGER);
                 CREATE TABLE agent_work_update_evidence_refs(update_id BLOB, evidence_kind INTEGER, evidence_id BLOB);
                 CREATE TABLE writer_leases(activity_id BLOB, state INTEGER);
                 CREATE TABLE executions(execution_id BLOB PRIMARY KEY, workspace_id BLOB, activity_id BLOB, state INTEGER);
                 CREATE TABLE execution_provenance(execution_id BLOB PRIMARY KEY, goal_id BLOB);
                 CREATE TABLE execution_output_events(execution_id BLOB);
                 CREATE TABLE execution_command_evidence(execution_id BLOB);
                 CREATE TABLE execution_generated_artifacts(execution_id BLOB, workspace_id BLOB, content_hash BLOB, byte_count INTEGER);
                 CREATE TABLE verification_runs(execution_id BLOB PRIMARY KEY, input_id BLOB, state INTEGER, workspace_id BLOB);
                 CREATE TABLE verification_inputs(input_id BLOB PRIMARY KEY, workspace_id BLOB, fingerprint BLOB);
                 CREATE TABLE approval_requests(approval_id BLOB PRIMARY KEY, workspace_id BLOB, activity_id BLOB, execution_id BLOB, state INTEGER);
                 CREATE TABLE execution_grants(execution_id BLOB, state INTEGER);
                 CREATE TABLE checkpoint_restores(checkpoint_id BLOB, state INTEGER);
                 CREATE TABLE checkpoints(checkpoint_id BLOB PRIMARY KEY, workspace_id BLOB, activity_id BLOB, changeset_id BLOB, pre_commit BLOB, post_commit BLOB, state INTEGER);
                 CREATE TABLE change_sets(changeset_id BLOB PRIMARY KEY, workspace_id BLOB, activity_id BLOB);
                 CREATE TABLE source_tree_requests(changeset_id BLOB);
                 CREATE TABLE tree_mutations(changeset_id BLOB);
                 CREATE TABLE file_mutations(changeset_id BLOB);
                 CREATE TABLE diff_evidence(diff_id BLOB PRIMARY KEY, changeset_id BLOB, state INTEGER, pending_relative_path BLOB, artifact_relative_path BLOB, compressed_hash BLOB, compressed_size INTEGER);
                 CREATE TABLE diff_entries(diff_id BLOB);
                 CREATE TABLE workspace_root_dummy(value INTEGER);",
            )
            ?;
        create_schema(&connection)?;
        Ok(connection)
    }

    /// Build the real current Workspace schema through `WorkspaceStore`, then
    /// reopen its `SQLite` file for direct transaction assertions. This keeps
    /// the deletion regression tied to schema34 rather than a second DDL copy.
    fn full_schema_fixture() -> Result<(PathBuf, Connection, GoalDeletionRequest), Box<dyn Error>> {
        let root = std::env::temp_dir().join(format!("forge-goal-delete-{}", Uuid::now_v7()));
        fs::create_dir_all(&root)?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(100));
        let location_id = LocationId::from_uuid(Uuid::from_u128(101));
        let activity_id = ActivityId::from_uuid(Uuid::from_u128(102));
        let goal_id = GoalId::from_uuid(Uuid::from_u128(103));
        let root_fingerprint = layout.root_fingerprint()?;
        let command = EstablishWorkspace::new(
            workspace_id,
            location_id,
            WorkspaceRoot::from_canonical(layout.workspace_root().to_path_buf())?,
            root_fingerprint,
            TimestampMillis::new(1)?,
        );
        let mut store = crate::WorkspaceStore::open(&layout, &command)?;
        store.create_activity(&CreateActivity::new(
            activity_id,
            workspace_id,
            WorkspaceRevision::INITIAL,
            TimestampMillis::new(2)?,
        ))?;
        drop(store);
        let mut connection = Connection::open(layout.database_path())?;
        connection.pragma_update(None, "foreign_keys", true)?;
        let contract = GoalContract::new(
            GoalObjective::new("Delete this fixture Goal".to_owned())?,
            vec![GoalStatement::new(
                "The deletion closure is complete".to_owned(),
            )?],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )?;
        let goal = RegisteredGoal::create(
            goal_id,
            workspace_id,
            activity_id,
            contract,
            TimestampMillis::new(10)?,
        );
        let _ = crate::workspace_goals::insert_goal(&mut connection, &goal)?;
        let changeset_id = Uuid::from_u128(104);
        let runtime_id = Uuid::from_u128(105);
        connection.execute(
            "INSERT INTO change_sets (
                 changeset_id, workspace_id, activity_id, runtime_instance_id,
                 activity_lease_revision, workspace_revision, state, failure_code,
                 created_at_ms, updated_at_ms, revision
             ) VALUES (?1, ?2, ?3, ?4, 1, 1, 0, NULL, 20, 20, 1)",
            params![
                changeset_id.as_bytes(),
                workspace_id.into_uuid().as_bytes(),
                activity_id.into_uuid().as_bytes(),
                runtime_id.as_bytes(),
            ],
        )?;
        connection.execute(
            "INSERT INTO goal_evidence_refs(goal_id, evidence_kind, evidence_id, associated_at_ms)
             VALUES (?1, 0, ?2, 20)",
            params![goal_id.into_uuid().as_bytes(), changeset_id.as_bytes()],
        )?;
        seed_full_schema_dag(&connection, goal_id, changeset_id)?;
        let request = GoalDeletionRequest::new(
            GoalDeletionTarget::Goal,
            workspace_id,
            activity_id,
            goal_id,
            TimestampMillis::new(10)?,
            GoalRevision::INITIAL,
            Some(DagHeadRevision::INITIAL),
        );
        Ok((root, connection, request))
    }

    #[test]
    fn completed_goal_cycle_deletion_keeps_foreign_key_enforcement() -> Result<(), Box<dyn Error>> {
        let (root, mut connection, request) = full_schema_fixture()?;
        let review_id = Uuid::from_u128(0xCF01);
        // Construct the persisted FK cycle. The real HTTP flow separately
        // verifies completion authorization and its evidence prerequisites.
        connection.execute(
            "INSERT INTO goal_completion_reviews (review_id, goal_id, goal_revision,
            observed_at_ms, required_check_count, linked_evidence_count, pending_approval_count,
            active_execution_count, unsealed_evidence_count) VALUES (?1, ?2, 1, 30, 0, 0, 0, 0, 0)",
            params![
                review_id.as_bytes(),
                request.goal_id().into_uuid().as_bytes()
            ],
        )?;
        connection.execute(
            "UPDATE goals SET state = 3, completion_review_id = ?1,
            updated_at_ms = 30, revision = 2 WHERE goal_id = ?2",
            params![
                review_id.as_bytes(),
                request.goal_id().into_uuid().as_bytes()
            ],
        )?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        delete_dag_closure(&transaction, request.goal_id())?;
        delete_goal_closure(&transaction, request.goal_id())?;
        assert_eq!(
            transaction.query_row("PRAGMA foreign_keys", [], |row| row.get::<_, i64>(0))?,
            1
        );
        assert!(
            !transaction
                .prepare("PRAGMA foreign_key_check")?
                .exists([])?
        );
        transaction.commit()?;
        assert_eq!(
            connection.query_row("PRAGMA defer_foreign_keys", [], |row| row.get::<_, i64>(0))?,
            0
        );
        assert_eq!(
            connection.query_row("PRAGMA foreign_keys", [], |row| row.get::<_, i64>(0))?,
            1
        );
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.pragma_update(None, "defer_foreign_keys", true)?;
        transaction.execute(
            "INSERT INTO goal_statements (goal_id, statement_kind, ordinal, statement_text)
            VALUES (?1, 0, 0, 'dangling reference')",
            params![request.goal_id().into_uuid().as_bytes()],
        )?;
        assert!(transaction.commit().is_err());
        assert!(!connection.prepare("PRAGMA foreign_key_check")?.exists([])?);
        assert_eq!(
            connection.query_row("PRAGMA defer_foreign_keys", [], |row| row.get::<_, i64>(0))?,
            0
        );
        drop(connection);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    fn seed_full_schema_dag(
        connection: &Connection,
        goal_id: GoalId,
        changeset_id: Uuid,
    ) -> Result<(), Box<dyn Error>> {
        let revision_id = Uuid::from_u128(106);
        let node_id = Uuid::from_u128(107);
        connection.execute(
            "INSERT INTO goal_dag_revisions(
                 goal_id, dag_revision, revision_id, parent_dag_revision,
                 base_goal_revision, created_at_ms, node_count, edge_count
             ) VALUES (?1, 1, ?2, NULL, 1, 20, 1, 0)",
            params![goal_id.into_uuid().as_bytes(), revision_id.as_bytes()],
        )?;
        connection.execute(
            "INSERT INTO goal_dag_heads(goal_id, dag_revision, head_revision, updated_at_ms)
             VALUES (?1, 1, 1, 20)",
            params![goal_id.into_uuid().as_bytes()],
        )?;
        connection.execute(
            "INSERT INTO goal_dag_nodes(
                 goal_id, dag_revision, node_id, ordinal, title, objective,
                 lifecycle_state, reason_text, created_at_ms, updated_at_ms, node_revision
             ) VALUES (?1, 1, ?2, 0, 'Delete', 'Delete fixture', 0, NULL, 20, 20, 1)",
            params![goal_id.into_uuid().as_bytes(), node_id.as_bytes()],
        )?;
        connection.execute(
            "INSERT INTO goal_dag_node_evidence_refs(
                 goal_id, dag_revision, node_id, evidence_kind, evidence_id, associated_at_ms
             ) VALUES (?1, 1, ?2, 0, ?3, 20)",
            params![
                goal_id.into_uuid().as_bytes(),
                node_id.as_bytes(),
                changeset_id.as_bytes(),
            ],
        )?;
        Ok(())
    }

    fn seed_delegated_focus_source(
        connection: &mut Connection,
        request: GoalDeletionRequest,
    ) -> Result<(AgentInstanceId, AgentFocusEvent, AgentEvent), Box<dyn Error>> {
        let agent_id = AgentInstanceId::from_uuid(Uuid::from_u128(200));
        let node_id = DagNodeId::from_uuid(Uuid::from_u128(107));
        let focus = AgentFocus::new(
            Some(GoalAttribution::new(
                request.goal_id(),
                GoalRevision::INITIAL,
            )),
            Some(DagRevisionNumber::INITIAL),
            Some(AgentFocusNode::new(node_id, DagNodeRevision::INITIAL)),
        )?;
        connection.execute(
            "INSERT INTO agent_instances(
                 agent_id, workspace_id, activity_id, display_name, declared_role,
                 transport_kind, principal_kind, principal_id, attachment_state,
                 focus_goal_id, focus_goal_revision, focus_dag_revision, focus_node_id,
                 focus_node_revision, created_at_ms, updated_at_ms, revision, session_id
             ) VALUES (?1, ?2, ?3, 'legacy-focus', 'worker', 0, 0, NULL, 0,
                       ?4, 1, 1, ?5, 1, 19, 20, 2, NULL)",
            params![
                agent_id.into_uuid().as_bytes(),
                request.workspace_id().into_uuid().as_bytes(),
                request.activity_id().into_uuid().as_bytes(),
                request.goal_id().into_uuid().as_bytes(),
                node_id.into_uuid().as_bytes(),
            ],
        )?;
        let focus_event = AgentFocusEvent::from_parts(
            agent_id,
            request.workspace_id(),
            request.activity_id(),
            AgentFocusEventSequence::new(2)?,
            AgentFocusEventKind::Changed,
            focus,
            TimestampMillis::new(20)?,
        );
        crate::workspace_agents::insert_focus_event(connection, &focus_event)?;

        let goal_attribution = GoalAttribution::new(request.goal_id(), GoalRevision::INITIAL);
        let coordination = CoordinationSnapshot::new(
            Some(goal_attribution),
            Some(DagRevisionNumber::INITIAL),
            Some(DagHeadRevision::INITIAL),
            None,
        )?;
        let legacy_event = AgentEvent::new(
            AgentEventId::from_uuid(Uuid::from_u128(201)),
            request.workspace_id(),
            request.activity_id(),
            AgentMembershipRevision::INITIAL,
            AgentEventKind::RoleChanged,
            None,
            None,
            coordination,
            coordination,
            CoordinatorSnapshot::unbound(),
            CoordinatorSnapshot::unbound(),
            TimestampMillis::new(20)?,
        );
        let event_transaction =
            connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        crate::workspace_agent_events::append_event_in_transaction(
            &event_transaction,
            &legacy_event,
            &[],
        )?;
        event_transaction.commit()?;

        let freeze_request = crate::AgentOperationsFreezeRequest::new(
            Uuid::from_u128(202),
            Uuid::from_u128(203),
            TimestampMillis::new(25)?,
        )?;
        let freeze = crate::workspace_agent_migration::freeze(
            connection,
            request.workspace_id(),
            &freeze_request,
        )?;
        let _delegation = crate::workspace_agent_delegation::delegate(
            connection,
            request.workspace_id(),
            &freeze,
            [0xA1; 32],
            TimestampMillis::new(30)?,
        )?;
        let fact_transaction =
            connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        crate::workspace_agent_effect_outbox::append_focus(&fact_transaction, &focus_event)?;
        fact_transaction.commit()?;
        Ok((agent_id, focus_event, legacy_event))
    }

    #[test]
    fn delegated_full_schema_goal_deletion_clears_focus_and_preserves_opaque_facts()
    -> Result<(), Box<dyn Error>> {
        let (root, mut connection, request) = full_schema_fixture()?;
        let (agent_id, _focus_event, legacy_event) =
            seed_delegated_focus_source(&mut connection, request)?;
        let layout = WorkspaceStateLayout::inspect_existing(&root)?
            .ok_or_else(|| std::io::Error::other("full schema fixture layout missing"))?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let stage = stage_delete_in_transaction(
            &transaction,
            request,
            TimestampMillis::new(40)?,
            layout.root_fingerprint()?,
        )?;
        assert!(stage.artifacts().is_empty());
        transaction.commit()?;

        let agent_state: (i64, Option<Vec<u8>>) = connection.query_row(
            "SELECT revision, focus_goal_id FROM agent_instances WHERE agent_id = ?1",
            params![agent_id.into_uuid().as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        assert_eq!(agent_state.0, 3);
        assert!(agent_state.1.is_none());
        let focus_rows = connection
            .prepare(
                "SELECT event_sequence, focus_goal_id FROM agent_focus_events
                 WHERE agent_id = ?1 ORDER BY event_sequence ASC",
            )?
            .query_map(params![agent_id.into_uuid().as_bytes()], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, Option<Vec<u8>>>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(focus_rows, vec![(3, None)]);

        let old_outbox_focus: i64 = connection.query_row(
            "SELECT COUNT(*) FROM agent_effect_outbox_focus
             WHERE focus_goal_id = ?1",
            params![request.goal_id().into_uuid().as_bytes()],
            |row| row.get(0),
        )?;
        let cleared_outbox_focus: i64 = connection.query_row(
            "SELECT COUNT(*) FROM agent_effect_outbox_focus
             WHERE focus_goal_id IS NULL",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(old_outbox_focus, 1);
        assert_eq!(cleared_outbox_focus, 1);

        let legacy_snapshot: (Option<Vec<u8>>, Option<Vec<u8>>) = connection.query_row(
            "SELECT before_goal_id, after_goal_id FROM agent_events WHERE event_id = ?1",
            params![legacy_event.id().into_uuid().as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        assert_eq!(
            legacy_snapshot,
            (
                Some(request.goal_id().into_uuid().into_bytes().to_vec()),
                Some(request.goal_id().into_uuid().into_bytes().to_vec()),
            )
        );
        assert_eq!(
            connection.query_row(
                "SELECT COUNT(*) FROM goals WHERE goal_id = ?1",
                params![request.goal_id().into_uuid().as_bytes()],
                |row| row.get::<_, i64>(0),
            )?,
            0
        );
        assert_eq!(
            connection.query_row(
                "SELECT COUNT(*) FROM goal_dag_revisions WHERE goal_id = ?1",
                params![request.goal_id().into_uuid().as_bytes()],
                |row| row.get::<_, i64>(0),
            )?,
            0
        );
        assert!(!connection.prepare("PRAGMA foreign_key_check")?.exists([])?);
        drop(connection);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    fn ids() -> (WorkspaceId, ActivityId, GoalId) {
        (
            WorkspaceId::from_uuid(Uuid::from_u128(1)),
            ActivityId::from_uuid(Uuid::from_u128(2)),
            GoalId::from_uuid(Uuid::from_u128(3)),
        )
    }

    fn request(
        target: GoalDeletionTarget,
        head: Option<DagHeadRevision>,
    ) -> Result<GoalDeletionRequest, Box<dyn Error>> {
        let (workspace, activity, goal) = ids();
        Ok(GoalDeletionRequest::new(
            target,
            workspace,
            activity,
            goal,
            TimestampMillis::new(10)?,
            GoalRevision::new(2)?,
            head,
        ))
    }

    fn insert_goal(connection: &Connection) -> Result<(), Box<dyn Error>> {
        let (workspace, activity, goal) = ids();
        connection.execute(
            "INSERT INTO workspace(workspace_id) VALUES (?1)",
            params![workspace.into_uuid().as_bytes()],
        )?;
        connection.execute(
            "INSERT INTO activities(activity_id, workspace_id) VALUES (?1, ?2)",
            params![
                activity.into_uuid().as_bytes(),
                workspace.into_uuid().as_bytes()
            ],
        )?;
        connection
            .execute(
                "INSERT INTO goals(goal_id, workspace_id, activity_id, created_at_ms, revision) VALUES (?1, ?2, ?3, 10, 2)",
                params![goal.into_uuid().as_bytes(), workspace.into_uuid().as_bytes(), activity.into_uuid().as_bytes()],
            )
            ?;
        Ok(())
    }

    fn insert_journal_fixture(
        connection: &Connection,
        request: GoalDeletionRequest,
    ) -> Result<Uuid, Box<dyn Error>> {
        let cleanup_id = Uuid::now_v7();
        connection.execute(
            "INSERT INTO goal_deletion_cleanup_journal (
                     cleanup_id, ordinal, workspace_id, activity_id, goal_id,
                     goal_created_at_ms, expected_goal_revision,
                     expected_dag_head_revision, target_kind, root_fingerprint,
                     artifact_kind, artifact_id, relative_path, expected_hash,
                     expected_size, requires_filesystem, created_at_ms
                 ) VALUES (?1, 0, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 1, ?10,
                           ?11, ?12, 3, 1, 20)",
            params![
                cleanup_id.as_bytes(),
                request.workspace_id().into_uuid().as_bytes(),
                request.activity_id().into_uuid().as_bytes(),
                request.goal_id().into_uuid().as_bytes(),
                request.goal_created_at().get(),
                request.expected_goal_revision().get(),
                request
                    .expected_dag_head_revision()
                    .map(DagHeadRevision::get),
                encode_target(request.target()),
                [7_u8; 16].as_slice(),
                [9_u8; 16].as_slice(),
                b"diffs/diff.zst".as_slice(),
                [8_u8; 32].as_slice(),
            ],
        )?;
        Ok(cleanup_id)
    }

    #[test]
    fn journal_schema_is_reopenable_and_validated() -> Result<(), Box<dyn Error>> {
        let connection = setup()?;
        validate_schema(&connection)?;
        validate_schema(&connection)?;
        Ok(())
    }

    #[test]
    fn stale_created_at_fence_rolls_back_without_rows() -> Result<(), Box<dyn Error>> {
        let connection = setup()?;
        insert_goal(&connection)?;
        let mut connection = connection;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut stale = request(GoalDeletionTarget::Goal, None)?;
        stale = GoalDeletionRequest::new(
            stale.target(),
            stale.workspace_id(),
            stale.activity_id(),
            stale.goal_id(),
            TimestampMillis::new(11)?,
            stale.expected_goal_revision(),
            stale.expected_dag_head_revision(),
        );
        assert!(matches!(
            stage_delete_in_transaction(
                &transaction,
                stale,
                TimestampMillis::new(20)?,
                WorkspaceRootFingerprint::from_bytes([7; 16]),
            ),
            Err(GoalDeletionStoreError::CreatedAtConflict { .. })
        ));
        drop(transaction);
        let goal_count =
            connection.query_row("SELECT COUNT(*) FROM goals", [], |row| row.get::<_, i64>(0))?;
        assert_eq!(goal_count, 1);
        Ok(())
    }

    #[test]
    fn every_target_requires_current_dag_head_fence_when_head_exists() -> Result<(), Box<dyn Error>>
    {
        let connection = setup()?;
        insert_goal(&connection)?;
        let (_, _, goal) = ids();
        connection.execute(
            "INSERT INTO goal_dag_heads(goal_id, dag_revision, head_revision)
             VALUES (?1, 1, 7)",
            params![goal.into_uuid().as_bytes()],
        )?;
        let mut connection = connection;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let request_without_head = request(GoalDeletionTarget::Goal, None)?;
        assert!(matches!(
            stage_delete_in_transaction(
                &transaction,
                request_without_head,
                TimestampMillis::new(20)?,
                WorkspaceRootFingerprint::from_bytes([7; 16]),
            ),
            Err(GoalDeletionStoreError::DagHeadFenceRequired)
        ));
        drop(transaction);
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let stale = GoalDeletionRequest::new(
            GoalDeletionTarget::Goal,
            request_without_head.workspace_id(),
            request_without_head.activity_id(),
            request_without_head.goal_id(),
            request_without_head.goal_created_at(),
            request_without_head.expected_goal_revision(),
            Some(DagHeadRevision::new(8)?),
        );
        assert!(matches!(
            stage_delete_in_transaction(
                &transaction,
                stale,
                TimestampMillis::new(20)?,
                WorkspaceRootFingerprint::from_bytes([7; 16]),
            ),
            Err(GoalDeletionStoreError::DagHeadConflict { .. })
        ));
        Ok(())
    }

    #[test]
    fn pending_journal_readback_and_identity_guard_are_durable() -> Result<(), Box<dyn Error>> {
        let mut connection = setup()?;
        let request = request(GoalDeletionTarget::Goal, None)?;
        let cleanup_id = insert_journal_fixture(&connection, request)?;
        connection.execute(
            "INSERT INTO goal_deletion_cleanup_journal (
                     cleanup_id, ordinal, workspace_id, activity_id, goal_id,
                     goal_created_at_ms, expected_goal_revision,
                     expected_dag_head_revision, target_kind, root_fingerprint,
                     artifact_kind, artifact_id, relative_path, expected_hash,
                     expected_size, requires_filesystem, created_at_ms
                 ) VALUES (?1, 1, ?2, ?3, ?4, ?5, ?6, NULL, 0, ?7, 0, ?8,
                           ?9, ?10, 4, 1, 20)",
            params![
                cleanup_id.as_bytes(),
                request.workspace_id().into_uuid().as_bytes(),
                request.activity_id().into_uuid().as_bytes(),
                request.goal_id().into_uuid().as_bytes(),
                request.goal_created_at().get(),
                request.expected_goal_revision().get(),
                [7_u8; 16].as_slice(),
                [6_u8; 16].as_slice(),
                b"diffs/.pending".as_slice(),
                [5_u8; 32].as_slice(),
            ],
        )?;
        let readback = load_pending_cleanup(&connection, cleanup_id)?
            .ok_or_else(|| std::io::Error::other("pending journal missing"))?;
        assert_eq!(readback.cleanup_id(), cleanup_id);
        assert_eq!(readback.request(), request);
        assert_eq!(
            readback.root_fingerprint(),
            WorkspaceRootFingerprint::from_bytes([7; 16])
        );
        assert_eq!(readback.artifacts().len(), 2);
        assert_eq!(
            readback.artifacts()[0].kind(),
            GoalDeletionArtifactKind::DiffCompressed
        );
        assert!(has_pending_goal_cleanup(&connection, request.goal_id())?);
        assert!(artifact_identity_is_pending(
            &connection,
            GoalDeletionArtifactIdentity::Diff(DiffId::from_uuid(Uuid::from_bytes([9; 16])))
        )?);
        assert!(load_pending_cleanup_for_request(&connection, request)?.is_some());
        let stale_request = GoalDeletionRequest::new(
            request.target(),
            request.workspace_id(),
            request.activity_id(),
            request.goal_id(),
            request.goal_created_at(),
            GoalRevision::new(3)?,
            request.expected_dag_head_revision(),
        );
        assert!(matches!(
            load_pending_cleanup_for_request(&connection, stale_request),
            Err(GoalDeletionStoreError::CleanupRequestConflict { .. })
        ));
        let _second_cleanup = insert_journal_fixture(&connection, request)?;
        let inventory = list_pending_cleanup(&connection, request.workspace_id(), 1)?;
        assert_eq!(inventory.summaries().len(), 1);
        assert!(inventory.has_more());
        assert_eq!(inventory.summaries()[0].remaining(), 2);
        let first = record_cleanup_progress(
            &mut connection,
            cleanup_id,
            &[GoalDeletionArtifactProof::new(
                0,
                GoalDeletionArtifactStatus::Deleted,
            )],
        )?;
        assert_eq!(
            first.status(),
            GoalDeletionCleanupStatus::Pending { remaining: 1 }
        );
        Ok(())
    }

    #[test]
    fn incomplete_cleanup_keeps_journal_and_terminal_proof_removes_it() -> Result<(), Box<dyn Error>>
    {
        let mut connection = setup()?;
        let request = request(GoalDeletionTarget::Goal, None)?;
        let cleanup_id = insert_journal_fixture(&connection, request)?;
        let pending = finish_cleanup(
            &mut connection,
            cleanup_id,
            &[GoalDeletionArtifactProof::new(
                0,
                GoalDeletionArtifactStatus::Incomplete,
            )],
        )?;
        assert_eq!(
            pending.status(),
            GoalDeletionCleanupStatus::Pending { remaining: 1 }
        );
        let complete = finish_cleanup(
            &mut connection,
            cleanup_id,
            &[GoalDeletionArtifactProof::new(
                0,
                GoalDeletionArtifactStatus::AlreadyMissing,
            )],
        )?;
        assert_eq!(complete.status(), GoalDeletionCleanupStatus::Complete);
        let deleted_cleanup_id = insert_journal_fixture(&connection, request)?;
        let deleted = finish_cleanup(
            &mut connection,
            deleted_cleanup_id,
            &[GoalDeletionArtifactProof::new(
                0,
                GoalDeletionArtifactStatus::Deleted,
            )],
        )?;
        assert_eq!(deleted.status(), GoalDeletionCleanupStatus::Complete);
        assert!(matches!(
            finish_cleanup(&mut connection, cleanup_id, &[]),
            Err(GoalDeletionStoreError::CleanupJournalMissing { .. })
        ));
        Ok(())
    }

    #[test]
    fn zero_filesystem_stage_has_explicit_sql_only_outcome() {
        let stage = GoalDeletionStage {
            cleanup_id: None,
            target: GoalDeletionTarget::Goal,
            artifacts: Vec::new(),
            next_goal_revision: None,
        };
        assert_eq!(
            stage.cleanup_status(),
            GoalDeletionCleanupStatus::SqlOnlyComplete
        );
    }

    #[test]
    fn full_schema34_goal_closure_deletes_dag_node_evidence_and_changeset()
    -> Result<(), Box<dyn Error>> {
        let (root, mut connection, request) = full_schema_fixture()?;
        let existing = WorkspaceStateLayout::inspect_existing(&root)?
            .ok_or_else(|| std::io::Error::other("fixture layout missing"))?;
        let fingerprint = existing.root_fingerprint()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let stage = stage_delete_in_transaction(
            &transaction,
            request,
            TimestampMillis::new(30)?,
            fingerprint,
        )?;
        assert_eq!(stage.cleanup_id(), None);
        assert_eq!(
            stage.cleanup_status(),
            GoalDeletionCleanupStatus::SqlOnlyComplete
        );
        transaction.commit()?;
        assert!(
            connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM goals WHERE goal_id = ?1)",
                    params![request.goal_id().into_uuid().as_bytes()],
                    |row| row.get::<_, bool>(0),
                )
                .map(|exists| !exists)?
        );
        assert_eq!(
            connection
                .query_row("PRAGMA foreign_key_check", [], |_| Ok(0_i64))
                .optional()?,
            None
        );
        drop(connection);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn full_schema34_dag_only_keeps_goal_contract_and_bumps_revision() -> Result<(), Box<dyn Error>>
    {
        let (root, mut connection, goal_request) = full_schema_fixture()?;
        let request = GoalDeletionRequest::new(
            GoalDeletionTarget::Dag,
            goal_request.workspace_id(),
            goal_request.activity_id(),
            goal_request.goal_id(),
            goal_request.goal_created_at(),
            goal_request.expected_goal_revision(),
            goal_request.expected_dag_head_revision(),
        );
        let existing = WorkspaceStateLayout::inspect_existing(&root)?
            .ok_or_else(|| std::io::Error::other("fixture layout missing"))?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let stage = stage_delete_in_transaction(
            &transaction,
            request,
            TimestampMillis::new(30)?,
            existing.root_fingerprint()?,
        )?;
        assert_eq!(stage.next_goal_revision().map(GoalRevision::get), Some(2));
        transaction.commit()?;
        let revision = connection.query_row(
            "SELECT revision FROM goals WHERE goal_id = ?1",
            params![request.goal_id().into_uuid().as_bytes()],
            |row| row.get::<_, i64>(0),
        )?;
        assert_eq!(revision, 2);
        assert_eq!(
            connection.query_row(
                "SELECT COUNT(*) FROM goal_statements WHERE goal_id = ?1",
                params![request.goal_id().into_uuid().as_bytes()],
                |row| row.get::<_, i64>(0),
            )?,
            1
        );
        assert_eq!(
            connection.query_row(
                "SELECT COUNT(*) FROM goal_dag_revisions WHERE goal_id = ?1",
                params![request.goal_id().into_uuid().as_bytes()],
                |row| row.get::<_, i64>(0),
            )?,
            0
        );
        drop(connection);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "full schema shared verification closure fixture"
    )]
    fn full_schema34_shared_execution_and_verification_run_are_preserved()
    -> Result<(), Box<dyn Error>> {
        let (root, mut connection, request) = full_schema_fixture()?;
        let other_goal_id = GoalId::from_uuid(Uuid::from_u128(108));
        let contract = GoalContract::new(
            GoalObjective::new("Other Goal".to_owned())?,
            vec![GoalStatement::new("Other criterion".to_owned())?],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )?;
        let other_goal = RegisteredGoal::create(
            other_goal_id,
            request.workspace_id(),
            request.activity_id(),
            contract,
            TimestampMillis::new(11)?,
        );
        let _ = crate::workspace_goals::insert_goal(&mut connection, &other_goal)?;
        let agent_id = Uuid::from_u128(109);
        let session_id = Uuid::from_u128(110);
        connection.execute(
            "INSERT INTO agent_instances(
                 agent_id, workspace_id, activity_id, display_name, declared_role,
                 transport_kind, principal_kind, principal_id, attachment_state,
                 focus_goal_id, focus_goal_revision, focus_dag_revision, focus_node_id,
                 focus_node_revision, created_at_ms, updated_at_ms, revision, session_id
             ) VALUES (?1, ?2, ?3, 'agent', 'worker', 0, 0, NULL, 1,
                       NULL, NULL, NULL, NULL, NULL, 1, 1, 1, ?4)",
            params![
                agent_id.as_bytes(),
                request.workspace_id().into_uuid().as_bytes(),
                request.activity_id().into_uuid().as_bytes(),
                session_id.as_bytes(),
            ],
        )?;
        let execution_id = Uuid::from_u128(111);
        connection.execute(
            "INSERT INTO executions(
                 execution_id, workspace_id, activity_id, state, mode, request_digest,
                 cwd, timeout_ms, output_limit, workspace_read, workspace_write, network,
                 exit_code, signal, duration_ms, stdout, stdout_total_bytes, stdout_truncated,
                 stderr, stderr_total_bytes, stderr_truncated, failure_code,
                 created_at_ms, updated_at_ms, revision
             ) VALUES (?1, ?2, ?3, 3, 0, ?4, NULL, 1000, 16, 1, 0, 0,
                       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 1, 20, 20, 2)",
            params![
                execution_id.as_bytes(),
                request.workspace_id().into_uuid().as_bytes(),
                request.activity_id().into_uuid().as_bytes(),
                [3_u8; 32].as_slice(),
            ],
        )?;
        connection.execute(
            "INSERT INTO execution_provenance(
                 execution_id, agent_id, agent_revision, principal_kind, principal_id,
                 goal_id, goal_revision, dag_revision, node_id, node_revision,
                 command_id, session_id
             ) VALUES (?1, ?2, 1, 0, NULL, ?3, 1, 1, ?4, 1, 'shared', ?5)",
            params![
                execution_id.as_bytes(),
                agent_id.as_bytes(),
                request.goal_id().into_uuid().as_bytes(),
                Uuid::from_u128(107).as_bytes(),
                session_id.as_bytes(),
            ],
        )?;
        let input_id = Uuid::from_u128(112);
        connection.execute(
            "INSERT INTO verification_inputs(
                 input_id, workspace_id, policy, fingerprint, file_count,
                 total_bytes, created_at_ms, revision
             ) VALUES (?1, ?2, 1, ?3, 0, 0, 20, 1)",
            params![
                input_id.as_bytes(),
                request.workspace_id().into_uuid().as_bytes(),
                [4_u8; 32].as_slice(),
            ],
        )?;
        connection.execute(
            "INSERT INTO verification_runs(
                 execution_id, workspace_id, input_id, state, output_integrity,
                 output_fingerprint, created_at_ms, updated_at_ms, revision
             ) VALUES (?1, ?2, ?3, 2, 0, ?4, 20, 20, 2)",
            params![
                execution_id.as_bytes(),
                request.workspace_id().into_uuid().as_bytes(),
                input_id.as_bytes(),
                [5_u8; 32].as_slice(),
            ],
        )?;
        connection.execute(
            "INSERT INTO verification_requirement_links(
                 execution_id, goal_id, goal_revision, ordinal
             ) VALUES (?1, ?2, 1, 0), (?1, ?3, 1, 0)",
            params![
                execution_id.as_bytes(),
                request.goal_id().into_uuid().as_bytes(),
                other_goal_id.into_uuid().as_bytes(),
            ],
        )?;
        connection.execute(
            "INSERT INTO goal_evidence_refs(goal_id, evidence_kind, evidence_id, associated_at_ms)
             VALUES (?1, 1, ?2, 20)",
            params![
                request.goal_id().into_uuid().as_bytes(),
                execution_id.as_bytes()
            ],
        )?;
        let existing = WorkspaceStateLayout::inspect_existing(&root)?
            .ok_or_else(|| std::io::Error::other("fixture layout missing"))?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let deletion = stage_delete_in_transaction(
            &transaction,
            request,
            TimestampMillis::new(30)?,
            existing.root_fingerprint()?,
        );
        assert!(matches!(
            deletion,
            Err(GoalDeletionStoreError::SharedExecutionAuthorityConflict { .. })
        ));
        drop(transaction);
        assert!(connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM executions WHERE execution_id = ?1)",
            params![execution_id.as_bytes()],
            |row| row.get::<_, bool>(0),
        )?);
        assert!(connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM verification_runs WHERE execution_id = ?1)",
            params![execution_id.as_bytes()],
            |row| row.get::<_, bool>(0),
        )?);
        assert!(connection.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM verification_requirement_links
                 WHERE execution_id = ?1 AND goal_id = ?2
             )",
            params![
                execution_id.as_bytes(),
                other_goal_id.into_uuid().as_bytes()
            ],
            |row| row.get::<_, bool>(0),
        )?);
        assert!(connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM execution_provenance WHERE execution_id = ?1)",
            params![execution_id.as_bytes()],
            |row| row.get::<_, bool>(0),
        )?);
        assert!(connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM goal_evidence_refs WHERE goal_id = ?1 AND evidence_kind = 1 AND evidence_id = ?2)",
            params![request.goal_id().into_uuid().as_bytes(), execution_id.as_bytes()],
            |row| row.get::<_, bool>(0),
        )?);
        drop(connection);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    fn seed_shared_checkpoint(
        connection: &mut Connection,
        request: GoalDeletionRequest,
    ) -> Result<(GoalId, Uuid), Box<dyn Error>> {
        let other_goal_id = GoalId::from_uuid(Uuid::from_u128(120));
        let other_goal = RegisteredGoal::create(
            other_goal_id,
            request.workspace_id(),
            request.activity_id(),
            GoalContract::new(
                GoalObjective::new("Keep the shared checkpoint".to_owned())?,
                vec![GoalStatement::new(
                    "Checkpoint provenance remains readable".to_owned(),
                )?],
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            )?,
            TimestampMillis::new(11)?,
        );
        let _ = crate::workspace_goals::insert_goal(connection, &other_goal)?;
        let checkpoint_id = Uuid::from_u128(121);
        connection.execute(
            "INSERT INTO checkpoints (
                 checkpoint_id, changeset_id, workspace_id, activity_id,
                 workspace_revision, relative_path, object_format, state,
                 pre_state, pre_commit, post_state, post_commit,
                 created_at_ms, updated_at_ms, revision
             ) VALUES (?1, ?2, ?3, ?4, 1, ?5, 0, 1, 0, ?6, 0, ?7, 20, 21, 2)",
            params![
                checkpoint_id.as_bytes(),
                Uuid::from_u128(104).as_bytes(),
                request.workspace_id().into_uuid().as_bytes(),
                request.activity_id().into_uuid().as_bytes(),
                b"source.rs".as_slice(),
                [1_u8; 20].as_slice(),
                [2_u8; 20].as_slice(),
            ],
        )?;
        connection.execute(
            "INSERT INTO goal_evidence_refs (
                 goal_id, evidence_kind, evidence_id, associated_at_ms
             ) VALUES (?1, 3, ?2, 22)",
            params![
                other_goal_id.into_uuid().as_bytes(),
                checkpoint_id.as_bytes()
            ],
        )?;
        let diff_id = forge_domain::DiffId::for_change_set(forge_domain::ChangeSetId::from_uuid(
            Uuid::from_u128(104),
        ));
        connection.execute(
            "INSERT INTO diff_evidence (
                 diff_id, changeset_id, workspace_id, activity_id,
                 origin_kind, mutation_id, state, render_kind,
                 renderer_version, redaction_policy_version,
                 created_at_ms, updated_at_ms, revision
             ) VALUES (?1, ?2, ?3, ?4, 1, NULL, 2, 3, 1, 1, 20, 21, 2)",
            params![
                diff_id.into_uuid().as_bytes(),
                Uuid::from_u128(104).as_bytes(),
                request.workspace_id().into_uuid().as_bytes(),
                request.activity_id().into_uuid().as_bytes(),
            ],
        )?;
        Ok((other_goal_id, checkpoint_id))
    }

    #[test]
    fn full_schema_cross_kind_shared_checkpoint_preserves_changeset() -> Result<(), Box<dyn Error>>
    {
        for target in [GoalDeletionTarget::Goal, GoalDeletionTarget::Dag] {
            let (root, mut connection, original) = full_schema_fixture()?;
            let (other_goal, checkpoint) = seed_shared_checkpoint(&mut connection, original)?;
            let request = GoalDeletionRequest::new(
                target,
                original.workspace_id(),
                original.activity_id(),
                original.goal_id(),
                original.goal_created_at(),
                original.expected_goal_revision(),
                original.expected_dag_head_revision(),
            );
            let layout = WorkspaceStateLayout::inspect_existing(&root)?
                .ok_or("full schema fixture layout missing")?;
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let stage = stage_delete_in_transaction(
                &transaction,
                request,
                TimestampMillis::new(30)?,
                layout.root_fingerprint()?,
            )?;
            assert!(
                stage.artifacts().is_empty(),
                "shared checkpoint must not be purged"
            );
            transaction.commit()?;
            let retained: bool = connection.query_row(
                "SELECT EXISTS (
                     SELECT 1 FROM goal_evidence_refs AS e
                     JOIN checkpoints AS k ON k.checkpoint_id = e.evidence_id
                     JOIN change_sets AS c ON c.changeset_id = k.changeset_id
                     WHERE e.goal_id = ?1 AND e.evidence_kind = 3
                       AND k.checkpoint_id = ?2 AND c.changeset_id = ?3
                 )",
                params![
                    other_goal.into_uuid().as_bytes(),
                    checkpoint.as_bytes(),
                    Uuid::from_u128(104).as_bytes(),
                ],
                |row| row.get(0),
            )?;
            assert!(
                retained,
                "deleting {target:?} broke another Goal's checkpoint evidence"
            );
            let retained_diff: bool = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM diff_evidence WHERE changeset_id = ?1 AND state = 2)",
                params![Uuid::from_u128(104).as_bytes()],
                |row| row.get(0),
            )?;
            assert!(retained_diff, "shared ChangeSet lost its Diff evidence");
            let foreign_key_violation =
                connection.prepare("PRAGMA foreign_key_check")?.exists([])?;
            assert!(!foreign_key_violation);
            let target_exists: bool = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM goals WHERE goal_id = ?1)",
                params![request.goal_id().into_uuid().as_bytes()],
                |row| row.get(0),
            )?;
            assert_eq!(target_exists, target == GoalDeletionTarget::Dag);
            drop(connection);
            fs::remove_dir_all(root)?;
        }
        Ok(())
    }

    #[test]
    fn shared_goal_evidence_is_preserved_for_closure_selection() -> Result<(), Box<dyn Error>> {
        let connection = setup()?;
        let (workspace, activity, goal) = ids();
        let other_goal = GoalId::from_uuid(Uuid::from_u128(4));
        let change_set = Uuid::from_u128(5).into_bytes().to_vec();
        connection.execute(
            "INSERT INTO goal_evidence_refs(goal_id, evidence_kind, evidence_id)
                 VALUES (?1, 0, ?2), (?3, 0, ?2)",
            params![
                goal.into_uuid().as_bytes(),
                change_set.as_slice(),
                other_goal.into_uuid().as_bytes(),
            ],
        )?;
        connection.execute(
            "INSERT INTO change_sets(changeset_id, workspace_id, activity_id)
                 VALUES (?1, ?2, ?3)",
            params![
                change_set.as_slice(),
                workspace.into_uuid().as_bytes(),
                activity.into_uuid().as_bytes(),
            ],
        )?;
        let mut closure = Closure::new(GoalDeletionRequest::new(
            GoalDeletionTarget::Goal,
            workspace,
            activity,
            goal,
            TimestampMillis::new(10)?,
            GoalRevision::new(2)?,
            None,
        ));
        let owner = connection.query_row(
            "SELECT EXISTS(
                     SELECT 1 FROM goal_evidence_refs
                     WHERE evidence_kind = 0 AND evidence_id = ?1 AND goal_id != ?2
                 )",
            params![change_set.as_slice(), goal.into_uuid().as_bytes()],
            |row| row.get::<_, bool>(0),
        )?;
        assert!(owner);
        let transaction = connection.unchecked_transaction()?;
        load_goal_evidence(&transaction, &mut closure)?;
        assert!(closure.owned_evidence.is_empty());
        assert!(closure.changesets.is_empty());
        Ok(())
    }

    #[test]
    fn active_writer_lease_guard_is_fail_closed() -> Result<(), Box<dyn Error>> {
        let connection = setup()?;
        let (_, activity, _) = ids();
        connection.execute(
            "INSERT INTO writer_leases(activity_id, state) VALUES (?1, 0)",
            params![activity.into_uuid().as_bytes()],
        )?;
        let transaction = connection.unchecked_transaction()?;
        assert!(matches!(
            reject_active_writer_lease(&transaction, activity),
            Err(GoalDeletionStoreError::ActiveWriterLease { .. })
        ));
        Ok(())
    }

    #[test]
    fn verification_requirement_link_keeps_execution_shared() -> Result<(), Box<dyn Error>> {
        let connection = setup()?;
        let (_, _, goal) = ids();
        let execution_id = Uuid::from_u128(8).into_bytes();
        let other_goal = GoalId::from_uuid(Uuid::from_u128(9));
        connection.execute(
            "INSERT INTO verification_requirement_links(execution_id, goal_id)
             VALUES (?1, ?2)",
            params![execution_id.as_slice(), other_goal.into_uuid().as_bytes()],
        )?;
        let transaction = connection.unchecked_transaction()?;
        assert!(execution_has_other_goal_links(
            &transaction,
            execution_id.as_slice(),
            goal,
        )?);
        Ok(())
    }

    #[test]
    fn submitted_and_cancelled_assignments_are_removable_but_running_blocks()
    -> Result<(), Box<dyn Error>> {
        let connection = setup()?;
        connection.execute(
            "CREATE TABLE agent_assignments(
                 assignment_id BLOB PRIMARY KEY, workspace_id BLOB,
                 activity_id BLOB, goal_id BLOB, goal_created_at_ms INTEGER,
                 state INTEGER, cancellation_requested INTEGER
             )",
            [],
        )?;
        let request = request(GoalDeletionTarget::Goal, None)?;
        let ids = [
            (Uuid::from_u128(120), 2_i64, 0_i64),
            (Uuid::from_u128(121), 5_i64, 1_i64),
        ];
        for (assignment_id, state, cancellation) in ids {
            connection.execute(
                "INSERT INTO agent_assignments(
                     assignment_id, workspace_id, activity_id, goal_id,
                     goal_created_at_ms, state, cancellation_requested
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    assignment_id.as_bytes(),
                    request.workspace_id().into_uuid().as_bytes(),
                    request.activity_id().into_uuid().as_bytes(),
                    request.goal_id().into_uuid().as_bytes(),
                    request.goal_created_at().get(),
                    state,
                    cancellation,
                ],
            )?;
        }
        let transaction = connection.unchecked_transaction()?;
        let mut closure = Closure::new(request);
        load_goal_assignments(&transaction, &mut closure)?;
        drop(transaction);
        connection.execute(
            "INSERT INTO agent_assignments(
                 assignment_id, workspace_id, activity_id, goal_id,
                 goal_created_at_ms, state, cancellation_requested
             ) VALUES (?1, ?2, ?3, ?4, ?5, 1, 0)",
            params![
                Uuid::from_u128(122).as_bytes(),
                request.workspace_id().into_uuid().as_bytes(),
                request.activity_id().into_uuid().as_bytes(),
                request.goal_id().into_uuid().as_bytes(),
                request.goal_created_at().get(),
            ],
        )?;
        let transaction = connection.unchecked_transaction()?;
        assert!(matches!(
            load_goal_assignments(&transaction, &mut Closure::new(request)),
            Err(GoalDeletionStoreError::ActiveAgentAssignment { .. })
        ));
        Ok(())
    }

    #[test]
    fn bounded_evidence_probe_rejects_overflow_before_mutation() -> Result<(), Box<dyn Error>> {
        let connection = setup()?;
        let (workspace, activity, goal) = ids();
        let request = GoalDeletionRequest::new(
            GoalDeletionTarget::Goal,
            workspace,
            activity,
            goal,
            TimestampMillis::new(10)?,
            GoalRevision::new(2)?,
            None,
        );
        for ordinal in 0..=MAX_GOAL_DELETION_ARTIFACTS {
            let evidence_id = Uuid::from_u128(ordinal as u128 + 10).into_bytes();
            connection.execute(
                "INSERT INTO goal_evidence_refs(goal_id, evidence_kind, evidence_id)
                     VALUES (?1, 0, ?2)",
                params![goal.into_uuid().as_bytes(), evidence_id.as_slice()],
            )?;
            connection.execute(
                "INSERT INTO change_sets(changeset_id, workspace_id, activity_id)
                     VALUES (?1, ?2, ?3)",
                params![
                    evidence_id.as_slice(),
                    workspace.into_uuid().as_bytes(),
                    activity.into_uuid().as_bytes(),
                ],
            )?;
        }
        let transaction = connection.unchecked_transaction()?;
        let mut closure = Closure::new(request);
        assert!(matches!(
            load_goal_evidence(&transaction, &mut closure),
            Err(GoalDeletionStoreError::ArtifactOverflow { .. })
        ));
        Ok(())
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "explicit FK fixture documents deletion order"
    )]
    fn dag_node_evidence_is_deleted_before_goal_evidence_foreign_key() -> Result<(), Box<dyn Error>>
    {
        let mut connection = Connection::open_in_memory()?;
        connection.execute_batch(
            "PRAGMA foreign_keys = ON;
                 CREATE TABLE goals(goal_id BLOB PRIMARY KEY);
                 CREATE TABLE goal_evidence_refs(
                     goal_id BLOB NOT NULL, evidence_kind INTEGER NOT NULL,
                     evidence_id BLOB NOT NULL,
                     PRIMARY KEY(goal_id, evidence_kind, evidence_id),
                     FOREIGN KEY(goal_id) REFERENCES goals(goal_id));
                 CREATE TABLE goal_dag_revisions(
                     goal_id BLOB NOT NULL, dag_revision INTEGER NOT NULL,
                     PRIMARY KEY(goal_id, dag_revision),
                     FOREIGN KEY(goal_id) REFERENCES goals(goal_id));
                 CREATE TABLE goal_dag_nodes(
                     goal_id BLOB NOT NULL, dag_revision INTEGER NOT NULL,
                     node_id BLOB NOT NULL,
                     PRIMARY KEY(goal_id, dag_revision, node_id),
                     FOREIGN KEY(goal_id, dag_revision)
                         REFERENCES goal_dag_revisions(goal_id, dag_revision));
                 CREATE TABLE goal_dag_node_evidence_refs(
                     goal_id BLOB NOT NULL, dag_revision INTEGER NOT NULL,
                     node_id BLOB NOT NULL, evidence_kind INTEGER NOT NULL,
                     evidence_id BLOB NOT NULL,
                     PRIMARY KEY(goal_id, dag_revision, node_id, evidence_kind, evidence_id),
                     FOREIGN KEY(goal_id, dag_revision, node_id)
                         REFERENCES goal_dag_nodes(goal_id, dag_revision, node_id),
                     FOREIGN KEY(goal_id, evidence_kind, evidence_id)
                         REFERENCES goal_evidence_refs(goal_id, evidence_kind, evidence_id));
                 CREATE TABLE goal_dag_node_acceptance(goal_id BLOB);
                 CREATE TABLE goal_dag_edges(goal_id BLOB);
                 CREATE TABLE goal_dag_node_lineage(goal_id BLOB);
                 CREATE TABLE goal_dag_heads(goal_id BLOB);
                 CREATE TABLE agent_dag_plan_ledger(request_id BLOB PRIMARY KEY, goal_id BLOB);
                 CREATE TABLE agent_dag_plan_sessions(
                     request_id BLOB PRIMARY KEY REFERENCES agent_dag_plan_ledger(request_id),
                     session_id BLOB NOT NULL);
                 CREATE TABLE agent_assignments(assignment_id BLOB, goal_id BLOB);
                 CREATE TABLE agent_assignment_sources(assignment_id BLOB);",
        )?;
        let goal = GoalId::from_uuid(Uuid::from_u128(3));
        let evidence_id = Uuid::from_u128(4).into_bytes();
        let node_id = Uuid::from_u128(5).into_bytes();
        connection.execute(
            "INSERT INTO goals(goal_id) VALUES (?1)",
            params![goal.into_uuid().as_bytes()],
        )?;
        connection.execute(
            "INSERT INTO goal_evidence_refs(goal_id, evidence_kind, evidence_id)
                 VALUES (?1, 0, ?2)",
            params![goal.into_uuid().as_bytes(), evidence_id.as_slice()],
        )?;
        connection.execute(
            "INSERT INTO goal_dag_revisions(goal_id, dag_revision) VALUES (?1, 1)",
            params![goal.into_uuid().as_bytes()],
        )?;
        connection.execute(
            "INSERT INTO goal_dag_nodes(goal_id, dag_revision, node_id)
                 VALUES (?1, 1, ?2)",
            params![goal.into_uuid().as_bytes(), node_id.as_slice()],
        )?;
        connection.execute(
            "INSERT INTO goal_dag_node_evidence_refs(
                     goal_id, dag_revision, node_id, evidence_kind, evidence_id
                 ) VALUES (?1, 1, ?2, 0, ?3)",
            params![
                goal.into_uuid().as_bytes(),
                node_id.as_slice(),
                evidence_id.as_slice(),
            ],
        )?;
        let request_id = Uuid::from_u128(6).into_bytes();
        let session_id = Uuid::from_u128(7).into_bytes();
        connection.execute(
            "INSERT INTO agent_dag_plan_ledger(request_id, goal_id) VALUES (?1, ?2)",
            params![request_id.as_slice(), goal.into_uuid().as_bytes()],
        )?;
        connection.execute(
            "INSERT INTO agent_dag_plan_sessions(request_id, session_id) VALUES (?1, ?2)",
            params![request_id.as_slice(), session_id.as_slice()],
        )?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        delete_dag_closure(&transaction, goal)?;
        let mut closure = Closure::new(request(GoalDeletionTarget::Goal, None)?);
        closure.evidence.push(EvidenceRow {
            kind: 0,
            id: evidence_id.to_vec(),
            shared: false,
        });
        delete_goal_evidence_links(&transaction, &closure)?;
        transaction.execute(
            "DELETE FROM goals WHERE goal_id = ?1",
            params![goal.into_uuid().as_bytes()],
        )?;
        transaction.commit()?;
        assert_eq!(
            connection
                .query_row("PRAGMA foreign_key_check", [], |_| Ok(0_i64))
                .optional()?,
            None
        );
        Ok(())
    }
}
