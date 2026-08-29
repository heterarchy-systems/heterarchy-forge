//! Durable semantic state for one explicitly selected Workspace.
//!
//! The Global Registry owns Location metadata only. This adapter owns the
//! database below one `WorkspaceStateLayout` and isolates Workspace identity and
//! Activity state from every other Workspace.

use std::borrow::Borrow;
use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::io;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use forge_domain::{
    AbandonDiffEvidence, ActivityId, ActivityLeaseBatchLimit, ActivityLeaseProjection,
    ActivityLeaseRevision, ActivityListLimit, ActivityProjection, ActivityRevision, ActivityState,
    AppliedHarness, ApprovalDecision, ApprovalRequestId, ApprovalRevision, AutoApprovalScope,
    AutoApprovalScopeId, BeginDiffEvidence, BeginDiffPurge, BeginExecution, BeginFileMutation,
    BeginFileMutationResult, BeginFileMutationStatus, BootstrapActivity, BootstrapActivityDecision,
    CheckpointId, CheckpointRestoreId, CheckpointRestoreRevision, CheckpointRevision,
    ClaimRecoveryLease, CloseActivity, CompleteDiffEvidence, CompleteDiffPurge, CompleteExecution,
    CompleteFileMutation, CreateActivity, DagHeadRevision, DagRevision, DagRevisionNumber, DiffId,
    DiffListLimit, DiffPurgeRecord, DiffRetentionKeepCount, DiffRetentionPlan,
    DiffRetentionPlanLimit, EstablishWorkspace, ExecutionAuthorizationRequest, ExecutionGrant,
    ExecutionGrantId, ExecutionGrantRevision, ExecutionId, ExecutionListLimit, FailExecution,
    FailFileMutation, FileMutationRecord, GoalEvidenceRef, GoalId, GoalListLimit, GoalReview,
    GoalRevision, GoalWorkAttribution, HarnessRevision, LocationId, MarkExecutionRunning,
    PolicyRevision, ReconcileExpiredActivities, RecoveryMaintenanceLease, RegisteredActivity,
    RegisteredApprovalRequest, RegisteredCheckpoint, RegisteredCheckpointRestore,
    RegisteredDagNode, RegisteredDiffEvidence, RegisteredExecution, RegisteredGoal,
    RegisteredWorkspace, ReleaseActivityLease, ReleaseRecoveryLease, RenewActivityLease,
    RenewRecoveryLease, RuntimeInstanceId, SetActivityState, TimestampMillis, WorkspaceId,
    WorkspacePolicy, WorkspaceRevision, WorkspaceRoot, WorkspaceRootDecision,
    WorkspaceRootDecisionError, WorkspaceRootFingerprint, decide_bootstrap_activity,
    decide_workspace_root,
};
use forge_workspace::{ExistingWorkspaceStateLayout, StateLayoutError, WorkspaceStateLayout};
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Row, Rows, Transaction, TransactionBehavior, params,
};
use thiserror::Error;
use uuid::Uuid;

use crate::workspace_agent_dag::{self, AgentDagReplanCommitResult, AgentDagStoreError};
use crate::workspace_agents::{self, AgentStoreError};
use crate::workspace_approvals::{self, ApprovalStoreError};
use crate::workspace_changesets::{self, ChangeSetStoreError};
use crate::workspace_checkpoints::{self, CheckpointDoctorReport, CheckpointStoreError};
use crate::workspace_dags::{self, DagDoctorReport};
use crate::workspace_diffs::{self, DiffDoctorReport, DiffStoreError};
use crate::workspace_executions::{self, ExecutionStoreError};
use crate::workspace_goals::{self, GoalCompletionReceipt, GoalEvidenceRecord, GoalStoreError};
use crate::workspace_harness::{self, HarnessStoreError};
use crate::workspace_harness_verifiers::{self, HarnessVerifierStoreError};
use crate::workspace_recovery::{self, RecoveryStoreError};

/// `SQLite` application marker for Workspace-local databases.
///
/// This is deliberately different from the Global Registry marker.
pub const WORKSPACE_APPLICATION_ID: i64 = 0x4846_5753;

const CURRENT_SCHEMA_VERSION: i64 = 16;
const HARNESS_VERIFIER_PREVIOUS_SCHEMA_VERSION: i64 = 13;
const AGENT_PREVIOUS_SCHEMA_VERSION: i64 = 14;
const AGENT_DAG_PREVIOUS_SCHEMA_VERSION: i64 = 15;
const HARNESS_PREVIOUS_SCHEMA_VERSION: i64 = 12;
const RESTORE_PROVENANCE_PREVIOUS_SCHEMA_VERSION: i64 = 11;
const RECOVERY_PREVIOUS_SCHEMA_VERSION: i64 = 10;
const CHECKPOINT_SCHEMA_VERSION: i64 = 7;
const GOAL_PREVIOUS_SCHEMA_VERSION: i64 = 8;
const DAG_PREVIOUS_SCHEMA_VERSION: i64 = 9;
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_SCHEMA_SQL_BYTES: usize = 16 * 1024;
const MAX_SCHEMA_METADATA_ROWS: usize = 256;
const MAX_SCHEMA_NAME_BYTES: usize = 256;
const ID_BYTES: usize = 16;
const ID_BYTES_I64: i64 = 16;
const FINGERPRINT_BYTES: usize = 16;
const FINGERPRINT_BYTES_I64: i64 = 16;
const MAX_WORKSPACE_ROOT_BYTES: usize = 4_096;
const MAX_DOCTOR_STALE_ROWS: usize = 256;
const DOCTOR_STALE_PROBE_ROWS: usize = MAX_DOCTOR_STALE_ROWS + 1;
const MAX_DOCTOR_SNAPSHOT_BYTES: u64 = 512 * 1024 * 1024;

const EXPECTED_WORKSPACE_TABLE_SQL: &str = "CREATE TABLE workspace (singleton INTEGER PRIMARY KEY CHECK(singleton = 1), workspace_id BLOB NOT NULL UNIQUE CHECK(length(workspace_id) = 16), location_id BLOB NOT NULL CHECK(length(location_id) = 16), root_path BLOB NOT NULL, root_fingerprint BLOB NOT NULL CHECK(length(root_fingerprint) = 16), created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0), updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0), revision INTEGER NOT NULL CHECK(revision >= 1))";
const EXPECTED_V1_ACTIVITIES_TABLE_SQL: &str = "CREATE TABLE activities (activity_id BLOB PRIMARY KEY NOT NULL CHECK(length(activity_id) = 16), workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id), state INTEGER NOT NULL CHECK(state IN (0, 1)), created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0), updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0), revision INTEGER NOT NULL CHECK(revision >= 1))";
const EXPECTED_ACTIVITIES_TABLE_SQL: &str = "CREATE TABLE activities (activity_id BLOB PRIMARY KEY NOT NULL CHECK(length(activity_id) = 16), workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id), state INTEGER NOT NULL CHECK(state IN (0, 1, 2)), created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0), updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0), revision INTEGER NOT NULL CHECK(revision >= 1), lease_owner_id BLOB CHECK(lease_owner_id IS NULL OR length(lease_owner_id) = 16), lease_until_ms INTEGER CHECK(lease_until_ms IS NULL OR lease_until_ms >= 0), lease_revision INTEGER NOT NULL CHECK(lease_revision >= 1), CHECK((lease_owner_id IS NULL) = (lease_until_ms IS NULL)))";
const EXPECTED_ACTIVITIES_INDEX_SQL: &str = "CREATE INDEX activities_workspace_updated_idx ON activities(workspace_id, updated_at_ms DESC, activity_id DESC)";
const EXPECTED_ACTIVITIES_LEASE_INDEX_SQL: &str = "CREATE INDEX activities_workspace_lease_idx ON activities(workspace_id, state, lease_until_ms, activity_id)";

const EXPECTED_WORKSPACE_COLUMNS: [(&str, &str, i64, i64); 8] = [
    ("singleton", "INTEGER", 0, 1),
    ("workspace_id", "BLOB", 1, 0),
    ("location_id", "BLOB", 1, 0),
    ("root_path", "BLOB", 1, 0),
    ("root_fingerprint", "BLOB", 1, 0),
    ("created_at_ms", "INTEGER", 1, 0),
    ("updated_at_ms", "INTEGER", 1, 0),
    ("revision", "INTEGER", 1, 0),
];
const EXPECTED_V1_ACTIVITY_COLUMNS: [(&str, &str, i64, i64); 6] = [
    ("activity_id", "BLOB", 1, 1),
    ("workspace_id", "BLOB", 1, 0),
    ("state", "INTEGER", 1, 0),
    ("created_at_ms", "INTEGER", 1, 0),
    ("updated_at_ms", "INTEGER", 1, 0),
    ("revision", "INTEGER", 1, 0),
];
const EXPECTED_ACTIVITY_COLUMNS: [(&str, &str, i64, i64); 9] = [
    ("activity_id", "BLOB", 1, 1),
    ("workspace_id", "BLOB", 1, 0),
    ("state", "INTEGER", 1, 0),
    ("created_at_ms", "INTEGER", 1, 0),
    ("updated_at_ms", "INTEGER", 1, 0),
    ("revision", "INTEGER", 1, 0),
    ("lease_owner_id", "BLOB", 0, 0),
    ("lease_until_ms", "INTEGER", 0, 0),
    ("lease_revision", "INTEGER", 1, 0),
];

const WORKSPACE_BY_SINGLETON_QUERY: &str = "SELECT length(CAST(workspace_id AS BLOB)),
            length(CAST(location_id AS BLOB)),
            length(CAST(root_path AS BLOB)),
            length(CAST(root_fingerprint AS BLOB)),
            workspace_id, location_id, root_path, root_fingerprint,
            created_at_ms, updated_at_ms, revision
        FROM workspace
        WHERE singleton = 1";

const ACTIVITY_BY_ID_QUERY: &str = "SELECT length(CAST(activity_id AS BLOB)),
            length(CAST(workspace_id AS BLOB)),
            length(CAST(lease_owner_id AS BLOB)),
            activity_id, workspace_id, state, created_at_ms, updated_at_ms, revision,
            lease_owner_id, lease_until_ms, lease_revision
        FROM activities
        WHERE activity_id = ?1";

const ACTIVITY_LIST_QUERY: &str = "SELECT length(CAST(activity_id AS BLOB)),
            length(CAST(workspace_id AS BLOB)),
            length(CAST(lease_owner_id AS BLOB)),
            activity_id, workspace_id, state, created_at_ms, updated_at_ms, revision,
            lease_owner_id, lease_until_ms, lease_revision
        FROM activities
        ORDER BY workspace_id ASC, updated_at_ms DESC, activity_id DESC
        LIMIT ?1";

/// Health projection for a Workspace-local semantic database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceStoreHealth {
    schema_version: i64,
    application_id: i64,
    journal_mode: String,
    foreign_keys_enabled: bool,
    synchronous: i64,
}

impl WorkspaceStoreHealth {
    pub const fn schema_version(&self) -> i64 {
        self.schema_version
    }

    pub const fn application_id(&self) -> i64 {
        self.application_id
    }

    pub fn journal_mode(&self) -> &str {
        &self.journal_mode
    }

    pub const fn foreign_keys_enabled(&self) -> bool {
        self.foreign_keys_enabled
    }

    pub const fn synchronous(&self) -> i64 {
        self.synchronous
    }

    pub const fn synchronous_full(&self) -> bool {
        self.synchronous == 2
    }
}

/// Result of one bounded `SQLite` consistency probe performed by the read-only
/// Workspace Doctor.  `SQLite`'s diagnostic strings are intentionally not
/// retained because they can contain unbounded/caller-controlled text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceDoctorIntegrity {
    Passed,
    Failed,
}

impl WorkspaceDoctorIntegrity {
    pub const fn passed(self) -> bool {
        matches!(self, Self::Passed)
    }
}

/// Bounded count returned by a stale-state Doctor query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkspaceDoctorCount {
    count: u16,
    truncated: bool,
}

impl WorkspaceDoctorCount {
    const fn new(count: u16, truncated: bool) -> Self {
        Self { count, truncated }
    }

    /// Number of rows observed, capped at the Doctor bound.
    pub const fn count(self) -> u16 {
        self.count
    }

    /// Whether at least one additional row existed beyond the reported cap.
    pub const fn truncated(self) -> bool {
        self.truncated
    }

    pub const fn is_empty(self) -> bool {
        self.count == 0 && !self.truncated
    }
}

/// Overall read-only Workspace Doctor outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceDoctorOutcome {
    Healthy,
    RecoveryRequired,
    Damaged,
}

/// Bounded, metadata-only health projection for one existing Workspace
/// database, including current Diff artifact expectations.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceDoctorReport {
    schema_version: i64,
    application_id: i64,
    location_id: LocationId,
    workspace_id: WorkspaceId,
    workspace_revision: WorkspaceRevision,
    quick_check: WorkspaceDoctorIntegrity,
    foreign_key_check: WorkspaceDoctorIntegrity,
    stale_executions: WorkspaceDoctorCount,
    stale_checkpoint_restores: WorkspaceDoctorCount,
    checkpoint_references: CheckpointDoctorReport,
    dag_semantics: DagDoctorReport,
    diff_references: DiffDoctorReport,
    outcome: WorkspaceDoctorOutcome,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WorkspaceDoctorIdentity {
    schema_version: i64,
    application_id: i64,
    location_id: LocationId,
    workspace_id: WorkspaceId,
    workspace_revision: WorkspaceRevision,
}

#[derive(Debug)]
struct ReadOnlyWorkspaceIdentitySnapshot {
    schema_version: i64,
    application_id: i64,
    workspace: RegisteredWorkspace,
}

struct WorkspaceDoctorObservations {
    quick_check: WorkspaceDoctorIntegrity,
    foreign_key_check: WorkspaceDoctorIntegrity,
    stale_executions: WorkspaceDoctorCount,
    stale_checkpoint_restores: WorkspaceDoctorCount,
    checkpoint_references: CheckpointDoctorReport,
    dag_semantics: DagDoctorReport,
    diff_references: DiffDoctorReport,
}

impl WorkspaceDoctorReport {
    fn new(identity: WorkspaceDoctorIdentity, observations: WorkspaceDoctorObservations) -> Self {
        let WorkspaceDoctorObservations {
            quick_check,
            foreign_key_check,
            stale_executions,
            stale_checkpoint_restores,
            checkpoint_references,
            dag_semantics,
            diff_references,
        } = observations;
        let damaged =
            !quick_check.passed() || !foreign_key_check.passed() || dag_semantics.is_damaged();
        let starting_checkpoint = checkpoint_references
            .references()
            .iter()
            .any(|reference| reference.state() == forge_domain::CheckpointState::Starting);
        let recovery_required = !stale_executions.is_empty()
            || stale_executions.truncated()
            || !stale_checkpoint_restores.is_empty()
            || stale_checkpoint_restores.truncated()
            || starting_checkpoint;
        let outcome = if damaged {
            WorkspaceDoctorOutcome::Damaged
        } else if recovery_required {
            WorkspaceDoctorOutcome::RecoveryRequired
        } else {
            WorkspaceDoctorOutcome::Healthy
        };
        Self {
            schema_version: identity.schema_version,
            application_id: identity.application_id,
            location_id: identity.location_id,
            workspace_id: identity.workspace_id,
            workspace_revision: identity.workspace_revision,
            quick_check,
            foreign_key_check,
            stale_executions,
            stale_checkpoint_restores,
            checkpoint_references,
            dag_semantics,
            diff_references,
            outcome,
        }
    }

    pub const fn schema_version(&self) -> i64 {
        self.schema_version
    }

    pub const fn application_id(&self) -> i64 {
        self.application_id
    }

    pub const fn location_id(&self) -> LocationId {
        self.location_id
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn workspace_revision(&self) -> WorkspaceRevision {
        self.workspace_revision
    }

    pub const fn quick_check(&self) -> WorkspaceDoctorIntegrity {
        self.quick_check
    }

    pub const fn foreign_key_check(&self) -> WorkspaceDoctorIntegrity {
        self.foreign_key_check
    }

    pub const fn stale_executions(&self) -> WorkspaceDoctorCount {
        self.stale_executions
    }

    pub const fn stale_checkpoint_restores(&self) -> WorkspaceDoctorCount {
        self.stale_checkpoint_restores
    }

    pub const fn checkpoint_references(&self) -> &CheckpointDoctorReport {
        &self.checkpoint_references
    }

    pub const fn dag_semantics(&self) -> &DagDoctorReport {
        &self.dag_semantics
    }

    pub const fn outcome(&self) -> WorkspaceDoctorOutcome {
        self.outcome
    }

    pub const fn diff_references(&self) -> &DiffDoctorReport {
        &self.diff_references
    }

    pub const fn is_healthy(&self) -> bool {
        matches!(self.outcome, WorkspaceDoctorOutcome::Healthy)
    }

    pub const fn requires_recovery(&self) -> bool {
        matches!(self.outcome, WorkspaceDoctorOutcome::RecoveryRequired)
    }

    pub const fn is_damaged(&self) -> bool {
        matches!(self.outcome, WorkspaceDoctorOutcome::Damaged)
    }
}

/// Atomic `ChangeSet`/Diff intent result. `None` is reserved for a migrated v3
/// terminal `ChangeSet` that predates Diff Evidence.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeginFileMutationDiffResult {
    file: BeginFileMutationResult,
    diff: Option<RegisteredDiffEvidence>,
}

impl BeginFileMutationDiffResult {
    const fn new(file: BeginFileMutationResult, diff: Option<RegisteredDiffEvidence>) -> Self {
        Self { file, diff }
    }

    pub const fn file(&self) -> &BeginFileMutationResult {
        &self.file
    }

    pub const fn diff(&self) -> Option<&RegisteredDiffEvidence> {
        self.diff.as_ref()
    }

    pub const fn status(&self) -> BeginFileMutationStatus {
        self.file.status()
    }

    pub const fn record(&self) -> &FileMutationRecord {
        self.file.record()
    }
}

/// Atomic terminal `ChangeSet`/Diff projection.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileMutationDiffRecord {
    file: FileMutationRecord,
    diff: RegisteredDiffEvidence,
}

impl FileMutationDiffRecord {
    const fn new(file: FileMutationRecord, diff: RegisteredDiffEvidence) -> Self {
        Self { file, diff }
    }

    pub const fn file(&self) -> &FileMutationRecord {
        &self.file
    }

    pub const fn diff(&self) -> &RegisteredDiffEvidence {
        &self.diff
    }

    pub const fn change_set(&self) -> &forge_domain::RegisteredChangeSet {
        self.file.change_set()
    }

    pub const fn mutation(&self) -> &forge_domain::RegisteredFileMutation {
        self.file.mutation()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    links: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
}

impl DirectoryIdentity {
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

impl FileIdentity {
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            links: metadata.nlink(),
        }
    }
}

/// Build a `SQLite` URI without lossy path conversion.  Paths are encoded from
/// their native bytes so non-UTF-8 Workspace roots remain addressable.
fn sqlite_uri(path: &Path, query: &str) -> String {
    let mut uri = String::from("file:");
    for byte in path.as_os_str().as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-') {
            uri.push(char::from(*byte));
        } else {
            const HEX: &[u8; 16] = b"0123456789ABCDEF";
            uri.push('%');
            uri.push(char::from(HEX[usize::from(*byte >> 4)]));
            uri.push(char::from(HEX[usize::from(*byte & 0x0f)]));
        }
    }
    uri.push('?');
    uri.push_str(query);
    uri
}

/// Build an immutable `SQLite` URI.  Immutable mode never takes a write lock
/// and therefore cannot create WAL or SHM sidecars while a read-only Workspace
/// is being inspected.
fn sqlite_read_only_uri(path: &Path) -> String {
    sqlite_uri(path, "immutable=1")
}

/// Build a normal read-only URI for a database whose existing WAL and SHM
/// sidecars are available.  Unlike immutable mode this connection can see
/// committed frames in the WAL snapshot.
fn sqlite_read_only_wal_uri(path: &Path) -> String {
    sqlite_uri(path, "mode=ro")
}

struct ReadOnlyDoctorDatabase {
    path: PathBuf,
    state_root: PathBuf,
    state_root_identity: DirectoryIdentity,
    workspace_root: PathBuf,
    root_fingerprint: WorkspaceRootFingerprint,
    database_identity: FileIdentity,
    database_observation: DoctorFileObservation,
    wal_identity: Option<FileIdentity>,
    wal_observation: Option<DoctorFileObservation>,
    shm_identity: Option<FileIdentity>,
    shm_observation: Option<DoctorFileObservation>,
    connection: Connection,
    _snapshot: Option<DoctorSnapshot>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DoctorFileObservation {
    identity: FileIdentity,
    size: u64,
    modified: SystemTime,
}

/// Opaque source-file observation captured with a read-only Workspace Doctor
/// report. Callers can revalidate it after external filesystem/Git observation
/// without holding a `SQLite` transaction across those effects.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkspaceDoctorSourceObservation {
    state_root_identity: DirectoryIdentity,
    root_fingerprint: WorkspaceRootFingerprint,
    database_identity: FileIdentity,
    database_observation: DoctorFileObservation,
    wal_identity: Option<FileIdentity>,
    wal_observation: Option<DoctorFileObservation>,
    shm_identity: Option<FileIdentity>,
    shm_observation: Option<DoctorFileObservation>,
}

impl WorkspaceDoctorSourceObservation {
    /// Return whether the live Workspace database source still matches the
    /// exact root/database/WAL/SHM observation that produced the Doctor report.
    /// Any re-observation failure is conservatively treated as changed.
    pub fn is_unchanged(self, layout: &ExistingWorkspaceStateLayout) -> bool {
        self.ensure_unchanged(layout).is_ok()
    }

    fn ensure_unchanged(
        self,
        layout: &ExistingWorkspaceStateLayout,
    ) -> Result<(), WorkspaceStoreError> {
        let database_path = layout.database_path();
        ensure_live_paths(WorkspaceLiveBinding {
            state_root: layout.state_root(),
            state_root_identity: self.state_root_identity,
            workspace_root: layout.workspace_root(),
            root_fingerprint: self.root_fingerprint,
            database_path: &database_path,
            database_identity: self.database_identity,
            wal_identity: self.wal_identity,
            shm_identity: self.shm_identity,
        })?;
        for (path, expected) in [
            (&database_path, Some(self.database_observation)),
            (&sidecar_path(&database_path, "-wal"), self.wal_observation),
            (&sidecar_path(&database_path, "-shm"), self.shm_observation),
        ] {
            if doctor_file_observation(path, true)? != expected {
                return Err(WorkspaceStoreError::DatabasePathChanged(path.clone()));
            }
        }
        Ok(())
    }
}

/// Private source snapshot used when a live WAL is present.  Opening a
/// read-only WAL database may update `SQLite`'s shared-memory read marks on some
/// VFSes, so the source files are never opened by the Doctor itself.  The main
/// database and WAL are copied to a canonical temporary directory; `SQLite`
/// rebuilds a private temporary SHM index there.  Source observations are
/// checked before and after the copy/open and any concurrent change fails
/// closed rather than producing an unverified report.
#[derive(Debug)]
struct DoctorSnapshot {
    directory: PathBuf,
}

impl DoctorSnapshot {
    fn create(source_database: &Path, source_wal: &Path) -> Result<Self, WorkspaceStoreError> {
        validate_doctor_snapshot_size(
            fs::metadata(source_database)
                .map_err(|source| WorkspaceStoreError::DatabasePathMetadata {
                    path: source_database.to_path_buf(),
                    source,
                })?
                .len(),
            fs::metadata(source_wal)
                .map_err(|source| WorkspaceStoreError::DatabasePathMetadata {
                    path: source_wal.to_path_buf(),
                    source,
                })?
                .len(),
        )?;
        let temp_dir = std::env::temp_dir();
        let temp_root = fs::canonicalize(&temp_dir).map_err(|source| {
            WorkspaceStoreError::DoctorSnapshotIo {
                operation: "resolve temporary root",
                path: temp_dir,
                source,
            }
        })?;
        let directory = temp_root.join(format!("heterarchy-forge-doctor-{}", Uuid::now_v7()));
        fs::create_dir(&directory).map_err(|source| WorkspaceStoreError::DoctorSnapshotIo {
            operation: "create directory",
            path: directory.clone(),
            source,
        })?;
        let copy = |source_path: &Path, name: &str| -> Result<(), WorkspaceStoreError> {
            fs::copy(source_path, directory.join(name)).map_err(|source| {
                WorkspaceStoreError::DoctorSnapshotIo {
                    operation: "copy database artifact",
                    path: source_path.to_path_buf(),
                    source,
                }
            })?;
            Ok(())
        };
        if let Err(error) = copy(source_database, "state.sqlite3")
            .and_then(|()| copy(source_wal, "state.sqlite3-wal"))
        {
            let _ignored = fs::remove_dir_all(&directory);
            return Err(error);
        }
        Ok(Self { directory })
    }

    fn database_path(&self) -> PathBuf {
        self.directory.join("state.sqlite3")
    }
}

fn validate_doctor_snapshot_size(
    database_bytes: u64,
    wal_bytes: u64,
) -> Result<(), WorkspaceStoreError> {
    let actual = database_bytes.checked_add(wal_bytes).ok_or(
        WorkspaceStoreError::DoctorSnapshotTooLarge {
            actual: u64::MAX,
            maximum: MAX_DOCTOR_SNAPSHOT_BYTES,
        },
    )?;
    if actual > MAX_DOCTOR_SNAPSHOT_BYTES {
        return Err(WorkspaceStoreError::DoctorSnapshotTooLarge {
            actual,
            maximum: MAX_DOCTOR_SNAPSHOT_BYTES,
        });
    }
    Ok(())
}

impl Drop for DoctorSnapshot {
    fn drop(&mut self) {
        let _ignored = fs::remove_dir_all(&self.directory);
    }
}

impl ReadOnlyDoctorDatabase {
    fn open(layout: &ExistingWorkspaceStateLayout) -> Result<Self, WorkspaceStoreError> {
        let path = layout.database_path();
        let state_root = layout.state_root().to_path_buf();
        let state_root_identity = inspect_directory(&state_root)?;
        let root_fingerprint = layout
            .root_fingerprint()
            .map_err(|source| WorkspaceStoreError::LayoutFingerprintObservation { source })?;
        path_to_bytes_bounded(layout.workspace_root())?;

        let database_observation = doctor_file_observation(&path, true)?
            .ok_or_else(|| WorkspaceStoreError::MissingDatabase(path.clone()))?;
        let database_identity = database_observation.identity;
        let wal_path = sidecar_path(&path, "-wal");
        let shm_path = sidecar_path(&path, "-shm");
        let wal_observation = doctor_file_observation(&wal_path, true)?;
        let shm_observation = doctor_file_observation(&shm_path, true)?;
        let wal_identity = wal_observation.map(|observation| observation.identity);
        let shm_identity = shm_observation.map(|observation| observation.identity);
        if wal_identity.is_none() != shm_identity.is_none() {
            return Err(WorkspaceStoreError::DatabaseSidecarPairMismatch {
                wal: wal_path,
                shm: shm_path,
            });
        }
        if wal_identity.is_some() {
            fs::File::open(&shm_path).map_err(|source| {
                WorkspaceStoreError::DatabasePathMetadata {
                    path: shm_path.clone(),
                    source,
                }
            })?;
        }

        let flags = OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NOFOLLOW
            | OpenFlags::SQLITE_OPEN_URI;
        let snapshot = if wal_identity.is_some() {
            Some(DoctorSnapshot::create(&path, &wal_path)?)
        } else {
            None
        };
        let connection_path = snapshot
            .as_ref()
            .map_or_else(|| path.clone(), DoctorSnapshot::database_path);
        let uri = if snapshot.is_some() {
            sqlite_read_only_wal_uri(&connection_path)
        } else {
            sqlite_read_only_uri(&connection_path)
        };
        let connection = Connection::open_with_flags(&uri, flags).map_err(|source| {
            WorkspaceStoreError::Open {
                path: path.clone(),
                source,
            }
        })?;
        let database = Self {
            path,
            state_root,
            state_root_identity,
            workspace_root: layout.workspace_root().to_path_buf(),
            root_fingerprint,
            database_identity,
            database_observation,
            wal_identity,
            wal_observation,
            shm_identity,
            shm_observation,
            connection,
            _snapshot: snapshot,
        };
        database.ensure_unchanged()?;
        // Both pragmas are connection-local.  They cannot create or modify
        // database/WAL/SHM state and are required before the Doctor probes.
        database.connection.busy_timeout(BUSY_TIMEOUT)?;
        database
            .connection
            .pragma_update(None, "foreign_keys", true)?;
        database
            .connection
            .pragma_update(None, "query_only", true)?;
        database.ensure_unchanged()?;
        Ok(database)
    }

    fn source_observation(&self) -> WorkspaceDoctorSourceObservation {
        WorkspaceDoctorSourceObservation {
            state_root_identity: self.state_root_identity,
            root_fingerprint: self.root_fingerprint,
            database_identity: self.database_identity,
            database_observation: self.database_observation,
            wal_identity: self.wal_identity,
            wal_observation: self.wal_observation,
            shm_identity: self.shm_identity,
            shm_observation: self.shm_observation,
        }
    }

    fn ensure_unchanged(&self) -> Result<(), WorkspaceStoreError> {
        ensure_live_paths(WorkspaceLiveBinding {
            state_root: &self.state_root,
            state_root_identity: self.state_root_identity,
            workspace_root: &self.workspace_root,
            root_fingerprint: self.root_fingerprint,
            database_path: &self.path,
            database_identity: self.database_identity,
            wal_identity: self.wal_identity,
            shm_identity: self.shm_identity,
        })?;
        for (path, expected) in [
            (&self.path, Some(self.database_observation)),
            (&sidecar_path(&self.path, "-wal"), self.wal_observation),
            (&sidecar_path(&self.path, "-shm"), self.shm_observation),
        ] {
            if doctor_file_observation(path, true)? != expected {
                return Err(WorkspaceStoreError::DatabasePathChanged(path.clone()));
            }
        }
        Ok(())
    }
}

fn doctor_file_observation(
    path: &Path,
    allow_missing: bool,
) -> Result<Option<DoctorFileObservation>, WorkspaceStoreError> {
    let Some(identity) = inspect_regular_file(path, allow_missing)? else {
        return Ok(None);
    };
    let metadata =
        fs::metadata(path).map_err(|source| WorkspaceStoreError::DatabasePathMetadata {
            path: path.to_path_buf(),
            source,
        })?;
    let modified =
        metadata
            .modified()
            .map_err(|source| WorkspaceStoreError::DatabasePathMetadata {
                path: path.to_path_buf(),
                source,
            })?;
    Ok(Some(DoctorFileObservation {
        identity,
        size: metadata.len(),
        modified,
    }))
}

fn doctor_quick_check(
    connection: &Connection,
) -> Result<WorkspaceDoctorIntegrity, WorkspaceStoreError> {
    let mut statement = connection.prepare("PRAGMA quick_check(1)")?;
    let mut rows = statement.query([])?;
    let Some(row) = rows.next()? else {
        return Ok(WorkspaceDoctorIntegrity::Failed);
    };
    let result: String = row.get(0)?;
    Ok(if result.eq_ignore_ascii_case("ok") {
        WorkspaceDoctorIntegrity::Passed
    } else {
        WorkspaceDoctorIntegrity::Failed
    })
}

fn doctor_foreign_key_check(
    connection: &Connection,
) -> Result<WorkspaceDoctorIntegrity, WorkspaceStoreError> {
    let mut statement = connection.prepare("PRAGMA foreign_key_check")?;
    let mut rows = statement.query([])?;
    Ok(if rows.next()?.is_some() {
        WorkspaceDoctorIntegrity::Failed
    } else {
        WorkspaceDoctorIntegrity::Passed
    })
}

fn doctor_stale_count(
    connection: &Connection,
    query: &'static str,
) -> Result<WorkspaceDoctorCount, WorkspaceStoreError> {
    let mut statement = connection.prepare(query)?;
    let mut rows = statement.query([])?;
    let mut count = 0_usize;
    while rows.next()?.is_some() {
        count = count.saturating_add(1);
        if count == DOCTOR_STALE_PROBE_ROWS {
            return Ok(WorkspaceDoctorCount::new(
                u16::try_from(MAX_DOCTOR_STALE_ROWS).map_err(|_| {
                    WorkspaceStoreError::CorruptRecord {
                        field: "doctor.stale_count",
                        detail: "Doctor bound exceeds u16".to_owned(),
                    }
                })?,
                true,
            ));
        }
    }
    Ok(WorkspaceDoctorCount::new(
        u16::try_from(count).map_err(|_| WorkspaceStoreError::CorruptRecord {
            field: "doctor.stale_count",
            detail: "Doctor count exceeds u16".to_owned(),
        })?,
        false,
    ))
}

/// SQLite-backed Workspace semantic authority.
pub struct WorkspaceStore {
    path: PathBuf,
    state_root: PathBuf,
    state_root_identity: DirectoryIdentity,
    workspace_root: PathBuf,
    root_fingerprint: WorkspaceRootFingerprint,
    database_identity: FileIdentity,
    wal_identity: Option<FileIdentity>,
    shm_identity: Option<FileIdentity>,
    connection: Connection,
    batch_transaction_count: u64,
}

impl fmt::Debug for WorkspaceStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkspaceStore")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl WorkspaceStore {
    /// Open the database reserved by a layout, establishing or confirming the
    /// supplied Workspace observation.
    pub fn open<C>(layout: &WorkspaceStateLayout, command: C) -> Result<Self, WorkspaceStoreError>
    where
        C: Borrow<EstablishWorkspace>,
    {
        Self::open_or_establish(layout, command)
    }

    /// Open or establish the Workspace identity atomically.
    pub fn open_or_establish<C>(
        layout: &WorkspaceStateLayout,
        command: C,
    ) -> Result<Self, WorkspaceStoreError>
    where
        C: Borrow<EstablishWorkspace>,
    {
        Self::open_or_establish_with_timeout(layout, command, BUSY_TIMEOUT)
    }

    /// Open an already-owned Workspace state database without establishing,
    /// rebinding, or creating any durable identity.
    ///
    /// This is the restart/recovery entry point.  Callers that need to create
    /// a new state directory must use `open_or_establish`; an existing open
    /// rejects a missing database, fresh database, unowned database, and a
    /// missing Workspace identity row.
    pub fn open_existing(
        layout: &ExistingWorkspaceStateLayout,
    ) -> Result<Self, WorkspaceStoreError> {
        Self::open_existing_with_timeout(layout, BUSY_TIMEOUT)
    }

    /// Inspect one already-owned Workspace database without taking a write
    /// connection or changing any on-disk `SQLite` state.
    ///
    /// This is intentionally separate from [`Self::open_existing`], which may
    /// migrate a v1 database and configure a write-capable connection for
    /// restart/recovery.  Read-only workspace listing and resolution must use
    /// this method so observing a candidate cannot create WAL/SHM files,
    /// migrate schema, rebind identity, or otherwise establish authority.
    pub fn inspect_existing_read_only(
        layout: &ExistingWorkspaceStateLayout,
    ) -> Result<RegisteredWorkspace, WorkspaceStoreError> {
        let path = layout.database_path();
        let state_root = layout.state_root().to_path_buf();
        let state_root_identity = inspect_directory(&state_root)?;
        let root_fingerprint = layout
            .root_fingerprint()
            .map_err(|source| WorkspaceStoreError::LayoutFingerprintObservation { source })?;
        path_to_bytes_bounded(layout.workspace_root())?;

        let database_before = inspect_regular_file(&path, true)?;
        let Some(database_before) = database_before else {
            return Err(WorkspaceStoreError::MissingDatabase(path));
        };
        let wal_path = sidecar_path(&path, "-wal");
        let shm_path = sidecar_path(&path, "-shm");
        let wal_before = inspect_regular_file(&wal_path, true)?;
        let shm_before = inspect_regular_file(&shm_path, true)?;

        if wal_before.is_none() != shm_before.is_none() {
            return Err(WorkspaceStoreError::DatabaseSidecarPairMismatch {
                wal: wal_path,
                shm: shm_path,
            });
        }
        if wal_before.is_some() {
            return Err(WorkspaceStoreError::ReadOnlyWalActive {
                wal: wal_path,
                shm: shm_path,
            });
        }
        let flags = OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NOFOLLOW
            | OpenFlags::SQLITE_OPEN_URI;
        let immutable_uri = sqlite_read_only_uri(&path);
        let connection_result = Connection::open_with_flags(&immutable_uri, flags);
        let connection = connection_result.map_err(|source| WorkspaceStoreError::Open {
            path: path.clone(),
            source,
        })?;
        ensure_directory_identity(&state_root, state_root_identity)?;
        ensure_database_identity(&path, database_before)?;
        ensure_sidecar_identities(&wal_path, wal_before, &shm_path, shm_before)?;

        // These pragmas are connection-local and do not write the database.
        // In particular, do not call `configure_connection`: journal_mode and
        // synchronous configuration belong only to the write/recovery path.
        connection.busy_timeout(BUSY_TIMEOUT)?;
        connection.pragma_update(None, "foreign_keys", true)?;
        connection.pragma_update(None, "query_only", true)?;

        let ownership = match inspect_database(&connection) {
            Ok(ownership) => ownership,
            Err(WorkspaceStoreError::UnsupportedSchemaVersion {
                actual,
                maximum_supported,
            }) => {
                return Err(WorkspaceStoreError::UnsupportedForReadOnly {
                    actual,
                    maximum_supported,
                });
            }
            Err(error) => return Err(error),
        };
        if ownership == DatabaseOwnership::Fresh {
            return Err(WorkspaceStoreError::FreshDatabase);
        }
        if let Some(actual) = migration_required_version(ownership) {
            return Err(WorkspaceStoreError::MigrationRequired {
                actual,
                required: CURRENT_SCHEMA_VERSION,
            });
        }

        validate_schema_shape(&connection)?;
        // An immutable SQLite URI reports `journal_mode=delete` even when
        // the write connection uses WAL, because no journal can be opened or
        // changed by this connection.  Runtime durability policy belongs to
        // `open_existing`/`health`; read-only inspection validates ownership
        // and schema without issuing a mutating journal pragma.
        let workspace = query_workspace_row(&connection)?
            .ok_or(WorkspaceStoreError::WorkspaceIdentityMissing)
            .and_then(decode_workspace)?;
        validate_existing_workspace_binding(&workspace, layout, root_fingerprint)?;
        let _recovery_lease = workspace_recovery::get(&connection, workspace.id())?;

        ensure_database_identity(&path, database_before)?;
        ensure_sidecar_identities(&wal_path, wal_before, &shm_path, shm_before)?;
        ensure_directory_identity(&state_root, state_root_identity)?;
        Ok(workspace)
    }

    /// Read only the current durable Workspace identity from an existing state
    /// root, including committed WAL frames when they are present.
    ///
    /// This uses the same immutable/private-snapshot boundary as Doctor but
    /// intentionally skips stale lifecycle, Diff, checkpoint, and DAG scans.
    /// It never initializes, migrates, reconciles, or mutates Workspace state.
    pub fn inspect_existing_identity_read_only(
        layout: &ExistingWorkspaceStateLayout,
    ) -> Result<RegisteredWorkspace, WorkspaceStoreError> {
        let database = ReadOnlyDoctorDatabase::open(layout)?;
        let snapshot = inspect_read_only_workspace_identity(&database, layout)?;
        database.ensure_unchanged()?;
        Ok(snapshot.workspace)
    }

    /// Run a bounded, strictly read-only Doctor against an existing Workspace
    /// database.
    ///
    /// A pair of existing readable `-wal`/`-shm` sidecars is opened with a
    /// normal `SQLite` `mode=ro` URI so the snapshot includes committed WAL
    /// frames.  When no sidecars exist, immutable mode is used to guarantee
    /// that opening the database cannot create them.  A partial or replaced
    /// sidecar pair fails closed.  This method never migrates, configures
    /// journal mode, checkpoints, reconciles, or mutates semantic rows.
    pub fn doctor_existing_read_only(
        layout: &ExistingWorkspaceStateLayout,
    ) -> Result<WorkspaceDoctorReport, WorkspaceStoreError> {
        let (report, _source) = Self::doctor_existing_read_only_observed(layout)?;
        Ok(report)
    }

    /// Run the same bounded read-only Doctor while also returning an opaque
    /// source observation that can be revalidated after external effects.
    pub fn doctor_existing_read_only_observed(
        layout: &ExistingWorkspaceStateLayout,
    ) -> Result<(WorkspaceDoctorReport, WorkspaceDoctorSourceObservation), WorkspaceStoreError>
    {
        let database = ReadOnlyDoctorDatabase::open(layout)?;
        database.ensure_unchanged()?;

        let identity = inspect_read_only_workspace_identity(&database, layout)?;
        let workspace = &identity.workspace;

        let quick_check = doctor_quick_check(&database.connection)?;
        let foreign_key_check = doctor_foreign_key_check(&database.connection)?;
        let stale_executions = doctor_stale_count(
            &database.connection,
            "SELECT 1 FROM executions
             WHERE state IN (0, 1)
             ORDER BY updated_at_ms ASC, execution_id ASC
             LIMIT 257",
        )?;
        let stale_checkpoint_restores = doctor_stale_count(
            &database.connection,
            "SELECT 1 FROM checkpoint_restores
             WHERE state = 0
             ORDER BY updated_at_ms ASC, restore_id ASC
             LIMIT 257",
        )?;
        let checkpoint_references =
            workspace_checkpoints::doctor_references(&database.connection, workspace.id())?;
        let dag_semantics = workspace_dags::doctor_current(&database.connection, workspace.id())?;
        let diff_references = workspace_diffs::doctor_references(&database.connection)?;
        let report = WorkspaceDoctorReport::new(
            WorkspaceDoctorIdentity {
                schema_version: identity.schema_version,
                application_id: identity.application_id,
                location_id: workspace.location_id(),
                workspace_id: workspace.id(),
                workspace_revision: workspace.revision(),
            },
            WorkspaceDoctorObservations {
                quick_check,
                foreign_key_check,
                stale_executions,
                stale_checkpoint_restores,
                checkpoint_references,
                dag_semantics,
                diff_references,
            },
        );
        database.ensure_unchanged()?;
        let source = database.source_observation();
        Ok((report, source))
    }

    fn open_existing_with_timeout(
        layout: &ExistingWorkspaceStateLayout,
        busy_timeout: Duration,
    ) -> Result<Self, WorkspaceStoreError> {
        let path = layout.database_path();
        let state_root = layout.state_root().to_path_buf();
        let state_root_identity = inspect_directory(&state_root)?;
        let root_fingerprint = layout
            .root_fingerprint()
            .map_err(|source| WorkspaceStoreError::LayoutFingerprintObservation { source })?;
        let database_before = inspect_regular_file(&path, true)?;
        if database_before.is_none() {
            return Err(WorkspaceStoreError::MissingDatabase(path));
        }
        let wal_path = sidecar_path(&path, "-wal");
        let shm_path = sidecar_path(&path, "-shm");
        let wal_before = inspect_regular_file(&wal_path, true)?;
        let shm_before = inspect_regular_file(&shm_path, true)?;
        let flags = OpenFlags::default() | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let connection = Connection::open_with_flags(&path, flags).map_err(|source| {
            WorkspaceStoreError::Open {
                path: path.clone(),
                source,
            }
        })?;
        let database_after = inspect_regular_file(&path, false)?.ok_or_else(|| {
            WorkspaceStoreError::DatabasePathInvariant {
                path: path.clone(),
                detail: "SQLite open returned without a regular database file",
            }
        })?;
        if database_before != Some(database_after) {
            return Err(WorkspaceStoreError::DatabasePathChanged(path));
        }
        ensure_directory_identity(&state_root, state_root_identity)?;
        let mut store = Self {
            path,
            state_root,
            state_root_identity,
            workspace_root: layout.workspace_root().to_path_buf(),
            root_fingerprint,
            database_identity: database_after,
            wal_identity: wal_before,
            shm_identity: shm_before,
            connection,
            batch_transaction_count: 0,
        };
        prepare_database(&mut store.connection, busy_timeout, false)?;
        store.ensure_live_binding()?;
        store.validate_runtime_policy()?;
        let workspace = query_workspace_row(&store.connection)?
            .ok_or(WorkspaceStoreError::WorkspaceIdentityMissing)
            .and_then(decode_workspace)?;
        if workspace.root().as_path() != layout.workspace_root()
            || workspace.root_fingerprint() != root_fingerprint
        {
            return Err(WorkspaceStoreError::ExistingWorkspaceBindingMismatch {
                stored_root: workspace.root().as_path().to_path_buf(),
                observed_root: layout.workspace_root().to_path_buf(),
                stored_fingerprint: workspace.root_fingerprint(),
                observed_fingerprint: root_fingerprint,
            });
        }
        let _recovery_lease = workspace_recovery::get(&store.connection, workspace.id())?;
        store.capture_sidecar_identities()?;
        store.ensure_live_binding()?;
        Ok(store)
    }

    fn open_or_establish_with_timeout<C>(
        layout: &WorkspaceStateLayout,
        command: C,
        busy_timeout: Duration,
    ) -> Result<Self, WorkspaceStoreError>
    where
        C: Borrow<EstablishWorkspace>,
    {
        let command = command.borrow();
        if command.root().as_path() != layout.workspace_root() {
            return Err(WorkspaceStoreError::LayoutRootMismatch {
                layout_root: layout.workspace_root().to_path_buf(),
                command_root: command.root().as_path().to_path_buf(),
            });
        }
        let layout_fingerprint = layout
            .root_fingerprint()
            .map_err(|source| WorkspaceStoreError::LayoutFingerprintObservation { source })?;
        if command.root_fingerprint() != layout_fingerprint {
            return Err(WorkspaceStoreError::LayoutFingerprintMismatch {
                expected: layout_fingerprint,
                observed: command.root_fingerprint(),
            });
        }
        path_to_bytes_bounded(command.root().as_path())?;

        let path = layout.database_path();
        let state_root = layout.state_root().to_path_buf();
        let state_root_identity = inspect_directory(&state_root)?;
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .ok_or_else(|| WorkspaceStoreError::MissingParent(path.clone()))?;
        fs::create_dir_all(parent).map_err(|source| WorkspaceStoreError::CreateParent {
            path: parent.to_path_buf(),
            source,
        })?;

        let database_before = inspect_regular_file(&path, true)?;
        let wal_path = sidecar_path(&path, "-wal");
        let shm_path = sidecar_path(&path, "-shm");
        let wal_before = inspect_regular_file(&wal_path, true)?;
        let shm_before = inspect_regular_file(&shm_path, true)?;
        if database_before.is_none() {
            if wal_before.is_some() {
                return Err(WorkspaceStoreError::DatabaseSidecarWithoutMain(wal_path));
            }
            if shm_before.is_some() {
                return Err(WorkspaceStoreError::DatabaseSidecarWithoutMain(shm_path));
            }
        }

        let flags = OpenFlags::default() | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let connection = Connection::open_with_flags(&path, flags).map_err(|source| {
            WorkspaceStoreError::Open {
                path: path.clone(),
                source,
            }
        })?;
        let database_after = inspect_regular_file(&path, false)?.ok_or_else(|| {
            WorkspaceStoreError::DatabasePathInvariant {
                path: path.clone(),
                detail: "SQLite open returned without a regular database file",
            }
        })?;
        if let Some(expected) = database_before
            && expected != database_after
        {
            return Err(WorkspaceStoreError::DatabasePathChanged(path));
        }
        ensure_directory_identity(&state_root, state_root_identity)?;
        let mut store = Self {
            path,
            state_root,
            state_root_identity,
            workspace_root: layout.workspace_root().to_path_buf(),
            root_fingerprint: layout_fingerprint,
            database_identity: database_after,
            wal_identity: wal_before,
            shm_identity: shm_before,
            connection,
            batch_transaction_count: 0,
        };
        prepare_database(&mut store.connection, busy_timeout, true)?;

        store.ensure_live_binding()?;
        store.validate_runtime_policy()?;
        let durable = store.establish_or_confirm(command)?;
        let _recovery_lease = workspace_recovery::get(&store.connection, durable.id())?;
        store.capture_sidecar_identities()?;
        store.ensure_live_binding()?;
        Ok(store)
    }

    /// Validate ownership, schema shape, identity and durability policy.
    pub fn health(&self) -> Result<WorkspaceStoreHealth, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        validate_owned_database(&self.connection)?;
        let policy = runtime_policy(&self.connection)?;
        validate_runtime_policy(&policy)?;
        let raw = query_workspace_row(&self.connection)?.ok_or_else(|| {
            WorkspaceStoreError::DamagedSchema {
                detail: "workspace identity row is missing".to_owned(),
            }
        })?;
        let workspace = decode_workspace(raw)?;
        let _recovery_lease = workspace_recovery::get(&self.connection, workspace.id())?;
        let health = WorkspaceStoreHealth {
            schema_version: schema_version(&self.connection)?,
            application_id: application_id(&self.connection)?,
            journal_mode: policy.journal_mode,
            foreign_keys_enabled: policy.foreign_keys_enabled,
            synchronous: policy.synchronous,
        };
        self.ensure_live_binding()?;
        Ok(health)
    }

    /// Return the durable Workspace projection.
    pub fn workspace(&self) -> Result<RegisteredWorkspace, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let workspace = query_workspace_row(&self.connection)?
            .ok_or(WorkspaceStoreError::WorkspaceIdentityMissing)
            .and_then(decode_workspace)?;
        self.ensure_live_binding()?;
        Ok(workspace)
    }

    /// Repository-style alias for workspace.
    pub fn get_workspace(&self) -> Result<RegisteredWorkspace, WorkspaceStoreError> {
        self.workspace()
    }

    /// Read the exact Harness Bundle currently applied to this Workspace.
    pub fn get_applied_harness(&self) -> Result<Option<AppliedHarness>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let workspace = self.workspace()?;
        let applied = workspace_harness::get(&self.connection, workspace.id())?;
        self.ensure_live_binding()?;
        Ok(applied)
    }

    /// Persist one applied/verified Harness snapshot through revision CAS.
    pub fn persist_applied_harness(
        &mut self,
        applied: &AppliedHarness,
        expected_revision: Option<HarnessRevision>,
    ) -> Result<AppliedHarness, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let workspace = self.workspace()?;
        if applied.workspace_id() != workspace.id() {
            return Err(HarnessStoreError::WorkspaceMismatch {
                expected: workspace.id(),
                actual: applied.workspace_id(),
            }
            .into());
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let persisted = workspace_harness::persist(&transaction, applied, expected_revision)?;
        ensure_live_paths(WorkspaceLiveBinding {
            state_root: &self.state_root,
            state_root_identity: self.state_root_identity,
            workspace_root: &self.workspace_root,
            root_fingerprint: self.root_fingerprint,
            database_path: &self.path,
            database_identity: self.database_identity,
            wal_identity: self.wal_identity,
            shm_identity: self.shm_identity,
        })?;
        transaction.commit()?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;
        Ok(persisted)
    }

    /// Remove the exact applied Harness snapshot through revision CAS.
    pub fn delete_applied_harness(
        &mut self,
        expected_revision: HarnessRevision,
    ) -> Result<(), WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let workspace = self.workspace()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        workspace_harness::delete(&transaction, workspace.id(), expected_revision)?;
        ensure_live_paths(WorkspaceLiveBinding {
            state_root: &self.state_root,
            state_root_identity: self.state_root_identity,
            workspace_root: &self.workspace_root,
            root_fingerprint: self.root_fingerprint,
            database_path: &self.path,
            database_identity: self.database_identity,
            wal_identity: self.wal_identity,
            shm_identity: self.shm_identity,
        })?;
        transaction.commit()?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;
        Ok(())
    }

    /// Read one exact durable Harness verifier run snapshot.
    pub fn get_harness_verifier_run(
        &self,
        run_id: forge_domain::HarnessVerifierRunId,
    ) -> Result<Option<forge_domain::HarnessVerifierRun>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let run = workspace_harness_verifiers::get(&self.connection, run_id)?;
        self.ensure_live_binding()?;
        Ok(run)
    }

    /// Read the newest durable Harness verifier run for this Workspace.
    pub fn get_latest_harness_verifier_run(
        &self,
    ) -> Result<Option<forge_domain::HarnessVerifierRun>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let workspace = self.workspace()?;
        let run = workspace_harness_verifiers::latest(&self.connection, workspace.id())?;
        self.ensure_live_binding()?;
        Ok(run)
    }

    /// Persist one complete bounded Harness verifier run snapshot through CAS.
    pub fn persist_harness_verifier_run(
        &mut self,
        run: &forge_domain::HarnessVerifierRun,
        expected_revision: Option<forge_domain::HarnessVerifierRunRevision>,
    ) -> Result<forge_domain::HarnessVerifierRun, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let workspace = self.workspace()?;
        if run.workspace_id() != workspace.id() {
            return Err(HarnessVerifierStoreError::WorkspaceMismatch {
                expected: workspace.id(),
                actual: run.workspace_id(),
            }
            .into());
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let persisted = workspace_harness_verifiers::persist(&transaction, run, expected_revision)?;
        ensure_live_paths(WorkspaceLiveBinding {
            state_root: &self.state_root,
            state_root_identity: self.state_root_identity,
            workspace_root: &self.workspace_root,
            root_fingerprint: self.root_fingerprint,
            database_path: &self.path,
            database_identity: self.database_identity,
            wal_identity: self.wal_identity,
            shm_identity: self.shm_identity,
        })?;
        transaction.commit()?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;
        Ok(persisted)
    }

    /// Read the durable Workspace recovery-maintenance lease.
    pub fn get_recovery_maintenance_lease(
        &self,
    ) -> Result<RecoveryMaintenanceLease, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let workspace = self.workspace()?;
        let lease = workspace_recovery::get(&self.connection, workspace.id())?;
        self.ensure_live_binding()?;
        Ok(lease)
    }

    /// Claim or classify the Workspace recovery-maintenance lease.
    ///
    /// The decision and, for `Acquired`, the compare-and-swap are performed in
    /// one short IMMEDIATE transaction. `Busy` and `ClaimConflict` return an
    /// unchanged lease snapshot and do not update any semantic state.
    pub fn claim_recovery_maintenance_lease<C>(
        &mut self,
        command: C,
    ) -> Result<crate::RecoveryLeaseClaimResult, WorkspaceStoreError>
    where
        C: Borrow<ClaimRecoveryLease>,
    {
        let command = command.borrow();
        self.ensure_live_binding()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let result = workspace_recovery::claim(&transaction, command)?;
        ensure_live_paths(WorkspaceLiveBinding {
            state_root: &self.state_root,
            state_root_identity: self.state_root_identity,
            workspace_root: &self.workspace_root,
            root_fingerprint: self.root_fingerprint,
            database_path: &self.path,
            database_identity: self.database_identity,
            wal_identity: self.wal_identity,
            shm_identity: self.shm_identity,
        })?;
        transaction.commit()?;
        self.ensure_live_binding()?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Renew a recovery-maintenance lease through exact owner, epoch, and
    /// revision fencing.
    pub fn renew_recovery_maintenance_lease<C>(
        &mut self,
        command: C,
    ) -> Result<RecoveryMaintenanceLease, WorkspaceStoreError>
    where
        C: Borrow<RenewRecoveryLease>,
    {
        let command = command.borrow();
        self.ensure_live_binding()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let lease = workspace_recovery::renew(&transaction, command)?;
        ensure_live_paths(WorkspaceLiveBinding {
            state_root: &self.state_root,
            state_root_identity: self.state_root_identity,
            workspace_root: &self.workspace_root,
            root_fingerprint: self.root_fingerprint,
            database_path: &self.path,
            database_identity: self.database_identity,
            wal_identity: self.wal_identity,
            shm_identity: self.shm_identity,
        })?;
        transaction.commit()?;
        self.ensure_live_binding()?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;
        Ok(lease)
    }

    /// Release a recovery-maintenance lease through exact owner, epoch, and
    /// revision fencing.
    pub fn release_recovery_maintenance_lease<C>(
        &mut self,
        command: C,
    ) -> Result<RecoveryMaintenanceLease, WorkspaceStoreError>
    where
        C: Borrow<ReleaseRecoveryLease>,
    {
        let command = command.borrow();
        self.ensure_live_binding()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let lease = workspace_recovery::release(&transaction, command)?;
        ensure_live_paths(WorkspaceLiveBinding {
            state_root: &self.state_root,
            state_root_identity: self.state_root_identity,
            workspace_root: &self.workspace_root,
            root_fingerprint: self.root_fingerprint,
            database_path: &self.path,
            database_identity: self.database_identity,
            wal_identity: self.wal_identity,
            shm_identity: self.shm_identity,
        })?;
        transaction.commit()?;
        self.ensure_live_binding()?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;
        Ok(lease)
    }

    /// Create one Open Activity in this Workspace.
    pub fn create_activity(
        &mut self,
        command: &CreateActivity,
    ) -> Result<RegisteredActivity, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let workspace = query_workspace_row(&transaction)?
            .ok_or(WorkspaceStoreError::WorkspaceIdentityMissing)?;
        let workspace = decode_workspace(workspace)?;
        if workspace.id() != command.workspace_id() {
            return Err(WorkspaceStoreError::ActivityWorkspaceMismatch {
                expected: workspace.id(),
                actual: command.workspace_id(),
            });
        }
        if workspace.revision() != command.expected_workspace_revision() {
            return Err(WorkspaceStoreError::WorkspaceRevisionConflict {
                expected: command.expected_workspace_revision(),
                actual: workspace.revision(),
            });
        }

        let activity_id = command.id().into_uuid().into_bytes();
        let id_exists: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM activities WHERE activity_id = ?1)",
            params![activity_id.as_slice()],
            |row| row.get(0),
        )?;
        if id_exists {
            return Err(WorkspaceStoreError::ActivityIdConflict(command.id()));
        }

        let workspace_id = workspace.id().into_uuid().into_bytes();
        transaction.execute(
            "INSERT INTO activities (
                activity_id, workspace_id, state, created_at_ms, updated_at_ms, revision,
                lease_owner_id, lease_until_ms, lease_revision
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, NULL, ?7)",
            params![
                activity_id.as_slice(),
                workspace_id.as_slice(),
                encode_activity_state(ActivityState::Open),
                command.observed_at().get(),
                command.observed_at().get(),
                ActivityRevision::INITIAL.get(),
                ActivityLeaseRevision::INITIAL.get(),
            ],
        )?;
        let raw = query_activity_row(&transaction, command.id())?
            .ok_or(WorkspaceStoreError::ActivityNotFound(command.id()))?;
        let activity = decode_activity(&raw)?;
        ensure_live_paths(WorkspaceLiveBinding {
            state_root: &self.state_root,
            state_root_identity: self.state_root_identity,
            workspace_root: &self.workspace_root,
            root_fingerprint: self.root_fingerprint,
            database_path: &self.path,
            database_identity: self.database_identity,
            wal_identity: self.wal_identity,
            shm_identity: self.shm_identity,
        })?;
        transaction.commit()?;
        self.ensure_live_binding()?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;
        Ok(activity)
    }

    /// Read one Activity by identity.
    pub fn get_activity(
        &self,
        id: ActivityId,
    ) -> Result<Option<RegisteredActivity>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let workspace = self.workspace()?;
        let Some(raw) = query_activity_row(&self.connection, id)? else {
            return Ok(None);
        };
        let activity = decode_activity(&raw)?;
        validate_activity_workspace(&activity, workspace.id())?;
        self.ensure_live_binding()?;
        Ok(Some(activity))
    }

    /// Read at most the bounded number of Activities requested by the caller.
    pub fn list_activities(
        &self,
        limit: ActivityListLimit,
    ) -> Result<Vec<RegisteredActivity>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let workspace = self.workspace()?;
        let mut statement = self.connection.prepare(ACTIVITY_LIST_QUERY)?;
        let mut rows = statement.query(params![i64::from(limit.get())])?;
        let mut activities = Vec::new();
        while let Some(row) = rows.next()? {
            let raw = decode_raw_activity(row)?;
            let activity = decode_activity(&raw)?;
            validate_activity_workspace(&activity, workspace.id())?;
            activities.push(activity);
        }
        self.ensure_live_binding()?;
        Ok(activities)
    }

    /// Persist one newly attached Agent instance.  The application boundary
    /// supplies the identity; retries with the exact same immutable snapshot
    /// are idempotent and conflicting identities fail closed.
    pub fn attach_agent(
        &mut self,
        agent: &forge_domain::RegisteredAgentInstance,
    ) -> Result<forge_domain::RegisteredAgentInstance, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_agents::attach(&mut self.connection, agent)?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Read one Agent instance by identity.
    pub fn get_agent(
        &self,
        agent_id: forge_domain::AgentInstanceId,
    ) -> Result<Option<forge_domain::RegisteredAgentInstance>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_agents::get(&self.connection, agent_id)?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Change an Agent's exact Goal/DAG/node focus through revision CAS.
    /// Persistence validates that the referenced Goal and current DAG/node
    /// still match; it never remaps a focus after a replan.
    pub fn set_agent_focus(
        &mut self,
        command: &forge_domain::SetAgentFocus,
    ) -> Result<forge_domain::RegisteredAgentInstance, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_agents::set_focus(&mut self.connection, command)?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Append one bounded public Agent work update.
    pub fn publish_agent_work_update(
        &mut self,
        update: &forge_domain::AgentWorkUpdate,
    ) -> Result<forge_domain::AgentWorkUpdate, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_agents::publish_work_update(&mut self.connection, update)?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Detach an Agent instance through revision CAS and append a terminal
    /// focus event.  Activity lease state is left to the Activity authority.
    pub fn detach_agent(
        &mut self,
        command: &forge_domain::DetachAgent,
    ) -> Result<forge_domain::RegisteredAgentInstance, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_agents::detach(&mut self.connection, command)?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// List Agent attachment projections for one exact Workspace/Activity.
    /// Activity lease/liveness is projected from the same `SQLite` snapshot and
    /// is never duplicated into an Agent heartbeat table.
    pub fn list_agent_attachments(
        &self,
        activity_id: Option<forge_domain::ActivityId>,
        now: TimestampMillis,
        limit: forge_domain::AgentListLimit,
    ) -> Result<Vec<forge_domain::AgentAttachmentProjection>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let workspace = self.workspace()?;
        let result = workspace_agents::list_attachments(
            &self.connection,
            workspace.id(),
            activity_id,
            now,
            limit.get(),
        )?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Read one bounded Agent context from one `SQLite` snapshot.
    pub fn get_agent_context(
        &self,
        agent_id: forge_domain::AgentInstanceId,
        activity_id: forge_domain::ActivityId,
        now: TimestampMillis,
        event_limit: forge_domain::AgentListLimit,
        update_limit: forge_domain::AgentListLimit,
    ) -> Result<Option<forge_domain::AgentContextProjection>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let workspace = self.workspace()?;
        let result = workspace_agents::get_context(
            &self.connection,
            workspace.id(),
            activity_id,
            agent_id,
            now,
            event_limit.get(),
            update_limit.get(),
        )?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Read one exact Agent DAG authoring grant by identity.
    pub fn get_agent_dag_authoring_grant(
        &self,
        grant_id: forge_domain::AgentDagAuthoringGrantId,
    ) -> Result<Option<forge_domain::AgentDagAuthoringGrant>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let grant = workspace_agent_dag::get_grant(&self.connection, grant_id)?;
        self.ensure_live_binding()?;
        Ok(grant)
    }

    /// Discover the currently usable operator-issued grant for an exact
    /// Agent/credential/Goal/head tuple.  The read includes the caller's
    /// observation time so expired active rows are not advertised.
    pub fn find_active_agent_dag_authoring_grant(
        &self,
        actor: forge_domain::AgentDagAuthoringActor,
        goal: forge_domain::GoalAttribution,
        expected_dag_revision: forge_domain::DagRevisionNumber,
        expected_head_revision: forge_domain::DagHeadRevision,
        now: TimestampMillis,
    ) -> Result<Option<forge_domain::AgentDagAuthoringGrant>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let grant = workspace_agent_dag::find_active_grant(
            &self.connection,
            actor,
            goal,
            expected_dag_revision,
            expected_head_revision,
            now,
        )?;
        self.ensure_live_binding()?;
        Ok(grant)
    }

    /// Persist one exact Agent DAG authoring grant issuance.
    pub fn issue_agent_dag_authoring_grant(
        &mut self,
        grant: &forge_domain::AgentDagAuthoringGrant,
    ) -> Result<forge_domain::AgentDagAuthoringGrant, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_agent_dag::issue_grant(&mut self.connection, grant)?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Revoke one active Agent DAG authoring grant through exact revision CAS.
    pub fn revoke_agent_dag_authoring_grant(
        &mut self,
        grant_id: forge_domain::AgentDagAuthoringGrantId,
        expected_revision: forge_domain::AgentDagAuthoringGrantRevision,
    ) -> Result<forge_domain::AgentDagAuthoringGrant, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let workspace = self.workspace()?;
        let result = workspace_agent_dag::revoke_grant(
            &mut self.connection,
            grant_id,
            expected_revision,
            workspace.id(),
        )?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Atomically commit one one-shot Agent DAG replan, consuming its grant
    /// and recording the replay ledger and factual Agent update.
    pub fn commit_agent_dag_replan(
        &mut self,
        request: &forge_domain::AgentDagReplanRequest,
    ) -> Result<AgentDagReplanCommitResult, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_agent_dag::commit_replan(&mut self.connection, request)?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Persist one Activity-attributed file mutation intent before its live
    /// filesystem effect begins.
    ///
    /// Retrying the same identities and exact intent is idempotent. A durable
    /// `Starting` record is returned as recovery-required and is never replayed
    /// by the repository.
    pub fn begin_file_mutation(
        &mut self,
        command: &BeginFileMutation,
        diff_command: &BeginDiffEvidence,
    ) -> Result<BeginFileMutationDiffResult, WorkspaceStoreError> {
        self.begin_file_mutation_for_goal(command, diff_command, None)
    }

    pub fn begin_file_mutation_for_goal(
        &mut self,
        command: &BeginFileMutation,
        diff_command: &BeginDiffEvidence,
        goal: Option<GoalWorkAttribution>,
    ) -> Result<BeginFileMutationDiffResult, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let file = workspace_changesets::begin(&transaction, command)?;
        let existing_diff =
            workspace_diffs::get_by_change_set(&transaction, command.change_set_id())?;
        let diff = match (file.status(), existing_diff) {
            (BeginFileMutationStatus::Started, None) => {
                Some(workspace_diffs::begin(&transaction, command, diff_command)?)
            }
            (_, Some(_)) => Some(workspace_diffs::begin(&transaction, command, diff_command)?),
            (BeginFileMutationStatus::RecoveryRequired, None) => {
                return Err(DiffStoreError::RecordMissing.into());
            }
            (
                BeginFileMutationStatus::AlreadyApplied | BeginFileMutationStatus::TerminalFailed,
                None,
            ) => None,
        };
        associate_work_evidence(
            &transaction,
            goal,
            GoalEvidenceRef::ChangeSet(command.change_set_id()),
            command.observed_at(),
        )?;
        let result = BeginFileMutationDiffResult::new(file, diff);
        ensure_live_paths(WorkspaceLiveBinding {
            state_root: &self.state_root,
            state_root_identity: self.state_root_identity,
            workspace_root: &self.workspace_root,
            root_fingerprint: self.root_fingerprint,
            database_path: &self.path,
            database_identity: self.database_identity,
            wal_identity: self.wal_identity,
            shm_identity: self.shm_identity,
        })?;
        transaction.commit()?;
        self.ensure_live_binding()?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Mark one durable file mutation as applied after the exact POST state
    /// has been observed through the confined filesystem adapter.
    pub fn complete_file_mutation(
        &mut self,
        command: &CompleteFileMutation,
        diff_command: &CompleteDiffEvidence,
    ) -> Result<FileMutationDiffRecord, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        workspace_diffs::complete(&transaction, diff_command)?;
        let file = workspace_changesets::complete(&transaction, command)?;
        let diff = workspace_diffs::get_by_id(&transaction, diff_command.id())?
            .ok_or(DiffStoreError::RecordMissing)?;
        let result = FileMutationDiffRecord::new(file, diff);
        ensure_live_paths(WorkspaceLiveBinding {
            state_root: &self.state_root,
            state_root_identity: self.state_root_identity,
            workspace_root: &self.workspace_root,
            root_fingerprint: self.root_fingerprint,
            database_path: &self.path,
            database_identity: self.database_identity,
            wal_identity: self.wal_identity,
            shm_identity: self.shm_identity,
        })?;
        transaction.commit()?;
        self.ensure_live_binding()?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Record a terminal failure only when the caller knows the filesystem
    /// effect did not commit. Uncertain effects deliberately remain Starting.
    pub fn fail_file_mutation(
        &mut self,
        command: &FailFileMutation,
        diff_command: AbandonDiffEvidence,
    ) -> Result<FileMutationDiffRecord, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        workspace_diffs::abandon(&transaction, diff_command)?;
        let file = workspace_changesets::fail(&transaction, command)?;
        let diff = workspace_diffs::get_by_id(&transaction, diff_command.id())?
            .ok_or(DiffStoreError::RecordMissing)?;
        let result = FileMutationDiffRecord::new(file, diff);
        ensure_live_paths(WorkspaceLiveBinding {
            state_root: &self.state_root,
            state_root_identity: self.state_root_identity,
            workspace_root: &self.workspace_root,
            root_fingerprint: self.root_fingerprint,
            database_path: &self.path,
            database_identity: self.database_identity,
            wal_identity: self.wal_identity,
            shm_identity: self.shm_identity,
        })?;
        transaction.commit()?;
        self.ensure_live_binding()?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Read one bounded ChangeSet/file-mutation record by identity.
    pub fn get_file_mutation(
        &self,
        id: forge_domain::ChangeSetId,
    ) -> Result<Option<FileMutationRecord>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_changesets::get(&self.connection, id)?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Read the Diff Evidence row associated with one `ChangeSet`. `None`
    /// identifies either a missing `ChangeSet` or a migrated v3 legacy row.
    pub fn get_diff_for_change_set(
        &self,
        id: forge_domain::ChangeSetId,
    ) -> Result<Option<RegisteredDiffEvidence>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_diffs::get_by_change_set(&self.connection, id)?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Read one Diff Evidence record by its stable identity.
    pub fn get_diff(
        &self,
        id: DiffId,
    ) -> Result<Option<RegisteredDiffEvidence>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_diffs::get_by_id(&self.connection, id)?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// List bounded Diff Evidence metadata for one Activity.
    pub fn list_diffs(
        &self,
        activity_id: ActivityId,
        limit: DiffListLimit,
    ) -> Result<Vec<RegisteredDiffEvidence>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_diffs::list_by_activity(&self.connection, activity_id, limit)?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Load the bounded fixed-query Diff reference projection used by
    /// filesystem inventory Doctor composition.
    pub fn list_diff_doctor_references(&self) -> Result<DiffDoctorReport, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let report = workspace_diffs::doctor_references(&self.connection)?;
        self.ensure_live_binding()?;
        Ok(report)
    }

    /// Build a read-only, explicit keep-most-recent retention plan. This never
    /// changes metadata or artifacts.
    pub fn plan_diff_retention(
        &self,
        keep_recent: DiffRetentionKeepCount,
        limit: DiffRetentionPlanLimit,
    ) -> Result<DiffRetentionPlan, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let candidates =
            workspace_diffs::list_retention_candidates(&self.connection, keep_recent, limit)?;
        self.ensure_live_binding()?;
        Ok(DiffRetentionPlan::new(keep_recent, candidates))
    }

    /// Mark one Ready text Diff as `PurgePending` before artifact deletion.
    pub fn begin_diff_purge(
        &mut self,
        command: BeginDiffPurge,
    ) -> Result<DiffPurgeRecord, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let result = workspace_diffs::begin_purge(&transaction, command)?;
        ensure_live_paths(WorkspaceLiveBinding {
            state_root: &self.state_root,
            state_root_identity: self.state_root_identity,
            workspace_root: &self.workspace_root,
            root_fingerprint: self.root_fingerprint,
            database_path: &self.path,
            database_identity: self.database_identity,
            wal_identity: self.wal_identity,
            shm_identity: self.shm_identity,
        })?;
        transaction.commit()?;
        self.ensure_live_binding()?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Tombstone one `PurgePending` Diff after its payload is confirmed absent.
    pub fn complete_diff_purge(
        &mut self,
        command: CompleteDiffPurge,
    ) -> Result<DiffPurgeRecord, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let result = workspace_diffs::complete_purge(&transaction, command)?;
        ensure_live_paths(WorkspaceLiveBinding {
            state_root: &self.state_root,
            state_root_identity: self.state_root_identity,
            workspace_root: &self.workspace_root,
            root_fingerprint: self.root_fingerprint,
            database_path: &self.path,
            database_identity: self.database_identity,
            wal_identity: self.wal_identity,
            shm_identity: self.shm_identity,
        })?;
        transaction.commit()?;
        self.ensure_live_binding()?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Persist one Activity-attributed execution intent before process spawn.
    pub fn begin_execution(
        &mut self,
        command: &BeginExecution,
    ) -> Result<crate::BeginExecutionRecord, WorkspaceStoreError> {
        self.begin_execution_for_goal(command, None)
    }

    pub fn begin_execution_for_goal(
        &mut self,
        command: &BeginExecution,
        goal: Option<GoalWorkAttribution>,
    ) -> Result<crate::BeginExecutionRecord, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let result = workspace_executions::begin_execution_in_transaction(&transaction, command)?;
        associate_work_evidence(
            &transaction,
            goal,
            GoalEvidenceRef::Execution(command.id()),
            command.observed_at(),
        )?;
        transaction.commit()?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Mark an admitted execution as running after the supervisor is owned.
    pub fn mark_execution_running(
        &mut self,
        command: MarkExecutionRunning,
    ) -> Result<RegisteredExecution, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_executions::mark_execution_running(&mut self.connection, command)?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Persist terminal process evidence after every descendant has been reaped.
    pub fn complete_execution(
        &mut self,
        command: &CompleteExecution,
    ) -> Result<RegisteredExecution, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_executions::complete_execution(&mut self.connection, command)?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Persist a typed internal failure when no uncertain process effect remains.
    pub fn fail_execution(
        &mut self,
        command: FailExecution,
    ) -> Result<RegisteredExecution, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_executions::fail_execution(&mut self.connection, command)?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Mark bounded pre-crash execution intents as interrupted during restart.
    pub fn reconcile_interrupted_executions(
        &mut self,
        observed_at: TimestampMillis,
        limit: ExecutionListLimit,
    ) -> Result<Vec<RegisteredExecution>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_executions::reconcile_interrupted_executions(
            &mut self.connection,
            observed_at,
            limit,
        )?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Reconcile bounded Starting/Running Executions whose owning Activity
    /// lease is expired at the observed time.
    ///
    /// Live Activity ownership blocks reconciliation: an Execution whose
    /// Activity still holds an unexpired lease is never touched by this path.
    /// Activities without any lease are also left untouched this slice; only
    /// proven durable-authority expiry grants recovery classification.
    pub fn reconcile_expired_authority_executions(
        &mut self,
        observed_at: TimestampMillis,
        limit: ExecutionListLimit,
    ) -> Result<Vec<RegisteredExecution>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_executions::reconcile_expired_authority_executions(
            &mut self.connection,
            observed_at,
            limit,
        )?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Read one durable execution record by stable identity.
    pub fn get_execution(
        &self,
        id: ExecutionId,
    ) -> Result<Option<RegisteredExecution>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_executions::get_execution(&self.connection, id)?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// List bounded execution evidence for one Activity.
    pub fn list_executions(
        &self,
        activity_id: ActivityId,
        limit: ExecutionListLimit,
    ) -> Result<Vec<RegisteredExecution>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_executions::list_executions(&self.connection, activity_id, limit)?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Persist a Starting Git checkpoint after its bounded metadata and
    /// `ChangeSet` attribution have been validated by the checkpoint adapter.
    pub fn begin_checkpoint(
        &mut self,
        checkpoint: &RegisteredCheckpoint,
    ) -> Result<RegisteredCheckpoint, WorkspaceStoreError> {
        self.begin_checkpoint_for_goal(checkpoint, None)
    }

    pub fn begin_checkpoint_for_goal(
        &mut self,
        checkpoint: &RegisteredCheckpoint,
        goal: Option<GoalWorkAttribution>,
    ) -> Result<RegisteredCheckpoint, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let result =
            workspace_checkpoints::insert_checkpoint_in_transaction(&transaction, checkpoint)?;
        associate_work_evidence(
            &transaction,
            goal,
            GoalEvidenceRef::Checkpoint(checkpoint.id()),
            checkpoint.timestamps().created_at(),
        )?;
        transaction.commit()?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Compare-and-set a Starting checkpoint to its pure-domain Ready
    /// projection. Git/file effects are intentionally outside this call.
    pub fn complete_checkpoint(
        &mut self,
        checkpoint: &RegisteredCheckpoint,
        expected_revision: CheckpointRevision,
    ) -> Result<RegisteredCheckpoint, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_checkpoints::complete_checkpoint(
            &mut self.connection,
            checkpoint,
            expected_revision,
        )?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    pub fn get_checkpoint(
        &self,
        id: CheckpointId,
    ) -> Result<Option<RegisteredCheckpoint>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_checkpoints::get_checkpoint(&self.connection, id)?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    pub fn list_checkpoints(
        &self,
        workspace_id: WorkspaceId,
        limit: u32,
    ) -> Result<Vec<RegisteredCheckpoint>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result =
            workspace_checkpoints::list_checkpoints(&self.connection, workspace_id, limit)?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Persist a Starting restore journal after the pure restore plan has
    /// matched the exact observed POST state.
    pub fn begin_checkpoint_restore(
        &mut self,
        restore: &RegisteredCheckpointRestore,
    ) -> Result<RegisteredCheckpointRestore, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result =
            workspace_checkpoints::insert_checkpoint_restore(&mut self.connection, restore)?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Compare-and-set a Starting restore journal to a terminal domain
    /// projection after the external filesystem/Git effect has settled.
    pub fn complete_checkpoint_restore(
        &mut self,
        restore: &RegisteredCheckpointRestore,
        expected_revision: CheckpointRestoreRevision,
    ) -> Result<RegisteredCheckpointRestore, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_checkpoints::complete_checkpoint_restore(
            &mut self.connection,
            restore,
            expected_revision,
        )?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    pub fn get_checkpoint_restore(
        &self,
        id: CheckpointRestoreId,
    ) -> Result<Option<RegisteredCheckpointRestore>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_checkpoints::get_checkpoint_restore(&self.connection, id)?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    pub fn list_checkpoint_restores(
        &self,
        workspace_id: WorkspaceId,
        limit: u32,
    ) -> Result<Vec<RegisteredCheckpointRestore>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result =
            workspace_checkpoints::list_checkpoint_restores(&self.connection, workspace_id, limit)?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Insert one optional durable Goal contract. Goal creation does not start
    /// background work or grant effect authority.
    pub fn insert_goal(
        &mut self,
        goal: &RegisteredGoal,
    ) -> Result<RegisteredGoal, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_goals::insert_goal(&mut self.connection, goal)?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    pub fn get_goal(&self, id: GoalId) -> Result<Option<RegisteredGoal>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_goals::get_goal(&self.connection, id)?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    pub fn list_goals(
        &self,
        workspace_id: WorkspaceId,
        limit: GoalListLimit,
    ) -> Result<Vec<RegisteredGoal>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let workspace = self.workspace()?;
        if workspace.id() != workspace_id {
            return Err(GoalStoreError::WorkspaceMismatch.into());
        }
        let result = workspace_goals::list_goals(&self.connection, workspace_id, limit)?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Persist a pure-domain Goal lifecycle projection using exact revision
    /// compare-and-set. Completed Goals use [`Self::complete_goal`] instead.
    pub fn update_goal(
        &mut self,
        goal: &RegisteredGoal,
        expected_revision: GoalRevision,
    ) -> Result<RegisteredGoal, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_goals::update_goal(&mut self.connection, goal, expected_revision)?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    #[cfg(test)]
    pub(crate) fn associate_goal_evidence(
        &mut self,
        goal_id: GoalId,
        expected_revision: GoalRevision,
        evidence: GoalEvidenceRef,
        associated_at: TimestampMillis,
    ) -> Result<GoalEvidenceRecord, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_goals::associate_evidence(
            &mut self.connection,
            goal_id,
            expected_revision,
            evidence,
            associated_at,
        )?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    pub fn list_goal_evidence(
        &self,
        goal_id: GoalId,
        limit: usize,
    ) -> Result<Vec<GoalEvidenceRecord>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_goals::list_evidence(&self.connection, goal_id, limit)?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    pub fn review_goal(&self, goal_id: GoalId) -> Result<GoalReview, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_goals::review_goal(&self.connection, goal_id)?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    pub fn complete_goal(
        &mut self,
        goal: &RegisteredGoal,
        expected_revision: GoalRevision,
        review: &GoalReview,
        receipt: &GoalCompletionReceipt,
    ) -> Result<RegisteredGoal, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_goals::complete_goal(
            &mut self.connection,
            goal,
            expected_revision,
            review,
            receipt,
        )?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    #[cfg(test)]
    pub(crate) fn goal_evidence_is_linked(
        &self,
        evidence: GoalEvidenceRef,
    ) -> Result<bool, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_goals::evidence_is_goal_linked(&self.connection, evidence)?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    pub fn insert_dag_revision(
        &mut self,
        revision: &DagRevision,
        nodes: &[RegisteredDagNode],
        lineage: &[forge_domain::DagNodeLineage],
        expected_head_revision: Option<DagHeadRevision>,
    ) -> Result<crate::StoredDagRevision, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_dags::insert_revision(
            &mut self.connection,
            revision,
            nodes,
            lineage,
            expected_head_revision,
        )?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    pub fn get_current_dag(
        &self,
        goal_id: GoalId,
    ) -> Result<Option<crate::StoredDagRevision>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_dags::get_current(&self.connection, goal_id)?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    pub fn get_dag_revision(
        &self,
        goal_id: GoalId,
        number: DagRevisionNumber,
    ) -> Result<Option<crate::StoredDagRevision>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_dags::get_revision(&self.connection, goal_id, number)?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    pub fn start_dag_node(
        &mut self,
        goal_id: GoalId,
        node_id: forge_domain::DagNodeId,
        expected_revision: forge_domain::DagNodeRevision,
        observed_at: TimestampMillis,
    ) -> Result<RegisteredDagNode, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_dags::start_node(
            &mut self.connection,
            goal_id,
            node_id,
            expected_revision,
            observed_at,
        )?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    pub fn update_dag_node(
        &mut self,
        requested: &RegisteredDagNode,
        expected_revision: forge_domain::DagNodeRevision,
    ) -> Result<RegisteredDagNode, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result =
            workspace_dags::update_node(&mut self.connection, requested, expected_revision)?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    pub fn ensure_workspace_policy(
        &mut self,
        observed_at: TimestampMillis,
    ) -> Result<WorkspacePolicy, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let workspace = self.workspace()?;
        let policy =
            workspace_approvals::ensure_policy(&mut self.connection, workspace.id(), observed_at)?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;
        Ok(policy)
    }

    pub fn get_workspace_policy(&self) -> Result<Option<WorkspacePolicy>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let policy = workspace_approvals::get_policy(&self.connection)?;
        self.ensure_live_binding()?;
        Ok(policy)
    }

    pub fn replace_workspace_policy(
        &mut self,
        policy: &WorkspacePolicy,
        expected_revision: PolicyRevision,
        observed_at: TimestampMillis,
    ) -> Result<WorkspacePolicy, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_approvals::replace_policy(
            &mut self.connection,
            policy,
            expected_revision,
            observed_at,
        )?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    pub fn insert_pending_approval(
        &mut self,
        request: &RegisteredApprovalRequest,
    ) -> Result<RegisteredApprovalRequest, WorkspaceStoreError> {
        self.insert_pending_approval_for_goal(request, None)
    }

    pub fn insert_pending_approval_for_goal(
        &mut self,
        request: &RegisteredApprovalRequest,
        goal: Option<GoalWorkAttribution>,
    ) -> Result<RegisteredApprovalRequest, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let result = workspace_approvals::insert_pending_in_transaction(&transaction, request)?;
        associate_work_evidence(
            &transaction,
            goal,
            GoalEvidenceRef::Approval(request.id()),
            request.created_at(),
        )?;
        transaction.commit()?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    pub fn insert_approval_audit(
        &mut self,
        request: &RegisteredApprovalRequest,
    ) -> Result<RegisteredApprovalRequest, WorkspaceStoreError> {
        self.insert_approval_audit_for_goal(request, None)
    }

    pub fn insert_approval_audit_for_goal(
        &mut self,
        request: &RegisteredApprovalRequest,
        goal: Option<GoalWorkAttribution>,
    ) -> Result<RegisteredApprovalRequest, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let result =
            workspace_approvals::insert_approval_audit_in_transaction(&transaction, request)?;
        associate_work_evidence(
            &transaction,
            goal,
            GoalEvidenceRef::Approval(request.id()),
            request.created_at(),
        )?;
        transaction.commit()?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    pub fn get_approval_request(
        &self,
        id: ApprovalRequestId,
    ) -> Result<Option<RegisteredApprovalRequest>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_approvals::get_approval(&self.connection, id)?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    pub fn list_pending_approvals(
        &self,
        workspace_id: WorkspaceId,
        limit: ExecutionListLimit,
    ) -> Result<Vec<RegisteredApprovalRequest>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_approvals::list_pending(&self.connection, workspace_id, limit)?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn approve_once(
        &mut self,
        approval_id: ApprovalRequestId,
        expected_revision: ApprovalRevision,
        grant_id: ExecutionGrantId,
        observed_at: TimestampMillis,
        grant_expires_at: TimestampMillis,
    ) -> Result<(RegisteredApprovalRequest, ExecutionGrant), WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_approvals::approve_once(
            &mut self.connection,
            approval_id,
            expected_revision,
            grant_id,
            observed_at,
            grant_expires_at,
        )?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    pub fn decide_pending_approval(
        &mut self,
        approval_id: ApprovalRequestId,
        decision: ApprovalDecision,
        expected_revision: ApprovalRevision,
        observed_at: TimestampMillis,
    ) -> Result<RegisteredApprovalRequest, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_approvals::decide_pending(
            &mut self.connection,
            approval_id,
            decision,
            expected_revision,
            observed_at,
        )?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    pub fn create_auto_approval_scope(
        &mut self,
        scope: &AutoApprovalScope,
        created_at: TimestampMillis,
    ) -> Result<AutoApprovalScope, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result =
            workspace_approvals::create_auto_scope(&mut self.connection, scope, created_at)?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    pub fn get_auto_approval_scope(
        &self,
        id: AutoApprovalScopeId,
    ) -> Result<Option<AutoApprovalScope>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_approvals::get_auto_scope(&self.connection, id)?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    pub fn revoke_auto_approval_scope(
        &mut self,
        id: AutoApprovalScopeId,
        expected_revision: forge_domain::AutoApprovalScopeRevision,
        observed_at: TimestampMillis,
    ) -> Result<AutoApprovalScope, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_approvals::revoke_auto_scope(
            &mut self.connection,
            id,
            expected_revision,
            observed_at,
        )?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    pub fn consume_grant_and_begin_execution(
        &mut self,
        grant_id: ExecutionGrantId,
        expected_revision: ExecutionGrantRevision,
        request: ExecutionAuthorizationRequest,
        begin: &BeginExecution,
        observed_at: TimestampMillis,
        goal: Option<GoalWorkAttribution>,
    ) -> Result<(ExecutionGrant, crate::BeginExecutionRecord), WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_approvals::consume_grant_and_begin_execution(
            &mut self.connection,
            grant_id,
            expected_revision,
            request,
            begin,
            observed_at,
            goal,
        )?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn consume_auto_scope_and_begin_execution(
        &mut self,
        scope_id: AutoApprovalScopeId,
        expected_scope_revision: forge_domain::AutoApprovalScopeRevision,
        approval_id: ApprovalRequestId,
        grant_id: ExecutionGrantId,
        request: ExecutionAuthorizationRequest,
        begin: &BeginExecution,
        observed_at: TimestampMillis,
        goal: Option<GoalWorkAttribution>,
    ) -> Result<crate::AutoApprovalExecutionRecord, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_approvals::consume_auto_scope_and_begin_execution(
            &mut self.connection,
            scope_id,
            expected_scope_revision,
            approval_id,
            grant_id,
            request,
            begin,
            observed_at,
            goal,
        )?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    pub fn reconcile_expired_approval_authority(
        &mut self,
        observed_at: TimestampMillis,
        limit: ExecutionListLimit,
    ) -> Result<crate::ApprovalAuthorityCleanupReport, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let workspace_id = self.workspace()?.id();
        let result = workspace_approvals::reconcile_expired_authority(
            &mut self.connection,
            workspace_id,
            observed_at,
            limit,
        )?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    pub fn cancel_activity_approval_authority(
        &mut self,
        activity_id: ActivityId,
        observed_at: TimestampMillis,
        limit: ExecutionListLimit,
    ) -> Result<crate::ApprovalAuthorityCleanupReport, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let workspace_id = self.workspace()?.id();
        let result = workspace_approvals::cancel_activity_authority(
            &mut self.connection,
            workspace_id,
            activity_id,
            observed_at,
            limit,
        )?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    pub fn cancel_workspace_approval_authority(
        &mut self,
        observed_at: TimestampMillis,
        limit: ExecutionListLimit,
    ) -> Result<crate::ApprovalAuthorityCleanupReport, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let workspace_id = self.workspace()?.id();
        let result = workspace_approvals::cancel_workspace_authority(
            &mut self.connection,
            workspace_id,
            observed_at,
            limit,
        )?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Compare-and-set an Activity lifecycle state.
    pub fn set_activity_state(
        &mut self,
        command: &SetActivityState,
    ) -> Result<RegisteredActivity, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let raw = query_activity_row(&transaction, command.id())?
            .ok_or(WorkspaceStoreError::ActivityNotFound(command.id()))?;
        let current = decode_activity(&raw)?;
        let workspace = query_workspace_row(&transaction)?
            .ok_or(WorkspaceStoreError::WorkspaceIdentityMissing)?;
        let workspace = decode_workspace(workspace)?;
        validate_activity_workspace(&current, workspace.id())?;
        if current.revision() != command.expected_revision() {
            return Err(WorkspaceStoreError::ActivityRevisionConflict {
                id: command.id(),
                expected: command.expected_revision(),
                actual: current.revision(),
            });
        }
        if matches!(
            current.state(),
            ActivityState::Closed | ActivityState::Interrupted
        ) && command.state() == ActivityState::Open
        {
            return Err(WorkspaceStoreError::ActivityTerminal(command.id()));
        }
        if command.state() == ActivityState::Interrupted {
            return Err(WorkspaceStoreError::InvalidActivityTransition {
                id: command.id(),
                from: current.state(),
                to: command.state(),
            });
        }
        if command.state() == ActivityState::Closed && !current.lease().is_unleased() {
            return Err(WorkspaceStoreError::ActivityLeaseRequired(command.id()));
        }
        let next_revision = current.revision().checked_next().map_err(|_| {
            WorkspaceStoreError::ActivityRevisionOverflow {
                id: command.id(),
                current: current.revision(),
            }
        })?;
        let id_bytes = command.id().into_uuid().into_bytes();
        let changed = transaction.execute(
            "UPDATE activities
             SET state = ?1, updated_at_ms = ?2, revision = ?3
             WHERE activity_id = ?4 AND revision = ?5",
            params![
                encode_activity_state(command.state()),
                command.observed_at().get(),
                next_revision.get(),
                id_bytes.as_slice(),
                command.expected_revision().get(),
            ],
        )?;
        if changed == 0 {
            return Err(WorkspaceStoreError::ActivityRevisionConflict {
                id: command.id(),
                expected: command.expected_revision(),
                actual: current.revision(),
            });
        }
        let updated = query_activity_row(&transaction, command.id())?
            .ok_or(WorkspaceStoreError::ActivityNotFound(command.id()))?;
        let activity = decode_activity(&updated)?;
        ensure_live_paths(WorkspaceLiveBinding {
            state_root: &self.state_root,
            state_root_identity: self.state_root_identity,
            workspace_root: &self.workspace_root,
            root_fingerprint: self.root_fingerprint,
            database_path: &self.path,
            database_identity: self.database_identity,
            wal_identity: self.wal_identity,
            shm_identity: self.shm_identity,
        })?;
        transaction.commit()?;
        self.ensure_live_binding()?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;
        Ok(activity)
    }

    /// Bootstrap one new Activity or idempotently confirm a still-live lease
    /// for an explicit runtime instance.
    ///
    /// The entire decision and write are performed in one IMMEDIATE
    /// transaction.  A same-owner live bootstrap is intentionally idempotent;
    /// a different live owner receives `AlreadyLive`; expired/unleased Open
    /// rows require explicit recovery and a new `ActivityId`; terminal rows are
    /// returned without revival.
    pub fn bootstrap_activity(
        &mut self,
        command: &BootstrapActivity,
    ) -> Result<RegisteredActivity, WorkspaceStoreError> {
        validate_lease_window(command.lease_until(), command.observed_at())?;
        self.ensure_live_binding()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let workspace = query_workspace_row(&transaction)?
            .ok_or(WorkspaceStoreError::WorkspaceIdentityMissing)
            .and_then(decode_workspace)?;
        validate_bootstrap_workspace(&workspace, command)?;

        let activity = match query_activity_row(&transaction, command.id())? {
            None => insert_bootstrapped_activity(&transaction, &workspace, command)?,
            Some(existing_raw) => {
                let existing = decode_activity(&existing_raw)?;
                let decision =
                    decide_bootstrap_activity(Some(&existing), command, command.observed_at());
                match decision {
                    BootstrapActivityDecision::AlreadyOwned
                    | BootstrapActivityDecision::Terminal => {
                        transaction.commit()?;
                        self.ensure_live_binding()?;
                        return Ok(existing);
                    }
                    BootstrapActivityDecision::AlreadyLive => {
                        return Err(already_live_error(&existing));
                    }
                    BootstrapActivityDecision::Create => {
                        return Err(WorkspaceStoreError::ActivityIdConflict(command.id()));
                    }
                    BootstrapActivityDecision::ExpiredRecoveryRequired => {
                        return Err(expired_recovery_error(&existing, command.observed_at()));
                    }
                    BootstrapActivityDecision::UnleasedRecoveryRequired => {
                        return Err(WorkspaceStoreError::ActivityLeaseUnavailable(command.id()));
                    }
                }
            }
        };
        ensure_live_paths(WorkspaceLiveBinding {
            state_root: &self.state_root,
            state_root_identity: self.state_root_identity,
            workspace_root: &self.workspace_root,
            root_fingerprint: self.root_fingerprint,
            database_path: &self.path,
            database_identity: self.database_identity,
            wal_identity: self.wal_identity,
            shm_identity: self.shm_identity,
        })?;
        transaction.commit()?;
        self.ensure_live_binding()?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;
        Ok(activity)
    }

    /// Renew one or more live leases in one serialized transaction.
    pub fn renew_activity_leases(
        &mut self,
        commands: &[RenewActivityLease],
    ) -> Result<Vec<RegisteredActivity>, WorkspaceStoreError> {
        if commands.is_empty() {
            return Ok(Vec::new());
        }
        validate_activity_lease_batch_size(commands.len())?;
        validate_same_owner_for_renewals(commands)?;
        validate_unique_activity_ids(commands.iter().map(RenewActivityLease::id))?;
        for command in commands {
            validate_lease_window(command.lease_until(), command.observed_at())?;
        }
        self.ensure_live_binding()?;
        self.batch_transaction_count = self.batch_transaction_count.saturating_add(1);
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let workspace = query_workspace_row(&transaction)?
            .ok_or(WorkspaceStoreError::WorkspaceIdentityMissing)
            .and_then(decode_workspace)?;
        let mut preflight = Vec::with_capacity(commands.len());
        for command in commands {
            let raw = query_activity_row(&transaction, command.id())?
                .ok_or(WorkspaceStoreError::ActivityNotFound(command.id()))?;
            let current = decode_activity(&raw)?;
            validate_activity_workspace(&current, workspace.id())?;
            if current.state() != ActivityState::Open {
                return Err(WorkspaceStoreError::ActivityTerminal(command.id()));
            }
            validate_owned_live_lease(&current, command.owner_id(), command.observed_at())?;
            if current.lease_revision() != command.expected_lease_revision() {
                return Err(WorkspaceStoreError::LeaseRevisionConflict {
                    id: command.id(),
                    expected: command.expected_lease_revision(),
                    actual: current.lease_revision(),
                });
            }
            let next_lease_revision = current.lease_revision().checked_next().map_err(|_| {
                WorkspaceStoreError::ActivityLeaseRevisionOverflow {
                    id: command.id(),
                    current: current.lease_revision(),
                }
            })?;
            preflight.push(RenewPreflight {
                command,
                current,
                next_lease_revision,
            });
        }

        let mut updated_activities = Vec::with_capacity(preflight.len());
        for item in &preflight {
            let owner = item.command.owner_id().into_uuid().into_bytes();
            let id = item.command.id().into_uuid().into_bytes();
            let changed = transaction.execute(
                "UPDATE activities
                 SET lease_until_ms = ?1, lease_revision = ?2
                 WHERE activity_id = ?3 AND state = ?4 AND lease_owner_id = ?5
                   AND lease_revision = ?6 AND lease_until_ms > ?7",
                params![
                    item.command.lease_until().get(),
                    item.next_lease_revision.get(),
                    id.as_slice(),
                    encode_activity_state(ActivityState::Open),
                    owner.as_slice(),
                    item.command.expected_lease_revision().get(),
                    item.command.observed_at().get(),
                ],
            )?;
            if changed == 0 {
                return Err(WorkspaceStoreError::LeaseRevisionConflict {
                    id: item.command.id(),
                    expected: item.command.expected_lease_revision(),
                    actual: item.current.lease_revision(),
                });
            }
            let updated = query_activity_row(&transaction, item.command.id())?
                .ok_or(WorkspaceStoreError::ActivityNotFound(item.command.id()))?;
            updated_activities.push(decode_activity(&updated)?);
        }
        ensure_live_paths(WorkspaceLiveBinding {
            state_root: &self.state_root,
            state_root_identity: self.state_root_identity,
            workspace_root: &self.workspace_root,
            root_fingerprint: self.root_fingerprint,
            database_path: &self.path,
            database_identity: self.database_identity,
            wal_identity: self.wal_identity,
            shm_identity: self.shm_identity,
        })?;
        transaction.commit()?;
        self.ensure_live_binding()?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;
        Ok(updated_activities)
    }

    /// Renew one live lease through the batch path.
    pub fn renew_activity_lease(
        &mut self,
        command: &RenewActivityLease,
    ) -> Result<RegisteredActivity, WorkspaceStoreError> {
        let mut activities = self.renew_activity_leases(std::slice::from_ref(command))?;
        activities
            .pop()
            .ok_or(WorkspaceStoreError::ActivityBatchInvariant)
    }

    /// Close one or more owned Activities and atomically release their leases.
    pub fn close_owned_activities(
        &mut self,
        commands: &[CloseActivity],
    ) -> Result<Vec<RegisteredActivity>, WorkspaceStoreError> {
        if commands.is_empty() {
            return Ok(Vec::new());
        }
        validate_activity_lease_batch_size(commands.len())?;
        validate_same_owner_for_closes(commands)?;
        validate_unique_activity_ids(commands.iter().map(CloseActivity::id))?;
        self.ensure_live_binding()?;
        self.batch_transaction_count = self.batch_transaction_count.saturating_add(1);
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let workspace = query_workspace_row(&transaction)?
            .ok_or(WorkspaceStoreError::WorkspaceIdentityMissing)
            .and_then(decode_workspace)?;
        let mut preflight = Vec::with_capacity(commands.len());
        for command in commands {
            let raw = query_activity_row(&transaction, command.id())?
                .ok_or(WorkspaceStoreError::ActivityNotFound(command.id()))?;
            let current = decode_activity(&raw)?;
            validate_activity_workspace(&current, workspace.id())?;
            if matches!(
                current.state(),
                ActivityState::Closed | ActivityState::Interrupted
            ) {
                preflight.push(ClosePreflight {
                    command,
                    current,
                    next_activity_revision: None,
                    next_lease_revision: None,
                });
                continue;
            }
            validate_owned_live_lease(&current, command.owner_id(), command.observed_at())?;
            if current.lease_revision() != command.expected_lease_revision() {
                return Err(WorkspaceStoreError::LeaseRevisionConflict {
                    id: command.id(),
                    expected: command.expected_lease_revision(),
                    actual: current.lease_revision(),
                });
            }
            let next_activity_revision = current.revision().checked_next().map_err(|_| {
                WorkspaceStoreError::ActivityRevisionOverflow {
                    id: command.id(),
                    current: current.revision(),
                }
            })?;
            let next_lease_revision = current.lease_revision().checked_next().map_err(|_| {
                WorkspaceStoreError::ActivityLeaseRevisionOverflow {
                    id: command.id(),
                    current: current.lease_revision(),
                }
            })?;
            preflight.push(ClosePreflight {
                command,
                current,
                next_activity_revision: Some(next_activity_revision),
                next_lease_revision: Some(next_lease_revision),
            });
        }

        let closed_activities = apply_close_preflight(&transaction, &preflight)?;
        ensure_live_paths(WorkspaceLiveBinding {
            state_root: &self.state_root,
            state_root_identity: self.state_root_identity,
            workspace_root: &self.workspace_root,
            root_fingerprint: self.root_fingerprint,
            database_path: &self.path,
            database_identity: self.database_identity,
            wal_identity: self.wal_identity,
            shm_identity: self.shm_identity,
        })?;
        transaction.commit()?;
        self.ensure_live_binding()?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;
        Ok(closed_activities)
    }

    /// Close one owned Activity through the batch path.
    pub fn close_activity(
        &mut self,
        command: &CloseActivity,
    ) -> Result<RegisteredActivity, WorkspaceStoreError> {
        let mut activities = self.close_owned_activities(std::slice::from_ref(command))?;
        activities
            .pop()
            .ok_or(WorkspaceStoreError::ActivityBatchInvariant)
    }

    /// Release an owned lease while keeping an Open Activity available.
    pub fn release_activity_lease(
        &mut self,
        command: &ReleaseActivityLease,
    ) -> Result<RegisteredActivity, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let raw = query_activity_row(&transaction, command.id())?
            .ok_or(WorkspaceStoreError::ActivityNotFound(command.id()))?;
        let current = decode_activity(&raw)?;
        if matches!(
            current.state(),
            ActivityState::Closed | ActivityState::Interrupted
        ) {
            transaction.commit()?;
            return Ok(current);
        }
        validate_owned_live_lease(&current, command.owner_id(), command.observed_at())?;
        if current.lease_revision() != command.expected_lease_revision() {
            return Err(WorkspaceStoreError::LeaseRevisionConflict {
                id: command.id(),
                expected: command.expected_lease_revision(),
                actual: current.lease_revision(),
            });
        }
        let next_lease_revision = current.lease_revision().checked_next().map_err(|_| {
            WorkspaceStoreError::ActivityLeaseRevisionOverflow {
                id: command.id(),
                current: current.lease_revision(),
            }
        })?;
        let owner = command.owner_id().into_uuid().into_bytes();
        let id = command.id().into_uuid().into_bytes();
        let changed = transaction.execute(
            "UPDATE activities
             SET lease_owner_id = NULL, lease_until_ms = NULL, lease_revision = ?1
             WHERE activity_id = ?2 AND state = ?3 AND lease_owner_id = ?4
               AND lease_revision = ?5 AND lease_until_ms > ?6",
            params![
                next_lease_revision.get(),
                id.as_slice(),
                encode_activity_state(ActivityState::Open),
                owner.as_slice(),
                command.expected_lease_revision().get(),
                command.observed_at().get(),
            ],
        )?;
        if changed == 0 {
            return Err(WorkspaceStoreError::LeaseRevisionConflict {
                id: command.id(),
                expected: command.expected_lease_revision(),
                actual: current.lease_revision(),
            });
        }
        let updated = query_activity_row(&transaction, command.id())?
            .ok_or(WorkspaceStoreError::ActivityNotFound(command.id()))?;
        let activity = decode_activity(&updated)?;
        ensure_live_paths(WorkspaceLiveBinding {
            state_root: &self.state_root,
            state_root_identity: self.state_root_identity,
            workspace_root: &self.workspace_root,
            root_fingerprint: self.root_fingerprint,
            database_path: &self.path,
            database_identity: self.database_identity,
            wal_identity: self.wal_identity,
            shm_identity: self.shm_identity,
        })?;
        transaction.commit()?;
        self.ensure_live_binding()?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;
        Ok(activity)
    }

    /// Reconcile a bounded batch of expired Open rows to Interrupted.
    pub fn reconcile_expired_activities(
        &mut self,
        command: &ReconcileExpiredActivities,
    ) -> Result<Vec<RegisteredActivity>, WorkspaceStoreError> {
        self.reconcile_expired_activities_limited(command, ActivityListLimit::DEFAULT)
    }

    /// Reconcile expired Activity leases.  This is the sole lease-expiry
    /// transition: bootstrap never steals an old lease or revives its row.
    pub fn reconcile_expired_activity_leases(
        &mut self,
        command: &ReconcileExpiredActivities,
    ) -> Result<Vec<RegisteredActivity>, WorkspaceStoreError> {
        self.reconcile_expired_activities(command)
    }

    /// Reconcile expired Open rows with an explicit caller-provided bound.
    pub fn reconcile_expired_activities_limited(
        &mut self,
        command: &ReconcileExpiredActivities,
        limit: ActivityListLimit,
    ) -> Result<Vec<RegisteredActivity>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut statement = transaction.prepare(
            "SELECT activity_id FROM activities
             WHERE state = ?1 AND lease_owner_id IS NOT NULL
               AND lease_until_ms IS NOT NULL AND lease_until_ms <= ?2
             ORDER BY lease_until_ms ASC, activity_id ASC
             LIMIT ?3",
        )?;
        let mut rows = statement.query(params![
            encode_activity_state(ActivityState::Open),
            command.now().get(),
            i64::from(limit.get()),
        ])?;
        let mut ids = Vec::new();
        while let Some(row) = rows.next()? {
            ids.push(row.get::<_, Vec<u8>>(0)?);
        }
        drop(rows);
        drop(statement);
        let mut reconciled = Vec::with_capacity(ids.len());
        for id_bytes in ids {
            let id = decode_activity_id(&id_bytes)?;
            let Some(raw) = query_activity_row(&transaction, id)? else {
                continue;
            };
            let current = decode_activity(&raw)?;
            let Some(owner_id) = current.lease_owner_id() else {
                continue;
            };
            let Some(lease_until) = current.lease_until() else {
                continue;
            };
            if current.state() != ActivityState::Open || lease_until.get() > command.now().get() {
                continue;
            }
            let next_activity_revision = current.revision().checked_next().map_err(|_| {
                WorkspaceStoreError::ActivityRevisionOverflow {
                    id,
                    current: current.revision(),
                }
            })?;
            let next_lease_revision = current.lease_revision().checked_next().map_err(|_| {
                WorkspaceStoreError::ActivityLeaseRevisionOverflow {
                    id,
                    current: current.lease_revision(),
                }
            })?;
            let owner = owner_id.into_uuid().into_bytes();
            let changed = transaction.execute(
                "UPDATE activities
                 SET state = ?1, updated_at_ms = ?2, revision = ?3,
                     lease_owner_id = NULL, lease_until_ms = NULL, lease_revision = ?4
                 WHERE activity_id = ?5 AND state = ?6 AND lease_owner_id = ?7
                   AND lease_until_ms = ?8 AND lease_revision = ?9",
                params![
                    encode_activity_state(ActivityState::Interrupted),
                    command.now().get(),
                    next_activity_revision.get(),
                    next_lease_revision.get(),
                    id_bytes.as_slice(),
                    encode_activity_state(ActivityState::Open),
                    owner.as_slice(),
                    lease_until.get(),
                    current.lease_revision().get(),
                ],
            )?;
            if changed == 0 {
                continue;
            }
            let updated = query_activity_row(&transaction, id)?
                .ok_or(WorkspaceStoreError::ActivityNotFound(id))?;
            reconciled.push(decode_activity(&updated)?);
        }
        ensure_live_paths(WorkspaceLiveBinding {
            state_root: &self.state_root,
            state_root_identity: self.state_root_identity,
            workspace_root: &self.workspace_root,
            root_fingerprint: self.root_fingerprint,
            database_path: &self.path,
            database_identity: self.database_identity,
            wal_identity: self.wal_identity,
            shm_identity: self.shm_identity,
        })?;
        transaction.commit()?;
        self.ensure_live_binding()?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;
        Ok(reconciled)
    }

    /// Caller-time classified Activity projections.  Classification never
    /// mutates durable state and therefore cannot silently reconcile rows.
    pub fn list_activity_projections(
        &self,
        limit: ActivityListLimit,
        now: TimestampMillis,
    ) -> Result<Vec<ActivityProjection>, WorkspaceStoreError> {
        self.list_activities(limit).map(|activities| {
            activities
                .into_iter()
                .map(|activity| ActivityProjection::from_activity(activity, now))
                .collect()
        })
    }

    #[cfg(test)]
    fn batch_transaction_count(&self) -> u64 {
        self.batch_transaction_count
    }

    fn ensure_live_binding(&self) -> Result<(), WorkspaceStoreError> {
        ensure_live_paths(WorkspaceLiveBinding {
            state_root: &self.state_root,
            state_root_identity: self.state_root_identity,
            workspace_root: &self.workspace_root,
            root_fingerprint: self.root_fingerprint,
            database_path: &self.path,
            database_identity: self.database_identity,
            wal_identity: self.wal_identity,
            shm_identity: self.shm_identity,
        })
    }

    fn capture_sidecar_identities(&mut self) -> Result<(), WorkspaceStoreError> {
        self.wal_identity = inspect_regular_file(&sidecar_path(&self.path, "-wal"), true)?;
        self.shm_identity = inspect_regular_file(&sidecar_path(&self.path, "-shm"), true)?;
        Ok(())
    }

    fn validate_runtime_policy(&self) -> Result<(), WorkspaceStoreError> {
        validate_runtime_policy(&runtime_policy(&self.connection)?)
    }

    fn establish_or_confirm(
        &mut self,
        command: &EstablishWorkspace,
    ) -> Result<RegisteredWorkspace, WorkspaceStoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let Some(raw) = query_workspace_row(&transaction)? else {
            let id = command.id().into_uuid().into_bytes();
            let location_id = command.location_id().into_uuid().into_bytes();
            let root = path_to_bytes_bounded(command.root().as_path())?;
            let fingerprint = command.root_fingerprint().into_bytes();
            transaction.execute(
                "INSERT INTO workspace (
                    singleton, workspace_id, location_id, root_path,
                    root_fingerprint, created_at_ms, updated_at_ms, revision
                 ) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    id.as_slice(),
                    location_id.as_slice(),
                    root,
                    fingerprint.as_slice(),
                    command.observed_at().get(),
                    command.observed_at().get(),
                    WorkspaceRevision::INITIAL.get(),
                ],
            )?;
            let inserted = query_workspace_row(&transaction)?
                .ok_or(WorkspaceStoreError::WorkspaceIdentityMissing)?;
            let inserted = decode_workspace(inserted)?;
            let _ = workspace_recovery::insert_released(
                &transaction,
                inserted.id(),
                command.observed_at(),
            )?;
            transaction.commit()?;
            return Ok(inserted);
        };

        let registered = decode_workspace(raw)?;
        if registered.location_id() != command.location_id() {
            return Err(WorkspaceStoreError::LocationBindingConflict {
                stored: registered.location_id(),
                requested: command.location_id(),
            });
        }

        let decision = decide_workspace_root(
            &registered,
            command.root().clone(),
            command.root_fingerprint(),
            command.observed_at(),
        )
        .map_err(map_root_decision_error)?;
        match decision {
            WorkspaceRootDecision::Confirmed => {
                transaction.commit()?;
                Ok(registered)
            }
            WorkspaceRootDecision::Rebind {
                root,
                observed_at,
                next_revision,
            } => {
                let root_bytes = path_to_bytes_bounded(root.as_path())?;
                let workspace_id = registered.id().into_uuid().into_bytes();
                let changed = transaction.execute(
                    "UPDATE workspace
                     SET root_path = ?1, updated_at_ms = ?2, revision = ?3
                     WHERE singleton = 1 AND workspace_id = ?4 AND revision = ?5",
                    params![
                        root_bytes,
                        observed_at.get(),
                        next_revision.get(),
                        workspace_id.as_slice(),
                        registered.revision().get(),
                    ],
                )?;
                if changed == 0 {
                    return Err(WorkspaceStoreError::WorkspaceRevisionConflict {
                        expected: registered.revision(),
                        actual: registered.revision(),
                    });
                }
                let updated = query_workspace_row(&transaction)?
                    .ok_or(WorkspaceStoreError::WorkspaceIdentityMissing)?;
                let updated = decode_workspace(updated)?;
                transaction.commit()?;
                Ok(updated)
            }
        }
    }
}

fn ensure_database_identity(
    path: &Path,
    expected: FileIdentity,
) -> Result<(), WorkspaceStoreError> {
    let observed = inspect_regular_file(path, false)?.ok_or_else(|| {
        WorkspaceStoreError::DatabasePathInvariant {
            path: path.to_path_buf(),
            detail: "database file disappeared",
        }
    })?;
    if observed != expected {
        return Err(WorkspaceStoreError::DatabasePathChanged(path.to_path_buf()));
    }
    Ok(())
}

fn ensure_sidecar_identities(
    wal_path: &Path,
    expected_wal: Option<FileIdentity>,
    shm_path: &Path,
    expected_shm: Option<FileIdentity>,
) -> Result<(), WorkspaceStoreError> {
    for (path, expected) in [(wal_path, expected_wal), (shm_path, expected_shm)] {
        let observed = inspect_regular_file(path, true)?;
        if observed != expected {
            return Err(WorkspaceStoreError::DatabasePathChanged(path.to_path_buf()));
        }
    }
    Ok(())
}

fn validate_existing_workspace_binding(
    workspace: &RegisteredWorkspace,
    layout: &ExistingWorkspaceStateLayout,
    root_fingerprint: WorkspaceRootFingerprint,
) -> Result<(), WorkspaceStoreError> {
    if workspace.root().as_path() != layout.workspace_root()
        || workspace.root_fingerprint() != root_fingerprint
    {
        return Err(WorkspaceStoreError::ExistingWorkspaceBindingMismatch {
            stored_root: workspace.root().as_path().to_path_buf(),
            observed_root: layout.workspace_root().to_path_buf(),
            stored_fingerprint: workspace.root_fingerprint(),
            observed_fingerprint: root_fingerprint,
        });
    }
    Ok(())
}

fn insert_bootstrapped_activity(
    transaction: &Transaction<'_>,
    workspace: &RegisteredWorkspace,
    command: &BootstrapActivity,
) -> Result<RegisteredActivity, WorkspaceStoreError> {
    let activity_id = command.id().into_uuid().into_bytes();
    let workspace_id = workspace.id().into_uuid().into_bytes();
    let owner = command.owner_id().into_uuid().into_bytes();
    transaction.execute(
        "INSERT INTO activities (
            activity_id, workspace_id, state, created_at_ms, updated_at_ms,
            revision, lease_owner_id, lease_until_ms, lease_revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            activity_id.as_slice(),
            workspace_id.as_slice(),
            encode_activity_state(ActivityState::Open),
            command.observed_at().get(),
            command.observed_at().get(),
            ActivityRevision::INITIAL.get(),
            owner.as_slice(),
            command.lease_until().get(),
            ActivityLeaseRevision::INITIAL.get(),
        ],
    )?;
    let raw = query_activity_row(transaction, command.id())?
        .ok_or(WorkspaceStoreError::ActivityNotFound(command.id()))?;
    decode_activity(&raw)
}

fn already_live_error(activity: &RegisteredActivity) -> WorkspaceStoreError {
    let Some(owner_id) = activity.lease_owner_id() else {
        return WorkspaceStoreError::CorruptRecord {
            field: "activity.lease_owner_id",
            detail: "live Activity has no lease owner".to_owned(),
        };
    };
    let Some(lease_until) = activity.lease_until() else {
        return WorkspaceStoreError::CorruptRecord {
            field: "activity.lease_until_ms",
            detail: "live Activity has no lease expiry".to_owned(),
        };
    };
    WorkspaceStoreError::AlreadyLive {
        id: activity.id(),
        owner_id,
        lease_until,
    }
}

fn expired_recovery_error(
    activity: &RegisteredActivity,
    observed_at: TimestampMillis,
) -> WorkspaceStoreError {
    let Some(lease_until) = activity.lease_until() else {
        return WorkspaceStoreError::ActivityLeaseUnavailable(activity.id());
    };
    WorkspaceStoreError::ExpiredRecoveryRequired {
        id: activity.id(),
        lease_until,
        observed_at,
    }
}

struct RenewPreflight<'a> {
    command: &'a RenewActivityLease,
    current: RegisteredActivity,
    next_lease_revision: ActivityLeaseRevision,
}

struct ClosePreflight<'a> {
    command: &'a CloseActivity,
    current: RegisteredActivity,
    next_activity_revision: Option<ActivityRevision>,
    next_lease_revision: Option<ActivityLeaseRevision>,
}

fn apply_close_preflight(
    transaction: &Transaction<'_>,
    preflight: &[ClosePreflight<'_>],
) -> Result<Vec<RegisteredActivity>, WorkspaceStoreError> {
    let mut closed_activities = Vec::with_capacity(preflight.len());
    for item in preflight {
        let Some(next_activity_revision) = item.next_activity_revision else {
            closed_activities.push(item.current.clone());
            continue;
        };
        let Some(next_lease_revision) = item.next_lease_revision else {
            return Err(WorkspaceStoreError::ActivityBatchInvariant);
        };
        let owner = item.command.owner_id().into_uuid().into_bytes();
        let id = item.command.id().into_uuid().into_bytes();
        let changed = transaction.execute(
            "UPDATE activities
             SET state = ?1, updated_at_ms = ?2, revision = ?3,
                 lease_owner_id = NULL, lease_until_ms = NULL, lease_revision = ?4
             WHERE activity_id = ?5 AND state = ?6 AND lease_owner_id = ?7
               AND lease_revision = ?8 AND lease_until_ms > ?9",
            params![
                encode_activity_state(ActivityState::Closed),
                item.command.observed_at().get(),
                next_activity_revision.get(),
                next_lease_revision.get(),
                id.as_slice(),
                encode_activity_state(ActivityState::Open),
                owner.as_slice(),
                item.command.expected_lease_revision().get(),
                item.command.observed_at().get(),
            ],
        )?;
        if changed == 0 {
            return Err(WorkspaceStoreError::LeaseRevisionConflict {
                id: item.command.id(),
                expected: item.command.expected_lease_revision(),
                actual: item.current.lease_revision(),
            });
        }
        let updated = query_activity_row(transaction, item.command.id())?
            .ok_or(WorkspaceStoreError::ActivityNotFound(item.command.id()))?;
        closed_activities.push(decode_activity(&updated)?);
    }
    Ok(closed_activities)
}

fn validate_activity_lease_batch_size(actual: usize) -> Result<(), WorkspaceStoreError> {
    let actual = u32::try_from(actual).unwrap_or(u32::MAX);
    ActivityLeaseBatchLimit::new(actual)
        .map(|_| ())
        .map_err(WorkspaceStoreError::ActivityLeaseBatchLimit)
}

fn validate_same_owner_for_renewals(
    commands: &[RenewActivityLease],
) -> Result<(), WorkspaceStoreError> {
    let expected = commands[0].owner_id();
    for command in &commands[1..] {
        if command.owner_id() != expected {
            return Err(WorkspaceStoreError::ActivityLeaseBatchOwnerMismatch {
                expected,
                actual: command.owner_id(),
            });
        }
    }
    Ok(())
}

fn validate_same_owner_for_closes(commands: &[CloseActivity]) -> Result<(), WorkspaceStoreError> {
    let expected = commands[0].owner_id();
    for command in &commands[1..] {
        if command.owner_id() != expected {
            return Err(WorkspaceStoreError::ActivityLeaseBatchOwnerMismatch {
                expected,
                actual: command.owner_id(),
            });
        }
    }
    Ok(())
}

fn validate_unique_activity_ids<I>(ids: I) -> Result<(), WorkspaceStoreError>
where
    I: IntoIterator<Item = ActivityId>,
{
    let mut seen = HashSet::new();
    for id in ids {
        if !seen.insert(id) {
            return Err(WorkspaceStoreError::ActivityLeaseBatchDuplicate(id));
        }
    }
    Ok(())
}

fn validate_lease_window(
    lease_until: TimestampMillis,
    observed_at: TimestampMillis,
) -> Result<(), WorkspaceStoreError> {
    if lease_until.get() <= observed_at.get() {
        return Err(WorkspaceStoreError::InvalidLeaseWindow {
            observed_at,
            lease_until,
        });
    }
    Ok(())
}

fn validate_bootstrap_workspace(
    workspace: &RegisteredWorkspace,
    command: &BootstrapActivity,
) -> Result<(), WorkspaceStoreError> {
    if workspace.id() != command.workspace_id() {
        return Err(WorkspaceStoreError::ActivityWorkspaceMismatch {
            expected: workspace.id(),
            actual: command.workspace_id(),
        });
    }
    if workspace.revision() != command.expected_workspace_revision() {
        return Err(WorkspaceStoreError::WorkspaceRevisionConflict {
            expected: command.expected_workspace_revision(),
            actual: workspace.revision(),
        });
    }
    Ok(())
}

fn validate_owned_live_lease(
    activity: &RegisteredActivity,
    owner_id: RuntimeInstanceId,
    now: TimestampMillis,
) -> Result<(), WorkspaceStoreError> {
    if activity.lease_owner_id() != Some(owner_id) {
        return Err(WorkspaceStoreError::LeaseOwnerMismatch {
            id: activity.id(),
            expected: owner_id,
            actual: activity.lease_owner_id(),
        });
    }
    let Some(until) = activity.lease_until() else {
        return Err(WorkspaceStoreError::CorruptRecord {
            field: "activity.lease_until_ms",
            detail: "owned Activity has no lease expiry".to_owned(),
        });
    };
    if until.get() <= now.get() {
        return Err(WorkspaceStoreError::LeaseExpired {
            id: activity.id(),
            lease_until: until,
            observed_at: now,
        });
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct WorkspaceLiveBinding<'a> {
    state_root: &'a Path,
    state_root_identity: DirectoryIdentity,
    workspace_root: &'a Path,
    root_fingerprint: WorkspaceRootFingerprint,
    database_path: &'a Path,
    database_identity: FileIdentity,
    wal_identity: Option<FileIdentity>,
    shm_identity: Option<FileIdentity>,
}

fn ensure_live_paths(binding: WorkspaceLiveBinding<'_>) -> Result<(), WorkspaceStoreError> {
    ensure_directory_identity(binding.state_root, binding.state_root_identity)?;
    let observed_root = observe_root_fingerprint(binding.workspace_root)?;
    if observed_root != binding.root_fingerprint {
        return Err(WorkspaceStoreError::WorkspaceRootFingerprintChanged {
            expected: binding.root_fingerprint,
            observed: observed_root,
        });
    }
    let observed_database =
        inspect_regular_file(binding.database_path, false)?.ok_or_else(|| {
            WorkspaceStoreError::DatabasePathInvariant {
                path: binding.database_path.to_path_buf(),
                detail: "database file disappeared",
            }
        })?;
    if observed_database != binding.database_identity {
        return Err(WorkspaceStoreError::DatabasePathChanged(
            binding.database_path.to_path_buf(),
        ));
    }
    for (path, expected) in [
        (
            sidecar_path(binding.database_path, "-wal"),
            binding.wal_identity,
        ),
        (
            sidecar_path(binding.database_path, "-shm"),
            binding.shm_identity,
        ),
    ] {
        let observed = inspect_regular_file(&path, true)?;
        if let (Some(expected), Some(observed)) = (expected, observed)
            && expected != observed
        {
            return Err(WorkspaceStoreError::DatabasePathChanged(path));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DatabaseOwnership {
    Fresh,
    OwnedV1,
    OwnedV2,
    OwnedV3,
    OwnedV4,
    OwnedV5,
    OwnedV6,
    OwnedV7,
    OwnedV8,
    OwnedV9,
    OwnedV10,
    OwnedV11,
    OwnedV12,
    OwnedV13,
    OwnedV14,
    OwnedV15,
    OwnedV16,
}

const fn migration_required_version(ownership: DatabaseOwnership) -> Option<i64> {
    match ownership {
        DatabaseOwnership::OwnedV1 => Some(1),
        DatabaseOwnership::OwnedV2 => Some(2),
        DatabaseOwnership::OwnedV3 => Some(3),
        DatabaseOwnership::OwnedV4 => Some(4),
        DatabaseOwnership::OwnedV5 => Some(5),
        DatabaseOwnership::OwnedV6 => Some(6),
        DatabaseOwnership::OwnedV7 => Some(CHECKPOINT_SCHEMA_VERSION),
        DatabaseOwnership::OwnedV8 => Some(GOAL_PREVIOUS_SCHEMA_VERSION),
        DatabaseOwnership::OwnedV9 => Some(DAG_PREVIOUS_SCHEMA_VERSION),
        DatabaseOwnership::OwnedV10 => Some(RECOVERY_PREVIOUS_SCHEMA_VERSION),
        DatabaseOwnership::OwnedV11 => Some(RESTORE_PROVENANCE_PREVIOUS_SCHEMA_VERSION),
        DatabaseOwnership::OwnedV12 => Some(HARNESS_PREVIOUS_SCHEMA_VERSION),
        DatabaseOwnership::OwnedV13 => Some(HARNESS_VERIFIER_PREVIOUS_SCHEMA_VERSION),
        DatabaseOwnership::OwnedV14 => Some(AGENT_PREVIOUS_SCHEMA_VERSION),
        DatabaseOwnership::OwnedV15 => Some(AGENT_DAG_PREVIOUS_SCHEMA_VERSION),
        DatabaseOwnership::Fresh | DatabaseOwnership::OwnedV16 => None,
    }
}

fn configure_connection(
    connection: &Connection,
    busy_timeout: Duration,
) -> Result<(), WorkspaceStoreError> {
    connection.busy_timeout(busy_timeout)?;
    connection.pragma_update(None, "foreign_keys", true)?;
    connection.pragma_update(None, "journal_mode", "WAL")?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    Ok(())
}

fn migrate_v7_to_current(connection: &mut Connection) -> Result<(), WorkspaceStoreError> {
    workspace_approvals::migrate_v6_to_v7(connection, CHECKPOINT_SCHEMA_VERSION)?;
    validate_schema_shape_v7(connection)?;
    workspace_checkpoints::migrate_v7_to_v8(connection, GOAL_PREVIOUS_SCHEMA_VERSION)?;
    validate_schema_shape_v8(connection)?;
    workspace_goals::migrate_v8_to_v9(connection, DAG_PREVIOUS_SCHEMA_VERSION)?;
    validate_schema_shape_v9(connection)?;
    workspace_dags::migrate_v9_to_v10(connection, RECOVERY_PREVIOUS_SCHEMA_VERSION)?;
    migrate_v10_to_current(connection)?;
    Ok(())
}

fn migrate_v10_to_current(connection: &mut Connection) -> Result<(), WorkspaceStoreError> {
    workspace_recovery::migrate_v10_to_v11(connection, RESTORE_PROVENANCE_PREVIOUS_SCHEMA_VERSION)?;
    migrate_v11_to_current(connection)
}

fn migrate_v11_to_current(connection: &mut Connection) -> Result<(), WorkspaceStoreError> {
    workspace_checkpoints::migrate_v11_to_v12(connection, HARNESS_PREVIOUS_SCHEMA_VERSION)
        .map_err(WorkspaceStoreError::from)?;
    migrate_v12_to_current(connection)
}

fn migrate_v12_to_current(connection: &mut Connection) -> Result<(), WorkspaceStoreError> {
    workspace_harness::migrate_v12_to_v13(connection, HARNESS_VERIFIER_PREVIOUS_SCHEMA_VERSION)
        .map_err(WorkspaceStoreError::from)?;
    migrate_v13_to_current(connection)
}

fn migrate_v13_to_current(connection: &mut Connection) -> Result<(), WorkspaceStoreError> {
    workspace_harness_verifiers::migrate_v13_to_v14(
        connection,
        HARNESS_VERIFIER_PREVIOUS_SCHEMA_VERSION,
    )
    .map_err(WorkspaceStoreError::from)?;
    migrate_v14_to_current(connection)
}

fn migrate_v14_to_current(connection: &mut Connection) -> Result<(), WorkspaceStoreError> {
    workspace_agents::migrate_v14_to_v15(connection, AGENT_DAG_PREVIOUS_SCHEMA_VERSION)
        .map_err(WorkspaceStoreError::from)?;
    workspace_agents::validate_schema_v15(connection).map_err(WorkspaceStoreError::from)?;
    migrate_v15_to_current(connection)
}

fn migrate_v15_to_current(connection: &mut Connection) -> Result<(), WorkspaceStoreError> {
    // v15 attachment/principal authority is retained before the v16 grant
    // tables are created.  Older v14 databases have no principal table yet;
    // this idempotent v15 transition materializes that exact authority.
    let has_principal: bool = connection.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM sqlite_schema
            WHERE type = 'table' AND name = 'agent_transport_principals'
        )",
        [],
        |row| row.get(0),
    )?;
    if !has_principal {
        workspace_agents::migrate_v15_to_v16(connection, AGENT_DAG_PREVIOUS_SCHEMA_VERSION)
            .map_err(WorkspaceStoreError::from)?;
    }
    workspace_agent_dag::migrate_v15_to_v16(connection, CURRENT_SCHEMA_VERSION)
        .map_err(WorkspaceStoreError::from)
}

#[allow(clippy::too_many_lines)]
fn prepare_database(
    connection: &mut Connection,
    busy_timeout: Duration,
    allow_fresh: bool,
) -> Result<(), WorkspaceStoreError> {
    match inspect_database(connection)? {
        DatabaseOwnership::Fresh if allow_fresh => {
            configure_connection(connection, busy_timeout)?;
            migrate_fresh(connection)?;
        }
        DatabaseOwnership::Fresh => return Err(WorkspaceStoreError::FreshDatabase),
        DatabaseOwnership::OwnedV1 => {
            validate_schema_shape_v1(connection)?;
            configure_connection(connection, busy_timeout)?;
            migrate_v1_to_v2(connection)?;
            validate_schema_shape_v2(connection)?;
            workspace_changesets::migrate_v2_to_v3(connection, 3)?;
            validate_schema_shape_v3(connection)?;
            workspace_diffs::migrate_v3_to_v4(connection, 4)?;
            validate_schema_shape_v4(connection)?;
            workspace_diffs::migrate_v4_to_v5(connection, 5)?;
            validate_schema_shape_v5(connection)?;
            workspace_executions::migrate_v5_to_v6(connection, 6)?;
            validate_schema_shape_v6(connection)?;
            migrate_v7_to_current(connection)?;
        }
        DatabaseOwnership::OwnedV2 => {
            validate_schema_shape_v2(connection)?;
            configure_connection(connection, busy_timeout)?;
            workspace_changesets::migrate_v2_to_v3(connection, 3)?;
            validate_schema_shape_v3(connection)?;
            workspace_diffs::migrate_v3_to_v4(connection, 4)?;
            validate_schema_shape_v4(connection)?;
            workspace_diffs::migrate_v4_to_v5(connection, 5)?;
            validate_schema_shape_v5(connection)?;
            workspace_executions::migrate_v5_to_v6(connection, 6)?;
            validate_schema_shape_v6(connection)?;
            migrate_v7_to_current(connection)?;
        }
        DatabaseOwnership::OwnedV3 => {
            validate_schema_shape_v3(connection)?;
            configure_connection(connection, busy_timeout)?;
            workspace_diffs::migrate_v3_to_v4(connection, 4)?;
            validate_schema_shape_v4(connection)?;
            workspace_diffs::migrate_v4_to_v5(connection, 5)?;
            validate_schema_shape_v5(connection)?;
            workspace_executions::migrate_v5_to_v6(connection, 6)?;
            validate_schema_shape_v6(connection)?;
            migrate_v7_to_current(connection)?;
        }
        DatabaseOwnership::OwnedV4 => {
            validate_schema_shape_v4(connection)?;
            configure_connection(connection, busy_timeout)?;
            workspace_diffs::migrate_v4_to_v5(connection, 5)?;
            validate_schema_shape_v5(connection)?;
            workspace_executions::migrate_v5_to_v6(connection, 6)?;
            validate_schema_shape_v6(connection)?;
            migrate_v7_to_current(connection)?;
        }
        DatabaseOwnership::OwnedV5 => {
            validate_schema_shape_v5(connection)?;
            configure_connection(connection, busy_timeout)?;
            workspace_executions::migrate_v5_to_v6(connection, 6)?;
            validate_schema_shape_v6(connection)?;
            migrate_v7_to_current(connection)?;
        }
        DatabaseOwnership::OwnedV6 => {
            validate_schema_shape_v6(connection)?;
            configure_connection(connection, busy_timeout)?;
            migrate_v7_to_current(connection)?;
        }
        DatabaseOwnership::OwnedV7 => {
            validate_schema_shape_v7(connection)?;
            configure_connection(connection, busy_timeout)?;
            workspace_checkpoints::migrate_v7_to_v8(connection, GOAL_PREVIOUS_SCHEMA_VERSION)?;
            validate_schema_shape_v8(connection)?;
            workspace_goals::migrate_v8_to_v9(connection, DAG_PREVIOUS_SCHEMA_VERSION)?;
            validate_schema_shape_v9(connection)?;
            workspace_dags::migrate_v9_to_v10(connection, RECOVERY_PREVIOUS_SCHEMA_VERSION)?;
            migrate_v10_to_current(connection)?;
        }
        DatabaseOwnership::OwnedV8 => {
            validate_schema_shape_v8(connection)?;
            configure_connection(connection, busy_timeout)?;
            workspace_goals::migrate_v8_to_v9(connection, DAG_PREVIOUS_SCHEMA_VERSION)?;
            validate_schema_shape_v9(connection)?;
            workspace_dags::migrate_v9_to_v10(connection, RECOVERY_PREVIOUS_SCHEMA_VERSION)?;
            migrate_v10_to_current(connection)?;
        }
        DatabaseOwnership::OwnedV9 => {
            validate_schema_shape_v9(connection)?;
            configure_connection(connection, busy_timeout)?;
            workspace_dags::migrate_v9_to_v10(connection, RECOVERY_PREVIOUS_SCHEMA_VERSION)?;
            migrate_v10_to_current(connection)?;
        }
        DatabaseOwnership::OwnedV10 => {
            validate_schema_shape_v10(connection)?;
            configure_connection(connection, busy_timeout)?;
            migrate_v10_to_current(connection)?;
        }
        DatabaseOwnership::OwnedV11 => {
            validate_schema_shape_v11(connection)?;
            configure_connection(connection, busy_timeout)?;
            migrate_v11_to_current(connection)?;
        }
        DatabaseOwnership::OwnedV12 => {
            validate_schema_shape_v12(connection)?;
            configure_connection(connection, busy_timeout)?;
            migrate_v12_to_current(connection)?;
        }
        DatabaseOwnership::OwnedV13 => {
            validate_schema_shape_v13(connection)?;
            configure_connection(connection, busy_timeout)?;
            migrate_v13_to_current(connection)?;
        }
        DatabaseOwnership::OwnedV14 => {
            configure_connection(connection, busy_timeout)?;
            migrate_v14_to_current(connection)?;
        }
        DatabaseOwnership::OwnedV15 => {
            configure_connection(connection, busy_timeout)?;
            migrate_v15_to_current(connection)?;
        }
        DatabaseOwnership::OwnedV16 => {
            configure_connection(connection, busy_timeout)?;
        }
    }
    validate_schema_shape(connection)
}

fn inspect_database(connection: &Connection) -> Result<DatabaseOwnership, WorkspaceStoreError> {
    let app_id = application_id(connection)?;
    let version = schema_version(connection)?;
    let empty = database_is_empty(connection)?;
    if app_id != 0 && app_id != WORKSPACE_APPLICATION_ID {
        return Err(WorkspaceStoreError::DatabaseOwnershipMismatch {
            actual: app_id,
            expected: WORKSPACE_APPLICATION_ID,
        });
    }
    if app_id == WORKSPACE_APPLICATION_ID && version > CURRENT_SCHEMA_VERSION {
        return Err(WorkspaceStoreError::UnsupportedSchemaVersion {
            actual: version,
            maximum_supported: CURRENT_SCHEMA_VERSION,
        });
    }
    if app_id == 0 {
        if version == 0 && empty {
            return Ok(DatabaseOwnership::Fresh);
        }
        return Err(WorkspaceStoreError::UnownedDatabase);
    }
    if empty {
        return Err(WorkspaceStoreError::DamagedSchema {
            detail: "owned database has an empty schema".to_owned(),
        });
    }
    match version {
        1 => Ok(DatabaseOwnership::OwnedV1),
        2 => Ok(DatabaseOwnership::OwnedV2),
        3 => Ok(DatabaseOwnership::OwnedV3),
        4 => Ok(DatabaseOwnership::OwnedV4),
        5 => Ok(DatabaseOwnership::OwnedV5),
        6 => Ok(DatabaseOwnership::OwnedV6),
        7 => Ok(DatabaseOwnership::OwnedV7),
        GOAL_PREVIOUS_SCHEMA_VERSION => Ok(DatabaseOwnership::OwnedV8),
        DAG_PREVIOUS_SCHEMA_VERSION => Ok(DatabaseOwnership::OwnedV9),
        RECOVERY_PREVIOUS_SCHEMA_VERSION => Ok(DatabaseOwnership::OwnedV10),
        RESTORE_PROVENANCE_PREVIOUS_SCHEMA_VERSION => Ok(DatabaseOwnership::OwnedV11),
        HARNESS_PREVIOUS_SCHEMA_VERSION => Ok(DatabaseOwnership::OwnedV12),
        HARNESS_VERIFIER_PREVIOUS_SCHEMA_VERSION => Ok(DatabaseOwnership::OwnedV13),
        AGENT_PREVIOUS_SCHEMA_VERSION => Ok(DatabaseOwnership::OwnedV14),
        AGENT_DAG_PREVIOUS_SCHEMA_VERSION => Ok(DatabaseOwnership::OwnedV15),
        CURRENT_SCHEMA_VERSION => Ok(DatabaseOwnership::OwnedV16),
        actual => Err(WorkspaceStoreError::DamagedSchema {
            detail: format!("owned database has unsupported schema version {actual}"),
        }),
    }
}

fn validate_owned_database(connection: &Connection) -> Result<(), WorkspaceStoreError> {
    match inspect_database(connection)? {
        DatabaseOwnership::OwnedV1 => validate_schema_shape_v1(connection),
        DatabaseOwnership::OwnedV2 => validate_schema_shape_v2(connection),
        DatabaseOwnership::OwnedV3 => validate_schema_shape_v3(connection),
        DatabaseOwnership::OwnedV4 => validate_schema_shape_v4(connection),
        DatabaseOwnership::OwnedV5 => validate_schema_shape_v5(connection),
        DatabaseOwnership::OwnedV6 => validate_schema_shape_v6(connection),
        DatabaseOwnership::OwnedV7 => validate_schema_shape_v7(connection),
        DatabaseOwnership::OwnedV8 => validate_schema_shape_v8(connection),
        DatabaseOwnership::OwnedV9 => validate_schema_shape_v9(connection),
        DatabaseOwnership::OwnedV10 => validate_schema_shape_v10(connection),
        DatabaseOwnership::OwnedV11 => validate_schema_shape_v11(connection),
        DatabaseOwnership::OwnedV12 => validate_schema_shape_v12(connection),
        DatabaseOwnership::OwnedV13 => validate_schema_shape_v13(connection),
        DatabaseOwnership::OwnedV14 => validate_schema_shape_v14(connection),
        DatabaseOwnership::OwnedV15 => validate_schema_shape_v15(connection),
        DatabaseOwnership::OwnedV16 => validate_schema_shape(connection),
        DatabaseOwnership::Fresh => Err(WorkspaceStoreError::DamagedSchema {
            detail: "Workspace schema is not initialized".to_owned(),
        }),
    }
}

fn database_is_empty(connection: &Connection) -> Result<bool, WorkspaceStoreError> {
    let has_user_objects: i64 = connection.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'
        )",
        [],
        |row| row.get(0),
    )?;
    Ok(has_user_objects == 0)
}

fn sidecar_path(database: &Path, suffix: &str) -> PathBuf {
    let mut file_name = database
        .file_name()
        .map_or_else(std::ffi::OsString::new, std::ffi::OsStr::to_os_string);
    file_name.push(suffix);
    database.with_file_name(file_name)
}

fn inspect_regular_file(
    path: &Path,
    allow_missing: bool,
) -> Result<Option<FileIdentity>, WorkspaceStoreError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(source) if allow_missing && source.kind() == io::ErrorKind::NotFound => {
            return Ok(None);
        }
        Err(source) => {
            return Err(WorkspaceStoreError::DatabasePathMetadata {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    if metadata.file_type().is_symlink() {
        return Err(WorkspaceStoreError::DatabasePathSymlink(path.to_path_buf()));
    }
    if !metadata.is_file() {
        return Err(WorkspaceStoreError::DatabasePathNotRegular(
            path.to_path_buf(),
        ));
    }
    let identity = FileIdentity::from_metadata(&metadata);
    if identity.links != 1 {
        return Err(WorkspaceStoreError::DatabasePathHardlink {
            path: path.to_path_buf(),
            links: identity.links,
        });
    }
    Ok(Some(identity))
}

fn inspect_directory(path: &Path) -> Result<DirectoryIdentity, WorkspaceStoreError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|source| WorkspaceStoreError::StateRootMetadata {
            path: path.to_path_buf(),
            source,
        })?;
    if metadata.file_type().is_symlink() {
        return Err(WorkspaceStoreError::StateRootSymlink(path.to_path_buf()));
    }
    if !metadata.is_dir() {
        return Err(WorkspaceStoreError::StateRootNotDirectory(
            path.to_path_buf(),
        ));
    }
    Ok(DirectoryIdentity::from_metadata(&metadata))
}

fn ensure_directory_identity(
    path: &Path,
    expected: DirectoryIdentity,
) -> Result<(), WorkspaceStoreError> {
    let observed = inspect_directory(path)?;
    if observed != expected {
        return Err(WorkspaceStoreError::StateRootChanged(path.to_path_buf()));
    }
    Ok(())
}

fn observe_root_fingerprint(path: &Path) -> Result<WorkspaceRootFingerprint, WorkspaceStoreError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| {
        WorkspaceStoreError::WorkspaceRootMetadata {
            path: path.to_path_buf(),
            source,
        }
    })?;
    if metadata.file_type().is_symlink() {
        return Err(WorkspaceStoreError::WorkspaceRootSymlink(
            path.to_path_buf(),
        ));
    }
    if !metadata.is_dir() {
        return Err(WorkspaceStoreError::WorkspaceRootNotDirectory(
            path.to_path_buf(),
        ));
    }
    let canonical =
        fs::canonicalize(path).map_err(|source| WorkspaceStoreError::WorkspaceRootMetadata {
            path: path.to_path_buf(),
            source,
        })?;
    if canonical != path {
        return Err(WorkspaceStoreError::WorkspaceRootCanonicalPathChanged {
            expected: path.to_path_buf(),
            observed: canonical,
        });
    }
    let mut bytes = [0_u8; FINGERPRINT_BYTES];
    bytes[..8].copy_from_slice(&metadata.dev().to_le_bytes());
    bytes[8..].copy_from_slice(&metadata.ino().to_le_bytes());
    Ok(WorkspaceRootFingerprint::from_bytes(bytes))
}

/// Pre-provenance v11 shape: everything current except the exact
/// checkpoint-restore provenance columns, which the migration adds.
fn validate_schema_shape_v11(connection: &Connection) -> Result<(), WorkspaceStoreError> {
    validate_schema_objects_v11(connection)?;
    validate_workspace_table_shape(connection)?;
    validate_activity_table_shape(connection)?;
    validate_activity_index_shape(connection)?;
    validate_activity_lease_index_shape(connection)?;
    validate_activity_foreign_key_shape(connection)?;
    workspace_changesets::validate_schema(connection)?;
    workspace_diffs::validate_schema(connection)?;
    workspace_executions::validate_schema(connection)?;
    workspace_approvals::validate_schema(connection)?;
    workspace_checkpoints::validate_schema_without_restore_provenance(connection)?;
    workspace_goals::validate_schema(connection)?;
    workspace_dags::validate_schema(connection)?;
    workspace_recovery::validate_schema(connection)?;
    Ok(())
}

fn validate_schema_shape_v12(connection: &Connection) -> Result<(), WorkspaceStoreError> {
    validate_schema_objects_v12(connection)?;
    validate_workspace_table_shape(connection)?;
    validate_activity_table_shape(connection)?;
    validate_activity_index_shape(connection)?;
    validate_activity_lease_index_shape(connection)?;
    validate_activity_foreign_key_shape(connection)?;
    workspace_changesets::validate_schema(connection)?;
    workspace_diffs::validate_schema(connection)?;
    workspace_executions::validate_schema(connection)?;
    workspace_approvals::validate_schema(connection)?;
    workspace_checkpoints::validate_schema(connection)?;
    workspace_goals::validate_schema(connection)?;
    workspace_dags::validate_schema(connection)?;
    workspace_recovery::validate_schema(connection)?;
    Ok(())
}

fn validate_schema_shape(connection: &Connection) -> Result<(), WorkspaceStoreError> {
    validate_schema_objects(connection)?;
    validate_workspace_table_shape(connection)?;
    validate_activity_table_shape(connection)?;
    validate_activity_index_shape(connection)?;
    validate_activity_lease_index_shape(connection)?;
    validate_activity_foreign_key_shape(connection)?;
    workspace_changesets::validate_schema(connection)?;
    workspace_diffs::validate_schema(connection)?;
    workspace_executions::validate_schema(connection)?;
    workspace_approvals::validate_schema(connection)?;
    workspace_checkpoints::validate_schema(connection)?;
    workspace_goals::validate_schema(connection)?;
    workspace_dags::validate_schema(connection)?;
    workspace_recovery::validate_schema(connection)?;
    workspace_harness::validate_schema(connection)?;
    workspace_harness_verifiers::validate_schema(connection)?;
    workspace_agents::validate_schema(connection)?;
    workspace_agent_dag::validate_schema(connection)?;
    Ok(())
}

fn validate_schema_shape_v15(connection: &Connection) -> Result<(), WorkspaceStoreError> {
    validate_schema_objects_v15(connection)?;
    validate_workspace_table_shape(connection)?;
    validate_activity_table_shape(connection)?;
    validate_activity_index_shape(connection)?;
    validate_activity_lease_index_shape(connection)?;
    validate_activity_foreign_key_shape(connection)?;
    workspace_changesets::validate_schema(connection)?;
    workspace_diffs::validate_schema(connection)?;
    workspace_executions::validate_schema(connection)?;
    workspace_approvals::validate_schema(connection)?;
    workspace_checkpoints::validate_schema(connection)?;
    workspace_goals::validate_schema(connection)?;
    workspace_dags::validate_schema(connection)?;
    workspace_recovery::validate_schema(connection)?;
    workspace_harness::validate_schema(connection)?;
    workspace_harness_verifiers::validate_schema(connection)?;
    workspace_agents::validate_schema(connection)?;
    Ok(())
}

fn validate_schema_shape_v13(connection: &Connection) -> Result<(), WorkspaceStoreError> {
    validate_schema_objects_v13(connection)?;
    validate_workspace_table_shape(connection)?;
    validate_activity_table_shape(connection)?;
    validate_activity_index_shape(connection)?;
    validate_activity_lease_index_shape(connection)?;
    validate_activity_foreign_key_shape(connection)?;
    workspace_changesets::validate_schema(connection)?;
    workspace_diffs::validate_schema(connection)?;
    workspace_executions::validate_schema(connection)?;
    workspace_approvals::validate_schema(connection)?;
    workspace_checkpoints::validate_schema(connection)?;
    workspace_goals::validate_schema(connection)?;
    workspace_dags::validate_schema(connection)?;
    workspace_recovery::validate_schema(connection)?;
    workspace_harness::validate_schema(connection)?;
    Ok(())
}

fn validate_schema_shape_v14(connection: &Connection) -> Result<(), WorkspaceStoreError> {
    validate_schema_objects_v14(connection)?;
    validate_workspace_table_shape(connection)?;
    validate_activity_table_shape(connection)?;
    validate_activity_index_shape(connection)?;
    validate_activity_lease_index_shape(connection)?;
    validate_activity_foreign_key_shape(connection)?;
    workspace_changesets::validate_schema(connection)?;
    workspace_diffs::validate_schema(connection)?;
    workspace_executions::validate_schema(connection)?;
    workspace_approvals::validate_schema(connection)?;
    workspace_checkpoints::validate_schema(connection)?;
    workspace_goals::validate_schema(connection)?;
    workspace_dags::validate_schema(connection)?;
    workspace_recovery::validate_schema(connection)?;
    workspace_harness::validate_schema(connection)?;
    workspace_harness_verifiers::validate_schema(connection)?;
    Ok(())
}

fn validate_schema_shape_v10(connection: &Connection) -> Result<(), WorkspaceStoreError> {
    validate_schema_objects_v10(connection)?;
    validate_workspace_table_shape(connection)?;
    validate_activity_table_shape(connection)?;
    validate_activity_index_shape(connection)?;
    validate_activity_lease_index_shape(connection)?;
    validate_activity_foreign_key_shape(connection)?;
    workspace_changesets::validate_schema(connection)?;
    workspace_diffs::validate_schema(connection)?;
    workspace_executions::validate_schema(connection)?;
    workspace_approvals::validate_schema(connection)?;
    workspace_checkpoints::validate_schema(connection)?;
    workspace_goals::validate_schema(connection)?;
    workspace_dags::validate_schema(connection)?;
    Ok(())
}

fn validate_schema_shape_v9(connection: &Connection) -> Result<(), WorkspaceStoreError> {
    validate_schema_objects_v9(connection)?;
    validate_workspace_table_shape(connection)?;
    validate_activity_table_shape(connection)?;
    validate_activity_index_shape(connection)?;
    validate_activity_lease_index_shape(connection)?;
    validate_activity_foreign_key_shape(connection)?;
    workspace_changesets::validate_schema(connection)?;
    workspace_diffs::validate_schema(connection)?;
    workspace_executions::validate_schema(connection)?;
    workspace_approvals::validate_schema(connection)?;
    workspace_checkpoints::validate_schema(connection)?;
    workspace_goals::validate_schema(connection)?;
    Ok(())
}

fn validate_schema_shape_v8(connection: &Connection) -> Result<(), WorkspaceStoreError> {
    validate_schema_objects_v8(connection)?;
    validate_workspace_table_shape(connection)?;
    validate_activity_table_shape(connection)?;
    validate_activity_index_shape(connection)?;
    validate_activity_lease_index_shape(connection)?;
    validate_activity_foreign_key_shape(connection)?;
    workspace_changesets::validate_schema(connection)?;
    workspace_diffs::validate_schema(connection)?;
    workspace_executions::validate_schema(connection)?;
    workspace_approvals::validate_schema(connection)?;
    workspace_checkpoints::validate_schema(connection)?;
    Ok(())
}

fn validate_schema_shape_v7(connection: &Connection) -> Result<(), WorkspaceStoreError> {
    validate_schema_objects_v7(connection)?;
    validate_workspace_table_shape(connection)?;
    validate_activity_table_shape(connection)?;
    validate_activity_index_shape(connection)?;
    validate_activity_lease_index_shape(connection)?;
    validate_activity_foreign_key_shape(connection)?;
    workspace_changesets::validate_schema(connection)?;
    workspace_diffs::validate_schema(connection)?;
    workspace_executions::validate_schema(connection)?;
    workspace_approvals::validate_schema(connection)?;
    Ok(())
}

fn validate_schema_shape_v6(connection: &Connection) -> Result<(), WorkspaceStoreError> {
    validate_schema_objects_v6(connection)?;
    validate_workspace_table_shape(connection)?;
    validate_activity_table_shape(connection)?;
    validate_activity_index_shape(connection)?;
    validate_activity_lease_index_shape(connection)?;
    validate_activity_foreign_key_shape(connection)?;
    workspace_changesets::validate_schema(connection)?;
    workspace_diffs::validate_schema(connection)?;
    workspace_executions::validate_schema(connection)?;
    Ok(())
}

fn validate_schema_shape_v5(connection: &Connection) -> Result<(), WorkspaceStoreError> {
    validate_schema_objects_v5(connection)?;
    validate_workspace_table_shape(connection)?;
    validate_activity_table_shape(connection)?;
    validate_activity_index_shape(connection)?;
    validate_activity_lease_index_shape(connection)?;
    validate_activity_foreign_key_shape(connection)?;
    workspace_changesets::validate_schema(connection)?;
    workspace_diffs::validate_schema(connection)?;
    Ok(())
}

fn validate_schema_shape_v3(connection: &Connection) -> Result<(), WorkspaceStoreError> {
    validate_schema_objects_v3(connection)?;
    validate_workspace_table_shape(connection)?;
    validate_activity_table_shape(connection)?;
    validate_activity_index_shape(connection)?;
    validate_activity_lease_index_shape(connection)?;
    validate_activity_foreign_key_shape(connection)?;
    workspace_changesets::validate_schema(connection)?;
    Ok(())
}

fn validate_schema_shape_v4(connection: &Connection) -> Result<(), WorkspaceStoreError> {
    validate_schema_objects_v4(connection)?;
    validate_workspace_table_shape(connection)?;
    validate_activity_table_shape(connection)?;
    validate_activity_index_shape(connection)?;
    validate_activity_lease_index_shape(connection)?;
    validate_activity_foreign_key_shape(connection)?;
    workspace_changesets::validate_schema(connection)?;
    workspace_diffs::validate_schema_v4(connection)?;
    Ok(())
}

fn validate_schema_shape_v2(connection: &Connection) -> Result<(), WorkspaceStoreError> {
    validate_schema_objects_v2(connection)?;
    validate_workspace_table_shape(connection)?;
    validate_activity_table_shape(connection)?;
    validate_activity_index_shape(connection)?;
    validate_activity_lease_index_shape(connection)?;
    validate_activity_foreign_key_shape(connection)
}

fn validate_schema_shape_v1(connection: &Connection) -> Result<(), WorkspaceStoreError> {
    validate_schema_objects_v1(connection)?;
    validate_workspace_table_shape(connection)?;
    validate_activity_table_shape_v1(connection)?;
    validate_activity_index_shape(connection)?;
    validate_activity_foreign_key_shape(connection)
}

fn validate_workspace_table_shape(connection: &Connection) -> Result<(), WorkspaceStoreError> {
    let workspace_sql = bounded_schema_sql(connection, "table", "workspace", "workspace table")?
        .ok_or_else(|| WorkspaceStoreError::DamagedSchema {
            detail: "required workspace table is missing".to_owned(),
        })?;
    if !schema_sql_matches(&workspace_sql, EXPECTED_WORKSPACE_TABLE_SQL) {
        return Err(WorkspaceStoreError::DamagedSchema {
            detail: "workspace table SQL definition does not match the expected policy".to_owned(),
        });
    }
    let workspace_columns = table_columns(connection, "workspace")?;
    let columns_match = workspace_columns.len() == EXPECTED_WORKSPACE_COLUMNS.len()
        && workspace_columns
            .iter()
            .zip(EXPECTED_WORKSPACE_COLUMNS)
            .all(|((name, data_type, not_null, primary_key), expected)| {
                name == expected.0
                    && data_type == expected.1
                    && *not_null == expected.2
                    && *primary_key == expected.3
            });
    if !columns_match {
        return Err(WorkspaceStoreError::DamagedSchema {
            detail: "workspace table columns do not match the expected shape".to_owned(),
        });
    }
    Ok(())
}

fn validate_activity_table_shape(connection: &Connection) -> Result<(), WorkspaceStoreError> {
    let activity_sql = bounded_schema_sql(connection, "table", "activities", "activities table")?
        .ok_or_else(|| WorkspaceStoreError::DamagedSchema {
        detail: "required activities table is missing".to_owned(),
    })?;
    if !schema_sql_matches(&activity_sql, EXPECTED_ACTIVITIES_TABLE_SQL) {
        return Err(WorkspaceStoreError::DamagedSchema {
            detail: "activities table SQL definition does not match the expected policy".to_owned(),
        });
    }
    let activity_columns = table_columns(connection, "activities")?;
    let columns_match = activity_columns.len() == EXPECTED_ACTIVITY_COLUMNS.len()
        && activity_columns.iter().zip(EXPECTED_ACTIVITY_COLUMNS).all(
            |((name, data_type, not_null, primary_key), expected)| {
                name == expected.0
                    && data_type == expected.1
                    && *not_null == expected.2
                    && *primary_key == expected.3
            },
        );
    if !columns_match {
        return Err(WorkspaceStoreError::DamagedSchema {
            detail: "activities table columns do not match the expected shape".to_owned(),
        });
    }
    Ok(())
}

fn validate_activity_table_shape_v1(connection: &Connection) -> Result<(), WorkspaceStoreError> {
    let activity_sql = bounded_schema_sql(connection, "table", "activities", "activities table")?
        .ok_or_else(|| WorkspaceStoreError::DamagedSchema {
        detail: "required activities table is missing".to_owned(),
    })?;
    if !schema_sql_matches(&activity_sql, EXPECTED_V1_ACTIVITIES_TABLE_SQL) {
        return Err(WorkspaceStoreError::DamagedSchema {
            detail: "v1 activities table SQL definition does not match the expected policy"
                .to_owned(),
        });
    }
    let activity_columns = table_columns(connection, "activities")?;
    let columns_match = activity_columns.len() == EXPECTED_V1_ACTIVITY_COLUMNS.len()
        && activity_columns
            .iter()
            .zip(EXPECTED_V1_ACTIVITY_COLUMNS)
            .all(|((name, data_type, not_null, primary_key), expected)| {
                name == expected.0
                    && data_type == expected.1
                    && *not_null == expected.2
                    && *primary_key == expected.3
            });
    if !columns_match {
        return Err(WorkspaceStoreError::DamagedSchema {
            detail: "v1 activities table columns do not match the expected shape".to_owned(),
        });
    }
    Ok(())
}

fn validate_activity_index_shape(connection: &Connection) -> Result<(), WorkspaceStoreError> {
    let mut index_list = connection.prepare("PRAGMA index_list(activities)")?;
    let mut index_rows = index_list.query([])?;
    let indexes = collect_bounded_metadata(&mut index_rows, "activities indexes", |row| {
        Ok((row.get::<_, String>(1)?, row.get::<_, i64>(2)?))
    })?;
    let Some((_, unique)) = indexes
        .iter()
        .find(|(name, _)| name == "activities_workspace_updated_idx")
    else {
        return Err(WorkspaceStoreError::DamagedSchema {
            detail: "required Activity ordering index is missing".to_owned(),
        });
    };
    if *unique != 0 {
        return Err(WorkspaceStoreError::DamagedSchema {
            detail: "required Activity ordering index has unexpected uniqueness".to_owned(),
        });
    }
    let index_sql = bounded_schema_sql(
        connection,
        "index",
        "activities_workspace_updated_idx",
        "Activity ordering index",
    )?
    .ok_or_else(|| WorkspaceStoreError::DamagedSchema {
        detail: "required Activity ordering index SQL is missing".to_owned(),
    })?;
    if !schema_sql_matches(&index_sql, EXPECTED_ACTIVITIES_INDEX_SQL) {
        return Err(WorkspaceStoreError::DamagedSchema {
            detail:
                "required Activity ordering index SQL definition does not match the expected policy"
                    .to_owned(),
        });
    }
    let mut index_info =
        connection.prepare("PRAGMA index_info(activities_workspace_updated_idx)")?;
    let mut index_rows = index_info.query([])?;
    let index_columns =
        collect_bounded_metadata(&mut index_rows, "Activity ordering index columns", |row| {
            row.get::<_, String>(2)
        })?;
    if index_columns != ["workspace_id", "updated_at_ms", "activity_id"] {
        return Err(WorkspaceStoreError::DamagedSchema {
            detail: "required Activity ordering index columns are invalid".to_owned(),
        });
    }
    Ok(())
}

fn validate_activity_lease_index_shape(connection: &Connection) -> Result<(), WorkspaceStoreError> {
    let mut index_list = connection.prepare("PRAGMA index_list(activities)")?;
    let mut index_rows = index_list.query([])?;
    let indexes = collect_bounded_metadata(&mut index_rows, "activities indexes", |row| {
        Ok((row.get::<_, String>(1)?, row.get::<_, i64>(2)?))
    })?;
    let Some((_, unique)) = indexes
        .iter()
        .find(|(name, _)| name == "activities_workspace_lease_idx")
    else {
        return Err(WorkspaceStoreError::DamagedSchema {
            detail: "required Activity lease index is missing".to_owned(),
        });
    };
    if *unique != 0 {
        return Err(WorkspaceStoreError::DamagedSchema {
            detail: "required Activity lease index has unexpected uniqueness".to_owned(),
        });
    }
    let index_sql = bounded_schema_sql(
        connection,
        "index",
        "activities_workspace_lease_idx",
        "Activity lease index",
    )?
    .ok_or_else(|| WorkspaceStoreError::DamagedSchema {
        detail: "required Activity lease index SQL is missing".to_owned(),
    })?;
    if !schema_sql_matches(&index_sql, EXPECTED_ACTIVITIES_LEASE_INDEX_SQL) {
        return Err(WorkspaceStoreError::DamagedSchema {
            detail:
                "required Activity lease index SQL definition does not match the expected policy"
                    .to_owned(),
        });
    }
    let mut index_info = connection.prepare("PRAGMA index_info(activities_workspace_lease_idx)")?;
    let mut index_rows = index_info.query([])?;
    let index_columns =
        collect_bounded_metadata(&mut index_rows, "Activity lease index columns", |row| {
            row.get::<_, String>(2)
        })?;
    if index_columns != ["workspace_id", "state", "lease_until_ms", "activity_id"] {
        return Err(WorkspaceStoreError::DamagedSchema {
            detail: "required Activity lease index columns are invalid".to_owned(),
        });
    }
    Ok(())
}

fn validate_activity_foreign_key_shape(connection: &Connection) -> Result<(), WorkspaceStoreError> {
    let mut foreign_keys = connection.prepare("PRAGMA foreign_key_list(activities)")?;
    let mut foreign_key_rows = foreign_keys.query([])?;
    let foreign_key_columns =
        collect_bounded_metadata(&mut foreign_key_rows, "activities foreign keys", |row| {
            Ok((
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
            ))
        })?;
    let valid_foreign_key = foreign_key_columns.len() == 1
        && foreign_key_columns[0].0 == "workspace"
        && foreign_key_columns[0].1 == "workspace_id"
        && foreign_key_columns[0].2 == "workspace_id"
        && foreign_key_columns[0].3 == "NO ACTION"
        && foreign_key_columns[0].4 == "NO ACTION"
        && foreign_key_columns[0].5 == "NONE";
    if !valid_foreign_key {
        return Err(WorkspaceStoreError::DamagedSchema {
            detail: "activities foreign-key shape is invalid".to_owned(),
        });
    }
    Ok(())
}

fn validate_schema_objects_v7(connection: &Connection) -> Result<(), WorkspaceStoreError> {
    let change_set_objects = workspace_changesets::schema_objects();
    let diff_objects = workspace_diffs::schema_objects();
    let execution_objects = workspace_executions::schema_objects();
    let approval_objects = workspace_approvals::schema_objects();
    let expected = [
        ("table", "workspace"),
        ("table", "activities"),
        ("index", "activities_workspace_updated_idx"),
        ("index", "activities_workspace_lease_idx"),
        change_set_objects[0],
        change_set_objects[1],
        change_set_objects[2],
        change_set_objects[3],
        diff_objects[0],
        diff_objects[1],
        diff_objects[2],
        diff_objects[3],
        diff_objects[4],
        execution_objects[0],
        execution_objects[1],
        execution_objects[2],
        approval_objects[0],
        approval_objects[1],
        approval_objects[2],
        approval_objects[3],
        approval_objects[4],
        approval_objects[5],
        approval_objects[6],
        approval_objects[7],
    ];
    validate_schema_objects_for(connection, &expected)
}

fn validate_schema_objects_v8(connection: &Connection) -> Result<(), WorkspaceStoreError> {
    let change_set_objects = workspace_changesets::schema_objects();
    let diff_objects = workspace_diffs::schema_objects();
    let execution_objects = workspace_executions::schema_objects();
    let approval_objects = workspace_approvals::schema_objects();
    let checkpoint_objects = workspace_checkpoints::schema_objects();
    let expected = [
        ("table", "workspace"),
        ("table", "activities"),
        ("index", "activities_workspace_updated_idx"),
        ("index", "activities_workspace_lease_idx"),
        change_set_objects[0],
        change_set_objects[1],
        change_set_objects[2],
        change_set_objects[3],
        diff_objects[0],
        diff_objects[1],
        diff_objects[2],
        diff_objects[3],
        diff_objects[4],
        execution_objects[0],
        execution_objects[1],
        execution_objects[2],
        approval_objects[0],
        approval_objects[1],
        approval_objects[2],
        approval_objects[3],
        approval_objects[4],
        approval_objects[5],
        approval_objects[6],
        approval_objects[7],
        checkpoint_objects[0],
        checkpoint_objects[1],
        checkpoint_objects[2],
        checkpoint_objects[3],
        checkpoint_objects[4],
        checkpoint_objects[5],
    ];
    validate_schema_objects_for(connection, &expected)
}

fn validate_schema_objects_v9(connection: &Connection) -> Result<(), WorkspaceStoreError> {
    let change_set_objects = workspace_changesets::schema_objects();
    let diff_objects = workspace_diffs::schema_objects();
    let execution_objects = workspace_executions::schema_objects();
    let approval_objects = workspace_approvals::schema_objects();
    let checkpoint_objects = workspace_checkpoints::schema_objects();
    let goal_objects = workspace_goals::schema_objects();
    let expected = [
        ("table", "workspace"),
        ("table", "activities"),
        ("index", "activities_workspace_updated_idx"),
        ("index", "activities_workspace_lease_idx"),
        change_set_objects[0],
        change_set_objects[1],
        change_set_objects[2],
        change_set_objects[3],
        diff_objects[0],
        diff_objects[1],
        diff_objects[2],
        diff_objects[3],
        diff_objects[4],
        execution_objects[0],
        execution_objects[1],
        execution_objects[2],
        approval_objects[0],
        approval_objects[1],
        approval_objects[2],
        approval_objects[3],
        approval_objects[4],
        approval_objects[5],
        approval_objects[6],
        approval_objects[7],
        checkpoint_objects[0],
        checkpoint_objects[1],
        checkpoint_objects[2],
        checkpoint_objects[3],
        checkpoint_objects[4],
        checkpoint_objects[5],
        goal_objects[0],
        goal_objects[1],
        goal_objects[2],
        goal_objects[3],
        goal_objects[4],
        goal_objects[5],
        goal_objects[6],
    ];
    validate_schema_objects_for(connection, &expected)
}

fn validate_schema_objects_v10(connection: &Connection) -> Result<(), WorkspaceStoreError> {
    let mut expected = Vec::from([
        ("table", "workspace"),
        ("table", "activities"),
        ("index", "activities_workspace_updated_idx"),
        ("index", "activities_workspace_lease_idx"),
    ]);
    expected.extend(workspace_changesets::schema_objects());
    expected.extend(workspace_diffs::schema_objects());
    expected.extend(workspace_executions::schema_objects());
    expected.extend(workspace_approvals::schema_objects());
    expected.extend(workspace_checkpoints::schema_objects());
    expected.extend(workspace_goals::schema_objects());
    expected.extend(workspace_dags::schema_objects());
    validate_schema_objects_for(connection, &expected)
}

fn validate_schema_objects_v11(connection: &Connection) -> Result<(), WorkspaceStoreError> {
    let mut expected = Vec::from([
        ("table", "workspace"),
        ("table", "activities"),
        ("index", "activities_workspace_updated_idx"),
        ("index", "activities_workspace_lease_idx"),
    ]);
    expected.extend(workspace_changesets::schema_objects());
    expected.extend(workspace_diffs::schema_objects());
    expected.extend(workspace_executions::schema_objects());
    expected.extend(workspace_approvals::schema_objects());
    expected.extend(workspace_checkpoints::schema_objects());
    expected.extend(workspace_goals::schema_objects());
    expected.extend(workspace_dags::schema_objects());
    expected.extend(workspace_recovery::schema_objects());
    validate_schema_objects_for(connection, &expected)
}

fn validate_schema_objects_v12(connection: &Connection) -> Result<(), WorkspaceStoreError> {
    let mut expected = Vec::from([
        ("table", "workspace"),
        ("table", "activities"),
        ("index", "activities_workspace_updated_idx"),
        ("index", "activities_workspace_lease_idx"),
    ]);
    expected.extend(workspace_changesets::schema_objects());
    expected.extend(workspace_diffs::schema_objects());
    expected.extend(workspace_executions::schema_objects());
    expected.extend(workspace_approvals::schema_objects());
    expected.extend(workspace_checkpoints::schema_objects());
    expected.extend(workspace_goals::schema_objects());
    expected.extend(workspace_dags::schema_objects());
    expected.extend(workspace_recovery::schema_objects());
    validate_schema_objects_for(connection, &expected)
}

fn validate_schema_objects(connection: &Connection) -> Result<(), WorkspaceStoreError> {
    let mut expected = Vec::from([
        ("table", "workspace"),
        ("table", "activities"),
        ("index", "activities_workspace_updated_idx"),
        ("index", "activities_workspace_lease_idx"),
    ]);
    expected.extend(workspace_changesets::schema_objects());
    expected.extend(workspace_diffs::schema_objects());
    expected.extend(workspace_executions::schema_objects());
    expected.extend(workspace_approvals::schema_objects());
    expected.extend(workspace_checkpoints::schema_objects());
    expected.extend(workspace_goals::schema_objects());
    expected.extend(workspace_dags::schema_objects());
    expected.extend(workspace_recovery::schema_objects());
    expected.extend(workspace_harness::schema_objects());
    expected.extend(workspace_harness_verifiers::schema_objects());
    expected.extend(workspace_agents::schema_objects());
    expected.extend(workspace_agent_dag::schema_objects());
    validate_schema_objects_for(connection, &expected)
}

fn validate_schema_objects_v15(connection: &Connection) -> Result<(), WorkspaceStoreError> {
    let mut expected = Vec::from([
        ("table", "workspace"),
        ("table", "activities"),
        ("index", "activities_workspace_updated_idx"),
        ("index", "activities_workspace_lease_idx"),
    ]);
    expected.extend(workspace_changesets::schema_objects());
    expected.extend(workspace_diffs::schema_objects());
    expected.extend(workspace_executions::schema_objects());
    expected.extend(workspace_approvals::schema_objects());
    expected.extend(workspace_checkpoints::schema_objects());
    expected.extend(workspace_goals::schema_objects());
    expected.extend(workspace_dags::schema_objects());
    expected.extend(workspace_recovery::schema_objects());
    expected.extend(workspace_harness::schema_objects());
    expected.extend(workspace_harness_verifiers::schema_objects());
    expected.extend(workspace_agents::schema_objects_v15());
    expected.extend([
        ("table", "agent_transport_principals"),
        ("index", "agent_transport_principals_workspace_token_idx"),
    ]);
    validate_schema_objects_for(connection, &expected)
}

fn validate_schema_objects_v13(connection: &Connection) -> Result<(), WorkspaceStoreError> {
    let mut expected = Vec::from([
        ("table", "workspace"),
        ("table", "activities"),
        ("index", "activities_workspace_updated_idx"),
        ("index", "activities_workspace_lease_idx"),
    ]);
    expected.extend(workspace_changesets::schema_objects());
    expected.extend(workspace_diffs::schema_objects());
    expected.extend(workspace_executions::schema_objects());
    expected.extend(workspace_approvals::schema_objects());
    expected.extend(workspace_checkpoints::schema_objects());
    expected.extend(workspace_goals::schema_objects());
    expected.extend(workspace_dags::schema_objects());
    expected.extend(workspace_recovery::schema_objects());
    expected.extend(workspace_harness::schema_objects());
    validate_schema_objects_for(connection, &expected)
}

fn validate_schema_objects_v14(connection: &Connection) -> Result<(), WorkspaceStoreError> {
    let mut expected = Vec::from([
        ("table", "workspace"),
        ("table", "activities"),
        ("index", "activities_workspace_updated_idx"),
        ("index", "activities_workspace_lease_idx"),
    ]);
    expected.extend(workspace_changesets::schema_objects());
    expected.extend(workspace_diffs::schema_objects());
    expected.extend(workspace_executions::schema_objects());
    expected.extend(workspace_approvals::schema_objects());
    expected.extend(workspace_checkpoints::schema_objects());
    expected.extend(workspace_goals::schema_objects());
    expected.extend(workspace_dags::schema_objects());
    expected.extend(workspace_recovery::schema_objects());
    expected.extend(workspace_harness::schema_objects());
    expected.extend(workspace_harness_verifiers::schema_objects());
    validate_schema_objects_for(connection, &expected)
}

fn validate_schema_objects_v6(connection: &Connection) -> Result<(), WorkspaceStoreError> {
    let change_set_objects = workspace_changesets::schema_objects();
    let diff_objects = workspace_diffs::schema_objects();
    let execution_objects = workspace_executions::schema_objects();
    let expected = [
        ("table", "workspace"),
        ("table", "activities"),
        ("index", "activities_workspace_updated_idx"),
        ("index", "activities_workspace_lease_idx"),
        change_set_objects[0],
        change_set_objects[1],
        change_set_objects[2],
        change_set_objects[3],
        diff_objects[0],
        diff_objects[1],
        diff_objects[2],
        diff_objects[3],
        diff_objects[4],
        execution_objects[0],
        execution_objects[1],
        execution_objects[2],
    ];
    validate_schema_objects_for(connection, &expected)
}

fn validate_schema_objects_v5(connection: &Connection) -> Result<(), WorkspaceStoreError> {
    let change_set_objects = workspace_changesets::schema_objects();
    let diff_objects = workspace_diffs::schema_objects();
    let expected = [
        ("table", "workspace"),
        ("table", "activities"),
        ("index", "activities_workspace_updated_idx"),
        ("index", "activities_workspace_lease_idx"),
        change_set_objects[0],
        change_set_objects[1],
        change_set_objects[2],
        change_set_objects[3],
        diff_objects[0],
        diff_objects[1],
        diff_objects[2],
        diff_objects[3],
        diff_objects[4],
    ];
    validate_schema_objects_for(connection, &expected)
}

fn validate_schema_objects_v3(connection: &Connection) -> Result<(), WorkspaceStoreError> {
    let change_set_objects = workspace_changesets::schema_objects();
    let expected = [
        ("table", "workspace"),
        ("table", "activities"),
        ("index", "activities_workspace_updated_idx"),
        ("index", "activities_workspace_lease_idx"),
        change_set_objects[0],
        change_set_objects[1],
        change_set_objects[2],
        change_set_objects[3],
    ];
    validate_schema_objects_for(connection, &expected)
}

fn validate_schema_objects_v4(connection: &Connection) -> Result<(), WorkspaceStoreError> {
    let change_set_objects = workspace_changesets::schema_objects();
    let diff_objects = workspace_diffs::schema_objects_v4();
    let expected = [
        ("table", "workspace"),
        ("table", "activities"),
        ("index", "activities_workspace_updated_idx"),
        ("index", "activities_workspace_lease_idx"),
        change_set_objects[0],
        change_set_objects[1],
        change_set_objects[2],
        change_set_objects[3],
        diff_objects[0],
        diff_objects[1],
        diff_objects[2],
        diff_objects[3],
    ];
    validate_schema_objects_for(connection, &expected)
}

fn validate_schema_objects_v2(connection: &Connection) -> Result<(), WorkspaceStoreError> {
    validate_schema_objects_for(
        connection,
        &[
            ("table", "workspace"),
            ("table", "activities"),
            ("index", "activities_workspace_updated_idx"),
            ("index", "activities_workspace_lease_idx"),
        ],
    )
}

fn validate_schema_objects_v1(connection: &Connection) -> Result<(), WorkspaceStoreError> {
    validate_schema_objects_for(
        connection,
        &[
            ("table", "workspace"),
            ("table", "activities"),
            ("index", "activities_workspace_updated_idx"),
        ],
    )
}

fn validate_schema_objects_for(
    connection: &Connection,
    expected: &[(&str, &str)],
) -> Result<(), WorkspaceStoreError> {
    let mut statement = connection.prepare(
        "SELECT type, name,
                length(CAST(name AS BLOB)),
                length(CAST(sql AS BLOB))
         FROM sqlite_schema
         WHERE name NOT LIKE 'sqlite_%'
         ORDER BY type, name",
    )?;
    let mut rows = statement.query([])?;
    let mut objects = Vec::new();
    while let Some(row) = rows.next()? {
        if objects.len() >= MAX_SCHEMA_METADATA_ROWS {
            return Err(WorkspaceStoreError::SchemaMetadataTooLarge {
                object: "schema objects",
                actual: objects.len() + 1,
                maximum: MAX_SCHEMA_METADATA_ROWS,
            });
        }
        let name_length = row.get::<_, i64>(2)?;
        validate_schema_name_length(name_length)?;
        let sql_length = row.get::<_, Option<i64>>(3)?;
        if let Some(sql_length) = sql_length {
            validate_schema_sql_length("Workspace schema object", sql_length)?;
        }
        objects.push((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            name_length,
            sql_length,
        ));
    }
    if objects.len() != expected.len() {
        return Err(WorkspaceStoreError::DamagedSchema {
            detail: format!(
                "Workspace schema contains unexpected objects (actual {}, expected {})",
                objects.len(),
                expected.len()
            ),
        });
    }
    for (object_type, name, name_length, sql_length) in objects {
        let _ = (name_length, sql_length);
        if !expected.iter().any(|(expected_type, expected_name)| {
            *expected_type == object_type && *expected_name == name
        }) {
            return Err(WorkspaceStoreError::DamagedSchema {
                detail: format!("unexpected schema object {object_type} {name}"),
            });
        }
    }
    Ok(())
}

fn table_columns(
    connection: &Connection,
    table: &'static str,
) -> Result<Vec<(String, String, i64, i64)>, WorkspaceStoreError> {
    let mut statement = connection.prepare(&format!("PRAGMA table_info({table})"))?;
    let mut rows = statement.query([])?;
    collect_bounded_metadata(&mut rows, "table columns", |row| {
        Ok((
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, i64>(5)?,
        ))
    })
}

fn bounded_schema_sql(
    connection: &Connection,
    object_type: &str,
    object_name: &str,
    object: &'static str,
) -> Result<Option<String>, WorkspaceStoreError> {
    let length: Option<i64> = connection.query_row(
        "SELECT length(CAST(sql AS BLOB))
         FROM sqlite_schema WHERE type = ?1 AND name = ?2",
        params![object_type, object_name],
        |row| row.get(0),
    )?;
    let Some(length) = length else {
        return Ok(None);
    };
    validate_schema_sql_length(object, length)?;
    connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type = ?1 AND name = ?2",
            params![object_type, object_name],
            |row| row.get(0),
        )
        .optional()
        .map_err(WorkspaceStoreError::from)
}

fn validate_schema_name_length(length: i64) -> Result<(), WorkspaceStoreError> {
    if length < 0 {
        return Err(WorkspaceStoreError::DamagedSchema {
            detail: "schema object name length is negative".to_owned(),
        });
    }
    let actual = usize::try_from(length).unwrap_or(usize::MAX);
    if actual > MAX_SCHEMA_NAME_BYTES {
        return Err(WorkspaceStoreError::SchemaMetadataTooLarge {
            object: "schema object name",
            actual,
            maximum: MAX_SCHEMA_NAME_BYTES,
        });
    }
    Ok(())
}

fn validate_schema_sql_length(
    object: &'static str,
    length: i64,
) -> Result<(), WorkspaceStoreError> {
    if length < 0 {
        return Err(WorkspaceStoreError::DamagedSchema {
            detail: "schema SQL length is negative".to_owned(),
        });
    }
    let actual = usize::try_from(length).unwrap_or(usize::MAX);
    if actual > MAX_SCHEMA_SQL_BYTES {
        return Err(WorkspaceStoreError::SchemaSqlTooLarge {
            object,
            actual,
            maximum: MAX_SCHEMA_SQL_BYTES,
        });
    }
    Ok(())
}

fn collect_bounded_metadata<T, F>(
    rows: &mut Rows<'_>,
    object: &'static str,
    mut decode: F,
) -> Result<Vec<T>, WorkspaceStoreError>
where
    F: FnMut(&Row<'_>) -> rusqlite::Result<T>,
{
    let mut values = Vec::new();
    while let Some(row) = rows.next()? {
        if values.len() >= MAX_SCHEMA_METADATA_ROWS {
            return Err(WorkspaceStoreError::SchemaMetadataTooLarge {
                object,
                actual: values.len() + 1,
                maximum: MAX_SCHEMA_METADATA_ROWS,
            });
        }
        values.push(decode(row)?);
    }
    Ok(values)
}

fn schema_sql_matches(actual: &str, expected: &str) -> bool {
    let actual_bytes = actual
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .map(|byte| byte.to_ascii_lowercase());
    let expected_bytes = expected
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .map(|byte| byte.to_ascii_lowercase());
    actual_bytes.eq(expected_bytes)
}

#[derive(Debug)]
struct RuntimePolicy {
    journal_mode: String,
    foreign_keys_enabled: bool,
    synchronous: i64,
}

fn runtime_policy(connection: &Connection) -> Result<RuntimePolicy, WorkspaceStoreError> {
    let journal_mode = connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
    let foreign_keys: i64 =
        connection.pragma_query_value(None, "foreign_keys", |row| row.get(0))?;
    let synchronous: i64 = connection.pragma_query_value(None, "synchronous", |row| row.get(0))?;
    Ok(RuntimePolicy {
        journal_mode,
        foreign_keys_enabled: foreign_keys == 1,
        synchronous,
    })
}

fn validate_runtime_policy(policy: &RuntimePolicy) -> Result<(), WorkspaceStoreError> {
    if !policy.journal_mode.eq_ignore_ascii_case("wal") {
        return Err(WorkspaceStoreError::UnhealthyConfiguration {
            setting: "journal_mode",
            actual: policy.journal_mode.clone(),
            expected: "WAL",
        });
    }
    if !policy.foreign_keys_enabled {
        return Err(WorkspaceStoreError::UnhealthyConfiguration {
            setting: "foreign_keys",
            actual: "OFF".to_owned(),
            expected: "ON",
        });
    }
    if policy.synchronous != 2 {
        return Err(WorkspaceStoreError::UnhealthyConfiguration {
            setting: "synchronous",
            actual: synchronous_label(policy.synchronous).to_owned(),
            expected: "FULL",
        });
    }
    Ok(())
}

const fn synchronous_label(value: i64) -> &'static str {
    match value {
        0 => "OFF",
        1 => "NORMAL",
        2 => "FULL",
        3 => "EXTRA",
        _ => "UNKNOWN",
    }
}

fn migrate_fresh(connection: &mut Connection) -> Result<(), WorkspaceStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.pragma_update(None, "application_id", WORKSPACE_APPLICATION_ID)?;
    transaction.execute_batch(
        "CREATE TABLE workspace (
            singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
            workspace_id BLOB NOT NULL UNIQUE CHECK(length(workspace_id) = 16),
            location_id BLOB NOT NULL CHECK(length(location_id) = 16),
            root_path BLOB NOT NULL,
            root_fingerprint BLOB NOT NULL CHECK(length(root_fingerprint) = 16),
            created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
            updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0),
            revision INTEGER NOT NULL CHECK(revision >= 1)
         );
         CREATE TABLE activities (
            activity_id BLOB PRIMARY KEY NOT NULL CHECK(length(activity_id) = 16),
            workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id),
            state INTEGER NOT NULL CHECK(state IN (0, 1, 2)),
            created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
            updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0),
            revision INTEGER NOT NULL CHECK(revision >= 1),
            lease_owner_id BLOB CHECK(lease_owner_id IS NULL OR length(lease_owner_id) = 16),
            lease_until_ms INTEGER CHECK(lease_until_ms IS NULL OR lease_until_ms >= 0),
            lease_revision INTEGER NOT NULL CHECK(lease_revision >= 1),
            CHECK((lease_owner_id IS NULL) = (lease_until_ms IS NULL))
         );
         CREATE INDEX activities_workspace_updated_idx
             ON activities(workspace_id, updated_at_ms DESC, activity_id DESC);
         CREATE INDEX activities_workspace_lease_idx
             ON activities(workspace_id, state, lease_until_ms, activity_id);",
    )?;
    workspace_changesets::create_schema(&transaction)?;
    workspace_diffs::create_schema(&transaction)?;
    workspace_executions::create_schema(&transaction)?;
    workspace_approvals::create_schema(&transaction)?;
    workspace_checkpoints::create_schema(&transaction)?;
    workspace_goals::create_schema(&transaction)?;
    workspace_dags::create_schema(&transaction)?;
    workspace_recovery::create_schema(&transaction)?;
    workspace_harness::create_schema(&transaction)?;
    workspace_harness_verifiers::create_schema(&transaction)?;
    workspace_agents::create_schema(&transaction)?;
    workspace_agent_dag::create_schema(&transaction)?;
    transaction.pragma_update(None, "user_version", CURRENT_SCHEMA_VERSION)?;
    transaction.commit()?;
    Ok(())
}

/// Migrate the first Workspace schema without changing any durable v1 value.
///
/// `SQLite` cannot add the all-null/all-present lease pair and its table-level
/// checks with a simple `ALTER TABLE`, so the migration uses a short IMMEDIATE
/// transaction and copies every v1 row while explicitly supplying the only
/// new value that has a meaning: the initial lease revision.  Existing rows
/// remain open/closed exactly as before and start unleased.
fn migrate_v1_to_v2(connection: &mut Connection) -> Result<(), WorkspaceStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(
        "ALTER TABLE activities RENAME TO activities_v1;
         CREATE TABLE activities (
            activity_id BLOB PRIMARY KEY NOT NULL CHECK(length(activity_id) = 16),
            workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id),
            state INTEGER NOT NULL CHECK(state IN (0, 1, 2)),
            created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
            updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0),
            revision INTEGER NOT NULL CHECK(revision >= 1),
            lease_owner_id BLOB CHECK(lease_owner_id IS NULL OR length(lease_owner_id) = 16),
            lease_until_ms INTEGER CHECK(lease_until_ms IS NULL OR lease_until_ms >= 0),
            lease_revision INTEGER NOT NULL CHECK(lease_revision >= 1),
            CHECK((lease_owner_id IS NULL) = (lease_until_ms IS NULL))
         );
         INSERT INTO activities (
            activity_id, workspace_id, state, created_at_ms, updated_at_ms,
            revision, lease_owner_id, lease_until_ms, lease_revision
         )
         SELECT activity_id, workspace_id, state, created_at_ms, updated_at_ms,
                revision, NULL, NULL, 1
         FROM activities_v1;
         DROP TABLE activities_v1;
         CREATE INDEX activities_workspace_updated_idx
             ON activities(workspace_id, updated_at_ms DESC, activity_id DESC);
         CREATE INDEX activities_workspace_lease_idx
             ON activities(workspace_id, state, lease_until_ms, activity_id);",
    )?;
    transaction.pragma_update(None, "user_version", 2_i64)?;
    transaction.commit()?;
    Ok(())
}

fn inspect_read_only_workspace_identity(
    database: &ReadOnlyDoctorDatabase,
    layout: &ExistingWorkspaceStateLayout,
) -> Result<ReadOnlyWorkspaceIdentitySnapshot, WorkspaceStoreError> {
    database.ensure_unchanged()?;
    let ownership = match inspect_database(&database.connection) {
        Ok(ownership) => ownership,
        Err(WorkspaceStoreError::UnsupportedSchemaVersion {
            actual,
            maximum_supported,
        }) => {
            return Err(WorkspaceStoreError::UnsupportedForReadOnly {
                actual,
                maximum_supported,
            });
        }
        Err(error) => return Err(error),
    };
    if ownership == DatabaseOwnership::Fresh {
        return Err(WorkspaceStoreError::FreshDatabase);
    }
    if let Some(actual) = migration_required_version(ownership) {
        return Err(WorkspaceStoreError::MigrationRequired {
            actual,
            required: CURRENT_SCHEMA_VERSION,
        });
    }
    let schema_version = schema_version(&database.connection)?;
    let application_id = application_id(&database.connection)?;
    validate_schema_shape(&database.connection)?;
    let workspace = query_workspace_row(&database.connection)?
        .ok_or(WorkspaceStoreError::WorkspaceIdentityMissing)
        .and_then(decode_workspace)?;
    validate_existing_workspace_binding(&workspace, layout, database.root_fingerprint)?;
    let _recovery_lease = workspace_recovery::get(&database.connection, workspace.id())?;
    database.ensure_unchanged()?;
    Ok(ReadOnlyWorkspaceIdentitySnapshot {
        schema_version,
        application_id,
        workspace,
    })
}

fn application_id(connection: &Connection) -> Result<i64, WorkspaceStoreError> {
    connection
        .pragma_query_value(None, "application_id", |row| row.get(0))
        .map_err(WorkspaceStoreError::from)
}

fn schema_version(connection: &Connection) -> Result<i64, WorkspaceStoreError> {
    connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(WorkspaceStoreError::from)
}

#[derive(Debug)]
struct RawWorkspaceRow {
    id: Vec<u8>,
    location_id: Vec<u8>,
    root: Vec<u8>,
    fingerprint: Vec<u8>,
    created_at: i64,
    updated_at: i64,
    revision: i64,
}

fn query_workspace_row(
    connection: &Connection,
) -> Result<Option<RawWorkspaceRow>, WorkspaceStoreError> {
    let mut statement = connection.prepare(WORKSPACE_BY_SINGLETON_QUERY)?;
    let mut rows = statement.query([])?;
    let Some(row) = rows.next()? else {
        return Ok(None);
    };
    let raw = decode_raw_workspace(row)?;
    drop(rows);
    drop(statement);
    Ok(Some(raw))
}

fn decode_raw_workspace(row: &Row<'_>) -> Result<RawWorkspaceRow, WorkspaceStoreError> {
    validate_exact_length("workspace_id", row.get(0)?, ID_BYTES_I64, ID_BYTES)?;
    validate_exact_length("location_id", row.get(1)?, ID_BYTES_I64, ID_BYTES)?;
    validate_persisted_length("root_path", row.get(2)?, MAX_WORKSPACE_ROOT_BYTES)?;
    validate_exact_length(
        "root_fingerprint",
        row.get(3)?,
        FINGERPRINT_BYTES_I64,
        FINGERPRINT_BYTES,
    )?;
    Ok(RawWorkspaceRow {
        id: row.get(4)?,
        location_id: row.get(5)?,
        root: row.get(6)?,
        fingerprint: row.get(7)?,
        created_at: row.get(8)?,
        updated_at: row.get(9)?,
        revision: row.get(10)?,
    })
}

fn decode_workspace(raw: RawWorkspaceRow) -> Result<RegisteredWorkspace, WorkspaceStoreError> {
    let id = decode_workspace_id(&raw.id)?;
    let location_id = decode_location_id(&raw.location_id)?;
    let root = WorkspaceRoot::from_canonical(path_from_bytes(raw.root)).map_err(|source| {
        WorkspaceStoreError::CorruptRecord {
            field: "root_path",
            detail: source.to_string(),
        }
    })?;
    let fingerprint = decode_fingerprint(&raw.fingerprint)?;
    let created_at = TimestampMillis::new(raw.created_at).map_err(|source| {
        WorkspaceStoreError::CorruptRecord {
            field: "created_at_ms",
            detail: source.to_string(),
        }
    })?;
    let updated_at = TimestampMillis::new(raw.updated_at).map_err(|source| {
        WorkspaceStoreError::CorruptRecord {
            field: "updated_at_ms",
            detail: source.to_string(),
        }
    })?;
    let revision = WorkspaceRevision::new(raw.revision).map_err(|source| {
        WorkspaceStoreError::CorruptRecord {
            field: "revision",
            detail: source.to_string(),
        }
    })?;
    Ok(RegisteredWorkspace::from_parts_with_revision(
        id,
        location_id,
        root,
        fingerprint,
        created_at,
        updated_at,
        revision,
    ))
}

#[derive(Debug)]
struct RawActivityRow {
    id: Vec<u8>,
    workspace_id: Vec<u8>,
    state: i64,
    created_at: i64,
    updated_at: i64,
    revision: i64,
    lease_owner_id: Option<Vec<u8>>,
    lease_until: Option<i64>,
    lease_revision: i64,
}

fn query_activity_row(
    connection: &Connection,
    id: ActivityId,
) -> Result<Option<RawActivityRow>, WorkspaceStoreError> {
    let id_bytes = id.into_uuid().into_bytes();
    let mut statement = connection.prepare(ACTIVITY_BY_ID_QUERY)?;
    let mut rows = statement.query(params![id_bytes.as_slice()])?;
    let Some(row) = rows.next()? else {
        return Ok(None);
    };
    let raw = decode_raw_activity(row)?;
    drop(rows);
    drop(statement);
    Ok(Some(raw))
}

fn decode_raw_activity(row: &Row<'_>) -> Result<RawActivityRow, WorkspaceStoreError> {
    validate_exact_length("activity_id", row.get(0)?, ID_BYTES_I64, ID_BYTES)?;
    validate_exact_length("activity.workspace_id", row.get(1)?, ID_BYTES_I64, ID_BYTES)?;
    let owner_length: Option<i64> = row.get(2)?;
    if let Some(length) = owner_length {
        validate_exact_length("activity.lease_owner_id", length, ID_BYTES_I64, ID_BYTES)?;
    }
    Ok(RawActivityRow {
        id: row.get(3)?,
        workspace_id: row.get(4)?,
        state: row.get(5)?,
        created_at: row.get(6)?,
        updated_at: row.get(7)?,
        revision: row.get(8)?,
        lease_owner_id: row.get(9)?,
        lease_until: row.get(10)?,
        lease_revision: row.get(11)?,
    })
}

fn decode_activity(raw: &RawActivityRow) -> Result<RegisteredActivity, WorkspaceStoreError> {
    let id = decode_activity_id(&raw.id)?;
    let workspace_id = decode_workspace_id(&raw.workspace_id)?;
    let state = decode_activity_state(raw.state)?;
    let created_at = TimestampMillis::new(raw.created_at).map_err(|source| {
        WorkspaceStoreError::CorruptRecord {
            field: "activity.created_at_ms",
            detail: source.to_string(),
        }
    })?;
    let updated_at = TimestampMillis::new(raw.updated_at).map_err(|source| {
        WorkspaceStoreError::CorruptRecord {
            field: "activity.updated_at_ms",
            detail: source.to_string(),
        }
    })?;
    let revision = ActivityRevision::new(raw.revision).map_err(|source| {
        WorkspaceStoreError::CorruptRecord {
            field: "activity.revision",
            detail: source.to_string(),
        }
    })?;
    let lease_owner_id = raw
        .lease_owner_id
        .as_deref()
        .map(decode_runtime_instance_id)
        .transpose()?;
    let lease_until = raw
        .lease_until
        .map(TimestampMillis::new)
        .transpose()
        .map_err(|source| WorkspaceStoreError::CorruptRecord {
            field: "activity.lease_until_ms",
            detail: source.to_string(),
        })?;
    let lease_revision = ActivityLeaseRevision::new(raw.lease_revision).map_err(|source| {
        WorkspaceStoreError::CorruptRecord {
            field: "activity.lease_revision",
            detail: source.to_string(),
        }
    })?;
    let lease = ActivityLeaseProjection::from_parts(lease_owner_id, lease_until, lease_revision)
        .map_err(|source| WorkspaceStoreError::CorruptRecord {
            field: "activity.lease",
            detail: source.to_string(),
        })?;
    if matches!(state, ActivityState::Closed | ActivityState::Interrupted) && !lease.is_unleased() {
        return Err(WorkspaceStoreError::CorruptRecord {
            field: "activity.lease",
            detail: "terminal Activity must not retain a live lease".to_owned(),
        });
    }
    Ok(RegisteredActivity::from_parts_with_lease(
        id,
        workspace_id,
        state,
        created_at,
        updated_at,
        revision,
        lease,
    ))
}

fn validate_activity_workspace(
    activity: &RegisteredActivity,
    expected: WorkspaceId,
) -> Result<(), WorkspaceStoreError> {
    if activity.workspace_id() == expected {
        Ok(())
    } else {
        Err(WorkspaceStoreError::ActivityWorkspaceMismatch {
            expected,
            actual: activity.workspace_id(),
        })
    }
}

fn decode_workspace_id(bytes: &[u8]) -> Result<WorkspaceId, WorkspaceStoreError> {
    Uuid::from_slice(bytes)
        .map(WorkspaceId::from_uuid)
        .map_err(|source| WorkspaceStoreError::CorruptRecord {
            field: "workspace_id",
            detail: source.to_string(),
        })
}

fn decode_activity_id(bytes: &[u8]) -> Result<ActivityId, WorkspaceStoreError> {
    Uuid::from_slice(bytes)
        .map(ActivityId::from_uuid)
        .map_err(|source| WorkspaceStoreError::CorruptRecord {
            field: "activity_id",
            detail: source.to_string(),
        })
}

fn decode_runtime_instance_id(bytes: &[u8]) -> Result<RuntimeInstanceId, WorkspaceStoreError> {
    Uuid::from_slice(bytes)
        .map(RuntimeInstanceId::from_uuid)
        .map_err(|source| WorkspaceStoreError::CorruptRecord {
            field: "activity.lease_owner_id",
            detail: source.to_string(),
        })
}

fn decode_location_id(bytes: &[u8]) -> Result<LocationId, WorkspaceStoreError> {
    Uuid::from_slice(bytes)
        .map(LocationId::from_uuid)
        .map_err(|source| WorkspaceStoreError::CorruptRecord {
            field: "location_id",
            detail: source.to_string(),
        })
}

fn decode_fingerprint(bytes: &[u8]) -> Result<WorkspaceRootFingerprint, WorkspaceStoreError> {
    let value: [u8; FINGERPRINT_BYTES] =
        bytes
            .try_into()
            .map_err(|_| WorkspaceStoreError::PersistedFieldLengthInvalid {
                field: "root_fingerprint",
                actual: bytes.len(),
                expected: FINGERPRINT_BYTES,
            })?;
    Ok(WorkspaceRootFingerprint::from_bytes(value))
}

pub(crate) const fn encode_activity_state(state: ActivityState) -> i64 {
    match state {
        ActivityState::Open => 1,
        ActivityState::Closed => 0,
        ActivityState::Interrupted => 2,
    }
}

fn decode_activity_state(value: i64) -> Result<ActivityState, WorkspaceStoreError> {
    match value {
        1 => Ok(ActivityState::Open),
        0 => Ok(ActivityState::Closed),
        2 => Ok(ActivityState::Interrupted),
        other => Err(WorkspaceStoreError::CorruptRecord {
            field: "activity.state",
            detail: format!("unknown state code {other}"),
        }),
    }
}

fn path_to_bytes_bounded(path: &Path) -> Result<Vec<u8>, WorkspaceStoreError> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.len() > MAX_WORKSPACE_ROOT_BYTES {
        return Err(WorkspaceStoreError::InputRootTooLarge {
            actual: bytes.len(),
            maximum: MAX_WORKSPACE_ROOT_BYTES,
        });
    }
    Ok(bytes.to_vec())
}

fn path_from_bytes(bytes: Vec<u8>) -> PathBuf {
    PathBuf::from(std::ffi::OsString::from_vec(bytes))
}

fn validate_exact_length(
    field: &'static str,
    length: i64,
    expected_i64: i64,
    expected: usize,
) -> Result<(), WorkspaceStoreError> {
    if length == expected_i64 {
        Ok(())
    } else {
        let actual = usize::try_from(length).unwrap_or(usize::MAX);
        Err(WorkspaceStoreError::PersistedFieldLengthInvalid {
            field,
            actual,
            expected,
        })
    }
}

fn validate_persisted_length(
    field: &'static str,
    length: i64,
    maximum: usize,
) -> Result<(), WorkspaceStoreError> {
    if length < 0 {
        return Err(WorkspaceStoreError::CorruptRecord {
            field,
            detail: "persisted length is negative".to_owned(),
        });
    }
    let actual = usize::try_from(length).unwrap_or(usize::MAX);
    if actual > maximum {
        Err(WorkspaceStoreError::PersistedFieldTooLarge {
            field,
            actual,
            maximum,
        })
    } else {
        Ok(())
    }
}

fn map_root_decision_error(error: WorkspaceRootDecisionError) -> WorkspaceStoreError {
    match error {
        WorkspaceRootDecisionError::FingerprintMismatch { expected, observed } => {
            WorkspaceStoreError::WorkspaceRootBindingConflict { expected, observed }
        }
        WorkspaceRootDecisionError::RevisionOverflow { current } => {
            WorkspaceStoreError::WorkspaceRevisionOverflow { current }
        }
    }
}

fn associate_work_evidence(
    transaction: &Transaction<'_>,
    attribution: Option<GoalWorkAttribution>,
    evidence: GoalEvidenceRef,
    associated_at: TimestampMillis,
) -> Result<(), WorkspaceStoreError> {
    workspace_goals::associate_optional_evidence_in_transaction(
        transaction,
        attribution,
        evidence,
        associated_at,
    )?;
    workspace_dags::associate_node_evidence_in_transaction(
        transaction,
        attribution.and_then(GoalWorkAttribution::node),
        evidence,
        associated_at,
    )?;
    Ok(())
}

/// Errors raised by the Workspace-local semantic authority.
#[derive(Debug, Error)]
pub enum WorkspaceStoreError {
    #[error("Workspace state database path has no parent directory: {0}")]
    MissingParent(PathBuf),
    #[error("failed to create Workspace state database parent directory {path}")]
    CreateParent {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("Workspace state database is missing: {0}")]
    MissingDatabase(PathBuf),
    #[error("Workspace state database is fresh and has not been established")]
    FreshDatabase,
    #[error("Workspace Doctor snapshot is {actual} bytes; maximum is {maximum}")]
    DoctorSnapshotTooLarge { actual: u64, maximum: u64 },
    #[error("failed to open Workspace state database {path}")]
    Open {
        path: PathBuf,
        #[source]
        source: rusqlite::Error,
    },
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    ChangeSet(#[from] ChangeSetStoreError),
    #[error(transparent)]
    Diff(#[from] DiffStoreError),
    #[error(transparent)]
    Execution(#[from] ExecutionStoreError),
    #[error(transparent)]
    Approval(#[from] ApprovalStoreError),
    #[error(transparent)]
    Checkpoint(#[from] CheckpointStoreError),
    #[error(transparent)]
    Goal(#[from] GoalStoreError),
    #[error(transparent)]
    Dag(#[from] crate::DagStoreError),
    #[error(transparent)]
    Recovery(#[from] RecoveryStoreError),
    #[error(transparent)]
    Harness(#[from] HarnessStoreError),
    #[error(transparent)]
    HarnessVerifier(#[from] HarnessVerifierStoreError),
    #[error(transparent)]
    Agent(#[from] AgentStoreError),
    #[error(transparent)]
    AgentDag(#[from] AgentDagStoreError),
    #[error("Workspace database has application id {actual:#x}; expected {expected:#x}")]
    DatabaseOwnershipMismatch { actual: i64, expected: i64 },
    #[error("Workspace database is non-empty but has no Forge ownership marker")]
    UnownedDatabase,
    #[error("Workspace schema is damaged: {detail}")]
    DamagedSchema { detail: String },
    #[error(
        "Workspace schema version {actual} is newer than supported version {maximum_supported}"
    )]
    UnsupportedSchemaVersion { actual: i64, maximum_supported: i64 },
    #[error(
        "Workspace schema version {actual} requires migration to version {required} before read-only inspection"
    )]
    MigrationRequired { actual: i64, required: i64 },
    #[error(
        "Workspace schema version {actual} is unsupported for read-only inspection; maximum is {maximum_supported}"
    )]
    UnsupportedForReadOnly { actual: i64, maximum_supported: i64 },
    #[error("Workspace {object} SQL is {actual} bytes; maximum is {maximum}")]
    SchemaSqlTooLarge {
        object: &'static str,
        actual: usize,
        maximum: usize,
    },
    #[error("Workspace {object} metadata has {actual} rows/bytes; maximum is {maximum}")]
    SchemaMetadataTooLarge {
        object: &'static str,
        actual: usize,
        maximum: usize,
    },
    #[error("persisted Workspace field {field} is {actual} bytes; maximum is {maximum}")]
    PersistedFieldTooLarge {
        field: &'static str,
        actual: usize,
        maximum: usize,
    },
    #[error("persisted Workspace field {field} has {actual} bytes; expected exactly {expected}")]
    PersistedFieldLengthInvalid {
        field: &'static str,
        actual: usize,
        expected: usize,
    },
    #[error("input Workspace root is {actual} bytes; maximum is {maximum}")]
    InputRootTooLarge { actual: usize, maximum: usize },
    #[error("Workspace database path is a symbolic link: {0}")]
    DatabasePathSymlink(PathBuf),
    #[error("Workspace database path is not a regular file: {0}")]
    DatabasePathNotRegular(PathBuf),
    #[error("Workspace database path has {links} hard links: {path}")]
    DatabasePathHardlink { path: PathBuf, links: u64 },
    #[error("failed to inspect Workspace database path {path}: {source}")]
    DatabasePathMetadata {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("Workspace database path invariant failed for {path}: {detail}")]
    DatabasePathInvariant { path: PathBuf, detail: &'static str },
    #[error("read-only Doctor snapshot {operation} failed for {path}: {source}")]
    DoctorSnapshotIo {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("Workspace database sidecar exists without its main database: {0}")]
    DatabaseSidecarWithoutMain(PathBuf),
    #[error("Workspace database WAL/SHM sidecars are incomplete: WAL {wal}, SHM {shm}")]
    DatabaseSidecarPairMismatch { wal: PathBuf, shm: PathBuf },
    #[error(
        "Workspace database has an active WAL; read-only inspection requires a quiescent database"
    )]
    ReadOnlyWalActive { wal: PathBuf, shm: PathBuf },
    #[error("Workspace database path identity changed: {0}")]
    DatabasePathChanged(PathBuf),
    #[error("Workspace state root is a symbolic link: {0}")]
    StateRootSymlink(PathBuf),
    #[error("Workspace state root is not a directory: {0}")]
    StateRootNotDirectory(PathBuf),
    #[error("failed to inspect Workspace state root {path}: {source}")]
    StateRootMetadata {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("Workspace state root physical identity changed: {0}")]
    StateRootChanged(PathBuf),
    #[error("Workspace root is a symbolic link: {0}")]
    WorkspaceRootSymlink(PathBuf),
    #[error("Workspace root is not a directory: {0}")]
    WorkspaceRootNotDirectory(PathBuf),
    #[error("failed to inspect Workspace root {path}: {source}")]
    WorkspaceRootMetadata {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("Workspace root canonical path changed from {expected} to {observed}")]
    WorkspaceRootCanonicalPathChanged {
        expected: PathBuf,
        observed: PathBuf,
    },
    #[error("Workspace root fingerprint changed")]
    WorkspaceRootFingerprintChanged {
        expected: WorkspaceRootFingerprint,
        observed: WorkspaceRootFingerprint,
    },
    #[error("Workspace command root {command_root} does not match state layout root {layout_root}")]
    LayoutRootMismatch {
        layout_root: PathBuf,
        command_root: PathBuf,
    },
    #[error("failed to observe Workspace layout root fingerprint")]
    LayoutFingerprintObservation {
        #[source]
        source: StateLayoutError,
    },
    #[error("Workspace root fingerprint does not match layout observation")]
    LayoutFingerprintMismatch {
        expected: WorkspaceRootFingerprint,
        observed: WorkspaceRootFingerprint,
    },
    #[error("SQLite runtime policy {setting} is {actual}; expected {expected}")]
    UnhealthyConfiguration {
        setting: &'static str,
        actual: String,
        expected: &'static str,
    },
    #[error("Workspace identity row is missing")]
    WorkspaceIdentityMissing,
    #[error("Workspace Location binding conflict: stored {stored}, requested {requested}")]
    LocationBindingConflict {
        stored: LocationId,
        requested: LocationId,
    },
    #[error("Workspace root fingerprint conflict: expected {expected:?}, observed {observed:?}")]
    WorkspaceRootBindingConflict {
        expected: WorkspaceRootFingerprint,
        observed: WorkspaceRootFingerprint,
    },
    #[error("existing Workspace binding does not match the observed state layout")]
    ExistingWorkspaceBindingMismatch {
        stored_root: PathBuf,
        observed_root: PathBuf,
        stored_fingerprint: WorkspaceRootFingerprint,
        observed_fingerprint: WorkspaceRootFingerprint,
    },
    #[error("Workspace revision conflict: expected {expected}, actual {actual}")]
    WorkspaceRevisionConflict {
        expected: WorkspaceRevision,
        actual: WorkspaceRevision,
    },
    #[error("Workspace revision overflow at {current}")]
    WorkspaceRevisionOverflow { current: WorkspaceRevision },
    #[error("Activity identity already exists: {0}")]
    ActivityIdConflict(ActivityId),
    #[error("Activity {0} was not found")]
    ActivityNotFound(ActivityId),
    #[error("Activity {0} is terminal and cannot be revived")]
    ActivityTerminal(ActivityId),
    #[error("Activity {0} has no live lease and cannot be attached; mint a new ActivityId")]
    ActivityLeaseUnavailable(ActivityId),
    #[error(
        "Activity {id} lease expired at {lease_until:?}; reconcile it before minting a new ActivityId (observed {observed_at:?})"
    )]
    ExpiredRecoveryRequired {
        id: ActivityId,
        lease_until: TimestampMillis,
        observed_at: TimestampMillis,
    },
    #[error("Activity {0} has an owned lease; use the explicit owner command")]
    ActivityLeaseRequired(ActivityId),
    #[error("invalid Activity transition for {id}: {from:?} -> {to:?}")]
    InvalidActivityTransition {
        id: ActivityId,
        from: ActivityState,
        to: ActivityState,
    },
    #[error(
        "Activity {id} is already live under runtime instance {owner_id} until {lease_until:?}"
    )]
    AlreadyLive {
        id: ActivityId,
        owner_id: RuntimeInstanceId,
        lease_until: TimestampMillis,
    },
    #[error("Activity {id} lease owner mismatch: expected {expected}, actual {actual:?}")]
    LeaseOwnerMismatch {
        id: ActivityId,
        expected: RuntimeInstanceId,
        actual: Option<RuntimeInstanceId>,
    },
    #[error("Activity {id} lease expired at {lease_until:?} before observation {observed_at:?}")]
    LeaseExpired {
        id: ActivityId,
        lease_until: TimestampMillis,
        observed_at: TimestampMillis,
    },
    #[error(
        "Activity lease window is invalid: expiry {lease_until:?} must be after observation {observed_at:?}"
    )]
    InvalidLeaseWindow {
        observed_at: TimestampMillis,
        lease_until: TimestampMillis,
    },
    #[error("Activity lease revision conflict for {id}: expected {expected}, actual {actual}")]
    LeaseRevisionConflict {
        id: ActivityId,
        expected: ActivityLeaseRevision,
        actual: ActivityLeaseRevision,
    },
    #[error("Activity lease revision overflow for {id} at {current}")]
    ActivityLeaseRevisionOverflow {
        id: ActivityId,
        current: ActivityLeaseRevision,
    },
    #[error(transparent)]
    ActivityLeaseBatchLimit(#[from] forge_domain::ActivityLeaseBatchLimitError),
    #[error("Activity lease batch owner mismatch: expected {expected}, actual {actual}")]
    ActivityLeaseBatchOwnerMismatch {
        expected: RuntimeInstanceId,
        actual: RuntimeInstanceId,
    },
    #[error("Activity {0} appears more than once in one lease batch")]
    ActivityLeaseBatchDuplicate(ActivityId),
    #[error("Activity lease batch produced no result for one input command")]
    ActivityBatchInvariant,
    #[error("Activity belongs to Workspace {actual}, expected {expected}")]
    ActivityWorkspaceMismatch {
        expected: WorkspaceId,
        actual: WorkspaceId,
    },
    #[error("Activity revision conflict for {id}: expected {expected}, actual {actual}")]
    ActivityRevisionConflict {
        id: ActivityId,
        expected: ActivityRevision,
        actual: ActivityRevision,
    },
    #[error("Activity revision overflow for {id} at {current}")]
    ActivityRevisionOverflow {
        id: ActivityId,
        current: ActivityRevision,
    },
    #[error("corrupt Workspace field {field}: {detail}")]
    CorruptRecord { field: &'static str, detail: String },
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::os::unix::fs::{MetadataExt, symlink};
    use std::path::PathBuf;
    use std::process::Command;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use forge_domain::{
        AbandonDiffEvidence, ActivityId, ActivityLeaseRevision, ActivityListLimit,
        ActivityRevision, ActivityState, BeginDiffEvidence, BeginDiffPurge, BeginFileMutation,
        BeginFileMutationStatus, BootstrapActivity, ChangeSetId, ChangeSetRevision, ChangeSetState,
        ClaimRecoveryLease, CloseActivity, CompleteDiffEvidence, CompleteDiffPurge,
        CompleteFileMutation, CreateActivity, DagAcceptanceCriterion, DagNodeDefinition, DagNodeId,
        DagNodeObjective, DagNodeOrdinal, DagNodeTitle, DagRevision, DagRevisionId,
        DagRevisionNumber, DiffArtifactRelativePath, DiffAttribution, DiffByteCount,
        DiffChangeKind, DiffContractVersions, DiffEvidenceState, DiffFileSummary, DiffId,
        DiffLineCount, DiffPayloadHash, DiffPayloadProjection, DiffPurgeStatus, DiffRenderKind,
        DiffRetentionKeepCount, DiffRetentionPlanLimit, DiffRevision, EstablishWorkspace,
        ExecutionId, ExecutionState, FailFileMutation, FileByteCount, FileContentHash,
        FileMutationFailureCode, FileMutationId, FileMutationIdentity, FileMutationKind,
        FileMutationPlan, FileMutationRevision, FileMutationScope, FilePathState, FilePrecondition,
        GoalContract, GoalEvidenceRef, GoalId, GoalListLimit, GoalNodeAttribution, GoalObjective,
        GoalStatement, GoalWorkAttribution, LocationId, ReconcileExpiredActivities,
        RecoveryLeaseDurationMillis, RegisteredActivity, RegisteredDagNode, RegisteredDiffEvidence,
        RegisteredGoal, ReleaseActivityLease, RenewActivityLease, RuntimeInstanceId,
        TimestampMillis, WorkspaceId, WorkspaceRelativePath, WorkspaceRevision, WorkspaceRoot,
    };
    use rusqlite::{Connection, ErrorCode, TransactionBehavior, params};
    use uuid::Uuid;

    use super::{
        CURRENT_SCHEMA_VERSION, EXPECTED_ACTIVITIES_TABLE_SQL, HARNESS_PREVIOUS_SCHEMA_VERSION,
        HARNESS_VERIFIER_PREVIOUS_SCHEMA_VERSION, MAX_DOCTOR_SNAPSHOT_BYTES,
        WORKSPACE_APPLICATION_ID, WorkspaceDoctorIntegrity, WorkspaceDoctorOutcome, WorkspaceStore,
        WorkspaceStoreError, validate_doctor_snapshot_size,
    };
    use crate::DiffStoreError;
    use crate::RecoveryLeaseClaimStatus;
    use forge_workspace::WorkspaceStateLayout;

    fn prepare_pre_v14_fixture(connection: &Connection) -> Result<(), Box<dyn std::error::Error>> {
        connection.execute_batch(
            "PRAGMA wal_checkpoint(TRUNCATE);
             PRAGMA journal_mode = DELETE;
             DROP TABLE agent_dag_replan_ledger;
             DROP TABLE agent_dag_authoring_grants;
             DROP INDEX agent_transport_principals_workspace_token_idx;
             DROP TABLE agent_transport_principals;
             DROP TABLE agent_work_update_evidence_refs;
             DROP TABLE agent_work_updates;
             DROP TABLE agent_focus_events;
             DROP TABLE agent_instances;
             DROP TABLE workspace_harness_verifier_items;
             DROP TABLE workspace_harness_verifier_runs;",
        )?;
        Ok(())
    }

    fn unique_root(label: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let unique = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path = std::env::temp_dir().join(format!("forge-workspace-store-{label}-{unique}"));
        fs::create_dir_all(&path)?;
        Ok(path)
    }

    fn workspace_id(value: u128) -> WorkspaceId {
        WorkspaceId::from_uuid(Uuid::from_u128(value))
    }

    fn location_id(value: u128) -> LocationId {
        LocationId::from_uuid(Uuid::from_u128(value))
    }

    fn activity_id(value: u128) -> ActivityId {
        ActivityId::from_uuid(Uuid::from_u128(value))
    }

    fn runtime_id(value: u128) -> RuntimeInstanceId {
        RuntimeInstanceId::from_uuid(Uuid::from_u128(value))
    }

    type FileSnapshot = Option<(Vec<u8>, SystemTime)>;

    fn file_snapshot(path: &std::path::Path) -> Result<FileSnapshot, Box<dyn std::error::Error>> {
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        Ok(Some((fs::read(path)?, metadata.modified()?)))
    }

    fn timestamp(value: i64) -> Result<TimestampMillis, Box<dyn std::error::Error>> {
        Ok(TimestampMillis::new(value)?)
    }

    fn insert_stale_doctor_records(
        store: &mut WorkspaceStore,
        workspace: &EstablishWorkspace,
        activity: &RegisteredActivity,
    ) -> Result<(Uuid, Uuid), Box<dyn std::error::Error>> {
        let execution_id = Uuid::from_u128(0xD013);
        let changeset_id = Uuid::from_u128(0xD014);
        let mutation_id = Uuid::from_u128(0xD015);
        let checkpoint_id = Uuid::from_u128(0xD016);
        let restore_id = Uuid::from_u128(0xD017);
        let workspace_id = workspace.id().into_uuid();
        let activity_id = activity.id().into_uuid();
        store.connection.execute(
            "INSERT INTO executions (
                execution_id, workspace_id, activity_id, state, mode, request_digest,
                cwd, timeout_ms, output_limit, workspace_read, workspace_write, network,
                created_at_ms, updated_at_ms, revision
             ) VALUES (?1, ?2, ?3, 0, 0, ?4, NULL, 1000, 16, 1, 0, 0, 20, 20, 1)",
            params![
                execution_id.as_bytes(),
                workspace_id.as_bytes(),
                activity_id.as_bytes(),
                [7_u8; 32].as_slice(),
            ],
        )?;
        store.connection.execute(
            "INSERT INTO change_sets (
                changeset_id, workspace_id, activity_id, runtime_instance_id,
                activity_lease_revision, workspace_revision, state, failure_code,
                created_at_ms, updated_at_ms, revision
             ) VALUES (?1, ?2, ?3, ?4, 1, 1, 0, NULL, 20, 20, 1)",
            params![
                changeset_id.as_bytes(),
                workspace_id.as_bytes(),
                activity_id.as_bytes(),
                [8_u8; 16].as_slice(),
            ],
        )?;
        store.connection.execute(
            "INSERT INTO file_mutations (
                mutation_id, changeset_id, ordinal, relative_path, kind, precondition,
                expected_hash, intended_hash, pre_state, pre_hash, pre_size,
                post_state, post_hash, post_size, revision
             ) VALUES (?1, ?2, 0, ?3, 0, 0, NULL, ?4, 0, NULL, NULL, NULL, NULL, NULL, 1)",
            params![
                mutation_id.as_bytes(),
                changeset_id.as_bytes(),
                b"doctor.txt".as_slice(),
                [9_u8; 32].as_slice(),
            ],
        )?;
        store.connection.execute(
            "INSERT INTO checkpoints (
                checkpoint_id, changeset_id, workspace_id, activity_id, workspace_revision,
                relative_path, object_format, state, pre_state, pre_blob, pre_hash,
                pre_size, pre_mode, pre_commit, post_state, post_blob, post_hash,
                post_size, post_mode, post_commit, created_at_ms, updated_at_ms, revision
             ) VALUES (?1, ?2, ?3, ?4, 1, ?5, 0, 0, 0, NULL, NULL, NULL, NULL, ?6,
                       NULL, NULL, NULL, NULL, NULL, NULL, 20, 20, 1)",
            params![
                checkpoint_id.as_bytes(),
                changeset_id.as_bytes(),
                workspace_id.as_bytes(),
                activity_id.as_bytes(),
                b"doctor.txt".as_slice(),
                [4_u8; 20].as_slice(),
            ],
        )?;
        store.connection.execute(
            "INSERT INTO checkpoint_restores (
                restore_id, checkpoint_id, workspace_id, expected_checkpoint_revision,
                initiator_runtime_instance_id, activity_id, approval_request_id,
                maintenance_owner, maintenance_lease_epoch,
                expected_post_state, expected_post_hash, expected_post_size, expected_post_mode,
                inverse_kind, inverse_blob, inverse_hash, inverse_size, inverse_mode, state,
                failure_code, created_at_ms, updated_at_ms, revision
             ) VALUES (?1, ?2, ?3, 1, ?4, ?5, NULL, NULL, NULL,
                       0, NULL, NULL, NULL, 0, NULL, NULL, NULL, NULL,
                       0, NULL, 20, 20, 1)",
            params![
                restore_id.as_bytes(),
                checkpoint_id.as_bytes(),
                workspace_id.as_bytes(),
                activity_id.as_bytes(),
                activity_id.as_bytes(),
            ],
        )?;
        Ok((execution_id, restore_id))
    }

    fn summary_diff_intent(
        command: &BeginFileMutation,
    ) -> Result<BeginDiffEvidence, Box<dyn std::error::Error>> {
        let kind = match command.kind() {
            FileMutationKind::Create => DiffChangeKind::Created,
            FileMutationKind::Replace => DiffChangeKind::Modified,
            FileMutationKind::Delete => DiffChangeKind::Deleted,
        };
        Ok(BeginDiffEvidence::new(
            DiffAttribution::new(
                DiffId::for_change_set(command.change_set_id()),
                command.workspace_id(),
                command.activity_id(),
                command.change_set_id(),
                command.mutation_id(),
            ),
            DiffFileSummary::new(
                command.path().clone(),
                kind,
                DiffLineCount::new(0),
                DiffLineCount::new(0),
            ),
            DiffPayloadProjection::IntentSummary {
                render_kind: DiffRenderKind::Binary,
            },
            command.observed_at(),
            DiffContractVersions::V1,
        )?)
    }

    fn summary_completion(
        identity: FileMutationIdentity,
        post_hash: FileContentHash,
        observed_at: i64,
    ) -> Result<(CompleteFileMutation, CompleteDiffEvidence), Box<dyn std::error::Error>> {
        Ok((
            CompleteFileMutation::new(
                identity,
                ChangeSetRevision::INITIAL,
                FileMutationRevision::INITIAL,
                FilePathState::Regular {
                    hash: post_hash,
                    size: FileByteCount::new(7),
                },
                timestamp(observed_at)?,
            ),
            CompleteDiffEvidence::new(
                DiffId::for_change_set(identity.change_set_id()),
                DiffRevision::INITIAL,
                DiffPayloadProjection::SummaryOnly {
                    render_kind: DiffRenderKind::Binary,
                },
                timestamp(observed_at)?,
            )?,
        ))
    }

    fn insert_file_test_goal(
        store: &mut WorkspaceStore,
        workspace_id: WorkspaceId,
    ) -> Result<GoalWorkAttribution, Box<dyn std::error::Error>> {
        let goal = RegisteredGoal::create(
            GoalId::from_uuid(Uuid::from_u128(0xB108)),
            workspace_id,
            GoalContract::new(
                GoalObjective::new("Apply one attributed file mutation".to_owned())?,
                vec![GoalStatement::new("The ChangeSet is durable".to_owned())?],
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            )?,
            timestamp(19)?,
        );
        let _ = store.insert_goal(&goal)?;
        let definition = DagNodeDefinition::new(
            DagNodeId::from_uuid(Uuid::from_u128(0xB10B)),
            DagNodeOrdinal::new(0)?,
            DagNodeTitle::new("Apply mutation".to_owned())?,
            DagNodeObjective::new("Apply the attributed file mutation".to_owned())?,
            vec![DagAcceptanceCriterion::new(
                "ChangeSet is durable".to_owned(),
            )?],
        )?;
        let dag = DagRevision::new(
            DagRevisionId::from_uuid(Uuid::from_u128(0xB10C)),
            goal.id(),
            goal.revision(),
            DagRevisionNumber::INITIAL,
            None,
            vec![definition.clone()],
            Vec::new(),
            timestamp(19)?,
        )?;
        let nodes = vec![RegisteredDagNode::create(
            goal.id(),
            dag.number(),
            definition,
            timestamp(19)?,
        )];
        let _ = store.insert_dag_revision(&dag, &nodes, &[], None)?;
        let active = store.start_dag_node(
            goal.id(),
            nodes[0].id(),
            nodes[0].revision(),
            timestamp(19)?,
        )?;
        Ok(GoalNodeAttribution::new(
            goal.id(),
            goal.revision(),
            dag.number(),
            active.id(),
            active.revision(),
        )
        .into())
    }

    fn assert_stale_file_goal_attribution_rolls_back(
        store: &mut WorkspaceStore,
        workspace_id: WorkspaceId,
        activity: &RegisteredActivity,
        owner: RuntimeInstanceId,
        attribution: GoalWorkAttribution,
        post_hash: FileContentHash,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let identity = FileMutationIdentity::new(
            ChangeSetId::from_uuid(Uuid::from_u128(0xB109)),
            FileMutationId::from_uuid(Uuid::from_u128(0xB10A)),
        );
        let begin = BeginFileMutation::new(
            identity,
            FileMutationScope::new(
                workspace_id,
                WorkspaceRevision::INITIAL,
                activity.id(),
                owner,
                activity.lease_revision(),
            ),
            FileMutationPlan::new(
                WorkspaceRelativePath::new(PathBuf::from("src/other.rs"))?,
                FileMutationKind::Create,
                FilePrecondition::Absent,
            ),
            Some(post_hash),
            FilePathState::Absent,
            timestamp(23)?,
        )?;
        let diff = summary_diff_intent(&begin)?;
        let node = attribution.node().ok_or("node attribution missing")?;
        let stale = GoalNodeAttribution::new(
            node.goal_id(),
            node.expected_goal_revision().checked_next()?,
            node.dag_revision(),
            node.node_id(),
            node.expected_node_revision(),
        );
        assert!(matches!(
            store.begin_file_mutation_for_goal(&begin, &diff, Some(stale.into())),
            Err(WorkspaceStoreError::Goal(
                crate::GoalStoreError::RevisionConflict
            ))
        ));
        assert!(store.get_file_mutation(identity.change_set_id())?.is_none());
        Ok(())
    }

    fn assert_changeset_node_evidence_linked(
        store: &WorkspaceStore,
        change_set_id: ChangeSetId,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let count: i64 = store.connection.query_row(
            "SELECT COUNT(*) FROM goal_dag_node_evidence_refs WHERE evidence_kind = 0 AND evidence_id = ?1",
            params![change_set_id.into_uuid().as_bytes()],
            |row| row.get(0),
        )?;
        assert_eq!(count, 1);
        Ok(())
    }

    struct TextDiffTestScope {
        workspace_id: WorkspaceId,
        activity: RegisteredActivity,
        owner: RuntimeInstanceId,
    }

    fn apply_text_diff(
        store: &mut WorkspaceStore,
        scope: &TextDiffTestScope,
        seed: u128,
        observed_at: i64,
    ) -> Result<RegisteredDiffEvidence, Box<dyn std::error::Error>> {
        let seed_byte = u8::try_from(seed & u128::from(u8::MAX))?;
        let identity = FileMutationIdentity::new(
            ChangeSetId::from_uuid(Uuid::from_u128(seed)),
            FileMutationId::from_uuid(Uuid::from_u128(seed + 1)),
        );
        let content_hash = FileContentHash::from_bytes([seed_byte; 32]);
        let begin = BeginFileMutation::new(
            identity,
            FileMutationScope::new(
                scope.workspace_id,
                WorkspaceRevision::INITIAL,
                scope.activity.id(),
                scope.owner,
                scope.activity.lease_revision(),
            ),
            FileMutationPlan::new(
                WorkspaceRelativePath::new(PathBuf::from(format!("file-{seed}.txt")))?,
                FileMutationKind::Create,
                FilePrecondition::Absent,
            ),
            Some(content_hash),
            FilePathState::Absent,
            timestamp(observed_at)?,
        )?;
        let diff_id = DiffId::for_change_set(identity.change_set_id());
        let compressed_hash = DiffPayloadHash::from_bytes([seed_byte.wrapping_add(2); 32]);
        let uncompressed_hash = DiffPayloadHash::from_bytes([seed_byte.wrapping_add(3); 32]);
        let final_path =
            DiffArtifactRelativePath::new(PathBuf::from(format!("diffs/diff_{diff_id}.diff.zst")))?;
        let diff_begin = BeginDiffEvidence::new(
            DiffAttribution::new(
                diff_id,
                scope.workspace_id,
                scope.activity.id(),
                identity.change_set_id(),
                identity.mutation_id(),
            ),
            DiffFileSummary::new(
                begin.path().clone(),
                DiffChangeKind::Created,
                DiffLineCount::new(1),
                DiffLineCount::new(0),
            ),
            DiffPayloadProjection::IntentText {
                pending_relative_path: DiffArtifactRelativePath::new(PathBuf::from(format!(
                    "diffs/.diff-{diff_id}.pending"
                )))?,
                final_relative_path: final_path.clone(),
                compressed_hash,
                uncompressed_hash,
                compressed_size: DiffByteCount::new(20),
                uncompressed_size: DiffByteCount::new(40),
            },
            timestamp(observed_at)?,
            DiffContractVersions::V1,
        )?;
        let started = store.begin_file_mutation(&begin, &diff_begin)?;
        let complete_file = CompleteFileMutation::new(
            identity,
            started.record().change_set().revision(),
            started.record().mutation().revision(),
            FilePathState::Regular {
                hash: content_hash,
                size: FileByteCount::new(7),
            },
            timestamp(observed_at + 1)?,
        );
        let complete_diff = CompleteDiffEvidence::new(
            diff_id,
            started.diff().ok_or("Diff intent missing")?.revision(),
            DiffPayloadProjection::Ready {
                relative_path: final_path,
                compressed_hash,
                uncompressed_hash,
                compressed_size: DiffByteCount::new(20),
                uncompressed_size: DiffByteCount::new(40),
            },
            timestamp(observed_at + 1)?,
        )?;
        Ok(store
            .complete_file_mutation(&complete_file, &complete_diff)?
            .diff()
            .clone())
    }

    fn command(
        layout: &WorkspaceStateLayout,
        id: WorkspaceId,
        location: LocationId,
        observed_at: i64,
    ) -> Result<EstablishWorkspace, Box<dyn std::error::Error>> {
        Ok(EstablishWorkspace::new(
            id,
            location,
            WorkspaceRoot::from_canonical(layout.workspace_root().to_path_buf())?,
            layout.root_fingerprint()?,
            timestamp(observed_at)?,
        ))
    }

    fn store_with_activity(
        label: &str,
    ) -> Result<
        (PathBuf, WorkspaceStateLayout, WorkspaceStore, ActivityId),
        Box<dyn std::error::Error>,
    > {
        let root = unique_root(label)?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_command = command(&layout, workspace_id(100), location_id(101), 1)?;
        let mut store = WorkspaceStore::open(&layout, &workspace_command)?;
        let activity = store.create_activity(&CreateActivity::new(
            activity_id(102),
            workspace_command.id(),
            WorkspaceRevision::INITIAL,
            timestamp(2)?,
        ))?;
        Ok((root, layout, store, activity.id()))
    }

    fn copy_directory(
        source: &std::path::Path,
        destination: &std::path::Path,
    ) -> std::io::Result<()> {
        fs::create_dir_all(destination)?;
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            let source_path = entry.path();
            let destination_path = destination.join(entry.file_name());
            let metadata = fs::symlink_metadata(&source_path)?;
            if metadata.is_dir() {
                copy_directory(&source_path, &destination_path)?;
            } else if metadata.is_file() {
                fs::copy(&source_path, &destination_path)?;
            } else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "unexpected non-file Workspace state entry",
                ));
            }
        }
        Ok(())
    }

    fn open_with_timeout(
        layout: &WorkspaceStateLayout,
        command: &EstablishWorkspace,
        timeout: Duration,
    ) -> Result<WorkspaceStore, WorkspaceStoreError> {
        WorkspaceStore::open_or_establish_with_timeout(layout, command, timeout)
    }

    type WorkspaceMigrationSnapshot = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, i64, i64, i64);
    type ActivityMigrationSnapshot = (Vec<u8>, Vec<u8>, i64, i64, i64, i64);
    type GoalMigrationSnapshot = (Vec<u8>, Vec<u8>, String, i64, i64, i64, i64);
    type ExecutionMigrationSnapshot = (i64, i64, Vec<u8>, i64, i64, i64);

    #[derive(Debug, PartialEq, Eq)]
    struct MigrationSemanticSnapshot {
        workspace: WorkspaceMigrationSnapshot,
        activity: ActivityMigrationSnapshot,
        goal: GoalMigrationSnapshot,
        dag_counts: [i64; 7],
        execution: ExecutionMigrationSnapshot,
    }

    fn migration_snapshot(
        connection: &Connection,
    ) -> Result<MigrationSemanticSnapshot, rusqlite::Error> {
        let workspace = connection.query_row(
            "SELECT workspace_id, location_id, root_path, root_fingerprint,
                    created_at_ms, updated_at_ms, revision
             FROM workspace",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )?;
        let activity = connection.query_row(
            "SELECT activity_id, workspace_id, state, created_at_ms, updated_at_ms, revision
             FROM activities",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )?;
        let goal = connection.query_row(
            "SELECT goal_id, workspace_id, objective, state,
                    created_at_ms, updated_at_ms, revision
             FROM goals",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )?;
        let mut dag_counts = [0_i64; 7];
        for (index, table) in [
            "goal_dag_revisions",
            "goal_dag_heads",
            "goal_dag_nodes",
            "goal_dag_edges",
            "goal_dag_node_acceptance",
            "goal_dag_node_evidence_refs",
            "goal_dag_node_lineage",
        ]
        .into_iter()
        .enumerate()
        {
            dag_counts[index] =
                connection.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })?;
        }
        let execution = connection.query_row(
            "SELECT state, mode, request_digest, created_at_ms, updated_at_ms, revision
             FROM executions",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )?;
        Ok(MigrationSemanticSnapshot {
            workspace,
            activity,
            goal,
            dag_counts,
            execution,
        })
    }

    #[test]
    fn fresh_reopen_preserves_identity_activities_and_health()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_root("reopen")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let first_command = command(&layout, workspace_id(1), location_id(2), 10)?;
        let activity = {
            let mut store = WorkspaceStore::open(&layout, &first_command)?;
            let health = store.health()?;
            assert_eq!(health.schema_version(), CURRENT_SCHEMA_VERSION);
            assert_eq!(health.application_id(), WORKSPACE_APPLICATION_ID);
            assert_eq!(health.journal_mode().to_ascii_lowercase(), "wal");
            assert!(health.foreign_keys_enabled());
            assert!(health.synchronous_full());

            store.create_activity(&CreateActivity::new(
                activity_id(3),
                first_command.id(),
                WorkspaceRevision::INITIAL,
                timestamp(11)?,
            ))?
        };
        assert_eq!(activity.state(), ActivityState::Open);

        let proposed_id = workspace_id(99);
        let reopened =
            WorkspaceStore::open(&layout, command(&layout, proposed_id, location_id(2), 12)?)?;
        let workspace = reopened.workspace()?;
        assert_eq!(workspace.id(), first_command.id());
        assert_eq!(workspace.location_id(), first_command.location_id());
        assert_eq!(workspace.revision(), WorkspaceRevision::INITIAL);
        assert_eq!(
            reopened
                .get_activity(activity.id())?
                .as_ref()
                .map(forge_domain::RegisteredActivity::id),
            Some(activity.id())
        );
        assert_eq!(
            reopened.list_activities(ActivityListLimit::DEFAULT)?.len(),
            1
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn activities_are_isolated_bounded_and_deterministically_ordered()
    -> Result<(), Box<dyn std::error::Error>> {
        let root_a = unique_root("isolation-a")?;
        let root_b = unique_root("isolation-b")?;
        let layout_a = WorkspaceStateLayout::initialize(&root_a)?;
        let layout_b = WorkspaceStateLayout::initialize(&root_b)?;
        let command_a = command(&layout_a, workspace_id(10), location_id(11), 1)?;
        let command_b = command(&layout_b, workspace_id(20), location_id(21), 1)?;
        let mut store_a = WorkspaceStore::open(&layout_a, &command_a)?;
        let mut store_b = WorkspaceStore::open(&layout_b, &command_b)?;

        for (id, observed_at) in [
            (activity_id(1), 10_i64),
            (activity_id(2), 30),
            (activity_id(3), 20),
        ] {
            store_a.create_activity(&CreateActivity::new(
                id,
                command_a.id(),
                WorkspaceRevision::INITIAL,
                timestamp(observed_at)?,
            ))?;
        }
        store_b.create_activity(&CreateActivity::new(
            activity_id(4),
            command_b.id(),
            WorkspaceRevision::INITIAL,
            timestamp(40)?,
        ))?;

        let bounded = store_a.list_activities(ActivityListLimit::new(2)?)?;
        assert_eq!(
            bounded
                .iter()
                .map(forge_domain::RegisteredActivity::id)
                .collect::<Vec<_>>(),
            vec![activity_id(2), activity_id(3)]
        );
        assert_eq!(
            store_b.list_activities(ActivityListLimit::DEFAULT)?.len(),
            1
        );
        assert!(store_a.get_activity(activity_id(4))?.is_none());
        fs::remove_dir_all(root_a)?;
        fs::remove_dir_all(root_b)?;
        Ok(())
    }

    #[test]
    fn activity_workspace_cas_and_rollback_are_typed() -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_root("cas")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_command = command(&layout, workspace_id(30), location_id(31), 1)?;
        let mut store = WorkspaceStore::open(&layout, &workspace_command)?;

        let stale_create = store.create_activity(&CreateActivity::new(
            activity_id(32),
            workspace_command.id(),
            WorkspaceRevision::new(2)?,
            timestamp(2)?,
        ));
        assert!(matches!(
            stale_create,
            Err(WorkspaceStoreError::WorkspaceRevisionConflict {
                expected,
                actual
            }) if expected == WorkspaceRevision::new(2)? && actual == WorkspaceRevision::INITIAL
        ));
        assert!(
            store
                .list_activities(ActivityListLimit::DEFAULT)?
                .is_empty()
        );

        let activity = store.create_activity(&CreateActivity::new(
            activity_id(32),
            workspace_command.id(),
            WorkspaceRevision::INITIAL,
            timestamp(3)?,
        ))?;
        let stale_state = store.set_activity_state(&forge_domain::SetActivityState::new(
            activity.id(),
            ActivityRevision::new(2)?,
            ActivityState::Closed,
            timestamp(4)?,
        ));
        assert!(matches!(
            stale_state,
            Err(WorkspaceStoreError::ActivityRevisionConflict { .. })
        ));
        let current = store
            .get_activity(activity.id())?
            .ok_or("activity unexpectedly missing after stale CAS")?;
        assert_eq!(current.state(), ActivityState::Open);

        let updated = store.set_activity_state(&forge_domain::SetActivityState::new(
            activity.id(),
            ActivityRevision::INITIAL,
            ActivityState::Closed,
            timestamp(5)?,
        ))?;
        assert_eq!(updated.state(), ActivityState::Closed);
        assert_eq!(updated.revision(), ActivityRevision::new(2)?);

        let duplicate = store.create_activity(&CreateActivity::new(
            activity.id(),
            workspace_command.id(),
            WorkspaceRevision::INITIAL,
            timestamp(6)?,
        ));
        assert!(matches!(
            duplicate,
            Err(WorkspaceStoreError::ActivityIdConflict(id)) if id == activity.id()
        ));
        assert_eq!(store.list_activities(ActivityListLimit::DEFAULT)?.len(), 1);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn same_fingerprint_rename_rebinds_with_cas_and_preserves_id()
    -> Result<(), Box<dyn std::error::Error>> {
        let parent = unique_root("rebind")?;
        let old_root = parent.join("old");
        let new_root = parent.join("new");
        fs::create_dir_all(&old_root)?;
        let old_layout = WorkspaceStateLayout::initialize(&old_root)?;
        let first = command(&old_layout, workspace_id(40), location_id(41), 10)?;
        let store = WorkspaceStore::open(&old_layout, &first)?;
        let old_fingerprint = old_layout.root_fingerprint()?;
        drop(store);
        fs::rename(&old_root, &new_root)?;

        let new_layout = WorkspaceStateLayout::initialize(&new_root)?;
        assert_eq!(new_layout.root_fingerprint()?, old_fingerprint);
        let reopened = WorkspaceStore::open(
            &new_layout,
            command(&new_layout, workspace_id(99), location_id(41), 20)?,
        )?;
        let workspace = reopened.workspace()?;
        assert_eq!(workspace.id(), first.id());
        assert_eq!(workspace.root().as_path(), new_layout.workspace_root());
        assert_eq!(workspace.revision(), WorkspaceRevision::new(2)?);
        fs::remove_dir_all(parent)?;
        Ok(())
    }

    #[test]
    fn binding_conflicts_and_layout_mismatch_do_not_mutate()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_root("conflicts")?;
        let other_root = unique_root("other")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let first = command(&layout, workspace_id(50), location_id(51), 1)?;
        let store = WorkspaceStore::open(&layout, &first)?;
        let before = store.workspace()?;
        drop(store);

        let mut forged = first.clone();
        forged = EstablishWorkspace::new(
            forged.id(),
            forged.location_id(),
            forged.root().clone(),
            forge_domain::WorkspaceRootFingerprint::from_bytes([9; 16]),
            forged.observed_at(),
        );
        assert!(matches!(
            WorkspaceStore::open(&layout, &forged),
            Err(WorkspaceStoreError::LayoutFingerprintMismatch { .. })
        ));
        let reopened = WorkspaceStore::open(&layout, &first)?;
        assert_eq!(reopened.workspace()?, before);

        let wrong_location = command(&layout, workspace_id(999), location_id(999), 2)?;
        assert!(matches!(
            WorkspaceStore::open(&layout, &wrong_location),
            Err(WorkspaceStoreError::LocationBindingConflict { .. })
        ));
        let second_layout = WorkspaceStateLayout::initialize(&other_root)?;
        let other_command = command(&second_layout, workspace_id(70), location_id(71), 1)?;
        assert!(matches!(
            WorkspaceStore::open(&layout, &other_command),
            Err(WorkspaceStoreError::LayoutRootMismatch { .. })
        ));
        assert_eq!(WorkspaceStore::open(&layout, &first)?.workspace()?, before);

        fs::remove_dir_all(root)?;
        fs::remove_dir_all(other_root)?;
        Ok(())
    }

    #[test]
    fn schema_ownership_future_and_damage_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        let unowned_root = unique_root("unowned")?;
        let unowned_layout = WorkspaceStateLayout::initialize(&unowned_root)?;
        {
            let connection = Connection::open(unowned_layout.database_path())?;
            connection.execute("CREATE TABLE unrelated(value TEXT)", [])?;
        }
        assert!(matches!(
            WorkspaceStore::open(
                &unowned_layout,
                command(&unowned_layout, workspace_id(80), location_id(81), 1)?
            ),
            Err(WorkspaceStoreError::UnownedDatabase)
        ));

        let future_root = unique_root("future")?;
        let future_layout = WorkspaceStateLayout::initialize(&future_root)?;
        {
            let connection = Connection::open(future_layout.database_path())?;
            connection.pragma_update(None, "application_id", WORKSPACE_APPLICATION_ID)?;
            connection.pragma_update(None, "user_version", 99_i64)?;
        }
        assert!(matches!(
            WorkspaceStore::open(
                &future_layout,
                command(&future_layout, workspace_id(82), location_id(83), 1)?
            ),
            Err(WorkspaceStoreError::UnsupportedSchemaVersion { actual: 99, .. })
        ));

        let damaged_root = unique_root("damaged")?;
        let damaged_layout = WorkspaceStateLayout::initialize(&damaged_root)?;
        let damaged_command = command(&damaged_layout, workspace_id(84), location_id(85), 1)?;
        drop(WorkspaceStore::open(&damaged_layout, &damaged_command)?);
        {
            let connection = Connection::open(damaged_layout.database_path())?;
            connection.execute("DROP INDEX activities_workspace_updated_idx", [])?;
        }
        assert!(matches!(
            WorkspaceStore::open(&damaged_layout, &damaged_command),
            Err(WorkspaceStoreError::DamagedSchema { .. })
        ));

        fs::remove_dir_all(unowned_root)?;
        fs::remove_dir_all(future_root)?;
        fs::remove_dir_all(damaged_root)?;
        Ok(())
    }

    #[test]
    fn main_database_path_shape_is_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        for (index, case) in ["symlink", "directory", "hardlink"].into_iter().enumerate() {
            let root = unique_root(case)?;
            let layout = WorkspaceStateLayout::initialize(&root)?;
            let database = layout.database_path();
            let result = match case {
                "symlink" => {
                    let target = root.join("target.sqlite3");
                    fs::write(&target, b"not-a-database")?;
                    symlink(&target, &database)?;
                    WorkspaceStore::open(
                        &layout,
                        command(
                            &layout,
                            workspace_id(160 + u128::try_from(index)?),
                            location_id(161 + u128::try_from(index)?),
                            1,
                        )?,
                    )
                }
                "directory" => {
                    fs::create_dir(&database)?;
                    WorkspaceStore::open(
                        &layout,
                        command(
                            &layout,
                            workspace_id(160 + u128::try_from(index)?),
                            location_id(161 + u128::try_from(index)?),
                            1,
                        )?,
                    )
                }
                "hardlink" => {
                    let source = root.join("database-source.sqlite3");
                    fs::write(&source, b"not-a-database")?;
                    fs::hard_link(&source, &database)?;
                    WorkspaceStore::open(
                        &layout,
                        command(
                            &layout,
                            workspace_id(160 + u128::try_from(index)?),
                            location_id(161 + u128::try_from(index)?),
                            1,
                        )?,
                    )
                }
                _ => unreachable!(),
            };
            match case {
                "symlink" => assert!(matches!(
                    result,
                    Err(WorkspaceStoreError::DatabasePathSymlink(path)) if path == database
                )),
                "directory" => assert!(matches!(
                    result,
                    Err(WorkspaceStoreError::DatabasePathNotRegular(path)) if path == database
                )),
                "hardlink" => assert!(matches!(
                    result,
                    Err(WorkspaceStoreError::DatabasePathHardlink { path, links: 2 }) if path == database
                )),
                _ => unreachable!(),
            }
            fs::remove_dir_all(root)?;
        }
        Ok(())
    }

    #[test]
    fn sqlite_sidecar_path_shape_is_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        for (index, case) in ["symlink", "directory", "hardlink"].into_iter().enumerate() {
            let root = unique_root(case)?;
            let layout = WorkspaceStateLayout::initialize(&root)?;
            let workspace_command = command(
                &layout,
                workspace_id(170 + u128::try_from(index)?),
                location_id(180 + u128::try_from(index)?),
                1,
            )?;
            let store = WorkspaceStore::open(&layout, &workspace_command)?;
            drop(store);
            let database = layout.database_path();
            let sidecar = super::sidecar_path(&database, "-wal");
            if sidecar.exists() {
                fs::remove_file(&sidecar)?;
            }
            let result = match case {
                "symlink" => {
                    let target = root.join("target-wal");
                    fs::write(&target, b"not-a-wal")?;
                    symlink(&target, &sidecar)?;
                    WorkspaceStore::open(&layout, &workspace_command)
                }
                "directory" => {
                    fs::create_dir(&sidecar)?;
                    WorkspaceStore::open(&layout, &workspace_command)
                }
                "hardlink" => {
                    let source = root.join("source-wal");
                    fs::write(&source, b"not-a-wal")?;
                    fs::hard_link(&source, &sidecar)?;
                    WorkspaceStore::open(&layout, &workspace_command)
                }
                _ => unreachable!(),
            };
            match case {
                "symlink" => assert!(matches!(
                    result,
                    Err(WorkspaceStoreError::DatabasePathSymlink(path)) if path == sidecar
                )),
                "directory" => assert!(matches!(
                    result,
                    Err(WorkspaceStoreError::DatabasePathNotRegular(path)) if path == sidecar
                )),
                "hardlink" => assert!(matches!(
                    result,
                    Err(WorkspaceStoreError::DatabasePathHardlink { path, links: 2 }) if path == sidecar
                )),
                _ => unreachable!(),
            }
            fs::remove_dir_all(root)?;
        }
        Ok(())
    }

    #[test]
    fn long_lived_store_rejects_root_and_database_replacement()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_root("long-lived-root")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_command = command(&layout, workspace_id(190), location_id(191), 1)?;
        let store = WorkspaceStore::open(&layout, &workspace_command)?;
        let moved_root = root.with_file_name(format!(
            "{}-moved",
            root.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("root")
        ));
        fs::rename(&root, &moved_root)?;
        fs::create_dir(&root)?;
        assert!(matches!(
            store.health(),
            Err(WorkspaceStoreError::StateRootMetadata { .. })
        ));
        drop(store);
        fs::remove_dir_all(&root)?;
        fs::remove_dir_all(&moved_root)?;

        let root = unique_root("long-lived-database")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_command = command(&layout, workspace_id(192), location_id(193), 1)?;
        let store = WorkspaceStore::open(&layout, &workspace_command)?;
        let replacement = root.join("replacement.sqlite3");
        fs::copy(layout.database_path(), &replacement)?;
        fs::rename(&replacement, layout.database_path())?;
        assert!(matches!(
            store.workspace(),
            Err(WorkspaceStoreError::DatabasePathChanged(path)) if path == layout.database_path()
        ));
        drop(store);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn state_root_symlink_to_original_is_rejected_even_when_database_inode_survives()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_root("state-root-symlink-original")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_command = command(&layout, workspace_id(194), location_id(195), 1)?;
        let store = WorkspaceStore::open(&layout, &workspace_command)?;
        let state_root = layout.state_root().to_path_buf();
        let moved_state_root = root.join(".heterarchy-forge.original");
        let database = layout.database_path();
        let database_identity = fs::metadata(&database)?.ino();
        fs::rename(&state_root, &moved_state_root)?;
        symlink(&moved_state_root, &state_root)?;
        assert_eq!(
            fs::metadata(moved_state_root.join("state.sqlite3"))?.ino(),
            database_identity
        );
        assert!(matches!(
            store.workspace(),
            Err(WorkspaceStoreError::StateRootSymlink(path)) if path == state_root
        ));
        fs::remove_file(&state_root)?;
        fs::rename(&moved_state_root, &state_root)?;
        drop(store);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn state_root_replacement_is_rejected_without_false_success()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_root("state-root-replacement")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_command = command(&layout, workspace_id(196), location_id(197), 1)?;
        let store = WorkspaceStore::open(&layout, &workspace_command)?;
        let state_root = layout.state_root().to_path_buf();
        let moved_state_root = root.join(".heterarchy-forge.replaced");
        fs::rename(&state_root, &moved_state_root)?;
        fs::create_dir(&state_root)?;
        assert!(matches!(
            store.health(),
            Err(WorkspaceStoreError::StateRootChanged(path)) if path == state_root
        ));
        fs::remove_dir(&state_root)?;
        fs::rename(&moved_state_root, &state_root)?;
        drop(store);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn dropped_uncommitted_transaction_does_not_reappear_after_reopen()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_root("rollback-reopen")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_command = command(&layout, workspace_id(200), location_id(201), 1)?;
        let mut store = WorkspaceStore::open(&layout, &workspace_command)?;
        {
            let transaction = store
                .connection
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let id = activity_id(202).into_uuid().into_bytes();
            let workspace_id = workspace_command.id().into_uuid().into_bytes();
            transaction.execute(
                "INSERT INTO activities (
                    activity_id, workspace_id, state, created_at_ms, updated_at_ms, revision,
                    lease_revision
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    id.as_slice(),
                    workspace_id.as_slice(),
                    1_i64,
                    2_i64,
                    2_i64,
                    1_i64,
                    1_i64
                ],
            )?;
        }
        drop(store);
        let reopened = WorkspaceStore::open(&layout, &workspace_command)?;
        assert!(
            reopened
                .list_activities(ActivityListLimit::DEFAULT)?
                .is_empty()
        );
        assert!(reopened.health()?.synchronous_full());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn nullable_activity_id_schema_is_rejected_before_any_row_decode()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_root("nullable-activity-schema")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let nullable_activity_sql =
            EXPECTED_ACTIVITIES_TABLE_SQL.replace(" PRIMARY KEY NOT NULL ", " PRIMARY KEY ");
        let connection = Connection::open(layout.database_path())?;
        connection.execute_batch(&format!(
            "PRAGMA application_id = {WORKSPACE_APPLICATION_ID};
             CREATE TABLE workspace (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                workspace_id BLOB NOT NULL UNIQUE CHECK(length(workspace_id) = 16),
                location_id BLOB NOT NULL CHECK(length(location_id) = 16),
                root_path BLOB NOT NULL,
                root_fingerprint BLOB NOT NULL CHECK(length(root_fingerprint) = 16),
                created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
                updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0),
                revision INTEGER NOT NULL CHECK(revision >= 1)
             );
             {nullable_activity_sql};
             CREATE INDEX activities_workspace_updated_idx
                 ON activities(workspace_id, updated_at_ms DESC, activity_id DESC);
             PRAGMA user_version = 1;"
        ))?;
        let workspace_command = command(&layout, workspace_id(150), location_id(151), 1)?;
        assert!(matches!(
            WorkspaceStore::open(&layout, &workspace_command),
            Err(WorkspaceStoreError::DamagedSchema { .. })
        ));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn native_non_utf8_root_and_persisted_bounds_fail_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let parent = unique_root("native")?;
        let root = parent.join("root");
        fs::create_dir_all(&root)?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let command = command(&layout, workspace_id(90), location_id(91), 1)?;
        let store = WorkspaceStore::open(&layout, &command)?;
        assert_eq!(
            store.workspace()?.root().as_path().as_os_str().as_bytes(),
            layout.workspace_root().as_os_str().as_bytes()
        );

        let connection = Connection::open(layout.database_path())?;
        connection.pragma_update(None, "ignore_check_constraints", true)?;
        let native_root = std::ffi::OsString::from_vec(b"/tmp/native-\xff".to_vec());
        connection.execute(
            "UPDATE workspace SET root_path = ?1 WHERE singleton = 1",
            params![native_root.as_bytes()],
        )?;
        assert_eq!(
            store.workspace()?.root().as_path().as_os_str().as_bytes(),
            native_root.as_bytes()
        );
        connection.execute(
            "UPDATE workspace SET root_path = ?1 WHERE singleton = 1",
            params![vec![b'x'; 4_097]],
        )?;
        assert!(matches!(
            store.workspace(),
            Err(WorkspaceStoreError::PersistedFieldTooLarge {
                field: "root_path",
                ..
            })
        ));

        fs::remove_dir_all(parent)?;
        Ok(())
    }

    #[test]
    fn bounded_busy_write_has_no_partial_activity_row() -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_root("busy-write")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_command = command(&layout, workspace_id(110), location_id(111), 1)?;
        let mut holder = WorkspaceStore::open(&layout, &workspace_command)?;
        let mut contender =
            open_with_timeout(&layout, &workspace_command, Duration::from_millis(50))?;
        let transaction = holder
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let started = Instant::now();
        let result = contender.create_activity(&CreateActivity::new(
            activity_id(112),
            workspace_command.id(),
            WorkspaceRevision::INITIAL,
            timestamp(2)?,
        ));
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(matches!(
            result,
            Err(WorkspaceStoreError::Sqlite(rusqlite::Error::SqliteFailure(
                error,
                _
            ))) if matches!(error.code, ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked)
        ));
        drop(transaction);
        assert!(
            holder
                .list_activities(ActivityListLimit::DEFAULT)?
                .is_empty()
        );
        assert!(
            contender
                .list_activities(ActivityListLimit::DEFAULT)?
                .is_empty()
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn independent_handles_reject_stale_activity_cas_without_overwrite()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_root("two-handles")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_command = command(&layout, workspace_id(120), location_id(121), 1)?;
        let mut first = WorkspaceStore::open(&layout, &workspace_command)?;
        let mut second = WorkspaceStore::open(&layout, &workspace_command)?;
        let activity = first.create_activity(&CreateActivity::new(
            activity_id(122),
            workspace_command.id(),
            WorkspaceRevision::INITIAL,
            timestamp(2)?,
        ))?;
        let committed = first.set_activity_state(&forge_domain::SetActivityState::new(
            activity.id(),
            ActivityRevision::INITIAL,
            ActivityState::Closed,
            timestamp(3)?,
        ))?;
        let stale = second.set_activity_state(&forge_domain::SetActivityState::new(
            activity.id(),
            ActivityRevision::INITIAL,
            ActivityState::Open,
            timestamp(4)?,
        ));
        assert!(matches!(
            stale,
            Err(WorkspaceStoreError::ActivityRevisionConflict {
                expected,
                actual,
                ..
            }) if expected == ActivityRevision::INITIAL && actual == committed.revision()
        ));
        let observed = second
            .get_activity(activity.id())?
            .ok_or("activity disappeared after stale CAS")?;
        assert_eq!(observed.state(), ActivityState::Closed);
        assert_eq!(observed.revision(), committed.revision());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn copied_state_fails_root_binding_without_mutation() -> Result<(), Box<dyn std::error::Error>>
    {
        let parent = unique_root("copied-state")?;
        let original_root = parent.join("original");
        let copy_root = parent.join("copy");
        fs::create_dir_all(&original_root)?;
        fs::create_dir_all(&copy_root)?;
        let original_layout = WorkspaceStateLayout::initialize(&original_root)?;
        let original_command = command(&original_layout, workspace_id(130), location_id(131), 1)?;
        let original = WorkspaceStore::open(&original_layout, &original_command)?;
        let original_workspace = original.workspace()?;
        drop(original);
        copy_directory(
            original_layout.state_root(),
            &copy_root.join(".heterarchy-forge"),
        )?;
        let copy_layout = WorkspaceStateLayout::initialize(&copy_root)?;
        assert_ne!(
            original_layout.root_fingerprint()?,
            copy_layout.root_fingerprint()?
        );
        let copy_command = command(&copy_layout, workspace_id(999), location_id(131), 2)?;
        assert!(matches!(
            WorkspaceStore::open(&copy_layout, &copy_command),
            Err(WorkspaceStoreError::WorkspaceRootBindingConflict { .. })
        ));
        let connection = Connection::open(copy_layout.database_path())?;
        let stored_id: Vec<u8> = connection.query_row(
            "SELECT workspace_id FROM workspace WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        let stored_root: Vec<u8> = connection.query_row(
            "SELECT root_path FROM workspace WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(stored_id, original_workspace.id().into_uuid().as_bytes());
        assert_eq!(
            stored_root,
            original_layout.workspace_root().as_os_str().as_bytes()
        );
        fs::remove_dir_all(parent)?;
        Ok(())
    }

    #[test]
    fn health_rejects_mutated_sqlite_durability_policy() -> Result<(), Box<dyn std::error::Error>> {
        for (label, pragma, value) in [
            ("journal-mode", "journal_mode", "DELETE"),
            ("foreign-keys", "foreign_keys", "OFF"),
            ("synchronous", "synchronous", "NORMAL"),
        ] {
            let root = unique_root(label)?;
            let layout = WorkspaceStateLayout::initialize(&root)?;
            let workspace_command = command(&layout, workspace_id(140), location_id(141), 1)?;
            let store = WorkspaceStore::open(&layout, &workspace_command)?;
            store.connection.pragma_update(None, pragma, value)?;
            assert!(matches!(
                store.health(),
                Err(WorkspaceStoreError::UnhealthyConfiguration { setting, .. })
                    if setting == pragma
            ));
            fs::remove_dir_all(root)?;
        }
        Ok(())
    }

    #[test]
    fn malformed_persisted_workspace_and_activity_values_fail_before_decode()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, layout, store, _) = store_with_activity("malformed-workspace-id")?;
        let connection = Connection::open(layout.database_path())?;
        connection.pragma_update(None, "foreign_keys", false)?;
        connection.pragma_update(None, "ignore_check_constraints", true)?;
        connection.execute(
            "UPDATE workspace SET workspace_id = zeroblob(15) WHERE singleton = 1",
            [],
        )?;
        assert!(matches!(
            store.workspace(),
            Err(WorkspaceStoreError::PersistedFieldLengthInvalid {
                field: "workspace_id",
                actual: 15,
                expected: 16
            })
        ));
        fs::remove_dir_all(root)?;

        let (root, layout, store, _) = store_with_activity("malformed-location-id")?;
        let connection = Connection::open(layout.database_path())?;
        connection.pragma_update(None, "foreign_keys", false)?;
        connection.pragma_update(None, "ignore_check_constraints", true)?;
        connection.execute(
            "UPDATE workspace SET location_id = zeroblob(15) WHERE singleton = 1",
            [],
        )?;
        assert!(matches!(
            store.workspace(),
            Err(WorkspaceStoreError::PersistedFieldLengthInvalid {
                field: "location_id",
                actual: 15,
                expected: 16
            })
        ));
        fs::remove_dir_all(root)?;

        let (root, layout, store, _) = store_with_activity("malformed-fingerprint")?;
        let connection = Connection::open(layout.database_path())?;
        connection.pragma_update(None, "foreign_keys", false)?;
        connection.pragma_update(None, "ignore_check_constraints", true)?;
        connection.execute(
            "UPDATE workspace SET root_fingerprint = zeroblob(15) WHERE singleton = 1",
            [],
        )?;
        assert!(matches!(
            store.workspace(),
            Err(WorkspaceStoreError::PersistedFieldLengthInvalid {
                field: "root_fingerprint",
                actual: 15,
                expected: 16
            })
        ));
        fs::remove_dir_all(root)?;

        let (root, layout, store, _) = store_with_activity("malformed-activity-id")?;
        let connection = Connection::open(layout.database_path())?;
        connection.pragma_update(None, "foreign_keys", false)?;
        connection.pragma_update(None, "ignore_check_constraints", true)?;
        connection.execute("UPDATE activities SET activity_id = zeroblob(15)", [])?;
        assert!(matches!(
            store.list_activities(ActivityListLimit::DEFAULT),
            Err(WorkspaceStoreError::PersistedFieldLengthInvalid {
                field: "activity_id",
                actual: 15,
                expected: 16
            })
        ));
        fs::remove_dir_all(root)?;

        let (root, layout, store, _) = store_with_activity("malformed-activity-workspace-id")?;
        let connection = Connection::open(layout.database_path())?;
        connection.pragma_update(None, "foreign_keys", false)?;
        connection.pragma_update(None, "ignore_check_constraints", true)?;
        connection.execute("UPDATE activities SET workspace_id = zeroblob(15)", [])?;
        assert!(matches!(
            store.list_activities(ActivityListLimit::DEFAULT),
            Err(WorkspaceStoreError::PersistedFieldLengthInvalid {
                field: "activity.workspace_id",
                actual: 15,
                expected: 16
            })
        ));
        fs::remove_dir_all(root)?;

        let (root, layout, store, _) = store_with_activity("malformed-activity-state")?;
        let connection = Connection::open(layout.database_path())?;
        connection.pragma_update(None, "foreign_keys", false)?;
        connection.pragma_update(None, "ignore_check_constraints", true)?;
        connection.execute("UPDATE activities SET state = 9", [])?;
        assert!(matches!(
            store.list_activities(ActivityListLimit::DEFAULT),
            Err(WorkspaceStoreError::CorruptRecord {
                field: "activity.state",
                ..
            })
        ));
        fs::remove_dir_all(root)?;

        Ok(())
    }

    #[test]
    fn v1_activity_rows_migrate_without_changing_semantic_values()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_root("v1-migration")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let database = layout.database_path();
        let connection = Connection::open(&database)?;
        connection.execute_batch(&format!(
            "PRAGMA application_id = {WORKSPACE_APPLICATION_ID};
             CREATE TABLE workspace (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                workspace_id BLOB NOT NULL UNIQUE CHECK(length(workspace_id) = 16),
                location_id BLOB NOT NULL CHECK(length(location_id) = 16),
                root_path BLOB NOT NULL,
                root_fingerprint BLOB NOT NULL CHECK(length(root_fingerprint) = 16),
                created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
                updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0),
                revision INTEGER NOT NULL CHECK(revision >= 1)
             );
             CREATE TABLE activities (
                activity_id BLOB PRIMARY KEY NOT NULL CHECK(length(activity_id) = 16),
                workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id),
                state INTEGER NOT NULL CHECK(state IN (0, 1)),
                created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
                updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0),
                revision INTEGER NOT NULL CHECK(revision >= 1)
             );
             CREATE INDEX activities_workspace_updated_idx
                ON activities(workspace_id, updated_at_ms DESC, activity_id DESC);
             PRAGMA user_version = 1;"
        ))?;
        let workspace = workspace_id(401);
        let location = location_id(402);
        let activity = activity_id(403);
        let workspace_bytes = workspace.into_uuid().into_bytes();
        let location_bytes = location.into_uuid().into_bytes();
        let activity_bytes = activity.into_uuid().into_bytes();
        let root_bytes = layout.workspace_root().as_os_str().as_bytes();
        let fingerprint = layout.root_fingerprint()?.into_bytes();
        connection.execute(
            "INSERT INTO workspace (
                singleton, workspace_id, location_id, root_path, root_fingerprint,
                created_at_ms, updated_at_ms, revision
             ) VALUES (1, ?1, ?2, ?3, ?4, 7, 8, 3)",
            params![
                workspace_bytes.as_slice(),
                location_bytes.as_slice(),
                root_bytes,
                fingerprint.as_slice()
            ],
        )?;
        connection.execute(
            "INSERT INTO activities (
                activity_id, workspace_id, state, created_at_ms, updated_at_ms, revision
             ) VALUES (?1, ?2, 1, 10, 11, 4)",
            params![activity_bytes.as_slice(), workspace_bytes.as_slice()],
        )?;
        drop(connection);

        let before = fs::read(&database)?;
        let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
        assert!(matches!(
            WorkspaceStore::inspect_existing_read_only(&existing),
            Err(WorkspaceStoreError::MigrationRequired {
                actual: 1,
                required: CURRENT_SCHEMA_VERSION
            })
        ));
        assert_eq!(fs::read(&database)?, before);
        let version_connection = Connection::open(&database)?;
        let version: i64 =
            version_connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
        assert_eq!(version, 1);

        let command = command(&layout, workspace, location, 12)?;
        let store = WorkspaceStore::open(&layout, &command)?;
        assert_eq!(store.health()?.schema_version(), CURRENT_SCHEMA_VERSION);
        let workspace_after = store.workspace()?;
        assert_eq!(workspace_after.id(), workspace);
        assert_eq!(workspace_after.location_id(), location);
        assert_eq!(workspace_after.created_at().get(), 7);
        assert_eq!(workspace_after.updated_at().get(), 8);
        assert_eq!(workspace_after.revision().get(), 3);
        let activity_after = store
            .get_activity(activity)?
            .ok_or("migrated Activity missing")?;
        assert_eq!(activity_after.state(), ActivityState::Open);
        assert_eq!(activity_after.created_at().get(), 10);
        assert_eq!(activity_after.updated_at().get(), 11);
        assert_eq!(activity_after.revision().get(), 4);
        assert_eq!(activity_after.lease_owner_id(), None);
        assert_eq!(activity_after.lease_until(), None);
        assert_eq!(
            activity_after.lease_revision(),
            ActivityLeaseRevision::INITIAL
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn activity_bootstrap_is_idempotent_and_expiry_requires_recovery()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_root("activity-lease")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_command = command(&layout, workspace_id(410), location_id(411), 1)?;
        let mut store = WorkspaceStore::open(&layout, &workspace_command)?;
        let owner_a = runtime_id(412);
        let owner_b = runtime_id(413);
        let id = activity_id(414);
        let first = store.bootstrap_activity(&BootstrapActivity::new(
            id,
            workspace_command.id(),
            WorkspaceRevision::INITIAL,
            owner_a,
            timestamp(100)?,
            timestamp(10)?,
        ))?;
        assert_eq!(first.lease_owner_id(), Some(owner_a));
        assert_eq!(first.lease_revision(), ActivityLeaseRevision::INITIAL);
        let idempotent = store.bootstrap_activity(&BootstrapActivity::new(
            id,
            workspace_command.id(),
            WorkspaceRevision::INITIAL,
            owner_a,
            timestamp(200)?,
            timestamp(20)?,
        ))?;
        assert_eq!(idempotent.lease_until(), Some(timestamp(100)?));
        assert_eq!(idempotent.lease_revision(), ActivityLeaseRevision::INITIAL);
        assert!(matches!(
            store.bootstrap_activity(&BootstrapActivity::new(
                id,
                workspace_command.id(),
                WorkspaceRevision::INITIAL,
                owner_b,
                timestamp(200)?,
                timestamp(20)?,
            )),
            Err(WorkspaceStoreError::AlreadyLive { id: actual, owner_id, .. })
                if actual == id && owner_id == owner_a
        ));
        let before_expired_retry = store.get_activity(id)?.ok_or("activity missing")?;
        assert!(matches!(
            store.bootstrap_activity(&BootstrapActivity::new(
                id,
                workspace_command.id(),
                WorkspaceRevision::INITIAL,
                owner_b,
                timestamp(300)?,
                timestamp(100)?,
            )),
            Err(WorkspaceStoreError::ExpiredRecoveryRequired {
                id: actual,
                lease_until,
                observed_at,
            }) if actual == id && lease_until == timestamp(100)? && observed_at == timestamp(100)?
        ));
        let after_expired_retry = store.get_activity(id)?.ok_or("activity missing")?;
        assert_eq!(after_expired_retry, before_expired_retry);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn lease_renew_release_close_and_expiry_reconcile_are_durable()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_root("activity-lifecycle")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_command = command(&layout, workspace_id(420), location_id(421), 1)?;
        let mut store = WorkspaceStore::open(&layout, &workspace_command)?;
        let owner = runtime_id(422);
        let id = activity_id(423);
        let activity = store.bootstrap_activity(&BootstrapActivity::new(
            id,
            workspace_command.id(),
            WorkspaceRevision::INITIAL,
            owner,
            timestamp(100)?,
            timestamp(10)?,
        ))?;
        let renewed = store.renew_activity_lease(&RenewActivityLease::new(
            id,
            owner,
            activity.lease_revision(),
            timestamp(150)?,
            timestamp(20)?,
        ))?;
        assert_eq!(renewed.lease_until(), Some(timestamp(150)?));
        assert_eq!(renewed.lease_revision().get(), 2);
        assert!(matches!(
            store.renew_activity_lease(&RenewActivityLease::new(
                id,
                owner,
                ActivityLeaseRevision::INITIAL,
                timestamp(200)?,
                timestamp(30)?,
            )),
            Err(WorkspaceStoreError::LeaseRevisionConflict { .. })
        ));
        let released = store.release_activity_lease(&ReleaseActivityLease::new(
            id,
            owner,
            renewed.lease_revision(),
            timestamp(30)?,
        ))?;
        assert_eq!(released.state(), ActivityState::Open);
        assert_eq!(released.lease_owner_id(), None);
        assert_eq!(released.lease_revision().get(), 3);
        assert!(matches!(
            store.bootstrap_activity(&BootstrapActivity::new(
                id,
                workspace_command.id(),
                WorkspaceRevision::INITIAL,
                owner,
                timestamp(200)?,
                timestamp(31)?,
            )),
            Err(WorkspaceStoreError::ActivityLeaseUnavailable(actual)) if actual == id
        ));

        let closed_id = activity_id(424);
        let closed = store.bootstrap_activity(&BootstrapActivity::new(
            closed_id,
            workspace_command.id(),
            WorkspaceRevision::INITIAL,
            owner,
            timestamp(200)?,
            timestamp(40)?,
        ))?;
        let closed = store.close_activity(&CloseActivity::new(
            closed_id,
            owner,
            closed.lease_revision(),
            timestamp(50)?,
        ))?;
        assert_eq!(closed.state(), ActivityState::Closed);
        assert_eq!(closed.lease_owner_id(), None);

        let expired_id = activity_id(425);
        store.bootstrap_activity(&BootstrapActivity::new(
            expired_id,
            workspace_command.id(),
            WorkspaceRevision::INITIAL,
            owner,
            timestamp(60)?,
            timestamp(51)?,
        ))?;
        let interrupted =
            store.reconcile_expired_activities(&ReconcileExpiredActivities::new(timestamp(60)?))?;
        assert_eq!(interrupted.len(), 1);
        assert_eq!(interrupted[0].id(), expired_id);
        assert_eq!(interrupted[0].state(), ActivityState::Interrupted);
        assert_eq!(interrupted[0].lease_owner_id(), None);
        assert!(matches!(
            store.bootstrap_activity(&BootstrapActivity::new(
                expired_id,
                workspace_command.id(),
                WorkspaceRevision::INITIAL,
                owner,
                timestamp(100)?,
                timestamp(70)?,
            )),
            Ok(activity) if activity.state() == ActivityState::Interrupted
        ));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn lease_batches_are_bounded_ordered_single_transaction_and_restartable()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_root("lease-batch-128")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_command = command(&layout, workspace_id(460), location_id(461), 1)?;
        let mut store = WorkspaceStore::open(&layout, &workspace_command)?;
        let owner = runtime_id(462);
        let mut activities = Vec::new();
        for index in 0..128_u128 {
            let activity = store.bootstrap_activity(&BootstrapActivity::new(
                activity_id(5_000 + index),
                workspace_command.id(),
                WorkspaceRevision::INITIAL,
                owner,
                timestamp(1_000)?,
                timestamp(10)?,
            ))?;
            activities.push(activity);
        }
        let renew_commands: Vec<_> = activities
            .iter()
            .rev()
            .enumerate()
            .map(|(index, activity)| {
                Ok(RenewActivityLease::new(
                    activity.id(),
                    owner,
                    activity.lease_revision(),
                    TimestampMillis::new(2_000 + i64::try_from(index).unwrap_or(i64::MAX))?,
                    timestamp(20)?,
                ))
            })
            .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
        let transactions_before = store.batch_transaction_count();
        let renewed = store.renew_activity_leases(&renew_commands)?;
        assert_eq!(store.batch_transaction_count(), transactions_before + 1);
        assert_eq!(renewed.len(), 128);
        for (result, command) in renewed.iter().zip(&renew_commands) {
            assert_eq!(result.id(), command.id());
            assert_eq!(result.lease_until(), Some(command.lease_until()));
            assert_eq!(result.lease_revision().get(), 2);
        }

        let close_commands: Vec<_> = renewed
            .iter()
            .map(|activity| {
                Ok(CloseActivity::new(
                    activity.id(),
                    owner,
                    activity.lease_revision(),
                    timestamp(30)?,
                ))
            })
            .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
        let closed = store.close_owned_activities(&close_commands)?;
        assert_eq!(store.batch_transaction_count(), transactions_before + 2);
        assert_eq!(closed.len(), 128);
        assert!(closed.iter().all(|activity| {
            activity.state() == ActivityState::Closed && activity.lease_owner_id().is_none()
        }));
        drop(store);

        let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
        let reopened = WorkspaceStore::open_existing(&existing)?;
        let list_limit = ActivityListLimit::new(128)?;
        let persisted = reopened.list_activities(list_limit)?;
        assert_eq!(persisted.len(), 128);
        assert!(
            persisted
                .iter()
                .all(|activity| activity.state() == ActivityState::Closed)
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn lease_batch_preflight_conflict_rolls_back_every_update()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_root("lease-batch-rollback")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_command = command(&layout, workspace_id(470), location_id(471), 1)?;
        let mut store = WorkspaceStore::open(&layout, &workspace_command)?;
        let owner = runtime_id(472);
        let first = store.bootstrap_activity(&BootstrapActivity::new(
            activity_id(473),
            workspace_command.id(),
            WorkspaceRevision::INITIAL,
            owner,
            timestamp(100)?,
            timestamp(10)?,
        ))?;
        let second = store.bootstrap_activity(&BootstrapActivity::new(
            activity_id(474),
            workspace_command.id(),
            WorkspaceRevision::INITIAL,
            owner,
            timestamp(100)?,
            timestamp(10)?,
        ))?;
        let commands = [
            RenewActivityLease::new(
                first.id(),
                owner,
                first.lease_revision(),
                timestamp(200)?,
                timestamp(20)?,
            ),
            RenewActivityLease::new(
                second.id(),
                owner,
                ActivityLeaseRevision::INITIAL.checked_next()?,
                timestamp(300)?,
                timestamp(20)?,
            ),
        ];
        let before_count = store.batch_transaction_count();
        assert!(matches!(
            store.renew_activity_leases(&commands),
            Err(WorkspaceStoreError::LeaseRevisionConflict { id, .. }) if id == second.id()
        ));
        assert_eq!(store.batch_transaction_count(), before_count + 1);
        let first_after = store.get_activity(first.id())?.ok_or("first missing")?;
        let second_after = store.get_activity(second.id())?.ok_or("second missing")?;
        assert_eq!(first_after.lease_until(), first.lease_until());
        assert_eq!(first_after.lease_revision(), first.lease_revision());
        assert_eq!(second_after.lease_until(), second.lease_until());
        assert_eq!(second_after.lease_revision(), second.lease_revision());

        let owner_mismatch = [
            RenewActivityLease::new(
                first.id(),
                owner,
                first.lease_revision(),
                timestamp(200)?,
                timestamp(20)?,
            ),
            RenewActivityLease::new(
                second.id(),
                runtime_id(475),
                second.lease_revision(),
                timestamp(300)?,
                timestamp(20)?,
            ),
        ];
        let before_owner_count = store.batch_transaction_count();
        assert!(matches!(
            store.renew_activity_leases(&owner_mismatch),
            Err(WorkspaceStoreError::ActivityLeaseBatchOwnerMismatch { .. })
        ));
        assert_eq!(store.batch_transaction_count(), before_owner_count);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn busy_lease_batch_has_no_partial_update() -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_root("lease-batch-busy")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_command = command(&layout, workspace_id(480), location_id(481), 1)?;
        let mut holder = WorkspaceStore::open(&layout, &workspace_command)?;
        let mut contender =
            open_with_timeout(&layout, &workspace_command, Duration::from_millis(50))?;
        let owner = runtime_id(482);
        let first = holder.bootstrap_activity(&BootstrapActivity::new(
            activity_id(483),
            workspace_command.id(),
            WorkspaceRevision::INITIAL,
            owner,
            timestamp(100)?,
            timestamp(10)?,
        ))?;
        let second = holder.bootstrap_activity(&BootstrapActivity::new(
            activity_id(484),
            workspace_command.id(),
            WorkspaceRevision::INITIAL,
            owner,
            timestamp(100)?,
            timestamp(10)?,
        ))?;
        let commands = [
            RenewActivityLease::new(
                first.id(),
                owner,
                first.lease_revision(),
                timestamp(200)?,
                timestamp(20)?,
            ),
            RenewActivityLease::new(
                second.id(),
                owner,
                second.lease_revision(),
                timestamp(300)?,
                timestamp(20)?,
            ),
        ];
        let transaction = holder
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let result = contender.renew_activity_leases(&commands);
        assert!(matches!(
            result,
            Err(WorkspaceStoreError::Sqlite(rusqlite::Error::SqliteFailure(error, _)))
                if matches!(error.code, ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked)
        ));
        drop(transaction);
        let first_after = holder.get_activity(first.id())?.ok_or("first missing")?;
        let second_after = holder.get_activity(second.id())?.ok_or("second missing")?;
        assert_eq!(first_after.lease_until(), first.lease_until());
        assert_eq!(second_after.lease_until(), second.lease_until());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn existing_open_rejects_missing_and_fresh_without_establishing()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_root("open-existing")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
        assert!(matches!(
            WorkspaceStore::open_existing(&existing),
            Err(WorkspaceStoreError::MissingDatabase(_))
        ));
        let connection = Connection::open(layout.database_path())?;
        drop(connection);
        let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
        assert!(matches!(
            WorkspaceStore::open_existing(&existing),
            Err(WorkspaceStoreError::FreshDatabase)
        ));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn existing_open_restarts_live_leases_without_rebinding()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_root("open-existing-restart")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_command = command(&layout, workspace_id(430), location_id(431), 1)?;
        let owner = runtime_id(432);
        let activity_id = activity_id(433);
        {
            let mut store = WorkspaceStore::open(&layout, &workspace_command)?;
            store.bootstrap_activity(&BootstrapActivity::new(
                activity_id,
                workspace_command.id(),
                WorkspaceRevision::INITIAL,
                owner,
                timestamp(100)?,
                timestamp(10)?,
            ))?;
        }
        let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
        let reopened = WorkspaceStore::open_existing(&existing)?;
        let projection =
            reopened.list_activity_projections(ActivityListLimit::DEFAULT, timestamp(20)?)?;
        assert_eq!(projection.len(), 1);
        assert_eq!(
            projection[0].liveness(),
            forge_domain::ActivityLiveness::Live
        );
        assert_eq!(projection[0].activity().lease_owner_id(), Some(owner));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn read_only_inspection_preserves_database_sidecars_and_git_exclude()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_root("read-only-invariants")?;
        let git_status = Command::new("/usr/bin/git")
            .args(["init", "--quiet"])
            .current_dir(&root)
            .status()?;
        assert!(git_status.success());
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_command = command(&layout, workspace_id(440), location_id(441), 1)?;
        {
            let mut store = WorkspaceStore::open(&layout, &workspace_command)?;
            store.bootstrap_activity(&BootstrapActivity::new(
                activity_id(442),
                workspace_command.id(),
                WorkspaceRevision::INITIAL,
                runtime_id(443),
                timestamp(100)?,
                timestamp(10)?,
            ))?;
        }

        let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
        let database = existing.database_path();
        let wal = {
            let mut value = database.as_os_str().to_os_string();
            value.push("-wal");
            PathBuf::from(value)
        };
        let shm = {
            let mut value = database.as_os_str().to_os_string();
            value.push("-shm");
            PathBuf::from(value)
        };
        let exclude = root.join(".git").join("info").join("exclude");
        let database_before = file_snapshot(&database)?;
        let wal_before = file_snapshot(&wal)?;
        let shm_before = file_snapshot(&shm)?;
        let exclude_before = file_snapshot(&exclude)?;
        let observed = WorkspaceStore::inspect_existing_read_only(&existing)?;
        assert_eq!(observed.id(), workspace_command.id());
        assert_eq!(file_snapshot(&database)?, database_before);
        assert_eq!(file_snapshot(&wal)?, wal_before);
        assert_eq!(file_snapshot(&shm)?, shm_before);
        assert_eq!(file_snapshot(&exclude)?, exclude_before);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn read_only_inspection_with_active_wal_preserves_sidecar_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_root("read-only-active-wal")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_command = command(&layout, workspace_id(450), location_id(451), 1)?;
        let mut store = WorkspaceStore::open(&layout, &workspace_command)?;
        store.create_activity(&CreateActivity::new(
            activity_id(452),
            workspace_command.id(),
            WorkspaceRevision::INITIAL,
            timestamp(2)?,
        ))?;
        let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
        let database = existing.database_path();
        let wal = PathBuf::from(format!("{}-wal", database.display()));
        let shm = PathBuf::from(format!("{}-shm", database.display()));
        let wal_before = file_snapshot(&wal)?;
        let shm_before = file_snapshot(&shm)?;
        assert!(wal_before.is_some());
        assert!(shm_before.is_some());
        let result = WorkspaceStore::inspect_existing_read_only(&existing);
        assert!(
            matches!(&result, Err(WorkspaceStoreError::ReadOnlyWalActive { .. })),
            "unexpected read-only result: {result:?}"
        );
        assert_eq!(file_snapshot(&wal)?, wal_before);
        assert_eq!(file_snapshot(&shm)?, shm_before);
        drop(store);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn doctor_read_only_reports_health_and_preserves_active_wal_snapshot()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_root("doctor-healthy-wal")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_command = command(&layout, workspace_id(0xD001), location_id(0xD002), 1)?;
        let mut store = WorkspaceStore::open(&layout, &workspace_command)?;
        let _activity = store.create_activity(&CreateActivity::new(
            activity_id(0xD003),
            workspace_command.id(),
            WorkspaceRevision::INITIAL,
            timestamp(2)?,
        ))?;
        let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
        let database = existing.database_path();
        let wal = super::sidecar_path(&database, "-wal");
        let shm = super::sidecar_path(&database, "-shm");
        let database_before = file_snapshot(&database)?;
        let wal_before = file_snapshot(&wal)?;
        let shm_before = file_snapshot(&shm)?;
        assert!(wal_before.is_some());
        assert!(shm_before.is_some());

        let identity = WorkspaceStore::inspect_existing_identity_read_only(&existing)?;
        assert_eq!(identity.id(), workspace_command.id());
        assert_eq!(identity.location_id(), workspace_command.location_id());
        assert_eq!(identity.revision(), WorkspaceRevision::INITIAL);
        assert_eq!(file_snapshot(&database)?, database_before);
        assert_eq!(file_snapshot(&wal)?, wal_before);
        assert_eq!(file_snapshot(&shm)?, shm_before);

        let (report, source) = WorkspaceStore::doctor_existing_read_only_observed(&existing)?;
        assert!(source.is_unchanged(&existing));
        assert_eq!(report.schema_version(), CURRENT_SCHEMA_VERSION);
        assert_eq!(report.application_id(), WORKSPACE_APPLICATION_ID);
        assert_eq!(report.location_id(), workspace_command.location_id());
        assert_eq!(report.workspace_id(), workspace_command.id());
        assert_eq!(report.workspace_revision(), WorkspaceRevision::INITIAL);
        assert_eq!(report.quick_check(), WorkspaceDoctorIntegrity::Passed);
        assert_eq!(report.foreign_key_check(), WorkspaceDoctorIntegrity::Passed);
        assert_eq!(report.stale_executions().count(), 0);
        assert!(!report.stale_executions().truncated());
        assert_eq!(report.stale_checkpoint_restores().count(), 0);
        assert!(!report.stale_checkpoint_restores().truncated());
        assert!(report.diff_references().references().is_empty());
        assert!(!report.diff_references().truncated());
        assert_eq!(report.outcome(), WorkspaceDoctorOutcome::Healthy);
        assert_eq!(file_snapshot(&database)?, database_before);
        assert_eq!(file_snapshot(&wal)?, wal_before);
        assert_eq!(file_snapshot(&shm)?, shm_before);

        store.create_activity(&CreateActivity::new(
            activity_id(0xD00A),
            workspace_command.id(),
            WorkspaceRevision::INITIAL,
            timestamp(20)?,
        ))?;
        assert!(
            !source.is_unchanged(&existing),
            "Doctor source observation must reject a later durable Workspace write"
        );

        drop(store);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn doctor_read_only_promotes_missing_current_dag_head_to_damaged()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_root("doctor-dag-missing-head")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_command = command(&layout, workspace_id(0xD004), location_id(0xD014), 1)?;
        let mut store = WorkspaceStore::open(&layout, &workspace_command)?;
        let attribution = insert_file_test_goal(&mut store, workspace_command.id())?;
        store.connection.execute(
            "DELETE FROM goal_dag_heads WHERE goal_id = ?1",
            params![attribution.goal().goal_id().into_uuid().as_bytes()],
        )?;
        let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;

        let report = WorkspaceStore::doctor_existing_read_only(&existing)?;
        assert_eq!(report.outcome(), WorkspaceDoctorOutcome::Damaged);
        assert!(report.dag_semantics().is_damaged());
        assert!(report.dag_semantics().findings().iter().any(|finding| {
            finding.goal_id() == attribution.goal().goal_id()
                && finding.dag_revision().is_none()
                && finding.state()
                    == crate::DagDoctorState::Damaged(crate::DagDoctorIssue::MissingHead)
        }));

        drop(store);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn doctor_read_only_uses_immutable_main_database_without_creating_sidecars()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_root("doctor-immutable-main")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_command = command(&layout, workspace_id(0xD005), location_id(0xD006), 1)?;
        let store = WorkspaceStore::open(&layout, &workspace_command)?;
        drop(store);
        let database = layout.database_path();
        let wal = super::sidecar_path(&database, "-wal");
        let shm = super::sidecar_path(&database, "-shm");
        if wal.exists() {
            fs::remove_file(&wal)?;
        }
        if shm.exists() {
            fs::remove_file(&shm)?;
        }
        let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
        let database_before = file_snapshot(&database)?;
        let report = WorkspaceStore::doctor_existing_read_only(&existing)?;
        assert_eq!(report.outcome(), WorkspaceDoctorOutcome::Healthy);
        assert_eq!(report.quick_check(), WorkspaceDoctorIntegrity::Passed);
        assert_eq!(report.foreign_key_check(), WorkspaceDoctorIntegrity::Passed);
        assert_eq!(file_snapshot(&database)?, database_before);
        assert!(!wal.exists());
        assert!(!shm.exists());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn doctor_detects_stale_execution_and_restore_without_mutation()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_root("doctor-stale")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_command = command(&layout, workspace_id(0xD010), location_id(0xD011), 1)?;
        let mut store = WorkspaceStore::open(&layout, &workspace_command)?;
        let activity = store.create_activity(&CreateActivity::new(
            activity_id(0xD012),
            workspace_command.id(),
            WorkspaceRevision::INITIAL,
            timestamp(2)?,
        ))?;
        let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
        let (execution_id, restore_id) =
            insert_stale_doctor_records(&mut store, &workspace_command, &activity)?;

        let execution_before: (i64, i64) = store.connection.query_row(
            "SELECT state, revision FROM executions WHERE execution_id = ?1",
            params![execution_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let restore_before: (i64, i64) = store.connection.query_row(
            "SELECT state, revision FROM checkpoint_restores WHERE restore_id = ?1",
            params![restore_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let database_before = file_snapshot(&existing.database_path())?;
        let wal_before = file_snapshot(&super::sidecar_path(&existing.database_path(), "-wal"))?;
        let shm_before = file_snapshot(&super::sidecar_path(&existing.database_path(), "-shm"))?;

        let report = WorkspaceStore::doctor_existing_read_only(&existing)?;
        assert_eq!(report.quick_check(), WorkspaceDoctorIntegrity::Passed);
        assert_eq!(report.foreign_key_check(), WorkspaceDoctorIntegrity::Passed);
        assert_eq!(report.stale_executions().count(), 1);
        assert!(!report.stale_executions().truncated());
        assert_eq!(report.stale_checkpoint_restores().count(), 1);
        assert!(!report.stale_checkpoint_restores().truncated());
        assert_eq!(report.outcome(), WorkspaceDoctorOutcome::RecoveryRequired);
        assert_eq!(
            store.connection.query_row(
                "SELECT state, revision FROM executions WHERE execution_id = ?1",
                params![execution_id.as_bytes()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?,
            execution_before
        );
        assert_eq!(
            store.connection.query_row(
                "SELECT state, revision FROM checkpoint_restores WHERE restore_id = ?1",
                params![restore_id.as_bytes()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?,
            restore_before
        );
        assert_eq!(file_snapshot(&existing.database_path())?, database_before);
        assert_eq!(
            file_snapshot(&super::sidecar_path(&existing.database_path(), "-wal"))?,
            wal_before
        );
        assert_eq!(
            file_snapshot(&super::sidecar_path(&existing.database_path(), "-shm"))?,
            shm_before
        );

        drop(store);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn doctor_stale_counts_are_bounded_and_deterministic() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = unique_root("doctor-bound")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_command = command(&layout, workspace_id(0xD020), location_id(0xD021), 1)?;
        let mut store = WorkspaceStore::open(&layout, &workspace_command)?;
        let activity = store.create_activity(&CreateActivity::new(
            activity_id(0xD022),
            workspace_command.id(),
            WorkspaceRevision::INITIAL,
            timestamp(2)?,
        ))?;
        let transaction = store
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        for index in 0..257_u128 {
            let id = Uuid::from_u128(0xD100 + index);
            transaction.execute(
                "INSERT INTO executions (
                    execution_id, workspace_id, activity_id, state, mode, request_digest,
                    cwd, timeout_ms, output_limit, workspace_read, workspace_write, network,
                    created_at_ms, updated_at_ms, revision
                 ) VALUES (?1, ?2, ?3, 0, 0, ?4, NULL, 1000, 16, 1, 0, 0, ?5, ?5, 1)",
                params![
                    id.as_bytes(),
                    workspace_command.id().into_uuid().as_bytes(),
                    activity.id().into_uuid().as_bytes(),
                    [7_u8; 32].as_slice(),
                    i64::try_from(index)?,
                ],
            )?;
        }
        transaction.commit()?;
        let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
        let first = WorkspaceStore::doctor_existing_read_only(&existing)?;
        let second = WorkspaceStore::doctor_existing_read_only(&existing)?;
        assert_eq!(first.stale_executions().count(), 256);
        assert!(first.stale_executions().truncated());
        assert_eq!(first.outcome(), WorkspaceDoctorOutcome::RecoveryRequired);
        assert_eq!(first, second);
        assert_eq!(
            store
                .connection
                .query_row("SELECT COUNT(*) FROM executions", [], |row| {
                    row.get::<_, i64>(0)
                })?,
            257
        );

        drop(store);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn doctor_snapshot_disk_budget_is_explicit_and_overflow_safe() {
        assert!(validate_doctor_snapshot_size(MAX_DOCTOR_SNAPSHOT_BYTES, 0).is_ok());
        assert!(matches!(
            validate_doctor_snapshot_size(MAX_DOCTOR_SNAPSHOT_BYTES, 1),
            Err(WorkspaceStoreError::DoctorSnapshotTooLarge {
                actual,
                maximum: MAX_DOCTOR_SNAPSHOT_BYTES,
            }) if actual == MAX_DOCTOR_SNAPSHOT_BYTES + 1
        ));
        assert!(matches!(
            validate_doctor_snapshot_size(u64::MAX, 1),
            Err(WorkspaceStoreError::DoctorSnapshotTooLarge {
                actual: u64::MAX,
                maximum: MAX_DOCTOR_SNAPSHOT_BYTES,
            })
        ));
    }

    #[test]
    fn doctor_reports_foreign_key_violation_without_exposing_row_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_root("doctor-foreign-key")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_command = command(&layout, workspace_id(0xD030), location_id(0xD031), 1)?;
        let store = WorkspaceStore::open(&layout, &workspace_command)?;
        let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
        let connection = Connection::open(existing.database_path())?;
        connection.pragma_update(None, "foreign_keys", false)?;
        connection.execute(
            "INSERT INTO activities (
                activity_id, workspace_id, state, created_at_ms, updated_at_ms, revision,
                lease_owner_id, lease_until_ms, lease_revision
             ) VALUES (?1, zeroblob(16), 1, 1, 1, 1, NULL, NULL, 1)",
            params![Uuid::from_u128(0xD032).as_bytes()],
        )?;
        drop(connection);
        let report = WorkspaceStore::doctor_existing_read_only(&existing)?;
        assert_eq!(report.quick_check(), WorkspaceDoctorIntegrity::Passed);
        assert_eq!(report.foreign_key_check(), WorkspaceDoctorIntegrity::Failed);
        assert_eq!(report.outcome(), WorkspaceDoctorOutcome::Damaged);
        assert_eq!(
            store
                .connection
                .query_row("SELECT COUNT(*) FROM activities", [], |row| {
                    row.get::<_, i64>(0)
                })?,
            1
        );
        drop(store);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn doctor_rejects_partial_sidecars_and_old_schema_without_mutation()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_root("doctor-sidecar-schema")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_command = command(&layout, workspace_id(0xD040), location_id(0xD041), 1)?;
        let store = WorkspaceStore::open(&layout, &workspace_command)?;
        drop(store);
        let database = layout.database_path();
        let wal = super::sidecar_path(&database, "-wal");
        let shm = super::sidecar_path(&database, "-shm");
        if wal.exists() {
            fs::remove_file(&wal)?;
        }
        if shm.exists() {
            fs::remove_file(&shm)?;
        }
        fs::write(&wal, b"not-a-wal")?;
        let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
        assert!(matches!(
            WorkspaceStore::doctor_existing_read_only(&existing),
            Err(WorkspaceStoreError::DatabaseSidecarPairMismatch { .. })
        ));
        fs::remove_file(&wal)?;

        let connection = Connection::open(&database)?;
        connection.execute_batch(
            "PRAGMA journal_mode = DELETE;
             DROP TABLE workspace_harness_verifier_items;
             DROP TABLE workspace_harness_verifier_runs;
             DROP TABLE workspace_harness;
             DROP TABLE recovery_maintenance;
             DROP TABLE goal_dag_node_lineage;
             DROP TABLE goal_dag_node_evidence_refs;
             DROP TABLE goal_dag_node_acceptance;
             DROP TABLE goal_dag_edges;
             DROP TABLE goal_dag_nodes;
             DROP TABLE goal_dag_heads;
             DROP TABLE goal_dag_revisions;
             PRAGMA user_version = 9;",
        )?;
        drop(connection);
        let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
        assert!(matches!(
            WorkspaceStore::doctor_existing_read_only(&existing),
            Err(WorkspaceStoreError::MigrationRequired {
                actual: 9,
                required: CURRENT_SCHEMA_VERSION
            })
        ));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn malformed_lease_columns_fail_closed_before_projection()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, layout, store, activity_id) = store_with_activity("malformed-lease")?;
        let connection = Connection::open(layout.database_path())?;
        connection.pragma_update(None, "ignore_check_constraints", true)?;
        connection.execute(
            "UPDATE activities SET lease_owner_id = zeroblob(15), lease_until_ms = 10
             WHERE activity_id = ?1",
            params![activity_id.into_uuid().as_bytes().as_slice()],
        )?;
        assert!(matches!(
            store.list_activities(ActivityListLimit::DEFAULT),
            Err(WorkspaceStoreError::PersistedFieldLengthInvalid {
                field: "activity.lease_owner_id",
                actual: 15,
                expected: 16
            })
        ));
        connection.execute(
            "UPDATE activities SET lease_owner_id = zeroblob(16), lease_until_ms = -1
             WHERE activity_id = ?1",
            params![activity_id.into_uuid().as_bytes().as_slice()],
        )?;
        assert!(matches!(
            store.list_activities(ActivityListLimit::DEFAULT),
            Err(WorkspaceStoreError::CorruptRecord {
                field: "activity.lease_until_ms",
                ..
            })
        ));
        connection.execute(
            "UPDATE activities SET lease_owner_id = zeroblob(16), lease_until_ms = 10,
                lease_revision = 0 WHERE activity_id = ?1",
            params![activity_id.into_uuid().as_bytes().as_slice()],
        )?;
        assert!(matches!(
            store.list_activities(ActivityListLimit::DEFAULT),
            Err(WorkspaceStoreError::CorruptRecord {
                field: "activity.lease_revision",
                ..
            })
        ));
        connection.execute(
            "UPDATE activities SET lease_owner_id = zeroblob(16), lease_until_ms = NULL,
                lease_revision = 1 WHERE activity_id = ?1",
            params![activity_id.into_uuid().as_bytes().as_slice()],
        )?;
        assert!(matches!(
            store.list_activities(ActivityListLimit::DEFAULT),
            Err(WorkspaceStoreError::CorruptRecord {
                field: "activity.lease",
                ..
            })
        ));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn file_mutation_intent_is_activity_attributed_idempotent_and_cas_terminal()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_root("file-mutation-intent")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_command = command(&layout, workspace_id(0xB100), location_id(0xB101), 1)?;
        let mut store = WorkspaceStore::open(&layout, &workspace_command)?;
        let owner = runtime_id(0xB102);
        let activity = store.bootstrap_activity(&BootstrapActivity::new(
            activity_id(0xB103),
            workspace_command.id(),
            WorkspaceRevision::INITIAL,
            owner,
            timestamp(1_000)?,
            timestamp(10)?,
        ))?;
        let identity = FileMutationIdentity::new(
            ChangeSetId::from_uuid(Uuid::from_u128(0xB104)),
            FileMutationId::from_uuid(Uuid::from_u128(0xB105)),
        );
        let post_hash = FileContentHash::from_bytes([7; FileContentHash::BYTE_LEN]);
        let begin = BeginFileMutation::new(
            identity,
            FileMutationScope::new(
                workspace_command.id(),
                WorkspaceRevision::INITIAL,
                activity.id(),
                owner,
                activity.lease_revision(),
            ),
            FileMutationPlan::new(
                WorkspaceRelativePath::new(PathBuf::from("src/lib.rs"))?,
                FileMutationKind::Create,
                FilePrecondition::Absent,
            ),
            Some(post_hash),
            FilePathState::Absent,
            timestamp(20)?,
        )?;
        let diff_begin = summary_diff_intent(&begin)?;
        let attribution = insert_file_test_goal(&mut store, workspace_command.id())?;

        let started = store.begin_file_mutation_for_goal(&begin, &diff_begin, Some(attribution))?;
        assert_eq!(started.status(), BeginFileMutationStatus::Started);
        assert_eq!(
            started.record().change_set().state(),
            ChangeSetState::Starting
        );
        assert_eq!(started.record().change_set().activity_id(), activity.id());
        assert_eq!(started.record().change_set().runtime_instance_id(), owner);
        assert!(
            store.goal_evidence_is_linked(GoalEvidenceRef::ChangeSet(identity.change_set_id()))?
        );
        assert_changeset_node_evidence_linked(&store, identity.change_set_id())?;
        assert!(matches!(
            store.begin_file_mutation(&begin, &diff_begin),
            Err(WorkspaceStoreError::Goal(
                crate::GoalStoreError::EvidenceConflict
            ))
        ));
        let retry = store.begin_file_mutation_for_goal(&begin, &diff_begin, Some(attribution))?;
        assert_eq!(retry.status(), BeginFileMutationStatus::RecoveryRequired);

        let (file_completion, diff_completion) = summary_completion(identity, post_hash, 21)?;
        let completed = store.complete_file_mutation(&file_completion, &diff_completion)?;
        assert_eq!(completed.change_set().state(), ChangeSetState::Applied);
        assert_eq!(completed.change_set().revision().get(), 2);
        assert_eq!(completed.mutation().revision().get(), 2);
        assert_eq!(
            completed
                .mutation()
                .post_state()
                .and_then(FilePathState::hash),
            Some(post_hash)
        );
        assert_eq!(
            store
                .begin_file_mutation_for_goal(&begin, &diff_begin, Some(attribution))?
                .status(),
            BeginFileMutationStatus::AlreadyApplied
        );
        assert_eq!(
            store
                .get_file_mutation(identity.change_set_id())?
                .ok_or("persisted ChangeSet missing")?,
            completed.file().clone()
        );
        let (file_completion, diff_completion) = summary_completion(identity, post_hash, 22)?;
        assert!(matches!(
            store.complete_file_mutation(&file_completion, &diff_completion),
            Err(WorkspaceStoreError::Diff(DiffStoreError::Terminal))
        ));

        assert_stale_file_goal_attribution_rolls_back(
            &mut store,
            workspace_command.id(),
            &activity,
            owner,
            attribution,
            post_hash,
        )?;

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn definitely_uncommitted_file_mutation_failure_is_terminal_and_idempotent()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_root("file-mutation-failed")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_command = command(&layout, workspace_id(0xB110), location_id(0xB111), 1)?;
        let mut store = WorkspaceStore::open(&layout, &workspace_command)?;
        let owner = runtime_id(0xB112);
        let activity = store.bootstrap_activity(&BootstrapActivity::new(
            activity_id(0xB113),
            workspace_command.id(),
            WorkspaceRevision::INITIAL,
            owner,
            timestamp(1_000)?,
            timestamp(10)?,
        ))?;
        let post_hash = FileContentHash::from_bytes([7; FileContentHash::BYTE_LEN]);
        let failed_identity = FileMutationIdentity::new(
            ChangeSetId::from_uuid(Uuid::from_u128(0xB106)),
            FileMutationId::from_uuid(Uuid::from_u128(0xB107)),
        );
        let failed_begin = BeginFileMutation::new(
            failed_identity,
            FileMutationScope::new(
                workspace_command.id(),
                WorkspaceRevision::INITIAL,
                activity.id(),
                owner,
                activity.lease_revision(),
            ),
            FileMutationPlan::new(
                WorkspaceRelativePath::new(PathBuf::from("src/old.rs"))?,
                FileMutationKind::Delete,
                FilePrecondition::Matches(post_hash),
            ),
            None,
            FilePathState::Regular {
                hash: post_hash,
                size: FileByteCount::new(7),
            },
            timestamp(23)?,
        )?;
        let failed_diff_begin = summary_diff_intent(&failed_begin)?;
        assert_eq!(
            store
                .begin_file_mutation(&failed_begin, &failed_diff_begin)?
                .status(),
            BeginFileMutationStatus::Started
        );
        let failed = store.fail_file_mutation(
            &FailFileMutation::new(
                failed_identity,
                ChangeSetRevision::INITIAL,
                FileMutationRevision::INITIAL,
                FileMutationFailureCode::StaleWrite,
                timestamp(24)?,
            ),
            AbandonDiffEvidence::new(
                DiffId::for_change_set(failed_identity.change_set_id()),
                DiffRevision::INITIAL,
                timestamp(24)?,
            ),
        )?;
        assert_eq!(failed.change_set().state(), ChangeSetState::Failed);
        assert_eq!(
            failed.change_set().failure_code(),
            Some(FileMutationFailureCode::StaleWrite)
        );
        assert_eq!(
            store
                .begin_file_mutation(&failed_begin, &failed_diff_begin)?
                .status(),
            BeginFileMutationStatus::TerminalFailed
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn explicit_retention_plan_and_purge_are_revision_bound_and_restartable()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_root("diff-retention")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_command = command(&layout, workspace_id(0xD500), location_id(0xD501), 1)?;
        let mut store = WorkspaceStore::open(&layout, &workspace_command)?;
        let owner = runtime_id(0xD502);
        let activity = store.bootstrap_activity(&BootstrapActivity::new(
            activity_id(0xD503),
            workspace_command.id(),
            WorkspaceRevision::INITIAL,
            owner,
            timestamp(1_000)?,
            timestamp(10)?,
        ))?;
        let scope = TextDiffTestScope {
            workspace_id: workspace_command.id(),
            activity,
            owner,
        };
        let oldest = apply_text_diff(&mut store, &scope, 0xD510, 20)?;
        let middle = apply_text_diff(&mut store, &scope, 0xD520, 30)?;
        let newest = apply_text_diff(&mut store, &scope, 0xD530, 40)?;

        let plan = store.plan_diff_retention(
            DiffRetentionKeepCount::new(1)?,
            DiffRetentionPlanLimit::new(10)?,
        )?;
        assert_eq!(plan.candidates().len(), 2);
        assert_eq!(plan.candidates()[0].id(), middle.id());
        assert_eq!(plan.candidates()[1].id(), oldest.id());
        assert!(
            !plan
                .candidates()
                .iter()
                .any(|diff| diff.id() == newest.id())
        );

        let goal = RegisteredGoal::create(
            GoalId::from_uuid(Uuid::from_u128(0xD540)),
            workspace_command.id(),
            GoalContract::new(
                GoalObjective::new("Preserve linked Diff evidence".to_owned())?,
                vec![GoalStatement::new(
                    "The linked ChangeSet remains inspectable".to_owned(),
                )?],
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            )?,
            timestamp(50)?,
        );
        let _ = store.insert_goal(&goal)?;
        store.associate_goal_evidence(
            goal.id(),
            goal.revision(),
            GoalEvidenceRef::ChangeSet(oldest.change_set_id()),
            timestamp(51)?,
        )?;
        let protected_plan = store.plan_diff_retention(
            DiffRetentionKeepCount::new(1)?,
            DiffRetentionPlanLimit::new(10)?,
        )?;
        assert_eq!(protected_plan.candidates().len(), 1);
        assert_eq!(protected_plan.candidates()[0].id(), middle.id());
        assert!(matches!(
            store.begin_diff_purge(BeginDiffPurge::new(
                oldest.id(),
                oldest.revision(),
                timestamp(100)?,
            )),
            Err(WorkspaceStoreError::Diff(
                DiffStoreError::RetentionProtected
            ))
        ));

        let begin = BeginDiffPurge::new(middle.id(), middle.revision(), timestamp(100)?);
        let pending = store.begin_diff_purge(begin)?;
        assert_eq!(pending.status(), DiffPurgeStatus::MarkedPending);
        assert_eq!(pending.evidence().state(), DiffEvidenceState::PurgePending);
        let retry = store.begin_diff_purge(begin)?;
        assert_eq!(retry.status(), DiffPurgeStatus::AlreadyPending);
        let complete =
            CompleteDiffPurge::new(middle.id(), pending.evidence().revision(), timestamp(101)?);
        let tombstoned = store.complete_diff_purge(complete)?;
        assert_eq!(tombstoned.status(), DiffPurgeStatus::Tombstoned);
        assert_eq!(tombstoned.evidence().state(), DiffEvidenceState::Tombstoned);
        assert_eq!(
            store.complete_diff_purge(complete)?.status(),
            DiffPurgeStatus::AlreadyTombstoned
        );

        let next = store.plan_diff_retention(
            DiffRetentionKeepCount::new(1)?,
            DiffRetentionPlanLimit::new(10)?,
        )?;
        assert!(next.candidates().is_empty());
        drop(store);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn purge_pending_diff_cannot_be_adopted_or_tombstoned_by_a_goal_race()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_root("diff-goal-retention-race")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_command = command(&layout, workspace_id(0xD600), location_id(0xD601), 1)?;
        let mut store = WorkspaceStore::open(&layout, &workspace_command)?;
        let owner = runtime_id(0xD602);
        let activity = store.bootstrap_activity(&BootstrapActivity::new(
            activity_id(0xD603),
            workspace_command.id(),
            WorkspaceRevision::INITIAL,
            owner,
            timestamp(1_000)?,
            timestamp(10)?,
        ))?;
        let scope = TextDiffTestScope {
            workspace_id: workspace_command.id(),
            activity,
            owner,
        };
        let diff = apply_text_diff(&mut store, &scope, 0xD610, 20)?;
        let goal = RegisteredGoal::create(
            GoalId::from_uuid(Uuid::from_u128(0xD620)),
            workspace_command.id(),
            GoalContract::new(
                GoalObjective::new("Preserve evidence during retention races".to_owned())?,
                vec![GoalStatement::new(
                    "No linked Diff is tombstoned".to_owned(),
                )?],
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            )?,
            timestamp(30)?,
        );
        let _ = store.insert_goal(&goal)?;
        let pending = store.begin_diff_purge(BeginDiffPurge::new(
            diff.id(),
            diff.revision(),
            timestamp(40)?,
        ))?;
        assert!(matches!(
            store.associate_goal_evidence(
                goal.id(),
                goal.revision(),
                GoalEvidenceRef::ChangeSet(diff.change_set_id()),
                timestamp(41)?,
            ),
            Err(WorkspaceStoreError::Goal(
                crate::GoalStoreError::EvidenceConflict
            ))
        ));

        store.connection.execute(
            "INSERT INTO goal_evidence_refs (
                goal_id, evidence_kind, evidence_id, associated_at_ms
             ) VALUES (?1, 0, ?2, ?3)",
            params![
                goal.id().into_uuid().as_bytes(),
                diff.change_set_id().into_uuid().as_bytes(),
                41_i64,
            ],
        )?;
        assert!(matches!(
            store.complete_diff_purge(CompleteDiffPurge::new(
                diff.id(),
                pending.evidence().revision(),
                timestamp(42)?,
            )),
            Err(WorkspaceStoreError::Diff(
                DiffStoreError::RetentionProtected
            ))
        ));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn exact_v2_workspace_migrates_to_v7_without_changing_identity_or_activity()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_root("v2-to-v7")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_command = command(&layout, workspace_id(0xB200), location_id(0xB201), 1)?;
        let activity = {
            let mut store = WorkspaceStore::open(&layout, &workspace_command)?;
            store.create_activity(&CreateActivity::new(
                activity_id(0xB202),
                workspace_command.id(),
                WorkspaceRevision::INITIAL,
                timestamp(2)?,
            ))?
        };
        let database = layout.database_path();
        let connection = Connection::open(&database)?;
        prepare_pre_v14_fixture(&connection)?;
        connection.execute_batch(
            "             DROP TABLE workspace_harness;
             DROP TABLE recovery_maintenance;
             DROP TABLE goal_dag_node_lineage;
             DROP TABLE goal_dag_node_evidence_refs;
             DROP TABLE goal_dag_node_acceptance;
             DROP TABLE goal_dag_edges;
             DROP TABLE goal_dag_nodes;
             DROP TABLE goal_dag_heads;
             DROP TABLE goal_dag_revisions;
             DROP TABLE goal_completion_reviews;
             DROP TABLE goal_evidence_refs;
             DROP TABLE goal_verification_requirements;
             DROP TABLE goal_statements;
             DROP TABLE goals;
             DROP TABLE checkpoint_restores;
             DROP TABLE checkpoints;
             DROP TABLE execution_grants;
             DROP TABLE auto_approval_scopes;
             DROP TABLE approval_requests;
             DROP TABLE workspace_policy;
             DROP TABLE executions;
             DROP TABLE diff_files;
             DROP TABLE diff_evidence;
             DROP TABLE file_mutations;
             DROP TABLE change_sets;
             PRAGMA user_version = 2;",
        )?;
        drop(connection);
        for sidecar in [
            super::sidecar_path(&database, "-wal"),
            super::sidecar_path(&database, "-shm"),
        ] {
            if sidecar.exists() {
                fs::remove_file(sidecar)?;
            }
        }
        let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
        assert!(matches!(
            WorkspaceStore::inspect_existing_read_only(&existing),
            Err(WorkspaceStoreError::MigrationRequired {
                actual: 2,
                required: CURRENT_SCHEMA_VERSION
            })
        ));
        let store = WorkspaceStore::open_existing(&existing)?;
        assert_eq!(store.health()?.schema_version(), CURRENT_SCHEMA_VERSION);
        assert_eq!(store.workspace()?.id(), workspace_command.id());
        assert_eq!(
            store.get_activity(activity.id())?.map(|value| value.id()),
            Some(activity.id())
        );
        assert_eq!(
            store.get_file_mutation(ChangeSetId::from_uuid(Uuid::from_u128(1)))?,
            None
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn exact_v8_workspace_migrates_to_v10_without_fabricating_goals()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_root("v8-to-v10-goals")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_command = command(&layout, workspace_id(0xB280), location_id(0xB281), 1)?;
        let activity = {
            let mut store = WorkspaceStore::open(&layout, &workspace_command)?;
            store.create_activity(&CreateActivity::new(
                activity_id(0xB282),
                workspace_command.id(),
                WorkspaceRevision::INITIAL,
                timestamp(2)?,
            ))?
        };
        let database = layout.database_path();
        let connection = Connection::open(&database)?;
        prepare_pre_v14_fixture(&connection)?;
        connection.execute_batch(
            "             DROP TABLE workspace_harness;
             DROP TABLE recovery_maintenance;
             DROP TABLE goal_dag_node_lineage;
             DROP TABLE goal_dag_node_evidence_refs;
             DROP TABLE goal_dag_node_acceptance;
             DROP TABLE goal_dag_edges;
             DROP TABLE goal_dag_nodes;
             DROP TABLE goal_dag_heads;
             DROP TABLE goal_dag_revisions;
             DROP TABLE goal_completion_reviews;
             DROP TABLE goal_evidence_refs;
             DROP TABLE goal_verification_requirements;
             DROP TABLE goal_statements;
             DROP TABLE goals;
             PRAGMA user_version = 8;",
        )?;
        drop(connection);
        for sidecar in [
            super::sidecar_path(&database, "-wal"),
            super::sidecar_path(&database, "-shm"),
        ] {
            if sidecar.exists() {
                fs::remove_file(sidecar)?;
            }
        }

        let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
        assert!(matches!(
            WorkspaceStore::inspect_existing_read_only(&existing),
            Err(WorkspaceStoreError::MigrationRequired {
                actual: 8,
                required: CURRENT_SCHEMA_VERSION
            })
        ));
        let store = WorkspaceStore::open_existing(&existing)?;
        assert_eq!(store.health()?.schema_version(), CURRENT_SCHEMA_VERSION);
        assert_eq!(store.workspace()?.id(), workspace_command.id());
        assert_eq!(
            store.get_activity(activity.id())?.map(|value| value.id()),
            Some(activity.id())
        );
        assert!(
            store
                .list_goals(workspace_command.id(), GoalListLimit::DEFAULT)?
                .is_empty()
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn exact_v9_workspace_migrates_to_v10_without_fabricating_a_dag()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_root("v9-to-v10-dag")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_command = command(&layout, workspace_id(0xB290), location_id(0xB291), 1)?;
        drop(WorkspaceStore::open(&layout, &workspace_command)?);
        let database = layout.database_path();
        let connection = Connection::open(&database)?;
        prepare_pre_v14_fixture(&connection)?;
        connection.execute_batch(
            "             DROP TABLE workspace_harness;
             DROP TABLE recovery_maintenance;
             DROP TABLE goal_dag_node_lineage;
             DROP TABLE goal_dag_node_evidence_refs;
             DROP TABLE goal_dag_node_acceptance;
             DROP TABLE goal_dag_edges;
             DROP TABLE goal_dag_nodes;
             DROP TABLE goal_dag_heads;
             DROP TABLE goal_dag_revisions;
             PRAGMA user_version = 9;",
        )?;
        drop(connection);
        for sidecar in [
            super::sidecar_path(&database, "-wal"),
            super::sidecar_path(&database, "-shm"),
        ] {
            if sidecar.exists() {
                fs::remove_file(sidecar)?;
            }
        }
        let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
        assert!(matches!(
            WorkspaceStore::inspect_existing_read_only(&existing),
            Err(WorkspaceStoreError::MigrationRequired {
                actual: 9,
                required: CURRENT_SCHEMA_VERSION
            })
        ));
        let store = WorkspaceStore::open_existing(&existing)?;
        assert_eq!(store.health()?.schema_version(), CURRENT_SCHEMA_VERSION);
        drop(store);
        let connection = Connection::open(&database)?;
        let revision_count: i64 =
            connection.query_row("SELECT COUNT(*) FROM goal_dag_revisions", [], |row| {
                row.get(0)
            })?;
        assert_eq!(revision_count, 0);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn exact_v3_applied_changeset_migrates_as_explicit_legacy_without_diff()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_root("v3-legacy-diff")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_command = command(&layout, workspace_id(0xB300), location_id(0xB301), 1)?;
        let mut store = WorkspaceStore::open(&layout, &workspace_command)?;
        let owner = runtime_id(0xB302);
        let activity = store.bootstrap_activity(&BootstrapActivity::new(
            activity_id(0xB303),
            workspace_command.id(),
            WorkspaceRevision::INITIAL,
            owner,
            timestamp(1_000)?,
            timestamp(10)?,
        ))?;
        let identity = FileMutationIdentity::new(
            ChangeSetId::from_uuid(Uuid::from_u128(0xB304)),
            FileMutationId::from_uuid(Uuid::from_u128(0xB305)),
        );
        let post_hash = FileContentHash::from_bytes([4; FileContentHash::BYTE_LEN]);
        let begin = BeginFileMutation::new(
            identity,
            FileMutationScope::new(
                workspace_command.id(),
                WorkspaceRevision::INITIAL,
                activity.id(),
                owner,
                activity.lease_revision(),
            ),
            FileMutationPlan::new(
                WorkspaceRelativePath::new(PathBuf::from("legacy.txt"))?,
                FileMutationKind::Create,
                FilePrecondition::Absent,
            ),
            Some(post_hash),
            FilePathState::Absent,
            timestamp(20)?,
        )?;
        let diff_begin = summary_diff_intent(&begin)?;
        let started = store.begin_file_mutation(&begin, &diff_begin)?;
        assert_eq!(started.status(), BeginFileMutationStatus::Started);
        let (file_completion, diff_completion) = summary_completion(identity, post_hash, 21)?;
        let completed = store.complete_file_mutation(&file_completion, &diff_completion)?;
        assert_eq!(completed.change_set().state(), ChangeSetState::Applied);
        drop(store);

        let database = layout.database_path();
        let connection = Connection::open(&database)?;
        prepare_pre_v14_fixture(&connection)?;
        connection.execute_batch(
            "PRAGMA foreign_keys = OFF;
             DROP TABLE workspace_harness;
             DROP TABLE recovery_maintenance;
             DROP TABLE goal_dag_node_lineage;
             DROP TABLE goal_dag_node_evidence_refs;
             DROP TABLE goal_dag_node_acceptance;
             DROP TABLE goal_dag_edges;
             DROP TABLE goal_dag_nodes;
             DROP TABLE goal_dag_heads;
             DROP TABLE goal_dag_revisions;
             DROP TABLE goal_completion_reviews;
             DROP TABLE goal_evidence_refs;
             DROP TABLE goal_verification_requirements;
             DROP TABLE goal_statements;
             DROP TABLE goals;
             DROP TABLE checkpoint_restores;
             DROP TABLE checkpoints;
             DROP TABLE execution_grants;
             DROP TABLE auto_approval_scopes;
             DROP TABLE approval_requests;
             DROP TABLE workspace_policy;
             DROP TABLE executions;
             DROP TABLE diff_files;
             DROP TABLE diff_evidence;
             PRAGMA user_version = 3;",
        )?;
        drop(connection);
        for sidecar in [
            super::sidecar_path(&database, "-wal"),
            super::sidecar_path(&database, "-shm"),
        ] {
            if sidecar.exists() {
                fs::remove_file(sidecar)?;
            }
        }
        let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
        assert!(matches!(
            WorkspaceStore::inspect_existing_read_only(&existing),
            Err(WorkspaceStoreError::MigrationRequired {
                actual: 3,
                required: CURRENT_SCHEMA_VERSION
            })
        ));
        let store = WorkspaceStore::open_existing(&existing)?;
        assert_eq!(store.health()?.schema_version(), CURRENT_SCHEMA_VERSION);
        assert!(store.get_file_mutation(identity.change_set_id())?.is_some());
        assert_eq!(
            store.get_diff_for_change_set(identity.change_set_id())?,
            None
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn exact_v4_workspace_adds_retention_execution_and_approval_schema()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_root("v4-retention-index")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_command = command(&layout, workspace_id(0xB400), location_id(0xB401), 1)?;
        let store = WorkspaceStore::open(&layout, &workspace_command)?;
        drop(store);
        let database = layout.database_path();
        let connection = Connection::open(&database)?;
        prepare_pre_v14_fixture(&connection)?;
        connection.execute_batch(
            "             DROP TABLE workspace_harness;
             DROP TABLE recovery_maintenance;
             DROP TABLE goal_dag_node_lineage;
             DROP TABLE goal_dag_node_evidence_refs;
             DROP TABLE goal_dag_node_acceptance;
             DROP TABLE goal_dag_edges;
             DROP TABLE goal_dag_nodes;
             DROP TABLE goal_dag_heads;
             DROP TABLE goal_dag_revisions;
             DROP TABLE goal_completion_reviews;
             DROP TABLE goal_evidence_refs;
             DROP TABLE goal_verification_requirements;
             DROP TABLE goal_statements;
             DROP TABLE goals;
             DROP TABLE checkpoint_restores;
             DROP TABLE checkpoints;
             DROP TABLE execution_grants;
             DROP TABLE auto_approval_scopes;
             DROP TABLE approval_requests;
             DROP TABLE workspace_policy;
             DROP TABLE executions;
             DROP INDEX diff_evidence_retention_idx;
             PRAGMA user_version = 4;",
        )?;
        drop(connection);
        for sidecar in [
            super::sidecar_path(&database, "-wal"),
            super::sidecar_path(&database, "-shm"),
        ] {
            if sidecar.exists() {
                fs::remove_file(sidecar)?;
            }
        }
        let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
        assert!(matches!(
            WorkspaceStore::inspect_existing_read_only(&existing),
            Err(WorkspaceStoreError::MigrationRequired {
                actual: 4,
                required: CURRENT_SCHEMA_VERSION
            })
        ));
        let store = WorkspaceStore::open_existing(&existing)?;
        assert_eq!(store.health()?.schema_version(), CURRENT_SCHEMA_VERSION);
        let index_count: i64 = store.connection.query_row(
            "SELECT COUNT(*) FROM sqlite_schema
             WHERE type = 'index' AND name = 'diff_evidence_retention_idx'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(index_count, 1);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn exact_v6_workspace_migrates_active_execution_to_interrupted_and_adds_approval_schema()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_root("v6-approval-schema")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_command = command(&layout, workspace_id(0xB600), location_id(0xB601), 1)?;
        let activity = {
            let mut store = WorkspaceStore::open(&layout, &workspace_command)?;
            store.create_activity(&CreateActivity::new(
                activity_id(0xB602),
                workspace_command.id(),
                WorkspaceRevision::INITIAL,
                timestamp(2)?,
            ))?
        };
        let execution_id = ExecutionId::from_uuid(Uuid::from_u128(0xB603));
        let database = layout.database_path();
        let connection = Connection::open(&database)?;
        prepare_pre_v14_fixture(&connection)?;
        connection.execute_batch(
            "             DROP TABLE workspace_harness;
             DROP TABLE recovery_maintenance;
             DROP TABLE goal_dag_node_lineage;
             DROP TABLE goal_dag_node_evidence_refs;
             DROP TABLE goal_dag_node_acceptance;
             DROP TABLE goal_dag_edges;
             DROP TABLE goal_dag_nodes;
             DROP TABLE goal_dag_heads;
             DROP TABLE goal_dag_revisions;
             DROP TABLE goal_completion_reviews;
             DROP TABLE goal_evidence_refs;
             DROP TABLE goal_verification_requirements;
             DROP TABLE goal_statements;
             DROP TABLE goals;
             DROP TABLE checkpoint_restores;
             DROP TABLE checkpoints;
             DROP TABLE execution_grants;
             DROP TABLE auto_approval_scopes;
             DROP TABLE approval_requests;
             DROP TABLE workspace_policy;
             PRAGMA user_version = 6;",
        )?;
        connection.execute(
            "INSERT INTO executions (
                execution_id, workspace_id, activity_id, state, mode, request_digest,
                cwd, timeout_ms, output_limit, workspace_read, workspace_write, network,
                created_at_ms, updated_at_ms, revision
             ) VALUES (?1, ?2, ?3, 1, 0, ?4, NULL, 1000, 1024, 1, 0, 0, 3, 3, 1)",
            params![
                execution_id.into_uuid().as_bytes(),
                workspace_command.id().into_uuid().as_bytes(),
                activity.id().into_uuid().as_bytes(),
                [7_u8; 32].as_slice(),
            ],
        )?;
        drop(connection);
        for sidecar in [
            super::sidecar_path(&database, "-wal"),
            super::sidecar_path(&database, "-shm"),
        ] {
            if sidecar.exists() {
                fs::remove_file(sidecar)?;
            }
        }
        let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
        assert!(matches!(
            WorkspaceStore::inspect_existing_read_only(&existing),
            Err(WorkspaceStoreError::MigrationRequired {
                actual: 6,
                required: CURRENT_SCHEMA_VERSION
            })
        ));
        let store = WorkspaceStore::open_existing(&existing)?;
        assert_eq!(store.health()?.schema_version(), CURRENT_SCHEMA_VERSION);
        let execution = store
            .get_execution(execution_id)?
            .ok_or("migrated Execution missing")?;
        assert_eq!(execution.state(), ExecutionState::Interrupted);
        assert_eq!(execution.revision().get(), 2);
        assert!(store.get_workspace_policy()?.is_none());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn recovery_expired_takeover_persists_new_owner_epoch_and_revision()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_root("recovery-expired-takeover")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_command = command(&layout, workspace_id(0xE100), location_id(0xE101), 1)?;
        let mut store = WorkspaceStore::open(&layout, &workspace_command)?;

        let first = ClaimRecoveryLease::new(
            workspace_command.id(),
            runtime_id(0xE102),
            RecoveryLeaseDurationMillis::new(1_000)?,
            timestamp(1)?,
        )?;
        let first = store.claim_recovery_maintenance_lease(first)?;
        assert_eq!(first.status(), RecoveryLeaseClaimStatus::Acquired);
        assert_eq!(first.lease().epoch().get(), 1);
        assert_eq!(first.lease().revision().get(), 2);
        assert_eq!(first.lease().lease_until(), Some(timestamp(1_001)?));

        let takeover = ClaimRecoveryLease::new(
            workspace_command.id(),
            runtime_id(0xE103),
            RecoveryLeaseDurationMillis::new(1_000)?,
            timestamp(1_001)?,
        )?;
        let takeover = store.claim_recovery_maintenance_lease(takeover)?;
        assert_eq!(takeover.status(), RecoveryLeaseClaimStatus::Acquired);
        assert_eq!(takeover.lease().owner_id(), Some(runtime_id(0xE103)));
        assert_eq!(takeover.lease().epoch().get(), 2);
        assert_eq!(takeover.lease().revision().get(), 3);
        assert_eq!(takeover.lease().lease_until(), Some(timestamp(2_001)?));
        assert_eq!(
            store.get_recovery_maintenance_lease()?,
            takeover.lease().clone()
        );

        drop(store);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn independent_recovery_handles_have_one_winner_and_no_double_epoch()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_root("recovery-race")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_command = command(&layout, workspace_id(0xE110), location_id(0xE111), 1)?;
        drop(WorkspaceStore::open(&layout, &workspace_command)?);
        let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
        let first_store = WorkspaceStore::open_existing(&existing)?;
        let second_store = WorkspaceStore::open_existing(&existing)?;
        let first_command = ClaimRecoveryLease::new(
            workspace_command.id(),
            runtime_id(0xE112),
            RecoveryLeaseDurationMillis::new(1_000)?,
            timestamp(1)?,
        )?;
        let second_command = ClaimRecoveryLease::new(
            workspace_command.id(),
            runtime_id(0xE113),
            RecoveryLeaseDurationMillis::new(1_000)?,
            timestamp(1)?,
        )?;

        let (first, second) = std::thread::scope(|scope| {
            let first = scope.spawn(move || {
                let mut store = first_store;
                store.claim_recovery_maintenance_lease(first_command)
            });
            let second = scope.spawn(move || {
                let mut store = second_store;
                store.claim_recovery_maintenance_lease(second_command)
            });
            (
                first.join().map_err(|_| {
                    std::io::Error::other("first recovery claim thread must not panic")
                }),
                second.join().map_err(|_| {
                    std::io::Error::other("second recovery claim thread must not panic")
                }),
            )
        });
        let first = first??;
        let second = second??;
        let statuses = [first.status(), second.status()];
        assert!(statuses.contains(&RecoveryLeaseClaimStatus::Acquired));
        assert!(statuses.contains(&RecoveryLeaseClaimStatus::Busy));
        let winner = if first.status() == RecoveryLeaseClaimStatus::Acquired {
            first.lease()
        } else {
            second.lease()
        };
        assert_eq!(winner.epoch().get(), 1);
        assert_eq!(winner.revision().get(), 2);

        let final_store = WorkspaceStore::open_existing(&existing)?;
        let persisted = final_store.get_recovery_maintenance_lease()?;
        assert_eq!(persisted.epoch().get(), 1);
        assert_eq!(persisted.revision().get(), 2);
        assert_eq!(persisted.owner_id(), winner.owner_id());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn exact_v10_to_v11_migration_only_adds_released_recovery_row()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_root("recovery-v10-migration")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_command = command(&layout, workspace_id(0xE120), location_id(0xE121), 1)?;
        let activity_id = activity_id(0xE122);
        let execution_id = ExecutionId::from_uuid(Uuid::from_u128(0xE123));
        let mut store = WorkspaceStore::open(&layout, &workspace_command)?;
        let _activity = store.create_activity(&CreateActivity::new(
            activity_id,
            workspace_command.id(),
            WorkspaceRevision::INITIAL,
            timestamp(2)?,
        ))?;
        let _goal_attribution = insert_file_test_goal(&mut store, workspace_command.id())?;
        store.connection.execute(
            "INSERT INTO executions (
                execution_id, workspace_id, activity_id, state, mode, request_digest,
                cwd, timeout_ms, output_limit, workspace_read, workspace_write, network,
                created_at_ms, updated_at_ms, revision
             ) VALUES (?1, ?2, ?3, 0, 0, ?4, NULL, 1000, 1024, 1, 0, 0, 20, 20, 1)",
            params![
                execution_id.into_uuid().as_bytes(),
                workspace_command.id().into_uuid().as_bytes(),
                activity_id.into_uuid().as_bytes(),
                [0xE1_u8; 32].as_slice(),
            ],
        )?;
        let before = migration_snapshot(&store.connection)?;
        drop(store);

        let database = layout.database_path();
        let connection = Connection::open(&database)?;
        prepare_pre_v14_fixture(&connection)?;
        connection.execute_batch(
            "             DROP TABLE workspace_harness;
             DROP TABLE recovery_maintenance;
             PRAGMA user_version = 10;",
        )?;
        drop(connection);
        for sidecar in [
            super::sidecar_path(&database, "-wal"),
            super::sidecar_path(&database, "-shm"),
        ] {
            if sidecar.exists() {
                fs::remove_file(sidecar)?;
            }
        }
        let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
        assert!(matches!(
            WorkspaceStore::inspect_existing_read_only(&existing),
            Err(WorkspaceStoreError::MigrationRequired {
                actual: 10,
                required: CURRENT_SCHEMA_VERSION
            })
        ));

        let migrated = WorkspaceStore::open_existing(&existing)?;
        assert_eq!(migrated.health()?.schema_version(), CURRENT_SCHEMA_VERSION);
        let recovery = migrated.get_recovery_maintenance_lease()?;
        assert!(recovery.is_released());
        assert_eq!(recovery.epoch().get(), 0);
        assert_eq!(recovery.revision().get(), 1);
        assert_eq!(recovery.updated_at(), timestamp(1)?);
        assert_eq!(
            migrated.connection.query_row(
                "SELECT COUNT(*) FROM recovery_maintenance",
                [],
                |row| row.get::<_, i64>(0),
            )?,
            1
        );
        assert_eq!(migration_snapshot(&migrated.connection)?, before);
        let execution_state: i64 = migrated.connection.query_row(
            "SELECT state FROM executions WHERE execution_id = ?1",
            params![execution_id.into_uuid().as_bytes()],
            |row| row.get(0),
        )?;
        assert_eq!(execution_state, 0);
        drop(migrated);

        let restarted = WorkspaceStore::open_existing(&existing)?;
        assert_eq!(restarted.get_recovery_maintenance_lease()?, recovery);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn v12_to_v13_migration_adds_empty_harness_authority_without_fabrication()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_root("harness-v12-migration")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_command = command(&layout, workspace_id(0xE130), location_id(0xE131), 1)?;
        let activity = {
            let mut store = WorkspaceStore::open(&layout, &workspace_command)?;
            store.create_activity(&CreateActivity::new(
                activity_id(0xE132),
                workspace_command.id(),
                WorkspaceRevision::INITIAL,
                timestamp(2)?,
            ))?
        };

        let database = layout.database_path();
        let connection = Connection::open(&database)?;
        prepare_pre_v14_fixture(&connection)?;
        connection.execute_batch(
            "             DROP TABLE workspace_harness;
             PRAGMA user_version = 12;",
        )?;
        drop(connection);
        for sidecar in [
            super::sidecar_path(&database, "-wal"),
            super::sidecar_path(&database, "-shm"),
        ] {
            if sidecar.exists() {
                fs::remove_file(sidecar)?;
            }
        }

        let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
        assert!(matches!(
            WorkspaceStore::inspect_existing_read_only(&existing),
            Err(WorkspaceStoreError::MigrationRequired {
                actual: HARNESS_PREVIOUS_SCHEMA_VERSION,
                required: CURRENT_SCHEMA_VERSION
            })
        ));

        let migrated = WorkspaceStore::open_existing(&existing)?;
        assert_eq!(migrated.health()?.schema_version(), CURRENT_SCHEMA_VERSION);
        assert_eq!(migrated.workspace()?.id(), workspace_command.id());
        assert_eq!(
            migrated
                .get_activity(activity.id())?
                .map(|value| value.id()),
            Some(activity.id())
        );
        assert_eq!(migrated.get_applied_harness()?, None);
        drop(migrated);

        let restarted = WorkspaceStore::open_existing(&existing)?;
        assert_eq!(restarted.health()?.schema_version(), CURRENT_SCHEMA_VERSION);
        assert_eq!(restarted.get_applied_harness()?, None);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn schema_v13_migrates_to_v14_without_fabricating_verifier_runs()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_root("harness-verifier-v13-migration")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_command = command(&layout, workspace_id(0xE140), location_id(0xE141), 1)?;
        let activity = {
            let mut store = WorkspaceStore::open(&layout, &workspace_command)?;
            store.create_activity(&CreateActivity::new(
                activity_id(0xE142),
                workspace_command.id(),
                WorkspaceRevision::INITIAL,
                timestamp(2)?,
            ))?
        };

        let database = layout.database_path();
        let connection = Connection::open(&database)?;
        connection.execute_batch(
            "DROP TABLE agent_dag_replan_ledger;
             DROP TABLE agent_dag_authoring_grants;
             DROP INDEX agent_transport_principals_workspace_token_idx;
             DROP TABLE agent_transport_principals;",
        )?;
        connection.execute_batch(
            "PRAGMA wal_checkpoint(TRUNCATE);\n             PRAGMA journal_mode = DELETE;\n             DROP TABLE agent_work_update_evidence_refs;\n             DROP TABLE agent_work_updates;\n             DROP TABLE agent_focus_events;\n             DROP TABLE agent_instances;\n             DROP TABLE workspace_harness_verifier_items;\n             DROP TABLE workspace_harness_verifier_runs;\n             PRAGMA user_version = 13;",
        )?;
        drop(connection);
        for sidecar in [
            super::sidecar_path(&database, "-wal"),
            super::sidecar_path(&database, "-shm"),
        ] {
            if sidecar.exists() {
                fs::remove_file(sidecar)?;
            }
        }

        let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
        assert!(matches!(
            WorkspaceStore::inspect_existing_read_only(&existing),
            Err(WorkspaceStoreError::MigrationRequired {
                actual: HARNESS_VERIFIER_PREVIOUS_SCHEMA_VERSION,
                required: CURRENT_SCHEMA_VERSION
            })
        ));

        let migrated = WorkspaceStore::open_existing(&existing)?;
        assert_eq!(migrated.health()?.schema_version(), CURRENT_SCHEMA_VERSION);
        assert_eq!(migrated.workspace()?.id(), workspace_command.id());
        assert_eq!(
            migrated
                .get_activity(activity.id())?
                .map(|value| value.id()),
            Some(activity.id())
        );
        assert!(migrated.get_latest_harness_verifier_run()?.is_none());
        drop(migrated);

        let restarted = WorkspaceStore::open_existing(&existing)?;
        assert_eq!(restarted.health()?.schema_version(), CURRENT_SCHEMA_VERSION);
        assert!(restarted.get_latest_harness_verifier_run()?.is_none());
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
