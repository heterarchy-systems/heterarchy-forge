//! Durable semantic state for one explicitly selected Workspace.
//!
//! The Global Registry owns Location metadata only. This adapter owns the
//! database below one `WorkspaceStateLayout` and isolates Workspace identity and
//! Activity state from every other Workspace.

use crate::workspace_coordinator_recovery;
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
    AbandonDiffEvidence, ActivityCoordinatorActor, ActivityId, ActivityLeaseBatchLimit,
    ActivityLeaseProjection, ActivityLeaseRevision, ActivityListLimit, ActivityProjection,
    ActivityRevision, ActivityState, ActivitySuccessor, ApprovalDecision, ApprovalRequestId,
    ApprovalRevision, AuthorizedExecutionRead, AutoApprovalScope, AutoApprovalScopeId,
    BeginDiffEvidence, BeginDiffPurge, BeginExecution, BeginFileMutation, BeginFileMutationResult,
    BeginFileMutationStatus, BootstrapActivity, BootstrapActivityDecision, ChangeSetAttribution,
    ChangeSetProducer, CheckpointId, CheckpointRestoreId, CheckpointRestoreRevision,
    CheckpointRevision, ClaimRecoveryLease, CloseActivity, CompleteDiffEvidence, CompleteDiffPurge,
    CompleteExecution, CompleteFileMutation, CreateActivity, DagHeadRevision, DagRevision,
    DagRevisionNumber, DiffId, DiffListLimit, DiffPurgeRecord, DiffRetentionKeepCount,
    DiffRetentionPlan, DiffRetentionPlanLimit, EstablishWorkspace, ExecutionAgentProvenance,
    ExecutionAuthorizationRequest, ExecutionGrant, ExecutionGrantId, ExecutionGrantRevision,
    ExecutionId, ExecutionListLimit, ExecutionOutputCursor, ExecutionOutputEvent,
    ExecutionOutputRead, FailExecution, FailFileMutation, FileMutationRecord, GoalEvidenceRef,
    GoalId, GoalListLimit, GoalReview, GoalRevision, GoalStatusKind, GoalWorkAttribution,
    LocationId, MarkExecutionRunning, PolicyRevision, ReconcileExpiredActivities,
    RecoveryLeaseDurationMillis, RecoveryMaintenanceLease, RegisteredActivity,
    RegisteredApprovalRequest, RegisteredCheckpoint, RegisteredCheckpointRestore,
    RegisteredDagNode, RegisteredDiffEvidence, RegisteredExecution, RegisteredGoal,
    RegisteredWorkspace, ReleaseActivityLease, ReleaseRecoveryLease, RenewActivityLease,
    RenewRecoveryLease, RuntimeInstanceId, SetActivityState, SourceTreeRequestDigest,
    SourceWriteAuthority, TimestampMillis, TreeChangeSetAdmission, TreeChangeSetIntent,
    TreeMutationId, VerificationInputEvidence, VerificationProjection, WorkspaceId,
    WorkspacePolicy, WorkspaceRelativePath, WorkspaceRevision, WorkspaceRoot,
    WorkspaceRootDecision, WorkspaceRootDecisionError, WorkspaceRootFingerprint,
    decide_bootstrap_activity, decide_workspace_root,
};
use forge_workspace::{
    ExistingWorkspaceStateLayout, StateLayoutError, WorkspaceStateExclusiveGate,
    WorkspaceStateGateError, WorkspaceStateLayout, WorkspaceStateSharedGate,
};
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Row, Rows, Transaction, TransactionBehavior, params,
};
use thiserror::Error;
use uuid::Uuid;

mod agent_dag_readback;
mod approval_cleanup;
mod execution_evidence;
mod execution_stop;
mod expired_activity_recovery;
mod quiescent_activity_lease_resume;
mod recovery_maintenance;
mod recovery_run;
mod relocation;
mod root_recovery;
mod started_activity_lease_resume;
mod unstarted_activity_continuation;
pub use execution_stop::OwnedWorkspaceStopCapture;
pub use expired_activity_recovery::{
    ExpiredActivityRecoveryOperation, ExpiredActivityRecoveryReadback,
    ExpiredActivityRecoveryReceipt, ExpiredActivityRecoveryStoreError,
    ExpiredActivityRecoveryStoreRequest,
};
pub use quiescent_activity_lease_resume::{
    QuiescentActivityLeaseResumeReadback, QuiescentActivityLeaseResumeStoreError,
};
pub use recovery_run::RecoveryRunOperation;
pub use root_recovery::{
    RootRecoveryAuthorityBlocker, RootRecoveryIdentityObservation, RootRecoveryOperation,
    RootRecoveryProbe, RootRecoveryReceipt, RootRecoveryStoreError, delegated_authority_digest,
};
pub use started_activity_lease_resume::{
    StartedActivityLeaseResumeOperation, StartedActivityLeaseResumeReadback,
    StartedActivityLeaseResumeStoreError,
};
pub use unstarted_activity_continuation::{
    UnstartedActivityContinuationOperation, UnstartedActivityContinuationReadback,
    UnstartedActivityContinuationReceipt, UnstartedActivityContinuationStoreError,
    UnstartedActivityContinuationStoreRequest,
};
mod goal_deletion;
mod goal_mutation;
pub use goal_deletion::{GoalDeletionAdmission, GoalDeletionStore};

use crate::queue_settings_catalog::{
    QueueSettings, QueueSettingsRevision, RegisteredQueueSettings,
};
use crate::workspace_activity_successors::{self, ActivitySuccessorStoreError};
use crate::workspace_admission_envelopes;
use crate::workspace_agent_assignments;
use crate::workspace_agent_binding_activation;
use crate::workspace_agent_binding_rejections;
use crate::workspace_agent_binding_reservations;
use crate::workspace_agent_dag::{self, AgentDagPlanCommitResult, AgentDagStoreError};
use crate::workspace_agent_delegation;
use crate::workspace_agent_departure_reconciliation;
use crate::workspace_agent_effect_outbox;
use crate::workspace_agent_events::{self, AgentEventStoreError};
use crate::workspace_agent_migration;
use crate::workspace_agent_session_reconciliation;
use crate::workspace_agents::{self, AgentStoreError};
use crate::workspace_approvals::{self, ApprovalStoreError};
use crate::workspace_changesets::{self, ChangeSetStoreError};
use crate::workspace_checkpoints::{self, CheckpointDoctorReport, CheckpointStoreError};
use crate::workspace_coordinators::{self, CoordinatorStoreError};
use crate::workspace_dag_node_evidence;
use crate::workspace_dags::{self, DagDoctorReport};
use crate::workspace_diffs::{self, DiffDoctorReport, DiffStoreError};
use crate::workspace_effect_fact_outbox;
use crate::workspace_execution_stops;
use crate::workspace_executions::{self, ExecutionStoreError};
use crate::workspace_goal_creation_watermarks;
use crate::workspace_goal_deletion;
use crate::workspace_goal_mutations;
use crate::workspace_goals::{self, GoalCompletionReceipt, GoalEvidenceRecord, GoalStoreError};
use crate::workspace_queue_settings::{self, WorkspaceQueueSettingsStoreError};
use crate::workspace_recovery::{self, RecoveryStoreError};
use crate::workspace_semantic_events;
use crate::workspace_verification::{self, VerificationStoreError};
use crate::workspace_work_cuts;
use crate::workspace_writer_leases::{self, WriterLeaseStoreError};

/// `SQLite` application marker for Workspace-local databases.
///
/// This is deliberately different from the Global Registry marker.
pub const WORKSPACE_APPLICATION_ID: i64 = 0x4846_5753;

pub(crate) const CURRENT_SCHEMA_VERSION: i64 = 69;
const PREVIOUS_QUIESCENT_ACTIVITY_LEASE_RESUME_SCHEMA_VERSION: i64 = 68;
const PREVIOUS_ADMISSION_IDENTITY_SCHEMA_VERSION: i64 = 67;
const PREVIOUS_STARTED_ACTIVITY_LEASE_RESUME_SCHEMA_VERSION: i64 = 66;
const PREVIOUS_UNSTARTED_ACTIVITY_CONTINUATION_SCHEMA_VERSION: i64 = 65;
const PREVIOUS_BINDING_REJECTION_SCHEMA_VERSION: i64 = 64;
const PREVIOUS_EXPIRED_ACTIVITY_RECOVERY_SCHEMA_VERSION: i64 = 63;
const PREVIOUS_DELEGATED_ROOT_RECOVERY_SCHEMA_VERSION: i64 = 62;
const PREVIOUS_ROOT_RECOVERY_SCHEMA_VERSION: i64 = 61;
const PREVIOUS_RECOVERY_RUNS_SCHEMA_VERSION: i64 = 60;
const PREVIOUS_STOP_SETTLEMENT_SCHEMA_VERSION: i64 = 59;
const PREVIOUS_NATIVE_CLOSURE_SCHEMA_VERSION: i64 = 58;
const PREVIOUS_STOP_AUTHORITY_SCHEMA_VERSION: i64 = 57;
const PREVIOUS_EXECUTION_STOPS_SCHEMA_VERSION: i64 = 56;
/// Schema v55 permits finite automatic-approval counts only.
const PREVIOUS_AUTO_APPROVAL_SCHEMA_VERSION: i64 = 55;
/// Schema v54 contains the work-cut journal but no continuation journal.
const PREVIOUS_WORK_CUT_CONTINUATIONS_SCHEMA_VERSION: i64 = 54;
/// Schema v53 contains Assignment offer seals but no work-cut journal.
const PREVIOUS_WORK_CUTS_SCHEMA_VERSION: i64 = 53;
/// Schema v52 contains Goal creation watermarks but no Assignment offer seals.
const PREVIOUS_ASSIGNMENT_OFFER_SEALS_SCHEMA_VERSION: i64 = 52;
const PREVIOUS_GOAL_CREATION_WATERMARK_SCHEMA_VERSION: i64 = 51;
const PREVIOUS_COORDINATOR_RECOVERY_SCHEMA_VERSION: i64 = 50;
const PREVIOUS_APPROVAL_AUTHORITY_FENCE_SCHEMA_VERSION: i64 = 49;
const PREVIOUS_GOAL_MUTATION_RECEIPTS_SCHEMA_VERSION: i64 = 48;
const PREVIOUS_SOURCE_REFS_SCHEMA_VERSION: i64 = 47;
const PREVIOUS_CHANGE_SET_PRODUCER_SCHEMA_VERSION: i64 = 46;
const PREVIOUS_ADMISSION_ENVELOPE_SCHEMA_VERSION: i64 = 45;
const PREVIOUS_SEMANTIC_EVENTS_SCHEMA_VERSION: i64 = 44;
const PREVIOUS_ASSIGNMENT_SUBMITTED_SCHEMA_VERSION: i64 = 43;
const PREVIOUS_ASSIGNMENT_OFFERED_SCHEMA_VERSION: i64 = 42;
const PREVIOUS_WORK_CREDIT_SCHEMA_VERSION: i64 = 41;
const PREVIOUS_CHANGE_SET_FACT_SCHEMA_VERSION: i64 = 40;
const PREVIOUS_EFFECT_FACT_SCHEMA_VERSION: i64 = 39;
const PREVIOUS_DEPARTURE_RECONCILIATION_SCHEMA_VERSION: i64 = 38;
const PREVIOUS_RECONCILIATION_SCHEMA_VERSION: i64 = 37;
const PREVIOUS_DELEGATED_SCHEMA_VERSION: i64 = 36;
const PREVIOUS_BINDING_SCHEMA_VERSION: i64 = 35;
const PREVIOUS_OPERATIONS_SCHEMA_VERSION: i64 = 34;
const PREVIOUS_QUEUE_SCHEMA_VERSION: i64 = 33;
const PREVIOUS_SCHEMA_VERSION: i64 = 30;
const PREVIOUS_MODERN_SCHEMA_VERSION: i64 = 31;
const PREVIOUS_LATEST_SCHEMA_VERSION: i64 = 32;
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const LIVE_IDENTITY_RETRY_LIMIT: usize = 8;
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

/// Historical single-file mutation metadata and its optional Diff projection
/// read from one Workspace `SQLite` snapshot.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileMutationReadSnapshot {
    record: FileMutationRecord,
    diff: Option<RegisteredDiffEvidence>,
}

impl FileMutationReadSnapshot {
    pub(crate) const fn new(
        record: FileMutationRecord,
        diff: Option<RegisteredDiffEvidence>,
    ) -> Self {
        Self { record, diff }
    }

    pub const fn record(&self) -> &FileMutationRecord {
        &self.record
    }

    pub const fn diff(&self) -> Option<&RegisteredDiffEvidence> {
        self.diff.as_ref()
    }
}

/// Historical source-tree metadata and its optional Diff projection read from
/// one Workspace `SQLite` snapshot.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceTreeReadSnapshot {
    change_set: forge_domain::RegisteredChangeSet,
    request_digest: SourceTreeRequestDigest,
    applied_mutations: Vec<TreeMutationId>,
    mutation_count: usize,
    diff: Option<RegisteredDiffEvidence>,
}

impl SourceTreeReadSnapshot {
    pub(crate) const fn new(
        change_set: forge_domain::RegisteredChangeSet,
        request_digest: SourceTreeRequestDigest,
        applied_mutations: Vec<TreeMutationId>,
        mutation_count: usize,
        diff: Option<RegisteredDiffEvidence>,
    ) -> Self {
        Self {
            change_set,
            request_digest,
            applied_mutations,
            mutation_count,
            diff,
        }
    }

    pub const fn change_set(&self) -> &forge_domain::RegisteredChangeSet {
        &self.change_set
    }

    pub const fn request_digest(&self) -> SourceTreeRequestDigest {
        self.request_digest
    }

    pub const fn applied_mutations(&self) -> &[TreeMutationId] {
        self.applied_mutations.as_slice()
    }

    pub const fn mutation_count(&self) -> usize {
        self.mutation_count
    }

    pub const fn diff(&self) -> Option<&RegisteredDiffEvidence> {
        self.diff.as_ref()
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
    observation_policy: ReadOnlyObservationPolicy,
    _snapshot: Option<DoctorSnapshot>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadOnlyObservationPolicy {
    StableFiles,
    LiveWal,
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
        Self::open_with_mode(layout, false)
    }

    /// Open a stable read-only snapshot while the caller already holds the
    /// exclusive root gate.  The ordinary Doctor path acquires a shared gate;
    /// recovery must never attempt that nested lock.
    fn open_under_exclusive(
        layout: &ExistingWorkspaceStateLayout,
        gate: &WorkspaceStateExclusiveGate,
    ) -> Result<Self, WorkspaceStoreError> {
        Self::open_with_mode_and_gate(layout, false, Some(gate))
    }

    /// Open a live read-only view. A paired WAL/SHM source stays on the
    /// original database so concurrent committed frames remain observable;
    /// an unpaired source uses the immutable no-sidecar path.
    fn open_live(layout: &ExistingWorkspaceStateLayout) -> Result<Self, WorkspaceStoreError> {
        Self::open_with_mode(layout, true)
    }

    fn open_with_mode(
        layout: &ExistingWorkspaceStateLayout,
        allow_live_wal: bool,
    ) -> Result<Self, WorkspaceStoreError> {
        Self::open_with_mode_and_gate(layout, allow_live_wal, None)
    }

    fn open_with_mode_and_gate(
        layout: &ExistingWorkspaceStateLayout,
        allow_live_wal: bool,
        exclusive_gate: Option<&WorkspaceStateExclusiveGate>,
    ) -> Result<Self, WorkspaceStoreError> {
        let path = layout.database_path();
        let state_root = layout.state_root().to_path_buf();
        let state_root_identity = inspect_directory(&state_root)?;
        let root_fingerprint = layout
            .root_fingerprint()
            .map_err(|source| WorkspaceStoreError::LayoutFingerprintObservation { source })?;
        let _state_gate = match exclusive_gate {
            Some(gate) => {
                gate.ensure_root_binding(layout.workspace_root(), root_fingerprint)
                    .map_err(WorkspaceStoreError::StateGate)?;
                None
            }
            None => Some(
                WorkspaceStateSharedGate::acquire(layout.workspace_root(), root_fingerprint)
                    .map_err(WorkspaceStoreError::StateGate)?,
            ),
        };
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
        let live_wal = allow_live_wal && wal_identity.is_some();
        let observation_policy = if live_wal {
            ReadOnlyObservationPolicy::LiveWal
        } else {
            ReadOnlyObservationPolicy::StableFiles
        };
        let snapshot = if wal_identity.is_some() && !live_wal {
            Some(DoctorSnapshot::create(&path, &wal_path)?)
        } else {
            None
        };
        let connection_path = snapshot
            .as_ref()
            .map_or_else(|| path.clone(), DoctorSnapshot::database_path);
        let uri = if snapshot.is_some() || live_wal {
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
            observation_policy,
            _snapshot: snapshot,
        };
        database.ensure_live_observation()?;
        // Both pragmas are connection-local. Stable-file and immutable
        // observations cannot create or modify source state. An active WAL
        // read may update SQLite shared-memory read marks; identity fences
        // still reject replacement or disappearance.
        database.connection.busy_timeout(BUSY_TIMEOUT)?;
        database
            .connection
            .pragma_update(None, "foreign_keys", true)?;
        database
            .connection
            .pragma_update(None, "query_only", true)?;
        database.ensure_live_observation()?;
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
        self.ensure_identity()?;
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

    fn ensure_live_observation(&self) -> Result<(), WorkspaceStoreError> {
        match self.observation_policy {
            ReadOnlyObservationPolicy::StableFiles => self.ensure_unchanged(),
            ReadOnlyObservationPolicy::LiveWal => self.ensure_identity(),
        }
    }

    fn ensure_identity(&self) -> Result<(), WorkspaceStoreError> {
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
type ApprovalExecutionGrantReadback = workspace_approvals::ApprovalExecutionGrantReadback;

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
    _state_gate: Option<WorkspaceStateSharedGate>,
    batch_transaction_count: u64,
}

/// Opaque physical and durable Workspace binding captured from one checked
/// `WorkspaceStore`. It carries no WAL/SHM identity because those sidecars are
/// SQLite-managed and may rotate while a journal remains admitted.
#[must_use]
#[derive(Clone, PartialEq, Eq)]
pub struct WorkspaceJournalBinding {
    workspace_id: WorkspaceId,
    workspace_revision: WorkspaceRevision,
    location_id: LocationId,
    workspace_root: PathBuf,
    state_root: PathBuf,
    database_path: PathBuf,
    root_fingerprint: WorkspaceRootFingerprint,
    state_root_identity: DirectoryIdentity,
    database_identity: FileIdentity,
}

impl fmt::Debug for WorkspaceJournalBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkspaceJournalBinding")
            .field("workspace_id", &self.workspace_id)
            .field("workspace_revision", &self.workspace_revision)
            .field("location_id", &self.location_id)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy)]
enum ExistingOpenPolicy<'a> {
    Restart,
    Journal(&'a WorkspaceJournalBinding),
    Relocation(&'a RegisteredWorkspace),
}

impl ExistingOpenPolicy<'_> {
    fn path_matches(self, workspace: &RegisteredWorkspace, path: &Path) -> bool {
        match self {
            Self::Relocation(expected) => workspace == expected,
            _ => workspace.root().as_path() == path,
        }
    }
}

impl WorkspaceJournalBinding {
    /// Logical durable binding for immutable history. Live file identities
    /// remain checked through this opaque binding at every effect boundary.
    pub fn recovery_history_digest(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hash = Sha256::new();
        hash.update(b"forge.recovery.binding.v1\0");
        hash.update(self.workspace_id.into_uuid().as_bytes());
        hash.update(self.workspace_revision.get().to_le_bytes());
        hash.update(self.location_id.into_uuid().as_bytes());
        hash.update(self.root_fingerprint.as_bytes());
        for path in [&self.workspace_root, &self.state_root, &self.database_path] {
            let bytes = path.as_os_str().as_bytes();
            hash.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
            hash.update(bytes);
        }
        hash.finalize().into()
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn workspace_revision(&self) -> WorkspaceRevision {
        self.workspace_revision
    }

    pub const fn location_id(&self) -> LocationId {
        self.location_id
    }

    fn validate_layout(
        &self,
        layout: &ExistingWorkspaceStateLayout,
    ) -> Result<WorkspaceRootFingerprint, WorkspaceStoreError> {
        let root_fingerprint = layout
            .root_fingerprint()
            .map_err(|source| WorkspaceStoreError::LayoutFingerprintObservation { source })?;
        if self.workspace_root != layout.workspace_root()
            || self.state_root != layout.state_root()
            || self.database_path != layout.database_path()
        {
            return Err(WorkspaceStoreError::WorkspaceJournalBindingPathMismatch);
        }
        if self.root_fingerprint != root_fingerprint {
            return Err(WorkspaceStoreError::WorkspaceRootBindingConflict {
                expected: self.root_fingerprint,
                observed: root_fingerprint,
            });
        }
        let wal_path = sidecar_path(&self.database_path, "-wal");
        let shm_path = sidecar_path(&self.database_path, "-shm");
        let wal_identity = inspect_regular_file(&wal_path, true)?;
        let shm_identity = inspect_regular_file(&shm_path, true)?;
        if wal_identity.is_none() != shm_identity.is_none() {
            return Err(WorkspaceStoreError::DatabaseSidecarPairMismatch {
                wal: wal_path,
                shm: shm_path,
            });
        }
        ensure_live_paths(WorkspaceLiveBinding {
            state_root: layout.state_root(),
            state_root_identity: self.state_root_identity,
            workspace_root: layout.workspace_root(),
            root_fingerprint,
            database_path: &self.database_path,
            database_identity: self.database_identity,
            wal_identity,
            shm_identity,
        })?;
        Ok(root_fingerprint)
    }
}

/// A durable lifecycle fact that blocks deletion of a Workspace state root.
///
/// The preflight deliberately treats stale-looking nonterminal state as a
/// blocker.  Recovery or an owner-authorized stop must resolve it first; this
/// operation never infers that a foreign process has exited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceStateRemovalBlocker {
    PendingExecutionStop,
    OpenActivity,
    ActiveExecution,
    ActiveWriterLease,
    RecoveryMaintenanceLease,
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

    /// Capture an opaque binding for journal writes against this exact
    /// Workspace identity and physical state layout. The binding is only
    /// minted from a checked live store and cannot be constructed externally.
    pub fn journal_binding(&self) -> Result<WorkspaceJournalBinding, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let workspace = self.workspace()?;
        if workspace.root().as_path() != self.workspace_root
            || workspace.root_fingerprint() != self.root_fingerprint
        {
            return Err(WorkspaceStoreError::ExistingWorkspaceBindingMismatch {
                stored_root: workspace.root().as_path().to_path_buf(),
                observed_root: self.workspace_root.clone(),
                stored_fingerprint: workspace.root_fingerprint(),
                observed_fingerprint: self.root_fingerprint,
            });
        }
        self.ensure_live_binding()?;
        Ok(WorkspaceJournalBinding {
            workspace_id: workspace.id(),
            workspace_revision: workspace.revision(),
            location_id: workspace.location_id(),
            workspace_root: self.workspace_root.clone(),
            state_root: self.state_root.clone(),
            database_path: self.path.clone(),
            root_fingerprint: self.root_fingerprint,
            state_root_identity: self.state_root_identity,
            database_identity: self.database_identity,
        })
    }

    /// Open an existing current-schema Workspace using an exact previously
    /// captured journal binding. This path never initializes or migrates.
    pub fn open_existing_journal(
        layout: &ExistingWorkspaceStateLayout,
        binding: &WorkspaceJournalBinding,
    ) -> Result<Self, WorkspaceStoreError> {
        binding.validate_layout(layout)?;
        let root_fingerprint = layout
            .root_fingerprint()
            .map_err(|source| WorkspaceStoreError::LayoutFingerprintObservation { source })?;
        let gate = WorkspaceStateSharedGate::acquire(layout.workspace_root(), root_fingerprint)
            .map_err(WorkspaceStoreError::StateGate)?;
        binding.validate_layout(layout)?;
        Self::open_existing_with_timeout_and_gate_policy(
            layout,
            BUSY_TIMEOUT,
            Some(gate),
            || Ok(()),
            ExistingOpenPolicy::Journal(binding),
        )
    }

    /// Validate that a state root may be removed while the caller retains the
    /// matching exclusive root-directory gate. It performs no semantic
    /// transition, but opens the normal checked `SQLite` connection to validate
    /// current schema and runtime policy; it is therefore not a read-only
    /// diagnostic API. Expired foreign authority remains a blocker.
    ///
    /// A valid initialized state root that has never received a `SQLite`
    /// database is removable. A missing main database with either `SQLite`
    /// sidecar remains corruption and fails closed.
    pub fn preflight_state_removal_under_exclusive(
        layout: &ExistingWorkspaceStateLayout,
        gate: &WorkspaceStateExclusiveGate,
        expected_location_id: LocationId,
    ) -> Result<Option<RegisteredWorkspace>, WorkspaceStoreError> {
        let root_fingerprint = layout
            .root_fingerprint()
            .map_err(|source| WorkspaceStoreError::LayoutFingerprintObservation { source })?;
        gate.ensure_root_binding(layout.workspace_root(), root_fingerprint)
            .map_err(WorkspaceStoreError::StateGate)?;

        let path = layout.database_path();
        let database = inspect_regular_file(&path, true)?;
        if database.is_none() {
            let wal = sidecar_path(&path, "-wal");
            let shm = sidecar_path(&path, "-shm");
            if inspect_regular_file(&wal, true)?.is_some() {
                return Err(WorkspaceStoreError::DatabaseSidecarWithoutMain(wal));
            }
            if inspect_regular_file(&shm, true)?.is_some() {
                return Err(WorkspaceStoreError::DatabaseSidecarWithoutMain(shm));
            }
            gate.ensure_root_binding(layout.workspace_root(), root_fingerprint)
                .map_err(WorkspaceStoreError::StateGate)?;
            return Ok(None);
        }

        let store =
            Self::open_existing_with_timeout_and_gate(layout, BUSY_TIMEOUT, None, || Ok(()))?;
        let workspace = store.workspace()?;
        if workspace.location_id() != expected_location_id {
            return Err(WorkspaceStoreError::StateRemovalLocationMismatch {
                expected: expected_location_id,
                actual: workspace.location_id(),
            });
        }
        if let Some(blocker) = store.state_removal_blocker(workspace.id())? {
            return Err(WorkspaceStoreError::StateRemovalBlocked(blocker));
        }
        drop(store);
        gate.ensure_root_binding(layout.workspace_root(), root_fingerprint)
            .map_err(WorkspaceStoreError::StateGate)?;
        Ok(Some(workspace))
    }

    /// Inspect one already-owned Workspace database without taking a write
    /// connection or changing any on-disk `SQLite` state.
    ///
    /// This is intentionally separate from [`Self::open_existing`], which opens
    /// only the current schema with a write-capable connection for
    /// restart/recovery. Read-only workspace listing and resolution must use
    /// this method so observing a candidate cannot create WAL/SHM files,
    /// rebind identity, or otherwise establish authority.
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
        let read_shape = compatible_read_only_shape(ownership)?;
        validate_schema_shape_for_version(&connection, read_shape)?;
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
        let root_fingerprint = layout
            .root_fingerprint()
            .map_err(|source| WorkspaceStoreError::LayoutFingerprintObservation { source })?;
        let _state_gate =
            WorkspaceStateSharedGate::acquire(layout.workspace_root(), root_fingerprint)
                .map_err(WorkspaceStoreError::StateGate)?;
        let database = ReadOnlyDoctorDatabase::open(layout)?;
        let snapshot = inspect_read_only_workspace_identity(&database, layout)?;
        database.ensure_unchanged()?;
        Ok(snapshot.workspace)
    }

    /// Read the current durable Workspace identity from one live read-only
    /// `SQLite` transaction while concurrent writers continue using WAL.
    ///
    /// Unlike the Doctor snapshot boundary, this operation does not require
    /// database/WAL byte metadata to remain quiescent. It anchors a normal
    /// read transaction, validates ownership and schema inside that snapshot,
    /// and fences the Workspace root plus database/WAL/SHM path identities
    /// before returning. No semantic row, schema, or journal policy is
    /// mutated; SQLite may update shared-memory read marks for an active WAL.
    pub fn inspect_existing_identity_live_read_only(
        layout: &ExistingWorkspaceStateLayout,
    ) -> Result<RegisteredWorkspace, WorkspaceStoreError> {
        let root_fingerprint = layout
            .root_fingerprint()
            .map_err(|source| WorkspaceStoreError::LayoutFingerprintObservation { source })?;
        let _state_gate =
            WorkspaceStateSharedGate::acquire(layout.workspace_root(), root_fingerprint)
                .map_err(WorkspaceStoreError::StateGate)?;
        let database_path = layout.database_path();
        let mut last_retryable = None;
        for _ in 0..LIVE_IDENTITY_RETRY_LIMIT {
            match Self::inspect_existing_identity_live_read_only_once(layout) {
                Ok(workspace) => return Ok(workspace),
                Err(error) if is_retryable_live_identity_error(&error, &database_path) => {
                    last_retryable = Some(error);
                }
                Err(error) => return Err(error),
            }
        }
        Err(
            last_retryable.unwrap_or_else(|| WorkspaceStoreError::DatabasePathInvariant {
                path: database_path,
                detail: "live identity retry budget was unexpectedly empty",
            }),
        )
    }

    fn inspect_existing_identity_live_read_only_once(
        layout: &ExistingWorkspaceStateLayout,
    ) -> Result<RegisteredWorkspace, WorkspaceStoreError> {
        let database = ReadOnlyDoctorDatabase::open_live(layout)?;
        database.ensure_live_observation()?;
        let transaction = database.connection.unchecked_transaction()?;

        let ownership = match inspect_database(&transaction) {
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
        let read_shape = compatible_read_only_shape(ownership)?;
        validate_schema_shape_for_version(&transaction, read_shape)?;
        let workspace = query_workspace_row(&transaction)?
            .ok_or(WorkspaceStoreError::WorkspaceIdentityMissing)
            .and_then(decode_workspace)?;
        validate_existing_workspace_binding(&workspace, layout, database.root_fingerprint)?;
        let _recovery_lease = workspace_recovery::get(&transaction, workspace.id())?;
        database.ensure_live_observation()?;
        transaction.commit()?;
        database.ensure_live_observation()?;
        Ok(workspace)
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
        let root_fingerprint = layout
            .root_fingerprint()
            .map_err(|source| WorkspaceStoreError::LayoutFingerprintObservation { source })?;
        let _state_gate =
            WorkspaceStateSharedGate::acquire(layout.workspace_root(), root_fingerprint)
                .map_err(WorkspaceStoreError::StateGate)?;
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
        let root_fingerprint = layout
            .root_fingerprint()
            .map_err(|source| WorkspaceStoreError::LayoutFingerprintObservation { source })?;
        let gate = WorkspaceStateSharedGate::acquire(layout.workspace_root(), root_fingerprint)
            .map_err(WorkspaceStoreError::StateGate)?;
        Self::open_existing_with_timeout_and_gate(layout, busy_timeout, Some(gate), || Ok(()))
    }

    fn open_existing_with_timeout_and_gate<F>(
        layout: &ExistingWorkspaceStateLayout,
        busy_timeout: Duration,
        state_gate: Option<WorkspaceStateSharedGate>,
        after_sidecar_observation: F,
    ) -> Result<Self, WorkspaceStoreError>
    where
        F: FnOnce() -> Result<(), WorkspaceStoreError>,
    {
        Self::open_existing_with_timeout_and_gate_policy(
            layout,
            busy_timeout,
            state_gate,
            after_sidecar_observation,
            ExistingOpenPolicy::Restart,
        )
    }

    fn open_existing_with_timeout_and_gate_policy<F>(
        layout: &ExistingWorkspaceStateLayout,
        busy_timeout: Duration,
        state_gate: Option<WorkspaceStateSharedGate>,
        after_sidecar_observation: F,
        policy: ExistingOpenPolicy<'_>,
    ) -> Result<Self, WorkspaceStoreError>
    where
        F: FnOnce() -> Result<(), WorkspaceStoreError>,
    {
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
        after_sidecar_observation()?;
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
            _state_gate: state_gate,
            batch_transaction_count: 0,
        };
        match policy {
            ExistingOpenPolicy::Restart => {
                prepare_database(&mut store.connection, busy_timeout, false)?;
            }
            ExistingOpenPolicy::Relocation(_) => {
                prepare_database_current_only(&mut store.connection, busy_timeout)?;
            }
            ExistingOpenPolicy::Journal(binding) => {
                prepare_database_current_only(&mut store.connection, busy_timeout)?;
                binding.validate_layout(layout)?;
            }
        }
        // WAL/SHM files are SQLite-owned ephemeral sidecars. Another valid
        // connection may create or rotate them between the pre-open
        // observation and this connection joining the WAL. Rebase only after
        // SQLite has opened/configured the database, then require that exact
        // identity to remain stable for each subsequent operation.
        store.capture_sidecar_identities()?;
        store.ensure_live_binding()?;
        store.validate_runtime_policy()?;
        let workspace = query_workspace_row(&store.connection)?
            .ok_or(WorkspaceStoreError::WorkspaceIdentityMissing)
            .and_then(decode_workspace)?;
        let path_matches = policy.path_matches(&workspace, layout.workspace_root());
        if !path_matches || workspace.root_fingerprint() != root_fingerprint {
            return Err(WorkspaceStoreError::ExistingWorkspaceBindingMismatch {
                stored_root: workspace.root().as_path().to_path_buf(),
                observed_root: layout.workspace_root().to_path_buf(),
                stored_fingerprint: workspace.root_fingerprint(),
                observed_fingerprint: root_fingerprint,
            });
        }
        if let ExistingOpenPolicy::Journal(binding) = policy {
            if workspace.id() != binding.workspace_id {
                return Err(
                    WorkspaceStoreError::WorkspaceJournalBindingWorkspaceMismatch {
                        expected: binding.workspace_id,
                        actual: workspace.id(),
                    },
                );
            }
            if workspace.location_id() != binding.location_id {
                return Err(WorkspaceStoreError::LocationBindingConflict {
                    stored: workspace.location_id(),
                    requested: binding.location_id,
                });
            }
            if workspace.revision() != binding.workspace_revision {
                return Err(WorkspaceStoreError::WorkspaceRevisionConflict {
                    expected: binding.workspace_revision,
                    actual: workspace.revision(),
                });
            }
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
        let state_gate =
            WorkspaceStateSharedGate::acquire(layout.workspace_root(), layout_fingerprint)
                .map_err(WorkspaceStoreError::StateGate)?;
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
            _state_gate: Some(state_gate),
            batch_transaction_count: 0,
        };
        prepare_database(&mut store.connection, busy_timeout, true)?;

        store.capture_sidecar_identities()?;
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

    fn state_removal_blocker(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<Option<WorkspaceStateRemovalBlocker>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let blocker = state_removal_blocker_for_connection(&self.connection, workspace_id)?;
        self.ensure_live_binding()?;
        Ok(blocker)
    }
}

/// Read the legacy removal blockers from a caller-owned connection.  Recovery
/// uses this same query set against its bounded read-only snapshot so the
/// ordinary removal contract and the owner-controlled binding transition do
/// not drift apart.
fn state_removal_blocker_for_connection(
    connection: &Connection,
    workspace_id: WorkspaceId,
) -> Result<Option<WorkspaceStateRemovalBlocker>, WorkspaceStoreError> {
    workspace_agent_migration::ensure_legacy_writes(connection)?;
    state_removal_blocker_rows(connection, workspace_id)
}

fn state_removal_blocker_rows(
    connection: &Connection,
    workspace_id: WorkspaceId,
) -> Result<Option<WorkspaceStateRemovalBlocker>, WorkspaceStoreError> {
    let workspace = workspace_id.into_uuid().into_bytes();
    let pending_stop: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM workspace_execution_stops WHERE workspace_id = ?1)",
        params![workspace.as_slice()],
        |row| row.get(0),
    )?;
    if pending_stop {
        return Ok(Some(WorkspaceStateRemovalBlocker::PendingExecutionStop));
    }
    let open_activity: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM activities WHERE workspace_id = ?1 AND state = ?2)",
        params![
            workspace.as_slice(),
            encode_activity_state(ActivityState::Open),
        ],
        |row| row.get(0),
    )?;
    if open_activity {
        return Ok(Some(WorkspaceStateRemovalBlocker::OpenActivity));
    }
    let active_execution: bool = connection.query_row(
        "SELECT EXISTS(
                 SELECT 1 FROM executions
                 INNER JOIN activities USING(activity_id)
                 WHERE activities.workspace_id = ?1 AND executions.state IN (0, 1)
             )",
        params![workspace.as_slice()],
        |row| row.get(0),
    )?;
    if active_execution {
        return Ok(Some(WorkspaceStateRemovalBlocker::ActiveExecution));
    }
    let active_writer_lease: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM writer_leases WHERE workspace_id = ?1 AND state = 0)",
        params![workspace.as_slice()],
        |row| row.get(0),
    )?;
    if active_writer_lease {
        return Ok(Some(WorkspaceStateRemovalBlocker::ActiveWriterLease));
    }
    let maintenance_owned: bool = connection.query_row(
        "SELECT EXISTS(
                 SELECT 1 FROM recovery_maintenance
                 WHERE workspace_id = ?1 AND owner_runtime_instance_id IS NOT NULL
             )",
        params![workspace.as_slice()],
        |row| row.get(0),
    )?;
    Ok(maintenance_owned.then_some(WorkspaceStateRemovalBlocker::RecoveryMaintenanceLease))
}

impl WorkspaceStore {
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

    pub fn list_pending_goal_deletions(
        &self,
        limit: u32,
    ) -> Result<crate::GoalDeletionPendingInventory, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let transaction = self.connection.unchecked_transaction()?;
        let workspace = query_workspace_row(&transaction)?
            .ok_or(WorkspaceStoreError::WorkspaceIdentityMissing)
            .and_then(decode_workspace)?;
        let pending =
            workspace_goal_deletion::list_pending_cleanup(&transaction, workspace.id(), limit)?;
        transaction.commit()?;
        self.ensure_live_binding()?;
        Ok(pending)
    }

    pub fn get_agent_assignment(
        &self,
        id: forge_domain::AgentAssignmentId,
    ) -> Result<Option<forge_domain::RegisteredAgentAssignment>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let transaction = self.connection.unchecked_transaction()?;
        let result = workspace_agent_assignments::get(&transaction, id)?;
        let workspace = query_workspace_row(&transaction)?
            .ok_or(WorkspaceStoreError::WorkspaceIdentityMissing)
            .and_then(decode_workspace)?;
        if result
            .as_ref()
            .is_some_and(|assignment| assignment.workspace_id() != workspace.id())
        {
            return Err(crate::AgentAssignmentStoreError::WorkspaceMismatch.into());
        }
        transaction.commit()?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Observe the bounded current-work inventory for a leadership cut request.
    ///
    /// The inventory reads Forge's existing Workspace, Agent, Goal, DAG and
    /// Assignment authority. It does not create custody or alter work state.
    pub fn observe_leadership_work_inventory(
        &self,
        request: &forge_domain::WorkCutRequest,
    ) -> Result<crate::WorkCutInventory, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let inventory = crate::workspace_work_inventory::observe(&self.connection, request);
        self.ensure_live_binding()?;
        inventory.map_err(WorkspaceStoreError::from)
    }

    /// Atomically prepare an incumbent work cut using Forge's current durable
    /// inventory and effect authority.
    ///
    /// The caller must authenticate `authenticated_issuer` through its private
    /// Orchestration governance boundary. These typed values record the grant
    /// context; they do not authenticate the caller, complete reciprocal
    /// transfer, grant Workspace membership or a Writer Lease, or admit a runtime.
    pub fn prepare_leadership_work_cut(
        &mut self,
        request: &forge_domain::WorkCutRequest,
        grant: forge_domain::WorkCutGrant,
        authenticated_issuer: forge_domain::OrchestrationIssuerId,
        actual_backend: forge_domain::ForgeBackendId,
        now: TimestampMillis,
    ) -> Result<crate::WorkCutPrepareOutcome, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let outcome = workspace_work_cuts::prepare(
            &mut self.connection,
            request,
            grant,
            authenticated_issuer,
            actual_backend,
            now,
        )?;
        let cut_id = match &outcome {
            crate::WorkCutPrepareOutcome::Prepared(record)
            | crate::WorkCutPrepareOutcome::Existing(record) => record.request().cut_id(),
        };
        self.ensure_live_binding().map_err(|source| {
            WorkspaceStoreError::WorkCutReadbackRequired {
                cut_id,
                source: Box::new(source),
            }
        })?;
        Ok(outcome)
    }

    /// Read one durable work cut by its exact idempotency identity.
    pub fn get_leadership_work_cut(
        &self,
        cut_id: Uuid,
    ) -> Result<Option<crate::WorkCutRecord>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let record = workspace_work_cuts::get(&self.connection, cut_id)?;
        self.ensure_live_binding()?;
        Ok(record)
    }

    /// Persist one immutable per-assignment continuation proposal under the exact cut revision.
    ///
    /// This prepares a proposal only; it does not release custody, accept a worktree, or transfer
    /// ownership of the source Assignment.
    /// The caller must authenticate the issuer and select the actual backend before this call;
    /// supplied identities and cut digests are not authentication credentials.
    pub fn prepare_assignment_continuation(
        &mut self,
        plan: &forge_domain::AgentAssignmentContinuationPlan,
        expected_cut_revision: i64,
        authenticated_issuer: forge_domain::OrchestrationIssuerId,
        actual_backend: forge_domain::ForgeBackendId,
        now: TimestampMillis,
    ) -> Result<crate::AssignmentContinuationPrepareOutcome, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let outcome = workspace_work_cuts::prepare_continuation(
            &mut self.connection,
            plan,
            expected_cut_revision,
            authenticated_issuer,
            actual_backend,
            now,
        )?;
        self.ensure_live_binding().map_err(|source| {
            WorkspaceStoreError::AssignmentContinuationReadbackRequired {
                successor_id: plan.successor_id(),
                request_id: None,
                source: Box::new(source),
            }
        })?;
        Ok(outcome)
    }

    /// Compose and record a stable application intent in the same transaction as
    /// its exact historical replay lookup. The caller authenticates the issuer.
    pub fn prepare_assignment_continuation_intent(
        &mut self,
        intent: &crate::AssignmentContinuationIntent,
        authenticated_issuer: forge_domain::OrchestrationIssuerId,
        actual_backend: forge_domain::ForgeBackendId,
        now: TimestampMillis,
    ) -> Result<crate::AssignmentContinuationPrepareOutcome, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let outcome = workspace_work_cuts::prepare_continuation_intent(
            &mut self.connection,
            intent,
            authenticated_issuer,
            actual_backend,
            now,
        )?;
        self.ensure_live_binding().map_err(|source| {
            WorkspaceStoreError::AssignmentContinuationReadbackRequired {
                successor_id: intent.successor_id(),
                request_id: None,
                source: Box::new(source),
            }
        })?;
        Ok(outcome)
    }

    /// Read an immutable continuation proposal by its successor Assignment identity.
    pub fn get_assignment_continuation(
        &self,
        successor_id: forge_domain::AgentAssignmentId,
    ) -> Result<Option<crate::AssignmentContinuationProposal>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let proposal = workspace_work_cuts::get_continuation(&self.connection, successor_id)?;
        self.ensure_live_binding()?;
        Ok(proposal)
    }

    /// Record the recipient's same-plan acknowledgement for one continuation proposal.
    ///
    /// The receipt does not accept a worktree or complete an Assignment transfer.
    /// The caller must authenticate the recipient's Session and principal before this call.
    pub fn acknowledge_assignment_continuation(
        &mut self,
        request_id: Uuid,
        successor_id: forge_domain::AgentAssignmentId,
        expected_digest: [u8; 32],
        recipient: forge_domain::AgentAssignmentTarget,
        now: TimestampMillis,
    ) -> Result<crate::AssignmentContinuationAcknowledgeOutcome, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let outcome = workspace_work_cuts::acknowledge_continuation(
            &mut self.connection,
            request_id,
            successor_id,
            expected_digest,
            recipient,
            now,
        )?;
        self.ensure_live_binding().map_err(|source| {
            WorkspaceStoreError::AssignmentContinuationReadbackRequired {
                successor_id,
                request_id: Some(request_id),
                source: Box::new(source),
            }
        })?;
        Ok(outcome)
    }

    /// Read one durable acknowledgement by its request identity.
    pub fn get_assignment_continuation_acknowledgment(
        &self,
        request_id: Uuid,
    ) -> Result<Option<crate::AssignmentContinuationAcknowledgment>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let acknowledgment =
            workspace_work_cuts::get_continuation_acknowledgment(&self.connection, request_id)?;
        self.ensure_live_binding()?;
        Ok(acknowledgment)
    }

    /// Observe captured effect settlement in one read transaction. This does
    /// not transfer work or release custody; any later mutation must recheck.
    pub fn observe_leadership_work_cut_drain(
        &self,
        cut_id: Uuid,
        expected_revision: i64,
        observed_at: TimestampMillis,
    ) -> Result<crate::WorkCutDrainObservation, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let observation = workspace_work_cuts::observe_drain(
            &self.connection,
            cut_id,
            expected_revision,
            observed_at,
        )?;
        self.ensure_live_binding()?;
        Ok(observation)
    }

    pub fn offer_agent_assignment(
        &mut self,
        command: &forge_domain::OfferAgentAssignment,
        admitted_at: TimestampMillis,
    ) -> Result<forge_domain::RegisteredAgentAssignment, WorkspaceStoreError> {
        self.mutate_agent_assignment(|connection| {
            workspace_agent_assignments::offer(connection, command, admitted_at)
        })
    }

    /// Permanently seal one exact Activity/Assignment key as a trusted native operator.
    ///
    /// The returned snapshot observes the current global Assignment ID in the same
    /// IMMEDIATE transaction. `current_assignment == None` means `AbsentNowSealed`,
    /// not that the Assignment was never offered.
    pub fn seal_agent_assignment_offer_local(
        &mut self,
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        assignment_id: forge_domain::AgentAssignmentId,
        observed_at: TimestampMillis,
    ) -> Result<workspace_agent_assignments::AgentAssignmentOfferSealSnapshot, WorkspaceStoreError>
    {
        if self.workspace()?.id() != workspace_id {
            return Err(crate::AgentAssignmentStoreError::WorkspaceMismatch.into());
        }
        self.mutate_agent_assignment(|connection| {
            workspace_agent_assignments::seal_offer(
                connection,
                workspace_id,
                activity_id,
                assignment_id,
                None,
                observed_at,
            )
        })
    }

    /// Permanently seal one exact Activity/Assignment key under its current Coordinator.
    pub fn seal_agent_assignment_offer_authorized(
        &mut self,
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        assignment_id: forge_domain::AgentAssignmentId,
        actor: forge_domain::ActivityCoordinatorActor,
        observed_at: TimestampMillis,
    ) -> Result<workspace_agent_assignments::AgentAssignmentOfferSealSnapshot, WorkspaceStoreError>
    {
        if self.workspace()?.id() != workspace_id {
            return Err(crate::AgentAssignmentStoreError::WorkspaceMismatch.into());
        }
        self.mutate_agent_assignment(|connection| {
            workspace_agent_assignments::seal_offer(
                connection,
                workspace_id,
                activity_id,
                assignment_id,
                Some(actor),
                observed_at,
            )
        })
    }

    /// Read one exact seal. `None` means no seal row exists and proves nothing
    /// about current Assignment presence or future admission.
    pub fn get_agent_assignment_offer_seal_local(
        &self,
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        assignment_id: forge_domain::AgentAssignmentId,
    ) -> Result<
        Option<workspace_agent_assignments::AgentAssignmentOfferSealSnapshot>,
        WorkspaceStoreError,
    > {
        self.get_agent_assignment_offer_seal_with_authority(
            workspace_id,
            activity_id,
            assignment_id,
            None,
            TimestampMillis::new(0).map_err(|_| {
                WorkspaceStoreError::AgentAssignment(
                    crate::AgentAssignmentStoreError::CorruptRecord("offer_seal.read_time"),
                )
            })?,
        )
    }

    /// Read one exact seal under the current Coordinator authority.
    pub fn get_agent_assignment_offer_seal_authorized(
        &self,
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        assignment_id: forge_domain::AgentAssignmentId,
        actor: forge_domain::ActivityCoordinatorActor,
        observed_at: TimestampMillis,
    ) -> Result<
        Option<workspace_agent_assignments::AgentAssignmentOfferSealSnapshot>,
        WorkspaceStoreError,
    > {
        self.get_agent_assignment_offer_seal_with_authority(
            workspace_id,
            activity_id,
            assignment_id,
            Some(actor),
            observed_at,
        )
    }

    fn get_agent_assignment_offer_seal_with_authority(
        &self,
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        assignment_id: forge_domain::AgentAssignmentId,
        actor: Option<forge_domain::ActivityCoordinatorActor>,
        observed_at: TimestampMillis,
    ) -> Result<
        Option<workspace_agent_assignments::AgentAssignmentOfferSealSnapshot>,
        WorkspaceStoreError,
    > {
        self.ensure_live_binding()?;
        if self.workspace()?.id() != workspace_id {
            return Err(crate::AgentAssignmentStoreError::WorkspaceMismatch.into());
        }
        let result = workspace_agent_assignments::get_offer_seal(
            &self.connection,
            workspace_id,
            activity_id,
            assignment_id,
            actor,
            observed_at,
        )?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    pub fn list_agent_assignments(
        &self,
        workspace_id: WorkspaceId,
        limit: u32,
    ) -> Result<Vec<forge_domain::AgentAssignmentSummary>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let transaction = self.connection.unchecked_transaction()?;
        let workspace = query_workspace_row(&transaction)?
            .ok_or(WorkspaceStoreError::WorkspaceIdentityMissing)
            .and_then(decode_workspace)?;
        if workspace.id() != workspace_id {
            return Err(crate::AgentAssignmentStoreError::WorkspaceMismatch.into());
        }
        let result = workspace_agent_assignments::list(&transaction, workspace_id, limit)?;
        transaction.commit()?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    pub fn list_agent_assignments_for_activity(
        &self,
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        target_agent_id: Option<forge_domain::AgentInstanceId>,
        limit: u32,
    ) -> Result<Vec<forge_domain::AgentAssignmentSummary>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let transaction = self.connection.unchecked_transaction()?;
        let workspace = query_workspace_row(&transaction)?
            .ok_or(WorkspaceStoreError::WorkspaceIdentityMissing)
            .and_then(decode_workspace)?;
        if workspace.id() != workspace_id {
            return Err(crate::AgentAssignmentStoreError::WorkspaceMismatch.into());
        }
        let result = workspace_agent_assignments::list_for_activity(
            &transaction,
            workspace_id,
            activity_id,
            target_agent_id,
            limit,
        )?;
        transaction.commit()?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    pub fn claim_agent_assignment(
        &mut self,
        command: &forge_domain::ClaimAgentAssignment,
        admitted_at: TimestampMillis,
    ) -> Result<forge_domain::RegisteredAgentAssignment, WorkspaceStoreError> {
        self.mutate_agent_assignment(|connection| {
            workspace_agent_assignments::claim(connection, command, admitted_at)
        })
    }

    pub fn submit_agent_assignment(
        &mut self,
        command: &forge_domain::SubmitAgentAssignment,
        admitted_at: TimestampMillis,
    ) -> Result<forge_domain::RegisteredAgentAssignment, WorkspaceStoreError> {
        self.mutate_agent_assignment(|connection| {
            workspace_agent_assignments::submit(connection, command, admitted_at)
        })
    }

    pub fn accept_agent_assignment(
        &mut self,
        command: &forge_domain::ReviewAgentAssignment,
        admitted_at: TimestampMillis,
    ) -> Result<forge_domain::RegisteredAgentAssignment, WorkspaceStoreError> {
        self.mutate_agent_assignment(|connection| {
            workspace_agent_assignments::accept(connection, command, admitted_at)
        })
    }

    pub fn reject_agent_assignment(
        &mut self,
        command: &forge_domain::ReviewAgentAssignment,
        admitted_at: TimestampMillis,
    ) -> Result<forge_domain::RegisteredAgentAssignment, WorkspaceStoreError> {
        self.mutate_agent_assignment(|connection| {
            workspace_agent_assignments::reject(connection, command, admitted_at)
        })
    }

    pub fn cancel_agent_assignment(
        &mut self,
        command: &forge_domain::CancelAgentAssignment,
    ) -> Result<forge_domain::RegisteredAgentAssignment, WorkspaceStoreError> {
        self.mutate_agent_assignment(|connection| {
            workspace_agent_assignments::cancel(connection, command)
        })
    }

    pub fn acknowledge_agent_assignment_cancellation(
        &mut self,
        command: &forge_domain::AcknowledgeAgentAssignmentCancellation,
    ) -> Result<forge_domain::RegisteredAgentAssignment, WorkspaceStoreError> {
        self.mutate_agent_assignment(|connection| {
            workspace_agent_assignments::acknowledge_cancellation(connection, command)
        })
    }

    pub fn interrupt_agent_assignment(
        &mut self,
        command: &forge_domain::InterruptAgentAssignment,
    ) -> Result<forge_domain::RegisteredAgentAssignment, WorkspaceStoreError> {
        self.mutate_agent_assignment(|connection| {
            workspace_agent_assignments::interrupt(connection, command)
        })
    }

    fn mutate_agent_assignment<T, F>(&mut self, mutate: F) -> Result<T, WorkspaceStoreError>
    where
        F: FnOnce(&mut Connection) -> Result<T, crate::AgentAssignmentStoreError>,
    {
        self.ensure_live_binding()?;
        let result = mutate(&mut self.connection)?;
        self.capture_sidecar_identities()
            .and_then(|()| self.ensure_live_binding())
            .map_err(
                |source| WorkspaceStoreError::AgentAssignmentCommittedUnconfirmed {
                    source: Box::new(source),
                },
            )?;
        Ok(result)
    }

    /// Read the optional per-Workspace queue-capacity preference.
    ///
    /// A missing row remains `None`; reads never materialize the default.
    pub fn get_workspace_queue_settings(
        &self,
    ) -> Result<Option<RegisteredQueueSettings>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let transaction = self.connection.unchecked_transaction()?;
        let workspace = query_workspace_row(&transaction)?
            .ok_or(WorkspaceStoreError::WorkspaceIdentityMissing)
            .and_then(decode_workspace)?;
        let settings = workspace_queue_settings::get(&transaction, workspace.id())?;
        transaction.commit()?;
        self.ensure_live_binding()?;
        Ok(settings)
    }

    /// Replace the optional per-Workspace queue-capacity preference through an
    /// exact compare-and-swap revision fence. `None` inserts the first row;
    /// `Some(revision)` updates exactly that existing revision.
    pub fn replace_workspace_queue_settings(
        &mut self,
        settings: QueueSettings,
        expected_revision: Option<QueueSettingsRevision>,
        observed_at: TimestampMillis,
    ) -> Result<RegisteredQueueSettings, WorkspaceStoreError> {
        self.replace_workspace_queue_settings_with_hook(
            settings,
            expected_revision,
            observed_at,
            |_| {},
        )
    }

    fn replace_workspace_queue_settings_with_hook<F>(
        &mut self,
        settings: QueueSettings,
        expected_revision: Option<QueueSettingsRevision>,
        observed_at: TimestampMillis,
        after_commit: F,
    ) -> Result<RegisteredQueueSettings, WorkspaceStoreError>
    where
        F: FnOnce(&mut Self),
    {
        self.ensure_live_binding()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let workspace = query_workspace_row(&transaction)?
            .ok_or(WorkspaceStoreError::WorkspaceIdentityMissing)
            .and_then(decode_workspace)?;
        let registered = workspace_queue_settings::replace(
            &transaction,
            workspace.id(),
            settings,
            expected_revision,
            observed_at,
        )?;
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
        transaction.commit().map_err(|source| {
            WorkspaceStoreError::WorkspaceQueueSettingsCommittedUnconfirmed {
                source: Box::new(source.into()),
            }
        })?;
        after_commit(self);
        self.ensure_live_binding()
            .and_then(|()| self.capture_sidecar_identities())
            .and_then(|()| self.ensure_live_binding())
            .map_err(
                |source| WorkspaceStoreError::WorkspaceQueueSettingsCommittedUnconfirmed {
                    source: Box::new(source),
                },
            )?;
        Ok(registered)
    }

    /// Read only the optional queue preference from an existing Workspace
    /// state database. Historical v30/v31/v32 schemas are validated using
    /// their exact shape and return `None`; no schema migration or row insert
    /// occurs on this observational path.
    pub fn inspect_queue_settings_live_read_only(
        layout: &ExistingWorkspaceStateLayout,
    ) -> Result<Option<RegisteredQueueSettings>, WorkspaceStoreError> {
        Self::inspect_metadata_live_read_only(layout, |connection, workspace_id, shape| {
            if shape.includes_queue_settings() {
                workspace_queue_settings::get(connection, workspace_id).map_err(Into::into)
            } else {
                Ok(None)
            }
        })
    }

    /// Read the current Workspace recovery-maintenance lease without opening
    /// a write-capable connection or consulting a historical schema's missing
    /// recovery table. This operation never migrates, initializes, or writes
    /// semantic rows. With an existing WAL/SHM pair SQLite may update shared
    /// memory read marks; source identities remain fenced. A missing pair uses
    /// the immutable no-sidecar path.
    pub fn inspect_recovery_maintenance_lease_live_read_only(
        layout: &ExistingWorkspaceStateLayout,
    ) -> Result<RecoveryMaintenanceLease, WorkspaceStoreError> {
        Self::inspect_metadata_live_read_only_with_recovery(
            layout,
            false,
            |connection, workspace_id, shape| {
                if shape != WorkspaceSchemaShape::Current {
                    return Err(WorkspaceStoreError::OutdatedSchema {
                        actual: shape.version(),
                        current: CURRENT_SCHEMA_VERSION,
                    });
                }
                workspace_recovery::get(connection, workspace_id).map_err(Into::into)
            },
        )
    }

    /// Discover unfinished cleanup without migration, inserts, or sidecar creation.
    pub fn inspect_pending_goal_deletions_live_read_only(
        layout: &ExistingWorkspaceStateLayout,
        limit: u32,
    ) -> Result<crate::GoalDeletionPendingInventory, WorkspaceStoreError> {
        if !(1..=32).contains(&limit) {
            return Err(
                workspace_goal_deletion::GoalDeletionStoreError::PendingCleanupLimitInvalid {
                    actual: limit,
                    maximum: 32,
                }
                .into(),
            );
        }
        Self::inspect_metadata_live_read_only(layout, |connection, workspace_id, shape| {
            if shape.includes_assignments_and_deletion() {
                workspace_goal_deletion::list_pending_cleanup(connection, workspace_id, limit)
                    .map_err(Into::into)
            } else {
                Ok(crate::GoalDeletionPendingInventory::default())
            }
        })
    }

    fn inspect_metadata_live_read_only<T, F>(
        layout: &ExistingWorkspaceStateLayout,
        read: F,
    ) -> Result<T, WorkspaceStoreError>
    where
        F: Fn(&Connection, WorkspaceId, WorkspaceSchemaShape) -> Result<T, WorkspaceStoreError>,
    {
        Self::inspect_metadata_live_read_only_with_recovery(layout, true, read)
    }

    fn inspect_metadata_live_read_only_with_recovery<T, F>(
        layout: &ExistingWorkspaceStateLayout,
        validate_recovery_lease: bool,
        read: F,
    ) -> Result<T, WorkspaceStoreError>
    where
        F: Fn(&Connection, WorkspaceId, WorkspaceSchemaShape) -> Result<T, WorkspaceStoreError>,
    {
        let root_fingerprint = layout
            .root_fingerprint()
            .map_err(|source| WorkspaceStoreError::LayoutFingerprintObservation { source })?;
        let _state_gate =
            WorkspaceStateSharedGate::acquire(layout.workspace_root(), root_fingerprint)
                .map_err(WorkspaceStoreError::StateGate)?;
        let database_path = layout.database_path();
        let mut last_retryable = None;
        for _ in 0..LIVE_IDENTITY_RETRY_LIMIT {
            match Self::inspect_metadata_live_read_only_once(layout, validate_recovery_lease, &read)
            {
                Ok(settings) => return Ok(settings),
                Err(error) if is_retryable_live_identity_error(&error, &database_path) => {
                    last_retryable = Some(error);
                }
                Err(error) => return Err(error),
            }
        }
        Err(
            last_retryable.unwrap_or_else(|| WorkspaceStoreError::DatabasePathInvariant {
                path: database_path,
                detail: "live metadata retry budget was unexpectedly empty",
            }),
        )
    }

    fn inspect_metadata_live_read_only_once<T, F>(
        layout: &ExistingWorkspaceStateLayout,
        validate_recovery_lease: bool,
        read: &F,
    ) -> Result<T, WorkspaceStoreError>
    where
        F: Fn(&Connection, WorkspaceId, WorkspaceSchemaShape) -> Result<T, WorkspaceStoreError>,
    {
        let database = ReadOnlyDoctorDatabase::open_live(layout)?;
        database.ensure_live_observation()?;
        let transaction = database.connection.unchecked_transaction()?;

        let ownership = match inspect_database(&transaction) {
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
        let shape = read_only_schema_shape(ownership)?;

        validate_schema_shape_for_version(&transaction, shape)?;
        let workspace = query_workspace_row(&transaction)?
            .ok_or(WorkspaceStoreError::WorkspaceIdentityMissing)
            .and_then(decode_workspace)?;
        validate_existing_workspace_binding(&workspace, layout, database.root_fingerprint)?;
        if validate_recovery_lease {
            let _recovery_lease = workspace_recovery::get(&transaction, workspace.id())?;
        }
        let settings = read(&transaction, workspace.id(), shape)?;
        database.ensure_live_observation()?;
        transaction.commit()?;
        database.ensure_live_observation()?;
        Ok(settings)
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
        self.claim_recovery_maintenance_lease_with_hook(command, |_| {})
    }

    /// Claim the Workspace recovery-maintenance lease with a runtime-owned
    /// observation sampled after the IMMEDIATE transaction has acquired its
    /// SQLite writer lock and immediately before the durable decision.
    ///
    /// The caller supplies only the bounded lease duration and identity.  The
    /// clock callback is deliberately typed as a Workspace-store result so a
    /// failed observation remains part of the persistence error provenance.
    /// It must be a bounded time-only observation; filesystem and network work
    /// do not belong inside the transaction callback.
    pub fn claim_recovery_maintenance_lease_with_clock<F>(
        &mut self,
        workspace_id: WorkspaceId,
        owner_id: RuntimeInstanceId,
        duration: RecoveryLeaseDurationMillis,
        clock: F,
    ) -> Result<crate::RecoveryLeaseClaimResult, WorkspaceStoreError>
    where
        F: FnOnce() -> Result<TimestampMillis, WorkspaceStoreError>,
    {
        self.claim_recovery_maintenance_lease_with_builder(
            move || {
                let observed_at = clock().map_err(|source| {
                    WorkspaceStoreError::RecoveryLeaseClockObservation {
                        source: Box::new(source),
                    }
                })?;
                ClaimRecoveryLease::new(workspace_id, owner_id, duration, observed_at).map_err(
                    |source| WorkspaceStoreError::RecoveryLeaseClockObservation {
                        source: Box::new(source),
                    },
                )
            },
            |_| {},
        )
    }

    fn claim_recovery_maintenance_lease_with_hook<C, F>(
        &mut self,
        command: C,
        after_commit: F,
    ) -> Result<crate::RecoveryLeaseClaimResult, WorkspaceStoreError>
    where
        C: Borrow<ClaimRecoveryLease>,
        F: FnOnce(&mut Self),
    {
        let command = *command.borrow();
        self.claim_recovery_maintenance_lease_with_builder(|| Ok(command), after_commit)
    }

    fn claim_recovery_maintenance_lease_with_builder<B, F>(
        &mut self,
        build_command: B,
        after_commit: F,
    ) -> Result<crate::RecoveryLeaseClaimResult, WorkspaceStoreError>
    where
        B: FnOnce() -> Result<ClaimRecoveryLease, WorkspaceStoreError>,
        F: FnOnce(&mut Self),
    {
        self.ensure_live_binding()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let command = build_command()?;
        let result = workspace_recovery::claim(&transaction, &command)?;
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
        transaction.commit().map_err(|source| {
            if result.is_acquired() {
                WorkspaceStoreError::RecoveryMaintenanceLeaseCommittedUnconfirmed {
                    source: Box::new(source.into()),
                }
            } else {
                WorkspaceStoreError::Sqlite(source)
            }
        })?;
        after_commit(self);
        if result.is_acquired() {
            self.confirm_recovery_maintenance_lease_commit()?;
        } else {
            self.ensure_live_binding()?;
            self.capture_sidecar_identities()?;
            self.ensure_live_binding()?;
        }
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
        self.renew_recovery_maintenance_lease_with_hook(command, |_| {})
    }

    fn renew_recovery_maintenance_lease_with_hook<C, F>(
        &mut self,
        command: C,
        after_commit: F,
    ) -> Result<RecoveryMaintenanceLease, WorkspaceStoreError>
    where
        C: Borrow<RenewRecoveryLease>,
        F: FnOnce(&mut Self),
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
        transaction.commit().map_err(|source| {
            WorkspaceStoreError::RecoveryMaintenanceLeaseCommittedUnconfirmed {
                source: Box::new(source.into()),
            }
        })?;
        after_commit(self);
        self.confirm_recovery_maintenance_lease_commit()?;
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
        self.release_recovery_maintenance_lease_with_hook(command, |_| {})
    }

    fn release_recovery_maintenance_lease_with_hook<C, F>(
        &mut self,
        command: C,
        after_commit: F,
    ) -> Result<RecoveryMaintenanceLease, WorkspaceStoreError>
    where
        C: Borrow<ReleaseRecoveryLease>,
        F: FnOnce(&mut Self),
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
        transaction.commit().map_err(|source| {
            WorkspaceStoreError::RecoveryMaintenanceLeaseCommittedUnconfirmed {
                source: Box::new(source.into()),
            }
        })?;
        after_commit(self);
        self.confirm_recovery_maintenance_lease_commit()?;
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

        insert_open_activity(
            &transaction,
            &workspace,
            command.id(),
            command.observed_at(),
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

    /// Atomically create one fresh successor Activity and its immutable
    /// predecessor relation. Retries with the same predecessor and successor
    /// replay the durable relation and current successor projection.
    pub fn create_activity_successor(
        &mut self,
        command: &forge_domain::CreateActivitySuccessor,
    ) -> Result<forge_domain::ActivitySuccessorResult, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let workspace = query_workspace_row(&transaction)?
            .ok_or(WorkspaceStoreError::WorkspaceIdentityMissing)
            .and_then(decode_workspace)?;
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
        let predecessor =
            validate_activity_successor_predecessor(&transaction, &workspace, command)?;
        if let Some((relation, successor)) =
            replay_activity_successor(&transaction, &workspace, &predecessor, command)?
        {
            transaction.commit()?;
            self.ensure_live_binding()?;
            self.capture_sidecar_identities()?;
            self.ensure_live_binding()?;
            return Ok(forge_domain::ActivitySuccessorResult::new(
                relation, successor, false,
            ));
        }
        let (persisted, successor) = create_activity_successor_in_transaction(
            &transaction,
            &workspace,
            &predecessor,
            command,
        )?;
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
        Ok(forge_domain::ActivitySuccessorResult::new(
            persisted, successor, true,
        ))
    }

    /// Read one immutable Activity successor relation and its current successor
    /// projection from one `SQLite` snapshot. This is the durable readback path
    /// for unknown admission outcomes.
    pub fn get_activity_successor(
        &self,
        predecessor_activity_id: ActivityId,
    ) -> Result<Option<(ActivitySuccessor, RegisteredActivity)>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let transaction = self.connection.unchecked_transaction()?;
        let workspace = query_workspace_row(&transaction)?
            .ok_or(WorkspaceStoreError::WorkspaceIdentityMissing)
            .and_then(decode_workspace)?;
        let predecessor_raw = query_activity_row(&transaction, predecessor_activity_id)?.ok_or(
            WorkspaceStoreError::ActivityNotFound(predecessor_activity_id),
        )?;
        let predecessor = decode_activity(&predecessor_raw)?;
        validate_activity_workspace(&predecessor, workspace.id())?;
        let Some(relation) = workspace_activity_successors::get_by_predecessor(
            &transaction,
            predecessor_activity_id,
        )?
        else {
            transaction.commit()?;
            return Ok(None);
        };
        if relation.workspace_id() != workspace.id()
            || relation.predecessor_activity_id() != predecessor.id()
            || relation.predecessor_activity_revision() != predecessor.revision()
            || relation.created_at().get() < predecessor.updated_at().get()
        {
            return Err(WorkspaceStoreError::ActivitySuccessorCorrupt(
                predecessor_activity_id,
            ));
        }
        let successor_raw = query_activity_row(&transaction, relation.successor_activity_id())?
            .ok_or(WorkspaceStoreError::ActivityNotFound(
                relation.successor_activity_id(),
            ))?;
        let successor = decode_activity(&successor_raw)?;
        validate_activity_workspace(&successor, workspace.id())?;
        if successor.id() != relation.successor_activity_id()
            || successor.created_at() != relation.created_at()
        {
            return Err(WorkspaceStoreError::ActivitySuccessorCorrupt(
                predecessor_activity_id,
            ));
        }
        transaction.commit()?;
        self.ensure_live_binding()?;
        Ok(Some((relation, successor)))
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

    /// Read one bounded typed page while the exact source migration remains frozen.
    /// No destination transaction or external effect is held across this read.
    pub fn export_agent_operations(
        &self,
        migration_id: Uuid,
        cursor: crate::AgentOperationsExportCursor,
    ) -> Result<crate::AgentOperationsExportPage, WorkspaceStoreError> {
        let workspace = self.workspace()?.id();
        workspace_agent_migration::ensure_not_delegated(&self.connection)?;
        let page =
            workspace_agent_migration::export::export(&self.connection, migration_id, cursor)?;
        if page.workspace_id() != workspace {
            return Err(crate::AgentOperationsExportError::WorkspaceMismatch {
                expected: workspace,
                actual: page.workspace_id(),
            }
            .into());
        }
        self.ensure_live_binding()?;
        Ok(page)
    }

    /// Reserve only an effect identity; no active Agent or operational rows are created.
    pub fn reserve_agent_binding(
        &mut self,
        freeze: &crate::AgentOperationsFreeze,
        request: &crate::AgentBindingReservationRequest,
        observed_at: TimestampMillis,
    ) -> Result<crate::AgentBindingReservation, WorkspaceStoreError> {
        let workspace = self.workspace()?.id();
        if freeze.workspace_id() != workspace {
            return Err(crate::AgentOperationsMigrationError::WorkspaceMismatch {
                expected: workspace,
                actual: freeze.workspace_id(),
            }
            .into());
        }
        let result = workspace_agent_binding_reservations::reserve(
            &mut self.connection,
            freeze,
            request,
            observed_at,
        )
        .map_err(|error| {
            let unknown = matches!(
                error,
                crate::AgentBindingReservationError::CommitUnconfirmed { .. }
            );
            let source = WorkspaceStoreError::AgentBindingReservation(error);
            if unknown {
                WorkspaceStoreError::AgentBindingReservationCommittedUnconfirmed {
                    request_id: request.request_id(),
                    source: Box::new(source),
                }
            } else {
                source
            }
        })?;
        self.capture_sidecar_identities()
            .and_then(|()| self.ensure_live_binding())
            .map_err(
                |source| WorkspaceStoreError::AgentBindingReservationCommittedUnconfirmed {
                    request_id: request.request_id(),
                    source: Box::new(source),
                },
            )?;
        Ok(result)
    }

    /// Read the exact reserved identity after an uncertain response. This grants no effect authority.
    pub fn agent_binding_reservation(
        &self,
        request_id: Uuid,
    ) -> Result<Option<crate::AgentBindingReservation>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_agent_binding_reservations::get(&self.connection, request_id)?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Seal the current frozen source migration to the exact verified
    /// destination manifest supplied by trusted Orchestration composition.
    pub fn delegate_agent_operations(
        &mut self,
        freeze: &crate::AgentOperationsFreeze,
        manifest_digest: [u8; 32],
        delegated_at: TimestampMillis,
    ) -> Result<crate::AgentOperationsDelegation, WorkspaceStoreError> {
        let workspace = self.workspace()?.id();
        if freeze.workspace_id() != workspace {
            return Err(crate::AgentOperationsDelegationError::WorkspaceMismatch {
                expected: workspace,
                actual: freeze.workspace_id(),
            }
            .into());
        }
        let result = workspace_agent_delegation::delegate(
            &mut self.connection,
            workspace,
            freeze,
            manifest_digest,
            delegated_at,
        )
        .map_err(|error| {
            let uncertain = matches!(
                error,
                crate::AgentOperationsDelegationError::CommitUnconfirmed { .. }
            );
            let source = WorkspaceStoreError::AgentOperationsDelegation(error);
            if uncertain {
                WorkspaceStoreError::AgentOperationsDelegationCommittedUnconfirmed {
                    migration_id: freeze.migration_id(),
                    source: Box::new(source),
                }
            } else {
                source
            }
        })?;
        self.capture_sidecar_identities()
            .and_then(|()| self.ensure_live_binding())
            .map_err(|source| {
                WorkspaceStoreError::AgentOperationsDelegationCommittedUnconfirmed {
                    migration_id: freeze.migration_id(),
                    source: Box::new(source),
                }
            })?;
        Ok(result)
    }

    /// Read the immutable source delegation seal for this Workspace.
    pub fn agent_operations_delegation(
        &self,
    ) -> Result<Option<crate::AgentOperationsDelegation>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let workspace = self.workspace()?.id();
        let result = workspace_agent_delegation::get(&self.connection, workspace)?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Activate one reserved binding through the trusted Orchestration
    /// composition boundary. The activation receipt and Agent insert commit
    /// together with an initial work-focus fact. This emits no presence,
    /// membership event, or inbox state.
    pub fn activate_agent_binding(
        &mut self,
        delegation: &crate::AgentOperationsDelegation,
        request: &crate::AgentBindingActivationRequest,
        activated_at: TimestampMillis,
    ) -> Result<crate::AgentBindingActivation, WorkspaceStoreError> {
        let workspace = self.workspace()?.id();
        if delegation.workspace_id() != workspace {
            return Err(crate::AgentOperationsDelegationError::WorkspaceMismatch {
                expected: workspace,
                actual: delegation.workspace_id(),
            }
            .into());
        }
        let result = workspace_agent_binding_activation::activate(
            &mut self.connection,
            delegation,
            request,
            activated_at,
        )
        .map_err(|error| {
            let uncertain = matches!(
                error,
                crate::AgentBindingActivationError::CommitUnconfirmed { .. }
            );
            let source = WorkspaceStoreError::AgentBindingActivation(error);
            if uncertain {
                WorkspaceStoreError::AgentBindingActivationCommittedUnconfirmed {
                    request_id: request.request_id(),
                    source: Box::new(source),
                }
            } else {
                source
            }
        })?;
        self.capture_sidecar_identities()
            .and_then(|()| self.ensure_live_binding())
            .map_err(
                |source| WorkspaceStoreError::AgentBindingActivationCommittedUnconfirmed {
                    request_id: request.request_id(),
                    source: Box::new(source),
                },
            )?;
        Ok(result)
    }

    /// Read one immutable binding activation receipt.
    pub fn agent_binding_activation(
        &self,
        request_id: Uuid,
    ) -> Result<Option<crate::AgentBindingActivation>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_agent_binding_activation::get(&self.connection, request_id)?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Settle one exact invalid reserved binding without creating an Agent or
    /// activation effect. The rejection receipt is immutable and replayable.
    pub fn reject_agent_binding(
        &mut self,
        binding: &WorkspaceJournalBinding,
        request: &crate::AgentBindingRejectionStoreRequest,
    ) -> Result<crate::AgentBindingRejectionOperation, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        if binding.workspace_id() != request.request.workspace_id()
            || binding.recovery_history_digest() != request.request.binding_digest()
        {
            return Err(WorkspaceStoreError::AgentBindingRejection(
                crate::AgentBindingRejectionStoreError::Conflict("Workspace binding"),
            ));
        }
        let result = workspace_agent_binding_rejections::reject(&mut self.connection, request)
            .map_err(|error| {
                if matches!(
                    error,
                    crate::AgentBindingRejectionStoreError::CommitUnconfirmed(_)
                ) {
                    WorkspaceStoreError::AgentBindingRejectionCommittedUnconfirmed {
                        request_id: request.request.request_id(),
                        source: Box::new(WorkspaceStoreError::AgentBindingRejection(error)),
                    }
                } else {
                    WorkspaceStoreError::AgentBindingRejection(error)
                }
            })?;
        self.capture_sidecar_identities()
            .and_then(|()| self.ensure_live_binding())
            .map_err(
                |source| WorkspaceStoreError::AgentBindingRejectionCommittedUnconfirmed {
                    request_id: request.request.request_id(),
                    source: Box::new(source),
                },
            )?;
        Ok(result)
    }

    /// Read one immutable rejection receipt without resolving a fresh Session.
    pub fn agent_binding_rejection(
        &self,
        request_id: Uuid,
    ) -> Result<Option<crate::AgentBindingRejectionReceipt>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_agent_binding_rejections::get(&self.connection, request_id)?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Reconcile the Forge-owned effect-session identity for one imported legacy
    /// Agent after operations were delegated to Orchestration. This transition
    /// never writes presence, membership events, inbox receipts, or public role
    /// metadata.
    pub fn reconcile_agent_session(
        &mut self,
        delegation: &crate::AgentOperationsDelegation,
        request: crate::AgentSessionReconciliationRequest,
    ) -> Result<crate::AgentSessionReconciliation, WorkspaceStoreError> {
        let workspace = self.workspace()?.id();
        if delegation.workspace_id() != workspace {
            return Err(crate::AgentSessionReconciliationError::WorkspaceMismatch.into());
        }
        let request_id = request.request_id();
        let result = workspace_agent_session_reconciliation::reconcile(
            &mut self.connection,
            delegation,
            request,
        )
        .map_err(|error| {
            let uncertain = matches!(
                error,
                crate::AgentSessionReconciliationError::CommitUnconfirmed { .. }
            );
            let source = WorkspaceStoreError::AgentSessionReconciliation(error);
            if uncertain {
                WorkspaceStoreError::AgentSessionReconciliationReadbackRequired {
                    request_id,
                    source: Box::new(source),
                }
            } else {
                source
            }
        })?;
        self.capture_sidecar_identities()
            .and_then(|()| self.ensure_live_binding())
            .map_err(
                |source| WorkspaceStoreError::AgentSessionReconciliationReadbackRequired {
                    request_id,
                    source: Box::new(source),
                },
            )?;
        Ok(result)
    }

    /// Read one immutable legacy effect-session reconciliation receipt.
    pub fn agent_session_reconciliation(
        &self,
        request_id: Uuid,
    ) -> Result<Option<crate::AgentSessionReconciliation>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_agent_session_reconciliation::get(&self.connection, request_id)?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Read one bounded page of immutable delegated source work facts for this
    /// Workspace. The cursor is the last observed outbox sequence.
    pub fn agent_effect_outbox(
        &self,
        after: i64,
        limit: usize,
    ) -> Result<Vec<crate::AgentEffectOutboxEntry>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let workspace = self.workspace()?.id();
        let result =
            workspace_agent_effect_outbox::read(&self.connection, workspace, after, limit)?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Read one bounded page of immutable Forge-owned effect facts for cross-service
    /// projection. The cursor is the last observed monotonically increasing sequence.
    pub fn effect_fact_outbox(
        &self,
        after: u64,
        limit: u32,
    ) -> Result<Vec<crate::EffectFactOutboxEntry>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let workspace_id = self.workspace()?.id();
        let result =
            workspace_effect_fact_outbox::read(&self.connection, workspace_id, after, limit)?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Read one bounded page of the durable semantic event stream. The cursor
    /// is the last observed monotonically increasing sequence; the result also
    /// exposes the durable high-water and retention-floor cursors. Pure read.
    pub fn semantic_events_page(
        &self,
        workspace_id: WorkspaceId,
        after: u64,
        limit: u32,
    ) -> Result<crate::SemanticEventPage, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let bound_workspace = self.workspace()?.id();
        if bound_workspace != workspace_id {
            return Err(WorkspaceStoreError::SemanticEventsWorkspaceMismatch {
                expected: bound_workspace,
                actual: workspace_id,
            });
        }
        let result = workspace_semantic_events::semantic_events_after(
            &self.connection,
            workspace_id,
            after,
            limit,
        )?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Read one consistent Workspace snapshot: the durable semantic cursor
    /// pair plus a bounded Goal/DAG current-state summary, composed inside a
    /// single read transaction. Pure read; never mutates state.
    pub fn semantic_snapshot(
        &self,
        goal_limit: u32,
    ) -> Result<crate::WorkspaceSemanticSnapshot, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let workspace_id = self.workspace()?.id();
        let result = workspace_semantic_events::workspace_semantic_snapshot(
            &self.connection,
            workspace_id,
            goal_limit,
        )?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Read the durable source-freeze operation after a retry or uncertain commit.
    pub fn agent_operations_freeze(
        &self,
        migration_id: Uuid,
    ) -> Result<Option<crate::AgentOperationsFreeze>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_agent_migration::get(&self.connection, migration_id)?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Prepare the source side of an operational-state migration. This does not
    /// activate a destination or revoke accepted effects and their evidence.
    pub fn freeze_agent_operations(
        &mut self,
        request: &crate::AgentOperationsFreezeRequest,
    ) -> Result<crate::AgentOperationsFreeze, WorkspaceStoreError> {
        let workspace_id = self.workspace()?.id();
        let result = workspace_agent_migration::freeze(&mut self.connection, workspace_id, request)
            .map_err(map_agent_operations_migration_error)?;
        self.capture_sidecar_identities()
            .and_then(|()| self.ensure_live_binding())
            .map_err(|source| {
                WorkspaceStoreError::AgentOperationsMigrationCommittedUnconfirmed {
                    source: Box::new(source),
                }
            })?;
        Ok(result)
    }

    /// Release a source preparation before destination activation exists. Exact
    /// operation/revision read-back resolves retries without creating another freeze.
    pub fn release_agent_operations_freeze(
        &mut self,
        migration_id: Uuid,
        expected_revision: u64,
        observed_at: TimestampMillis,
    ) -> Result<crate::AgentOperationsFreeze, WorkspaceStoreError> {
        let workspace_id = self.workspace()?.id();
        let result = workspace_agent_migration::release(
            &mut self.connection,
            workspace_id,
            migration_id,
            expected_revision,
            observed_at,
        )
        .map_err(map_agent_operations_migration_error)?;
        self.capture_sidecar_identities()
            .and_then(|()| self.ensure_live_binding())
            .map_err(|source| {
                WorkspaceStoreError::AgentOperationsMigrationCommittedUnconfirmed {
                    source: Box::new(source),
                }
            })?;
        Ok(result)
    }

    /// Read bounded immutable participation events for one exact Activity.
    pub fn list_agent_events(
        &self,
        activity_id: forge_domain::ActivityId,
        limit: forge_domain::AgentEventListLimit,
    ) -> Result<Vec<forge_domain::AgentEvent>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let workspace = self.workspace()?;
        let result = workspace_agent_events::list_events(
            &self.connection,
            workspace.id(),
            activity_id,
            limit,
        )?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Read bounded inbox receipts for one exact Agent/session. This read is
    /// observational and never acknowledges a receipt.
    pub fn list_agent_inbox(
        &self,
        agent_id: forge_domain::AgentInstanceId,
        session_id: forge_domain::AgentSessionId,
        limit: forge_domain::AgentInboxListLimit,
    ) -> Result<Vec<forge_domain::InboxEntry>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let workspace = self.workspace()?;
        let result = workspace_agent_events::list_inbox(
            &self.connection,
            workspace.id(),
            agent_id,
            session_id,
            limit.get(),
        )?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Read one atomic bounded Activity participant/presence aggregate. The
    /// returned page is capped independently from the truthful participant and
    /// unread counts.
    pub fn list_agent_presence(
        &self,
        activity_id: forge_domain::ActivityId,
    ) -> Result<forge_domain::ActivityPresenceSnapshot, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let workspace = self.workspace()?;
        let result =
            workspace_agent_events::list_presence(&self.connection, workspace.id(), activity_id)?;
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

    /// Read one durable Writer Lease by identity.
    pub fn get_writer_lease(
        &self,
        lease_id: forge_domain::WriterLeaseId,
    ) -> Result<Option<forge_domain::WriterLease>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_writer_leases::get(&self.connection, lease_id)?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// List every unreleased Writer Lease for this exact Workspace.
    /// Expired leases remain present because expiry alone never transfers source authority.
    pub fn list_active_writer_leases(
        &self,
    ) -> Result<Vec<forge_domain::WriterLease>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let workspace = self.workspace()?;
        let result = workspace_writer_leases::list_active(&self.connection, workspace.id())?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Read one deterministic bounded page of unreleased Writer Leases.
    pub fn list_active_writer_leases_page(
        &self,
        cursor: Option<forge_domain::WriterLeaseId>,
        limit: usize,
    ) -> Result<
        (
            Vec<forge_domain::WriterLease>,
            Option<forge_domain::WriterLeaseId>,
        ),
        WorkspaceStoreError,
    > {
        self.ensure_live_binding()?;
        let workspace = self.workspace()?;
        let result = workspace_writer_leases::list_active_page(
            &self.connection,
            workspace.id(),
            cursor,
            limit,
        )?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Acquire one path-scoped Writer Lease after exact Open Activity and Agent
    /// attachment checks. Durable Writer Lease authority is session/Agent
    /// based and does not compare it to the Activity heartbeat owner.
    pub fn acquire_writer_lease(
        &mut self,
        command: &forge_domain::AcquireWriterLease,
    ) -> Result<forge_domain::WriterLease, WorkspaceStoreError> {
        self.acquire_writer_lease_with_hook(command, |_| {})
    }

    fn acquire_writer_lease_with_hook<F>(
        &mut self,
        command: &forge_domain::AcquireWriterLease,
        after_commit: F,
    ) -> Result<forge_domain::WriterLease, WorkspaceStoreError>
    where
        F: FnOnce(&mut Self),
    {
        self.ensure_live_binding()?;
        let workspace = self.workspace()?;
        if command.workspace_id() != workspace.id() {
            return Err(WriterLeaseStoreError::WorkspaceMismatch.into());
        }
        let result = workspace_writer_leases::acquire(&mut self.connection, command)?;
        after_commit(self);
        self.confirm_writer_lease_commit()?;
        Ok(result)
    }

    /// Renew an existing Writer Lease through exact Agent/session and revision
    /// fencing.
    pub fn renew_writer_lease(
        &mut self,
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        command: forge_domain::RenewWriterLease,
    ) -> Result<forge_domain::WriterLease, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let workspace = self.workspace()?;
        if workspace_id != workspace.id() {
            return Err(WriterLeaseStoreError::WorkspaceMismatch.into());
        }
        let result = workspace_writer_leases::renew(
            &mut self.connection,
            command,
            workspace_id,
            activity_id,
        )?;
        self.confirm_writer_lease_commit()?;
        Ok(result)
    }

    /// Release one live Writer Lease through exact Agent/session and revision
    /// fencing.
    pub fn release_writer_lease(
        &mut self,
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        command: forge_domain::ReleaseWriterLease,
    ) -> Result<forge_domain::WriterLease, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let workspace = self.workspace()?;
        if workspace_id != workspace.id() {
            return Err(WriterLeaseStoreError::WorkspaceMismatch.into());
        }
        let result = workspace_writer_leases::release(
            &mut self.connection,
            command,
            workspace_id,
            activity_id,
        )?;
        self.confirm_writer_lease_commit()?;
        Ok(result)
    }

    /// Explicit recovery-only release for an expired/orphaned Writer Lease.
    /// This bypasses normal Agent/Activity liveness but preserves exact lease revision CAS.
    pub fn release_writer_lease_for_recovery(
        &mut self,
        lease_id: forge_domain::WriterLeaseId,
        expected_revision: forge_domain::WriterLeaseRevision,
        observed_at: TimestampMillis,
    ) -> Result<forge_domain::WriterLease, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_writer_leases::release_for_recovery(
            &mut self.connection,
            lease_id,
            expected_revision,
            observed_at,
        )?;
        self.confirm_writer_lease_commit()?;
        Ok(result)
    }

    fn confirm_writer_lease_commit(&mut self) -> Result<(), WorkspaceStoreError> {
        self.capture_sidecar_identities()
            .and_then(|()| self.ensure_live_binding())
            .map_err(
                |source| WorkspaceStoreError::WriterLeaseCommittedUnconfirmed {
                    source: Box::new(source),
                },
            )
    }

    fn confirm_recovery_maintenance_lease_commit(&mut self) -> Result<(), WorkspaceStoreError> {
        self.ensure_live_binding()
            .and_then(|()| self.capture_sidecar_identities())
            .and_then(|()| self.ensure_live_binding())
            .map_err(
                |source| WorkspaceStoreError::RecoveryMaintenanceLeaseCommittedUnconfirmed {
                    source: Box::new(source),
                },
            )
    }

    /// Read the current durable planning Coordinator for one Activity.
    pub fn get_activity_coordinator(
        &self,
        activity_id: forge_domain::ActivityId,
    ) -> Result<Option<forge_domain::ActivityCoordinatorBinding>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_coordinators::get(&self.connection, activity_id)?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Claim planning authority for an Activity that has no Coordinator yet.
    pub fn claim_activity_coordinator(
        &mut self,
        command: forge_domain::ClaimActivityCoordinator,
        admitted_at: TimestampMillis,
    ) -> Result<forge_domain::ActivityCoordinatorBinding, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_coordinators::claim(&mut self.connection, command, admitted_at)?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Transfer planning authority through the current Coordinator revision fence.
    pub fn transfer_activity_coordinator(
        &mut self,
        command: forge_domain::TransferActivityCoordinator,
        admitted_at: TimestampMillis,
    ) -> Result<forge_domain::ActivityCoordinatorBinding, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_coordinators::transfer(&mut self.connection, command, admitted_at)?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Read the exact local-owner recovery fence without changing authority.
    pub fn coordinator_recovery_preview(
        &self,
        activity_id: ActivityId,
        target_agent_id: forge_domain::AgentInstanceId,
    ) -> Result<forge_domain::CoordinatorRecoveryFence, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_coordinator_recovery::preview(
            &self.connection,
            self.workspace()?.id(),
            activity_id,
            target_agent_id,
        )?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Native local-owner operation; external HTTP must not expose this path.
    pub fn confirm_local_coordinator_recovery(
        &mut self,
        request: &forge_domain::ConfirmedCoordinatorRecovery,
    ) -> Result<forge_domain::CoordinatorRecoveryReceipt, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        if request.fence().binding().workspace_id() != self.workspace()?.id() {
            return Err(crate::CoordinatorRecoveryStoreError::Domain(
                forge_domain::CoordinatorRecoveryError::ScopeMismatch,
            )
            .into());
        }
        let recovery_id = request.id();
        let result = workspace_coordinator_recovery::recover(&mut self.connection, request)
            .map_err(|error| {
                let uncertain = matches!(
                    error,
                    crate::CoordinatorRecoveryStoreError::CommitUnconfirmed { .. }
                );
                let source = WorkspaceStoreError::CoordinatorRecovery(error);
                if uncertain {
                    WorkspaceStoreError::CoordinatorRecoveryReadbackRequired {
                        recovery_id,
                        source: Box::new(source),
                    }
                } else {
                    source
                }
            })?;
        self.capture_sidecar_identities()
            .and_then(|()| self.ensure_live_binding())
            .map_err(
                |source| WorkspaceStoreError::CoordinatorRecoveryReadbackRequired {
                    recovery_id,
                    source: Box::new(source),
                },
            )?;
        Ok(result)
    }

    /// Read one immutable local-owner receipt after an uncertain response.
    pub fn coordinator_recovery_receipt(
        &self,
        recovery_id: Uuid,
    ) -> Result<Option<forge_domain::CoordinatorRecoveryReceipt>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let workspace_id = self.workspace()?.id();
        let result = workspace_coordinator_recovery::get(&self.connection, recovery_id)?;
        if result.as_ref().is_some_and(|receipt| {
            receipt.request().fence().binding().workspace_id() != workspace_id
        }) {
            return Err(crate::CoordinatorRecoveryStoreError::Domain(
                forge_domain::CoordinatorRecoveryError::ScopeMismatch,
            )
            .into());
        }
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Bounded immutable audit history, including previous Coordinator epochs.
    pub fn coordinator_recovery_history(
        &self,
        activity_id: ActivityId,
        limit: u32,
    ) -> Result<Vec<forge_domain::CoordinatorRecoveryReceipt>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_coordinator_recovery::list(
            &self.connection,
            self.workspace()?.id(),
            activity_id,
            limit,
        )?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Reconcile one Agent departure (detach or Coordinator handoff) after
    /// operations were delegated to Orchestration. The transaction writes only
    /// the effect/planning-plane facts the departure needs plus its immutable
    /// journal receipt; Left/Handoff participation events, presence, inbox
    /// receipts, and effect-outbox rows are never written here.
    pub fn reconcile_agent_departure(
        &mut self,
        delegation: &crate::AgentOperationsDelegation,
        request: &crate::AgentDepartureReconciliationRequest,
        admitted_at: TimestampMillis,
    ) -> Result<crate::AgentDepartureReconciliation, WorkspaceStoreError> {
        let workspace = self.workspace()?.id();
        if delegation.workspace_id() != workspace {
            return Err(crate::AgentDepartureReconciliationError::WorkspaceMismatch.into());
        }
        let request_id = request.request_id();
        let result = match request.command() {
            crate::AgentDepartureCommand::Detach(_) => {
                workspace_agent_departure_reconciliation::reconcile_detach(
                    &mut self.connection,
                    delegation,
                    request,
                )
            }
            crate::AgentDepartureCommand::Handoff(_) => {
                workspace_agent_departure_reconciliation::reconcile_handoff(
                    &mut self.connection,
                    delegation,
                    request,
                    admitted_at,
                )
            }
        }
        .map_err(|error| {
            let uncertain = matches!(
                error,
                crate::AgentDepartureReconciliationError::CommitUnconfirmed { .. }
            );
            let source = WorkspaceStoreError::AgentDepartureReconciliation(error);
            if uncertain {
                WorkspaceStoreError::AgentDepartureReconciliationReadbackRequired {
                    request_id,
                    source: Box::new(source),
                }
            } else {
                source
            }
        })?;
        self.capture_sidecar_identities()
            .and_then(|()| self.ensure_live_binding())
            .map_err(|source| {
                WorkspaceStoreError::AgentDepartureReconciliationReadbackRequired {
                    request_id,
                    source: Box::new(source),
                }
            })?;
        Ok(result)
    }

    /// Read one immutable Agent departure reconciliation receipt.
    pub fn agent_departure_reconciliation(
        &self,
        request_id: Uuid,
    ) -> Result<Option<crate::AgentDepartureReconciliation>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_agent_departure_reconciliation::get(&self.connection, request_id)?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Change an Agent's exact Goal/DAG/node focus through revision CAS.
    /// Persistence validates that the referenced Goal and current DAG/node
    /// still match; it never remaps a focus after a replan.
    pub fn set_agent_focus(
        &mut self,
        actor: ActivityCoordinatorActor,
        command: &forge_domain::SetAgentFocus,
        admitted_at: TimestampMillis,
    ) -> Result<forge_domain::RegisteredAgentInstance, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        if actor.activity_id() != command.activity_id() {
            return Err(AgentStoreError::ActivityAgentMismatch {
                expected: actor.activity_id(),
                actual: command.activity_id(),
            }
            .into());
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let _binding = workspace_coordinators::authorize_live_in_transaction(
            &transaction,
            actor,
            admitted_at,
        )?;
        let result = workspace_agents::set_focus_in_transaction(&transaction, command)?;
        transaction.commit()?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Append one bounded public Agent work update.
    pub fn publish_agent_work_update(
        &mut self,
        update: &forge_domain::AgentWorkUpdate,
        session_id: forge_domain::AgentSessionId,
        principal: forge_domain::AuthenticatedPrincipal,
        admitted_at: TimestampMillis,
    ) -> Result<forge_domain::AgentWorkUpdate, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_agents::publish_work_update(
            &mut self.connection,
            update,
            session_id,
            principal,
            admitted_at,
        )?;
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

    /// Atomically commit one Coordinator-authorized DAG plan and record its
    /// replay ledger plus factual Coordinator planning history. Initial plans
    /// and successor replans share this authority; exact DAG head CAS remains
    /// in DAG persistence.
    pub fn commit_coordinator_dag_plan(
        &mut self,
        request: &forge_domain::AgentDagPlanRequest,
        admitted_at: TimestampMillis,
    ) -> Result<AgentDagPlanCommitResult, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_agent_dag::commit_plan(&mut self.connection, request, admitted_at)?;
        self.confirm_planning_commit()?;
        Ok(result)
    }

    /// Read one mutation retry only after current source authority is checked.
    /// This is observational; effect admission revalidates in its write transaction.
    pub fn inspect_file_mutation_request(
        &mut self,
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        authority: SourceWriteAuthority,
        observed_at: TimestampMillis,
        path: &WorkspaceRelativePath,
        change_set_id: forge_domain::ChangeSetId,
    ) -> Result<Option<FileMutationRecord>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        workspace_writer_leases::authorize_source_write(
            &transaction,
            workspace_id,
            activity_id,
            authority,
            observed_at,
            &[path],
        )?;
        let result = workspace_changesets::get(&transaction, change_set_id)?;
        transaction.commit()?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Inspect one caller-authored source-tree request before patch materialization.
    ///
    /// The raw request digest is durable retry identity. Exact source authority is
    /// still revalidated against every caller-authored path so a completed retry
    /// cannot bypass Agent/Goal/DAG/Writer-Lease fencing.
    pub fn inspect_source_tree_request(
        &mut self,
        attribution: ChangeSetAttribution,
        request_digest: SourceTreeRequestDigest,
        observed_at: TimestampMillis,
        authority: SourceWriteAuthority,
        paths: &[&WorkspaceRelativePath],
    ) -> Result<Option<TreeChangeSetAdmission>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        workspace_writer_leases::authorize_source_write(
            &transaction,
            attribution.workspace_id(),
            attribution.activity_id(),
            authority,
            observed_at,
            paths,
        )?;
        let result = workspace_changesets::inspect_source_tree_request(
            &transaction,
            attribution,
            request_digest,
        )?;
        if result.is_some()
            && workspace_diffs::get_by_change_set(&transaction, attribution.id())?.is_none()
        {
            return Err(DiffStoreError::RecordMissing.into());
        }
        transaction.commit()?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Persist one materialized source-tree `ChangeSet` together with its caller
    /// request digest before any filesystem effect.
    pub fn begin_source_tree_change_set(
        &mut self,
        intent: &TreeChangeSetIntent,
        diff_command: &BeginDiffEvidence,
        request_digest: SourceTreeRequestDigest,
        authority: SourceWriteAuthority,
    ) -> Result<TreeChangeSetAdmission, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut paths = Vec::with_capacity(intent.mutations().len() * 2);
        for mutation in intent.mutations() {
            paths.push(mutation.plan().primary_path());
            if let Some(path) = mutation.plan().secondary_path() {
                paths.push(path);
            }
        }
        let attribution = intent.attribution();
        workspace_writer_leases::authorize_source_write(
            &transaction,
            attribution.workspace_id(),
            attribution.activity_id(),
            authority,
            intent.observed_at(),
            &paths,
        )?;
        let result = workspace_changesets::begin_tree_change_set(&transaction, intent)?;
        match result.status() {
            forge_domain::TreeChangeSetAdmissionStatus::Started => {
                workspace_work_cuts::guards::ensure_source_write_open(
                    &transaction,
                    attribution.workspace_id(),
                    authority,
                )?;
                workspace_changesets::insert_source_tree_request_digest(
                    &transaction,
                    attribution.id(),
                    request_digest,
                )?;
                let _diff = workspace_diffs::begin_tree(&transaction, intent, diff_command)?;
            }
            forge_domain::TreeChangeSetAdmissionStatus::RecoveryRequired
            | forge_domain::TreeChangeSetAdmissionStatus::AlreadyApplied
            | forge_domain::TreeChangeSetAdmissionStatus::TerminalFailed => {
                if !workspace_changesets::source_tree_request_digest_matches(
                    &transaction,
                    attribution.id(),
                    request_digest,
                )? {
                    return Err(ChangeSetStoreError::IdentityConflict.into());
                }
                if workspace_diffs::inspect_tree(&transaction, intent, diff_command)?.is_none() {
                    return Err(DiffStoreError::RecordMissing.into());
                }
            }
        }
        associate_work_evidence(
            &transaction,
            Some(authority.attribution().into()),
            GoalEvidenceRef::ChangeSet(attribution.id()),
            intent.observed_at(),
        )?;
        transaction.commit()?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Inspect an existing tree-level `ChangeSet` without creating durable intent.
    ///
    /// Exact source authority is still validated so an idempotent retry cannot bypass
    /// Agent/Goal/DAG/Writer-Lease fencing merely because the original effect completed.
    pub fn inspect_tree_change_set(
        &mut self,
        intent: &TreeChangeSetIntent,
        diff_command: &BeginDiffEvidence,
        authority: SourceWriteAuthority,
    ) -> Result<Option<TreeChangeSetAdmission>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        let mut paths = Vec::with_capacity(intent.mutations().len() * 2);
        for mutation in intent.mutations() {
            paths.push(mutation.plan().primary_path());
            if let Some(path) = mutation.plan().secondary_path() {
                paths.push(path);
            }
        }
        let attribution = intent.attribution();
        workspace_writer_leases::authorize_source_write(
            &transaction,
            attribution.workspace_id(),
            attribution.activity_id(),
            authority,
            intent.observed_at(),
            &paths,
        )?;
        let result = workspace_changesets::inspect_tree_change_set(&transaction, intent)?;
        if result.is_some()
            && workspace_diffs::inspect_tree(&transaction, intent, diff_command)?.is_none()
        {
            return Err(DiffStoreError::RecordMissing.into());
        }
        transaction.commit()?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Persist one bounded tree-level `ChangeSet` intent before any source-tree effect.
    ///
    /// Writer Lease coverage is validated for every source/destination endpoint
    /// in the same `BEGIN IMMEDIATE` transaction as the durable intent.
    pub fn begin_tree_change_set(
        &mut self,
        intent: &TreeChangeSetIntent,
        diff_command: &BeginDiffEvidence,
        authority: SourceWriteAuthority,
    ) -> Result<TreeChangeSetAdmission, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut paths = Vec::with_capacity(intent.mutations().len() * 2);
        for mutation in intent.mutations() {
            paths.push(mutation.plan().primary_path());
            if let Some(path) = mutation.plan().secondary_path() {
                paths.push(path);
            }
        }
        let attribution = intent.attribution();
        workspace_writer_leases::authorize_source_write(
            &transaction,
            attribution.workspace_id(),
            attribution.activity_id(),
            authority,
            intent.observed_at(),
            &paths,
        )?;
        let result = workspace_changesets::begin_tree_change_set(&transaction, intent)?;
        match result.status() {
            forge_domain::TreeChangeSetAdmissionStatus::Started => {
                workspace_work_cuts::guards::ensure_source_write_open(
                    &transaction,
                    attribution.workspace_id(),
                    authority,
                )?;
                let _diff = workspace_diffs::begin_tree(&transaction, intent, diff_command)?;
            }
            forge_domain::TreeChangeSetAdmissionStatus::RecoveryRequired
            | forge_domain::TreeChangeSetAdmissionStatus::AlreadyApplied
            | forge_domain::TreeChangeSetAdmissionStatus::TerminalFailed => {
                if workspace_diffs::inspect_tree(&transaction, intent, diff_command)?.is_none() {
                    return Err(DiffStoreError::RecordMissing.into());
                }
            }
        }
        transaction.commit()?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    pub fn mark_tree_mutation_applied(
        &mut self,
        change_set_id: forge_domain::ChangeSetId,
        mutation_id: forge_domain::TreeMutationId,
    ) -> Result<(), WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        workspace_changesets::mark_tree_mutation_applied(&transaction, change_set_id, mutation_id)?;
        transaction.commit()?;
        self.capture_sidecar_identities()?;
        Ok(())
    }

    pub fn complete_tree_change_set(
        &mut self,
        change_set_id: forge_domain::ChangeSetId,
        diff_command: &CompleteDiffEvidence,
        observed_at: TimestampMillis,
        producer: ChangeSetProducer,
    ) -> Result<forge_domain::RegisteredChangeSet, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        workspace_diffs::complete(&transaction, diff_command)?;
        let result = workspace_changesets::complete_tree_change_set(
            &transaction,
            change_set_id,
            observed_at,
        )?;
        let diff = workspace_diffs::get_by_id(&transaction, diff_command.id())?
            .ok_or(DiffStoreError::RecordMissing)?;
        workspace_effect_fact_outbox::append_change_set_terminal(
            &transaction,
            &result,
            &diff,
            producer,
        )?;
        append_change_set_semantic_events(&transaction, &result, &diff)?;
        transaction.commit()?;
        self.capture_sidecar_identities()?;
        Ok(result)
    }

    pub fn fail_tree_change_set_without_effect(
        &mut self,
        change_set_id: forge_domain::ChangeSetId,
        diff_command: AbandonDiffEvidence,
        failure_code: forge_domain::FileMutationFailureCode,
        observed_at: TimestampMillis,
        producer: ChangeSetProducer,
    ) -> Result<forge_domain::RegisteredChangeSet, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        workspace_diffs::abandon(&transaction, diff_command)?;
        let result = workspace_changesets::fail_tree_change_set_without_effect(
            &transaction,
            change_set_id,
            failure_code,
            observed_at,
        )?;
        let diff = workspace_diffs::get_by_id(&transaction, diff_command.id())?
            .ok_or(DiffStoreError::RecordMissing)?;
        workspace_effect_fact_outbox::append_change_set_terminal(
            &transaction,
            &result,
            &diff,
            producer,
        )?;
        append_change_set_semantic_events(&transaction, &result, &diff)?;
        transaction.commit()?;
        self.capture_sidecar_identities()?;
        Ok(result)
    }

    pub fn tree_change_set_applied_mutations(
        &self,
        change_set_id: forge_domain::ChangeSetId,
    ) -> Result<Vec<forge_domain::TreeMutationId>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        Ok(workspace_changesets::tree_change_set_applied_mutations(
            &self.connection,
            change_set_id,
        )?)
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
        authority: SourceWriteAuthority,
    ) -> Result<BeginFileMutationDiffResult, WorkspaceStoreError> {
        self.begin_file_mutation_for_goal(command, diff_command, None, authority)
    }

    pub fn begin_file_mutation_for_goal(
        &mut self,
        command: &BeginFileMutation,
        diff_command: &BeginDiffEvidence,
        goal: Option<GoalWorkAttribution>,
        authority: SourceWriteAuthority,
    ) -> Result<BeginFileMutationDiffResult, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        workspace_writer_leases::authorize_source_write(
            &transaction,
            command.workspace_id(),
            command.activity_id(),
            authority,
            command.observed_at(),
            &[command.path()],
        )?;
        let file = workspace_changesets::begin(&transaction, command)?;
        if file.status() == BeginFileMutationStatus::Started {
            workspace_work_cuts::guards::ensure_source_write_open(
                &transaction,
                command.workspace_id(),
                authority,
            )?;
        }
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
        producer: ChangeSetProducer,
    ) -> Result<FileMutationDiffRecord, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        workspace_diffs::complete(&transaction, diff_command)?;
        let file = workspace_changesets::complete(&transaction, command)?;
        let diff = workspace_diffs::get_by_id(&transaction, diff_command.id())?
            .ok_or(DiffStoreError::RecordMissing)?;
        workspace_effect_fact_outbox::append_change_set_terminal(
            &transaction,
            file.change_set(),
            &diff,
            producer,
        )?;
        append_change_set_semantic_events(&transaction, file.change_set(), &diff)?;
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
        producer: ChangeSetProducer,
    ) -> Result<FileMutationDiffRecord, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        workspace_diffs::abandon(&transaction, diff_command)?;
        let file = workspace_changesets::fail(&transaction, command)?;
        let diff = workspace_diffs::get_by_id(&transaction, diff_command.id())?
            .ok_or(DiffStoreError::RecordMissing)?;
        workspace_effect_fact_outbox::append_change_set_terminal(
            &transaction,
            file.change_set(),
            &diff,
            producer,
        )?;
        append_change_set_semantic_events(&transaction, file.change_set(), &diff)?;
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

    /// Observe any durable single-file or tree admission in this bound store.
    pub fn has_change_set(
        &self,
        change_set_id: forge_domain::ChangeSetId,
    ) -> Result<bool, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let present = workspace_changesets::has_change_set(&self.connection, change_set_id)?;
        self.ensure_live_binding()?;
        Ok(present)
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

    /// Read one historical single-file mutation and its optional Diff
    /// projection from the same deferred `SQLite` snapshot. This path performs
    /// no current Writer Lease or source-mutation authority check.
    pub fn file_mutation_read_snapshot(
        &mut self,
        id: forge_domain::ChangeSetId,
    ) -> Result<Option<FileMutationReadSnapshot>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        let Some(record) = workspace_changesets::get(&transaction, id)? else {
            transaction.commit()?;
            self.ensure_live_binding()?;
            return Ok(None);
        };
        let diff = workspace_diffs::get_by_change_set(&transaction, id)?;
        let snapshot = FileMutationReadSnapshot::new(record, diff);
        transaction.commit()?;
        self.ensure_live_binding()?;
        Ok(Some(snapshot))
    }

    /// Read one historical source-tree request and its optional Diff
    /// projection from the same deferred `SQLite` snapshot. This path performs
    /// no current Writer Lease or source-mutation authority check.
    pub fn source_tree_read_snapshot(
        &mut self,
        id: forge_domain::ChangeSetId,
    ) -> Result<Option<SourceTreeReadSnapshot>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        let Some(data) = workspace_changesets::source_tree_read_data(&transaction, id)? else {
            transaction.commit()?;
            self.ensure_live_binding()?;
            return Ok(None);
        };
        let diff = workspace_diffs::get_by_change_set(&transaction, id)?;
        let snapshot = SourceTreeReadSnapshot::new(
            data.change_set,
            data.request_digest,
            data.applied_mutations,
            data.mutation_count,
            diff,
        );
        transaction.commit()?;
        self.ensure_live_binding()?;
        Ok(Some(snapshot))
    }

    /// Read the Diff Evidence row associated with one `ChangeSet`.
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
        let result = workspace_executions::complete_execution(&mut self.connection, command)
            .map_err(map_execution_journal_error)?;
        self.confirm_execution_journal_commit()?;
        Ok(result)
    }

    /// Atomically retain the validated fixed-name generated package manifest
    /// with the terminal execution outcome.
    pub fn complete_execution_with_generated_package(
        &mut self,
        command: &CompleteExecution,
        manifest: forge_domain::GeneratedPackageManifest,
    ) -> Result<RegisteredExecution, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_executions::complete_execution_with_generated_package(
            &mut self.connection,
            command,
            manifest,
        )
        .map_err(map_execution_journal_error)?;
        self.confirm_execution_journal_commit()?;
        Ok(result)
    }

    /// Persist a typed internal failure when no uncertain process effect remains.
    pub fn fail_execution(
        &mut self,
        command: FailExecution,
    ) -> Result<RegisteredExecution, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_executions::fail_execution(&mut self.connection, command)
            .map_err(map_execution_journal_error)?;
        self.confirm_execution_journal_commit()?;
        Ok(result)
    }

    /// Atomically retain native closure evidence with the exact terminal outcome.
    pub fn complete_execution_with_native_closure(
        &mut self,
        command: &CompleteExecution,
        manifest: Option<forge_domain::GeneratedPackageManifest>,
        closure: Option<forge_domain::ExecutionNativeClosureFact>,
    ) -> Result<RegisteredExecution, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let record = workspace_executions::complete_execution_with_native_closure(
            &mut self.connection,
            command,
            manifest,
            closure,
        )
        .map_err(map_execution_journal_error)?;
        self.confirm_execution_journal_commit()?;
        Ok(record)
    }

    /// Retain positive native cleanup evidence with an actual failure result.
    pub fn fail_execution_with_native_closure(
        &mut self,
        command: FailExecution,
        closure: Option<forge_domain::ExecutionNativeClosureFact>,
    ) -> Result<RegisteredExecution, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let record = workspace_executions::fail_execution_with_native_closure(
            &mut self.connection,
            command,
            closure,
        )
        .map_err(map_execution_journal_error)?;
        self.confirm_execution_journal_commit()?;
        Ok(record)
    }

    /// Read terminal record, artifact and closure from one durable snapshot.
    pub fn execution_native_closure_snapshot(
        &self,
        execution_id: forge_domain::ExecutionId,
    ) -> Result<
        Option<crate::workspace_executions::native_closure::ExecutionNativeClosureSnapshot>,
        WorkspaceStoreError,
    > {
        self.ensure_live_binding()?;
        let snapshot =
            workspace_executions::get_native_closure_snapshot(&self.connection, execution_id)?;
        self.ensure_live_binding()?;
        Ok(snapshot)
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
    /// lease is expired at the observed time and has no attached
    /// session-bound Agent participant.
    ///
    /// An attached session-bound participant blocks reconciliation even when the
    /// Activity heartbeat is expired. Activities without any lease are also left
    /// untouched this slice; only proven durable-authority expiry grants recovery
    /// classification.
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

    /// Read the bounded latest-per-command `VerificationRun` projection.
    pub fn verification_projection(&self) -> Result<VerificationProjection, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let workspace_id = self.workspace()?.id();
        let projection = workspace_verification::projection(&self.connection, workspace_id)?;
        self.ensure_live_binding()?;
        Ok(projection)
    }

    /// Service/operator observation, scoped and read in one SQLite snapshot.
    /// Output blobs are excluded from inventory; mutation authority is unchanged.
    pub fn execution_evidence_inventory(
        &self,
        selection: forge_domain::ExecutionObservationSelection,
        limit: ExecutionListLimit,
    ) -> Result<crate::ExecutionEvidenceInventory, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_executions::observation_inventory(
            &self.connection,
            self.workspace()?.id(),
            selection,
            limit,
        )?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    pub fn execution_evidence_read(
        &self,
        selection: forge_domain::ExecutionObservationSelection,
        id: ExecutionId,
        cursor: ExecutionOutputCursor,
        max_bytes: u64,
        max_events: usize,
    ) -> Result<crate::ExecutionEvidenceRead, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_executions::observation_read(
            &self.connection,
            self.workspace()?.id(),
            selection,
            id,
            cursor,
            max_bytes,
            max_events,
        )?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Return only durable generated-artifact metadata; callers derive any
    /// product-cache path from this execution identity outside `SQLite`.
    pub fn generated_package_manifest(
        &self,
        execution_id: ExecutionId,
    ) -> Result<Option<forge_domain::GeneratedPackageManifest>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        workspace_executions::get_generated_package_manifest(&self.connection, execution_id)
            .map_err(WorkspaceStoreError::from)
    }

    /// Return only bounded manifests backed by successful `GeneratedPackage`
    /// execution rows in this exact Workspace database.
    pub fn list_generated_package_manifests(
        &self,
        limit: ExecutionListLimit,
    ) -> Result<Vec<forge_domain::GeneratedPackageManifest>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let workspace_id = self.workspace()?.id();
        let result = workspace_executions::list_generated_package_manifests(
            &self.connection,
            workspace_id,
            limit,
        )?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Read one Agent-originated execution after one `SQLite` snapshot verifies
    /// its Workspace/Activity attribution, immutable provenance, and current
    /// Agent attachment/focus.
    pub fn get_execution_authorized(
        &self,
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        execution_id: ExecutionId,
        provenance: &ExecutionAgentProvenance,
    ) -> Result<RegisteredExecution, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_executions::get_execution_authorized(
            &self.connection,
            workspace_id,
            activity_id,
            execution_id,
            provenance,
        )?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Read one Agent-owned execution record and bounded output from one
    /// durable `SQLite` snapshot. The live Workspace binding is fenced both
    /// before and after the transaction, just like the existing read APIs.
    pub fn read_execution_authorized(
        &self,
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        provenance: &ExecutionAgentProvenance,
        cursor: ExecutionOutputCursor,
        max_bytes: u64,
        max_events: usize,
    ) -> Result<AuthorizedExecutionRead, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_executions::read_execution_authorized(
            &self.connection,
            workspace_id,
            activity_id,
            provenance,
            cursor,
            max_bytes,
            max_events,
        )?;
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

    /// Append a bounded batch of incremental output events in one `SQLite`
    /// transaction. A failed batch commits no new event and can be replayed
    /// exactly by the owning coordinator.
    pub fn append_execution_output_events(
        &mut self,
        events: &[ExecutionOutputEvent],
    ) -> Result<(), WorkspaceStoreError> {
        self.append_execution_output_events_with_hook(events, |_| {})
    }

    fn append_execution_output_events_with_hook<F>(
        &mut self,
        events: &[ExecutionOutputEvent],
        after_commit: F,
    ) -> Result<(), WorkspaceStoreError>
    where
        F: FnOnce(&mut Self),
    {
        self.ensure_live_binding()?;
        workspace_executions::append_output_events(&mut self.connection, events)
            .map_err(map_execution_journal_error)?;
        after_commit(self);
        self.confirm_execution_journal_commit()?;
        Ok(())
    }

    /// Read a bounded, ordered durable output prefix after the supplied
    /// execution-local cursor. The read is observational and does not consume
    /// output; callers retain the cursor until the corresponding effect is
    /// durably committed elsewhere.
    pub fn read_execution_output_events(
        &self,
        cursor: ExecutionOutputCursor,
        max_bytes: u64,
        max_events: usize,
    ) -> Result<ExecutionOutputRead, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_executions::read_output_events(
            &self.connection,
            cursor,
            max_bytes,
            max_events,
        )?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Read one Agent-owned output prefix with execution provenance and the
    /// current Agent snapshot checked by the same `SQLite` transaction.
    pub fn read_execution_output_events_authorized(
        &self,
        activity_id: ActivityId,
        execution_id: ExecutionId,
        provenance: &ExecutionAgentProvenance,
        cursor: ExecutionOutputCursor,
        max_bytes: u64,
        max_events: usize,
    ) -> Result<ExecutionOutputRead, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_executions::read_output_events_authorized(
            &self.connection,
            activity_id,
            execution_id,
            provenance,
            cursor,
            max_bytes,
            max_events,
        )?;
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
        actor: ActivityCoordinatorActor,
        goal: &RegisteredGoal,
        admitted_at: TimestampMillis,
    ) -> Result<RegisteredGoal, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        validate_goal_actor(actor, goal)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let _binding = workspace_coordinators::authorize_live_in_transaction(
            &transaction,
            actor,
            admitted_at,
        )?;
        let result = workspace_goals::insert_goal_in_transaction(&transaction, goal)?;
        transaction.commit()?;
        self.confirm_planning_commit()?;
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
        activity_id: forge_domain::ActivityId,
        limit: GoalListLimit,
    ) -> Result<Vec<RegisteredGoal>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let workspace = self.workspace()?;
        if workspace.id() != workspace_id {
            return Err(GoalStoreError::WorkspaceMismatch.into());
        }
        let result =
            workspace_goals::list_goals(&self.connection, workspace_id, activity_id, limit)?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Persist a pure-domain Goal lifecycle projection using exact revision
    /// compare-and-set. Completed Goals use [`Self::complete_goal`] instead.
    pub fn update_goal(
        &mut self,
        actor: ActivityCoordinatorActor,
        goal: &RegisteredGoal,
        expected_revision: GoalRevision,
        admitted_at: TimestampMillis,
    ) -> Result<RegisteredGoal, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        validate_goal_actor(actor, goal)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let _binding = workspace_coordinators::authorize_live_in_transaction(
            &transaction,
            actor,
            admitted_at,
        )?;
        let result =
            workspace_goals::update_goal_in_transaction(&transaction, goal, expected_revision)?;
        transaction.commit()?;
        self.confirm_planning_commit()?;
        Ok(result)
    }

    /// Persist one user-owned Goal contract revision using exact revision CAS.
    /// Lifecycle state is preserved; terminal Goals are immutable.
    pub fn revise_goal_contract(
        &mut self,
        actor: ActivityCoordinatorActor,
        goal: &RegisteredGoal,
        expected_revision: GoalRevision,
        admitted_at: TimestampMillis,
    ) -> Result<RegisteredGoal, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        validate_goal_actor(actor, goal)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let _binding = workspace_coordinators::authorize_live_in_transaction(
            &transaction,
            actor,
            admitted_at,
        )?;
        let result = workspace_goals::revise_goal_contract_in_transaction(
            &transaction,
            goal,
            expected_revision,
        )?;
        transaction.commit()?;
        self.confirm_planning_commit()?;
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
        actor: ActivityCoordinatorActor,
        goal: &RegisteredGoal,
        expected_revision: GoalRevision,
        review: &GoalReview,
        receipt: &GoalCompletionReceipt,
        admitted_at: TimestampMillis,
    ) -> Result<RegisteredGoal, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        validate_goal_actor(actor, goal)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let _binding = workspace_coordinators::authorize_live_in_transaction(
            &transaction,
            actor,
            admitted_at,
        )?;
        let result = workspace_goals::complete_goal_in_transaction(
            &transaction,
            goal,
            expected_revision,
            review,
            receipt,
        )?;
        transaction.commit()?;
        self.confirm_planning_commit()?;
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

    /// Read exact Goal/DAG/node assignment context and the current head from
    /// one `SQLite` snapshot. A historical requested revision remains readable;
    /// callers can compare `scope().dag_revision()` with `head().dag_revision()`
    /// before sending work to the participant.
    pub fn dag_node_assignment_snapshot(
        &self,
        scope: crate::DagNodeEvidenceScope,
    ) -> Result<Option<crate::DagNodeAssignmentSnapshot>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let transaction = self.connection.unchecked_transaction()?;
        let result: Result<Option<crate::DagNodeAssignmentSnapshot>, WorkspaceStoreError> =
            (|| {
                let workspace = query_workspace_row(&transaction)?
                    .ok_or(WorkspaceStoreError::WorkspaceIdentityMissing)
                    .and_then(decode_workspace)?;
                let Some(goal) = workspace_goals::get_goal(&transaction, scope.goal_id())? else {
                    return Ok(None);
                };
                if goal.workspace_id() != workspace.id() {
                    return Err(GoalStoreError::WorkspaceMismatch.into());
                }
                let activity_raw = query_activity_row(&transaction, goal.activity_id())?
                    .ok_or(WorkspaceStoreError::ActivityNotFound(goal.activity_id()))?;
                let activity = decode_activity(&activity_raw)?;
                validate_activity_workspace(&activity, workspace.id())?;
                let Some(dag) = workspace_dags::get_revision_in_transaction(
                    &transaction,
                    scope.goal_id(),
                    scope.dag_revision(),
                )?
                else {
                    return Ok(None);
                };
                let Some(node) = dag.nodes().iter().find(|node| node.id() == scope.node_id())
                else {
                    return Ok(None);
                };
                let assignment = workspace_agent_assignments::active_for_node(
                    &transaction,
                    workspace.id(),
                    scope,
                    goal.timestamps().created_at(),
                )?;
                Ok(Some(crate::DagNodeAssignmentSnapshot::new(
                    &goal, &dag, node, assignment,
                )))
            })();
        let result = result?;
        transaction.commit()?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Read one bounded page of immutable evidence attributed to an exact
    /// historical Goal/DAG revision/Node scope. The read validates the scope
    /// and page boundary inside one `SQLite` read transaction.
    pub fn list_dag_node_evidence(
        &self,
        scope: crate::DagNodeEvidenceScope,
        limit: usize,
        cursor: Option<crate::DagNodeEvidenceCursor>,
    ) -> Result<crate::DagNodeEvidencePage, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_dag_node_evidence::read(&self.connection, scope, limit, cursor)?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    pub fn start_dag_node(
        &mut self,
        request: workspace_dags::DagNodeTransition,
    ) -> Result<RegisteredDagNode, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_dags::start_node(&mut self.connection, request)?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Start one current DAG node through the exact session/principal Agent
    /// admission boundary. The underlying deterministic transition remains
    /// available through [`Self::start_dag_node`] for trusted internal paths.
    pub fn start_dag_node_authorized(
        &mut self,
        request: workspace_dags::DagNodeTransition,
        session_id: forge_domain::AgentSessionId,
        principal: forge_domain::AuthenticatedPrincipal,
        admitted_at: TimestampMillis,
    ) -> Result<RegisteredDagNode, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_dags::start_node_authorized(
            &mut self.connection,
            request,
            session_id,
            principal,
            admitted_at,
        )?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    pub fn complete_dag_node(
        &mut self,
        request: workspace_dags::DagNodeTransition,
    ) -> Result<RegisteredDagNode, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_dags::complete_node(&mut self.connection, request)?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Complete one current DAG node through the exact session/principal Agent
    /// admission boundary. The underlying deterministic transition remains
    /// available through [`Self::complete_dag_node`] for trusted internal
    /// paths.
    pub fn complete_dag_node_authorized(
        &mut self,
        request: workspace_dags::DagNodeTransition,
        session_id: forge_domain::AgentSessionId,
        principal: forge_domain::AuthenticatedPrincipal,
        admitted_at: TimestampMillis,
    ) -> Result<RegisteredDagNode, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_dags::complete_node_authorized(
            &mut self.connection,
            request,
            session_id,
            principal,
            admitted_at,
        )?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    pub fn update_dag_node(
        &mut self,
        requested: &RegisteredDagNode,
        expected_revision: forge_domain::DagNodeRevision,
        admitted_at: TimestampMillis,
    ) -> Result<RegisteredDagNode, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_dags::update_node_authorized(
            &mut self.connection,
            requested,
            expected_revision,
            admitted_at,
        )?;
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

    /// Read one Approval and its optional durable Execution from one `SQLite`
    /// snapshot. Pending approvals intentionally return `None` for the
    /// Execution component.
    pub fn get_approval_request_with_execution(
        &self,
        id: ApprovalRequestId,
    ) -> Result<
        Option<(
            RegisteredApprovalRequest,
            Option<forge_domain::RegisteredExecution>,
        )>,
        WorkspaceStoreError,
    > {
        self.ensure_live_binding()?;
        let result = workspace_approvals::get_approval_with_execution(&self.connection, id)?;
        self.ensure_live_binding()?;
        Ok(result)
    }

    /// Read one Approval, its optional durable Execution, and its optional
    /// exact local Execution Grant from one SQLite snapshot.
    pub fn get_approval_request_with_execution_and_grant(
        &self,
        id: ApprovalRequestId,
    ) -> Result<ApprovalExecutionGrantReadback, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result =
            workspace_approvals::get_approval_with_execution_and_grant(&self.connection, id)?;
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

    #[allow(clippy::too_many_arguments)]
    pub fn consume_grant_and_begin_execution(
        &mut self,
        grant_id: ExecutionGrantId,
        expected_revision: ExecutionGrantRevision,
        request: ExecutionAuthorizationRequest,
        begin: &BeginExecution,
        observed_at: TimestampMillis,
        admission: workspace_approvals::ExecutionAdmissionContext,
        admission_envelope: Option<&workspace_admission_envelopes::AdmissionEnvelopeConsumption>,
    ) -> Result<(ExecutionGrant, crate::BeginExecutionRecord), WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_approvals::consume_grant_and_begin_execution(
            &mut self.connection,
            grant_id,
            expected_revision,
            request,
            begin,
            observed_at,
            admission,
            admission_envelope,
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
        verification: Option<VerificationInputEvidence>,
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
            verification,
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

    /// Bootstrap one new Activity, idempotently confirm a still-live lease,
    /// or resume one explicitly released Open Activity for a new runtime.
    ///
    /// The entire decision and write are performed in one IMMEDIATE
    /// transaction. A same-owner live bootstrap is intentionally idempotent;
    /// a different live owner receives `AlreadyLive`; expired Open rows and
    /// initial unleased rows require explicit recovery; released Open rows are
    /// re-leased with an exact lease-revision CAS; terminal rows are returned
    /// without revival.
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
                    BootstrapActivityDecision::ResumeReleased => {
                        resume_released_activity(&transaction, &existing, command)?
                    }
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
        self.renew_activity_leases_with_guard(commands, None)
    }

    /// Renew one lease only while its exact supervised Goal and Coordinator
    /// fences still hold inside the same immediate transaction as the lease CAS.
    pub fn renew_activity_lease_with_supervision_guard(
        &mut self,
        command: &RenewActivityLease,
        actor: ActivityCoordinatorActor,
        goal_id: GoalId,
        goal_created_at: TimestampMillis,
    ) -> Result<RegisteredActivity, WorkspaceStoreError> {
        let guard = SupervisedActivityLeaseRenewGuard {
            actor,
            goal_id,
            goal_created_at,
        };
        let mut activities =
            self.renew_activity_leases_with_guard(std::slice::from_ref(command), Some(guard))?;
        activities
            .pop()
            .ok_or(WorkspaceStoreError::ActivityBatchInvariant)
    }

    fn renew_activity_leases_with_guard(
        &mut self,
        commands: &[RenewActivityLease],
        guard: Option<SupervisedActivityLeaseRenewGuard>,
    ) -> Result<Vec<RegisteredActivity>, WorkspaceStoreError> {
        if commands.is_empty() {
            return Ok(Vec::new());
        }
        if guard.is_some() && commands.len() != 1 {
            return Err(WorkspaceStoreError::ActivityBatchInvariant);
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
        if let Some(guard) = guard {
            validate_supervised_activity_lease_renew_guard(
                &transaction,
                workspace.id(),
                &commands[0],
                guard,
            )?;
        }
        let preflight = prepare_renew_preflight(&transaction, workspace.id(), commands)?;

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

    /// Release one or more owned leases while keeping Open Activities available.
    pub fn release_activity_leases(
        &mut self,
        commands: &[ReleaseActivityLease],
    ) -> Result<Vec<RegisteredActivity>, WorkspaceStoreError> {
        if commands.is_empty() {
            return Ok(Vec::new());
        }
        validate_activity_lease_batch_size(commands.len())?;
        validate_same_owner_for_releases(commands)?;
        validate_unique_activity_ids(commands.iter().map(ReleaseActivityLease::id))?;
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
                preflight.push(ReleasePreflight {
                    command,
                    current,
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
            let next_lease_revision = current.lease_revision().checked_next().map_err(|_| {
                WorkspaceStoreError::ActivityLeaseRevisionOverflow {
                    id: command.id(),
                    current: current.lease_revision(),
                }
            })?;
            preflight.push(ReleasePreflight {
                command,
                current,
                next_lease_revision: Some(next_lease_revision),
            });
        }

        let released_activities = apply_release_preflight(&transaction, &preflight)?;
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
        Ok(released_activities)
    }

    /// Release one owned lease through the batch path.
    pub fn release_activity_lease(
        &mut self,
        command: &ReleaseActivityLease,
    ) -> Result<RegisteredActivity, WorkspaceStoreError> {
        let mut activities = self.release_activity_leases(std::slice::from_ref(command))?;
        activities
            .pop()
            .ok_or(WorkspaceStoreError::ActivityBatchInvariant)
    }

    /// Reconcile a bounded batch of expired Open rows to Interrupted. An Open
    /// Activity with any attached session-bound Agent is retained for that
    /// participant; Activities with no Agent rows keep the existing expiry path.
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
        let reconciled =
            Self::reconcile_expired_activities_in_transaction(&transaction, *command, limit)?;
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

    fn reconcile_expired_activities_in_transaction(
        transaction: &Transaction<'_>,
        command: ReconcileExpiredActivities,
        limit: ActivityListLimit,
    ) -> Result<Vec<RegisteredActivity>, WorkspaceStoreError> {
        let ids = Self::expired_activity_ids(transaction, command, limit)?;
        let mut reconciled = Vec::with_capacity(ids.len());
        for id_bytes in ids {
            let id = decode_activity_id(&id_bytes)?;
            let Some(raw) = query_activity_row(transaction, id)? else {
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
                   AND lease_until_ms = ?8 AND lease_revision = ?9
                   AND NOT EXISTS (
                       SELECT 1 FROM agent_instances AS ai
                       WHERE ai.activity_id = activities.activity_id
                         AND ai.session_id IS NOT NULL
                         AND ai.attachment_state = 0
                   )",
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
            let updated = query_activity_row(transaction, id)?
                .ok_or(WorkspaceStoreError::ActivityNotFound(id))?;
            reconciled.push(decode_activity(&updated)?);
        }
        Ok(reconciled)
    }

    fn expired_activity_ids(
        transaction: &Transaction<'_>,
        command: ReconcileExpiredActivities,
        limit: ActivityListLimit,
    ) -> Result<Vec<Vec<u8>>, WorkspaceStoreError> {
        let mut statement = transaction.prepare(
            "SELECT a.activity_id FROM activities AS a
             WHERE a.state = ?1 AND a.lease_owner_id IS NOT NULL
               AND a.lease_until_ms IS NOT NULL AND a.lease_until_ms <= ?2
               AND NOT EXISTS (
                   SELECT 1 FROM agent_instances AS ai
                   WHERE ai.activity_id = a.activity_id
                     AND ai.session_id IS NOT NULL
                     AND ai.attachment_state = 0
               )
             ORDER BY a.lease_until_ms ASC, a.activity_id ASC
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
        Ok(ids)
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

    fn confirm_execution_journal_commit(&mut self) -> Result<(), WorkspaceStoreError> {
        self.ensure_live_binding()
            .and_then(|()| self.capture_sidecar_identities())
            .and_then(|()| self.ensure_live_binding())
            .map_err(
                |source| WorkspaceStoreError::ExecutionJournalCommittedUnconfirmed {
                    source: Box::new(source),
                },
            )
    }

    fn confirm_planning_commit(&mut self) -> Result<(), WorkspaceStoreError> {
        self.capture_sidecar_identities()
            .and_then(|()| self.ensure_live_binding())
            .map_err(|source| WorkspaceStoreError::PlanningCommittedUnconfirmed {
                source: Box::new(source),
            })
    }

    fn validate_runtime_policy(&self) -> Result<(), WorkspaceStoreError> {
        validate_runtime_policy(&runtime_policy(&self.connection)?)
    }

    fn establish_or_confirm(
        &mut self,
        command: &EstablishWorkspace,
    ) -> Result<RegisteredWorkspace, WorkspaceStoreError> {
        self.establish_or_confirm_expected(command, None)
    }

    fn establish_or_confirm_expected(
        &mut self,
        command: &EstablishWorkspace,
        expected: Option<&RegisteredWorkspace>,
    ) -> Result<RegisteredWorkspace, WorkspaceStoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(expected) = expected {
            let current = query_workspace_row(&transaction)?
                .map(decode_workspace)
                .transpose()?;
            if current.as_ref() != Some(expected) {
                return Err(WorkspaceStoreError::RelocationBlocked(
                    "Workspace snapshot changed",
                ));
            }
        }
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

fn is_retryable_live_identity_error(error: &WorkspaceStoreError, database: &Path) -> bool {
    match error {
        WorkspaceStoreError::DatabaseSidecarPairMismatch { .. } => true,
        WorkspaceStoreError::DatabasePathChanged(path) => {
            path == &sidecar_path(database, "-wal") || path == &sidecar_path(database, "-shm")
        }
        _ => false,
    }
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

fn validate_activity_successor_predecessor(
    transaction: &Transaction<'_>,
    workspace: &RegisteredWorkspace,
    command: &forge_domain::CreateActivitySuccessor,
) -> Result<RegisteredActivity, WorkspaceStoreError> {
    let predecessor = query_activity_row(transaction, command.predecessor_activity_id())?
        .ok_or(WorkspaceStoreError::ActivityNotFound(
            command.predecessor_activity_id(),
        ))
        .and_then(|raw| decode_activity(&raw))?;
    validate_activity_workspace(&predecessor, workspace.id())?;
    if predecessor.revision() != command.predecessor_activity_revision() {
        return Err(WorkspaceStoreError::ActivityRevisionConflict {
            id: predecessor.id(),
            expected: command.predecessor_activity_revision(),
            actual: predecessor.revision(),
        });
    }
    if !matches!(
        predecessor.state(),
        ActivityState::Closed | ActivityState::Interrupted
    ) {
        return Err(
            WorkspaceStoreError::ActivitySuccessorPredecessorNotTerminal {
                id: predecessor.id(),
                state: predecessor.state(),
            },
        );
    }
    Ok(predecessor)
}

fn replay_activity_successor(
    transaction: &Transaction<'_>,
    workspace: &RegisteredWorkspace,
    predecessor: &RegisteredActivity,
    command: &forge_domain::CreateActivitySuccessor,
) -> Result<Option<(ActivitySuccessor, RegisteredActivity)>, WorkspaceStoreError> {
    let Some(existing) =
        workspace_activity_successors::get_by_predecessor(transaction, predecessor.id())?
    else {
        return Ok(None);
    };
    if existing.workspace_id() != workspace.id()
        || existing.predecessor_activity_id() != predecessor.id()
        || existing.predecessor_activity_revision() != predecessor.revision()
        || existing.created_at().get() < predecessor.updated_at().get()
    {
        return Err(WorkspaceStoreError::ActivitySuccessorCorrupt(
            predecessor.id(),
        ));
    }
    if existing.successor_activity_id() != command.successor_activity_id() {
        return Err(WorkspaceStoreError::ActivitySuccessorConflict {
            predecessor: predecessor.id(),
            existing_successor: existing.successor_activity_id(),
            requested_successor: command.successor_activity_id(),
        });
    }
    let successor_raw = query_activity_row(transaction, existing.successor_activity_id())?.ok_or(
        WorkspaceStoreError::ActivityNotFound(existing.successor_activity_id()),
    )?;
    let successor = decode_activity(&successor_raw)?;
    validate_activity_workspace(&successor, workspace.id())?;
    if successor.id() != existing.successor_activity_id()
        || successor.created_at() != existing.created_at()
    {
        return Err(WorkspaceStoreError::ActivitySuccessorCorrupt(
            predecessor.id(),
        ));
    }
    Ok(Some((existing, successor)))
}

fn create_activity_successor_in_transaction(
    transaction: &Transaction<'_>,
    workspace: &RegisteredWorkspace,
    predecessor: &RegisteredActivity,
    command: &forge_domain::CreateActivitySuccessor,
) -> Result<(ActivitySuccessor, RegisteredActivity), WorkspaceStoreError> {
    if command.observed_at().get() < predecessor.updated_at().get() {
        return Err(WorkspaceStoreError::ActivitySuccessorTimestampOrder {
            predecessor: predecessor.id(),
            predecessor_updated_at: predecessor.updated_at(),
            observed_at: command.observed_at(),
        });
    }
    if query_activity_row(transaction, command.successor_activity_id())?.is_some() {
        return Err(WorkspaceStoreError::ActivitySuccessorTargetAlreadyExists(
            command.successor_activity_id(),
        ));
    }
    insert_open_activity(
        transaction,
        workspace,
        command.successor_activity_id(),
        command.observed_at(),
    )?;
    let successor_raw = query_activity_row(transaction, command.successor_activity_id())?.ok_or(
        WorkspaceStoreError::ActivityNotFound(command.successor_activity_id()),
    )?;
    let successor = decode_activity(&successor_raw)?;
    let relation = ActivitySuccessor::from_parts(
        workspace.id(),
        predecessor.id(),
        predecessor.revision(),
        successor.id(),
        command.initiating_session_id(),
        command.runtime_instance_id(),
        command.observed_at(),
    )
    .map_err(ActivitySuccessorStoreError::Domain)?;
    workspace_activity_successors::insert_in_transaction(transaction, relation)?;
    let persisted =
        workspace_activity_successors::get_by_predecessor(transaction, predecessor.id())?.ok_or(
            WorkspaceStoreError::ActivitySuccessorMissing(predecessor.id()),
        )?;
    Ok((persisted, successor))
}

fn insert_open_activity(
    transaction: &Transaction<'_>,
    workspace: &RegisteredWorkspace,
    activity_id: ActivityId,
    observed_at: TimestampMillis,
) -> Result<(), WorkspaceStoreError> {
    let activity_id_bytes = activity_id.into_uuid().into_bytes();
    let workspace_id_bytes = workspace.id().into_uuid().into_bytes();
    transaction.execute(
        "INSERT INTO activities (
            activity_id, workspace_id, state, created_at_ms, updated_at_ms, revision,
            lease_owner_id, lease_until_ms, lease_revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, NULL, ?7)",
        params![
            activity_id_bytes.as_slice(),
            workspace_id_bytes.as_slice(),
            encode_activity_state(ActivityState::Open),
            observed_at.get(),
            observed_at.get(),
            ActivityRevision::INITIAL.get(),
            ActivityLeaseRevision::INITIAL.get(),
        ],
    )?;
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

fn resume_released_activity(
    transaction: &Transaction<'_>,
    existing: &RegisteredActivity,
    command: &BootstrapActivity,
) -> Result<RegisteredActivity, WorkspaceStoreError> {
    let next_lease_revision = existing.lease_revision().checked_next().map_err(|_| {
        WorkspaceStoreError::ActivityLeaseRevisionOverflow {
            id: command.id(),
            current: existing.lease_revision(),
        }
    })?;
    let owner = command.owner_id().into_uuid().into_bytes();
    let id = command.id().into_uuid().into_bytes();
    let changed = transaction.execute(
        "UPDATE activities
         SET lease_owner_id = ?1, lease_until_ms = ?2, lease_revision = ?3
         WHERE activity_id = ?4 AND state = ?5
           AND lease_owner_id IS NULL AND lease_until_ms IS NULL
           AND lease_revision = ?6",
        params![
            owner.as_slice(),
            command.lease_until().get(),
            next_lease_revision.get(),
            id.as_slice(),
            encode_activity_state(ActivityState::Open),
            existing.lease_revision().get(),
        ],
    )?;
    if changed == 0 {
        return Err(WorkspaceStoreError::LeaseRevisionConflict {
            id: command.id(),
            expected: existing.lease_revision(),
            actual: existing.lease_revision(),
        });
    }
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

fn prepare_renew_preflight<'a>(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
    commands: &'a [RenewActivityLease],
) -> Result<Vec<RenewPreflight<'a>>, WorkspaceStoreError> {
    let mut preflight = Vec::with_capacity(commands.len());
    for command in commands {
        let raw = query_activity_row(transaction, command.id())?
            .ok_or(WorkspaceStoreError::ActivityNotFound(command.id()))?;
        let current = decode_activity(&raw)?;
        validate_activity_workspace(&current, workspace_id)?;
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
    Ok(preflight)
}

#[derive(Debug, Clone, Copy)]
struct SupervisedActivityLeaseRenewGuard {
    actor: ActivityCoordinatorActor,
    goal_id: GoalId,
    goal_created_at: TimestampMillis,
}

fn validate_supervised_activity_lease_renew_guard(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
    command: &RenewActivityLease,
    guard: SupervisedActivityLeaseRenewGuard,
) -> Result<(), WorkspaceStoreError> {
    let actor = guard.actor;
    let activity_id = command.id();
    if actor.workspace_id() != workspace_id || actor.activity_id() != activity_id {
        return Err(WorkspaceStoreError::ActivityLeaseUnavailable(activity_id));
    }

    let Some(goal) = crate::workspace_goals::get_goal(transaction, guard.goal_id)? else {
        return Err(WorkspaceStoreError::ActivityLeaseUnavailable(activity_id));
    };
    if goal.workspace_id() != workspace_id
        || goal.activity_id() != activity_id
        || goal.timestamps().created_at() != guard.goal_created_at
        || goal.status().kind() != GoalStatusKind::Active
    {
        return Err(WorkspaceStoreError::ActivityLeaseUnavailable(activity_id));
    }

    let Some(coordinator) = workspace_coordinators::get(transaction, activity_id)? else {
        return Err(WorkspaceStoreError::ActivityLeaseUnavailable(activity_id));
    };
    if coordinator.workspace_id() != workspace_id
        || coordinator.activity_id() != activity_id
        || coordinator.agent_id() != actor.agent_id()
        || coordinator.revision() != actor.expected_revision()
    {
        return Err(WorkspaceStoreError::ActivityLeaseUnavailable(activity_id));
    }
    let Some(agent) = crate::workspace_agents::get(transaction, actor.agent_id())? else {
        return Err(WorkspaceStoreError::ActivityLeaseUnavailable(activity_id));
    };
    if agent.workspace_id() != workspace_id
        || agent.activity_id() != activity_id
        || !agent.attachment_state().is_attached()
        || agent.session_id() != Some(actor.session_id())
        || agent.principal() != actor.principal()
    {
        return Err(WorkspaceStoreError::ActivityLeaseUnavailable(activity_id));
    }
    Ok(())
}

struct ClosePreflight<'a> {
    command: &'a CloseActivity,
    current: RegisteredActivity,
    next_activity_revision: Option<ActivityRevision>,
    next_lease_revision: Option<ActivityLeaseRevision>,
}

struct ReleasePreflight<'a> {
    command: &'a ReleaseActivityLease,
    current: RegisteredActivity,
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

fn apply_release_preflight(
    transaction: &Transaction<'_>,
    preflight: &[ReleasePreflight<'_>],
) -> Result<Vec<RegisteredActivity>, WorkspaceStoreError> {
    let mut released_activities = Vec::with_capacity(preflight.len());
    for item in preflight {
        let Some(next_lease_revision) = item.next_lease_revision else {
            released_activities.push(item.current.clone());
            continue;
        };
        let owner = item.command.owner_id().into_uuid().into_bytes();
        let id = item.command.id().into_uuid().into_bytes();
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
        released_activities.push(decode_activity(&updated)?);
    }
    Ok(released_activities)
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

fn validate_same_owner_for_releases(
    commands: &[ReleaseActivityLease],
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
    Outdated { version: i64 },
    Current,
}

fn compatible_read_only_shape(
    ownership: DatabaseOwnership,
) -> Result<WorkspaceSchemaShape, WorkspaceStoreError> {
    match ownership {
        DatabaseOwnership::Current => Ok(WorkspaceSchemaShape::Current),
        DatabaseOwnership::Outdated { version }
            if version == PREVIOUS_QUIESCENT_ACTIVITY_LEASE_RESUME_SCHEMA_VERSION =>
        {
            Ok(WorkspaceSchemaShape::V68)
        }
        DatabaseOwnership::Outdated { version }
            if version == PREVIOUS_DELEGATED_ROOT_RECOVERY_SCHEMA_VERSION =>
        {
            Ok(WorkspaceSchemaShape::V62)
        }
        DatabaseOwnership::Outdated { version }
            if version == PREVIOUS_ROOT_RECOVERY_SCHEMA_VERSION =>
        {
            Ok(WorkspaceSchemaShape::V61)
        }
        DatabaseOwnership::Outdated { version } => Err(WorkspaceStoreError::OutdatedSchema {
            actual: version,
            current: CURRENT_SCHEMA_VERSION,
        }),
        DatabaseOwnership::Fresh => Err(WorkspaceStoreError::FreshDatabase),
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

fn map_agent_operations_migration_error(
    error: crate::AgentOperationsMigrationError,
) -> WorkspaceStoreError {
    let uncertain = matches!(
        &error,
        crate::AgentOperationsMigrationError::CommitUnconfirmed { .. }
    );
    let source = WorkspaceStoreError::AgentOperationsMigration(error);
    if uncertain {
        WorkspaceStoreError::AgentOperationsMigrationCommittedUnconfirmed {
            source: Box::new(source),
        }
    } else {
        source
    }
}

fn prepare_database(
    connection: &mut Connection,
    busy_timeout: Duration,
    allow_fresh: bool,
) -> Result<(), WorkspaceStoreError> {
    match inspect_database(connection)? {
        DatabaseOwnership::Fresh if allow_fresh => {
            configure_connection(connection, busy_timeout)?;
            initialize_fresh_schema(connection)?;
        }
        DatabaseOwnership::Fresh => return Err(WorkspaceStoreError::FreshDatabase),
        DatabaseOwnership::Outdated { version } => {
            migrate_outdated_schema(connection, busy_timeout, version)?;
            // Historical additive upgrades commit their original v55 shape.
            // The parent-table rebuild needs its own transaction so foreign
            // keys can be disabled before BEGIN and restored on every exit.
            if schema_version(connection)? == PREVIOUS_AUTO_APPROVAL_SCHEMA_VERSION {
                migrate_unlimited_auto_approval_schema(connection, busy_timeout)?;
            }
            if schema_version(connection)? == PREVIOUS_EXECUTION_STOPS_SCHEMA_VERSION {
                migrate_execution_stops_schema(connection, busy_timeout)?;
            }
            if schema_version(connection)? == PREVIOUS_STOP_AUTHORITY_SCHEMA_VERSION {
                migrate_stop_authority_schema(connection, busy_timeout)?;
            }
            if schema_version(connection)? == PREVIOUS_NATIVE_CLOSURE_SCHEMA_VERSION {
                migrate_native_closure_schema(connection, busy_timeout)?;
            }
            if schema_version(connection)? == PREVIOUS_STOP_SETTLEMENT_SCHEMA_VERSION {
                migrate_stop_settlement_schema(connection, busy_timeout)?;
            }
            if schema_version(connection)? == PREVIOUS_RECOVERY_RUNS_SCHEMA_VERSION {
                migrate_recovery_runs_schema(connection, busy_timeout)?;
            }
            if schema_version(connection)? == PREVIOUS_ROOT_RECOVERY_SCHEMA_VERSION {
                migrate_root_recovery_schema(connection, busy_timeout)?;
            }
            if schema_version(connection)? == PREVIOUS_DELEGATED_ROOT_RECOVERY_SCHEMA_VERSION {
                migrate_delegated_root_recovery_schema(connection, busy_timeout)?;
            }
            if schema_version(connection)? == PREVIOUS_EXPIRED_ACTIVITY_RECOVERY_SCHEMA_VERSION {
                migrate_expired_activity_recovery_schema(connection, busy_timeout)?;
            }
            if schema_version(connection)? == PREVIOUS_BINDING_REJECTION_SCHEMA_VERSION {
                migrate_binding_rejection_schema(connection, busy_timeout)?;
            }
            if schema_version(connection)?
                == PREVIOUS_UNSTARTED_ACTIVITY_CONTINUATION_SCHEMA_VERSION
            {
                migrate_unstarted_activity_continuation_schema(connection, busy_timeout)?;
            }
            if schema_version(connection)? == PREVIOUS_STARTED_ACTIVITY_LEASE_RESUME_SCHEMA_VERSION
            {
                migrate_started_activity_lease_resume_schema(connection, busy_timeout)?;
            }
            if schema_version(connection)? == PREVIOUS_ADMISSION_IDENTITY_SCHEMA_VERSION {
                migrate_admission_identity_schema(connection, busy_timeout)?;
            }
            if schema_version(connection)?
                == PREVIOUS_QUIESCENT_ACTIVITY_LEASE_RESUME_SCHEMA_VERSION
            {
                migrate_quiescent_activity_lease_resume_schema(connection, busy_timeout)?;
            }
        }
        DatabaseOwnership::Current => configure_connection(connection, busy_timeout)?,
    }
    validate_schema_shape(connection)
}

fn prepare_database_current_only(
    connection: &mut Connection,
    busy_timeout: Duration,
) -> Result<(), WorkspaceStoreError> {
    match inspect_database(connection)? {
        DatabaseOwnership::Fresh => Err(WorkspaceStoreError::FreshDatabase),
        DatabaseOwnership::Outdated { version } => Err(WorkspaceStoreError::OutdatedSchema {
            actual: version,
            current: CURRENT_SCHEMA_VERSION,
        }),
        DatabaseOwnership::Current => {
            configure_connection(connection, busy_timeout)?;
            validate_schema_shape(connection)
        }
    }
}

fn migrate_unlimited_auto_approval_schema(
    connection: &mut Connection,
    busy_timeout: Duration,
) -> Result<(), WorkspaceStoreError> {
    validate_schema_shape_for_version(connection, WorkspaceSchemaShape::V55)?;
    configure_connection(connection, busy_timeout)?;
    // SQLite parent-table rebuild protocol: changing this pragma inside the
    // transaction has no effect. Referencing grants are preserved, not deleted.
    connection.pragma_update(None, "foreign_keys", false)?;
    let result = commit_unlimited_auto_approval_schema(connection);
    let restore = connection
        .pragma_update(None, "foreign_keys", true)
        .map_err(WorkspaceStoreError::from);
    result.and(restore)
}

fn commit_unlimited_auto_approval_schema(
    connection: &mut Connection,
) -> Result<(), WorkspaceStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let version = schema_version(&transaction)?;
    if version == PREVIOUS_EXECUTION_STOPS_SCHEMA_VERSION {
        validate_schema_shape_for_version(&transaction, WorkspaceSchemaShape::V56)?;
        transaction.commit()?;
        return Ok(());
    }
    if version != PREVIOUS_AUTO_APPROVAL_SCHEMA_VERSION {
        return Err(WorkspaceStoreError::DamagedSchema {
            detail: "auto-approval migration source revision changed".to_owned(),
        });
    }
    validate_schema_shape_for_version(&transaction, WorkspaceSchemaShape::V55)?;
    workspace_approvals::migrate_unlimited_scope_schema(&transaction)?;
    workspace_agent_migration::install_approval_authority_fences(&transaction)?;
    let foreign_key_violation = {
        let mut statement = transaction.prepare("PRAGMA foreign_key_check")?;
        let mut rows = statement.query([])?;
        rows.next()?.is_some()
    };
    if foreign_key_violation {
        return Err(WorkspaceStoreError::DamagedSchema {
            detail: "auto-approval migration failed foreign-key validation".to_owned(),
        });
    }
    validate_schema_shape_for_version(&transaction, WorkspaceSchemaShape::V56)?;
    transaction.pragma_update(
        None,
        "user_version",
        PREVIOUS_EXECUTION_STOPS_SCHEMA_VERSION,
    )?;
    transaction.commit()?;
    Ok(())
}

fn migrate_execution_stops_schema(
    connection: &mut Connection,
    busy_timeout: Duration,
) -> Result<(), WorkspaceStoreError> {
    validate_schema_shape_for_version(connection, WorkspaceSchemaShape::V56)?;
    configure_connection(connection, busy_timeout)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if schema_version(&transaction)? != PREVIOUS_EXECUTION_STOPS_SCHEMA_VERSION {
        return Err(WorkspaceStoreError::DamagedSchema {
            detail: "execution-stop migration source revision changed".to_owned(),
        });
    }
    validate_schema_shape_for_version(&transaction, WorkspaceSchemaShape::V56)?;
    workspace_execution_stops::create_schema_v59(&transaction)?;
    validate_schema_shape_for_version(&transaction, WorkspaceSchemaShape::V57)?;
    transaction.pragma_update(None, "user_version", PREVIOUS_STOP_AUTHORITY_SCHEMA_VERSION)?;
    transaction.commit()?;
    Ok(())
}

fn migrate_stop_authority_schema(
    connection: &mut Connection,
    busy_timeout: Duration,
) -> Result<(), WorkspaceStoreError> {
    validate_schema_shape_for_version(connection, WorkspaceSchemaShape::V57)?;
    configure_connection(connection, busy_timeout)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if schema_version(&transaction)? != PREVIOUS_STOP_AUTHORITY_SCHEMA_VERSION {
        return Err(WorkspaceStoreError::DamagedSchema {
            detail: "stop authority migration source revision changed".to_owned(),
        });
    }
    validate_schema_shape_for_version(&transaction, WorkspaceSchemaShape::V57)?;
    workspace_approvals::cleanup::stop_receipts::create_schema(&transaction)?;
    validate_schema_shape_for_version(&transaction, WorkspaceSchemaShape::V58)?;
    transaction.pragma_update(None, "user_version", PREVIOUS_NATIVE_CLOSURE_SCHEMA_VERSION)?;
    transaction.commit()?;
    Ok(())
}

fn migrate_native_closure_schema(
    connection: &mut Connection,
    busy_timeout: Duration,
) -> Result<(), WorkspaceStoreError> {
    validate_schema_shape_for_version(connection, WorkspaceSchemaShape::V58)?;
    configure_connection(connection, busy_timeout)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if schema_version(&transaction)? != PREVIOUS_NATIVE_CLOSURE_SCHEMA_VERSION {
        return Err(WorkspaceStoreError::DamagedSchema {
            detail: "native closure migration source revision changed".to_owned(),
        });
    }
    validate_schema_shape_for_version(&transaction, WorkspaceSchemaShape::V58)?;
    workspace_executions::native_closure::create_schema(&transaction)?;
    validate_schema_shape_for_version(&transaction, WorkspaceSchemaShape::V59)?;
    transaction.pragma_update(
        None,
        "user_version",
        PREVIOUS_STOP_SETTLEMENT_SCHEMA_VERSION,
    )?;
    transaction.commit()?;
    Ok(())
}

fn migrate_recovery_runs_schema(
    connection: &mut Connection,
    busy_timeout: Duration,
) -> Result<(), WorkspaceStoreError> {
    validate_schema_shape_for_version(connection, WorkspaceSchemaShape::V60)?;
    configure_connection(connection, busy_timeout)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if schema_version(&transaction)? != PREVIOUS_RECOVERY_RUNS_SCHEMA_VERSION {
        return Err(WorkspaceStoreError::DamagedSchema {
            detail: "recovery history migration source changed".to_owned(),
        });
    }
    validate_schema_shape_for_version(&transaction, WorkspaceSchemaShape::V60)?;
    crate::workspace_recovery_runs::create_schema(&transaction)?;
    validate_schema_shape_for_version(&transaction, WorkspaceSchemaShape::V61)?;
    transaction.pragma_update(None, "user_version", PREVIOUS_ROOT_RECOVERY_SCHEMA_VERSION)?;
    transaction.commit()?;
    Ok(())
}

fn migrate_root_recovery_schema(
    connection: &mut Connection,
    busy_timeout: Duration,
) -> Result<(), WorkspaceStoreError> {
    validate_schema_shape_for_version(connection, WorkspaceSchemaShape::V61)?;
    configure_connection(connection, busy_timeout)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if schema_version(&transaction)? != PREVIOUS_ROOT_RECOVERY_SCHEMA_VERSION {
        return Err(WorkspaceStoreError::DamagedSchema {
            detail: "root recovery migration source revision changed".to_owned(),
        });
    }
    validate_schema_shape_for_version(&transaction, WorkspaceSchemaShape::V61)?;
    root_recovery::create_base_schema(&transaction)?;
    validate_schema_shape_for_version(&transaction, WorkspaceSchemaShape::V62)?;
    transaction.pragma_update(
        None,
        "user_version",
        PREVIOUS_DELEGATED_ROOT_RECOVERY_SCHEMA_VERSION,
    )?;
    transaction.commit()?;
    Ok(())
}

fn migrate_delegated_root_recovery_schema(
    connection: &mut Connection,
    busy_timeout: Duration,
) -> Result<(), WorkspaceStoreError> {
    validate_schema_shape_for_version(connection, WorkspaceSchemaShape::V62)?;
    configure_connection(connection, busy_timeout)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if schema_version(&transaction)? != PREVIOUS_DELEGATED_ROOT_RECOVERY_SCHEMA_VERSION {
        return Err(WorkspaceStoreError::DamagedSchema {
            detail: "delegated root recovery migration source revision changed".to_owned(),
        });
    }
    validate_schema_shape_for_version(&transaction, WorkspaceSchemaShape::V62)?;
    root_recovery::create_delegation_schema(&transaction)?;
    transaction.pragma_update(
        None,
        "user_version",
        PREVIOUS_EXPIRED_ACTIVITY_RECOVERY_SCHEMA_VERSION,
    )?;
    validate_schema_shape_for_version(&transaction, WorkspaceSchemaShape::V63)?;
    transaction.commit()?;
    Ok(())
}

fn migrate_expired_activity_recovery_schema(
    connection: &mut Connection,
    busy_timeout: Duration,
) -> Result<(), WorkspaceStoreError> {
    validate_schema_shape_for_version(connection, WorkspaceSchemaShape::V63)?;
    configure_connection(connection, busy_timeout)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if schema_version(&transaction)? != PREVIOUS_EXPIRED_ACTIVITY_RECOVERY_SCHEMA_VERSION {
        return Err(WorkspaceStoreError::DamagedSchema {
            detail: "expired Activity recovery migration source revision changed".to_owned(),
        });
    }
    let existing_v64_objects: i64 = transaction.query_row(
        "SELECT COUNT(*) FROM sqlite_schema WHERE (type = 'table' AND name IN ('expired_activity_recovery_receipts', 'expired_activity_recovery_agents')) OR (type = 'index' AND name = 'expired_activity_recovery_receipts_successor_uidx')",
        [],
        |row| row.get(0),
    )?;
    if existing_v64_objects == 0 {
        crate::workspace_expired_activity_recovery::create_schema(&transaction).map_err(
            |error| WorkspaceStoreError::DamagedSchema {
                detail: error.to_string(),
            },
        )?;
    } else if existing_v64_objects != 3 {
        return Err(WorkspaceStoreError::DamagedSchema {
            detail: "schema-v64 recovery objects are only partially present".to_owned(),
        });
    }
    transaction.pragma_update(
        None,
        "user_version",
        PREVIOUS_BINDING_REJECTION_SCHEMA_VERSION,
    )?;
    validate_schema_shape_for_version(&transaction, WorkspaceSchemaShape::V64)?;
    transaction.commit()?;
    Ok(())
}

fn migrate_binding_rejection_schema(
    connection: &mut Connection,
    busy_timeout: Duration,
) -> Result<(), WorkspaceStoreError> {
    validate_schema_shape_for_version(connection, WorkspaceSchemaShape::V64)?;
    configure_connection(connection, busy_timeout)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if schema_version(&transaction)? != PREVIOUS_BINDING_REJECTION_SCHEMA_VERSION {
        return Err(WorkspaceStoreError::DamagedSchema {
            detail: "binding rejection migration source revision changed".to_owned(),
        });
    }
    crate::workspace_agent_binding_rejections::create_schema(&transaction).map_err(|error| {
        WorkspaceStoreError::DamagedSchema {
            detail: error.to_string(),
        }
    })?;
    transaction.pragma_update(
        None,
        "user_version",
        PREVIOUS_UNSTARTED_ACTIVITY_CONTINUATION_SCHEMA_VERSION,
    )?;
    validate_schema_shape_for_version(&transaction, WorkspaceSchemaShape::V65)?;
    transaction.commit()?;
    Ok(())
}

fn migrate_unstarted_activity_continuation_schema(
    connection: &mut Connection,
    busy_timeout: Duration,
) -> Result<(), WorkspaceStoreError> {
    validate_schema_shape_for_version(connection, WorkspaceSchemaShape::V65)?;
    configure_connection(connection, busy_timeout)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    crate::workspace_unstarted_activity_continuation::create_schema(&transaction).map_err(
        |error| WorkspaceStoreError::DamagedSchema {
            detail: error.to_string(),
        },
    )?;
    transaction.pragma_update(
        None,
        "user_version",
        PREVIOUS_STARTED_ACTIVITY_LEASE_RESUME_SCHEMA_VERSION,
    )?;
    validate_schema_shape_for_version(&transaction, WorkspaceSchemaShape::V66)?;
    transaction.commit()?;
    Ok(())
}

fn migrate_started_activity_lease_resume_schema(
    connection: &mut Connection,
    busy_timeout: Duration,
) -> Result<(), WorkspaceStoreError> {
    validate_schema_shape_for_version(connection, WorkspaceSchemaShape::V66)?;
    configure_connection(connection, busy_timeout)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    crate::workspace_started_activity_lease_resumes::create_schema(&transaction).map_err(
        |error| WorkspaceStoreError::DamagedSchema {
            detail: error.to_string(),
        },
    )?;
    transaction.pragma_update(
        None,
        "user_version",
        PREVIOUS_ADMISSION_IDENTITY_SCHEMA_VERSION,
    )?;
    validate_schema_shape_for_version(&transaction, WorkspaceSchemaShape::V67)?;
    transaction.commit()?;
    Ok(())
}

fn migrate_admission_identity_schema(
    connection: &mut Connection,
    busy_timeout: Duration,
) -> Result<(), WorkspaceStoreError> {
    validate_schema_shape_for_version(connection, WorkspaceSchemaShape::V67)?;
    configure_connection(connection, busy_timeout)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    workspace_admission_envelopes::migrate_identity_schema(&transaction)?;
    transaction.pragma_update(
        None,
        "user_version",
        PREVIOUS_QUIESCENT_ACTIVITY_LEASE_RESUME_SCHEMA_VERSION,
    )?;
    validate_schema_shape_for_version(&transaction, WorkspaceSchemaShape::V68)?;
    transaction.commit()?;
    Ok(())
}

fn migrate_quiescent_activity_lease_resume_schema(
    connection: &mut Connection,
    busy_timeout: Duration,
) -> Result<(), WorkspaceStoreError> {
    validate_schema_shape_for_version(connection, WorkspaceSchemaShape::V68)?;
    configure_connection(connection, busy_timeout)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if schema_version(&transaction)? != PREVIOUS_QUIESCENT_ACTIVITY_LEASE_RESUME_SCHEMA_VERSION {
        return Err(WorkspaceStoreError::DamagedSchema {
            detail: "quiescent Activity lease-resume migration source changed".to_owned(),
        });
    }
    crate::workspace_quiescent_activity_lease_resumes::create_schema(&transaction).map_err(
        |error| WorkspaceStoreError::DamagedSchema {
            detail: error.to_string(),
        },
    )?;
    transaction.pragma_update(None, "user_version", CURRENT_SCHEMA_VERSION)?;
    validate_schema_shape_for_version(&transaction, WorkspaceSchemaShape::Current)?;
    transaction.commit()?;
    Ok(())
}

fn migrate_stop_settlement_schema(
    connection: &mut Connection,
    busy_timeout: Duration,
) -> Result<(), WorkspaceStoreError> {
    validate_schema_shape_for_version(connection, WorkspaceSchemaShape::V59)?;
    configure_connection(connection, busy_timeout)?;
    connection.pragma_update(None, "foreign_keys", false)?;
    let result = commit_stop_settlement_schema(connection);
    let restore = connection
        .pragma_update(None, "foreign_keys", true)
        .map_err(WorkspaceStoreError::from);
    result.and(restore)
}

fn commit_stop_settlement_schema(connection: &mut Connection) -> Result<(), WorkspaceStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if schema_version(&transaction)? != PREVIOUS_STOP_SETTLEMENT_SCHEMA_VERSION {
        return Err(WorkspaceStoreError::DamagedSchema {
            detail: "stop settlement migration source revision changed".to_owned(),
        });
    }
    validate_schema_shape_for_version(&transaction, WorkspaceSchemaShape::V59)?;
    workspace_execution_stops::rebuild_capture_v60(&transaction)?;
    workspace_execution_stops::settlement::create_schema(&transaction)?;
    workspace_execution_stops::settlement::populate_legacy_fences(&transaction)?;
    let violation = transaction
        .query_row("PRAGMA foreign_key_check", [], |_| Ok(()))
        .optional()?;
    if violation.is_some() {
        return Err(WorkspaceStoreError::DamagedSchema {
            detail: "stop settlement migration foreign key mismatch".to_owned(),
        });
    }
    validate_schema_shape_for_version(&transaction, WorkspaceSchemaShape::V60)?;
    transaction.pragma_update(None, "user_version", PREVIOUS_RECOVERY_RUNS_SCHEMA_VERSION)?;
    transaction.commit()?;
    Ok(())
}

/// Dispatch one exactly-supported previous schema version to its checked
/// migration; every other version fails closed without mutation.
#[allow(
    clippy::too_many_lines,
    reason = "Keep supported historical-schema dispatch in one reviewed match."
)]
fn migrate_outdated_schema(
    connection: &mut Connection,
    busy_timeout: Duration,
    version: i64,
) -> Result<(), WorkspaceStoreError> {
    match version {
        PREVIOUS_QUIESCENT_ACTIVITY_LEASE_RESUME_SCHEMA_VERSION => {
            migrate_quiescent_activity_lease_resume_schema(connection, busy_timeout)
        }
        PREVIOUS_ADMISSION_IDENTITY_SCHEMA_VERSION => {
            migrate_admission_identity_schema(connection, busy_timeout)
        }
        PREVIOUS_STARTED_ACTIVITY_LEASE_RESUME_SCHEMA_VERSION => {
            migrate_started_activity_lease_resume_schema(connection, busy_timeout)
        }
        PREVIOUS_UNSTARTED_ACTIVITY_CONTINUATION_SCHEMA_VERSION => {
            migrate_unstarted_activity_continuation_schema(connection, busy_timeout)
        }
        PREVIOUS_DELEGATED_ROOT_RECOVERY_SCHEMA_VERSION => {
            migrate_delegated_root_recovery_schema(connection, busy_timeout)
        }
        PREVIOUS_EXPIRED_ACTIVITY_RECOVERY_SCHEMA_VERSION => {
            migrate_expired_activity_recovery_schema(connection, busy_timeout)
        }
        PREVIOUS_BINDING_REJECTION_SCHEMA_VERSION => {
            migrate_binding_rejection_schema(connection, busy_timeout)
        }
        PREVIOUS_ROOT_RECOVERY_SCHEMA_VERSION => {
            migrate_root_recovery_schema(connection, busy_timeout)
        }
        PREVIOUS_RECOVERY_RUNS_SCHEMA_VERSION => {
            migrate_recovery_runs_schema(connection, busy_timeout)
        }
        PREVIOUS_STOP_SETTLEMENT_SCHEMA_VERSION => {
            migrate_stop_settlement_schema(connection, busy_timeout)
        }
        PREVIOUS_NATIVE_CLOSURE_SCHEMA_VERSION => {
            migrate_native_closure_schema(connection, busy_timeout)
        }
        PREVIOUS_STOP_AUTHORITY_SCHEMA_VERSION => {
            migrate_stop_authority_schema(connection, busy_timeout)
        }
        PREVIOUS_EXECUTION_STOPS_SCHEMA_VERSION => {
            migrate_execution_stops_schema(connection, busy_timeout)
        }
        PREVIOUS_AUTO_APPROVAL_SCHEMA_VERSION => {
            migrate_unlimited_auto_approval_schema(connection, busy_timeout)
        }
        PREVIOUS_WORK_CUT_CONTINUATIONS_SCHEMA_VERSION => {
            migrate_work_cut_continuations_schema(connection, busy_timeout)
        }
        PREVIOUS_WORK_CUTS_SCHEMA_VERSION => migrate_work_cuts_schema(connection, busy_timeout),
        PREVIOUS_ASSIGNMENT_OFFER_SEALS_SCHEMA_VERSION => {
            migrate_agent_assignment_offer_seals_schema(connection, busy_timeout)
        }
        PREVIOUS_GOAL_CREATION_WATERMARK_SCHEMA_VERSION => {
            migrate_goal_creation_watermark_schema(connection, busy_timeout)
        }
        PREVIOUS_COORDINATOR_RECOVERY_SCHEMA_VERSION => {
            migrate_coordinator_recovery_schema(connection, busy_timeout)
        }

        PREVIOUS_SCHEMA_VERSION => {
            validate_schema_shape_for_version(connection, WorkspaceSchemaShape::V30)?;
            configure_connection(connection, busy_timeout)?;
            migrate_previous_schema(connection)
        }
        PREVIOUS_MODERN_SCHEMA_VERSION => {
            validate_schema_shape_for_version(connection, WorkspaceSchemaShape::V31)?;
            configure_connection(connection, busy_timeout)?;
            migrate_current_schema(connection)
        }
        PREVIOUS_LATEST_SCHEMA_VERSION => {
            validate_schema_shape_for_version(connection, WorkspaceSchemaShape::V32)?;
            configure_connection(connection, busy_timeout)?;
            migrate_previous_queue_settings_schema(connection)
        }
        PREVIOUS_QUEUE_SCHEMA_VERSION => {
            validate_schema_shape_for_version(connection, WorkspaceSchemaShape::V33)?;
            configure_connection(connection, busy_timeout)?;
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            create_assignment_deletion_schema(&transaction)?;
            workspace_agent_migration::create_schema(&transaction)?;
            workspace_agent_binding_reservations::create_schema(&transaction)?;
            create_delegated_effect_schema(&transaction)?;
            commit_schema_migration(transaction)
        }
        PREVIOUS_OPERATIONS_SCHEMA_VERSION => {
            validate_schema_shape_for_version(connection, WorkspaceSchemaShape::V34)?;
            configure_connection(connection, busy_timeout)?;
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            workspace_agent_assignments::add_credit_budget_column(&transaction)?;
            workspace_agent_migration::create_schema(&transaction)?;
            workspace_agent_binding_reservations::create_schema(&transaction)?;
            create_delegated_effect_schema(&transaction)?;
            commit_schema_migration(transaction)
        }
        PREVIOUS_BINDING_SCHEMA_VERSION => {
            validate_schema_shape_for_version(connection, WorkspaceSchemaShape::V35)?;
            configure_connection(connection, busy_timeout)?;
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            workspace_agent_assignments::add_credit_budget_column(&transaction)?;
            workspace_agent_binding_reservations::create_schema(&transaction)?;
            create_delegated_effect_schema(&transaction)?;
            commit_schema_migration(transaction)
        }
        PREVIOUS_DELEGATED_SCHEMA_VERSION => {
            validate_schema_shape_for_version(connection, WorkspaceSchemaShape::V36)?;
            configure_connection(connection, busy_timeout)?;
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            workspace_agent_assignments::add_credit_budget_column(&transaction)?;
            create_delegated_effect_schema(&transaction)?;
            commit_schema_migration(transaction)
        }
        PREVIOUS_RECONCILIATION_SCHEMA_VERSION => {
            migrate_reconciliation_schema(connection, busy_timeout)
        }
        PREVIOUS_DEPARTURE_RECONCILIATION_SCHEMA_VERSION => {
            migrate_departure_reconciliation_schema(connection, busy_timeout)
        }
        PREVIOUS_CHANGE_SET_FACT_SCHEMA_VERSION => {
            migrate_change_set_fact_schema(connection, busy_timeout)
        }
        PREVIOUS_EFFECT_FACT_SCHEMA_VERSION => migrate_effect_fact_schema(connection, busy_timeout),
        PREVIOUS_WORK_CREDIT_SCHEMA_VERSION => migrate_work_credit_schema(connection, busy_timeout),
        PREVIOUS_ASSIGNMENT_OFFERED_SCHEMA_VERSION => {
            migrate_assignment_offered_schema(connection, busy_timeout)
        }
        PREVIOUS_ASSIGNMENT_SUBMITTED_SCHEMA_VERSION => {
            migrate_assignment_submitted_schema(connection, busy_timeout)
        }
        PREVIOUS_SEMANTIC_EVENTS_SCHEMA_VERSION => {
            migrate_semantic_events_schema(connection, busy_timeout)
        }
        PREVIOUS_ADMISSION_ENVELOPE_SCHEMA_VERSION => {
            migrate_admission_envelope_schema(connection, busy_timeout)
        }
        PREVIOUS_CHANGE_SET_PRODUCER_SCHEMA_VERSION => {
            migrate_change_set_producer_schema(connection, busy_timeout)
        }
        PREVIOUS_SOURCE_REFS_SCHEMA_VERSION => migrate_source_refs_schema(connection, busy_timeout),
        PREVIOUS_GOAL_MUTATION_RECEIPTS_SCHEMA_VERSION => {
            migrate_goal_mutation_receipts_schema(connection, busy_timeout)
        }
        PREVIOUS_APPROVAL_AUTHORITY_FENCE_SCHEMA_VERSION => {
            migrate_approval_authority_fence_schema(connection, busy_timeout)
        }
        actual => Err(WorkspaceStoreError::OutdatedSchema {
            actual,
            current: CURRENT_SCHEMA_VERSION,
        }),
    }
}

/// Upgrade the exact schema-v54 shape by creating the empty continuation journal.
fn migrate_work_cut_continuations_schema(
    connection: &mut Connection,
    busy_timeout: Duration,
) -> Result<(), WorkspaceStoreError> {
    validate_schema_shape_for_version(connection, WorkspaceSchemaShape::V54)?;
    configure_connection(connection, busy_timeout)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    commit_schema_55_migration(transaction, PREVIOUS_AUTO_APPROVAL_SCHEMA_VERSION)
}

/// Upgrade the exact schema-v53 shape through the work-cut and continuation journals.
fn migrate_work_cuts_schema(
    connection: &mut Connection,
    busy_timeout: Duration,
) -> Result<(), WorkspaceStoreError> {
    validate_schema_shape_for_version(connection, WorkspaceSchemaShape::V53)?;
    configure_connection(connection, busy_timeout)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    commit_schema_54_migration(transaction, PREVIOUS_AUTO_APPROVAL_SCHEMA_VERSION)
}

/// Upgrade the exact schema-v50 shape with Coordinator recovery and Goal fences.
fn migrate_coordinator_recovery_schema(
    connection: &mut Connection,
    busy_timeout: Duration,
) -> Result<(), WorkspaceStoreError> {
    validate_schema_shape_for_version(connection, WorkspaceSchemaShape::V50)?;
    configure_connection(connection, busy_timeout)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    workspace_coordinator_recovery::create_schema(&transaction)?;
    commit_current_schema_migration(transaction)
}

/// Upgrade the exact schema-v51 shape by adding the Goal creation watermark,
/// empty Assignment offer-seal table, the schema-v54 work-cut journal, and the
/// schema-v55 continuation journal. The
/// watermark backfill can recover current Goal rows, exact pending-deletion
/// timestamps, and retained `GoalCreated` events. Deleted lifetimes from before
/// semantic `GoalCreated` events existed have no durable source and cannot be
/// reconstructed.
fn migrate_goal_creation_watermark_schema(
    connection: &mut Connection,
    busy_timeout: Duration,
) -> Result<(), WorkspaceStoreError> {
    validate_schema_shape_for_version(connection, WorkspaceSchemaShape::V51)?;
    configure_connection(connection, busy_timeout)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    commit_current_schema_migration(transaction)
}

/// Upgrade the exact schema-v52 shape through Assignment seals and the empty
/// schema-v54 work-cut and schema-v55 continuation journals in one transaction.
fn migrate_agent_assignment_offer_seals_schema(
    connection: &mut Connection,
    busy_timeout: Duration,
) -> Result<(), WorkspaceStoreError> {
    validate_schema_shape_for_version(connection, WorkspaceSchemaShape::V52)?;
    configure_connection(connection, busy_timeout)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    commit_schema_53_migration(transaction, PREVIOUS_AUTO_APPROVAL_SCHEMA_VERSION)
}

/// Bump the schema version and seal one prepared migration transaction.
fn commit_schema_migration(transaction: Transaction<'_>) -> Result<(), WorkspaceStoreError> {
    workspace_goal_mutations::create_schema(&transaction)?;
    workspace_agent_migration::install_approval_authority_fences(&transaction)?;
    workspace_coordinator_recovery::create_schema(&transaction)?;
    commit_current_schema_migration(transaction)
}

/// Backfill schema-v52 Goal creation history and install the v53-v55 additions
/// in the same transaction that advances `user_version`.
///
/// Historical additive upgrades seal at the v55 shape; `prepare_database`
/// then runs the separate unlimited-auto-approval step to reach the current
/// version. Fresh creation instead builds the current DDL directly and seals
/// through [`commit_fresh_current_schema_migration`].
fn commit_current_schema_migration(
    transaction: Transaction<'_>,
) -> Result<(), WorkspaceStoreError> {
    prepare_schema_53_migration(&transaction)?;
    commit_schema_53_migration(transaction, PREVIOUS_AUTO_APPROVAL_SCHEMA_VERSION)
}

/// Seal the fresh-creation transaction at the current schema version.
///
/// Fresh creation builds the current DDL directly — there is no v55
/// intermediate shape — so stamping the shared v55 seal here would classify
/// every freshly created store as outdated on first reopen.
fn commit_fresh_current_schema_migration(
    transaction: Transaction<'_>,
) -> Result<(), WorkspaceStoreError> {
    prepare_schema_53_migration(&transaction)?;
    workspace_execution_stops::create_schema(&transaction)?;
    workspace_execution_stops::settlement::create_schema(&transaction)?;
    workspace_approvals::cleanup::stop_receipts::create_schema(&transaction)?;
    workspace_executions::native_closure::create_schema(&transaction)?;
    crate::workspace_recovery_runs::create_schema(&transaction)?;
    root_recovery::create_schema(&transaction)?;
    crate::workspace_expired_activity_recovery::create_schema(&transaction).map_err(|error| {
        WorkspaceStoreError::DamagedSchema {
            detail: error.to_string(),
        }
    })?;
    crate::workspace_agent_binding_rejections::create_schema(&transaction).map_err(|error| {
        WorkspaceStoreError::DamagedSchema {
            detail: error.to_string(),
        }
    })?;
    crate::workspace_unstarted_activity_continuation::create_schema(&transaction).map_err(
        |error| WorkspaceStoreError::DamagedSchema {
            detail: error.to_string(),
        },
    )?;
    crate::workspace_started_activity_lease_resumes::create_schema(&transaction).map_err(
        |error| WorkspaceStoreError::DamagedSchema {
            detail: error.to_string(),
        },
    )?;
    crate::workspace_quiescent_activity_lease_resumes::create_schema(&transaction).map_err(
        |error| WorkspaceStoreError::DamagedSchema {
            detail: error.to_string(),
        },
    )?;
    workspace_admission_envelopes::migrate_identity_schema(&transaction)?;
    commit_schema_53_migration(transaction, CURRENT_SCHEMA_VERSION)
}

fn prepare_schema_53_migration(transaction: &Transaction<'_>) -> Result<(), WorkspaceStoreError> {
    workspace_goal_creation_watermarks::create_schema(transaction)?;
    workspace_goal_creation_watermarks::backfill(transaction)?;
    Ok(())
}

fn commit_schema_53_migration(
    transaction: Transaction<'_>,
    seal_version: i64,
) -> Result<(), WorkspaceStoreError> {
    workspace_agent_assignments::create_offer_seal_schema(&transaction)?;
    commit_schema_54_migration(transaction, seal_version)
}

fn commit_schema_54_migration(
    transaction: Transaction<'_>,
    seal_version: i64,
) -> Result<(), WorkspaceStoreError> {
    workspace_work_cuts::create_schema(&transaction)?;
    commit_schema_55_migration(transaction, seal_version)
}

fn commit_schema_55_migration(
    transaction: Transaction<'_>,
    seal_version: i64,
) -> Result<(), WorkspaceStoreError> {
    workspace_work_cuts::create_continuation_schema(&transaction)?;
    transaction.pragma_update(None, "user_version", seal_version)?;
    transaction.commit()?;
    Ok(())
}

fn migrate_reconciliation_schema(
    connection: &mut Connection,
    busy_timeout: Duration,
) -> Result<(), WorkspaceStoreError> {
    validate_schema_shape_for_version(connection, WorkspaceSchemaShape::V37)?;
    configure_connection(connection, busy_timeout)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    workspace_agent_assignments::add_credit_budget_column(&transaction)?;
    workspace_agent_session_reconciliation::create_schema(&transaction)?;
    workspace_agent_departure_reconciliation::create_schema(&transaction)?;
    workspace_effect_fact_outbox::create_schema(&transaction)?;
    workspace_semantic_events::create_schema(&transaction)?;
    workspace_admission_envelopes::create_legacy_schema(&transaction)?;
    workspace_agent_migration::install_delegated_fences(&transaction)?;
    workspace_goal_mutations::create_schema(&transaction)?;
    workspace_agent_migration::install_approval_authority_fences(&transaction)?;
    workspace_coordinator_recovery::create_schema(&transaction)?;
    commit_current_schema_migration(transaction)
}

fn migrate_departure_reconciliation_schema(
    connection: &mut Connection,
    busy_timeout: Duration,
) -> Result<(), WorkspaceStoreError> {
    validate_schema_shape_for_version(connection, WorkspaceSchemaShape::V38)?;
    configure_connection(connection, busy_timeout)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    workspace_agent_assignments::add_credit_budget_column(&transaction)?;
    workspace_agent_departure_reconciliation::create_schema(&transaction)?;
    workspace_effect_fact_outbox::create_schema(&transaction)?;
    workspace_semantic_events::create_schema(&transaction)?;
    workspace_admission_envelopes::create_legacy_schema(&transaction)?;
    workspace_agent_migration::install_delegated_fences(&transaction)?;
    workspace_goal_mutations::create_schema(&transaction)?;
    workspace_agent_migration::install_approval_authority_fences(&transaction)?;
    workspace_coordinator_recovery::create_schema(&transaction)?;
    commit_current_schema_migration(transaction)
}

fn migrate_effect_fact_schema(
    connection: &mut Connection,
    busy_timeout: Duration,
) -> Result<(), WorkspaceStoreError> {
    validate_schema_shape_for_version(connection, WorkspaceSchemaShape::V39)?;
    configure_connection(connection, busy_timeout)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    workspace_agent_assignments::add_credit_budget_column(&transaction)?;
    workspace_effect_fact_outbox::create_schema(&transaction)?;
    workspace_semantic_events::create_schema(&transaction)?;
    workspace_admission_envelopes::create_legacy_schema(&transaction)?;
    workspace_goal_mutations::create_schema(&transaction)?;
    workspace_agent_migration::install_approval_authority_fences(&transaction)?;
    workspace_coordinator_recovery::create_schema(&transaction)?;
    commit_current_schema_migration(transaction)
}

fn migrate_change_set_fact_schema(
    connection: &mut Connection,
    busy_timeout: Duration,
) -> Result<(), WorkspaceStoreError> {
    validate_schema_shape_for_version(connection, WorkspaceSchemaShape::V40)?;
    configure_connection(connection, busy_timeout)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    workspace_agent_assignments::add_credit_budget_column(&transaction)?;
    workspace_effect_fact_outbox::create_change_set_schema(&transaction)?;
    workspace_effect_fact_outbox::create_work_credit_schema(&transaction)?;
    workspace_effect_fact_outbox::create_assignment_offered_schema(&transaction)?;
    workspace_effect_fact_outbox::create_assignment_submitted_schema(&transaction)?;
    workspace_semantic_events::create_schema(&transaction)?;
    workspace_admission_envelopes::create_legacy_schema(&transaction)?;
    workspace_goal_mutations::create_schema(&transaction)?;
    workspace_agent_migration::install_approval_authority_fences(&transaction)?;
    workspace_coordinator_recovery::create_schema(&transaction)?;
    commit_current_schema_migration(transaction)
}

fn migrate_work_credit_schema(
    connection: &mut Connection,
    busy_timeout: Duration,
) -> Result<(), WorkspaceStoreError> {
    validate_schema_shape_for_version(connection, WorkspaceSchemaShape::V41)?;
    configure_connection(connection, busy_timeout)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    workspace_agent_assignments::add_credit_budget_column(&transaction)?;
    workspace_effect_fact_outbox::add_change_set_producer_columns(&transaction)?;
    workspace_effect_fact_outbox::create_work_credit_schema(&transaction)?;
    workspace_effect_fact_outbox::create_assignment_offered_schema(&transaction)?;
    workspace_effect_fact_outbox::create_assignment_submitted_schema(&transaction)?;
    workspace_semantic_events::create_schema(&transaction)?;
    workspace_admission_envelopes::create_legacy_schema(&transaction)?;
    workspace_goal_mutations::create_schema(&transaction)?;
    workspace_agent_migration::install_approval_authority_fences(&transaction)?;
    workspace_coordinator_recovery::create_schema(&transaction)?;
    commit_current_schema_migration(transaction)
}

/// Direct v42 -> current migration path: create both post-v42 assignment
/// payload tables and the semantic event stream. No durable row is rewritten
/// or fabricated.
fn migrate_assignment_offered_schema(
    connection: &mut Connection,
    busy_timeout: Duration,
) -> Result<(), WorkspaceStoreError> {
    validate_schema_shape_for_version(connection, WorkspaceSchemaShape::V42)?;
    configure_connection(connection, busy_timeout)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    workspace_effect_fact_outbox::add_change_set_producer_columns(&transaction)?;
    workspace_effect_fact_outbox::create_assignment_offered_schema(&transaction)?;
    workspace_effect_fact_outbox::create_assignment_submitted_schema(&transaction)?;
    workspace_semantic_events::create_schema(&transaction)?;
    workspace_admission_envelopes::create_legacy_schema(&transaction)?;
    workspace_goal_mutations::create_schema(&transaction)?;
    workspace_agent_migration::install_approval_authority_fences(&transaction)?;
    workspace_coordinator_recovery::create_schema(&transaction)?;
    commit_current_schema_migration(transaction)
}

/// One additive v43 -> current migration step: create the assignment-submitted
/// payload table and the semantic event stream. No durable row is rewritten or
/// fabricated.
fn migrate_assignment_submitted_schema(
    connection: &mut Connection,
    busy_timeout: Duration,
) -> Result<(), WorkspaceStoreError> {
    validate_schema_shape_for_version(connection, WorkspaceSchemaShape::V43)?;
    configure_connection(connection, busy_timeout)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    workspace_effect_fact_outbox::add_change_set_producer_columns(&transaction)?;
    workspace_effect_fact_outbox::create_assignment_submitted_schema(&transaction)?;
    workspace_semantic_events::create_schema(&transaction)?;
    workspace_admission_envelopes::create_legacy_schema(&transaction)?;
    workspace_goal_mutations::create_schema(&transaction)?;
    workspace_agent_migration::install_approval_authority_fences(&transaction)?;
    workspace_coordinator_recovery::create_schema(&transaction)?;
    commit_current_schema_migration(transaction)
}

/// Direct v44 -> current migration path: add producer attribution, source-ref
/// durability, and the semantic event stream. No durable row is rewritten or
/// fabricated.
fn migrate_semantic_events_schema(
    connection: &mut Connection,
    busy_timeout: Duration,
) -> Result<(), WorkspaceStoreError> {
    validate_schema_shape_for_version(connection, WorkspaceSchemaShape::V44)?;
    configure_connection(connection, busy_timeout)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    workspace_effect_fact_outbox::add_change_set_producer_columns(&transaction)?;
    workspace_effect_fact_outbox::add_assignment_submitted_source_refs(&transaction)?;
    workspace_semantic_events::create_schema(&transaction)?;
    workspace_admission_envelopes::create_legacy_schema(&transaction)?;
    workspace_goal_mutations::create_schema(&transaction)?;
    workspace_agent_migration::install_approval_authority_fences(&transaction)?;
    workspace_coordinator_recovery::create_schema(&transaction)?;
    commit_current_schema_migration(transaction)
}

/// Direct v45 -> current migration path: add producer attribution, source-ref
/// durability, and the execution admission envelope journal. No durable row is
/// rewritten or fabricated.
fn migrate_admission_envelope_schema(
    connection: &mut Connection,
    busy_timeout: Duration,
) -> Result<(), WorkspaceStoreError> {
    validate_schema_shape_for_version(connection, WorkspaceSchemaShape::V45)?;
    configure_connection(connection, busy_timeout)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    workspace_effect_fact_outbox::add_change_set_producer_columns(&transaction)?;
    workspace_effect_fact_outbox::add_assignment_submitted_source_refs(&transaction)?;
    workspace_admission_envelopes::create_legacy_schema(&transaction)?;
    workspace_goal_mutations::create_schema(&transaction)?;
    workspace_agent_migration::install_approval_authority_fences(&transaction)?;
    workspace_coordinator_recovery::create_schema(&transaction)?;
    commit_current_schema_migration(transaction)
}

/// Direct v46 -> current migration path: add change-set producer attribution
/// and submitted source-ref durability. No durable row is rewritten or
/// fabricated; legacy rows keep a `NULL` producer and marker `0`.
fn migrate_change_set_producer_schema(
    connection: &mut Connection,
    busy_timeout: Duration,
) -> Result<(), WorkspaceStoreError> {
    validate_schema_shape_for_version(connection, WorkspaceSchemaShape::V46)?;
    configure_connection(connection, busy_timeout)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    workspace_effect_fact_outbox::add_change_set_producer_columns(&transaction)?;
    workspace_effect_fact_outbox::add_assignment_submitted_source_refs(&transaction)?;
    workspace_goal_mutations::create_schema(&transaction)?;
    workspace_agent_migration::install_approval_authority_fences(&transaction)?;
    workspace_coordinator_recovery::create_schema(&transaction)?;
    commit_current_schema_migration(transaction)
}

/// Direct v47 -> current migration path: record the marker, immutable
/// submitted provenance child table, and Goal mutation receipt schema. Legacy
/// rows keep the default marker `0`; no child or receipt rows are fabricated.
fn migrate_source_refs_schema(
    connection: &mut Connection,
    busy_timeout: Duration,
) -> Result<(), WorkspaceStoreError> {
    validate_schema_shape_for_version(connection, WorkspaceSchemaShape::V47)?;
    configure_connection(connection, busy_timeout)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    workspace_effect_fact_outbox::add_assignment_submitted_source_refs(&transaction)?;
    workspace_goal_mutations::create_schema(&transaction)?;
    workspace_agent_migration::install_approval_authority_fences(&transaction)?;
    workspace_coordinator_recovery::create_schema(&transaction)?;
    commit_current_schema_migration(transaction)
}

/// One additive v48 -> v49 migration step: create the immutable Goal mutation
/// receipt journal. No legacy rows can be reconstructed, so this migration
/// creates only the canonical empty receipt schema.
fn migrate_goal_mutation_receipts_schema(
    connection: &mut Connection,
    busy_timeout: Duration,
) -> Result<(), WorkspaceStoreError> {
    validate_schema_shape_for_version(connection, WorkspaceSchemaShape::V48)?;
    configure_connection(connection, busy_timeout)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    workspace_goal_mutations::create_schema(&transaction)?;
    workspace_agent_migration::install_approval_authority_fences(&transaction)?;
    workspace_coordinator_recovery::create_schema(&transaction)?;
    commit_current_schema_migration(transaction)
}

/// One additive v49 -> v50 migration step: fence the legacy
/// approval-authority tables behind the open-migration boundary.  No legacy
/// row is rewritten or fabricated.
fn migrate_approval_authority_fence_schema(
    connection: &mut Connection,
    busy_timeout: Duration,
) -> Result<(), WorkspaceStoreError> {
    validate_schema_shape_for_version(connection, WorkspaceSchemaShape::V49)?;
    configure_connection(connection, busy_timeout)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    workspace_agent_migration::install_approval_authority_fences(&transaction)?;
    workspace_coordinator_recovery::create_schema(&transaction)?;
    commit_current_schema_migration(transaction)
}

/// Append the terminal `ChangeSet` and Diff semantic events inside the exact
/// transaction that terminalized them, mirroring the effect-fact hook sites.
fn append_change_set_semantic_events(
    transaction: &Transaction<'_>,
    change_set: &forge_domain::RegisteredChangeSet,
    diff: &forge_domain::RegisteredDiffEvidence,
) -> Result<(), WorkspaceStoreError> {
    workspace_semantic_events::append_semantic_event(
        transaction,
        &workspace_semantic_events::SemanticEventAppend::new(
            workspace_semantic_events::SemanticEventKind::ChangeSetTerminal,
            change_set.workspace_id(),
            workspace_semantic_events::SemanticEventSubjects {
                change_set_id: Some(change_set.id()),
                ..workspace_semantic_events::SemanticEventSubjects::NONE
            },
            change_set.revision().get(),
            change_set.updated_at(),
        ),
    )?;
    workspace_semantic_events::append_semantic_event(
        transaction,
        &workspace_semantic_events::SemanticEventAppend::new(
            workspace_semantic_events::SemanticEventKind::DiffTerminal,
            diff.workspace_id(),
            workspace_semantic_events::SemanticEventSubjects {
                change_set_id: Some(diff.change_set_id()),
                diff_id: Some(diff.id()),
                ..workspace_semantic_events::SemanticEventSubjects::NONE
            },
            diff.revision().get(),
            diff.updated_at(),
        ),
    )?;
    Ok(())
}

fn create_assignment_deletion_schema(connection: &Connection) -> Result<(), WorkspaceStoreError> {
    workspace_agent_assignments::create_schema(connection)?;
    workspace_goal_deletion::create_schema(connection)?;
    Ok(())
}

fn create_delegated_effect_schema(connection: &Connection) -> Result<(), WorkspaceStoreError> {
    workspace_agent_effect_outbox::create_schema(connection)?;
    workspace_effect_fact_outbox::create_schema(connection)?;
    workspace_agent_delegation::create_schema(connection)?;
    workspace_agent_binding_activation::create_schema(connection)?;
    workspace_agent_session_reconciliation::create_schema(connection)?;
    workspace_agent_departure_reconciliation::create_schema(connection)?;
    workspace_semantic_events::create_schema(connection)?;
    workspace_admission_envelopes::create_legacy_schema(connection)?;
    workspace_agent_migration::install_delegated_fences(connection)?;
    Ok(())
}

fn migrate_previous_schema(connection: &mut Connection) -> Result<(), WorkspaceStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    workspace_executions::migrate_output_events_to_v31(&transaction)?;
    workspace_verification::migrate_to_v31(&transaction)?;
    workspace_activity_successors::create_schema(&transaction)?;
    workspace_queue_settings::create_schema(&transaction)?;
    create_assignment_deletion_schema(&transaction)?;
    workspace_agent_migration::create_schema(&transaction)?;
    workspace_agent_binding_reservations::create_schema(&transaction)?;
    create_delegated_effect_schema(&transaction)?;
    workspace_goal_mutations::create_schema(&transaction)?;
    workspace_agent_migration::install_approval_authority_fences(&transaction)?;
    workspace_coordinator_recovery::create_schema(&transaction)?;
    commit_current_schema_migration(transaction)
}

fn migrate_current_schema(connection: &mut Connection) -> Result<(), WorkspaceStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    workspace_activity_successors::create_schema(&transaction)?;
    workspace_queue_settings::create_schema(&transaction)?;
    create_assignment_deletion_schema(&transaction)?;
    workspace_agent_migration::create_schema(&transaction)?;
    workspace_agent_binding_reservations::create_schema(&transaction)?;
    create_delegated_effect_schema(&transaction)?;
    workspace_goal_mutations::create_schema(&transaction)?;
    workspace_agent_migration::install_approval_authority_fences(&transaction)?;
    workspace_coordinator_recovery::create_schema(&transaction)?;
    commit_current_schema_migration(transaction)
}

fn migrate_previous_queue_settings_schema(
    connection: &mut Connection,
) -> Result<(), WorkspaceStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    workspace_queue_settings::create_schema(&transaction)?;
    create_assignment_deletion_schema(&transaction)?;
    workspace_agent_migration::create_schema(&transaction)?;
    workspace_agent_binding_reservations::create_schema(&transaction)?;
    create_delegated_effect_schema(&transaction)?;
    workspace_goal_mutations::create_schema(&transaction)?;
    workspace_agent_migration::install_approval_authority_fences(&transaction)?;
    workspace_coordinator_recovery::create_schema(&transaction)?;
    commit_current_schema_migration(transaction)
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
    if version == CURRENT_SCHEMA_VERSION {
        return Ok(DatabaseOwnership::Current);
    }
    if (1..CURRENT_SCHEMA_VERSION).contains(&version) {
        return Ok(DatabaseOwnership::Outdated { version });
    }
    Err(WorkspaceStoreError::DamagedSchema {
        detail: format!("owned database has unsupported schema version {version}"),
    })
}

fn validate_owned_database(connection: &Connection) -> Result<(), WorkspaceStoreError> {
    match inspect_database(connection)? {
        DatabaseOwnership::Current => validate_schema_shape(connection),
        DatabaseOwnership::Outdated { version } => Err(WorkspaceStoreError::OutdatedSchema {
            actual: version,
            current: CURRENT_SCHEMA_VERSION,
        }),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkspaceSchemaShape {
    V30,
    V31,
    V32,
    V33,
    V34,
    V35,
    V36,
    V37,
    V38,
    V39,
    V40,
    V41,
    V42,
    V43,
    V44,
    V45,
    V46,
    V47,
    V48,
    V49,
    V50,
    V51,
    V52,
    V53,
    V54,
    V55,
    V56,
    V57,
    V58,
    V59,
    V60,
    V61,
    V62,
    V63,
    V64,
    V65,
    V66,
    V67,
    V68,
    Current,
}

impl WorkspaceSchemaShape {
    /// All listed feature introductions are additive. Keep the version
    /// identity explicit once, rather than duplicating every later variant
    /// in every feature predicate whenever a new schema is introduced.
    const fn version(self) -> i64 {
        match self {
            Self::V30 => 30,
            Self::V31 => 31,
            Self::V32 => 32,
            Self::V33 => 33,
            Self::V34 => 34,
            Self::V35 => 35,
            Self::V36 => 36,
            Self::V37 => 37,
            Self::V38 => 38,
            Self::V39 => 39,
            Self::V40 => 40,
            Self::V41 => 41,
            Self::V42 => 42,
            Self::V43 => 43,
            Self::V44 => 44,
            Self::V45 => 45,
            Self::V46 => 46,
            Self::V47 => 47,
            Self::V48 => 48,
            Self::V49 => 49,
            Self::V50 => 50,
            Self::V51 => 51,
            Self::V52 => 52,
            Self::V53 => 53,
            Self::V54 => 54,
            Self::V55 => 55,
            Self::V56 => 56,
            Self::V57 => 57,
            Self::V58 => 58,
            Self::V59 => 59,
            Self::V60 => 60,
            Self::V61 => 61,
            Self::V62 => 62,
            Self::V63 => 63,
            Self::V64 => 64,
            Self::V65 => 65,
            Self::V66 => 66,
            Self::V67 => 67,
            Self::V68 => 68,
            Self::Current => CURRENT_SCHEMA_VERSION,
        }
    }

    const fn includes_agent_session(self) -> bool {
        self.version() >= 30
    }
    const fn includes_verification(self) -> bool {
        self.version() >= 31
    }
    const fn includes_activity_successor(self) -> bool {
        self.version() >= 32
    }
    const fn includes_queue_settings(self) -> bool {
        self.version() >= 33
    }
    const fn includes_assignments_and_deletion(self) -> bool {
        self.version() >= 34
    }
    const fn includes_agent_operations_migration(self) -> bool {
        self.version() >= 35
    }
    const fn includes_binding_reservations(self) -> bool {
        self.version() >= 36
    }
    const fn includes_delegated_effects(self) -> bool {
        self.version() >= 37
    }
    const fn includes_session_reconciliation(self) -> bool {
        self.version() >= 38
    }
    const fn includes_departure_reconciliation(self) -> bool {
        self.version() >= 39
    }
    const fn includes_effect_fact_outbox(self) -> bool {
        self.version() >= 40
    }
    const fn includes_change_set_fact(self) -> bool {
        self.version() >= 41
    }
    const fn includes_work_credit(self) -> bool {
        self.version() >= 42
    }
    const fn includes_assignment_offered(self) -> bool {
        self.version() >= 43
    }
    const fn includes_assignment_submitted(self) -> bool {
        self.version() >= 44
    }
    const fn includes_semantic_events(self) -> bool {
        self.version() >= 45
    }
    const fn includes_admission_envelopes(self) -> bool {
        self.version() >= 46
    }
    const fn includes_change_set_producer(self) -> bool {
        self.version() >= 47
    }
    const fn includes_assignment_submitted_source_refs(self) -> bool {
        self.version() >= 48
    }
    const fn includes_goal_mutation_receipts(self) -> bool {
        self.version() >= 49
    }
    const fn includes_approval_authority_fences(self) -> bool {
        self.version() >= 50
    }
    const fn includes_coordinator_recovery(self) -> bool {
        self.version() >= 51
    }
    const fn includes_goal_creation_watermarks(self) -> bool {
        self.version() >= 52
    }
    const fn includes_offer_seals(self) -> bool {
        self.version() >= 53
    }
    const fn includes_work_cuts(self) -> bool {
        self.version() >= 54
    }
    const fn includes_work_cut_continuations(self) -> bool {
        self.version() >= 55
    }
    const fn includes_unlimited_auto_approval(self) -> bool {
        self.version() >= 56
    }
    const fn includes_execution_stops(self) -> bool {
        self.version() >= 57
    }
    const fn includes_stop_authority(self) -> bool {
        self.version() >= 58
    }
    const fn includes_native_closure(self) -> bool {
        self.version() >= 59
    }
    const fn includes_stop_settlement(self) -> bool {
        self.version() >= 60
    }
    const fn includes_recovery_runs(self) -> bool {
        self.version() >= 61
    }

    const fn includes_root_recovery_receipts(self) -> bool {
        self.version() >= PREVIOUS_DELEGATED_ROOT_RECOVERY_SCHEMA_VERSION
    }

    const fn includes_delegated_root_recovery_receipts(self) -> bool {
        self.version() >= PREVIOUS_EXPIRED_ACTIVITY_RECOVERY_SCHEMA_VERSION
    }

    const fn includes_expired_activity_recovery(self) -> bool {
        self.version() >= PREVIOUS_BINDING_REJECTION_SCHEMA_VERSION
    }

    const fn includes_binding_rejections(self) -> bool {
        self.version() >= PREVIOUS_UNSTARTED_ACTIVITY_CONTINUATION_SCHEMA_VERSION
    }

    const fn includes_unstarted_activity_continuation(self) -> bool {
        self.version() >= PREVIOUS_STARTED_ACTIVITY_LEASE_RESUME_SCHEMA_VERSION
    }
    const fn includes_started_activity_lease_resume(self) -> bool {
        self.version() >= PREVIOUS_ADMISSION_IDENTITY_SCHEMA_VERSION
    }
    const fn includes_quiescent_activity_lease_resume(self) -> bool {
        self.version() >= CURRENT_SCHEMA_VERSION
    }
}
/// Map one inspected database to the schema shape its version must exhibit.
fn read_only_schema_shape(
    ownership: DatabaseOwnership,
) -> Result<WorkspaceSchemaShape, WorkspaceStoreError> {
    match ownership {
        DatabaseOwnership::Current => Ok(WorkspaceSchemaShape::Current),
        DatabaseOwnership::Outdated { version } => match version {
            PREVIOUS_DELEGATED_ROOT_RECOVERY_SCHEMA_VERSION => Ok(WorkspaceSchemaShape::V62),
            PREVIOUS_EXPIRED_ACTIVITY_RECOVERY_SCHEMA_VERSION => Ok(WorkspaceSchemaShape::V63),
            PREVIOUS_BINDING_REJECTION_SCHEMA_VERSION => Ok(WorkspaceSchemaShape::V64),
            PREVIOUS_UNSTARTED_ACTIVITY_CONTINUATION_SCHEMA_VERSION => {
                Ok(WorkspaceSchemaShape::V65)
            }
            PREVIOUS_STARTED_ACTIVITY_LEASE_RESUME_SCHEMA_VERSION => Ok(WorkspaceSchemaShape::V66),
            PREVIOUS_ADMISSION_IDENTITY_SCHEMA_VERSION => Ok(WorkspaceSchemaShape::V67),
            PREVIOUS_QUIESCENT_ACTIVITY_LEASE_RESUME_SCHEMA_VERSION => {
                Ok(WorkspaceSchemaShape::V68)
            }
            PREVIOUS_ROOT_RECOVERY_SCHEMA_VERSION => Ok(WorkspaceSchemaShape::V61),
            PREVIOUS_RECOVERY_RUNS_SCHEMA_VERSION => Ok(WorkspaceSchemaShape::V60),
            PREVIOUS_STOP_SETTLEMENT_SCHEMA_VERSION => Ok(WorkspaceSchemaShape::V59),
            PREVIOUS_NATIVE_CLOSURE_SCHEMA_VERSION => Ok(WorkspaceSchemaShape::V58),
            PREVIOUS_STOP_AUTHORITY_SCHEMA_VERSION => Ok(WorkspaceSchemaShape::V57),
            PREVIOUS_EXECUTION_STOPS_SCHEMA_VERSION => Ok(WorkspaceSchemaShape::V56),
            PREVIOUS_AUTO_APPROVAL_SCHEMA_VERSION => Ok(WorkspaceSchemaShape::V55),
            PREVIOUS_WORK_CUT_CONTINUATIONS_SCHEMA_VERSION => Ok(WorkspaceSchemaShape::V54),
            PREVIOUS_WORK_CUTS_SCHEMA_VERSION => Ok(WorkspaceSchemaShape::V53),
            PREVIOUS_ASSIGNMENT_OFFER_SEALS_SCHEMA_VERSION => Ok(WorkspaceSchemaShape::V52),
            PREVIOUS_GOAL_CREATION_WATERMARK_SCHEMA_VERSION => Ok(WorkspaceSchemaShape::V51),
            PREVIOUS_COORDINATOR_RECOVERY_SCHEMA_VERSION => Ok(WorkspaceSchemaShape::V50),

            PREVIOUS_SCHEMA_VERSION => Ok(WorkspaceSchemaShape::V30),
            PREVIOUS_MODERN_SCHEMA_VERSION => Ok(WorkspaceSchemaShape::V31),
            PREVIOUS_LATEST_SCHEMA_VERSION => Ok(WorkspaceSchemaShape::V32),
            PREVIOUS_QUEUE_SCHEMA_VERSION => Ok(WorkspaceSchemaShape::V33),
            PREVIOUS_OPERATIONS_SCHEMA_VERSION => Ok(WorkspaceSchemaShape::V34),
            PREVIOUS_BINDING_SCHEMA_VERSION => Ok(WorkspaceSchemaShape::V35),
            PREVIOUS_DELEGATED_SCHEMA_VERSION => Ok(WorkspaceSchemaShape::V36),
            PREVIOUS_RECONCILIATION_SCHEMA_VERSION => Ok(WorkspaceSchemaShape::V37),
            PREVIOUS_DEPARTURE_RECONCILIATION_SCHEMA_VERSION => Ok(WorkspaceSchemaShape::V38),
            PREVIOUS_EFFECT_FACT_SCHEMA_VERSION => Ok(WorkspaceSchemaShape::V39),
            PREVIOUS_CHANGE_SET_FACT_SCHEMA_VERSION => Ok(WorkspaceSchemaShape::V40),
            PREVIOUS_WORK_CREDIT_SCHEMA_VERSION => Ok(WorkspaceSchemaShape::V41),
            PREVIOUS_ASSIGNMENT_OFFERED_SCHEMA_VERSION => Ok(WorkspaceSchemaShape::V42),
            PREVIOUS_ASSIGNMENT_SUBMITTED_SCHEMA_VERSION => Ok(WorkspaceSchemaShape::V43),
            PREVIOUS_SEMANTIC_EVENTS_SCHEMA_VERSION => Ok(WorkspaceSchemaShape::V44),
            PREVIOUS_ADMISSION_ENVELOPE_SCHEMA_VERSION => Ok(WorkspaceSchemaShape::V45),
            PREVIOUS_CHANGE_SET_PRODUCER_SCHEMA_VERSION => Ok(WorkspaceSchemaShape::V46),
            PREVIOUS_SOURCE_REFS_SCHEMA_VERSION => Ok(WorkspaceSchemaShape::V47),
            PREVIOUS_GOAL_MUTATION_RECEIPTS_SCHEMA_VERSION => Ok(WorkspaceSchemaShape::V48),
            PREVIOUS_APPROVAL_AUTHORITY_FENCE_SCHEMA_VERSION => Ok(WorkspaceSchemaShape::V49),
            actual => Err(WorkspaceStoreError::OutdatedSchema {
                actual,
                current: CURRENT_SCHEMA_VERSION,
            }),
        },
        DatabaseOwnership::Fresh => Err(WorkspaceStoreError::FreshDatabase),
    }
}

fn validate_schema_shape(connection: &Connection) -> Result<(), WorkspaceStoreError> {
    validate_schema_shape_for_version(connection, WorkspaceSchemaShape::Current)
}

#[allow(
    clippy::too_many_lines,
    reason = "One reviewed arm per supported schema shape keeps validation legible."
)]
fn validate_schema_shape_for_version(
    connection: &Connection,
    shape: WorkspaceSchemaShape,
) -> Result<(), WorkspaceStoreError> {
    validate_schema_objects(connection, shape)?;
    if shape.includes_native_closure() {
        workspace_executions::native_closure::validate_schema(connection)?;
    }
    if shape.includes_recovery_runs() {
        crate::workspace_recovery_runs::validate_schema(connection)?;
    }
    if shape.includes_root_recovery_receipts() {
        if shape.includes_delegated_root_recovery_receipts() {
            root_recovery::validate_schema(connection)?;
        } else {
            root_recovery::validate_schema_v62(connection)?;
        }
    }
    if shape.includes_expired_activity_recovery() {
        crate::workspace_expired_activity_recovery::validate_schema(connection).map_err(
            |error| WorkspaceStoreError::DamagedSchema {
                detail: error.to_string(),
            },
        )?;
    }
    if shape.includes_binding_rejections() {
        crate::workspace_agent_binding_rejections::validate_schema(connection).map_err(
            |error| WorkspaceStoreError::DamagedSchema {
                detail: error.to_string(),
            },
        )?;
    }
    if shape.includes_unstarted_activity_continuation() {
        crate::workspace_unstarted_activity_continuation::validate_schema(connection).map_err(
            |error| WorkspaceStoreError::DamagedSchema {
                detail: error.to_string(),
            },
        )?;
    }
    let validate_started_activity_lease_resume = if shape.includes_started_activity_lease_resume() {
        crate::workspace_started_activity_lease_resumes::validate_schema(connection)
    } else {
        crate::workspace_started_activity_lease_resumes::validate_schema_if_present(connection)
    };
    validate_started_activity_lease_resume.map_err(|error| WorkspaceStoreError::DamagedSchema {
        detail: error.to_string(),
    })?;
    let validate_quiescent_activity_lease_resume = if shape
        .includes_quiescent_activity_lease_resume()
    {
        crate::workspace_quiescent_activity_lease_resumes::validate_schema(connection)
    } else {
        crate::workspace_quiescent_activity_lease_resumes::validate_schema_if_present(connection)
    };
    validate_quiescent_activity_lease_resume.map_err(|error| {
        WorkspaceStoreError::DamagedSchema {
            detail: error.to_string(),
        }
    })?;
    if shape.includes_stop_authority() {
        workspace_approvals::cleanup::stop_receipts::validate_schema(connection)?;
    }
    if shape.includes_execution_stops() {
        if shape.includes_stop_settlement() {
            workspace_execution_stops::validate_schema(connection)?;
            workspace_execution_stops::settlement::validate_schema(connection)?;
        } else {
            workspace_execution_stops::validate_schema_v59(connection)?;
        }
    }
    if shape.includes_work_cuts() {
        workspace_work_cuts::validate_schema(connection)?;
    }
    if shape.includes_work_cut_continuations() {
        workspace_work_cuts::validate_continuation_schema(connection)?;
    }
    validate_agent_authority_schema(connection, shape)?;
    if shape.includes_effect_fact_outbox() {
        if shape.includes_assignment_submitted_source_refs() {
            workspace_effect_fact_outbox::validate_schema(connection)?;
        } else if shape.includes_change_set_producer() {
            workspace_effect_fact_outbox::validate_schema_pre_source_refs(connection)?;
        } else if shape.includes_assignment_submitted() {
            workspace_effect_fact_outbox::validate_schema_pre_producer(connection)?;
        } else if shape.includes_assignment_offered() {
            workspace_effect_fact_outbox::validate_assignment_offered_schema(connection)?;
        } else if shape.includes_work_credit() {
            workspace_effect_fact_outbox::validate_work_credit_schema(connection)?;
        } else if shape.includes_change_set_fact() {
            workspace_effect_fact_outbox::validate_change_set_schema(connection)?;
        } else {
            workspace_effect_fact_outbox::validate_base_schema(connection)?;
        }
    }
    if shape.includes_semantic_events() {
        workspace_semantic_events::validate_schema(connection)?;
    }
    if shape.includes_admission_envelopes() {
        if shape.version() >= PREVIOUS_QUIESCENT_ACTIVITY_LEASE_RESUME_SCHEMA_VERSION {
            workspace_admission_envelopes::validate_schema(connection)?;
        } else {
            workspace_admission_envelopes::validate_legacy_schema(connection)?;
        }
    }
    if shape.includes_goal_mutation_receipts() {
        workspace_goal_mutations::validate_schema(connection)?;
    }
    if shape.includes_goal_creation_watermarks() {
        workspace_goal_creation_watermarks::validate_schema(connection)?;
    }
    if shape.includes_agent_operations_migration() {
        workspace_agent_migration::validate_schema(connection)?;
    }
    if shape.includes_assignments_and_deletion() {
        if shape.includes_work_credit() {
            if shape.includes_offer_seals() {
                workspace_agent_assignments::validate_schema(connection)?;
            } else {
                workspace_agent_assignments::validate_schema_pre_offer_seals(connection)?;
            }
        } else {
            workspace_agent_assignments::validate_schema_pre_work_credit(connection)?;
        }
        workspace_goal_deletion::validate_schema(connection)?;
    }
    if shape.includes_activity_successor() {
        workspace_activity_successors::validate_schema(connection)?;
    }
    if shape.includes_queue_settings() {
        workspace_queue_settings::validate_schema(connection)?;
    }
    validate_workspace_table_shape(connection)?;
    validate_activity_table_shape(connection)?;
    validate_activity_index_shape(connection)?;
    validate_activity_lease_index_shape(connection)?;
    validate_activity_foreign_key_shape(connection)?;
    workspace_changesets::validate_schema(connection)?;
    workspace_changesets::validate_source_tree_request_schema(connection)?;
    workspace_diffs::validate_schema(connection)?;
    if shape.includes_verification() {
        workspace_executions::validate_schema(connection)?;
    } else if shape.includes_agent_session() {
        workspace_executions::validate_schema_v30(connection)?;
    } else {
        workspace_executions::validate_schema_v29(connection)?;
    }
    if shape.includes_verification() {
        workspace_verification::validate_schema(connection)?;
    }
    if shape.includes_agent_session() {
        if shape.includes_unlimited_auto_approval() {
            workspace_approvals::validate_schema(connection)?;
        } else {
            workspace_approvals::validate_schema_v55(connection)?;
        }
    } else {
        workspace_approvals::validate_schema_v29(connection)?;
    }
    workspace_checkpoints::validate_schema(connection)?;
    workspace_goals::validate_schema(connection)?;
    workspace_dags::validate_schema(connection)?;
    workspace_recovery::validate_schema(connection)?;
    if shape.includes_agent_session() {
        workspace_agents::validate_schema(connection)?;
    } else {
        workspace_agents::validate_schema_v29(connection)?;
    }
    workspace_writer_leases::validate_schema(connection)?;
    workspace_coordinators::validate_schema(connection)?;
    if shape.includes_agent_session() {
        workspace_agent_events::validate_schema(connection)?;
        workspace_agent_dag::validate_schema(connection)?;
    } else {
        workspace_agent_dag::validate_schema_v29(connection)?;
    }
    Ok(())
}

/// Validate versioned Agent attachment, delegation and recovery authority.
fn validate_agent_authority_schema(
    connection: &Connection,
    shape: WorkspaceSchemaShape,
) -> Result<(), WorkspaceStoreError> {
    if shape.includes_coordinator_recovery() {
        workspace_coordinator_recovery::validate_schema(connection)?;
    }
    if shape.includes_binding_reservations() {
        workspace_agent_binding_reservations::validate_schema(connection)?;
    }
    if shape.includes_delegated_effects() {
        workspace_agent_delegation::validate_schema(connection)?;
        workspace_agent_binding_activation::validate_schema(connection)?;
        workspace_agent_effect_outbox::validate_schema(connection)?;
    }
    if shape.includes_session_reconciliation() {
        workspace_agent_session_reconciliation::validate_schema(connection)?;
    }
    if shape.includes_departure_reconciliation() {
        workspace_agent_departure_reconciliation::validate_schema(connection)?;
    }
    Ok(())
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

#[allow(clippy::too_many_lines)]
fn validate_schema_objects(
    connection: &Connection,
    shape: WorkspaceSchemaShape,
) -> Result<(), WorkspaceStoreError> {
    let mut expected = Vec::from([
        ("table", "workspace"),
        ("table", "activities"),
        ("index", "activities_workspace_updated_idx"),
        ("index", "activities_workspace_lease_idx"),
    ]);
    if shape.includes_assignments_and_deletion() {
        if shape.includes_offer_seals() {
            expected.extend(workspace_agent_assignments::schema_objects());
        } else {
            expected.extend(workspace_agent_assignments::schema_objects_pre_offer_seals());
        }
        expected.extend(workspace_goal_deletion::schema_objects());
    }
    expected.extend(workspace_changesets::schema_objects());
    expected.extend(workspace_changesets::source_tree_request_schema_objects());
    expected.extend(workspace_diffs::schema_objects());
    if shape.includes_agent_session() {
        expected.extend(workspace_executions::schema_objects());
    } else {
        expected.extend(workspace_executions::schema_objects_v29());
    }
    if shape.includes_verification() {
        expected.extend(workspace_verification::schema_objects());
    }
    if shape.includes_activity_successor() {
        expected.extend(workspace_activity_successors::schema_objects());
    }
    if shape.includes_queue_settings() {
        expected.extend(workspace_queue_settings::schema_objects());
    }
    expected.extend(workspace_approvals::schema_objects());
    expected.extend(workspace_checkpoints::schema_objects());
    expected.extend(workspace_goals::schema_objects());
    expected.extend(workspace_dags::schema_objects());
    expected.extend(workspace_recovery::schema_objects());
    if shape.includes_agent_session() {
        expected.extend(workspace_agents::schema_objects());
    } else {
        expected.extend(workspace_agents::schema_objects_v29());
    }
    if shape.includes_agent_session() {
        expected.extend(workspace_agent_events::schema_objects());
    }
    expected.extend(workspace_writer_leases::schema_objects());
    expected.extend(workspace_coordinators::schema_objects());
    if shape.includes_coordinator_recovery() {
        expected.extend(workspace_coordinator_recovery::schema_objects());
    }
    if shape.includes_goal_creation_watermarks() {
        expected.extend(workspace_goal_creation_watermarks::schema_objects());
    }
    let dag_objects = workspace_agent_dag::schema_objects();
    expected.extend(
        dag_objects
            .iter()
            .take(if shape.includes_agent_session() {
                dag_objects.len()
            } else {
                2
            })
            .map(|(kind, name)| (*kind, *name)),
    );
    let migration_objects = if shape.includes_approval_authority_fences() {
        workspace_agent_migration::schema_objects()
    } else if shape.includes_agent_operations_migration() {
        workspace_agent_migration::schema_objects_pre_approval_fences()
    } else {
        Vec::new()
    };
    expected.extend(
        migration_objects
            .iter()
            .map(|(kind, name)| (*kind, name.as_str())),
    );
    let binding_objects = if shape.includes_binding_reservations() {
        workspace_agent_binding_reservations::schema_objects()
    } else {
        Vec::new()
    };
    expected.extend(binding_objects);
    if shape.includes_delegated_effects() {
        expected.extend(workspace_agent_delegation::schema_objects());
        expected.extend(workspace_agent_binding_activation::schema_objects());
        expected.extend(workspace_agent_effect_outbox::schema_objects());
    }
    if shape.includes_session_reconciliation() {
        expected.extend(workspace_agent_session_reconciliation::schema_objects());
    }
    if shape.includes_departure_reconciliation() {
        expected.extend(workspace_agent_departure_reconciliation::schema_objects());
    }
    if shape.includes_effect_fact_outbox() {
        expected.extend(workspace_effect_fact_outbox::base_schema_objects());
    }
    if shape.includes_change_set_fact() {
        expected.extend(workspace_effect_fact_outbox::change_set_schema_objects());
    }
    if shape.includes_work_credit() {
        expected.extend(workspace_effect_fact_outbox::work_credit_schema_objects());
    }
    if shape.includes_assignment_offered() {
        expected.extend(workspace_effect_fact_outbox::assignment_offered_schema_objects());
    }
    if shape.includes_assignment_submitted() {
        if shape.includes_assignment_submitted_source_refs() {
            expected.extend(workspace_effect_fact_outbox::assignment_submitted_schema_objects());
        } else {
            expected.extend(
                workspace_effect_fact_outbox::assignment_submitted_schema_objects_pre_source_refs(),
            );
        }
    }
    if shape.includes_semantic_events() {
        expected.extend(workspace_semantic_events::schema_objects());
    }
    if shape.includes_admission_envelopes() {
        expected.extend(
            if shape.version() >= PREVIOUS_QUIESCENT_ACTIVITY_LEASE_RESUME_SCHEMA_VERSION {
                workspace_admission_envelopes::schema_objects()
            } else {
                workspace_admission_envelopes::legacy_schema_objects()
            },
        );
    }
    if shape.includes_goal_mutation_receipts() {
        expected.extend(workspace_goal_mutations::schema_objects());
    }
    if shape.includes_work_cuts() {
        expected.extend(workspace_work_cuts::schema_objects());
    }
    if shape.includes_work_cut_continuations() {
        expected.extend(workspace_work_cuts::continuation_schema_objects());
    }
    if shape.includes_execution_stops() {
        expected.extend(workspace_execution_stops::schema_objects());
    }
    if shape.includes_stop_settlement() {
        expected.extend(workspace_execution_stops::settlement::schema_objects());
    }
    if shape.includes_stop_authority() {
        expected.extend(workspace_approvals::cleanup::stop_receipts::schema_objects());
    }
    if shape.includes_native_closure() {
        expected.extend(workspace_executions::native_closure::schema_objects());
    }
    if shape.includes_recovery_runs() {
        expected.extend(crate::workspace_recovery_runs::schema_objects());
    }
    if shape.includes_root_recovery_receipts() {
        expected.extend(root_recovery::schema_objects_v62());
    }
    if shape.includes_delegated_root_recovery_receipts() {
        expected.extend(root_recovery::delegation_schema_objects());
    }
    if shape.includes_expired_activity_recovery() {
        expected.extend(crate::workspace_expired_activity_recovery::schema_objects());
    }
    if shape.includes_binding_rejections() {
        expected.extend(crate::workspace_agent_binding_rejections::schema_objects());
    }
    if shape.includes_unstarted_activity_continuation() {
        expected.extend(crate::workspace_unstarted_activity_continuation::schema_objects());
    }
    if shape.includes_started_activity_lease_resume() {
        expected.extend(crate::workspace_started_activity_lease_resumes::schema_objects());
    }
    if shape.includes_quiescent_activity_lease_resume() {
        expected.extend(crate::workspace_quiescent_activity_lease_resumes::schema_objects());
    }
    validate_schema_objects_for(connection, &expected)
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
    // Rewind-only historical fixtures may retain a complete newer additive
    // set; a partial optional set remains a damaged shape.
    let optional_v64 = [
        ("table", "expired_activity_recovery_receipts"),
        ("table", "expired_activity_recovery_agents"),
        ("index", "expired_activity_recovery_receipts_successor_uidx"),
    ];
    tolerate_complete_optional_schema_objects(&mut objects, expected, &optional_v64);
    let optional_v67 = crate::workspace_started_activity_lease_resumes::schema_objects();
    tolerate_complete_optional_schema_objects(&mut objects, expected, &optional_v67);
    let optional_v69 = crate::workspace_quiescent_activity_lease_resumes::schema_objects();
    tolerate_complete_optional_schema_objects(&mut objects, expected, &optional_v69);
    if objects.len() != expected.len() {
        let unexpected = objects
            .iter()
            .find(|(object_type, name, _, _)| {
                !expected.iter().any(|(expected_type, expected_name)| {
                    expected_type == object_type && expected_name == name
                })
            })
            .map(|(kind, name, _, _)| format!("; first unexpected {kind} {name}"))
            .unwrap_or_default();
        return Err(WorkspaceStoreError::DamagedSchema {
            detail: format!(
                "Workspace schema contains unexpected objects (actual {}, expected {}){}",
                objects.len(),
                expected.len(),
                unexpected,
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

fn tolerate_complete_optional_schema_objects(
    objects: &mut Vec<(String, String, i64, Option<i64>)>,
    expected: &[(&str, &str)],
    optional: &[(&str, &str)],
) {
    let expected_present = optional.iter().all(|entry| {
        expected
            .iter()
            .any(|candidate| candidate.0 == entry.0 && candidate.1 == entry.1)
    });
    let any_present = optional.iter().any(|entry| {
        objects
            .iter()
            .any(|candidate| candidate.0 == entry.0 && candidate.1 == entry.1)
    });
    let complete_present = optional.iter().all(|entry| {
        objects
            .iter()
            .any(|candidate| candidate.0 == entry.0 && candidate.1 == entry.1)
    });
    if !expected_present && any_present && complete_present {
        objects.retain(|candidate| {
            !optional
                .iter()
                .any(|entry| candidate.0 == entry.0 && candidate.1 == entry.1)
        });
    }
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

fn initialize_fresh_schema(connection: &mut Connection) -> Result<(), WorkspaceStoreError> {
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
    workspace_changesets::create_source_tree_request_schema(&transaction)?;
    workspace_diffs::create_schema(&transaction)?;
    workspace_executions::create_schema(&transaction)?;
    workspace_verification::create_schema(&transaction)?;
    workspace_approvals::create_schema(&transaction)?;
    workspace_checkpoints::create_schema(&transaction)?;
    workspace_goals::create_schema(&transaction)?;
    workspace_dags::create_schema(&transaction)?;
    workspace_recovery::create_schema(&transaction)?;
    workspace_agents::create_schema(&transaction)?;
    workspace_agent_events::create_schema(&transaction)?;
    workspace_writer_leases::create_schema(&transaction)?;
    workspace_coordinators::create_schema(&transaction)?;
    workspace_agent_dag::create_schema(&transaction)?;
    workspace_activity_successors::create_schema(&transaction)?;
    workspace_queue_settings::create_schema(&transaction)?;
    create_assignment_deletion_schema(&transaction)?;
    workspace_agent_migration::create_schema(&transaction)?;
    workspace_agent_binding_reservations::create_schema(&transaction)?;
    create_delegated_effect_schema(&transaction)?;
    workspace_goal_mutations::create_schema(&transaction)?;
    workspace_agent_migration::install_approval_authority_fences(&transaction)?;
    workspace_coordinator_recovery::create_schema(&transaction)?;
    commit_fresh_current_schema_migration(transaction)
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
    let read_shape = compatible_read_only_shape(ownership)?;
    let schema_version = schema_version(&database.connection)?;
    let application_id = application_id(&database.connection)?;
    validate_schema_shape_for_version(&database.connection, read_shape)?;
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

fn map_execution_journal_error(error: ExecutionStoreError) -> WorkspaceStoreError {
    match error {
        ExecutionStoreError::CommittedUnconfirmed { .. } => {
            WorkspaceStoreError::ExecutionJournalCommittedUnconfirmed {
                source: Box::new(WorkspaceStoreError::Execution(error)),
            }
        }
        other => WorkspaceStoreError::Execution(other),
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
fn validate_goal_actor(
    actor: ActivityCoordinatorActor,
    goal: &RegisteredGoal,
) -> Result<(), WorkspaceStoreError> {
    if actor.workspace_id() != goal.workspace_id() {
        return Err(GoalStoreError::WorkspaceMismatch.into());
    }
    if actor.activity_id() != goal.activity_id() {
        return Err(GoalStoreError::ActivityMismatch.into());
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum WorkspaceStoreError {
    #[error("Workspace relocation blocked: {0}")]
    RelocationBlocked(&'static str),
    #[error("started Activity lease resume {request_id} committed; exact GET readback is required")]
    StartedActivityLeaseResumeCommittedUnconfirmed {
        request_id: Uuid,
        #[source]
        source: Box<WorkspaceStoreError>,
    },
    #[error(transparent)]
    StartedActivityLeaseResume(
        #[from]
        crate::workspace_store::started_activity_lease_resume::StartedActivityLeaseResumeStoreError,
    ),
    #[error("quiescent Activity lease resume {request_id} committed; exact GET readback is required")]
    QuiescentActivityLeaseResumeCommittedUnconfirmed {
        request_id: Uuid,
        #[source]
        source: Box<WorkspaceStoreError>,
    },
    #[error(transparent)]
    QuiescentActivityLeaseResume(
        #[from]
        crate::workspace_store::quiescent_activity_lease_resume::QuiescentActivityLeaseResumeStoreError,
    ),
    #[error("unstarted Activity continuation {request_id:?} committed; exact GET readback is required")]
    UnstartedActivityContinuationCommittedUnconfirmed {
        request_id: forge_domain::UnstartedActivityContinuationRequestId,
        #[source]
        source: Box<WorkspaceStoreError>,
    },
    #[error(transparent)]
    UnstartedActivityContinuation(
        #[from] crate::workspace_store::unstarted_activity_continuation::UnstartedActivityContinuationStoreError,
    ),
    #[error(transparent)]
    ExpiredActivityRecovery(
        #[from]
        crate::workspace_store::expired_activity_recovery::ExpiredActivityRecoveryStoreError,
    ),
    #[error(transparent)]
    RecoveryRun(#[from] crate::workspace_recovery_runs::RecoveryRunStoreError),
    #[error(transparent)]
    CoordinatorRecovery(#[from] crate::CoordinatorRecoveryStoreError),
    #[error("Coordinator recovery {recovery_id} requires durable readback")]
    CoordinatorRecoveryReadbackRequired {
        recovery_id: Uuid,
        #[source]
        source: Box<WorkspaceStoreError>,
    },

    #[error(transparent)]
    AgentBindingReservation(#[from] crate::AgentBindingReservationError),
    #[error("Agent binding reservation {request_id} commit requires durable readback")]
    AgentBindingReservationCommittedUnconfirmed {
        request_id: Uuid,
        #[source]
        source: Box<WorkspaceStoreError>,
    },
    #[error(transparent)]
    AgentOperationsDelegation(#[from] crate::AgentOperationsDelegationError),
    #[error("Agent operations delegation {migration_id} commit requires durable readback")]
    AgentOperationsDelegationCommittedUnconfirmed {
        migration_id: Uuid,
        #[source]
        source: Box<WorkspaceStoreError>,
    },
    #[error(transparent)]
    AgentBindingActivation(#[from] crate::AgentBindingActivationError),
    #[error(transparent)]
    AgentBindingRejection(#[from] crate::AgentBindingRejectionStoreError),
    #[error("Agent binding rejection {request_id} commit requires durable readback")]
    AgentBindingRejectionCommittedUnconfirmed {
        request_id: Uuid,
        #[source]
        source: Box<WorkspaceStoreError>,
    },
    #[error(transparent)]
    AgentSessionReconciliation(#[from] crate::AgentSessionReconciliationError),
    #[error("Agent session reconciliation {request_id} commit requires durable readback")]
    AgentSessionReconciliationReadbackRequired {
        request_id: Uuid,
        #[source]
        source: Box<WorkspaceStoreError>,
    },
    #[error(transparent)]
    AgentDepartureReconciliation(#[from] crate::AgentDepartureReconciliationError),
    #[error("Agent departure reconciliation {request_id} commit requires durable readback")]
    AgentDepartureReconciliationReadbackRequired {
        request_id: Uuid,
        #[source]
        source: Box<WorkspaceStoreError>,
    },
    #[error("Agent binding activation {request_id} commit requires durable readback")]
    AgentBindingActivationCommittedUnconfirmed {
        request_id: Uuid,
        #[source]
        source: Box<WorkspaceStoreError>,
    },
    #[error(transparent)]
    AgentEffectOutbox(#[from] crate::AgentEffectOutboxError),
    #[error(transparent)]
    EffectFactOutbox(#[from] crate::EffectFactOutboxError),
    #[error(transparent)]
    SemanticEvents(#[from] crate::SemanticEventError),
    #[error("semantic events requested for Workspace {actual}; the bound Workspace is {expected}")]
    SemanticEventsWorkspaceMismatch {
        expected: WorkspaceId,
        actual: WorkspaceId,
    },
    #[error(transparent)]
    AdmissionEnvelope(#[from] crate::workspace_admission_envelopes::AdmissionEnvelopeError),
    #[error(transparent)]
    AgentOperationsExport(#[from] crate::AgentOperationsExportError),
    #[error(
        "Agent operations freeze committed, but its live binding could not be confirmed; read the same migration identity"
    )]
    AgentOperationsMigrationCommittedUnconfirmed {
        #[source]
        source: Box<WorkspaceStoreError>,
    },
    #[error(transparent)]
    AgentOperationsMigration(#[from] crate::AgentOperationsMigrationError),
    #[error("Writer Lease committed, but its live binding could not be confirmed")]
    WriterLeaseCommittedUnconfirmed {
        #[source]
        source: Box<WorkspaceStoreError>,
    },
    #[error("Goal deletion committed, but its live binding could not be confirmed")]
    GoalDeletionCommittedUnconfirmed {
        #[source]
        source: Box<WorkspaceStoreError>,
    },
    #[error("planning committed, but its live binding could not be confirmed")]
    PlanningCommittedUnconfirmed {
        #[source]
        source: Box<WorkspaceStoreError>,
    },
    #[error("Agent assignment committed, but its live binding could not be confirmed")]
    AgentAssignmentCommittedUnconfirmed {
        #[source]
        source: Box<WorkspaceStoreError>,
    },
    #[error(transparent)]
    AgentAssignment(#[from] crate::AgentAssignmentStoreError),
    #[error(transparent)]
    WorkInventory(#[from] crate::WorkInventoryError),
    #[error(transparent)]
    WorkCut(#[from] crate::WorkCutError),
    #[error("work cut {cut_id} preparation outcome requires durable readback")]
    WorkCutReadbackRequired {
        cut_id: Uuid,
        #[source]
        source: Box<WorkspaceStoreError>,
    },
    #[error(
        "assignment continuation for successor {successor_id:?} committed, but its live binding could not be confirmed; durable readback required"
    )]
    AssignmentContinuationReadbackRequired {
        successor_id: forge_domain::AgentAssignmentId,
        request_id: Option<Uuid>,
        #[source]
        source: Box<WorkspaceStoreError>,
    },
    #[error(transparent)]
    GoalDeletion(#[from] workspace_goal_deletion::GoalDeletionStoreError),
    #[error("Workspace queue preference committed, but its live binding could not be confirmed")]
    WorkspaceQueueSettingsCommittedUnconfirmed {
        #[source]
        source: Box<WorkspaceStoreError>,
    },
    #[error("recovery-maintenance lease committed, but its live binding could not be confirmed")]
    RecoveryMaintenanceLeaseCommittedUnconfirmed {
        #[source]
        source: Box<WorkspaceStoreError>,
    },
    #[error("recovery lease clock or command observation failed")]
    RecoveryLeaseClockObservation {
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },
    #[error("recovery classification original Workspace binding changed")]
    RecoveryClassificationBindingConflict,
    #[error("recovery classification may have committed; exact readback is required")]
    RecoveryClassificationCommittedUnconfirmed {
        #[source]
        source: Box<WorkspaceStoreError>,
    },
    #[error("recovery classification rollback could not be confirmed")]
    RecoveryClassificationRollbackUnconfirmed {
        #[source]
        source: Box<WorkspaceStoreError>,
        rollback: rusqlite::Error,
    },
    #[error("execution journal committed, but its live binding could not be confirmed")]
    ExecutionJournalCommittedUnconfirmed {
        #[source]
        source: Box<WorkspaceStoreError>,
    },
    #[error("approval cleanup commit requires exact target readback")]
    ApprovalCleanupCommittedUnconfirmed {
        #[source]
        source: Box<WorkspaceStoreError>,
    },
    #[error("execution-stop capture requires exact durable readback")]
    ExecutionStopCommittedUnconfirmed {
        #[source]
        source: Box<WorkspaceStoreError>,
    },
    #[error("execution-stop rollback could not be confirmed; durable readback required")]
    ExecutionStopRollbackUnconfirmed {
        #[source]
        source: Box<WorkspaceStoreError>,
        rollback: rusqlite::Error,
    },
    #[error(transparent)]
    ExecutionStop(#[from] crate::workspace_execution_stops::ExecutionStopStoreError),
    #[error(transparent)]
    StateGate(#[from] WorkspaceStateGateError),
    #[error("Workspace state belongs to Location {actual}, not requested Location {expected}")]
    StateRemovalLocationMismatch {
        expected: LocationId,
        actual: LocationId,
    },
    #[error("Workspace state removal is blocked by durable {0:?}")]
    StateRemovalBlocked(WorkspaceStateRemovalBlocker),
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
    Verification(#[from] VerificationStoreError),
    #[error(transparent)]
    Approval(#[from] ApprovalStoreError),
    #[error(transparent)]
    Checkpoint(#[from] CheckpointStoreError),
    #[error(transparent)]
    Goal(#[from] GoalStoreError),
    #[error(transparent)]
    GoalMutation(#[from] crate::GoalMutationStoreError),
    #[error(transparent)]
    Dag(#[from] crate::DagStoreError),
    #[error(transparent)]
    DagNodeEvidence(#[from] crate::DagNodeEvidenceError),
    #[error(transparent)]
    Recovery(#[from] RecoveryStoreError),
    #[error(transparent)]
    Agent(#[from] AgentStoreError),
    #[error(transparent)]
    AgentEvents(#[from] AgentEventStoreError),
    #[error(transparent)]
    WriterLease(#[from] WriterLeaseStoreError),
    #[error(transparent)]
    Coordinator(#[from] CoordinatorStoreError),
    #[error(transparent)]
    AgentDag(#[from] AgentDagStoreError),
    #[error(transparent)]
    ActivitySuccessor(#[from] ActivitySuccessorStoreError),
    #[error(transparent)]
    WorkspaceQueueSettings(#[from] WorkspaceQueueSettingsStoreError),
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
        "Workspace schema version {actual} is outdated; current supported version is {current}"
    )]
    OutdatedSchema { actual: i64, current: i64 },
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
    #[error("Workspace journal binding paths do not match the observed state layout")]
    WorkspaceJournalBindingPathMismatch,
    #[error(
        "Workspace journal binding Workspace identity mismatch: expected {expected}, actual {actual}"
    )]
    WorkspaceJournalBindingWorkspaceMismatch {
        expected: WorkspaceId,
        actual: WorkspaceId,
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
    #[error("Activity {id} is not terminal and cannot receive a successor: {state:?}")]
    ActivitySuccessorPredecessorNotTerminal {
        id: ActivityId,
        state: ActivityState,
    },
    #[error(
        "Activity successor conflict for predecessor {predecessor}: existing {existing_successor}, requested {requested_successor}"
    )]
    ActivitySuccessorConflict {
        predecessor: ActivityId,
        existing_successor: ActivityId,
        requested_successor: ActivityId,
    },
    #[error("Activity successor target already exists: {0}")]
    ActivitySuccessorTargetAlreadyExists(ActivityId),
    #[error("Activity successor relation is missing for predecessor {0}")]
    ActivitySuccessorMissing(ActivityId),
    #[error(
        "Activity successor timestamp for predecessor {predecessor} is before terminal update {predecessor_updated_at:?}: observed {observed_at:?}"
    )]
    ActivitySuccessorTimestampOrder {
        predecessor: ActivityId,
        predecessor_updated_at: TimestampMillis,
        observed_at: TimestampMillis,
    },
    #[error("Activity successor relation or successor projection is corrupt for predecessor {0}")]
    ActivitySuccessorCorrupt(ActivityId),
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
    mod admission_identity;
    mod assignment_continuation;
    mod binding_rejection;
    mod execution_stop;
    mod expired_successor_recovery;
    mod native_closure;
    mod owned_stop_authority;
    mod quiescent_activity_lease_resume;
    mod recovery_maintenance;
    mod recovery_runs;
    mod started_activity_lease_resume;
    mod stop_settlement;
    mod supervised_activity_lease_renew;
    mod unstarted_activity_continuation;
    mod unstarted_activity_continuation_agent_metadata;
    mod unstarted_activity_continuation_live_snapshot;
    mod unstarted_activity_continuation_provenance;
    mod unstarted_activity_continuation_recovery_runs;
    mod work_cut_admission;

    use std::fs;
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::os::unix::fs::{MetadataExt, symlink};
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::{Arc, Barrier, mpsc};
    use std::thread;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use forge_domain::{
        AbandonDiffEvidence, ActivityId, ActivityLeaseRevision, ActivityListLimit,
        ActivityRevision, ActivityState, AgentDeclaredRole, AgentDisplayName, AgentInstanceId,
        AgentInstanceRevision, AgentSessionId, AgentTransportKind, AuthenticatedPrincipal,
        BeginDiffEvidence, BeginDiffPurge, BeginFileMutation, BeginFileMutationStatus,
        BootstrapActivity, ChangeSetAttribution, ChangeSetId, ChangeSetProducer, ChangeSetRevision,
        ChangeSetState, ChangeSetTimestamps, ClaimRecoveryLease, CloseActivity,
        CompleteDiffEvidence, CompleteDiffPurge, CompleteFileMutation, CreateActivity,
        DagAcceptanceCriterion, DagNodeDefinition, DagNodeId, DagNodeObjective, DagNodeOrdinal,
        DagNodeTitle, DagRevision, DagRevisionId, DagRevisionNumber, DiffArtifactRelativePath,
        DiffAttribution, DiffByteCount, DiffChangeKind, DiffContractVersions, DiffEntrySubject,
        DiffEntrySummary, DiffEvidenceState, DiffEvidenceTimestamps, DiffId, DiffLineCount,
        DiffPayloadHash, DiffPayloadProjection, DiffPurgeStatus, DiffRenderKind,
        DiffRetentionKeepCount, DiffRetentionPlanLimit, DiffRevision, EstablishWorkspace,
        FailFileMutation, FileByteCount, FileContentHash, FileMutationFailureCode, FileMutationId,
        FileMutationIdentity, FileMutationKind, FileMutationPlan, FileMutationRevision,
        FileMutationScope, FilePathState, FilePrecondition, GoalContract, GoalEvidenceRef, GoalId,
        GoalNodeAttribution, GoalObjective, GoalStatement, GoalWorkAttribution, LocationId,
        ReconcileExpiredActivities, RecoveryLeaseDurationMillis, RecoveryLeaseTransitionError,
        RegisteredActivity, RegisteredChangeSet, RegisteredDagNode, RegisteredDiffEvidence,
        RegisteredGoal, ReleaseActivityLease, RenewActivityLease, RuntimeInstanceId,
        SourceWriteAuthority, TimestampMillis, TreeChangeSetAdmissionStatus, TreeChangeSetDraft,
        TreeChangeSetIntent, TreeMutationDraft, TreeMutationId, TreeMutationPlan, WorkspaceId,
        WorkspaceRelativePath, WorkspaceRevision, WorkspaceRoot, WriterLeaseId,
        WriterLeaseRevision,
    };
    use rusqlite::{Connection, ErrorCode, TransactionBehavior, params};
    use uuid::Uuid;

    /// Materialize the historical admission key when a migration fixture
    /// deliberately downgrades an otherwise current database.
    pub(super) fn downgrade_admission_identity(
        connection: &Connection,
    ) -> Result<(), rusqlite::Error> {
        let exists: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='execution_admission_consumptions')", [], |row| row.get(0)
        )?;
        if !exists {
            return Ok(());
        }
        let execution_is_primary: bool = connection.query_row(
            "SELECT pk > 0 FROM pragma_table_info('execution_admission_consumptions') WHERE name='execution_id'", [], |row| row.get(0)
        )?;
        if !execution_is_primary {
            return Ok(());
        }
        connection.execute_batch("DROP INDEX execution_admission_consumptions_execution_idx; ALTER TABLE execution_admission_consumptions RENAME TO admission_identity_fixture_v68")?;
        crate::workspace_admission_envelopes::create_legacy_schema(connection)
            .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
        connection.execute_batch("INSERT INTO execution_admission_consumptions(issuer, request_digest, execution_id, consumed_at_ms) SELECT issuer, request_digest, execution_id, consumed_at_ms FROM admission_identity_fixture_v68; DROP TABLE admission_identity_fixture_v68;")?;
        Ok(())
    }

    use super::{
        BUSY_TIMEOUT, CURRENT_SCHEMA_VERSION, EXPECTED_ACTIVITIES_TABLE_SQL,
        MAX_DOCTOR_SNAPSHOT_BYTES, PREVIOUS_ASSIGNMENT_OFFER_SEALS_SCHEMA_VERSION,
        PREVIOUS_ASSIGNMENT_SUBMITTED_SCHEMA_VERSION, PREVIOUS_COORDINATOR_RECOVERY_SCHEMA_VERSION,
        PREVIOUS_GOAL_CREATION_WATERMARK_SCHEMA_VERSION,
        PREVIOUS_GOAL_MUTATION_RECEIPTS_SCHEMA_VERSION, PREVIOUS_MODERN_SCHEMA_VERSION,
        PREVIOUS_SCHEMA_VERSION, PREVIOUS_SOURCE_REFS_SCHEMA_VERSION,
        PREVIOUS_WORK_CUT_CONTINUATIONS_SCHEMA_VERSION, PREVIOUS_WORK_CUTS_SCHEMA_VERSION,
        WORKSPACE_APPLICATION_ID, WorkspaceDoctorIntegrity, WorkspaceDoctorOutcome,
        WorkspaceStateRemovalBlocker, WorkspaceStore, WorkspaceStoreError,
        validate_doctor_snapshot_size,
    };
    use crate::workspace_executions;
    use crate::workspace_goals;
    use crate::{DiffStoreError, RecoveryLeaseClaimStatus, RecoveryStoreError};
    use forge_workspace::{FORGE_GIT_PROGRAM, WorkspaceStateExclusiveGate, WorkspaceStateLayout};

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

    fn test_clock_timestamp(value: i64) -> Result<TimestampMillis, WorkspaceStoreError> {
        TimestampMillis::new(value).map_err(|_| WorkspaceStoreError::CorruptRecord {
            field: "test_source_clock",
            detail: "invalid test clock timestamp".to_owned(),
        })
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
            DiffAttribution::for_file_mutation(
                DiffId::for_change_set(command.change_set_id()),
                command.workspace_id(),
                command.activity_id(),
                command.change_set_id(),
                command.mutation_id(),
            ),
            vec![DiffEntrySummary::new(
                DiffEntrySubject::File,
                command.path().clone(),
                None,
                kind,
                DiffLineCount::new(0),
                DiffLineCount::new(0),
            )?],
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
        goal_activity_id: forge_domain::ActivityId,
    ) -> Result<GoalWorkAttribution, Box<dyn std::error::Error>> {
        insert_file_test_goal_seeded(store, workspace_id, goal_activity_id, 0xB108)
    }

    fn insert_file_test_goal_seeded(
        store: &mut WorkspaceStore,
        workspace_id: WorkspaceId,
        goal_activity_id: forge_domain::ActivityId,
        seed: u128,
    ) -> Result<GoalWorkAttribution, Box<dyn std::error::Error>> {
        let goal = RegisteredGoal::create(
            GoalId::from_uuid(Uuid::from_u128(seed)),
            workspace_id,
            goal_activity_id,
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
        let _ = workspace_goals::insert_goal(&mut store.connection, &goal)?;
        let definition = DagNodeDefinition::new(
            DagNodeId::from_uuid(Uuid::from_u128(seed + 1)),
            DagNodeOrdinal::new(0)?,
            DagNodeTitle::new("Apply mutation".to_owned())?,
            DagNodeObjective::new("Apply the attributed file mutation".to_owned())?,
            vec![DagAcceptanceCriterion::new(
                "ChangeSet is durable".to_owned(),
            )?],
        )?;
        let dag = DagRevision::new(
            DagRevisionId::from_uuid(Uuid::from_u128(seed + 2)),
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
        let active = store.start_dag_node(crate::DagNodeTransition::new(
            crate::DagTransitionScope::new(
                goal.workspace_id(),
                goal.activity_id(),
                goal.id(),
                goal.revision(),
                dag.number(),
            ),
            nodes[0].id(),
            nodes[0].revision(),
            timestamp(19)?,
        ))?;
        Ok(GoalNodeAttribution::new(
            goal.id(),
            goal.revision(),
            dag.number(),
            active.id(),
            active.revision(),
        )
        .into())
    }

    fn insert_two_node_file_test_goal(
        store: &mut WorkspaceStore,
        workspace_id: WorkspaceId,
        goal_activity_id: forge_domain::ActivityId,
        seed: u128,
    ) -> Result<Vec<GoalWorkAttribution>, Box<dyn std::error::Error>> {
        let goal = RegisteredGoal::create(
            GoalId::from_uuid(Uuid::from_u128(seed)),
            workspace_id,
            goal_activity_id,
            GoalContract::new(
                GoalObjective::new("Apply attributed file mutations".to_owned())?,
                vec![GoalStatement::new("Each ChangeSet is durable".to_owned())?],
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            )?,
            timestamp(19)?,
        );
        let _ = workspace_goals::insert_goal(&mut store.connection, &goal)?;
        let definitions = vec![
            DagNodeDefinition::new(
                DagNodeId::from_uuid(Uuid::from_u128(seed + 1)),
                DagNodeOrdinal::new(0)?,
                DagNodeTitle::new("Apply mutation 0".to_owned())?,
                DagNodeObjective::new("Apply attributed mutation 0".to_owned())?,
                vec![DagAcceptanceCriterion::new(
                    "ChangeSet is durable".to_owned(),
                )?],
            )?,
            DagNodeDefinition::new(
                DagNodeId::from_uuid(Uuid::from_u128(seed + 2)),
                DagNodeOrdinal::new(1)?,
                DagNodeTitle::new("Apply mutation 1".to_owned())?,
                DagNodeObjective::new("Apply attributed mutation 1".to_owned())?,
                vec![DagAcceptanceCriterion::new(
                    "ChangeSet is durable".to_owned(),
                )?],
            )?,
        ];
        let dag = DagRevision::new(
            DagRevisionId::from_uuid(Uuid::from_u128(seed + 3)),
            goal.id(),
            goal.revision(),
            DagRevisionNumber::INITIAL,
            None,
            definitions.clone(),
            Vec::new(),
            timestamp(19)?,
        )?;
        let mut nodes = Vec::with_capacity(definitions.len());
        for definition in definitions {
            nodes.push(RegisteredDagNode::create(
                goal.id(),
                dag.number(),
                definition,
                timestamp(19)?,
            ));
        }
        let _ = store.insert_dag_revision(&dag, &nodes, &[], None)?;
        let mut attributions = Vec::with_capacity(nodes.len());
        for node in nodes {
            let active = store.start_dag_node(crate::DagNodeTransition::new(
                crate::DagTransitionScope::new(
                    goal.workspace_id(),
                    goal.activity_id(),
                    goal.id(),
                    goal.revision(),
                    dag.number(),
                ),
                node.id(),
                node.revision(),
                timestamp(19)?,
            ))?;
            attributions.push(
                GoalNodeAttribution::new(
                    goal.id(),
                    goal.revision(),
                    dag.number(),
                    active.id(),
                    active.revision(),
                )
                .into(),
            );
        }
        Ok(attributions)
    }

    fn seed_test_source_write_authority(
        store: &mut WorkspaceStore,
        workspace_id: WorkspaceId,
        activity: &RegisteredActivity,
        attribution: GoalWorkAttribution,
        path: &WorkspaceRelativePath,
        seed: u128,
    ) -> Result<SourceWriteAuthority, Box<dyn std::error::Error>> {
        let node = attribution.node().ok_or("node attribution missing")?;
        let agent_id = AgentInstanceId::from_uuid(Uuid::from_u128(seed));
        let session_id = AgentSessionId::from_uuid(Uuid::from_u128(seed + 2));
        let lease_id = WriterLeaseId::from_uuid(Uuid::from_u128(seed + 1));
        store.connection.execute(
            "INSERT INTO agent_instances (
                agent_id, workspace_id, activity_id, display_name, declared_role,
                transport_kind, principal_kind, principal_id, attachment_state,
                focus_goal_id, focus_goal_revision, focus_dag_revision,
                focus_node_id, focus_node_revision, created_at_ms, updated_at_ms, revision, session_id
             ) VALUES (?1, ?2, ?3, 'Writer fixture', 'worker', 0, 0, NULL, 0,
                       ?4, ?5, ?6, ?7, ?8, 10, 11, 2, ?9)",
            params![
                agent_id.into_uuid().as_bytes(),
                workspace_id.into_uuid().as_bytes(),
                activity.id().into_uuid().as_bytes(),
                node.goal_id().into_uuid().as_bytes(),
                node.expected_goal_revision().get(),
                node.dag_revision().get(),
                node.node_id().into_uuid().as_bytes(),
                node.expected_node_revision().get(),
                session_id.into_uuid().as_bytes(),
            ],
        )?;
        store.connection.execute(
            "INSERT INTO writer_leases (
                lease_id, workspace_id, activity_id, agent_id, state,
                acquired_at_ms, updated_at_ms, lease_until_ms, revision
             ) VALUES (?1, ?2, ?3, ?4, 0, 12, 12, 100000, 1)",
            params![
                lease_id.into_uuid().as_bytes(),
                workspace_id.into_uuid().as_bytes(),
                activity.id().into_uuid().as_bytes(),
                agent_id.into_uuid().as_bytes(),
            ],
        )?;
        store.connection.execute(
            "INSERT INTO writer_lease_scope_entries (
                lease_id, ordinal, scope_kind, relative_path
             ) VALUES (?1, 0, 0, ?2)",
            params![
                lease_id.into_uuid().as_bytes(),
                path.as_path().as_os_str().as_bytes(),
            ],
        )?;
        Ok(SourceWriteAuthority::new(
            agent_id,
            AgentInstanceRevision::new(2)?,
            AuthenticatedPrincipal::TrustedStdio,
            node,
            lease_id,
            WriterLeaseRevision::INITIAL,
            session_id,
        ))
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
        let authority = seed_test_source_write_authority(
            store,
            workspace_id,
            activity,
            attribution,
            begin.path(),
            0xB10D,
        )?;
        assert!(matches!(
            store.begin_file_mutation_for_goal(&begin, &diff, Some(stale.into()), authority),
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

    #[allow(clippy::too_many_lines)]
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
            DiffAttribution::for_file_mutation(
                diff_id,
                scope.workspace_id,
                scope.activity.id(),
                identity.change_set_id(),
                identity.mutation_id(),
            ),
            vec![DiffEntrySummary::new(
                DiffEntrySubject::File,
                begin.path().clone(),
                None,
                DiffChangeKind::Created,
                DiffLineCount::new(1),
                DiffLineCount::new(0),
            )?],
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
        let hidden_goal = insert_file_test_goal_seeded(
            store,
            scope.workspace_id,
            scope.activity.id(),
            seed + 0x1000,
        )?;
        let authority = seed_test_source_write_authority(
            store,
            scope.workspace_id,
            &scope.activity,
            hidden_goal,
            begin.path(),
            seed + 0x2000,
        )?;
        let started = store.begin_file_mutation(&begin, &diff_begin, authority)?;
        let producer = forge_domain::ChangeSetProducer::new(
            AgentInstanceId::from_uuid(Uuid::from_u128(seed + 0x2000)),
            AgentSessionId::from_uuid(Uuid::from_u128(seed + 0x2002)),
        );
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
            .complete_file_mutation(&complete_file, &complete_diff, producer)?
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

    fn install_recovery_commit_failure_guard(
        store: &WorkspaceStore,
    ) -> Result<(), Box<dyn std::error::Error>> {
        store.connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TEMP TABLE recovery_commit_guard_parent (
                 id INTEGER PRIMARY KEY
             );
             CREATE TEMP TABLE recovery_commit_guard_child (
                 parent_id INTEGER REFERENCES recovery_commit_guard_parent(id)
                     DEFERRABLE INITIALLY DEFERRED
             );
             CREATE TEMP TRIGGER recovery_commit_guard
             AFTER UPDATE ON recovery_maintenance
             BEGIN
                 INSERT INTO recovery_commit_guard_child(parent_id) VALUES (99);
             END;",
        )?;
        Ok(())
    }

    fn assert_recovery_commit_unknown<T>(outcome: Result<T, WorkspaceStoreError>) {
        assert!(matches!(
            outcome,
            Err(WorkspaceStoreError::RecoveryMaintenanceLeaseCommittedUnconfirmed { source })
                if matches!(source.as_ref(), WorkspaceStoreError::Sqlite(_))
        ));
    }

    fn journal_execution_fixture(
        label: &str,
    ) -> Result<
        (
            PathBuf,
            WorkspaceStateLayout,
            WorkspaceStore,
            forge_domain::ExecutionOutputEvent,
        ),
        Box<dyn std::error::Error>,
    > {
        let (root, layout, mut store, activity_id) = store_with_activity(label)?;
        let workspace = store.workspace()?;
        let execution_id = forge_domain::ExecutionId::from_uuid(Uuid::now_v7());
        let request = forge_domain::ExecutionRequest::new(
            forge_domain::ExecutionAttribution::new(execution_id, workspace.id(), activity_id),
            forge_domain::ExecutionKind::Structured {
                program: forge_domain::ExecutionProgram::new(PathBuf::from("/usr/bin/printf"))?,
                arguments: Vec::new(),
            },
            None,
            forge_domain::ExecutionLimits::new(
                forge_domain::ExecutionTimeoutMillis::new(1_000)?,
                forge_domain::ExecutionOutputLimit::new(16)?,
            ),
            forge_domain::ExecutionPermissions::new(true, false, false),
        )?;
        let begun = store.begin_execution(&forge_domain::BeginExecution::from_request(
            &request,
            forge_domain::ExecutionRequestDigest::from_bytes([0xE9; 32]),
            timestamp(3)?,
        ))?;
        let running = store.mark_execution_running(forge_domain::MarkExecutionRunning::new(
            begun.record().id(),
            begun.record().revision(),
            timestamp(4)?,
        ))?;
        let event =
            forge_domain::ExecutionOutputEvent::Chunk(forge_domain::ExecutionOutputChunk::new(
                running.id(),
                forge_domain::ExecutionOutputSequence::new(1)?,
                forge_domain::ExecutionOutputStream::Stdout,
                b"journal-output",
            )?);
        Ok((root, layout, store, event))
    }

    #[test]
    fn execution_journal_output_commit_failure_preserves_unknown_outcome()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, _layout, mut store, event) = journal_execution_fixture("journal-output-commit")?;
        store.connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TEMP TABLE execution_store_commit_guard_parent (
                 id INTEGER PRIMARY KEY
             );
             CREATE TEMP TABLE execution_store_commit_guard_child (
                 parent_id INTEGER REFERENCES execution_store_commit_guard_parent(id)
                     DEFERRABLE INITIALLY DEFERRED
             );
             CREATE TEMP TRIGGER execution_store_commit_guard
             AFTER INSERT ON execution_output_events
             BEGIN
                 INSERT INTO execution_store_commit_guard_child(parent_id) VALUES (99);
             END;",
        )?;
        let outcome = store.append_execution_output_events(std::slice::from_ref(&event));
        assert!(matches!(
            outcome,
            Err(WorkspaceStoreError::ExecutionJournalCommittedUnconfirmed { source })
                if matches!(
                    source.as_ref(),
                    WorkspaceStoreError::Execution(
                        crate::workspace_executions::ExecutionStoreError::CommittedUnconfirmed {
                            source: inner
                        }
                    ) if matches!(inner.as_ref(), crate::workspace_executions::ExecutionStoreError::Sqlite(_))
                )
        ));
        assert_eq!(
            store.connection.query_row(
                "SELECT COUNT(*) FROM execution_output_events",
                [],
                |row| { row.get::<_, i64>(0) }
            )?,
            0
        );
        drop(store);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn execution_journal_post_commit_binding_failure_requires_readback()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, layout, mut store, event) = journal_execution_fixture("journal-output-binding")?;
        let marker = root.join("journal-marker");
        fs::write(&marker, b"preserved")?;
        let original_identity = store.database_identity;
        let outcome =
            store.append_execution_output_events_with_hook(std::slice::from_ref(&event), |store| {
                store.database_identity.inode ^= 1;
            });
        assert!(matches!(
            outcome,
            Err(WorkspaceStoreError::ExecutionJournalCommittedUnconfirmed { .. })
        ));
        store.database_identity = original_identity;
        drop(store);
        let existing = WorkspaceStateLayout::inspect_existing(layout.workspace_root())?
            .ok_or("layout missing")?;
        let reopened = WorkspaceStore::open_existing(&existing)?;
        let count: i64 = reopened.connection.query_row(
            "SELECT COUNT(*) FROM execution_output_events",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(count, 1);
        assert_eq!(fs::read(&marker)?, b"preserved");
        drop(reopened);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn approval_cleanup_postcommit_binding_failure_retains_exact_after_images()
    -> Result<(), Box<dyn std::error::Error>> {
        approval_cleanup_postcommit_readback_fixture(
            crate::ApprovalCleanupMode::AuthorityCancellation,
        )
    }

    #[test]
    fn approval_expiry_postcommit_binding_failure_retains_exact_after_images()
    -> Result<(), Box<dyn std::error::Error>> {
        approval_cleanup_postcommit_readback_fixture(crate::ApprovalCleanupMode::ExpiredOnly)
    }

    fn approval_cleanup_postcommit_readback_fixture(
        mode: crate::ApprovalCleanupMode,
    ) -> Result<(), Box<dyn std::error::Error>> {
        use forge_domain::{
            ApprovalRequestId, ExecutionAuthorizationRequest, ExecutionId, ExecutionListLimit,
            RegisteredApprovalRequest,
        };

        let (root, layout, mut store, activity) = store_with_activity("cleanup-postcommit")?;
        let workspace = store.workspace()?.id();
        let policy = store.ensure_workspace_policy(timestamp(3)?)?;
        let pending = RegisteredApprovalRequest::pending(
            ApprovalRequestId::from_uuid(Uuid::from_u128(0xCC01)),
            ExecutionAuthorizationRequest::new(
                ExecutionId::from_uuid(Uuid::from_u128(0xCC02)),
                workspace,
                activity,
                forge_domain::ExecutionRequestDigest::from_bytes([0xCC; 32]),
                forge_domain::ExecutionActionClass::DirectStructured,
                forge_domain::RequestedExecutionPermissions::new(
                    forge_domain::ExecutionPermissions::new(false, false, false),
                ),
            ),
            policy.revision(),
            timestamp(3)?,
            timestamp(100)?,
        )?;
        let _pending = store.insert_pending_approval(&pending)?;
        let checked = WorkspaceStateLayout::inspect_existing(layout.workspace_root())?
            .ok_or("cleanup fixture layout missing")?;
        let binding = store.journal_binding()?;
        let (plan, expected_state, observed_at) = match mode {
            crate::ApprovalCleanupMode::AuthorityCancellation => (
                store.prepare_approval_cleanup(
                    crate::ApprovalCleanupSelector::Workspace,
                    timestamp(5)?,
                    ExecutionListLimit::new(256)?,
                )?,
                forge_domain::ApprovalRequestState::Cancelled,
                timestamp(5)?,
            ),
            crate::ApprovalCleanupMode::ExpiredOnly => (
                store.prepare_expired_approval_cleanup(
                    crate::ApprovalCleanupSelector::Workspace,
                    timestamp(150)?,
                    ExecutionListLimit::new(256)?,
                )?,
                forge_domain::ApprovalRequestState::Expired,
                timestamp(150)?,
            ),
        };
        let state_root = layout.state_root();
        let moved_state_root = root.join("cleanup-postcommit-state-moved");
        let mut relocation = None;
        let attempt = crate::ApprovalCleanupAttemptId::from_uuid(Uuid::from_u128(0xCC03));
        let outcome =
            store.apply_approval_cleanup_with_posttransaction_hook(&plan, attempt, |_store| {
                relocation = Some(fs::rename(state_root, &moved_state_root));
            });
        relocation.ok_or("postcommit relocation hook did not run")??;
        // Restore the owned fixture before asserting or dropping the open DB.
        fs::rename(&moved_state_root, state_root)?;
        assert!(matches!(
            outcome,
            Err(WorkspaceStoreError::ApprovalCleanupCommittedUnconfirmed { .. })
        ));
        drop(store);
        let reopened = WorkspaceStore::open_existing_journal(&checked, &binding)?;
        assert_eq!(
            reopened.observe_approval_cleanup(&plan)?,
            crate::ApprovalCleanupReadback::SettledTargetState
        );
        let durable = reopened
            .get_approval_request(pending.id())?
            .ok_or("cleanup target missing")?;
        assert_eq!(durable.state(), expected_state);
        assert_eq!(durable.revision(), pending.revision().checked_next()?);
        assert_eq!(durable.decided_at(), Some(observed_at));
        drop(reopened);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn cleanup_rejection_binding_change_does_not_return_confirmed_proof()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, layout, mut store, activity) = store_with_activity("rejection-binding")?;
        let workspace = store.workspace()?.id();
        let policy = store.ensure_workspace_policy(timestamp(3)?)?;
        let pending = forge_domain::RegisteredApprovalRequest::pending(
            forge_domain::ApprovalRequestId::from_uuid(Uuid::from_u128(0xCD01)),
            forge_domain::ExecutionAuthorizationRequest::new(
                forge_domain::ExecutionId::from_uuid(Uuid::from_u128(0xCD02)),
                workspace,
                activity,
                forge_domain::ExecutionRequestDigest::from_bytes([0xCD; 32]),
                forge_domain::ExecutionActionClass::DirectStructured,
                forge_domain::RequestedExecutionPermissions::new(
                    forge_domain::ExecutionPermissions::new(false, false, false),
                ),
            ),
            policy.revision(),
            timestamp(3)?,
            timestamp(100)?,
        )?;
        let _inserted = store.insert_pending_approval(&pending)?;
        let plan = store.prepare_approval_cleanup(
            crate::ApprovalCleanupSelector::Workspace,
            timestamp(5)?,
            forge_domain::ExecutionListLimit::new(256)?,
        )?;
        let other = store.decide_pending_approval(
            pending.id(),
            forge_domain::ApprovalDecision::Reject,
            pending.revision(),
            timestamp(6)?,
        )?;
        let state_root = layout.state_root();
        let moved = root.join("rejection-state-moved");
        let mut relocation = None;
        let outcome = store.apply_approval_cleanup_with_posttransaction_hook(
            &plan,
            crate::ApprovalCleanupAttemptId::from_uuid(Uuid::from_u128(0xCD03)),
            |_store| {
                relocation = Some(fs::rename(state_root, &moved));
            },
        );
        relocation.ok_or("rejection hook did not run")??;
        fs::rename(&moved, state_root)?;
        assert!(
            outcome.is_err(),
            "binding loss returned a confirmed no-write proof"
        );
        assert_eq!(store.get_approval_request(pending.id())?, Some(other));
        drop(store);
        fs::remove_dir_all(root)?;
        Ok(())
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

    #[test]
    fn journal_binding_reopens_exact_store_and_rejects_replacements_and_revision_drift()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, layout, store, _) = store_with_activity("journal-binding")?;
        let binding = store.journal_binding()?;
        drop(store);
        let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
        let reopened = WorkspaceStore::open_existing_journal(&existing, &binding)?;
        assert_eq!(reopened.workspace()?.id(), binding.workspace_id);
        assert_eq!(reopened.workspace()?.revision(), binding.workspace_revision);
        drop(reopened);

        let moved_root = root.with_file_name(format!(
            "{}-moved",
            root.file_name()
                .ok_or("root name missing")?
                .to_string_lossy()
        ));
        fs::rename(&root, &moved_root)?;
        fs::create_dir(&root)?;
        assert!(matches!(
            WorkspaceStore::open_existing_journal(&existing, &binding),
            Err(WorkspaceStoreError::WorkspaceRootBindingConflict { .. })
        ));
        fs::remove_dir_all(&root)?;
        fs::rename(&moved_root, &root)?;

        let state_root = root.join(".heterarchy-forge");
        let moved_state = root.join(".heterarchy-forge-moved");
        fs::rename(&state_root, &moved_state)?;
        fs::create_dir(&state_root)?;
        assert!(matches!(
            WorkspaceStore::open_existing_journal(&existing, &binding),
            Err(WorkspaceStoreError::StateRootChanged(_))
        ));
        fs::remove_dir_all(&state_root)?;
        fs::rename(&moved_state, &state_root)?;

        let database = existing.database_path();
        let moved_database = root.join("state-replacement.sqlite3");
        fs::rename(&database, &moved_database)?;
        fs::copy(&moved_database, &database)?;
        assert!(matches!(
            WorkspaceStore::open_existing_journal(&existing, &binding),
            Err(WorkspaceStoreError::DatabasePathChanged(_))
        ));
        fs::remove_file(&database)?;
        fs::rename(&moved_database, &database)?;

        let connection = Connection::open(&database)?;
        connection.execute(
            "UPDATE workspace SET revision = ?1, updated_at_ms = ?2 WHERE singleton = 1",
            params![2_i64, 2_i64],
        )?;
        assert!(matches!(
            WorkspaceStore::open_existing_journal(&existing, &binding),
            Err(WorkspaceStoreError::WorkspaceRevisionConflict { .. })
        ));
        connection.execute(
            "UPDATE workspace SET revision = ?1, updated_at_ms = ?2 WHERE singleton = 1",
            params![binding.workspace_revision.get(), 1_i64],
        )?;
        drop(connection);

        // Keep the original layout exercised explicitly; it must remain the
        // only accepted path after all replacement attempts have been undone.
        let restored = WorkspaceStore::open_existing_journal(&existing, &binding)?;
        assert_eq!(restored.workspace()?.location_id(), binding.location_id);
        drop(restored);
        drop(layout);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn journal_binding_ignores_lifetime_wal_identity_and_reopens_after_rotation()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, layout, mut store, _) = store_with_activity("journal-binding-wal")?;
        let binding = store.journal_binding()?;
        assert_eq!(binding, binding.clone());
        let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;

        let first = WorkspaceStore::open_existing_journal(&existing, &binding)?;
        assert_eq!(first.workspace()?.id(), binding.workspace_id);
        drop(first);

        store
            .connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
        let workspace = store.workspace()?;
        store.create_activity(&CreateActivity::new(
            activity_id(0xE180),
            workspace.id(),
            workspace.revision(),
            timestamp(4)?,
        ))?;

        let after_rotation = WorkspaceStore::open_existing_journal(&existing, &binding)?;
        assert_eq!(after_rotation.workspace()?.id(), binding.workspace_id);
        drop(after_rotation);
        drop(store);
        drop(layout);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn journal_binding_rejects_old_schema_without_migration()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, _layout, store, _) = store_with_activity("journal-old-schema")?;
        let binding = store.journal_binding()?;
        drop(store);
        let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
        let database = existing.database_path();
        let connection = Connection::open(&database)?;
        connection.pragma_update(None, "user_version", PREVIOUS_SCHEMA_VERSION)?;
        drop(connection);

        assert!(matches!(
            WorkspaceStore::open_existing_journal(&existing, &binding),
            Err(WorkspaceStoreError::OutdatedSchema {
                actual: PREVIOUS_SCHEMA_VERSION,
                current: CURRENT_SCHEMA_VERSION,
            })
        ));
        let connection = Connection::open(&database)?;
        let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
        assert_eq!(version, PREVIOUS_SCHEMA_VERSION);
        drop(connection);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn queue_settings_post_commit_binding_failure_requires_readback()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, layout, mut store, _) = store_with_activity("queue-commit-unknown")?;
        let original_identity = store.database_identity;
        let settings =
            crate::QueueSettings::new(heterarchy_orchestration_policy::QueueCapacity::C64);
        let outcome = store.replace_workspace_queue_settings_with_hook(
            settings,
            None,
            timestamp(3)?,
            |store| store.database_identity.inode ^= 1,
        );
        assert!(matches!(
            outcome,
            Err(WorkspaceStoreError::WorkspaceQueueSettingsCommittedUnconfirmed { .. })
        ));
        store.database_identity = original_identity;
        drop(store);
        let existing = WorkspaceStateLayout::inspect_existing(layout.workspace_root())?
            .ok_or("missing Workspace after committed preference")?;
        let reopened = WorkspaceStore::open_existing(&existing)?;
        let observed = reopened
            .get_workspace_queue_settings()?
            .ok_or("committed row missing")?;
        assert_eq!(observed.settings(), settings);
        assert_eq!(observed.revision(), crate::QueueSettingsRevision::INITIAL);
        drop(reopened);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn queue_settings_sqlite_commit_failure_preserves_unknown_outcome()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, _layout, mut store, _) = store_with_activity("queue-sqlite-commit-unknown")?;
        store.connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TEMP TABLE queue_commit_guard_parent (
                 id INTEGER PRIMARY KEY
             );
             CREATE TEMP TABLE queue_commit_guard_child (
                 parent_id INTEGER REFERENCES queue_commit_guard_parent(id)
                     DEFERRABLE INITIALLY DEFERRED
             );
             CREATE TEMP TRIGGER queue_commit_guard
             AFTER INSERT ON workspace_queue_settings
             BEGIN
                 INSERT INTO queue_commit_guard_child(parent_id) VALUES (99);
             END;",
        )?;

        let outcome = store.replace_workspace_queue_settings(
            crate::QueueSettings::new(heterarchy_orchestration_policy::QueueCapacity::C32),
            None,
            timestamp(3)?,
        );
        assert!(matches!(
            outcome,
            Err(WorkspaceStoreError::WorkspaceQueueSettingsCommittedUnconfirmed { .. })
        ));
        assert_eq!(store.get_workspace_queue_settings()?, None);

        drop(store);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn writer_lease_post_commit_binding_failure_preserves_durable_acquisition()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, layout, mut store, activity_id) = store_with_activity("lease-commit-unknown")?;
        let workspace = store.workspace()?;
        let activity = store.get_activity(activity_id)?.ok_or("missing Activity")?;
        let attribution = insert_file_test_goal(&mut store, workspace.id(), activity_id)?;
        let authority = seed_test_source_write_authority(
            &mut store,
            workspace.id(),
            &activity,
            attribution,
            &WorkspaceRelativePath::new("seed.txt".into())?,
            0xC200,
        )?;
        store.capture_sidecar_identities()?;
        let lease_id = WriterLeaseId::from_uuid(Uuid::from_u128(0xC300));
        let command = forge_domain::AcquireWriterLease::new(
            lease_id,
            workspace.id(),
            activity_id,
            authority.agent_id(),
            forge_domain::WriterLeaseScope::new(vec![forge_domain::WriterLeaseScopeEntry::new(
                forge_domain::WriterLeaseScopeKind::ExactPath,
                WorkspaceRelativePath::new("committed.txt".into())?,
            )])?,
            forge_domain::WriterLeaseDurationMillis::new(1000)?,
            timestamp(20)?,
            authority.session_id(),
            AuthenticatedPrincipal::TrustedStdio,
        )?;
        let identity = store.database_identity;
        let result = store
            .acquire_writer_lease_with_hook(&command, |store| store.database_identity.inode ^= 1);
        assert!(matches!(
            result,
            Err(WorkspaceStoreError::WriterLeaseCommittedUnconfirmed { .. })
        ));
        store.database_identity = identity;
        drop(store);
        let existing = WorkspaceStateLayout::inspect_existing(layout.workspace_root())?
            .ok_or("missing Workspace after lease commit")?;
        let reopened = WorkspaceStore::open_existing(&existing)?;
        let durable = reopened
            .get_writer_lease(lease_id)?
            .ok_or("committed lease missing")?;
        assert_eq!(durable.id(), lease_id);
        assert_eq!(durable.revision(), WriterLeaseRevision::INITIAL);
        assert_eq!(durable.agent_id(), authority.agent_id());
        drop(reopened);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    fn goal_mutation_fixture(
        label: &str,
    ) -> Result<
        (
            PathBuf,
            WorkspaceStateLayout,
            WorkspaceStore,
            forge_domain::GoalMutationCommand,
        ),
        Box<dyn std::error::Error>,
    > {
        let (root, layout, mut store, activity_id) = store_with_live_activity(label)?;
        let workspace = store.workspace()?;
        let activity = store.get_activity(activity_id)?.ok_or("Activity missing")?;
        let attribution = insert_file_test_goal(&mut store, workspace.id(), activity_id)?;
        let authority = seed_test_source_write_authority(
            &mut store,
            workspace.id(),
            &activity,
            attribution,
            &WorkspaceRelativePath::new("goal-receipt.txt".into())?,
            0xCE00,
        )?;
        store.capture_sidecar_identities()?;
        let binding = store.claim_activity_coordinator(
            forge_domain::ClaimActivityCoordinator::new(
                workspace.id(),
                activity_id,
                authority.agent_id(),
                AuthenticatedPrincipal::TrustedStdio,
                timestamp(20)?,
                authority.session_id(),
            ),
            timestamp(99)?,
        )?;
        let actor = forge_domain::ActivityCoordinatorActor::new(
            workspace.id(),
            activity_id,
            authority.agent_id(),
            binding.revision(),
            AuthenticatedPrincipal::TrustedStdio,
            authority.session_id(),
        );
        let command = forge_domain::GoalMutationCommand::new(
            forge_domain::GoalMutationRequestId::from_uuid(Uuid::from_u128(0xCE10)),
            actor,
            workspace.revision(),
            attribution.goal().goal_id(),
            Some(forge_domain::GoalRevision::INITIAL),
            timestamp(21)?,
            forge_domain::GoalMutationAction::Transition(forge_domain::GoalLifecycleAction::Pause),
        )?;
        Ok((root, layout, store, command))
    }

    fn fixture_goal(
        store: &WorkspaceStore,
        command: &forge_domain::GoalMutationCommand,
        value: u128,
        created_at_ms: i64,
    ) -> Result<RegisteredGoal, Box<dyn std::error::Error>> {
        let base = store
            .get_goal(command.goal_id())?
            .ok_or("fixture Goal missing")?;
        Ok(RegisteredGoal::create(
            GoalId::from_uuid(Uuid::from_u128(value)),
            command.actor().workspace_id(),
            command.actor().activity_id(),
            base.contract().clone(),
            timestamp(created_at_ms)?,
        ))
    }

    fn store_with_live_activity(
        label: &str,
    ) -> Result<
        (PathBuf, WorkspaceStateLayout, WorkspaceStore, ActivityId),
        Box<dyn std::error::Error>,
    > {
        let root = unique_root(label)?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_command = command(&layout, workspace_id(100), location_id(101), 1)?;
        let mut store = WorkspaceStore::open(&layout, &workspace_command)?;
        let activity = activity_id(102);
        store.bootstrap_activity(&forge_domain::BootstrapActivity::new(
            activity,
            workspace_command.id(),
            WorkspaceRevision::INITIAL,
            forge_domain::RuntimeInstanceId::from_uuid(Uuid::from_u128(103)),
            timestamp(100)?,
            timestamp(2)?,
        ))?;
        Ok((root, layout, store, activity))
    }

    #[test]
    fn activity_lease_released_through_store_blocks_live_coordinator_authorization()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, _layout, mut store, activity_id) =
            store_with_live_activity("released-activity-admission")?;
        let workspace_id = store.workspace()?.id();
        let agent = inventory_seeded_agent(&store, workspace_id, activity_id, 0xF801)?;
        let session_id = agent
            .session_id()
            .ok_or("released-lease Coordinator session missing")?;
        let binding = store.claim_activity_coordinator(
            forge_domain::ClaimActivityCoordinator::new(
                workspace_id,
                activity_id,
                agent.id(),
                agent.principal(),
                timestamp(4)?,
                session_id,
            ),
            timestamp(99)?,
        )?;
        let actor = forge_domain::ActivityCoordinatorActor::new(
            workspace_id,
            activity_id,
            agent.id(),
            binding.revision(),
            agent.principal(),
            session_id,
        );
        store.release_activity_lease(&ReleaseActivityLease::new(
            activity_id,
            forge_domain::RuntimeInstanceId::from_uuid(Uuid::from_u128(103)),
            ActivityLeaseRevision::INITIAL,
            timestamp(99)?,
        ))?;

        assert!(matches!(
            crate::workspace_coordinators::authorize_live_in_transaction(
                &store.connection,
                actor,
                timestamp(99)?,
            ),
            Err(crate::CoordinatorStoreError::ActivityLeaseNotLive(actual))
                if actual == activity_id
        ));
        assert!(
            crate::workspace_coordinators::authorize_in_transaction(&store.connection, actor)
                .is_ok()
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    fn release_goal_mutation_fixture_lease(
        store: &mut WorkspaceStore,
        command: &forge_domain::GoalMutationCommand,
    ) -> Result<(), Box<dyn std::error::Error>> {
        store.release_writer_lease(
            command.actor().workspace_id(),
            command.actor().activity_id(),
            forge_domain::ReleaseWriterLease::new(
                WriterLeaseId::from_uuid(Uuid::from_u128(0xCE01)),
                AgentInstanceId::from_uuid(Uuid::from_u128(0xCE00)),
                WriterLeaseRevision::INITIAL,
                timestamp(22)?,
                AgentSessionId::from_uuid(Uuid::from_u128(0xCE02)),
                AuthenticatedPrincipal::TrustedStdio,
            ),
        )?;
        Ok(())
    }

    #[allow(
        clippy::too_many_lines,
        reason = "One lifecycle regression covers rollback, deletion, strict reuse fencing, and reopen."
    )]
    #[test]
    fn goal_creation_watermark_fences_deleted_identity_and_survives_reopen()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, layout, mut store, command) = goal_mutation_fixture("goal-create-watermark")?;
        let goal_id = GoalId::from_uuid(Uuid::from_u128(0xCE90));
        release_goal_mutation_fixture_lease(&mut store, &command)?;

        let rejected = fixture_goal(&store, &command, 0xCE91, 25)?;
        store.connection.execute_batch(
            "CREATE TRIGGER reject_goal_created BEFORE INSERT ON semantic_events
             WHEN NEW.event_kind = 'goal_created'
             BEGIN SELECT RAISE(ABORT, 'injected GoalCreated failure'); END",
        )?;
        assert!(
            store
                .insert_goal(command.actor(), &rejected, timestamp(99)?)
                .is_err()
        );
        assert!(store.get_goal(rejected.id())?.is_none());
        assert_eq!(
            crate::workspace_goal_creation_watermarks::greatest_created_at_ms(
                &store.connection,
                command.actor().workspace_id(),
                rejected.id(),
            )?,
            None,
            "the watermark must roll back with a failed GoalCreated append"
        );
        store
            .connection
            .execute_batch("DROP TRIGGER reject_goal_created")?;

        let goal = fixture_goal(&store, &command, 0xCE90, 30)?;
        assert_eq!(goal.id(), goal_id);
        assert_eq!(
            store.insert_goal(command.actor(), &goal, timestamp(99)?)?,
            goal
        );
        assert_eq!(
            store.insert_goal(command.actor(), &goal, timestamp(99)?)?,
            goal
        );
        drop(store);

        let existing = WorkspaceStateLayout::inspect_existing(layout.workspace_root())?
            .ok_or("Workspace missing before Goal deletion")?;
        let gate = WorkspaceStateExclusiveGate::acquire(
            existing.workspace_root(),
            existing.root_fingerprint()?,
        )?;
        let mut deletion = WorkspaceStore::open_goal_deletion(&existing, &gate)?;
        let request = forge_domain::GoalDeletionRequest::new(
            forge_domain::GoalDeletionTarget::Goal,
            goal.workspace_id(),
            goal.activity_id(),
            goal.id(),
            goal.timestamps().created_at(),
            goal.revision(),
            None,
        );
        let crate::GoalDeletionAdmission::Staged(stage) =
            deletion.stage_local(request, timestamp(40)?)?
        else {
            return Err("SQL-only Goal deletion unexpectedly resumed cleanup".into());
        };
        assert!(stage.cleanup_id().is_none());
        assert!(stage.artifacts().is_empty());
        drop(deletion);
        drop(gate);

        let existing = WorkspaceStateLayout::inspect_existing(layout.workspace_root())?
            .ok_or("Workspace missing after Goal deletion")?;
        let mut reopened = WorkspaceStore::open_existing(&existing)?;
        assert!(reopened.get_goal(goal.id())?.is_none());
        for created_at_ms in [30, 29] {
            let reused = RegisteredGoal::create(
                goal.id(),
                goal.workspace_id(),
                goal.activity_id(),
                goal.contract().clone(),
                timestamp(created_at_ms)?,
            );
            assert!(matches!(
                reopened.insert_goal(command.actor(), &reused, timestamp(99)?),
                Err(WorkspaceStoreError::Goal(
                    crate::GoalStoreError::CreationTimestampNotIncreasing { goal_id: rejected_id }
                )) if rejected_id == goal.id()
            ));
        }
        let later = RegisteredGoal::create(
            goal.id(),
            goal.workspace_id(),
            goal.activity_id(),
            goal.contract().clone(),
            timestamp(41)?,
        );
        assert_eq!(
            reopened.insert_goal(command.actor(), &later, timestamp(99)?)?,
            later
        );
        assert_eq!(
            reopened.insert_goal(command.actor(), &later, timestamp(99)?)?,
            later
        );
        assert!(
            reopened
                .connection
                .execute(
                    "DELETE FROM goal_creation_watermarks
                 WHERE workspace_id = ?1 AND goal_id = ?2",
                    params![
                        goal.workspace_id().into_uuid().as_bytes(),
                        goal.id().into_uuid().as_bytes(),
                    ],
                )
                .is_err()
        );
        assert_eq!(
            crate::workspace_goal_creation_watermarks::greatest_created_at_ms(
                &reopened.connection,
                goal.workspace_id(),
                goal.id(),
            )?,
            Some(41)
        );
        drop(reopened);

        let existing = WorkspaceStateLayout::inspect_existing(layout.workspace_root())?
            .ok_or("Workspace missing after Goal recreation")?;
        let reopened = WorkspaceStore::open_existing(&existing)?;
        assert_eq!(reopened.get_goal(goal.id())?, Some(later));
        assert_eq!(
            crate::workspace_goal_creation_watermarks::greatest_created_at_ms(
                &reopened.connection,
                goal.workspace_id(),
                goal.id(),
            )?,
            Some(41)
        );
        drop(reopened);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn schema_v52_adds_empty_assignment_offer_seals_without_backfill()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_root("assignment-offer-seal-v52")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let expected_workspace_id = workspace_id(0xB500);
        let workspace_command = command(&layout, expected_workspace_id, location_id(0xB501), 1)?;
        let mut store = WorkspaceStore::open(&layout, &workspace_command)?;
        let activity_id = activity_id(0xB502);
        store.bootstrap_activity(&forge_domain::BootstrapActivity::new(
            activity_id,
            expected_workspace_id,
            WorkspaceRevision::INITIAL,
            forge_domain::RuntimeInstanceId::from_uuid(Uuid::from_u128(0xB503)),
            timestamp(100)?,
            timestamp(2)?,
        ))?;
        let old_assignment = seed_assignment_for_offer_seal_migration(
            &mut store,
            expected_workspace_id,
            activity_id,
        )?;
        drop(store);

        let database = layout.database_path();
        let connection = Connection::open(&database)?;
        connection.pragma_update(None, "journal_mode", "DELETE")?;
        remove_assignment_offer_seal_and_work_cut_schema(&connection)?;
        connection.pragma_update(
            None,
            "user_version",
            PREVIOUS_ASSIGNMENT_OFFER_SEALS_SCHEMA_VERSION,
        )?;
        let old_assignment_count: i64 = connection.query_row(
            "SELECT COUNT(*) FROM agent_assignments WHERE assignment_id = ?1",
            params![old_assignment.id().into_uuid().as_bytes()],
            |row| row.get(0),
        )?;
        assert_eq!(
            old_assignment_count, 1,
            "the v52 input must include an Assignment"
        );
        drop(connection);
        for sidecar in [
            super::sidecar_path(&database, "-wal"),
            super::sidecar_path(&database, "-shm"),
        ] {
            if sidecar.exists() {
                fs::remove_file(sidecar)?;
            }
        }

        let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("Workspace missing")?;
        assert!(matches!(
            WorkspaceStore::inspect_existing_read_only(&existing),
            Err(WorkspaceStoreError::OutdatedSchema {
                actual: PREVIOUS_ASSIGNMENT_OFFER_SEALS_SCHEMA_VERSION,
                current: CURRENT_SCHEMA_VERSION,
            })
        ));
        let migrated = WorkspaceStore::open_existing(&existing)?;
        assert_eq!(migrated.health()?.schema_version(), CURRENT_SCHEMA_VERSION);
        assert_eq!(
            migrated.get_agent_assignment(old_assignment.id())?,
            Some(old_assignment.clone()),
            "schema upgrade must preserve an existing Assignment unchanged"
        );
        let connection = Connection::open(&database)?;
        let seal_count: i64 = connection.query_row(
            "SELECT COUNT(*) FROM agent_assignment_offer_seals",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(seal_count, 0, "schema upgrade must not fabricate seals");
        drop(connection);
        drop(migrated);
        let reopened = WorkspaceStore::open_existing(&existing)?;
        assert_eq!(
            reopened.get_agent_assignment(old_assignment.id())?,
            Some(old_assignment.clone()),
            "the migrated Assignment remains available after a second reopen"
        );
        assert!(
            reopened
                .get_agent_assignment_offer_seal_local(
                    expected_workspace_id,
                    activity_id,
                    old_assignment.id(),
                )?
                .is_none(),
            "a prior Assignment must not be converted into a fabricated seal"
        );
        drop(reopened);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[allow(
        clippy::too_many_lines,
        reason = "One v53 migration regression preserves the canonical inventory snapshot."
    )]
    #[test]
    fn schema_v53_adds_empty_work_cut_journal_without_changing_canonical_inventory()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, layout, mut store, activity_id) =
            store_with_live_activity("work-cut-schema-v53")?;
        let workspace_id = store.workspace()?.id();
        let agent = inventory_seeded_agent(&store, workspace_id, activity_id, 0xD301)?;
        let session_id = agent
            .session_id()
            .ok_or("work-cut migration fixture Agent is unbound")?;
        let coordinator = store.claim_activity_coordinator(
            forge_domain::ClaimActivityCoordinator::new(
                workspace_id,
                activity_id,
                agent.id(),
                agent.principal(),
                timestamp(4)?,
                session_id,
            ),
            timestamp(99)?,
        )?;
        let actor = forge_domain::ActivityCoordinatorActor::new(
            workspace_id,
            activity_id,
            agent.id(),
            coordinator.revision(),
            agent.principal(),
            session_id,
        );
        let attribution =
            insert_file_test_goal_seeded(&mut store, workspace_id, activity_id, 0xD311)?;
        let node = attribution
            .node()
            .ok_or("Started node attribution missing")?;
        let focus = forge_domain::AgentFocus::new(
            Some(forge_domain::GoalAttribution::new(
                node.goal_id(),
                node.expected_goal_revision(),
            )),
            Some(node.dag_revision()),
            Some(forge_domain::AgentFocusNode::new(
                node.node_id(),
                node.expected_node_revision(),
            )),
        )?;
        let current_agent = store
            .get_agent(agent.id())?
            .ok_or("work-cut migration fixture Agent disappeared")?;
        let _focused = store.set_agent_focus(
            actor,
            &forge_domain::SetAgentFocus::new(
                agent.id(),
                activity_id,
                current_agent.revision(),
                focus,
                timestamp(20)?,
            ),
            timestamp(99)?,
        )?;
        let delegation = install_delegation_seal(&mut store, 0xD321, 21)?;
        let (elected_session, binding) =
            inventory_endpoint(&agent, forge_domain::WorkCutSide::Elected)?;
        let request = work_cut_request_for_inventory(
            &store,
            delegation.destination_id(),
            0xD331,
            vec![
                forge_domain::WorkCutSession::new(
                    forge_domain::WorkCutSide::Incumbent,
                    forge_domain::AgentSessionId::from_uuid(Uuid::from_u128(0xD30F)),
                )?,
                elected_session,
            ],
            vec![binding],
            forge_domain::WorkCutScope::Workspace,
        )?;
        let before_migration = store.observe_leadership_work_inventory(&request)?;
        assert_eq!(before_migration.nodes().len(), 1);
        assert!(before_migration.nodes()[0].direct_focus());
        drop(store);

        let database = layout.database_path();
        let connection = Connection::open(&database)?;
        connection.pragma_update(None, "journal_mode", "DELETE")?;
        remove_work_cut_schema(&connection)?;
        connection.pragma_update(None, "user_version", PREVIOUS_WORK_CUTS_SCHEMA_VERSION)?;
        drop(connection);
        for sidecar in [
            super::sidecar_path(&database, "-wal"),
            super::sidecar_path(&database, "-shm"),
        ] {
            if sidecar.exists() {
                fs::remove_file(sidecar)?;
            }
        }

        let existing = WorkspaceStateLayout::inspect_existing(layout.workspace_root())?
            .ok_or("Workspace missing before v53 migration")?;
        assert!(matches!(
            WorkspaceStore::inspect_existing_read_only(&existing),
            Err(WorkspaceStoreError::OutdatedSchema {
                actual: PREVIOUS_WORK_CUTS_SCHEMA_VERSION,
                current: CURRENT_SCHEMA_VERSION,
            })
        ));
        let migrated = WorkspaceStore::open_existing(&existing)?;
        assert_eq!(migrated.health()?.schema_version(), CURRENT_SCHEMA_VERSION);
        assert_eq!(
            migrated.observe_leadership_work_inventory(&request)?,
            before_migration,
            "schema migration must preserve the canonical inventory snapshot"
        );
        assert!(
            migrated
                .get_leadership_work_cut(request.cut_id())?
                .is_none()
        );
        for (kind, table) in crate::workspace_work_cuts::schema_objects()
            .into_iter()
            .filter(|(kind, _)| *kind == "table")
        {
            let count: i64 = migrated.connection.query_row(
                &format!("SELECT COUNT(*) FROM {table}"),
                [],
                |row| row.get(0),
            )?;
            assert_eq!(
                count, 0,
                "migration must not fabricate rows in {kind} {table}"
            );
        }
        for (kind, table) in crate::workspace_work_cuts::continuation_schema_objects()
            .into_iter()
            .filter(|(kind, _)| *kind == "table")
        {
            let count: i64 = migrated.connection.query_row(
                &format!("SELECT COUNT(*) FROM {table}"),
                [],
                |row| row.get(0),
            )?;
            assert_eq!(
                count, 0,
                "v53 migration must not fabricate continuation rows in {kind} {table}"
            );
        }
        drop(migrated);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[allow(
        clippy::too_many_lines,
        reason = "One custody round trip covers prepare, retry, readback, and the actor fence."
    )]
    #[test]
    fn leadership_work_cut_prepare_round_trips_readback_and_fences_the_actor()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, _layout, mut store, activity_id) =
            store_with_live_activity("work-cut-prepare-round-trip")?;
        let workspace_id = store.workspace()?.id();
        let agent = inventory_seeded_agent(&store, workspace_id, activity_id, 0xD401)?;
        let session_id = agent
            .session_id()
            .ok_or("work-cut fixture Agent is unbound")?;
        let coordinator = store.claim_activity_coordinator(
            forge_domain::ClaimActivityCoordinator::new(
                workspace_id,
                activity_id,
                agent.id(),
                agent.principal(),
                timestamp(4)?,
                session_id,
            ),
            timestamp(99)?,
        )?;
        let actor = forge_domain::ActivityCoordinatorActor::new(
            workspace_id,
            activity_id,
            agent.id(),
            coordinator.revision(),
            agent.principal(),
            session_id,
        );
        let attribution =
            insert_file_test_goal_seeded(&mut store, workspace_id, activity_id, 0xD411)?;
        let node = attribution
            .node()
            .ok_or("work-cut fixture Started node missing")?;
        let focus = forge_domain::AgentFocus::new(
            Some(forge_domain::GoalAttribution::new(
                node.goal_id(),
                node.expected_goal_revision(),
            )),
            Some(node.dag_revision()),
            Some(forge_domain::AgentFocusNode::new(
                node.node_id(),
                node.expected_node_revision(),
            )),
        )?;
        let current_agent = store
            .get_agent(agent.id())?
            .ok_or("work-cut fixture Agent disappeared")?;
        let _focused = store.set_agent_focus(
            actor,
            &forge_domain::SetAgentFocus::new(
                agent.id(),
                activity_id,
                current_agent.revision(),
                focus,
                timestamp(20)?,
            ),
            timestamp(99)?,
        )?;
        let delegation = install_delegation_seal(&mut store, 0xD421, 21)?;
        let incumbent_session = forge_domain::WorkCutSession::new(
            forge_domain::WorkCutSide::Incumbent,
            forge_domain::AgentSessionId::from_uuid(Uuid::from_u128(0xD40F)),
        )?;
        let (elected_session, binding) =
            inventory_endpoint(&agent, forge_domain::WorkCutSide::Elected)?;
        let request = work_cut_request_for_inventory(
            &store,
            delegation.destination_id(),
            0xD431,
            vec![incumbent_session, elected_session],
            vec![binding],
            forge_domain::WorkCutScope::Workspace,
        )?;
        let issuer = forge_domain::OrchestrationIssuerId::from_uuid(Uuid::from_u128(0xD441));
        let grant = forge_domain::WorkCutGrant::new(
            issuer,
            request.request_digest(),
            timestamp(30)?,
            timestamp(90)?,
        )?;
        let now = timestamp(40)?;

        let outcome = store.prepare_leadership_work_cut(
            &request,
            grant,
            issuer,
            request.backend_id(),
            now,
        )?;
        let record = match outcome {
            crate::WorkCutPrepareOutcome::Prepared(record) => record,
            crate::WorkCutPrepareOutcome::Existing(_) => {
                return Err("first prepare must not resolve to Existing".into());
            }
        };
        assert_eq!(record.state(), crate::WorkCutState::Held);
        assert_eq!(record.revision(), 1);
        assert_eq!(record.inventory().nodes().len(), 1);
        assert!(record.inventory().nodes()[0].direct_focus());
        assert_eq!(record.issuer(), issuer);

        let retried = store.prepare_leadership_work_cut(
            &request,
            grant,
            issuer,
            request.backend_id(),
            now,
        )?;
        match retried {
            crate::WorkCutPrepareOutcome::Existing(existing) => assert_eq!(existing, record),
            crate::WorkCutPrepareOutcome::Prepared(_) => {
                return Err("exact retry must resolve to Existing".into());
            }
        }

        let stored = store
            .get_leadership_work_cut(request.cut_id())?
            .ok_or("prepared cut missing from readback")?;
        assert_eq!(stored, record);

        let fenced = store.set_agent_focus(
            actor,
            &forge_domain::SetAgentFocus::new(
                agent.id(),
                activity_id,
                current_agent.revision(),
                focus,
                timestamp(60)?,
            ),
            timestamp(99)?,
        );
        assert!(matches!(
            fenced,
            Err(WorkspaceStoreError::Agent(crate::AgentStoreError::WorkCut(
                _
            )))
        ));

        drop(store);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[allow(
        clippy::too_many_lines,
        reason = "One v51 migration regression distinguishes all authoritative backfill sources."
    )]
    #[test]
    fn schema_v51_backfills_live_goal_created_event_and_pending_cleanup_watermarks()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, layout, mut store, command) = goal_mutation_fixture("goal-watermark-v51")?;
        release_goal_mutation_fixture_lease(&mut store, &command)?;
        let live_goal = store
            .get_goal(command.goal_id())?
            .ok_or("fixture Goal missing")?;
        let created = fixture_goal(&store, &command, 0xCE92, 30)?;
        assert_eq!(
            store.insert_goal(command.actor(), &created, timestamp(99)?)?,
            created
        );
        let update = forge_domain::GoalMutationCommand::new(
            forge_domain::GoalMutationRequestId::from_uuid(Uuid::from_u128(0xCE93)),
            command.actor(),
            store.workspace()?.revision(),
            created.id(),
            Some(forge_domain::GoalRevision::INITIAL),
            timestamp(35)?,
            forge_domain::GoalMutationAction::Transition(forge_domain::GoalLifecycleAction::Pause),
        )?;
        let _transition = store.apply_goal_mutation(&update, None, timestamp(99)?)?;
        let updated = store
            .get_goal(created.id())?
            .ok_or("created Goal missing after update")?;
        assert_eq!(updated.timestamps().created_at(), timestamp(30)?);
        assert_eq!(updated.timestamps().updated_at(), timestamp(35)?);
        drop(store);

        let existing = WorkspaceStateLayout::inspect_existing(layout.workspace_root())?
            .ok_or("Workspace missing before Goal deletion")?;
        let gate = WorkspaceStateExclusiveGate::acquire(
            existing.workspace_root(),
            existing.root_fingerprint()?,
        )?;
        let mut deletion = WorkspaceStore::open_goal_deletion(&existing, &gate)?;
        let request = forge_domain::GoalDeletionRequest::new(
            forge_domain::GoalDeletionTarget::Goal,
            updated.workspace_id(),
            updated.activity_id(),
            updated.id(),
            updated.timestamps().created_at(),
            updated.revision(),
            None,
        );
        let crate::GoalDeletionAdmission::Staged(stage) =
            deletion.stage_local(request, timestamp(40)?)?
        else {
            return Err("SQL-only Goal deletion unexpectedly resumed cleanup".into());
        };
        assert!(stage.cleanup_id().is_none());
        drop(deletion);
        drop(gate);

        let existing = WorkspaceStateLayout::inspect_existing(layout.workspace_root())?
            .ok_or("Workspace missing after Goal deletion")?;
        let mut store = WorkspaceStore::open_existing(&existing)?;
        store.connection.execute(
            "DELETE FROM semantic_events
             WHERE event_kind = 'goal_created' AND subject_goal_id = ?1",
            params![live_goal.id().into_uuid().as_bytes()],
        )?;

        let workspace_bytes = live_goal.workspace_id().into_uuid().into_bytes();
        let activity_bytes = live_goal.activity_id().into_uuid().into_bytes();
        let pending_goal_id = Uuid::from_u128(0xCE94);
        let pending_goal_bytes = pending_goal_id.into_bytes();
        let cleanup_id = Uuid::from_u128(0xCE95);
        let artifact_id = Uuid::from_u128(0xCE96);
        let root_fingerprint = [0xA5_u8; 16];
        let pending_created_at_ms = 50_i64;
        let transaction = store
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "INSERT INTO goal_deletion_cleanup_journal (
                 cleanup_id, ordinal, workspace_id, activity_id, goal_id,
                 goal_created_at_ms, expected_goal_revision, expected_dag_head_revision,
                 target_kind, root_fingerprint, artifact_kind, artifact_id, relative_path,
                 expected_hash, expected_size, requires_filesystem, created_at_ms
             ) VALUES (?1, 0, ?2, ?3, ?4, ?5, 1, NULL, 0, ?6, 0, ?7, NULL, NULL, NULL, 1, 60)",
            params![
                cleanup_id.as_bytes(),
                workspace_bytes.as_slice(),
                activity_bytes.as_slice(),
                pending_goal_bytes.as_slice(),
                pending_created_at_ms,
                root_fingerprint.as_slice(),
                artifact_id.as_bytes(),
            ],
        )?;
        transaction.commit()?;
        drop(store);

        let connection = Connection::open(layout.database_path())?;
        connection.pragma_update(None, "journal_mode", "DELETE")?;
        remove_assignment_offer_seal_and_work_cut_schema(&connection)?;
        for (kind, name) in crate::workspace_goal_creation_watermarks::schema_objects()
            .into_iter()
            .rev()
        {
            connection.execute_batch(&format!("DROP {kind} {name}"))?;
        }
        connection.pragma_update(
            None,
            "user_version",
            PREVIOUS_GOAL_CREATION_WATERMARK_SCHEMA_VERSION,
        )?;
        drop(connection);

        let existing = WorkspaceStateLayout::inspect_existing(layout.workspace_root())?
            .ok_or("Workspace missing before v51 migration")?;
        assert!(matches!(
            WorkspaceStore::inspect_existing_read_only(&existing),
            Err(WorkspaceStoreError::OutdatedSchema {
                actual: PREVIOUS_GOAL_CREATION_WATERMARK_SCHEMA_VERSION,
                current: CURRENT_SCHEMA_VERSION
            })
        ));
        let migrated = WorkspaceStore::open_existing(&existing)?;
        let workspace_id = live_goal.workspace_id();
        assert_eq!(migrated.health()?.schema_version(), CURRENT_SCHEMA_VERSION);
        assert_eq!(
            crate::workspace_goal_creation_watermarks::greatest_created_at_ms(
                &migrated.connection,
                workspace_id,
                live_goal.id(),
            )?,
            Some(live_goal.timestamps().created_at().get()),
            "a current Goal without a retained GoalCreated event uses its row"
        );
        assert_eq!(
            crate::workspace_goal_creation_watermarks::greatest_created_at_ms(
                &migrated.connection,
                workspace_id,
                updated.id(),
            )?,
            Some(updated.timestamps().created_at().get()),
            "a deleted Goal uses only its retained GoalCreated timestamp, not GoalUpdated"
        );
        assert_eq!(
            crate::workspace_goal_creation_watermarks::greatest_created_at_ms(
                &migrated.connection,
                workspace_id,
                forge_domain::GoalId::from_uuid(pending_goal_id),
            )?,
            Some(pending_created_at_ms),
            "a pending deletion contributes its exact stored creation timestamp"
        );
        drop(migrated);

        let existing = WorkspaceStateLayout::inspect_existing(layout.workspace_root())?
            .ok_or("Workspace missing after v51 migration")?;
        let reopened = WorkspaceStore::open_existing(&existing)?;
        assert_eq!(
            crate::workspace_goal_creation_watermarks::greatest_created_at_ms(
                &reopened.connection,
                workspace_id,
                updated.id(),
            )?,
            Some(updated.timestamps().created_at().get())
        );
        drop(reopened);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn goal_receipt_failure_rolls_back_goal_and_semantic_event()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, _layout, mut store, command) = goal_mutation_fixture("goal-receipt-rollback")?;
        let before = store.get_goal(command.goal_id())?.ok_or("Goal missing")?;
        let events: i64 =
            store
                .connection
                .query_row("SELECT COUNT(*) FROM semantic_events", [], |row| row.get(0))?;
        store.connection.execute_batch("CREATE TRIGGER reject_goal_receipt BEFORE INSERT ON goal_mutation_receipts BEGIN SELECT RAISE(ABORT, 'injected receipt failure'); END")?;
        assert!(
            store
                .apply_goal_mutation(&command, None, timestamp(99)?)
                .is_err()
        );
        assert_eq!(store.get_goal(command.goal_id())?, Some(before));
        assert!(store.goal_mutation_receipt(command.request_id())?.is_none());
        let after: i64 =
            store
                .connection
                .query_row("SELECT COUNT(*) FROM semantic_events", [], |row| row.get(0))?;
        assert_eq!(events, after);
        drop(store);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn goal_receipt_replay_does_not_project_another_activity_goal()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, _layout, mut store, command) = goal_mutation_fixture("goal-replay-scope")?;
        let first = store.apply_goal_mutation(&command, None, timestamp(99)?)?;
        let other_id = ActivityId::from_uuid(Uuid::from_u128(0xCE20));
        let _other = store.create_activity(&CreateActivity::new(
            other_id,
            command.actor().workspace_id(),
            command.workspace_revision(),
            timestamp(22)?,
        ))?;
        // Exercise the defensive scope boundary even if the current Goal row
        // now belongs elsewhere; the historical receipt remains in its original scope.
        store.connection.execute(
            "UPDATE goals SET activity_id = ?1 WHERE goal_id = ?2",
            params![
                other_id.into_uuid().as_bytes(),
                command.goal_id().into_uuid().as_bytes()
            ],
        )?;
        let replay = store.apply_goal_mutation(&command, None, timestamp(99)?)?;
        assert!(replay.replayed());
        assert_eq!(replay.receipt(), first.receipt());
        assert!(replay.current_goal().is_none());
        drop(store);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn expired_exact_goal_mutation_replay_is_blocked_but_receipt_readback_survives()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, _layout, mut store, fixture_command) =
            goal_mutation_fixture("goal-replay-expired-authority")?;
        let goal_id = GoalId::from_uuid(Uuid::from_u128(0xCE30));
        let command = forge_domain::GoalMutationCommand::new(
            forge_domain::GoalMutationRequestId::from_uuid(Uuid::from_u128(0xCE31)),
            fixture_command.actor(),
            fixture_command.workspace_revision(),
            goal_id,
            None,
            timestamp(0)?,
            forge_domain::GoalMutationAction::Create(Box::new(GoalContract::new(
                GoalObjective::new("Create with an immutable old audit time".to_owned())?,
                vec![GoalStatement::new(
                    "The lease gate uses admission time".to_owned(),
                )?],
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            )?)),
        )?;

        let applied = store.apply_goal_mutation(&command, None, timestamp(99)?)?;
        assert_eq!(applied.receipt().data().observed_at, timestamp(0)?);

        let replay = store.replay_goal_mutation(&command, timestamp(100)?);
        assert!(matches!(
            replay,
            Err(WorkspaceStoreError::GoalMutation(
                crate::GoalMutationStoreError::Coordinator(
                    crate::CoordinatorStoreError::ActivityLeaseNotLive(activity_id)
                )
            )) if activity_id == fixture_command.actor().activity_id()
        ));

        let readback = store
            .goal_mutation_receipt(command.request_id())?
            .ok_or("historical Goal mutation receipt missing after lease expiry")?;
        assert_eq!(&readback, applied.receipt());
        assert_eq!(store.get_goal(goal_id)?, applied.current_goal().cloned());
        drop(store);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn goal_receipt_survives_postcommit_binding_failure() -> Result<(), Box<dyn std::error::Error>>
    {
        let (root, layout, mut store, command) = goal_mutation_fixture("goal-receipt-postcommit")?;
        let original_identity = store.database_identity;
        let result = store.apply_goal_mutation_with_hook(&command, None, timestamp(99)?, |store| {
            store.database_identity.inode ^= 1;
        });
        assert!(matches!(
            result,
            Err(WorkspaceStoreError::PlanningCommittedUnconfirmed { .. })
        ));
        store.database_identity = original_identity;
        drop(store);
        let existing = WorkspaceStateLayout::inspect_existing(layout.workspace_root())?
            .ok_or("Workspace missing")?;
        let mut store = WorkspaceStore::open_existing(&existing)?;
        let receipt = store
            .goal_mutation_receipt(command.request_id())?
            .ok_or("receipt missing")?;
        assert_eq!(receipt.data().digest, command.digest());
        assert_eq!(
            receipt.data().result_revision,
            forge_domain::GoalRevision::new(2)?
        );
        assert_eq!(
            receipt.data().result_status,
            forge_domain::GoalStatusKind::Paused
        );
        assert_eq!(
            store
                .get_goal(command.goal_id())?
                .ok_or("Goal missing")?
                .revision(),
            receipt.data().result_revision
        );
        drop(store);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    fn open_with_timeout(
        layout: &WorkspaceStateLayout,
        command: &EstablishWorkspace,
        timeout: Duration,
    ) -> Result<WorkspaceStore, WorkspaceStoreError> {
        WorkspaceStore::open_or_establish_with_timeout(layout, command, timeout)
    }

    #[test]
    fn schema_v65_adds_empty_unstarted_continuation_ledger_and_preserves_activity()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, layout, store, activity_id) = store_with_activity("unstarted-continuation-v65")?;
        let before = store.get_activity(activity_id)?.ok_or("Activity missing")?;
        drop(store);

        let connection = Connection::open(layout.database_path())?;
        downgrade_admission_identity(&connection)?;
        connection.execute_batch("DROP TABLE unstarted_activity_continuation_receipts")?;
        connection.execute_batch("DROP TABLE started_activity_lease_resume_receipts")?;
        connection.pragma_update(
            None,
            "user_version",
            super::PREVIOUS_UNSTARTED_ACTIVITY_CONTINUATION_SCHEMA_VERSION,
        )?;
        drop(connection);

        let existing = WorkspaceStateLayout::inspect_existing(layout.workspace_root())?
            .ok_or("Workspace missing")?;
        assert!(matches!(
            WorkspaceStore::inspect_existing_read_only(&existing),
            Err(WorkspaceStoreError::OutdatedSchema {
                actual: super::PREVIOUS_UNSTARTED_ACTIVITY_CONTINUATION_SCHEMA_VERSION,
                current: CURRENT_SCHEMA_VERSION,
            })
        ));
        let migrated = WorkspaceStore::open_existing(&existing)?;
        assert_eq!(migrated.health()?.schema_version(), CURRENT_SCHEMA_VERSION);
        assert_eq!(migrated.get_activity(activity_id)?, Some(before));
        let receipt_count: i64 = migrated.connection.query_row(
            "SELECT COUNT(*) FROM unstarted_activity_continuation_receipts",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(
            receipt_count, 0,
            "schema migration must not invent continuation history"
        );
        drop(migrated);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    fn remove_operations_migration_schema(connection: &Connection) -> Result<(), rusqlite::Error> {
        remove_delegated_effect_schema(connection)?;
        connection.execute_batch("DROP TABLE IF EXISTS agent_binding_reservations")?;
        // Names come only from the canonical closed schema object inventory.
        for (kind, name) in crate::workspace_agent_migration::schema_objects()
            .into_iter()
            .rev()
        {
            connection.execute_batch(&format!("DROP {kind} {name}"))?;
        }
        Ok(())
    }

    fn remove_work_cut_schema(connection: &Connection) -> Result<(), rusqlite::Error> {
        remove_continuation_schema(connection)?;
        for (kind, name) in crate::workspace_work_cuts::schema_objects()
            .into_iter()
            .rev()
        {
            connection.execute_batch(&format!("DROP {kind} IF EXISTS {name}"))?;
        }
        Ok(())
    }

    #[test]
    fn finite_scope_schema_upgrade_preserves_scope_and_reopens()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, layout, store, _) = store_with_activity("unlimited-scope-upgrade")?;
        drop(store);
        let connection = Connection::open(layout.database_path())?;
        connection.execute(
            "INSERT INTO auto_approval_scopes
             (scope_id, workspace_id, activity_id, action_class, workspace_read,
              workspace_write, network, policy_revision, expires_at_ms, max_uses,
              used_count, state, created_at_ms, updated_at_ms, revision)
             SELECT x'11111111111141118111111111111111', workspace_id, NULL,
                    1, 1, 0, 0, 1, 1000, 10, 7, 0, 0, 0, 1 FROM workspace",
            [],
        )?;
        crate::workspace_approvals::rebuild_v55_auto_scopes_fixture(&connection)?;
        remove_execution_stop_schema(&connection)?;
        connection.pragma_update(None, "user_version", 55)?;
        drop(connection);
        let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
        let migrated = WorkspaceStore::open_existing(&existing)?;
        assert_eq!(migrated.health()?.schema_version(), CURRENT_SCHEMA_VERSION);
        let finite: (Option<i64>, i64) = migrated.connection.query_row(
            "SELECT max_uses, used_count FROM auto_approval_scopes
             WHERE scope_id = x'11111111111141118111111111111111'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        assert_eq!(finite, (Some(10), 7));
        migrated.connection.execute(
            "UPDATE auto_approval_scopes SET max_uses = NULL, used_count = 1001
             WHERE scope_id = x'11111111111141118111111111111111'",
            [],
        )?;
        drop(migrated);
        let reopened = WorkspaceStore::open_existing(&existing)?;
        assert_eq!(reopened.health()?.schema_version(), CURRENT_SCHEMA_VERSION);
        let unlimited: (Option<i64>, i64) = reopened.connection.query_row(
            "SELECT max_uses, used_count FROM auto_approval_scopes
             WHERE scope_id = x'11111111111141118111111111111111'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        assert_eq!(unlimited, (None, 1001));
        drop(reopened);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    fn remove_continuation_schema(connection: &Connection) -> Result<(), rusqlite::Error> {
        remove_execution_stop_schema(connection)?;
        crate::workspace_approvals::rebuild_v55_auto_scopes_fixture(connection)?;
        for (kind, name) in crate::workspace_work_cuts::continuation_schema_objects()
            .into_iter()
            .rev()
        {
            connection.execute_batch(&format!("DROP {kind} IF EXISTS {name}"))?;
        }
        Ok(())
    }

    fn remove_stop_settlement_schema(
        connection: &Connection,
    ) -> Result<(), Box<dyn std::error::Error>> {
        remove_recovery_runs_schema(connection)?;
        connection.pragma_update(None, "foreign_keys", false)?;
        let result = (|| -> Result<(), Box<dyn std::error::Error>> {
            connection.execute_batch(
                "DROP TABLE IF EXISTS workspace_execution_stop_settlement_targets;
                DROP TABLE IF EXISTS workspace_execution_stop_settlements;
                DROP TABLE IF EXISTS workspace_execution_stop_fences;",
            )?;
            crate::workspace_execution_stops::rebuild_capture_v59_fixture(connection)?;
            Ok(())
        })();
        connection.pragma_update(None, "foreign_keys", true)?;
        result
    }

    fn remove_execution_stop_schema(connection: &Connection) -> Result<(), rusqlite::Error> {
        remove_recovery_runs_schema(connection)?;
        connection.execute_batch(
            "DROP TABLE IF EXISTS workspace_execution_stop_settlement_targets;
             DROP TABLE IF EXISTS workspace_execution_stop_settlements;
             DROP TABLE IF EXISTS workspace_execution_stop_fences;
             DROP TABLE IF EXISTS execution_native_closures;
             DROP TABLE IF EXISTS authority_stop_targets;
             DROP TABLE IF EXISTS authority_stop_batches;
             DROP TABLE IF EXISTS workspace_execution_stop_targets;
             DROP TABLE IF EXISTS workspace_execution_stops;",
        )
    }

    fn remove_recovery_runs_schema(connection: &Connection) -> Result<(), rusqlite::Error> {
        downgrade_admission_identity(connection)?;
        connection.execute_batch(
            "DROP TABLE IF EXISTS unstarted_activity_continuation_receipts;
            DROP TRIGGER IF EXISTS agent_binding_activations_block_rejection;
            DROP TRIGGER IF EXISTS agent_binding_rejections_block_activation;
            DROP TABLE IF EXISTS agent_binding_rejections;
            DROP INDEX IF EXISTS expired_activity_recovery_receipts_successor_uidx;
            DROP TABLE IF EXISTS expired_activity_recovery_agents;
            DROP TABLE IF EXISTS expired_activity_recovery_receipts;
            DROP TABLE IF EXISTS recovery_run_executions;
            DROP TABLE IF EXISTS recovery_run_activities;
            DROP TABLE IF EXISTS recovery_runs;
            DROP TABLE IF EXISTS root_recovery_delegation_receipts;
            DROP TABLE IF EXISTS workspace_root_recovery_receipts;",
        )
    }

    fn remove_assignment_offer_seal_and_work_cut_schema(
        connection: &Connection,
    ) -> Result<(), rusqlite::Error> {
        remove_work_cut_schema(connection)?;
        for (kind, name) in crate::workspace_agent_assignments::offer_seal_schema_objects()
            .into_iter()
            .rev()
        {
            connection.execute_batch(&format!("DROP {kind} {name}"))?;
        }
        Ok(())
    }

    fn remove_goal_creation_watermark_schema(
        connection: &Connection,
    ) -> Result<(), rusqlite::Error> {
        remove_assignment_offer_seal_and_work_cut_schema(connection)?;
        for (kind, name) in crate::workspace_goal_creation_watermarks::schema_objects()
            .into_iter()
            .rev()
        {
            connection.execute_batch(&format!("DROP {kind} {name}"))?;
        }
        Ok(())
    }

    fn seed_assignment_for_offer_seal_migration(
        store: &mut WorkspaceStore,
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
    ) -> Result<forge_domain::RegisteredAgentAssignment, Box<dyn std::error::Error>> {
        let coordinator_agent = migration_test_agent(workspace_id, activity_id, 0xB510)?;
        let target_agent = migration_test_agent(workspace_id, activity_id, 0xB520)?;
        for (agent, event_id) in [
            (&coordinator_agent, Uuid::from_u128(0xB511)),
            (&target_agent, Uuid::from_u128(0xB521)),
        ] {
            crate::legacy_agent_seed::seed_agent(
                &store.connection,
                agent,
                Some(forge_domain::AgentEventId::from_uuid(event_id)),
            )?;
        }
        let coordinator_session = coordinator_agent
            .session_id()
            .ok_or("migration Coordinator session missing")?;
        let binding = store.claim_activity_coordinator(
            forge_domain::ClaimActivityCoordinator::new(
                workspace_id,
                activity_id,
                coordinator_agent.id(),
                AuthenticatedPrincipal::TrustedStdio,
                timestamp(4)?,
                coordinator_session,
            ),
            timestamp(99)?,
        )?;
        let coordinator = forge_domain::ActivityCoordinatorActor::new(
            workspace_id,
            activity_id,
            coordinator_agent.id(),
            binding.revision(),
            AuthenticatedPrincipal::TrustedStdio,
            coordinator_session,
        );
        let goal = RegisteredGoal::create(
            GoalId::from_uuid(Uuid::from_u128(0xB530)),
            workspace_id,
            activity_id,
            GoalContract::new(
                GoalObjective::new("Preserve this Assignment during migration".to_owned())?,
                vec![GoalStatement::new(
                    "The prior Assignment remains readable".to_owned(),
                )?],
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            )?,
            timestamp(5)?,
        );
        let goal = store.insert_goal(coordinator, &goal, timestamp(99)?)?;
        let definition = DagNodeDefinition::new(
            DagNodeId::from_uuid(Uuid::from_u128(0xB531)),
            DagNodeOrdinal::new(0)?,
            DagNodeTitle::new("Retained Assignment".to_owned())?,
            DagNodeObjective::new("Remain durably registered".to_owned())?,
            vec![DagAcceptanceCriterion::new(
                "The Assignment row remains".to_owned(),
            )?],
        )?;
        let dag = DagRevision::new(
            DagRevisionId::from_uuid(Uuid::from_u128(0xB532)),
            goal.id(),
            goal.revision(),
            DagRevisionNumber::INITIAL,
            None,
            vec![definition.clone()],
            Vec::new(),
            timestamp(6)?,
        )?;
        let node = RegisteredDagNode::create(goal.id(), dag.number(), definition, timestamp(6)?);
        let _ = store.insert_dag_revision(&dag, std::slice::from_ref(&node), &[], None)?;
        let target = forge_domain::AgentAssignmentTarget::new(
            target_agent.id(),
            target_agent
                .session_id()
                .ok_or("migration target session missing")?,
            target_agent.principal(),
            target_agent.revision(),
        );
        let offer = forge_domain::OfferAgentAssignment::new(
            forge_domain::AgentAssignmentId::from_uuid(Uuid::from_u128(0xB533)),
            coordinator,
            target,
            goal.id(),
            goal.revision(),
            goal.timestamps().created_at(),
            dag.number(),
            forge_domain::DagHeadRevision::INITIAL,
            node.id(),
            node.revision(),
            None,
            timestamp(7)?,
        );
        Ok(store.offer_agent_assignment(&offer, timestamp(99)?)?)
    }

    fn remove_goal_mutation_receipts_schema(
        connection: &Connection,
    ) -> Result<(), rusqlite::Error> {
        remove_goal_creation_watermark_schema(connection)?;
        for (kind, name) in crate::workspace_coordinator_recovery::schema_objects() {
            connection.execute_batch(&format!("DROP {kind} {name}"))?;
        }
        for (kind, name) in crate::workspace_goal_mutations::schema_objects()
            .into_iter()
            .rev()
        {
            connection.execute_batch(&format!("DROP {kind} {name}"))?;
        }
        Ok(())
    }

    fn remove_delegated_effect_schema(connection: &Connection) -> Result<(), rusqlite::Error> {
        remove_goal_mutation_receipts_schema(connection)?;
        for (kind, name) in crate::workspace_effect_fact_outbox::base_schema_objects()
            .into_iter()
            .chain(crate::workspace_effect_fact_outbox::change_set_schema_objects())
            .chain(crate::workspace_effect_fact_outbox::work_credit_schema_objects())
            .chain(crate::workspace_effect_fact_outbox::assignment_offered_schema_objects())
            .chain(crate::workspace_effect_fact_outbox::assignment_submitted_schema_objects())
            .chain(crate::workspace_semantic_events::schema_objects())
            .chain(crate::workspace_admission_envelopes::schema_objects())
            .rev()
        {
            connection.execute_batch(&format!("DROP {kind} {name}"))?;
        }
        for (kind, name) in crate::workspace_agent_departure_reconciliation::schema_objects()
            .into_iter()
            .rev()
        {
            connection.execute_batch(&format!("DROP {kind} {name}"))?;
        }
        for (kind, name) in crate::workspace_agent_session_reconciliation::schema_objects()
            .into_iter()
            .rev()
        {
            connection.execute_batch(&format!("DROP {kind} {name}"))?;
        }
        for (kind, name) in crate::workspace_agent_binding_activation::schema_objects()
            .into_iter()
            .rev()
        {
            connection.execute_batch(&format!("DROP {kind} {name}"))?;
        }
        for (kind, name) in crate::workspace_agent_effect_outbox::schema_objects()
            .into_iter()
            .rev()
        {
            connection.execute_batch(&format!("DROP {kind} {name}"))?;
        }
        for (kind, name) in crate::workspace_agent_delegation::schema_objects()
            .into_iter()
            .rev()
        {
            connection.execute_batch(&format!("DROP {kind} {name}"))?;
        }
        Ok(())
    }

    /// Revert the additive `WorkCredit` budget column so a fixture matches the
    /// exact pre-v42 `agent_assignments` shape. `SQLite` restores the original
    /// schema text when the added column is dropped again.
    fn remove_work_credit_column(connection: &Connection) -> Result<(), rusqlite::Error> {
        connection.execute_batch("ALTER TABLE agent_assignments DROP COLUMN credit_budget")
    }

    fn remove_change_set_producer_columns_from(
        connection: &Connection,
    ) -> Result<(), rusqlite::Error> {
        connection.execute_batch(
            "ALTER TABLE effect_fact_outbox_change_set DROP COLUMN producer_agent_id;
             ALTER TABLE effect_fact_outbox_change_set DROP COLUMN producer_session_id;",
        )
    }

    fn remove_assignment_submitted_source_refs_from(
        connection: &Connection,
    ) -> Result<(), rusqlite::Error> {
        connection.execute_batch(
            "DROP TABLE effect_fact_outbox_assignment_submitted_source_ref;
             ALTER TABLE effect_fact_outbox_assignment_submitted DROP COLUMN source_refs_recorded;",
        )
    }

    fn migration_test_agent(
        workspace: WorkspaceId,
        activity: ActivityId,
        seed: u128,
    ) -> Result<forge_domain::RegisteredAgentInstance, Box<dyn std::error::Error>> {
        Ok(forge_domain::RegisteredAgentInstance::create_bound(
            AgentInstanceId::from_uuid(Uuid::from_u128(seed)),
            workspace,
            activity,
            AgentSessionId::from_uuid(Uuid::from_u128(seed + 1)),
            AgentDisplayName::new("migration participant".to_owned())?,
            AgentDeclaredRole::new("worker".to_owned())?,
            AgentTransportKind::Stdio,
            AuthenticatedPrincipal::TrustedStdio,
            timestamp(3)?,
        ))
    }

    #[test]
    fn binding_reservation_survives_reopen_but_never_creates_an_agent()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, layout, mut store, activity) = store_with_activity("binding-reservation")?;
        let frozen = store.freeze_agent_operations(&crate::AgentOperationsFreezeRequest::new(
            Uuid::from_u128(0xBC101),
            Uuid::from_u128(0xBC102),
            timestamp(4)?,
        )?)?;
        let request = crate::AgentBindingReservationRequest::new(
            Uuid::from_u128(0xBC103),
            activity,
            AgentInstanceId::from_uuid(Uuid::from_u128(0xBC104)),
            AgentSessionId::from_uuid(Uuid::from_u128(0xBC105)),
            AuthenticatedPrincipal::TrustedStdio,
            timestamp(5)?,
        )?;
        let first = store.reserve_agent_binding(&frozen, &request, timestamp(6)?)?;
        assert_eq!(
            store.reserve_agent_binding(&frozen, &request, timestamp(7)?)?,
            first
        );
        assert!(store.get_agent(request.agent_id())?.is_none());
        for table in [
            "agent_instances",
            "agent_presence",
            "agent_events",
            "agent_inbox",
        ] {
            let count: i64 = store.connection.query_row(
                &format!("SELECT COUNT(*) FROM {table}"),
                [],
                |row| row.get(0),
            )?;
            assert_eq!(
                count, 0,
                "reservation must not create active operation state"
            );
        }
        let conflicting = crate::AgentBindingReservationRequest::new(
            Uuid::from_u128(0xBC106),
            activity,
            AgentInstanceId::from_uuid(Uuid::from_u128(0xBC107)),
            request.session_id(),
            request.principal(),
            request.requested_at(),
        )?;
        assert!(
            store
                .reserve_agent_binding(&frozen, &conflicting, timestamp(7)?)
                .is_err()
        );
        drop(store);
        let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
        let mut store = WorkspaceStore::open_existing(&existing)?;
        assert_eq!(
            store.agent_binding_reservation(request.request_id())?,
            Some(first)
        );
        let _released = store.release_agent_operations_freeze(
            frozen.migration_id(),
            frozen.revision(),
            timestamp(8)?,
        )?;
        assert!(
            store
                .reserve_agent_binding(&frozen, &request, timestamp(9)?)
                .is_err()
        );
        assert!(store.get_agent(request.agent_id())?.is_none());
        assert!(
            store
                .agent_binding_reservation(request.request_id())?
                .is_some()
        );
        drop(store);
        drop(layout);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn v35_upgrade_preserves_frozen_agent_history_and_adds_empty_reservations()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, layout, mut store, activity) = store_with_activity("binding-upgrade")?;
        let agent = migration_test_agent(store.workspace()?.id(), activity, 0xBC200)?;
        crate::legacy_agent_seed::seed_agent(
            &store.connection,
            &agent,
            Some(forge_domain::AgentEventId::from_uuid(Uuid::from_u128(
                0xBC202,
            ))),
        )?;
        let frozen = store.freeze_agent_operations(&crate::AgentOperationsFreezeRequest::new(
            Uuid::from_u128(0xBC203),
            Uuid::from_u128(0xBC204),
            timestamp(4)?,
        )?)?;
        drop(store);
        let connection = Connection::open(layout.database_path())?;
        // Drop the added column while every delegated-fence table it may be
        // re-parsed against still exists.
        remove_work_cut_schema(&connection)?;
        remove_work_credit_column(&connection)?;
        remove_delegated_effect_schema(&connection)?;
        connection.execute_batch("DROP TABLE agent_binding_reservations")?;
        crate::workspace_agent_migration::install_legacy_fences(&connection)?;
        // Schema 50 added the approval-authority freeze fences; the v35 shape
        // must not carry them.
        for (kind, name) in crate::workspace_agent_migration::approval_authority_schema_objects() {
            connection.execute_batch(&format!("DROP {kind} {name}"))?;
        }
        connection.pragma_update(None, "user_version", 35)?;
        drop(connection);
        let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
        let store = WorkspaceStore::open_existing(&existing)?;
        assert_eq!(store.health()?.schema_version(), CURRENT_SCHEMA_VERSION);
        assert_eq!(store.get_agent(agent.id())?, Some(agent));
        assert_eq!(
            store.agent_operations_freeze(frozen.migration_id())?,
            Some(frozen)
        );
        let count: i64 = store.connection.query_row(
            "SELECT COUNT(*) FROM agent_binding_reservations",
            [],
            |r| r.get(0),
        )?;
        assert_eq!(count, 0);
        drop(store);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn v36_upgrade_preserves_reservation_and_legacy_agent_history()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, layout, mut store, activity) = store_with_activity("delegated-upgrade")?;
        let workspace = store.workspace()?.id();
        let agent = migration_test_agent(workspace, activity, 0xBC300)?;
        crate::legacy_agent_seed::seed_agent(
            &store.connection,
            &agent,
            Some(forge_domain::AgentEventId::from_uuid(Uuid::from_u128(
                0xBC302,
            ))),
        )?;
        let attached = agent.clone();
        let frozen = store.freeze_agent_operations(&crate::AgentOperationsFreezeRequest::new(
            Uuid::from_u128(0xBC303),
            Uuid::from_u128(0xBC304),
            timestamp(4)?,
        )?)?;
        let request = crate::AgentBindingReservationRequest::new(
            Uuid::from_u128(0xBC305),
            activity,
            AgentInstanceId::from_uuid(Uuid::from_u128(0xBC306)),
            AgentSessionId::from_uuid(Uuid::from_u128(0xBC307)),
            AuthenticatedPrincipal::TrustedStdio,
            timestamp(5)?,
        )?;
        let reservation = store.reserve_agent_binding(&frozen, &request, timestamp(6)?)?;
        let legacy_counts = ["agent_presence", "agent_events", "agent_inbox"]
            .into_iter()
            .map(|table| {
                store
                    .connection
                    .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                        row.get::<_, i64>(0)
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        drop(store);

        let connection = Connection::open(layout.database_path())?;
        // Drop the added column while every delegated-fence table it may be
        // re-parsed against still exists.
        remove_work_cut_schema(&connection)?;
        remove_work_credit_column(&connection)?;
        remove_delegated_effect_schema(&connection)?;
        crate::workspace_agent_migration::install_legacy_fences(&connection)?;
        // Schema 50 added the approval-authority freeze fences; the v36 shape
        // must not carry them.
        for (kind, name) in crate::workspace_agent_migration::approval_authority_schema_objects()
            .into_iter()
            .rev()
        {
            connection.execute_batch(&format!("DROP {kind} {name}"))?;
        }
        connection.pragma_update(None, "user_version", 36_i64)?;
        crate::workspace_agent_migration::validate_schema(&connection)?;
        let blocked_write = connection.execute(
            "UPDATE agent_instances SET display_name = 'must remain fenced' WHERE agent_id = ?1",
            params![attached.id().into_uuid().as_bytes()],
        );
        assert!(blocked_write.is_err(), "v36 freeze fence was not restored");
        drop(connection);

        let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
        let migrated = WorkspaceStore::open_existing(&existing)?;
        assert_eq!(migrated.health()?.schema_version(), CURRENT_SCHEMA_VERSION);
        assert_eq!(
            migrated.agent_operations_freeze(frozen.migration_id())?,
            Some(frozen)
        );
        assert_eq!(
            migrated.agent_binding_reservation(request.request_id())?,
            Some(reservation)
        );
        assert_eq!(migrated.get_agent(attached.id())?, Some(attached));
        let migrated_counts = ["agent_presence", "agent_events", "agent_inbox"]
            .into_iter()
            .map(|table| {
                migrated
                    .connection
                    .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                        row.get::<_, i64>(0)
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(migrated_counts, legacy_counts);
        for table in [
            "agent_operations_delegations",
            "agent_binding_activations",
            "agent_effect_outbox_entries",
            "agent_effect_outbox_focus",
            "agent_effect_outbox_transitions",
            "agent_effect_outbox_recipients",
        ] {
            let count: i64 = migrated.connection.query_row(
                &format!("SELECT COUNT(*) FROM {table}"),
                [],
                |row| row.get(0),
            )?;
            assert_eq!(count, 0, "new delegated object {table} must start empty");
        }
        drop(migrated);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn operations_freeze_fences_stale_connections_and_survives_reopen()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, layout, mut store, activity) = store_with_activity("operations-freeze")?;
        let (other_root, _, other, other_activity) = store_with_activity("operations-other")?;
        let agent = migration_test_agent(store.workspace()?.id(), activity, 0xFA001)?;
        crate::legacy_agent_seed::seed_agent(
            &store.connection,
            &agent,
            Some(forge_domain::AgentEventId::from_uuid(Uuid::from_u128(
                0xFA003,
            ))),
        )?;
        let mut stale = Connection::open(layout.database_path())?;
        let request = crate::AgentOperationsFreezeRequest::new(
            Uuid::from_u128(0xFA004),
            Uuid::from_u128(0xFA005),
            timestamp(4)?,
        )?;
        let frozen = store.freeze_agent_operations(&request)?;
        assert_eq!(store.freeze_agent_operations(&request)?, frozen);
        let transaction = stale.transaction()?;
        transaction.execute("UPDATE activities SET updated_at_ms = 100", [])?;
        assert!(
            transaction
                .execute(
                    "UPDATE agent_instances SET display_name = 'stale writer'",
                    []
                )
                .is_err()
        );
        drop(transaction);
        assert_eq!(
            store
                .get_activity(activity)?
                .ok_or("activity missing")?
                .updated_at(),
            timestamp(2)?
        );
        let other_agent = migration_test_agent(other.workspace()?.id(), other_activity, 0xFA006)?;
        crate::legacy_agent_seed::seed_agent(
            &other.connection,
            &other_agent,
            Some(forge_domain::AgentEventId::from_uuid(Uuid::from_u128(
                0xFA008,
            ))),
        )?;
        drop(stale);
        drop(store);
        let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
        let mut reopened = WorkspaceStore::open_existing(&existing)?;
        assert_eq!(
            reopened.agent_operations_freeze(Uuid::from_u128(0xFA004))?,
            Some(frozen)
        );
        let released =
            reopened.release_agent_operations_freeze(Uuid::from_u128(0xFA004), 1, timestamp(6)?)?;
        assert_eq!(
            reopened.release_agent_operations_freeze(Uuid::from_u128(0xFA004), 1, timestamp(6)?)?,
            released
        );
        assert_eq!(reopened.freeze_agent_operations(&request)?, released);
        drop(reopened);
        drop(other);
        fs::remove_dir_all(root)?;
        fs::remove_dir_all(other_root)?;
        Ok(())
    }

    #[test]
    fn v34_migration_preserves_participants_and_rejects_dropped_freeze_trigger()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, layout, store, activity) = store_with_activity("operations-upgrade")?;
        let agent = migration_test_agent(store.workspace()?.id(), activity, 0xFB001)?;
        crate::legacy_agent_seed::seed_agent(
            &store.connection,
            &agent,
            Some(forge_domain::AgentEventId::from_uuid(Uuid::from_u128(
                0xFB003,
            ))),
        )?;
        drop(store);
        let connection = Connection::open(layout.database_path())?;
        remove_work_cut_schema(&connection)?;
        remove_operations_migration_schema(&connection)?;
        remove_work_credit_column(&connection)?;
        connection.pragma_update(None, "user_version", 34)?;
        drop(connection);
        let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
        let migrated = WorkspaceStore::open_existing(&existing)?;
        assert_eq!(migrated.health()?.schema_version(), CURRENT_SCHEMA_VERSION);
        assert_eq!(migrated.get_agent(agent.id())?, Some(agent));
        drop(migrated);
        let connection = Connection::open(layout.database_path())?;
        let (_, trigger) = crate::workspace_agent_migration::schema_objects()
            .into_iter()
            .find(|(kind, _)| *kind == "trigger")
            .ok_or("trigger missing")?;
        connection.execute_batch(&format!("DROP TRIGGER {trigger}"))?;
        drop(connection);
        assert!(WorkspaceStore::open_existing(&existing).is_err());
        fs::remove_dir_all(root)?;
        Ok(())
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
             PRAGMA user_version = {CURRENT_SCHEMA_VERSION};"
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
    fn outdated_workspace_schemas_are_rejected_without_mutation()
    -> Result<(), Box<dyn std::error::Error>> {
        for version in [1_i64, 8, 16] {
            let root = unique_root(&format!("outdated-schema-{version}"))?;
            let layout = WorkspaceStateLayout::initialize(&root)?;
            let workspace_command = command(
                &layout,
                workspace_id(0xA000 + u128::try_from(version)?),
                location_id(0xA100 + u128::try_from(version)?),
                1,
            )?;
            drop(WorkspaceStore::open(&layout, &workspace_command)?);

            let database = layout.database_path();
            let connection = Connection::open(&database)?;
            connection.pragma_update(None, "journal_mode", "DELETE")?;
            connection.pragma_update(None, "user_version", version)?;
            drop(connection);
            for sidecar in [
                super::sidecar_path(&database, "-wal"),
                super::sidecar_path(&database, "-shm"),
            ] {
                if sidecar.exists() {
                    fs::remove_file(sidecar)?;
                }
            }

            let existing =
                WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
            assert!(matches!(
                WorkspaceStore::inspect_existing_read_only(&existing),
                Err(WorkspaceStoreError::OutdatedSchema {
                    actual,
                    current: CURRENT_SCHEMA_VERSION
                }) if actual == version
            ));
            assert!(matches!(
                WorkspaceStore::inspect_recovery_maintenance_lease_live_read_only(&existing),
                Err(WorkspaceStoreError::OutdatedSchema {
                    actual,
                    current: CURRENT_SCHEMA_VERSION
                }) if actual == version
            ));
            assert!(matches!(
                WorkspaceStore::open_existing(&existing),
                Err(WorkspaceStoreError::OutdatedSchema {
                    actual,
                    current: CURRENT_SCHEMA_VERSION
                }) if actual == version
            ));
            assert!(matches!(
                WorkspaceStore::open(&layout, &workspace_command),
                Err(WorkspaceStoreError::OutdatedSchema {
                    actual,
                    current: CURRENT_SCHEMA_VERSION
                }) if actual == version
            ));

            let connection = Connection::open(&database)?;
            let observed: i64 =
                connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
            assert_eq!(observed, version);
            drop(connection);
            fs::remove_dir_all(root)?;
        }
        Ok(())
    }

    #[test]
    fn coordinator_recovery_v50_migration_preserves_authority_without_inventing_receipts()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, layout, store, command) = goal_mutation_fixture("coordinator-recovery-v50")?;
        let activity_id = command.actor().activity_id();
        let before_activity = store.get_activity(activity_id)?;
        let before_coordinator = store.get_activity_coordinator(activity_id)?;
        let before_goal = store.get_goal(command.goal_id())?;
        drop(store);
        let connection = Connection::open(layout.database_path())?;
        connection.pragma_update(None, "journal_mode", "DELETE")?;
        remove_goal_creation_watermark_schema(&connection)?;
        for (kind, name) in crate::workspace_coordinator_recovery::schema_objects() {
            connection.execute_batch(&format!("DROP {kind} {name}"))?;
        }
        connection.pragma_update(
            None,
            "user_version",
            PREVIOUS_COORDINATOR_RECOVERY_SCHEMA_VERSION,
        )?;
        drop(connection);
        let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
        assert!(matches!(
            WorkspaceStore::inspect_existing_read_only(&existing),
            Err(WorkspaceStoreError::OutdatedSchema {
                actual: PREVIOUS_COORDINATOR_RECOVERY_SCHEMA_VERSION,
                current: CURRENT_SCHEMA_VERSION
            })
        ));
        let migrated = WorkspaceStore::open_existing(&existing)?;
        assert_eq!(migrated.health()?.schema_version(), CURRENT_SCHEMA_VERSION);
        crate::workspace_coordinator_recovery::validate_schema(&migrated.connection)?;
        assert_eq!(migrated.get_activity(activity_id)?, before_activity);
        assert_eq!(
            migrated.get_activity_coordinator(activity_id)?,
            before_coordinator
        );
        assert_eq!(migrated.get_goal(command.goal_id())?, before_goal);
        assert!(
            migrated
                .coordinator_recovery_history(activity_id, 32)?
                .is_empty()
        );
        drop(migrated);
        let reopened = WorkspaceStore::open_existing(&existing)?;
        assert_eq!(
            reopened.get_activity_coordinator(activity_id)?,
            before_coordinator
        );
        assert!(
            reopened
                .coordinator_recovery_history(activity_id, 32)?
                .is_empty()
        );
        drop(reopened);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn previous_goal_mutation_receipt_schema_preserves_goals_without_fabrication()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, layout, mut store, activity_id) =
            store_with_activity("goal-mutation-receipts-v48")?;
        let workspace_id = store.workspace()?.id();
        let goal = RegisteredGoal::create(
            GoalId::from_uuid(Uuid::from_u128(0xD480)),
            workspace_id,
            activity_id,
            GoalContract::new(
                GoalObjective::new("Preserve the Goal across schema migration".to_owned())?,
                vec![GoalStatement::new("No receipt row is inferred".to_owned())?],
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            )?,
            timestamp(10)?,
        );
        let _ = workspace_goals::insert_goal(&mut store.connection, &goal)?;
        drop(store);

        let connection = Connection::open(layout.database_path())?;
        connection.pragma_update(None, "journal_mode", "DELETE")?;
        remove_goal_mutation_receipts_schema(&connection)?;
        for (kind, name) in crate::workspace_agent_migration::approval_authority_schema_objects() {
            connection.execute_batch(&format!("DROP {kind} {name}"))?;
        }
        connection.pragma_update(
            None,
            "user_version",
            PREVIOUS_GOAL_MUTATION_RECEIPTS_SCHEMA_VERSION,
        )?;
        drop(connection);

        let existing = WorkspaceStateLayout::inspect_existing(layout.workspace_root())?
            .ok_or("Workspace state layout disappeared before v48 fixture")?;
        let migrated = WorkspaceStore::open_existing(&existing)?;
        assert_eq!(migrated.health()?.schema_version(), CURRENT_SCHEMA_VERSION);
        assert_eq!(migrated.get_goal(goal.id())?, Some(goal));
        let receipt_count: i64 = migrated.connection.query_row(
            "SELECT COUNT(*) FROM goal_mutation_receipts",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(
            receipt_count, 0,
            "v48 migration must not fabricate receipts"
        );
        drop(migrated);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn previous_source_refs_schema_migrates_without_fabricating_refs()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, layout, store, activity_id) = store_with_activity("effect-fact-v47")?;
        let workspace_id = store.workspace()?.id();
        drop(store);

        let migration = Uuid::from_u128(0xD470);
        let destination = Uuid::from_u128(0xD471);
        let assignment = Uuid::from_u128(0xD472);
        let goal = Uuid::from_u128(0xD473);
        let node = Uuid::from_u128(0xD474);
        let target_agent = Uuid::from_u128(0xD475);
        let connection = Connection::open(layout.database_path())?;
        connection.pragma_update(None, "foreign_keys", true)?;
        connection.execute(
            "INSERT INTO effect_fact_outbox_entries(
                migration_id, destination_id, workspace_id, fact_kind
             ) VALUES(?1, ?2, ?3, 4)",
            params![
                migration.as_bytes(),
                destination.as_bytes(),
                workspace_id.into_uuid().as_bytes()
            ],
        )?;
        let sequence = connection.last_insert_rowid();
        connection.execute(
            "INSERT INTO effect_fact_outbox_assignment_submitted(
                outbox_sequence, migration_id, destination_id, workspace_id,
                activity_id, assignment_id, goal_id, node_id, target_agent_id,
                target_session_id, source_count, source_digests, source_kinds,
                result_digest, submitted_at_ms
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 0, NULL, NULL, NULL, 12)",
            params![
                sequence,
                migration.as_bytes(),
                destination.as_bytes(),
                workspace_id.into_uuid().as_bytes(),
                activity_id.into_uuid().as_bytes(),
                assignment.as_bytes(),
                goal.as_bytes(),
                node.as_bytes(),
                target_agent.as_bytes(),
                Option::<Vec<u8>>::None,
            ],
        )?;
        connection.execute_batch(
            "DROP TABLE effect_fact_outbox_assignment_submitted_source_ref;
             ALTER TABLE effect_fact_outbox_assignment_submitted DROP COLUMN source_refs_recorded;",
        )?;
        remove_goal_mutation_receipts_schema(&connection)?;
        for (kind, name) in crate::workspace_agent_migration::approval_authority_schema_objects() {
            connection.execute_batch(&format!("DROP {kind} {name}"))?;
        }
        connection.pragma_update(None, "user_version", PREVIOUS_SOURCE_REFS_SCHEMA_VERSION)?;
        drop(connection);

        let existing = WorkspaceStateLayout::inspect_existing(layout.workspace_root())?
            .ok_or("Workspace state layout disappeared before v47 fixture")?;
        let migrated = WorkspaceStore::open_existing(&existing)?;
        let facts = migrated.effect_fact_outbox(0, 64)?;
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].submitted_source_refs(), None);
        let marker: i64 = migrated.connection.query_row(
            "SELECT source_refs_recorded FROM effect_fact_outbox_assignment_submitted",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(marker, 0);
        let child_count: i64 = migrated.connection.query_row(
            "SELECT COUNT(*) FROM effect_fact_outbox_assignment_submitted_source_ref",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(child_count, 0);
        drop(migrated);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn previous_effect_fact_schema_migrates_additively_without_fabrication()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, layout, store, activity_id) = store_with_activity("effect-fact-v39")?;
        assert_eq!(store.health()?.schema_version(), CURRENT_SCHEMA_VERSION);
        assert!(store.effect_fact_outbox(0, 64)?.is_empty());
        drop(store);

        let base = crate::workspace_effect_fact_outbox::base_schema_objects();
        let change_set = crate::workspace_effect_fact_outbox::change_set_schema_objects();
        let work_credit = crate::workspace_effect_fact_outbox::work_credit_schema_objects();
        let offered = crate::workspace_effect_fact_outbox::assignment_offered_schema_objects();
        let submitted = crate::workspace_effect_fact_outbox::assignment_submitted_schema_objects();
        let semantic = crate::workspace_semantic_events::schema_objects();
        let admission = crate::workspace_admission_envelopes::schema_objects();

        // The v39 outbox introduction arm creates the full current outbox shape
        // (header plus all five payload tables) and the semantic event stream
        // in one additive step.
        downgrade_and_migrate(
            &layout,
            activity_id,
            &concat_objects(&[
                &base,
                &change_set,
                &work_credit,
                &offered,
                &submitted,
                &semantic,
                &admission,
            ]),
            true,
            false,
            39,
            0,
            "v39 -> current",
        )?;
        // A v40 database (effect facts without the ChangeSet payload table)
        // gains exactly the missing tables.
        downgrade_and_migrate(
            &layout,
            activity_id,
            &concat_objects(&[
                &change_set,
                &work_credit,
                &offered,
                &submitted,
                &semantic,
                &admission,
            ]),
            true,
            false,
            40,
            0,
            "v40 -> current",
        )?;
        // A v41 database (ChangeSet facts without the assignment-review
        // payload table or the WorkCredit budget column) gains exactly the
        // missing column and tables, without rewriting assignment history.
        downgrade_and_migrate(
            &layout,
            activity_id,
            &concat_objects(&[&work_credit, &offered, &submitted, &semantic, &admission]),
            true,
            true,
            41,
            0,
            "v41 -> current",
        )?;
        // A v42 database (WorkCredit facts without the assignment-offered
        // payload table) gains both post-v42 payload tables on the direct
        // path to the current schema.
        downgrade_and_migrate(
            &layout,
            activity_id,
            &concat_objects(&[&offered, &submitted, &semantic, &admission]),
            false,
            true,
            42,
            0,
            "v42 -> current",
        )?;
        let previous_facts = seed_offered_fact_for_migration(&layout, activity_id)?;
        // A v43 database (assignment-offered facts without the submitted
        // payload table) gains only the new table.
        downgrade_and_migrate(
            &layout,
            activity_id,
            &concat_objects(&[&submitted, &semantic, &admission]),
            false,
            true,
            43,
            1,
            "v43 -> current",
        )?;
        let existing = WorkspaceStateLayout::inspect_existing(layout.workspace_root())?
            .ok_or("Workspace state layout disappeared after v43 migration")?;
        let reopened = WorkspaceStore::open_existing(&existing)?;
        assert_eq!(reopened.effect_fact_outbox(0, 64)?, previous_facts);
        drop(reopened);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn previous_semantic_events_schema_migrates_additively_without_fabrication()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, layout, store, activity_id) = store_with_activity("semantic-events-v44")?;
        assert_eq!(store.health()?.schema_version(), CURRENT_SCHEMA_VERSION);
        let workspace = store.workspace()?.id();
        assert_eq!(
            store.semantic_events_page(workspace, 0, 64)?.events().len(),
            0
        );
        drop(store);

        // A v44 database predates the semantic event stream: drop exactly the
        // new objects, set the previous version, and migrate back. Workspace
        // state and delegated effect facts must be preserved without
        // fabricating events.
        let semantic = crate::workspace_semantic_events::schema_objects();
        let admission = crate::workspace_admission_envelopes::schema_objects();
        let connection = Connection::open(layout.database_path())?;
        remove_assignment_submitted_source_refs_from(&connection)?;
        drop(connection);
        downgrade_and_migrate(
            &layout,
            activity_id,
            &concat_objects(&[&semantic, &admission]),
            false,
            true,
            44,
            0,
            "v44 -> current",
        )?;
        let existing = WorkspaceStateLayout::inspect_existing(layout.workspace_root())?
            .ok_or("Workspace state layout disappeared before v44 fixture")?;
        let reopened = WorkspaceStore::open_existing(&existing)?;
        let page = reopened.semantic_events_page(workspace, 0, 64)?;
        assert_eq!(
            page.events().len(),
            0,
            "migration must not fabricate events"
        );
        assert_eq!(page.high_water(), 0);
        assert_eq!(page.retained_low(), 0);
        drop(reopened);

        // A v45 database with one seeded event loses only the dropped stream
        // objects; the migration must not reinvent the seeded row.
        seed_semantic_event_for_migration(&layout, workspace)?;
        let connection = Connection::open(layout.database_path())?;
        for (kind, name) in semantic.iter().chain(admission.iter()).rev() {
            connection.execute_batch(&format!("DROP {kind} {name}"))?;
        }
        remove_assignment_submitted_source_refs_from(&connection)?;
        remove_change_set_producer_columns_from(&connection)?;
        remove_goal_mutation_receipts_schema(&connection)?;
        for (kind, name) in crate::workspace_agent_migration::approval_authority_schema_objects() {
            connection.execute_batch(&format!("DROP {kind} {name}"))?;
        }
        connection.pragma_update(None, "user_version", 44_i64)?;
        drop(connection);
        let existing = WorkspaceStateLayout::inspect_existing(layout.workspace_root())?
            .ok_or("Workspace state layout disappeared before v44 seeded fixture")?;
        let migrated = WorkspaceStore::open_existing(&existing)?;
        assert_eq!(migrated.health()?.schema_version(), CURRENT_SCHEMA_VERSION);
        let page = migrated.semantic_events_page(workspace, 0, 64)?;
        assert_eq!(
            page.events().len(),
            0,
            "migration must not fabricate the dropped seeded event"
        );
        drop(migrated);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn goal_transition_appends_monotonic_semantic_events_atomically()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, layout, mut store, activity_id) = store_with_activity("semantic-events-flow")?;
        let workspace = store.workspace()?.id();
        let contract = |label: &str| -> Result<GoalContract, Box<dyn std::error::Error>> {
            Ok(GoalContract::new(
                GoalObjective::new(label.to_owned())?,
                vec![GoalStatement::new("The transition is durable".to_owned())?],
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            )?)
        };

        // A representative authoritative transition appends exactly one event
        // and advances the high-water cursor with it.
        let first = RegisteredGoal::create(
            GoalId::from_uuid(Uuid::from_u128(0x5E50)),
            workspace,
            activity_id,
            contract("Emit durable semantic events")?,
            timestamp(10)?,
        );
        let _ = workspace_goals::insert_goal(&mut store.connection, &first)?;
        let page = store.semantic_events_page(workspace, 0, 64)?;
        assert_eq!(page.events().len(), 1);
        assert_eq!(page.events()[0].sequence(), 1);
        assert_eq!(
            page.events()[0].event().kind(),
            crate::SemanticEventKind::GoalCreated
        );
        assert_eq!(
            page.events()[0].event().subjects().goal_id,
            Some(first.id())
        );
        assert_eq!(page.events()[0].event().revision(), first.revision().get());
        assert_eq!(page.high_water(), 1);
        assert_eq!(page.retained_low(), 0);

        // A second transition appends with the next monotonic sequence, and
        // the after-cursor observes only the newer event.
        let second = RegisteredGoal::create(
            GoalId::from_uuid(Uuid::from_u128(0x5E51)),
            workspace,
            activity_id,
            contract("Emit a second durable event")?,
            timestamp(11)?,
        );
        let _ = workspace_goals::insert_goal(&mut store.connection, &second)?;
        let page = store.semantic_events_page(workspace, 1, 64)?;
        assert_eq!(page.events().len(), 1);
        assert_eq!(page.events()[0].sequence(), 2);
        assert_eq!(
            page.events()[0].event().subjects().goal_id,
            Some(second.id())
        );
        assert_eq!(page.high_water(), 2);
        assert!(matches!(
            store.semantic_events_page(workspace, 0, 0),
            Err(WorkspaceStoreError::SemanticEvents(
                crate::SemanticEventError::InvalidLimit { limit: 0 }
            ))
        ));
        let foreign = WorkspaceId::from_uuid(Uuid::from_u128(0x5E5F));
        assert!(matches!(
            store.semantic_events_page(foreign, 0, 64),
            Err(WorkspaceStoreError::SemanticEventsWorkspaceMismatch {
                expected,
                actual,
            }) if expected == workspace && actual == foreign
        ));

        // Atomicity: when the event append fails after the authoritative row
        // write, the whole caller transaction rolls back with it. Remove the
        // event-stream cursor while the bound store stays open, exactly like
        // the effect-fact rollback fixtures.
        let raw = Connection::open(layout.database_path())?;
        raw.execute_batch("DROP TABLE semantic_events_meta")?;
        drop(raw);
        let third = RegisteredGoal::create(
            GoalId::from_uuid(Uuid::from_u128(0x5E52)),
            workspace,
            activity_id,
            contract("Must never partially commit")?,
            timestamp(12)?,
        );
        assert!(
            workspace_goals::insert_goal(&mut store.connection, &third).is_err(),
            "a missing event-stream cursor must fail the transition closed"
        );
        let persisted = crate::workspace_goals::get_goal(&store.connection, third.id())?;
        assert!(persisted.is_none(), "rollback must remove the Goal row");
        let event_count: i64 =
            store
                .connection
                .query_row("SELECT COUNT(*) FROM semantic_events", [], |row| row.get(0))?;
        assert_eq!(event_count, 2, "rollback must not leave a partial event");
        drop(store);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    /// Seed one semantic event row plus its high-water meta row exactly as a
    /// v45 writer would, through the raw connection, for migration fixtures.
    fn seed_semantic_event_for_migration(
        layout: &WorkspaceStateLayout,
        workspace_id: WorkspaceId,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let existing = WorkspaceStateLayout::inspect_existing(layout.workspace_root())?
            .ok_or("Workspace state layout disappeared before semantic event seed")?;
        let seeded = WorkspaceStore::open_existing(&existing)?;
        seeded.connection.execute(
            "INSERT INTO semantic_events(
                sequence, workspace_id, event_kind, subject_goal_id, subject_dag_revision,
                subject_node_id, subject_execution_id, subject_change_set_id, subject_diff_id,
                subject_verification, revision, payload_digest, observed_at_ms
             ) VALUES (?1, ?2, ?3, ?4, NULL, NULL, NULL, NULL, NULL, NULL, ?5, ?6, ?7)",
            params![
                1_i64,
                workspace_id.into_uuid().as_bytes(),
                "goal_created",
                workspace_id.into_uuid().as_bytes(),
                1_i64,
                [7_u8; 32],
                8_i64,
            ],
        )?;
        seeded.connection.execute(
            "INSERT INTO semantic_events_meta(workspace_id, high_water_seq, retained_low)
             VALUES (?1, 1, 0)",
            params![workspace_id.into_uuid().as_bytes()],
        )?;
        Ok(())
    }

    fn seed_offered_fact_for_migration(
        layout: &WorkspaceStateLayout,
        activity_id: ActivityId,
    ) -> Result<Vec<crate::EffectFactOutboxEntry>, Box<dyn std::error::Error>> {
        let existing = WorkspaceStateLayout::inspect_existing(layout.workspace_root())?
            .ok_or("Workspace state layout disappeared before v43 fixture")?;
        let seeded = WorkspaceStore::open_existing(&existing)?;
        let workspace_uuid = seeded.workspace()?.id().into_uuid();
        let activity_uuid = activity_id.into_uuid();
        let migration_uuid = Uuid::from_u128(0xD440);
        let destination_uuid = Uuid::from_u128(0xD441);
        let assignment_uuid = Uuid::from_u128(0xD442);
        let goal_uuid = Uuid::from_u128(0xD443);
        let node_uuid = Uuid::from_u128(0xD444);
        let target_agent_uuid = Uuid::from_u128(0xD445);
        seeded.connection.execute(
            "INSERT INTO effect_fact_outbox_entries(
                migration_id, destination_id, workspace_id, fact_kind
             ) VALUES (?1, ?2, ?3, ?4)",
            params![
                migration_uuid.as_bytes(),
                destination_uuid.as_bytes(),
                workspace_uuid.as_bytes(),
                3_i64,
            ],
        )?;
        let sequence = seeded.connection.last_insert_rowid();
        seeded.connection.execute(
            "INSERT INTO effect_fact_outbox_assignment_offered(
                outbox_sequence, migration_id, destination_id, workspace_id,
                activity_id, assignment_id, goal_id, node_id, target_agent_id,
                target_session_id, credit_budget, offered_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                sequence,
                migration_uuid.as_bytes(),
                destination_uuid.as_bytes(),
                workspace_uuid.as_bytes(),
                activity_uuid.as_bytes(),
                assignment_uuid.as_bytes(),
                goal_uuid.as_bytes(),
                node_uuid.as_bytes(),
                target_agent_uuid.as_bytes(),
                Option::<Vec<u8>>::None,
                1_i64,
                8_i64,
            ],
        )?;
        Ok(seeded.effect_fact_outbox(0, 64)?)
    }

    #[test]
    fn assignment_submitted_schema_rejects_damaged_previous_and_current_shapes()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, layout, store, _) = store_with_activity("submitted-shape-current")?;
        drop(store);
        let (_, submitted_table) =
            crate::workspace_effect_fact_outbox::assignment_submitted_schema_objects()[0];
        let connection = Connection::open(layout.database_path())?;
        connection.execute_batch(&format!("DROP TABLE {submitted_table}"))?;
        drop(connection);
        let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
        assert!(matches!(
            WorkspaceStore::open_existing(&existing),
            Err(WorkspaceStoreError::DamagedSchema { .. })
        ));
        fs::remove_dir_all(root)?;

        let (root, layout, store, _) = store_with_activity("submitted-shape-previous")?;
        drop(store);
        let (_, offered_table) =
            crate::workspace_effect_fact_outbox::assignment_offered_schema_objects()[0];
        let (_, submitted_table) =
            crate::workspace_effect_fact_outbox::assignment_submitted_schema_objects()[0];
        let connection = Connection::open(layout.database_path())?;
        connection.execute_batch(&format!(
            "DROP TABLE {submitted_table}; DROP TABLE {offered_table}"
        ))?;
        connection.pragma_update(
            None,
            "user_version",
            PREVIOUS_ASSIGNMENT_SUBMITTED_SCHEMA_VERSION,
        )?;
        drop(connection);
        let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
        assert!(matches!(
            WorkspaceStore::open_existing(&existing),
            Err(WorkspaceStoreError::DamagedSchema { .. })
        ));
        let connection = Connection::open(layout.database_path())?;
        let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
        assert_eq!(version, PREVIOUS_ASSIGNMENT_SUBMITTED_SCHEMA_VERSION);
        let submitted_exists: i64 = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1)",
            params![submitted_table],
            |row| row.get(0),
        )?;
        assert_eq!(submitted_exists, 0);
        drop(connection);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    /// Degrade the current database to `version` by removing exactly the
    /// outbox objects that version predates, then migrate it back and prove
    /// the additive step preserved state without fabricating facts.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn downgrade_and_migrate(
        layout: &WorkspaceStateLayout,
        activity_id: ActivityId,
        objects: &[(&'static str, &'static str)],
        remove_credit_column: bool,
        remove_change_set_producer_columns: bool,
        version: i64,
        expected_effect_facts: usize,
        label: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let connection = Connection::open(layout.database_path())?;
        connection.pragma_update(None, "foreign_keys", true)?;
        remove_goal_mutation_receipts_schema(&connection)?;
        // Every downgraded target here predates schema 50, so the
        // approval-authority freeze fences must not remain either.
        for (kind, name) in crate::workspace_agent_migration::approval_authority_schema_objects() {
            connection.execute_batch(&format!("DROP {kind} {name}"))?;
        }
        for (kind, name) in objects.iter().rev() {
            connection.execute_batch(&format!("DROP {kind} {name}"))?;
        }
        if remove_credit_column {
            remove_work_credit_column(&connection)?;
        }
        if remove_change_set_producer_columns {
            remove_change_set_producer_columns_from(&connection)?;
        }
        connection.pragma_update(None, "user_version", version)?;
        drop(connection);

        let existing = WorkspaceStateLayout::inspect_existing(layout.workspace_root())?
            .ok_or_else(|| format!("Workspace state layout disappeared before {label}"))?;
        let migrated = WorkspaceStore::open_existing(&existing)?;
        assert_eq!(migrated.health()?.schema_version(), CURRENT_SCHEMA_VERSION);
        assert_eq!(
            migrated
                .get_activity(activity_id)?
                .map(|activity| activity.id()),
            Some(activity_id),
            "{label} must preserve pre-existing Workspace state"
        );
        assert_eq!(
            migrated.effect_fact_outbox(0, 64)?.len(),
            expected_effect_facts,
            "{label} must preserve source facts without fabrication"
        );
        let submitted_count: i64 = migrated.connection.query_row(
            "SELECT COUNT(*) FROM effect_fact_outbox_assignment_submitted",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(
            submitted_count, 0,
            "{label} must not fabricate submitted facts"
        );
        drop(migrated);
        Ok(())
    }

    fn concat_objects(
        parts: &[&[(&'static str, &'static str)]],
    ) -> Vec<(&'static str, &'static str)> {
        parts.iter().flat_map(|part| part.iter().copied()).collect()
    }

    fn install_delegation_seal(
        store: &mut WorkspaceStore,
        seed: u128,
        at: i64,
    ) -> Result<crate::AgentOperationsDelegation, Box<dyn std::error::Error>> {
        let freeze = store.freeze_agent_operations(&crate::AgentOperationsFreezeRequest::new(
            Uuid::from_u128(seed),
            Uuid::from_u128(seed + 1),
            timestamp(at)?,
        )?)?;
        Ok(store.delegate_agent_operations(&freeze, [0x5C; 32], timestamp(at + 1)?)?)
    }

    struct FileFactFixture {
        root: PathBuf,
        layout: WorkspaceStateLayout,
        store: WorkspaceStore,
        activity: RegisteredActivity,
        owner: RuntimeInstanceId,
    }

    struct DelegatedFileFactFixture {
        fixture: FileFactFixture,
        delegation: crate::AgentOperationsDelegation,
    }

    fn delegated_file_fixture(
        label: &str,
        seed: u128,
    ) -> Result<DelegatedFileFactFixture, Box<dyn std::error::Error>> {
        let mut fixture = file_fact_fixture(label, seed)?;
        let delegation = install_delegation_seal(&mut fixture.store, seed + 0x10, 20)?;
        Ok(DelegatedFileFactFixture {
            fixture,
            delegation,
        })
    }

    fn file_fact_fixture(
        label: &str,
        seed: u128,
    ) -> Result<FileFactFixture, Box<dyn std::error::Error>> {
        let root = unique_root(label)?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_command = command(&layout, workspace_id(seed), location_id(seed + 1), 1)?;
        let mut store = WorkspaceStore::open(&layout, &workspace_command)?;
        let owner = runtime_id(seed + 2);
        let activity = store.bootstrap_activity(&BootstrapActivity::new(
            activity_id(seed + 3),
            workspace_command.id(),
            WorkspaceRevision::INITIAL,
            owner,
            timestamp(1_000)?,
            timestamp(10)?,
        ))?;
        Ok(FileFactFixture {
            root,
            layout,
            store,
            activity,
            owner,
        })
    }

    struct SeededFileMutation {
        identity: FileMutationIdentity,
    }

    struct FileMutationSeed {
        identity: FileMutationIdentity,
        path: &'static str,
        kind: FileMutationKind,
        precondition: FilePrecondition,
        intended_hash: Option<FileContentHash>,
        pre_state: FilePathState,
        goal_seed: u128,
        authority_seed: u128,
        observed_at: i64,
    }

    fn seed_and_begin_file_mutation(
        store: &mut WorkspaceStore,
        workspace: WorkspaceId,
        activity: &RegisteredActivity,
        owner: RuntimeInstanceId,
        seed: &FileMutationSeed,
    ) -> Result<SeededFileMutation, Box<dyn std::error::Error>> {
        let begin = BeginFileMutation::new(
            seed.identity,
            FileMutationScope::new(
                workspace,
                WorkspaceRevision::INITIAL,
                activity.id(),
                owner,
                activity.lease_revision(),
            ),
            FileMutationPlan::new(
                WorkspaceRelativePath::new(PathBuf::from(seed.path))?,
                seed.kind,
                seed.precondition,
            ),
            seed.intended_hash,
            seed.pre_state,
            timestamp(seed.observed_at)?,
        )?;
        let diff_begin = summary_diff_intent(&begin)?;
        let goal = insert_file_test_goal_seeded(store, workspace, activity.id(), seed.goal_seed)?;
        let authority = seed_test_source_write_authority(
            store,
            workspace,
            activity,
            goal,
            begin.path(),
            seed.authority_seed,
        )?;
        assert_eq!(
            store
                .begin_file_mutation(&begin, &diff_begin, authority)?
                .status(),
            BeginFileMutationStatus::Started
        );
        Ok(SeededFileMutation {
            identity: seed.identity,
        })
    }

    struct TreeIntentFixture {
        draft: TreeChangeSetDraft,
        intent: TreeChangeSetIntent,
        diff_begin: BeginDiffEvidence,
        completion: CompleteDiffEvidence,
        path: WorkspaceRelativePath,
    }

    fn tree_update_intent_fixture(
        workspace: WorkspaceId,
        activity_id: ActivityId,
        owner: RuntimeInstanceId,
        lease_revision: ActivityLeaseRevision,
        change_set_id: ChangeSetId,
        mutation_id: TreeMutationId,
    ) -> Result<TreeIntentFixture, Box<dyn std::error::Error>> {
        let path = WorkspaceRelativePath::new(PathBuf::from("src/tree.rs"))?;
        let diff_id = DiffId::for_change_set(change_set_id);
        let expected_hash = FileContentHash::from_bytes([8; FileContentHash::BYTE_LEN]);
        let intended_hash = FileContentHash::from_bytes([9; FileContentHash::BYTE_LEN]);
        let attribution = ChangeSetAttribution::new(
            change_set_id,
            workspace,
            WorkspaceRevision::INITIAL,
            activity_id,
            owner,
            lease_revision,
        );
        let draft = TreeChangeSetDraft::new(&[TreeMutationDraft::new(
            mutation_id,
            TreeMutationPlan::UpdateFile {
                path: path.clone(),
                expected_hash,
                intended_hash,
            },
        )])?;
        let intent = TreeChangeSetIntent::from_draft(attribution, &draft, timestamp(30)?)?;
        let compressed_hash = DiffPayloadHash::from_bytes([11; 32]);
        let uncompressed_hash = DiffPayloadHash::from_bytes([12; 32]);
        let final_relative_path =
            DiffArtifactRelativePath::new(PathBuf::from(format!("diffs/diff_{diff_id}.diff.zst")))?;
        let diff_begin = BeginDiffEvidence::new(
            DiffAttribution::for_tree_change_set(diff_id, workspace, activity_id, change_set_id),
            intent.diff_entries().to_vec(),
            DiffPayloadProjection::IntentText {
                pending_relative_path: DiffArtifactRelativePath::new(PathBuf::from(format!(
                    "diffs/.diff-{diff_id}.pending"
                )))?,
                final_relative_path: final_relative_path.clone(),
                compressed_hash,
                uncompressed_hash,
                compressed_size: DiffByteCount::new(20),
                uncompressed_size: DiffByteCount::new(40),
            },
            timestamp(30)?,
            DiffContractVersions::V2,
        )?;
        let completion = CompleteDiffEvidence::new(
            diff_id,
            DiffRevision::INITIAL,
            DiffPayloadProjection::Ready {
                relative_path: final_relative_path,
                compressed_hash,
                uncompressed_hash,
                compressed_size: DiffByteCount::new(20),
                uncompressed_size: DiffByteCount::new(40),
            },
            timestamp(31)?,
        )?;
        Ok(TreeIntentFixture {
            draft,
            intent,
            diff_begin,
            completion,
            path,
        })
    }

    fn fabricated_terminal_change_set(
        change_set_id: ChangeSetId,
        workspace: WorkspaceId,
        activity: ActivityId,
        owner: RuntimeInstanceId,
        lease_revision: ActivityLeaseRevision,
        observed_at: i64,
    ) -> Result<RegisteredChangeSet, Box<dyn std::error::Error>> {
        Ok(RegisteredChangeSet::from_parts(
            ChangeSetAttribution::new(
                change_set_id,
                workspace,
                WorkspaceRevision::INITIAL,
                activity,
                owner,
                lease_revision,
            ),
            ChangeSetState::Applied,
            ChangeSetTimestamps::new(timestamp(observed_at)?, timestamp(observed_at + 1)?),
            ChangeSetRevision::INITIAL,
            None,
        ))
    }

    fn fabricated_terminal_diff(
        diff_id: DiffId,
        workspace: WorkspaceId,
        activity: ActivityId,
        change_set_id: ChangeSetId,
        revision: i64,
    ) -> Result<RegisteredDiffEvidence, Box<dyn std::error::Error>> {
        Ok(RegisteredDiffEvidence::from_parts(
            DiffAttribution::for_file_mutation(
                diff_id,
                workspace,
                activity,
                change_set_id,
                FileMutationId::from_uuid(Uuid::from_u128(0xF121)),
            ),
            vec![DiffEntrySummary::new(
                DiffEntrySubject::File,
                WorkspaceRelativePath::new(PathBuf::from("src/lib.rs"))?,
                None,
                DiffChangeKind::Created,
                DiffLineCount::new(1),
                DiffLineCount::new(0),
            )?],
            DiffPayloadProjection::SummaryOnly {
                render_kind: DiffRenderKind::Binary,
            },
            DiffEvidenceTimestamps::new(timestamp(30)?, timestamp(31)?),
            DiffContractVersions::V1,
            DiffRevision::new(revision)?,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn assert_replayed_change_set_fact(
        fact: &crate::ChangeSetTerminalEffectFact,
        change_set_id: ChangeSetId,
        workspace: WorkspaceId,
        activity_id: ActivityId,
        owner: RuntimeInstanceId,
        lease_revision: ActivityLeaseRevision,
        diff_id: DiffId,
        producer_agent: AgentInstanceId,
        producer_session: AgentSessionId,
    ) -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(fact.change_set_id(), change_set_id);
        assert_eq!(fact.workspace_id(), workspace);
        assert_eq!(fact.workspace_revision(), WorkspaceRevision::INITIAL);
        assert_eq!(fact.activity_id(), activity_id);
        assert_eq!(fact.runtime_instance_id(), owner);
        assert_eq!(fact.activity_lease_revision(), lease_revision);
        assert_eq!(fact.change_set_revision(), ChangeSetRevision::INITIAL);
        assert_eq!(fact.state(), ChangeSetState::Applied);
        assert_eq!(fact.failure_code(), None);
        assert_eq!(fact.diff_id(), diff_id);
        assert_eq!(fact.diff_state(), DiffEvidenceState::SummaryOnly);
        assert_eq!(fact.diff_revision(), DiffRevision::new(2)?);
        assert_eq!(fact.observed_at(), timestamp(31)?);
        assert_eq!(
            fact.producer_agent_id(),
            Some(producer_agent),
            "the kind-1 fact must carry the Writer Lease holder as producer"
        );
        assert_eq!(fact.producer_session_id(), Some(producer_session));
        Ok(())
    }

    fn assert_change_set_facts_are_workspace_scoped() -> Result<(), Box<dyn std::error::Error>> {
        // Facts stay inside their Workspace scope: another bound Workspace
        // observes none of them.
        let other_root = unique_root("changeset-fact-other-workspace")?;
        let other_layout = WorkspaceStateLayout::initialize(&other_root)?;
        let other_command = command(&other_layout, workspace_id(0xF3F0), location_id(0xF3F1), 1)?;
        let other_store = WorkspaceStore::open(&other_layout, &other_command)?;
        assert!(other_store.effect_fact_outbox(0, 64)?.is_empty());
        drop(other_store);
        fs::remove_dir_all(other_root)?;
        Ok(())
    }

    fn assert_terminal_change_set_fact(
        entry: &crate::EffectFactOutboxEntry,
        change_set_id: ChangeSetId,
        state: ChangeSetState,
        failure_code: Option<FileMutationFailureCode>,
        diff_state: DiffEvidenceState,
        observed_at: i64,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match entry.fact() {
            crate::EffectFact::ChangeSetTerminal(fact) => {
                assert_eq!(fact.change_set_id(), change_set_id);
                assert_eq!(fact.state(), state);
                assert_eq!(fact.failure_code(), failure_code);
                assert_eq!(fact.diff_state(), diff_state);
                assert_eq!(fact.change_set_revision(), ChangeSetRevision::new(2)?);
                assert_eq!(fact.diff_revision(), DiffRevision::new(2)?);
                assert_eq!(fact.observed_at(), timestamp(observed_at)?);
            }
            crate::EffectFact::ExecutionTerminal(_) => {
                unreachable!("unexpected execution fact")
            }
            crate::EffectFact::AssignmentReviewed(_) => {
                unreachable!("file work must not produce an assignment-review fact")
            }
            crate::EffectFact::AssignmentOffered(_) => {
                unreachable!("file work must not produce an assignment-offer fact")
            }
            crate::EffectFact::AssignmentSubmitted(_) => {
                unreachable!("file work must not produce an assignment-submission fact")
            }
        }
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn change_set_effect_fact_exact_replay_is_idempotent_and_conflicts_on_change()
    -> Result<(), Box<dyn std::error::Error>> {
        let delegated = delegated_file_fixture("changeset-fact-replay", 0xF100)?;
        let FileFactFixture {
            root,
            layout,
            store,
            activity,
            owner,
        } = delegated.fixture;
        let delegation = delegated.delegation;
        let workspace = workspace_id(0xF100);
        let change_set_id = ChangeSetId::from_uuid(Uuid::from_u128(0xF120));
        let diff_id = DiffId::for_change_set(change_set_id);
        let terminal = fabricated_terminal_change_set(
            change_set_id,
            workspace,
            activity.id(),
            owner,
            activity.lease_revision(),
            30,
        )?;
        let diff = fabricated_terminal_diff(diff_id, workspace, activity.id(), change_set_id, 2)?;

        let mut fact_connection = Connection::open(layout.database_path())?;
        fact_connection.pragma_update(None, "foreign_keys", true)?;
        let fact_transaction =
            fact_connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let producer = forge_domain::ChangeSetProducer::new(
            AgentInstanceId::from_uuid(Uuid::from_u128(0xF126)),
            AgentSessionId::from_uuid(Uuid::from_u128(0xF127)),
        );
        crate::workspace_effect_fact_outbox::append_change_set_terminal(
            &fact_transaction,
            &terminal,
            &diff,
            producer,
        )?;
        crate::workspace_effect_fact_outbox::append_change_set_terminal(
            &fact_transaction,
            &terminal,
            &diff,
            producer,
        )?;
        fact_transaction.commit()?;

        let effect_facts = store.effect_fact_outbox(0, 64)?;
        assert_eq!(
            effect_facts.len(),
            1,
            "exact replay must not duplicate facts"
        );
        let effect_entry = &effect_facts[0];
        assert_eq!(effect_entry.migration_id(), delegation.migration_id());
        assert_eq!(effect_entry.destination_id(), delegation.destination_id());
        assert_eq!(effect_entry.workspace_id(), workspace);
        match effect_entry.fact() {
            crate::EffectFact::ChangeSetTerminal(fact) => assert_replayed_change_set_fact(
                fact,
                change_set_id,
                workspace,
                activity.id(),
                owner,
                activity.lease_revision(),
                diff_id,
                AgentInstanceId::from_uuid(Uuid::from_u128(0xF126)),
                AgentSessionId::from_uuid(Uuid::from_u128(0xF127)),
            )?,
            crate::EffectFact::ExecutionTerminal(_) => {
                unreachable!("ChangeSet work must not produce an execution fact")
            }
            crate::EffectFact::AssignmentReviewed(_) => {
                unreachable!("file work must not produce an assignment-review fact")
            }
            crate::EffectFact::AssignmentOffered(_) => {
                unreachable!("file work must not produce an assignment-offer fact")
            }
            crate::EffectFact::AssignmentSubmitted(_) => {
                unreachable!("file work must not produce an assignment-submission fact")
            }
        }
        assert!(
            store
                .effect_fact_outbox(effect_entry.sequence(), 64)?
                .is_empty(),
            "the source cursor must advance strictly after the observed fact"
        );

        let changed_diff =
            fabricated_terminal_diff(diff_id, workspace, activity.id(), change_set_id, 3)?;
        let conflict_transaction =
            fact_connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert!(matches!(
            crate::workspace_effect_fact_outbox::append_change_set_terminal(
                &conflict_transaction,
                &terminal,
                &changed_diff,
                producer,
            ),
            Err(crate::EffectFactOutboxError::ReplayConflict)
        ));
        drop(conflict_transaction);
        drop(fact_connection);
        assert_eq!(
            store.effect_fact_outbox(0, 64)?.len(),
            1,
            "conflicting replay must not add a fact"
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn change_set_producer_columns_migrate_additively_and_stay_exact()
    -> Result<(), Box<dyn std::error::Error>> {
        let FileFactFixture {
            root,
            layout,
            mut store,
            activity,
            owner,
        } = file_fact_fixture("changeset-producer-migration", 0xF500)?;
        let workspace = workspace_id(0xF500);
        let producer = ChangeSetProducer::new(
            AgentInstanceId::from_uuid(Uuid::from_u128(0xF520)),
            AgentSessionId::from_uuid(Uuid::from_u128(0xF522)),
        );
        // Seed and begin before the delegation seal freezes the writer tables;
        // the terminal fact append itself requires the sealed delegation.
        let applied = seed_and_begin_file_mutation(
            &mut store,
            workspace,
            &activity,
            owner,
            &FileMutationSeed {
                identity: FileMutationIdentity::new(
                    ChangeSetId::from_uuid(Uuid::from_u128(0xF504)),
                    FileMutationId::from_uuid(Uuid::from_u128(0xF505)),
                ),
                path: "src/lib.rs",
                kind: FileMutationKind::Create,
                precondition: FilePrecondition::Absent,
                intended_hash: Some(FileContentHash::from_bytes([7; FileContentHash::BYTE_LEN])),
                pre_state: FilePathState::Absent,
                goal_seed: 0xF506,
                authority_seed: 0xF520,
                observed_at: 20,
            },
        )?;
        let delegation = install_delegation_seal(&mut store, 0xF510, 20)?;
        let (file_completion, diff_completion) = summary_completion(
            applied.identity,
            FileContentHash::from_bytes([7; FileContentHash::BYTE_LEN]),
            21,
        )?;
        let record = store.complete_file_mutation(&file_completion, &diff_completion, producer)?;
        assert_eq!(record.change_set().state(), ChangeSetState::Applied);
        assert_eq!(
            store.effect_fact_outbox(0, 64)?[0].migration_id(),
            delegation.migration_id()
        );
        assert_eq!(store.effect_fact_outbox(0, 64)?.len(), 1);
        drop(store);

        // Downgrade in place: drop the producer columns and claim v46. The
        // durable fact row survives with a NULL producer.
        let raw = Connection::open(layout.database_path())?;
        raw.pragma_update(None, "foreign_keys", true)?;
        raw.execute_batch(
            "ALTER TABLE effect_fact_outbox_change_set DROP COLUMN producer_agent_id;
             ALTER TABLE effect_fact_outbox_change_set DROP COLUMN producer_session_id;",
        )?;
        remove_assignment_submitted_source_refs_from(&raw)?;
        remove_goal_mutation_receipts_schema(&raw)?;
        for (kind, name) in crate::workspace_agent_migration::approval_authority_schema_objects() {
            raw.execute_batch(&format!("DROP {kind} {name}"))?;
        }
        raw.pragma_update(None, "user_version", 46_i64)?;
        drop(raw);

        let existing = WorkspaceStateLayout::inspect_existing(layout.workspace_root())?
            .ok_or("Workspace state layout disappeared before v46 fixture")?;
        let migrated = WorkspaceStore::open_existing(&existing)?;
        assert_eq!(migrated.health()?.schema_version(), CURRENT_SCHEMA_VERSION);
        let facts = migrated.effect_fact_outbox(0, 64)?;
        assert_eq!(
            facts.len(),
            1,
            "the v46 -> v47 migration must preserve durable facts"
        );
        match facts[0].fact() {
            crate::EffectFact::ChangeSetTerminal(fact) => {
                assert_eq!(
                    fact.producer_agent_id(),
                    None,
                    "legacy pre-attribution rows decode without a producer"
                );
                assert_eq!(fact.producer_session_id(), None);
            }
            _ => unreachable!("unexpected fact kind"),
        }

        // A legacy row can never be re-admitted under the attribution
        // contract: the retry conflicts instead of fabricating a producer.
        let terminal = fabricated_terminal_change_set(
            ChangeSetId::from_uuid(Uuid::from_u128(0xF504)),
            workspace,
            activity.id(),
            owner,
            activity.lease_revision(),
            30,
        )?;
        let diff = fabricated_terminal_diff(
            DiffId::for_change_set(ChangeSetId::from_uuid(Uuid::from_u128(0xF504))),
            workspace,
            activity.id(),
            ChangeSetId::from_uuid(Uuid::from_u128(0xF504)),
            2,
        )?;
        let mut raw = Connection::open(layout.database_path())?;
        raw.pragma_update(None, "foreign_keys", true)?;
        let transaction = raw.transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert!(matches!(
            crate::workspace_effect_fact_outbox::append_change_set_terminal(
                &transaction,
                &terminal,
                &diff,
                producer,
            ),
            Err(crate::EffectFactOutboxError::ReplayConflict)
        ));
        drop(transaction);
        drop(raw);
        assert_eq!(
            migrated.effect_fact_outbox(0, 64)?.len(),
            1,
            "legacy replay conflict must not add a fact"
        );
        drop(migrated);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn change_set_fact_append_failure_rolls_back_file_terminalization()
    -> Result<(), Box<dyn std::error::Error>> {
        let FileFactFixture {
            root,
            layout,
            mut store,
            activity,
            owner,
        } = file_fact_fixture("changeset-fact-rollback", 0xF200)?;
        let post_hash = FileContentHash::from_bytes([7; FileContentHash::BYTE_LEN]);
        let seeded = seed_and_begin_file_mutation(
            &mut store,
            workspace_id(0xF200),
            &activity,
            owner,
            &FileMutationSeed {
                identity: FileMutationIdentity::new(
                    ChangeSetId::from_uuid(Uuid::from_u128(0xF204)),
                    FileMutationId::from_uuid(Uuid::from_u128(0xF205)),
                ),
                path: "src/lib.rs",
                kind: FileMutationKind::Create,
                precondition: FilePrecondition::Absent,
                intended_hash: Some(post_hash),
                pre_state: FilePathState::Absent,
                goal_seed: 0xF206,
                authority_seed: 0xF220,
                observed_at: 20,
            },
        )?;

        // Remove the delegation authority the fact protocol depends on while the
        // database still claims a current schema. Terminalization must fail
        // closed and roll back the ChangeSet/Diff terminal state with it.
        let raw = Connection::open(layout.database_path())?;
        raw.execute_batch("DROP TABLE agent_operations_delegations")?;
        drop(raw);
        let (file_completion, diff_completion) =
            summary_completion(seeded.identity, post_hash, 21)?;
        let Err(error) = store.complete_file_mutation(
            &file_completion,
            &diff_completion,
            ChangeSetProducer::new(
                AgentInstanceId::from_uuid(Uuid::from_u128(0xF220)),
                AgentSessionId::from_uuid(Uuid::from_u128(0xF222)),
            ),
        ) else {
            return Err(std::io::Error::other(
                "missing effect-fact authority unexpectedly succeeded",
            )
            .into());
        };
        assert!(matches!(error, WorkspaceStoreError::EffectFactOutbox(_)));

        let conn = Connection::open(layout.database_path())?;
        let (state, revision): (i64, i64) = conn.query_row(
            "SELECT state, revision FROM change_sets WHERE changeset_id = ?1",
            params![
                seeded
                    .identity
                    .change_set_id()
                    .into_uuid()
                    .as_bytes()
                    .as_slice()
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        assert_eq!((state, revision), (0, 1), "ChangeSet must remain Starting");
        let diff_state: i64 = conn.query_row(
            "SELECT state FROM diff_evidence WHERE diff_id = ?1",
            params![
                DiffId::for_change_set(seeded.identity.change_set_id())
                    .into_uuid()
                    .as_bytes()
                    .as_slice()
            ],
            |row| row.get(0),
        )?;
        assert_eq!(
            diff_state, 0,
            "Diff evidence must remain a non-terminal intent"
        );
        let fact_rows: i64 = conn.query_row(
            "SELECT COUNT(*) FROM effect_fact_outbox_entries",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(fact_rows, 0, "no fact rows may survive the rollback");
        drop(conn);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn delegated_file_completion_and_failure_emit_scoped_change_set_facts()
    -> Result<(), Box<dyn std::error::Error>> {
        let FileFactFixture {
            root,
            layout: _layout,
            mut store,
            activity,
            owner,
        } = file_fact_fixture("changeset-fact-file-paths", 0xF300)?;
        let workspace = workspace_id(0xF300);
        let post_hash = FileContentHash::from_bytes([7; FileContentHash::BYTE_LEN]);
        let applied = seed_and_begin_file_mutation(
            &mut store,
            workspace,
            &activity,
            owner,
            &FileMutationSeed {
                identity: FileMutationIdentity::new(
                    ChangeSetId::from_uuid(Uuid::from_u128(0xF304)),
                    FileMutationId::from_uuid(Uuid::from_u128(0xF305)),
                ),
                path: "src/lib.rs",
                kind: FileMutationKind::Create,
                precondition: FilePrecondition::Absent,
                intended_hash: Some(post_hash),
                pre_state: FilePathState::Absent,
                goal_seed: 0xF306,
                authority_seed: 0xF320,
                observed_at: 20,
            },
        )?;
        let failed = seed_and_begin_file_mutation(
            &mut store,
            workspace,
            &activity,
            owner,
            &FileMutationSeed {
                identity: FileMutationIdentity::new(
                    ChangeSetId::from_uuid(Uuid::from_u128(0xF308)),
                    FileMutationId::from_uuid(Uuid::from_u128(0xF309)),
                ),
                path: "src/old.rs",
                kind: FileMutationKind::Delete,
                precondition: FilePrecondition::Matches(post_hash),
                intended_hash: None,
                pre_state: FilePathState::Regular {
                    hash: post_hash,
                    size: FileByteCount::new(7),
                },
                goal_seed: 0xF30A,
                authority_seed: 0xF322,
                observed_at: 23,
            },
        )?;
        let delegation = install_delegation_seal(&mut store, 0xF310, 19)?;

        let (file_completion, diff_completion) =
            summary_completion(applied.identity, post_hash, 21)?;
        let completed = store.complete_file_mutation(
            &file_completion,
            &diff_completion,
            ChangeSetProducer::new(
                AgentInstanceId::from_uuid(Uuid::from_u128(0xF320)),
                AgentSessionId::from_uuid(Uuid::from_u128(0xF322)),
            ),
        )?;
        assert_eq!(completed.change_set().state(), ChangeSetState::Applied);
        let failed_record = store.fail_file_mutation(
            &FailFileMutation::new(
                failed.identity,
                ChangeSetRevision::INITIAL,
                FileMutationRevision::INITIAL,
                FileMutationFailureCode::StaleWrite,
                timestamp(24)?,
            ),
            AbandonDiffEvidence::new(
                DiffId::for_change_set(failed.identity.change_set_id()),
                DiffRevision::INITIAL,
                timestamp(24)?,
            ),
            ChangeSetProducer::new(
                AgentInstanceId::from_uuid(Uuid::from_u128(0xF322)),
                AgentSessionId::from_uuid(Uuid::from_u128(0xF324)),
            ),
        )?;
        assert_eq!(failed_record.change_set().state(), ChangeSetState::Failed);

        let facts = store.effect_fact_outbox(0, 64)?;
        assert_eq!(facts.len(), 2, "each terminal path emits exactly one fact");
        for entry in &facts {
            assert_eq!(entry.migration_id(), delegation.migration_id());
            assert_eq!(entry.destination_id(), delegation.destination_id());
            assert_eq!(entry.workspace_id(), workspace);
        }
        assert_terminal_change_set_fact(
            &facts[0],
            applied.identity.change_set_id(),
            ChangeSetState::Applied,
            None,
            DiffEvidenceState::SummaryOnly,
            21,
        )?;
        assert_terminal_change_set_fact(
            &facts[1],
            failed.identity.change_set_id(),
            ChangeSetState::Failed,
            Some(FileMutationFailureCode::StaleWrite),
            DiffEvidenceState::Abandoned,
            24,
        )?;

        assert_change_set_facts_are_workspace_scoped()?;

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn delegated_tree_completion_emits_one_scoped_change_set_fact()
    -> Result<(), Box<dyn std::error::Error>> {
        let FileFactFixture {
            root,
            layout: _layout,
            mut store,
            activity,
            owner,
        } = file_fact_fixture("changeset-fact-tree-path", 0xF400)?;
        let workspace = workspace_id(0xF400);
        let change_set_id = ChangeSetId::from_uuid(Uuid::from_u128(0xF404));
        let tree = tree_update_intent_fixture(
            workspace,
            activity.id(),
            owner,
            activity.lease_revision(),
            change_set_id,
            TreeMutationId::from_uuid(Uuid::from_u128(0xF405)),
        )?;
        let hidden_goal =
            insert_file_test_goal_seeded(&mut store, workspace, activity.id(), 0xF406)?;
        let authority = seed_test_source_write_authority(
            &mut store,
            workspace,
            &activity,
            hidden_goal,
            &tree.path,
            0xF420,
        )?;
        let delegation = install_delegation_seal(&mut store, 0xF410, 19)?;

        let admission = store.begin_tree_change_set(&tree.intent, &tree.diff_begin, authority)?;
        assert_eq!(admission.status(), TreeChangeSetAdmissionStatus::Started);
        for id in tree.draft.mutation_ids() {
            store.mark_tree_mutation_applied(change_set_id, *id)?;
        }
        let completed = store.complete_tree_change_set(
            change_set_id,
            &tree.completion,
            timestamp(31)?,
            ChangeSetProducer::new(
                AgentInstanceId::from_uuid(Uuid::from_u128(0xF420)),
                AgentSessionId::from_uuid(Uuid::from_u128(0xF422)),
            ),
        )?;
        assert_eq!(completed.state(), ChangeSetState::Applied);

        let facts = store.effect_fact_outbox(0, 64)?;
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].migration_id(), delegation.migration_id());
        assert_eq!(facts[0].destination_id(), delegation.destination_id());
        assert_eq!(facts[0].workspace_id(), workspace);
        match facts[0].fact() {
            crate::EffectFact::ChangeSetTerminal(fact) => {
                assert_eq!(fact.change_set_id(), change_set_id);
                assert_eq!(fact.workspace_id(), workspace);
                assert_eq!(fact.activity_id(), activity.id());
                assert_eq!(fact.runtime_instance_id(), owner);
                assert_eq!(fact.change_set_revision(), ChangeSetRevision::new(2)?);
                assert_eq!(fact.state(), ChangeSetState::Applied);
                assert_eq!(fact.failure_code(), None);
                assert_eq!(fact.diff_id(), tree.completion.id());
                assert_eq!(fact.diff_state(), DiffEvidenceState::Ready);
                assert_eq!(fact.diff_revision(), DiffRevision::new(2)?);
                assert_eq!(fact.observed_at(), timestamp(31)?);
                assert_eq!(
                    fact.producer_agent_id(),
                    Some(AgentInstanceId::from_uuid(Uuid::from_u128(0xF420))),
                    "tree completion facts carry the lease holder as producer"
                );
                assert_eq!(
                    fact.producer_session_id(),
                    Some(AgentSessionId::from_uuid(Uuid::from_u128(0xF422)))
                );
            }
            crate::EffectFact::ExecutionTerminal(_) => {
                unreachable!("unexpected execution fact")
            }
            crate::EffectFact::AssignmentReviewed(_) => {
                unreachable!("tree work must not produce an assignment-review fact")
            }
            crate::EffectFact::AssignmentOffered(_) => {
                unreachable!("tree work must not produce an assignment-offer fact")
            }
            crate::EffectFact::AssignmentSubmitted(_) => {
                unreachable!("tree work must not produce an assignment-submission fact")
            }
        }
        assert_eq!(facts.len(), 1);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn previous_workspace_schema_migrates_without_fabricating_verification()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_root("previous-verification-schema")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let expected_workspace_id = workspace_id(0xB100);
        let workspace_command = command(&layout, expected_workspace_id, location_id(0xB101), 1)?;
        let mut store = WorkspaceStore::open(&layout, &workspace_command)?;
        let activity_id = activity_id(0xB102);
        store.create_activity(&CreateActivity::new(
            activity_id,
            expected_workspace_id,
            WorkspaceRevision::INITIAL,
            timestamp(2)?,
        ))?;
        let execution_id = forge_domain::ExecutionId::from_uuid(Uuid::from_u128(0xB108));
        store.connection.execute(
            "INSERT INTO executions (
            execution_id, workspace_id, activity_id, state, mode, request_digest, cwd,
            timeout_ms, output_limit, workspace_read, workspace_write, network,
            exit_code, signal, duration_ms, stdout, stdout_total_bytes, stdout_truncated,
            stderr, stderr_total_bytes, stderr_truncated, failure_code,
            created_at_ms, updated_at_ms, revision
         ) VALUES (?1, ?2, ?3, 2, 0, ?4, NULL, 100, 1, 1, 0, 0,
            0, NULL, 1, ?5, 0, 0, ?5, 0, 0, NULL, 3, 3, 1)",
            params![
                execution_id.into_uuid().as_bytes(),
                expected_workspace_id.into_uuid().as_bytes(),
                activity_id.into_uuid().as_bytes(),
                [0xA6_u8; 32].as_slice(),
                Vec::<u8>::new(),
            ],
        )?;
        let database = layout.database_path();
        drop(store);

        let connection = Connection::open(&database)?;
        connection.pragma_update(None, "journal_mode", "DELETE")?;
        remove_work_cut_schema(&connection)?;
        remove_operations_migration_schema(&connection)?;
        connection.execute_batch(
            "DROP TABLE verification_requirement_links;
         DROP TABLE verification_runs;
         DROP TABLE verification_inputs;
         DROP TABLE activity_successors;
         DROP TABLE workspace_queue_settings;
         DROP TABLE agent_assignment_sources;
         DROP TABLE agent_assignments;
         DROP TABLE goal_deletion_cleanup_journal;
         DROP TABLE execution_output_events;",
        )?;
        connection
            .execute_batch(workspace_executions::EXPECTED_EXECUTION_OUTPUT_EVENTS_TABLE_SQL_V30)?;
        connection.pragma_update(None, "user_version", PREVIOUS_SCHEMA_VERSION)?;
        drop(connection);

        let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
        assert!(matches!(
            WorkspaceStore::inspect_existing_read_only(&existing),
            Err(WorkspaceStoreError::OutdatedSchema {
                actual: PREVIOUS_SCHEMA_VERSION,
                current: CURRENT_SCHEMA_VERSION,
            })
        ));
        let migrated = WorkspaceStore::open_existing(&existing)?;
        assert_eq!(
            migrated
                .get_execution(execution_id)?
                .map(|record| record.state()),
            Some(forge_domain::ExecutionState::Completed)
        );
        drop(migrated);

        let connection = Connection::open(&database)?;
        let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
        assert_eq!(version, CURRENT_SCHEMA_VERSION);
        let fabricated_runs: i64 =
            connection.query_row("SELECT COUNT(*) FROM verification_runs", [], |row| {
                row.get(0)
            })?;
        assert_eq!(fabricated_runs, 0);
        assert!(
            connection
                .execute(
                    "INSERT INTO execution_output_events (
                execution_id, sequence, event_kind, stream, bytes,
                first_missing, last_missing, omitted_bytes, omitted_chunks, gap_cause
             ) VALUES (?1, 3, 1, NULL, NULL, 1, 1, 4, 1, 0)",
                    params![execution_id.into_uuid().as_bytes()],
                )
                .is_err()
        );
        drop(connection);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn previous_modern_schema_migrates_activity_successors_without_fabrication()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_root("previous-modern-successor-schema")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_command = command(&layout, workspace_id(0xB300), location_id(0xB301), 1)?;
        let activity_id = activity_id(0xB302);
        let mut store = WorkspaceStore::open(&layout, &workspace_command)?;
        store.create_activity(&CreateActivity::new(
            activity_id,
            workspace_command.id(),
            WorkspaceRevision::INITIAL,
            timestamp(2)?,
        ))?;
        drop(store);

        let database = layout.database_path();
        let connection = Connection::open(&database)?;
        connection.pragma_update(None, "journal_mode", "DELETE")?;
        remove_work_cut_schema(&connection)?;
        remove_operations_migration_schema(&connection)?;
        connection.execute_batch(
            "DROP TABLE activity_successors;
             DROP TABLE workspace_queue_settings;
             DROP TABLE agent_assignment_sources;
             DROP TABLE agent_assignments;
             DROP TABLE goal_deletion_cleanup_journal;",
        )?;
        connection.pragma_update(None, "user_version", PREVIOUS_MODERN_SCHEMA_VERSION)?;
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
            Err(WorkspaceStoreError::OutdatedSchema {
                actual: PREVIOUS_MODERN_SCHEMA_VERSION,
                current: CURRENT_SCHEMA_VERSION,
            })
        ));
        let migrated = WorkspaceStore::open_existing(&existing)?;
        assert!(migrated.get_activity(activity_id)?.is_some());
        drop(migrated);

        let connection = Connection::open(&database)?;
        let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
        assert_eq!(version, CURRENT_SCHEMA_VERSION);
        let relation_count: i64 =
            connection.query_row("SELECT COUNT(*) FROM activity_successors", [], |row| {
                row.get(0)
            })?;
        assert_eq!(relation_count, 0);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn downgraded_modern_workspace_schema_is_rejected_without_mutation()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_root("modern-schema-downgrade")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_command = command(&layout, workspace_id(0xB200), location_id(0xB201), 1)?;
        drop(WorkspaceStore::open(&layout, &workspace_command)?);
        let database = layout.database_path();
        let connection = Connection::open(&database)?;
        connection.pragma_update(None, "journal_mode", "DELETE")?;
        remove_work_cut_schema(&connection)?;
        connection.pragma_update(None, "user_version", PREVIOUS_SCHEMA_VERSION)?;
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
            WorkspaceStore::open_existing(&existing),
            Err(WorkspaceStoreError::DamagedSchema { .. }
                | WorkspaceStoreError::Agent(_)
                | WorkspaceStoreError::Execution(_),)
        ));
        let connection = Connection::open(&database)?;
        let observed: i64 =
            connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
        assert_eq!(observed, PREVIOUS_SCHEMA_VERSION);
        let session_column_exists: i64 = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('agent_instances') WHERE name = 'session_id')",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(session_column_exists, 1);
        drop(connection);
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

        let resumed_owner = runtime_id(426);
        let resumed = store.bootstrap_activity(&BootstrapActivity::new(
            id,
            workspace_command.id(),
            WorkspaceRevision::INITIAL,
            resumed_owner,
            timestamp(200)?,
            timestamp(31)?,
        ))?;
        assert_eq!(resumed.state(), ActivityState::Open);
        assert_eq!(resumed.lease_owner_id(), Some(resumed_owner));
        assert_eq!(resumed.lease_until(), Some(timestamp(200)?));
        assert_eq!(resumed.lease_revision().get(), 4);

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
    fn expired_activity_with_attached_session_participant_is_retained()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_root("activity-expired-participant")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_command = command(&layout, workspace_id(426), location_id(427), 1)?;
        let mut store = WorkspaceStore::open(&layout, &workspace_command)?;
        let activity_id = activity_id(428);
        let owner = runtime_id(429);
        store.bootstrap_activity(&BootstrapActivity::new(
            activity_id,
            workspace_command.id(),
            WorkspaceRevision::INITIAL,
            owner,
            timestamp(10)?,
            timestamp(1)?,
        ))?;
        let participant = forge_domain::RegisteredAgentInstance::create_bound(
            AgentInstanceId::from_uuid(Uuid::from_u128(0x4261)),
            workspace_command.id(),
            activity_id,
            AgentSessionId::from_uuid(Uuid::from_u128(0x4262)),
            AgentDisplayName::new("Recovery participant".to_owned())?,
            AgentDeclaredRole::new("worker".to_owned())?,
            AgentTransportKind::Stdio,
            AuthenticatedPrincipal::TrustedStdio,
            timestamp(2)?,
        );
        crate::legacy_agent_seed::seed_agent(
            &store.connection,
            &participant,
            Some(forge_domain::AgentEventId::from_uuid(Uuid::from_u128(
                0x4263,
            ))),
        )?;
        assert!(
            store
                .reconcile_expired_activities(&ReconcileExpiredActivities::new(timestamp(20)?))?
                .is_empty()
        );
        let retained = store
            .get_activity(activity_id)?
            .ok_or("participant Activity missing")?;
        assert_eq!(retained.state(), ActivityState::Open);
        assert_eq!(retained.lease_owner_id(), Some(owner));
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
        let git_status = Command::new(FORGE_GIT_PROGRAM)
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
    fn open_existing_rebases_sidecars_created_after_preopen_observation()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_root("open-existing-sidecar-race")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_command = command(&layout, workspace_id(460), location_id(461), 1)?;
        drop(WorkspaceStore::open(&layout, &workspace_command)?);
        let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
        let observed_at = timestamp(2)?;
        let mut anchor = None;

        let root_fingerprint = existing.root_fingerprint()?;
        let gate = forge_workspace::WorkspaceStateSharedGate::acquire(
            existing.workspace_root(),
            root_fingerprint,
        )?;
        let reopened = WorkspaceStore::open_existing_with_timeout_and_gate(
            &existing,
            BUSY_TIMEOUT,
            Some(gate),
            || {
                let mut concurrent = WorkspaceStore::open_existing(&existing)?;
                concurrent.create_activity(&CreateActivity::new(
                    activity_id(462),
                    workspace_command.id(),
                    WorkspaceRevision::INITIAL,
                    observed_at,
                ))?;
                anchor = Some(concurrent);
                Ok(())
            },
        )?;

        assert_eq!(reopened.workspace()?.id(), workspace_command.id());
        assert!(anchor.is_some());
        drop(reopened);
        drop(anchor);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn live_read_only_identity_remains_available_during_concurrent_wal_writes()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_root("live-identity-concurrent-wal")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_command = command(&layout, workspace_id(470), location_id(471), 1)?;
        drop(WorkspaceStore::open(&layout, &workspace_command)?);
        let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
        let activity_writes = (0_u128..32)
            .map(|serial| {
                Ok((
                    activity_id(0xD100 + serial),
                    timestamp(10 + i64::try_from(serial)?)?,
                ))
            })
            .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
        let barrier = Arc::new(Barrier::new(2));
        let writer_barrier = Arc::clone(&barrier);
        let writer_layout = existing.clone();
        let writer_workspace_id = workspace_command.id();
        // The writer reports its open outcome before the rendezvous: a
        // pre-barrier failure must surface as a test error, never as an
        // unbounded barrier wait.
        let (opened_sender, opened_receiver) = std::sync::mpsc::sync_channel::<bool>(1);
        let writer_thread = thread::spawn(move || -> Result<(), WorkspaceStoreError> {
            let mut store = match WorkspaceStore::open_existing(&writer_layout) {
                Ok(store) => store,
                Err(error) => {
                    let _ignored = opened_sender.send(false);
                    return Err(error);
                }
            };
            let _ignored = opened_sender.send(true);
            writer_barrier.wait();
            for (activity_id, observed_at) in activity_writes {
                store.create_activity(&CreateActivity::new(
                    activity_id,
                    writer_workspace_id,
                    WorkspaceRevision::INITIAL,
                    observed_at,
                ))?;
            }
            Ok(())
        });

        match opened_receiver.recv() {
            Ok(true) => {}
            // The writer failed or panicked before the rendezvous; surface
            // its real outcome instead of waiting on a barrier it will
            // never reach.
            Ok(false) | Err(_) => {
                return writer_thread
                    .join()
                    .map_err(|_| "WAL writer panicked before the rendezvous")?
                    .map_err(Into::into);
            }
        }
        barrier.wait();
        for _ in 0..32 {
            let identity = WorkspaceStore::inspect_existing_identity_live_read_only(&existing)?;
            assert_eq!(identity.id(), workspace_command.id());
        }
        writer_thread.join().map_err(|_| "WAL writer panicked")??;
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
        let goal_activity = store.create_activity(&CreateActivity::new(
            activity_id(0xD015),
            workspace_command.id(),
            WorkspaceRevision::INITIAL,
            timestamp(9)?,
        ))?;
        let attribution =
            insert_file_test_goal(&mut store, workspace_command.id(), goal_activity.id())?;
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
            Err(WorkspaceStoreError::OutdatedSchema {
                actual: 9,
                current: CURRENT_SCHEMA_VERSION
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

    fn assert_file_mutation_terminal_and_retry_semantics(
        store: &mut WorkspaceStore,
        begin: &BeginFileMutation,
        diff_begin: &BeginDiffEvidence,
        attribution: GoalWorkAttribution,
        authority: SourceWriteAuthority,
        identity: FileMutationIdentity,
        post_hash: FileContentHash,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let producer = ChangeSetProducer::new(authority.agent_id(), authority.session_id());
        let (file_completion, diff_completion) = summary_completion(identity, post_hash, 21)?;
        let completed =
            store.complete_file_mutation(&file_completion, &diff_completion, producer)?;
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
                .begin_file_mutation_for_goal(begin, diff_begin, Some(attribution), authority)?
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
            store.complete_file_mutation(&file_completion, &diff_completion, producer),
            Err(WorkspaceStoreError::Diff(DiffStoreError::Terminal))
        ));
        Ok(())
    }

    #[test]
    fn file_mutation_intent_is_activity_attributed_idempotent_and_cas_terminal()
    -> Result<(), Box<dyn std::error::Error>> {
        file_mutation_lifecycle(false)
    }

    #[test]
    fn admitted_file_mutation_keeps_evidence_through_agent_operations_freeze()
    -> Result<(), Box<dyn std::error::Error>> {
        file_mutation_lifecycle(true)
    }

    // Keep the complete admitted-effect and terminal-evidence scenario together.
    #[allow(clippy::too_many_lines)]
    fn file_mutation_lifecycle(freeze_operations: bool) -> Result<(), Box<dyn std::error::Error>> {
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
        let attribution = insert_file_test_goal(&mut store, workspace_command.id(), activity.id())?;
        let authority = seed_test_source_write_authority(
            &mut store,
            workspace_command.id(),
            &activity,
            attribution,
            begin.path(),
            0xB120,
        )?;

        let started = store.begin_file_mutation_for_goal(
            &begin,
            &diff_begin,
            Some(attribution),
            authority,
        )?;
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
            store.begin_file_mutation(&begin, &diff_begin, authority),
            Err(WorkspaceStoreError::Goal(
                crate::GoalStoreError::EvidenceConflict
            ))
        ));
        let retry = store.begin_file_mutation_for_goal(
            &begin,
            &diff_begin,
            Some(attribution),
            authority,
        )?;
        assert_eq!(retry.status(), BeginFileMutationStatus::RecoveryRequired);

        let freeze_request = crate::AgentOperationsFreezeRequest::new(
            Uuid::from_u128(0xFA010),
            Uuid::from_u128(0xFA011),
            timestamp(20)?,
        )?;
        if freeze_operations {
            let _ = store.freeze_agent_operations(&freeze_request)?;
        }

        assert_file_mutation_terminal_and_retry_semantics(
            &mut store,
            &begin,
            &diff_begin,
            attribution,
            authority,
            identity,
            post_hash,
        )?;

        if freeze_operations {
            let _ = store.release_agent_operations_freeze(
                Uuid::from_u128(0xFA010),
                1,
                timestamp(22)?,
            )?;
        }

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

    fn admit_node_file_mutation(
        store: &mut WorkspaceStore,
        workspace_id: WorkspaceId,
        activity: &RegisteredActivity,
        owner: RuntimeInstanceId,
        attribution: GoalWorkAttribution,
        seed: u128,
        observed_at: i64,
    ) -> Result<
        (BeginFileMutation, BeginDiffEvidence, SourceWriteAuthority),
        Box<dyn std::error::Error>,
    > {
        let identity = FileMutationIdentity::new(
            ChangeSetId::from_uuid(Uuid::from_u128(seed)),
            FileMutationId::from_uuid(Uuid::from_u128(seed + 1)),
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
                WorkspaceRelativePath::new(PathBuf::from(format!("node-{seed}.txt")))?,
                FileMutationKind::Create,
                FilePrecondition::Absent,
            ),
            Some(FileContentHash::from_bytes(
                [u8::try_from(seed & 0xff)?; 32],
            )),
            FilePathState::Absent,
            timestamp(observed_at)?,
        )?;
        let diff = summary_diff_intent(&begin)?;
        let authority = seed_test_source_write_authority(
            store,
            workspace_id,
            activity,
            attribution,
            begin.path(),
            seed + 0x100,
        )?;
        let admitted =
            store.begin_file_mutation_for_goal(&begin, &diff, Some(attribution), authority)?;
        assert_eq!(admitted.status(), BeginFileMutationStatus::Started);
        assert_eq!(
            admitted.record().change_set().state(),
            ChangeSetState::Starting
        );
        Ok((begin, diff, authority))
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn dag_node_evidence_read_is_exact_bounded_and_replay_idempotent()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_root("dag-node-evidence-read")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_command = command(&layout, workspace_id(0xE000), location_id(0xE001), 1)?;
        let mut store = WorkspaceStore::open(&layout, &workspace_command)?;
        let owner = runtime_id(0xE002);
        let activity = store.bootstrap_activity(&BootstrapActivity::new(
            activity_id(0xE003),
            workspace_command.id(),
            WorkspaceRevision::INITIAL,
            owner,
            timestamp(1_000)?,
            timestamp(10)?,
        ))?;
        let attributions = insert_two_node_file_test_goal(
            &mut store,
            workspace_command.id(),
            activity.id(),
            0xE010,
        )?;
        let first_node = attributions[0]
            .node()
            .ok_or("first node attribution missing")?;
        let second_node = attributions[1]
            .node()
            .ok_or("second node attribution missing")?;
        let first_scope = crate::DagNodeEvidenceScope::new(
            first_node.goal_id(),
            first_node.dag_revision(),
            first_node.node_id(),
        );
        let second_scope = crate::DagNodeEvidenceScope::new(
            second_node.goal_id(),
            second_node.dag_revision(),
            second_node.node_id(),
        );

        let (first_begin, first_diff, first_authority) = admit_node_file_mutation(
            &mut store,
            workspace_command.id(),
            &activity,
            owner,
            attributions[0],
            0xE100,
            20,
        )?;
        let (second_begin, _second_diff, _second_authority) = admit_node_file_mutation(
            &mut store,
            workspace_command.id(),
            &activity,
            owner,
            attributions[0],
            0xE200,
            20,
        )?;
        let (_third_begin, _third_diff, _third_authority) = admit_node_file_mutation(
            &mut store,
            workspace_command.id(),
            &activity,
            owner,
            attributions[0],
            0xE300,
            20,
        )?;
        let (_other_begin, _other_diff, _other_authority) = admit_node_file_mutation(
            &mut store,
            workspace_command.id(),
            &activity,
            owner,
            attributions[1],
            0xE400,
            20,
        )?;

        let replay = store.begin_file_mutation_for_goal(
            &first_begin,
            &first_diff,
            Some(attributions[0]),
            first_authority,
        )?;
        assert_eq!(replay.status(), BeginFileMutationStatus::RecoveryRequired);
        assert_eq!(
            replay.record().change_set().state(),
            ChangeSetState::Starting
        );

        let first_page = store.list_dag_node_evidence(first_scope, 2, None)?;
        assert_eq!(first_page.scope(), first_scope);
        assert!(first_page.truncated());
        assert_eq!(first_page.entries().len(), 2);
        assert_eq!(
            first_page.entries()[0].evidence(),
            GoalEvidenceRef::ChangeSet(first_begin.change_set_id())
        );
        assert_eq!(
            first_page.entries()[1].evidence(),
            GoalEvidenceRef::ChangeSet(second_begin.change_set_id())
        );
        let associated_at = timestamp(20)?;
        assert!(
            first_page
                .entries()
                .iter()
                .all(|entry| entry.associated_at() == associated_at)
        );

        let second_page = store.list_dag_node_evidence(first_scope, 2, first_page.next_cursor())?;
        assert_eq!(second_page.entries().len(), 1);
        assert!(!second_page.truncated());
        assert_eq!(
            second_page.entries()[0].evidence(),
            GoalEvidenceRef::ChangeSet(ChangeSetId::from_uuid(Uuid::from_u128(0xE300)))
        );
        assert_eq!(second_page.entries()[0].associated_at(), associated_at);

        let other_page = store.list_dag_node_evidence(second_scope, 2, None)?;
        assert_eq!(other_page.entries().len(), 1);
        assert_eq!(
            other_page.entries()[0].evidence(),
            GoalEvidenceRef::ChangeSet(ChangeSetId::from_uuid(Uuid::from_u128(0xE400)))
        );
        assert!(matches!(
            store.list_dag_node_evidence(second_scope, 2, first_page.next_cursor()),
            Err(WorkspaceStoreError::DagNodeEvidence(
                crate::DagNodeEvidenceError::CursorScopeMismatch
            ))
        ));
        assert!(matches!(
            store.list_dag_node_evidence(first_scope, 0, None),
            Err(WorkspaceStoreError::DagNodeEvidence(
                crate::DagNodeEvidenceError::InvalidLimit { .. }
            ))
        ));
        assert!(matches!(
            store.list_dag_node_evidence(
                crate::DagNodeEvidenceScope::new(
                    first_scope.goal_id(),
                    DagRevisionNumber::new(2)?,
                    first_scope.node_id(),
                ),
                2,
                None,
            ),
            Err(WorkspaceStoreError::DagNodeEvidence(
                crate::DagNodeEvidenceError::DagRevisionMissing { .. }
            ))
        ));
        assert!(matches!(
            store.list_dag_node_evidence(
                crate::DagNodeEvidenceScope::new(
                    first_scope.goal_id(),
                    first_scope.dag_revision(),
                    DagNodeId::from_uuid(Uuid::from_u128(0xE099)),
                ),
                2,
                None,
            ),
            Err(WorkspaceStoreError::DagNodeEvidence(
                crate::DagNodeEvidenceError::NodeMissing { .. }
            ))
        ));
        assert_eq!(
            store.list_goal_evidence(first_scope.goal_id(), 128)?.len(),
            4
        );
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
        let hidden_goal = insert_file_test_goal_seeded(
            &mut store,
            workspace_command.id(),
            activity.id(),
            0xB130,
        )?;
        let authority = seed_test_source_write_authority(
            &mut store,
            workspace_command.id(),
            &activity,
            hidden_goal,
            failed_begin.path(),
            0xB140,
        )?;
        assert_eq!(
            store
                .begin_file_mutation(&failed_begin, &failed_diff_begin, authority)?
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
            ChangeSetProducer::new(authority.agent_id(), authority.session_id()),
        )?;
        assert_eq!(failed.change_set().state(), ChangeSetState::Failed);
        assert_eq!(
            failed.change_set().failure_code(),
            Some(FileMutationFailureCode::StaleWrite)
        );
        assert_eq!(
            store
                .begin_file_mutation(&failed_begin, &failed_diff_begin, authority)?
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
        let goal_activity_id = activity.id();
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
            goal_activity_id,
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
        let _ = workspace_goals::insert_goal(&mut store.connection, &goal)?;
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
        let goal_activity_id = activity.id();
        let scope = TextDiffTestScope {
            workspace_id: workspace_command.id(),
            activity,
            owner,
        };
        let diff = apply_text_diff(&mut store, &scope, 0xD610, 20)?;
        let goal = RegisteredGoal::create(
            GoalId::from_uuid(Uuid::from_u128(0xD620)),
            workspace_command.id(),
            goal_activity_id,
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
        let _ = workspace_goals::insert_goal(&mut store.connection, &goal)?;
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
    fn state_removal_rejects_residual_execution_after_activity_closure()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_root("state-removal-execution-blocker")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let command = command(&layout, workspace_id(0xE0D0), location_id(0xE0D1), 1)?;
        let mut store = WorkspaceStore::open(&layout, &command)?;
        let activity = store.create_activity(&CreateActivity::new(
            activity_id(0xE0D2),
            command.id(),
            WorkspaceRevision::INITIAL,
            timestamp(2)?,
        ))?;
        // Adversarial recovery residue: a terminal Activity must not hide an
        // independently nonterminal execution. Reuse the canonical stale-record fixture.
        insert_stale_doctor_records(&mut store, &command, &activity)?;
        store.set_activity_state(&forge_domain::SetActivityState::new(
            activity.id(),
            activity.revision(),
            ActivityState::Closed,
            timestamp(3)?,
        ))?;
        drop(store);
        let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("missing layout")?;
        let gate = WorkspaceStateExclusiveGate::acquire(
            existing.workspace_root(),
            existing.root_fingerprint()?,
        )?;
        assert!(matches!(
            WorkspaceStore::preflight_state_removal_under_exclusive(
                &existing,
                &gate,
                command.location_id()
            ),
            Err(WorkspaceStoreError::StateRemovalBlocked(
                WorkspaceStateRemovalBlocker::ActiveExecution
            ))
        ));
        drop(gate);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn state_removal_rejects_expired_unreleased_writer_after_activity_closure()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_root("state-removal-writer-blocker")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let command = command(&layout, workspace_id(0xE0E0), location_id(0xE0E1), 1)?;
        let mut store = WorkspaceStore::open(&layout, &command)?;
        let activity = store.create_activity(&CreateActivity::new(
            activity_id(0xE0E2),
            command.id(),
            WorkspaceRevision::INITIAL,
            timestamp(2)?,
        ))?;
        let agent = Uuid::from_u128(0xE0E3);
        let lease = Uuid::from_u128(0xE0E4);
        // A deliberately stale durable lease remains a deletion fence. These
        // rows obey the current schema and foreign keys, with no authority inferred from time.
        store.connection.execute(
            "INSERT INTO agent_instances (
            agent_id, workspace_id, activity_id, display_name, declared_role,
            transport_kind, principal_kind, principal_id, attachment_state,
            focus_goal_id, focus_goal_revision, focus_dag_revision, focus_node_id,
            focus_node_revision, created_at_ms, updated_at_ms, revision
        ) VALUES (?1, ?2, ?3, 'Writer', 'worker', 0, 0, NULL, 0,
            NULL, NULL, NULL, NULL, NULL, 1, 1, 1)",
            params![
                agent.as_bytes(),
                command.id().into_uuid().as_bytes(),
                activity.id().into_uuid().as_bytes()
            ],
        )?;
        store.connection.execute(
            "INSERT INTO writer_leases (
            lease_id, workspace_id, activity_id, agent_id, state, acquired_at_ms,
            updated_at_ms, lease_until_ms, revision
        ) VALUES (?1, ?2, ?3, ?4, 0, 1, 1, 2, 1)",
            params![
                lease.as_bytes(),
                command.id().into_uuid().as_bytes(),
                activity.id().into_uuid().as_bytes(),
                agent.as_bytes()
            ],
        )?;
        store.connection.execute(
            "INSERT INTO writer_lease_scope_entries
            (lease_id, ordinal, scope_kind, relative_path) VALUES (?1, 0, 0, ?2)",
            params![lease.as_bytes(), b"source.rs".as_slice()],
        )?;
        store.set_activity_state(&forge_domain::SetActivityState::new(
            activity.id(),
            activity.revision(),
            ActivityState::Closed,
            timestamp(3)?,
        ))?;
        drop(store);
        let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("missing layout")?;
        let gate = WorkspaceStateExclusiveGate::acquire(
            existing.workspace_root(),
            existing.root_fingerprint()?,
        )?;
        assert!(matches!(
            WorkspaceStore::preflight_state_removal_under_exclusive(
                &existing,
                &gate,
                command.location_id()
            ),
            Err(WorkspaceStoreError::StateRemovalBlocked(
                WorkspaceStateRemovalBlocker::ActiveWriterLease
            ))
        ));
        drop(gate);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn state_removal_preflight_rejects_an_owned_recovery_lease()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_root("state-removal-recovery-blocker")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_command = command(&layout, workspace_id(0xE0F0), location_id(0xE0F1), 1)?;
        let mut store = WorkspaceStore::open(&layout, &workspace_command)?;
        let command = ClaimRecoveryLease::new(
            workspace_command.id(),
            runtime_id(0xE0F2),
            RecoveryLeaseDurationMillis::new(1_000)?,
            timestamp(1)?,
        )?;
        assert_eq!(
            store.claim_recovery_maintenance_lease(command)?.status(),
            RecoveryLeaseClaimStatus::Acquired
        );
        drop(store);
        let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("missing layout")?;
        let gate = WorkspaceStateExclusiveGate::acquire(
            existing.workspace_root(),
            existing.root_fingerprint()?,
        )?;
        assert!(matches!(
            WorkspaceStore::preflight_state_removal_under_exclusive(
                &existing,
                &gate,
                workspace_command.location_id(),
            ),
            Err(WorkspaceStoreError::StateRemovalBlocked(
                WorkspaceStateRemovalBlocker::RecoveryMaintenanceLease
            ))
        ));
        drop(gate);
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
    fn recovery_lease_claim_sqlite_commit_failure_is_unknown()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_root("recovery-claim-commit-unknown")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_command = command(&layout, workspace_id(0xE120), location_id(0xE121), 1)?;
        let mut store = WorkspaceStore::open(&layout, &workspace_command)?;
        install_recovery_commit_failure_guard(&store)?;

        let claim = ClaimRecoveryLease::new(
            workspace_command.id(),
            runtime_id(0xE122),
            RecoveryLeaseDurationMillis::new(1_000)?,
            timestamp(1)?,
        )?;
        let outcome = store.claim_recovery_maintenance_lease(claim);
        assert_recovery_commit_unknown(outcome);
        assert!(store.get_recovery_maintenance_lease()?.is_released());

        drop(store);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn recovery_lease_renew_sqlite_commit_failure_is_unknown()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_root("recovery-renew-commit-unknown")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_command = command(&layout, workspace_id(0xE130), location_id(0xE131), 1)?;
        let mut store = WorkspaceStore::open(&layout, &workspace_command)?;
        let owner = runtime_id(0xE132);
        let acquired = store.claim_recovery_maintenance_lease(ClaimRecoveryLease::new(
            workspace_command.id(),
            owner,
            RecoveryLeaseDurationMillis::new(1_000)?,
            timestamp(1)?,
        )?)?;
        install_recovery_commit_failure_guard(&store)?;

        let renew = forge_domain::RenewRecoveryLease::new(
            workspace_command.id(),
            owner,
            acquired.lease().epoch(),
            acquired.lease().revision(),
            RecoveryLeaseDurationMillis::new(1_000)?,
            timestamp(500)?,
        )?;
        assert_recovery_commit_unknown(store.renew_recovery_maintenance_lease(renew));
        assert_eq!(
            store.get_recovery_maintenance_lease()?,
            acquired.lease().clone()
        );

        drop(store);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn recovery_lease_release_sqlite_commit_failure_is_unknown()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_root("recovery-release-commit-unknown")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_command = command(&layout, workspace_id(0xE140), location_id(0xE141), 1)?;
        let mut store = WorkspaceStore::open(&layout, &workspace_command)?;
        let owner = runtime_id(0xE142);
        let acquired = store.claim_recovery_maintenance_lease(ClaimRecoveryLease::new(
            workspace_command.id(),
            owner,
            RecoveryLeaseDurationMillis::new(1_000)?,
            timestamp(1)?,
        )?)?;
        install_recovery_commit_failure_guard(&store)?;

        let release = forge_domain::ReleaseRecoveryLease::new(
            workspace_command.id(),
            owner,
            acquired.lease().epoch(),
            acquired.lease().revision(),
            timestamp(500)?,
        );
        assert_recovery_commit_unknown(store.release_recovery_maintenance_lease(release));
        assert_eq!(
            store.get_recovery_maintenance_lease()?,
            acquired.lease().clone()
        );

        drop(store);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn recovery_lease_post_commit_binding_failure_requires_reopen_readback()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_root("recovery-post-commit-binding-unknown")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_command = command(&layout, workspace_id(0xE150), location_id(0xE151), 1)?;
        let mut store = WorkspaceStore::open(&layout, &workspace_command)?;
        let original_identity = store.database_identity;
        let owner = runtime_id(0xE152);
        let claim = ClaimRecoveryLease::new(
            workspace_command.id(),
            owner,
            RecoveryLeaseDurationMillis::new(1_000)?,
            timestamp(1)?,
        )?;
        let outcome = store.claim_recovery_maintenance_lease_with_hook(claim, |store| {
            store.database_identity.inode ^= 1;
        });
        assert!(matches!(
            outcome,
            Err(WorkspaceStoreError::RecoveryMaintenanceLeaseCommittedUnconfirmed { .. })
        ));
        store.database_identity = original_identity;
        drop(store);

        let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
        let reopened = WorkspaceStore::open_existing(&existing)?;
        let persisted = reopened.get_recovery_maintenance_lease()?;
        assert_eq!(persisted.owner_id(), Some(owner));
        assert_eq!(persisted.epoch().get(), 1);
        assert_eq!(persisted.revision().get(), 2);
        drop(reopened);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn recovery_lease_live_read_only_preserves_row_and_path_identities()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_root("recovery-live-read-only")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_command = command(&layout, workspace_id(0xE160), location_id(0xE161), 1)?;
        let store = WorkspaceStore::open(&layout, &workspace_command)?;
        let expected = store.get_recovery_maintenance_lease()?;
        drop(store);

        let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
        let database = existing.database_path();
        let wal = super::sidecar_path(&database, "-wal");
        let shm = super::sidecar_path(&database, "-shm");
        let before = (
            super::inspect_regular_file(&database, true)?,
            super::inspect_regular_file(&wal, true)?,
            super::inspect_regular_file(&shm, true)?,
        );

        let observed =
            WorkspaceStore::inspect_recovery_maintenance_lease_live_read_only(&existing)?;
        assert_eq!(observed, expected);
        assert_eq!(
            (
                super::inspect_regular_file(&database, true)?,
                super::inspect_regular_file(&wal, true)?,
                super::inspect_regular_file(&shm, true)?,
            ),
            before
        );

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

    fn assert_recovery_writer_lock_held(
        connection: &mut Connection,
    ) -> Result<(), WorkspaceStoreError> {
        match connection.transaction_with_behavior(TransactionBehavior::Immediate) {
            Ok(probe) => {
                probe.rollback()?;
                Err(WorkspaceStoreError::RecoveryLeaseClockObservation {
                    source: Box::new(std::io::Error::other("clock ran before the writer lock")),
                })
            }
            Err(rusqlite::Error::SqliteFailure(error, _))
                if error.code == rusqlite::ErrorCode::DatabaseBusy =>
            {
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }

    #[test]
    fn recovery_clock_is_sampled_after_lock_and_preserves_requested_duration()
    -> Result<(), Box<dyn std::error::Error>> {
        fn clock_test_error(message: &'static str) -> WorkspaceStoreError {
            WorkspaceStoreError::RecoveryLeaseClockObservation {
                source: Box::new(std::io::Error::other(message)),
            }
        }

        let root = unique_root("recovery-clock-after-lock")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_command = command(&layout, workspace_id(0xE170), location_id(0xE171), 1)?;
        drop(WorkspaceStore::open(&layout, &workspace_command)?);
        let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
        let first_store = WorkspaceStore::open_existing(&existing)?;
        let second_store = WorkspaceStore::open_existing(&existing)?;
        let workspace_id = workspace_command.id();
        let duration = RecoveryLeaseDurationMillis::new(1_000)?;
        let owner_a = runtime_id(0xE172);
        let owner_b = runtime_id(0xE173);
        let mut lock_probe = Connection::open(existing.database_path())?;
        lock_probe.busy_timeout(Duration::ZERO)?;

        let (first_clock_tx, first_clock_rx) = mpsc::channel();
        let (release_first_tx, release_first_rx) = mpsc::channel();
        let first = thread::spawn(move || {
            let mut store = first_store;
            store.claim_recovery_maintenance_lease_with_clock(
                workspace_id,
                owner_a,
                duration,
                || {
                    assert_recovery_writer_lock_held(&mut lock_probe)?;
                    first_clock_tx
                        .send(())
                        .map_err(|_| clock_test_error("first clock observer was dropped"))?;
                    release_first_rx
                        .recv_timeout(Duration::from_secs(5))
                        .map_err(|_| clock_test_error("first clock release was dropped"))?;
                    TimestampMillis::new(2).map_err(|source| {
                        WorkspaceStoreError::RecoveryLeaseClockObservation {
                            source: Box::new(source),
                        }
                    })
                },
            )
        });
        first_clock_rx.recv_timeout(Duration::from_secs(5))?;

        let (second_started_tx, second_started_rx) = mpsc::channel();
        let (second_clock_tx, second_clock_rx) = mpsc::channel();
        let second = thread::spawn(move || {
            second_started_tx
                .send(())
                .map_err(|_| clock_test_error("second claim was not admitted"))?;
            let mut store = second_store;
            store.claim_recovery_maintenance_lease_with_clock(
                workspace_id,
                owner_b,
                duration,
                || {
                    second_clock_tx
                        .send(())
                        .map_err(|_| clock_test_error("second clock observer was dropped"))?;
                    TimestampMillis::new(3).map_err(|source| {
                        WorkspaceStoreError::RecoveryLeaseClockObservation {
                            source: Box::new(source),
                        }
                    })
                },
            )
        });
        second_started_rx.recv_timeout(Duration::from_secs(5))?;
        assert!(matches!(
            second_clock_rx.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        release_first_tx.send(())?;

        let first = first
            .join()
            .map_err(|_| std::io::Error::other("first recovery clock thread panicked"))??;
        second_clock_rx.recv_timeout(Duration::from_secs(5))?;
        let second = second
            .join()
            .map_err(|_| std::io::Error::other("second recovery clock thread panicked"))??;

        assert_eq!(first.status(), RecoveryLeaseClaimStatus::Acquired);
        assert_eq!(first.lease().owner_id(), Some(owner_a));
        assert_eq!(first.lease().updated_at(), timestamp(2)?);
        assert_eq!(first.lease().lease_until(), Some(timestamp(1_002)?));
        assert_eq!(first.lease().revision().get(), 2);
        assert_eq!(second.status(), RecoveryLeaseClaimStatus::Busy);
        assert_eq!(second.lease(), first.lease());

        // A caller timestamp captured at t1 and applied after the t2 commit is
        // still rejected by the explicit native command path.
        let stale = ClaimRecoveryLease::new(workspace_id, owner_b, duration, timestamp(1)?)?;
        let mut explicit_store = WorkspaceStore::open_existing(&existing)?;
        assert!(matches!(
            explicit_store.claim_recovery_maintenance_lease(stale),
            Err(WorkspaceStoreError::Recovery(
                RecoveryStoreError::Transition(RecoveryLeaseTransitionError::TimestampInversion)
            ))
        ));
        assert_eq!(
            explicit_store.get_recovery_maintenance_lease()?,
            first.lease().clone()
        );

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn activity_successor_is_terminal_cas_idempotent_and_readback_fenced()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, _layout, mut store, predecessor_id) = store_with_activity("activity-successor")?;
        let workspace_id = store.workspace()?.id();
        let predecessor = store
            .get_activity(predecessor_id)?
            .ok_or("predecessor missing")?;
        let predecessor = store.set_activity_state(&forge_domain::SetActivityState::new(
            predecessor.id(),
            predecessor.revision(),
            ActivityState::Closed,
            timestamp(3)?,
        ))?;
        let successor_id = activity_id(0xF001);
        let command = forge_domain::CreateActivitySuccessor::new(
            workspace_id,
            WorkspaceRevision::INITIAL,
            predecessor.id(),
            predecessor.revision(),
            successor_id,
            AgentSessionId::from_uuid(Uuid::from_u128(0xF002)),
            RuntimeInstanceId::from_uuid(Uuid::from_u128(0xF003)),
            timestamp(4)?,
        )?;

        let created = store.create_activity_successor(&command)?;
        assert!(created.created());
        assert_eq!(
            created.relation().predecessor_activity_id(),
            predecessor.id()
        );
        assert_eq!(created.successor().id(), successor_id);
        assert!(created.successor().lease().is_unleased());

        let replay_command = forge_domain::CreateActivitySuccessor::new(
            workspace_id,
            WorkspaceRevision::INITIAL,
            predecessor.id(),
            predecessor.revision(),
            successor_id,
            AgentSessionId::from_uuid(Uuid::from_u128(0xF007)),
            RuntimeInstanceId::from_uuid(Uuid::from_u128(0xF008)),
            timestamp(1)?,
        )?;
        let replayed = store.create_activity_successor(&replay_command)?;
        assert!(!replayed.created());
        assert_eq!(replayed.relation(), created.relation());
        assert_eq!(replayed.successor(), created.successor());

        let readback = store
            .get_activity_successor(predecessor.id())?
            .ok_or("successor readback missing")?;
        assert_eq!(readback.0, created.relation());
        assert_eq!(readback.1, *created.successor());

        let conflict = forge_domain::CreateActivitySuccessor::new(
            workspace_id,
            WorkspaceRevision::INITIAL,
            predecessor.id(),
            predecessor.revision(),
            activity_id(0xF004),
            AgentSessionId::from_uuid(Uuid::from_u128(0xF005)),
            RuntimeInstanceId::from_uuid(Uuid::from_u128(0xF006)),
            timestamp(5)?,
        )?;
        assert!(matches!(
            store.create_activity_successor(&conflict),
            Err(WorkspaceStoreError::ActivitySuccessorConflict { .. })
        ));

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn activity_successor_rolls_back_when_target_already_exists_or_predecessor_is_open()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, _layout, mut store, predecessor_id) =
            store_with_activity("activity-successor-rollback")?;
        let workspace_id = store.workspace()?.id();
        let predecessor = store
            .get_activity(predecessor_id)?
            .ok_or("predecessor missing")?;
        let open_command = forge_domain::CreateActivitySuccessor::new(
            workspace_id,
            WorkspaceRevision::INITIAL,
            predecessor.id(),
            predecessor.revision(),
            activity_id(0xF101),
            AgentSessionId::from_uuid(Uuid::from_u128(0xF102)),
            RuntimeInstanceId::from_uuid(Uuid::from_u128(0xF103)),
            timestamp(2)?,
        )?;
        assert!(matches!(
            store.create_activity_successor(&open_command),
            Err(WorkspaceStoreError::ActivitySuccessorPredecessorNotTerminal { .. })
        ));
        assert_eq!(store.list_activities(ActivityListLimit::DEFAULT)?.len(), 1);

        let predecessor = store.set_activity_state(&forge_domain::SetActivityState::new(
            predecessor.id(),
            predecessor.revision(),
            ActivityState::Closed,
            timestamp(3)?,
        ))?;
        store.create_activity(&CreateActivity::new(
            activity_id(0xF104),
            workspace_id,
            WorkspaceRevision::INITIAL,
            timestamp(4)?,
        ))?;
        let target_exists = forge_domain::CreateActivitySuccessor::new(
            workspace_id,
            WorkspaceRevision::INITIAL,
            predecessor.id(),
            predecessor.revision(),
            activity_id(0xF104),
            AgentSessionId::from_uuid(Uuid::from_u128(0xF105)),
            RuntimeInstanceId::from_uuid(Uuid::from_u128(0xF106)),
            timestamp(5)?,
        )?;
        assert!(matches!(
            store.create_activity_successor(&target_exists),
            Err(WorkspaceStoreError::ActivitySuccessorTargetAlreadyExists(id)) if id == activity_id(0xF104)
        ));
        assert!(store.get_activity_successor(predecessor.id())?.is_none());
        assert_eq!(store.list_activities(ActivityListLimit::DEFAULT)?.len(), 2);

        fs::remove_dir_all(root)?;
        Ok(())
    }

    fn inventory_seeded_agent(
        store: &WorkspaceStore,
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        seed: u128,
    ) -> Result<forge_domain::RegisteredAgentInstance, Box<dyn std::error::Error>> {
        let agent = migration_test_agent(workspace_id, activity_id, seed)?;
        crate::legacy_agent_seed::seed_agent(
            &store.connection,
            &agent,
            Some(forge_domain::AgentEventId::from_uuid(Uuid::from_u128(
                seed + 2,
            ))),
        )?;
        Ok(agent)
    }

    fn inventory_endpoint(
        agent: &forge_domain::RegisteredAgentInstance,
        side: forge_domain::WorkCutSide,
    ) -> Result<
        (forge_domain::WorkCutSession, forge_domain::WorkCutBinding),
        Box<dyn std::error::Error>,
    > {
        let session_id = agent
            .session_id()
            .ok_or("inventory fixture Agent is unbound")?;
        Ok((
            forge_domain::WorkCutSession::new(side, session_id)?,
            forge_domain::WorkCutBinding::new(
                side,
                agent.activity_id(),
                agent.id(),
                session_id,
                agent.principal(),
            )?,
        ))
    }

    fn work_cut_request_for_inventory(
        store: &WorkspaceStore,
        destination_id: Uuid,
        seed: u128,
        sessions: Vec<forge_domain::WorkCutSession>,
        bindings: Vec<forge_domain::WorkCutBinding>,
        scope: forge_domain::WorkCutScope,
    ) -> Result<forge_domain::WorkCutRequest, Box<dyn std::error::Error>> {
        let workspace = store.workspace()?;
        Ok(forge_domain::WorkCutRequest::new(
            Uuid::from_u128(seed),
            Uuid::from_u128(seed + 1),
            destination_id,
            forge_domain::ForgeBackendId::from_uuid(Uuid::from_u128(seed + 2)),
            workspace.id(),
            workspace.revision(),
            1,
            [0xA5; 32],
            [
                forge_domain::WorkCutParty::new(
                    Uuid::from_u128(seed + 3),
                    Uuid::from_u128(seed + 4),
                )?,
                forge_domain::WorkCutParty::new(
                    Uuid::from_u128(seed + 5),
                    Uuid::from_u128(seed + 6),
                )?,
            ],
            sessions,
            bindings,
            scope,
        )?)
    }

    type CrossActivityInventoryFixture = (
        PathBuf,
        WorkspaceStore,
        WorkspaceId,
        ActivityId,
        ActivityId,
        forge_domain::RegisteredAgentInstance,
        forge_domain::ActivityCoordinatorActor,
        forge_domain::GoalNodeAttribution,
    );

    fn cross_activity_focus_inventory_fixture(
        label: &str,
        seed: u128,
    ) -> Result<CrossActivityInventoryFixture, Box<dyn std::error::Error>> {
        let (root, _layout, mut store, activity_a) = store_with_live_activity(label)?;
        let workspace_id = store.workspace()?.id();
        let activity_b = activity_id(seed + 1);
        store.create_activity(&CreateActivity::new(
            activity_b,
            workspace_id,
            WorkspaceRevision::INITIAL,
            timestamp(3)?,
        ))?;
        let agent = inventory_seeded_agent(&store, workspace_id, activity_a, seed + 2)?;
        let session_id = agent
            .session_id()
            .ok_or("inventory fixture Agent is unbound")?;
        let coordinator = store.claim_activity_coordinator(
            forge_domain::ClaimActivityCoordinator::new(
                workspace_id,
                activity_a,
                agent.id(),
                agent.principal(),
                timestamp(4)?,
                session_id,
            ),
            timestamp(99)?,
        )?;
        let actor = forge_domain::ActivityCoordinatorActor::new(
            workspace_id,
            activity_a,
            agent.id(),
            coordinator.revision(),
            agent.principal(),
            session_id,
        );
        let node = insert_file_test_goal_seeded(&mut store, workspace_id, activity_b, seed + 0x20)?
            .node()
            .ok_or("cross-Activity Started node attribution missing")?;
        Ok((
            root,
            store,
            workspace_id,
            activity_a,
            activity_b,
            agent,
            actor,
            node,
        ))
    }

    #[test]
    fn leadership_work_inventory_rejects_an_omitted_attached_binding()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, _layout, mut store, activity_id) =
            store_with_activity("work-inventory-omitted-binding")?;
        let workspace_id = store.workspace()?.id();
        let incumbent = inventory_seeded_agent(&store, workspace_id, activity_id, 0xF201)?;
        let elected = inventory_seeded_agent(&store, workspace_id, activity_id, 0xF211)?;
        let delegation = install_delegation_seal(&mut store, 0xF221, 20)?;
        let (incumbent_session, incumbent_binding) =
            inventory_endpoint(&incumbent, forge_domain::WorkCutSide::Incumbent)?;
        let (elected_session, _omitted_binding) =
            inventory_endpoint(&elected, forge_domain::WorkCutSide::Elected)?;
        let request = work_cut_request_for_inventory(
            &store,
            delegation.destination_id(),
            0xF231,
            vec![incumbent_session, elected_session],
            vec![incumbent_binding],
            forge_domain::WorkCutScope::Workspace,
        )?;

        assert!(matches!(
            store.observe_leadership_work_inventory(&request),
            Err(WorkspaceStoreError::WorkInventory(
                crate::WorkInventoryError::Conflict("source binding roster differs")
            ))
        ));

        drop(store);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn leadership_work_inventory_captures_started_direct_focus_without_assignment()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, _layout, mut store, activity_id) =
            store_with_live_activity("work-inventory-direct-focus")?;
        let workspace_id = store.workspace()?.id();
        let agent = inventory_seeded_agent(&store, workspace_id, activity_id, 0xF301)?;
        let session_id = agent
            .session_id()
            .ok_or("inventory fixture Agent is unbound")?;
        let coordinator = store.claim_activity_coordinator(
            forge_domain::ClaimActivityCoordinator::new(
                workspace_id,
                activity_id,
                agent.id(),
                agent.principal(),
                timestamp(4)?,
                session_id,
            ),
            timestamp(99)?,
        )?;
        let actor = forge_domain::ActivityCoordinatorActor::new(
            workspace_id,
            activity_id,
            agent.id(),
            coordinator.revision(),
            agent.principal(),
            session_id,
        );
        let attribution =
            insert_file_test_goal_seeded(&mut store, workspace_id, activity_id, 0xF311)?;
        let node = attribution
            .node()
            .ok_or("Started node attribution missing")?;
        let focus = forge_domain::AgentFocus::new(
            Some(forge_domain::GoalAttribution::new(
                node.goal_id(),
                node.expected_goal_revision(),
            )),
            Some(node.dag_revision()),
            Some(forge_domain::AgentFocusNode::new(
                node.node_id(),
                node.expected_node_revision(),
            )),
        )?;
        let current_agent = store
            .get_agent(agent.id())?
            .ok_or("inventory fixture Agent disappeared")?;
        let _focused = store.set_agent_focus(
            actor,
            &forge_domain::SetAgentFocus::new(
                agent.id(),
                activity_id,
                current_agent.revision(),
                focus,
                timestamp(20)?,
            ),
            timestamp(99)?,
        )?;
        let delegation = install_delegation_seal(&mut store, 0xF321, 21)?;
        let (elected_session, binding) =
            inventory_endpoint(&agent, forge_domain::WorkCutSide::Elected)?;
        let request = work_cut_request_for_inventory(
            &store,
            delegation.destination_id(),
            0xF331,
            vec![
                forge_domain::WorkCutSession::new(
                    forge_domain::WorkCutSide::Incumbent,
                    forge_domain::AgentSessionId::from_uuid(Uuid::from_u128(0xF30F)),
                )?,
                elected_session,
            ],
            vec![binding],
            forge_domain::WorkCutScope::Workspace,
        )?;

        let inventory = store.observe_leadership_work_inventory(&request)?;
        assert_eq!(inventory.nodes().len(), 1);
        let node = inventory.nodes()[0];
        assert_eq!(node.agent_id(), agent.id());
        assert!(node.direct_focus());
        assert_eq!(node.node_state(), forge_domain::DagNodeStatus::Active);
        assert!(node.assignment().is_none());

        drop(store);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn leadership_work_inventory_merges_per_actor_focus_and_preserves_shared_node_work()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, _layout, mut store, activity_id) =
            store_with_live_activity("work-inventory-focus-assignment-dedup")?;
        let workspace_id = store.workspace()?.id();
        let offered =
            seed_assignment_for_offer_seal_migration(&mut store, workspace_id, activity_id)?;
        let running = store.claim_agent_assignment(
            &forge_domain::ClaimAgentAssignment::new(
                offered.id(),
                offered.target(),
                offered.revision(),
                timestamp(8)?,
            ),
            timestamp(99)?,
        )?;
        let delegation = install_delegation_seal(&mut store, 0xF421, 20)?;
        let coordinator = store
            .get_agent(running.coordinator().agent_id())?
            .ok_or("inventory Coordinator disappeared")?;
        let target = store
            .get_agent(running.target().agent_id())?
            .ok_or("inventory target disappeared")?;
        let (coordinator_session, coordinator_binding) =
            inventory_endpoint(&coordinator, forge_domain::WorkCutSide::Incumbent)?;
        let (target_session, target_binding) =
            inventory_endpoint(&target, forge_domain::WorkCutSide::Elected)?;
        let request = work_cut_request_for_inventory(
            &store,
            delegation.destination_id(),
            0xF431,
            vec![coordinator_session, target_session],
            vec![coordinator_binding, target_binding],
            forge_domain::WorkCutScope::Workspace,
        )?;

        let inventory = store.observe_leadership_work_inventory(&request)?;
        assert_eq!(inventory.nodes().len(), 1);
        let node = inventory.nodes()[0];
        assert_eq!(node.agent_id(), target.id());
        assert!(node.direct_focus());
        let assignment = node.assignment().ok_or("active Assignment missing")?;
        assert_eq!(assignment.assignment_id(), running.id());
        assert_eq!(
            assignment.state(),
            forge_domain::AgentAssignmentState::Running
        );

        // Two Agents can focus one node. Preserve both provenance witnesses.
        let actor = forge_domain::ActivityCoordinatorActor::new(
            workspace_id,
            activity_id,
            coordinator.id(),
            running.coordinator().revision(),
            coordinator.principal(),
            coordinator_session.session_id(),
        );
        let shared_focus = forge_domain::AgentFocus::new(
            Some(forge_domain::GoalAttribution::new(
                running.goal_id(),
                running.goal_revision(),
            )),
            Some(running.dag_revision()),
            Some(forge_domain::AgentFocusNode::new(
                running.node_id(),
                node.node_revision(),
            )),
        )?;
        let _focused = store.set_agent_focus(
            actor,
            &forge_domain::SetAgentFocus::new(
                coordinator.id(),
                activity_id,
                coordinator.revision(),
                shared_focus,
                timestamp(21)?,
            ),
            timestamp(99)?,
        )?;
        let shared = store.observe_leadership_work_inventory(&request)?;
        assert_eq!(shared.nodes().len(), 2);
        assert!(
            shared
                .nodes()
                .iter()
                .all(|item| item.scope() == node.scope())
        );
        let planning_focus = shared
            .nodes()
            .iter()
            .find(|item| item.agent_id() == coordinator.id())
            .ok_or("shared Coordinator focus was dropped")?;
        assert!(planning_focus.direct_focus());
        assert!(planning_focus.assignment().is_none());
        assert!(shared.nodes().iter().any(|item| item.agent_id() == target.id() && item.assignment() == Some(assignment)));

        drop(store);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn leadership_work_inventory_rejects_active_assignment_after_target_detaches()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, _layout, mut store, activity_id) =
            store_with_live_activity("work-inventory-detached-assignment-target")?;
        let workspace_id = store.workspace()?.id();
        let offered =
            seed_assignment_for_offer_seal_migration(&mut store, workspace_id, activity_id)?;
        let delegation = install_delegation_seal(&mut store, 0xF521, 20)?;
        let target = store
            .get_agent(offered.target().agent_id())?
            .ok_or("inventory target disappeared")?;
        let target_session = target.session_id().ok_or("target session missing")?;
        let departure = crate::AgentDepartureReconciliationRequest::new(
            Uuid::from_u128(0xF530),
            crate::AgentDepartureCommand::Detach(forge_domain::DetachAgent::new(
                target.id(),
                target.activity_id(),
                target.revision(),
                timestamp(22)?,
            )),
            target_session,
            target.principal(),
            [0x66; 32],
        )?;
        let _departure =
            store.reconcile_agent_departure(&delegation, &departure, timestamp(99)?)?;
        let detached = store
            .get_agent(target.id())?
            .ok_or("detached inventory target disappeared")?;
        assert_eq!(
            detached.attachment_state(),
            forge_domain::AgentAttachmentState::Detached
        );
        assert_eq!(
            store
                .get_agent_assignment(offered.id())?
                .ok_or("active Assignment disappeared")?
                .state(),
            forge_domain::AgentAssignmentState::Offered
        );
        let coordinator = store
            .get_agent(offered.coordinator().agent_id())?
            .ok_or("inventory Coordinator disappeared")?;
        let (coordinator_session, coordinator_binding) =
            inventory_endpoint(&coordinator, forge_domain::WorkCutSide::Incumbent)?;
        let request = work_cut_request_for_inventory(
            &store,
            delegation.destination_id(),
            0xF531,
            vec![
                coordinator_session,
                forge_domain::WorkCutSession::new(
                    forge_domain::WorkCutSide::Elected,
                    target_session,
                )?,
            ],
            vec![coordinator_binding],
            forge_domain::WorkCutScope::Workspace,
        )?;

        assert!(matches!(
            store.observe_leadership_work_inventory(&request),
            Err(WorkspaceStoreError::WorkInventory(
                crate::WorkInventoryError::Conflict(
                    "active assignment lacks attached source target"
                )
            ))
        ));

        drop(store);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn leadership_work_inventory_keeps_cross_activity_focus_scope_separate_from_binding()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, mut store, _workspace_id, activity_a, activity_b, agent, actor, node) =
            cross_activity_focus_inventory_fixture("work-inventory-cross-activity-focus", 0xF601)?;
        let focus = forge_domain::AgentFocus::new(
            Some(forge_domain::GoalAttribution::new(
                node.goal_id(),
                node.expected_goal_revision(),
            )),
            Some(node.dag_revision()),
            Some(forge_domain::AgentFocusNode::new(
                node.node_id(),
                node.expected_node_revision(),
            )),
        )?;
        let current_agent = store
            .get_agent(agent.id())?
            .ok_or("cross-Activity Agent disappeared")?;
        let _focused = store.set_agent_focus(
            actor,
            &forge_domain::SetAgentFocus::new(
                agent.id(),
                activity_a,
                current_agent.revision(),
                focus,
                timestamp(20)?,
            ),
            timestamp(99)?,
        )?;
        let delegation = install_delegation_seal(&mut store, 0xF641, 21)?;
        let (elected_session, binding) =
            inventory_endpoint(&agent, forge_domain::WorkCutSide::Elected)?;
        let request = work_cut_request_for_inventory(
            &store,
            delegation.destination_id(),
            0xF651,
            vec![
                forge_domain::WorkCutSession::new(
                    forge_domain::WorkCutSide::Incumbent,
                    forge_domain::AgentSessionId::from_uuid(Uuid::from_u128(0xF650)),
                )?,
                elected_session,
            ],
            vec![binding],
            forge_domain::WorkCutScope::Workspace,
        )?;

        let inventory = store.observe_leadership_work_inventory(&request)?;
        assert_eq!(inventory.agents().len(), 1);
        assert_eq!(inventory.agents()[0].binding().activity_id(), activity_a);
        assert_eq!(inventory.nodes().len(), 1);
        assert_eq!(inventory.nodes()[0].scope().activity_id(), activity_b);
        assert_eq!(inventory.nodes()[0].agent_id(), agent.id());
        assert!(inventory.nodes()[0].direct_focus());

        drop(store);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn leadership_work_inventory_rejects_cross_activity_goal_only_team_focus()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, mut store, _workspace_id, activity_a, activity_b, agent, actor, node) =
            cross_activity_focus_inventory_fixture("work-inventory-team-goal-only", 0xF701)?;
        let focus = forge_domain::AgentFocus::new(
            Some(forge_domain::GoalAttribution::new(
                node.goal_id(),
                node.expected_goal_revision(),
            )),
            Some(node.dag_revision()),
            None,
        )?;
        let current_agent = store
            .get_agent(agent.id())?
            .ok_or("cross-Activity Agent disappeared")?;
        let _focused = store.set_agent_focus(
            actor,
            &forge_domain::SetAgentFocus::new(
                agent.id(),
                activity_a,
                current_agent.revision(),
                focus,
                timestamp(20)?,
            ),
            timestamp(99)?,
        )?;
        let goal = store
            .get_goal(node.goal_id())?
            .ok_or("cross-Activity Goal disappeared")?;
        let dag = store
            .get_dag_revision(node.goal_id(), node.dag_revision())?
            .ok_or("cross-Activity DAG disappeared")?;
        let team_node = forge_domain::WorkCutNodeScope::new(
            activity_b,
            node.goal_id(),
            goal.timestamps().created_at(),
            dag.revision().base_goal_revision(),
            node.dag_revision(),
            node.node_id(),
        )?;
        let delegation = install_delegation_seal(&mut store, 0xF741, 21)?;
        let (elected_session, binding) =
            inventory_endpoint(&agent, forge_domain::WorkCutSide::Elected)?;
        let request = work_cut_request_for_inventory(
            &store,
            delegation.destination_id(),
            0xF751,
            vec![
                forge_domain::WorkCutSession::new(
                    forge_domain::WorkCutSide::Incumbent,
                    forge_domain::AgentSessionId::from_uuid(Uuid::from_u128(0xF750)),
                )?,
                elected_session,
            ],
            vec![binding],
            forge_domain::WorkCutScope::Team {
                team_id: Uuid::from_u128(0xF752),
                nodes: vec![team_node],
            },
        )?;

        assert!(matches!(
            store.observe_leadership_work_inventory(&request),
            Err(WorkspaceStoreError::WorkInventory(
                crate::WorkInventoryError::Conflict("Goal-only focus needs disposition")
            ))
        ));

        drop(store);
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
