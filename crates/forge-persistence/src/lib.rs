//! Durable persistence adapters for Heterarchy Forge.

mod global_registry;
mod harness_catalog;
mod workspace_approvals;
mod workspace_changesets;
mod workspace_checkpoints;
mod workspace_dags;
mod workspace_diffs;
mod workspace_executions;
mod workspace_goals;
mod workspace_harness;
mod workspace_harness_verifiers;
mod workspace_recovery;
mod workspace_store;

pub use global_registry::{GlobalRegistry, RegistryError, RegistryHealth};
pub use harness_catalog::{
    HARNESS_CATALOG_APPLICATION_ID, HARNESS_CATALOG_SCHEMA_VERSION, HarnessCatalog,
    HarnessCatalogEntry, HarnessCatalogError, MAX_HARNESS_CATALOG_RESULTS,
};
pub use workspace_approvals::{
    ApprovalAuthorityCleanupReport, ApprovalStoreError, AutoApprovalExecutionRecord,
};
pub use workspace_changesets::ChangeSetStoreError;
pub use workspace_checkpoints::{
    CHECKPOINT_DOCTOR_MAX_REFERENCES, CheckpointDoctorReference, CheckpointDoctorReport,
    CheckpointDoctorSnapshotReference, CheckpointStoreError,
};
pub use workspace_dags::{
    DAG_DOCTOR_MAX_CURRENT_DAGS, DagDoctorFinding, DagDoctorIssue, DagDoctorNodeSummary,
    DagDoctorReport, DagDoctorState, DagHead, DagNodeEvidenceSummary, DagStoreError,
    StoredDagRevision,
};
pub use workspace_diffs::{
    DIFF_DOCTOR_MAX_REFERENCES, DiffDoctorArtifactReference, DiffDoctorLifecycle,
    DiffDoctorReference, DiffDoctorReport, DiffStoreError,
};
pub use workspace_executions::{BeginExecutionRecord, BeginExecutionStatus, ExecutionStoreError};
pub use workspace_goals::{GoalCompletionReceipt, GoalEvidenceRecord, GoalStoreError};
pub use workspace_harness::HarnessStoreError;
pub use workspace_harness_verifiers::HarnessVerifierStoreError;
pub use workspace_recovery::{
    RecoveryLeaseClaimResult, RecoveryLeaseClaimStatus, RecoveryStoreError,
};
pub use workspace_store::{
    BeginFileMutationDiffResult, FileMutationDiffRecord, WORKSPACE_APPLICATION_ID,
    WorkspaceDoctorCount, WorkspaceDoctorIntegrity, WorkspaceDoctorOutcome, WorkspaceDoctorReport,
    WorkspaceDoctorSourceObservation, WorkspaceStore, WorkspaceStoreError, WorkspaceStoreHealth,
};
