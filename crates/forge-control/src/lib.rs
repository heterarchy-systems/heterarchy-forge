//! Transport- and UI-neutral application control services for Heterarchy Forge.
//!
//! The control plane is intentionally synchronous.  MCP, desktop, and other
//! adapters can submit bounded commands through [`ForgeControlClient`] without
//! acquiring a shared mutable application-state lock.  Durable state remains
//! authoritative in the Global Registry and one Workspace-local `SQLite` store.

#![deny(unsafe_code)]

mod agent;
mod approval;
mod approval_coordinator;
mod checkpoint;
mod dag;
mod diff;
mod doctor;
mod error;
mod execution;
mod execution_coordinator;
mod filesystem;
mod goal;
mod grant;
mod harness;
mod harness_verifier_coordinator;
#[path = "mcp_auth.rs"]
mod mcp_token;
mod recovery;
mod retention;
mod service;
mod worker;

pub use agent::{
    AgentAttachRequest, AgentContextRequest, AgentDetachRequest, AgentFocusRequest,
    AgentListRequest, AgentWorkUpdateRequest, MAX_AGENT_PROJECTION_RESULTS,
};
pub use approval::{
    ApprovalActivityScope, ApprovalCancelActivityRequest, ApprovalCancelWorkspaceRequest,
    ApprovalCreateRequest, ApprovalDecisionRequest, ApprovalGrantConsumeRequest,
    ApprovalGrantConsumeResult, ApprovalOnceRequest, ApprovalReconcileRequest,
    AutoApprovalConsumeRequest, AutoApprovalConsumeResult, AutoApprovalScopeCreateRequest,
    AutoApprovalScopeRevokeRequest, WorkspacePolicyReplaceRequest,
};
pub use approval_coordinator::{
    ApprovalSubmission, ApprovalSubmissionStatus, ForgeApprovalCoordinator,
    ForgeApprovalCoordinatorClient, ForgeApprovalCoordinatorError,
    ForgeApprovalCoordinatorShutdown, PendingApproval, PendingApprovalProjection,
    SubmitExecutionForApproval,
};
pub use dag::{DagNodeStartRequest, DagNodeUpdateRequest, DagRevisionCreateRequest};
pub use diff::{
    DiffDoctorRequest, DiffDoctorResult, DiffListRequest, DiffListResult, DiffReadRequest,
    DiffReadResult,
};
pub use doctor::{
    WORKSPACE_IDENTITY_DOCTOR_MAX_LOCATIONS, WorkspaceCheckpointStoreAvailability,
    WorkspaceCheckpointStoreFinding, WorkspaceCheckpointStoreReport,
    WorkspaceCheckpointStoreStatus, WorkspaceDiffArtifactDoctorReport,
    WorkspaceDiffArtifactFinding, WorkspaceDiffArtifactStatus, WorkspaceDoctorAggregateOutcome,
    WorkspaceDoctorObservationConsistency, WorkspaceDoctorRequest, WorkspaceDoctorResult,
    WorkspaceIdentityDoctorOutcome, WorkspaceIdentityDoctorReport,
    WorkspaceIdentityDuplicateFinding, WorkspaceLocationMismatchFinding,
};
pub use error::{ControlError, ControlErrorCode, ControlErrorView};
pub use execution_coordinator::{
    ForgeExecutionCoordinator, ForgeExecutionCoordinatorClient, ForgeExecutionCoordinatorError,
    ForgeExecutionCoordinatorShutdown,
};
pub use filesystem::{
    FileActivityScope, FileMutationRequest, FileMutationResult, FileMutationStatus,
    FileReadRequest, FileReadResult,
};
pub use goal::{
    GoalCompletionRequest, GoalLifecycleAction, GoalLifecycleRequest, MAX_GOAL_EVIDENCE_RESULTS,
};
pub use grant::{
    AgentDagGrantDiscoverRequest, AgentDagGrantGetRequest, AgentDagGrantIssueRequest,
    AgentDagGrantRevokeRequest, AgentDagReplanCommitRequest,
};
pub use harness::{
    HarnessApplyRequest, HarnessCompositionRequest, HarnessCompositionRequestError,
    HarnessCompositionSkillSelection, HarnessLibrary, HarnessLibraryError,
    HarnessLifecycleApplyRequest, HarnessLifecyclePreviewProjection,
    HarnessLifecyclePreviewRequest, HarnessLifecycleTarget, HarnessPreviewRequest,
    HarnessVerifyRequest,
};
pub use harness_verifier_coordinator::{
    ForgeHarnessVerifierCoordinator, ForgeHarnessVerifierCoordinatorClient,
    ForgeHarnessVerifierCoordinatorError, HarnessVerifierRunRequest, PendingHarnessVerifierRun,
};
pub use mcp_token::{
    MAX_MCP_TOKEN_BEARER_BYTES, MAX_MCP_TOKEN_LIST_RESULTS, MCP_TOKEN_QUEUE_CAPACITY,
    MCP_TOKEN_REVEAL_BYTES, MCP_TOKEN_REVEAL_CHARS, McpTokenAuthorization, McpTokenCatalog,
    McpTokenClient, McpTokenClientError, McpTokenIssueRequest, McpTokenIssueRequestError,
    McpTokenIssued, McpTokenMetadata, McpTokenRequest, McpTokenReveal, McpTokenRotation,
    McpTokenService, McpTokenServiceError, McpTokenWorker, McpTokenWorkerError, PendingMcpToken,
};
pub use recovery::{
    RecoveryLeaseAcquisition, RecoveryLeaseClaimOperation, RecoveryMaintenanceOutcome,
    RecoveryMaintenanceReport, RecoveryMaintenanceRequest,
};
pub use retention::{
    DeleteOrphanDiffArtifactRequest, DeleteOrphanDiffArtifactResult, DiffArtifactDiagnosticEntry,
    DiffArtifactDoctorRequest, DiffArtifactDoctorResult, DiffArtifactOwnershipStatus,
    DiffPurgeRequest, DiffPurgeResult, DiffRetentionPlanRequest, DiffRetentionPlanResult,
};
pub use service::{
    ActivityBootstrap, ActivityBootstrapStatus, ActivityLeaseOperation, ActivityOperation,
    ActivityOperationStatus, ActivityReconcileResult, ForgeControl, MAX_ACTIVITY_LEASE_BATCH,
    MAX_ACTIVITY_PROJECTION_RESULTS, MAX_WORKSPACE_CATALOG_ENTRIES, OwnedActivityLease,
    ResolvedWorkspaceScope, WorkspaceActivityProjection, WorkspaceActivityProjectionRequest,
    WorkspaceCatalogEntry, WorkspaceCatalogStatus,
};
pub use worker::{
    CONTROL_QUEUE_CAPACITY, ControlClientError, ControlWorkerError, ForgeControlClient,
    ForgeControlRequest, ForgeControlWorker, MAX_SHUTDOWN_ACTIVITIES, PendingControl,
    ShutdownReport,
};

impl ForgeControl {
    /// Start the bounded single-owner worker for this service.
    pub fn start_worker(
        self,
    ) -> Result<(ForgeControlClient, ForgeControlWorker), ControlWorkerError> {
        ForgeControlWorker::start(self)
    }
}

pub use forge_domain::{
    ActivityId, ActivityLeaseProjection, ActivityLeaseRevision, ActivityLiveness,
    ActivityProjection, ActivityState, ChangeSetId, ChangeSetState, ClaimRecoveryLease,
    DiffArtifactHealth, DiffEvidenceState, DiffId, DiffListLimit, DiffPayloadProjection,
    FileContentHash, FileMutationId, FileMutationKind, FileMutationPlan, FileMutationRecord,
    FilePathState, FilePrecondition, LocationId, LocationRevision, RecoveryLeaseDurationMillis,
    RecoveryLeaseEpoch, RecoveryLeaseRevision, RecoveryMaintenanceLease, RegisteredActivity,
    RegisteredDiffEvidence, RegisteredExecution, RegisteredGoal, ReleaseRecoveryLease,
    RenewRecoveryLease, RuntimeInstanceId, TimestampMillis, WorkspaceId, WorkspaceRelativePath,
    WorkspaceRevision,
};
pub use forge_workspace::{WorkspaceCandidateKind, WorkspaceLocator};

/// Naming alias for callers that consume the Activity projection boundary.
pub type ActivityProjectionService = ForgeControl;

/// Naming alias for the single-owner Activity supervisor worker.
pub type ActivitySupervisor = ForgeControlWorker;
