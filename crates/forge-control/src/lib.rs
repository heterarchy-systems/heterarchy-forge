//! Transport- and UI-neutral application control services for Heterarchy Forge.
//!
//! The control plane is intentionally synchronous.  Desktop and other
//! adapters can submit bounded commands through [`ForgeControlClient`] without
//! acquiring a shared mutable application-state lock.  Durable state remains
//! authoritative in the Global Registry and one Workspace-local `SQLite` store.

#![deny(unsafe_code)]

mod activity_observation;
mod activity_recovery;
mod activity_successor;
mod agent;
mod agent_assignment;
mod agent_coordination;
mod agent_dag;
mod agent_operations_migration;
mod agent_session;
mod approval;
mod approval_cleanup;
mod approval_coordinator;
mod approval_expiry;
mod binding_activation;
mod binding_reference;
mod binding_registration;
mod binding_rejection;
mod checkpoint;
mod command;
mod continuation;
mod coordinator;
mod dag;
mod dag_plan_readback;
mod diff;
mod doctor;
mod error;
mod execution;
mod execution_coordinator;
mod execution_journal;
mod execution_stop;
mod file_mutation_readback;
mod filesystem;
mod generated_artifact;
mod goal;
mod goal_deletion;
mod goal_mutation;
mod queue;
mod quiescent_activity_lease_resume;
mod recovery;
mod retention;
mod semantic_projection;
mod service;
mod shell;
mod source_tree;
mod source_tree_digest;
mod source_tree_readback;
mod started_activity_lease_resume;
mod unstarted_activity_continuation;
mod work_cut;
mod worker;
mod workspace_inventory;
mod workspace_lifecycle;
mod workspace_queue;
mod workspace_registration;
mod workspace_removal;
mod workspace_root_recovery;
mod workspace_stop_intent;
mod writer_lease;
pub use continuation::{
    ContinuationCommand, ContinuationCutWitness, ContinuationOperation, ContinuationPrepare,
    ContinuationResponse,
};
pub use work_cut::{WorkCutCommand, WorkCutOperation, WorkCutResponse, WorkCutService};

#[cfg(test)]
mod legacy_agent_fixture;

pub use workspace_inventory::{WorkspaceInventory, WorkspaceInventoryEntry};
pub use workspace_queue::WorkspaceQueueSettingsRequest;
pub use workspace_registration::{
    WorkspaceRegistrationError, WorkspaceRegistrationOutcome, WorkspaceRegistrationProbe,
    WorkspaceRegistrationRequest, WorkspaceRevalidationReason, probe_workspace_registration,
    register_workspace,
};
pub use workspace_removal::{
    LocationRemovalProbe, LocationRemovalRequest, RemovalStateExpectation, WorkspaceRemovalCleanup,
    WorkspaceRemovalError, WorkspaceRemovalFailure, WorkspaceRemovalMode, WorkspaceRemovalOutcome,
    native_execute_checked, probe_location_removal, remove_workspace,
};
pub use workspace_root_recovery::{
    WorkspaceRootRecoveryCommitOutcome, WorkspaceRootRecoveryCommitRequest,
    WorkspaceRootRecoveryPrepareRequest, WorkspaceRootRecoveryProbe,
    WorkspaceRootRecoveryProbeRequest, WorkspaceRootRecoveryReadbackRequest,
    WorkspaceRootRecoveryRevalidationReason,
};

pub use activity_observation::{ActivityReadRequest, ActivityReadSnapshot};
pub use activity_recovery::{
    DurableExpiredActivityRecoveryRequest, ExpiredActivityRecoveryGetRequest,
    ExpiredActivityRecoveryProbeRequest, ExpiredActivityRecoveryReport,
};
pub use activity_successor::ActivitySuccessorCreateRequest;
pub use agent::{
    AgentContextRequest, AgentExecutionAuthorityRequest, AgentFocusRequest, AgentListRequest,
    AgentWorkUpdateRequest, MAX_AGENT_PROJECTION_RESULTS,
};
pub use agent_assignment::{
    AgentAssignmentGetRequest, AgentAssignmentListRequest, AgentAssignmentMutation,
    AgentAssignmentMutationRequest, AgentAssignmentOfferSealRequest, AgentAssignmentReadAuthority,
    MAX_ASSIGNMENT_LIST_RESULTS,
};
pub use agent_coordination::{
    AgentCoordinationQuery, AgentCoordinationView, AgentInboxListRequest,
};
pub use agent_dag::AgentDagPlanCommitRequest;
pub use agent_operations_migration::{
    AgentOperationsExportRequest, AgentOperationsFreezeReadRequest,
    AgentOperationsFreezeReleaseRequest, AgentOperationsFreezeRequest,
};
pub use agent_session::{
    AgentSessionAuthority, AgentSessionAuthorityFailure, AgentSessionProofRequest,
    AgentSessionResolveRequest,
};
pub use approval::ExecutionAdmissionEnvelope;
pub use approval::{
    ApprovalActivityScope, ApprovalCreateRequest, ApprovalDecisionRequest,
    ApprovalGrantConsumeRequest, ApprovalGrantConsumeResult, ApprovalOnceRequest,
    AutoApprovalConsumeRequest, AutoApprovalConsumeResult, AutoApprovalScopeCreateRequest,
    AutoApprovalScopeRevokeRequest, WorkspacePolicyReplaceRequest,
};
pub use approval_coordinator::{
    ApprovalSubmission, ApprovalSubmissionStatus, AutoApprovalActionStatus,
    AutoApprovalRuntimeState, AutoApprovalScopeLocality, AutoApprovalStatus,
    ForgeApprovalCoordinator, ForgeApprovalCoordinatorClient, ForgeApprovalCoordinatorError,
    ForgeApprovalCoordinatorShutdown, PendingApproval, PendingApprovalProjection,
    SubmitExecutionForApproval,
};
pub use binding_activation::{
    AgentBindingActivateRequest, AgentBindingActivationReadRequest, AgentEffectOutboxReadRequest,
    AgentOperationsDelegationReadRequest, AgentOperationsDelegationRequest,
    EffectFactOutboxReadRequest,
};
pub use binding_activation::{
    AgentDepartureReconcileReadRequest, AgentDepartureReconcileRequest,
    AgentSessionReconcileReadRequest, AgentSessionReconcileRequest,
};
pub use binding_reference::{
    AgentBindingActivateReferenceRequest, AgentBindingReserveReferenceRequest,
    AgentDepartureReconcileDestinationRequest, AgentOperationsDelegateReferenceRequest,
    AgentOperationsDelegationReference, AgentOperationsFreezeReference,
    AgentSessionReconcileDestinationRequest,
};
pub use binding_registration::{AgentBindingReservationReadRequest, AgentBindingReserveRequest};
pub use binding_rejection::{AgentBindingRejectRequest, AgentBindingRejectionReadRequest};
pub use command::{
    DiscoveredProjectCommand, MAX_PROJECT_COMMAND_ID_BYTES, ProjectCommandId,
    ProjectCommandIdError, ProjectCommandListRequest, ProjectCommandListResult,
    ResolvedProjectCommandExecution,
};
pub use coordinator::{
    CoordinatorActorRequest, CoordinatorClaimRequest, CoordinatorGetRequest,
    CoordinatorTransferRequest,
};
pub use dag::{DagNodeCompleteRequest, DagNodeStartRequest, DagNodeUpdateRequest};
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
pub use error::{
    ControlError, ControlErrorCategory, ControlErrorCode, ControlErrorDetails, ControlErrorView,
    ControlOperationOutcome, ControlRecoveryAction,
};
pub use execution_coordinator::{
    ApprovedAgentExecutionRequest, ExecutionStartDisposition, ExecutionStartResult,
    ExecutionWaitHandle, ExecutionWaitParameters, ExecutionWaitResult, ExecutionWaiterId,
    ForgeExecutionCoordinator, ForgeExecutionCoordinatorClient, ForgeExecutionCoordinatorError,
    ForgeExecutionCoordinatorShutdown, JournalFailure, JournalFailureStage,
    JournalPersistenceFailure, OwnedWorkspaceExecutionStopObservation,
    WorkspaceExecutionStopObservation,
};
pub use file_mutation_readback::FileMutationReadbackRequest;
pub use filesystem::{
    FileActivityScope, FileApplyPatchOperation, FileApplyPatchRequest, FileApplyPatchResult,
    FileListRequest, FileListResult, FileMutationRequest, FileMutationResult, FileMutationStatus,
    FileReadRequest, FileReadResult, FileReadSliceRequest, FileReadSliceResult,
    SourceTreeTransactionRequest, SourceTreeTransactionResult, SourceTreeTransactionStatus,
    TextSearchRequest, TextSearchResult,
};
pub use forge_domain::{ProjectCommandCatalogFingerprint, ProjectCommandClass};
pub use forge_execution::{
    RUST_CI_PINNED_VERSION, RUST_CI_SANDBOX_MARKER_ENV, RUST_CI_SANDBOX_MARKER_VALUE,
    RustCiDiscoveryInput, RustCiHostArchitecture, RustCiToolchainCapability,
};
pub use generated_artifact::{
    GeneratedArtifactAccessError, GeneratedArtifactInventory, GeneratedArtifactInventoryLimit,
    GeneratedArtifactNodeKind, GeneratedArtifactObservation, GeneratedArtifactStatus,
    GeneratedPackageAccess, MAX_GENERATED_ARTIFACT_HASH_BYTES_PER_INVENTORY,
    MAX_GENERATED_ARTIFACT_INVENTORY,
};
pub use goal::{
    GoalCompletionRequest, GoalContractRevisionRequest, GoalLifecycleAction, GoalLifecycleRequest,
    MAX_GOAL_EVIDENCE_RESULTS,
};
pub use goal_deletion::{
    GoalDeleteIssue, GoalDeleteOutcome, GoalDeletePhase, GoalDeleteRequest, GoalDeletionAuthority,
    MAX_GOAL_DELETE_GROUPS_PER_CALL,
};
pub use heterarchy_orchestration_policy::{QueueCapacity, ServiceClass};
pub use queue::{QueueCapacitySource, QueueConfigError, QueueRuntimeError, QueueStatus};
pub use quiescent_activity_lease_resume::{
    QuiescentActivityLeaseResumeGetRequest, QuiescentActivityLeaseResumeProbeRequest,
    QuiescentActivityLeaseResumeRunRequest,
};
pub use recovery::{
    DurableRecoveryMaintenanceRequest, RecoveryLeaseAcquisition, RecoveryLeaseClaimOperation,
    RecoveryMaintenanceOutcome, RecoveryMaintenanceReport, RecoveryMaintenanceRequest,
};
pub use retention::{
    DeleteOrphanDiffArtifactRequest, DeleteOrphanDiffArtifactResult, DiffArtifactDiagnosticEntry,
    DiffArtifactDoctorRequest, DiffArtifactDoctorResult, DiffArtifactOwnershipStatus,
    DiffPurgeRequest, DiffPurgeResult, DiffRetentionPlanRequest, DiffRetentionPlanResult,
};
pub use semantic_projection::{
    MAX_SNAPSHOT_GOAL_SUMMARIES, SemanticEventsPageRequest, SemanticEventsPageResult,
    WorkspaceSemanticSnapshotRequest, WorkspaceSemanticSnapshotResult,
};
pub use service::{
    ActivityBootstrap, ActivityBootstrapStatus, ActivityLeaseOperation, ActivityOperation,
    ActivityOperationStatus, ActivityReconcileResult, ForgeControl, MAX_ACTIVITY_LEASE_BATCH,
    MAX_ACTIVITY_LEASE_OBSERVATION_IDS, MAX_ACTIVITY_PROJECTION_RESULTS,
    MAX_WORKSPACE_CATALOG_ENTRIES, OwnedActivityLease, RegisterLocationRequest,
    ResolvedWorkspaceScope, SupervisedActivityLeaseRenewRequest, WorkspaceActivityProjection,
    WorkspaceActivityProjectionRequest, WorkspaceCatalogEntry, WorkspaceDiscoveryEntry,
};
pub use shell::{
    AnalyzedShellExecution, ShellAnalysisError, ShellExecutionClass, analyze_shell_script,
};
pub use source_tree::SourceTreeMutationRequest;
pub use source_tree_digest::source_tree_request_digest;
pub use source_tree_readback::SourceTreeReadbackRequest;
pub use started_activity_lease_resume::{
    StartedActivityLeaseResumeGetRequest, StartedActivityLeaseResumeProbeRequest,
    StartedActivityLeaseResumeRunRequest,
};
pub use unstarted_activity_continuation::{
    DurableUnstartedActivityContinuationRequest, UnstartedActivityContinuationGetRequest,
    UnstartedActivityContinuationProbeRequest, UnstartedActivityContinuationReport,
};
pub use worker::{
    ACTIVITY_LEASE_QUEUE_CAPACITY, ActivityLeaseClient, CONTROL_QUEUE_CAPACITY, ControlClientError,
    ControlWorkerError, ForgeControlClient, ForgeControlWorker, MAX_SHUTDOWN_ACTIVITIES,
    PendingControl, ShutdownReport,
};
pub use workspace_stop_intent::{WorkspaceStopIntent, WorkspaceStopServiceIdentity};
pub use writer_lease::{
    WriterLeaseAcquireRequest, WriterLeaseGetRequest, WriterLeaseListRequest,
    WriterLeaseRecoveryReleaseRequest, WriterLeaseReleaseRequest, WriterLeaseRenewRequest,
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
    ActivityProjection, ActivityState, AuthorizedExecutionRead, ChangeSetId, ChangeSetState,
    ClaimRecoveryLease, DiffArtifactHealth, DiffEvidenceState, DiffId, DiffListLimit,
    DiffPayloadProjection, ExecutionAgentProvenance, ExecutionCommandId, ExecutionCommandIdError,
    ExecutionOutputChunk, ExecutionOutputCursor, ExecutionOutputEvent, ExecutionOutputEventKey,
    ExecutionOutputGap, ExecutionOutputGapCause, ExecutionOutputGapError, ExecutionOutputGapParts,
    ExecutionOutputRead, ExecutionOutputSequence, ExecutionOutputSequenceError,
    ExecutionOutputStream, FileContentHash, FileMutationId, FileMutationKind, FileMutationPlan,
    FileMutationRecord, FilePathState, FilePrecondition, LocationId, LocationRevision,
    RecoveryLeaseDurationMillis, RecoveryLeaseEpoch, RecoveryLeaseRevision,
    RecoveryMaintenanceLease, RegisteredActivity, RegisteredDiffEvidence, RegisteredExecution,
    RegisteredGoal, ReleaseRecoveryLease, RenewRecoveryLease, RuntimeInstanceId, TimestampMillis,
    WorkspaceId, WorkspaceRelativePath, WorkspaceRevision,
};
pub use forge_workspace::{WorkspaceCandidateKind, WorkspaceLocator};

/// Naming alias for callers that consume the Activity projection boundary.
pub type ActivityProjectionService = ForgeControl;

/// Naming alias for the single-owner Activity supervisor worker.
pub type ActivitySupervisor = ForgeControlWorker;

pub use dag_plan_readback::DagPlanReadbackRequest;
pub use goal_mutation::{GoalMutationReadbackRequest, GoalMutationRequest};

mod coordinator_recovery;
pub use coordinator_recovery::{
    CoordinatorRecoveryConfirmRequest, CoordinatorRecoveryHistoryRequest,
    CoordinatorRecoveryPrepareRequest, CoordinatorRecoveryReadRequest,
};
