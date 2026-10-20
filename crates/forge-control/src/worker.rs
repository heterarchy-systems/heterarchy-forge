use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::thread::{self, JoinHandle};
use std::time::{SystemTime, UNIX_EPOCH};

use forge_domain::{
    ActivityCoordinatorActor, ActivityId, ActivityLeaseRevision, ActivityListLimit,
    ActivityProjection, ApprovalRequestId, AuthorizedExecutionRead, AutoApprovalScope,
    AutoApprovalScopeId, ClaimRecoveryLease, CloseActivity, CompleteExecution, DagRevisionNumber,
    ExecutionGrant, ExecutionId, ExecutionListLimit, ExecutionOutputCursor, ExecutionOutputEvent,
    ExecutionOutputRead, FailExecution, GoalId, GoalListLimit, GoalReview, LocationId,
    LocationRevision, MarkExecutionRunning, RecoveryLeaseDurationMillis, RecoveryMaintenanceLease,
    RegisteredActivity, RegisteredApprovalRequest, RegisteredDagNode, RegisteredExecution,
    RegisteredGoal, RegisteredLocation, ReleaseActivityLease, ReleaseRecoveryLease,
    RenewActivityLease, RenewRecoveryLease, RuntimeInstanceId, SetLocationState, TimestampMillis,
    VerificationProjection, WorkspaceId, WorkspacePolicy,
};
use forge_persistence::{
    ApprovalCleanupApplyOutcome, ApprovalCleanupAttemptId, DagNodeAssignmentSnapshot,
    DagNodeEvidenceScope, StoredDagRevision, WorkspaceStoreError,
};
use forge_workspace::WorkspaceLocator;
use heterarchy_orchestration_policy::{QueueCapacity, ServiceClass};

use crate::activity_observation::{ActivityReadRequest, ActivityReadSnapshot};
use crate::activity_recovery::{
    DurableExpiredActivityRecoveryRequest, ExpiredActivityRecoveryGetRequest,
    ExpiredActivityRecoveryProbeRequest, ExpiredActivityRecoveryReport,
};
use crate::activity_successor::ActivitySuccessorCreateRequest;
use crate::agent::{
    AgentContextRequest, AgentExecutionAuthorityRequest, AgentFocusRequest, AgentListRequest,
    AgentWorkUpdateRequest,
};
use crate::agent_coordination::{
    AgentCoordinationQuery, AgentCoordinationView, AgentInboxListRequest,
};
use crate::agent_dag::AgentDagPlanCommitRequest;
use crate::agent_operations_migration::{
    AgentOperationsExportRequest, AgentOperationsFreezeReadRequest,
    AgentOperationsFreezeReleaseRequest, AgentOperationsFreezeRequest,
};
use crate::agent_session::{AgentSessionProofRequest, AgentSessionResolveRequest};
use crate::approval::{
    ApprovalCreateRequest, ApprovalDecisionRequest, ApprovalExecutionGrantReadback,
    ApprovalGrantConsumeRequest, ApprovalGrantConsumeResult, ApprovalOnceRequest,
    AutoApprovalConsumeRequest, AutoApprovalConsumeResult, AutoApprovalScopeCreateRequest,
    AutoApprovalScopeRevokeRequest, WorkspacePolicyReplaceRequest,
};
use crate::approval_cleanup::{
    ApprovalCleanupOwner, ApprovalCleanupPermit, ApprovalCleanupPlan, ApprovalCleanupReadback,
    ApprovalCleanupSelector,
};
use crate::approval_expiry::ApprovalExpiryPlan;
use crate::binding_reference::{
    AgentBindingActivateReferenceRequest, AgentBindingReserveReferenceRequest,
    AgentDepartureReconcileDestinationRequest, AgentOperationsDelegateReferenceRequest,
    AgentSessionReconcileDestinationRequest,
};
use crate::checkpoint::CheckpointRestoreOutcome;
use crate::checkpoint::CheckpointRestoreRequest;
use crate::command::{
    PreparedProjectCommandVerification, ProjectCommandListRequest, ProjectCommandListResult,
};
use crate::coordinator::{
    CoordinatorClaimRequest, CoordinatorGetRequest, CoordinatorTransferRequest,
};
use crate::coordinator_recovery::{
    CoordinatorRecoveryConfirmRequest, CoordinatorRecoveryHistoryRequest,
    CoordinatorRecoveryPrepareRequest, CoordinatorRecoveryReadRequest,
};
use crate::dag::{DagNodeCompleteRequest, DagNodeStartRequest, DagNodeUpdateRequest};
use crate::diff::{
    DiffDoctorRequest, DiffDoctorResult, DiffListRequest, DiffListResult, DiffReadRequest,
    DiffReadResult,
};
use crate::doctor::{WorkspaceDoctorRequest, WorkspaceDoctorResult, WorkspaceIdentityDoctorReport};
use crate::error::{ControlError, ControlErrorCode, ControlErrorView};
use crate::execution_stop::ExecutionStopContext;
use crate::filesystem::{
    FileActivityScope, FileApplyPatchRequest, FileApplyPatchResult, FileListRequest,
    FileListResult, FileMutationRequest, FileMutationResult, FileReadRequest, FileReadResult,
    FileReadSliceRequest, FileReadSliceResult, SourceTreeTransactionRequest,
    SourceTreeTransactionResult, TextSearchRequest, TextSearchResult,
};
use crate::goal::{GoalCompletionRequest, GoalContractRevisionRequest, GoalLifecycleRequest};
use crate::queue::{
    QueueAttribution, QueueConfigError, QueueDequeue, QueueEnqueueError, QueueMailbox,
    QueueRuntimeError, QueueStatus,
};
use crate::quiescent_activity_lease_resume::{
    QuiescentActivityLeaseResumeGetRequest, QuiescentActivityLeaseResumeProbeRequest,
    QuiescentActivityLeaseResumeRunRequest,
};
use crate::recovery::{
    RecoveryLeaseClaimOperation, RecoveryMaintenanceReport, RecoveryMaintenanceRequest,
};
use crate::retention::{
    DeleteOrphanDiffArtifactRequest, DeleteOrphanDiffArtifactResult, DiffArtifactDoctorRequest,
    DiffArtifactDoctorResult, DiffPurgeRequest, DiffPurgeResult, DiffRetentionPlanRequest,
    DiffRetentionPlanResult,
};
use crate::service::{
    ActivityBootstrap, ActivityLeaseOperation, ForgeControl, MAX_ACTIVITY_LEASE_OBSERVATION_IDS,
    OwnedActivityLease, RegisterLocationRequest, ResolvedWorkspaceScope,
    SupervisedActivityLeaseRenewRequest, WorkspaceActivityProjection,
    WorkspaceActivityProjectionRequest, WorkspaceCatalogEntry, WorkspaceDiscoveryEntry,
};
use crate::started_activity_lease_resume::{
    StartedActivityLeaseResumeGetRequest, StartedActivityLeaseResumeProbeRequest,
    StartedActivityLeaseResumeRunRequest,
};
use crate::unstarted_activity_continuation::{
    DurableUnstartedActivityContinuationRequest, UnstartedActivityContinuationGetRequest,
    UnstartedActivityContinuationProbeRequest, UnstartedActivityContinuationReport,
};
use crate::workspace_queue::WorkspaceQueueSettingsRequest;
use crate::workspace_root_recovery::{
    WorkspaceRootRecoveryCommitOutcome, WorkspaceRootRecoveryCommitRequest,
    WorkspaceRootRecoveryPrepareRequest, WorkspaceRootRecoveryProbe,
    WorkspaceRootRecoveryProbeRequest, WorkspaceRootRecoveryReadbackRequest,
};
use crate::writer_lease::{
    WriterLeaseAcquireRequest, WriterLeaseGetRequest, WriterLeaseListPage, WriterLeaseListRequest,
    WriterLeaseRecoveryReleaseRequest, WriterLeaseReleaseRequest, WriterLeaseRenewRequest,
};
use crate::{
    AgentBindingActivateRequest, AgentBindingActivationReadRequest, AgentBindingRejectRequest,
    AgentBindingRejectionReadRequest, AgentBindingReservationReadRequest,
    AgentBindingReserveRequest, AgentEffectOutboxReadRequest, AgentOperationsDelegationReadRequest,
    AgentOperationsDelegationRequest,
};

use crate::{
    AgentDepartureReconcileReadRequest, AgentDepartureReconcileRequest,
    AgentSessionReconcileReadRequest, AgentSessionReconcileRequest,
};

use crate::EffectFactOutboxReadRequest;

/// Bounded admission capacity for the single-owner control worker.
/// Temporary INC-001 mitigation; the root-cause isolation work remains required.
pub const CONTROL_QUEUE_CAPACITY: usize = 128;

/// Bounded admission capacity for the dedicated Activity lease worker.
///
/// Lease heartbeats and graceful close operations use a separate worker and
/// queue so a long-running general control request cannot starve liveness.
/// The queue remains deliberately small: callers must treat a full queue as a
/// bounded failure and enter the existing recovery path.
pub const ACTIVITY_LEASE_QUEUE_CAPACITY: usize = 4;

/// Maximum caller-owned Activities accepted by one graceful shutdown request.
pub const MAX_SHUTDOWN_ACTIVITIES: usize = 256;

const WORKER_THREAD_NAME: &str = "heterarchy-forge-control";
const ACTIVITY_LEASE_WORKER_THREAD_NAME: &str = "heterarchy-forge-activity-lease";
const MIN_APPROVAL_WINDOW_MILLIS: i64 = 1_000;
const MAX_APPROVAL_WINDOW_MILLIS: i64 = 60 * 60 * 1_000;

type Response<T> = SyncSender<Result<T, ControlError>>;

fn send_response<T>(response: &Response<T>, result: Result<T, ControlError>) {
    let _ignored = response.send(result);
}

/// Internal requests accepted by [`ForgeControlWorker`].
///
/// Adapters use the typed [`ForgeControlClient`] methods; the raw worker
/// channel is crate-private so internal response types never become API.
#[derive(Debug)]
pub(crate) enum ForgeControlRequest {
    LeadershipWorkCut {
        command: Box<crate::WorkCutCommand>,
        response: Response<crate::WorkCutResponse>,
    },
    GoalDeletePending {
        scope: ResolvedWorkspaceScope,
        limit: u32,
        response: Response<forge_persistence::GoalDeletionPendingInventory>,
    },
    GoalDelete {
        request: crate::GoalDeleteRequest,
        product_cache_root: Option<std::path::PathBuf>,
        response: Response<crate::GoalDeleteOutcome>,
    },
    AgentAssignmentMutate {
        request: crate::AgentAssignmentMutationRequest,
        response: Response<forge_domain::RegisteredAgentAssignment>,
    },
    AgentAssignmentOfferSeal {
        request: crate::AgentAssignmentOfferSealRequest,
        response: Response<forge_persistence::AgentAssignmentOfferSealSnapshot>,
    },
    AgentAssignmentOfferSealGet {
        request: crate::AgentAssignmentOfferSealRequest,
        response: Response<Option<forge_persistence::AgentAssignmentOfferSealSnapshot>>,
    },
    AgentAssignmentGet {
        request: crate::AgentAssignmentGetRequest,
        response: Response<Option<forge_domain::RegisteredAgentAssignment>>,
    },
    AgentAssignmentList {
        request: crate::AgentAssignmentListRequest,
        response: Response<Vec<forge_domain::AgentAssignmentSummary>>,
    },
    ActivitySuccessorCreate {
        request: ActivitySuccessorCreateRequest,
        response: Response<forge_domain::ActivitySuccessorResult>,
    },
    ActivitySuccessorGet {
        scope: ResolvedWorkspaceScope,
        predecessor_activity_id: ActivityId,
        response: Response<
            Option<(
                forge_domain::ActivitySuccessor,
                forge_domain::RegisteredActivity,
            )>,
        >,
    },
    ExpiredActivityRecoveryProbe {
        request: ExpiredActivityRecoveryProbeRequest,
        response: Response<forge_domain::ExpiredActivityRecoveryProbe>,
    },
    ExpiredActivityRecoveryRun {
        request: DurableExpiredActivityRecoveryRequest,
        response: Response<ExpiredActivityRecoveryReport>,
    },
    ExpiredActivityRecoveryGet {
        request: ExpiredActivityRecoveryGetRequest,
        response: Response<Option<forge_persistence::ExpiredActivityRecoveryReadback>>,
    },
    UnstartedActivityContinuationProbe {
        request: UnstartedActivityContinuationProbeRequest,
        response: Response<forge_domain::UnstartedActivityContinuationProbe>,
    },
    UnstartedActivityContinuationRun {
        request: DurableUnstartedActivityContinuationRequest,
        response: Response<UnstartedActivityContinuationReport>,
    },
    UnstartedActivityContinuationGet {
        request: UnstartedActivityContinuationGetRequest,
        response: Response<Option<forge_persistence::UnstartedActivityContinuationReadback>>,
    },
    StartedActivityLeaseResumeProbe {
        request: StartedActivityLeaseResumeProbeRequest,
        response: Response<forge_domain::StartedActivityLeaseResumeProbe>,
    },
    StartedActivityLeaseResumeRun {
        request: StartedActivityLeaseResumeRunRequest,
        response: Response<forge_domain::StartedActivityLeaseResumeOperation>,
    },
    StartedActivityLeaseResumeGet {
        request: StartedActivityLeaseResumeGetRequest,
        response: Response<Option<forge_persistence::StartedActivityLeaseResumeReadback>>,
    },
    QuiescentActivityLeaseResumeProbe {
        request: QuiescentActivityLeaseResumeProbeRequest,
        response: Response<forge_domain::QuiescentActivityLeaseResumeProbe>,
    },
    QuiescentActivityLeaseResumeRun {
        request: QuiescentActivityLeaseResumeRunRequest,
        response: Response<forge_domain::QuiescentActivityLeaseResumeOperation>,
    },
    QuiescentActivityLeaseResumeGet {
        request: QuiescentActivityLeaseResumeGetRequest,
        response: Response<Option<forge_persistence::QuiescentActivityLeaseResumeReadback>>,
    },
    AgentCoordinationView {
        request: AgentCoordinationQuery,
        response: Response<AgentCoordinationView>,
    },
    AgentInboxList {
        request: AgentInboxListRequest,
        response: Response<Vec<forge_domain::InboxEntry>>,
    },
    AgentSessionOpen {
        request: forge_domain::OpenAgentSession,
        response: Response<forge_domain::AgentSessionOpenOutcome>,
    },
    AgentBindingReserve {
        request: AgentBindingReserveRequest,
        response: Response<forge_persistence::AgentBindingReservation>,
    },
    AgentBindingReserveReference {
        request: AgentBindingReserveReferenceRequest,
        response: Response<forge_persistence::AgentBindingReservation>,
    },
    AgentBindingReservationRead {
        request: AgentBindingReservationReadRequest,
        response: Response<Option<forge_persistence::AgentBindingReservation>>,
    },
    AgentOperationsDelegation {
        request: AgentOperationsDelegationRequest,
        response: Response<forge_persistence::AgentOperationsDelegation>,
    },
    AgentOperationsDelegationReference {
        request: AgentOperationsDelegateReferenceRequest,
        response: Response<forge_persistence::AgentOperationsDelegation>,
    },
    AgentOperationsDelegationRead {
        request: AgentOperationsDelegationReadRequest,
        response: Response<Option<forge_persistence::AgentOperationsDelegation>>,
    },
    AgentOperationsFreeze {
        request: AgentOperationsFreezeRequest,
        response: Response<forge_persistence::AgentOperationsFreeze>,
    },
    AgentOperationsFreezeRead {
        request: AgentOperationsFreezeReadRequest,
        response: Response<Option<forge_persistence::AgentOperationsFreeze>>,
    },
    AgentOperationsExport {
        request: AgentOperationsExportRequest,
        response: Response<forge_persistence::AgentOperationsExportPage>,
    },
    AgentOperationsFreezeRelease {
        request: AgentOperationsFreezeReleaseRequest,
        response: Response<forge_persistence::AgentOperationsFreeze>,
    },
    AgentBindingActivate {
        request: AgentBindingActivateRequest,
        response: Response<forge_persistence::AgentBindingActivation>,
    },
    AgentBindingActivateReference {
        request: AgentBindingActivateReferenceRequest,
        response: Response<forge_persistence::AgentBindingActivation>,
    },
    AgentBindingActivationRead {
        request: AgentBindingActivationReadRequest,
        response: Response<Option<forge_persistence::AgentBindingActivation>>,
    },
    AgentBindingReject {
        request: AgentBindingRejectRequest,
        response: Response<forge_persistence::AgentBindingRejectionOperation>,
    },
    AgentBindingRejectionRead {
        request: AgentBindingRejectionReadRequest,
        response: Response<Option<forge_persistence::AgentBindingRejectionReceipt>>,
    },
    AgentSessionReconcile {
        request: AgentSessionReconcileRequest,
        response: Response<forge_persistence::AgentSessionReconciliation>,
    },
    AgentSessionReconcileDestination {
        request: AgentSessionReconcileDestinationRequest,
        response: Response<forge_persistence::AgentSessionReconciliation>,
    },
    AgentSessionReconciliationRead {
        request: AgentSessionReconcileReadRequest,
        response: Response<Option<forge_persistence::AgentSessionReconciliation>>,
    },
    AgentDepartureReconcile {
        request: AgentDepartureReconcileRequest,
        response: Response<forge_persistence::AgentDepartureReconciliation>,
    },
    AgentDepartureReconcileDestination {
        request: AgentDepartureReconcileDestinationRequest,
        response: Response<forge_persistence::AgentDepartureReconciliation>,
    },
    AgentDepartureReconciliationRead {
        request: AgentDepartureReconcileReadRequest,
        response: Response<Option<forge_persistence::AgentDepartureReconciliation>>,
    },
    AgentEffectOutboxRead {
        request: AgentEffectOutboxReadRequest,
        response: Response<Vec<forge_persistence::AgentEffectOutboxEntry>>,
    },
    EffectFactOutboxRead {
        request: EffectFactOutboxReadRequest,
        response: Response<Vec<forge_persistence::EffectFactOutboxEntry>>,
    },
    SemanticEventsPage {
        request: crate::semantic_projection::SemanticEventsPageRequest,
        response: Response<crate::semantic_projection::SemanticEventsPageResult>,
    },
    WorkspaceSemanticSnapshot {
        request: crate::semantic_projection::WorkspaceSemanticSnapshotRequest,
        response: Response<crate::semantic_projection::WorkspaceSemanticSnapshotResult>,
    },
    AgentSessionResolve {
        request: AgentSessionResolveRequest,
        response: Response<forge_domain::RegisteredAgentSession>,
    },
    AgentSessionProve {
        request: AgentSessionProofRequest,
        response: Response<forge_domain::RegisteredAgentInstance>,
    },
    LocationList {
        response: Response<Vec<RegisteredLocation>>,
    },
    LocationRemovalProbe {
        id: LocationId,
        response: Response<crate::LocationRemovalProbe>,
    },
    LocationRemove {
        request: crate::LocationRemovalRequest,
        response: Response<crate::WorkspaceRemovalOutcome>,
    },
    RegisterLocation {
        request: RegisterLocationRequest,
        response: Response<RegisteredLocation>,
    },
    RegisterWorkspace {
        request: crate::WorkspaceRegistrationRequest,
        response: Response<crate::WorkspaceRegistrationOutcome>,
    },
    ProbeWorkspaceRegistration {
        locator: WorkspaceLocator,
        response: Response<crate::WorkspaceRegistrationProbe>,
    },
    WorkspaceRootRecoveryProbe {
        request: WorkspaceRootRecoveryProbeRequest,
        response: Response<WorkspaceRootRecoveryProbe>,
    },
    WorkspaceRootRecoveryPrepare {
        request: WorkspaceRootRecoveryPrepareRequest,
        response: Response<WorkspaceRootRecoveryProbe>,
    },
    WorkspaceRootRecoveryCommit {
        request: WorkspaceRootRecoveryCommitRequest,
        response: Response<WorkspaceRootRecoveryCommitOutcome>,
    },
    WorkspaceRootRecoveryReadback {
        request: WorkspaceRootRecoveryReadbackRequest,
        response: Response<Option<forge_persistence::RootRecoveryReceipt>>,
    },
    WorkspaceInventory {
        location_id: LocationId,
        expected_revision: LocationRevision,
        response: Response<crate::WorkspaceInventory>,
    },
    SetLocationState {
        command: SetLocationState,
        response: Response<RegisteredLocation>,
    },
    WorkspaceList {
        location_id: LocationId,
        expected_revision: LocationRevision,
        response: Response<Vec<WorkspaceCatalogEntry>>,
    },
    WorkspaceDiscover {
        location_id: LocationId,
        expected_revision: LocationRevision,
        response: Response<Vec<WorkspaceDiscoveryEntry>>,
    },
    ResolveWorkspace {
        location_id: LocationId,
        expected_revision: LocationRevision,
        locator: WorkspaceLocator,
        response: Response<ResolvedWorkspaceScope>,
    },
    /// Internal durable Activity admission used by transport scope resolvers.
    /// It is not part of any public tool surface.
    AuthorizeActivity {
        scope: ResolvedWorkspaceScope,
        activity: FileActivityScope,
        response: Response<()>,
    },
    WorkspaceDoctor {
        request: WorkspaceDoctorRequest,
        response: Response<WorkspaceDoctorResult>,
    },
    WorkspaceIdentityDoctor {
        response: Response<WorkspaceIdentityDoctorReport>,
    },
    BootstrapActivity {
        scope: ResolvedWorkspaceScope,
        caller_activity_id: ActivityId,
        runtime_instance_id: RuntimeInstanceId,
        observed_at: TimestampMillis,
        lease_until: TimestampMillis,
        response: Response<ActivityBootstrap>,
    },
    RenewActivityLease {
        scope: ResolvedWorkspaceScope,
        activity_id: ActivityId,
        runtime_instance_id: RuntimeInstanceId,
        expected_lease_revision: ActivityLeaseRevision,
        observed_at: TimestampMillis,
        lease_until: TimestampMillis,
        response: Response<ActivityLeaseOperation>,
    },
    RenewActivityLeaseBatch {
        scope: ResolvedWorkspaceScope,
        commands: Vec<RenewActivityLease>,
        response: Response<ActivityLeaseOperation>,
    },
    SupervisedActivityLeaseRenew {
        request: SupervisedActivityLeaseRenewRequest,
        response: Response<ActivityLeaseOperation>,
    },
    CloseActivity {
        scope: ResolvedWorkspaceScope,
        activity_id: ActivityId,
        runtime_instance_id: RuntimeInstanceId,
        expected_lease_revision: ActivityLeaseRevision,
        response: Response<ActivityLeaseOperation>,
    },
    CloseOwnedActivityBatch {
        scope: ResolvedWorkspaceScope,
        commands: Vec<CloseActivity>,
        response: Response<ActivityLeaseOperation>,
    },
    ReleaseActivityLease {
        scope: ResolvedWorkspaceScope,
        activity_id: ActivityId,
        runtime_instance_id: RuntimeInstanceId,
        expected_lease_revision: ActivityLeaseRevision,
        response: Response<ActivityLeaseOperation>,
    },
    ReleaseActivityLeaseBatch {
        scope: ResolvedWorkspaceScope,
        commands: Vec<ReleaseActivityLease>,
        response: Response<ActivityLeaseOperation>,
    },
    ObserveActivityLeases {
        scope: ResolvedWorkspaceScope,
        activity_ids: Vec<ActivityId>,
        response: Response<Vec<RegisteredActivity>>,
    },
    ReconcileExpiredActivityLeases {
        scope: ResolvedWorkspaceScope,
        observed_at: TimestampMillis,
        limit: ActivityListLimit,
        response: Response<ActivityLeaseOperation>,
    },
    ListActivityProjections {
        scope: ResolvedWorkspaceScope,
        now: TimestampMillis,
        limit: ActivityListLimit,
        response: Response<Vec<ActivityProjection>>,
    },
    ListWorkspaceActivityProjections {
        request: WorkspaceActivityProjectionRequest,
        response: Response<WorkspaceActivityProjection>,
    },
    ActivityRead {
        request: ActivityReadRequest,
        response: Response<ActivityReadSnapshot>,
    },
    AgentSetFocus {
        request: AgentFocusRequest,
        response: Response<forge_domain::RegisteredAgentInstance>,
    },
    AgentPublishWorkUpdate {
        request: AgentWorkUpdateRequest,
        response: Response<forge_domain::AgentWorkUpdate>,
    },
    AgentList {
        request: AgentListRequest,
        response: Response<Vec<forge_domain::AgentAttachmentProjection>>,
    },
    AgentGetContext {
        request: AgentContextRequest,
        response: Response<Option<forge_domain::AgentContextProjection>>,
    },
    WriterLeaseAcquire {
        request: WriterLeaseAcquireRequest,
        response: Response<forge_domain::WriterLease>,
    },
    WriterLeaseRenew {
        request: WriterLeaseRenewRequest,
        response: Response<forge_domain::WriterLease>,
    },
    WriterLeaseRelease {
        request: WriterLeaseReleaseRequest,
        response: Response<forge_domain::WriterLease>,
    },
    WriterLeaseGet {
        request: WriterLeaseGetRequest,
        response: Response<
            Option<(
                forge_domain::WriterLease,
                Option<forge_domain::AgentSessionId>,
            )>,
        >,
    },
    WriterLeaseList {
        request: WriterLeaseListRequest,
        response: Response<WriterLeaseListPage>,
    },
    WriterLeaseRecoveryRelease {
        request: WriterLeaseRecoveryReleaseRequest,
        response: Response<forge_domain::WriterLease>,
    },
    CoordinatorActor {
        request: crate::CoordinatorActorRequest,
        response: Response<Option<forge_domain::ActivityCoordinatorActor>>,
    },
    CoordinatorGet {
        request: CoordinatorGetRequest,
        response: Response<Option<forge_domain::ActivityCoordinatorBinding>>,
    },
    CoordinatorClaim {
        request: CoordinatorClaimRequest,
        response: Response<forge_domain::ActivityCoordinatorBinding>,
    },
    CoordinatorTransfer {
        request: CoordinatorTransferRequest,
        response: Response<forge_domain::ActivityCoordinatorBinding>,
    },
    CoordinatorRecoveryPrepare {
        request: CoordinatorRecoveryPrepareRequest,
        response: Response<forge_domain::CoordinatorRecoveryFence>,
    },
    CoordinatorRecoveryConfirm {
        request: CoordinatorRecoveryConfirmRequest,
        response: Response<forge_domain::CoordinatorRecoveryReceipt>,
    },
    CoordinatorRecoveryReceipt {
        request: CoordinatorRecoveryReadRequest,
        response: Response<Option<forge_domain::CoordinatorRecoveryReceipt>>,
    },
    CoordinatorRecoveryHistory {
        request: CoordinatorRecoveryHistoryRequest,
        response: Response<Vec<forge_domain::CoordinatorRecoveryReceipt>>,
    },
    AgentDagPlanCommit {
        request: AgentDagPlanCommitRequest,
        response: Response<forge_persistence::AgentDagPlanCommitResult>,
    },
    AgentVerifyExecutionAuthority {
        request: AgentExecutionAuthorityRequest,
        response: Response<()>,
    },
    ProjectCommandResolve {
        request: ProjectCommandListRequest,
        command_id: crate::ProjectCommandId,
        expected_fingerprint: forge_domain::ProjectCommandCatalogFingerprint,
        execution_id: ExecutionId,
        response: Response<crate::ResolvedProjectCommandExecution>,
    },
    ProjectCommandPrepareVerification {
        request: ProjectCommandListRequest,
        command_id: crate::ProjectCommandId,
        expected_fingerprint: forge_domain::ProjectCommandCatalogFingerprint,
        execution_id: ExecutionId,
        cancellation: Arc<AtomicBool>,
        response: Response<PreparedProjectCommandVerification>,
    },
    WorkspaceVerificationPrepare {
        scope: ResolvedWorkspaceScope,
        activity: crate::FileActivityScope,
        input_id: forge_domain::VerificationInputId,
        cancellation: Arc<AtomicBool>,
        response: Response<forge_workspace::PublishedVerificationInput>,
    },
    ProjectCommandList {
        request: ProjectCommandListRequest,
        response: Response<ProjectCommandListResult>,
    },
    GeneratedArtifactInventory {
        scope: ResolvedWorkspaceScope,
        cache_root: std::path::PathBuf,
        limit: crate::GeneratedArtifactInventoryLimit,
        response: Response<crate::GeneratedArtifactInventory>,
    },
    GeneratedPackageAccess {
        scope: ResolvedWorkspaceScope,
        cache_root: std::path::PathBuf,
        execution_id: ExecutionId,
        response: Response<Option<std::path::PathBuf>>,
    },
    FileRead {
        request: FileReadRequest,
        response: Response<FileReadResult>,
    },
    FileList {
        request: FileListRequest,
        response: Response<FileListResult>,
    },
    TextSearch {
        request: TextSearchRequest,
        response: Response<TextSearchResult>,
    },
    FileMutationReadback {
        request: crate::FileMutationReadbackRequest,
        response: Response<Option<forge_persistence::FileMutationReadSnapshot>>,
    },
    SourceTreeReadback {
        request: crate::SourceTreeReadbackRequest,
        response: Response<Option<forge_persistence::SourceTreeReadSnapshot>>,
    },
    GoalMutation {
        request: Box<crate::GoalMutationRequest>,
        response: Response<forge_persistence::GoalMutationResult>,
    },
    GoalMutationReadback {
        request: crate::GoalMutationReadbackRequest,
        response: Response<Option<forge_domain::GoalMutationReceipt>>,
    },
    DagPlanReadback {
        request: crate::DagPlanReadbackRequest,
        response: Response<Option<forge_persistence::AgentDagPlanRecord>>,
    },
    FileReadSlice {
        request: FileReadSliceRequest,
        response: Response<FileReadSliceResult>,
    },
    FileApplyPatch {
        request: FileApplyPatchRequest,
        response: Response<FileApplyPatchResult>,
    },
    SourceTreeApply {
        request: SourceTreeTransactionRequest,
        response: Response<SourceTreeTransactionResult>,
    },
    FileImportBinary {
        request: FileMutationRequest,
        response: Response<FileMutationResult>,
        _permit: BinaryImportPermit,
    },
    FileMutate {
        request: FileMutationRequest,
        response: Response<FileMutationResult>,
    },
    ExecutionMarkRunning {
        scope: ResolvedWorkspaceScope,
        command: MarkExecutionRunning,
        response: Response<RegisteredExecution>,
    },
    ExecutionCompleteGenerated {
        scope: ResolvedWorkspaceScope,
        command: CompleteExecution,
        manifest: forge_domain::GeneratedPackageManifest,
        response: Response<RegisteredExecution>,
    },
    ExecutionComplete {
        scope: ResolvedWorkspaceScope,
        command: CompleteExecution,
        response: Response<RegisteredExecution>,
    },
    ExecutionJournalOutput {
        authority: crate::execution_journal::ExecutionJournalAuthority,
        events: Vec<ExecutionOutputEvent>,
        response: Response<()>,
    },
    ExecutionJournalComplete {
        authority: crate::execution_journal::ExecutionJournalAuthority,
        command: CompleteExecution,
        closure: Option<forge_domain::ExecutionNativeClosureFact>,
        response: Response<RegisteredExecution>,
    },
    ExecutionJournalCompleteGenerated {
        authority: crate::execution_journal::ExecutionJournalAuthority,
        command: CompleteExecution,
        manifest: forge_domain::GeneratedPackageManifest,
        closure: Option<forge_domain::ExecutionNativeClosureFact>,
        response: Response<RegisteredExecution>,
    },
    ExecutionJournalFail {
        authority: crate::execution_journal::ExecutionJournalAuthority,
        command: FailExecution,
        closure: Option<forge_domain::ExecutionNativeClosureFact>,
        response: Response<RegisteredExecution>,
    },
    ExecutionJournalReconcileOutput {
        authority: crate::execution_journal::ExecutionJournalAuthority,
        before: RegisteredExecution,
        events: Vec<ExecutionOutputEvent>,
        response: Response<crate::execution_journal::JournalReadback>,
    },
    ExecutionJournalReconcileTerminal {
        authority: crate::execution_journal::ExecutionJournalAuthority,
        before: RegisteredExecution,
        command: Box<crate::execution_journal::JournalTerminalCommand>,
        closure: Option<forge_domain::ExecutionNativeClosureFact>,
        response: Response<crate::execution_journal::JournalReadback>,
    },
    ExecutionFail {
        scope: ResolvedWorkspaceScope,
        command: FailExecution,
        response: Response<RegisteredExecution>,
    },
    ExecutionReconcile {
        scope: ResolvedWorkspaceScope,
        observed_at: TimestampMillis,
        limit: ExecutionListLimit,
        response: Response<Vec<RegisteredExecution>>,
    },
    ExecutionGet {
        scope: ResolvedWorkspaceScope,
        id: ExecutionId,
        response: Response<Option<RegisteredExecution>>,
    },
    VerificationProjection {
        scope: ResolvedWorkspaceScope,
        response: Response<VerificationProjection>,
    },
    ExecutionEvidenceInventory {
        scope: ResolvedWorkspaceScope,
        selection: forge_domain::ExecutionObservationSelection,
        limit: ExecutionListLimit,
        response: Response<forge_persistence::ExecutionEvidenceInventory>,
    },
    ExecutionEvidenceRead {
        scope: ResolvedWorkspaceScope,
        selection: forge_domain::ExecutionObservationSelection,
        id: ExecutionId,
        cursor: ExecutionOutputCursor,
        max_bytes: u64,
        max_events: usize,
        response: Response<forge_persistence::ExecutionEvidenceRead>,
    },
    ExecutionGeneratedPackage {
        scope: ResolvedWorkspaceScope,
        id: ExecutionId,
        response: Response<Option<forge_domain::GeneratedPackageManifest>>,
    },
    ExecutionGetEvidence {
        request: AgentExecutionAuthorityRequest,
        id: ExecutionId,
        response: Response<forge_persistence::AuthorizedExecutionSnapshot>,
    },
    ExecutionGetAuthorized {
        request: AgentExecutionAuthorityRequest,
        id: ExecutionId,
        response: Response<RegisteredExecution>,
    },
    ExecutionList {
        scope: ResolvedWorkspaceScope,
        activity_id: ActivityId,
        limit: ExecutionListLimit,
        response: Response<Vec<RegisteredExecution>>,
    },
    ExecutionOutputAppendBatch {
        scope: ResolvedWorkspaceScope,
        events: Vec<ExecutionOutputEvent>,
        response: Response<()>,
    },
    ExecutionOutputRead {
        scope: ResolvedWorkspaceScope,
        cursor: ExecutionOutputCursor,
        max_bytes: u64,
        max_events: usize,
        response: Response<ExecutionOutputRead>,
    },
    ExecutionOutputReadAuthorized {
        request: AgentExecutionAuthorityRequest,
        id: ExecutionId,
        cursor: ExecutionOutputCursor,
        max_bytes: u64,
        max_events: usize,
        response: Response<ExecutionOutputRead>,
    },
    ExecutionReadAuthorized {
        request: AgentExecutionAuthorityRequest,
        id: ExecutionId,
        cursor: ExecutionOutputCursor,
        max_bytes: u64,
        max_events: usize,
        response: Response<AuthorizedExecutionRead>,
    },
    GoalCreate {
        scope: ResolvedWorkspaceScope,
        actor: ActivityCoordinatorActor,
        goal: RegisteredGoal,
        response: Response<RegisteredGoal>,
    },
    GoalGet {
        scope: ResolvedWorkspaceScope,
        activity_id: ActivityId,
        goal_id: GoalId,
        response: Response<Option<RegisteredGoal>>,
    },
    GoalList {
        scope: ResolvedWorkspaceScope,
        activity_id: ActivityId,
        limit: GoalListLimit,
        response: Response<Vec<RegisteredGoal>>,
    },
    GoalReviseContract {
        request: GoalContractRevisionRequest,
        response: Response<RegisteredGoal>,
    },
    GoalTransition {
        request: GoalLifecycleRequest,
        response: Response<RegisteredGoal>,
    },
    GoalReview {
        scope: ResolvedWorkspaceScope,
        activity_id: ActivityId,
        goal_id: GoalId,
        response: Response<GoalReview>,
    },
    GoalComplete {
        request: GoalCompletionRequest,
        response: Response<RegisteredGoal>,
    },
    DagGetCurrent {
        scope: ResolvedWorkspaceScope,
        goal_id: GoalId,
        response: Response<Option<StoredDagRevision>>,
    },
    DagNodeAssignmentSnapshot {
        scope: ResolvedWorkspaceScope,
        node_scope: DagNodeEvidenceScope,
        response: Response<Option<DagNodeAssignmentSnapshot>>,
    },
    DagGetRevision {
        scope: ResolvedWorkspaceScope,
        goal_id: GoalId,
        number: DagRevisionNumber,
        response: Response<Option<StoredDagRevision>>,
    },
    DagNodeStart {
        request: DagNodeStartRequest,
        response: Response<RegisteredDagNode>,
    },
    DagNodeComplete {
        request: DagNodeCompleteRequest,
        response: Response<RegisteredDagNode>,
    },
    DagNodeUpdate {
        request: DagNodeUpdateRequest,
        response: Response<RegisteredDagNode>,
    },
    RecoveryLeaseGet {
        scope: ResolvedWorkspaceScope,
        response: Response<RecoveryMaintenanceLease>,
    },
    RecoveryLeaseClaim {
        scope: ResolvedWorkspaceScope,
        command: ClaimRecoveryLease,
        response: Response<RecoveryLeaseClaimOperation>,
    },
    RecoveryLeaseRenew {
        scope: ResolvedWorkspaceScope,
        command: RenewRecoveryLease,
        response: Response<RecoveryMaintenanceLease>,
    },
    RecoveryLeaseRelease {
        scope: ResolvedWorkspaceScope,
        command: ReleaseRecoveryLease,
        response: Response<RecoveryMaintenanceLease>,
    },
    RecoveryMaintenanceRun {
        request: RecoveryMaintenanceRequest,
        response: Response<RecoveryMaintenanceReport>,
    },
    RecoveryMaintenanceDurable {
        request: crate::DurableRecoveryMaintenanceRequest,
        response: Response<RecoveryMaintenanceReport>,
    },
    RecoveryMaintenanceGet {
        scope: ResolvedWorkspaceScope,
        request_id: uuid::Uuid,
        request_digest: [u8; 32],
        response: Response<Option<forge_persistence::RecoveryRunReceipt>>,
    },
    CheckpointRestoreRun {
        request: CheckpointRestoreRequest,
        response: Response<CheckpointRestoreOutcome>,
    },
    EnsureWorkspacePolicy {
        scope: ResolvedWorkspaceScope,
        response: Response<WorkspacePolicy>,
    },
    GetWorkspacePolicy {
        scope: ResolvedWorkspaceScope,
        response: Response<Option<WorkspacePolicy>>,
    },
    WorkspaceQueueSettingsGet {
        scope: ResolvedWorkspaceScope,
        response: Response<Option<forge_persistence::RegisteredQueueSettings>>,
    },
    WorkspaceQueueSettingsReplace {
        request: WorkspaceQueueSettingsRequest,
        response: Response<forge_persistence::RegisteredQueueSettings>,
    },
    ReplaceWorkspacePolicy {
        request: WorkspacePolicyReplaceRequest,
        response: Response<WorkspacePolicy>,
    },
    ApprovalCreate {
        request: ApprovalCreateRequest,
        response: Response<RegisteredApprovalRequest>,
    },
    ApprovalListPending {
        scope: ResolvedWorkspaceScope,
        limit: ExecutionListLimit,
        response: Response<Vec<RegisteredApprovalRequest>>,
    },
    ApprovalGet {
        scope: ResolvedWorkspaceScope,
        approval_id: ApprovalRequestId,
        response: Response<Option<(RegisteredApprovalRequest, Option<RegisteredExecution>)>>,
    },
    ApprovalGetWithGrant {
        scope: ResolvedWorkspaceScope,
        approval_id: ApprovalRequestId,
        response: Response<ApprovalExecutionGrantReadback>,
    },
    ApprovalApproveOnce {
        request: ApprovalOnceRequest,
        response: Response<(RegisteredApprovalRequest, ExecutionGrant)>,
    },
    ApprovalDecide {
        request: ApprovalDecisionRequest,
        response: Response<RegisteredApprovalRequest>,
    },
    AutoApprovalScopeCreate {
        request: AutoApprovalScopeCreateRequest,
        response: Response<AutoApprovalScope>,
    },
    AutoApprovalScopeRevoke {
        request: AutoApprovalScopeRevokeRequest,
        response: Response<AutoApprovalScope>,
    },
    AutoApprovalScopeGet {
        scope: ResolvedWorkspaceScope,
        id: AutoApprovalScopeId,
        response: Response<Option<AutoApprovalScope>>,
    },
    ApprovalGrantConsume {
        request: ApprovalGrantConsumeRequest,
        response: Response<ApprovalGrantConsumeResult>,
    },
    AutoApprovalConsume {
        request: AutoApprovalConsumeRequest,
        response: Response<AutoApprovalConsumeResult>,
    },
    ApprovalCleanupPermitMint {
        owner: ApprovalCleanupOwner,
        scope: ResolvedWorkspaceScope,
        selector: ApprovalCleanupSelector,
        response: Response<ApprovalCleanupPermit>,
    },
    ApprovalCleanupPrepare {
        permit: ApprovalCleanupPermit,
        owner: ApprovalCleanupOwner,
        selector: ApprovalCleanupSelector,
        observed_at: TimestampMillis,
        limit: ExecutionListLimit,
        response: Response<ApprovalCleanupPlan>,
    },
    ApprovalCleanupApply {
        owner: ApprovalCleanupOwner,
        plan: ApprovalCleanupPlan,
        attempt: ApprovalCleanupAttemptId,
        response: Response<ApprovalCleanupApplyOutcome>,
    },
    ApprovalCleanupObserve {
        owner: ApprovalCleanupOwner,
        plan: ApprovalCleanupPlan,
        response: Response<ApprovalCleanupReadback>,
    },
    ApprovalExpiryPrepare {
        scope: ResolvedWorkspaceScope,
        observed_at: TimestampMillis,
        limit: ExecutionListLimit,
        response: Response<ApprovalExpiryPlan>,
    },
    ExecutionStopPrepare {
        scope: ResolvedWorkspaceScope,
        request: forge_persistence::ExecutionStopRequest,
        response: Response<ExecutionStopContext>,
    },
    ExecutionStopApply {
        context: ExecutionStopContext,
        response: Response<forge_persistence::ExecutionStopCapture>,
    },
    ExecutionStopObserve {
        context: ExecutionStopContext,
        response: Response<Option<forge_persistence::ExecutionStopRecord>>,
    },
    OwnedExecutionStopHistory {
        permit: ApprovalCleanupPermit,
        owner: ApprovalCleanupOwner,
        request: forge_persistence::ExecutionStopRequest,
        response: Response<
            Option<(
                forge_persistence::ExecutionStopRecord,
                forge_persistence::AuthorityStopReceipt,
            )>,
        >,
    },
    OwnedExecutionStopSettle {
        settlement: Box<crate::execution_stop::owned::OwnedExecutionStopSettlement>,
        response: Response<(
            forge_persistence::ExecutionStopRecord,
            forge_persistence::AuthorityStopReceipt,
        )>,
    },
    OwnedExecutionStopPrepare {
        permit: ApprovalCleanupPermit,
        owner: ApprovalCleanupOwner,
        request: forge_persistence::ExecutionStopRequest,
        response: Response<crate::execution_stop::owned::OwnedExecutionStopContext>,
    },
    OwnedExecutionStopApply {
        context: crate::execution_stop::owned::OwnedExecutionStopContext,
        response: Response<forge_persistence::OwnedWorkspaceStopCapture>,
    },
    OwnedExecutionStopObserve {
        context: crate::execution_stop::owned::OwnedExecutionStopContext,
        response: Response<
            Option<(
                forge_persistence::ExecutionStopRecord,
                forge_persistence::AuthorityStopReceipt,
            )>,
        >,
    },
    ApprovalExpiryApply {
        plan: ApprovalExpiryPlan,
        attempt: ApprovalCleanupAttemptId,
        response: Response<ApprovalCleanupApplyOutcome>,
    },
    ApprovalExpiryObserve {
        plan: ApprovalExpiryPlan,
        response: Response<ApprovalCleanupReadback>,
    },
    DiffList {
        request: DiffListRequest,
        response: Response<DiffListResult>,
    },
    DiffRead {
        request: DiffReadRequest,
        response: Response<DiffReadResult>,
    },
    DiffDoctor {
        request: DiffDoctorRequest,
        response: Response<DiffDoctorResult>,
    },
    DiffRetentionPlan {
        request: DiffRetentionPlanRequest,
        response: Response<DiffRetentionPlanResult>,
    },
    DiffPurge {
        request: DiffPurgeRequest,
        response: Response<DiffPurgeResult>,
    },
    DiffArtifactDoctor {
        request: DiffArtifactDoctorRequest,
        response: Response<DiffArtifactDoctorResult>,
    },
    DeleteOrphanDiffArtifact {
        request: DeleteOrphanDiffArtifactRequest,
        response: Response<DeleteOrphanDiffArtifactResult>,
    },
    Shutdown {
        owned_activities: Vec<OwnedActivityLease>,
        response: Option<SyncSender<ShutdownReport>>,
    },
}

/// Redacted, bounded outcome of graceful owned-Activity shutdown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShutdownReport {
    attempted: usize,
    closed: usize,
    committed_but_unconfirmed: usize,
    failures: Vec<crate::ControlErrorView>,
}

impl ShutdownReport {
    fn empty() -> Self {
        Self {
            attempted: 0,
            closed: 0,
            committed_but_unconfirmed: 0,
            failures: Vec::new(),
        }
    }

    pub const fn attempted(&self) -> usize {
        self.attempted
    }

    pub const fn closed(&self) -> usize {
        self.closed
    }

    pub const fn committed_but_unconfirmed(&self) -> usize {
        self.committed_but_unconfirmed
    }

    pub fn failures(&self) -> &[crate::ControlErrorView] {
        &self.failures
    }
}

/// Client-side admission/response error for the bounded worker.
#[derive(Debug)]
pub enum ControlClientError {
    QueueFull,
    WorkerClosed,
    WorkerShuttingDown,
    ResponseDropped,
    Service(ControlError),
}

impl ControlClientError {
    pub const fn code(&self) -> ControlErrorCode {
        match self {
            Self::QueueFull => ControlErrorCode::CapacityExceeded,
            Self::WorkerClosed | Self::ResponseDropped => ControlErrorCode::WorkerClosed,
            Self::WorkerShuttingDown => ControlErrorCode::WorkerShuttingDown,
            Self::Service(error) => error.code(),
        }
    }

    pub const fn service_error(&self) -> Option<&ControlError> {
        match self {
            Self::Service(error) => Some(error),
            Self::QueueFull
            | Self::WorkerClosed
            | Self::WorkerShuttingDown
            | Self::ResponseDropped => None,
        }
    }

    /// Return one bounded, redacted recovery projection for both admission
    /// failures and service responses.
    pub const fn view(&self) -> ControlErrorView {
        match self {
            Self::QueueFull => ControlErrorView::retryable_admission(),
            Self::WorkerClosed | Self::WorkerShuttingDown => {
                ControlErrorView::not_admitted(self.code())
            }
            Self::ResponseDropped => ControlErrorView::unknown(self.code()),
            Self::Service(error) => error.view(),
        }
    }
}

impl std::fmt::Display for ControlClientError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code().summary())
    }
}

impl std::error::Error for ControlClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Service(error) => Some(error),
            Self::QueueFull
            | Self::WorkerClosed
            | Self::WorkerShuttingDown
            | Self::ResponseDropped => None,
        }
    }
}

/// One admitted response that can be polled without blocking the caller.
#[derive(Debug)]
pub struct PendingControl<T> {
    receiver: Receiver<Result<T, ControlError>>,
}

impl<T> PendingControl<T> {
    fn new(receiver: Receiver<Result<T, ControlError>>) -> Self {
        Self { receiver }
    }

    #[cfg(test)]
    pub(crate) fn from_receiver(receiver: Receiver<Result<T, ControlError>>) -> Self {
        Self::new(receiver)
    }

    /// Blocking completion path for non-UI callers such as HTTP adapters.
    pub fn recv(self) -> Result<T, ControlClientError> {
        self.receiver
            .recv()
            .map_err(|_| ControlClientError::ResponseDropped)?
            .map_err(ControlClientError::Service)
    }

    /// Nonblocking completion poll.  `Ok(None)` means the worker is still
    /// processing; a disconnected response channel means the request was
    /// already admitted but its response was lost, so its durable outcome is
    /// unknown.
    pub fn try_recv(&self) -> Result<Option<Result<T, ControlError>>, ControlClientError> {
        match self.receiver.try_recv() {
            Ok(result) => Ok(Some(result)),
            Err(std::sync::mpsc::TryRecvError::Empty) => Ok(None),
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                Err(ControlClientError::ResponseDropped)
            }
        }
    }
}

/// Worker lifecycle/join errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlWorkerError {
    AlreadyShutdown,
    WorkerClosed,
    JoinFailed,
    TooManyOwnedActivities,
}

impl std::fmt::Display for ControlWorkerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::AlreadyShutdown => "control worker is already shut down",
            Self::WorkerClosed => "control worker is closed",
            Self::JoinFailed => "control worker failed to join",
            Self::TooManyOwnedActivities => "too many owned Activities for graceful shutdown",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ControlWorkerError {}

/// Cloneable bounded request handle.  Cloning shares only a channel sender and
/// an atomic admission flag; no mutable application state is shared.
#[derive(Debug, Clone)]
enum ControlSender {
    General(QueueMailbox<ForgeControlRequest>),
    ActivityLease(SyncSender<ForgeControlRequest>),
}

#[derive(Debug, Clone)]
pub struct ForgeControlClient {
    sender: ControlSender,
    accepting: Arc<AtomicBool>,
    binary_import: Arc<AtomicBool>,
}

/// Owns the one queued-or-running binary slot. All terminal paths drop the
/// request, so rejection and shutdown cannot leak capacity.
#[derive(Debug)]
pub(crate) struct BinaryImportPermit(Arc<AtomicBool>);

impl Drop for BinaryImportPermit {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl ForgeControlClient {
    pub fn leadership_work_cut(
        &self,
        command: crate::WorkCutCommand,
    ) -> Result<crate::WorkCutResponse, ControlClientError> {
        self.submit(|response| ForgeControlRequest::LeadershipWorkCut {
            command: Box::new(command),
            response,
        })
    }
    #[cfg(test)]
    pub(crate) fn journal_test_channel(capacity: usize) -> (Self, Receiver<ForgeControlRequest>) {
        let (sender, receiver) = mpsc::sync_channel(capacity);
        (
            Self::new(
                ControlSender::ActivityLease(sender),
                Arc::new(AtomicBool::new(true)),
            ),
            receiver,
        )
    }

    pub fn activity_read(
        &self,
        request: ActivityReadRequest,
    ) -> Result<ActivityReadSnapshot, ControlClientError> {
        self.submit(|response| ForgeControlRequest::ActivityRead { request, response })
    }
    pub fn goal_delete_pending(
        &self,
        scope: ResolvedWorkspaceScope,
        limit: u32,
    ) -> Result<forge_persistence::GoalDeletionPendingInventory, ControlClientError> {
        self.submit(|response| ForgeControlRequest::GoalDeletePending {
            scope,
            limit,
            response,
        })
    }
    pub fn goal_delete(
        &self,
        request: crate::GoalDeleteRequest,
        product_cache_root: Option<std::path::PathBuf>,
    ) -> Result<crate::GoalDeleteOutcome, ControlClientError> {
        self.submit(|response| ForgeControlRequest::GoalDelete {
            request,
            product_cache_root,
            response,
        })
    }
    pub fn agent_assignment_mutate(
        &self,
        request: crate::AgentAssignmentMutationRequest,
    ) -> Result<forge_domain::RegisteredAgentAssignment, ControlClientError> {
        self.submit(|response| ForgeControlRequest::AgentAssignmentMutate { request, response })
    }

    pub fn agent_assignment_offer_seal(
        &self,
        request: crate::AgentAssignmentOfferSealRequest,
    ) -> Result<forge_persistence::AgentAssignmentOfferSealSnapshot, ControlClientError> {
        self.submit(|response| ForgeControlRequest::AgentAssignmentOfferSeal { request, response })
    }

    pub fn agent_assignment_offer_seal_get(
        &self,
        request: crate::AgentAssignmentOfferSealRequest,
    ) -> Result<Option<forge_persistence::AgentAssignmentOfferSealSnapshot>, ControlClientError>
    {
        self.submit(
            |response| ForgeControlRequest::AgentAssignmentOfferSealGet { request, response },
        )
    }

    pub fn agent_assignment_get(
        &self,
        request: crate::AgentAssignmentGetRequest,
    ) -> Result<Option<forge_domain::RegisteredAgentAssignment>, ControlClientError> {
        self.submit(|response| ForgeControlRequest::AgentAssignmentGet { request, response })
    }

    pub fn agent_assignment_list(
        &self,
        request: crate::AgentAssignmentListRequest,
    ) -> Result<Vec<forge_domain::AgentAssignmentSummary>, ControlClientError> {
        self.submit(|response| ForgeControlRequest::AgentAssignmentList { request, response })
    }
    pub fn agent_coordination_view(
        &self,
        request: AgentCoordinationQuery,
    ) -> Result<AgentCoordinationView, ControlClientError> {
        self.submit(|response| ForgeControlRequest::AgentCoordinationView { request, response })
    }

    pub fn agent_inbox_list(
        &self,
        request: AgentInboxListRequest,
    ) -> Result<Vec<forge_domain::InboxEntry>, ControlClientError> {
        self.submit(|response| ForgeControlRequest::AgentInboxList { request, response })
    }

    pub fn submit_agent_coordination_view(
        &self,
        request: AgentCoordinationQuery,
    ) -> Result<PendingControl<AgentCoordinationView>, ControlClientError> {
        self.submit_pending(|response| ForgeControlRequest::AgentCoordinationView {
            request,
            response,
        })
    }
    pub fn agent_session_open(
        &self,
        request: forge_domain::OpenAgentSession,
    ) -> Result<forge_domain::AgentSessionOpenOutcome, ControlClientError> {
        self.submit(|response| ForgeControlRequest::AgentSessionOpen { request, response })
    }

    pub fn reserve_agent_binding(
        &self,
        request: AgentBindingReserveRequest,
    ) -> Result<forge_persistence::AgentBindingReservation, ControlClientError> {
        self.submit_reserve_agent_binding(request)?.recv()
    }

    pub fn reserve_agent_binding_ref(
        &self,
        request: AgentBindingReserveReferenceRequest,
    ) -> Result<forge_persistence::AgentBindingReservation, ControlClientError> {
        self.submit(
            |response| ForgeControlRequest::AgentBindingReserveReference { request, response },
        )
    }

    pub fn submit_reserve_agent_binding(
        &self,
        request: AgentBindingReserveRequest,
    ) -> Result<PendingControl<forge_persistence::AgentBindingReservation>, ControlClientError>
    {
        self.submit_pending(|response| ForgeControlRequest::AgentBindingReserve {
            request,
            response,
        })
    }

    pub fn agent_binding_reservation(
        &self,
        request: AgentBindingReservationReadRequest,
    ) -> Result<Option<forge_persistence::AgentBindingReservation>, ControlClientError> {
        self.submit(
            |response| ForgeControlRequest::AgentBindingReservationRead { request, response },
        )
    }

    pub fn delegate_agent_operations(
        &self,
        request: AgentOperationsDelegationRequest,
    ) -> Result<forge_persistence::AgentOperationsDelegation, ControlClientError> {
        self.submit_delegate_agent_operations(request)?.recv()
    }

    pub fn delegate_agent_operations_ref(
        &self,
        request: AgentOperationsDelegateReferenceRequest,
    ) -> Result<forge_persistence::AgentOperationsDelegation, ControlClientError> {
        self.submit(
            |response| ForgeControlRequest::AgentOperationsDelegationReference {
                request,
                response,
            },
        )
    }

    pub fn submit_delegate_agent_operations(
        &self,
        request: AgentOperationsDelegationRequest,
    ) -> Result<PendingControl<forge_persistence::AgentOperationsDelegation>, ControlClientError>
    {
        self.submit_pending(|response| ForgeControlRequest::AgentOperationsDelegation {
            request,
            response,
        })
    }

    pub fn agent_operations_delegation(
        &self,
        request: AgentOperationsDelegationReadRequest,
    ) -> Result<Option<forge_persistence::AgentOperationsDelegation>, ControlClientError> {
        self.submit(
            |response| ForgeControlRequest::AgentOperationsDelegationRead { request, response },
        )
    }

    pub fn agent_operations_freeze(
        &self,
        request: AgentOperationsFreezeRequest,
    ) -> Result<forge_persistence::AgentOperationsFreeze, ControlClientError> {
        self.submit(|response| ForgeControlRequest::AgentOperationsFreeze { request, response })
    }

    pub fn agent_operations_freeze_read(
        &self,
        request: AgentOperationsFreezeReadRequest,
    ) -> Result<Option<forge_persistence::AgentOperationsFreeze>, ControlClientError> {
        self.submit(|response| ForgeControlRequest::AgentOperationsFreezeRead { request, response })
    }

    pub fn agent_operations_export(
        &self,
        request: AgentOperationsExportRequest,
    ) -> Result<forge_persistence::AgentOperationsExportPage, ControlClientError> {
        self.submit(|response| ForgeControlRequest::AgentOperationsExport { request, response })
    }

    pub fn agent_operations_freeze_release(
        &self,
        request: AgentOperationsFreezeReleaseRequest,
    ) -> Result<forge_persistence::AgentOperationsFreeze, ControlClientError> {
        self.submit(
            |response| ForgeControlRequest::AgentOperationsFreezeRelease { request, response },
        )
    }

    pub fn activate_agent_binding(
        &self,
        request: AgentBindingActivateRequest,
    ) -> Result<forge_persistence::AgentBindingActivation, ControlClientError> {
        self.submit_activate_agent_binding(request)?.recv()
    }

    pub fn activate_agent_binding_ref(
        &self,
        request: AgentBindingActivateReferenceRequest,
    ) -> Result<forge_persistence::AgentBindingActivation, ControlClientError> {
        self.submit(
            |response| ForgeControlRequest::AgentBindingActivateReference { request, response },
        )
    }

    pub fn submit_activate_agent_binding(
        &self,
        request: AgentBindingActivateRequest,
    ) -> Result<PendingControl<forge_persistence::AgentBindingActivation>, ControlClientError> {
        self.submit_pending(|response| ForgeControlRequest::AgentBindingActivate {
            request,
            response,
        })
    }

    pub fn agent_binding_activation(
        &self,
        request: AgentBindingActivationReadRequest,
    ) -> Result<Option<forge_persistence::AgentBindingActivation>, ControlClientError> {
        self.submit(|response| ForgeControlRequest::AgentBindingActivationRead {
            request,
            response,
        })
    }

    pub fn reject_agent_binding(
        &self,
        request: AgentBindingRejectRequest,
    ) -> Result<forge_persistence::AgentBindingRejectionOperation, ControlClientError> {
        self.submit(|response| ForgeControlRequest::AgentBindingReject { request, response })
    }

    pub fn agent_binding_rejection(
        &self,
        request: AgentBindingRejectionReadRequest,
    ) -> Result<Option<forge_persistence::AgentBindingRejectionReceipt>, ControlClientError> {
        self.submit(|response| ForgeControlRequest::AgentBindingRejectionRead { request, response })
    }

    pub fn reconcile_agent_session(
        &self,
        request: AgentSessionReconcileRequest,
    ) -> Result<forge_persistence::AgentSessionReconciliation, ControlClientError> {
        self.submit(|response| ForgeControlRequest::AgentSessionReconcile { request, response })
    }

    pub fn reconcile_agent_session_destination(
        &self,
        request: AgentSessionReconcileDestinationRequest,
    ) -> Result<forge_persistence::AgentSessionReconciliation, ControlClientError> {
        self.submit(
            |response| ForgeControlRequest::AgentSessionReconcileDestination { request, response },
        )
    }

    pub fn agent_session_reconciliation(
        &self,
        request: AgentSessionReconcileReadRequest,
    ) -> Result<Option<forge_persistence::AgentSessionReconciliation>, ControlClientError> {
        self.submit(
            |response| ForgeControlRequest::AgentSessionReconciliationRead { request, response },
        )
    }

    pub fn reconcile_agent_departure(
        &self,
        request: AgentDepartureReconcileRequest,
    ) -> Result<forge_persistence::AgentDepartureReconciliation, ControlClientError> {
        self.submit(|response| ForgeControlRequest::AgentDepartureReconcile { request, response })
    }

    pub fn reconcile_agent_departure_destination(
        &self,
        request: AgentDepartureReconcileDestinationRequest,
    ) -> Result<forge_persistence::AgentDepartureReconciliation, ControlClientError> {
        self.submit(
            |response| ForgeControlRequest::AgentDepartureReconcileDestination {
                request,
                response,
            },
        )
    }

    pub fn agent_departure_reconciliation(
        &self,
        request: AgentDepartureReconcileReadRequest,
    ) -> Result<Option<forge_persistence::AgentDepartureReconciliation>, ControlClientError> {
        self.submit(
            |response| ForgeControlRequest::AgentDepartureReconciliationRead { request, response },
        )
    }

    pub fn agent_effect_outbox(
        &self,
        request: AgentEffectOutboxReadRequest,
    ) -> Result<Vec<forge_persistence::AgentEffectOutboxEntry>, ControlClientError> {
        self.submit(|response| ForgeControlRequest::AgentEffectOutboxRead { request, response })
    }

    pub fn effect_fact_outbox(
        &self,
        request: EffectFactOutboxReadRequest,
    ) -> Result<Vec<forge_persistence::EffectFactOutboxEntry>, ControlClientError> {
        self.submit(|response| ForgeControlRequest::EffectFactOutboxRead { request, response })
    }

    /// Submit one explicit approval-grant consumption + execution begin to the
    /// bounded worker. Orchestration adapters pass an optional admission
    /// envelope that is validated and consumed in the same durable transaction.
    pub fn approval_grant_consume(
        &self,
        request: ApprovalGrantConsumeRequest,
    ) -> Result<ApprovalGrantConsumeResult, ControlClientError> {
        self.submit(|response| ForgeControlRequest::ApprovalGrantConsume { request, response })
    }

    pub fn semantic_events_page(
        &self,
        request: crate::semantic_projection::SemanticEventsPageRequest,
    ) -> Result<crate::semantic_projection::SemanticEventsPageResult, ControlClientError> {
        self.submit(|response| ForgeControlRequest::SemanticEventsPage { request, response })
    }

    pub fn workspace_semantic_snapshot(
        &self,
        request: crate::semantic_projection::WorkspaceSemanticSnapshotRequest,
    ) -> Result<crate::semantic_projection::WorkspaceSemanticSnapshotResult, ControlClientError>
    {
        self.submit(|response| ForgeControlRequest::WorkspaceSemanticSnapshot { request, response })
    }

    pub fn agent_session_resolve(
        &self,
        request: AgentSessionResolveRequest,
    ) -> Result<forge_domain::RegisteredAgentSession, ControlClientError> {
        self.submit(|response| ForgeControlRequest::AgentSessionResolve { request, response })
    }

    pub fn agent_session_prove(
        &self,
        request: AgentSessionProofRequest,
    ) -> Result<forge_domain::RegisteredAgentInstance, ControlClientError> {
        self.submit(|response| ForgeControlRequest::AgentSessionProve { request, response })
    }
    fn new(sender: ControlSender, accepting: Arc<AtomicBool>) -> Self {
        Self {
            sender,
            accepting,
            binary_import: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Read the bounded general-mailbox projection without entering the
    /// effect-owning worker lane.
    pub fn queue_status(&self) -> Result<QueueStatus, QueueRuntimeError> {
        match &self.sender {
            ControlSender::General(queue) => queue.status(queue_timestamp_micros()),
            ControlSender::ActivityLease(_) => Err(QueueRuntimeError::Closed),
        }
    }

    pub fn workspace_queue_status(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<QueueStatus, QueueRuntimeError> {
        match &self.sender {
            ControlSender::General(queue) => queue.status_for(
                crate::queue::QueueAttribution::Workspace(workspace_id),
                queue_timestamp_micros(),
            ),
            ControlSender::ActivityLease(_) => Err(QueueRuntimeError::Closed),
        }
    }

    /// Apply one revision-fenced general-mailbox capacity update.
    pub fn apply_queue_capacity(
        &self,
        capacity: QueueCapacity,
        expected_config_revision: u64,
    ) -> Result<QueueStatus, QueueConfigError> {
        match &self.sender {
            ControlSender::General(queue) => {
                queue.apply_capacity(capacity, expected_config_revision)
            }
            ControlSender::ActivityLease(_) => Err(QueueConfigError::Closed),
        }
    }

    pub fn apply_workspace_queue_capacity(
        &self,
        workspace_id: WorkspaceId,
        capacity: QueueCapacity,
        expected_config_revision: u64,
    ) -> Result<QueueStatus, QueueConfigError> {
        match &self.sender {
            ControlSender::General(queue) => {
                queue.apply_workspace_capacity(workspace_id, capacity, expected_config_revision)
            }
            ControlSender::ActivityLease(_) => Err(QueueConfigError::Closed),
        }
    }

    pub fn workspace_queue_settings(
        &self,
        scope: ResolvedWorkspaceScope,
    ) -> Result<Option<forge_persistence::RegisteredQueueSettings>, ControlClientError> {
        self.submit(|response| ForgeControlRequest::WorkspaceQueueSettingsGet { scope, response })
    }

    pub fn replace_workspace_queue_settings(
        &self,
        request: WorkspaceQueueSettingsRequest,
    ) -> Result<forge_persistence::RegisteredQueueSettings, ControlClientError> {
        self.submit(
            |response| ForgeControlRequest::WorkspaceQueueSettingsReplace { request, response },
        )
    }

    pub fn location_list(&self) -> Result<Vec<RegisteredLocation>, ControlClientError> {
        self.submit(|response| ForgeControlRequest::LocationList { response })
    }

    pub fn location_removal_probe(
        &self,
        id: LocationId,
    ) -> Result<crate::LocationRemovalProbe, ControlClientError> {
        self.submit(|response| ForgeControlRequest::LocationRemovalProbe { id, response })
    }

    pub fn location_remove(
        &self,
        request: crate::LocationRemovalRequest,
    ) -> Result<crate::WorkspaceRemovalOutcome, ControlClientError> {
        self.submit(|response| ForgeControlRequest::LocationRemove { request, response })
    }

    /// Register one exact root path as a Location identity through the
    /// single-owner control worker.
    pub fn register_location(
        &self,
        request: RegisterLocationRequest,
    ) -> Result<RegisteredLocation, ControlClientError> {
        self.submit(|response| ForgeControlRequest::RegisterLocation { request, response })
    }

    /// Apply one Location enable/disable transition through the
    /// single-owner control worker.
    pub fn set_location_state(
        &self,
        command: SetLocationState,
    ) -> Result<RegisteredLocation, ControlClientError> {
        self.submit(|response| ForgeControlRequest::SetLocationState { command, response })
    }

    pub fn register_workspace(
        &self,
        request: crate::WorkspaceRegistrationRequest,
    ) -> Result<crate::WorkspaceRegistrationOutcome, ControlClientError> {
        self.submit(|response| ForgeControlRequest::RegisterWorkspace { request, response })
    }

    pub fn probe_workspace_registration(
        &self,
        locator: WorkspaceLocator,
    ) -> Result<crate::WorkspaceRegistrationProbe, ControlClientError> {
        self.submit(|response| ForgeControlRequest::ProbeWorkspaceRegistration {
            locator,
            response,
        })
    }

    pub fn probe_workspace_root_recovery(
        &self,
        request: WorkspaceRootRecoveryProbeRequest,
    ) -> Result<WorkspaceRootRecoveryProbe, ControlClientError> {
        self.submit(|response| ForgeControlRequest::WorkspaceRootRecoveryProbe {
            request,
            response,
        })
    }

    pub fn prepare_workspace_root_recovery(
        &self,
        request: WorkspaceRootRecoveryPrepareRequest,
    ) -> Result<WorkspaceRootRecoveryProbe, ControlClientError> {
        self.submit(
            |response| ForgeControlRequest::WorkspaceRootRecoveryPrepare { request, response },
        )
    }

    pub fn commit_workspace_root_recovery(
        &self,
        request: WorkspaceRootRecoveryCommitRequest,
    ) -> Result<WorkspaceRootRecoveryCommitOutcome, ControlClientError> {
        self.submit(
            |response| ForgeControlRequest::WorkspaceRootRecoveryCommit { request, response },
        )
    }

    pub fn readback_workspace_root_recovery(
        &self,
        request: WorkspaceRootRecoveryReadbackRequest,
    ) -> Result<Option<forge_persistence::RootRecoveryReceipt>, ControlClientError> {
        self.submit(
            |response| ForgeControlRequest::WorkspaceRootRecoveryReadback { request, response },
        )
    }

    pub fn workspace_list(
        &self,
        location_id: LocationId,
        expected_revision: LocationRevision,
    ) -> Result<Vec<WorkspaceCatalogEntry>, ControlClientError> {
        self.submit(|response| ForgeControlRequest::WorkspaceList {
            location_id,
            expected_revision,
            response,
        })
    }

    pub fn registered_workspace_inventory(
        &self,
        location_id: LocationId,
        expected_revision: LocationRevision,
    ) -> Result<crate::WorkspaceInventory, ControlClientError> {
        self.submit(|response| ForgeControlRequest::WorkspaceInventory {
            location_id,
            expected_revision,
            response,
        })
    }

    pub fn workspace_discover(
        &self,
        location_id: LocationId,
        expected_revision: LocationRevision,
    ) -> Result<Vec<WorkspaceDiscoveryEntry>, ControlClientError> {
        self.submit(|response| ForgeControlRequest::WorkspaceDiscover {
            location_id,
            expected_revision,
            response,
        })
    }

    pub fn resolve_workspace(
        &self,
        location_id: LocationId,
        expected_revision: LocationRevision,
        locator: WorkspaceLocator,
    ) -> Result<ResolvedWorkspaceScope, ControlClientError> {
        self.submit(|response| ForgeControlRequest::ResolveWorkspace {
            location_id,
            expected_revision,
            locator,
            response,
        })
    }

    /// Revalidate Activity ownership through the single-owner control worker.
    /// The worker stamps the observation immediately before the durable check.
    pub fn authorize_activity(
        &self,
        scope: ResolvedWorkspaceScope,
        activity: FileActivityScope,
    ) -> Result<(), ControlClientError> {
        self.submit(|response| ForgeControlRequest::AuthorizeActivity {
            scope,
            activity,
            response,
        })
    }

    pub fn workspace_doctor(
        &self,
        request: WorkspaceDoctorRequest,
    ) -> Result<WorkspaceDoctorResult, ControlClientError> {
        self.submit_workspace_doctor(request)?.recv()
    }

    pub fn workspace_identity_doctor(
        &self,
    ) -> Result<WorkspaceIdentityDoctorReport, ControlClientError> {
        self.submit_workspace_identity_doctor()?.recv()
    }

    pub fn bootstrap_activity(
        &self,
        scope: ResolvedWorkspaceScope,
        caller_activity_id: ActivityId,
        runtime_instance_id: RuntimeInstanceId,
        observed_at: TimestampMillis,
        lease_until: TimestampMillis,
    ) -> Result<ActivityBootstrap, ControlClientError> {
        self.submit(|response| ForgeControlRequest::BootstrapActivity {
            scope,
            caller_activity_id,
            runtime_instance_id,
            observed_at,
            lease_until,
            response,
        })
    }

    pub fn activity_successor_create(
        &self,
        request: ActivitySuccessorCreateRequest,
    ) -> Result<forge_domain::ActivitySuccessorResult, ControlClientError> {
        self.submit(|response| ForgeControlRequest::ActivitySuccessorCreate { request, response })
    }

    pub fn activity_successor_get(
        &self,
        scope: ResolvedWorkspaceScope,
        predecessor_activity_id: ActivityId,
    ) -> Result<
        Option<(
            forge_domain::ActivitySuccessor,
            forge_domain::RegisteredActivity,
        )>,
        ControlClientError,
    > {
        self.submit(|response| ForgeControlRequest::ActivitySuccessorGet {
            scope,
            predecessor_activity_id,
            response,
        })
    }

    pub fn expired_activity_recovery_probe(
        &self,
        request: ExpiredActivityRecoveryProbeRequest,
    ) -> Result<forge_domain::ExpiredActivityRecoveryProbe, ControlClientError> {
        self.submit(
            |response| ForgeControlRequest::ExpiredActivityRecoveryProbe { request, response },
        )
    }

    pub fn expired_activity_recovery_run(
        &self,
        request: DurableExpiredActivityRecoveryRequest,
    ) -> Result<ExpiredActivityRecoveryReport, ControlClientError> {
        self.submit(|response| ForgeControlRequest::ExpiredActivityRecoveryRun {
            request,
            response,
        })
    }

    pub fn expired_activity_recovery_get(
        &self,
        request: ExpiredActivityRecoveryGetRequest,
    ) -> Result<Option<forge_persistence::ExpiredActivityRecoveryReadback>, ControlClientError>
    {
        self.submit(|response| ForgeControlRequest::ExpiredActivityRecoveryGet {
            request,
            response,
        })
    }

    pub fn unstarted_activity_continuation_probe(
        &self,
        request: UnstartedActivityContinuationProbeRequest,
    ) -> Result<forge_domain::UnstartedActivityContinuationProbe, ControlClientError> {
        self.submit(
            |response| ForgeControlRequest::UnstartedActivityContinuationProbe {
                request,
                response,
            },
        )
    }

    pub fn unstarted_activity_continuation_run(
        &self,
        request: DurableUnstartedActivityContinuationRequest,
    ) -> Result<UnstartedActivityContinuationReport, ControlClientError> {
        self.submit(
            |response| ForgeControlRequest::UnstartedActivityContinuationRun { request, response },
        )
    }

    pub fn unstarted_activity_continuation_get(
        &self,
        request: UnstartedActivityContinuationGetRequest,
    ) -> Result<Option<forge_persistence::UnstartedActivityContinuationReadback>, ControlClientError>
    {
        self.submit(
            |response| ForgeControlRequest::UnstartedActivityContinuationGet { request, response },
        )
    }

    pub fn started_activity_lease_resume_probe(
        &self,
        request: StartedActivityLeaseResumeProbeRequest,
    ) -> Result<forge_domain::StartedActivityLeaseResumeProbe, ControlClientError> {
        self.submit(
            |response| ForgeControlRequest::StartedActivityLeaseResumeProbe { request, response },
        )
    }

    pub fn run_started_activity_lease_resume(
        &self,
        request: StartedActivityLeaseResumeRunRequest,
    ) -> Result<forge_domain::StartedActivityLeaseResumeOperation, ControlClientError> {
        self.submit(
            |response| ForgeControlRequest::StartedActivityLeaseResumeRun { request, response },
        )
    }

    pub fn started_activity_lease_resume_get(
        &self,
        request: StartedActivityLeaseResumeGetRequest,
    ) -> Result<Option<forge_persistence::StartedActivityLeaseResumeReadback>, ControlClientError>
    {
        self.submit(
            |response| ForgeControlRequest::StartedActivityLeaseResumeGet { request, response },
        )
    }

    pub fn quiescent_activity_lease_resume_probe(
        &self,
        request: QuiescentActivityLeaseResumeProbeRequest,
    ) -> Result<forge_domain::QuiescentActivityLeaseResumeProbe, ControlClientError> {
        self.submit(
            |response| ForgeControlRequest::QuiescentActivityLeaseResumeProbe { request, response },
        )
    }

    pub fn run_quiescent_activity_lease_resume(
        &self,
        request: QuiescentActivityLeaseResumeRunRequest,
    ) -> Result<forge_domain::QuiescentActivityLeaseResumeOperation, ControlClientError> {
        self.submit(
            |response| ForgeControlRequest::QuiescentActivityLeaseResumeRun { request, response },
        )
    }

    pub fn quiescent_activity_lease_resume_get(
        &self,
        request: QuiescentActivityLeaseResumeGetRequest,
    ) -> Result<Option<forge_persistence::QuiescentActivityLeaseResumeReadback>, ControlClientError>
    {
        self.submit(
            |response| ForgeControlRequest::QuiescentActivityLeaseResumeGet { request, response },
        )
    }

    pub fn renew_activity_lease(
        &self,
        scope: ResolvedWorkspaceScope,
        activity_id: ActivityId,
        runtime_instance_id: RuntimeInstanceId,
        expected_lease_revision: ActivityLeaseRevision,
        observed_at: TimestampMillis,
        lease_until: TimestampMillis,
    ) -> Result<ActivityLeaseOperation, ControlClientError> {
        self.submit(|response| ForgeControlRequest::RenewActivityLease {
            scope,
            activity_id,
            runtime_instance_id,
            expected_lease_revision,
            observed_at,
            lease_until,
            response,
        })
    }

    pub fn renew_activity_lease_batch(
        &self,
        scope: ResolvedWorkspaceScope,
        commands: Vec<RenewActivityLease>,
    ) -> Result<ActivityLeaseOperation, ControlClientError> {
        self.submit_renew_activity_lease_batch(scope, commands)?
            .recv()
    }

    pub fn submit_renew_activity_lease_batch(
        &self,
        scope: ResolvedWorkspaceScope,
        commands: Vec<RenewActivityLease>,
    ) -> Result<PendingControl<ActivityLeaseOperation>, ControlClientError> {
        if commands.len() > crate::MAX_ACTIVITY_LEASE_BATCH {
            return Err(ControlClientError::Service(ControlError::new(
                ControlErrorCode::CapacityExceeded,
            )));
        }
        self.submit_pending(|response| ForgeControlRequest::RenewActivityLeaseBatch {
            scope,
            commands,
            response,
        })
    }

    pub fn renew_supervised_activity_lease(
        &self,
        request: SupervisedActivityLeaseRenewRequest,
    ) -> Result<ActivityLeaseOperation, ControlClientError> {
        self.submit_pending(
            |response| ForgeControlRequest::SupervisedActivityLeaseRenew { request, response },
        )?
        .recv()
    }

    pub fn close_activity(
        &self,
        scope: ResolvedWorkspaceScope,
        activity_id: ActivityId,
        runtime_instance_id: RuntimeInstanceId,
        expected_lease_revision: ActivityLeaseRevision,
    ) -> Result<ActivityLeaseOperation, ControlClientError> {
        self.submit(|response| ForgeControlRequest::CloseActivity {
            scope,
            activity_id,
            runtime_instance_id,
            expected_lease_revision,
            response,
        })
    }

    pub fn close_owned_activity_batch(
        &self,
        scope: ResolvedWorkspaceScope,
        commands: Vec<CloseActivity>,
    ) -> Result<ActivityLeaseOperation, ControlClientError> {
        self.submit_close_owned_activity_batch(scope, commands)?
            .recv()
    }

    pub fn submit_close_owned_activity_batch(
        &self,
        scope: ResolvedWorkspaceScope,
        commands: Vec<CloseActivity>,
    ) -> Result<PendingControl<ActivityLeaseOperation>, ControlClientError> {
        if commands.len() > crate::MAX_ACTIVITY_LEASE_BATCH {
            return Err(ControlClientError::Service(ControlError::new(
                ControlErrorCode::CapacityExceeded,
            )));
        }
        self.submit_pending(|response| ForgeControlRequest::CloseOwnedActivityBatch {
            scope,
            commands,
            response,
        })
    }

    pub fn release_activity_lease(
        &self,
        scope: ResolvedWorkspaceScope,
        activity_id: ActivityId,
        runtime_instance_id: RuntimeInstanceId,
        expected_lease_revision: ActivityLeaseRevision,
    ) -> Result<ActivityLeaseOperation, ControlClientError> {
        self.submit(|response| ForgeControlRequest::ReleaseActivityLease {
            scope,
            activity_id,
            runtime_instance_id,
            expected_lease_revision,
            response,
        })
    }

    pub fn release_activity_lease_batch(
        &self,
        scope: ResolvedWorkspaceScope,
        commands: Vec<ReleaseActivityLease>,
    ) -> Result<ActivityLeaseOperation, ControlClientError> {
        if commands.len() > crate::MAX_ACTIVITY_LEASE_BATCH {
            return Err(ControlClientError::Service(ControlError::new(
                ControlErrorCode::CapacityExceeded,
            )));
        }
        self.submit(|response| ForgeControlRequest::ReleaseActivityLeaseBatch {
            scope,
            commands,
            response,
        })
    }

    /// Read exact durable Activity rows for observational tracker reconciliation.
    pub fn observe_activity_leases(
        &self,
        scope: ResolvedWorkspaceScope,
        activity_ids: Vec<ActivityId>,
    ) -> Result<Vec<RegisteredActivity>, ControlClientError> {
        if activity_ids.len() > MAX_ACTIVITY_LEASE_OBSERVATION_IDS {
            return Err(ControlClientError::Service(ControlError::new(
                ControlErrorCode::CapacityExceeded,
            )));
        }
        self.submit(|response| ForgeControlRequest::ObserveActivityLeases {
            scope,
            activity_ids,
            response,
        })
    }

    pub fn reconcile_expired_activity_leases(
        &self,
        scope: ResolvedWorkspaceScope,
        observed_at: TimestampMillis,
    ) -> Result<ActivityLeaseOperation, ControlClientError> {
        self.reconcile_expired_activity_leases_limited(
            scope,
            observed_at,
            ActivityListLimit::DEFAULT,
        )
    }

    pub fn reconcile_expired_activity_leases_limited(
        &self,
        scope: ResolvedWorkspaceScope,
        observed_at: TimestampMillis,
        limit: ActivityListLimit,
    ) -> Result<ActivityLeaseOperation, ControlClientError> {
        self.submit(
            |response| ForgeControlRequest::ReconcileExpiredActivityLeases {
                scope,
                observed_at,
                limit,
                response,
            },
        )
    }

    pub fn list_activity_projections(
        &self,
        scope: ResolvedWorkspaceScope,
        now: TimestampMillis,
        limit: ActivityListLimit,
    ) -> Result<Vec<ActivityProjection>, ControlClientError> {
        self.submit(|response| ForgeControlRequest::ListActivityProjections {
            scope,
            now,
            limit,
            response,
        })
    }

    pub fn list_workspace_activity_projections(
        &self,
        request: WorkspaceActivityProjectionRequest,
    ) -> Result<WorkspaceActivityProjection, ControlClientError> {
        self.submit_list_workspace_activity_projections(request)?
            .recv()
    }

    /// Nonblocking UI/Desktop admission variant for workspace Activity
    /// projection refresh.
    pub fn submit_list_workspace_activity_projections(
        &self,
        request: WorkspaceActivityProjectionRequest,
    ) -> Result<PendingControl<WorkspaceActivityProjection>, ControlClientError> {
        self.submit_pending(
            |response| ForgeControlRequest::ListWorkspaceActivityProjections { request, response },
        )
    }

    pub fn agent_set_focus(
        &self,
        request: AgentFocusRequest,
    ) -> Result<forge_domain::RegisteredAgentInstance, ControlClientError> {
        self.submit(|response| ForgeControlRequest::AgentSetFocus { request, response })
    }

    pub fn submit_agent_set_focus(
        &self,
        request: AgentFocusRequest,
    ) -> Result<PendingControl<forge_domain::RegisteredAgentInstance>, ControlClientError> {
        self.submit_pending(|response| ForgeControlRequest::AgentSetFocus { request, response })
    }

    pub fn agent_publish_work_update(
        &self,
        request: AgentWorkUpdateRequest,
    ) -> Result<forge_domain::AgentWorkUpdate, ControlClientError> {
        self.submit(|response| ForgeControlRequest::AgentPublishWorkUpdate { request, response })
    }

    pub fn submit_agent_publish_work_update(
        &self,
        request: AgentWorkUpdateRequest,
    ) -> Result<PendingControl<forge_domain::AgentWorkUpdate>, ControlClientError> {
        self.submit_pending(|response| ForgeControlRequest::AgentPublishWorkUpdate {
            request,
            response,
        })
    }

    pub fn agent_list(
        &self,
        request: AgentListRequest,
    ) -> Result<Vec<forge_domain::AgentAttachmentProjection>, ControlClientError> {
        self.submit(|response| ForgeControlRequest::AgentList { request, response })
    }

    pub fn submit_agent_list(
        &self,
        request: AgentListRequest,
    ) -> Result<PendingControl<Vec<forge_domain::AgentAttachmentProjection>>, ControlClientError>
    {
        self.submit_pending(|response| ForgeControlRequest::AgentList { request, response })
    }

    pub fn agent_get_context(
        &self,
        request: AgentContextRequest,
    ) -> Result<Option<forge_domain::AgentContextProjection>, ControlClientError> {
        self.submit(|response| ForgeControlRequest::AgentGetContext { request, response })
    }

    pub fn submit_agent_get_context(
        &self,
        request: AgentContextRequest,
    ) -> Result<PendingControl<Option<forge_domain::AgentContextProjection>>, ControlClientError>
    {
        self.submit_pending(|response| ForgeControlRequest::AgentGetContext { request, response })
    }

    pub fn writer_lease_acquire(
        &self,
        request: WriterLeaseAcquireRequest,
    ) -> Result<forge_domain::WriterLease, ControlClientError> {
        self.submit(|response| ForgeControlRequest::WriterLeaseAcquire { request, response })
    }

    pub fn writer_lease_renew(
        &self,
        request: WriterLeaseRenewRequest,
    ) -> Result<forge_domain::WriterLease, ControlClientError> {
        self.submit(|response| ForgeControlRequest::WriterLeaseRenew { request, response })
    }

    pub fn writer_lease_release(
        &self,
        request: WriterLeaseReleaseRequest,
    ) -> Result<forge_domain::WriterLease, ControlClientError> {
        self.submit(|response| ForgeControlRequest::WriterLeaseRelease { request, response })
    }

    pub fn writer_lease_get(
        &self,
        request: WriterLeaseGetRequest,
    ) -> Result<
        Option<(
            forge_domain::WriterLease,
            Option<forge_domain::AgentSessionId>,
        )>,
        ControlClientError,
    > {
        self.submit(|response| ForgeControlRequest::WriterLeaseGet { request, response })
    }

    pub fn writer_lease_list(
        &self,
        request: WriterLeaseListRequest,
    ) -> Result<WriterLeaseListPage, ControlClientError> {
        self.submit(|response| ForgeControlRequest::WriterLeaseList { request, response })
    }

    pub fn writer_lease_release_for_recovery(
        &self,
        request: WriterLeaseRecoveryReleaseRequest,
    ) -> Result<forge_domain::WriterLease, ControlClientError> {
        self.submit(|response| ForgeControlRequest::WriterLeaseRecoveryRelease {
            request,
            response,
        })
    }

    pub fn verify_agent_execution_authority(
        &self,
        request: AgentExecutionAuthorityRequest,
    ) -> Result<(), ControlClientError> {
        self.submit(
            |response| ForgeControlRequest::AgentVerifyExecutionAuthority { request, response },
        )
    }

    pub fn project_command_execution_request_fenced(
        &self,
        request: ProjectCommandListRequest,
        command_id: crate::ProjectCommandId,
        expected_fingerprint: forge_domain::ProjectCommandCatalogFingerprint,
        execution_id: ExecutionId,
    ) -> Result<crate::ResolvedProjectCommandExecution, ControlClientError> {
        self.submit(|response| ForgeControlRequest::ProjectCommandResolve {
            request,
            command_id,
            expected_fingerprint,
            execution_id,
            response,
        })
    }

    pub(crate) fn prepare_project_command_verification(
        &self,
        request: ProjectCommandListRequest,
        command_id: crate::ProjectCommandId,
        expected_fingerprint: forge_domain::ProjectCommandCatalogFingerprint,
        execution_id: ExecutionId,
        cancellation: Arc<AtomicBool>,
    ) -> Result<PreparedProjectCommandVerification, ControlClientError> {
        self.submit(
            |response| ForgeControlRequest::ProjectCommandPrepareVerification {
                request,
                command_id,
                expected_fingerprint,
                execution_id,
                cancellation,
                response,
            },
        )
    }

    pub(crate) fn prepare_workspace_verification_input(
        &self,
        scope: ResolvedWorkspaceScope,
        activity: crate::FileActivityScope,
        input_id: forge_domain::VerificationInputId,
        cancellation: Arc<AtomicBool>,
    ) -> Result<forge_workspace::PublishedVerificationInput, ControlClientError> {
        self.submit(
            |response| ForgeControlRequest::WorkspaceVerificationPrepare {
                scope,
                activity,
                input_id,
                cancellation,
                response,
            },
        )
    }

    pub fn project_command_list(
        &self,
        request: ProjectCommandListRequest,
    ) -> Result<ProjectCommandListResult, ControlClientError> {
        self.submit(|response| ForgeControlRequest::ProjectCommandList { request, response })
    }

    pub fn activity_coordinator_actor(
        &self,
        request: crate::CoordinatorActorRequest,
    ) -> Result<Option<forge_domain::ActivityCoordinatorActor>, ControlClientError> {
        self.submit_activity_coordinator_actor(request)?.recv()
    }

    pub fn submit_generated_artifact_inventory(
        &self,
        scope: ResolvedWorkspaceScope,
        cache_root: std::path::PathBuf,
        limit: crate::GeneratedArtifactInventoryLimit,
    ) -> Result<PendingControl<crate::GeneratedArtifactInventory>, ControlClientError> {
        self.submit_pending(|response| ForgeControlRequest::GeneratedArtifactInventory {
            scope,
            cache_root,
            limit,
            response,
        })
    }

    pub fn submit_generated_package_access(
        &self,
        scope: ResolvedWorkspaceScope,
        cache_root: std::path::PathBuf,
        execution_id: ExecutionId,
    ) -> Result<PendingControl<Option<std::path::PathBuf>>, ControlClientError> {
        self.submit_pending(|response| ForgeControlRequest::GeneratedPackageAccess {
            scope,
            cache_root,
            execution_id,
            response,
        })
    }

    pub fn submit_activity_coordinator_actor(
        &self,
        request: crate::CoordinatorActorRequest,
    ) -> Result<PendingControl<Option<forge_domain::ActivityCoordinatorActor>>, ControlClientError>
    {
        self.submit_pending(|response| ForgeControlRequest::CoordinatorActor { request, response })
    }

    pub fn activity_coordinator_get(
        &self,
        request: CoordinatorGetRequest,
    ) -> Result<Option<forge_domain::ActivityCoordinatorBinding>, ControlClientError> {
        self.submit_activity_coordinator_get(request)?.recv()
    }

    pub fn submit_activity_coordinator_get(
        &self,
        request: CoordinatorGetRequest,
    ) -> Result<PendingControl<Option<forge_domain::ActivityCoordinatorBinding>>, ControlClientError>
    {
        self.submit_pending(|response| ForgeControlRequest::CoordinatorGet { request, response })
    }

    pub fn activity_coordinator_claim(
        &self,
        request: CoordinatorClaimRequest,
    ) -> Result<forge_domain::ActivityCoordinatorBinding, ControlClientError> {
        self.submit_activity_coordinator_claim(request)?.recv()
    }

    pub fn submit_activity_coordinator_claim(
        &self,
        request: CoordinatorClaimRequest,
    ) -> Result<PendingControl<forge_domain::ActivityCoordinatorBinding>, ControlClientError> {
        self.submit_pending(|response| ForgeControlRequest::CoordinatorClaim { request, response })
    }

    pub fn activity_coordinator_transfer(
        &self,
        request: CoordinatorTransferRequest,
    ) -> Result<forge_domain::ActivityCoordinatorBinding, ControlClientError> {
        self.submit_activity_coordinator_transfer(request)?.recv()
    }

    pub fn submit_activity_coordinator_transfer(
        &self,
        request: CoordinatorTransferRequest,
    ) -> Result<PendingControl<forge_domain::ActivityCoordinatorBinding>, ControlClientError> {
        self.submit_pending(|response| ForgeControlRequest::CoordinatorTransfer {
            request,
            response,
        })
    }

    pub fn prepare_coordinator_recovery(
        &self,
        request: CoordinatorRecoveryPrepareRequest,
    ) -> Result<forge_domain::CoordinatorRecoveryFence, ControlClientError> {
        self.submit(|response| ForgeControlRequest::CoordinatorRecoveryPrepare {
            request,
            response,
        })
    }

    pub fn confirm_coordinator_recovery(
        &self,
        request: CoordinatorRecoveryConfirmRequest,
    ) -> Result<forge_domain::CoordinatorRecoveryReceipt, ControlClientError> {
        self.submit(|response| ForgeControlRequest::CoordinatorRecoveryConfirm {
            request,
            response,
        })
    }

    pub fn coordinator_recovery_receipt(
        &self,
        request: CoordinatorRecoveryReadRequest,
    ) -> Result<Option<forge_domain::CoordinatorRecoveryReceipt>, ControlClientError> {
        self.submit(|response| ForgeControlRequest::CoordinatorRecoveryReceipt {
            request,
            response,
        })
    }

    pub fn coordinator_recovery_history(
        &self,
        request: CoordinatorRecoveryHistoryRequest,
    ) -> Result<Vec<forge_domain::CoordinatorRecoveryReceipt>, ControlClientError> {
        self.submit(|response| ForgeControlRequest::CoordinatorRecoveryHistory {
            request,
            response,
        })
    }

    pub fn agent_dag_plan_commit(
        &self,
        request: AgentDagPlanCommitRequest,
    ) -> Result<forge_persistence::AgentDagPlanCommitResult, ControlClientError> {
        self.submit_agent_dag_plan_commit(request)?.recv()
    }

    pub fn submit_agent_dag_plan_commit(
        &self,
        request: AgentDagPlanCommitRequest,
    ) -> Result<PendingControl<forge_persistence::AgentDagPlanCommitResult>, ControlClientError>
    {
        self.submit_pending(|response| ForgeControlRequest::AgentDagPlanCommit {
            request,
            response,
        })
    }

    /// Blocking confined file read through the single-owner application
    /// service worker.
    pub fn file_read(
        &self,
        request: FileReadRequest,
    ) -> Result<FileReadResult, ControlClientError> {
        self.submit_file_read(request)?.recv()
    }

    pub fn submit_file_read(
        &self,
        request: FileReadRequest,
    ) -> Result<PendingControl<FileReadResult>, ControlClientError> {
        self.submit_pending(|response| ForgeControlRequest::FileRead { request, response })
    }

    pub fn file_list(
        &self,
        request: FileListRequest,
    ) -> Result<FileListResult, ControlClientError> {
        self.submit_file_list(request)?.recv()
    }

    pub fn submit_file_list(
        &self,
        request: FileListRequest,
    ) -> Result<PendingControl<FileListResult>, ControlClientError> {
        self.submit_pending(|response| ForgeControlRequest::FileList { request, response })
    }

    pub fn text_search(
        &self,
        request: TextSearchRequest,
    ) -> Result<TextSearchResult, ControlClientError> {
        self.submit_text_search(request)?.recv()
    }

    pub fn submit_text_search(
        &self,
        request: TextSearchRequest,
    ) -> Result<PendingControl<TextSearchResult>, ControlClientError> {
        self.submit_pending(|response| ForgeControlRequest::TextSearch { request, response })
    }

    /// Observe one exact historical mutation tuple without acquiring write authority.
    pub fn file_mutation_readback(
        &self,
        request: crate::FileMutationReadbackRequest,
    ) -> Result<Option<forge_persistence::FileMutationReadSnapshot>, ControlClientError> {
        self.submit_file_mutation_readback(request)?.recv()
    }

    pub fn submit_file_mutation_readback(
        &self,
        request: crate::FileMutationReadbackRequest,
    ) -> Result<
        PendingControl<Option<forge_persistence::FileMutationReadSnapshot>>,
        ControlClientError,
    > {
        self.submit_pending(|response| ForgeControlRequest::FileMutationReadback {
            request,
            response,
        })
    }

    /// Observe one exact historical mutation tuple without acquiring write authority.
    pub fn source_tree_readback(
        &self,
        request: crate::SourceTreeReadbackRequest,
    ) -> Result<Option<forge_persistence::SourceTreeReadSnapshot>, ControlClientError> {
        self.submit_source_tree_readback(request)?.recv()
    }

    pub fn submit_source_tree_readback(
        &self,
        request: crate::SourceTreeReadbackRequest,
    ) -> Result<PendingControl<Option<forge_persistence::SourceTreeReadSnapshot>>, ControlClientError>
    {
        self.submit_pending(|response| ForgeControlRequest::SourceTreeReadback {
            request,
            response,
        })
    }

    pub fn goal_mutation(
        &self,
        request: crate::GoalMutationRequest,
    ) -> Result<forge_persistence::GoalMutationResult, ControlClientError> {
        self.submit_goal_mutation(request)?.recv()
    }
    pub fn submit_goal_mutation(
        &self,
        request: crate::GoalMutationRequest,
    ) -> Result<PendingControl<forge_persistence::GoalMutationResult>, ControlClientError> {
        self.submit_pending(|response| ForgeControlRequest::GoalMutation {
            request: Box::new(request),
            response,
        })
    }

    pub fn goal_mutation_readback(
        &self,
        request: crate::GoalMutationReadbackRequest,
    ) -> Result<Option<forge_domain::GoalMutationReceipt>, ControlClientError> {
        self.submit_goal_mutation_readback(request)?.recv()
    }
    pub fn submit_goal_mutation_readback(
        &self,
        request: crate::GoalMutationReadbackRequest,
    ) -> Result<PendingControl<Option<forge_domain::GoalMutationReceipt>>, ControlClientError> {
        self.submit_pending(|response| ForgeControlRequest::GoalMutationReadback {
            request,
            response,
        })
    }

    pub fn dag_plan_readback(
        &self,
        request: crate::DagPlanReadbackRequest,
    ) -> Result<Option<forge_persistence::AgentDagPlanRecord>, ControlClientError> {
        self.submit_dag_plan_readback(request)?.recv()
    }
    pub fn submit_dag_plan_readback(
        &self,
        request: crate::DagPlanReadbackRequest,
    ) -> Result<PendingControl<Option<forge_persistence::AgentDagPlanRecord>>, ControlClientError>
    {
        self.submit_pending(|response| ForgeControlRequest::DagPlanReadback { request, response })
    }

    pub fn file_read_slice(
        &self,
        request: FileReadSliceRequest,
    ) -> Result<FileReadSliceResult, ControlClientError> {
        self.submit_file_read_slice(request)?.recv()
    }

    pub fn submit_file_read_slice(
        &self,
        request: FileReadSliceRequest,
    ) -> Result<PendingControl<FileReadSliceResult>, ControlClientError> {
        self.submit_pending(|response| ForgeControlRequest::FileReadSlice { request, response })
    }

    pub fn file_apply_patch(
        &self,
        request: FileApplyPatchRequest,
    ) -> Result<FileApplyPatchResult, ControlClientError> {
        self.submit_file_apply_patch(request)?.recv()
    }

    pub fn submit_file_apply_patch(
        &self,
        request: FileApplyPatchRequest,
    ) -> Result<PendingControl<FileApplyPatchResult>, ControlClientError> {
        self.submit_pending(|response| ForgeControlRequest::FileApplyPatch { request, response })
    }

    pub fn source_tree_apply(
        &self,
        request: SourceTreeTransactionRequest,
    ) -> Result<SourceTreeTransactionResult, ControlClientError> {
        self.submit_source_tree_apply(request)?.recv()
    }

    pub fn submit_source_tree_apply(
        &self,
        request: SourceTreeTransactionRequest,
    ) -> Result<PendingControl<SourceTreeTransactionResult>, ControlClientError> {
        self.submit_pending(|response| ForgeControlRequest::SourceTreeApply { request, response })
    }

    /// Bounded native binary import; payload size is checked before queue admission.
    pub fn file_import_binary(
        &self,
        request: FileMutationRequest,
    ) -> Result<FileMutationResult, ControlClientError> {
        self.submit_file_import_binary(request)?.recv()
    }

    pub fn submit_file_import_binary(
        &self,
        request: FileMutationRequest,
    ) -> Result<PendingControl<FileMutationResult>, ControlClientError> {
        let content = request.content.as_deref().ok_or_else(|| {
            ControlClientError::Service(ControlError::new(ControlErrorCode::FileConflict))
        })?;
        if content.len() > forge_workspace::MAX_BINARY_IMPORT_BYTES {
            return Err(ControlClientError::Service(ControlError::new(
                ControlErrorCode::FileCapacityExceeded,
            )));
        }
        // One queued-or-running binary payload per worker, independent of the
        // configurable general queue capacity. The owned permit follows the
        // request through rejection, shutdown and effect completion.
        self.binary_import
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| ControlClientError::QueueFull)?;
        let permit = BinaryImportPermit(Arc::clone(&self.binary_import));
        self.submit_pending(|response| ForgeControlRequest::FileImportBinary {
            request,
            response,
            _permit: permit,
        })
    }

    /// Blocking one-file mutation with bounded content before queue admission.
    pub fn file_mutate(
        &self,
        request: FileMutationRequest,
    ) -> Result<FileMutationResult, ControlClientError> {
        self.submit_file_mutate(request)?.recv()
    }

    pub fn submit_file_mutate(
        &self,
        request: FileMutationRequest,
    ) -> Result<PendingControl<FileMutationResult>, ControlClientError> {
        if request
            .content
            .as_ref()
            .is_some_and(|content| content.len() > forge_workspace::MAX_FILE_WRITE_BYTES)
        {
            return Err(ControlClientError::Service(ControlError::new(
                ControlErrorCode::FileCapacityExceeded,
            )));
        }
        self.submit_pending(|response| ForgeControlRequest::FileMutate { request, response })
    }

    pub fn execution_mark_running(
        &self,
        scope: ResolvedWorkspaceScope,
        command: MarkExecutionRunning,
    ) -> Result<RegisteredExecution, ControlClientError> {
        self.submit(|response| ForgeControlRequest::ExecutionMarkRunning {
            scope,
            command,
            response,
        })
    }

    pub(crate) fn execution_journal_output(
        &self,
        authority: &crate::execution_journal::ExecutionJournalAuthority,
        events: Vec<ExecutionOutputEvent>,
    ) -> Result<(), ControlClientError> {
        if events.len() > forge_domain::MAX_EXECUTION_OUTPUT_READ_EVENTS {
            return Err(ControlClientError::Service(ControlError::new(
                ControlErrorCode::InvalidInput,
            )));
        }
        self.submit(|response| ForgeControlRequest::ExecutionJournalOutput {
            authority: authority.clone(),
            events,
            response,
        })
    }

    pub(crate) fn execution_journal_complete(
        &self,
        authority: &crate::execution_journal::ExecutionJournalAuthority,
        command: CompleteExecution,
        closure: Option<forge_domain::ExecutionNativeClosureFact>,
    ) -> Result<RegisteredExecution, ControlClientError> {
        self.submit(|response| ForgeControlRequest::ExecutionJournalComplete {
            authority: authority.clone(),
            command,
            closure,
            response,
        })
    }

    pub(crate) fn execution_journal_complete_generated(
        &self,
        authority: &crate::execution_journal::ExecutionJournalAuthority,
        command: CompleteExecution,
        manifest: forge_domain::GeneratedPackageManifest,
        closure: Option<forge_domain::ExecutionNativeClosureFact>,
    ) -> Result<RegisteredExecution, ControlClientError> {
        self.submit(
            |response| ForgeControlRequest::ExecutionJournalCompleteGenerated {
                authority: authority.clone(),
                command,
                manifest,
                closure,
                response,
            },
        )
    }

    pub(crate) fn execution_journal_fail(
        &self,
        authority: &crate::execution_journal::ExecutionJournalAuthority,
        command: FailExecution,
        closure: Option<forge_domain::ExecutionNativeClosureFact>,
    ) -> Result<RegisteredExecution, ControlClientError> {
        self.submit(|response| ForgeControlRequest::ExecutionJournalFail {
            authority: authority.clone(),
            command,
            closure,
            response,
        })
    }

    pub(crate) fn execution_journal_reconcile_output(
        &self,
        authority: &crate::execution_journal::ExecutionJournalAuthority,
        before: &RegisteredExecution,
        events: &[ExecutionOutputEvent],
    ) -> Result<crate::execution_journal::JournalReadback, ControlClientError> {
        self.submit(
            |response| ForgeControlRequest::ExecutionJournalReconcileOutput {
                authority: authority.clone(),
                before: before.clone(),
                events: events.to_vec(),
                response,
            },
        )
    }

    pub(crate) fn execution_journal_reconcile_terminal(
        &self,
        authority: &crate::execution_journal::ExecutionJournalAuthority,
        before: &RegisteredExecution,
        command: &crate::execution_journal::JournalTerminalCommand,
        closure: Option<forge_domain::ExecutionNativeClosureFact>,
    ) -> Result<crate::execution_journal::JournalReadback, ControlClientError> {
        self.submit(
            |response| ForgeControlRequest::ExecutionJournalReconcileTerminal {
                authority: authority.clone(),
                before: before.clone(),
                command: Box::new(command.clone()),
                closure,
                response,
            },
        )
    }

    pub fn execution_complete_generated(
        &self,
        scope: ResolvedWorkspaceScope,
        command: CompleteExecution,
        manifest: forge_domain::GeneratedPackageManifest,
    ) -> Result<RegisteredExecution, ControlClientError> {
        self.submit(|response| ForgeControlRequest::ExecutionCompleteGenerated {
            scope,
            command,
            manifest,
            response,
        })
    }

    pub fn execution_complete(
        &self,
        scope: ResolvedWorkspaceScope,
        command: CompleteExecution,
    ) -> Result<RegisteredExecution, ControlClientError> {
        self.submit(|response| ForgeControlRequest::ExecutionComplete {
            scope,
            command,
            response,
        })
    }

    pub fn execution_fail(
        &self,
        scope: ResolvedWorkspaceScope,
        command: FailExecution,
    ) -> Result<RegisteredExecution, ControlClientError> {
        self.submit(|response| ForgeControlRequest::ExecutionFail {
            scope,
            command,
            response,
        })
    }

    pub fn reconcile_interrupted_executions(
        &self,
        scope: ResolvedWorkspaceScope,
        observed_at: TimestampMillis,
        limit: ExecutionListLimit,
    ) -> Result<Vec<RegisteredExecution>, ControlClientError> {
        self.submit(|response| ForgeControlRequest::ExecutionReconcile {
            scope,
            observed_at,
            limit,
            response,
        })
    }

    pub fn execution_get(
        &self,
        scope: ResolvedWorkspaceScope,
        id: ExecutionId,
    ) -> Result<Option<RegisteredExecution>, ControlClientError> {
        self.submit(|response| ForgeControlRequest::ExecutionGet {
            scope,
            id,
            response,
        })
    }

    pub fn submit_verification_projection(
        &self,
        scope: ResolvedWorkspaceScope,
    ) -> Result<PendingControl<VerificationProjection>, ControlClientError> {
        self.submit_pending(|response| ForgeControlRequest::VerificationProjection {
            scope,
            response,
        })
    }

    pub fn execution_evidence_inventory(
        &self,
        scope: ResolvedWorkspaceScope,
        selection: forge_domain::ExecutionObservationSelection,
        limit: ExecutionListLimit,
    ) -> Result<forge_persistence::ExecutionEvidenceInventory, ControlClientError> {
        self.submit(|response| ForgeControlRequest::ExecutionEvidenceInventory {
            scope,
            selection,
            limit,
            response,
        })
    }

    pub fn execution_evidence_read(
        &self,
        scope: ResolvedWorkspaceScope,
        selection: forge_domain::ExecutionObservationSelection,
        id: ExecutionId,
        cursor: ExecutionOutputCursor,
        max_bytes: u64,
        max_events: usize,
    ) -> Result<forge_persistence::ExecutionEvidenceRead, ControlClientError> {
        self.submit(|response| ForgeControlRequest::ExecutionEvidenceRead {
            scope,
            selection,
            id,
            cursor,
            max_bytes,
            max_events,
            response,
        })
    }

    pub fn execution_generated_package_manifest(
        &self,
        scope: ResolvedWorkspaceScope,
        id: ExecutionId,
    ) -> Result<Option<forge_domain::GeneratedPackageManifest>, ControlClientError> {
        self.submit(|response| ForgeControlRequest::ExecutionGeneratedPackage {
            scope,
            id,
            response,
        })
    }

    pub fn execution_get_authorized_with_generated_package(
        &self,
        request: AgentExecutionAuthorityRequest,
        id: ExecutionId,
    ) -> Result<forge_persistence::AuthorizedExecutionSnapshot, ControlClientError> {
        self.submit(|response| ForgeControlRequest::ExecutionGetEvidence {
            request,
            id,
            response,
        })
    }

    pub fn execution_get_authorized(
        &self,
        request: AgentExecutionAuthorityRequest,
        id: ExecutionId,
    ) -> Result<RegisteredExecution, ControlClientError> {
        self.submit(|response| ForgeControlRequest::ExecutionGetAuthorized {
            request,
            id,
            response,
        })
    }

    pub fn execution_list(
        &self,
        scope: ResolvedWorkspaceScope,
        activity_id: ActivityId,
        limit: ExecutionListLimit,
    ) -> Result<Vec<RegisteredExecution>, ControlClientError> {
        self.submit(|response| ForgeControlRequest::ExecutionList {
            scope,
            activity_id,
            limit,
            response,
        })
    }

    pub fn execution_output_append_batch(
        &self,
        scope: ResolvedWorkspaceScope,
        events: Vec<ExecutionOutputEvent>,
    ) -> Result<(), ControlClientError> {
        if events.len() > forge_domain::MAX_EXECUTION_OUTPUT_READ_EVENTS {
            return Err(ControlClientError::Service(ControlError::new(
                ControlErrorCode::InvalidInput,
            )));
        }
        self.submit(|response| ForgeControlRequest::ExecutionOutputAppendBatch {
            scope,
            events,
            response,
        })
    }

    pub fn execution_output_read(
        &self,
        scope: ResolvedWorkspaceScope,
        cursor: ExecutionOutputCursor,
        max_bytes: u64,
        max_events: usize,
    ) -> Result<ExecutionOutputRead, ControlClientError> {
        self.submit(|response| ForgeControlRequest::ExecutionOutputRead {
            scope,
            cursor,
            max_bytes,
            max_events,
            response,
        })
    }

    pub fn execution_output_read_authorized(
        &self,
        request: AgentExecutionAuthorityRequest,
        id: ExecutionId,
        cursor: ExecutionOutputCursor,
        max_bytes: u64,
        max_events: usize,
    ) -> Result<ExecutionOutputRead, ControlClientError> {
        self.submit(
            |response| ForgeControlRequest::ExecutionOutputReadAuthorized {
                request,
                id,
                cursor,
                max_bytes,
                max_events,
                response,
            },
        )
    }

    /// Read an Agent-owned execution record and bounded output from one
    /// durable snapshot through the single-owner control worker.
    pub fn execution_read_authorized(
        &self,
        request: AgentExecutionAuthorityRequest,
        id: ExecutionId,
        cursor: ExecutionOutputCursor,
        max_bytes: u64,
        max_events: usize,
    ) -> Result<AuthorizedExecutionRead, ControlClientError> {
        self.submit(|response| ForgeControlRequest::ExecutionReadAuthorized {
            request,
            id,
            cursor,
            max_bytes,
            max_events,
            response,
        })
    }

    pub fn goal_create(
        &self,
        scope: ResolvedWorkspaceScope,
        actor: ActivityCoordinatorActor,
        goal: RegisteredGoal,
    ) -> Result<RegisteredGoal, ControlClientError> {
        self.submit_goal_create(scope, actor, goal)?.recv()
    }

    pub fn submit_goal_create(
        &self,
        scope: ResolvedWorkspaceScope,
        actor: ActivityCoordinatorActor,
        goal: RegisteredGoal,
    ) -> Result<PendingControl<RegisteredGoal>, ControlClientError> {
        self.submit_pending(|response| ForgeControlRequest::GoalCreate {
            scope,
            actor,
            goal,
            response,
        })
    }

    pub fn goal_get(
        &self,
        scope: ResolvedWorkspaceScope,
        activity_id: ActivityId,
        goal_id: GoalId,
    ) -> Result<Option<RegisteredGoal>, ControlClientError> {
        self.submit_goal_get(scope, activity_id, goal_id)?.recv()
    }

    pub fn submit_goal_get(
        &self,
        scope: ResolvedWorkspaceScope,
        activity_id: ActivityId,
        goal_id: GoalId,
    ) -> Result<PendingControl<Option<RegisteredGoal>>, ControlClientError> {
        self.submit_pending(|response| ForgeControlRequest::GoalGet {
            scope,
            activity_id,
            goal_id,
            response,
        })
    }

    pub fn goal_list(
        &self,
        scope: ResolvedWorkspaceScope,
        activity_id: ActivityId,
        limit: GoalListLimit,
    ) -> Result<Vec<RegisteredGoal>, ControlClientError> {
        self.submit_goal_list(scope, activity_id, limit)?.recv()
    }

    pub fn submit_goal_list(
        &self,
        scope: ResolvedWorkspaceScope,
        activity_id: ActivityId,
        limit: GoalListLimit,
    ) -> Result<PendingControl<Vec<RegisteredGoal>>, ControlClientError> {
        self.submit_pending(|response| ForgeControlRequest::GoalList {
            scope,
            activity_id,
            limit,
            response,
        })
    }

    pub fn goal_revise_contract(
        &self,
        request: GoalContractRevisionRequest,
    ) -> Result<RegisteredGoal, ControlClientError> {
        self.submit_goal_revise_contract(request)?.recv()
    }

    pub fn submit_goal_revise_contract(
        &self,
        request: GoalContractRevisionRequest,
    ) -> Result<PendingControl<RegisteredGoal>, ControlClientError> {
        self.submit_pending(|response| ForgeControlRequest::GoalReviseContract {
            request,
            response,
        })
    }

    pub fn goal_transition(
        &self,
        request: GoalLifecycleRequest,
    ) -> Result<RegisteredGoal, ControlClientError> {
        self.submit_goal_transition(request)?.recv()
    }

    pub fn submit_goal_transition(
        &self,
        request: GoalLifecycleRequest,
    ) -> Result<PendingControl<RegisteredGoal>, ControlClientError> {
        self.submit_pending(|response| ForgeControlRequest::GoalTransition { request, response })
    }

    pub fn goal_review(
        &self,
        scope: ResolvedWorkspaceScope,
        activity_id: ActivityId,
        goal_id: GoalId,
    ) -> Result<GoalReview, ControlClientError> {
        self.submit_goal_review(scope, activity_id, goal_id)?.recv()
    }

    pub fn submit_goal_review(
        &self,
        scope: ResolvedWorkspaceScope,
        activity_id: ActivityId,
        goal_id: GoalId,
    ) -> Result<PendingControl<GoalReview>, ControlClientError> {
        self.submit_pending(|response| ForgeControlRequest::GoalReview {
            scope,
            activity_id,
            goal_id,
            response,
        })
    }

    pub fn goal_complete(
        &self,
        request: GoalCompletionRequest,
    ) -> Result<RegisteredGoal, ControlClientError> {
        self.submit_goal_complete(request)?.recv()
    }

    pub fn submit_goal_complete(
        &self,
        request: GoalCompletionRequest,
    ) -> Result<PendingControl<RegisteredGoal>, ControlClientError> {
        self.submit_pending(|response| ForgeControlRequest::GoalComplete { request, response })
    }

    pub fn dag_get_current(
        &self,
        scope: ResolvedWorkspaceScope,
        goal_id: GoalId,
    ) -> Result<Option<StoredDagRevision>, ControlClientError> {
        self.submit_dag_get_current(scope, goal_id)?.recv()
    }

    pub fn submit_dag_get_current(
        &self,
        scope: ResolvedWorkspaceScope,
        goal_id: GoalId,
    ) -> Result<PendingControl<Option<StoredDagRevision>>, ControlClientError> {
        self.submit_pending(|response| ForgeControlRequest::DagGetCurrent {
            scope,
            goal_id,
            response,
        })
    }

    pub fn dag_node_assignment_snapshot(
        &self,
        scope: ResolvedWorkspaceScope,
        node_scope: DagNodeEvidenceScope,
    ) -> Result<Option<DagNodeAssignmentSnapshot>, ControlClientError> {
        self.submit_dag_node_assignment_snapshot(scope, node_scope)?
            .recv()
    }

    pub fn submit_dag_node_assignment_snapshot(
        &self,
        scope: ResolvedWorkspaceScope,
        node_scope: DagNodeEvidenceScope,
    ) -> Result<PendingControl<Option<DagNodeAssignmentSnapshot>>, ControlClientError> {
        self.submit_pending(|response| ForgeControlRequest::DagNodeAssignmentSnapshot {
            scope,
            node_scope,
            response,
        })
    }

    pub fn dag_get_revision(
        &self,
        scope: ResolvedWorkspaceScope,
        goal_id: GoalId,
        number: DagRevisionNumber,
    ) -> Result<Option<StoredDagRevision>, ControlClientError> {
        self.submit_dag_get_revision(scope, goal_id, number)?.recv()
    }

    pub fn submit_dag_get_revision(
        &self,
        scope: ResolvedWorkspaceScope,
        goal_id: GoalId,
        number: DagRevisionNumber,
    ) -> Result<PendingControl<Option<StoredDagRevision>>, ControlClientError> {
        self.submit_pending(|response| ForgeControlRequest::DagGetRevision {
            scope,
            goal_id,
            number,
            response,
        })
    }

    pub fn dag_node_start(
        &self,
        request: DagNodeStartRequest,
    ) -> Result<RegisteredDagNode, ControlClientError> {
        self.submit_dag_node_start(request)?.recv()
    }

    pub fn submit_dag_node_start(
        &self,
        request: DagNodeStartRequest,
    ) -> Result<PendingControl<RegisteredDagNode>, ControlClientError> {
        self.submit_pending(|response| ForgeControlRequest::DagNodeStart { request, response })
    }

    pub fn dag_node_complete(
        &self,
        request: DagNodeCompleteRequest,
    ) -> Result<RegisteredDagNode, ControlClientError> {
        self.submit_dag_node_complete(request)?.recv()
    }

    pub fn submit_dag_node_complete(
        &self,
        request: DagNodeCompleteRequest,
    ) -> Result<PendingControl<RegisteredDagNode>, ControlClientError> {
        self.submit_pending(|response| ForgeControlRequest::DagNodeComplete { request, response })
    }

    pub fn dag_node_update(
        &self,
        request: DagNodeUpdateRequest,
    ) -> Result<RegisteredDagNode, ControlClientError> {
        self.submit_dag_node_update(request)?.recv()
    }

    pub fn submit_dag_node_update(
        &self,
        request: DagNodeUpdateRequest,
    ) -> Result<PendingControl<RegisteredDagNode>, ControlClientError> {
        self.submit_pending(|response| ForgeControlRequest::DagNodeUpdate { request, response })
    }

    /// Observe the durable Workspace recovery-maintenance lease through the
    /// bounded control worker.  This is a read-only observation.
    pub fn recovery_maintenance_lease(
        &self,
        scope: ResolvedWorkspaceScope,
    ) -> Result<RecoveryMaintenanceLease, ControlClientError> {
        self.submit(|response| ForgeControlRequest::RecoveryLeaseGet { scope, response })
    }

    /// Claim or take over the Workspace recovery-maintenance lease through
    /// the bounded control worker.
    pub fn claim_recovery_maintenance_lease(
        &self,
        scope: ResolvedWorkspaceScope,
        command: ClaimRecoveryLease,
    ) -> Result<RecoveryLeaseClaimOperation, ControlClientError> {
        self.submit(|response| ForgeControlRequest::RecoveryLeaseClaim {
            scope,
            command,
            response,
        })
    }

    /// Renew the owned recovery-maintenance lease with exact fencing.
    pub fn renew_recovery_maintenance_lease(
        &self,
        scope: ResolvedWorkspaceScope,
        command: RenewRecoveryLease,
    ) -> Result<RecoveryMaintenanceLease, ControlClientError> {
        self.submit(|response| ForgeControlRequest::RecoveryLeaseRenew {
            scope,
            command,
            response,
        })
    }

    /// Release the owned recovery-maintenance lease with exact fencing.
    pub fn release_recovery_maintenance_lease(
        &self,
        scope: ResolvedWorkspaceScope,
        command: ReleaseRecoveryLease,
    ) -> Result<RecoveryMaintenanceLease, ControlClientError> {
        self.submit(|response| ForgeControlRequest::RecoveryLeaseRelease {
            scope,
            command,
            response,
        })
    }

    /// Run one explicit leased recovery-maintenance pass through the bounded
    /// control worker.
    pub fn run_recovery_maintenance(
        &self,
        request: RecoveryMaintenanceRequest,
    ) -> Result<RecoveryMaintenanceReport, ControlClientError> {
        self.submit(|response| ForgeControlRequest::RecoveryMaintenanceRun { request, response })
    }

    pub fn run_durable_recovery_maintenance(
        &self,
        request: crate::DurableRecoveryMaintenanceRequest,
    ) -> Result<RecoveryMaintenanceReport, ControlClientError> {
        self.submit(|response| ForgeControlRequest::RecoveryMaintenanceDurable {
            request,
            response,
        })
    }

    pub fn recovery_maintenance_get(
        &self,
        scope: ResolvedWorkspaceScope,
        request_id: uuid::Uuid,
        request_digest: [u8; 32],
    ) -> Result<Option<forge_persistence::RecoveryRunReceipt>, ControlClientError> {
        self.submit(|response| ForgeControlRequest::RecoveryMaintenanceGet {
            scope,
            request_id,
            request_digest,
            response,
        })
    }

    /// Restore one Ready checkpoint through the bounded control worker.
    pub fn checkpoint_restore(
        &self,
        request: CheckpointRestoreRequest,
    ) -> Result<CheckpointRestoreOutcome, ControlClientError> {
        self.submit(|response| ForgeControlRequest::CheckpointRestoreRun { request, response })
    }

    pub fn ensure_workspace_policy(
        &self,
        scope: ResolvedWorkspaceScope,
    ) -> Result<WorkspacePolicy, ControlClientError> {
        self.submit(|response| ForgeControlRequest::EnsureWorkspacePolicy { scope, response })
    }

    pub fn get_workspace_policy(
        &self,
        scope: ResolvedWorkspaceScope,
    ) -> Result<Option<WorkspacePolicy>, ControlClientError> {
        self.submit(|response| ForgeControlRequest::GetWorkspacePolicy { scope, response })
    }

    pub fn replace_workspace_policy(
        &self,
        request: WorkspacePolicyReplaceRequest,
    ) -> Result<WorkspacePolicy, ControlClientError> {
        self.submit(|response| ForgeControlRequest::ReplaceWorkspacePolicy { request, response })
    }

    pub fn create_pending_approval(
        &self,
        request: ApprovalCreateRequest,
    ) -> Result<RegisteredApprovalRequest, ControlClientError> {
        self.submit(|response| ForgeControlRequest::ApprovalCreate { request, response })
    }

    pub fn list_pending_approvals(
        &self,
        scope: ResolvedWorkspaceScope,
        limit: ExecutionListLimit,
    ) -> Result<Vec<RegisteredApprovalRequest>, ControlClientError> {
        self.submit(|response| ForgeControlRequest::ApprovalListPending {
            scope,
            limit,
            response,
        })
    }

    pub fn approval_get(
        &self,
        scope: ResolvedWorkspaceScope,
        approval_id: ApprovalRequestId,
    ) -> Result<Option<(RegisteredApprovalRequest, Option<RegisteredExecution>)>, ControlClientError>
    {
        self.submit(|response| ForgeControlRequest::ApprovalGet {
            scope,
            approval_id,
            response,
        })
    }

    pub fn approval_get_with_grant(
        &self,
        scope: ResolvedWorkspaceScope,
        approval_id: ApprovalRequestId,
    ) -> Result<ApprovalExecutionGrantReadback, ControlClientError> {
        self.submit(|response| ForgeControlRequest::ApprovalGetWithGrant {
            scope,
            approval_id,
            response,
        })
    }

    pub fn approve_once(
        &self,
        request: ApprovalOnceRequest,
    ) -> Result<(RegisteredApprovalRequest, ExecutionGrant), ControlClientError> {
        self.submit(|response| ForgeControlRequest::ApprovalApproveOnce { request, response })
    }

    pub fn decide_pending_approval(
        &self,
        request: ApprovalDecisionRequest,
    ) -> Result<RegisteredApprovalRequest, ControlClientError> {
        self.submit(|response| ForgeControlRequest::ApprovalDecide { request, response })
    }

    pub fn create_auto_approval_scope(
        &self,
        request: AutoApprovalScopeCreateRequest,
    ) -> Result<AutoApprovalScope, ControlClientError> {
        self.submit(|response| ForgeControlRequest::AutoApprovalScopeCreate { request, response })
    }

    pub fn revoke_auto_approval_scope(
        &self,
        request: AutoApprovalScopeRevokeRequest,
    ) -> Result<AutoApprovalScope, ControlClientError> {
        self.submit(|response| ForgeControlRequest::AutoApprovalScopeRevoke { request, response })
    }

    pub fn get_auto_approval_scope(
        &self,
        scope: ResolvedWorkspaceScope,
        id: AutoApprovalScopeId,
    ) -> Result<Option<AutoApprovalScope>, ControlClientError> {
        self.submit(|response| ForgeControlRequest::AutoApprovalScopeGet {
            scope,
            id,
            response,
        })
    }

    pub(crate) fn consume_execution_grant(
        &self,
        request: ApprovalGrantConsumeRequest,
    ) -> Result<ApprovalGrantConsumeResult, ControlClientError> {
        self.submit(|response| ForgeControlRequest::ApprovalGrantConsume { request, response })
    }

    pub(crate) fn consume_auto_approval(
        &self,
        request: AutoApprovalConsumeRequest,
    ) -> Result<AutoApprovalConsumeResult, ControlClientError> {
        self.submit(|response| ForgeControlRequest::AutoApprovalConsume { request, response })
    }

    pub(crate) fn mint_approval_cleanup_permit(
        &self,
        owner: ApprovalCleanupOwner,
        scope: ResolvedWorkspaceScope,
        selector: ApprovalCleanupSelector,
    ) -> Result<ApprovalCleanupPermit, ControlClientError> {
        self.submit(|response| ForgeControlRequest::ApprovalCleanupPermitMint {
            owner,
            scope,
            selector,
            response,
        })
    }

    pub(crate) fn prepare_approval_cleanup_plan(
        &self,
        permit: ApprovalCleanupPermit,
        owner: ApprovalCleanupOwner,
        selector: ApprovalCleanupSelector,
        observed_at: TimestampMillis,
        limit: ExecutionListLimit,
    ) -> Result<ApprovalCleanupPlan, ControlClientError> {
        self.submit(|response| ForgeControlRequest::ApprovalCleanupPrepare {
            permit,
            owner,
            selector,
            observed_at,
            limit,
            response,
        })
    }

    pub(crate) fn apply_approval_cleanup_plan(
        &self,
        owner: ApprovalCleanupOwner,
        plan: ApprovalCleanupPlan,
        attempt: ApprovalCleanupAttemptId,
    ) -> Result<ApprovalCleanupApplyOutcome, ControlClientError> {
        self.submit(|response| ForgeControlRequest::ApprovalCleanupApply {
            owner,
            plan,
            attempt,
            response,
        })
    }

    pub(crate) fn observe_approval_cleanup_plan(
        &self,
        owner: ApprovalCleanupOwner,
        plan: ApprovalCleanupPlan,
    ) -> Result<ApprovalCleanupReadback, ControlClientError> {
        self.submit(|response| ForgeControlRequest::ApprovalCleanupObserve {
            owner,
            plan,
            response,
        })
    }

    pub(crate) fn prepare_execution_stop_context(
        &self,
        scope: ResolvedWorkspaceScope,
        request: forge_persistence::ExecutionStopRequest,
    ) -> Result<ExecutionStopContext, ControlClientError> {
        self.submit(|response| ForgeControlRequest::ExecutionStopPrepare {
            scope,
            request,
            response,
        })
    }

    pub(crate) fn apply_execution_stop_context(
        &self,
        context: ExecutionStopContext,
    ) -> Result<forge_persistence::ExecutionStopCapture, ControlClientError> {
        self.submit(|response| ForgeControlRequest::ExecutionStopApply { context, response })
    }

    pub(crate) fn observe_execution_stop_context(
        &self,
        context: ExecutionStopContext,
    ) -> Result<Option<forge_persistence::ExecutionStopRecord>, ControlClientError> {
        self.submit(|response| ForgeControlRequest::ExecutionStopObserve { context, response })
    }

    pub(crate) fn observe_owned_stop_history(
        &self,
        permit: ApprovalCleanupPermit,
        owner: ApprovalCleanupOwner,
        request: forge_persistence::ExecutionStopRequest,
    ) -> Result<
        Option<(
            forge_persistence::ExecutionStopRecord,
            forge_persistence::AuthorityStopReceipt,
        )>,
        ControlClientError,
    > {
        self.submit(|response| ForgeControlRequest::OwnedExecutionStopHistory {
            permit,
            owner,
            request,
            response,
        })
    }

    pub(crate) fn settle_owned_execution_stop_context(
        &self,
        settlement: crate::execution_stop::owned::OwnedExecutionStopSettlement,
    ) -> Result<
        (
            forge_persistence::ExecutionStopRecord,
            forge_persistence::AuthorityStopReceipt,
        ),
        ControlClientError,
    > {
        self.submit(|response| ForgeControlRequest::OwnedExecutionStopSettle {
            settlement: Box::new(settlement),
            response,
        })
    }

    pub(crate) fn prepare_owned_execution_stop_context(
        &self,
        permit: ApprovalCleanupPermit,
        owner: ApprovalCleanupOwner,
        request: forge_persistence::ExecutionStopRequest,
    ) -> Result<crate::execution_stop::owned::OwnedExecutionStopContext, ControlClientError> {
        self.submit(|response| ForgeControlRequest::OwnedExecutionStopPrepare {
            permit,
            owner,
            request,
            response,
        })
    }

    pub(crate) fn apply_owned_execution_stop_context(
        &self,
        context: crate::execution_stop::owned::OwnedExecutionStopContext,
    ) -> Result<forge_persistence::OwnedWorkspaceStopCapture, ControlClientError> {
        self.submit(|response| ForgeControlRequest::OwnedExecutionStopApply { context, response })
    }

    pub(crate) fn observe_owned_execution_stop_context(
        &self,
        context: crate::execution_stop::owned::OwnedExecutionStopContext,
    ) -> Result<
        Option<(
            forge_persistence::ExecutionStopRecord,
            forge_persistence::AuthorityStopReceipt,
        )>,
        ControlClientError,
    > {
        self.submit(|response| ForgeControlRequest::OwnedExecutionStopObserve { context, response })
    }

    pub(crate) fn prepare_approval_expiry_plan(
        &self,
        scope: ResolvedWorkspaceScope,
        observed_at: TimestampMillis,
        limit: ExecutionListLimit,
    ) -> Result<ApprovalExpiryPlan, ControlClientError> {
        self.submit(|response| ForgeControlRequest::ApprovalExpiryPrepare {
            scope,
            observed_at,
            limit,
            response,
        })
    }

    pub(crate) fn apply_approval_expiry_plan(
        &self,
        plan: ApprovalExpiryPlan,
        attempt: ApprovalCleanupAttemptId,
    ) -> Result<ApprovalCleanupApplyOutcome, ControlClientError> {
        self.submit(|response| ForgeControlRequest::ApprovalExpiryApply {
            plan,
            attempt,
            response,
        })
    }

    pub(crate) fn observe_approval_expiry_plan(
        &self,
        plan: ApprovalExpiryPlan,
    ) -> Result<ApprovalCleanupReadback, ControlClientError> {
        self.submit(|response| ForgeControlRequest::ApprovalExpiryObserve { plan, response })
    }

    pub fn diff_list(
        &self,
        request: DiffListRequest,
    ) -> Result<DiffListResult, ControlClientError> {
        self.submit_diff_list(request)?.recv()
    }

    pub fn submit_diff_list(
        &self,
        request: DiffListRequest,
    ) -> Result<PendingControl<DiffListResult>, ControlClientError> {
        self.submit_pending(|response| ForgeControlRequest::DiffList { request, response })
    }

    pub fn diff_read(
        &self,
        request: DiffReadRequest,
    ) -> Result<DiffReadResult, ControlClientError> {
        self.submit_diff_read(request)?.recv()
    }

    pub fn submit_diff_read(
        &self,
        request: DiffReadRequest,
    ) -> Result<PendingControl<DiffReadResult>, ControlClientError> {
        self.submit_pending(|response| ForgeControlRequest::DiffRead { request, response })
    }

    pub fn diff_doctor(
        &self,
        request: DiffDoctorRequest,
    ) -> Result<DiffDoctorResult, ControlClientError> {
        self.submit_diff_doctor(request)?.recv()
    }

    pub fn submit_diff_doctor(
        &self,
        request: DiffDoctorRequest,
    ) -> Result<PendingControl<DiffDoctorResult>, ControlClientError> {
        self.submit_pending(|response| ForgeControlRequest::DiffDoctor { request, response })
    }

    pub fn plan_diff_retention(
        &self,
        request: DiffRetentionPlanRequest,
    ) -> Result<DiffRetentionPlanResult, ControlClientError> {
        self.submit_diff_retention_plan(request)?.recv()
    }

    pub fn submit_diff_retention_plan(
        &self,
        request: DiffRetentionPlanRequest,
    ) -> Result<PendingControl<DiffRetentionPlanResult>, ControlClientError> {
        self.submit_pending(|response| ForgeControlRequest::DiffRetentionPlan { request, response })
    }

    pub fn purge_diff(
        &self,
        request: DiffPurgeRequest,
    ) -> Result<DiffPurgeResult, ControlClientError> {
        self.submit_diff_purge(request)?.recv()
    }

    pub fn submit_diff_purge(
        &self,
        request: DiffPurgeRequest,
    ) -> Result<PendingControl<DiffPurgeResult>, ControlClientError> {
        self.submit_pending(|response| ForgeControlRequest::DiffPurge { request, response })
    }

    pub fn diff_artifact_doctor(
        &self,
        request: DiffArtifactDoctorRequest,
    ) -> Result<DiffArtifactDoctorResult, ControlClientError> {
        self.submit_diff_artifact_doctor(request)?.recv()
    }

    pub fn submit_diff_artifact_doctor(
        &self,
        request: DiffArtifactDoctorRequest,
    ) -> Result<PendingControl<DiffArtifactDoctorResult>, ControlClientError> {
        self.submit_pending(|response| ForgeControlRequest::DiffArtifactDoctor {
            request,
            response,
        })
    }

    pub fn delete_orphan_diff_artifact(
        &self,
        request: DeleteOrphanDiffArtifactRequest,
    ) -> Result<DeleteOrphanDiffArtifactResult, ControlClientError> {
        self.submit_delete_orphan_diff_artifact(request)?.recv()
    }

    pub fn submit_delete_orphan_diff_artifact(
        &self,
        request: DeleteOrphanDiffArtifactRequest,
    ) -> Result<PendingControl<DeleteOrphanDiffArtifactResult>, ControlClientError> {
        self.submit_pending(|response| ForgeControlRequest::DeleteOrphanDiffArtifact {
            request,
            response,
        })
    }

    pub fn submit_workspace_list(
        &self,
        location_id: LocationId,
        expected_revision: LocationRevision,
    ) -> Result<PendingControl<Vec<WorkspaceCatalogEntry>>, ControlClientError> {
        self.submit_pending(|response| ForgeControlRequest::WorkspaceList {
            location_id,
            expected_revision,
            response,
        })
    }

    pub fn submit_workspace_discover(
        &self,
        location_id: LocationId,
        expected_revision: LocationRevision,
    ) -> Result<PendingControl<Vec<WorkspaceDiscoveryEntry>>, ControlClientError> {
        self.submit_pending(|response| ForgeControlRequest::WorkspaceDiscover {
            location_id,
            expected_revision,
            response,
        })
    }

    pub fn submit_resolve_workspace(
        &self,
        location_id: LocationId,
        expected_revision: LocationRevision,
        locator: WorkspaceLocator,
    ) -> Result<PendingControl<ResolvedWorkspaceScope>, ControlClientError> {
        self.submit_pending(|response| ForgeControlRequest::ResolveWorkspace {
            location_id,
            expected_revision,
            locator,
            response,
        })
    }

    pub fn submit_workspace_doctor(
        &self,
        request: WorkspaceDoctorRequest,
    ) -> Result<PendingControl<WorkspaceDoctorResult>, ControlClientError> {
        self.submit_pending(|response| ForgeControlRequest::WorkspaceDoctor { request, response })
    }

    pub fn submit_workspace_identity_doctor(
        &self,
    ) -> Result<PendingControl<WorkspaceIdentityDoctorReport>, ControlClientError> {
        self.submit_pending(|response| ForgeControlRequest::WorkspaceIdentityDoctor { response })
    }

    pub fn submit_bootstrap_activity(
        &self,
        scope: ResolvedWorkspaceScope,
        caller_activity_id: ActivityId,
        runtime_instance_id: RuntimeInstanceId,
        observed_at: TimestampMillis,
        lease_until: TimestampMillis,
    ) -> Result<PendingControl<ActivityBootstrap>, ControlClientError> {
        self.submit_pending(|response| ForgeControlRequest::BootstrapActivity {
            scope,
            caller_activity_id,
            runtime_instance_id,
            observed_at,
            lease_until,
            response,
        })
    }

    pub fn submit_renew_activity_lease(
        &self,
        scope: ResolvedWorkspaceScope,
        activity_id: ActivityId,
        runtime_instance_id: RuntimeInstanceId,
        expected_lease_revision: ActivityLeaseRevision,
        observed_at: TimestampMillis,
        lease_until: TimestampMillis,
    ) -> Result<PendingControl<ActivityLeaseOperation>, ControlClientError> {
        self.submit_pending(|response| ForgeControlRequest::RenewActivityLease {
            scope,
            activity_id,
            runtime_instance_id,
            expected_lease_revision,
            observed_at,
            lease_until,
            response,
        })
    }

    pub fn submit_close_activity(
        &self,
        scope: ResolvedWorkspaceScope,
        activity_id: ActivityId,
        runtime_instance_id: RuntimeInstanceId,
        expected_lease_revision: ActivityLeaseRevision,
    ) -> Result<PendingControl<ActivityLeaseOperation>, ControlClientError> {
        self.submit_pending(|response| ForgeControlRequest::CloseActivity {
            scope,
            activity_id,
            runtime_instance_id,
            expected_lease_revision,
            response,
        })
    }

    pub fn submit_release_activity_lease(
        &self,
        scope: ResolvedWorkspaceScope,
        activity_id: ActivityId,
        runtime_instance_id: RuntimeInstanceId,
        expected_lease_revision: ActivityLeaseRevision,
    ) -> Result<PendingControl<ActivityLeaseOperation>, ControlClientError> {
        self.submit_pending(|response| ForgeControlRequest::ReleaseActivityLease {
            scope,
            activity_id,
            runtime_instance_id,
            expected_lease_revision,
            response,
        })
    }

    pub fn submit_observe_activity_leases(
        &self,
        scope: ResolvedWorkspaceScope,
        activity_ids: Vec<ActivityId>,
    ) -> Result<PendingControl<Vec<RegisteredActivity>>, ControlClientError> {
        if activity_ids.len() > MAX_ACTIVITY_LEASE_OBSERVATION_IDS {
            return Err(ControlClientError::Service(ControlError::new(
                ControlErrorCode::CapacityExceeded,
            )));
        }
        self.submit_pending(|response| ForgeControlRequest::ObserveActivityLeases {
            scope,
            activity_ids,
            response,
        })
    }

    pub fn submit_reconcile_expired_activity_leases(
        &self,
        scope: ResolvedWorkspaceScope,
        observed_at: TimestampMillis,
    ) -> Result<PendingControl<ActivityLeaseOperation>, ControlClientError> {
        self.submit_reconcile_expired_activity_leases_limited(
            scope,
            observed_at,
            ActivityListLimit::DEFAULT,
        )
    }

    pub fn submit_reconcile_expired_activity_leases_limited(
        &self,
        scope: ResolvedWorkspaceScope,
        observed_at: TimestampMillis,
        limit: ActivityListLimit,
    ) -> Result<PendingControl<ActivityLeaseOperation>, ControlClientError> {
        self.submit_pending(
            |response| ForgeControlRequest::ReconcileExpiredActivityLeases {
                scope,
                observed_at,
                limit,
                response,
            },
        )
    }

    pub fn submit_list_activity_projections(
        &self,
        scope: ResolvedWorkspaceScope,
        now: TimestampMillis,
        limit: ActivityListLimit,
    ) -> Result<PendingControl<Vec<ActivityProjection>>, ControlClientError> {
        self.submit_pending(|response| ForgeControlRequest::ListActivityProjections {
            scope,
            now,
            limit,
            response,
        })
    }

    fn submit<T, Build>(&self, build: Build) -> Result<T, ControlClientError>
    where
        Build: FnOnce(Response<T>) -> ForgeControlRequest,
    {
        self.submit_pending(build)?.recv()
    }

    fn submit_pending<T, Build>(
        &self,
        build: Build,
    ) -> Result<PendingControl<T>, ControlClientError>
    where
        Build: FnOnce(Response<T>) -> ForgeControlRequest,
    {
        if !self.accepting.load(Ordering::Acquire) {
            return Err(ControlClientError::WorkerShuttingDown);
        }
        let (response_sender, response_receiver) = mpsc::sync_channel(1);
        let request = build(response_sender);
        match &self.sender {
            ControlSender::ActivityLease(sender) => {
                sender.try_send(request).map_err(|error| match error {
                    TrySendError::Full(_) => ControlClientError::QueueFull,
                    TrySendError::Disconnected(_) => ControlClientError::WorkerClosed,
                })?;
            }
            ControlSender::General(queue) => {
                let class = service_class_for_request(&request);
                let attribution = queue_attribution_for_request(&request);
                queue
                    .try_enqueue_attribution(attribution, class, request, queue_timestamp_micros())
                    .map_err(|error| map_queue_enqueue_error(&error))?;
            }
        }
        Ok(PendingControl::new(response_receiver))
    }
}

fn queue_timestamp_micros() -> heterarchy_orchestration_policy::TimestampMicros {
    let micros = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_micros());
    heterarchy_orchestration_policy::TimestampMicros(u64::try_from(micros).unwrap_or(u64::MAX))
}

fn map_queue_enqueue_error(error: &QueueEnqueueError) -> ControlClientError {
    match error {
        QueueEnqueueError::Rejected
        | QueueEnqueueError::PartitionLimit
        | QueueEnqueueError::CounterOverflow => ControlClientError::QueueFull,
        QueueEnqueueError::Policy => {
            ControlClientError::Service(ControlError::new(ControlErrorCode::InvalidInput))
        }
        QueueEnqueueError::Closed | QueueEnqueueError::Poisoned => ControlClientError::WorkerClosed,
    }
}

/// Exhaustive server-owned routing key. This is deliberately separate from
/// service class so a UI selection can never choose another Workspace's queue.
// Keep each request variant explicit: several arms carry different concrete
// payload types, so merging same-body arms would weaken typed dispatch clarity.
#[allow(clippy::match_same_arms, clippy::too_many_lines)]
fn queue_attribution_for_request(request: &ForgeControlRequest) -> QueueAttribution {
    match request {
        ForgeControlRequest::ExecutionJournalOutput { authority, .. }
        | ForgeControlRequest::ExecutionJournalComplete { authority, .. }
        | ForgeControlRequest::ExecutionJournalCompleteGenerated { authority, .. }
        | ForgeControlRequest::ExecutionJournalFail { authority, .. }
        | ForgeControlRequest::ExecutionJournalReconcileOutput { authority, .. }
        | ForgeControlRequest::ExecutionJournalReconcileTerminal { authority, .. } => {
            QueueAttribution::Workspace(authority.scope().workspace_id())
        }
        ForgeControlRequest::GoalDeletePending { scope, .. } => {
            QueueAttribution::Workspace(scope.workspace_id())
        }
        ForgeControlRequest::GoalDelete { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::AgentAssignmentMutate { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::AgentAssignmentOfferSeal { request, .. }
        | ForgeControlRequest::AgentAssignmentOfferSealGet { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::AgentAssignmentGet { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::AgentBindingReject { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::AgentBindingRejectionRead { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::AgentAssignmentList { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::ActivitySuccessorCreate { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::AgentCoordinationView { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::AgentInboxList { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::AgentBindingReserve { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::AgentBindingReserveReference { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::AgentBindingReservationRead { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::AgentOperationsDelegation { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::AgentOperationsDelegationReference { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::AgentOperationsDelegationRead { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::AgentOperationsFreeze { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::AgentOperationsFreezeRead { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::AgentOperationsExport { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::AgentOperationsFreezeRelease { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::AgentBindingActivate { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::AgentBindingActivateReference { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::AgentBindingActivationRead { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::AgentSessionReconcile { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::AgentSessionReconcileDestination { request, .. } => {
            QueueAttribution::Workspace(request.request.scope.workspace_id())
        }
        ForgeControlRequest::AgentSessionReconciliationRead { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::AgentDepartureReconcile { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::AgentDepartureReconcileDestination { request, .. } => {
            QueueAttribution::Workspace(request.request.scope.workspace_id())
        }
        ForgeControlRequest::AgentDepartureReconciliationRead { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::AgentEffectOutboxRead { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::EffectFactOutboxRead { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::SemanticEventsPage { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::WorkspaceSemanticSnapshot { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::AgentSessionProve { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::AgentSetFocus { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::AgentPublishWorkUpdate { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::AgentList { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::AgentGetContext { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::WriterLeaseAcquire { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::WriterLeaseRenew { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::WriterLeaseRelease { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::WriterLeaseGet { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::WriterLeaseList { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::WriterLeaseRecoveryRelease { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::CoordinatorActor { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::CoordinatorGet { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::CoordinatorClaim { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::CoordinatorTransfer { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::CoordinatorRecoveryPrepare { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::CoordinatorRecoveryConfirm { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::CoordinatorRecoveryReceipt { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::CoordinatorRecoveryHistory { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::AgentDagPlanCommit { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::AgentVerifyExecutionAuthority { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::ProjectCommandResolve { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::ProjectCommandPrepareVerification { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::ProjectCommandList { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::FileRead { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::FileList { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::TextSearch { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::GoalMutation { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::GoalMutationReadback { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::DagPlanReadback { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::SourceTreeReadback { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::FileMutationReadback { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::FileReadSlice { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::FileApplyPatch { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::SourceTreeApply { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::FileMutate { request, .. }
        | ForgeControlRequest::FileImportBinary { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::ExecutionGetEvidence { request, .. }
        | ForgeControlRequest::ExecutionGetAuthorized { request, .. }
        | ForgeControlRequest::ExecutionOutputReadAuthorized { request, .. }
        | ForgeControlRequest::ExecutionReadAuthorized { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::GoalReviseContract { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::GoalTransition { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::GoalComplete { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::DagNodeStart { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::DagNodeComplete { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::DagNodeUpdate { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::RecoveryMaintenanceRun { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::LeadershipWorkCut { command, .. } => {
            QueueAttribution::Workspace(command.scope.workspace_id())
        }
        ForgeControlRequest::RecoveryMaintenanceDurable { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::CheckpointRestoreRun { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::ReplaceWorkspacePolicy { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::ApprovalCreate { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::ApprovalApproveOnce { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::ApprovalDecide { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::AutoApprovalScopeCreate { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::AutoApprovalScopeRevoke { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::ApprovalGrantConsume { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::AutoApprovalConsume { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::ApprovalCleanupPermitMint { scope, .. } => {
            QueueAttribution::Workspace(scope.workspace_id())
        }
        ForgeControlRequest::ApprovalCleanupPrepare { permit, .. } => {
            QueueAttribution::Workspace(permit.scope().workspace_id())
        }
        ForgeControlRequest::ApprovalCleanupApply { plan, .. }
        | ForgeControlRequest::ApprovalCleanupObserve { plan, .. } => {
            QueueAttribution::Workspace(plan.permit().scope().workspace_id())
        }
        ForgeControlRequest::ExecutionStopPrepare { scope, .. } => {
            QueueAttribution::Workspace(scope.workspace_id())
        }
        ForgeControlRequest::OwnedExecutionStopSettle { settlement, .. } => {
            QueueAttribution::Workspace(settlement.context().scope().workspace_id())
        }
        ForgeControlRequest::OwnedExecutionStopHistory { permit, .. }
        | ForgeControlRequest::OwnedExecutionStopPrepare { permit, .. } => {
            QueueAttribution::Workspace(permit.scope().workspace_id())
        }
        ForgeControlRequest::OwnedExecutionStopApply { context, .. }
        | ForgeControlRequest::OwnedExecutionStopObserve { context, .. } => {
            QueueAttribution::Workspace(context.scope().workspace_id())
        }
        ForgeControlRequest::ExecutionStopApply { context, .. }
        | ForgeControlRequest::ExecutionStopObserve { context, .. } => {
            QueueAttribution::Workspace(context.scope().workspace_id())
        }
        ForgeControlRequest::ApprovalExpiryPrepare { scope, .. } => {
            QueueAttribution::Workspace(scope.workspace_id())
        }
        ForgeControlRequest::ApprovalExpiryApply { plan, .. }
        | ForgeControlRequest::ApprovalExpiryObserve { plan, .. } => {
            QueueAttribution::Workspace(plan.scope().workspace_id())
        }
        ForgeControlRequest::DiffList { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::DiffRead { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::DiffDoctor { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::DiffRetentionPlan { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::DiffPurge { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::DiffArtifactDoctor { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::DeleteOrphanDiffArtifact { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::ActivitySuccessorGet { scope, .. }
        | ForgeControlRequest::ExpiredActivityRecoveryProbe {
            request: crate::activity_recovery::ExpiredActivityRecoveryProbeRequest { scope, .. },
            ..
        }
        | ForgeControlRequest::ExpiredActivityRecoveryRun {
            request: crate::activity_recovery::DurableExpiredActivityRecoveryRequest { scope, .. },
            ..
        }
        | ForgeControlRequest::ExpiredActivityRecoveryGet {
            request: crate::activity_recovery::ExpiredActivityRecoveryGetRequest { scope, .. },
            ..
        }
        | ForgeControlRequest::UnstartedActivityContinuationProbe {
            request:
                crate::unstarted_activity_continuation::UnstartedActivityContinuationProbeRequest {
                    scope,
                    ..
                },
            ..
        }
        | ForgeControlRequest::UnstartedActivityContinuationRun {
            request:
                crate::unstarted_activity_continuation::DurableUnstartedActivityContinuationRequest {
                    scope,
                    ..
                },
            ..
        }
        | ForgeControlRequest::UnstartedActivityContinuationGet {
            request:
                crate::unstarted_activity_continuation::UnstartedActivityContinuationGetRequest {
                    scope,
                    ..
                },
            ..
        }
        | ForgeControlRequest::StartedActivityLeaseResumeProbe {
            request:
                crate::started_activity_lease_resume::StartedActivityLeaseResumeProbeRequest {
                    scope,
                    ..
                },
            ..
        }
        | ForgeControlRequest::StartedActivityLeaseResumeRun {
            request:
                crate::started_activity_lease_resume::StartedActivityLeaseResumeRunRequest {
                    scope, ..
                },
            ..
        }
        | ForgeControlRequest::StartedActivityLeaseResumeGet {
            request:
                crate::started_activity_lease_resume::StartedActivityLeaseResumeGetRequest {
                    scope, ..
                },
            ..
        }
        | ForgeControlRequest::QuiescentActivityLeaseResumeProbe {
            request:
                crate::quiescent_activity_lease_resume::QuiescentActivityLeaseResumeProbeRequest {
                    scope,
                    ..
                },
            ..
        }
        | ForgeControlRequest::QuiescentActivityLeaseResumeRun {
            request:
                crate::quiescent_activity_lease_resume::QuiescentActivityLeaseResumeRunRequest {
                    scope,
                    ..
                },
            ..
        }
        | ForgeControlRequest::QuiescentActivityLeaseResumeGet {
            request:
                crate::quiescent_activity_lease_resume::QuiescentActivityLeaseResumeGetRequest {
                    scope,
                    ..
                },
            ..
        }
        | ForgeControlRequest::AuthorizeActivity { scope, .. }
        | ForgeControlRequest::BootstrapActivity { scope, .. }
        | ForgeControlRequest::RenewActivityLease { scope, .. }
        | ForgeControlRequest::RenewActivityLeaseBatch { scope, .. }
        | ForgeControlRequest::SupervisedActivityLeaseRenew {
            request: SupervisedActivityLeaseRenewRequest { scope, .. },
            ..
        }
        | ForgeControlRequest::CloseActivity { scope, .. }
        | ForgeControlRequest::CloseOwnedActivityBatch { scope, .. }
        | ForgeControlRequest::ReleaseActivityLease { scope, .. }
        | ForgeControlRequest::ReleaseActivityLeaseBatch { scope, .. }
        | ForgeControlRequest::ObserveActivityLeases { scope, .. }
        | ForgeControlRequest::ReconcileExpiredActivityLeases { scope, .. }
        | ForgeControlRequest::ListActivityProjections { scope, .. }
        | ForgeControlRequest::WorkspaceVerificationPrepare { scope, .. }
        | ForgeControlRequest::GeneratedArtifactInventory { scope, .. }
        | ForgeControlRequest::GeneratedPackageAccess { scope, .. }
        | ForgeControlRequest::ExecutionMarkRunning { scope, .. }
        | ForgeControlRequest::ExecutionCompleteGenerated { scope, .. }
        | ForgeControlRequest::ExecutionComplete { scope, .. }
        | ForgeControlRequest::ExecutionFail { scope, .. }
        | ForgeControlRequest::ExecutionReconcile { scope, .. }
        | ForgeControlRequest::ExecutionGet { scope, .. }
        | ForgeControlRequest::VerificationProjection { scope, .. }
        | ForgeControlRequest::ExecutionEvidenceInventory { scope, .. }
        | ForgeControlRequest::ExecutionEvidenceRead { scope, .. }
        | ForgeControlRequest::ExecutionGeneratedPackage { scope, .. }
        | ForgeControlRequest::ExecutionList { scope, .. }
        | ForgeControlRequest::ExecutionOutputAppendBatch { scope, .. }
        | ForgeControlRequest::ExecutionOutputRead { scope, .. }
        | ForgeControlRequest::GoalCreate { scope, .. }
        | ForgeControlRequest::GoalGet { scope, .. }
        | ForgeControlRequest::GoalList { scope, .. }
        | ForgeControlRequest::GoalReview { scope, .. }
        | ForgeControlRequest::DagGetCurrent { scope, .. }
        | ForgeControlRequest::DagGetRevision { scope, .. }
        | ForgeControlRequest::DagNodeAssignmentSnapshot { scope, .. }
        | ForgeControlRequest::RecoveryLeaseGet { scope, .. }
        | ForgeControlRequest::RecoveryMaintenanceGet { scope, .. }
        | ForgeControlRequest::RecoveryLeaseClaim { scope, .. }
        | ForgeControlRequest::RecoveryLeaseRenew { scope, .. }
        | ForgeControlRequest::RecoveryLeaseRelease { scope, .. }
        | ForgeControlRequest::EnsureWorkspacePolicy { scope, .. }
        | ForgeControlRequest::GetWorkspacePolicy { scope, .. }
        | ForgeControlRequest::AutoApprovalScopeGet { scope, .. }
        | ForgeControlRequest::ApprovalListPending { scope, .. }
        | ForgeControlRequest::ApprovalGet { scope, .. }
        | ForgeControlRequest::ApprovalGetWithGrant { scope, .. }
        | ForgeControlRequest::WorkspaceDoctor {
            request: WorkspaceDoctorRequest { scope },
            ..
        }
        | ForgeControlRequest::WorkspaceQueueSettingsGet { scope, .. } => {
            QueueAttribution::Workspace(scope.workspace_id())
        }
        ForgeControlRequest::ActivityRead { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::ListWorkspaceActivityProjections { request, .. } => {
            QueueAttribution::Workspace(request.expected_workspace_id)
        }
        ForgeControlRequest::WorkspaceQueueSettingsReplace { request, .. } => {
            QueueAttribution::Workspace(request.scope.workspace_id())
        }
        ForgeControlRequest::RegisterWorkspace { request, .. } => {
            QueueAttribution::Location(request.locator().location_id())
        }
        ForgeControlRequest::ProbeWorkspaceRegistration { locator, .. } => {
            QueueAttribution::Location(locator.location_id())
        }
        ForgeControlRequest::WorkspaceRootRecoveryProbe { request, .. } => {
            QueueAttribution::Location(request.locator().location_id())
        }
        ForgeControlRequest::WorkspaceRootRecoveryPrepare { request, .. } => {
            QueueAttribution::Location(request.locator().location_id())
        }
        ForgeControlRequest::WorkspaceRootRecoveryCommit { request, .. } => {
            QueueAttribution::Location(request.locator().location_id())
        }
        ForgeControlRequest::WorkspaceRootRecoveryReadback { request, .. } => {
            QueueAttribution::Location(request.locator().location_id())
        }
        ForgeControlRequest::WorkspaceInventory { location_id, .. }
        | ForgeControlRequest::WorkspaceList { location_id, .. }
        | ForgeControlRequest::WorkspaceDiscover { location_id, .. }
        | ForgeControlRequest::ResolveWorkspace { location_id, .. } => {
            QueueAttribution::Location(*location_id)
        }
        ForgeControlRequest::LocationList { .. }
        | ForgeControlRequest::RegisterLocation { .. }
        | ForgeControlRequest::SetLocationState { .. }
        | ForgeControlRequest::AgentSessionOpen { .. }
        | ForgeControlRequest::AgentSessionResolve { .. }
        | ForgeControlRequest::WorkspaceIdentityDoctor { .. }
        | ForgeControlRequest::Shutdown { .. } => QueueAttribution::Global,
        ForgeControlRequest::LocationRemovalProbe { id, .. } => QueueAttribution::Location(*id),
        ForgeControlRequest::LocationRemove { request, .. } => {
            QueueAttribution::Location(request.id())
        }
    }
}

/// Exhaustive server-owned request classification. Keep every request variant
/// in this match so adding a control authority forces a queue-policy review.
#[allow(clippy::too_many_lines)]
fn service_class_for_request(request: &ForgeControlRequest) -> ServiceClass {
    use ServiceClass::{AuthorityControl, Background, Interactive, Liveness, Work};
    match request {
        ForgeControlRequest::BootstrapActivity { .. }
        | ForgeControlRequest::RenewActivityLease { .. }
        | ForgeControlRequest::RenewActivityLeaseBatch { .. }
        | ForgeControlRequest::SupervisedActivityLeaseRenew { .. }
        | ForgeControlRequest::CloseActivity { .. }
        | ForgeControlRequest::CloseOwnedActivityBatch { .. }
        | ForgeControlRequest::ReleaseActivityLease { .. }
        | ForgeControlRequest::ReleaseActivityLeaseBatch { .. }
        | ForgeControlRequest::ObserveActivityLeases { .. }
        | ForgeControlRequest::ReconcileExpiredActivityLeases { .. }
        | ForgeControlRequest::ListActivityProjections { .. }
        | ForgeControlRequest::ListWorkspaceActivityProjections { .. }
        | ForgeControlRequest::ActivityRead { .. } => Liveness,
        ForgeControlRequest::AuthorizeActivity { .. }
        | ForgeControlRequest::AgentCoordinationView { .. }
        | ForgeControlRequest::AgentInboxList { .. }
        | ForgeControlRequest::AgentSessionOpen { .. }
        | ForgeControlRequest::AgentSessionResolve { .. }
        | ForgeControlRequest::AgentBindingReserve { .. }
        | ForgeControlRequest::AgentBindingReserveReference { .. }
        | ForgeControlRequest::AgentBindingReservationRead { .. }
        | ForgeControlRequest::AgentOperationsDelegation { .. }
        | ForgeControlRequest::AgentOperationsDelegationReference { .. }
        | ForgeControlRequest::AgentOperationsDelegationRead { .. }
        | ForgeControlRequest::AgentOperationsFreeze { .. }
        | ForgeControlRequest::AgentOperationsFreezeRead { .. }
        | ForgeControlRequest::AgentOperationsExport { .. }
        | ForgeControlRequest::AgentOperationsFreezeRelease { .. }
        | ForgeControlRequest::AgentBindingActivate { .. }
        | ForgeControlRequest::AgentBindingActivateReference { .. }
        | ForgeControlRequest::AgentBindingActivationRead { .. }
        | ForgeControlRequest::AgentBindingReject { .. }
        | ForgeControlRequest::AgentBindingRejectionRead { .. }
        | ForgeControlRequest::AgentSessionReconcile { .. }
        | ForgeControlRequest::AgentSessionReconcileDestination { .. }
        | ForgeControlRequest::AgentSessionReconciliationRead { .. }
        | ForgeControlRequest::AgentDepartureReconcile { .. }
        | ForgeControlRequest::AgentDepartureReconcileDestination { .. }
        | ForgeControlRequest::AgentDepartureReconciliationRead { .. }
        | ForgeControlRequest::AgentEffectOutboxRead { .. }
        | ForgeControlRequest::EffectFactOutboxRead { .. }
        | ForgeControlRequest::SemanticEventsPage { .. }
        | ForgeControlRequest::WorkspaceSemanticSnapshot { .. }
        | ForgeControlRequest::AgentSessionProve { .. }
        | ForgeControlRequest::AgentSetFocus { .. }
        | ForgeControlRequest::AgentAssignmentMutate { .. }
        | ForgeControlRequest::AgentAssignmentOfferSeal { .. }
        | ForgeControlRequest::AgentAssignmentOfferSealGet { .. }
        | ForgeControlRequest::AgentPublishWorkUpdate { .. }
        | ForgeControlRequest::WriterLeaseAcquire { .. }
        | ForgeControlRequest::WriterLeaseRenew { .. }
        | ForgeControlRequest::WriterLeaseRelease { .. }
        | ForgeControlRequest::WriterLeaseGet { .. }
        | ForgeControlRequest::WriterLeaseList { .. }
        | ForgeControlRequest::WriterLeaseRecoveryRelease { .. }
        | ForgeControlRequest::CoordinatorActor { .. }
        | ForgeControlRequest::CoordinatorGet { .. }
        | ForgeControlRequest::CoordinatorClaim { .. }
        | ForgeControlRequest::CoordinatorTransfer { .. }
        | ForgeControlRequest::CoordinatorRecoveryConfirm { .. }
        | ForgeControlRequest::AgentDagPlanCommit { .. }
        | ForgeControlRequest::ActivitySuccessorCreate { .. }
        | ForgeControlRequest::AgentVerifyExecutionAuthority { .. }
        | ForgeControlRequest::ExecutionGetEvidence { .. }
        | ForgeControlRequest::ExecutionGetAuthorized { .. }
        | ForgeControlRequest::EnsureWorkspacePolicy { .. }
        | ForgeControlRequest::GetWorkspacePolicy { .. }
        | ForgeControlRequest::ReplaceWorkspacePolicy { .. }
        | ForgeControlRequest::WorkspaceQueueSettingsGet { .. }
        | ForgeControlRequest::WorkspaceQueueSettingsReplace { .. }
        | ForgeControlRequest::GoalDelete { .. }
        | ForgeControlRequest::GoalDeletePending { .. }
        | ForgeControlRequest::ApprovalCreate { .. }
        | ForgeControlRequest::ApprovalApproveOnce { .. }
        | ForgeControlRequest::ApprovalDecide { .. }
        | ForgeControlRequest::AutoApprovalScopeCreate { .. }
        | ForgeControlRequest::AutoApprovalScopeRevoke { .. }
        | ForgeControlRequest::AutoApprovalScopeGet { .. }
        | ForgeControlRequest::ApprovalGrantConsume { .. }
        | ForgeControlRequest::AutoApprovalConsume { .. }
        | ForgeControlRequest::ApprovalCleanupPermitMint { .. }
        | ForgeControlRequest::ApprovalCleanupPrepare { .. }
        | ForgeControlRequest::ApprovalCleanupApply { .. }
        | ForgeControlRequest::ApprovalCleanupObserve { .. }
        | ForgeControlRequest::ApprovalExpiryPrepare { .. }
        | ForgeControlRequest::ApprovalExpiryApply { .. }
        | ForgeControlRequest::ApprovalExpiryObserve { .. }
        | ForgeControlRequest::ExecutionStopPrepare { .. }
        | ForgeControlRequest::ExecutionStopApply { .. }
        | ForgeControlRequest::ExecutionStopObserve { .. }
        | ForgeControlRequest::OwnedExecutionStopPrepare { .. }
        | ForgeControlRequest::OwnedExecutionStopApply { .. }
        | ForgeControlRequest::OwnedExecutionStopObserve { .. }
        | ForgeControlRequest::OwnedExecutionStopSettle { .. }
        | ForgeControlRequest::OwnedExecutionStopHistory { .. }
        | ForgeControlRequest::WorkspaceRootRecoveryPrepare { .. }
        | ForgeControlRequest::WorkspaceRootRecoveryCommit { .. } => AuthorityControl,
        ForgeControlRequest::LocationRemovalProbe { .. }
        | ForgeControlRequest::LocationList { .. }
        | ForgeControlRequest::RegisterLocation { .. }
        | ForgeControlRequest::SetLocationState { .. }
        | ForgeControlRequest::RegisterWorkspace { .. }
        | ForgeControlRequest::ProbeWorkspaceRegistration { .. }
        | ForgeControlRequest::WorkspaceRootRecoveryProbe { .. }
        | ForgeControlRequest::WorkspaceRootRecoveryReadback { .. }
        | ForgeControlRequest::WorkspaceInventory { .. }
        | ForgeControlRequest::WorkspaceList { .. }
        | ForgeControlRequest::WorkspaceDiscover { .. }
        | ForgeControlRequest::ResolveWorkspace { .. }
        | ForgeControlRequest::WorkspaceDoctor { .. }
        | ForgeControlRequest::WorkspaceIdentityDoctor { .. }
        | ForgeControlRequest::AgentList { .. }
        | ForgeControlRequest::AgentAssignmentGet { .. }
        | ForgeControlRequest::AgentAssignmentList { .. }
        | ForgeControlRequest::AgentGetContext { .. }
        | ForgeControlRequest::ProjectCommandList { .. }
        | ForgeControlRequest::FileRead { .. }
        | ForgeControlRequest::FileList { .. }
        | ForgeControlRequest::FileReadSlice { .. }
        | ForgeControlRequest::FileMutationReadback { .. }
        | ForgeControlRequest::SourceTreeReadback { .. }
        | ForgeControlRequest::GoalMutationReadback { .. }
        | ForgeControlRequest::DagPlanReadback { .. }
        | ForgeControlRequest::ExecutionGet { .. }
        | ForgeControlRequest::ExecutionList { .. }
        | ForgeControlRequest::ExecutionOutputRead { .. }
        | ForgeControlRequest::ExecutionOutputReadAuthorized { .. }
        | ForgeControlRequest::ExecutionReadAuthorized { .. }
        | ForgeControlRequest::VerificationProjection { .. }
        | ForgeControlRequest::ExecutionEvidenceInventory { .. }
        | ForgeControlRequest::ExecutionEvidenceRead { .. }
        | ForgeControlRequest::GoalGet { .. }
        | ForgeControlRequest::GoalList { .. }
        | ForgeControlRequest::GoalReview { .. }
        | ForgeControlRequest::DagGetCurrent { .. }
        | ForgeControlRequest::DagGetRevision { .. }
        | ForgeControlRequest::DagNodeAssignmentSnapshot { .. }
        | ForgeControlRequest::ActivitySuccessorGet { .. }
        | ForgeControlRequest::ExpiredActivityRecoveryProbe { .. }
        | ForgeControlRequest::ExpiredActivityRecoveryRun { .. }
        | ForgeControlRequest::ExpiredActivityRecoveryGet { .. }
        | ForgeControlRequest::UnstartedActivityContinuationProbe { .. }
        | ForgeControlRequest::UnstartedActivityContinuationRun { .. }
        | ForgeControlRequest::UnstartedActivityContinuationGet { .. }
        | ForgeControlRequest::StartedActivityLeaseResumeProbe { .. }
        | ForgeControlRequest::StartedActivityLeaseResumeRun { .. }
        | ForgeControlRequest::StartedActivityLeaseResumeGet { .. }
        | ForgeControlRequest::QuiescentActivityLeaseResumeProbe { .. }
        | ForgeControlRequest::QuiescentActivityLeaseResumeRun { .. }
        | ForgeControlRequest::QuiescentActivityLeaseResumeGet { .. }
        | ForgeControlRequest::CoordinatorRecoveryPrepare { .. }
        | ForgeControlRequest::CoordinatorRecoveryReceipt { .. }
        | ForgeControlRequest::CoordinatorRecoveryHistory { .. }
        | ForgeControlRequest::DiffList { .. }
        | ForgeControlRequest::DiffRead { .. } => Interactive,
        ForgeControlRequest::LocationRemove { .. }
        | ForgeControlRequest::ProjectCommandResolve { .. }
        | ForgeControlRequest::ProjectCommandPrepareVerification { .. }
        | ForgeControlRequest::WorkspaceVerificationPrepare { .. }
        | ForgeControlRequest::FileApplyPatch { .. }
        | ForgeControlRequest::SourceTreeApply { .. }
        | ForgeControlRequest::FileImportBinary { .. }
        | ForgeControlRequest::FileMutate { .. }
        | ForgeControlRequest::ExecutionMarkRunning { .. }
        | ForgeControlRequest::ExecutionCompleteGenerated { .. }
        | ForgeControlRequest::ExecutionComplete { .. }
        | ForgeControlRequest::ExecutionJournalOutput { .. }
        | ForgeControlRequest::ExecutionJournalComplete { .. }
        | ForgeControlRequest::ExecutionJournalCompleteGenerated { .. }
        | ForgeControlRequest::ExecutionJournalFail { .. }
        | ForgeControlRequest::ExecutionJournalReconcileOutput { .. }
        | ForgeControlRequest::ExecutionJournalReconcileTerminal { .. }
        | ForgeControlRequest::ExecutionFail { .. }
        | ForgeControlRequest::ExecutionReconcile { .. }
        | ForgeControlRequest::ExecutionGeneratedPackage { .. }
        | ForgeControlRequest::ExecutionOutputAppendBatch { .. }
        | ForgeControlRequest::GoalCreate { .. }
        | ForgeControlRequest::GoalMutation { .. }
        | ForgeControlRequest::GoalReviseContract { .. }
        | ForgeControlRequest::GoalTransition { .. }
        | ForgeControlRequest::GoalComplete { .. }
        | ForgeControlRequest::DagNodeStart { .. }
        | ForgeControlRequest::DagNodeComplete { .. }
        | ForgeControlRequest::DagNodeUpdate { .. }
        | ForgeControlRequest::CheckpointRestoreRun { .. }
        | ForgeControlRequest::GeneratedPackageAccess { .. } => Work,
        ForgeControlRequest::TextSearch { .. }
        | ForgeControlRequest::GeneratedArtifactInventory { .. }
        | ForgeControlRequest::RecoveryLeaseGet { .. }
        | ForgeControlRequest::RecoveryLeaseClaim { .. }
        | ForgeControlRequest::RecoveryLeaseRenew { .. }
        | ForgeControlRequest::RecoveryLeaseRelease { .. }
        | ForgeControlRequest::RecoveryMaintenanceRun { .. }
        | ForgeControlRequest::LeadershipWorkCut { .. }
        | ForgeControlRequest::RecoveryMaintenanceDurable { .. }
        | ForgeControlRequest::RecoveryMaintenanceGet { .. }
        | ForgeControlRequest::ApprovalListPending { .. }
        | ForgeControlRequest::ApprovalGet { .. }
        | ForgeControlRequest::ApprovalGetWithGrant { .. }
        | ForgeControlRequest::DiffDoctor { .. }
        | ForgeControlRequest::DiffRetentionPlan { .. }
        | ForgeControlRequest::DiffPurge { .. }
        | ForgeControlRequest::DiffArtifactDoctor { .. }
        | ForgeControlRequest::DeleteOrphanDiffArtifact { .. }
        | ForgeControlRequest::Shutdown { .. } => Background,
    }
}

/// Narrow client for Activity lease lifecycle operations.
///
/// This type intentionally does not expose the general control request
/// surface.  It is created only by [`ForgeControlWorker::start_activity_lease`]
/// and must be backed by the separately owned worker returned alongside it.
/// Scope, owner, and lease revisions continue to be validated by the same
/// durable [`ForgeControl`] service and Workspace CAS as general requests.
#[derive(Debug, Clone)]
pub struct ActivityLeaseClient {
    client: ForgeControlClient,
}

impl ActivityLeaseClient {
    fn new(client: ForgeControlClient) -> Self {
        Self { client }
    }

    /// Bootstrap one caller-selected Activity through the dedicated lease
    /// lane so a long-running general control request cannot delay lease
    /// acquisition behind unrelated work.
    pub fn bootstrap_activity(
        &self,
        scope: ResolvedWorkspaceScope,
        caller_activity_id: ActivityId,
        runtime_instance_id: RuntimeInstanceId,
        observed_at: TimestampMillis,
        lease_until: TimestampMillis,
    ) -> Result<ActivityBootstrap, ControlClientError> {
        self.client.bootstrap_activity(
            scope,
            caller_activity_id,
            runtime_instance_id,
            observed_at,
            lease_until,
        )
    }

    /// Renew one bounded batch of caller-owned Activity leases.
    pub fn renew_activity_lease_batch(
        &self,
        scope: ResolvedWorkspaceScope,
        commands: Vec<RenewActivityLease>,
    ) -> Result<ActivityLeaseOperation, ControlClientError> {
        self.client.renew_activity_lease_batch(scope, commands)
    }

    pub fn renew_supervised_activity_lease(
        &self,
        request: SupervisedActivityLeaseRenewRequest,
    ) -> Result<ActivityLeaseOperation, ControlClientError> {
        self.client.renew_supervised_activity_lease(request)
    }

    /// Release one bounded batch of caller-owned Activity leases.
    pub fn release_activity_lease_batch(
        &self,
        scope: ResolvedWorkspaceScope,
        commands: Vec<ReleaseActivityLease>,
    ) -> Result<ActivityLeaseOperation, ControlClientError> {
        self.client.release_activity_lease_batch(scope, commands)
    }

    /// Read exact durable Activity rows for observational tracker reconciliation.
    pub fn observe_activity_leases(
        &self,
        scope: ResolvedWorkspaceScope,
        activity_ids: Vec<ActivityId>,
    ) -> Result<Vec<RegisteredActivity>, ControlClientError> {
        self.client.observe_activity_leases(scope, activity_ids)
    }

    /// Close one bounded batch of caller-owned Activity leases.
    pub fn close_owned_activity_batch(
        &self,
        scope: ResolvedWorkspaceScope,
        commands: Vec<CloseActivity>,
    ) -> Result<ActivityLeaseOperation, ControlClientError> {
        self.client.close_owned_activity_batch(scope, commands)
    }

    /// Report whether the dedicated worker is still accepting lease work.
    pub fn is_accepting(&self) -> bool {
        self.client.accepting.load(Ordering::Acquire)
    }
}

/// Owner of one control service thread and its bounded queue.
#[derive(Debug)]
pub struct ForgeControlWorker {
    queue: Option<QueueMailbox<ForgeControlRequest>>,
    shutdown_sender: SyncSender<ForgeControlRequest>,
    accepting: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl ForgeControlWorker {
    /// Start a single-owner worker with a queue bounded to 128 requests.
    pub fn start(control: ForgeControl) -> Result<(ForgeControlClient, Self), ControlWorkerError> {
        let queue = QueueMailbox::new();
        let (shutdown_sender, shutdown_receiver) = mpsc::sync_channel(1);
        let accepting = Arc::new(AtomicBool::new(true));
        let worker_accepting = Arc::clone(&accepting);
        let worker_queue = queue.clone();
        let join = thread::Builder::new()
            .name(WORKER_THREAD_NAME.to_owned())
            .spawn(move || {
                WorkerRuntime {
                    control,
                    ingress: WorkerIngress::General(worker_queue),
                    shutdown_receiver: Some(shutdown_receiver),
                    accepting: worker_accepting,
                }
                .run();
            })
            .map_err(|_| ControlWorkerError::WorkerClosed)?;
        let sender = ControlSender::General(queue.clone());
        let client = ForgeControlClient::new(sender.clone(), Arc::clone(&accepting));
        Ok((
            client,
            Self {
                queue: Some(queue),
                shutdown_sender,
                accepting,
                join: Some(join),
            },
        ))
    }

    /// Start the dedicated bounded Activity lease worker.
    ///
    /// The returned [`ActivityLeaseClient`] is the only request handle exposed
    /// for this lane.  Callers must retain the returned worker for as long as
    /// the client is in use; dropping or shutting it down makes subsequent
    /// lease operations fail closed through [`ControlClientError`].
    pub fn start_activity_lease(
        control: ForgeControl,
    ) -> Result<(ActivityLeaseClient, Self), ControlWorkerError> {
        let (sender, receiver) = mpsc::sync_channel(ACTIVITY_LEASE_QUEUE_CAPACITY);
        let accepting = Arc::new(AtomicBool::new(true));
        let worker_accepting = Arc::clone(&accepting);
        let join = thread::Builder::new()
            .name(ACTIVITY_LEASE_WORKER_THREAD_NAME.to_owned())
            .spawn(move || {
                WorkerRuntime {
                    control,
                    ingress: WorkerIngress::ActivityLease(receiver),
                    shutdown_receiver: None,
                    accepting: worker_accepting,
                }
                .run();
            })
            .map_err(|_| ControlWorkerError::WorkerClosed)?;
        let control_sender = ControlSender::ActivityLease(sender.clone());
        let client = ForgeControlClient::new(control_sender.clone(), Arc::clone(&accepting));
        let client = ActivityLeaseClient::new(client);
        let worker = Self {
            queue: None,
            shutdown_sender: sender,
            accepting,
            join: Some(join),
        };
        Ok((client, worker))
    }

    /// Alias for callers that prefer constructor terminology.
    pub fn spawn(control: ForgeControl) -> Result<(ForgeControlClient, Self), ControlWorkerError> {
        Self::start(control)
    }

    /// Constructor alias preserving the explicit client/owner split.
    pub fn new(control: ForgeControl) -> Result<(ForgeControlClient, Self), ControlWorkerError> {
        Self::start(control)
    }

    pub const fn queue_capacity() -> usize {
        CONTROL_QUEUE_CAPACITY
    }

    pub const fn activity_lease_queue_capacity() -> usize {
        ACTIVITY_LEASE_QUEUE_CAPACITY
    }

    pub fn is_accepting(&self) -> bool {
        self.accepting.load(Ordering::Acquire)
    }

    /// Stop admission, drain/reject queued work, and join the owned thread.
    pub fn shutdown(&mut self) -> Result<(), ControlWorkerError> {
        self.shutdown_owned(Vec::new()).map(|_| ())
    }

    /// Stop admission, close each caller-owned Activity through the same
    /// scope-validated service, drain queued requests, and join the worker.
    pub fn shutdown_owned(
        &mut self,
        owned_activities: Vec<OwnedActivityLease>,
    ) -> Result<ShutdownReport, ControlWorkerError> {
        if owned_activities.len() > MAX_SHUTDOWN_ACTIVITIES {
            return Err(ControlWorkerError::TooManyOwnedActivities);
        }
        self.accepting.store(false, Ordering::Release);
        let Some(join) = self.join.take() else {
            return Err(ControlWorkerError::AlreadyShutdown);
        };
        let (ack_sender, ack_receiver) = mpsc::sync_channel(0);
        if let Some(queue) = &self.queue
            && queue.close().is_err()
        {
            return match join.join() {
                Ok(()) => Err(ControlWorkerError::WorkerClosed),
                Err(_) => Err(ControlWorkerError::JoinFailed),
            };
        }
        if self
            .shutdown_sender
            .send(ForgeControlRequest::Shutdown {
                owned_activities,
                response: Some(ack_sender),
            })
            .is_err()
        {
            return match join.join() {
                Ok(()) => Err(ControlWorkerError::WorkerClosed),
                Err(_) => Err(ControlWorkerError::JoinFailed),
            };
        }
        let Ok(report) = ack_receiver.recv() else {
            return match join.join() {
                Ok(()) => Err(ControlWorkerError::WorkerClosed),
                Err(_) => Err(ControlWorkerError::JoinFailed),
            };
        };
        join.join().map_err(|_| ControlWorkerError::JoinFailed)?;
        Ok(report)
    }
}

impl Drop for ForgeControlWorker {
    fn drop(&mut self) {
        self.accepting.store(false, Ordering::Release);
        let Some(join) = self.join.take() else {
            return;
        };
        // Drop cannot report a lifecycle error, but it must not detach a
        // meaningful worker.  The bounded send and join provide best-effort
        // structured shutdown while preserving ordinary Drop semantics.
        if let Some(queue) = &self.queue {
            let _ = queue.close();
        }
        let _ = self.shutdown_sender.send(ForgeControlRequest::Shutdown {
            owned_activities: Vec::new(),
            response: None,
        });
        let _ = join.join();
    }
}

enum WorkerIngress {
    General(QueueMailbox<ForgeControlRequest>),
    ActivityLease(Receiver<ForgeControlRequest>),
}

struct WorkerRuntime {
    control: ForgeControl,
    ingress: WorkerIngress,
    shutdown_receiver: Option<Receiver<ForgeControlRequest>>,
    accepting: Arc<AtomicBool>,
}

impl WorkerRuntime {
    fn run(self) {
        let Self {
            mut control,
            ingress,
            shutdown_receiver,
            accepting,
        } = self;
        match ingress {
            WorkerIngress::General(queue) => {
                run_general_worker(&mut control, &queue, shutdown_receiver, &accepting);
            }
            WorkerIngress::ActivityLease(receiver) => {
                run_activity_lease_worker(&control, &receiver, &accepting);
            }
        }
        accepting.store(false, Ordering::Release);
    }
}

fn run_general_worker(
    control: &mut ForgeControl,
    queue: &QueueMailbox<ForgeControlRequest>,
    shutdown_receiver: Option<Receiver<ForgeControlRequest>>,
    accepting: &Arc<AtomicBool>,
) {
    let Some(shutdown_receiver) = shutdown_receiver else {
        return;
    };
    let _ = queue.set_active_worker(true);
    loop {
        if let Ok(request) = shutdown_receiver.try_recv() {
            handle_shutdown_request(control, queue, request, accepting);
            break;
        }
        match queue.wait_dequeue(queue_timestamp_micros()) {
            Ok(QueueDequeue::Item { item, .. }) => {
                dispatch_general_request(control, queue, item);
                let _ = queue.finish_dispatch();
            }
            Ok(QueueDequeue::Empty) => {}
            Ok(QueueDequeue::Closed) => {
                if let Ok(request) = shutdown_receiver.recv() {
                    handle_shutdown_request(control, queue, request, accepting);
                }
                break;
            }
            Err(_) => break,
        }
    }
    let _ = queue.set_active_worker(false);
}

fn dispatch_general_request(
    control: &mut ForgeControl,
    queue: &QueueMailbox<ForgeControlRequest>,
    request: ForgeControlRequest,
) {
    match request {
        // Location registration/state transitions are the only requests that
        // need the worker's exclusive (&mut) control ownership.
        ForgeControlRequest::RegisterLocation { request, response } => {
            send_response(&response, control.register_location(request));
        }
        ForgeControlRequest::SetLocationState { command, response } => {
            let result = runtime_timestamp_millis().and_then(|observed_at| {
                let command = SetLocationState::new(
                    command.id(),
                    command.expected_revision(),
                    command.state(),
                    observed_at,
                );
                control.set_location_state(&command)
            });
            send_response(&response, result);
        }
        ForgeControlRequest::LocationRemove { request, response } => {
            let result = runtime_timestamp_millis()
                .and_then(|observed_at| control.location_remove(&request, observed_at));
            send_response(&response, result);
        }
        ForgeControlRequest::RegisterWorkspace { request, response } => {
            send_response(&response, control.register_workspace(&request));
        }
        ForgeControlRequest::WorkspaceRootRecoveryProbe { request, response } => {
            send_response(&response, control.probe_workspace_root_recovery(&request));
        }
        ForgeControlRequest::WorkspaceRootRecoveryPrepare { request, response } => {
            send_response(&response, control.prepare_workspace_root_recovery(&request));
        }
        ForgeControlRequest::WorkspaceRootRecoveryCommit { request, response } => {
            send_response(&response, control.commit_workspace_root_recovery(&request));
        }
        ForgeControlRequest::WorkspaceRootRecoveryReadback { request, response } => {
            send_response(
                &response,
                control.readback_workspace_root_recovery(&request),
            );
        }
        ForgeControlRequest::ResolveWorkspace {
            location_id,
            expected_revision,
            locator,
            response,
        } => dispatch_resolve_workspace(
            control,
            queue,
            location_id,
            expected_revision,
            &locator,
            &response,
        ),
        request => dispatch_request(control, request),
    }
}

fn run_activity_lease_worker(
    control: &ForgeControl,
    receiver: &Receiver<ForgeControlRequest>,
    accepting: &Arc<AtomicBool>,
) {
    while let Ok(request) = receiver.recv() {
        match request {
            ForgeControlRequest::Shutdown {
                owned_activities,
                response,
            } => {
                accepting.store(false, Ordering::Release);
                let report = close_owned_activities(control, owned_activities);
                drain_queued_requests(receiver);
                if let Some(response) = response {
                    let _ignored = response.send(report);
                }
                break;
            }
            request => dispatch_request(control, request),
        }
    }
}

fn handle_shutdown_request(
    control: &ForgeControl,
    queue: &QueueMailbox<ForgeControlRequest>,
    request: ForgeControlRequest,
    accepting: &Arc<AtomicBool>,
) {
    let ForgeControlRequest::Shutdown {
        owned_activities,
        response,
    } = request
    else {
        return;
    };
    accepting.store(false, Ordering::Release);
    let report = close_owned_activities(control, owned_activities);
    drain_queued_queue(queue);
    if let Some(response) = response {
        let _ignored = response.send(report);
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "Exhaustive thin routing keeps every typed request visible; no application policy is implemented in this dispatcher."
)]
fn dispatch_request(control: &ForgeControl, request: ForgeControlRequest) {
    match request {
        ForgeControlRequest::WorkspaceInventory {
            location_id,
            expected_revision,
            response,
        } => {
            send_response(
                &response,
                control.registered_workspace_inventory(location_id, expected_revision),
            );
        }
        ForgeControlRequest::RegisterWorkspace { response, .. } => {
            send_response(
                &response,
                Err(ControlError::new(ControlErrorCode::InvalidInput)),
            );
        }
        ForgeControlRequest::ProbeWorkspaceRegistration { locator, response } => {
            send_response(&response, control.probe_workspace_registration(&locator));
        }
        ForgeControlRequest::WorkspaceRootRecoveryProbe { request, response } => {
            send_response(&response, control.probe_workspace_root_recovery(&request));
        }
        ForgeControlRequest::WorkspaceRootRecoveryPrepare { response, .. } => {
            send_response(
                &response,
                Err(ControlError::new(ControlErrorCode::InvalidInput)),
            );
        }
        ForgeControlRequest::WorkspaceRootRecoveryCommit { response, .. } => {
            send_response(
                &response,
                Err(ControlError::new(ControlErrorCode::InvalidInput)),
            );
        }
        ForgeControlRequest::WorkspaceRootRecoveryReadback { response, .. } => {
            send_response(
                &response,
                Err(ControlError::new(ControlErrorCode::InvalidInput)),
            );
        }
        ForgeControlRequest::GoalDeletePending {
            scope,
            limit,
            response,
        } => send_response(&response, control.goal_delete_pending(&scope, limit)),
        ForgeControlRequest::GoalDelete {
            request,
            product_cache_root,
            response,
        } => send_response(
            &response,
            control.goal_delete(&request, product_cache_root.as_deref()),
        ),
        ForgeControlRequest::LocationList { response } => {
            send_response(&response, control.location_list());
        }
        ForgeControlRequest::LocationRemovalProbe { id, response } => {
            send_response(&response, control.location_removal_probe(id));
        }
        ForgeControlRequest::LocationRemove { response, .. } => {
            send_response(
                &response,
                Err(ControlError::new(ControlErrorCode::InvalidInput)),
            );
        }
        // Location writes are owned by the general worker's exclusive control
        // access; reaching this shared match proves lane misuse.
        ForgeControlRequest::RegisterLocation { response, .. }
        | ForgeControlRequest::SetLocationState { response, .. } => {
            send_response(
                &response,
                Err(ControlError::new(ControlErrorCode::InvalidInput)),
            );
        }
        ForgeControlRequest::WorkspaceList {
            location_id,
            expected_revision,
            response,
        } => send_response(
            &response,
            control.workspace_list(location_id, expected_revision),
        ),
        ForgeControlRequest::WorkspaceDiscover {
            location_id,
            expected_revision,
            response,
        } => send_response(
            &response,
            control.workspace_discover(location_id, expected_revision),
        ),
        ForgeControlRequest::ResolveWorkspace {
            location_id,
            expected_revision,
            locator,
            response,
        } => send_response(
            &response,
            control.resolve_workspace(location_id, expected_revision, &locator),
        ),
        ForgeControlRequest::ActivitySuccessorCreate { request, response } => {
            send_response(&response, control.activity_successor_create(&request));
        }
        ForgeControlRequest::ActivitySuccessorGet {
            scope,
            predecessor_activity_id,
            response,
        } => send_response(
            &response,
            control.activity_successor_get(&scope, predecessor_activity_id),
        ),
        ForgeControlRequest::ExpiredActivityRecoveryProbe { request, response } => {
            send_response(&response, control.expired_activity_recovery_probe(&request));
        }
        ForgeControlRequest::ExpiredActivityRecoveryRun { request, response } => {
            send_response(
                &response,
                control.run_durable_expired_activity_recovery_with_clock(
                    &request,
                    runtime_timestamp_millis,
                ),
            );
        }
        ForgeControlRequest::ExpiredActivityRecoveryGet { request, response } => {
            send_response(&response, control.expired_activity_recovery_get(&request));
        }
        ForgeControlRequest::UnstartedActivityContinuationProbe { request, response } => {
            send_response(
                &response,
                control.unstarted_activity_continuation_probe(&request),
            );
        }
        ForgeControlRequest::UnstartedActivityContinuationRun { request, response } => {
            send_response(
                &response,
                control.run_durable_unstarted_activity_continuation_with_clock(
                    &request,
                    runtime_timestamp_millis,
                ),
            );
        }
        ForgeControlRequest::UnstartedActivityContinuationGet { request, response } => {
            send_response(
                &response,
                control.unstarted_activity_continuation_get(&request),
            );
        }
        ForgeControlRequest::StartedActivityLeaseResumeProbe { request, response } => {
            send_response(
                &response,
                control.started_activity_lease_resume_probe(&request),
            );
        }
        ForgeControlRequest::StartedActivityLeaseResumeRun { request, response } => {
            send_response(
                &response,
                control.started_activity_lease_resume_run_with_clock(
                    &request,
                    runtime_timestamp_millis,
                ),
            );
        }
        ForgeControlRequest::StartedActivityLeaseResumeGet { request, response } => {
            send_response(
                &response,
                control.started_activity_lease_resume_get(&request),
            );
        }
        ForgeControlRequest::QuiescentActivityLeaseResumeProbe { request, response } => {
            send_response(
                &response,
                control.quiescent_activity_lease_resume_probe(&request),
            );
        }
        ForgeControlRequest::QuiescentActivityLeaseResumeRun { request, response } => {
            send_response(
                &response,
                control.run_quiescent_activity_lease_resume_with_clock(
                    &request,
                    runtime_timestamp_millis,
                ),
            );
        }
        ForgeControlRequest::QuiescentActivityLeaseResumeGet { request, response } => {
            send_response(
                &response,
                control.quiescent_activity_lease_resume_get(&request),
            );
        }
        ForgeControlRequest::BootstrapActivity {
            scope,
            caller_activity_id,
            runtime_instance_id,
            observed_at,
            lease_until,
            response,
        } => dispatch_bootstrap_activity(
            control,
            &scope,
            caller_activity_id,
            runtime_instance_id,
            observed_at,
            lease_until,
            &response,
        ),
        ForgeControlRequest::SemanticEventsPage { request, response } => {
            send_response(&response, control.semantic_events_page(&request));
        }
        ForgeControlRequest::WorkspaceSemanticSnapshot { request, response } => {
            send_response(&response, control.workspace_semantic_snapshot(&request));
        }
        request => dispatch_agent_or_activity_request(control, request),
    }
}

fn dispatch_agent_or_activity_request(control: &ForgeControl, request: ForgeControlRequest) {
    match request {
        request @ (ForgeControlRequest::AgentSessionOpen { .. }
        | ForgeControlRequest::AgentCoordinationView { .. }
        | ForgeControlRequest::AgentInboxList { .. }
        | ForgeControlRequest::AgentSessionResolve { .. }
        | ForgeControlRequest::AgentBindingReserve { .. }
        | ForgeControlRequest::AgentBindingReserveReference { .. }
        | ForgeControlRequest::AgentBindingReservationRead { .. }
        | ForgeControlRequest::AgentOperationsDelegation { .. }
        | ForgeControlRequest::AgentOperationsDelegationReference { .. }
        | ForgeControlRequest::AgentOperationsDelegationRead { .. }
        | ForgeControlRequest::AgentOperationsFreeze { .. }
        | ForgeControlRequest::AgentOperationsFreezeRead { .. }
        | ForgeControlRequest::AgentOperationsExport { .. }
        | ForgeControlRequest::AgentOperationsFreezeRelease { .. }
        | ForgeControlRequest::AgentBindingActivate { .. }
        | ForgeControlRequest::AgentBindingActivateReference { .. }
        | ForgeControlRequest::AgentBindingActivationRead { .. }
        | ForgeControlRequest::AgentSessionReconcile { .. }
        | ForgeControlRequest::AgentSessionReconcileDestination { .. }
        | ForgeControlRequest::AgentSessionReconciliationRead { .. }
        | ForgeControlRequest::AgentDepartureReconcile { .. }
        | ForgeControlRequest::AgentDepartureReconcileDestination { .. }
        | ForgeControlRequest::AgentDepartureReconciliationRead { .. }
        | ForgeControlRequest::AgentEffectOutboxRead { .. }
        | ForgeControlRequest::EffectFactOutboxRead { .. }
        | ForgeControlRequest::AgentSessionProve { .. }
        | ForgeControlRequest::AgentSetFocus { .. }
        | ForgeControlRequest::AgentVerifyExecutionAuthority { .. }
        | ForgeControlRequest::AgentAssignmentMutate { .. }
        | ForgeControlRequest::AgentAssignmentOfferSeal { .. }
        | ForgeControlRequest::AgentAssignmentOfferSealGet { .. }
        | ForgeControlRequest::AgentPublishWorkUpdate { .. }
        | ForgeControlRequest::AgentList { .. }
        | ForgeControlRequest::AgentAssignmentGet { .. }
        | ForgeControlRequest::AgentAssignmentList { .. }
        | ForgeControlRequest::AgentGetContext { .. }
        | ForgeControlRequest::WriterLeaseAcquire { .. }
        | ForgeControlRequest::WriterLeaseRenew { .. }
        | ForgeControlRequest::WriterLeaseRelease { .. }
        | ForgeControlRequest::WriterLeaseGet { .. }
        | ForgeControlRequest::WriterLeaseList { .. }
        | ForgeControlRequest::WriterLeaseRecoveryRelease { .. }
        | ForgeControlRequest::AgentDagPlanCommit { .. }
        | ForgeControlRequest::CoordinatorActor { .. }
        | ForgeControlRequest::CoordinatorGet { .. }
        | ForgeControlRequest::CoordinatorClaim { .. }
        | ForgeControlRequest::CoordinatorTransfer { .. }
        | ForgeControlRequest::CoordinatorRecoveryPrepare { .. }
        | ForgeControlRequest::CoordinatorRecoveryConfirm { .. }
        | ForgeControlRequest::CoordinatorRecoveryReceipt { .. }
        | ForgeControlRequest::CoordinatorRecoveryHistory { .. }) => {
            dispatch_agent_request(control, request);
        }
        other => dispatch_activity_request(control, other),
    }
}

fn dispatch_authorize_activity(
    control: &ForgeControl,
    scope: &ResolvedWorkspaceScope,
    mut activity: FileActivityScope,
    response: &Response<()>,
) {
    let result = runtime_timestamp_millis().and_then(|observed_at| {
        activity.observed_at = observed_at;
        control.authorize_activity_request(scope, activity)
    });
    let _ignored = response.send(result);
}

fn dispatch_bootstrap_activity(
    control: &ForgeControl,
    scope: &ResolvedWorkspaceScope,
    caller_activity_id: ActivityId,
    runtime_instance_id: RuntimeInstanceId,
    observed_at: TimestampMillis,
    lease_until: TimestampMillis,
    response: &Response<ActivityBootstrap>,
) {
    let result =
        runtime_lease_window(observed_at, lease_until).and_then(|(observed_at, lease_until)| {
            control.bootstrap_activity(
                scope,
                caller_activity_id,
                runtime_instance_id,
                observed_at,
                lease_until,
            )
        });
    let _ignored = response.send(result);
}

fn dispatch_workspace_doctor(
    control: &ForgeControl,
    request: &WorkspaceDoctorRequest,
    response: &Response<WorkspaceDoctorResult>,
) {
    let _ignored = response.send(control.workspace_doctor(request));
}

fn dispatch_workspace_identity_doctor(
    control: &ForgeControl,
    response: &Response<WorkspaceIdentityDoctorReport>,
) {
    let _ignored = response.send(control.workspace_identity_doctor());
}

fn dispatch_resolve_workspace(
    control: &ForgeControl,
    queue: &QueueMailbox<ForgeControlRequest>,
    location_id: LocationId,
    expected_revision: LocationRevision,
    locator: &WorkspaceLocator,
    response: &Response<ResolvedWorkspaceScope>,
) {
    let result = control
        .resolve_workspace(location_id, expected_revision, locator)
        .and_then(|scope| {
            let settings = control.workspace_queue_settings(&scope)?;
            let preference = settings.map(|saved| (saved.capacity(), saved.revision().get()));
            queue
                .install_workspace_preference(scope.workspace_id(), preference)
                .map_err(|error| map_queue_preference_install_error(&error))?;
            Ok(scope)
        });
    let _ignored = response.send(result);
}

fn map_queue_preference_install_error(error: &QueueConfigError) -> ControlError {
    match error {
        QueueConfigError::StalePersistedRevision { .. }
        | QueueConfigError::PersistedPreferenceConflict => {
            ControlError::new(ControlErrorCode::WorkspaceQueueSettingsConflict)
        }
        QueueConfigError::Closed => ControlError::new(ControlErrorCode::WorkerClosed),
        _ => ControlError::new(ControlErrorCode::CapacityExceeded),
    }
}

#[allow(clippy::too_many_lines)]
fn dispatch_activity_request(control: &ForgeControl, request: ForgeControlRequest) {
    match request {
        request @ (ForgeControlRequest::AgentBindingReject { .. }
        | ForgeControlRequest::AgentBindingRejectionRead { .. }) => {
            dispatch_agent_request(control, request);
        }
        ForgeControlRequest::WorkspaceInventory {
            location_id,
            expected_revision,
            response,
        } => {
            send_response(
                &response,
                control.registered_workspace_inventory(location_id, expected_revision),
            );
        }
        ForgeControlRequest::RegisterWorkspace { response, .. } => {
            send_response(
                &response,
                Err(ControlError::new(ControlErrorCode::InvalidInput)),
            );
        }
        ForgeControlRequest::ProbeWorkspaceRegistration { locator, response } => {
            send_response(&response, control.probe_workspace_registration(&locator));
        }
        ForgeControlRequest::WorkspaceRootRecoveryProbe { response, .. }
        | ForgeControlRequest::WorkspaceRootRecoveryPrepare { response, .. } => {
            send_response(
                &response,
                Err(ControlError::new(ControlErrorCode::InvalidInput)),
            );
        }
        ForgeControlRequest::WorkspaceRootRecoveryCommit { response, .. } => {
            send_response(
                &response,
                Err(ControlError::new(ControlErrorCode::InvalidInput)),
            );
        }
        ForgeControlRequest::WorkspaceRootRecoveryReadback { response, .. } => {
            send_response(
                &response,
                Err(ControlError::new(ControlErrorCode::InvalidInput)),
            );
        }
        ForgeControlRequest::ActivitySuccessorCreate { request, response } => {
            let _ignored = response.send(control.activity_successor_create(&request));
        }
        ForgeControlRequest::ActivitySuccessorGet {
            scope,
            predecessor_activity_id,
            response,
        } => {
            let _ignored =
                response.send(control.activity_successor_get(&scope, predecessor_activity_id));
        }
        ForgeControlRequest::ExpiredActivityRecoveryProbe { request, response } => {
            let _ignored = response.send(control.expired_activity_recovery_probe(&request));
        }
        ForgeControlRequest::ExpiredActivityRecoveryRun { request, response } => {
            let _ignored = response.send(control.run_durable_expired_activity_recovery_with_clock(
                &request,
                runtime_timestamp_millis,
            ));
        }
        ForgeControlRequest::ExpiredActivityRecoveryGet { request, response } => {
            let _ignored = response.send(control.expired_activity_recovery_get(&request));
        }
        ForgeControlRequest::UnstartedActivityContinuationProbe { request, response } => {
            let _ignored = response.send(control.unstarted_activity_continuation_probe(&request));
        }
        ForgeControlRequest::UnstartedActivityContinuationRun { request, response } => {
            let _ignored = response.send(
                control.run_durable_unstarted_activity_continuation_with_clock(
                    &request,
                    runtime_timestamp_millis,
                ),
            );
        }
        ForgeControlRequest::UnstartedActivityContinuationGet { request, response } => {
            let _ignored = response.send(control.unstarted_activity_continuation_get(&request));
        }
        ForgeControlRequest::StartedActivityLeaseResumeProbe { request, response } => {
            let _ignored = response.send(control.started_activity_lease_resume_probe(&request));
        }
        ForgeControlRequest::StartedActivityLeaseResumeRun { request, response } => {
            let _ignored =
                response.send(control.started_activity_lease_resume_run_with_clock(
                    &request,
                    runtime_timestamp_millis,
                ));
        }
        ForgeControlRequest::StartedActivityLeaseResumeGet { request, response } => {
            let _ignored = response.send(control.started_activity_lease_resume_get(&request));
        }
        ForgeControlRequest::QuiescentActivityLeaseResumeProbe { request, response } => {
            let _ignored = response.send(control.quiescent_activity_lease_resume_probe(&request));
        }
        ForgeControlRequest::QuiescentActivityLeaseResumeRun { request, response } => {
            let _ignored = response.send(control.run_quiescent_activity_lease_resume_with_clock(
                &request,
                runtime_timestamp_millis,
            ));
        }
        ForgeControlRequest::QuiescentActivityLeaseResumeGet { request, response } => {
            let _ignored = response.send(control.quiescent_activity_lease_resume_get(&request));
        }
        ForgeControlRequest::SemanticEventsPage { request, response } => {
            let _ignored = response.send(control.semantic_events_page(&request));
        }
        ForgeControlRequest::WorkspaceSemanticSnapshot { request, response } => {
            let _ignored = response.send(control.workspace_semantic_snapshot(&request));
        }
        request @ (ForgeControlRequest::ApprovalCleanupPermitMint { .. }
        | ForgeControlRequest::ApprovalCleanupPrepare { .. }
        | ForgeControlRequest::ApprovalCleanupApply { .. }
        | ForgeControlRequest::ApprovalCleanupObserve { .. }) => {
            dispatch_approval_cleanup_request(control, request);
        }
        request @ (ForgeControlRequest::ExecutionStopPrepare { .. }
        | ForgeControlRequest::ExecutionStopApply { .. }
        | ForgeControlRequest::ExecutionStopObserve { .. }
        | ForgeControlRequest::OwnedExecutionStopPrepare { .. }
        | ForgeControlRequest::OwnedExecutionStopApply { .. }
        | ForgeControlRequest::OwnedExecutionStopObserve { .. }
        | ForgeControlRequest::OwnedExecutionStopSettle { .. }
        | ForgeControlRequest::OwnedExecutionStopHistory { .. }) => {
            dispatch_execution_stop_request(control, request);
        }
        request @ (ForgeControlRequest::ApprovalExpiryPrepare { .. }
        | ForgeControlRequest::ApprovalExpiryApply { .. }
        | ForgeControlRequest::ApprovalExpiryObserve { .. }) => {
            dispatch_approval_expiry_request(control, request);
        }
        ForgeControlRequest::AuthorizeActivity {
            scope,
            activity,
            response,
        } => dispatch_authorize_activity(control, &scope, activity, &response),
        ForgeControlRequest::WorkspaceDoctor { request, response } => {
            dispatch_workspace_doctor(control, &request, &response);
        }
        ForgeControlRequest::WorkspaceIdentityDoctor { response } => {
            dispatch_workspace_identity_doctor(control, &response);
        }
        // Location writes are owned by the general worker's exclusive control
        // access; reaching this lane proves request misuse.
        ForgeControlRequest::RegisterLocation { response, .. }
        | ForgeControlRequest::SetLocationState { response, .. } => {
            send_response(
                &response,
                Err(ControlError::new(ControlErrorCode::InvalidInput)),
            );
        }
        request @ (ForgeControlRequest::LocationList { .. }
        | ForgeControlRequest::LocationRemovalProbe { .. }
        | ForgeControlRequest::LocationRemove { .. }
        | ForgeControlRequest::WorkspaceList { .. }
        | ForgeControlRequest::WorkspaceDiscover { .. }
        | ForgeControlRequest::ResolveWorkspace { .. }
        | ForgeControlRequest::BootstrapActivity { .. }
        | ForgeControlRequest::AgentSessionOpen { .. }
        | ForgeControlRequest::AgentCoordinationView { .. }
        | ForgeControlRequest::AgentInboxList { .. }
        | ForgeControlRequest::AgentSessionResolve { .. }
        | ForgeControlRequest::AgentBindingReserve { .. }
        | ForgeControlRequest::AgentBindingReserveReference { .. }
        | ForgeControlRequest::AgentBindingReservationRead { .. }
        | ForgeControlRequest::AgentOperationsDelegation { .. }
        | ForgeControlRequest::AgentOperationsDelegationReference { .. }
        | ForgeControlRequest::AgentOperationsDelegationRead { .. }
        | ForgeControlRequest::AgentOperationsFreeze { .. }
        | ForgeControlRequest::AgentOperationsFreezeRead { .. }
        | ForgeControlRequest::AgentOperationsExport { .. }
        | ForgeControlRequest::AgentOperationsFreezeRelease { .. }
        | ForgeControlRequest::AgentBindingActivate { .. }
        | ForgeControlRequest::AgentBindingActivateReference { .. }
        | ForgeControlRequest::AgentBindingActivationRead { .. }
        | ForgeControlRequest::AgentSessionReconcile { .. }
        | ForgeControlRequest::AgentSessionReconcileDestination { .. }
        | ForgeControlRequest::AgentSessionReconciliationRead { .. }
        | ForgeControlRequest::AgentDepartureReconcile { .. }
        | ForgeControlRequest::AgentDepartureReconcileDestination { .. }
        | ForgeControlRequest::AgentDepartureReconciliationRead { .. }
        | ForgeControlRequest::AgentEffectOutboxRead { .. }
        | ForgeControlRequest::EffectFactOutboxRead { .. }
        | ForgeControlRequest::AgentSessionProve { .. }
        | ForgeControlRequest::AgentSetFocus { .. }
        | ForgeControlRequest::AgentVerifyExecutionAuthority { .. }
        | ForgeControlRequest::AgentAssignmentMutate { .. }
        | ForgeControlRequest::AgentAssignmentOfferSeal { .. }
        | ForgeControlRequest::AgentAssignmentOfferSealGet { .. }
        | ForgeControlRequest::AgentPublishWorkUpdate { .. }
        | ForgeControlRequest::AgentList { .. }
        | ForgeControlRequest::AgentAssignmentGet { .. }
        | ForgeControlRequest::AgentAssignmentList { .. }
        | ForgeControlRequest::AgentGetContext { .. }
        | ForgeControlRequest::WriterLeaseAcquire { .. }
        | ForgeControlRequest::WriterLeaseRenew { .. }
        | ForgeControlRequest::WriterLeaseRelease { .. }
        | ForgeControlRequest::WriterLeaseGet { .. }
        | ForgeControlRequest::WriterLeaseList { .. }
        | ForgeControlRequest::WriterLeaseRecoveryRelease { .. }
        | ForgeControlRequest::AgentDagPlanCommit { .. }
        | ForgeControlRequest::CoordinatorActor { .. }
        | ForgeControlRequest::CoordinatorGet { .. }
        | ForgeControlRequest::CoordinatorClaim { .. }
        | ForgeControlRequest::CoordinatorTransfer { .. }
        | ForgeControlRequest::CoordinatorRecoveryPrepare { .. }
        | ForgeControlRequest::CoordinatorRecoveryConfirm { .. }
        | ForgeControlRequest::CoordinatorRecoveryReceipt { .. }
        | ForgeControlRequest::CoordinatorRecoveryHistory { .. }) => {
            dispatch_request(control, request);
        }
        ForgeControlRequest::RenewActivityLease {
            scope,
            activity_id,
            runtime_instance_id,
            expected_lease_revision,
            observed_at,
            lease_until,
            response,
        } => {
            let result = runtime_lease_window(observed_at, lease_until).and_then(
                |(observed_at, lease_until)| {
                    control.renew_activity_lease(
                        &scope,
                        activity_id,
                        runtime_instance_id,
                        expected_lease_revision,
                        observed_at,
                        lease_until,
                    )
                },
            );
            let _ignored = response.send(result);
        }
        ForgeControlRequest::SupervisedActivityLeaseRenew {
            mut request,
            response,
        } => {
            let result = rebase_renew_activity_lease(&request.command).and_then(|command| {
                request.command = command;
                control.renew_supervised_activity_lease(&request)
            });
            let _ignored = response.send(result);
        }
        ForgeControlRequest::RenewActivityLeaseBatch { .. }
        | ForgeControlRequest::CloseOwnedActivityBatch { .. }
        | ForgeControlRequest::ReleaseActivityLease { .. }
        | ForgeControlRequest::ReleaseActivityLeaseBatch { .. }
        | ForgeControlRequest::ObserveActivityLeases { .. }
        | ForgeControlRequest::ReconcileExpiredActivityLeases { .. }
        | ForgeControlRequest::ListActivityProjections { .. }
        | ForgeControlRequest::ListWorkspaceActivityProjections { .. }
        | ForgeControlRequest::ActivityRead { .. }
        | ForgeControlRequest::ProjectCommandResolve { .. }
        | ForgeControlRequest::ProjectCommandPrepareVerification { .. }
        | ForgeControlRequest::WorkspaceVerificationPrepare { .. }
        | ForgeControlRequest::ProjectCommandList { .. }
        | ForgeControlRequest::GeneratedArtifactInventory { .. }
        | ForgeControlRequest::GeneratedPackageAccess { .. }
        | ForgeControlRequest::FileRead { .. }
        | ForgeControlRequest::FileList { .. }
        | ForgeControlRequest::TextSearch { .. }
        | ForgeControlRequest::FileReadSlice { .. }
        | ForgeControlRequest::FileMutationReadback { .. }
        | ForgeControlRequest::SourceTreeReadback { .. }
        | ForgeControlRequest::GoalMutationReadback { .. }
        | ForgeControlRequest::DagPlanReadback { .. }
        | ForgeControlRequest::FileApplyPatch { .. }
        | ForgeControlRequest::SourceTreeApply { .. }
        | ForgeControlRequest::FileImportBinary { .. }
        | ForgeControlRequest::FileMutate { .. }
        | ForgeControlRequest::ExecutionMarkRunning { .. }
        | ForgeControlRequest::ExecutionCompleteGenerated { .. }
        | ForgeControlRequest::ExecutionComplete { .. }
        | ForgeControlRequest::ExecutionJournalOutput { .. }
        | ForgeControlRequest::ExecutionJournalComplete { .. }
        | ForgeControlRequest::ExecutionJournalCompleteGenerated { .. }
        | ForgeControlRequest::ExecutionJournalFail { .. }
        | ForgeControlRequest::ExecutionJournalReconcileOutput { .. }
        | ForgeControlRequest::ExecutionJournalReconcileTerminal { .. }
        | ForgeControlRequest::ExecutionFail { .. }
        | ForgeControlRequest::ExecutionReconcile { .. }
        | ForgeControlRequest::ExecutionGet { .. }
        | ForgeControlRequest::VerificationProjection { .. }
        | ForgeControlRequest::ExecutionEvidenceInventory { .. }
        | ForgeControlRequest::ExecutionEvidenceRead { .. }
        | ForgeControlRequest::ExecutionGeneratedPackage { .. }
        | ForgeControlRequest::ExecutionGetEvidence { .. }
        | ForgeControlRequest::ExecutionGetAuthorized { .. }
        | ForgeControlRequest::ExecutionList { .. }
        | ForgeControlRequest::ExecutionOutputAppendBatch { .. }
        | ForgeControlRequest::ExecutionOutputRead { .. }
        | ForgeControlRequest::ExecutionOutputReadAuthorized { .. }
        | ForgeControlRequest::ExecutionReadAuthorized { .. }
        | ForgeControlRequest::GoalCreate { .. }
        | ForgeControlRequest::GoalMutation { .. }
        | ForgeControlRequest::GoalGet { .. }
        | ForgeControlRequest::GoalList { .. }
        | ForgeControlRequest::GoalReviseContract { .. }
        | ForgeControlRequest::GoalTransition { .. }
        | ForgeControlRequest::GoalReview { .. }
        | ForgeControlRequest::GoalComplete { .. }
        | ForgeControlRequest::DagGetCurrent { .. }
        | ForgeControlRequest::DagGetRevision { .. }
        | ForgeControlRequest::DagNodeAssignmentSnapshot { .. }
        | ForgeControlRequest::DagNodeStart { .. }
        | ForgeControlRequest::DagNodeComplete { .. }
        | ForgeControlRequest::DagNodeUpdate { .. }
        | ForgeControlRequest::RecoveryLeaseGet { .. }
        | ForgeControlRequest::RecoveryLeaseClaim { .. }
        | ForgeControlRequest::RecoveryLeaseRenew { .. }
        | ForgeControlRequest::RecoveryLeaseRelease { .. }
        | ForgeControlRequest::RecoveryMaintenanceRun { .. }
        | ForgeControlRequest::LeadershipWorkCut { .. }
        | ForgeControlRequest::RecoveryMaintenanceDurable { .. }
        | ForgeControlRequest::RecoveryMaintenanceGet { .. }
        | ForgeControlRequest::CheckpointRestoreRun { .. }
        | ForgeControlRequest::EnsureWorkspacePolicy { .. }
        | ForgeControlRequest::GetWorkspacePolicy { .. }
        | ForgeControlRequest::ReplaceWorkspacePolicy { .. }
        | ForgeControlRequest::WorkspaceQueueSettingsGet { .. }
        | ForgeControlRequest::WorkspaceQueueSettingsReplace { .. }
        | ForgeControlRequest::GoalDelete { .. }
        | ForgeControlRequest::GoalDeletePending { .. }
        | ForgeControlRequest::ApprovalCreate { .. }
        | ForgeControlRequest::ApprovalListPending { .. }
        | ForgeControlRequest::ApprovalGet { .. }
        | ForgeControlRequest::ApprovalGetWithGrant { .. }
        | ForgeControlRequest::ApprovalApproveOnce { .. }
        | ForgeControlRequest::ApprovalDecide { .. }
        | ForgeControlRequest::AutoApprovalScopeCreate { .. }
        | ForgeControlRequest::AutoApprovalScopeRevoke { .. }
        | ForgeControlRequest::AutoApprovalScopeGet { .. }
        | ForgeControlRequest::ApprovalGrantConsume { .. }
        | ForgeControlRequest::AutoApprovalConsume { .. }
        | ForgeControlRequest::DiffList { .. }
        | ForgeControlRequest::DiffRead { .. }
        | ForgeControlRequest::DiffDoctor { .. }
        | ForgeControlRequest::DiffRetentionPlan { .. }
        | ForgeControlRequest::DiffPurge { .. }
        | ForgeControlRequest::DiffArtifactDoctor { .. }
        | ForgeControlRequest::DeleteOrphanDiffArtifact { .. }
        | ForgeControlRequest::Shutdown { .. } => dispatch_supervisor_request(control, request),
        ForgeControlRequest::CloseActivity {
            scope,
            activity_id,
            runtime_instance_id,
            expected_lease_revision,
            response,
        } => {
            let result = runtime_timestamp_millis().and_then(|observed_at| {
                control.close_activity(
                    &scope,
                    activity_id,
                    runtime_instance_id,
                    expected_lease_revision,
                    observed_at,
                )
            });
            let _ignored = response.send(result);
        }
    }
}

fn dispatch_supervisor_request(control: &ForgeControl, request: ForgeControlRequest) {
    match request {
        request @ (ForgeControlRequest::LocationList { .. }
        | ForgeControlRequest::LocationRemovalProbe { .. }
        | ForgeControlRequest::LocationRemove { .. }
        | ForgeControlRequest::WorkspaceList { .. }
        | ForgeControlRequest::WorkspaceDiscover { .. }
        | ForgeControlRequest::ResolveWorkspace { .. }
        | ForgeControlRequest::AuthorizeActivity { .. }
        | ForgeControlRequest::BootstrapActivity { .. }
        | ForgeControlRequest::RenewActivityLease { .. }
        | ForgeControlRequest::SupervisedActivityLeaseRenew { .. }
        | ForgeControlRequest::CloseActivity { .. }) => {
            dispatch_activity_request(control, request);
        }
        request @ ForgeControlRequest::RenewActivityLeaseBatch { .. } => {
            dispatch_renew_activity_lease_batch(control, request);
        }
        ForgeControlRequest::CloseOwnedActivityBatch {
            scope,
            commands,
            response,
        } => {
            let result = runtime_timestamp_millis().and_then(|observed_at| {
                let commands: Vec<_> = commands
                    .iter()
                    .map(|command| {
                        CloseActivity::new(
                            command.id(),
                            command.owner_id(),
                            command.expected_lease_revision(),
                            observed_at,
                        )
                    })
                    .collect();
                control.close_owned_activity_batch(&scope, &commands)
            });
            let _ignored = response.send(result);
        }
        ForgeControlRequest::ReleaseActivityLease {
            scope,
            activity_id,
            runtime_instance_id,
            expected_lease_revision,
            response,
        } => {
            let result = runtime_timestamp_millis().and_then(|observed_at| {
                control.release_activity_lease(
                    &scope,
                    activity_id,
                    runtime_instance_id,
                    expected_lease_revision,
                    observed_at,
                )
            });
            let _ignored = response.send(result);
        }
        ForgeControlRequest::ReleaseActivityLeaseBatch {
            scope,
            commands,
            response,
        } => {
            let result = runtime_timestamp_millis().and_then(|observed_at| {
                let commands: Vec<_> = commands
                    .iter()
                    .map(|command| {
                        ReleaseActivityLease::new(
                            command.id(),
                            command.owner_id(),
                            command.expected_lease_revision(),
                            observed_at,
                        )
                    })
                    .collect();
                control.release_activity_lease_batch(&scope, &commands)
            });
            let _ignored = response.send(result);
        }
        ForgeControlRequest::Shutdown { .. } => {}
        request @ (ForgeControlRequest::ActivitySuccessorCreate { .. }
        | ForgeControlRequest::ActivitySuccessorGet { .. }
        | ForgeControlRequest::ExpiredActivityRecoveryProbe { .. }
        | ForgeControlRequest::ExpiredActivityRecoveryRun { .. }
        | ForgeControlRequest::ExpiredActivityRecoveryGet { .. }
        | ForgeControlRequest::UnstartedActivityContinuationProbe { .. }
        | ForgeControlRequest::UnstartedActivityContinuationRun { .. }
        | ForgeControlRequest::UnstartedActivityContinuationGet { .. }
        | ForgeControlRequest::StartedActivityLeaseResumeProbe { .. }
        | ForgeControlRequest::StartedActivityLeaseResumeRun { .. }
        | ForgeControlRequest::StartedActivityLeaseResumeGet { .. }
        | ForgeControlRequest::QuiescentActivityLeaseResumeProbe { .. }
        | ForgeControlRequest::QuiescentActivityLeaseResumeRun { .. }
        | ForgeControlRequest::QuiescentActivityLeaseResumeGet { .. }) => {
            dispatch_request(control, request);
        }
        request => dispatch_effect_request(control, request),
    }
}

fn dispatch_renew_activity_lease_batch(control: &ForgeControl, request: ForgeControlRequest) {
    if let ForgeControlRequest::RenewActivityLeaseBatch {
        scope,
        commands,
        response,
    } = request
    {
        let result = commands
            .iter()
            .map(rebase_renew_activity_lease)
            .collect::<Result<Vec<_>, _>>()
            .and_then(|commands| control.renew_activity_lease_batch(&scope, &commands));
        let _ignored = response.send(result);
    }
}

fn dispatch_effect_request(control: &ForgeControl, request: ForgeControlRequest) {
    let Some(request) = dispatch_workspace_effect_request(control, request) else {
        return;
    };
    match request {
        request @ (ForgeControlRequest::EnsureWorkspacePolicy { .. }
        | ForgeControlRequest::GetWorkspacePolicy { .. }
        | ForgeControlRequest::ReplaceWorkspacePolicy { .. }
        | ForgeControlRequest::WorkspaceQueueSettingsGet { .. }
        | ForgeControlRequest::WorkspaceQueueSettingsReplace { .. }
        | ForgeControlRequest::GoalDelete { .. }
        | ForgeControlRequest::GoalDeletePending { .. }
        | ForgeControlRequest::ApprovalCreate { .. }
        | ForgeControlRequest::ApprovalListPending { .. }
        | ForgeControlRequest::ApprovalGet { .. }
        | ForgeControlRequest::ApprovalGetWithGrant { .. }
        | ForgeControlRequest::ApprovalApproveOnce { .. }
        | ForgeControlRequest::ApprovalDecide { .. }
        | ForgeControlRequest::AutoApprovalScopeCreate { .. }
        | ForgeControlRequest::AutoApprovalScopeRevoke { .. }
        | ForgeControlRequest::AutoApprovalScopeGet { .. }
        | ForgeControlRequest::ApprovalGrantConsume { .. }
        | ForgeControlRequest::AutoApprovalConsume { .. }) => {
            dispatch_approval_request(control, request);
        }
        request @ ForgeControlRequest::LeadershipWorkCut { .. } => {
            dispatch_recovery_request(control, request);
        }
        other => dispatch_effect_request_inner(control, other),
    }
}

fn dispatch_effect_request_inner(control: &ForgeControl, request: ForgeControlRequest) {
    match request {
        request @ (ForgeControlRequest::ExecutionMarkRunning { .. }
        | ForgeControlRequest::ExecutionCompleteGenerated { .. }
        | ForgeControlRequest::ExecutionComplete { .. }
        | ForgeControlRequest::ExecutionJournalOutput { .. }
        | ForgeControlRequest::ExecutionJournalComplete { .. }
        | ForgeControlRequest::ExecutionJournalCompleteGenerated { .. }
        | ForgeControlRequest::ExecutionJournalFail { .. }
        | ForgeControlRequest::ExecutionJournalReconcileOutput { .. }
        | ForgeControlRequest::ExecutionJournalReconcileTerminal { .. }
        | ForgeControlRequest::ExecutionFail { .. }
        | ForgeControlRequest::ExecutionReconcile { .. }
        | ForgeControlRequest::ExecutionGet { .. }
        | ForgeControlRequest::VerificationProjection { .. }
        | ForgeControlRequest::ExecutionEvidenceInventory { .. }
        | ForgeControlRequest::ExecutionEvidenceRead { .. }
        | ForgeControlRequest::ExecutionGeneratedPackage { .. }
        | ForgeControlRequest::ExecutionGetEvidence { .. }
        | ForgeControlRequest::ExecutionGetAuthorized { .. }
        | ForgeControlRequest::ExecutionList { .. }
        | ForgeControlRequest::ExecutionOutputAppendBatch { .. }
        | ForgeControlRequest::ExecutionOutputRead { .. }
        | ForgeControlRequest::ExecutionOutputReadAuthorized { .. }
        | ForgeControlRequest::ExecutionReadAuthorized { .. }) => {
            dispatch_execution_request(control, request);
        }
        request @ (ForgeControlRequest::GoalCreate { .. }
        | ForgeControlRequest::GoalReviseContract { .. }
        | ForgeControlRequest::GoalGet { .. }
        | ForgeControlRequest::GoalList { .. }
        | ForgeControlRequest::GoalTransition { .. }
        | ForgeControlRequest::GoalReview { .. }
        | ForgeControlRequest::GoalComplete { .. }) => dispatch_goal_request(control, request),
        request @ (ForgeControlRequest::DagGetCurrent { .. }
        | ForgeControlRequest::DagGetRevision { .. }
        | ForgeControlRequest::DagNodeAssignmentSnapshot { .. }
        | ForgeControlRequest::DagNodeStart { .. }
        | ForgeControlRequest::DagNodeComplete { .. }
        | ForgeControlRequest::DagNodeUpdate { .. }) => dispatch_dag_request(control, request),
        request @ (ForgeControlRequest::RecoveryLeaseGet { .. }
        | ForgeControlRequest::RecoveryLeaseClaim { .. }
        | ForgeControlRequest::RecoveryLeaseRenew { .. }
        | ForgeControlRequest::RecoveryLeaseRelease { .. }
        | ForgeControlRequest::RecoveryMaintenanceRun { .. }
        | ForgeControlRequest::RecoveryMaintenanceDurable { .. }
        | ForgeControlRequest::RecoveryMaintenanceGet { .. }
        | ForgeControlRequest::CheckpointRestoreRun { .. }) => {
            dispatch_recovery_request(control, request);
        }
        request @ (ForgeControlRequest::ApprovalCleanupPermitMint { .. }
        | ForgeControlRequest::ApprovalCleanupPrepare { .. }
        | ForgeControlRequest::ApprovalCleanupApply { .. }
        | ForgeControlRequest::ApprovalCleanupObserve { .. }) => {
            dispatch_approval_cleanup_request(control, request);
        }
        request @ (ForgeControlRequest::ExecutionStopPrepare { .. }
        | ForgeControlRequest::ExecutionStopApply { .. }
        | ForgeControlRequest::ExecutionStopObserve { .. }
        | ForgeControlRequest::OwnedExecutionStopPrepare { .. }
        | ForgeControlRequest::OwnedExecutionStopApply { .. }
        | ForgeControlRequest::OwnedExecutionStopObserve { .. }
        | ForgeControlRequest::OwnedExecutionStopSettle { .. }
        | ForgeControlRequest::OwnedExecutionStopHistory { .. }) => {
            dispatch_execution_stop_request(control, request);
        }
        request @ (ForgeControlRequest::ApprovalExpiryPrepare { .. }
        | ForgeControlRequest::ApprovalExpiryApply { .. }
        | ForgeControlRequest::ApprovalExpiryObserve { .. }) => {
            dispatch_approval_expiry_request(control, request);
        }
        request @ (ForgeControlRequest::DiffList { .. }
        | ForgeControlRequest::DiffRead { .. }
        | ForgeControlRequest::DiffDoctor { .. }
        | ForgeControlRequest::DiffRetentionPlan { .. }
        | ForgeControlRequest::DiffPurge { .. }
        | ForgeControlRequest::DiffArtifactDoctor { .. }
        | ForgeControlRequest::DeleteOrphanDiffArtifact { .. }) => {
            dispatch_diff_request(control, request);
        }
        other => dispatch_agent_or_supervisor_request(control, other),
    }
}

fn dispatch_agent_or_supervisor_request(control: &ForgeControl, request: ForgeControlRequest) {
    match request {
        request @ (ForgeControlRequest::AgentSessionOpen { .. }
        | ForgeControlRequest::AgentCoordinationView { .. }
        | ForgeControlRequest::AgentInboxList { .. }
        | ForgeControlRequest::AgentSessionResolve { .. }
        | ForgeControlRequest::AgentBindingReserve { .. }
        | ForgeControlRequest::AgentBindingReserveReference { .. }
        | ForgeControlRequest::AgentBindingReservationRead { .. }
        | ForgeControlRequest::AgentOperationsDelegation { .. }
        | ForgeControlRequest::AgentOperationsDelegationReference { .. }
        | ForgeControlRequest::AgentOperationsDelegationRead { .. }
        | ForgeControlRequest::AgentOperationsFreeze { .. }
        | ForgeControlRequest::AgentOperationsFreezeRead { .. }
        | ForgeControlRequest::AgentOperationsExport { .. }
        | ForgeControlRequest::AgentOperationsFreezeRelease { .. }
        | ForgeControlRequest::AgentBindingActivate { .. }
        | ForgeControlRequest::AgentBindingActivateReference { .. }
        | ForgeControlRequest::AgentBindingActivationRead { .. }
        | ForgeControlRequest::AgentSessionReconcile { .. }
        | ForgeControlRequest::AgentSessionReconcileDestination { .. }
        | ForgeControlRequest::AgentSessionReconciliationRead { .. }
        | ForgeControlRequest::AgentDepartureReconcile { .. }
        | ForgeControlRequest::AgentDepartureReconcileDestination { .. }
        | ForgeControlRequest::AgentDepartureReconciliationRead { .. }
        | ForgeControlRequest::AgentEffectOutboxRead { .. }
        | ForgeControlRequest::AgentSessionProve { .. }
        | ForgeControlRequest::AgentSetFocus { .. }
        | ForgeControlRequest::AgentVerifyExecutionAuthority { .. }
        | ForgeControlRequest::AgentAssignmentMutate { .. }
        | ForgeControlRequest::AgentAssignmentOfferSeal { .. }
        | ForgeControlRequest::AgentAssignmentOfferSealGet { .. }
        | ForgeControlRequest::AgentPublishWorkUpdate { .. }
        | ForgeControlRequest::AgentList { .. }
        | ForgeControlRequest::AgentAssignmentGet { .. }
        | ForgeControlRequest::AgentAssignmentList { .. }
        | ForgeControlRequest::AgentGetContext { .. }
        | ForgeControlRequest::WriterLeaseAcquire { .. }
        | ForgeControlRequest::WriterLeaseRenew { .. }
        | ForgeControlRequest::WriterLeaseRelease { .. }
        | ForgeControlRequest::WriterLeaseGet { .. }
        | ForgeControlRequest::WriterLeaseList { .. }
        | ForgeControlRequest::WriterLeaseRecoveryRelease { .. }
        | ForgeControlRequest::AgentDagPlanCommit { .. }
        | ForgeControlRequest::CoordinatorActor { .. }
        | ForgeControlRequest::CoordinatorGet { .. }
        | ForgeControlRequest::CoordinatorClaim { .. }
        | ForgeControlRequest::CoordinatorTransfer { .. }
        | ForgeControlRequest::CoordinatorRecoveryPrepare { .. }
        | ForgeControlRequest::CoordinatorRecoveryConfirm { .. }
        | ForgeControlRequest::CoordinatorRecoveryReceipt { .. }
        | ForgeControlRequest::CoordinatorRecoveryHistory { .. }) => {
            dispatch_agent_request(control, request);
        }
        other => dispatch_supervisor_request(control, other),
    }
}

fn dispatch_workspace_effect_request(
    control: &ForgeControl,
    request: ForgeControlRequest,
) -> Option<ForgeControlRequest> {
    match request {
        ForgeControlRequest::ReconcileExpiredActivityLeases {
            scope,
            observed_at,
            limit,
            response,
        } => {
            let _ignored = response.send(control.reconcile_expired_activity_leases_limited(
                &scope,
                observed_at,
                limit,
            ));
        }
        ForgeControlRequest::ListActivityProjections {
            scope,
            now,
            limit,
            response,
        } => {
            let _ignored = response.send(control.list_activity_projections(&scope, now, limit));
        }
        ForgeControlRequest::ObserveActivityLeases {
            scope,
            activity_ids,
            response,
        } => {
            let _ignored = response.send(control.observe_activity_leases(&scope, &activity_ids));
        }
        ForgeControlRequest::ListWorkspaceActivityProjections { request, response } => {
            let _ignored = response.send(control.list_workspace_activity_projections(&request));
        }
        ForgeControlRequest::ActivityRead { request, response } => {
            let _ignored = response.send(control.activity_read(&request));
        }
        ForgeControlRequest::ProjectCommandResolve {
            request,
            command_id,
            expected_fingerprint,
            execution_id,
            response,
        } => {
            let _ignored = response.send(control.project_command_execution_request_fenced(
                &request,
                &command_id,
                expected_fingerprint,
                execution_id,
            ));
        }
        ForgeControlRequest::ProjectCommandPrepareVerification {
            request,
            command_id,
            expected_fingerprint,
            execution_id,
            cancellation,
            response,
        } => {
            let _ignored = response.send(control.prepare_project_command_verification(
                &request,
                &command_id,
                expected_fingerprint,
                execution_id,
                &cancellation,
            ));
        }
        ForgeControlRequest::WorkspaceVerificationPrepare {
            scope,
            activity,
            input_id,
            cancellation,
            response,
        } => {
            let _ignored = response.send(control.prepare_workspace_verification_input(
                &scope,
                activity,
                input_id,
                &cancellation,
            ));
        }
        ForgeControlRequest::ProjectCommandList { request, response } => {
            let _ignored = response.send(control.project_command_list(&request));
        }
        other => return dispatch_generated_artifact_request(control, other),
    }
    None
}

fn dispatch_generated_artifact_request(
    control: &ForgeControl,
    request: ForgeControlRequest,
) -> Option<ForgeControlRequest> {
    match request {
        ForgeControlRequest::GeneratedArtifactInventory {
            scope,
            cache_root,
            limit,
            response,
        } => {
            let _ignored =
                response.send(control.generated_artifact_inventory(&scope, &cache_root, limit));
        }
        ForgeControlRequest::GeneratedPackageAccess {
            scope,
            cache_root,
            execution_id,
            response,
        } => {
            let result = control
                .generated_package_access(&scope, &cache_root, execution_id)
                .and_then(|access| {
                    access
                        .map(|access| {
                            access.path().map_err(|error| {
                                ControlError::with_source(
                                    ControlErrorCode::ExecutionConflict,
                                    error,
                                )
                            })
                        })
                        .transpose()
                });
            let _ignored = response.send(result);
        }
        other => return dispatch_file_effect_request(control, other),
    }
    None
}

fn dispatch_file_effect_request(
    control: &ForgeControl,
    request: ForgeControlRequest,
) -> Option<ForgeControlRequest> {
    match request {
        ForgeControlRequest::FileRead { request, response } => {
            dispatch_file_read(control, request, &response);
        }
        ForgeControlRequest::FileList { request, response } => {
            dispatch_file_list(control, request, &response);
        }
        ForgeControlRequest::TextSearch { request, response } => {
            dispatch_text_search(control, request, &response);
        }
        ForgeControlRequest::FileMutationReadback { request, response } => {
            send_response(&response, control.file_mutation_readback(&request));
        }
        ForgeControlRequest::SourceTreeReadback { request, response } => {
            send_response(&response, control.source_tree_readback(&request));
        }
        ForgeControlRequest::GoalMutation { request, response } => {
            let result = runtime_timestamp_millis()
                .and_then(|admitted_at| control.goal_mutation(&request, admitted_at));
            send_response(&response, result);
        }
        ForgeControlRequest::GoalMutationReadback { request, response } => {
            send_response(&response, control.goal_mutation_readback(&request));
        }
        ForgeControlRequest::DagPlanReadback { request, response } => {
            send_response(&response, control.dag_plan_readback(&request));
        }
        ForgeControlRequest::FileReadSlice { request, response } => {
            dispatch_file_read_slice(control, request, &response);
        }
        ForgeControlRequest::FileApplyPatch { request, response } => {
            dispatch_file_apply_patch(control, request, &response);
        }
        ForgeControlRequest::SourceTreeApply { request, response } => {
            dispatch_source_tree_apply(control, request, &response);
        }
        ForgeControlRequest::FileImportBinary {
            mut request,
            response,
            _permit,
        } => {
            let result = runtime_timestamp_millis().and_then(|observed_at| {
                request.activity.observed_at = observed_at;
                control.file_import_binary(&request)
            });
            let _ignored = response.send(result);
        }
        ForgeControlRequest::FileMutate { request, response } => {
            dispatch_file_mutation(control, request, &response);
        }
        other => return Some(other),
    }
    None
}

fn dispatch_binding_reserve(
    control: &ForgeControl,
    mut request: AgentBindingReserveRequest,
    response: &Response<forge_persistence::AgentBindingReservation>,
) {
    let result = runtime_timestamp_millis().and_then(|observed_at| {
        request.observed_at = observed_at;
        control.reserve_agent_binding(&request)
    });
    let _ignored = response.send(result);
}

fn dispatch_operations_delegation(
    control: &ForgeControl,
    mut request: AgentOperationsDelegationRequest,
    response: &Response<forge_persistence::AgentOperationsDelegation>,
) {
    let result = runtime_timestamp_millis().and_then(|observed_at| {
        request.observed_at = observed_at;
        control.delegate_agent_operations(&request)
    });
    let _ignored = response.send(result);
}

fn dispatch_binding_activation(
    control: &ForgeControl,
    mut request: AgentBindingActivateRequest,
    response: &Response<forge_persistence::AgentBindingActivation>,
) {
    let result = runtime_timestamp_millis().and_then(|observed_at| {
        request.observed_at = observed_at;
        control.activate_agent_binding(&request)
    });
    let _ignored = response.send(result);
}

#[allow(clippy::needless_pass_by_value)]
fn dispatch_binding_rejection(
    control: &ForgeControl,
    request: AgentBindingRejectRequest,
    response: &Response<forge_persistence::AgentBindingRejectionOperation>,
) {
    let result = control.reject_agent_binding(&request);
    let _ignored = response.send(result);
}

fn dispatch_binding_reserve_reference(
    control: &ForgeControl,
    mut request: AgentBindingReserveReferenceRequest,
    response: &Response<forge_persistence::AgentBindingReservation>,
) {
    let result = runtime_timestamp_millis().and_then(|observed_at| {
        request.observed_at = observed_at;
        control.reserve_agent_binding_ref(&request)
    });
    let _ignored = response.send(result);
}

fn dispatch_operations_delegation_reference(
    control: &ForgeControl,
    mut request: AgentOperationsDelegateReferenceRequest,
    response: &Response<forge_persistence::AgentOperationsDelegation>,
) {
    let result = runtime_timestamp_millis().and_then(|observed_at| {
        request.observed_at = observed_at;
        control.delegate_agent_operations_ref(&request)
    });
    let _ignored = response.send(result);
}

fn dispatch_binding_activation_reference(
    control: &ForgeControl,
    mut request: AgentBindingActivateReferenceRequest,
    response: &Response<forge_persistence::AgentBindingActivation>,
) {
    let result = runtime_timestamp_millis().and_then(|observed_at| {
        request.observed_at = observed_at;
        control.activate_agent_binding_ref(&request)
    });
    let _ignored = response.send(result);
}

fn refresh_writer_lease_acquire(
    mut request: WriterLeaseAcquireRequest,
) -> Result<WriterLeaseAcquireRequest, ControlError> {
    let observed_at = runtime_timestamp_millis()?;
    request.command = request
        .command
        .with_observed_at(observed_at)
        .map_err(|error| ControlError::with_source(ControlErrorCode::InvalidInput, error))?;
    Ok(request)
}

fn refresh_writer_lease_renew(
    mut request: WriterLeaseRenewRequest,
) -> Result<WriterLeaseRenewRequest, ControlError> {
    let observed_at = runtime_timestamp_millis()?;
    request.command = request
        .command
        .with_observed_at(observed_at)
        .map_err(|error| ControlError::with_source(ControlErrorCode::InvalidInput, error))?;
    Ok(request)
}

fn refresh_writer_lease_release(
    mut request: WriterLeaseReleaseRequest,
) -> Result<WriterLeaseReleaseRequest, ControlError> {
    let observed_at = runtime_timestamp_millis()?;
    request.command = request.command.with_observed_at(observed_at);
    Ok(request)
}

fn dispatch_delegated_operations_request(control: &ForgeControl, request: ForgeControlRequest) {
    match request {
        ForgeControlRequest::AgentBindingReserve { request, response } => {
            dispatch_binding_reserve(control, request, &response);
        }
        ForgeControlRequest::AgentBindingReserveReference { request, response } => {
            dispatch_binding_reserve_reference(control, request, &response);
        }
        ForgeControlRequest::AgentBindingReservationRead { request, response } => {
            let _ignored = response.send(control.agent_binding_reservation(&request));
        }
        ForgeControlRequest::AgentOperationsDelegation { request, response } => {
            dispatch_operations_delegation(control, request, &response);
        }
        ForgeControlRequest::AgentOperationsDelegationReference { request, response } => {
            dispatch_operations_delegation_reference(control, request, &response);
        }
        ForgeControlRequest::AgentOperationsDelegationRead { request, response } => {
            let _ignored = response.send(control.agent_operations_delegation(&request));
        }
        ForgeControlRequest::AgentBindingActivate { request, response } => {
            dispatch_binding_activation(control, request, &response);
        }
        ForgeControlRequest::AgentBindingActivateReference { request, response } => {
            dispatch_binding_activation_reference(control, request, &response);
        }
        ForgeControlRequest::AgentBindingActivationRead { request, response } => {
            let _ignored = response.send(control.agent_binding_activation(&request));
        }
        ForgeControlRequest::AgentBindingReject { request, response } => {
            dispatch_binding_rejection(control, request, &response);
        }
        ForgeControlRequest::AgentBindingRejectionRead { request, response } => {
            let _ignored = response.send(control.agent_binding_rejection(&request));
        }
        ForgeControlRequest::AgentSessionReconcile { request, response } => {
            let _ignored = response.send(control.reconcile_agent_session(&request));
        }
        ForgeControlRequest::AgentSessionReconcileDestination { request, response } => {
            let _ignored = response.send(control.reconcile_agent_session_destination(&request));
        }
        ForgeControlRequest::AgentSessionReconciliationRead { request, response } => {
            let _ignored = response.send(control.agent_session_reconciliation(&request));
        }
        ForgeControlRequest::AgentDepartureReconcile { request, response } => {
            let result = runtime_timestamp_millis()
                .and_then(|admitted_at| control.reconcile_agent_departure(&request, admitted_at));
            let _ignored = response.send(result);
        }
        ForgeControlRequest::AgentDepartureReconcileDestination { request, response } => {
            let result = runtime_timestamp_millis().and_then(|admitted_at| {
                control.reconcile_agent_departure_destination(&request, admitted_at)
            });
            let _ignored = response.send(result);
        }
        ForgeControlRequest::AgentDepartureReconciliationRead { request, response } => {
            let _ignored = response.send(control.agent_departure_reconciliation(&request));
        }
        ForgeControlRequest::AgentEffectOutboxRead { request, response } => {
            let _ignored = response.send(control.agent_effect_outbox(&request));
        }
        ForgeControlRequest::EffectFactOutboxRead { request, response } => {
            let _ignored = response.send(control.effect_fact_outbox(&request));
        }
        ForgeControlRequest::AgentOperationsFreeze { request, response } => {
            let _ignored = response.send(control.agent_operations_freeze(&request));
        }
        ForgeControlRequest::AgentOperationsFreezeRead { request, response } => {
            let _ignored = response.send(control.agent_operations_freeze_read(&request));
        }
        ForgeControlRequest::AgentOperationsExport { request, response } => {
            let _ignored = response.send(control.agent_operations_export(&request));
        }
        ForgeControlRequest::AgentOperationsFreezeRelease { request, response } => {
            let _ignored = response.send(control.agent_operations_freeze_release(&request));
        }
        _ => unreachable!("non-delegated request reached delegated dispatcher"),
    }
}

fn dispatch_agent_read_request(control: &ForgeControl, request: ForgeControlRequest) {
    match request {
        ForgeControlRequest::AgentInboxList { request, response } => {
            let _ignored = response.send(control.agent_inbox_list(&request));
        }
        ForgeControlRequest::AgentAssignmentOfferSealGet { request, response } => {
            let _ignored = response.send(control.agent_assignment_offer_seal_get(&request));
        }
        ForgeControlRequest::AgentAssignmentGet { request, response } => {
            let _ignored = response.send(control.agent_assignment_get(&request));
        }
        ForgeControlRequest::AgentAssignmentList { request, response } => {
            let _ignored = response.send(control.agent_assignment_list(&request));
        }
        ForgeControlRequest::AgentCoordinationView { request, response } => {
            let _ignored = response.send(control.agent_coordination_view(&request));
        }
        ForgeControlRequest::AgentList { request, response } => {
            let _ignored = response.send(control.agent_list(&request));
        }
        ForgeControlRequest::AgentGetContext { request, response } => {
            let _ignored = response.send(control.agent_get_context(&request));
        }
        ForgeControlRequest::CoordinatorRecoveryPrepare { request, response } => {
            let _ignored = response.send(control.prepare_coordinator_recovery(&request));
        }
        ForgeControlRequest::CoordinatorRecoveryReceipt { request, response } => {
            let _ignored = response.send(control.coordinator_recovery_receipt(&request));
        }
        ForgeControlRequest::CoordinatorRecoveryHistory { request, response } => {
            let _ignored = response.send(control.coordinator_recovery_history(&request));
        }
        _ => unreachable!("non-read request reached Agent read dispatcher"),
    }
}

#[allow(clippy::too_many_lines)]
fn dispatch_agent_request(control: &ForgeControl, request: ForgeControlRequest) {
    match request {
        ForgeControlRequest::AgentAssignmentMutate { request, response } => {
            let result = runtime_timestamp_millis()
                .and_then(|admitted_at| control.agent_assignment_mutate(&request, admitted_at));
            let _ignored = response.send(result);
        }
        ForgeControlRequest::AgentAssignmentOfferSeal { request, response } => {
            let _ignored = response.send(control.agent_assignment_offer_seal(&request));
        }
        request @ (ForgeControlRequest::AgentAssignmentOfferSealGet { .. }
        | ForgeControlRequest::AgentInboxList { .. }
        | ForgeControlRequest::AgentAssignmentGet { .. }
        | ForgeControlRequest::AgentAssignmentList { .. }
        | ForgeControlRequest::AgentCoordinationView { .. }
        | ForgeControlRequest::AgentList { .. }
        | ForgeControlRequest::AgentGetContext { .. }
        | ForgeControlRequest::CoordinatorRecoveryPrepare { .. }
        | ForgeControlRequest::CoordinatorRecoveryReceipt { .. }
        | ForgeControlRequest::CoordinatorRecoveryHistory { .. }) => {
            dispatch_agent_read_request(control, request);
        }
        ForgeControlRequest::AgentSessionOpen { request, response } => {
            let _ignored = response.send(control.agent_session_open(&request));
        }
        request @ (ForgeControlRequest::AgentBindingReserve { .. }
        | ForgeControlRequest::AgentBindingReserveReference { .. }
        | ForgeControlRequest::AgentBindingReservationRead { .. }
        | ForgeControlRequest::AgentOperationsDelegation { .. }
        | ForgeControlRequest::AgentOperationsDelegationReference { .. }
        | ForgeControlRequest::AgentOperationsDelegationRead { .. }
        | ForgeControlRequest::AgentOperationsFreeze { .. }
        | ForgeControlRequest::AgentOperationsFreezeRead { .. }
        | ForgeControlRequest::AgentOperationsExport { .. }
        | ForgeControlRequest::AgentOperationsFreezeRelease { .. }
        | ForgeControlRequest::AgentBindingActivate { .. }
        | ForgeControlRequest::AgentBindingActivateReference { .. }
        | ForgeControlRequest::AgentBindingActivationRead { .. }
        | ForgeControlRequest::AgentBindingReject { .. }
        | ForgeControlRequest::AgentBindingRejectionRead { .. }
        | ForgeControlRequest::AgentSessionReconcile { .. }
        | ForgeControlRequest::AgentSessionReconcileDestination { .. }
        | ForgeControlRequest::AgentSessionReconciliationRead { .. }
        | ForgeControlRequest::AgentDepartureReconcile { .. }
        | ForgeControlRequest::AgentDepartureReconcileDestination { .. }
        | ForgeControlRequest::AgentDepartureReconciliationRead { .. }
        | ForgeControlRequest::AgentEffectOutboxRead { .. }
        | ForgeControlRequest::EffectFactOutboxRead { .. }) => {
            dispatch_delegated_operations_request(control, request);
        }
        ForgeControlRequest::AgentSessionResolve { request, response } => {
            let _ignored = response.send(control.agent_session_resolve(request));
        }
        ForgeControlRequest::AgentSessionProve { request, response } => {
            let _ignored = response.send(control.agent_session_prove(&request));
        }
        ForgeControlRequest::AgentSetFocus { request, response } => {
            let result = runtime_timestamp_millis()
                .and_then(|admitted_at| control.agent_set_focus(&request, admitted_at));
            let _ignored = response.send(result);
        }
        ForgeControlRequest::AgentVerifyExecutionAuthority { request, response } => {
            let _ignored = response.send(control.verify_agent_execution_authority(&request));
        }
        ForgeControlRequest::AgentPublishWorkUpdate { request, response } => {
            let result = runtime_timestamp_millis()
                .and_then(|admitted_at| control.agent_publish_work_update(&request, admitted_at));
            let _ignored = response.send(result);
        }
        ForgeControlRequest::WriterLeaseAcquire { request, response } => {
            let result = refresh_writer_lease_acquire(request)
                .and_then(|request| control.writer_lease_acquire(&request));
            let _ignored = response.send(result);
        }
        ForgeControlRequest::WriterLeaseRenew { request, response } => {
            let result = refresh_writer_lease_renew(request)
                .and_then(|request| control.writer_lease_renew(&request));
            let _ignored = response.send(result);
        }
        ForgeControlRequest::WriterLeaseRelease { request, response } => {
            let result = refresh_writer_lease_release(request)
                .and_then(|request| control.writer_lease_release(&request));
            let _ignored = response.send(result);
        }
        ForgeControlRequest::WriterLeaseGet { request, response } => {
            let _ignored = response.send(control.writer_lease_get(&request));
        }
        ForgeControlRequest::WriterLeaseList { request, response } => {
            let _ignored = response.send(control.writer_lease_list(&request));
        }
        ForgeControlRequest::WriterLeaseRecoveryRelease { request, response } => {
            let _ignored = response.send(control.writer_lease_release_for_recovery(&request));
        }
        ForgeControlRequest::CoordinatorActor { request, response } => {
            let _ignored = response.send(control.activity_coordinator_actor(&request));
        }
        ForgeControlRequest::CoordinatorGet { request, response } => {
            let _ignored = response.send(control.activity_coordinator_get(&request));
        }
        ForgeControlRequest::CoordinatorClaim { request, response } => {
            let result = runtime_timestamp_millis()
                .and_then(|admitted_at| control.activity_coordinator_claim(&request, admitted_at));
            let _ignored = response.send(result);
        }
        ForgeControlRequest::CoordinatorTransfer { request, response } => {
            let result = runtime_timestamp_millis().and_then(|admitted_at| {
                control.activity_coordinator_transfer(&request, admitted_at)
            });
            let _ignored = response.send(result);
        }
        ForgeControlRequest::CoordinatorRecoveryConfirm { request, response } => {
            let _ignored = response.send(control.confirm_coordinator_recovery(&request));
        }
        ForgeControlRequest::AgentDagPlanCommit { request, response } => {
            let result = runtime_timestamp_millis()
                .and_then(|admitted_at| control.agent_dag_plan_commit(&request, admitted_at));
            let _ignored = response.send(result);
        }
        other => dispatch_effect_request(control, other),
    }
}

fn dispatch_execution_observation(control: &ForgeControl, request: ForgeControlRequest) {
    match request {
        ForgeControlRequest::ExecutionEvidenceInventory {
            scope,
            selection,
            limit,
            response,
        } => send_response(
            &response,
            control.execution_evidence_inventory(&scope, selection, limit),
        ),
        ForgeControlRequest::ExecutionEvidenceRead {
            scope,
            selection,
            id,
            cursor,
            max_bytes,
            max_events,
            response,
        } => send_response(
            &response,
            control.execution_evidence_read(&scope, selection, id, cursor, max_bytes, max_events),
        ),
        request => reject_queued_execution(request),
    }
}

fn dispatch_execution_request(control: &ForgeControl, request: ForgeControlRequest) {
    match request {
        ForgeControlRequest::ExecutionJournalOutput {
            authority,
            events,
            response,
        } => {
            let _ignored =
                response.send(ForgeControl::execution_journal_output(&authority, &events));
        }
        ForgeControlRequest::ExecutionJournalComplete {
            authority,
            command,
            closure,
            response,
        } => {
            let _ignored = response.send(ForgeControl::execution_journal_complete(
                &authority, &command, closure,
            ));
        }
        ForgeControlRequest::ExecutionJournalCompleteGenerated {
            authority,
            command,
            manifest,
            closure,
            response,
        } => {
            let _ignored = response.send(ForgeControl::execution_journal_complete_generated(
                &authority, &command, manifest, closure,
            ));
        }
        ForgeControlRequest::ExecutionJournalFail {
            authority,
            command,
            closure,
            response,
        } => {
            let _ignored = response.send(ForgeControl::execution_journal_fail(
                &authority, command, closure,
            ));
        }
        request @ (ForgeControlRequest::ExecutionJournalReconcileOutput { .. }
        | ForgeControlRequest::ExecutionJournalReconcileTerminal { .. }) => {
            dispatch_execution_journal_readback(request);
        }
        request => dispatch_scoped_execution_request(control, request),
    }
}

fn dispatch_execution_journal_readback(request: ForgeControlRequest) {
    match request {
        ForgeControlRequest::ExecutionJournalReconcileOutput {
            authority,
            before,
            events,
            response,
        } => {
            let _ignored = response.send(ForgeControl::execution_journal_reconcile_output(
                &authority, &before, &events,
            ));
        }
        ForgeControlRequest::ExecutionJournalReconcileTerminal {
            authority,
            before,
            command,
            closure,
            response,
        } => {
            let _ignored = response.send(ForgeControl::execution_journal_reconcile_terminal(
                &authority, &before, &command, closure,
            ));
        }
        request => reject_queued_execution(request),
    }
}

fn dispatch_scoped_execution_request(control: &ForgeControl, request: ForgeControlRequest) {
    match request {
        ForgeControlRequest::ExecutionMarkRunning {
            scope,
            command,
            response,
        } => {
            let _ignored = response.send(control.execution_mark_running(&scope, command));
        }
        ForgeControlRequest::ExecutionCompleteGenerated {
            scope,
            command,
            manifest,
            response,
        } => {
            let _ignored = response.send(
                control.execution_complete_with_generated_package(&scope, &command, manifest),
            );
        }
        ForgeControlRequest::ExecutionComplete {
            scope,
            command,
            response,
        } => {
            let _ignored = response.send(control.execution_complete(&scope, &command));
        }
        ForgeControlRequest::ExecutionFail {
            scope,
            command,
            response,
        } => {
            let _ignored = response.send(control.execution_fail(&scope, command));
        }
        ForgeControlRequest::ExecutionReconcile {
            scope,
            observed_at,
            limit,
            response,
        } => {
            let _ignored =
                response.send(control.reconcile_interrupted_executions(&scope, observed_at, limit));
        }
        ForgeControlRequest::ExecutionGet {
            scope,
            id,
            response,
        } => {
            let _ignored = response.send(control.execution_get(&scope, id));
        }
        ForgeControlRequest::VerificationProjection { scope, response } => {
            let _ignored = response.send(control.verification_projection(&scope));
        }
        request @ (ForgeControlRequest::ExecutionEvidenceInventory { .. }
        | ForgeControlRequest::ExecutionEvidenceRead { .. }) => {
            dispatch_execution_observation(control, request);
        }
        ForgeControlRequest::ExecutionGeneratedPackage {
            scope,
            id,
            response,
        } => {
            let _ignored = response.send(control.execution_generated_package_manifest(&scope, id));
        }
        ForgeControlRequest::ExecutionGetEvidence {
            request,
            id,
            response,
        } => {
            let _ignored = response
                .send(control.execution_get_authorized_with_generated_package(&request, id));
        }
        ForgeControlRequest::ExecutionGetAuthorized {
            request,
            id,
            response,
        } => {
            let _ignored = response.send(control.execution_get_authorized(&request, id));
        }
        ForgeControlRequest::ExecutionList {
            scope,
            activity_id,
            limit,
            response,
        } => {
            let _ignored = response.send(control.execution_list(&scope, activity_id, limit));
        }
        other => dispatch_execution_output_request(control, other),
    }
}

fn dispatch_execution_output_request(control: &ForgeControl, request: ForgeControlRequest) {
    match request {
        ForgeControlRequest::ExecutionOutputAppendBatch {
            scope,
            events,
            response,
        } => {
            let _ignored = response.send(control.execution_output_append_batch(&scope, &events));
        }
        ForgeControlRequest::ExecutionOutputRead {
            scope,
            cursor,
            max_bytes,
            max_events,
            response,
        } => {
            let _ignored =
                response.send(control.execution_output_read(&scope, cursor, max_bytes, max_events));
        }
        ForgeControlRequest::ExecutionOutputReadAuthorized {
            request,
            id,
            cursor,
            max_bytes,
            max_events,
            response,
        } => {
            let _ignored = response.send(
                control
                    .execution_output_read_authorized(&request, id, cursor, max_bytes, max_events),
            );
        }
        ForgeControlRequest::ExecutionReadAuthorized {
            request,
            id,
            cursor,
            max_bytes,
            max_events,
            response,
        } => {
            let _ignored = response.send(
                control.execution_read_authorized(&request, id, cursor, max_bytes, max_events),
            );
        }
        other => dispatch_supervisor_request(control, other),
    }
}

fn dispatch_goal_request(control: &ForgeControl, request: ForgeControlRequest) {
    match request {
        ForgeControlRequest::GoalCreate {
            scope,
            actor,
            goal,
            response,
        } => {
            let result = runtime_timestamp_millis()
                .and_then(|admitted_at| control.goal_create(&scope, actor, &goal, admitted_at));
            let _ignored = response.send(result);
        }
        ForgeControlRequest::GoalGet {
            scope,
            activity_id,
            goal_id,
            response,
        } => {
            let _ignored = response.send(control.goal_get(&scope, activity_id, goal_id));
        }
        ForgeControlRequest::GoalList {
            scope,
            activity_id,
            limit,
            response,
        } => {
            let _ignored = response.send(control.goal_list(&scope, activity_id, limit));
        }
        ForgeControlRequest::GoalReviseContract { request, response } => {
            let result = runtime_timestamp_millis()
                .and_then(|admitted_at| control.goal_revise_contract(&request, admitted_at));
            let _ignored = response.send(result);
        }
        ForgeControlRequest::GoalTransition { request, response } => {
            let result = runtime_timestamp_millis()
                .and_then(|admitted_at| control.goal_transition(&request, admitted_at));
            let _ignored = response.send(result);
        }
        ForgeControlRequest::GoalReview {
            scope,
            activity_id,
            goal_id,
            response,
        } => {
            let _ignored = response.send(control.goal_review(&scope, activity_id, goal_id));
        }
        ForgeControlRequest::GoalComplete { request, response } => {
            let result = runtime_timestamp_millis()
                .and_then(|admitted_at| control.goal_complete(&request, admitted_at));
            let _ignored = response.send(result);
        }
        other => dispatch_supervisor_request(control, other),
    }
}

fn dispatch_dag_request(control: &ForgeControl, request: ForgeControlRequest) {
    match request {
        ForgeControlRequest::DagGetCurrent {
            scope,
            goal_id,
            response,
        } => {
            let _ignored = response.send(control.dag_get_current(&scope, goal_id));
        }
        ForgeControlRequest::DagGetRevision {
            scope,
            goal_id,
            number,
            response,
        } => {
            let _ignored = response.send(control.dag_get_revision(&scope, goal_id, number));
        }
        ForgeControlRequest::DagNodeAssignmentSnapshot {
            scope,
            node_scope,
            response,
        } => {
            let _ignored = response.send(control.dag_node_assignment_snapshot(&scope, node_scope));
        }
        ForgeControlRequest::DagNodeStart { request, response } => {
            let result = runtime_timestamp_millis()
                .and_then(|admitted_at| control.dag_node_start(&request, admitted_at));
            let _ignored = response.send(result);
        }
        ForgeControlRequest::DagNodeComplete { request, response } => {
            let result = runtime_timestamp_millis()
                .and_then(|admitted_at| control.dag_node_complete(&request, admitted_at));
            let _ignored = response.send(result);
        }
        ForgeControlRequest::DagNodeUpdate { request, response } => {
            let result = runtime_timestamp_millis()
                .and_then(|admitted_at| control.dag_node_update(&request, admitted_at));
            let _ignored = response.send(result);
        }
        other => dispatch_supervisor_request(control, other),
    }
}

fn dispatch_recovery_request(control: &ForgeControl, request: ForgeControlRequest) {
    match request {
        ForgeControlRequest::RecoveryLeaseGet { scope, response } => {
            let _ignored = response.send(control.recovery_maintenance_lease(&scope));
        }
        ForgeControlRequest::RecoveryLeaseClaim {
            scope,
            command,
            response,
        } => {
            let result =
                control.claim_recovery_maintenance_lease_with_clock(&scope, &command, || {
                    runtime_timestamp_millis().map_err(|source| {
                        WorkspaceStoreError::RecoveryLeaseClockObservation {
                            source: Box::new(source),
                        }
                    })
                });
            let _ignored = response.send(result);
        }
        ForgeControlRequest::RecoveryLeaseRenew {
            scope,
            command,
            response,
        } => {
            let result = rebase_renew_recovery_lease(command)
                .and_then(|command| control.renew_recovery_maintenance_lease(&scope, &command));
            let _ignored = response.send(result);
        }
        ForgeControlRequest::RecoveryLeaseRelease {
            scope,
            command,
            response,
        } => {
            let result = rebase_release_recovery_lease(command)
                .and_then(|command| control.release_recovery_maintenance_lease(&scope, &command));
            let _ignored = response.send(result);
        }
        ForgeControlRequest::RecoveryMaintenanceRun { request, response } => {
            let _ignored = response.send(control.run_recovery_maintenance(&request));
        }
        ForgeControlRequest::LeadershipWorkCut { command, response } => {
            let result = runtime_timestamp_millis()
                .and_then(|now| control.leadership_work_cut(&command, now));
            let _ignored = response.send(result);
        }
        ForgeControlRequest::RecoveryMaintenanceDurable { request, response } => {
            let result = runtime_timestamp_millis()
                .and_then(|now| control.run_durable_recovery_maintenance(&request, now));
            let _ignored = response.send(result);
        }
        ForgeControlRequest::RecoveryMaintenanceGet {
            scope,
            request_id,
            request_digest,
            response,
        } => {
            let _ignored =
                response.send(control.recovery_maintenance_get(&scope, request_id, request_digest));
        }
        ForgeControlRequest::CheckpointRestoreRun { request, response } => {
            let _ignored = response.send(control.checkpoint_restore(&request));
        }
        other => dispatch_supervisor_request(control, other),
    }
}

fn dispatch_approval_request(control: &ForgeControl, request: ForgeControlRequest) {
    match request {
        ForgeControlRequest::EnsureWorkspacePolicy { scope, response } => {
            let result = runtime_timestamp_millis()
                .and_then(|observed_at| control.ensure_workspace_policy(&scope, observed_at));
            let _ignored = response.send(result);
        }
        ForgeControlRequest::GetWorkspacePolicy { scope, response } => {
            let _ignored = response.send(control.get_workspace_policy(&scope));
        }
        ForgeControlRequest::ReplaceWorkspacePolicy { request, response } => {
            let result = rebase_policy_request(request)
                .and_then(|request| control.replace_workspace_policy(&request));
            let _ignored = response.send(result);
        }
        ForgeControlRequest::WorkspaceQueueSettingsGet { scope, response } => {
            let _ignored = response.send(control.workspace_queue_settings(&scope));
        }
        ForgeControlRequest::WorkspaceQueueSettingsReplace {
            mut request,
            response,
        } => {
            let result = runtime_timestamp_millis().and_then(|observed_at| {
                request.observed_at = observed_at;
                control.replace_workspace_queue_settings(&request)
            });
            let _ignored = response.send(result);
        }
        ForgeControlRequest::ApprovalCreate { request, response } => {
            let result = rebase_approval_create(request)
                .and_then(|request| control.create_pending_approval(&request));
            let _ignored = response.send(result);
        }
        ForgeControlRequest::ApprovalListPending {
            scope,
            limit,
            response,
        } => {
            let _ignored = response.send(control.list_pending_approvals(&scope, limit));
        }
        ForgeControlRequest::ApprovalGet {
            scope,
            approval_id,
            response,
        } => {
            let _ignored = response.send(control.approval_get(&scope, approval_id));
        }
        ForgeControlRequest::ApprovalGetWithGrant {
            scope,
            approval_id,
            response,
        } => {
            let _ignored = response.send(control.approval_get_with_grant(&scope, approval_id));
        }
        ForgeControlRequest::ApprovalApproveOnce { request, response } => {
            let result =
                rebase_approval_once(request).and_then(|request| control.approve_once(&request));
            let _ignored = response.send(result);
        }
        ForgeControlRequest::ApprovalDecide { request, response } => {
            let result = rebase_approval_decision(request)
                .and_then(|request| control.decide_pending_approval(&request));
            let _ignored = response.send(result);
        }
        ForgeControlRequest::AutoApprovalScopeCreate { request, response } => {
            let result = rebase_auto_scope_create(request)
                .and_then(|request| control.create_auto_approval_scope(&request));
            let _ignored = response.send(result);
        }
        ForgeControlRequest::AutoApprovalScopeRevoke { request, response } => {
            let result = rebase_auto_scope_revoke(request)
                .and_then(|request| control.revoke_auto_approval_scope(&request));
            let _ignored = response.send(result);
        }
        ForgeControlRequest::AutoApprovalScopeGet {
            scope,
            id,
            response,
        } => {
            let _ignored = response.send(control.get_auto_approval_scope(&scope, id));
        }
        ForgeControlRequest::ApprovalGrantConsume { request, response } => {
            let result = rebase_grant_consume(request)
                .and_then(|request| control.consume_execution_grant(&request));
            let _ignored = response.send(result);
        }
        ForgeControlRequest::AutoApprovalConsume { request, response } => {
            let result = rebase_auto_approval_consume(request)
                .and_then(|request| control.consume_auto_approval(&request));
            let _ignored = response.send(result);
        }
        other => dispatch_supervisor_request(control, other),
    }
}

fn dispatch_approval_cleanup_request(control: &ForgeControl, request: ForgeControlRequest) {
    match request {
        ForgeControlRequest::ApprovalCleanupPermitMint {
            owner,
            scope,
            selector,
            response,
        } => {
            let _ignored =
                response.send(control.mint_approval_cleanup_permit(owner, scope, selector));
        }
        ForgeControlRequest::ApprovalCleanupPrepare {
            permit,
            owner,
            selector,
            observed_at: _caller_observed_at,
            limit,
            response,
        } => {
            // Prepare owns the durable observation clock; the caller's value
            // is retained only as an untrusted request field.
            let result = runtime_timestamp_millis().and_then(|observed_at| {
                ForgeControl::prepare_approval_cleanup_plan(
                    &permit,
                    owner,
                    selector,
                    observed_at,
                    limit,
                )
            });
            let _ignored = response.send(result);
        }
        ForgeControlRequest::ApprovalCleanupApply {
            owner,
            plan,
            attempt,
            response,
        } => {
            let result = ForgeControl::apply_approval_cleanup_plan(owner, &plan, attempt);
            let _ignored = response.send(result);
        }
        ForgeControlRequest::ApprovalCleanupObserve {
            owner,
            plan,
            response,
        } => {
            let result = ForgeControl::observe_approval_cleanup_plan(owner, &plan);
            let _ignored = response.send(result);
        }
        other => dispatch_approval_request(control, other),
    }
}

fn dispatch_execution_stop_request(control: &ForgeControl, request: ForgeControlRequest) {
    match request {
        ForgeControlRequest::ExecutionStopPrepare {
            scope,
            request,
            response,
        } => {
            let result = runtime_timestamp_millis().and_then(|observed_at| {
                let request = forge_persistence::ExecutionStopRequest::new(
                    request.stop_id(),
                    request.workspace_id(),
                    request.request_id(),
                    request.owner_runtime_instance_id(),
                    *request.request_digest(),
                    observed_at,
                );
                control.prepare_execution_stop_context(&scope, request)
            });
            let _ignored = response.send(result);
        }
        ForgeControlRequest::ExecutionStopApply { context, response } => {
            let _ignored = response.send(control.apply_execution_stop_context(&context));
        }
        ForgeControlRequest::ExecutionStopObserve { context, response } => {
            let _ignored = response.send(ForgeControl::observe_execution_stop_context(&context));
        }
        ForgeControlRequest::OwnedExecutionStopHistory {
            permit,
            owner,
            request,
            response,
        } => {
            let _ignored = response.send(ForgeControl::observe_owned_stop_history(
                &permit, owner, request,
            ));
        }
        ForgeControlRequest::OwnedExecutionStopSettle {
            settlement,
            response,
        } => {
            let _ignored = response.send(ForgeControl::settle_owned_execution_stop_context(
                &settlement,
            ));
        }
        ForgeControlRequest::OwnedExecutionStopPrepare {
            permit,
            owner,
            request,
            response,
        } => {
            let result = runtime_timestamp_millis().and_then(|observed_at| {
                let request = forge_persistence::ExecutionStopRequest::new(
                    request.stop_id(),
                    request.workspace_id(),
                    request.request_id(),
                    request.owner_runtime_instance_id(),
                    *request.request_digest(),
                    observed_at,
                );
                ForgeControl::prepare_owned_execution_stop_context(&permit, owner, request)
            });
            let _ignored = response.send(result);
        }
        ForgeControlRequest::OwnedExecutionStopApply { context, response } => {
            let _ignored =
                response.send(ForgeControl::apply_owned_execution_stop_context(&context));
        }
        ForgeControlRequest::OwnedExecutionStopObserve { context, response } => {
            let _ignored =
                response.send(ForgeControl::observe_owned_execution_stop_context(&context));
        }
        other => dispatch_approval_request(control, other),
    }
}

fn dispatch_approval_expiry_request(control: &ForgeControl, request: ForgeControlRequest) {
    match request {
        ForgeControlRequest::ApprovalExpiryPrepare {
            scope,
            observed_at: _caller_observed_at,
            limit,
            response,
        } => {
            // Expiry preparation owns its observation clock in the worker.
            let result = runtime_timestamp_millis().and_then(|observed_at| {
                control.prepare_approval_expiry_plan(&scope, observed_at, limit)
            });
            let _ignored = response.send(result);
        }
        ForgeControlRequest::ApprovalExpiryApply {
            plan,
            attempt,
            response,
        } => {
            let _ignored = response.send(control.apply_approval_expiry_plan(&plan, attempt));
        }
        ForgeControlRequest::ApprovalExpiryObserve { plan, response } => {
            let _ignored = response.send(ForgeControl::observe_approval_expiry_plan(&plan));
        }
        other => dispatch_approval_request(control, other),
    }
}

fn dispatch_diff_request(control: &ForgeControl, request: ForgeControlRequest) {
    match request {
        ForgeControlRequest::DiffList { request, response } => {
            dispatch_diff_list(control, &request, &response);
        }
        ForgeControlRequest::DiffRead { request, response } => {
            dispatch_diff_read(control, &request, &response);
        }
        ForgeControlRequest::DiffDoctor { request, response } => {
            dispatch_diff_doctor(control, &request, &response);
        }
        ForgeControlRequest::DiffRetentionPlan { request, response } => {
            dispatch_diff_retention_plan(control, &request, &response);
        }
        ForgeControlRequest::DiffPurge { request, response } => {
            dispatch_diff_purge(control, request, &response);
        }
        ForgeControlRequest::DiffArtifactDoctor { request, response } => {
            dispatch_diff_artifact_doctor(control, &request, &response);
        }
        ForgeControlRequest::DeleteOrphanDiffArtifact { request, response } => {
            dispatch_delete_orphan_diff_artifact(control, &request, &response);
        }
        other => dispatch_supervisor_request(control, other),
    }
}

fn dispatch_diff_list(
    control: &ForgeControl,
    request: &DiffListRequest,
    response: &Response<DiffListResult>,
) {
    let _ignored = response.send(control.diff_list(request));
}

fn dispatch_diff_read(
    control: &ForgeControl,
    request: &DiffReadRequest,
    response: &Response<DiffReadResult>,
) {
    let _ignored = response.send(control.diff_read(request));
}

fn dispatch_diff_doctor(
    control: &ForgeControl,
    request: &DiffDoctorRequest,
    response: &Response<DiffDoctorResult>,
) {
    let _ignored = response.send(control.diff_doctor(request));
}

fn dispatch_diff_retention_plan(
    control: &ForgeControl,
    request: &DiffRetentionPlanRequest,
    response: &Response<DiffRetentionPlanResult>,
) {
    let _ignored = response.send(control.plan_diff_retention(request));
}

fn dispatch_diff_purge(
    control: &ForgeControl,
    mut request: DiffPurgeRequest,
    response: &Response<DiffPurgeResult>,
) {
    let result = runtime_timestamp_millis().and_then(|observed_at| {
        request.observed_at = observed_at;
        control.purge_diff(&request)
    });
    let _ignored = response.send(result);
}

fn dispatch_diff_artifact_doctor(
    control: &ForgeControl,
    request: &DiffArtifactDoctorRequest,
    response: &Response<DiffArtifactDoctorResult>,
) {
    let _ignored = response.send(control.diff_artifact_doctor(request));
}

fn dispatch_delete_orphan_diff_artifact(
    control: &ForgeControl,
    request: &DeleteOrphanDiffArtifactRequest,
    response: &Response<DeleteOrphanDiffArtifactResult>,
) {
    let _ignored = response.send(control.delete_orphan_diff_artifact(request));
}

fn dispatch_file_read(
    control: &ForgeControl,
    mut request: FileReadRequest,
    response: &Response<FileReadResult>,
) {
    let result = runtime_timestamp_millis().and_then(|observed_at| {
        request.activity.observed_at = observed_at;
        control.file_read(&request)
    });
    let _ignored = response.send(result);
}

fn dispatch_file_list(
    control: &ForgeControl,
    mut request: FileListRequest,
    response: &Response<FileListResult>,
) {
    let result = runtime_timestamp_millis().and_then(|observed_at| {
        request.activity.observed_at = observed_at;
        control.file_list(&request)
    });
    let _ignored = response.send(result);
}

fn dispatch_text_search(
    control: &ForgeControl,
    mut request: TextSearchRequest,
    response: &Response<TextSearchResult>,
) {
    let result = runtime_timestamp_millis().and_then(|observed_at| {
        request.activity.observed_at = observed_at;
        control.text_search(&request)
    });
    let _ignored = response.send(result);
}

fn dispatch_file_read_slice(
    control: &ForgeControl,
    mut request: FileReadSliceRequest,
    response: &Response<FileReadSliceResult>,
) {
    let result = runtime_timestamp_millis().and_then(|observed_at| {
        request.activity.observed_at = observed_at;
        control.file_read_slice(&request)
    });
    let _ignored = response.send(result);
}

fn dispatch_file_apply_patch(
    control: &ForgeControl,
    mut request: FileApplyPatchRequest,
    response: &Response<FileApplyPatchResult>,
) {
    let result = runtime_timestamp_millis().and_then(|observed_at| {
        request.activity.observed_at = observed_at;
        control.file_apply_patch(&request)
    });
    let _ignored = response.send(result);
}

fn dispatch_source_tree_apply(
    control: &ForgeControl,
    mut request: SourceTreeTransactionRequest,
    response: &Response<SourceTreeTransactionResult>,
) {
    let result = runtime_timestamp_millis().and_then(|observed_at| {
        request.activity.observed_at = observed_at;
        control.source_tree_apply(&request)
    });
    let _ignored = response.send(result);
}

fn dispatch_file_mutation(
    control: &ForgeControl,
    mut request: FileMutationRequest,
    response: &Response<FileMutationResult>,
) {
    let result = runtime_timestamp_millis().and_then(|observed_at| {
        request.activity.observed_at = observed_at;
        control.file_mutate(&request)
    });
    let _ignored = response.send(result);
}

fn rebase_policy_request(
    mut request: WorkspacePolicyReplaceRequest,
) -> Result<WorkspacePolicyReplaceRequest, ControlError> {
    request.observed_at = runtime_timestamp_millis()?;
    Ok(request)
}

fn rebase_approval_create(
    mut request: ApprovalCreateRequest,
) -> Result<ApprovalCreateRequest, ControlError> {
    let (observed_at, expires_at) =
        approval_window(request.activity.observed_at, request.expires_at)?;
    request.activity.observed_at = observed_at;
    request.expires_at = expires_at;
    Ok(request)
}

fn rebase_approval_once(
    mut request: ApprovalOnceRequest,
) -> Result<ApprovalOnceRequest, ControlError> {
    let (observed_at, grant_expires_at) =
        approval_window(request.observed_at, request.grant_expires_at)?;
    request.observed_at = observed_at;
    request.grant_expires_at = grant_expires_at;
    Ok(request)
}

fn rebase_approval_decision(
    mut request: ApprovalDecisionRequest,
) -> Result<ApprovalDecisionRequest, ControlError> {
    request.observed_at = runtime_timestamp_millis()?;
    Ok(request)
}

fn rebase_auto_scope_create(
    request: AutoApprovalScopeCreateRequest,
) -> Result<AutoApprovalScopeCreateRequest, ControlError> {
    let (created_at, expires_at) =
        approval_window(request.created_at, request.auto_scope.expires_at())?;
    let auto_scope = AutoApprovalScope::from_parts(
        request.auto_scope.id(),
        request.auto_scope.workspace_id(),
        request.auto_scope.activity_id(),
        request.auto_scope.action(),
        request.auto_scope.permission_ceiling(),
        request.auto_scope.policy_revision(),
        expires_at,
        request.auto_scope.max_uses(),
        request.auto_scope.used_count(),
        request.auto_scope.state(),
        request.auto_scope.revision(),
    )
    .map_err(|error| ControlError::with_source(ControlErrorCode::InvalidInput, error))?;
    Ok(AutoApprovalScopeCreateRequest {
        scope: request.scope,
        auto_scope,
        created_at,
    })
}

fn rebase_auto_scope_revoke(
    mut request: AutoApprovalScopeRevokeRequest,
) -> Result<AutoApprovalScopeRevokeRequest, ControlError> {
    request.observed_at = runtime_timestamp_millis()?;
    Ok(request)
}

fn rebase_grant_consume(
    mut request: ApprovalGrantConsumeRequest,
) -> Result<ApprovalGrantConsumeRequest, ControlError> {
    let observed_at = runtime_timestamp_millis()?;
    request.activity.observed_at = observed_at;
    request.begin = request.begin.with_observed_at(observed_at);
    Ok(request)
}

fn rebase_auto_approval_consume(
    mut request: AutoApprovalConsumeRequest,
) -> Result<AutoApprovalConsumeRequest, ControlError> {
    let observed_at = runtime_timestamp_millis()?;
    request.activity.observed_at = observed_at;
    request.begin = request.begin.with_observed_at(observed_at);
    Ok(request)
}

fn approval_window(
    proposed_at: TimestampMillis,
    proposed_expiry: TimestampMillis,
) -> Result<(TimestampMillis, TimestampMillis), ControlError> {
    let duration = proposed_expiry
        .get()
        .checked_sub(proposed_at.get())
        .filter(|duration| {
            (MIN_APPROVAL_WINDOW_MILLIS..=MAX_APPROVAL_WINDOW_MILLIS).contains(duration)
        })
        .ok_or_else(|| ControlError::new(ControlErrorCode::InvalidInput))?;
    let observed_at = runtime_timestamp_millis()?;
    let expires_at = observed_at
        .get()
        .checked_add(duration)
        .and_then(|value| TimestampMillis::new(value).ok())
        .ok_or_else(|| ControlError::new(ControlErrorCode::InvalidInput))?;
    Ok((observed_at, expires_at))
}

pub(crate) fn runtime_timestamp_millis() -> Result<TimestampMillis, ControlError> {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| ControlError::with_source(ControlErrorCode::Internal, error))?;
    let millis = i64::try_from(duration.as_millis())
        .map_err(|error| ControlError::with_source(ControlErrorCode::Internal, error))?;
    TimestampMillis::new(millis)
        .map_err(|error| ControlError::with_source(ControlErrorCode::Internal, error))
}

fn runtime_lease_window(
    requested_at: TimestampMillis,
    requested_until: TimestampMillis,
) -> Result<(TimestampMillis, TimestampMillis), ControlError> {
    let duration = requested_until
        .get()
        .checked_sub(requested_at.get())
        .filter(|duration| *duration > 0)
        .ok_or_else(|| ControlError::new(ControlErrorCode::InvalidInput))?;
    let observed_at = runtime_timestamp_millis()?;
    let lease_until = observed_at
        .get()
        .checked_add(duration)
        .ok_or_else(|| ControlError::new(ControlErrorCode::InvalidInput))?;
    let lease_until = TimestampMillis::new(lease_until)
        .map_err(|error| ControlError::with_source(ControlErrorCode::InvalidInput, error))?;
    Ok((observed_at, lease_until))
}

fn rebase_renew_activity_lease(
    command: &RenewActivityLease,
) -> Result<RenewActivityLease, ControlError> {
    let (observed_at, lease_until) =
        runtime_lease_window(command.observed_at(), command.lease_until())?;
    Ok(RenewActivityLease::new(
        command.id(),
        command.owner_id(),
        command.expected_lease_revision(),
        lease_until,
        observed_at,
    ))
}

fn recovery_lease_duration(
    requested_at: TimestampMillis,
    requested_until: TimestampMillis,
) -> Result<RecoveryLeaseDurationMillis, ControlError> {
    let duration = requested_until
        .get()
        .checked_sub(requested_at.get())
        .ok_or_else(|| ControlError::new(ControlErrorCode::InvalidInput))?;
    RecoveryLeaseDurationMillis::new(duration)
        .map_err(|error| ControlError::with_source(ControlErrorCode::InvalidInput, error))
}

fn rebase_renew_recovery_lease(
    command: RenewRecoveryLease,
) -> Result<RenewRecoveryLease, ControlError> {
    let duration = recovery_lease_duration(command.observed_at(), command.lease_until())?;
    let observed_at = runtime_timestamp_millis()?;
    RenewRecoveryLease::new(
        command.workspace_id(),
        command.owner_id(),
        command.expected_epoch(),
        command.expected_revision(),
        duration,
        observed_at,
    )
    .map_err(|error| ControlError::with_source(ControlErrorCode::InvalidInput, error))
}

fn rebase_release_recovery_lease(
    command: ReleaseRecoveryLease,
) -> Result<ReleaseRecoveryLease, ControlError> {
    Ok(ReleaseRecoveryLease::new(
        command.workspace_id(),
        command.owner_id(),
        command.expected_epoch(),
        command.expected_revision(),
        runtime_timestamp_millis()?,
    ))
}

fn close_owned_activities(
    control: &ForgeControl,
    owned_activities: Vec<OwnedActivityLease>,
) -> ShutdownReport {
    let mut report = ShutdownReport {
        attempted: owned_activities.len(),
        ..ShutdownReport::empty()
    };
    report.failures.reserve(owned_activities.len());
    let observed_at = match runtime_timestamp_millis() {
        Ok(observed_at) => observed_at,
        Err(error) => {
            report.failures.resize(owned_activities.len(), error.view());
            return report;
        }
    };
    for owned in owned_activities {
        match control.close_activity(
            owned.scope(),
            owned.activity_id(),
            owned.runtime_instance_id(),
            owned.expected_lease_revision(),
            observed_at,
        ) {
            Ok(result) if result.is_committed_but_unconfirmed() => {
                report.committed_but_unconfirmed += 1;
                report.failures.push(ControlError::committed().view());
            }
            Ok(_) => report.closed += 1,
            Err(error) => report.failures.push(error.view()),
        }
    }
    report
}

fn drain_queued_requests(receiver: &Receiver<ForgeControlRequest>) {
    drain_queued_requests_iter(std::iter::from_fn(|| receiver.try_recv().ok()));
}

fn drain_queued_queue(queue: &QueueMailbox<ForgeControlRequest>) {
    drain_queued_requests_iter(std::iter::from_fn(|| {
        match queue.try_dequeue(queue_timestamp_micros()) {
            Ok(QueueDequeue::Item { item, .. }) => Some(item),
            Ok(QueueDequeue::Empty | QueueDequeue::Closed) | Err(_) => None,
        }
    }));
}

#[allow(clippy::too_many_lines)]
fn drain_queued_requests_iter<I>(requests: I)
where
    I: Iterator<Item = ForgeControlRequest>,
{
    for request in requests {
        match request {
            request @ (ForgeControlRequest::LocationList { .. }
            | ForgeControlRequest::LocationRemovalProbe { .. }
            | ForgeControlRequest::LocationRemove { .. }
            | ForgeControlRequest::RegisterLocation { .. }
            | ForgeControlRequest::SetLocationState { .. }
            | ForgeControlRequest::RegisterWorkspace { .. }
            | ForgeControlRequest::ProbeWorkspaceRegistration { .. }
            | ForgeControlRequest::WorkspaceRootRecoveryProbe { .. }
            | ForgeControlRequest::WorkspaceRootRecoveryPrepare { .. }
            | ForgeControlRequest::WorkspaceRootRecoveryCommit { .. }
            | ForgeControlRequest::WorkspaceRootRecoveryReadback { .. }
            | ForgeControlRequest::WorkspaceInventory { .. }
            | ForgeControlRequest::WorkspaceList { .. }
            | ForgeControlRequest::WorkspaceDiscover { .. }
            | ForgeControlRequest::ResolveWorkspace { .. }
            | ForgeControlRequest::AuthorizeActivity { .. }
            | ForgeControlRequest::WorkspaceDoctor { .. }
            | ForgeControlRequest::WorkspaceIdentityDoctor { .. }
            | ForgeControlRequest::BootstrapActivity { .. }) => reject_queued_workspace(request),
            request @ (ForgeControlRequest::AgentSessionOpen { .. }
            | ForgeControlRequest::AgentCoordinationView { .. }
            | ForgeControlRequest::AgentInboxList { .. }
            | ForgeControlRequest::AgentSessionResolve { .. }
            | ForgeControlRequest::AgentBindingReserve { .. }
            | ForgeControlRequest::AgentBindingReserveReference { .. }
            | ForgeControlRequest::AgentBindingReservationRead { .. }
            | ForgeControlRequest::AgentOperationsDelegation { .. }
            | ForgeControlRequest::AgentOperationsDelegationReference { .. }
            | ForgeControlRequest::AgentOperationsDelegationRead { .. }
            | ForgeControlRequest::AgentOperationsFreeze { .. }
            | ForgeControlRequest::AgentOperationsFreezeRead { .. }
            | ForgeControlRequest::AgentOperationsExport { .. }
            | ForgeControlRequest::AgentOperationsFreezeRelease { .. }
            | ForgeControlRequest::AgentBindingActivate { .. }
            | ForgeControlRequest::AgentBindingActivateReference { .. }
            | ForgeControlRequest::AgentBindingActivationRead { .. }
            | ForgeControlRequest::AgentBindingReject { .. }
            | ForgeControlRequest::AgentBindingRejectionRead { .. }
            | ForgeControlRequest::AgentSessionReconcile { .. }
            | ForgeControlRequest::AgentSessionReconcileDestination { .. }
            | ForgeControlRequest::AgentSessionReconciliationRead { .. }
            | ForgeControlRequest::AgentDepartureReconcile { .. }
            | ForgeControlRequest::AgentDepartureReconcileDestination { .. }
            | ForgeControlRequest::AgentDepartureReconciliationRead { .. }
            | ForgeControlRequest::AgentEffectOutboxRead { .. }
            | ForgeControlRequest::EffectFactOutboxRead { .. }
            | ForgeControlRequest::AgentSessionProve { .. }
            | ForgeControlRequest::AgentSetFocus { .. }
            | ForgeControlRequest::AgentVerifyExecutionAuthority { .. }
            | ForgeControlRequest::AgentAssignmentMutate { .. }
            | ForgeControlRequest::AgentAssignmentOfferSeal { .. }
            | ForgeControlRequest::AgentAssignmentOfferSealGet { .. }
            | ForgeControlRequest::AgentPublishWorkUpdate { .. }
            | ForgeControlRequest::AgentList { .. }
            | ForgeControlRequest::AgentAssignmentGet { .. }
            | ForgeControlRequest::AgentAssignmentList { .. }
            | ForgeControlRequest::AgentGetContext { .. }
            | ForgeControlRequest::WriterLeaseAcquire { .. }
            | ForgeControlRequest::WriterLeaseRenew { .. }
            | ForgeControlRequest::WriterLeaseRelease { .. }
            | ForgeControlRequest::WriterLeaseGet { .. }
            | ForgeControlRequest::WriterLeaseList { .. }
            | ForgeControlRequest::WriterLeaseRecoveryRelease { .. }
            | ForgeControlRequest::AgentDagPlanCommit { .. }
            | ForgeControlRequest::CoordinatorActor { .. }
            | ForgeControlRequest::CoordinatorGet { .. }
            | ForgeControlRequest::CoordinatorClaim { .. }
            | ForgeControlRequest::CoordinatorTransfer { .. }
            | ForgeControlRequest::CoordinatorRecoveryPrepare { .. }
            | ForgeControlRequest::CoordinatorRecoveryConfirm { .. }
            | ForgeControlRequest::CoordinatorRecoveryReceipt { .. }
            | ForgeControlRequest::CoordinatorRecoveryHistory { .. }) => {
                reject_queued_agent(request);
            }
            ForgeControlRequest::RenewActivityLease { response, .. }
            | ForgeControlRequest::RenewActivityLeaseBatch { response, .. }
            | ForgeControlRequest::SupervisedActivityLeaseRenew { response, .. }
            | ForgeControlRequest::CloseActivity { response, .. }
            | ForgeControlRequest::CloseOwnedActivityBatch { response, .. }
            | ForgeControlRequest::ReleaseActivityLease { response, .. }
            | ForgeControlRequest::ReleaseActivityLeaseBatch { response, .. }
            | ForgeControlRequest::ReconcileExpiredActivityLeases { response, .. } => {
                let _ignored =
                    response.send(Err(ControlError::new(ControlErrorCode::WorkerShuttingDown)));
            }
            ForgeControlRequest::ObserveActivityLeases { response, .. } => {
                let _ignored =
                    response.send(Err(ControlError::new(ControlErrorCode::WorkerShuttingDown)));
            }
            ForgeControlRequest::ListActivityProjections { response, .. } => {
                let _ignored =
                    response.send(Err(ControlError::new(ControlErrorCode::WorkerShuttingDown)));
            }
            ForgeControlRequest::ListWorkspaceActivityProjections { response, .. } => {
                let _ignored =
                    response.send(Err(ControlError::new(ControlErrorCode::WorkerShuttingDown)));
            }
            ForgeControlRequest::ActivityRead { response, .. } => {
                let _ignored =
                    response.send(Err(ControlError::new(ControlErrorCode::WorkerShuttingDown)));
            }
            ForgeControlRequest::ProjectCommandResolve { response, .. } => {
                let _ignored = response.send(worker_shutting_down());
            }
            ForgeControlRequest::ProjectCommandPrepareVerification { response, .. } => {
                let _ignored = response.send(worker_shutting_down());
            }
            ForgeControlRequest::WorkspaceVerificationPrepare { response, .. } => {
                let _ignored = response.send(worker_shutting_down());
            }
            ForgeControlRequest::ProjectCommandList { response, .. } => {
                let _ignored =
                    response.send(Err(ControlError::new(ControlErrorCode::WorkerShuttingDown)));
            }
            ForgeControlRequest::GeneratedArtifactInventory { response, .. } => {
                let _ignored = response.send(worker_shutting_down());
            }
            ForgeControlRequest::GeneratedPackageAccess { response, .. } => {
                let _ignored = response.send(worker_shutting_down());
            }
            ForgeControlRequest::FileRead { response, .. } => {
                let _ignored =
                    response.send(Err(ControlError::new(ControlErrorCode::WorkerShuttingDown)));
            }
            ForgeControlRequest::FileList { response, .. } => {
                let _ignored =
                    response.send(Err(ControlError::new(ControlErrorCode::WorkerShuttingDown)));
            }
            ForgeControlRequest::TextSearch { response, .. } => {
                let _ignored =
                    response.send(Err(ControlError::new(ControlErrorCode::WorkerShuttingDown)));
            }
            ForgeControlRequest::FileMutationReadback { response, .. } => {
                send_response(
                    &response,
                    Err(ControlError::new(ControlErrorCode::WorkerShuttingDown)),
                );
            }
            ForgeControlRequest::SourceTreeReadback { response, .. } => {
                send_response(
                    &response,
                    Err(ControlError::new(ControlErrorCode::WorkerShuttingDown)),
                );
            }
            ForgeControlRequest::GoalMutation { response, .. } => {
                send_response(
                    &response,
                    Err(ControlError::new(ControlErrorCode::WorkerShuttingDown)),
                );
            }
            ForgeControlRequest::GoalMutationReadback { response, .. } => {
                send_response(
                    &response,
                    Err(ControlError::new(ControlErrorCode::WorkerShuttingDown)),
                );
            }
            ForgeControlRequest::DagPlanReadback { response, .. } => {
                send_response(
                    &response,
                    Err(ControlError::new(ControlErrorCode::WorkerShuttingDown)),
                );
            }

            ForgeControlRequest::FileReadSlice { response, .. } => {
                let _ignored =
                    response.send(Err(ControlError::new(ControlErrorCode::WorkerShuttingDown)));
            }
            ForgeControlRequest::FileApplyPatch { response, .. }
            | ForgeControlRequest::FileImportBinary { response, .. }
            | ForgeControlRequest::FileMutate { response, .. } => {
                let _ignored =
                    response.send(Err(ControlError::new(ControlErrorCode::WorkerShuttingDown)));
            }
            ForgeControlRequest::SourceTreeApply { response, .. } => {
                let _ignored =
                    response.send(Err(ControlError::new(ControlErrorCode::WorkerShuttingDown)));
            }
            ForgeControlRequest::CheckpointRestoreRun { response, .. } => {
                let _ignored =
                    response.send(Err(ControlError::new(ControlErrorCode::WorkerShuttingDown)));
            }
            request @ (ForgeControlRequest::ExecutionMarkRunning { .. }
            | ForgeControlRequest::ExecutionCompleteGenerated { .. }
            | ForgeControlRequest::ExecutionComplete { .. }
            | ForgeControlRequest::ExecutionJournalOutput { .. }
            | ForgeControlRequest::ExecutionJournalComplete { .. }
            | ForgeControlRequest::ExecutionJournalCompleteGenerated { .. }
            | ForgeControlRequest::ExecutionJournalFail { .. }
            | ForgeControlRequest::ExecutionJournalReconcileOutput { .. }
            | ForgeControlRequest::ExecutionJournalReconcileTerminal { .. }
            | ForgeControlRequest::ExecutionFail { .. }
            | ForgeControlRequest::ExecutionReconcile { .. }
            | ForgeControlRequest::ExecutionList { .. }
            | ForgeControlRequest::ExecutionGet { .. }
            | ForgeControlRequest::VerificationProjection { .. }
            | ForgeControlRequest::ExecutionEvidenceInventory { .. }
            | ForgeControlRequest::ExecutionEvidenceRead { .. }
            | ForgeControlRequest::ExecutionGeneratedPackage { .. }
            | ForgeControlRequest::ExecutionGetEvidence { .. }
            | ForgeControlRequest::ExecutionGetAuthorized { .. }
            | ForgeControlRequest::ExecutionOutputAppendBatch { .. }
            | ForgeControlRequest::ExecutionOutputRead { .. }
            | ForgeControlRequest::ExecutionOutputReadAuthorized { .. }
            | ForgeControlRequest::ExecutionReadAuthorized { .. }) => {
                reject_queued_execution(request);
            }
            request @ (ForgeControlRequest::GoalCreate { .. }
            | ForgeControlRequest::GoalReviseContract { .. }
            | ForgeControlRequest::GoalGet { .. }
            | ForgeControlRequest::GoalList { .. }
            | ForgeControlRequest::GoalTransition { .. }
            | ForgeControlRequest::GoalReview { .. }
            | ForgeControlRequest::GoalComplete { .. }) => reject_queued_goal(request),
            request @ (ForgeControlRequest::DagGetCurrent { .. }
            | ForgeControlRequest::DagGetRevision { .. }
            | ForgeControlRequest::DagNodeAssignmentSnapshot { .. }
            | ForgeControlRequest::DagNodeStart { .. }
            | ForgeControlRequest::DagNodeComplete { .. }
            | ForgeControlRequest::DagNodeUpdate { .. }) => reject_queued_dag(request),
            request @ (ForgeControlRequest::RecoveryLeaseGet { .. }
            | ForgeControlRequest::RecoveryLeaseClaim { .. }
            | ForgeControlRequest::RecoveryLeaseRenew { .. }
            | ForgeControlRequest::RecoveryLeaseRelease { .. }
            | ForgeControlRequest::RecoveryMaintenanceRun { .. }
            | ForgeControlRequest::LeadershipWorkCut { .. }
            | ForgeControlRequest::RecoveryMaintenanceDurable { .. }
            | ForgeControlRequest::RecoveryMaintenanceGet { .. }) => {
                reject_queued_recovery(request);
            }
            request @ (ForgeControlRequest::EnsureWorkspacePolicy { .. }
            | ForgeControlRequest::GetWorkspacePolicy { .. }
            | ForgeControlRequest::ReplaceWorkspacePolicy { .. }
            | ForgeControlRequest::WorkspaceQueueSettingsGet { .. }
            | ForgeControlRequest::WorkspaceQueueSettingsReplace { .. }
            | ForgeControlRequest::GoalDelete { .. }
            | ForgeControlRequest::GoalDeletePending { .. }
            | ForgeControlRequest::ApprovalCreate { .. }
            | ForgeControlRequest::ApprovalListPending { .. }
            | ForgeControlRequest::ApprovalGet { .. }
            | ForgeControlRequest::ApprovalGetWithGrant { .. }
            | ForgeControlRequest::ApprovalApproveOnce { .. }
            | ForgeControlRequest::ApprovalDecide { .. }
            | ForgeControlRequest::AutoApprovalScopeCreate { .. }
            | ForgeControlRequest::AutoApprovalScopeRevoke { .. }
            | ForgeControlRequest::AutoApprovalScopeGet { .. }
            | ForgeControlRequest::ApprovalGrantConsume { .. }
            | ForgeControlRequest::AutoApprovalConsume { .. }
            | ForgeControlRequest::ApprovalCleanupPermitMint { .. }
            | ForgeControlRequest::ApprovalCleanupPrepare { .. }
            | ForgeControlRequest::ApprovalCleanupApply { .. }
            | ForgeControlRequest::ApprovalCleanupObserve { .. }
            | ForgeControlRequest::ApprovalExpiryPrepare { .. }
            | ForgeControlRequest::ApprovalExpiryApply { .. }
            | ForgeControlRequest::ApprovalExpiryObserve { .. }
            | ForgeControlRequest::ExecutionStopPrepare { .. }
            | ForgeControlRequest::ExecutionStopApply { .. }
            | ForgeControlRequest::ExecutionStopObserve { .. }
            | ForgeControlRequest::OwnedExecutionStopPrepare { .. }
            | ForgeControlRequest::OwnedExecutionStopApply { .. }
            | ForgeControlRequest::OwnedExecutionStopObserve { .. }
            | ForgeControlRequest::OwnedExecutionStopSettle { .. }
            | ForgeControlRequest::OwnedExecutionStopHistory { .. }) => {
                reject_queued_approval(request);
            }
            request @ (ForgeControlRequest::DiffList { .. }
            | ForgeControlRequest::DiffRead { .. }
            | ForgeControlRequest::DiffDoctor { .. }
            | ForgeControlRequest::DiffRetentionPlan { .. }
            | ForgeControlRequest::DiffPurge { .. }
            | ForgeControlRequest::DiffArtifactDoctor { .. }
            | ForgeControlRequest::DeleteOrphanDiffArtifact { .. }) => reject_queued_diff(request),
            ForgeControlRequest::SemanticEventsPage { response, .. } => {
                let _ignored = response.send(worker_shutting_down());
            }
            ForgeControlRequest::WorkspaceSemanticSnapshot { response, .. } => {
                let _ignored = response.send(worker_shutting_down());
            }
            ForgeControlRequest::ActivitySuccessorCreate { response, .. } => {
                let _ignored = response.send(worker_shutting_down());
            }
            ForgeControlRequest::ActivitySuccessorGet { response, .. } => {
                let _ignored = response.send(worker_shutting_down());
            }
            ForgeControlRequest::ExpiredActivityRecoveryProbe { response, .. } => {
                let _ignored = response.send(worker_shutting_down());
            }
            ForgeControlRequest::ExpiredActivityRecoveryRun { response, .. } => {
                let _ignored = response.send(worker_shutting_down());
            }
            ForgeControlRequest::ExpiredActivityRecoveryGet { response, .. } => {
                let _ignored = response.send(worker_shutting_down());
            }
            ForgeControlRequest::UnstartedActivityContinuationProbe { response, .. } => {
                let _ignored = response.send(worker_shutting_down());
            }
            ForgeControlRequest::UnstartedActivityContinuationRun { response, .. } => {
                let _ignored = response.send(worker_shutting_down());
            }
            ForgeControlRequest::UnstartedActivityContinuationGet { response, .. } => {
                let _ignored = response.send(worker_shutting_down());
            }
            ForgeControlRequest::StartedActivityLeaseResumeProbe { response, .. } => {
                let _ignored = response.send(worker_shutting_down());
            }
            ForgeControlRequest::StartedActivityLeaseResumeRun { response, .. } => {
                let _ignored = response.send(worker_shutting_down());
            }
            ForgeControlRequest::StartedActivityLeaseResumeGet { response, .. } => {
                let _ignored = response.send(worker_shutting_down());
            }
            ForgeControlRequest::QuiescentActivityLeaseResumeProbe { response, .. } => {
                let _ignored = response.send(worker_shutting_down());
            }
            ForgeControlRequest::QuiescentActivityLeaseResumeRun { response, .. } => {
                let _ignored = response.send(worker_shutting_down());
            }
            ForgeControlRequest::QuiescentActivityLeaseResumeGet { response, .. } => {
                let _ignored = response.send(worker_shutting_down());
            }
            ForgeControlRequest::Shutdown { response, .. } => {
                if let Some(response) = response {
                    let _ignored = response.send(ShutdownReport::empty());
                }
            }
        }
    }
}

fn reject_queued_agent(request: ForgeControlRequest) {
    match request {
        ForgeControlRequest::AgentCoordinationView { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::AgentInboxList { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::AgentSessionOpen { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::AgentBindingReserve { response, .. }
        | ForgeControlRequest::AgentBindingReserveReference { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::AgentBindingReservationRead { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::AgentOperationsDelegation { response, .. }
        | ForgeControlRequest::AgentOperationsDelegationReference { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::AgentOperationsDelegationRead { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::AgentOperationsFreeze { response, .. }
        | ForgeControlRequest::AgentOperationsFreezeRelease { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::AgentOperationsFreezeRead { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::AgentOperationsExport { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::AgentBindingActivate { response, .. }
        | ForgeControlRequest::AgentBindingActivateReference { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::AgentBindingActivationRead { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::AgentSessionReconcile { response, .. }
        | ForgeControlRequest::AgentSessionReconcileDestination { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::AgentSessionReconciliationRead { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::AgentEffectOutboxRead { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::EffectFactOutboxRead { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        other => reject_queued_agent_state(other),
    }
}

fn reject_queued_agent_state(request: ForgeControlRequest) {
    match request {
        ForgeControlRequest::AgentSessionResolve { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::AgentSessionProve { response, .. }
        | ForgeControlRequest::AgentSetFocus { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::AgentDepartureReconcile { response, .. }
        | ForgeControlRequest::AgentDepartureReconcileDestination { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::AgentDepartureReconciliationRead { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::AgentPublishWorkUpdate { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::AgentVerifyExecutionAuthority { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::AgentList { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::AgentGetContext { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::AgentAssignmentMutate { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::AgentAssignmentOfferSeal { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::AgentAssignmentOfferSealGet { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::AgentAssignmentGet { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::AgentAssignmentList { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::WriterLeaseAcquire { response, .. }
        | ForgeControlRequest::WriterLeaseRenew { response, .. }
        | ForgeControlRequest::WriterLeaseRelease { response, .. }
        | ForgeControlRequest::WriterLeaseRecoveryRelease { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::WriterLeaseGet { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::WriterLeaseList { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::AgentDagPlanCommit { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::CoordinatorActor { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::CoordinatorGet { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::CoordinatorClaim { response, .. }
        | ForgeControlRequest::CoordinatorTransfer { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        other => reject_queued_coordinator_recovery(other),
    }
}

fn reject_queued_coordinator_recovery(request: ForgeControlRequest) {
    match request {
        ForgeControlRequest::CoordinatorRecoveryPrepare { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::CoordinatorRecoveryReceipt { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::CoordinatorRecoveryHistory { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::CoordinatorRecoveryConfirm { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        other => reject_queued_workspace(other),
    }
}

fn reject_queued_workspace(request: ForgeControlRequest) {
    match request {
        ForgeControlRequest::LocationRemovalProbe { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::LocationRemove { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::WorkspaceInventory { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::RegisterWorkspace { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::ProbeWorkspaceRegistration { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::WorkspaceRootRecoveryProbe { response, .. }
        | ForgeControlRequest::WorkspaceRootRecoveryPrepare { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::WorkspaceRootRecoveryCommit { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::WorkspaceRootRecoveryReadback { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::LocationList { response } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::RegisterLocation { response, .. }
        | ForgeControlRequest::SetLocationState { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::WorkspaceList { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::WorkspaceDiscover { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::ResolveWorkspace { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::AuthorizeActivity { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::WorkspaceDoctor { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::WorkspaceIdentityDoctor { response } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::BootstrapActivity { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        _ => {}
    }
}

fn reject_queued_approval(request: ForgeControlRequest) {
    match request {
        ForgeControlRequest::EnsureWorkspacePolicy { response, .. }
        | ForgeControlRequest::ReplaceWorkspacePolicy { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::GetWorkspacePolicy { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::WorkspaceQueueSettingsGet { response, .. } => {
            let _ignored =
                response.send(Err(ControlError::new(ControlErrorCode::WorkerShuttingDown)));
        }
        ForgeControlRequest::GoalDelete { response, .. } => {
            let _ignored =
                response.send(Err(ControlError::new(ControlErrorCode::WorkerShuttingDown)));
        }
        ForgeControlRequest::GoalDeletePending { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::WorkspaceQueueSettingsReplace { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::ApprovalCreate { response, .. }
        | ForgeControlRequest::ApprovalDecide { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::ApprovalListPending { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::ApprovalGet { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::ApprovalGetWithGrant { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::ApprovalApproveOnce { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::AutoApprovalScopeCreate { response, .. }
        | ForgeControlRequest::AutoApprovalScopeRevoke { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::AutoApprovalScopeGet { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::ApprovalGrantConsume { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::AutoApprovalConsume { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::ApprovalCleanupApply { response, .. }
        | ForgeControlRequest::ApprovalExpiryApply { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::ApprovalCleanupPermitMint { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::ApprovalCleanupPrepare { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::ApprovalCleanupObserve { response, .. }
        | ForgeControlRequest::ApprovalExpiryObserve { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::ExecutionStopPrepare { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::ExecutionStopApply { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::ExecutionStopObserve { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::OwnedExecutionStopHistory { response, .. }
        | ForgeControlRequest::OwnedExecutionStopObserve { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::OwnedExecutionStopSettle { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::OwnedExecutionStopPrepare { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::OwnedExecutionStopApply { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::ApprovalExpiryPrepare { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        _ => {}
    }
}

fn reject_queued_execution(request: ForgeControlRequest) {
    match request {
        ForgeControlRequest::ExecutionJournalReconcileOutput { response, .. }
        | ForgeControlRequest::ExecutionJournalReconcileTerminal { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::ExecutionJournalComplete { response, .. }
        | ForgeControlRequest::ExecutionJournalCompleteGenerated { response, .. }
        | ForgeControlRequest::ExecutionJournalFail { response, .. }
        | ForgeControlRequest::ExecutionMarkRunning { response, .. }
        | ForgeControlRequest::ExecutionCompleteGenerated { response, .. }
        | ForgeControlRequest::ExecutionComplete { response, .. }
        | ForgeControlRequest::ExecutionFail { response, .. }
        | ForgeControlRequest::ExecutionGetAuthorized { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::ExecutionGetEvidence { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::ExecutionReconcile { response, .. }
        | ForgeControlRequest::ExecutionList { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::ExecutionGet { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::VerificationProjection { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::ExecutionEvidenceInventory { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::ExecutionEvidenceRead { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::ExecutionGeneratedPackage { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::ExecutionJournalOutput { response, .. }
        | ForgeControlRequest::ExecutionOutputAppendBatch { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::ExecutionOutputRead { response, .. }
        | ForgeControlRequest::ExecutionOutputReadAuthorized { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::ExecutionReadAuthorized { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        _ => {}
    }
}

fn reject_queued_goal(request: ForgeControlRequest) {
    match request {
        ForgeControlRequest::GoalCreate { response, .. }
        | ForgeControlRequest::GoalReviseContract { response, .. }
        | ForgeControlRequest::GoalTransition { response, .. }
        | ForgeControlRequest::GoalComplete { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::GoalGet { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::GoalList { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::GoalReview { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        _ => {}
    }
}

fn reject_queued_dag(request: ForgeControlRequest) {
    match request {
        ForgeControlRequest::DagGetCurrent { response, .. }
        | ForgeControlRequest::DagGetRevision { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::DagNodeAssignmentSnapshot { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::DagNodeStart { response, .. }
        | ForgeControlRequest::DagNodeComplete { response, .. }
        | ForgeControlRequest::DagNodeUpdate { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        _ => {}
    }
}

fn reject_queued_recovery(request: ForgeControlRequest) {
    match request {
        ForgeControlRequest::LeadershipWorkCut { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::CheckpointRestoreRun { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::RecoveryLeaseGet { response, .. }
        | ForgeControlRequest::RecoveryLeaseRenew { response, .. }
        | ForgeControlRequest::RecoveryLeaseRelease { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::RecoveryMaintenanceRun { response, .. }
        | ForgeControlRequest::RecoveryMaintenanceDurable { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::RecoveryMaintenanceGet { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::RecoveryLeaseClaim { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        _ => {}
    }
}

fn reject_queued_diff(request: ForgeControlRequest) {
    match request {
        ForgeControlRequest::DiffList { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::DiffRead { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::DiffDoctor { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::DiffRetentionPlan { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::DiffPurge { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::DiffArtifactDoctor { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::DeleteOrphanDiffArtifact { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        _ => {}
    }
}

fn worker_shutting_down<T>() -> Result<T, ControlError> {
    Err(ControlError::new(ControlErrorCode::WorkerShuttingDown))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use forge_domain::{
        ActivityId, AgentInstanceId, AgentInstanceRevision, AgentSessionId, AuthenticatedPrincipal,
        DagNodeId, DagNodeRevision, DagRevisionNumber, ExecutionCommandId, ExecutionId,
        GoalNodeAttribution, GoalRevision, LocationId, LocationRevision,
        RecoveryLeaseDurationMillis, RecoveryLeaseEpoch, RecoveryLeaseRevision, TimestampMillis,
        WorkspaceId, WorkspaceRevision,
    };
    use forge_persistence::ApprovalCleanupAttemptId;
    use forge_workspace::WorkspaceLocator;
    use uuid::Uuid;

    use super::*;

    #[test]
    fn queued_expiry_apply_reply_loss_observes_same_plan_after_sqlite_release()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, control, scope) = crate::approval_expiry::tests::worker_fixture()?;
        let (client, mut worker) = ForgeControlWorker::start(control)?;
        let plan = client.prepare_approval_expiry_plan(
            scope,
            TimestampMillis::new(50)?,
            ExecutionListLimit::DEFAULT,
        )?;
        let database = root.join("location/workspace/.heterarchy-forge/state.sqlite3");
        let lock = rusqlite::Connection::open(database)?;
        lock.execute_batch("BEGIN IMMEDIATE")?;

        let attempt = ApprovalCleanupAttemptId::from_uuid(Uuid::now_v7());
        let pending =
            client.submit_pending(|response| ForgeControlRequest::ApprovalExpiryApply {
                plan: plan.clone(),
                attempt,
                response,
            })?;
        drop(pending);
        drop(lock);

        let mut settled = false;
        for _ in 0..8 {
            match client.observe_approval_expiry_plan(plan.clone())? {
                ApprovalCleanupReadback::SettledTargetState => {
                    settled = true;
                    break;
                }
                ApprovalCleanupReadback::Absent => {}
                ApprovalCleanupReadback::Mismatch => {
                    return Err("expiry readback mismatched the original plan".into());
                }
            }
        }
        assert!(
            settled,
            "dropped Apply reply never reached settled readback"
        );
        worker.shutdown()?;
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn recovery_lease_worker_preserves_requested_windows_and_cas_fences()
    -> Result<(), Box<dyn std::error::Error>> {
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(0x7101));
        let owner_id = RuntimeInstanceId::from_uuid(Uuid::from_u128(0x7102));
        let duration = RecoveryLeaseDurationMillis::new(1_000)?;
        let past =
            ClaimRecoveryLease::new(workspace_id, owner_id, duration, TimestampMillis::new(1)?)?;
        assert_eq!(
            recovery_lease_duration(past.observed_at(), past.lease_until())?,
            duration
        );

        let future_observed_at = TimestampMillis::new(4_000_000_000_000)?;

        let expected_epoch = RecoveryLeaseEpoch::new(7)?;
        let expected_revision = RecoveryLeaseRevision::new(19)?;
        let renewal = RenewRecoveryLease::new(
            workspace_id,
            owner_id,
            expected_epoch,
            expected_revision,
            duration,
            future_observed_at,
        )?;
        let rebased_renewal = rebase_renew_recovery_lease(renewal)?;
        assert_eq!(rebased_renewal.workspace_id(), workspace_id);
        assert_eq!(rebased_renewal.owner_id(), owner_id);
        assert_eq!(rebased_renewal.expected_epoch(), expected_epoch);
        assert_eq!(rebased_renewal.expected_revision(), expected_revision);
        assert_eq!(
            rebased_renewal.lease_until().get() - rebased_renewal.observed_at().get(),
            duration.get()
        );

        let release = ReleaseRecoveryLease::new(
            workspace_id,
            owner_id,
            expected_epoch,
            expected_revision,
            TimestampMillis::new(1)?,
        );
        let rebased_release = rebase_release_recovery_lease(release)?;
        assert_eq!(rebased_release.workspace_id(), workspace_id);
        assert_eq!(rebased_release.owner_id(), owner_id);
        assert_eq!(rebased_release.expected_epoch(), expected_epoch);
        assert_eq!(rebased_release.expected_revision(), expected_revision);
        assert_ne!(rebased_release.observed_at().get(), 1);
        Ok(())
    }

    #[test]
    fn queued_goal_requests_are_rejected_during_shutdown_drain()
    -> Result<(), Box<dyn std::error::Error>> {
        let scope = ResolvedWorkspaceScope::from_observation(
            WorkspaceId::from_uuid(Uuid::from_u128(0x1001)),
            WorkspaceRevision::INITIAL,
            WorkspaceLocator::new(
                LocationId::from_uuid(Uuid::from_u128(0x1002)),
                LocationRevision::INITIAL,
                Path::new("."),
            )?,
        );
        let (request_sender, request_receiver) = mpsc::sync_channel(1);
        let (response_sender, response_receiver) = mpsc::sync_channel(1);
        request_sender.send(ForgeControlRequest::GoalList {
            scope,
            activity_id: ActivityId::from_uuid(Uuid::from_u128(0x1003)),
            limit: GoalListLimit::DEFAULT,
            response: response_sender,
        })?;

        drain_queued_requests(&request_receiver);

        let result = response_receiver.recv()?;
        let Err(error) = result else {
            return Err("shutdown unexpectedly accepted queued Goal".into());
        };
        assert_eq!(error.code(), ControlErrorCode::WorkerShuttingDown);
        Ok(())
    }

    #[test]
    fn queued_dag_requests_are_rejected_during_shutdown_drain()
    -> Result<(), Box<dyn std::error::Error>> {
        let scope = ResolvedWorkspaceScope::from_observation(
            WorkspaceId::from_uuid(Uuid::from_u128(0x2001)),
            WorkspaceRevision::INITIAL,
            WorkspaceLocator::new(
                LocationId::from_uuid(Uuid::from_u128(0x2002)),
                LocationRevision::INITIAL,
                Path::new("."),
            )?,
        );
        let (request_sender, request_receiver) = mpsc::sync_channel(1);
        let (response_sender, response_receiver) = mpsc::sync_channel(1);
        request_sender.send(ForgeControlRequest::DagGetCurrent {
            scope,
            goal_id: GoalId::from_uuid(Uuid::from_u128(0x2003)),
            response: response_sender,
        })?;
        drain_queued_requests(&request_receiver);
        let Err(error) = response_receiver.recv()? else {
            return Err("shutdown unexpectedly accepted queued DAG read".into());
        };
        assert_eq!(error.code(), ControlErrorCode::WorkerShuttingDown);
        Ok(())
    }

    #[test]
    fn queued_workspace_identity_doctor_is_rejected_during_shutdown_drain()
    -> Result<(), Box<dyn std::error::Error>> {
        let (request_sender, request_receiver) = mpsc::sync_channel(1);
        let (response_sender, response_receiver) = mpsc::sync_channel(1);
        request_sender.send(ForgeControlRequest::WorkspaceIdentityDoctor {
            response: response_sender,
        })?;
        drain_queued_requests(&request_receiver);
        let Err(error) = response_receiver.recv()? else {
            return Err("queued Workspace identity Doctor was unexpectedly accepted".into());
        };
        assert_eq!(error.code(), ControlErrorCode::WorkerShuttingDown);
        Ok(())
    }

    #[test]
    fn queued_workspace_doctor_is_rejected_during_shutdown_drain()
    -> Result<(), Box<dyn std::error::Error>> {
        let scope = ResolvedWorkspaceScope::from_observation(
            WorkspaceId::from_uuid(Uuid::from_u128(0x3001)),
            WorkspaceRevision::INITIAL,
            WorkspaceLocator::new(
                LocationId::from_uuid(Uuid::from_u128(0x3002)),
                LocationRevision::INITIAL,
                Path::new("."),
            )?,
        );
        let (request_sender, request_receiver) = mpsc::sync_channel(1);
        let (response_sender, response_receiver) = mpsc::sync_channel(1);
        request_sender.send(ForgeControlRequest::WorkspaceDoctor {
            request: WorkspaceDoctorRequest { scope },
            response: response_sender,
        })?;
        drain_queued_requests(&request_receiver);
        let Err(error) = response_receiver.recv()? else {
            return Err("shutdown unexpectedly accepted queued Workspace Doctor".into());
        };
        assert_eq!(error.code(), ControlErrorCode::WorkerShuttingDown);
        Ok(())
    }

    #[test]
    fn queued_source_operations_are_rejected_during_shutdown_drain()
    -> Result<(), Box<dyn std::error::Error>> {
        let scope = ResolvedWorkspaceScope::from_observation(
            WorkspaceId::from_uuid(Uuid::from_u128(0x3501)),
            WorkspaceRevision::INITIAL,
            WorkspaceLocator::new(
                LocationId::from_uuid(Uuid::from_u128(0x3502)),
                LocationRevision::INITIAL,
                Path::new("workspace"),
            )?,
        );
        let (request_sender, request_receiver) = mpsc::sync_channel(1);
        let (response_sender, response_receiver) = mpsc::sync_channel(1);
        request_sender.send(ForgeControlRequest::FileList {
            request: FileListRequest {
                scope,
                activity: crate::FileActivityScope {
                    activity_id: ActivityId::from_uuid(Uuid::from_u128(0x3503)),
                    runtime_instance_id: RuntimeInstanceId::from_uuid(Uuid::from_u128(0x3504)),
                    observed_at: TimestampMillis::new(1)?,
                },
                directory: None,
                options: forge_domain::FileListOptions::default(),
            },
            response: response_sender,
        })?;
        drain_queued_requests(&request_receiver);
        let Err(error) = response_receiver.recv()? else {
            return Err("queued source operation was unexpectedly accepted".into());
        };
        assert_eq!(error.code(), ControlErrorCode::WorkerShuttingDown);
        Ok(())
    }

    #[test]
    fn queued_agent_requests_are_rejected_during_shutdown_drain()
    -> Result<(), Box<dyn std::error::Error>> {
        let scope = ResolvedWorkspaceScope::from_observation(
            WorkspaceId::from_uuid(Uuid::from_u128(0x4001)),
            WorkspaceRevision::INITIAL,
            WorkspaceLocator::new(
                LocationId::from_uuid(Uuid::from_u128(0x4002)),
                LocationRevision::INITIAL,
                Path::new("."),
            )?,
        );
        let (request_sender, request_receiver) = mpsc::sync_channel(1);
        let (response_sender, response_receiver) = mpsc::sync_channel(1);
        request_sender.send(ForgeControlRequest::AgentGetContext {
            request: AgentContextRequest {
                scope,
                activity_id: ActivityId::from_uuid(Uuid::from_u128(0x4004)),
                agent_id: AgentInstanceId::from_uuid(Uuid::from_u128(0x4003)),
                now: TimestampMillis::new(1)?,
                focus_event_limit: forge_domain::AgentListLimit::new(1)?,
                work_update_limit: forge_domain::AgentListLimit::new(1)?,
            },
            response: response_sender,
        })?;
        drain_queued_requests(&request_receiver);
        let Err(error) = response_receiver.recv()? else {
            return Err("queued Agent context read was unexpectedly accepted".into());
        };
        assert_eq!(error.code(), ControlErrorCode::WorkerShuttingDown);
        Ok(())
    }

    #[test]
    fn queued_authorized_execution_reads_are_rejected_during_shutdown_drain()
    -> Result<(), Box<dyn std::error::Error>> {
        let scope = ResolvedWorkspaceScope::from_observation(
            WorkspaceId::from_uuid(Uuid::from_u128(0x5001)),
            WorkspaceRevision::INITIAL,
            WorkspaceLocator::new(
                LocationId::from_uuid(Uuid::from_u128(0x5002)),
                LocationRevision::INITIAL,
                Path::new("."),
            )?,
        );
        let execution_id = ExecutionId::from_uuid(Uuid::from_u128(0x5003));
        let request = AgentExecutionAuthorityRequest {
            session_id: AgentSessionId::from_uuid(Uuid::from_u128(0x5008)),
            scope,
            activity_id: ActivityId::from_uuid(Uuid::from_u128(0x5004)),
            agent_id: AgentInstanceId::from_uuid(Uuid::from_u128(0x5005)),
            expected_revision: AgentInstanceRevision::INITIAL,
            principal: AuthenticatedPrincipal::TrustedStdio,
            attribution: GoalNodeAttribution::new(
                GoalId::from_uuid(Uuid::from_u128(0x5006)),
                GoalRevision::INITIAL,
                DagRevisionNumber::INITIAL,
                DagNodeId::from_uuid(Uuid::from_u128(0x5007)),
                DagNodeRevision::INITIAL,
            ),
            command_id: ExecutionCommandId::new("make:ci".to_owned())?,
        };
        let (request_sender, request_receiver) = mpsc::sync_channel(1);
        let (response_sender, response_receiver) = mpsc::sync_channel(1);
        request_sender.send(ForgeControlRequest::ExecutionReadAuthorized {
            request,
            id: execution_id,
            cursor: ExecutionOutputCursor::initial(execution_id),
            max_bytes: forge_domain::MIN_EXECUTION_OUTPUT_READ_BYTES,
            max_events: 1,
            response: response_sender,
        })?;
        drain_queued_requests(&request_receiver);
        let Err(error) = response_receiver.recv()? else {
            return Err("queued authorized execution read was unexpectedly accepted".into());
        };
        assert_eq!(error.code(), ControlErrorCode::WorkerShuttingDown);
        Ok(())
    }

    #[test]
    fn queued_verification_projection_is_rejected_during_shutdown_drain()
    -> Result<(), Box<dyn std::error::Error>> {
        let scope = ResolvedWorkspaceScope::from_observation(
            WorkspaceId::from_uuid(Uuid::from_u128(0x6001)),
            WorkspaceRevision::INITIAL,
            WorkspaceLocator::new(
                LocationId::from_uuid(Uuid::from_u128(0x6002)),
                LocationRevision::INITIAL,
                Path::new("."),
            )?,
        );
        let (request_sender, request_receiver) = mpsc::sync_channel(1);
        let (response_sender, response_receiver) = mpsc::sync_channel(1);
        request_sender.send(ForgeControlRequest::VerificationProjection {
            scope,
            response: response_sender,
        })?;

        drain_queued_requests(&request_receiver);

        let Err(error) = response_receiver.recv()? else {
            return Err("queued verification projection was unexpectedly accepted".into());
        };
        assert_eq!(error.code(), ControlErrorCode::WorkerShuttingDown);
        Ok(())
    }
}
