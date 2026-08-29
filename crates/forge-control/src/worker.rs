use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::thread::{self, JoinHandle};

use forge_domain::{
    ActivityId, ActivityLeaseRevision, ActivityListLimit, ActivityProjection, AppliedHarness,
    ApprovalRequestId, AutoApprovalScope, ClaimRecoveryLease, CloseActivity, CompleteExecution,
    DagRevisionNumber, ExecutionGrant, ExecutionId, ExecutionListLimit, FailExecution, GoalId,
    GoalListLimit, GoalReview, HarnessVerifierRun, HarnessVerifierRunRevision, LocationId,
    LocationRevision, MarkExecutionRunning, RecoveryMaintenanceLease, RegisteredApprovalRequest,
    RegisteredDagNode, RegisteredExecution, RegisteredGoal, ReleaseRecoveryLease,
    RenewActivityLease, RenewRecoveryLease, RuntimeInstanceId, TimestampMillis, WorkspacePolicy,
};
use forge_persistence::{ApprovalAuthorityCleanupReport, StoredDagRevision};
use forge_workspace::WorkspaceLocator;

use crate::agent::{
    AgentAttachRequest, AgentContextRequest, AgentDetachRequest, AgentFocusRequest,
    AgentListRequest, AgentWorkUpdateRequest,
};
use crate::approval::{
    ApprovalCancelActivityRequest, ApprovalCancelWorkspaceRequest, ApprovalCreateRequest,
    ApprovalDecisionRequest, ApprovalGrantConsumeRequest, ApprovalGrantConsumeResult,
    ApprovalOnceRequest, ApprovalReconcileRequest, AutoApprovalConsumeRequest,
    AutoApprovalConsumeResult, AutoApprovalScopeCreateRequest, AutoApprovalScopeRevokeRequest,
    WorkspacePolicyReplaceRequest,
};
use crate::checkpoint::CheckpointRestoreOutcome;
use crate::checkpoint::CheckpointRestoreRequest;
use crate::dag::{DagNodeStartRequest, DagNodeUpdateRequest, DagRevisionCreateRequest};
use crate::diff::{
    DiffDoctorRequest, DiffDoctorResult, DiffListRequest, DiffListResult, DiffReadRequest,
    DiffReadResult,
};
use crate::doctor::{WorkspaceDoctorRequest, WorkspaceDoctorResult, WorkspaceIdentityDoctorReport};
use crate::error::{ControlError, ControlErrorCode};
use crate::filesystem::{FileMutationRequest, FileMutationResult, FileReadRequest, FileReadResult};
use crate::goal::{GoalCompletionRequest, GoalLifecycleRequest};
use crate::grant::{
    AgentDagGrantDiscoverRequest, AgentDagGrantGetRequest, AgentDagGrantIssueRequest,
    AgentDagGrantRevokeRequest, AgentDagReplanCommitRequest,
};
use crate::harness::{
    HarnessApplyRequest, HarnessLifecycleApplyRequest, HarnessLifecyclePreviewProjection,
    HarnessLifecyclePreviewRequest, HarnessPreviewRequest, HarnessVerifyRequest,
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
    ActivityBootstrap, ActivityLeaseOperation, ForgeControl, OwnedActivityLease,
    ResolvedWorkspaceScope, WorkspaceActivityProjection, WorkspaceActivityProjectionRequest,
    WorkspaceCatalogEntry,
};
use forge_workspace::HarnessInstallPreview;

/// Bounded admission capacity for the single-owner control worker.
pub const CONTROL_QUEUE_CAPACITY: usize = 16;

/// Maximum caller-owned Activities accepted by one graceful shutdown request.
pub const MAX_SHUTDOWN_ACTIVITIES: usize = 256;

const WORKER_THREAD_NAME: &str = "heterarchy-forge-control";
const MIN_APPROVAL_WINDOW_MILLIS: i64 = 1_000;
const MAX_APPROVAL_WINDOW_MILLIS: i64 = 60 * 60 * 1_000;

type Response<T> = SyncSender<Result<T, ControlError>>;

/// Requests accepted by [`ForgeControlWorker`].
///
/// The enum is transport-neutral; adapters can use the typed client methods
/// rather than constructing requests directly.
#[derive(Debug)]
pub enum ForgeControlRequest {
    WorkspaceList {
        location_id: LocationId,
        expected_revision: LocationRevision,
        response: Response<Vec<WorkspaceCatalogEntry>>,
    },
    ResolveWorkspace {
        location_id: LocationId,
        expected_revision: LocationRevision,
        locator: WorkspaceLocator,
        response: Response<ResolvedWorkspaceScope>,
    },
    WorkspaceDoctor {
        request: WorkspaceDoctorRequest,
        response: Response<WorkspaceDoctorResult>,
    },
    WorkspaceIdentityDoctor {
        response: Response<WorkspaceIdentityDoctorReport>,
    },
    HarnessGetApplied {
        scope: ResolvedWorkspaceScope,
        response: Response<Option<AppliedHarness>>,
    },
    HarnessVerifierGetLatest {
        scope: ResolvedWorkspaceScope,
        response: Response<Option<HarnessVerifierRun>>,
    },
    HarnessVerifierPersist {
        scope: ResolvedWorkspaceScope,
        run: HarnessVerifierRun,
        expected_revision: Option<HarnessVerifierRunRevision>,
        response: Response<HarnessVerifierRun>,
    },
    HarnessPreview {
        request: HarnessPreviewRequest,
        response: Response<HarnessInstallPreview>,
    },
    HarnessApply {
        request: HarnessApplyRequest,
        response: Response<AppliedHarness>,
    },
    HarnessLifecyclePreview {
        request: HarnessLifecyclePreviewRequest,
        response: Response<HarnessLifecyclePreviewProjection>,
    },
    HarnessLifecycleApply {
        request: HarnessLifecycleApplyRequest,
        response: Response<Option<AppliedHarness>>,
    },
    HarnessVerifySource {
        request: HarnessVerifyRequest,
        response: Response<AppliedHarness>,
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
    CloseActivity {
        scope: ResolvedWorkspaceScope,
        activity_id: ActivityId,
        runtime_instance_id: RuntimeInstanceId,
        expected_lease_revision: ActivityLeaseRevision,
        observed_at: TimestampMillis,
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
        observed_at: TimestampMillis,
        response: Response<ActivityLeaseOperation>,
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
    AgentAttach {
        request: AgentAttachRequest,
        response: Response<forge_domain::RegisteredAgentInstance>,
    },
    AgentSetFocus {
        request: AgentFocusRequest,
        response: Response<forge_domain::RegisteredAgentInstance>,
    },
    AgentPublishWorkUpdate {
        request: AgentWorkUpdateRequest,
        response: Response<forge_domain::AgentWorkUpdate>,
    },
    AgentDetach {
        request: AgentDetachRequest,
        response: Response<forge_domain::RegisteredAgentInstance>,
    },
    AgentList {
        request: AgentListRequest,
        response: Response<Vec<forge_domain::AgentAttachmentProjection>>,
    },
    AgentGetContext {
        request: AgentContextRequest,
        response: Response<Option<forge_domain::AgentContextProjection>>,
    },
    AgentDagGrantIssue {
        request: AgentDagGrantIssueRequest,
        response: Response<forge_domain::AgentDagAuthoringGrant>,
    },
    AgentDagGrantRevoke {
        request: AgentDagGrantRevokeRequest,
        response: Response<forge_domain::AgentDagAuthoringGrant>,
    },
    AgentDagGrantGet {
        request: AgentDagGrantGetRequest,
        response: Response<Option<forge_domain::AgentDagAuthoringGrant>>,
    },
    AgentDagGrantDiscover {
        request: AgentDagGrantDiscoverRequest,
        response: Response<Option<forge_domain::AgentDagAuthoringGrant>>,
    },
    AgentDagReplanCommit {
        request: AgentDagReplanCommitRequest,
        response: Response<forge_persistence::AgentDagReplanCommitResult>,
    },
    FileRead {
        request: FileReadRequest,
        response: Response<FileReadResult>,
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
    ExecutionComplete {
        scope: ResolvedWorkspaceScope,
        command: CompleteExecution,
        response: Response<RegisteredExecution>,
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
    ExecutionList {
        scope: ResolvedWorkspaceScope,
        activity_id: ActivityId,
        limit: ExecutionListLimit,
        response: Response<Vec<RegisteredExecution>>,
    },
    GoalCreate {
        scope: ResolvedWorkspaceScope,
        goal: RegisteredGoal,
        response: Response<RegisteredGoal>,
    },
    GoalGet {
        scope: ResolvedWorkspaceScope,
        goal_id: GoalId,
        response: Response<Option<RegisteredGoal>>,
    },
    GoalList {
        scope: ResolvedWorkspaceScope,
        limit: GoalListLimit,
        response: Response<Vec<RegisteredGoal>>,
    },
    GoalTransition {
        request: GoalLifecycleRequest,
        response: Response<RegisteredGoal>,
    },
    GoalReview {
        scope: ResolvedWorkspaceScope,
        goal_id: GoalId,
        response: Response<GoalReview>,
    },
    GoalComplete {
        request: GoalCompletionRequest,
        response: Response<RegisteredGoal>,
    },
    DagRevisionCreate {
        request: DagRevisionCreateRequest,
        response: Response<StoredDagRevision>,
    },
    DagGetCurrent {
        scope: ResolvedWorkspaceScope,
        goal_id: GoalId,
        response: Response<Option<StoredDagRevision>>,
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
    CheckpointRestoreRun {
        request: CheckpointRestoreRequest,
        response: Response<CheckpointRestoreOutcome>,
    },
    EnsureWorkspacePolicy {
        scope: ResolvedWorkspaceScope,
        observed_at: TimestampMillis,
        response: Response<WorkspacePolicy>,
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
        response: Response<Option<RegisteredApprovalRequest>>,
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
    ApprovalGrantConsume {
        request: ApprovalGrantConsumeRequest,
        response: Response<ApprovalGrantConsumeResult>,
    },
    AutoApprovalConsume {
        request: AutoApprovalConsumeRequest,
        response: Response<AutoApprovalConsumeResult>,
    },
    ApprovalReconcileExpired {
        request: ApprovalReconcileRequest,
        response: Response<ApprovalAuthorityCleanupReport>,
    },
    ApprovalCancelActivity {
        request: ApprovalCancelActivityRequest,
        response: Response<ApprovalAuthorityCleanupReport>,
    },
    ApprovalCancelWorkspace {
        request: ApprovalCancelWorkspaceRequest,
        response: Response<ApprovalAuthorityCleanupReport>,
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

    /// Blocking completion path for non-UI callers such as MCP adapters.
    pub fn recv(self) -> Result<T, ControlClientError> {
        self.receiver
            .recv()
            .map_err(|_| ControlClientError::ResponseDropped)?
            .map_err(ControlClientError::Service)
    }

    /// Nonblocking completion poll.  `Ok(None)` means the worker is still
    /// processing; a disconnected channel is reported as a worker failure.
    pub fn try_recv(&self) -> Result<Option<Result<T, ControlError>>, ControlClientError> {
        match self.receiver.try_recv() {
            Ok(result) => Ok(Some(result)),
            Err(std::sync::mpsc::TryRecvError::Empty) => Ok(None),
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                Err(ControlClientError::WorkerClosed)
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
pub struct ForgeControlClient {
    sender: SyncSender<ForgeControlRequest>,
    accepting: Arc<AtomicBool>,
}

impl ForgeControlClient {
    fn new(sender: SyncSender<ForgeControlRequest>, accepting: Arc<AtomicBool>) -> Self {
        Self { sender, accepting }
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

    pub fn harness_get_applied(
        &self,
        scope: ResolvedWorkspaceScope,
    ) -> Result<Option<AppliedHarness>, ControlClientError> {
        self.submit_harness_get_applied(scope)?.recv()
    }

    pub fn submit_harness_get_applied(
        &self,
        scope: ResolvedWorkspaceScope,
    ) -> Result<PendingControl<Option<AppliedHarness>>, ControlClientError> {
        self.submit_pending(|response| ForgeControlRequest::HarnessGetApplied { scope, response })
    }

    pub fn harness_verifier_get_latest(
        &self,
        scope: ResolvedWorkspaceScope,
    ) -> Result<Option<HarnessVerifierRun>, ControlClientError> {
        self.submit(|response| ForgeControlRequest::HarnessVerifierGetLatest { scope, response })
    }

    pub fn harness_verifier_persist(
        &self,
        scope: ResolvedWorkspaceScope,
        run: HarnessVerifierRun,
        expected_revision: Option<HarnessVerifierRunRevision>,
    ) -> Result<HarnessVerifierRun, ControlClientError> {
        self.submit(|response| ForgeControlRequest::HarnessVerifierPersist {
            scope,
            run,
            expected_revision,
            response,
        })
    }

    pub fn harness_preview(
        &self,
        request: HarnessPreviewRequest,
    ) -> Result<HarnessInstallPreview, ControlClientError> {
        self.submit_harness_preview(request)?.recv()
    }

    pub fn submit_harness_preview(
        &self,
        request: HarnessPreviewRequest,
    ) -> Result<PendingControl<HarnessInstallPreview>, ControlClientError> {
        self.submit_pending(|response| ForgeControlRequest::HarnessPreview { request, response })
    }

    pub fn harness_apply(
        &self,
        request: HarnessApplyRequest,
    ) -> Result<AppliedHarness, ControlClientError> {
        self.submit_harness_apply(request)?.recv()
    }

    pub fn submit_harness_apply(
        &self,
        request: HarnessApplyRequest,
    ) -> Result<PendingControl<AppliedHarness>, ControlClientError> {
        self.submit_pending(|response| ForgeControlRequest::HarnessApply { request, response })
    }

    pub fn harness_lifecycle_preview(
        &self,
        request: HarnessLifecyclePreviewRequest,
    ) -> Result<HarnessLifecyclePreviewProjection, ControlClientError> {
        self.submit_harness_lifecycle_preview(request)?.recv()
    }

    pub fn submit_harness_lifecycle_preview(
        &self,
        request: HarnessLifecyclePreviewRequest,
    ) -> Result<PendingControl<HarnessLifecyclePreviewProjection>, ControlClientError> {
        self.submit_pending(|response| ForgeControlRequest::HarnessLifecyclePreview {
            request,
            response,
        })
    }

    pub fn harness_lifecycle_apply(
        &self,
        request: HarnessLifecycleApplyRequest,
    ) -> Result<Option<AppliedHarness>, ControlClientError> {
        self.submit_harness_lifecycle_apply(request)?.recv()
    }

    pub fn submit_harness_lifecycle_apply(
        &self,
        request: HarnessLifecycleApplyRequest,
    ) -> Result<PendingControl<Option<AppliedHarness>>, ControlClientError> {
        self.submit_pending(|response| ForgeControlRequest::HarnessLifecycleApply {
            request,
            response,
        })
    }

    pub fn harness_verify_source(
        &self,
        request: HarnessVerifyRequest,
    ) -> Result<AppliedHarness, ControlClientError> {
        self.submit_harness_verify_source(request)?.recv()
    }

    pub fn submit_harness_verify_source(
        &self,
        request: HarnessVerifyRequest,
    ) -> Result<PendingControl<AppliedHarness>, ControlClientError> {
        self.submit_pending(|response| ForgeControlRequest::HarnessVerifySource {
            request,
            response,
        })
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

    pub fn close_activity(
        &self,
        scope: ResolvedWorkspaceScope,
        activity_id: ActivityId,
        runtime_instance_id: RuntimeInstanceId,
        expected_lease_revision: ActivityLeaseRevision,
        observed_at: TimestampMillis,
    ) -> Result<ActivityLeaseOperation, ControlClientError> {
        self.submit(|response| ForgeControlRequest::CloseActivity {
            scope,
            activity_id,
            runtime_instance_id,
            expected_lease_revision,
            observed_at,
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
        observed_at: TimestampMillis,
    ) -> Result<ActivityLeaseOperation, ControlClientError> {
        self.submit(|response| ForgeControlRequest::ReleaseActivityLease {
            scope,
            activity_id,
            runtime_instance_id,
            expected_lease_revision,
            observed_at,
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

    pub fn agent_attach(
        &self,
        request: AgentAttachRequest,
    ) -> Result<forge_domain::RegisteredAgentInstance, ControlClientError> {
        self.submit(|response| ForgeControlRequest::AgentAttach { request, response })
    }

    pub fn submit_agent_attach(
        &self,
        request: AgentAttachRequest,
    ) -> Result<PendingControl<forge_domain::RegisteredAgentInstance>, ControlClientError> {
        self.submit_pending(|response| ForgeControlRequest::AgentAttach { request, response })
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

    pub fn agent_detach(
        &self,
        request: AgentDetachRequest,
    ) -> Result<forge_domain::RegisteredAgentInstance, ControlClientError> {
        self.submit(|response| ForgeControlRequest::AgentDetach { request, response })
    }

    pub fn submit_agent_detach(
        &self,
        request: AgentDetachRequest,
    ) -> Result<PendingControl<forge_domain::RegisteredAgentInstance>, ControlClientError> {
        self.submit_pending(|response| ForgeControlRequest::AgentDetach { request, response })
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

    pub fn agent_dag_grant_issue(
        &self,
        request: AgentDagGrantIssueRequest,
    ) -> Result<forge_domain::AgentDagAuthoringGrant, ControlClientError> {
        self.submit_agent_dag_grant_issue(request)?.recv()
    }

    pub fn submit_agent_dag_grant_issue(
        &self,
        request: AgentDagGrantIssueRequest,
    ) -> Result<PendingControl<forge_domain::AgentDagAuthoringGrant>, ControlClientError> {
        self.submit_pending(|response| ForgeControlRequest::AgentDagGrantIssue {
            request,
            response,
        })
    }

    pub fn agent_dag_grant_revoke(
        &self,
        request: AgentDagGrantRevokeRequest,
    ) -> Result<forge_domain::AgentDagAuthoringGrant, ControlClientError> {
        self.submit_agent_dag_grant_revoke(request)?.recv()
    }

    pub fn submit_agent_dag_grant_revoke(
        &self,
        request: AgentDagGrantRevokeRequest,
    ) -> Result<PendingControl<forge_domain::AgentDagAuthoringGrant>, ControlClientError> {
        self.submit_pending(|response| ForgeControlRequest::AgentDagGrantRevoke {
            request,
            response,
        })
    }

    pub fn agent_dag_grant_get(
        &self,
        request: AgentDagGrantGetRequest,
    ) -> Result<Option<forge_domain::AgentDagAuthoringGrant>, ControlClientError> {
        self.submit_agent_dag_grant_get(request)?.recv()
    }

    pub fn submit_agent_dag_grant_get(
        &self,
        request: AgentDagGrantGetRequest,
    ) -> Result<PendingControl<Option<forge_domain::AgentDagAuthoringGrant>>, ControlClientError>
    {
        self.submit_pending(|response| ForgeControlRequest::AgentDagGrantGet { request, response })
    }

    pub fn agent_dag_grant_discover(
        &self,
        request: AgentDagGrantDiscoverRequest,
    ) -> Result<Option<forge_domain::AgentDagAuthoringGrant>, ControlClientError> {
        self.submit_agent_dag_grant_discover(request)?.recv()
    }

    pub fn submit_agent_dag_grant_discover(
        &self,
        request: AgentDagGrantDiscoverRequest,
    ) -> Result<PendingControl<Option<forge_domain::AgentDagAuthoringGrant>>, ControlClientError>
    {
        self.submit_pending(|response| ForgeControlRequest::AgentDagGrantDiscover {
            request,
            response,
        })
    }

    pub fn agent_dag_replan_commit(
        &self,
        request: AgentDagReplanCommitRequest,
    ) -> Result<forge_persistence::AgentDagReplanCommitResult, ControlClientError> {
        self.submit_agent_dag_replan_commit(request)?.recv()
    }

    pub fn submit_agent_dag_replan_commit(
        &self,
        request: AgentDagReplanCommitRequest,
    ) -> Result<PendingControl<forge_persistence::AgentDagReplanCommitResult>, ControlClientError>
    {
        self.submit_pending(|response| ForgeControlRequest::AgentDagReplanCommit {
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

    pub fn goal_create(
        &self,
        scope: ResolvedWorkspaceScope,
        goal: RegisteredGoal,
    ) -> Result<RegisteredGoal, ControlClientError> {
        self.submit_goal_create(scope, goal)?.recv()
    }

    pub fn submit_goal_create(
        &self,
        scope: ResolvedWorkspaceScope,
        goal: RegisteredGoal,
    ) -> Result<PendingControl<RegisteredGoal>, ControlClientError> {
        self.submit_pending(|response| ForgeControlRequest::GoalCreate {
            scope,
            goal,
            response,
        })
    }

    pub fn goal_get(
        &self,
        scope: ResolvedWorkspaceScope,
        goal_id: GoalId,
    ) -> Result<Option<RegisteredGoal>, ControlClientError> {
        self.submit_goal_get(scope, goal_id)?.recv()
    }

    pub fn submit_goal_get(
        &self,
        scope: ResolvedWorkspaceScope,
        goal_id: GoalId,
    ) -> Result<PendingControl<Option<RegisteredGoal>>, ControlClientError> {
        self.submit_pending(|response| ForgeControlRequest::GoalGet {
            scope,
            goal_id,
            response,
        })
    }

    pub fn goal_list(
        &self,
        scope: ResolvedWorkspaceScope,
        limit: GoalListLimit,
    ) -> Result<Vec<RegisteredGoal>, ControlClientError> {
        self.submit_goal_list(scope, limit)?.recv()
    }

    pub fn submit_goal_list(
        &self,
        scope: ResolvedWorkspaceScope,
        limit: GoalListLimit,
    ) -> Result<PendingControl<Vec<RegisteredGoal>>, ControlClientError> {
        self.submit_pending(|response| ForgeControlRequest::GoalList {
            scope,
            limit,
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
        goal_id: GoalId,
    ) -> Result<GoalReview, ControlClientError> {
        self.submit_goal_review(scope, goal_id)?.recv()
    }

    pub fn submit_goal_review(
        &self,
        scope: ResolvedWorkspaceScope,
        goal_id: GoalId,
    ) -> Result<PendingControl<GoalReview>, ControlClientError> {
        self.submit_pending(|response| ForgeControlRequest::GoalReview {
            scope,
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

    pub fn dag_revision_create(
        &self,
        request: DagRevisionCreateRequest,
    ) -> Result<StoredDagRevision, ControlClientError> {
        self.submit_dag_revision_create(request)?.recv()
    }

    pub fn submit_dag_revision_create(
        &self,
        request: DagRevisionCreateRequest,
    ) -> Result<PendingControl<StoredDagRevision>, ControlClientError> {
        self.submit_pending(|response| ForgeControlRequest::DagRevisionCreate { request, response })
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
        observed_at: TimestampMillis,
    ) -> Result<WorkspacePolicy, ControlClientError> {
        self.submit(|response| ForgeControlRequest::EnsureWorkspacePolicy {
            scope,
            observed_at,
            response,
        })
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
    ) -> Result<Option<RegisteredApprovalRequest>, ControlClientError> {
        self.submit(|response| ForgeControlRequest::ApprovalGet {
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

    pub fn reconcile_expired_approval_authority(
        &self,
        request: ApprovalReconcileRequest,
    ) -> Result<ApprovalAuthorityCleanupReport, ControlClientError> {
        self.submit(|response| ForgeControlRequest::ApprovalReconcileExpired { request, response })
    }

    pub fn cancel_activity_approval_authority(
        &self,
        request: ApprovalCancelActivityRequest,
    ) -> Result<ApprovalAuthorityCleanupReport, ControlClientError> {
        self.submit(|response| ForgeControlRequest::ApprovalCancelActivity { request, response })
    }

    pub fn cancel_workspace_approval_authority(
        &self,
        request: ApprovalCancelWorkspaceRequest,
    ) -> Result<ApprovalAuthorityCleanupReport, ControlClientError> {
        self.submit(|response| ForgeControlRequest::ApprovalCancelWorkspace { request, response })
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
        observed_at: TimestampMillis,
    ) -> Result<PendingControl<ActivityLeaseOperation>, ControlClientError> {
        self.submit_pending(|response| ForgeControlRequest::CloseActivity {
            scope,
            activity_id,
            runtime_instance_id,
            expected_lease_revision,
            observed_at,
            response,
        })
    }

    pub fn submit_release_activity_lease(
        &self,
        scope: ResolvedWorkspaceScope,
        activity_id: ActivityId,
        runtime_instance_id: RuntimeInstanceId,
        expected_lease_revision: ActivityLeaseRevision,
        observed_at: TimestampMillis,
    ) -> Result<PendingControl<ActivityLeaseOperation>, ControlClientError> {
        self.submit_pending(|response| ForgeControlRequest::ReleaseActivityLease {
            scope,
            activity_id,
            runtime_instance_id,
            expected_lease_revision,
            observed_at,
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
        self.sender
            .try_send(build(response_sender))
            .map_err(|error| match error {
                TrySendError::Full(_) => ControlClientError::QueueFull,
                TrySendError::Disconnected(_) => ControlClientError::WorkerClosed,
            })?;
        Ok(PendingControl::new(response_receiver))
    }
}

/// Owner of one control service thread and its bounded queue.
#[derive(Debug)]
pub struct ForgeControlWorker {
    sender: SyncSender<ForgeControlRequest>,
    accepting: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl ForgeControlWorker {
    /// Start a single-owner worker with a queue bounded to 16 requests.
    pub fn start(control: ForgeControl) -> Result<(ForgeControlClient, Self), ControlWorkerError> {
        let (sender, receiver) = mpsc::sync_channel(CONTROL_QUEUE_CAPACITY);
        let accepting = Arc::new(AtomicBool::new(true));
        let worker_accepting = Arc::clone(&accepting);
        let join = thread::Builder::new()
            .name(WORKER_THREAD_NAME.to_owned())
            .spawn(move || {
                WorkerRuntime {
                    control,
                    receiver,
                    accepting: worker_accepting,
                }
                .run();
            })
            .map_err(|_| ControlWorkerError::WorkerClosed)?;
        let client = ForgeControlClient::new(sender.clone(), accepting.clone());
        Ok((
            client,
            Self {
                sender,
                accepting,
                join: Some(join),
            },
        ))
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
        if self
            .sender
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
        let report = ack_receiver
            .recv()
            .map_err(|_| ControlWorkerError::WorkerClosed)?;
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
        let _ = self.sender.send(ForgeControlRequest::Shutdown {
            owned_activities: Vec::new(),
            response: None,
        });
        let _ = join.join();
    }
}

struct WorkerRuntime {
    control: ForgeControl,
    receiver: Receiver<ForgeControlRequest>,
    accepting: Arc<AtomicBool>,
}

impl WorkerRuntime {
    fn run(self) {
        let Self {
            control,
            receiver,
            accepting,
        } = self;
        while let Ok(request) = receiver.recv() {
            match request {
                ForgeControlRequest::Shutdown {
                    owned_activities,
                    response,
                } => {
                    accepting.store(false, Ordering::Release);
                    let report = close_owned_activities(&control, owned_activities);
                    drain_queued_requests(&receiver);
                    if let Some(response) = response {
                        let _ignored = response.send(report);
                    }
                    break;
                }
                request => dispatch_request(&control, request),
            }
        }
        accepting.store(false, Ordering::Release);
    }
}

fn dispatch_request(control: &ForgeControl, request: ForgeControlRequest) {
    match request {
        ForgeControlRequest::WorkspaceList {
            location_id,
            expected_revision,
            response,
        } => {
            let _ignored = response.send(control.workspace_list(location_id, expected_revision));
        }
        ForgeControlRequest::ResolveWorkspace {
            location_id,
            expected_revision,
            locator,
            response,
        } => {
            let _ignored =
                response.send(control.resolve_workspace(location_id, expected_revision, &locator));
        }
        ForgeControlRequest::WorkspaceDoctor { request, response } => {
            let _ignored = response.send(control.workspace_doctor(&request));
        }
        ForgeControlRequest::WorkspaceIdentityDoctor { response } => {
            let _ignored = response.send(control.workspace_identity_doctor());
        }
        ForgeControlRequest::HarnessGetApplied { scope, response } => {
            let _ignored = response.send(control.harness_get_applied(&scope));
        }
        ForgeControlRequest::HarnessVerifierGetLatest { scope, response } => {
            let _ignored = response.send(control.harness_verifier_get_latest(&scope));
        }
        ForgeControlRequest::HarnessVerifierPersist {
            scope,
            run,
            expected_revision,
            response,
        } => {
            let _ignored =
                response.send(control.harness_verifier_persist(&scope, &run, expected_revision));
        }
        ForgeControlRequest::HarnessPreview { request, response } => {
            let _ignored = response.send(control.harness_preview(&request));
        }
        ForgeControlRequest::HarnessApply { request, response } => {
            let _ignored = response.send(control.harness_apply(&request));
        }
        ForgeControlRequest::HarnessLifecyclePreview { request, response } => {
            let _ignored = response.send(control.harness_lifecycle_preview(&request));
        }
        ForgeControlRequest::HarnessLifecycleApply { request, response } => {
            let _ignored = response.send(control.harness_lifecycle_apply(&request));
        }
        ForgeControlRequest::HarnessVerifySource { request, response } => {
            let _ignored = response.send(control.harness_verify_source(&request));
        }
        request @ (ForgeControlRequest::AgentAttach { .. }
        | ForgeControlRequest::AgentSetFocus { .. }
        | ForgeControlRequest::AgentPublishWorkUpdate { .. }
        | ForgeControlRequest::AgentDetach { .. }
        | ForgeControlRequest::AgentList { .. }
        | ForgeControlRequest::AgentGetContext { .. }
        | ForgeControlRequest::AgentDagGrantIssue { .. }
        | ForgeControlRequest::AgentDagGrantRevoke { .. }
        | ForgeControlRequest::AgentDagGrantGet { .. }
        | ForgeControlRequest::AgentDagGrantDiscover { .. }
        | ForgeControlRequest::AgentDagReplanCommit { .. }) => {
            dispatch_agent_request(control, request);
        }
        ForgeControlRequest::BootstrapActivity {
            scope,
            caller_activity_id,
            runtime_instance_id,
            observed_at,
            lease_until,
            response,
        } => {
            let result = runtime_lease_window(observed_at, lease_until).and_then(
                |(observed_at, lease_until)| {
                    control.bootstrap_activity(
                        &scope,
                        caller_activity_id,
                        runtime_instance_id,
                        observed_at,
                        lease_until,
                    )
                },
            );
            let _ignored = response.send(result);
        }
        request => dispatch_activity_request(control, request),
    }
}

#[allow(clippy::too_many_lines)]
fn dispatch_activity_request(control: &ForgeControl, request: ForgeControlRequest) {
    match request {
        request @ (ForgeControlRequest::WorkspaceList { .. }
        | ForgeControlRequest::ResolveWorkspace { .. }
        | ForgeControlRequest::WorkspaceDoctor { .. }
        | ForgeControlRequest::WorkspaceIdentityDoctor { .. }
        | ForgeControlRequest::HarnessGetApplied { .. }
        | ForgeControlRequest::HarnessVerifierGetLatest { .. }
        | ForgeControlRequest::HarnessVerifierPersist { .. }
        | ForgeControlRequest::HarnessPreview { .. }
        | ForgeControlRequest::HarnessApply { .. }
        | ForgeControlRequest::HarnessLifecyclePreview { .. }
        | ForgeControlRequest::HarnessLifecycleApply { .. }
        | ForgeControlRequest::HarnessVerifySource { .. }
        | ForgeControlRequest::BootstrapActivity { .. }
        | ForgeControlRequest::AgentAttach { .. }
        | ForgeControlRequest::AgentSetFocus { .. }
        | ForgeControlRequest::AgentPublishWorkUpdate { .. }
        | ForgeControlRequest::AgentDetach { .. }
        | ForgeControlRequest::AgentList { .. }
        | ForgeControlRequest::AgentGetContext { .. }
        | ForgeControlRequest::AgentDagGrantIssue { .. }
        | ForgeControlRequest::AgentDagGrantRevoke { .. }
        | ForgeControlRequest::AgentDagGrantGet { .. }
        | ForgeControlRequest::AgentDagGrantDiscover { .. }
        | ForgeControlRequest::AgentDagReplanCommit { .. }) => {
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
        ForgeControlRequest::RenewActivityLeaseBatch { .. }
        | ForgeControlRequest::CloseOwnedActivityBatch { .. }
        | ForgeControlRequest::ReleaseActivityLease { .. }
        | ForgeControlRequest::ReconcileExpiredActivityLeases { .. }
        | ForgeControlRequest::ListActivityProjections { .. }
        | ForgeControlRequest::ListWorkspaceActivityProjections { .. }
        | ForgeControlRequest::FileRead { .. }
        | ForgeControlRequest::FileMutate { .. }
        | ForgeControlRequest::ExecutionMarkRunning { .. }
        | ForgeControlRequest::ExecutionComplete { .. }
        | ForgeControlRequest::ExecutionFail { .. }
        | ForgeControlRequest::ExecutionReconcile { .. }
        | ForgeControlRequest::ExecutionGet { .. }
        | ForgeControlRequest::ExecutionList { .. }
        | ForgeControlRequest::GoalCreate { .. }
        | ForgeControlRequest::GoalGet { .. }
        | ForgeControlRequest::GoalList { .. }
        | ForgeControlRequest::GoalTransition { .. }
        | ForgeControlRequest::GoalReview { .. }
        | ForgeControlRequest::GoalComplete { .. }
        | ForgeControlRequest::DagRevisionCreate { .. }
        | ForgeControlRequest::DagGetCurrent { .. }
        | ForgeControlRequest::DagGetRevision { .. }
        | ForgeControlRequest::DagNodeStart { .. }
        | ForgeControlRequest::DagNodeUpdate { .. }
        | ForgeControlRequest::RecoveryLeaseGet { .. }
        | ForgeControlRequest::RecoveryLeaseClaim { .. }
        | ForgeControlRequest::RecoveryLeaseRenew { .. }
        | ForgeControlRequest::RecoveryLeaseRelease { .. }
        | ForgeControlRequest::RecoveryMaintenanceRun { .. }
        | ForgeControlRequest::CheckpointRestoreRun { .. }
        | ForgeControlRequest::EnsureWorkspacePolicy { .. }
        | ForgeControlRequest::ReplaceWorkspacePolicy { .. }
        | ForgeControlRequest::ApprovalCreate { .. }
        | ForgeControlRequest::ApprovalListPending { .. }
        | ForgeControlRequest::ApprovalGet { .. }
        | ForgeControlRequest::ApprovalApproveOnce { .. }
        | ForgeControlRequest::ApprovalDecide { .. }
        | ForgeControlRequest::AutoApprovalScopeCreate { .. }
        | ForgeControlRequest::AutoApprovalScopeRevoke { .. }
        | ForgeControlRequest::ApprovalGrantConsume { .. }
        | ForgeControlRequest::AutoApprovalConsume { .. }
        | ForgeControlRequest::ApprovalReconcileExpired { .. }
        | ForgeControlRequest::ApprovalCancelActivity { .. }
        | ForgeControlRequest::ApprovalCancelWorkspace { .. }
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
            observed_at: _,
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
        request @ (ForgeControlRequest::WorkspaceList { .. }
        | ForgeControlRequest::ResolveWorkspace { .. }
        | ForgeControlRequest::BootstrapActivity { .. }
        | ForgeControlRequest::RenewActivityLease { .. }
        | ForgeControlRequest::CloseActivity { .. }) => {
            dispatch_activity_request(control, request);
        }
        ForgeControlRequest::RenewActivityLeaseBatch {
            scope,
            commands,
            response,
        } => {
            let result = commands
                .iter()
                .map(rebase_renew_activity_lease)
                .collect::<Result<Vec<_>, _>>()
                .and_then(|commands| control.renew_activity_lease_batch(&scope, &commands));
            let _ignored = response.send(result);
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
            observed_at: _,
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
        ForgeControlRequest::Shutdown { .. } => {}
        request => dispatch_effect_request(control, request),
    }
}

fn dispatch_effect_request(control: &ForgeControl, request: ForgeControlRequest) {
    let Some(request) = dispatch_workspace_effect_request(control, request) else {
        return;
    };
    match request {
        request @ (ForgeControlRequest::ExecutionMarkRunning { .. }
        | ForgeControlRequest::ExecutionComplete { .. }
        | ForgeControlRequest::ExecutionFail { .. }
        | ForgeControlRequest::ExecutionReconcile { .. }
        | ForgeControlRequest::ExecutionGet { .. }
        | ForgeControlRequest::ExecutionList { .. }) => {
            dispatch_execution_request(control, request);
        }
        request @ (ForgeControlRequest::GoalCreate { .. }
        | ForgeControlRequest::GoalGet { .. }
        | ForgeControlRequest::GoalList { .. }
        | ForgeControlRequest::GoalTransition { .. }
        | ForgeControlRequest::GoalReview { .. }
        | ForgeControlRequest::GoalComplete { .. }) => {
            dispatch_goal_request(control, request);
        }
        request @ (ForgeControlRequest::DagRevisionCreate { .. }
        | ForgeControlRequest::DagGetCurrent { .. }
        | ForgeControlRequest::DagGetRevision { .. }
        | ForgeControlRequest::DagNodeStart { .. }
        | ForgeControlRequest::DagNodeUpdate { .. }) => {
            dispatch_dag_request(control, request);
        }
        request @ (ForgeControlRequest::RecoveryLeaseGet { .. }
        | ForgeControlRequest::RecoveryLeaseClaim { .. }
        | ForgeControlRequest::RecoveryLeaseRenew { .. }
        | ForgeControlRequest::RecoveryLeaseRelease { .. }
        | ForgeControlRequest::RecoveryMaintenanceRun { .. }
        | ForgeControlRequest::CheckpointRestoreRun { .. }) => {
            dispatch_recovery_request(control, request);
        }
        request @ (ForgeControlRequest::EnsureWorkspacePolicy { .. }
        | ForgeControlRequest::ReplaceWorkspacePolicy { .. }
        | ForgeControlRequest::ApprovalCreate { .. }
        | ForgeControlRequest::ApprovalListPending { .. }
        | ForgeControlRequest::ApprovalGet { .. }
        | ForgeControlRequest::ApprovalApproveOnce { .. }
        | ForgeControlRequest::ApprovalDecide { .. }
        | ForgeControlRequest::AutoApprovalScopeCreate { .. }
        | ForgeControlRequest::AutoApprovalScopeRevoke { .. }
        | ForgeControlRequest::ApprovalGrantConsume { .. }
        | ForgeControlRequest::AutoApprovalConsume { .. }
        | ForgeControlRequest::ApprovalReconcileExpired { .. }
        | ForgeControlRequest::ApprovalCancelActivity { .. }
        | ForgeControlRequest::ApprovalCancelWorkspace { .. }) => {
            dispatch_approval_request(control, request);
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
        request @ (ForgeControlRequest::AgentAttach { .. }
        | ForgeControlRequest::AgentSetFocus { .. }
        | ForgeControlRequest::AgentPublishWorkUpdate { .. }
        | ForgeControlRequest::AgentDetach { .. }
        | ForgeControlRequest::AgentList { .. }
        | ForgeControlRequest::AgentGetContext { .. }
        | ForgeControlRequest::AgentDagGrantIssue { .. }
        | ForgeControlRequest::AgentDagGrantRevoke { .. }
        | ForgeControlRequest::AgentDagGrantGet { .. }
        | ForgeControlRequest::AgentDagGrantDiscover { .. }
        | ForgeControlRequest::AgentDagReplanCommit { .. }) => {
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
        ForgeControlRequest::ListWorkspaceActivityProjections { request, response } => {
            let _ignored = response.send(control.list_workspace_activity_projections(&request));
        }
        ForgeControlRequest::FileRead { request, response } => {
            dispatch_file_read(control, request, &response);
        }
        ForgeControlRequest::FileMutate { request, response } => {
            dispatch_file_mutation(control, request, &response);
        }
        other => return Some(other),
    }
    None
}

fn dispatch_agent_request(control: &ForgeControl, request: ForgeControlRequest) {
    match request {
        ForgeControlRequest::AgentAttach { request, response } => {
            let _ignored = response.send(control.agent_attach(&request));
        }
        ForgeControlRequest::AgentSetFocus { request, response } => {
            let _ignored = response.send(control.agent_set_focus(&request));
        }
        ForgeControlRequest::AgentPublishWorkUpdate { request, response } => {
            let _ignored = response.send(control.agent_publish_work_update(&request));
        }
        ForgeControlRequest::AgentDetach { request, response } => {
            let _ignored = response.send(control.agent_detach(&request));
        }
        ForgeControlRequest::AgentList { request, response } => {
            let _ignored = response.send(control.agent_list(&request));
        }
        ForgeControlRequest::AgentGetContext { request, response } => {
            let _ignored = response.send(control.agent_get_context(&request));
        }
        ForgeControlRequest::AgentDagGrantIssue { request, response } => {
            let _ignored = response.send(control.agent_dag_grant_issue(&request));
        }
        ForgeControlRequest::AgentDagGrantRevoke { request, response } => {
            let _ignored = response.send(control.agent_dag_grant_revoke(&request));
        }
        ForgeControlRequest::AgentDagGrantGet { request, response } => {
            let _ignored = response.send(control.agent_dag_grant_get(&request));
        }
        ForgeControlRequest::AgentDagGrantDiscover { request, response } => {
            let _ignored = response.send(control.agent_dag_grant_discover(&request));
        }
        ForgeControlRequest::AgentDagReplanCommit { request, response } => {
            let _ignored = response.send(control.agent_dag_replan_commit(&request));
        }
        other => dispatch_effect_request(control, other),
    }
}

fn dispatch_execution_request(control: &ForgeControl, request: ForgeControlRequest) {
    match request {
        ForgeControlRequest::ExecutionMarkRunning {
            scope,
            command,
            response,
        } => {
            let _ignored = response.send(control.execution_mark_running(&scope, command));
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
        ForgeControlRequest::ExecutionList {
            scope,
            activity_id,
            limit,
            response,
        } => {
            let _ignored = response.send(control.execution_list(&scope, activity_id, limit));
        }
        other => dispatch_supervisor_request(control, other),
    }
}

fn dispatch_goal_request(control: &ForgeControl, request: ForgeControlRequest) {
    match request {
        ForgeControlRequest::GoalCreate {
            scope,
            goal,
            response,
        } => {
            let _ignored = response.send(control.goal_create(&scope, &goal));
        }
        ForgeControlRequest::GoalGet {
            scope,
            goal_id,
            response,
        } => {
            let _ignored = response.send(control.goal_get(&scope, goal_id));
        }
        ForgeControlRequest::GoalList {
            scope,
            limit,
            response,
        } => {
            let _ignored = response.send(control.goal_list(&scope, limit));
        }
        ForgeControlRequest::GoalTransition { request, response } => {
            let _ignored = response.send(control.goal_transition(&request));
        }
        ForgeControlRequest::GoalReview {
            scope,
            goal_id,
            response,
        } => {
            let _ignored = response.send(control.goal_review(&scope, goal_id));
        }
        ForgeControlRequest::GoalComplete { request, response } => {
            let _ignored = response.send(control.goal_complete(&request));
        }
        other => dispatch_supervisor_request(control, other),
    }
}

fn dispatch_dag_request(control: &ForgeControl, request: ForgeControlRequest) {
    match request {
        ForgeControlRequest::DagRevisionCreate { request, response } => {
            let _ignored = response.send(control.dag_revision_create(&request));
        }
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
        ForgeControlRequest::DagNodeStart { request, response } => {
            let _ignored = response.send(control.dag_node_start(&request));
        }
        ForgeControlRequest::DagNodeUpdate { request, response } => {
            let _ignored = response.send(control.dag_node_update(&request));
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
            let _ignored =
                response.send(control.claim_recovery_maintenance_lease(&scope, &command));
        }
        ForgeControlRequest::RecoveryLeaseRenew {
            scope,
            command,
            response,
        } => {
            let _ignored =
                response.send(control.renew_recovery_maintenance_lease(&scope, &command));
        }
        ForgeControlRequest::RecoveryLeaseRelease {
            scope,
            command,
            response,
        } => {
            let _ignored =
                response.send(control.release_recovery_maintenance_lease(&scope, &command));
        }
        ForgeControlRequest::RecoveryMaintenanceRun { request, response } => {
            let _ignored = response.send(control.run_recovery_maintenance(&request));
        }
        ForgeControlRequest::CheckpointRestoreRun { request, response } => {
            let _ignored = response.send(control.checkpoint_restore(&request));
        }
        other => dispatch_supervisor_request(control, other),
    }
}

fn dispatch_approval_request(control: &ForgeControl, request: ForgeControlRequest) {
    match request {
        ForgeControlRequest::EnsureWorkspacePolicy {
            scope,
            observed_at: _,
            response,
        } => {
            let result = runtime_timestamp_millis()
                .and_then(|observed_at| control.ensure_workspace_policy(&scope, observed_at));
            let _ignored = response.send(result);
        }
        ForgeControlRequest::ReplaceWorkspacePolicy { request, response } => {
            let result = rebase_policy_request(request)
                .and_then(|request| control.replace_workspace_policy(&request));
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
        ForgeControlRequest::ApprovalReconcileExpired { request, response } => {
            let result = rebase_approval_reconcile(request)
                .and_then(|request| control.reconcile_expired_approval_authority(&request));
            let _ignored = response.send(result);
        }
        ForgeControlRequest::ApprovalCancelActivity { request, response } => {
            let result = rebase_cancel_activity_authority(request)
                .and_then(|request| control.cancel_activity_approval_authority(&request));
            let _ignored = response.send(result);
        }
        ForgeControlRequest::ApprovalCancelWorkspace { request, response } => {
            let result = rebase_cancel_workspace_authority(request)
                .and_then(|request| control.cancel_workspace_approval_authority(&request));
            let _ignored = response.send(result);
        }
        other => dispatch_supervisor_request(control, other),
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

fn rebase_approval_reconcile(
    mut request: ApprovalReconcileRequest,
) -> Result<ApprovalReconcileRequest, ControlError> {
    request.observed_at = runtime_timestamp_millis()?;
    Ok(request)
}

fn rebase_cancel_activity_authority(
    mut request: ApprovalCancelActivityRequest,
) -> Result<ApprovalCancelActivityRequest, ControlError> {
    request.observed_at = runtime_timestamp_millis()?;
    Ok(request)
}

fn rebase_cancel_workspace_authority(
    mut request: ApprovalCancelWorkspaceRequest,
) -> Result<ApprovalCancelWorkspaceRequest, ControlError> {
    request.observed_at = runtime_timestamp_millis()?;
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

fn runtime_timestamp_millis() -> Result<TimestampMillis, ControlError> {
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

#[allow(clippy::too_many_lines)]
fn drain_queued_requests(receiver: &Receiver<ForgeControlRequest>) {
    while let Ok(request) = receiver.try_recv() {
        match request {
            request @ (ForgeControlRequest::WorkspaceList { .. }
            | ForgeControlRequest::ResolveWorkspace { .. }
            | ForgeControlRequest::WorkspaceDoctor { .. }
            | ForgeControlRequest::WorkspaceIdentityDoctor { .. }
            | ForgeControlRequest::HarnessGetApplied { .. }
            | ForgeControlRequest::HarnessVerifierGetLatest { .. }
            | ForgeControlRequest::HarnessVerifierPersist { .. }
            | ForgeControlRequest::HarnessPreview { .. }
            | ForgeControlRequest::HarnessApply { .. }
            | ForgeControlRequest::HarnessLifecyclePreview { .. }
            | ForgeControlRequest::HarnessLifecycleApply { .. }
            | ForgeControlRequest::HarnessVerifySource { .. }
            | ForgeControlRequest::BootstrapActivity { .. }) => reject_queued_workspace(request),
            request @ (ForgeControlRequest::AgentAttach { .. }
            | ForgeControlRequest::AgentSetFocus { .. }
            | ForgeControlRequest::AgentPublishWorkUpdate { .. }
            | ForgeControlRequest::AgentDetach { .. }
            | ForgeControlRequest::AgentList { .. }
            | ForgeControlRequest::AgentGetContext { .. }
            | ForgeControlRequest::AgentDagGrantIssue { .. }
            | ForgeControlRequest::AgentDagGrantRevoke { .. }
            | ForgeControlRequest::AgentDagGrantGet { .. }
            | ForgeControlRequest::AgentDagGrantDiscover { .. }
            | ForgeControlRequest::AgentDagReplanCommit { .. }) => reject_queued_agent(request),
            ForgeControlRequest::RenewActivityLease { response, .. }
            | ForgeControlRequest::RenewActivityLeaseBatch { response, .. }
            | ForgeControlRequest::CloseActivity { response, .. }
            | ForgeControlRequest::CloseOwnedActivityBatch { response, .. }
            | ForgeControlRequest::ReleaseActivityLease { response, .. }
            | ForgeControlRequest::ReconcileExpiredActivityLeases { response, .. } => {
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
            ForgeControlRequest::FileRead { response, .. } => {
                let _ignored =
                    response.send(Err(ControlError::new(ControlErrorCode::WorkerShuttingDown)));
            }
            ForgeControlRequest::CheckpointRestoreRun { response, .. } => {
                let _ignored =
                    response.send(Err(ControlError::new(ControlErrorCode::WorkerShuttingDown)));
            }
            ForgeControlRequest::FileMutate { response, .. } => {
                let _ignored =
                    response.send(Err(ControlError::new(ControlErrorCode::WorkerShuttingDown)));
            }
            request @ (ForgeControlRequest::ExecutionMarkRunning { .. }
            | ForgeControlRequest::ExecutionComplete { .. }
            | ForgeControlRequest::ExecutionFail { .. }
            | ForgeControlRequest::ExecutionReconcile { .. }
            | ForgeControlRequest::ExecutionList { .. }
            | ForgeControlRequest::ExecutionGet { .. }) => reject_queued_execution(request),
            request @ (ForgeControlRequest::GoalCreate { .. }
            | ForgeControlRequest::GoalGet { .. }
            | ForgeControlRequest::GoalList { .. }
            | ForgeControlRequest::GoalTransition { .. }
            | ForgeControlRequest::GoalReview { .. }
            | ForgeControlRequest::GoalComplete { .. }) => reject_queued_goal(request),
            request @ (ForgeControlRequest::DagRevisionCreate { .. }
            | ForgeControlRequest::DagGetCurrent { .. }
            | ForgeControlRequest::DagGetRevision { .. }
            | ForgeControlRequest::DagNodeStart { .. }
            | ForgeControlRequest::DagNodeUpdate { .. }) => reject_queued_dag(request),
            request @ (ForgeControlRequest::RecoveryLeaseGet { .. }
            | ForgeControlRequest::RecoveryLeaseClaim { .. }
            | ForgeControlRequest::RecoveryLeaseRenew { .. }
            | ForgeControlRequest::RecoveryLeaseRelease { .. }
            | ForgeControlRequest::RecoveryMaintenanceRun { .. }) => {
                reject_queued_recovery(request);
            }
            request @ (ForgeControlRequest::EnsureWorkspacePolicy { .. }
            | ForgeControlRequest::ReplaceWorkspacePolicy { .. }
            | ForgeControlRequest::ApprovalCreate { .. }
            | ForgeControlRequest::ApprovalListPending { .. }
            | ForgeControlRequest::ApprovalGet { .. }
            | ForgeControlRequest::ApprovalApproveOnce { .. }
            | ForgeControlRequest::ApprovalDecide { .. }
            | ForgeControlRequest::AutoApprovalScopeCreate { .. }
            | ForgeControlRequest::AutoApprovalScopeRevoke { .. }
            | ForgeControlRequest::ApprovalGrantConsume { .. }
            | ForgeControlRequest::AutoApprovalConsume { .. }
            | ForgeControlRequest::ApprovalReconcileExpired { .. }
            | ForgeControlRequest::ApprovalCancelActivity { .. }
            | ForgeControlRequest::ApprovalCancelWorkspace { .. }) => {
                reject_queued_approval(request);
            }
            request @ (ForgeControlRequest::DiffList { .. }
            | ForgeControlRequest::DiffRead { .. }
            | ForgeControlRequest::DiffDoctor { .. }
            | ForgeControlRequest::DiffRetentionPlan { .. }
            | ForgeControlRequest::DiffPurge { .. }
            | ForgeControlRequest::DiffArtifactDoctor { .. }
            | ForgeControlRequest::DeleteOrphanDiffArtifact { .. }) => reject_queued_diff(request),
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
        ForgeControlRequest::AgentAttach { response, .. }
        | ForgeControlRequest::AgentSetFocus { response, .. }
        | ForgeControlRequest::AgentDetach { response, .. } => {
            let _ignored =
                response.send(Err(ControlError::new(ControlErrorCode::WorkerShuttingDown)));
        }
        ForgeControlRequest::AgentPublishWorkUpdate { response, .. } => {
            let _ignored =
                response.send(Err(ControlError::new(ControlErrorCode::WorkerShuttingDown)));
        }
        ForgeControlRequest::AgentList { response, .. } => {
            let _ignored =
                response.send(Err(ControlError::new(ControlErrorCode::WorkerShuttingDown)));
        }
        ForgeControlRequest::AgentGetContext { response, .. } => {
            let _ignored =
                response.send(Err(ControlError::new(ControlErrorCode::WorkerShuttingDown)));
        }
        ForgeControlRequest::AgentDagGrantIssue { response, .. }
        | ForgeControlRequest::AgentDagGrantRevoke { response, .. } => {
            let _ignored =
                response.send(Err(ControlError::new(ControlErrorCode::WorkerShuttingDown)));
        }
        ForgeControlRequest::AgentDagGrantGet { response, .. }
        | ForgeControlRequest::AgentDagGrantDiscover { response, .. } => {
            let _ignored =
                response.send(Err(ControlError::new(ControlErrorCode::WorkerShuttingDown)));
        }
        ForgeControlRequest::AgentDagReplanCommit { response, .. } => {
            let _ignored =
                response.send(Err(ControlError::new(ControlErrorCode::WorkerShuttingDown)));
        }
        other => reject_queued_workspace(other),
    }
}

fn reject_queued_workspace(request: ForgeControlRequest) {
    match request {
        ForgeControlRequest::WorkspaceList { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::ResolveWorkspace { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::WorkspaceDoctor { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::WorkspaceIdentityDoctor { response } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::HarnessGetApplied { response, .. }
        | ForgeControlRequest::HarnessLifecycleApply { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::HarnessVerifierGetLatest { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::HarnessVerifierPersist { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::HarnessPreview { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::HarnessApply { response, .. }
        | ForgeControlRequest::HarnessVerifySource { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::HarnessLifecyclePreview { response, .. } => {
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
        ForgeControlRequest::ApprovalApproveOnce { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::AutoApprovalScopeCreate { response, .. }
        | ForgeControlRequest::AutoApprovalScopeRevoke { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::ApprovalGrantConsume { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::AutoApprovalConsume { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::ApprovalReconcileExpired { response, .. }
        | ForgeControlRequest::ApprovalCancelActivity { response, .. }
        | ForgeControlRequest::ApprovalCancelWorkspace { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        _ => {}
    }
}

fn reject_queued_execution(request: ForgeControlRequest) {
    match request {
        ForgeControlRequest::ExecutionMarkRunning { response, .. }
        | ForgeControlRequest::ExecutionComplete { response, .. }
        | ForgeControlRequest::ExecutionFail { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::ExecutionReconcile { response, .. }
        | ForgeControlRequest::ExecutionList { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::ExecutionGet { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        _ => {}
    }
}

fn reject_queued_goal(request: ForgeControlRequest) {
    match request {
        ForgeControlRequest::GoalCreate { response, .. }
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
        ForgeControlRequest::DagRevisionCreate { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::DagGetCurrent { response, .. }
        | ForgeControlRequest::DagGetRevision { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::DagNodeStart { response, .. }
        | ForgeControlRequest::DagNodeUpdate { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        _ => {}
    }
}

fn reject_queued_recovery(request: ForgeControlRequest) {
    match request {
        ForgeControlRequest::CheckpointRestoreRun { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::RecoveryLeaseGet { response, .. }
        | ForgeControlRequest::RecoveryLeaseRenew { response, .. }
        | ForgeControlRequest::RecoveryLeaseRelease { response, .. } => {
            let _ignored = response.send(worker_shutting_down());
        }
        ForgeControlRequest::RecoveryMaintenanceRun { response, .. } => {
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
    use std::path::Path;

    use forge_domain::{
        ActivityId, AgentDeclaredRole, AgentDisplayName, AgentInstanceId, AgentTransportKind,
        LocationId, LocationRevision, RegisteredAgentInstance, TimestampMillis, WorkspaceId,
        WorkspaceRevision,
    };
    use forge_workspace::WorkspaceLocator;
    use uuid::Uuid;

    use super::*;

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
        let agent = RegisteredAgentInstance::create(
            AgentInstanceId::from_uuid(Uuid::from_u128(0x4003)),
            scope.workspace_id(),
            ActivityId::from_uuid(Uuid::from_u128(0x4004)),
            AgentDisplayName::new("Planner".to_owned())?,
            AgentDeclaredRole::new("planner".to_owned())?,
            AgentTransportKind::Mcp,
            TimestampMillis::new(1)?,
        );
        let (request_sender, request_receiver) = mpsc::sync_channel(1);
        let (response_sender, response_receiver) = mpsc::sync_channel(1);
        request_sender.send(ForgeControlRequest::AgentAttach {
            request: AgentAttachRequest {
                scope,
                activity_id: agent.activity_id(),
                agent,
            },
            response: response_sender,
        })?;
        drain_queued_requests(&request_receiver);
        let Err(error) = response_receiver.recv()? else {
            return Err("queued Agent attach was unexpectedly accepted".into());
        };
        assert_eq!(error.code(), ControlErrorCode::WorkerShuttingDown);
        Ok(())
    }
}
