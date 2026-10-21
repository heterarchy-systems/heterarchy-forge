use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::thread::{self, JoinHandle};
use std::time::{SystemTime, UNIX_EPOCH};

use forge_domain::{
    ActivityId, ApprovalAgentBindingDigest, ApprovalDecision, ApprovalRequestId,
    ApprovalRequestState, AutoApprovalScope, AutoApprovalScopeId, AutoApprovalScopeRevision,
    AutoApprovalScopeState, AutoApprovalUseLimit, ExecutionActionClass,
    ExecutionAuthorizationRequest, ExecutionGrantId, ExecutionId, ExecutionKind,
    ExecutionListLimit, ExecutionPermissions, ExecutionPolicyDisposition, ExecutionRequest,
    GoalAttribution, GoalNodeAttribution, GoalWorkAttribution, ProjectCommandClass,
    ProjectCommandEvidence, RegisteredApprovalRequest, RequestedExecutionPermissions,
    RuntimeInstanceId, TimestampMillis, WorkspaceId,
};
use forge_execution::execution_request_digest;
use forge_persistence::{ApprovalCleanupApplyOutcome, ApprovalCleanupAttemptId};
use thiserror::Error;
use uuid::Uuid;

use crate::approval_cleanup::{
    ApprovalCleanupOwner, ApprovalCleanupPermit, ApprovalCleanupPlan, ApprovalCleanupReadback,
    ApprovalCleanupSelector,
};
use crate::approval_expiry::ApprovalExpiryPlan;
use crate::execution_coordinator::{
    AutoCoordinatorAuthorization, ExecutionCoordinatorStartRequest,
};
use crate::{
    AgentExecutionAuthorityRequest, ApprovalActivityScope, ApprovalCreateRequest,
    ApprovalDecisionRequest, ApprovalOnceRequest, AutoApprovalScopeCreateRequest,
    AutoApprovalScopeRevokeRequest, ControlClientError, ControlErrorDetails,
    ExecutionStartDisposition, ExecutionStartResult, ForgeControlClient,
    ForgeExecutionCoordinatorClient, ForgeExecutionCoordinatorError, ResolvedWorkspaceScope,
};

const APPROVAL_COORDINATOR_CAPACITY: usize = 16;
const MAX_PENDING_PAYLOADS: usize = 128;
const MAX_AUTO_SCOPES: usize = 32;
const APPROVAL_WINDOW_MILLIS: i64 = 10 * 60 * 1_000;
const GRANT_WINDOW_MILLIS: i64 = 5 * 60 * 1_000;
const CLEANUP_LIMIT: u16 = 256;
const CLEANUP_ROUNDS: usize = 4;
const THREAD_NAME: &str = "heterarchy-forge-approval-coordinator";

type Response<T> = SyncSender<Result<T, ForgeApprovalCoordinatorError>>;

#[must_use]
#[derive(Debug, Clone)]
pub struct SubmitExecutionForApproval {
    scope: ResolvedWorkspaceScope,
    activity_id: ActivityId,
    runtime_instance_id: RuntimeInstanceId,
    action: ExecutionActionClass,
    request: ExecutionRequest,
    goal: Option<GoalWorkAttribution>,
    approval_id: Option<ApprovalRequestId>,
    agent_authority: Option<AgentExecutionAuthorityRequest>,
    project_command: Option<ProjectCommandEvidence>,
}

impl SubmitExecutionForApproval {
    pub fn direct(
        scope: ResolvedWorkspaceScope,
        activity_id: ActivityId,
        runtime_instance_id: RuntimeInstanceId,
        request: ExecutionRequest,
    ) -> Self {
        let action = match request.kind() {
            ExecutionKind::Structured { .. } => ExecutionActionClass::DirectStructured,
            ExecutionKind::Shell { .. } => ExecutionActionClass::ShellEscape,
        };
        Self {
            scope,
            activity_id,
            runtime_instance_id,
            action,
            request,
            goal: None,
            approval_id: None,
            agent_authority: None,
            project_command: None,
        }
    }

    /// Reserve a stable approval identity before submission so a durable
    /// coordinator can safely retry after restart without inventing a second
    /// approval request for the same execution.
    pub const fn with_approval_id(mut self, approval_id: ApprovalRequestId) -> Self {
        self.approval_id = Some(approval_id);
        self
    }

    pub fn with_goal(mut self, attribution: GoalAttribution) -> Self {
        self.goal = Some(attribution.into());
        self
    }

    pub fn with_goal_node(mut self, attribution: GoalNodeAttribution) -> Self {
        self.goal = Some(attribution.into());
        self
    }

    /// Attach exact Agent/Goal/DAG/Node authority for Agent-originated
    /// execution. Internal execution callers leave this unset.
    pub fn with_agent_authority(mut self, authority: AgentExecutionAuthorityRequest) -> Self {
        self.agent_authority = Some(authority);
        self
    }

    /// Submit a command only after the control layer has re-resolved its
    /// exact catalog fingerprint. The caller cannot choose the policy action:
    /// generated packages retain a distinct durable class but use the
    /// direct-structured `Ask` policy rule.
    pub fn project_command(
        scope: ResolvedWorkspaceScope,
        activity_id: ActivityId,
        runtime_instance_id: RuntimeInstanceId,
        request: ExecutionRequest,
        evidence: ProjectCommandEvidence,
    ) -> Result<Self, ForgeApprovalCoordinatorError> {
        if !matches!(request.kind(), ExecutionKind::Structured { .. }) {
            return Err(ForgeApprovalCoordinatorError::AttributionMismatch);
        }
        let action = match evidence.class() {
            ProjectCommandClass::Verify => ExecutionActionClass::DiscoveredProjectCommand,
            ProjectCommandClass::GeneratedPackage => ExecutionActionClass::GeneratedProjectCommand,
        };
        Ok(Self {
            scope,
            activity_id,
            runtime_instance_id,
            action,
            request,
            goal: None,
            approval_id: None,
            agent_authority: None,
            project_command: Some(evidence),
        })
    }

    /// Submit a command discovered from trusted Workspace metadata. This
    /// ingress accepts structured execution only and preserves the distinct
    /// Agent-originated command policy action class.
    pub fn discovered(
        scope: ResolvedWorkspaceScope,
        activity_id: ActivityId,
        runtime_instance_id: RuntimeInstanceId,
        request: ExecutionRequest,
    ) -> Result<Self, ForgeApprovalCoordinatorError> {
        if !matches!(request.kind(), ExecutionKind::Structured { .. }) {
            return Err(ForgeApprovalCoordinatorError::AttributionMismatch);
        }
        Ok(Self {
            scope,
            activity_id,
            runtime_instance_id,
            action: ExecutionActionClass::DiscoveredProjectCommand,
            request,
            goal: None,
            approval_id: None,
            agent_authority: None,
            project_command: None,
        })
    }

    /// Submit one server-analyzed Agent shell script. The analyzer owns the
    /// effective permissions; exact Agent/Goal/DAG/node authority is attached
    /// before admission. Internal `ShellEscape` remains a separate action.
    pub fn analyzed_shell(
        scope: ResolvedWorkspaceScope,
        activity_id: ActivityId,
        runtime_instance_id: RuntimeInstanceId,
        request: ExecutionRequest,
    ) -> Result<Self, ForgeApprovalCoordinatorError> {
        if !matches!(request.kind(), ExecutionKind::Shell { .. }) {
            return Err(ForgeApprovalCoordinatorError::AttributionMismatch);
        }
        Ok(Self {
            scope,
            activity_id,
            runtime_instance_id,
            action: ExecutionActionClass::AnalyzedShell,
            request,
            goal: None,
            approval_id: None,
            agent_authority: None,
            project_command: None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalSubmissionStatus {
    Pending,
    Started,
    Existing,
    Denied,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalSubmission {
    status: ApprovalSubmissionStatus,
    approval_id: ApprovalRequestId,
    execution_id: ExecutionId,
}

impl ApprovalSubmission {
    pub const fn status(&self) -> ApprovalSubmissionStatus {
        self.status
    }

    pub const fn approval_id(&self) -> ApprovalRequestId {
        self.approval_id
    }

    pub const fn execution_id(&self) -> ExecutionId {
        self.execution_id
    }
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingApprovalProjection {
    approval_id: ApprovalRequestId,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    execution_id: ExecutionId,
    action: ExecutionActionClass,
    expires_at: TimestampMillis,
    actionable: bool,
}

impl PendingApprovalProjection {
    fn from_record(record: &RegisteredApprovalRequest, actionable: bool) -> Self {
        let request = record.request();
        Self {
            approval_id: record.id(),
            workspace_id: request.workspace_id(),
            activity_id: request.activity_id(),
            execution_id: request.execution_id(),
            action: request.action(),
            expires_at: record.expires_at(),
            actionable,
        }
    }

    pub const fn approval_id(self) -> ApprovalRequestId {
        self.approval_id
    }

    pub const fn workspace_id(self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn activity_id(self) -> ActivityId {
        self.activity_id
    }

    pub const fn execution_id(self) -> ExecutionId {
        self.execution_id
    }

    pub const fn action(self) -> ExecutionActionClass {
        self.action
    }

    pub const fn expires_at(self) -> TimestampMillis {
        self.expires_at
    }

    pub const fn actionable(self) -> bool {
        self.actionable
    }
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AutoApprovalActionStatus {
    action: ExecutionActionClass,
    runtime_state: AutoApprovalRuntimeState,
    locality: AutoApprovalScopeLocality,
    scope_id: Option<AutoApprovalScopeId>,
    scope_active: bool,
    expires_at: Option<TimestampMillis>,
    remaining_ttl_millis: Option<i64>,
    used_count: u32,
    max_uses: Option<u32>,
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AutoApprovalStatus {
    preference_enabled: bool,
    commands: AutoApprovalActionStatus,
    shell: AutoApprovalActionStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AutoApprovalRuntimeState {
    Inactive,
    Active,
    Expired,
    Exhausted,
    Revoked,
    PolicyChanged,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AutoApprovalScopeLocality {
    None,
    Local,
    External,
}

impl AutoApprovalActionStatus {
    const fn disabled(action: ExecutionActionClass) -> Self {
        Self {
            action,
            runtime_state: AutoApprovalRuntimeState::Inactive,
            locality: AutoApprovalScopeLocality::None,
            scope_id: None,
            scope_active: false,
            expires_at: None,
            remaining_ttl_millis: None,
            used_count: 0,
            max_uses: Some(0),
        }
    }

    const fn unavailable(action: ExecutionActionClass) -> Self {
        Self {
            action,
            runtime_state: AutoApprovalRuntimeState::Unavailable,
            locality: AutoApprovalScopeLocality::None,
            scope_id: None,
            scope_active: false,
            expires_at: None,
            remaining_ttl_millis: None,
            used_count: 0,
            max_uses: Some(0),
        }
    }

    fn from_scope(
        scope: &AutoApprovalScope,
        observed_at: TimestampMillis,
        policy_revision: Option<forge_domain::PolicyRevision>,
    ) -> Self {
        let runtime_state = if policy_revision.is_none() {
            AutoApprovalRuntimeState::Unavailable
        } else if policy_revision != Some(scope.policy_revision()) {
            AutoApprovalRuntimeState::PolicyChanged
        } else if scope.state() == AutoApprovalScopeState::Revoked {
            AutoApprovalRuntimeState::Revoked
        } else if !scope.max_uses().permits(u64::from(scope.used_count())) {
            AutoApprovalRuntimeState::Exhausted
        } else if observed_at.get() >= scope.expires_at().get()
            || scope.state() == AutoApprovalScopeState::Expired
        {
            AutoApprovalRuntimeState::Expired
        } else {
            AutoApprovalRuntimeState::Active
        };
        let remaining_ttl_millis = (runtime_state == AutoApprovalRuntimeState::Active)
            .then(|| scope.expires_at().get().saturating_sub(observed_at.get()));
        Self {
            action: scope.action(),
            runtime_state,
            locality: AutoApprovalScopeLocality::Local,
            scope_id: Some(scope.id()),
            scope_active: runtime_state == AutoApprovalRuntimeState::Active,
            expires_at: Some(scope.expires_at()),
            remaining_ttl_millis,
            used_count: scope.used_count(),
            max_uses: scope.max_uses().get().map(u32::from),
        }
    }

    pub const fn action(self) -> ExecutionActionClass {
        self.action
    }

    pub const fn scope_active(self) -> bool {
        self.scope_active
    }

    pub const fn runtime_state(self) -> AutoApprovalRuntimeState {
        self.runtime_state
    }

    pub const fn locality(self) -> AutoApprovalScopeLocality {
        self.locality
    }

    pub const fn scope_id(self) -> Option<AutoApprovalScopeId> {
        self.scope_id
    }

    pub const fn expires_at(self) -> Option<TimestampMillis> {
        self.expires_at
    }

    pub const fn remaining_ttl_millis(self) -> Option<i64> {
        self.remaining_ttl_millis
    }

    pub const fn used_count(self) -> u32 {
        self.used_count
    }

    /// `None` denotes an explicit unlimited-count scope. An inactive status
    /// reports `Some(0)` and never implies an approval grant.
    pub const fn max_uses(self) -> Option<u32> {
        self.max_uses
    }

    pub const fn remaining_uses(self) -> Option<u32> {
        match self.max_uses {
            Some(limit) => Some(limit.saturating_sub(self.used_count)),
            None => None,
        }
    }
}

impl AutoApprovalStatus {
    const fn disabled() -> Self {
        Self {
            preference_enabled: false,
            commands: AutoApprovalActionStatus::disabled(
                ExecutionActionClass::DiscoveredProjectCommand,
            ),
            shell: AutoApprovalActionStatus::disabled(ExecutionActionClass::AnalyzedShell),
        }
    }

    pub const fn preference_enabled(&self) -> bool {
        self.preference_enabled
    }

    pub const fn commands(&self) -> AutoApprovalActionStatus {
        self.commands
    }

    pub const fn shell(&self) -> AutoApprovalActionStatus {
        self.shell
    }

    fn for_scopes(
        preference_enabled: bool,
        commands: AutoApprovalActionStatus,
        shell: AutoApprovalActionStatus,
    ) -> Self {
        Self {
            preference_enabled,
            commands,
            shell,
        }
    }
}

#[derive(Debug)]
enum ApprovalCoordinatorRequest {
    StartApproved {
        request: Box<crate::ApprovedAgentExecutionRequest>,
        response: Response<ExecutionStartResult>,
    },
    Submit {
        request: Box<SubmitExecutionForApproval>,
        response: Response<ApprovalSubmission>,
    },
    Approve {
        approval_id: ApprovalRequestId,
        response: Response<ExecutionId>,
    },
    Reject {
        approval_id: ApprovalRequestId,
        response: Response<RegisteredApprovalRequest>,
    },
    ListPending {
        scope: ResolvedWorkspaceScope,
        response: Response<Vec<PendingApprovalProjection>>,
    },
    RegisterAutoScope {
        request: AutoApprovalScopeCreateRequest,
        response: Response<AutoApprovalScope>,
    },
    SetAutoApproval {
        scope: ResolvedWorkspaceScope,
        enabled: bool,
        response: Response<bool>,
    },
    AutoApprovalStatus {
        scope: ResolvedWorkspaceScope,
        response: Response<AutoApprovalStatus>,
    },
    StopWorkspace {
        workspace_id: WorkspaceId,
        response: Response<usize>,
    },
    StopWorkspaceDurable {
        scope: ResolvedWorkspaceScope,
        request: Box<forge_persistence::ExecutionStopRequest>,
        response: Response<crate::execution_coordinator::OwnedWorkspaceExecutionStopObservation>,
    },
    StopWorkspaceIntent {
        intent: Box<crate::WorkspaceStopIntent>,
        response: Response<crate::OwnedWorkspaceExecutionStopObservation>,
    },
    ObserveWorkspaceStopIntent {
        intent: Box<crate::WorkspaceStopIntent>,
        response: Response<
            Option<(
                forge_persistence::ExecutionStopRecord,
                forge_persistence::AuthorityStopReceipt,
            )>,
        >,
    },
    StopActivity {
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        response: Response<usize>,
    },
    EmergencyStop {
        response: Response<usize>,
    },
    StopOwned {
        response: Response<ForgeApprovalCoordinatorShutdown>,
    },
    Shutdown {
        response: Response<ForgeApprovalCoordinatorShutdown>,
    },
}

#[derive(Debug, Clone)]
pub struct ForgeApprovalCoordinatorClient {
    sender: SyncSender<ApprovalCoordinatorRequest>,
    accepting: Arc<AtomicBool>,
}

#[derive(Debug)]
pub struct PendingApproval<T> {
    receiver: Receiver<Result<T, ForgeApprovalCoordinatorError>>,
}

impl<T> PendingApproval<T> {
    pub fn try_recv(
        &self,
    ) -> Result<Option<Result<T, ForgeApprovalCoordinatorError>>, ForgeApprovalCoordinatorError>
    {
        match self.receiver.try_recv() {
            Ok(result) => Ok(Some(result)),
            Err(mpsc::TryRecvError::Empty) => Ok(None),
            Err(mpsc::TryRecvError::Disconnected) => {
                Err(ForgeApprovalCoordinatorError::ResponseDropped)
            }
        }
    }

    pub fn recv(self) -> Result<T, ForgeApprovalCoordinatorError> {
        self.receiver
            .recv()
            .map_err(|_| ForgeApprovalCoordinatorError::ResponseDropped)?
    }
}

impl ForgeApprovalCoordinatorClient {
    /// Submit an already approved execution through this application's sole
    /// cleanup owner without creating another approval or issuing a grant.
    pub fn start_approved_agent_execution(
        &self,
        request: crate::ApprovedAgentExecutionRequest,
    ) -> Result<ExecutionStartResult, ForgeApprovalCoordinatorError> {
        self.submit(|response| ApprovalCoordinatorRequest::StartApproved {
            request: Box::new(request),
            response,
        })
    }
    pub fn submit_execution(
        &self,
        request: SubmitExecutionForApproval,
    ) -> Result<ApprovalSubmission, ForgeApprovalCoordinatorError> {
        self.submit(|response| ApprovalCoordinatorRequest::Submit {
            request: Box::new(request),
            response,
        })
    }

    pub fn approve_once(
        &self,
        approval_id: ApprovalRequestId,
    ) -> Result<ExecutionId, ForgeApprovalCoordinatorError> {
        self.submit(|response| ApprovalCoordinatorRequest::Approve {
            approval_id,
            response,
        })
    }

    pub fn submit_approve_once(
        &self,
        approval_id: ApprovalRequestId,
    ) -> Result<PendingApproval<ExecutionId>, ForgeApprovalCoordinatorError> {
        self.submit_pending(|response| ApprovalCoordinatorRequest::Approve {
            approval_id,
            response,
        })
    }

    pub fn reject(
        &self,
        approval_id: ApprovalRequestId,
    ) -> Result<RegisteredApprovalRequest, ForgeApprovalCoordinatorError> {
        self.submit(|response| ApprovalCoordinatorRequest::Reject {
            approval_id,
            response,
        })
    }

    pub fn submit_reject(
        &self,
        approval_id: ApprovalRequestId,
    ) -> Result<PendingApproval<RegisteredApprovalRequest>, ForgeApprovalCoordinatorError> {
        self.submit_pending(|response| ApprovalCoordinatorRequest::Reject {
            approval_id,
            response,
        })
    }

    pub fn list_pending(
        &self,
        scope: ResolvedWorkspaceScope,
    ) -> Result<Vec<PendingApprovalProjection>, ForgeApprovalCoordinatorError> {
        self.submit(|response| ApprovalCoordinatorRequest::ListPending { scope, response })
    }

    pub fn submit_list_pending(
        &self,
        scope: ResolvedWorkspaceScope,
    ) -> Result<PendingApproval<Vec<PendingApprovalProjection>>, ForgeApprovalCoordinatorError>
    {
        self.submit_pending(|response| ApprovalCoordinatorRequest::ListPending { scope, response })
    }

    pub fn register_auto_scope(
        &self,
        request: AutoApprovalScopeCreateRequest,
    ) -> Result<AutoApprovalScope, ForgeApprovalCoordinatorError> {
        self.submit(|response| ApprovalCoordinatorRequest::RegisterAutoScope { request, response })
    }

    pub fn submit_register_auto_scope(
        &self,
        request: AutoApprovalScopeCreateRequest,
    ) -> Result<PendingApproval<AutoApprovalScope>, ForgeApprovalCoordinatorError> {
        self.submit_pending(|response| ApprovalCoordinatorRequest::RegisterAutoScope {
            request,
            response,
        })
    }

    pub fn submit_set_auto_approval(
        &self,
        scope: ResolvedWorkspaceScope,
        enabled: bool,
    ) -> Result<PendingApproval<bool>, ForgeApprovalCoordinatorError> {
        self.submit_pending(|response| ApprovalCoordinatorRequest::SetAutoApproval {
            scope,
            enabled,
            response,
        })
    }

    pub fn auto_approval_status(
        &self,
        scope: ResolvedWorkspaceScope,
    ) -> Result<AutoApprovalStatus, ForgeApprovalCoordinatorError> {
        self.submit(|response| ApprovalCoordinatorRequest::AutoApprovalStatus { scope, response })
    }

    pub fn submit_auto_approval_status(
        &self,
        scope: ResolvedWorkspaceScope,
    ) -> Result<PendingApproval<AutoApprovalStatus>, ForgeApprovalCoordinatorError> {
        self.submit_pending(|response| ApprovalCoordinatorRequest::AutoApprovalStatus {
            scope,
            response,
        })
    }

    pub fn stop_workspace(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<usize, ForgeApprovalCoordinatorError> {
        self.submit(|response| ApprovalCoordinatorRequest::StopWorkspace {
            workspace_id,
            response,
        })
    }

    /// Stop only a Workspace already attached to this administrative owner.
    /// A supplied scope/request cannot mint a cleanup permit or prove completion.
    pub fn stop_workspace_durable(
        &self,
        scope: ResolvedWorkspaceScope,
        request: forge_persistence::ExecutionStopRequest,
    ) -> Result<
        crate::execution_coordinator::OwnedWorkspaceExecutionStopObservation,
        ForgeApprovalCoordinatorError,
    > {
        self.submit_stop_workspace_durable(scope, request)?.recv()
    }

    pub fn submit_stop_workspace_durable(
        &self,
        scope: ResolvedWorkspaceScope,
        request: forge_persistence::ExecutionStopRequest,
    ) -> Result<
        PendingApproval<crate::execution_coordinator::OwnedWorkspaceExecutionStopObservation>,
        ForgeApprovalCoordinatorError,
    > {
        self.submit_pending(
            |response| ApprovalCoordinatorRequest::StopWorkspaceDurable {
                scope,
                request: Box::new(request),
                response,
            },
        )
    }

    pub fn stop_workspace_intent(
        &self,
        intent: crate::WorkspaceStopIntent,
    ) -> Result<crate::OwnedWorkspaceExecutionStopObservation, ForgeApprovalCoordinatorError> {
        self.submit_stop_workspace_intent(intent)?.recv()
    }

    pub fn submit_stop_workspace_intent(
        &self,
        intent: crate::WorkspaceStopIntent,
    ) -> Result<
        PendingApproval<crate::OwnedWorkspaceExecutionStopObservation>,
        ForgeApprovalCoordinatorError,
    > {
        self.submit_pending(|response| ApprovalCoordinatorRequest::StopWorkspaceIntent {
            intent: Box::new(intent),
            response,
        })
    }

    pub fn observe_workspace_stop_intent(
        &self,
        intent: crate::WorkspaceStopIntent,
    ) -> Result<
        Option<(
            forge_persistence::ExecutionStopRecord,
            forge_persistence::AuthorityStopReceipt,
        )>,
        ForgeApprovalCoordinatorError,
    > {
        self.submit_observe_workspace_stop_intent(intent)?.recv()
    }

    pub fn submit_observe_workspace_stop_intent(
        &self,
        intent: crate::WorkspaceStopIntent,
    ) -> Result<
        PendingApproval<
            Option<(
                forge_persistence::ExecutionStopRecord,
                forge_persistence::AuthorityStopReceipt,
            )>,
        >,
        ForgeApprovalCoordinatorError,
    > {
        self.submit_pending(
            |response| ApprovalCoordinatorRequest::ObserveWorkspaceStopIntent {
                intent: Box::new(intent),
                response,
            },
        )
    }

    pub fn submit_stop_workspace(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<PendingApproval<usize>, ForgeApprovalCoordinatorError> {
        self.submit_pending(|response| ApprovalCoordinatorRequest::StopWorkspace {
            workspace_id,
            response,
        })
    }

    pub fn stop_activity(
        &self,
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
    ) -> Result<usize, ForgeApprovalCoordinatorError> {
        self.submit(|response| ApprovalCoordinatorRequest::StopActivity {
            workspace_id,
            activity_id,
            response,
        })
    }

    pub fn emergency_stop(&self) -> Result<usize, ForgeApprovalCoordinatorError> {
        self.submit(|response| ApprovalCoordinatorRequest::EmergencyStop { response })
    }

    pub fn submit_emergency_stop(
        &self,
    ) -> Result<PendingApproval<usize>, ForgeApprovalCoordinatorError> {
        self.submit_pending(|response| ApprovalCoordinatorRequest::EmergencyStop { response })
    }

    /// Cancel only this coordinator's exact pending approvals, auto scopes,
    /// and executions while keeping the coordinator available for reads and
    /// later explicit re-enable.
    pub fn stop_owned(
        &self,
    ) -> Result<ForgeApprovalCoordinatorShutdown, ForgeApprovalCoordinatorError> {
        self.submit(|response| ApprovalCoordinatorRequest::StopOwned { response })
    }

    fn submit<T>(
        &self,
        build: impl FnOnce(Response<T>) -> ApprovalCoordinatorRequest,
    ) -> Result<T, ForgeApprovalCoordinatorError> {
        self.submit_pending(build)?.recv()
    }

    fn submit_pending<T>(
        &self,
        build: impl FnOnce(Response<T>) -> ApprovalCoordinatorRequest,
    ) -> Result<PendingApproval<T>, ForgeApprovalCoordinatorError> {
        if !self.accepting.load(Ordering::Acquire) {
            return Err(ForgeApprovalCoordinatorError::Closed);
        }
        let (response_sender, response_receiver) = mpsc::sync_channel(1);
        match self.sender.try_send(build(response_sender)) {
            Ok(()) => Ok(PendingApproval {
                receiver: response_receiver,
            }),
            Err(TrySendError::Full(_)) => Err(ForgeApprovalCoordinatorError::QueueFull),
            Err(TrySendError::Disconnected(_)) => Err(ForgeApprovalCoordinatorError::Closed),
        }
    }
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForgeApprovalCoordinatorShutdown {
    pending_cancelled: usize,
    executions_cancelled: usize,
}

impl ForgeApprovalCoordinatorShutdown {
    pub const fn pending_cancelled(self) -> usize {
        self.pending_cancelled
    }

    pub const fn executions_cancelled(self) -> usize {
        self.executions_cancelled
    }
}

#[derive(Debug)]
pub struct ForgeApprovalCoordinator {
    client: ForgeApprovalCoordinatorClient,
    thread: Option<JoinHandle<()>>,
}

impl ForgeApprovalCoordinator {
    pub fn start(
        control: ForgeControlClient,
        execution: ForgeExecutionCoordinatorClient,
    ) -> Result<Self, ForgeApprovalCoordinatorError> {
        let (sender, receiver) = mpsc::sync_channel(APPROVAL_COORDINATOR_CAPACITY);
        let accepting = Arc::new(AtomicBool::new(true));
        let runtime_accepting = Arc::clone(&accepting);
        let thread = thread::Builder::new()
            .name(THREAD_NAME.to_owned())
            .spawn(move || {
                ApprovalRuntime::new(control, execution, receiver, runtime_accepting).run();
            })
            .map_err(ForgeApprovalCoordinatorError::SpawnThread)?;
        Ok(Self {
            client: ForgeApprovalCoordinatorClient { sender, accepting },
            thread: Some(thread),
        })
    }

    pub fn client(&self) -> ForgeApprovalCoordinatorClient {
        self.client.clone()
    }

    pub fn shutdown(
        &mut self,
    ) -> Result<ForgeApprovalCoordinatorShutdown, ForgeApprovalCoordinatorError> {
        self.client.accepting.store(false, Ordering::Release);
        let Some(thread) = self.thread.take() else {
            return Err(ForgeApprovalCoordinatorError::AlreadyShutdown);
        };
        let (response_sender, response_receiver) = mpsc::sync_channel(0);
        if self
            .client
            .sender
            .send(ApprovalCoordinatorRequest::Shutdown {
                response: response_sender,
            })
            .is_err()
        {
            return match thread.join() {
                Ok(()) => Err(ForgeApprovalCoordinatorError::Closed),
                Err(_) => Err(ForgeApprovalCoordinatorError::ThreadPanicked),
            };
        }
        // A failed shutdown reply still leaves a thread to join. Do not
        // propagate the reply before accounting for the owned worker.
        let report = response_receiver.recv();
        let joined = thread
            .join()
            .map_err(|_| ForgeApprovalCoordinatorError::ThreadPanicked);
        joined?;
        report.map_err(|_| ForgeApprovalCoordinatorError::ResponseDropped)?
    }
}

impl Drop for ForgeApprovalCoordinator {
    fn drop(&mut self) {
        if self.thread.is_some() {
            let _ignored = self.shutdown();
        }
    }
}

#[derive(Debug, Clone)]
struct PendingPayload {
    record: RegisteredApprovalRequest,
    scope: ResolvedWorkspaceScope,
    runtime_instance_id: RuntimeInstanceId,
    request: ExecutionRequest,
    goal: Option<GoalWorkAttribution>,
    agent_authority: Option<AgentExecutionAuthorityRequest>,
    project_command: Option<ProjectCommandEvidence>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingCleanupPhase {
    Apply,
    Observe,
    Settled,
}

#[derive(Debug, Clone)]
struct PendingCleanupBatch {
    plan: ApprovalCleanupPlan,
    phase: PendingCleanupPhase,
}

#[derive(Debug, Clone)]
struct PendingExpiryBatch {
    plan: ApprovalExpiryPlan,
    phase: PendingCleanupPhase,
}

struct ApprovalRuntime {
    control: ForgeControlClient,
    execution: ForgeExecutionCoordinatorClient,
    receiver: Receiver<ApprovalCoordinatorRequest>,
    accepting: Arc<AtomicBool>,
    pending: HashMap<ApprovalRequestId, PendingPayload>,
    auto_scopes: HashMap<AutoApprovalScopeId, AutoApprovalScope>,
    auto_preferences: HashSet<WorkspaceId>,
    known_scopes: HashMap<WorkspaceId, ResolvedWorkspaceScope>,
    cleanup_owner: ApprovalCleanupOwner,
    cleanup_permits: HashMap<WorkspaceId, ApprovalCleanupPermit>,
    pending_cleanup: HashMap<(WorkspaceId, ApprovalCleanupSelector), PendingCleanupBatch>,
    pending_expiry: HashMap<WorkspaceId, PendingExpiryBatch>,
}

impl ApprovalRuntime {
    fn new(
        control: ForgeControlClient,
        execution: ForgeExecutionCoordinatorClient,
        receiver: Receiver<ApprovalCoordinatorRequest>,
        accepting: Arc<AtomicBool>,
    ) -> Self {
        Self {
            control,
            execution,
            receiver,
            accepting,
            pending: HashMap::new(),
            auto_scopes: HashMap::new(),
            auto_preferences: HashSet::new(),
            known_scopes: HashMap::new(),
            cleanup_owner: ApprovalCleanupOwner::new(),
            cleanup_permits: HashMap::new(),
            pending_cleanup: HashMap::new(),
            pending_expiry: HashMap::new(),
        }
    }

    fn run(mut self) {
        while let Ok(request) = self.receiver.recv() {
            match request {
                ApprovalCoordinatorRequest::Shutdown { response } => {
                    self.accepting.store(false, Ordering::Release);
                    let result = self.shutdown_runtime();
                    self.pending.clear();
                    self.auto_scopes.clear();
                    self.auto_preferences.clear();
                    let _ignored = response.send(result);
                    break;
                }
                request => self.handle_request(request),
            }
        }
        self.pending.clear();
        self.auto_scopes.clear();
        self.accepting.store(false, Ordering::Release);
    }

    fn handle_request(&mut self, request: ApprovalCoordinatorRequest) {
        match request {
            ApprovalCoordinatorRequest::StartApproved { request, response } => {
                let result = self.start_approved_agent_execution(*request);
                let _ignored = response.send(result);
            }
            ApprovalCoordinatorRequest::Submit { request, response } => {
                let result = self.submit_execution(*request);
                let _ignored = response.send(result);
            }
            ApprovalCoordinatorRequest::Approve {
                approval_id,
                response,
            } => {
                let result = self.approve(approval_id);
                let _ignored = response.send(result);
            }
            ApprovalCoordinatorRequest::Reject {
                approval_id,
                response,
            } => {
                let result = self.reject(approval_id);
                let _ignored = response.send(result);
            }
            ApprovalCoordinatorRequest::ListPending { scope, response } => {
                let result = self.list_pending(&scope);
                let _ignored = response.send(result);
            }
            ApprovalCoordinatorRequest::RegisterAutoScope { request, response } => {
                let result = self.register_auto_scope(request);
                let _ignored = response.send(result);
            }
            ApprovalCoordinatorRequest::SetAutoApproval {
                scope,
                enabled,
                response,
            } => {
                let result = self.set_auto_approval(&scope, enabled);
                let _ignored = response.send(result);
            }
            ApprovalCoordinatorRequest::AutoApprovalStatus { scope, response } => {
                let result = self.auto_approval_status(&scope);
                let _ignored = response.send(result);
            }
            ApprovalCoordinatorRequest::StopWorkspace {
                workspace_id,
                response,
            } => {
                let result = self.stop_workspace(workspace_id);
                let _ignored = response.send(result);
            }
            ApprovalCoordinatorRequest::StopWorkspaceDurable {
                scope,
                request,
                response,
            } => {
                let result = self.stop_workspace_durable(&scope, *request);
                let _ignored = response.send(result);
            }
            ApprovalCoordinatorRequest::StopWorkspaceIntent { intent, response } => {
                let result = self.stop_workspace_intent(&intent);
                let _ignored = response.send(result);
            }
            ApprovalCoordinatorRequest::ObserveWorkspaceStopIntent { intent, response } => {
                let result = self.observe_workspace_stop_intent(&intent);
                let _ignored = response.send(result);
            }
            ApprovalCoordinatorRequest::StopActivity {
                workspace_id,
                activity_id,
                response,
            } => {
                let result = self.stop_activity(workspace_id, activity_id);
                let _ignored = response.send(result);
            }
            ApprovalCoordinatorRequest::EmergencyStop { response } => {
                let result = self.emergency_stop();
                let _ignored = response.send(result);
            }
            ApprovalCoordinatorRequest::StopOwned { response } => {
                let result = self.stop_owned_runtime();
                let _ignored = response.send(result);
            }
            ApprovalCoordinatorRequest::Shutdown { .. } => {}
        }
    }

    fn submit_execution(
        &mut self,
        submit: SubmitExecutionForApproval,
    ) -> Result<ApprovalSubmission, ForgeApprovalCoordinatorError> {
        let requires_agent_authority =
            requires_agent_authority(submit.action, submit.project_command);
        if requires_agent_authority != submit.agent_authority.is_some() {
            return Err(ForgeApprovalCoordinatorError::AttributionMismatch);
        }
        if !project_command_matches_action(submit.action, submit.project_command) {
            return Err(ForgeApprovalCoordinatorError::AttributionMismatch);
        }
        if submit.request.workspace_id() != submit.scope.workspace_id()
            || submit.request.activity_id() != submit.activity_id
        {
            return Err(ForgeApprovalCoordinatorError::AttributionMismatch);
        }
        self.attach_workspace(&submit.scope)?;
        let observed_at = current_timestamp_millis()?;
        let authorization = ExecutionAuthorizationRequest::new(
            submit.request.id(),
            submit.scope.workspace_id(),
            submit.activity_id,
            execution_request_digest(&submit.request),
            submit.action,
            RequestedExecutionPermissions::new(submit.request.permissions()),
        );
        let agent_binding = approval_agent_binding(
            submit.action,
            submit.agent_authority.as_ref(),
            submit.request.id(),
            submit.project_command,
        );
        if let Some(approval_id) = submit.approval_id
            && let Some(record) = self
                .control
                .approval_get(submit.scope.clone(), approval_id)?
        {
            let (record, joined_execution) = record;
            if !pending_approval_matches_submission(&record, authorization, agent_binding) {
                return Err(ForgeApprovalCoordinatorError::PendingApprovalConflict {
                    approval_id: record.id(),
                    execution_id: authorization.execution_id(),
                });
            }
            return self.submission_from_approval_record(
                submit,
                &record,
                joined_execution.as_ref(),
                authorization,
            );
        }
        let policy = self.control.ensure_workspace_policy(submit.scope.clone())?;
        if submit.action != ExecutionActionClass::GeneratedProjectCommand
            && policy.evaluate(submit.action, authorization.requested())
                == ExecutionPolicyDisposition::AutoEligible
            && let Some(auto_scope) =
                self.find_auto_scope(&submit.scope, authorization, policy.revision(), observed_at)?
        {
            return self.start_auto_execution(
                submit,
                authorization,
                policy.revision(),
                observed_at,
                &auto_scope,
            );
        }
        if self.pending.len() >= MAX_PENDING_PAYLOADS {
            return Err(ForgeApprovalCoordinatorError::PendingCapacity);
        }
        let approval_id = submit
            .approval_id
            .unwrap_or_else(|| ApprovalRequestId::from_uuid(Uuid::now_v7()));
        let expires_at = add_millis(observed_at, APPROVAL_WINDOW_MILLIS)?;
        let record = self
            .control
            .create_pending_approval(ApprovalCreateRequest {
                scope: submit.scope.clone(),
                activity: ApprovalActivityScope {
                    activity_id: submit.activity_id,
                    runtime_instance_id: submit.runtime_instance_id,
                    observed_at,
                },
                goal: submit.goal,
                approval_id,
                request: authorization,
                agent_binding,
                expires_at,
            })?;
        self.submission_from_approval_record(submit, &record, None, authorization)
    }

    fn start_approved_agent_execution(
        &mut self,
        request: crate::ApprovedAgentExecutionRequest,
    ) -> Result<ExecutionStartResult, ForgeApprovalCoordinatorError> {
        let scope = request.scope.clone();
        let authority = request.agent_authority.clone();
        let start = request.into_start_request().map_err(|error| match error {
            ForgeExecutionCoordinatorError::AttributionMismatch => {
                ForgeApprovalCoordinatorError::AttributionMismatch
            }
            other => ForgeApprovalCoordinatorError::Execution(other),
        })?;
        self.control.verify_agent_execution_authority(authority)?;
        // This is a checked mutating submission, following the existing Submit
        // ownership boundary. Passive projections never enter this attachment.
        self.attach_workspace(&scope)?;
        self.execution.start_execution(start).map_err(Into::into)
    }

    fn start_auto_execution(
        &mut self,
        submit: SubmitExecutionForApproval,
        authorization: ExecutionAuthorizationRequest,
        policy_revision: forge_domain::PolicyRevision,
        observed_at: TimestampMillis,
        auto_scope: &AutoApprovalScope,
    ) -> Result<ApprovalSubmission, ForgeApprovalCoordinatorError> {
        let approval_id = submit
            .approval_id
            .unwrap_or_else(|| ApprovalRequestId::from_uuid(Uuid::now_v7()));
        let grant_id = ExecutionGrantId::from_uuid(Uuid::now_v7());
        let predicted = auto_scope
            .consume(
                authorization,
                policy_revision,
                auto_scope.revision(),
                observed_at,
            )
            .map_err(|_| ForgeApprovalCoordinatorError::AutoScopeUnavailable)?;
        let auto_authorization = AutoCoordinatorAuthorization::new(
            auto_scope.id(),
            auto_scope.revision(),
            approval_id,
            grant_id,
        );
        let started = self.execution.start_execution(
            ExecutionCoordinatorStartRequest::new_auto(
                submit.scope,
                submit.activity_id,
                submit.runtime_instance_id,
                auto_authorization,
                authorization,
                submit.request,
            )
            .with_goal(submit.goal)
            .with_agent_authority(submit.agent_authority)
            .with_project_command(submit.project_command),
        )?;
        let status = match started.disposition() {
            ExecutionStartDisposition::Created => {
                self.auto_scopes.insert(predicted.id(), predicted);
                ApprovalSubmissionStatus::Started
            }
            ExecutionStartDisposition::Existing => ApprovalSubmissionStatus::Existing,
        };
        Ok(ApprovalSubmission {
            status,
            approval_id,
            execution_id: started.id(),
        })
    }

    fn submission_from_approval_record(
        &mut self,
        submit: SubmitExecutionForApproval,
        record: &RegisteredApprovalRequest,
        joined_execution: Option<&forge_domain::RegisteredExecution>,
        authorization: ExecutionAuthorizationRequest,
    ) -> Result<ApprovalSubmission, ForgeApprovalCoordinatorError> {
        let status = match record.state() {
            ApprovalRequestState::Pending => {
                if self.pending.len() >= MAX_PENDING_PAYLOADS
                    && !self.pending.contains_key(&record.id())
                {
                    return Err(ForgeApprovalCoordinatorError::PendingCapacity);
                }
                self.pending.insert(
                    record.id(),
                    PendingPayload {
                        record: record.clone(),
                        scope: submit.scope,
                        runtime_instance_id: submit.runtime_instance_id,
                        request: submit.request,
                        goal: submit.goal,
                        agent_authority: submit.agent_authority,
                        project_command: submit.project_command,
                    },
                );
                ApprovalSubmissionStatus::Pending
            }
            ApprovalRequestState::Approved | ApprovalRequestState::AutoApproved => {
                let execution = joined_execution.ok_or(
                    ForgeApprovalCoordinatorError::PendingApprovalExecutionMissing {
                        approval_id: record.id(),
                        execution_id: authorization.execution_id(),
                    },
                )?;
                if !execution_matches_submission(execution, &submit, authorization) {
                    return Err(ForgeApprovalCoordinatorError::ExistingExecutionConflict {
                        execution_id: authorization.execution_id(),
                    });
                }
                ApprovalSubmissionStatus::Existing
            }
            ApprovalRequestState::Denied
            | ApprovalRequestState::Rejected
            | ApprovalRequestState::Cancelled
            | ApprovalRequestState::Expired
            | ApprovalRequestState::Superseded => ApprovalSubmissionStatus::Denied,
        };
        Ok(ApprovalSubmission {
            status,
            approval_id: record.id(),
            execution_id: authorization.execution_id(),
        })
    }

    fn approve(
        &mut self,
        approval_id: ApprovalRequestId,
    ) -> Result<ExecutionId, ForgeApprovalCoordinatorError> {
        let payload = self
            .pending
            .get(&approval_id)
            .cloned()
            .ok_or(ForgeApprovalCoordinatorError::PendingPayloadMissing)?;
        let observed_at = current_timestamp_millis()?;
        let grant_id = ExecutionGrantId::from_uuid(Uuid::now_v7());
        let (_approved, grant) = self.control.approve_once(ApprovalOnceRequest {
            scope: payload.scope.clone(),
            approval_id,
            expected_revision: payload.record.revision(),
            grant_id,
            observed_at,
            grant_expires_at: add_millis(observed_at, GRANT_WINDOW_MILLIS)?,
        })?;
        self.pending.remove(&approval_id);
        self.execution
            .start_execution(
                ExecutionCoordinatorStartRequest::new_explicit(
                    payload.scope,
                    payload.record.request().activity_id(),
                    payload.runtime_instance_id,
                    grant.id(),
                    grant.revision(),
                    payload.record.request(),
                    payload.request,
                )
                .with_goal(payload.goal)
                .with_agent_authority(payload.agent_authority)
                .with_project_command(payload.project_command),
            )
            .map_err(ForgeApprovalCoordinatorError::from)
            .map(ExecutionStartResult::id)
    }

    fn reject(
        &mut self,
        approval_id: ApprovalRequestId,
    ) -> Result<RegisteredApprovalRequest, ForgeApprovalCoordinatorError> {
        let payload = self
            .pending
            .get(&approval_id)
            .cloned()
            .ok_or(ForgeApprovalCoordinatorError::PendingPayloadMissing)?;
        let record = self
            .control
            .decide_pending_approval(ApprovalDecisionRequest {
                scope: payload.scope,
                approval_id,
                decision: ApprovalDecision::Reject,
                expected_revision: payload.record.revision(),
                observed_at: current_timestamp_millis()?,
            })?;
        self.pending.remove(&approval_id);
        Ok(record)
    }

    fn list_pending(
        &mut self,
        scope: &ResolvedWorkspaceScope,
    ) -> Result<Vec<PendingApprovalProjection>, ForgeApprovalCoordinatorError> {
        let observed_at = current_timestamp_millis()?;
        self.drive_expiry_page(scope, observed_at)?;
        self.pending
            .retain(|_, payload| payload.record.expires_at().get() > observed_at.get());
        let records = self
            .control
            .list_pending_approvals(scope.clone(), approval_limit()?)?;
        Ok(records
            .iter()
            .map(|record| {
                PendingApprovalProjection::from_record(
                    record,
                    self.pending.contains_key(&record.id()),
                )
            })
            .collect())
    }

    fn drive_expiry_page(
        &mut self,
        scope: &ResolvedWorkspaceScope,
        observed_at: TimestampMillis,
    ) -> Result<(), ForgeApprovalCoordinatorError> {
        let workspace_id = scope.workspace_id();
        if self
            .pending_cleanup
            .keys()
            .any(|(owned_workspace, _)| *owned_workspace == workspace_id)
        {
            return Err(ForgeApprovalCoordinatorError::CleanupIncomplete);
        }
        for _ in 0..=CLEANUP_ROUNDS {
            let (plan, phase) = self.ensure_expiry_batch(scope, observed_at)?;
            if plan.persistence().is_empty() {
                self.pending_expiry.remove(&workspace_id);
                return Ok(());
            }
            if phase == PendingCleanupPhase::Settled {
                // A list operation advances at most one settled page. The
                // next listing prepares the next bounded expiry page.
                return Ok(());
            }
            if phase == PendingCleanupPhase::Apply {
                let attempt = ApprovalCleanupAttemptId::from_uuid(Uuid::now_v7());
                let applied = self
                    .control
                    .apply_approval_expiry_plan(plan.clone(), attempt);
                if let Ok(ApprovalCleanupApplyOutcome::RejectedBeforeWrite(rejection)) = &applied {
                    if rejection.matches(plan.persistence(), attempt) {
                        self.pending_expiry.remove(&workspace_id);
                        continue;
                    }
                    if let Some(batch) = self.pending_expiry.get_mut(&workspace_id) {
                        batch.phase = PendingCleanupPhase::Observe;
                    }
                    return Err(ForgeApprovalCoordinatorError::CleanupIncomplete);
                }
                let apply_requires_observe = self
                    .pending_expiry
                    .get_mut(&workspace_id)
                    .is_some_and(|batch| {
                        cleanup_apply_phase_transition(&mut batch.phase, &applied)
                    });
                if !apply_requires_observe && let Err(error) = applied {
                    return Err(error.into());
                }
            }
            let readback = self.control.observe_approval_expiry_plan(plan.clone());
            let disposition = {
                let Some(batch) = self.pending_expiry.get_mut(&workspace_id) else {
                    return Err(ForgeApprovalCoordinatorError::InternalInvariant);
                };
                cleanup_observe_phase_transition(&mut batch.phase, readback)?
            };
            match disposition {
                CleanupReadbackDisposition::Settled => {
                    if !plan.persistence().has_more() {
                        self.pending_expiry.remove(&workspace_id);
                    }
                    return Ok(());
                }
                CleanupReadbackDisposition::Absent => {}
            }
        }
        Err(ForgeApprovalCoordinatorError::CleanupIncomplete)
    }

    fn ensure_expiry_batch(
        &mut self,
        scope: &ResolvedWorkspaceScope,
        observed_at: TimestampMillis,
    ) -> Result<(ApprovalExpiryPlan, PendingCleanupPhase), ForgeApprovalCoordinatorError> {
        let workspace_id = scope.workspace_id();
        if let Some(batch) = self.pending_expiry.get(&workspace_id)
            && batch.plan.scope() != scope
            && batch.phase != PendingCleanupPhase::Settled
        {
            return Err(ForgeApprovalCoordinatorError::Control(
                ControlClientError::Service(crate::ControlError::new(
                    crate::ControlErrorCode::WorkspaceRevisionConflict,
                )),
            ));
        }
        if self.pending_expiry.get(&workspace_id).is_some_and(|batch| {
            batch.plan.scope() != scope && batch.phase == PendingCleanupPhase::Settled
        }) {
            self.pending_expiry.remove(&workspace_id);
        }
        if let Some(batch) = self.pending_expiry.get(&workspace_id)
            && batch.phase != PendingCleanupPhase::Settled
        {
            return Ok((batch.plan.clone(), batch.phase));
        }
        if !self.pending_expiry.contains_key(&workspace_id)
            && self
                .pending_cleanup
                .len()
                .saturating_add(self.pending_expiry.len())
                >= MAX_AUTO_SCOPES
        {
            return Err(ForgeApprovalCoordinatorError::AutoScopeCapacity);
        }
        let plan = self.control.prepare_approval_expiry_plan(
            scope.clone(),
            observed_at,
            approval_limit()?,
        )?;
        self.pending_expiry.insert(
            workspace_id,
            PendingExpiryBatch {
                plan: plan.clone(),
                phase: PendingCleanupPhase::Apply,
            },
        );
        Ok((plan, PendingCleanupPhase::Apply))
    }

    fn settle_expiry_for_workspace(
        &mut self,
        workspace_id: WorkspaceId,
    ) -> Result<(), ForgeApprovalCoordinatorError> {
        let Some(batch) = self.pending_expiry.get(&workspace_id).cloned() else {
            return Ok(());
        };
        let readback = self
            .control
            .observe_approval_expiry_plan(batch.plan.clone());
        let disposition = {
            let Some(current) = self.pending_expiry.get_mut(&workspace_id) else {
                return Err(ForgeApprovalCoordinatorError::InternalInvariant);
            };
            cleanup_observe_phase_transition(&mut current.phase, readback)?
        };
        match disposition {
            CleanupReadbackDisposition::Settled | CleanupReadbackDisposition::Absent => {
                self.pending_expiry.remove(&workspace_id);
                Ok(())
            }
        }
    }

    fn settle_all_expiry(&mut self) -> Result<(), ForgeApprovalCoordinatorError> {
        let workspaces: Vec<_> = self.pending_expiry.keys().copied().collect();
        let mut first_error = None;
        for workspace_id in workspaces {
            if let Err(error) = self.settle_expiry_for_workspace(workspace_id)
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    fn register_auto_scope(
        &mut self,
        request: AutoApprovalScopeCreateRequest,
    ) -> Result<AutoApprovalScope, ForgeApprovalCoordinatorError> {
        if self.auto_scopes.len() >= MAX_AUTO_SCOPES
            && !self.auto_scopes.contains_key(&request.auto_scope.id())
        {
            return Err(ForgeApprovalCoordinatorError::AutoScopeCapacity);
        }
        self.attach_workspace(&request.scope)?;
        let scope = self.control.create_auto_approval_scope(request)?;
        self.auto_scopes.insert(scope.id(), scope.clone());
        Ok(scope)
    }

    fn set_auto_approval(
        &mut self,
        scope: &ResolvedWorkspaceScope,
        enabled: bool,
    ) -> Result<bool, ForgeApprovalCoordinatorError> {
        self.attach_workspace(scope)?;
        let workspace_id = scope.workspace_id();
        let observed_at = current_timestamp_millis()?;
        if !enabled {
            self.auto_preferences.remove(&workspace_id);
            self.revoke_owned_auto_scopes(scope, observed_at)?;
            self.auto_scopes
                .retain(|_, value| value.workspace_id() != workspace_id);
            return Ok(false);
        }
        self.auto_preferences.insert(workspace_id);
        let mut created_scope_ids = Vec::new();
        for action in [
            ExecutionActionClass::DiscoveredProjectCommand,
            ExecutionActionClass::AnalyzedShell,
        ] {
            let existing_ids: HashSet<_> = self.auto_scopes.keys().copied().collect();
            match self.ensure_auto_scope(scope.to_owned(), action, observed_at) {
                Ok(Some(auto_scope)) if !existing_ids.contains(&auto_scope.id()) => {
                    created_scope_ids.push(auto_scope.id());
                }
                Ok(_) => {}
                Err(error) => {
                    if let Err(rollback_error) =
                        self.revoke_auto_scope_ids(scope, &created_scope_ids, observed_at)
                    {
                        self.auto_preferences.remove(&workspace_id);
                        return Err(rollback_error);
                    }
                    self.auto_preferences.remove(&workspace_id);
                    return Err(error);
                }
            }
        }
        Ok(true)
    }

    fn auto_approval_status(
        &mut self,
        scope: &ResolvedWorkspaceScope,
    ) -> Result<AutoApprovalStatus, ForgeApprovalCoordinatorError> {
        if !self.auto_preferences.contains(&scope.workspace_id()) {
            return Ok(AutoApprovalStatus::disabled());
        }
        let observed_at = current_timestamp_millis()?;
        let policy_revision = self
            .control
            .get_workspace_policy(scope.clone())?
            .map(|policy| policy.revision());
        let commands = self.auto_approval_action_status(
            scope,
            ExecutionActionClass::DiscoveredProjectCommand,
            observed_at,
            policy_revision,
        )?;
        let shell = self.auto_approval_action_status(
            scope,
            ExecutionActionClass::AnalyzedShell,
            observed_at,
            policy_revision,
        )?;
        Ok(AutoApprovalStatus::for_scopes(true, commands, shell))
    }

    fn auto_approval_action_status(
        &mut self,
        scope: &ResolvedWorkspaceScope,
        action: ExecutionActionClass,
        observed_at: TimestampMillis,
        policy_revision: Option<forge_domain::PolicyRevision>,
    ) -> Result<AutoApprovalActionStatus, ForgeApprovalCoordinatorError> {
        let candidate = self
            .refresh_owned_auto_scopes(scope, action)?
            .into_iter()
            .next();
        Ok(candidate.map_or_else(
            || AutoApprovalActionStatus::unavailable(action),
            |scope| AutoApprovalActionStatus::from_scope(&scope, observed_at, policy_revision),
        ))
    }

    fn ensure_auto_scope(
        &mut self,
        scope: ResolvedWorkspaceScope,
        action: ExecutionActionClass,
        observed_at: TimestampMillis,
    ) -> Result<Option<AutoApprovalScope>, ForgeApprovalCoordinatorError> {
        let workspace_id = scope.workspace_id();
        if !self.auto_preferences.contains(&workspace_id) {
            return Ok(None);
        }
        if !matches!(
            action,
            ExecutionActionClass::DiscoveredProjectCommand | ExecutionActionClass::AnalyzedShell
        ) {
            return Ok(None);
        }
        let policy = self.control.ensure_workspace_policy(scope.clone())?;
        let permission_ceiling = ExecutionPermissions::new(true, false, false);
        let cached_scopes = self.refresh_owned_auto_scopes(&scope, action)?;
        if let Some(auto_scope) = cached_scopes.into_iter().find(|candidate| {
            candidate.activity_id().is_none()
                && candidate.permission_ceiling() == permission_ceiling
                && candidate.policy_revision() == policy.revision()
                && candidate.state() == AutoApprovalScopeState::Active
                && candidate
                    .max_uses()
                    .permits(u64::from(candidate.used_count()))
                && observed_at.get() < candidate.expires_at().get()
        }) {
            return Ok(Some(auto_scope));
        }
        self.auto_scopes.retain(|_, candidate| {
            candidate.workspace_id() != workspace_id || candidate.action() != action
        });
        if self.auto_scopes.len() >= MAX_AUTO_SCOPES {
            return Err(ForgeApprovalCoordinatorError::AutoScopeCapacity);
        }
        let auto_scope = AutoApprovalScope::active(
            AutoApprovalScopeId::from_uuid(Uuid::now_v7()),
            workspace_id,
            None,
            action,
            permission_ceiling,
            policy.revision(),
            add_millis(observed_at, APPROVAL_WINDOW_MILLIS)?,
            AutoApprovalUseLimit::unlimited(),
            AutoApprovalScopeRevision::INITIAL,
        )
        .map_err(|_| ForgeApprovalCoordinatorError::InternalInvariant)?;
        let registered =
            self.control
                .create_auto_approval_scope(AutoApprovalScopeCreateRequest {
                    scope,
                    auto_scope,
                    created_at: observed_at,
                })?;
        self.auto_scopes.insert(registered.id(), registered.clone());
        Ok(Some(registered))
    }

    fn find_auto_scope(
        &mut self,
        scope: &ResolvedWorkspaceScope,
        request: ExecutionAuthorizationRequest,
        policy_revision: forge_domain::PolicyRevision,
        observed_at: TimestampMillis,
    ) -> Result<Option<AutoApprovalScope>, ForgeApprovalCoordinatorError> {
        if !self.auto_preferences.contains(&scope.workspace_id()) {
            return Ok(None);
        }
        let ids: Vec<_> = self
            .auto_scopes
            .values()
            .filter(|candidate| {
                candidate.workspace_id() == scope.workspace_id()
                    && candidate.activity_id().is_none()
                    && candidate.action() == request.action()
            })
            .map(AutoApprovalScope::id)
            .collect();
        for id in ids {
            let Some(durable) = self.control.get_auto_approval_scope(scope.clone(), id)? else {
                self.auto_scopes.remove(&id);
                continue;
            };
            if durable.workspace_id() != scope.workspace_id()
                || durable.activity_id().is_some()
                || durable.action() != request.action()
            {
                self.auto_scopes.remove(&id);
                continue;
            }
            self.auto_scopes.insert(id, durable.clone());
            if durable.covers(request, policy_revision, observed_at) {
                return Ok(Some(durable));
            }
        }
        Ok(None)
    }

    fn refresh_owned_auto_scopes(
        &mut self,
        scope: &ResolvedWorkspaceScope,
        action: ExecutionActionClass,
    ) -> Result<Vec<AutoApprovalScope>, ForgeApprovalCoordinatorError> {
        let ids: Vec<_> = self
            .auto_scopes
            .values()
            .filter(|candidate| {
                candidate.workspace_id() == scope.workspace_id()
                    && candidate.activity_id().is_none()
                    && candidate.action() == action
            })
            .map(AutoApprovalScope::id)
            .collect();
        let mut refreshed = Vec::with_capacity(ids.len());
        for id in ids {
            let Some(durable) = self.control.get_auto_approval_scope(scope.clone(), id)? else {
                self.auto_scopes.remove(&id);
                continue;
            };
            if durable.workspace_id() != scope.workspace_id()
                || durable.activity_id().is_some()
                || durable.action() != action
            {
                self.auto_scopes.remove(&id);
                continue;
            }
            self.auto_scopes.insert(id, durable.clone());
            refreshed.push(durable);
        }
        Ok(refreshed)
    }

    fn revoke_owned_auto_scopes(
        &mut self,
        scope: &ResolvedWorkspaceScope,
        observed_at: TimestampMillis,
    ) -> Result<(), ForgeApprovalCoordinatorError> {
        let ids: Vec<_> = self
            .auto_scopes
            .values()
            .filter(|candidate| candidate.workspace_id() == scope.workspace_id())
            .map(AutoApprovalScope::id)
            .collect();
        self.revoke_auto_scope_ids(scope, &ids, observed_at)
    }

    fn revoke_auto_scope_ids(
        &mut self,
        scope: &ResolvedWorkspaceScope,
        ids: &[AutoApprovalScopeId],
        observed_at: TimestampMillis,
    ) -> Result<(), ForgeApprovalCoordinatorError> {
        for id in ids {
            let Some(durable) = self.control.get_auto_approval_scope(scope.clone(), *id)? else {
                self.auto_scopes.remove(id);
                continue;
            };
            if durable.state() != AutoApprovalScopeState::Active {
                self.auto_scopes.remove(id);
                continue;
            }
            let result = self
                .control
                .revoke_auto_approval_scope(AutoApprovalScopeRevokeRequest {
                    scope: scope.clone(),
                    auto_scope_id: *id,
                    expected_revision: durable.revision(),
                    observed_at,
                });
            match result {
                Ok(_) => {}
                Err(error) => {
                    let settled = self
                        .control
                        .get_auto_approval_scope(scope.clone(), *id)?
                        .is_none_or(|latest| latest.state() != AutoApprovalScopeState::Active);
                    if !settled {
                        return Err(error.into());
                    }
                }
            }
            self.auto_scopes.remove(id);
        }
        Ok(())
    }

    fn shutdown_approval_phases(&mut self) -> Result<usize, ForgeApprovalCoordinatorError> {
        let observed_at = current_timestamp_millis()?;
        let scopes: Vec<_> = self.known_scopes.values().cloned().collect();
        let mut pending_cancelled = 0_usize;
        let mut first_error = self.settle_all_expiry().err();
        for scope in scopes {
            match self.cleanup_selector(
                scope.workspace_id(),
                ApprovalCleanupSelector::Workspace,
                observed_at,
            ) {
                Ok(cancelled) => pending_cancelled = pending_cancelled.saturating_add(cancelled),
                Err(error) if first_error.is_none() => first_error = Some(error),
                Err(_) => {}
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(pending_cancelled),
        }
    }

    fn shutdown_runtime(
        &mut self,
    ) -> Result<ForgeApprovalCoordinatorShutdown, ForgeApprovalCoordinatorError> {
        let cleanup = self.shutdown_approval_phases();
        // Native stop is an independent phase. In particular, an approval
        // read/decision/revocation failure must not prevent execution stop.
        let execution = self.execution.stop_all();
        combine_shutdown_phases(cleanup, execution)
    }

    fn stop_owned_runtime(
        &mut self,
    ) -> Result<ForgeApprovalCoordinatorShutdown, ForgeApprovalCoordinatorError> {
        let report = self.shutdown_runtime()?;
        self.pending.clear();
        self.auto_scopes.clear();
        // Keep the process-local preference intent. A later status remains
        // inactive until an explicit re-enable creates a fresh scope.
        Ok(report)
    }

    fn attach_workspace(
        &mut self,
        scope: &ResolvedWorkspaceScope,
    ) -> Result<(), ForgeApprovalCoordinatorError> {
        self.release_settled_expiry(scope.workspace_id());
        if self
            .pending_cleanup
            .keys()
            .any(|(workspace_id, _)| *workspace_id == scope.workspace_id())
            || self.pending_expiry.contains_key(&scope.workspace_id())
        {
            return Err(ForgeApprovalCoordinatorError::Control(
                ControlClientError::Service(crate::ControlError::new(
                    crate::ControlErrorCode::WorkspaceRevisionConflict,
                )),
            ));
        }
        if let Some(known) = self.known_scopes.get(&scope.workspace_id())
            && known == scope
            && self.cleanup_permits.contains_key(&scope.workspace_id())
        {
            return Ok(());
        }
        if self.known_scopes.len() >= MAX_AUTO_SCOPES
            && !self.known_scopes.contains_key(&scope.workspace_id())
        {
            return Err(ForgeApprovalCoordinatorError::AutoScopeCapacity);
        }
        let permit = self.control.mint_approval_cleanup_permit(
            self.cleanup_owner,
            scope.clone(),
            ApprovalCleanupSelector::Workspace,
        )?;
        self.known_scopes
            .insert(scope.workspace_id(), scope.clone());
        self.cleanup_permits.insert(scope.workspace_id(), permit);
        Ok(())
    }

    fn cleanup_selector(
        &mut self,
        workspace_id: WorkspaceId,
        selector: ApprovalCleanupSelector,
        observed_at: TimestampMillis,
    ) -> Result<usize, ForgeApprovalCoordinatorError> {
        self.release_settled_expiry(workspace_id);
        let permit = self
            .cleanup_permits
            .get(&workspace_id)
            .cloned()
            .ok_or(ForgeApprovalCoordinatorError::AutoScopeUnavailable)?;
        let key = (workspace_id, selector);
        if self
            .pending_cleanup
            .iter()
            .any(|((owned_workspace, owned_selector), _)| {
                *owned_workspace == workspace_id && *owned_selector != selector
            })
            || self.pending_expiry.contains_key(&workspace_id)
        {
            return Err(ForgeApprovalCoordinatorError::CleanupIncomplete);
        }
        let mut approvals_settled = 0_usize;
        for _ in 0..=CLEANUP_ROUNDS {
            let (plan, phase) = self.ensure_cleanup_batch(&permit, key, selector, observed_at)?;

            if plan.persistence().is_empty() {
                self.pending_cleanup.remove(&key);
                return Ok(approvals_settled);
            }

            if phase == PendingCleanupPhase::Apply {
                let attempt = ApprovalCleanupAttemptId::from_uuid(Uuid::now_v7());
                let applied = self.control.apply_approval_cleanup_plan(
                    self.cleanup_owner,
                    plan.clone(),
                    attempt,
                );
                let proof_mismatch = matches!(
                    &applied,
                    Ok(ApprovalCleanupApplyOutcome::RejectedBeforeWrite(rejection))
                        if !rejection.matches(plan.persistence(), attempt)
                );
                let apply_requires_observe =
                    self.pending_cleanup.get_mut(&key).is_some_and(|batch| {
                        cleanup_apply_phase_transition(&mut batch.phase, &applied)
                    });
                if proof_mismatch {
                    return Err(ForgeApprovalCoordinatorError::CleanupIncomplete);
                }
                if !apply_requires_observe && let Err(error) = applied {
                    return Err(error.into());
                }
            }

            let readback = self
                .control
                .observe_approval_cleanup_plan(self.cleanup_owner, plan.clone());
            let disposition = {
                let Some(batch) = self.pending_cleanup.get_mut(&key) else {
                    return Err(ForgeApprovalCoordinatorError::InternalInvariant);
                };
                cleanup_observe_phase_transition(&mut batch.phase, readback)?
            };
            match disposition {
                CleanupReadbackDisposition::Settled => {
                    approvals_settled =
                        approvals_settled.saturating_add(plan.persistence().report().approvals());
                    if !plan.persistence().has_more() {
                        self.pending_cleanup.remove(&key);
                        return Ok(approvals_settled);
                    }
                }
                CleanupReadbackDisposition::Absent => {}
            }
        }
        Err(ForgeApprovalCoordinatorError::CleanupIncomplete)
    }

    fn release_settled_expiry(&mut self, workspace_id: WorkspaceId) {
        if self
            .pending_expiry
            .get(&workspace_id)
            .is_some_and(|batch| batch.phase == PendingCleanupPhase::Settled)
        {
            self.pending_expiry.remove(&workspace_id);
        }
    }

    fn ensure_cleanup_batch(
        &mut self,
        permit: &ApprovalCleanupPermit,
        key: (WorkspaceId, ApprovalCleanupSelector),
        selector: ApprovalCleanupSelector,
        observed_at: TimestampMillis,
    ) -> Result<(ApprovalCleanupPlan, PendingCleanupPhase), ForgeApprovalCoordinatorError> {
        if let Some(batch) = self.pending_cleanup.get(&key)
            && batch.phase != PendingCleanupPhase::Settled
        {
            return Ok((batch.plan.clone(), batch.phase));
        }
        if !self.pending_cleanup.contains_key(&key)
            && self
                .pending_cleanup
                .len()
                .saturating_add(self.pending_expiry.len())
                >= MAX_AUTO_SCOPES
        {
            return Err(ForgeApprovalCoordinatorError::AutoScopeCapacity);
        }
        let plan = self.control.prepare_approval_cleanup_plan(
            permit.clone(),
            self.cleanup_owner,
            selector,
            observed_at,
            approval_limit()?,
        )?;
        self.pending_cleanup.insert(
            key,
            PendingCleanupBatch {
                plan: plan.clone(),
                phase: PendingCleanupPhase::Apply,
            },
        );
        Ok((plan, PendingCleanupPhase::Apply))
    }

    fn owned_stop_permit(
        &self,
        scope: &ResolvedWorkspaceScope,
    ) -> Result<ApprovalCleanupPermit, ForgeApprovalCoordinatorError> {
        if self.known_scopes.get(&scope.workspace_id()) != Some(scope) {
            return Err(ForgeApprovalCoordinatorError::AttributionMismatch);
        }
        let permit = self
            .cleanup_permits
            .get(&scope.workspace_id())
            .ok_or(ForgeApprovalCoordinatorError::AttributionMismatch)?;
        if permit.scope() != scope {
            return Err(ForgeApprovalCoordinatorError::AttributionMismatch);
        }
        Ok(permit.clone())
    }

    fn validate_workspace_stop_intent(
        &self,
        intent: &crate::WorkspaceStopIntent,
    ) -> Result<ApprovalCleanupPermit, ForgeApprovalCoordinatorError> {
        let permit = self.owned_stop_permit(intent.scope())?;
        // Provider resolution verifies logical identity, not Workspace permission.
        // The original owner/permit above is the administrative authority.
        let _session = self
            .control
            .agent_session_resolve(crate::AgentSessionResolveRequest {
                session_id: intent.session_id(),
                principal: intent.principal(),
            })
            .map_err(ForgeApprovalCoordinatorError::WorkspaceStopValidation)?;
        Ok(permit)
    }

    fn stop_workspace_intent(
        &mut self,
        intent: &crate::WorkspaceStopIntent,
    ) -> Result<crate::OwnedWorkspaceExecutionStopObservation, ForgeApprovalCoordinatorError> {
        let _permit = self.validate_workspace_stop_intent(intent)?;
        let request = intent.execution_request(current_timestamp_millis()?);
        self.stop_workspace_durable(intent.scope(), request)
    }

    fn observe_workspace_stop_intent(
        &self,
        intent: &crate::WorkspaceStopIntent,
    ) -> Result<
        Option<(
            forge_persistence::ExecutionStopRecord,
            forge_persistence::AuthorityStopReceipt,
        )>,
        ForgeApprovalCoordinatorError,
    > {
        let permit = self.validate_workspace_stop_intent(intent)?;
        let request = intent.execution_request(current_timestamp_millis()?);
        let context = self.control.prepare_owned_execution_stop_context(
            permit,
            self.cleanup_owner,
            request,
        )?;
        self.control
            .observe_owned_execution_stop_context(context)
            .map_err(Into::into)
    }

    fn stop_workspace_durable(
        &mut self,
        scope: &ResolvedWorkspaceScope,
        request: forge_persistence::ExecutionStopRequest,
    ) -> Result<
        crate::execution_coordinator::OwnedWorkspaceExecutionStopObservation,
        ForgeApprovalCoordinatorError,
    > {
        let workspace_id = scope.workspace_id();
        if request.workspace_id() != workspace_id
            || self.known_scopes.get(&workspace_id) != Some(scope)
        {
            return Err(ForgeApprovalCoordinatorError::AttributionMismatch);
        }
        // Do not replace an unresolved cleanup/expiry cohort with a new stop.
        if self
            .pending_cleanup
            .keys()
            .any(|(id, _)| *id == workspace_id)
            || self.pending_expiry.contains_key(&workspace_id)
        {
            return Err(ForgeApprovalCoordinatorError::CleanupIncomplete);
        }
        let permit = self.owned_stop_permit(scope)?;
        let observation =
            self.execution
                .stop_owned_workspace_durable(permit, self.cleanup_owner, request)?;
        // The validated authority receipt permits removing transient payloads;
        // keep original ownership for exact replay and unresolved native closure.
        self.auto_preferences.remove(&workspace_id);
        self.pending
            .retain(|_, payload| payload.scope.workspace_id() != workspace_id);
        self.auto_scopes
            .retain(|_, scope| scope.workspace_id() != workspace_id);
        Ok(observation)
    }

    fn stop_workspace(
        &mut self,
        workspace_id: WorkspaceId,
    ) -> Result<usize, ForgeApprovalCoordinatorError> {
        let pending_before = self.pending.len();
        let observed_at = current_timestamp_millis()?;
        let cleanup = match self.settle_expiry_for_workspace(workspace_id) {
            Ok(()) => self
                .known_scopes
                .get(&workspace_id)
                .cloned()
                .map_or(Ok(0), |_| {
                    self.cleanup_selector(
                        workspace_id,
                        ApprovalCleanupSelector::Workspace,
                        observed_at,
                    )
                }),
            Err(error) => Err(error),
        };
        let execution = self.execution.stop_workspace(workspace_id);
        match (cleanup, execution) {
            (Ok(_), Ok(executions)) => {
                self.auto_preferences.remove(&workspace_id);
                self.pending
                    .retain(|_, payload| payload.scope.workspace_id() != workspace_id);
                self.auto_scopes
                    .retain(|_, scope| scope.workspace_id() != workspace_id);
                self.pending_cleanup
                    .retain(|(owned_workspace, _), _| *owned_workspace != workspace_id);
                self.cleanup_permits.remove(&workspace_id);
                self.known_scopes.remove(&workspace_id);
                Ok(pending_before - self.pending.len() + executions)
            }
            (Err(cleanup), Ok(_)) => Err(cleanup),
            (Ok(_), Err(execution)) => Err(ForgeApprovalCoordinatorError::Execution(execution)),
            (Err(cleanup), Err(execution)) => {
                Err(ForgeApprovalCoordinatorError::ApprovalCleanupAndExecution {
                    cleanup: Box::new(cleanup),
                    execution: Box::new(execution),
                })
            }
        }
    }

    fn stop_activity(
        &mut self,
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
    ) -> Result<usize, ForgeApprovalCoordinatorError> {
        let pending_before = self.pending.len();
        let observed_at = current_timestamp_millis()?;
        let cleanup = match self.settle_expiry_for_workspace(workspace_id) {
            Ok(()) => self
                .known_scopes
                .get(&workspace_id)
                .cloned()
                .map_or(Ok(0), |_| {
                    self.cleanup_selector(
                        workspace_id,
                        ApprovalCleanupSelector::Activity(activity_id),
                        observed_at,
                    )
                }),
            Err(error) => Err(error),
        };
        let execution = self.execution.stop_activity(workspace_id, activity_id);
        match (cleanup, execution) {
            (Ok(_), Ok(executions)) => {
                self.pending.retain(|_, payload| {
                    payload.scope.workspace_id() != workspace_id
                        || payload.record.request().activity_id() != activity_id
                });
                self.auto_scopes.retain(|_, scope| {
                    scope.workspace_id() != workspace_id || scope.activity_id() != Some(activity_id)
                });
                self.pending_cleanup
                    .remove(&(workspace_id, ApprovalCleanupSelector::Activity(activity_id)));
                Ok(pending_before - self.pending.len() + executions)
            }
            (Err(cleanup), Ok(_)) => Err(cleanup),
            (Ok(_), Err(execution)) => Err(ForgeApprovalCoordinatorError::Execution(execution)),
            (Err(cleanup), Err(execution)) => {
                Err(ForgeApprovalCoordinatorError::ApprovalCleanupAndExecution {
                    cleanup: Box::new(cleanup),
                    execution: Box::new(execution),
                })
            }
        }
    }

    fn emergency_stop(&mut self) -> Result<usize, ForgeApprovalCoordinatorError> {
        let pending = self.pending.len();
        let scopes: Vec<_> = self.known_scopes.values().cloned().collect();
        let observed_at = current_timestamp_millis()?;
        let mut cleanup_error = self.settle_all_expiry().err();
        for scope in scopes {
            if let Err(error) = self.cleanup_selector(
                scope.workspace_id(),
                ApprovalCleanupSelector::Workspace,
                observed_at,
            ) && cleanup_error.is_none()
            {
                cleanup_error = Some(error);
            }
        }
        let execution = self.execution.stop_all();
        match (cleanup_error, execution) {
            (None, Ok(executions)) => {
                self.pending.clear();
                self.auto_scopes.clear();
                self.auto_preferences.clear();
                self.pending_cleanup.clear();
                Ok(pending + executions)
            }
            (Some(cleanup), Ok(_)) => Err(cleanup),
            (None, Err(execution)) => Err(ForgeApprovalCoordinatorError::Execution(execution)),
            (Some(cleanup), Err(execution)) => {
                Err(ForgeApprovalCoordinatorError::ApprovalCleanupAndExecution {
                    cleanup: Box::new(cleanup),
                    execution: Box::new(execution),
                })
            }
        }
    }
}

fn execution_matches_submission(
    execution: &forge_domain::RegisteredExecution,
    submit: &SubmitExecutionForApproval,
    authorization: ExecutionAuthorizationRequest,
) -> bool {
    let provenance_matches = execution.provenance()
        == provenance_for_submission(
            submit.agent_authority.as_ref(),
            execution.id(),
            submit.project_command,
        )
        .as_ref();
    execution.id() == authorization.execution_id()
        && execution.workspace_id() == submit.scope.workspace_id()
        && execution.activity_id() == submit.activity_id
        && execution.mode() == submit.request.kind().mode()
        && execution.cwd() == submit.request.cwd()
        && execution.limits().timeout() == submit.request.timeout()
        && execution.limits().output() == submit.request.output_limit()
        && execution.permissions() == submit.request.permissions()
        && execution.request_digest() == authorization.request_digest()
        && provenance_matches
}

fn pending_approval_matches_submission(
    record: &RegisteredApprovalRequest,
    authorization: ExecutionAuthorizationRequest,
    agent_binding: Option<ApprovalAgentBindingDigest>,
) -> bool {
    record.request() == authorization && record.agent_binding() == agent_binding
}

fn requires_agent_authority(
    action: ExecutionActionClass,
    project_command: Option<ProjectCommandEvidence>,
) -> bool {
    matches!(
        action,
        ExecutionActionClass::DiscoveredProjectCommand
            | ExecutionActionClass::AnalyzedShell
            | ExecutionActionClass::GeneratedProjectCommand
    ) || project_command.is_some()
}

fn project_command_matches_action(
    action: ExecutionActionClass,
    project_command: Option<ProjectCommandEvidence>,
) -> bool {
    matches!(
        (action, project_command.map(ProjectCommandEvidence::class)),
        (
            ExecutionActionClass::DirectStructured
                | ExecutionActionClass::ShellEscape
                | ExecutionActionClass::AnalyzedShell,
            None
        ) | (
            ExecutionActionClass::DiscoveredProjectCommand,
            Some(ProjectCommandClass::Verify)
        ) | (
            ExecutionActionClass::GeneratedProjectCommand,
            Some(ProjectCommandClass::GeneratedPackage)
        )
    )
}

fn provenance_for_submission(
    authority: Option<&AgentExecutionAuthorityRequest>,
    execution_id: ExecutionId,
    project_command: Option<ProjectCommandEvidence>,
) -> Option<forge_domain::ExecutionAgentProvenance> {
    authority.map(|authority| {
        let provenance = authority.provenance(execution_id);
        match project_command {
            Some(evidence) => provenance.with_project_command(evidence),
            None => provenance,
        }
    })
}

fn approval_agent_binding(
    action: ExecutionActionClass,
    authority: Option<&AgentExecutionAuthorityRequest>,
    execution_id: ExecutionId,
    project_command: Option<ProjectCommandEvidence>,
) -> Option<ApprovalAgentBindingDigest> {
    matches!(
        action,
        ExecutionActionClass::DiscoveredProjectCommand
            | ExecutionActionClass::AnalyzedShell
            | ExecutionActionClass::GeneratedProjectCommand
    )
    .then(|| {
        provenance_for_submission(authority, execution_id, project_command)
            .map(|provenance| ApprovalAgentBindingDigest::from_provenance(&provenance))
    })
    .flatten()
}

fn cleanup_control_error_requires_readback(error: &ControlClientError) -> bool {
    matches!(error, ControlClientError::ResponseDropped)
        || matches!(error, ControlClientError::Service(error) if error.is_committed())
}

fn cleanup_apply_requires_observe<T>(result: &Result<T, ControlClientError>) -> bool {
    match result {
        Ok(_) => true,
        Err(error) => cleanup_control_error_requires_readback(error),
    }
}

fn cleanup_apply_phase_transition<T>(
    phase: &mut PendingCleanupPhase,
    result: &Result<T, ControlClientError>,
) -> bool {
    // Every Apply attempt crosses the retry boundary. A successful or
    // unknown attempt may observe immediately; known QueueFull/CAS failures
    // return now but the next call must still read back before reapplying.
    *phase = PendingCleanupPhase::Observe;
    cleanup_apply_requires_observe(result)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CleanupReadbackDisposition {
    Settled,
    Absent,
}

fn cleanup_observe_phase_transition(
    phase: &mut PendingCleanupPhase,
    result: Result<ApprovalCleanupReadback, ControlClientError>,
) -> Result<CleanupReadbackDisposition, ForgeApprovalCoordinatorError> {
    match result {
        Ok(ApprovalCleanupReadback::SettledTargetState) => {
            *phase = PendingCleanupPhase::Settled;
            Ok(CleanupReadbackDisposition::Settled)
        }
        Ok(ApprovalCleanupReadback::Absent) => {
            // Only an exact before-image readback permits reapplying the same
            // immutable plan.
            *phase = PendingCleanupPhase::Apply;
            Ok(CleanupReadbackDisposition::Absent)
        }
        Ok(ApprovalCleanupReadback::Mismatch) => {
            Err(ForgeApprovalCoordinatorError::CleanupIncomplete)
        }
        Err(error) => {
            // Preserve Observe across QueueFull, response loss, and
            // committed-but-unconfirmed errors.
            Err(error.into())
        }
    }
}

fn combine_shutdown_phases(
    cleanup: Result<usize, ForgeApprovalCoordinatorError>,
    execution: Result<usize, ForgeExecutionCoordinatorError>,
) -> Result<ForgeApprovalCoordinatorShutdown, ForgeApprovalCoordinatorError> {
    match (cleanup, execution) {
        (Ok(pending_cancelled), Ok(executions_cancelled)) => Ok(ForgeApprovalCoordinatorShutdown {
            pending_cancelled,
            executions_cancelled,
        }),
        (Err(cleanup), Ok(_)) => Err(cleanup),
        (Ok(_), Err(execution)) => Err(ForgeApprovalCoordinatorError::Execution(execution)),
        (Err(cleanup), Err(execution)) => {
            Err(ForgeApprovalCoordinatorError::ApprovalCleanupAndExecution {
                cleanup: Box::new(cleanup),
                execution: Box::new(execution),
            })
        }
    }
}

fn approval_limit() -> Result<ExecutionListLimit, ForgeApprovalCoordinatorError> {
    ExecutionListLimit::new(CLEANUP_LIMIT)
        .map_err(|_| ForgeApprovalCoordinatorError::InternalInvariant)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, atomic::AtomicBool, mpsc};
    use std::thread;

    use forge_domain::{
        ActivityId, AgentInstanceId, AgentInstanceRevision, AgentSessionId, ApprovalRequestId,
        AutoApprovalScope, AutoApprovalScopeRevision, AutoApprovalScopeState, AutoApprovalUseLimit,
        EstablishWorkspace, ExecutionActionClass, ExecutionAttribution, ExecutionCommandId,
        ExecutionId, ExecutionLimits, ExecutionListLimit, ExecutionOutputLimit,
        ExecutionPermissions, ExecutionProgram, ExecutionRequest, ExecutionRequestDigest,
        ExecutionTimeoutMillis, FileContentHash, GoalId, GoalNodeAttribution, GoalRevision,
        LocationId, LocationRevision, PolicyRevision, ProjectCommandCatalogFingerprint,
        ProjectCommandClass, ProjectCommandEvidence, RegisteredApprovalRequest,
        RequestedExecutionPermissions, TimestampMillis, WorkspaceId, WorkspaceRevision,
        WorkspaceRoot,
    };
    use forge_persistence::{
        ApprovalCleanupApplyOutcome, ApprovalCleanupAttemptId, GlobalRegistry, WorkspaceStore,
    };
    use forge_workspace::{LocationService, WorkspaceLocator, WorkspaceStateLayout};
    use uuid::Uuid;

    use super::{
        ApprovalAgentBindingDigest, ExecutionAuthorizationRequest, ForgeApprovalCoordinatorError,
        ForgeExecutionCoordinatorError, SubmitExecutionForApproval, approval_agent_binding,
        execution_request_digest, pending_approval_matches_submission,
    };
    use crate::worker::ForgeControlRequest;
    use crate::{
        AgentExecutionAuthorityRequest, ControlClientError, ControlError, ControlErrorCode,
        ControlErrorDetails, ForgeControl, ForgeControlClient, ForgeExecutionCoordinator,
        ResolvedWorkspaceScope,
    };

    fn id(value: u128) -> Uuid {
        Uuid::from_u128(value)
    }

    struct ExpiryRuntimeFixture {
        root: PathBuf,
        workspace_root: PathBuf,
        scope: ResolvedWorkspaceScope,
        expired_id: ApprovalRequestId,
        active_id: ApprovalRequestId,
        control: Option<ForgeControl>,
    }

    impl ExpiryRuntimeFixture {
        fn new() -> Result<Self, Box<dyn std::error::Error>> {
            let root =
                std::env::temp_dir().join(format!("forge-coordinator-expiry-{}", Uuid::now_v7()));
            fs::create_dir_all(&root)?;
            let location_root = root.join("location");
            let workspace_root = location_root.join("workspace");
            fs::create_dir_all(&workspace_root)?;
            let registry_path = root.join("registry.sqlite3");
            let location_id = LocationId::from_uuid(id(0xE201));
            let mut locations = LocationService::new(GlobalRegistry::open(&registry_path)?);
            let location = locations.register_selected_path(
                location_id,
                "Coordinator expiry fixture",
                &location_root,
                TimestampMillis::new(1)?,
            )?;
            let layout = WorkspaceStateLayout::initialize(&workspace_root)?;
            let workspace_id = WorkspaceId::from_uuid(id(0xE202));
            let establish = EstablishWorkspace::new(
                workspace_id,
                location.id(),
                WorkspaceRoot::from_canonical(workspace_root.clone())?,
                layout.root_fingerprint()?,
                TimestampMillis::new(2)?,
            );
            let mut store = WorkspaceStore::open(&layout, &establish)?;
            let activity_id = ActivityId::from_uuid(id(0xE203));
            let _activity = store.create_activity(&forge_domain::CreateActivity::new(
                activity_id,
                workspace_id,
                WorkspaceRevision::INITIAL,
                TimestampMillis::new(3)?,
            ))?;
            let policy = store.ensure_workspace_policy(TimestampMillis::new(4)?)?;
            let expired_id = ApprovalRequestId::from_uuid(id(0xE204));
            let active_id = ApprovalRequestId::from_uuid(id(0xE205));
            for (approval_id, execution_id, expires_at) in
                [(expired_id, 0xE206, 10_i64), (active_id, 0xE207, 100_i64)]
            {
                let authorization = ExecutionAuthorizationRequest::new(
                    ExecutionId::from_uuid(id(execution_id)),
                    workspace_id,
                    activity_id,
                    ExecutionRequestDigest::from_bytes([u8::try_from(expires_at)?; 32]),
                    ExecutionActionClass::DirectStructured,
                    RequestedExecutionPermissions::new(ExecutionPermissions::new(
                        true, false, false,
                    )),
                );
                let request = RegisteredApprovalRequest::pending(
                    approval_id,
                    authorization,
                    policy.revision(),
                    TimestampMillis::new(5)?,
                    TimestampMillis::new(expires_at)?,
                )?;
                let _inserted = store.insert_pending_approval(&request)?;
            }
            drop(store);
            drop(locations);
            let control = ForgeControl::new(GlobalRegistry::open(&registry_path)?);
            let locator = control
                .workspace_discover(location.id(), location.revision())?
                .into_iter()
                .find(|entry| entry.display_name() == "workspace")
                .ok_or("expiry fixture Workspace was not discovered")?
                .locator()
                .clone();
            let scope = control.resolve_workspace(location.id(), location.revision(), &locator)?;
            Ok(Self {
                root,
                workspace_root,
                scope,
                expired_id,
                active_id,
                control: Some(control),
            })
        }

        fn read_states(
            &self,
        ) -> Result<
            (
                forge_domain::ApprovalRequestState,
                forge_domain::ApprovalRequestState,
            ),
            Box<dyn std::error::Error>,
        > {
            let layout = WorkspaceStateLayout::inspect_existing(&self.workspace_root)?
                .ok_or("expiry fixture layout disappeared")?;
            let store = WorkspaceStore::open_existing(&layout)?;
            let expired = store
                .get_approval_request(self.expired_id)?
                .ok_or("expired approval disappeared")?;
            let active = store
                .get_approval_request(self.active_id)?
                .ok_or("active approval disappeared")?;
            Ok((expired.state(), active.state()))
        }

        fn read_approval(
            &self,
            approval_id: ApprovalRequestId,
        ) -> Result<RegisteredApprovalRequest, Box<dyn std::error::Error>> {
            let layout = WorkspaceStateLayout::inspect_existing(&self.workspace_root)?
                .ok_or("expiry fixture layout disappeared")?;
            let store = WorkspaceStore::open_existing(&layout)?;
            store
                .get_approval_request(approval_id)?
                .ok_or_else(|| "approval row disappeared".into())
        }

        fn finish(self) -> Result<(), Box<dyn std::error::Error>> {
            drop(self.control);
            fs::remove_dir_all(self.root)?;
            Ok(())
        }
    }

    fn spawn_expiry_rejection_handler(
        requests: mpsc::Receiver<ForgeControlRequest>,
        real_control: ForgeControl,
        plan_b: crate::approval_expiry::ApprovalExpiryPlan,
        outcome_sender: mpsc::SyncSender<ApprovalCleanupApplyOutcome>,
    ) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            let mut prepare_count = 0_u8;
            while let Ok(request) = requests.recv() {
                match request {
                    ForgeControlRequest::ApprovalExpiryPrepare {
                        scope: request_scope,
                        limit,
                        response,
                        ..
                    } => {
                        prepare_count = prepare_count.saturating_add(1);
                        let result = if prepare_count == 1 {
                            Ok(plan_b.clone())
                        } else {
                            match TimestampMillis::new(22) {
                                Ok(observed_at) => real_control.prepare_approval_expiry_plan(
                                    &request_scope,
                                    observed_at,
                                    limit,
                                ),
                                Err(_) => Err(ControlError::new(ControlErrorCode::Internal)),
                            }
                        };
                        let _ignored = response.send(result);
                    }
                    ForgeControlRequest::ApprovalExpiryApply {
                        plan,
                        attempt,
                        response,
                    } => {
                        let result = real_control.apply_approval_expiry_plan(&plan, attempt);
                        if let Ok(outcome) = &result {
                            let _ignored = outcome_sender.send(outcome.clone());
                        }
                        let _ignored = response.send(result);
                    }
                    ForgeControlRequest::ApprovalExpiryObserve { plan, response } => {
                        let _ignored =
                            response.send(ForgeControl::observe_approval_expiry_plan(&plan));
                    }
                    ForgeControlRequest::ApprovalListPending {
                        scope: request_scope,
                        limit,
                        response,
                    } => {
                        let _ignored = response
                            .send(real_control.list_pending_approvals(&request_scope, limit));
                    }
                    _ => {}
                }
            }
        })
    }

    #[test]
    fn expiry_runtime_retires_real_matching_rejection_and_recaptures_without_admin_owner()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = ExpiryRuntimeFixture::new()?;
        let limit = ExecutionListLimit::DEFAULT;
        let expired_before = fixture.read_approval(fixture.expired_id)?;
        let active_before = fixture.read_approval(fixture.active_id)?;
        assert_eq!(
            expired_before.revision(),
            forge_domain::ApprovalRevision::INITIAL
        );
        assert_eq!(expired_before.decided_at(), None);
        assert_eq!(expired_before.expires_at(), TimestampMillis::new(10)?);
        let plan_b = {
            let control = fixture.control.as_ref().ok_or("fixture control missing")?;
            let plan_a = control.prepare_approval_expiry_plan(
                &fixture.scope,
                TimestampMillis::new(20)?,
                limit,
            )?;
            let plan_b = control.prepare_approval_expiry_plan(
                &fixture.scope,
                TimestampMillis::new(21)?,
                limit,
            )?;
            assert!(matches!(
                control.apply_approval_expiry_plan(
                    &plan_a,
                    ApprovalCleanupAttemptId::from_uuid(Uuid::now_v7()),
                )?,
                ApprovalCleanupApplyOutcome::Applied(_)
            ));
            let expired = fixture.read_approval(fixture.expired_id)?;
            assert_eq!(expired.state(), forge_domain::ApprovalRequestState::Expired);
            assert_eq!(expired.revision(), forge_domain::ApprovalRevision::new(2)?);
            assert_eq!(expired.decided_at(), Some(TimestampMillis::new(20)?));
            plan_b
        };

        let (control_client, requests) = ForgeControlClient::journal_test_channel(16);
        let scope = fixture.scope.clone();
        let real_control = fixture.control.take().ok_or("fixture control missing")?;
        let (outcome_sender, outcome_receiver) = mpsc::sync_channel(1);
        let handler =
            spawn_expiry_rejection_handler(requests, real_control, plan_b, outcome_sender);
        let (dummy_control, _dummy_requests) = ForgeControlClient::journal_test_channel(1);
        let mut execution = ForgeExecutionCoordinator::start(dummy_control, 1)?;
        let (runtime_sender, runtime_receiver) = mpsc::sync_channel(1);
        let mut runtime = super::ApprovalRuntime::new(
            control_client,
            execution.client(),
            runtime_receiver,
            Arc::new(AtomicBool::new(true)),
        );
        let records = runtime.list_pending(&scope)?;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].approval_id(), fixture.active_id);
        assert!(runtime.known_scopes.is_empty());
        assert!(runtime.cleanup_permits.is_empty());
        assert!(runtime.pending_cleanup.is_empty());
        assert!(runtime.pending_expiry.is_empty());
        assert!(matches!(
            outcome_receiver.recv()?,
            ApprovalCleanupApplyOutcome::RejectedBeforeWrite(_)
        ));
        assert_eq!(
            fixture.read_states()?,
            (
                forge_domain::ApprovalRequestState::Expired,
                forge_domain::ApprovalRequestState::Pending,
            )
        );
        assert_eq!(fixture.read_approval(fixture.active_id)?, active_before);
        drop(runtime_sender);
        drop(runtime);
        handler.join().map_err(|_| "expiry handler panicked")?;
        let _ = execution.shutdown()?;
        fixture.finish()
    }

    #[test]
    fn expiry_runtime_observes_real_apply_after_response_drop()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = ExpiryRuntimeFixture::new()?;
        let active_before = fixture.read_approval(fixture.active_id)?;
        let scope = fixture.scope.clone();
        let real_control = fixture.control.take().ok_or("fixture control missing")?;
        let (control_client, requests) = ForgeControlClient::journal_test_channel(16);
        let (applied_sender, applied_receiver) = mpsc::sync_channel(1);
        let handler = thread::spawn(move || {
            while let Ok(request) = requests.recv() {
                match request {
                    ForgeControlRequest::ApprovalExpiryPrepare {
                        scope: request_scope,
                        limit,
                        response,
                        ..
                    } => {
                        let result = match TimestampMillis::new(20) {
                            Ok(observed_at) => real_control.prepare_approval_expiry_plan(
                                &request_scope,
                                observed_at,
                                limit,
                            ),
                            Err(_) => Err(ControlError::new(ControlErrorCode::Internal)),
                        };
                        let _ignored = response.send(result);
                    }
                    ForgeControlRequest::ApprovalExpiryApply {
                        plan,
                        attempt,
                        response,
                    } => {
                        let result = real_control.apply_approval_expiry_plan(&plan, attempt);
                        if let Ok(ApprovalCleanupApplyOutcome::Applied(_)) = &result {
                            let _ignored = applied_sender.send(());
                        }
                        drop(response);
                    }
                    ForgeControlRequest::ApprovalExpiryObserve { plan, response } => {
                        let result = ForgeControl::observe_approval_expiry_plan(&plan);
                        let _ignored = response.send(result);
                    }
                    ForgeControlRequest::ApprovalListPending {
                        scope: request_scope,
                        limit,
                        response,
                    } => {
                        let _ignored = response
                            .send(real_control.list_pending_approvals(&request_scope, limit));
                    }
                    _ => {}
                }
            }
        });
        let (dummy_control, _dummy_requests) = ForgeControlClient::journal_test_channel(1);
        let mut execution = ForgeExecutionCoordinator::start(dummy_control, 1)?;
        let (runtime_sender, runtime_receiver) = mpsc::sync_channel(1);
        let mut runtime = super::ApprovalRuntime::new(
            control_client,
            execution.client(),
            runtime_receiver,
            Arc::new(AtomicBool::new(true)),
        );
        let records = runtime.list_pending(&scope)?;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].approval_id(), fixture.active_id);
        assert!(!records[0].actionable());
        applied_receiver.recv()?;
        assert!(runtime.known_scopes.is_empty());
        assert!(runtime.cleanup_permits.is_empty());
        assert!(runtime.pending_expiry.is_empty());
        assert_eq!(
            fixture.read_states()?,
            (
                forge_domain::ApprovalRequestState::Expired,
                forge_domain::ApprovalRequestState::Pending,
            )
        );
        let expired = fixture.read_approval(fixture.expired_id)?;
        assert_eq!(expired.revision(), forge_domain::ApprovalRevision::new(2)?);
        assert_eq!(expired.decided_at(), Some(TimestampMillis::new(20)?));
        assert_eq!(fixture.read_approval(fixture.active_id)?, active_before);
        drop(runtime_sender);
        drop(runtime);
        handler.join().map_err(|_| "expiry drop handler panicked")?;
        let _ = execution.shutdown()?;
        fixture.finish()
    }

    #[test]
    fn cleanup_reply_loss_requires_readback_before_reusing_plan() {
        assert!(super::cleanup_control_error_requires_readback(
            &ControlClientError::ResponseDropped
        ));
        assert!(super::cleanup_control_error_requires_readback(
            &ControlClientError::Service(ControlError::committed())
        ));
        assert!(!super::cleanup_control_error_requires_readback(
            &ControlClientError::QueueFull
        ));
        assert!(!super::cleanup_control_error_requires_readback(
            &ControlClientError::Service(ControlError::new(ControlErrorCode::InvalidInput))
        ));
    }

    #[test]
    fn scripted_cleanup_channel_observes_unknown_apply_before_identical_retry()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::sync::mpsc;

        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        enum Request {
            Apply,
            Observe,
        }

        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        enum Reply {
            ApplyDropped,
            ObserveQueueFull,
            ObserveAbsent,
        }

        let (script_sender, script_receiver) = mpsc::sync_channel(8);
        let mut phase = super::PendingCleanupPhase::Apply;
        assert_eq!(phase, super::PendingCleanupPhase::Apply);
        let mut conflict_phase = super::PendingCleanupPhase::Apply;
        let conflict: Result<(), ControlClientError> = Err(ControlClientError::Service(
            ControlError::new(ControlErrorCode::ApprovalConflict),
        ));
        assert!(!super::cleanup_apply_phase_transition(
            &mut conflict_phase,
            &conflict
        ));
        assert_eq!(conflict_phase, super::PendingCleanupPhase::Observe);
        let mut queue_phase = super::PendingCleanupPhase::Apply;
        let queue_full: Result<(), ControlClientError> = Err(ControlClientError::QueueFull);
        assert!(!super::cleanup_apply_phase_transition(
            &mut queue_phase,
            &queue_full
        ));
        assert_eq!(queue_phase, super::PendingCleanupPhase::Observe);

        script_sender.send((Request::Apply, Reply::ApplyDropped))?;
        let (request, reply) = script_receiver.recv()?;
        assert_eq!(request, Request::Apply);
        assert_eq!(reply, Reply::ApplyDropped);
        let apply_result: Result<(), ControlClientError> = Err(ControlClientError::ResponseDropped);
        assert!(super::cleanup_apply_phase_transition(
            &mut phase,
            &apply_result
        ));

        script_sender.send((Request::Observe, Reply::ObserveQueueFull))?;
        let (request, reply) = script_receiver.recv()?;
        assert_eq!(request, Request::Observe);
        assert_eq!(reply, Reply::ObserveQueueFull);
        let observe_result: Result<super::ApprovalCleanupReadback, ControlClientError> =
            Err(ControlClientError::QueueFull);
        assert!(matches!(
            super::cleanup_observe_phase_transition(&mut phase, observe_result),
            Err(ForgeApprovalCoordinatorError::Control(
                ControlClientError::QueueFull
            ))
        ));
        assert_eq!(phase, super::PendingCleanupPhase::Observe);

        script_sender.send((Request::Observe, Reply::ObserveAbsent))?;
        let (request, reply) = script_receiver.recv()?;
        assert_eq!(request, Request::Observe);
        assert_eq!(reply, Reply::ObserveAbsent);
        assert!(matches!(
            super::cleanup_observe_phase_transition(
                &mut phase,
                Ok(super::ApprovalCleanupReadback::Absent)
            ),
            Ok(super::CleanupReadbackDisposition::Absent)
        ));

        script_sender.send((Request::Apply, Reply::ApplyDropped))?;
        let (request, _reply) = script_receiver.recv()?;
        assert_eq!(request, Request::Apply);
        assert_eq!(phase, super::PendingCleanupPhase::Apply);
        Ok(())
    }

    #[test]
    fn expiry_stop_settlement_observes_only_and_releases_before_or_after()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::sync::mpsc::{self, TryRecvError};

        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        enum Request {
            Observe,
        }

        let (sender, receiver) = mpsc::sync_channel(4);
        let mut phase = super::PendingCleanupPhase::Observe;

        sender.send(Request::Observe)?;
        assert_eq!(receiver.recv()?, Request::Observe);
        let unknown: Result<super::ApprovalCleanupReadback, ControlClientError> =
            Err(ControlClientError::ResponseDropped);
        assert!(super::cleanup_observe_phase_transition(&mut phase, unknown).is_err());
        assert_eq!(phase, super::PendingCleanupPhase::Observe);

        sender.send(Request::Observe)?;
        assert_eq!(receiver.recv()?, Request::Observe);
        assert!(matches!(
            super::cleanup_observe_phase_transition(
                &mut phase,
                Ok(super::ApprovalCleanupReadback::Absent)
            ),
            Ok(super::CleanupReadbackDisposition::Absent)
        ));
        assert_eq!(phase, super::PendingCleanupPhase::Apply);

        sender.send(Request::Observe)?;
        assert_eq!(receiver.recv()?, Request::Observe);
        assert!(matches!(
            super::cleanup_observe_phase_transition(
                &mut phase,
                Ok(super::ApprovalCleanupReadback::SettledTargetState)
            ),
            Ok(super::CleanupReadbackDisposition::Settled)
        ));
        assert_eq!(phase, super::PendingCleanupPhase::Settled);
        assert!(matches!(receiver.try_recv(), Err(TryRecvError::Empty)));
        Ok(())
    }

    #[test]
    fn approval_reply_loss_is_distinct_from_closed_before_enqueue()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sender, receiver) = mpsc::sync_channel(1);
        drop(sender);
        let pending = super::PendingApproval::<usize> { receiver };
        let lost = pending.recv().err().ok_or("dropped reply succeeded")?;
        assert!(matches!(
            lost,
            ForgeApprovalCoordinatorError::ResponseDropped
        ));
        assert_eq!(
            lost.view().outcome(),
            crate::ControlOperationOutcome::Unknown
        );
        let (sender, receiver) = mpsc::sync_channel(1);
        drop(receiver);
        let client = super::ForgeApprovalCoordinatorClient {
            sender,
            accepting: Arc::new(AtomicBool::new(true)),
        };
        let closed = client
            .stop_workspace(WorkspaceId::from_uuid(id(0xAA01)))
            .err()
            .ok_or("closed queue succeeded")?;
        assert!(matches!(closed, ForgeApprovalCoordinatorError::Closed));
        assert_eq!(
            closed.view().outcome(),
            crate::ControlOperationOutcome::NotAdmitted
        );
        Ok(())
    }

    #[test]
    fn owned_stop_requires_prior_attachment_and_replays_original_receipt_after_disable()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = ExpiryRuntimeFixture::new()?;
        let control = fixture.control.take().ok_or("fixture control missing")?;
        let (client, mut worker) = crate::ForgeControlWorker::start(control)?;
        let mut execution = ForgeExecutionCoordinator::start(client.clone(), 1)?;
        let (_sender, receiver) = mpsc::sync_channel(1);
        let mut runtime = super::ApprovalRuntime::new(
            client.clone(),
            execution.client(),
            receiver,
            Arc::new(AtomicBool::new(true)),
        );
        let request = forge_persistence::ExecutionStopRequest::new(
            id(0xE290),
            fixture.scope.workspace_id(),
            id(0xE291),
            forge_domain::RuntimeInstanceId::from_uuid(id(0xE292)),
            [0x92; 32],
            TimestampMillis::new(20)?,
        );
        let flow = (|| -> Result<(), Box<dyn std::error::Error>> {
            assert!(matches!(
                runtime.stop_workspace_durable(&fixture.scope, request),
                Err(ForgeApprovalCoordinatorError::AttributionMismatch)
            ));
            assert!(runtime.cleanup_permits.is_empty());
            runtime.attach_workspace(&fixture.scope)?;
            let original = runtime
                .cleanup_permits
                .get(&fixture.scope.workspace_id())
                .ok_or("permit missing")?
                .clone();
            client.set_location_state(forge_domain::SetLocationState::new(
                fixture.scope.locator().location_id(),
                LocationRevision::INITIAL,
                forge_domain::LocationState::Disabled,
                TimestampMillis::new(21)?,
            ))?;
            let before_capture = super::current_timestamp_millis()?;
            let first = runtime.stop_workspace_durable(&fixture.scope, request)?;
            let after_capture = super::current_timestamp_millis()?;
            assert!(first.record().created_at() >= before_capture);
            assert!(first.record().created_at() <= after_capture);
            assert_ne!(first.record().created_at(), request.observed_at());
            assert_eq!(first.authority().observed_at(), first.record().created_at());
            assert_eq!(
                first.record().status(),
                forge_persistence::ExecutionStopStatus::Completed
            );
            assert_eq!(first.authority().targets().len(), 2);
            assert!(matches!(first.native_result(), Some(Ok(0))));
            let retry = runtime.stop_workspace_durable(&fixture.scope, request)?;
            assert_eq!(retry.record(), first.record());
            assert_eq!(retry.authority(), first.authority());
            assert_eq!(
                runtime.cleanup_permits.get(&fixture.scope.workspace_id()),
                Some(&original)
            );
            assert_eq!(
                fixture.read_states()?,
                (
                    forge_domain::ApprovalRequestState::Expired,
                    forge_domain::ApprovalRequestState::Expired,
                )
            );
            Ok(())
        })();
        drop(runtime);
        let native_shutdown = execution.shutdown();
        drop(client);
        let worker_shutdown = worker.shutdown();
        fixture.finish()?;
        flow?;
        let _native = native_shutdown?;
        worker_shutdown?;
        Ok(())
    }

    #[test]
    fn shutdown_error_still_joins_the_owned_worker() -> Result<(), Box<dyn std::error::Error>> {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
            mpsc,
        };
        use std::time::Duration;

        let (sender, requests) = mpsc::sync_channel(1);
        let (reply_sent_tx, reply_sent_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let thread = std::thread::spawn(move || {
            if let Ok(super::ApprovalCoordinatorRequest::Shutdown { response }) = requests.recv() {
                let _ = response.send(Err(ForgeApprovalCoordinatorError::Closed));
                let _ = reply_sent_tx.send(());
                let _ = release_rx.recv();
            }
        });
        let coordinator = super::ForgeApprovalCoordinator {
            client: super::ForgeApprovalCoordinatorClient {
                sender,
                accepting: Arc::new(AtomicBool::new(true)),
            },
            thread: Some(thread),
        };
        let accepting = Arc::clone(&coordinator.client.accepting);
        let (done_tx, done_rx) = mpsc::sync_channel(1);
        let caller = std::thread::spawn(move || {
            let mut coordinator = coordinator;
            let _ = done_tx.send(coordinator.shutdown());
        });
        reply_sent_rx.recv_timeout(Duration::from_secs(2))?;
        let premature = done_rx.recv_timeout(Duration::from_millis(50));
        release_tx.send(())?;
        caller.join().map_err(|_| "shutdown caller panicked")?;
        assert!(
            matches!(premature, Err(mpsc::RecvTimeoutError::Timeout)),
            "shutdown returned its error before joining the worker"
        );
        assert!(matches!(
            done_rx.recv_timeout(Duration::from_secs(2))?,
            Err(ForgeApprovalCoordinatorError::Closed)
        ));
        assert!(!accepting.load(Ordering::Acquire));
        Ok(())
    }

    fn scope() -> Result<ResolvedWorkspaceScope, Box<dyn std::error::Error>> {
        Ok(ResolvedWorkspaceScope::from_observation(
            WorkspaceId::from_uuid(id(1)),
            WorkspaceRevision::INITIAL,
            WorkspaceLocator::new(
                LocationId::from_uuid(id(2)),
                LocationRevision::INITIAL,
                Path::new("workspace"),
            )?,
        ))
    }

    fn request(
        scope: &ResolvedWorkspaceScope,
        activity_id: ActivityId,
        execution_id: forge_domain::ExecutionId,
    ) -> Result<ExecutionRequest, Box<dyn std::error::Error>> {
        Ok(ExecutionRequest::new(
            ExecutionAttribution::new(execution_id, scope.workspace_id(), activity_id),
            forge_domain::ExecutionKind::Structured {
                program: ExecutionProgram::new("/usr/bin/true".into())?,
                arguments: Vec::new(),
            },
            None,
            ExecutionLimits::new(
                ExecutionTimeoutMillis::new(1_000)?,
                ExecutionOutputLimit::DEFAULT,
            ),
            ExecutionPermissions::new(true, false, false),
        )?)
    }

    fn authority(
        scope: ResolvedWorkspaceScope,
        activity_id: ActivityId,
        session_id: AgentSessionId,
    ) -> Result<AgentExecutionAuthorityRequest, Box<dyn std::error::Error>> {
        Ok(AgentExecutionAuthorityRequest {
            session_id,
            scope,
            activity_id,
            agent_id: AgentInstanceId::from_uuid(id(4)),
            expected_revision: AgentInstanceRevision::INITIAL,
            principal: forge_domain::AuthenticatedPrincipal::TrustedStdio,
            attribution: GoalNodeAttribution::new(
                GoalId::from_uuid(id(5)),
                GoalRevision::INITIAL,
                forge_domain::DagRevisionNumber::INITIAL,
                forge_domain::DagNodeId::from_uuid(id(6)),
                forge_domain::DagNodeRevision::INITIAL,
            ),
            command_id: ExecutionCommandId::new("make:package".to_owned())?,
        })
    }

    fn package_evidence(fingerprint: u8) -> ProjectCommandEvidence {
        ProjectCommandEvidence::new(
            ProjectCommandClass::GeneratedPackage,
            ProjectCommandCatalogFingerprint::from_hash(FileContentHash::from_bytes(
                [fingerprint; FileContentHash::BYTE_LEN],
            )),
        )
    }

    fn authorization(submit: &SubmitExecutionForApproval) -> ExecutionAuthorizationRequest {
        ExecutionAuthorizationRequest::new(
            submit.request.id(),
            submit.scope.workspace_id(),
            submit.activity_id,
            execution_request_digest(&submit.request),
            submit.action,
            RequestedExecutionPermissions::new(submit.request.permissions()),
        )
    }

    fn binding(submit: &SubmitExecutionForApproval) -> Option<ApprovalAgentBindingDigest> {
        approval_agent_binding(
            submit.action,
            submit.agent_authority.as_ref(),
            submit.request.id(),
            submit.project_command,
        )
    }

    #[test]
    fn scripted_shutdown_error_combiner_preserves_each_independent_phase() {
        let cleanup = ForgeApprovalCoordinatorError::CleanupIncomplete;
        let execution = ForgeExecutionCoordinatorError::JournalTimeout;
        let combined = super::combine_shutdown_phases(Err(cleanup), Err(execution));
        match combined {
            Err(ForgeApprovalCoordinatorError::ApprovalCleanupAndExecution {
                cleanup,
                execution,
            }) => {
                assert!(matches!(
                    *cleanup,
                    ForgeApprovalCoordinatorError::CleanupIncomplete
                ));
                assert!(matches!(
                    *execution,
                    ForgeExecutionCoordinatorError::JournalTimeout
                ));
            }
            other => assert!(other.is_err()),
        }

        let cleanup_only = super::combine_shutdown_phases(
            Err(ForgeApprovalCoordinatorError::CleanupIncomplete),
            Ok(3),
        );
        assert!(matches!(
            cleanup_only,
            Err(ForgeApprovalCoordinatorError::CleanupIncomplete)
        ));

        let execution_only = super::combine_shutdown_phases(
            Ok(2),
            Err(ForgeExecutionCoordinatorError::JournalTimeout),
        );
        assert!(matches!(
            execution_only,
            Err(ForgeApprovalCoordinatorError::Execution(
                ForgeExecutionCoordinatorError::JournalTimeout
            ))
        ));
    }

    #[test]
    fn auto_approval_status_reports_live_ttl_and_hard_limits()
    -> Result<(), Box<dyn std::error::Error>> {
        let workspace_id = WorkspaceId::from_uuid(id(0xB1));
        let active = AutoApprovalScope::from_parts(
            forge_domain::AutoApprovalScopeId::from_uuid(id(0xB2)),
            workspace_id,
            None,
            ExecutionActionClass::DiscoveredProjectCommand,
            ExecutionPermissions::new(true, false, false),
            PolicyRevision::INITIAL,
            TimestampMillis::new(10_000)?,
            AutoApprovalUseLimit::new(2)?,
            1,
            AutoApprovalScopeState::Active,
            AutoApprovalScopeRevision::INITIAL,
        )?;
        let live = super::AutoApprovalActionStatus::from_scope(
            &active,
            TimestampMillis::new(5_000)?,
            Some(PolicyRevision::INITIAL),
        );
        assert_eq!(
            live.runtime_state(),
            super::AutoApprovalRuntimeState::Active
        );
        assert_eq!(live.locality(), super::AutoApprovalScopeLocality::Local);
        assert!(live.scope_active());
        assert_eq!(live.remaining_ttl_millis(), Some(5_000));
        assert_eq!(live.used_count(), 1);
        assert_eq!(live.remaining_uses(), Some(1));

        let expired = super::AutoApprovalActionStatus::from_scope(
            &active,
            TimestampMillis::new(10_000)?,
            Some(PolicyRevision::INITIAL),
        );
        assert_eq!(
            expired.runtime_state(),
            super::AutoApprovalRuntimeState::Expired
        );
        assert!(!expired.scope_active());

        let exhausted = AutoApprovalScope::from_parts(
            active.id(),
            workspace_id,
            None,
            active.action(),
            active.permission_ceiling(),
            active.policy_revision(),
            active.expires_at(),
            active.max_uses(),
            2,
            AutoApprovalScopeState::Active,
            active.revision(),
        )?;
        let exhausted = super::AutoApprovalActionStatus::from_scope(
            &exhausted,
            TimestampMillis::new(5_000)?,
            Some(PolicyRevision::INITIAL),
        );
        assert_eq!(
            exhausted.runtime_state(),
            super::AutoApprovalRuntimeState::Exhausted
        );
        assert_eq!(exhausted.remaining_uses(), Some(0));

        let changed_policy = super::AutoApprovalActionStatus::from_scope(
            &active,
            TimestampMillis::new(5_000)?,
            Some(PolicyRevision::new(2)?),
        );
        assert_eq!(
            changed_policy.runtime_state(),
            super::AutoApprovalRuntimeState::PolicyChanged
        );
        assert!(!changed_policy.scope_active());
        Ok(())
    }

    #[test]
    fn approval_error_projection_preserves_causal_failure_family() {
        assert_eq!(
            ForgeApprovalCoordinatorError::CleanupIncomplete
                .view()
                .code(),
            ControlErrorCode::ApprovalConflict
        );
        assert_eq!(
            ForgeApprovalCoordinatorError::AutoScopeUnavailable
                .view()
                .code(),
            ControlErrorCode::ApprovalConflict
        );
        assert_eq!(
            ForgeApprovalCoordinatorError::PendingPayloadMissing
                .view()
                .code(),
            ControlErrorCode::ApprovalConflict
        );
        assert_eq!(
            ForgeApprovalCoordinatorError::AttributionMismatch
                .view()
                .code(),
            ControlErrorCode::ExecutionProvenanceConflict
        );
        assert_eq!(
            ForgeApprovalCoordinatorError::Clock.view().code(),
            ControlErrorCode::Internal
        );
        assert_eq!(
            ForgeApprovalCoordinatorError::InternalInvariant
                .view()
                .code(),
            ControlErrorCode::Internal
        );
        assert_eq!(
            ForgeApprovalCoordinatorError::SpawnThread(std::io::Error::other("test"))
                .view()
                .code(),
            ControlErrorCode::WorkerClosed
        );
    }

    #[test]
    fn pending_and_existing_targets_are_projected_to_the_correct_identity() {
        let approval_id = ApprovalRequestId::from_uuid(id(0xA1));
        let execution_id = ExecutionId::from_uuid(id(0xA2));
        let pending = ForgeApprovalCoordinatorError::PendingApprovalConflict {
            approval_id,
            execution_id,
        }
        .view();
        assert_eq!(
            pending.code(),
            ControlErrorCode::ExecutionProvenanceConflict
        );
        assert_eq!(
            pending.recovery_action(),
            crate::ControlRecoveryAction::InspectApproval
        );
        assert_eq!(
            pending.details(),
            ControlErrorDetails::ApprovalTarget {
                approval_id,
                execution_id,
            }
        );
        let existing =
            ForgeApprovalCoordinatorError::ExistingExecutionConflict { execution_id }.view();
        assert_eq!(existing.code(), ControlErrorCode::ExecutionConflict);
        assert_eq!(
            existing.details(),
            ControlErrorDetails::ExecutionTarget { execution_id }
        );
    }

    #[test]
    fn generated_package_pending_resubmission_fences_session_and_catalog_fingerprint()
    -> Result<(), Box<dyn std::error::Error>> {
        let scope = scope()?;
        let activity_id = ActivityId::from_uuid(id(3));
        let execution_id = forge_domain::ExecutionId::from_uuid(id(7));
        let original = SubmitExecutionForApproval::project_command(
            scope.clone(),
            activity_id,
            forge_domain::RuntimeInstanceId::from_uuid(id(8)),
            request(&scope, activity_id, execution_id)?,
            package_evidence(0x51),
        )?
        .with_agent_authority(authority(
            scope.clone(),
            activity_id,
            AgentSessionId::from_uuid(id(9)),
        )?)
        .with_approval_id(ApprovalRequestId::from_uuid(id(10)));
        assert_eq!(
            original.action,
            forge_domain::ExecutionActionClass::GeneratedProjectCommand
        );
        let original_authorization = authorization(&original);
        let original_binding = binding(&original).ok_or("generated package binding missing")?;
        let pending = forge_domain::RegisteredApprovalRequest::pending(
            ApprovalRequestId::from_uuid(id(10)),
            original_authorization,
            PolicyRevision::INITIAL,
            TimestampMillis::new(1)?,
            TimestampMillis::new(2)?,
        )?
        .with_agent_binding(original_binding);

        let changed_session = SubmitExecutionForApproval::project_command(
            scope.clone(),
            activity_id,
            forge_domain::RuntimeInstanceId::from_uuid(id(8)),
            request(&scope, activity_id, execution_id)?,
            package_evidence(0x51),
        )?
        .with_agent_authority(authority(
            scope.clone(),
            activity_id,
            AgentSessionId::from_uuid(id(11)),
        )?);
        assert!(!pending_approval_matches_submission(
            &pending,
            authorization(&changed_session),
            binding(&changed_session),
        ));

        let changed_fingerprint = SubmitExecutionForApproval::project_command(
            scope.clone(),
            activity_id,
            forge_domain::RuntimeInstanceId::from_uuid(id(8)),
            request(&scope, activity_id, execution_id)?,
            package_evidence(0x52),
        )?
        .with_agent_authority(authority(
            scope,
            activity_id,
            AgentSessionId::from_uuid(id(9)),
        )?);
        assert!(!pending_approval_matches_submission(
            &pending,
            authorization(&changed_fingerprint),
            binding(&changed_fingerprint),
        ));
        Ok(())
    }
}

fn current_timestamp_millis() -> Result<TimestampMillis, ForgeApprovalCoordinatorError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ForgeApprovalCoordinatorError::Clock)?;
    let millis =
        i64::try_from(elapsed.as_millis()).map_err(|_| ForgeApprovalCoordinatorError::Clock)?;
    TimestampMillis::new(millis).map_err(|_| ForgeApprovalCoordinatorError::Clock)
}

fn add_millis(
    timestamp: TimestampMillis,
    duration: i64,
) -> Result<TimestampMillis, ForgeApprovalCoordinatorError> {
    timestamp
        .get()
        .checked_add(duration)
        .and_then(|value| TimestampMillis::new(value).ok())
        .ok_or(ForgeApprovalCoordinatorError::Clock)
}

#[derive(Debug, Error)]
pub enum ForgeApprovalCoordinatorError {
    #[error("approval coordinator queue is full")]
    QueueFull,
    #[error("approval coordinator is closed")]
    Closed,
    #[error("approval coordinator reply was dropped after admission")]
    ResponseDropped,
    #[error("approval coordinator is already shut down")]
    AlreadyShutdown,
    #[error("failed to spawn approval coordinator thread")]
    SpawnThread(#[source] std::io::Error),
    #[error("approval coordinator thread panicked")]
    ThreadPanicked,
    #[error("approval pending payload capacity is full")]
    PendingCapacity,
    #[error("approval pending payload is unavailable")]
    PendingPayloadMissing,
    #[error("approval {approval_id} has no durable execution {execution_id}")]
    PendingApprovalExecutionMissing {
        approval_id: ApprovalRequestId,
        execution_id: ExecutionId,
    },
    #[error("auto approval scope capacity is full")]
    AutoScopeCapacity,
    #[error("auto approval scope is unavailable")]
    AutoScopeUnavailable,
    #[error("approval cleanup did not converge within its bound")]
    CleanupIncomplete,
    #[error("approval cleanup and execution stop both failed")]
    ApprovalCleanupAndExecution {
        cleanup: Box<ForgeApprovalCoordinatorError>,
        execution: Box<ForgeExecutionCoordinatorError>,
    },
    #[error("approval request attribution is invalid")]
    AttributionMismatch,
    #[error("approval {approval_id} conflicts with execution {execution_id}")]
    PendingApprovalConflict {
        approval_id: ApprovalRequestId,
        execution_id: ExecutionId,
    },
    #[error("execution {execution_id} conflicts with approval attribution")]
    ExistingExecutionConflict { execution_id: ExecutionId },
    #[error("approval coordinator clock is unavailable")]
    Clock,
    #[error("approval coordinator invariant failed")]
    InternalInvariant,
    #[error(transparent)]
    Control(#[from] ControlClientError),
    #[error("Workspace stop logical identity validation failed before effects")]
    WorkspaceStopValidation(#[source] ControlClientError),
    #[error(transparent)]
    Execution(#[from] ForgeExecutionCoordinatorError),
}

impl ForgeApprovalCoordinatorError {
    /// Shared redacted projection; no effect is retried here.
    pub fn view(&self) -> crate::ControlErrorView {
        use crate::{ControlErrorCode as Code, ControlErrorView as View};
        match self {
            Self::WorkspaceStopValidation(error) => View::not_admitted(error.view().code()),
            Self::Control(error) => error.view().after_admission(),
            Self::Execution(error) => error.view().after_admission(),
            Self::QueueFull => View::retryable_admission(),
            Self::PendingCapacity | Self::AutoScopeCapacity => {
                // Capacity is checked before creating the requested approval/scope.
                // Baseline policy inspection may already have happened; do not retry automatically.
                View::not_admitted(Code::CapacityExceeded)
            }
            Self::Closed => View::not_admitted(Code::WorkerClosed),
            Self::ResponseDropped
            | Self::AlreadyShutdown
            | Self::ThreadPanicked
            | Self::SpawnThread(_) => View::unknown(Code::WorkerClosed),
            Self::PendingPayloadMissing
            | Self::AutoScopeUnavailable
            | Self::CleanupIncomplete
            | Self::ApprovalCleanupAndExecution { .. } => View::unknown(Code::ApprovalConflict),
            Self::PendingApprovalExecutionMissing {
                approval_id,
                execution_id,
            } => View::unknown(Code::ApprovalConflict).with_details(
                ControlErrorDetails::ApprovalTarget {
                    approval_id: *approval_id,
                    execution_id: *execution_id,
                },
            ),
            Self::PendingApprovalConflict {
                approval_id,
                execution_id,
            } => View::unknown(Code::ExecutionProvenanceConflict).with_details(
                ControlErrorDetails::ApprovalTarget {
                    approval_id: *approval_id,
                    execution_id: *execution_id,
                },
            ),
            Self::ExistingExecutionConflict { execution_id } => View::unknown(
                Code::ExecutionConflict,
            )
            .with_details(ControlErrorDetails::ExecutionTarget {
                execution_id: *execution_id,
            }),
            Self::AttributionMismatch => View::unknown(Code::ExecutionProvenanceConflict),
            Self::Clock | Self::InternalInvariant => View::unknown(Code::Internal),
        }
    }
}
