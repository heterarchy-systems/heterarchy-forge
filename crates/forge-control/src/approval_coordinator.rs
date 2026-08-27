use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::thread::{self, JoinHandle};
use std::time::{SystemTime, UNIX_EPOCH};

use forge_domain::{
    ActivityId, ApprovalDecision, ApprovalRequestId, ApprovalRequestState, AutoApprovalScope,
    AutoApprovalScopeId, AutoApprovalScopeRevision, AutoApprovalUseLimit, ExecutionActionClass,
    ExecutionAuthorizationRequest, ExecutionGrantId, ExecutionId, ExecutionKind,
    ExecutionListLimit, ExecutionPermissions, ExecutionPolicyDisposition, ExecutionRequest,
    GoalAttribution, GoalNodeAttribution, GoalWorkAttribution, RegisteredApprovalRequest,
    RequestedExecutionPermissions, RuntimeInstanceId, TimestampMillis, WorkspaceId,
};
use forge_execution::execution_request_digest;
use thiserror::Error;
use uuid::Uuid;

use crate::execution_coordinator::ExecutionCoordinatorStartRequest;
use crate::{
    ApprovalActivityScope, ApprovalCancelActivityRequest, ApprovalCancelWorkspaceRequest,
    ApprovalCreateRequest, ApprovalDecisionRequest, ApprovalOnceRequest, ApprovalReconcileRequest,
    AutoApprovalScopeCreateRequest, AutoApprovalScopeRevokeRequest, ControlClientError,
    ForgeControlClient, ForgeExecutionCoordinatorClient, ForgeExecutionCoordinatorError,
    ResolvedWorkspaceScope,
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

    #[allow(dead_code)]
    pub(crate) fn discovered(
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
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalSubmissionStatus {
    Pending,
    Started,
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
}

impl PendingApprovalProjection {
    fn from_record(record: &RegisteredApprovalRequest) -> Self {
        let request = record.request();
        Self {
            approval_id: record.id(),
            workspace_id: request.workspace_id(),
            activity_id: request.activity_id(),
            execution_id: request.execution_id(),
            action: request.action(),
            expires_at: record.expires_at(),
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
}

#[derive(Debug)]
enum ApprovalCoordinatorRequest {
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
    StopWorkspace {
        workspace_id: WorkspaceId,
        response: Response<usize>,
    },
    StopActivity {
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        response: Response<usize>,
    },
    EmergencyStop {
        response: Response<usize>,
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
            Err(mpsc::TryRecvError::Disconnected) => Err(ForgeApprovalCoordinatorError::Closed),
        }
    }

    pub fn recv(self) -> Result<T, ForgeApprovalCoordinatorError> {
        self.receiver
            .recv()
            .map_err(|_| ForgeApprovalCoordinatorError::Closed)?
    }
}

impl ForgeApprovalCoordinatorClient {
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

    pub fn stop_workspace(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<usize, ForgeApprovalCoordinatorError> {
        self.submit(|response| ApprovalCoordinatorRequest::StopWorkspace {
            workspace_id,
            response,
        })
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
        let report = response_receiver
            .recv()
            .map_err(|_| ForgeApprovalCoordinatorError::Closed)??;
        thread
            .join()
            .map_err(|_| ForgeApprovalCoordinatorError::ThreadPanicked)?;
        Ok(report)
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
}

struct ApprovalRuntime {
    control: ForgeControlClient,
    execution: ForgeExecutionCoordinatorClient,
    receiver: Receiver<ApprovalCoordinatorRequest>,
    accepting: Arc<AtomicBool>,
    pending: HashMap<ApprovalRequestId, PendingPayload>,
    auto_scopes: HashMap<AutoApprovalScopeId, AutoApprovalScope>,
    known_scopes: HashMap<WorkspaceId, ResolvedWorkspaceScope>,
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
            known_scopes: HashMap::new(),
        }
    }

    fn run(mut self) {
        while let Ok(request) = self.receiver.recv() {
            match request {
                ApprovalCoordinatorRequest::Shutdown { response } => {
                    self.accepting.store(false, Ordering::Release);
                    let pending_cancelled = self.pending.len();
                    let result = self.emergency_stop().map(|total_cancelled| {
                        ForgeApprovalCoordinatorShutdown {
                            pending_cancelled,
                            executions_cancelled: total_cancelled.saturating_sub(pending_cancelled),
                        }
                    });
                    self.pending.clear();
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
                let result = self.set_auto_approval(scope, enabled);
                let _ignored = response.send(result);
            }
            ApprovalCoordinatorRequest::StopWorkspace {
                workspace_id,
                response,
            } => {
                let result = self.stop_workspace(workspace_id);
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
            ApprovalCoordinatorRequest::Shutdown { .. } => {}
        }
    }

    fn submit_execution(
        &mut self,
        submit: SubmitExecutionForApproval,
    ) -> Result<ApprovalSubmission, ForgeApprovalCoordinatorError> {
        if submit.request.workspace_id() != submit.scope.workspace_id()
            || submit.request.activity_id() != submit.activity_id
        {
            return Err(ForgeApprovalCoordinatorError::AttributionMismatch);
        }
        self.attach_workspace(submit.scope.clone())?;
        let observed_at = current_timestamp_millis()?;
        let policy = self
            .control
            .ensure_workspace_policy(submit.scope.clone(), observed_at)?;
        let authorization = ExecutionAuthorizationRequest::new(
            submit.request.id(),
            submit.scope.workspace_id(),
            submit.activity_id,
            execution_request_digest(&submit.request),
            submit.action,
            RequestedExecutionPermissions::new(submit.request.permissions()),
        );
        if policy.evaluate(submit.action, authorization.requested())
            == ExecutionPolicyDisposition::AutoEligible
            && let Some(auto_scope) =
                self.find_auto_scope(authorization, policy.revision(), observed_at)
        {
            let approval_id = submit
                .approval_id
                .unwrap_or_else(|| ApprovalRequestId::from_uuid(Uuid::now_v7()));
            let grant_id = ExecutionGrantId::from_uuid(Uuid::now_v7());
            let predicted = auto_scope
                .consume(
                    authorization,
                    policy.revision(),
                    auto_scope.revision(),
                    observed_at,
                )
                .map_err(|_| ForgeApprovalCoordinatorError::AutoScopeUnavailable)?;
            let execution_id = self.execution.start_execution(
                ExecutionCoordinatorStartRequest::new_auto(
                    submit.scope,
                    submit.activity_id,
                    submit.runtime_instance_id,
                    auto_scope.id(),
                    auto_scope.revision(),
                    approval_id,
                    grant_id,
                    authorization,
                    submit.request,
                )
                .with_goal(submit.goal),
            )?;
            self.auto_scopes.insert(predicted.id(), predicted);
            return Ok(ApprovalSubmission {
                status: ApprovalSubmissionStatus::Started,
                approval_id,
                execution_id,
            });
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
                expires_at,
            })?;
        let status = if record.state() == ApprovalRequestState::Denied {
            ApprovalSubmissionStatus::Denied
        } else {
            self.pending.insert(
                approval_id,
                PendingPayload {
                    record: record.clone(),
                    scope: submit.scope,
                    runtime_instance_id: submit.runtime_instance_id,
                    request: submit.request,
                    goal: submit.goal,
                },
            );
            ApprovalSubmissionStatus::Pending
        };
        Ok(ApprovalSubmission {
            status,
            approval_id,
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
                .with_goal(payload.goal),
            )
            .map_err(ForgeApprovalCoordinatorError::from)
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
        let _reconciled =
            self.control
                .reconcile_expired_approval_authority(ApprovalReconcileRequest {
                    scope: scope.clone(),
                    observed_at,
                    limit: approval_limit()?,
                })?;
        self.pending
            .retain(|_, payload| payload.record.expires_at().get() > observed_at.get());
        let records = self
            .control
            .list_pending_approvals(scope.clone(), approval_limit()?)?;
        Ok(records
            .iter()
            .filter(|record| self.pending.contains_key(&record.id()))
            .map(PendingApprovalProjection::from_record)
            .collect())
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
        self.attach_workspace(request.scope.clone())?;
        let scope = self.control.create_auto_approval_scope(request)?;
        self.auto_scopes.insert(scope.id(), scope.clone());
        Ok(scope)
    }

    fn set_auto_approval(
        &mut self,
        scope: ResolvedWorkspaceScope,
        enabled: bool,
    ) -> Result<bool, ForgeApprovalCoordinatorError> {
        self.attach_workspace(scope.clone())?;
        if !enabled {
            let scopes: Vec<_> = self
                .auto_scopes
                .values()
                .filter(|value| value.workspace_id() == scope.workspace_id())
                .cloned()
                .collect();
            for auto_scope in scopes {
                let _revoked =
                    self.control
                        .revoke_auto_approval_scope(AutoApprovalScopeRevokeRequest {
                            scope: scope.clone(),
                            auto_scope_id: auto_scope.id(),
                            expected_revision: auto_scope.revision(),
                            observed_at: current_timestamp_millis()?,
                        })?;
            }
            self.auto_scopes
                .retain(|_, value| value.workspace_id() != scope.workspace_id());
            return Ok(false);
        }
        let observed_at = current_timestamp_millis()?;
        let policy = self
            .control
            .ensure_workspace_policy(scope.clone(), observed_at)?;
        let auto_scope = AutoApprovalScope::active(
            AutoApprovalScopeId::from_uuid(Uuid::now_v7()),
            scope.workspace_id(),
            None,
            ExecutionActionClass::DiscoveredProjectCommand,
            ExecutionPermissions::new(true, false, false),
            policy.revision(),
            add_millis(observed_at, APPROVAL_WINDOW_MILLIS)?,
            AutoApprovalUseLimit::new(10)
                .map_err(|_| ForgeApprovalCoordinatorError::InternalInvariant)?,
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
        self.auto_scopes.insert(registered.id(), registered);
        Ok(true)
    }

    fn find_auto_scope(
        &self,
        request: ExecutionAuthorizationRequest,
        policy_revision: forge_domain::PolicyRevision,
        observed_at: TimestampMillis,
    ) -> Option<AutoApprovalScope> {
        self.auto_scopes
            .values()
            .find(|scope| scope.covers(request, policy_revision, observed_at))
            .cloned()
    }

    fn attach_workspace(
        &mut self,
        scope: ResolvedWorkspaceScope,
    ) -> Result<(), ForgeApprovalCoordinatorError> {
        if self.known_scopes.contains_key(&scope.workspace_id()) {
            return Ok(());
        }
        // Raw command payloads are intentionally memory-only. Any authority
        // left by an earlier runtime instance is therefore non-resumable and
        // is cancelled before this runtime admits new work.
        cleanup_workspace(&self.control, &scope)?;
        self.known_scopes.insert(scope.workspace_id(), scope);
        Ok(())
    }

    fn stop_workspace(
        &mut self,
        workspace_id: WorkspaceId,
    ) -> Result<usize, ForgeApprovalCoordinatorError> {
        let pending_before = self.pending.len();
        if let Some(scope) = self.known_scopes.get(&workspace_id).cloned() {
            cleanup_workspace(&self.control, &scope)?;
        }
        self.pending
            .retain(|_, payload| payload.scope.workspace_id() != workspace_id);
        self.auto_scopes
            .retain(|_, scope| scope.workspace_id() != workspace_id);
        let executions = self.execution.stop_workspace(workspace_id)?;
        Ok(pending_before - self.pending.len() + executions)
    }

    fn stop_activity(
        &mut self,
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
    ) -> Result<usize, ForgeApprovalCoordinatorError> {
        let pending_before = self.pending.len();
        if let Some(scope) = self.known_scopes.get(&workspace_id).cloned() {
            let _cleanup =
                self.control
                    .cancel_activity_approval_authority(ApprovalCancelActivityRequest {
                        scope,
                        activity_id,
                        observed_at: current_timestamp_millis()?,
                        limit: approval_limit()?,
                    })?;
        }
        self.pending.retain(|_, payload| {
            payload.scope.workspace_id() != workspace_id
                || payload.record.request().activity_id() != activity_id
        });
        self.auto_scopes.retain(|_, scope| {
            scope.workspace_id() != workspace_id || scope.activity_id() != Some(activity_id)
        });
        let executions = self.execution.stop_activity(workspace_id, activity_id)?;
        Ok(pending_before - self.pending.len() + executions)
    }

    fn emergency_stop(&mut self) -> Result<usize, ForgeApprovalCoordinatorError> {
        let pending = self.pending.len();
        for scope in self.known_scopes.values() {
            cleanup_workspace(&self.control, scope)?;
        }
        self.pending.clear();
        self.auto_scopes.clear();
        let executions = self.execution.stop_all()?;
        Ok(pending + executions)
    }
}

fn cleanup_workspace(
    control: &ForgeControlClient,
    scope: &ResolvedWorkspaceScope,
) -> Result<(), ForgeApprovalCoordinatorError> {
    for _ in 0..CLEANUP_ROUNDS {
        let report =
            control.cancel_workspace_approval_authority(ApprovalCancelWorkspaceRequest {
                scope: scope.clone(),
                observed_at: current_timestamp_millis()?,
                limit: approval_limit()?,
            })?;
        if report.total() == 0 {
            return Ok(());
        }
    }
    Err(ForgeApprovalCoordinatorError::CleanupIncomplete)
}

fn approval_limit() -> Result<ExecutionListLimit, ForgeApprovalCoordinatorError> {
    ExecutionListLimit::new(CLEANUP_LIMIT)
        .map_err(|_| ForgeApprovalCoordinatorError::InternalInvariant)
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
    #[error("auto approval scope capacity is full")]
    AutoScopeCapacity,
    #[error("auto approval scope is unavailable")]
    AutoScopeUnavailable,
    #[error("approval cleanup did not converge within its bound")]
    CleanupIncomplete,
    #[error("approval request attribution is invalid")]
    AttributionMismatch,
    #[error("approval coordinator clock is unavailable")]
    Clock,
    #[error("approval coordinator invariant failed")]
    InternalInvariant,
    #[error(transparent)]
    Control(#[from] ControlClientError),
    #[error(transparent)]
    Execution(#[from] ForgeExecutionCoordinatorError),
}
