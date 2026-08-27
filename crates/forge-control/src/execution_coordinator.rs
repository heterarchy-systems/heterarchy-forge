use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use forge_domain::{
    ActivityId, ApprovalRequestId, AutoApprovalScopeId, AutoApprovalScopeRevision, BeginExecution,
    CompleteExecution, ExecutionAuthorizationRequest, ExecutionFailureCode, ExecutionGrantId,
    ExecutionGrantRevision, ExecutionId, ExecutionRequest, ExecutionRevision, FailExecution,
    GoalWorkAttribution, MarkExecutionRunning, RuntimeInstanceId, TimestampMillis, WorkspaceId,
};
use forge_execution::{
    ExecutionSupervisor, ExecutionSupervisorError, ExecutionSupervisorEvent,
    execution_request_digest,
};
use thiserror::Error;

use crate::{
    ApprovalActivityScope, ApprovalGrantConsumeRequest, AutoApprovalConsumeRequest,
    ControlClientError, ForgeControlClient, ResolvedWorkspaceScope,
};

const COORDINATOR_QUEUE_CAPACITY: usize = 16;
const MAX_TERMINAL_BACKLOG: usize = 64;
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const STOP_DEADLINE: Duration = Duration::from_secs(2);
const THREAD_NAME: &str = "heterarchy-forge-execution-coordinator";

type Response<T> = SyncSender<Result<T, ForgeExecutionCoordinatorError>>;

#[derive(Debug)]
enum CoordinatorRequest {
    Start {
        request: Box<ExecutionCoordinatorStartRequest>,
        response: Response<ExecutionId>,
    },
    Cancel {
        id: ExecutionId,
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
    StopAll {
        response: Response<usize>,
    },
    Shutdown {
        response: Response<ForgeExecutionCoordinatorShutdown>,
    },
}

#[derive(Debug)]
pub(crate) struct ExecutionCoordinatorStartRequest {
    scope: ResolvedWorkspaceScope,
    activity_id: ActivityId,
    runtime_instance_id: RuntimeInstanceId,
    authorization: CoordinatorAuthorization,
    authorization_request: ExecutionAuthorizationRequest,
    request: ExecutionRequest,
    goal: Option<GoalWorkAttribution>,
}

impl ExecutionCoordinatorStartRequest {
    // Plan 07's grant-consumption service is the intended production caller;
    // the constructor stays crate-private so adapters cannot bypass approval.
    pub(crate) fn new_explicit(
        scope: ResolvedWorkspaceScope,
        activity_id: ActivityId,
        runtime_instance_id: RuntimeInstanceId,
        grant_id: ExecutionGrantId,
        grant_revision: ExecutionGrantRevision,
        authorization_request: ExecutionAuthorizationRequest,
        request: ExecutionRequest,
    ) -> Self {
        Self {
            scope,
            activity_id,
            runtime_instance_id,
            authorization: CoordinatorAuthorization::Explicit {
                grant_id,
                grant_revision,
            },
            authorization_request,
            request,
            goal: None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_auto(
        scope: ResolvedWorkspaceScope,
        activity_id: ActivityId,
        runtime_instance_id: RuntimeInstanceId,
        auto_scope_id: AutoApprovalScopeId,
        auto_scope_revision: AutoApprovalScopeRevision,
        approval_id: ApprovalRequestId,
        grant_id: ExecutionGrantId,
        authorization_request: ExecutionAuthorizationRequest,
        request: ExecutionRequest,
    ) -> Self {
        Self {
            scope,
            activity_id,
            runtime_instance_id,
            authorization: CoordinatorAuthorization::Auto {
                auto_scope_id,
                auto_scope_revision,
                approval_id,
                grant_id,
            },
            authorization_request,
            request,
            goal: None,
        }
    }

    pub(crate) fn with_goal(mut self, goal: Option<GoalWorkAttribution>) -> Self {
        self.goal = goal;
        self
    }
}

#[derive(Debug, Clone, Copy)]
enum CoordinatorAuthorization {
    Explicit {
        grant_id: ExecutionGrantId,
        grant_revision: ExecutionGrantRevision,
    },
    Auto {
        auto_scope_id: AutoApprovalScopeId,
        auto_scope_revision: AutoApprovalScopeRevision,
        approval_id: ApprovalRequestId,
        grant_id: ExecutionGrantId,
    },
}

#[derive(Debug, Clone)]
pub struct ForgeExecutionCoordinatorClient {
    sender: SyncSender<CoordinatorRequest>,
    accepting: Arc<AtomicBool>,
}

impl ForgeExecutionCoordinatorClient {
    pub(crate) fn start_execution(
        &self,
        request: ExecutionCoordinatorStartRequest,
    ) -> Result<ExecutionId, ForgeExecutionCoordinatorError> {
        self.submit(|response| CoordinatorRequest::Start {
            request: Box::new(request),
            response,
        })
    }

    pub fn cancel_execution(
        &self,
        id: ExecutionId,
    ) -> Result<bool, ForgeExecutionCoordinatorError> {
        self.submit(|response| CoordinatorRequest::Cancel { id, response })
    }

    pub fn stop_workspace(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<usize, ForgeExecutionCoordinatorError> {
        self.submit(|response| CoordinatorRequest::StopWorkspace {
            workspace_id,
            response,
        })
    }

    pub fn stop_activity(
        &self,
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
    ) -> Result<usize, ForgeExecutionCoordinatorError> {
        self.submit(|response| CoordinatorRequest::StopActivity {
            workspace_id,
            activity_id,
            response,
        })
    }

    pub fn stop_all(&self) -> Result<usize, ForgeExecutionCoordinatorError> {
        self.submit(|response| CoordinatorRequest::StopAll { response })
    }

    fn submit<T>(
        &self,
        build: impl FnOnce(Response<T>) -> CoordinatorRequest,
    ) -> Result<T, ForgeExecutionCoordinatorError> {
        if !self.accepting.load(Ordering::Acquire) {
            return Err(ForgeExecutionCoordinatorError::Closed);
        }
        let (response_sender, response_receiver) = mpsc::sync_channel(0);
        match self.sender.try_send(build(response_sender)) {
            Ok(()) => response_receiver
                .recv()
                .map_err(|_| ForgeExecutionCoordinatorError::Closed)?,
            Err(TrySendError::Full(_)) => Err(ForgeExecutionCoordinatorError::QueueFull),
            Err(TrySendError::Disconnected(_)) => Err(ForgeExecutionCoordinatorError::Closed),
        }
    }
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForgeExecutionCoordinatorShutdown {
    cancelled: usize,
    terminal_records: usize,
}

impl ForgeExecutionCoordinatorShutdown {
    pub const fn cancelled(self) -> usize {
        self.cancelled
    }

    pub const fn terminal_records(self) -> usize {
        self.terminal_records
    }
}

#[derive(Debug)]
pub struct ForgeExecutionCoordinator {
    client: ForgeExecutionCoordinatorClient,
    thread: Option<JoinHandle<()>>,
}

impl ForgeExecutionCoordinator {
    pub fn start(
        control: ForgeControlClient,
        maximum: usize,
    ) -> Result<Self, ForgeExecutionCoordinatorError> {
        let supervisor = ExecutionSupervisor::start(maximum)?;
        let (sender, receiver) = mpsc::sync_channel(COORDINATOR_QUEUE_CAPACITY);
        let accepting = Arc::new(AtomicBool::new(true));
        let runtime_accepting = Arc::clone(&accepting);
        let thread = thread::Builder::new()
            .name(THREAD_NAME.to_owned())
            .spawn(move || {
                CoordinatorRuntime::new(control, supervisor, receiver, runtime_accepting).run();
            })
            .map_err(ForgeExecutionCoordinatorError::SpawnThread)?;
        Ok(Self {
            client: ForgeExecutionCoordinatorClient { sender, accepting },
            thread: Some(thread),
        })
    }

    pub fn client(&self) -> ForgeExecutionCoordinatorClient {
        self.client.clone()
    }

    pub fn shutdown(
        &mut self,
    ) -> Result<ForgeExecutionCoordinatorShutdown, ForgeExecutionCoordinatorError> {
        self.client.accepting.store(false, Ordering::Release);
        let Some(thread) = self.thread.take() else {
            return Err(ForgeExecutionCoordinatorError::AlreadyShutdown);
        };
        let (response_sender, response_receiver) = mpsc::sync_channel(0);
        if self
            .client
            .sender
            .send(CoordinatorRequest::Shutdown {
                response: response_sender,
            })
            .is_err()
        {
            return match thread.join() {
                Ok(()) => Err(ForgeExecutionCoordinatorError::Closed),
                Err(_) => Err(ForgeExecutionCoordinatorError::ThreadPanicked),
            };
        }
        let report = response_receiver
            .recv()
            .map_err(|_| ForgeExecutionCoordinatorError::Closed)??;
        thread
            .join()
            .map_err(|_| ForgeExecutionCoordinatorError::ThreadPanicked)?;
        Ok(report)
    }
}

impl Drop for ForgeExecutionCoordinator {
    fn drop(&mut self) {
        if self.thread.is_some() {
            let _ignored = self.shutdown();
        }
    }
}

#[derive(Debug, Clone)]
struct ActiveExecution {
    scope: ResolvedWorkspaceScope,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    revision: ExecutionRevision,
}

struct CoordinatorRuntime {
    control: ForgeControlClient,
    supervisor: ExecutionSupervisor,
    receiver: Receiver<CoordinatorRequest>,
    accepting: Arc<AtomicBool>,
    active: HashMap<ExecutionId, ActiveExecution>,
    known_scopes: HashMap<WorkspaceId, ResolvedWorkspaceScope>,
    terminal_backlog: VecDeque<ExecutionSupervisorEvent>,
    terminal_records: usize,
    journal_failed: bool,
}

impl CoordinatorRuntime {
    fn new(
        control: ForgeControlClient,
        supervisor: ExecutionSupervisor,
        receiver: Receiver<CoordinatorRequest>,
        accepting: Arc<AtomicBool>,
    ) -> Self {
        Self {
            control,
            supervisor,
            receiver,
            accepting,
            active: HashMap::new(),
            known_scopes: HashMap::new(),
            terminal_backlog: VecDeque::new(),
            terminal_records: 0,
            journal_failed: false,
        }
    }

    fn run(mut self) {
        loop {
            self.poll_and_journal();
            match self.receiver.recv_timeout(POLL_INTERVAL) {
                Ok(CoordinatorRequest::Shutdown { response }) => {
                    self.accepting.store(false, Ordering::Release);
                    let result = self.stop_all_and_journal().and_then(|cancelled| {
                        let supervisor_report = self.supervisor.shutdown()?;
                        if !supervisor_report.events().is_empty() {
                            return Err(ForgeExecutionCoordinatorError::JournalFailed);
                        }
                        Ok(ForgeExecutionCoordinatorShutdown {
                            cancelled,
                            terminal_records: self.terminal_records,
                        })
                    });
                    let _ignored = response.send(result);
                    break;
                }
                Ok(request) => self.handle_request(request),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    self.accepting.store(false, Ordering::Release);
                    let _ignored = self.stop_all_and_journal();
                    let _ignored = self.supervisor.shutdown();
                    break;
                }
            }
        }
        self.accepting.store(false, Ordering::Release);
    }

    fn handle_request(&mut self, request: CoordinatorRequest) {
        match request {
            CoordinatorRequest::Start { request, response } => {
                let result = self.start_execution(*request);
                let _ignored = response.send(result);
            }
            CoordinatorRequest::Cancel { id, response } => {
                let result = self.cancel_execution(id);
                let _ignored = response.send(result);
            }
            CoordinatorRequest::StopWorkspace {
                workspace_id,
                response,
            } => {
                let result = self.stop_workspace_and_journal(workspace_id);
                let _ignored = response.send(result);
            }
            CoordinatorRequest::StopActivity {
                workspace_id,
                activity_id,
                response,
            } => {
                let result = self.stop_activity_and_journal(workspace_id, activity_id);
                let _ignored = response.send(result);
            }
            CoordinatorRequest::StopAll { response } => {
                let result = self.stop_all_and_journal();
                let _ignored = response.send(result);
            }
            CoordinatorRequest::Shutdown { .. } => {}
        }
    }

    fn start_execution(
        &mut self,
        start: ExecutionCoordinatorStartRequest,
    ) -> Result<ExecutionId, ForgeExecutionCoordinatorError> {
        if self.journal_failed {
            return Err(ForgeExecutionCoordinatorError::JournalFailed);
        }
        let id = start.request.id();
        if self.active.contains_key(&id) {
            return Err(ForgeExecutionCoordinatorError::DuplicateExecution(id));
        }
        validate_start_request(&start)?;
        let observed_at = current_timestamp_millis()?;
        let begin = BeginExecution::from_request(
            &start.request,
            start.authorization_request.request_digest(),
            observed_at,
        );
        let activity = ApprovalActivityScope {
            activity_id: start.activity_id,
            runtime_instance_id: start.runtime_instance_id,
            observed_at,
        };
        let (layout, begin_revision) = self.consume_authorization(&start, activity, begin)?;
        let running = self.control.execution_mark_running(
            start.scope.clone(),
            MarkExecutionRunning::new(id, begin_revision, current_timestamp_millis()?),
        )?;
        if let Err(error) = self
            .supervisor
            .client()
            .start_execution(layout, start.request)
        {
            let _failed = self.control.execution_fail(
                start.scope,
                FailExecution::new(
                    id,
                    running.revision(),
                    current_timestamp_millis()?,
                    error.execution_failure_code(),
                ),
            );
            return Err(error.into());
        }
        self.active.insert(
            id,
            ActiveExecution {
                workspace_id: start.scope.workspace_id(),
                activity_id: start.activity_id,
                scope: start.scope.clone(),
                revision: running.revision(),
            },
        );
        self.known_scopes
            .insert(start.scope.workspace_id(), start.scope.clone());
        Ok(id)
    }

    fn consume_authorization(
        &self,
        start: &ExecutionCoordinatorStartRequest,
        activity: ApprovalActivityScope,
        begin: BeginExecution,
    ) -> Result<
        (
            forge_workspace::ExistingWorkspaceStateLayout,
            ExecutionRevision,
        ),
        ForgeExecutionCoordinatorError,
    > {
        match start.authorization {
            CoordinatorAuthorization::Explicit {
                grant_id,
                grant_revision,
            } => {
                let admission =
                    self.control
                        .consume_execution_grant(ApprovalGrantConsumeRequest {
                            scope: start.scope.clone(),
                            activity,
                            goal: start.goal,
                            grant_id,
                            expected_grant_revision: grant_revision,
                            request: start.authorization_request,
                            begin,
                        })?;
                Ok((
                    admission.layout().clone(),
                    admission.begin().record().revision(),
                ))
            }
            CoordinatorAuthorization::Auto {
                auto_scope_id,
                auto_scope_revision,
                approval_id,
                grant_id,
            } => {
                let admission = self
                    .control
                    .consume_auto_approval(AutoApprovalConsumeRequest {
                        scope: start.scope.clone(),
                        activity,
                        goal: start.goal,
                        auto_scope_id,
                        expected_scope_revision: auto_scope_revision,
                        approval_id,
                        grant_id,
                        request: start.authorization_request,
                        begin,
                    })?;
                Ok((
                    admission.layout().clone(),
                    admission.record().begin().record().revision(),
                ))
            }
        }
    }

    fn cancel_execution(
        &mut self,
        id: ExecutionId,
    ) -> Result<bool, ForgeExecutionCoordinatorError> {
        let requested = self.supervisor.client().cancel_execution(id)?;
        if requested {
            self.wait_for(|active_id, _| active_id == id)?;
        }
        Ok(requested)
    }

    fn stop_workspace_and_journal(
        &mut self,
        workspace_id: WorkspaceId,
    ) -> Result<usize, ForgeExecutionCoordinatorError> {
        if let Some(scope) = self.known_scopes.get(&workspace_id).cloned() {
            let _cleanup = self.control.cancel_workspace_approval_authority(
                crate::ApprovalCancelWorkspaceRequest {
                    scope,
                    observed_at: current_timestamp_millis()?,
                    limit: forge_domain::ExecutionListLimit::new(256)
                        .map_err(|_| ForgeExecutionCoordinatorError::JournalFailed)?,
                },
            )?;
        }
        let requested = self.supervisor.client().cancel_workspace(workspace_id)?;
        if requested > 0 {
            self.wait_for(|_, active| active.workspace_id == workspace_id)?;
        }
        Ok(requested)
    }

    fn stop_activity_and_journal(
        &mut self,
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
    ) -> Result<usize, ForgeExecutionCoordinatorError> {
        if let Some(scope) = self.known_scopes.get(&workspace_id).cloned() {
            let _cleanup = self.control.cancel_activity_approval_authority(
                crate::ApprovalCancelActivityRequest {
                    scope,
                    activity_id,
                    observed_at: current_timestamp_millis()?,
                    limit: forge_domain::ExecutionListLimit::new(256)
                        .map_err(|_| ForgeExecutionCoordinatorError::JournalFailed)?,
                },
            )?;
        }
        let ids: Vec<_> = self
            .active
            .iter()
            .filter_map(|(id, active)| {
                (active.workspace_id == workspace_id && active.activity_id == activity_id)
                    .then_some(*id)
            })
            .collect();
        let mut requested = 0;
        for id in ids {
            requested += usize::from(self.supervisor.client().cancel_execution(id)?);
        }
        if requested > 0 {
            self.wait_for(|_, active| {
                active.workspace_id == workspace_id && active.activity_id == activity_id
            })?;
        }
        Ok(requested)
    }

    fn stop_all_and_journal(&mut self) -> Result<usize, ForgeExecutionCoordinatorError> {
        for scope in self.known_scopes.values().cloned() {
            let _cleanup = self.control.cancel_workspace_approval_authority(
                crate::ApprovalCancelWorkspaceRequest {
                    scope,
                    observed_at: current_timestamp_millis()?,
                    limit: forge_domain::ExecutionListLimit::new(256)
                        .map_err(|_| ForgeExecutionCoordinatorError::JournalFailed)?,
                },
            )?;
        }
        let requested = self.supervisor.client().stop_all()?;
        self.wait_for(|_, _| true)?;
        Ok(requested)
    }

    fn wait_for(
        &mut self,
        keep_waiting: impl Fn(ExecutionId, &ActiveExecution) -> bool,
    ) -> Result<(), ForgeExecutionCoordinatorError> {
        let deadline = Instant::now() + STOP_DEADLINE;
        while self
            .active
            .iter()
            .any(|(id, active)| keep_waiting(*id, active))
        {
            self.poll_and_journal();
            if self.journal_failed {
                return Err(ForgeExecutionCoordinatorError::JournalFailed);
            }
            if Instant::now() >= deadline {
                return Err(ForgeExecutionCoordinatorError::JournalTimeout);
            }
            thread::sleep(POLL_INTERVAL);
        }
        Ok(())
    }

    fn poll_and_journal(&mut self) {
        if self.terminal_backlog.len() < MAX_TERMINAL_BACKLOG
            && let Ok(events) = self.supervisor.client().drain_events(MAX_TERMINAL_BACKLOG)
        {
            self.terminal_backlog.extend(events);
        }
        while let Some(event) = self.terminal_backlog.pop_front() {
            let retry = event.clone();
            match self.journal_terminal(event) {
                Ok(()) => self.terminal_records += 1,
                Err(ControlClientError::QueueFull) => {
                    self.terminal_backlog.push_front(retry);
                    break;
                }
                Err(_) => {
                    self.terminal_backlog.push_front(retry);
                    self.journal_failed = true;
                    break;
                }
            }
        }
    }

    fn journal_terminal(
        &mut self,
        event: ExecutionSupervisorEvent,
    ) -> Result<(), ControlClientError> {
        let id = event.execution_id();
        let active = self.active.get(&id).ok_or_else(|| {
            ControlClientError::Service(crate::ControlError::new(
                crate::ControlErrorCode::ExecutionConflict,
            ))
        })?;
        match event.into_result() {
            Ok(outcome) => {
                let _record = self.control.execution_complete(
                    active.scope.clone(),
                    CompleteExecution::new(
                        active.revision,
                        current_timestamp_millis().map_err(|_| {
                            ControlClientError::Service(crate::ControlError::new(
                                crate::ControlErrorCode::Internal,
                            ))
                        })?,
                        outcome,
                    ),
                )?;
            }
            Err(failure) => {
                let _record = self.control.execution_fail(
                    active.scope.clone(),
                    FailExecution::new(
                        id,
                        active.revision,
                        current_timestamp_millis().map_err(|_| {
                            ControlClientError::Service(crate::ControlError::new(
                                crate::ControlErrorCode::Internal,
                            ))
                        })?,
                        failure,
                    ),
                )?;
            }
        }
        self.active.remove(&id);
        Ok(())
    }
}

fn validate_start_request(
    start: &ExecutionCoordinatorStartRequest,
) -> Result<(), ForgeExecutionCoordinatorError> {
    if start.request.workspace_id() != start.scope.workspace_id()
        || start.request.activity_id() != start.activity_id
        || start.authorization_request.execution_id() != start.request.id()
        || start.authorization_request.workspace_id() != start.scope.workspace_id()
        || start.authorization_request.activity_id() != start.activity_id
        || start.authorization_request.request_digest() != execution_request_digest(&start.request)
        || start.authorization_request.requested().get() != start.request.permissions()
    {
        Err(ForgeExecutionCoordinatorError::AttributionMismatch)
    } else {
        Ok(())
    }
}

fn current_timestamp_millis() -> Result<TimestampMillis, ForgeExecutionCoordinatorError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ForgeExecutionCoordinatorError::Clock)?;
    let millis =
        i64::try_from(elapsed.as_millis()).map_err(|_| ForgeExecutionCoordinatorError::Clock)?;
    TimestampMillis::new(millis).map_err(|_| ForgeExecutionCoordinatorError::Clock)
}

trait SupervisorFailureCode {
    fn execution_failure_code(&self) -> ExecutionFailureCode;
}

impl SupervisorFailureCode for ExecutionSupervisorError {
    fn execution_failure_code(&self) -> ExecutionFailureCode {
        match self {
            ExecutionSupervisorError::Execution(error) => error.failure_code(),
            ExecutionSupervisorError::QueueFull
            | ExecutionSupervisorError::CompletionBacklog
            | ExecutionSupervisorError::Draining
            | ExecutionSupervisorError::DuplicateExecution(_)
            | ExecutionSupervisorError::InvalidDrainLimit { .. }
            | ExecutionSupervisorError::AlreadyShutdown
            | ExecutionSupervisorError::Closed
            | ExecutionSupervisorError::SpawnThread(_)
            | ExecutionSupervisorError::ThreadPanicked => ExecutionFailureCode::Supervision,
        }
    }
}

#[derive(Debug, Error)]
pub enum ForgeExecutionCoordinatorError {
    #[error("execution coordinator queue is full")]
    QueueFull,
    #[error("execution coordinator is closed")]
    Closed,
    #[error("execution coordinator is already shut down")]
    AlreadyShutdown,
    #[error("failed to spawn execution coordinator thread")]
    SpawnThread(#[source] std::io::Error),
    #[error("execution coordinator thread panicked")]
    ThreadPanicked,
    #[error("Execution {0} is already active")]
    DuplicateExecution(ExecutionId),
    #[error("Execution {0} requires recovery and will not be replayed")]
    RecoveryRequired(ExecutionId),
    #[error("execution attribution does not match its Workspace or Activity")]
    AttributionMismatch,
    #[error("execution terminal journal failed")]
    JournalFailed,
    #[error("execution terminal journal did not complete within its bound")]
    JournalTimeout,
    #[error("execution authority clock is unavailable")]
    Clock,
    #[error(transparent)]
    Control(#[from] ControlClientError),
    #[error(transparent)]
    Supervisor(#[from] ExecutionSupervisorError),
}
