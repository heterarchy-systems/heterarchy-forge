use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::future::Future;
use std::num::NonZeroU64;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TryRecvError, TrySendError};
use std::sync::{Condvar, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use forge_domain::{
    ActivityId, ApprovalRequestId, AutoApprovalScopeId, AutoApprovalScopeRevision, BeginExecution,
    CompleteExecution, ExecutionActionClass, ExecutionAuthorizationRequest, ExecutionFailureCode,
    ExecutionGrantId, ExecutionGrantRevision, ExecutionId, ExecutionKind, ExecutionOutputCursor,
    ExecutionOutputEvent, ExecutionOutputEventKey, ExecutionOutputRead, ExecutionRequest,
    ExecutionRevision, ExecutionState, FailExecution, GoalWorkAttribution, MarkExecutionRunning,
    ProjectCommandClass, ProjectCommandEvidence, RegisteredExecution,
    RequestedExecutionPermissions, RuntimeInstanceId, TimestampMillis, WorkspaceId,
};
use forge_execution::{
    ExecutionLaunchKind, ExecutionSupervisor, ExecutionSupervisorError, ExecutionSupervisorEvent,
    PackageVExecutableCapability, RustCiDiscoveryError, RustCiToolchainCapability,
    SupervisorStartIdentity, SupervisorStartOutcome, SupervisorStartReceipt, TerminalEventKey,
    execution_request_digest,
};
use forge_workspace::PublishedVerificationInput;
use thiserror::Error;

mod journal_failure;
mod workspace_stop;
pub use journal_failure::{JournalFailure, JournalFailureStage, JournalPersistenceFailure};
pub use workspace_stop::WorkspaceExecutionStopObservation;
mod owned_workspace_stop;
pub use owned_workspace_stop::OwnedWorkspaceExecutionStopObservation;
mod pre_spawn_rejection;
mod start_diagnostic;

use crate::command::{
    ProjectCommandId, ProjectCommandListRequest, is_exact_project_verify_request,
    is_exact_research_package_request, is_exact_rust_generated_package_request,
};
use crate::execution_journal::{
    ExecutionJournalAuthority, JournalReadback, JournalTerminalCommand,
};
use crate::{
    AgentExecutionAuthorityRequest, ApprovalActivityScope, ApprovalGrantConsumeRequest,
    AutoApprovalConsumeRequest, ControlClientError, FileActivityScope, ForgeControlClient,
    ResolvedWorkspaceScope,
};

const COORDINATOR_QUEUE_CAPACITY: usize = 16;
const MAX_TERMINAL_BACKLOG: usize = 64;
/// Maximum number of durable execution waits retained by the coordinator.
///
/// A wait occupies one response slot until it observes a journaled change or
/// its deadline.  Keeping this separate from the request queue prevents a
/// burst of long polls from becoming hidden, unbounded coordinator state.
pub(crate) const MAX_EXECUTION_WAITERS: usize = 16;
/// Cancellation messages have their own bounded lane so a saturated request
/// queue cannot delay a caller's best-effort cancellation signal.
const EXECUTION_WAIT_CANCELLATION_CAPACITY: usize = 32;
/// Long-poll budget accepted by the execution coordinator.
pub(crate) const MAX_EXECUTION_WAIT_TIMEOUT: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const STOP_DEADLINE: Duration = Duration::from_secs(2);
const THREAD_NAME: &str = "heterarchy-forge-execution-coordinator";

const EXECUTION_WAIT_PENDING: u8 = 0;
const EXECUTION_WAIT_CANCELLED: u8 = 1;
const EXECUTION_WAIT_COMPLETED: u8 = 2;

/// Non-zero identity for one admitted execution wait.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ExecutionWaiterId(NonZeroU64);

impl ExecutionWaiterId {
    pub const fn new(value: u64) -> Option<Self> {
        match NonZeroU64::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Fully typed parameters for one authorization-scoped execution wait.
#[must_use]
#[derive(Debug, Clone)]
pub struct ExecutionWaitParameters {
    authority: AgentExecutionAuthorityRequest,
    id: ExecutionId,
    cursor: ExecutionOutputCursor,
    max_bytes: u64,
    max_events: usize,
    timeout: Duration,
}

impl ExecutionWaitParameters {
    pub fn new(
        authority: AgentExecutionAuthorityRequest,
        id: ExecutionId,
        cursor: ExecutionOutputCursor,
        max_bytes: u64,
        max_events: usize,
        timeout: Duration,
    ) -> Self {
        Self {
            authority,
            id,
            cursor,
            max_bytes,
            max_events,
            timeout,
        }
    }
}

type ExecutionWaitCancellation = ExecutionWaiterId;

type Response<T> = SyncSender<Result<T, ForgeExecutionCoordinatorError>>;

#[derive(Debug)]
enum CoordinatorRequest {
    Start {
        request: Box<ExecutionCoordinatorStartRequest>,
        response: Response<ExecutionStartResult>,
    },
    Cancel {
        id: ExecutionId,
        response: Response<bool>,
    },
    CancelAgent {
        authority: Box<AgentExecutionAuthorityRequest>,
        id: ExecutionId,
        response: Response<bool>,
    },
    StopWorkspace {
        workspace_id: WorkspaceId,
        response: Response<usize>,
    },
    StopWorkspaceDurable {
        scope: ResolvedWorkspaceScope,
        request: Box<forge_persistence::ExecutionStopRequest>,
        response: Response<WorkspaceExecutionStopObservation>,
    },
    StopOwnedWorkspaceDurable {
        permit: Box<crate::approval_cleanup::ApprovalCleanupPermit>,
        owner: crate::approval_cleanup::ApprovalCleanupOwner,
        request: Box<forge_persistence::ExecutionStopRequest>,
        response: Response<OwnedWorkspaceExecutionStopObservation>,
    },
    StopActivity {
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        response: Response<usize>,
    },
    StopAll {
        response: Response<usize>,
    },
    WaitExecutionOutputAuthorizedAsync {
        request: Box<AsyncExecutionWaitRequest>,
    },
    /// Wakes the coordinator's otherwise blocking idle receive after a wait
    /// handle is cancelled.  The cancellation itself is carried by the
    /// dedicated cancellation channel and the bridge's atomic state.
    WaitCancellationWake,
    Shutdown,
}

/// Shared completion state for an execution wait.
///
/// The state transition is the linearization point for cancellation and
/// completion.  Completion is stored in one bounded slot and delivered to a
/// Future poll or a synchronous Condvar wait; the coordinator never invokes
/// caller-supplied code and never blocks while publishing a result.
struct ExecutionWaitCompletionBridge {
    state: Arc<AtomicU8>,
    slot: Mutex<ExecutionWaitCompletionSlot>,
    condvar: Condvar,
}

struct ExecutionWaitCompletionSlot {
    result: Option<Result<ExecutionWaitResult, ForgeExecutionCoordinatorError>>,
    waker: Option<Waker>,
}

impl fmt::Debug for ExecutionWaitCompletionBridge {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutionWaitCompletionBridge")
            .field("state", &self.state.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

impl ExecutionWaitCompletionBridge {
    fn new() -> Self {
        Self {
            state: Arc::new(AtomicU8::new(EXECUTION_WAIT_PENDING)),
            slot: Mutex::new(ExecutionWaitCompletionSlot {
                result: None,
                waker: None,
            }),
            condvar: Condvar::new(),
        }
    }

    fn complete(&self, result: Result<ExecutionWaitResult, ForgeExecutionCoordinatorError>) {
        if self
            .state
            .compare_exchange(
                EXECUTION_WAIT_PENDING,
                EXECUTION_WAIT_COMPLETED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return;
        }
        let waker = {
            let mut slot = self.lock_slot();
            slot.result = Some(result);
            slot.waker.take()
        };
        self.condvar.notify_all();
        wake_without_panicking(waker);
    }

    fn cancel(&self) -> bool {
        let cancelled = self
            .state
            .compare_exchange(
                EXECUTION_WAIT_PENDING,
                EXECUTION_WAIT_CANCELLED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok();
        if !cancelled {
            return false;
        }
        let _waker = self.lock_slot().waker.take();
        self.condvar.notify_all();
        true
    }

    fn wait(&self) -> Result<ExecutionWaitResult, ForgeExecutionCoordinatorError> {
        let mut slot = self.lock_slot();
        loop {
            if let Some(result) = slot.result.take() {
                return result;
            }
            if self.state.load(Ordering::Acquire) == EXECUTION_WAIT_CANCELLED {
                return Err(ForgeExecutionCoordinatorError::Closed);
            }
            slot = match self.condvar.wait(slot) {
                Ok(slot) => slot,
                Err(poisoned) => poisoned.into_inner(),
            };
        }
    }

    fn poll(
        &self,
        context: &mut Context<'_>,
    ) -> Poll<Result<ExecutionWaitResult, ForgeExecutionCoordinatorError>> {
        let mut slot = self.lock_slot();
        if let Some(result) = slot.result.take() {
            return Poll::Ready(result);
        }
        if self.state.load(Ordering::Acquire) == EXECUTION_WAIT_CANCELLED {
            return Poll::Ready(Err(ForgeExecutionCoordinatorError::Closed));
        }
        let replace_waker = match slot.waker.as_ref() {
            Some(waker) => !waker.will_wake(context.waker()),
            None => true,
        };
        if replace_waker {
            slot.waker = Some(context.waker().clone());
        }
        Poll::Pending
    }

    fn lock_slot(&self) -> MutexGuard<'_, ExecutionWaitCompletionSlot> {
        match self.slot.lock() {
            Ok(slot) => slot,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

fn wake_without_panicking(waker: Option<Waker>) {
    let Some(waker) = waker else {
        return;
    };
    if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| waker.wake())).is_err() {
        tracing::warn!("execution wait completion waker panicked");
    }
}

/// Owns one asynchronous execution wait's cancellation capability.
///
/// Dropping the handle is a non-blocking cancellation request.  The
/// coordinator may already have completed the wait; an atomic state transition
/// ensures that cancellation and completion delivery are mutually exclusive.
#[must_use = "dropping an execution wait handle cancels the wait"]
#[derive(Debug)]
pub struct ExecutionWaitHandle {
    waiter_id: ExecutionWaiterId,
    completion: Arc<ExecutionWaitCompletionBridge>,
    cancellation_sender: SyncSender<ExecutionWaitCancellation>,
    wake_sender: SyncSender<CoordinatorRequest>,
}

impl ExecutionWaitHandle {
    pub const fn waiter_id(&self) -> ExecutionWaiterId {
        self.waiter_id
    }

    pub const fn id(&self) -> ExecutionWaiterId {
        self.waiter_id()
    }

    pub fn wait(self) -> Result<ExecutionWaitResult, ForgeExecutionCoordinatorError> {
        self.completion.wait()
    }

    fn request_cancellation(&self) {
        if !self.completion.cancel() {
            return;
        }
        // Both lanes are deliberately best-effort.  The state transition above
        // is the safety boundary when either bounded queue is saturated or
        // already disconnected; the coordinator also checks state while
        // servicing retained waiters.
        let _ignored = self.cancellation_sender.try_send(self.waiter_id);
        let _ignored = self
            .wake_sender
            .try_send(CoordinatorRequest::WaitCancellationWake);
    }
}

impl Future for ExecutionWaitHandle {
    type Output = Result<ExecutionWaitResult, ForgeExecutionCoordinatorError>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        self.as_ref().get_ref().completion.poll(context)
    }
}

impl Drop for ExecutionWaitHandle {
    fn drop(&mut self) {
        self.request_cancellation();
    }
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
    agent_authority: Option<AgentExecutionAuthorityRequest>,
    project_command: Option<ProjectCommandEvidence>,
    verification_input: Option<PublishedVerificationInput>,
    admission_envelope: Option<crate::ExecutionAdmissionEnvelope>,
}

/// Complete Forge-side input for one Orchestration-approved Agent execution.
///
/// The coordinator derives the authorization action, request digest, and
/// requested permissions from `request`. The durable grant and admission
/// envelope are consumed only after the current Agent authority is rechecked
/// and the execution owner has prepared the exact launch.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedAgentExecutionRequest {
    pub scope: ResolvedWorkspaceScope,
    pub activity: ApprovalActivityScope,
    pub grant_id: ExecutionGrantId,
    pub expected_grant_revision: ExecutionGrantRevision,
    pub request: ExecutionRequest,
    pub agent_authority: AgentExecutionAuthorityRequest,
    pub project_command: Option<ProjectCommandEvidence>,
    pub admission_envelope: crate::ExecutionAdmissionEnvelope,
}

impl ApprovedAgentExecutionRequest {
    /// Convert one fully checked approval payload into the coordinator's
    /// crate-private start request without performing I/O or minting any new
    /// authority. The coordinator remains the sole owner of submission.
    pub(crate) fn into_start_request(
        self,
    ) -> Result<ExecutionCoordinatorStartRequest, ForgeExecutionCoordinatorError> {
        let Self {
            scope,
            activity,
            grant_id,
            expected_grant_revision,
            request,
            agent_authority,
            project_command,
            admission_envelope,
        } = self;
        if agent_authority.scope != scope
            || agent_authority.activity_id != activity.activity_id
            || request.workspace_id() != scope.workspace_id()
            || request.activity_id() != activity.activity_id
        {
            return Err(ForgeExecutionCoordinatorError::AttributionMismatch);
        }
        let action = derive_approved_agent_action(&request, project_command)?;
        let authorization = ExecutionAuthorizationRequest::new(
            request.id(),
            scope.workspace_id(),
            activity.activity_id,
            execution_request_digest(&request),
            action,
            RequestedExecutionPermissions::new(request.permissions()),
        );
        Ok(ExecutionCoordinatorStartRequest::new_explicit(
            scope,
            activity.activity_id,
            activity.runtime_instance_id,
            grant_id,
            expected_grant_revision,
            authorization,
            request,
        )
        .with_goal(Some(agent_authority.attribution.into()))
        .with_agent_authority(Some(agent_authority))
        .with_project_command(project_command)
        .with_admission_envelope(&admission_envelope))
    }
}

/// Whether a start request created a new durable execution or converged on an
/// exact existing execution identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionStartDisposition {
    Created,
    Existing,
}

/// Result of the durable execution admission boundary.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionStartResult {
    id: ExecutionId,
    disposition: ExecutionStartDisposition,
}

impl ExecutionStartResult {
    pub const fn new(id: ExecutionId, disposition: ExecutionStartDisposition) -> Self {
        Self { id, disposition }
    }

    pub const fn id(self) -> ExecutionId {
        self.id
    }

    pub const fn execution_id(self) -> ExecutionId {
        self.id()
    }

    pub const fn disposition(self) -> ExecutionStartDisposition {
        self.disposition
    }
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
            agent_authority: None,
            project_command: None,
            verification_input: None,
            admission_envelope: None,
        }
    }

    pub(crate) fn new_auto(
        scope: ResolvedWorkspaceScope,
        activity_id: ActivityId,
        runtime_instance_id: RuntimeInstanceId,
        authorization: AutoCoordinatorAuthorization,
        authorization_request: ExecutionAuthorizationRequest,
        request: ExecutionRequest,
    ) -> Self {
        Self {
            scope,
            activity_id,
            runtime_instance_id,
            authorization: CoordinatorAuthorization::Auto(authorization),
            authorization_request,
            request,
            goal: None,
            agent_authority: None,
            project_command: None,
            verification_input: None,
            admission_envelope: None,
        }
    }

    pub(crate) fn with_goal(mut self, goal: Option<GoalWorkAttribution>) -> Self {
        self.goal = goal;
        self
    }

    pub(crate) fn with_agent_authority(
        mut self,
        authority: Option<AgentExecutionAuthorityRequest>,
    ) -> Self {
        self.agent_authority = authority;
        self
    }

    pub(crate) fn with_project_command(mut self, evidence: Option<ProjectCommandEvidence>) -> Self {
        self.project_command = evidence;
        self
    }

    pub(crate) fn with_admission_envelope(
        mut self,
        envelope: &crate::ExecutionAdmissionEnvelope,
    ) -> Self {
        self.admission_envelope = Some(*envelope);
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AutoCoordinatorAuthorization {
    auto_scope_id: AutoApprovalScopeId,
    auto_scope_revision: AutoApprovalScopeRevision,
    approval_id: ApprovalRequestId,
    grant_id: ExecutionGrantId,
}

impl AutoCoordinatorAuthorization {
    pub(crate) const fn new(
        auto_scope_id: AutoApprovalScopeId,
        auto_scope_revision: AutoApprovalScopeRevision,
        approval_id: ApprovalRequestId,
        grant_id: ExecutionGrantId,
    ) -> Self {
        Self {
            auto_scope_id,
            auto_scope_revision,
            approval_id,
            grant_id,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CoordinatorAuthorization {
    Explicit {
        grant_id: ExecutionGrantId,
        grant_revision: ExecutionGrantRevision,
    },
    Auto(AutoCoordinatorAuthorization),
}

#[derive(Debug, Clone)]
pub struct ForgeExecutionCoordinatorClient {
    sender: SyncSender<CoordinatorRequest>,
    cancellation_sender: SyncSender<ExecutionWaitCancellation>,
    accepting: Arc<AtomicBool>,
    verification_cancellation: Arc<AtomicBool>,
    next_waiter_id: Arc<AtomicU64>,
    rust_ci_available: bool,
}

impl ForgeExecutionCoordinatorClient {
    pub(crate) fn start_execution(
        &self,
        request: ExecutionCoordinatorStartRequest,
    ) -> Result<ExecutionStartResult, ForgeExecutionCoordinatorError> {
        self.submit(|response| CoordinatorRequest::Start {
            request: Box::new(request),
            response,
        })
    }

    /// Start one Agent execution through the coordinator's complete durable
    /// approval, admission, supervision, and journaling path.
    pub fn start_approved_agent_execution(
        &self,
        request: ApprovedAgentExecutionRequest,
    ) -> Result<ExecutionStartResult, ForgeExecutionCoordinatorError> {
        self.start_execution(request.into_start_request()?)
    }

    pub fn cancel_execution(
        &self,
        id: ExecutionId,
    ) -> Result<bool, ForgeExecutionCoordinatorError> {
        self.submit(|response| CoordinatorRequest::Cancel { id, response })
    }

    /// Cancel one Agent-originated execution after the coordinator's runtime
    /// thread resolves the current session and performs the authority-scoped
    /// persistence read immediately before signaling the process.
    pub fn cancel_agent_execution(
        &self,
        authority: AgentExecutionAuthorityRequest,
        id: ExecutionId,
    ) -> Result<bool, ForgeExecutionCoordinatorError> {
        self.submit(|response| CoordinatorRequest::CancelAgent {
            authority: Box::new(authority),
            id,
            response,
        })
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

    /// Queue durable capture with Start on this exact native owner. The returned
    /// receipt stays Pending until authority and terminal settlement is proven.
    pub fn stop_workspace_durable(
        &self,
        scope: ResolvedWorkspaceScope,
        request: forge_persistence::ExecutionStopRequest,
    ) -> Result<WorkspaceExecutionStopObservation, ForgeExecutionCoordinatorError> {
        self.submit(|response| CoordinatorRequest::StopWorkspaceDurable {
            scope,
            request: Box::new(request),
            response,
        })
    }

    pub(crate) fn stop_owned_workspace_durable(
        &self,
        permit: crate::approval_cleanup::ApprovalCleanupPermit,
        owner: crate::approval_cleanup::ApprovalCleanupOwner,
        request: forge_persistence::ExecutionStopRequest,
    ) -> Result<OwnedWorkspaceExecutionStopObservation, ForgeExecutionCoordinatorError> {
        self.submit(|response| CoordinatorRequest::StopOwnedWorkspaceDurable {
            permit: Box::new(permit),
            owner,
            request: Box::new(request),
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

    /// Wait for an Agent-owned execution's durable output or lifecycle to
    /// change.  The coordinator performs an authorization-scoped durable read
    /// before retaining the request; no waiter is created when the requested
    /// observation is already available.
    pub fn execution_wait_authorized(
        &self,
        authority: AgentExecutionAuthorityRequest,
        id: ExecutionId,
        cursor: ExecutionOutputCursor,
        max_bytes: u64,
        max_events: usize,
        timeout: Duration,
    ) -> Result<ExecutionWaitResult, ForgeExecutionCoordinatorError> {
        // Keep the non-Clone handle alive until its Condvar-backed completion
        // slot has delivered the result.  This preserves the established
        // synchronous API while sharing the Future completion implementation.
        let handle = self.begin_execution_wait_authorized(ExecutionWaitParameters::new(
            authority, id, cursor, max_bytes, max_events, timeout,
        ))?;
        handle.wait()
    }

    /// Begin an authorization-scoped execution wait without blocking the
    /// caller's thread.  Completion is delivered exactly once when the
    /// returned handle is polled or waited synchronously, unless it is
    /// cancelled or dropped first.
    pub fn begin_execution_wait_authorized(
        &self,
        request: ExecutionWaitParameters,
    ) -> Result<ExecutionWaitHandle, ForgeExecutionCoordinatorError> {
        let ExecutionWaitParameters {
            authority,
            id,
            cursor,
            max_bytes,
            max_events,
            timeout,
        } = request;
        if timeout > MAX_EXECUTION_WAIT_TIMEOUT {
            return Err(invalid_wait_timeout());
        }
        if !self.accepting.load(Ordering::Acquire) {
            return Err(ForgeExecutionCoordinatorError::Closed);
        }
        let waiter_id = self.allocate_waiter_id()?;
        let deadline = Instant::now()
            .checked_add(timeout)
            .unwrap_or_else(Instant::now);
        let completion = Arc::new(ExecutionWaitCompletionBridge::new());
        let request = CoordinatorRequest::WaitExecutionOutputAuthorizedAsync {
            request: Box::new(AsyncExecutionWaitRequest {
                waiter_id,
                state: Arc::clone(&completion.state),
                authority,
                id,
                cursor,
                max_bytes,
                max_events,
                deadline,
                completion: Arc::clone(&completion),
            }),
        };
        match self.sender.try_send(request) {
            Ok(()) => Ok(ExecutionWaitHandle {
                waiter_id,
                completion,
                cancellation_sender: self.cancellation_sender.clone(),
                wake_sender: self.sender.clone(),
            }),
            Err(TrySendError::Full(_)) => {
                let _ = completion.cancel();
                Err(ForgeExecutionCoordinatorError::QueueFull)
            }
            Err(TrySendError::Disconnected(_)) => {
                let _ = completion.cancel();
                Err(ForgeExecutionCoordinatorError::Closed)
            }
        }
    }

    fn allocate_waiter_id(&self) -> Result<ExecutionWaiterId, ForgeExecutionCoordinatorError> {
        let raw = self
            .next_waiter_id
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .map_err(|_| ForgeExecutionCoordinatorError::WaiterIdExhausted)?;
        ExecutionWaiterId::new(raw).ok_or(ForgeExecutionCoordinatorError::WaiterIdExhausted)
    }

    /// Whether the application prepared a Rust CI capability at startup.
    ///
    /// This is intentionally only a redacted availability bit.  Capability
    /// paths and discovery failures remain inside the coordinator boundary.
    pub const fn rust_ci_available(&self) -> bool {
        self.rust_ci_available
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
                .map_err(|_| ForgeExecutionCoordinatorError::ResponseDropped)?,
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

/// Result of one bounded execution long-poll.
///
/// The output is the existing non-destructive durable read.  `state` and
/// `revision` are read through the same authorization-scoped control boundary,
/// while `changed` tells the caller whether output or lifecycle advanced
/// relative to the observation that opened the wait.  A timeout is reported as
/// a normal, typed result and is always preceded by one final durable read.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionWaitResult {
    output: ExecutionOutputRead,
    state: ExecutionState,
    revision: ExecutionRevision,
    timed_out: bool,
    changed: bool,
}

impl ExecutionWaitResult {
    fn new(
        output: ExecutionOutputRead,
        state: ExecutionState,
        revision: ExecutionRevision,
        timed_out: bool,
        changed: bool,
    ) -> Self {
        Self {
            output,
            state,
            revision,
            timed_out,
            changed,
        }
    }

    pub const fn output(&self) -> &ExecutionOutputRead {
        &self.output
    }

    pub fn into_output(self) -> ExecutionOutputRead {
        self.output
    }

    pub const fn state(&self) -> ExecutionState {
        self.state
    }

    pub const fn revision(&self) -> ExecutionRevision {
        self.revision
    }

    pub const fn timed_out(&self) -> bool {
        self.timed_out
    }

    pub const fn changed(&self) -> bool {
        self.changed
    }
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
    thread: Option<
        JoinHandle<Result<ForgeExecutionCoordinatorShutdown, ForgeExecutionCoordinatorError>>,
    >,
}

impl ForgeExecutionCoordinator {
    pub fn start(
        control: ForgeControlClient,
        maximum: usize,
    ) -> Result<Self, ForgeExecutionCoordinatorError> {
        Self::start_with_rust_ci_capability(control, maximum, None)
    }

    /// Start the execution coordinator with one immutable, optionally
    /// prepared Rust CI capability.  The capability is owned by the
    /// coordinator runtime and is never refreshed or replaced during a run.
    pub fn start_with_rust_ci_capability(
        control: ForgeControlClient,
        maximum: usize,
        rust_ci_capability: Option<RustCiToolchainCapability>,
    ) -> Result<Self, ForgeExecutionCoordinatorError> {
        let supervisor = ExecutionSupervisor::start(maximum)?;
        let (sender, receiver) = mpsc::sync_channel(COORDINATOR_QUEUE_CAPACITY);
        let (cancellation_sender, cancellation_receiver) =
            mpsc::sync_channel(EXECUTION_WAIT_CANCELLATION_CAPACITY);
        let accepting = Arc::new(AtomicBool::new(true));
        let runtime_accepting = Arc::clone(&accepting);
        let verification_cancellation = Arc::new(AtomicBool::new(false));
        let runtime_verification_cancellation = Arc::clone(&verification_cancellation);
        let rust_ci_available = rust_ci_capability.is_some();
        let thread = thread::Builder::new()
            .name(THREAD_NAME.to_owned())
            .spawn(move || {
                CoordinatorRuntime::new(
                    control,
                    supervisor,
                    receiver,
                    cancellation_receiver,
                    runtime_accepting,
                    runtime_verification_cancellation,
                    rust_ci_capability,
                )
                .run()
            })
            .map_err(ForgeExecutionCoordinatorError::SpawnThread)?;
        Ok(Self {
            client: ForgeExecutionCoordinatorClient {
                sender,
                cancellation_sender,
                accepting,
                verification_cancellation,
                next_waiter_id: Arc::new(AtomicU64::new(1)),
                rust_ci_available,
            },
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
        self.client
            .verification_cancellation
            .store(true, Ordering::Release);
        let Some(thread) = self.thread.take() else {
            return Err(ForgeExecutionCoordinatorError::AlreadyShutdown);
        };
        let _marker_delivery = self.client.sender.send(CoordinatorRequest::Shutdown);
        thread
            .join()
            .map_err(|_| ForgeExecutionCoordinatorError::ThreadPanicked)?
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
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    /// The exact durable running record returned by the admission transition.
    /// Output journaling does not change this record; reconciliation uses it
    /// to distinguish an absent effect from an effect whose identity changed.
    running: RegisteredExecution,
    identity: ExecutionStartIdentity,
    /// The exact native Start identity retained for terminal-event ownership
    /// validation after the Start receipt itself has been acknowledged.
    native_identity: Option<SupervisorStartIdentity>,
    journal: ExecutionJournalAuthority,
    terminal_journaled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingStartAckPhase {
    Ready,
    Observe,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingStartOutcome {
    Unknown,
    Accepted {
        ack: PendingStartAckPhase,
    },
    Rejected {
        failure_code: ExecutionFailureCode,
        journal_confirmed: bool,
        ack: PendingStartAckPhase,
    },
}

/// Bounded ownership retained between native Start submission and receipt
/// acknowledgement.  The owner remains exact even when the native reply is
/// lost, so the coordinator cannot consume another grant or launch a second
/// child while admission is unresolved.
#[derive(Debug, Clone)]
struct PendingStart {
    native_identity: SupervisorStartIdentity,
    owner: ActiveExecution,
    outcome: PendingStartOutcome,
}

impl PendingStart {
    fn new(native_identity: SupervisorStartIdentity, owner: ActiveExecution) -> Self {
        Self {
            native_identity,
            owner,
            outcome: PendingStartOutcome::Unknown,
        }
    }

    fn id(&self) -> ExecutionId {
        self.owner.running.id()
    }

    fn workspace_id(&self) -> WorkspaceId {
        self.owner.workspace_id
    }

    fn activity_id(&self) -> ActivityId {
        self.owner.activity_id
    }
}

#[derive(Debug)]
struct AdmittedExecution {
    layout: forge_workspace::ExistingWorkspaceStateLayout,
    begin_revision: ExecutionRevision,
    status: forge_persistence::BeginExecutionStatus,
    state: ExecutionState,
    journal: ExecutionJournalAuthority,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExecutionStartIdentity {
    scope: ResolvedWorkspaceScope,
    activity_id: ActivityId,
    runtime_instance_id: RuntimeInstanceId,
    authorization_request: ExecutionAuthorizationRequest,
    request: ExecutionRequest,
    goal: Option<GoalWorkAttribution>,
    agent_authority: Option<AgentExecutionAuthorityRequest>,
    project_command: Option<ProjectCommandEvidence>,
    admission_envelope: Option<crate::ExecutionAdmissionEnvelope>,
}

impl ExecutionStartIdentity {
    fn from_request(request: &ExecutionCoordinatorStartRequest) -> Self {
        Self {
            scope: request.scope.clone(),
            activity_id: request.activity_id,
            runtime_instance_id: request.runtime_instance_id,
            authorization_request: request.authorization_request,
            request: request.request.clone(),
            goal: request.goal,
            agent_authority: request.agent_authority.clone(),
            project_command: request.project_command,
            admission_envelope: request.admission_envelope,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JournalWorkState {
    Write,
    Readback,
    Confirmed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TerminalAckPhase {
    Ready,
    Observe,
    Settled,
}

enum TerminalStep {
    Done,
    Back,
    FrontAndStop,
}

struct PendingOutputGroup {
    execution_id: ExecutionId,
    events: Vec<ExecutionOutputEvent>,
    before: RegisteredExecution,
    journal: ExecutionJournalAuthority,
    state: JournalWorkState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputAckState {
    Pending,
    Readback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AckReadback {
    Pending,
    Confirmed,
    Mismatch,
}

/// One exact supervisor output prefix retained until every durable group and
/// the supervisor acknowledgement have been confirmed.
struct PendingOutput {
    events: Vec<ExecutionOutputEvent>,
    ack_key: ExecutionOutputEventKey,
    groups: Vec<PendingOutputGroup>,
    ack_state: OutputAckState,
}

struct PendingTerminal {
    execution_id: ExecutionId,
    key: Option<TerminalEventKey>,
    native_identity: Option<SupervisorStartIdentity>,
    event: Option<ExecutionSupervisorEvent>,
    journal: Option<ExecutionJournalAuthority>,
    before: Option<RegisteredExecution>,
    command: Option<JournalTerminalCommand>,
    state: JournalWorkState,
    ack: TerminalAckPhase,
    durable_recorded: bool,
    closure: Option<forge_domain::ExecutionNativeClosureFact>,
}

impl PendingTerminal {
    fn new(event: ExecutionSupervisorEvent) -> Self {
        Self {
            execution_id: event.execution_id(),
            key: Some(event.key()),
            native_identity: Some(event.identity()),
            event: Some(event),
            journal: None,
            before: None,
            command: None,
            state: JournalWorkState::Write,
            ack: TerminalAckPhase::Ready,
            durable_recorded: false,
            closure: None,
        }
    }

    fn launch_failure(
        execution_id: ExecutionId,
        journal: ExecutionJournalAuthority,
        before: RegisteredExecution,
        command: FailExecution,
    ) -> Self {
        Self {
            execution_id,
            key: None,
            native_identity: None,
            event: None,
            journal: Some(journal),
            before: Some(before),
            command: Some(JournalTerminalCommand::Fail { command }),
            state: JournalWorkState::Write,
            ack: TerminalAckPhase::Settled,
            durable_recorded: false,
            closure: None,
        }
    }

    fn execution_id(&self) -> ExecutionId {
        self.execution_id
    }

    fn matches_event(&self, event: &ExecutionSupervisorEvent) -> bool {
        self.key == Some(event.key())
            && self.native_identity == Some(event.identity())
            && self.event.as_ref() == Some(event)
    }

    fn belongs_to_workspace(&self, workspace_id: WorkspaceId) -> bool {
        self.before
            .as_ref()
            .is_some_and(|before| before.workspace_id() == workspace_id)
    }

    fn belongs_to_activity(&self, workspace_id: WorkspaceId, activity_id: ActivityId) -> bool {
        self.before.as_ref().is_some_and(|before| {
            before.workspace_id() == workspace_id && before.activity_id() == activity_id
        })
    }
}

#[derive(Debug)]
struct PendingExecutionWait {
    waiter_id: ExecutionWaiterId,
    state: Arc<AtomicU8>,
    authority: AgentExecutionAuthorityRequest,
    id: ExecutionId,
    cursor: ExecutionOutputCursor,
    max_bytes: u64,
    max_events: usize,
    deadline: Instant,
    baseline_state: ExecutionState,
    baseline_revision: ExecutionRevision,
    completion: Arc<ExecutionWaitCompletionBridge>,
}

struct ExecutionWaitRequest {
    waiter_id: ExecutionWaiterId,
    state: Arc<AtomicU8>,
    authority: AgentExecutionAuthorityRequest,
    id: ExecutionId,
    cursor: ExecutionOutputCursor,
    max_bytes: u64,
    max_events: usize,
    deadline: Instant,
    completion: Arc<ExecutionWaitCompletionBridge>,
}

impl fmt::Debug for ExecutionWaitRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutionWaitRequest")
            .field("waiter_id", &self.waiter_id)
            .field("state", &self.state.load(Ordering::Acquire))
            .field("authority", &self.authority)
            .field("id", &self.id)
            .field("cursor", &self.cursor)
            .field("max_bytes", &self.max_bytes)
            .field("max_events", &self.max_events)
            .field("deadline", &self.deadline)
            .finish_non_exhaustive()
    }
}

struct AsyncExecutionWaitRequest {
    waiter_id: ExecutionWaiterId,
    state: Arc<AtomicU8>,
    authority: AgentExecutionAuthorityRequest,
    id: ExecutionId,
    cursor: ExecutionOutputCursor,
    max_bytes: u64,
    max_events: usize,
    deadline: Instant,
    completion: Arc<ExecutionWaitCompletionBridge>,
}

impl fmt::Debug for AsyncExecutionWaitRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AsyncExecutionWaitRequest")
            .field("waiter_id", &self.waiter_id)
            .field("state", &self.state.load(Ordering::Acquire))
            .field("authority", &self.authority)
            .field("id", &self.id)
            .field("cursor", &self.cursor)
            .field("max_bytes", &self.max_bytes)
            .field("max_events", &self.max_events)
            .field("deadline", &self.deadline)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Default)]
struct JournalProgress {
    execution_ids: Vec<ExecutionId>,
}

impl JournalProgress {
    fn record(&mut self, id: ExecutionId) {
        if !self.execution_ids.contains(&id) {
            self.execution_ids.push(id);
        }
    }

    fn contains(&self, id: ExecutionId) -> bool {
        self.execution_ids.contains(&id)
    }
}

#[derive(Debug)]
struct ExecutionWaitObservation {
    output: ExecutionOutputRead,
    state: ExecutionState,
    revision: ExecutionRevision,
}

impl ExecutionWaitObservation {
    fn changed_from(
        &self,
        baseline_state: ExecutionState,
        baseline_revision: ExecutionRevision,
    ) -> bool {
        !self.output.events().is_empty()
            || self.output.terminal_state().is_some()
            || self.state != baseline_state
            || self.revision != baseline_revision
    }

    fn changed_without_baseline(&self) -> bool {
        !self.output.events().is_empty()
            || self.output.terminal_state().is_some()
            || self.state.is_terminal()
    }

    fn into_result(self, timed_out: bool, changed: bool) -> ExecutionWaitResult {
        ExecutionWaitResult::new(self.output, self.state, self.revision, timed_out, changed)
    }
}

enum CoordinatorReceive {
    Request(CoordinatorRequest),
    Timeout,
    Closed,
}

struct CoordinatorRuntime {
    control: ForgeControlClient,
    supervisor: ExecutionSupervisor,
    receiver: Receiver<CoordinatorRequest>,
    cancellation_receiver: Receiver<ExecutionWaitCancellation>,
    accepting: Arc<AtomicBool>,
    verification_cancellation: Arc<AtomicBool>,
    rust_ci_capability: Option<RustCiToolchainCapability>,
    active: HashMap<ExecutionId, ActiveExecution>,
    terminal_backlog: VecDeque<PendingTerminal>,
    pending_output: Option<PendingOutput>,
    terminal_records: usize,
    journal_failed: bool,
    first_journal_failure: Option<JournalFailure>,
    waiters: VecDeque<PendingExecutionWait>,
    launch_failure: Option<PendingTerminal>,
    pending_start: Option<PendingStart>,
    workspace_stops: HashMap<WorkspaceId, workspace_stop::PendingWorkspaceStop>,
    owned_workspace_stops: HashMap<WorkspaceId, owned_workspace_stop::PendingOwnedWorkspaceStop>,
}

impl CoordinatorRuntime {
    fn new(
        control: ForgeControlClient,
        supervisor: ExecutionSupervisor,
        receiver: Receiver<CoordinatorRequest>,
        cancellation_receiver: Receiver<ExecutionWaitCancellation>,
        accepting: Arc<AtomicBool>,
        verification_cancellation: Arc<AtomicBool>,
        rust_ci_capability: Option<RustCiToolchainCapability>,
    ) -> Self {
        Self {
            control,
            supervisor,
            receiver,
            cancellation_receiver,
            accepting,
            verification_cancellation,
            rust_ci_capability,
            active: HashMap::new(),
            terminal_backlog: VecDeque::new(),
            pending_output: None,
            terminal_records: 0,
            journal_failed: false,
            first_journal_failure: None,
            waiters: VecDeque::new(),
            launch_failure: None,
            pending_start: None,
            workspace_stops: HashMap::new(),
            owned_workspace_stops: HashMap::new(),
        }
    }

    fn run(mut self) -> Result<ForgeExecutionCoordinatorShutdown, ForgeExecutionCoordinatorError> {
        loop {
            self.drain_wait_cancellations();
            let progress = self.poll_and_journal();
            self.drain_wait_cancellations();
            self.service_waiters(&progress);
            self.drain_wait_cancellations();
            match self.receive_request() {
                CoordinatorReceive::Request(CoordinatorRequest::Shutdown)
                | CoordinatorReceive::Closed => {
                    return self.teardown();
                }
                CoordinatorReceive::Request(request) => {
                    self.drain_wait_cancellations();
                    self.handle_request(request);
                    self.drain_wait_cancellations();
                }
                CoordinatorReceive::Timeout => {
                    self.drain_wait_cancellations();
                }
            }
        }
    }

    fn teardown(
        &mut self,
    ) -> Result<ForgeExecutionCoordinatorShutdown, ForgeExecutionCoordinatorError> {
        self.accepting.store(false, Ordering::Release);
        self.verification_cancellation
            .store(true, Ordering::Release);
        let stop_result = self.stop_all_and_journal();
        let supervisor_result = self.supervisor.shutdown();
        self.drain_wait_cancellations();
        self.resolve_waiters_as_closed();
        self.resolve_queued_waiters_as_closed();
        match (stop_result, supervisor_result) {
            (Ok(cancelled), Ok(supervisor_report)) => {
                if !supervisor_report.events().is_empty()
                    || !supervisor_report.output_events().is_empty()
                {
                    Err(ForgeExecutionCoordinatorError::JournalFailed)
                } else {
                    Ok(ForgeExecutionCoordinatorShutdown {
                        cancelled,
                        terminal_records: self.terminal_records,
                    })
                }
            }
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error.into()),
        }
    }

    fn receive_request(&self) -> CoordinatorReceive {
        if self.active.is_empty()
            && self.waiters.is_empty()
            && self.terminal_backlog.is_empty()
            && self.pending_output.is_none()
            && self.launch_failure.is_none()
            && self.pending_start.is_none()
        {
            return match self.receiver.recv() {
                Ok(request) => CoordinatorReceive::Request(request),
                Err(_) => CoordinatorReceive::Closed,
            };
        }
        match self.receiver.recv_timeout(self.next_receive_timeout()) {
            Ok(request) => CoordinatorReceive::Request(request),
            Err(RecvTimeoutError::Timeout) => CoordinatorReceive::Timeout,
            Err(RecvTimeoutError::Disconnected) => CoordinatorReceive::Closed,
        }
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
            CoordinatorRequest::CancelAgent {
                authority,
                id,
                response,
            } => {
                let result = self.cancel_agent_execution(*authority, id);
                let _ignored = response.send(result);
            }
            CoordinatorRequest::StopWorkspace {
                workspace_id,
                response,
            } => {
                let result = self.stop_workspace_and_journal(workspace_id);
                let _ignored = response.send(result);
            }
            CoordinatorRequest::StopWorkspaceDurable {
                scope,
                request,
                response,
            } => {
                let result = self.stop_workspace_durable(scope, *request);
                let _ignored = response.send(result);
            }
            CoordinatorRequest::StopOwnedWorkspaceDurable {
                permit,
                owner,
                request,
                response,
            } => {
                let result = self.stop_owned_workspace_durable(*permit, owner, *request);
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
            CoordinatorRequest::WaitExecutionOutputAuthorizedAsync { request } => {
                self.handle_async_execution_wait(*request);
            }
            CoordinatorRequest::WaitCancellationWake | CoordinatorRequest::Shutdown => {}
        }
    }

    fn drain_wait_cancellations(&mut self) {
        while let Ok(waiter_id) = self.cancellation_receiver.try_recv() {
            self.remove_waiter(waiter_id);
        }
    }

    fn remove_waiter(&mut self, waiter_id: ExecutionWaiterId) {
        if self.waiters.is_empty() {
            return;
        }
        let mut retained = VecDeque::with_capacity(self.waiters.len());
        while let Some(waiter) = self.waiters.pop_front() {
            if waiter.waiter_id == waiter_id
                || waiter.state.load(Ordering::Acquire) != EXECUTION_WAIT_PENDING
            {
                continue;
            }
            retained.push_back(waiter);
        }
        self.waiters = retained;
    }

    fn resolve_queued_waiters_as_closed(&mut self) {
        loop {
            let request = match self.receiver.try_recv() {
                Ok(request) => request,
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
            };
            match request {
                CoordinatorRequest::WaitExecutionOutputAuthorizedAsync { request } => {
                    request
                        .completion
                        .complete(Err(ForgeExecutionCoordinatorError::Closed));
                }
                CoordinatorRequest::Start { .. }
                | CoordinatorRequest::Cancel { .. }
                | CoordinatorRequest::CancelAgent { .. }
                | CoordinatorRequest::StopWorkspace { .. }
                | CoordinatorRequest::StopWorkspaceDurable { .. }
                | CoordinatorRequest::StopOwnedWorkspaceDurable { .. }
                | CoordinatorRequest::StopActivity { .. }
                | CoordinatorRequest::StopAll { .. }
                | CoordinatorRequest::WaitCancellationWake
                | CoordinatorRequest::Shutdown => {}
            }
        }
    }

    fn handle_execution_wait(&mut self, request: ExecutionWaitRequest) {
        let ExecutionWaitRequest {
            waiter_id,
            state,
            authority,
            id,
            cursor,
            max_bytes,
            max_events,
            deadline,
            completion,
        } = request;
        if state.load(Ordering::Acquire) != EXECUTION_WAIT_PENDING {
            return;
        }
        let observation = match self
            .read_execution_wait_observation(&authority, id, cursor, max_bytes, max_events)
        {
            Ok(observation) => observation,
            Err(error) => {
                completion.complete(Err(error));
                return;
            }
        };
        if state.load(Ordering::Acquire) != EXECUTION_WAIT_PENDING {
            return;
        }
        let changed = observation.changed_without_baseline();
        let timed_out = !changed && Instant::now() >= deadline;
        if changed || timed_out {
            completion.complete(Ok(observation.into_result(timed_out, changed)));
            return;
        }
        if self.waiters.len() >= MAX_EXECUTION_WAITERS {
            completion.complete(Err(ForgeExecutionCoordinatorError::QueueFull));
            return;
        }
        if state.load(Ordering::Acquire) != EXECUTION_WAIT_PENDING {
            return;
        }
        self.waiters.push_back(PendingExecutionWait {
            waiter_id,
            state,
            authority,
            id,
            cursor,
            max_bytes,
            max_events,
            deadline,
            baseline_state: observation.state,
            baseline_revision: observation.revision,
            completion,
        });
    }

    fn handle_async_execution_wait(&mut self, request: AsyncExecutionWaitRequest) {
        let AsyncExecutionWaitRequest {
            waiter_id,
            state,
            authority,
            id,
            cursor,
            max_bytes,
            max_events,
            deadline,
            completion,
        } = request;
        self.handle_execution_wait(ExecutionWaitRequest {
            waiter_id,
            state,
            authority,
            id,
            cursor,
            max_bytes,
            max_events,
            deadline,
            completion,
        });
    }

    fn read_execution_wait_observation(
        &self,
        authority: &AgentExecutionAuthorityRequest,
        id: ExecutionId,
        cursor: ExecutionOutputCursor,
        max_bytes: u64,
        max_events: usize,
    ) -> Result<ExecutionWaitObservation, ForgeExecutionCoordinatorError> {
        let snapshot = self.control.execution_read_authorized(
            authority.clone(),
            id,
            cursor,
            max_bytes,
            max_events,
        )?;
        let (record, output) = snapshot.into_parts();
        Ok(ExecutionWaitObservation {
            output,
            state: record.state(),
            revision: record.revision(),
        })
    }

    fn service_waiters(&mut self, progress: &JournalProgress) {
        if self.waiters.is_empty() {
            return;
        }
        let mut pending = VecDeque::with_capacity(self.waiters.len());
        while let Some(waiter) = self.waiters.pop_front() {
            if waiter.state.load(Ordering::Acquire) != EXECUTION_WAIT_PENDING {
                continue;
            }
            let deadline_reached = Instant::now() >= waiter.deadline;
            if !progress.contains(waiter.id) && !deadline_reached {
                if waiter.state.load(Ordering::Acquire) == EXECUTION_WAIT_PENDING {
                    pending.push_back(waiter);
                }
                continue;
            }
            if waiter.state.load(Ordering::Acquire) != EXECUTION_WAIT_PENDING {
                continue;
            }
            let observation = self.read_execution_wait_observation(
                &waiter.authority,
                waiter.id,
                waiter.cursor,
                waiter.max_bytes,
                waiter.max_events,
            );
            match observation {
                Ok(observation) => {
                    let changed =
                        observation.changed_from(waiter.baseline_state, waiter.baseline_revision);
                    if changed || deadline_reached {
                        let timed_out = deadline_reached && !changed;
                        waiter
                            .completion
                            .complete(Ok(observation.into_result(timed_out, changed)));
                    } else if waiter.state.load(Ordering::Acquire) == EXECUTION_WAIT_PENDING {
                        pending.push_back(waiter);
                    }
                }
                Err(error) => {
                    waiter.completion.complete(Err(error));
                }
            }
        }
        self.waiters = pending;
    }

    fn next_receive_timeout(&self) -> Duration {
        let now = Instant::now();
        let deadline = self
            .waiters
            .iter()
            .map(|waiter| waiter.deadline.saturating_duration_since(now))
            .min();
        match deadline {
            Some(deadline)
                if self.active.is_empty()
                    && self.terminal_backlog.is_empty()
                    && self.pending_output.is_none()
                    && self.launch_failure.is_none()
                    && self.pending_start.is_none() =>
            {
                deadline
            }
            Some(deadline) => POLL_INTERVAL.min(deadline),
            None => POLL_INTERVAL,
        }
    }

    fn resolve_waiters_as_closed(&mut self) {
        for waiter in self.waiters.drain(..) {
            waiter
                .completion
                .complete(Err(ForgeExecutionCoordinatorError::Closed));
        }
    }

    fn start_execution(
        &mut self,
        start: ExecutionCoordinatorStartRequest,
    ) -> Result<ExecutionStartResult, ForgeExecutionCoordinatorError> {
        if self.pending_start.is_some() {
            // A native Start with an unresolved or unacknowledged receipt owns
            // the coordinator's admission lane.  Returning the existing
            // journal error keeps callers fail-closed without inventing a
            // retry permission or a second durable intent.
            return Err(ForgeExecutionCoordinatorError::JournalFailed);
        }
        if self.journal_failed || self.launch_failure.is_some() {
            return Err(ForgeExecutionCoordinatorError::JournalFailed);
        }
        if let Some(authority) = start.agent_authority.as_ref() {
            self.control
                .verify_agent_execution_authority(authority.clone())
                .inspect_err(|error| {
                    start_diagnostic::control(
                        start.request.id(),
                        start_diagnostic::Stage::Authority,
                        error,
                    );
                })?;
        }
        let id = start.request.id();
        let identity = ExecutionStartIdentity::from_request(&start);
        if let Some(existing) = self.existing_execution_start(id, &identity)? {
            return Ok(existing);
        }
        let mut start = self
            .resolve_current_project_command(start)
            .inspect_err(|error| {
                start_diagnostic::coordinator(id, start_diagnostic::Stage::ResolveCommand, error);
            })?;
        validate_start_request(&start).inspect_err(|error| {
            start_diagnostic::coordinator(id, start_diagnostic::Stage::ValidateStart, error);
        })?;
        let launch_kind = derive_launch_kind_parts(
            start.authorization_request.action(),
            &start.request,
            start.agent_authority.as_ref(),
            start.project_command,
            self.rust_ci_capability.as_ref(),
        )
        .inspect_err(|error| {
            start_diagnostic::coordinator(id, start_diagnostic::Stage::LaunchKind, error);
        })?;
        let observed_at = current_timestamp_millis()?;
        let package_verification = start.agent_authority.as_ref().is_some_and(|authority| {
            is_exact_research_package_request(authority.command_id.as_str(), &start.request)
        });
        if (launch_kind == ExecutionLaunchKind::RustCi || package_verification)
            && start.verification_input.is_none()
        {
            start.verification_input = Some(self.control.prepare_workspace_verification_input(
                start.scope.clone(),
                FileActivityScope {
                    activity_id: start.activity_id,
                    runtime_instance_id: start.runtime_instance_id,
                    observed_at,
                },
                forge_domain::VerificationInputId::from_uuid(id.into_uuid()),
                Arc::clone(&self.verification_cancellation),
            )?);
        }
        let begin = begin_execution_for_start(&start, id, observed_at).inspect_err(|error| {
            start_diagnostic::coordinator(id, start_diagnostic::Stage::Provenance, error);
        })?;
        let activity = ApprovalActivityScope {
            activity_id: start.activity_id,
            runtime_instance_id: start.runtime_instance_id,
            observed_at,
        };
        let AdmittedExecution {
            layout,
            begin_revision,
            status,
            state: existing_state,
            journal,
        } = self
            .consume_authorization(&start, activity, begin)
            .inspect_err(|error| {
                start_diagnostic::coordinator(
                    id,
                    start_diagnostic::Stage::ConsumeAuthorization,
                    error,
                );
            })?;
        if status == forge_persistence::BeginExecutionStatus::Existing {
            if existing_state.is_active() {
                return Err(ForgeExecutionCoordinatorError::RecoveryRequired(id));
            }
            return Ok(ExecutionStartResult::new(
                id,
                ExecutionStartDisposition::Existing,
            ));
        }
        self.launch_admitted_execution(
            start,
            identity,
            launch_kind,
            layout,
            begin_revision,
            journal,
        )
    }

    fn launch_admitted_execution(
        &mut self,
        start: ExecutionCoordinatorStartRequest,
        identity: ExecutionStartIdentity,
        launch_kind: ExecutionLaunchKind,
        layout: forge_workspace::ExistingWorkspaceStateLayout,
        begin_revision: forge_domain::ExecutionRevision,
        journal: ExecutionJournalAuthority,
    ) -> Result<ExecutionStartResult, ForgeExecutionCoordinatorError> {
        let id = start.request.id();
        let running = self.control.execution_mark_running(
            start.scope.clone(),
            MarkExecutionRunning::new(id, begin_revision, current_timestamp_millis()?),
        )?;
        let native_identity = match SupervisorStartIdentity::capture(
            &layout,
            &start.request,
            launch_kind,
            start.verification_input.as_ref(),
        ) {
            Ok(identity) => identity,
            Err(error) => {
                pre_spawn_rejection::diagnose_native_start_error(
                    id,
                    pre_spawn_rejection::NativeStartErrorStage::IdentityCapture,
                    &error,
                );
                let owner = ActiveExecution {
                    workspace_id: start.scope.workspace_id(),
                    activity_id: start.activity_id,
                    running,
                    identity,
                    native_identity: None,
                    journal,
                    terminal_journaled: false,
                };
                let Some(failure_code) = supervisor_failure_code(&error) else {
                    return Err(error.into());
                };
                self.queue_launch_failure(&owner, failure_code)?;
                return if self.flush_launch_failure() {
                    Err(error.into())
                } else {
                    Err(ForgeExecutionCoordinatorError::JournalFailed)
                };
            }
        };
        let owner = ActiveExecution {
            workspace_id: start.scope.workspace_id(),
            activity_id: start.activity_id,
            running,
            identity,
            native_identity: Some(native_identity),
            journal,
            terminal_journaled: false,
        };
        let verification_input = start.verification_input;
        let capability = match launch_kind {
            ExecutionLaunchKind::Baseline => None,
            ExecutionLaunchKind::RustCi | ExecutionLaunchKind::RustCiGeneratedPackage => {
                let Some(capability) = self.rust_ci_capability.clone() else {
                    self.queue_launch_failure(&owner, ExecutionFailureCode::Admission)?;
                    return if self.flush_launch_failure() {
                        Err(ForgeExecutionCoordinatorError::RustCiCapabilityMissing)
                    } else {
                        Err(ForgeExecutionCoordinatorError::JournalFailed)
                    };
                };
                Some(capability)
            }
        };
        self.pending_start = Some(PendingStart::new(native_identity, owner));
        let package_verification = start.agent_authority.as_ref().is_some_and(|authority| {
            is_exact_research_package_request(authority.command_id.as_str(), &start.request)
        });
        let supervisor = self.supervisor.client();
        let supervisor_result = if package_verification {
            match verification_input {
                Some(input) => supervisor.start_package_verification_with_identity(
                    native_identity,
                    layout,
                    start.request,
                    input,
                ),
                None => Err(forge_execution::ExecutionError::VerificationInputMismatch.into()),
            }
        } else {
            supervisor.start_execution_with_identity(
                native_identity,
                layout,
                start.request,
                launch_kind,
                capability,
                verification_input,
            )
        };
        self.process_supervisor_start_result(supervisor_result)?;
        Ok(ExecutionStartResult::new(
            id,
            ExecutionStartDisposition::Created,
        ))
    }

    /// Process the typed native Start result after the exact owner has been
    /// retained.  Keeping this seam separate from dispatch lets focused tests
    /// inject a genuine typed reply loss without adding a production flag or
    /// fabricating a supervisor state.
    fn process_supervisor_start_result(
        &mut self,
        result: Result<ExecutionId, ExecutionSupervisorError>,
    ) -> Result<(), ForgeExecutionCoordinatorError> {
        let expected_id = self
            .pending_start
            .as_ref()
            .ok_or(ForgeExecutionCoordinatorError::JournalFailed)?
            .id();
        if let Err(error) = &result {
            pre_spawn_rejection::diagnose_native_start_error(
                expected_id,
                pre_spawn_rejection::NativeStartErrorStage::SupervisorStartResult,
                error,
            );
        }
        match result {
            Ok(actual_id) if actual_id == expected_id => {
                if let Some(pending) = self.pending_start.as_mut() {
                    pending.outcome = PendingStartOutcome::Accepted {
                        ack: PendingStartAckPhase::Ready,
                    };
                }
                self.progress_pending_start();
                Ok(())
            }
            Ok(_) => {
                // A native owner returned an ID different from the retained
                // key. Preserve the owner and stop normal journaling until an
                // exact readback can establish what happened.
                self.latch_journal_failure(JournalFailureStage::StartIdentity, None);
                Err(ForgeExecutionCoordinatorError::JournalFailed)
            }
            Err(error @ ExecutionSupervisorError::ReplyDropped) => {
                // The native owner may already have admitted the child. Keep
                // the exact owner and wait for its receipt; never synthesize a
                // terminal failure or replay the grant.
                Err(error.into())
            }
            Err(
                error @ (ExecutionSupervisorError::QueueFull | ExecutionSupervisorError::Closed),
            ) => {
                // These errors are returned before the native request enters
                // the supervisor queue, so there is no receipt to acknowledge.
                let Some(pending) = self.pending_start.take() else {
                    return Err(ForgeExecutionCoordinatorError::JournalFailed);
                };
                let Some(failure_code) = supervisor_failure_code(&error) else {
                    return Err(error.into());
                };
                self.queue_launch_failure(&pending.owner, failure_code)?;
                if self.flush_launch_failure() {
                    Err(error.into())
                } else {
                    Err(ForgeExecutionCoordinatorError::JournalFailed)
                }
            }
            Err(error) => {
                let Some(failure_code) = supervisor_failure_code(&error) else {
                    return Err(error.into());
                };
                if let Some(pending) = self.pending_start.as_mut() {
                    pending.outcome = PendingStartOutcome::Rejected {
                        failure_code,
                        journal_confirmed: false,
                        ack: PendingStartAckPhase::Ready,
                    };
                }
                self.queue_pending_start_failure()?;
                self.progress_pending_start();
                if self.pending_start.is_none() && self.launch_failure.is_none() {
                    Err(error.into())
                } else {
                    Err(ForgeExecutionCoordinatorError::JournalFailed)
                }
            }
        }
    }

    fn queue_launch_failure(
        &mut self,
        owner: &ActiveExecution,
        failure_code: ExecutionFailureCode,
    ) -> Result<(), ForgeExecutionCoordinatorError> {
        self.queue_launch_failure_with_rejection(owner, failure_code, None)
    }

    fn queue_launch_failure_with_rejection(
        &mut self,
        owner: &ActiveExecution,
        failure_code: ExecutionFailureCode,
        proof: Option<&forge_execution::NativePreSpawnRejection>,
    ) -> Result<(), ForgeExecutionCoordinatorError> {
        if self.launch_failure.is_some() {
            return Err(ForgeExecutionCoordinatorError::JournalFailed);
        }
        let failure = FailExecution::new(
            owner.running.id(),
            owner.running.revision(),
            current_timestamp_millis()?,
            failure_code,
        );
        let closure = proof
            .map(|proof| self.pre_spawn_rejection_fact(owner, &failure, proof))
            .transpose()?;
        let mut pending = PendingTerminal::launch_failure(
            owner.running.id(),
            owner.journal.clone(),
            owner.running.clone(),
            failure,
        );
        pending.closure = closure;
        self.launch_failure = Some(pending);
        Ok(())
    }

    fn queue_pending_start_failure(&mut self) -> Result<(), ForgeExecutionCoordinatorError> {
        let Some(owner) = self
            .pending_start
            .as_ref()
            .map(|pending| pending.owner.clone())
        else {
            return Err(ForgeExecutionCoordinatorError::JournalFailed);
        };
        let failure_code = match self.pending_start.as_ref().map(|pending| pending.outcome) {
            Some(PendingStartOutcome::Rejected {
                failure_code,
                journal_confirmed: false,
                ..
            }) => failure_code,
            Some(
                PendingStartOutcome::Accepted { .. }
                | PendingStartOutcome::Rejected {
                    journal_confirmed: true,
                    ..
                }
                | PendingStartOutcome::Unknown,
            )
            | None => {
                return Err(ForgeExecutionCoordinatorError::JournalFailed);
            }
        };
        let identity = self
            .pending_start
            .as_ref()
            .ok_or(ForgeExecutionCoordinatorError::JournalFailed)?
            .native_identity;
        let proof = if identity.launch_kind() == ExecutionLaunchKind::Baseline {
            // A failed query is unknown. Keep this original pending Start and
            // query again before any generic failure write or receipt ACK.
            match self.supervisor.client().observe_native_rejection(&identity) {
                Ok(proof) => proof,
                Err(error) => {
                    if matches!(
                        error,
                        ExecutionSupervisorError::StartIdentityMismatch { .. }
                    ) {
                        self.latch_journal_failure(JournalFailureStage::StartIdentity, None);
                    }
                    return Err(error.into());
                }
            }
        } else {
            None
        };
        let result = self.queue_launch_failure_with_rejection(&owner, failure_code, proof.as_ref());
        if let Err(ForgeExecutionCoordinatorError::Control(error)) = &result {
            self.latch_journal_service_failure(JournalFailureStage::StartIdentity, error);
        }
        result
    }

    fn install_pending_start_active(&mut self) {
        let Some(pending) = self.pending_start.as_ref() else {
            return;
        };
        let id = pending.id();
        if self.active.contains_key(&id) {
            return;
        }
        self.active.insert(id, pending.owner.clone());
    }

    fn progress_pending_start(&mut self) {
        let Some(outcome) = self.pending_start.as_ref().map(|pending| pending.outcome) else {
            return;
        };
        if outcome == PendingStartOutcome::Unknown {
            let Some(identity) = self
                .pending_start
                .as_ref()
                .map(|pending| pending.native_identity)
            else {
                return;
            };
            let observed = self.supervisor.client().observe_start(&identity);
            match observed {
                Ok(Some(receipt)) => {
                    if receipt.identity() == identity {
                        self.apply_start_receipt(receipt);
                    } else {
                        self.latch_journal_failure(JournalFailureStage::StartIdentity, None);
                        return;
                    }
                }
                Ok(None)
                | Err(
                    ExecutionSupervisorError::QueueFull | ExecutionSupervisorError::ReplyDropped,
                ) => return,
                Err(_) => {
                    self.latch_journal_failure(JournalFailureStage::StartObservation, None);
                    return;
                }
            }
        }

        match self.pending_start.as_ref().map(|pending| pending.outcome) {
            Some(PendingStartOutcome::Unknown) | None => {}
            Some(PendingStartOutcome::Accepted { .. }) => {
                if self.ensure_pending_active_owner() {
                    self.ack_pending_start();
                }
            }
            Some(PendingStartOutcome::Rejected {
                journal_confirmed, ..
            }) => {
                if !journal_confirmed {
                    if self.launch_failure.is_none() && self.queue_pending_start_failure().is_err()
                    {
                        return;
                    }
                    if self.launch_failure.is_some() && !self.flush_launch_failure() {
                        return;
                    }
                    if let Some(pending) = self.pending_start.as_mut()
                        && let PendingStartOutcome::Rejected {
                            failure_code, ack, ..
                        } = pending.outcome
                    {
                        pending.outcome = PendingStartOutcome::Rejected {
                            failure_code,
                            journal_confirmed: true,
                            ack,
                        };
                    }
                }
                self.ack_pending_start();
            }
        }
    }

    fn apply_start_receipt(&mut self, receipt: SupervisorStartReceipt) {
        let Some(pending) = self.pending_start.as_mut() else {
            return;
        };
        if pending.native_identity != receipt.identity() {
            return;
        }
        pending.outcome = match receipt.outcome() {
            SupervisorStartOutcome::Accepted => PendingStartOutcome::Accepted {
                ack: PendingStartAckPhase::Ready,
            },
            SupervisorStartOutcome::Rejected { failure_code } => PendingStartOutcome::Rejected {
                failure_code,
                journal_confirmed: false,
                ack: PendingStartAckPhase::Ready,
            },
        };
    }

    fn ensure_pending_active_owner(&mut self) -> bool {
        let Some(pending) = self.pending_start.as_ref() else {
            return false;
        };
        let id = pending.id();
        let expected_identity = pending.owner.identity.clone();
        let expected_revision = pending.owner.running.revision();
        match self.active.get(&id) {
            None => {
                self.install_pending_start_active();
                true
            }
            Some(active)
                if active.identity == expected_identity
                    && active.running.revision() == expected_revision =>
            {
                true
            }
            Some(_) => {
                // An active entry for the same ID is not enough.  Preserve
                // the pending owner and fail closed on an exact-owner change.
                self.journal_failed = true;
                false
            }
        }
    }

    fn ack_pending_start(&mut self) {
        let Some((identity, outcome, ack_phase)) =
            self.pending_start.as_ref().and_then(|pending| {
                let ack = match pending.outcome {
                    PendingStartOutcome::Unknown => return None,
                    PendingStartOutcome::Accepted { ack }
                    | PendingStartOutcome::Rejected { ack, .. } => ack,
                };
                Some((pending.native_identity, pending.outcome, ack))
            })
        else {
            return;
        };

        if matches!(outcome, PendingStartOutcome::Accepted { .. })
            && !self.ensure_pending_active_owner()
        {
            return;
        }

        if ack_phase == PendingStartAckPhase::Observe {
            match self.supervisor.client().observe_start(&identity) {
                Ok(Some(receipt))
                    if receipt.identity() == identity
                        && pending_start_receipt_matches(outcome, receipt.outcome()) =>
                {
                    self.set_pending_start_ack_phase(PendingStartAckPhase::Ready);
                    self.ack_pending_start();
                }
                Ok(None) => {
                    // Ownership is already known Accepted/Rejected; an
                    // absent receipt after a lost ACK therefore releases only
                    // this known owner, never an Unknown Start.
                    self.pending_start = None;
                }
                Ok(Some(_)) | Err(_) => {}
            }
            return;
        }

        let result = self.supervisor.client().acknowledge_start(&identity);
        self.process_pending_start_ack_result(&result);
    }

    fn process_pending_start_ack_result(
        &mut self,
        result: &Result<bool, ExecutionSupervisorError>,
    ) {
        match result {
            Ok(_) => self.pending_start = None,
            Err(ExecutionSupervisorError::QueueFull) => {}
            Err(ExecutionSupervisorError::ReplyDropped | ExecutionSupervisorError::Closed) => {
                self.set_pending_start_ack_phase(PendingStartAckPhase::Observe);
            }
            Err(_) => self.set_pending_start_ack_phase(PendingStartAckPhase::Observe),
        }
    }

    fn set_pending_start_ack_phase(&mut self, ack: PendingStartAckPhase) {
        let Some(pending) = self.pending_start.as_mut() else {
            return;
        };
        pending.outcome = match pending.outcome {
            PendingStartOutcome::Unknown => PendingStartOutcome::Unknown,
            PendingStartOutcome::Accepted { .. } => PendingStartOutcome::Accepted { ack },
            PendingStartOutcome::Rejected {
                failure_code,
                journal_confirmed,
                ..
            } => PendingStartOutcome::Rejected {
                failure_code,
                journal_confirmed,
                ack,
            },
        }
    }

    /// The approval wait may outlive a Makefile edit. Re-resolve the exact
    /// sealed catalog at the process-admission boundary, before a durable
    /// intent or child process can be created.
    fn resolve_current_project_command(
        &self,
        mut start: ExecutionCoordinatorStartRequest,
    ) -> Result<ExecutionCoordinatorStartRequest, ForgeExecutionCoordinatorError> {
        let Some(expected) = start.project_command else {
            return Ok(start);
        };
        let authority = start
            .agent_authority
            .as_ref()
            .ok_or(ForgeExecutionCoordinatorError::AttributionMismatch)?;
        let command_id = ProjectCommandId::new(authority.command_id.as_str().to_owned())
            .map_err(|_| ForgeExecutionCoordinatorError::AttributionMismatch)?;
        let observed_at = current_timestamp_millis()?;
        let prepared = self.control.prepare_project_command_verification(
            ProjectCommandListRequest {
                scope: start.scope.clone(),
                activity: FileActivityScope {
                    activity_id: start.activity_id,
                    runtime_instance_id: start.runtime_instance_id,
                    observed_at,
                },
            },
            command_id,
            expected.catalog_fingerprint(),
            start.request.id(),
            Arc::clone(&self.verification_cancellation),
        )?;
        let (resolved, input) = prepared.into_parts();
        let evidence = ProjectCommandEvidence::new(resolved.class(), resolved.fingerprint());
        if evidence != expected || resolved.request() != &start.request {
            return Err(ForgeExecutionCoordinatorError::AttributionMismatch);
        }
        start.request = resolved.into_request();
        start.verification_input = Some(input);
        Ok(start)
    }

    fn existing_execution_start(
        &self,
        id: ExecutionId,
        identity: &ExecutionStartIdentity,
    ) -> Result<Option<ExecutionStartResult>, ForgeExecutionCoordinatorError> {
        let Some(active) = self.active.get(&id) else {
            return Ok(None);
        };
        if &active.identity == identity {
            return Ok(Some(ExecutionStartResult::new(
                id,
                ExecutionStartDisposition::Existing,
            )));
        }
        Err(ForgeExecutionCoordinatorError::DuplicateExecution(id))
    }

    fn consume_authorization(
        &self,
        start: &ExecutionCoordinatorStartRequest,
        activity: ApprovalActivityScope,
        begin: BeginExecution,
    ) -> Result<AdmittedExecution, ForgeExecutionCoordinatorError> {
        let verification = start
            .verification_input
            .as_ref()
            .map(|input| {
                forge_domain::VerificationInputEvidence::from_manifest(input.id(), input.manifest())
            })
            .transpose()
            .map_err(|_| ForgeExecutionCoordinatorError::AttributionMismatch)?;
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
                            agent_authority: start.agent_authority.clone(),
                            project_command: start.project_command,
                            verification,
                            admission_envelope: start.admission_envelope.map(Box::new),
                        })?;
                Ok(AdmittedExecution {
                    layout: admission.layout().clone(),
                    begin_revision: admission.begin().record().revision(),
                    status: admission.begin().status(),
                    state: admission.begin().record().state(),
                    journal: admission.journal().clone(),
                })
            }
            CoordinatorAuthorization::Auto(authorization) => {
                let admission = self
                    .control
                    .consume_auto_approval(AutoApprovalConsumeRequest {
                        scope: start.scope.clone(),
                        activity,
                        goal: start.goal,
                        auto_scope_id: authorization.auto_scope_id,
                        expected_scope_revision: authorization.auto_scope_revision,
                        approval_id: authorization.approval_id,
                        grant_id: authorization.grant_id,
                        request: start.authorization_request,
                        begin,
                        agent_authority: start.agent_authority.clone(),
                        project_command: start.project_command,
                        verification,
                    })?;
                Ok(AdmittedExecution {
                    layout: admission.layout().clone(),
                    begin_revision: admission.record().begin().record().revision(),
                    status: admission.record().begin().status(),
                    state: admission.record().begin().record().state(),
                    journal: admission.journal().clone(),
                })
            }
        }
    }

    fn cancel_execution(
        &mut self,
        id: ExecutionId,
    ) -> Result<bool, ForgeExecutionCoordinatorError> {
        let cancellation = self
            .supervisor
            .client()
            .cancel_execution(id)
            .map(usize::from);
        self.finish_stop_phases(cancellation, |active_id, _| active_id == id, |_| false)
            .map(|requested| requested != 0)
    }

    fn cancel_agent_execution(
        &mut self,
        authority: AgentExecutionAuthorityRequest,
        id: ExecutionId,
    ) -> Result<bool, ForgeExecutionCoordinatorError> {
        // Cancellation is an effect: a stored provenance match alone cannot
        // authorize a closed or unavailable logical session. Resolve on this
        // owner thread after admission, outside the persistence transaction.
        let _session = self
            .control
            .agent_session_resolve(crate::AgentSessionResolveRequest {
                session_id: authority.session_id,
                principal: authority.principal,
            })?;
        // This read is the authorization linearization point. It must remain
        // directly adjacent to the supervisor request on this single owner
        // thread so external callers cannot perform a stale preflight/effect sequence.
        let _authorized = self.control.execution_get_authorized(authority, id)?;
        self.cancel_execution(id)
    }

    fn finish_stop_phases(
        &mut self,
        cancellation: Result<usize, ExecutionSupervisorError>,
        keep_waiting: impl Fn(ExecutionId, &ActiveExecution) -> bool,
        keep_pending: impl Fn(&PendingTerminal) -> bool,
    ) -> Result<usize, ForgeExecutionCoordinatorError> {
        let (requested, cancellation_error) = match cancellation {
            Ok(requested) => (Some(requested), None),
            Err(error) => (None, Some(error)),
        };
        let journal_error = self.wait_for(keep_waiting, keep_pending).err();
        let execution_error = match (cancellation_error, journal_error) {
            (None, None) => None,
            (Some(cancellation), None) => {
                Some(ForgeExecutionCoordinatorError::Supervisor(cancellation))
            }
            (None, Some(journal)) => Some(journal),
            (Some(cancellation), Some(journal)) => {
                Some(ForgeExecutionCoordinatorError::CancellationAndJournal {
                    cancellation: Box::new(cancellation),
                    journal: Box::new(journal),
                })
            }
        };
        match (execution_error, requested) {
            (None, Some(requested)) => Ok(requested),
            (Some(execution), _) => Err(execution),
            (None, None) => Err(ForgeExecutionCoordinatorError::JournalFailed),
        }
    }

    fn stop_workspace_and_journal(
        &mut self,
        workspace_id: WorkspaceId,
    ) -> Result<usize, ForgeExecutionCoordinatorError> {
        let cancellation = self.supervisor.client().cancel_workspace(workspace_id);
        self.finish_stop_phases(
            cancellation,
            |_, active| active.workspace_id == workspace_id,
            |pending| pending.belongs_to_workspace(workspace_id),
        )
    }

    fn stop_activity_and_journal(
        &mut self,
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
    ) -> Result<usize, ForgeExecutionCoordinatorError> {
        let ids: Vec<_> = self
            .active
            .iter()
            .filter_map(|(id, active)| {
                (active.workspace_id == workspace_id && active.activity_id == activity_id)
                    .then_some(*id)
            })
            .collect();
        let mut ids = ids;
        if let Some(pending) = self.pending_start.as_ref()
            && pending.workspace_id() == workspace_id
            && pending.activity_id() == activity_id
            && !ids.contains(&pending.id())
        {
            ids.push(pending.id());
        }
        let mut requested = 0;
        let mut cancellation_error = None;
        for id in ids {
            match self.supervisor.client().cancel_execution(id) {
                Ok(cancelled) => requested += usize::from(cancelled),
                Err(error) if cancellation_error.is_none() => cancellation_error = Some(error),
                Err(_) => {}
            }
        }
        let cancellation = match cancellation_error {
            Some(error) => Err(error),
            None => Ok(requested),
        };
        self.finish_stop_phases(
            cancellation,
            |_, active| active.workspace_id == workspace_id && active.activity_id == activity_id,
            |pending| pending.belongs_to_activity(workspace_id, activity_id),
        )
    }

    fn stop_all_and_journal(&mut self) -> Result<usize, ForgeExecutionCoordinatorError> {
        let cancellation = self.supervisor.client().stop_all();
        self.finish_stop_phases(cancellation, |_, _| true, |_| true)
    }

    fn wait_for(
        &mut self,
        keep_waiting: impl Fn(ExecutionId, &ActiveExecution) -> bool,
        keep_launch_failure: impl Fn(&PendingTerminal) -> bool,
    ) -> Result<(), ForgeExecutionCoordinatorError> {
        if self.journal_failed {
            return Err(self.journal_failure_error());
        }
        let deadline = Instant::now() + STOP_DEADLINE;
        while self
            .active
            .iter()
            .any(|(id, active)| keep_waiting(*id, active))
            || self
                .launch_failure
                .as_ref()
                .is_some_and(&keep_launch_failure)
            || self.terminal_backlog.iter().any(&keep_launch_failure)
            || self
                .pending_start
                .as_ref()
                .is_some_and(|pending| keep_waiting(pending.id(), &pending.owner))
        {
            self.drain_wait_cancellations();
            let _progress = self.poll_and_journal();
            self.drain_wait_cancellations();
            if self.journal_failed {
                return Err(self.journal_failure_error());
            }
            if Instant::now() >= deadline {
                return Err(ForgeExecutionCoordinatorError::JournalTimeout);
            }
            thread::sleep(POLL_INTERVAL);
        }
        Ok(())
    }

    fn poll_and_journal(&mut self) -> JournalProgress {
        let mut progress = JournalProgress::default();
        self.progress_pending_start();
        if self
            .pending_start
            .as_ref()
            .is_some_and(|pending| pending.outcome == PendingStartOutcome::Unknown)
        {
            // Output for an execution whose native admission is still
            // unknown cannot be attributed safely.  Keep the bounded native
            // ledger and apply backpressure until the exact receipt resolves.
            return progress;
        }
        self.poll_and_persist_output(&mut progress);
        if !self.journal_failed {
            let _ = self.flush_launch_failure();
        }
        if !self.journal_failed {
            self.drain_terminal_events();
            self.drive_terminal_backlog(&mut progress);
        }
        self.retire_terminal_executions();
        progress
    }

    fn drain_terminal_events(&mut self) {
        if self.terminal_backlog.len() >= MAX_TERMINAL_BACKLOG {
            return;
        }
        let remaining = MAX_TERMINAL_BACKLOG - self.terminal_backlog.len();
        // Peek the full native bounded ledger. Earlier retained events may be
        // blocked on output or an ACK; limiting the native peek to `remaining`
        // could therefore starve an unrelated later event that is ready.
        let events = match self
            .supervisor
            .client()
            .peek_terminal_events(MAX_TERMINAL_BACKLOG)
        {
            Ok(events) => events,
            Err(ExecutionSupervisorError::QueueFull | ExecutionSupervisorError::ReplyDropped) => {
                return;
            }
            Err(_) => {
                // A non-destructive peek cannot lose a terminal event, but an
                // unavailable native owner still leaves attribution unknown.
                self.journal_failed = true;
                return;
            }
        };
        let mut admitted = 0;
        for event in events {
            if let Some(existing) = self
                .terminal_backlog
                .iter()
                .find(|pending| pending.key == Some(event.key()))
            {
                if !existing.matches_event(&event) {
                    self.journal_failed = true;
                    return;
                }
                continue;
            }
            if admitted >= remaining {
                break;
            }
            self.terminal_backlog.push_back(PendingTerminal::new(event));
            admitted += 1;
        }
    }

    fn drive_terminal_backlog(&mut self, progress: &mut JournalProgress) {
        let terminal_passes = self.terminal_backlog.len();
        for _ in 0..terminal_passes {
            if self.journal_failed {
                break;
            }
            let Some(mut pending) = self.terminal_backlog.pop_front() else {
                break;
            };
            match self.advance_terminal(&mut pending, progress) {
                TerminalStep::Done => {}
                TerminalStep::Back => self.terminal_backlog.push_back(pending),
                TerminalStep::FrontAndStop => {
                    self.terminal_backlog.push_front(pending);
                    break;
                }
            }
        }
    }

    fn advance_terminal(
        &mut self,
        pending: &mut PendingTerminal,
        progress: &mut JournalProgress,
    ) -> TerminalStep {
        let id = pending.execution_id();
        if pending.event.is_some()
            && (self.pending_output_ack_unknown() || self.pending_output_for(id))
        {
            return TerminalStep::Back;
        }
        if pending.event.is_some() {
            match self.supervisor.client().has_pending_output(id) {
                Ok(true)
                | Err(
                    ExecutionSupervisorError::QueueFull | ExecutionSupervisorError::ReplyDropped,
                ) => {
                    return TerminalStep::Back;
                }
                Err(_) => {
                    self.journal_failed = true;
                    return TerminalStep::FrontAndStop;
                }
                Ok(false) => {}
            }
        }
        if pending.command.is_none() {
            match self.prepare_terminal(pending) {
                Ok(()) => {}
                Err(ControlClientError::QueueFull | ControlClientError::ResponseDropped) => {
                    return TerminalStep::Back;
                }
                Err(_) => {
                    self.journal_failed = true;
                    return TerminalStep::FrontAndStop;
                }
            }
        }
        match pending.state {
            JournalWorkState::Write => match self.write_terminal(pending) {
                Ok(()) => {
                    pending.state = JournalWorkState::Confirmed;
                    self.mark_terminal_confirmed(pending, progress);
                    self.advance_terminal_ack(pending)
                }
                Err(ControlClientError::QueueFull) => TerminalStep::Back,
                Err(error) if control_error_requires_readback(&error) => {
                    pending.state = JournalWorkState::Readback;
                    TerminalStep::Back
                }
                Err(_) => {
                    self.journal_failed = true;
                    TerminalStep::FrontAndStop
                }
            },
            JournalWorkState::Readback => self.reconcile_terminal(pending, progress),
            JournalWorkState::Confirmed => {
                self.mark_terminal_confirmed(pending, progress);
                self.advance_terminal_ack(pending)
            }
        }
    }

    fn advance_terminal_ack(&mut self, pending: &mut PendingTerminal) -> TerminalStep {
        let (Some(key), Some(identity)) = (pending.key.as_ref(), pending.native_identity) else {
            if pending.event.is_none()
                && pending.key.is_none()
                && pending.native_identity.is_none()
                && pending.ack == TerminalAckPhase::Settled
            {
                // Launch-failure envelopes have no native terminal event and
                // therefore have no native ACK obligation.
                return TerminalStep::Done;
            }
            self.journal_failed = true;
            return TerminalStep::FrontAndStop;
        };
        match pending.ack {
            TerminalAckPhase::Settled => TerminalStep::Done,
            TerminalAckPhase::Ready => {
                match self
                    .supervisor
                    .client()
                    .acknowledge_terminal_event(key, &identity)
                {
                    Ok(true) => {
                        pending.ack = TerminalAckPhase::Settled;
                        TerminalStep::Done
                    }
                    Ok(false) | Err(ExecutionSupervisorError::ReplyDropped) => {
                        pending.ack = TerminalAckPhase::Observe;
                        TerminalStep::Back
                    }
                    Err(ExecutionSupervisorError::QueueFull) => TerminalStep::Back,
                    Err(ExecutionSupervisorError::TerminalEventIdentityMismatch { .. }) => {
                        self.journal_failed = true;
                        TerminalStep::FrontAndStop
                    }
                    Err(_) => {
                        // A closed or otherwise unobservable owner cannot
                        // prove that this exact native event was settled.
                        self.journal_failed = true;
                        TerminalStep::FrontAndStop
                    }
                }
            }
            TerminalAckPhase::Observe => {
                match self
                    .supervisor
                    .client()
                    .observe_terminal_event(key, &identity)
                {
                    Ok(Some(event)) if pending.matches_event(&event) => {
                        pending.ack = TerminalAckPhase::Ready;
                        TerminalStep::Back
                    }
                    Ok(Some(_)) => {
                        self.journal_failed = true;
                        TerminalStep::FrontAndStop
                    }
                    Ok(None) => {
                        // The native owner has already checked this exact key
                        // and identity. After SQL confirmation, exact-owner
                        // absence proves the earlier ACK was settled.
                        pending.ack = TerminalAckPhase::Settled;
                        TerminalStep::Done
                    }
                    Err(error) => match error {
                        ExecutionSupervisorError::QueueFull
                        | ExecutionSupervisorError::ReplyDropped => TerminalStep::Back,
                        _ => {
                            self.journal_failed = true;
                            TerminalStep::FrontAndStop
                        }
                    },
                }
            }
        }
    }

    fn reconcile_terminal(
        &mut self,
        pending: &mut PendingTerminal,
        progress: &mut JournalProgress,
    ) -> TerminalStep {
        let (Some(journal), Some(before), Some(command)) = (
            pending.journal.as_ref(),
            pending.before.as_ref(),
            pending.command.as_ref(),
        ) else {
            self.journal_failed = true;
            return TerminalStep::FrontAndStop;
        };
        match self.control.execution_journal_reconcile_terminal(
            journal,
            before,
            command,
            pending.closure,
        ) {
            Ok(JournalReadback::Confirmed) => {
                pending.state = JournalWorkState::Confirmed;
                self.mark_terminal_confirmed(pending, progress);
                self.advance_terminal_ack(pending)
            }
            Ok(JournalReadback::Absent) => {
                pending.state = JournalWorkState::Write;
                TerminalStep::Back
            }
            Err(ControlClientError::QueueFull) => TerminalStep::Back,
            Ok(JournalReadback::Mismatch) | Err(_) => {
                self.journal_failed = true;
                TerminalStep::FrontAndStop
            }
        }
    }

    fn poll_and_persist_output(&mut self, progress: &mut JournalProgress) {
        if self.journal_failed {
            return;
        }
        if self.pending_output.is_none() {
            let read = match self
                .supervisor
                .client()
                .read_output_events(forge_execution::MAX_OUTPUT_EVENT_BACKLOG)
            {
                Ok(read) => read,
                Err(
                    ExecutionSupervisorError::QueueFull | ExecutionSupervisorError::ReplyDropped,
                ) => return,
                Err(_) => {
                    self.latch_journal_failure(JournalFailureStage::OutputRead, None);
                    return;
                }
            };
            if read.events().is_empty() {
                return;
            }
            let Some(ack_key) = read.ack_key() else {
                self.latch_journal_failure(JournalFailureStage::OutputIdentity, None);
                return;
            };
            let mut groups = Vec::new();
            for event in read.events().iter().cloned() {
                let id = event.execution_id();
                let Some(active) = self.active.get(&id) else {
                    self.latch_journal_failure(JournalFailureStage::OutputIdentity, None);
                    return;
                };
                if active.journal.execution_id() != id {
                    self.latch_journal_failure(JournalFailureStage::OutputIdentity, None);
                    return;
                }
                if let Some(group) = groups
                    .iter_mut()
                    .find(|group: &&mut PendingOutputGroup| group.execution_id == id)
                {
                    group.events.push(event);
                } else {
                    groups.push(PendingOutputGroup {
                        execution_id: id,
                        events: vec![event],
                        before: active.running.clone(),
                        journal: active.journal.clone(),
                        state: JournalWorkState::Write,
                    });
                }
            }
            self.pending_output = Some(PendingOutput {
                events: read.events().to_vec(),
                ack_key,
                groups,
                ack_state: OutputAckState::Pending,
            });
        }
        self.drive_pending_output(progress);
    }

    fn drive_pending_output(&mut self, progress: &mut JournalProgress) {
        if self.drive_pending_output_groups(progress) {
            self.advance_output_ack(progress);
        }
    }

    fn drive_pending_output_groups(&mut self, progress: &mut JournalProgress) -> bool {
        let group_count = self
            .pending_output
            .as_ref()
            .map_or(0, |pending| pending.groups.len());
        for index in 0..group_count {
            let (execution_id, state, journal, before, events) = {
                let Some(pending) = self.pending_output.as_ref() else {
                    return false;
                };
                let group = &pending.groups[index];
                (
                    group.execution_id,
                    group.state,
                    group.journal.clone(),
                    group.before.clone(),
                    group.events.clone(),
                )
            };
            match state {
                JournalWorkState::Confirmed => {}
                JournalWorkState::Write => {
                    match self.control.execution_journal_output(&journal, events) {
                        Ok(()) => {
                            if let Some(pending) = self.pending_output.as_mut() {
                                pending.groups[index].state = JournalWorkState::Confirmed;
                            }
                            progress.record(execution_id);
                        }
                        Err(ControlClientError::QueueFull) => return false,
                        Err(error) if control_error_requires_readback(&error) => {
                            if let Some(pending) = self.pending_output.as_mut() {
                                pending.groups[index].state = JournalWorkState::Readback;
                            }
                            return false;
                        }
                        Err(error) => {
                            self.latch_journal_service_failure(
                                JournalFailureStage::OutputWrite,
                                &error,
                            );
                            return false;
                        }
                    }
                }
                JournalWorkState::Readback => {
                    match self
                        .control
                        .execution_journal_reconcile_output(&journal, &before, &events)
                    {
                        Ok(JournalReadback::Confirmed) => {
                            if let Some(pending) = self.pending_output.as_mut() {
                                pending.groups[index].state = JournalWorkState::Confirmed;
                            }
                            progress.record(execution_id);
                        }
                        Ok(JournalReadback::Absent) => {
                            if let Some(pending) = self.pending_output.as_mut() {
                                pending.groups[index].state = JournalWorkState::Write;
                            }
                            return false;
                        }
                        Err(ControlClientError::QueueFull) => return false,
                        Ok(JournalReadback::Mismatch) => {
                            self.latch_journal_failure(JournalFailureStage::OutputReadback, None);
                            return false;
                        }
                        Err(error) => {
                            self.latch_journal_service_failure(
                                JournalFailureStage::OutputReadback,
                                &error,
                            );
                            return false;
                        }
                    }
                }
            }
        }

        true
    }

    fn advance_output_ack(&mut self, progress: &mut JournalProgress) {
        let Some(ack_state) = self
            .pending_output
            .as_ref()
            .map(|pending| pending.ack_state)
        else {
            return;
        };
        match ack_state {
            OutputAckState::Pending => {
                let Some(ack_key) = self.pending_output.as_ref().map(|pending| pending.ack_key)
                else {
                    self.latch_journal_failure(JournalFailureStage::OutputAcknowledgement, None);
                    return;
                };
                let event_count = self
                    .pending_output
                    .as_ref()
                    .map_or(0, |pending| pending.events.len());
                match self.supervisor.client().ack_output_events(ack_key) {
                    Ok(count) if count == event_count => {
                        self.confirm_output(progress);
                    }
                    Err(
                        ExecutionSupervisorError::Closed
                        | ExecutionSupervisorError::OutputReadInvalidated
                        | ExecutionSupervisorError::OutputAckWithoutRead
                        | ExecutionSupervisorError::OutputAckMismatch { .. },
                    ) => {
                        if let Some(pending) = self.pending_output.as_mut() {
                            pending.ack_state = OutputAckState::Readback;
                        }
                        self.latch_journal_failure(
                            JournalFailureStage::OutputAcknowledgement,
                            None,
                        );
                    }
                    Err(ExecutionSupervisorError::QueueFull) => {}
                    Ok(_) | Err(_) => {
                        if let Some(pending) = self.pending_output.as_mut() {
                            pending.ack_state = OutputAckState::Readback;
                        }
                    }
                }
            }
            OutputAckState::Readback => {
                let read = match self
                    .supervisor
                    .client()
                    .read_output_events(forge_execution::MAX_OUTPUT_EVENT_BACKLOG)
                {
                    Ok(read) => read,
                    Err(
                        ExecutionSupervisorError::QueueFull
                        | ExecutionSupervisorError::ReplyDropped,
                    ) => return,
                    Err(_) => {
                        self.latch_journal_failure(
                            JournalFailureStage::OutputAcknowledgement,
                            None,
                        );
                        return;
                    }
                };
                let Some(pending) = self.pending_output.as_ref() else {
                    return;
                };
                match classify_ack_readback(&pending.events, pending.ack_key, &read) {
                    AckReadback::Pending => {
                        if let Some(pending) = self.pending_output.as_mut() {
                            pending.ack_state = OutputAckState::Pending;
                        }
                    }
                    AckReadback::Confirmed => self.confirm_output(progress),
                    AckReadback::Mismatch => {
                        self.latch_journal_failure(
                            JournalFailureStage::OutputAcknowledgement,
                            None,
                        );
                    }
                }
            }
        }
    }

    fn confirm_output(&mut self, progress: &mut JournalProgress) {
        let Some(pending) = self.pending_output.take() else {
            return;
        };
        for event in pending.events {
            progress.record(event.execution_id());
        }
    }

    fn pending_output_for(&self, id: ExecutionId) -> bool {
        self.pending_output
            .as_ref()
            .is_some_and(|pending| pending.groups.iter().any(|group| group.execution_id == id))
    }

    fn pending_output_ack_unknown(&self) -> bool {
        self.pending_output
            .as_ref()
            .is_some_and(|pending| pending.ack_state == OutputAckState::Readback)
    }

    fn retire_terminal_executions(&mut self) {
        if self.journal_failed {
            return;
        }
        let ids: Vec<_> = self
            .active
            .iter()
            .filter_map(|(id, active)| active.terminal_journaled.then_some(*id))
            .collect();
        for id in ids {
            if self.pending_output_for(id) {
                continue;
            }
            if self
                .terminal_backlog
                .iter()
                .any(|pending| pending.execution_id() == id)
            {
                // The native terminal event remains the owner fence until
                // its exact key and identity have been acknowledged.
                continue;
            }
            if self.pending_start.as_ref().is_some_and(|pending| {
                pending.id() == id
                    && matches!(pending.outcome, PendingStartOutcome::Accepted { .. })
            }) {
                // Keep the exact active owner until the native receipt ACK is
                // resolved; a fast terminal must not make that owner vanish.
                continue;
            }
            match self.supervisor.client().has_pending_output(id) {
                Ok(false) => {
                    let _removed = self.active.remove(&id);
                }
                Ok(true)
                | Err(
                    ExecutionSupervisorError::QueueFull | ExecutionSupervisorError::ReplyDropped,
                ) => {}
                Err(_) => {
                    self.journal_failed = true;
                    return;
                }
            }
        }
    }

    fn prepare_terminal(
        &mut self,
        pending: &mut PendingTerminal,
    ) -> Result<(), ControlClientError> {
        let id = pending.execution_id();
        let event = pending.event.as_ref().ok_or_else(control_conflict)?;
        let active = self.active.get(&id).ok_or_else(control_conflict)?;
        let Some(native_identity) = active.native_identity else {
            return Err(control_conflict());
        };
        if active.journal.execution_id() != id
            || event.key() != pending.key.clone().ok_or_else(control_conflict)?
            || event.identity() != pending.native_identity.ok_or_else(control_conflict)?
            || event.identity() != native_identity
            || event.execution_id() != active.running.id()
            || event.execution_id() != event.identity().execution_id()
            || event.workspace_id() != active.running.workspace_id()
            || event.workspace_id() != event.identity().workspace_id()
            || event.identity().activity_id() != active.running.activity_id()
            || event.identity().request_digest() != active.running.request_digest()
        {
            return Err(control_conflict());
        }
        let before = active.running.clone();
        let observed_at = current_timestamp_millis().map_err(|_| control_internal())?;
        let closure = self
            .supervisor
            .client()
            .observe_native_closure(event)
            .map_err(|error| match error {
                ExecutionSupervisorError::QueueFull => ControlClientError::QueueFull,
                ExecutionSupervisorError::ReplyDropped => ControlClientError::ResponseDropped,
                _ => control_conflict(),
            })?;
        let closure = closure
            .map(|proof| native_closure_fact(&before, observed_at, &proof))
            .transpose()?;
        let command = match (event.result(), event.generated_package()) {
            (Ok(outcome), Some(manifest)) => JournalTerminalCommand::Complete {
                command: CompleteExecution::new(before.revision(), observed_at, outcome.clone()),
                manifest: Some(manifest),
            },
            (Ok(outcome), None) => JournalTerminalCommand::Complete {
                command: CompleteExecution::new(before.revision(), observed_at, outcome.clone()),
                manifest: None,
            },
            (Err(failure), None) => JournalTerminalCommand::Fail {
                command: FailExecution::new(id, before.revision(), observed_at, *failure),
            },
            (Err(_), Some(_)) => return Err(control_conflict()),
        };
        pending.journal = Some(active.journal.clone());
        pending.before = Some(before);
        pending.command = Some(command);
        pending.closure = closure;
        Ok(())
    }

    fn write_terminal(&self, pending: &PendingTerminal) -> Result<(), ControlClientError> {
        let journal = pending.journal.as_ref().ok_or_else(control_conflict)?;
        let command = pending.command.as_ref().ok_or_else(control_conflict)?;
        match command {
            JournalTerminalCommand::Complete {
                command,
                manifest: Some(manifest),
            } => self
                .control
                .execution_journal_complete_generated(
                    journal,
                    command.clone(),
                    *manifest,
                    pending.closure,
                )
                .map(|_| ()),
            JournalTerminalCommand::Complete {
                command,
                manifest: None,
            } => self
                .control
                .execution_journal_complete(journal, command.clone(), pending.closure)
                .map(|_| ()),
            JournalTerminalCommand::Fail { command } => self
                .control
                .execution_journal_fail(journal, *command, pending.closure)
                .map(|_| ()),
        }
    }

    fn mark_terminal_confirmed(
        &mut self,
        pending: &mut PendingTerminal,
        progress: &mut JournalProgress,
    ) {
        if pending.durable_recorded {
            return;
        }
        pending.durable_recorded = true;
        let id = pending.execution_id();
        if let Some(active) = self.active.get_mut(&id) {
            active.terminal_journaled = true;
        }
        progress.record(id);
        self.terminal_records += 1;
    }

    /// Advance the admitted launch-failure envelope once. The envelope is
    /// kept outside `active`: no active native owner was returned, but the
    /// durable running record and exact failure still need reconciliation.
    /// This alone does not prove process or runtime cleanup.
    fn flush_launch_failure(&mut self) -> bool {
        let Some(mut pending) = self.launch_failure.take() else {
            return true;
        };
        if self.pending_output_ack_unknown() {
            self.launch_failure = Some(pending);
            return false;
        }
        let confirmed = match pending.state {
            JournalWorkState::Write => match self.write_terminal(&pending) {
                Ok(()) if pending.closure.is_some() => {
                    // Confirm the complete immutable native fact with the
                    // terminal snapshot before releasing the Start receipt.
                    pending.state = JournalWorkState::Readback;
                    false
                }
                Ok(()) => true,
                Err(ControlClientError::QueueFull) => false,
                Err(error) if control_error_requires_readback(&error) => {
                    pending.state = JournalWorkState::Readback;
                    false
                }
                Err(_) => {
                    self.journal_failed = true;
                    false
                }
            },
            JournalWorkState::Readback => {
                let (Some(journal), Some(before), Some(command)) = (
                    pending.journal.as_ref(),
                    pending.before.as_ref(),
                    pending.command.as_ref(),
                ) else {
                    self.journal_failed = true;
                    self.launch_failure = Some(pending);
                    return false;
                };
                match self.control.execution_journal_reconcile_terminal(
                    journal,
                    before,
                    command,
                    pending.closure,
                ) {
                    Ok(JournalReadback::Confirmed) => true,
                    Ok(JournalReadback::Absent) => {
                        pending.state = JournalWorkState::Write;
                        false
                    }
                    Err(ControlClientError::QueueFull) => false,
                    Err(error) if control_error_requires_readback(&error) => false,
                    Ok(JournalReadback::Mismatch) | Err(_) => {
                        self.journal_failed = true;
                        false
                    }
                }
            }
            JournalWorkState::Confirmed => true,
        };
        if confirmed {
            self.terminal_records += 1;
            true
        } else {
            self.launch_failure = Some(pending);
            false
        }
    }
}

fn native_closure_fact(
    before: &RegisteredExecution,
    observed_at: TimestampMillis,
    proof: &forge_execution::NativeExecutionClosure,
) -> Result<forge_domain::ExecutionNativeClosureFact, ControlClientError> {
    use forge_domain::{
        NativeClosureLaunch as Launch, NativeClosureProcess as Process,
        NativeClosureRuntime as Runtime,
    };
    let identity = proof.identity();
    if identity.execution_id() != before.id()
        || identity.workspace_id() != before.workspace_id()
        || identity.activity_id() != before.activity_id()
        || identity.request_digest() != before.request_digest()
    {
        return Err(control_conflict());
    }
    let launch = match proof.identity().launch_kind() {
        ExecutionLaunchKind::Baseline => Launch::Baseline,
        ExecutionLaunchKind::RustCi => Launch::RustCi,
        ExecutionLaunchKind::RustCiGeneratedPackage => Launch::GeneratedPackage,
    };
    let process = match proof.process_disposition() {
        forge_execution::ProcessDisposition::NoChildSpawned => Process::NoChildSpawned,
        forge_execution::ProcessDisposition::ProcessGroupReaped => Process::ProcessGroupReaped,
    };
    let runtime = match proof.runtime_disposition() {
        forge_execution::RuntimeDisposition::NotApplicable => Runtime::NotApplicable,
        forge_execution::RuntimeDisposition::Cleaned => Runtime::Cleaned,
    };
    forge_domain::ExecutionNativeClosureFact::from_parts(
        forge_domain::ExecutionNativeClosureFactParts {
            attribution: forge_domain::ExecutionAttribution::new(
                before.id(),
                before.workspace_id(),
                before.activity_id(),
            ),
            request_digest: before.request_digest(),
            before_revision: before.revision(),
            after_revision: before
                .revision()
                .checked_next()
                .map_err(|_| control_conflict())?,
            output_cursor: proof.output_cursor(),
            launch,
            process,
            runtime,
            observed_at,
        },
    )
    .map_err(|_| control_conflict())
}

fn control_conflict() -> ControlClientError {
    ControlClientError::Service(crate::ControlError::new(
        crate::ControlErrorCode::ExecutionConflict,
    ))
}

fn control_internal() -> ControlClientError {
    ControlClientError::Service(crate::ControlError::new(crate::ControlErrorCode::Internal))
}

fn control_error_requires_readback(error: &ControlClientError) -> bool {
    matches!(error, ControlClientError::ResponseDropped)
        || matches!(error, ControlClientError::Service(error) if error.is_committed())
        || matches!(error, ControlClientError::Service(error)
            if error.code() == crate::ControlErrorCode::PersistenceFailure)
}

fn classify_ack_readback(
    expected_events: &[ExecutionOutputEvent],
    expected_ack_key: ExecutionOutputEventKey,
    read: &ExecutionOutputRead,
) -> AckReadback {
    if read.events() == expected_events && read.ack_key() == Some(expected_ack_key) {
        return AckReadback::Pending;
    }
    let overlaps_original_key = read.events().iter().any(|observed| {
        expected_events
            .iter()
            .any(|expected| expected.key() == observed.key())
    });
    if overlaps_original_key {
        AckReadback::Mismatch
    } else {
        AckReadback::Confirmed
    }
}

fn begin_execution_for_start(
    start: &ExecutionCoordinatorStartRequest,
    execution_id: ExecutionId,
    observed_at: TimestampMillis,
) -> Result<BeginExecution, ForgeExecutionCoordinatorError> {
    let begin = BeginExecution::from_request(
        &start.request,
        start.authorization_request.request_digest(),
        observed_at,
    );
    let begin = match start.agent_authority.as_ref() {
        Some(authority) => {
            let provenance = match start.project_command {
                Some(evidence) => authority
                    .provenance(execution_id)
                    .with_project_command(evidence),
                None => authority.provenance(execution_id),
            };
            begin
                .with_provenance(provenance)
                .map_err(|_| ForgeExecutionCoordinatorError::AttributionMismatch)?
        }
        None => begin,
    };
    Ok(begin.with_runtime_owner(start.runtime_instance_id))
}

fn derive_approved_agent_action(
    request: &ExecutionRequest,
    project_command: Option<ProjectCommandEvidence>,
) -> Result<ExecutionActionClass, ForgeExecutionCoordinatorError> {
    match (
        request.kind(),
        project_command.map(ProjectCommandEvidence::class),
    ) {
        (ExecutionKind::Structured { .. }, Some(ProjectCommandClass::Verify)) => {
            Ok(ExecutionActionClass::DiscoveredProjectCommand)
        }
        (ExecutionKind::Structured { .. }, Some(ProjectCommandClass::GeneratedPackage)) => {
            Ok(ExecutionActionClass::GeneratedProjectCommand)
        }
        (ExecutionKind::Shell { .. }, None) => Ok(ExecutionActionClass::AnalyzedShell),
        _ => Err(ForgeExecutionCoordinatorError::AttributionMismatch),
    }
}

fn validate_start_request(
    start: &ExecutionCoordinatorStartRequest,
) -> Result<(), ForgeExecutionCoordinatorError> {
    let authority_matches_action = matches!(
        (
            start.authorization_request.action(),
            start.agent_authority.is_some(),
            start.project_command.map(ProjectCommandEvidence::class),
        ),
        (
            ExecutionActionClass::DiscoveredProjectCommand,
            true,
            Some(ProjectCommandClass::Verify)
        ) | (ExecutionActionClass::AnalyzedShell, true, None)
            | (
                ExecutionActionClass::GeneratedProjectCommand,
                true,
                Some(ProjectCommandClass::GeneratedPackage)
            )
            | (
                ExecutionActionClass::DirectStructured | ExecutionActionClass::ShellEscape,
                false,
                None
            )
    );
    if start.request.workspace_id() != start.scope.workspace_id()
        || start.request.activity_id() != start.activity_id
        || start.authorization_request.execution_id() != start.request.id()
        || start.authorization_request.workspace_id() != start.scope.workspace_id()
        || start.authorization_request.activity_id() != start.activity_id
        || start.authorization_request.request_digest() != execution_request_digest(&start.request)
        || start.authorization_request.requested().get() != start.request.permissions()
        || !authority_matches_action
        || (start.project_command.is_some() != start.verification_input.is_some())
    {
        Err(ForgeExecutionCoordinatorError::AttributionMismatch)
    } else {
        Ok(())
    }
}

fn derive_launch_kind_parts(
    action: ExecutionActionClass,
    request: &ExecutionRequest,
    agent_authority: Option<&AgentExecutionAuthorityRequest>,
    project_command: Option<ProjectCommandEvidence>,
    capability: Option<&RustCiToolchainCapability>,
) -> Result<ExecutionLaunchKind, ForgeExecutionCoordinatorError> {
    match action {
        ExecutionActionClass::DiscoveredProjectCommand => {
            let authority =
                agent_authority.ok_or(ForgeExecutionCoordinatorError::AttributionMismatch)?;
            if project_command.map(ProjectCommandEvidence::class)
                != Some(ProjectCommandClass::Verify)
                || !is_exact_project_verify_request(authority.command_id.as_str(), request)
            {
                return Err(ForgeExecutionCoordinatorError::RustCiCommandMismatch);
            }
            if is_exact_research_package_request(authority.command_id.as_str(), request) {
                let capability = PackageVExecutableCapability::prepare_current()
                    .map_err(ForgeExecutionCoordinatorError::PackageVExecutableUnavailable)?;
                capability
                    .revalidate()
                    .map_err(ForgeExecutionCoordinatorError::PackageVExecutableUnavailable)?;
                return Ok(ExecutionLaunchKind::Baseline);
            }
            revalidate_rust_tooling(capability)?;
            Ok(ExecutionLaunchKind::RustCi)
        }
        ExecutionActionClass::AnalyzedShell => {
            let authority =
                agent_authority.ok_or(ForgeExecutionCoordinatorError::AttributionMismatch)?;
            let ExecutionKind::Shell { script } = request.kind() else {
                return Err(ForgeExecutionCoordinatorError::AttributionMismatch);
            };
            let analyzed = crate::shell::analyze_shell_script(script.as_str().to_owned())
                .map_err(|_| ForgeExecutionCoordinatorError::AttributionMismatch)?;
            if analyzed.intent_id() != &authority.command_id
                || analyzed.permissions() != request.permissions()
            {
                return Err(ForgeExecutionCoordinatorError::AttributionMismatch);
            }
            if analyzed.requires_rust_tooling() {
                revalidate_rust_tooling(capability)?;
                Ok(ExecutionLaunchKind::RustCi)
            } else {
                Ok(ExecutionLaunchKind::Baseline)
            }
        }
        ExecutionActionClass::GeneratedProjectCommand => {
            let evidence =
                project_command.ok_or(ForgeExecutionCoordinatorError::AttributionMismatch)?;
            let authority =
                agent_authority.ok_or(ForgeExecutionCoordinatorError::AttributionMismatch)?;
            if evidence.class() != ProjectCommandClass::GeneratedPackage
                || !is_exact_rust_generated_package_request(authority.command_id.as_str(), request)
            {
                return Err(ForgeExecutionCoordinatorError::RustCiCommandMismatch);
            }
            revalidate_rust_tooling(capability)?;
            Ok(ExecutionLaunchKind::RustCiGeneratedPackage)
        }
        ExecutionActionClass::DirectStructured | ExecutionActionClass::ShellEscape => {
            Ok(ExecutionLaunchKind::Baseline)
        }
    }
}

fn revalidate_rust_tooling(
    capability: Option<&RustCiToolchainCapability>,
) -> Result<(), ForgeExecutionCoordinatorError> {
    let capability = capability.ok_or(ForgeExecutionCoordinatorError::RustCiCapabilityMissing)?;
    capability
        .revalidate_current()
        .map_err(ForgeExecutionCoordinatorError::RustCiToolchainUnavailable)
}

fn current_timestamp_millis() -> Result<TimestampMillis, ForgeExecutionCoordinatorError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ForgeExecutionCoordinatorError::Clock)?;
    let millis =
        i64::try_from(elapsed.as_millis()).map_err(|_| ForgeExecutionCoordinatorError::Clock)?;
    TimestampMillis::new(millis).map_err(|_| ForgeExecutionCoordinatorError::Clock)
}

fn invalid_wait_timeout() -> ForgeExecutionCoordinatorError {
    ForgeExecutionCoordinatorError::InvalidWaitTimeout
}

fn pending_start_receipt_matches(
    outcome: PendingStartOutcome,
    receipt: SupervisorStartOutcome,
) -> bool {
    match (outcome, receipt) {
        (PendingStartOutcome::Accepted { .. }, SupervisorStartOutcome::Accepted) => true,
        (
            PendingStartOutcome::Rejected { failure_code, .. },
            SupervisorStartOutcome::Rejected {
                failure_code: actual,
            },
        ) => failure_code == actual,
        (PendingStartOutcome::Unknown, _)
        | (PendingStartOutcome::Accepted { .. }, SupervisorStartOutcome::Rejected { .. })
        | (PendingStartOutcome::Rejected { .. }, SupervisorStartOutcome::Accepted) => false,
    }
}

fn supervisor_failure_code(error: &ExecutionSupervisorError) -> Option<ExecutionFailureCode> {
    Some(match error {
        ExecutionSupervisorError::Execution(error) => error.failure_code(),
        ExecutionSupervisorError::RustCiWorkspaceCapacity(_)
        | ExecutionSupervisorError::Draining
        | ExecutionSupervisorError::CompletionBacklog
        | ExecutionSupervisorError::DuplicateExecution(_)
        | ExecutionSupervisorError::StartReceiptCapacity
        | ExecutionSupervisorError::StartIdentityMismatch { .. }
        | ExecutionSupervisorError::TerminalEventGenerationExhausted { .. }
        | ExecutionSupervisorError::StartRejected {
            failure_code: ExecutionFailureCode::Admission,
        }
        | ExecutionSupervisorError::QueueFull => ExecutionFailureCode::Admission,
        ExecutionSupervisorError::StartRejected { failure_code } => *failure_code,
        ExecutionSupervisorError::ReplyDropped
        | ExecutionSupervisorError::InvalidWorkspaceIdentity
        | ExecutionSupervisorError::TerminalEventOwnerMismatch { .. }
        | ExecutionSupervisorError::NativeClosureOwnerMismatch { .. }
        | ExecutionSupervisorError::NativeClosureEventMismatch { .. } => return None,
        ExecutionSupervisorError::Closed
        | ExecutionSupervisorError::TerminalEventIdentityMismatch { .. }
        | ExecutionSupervisorError::InvalidTerminalEventLimit { .. }
        | ExecutionSupervisorError::InvalidOutputDrainLimit { .. }
        | ExecutionSupervisorError::OutputAckWithoutRead
        | ExecutionSupervisorError::OutputAckMismatch { .. }
        | ExecutionSupervisorError::OutputReadInvalidated
        | ExecutionSupervisorError::AlreadyShutdown
        | ExecutionSupervisorError::SpawnThread(_)
        | ExecutionSupervisorError::ThreadPanicked => ExecutionFailureCode::Supervision,
    })
}

#[derive(Debug, Error)]
pub enum ForgeExecutionCoordinatorError {
    #[error(
        "durable Workspace stop settlement is unconfirmed; native attempt is preserved separately"
    )]
    WorkspaceStopSettlementAndExecution {
        settlement: Box<ControlClientError>,
        native: Option<Box<ForgeExecutionCoordinatorError>>,
        native_cancel_requested: Option<usize>,
    },
    #[error("durable Workspace stop capture failed; native outcome is preserved separately")]
    WorkspaceStopCaptureAndExecution {
        stop_id: uuid::Uuid,
        request_id: uuid::Uuid,
        capture: Box<ControlClientError>,
        native: Option<Box<ForgeExecutionCoordinatorError>>,
        native_cancel_requested: Option<usize>,
    },
    #[error("execution coordinator queue is full")]
    QueueFull,
    #[error("execution coordinator reply was dropped after admission")]
    ResponseDropped,
    #[error("execution wait timeout exceeds the coordinator limit")]
    InvalidWaitTimeout,
    #[error("execution wait identifier allocator is exhausted")]
    WaiterIdExhausted,
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
    #[error("discovered command is not the exact Rust CI command")]
    RustCiCommandMismatch,
    #[error("PackageV executable capability is unavailable or changed")]
    PackageVExecutableUnavailable(#[source] forge_execution::PackageVExecutableError),
    #[error("Rust CI capability was not prepared")]
    RustCiCapabilityMissing,
    #[error("Rust CI toolchain capability is unavailable")]
    RustCiToolchainUnavailable(#[source] RustCiDiscoveryError),
    #[error("execution terminal journal failed")]
    JournalFailed,
    #[error("execution journal failed: {0:?}")]
    JournalFailure(JournalFailure),
    #[error("execution terminal journal did not complete within its bound")]
    JournalTimeout,
    #[error("native cancellation and durable journal wait both failed")]
    CancellationAndJournal {
        cancellation: Box<ExecutionSupervisorError>,
        journal: Box<ForgeExecutionCoordinatorError>,
    },
    #[error("execution authority clock is unavailable")]
    Clock,
    #[error(transparent)]
    Control(#[from] ControlClientError),
    #[error(transparent)]
    Supervisor(#[from] ExecutionSupervisorError),
}

impl ForgeExecutionCoordinatorError {
    /// Preserve admission uncertainty when presenting coordinator failures.
    pub fn view(&self) -> crate::ControlErrorView {
        use crate::{ControlErrorCode as Code, ControlErrorView as View};
        match self {
            Self::Control(error) => error.view().after_admission(),
            Self::QueueFull => View::retryable_admission(),
            Self::InvalidWaitTimeout => View::not_admitted(Code::InvalidInput),
            // An exhausted allocator needs diagnosis, not repeated requests.
            Self::WaiterIdExhausted => View::unknown(Code::CapacityExceeded),
            Self::ResponseDropped => View::unknown(Code::WorkerClosed),
            Self::Closed | Self::AlreadyShutdown | Self::ThreadPanicked => {
                View::unknown(Code::WorkerClosed)
            }
            Self::RustCiCapabilityMissing | Self::RustCiToolchainUnavailable(_) => {
                View::unknown(Code::RustCiToolchainUnavailable)
            }
            Self::AttributionMismatch => View::unknown(Code::ExecutionProvenanceConflict),
            Self::DuplicateExecution(id) | Self::RecoveryRequired(id) => View::unknown(
                Code::ExecutionConflict,
            )
            .with_details(crate::error::ControlErrorDetails::ExecutionTarget { execution_id: *id }),
            Self::PackageVExecutableUnavailable(_)
            | Self::RustCiCommandMismatch
            | Self::WorkspaceStopCaptureAndExecution { .. }
            | Self::WorkspaceStopSettlementAndExecution { .. }
            | Self::JournalFailed
            | Self::JournalFailure(_)
            | Self::JournalTimeout
            | Self::CancellationAndJournal { .. }
            | Self::Clock
            | Self::SpawnThread(_)
            | Self::Supervisor(_) => View::unknown(Code::ExecutionConflict),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::execution_journal::JournalReadback;
    use crate::{ControlClientError, JournalFailure, JournalFailureStage};
    mod owned_workspace_stop;
    mod persistence_output_readback;
    mod pre_spawn_rejection;
    mod workspace_stop;
    use std::error::Error;
    use std::ffi::OsString;
    use std::fs;
    use std::future::Future;
    use std::num::NonZeroU64;
    use std::path::{Path, PathBuf};
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::mpsc;
    use std::task::{Context, Poll, Wake, Waker};
    use std::thread;
    use std::time::{Duration, Instant};

    use forge_domain::{
        ActivityCoordinatorActor, ActivityId, AgentDagDraft, AgentDagPlanRequest,
        AgentDagPlanRequestId, AgentDeclaredRole, AgentDisplayName, AgentFocus, AgentFocusNode,
        AgentInstanceId, AgentInstanceRevision, AgentTransportKind, AgentWorkUpdateId,
        AgentWorkUpdateSequence, AuthenticatedPrincipal, BeginExecution, DagAcceptanceCriterion,
        DagNodeDefinition, DagNodeId, DagNodeObjective, DagNodeOrdinal, DagNodeRevision,
        DagNodeTitle, DagRevision, DagRevisionId, DagRevisionNumber, EstablishWorkspace,
        ExecutionActionClass, ExecutionArgument, ExecutionAttribution,
        ExecutionAuthorizationRequest, ExecutionCommandId, ExecutionFailureCode, ExecutionGrantId,
        ExecutionGrantRevision, ExecutionId, ExecutionKind, ExecutionLimits, ExecutionOutputChunk,
        ExecutionOutputCursor, ExecutionOutputEvent, ExecutionOutputLimit, ExecutionOutputRead,
        ExecutionOutputSequence, ExecutionOutputStream, ExecutionPermissions, ExecutionProgram,
        ExecutionRequest, ExecutionRequestDigest, ExecutionRevision, ExecutionState,
        ExecutionTimeoutMillis, GoalAttribution, GoalContract, GoalId, GoalNodeAttribution,
        GoalObjective, GoalRevision, GoalStatement, LocationId, LocationRevision,
        MarkExecutionRunning, RegisteredAgentInstance, RegisteredDagNode, RegisteredGoal,
        RequestedExecutionPermissions, RuntimeInstanceId, TimestampMillis, WorkspaceId,
        WorkspaceRevision, WorkspaceRoot,
    };
    use forge_execution::{ExecutionSupervisorError, SupervisorStartIdentity};
    use forge_persistence::{GlobalRegistry, WorkspaceStore};
    use forge_workspace::WorkspaceLocator;
    use forge_workspace::{LocationService, WorkspaceStateLayout};
    use uuid::Uuid;

    use super::{
        AckReadback, ActiveExecution, AgentExecutionAuthorityRequest, COORDINATOR_QUEUE_CAPACITY,
        CoordinatorAuthorization, CoordinatorReceive, CoordinatorRequest, CoordinatorRuntime,
        EXECUTION_WAIT_CANCELLATION_CAPACITY, EXECUTION_WAIT_CANCELLED, EXECUTION_WAIT_COMPLETED,
        ExecutionCoordinatorStartRequest, ExecutionJournalAuthority, ExecutionLaunchKind,
        ExecutionStartIdentity, ExecutionWaitCompletionBridge, ExecutionWaitHandle,
        ExecutionWaitObservation, ExecutionWaitRequest, ExecutionWaitResult, ExecutionWaiterId,
        ForgeExecutionCoordinatorClient, ForgeExecutionCoordinatorError,
        ForgeExecutionCoordinatorShutdown, JournalProgress, JournalWorkState,
        MAX_EXECUTION_WAIT_TIMEOUT, MAX_EXECUTION_WAITERS, MAX_TERMINAL_BACKLOG,
        PendingExecutionWait, PendingStart, PendingStartAckPhase, PendingStartOutcome,
        PendingTerminal, ResolvedWorkspaceScope, TerminalAckPhase, TerminalStep,
        classify_ack_readback, derive_launch_kind_parts,
    };
    use crate::worker::ForgeControlRequest;
    use crate::{
        AgentDagPlanCommitRequest, AgentFocusRequest, CoordinatorClaimRequest, DagNodeStartRequest,
        ForgeControl, ForgeControlClient, ForgeControlWorker, command::RUST_CI_PROGRAM,
    };

    #[test]
    fn shutdown_error_still_joins_the_owned_worker() -> Result<(), Box<dyn Error>> {
        let (sender, requests) = mpsc::sync_channel(1);
        let (reply_sent_tx, reply_sent_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let thread = thread::spawn(
            move || -> Result<ForgeExecutionCoordinatorShutdown, ForgeExecutionCoordinatorError> {
                if !matches!(requests.recv(), Ok(CoordinatorRequest::Shutdown)) {
                    return Err(ForgeExecutionCoordinatorError::Closed);
                }
                let _ = reply_sent_tx.send(());
                let _ = release_rx.recv();
                Err(ForgeExecutionCoordinatorError::Closed)
            },
        );
        let (cancellation_sender, _cancellation_receiver) = mpsc::sync_channel(1);
        let coordinator = super::ForgeExecutionCoordinator {
            client: super::ForgeExecutionCoordinatorClient {
                sender,
                cancellation_sender,
                accepting: Arc::new(AtomicBool::new(true)),
                verification_cancellation: Arc::new(AtomicBool::new(false)),
                next_waiter_id: Arc::new(AtomicU64::new(1)),
                rust_ci_available: false,
            },
            thread: Some(thread),
        };
        let accepting = Arc::clone(&coordinator.client.accepting);
        let (done_tx, done_rx) = mpsc::sync_channel(1);
        let caller = thread::spawn(move || {
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
            Err(ForgeExecutionCoordinatorError::Closed)
        ));
        assert!(!accepting.load(Ordering::Acquire));
        Ok(())
    }

    #[test]
    fn shutdown_owner_panic_returns_thread_panicked() {
        let (sender, _receiver) = mpsc::sync_channel(1);
        let thread = thread::spawn(
            || -> Result<ForgeExecutionCoordinatorShutdown, ForgeExecutionCoordinatorError> {
                std::panic::resume_unwind(Box::new("owned coordinator worker panic"));
            },
        );
        let mut coordinator = super::ForgeExecutionCoordinator {
            client: super::ForgeExecutionCoordinatorClient {
                sender,
                cancellation_sender: mpsc::sync_channel(1).0,
                accepting: Arc::new(AtomicBool::new(true)),
                verification_cancellation: Arc::new(AtomicBool::new(false)),
                next_waiter_id: Arc::new(AtomicU64::new(1)),
                rust_ci_available: false,
            },
            thread: Some(thread),
        };
        assert!(matches!(
            coordinator.shutdown(),
            Err(ForgeExecutionCoordinatorError::ThreadPanicked)
        ));
    }

    #[test]
    fn shutdown_marker_send_failure_returns_actual_join_result() -> Result<(), Box<dyn Error>> {
        let (sender, receiver) = mpsc::sync_channel(1);
        drop(receiver);
        let thread = thread::spawn(|| {
            Ok::<_, ForgeExecutionCoordinatorError>(ForgeExecutionCoordinatorShutdown {
                cancelled: 0,
                terminal_records: 0,
            })
        });
        let mut coordinator = super::ForgeExecutionCoordinator {
            client: super::ForgeExecutionCoordinatorClient {
                sender,
                cancellation_sender: mpsc::sync_channel(1).0,
                accepting: Arc::new(AtomicBool::new(true)),
                verification_cancellation: Arc::new(AtomicBool::new(false)),
                next_waiter_id: Arc::new(AtomicU64::new(1)),
                rust_ci_available: false,
            },
            thread: Some(thread),
        };
        let report = coordinator.shutdown()?;
        assert_eq!(report.cancelled(), 0);
        assert_eq!(report.terminal_records(), 0);
        Ok(())
    }

    #[test]
    fn disconnected_runtime_empty_teardown_returns_success() -> Result<(), Box<dyn Error>> {
        let fixture = WaitFixture::new()?;
        let (sender, receiver) = mpsc::sync_channel(1);
        drop(sender);
        let (_cancellation_sender, cancellation_receiver) =
            mpsc::sync_channel(EXECUTION_WAIT_CANCELLATION_CAPACITY);
        let accepting = Arc::new(AtomicBool::new(true));
        let verification_cancellation = Arc::new(AtomicBool::new(false));
        let runtime = CoordinatorRuntime::new(
            fixture.workspace.client.clone(),
            forge_execution::ExecutionSupervisor::start(1)?,
            receiver,
            cancellation_receiver,
            Arc::clone(&accepting),
            verification_cancellation,
            None,
        );
        let owner = thread::spawn(move || runtime.run());
        let report = owner
            .join()
            .map_err(|_| "disconnected coordinator worker panicked")??;
        assert_eq!(report.cancelled(), 0);
        assert_eq!(report.terminal_records(), 0);
        assert!(!accepting.load(Ordering::Acquire));
        fixture.finish()?;
        Ok(())
    }

    #[test]
    fn disconnected_runtime_with_journal_owner_loss_retains_running() -> Result<(), Box<dyn Error>>
    {
        let fixture = WaitFixture::new_output()?;
        let (runtime, journal_owner, committed_rx, _release_tx, keepalive) =
            scripted_dropped_output_runtime(&fixture, 1, false, false)?;
        let owner = thread::spawn(move || runtime.run());
        committed_rx
            .recv_timeout(Duration::from_secs(3))?
            .map_err(|error| format!("durable output journal failed: {error:?}"))?;
        journal_owner
            .join()
            .map_err(|_| "journal owner thread panicked")?;
        drop(keepalive);
        let result = owner
            .join()
            .map_err(|_| "disconnected coordinator worker panicked")?;
        assert!(matches!(
            result,
            Err(ForgeExecutionCoordinatorError::JournalFailure(
                JournalFailure {
                    stage: JournalFailureStage::OutputReadback,
                    code: Some(crate::ControlErrorCode::WorkerClosed),
                    ..
                }
            ))
        ));
        assert_eq!(
            fixture
                .workspace
                .client
                .execution_get(fixture.workspace.scope.clone(), fixture.execution_id)?
                .ok_or("running execution disappeared after owner loss")?
                .state(),
            ExecutionState::Running
        );
        fixture.finish()?;
        Ok(())
    }

    #[test]
    fn disconnected_runtime_unknown_pending_start_times_out_and_joins() -> Result<(), Box<dyn Error>>
    {
        let fixture = WaitFixture::new()?;
        let (mut runtime, client) = runtime_and_client(&fixture)?;
        let (_identity, _layout, _request) =
            install_pending_start_fixture(&mut runtime, &fixture, ExecutionLaunchKind::Baseline)?;
        drop(client);
        let owner = thread::spawn(move || runtime.run());
        let result = owner
            .join()
            .map_err(|_| "disconnected coordinator worker panicked")?;
        assert!(matches!(
            result,
            Err(ForgeExecutionCoordinatorError::JournalTimeout)
        ));
        assert_eq!(
            fixture
                .workspace
                .client
                .execution_get(fixture.workspace.scope.clone(), fixture.execution_id)?
                .ok_or("running execution disappeared after unknown Start timeout")?
                .state(),
            ExecutionState::Running
        );
        fixture.finish()?;
        Ok(())
    }

    #[test]
    fn coordinator_submit_distinguishes_admitted_reply_loss_from_closed_queue()
    -> Result<(), Box<dyn Error>> {
        let (sender, requests) = mpsc::sync_channel(1);
        let owner = thread::spawn(move || {
            let request = requests.recv().map_err(|error| error.to_string())?;
            let CoordinatorRequest::Cancel { response, .. } = request else {
                return Err("expected cancel request".to_owned());
            };
            drop(response);
            Ok::<(), String>(())
        });
        let (cancellation_sender, _cancellation_receiver) = mpsc::sync_channel(1);
        let client = super::ForgeExecutionCoordinatorClient {
            sender,
            cancellation_sender,
            accepting: Arc::new(AtomicBool::new(true)),
            verification_cancellation: Arc::new(AtomicBool::new(false)),
            next_waiter_id: Arc::new(AtomicU64::new(1)),
            rust_ci_available: false,
        };
        let error = client
            .cancel_execution(ExecutionId::from_uuid(id(0xC001)))
            .err()
            .ok_or("dropped admitted reply must remain unknown")?;
        assert!(matches!(
            error,
            ForgeExecutionCoordinatorError::ResponseDropped
        ));
        owner.join().map_err(|_| "reply owner panicked")??;

        let (closed_sender, closed_receiver) = mpsc::sync_channel(1);
        drop(closed_receiver);
        let closed_client = super::ForgeExecutionCoordinatorClient {
            sender: closed_sender,
            cancellation_sender: mpsc::sync_channel(1).0,
            accepting: Arc::new(AtomicBool::new(true)),
            verification_cancellation: Arc::new(AtomicBool::new(false)),
            next_waiter_id: Arc::new(AtomicU64::new(1)),
            rust_ci_available: false,
        };
        assert!(matches!(
            closed_client.cancel_execution(ExecutionId::from_uuid(id(0xC002))),
            Err(ForgeExecutionCoordinatorError::Closed)
        ));
        Ok(())
    }

    static NEXT_WAIT_FIXTURE: AtomicU64 = AtomicU64::new(1);
    static NEXT_WAIT_REQUEST: AtomicU64 = AtomicU64::new(1);

    fn id(value: u128) -> Uuid {
        Uuid::from_u128(value)
    }

    fn start_request(
        action: forge_domain::ExecutionActionClass,
        command_id: &str,
        program: &str,
        argument: &str,
        permissions: ExecutionPermissions,
    ) -> Result<ExecutionCoordinatorStartRequest, Box<dyn Error>> {
        let workspace_id = WorkspaceId::from_uuid(id(1));
        let activity_id = ActivityId::from_uuid(id(2));
        let execution_id = ExecutionId::from_uuid(id(3));
        let scope = ResolvedWorkspaceScope::from_observation(
            workspace_id,
            WorkspaceRevision::INITIAL,
            WorkspaceLocator::new(
                LocationId::from_uuid(id(4)),
                LocationRevision::INITIAL,
                Path::new("workspace"),
            )?,
        );
        let request = ExecutionRequest::new(
            ExecutionAttribution::new(execution_id, workspace_id, activity_id),
            ExecutionKind::Structured {
                program: ExecutionProgram::new(PathBuf::from(program))?,
                arguments: vec![ExecutionArgument::new(OsString::from(argument))?],
            },
            None,
            ExecutionLimits::new(
                ExecutionTimeoutMillis::new(1_000)?,
                ExecutionOutputLimit::DEFAULT,
            ),
            permissions,
        )?;
        let authority = if matches!(
            action,
            forge_domain::ExecutionActionClass::DiscoveredProjectCommand
                | forge_domain::ExecutionActionClass::AnalyzedShell
        ) {
            Some(forge_control_authority(&scope, activity_id, command_id)?)
        } else {
            None
        };
        let project_command = matches!(
            action,
            forge_domain::ExecutionActionClass::DiscoveredProjectCommand
        )
        .then(|| {
            forge_domain::ProjectCommandEvidence::new(
                forge_domain::ProjectCommandClass::Verify,
                forge_domain::ProjectCommandCatalogFingerprint::from_hash(
                    forge_domain::FileContentHash::from_bytes(
                        [0xA5; forge_domain::FileContentHash::BYTE_LEN],
                    ),
                ),
            )
        });
        let authorization = ExecutionAuthorizationRequest::new(
            execution_id,
            workspace_id,
            activity_id,
            ExecutionRequestDigest::from_bytes([0; 32]),
            action,
            RequestedExecutionPermissions::new(permissions),
        );
        Ok(ExecutionCoordinatorStartRequest {
            scope,
            activity_id,
            runtime_instance_id: RuntimeInstanceId::from_uuid(id(5)),
            authorization: CoordinatorAuthorization::Explicit {
                grant_id: ExecutionGrantId::from_uuid(id(6)),
                grant_revision: ExecutionGrantRevision::INITIAL,
            },
            authorization_request: authorization,
            request,
            goal: None,
            agent_authority: authority,
            project_command,
            verification_input: None,
            admission_envelope: None,
        })
    }

    fn forge_control_authority(
        scope: &ResolvedWorkspaceScope,
        activity_id: ActivityId,
        command_id: &str,
    ) -> Result<super::AgentExecutionAuthorityRequest, Box<dyn Error>> {
        Ok(super::AgentExecutionAuthorityRequest {
            session_id: forge_domain::AgentSessionId::from_uuid(id(7)),
            scope: scope.clone(),
            activity_id,
            agent_id: AgentInstanceId::from_uuid(id(7)),
            expected_revision: AgentInstanceRevision::INITIAL,
            principal: AuthenticatedPrincipal::TrustedStdio,
            attribution: GoalNodeAttribution::new(
                GoalId::from_uuid(id(8)),
                GoalRevision::INITIAL,
                DagRevisionNumber::INITIAL,
                DagNodeId::from_uuid(id(9)),
                DagNodeRevision::INITIAL,
            ),
            command_id: ExecutionCommandId::new(command_id.to_owned())?,
        })
    }

    fn timestamp(value: i64) -> Result<TimestampMillis, Box<dyn Error>> {
        Ok(TimestampMillis::new(value)?)
    }

    struct WaitWorkspace {
        root: PathBuf,
        workspace_root: PathBuf,
        scope: ResolvedWorkspaceScope,
        client: ForgeControlClient,
        worker: ForgeControlWorker,
    }

    impl WaitWorkspace {
        fn new(serial: u64) -> Result<Self, Box<dyn Error>> {
            let root = std::env::temp_dir().join(format!(
                "heterarchy-forge-execution-wait-{}-{serial}",
                std::process::id()
            ));
            fs::create_dir_all(&root)?;
            let location_root = root.join("location");
            fs::create_dir_all(&location_root)?;
            let registry_path = root.join("registry.sqlite3");
            let location_id = LocationId::from_uuid(id(0xF000 + u128::from(serial)));
            let mut locations = LocationService::new(GlobalRegistry::open(&registry_path)?);
            let _location = locations.register_selected_path(
                location_id,
                "Wait fixture",
                &location_root,
                timestamp(1)?,
            )?;
            let workspace_root = location_root.join("workspace");
            fs::create_dir_all(&workspace_root)?;
            let layout = WorkspaceStateLayout::initialize(&workspace_root)?;
            let durable_root =
                WorkspaceRoot::from_canonical(layout.workspace_root().to_path_buf())?;
            let workspace_id = WorkspaceId::from_uuid(id(0xF100 + u128::from(serial)));
            let establish = EstablishWorkspace::new(
                workspace_id,
                location_id,
                durable_root,
                layout.root_fingerprint()?,
                timestamp(2)?,
            );
            let store = WorkspaceStore::open(&layout, &establish)?;
            drop(store);
            drop(locations);
            let (client, worker) = ForgeControlWorker::start(ForgeControl::new(
                GlobalRegistry::open(&registry_path)?,
            ))?;
            let locator = client
                .workspace_discover(location_id, LocationRevision::INITIAL)?
                .into_iter()
                .find(|entry| entry.display_name() == "workspace")
                .ok_or("wait fixture Workspace was not discovered")?
                .locator()
                .clone();
            let scope =
                client.resolve_workspace(location_id, LocationRevision::INITIAL, locator)?;
            Ok(Self {
                root,
                workspace_root,
                scope,
                client,
                worker,
            })
        }
    }

    struct WaitFixture {
        workspace: WaitWorkspace,
        authority: AgentExecutionAuthorityRequest,
        execution_id: ExecutionId,
        running_revision: ExecutionRevision,
    }

    impl WaitFixture {
        fn new() -> Result<Self, Box<dyn Error>> {
            Self::new_with_command("/usr/bin/true", &[])
        }

        fn new_output() -> Result<Self, Box<dyn Error>> {
            Self::new_with_command("/usr/bin/printf", &["durable-output"])
        }

        fn new_with_command(program: &str, arguments: &[&str]) -> Result<Self, Box<dyn Error>> {
            let serial = NEXT_WAIT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let workspace = WaitWorkspace::new(serial)?;
            let activity_id = ActivityId::from_uuid(id(0xF200 + u128::from(serial)));
            let owner = RuntimeInstanceId::from_uuid(id(0xF300 + u128::from(serial)));
            let client = &workspace.client;
            let _activity = client
                .bootstrap_activity(
                    workspace.scope.clone(),
                    activity_id,
                    owner,
                    timestamp(10)?,
                    timestamp(60_000)?,
                )?
                .activity()
                .cloned()
                .ok_or("wait fixture Activity was not created")?;
            let (agent_id, attached, actor) =
                attach_wait_agent(client, &workspace.scope, activity_id, serial)?;
            let attribution = create_wait_goal_and_focus(
                client,
                &workspace.scope,
                activity_id,
                agent_id,
                attached.revision(),
                actor,
                serial,
            )?;
            let focused = client.agent_list(crate::AgentListRequest {
                scope: workspace.scope.clone(),
                activity_id: Some(activity_id),
                now: timestamp(16)?,
                limit: forge_domain::AgentListLimit::DEFAULT,
            })?;
            let focused_agent = focused
                .into_iter()
                .find(|projection| projection.agent().id() == agent_id)
                .ok_or("wait fixture focused Agent was not found")?;
            let authority = AgentExecutionAuthorityRequest {
                session_id: attached
                    .session_id()
                    .ok_or("wait fixture Agent session is unresolved")?,
                scope: workspace.scope.clone(),
                activity_id,
                agent_id,
                expected_revision: focused_agent.agent().revision(),
                principal: AuthenticatedPrincipal::TrustedStdio,
                attribution,
                command_id: ExecutionCommandId::new("make:ci".to_owned())?,
            };
            let (execution_id, running_revision) = seed_wait_execution(
                &workspace,
                activity_id,
                owner,
                &authority,
                serial,
                program,
                arguments,
            )?;
            Ok(Self {
                workspace,
                authority,
                execution_id,
                running_revision,
            })
        }

        fn finish(mut self) -> Result<(), Box<dyn Error>> {
            self.workspace.worker.shutdown()?;
            fs::remove_dir_all(self.workspace.root)?;
            Ok(())
        }
    }

    fn attach_wait_agent(
        client: &ForgeControlClient,
        scope: &ResolvedWorkspaceScope,
        activity_id: ActivityId,
        serial: u64,
    ) -> Result<
        (
            AgentInstanceId,
            RegisteredAgentInstance,
            ActivityCoordinatorActor,
        ),
        Box<dyn Error>,
    > {
        let agent_id = AgentInstanceId::from_uuid(id(0xF400 + u128::from(serial)));
        let session_id = forge_domain::AgentSessionId::from_uuid(agent_id.into_uuid());
        let _session = client.agent_session_open(forge_domain::OpenAgentSession::new(
            session_id,
            forge_domain::AgentSessionOpenRequestId::from_uuid(id(agent_id
                .into_uuid()
                .as_u128()
                .wrapping_add(0x100))),
            AuthenticatedPrincipal::TrustedStdio,
            timestamp(11)?,
        ))?;
        let agent = RegisteredAgentInstance::create_bound(
            agent_id,
            scope.workspace_id(),
            activity_id,
            session_id,
            AgentDisplayName::new("Wait worker".to_owned())?,
            AgentDeclaredRole::new("worker".to_owned())?,
            AgentTransportKind::Stdio,
            AuthenticatedPrincipal::TrustedStdio,
            timestamp(11)?,
        );
        let attached = crate::legacy_agent_fixture::seed_client_agent(
            client,
            scope,
            &agent,
            forge_domain::AgentEventId::from_uuid(agent_id.into_uuid()),
        )?;
        let binding = client.activity_coordinator_claim(CoordinatorClaimRequest {
            session_id,
            scope: scope.clone(),
            activity_id,
            agent_id,
            principal: AuthenticatedPrincipal::TrustedStdio,
            observed_at: timestamp(12)?,
        })?;
        let actor = ActivityCoordinatorActor::new(
            scope.workspace_id(),
            activity_id,
            binding.agent_id(),
            binding.revision(),
            AuthenticatedPrincipal::TrustedStdio,
            session_id,
        );
        Ok((agent_id, attached, actor))
    }

    fn create_wait_goal_and_focus(
        client: &ForgeControlClient,
        scope: &ResolvedWorkspaceScope,
        activity_id: ActivityId,
        agent_id: AgentInstanceId,
        agent_revision: AgentInstanceRevision,
        actor: ActivityCoordinatorActor,
        serial: u64,
    ) -> Result<GoalNodeAttribution, Box<dyn Error>> {
        let goal = RegisteredGoal::create(
            GoalId::from_uuid(id(0xF500 + u128::from(serial))),
            scope.workspace_id(),
            activity_id,
            GoalContract::new(
                GoalObjective::new("Observe one execution".to_owned())?,
                vec![GoalStatement::new(
                    "The wait returns durable evidence".to_owned(),
                )?],
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            )?,
            timestamp(13)?,
        );
        let _goal = client.goal_create(scope.clone(), actor, goal.clone())?;
        let node_id = DagNodeId::from_uuid(id(0xF600 + u128::from(serial)));
        let definition = DagNodeDefinition::new(
            node_id,
            DagNodeOrdinal::new(0)?,
            DagNodeTitle::new("Observe".to_owned())?,
            DagNodeObjective::new("Observe durable execution output".to_owned())?,
            vec![DagAcceptanceCriterion::new(
                "Evidence is readable".to_owned(),
            )?],
        )?;
        let dag_revision = DagRevision::new(
            DagRevisionId::from_uuid(id(0xF700 + u128::from(serial))),
            goal.id(),
            goal.revision(),
            DagRevisionNumber::INITIAL,
            None,
            vec![definition.clone()],
            Vec::new(),
            timestamp(14)?,
        )?;
        let node = RegisteredDagNode::create(
            goal.id(),
            DagRevisionNumber::INITIAL,
            definition,
            timestamp(14)?,
        );
        let draft = AgentDagDraft::new(dag_revision, vec![node.clone()], Vec::new())?;
        let plan = AgentDagPlanRequest::new(
            AgentDagPlanRequestId::from_uuid(id(0xF800 + u128::from(serial))),
            actor,
            GoalAttribution::new(goal.id(), goal.revision()),
            None,
            None,
            draft,
            AgentWorkUpdateId::from_uuid(id(0xF900 + u128::from(serial))),
            AgentWorkUpdateSequence::INITIAL,
            timestamp(14)?,
        );
        let _planned = client.agent_dag_plan_commit(AgentDagPlanCommitRequest {
            scope: scope.clone(),
            request: plan,
        })?;
        let active_node = client.dag_node_start(DagNodeStartRequest {
            scope: scope.clone(),
            activity_id,
            session_id: actor.session_id(),
            principal: AuthenticatedPrincipal::TrustedStdio,
            goal_id: goal.id(),
            expected_goal_revision: goal.revision(),
            expected_dag_revision: DagRevisionNumber::INITIAL,
            node_id,
            expected_revision: node.revision(),
            observed_at: timestamp(15)?,
        })?;
        let attribution = GoalNodeAttribution::new(
            goal.id(),
            goal.revision(),
            DagRevisionNumber::INITIAL,
            node_id,
            active_node.revision(),
        );
        let focus = AgentFocus::new(
            Some(GoalAttribution::new(goal.id(), goal.revision())),
            Some(DagRevisionNumber::INITIAL),
            Some(AgentFocusNode::new(node_id, active_node.revision())),
        )?;
        let _focused = client.agent_set_focus(AgentFocusRequest {
            scope: scope.clone(),
            activity_id,
            actor,
            agent_id,
            expected_revision: agent_revision,
            focus,
            observed_at: timestamp(15)?,
        })?;
        Ok(attribution)
    }

    fn seed_wait_execution(
        workspace: &WaitWorkspace,
        activity_id: ActivityId,
        owner: RuntimeInstanceId,
        authority: &AgentExecutionAuthorityRequest,
        serial: u64,
        program: &str,
        arguments: &[&str],
    ) -> Result<(ExecutionId, ExecutionRevision), Box<dyn Error>> {
        let execution_id = ExecutionId::from_uuid(id(0xFA00 + u128::from(serial)));
        let request = ExecutionRequest::new(
            ExecutionAttribution::new(execution_id, workspace.scope.workspace_id(), activity_id),
            ExecutionKind::Structured {
                program: ExecutionProgram::new(PathBuf::from(program))?,
                arguments: arguments
                    .iter()
                    .map(|argument| ExecutionArgument::new(OsString::from(*argument)))
                    .collect::<Result<_, _>>()?,
            },
            None,
            ExecutionLimits::new(
                ExecutionTimeoutMillis::new(30_000)?,
                ExecutionOutputLimit::new(8_192)?,
            ),
            ExecutionPermissions::new(false, false, false),
        )?;
        let provenance = authority.provenance(execution_id);
        let begin_command = BeginExecution::from_request(
            &request,
            forge_execution::execution_request_digest(&request),
            timestamp(16)?,
        )
        .with_runtime_owner(owner)
        .with_provenance(provenance)
        .map_err(|_| "wait fixture provenance did not match execution")?;
        let existing_layout = WorkspaceStateLayout::inspect_existing(&workspace.workspace_root)?
            .ok_or("wait fixture Workspace state disappeared")?;
        let mut store = WorkspaceStore::open_existing(&existing_layout)?;
        let begin_record = store
            .begin_execution(&begin_command)
            .map_err(|error| format!("wait fixture begin execution: {error:?}"))?;
        let running = store
            .mark_execution_running(MarkExecutionRunning::new(
                execution_id,
                begin_record.record().revision(),
                timestamp(17)?,
            ))
            .map_err(|error| format!("wait fixture mark running: {error:?}"))?;
        drop(store);
        Ok((execution_id, running.revision()))
    }

    fn runtime_for(fixture: &WaitFixture) -> Result<CoordinatorRuntime, Box<dyn Error>> {
        let (runtime, _client) = runtime_and_client(fixture)?;
        Ok(runtime)
    }

    fn runtime_and_client(
        fixture: &WaitFixture,
    ) -> Result<(CoordinatorRuntime, ForgeExecutionCoordinatorClient), Box<dyn Error>> {
        runtime_and_client_with_control(fixture.workspace.client.clone())
    }

    fn runtime_and_client_with_control(
        control: ForgeControlClient,
    ) -> Result<(CoordinatorRuntime, ForgeExecutionCoordinatorClient), Box<dyn Error>> {
        let (sender, receiver) = mpsc::sync_channel(COORDINATOR_QUEUE_CAPACITY);
        let (cancellation_sender, cancellation_receiver) =
            mpsc::sync_channel(EXECUTION_WAIT_CANCELLATION_CAPACITY);
        let accepting = Arc::new(AtomicBool::new(true));
        let verification_cancellation = Arc::new(AtomicBool::new(false));
        let client = ForgeExecutionCoordinatorClient {
            sender,
            cancellation_sender,
            accepting: Arc::clone(&accepting),
            verification_cancellation: Arc::clone(&verification_cancellation),
            next_waiter_id: Arc::new(AtomicU64::new(1)),
            rust_ci_available: false,
        };
        let supervisor = forge_execution::ExecutionSupervisor::start(1)?;
        let runtime = CoordinatorRuntime::new(
            control,
            supervisor,
            receiver,
            cancellation_receiver,
            accepting,
            verification_cancellation,
            None,
        );
        Ok((runtime, client))
    }

    fn install_pending_start_fixture(
        runtime: &mut CoordinatorRuntime,
        fixture: &WaitFixture,
        launch_kind: ExecutionLaunchKind,
    ) -> Result<
        (
            SupervisorStartIdentity,
            forge_workspace::ExistingWorkspaceStateLayout,
            ExecutionRequest,
        ),
        Box<dyn Error>,
    > {
        install_pending_start_command_fixture(runtime, fixture, launch_kind, "/usr/bin/true", &[])
    }

    fn install_pending_start_command_fixture(
        runtime: &mut CoordinatorRuntime,
        fixture: &WaitFixture,
        launch_kind: ExecutionLaunchKind,
        program: &str,
        arguments: &[&str],
    ) -> Result<
        (
            SupervisorStartIdentity,
            forge_workspace::ExistingWorkspaceStateLayout,
            ExecutionRequest,
        ),
        Box<dyn Error>,
    > {
        let before = fixture
            .workspace
            .client
            .execution_get(fixture.workspace.scope.clone(), fixture.execution_id)?
            .ok_or("pending Start fixture execution disappeared")?;
        let request = ExecutionRequest::new(
            forge_domain::ExecutionAttribution::new(
                fixture.execution_id,
                fixture.workspace.scope.workspace_id(),
                fixture.authority.activity_id,
            ),
            ExecutionKind::Structured {
                program: ExecutionProgram::new(PathBuf::from(program))?,
                arguments: arguments
                    .iter()
                    .map(|argument| ExecutionArgument::new(OsString::from(*argument)))
                    .collect::<Result<_, _>>()?,
            },
            None,
            ExecutionLimits::new(
                ExecutionTimeoutMillis::new(30_000)?,
                ExecutionOutputLimit::new(8_192)?,
            ),
            ExecutionPermissions::new(false, false, false),
        )?;
        assert_eq!(
            before.request_digest(),
            forge_execution::execution_request_digest(&request),
            "native Start identity must match the retained running row"
        );
        let layout = WorkspaceStateLayout::inspect_existing(&fixture.workspace.workspace_root)?
            .ok_or("pending Start fixture Workspace state disappeared")?;
        let native_identity =
            SupervisorStartIdentity::capture(&layout, &request, launch_kind, None)?;
        assert_eq!(native_identity.execution_id(), before.id());
        assert_eq!(native_identity.workspace_id(), before.workspace_id());
        assert_eq!(native_identity.activity_id(), before.activity_id());
        assert_eq!(native_identity.request_digest(), before.request_digest());
        let authorization = ExecutionAuthorizationRequest::new(
            fixture.execution_id,
            fixture.workspace.scope.workspace_id(),
            fixture.authority.activity_id,
            forge_execution::execution_request_digest(&request),
            ExecutionActionClass::DirectStructured,
            RequestedExecutionPermissions::new(request.permissions()),
        );
        let owner_identity = ExecutionStartIdentity {
            scope: fixture.workspace.scope.clone(),
            activity_id: fixture.authority.activity_id,
            runtime_instance_id: RuntimeInstanceId::from_uuid(id(0xFE00)),
            authorization_request: authorization,
            request: request.clone(),
            goal: None,
            agent_authority: None,
            project_command: None,
            admission_envelope: None,
        };
        let owner = ActiveExecution {
            workspace_id: before.workspace_id(),
            activity_id: before.activity_id(),
            running: before,
            identity: owner_identity,
            native_identity: Some(native_identity),
            journal: journal_authority_for_fixture(fixture)?,
            terminal_journaled: false,
        };
        runtime.pending_start = Some(PendingStart::new(native_identity, owner));
        Ok((native_identity, layout, request))
    }

    fn journal_authority_for_fixture(
        fixture: &WaitFixture,
    ) -> Result<ExecutionJournalAuthority, Box<dyn Error>> {
        let layout = WorkspaceStateLayout::inspect_existing(&fixture.workspace.workspace_root)?
            .ok_or("wait fixture Workspace state disappeared")?;
        let store = WorkspaceStore::open_existing(&layout)?;
        let record = store
            .get_execution(fixture.execution_id)?
            .ok_or("wait fixture execution record disappeared")?;
        Ok(ExecutionJournalAuthority::capture(
            &fixture.workspace.scope,
            &layout,
            &store,
            &record,
        )?)
    }

    fn disable_wait_fixture_location(fixture: &WaitFixture) -> Result<(), Box<dyn Error>> {
        let registry_path = fixture.workspace.root.join("registry.sqlite3");
        let mut locations = LocationService::new(GlobalRegistry::open(&registry_path)?);
        let location_id = fixture.workspace.scope.locator().location_id();
        let location = locations
            .get_location(location_id)?
            .ok_or("wait fixture Location disappeared")?;
        locations.set_location_state(&forge_domain::SetLocationState::new(
            location_id,
            location.revision(),
            forge_domain::LocationState::Disabled,
            timestamp(20)?,
        ))?;
        Ok(())
    }

    fn read_wait_fixture_store(
        fixture: &WaitFixture,
    ) -> Result<(forge_domain::RegisteredExecution, ExecutionOutputRead), Box<dyn Error>> {
        let layout = WorkspaceStateLayout::inspect_existing(&fixture.workspace.workspace_root)?
            .ok_or("wait fixture Workspace state disappeared")?;
        let store = WorkspaceStore::open_existing(&layout)?;
        let record = store
            .get_execution(fixture.execution_id)?
            .ok_or("wait fixture execution disappeared")?;
        let output = store.read_execution_output_events(
            forge_domain::ExecutionOutputCursor::initial(fixture.execution_id),
            forge_domain::MAX_EXECUTION_OUTPUT_READ_BYTES,
            forge_domain::MAX_EXECUTION_OUTPUT_READ_EVENTS,
        )?;
        Ok((record, output))
    }

    struct MovedStateDirectory {
        original: PathBuf,
        backup: PathBuf,
        restored: bool,
    }

    fn read_wait_fixture_closure(
        fixture: &WaitFixture,
    ) -> Result<forge_domain::ExecutionNativeClosureFact, Box<dyn Error>> {
        let layout = WorkspaceStateLayout::inspect_existing(&fixture.workspace.workspace_root)?
            .ok_or("closure fixture state missing")?;
        let store = WorkspaceStore::open_existing(&layout)?;
        store
            .execution_native_closure_snapshot(fixture.execution_id)?
            .ok_or("closure snapshot missing")?
            .closure()
            .ok_or_else(|| "native closure was not durable".into())
    }

    impl MovedStateDirectory {
        fn move_from(workspace_root: &Path) -> Result<Self, Box<dyn Error>> {
            let original = workspace_root.join(".heterarchy-forge");
            let backup = workspace_root.join(".heterarchy-forge.stop-phase-backup");
            if backup.exists() {
                fs::remove_dir_all(&backup)?;
            }
            fs::rename(&original, &backup)?;
            Ok(Self {
                original,
                backup,
                restored: false,
            })
        }

        fn restore(&mut self) -> Result<(), Box<dyn Error>> {
            if !self.restored {
                fs::rename(&self.backup, &self.original)?;
                self.restored = true;
            }
            Ok(())
        }
    }

    impl Drop for MovedStateDirectory {
        fn drop(&mut self) {
            if !self.restored && self.backup.exists() && !self.original.exists() {
                let _ = fs::rename(&self.backup, &self.original);
            }
        }
    }

    fn begin_fixture_wait(
        client: &ForgeExecutionCoordinatorClient,
        fixture: &WaitFixture,
    ) -> Result<ExecutionWaitHandle, ForgeExecutionCoordinatorError> {
        client.begin_execution_wait_authorized(super::ExecutionWaitParameters::new(
            fixture.authority.clone(),
            fixture.execution_id,
            forge_domain::ExecutionOutputCursor::initial(fixture.execution_id),
            8_192,
            8,
            Duration::from_secs(30),
        ))
    }

    fn wait_request(
        fixture: &WaitFixture,
        deadline: Instant,
    ) -> (ExecutionWaitRequest, Arc<ExecutionWaitCompletionBridge>) {
        let completion = Arc::new(ExecutionWaitCompletionBridge::new());
        let completion_for_test = Arc::clone(&completion);
        let waiter_id = ExecutionWaiterId::new(NEXT_WAIT_REQUEST.fetch_add(1, Ordering::Relaxed))
            .unwrap_or(ExecutionWaiterId(NonZeroU64::MIN));
        (
            ExecutionWaitRequest {
                waiter_id,
                state: Arc::clone(&completion.state),
                authority: fixture.authority.clone(),
                id: fixture.execution_id,
                cursor: forge_domain::ExecutionOutputCursor::initial(fixture.execution_id),
                max_bytes: 8_192,
                max_events: 8,
                deadline,
                completion,
            },
            completion_for_test,
        )
    }

    fn pending_wait(
        request: ExecutionWaitRequest,
        baseline_state: ExecutionState,
        baseline_revision: ExecutionRevision,
    ) -> PendingExecutionWait {
        PendingExecutionWait {
            waiter_id: request.waiter_id,
            state: request.state,
            authority: request.authority,
            id: request.id,
            cursor: request.cursor,
            max_bytes: request.max_bytes,
            max_events: request.max_events,
            deadline: request.deadline,
            baseline_state,
            baseline_revision,
            completion: request.completion,
        }
    }

    fn output_event(
        execution_id: ExecutionId,
        bytes: &[u8],
    ) -> Result<ExecutionOutputEvent, Box<dyn Error>> {
        Ok(ExecutionOutputEvent::Chunk(ExecutionOutputChunk::new(
            execution_id,
            ExecutionOutputSequence::INITIAL,
            ExecutionOutputStream::Stdout,
            bytes,
        )?))
    }

    #[test]
    fn ack_readback_requires_exact_prefix_and_ack_key() -> Result<(), Box<dyn Error>> {
        let execution_id = ExecutionId::from_uuid(id(0xD500));
        let first = output_event(execution_id, b"first")?;
        let second = ExecutionOutputEvent::Chunk(ExecutionOutputChunk::new(
            execution_id,
            ExecutionOutputSequence::new(2)?,
            ExecutionOutputStream::Stdout,
            b"second",
        )?);
        let overlap = output_event(execution_id, b"different")?;
        let expected_key = first.key();
        assert_eq!(
            classify_ack_readback(
                std::slice::from_ref(&first),
                expected_key,
                &ExecutionOutputRead::new(vec![first.clone()]),
            ),
            AckReadback::Pending
        );
        assert_eq!(
            classify_ack_readback(
                std::slice::from_ref(&first),
                expected_key,
                &ExecutionOutputRead::empty_for(execution_id),
            ),
            AckReadback::Confirmed
        );
        assert_eq!(
            classify_ack_readback(
                std::slice::from_ref(&first),
                expected_key,
                &ExecutionOutputRead::new(vec![second.clone()]),
            ),
            AckReadback::Confirmed
        );
        assert_eq!(
            classify_ack_readback(
                std::slice::from_ref(&first),
                expected_key,
                &ExecutionOutputRead::new(vec![overlap]),
            ),
            AckReadback::Mismatch
        );
        assert_eq!(
            classify_ack_readback(
                std::slice::from_ref(&first),
                expected_key,
                &ExecutionOutputRead::new(vec![first.clone(), second]),
            ),
            AckReadback::Mismatch
        );
        Ok(())
    }

    #[test]
    fn pending_start_reply_drop_adopts_exact_native_receipt_and_terminalizes()
    -> Result<(), Box<dyn Error>> {
        let fixture = WaitFixture::new()?;
        let (mut runtime, _client) = runtime_and_client(&fixture)?;
        let (identity, layout, request) =
            install_pending_start_fixture(&mut runtime, &fixture, ExecutionLaunchKind::Baseline)?;
        let error = runtime
            .process_supervisor_start_result(Err(ExecutionSupervisorError::ReplyDropped))
            .err()
            .ok_or("reply loss must remain unknown to the coordinator")?;
        assert!(matches!(
            error,
            ForgeExecutionCoordinatorError::Supervisor(ExecutionSupervisorError::ReplyDropped)
        ));
        assert!(matches!(
            runtime
                .pending_start
                .as_ref()
                .map(|pending| pending.outcome),
            Some(PendingStartOutcome::Unknown)
        ));
        assert!(runtime.active.is_empty());
        assert!(runtime.launch_failure.is_none());
        assert_eq!(
            fixture
                .workspace
                .client
                .execution_get(fixture.workspace.scope.clone(), fixture.execution_id)?
                .ok_or("running row disappeared")?
                .state(),
            ExecutionState::Running
        );

        let admitted = runtime.supervisor.client().start_execution_with_identity(
            identity,
            layout,
            request,
            ExecutionLaunchKind::Baseline,
            None,
            None,
        )?;
        assert_eq!(admitted, fixture.execution_id);
        runtime.progress_pending_start();
        assert!(runtime.pending_start.is_none());
        assert!(runtime.active.contains_key(&fixture.execution_id));

        let deadline = Instant::now() + Duration::from_secs(3);
        while runtime.active.contains_key(&fixture.execution_id) {
            runtime.poll_and_journal();
            if Instant::now() >= deadline {
                return Err("accepted pending Start did not terminalize".into());
            }
            thread::yield_now();
        }
        let durable = fixture
            .workspace
            .client
            .execution_get(fixture.workspace.scope.clone(), fixture.execution_id)?
            .ok_or("terminal execution disappeared")?;
        assert_eq!(durable.state(), ExecutionState::Completed);
        stop_runtime(&mut runtime)?;
        fixture.finish()?;
        Ok(())
    }

    fn assert_changed_closure_mismatches(
        runtime: &CoordinatorRuntime,
        pending: &PendingTerminal,
        retained_closure: forge_domain::ExecutionNativeClosureFact,
    ) -> Result<(), Box<dyn Error>> {
        let changed_closure = forge_domain::ExecutionNativeClosureFact::from_parts(
            forge_domain::ExecutionNativeClosureFactParts {
                attribution: retained_closure.attribution(),
                request_digest: retained_closure.request_digest(),
                before_revision: retained_closure.before_revision(),
                after_revision: retained_closure.after_revision(),
                output_cursor: retained_closure.output_cursor(),
                launch: retained_closure.launch(),
                runtime: retained_closure.runtime(),
                process: forge_domain::NativeClosureProcess::NoChildSpawned,
                observed_at: retained_closure.observed_at(),
            },
        )?;
        assert_eq!(
            runtime.control.execution_journal_reconcile_terminal(
                pending.journal.as_ref().ok_or("journal missing")?,
                pending.before.as_ref().ok_or("before missing")?,
                pending.command.as_ref().ok_or("command missing")?,
                Some(changed_closure),
            )?,
            JournalReadback::Mismatch
        );

        Ok(())
    }

    fn confirm_terminal_after_dropped_write(
        runtime: &mut CoordinatorRuntime,
        pending: &mut PendingTerminal,
        progress: &mut JournalProgress,
    ) -> Result<(), Box<dyn Error>> {
        let original_control = runtime.control.clone();
        let (control, requests) = ForgeControlClient::journal_test_channel(1);
        runtime.control = control;
        let owner = thread::spawn(move || -> Result<(), String> {
            let ForgeControlRequest::ExecutionJournalComplete {
                authority,
                command,
                closure,
                response,
            } = requests.recv().map_err(|error| error.to_string())?
            else {
                return Err("expected native closure terminal write".to_owned());
            };
            let _record = ForgeControl::execution_journal_complete(&authority, &command, closure)
                .map_err(|error| error.to_string())?;
            drop(response);
            let ForgeControlRequest::ExecutionJournalReconcileTerminal {
                authority,
                before,
                command,
                closure,
                response,
            } = requests.recv().map_err(|error| error.to_string())?
            else {
                return Err("expected native closure exact readback".to_owned());
            };
            response
                .send(ForgeControl::execution_journal_reconcile_terminal(
                    &authority, &before, &command, closure,
                ))
                .map_err(|error| error.to_string())?;
            Ok(())
        });
        assert!(matches!(
            runtime.write_terminal(pending),
            Err(ControlClientError::ResponseDropped)
        ));
        pending.state = JournalWorkState::Readback;
        assert_eq!(
            runtime.control.execution_journal_reconcile_terminal(
                pending.journal.as_ref().ok_or("journal missing")?,
                pending.before.as_ref().ok_or("before record missing")?,
                pending.command.as_ref().ok_or("terminal command missing")?,
                pending.closure,
            )?,
            JournalReadback::Confirmed
        );
        owner
            .join()
            .map_err(|_| "native terminal proxy panicked")?
            .map_err(std::io::Error::other)?;
        runtime.control = original_control;
        pending.state = JournalWorkState::Confirmed;
        runtime.mark_terminal_confirmed(pending, progress);
        Ok(())
    }

    #[test]
    fn terminal_sql_is_counted_once_before_lost_ack_release() -> Result<(), Box<dyn Error>> {
        let fixture = WaitFixture::new()?;
        let (mut runtime, _client) = runtime_and_client(&fixture)?;
        let (identity, layout, request) =
            install_pending_start_fixture(&mut runtime, &fixture, ExecutionLaunchKind::Baseline)?;
        runtime.supervisor.client().start_execution_with_identity(
            identity,
            layout,
            request,
            ExecutionLaunchKind::Baseline,
            None,
            None,
        )?;
        runtime.progress_pending_start();
        assert!(runtime.pending_start.is_none());

        let deadline = Instant::now() + Duration::from_secs(3);
        let event = loop {
            if let Some(event) = runtime
                .supervisor
                .client()
                .peek_terminal_events(MAX_TERMINAL_BACKLOG)?
                .into_iter()
                .find(|event| event.identity() == identity)
            {
                break event;
            }
            if Instant::now() >= deadline {
                return Err("terminal event did not arrive for coordinator seam".into());
            }
            thread::yield_now();
        };
        let mut pending = PendingTerminal::new(event.clone());
        runtime.prepare_terminal(&mut pending)?;
        let original_observed_at = pending
            .command
            .as_ref()
            .ok_or("terminal command was not prepared")?
            .observed_at();
        let mut progress = JournalProgress::default();
        confirm_terminal_after_dropped_write(&mut runtime, &mut pending, &mut progress)?;
        assert_eq!(runtime.terminal_records, 1);
        assert_eq!(progress.execution_ids, vec![fixture.execution_id]);

        let durable = fixture
            .workspace
            .client
            .execution_get(fixture.workspace.scope.clone(), fixture.execution_id)?
            .ok_or("durable terminal execution disappeared")?;
        assert_eq!(durable.state(), ExecutionState::Completed);
        let retained_closure = pending.closure.ok_or("native closure missing before ACK")?;
        assert_eq!(read_wait_fixture_closure(&fixture)?, retained_closure);
        assert_changed_closure_mismatches(&runtime, &pending, retained_closure)?;

        // Consume the native event before the coordinator's ACK call. This
        // is the durable-readback half of a lost ACK reply: the coordinator
        // must settle the retained owner without rewriting or recounting SQL.
        assert!(
            runtime
                .supervisor
                .client()
                .acknowledge_terminal_event(&event.key(), &event.identity())?
        );
        assert!(matches!(
            runtime.advance_terminal_ack(&mut pending),
            TerminalStep::Back
        ));
        assert_eq!(pending.ack, TerminalAckPhase::Observe);
        assert!(matches!(
            runtime.advance_terminal_ack(&mut pending),
            TerminalStep::Done
        ));
        assert_eq!(pending.ack, TerminalAckPhase::Settled);
        assert_eq!(read_wait_fixture_closure(&fixture)?, retained_closure);
        assert_eq!(runtime.terminal_records, 1);
        assert_eq!(
            pending
                .command
                .as_ref()
                .ok_or("terminal command disappeared")?
                .observed_at(),
            original_observed_at
        );

        stop_runtime(&mut runtime)?;
        fixture.finish()?;
        Ok(())
    }

    #[test]
    fn terminal_peek_deduplicates_and_queue_full_preserves_write_phase()
    -> Result<(), Box<dyn Error>> {
        let fixture = WaitFixture::new()?;
        let (mut runtime, _client) = runtime_and_client(&fixture)?;
        let (identity, layout, request) =
            install_pending_start_fixture(&mut runtime, &fixture, ExecutionLaunchKind::Baseline)?;
        runtime.supervisor.client().start_execution_with_identity(
            identity,
            layout,
            request,
            ExecutionLaunchKind::Baseline,
            None,
            None,
        )?;
        runtime.progress_pending_start();
        assert!(runtime.pending_start.is_none());

        let deadline = Instant::now() + Duration::from_secs(3);
        while runtime.terminal_backlog.is_empty() {
            runtime.drain_terminal_events();
            if Instant::now() >= deadline {
                return Err("terminal event did not arrive for dedup seam".into());
            }
            thread::yield_now();
        }
        assert_eq!(runtime.terminal_backlog.len(), 1);
        runtime.drain_terminal_events();
        assert_eq!(runtime.terminal_backlog.len(), 1);

        let mut pending = runtime
            .terminal_backlog
            .pop_front()
            .ok_or("deduplicated terminal event disappeared")?;
        let (blocked_control, _blocked_requests) = ForgeControlClient::journal_test_channel(0);
        runtime.control = blocked_control;
        let mut progress = JournalProgress::default();
        assert!(matches!(
            runtime.advance_terminal(&mut pending, &mut progress),
            TerminalStep::Back
        ));
        assert!(!runtime.journal_failed);
        assert_eq!(pending.state, JournalWorkState::Write);

        runtime.control = fixture.workspace.client.clone();
        runtime.terminal_backlog.push_back(pending);
        let settle_deadline = Instant::now() + Duration::from_secs(3);
        while runtime.active.contains_key(&fixture.execution_id) {
            runtime.poll_and_journal();
            if runtime.journal_failed {
                return Err("terminal QueueFull retry failed closed unexpectedly".into());
            }
            if Instant::now() >= settle_deadline {
                return Err("terminal QueueFull retry did not settle".into());
            }
            thread::yield_now();
        }
        assert_eq!(runtime.terminal_records, 1);
        assert_eq!(
            fixture
                .workspace
                .client
                .execution_get(fixture.workspace.scope.clone(), fixture.execution_id)?
                .ok_or("durable terminal execution disappeared")?
                .state(),
            ExecutionState::Completed
        );
        stop_runtime(&mut runtime)?;
        fixture.finish()?;
        Ok(())
    }

    #[test]
    fn closed_terminal_ack_retains_durable_owner() -> Result<(), Box<dyn Error>> {
        let fixture = WaitFixture::new()?;
        let (mut runtime, _client) = runtime_and_client(&fixture)?;
        let (identity, layout, request) =
            install_pending_start_fixture(&mut runtime, &fixture, ExecutionLaunchKind::Baseline)?;
        runtime.supervisor.client().start_execution_with_identity(
            identity,
            layout,
            request,
            ExecutionLaunchKind::Baseline,
            None,
            None,
        )?;
        runtime.progress_pending_start();
        assert!(runtime.pending_start.is_none());

        let deadline = Instant::now() + Duration::from_secs(3);
        let event = loop {
            if let Some(event) = runtime
                .supervisor
                .client()
                .peek_terminal_events(MAX_TERMINAL_BACKLOG)?
                .into_iter()
                .find(|event| event.identity() == identity)
            {
                break event;
            }
            if Instant::now() >= deadline {
                return Err("terminal event did not arrive for closed-ACK seam".into());
            }
            thread::yield_now();
        };
        let mut pending = PendingTerminal::new(event);
        runtime.prepare_terminal(&mut pending)?;
        runtime.write_terminal(&pending)?;
        pending.state = JournalWorkState::Confirmed;
        let mut progress = JournalProgress::default();
        runtime.mark_terminal_confirmed(&mut pending, &mut progress);
        assert_eq!(runtime.terminal_records, 1);

        let _report = runtime.supervisor.shutdown()?;
        assert!(matches!(
            runtime.advance_terminal_ack(&mut pending),
            TerminalStep::FrontAndStop
        ));
        assert!(runtime.journal_failed);
        assert_eq!(pending.ack, TerminalAckPhase::Ready);
        assert_eq!(runtime.terminal_records, 1);
        assert_eq!(
            fixture
                .workspace
                .client
                .execution_get(fixture.workspace.scope.clone(), fixture.execution_id)?
                .ok_or("durable terminal execution disappeared")?
                .state(),
            ExecutionState::Completed
        );

        drop(runtime);
        fixture.finish()?;
        Ok(())
    }

    #[test]
    fn pending_start_native_rejection_journals_before_receipt_ack() -> Result<(), Box<dyn Error>> {
        let fixture = WaitFixture::new()?;
        let (mut runtime, _client) = runtime_and_client(&fixture)?;
        let (identity, layout, request) =
            install_pending_start_fixture(&mut runtime, &fixture, ExecutionLaunchKind::RustCi)?;
        let native_error = runtime
            .supervisor
            .client()
            .start_execution_with_identity(
                identity,
                layout,
                request,
                ExecutionLaunchKind::RustCi,
                None,
                None,
            )
            .err()
            .ok_or("missing Rust CI capability must be a native rejection")?;
        assert!(matches!(
            &native_error,
            ExecutionSupervisorError::Execution(_)
        ));
        let processed = runtime.process_supervisor_start_result(Err(native_error));
        assert!(processed.is_err());
        assert!(runtime.pending_start.is_none());
        assert!(runtime.launch_failure.is_none());
        assert!(runtime.active.is_empty());
        let durable = fixture
            .workspace
            .client
            .execution_get(fixture.workspace.scope.clone(), fixture.execution_id)?
            .ok_or("rejected execution disappeared")?;
        assert_eq!(durable.state(), ExecutionState::Failed);
        assert_eq!(
            durable.failure_code(),
            Some(ExecutionFailureCode::Admission)
        );
        stop_runtime(&mut runtime)?;
        fixture.finish()?;
        Ok(())
    }

    #[test]
    fn rejected_pending_start_ack_loss_reuses_confirmed_failure_command()
    -> Result<(), Box<dyn Error>> {
        let fixture = WaitFixture::new()?;
        let (mut runtime, _client) = runtime_and_client(&fixture)?;
        let (_identity, _layout, _request) =
            install_pending_start_fixture(&mut runtime, &fixture, ExecutionLaunchKind::Baseline)?;
        runtime.launch_failure = Some(fixture_launch_failure(&fixture)?);
        if let Some(pending) = runtime.pending_start.as_mut() {
            pending.outcome = PendingStartOutcome::Rejected {
                failure_code: ExecutionFailureCode::ProcessSpawn,
                journal_confirmed: false,
                ack: PendingStartAckPhase::Ready,
            };
        }
        assert!(runtime.flush_launch_failure());
        let confirmed_at = timestamp(50)?;
        assert!(runtime.launch_failure.is_none());
        assert_eq!(
            fixture
                .workspace
                .client
                .execution_get(fixture.workspace.scope.clone(), fixture.execution_id)?
                .ok_or("rejected execution disappeared")?
                .timestamps()
                .updated_at(),
            confirmed_at
        );
        if let Some(pending) = runtime.pending_start.as_mut() {
            pending.outcome = PendingStartOutcome::Rejected {
                failure_code: ExecutionFailureCode::ProcessSpawn,
                journal_confirmed: true,
                ack: PendingStartAckPhase::Ready,
            };
        }
        let ack_loss: Result<bool, ExecutionSupervisorError> =
            Err(ExecutionSupervisorError::ReplyDropped);
        runtime.process_pending_start_ack_result(&ack_loss);
        assert!(matches!(
            runtime
                .pending_start
                .as_ref()
                .map(|pending| pending.outcome),
            Some(PendingStartOutcome::Rejected {
                journal_confirmed: true,
                ack: PendingStartAckPhase::Observe,
                ..
            })
        ));
        assert!(runtime.launch_failure.is_none());
        runtime.progress_pending_start();
        assert!(runtime.pending_start.is_none());
        assert_eq!(
            fixture
                .workspace
                .client
                .execution_get(fixture.workspace.scope.clone(), fixture.execution_id)?
                .ok_or("rejected execution disappeared after ACK readback")?
                .timestamps()
                .updated_at(),
            confirmed_at
        );
        stop_runtime(&mut runtime)?;
        fixture.finish()?;
        Ok(())
    }

    #[test]
    fn scoped_stop_waits_for_unknown_pending_start_with_missing_receipt()
    -> Result<(), Box<dyn Error>> {
        let fixture = WaitFixture::new()?;
        let (mut runtime, _client) = runtime_and_client(&fixture)?;
        let (_identity, _layout, _request) =
            install_pending_start_fixture(&mut runtime, &fixture, ExecutionLaunchKind::Baseline)?;
        let result = runtime.stop_activity_and_journal(
            fixture.workspace.scope.workspace_id(),
            fixture.authority.activity_id,
        );
        assert!(matches!(
            result,
            Err(ForgeExecutionCoordinatorError::JournalTimeout)
        ));
        assert!(matches!(
            runtime
                .pending_start
                .as_ref()
                .map(|pending| pending.outcome),
            Some(PendingStartOutcome::Unknown)
        ));
        assert!(runtime.launch_failure.is_none());
        stop_runtime(&mut runtime)?;
        fixture.finish()?;
        Ok(())
    }

    fn stop_runtime(runtime: &mut CoordinatorRuntime) -> Result<(), Box<dyn Error>> {
        runtime.resolve_waiters_as_closed();
        let _report = runtime.supervisor.shutdown()?;
        Ok(())
    }

    fn standalone_wait_handle() -> (ExecutionWaitHandle, Arc<ExecutionWaitCompletionBridge>) {
        let completion = Arc::new(ExecutionWaitCompletionBridge::new());
        let (cancellation_sender, _cancellation_receiver) = mpsc::sync_channel(1);
        let (wake_sender, _wake_receiver) = mpsc::sync_channel(1);
        let handle = ExecutionWaitHandle {
            waiter_id: ExecutionWaiterId(NonZeroU64::MIN),
            completion: Arc::clone(&completion),
            cancellation_sender,
            wake_sender,
        };
        (handle, completion)
    }

    fn sample_wait_result() -> ExecutionWaitResult {
        ExecutionWaitResult::new(
            ExecutionOutputRead::empty_for(ExecutionId::from_uuid(id(0xD301))),
            ExecutionState::Running,
            ExecutionRevision::INITIAL,
            false,
            true,
        )
    }

    struct CountingWake {
        wakes: Arc<AtomicU64>,
    }

    impl Wake for CountingWake {
        fn wake(self: Arc<Self>) {
            self.wakes.fetch_add(1, Ordering::Relaxed);
        }
    }

    struct PanicWake;

    impl Wake for PanicWake {
        fn wake(self: Arc<Self>) {
            std::panic::resume_unwind(Box::new("test waker panic"));
        }
    }

    #[test]
    fn exact_discovered_verification_commands_require_rust_ci() -> Result<(), Box<dyn Error>> {
        for target in ["ci", "rules", "check", "test", "doctor"] {
            let exact = start_request(
                forge_domain::ExecutionActionClass::DiscoveredProjectCommand,
                &format!("make:{target}"),
                RUST_CI_PROGRAM,
                target,
                ExecutionPermissions::new(true, false, false),
            )?;
            assert!(matches!(
                derive_launch_kind_parts(
                    exact.authorization_request.action(),
                    &exact.request,
                    exact.agent_authority.as_ref(),
                    exact.project_command,
                    None,
                ),
                Err(ForgeExecutionCoordinatorError::RustCiCapabilityMissing)
            ));
        }

        let different_command = start_request(
            forge_domain::ExecutionActionClass::DiscoveredProjectCommand,
            "make:package",
            RUST_CI_PROGRAM,
            "package",
            ExecutionPermissions::new(true, false, false),
        )?;
        assert!(matches!(
            derive_launch_kind_parts(
                different_command.authorization_request.action(),
                &different_command.request,
                different_command.agent_authority.as_ref(),
                different_command.project_command,
                None,
            ),
            Err(ForgeExecutionCoordinatorError::RustCiCommandMismatch)
        ));

        let different_program = start_request(
            forge_domain::ExecutionActionClass::DiscoveredProjectCommand,
            "make:ci",
            "/usr/bin/true",
            "ci",
            ExecutionPermissions::new(true, false, false),
        )?;
        assert!(matches!(
            derive_launch_kind_parts(
                different_program.authorization_request.action(),
                &different_program.request,
                different_program.agent_authority.as_ref(),
                different_program.project_command,
                None,
            ),
            Err(ForgeExecutionCoordinatorError::RustCiCommandMismatch)
        ));
        Ok(())
    }

    #[test]
    fn baseline_direct_structured_request_does_not_require_rust_ci() -> Result<(), Box<dyn Error>> {
        let direct = start_request(
            forge_domain::ExecutionActionClass::DirectStructured,
            "make:ci",
            "/usr/bin/true",
            "ok",
            ExecutionPermissions::new(false, false, false),
        )?;
        assert_eq!(
            derive_launch_kind_parts(
                direct.authorization_request.action(),
                &direct.request,
                direct.agent_authority.as_ref(),
                direct.project_command,
                None,
            )?,
            ExecutionLaunchKind::Baseline
        );
        Ok(())
    }

    #[test]
    fn verification_cancellation_is_separate_from_accepting_state() -> Result<(), Box<dyn Error>> {
        let fixture = WaitFixture::new()?;
        let (mut runtime, client) = runtime_and_client(&fixture)?;
        assert!(client.accepting.load(Ordering::Acquire));
        assert!(!client.verification_cancellation.load(Ordering::Acquire));
        assert!(Arc::ptr_eq(
            &client.verification_cancellation,
            &runtime.verification_cancellation
        ));
        client
            .verification_cancellation
            .store(true, Ordering::Release);
        assert!(runtime.verification_cancellation.load(Ordering::Acquire));
        stop_runtime(&mut runtime)?;
        fixture.finish()?;
        Ok(())
    }

    #[test]
    fn coordinator_wait_wakes_after_durable_output_progress() -> Result<(), Box<dyn Error>> {
        let fixture = WaitFixture::new()?;
        let mut runtime = runtime_for(&fixture)?;
        let deadline = Instant::now()
            .checked_add(std::time::Duration::from_secs(5))
            .ok_or("wait deadline overflow")?;
        let (request, completion) = wait_request(&fixture, deadline);
        runtime.handle_execution_wait(request);
        assert_eq!(runtime.waiters.len(), 1);

        let event = output_event(fixture.execution_id, b"durable\n")?;
        fixture
            .workspace
            .client
            .execution_output_append_batch(fixture.workspace.scope.clone(), vec![event])?;
        let mut progress = JournalProgress::default();
        progress.record(fixture.execution_id);
        runtime.service_waiters(&progress);

        let result = completion.wait()?;
        assert!(result.changed());
        assert!(!result.timed_out());
        assert_eq!(result.state(), ExecutionState::Running);
        assert_eq!(result.output().events().len(), 1);
        stop_runtime(&mut runtime)?;
        fixture.finish()?;
        Ok(())
    }

    #[test]
    fn coordinator_wait_wakes_after_durable_terminal_progress() -> Result<(), Box<dyn Error>> {
        let fixture = WaitFixture::new()?;
        let mut runtime = runtime_for(&fixture)?;
        let deadline = Instant::now()
            .checked_add(std::time::Duration::from_secs(5))
            .ok_or("wait deadline overflow")?;
        let (request, completion) = wait_request(&fixture, deadline);
        runtime.handle_execution_wait(request);
        assert_eq!(runtime.waiters.len(), 1);

        let terminal = fixture.workspace.client.execution_fail(
            fixture.workspace.scope.clone(),
            forge_domain::FailExecution::new(
                fixture.execution_id,
                fixture.running_revision,
                timestamp(18)?,
                ExecutionFailureCode::Supervision,
            ),
        )?;
        assert_eq!(terminal.state(), ExecutionState::Failed);
        let mut progress = JournalProgress::default();
        progress.record(fixture.execution_id);
        runtime.service_waiters(&progress);

        let result = completion.wait()?;
        assert!(result.changed());
        assert!(!result.timed_out());
        assert_eq!(result.state(), ExecutionState::Failed);
        assert_eq!(result.revision(), terminal.revision());
        assert_eq!(
            result.output().terminal_state(),
            Some(ExecutionState::Failed)
        );
        stop_runtime(&mut runtime)?;
        fixture.finish()?;
        Ok(())
    }

    #[test]
    fn dropped_journal_reply_after_durable_output_reconciles_and_releases_coordinator()
    -> Result<(), Box<dyn Error>> {
        let fixture = WaitFixture::new_output()?;
        let (mut runtime, journal_owner, committed_rx, _release_tx, _keepalive) =
            scripted_dropped_output_runtime(&fixture, 1, true, false)?;

        let deadline = Instant::now() + Duration::from_secs(3);
        let mut progress = JournalProgress::default();
        loop {
            runtime.poll_and_persist_output(&mut progress);
            if let Ok(result) = committed_rx.try_recv() {
                result.map_err(|error| format!("durable journal output failed: {error:?}"))?;
                break;
            }
            if Instant::now() >= deadline {
                return Err("durable output journal request was not admitted".into());
            }
            thread::yield_now();
        }
        assert!(!runtime.journal_failed);
        assert!(!progress.contains(fixture.execution_id));

        let readback_deadline = Instant::now() + Duration::from_secs(3);
        while runtime.pending_output.is_some() && !runtime.journal_failed {
            runtime.poll_and_persist_output(&mut progress);
            if Instant::now() >= readback_deadline {
                return Err("output journal readback did not converge".into());
            }
            thread::yield_now();
        }
        assert!(!runtime.journal_failed);
        assert!(runtime.pending_output.is_none());
        assert!(progress.contains(fixture.execution_id));
        journal_owner
            .join()
            .map_err(|_| "journal owner thread panicked")?;

        let output = fixture.workspace.client.execution_output_read(
            fixture.workspace.scope.clone(),
            ExecutionOutputCursor::initial(fixture.execution_id),
            forge_domain::MAX_EXECUTION_OUTPUT_READ_BYTES,
            forge_domain::MAX_EXECUTION_OUTPUT_READ_EVENTS,
        )?;
        assert!(!output.events().is_empty());
        runtime.control = fixture.workspace.client.clone();
        let terminal_deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let _progress = runtime.poll_and_journal();
            let durable = fixture
                .workspace
                .client
                .execution_get(fixture.workspace.scope.clone(), fixture.execution_id)?
                .ok_or("durable execution disappeared")?;
            if durable.state().is_terminal() && !runtime.active.contains_key(&fixture.execution_id)
            {
                break;
            }
            if Instant::now() >= terminal_deadline {
                return Err("supervisor terminal did not reconcile".into());
            }
            thread::yield_now();
        }
        assert!(!runtime.journal_failed);
        let durable = fixture
            .workspace
            .client
            .execution_get(fixture.workspace.scope.clone(), fixture.execution_id)?
            .ok_or("durable execution disappeared")?;
        assert_eq!(durable.state(), ExecutionState::Completed);

        stop_runtime(&mut runtime)?;
        fixture.finish()?;
        Ok(())
    }

    type ScriptedDroppedOutput = (
        CoordinatorRuntime,
        thread::JoinHandle<()>,
        mpsc::Receiver<Result<(), crate::ControlError>>,
        Option<mpsc::SyncSender<()>>,
        mpsc::SyncSender<CoordinatorRequest>,
    );

    struct ScriptedOutputSetup {
        authority: ExecutionJournalAuthority,
        before: forge_domain::RegisteredExecution,
        layout: forge_workspace::ExistingWorkspaceStateLayout,
        request: ExecutionRequest,
        identity: ExecutionStartIdentity,
    }

    fn scripted_output_setup(fixture: &WaitFixture) -> Result<ScriptedOutputSetup, Box<dyn Error>> {
        let authority = journal_authority_for_fixture(fixture)?;
        let before = fixture
            .workspace
            .client
            .execution_get(fixture.workspace.scope.clone(), fixture.execution_id)?
            .ok_or("wait fixture execution record disappeared")?;
        let layout = WorkspaceStateLayout::inspect_existing(&fixture.workspace.workspace_root)?
            .ok_or("wait fixture Workspace state disappeared")?;
        let request = ExecutionRequest::new(
            ExecutionAttribution::new(
                fixture.execution_id,
                fixture.workspace.scope.workspace_id(),
                fixture.authority.activity_id,
            ),
            ExecutionKind::Structured {
                program: ExecutionProgram::new(PathBuf::from("/usr/bin/printf"))?,
                arguments: vec![ExecutionArgument::new(OsString::from("durable-output"))?],
            },
            None,
            ExecutionLimits::new(
                ExecutionTimeoutMillis::new(30_000)?,
                ExecutionOutputLimit::new(8_192)?,
            ),
            ExecutionPermissions::new(false, false, false),
        )?;
        let authorization = ExecutionAuthorizationRequest::new(
            fixture.execution_id,
            fixture.workspace.scope.workspace_id(),
            fixture.authority.activity_id,
            forge_execution::execution_request_digest(&request),
            ExecutionActionClass::DirectStructured,
            RequestedExecutionPermissions::new(request.permissions()),
        );
        let start = ExecutionCoordinatorStartRequest::new_explicit(
            fixture.workspace.scope.clone(),
            fixture.authority.activity_id,
            RuntimeInstanceId::from_uuid(id(0xFB00)),
            ExecutionGrantId::from_uuid(id(0xFB01)),
            ExecutionGrantRevision::INITIAL,
            authorization,
            request.clone(),
        );
        Ok(ScriptedOutputSetup {
            authority,
            before,
            layout,
            request,
            identity: ExecutionStartIdentity::from_request(&start),
        })
    }

    fn spawn_scripted_output_journal_owner(
        requests: mpsc::Receiver<ForgeControlRequest>,
        committed_tx: mpsc::SyncSender<Result<(), crate::ControlError>>,
        release_rx: mpsc::Receiver<()>,
        service_readback: bool,
        delay_readback: bool,
    ) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            let Ok(ForgeControlRequest::ExecutionJournalOutput {
                authority,
                events,
                response,
            }) = requests.recv()
            else {
                return;
            };
            let result = ForgeControl::execution_journal_output(&authority, events);
            let _ = committed_tx.send(result);
            drop(response);
            if !service_readback {
                return;
            }
            if delay_readback {
                let _ = release_rx.recv();
            }
            let Ok(ForgeControlRequest::ExecutionJournalReconcileOutput {
                authority,
                before,
                events,
                response,
            }) = requests.recv()
            else {
                return;
            };
            let result =
                ForgeControl::execution_journal_reconcile_output(&authority, &before, &events);
            let _ = response.send(result);
        })
    }

    fn scripted_dropped_output_runtime(
        fixture: &WaitFixture,
        capacity: usize,
        service_readback: bool,
        delay_readback: bool,
    ) -> Result<ScriptedDroppedOutput, Box<dyn Error>> {
        let ScriptedOutputSetup {
            authority,
            before,
            layout,
            request,
            identity,
        } = scripted_output_setup(fixture)?;
        let (control, requests) = ForgeControlClient::journal_test_channel(capacity);
        let (committed_tx, committed_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let journal_owner = spawn_scripted_output_journal_owner(
            requests,
            committed_tx,
            release_rx,
            service_readback,
            delay_readback,
        );
        let (mut runtime, client) = runtime_and_client_with_control(control)?;
        let keepalive = client.sender.clone();
        let native_identity = SupervisorStartIdentity::capture(
            &layout,
            &request,
            ExecutionLaunchKind::Baseline,
            None,
        )?;
        runtime
            .supervisor
            .client()
            .start_execution(layout, request)?;
        if !runtime
            .supervisor
            .client()
            .acknowledge_start(&native_identity)?
        {
            return Err("scripted output Start receipt was not acknowledged".into());
        }
        runtime.active.insert(
            fixture.execution_id,
            ActiveExecution {
                workspace_id: fixture.workspace.scope.workspace_id(),
                activity_id: fixture.authority.activity_id,
                running: before,
                identity,
                native_identity: Some(native_identity),
                journal: authority,
                terminal_journaled: false,
            },
        );
        Ok((
            runtime,
            journal_owner,
            committed_rx,
            delay_readback.then_some(release_tx),
            keepalive,
        ))
    }

    #[test]
    fn dropped_journal_reply_with_closed_owner_remains_unknown() -> Result<(), Box<dyn Error>> {
        let fixture = WaitFixture::new_output()?;
        let (mut runtime, journal_owner, committed_rx, _release_tx, _keepalive) =
            scripted_dropped_output_runtime(&fixture, 1, false, false)?;
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut progress = JournalProgress::default();
        loop {
            runtime.poll_and_persist_output(&mut progress);
            if let Ok(result) = committed_rx.try_recv() {
                result.map_err(|error| format!("durable journal output failed: {error:?}"))?;
                break;
            }
            if Instant::now() >= deadline {
                return Err("durable output journal request was not admitted".into());
            }
            thread::yield_now();
        }
        journal_owner
            .join()
            .map_err(|_| "journal owner thread panicked")?;
        assert!(!runtime.journal_failed);
        assert!(runtime.pending_output.is_some());

        runtime.poll_and_persist_output(&mut progress);
        assert!(runtime.journal_failed);
        let first = runtime
            .first_journal_failure
            .ok_or("first failure missing")?;
        assert_eq!(first.stage, JournalFailureStage::OutputReadback);
        assert_eq!(first.code, Some(crate::ControlErrorCode::WorkerClosed));
        runtime.latch_journal_failure(JournalFailureStage::OutputWrite, None);
        assert_eq!(runtime.first_journal_failure, Some(first));
        assert!(runtime.pending_output.is_some());
        assert_eq!(
            fixture
                .workspace
                .client
                .execution_get(fixture.workspace.scope.clone(), fixture.execution_id)?
                .ok_or("running execution disappeared after journal-owner loss")?
                .state(),
            ExecutionState::Running
        );
        stop_runtime(&mut runtime)?;
        fixture.finish()?;
        Ok(())
    }

    #[test]
    fn output_readback_queue_full_keeps_readback_until_owner_recovers() -> Result<(), Box<dyn Error>>
    {
        let fixture = WaitFixture::new_output()?;
        let (mut runtime, journal_owner, committed_rx, release_tx, _keepalive) =
            scripted_dropped_output_runtime(&fixture, 0, true, true)?;
        let release_tx = release_tx.ok_or("readback gate was not created")?;
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut progress = JournalProgress::default();
        loop {
            runtime.poll_and_persist_output(&mut progress);
            if let Ok(result) = committed_rx.try_recv() {
                result.map_err(|error| format!("durable journal output failed: {error:?}"))?;
                break;
            }
            if Instant::now() >= deadline {
                return Err("durable output journal request was not admitted".into());
            }
            thread::yield_now();
        }
        assert!(!runtime.journal_failed);
        assert!(runtime.pending_output.is_some());
        runtime.poll_and_persist_output(&mut progress);
        assert!(!runtime.journal_failed);
        assert!(runtime.pending_output.is_some());
        let pending = runtime
            .pending_output
            .as_ref()
            .ok_or("output prefix was unexpectedly released")?;
        assert_eq!(pending.groups[0].state, JournalWorkState::Readback);

        release_tx.send(())?;
        let readback_deadline = Instant::now() + Duration::from_secs(3);
        while runtime.pending_output.is_some() && !runtime.journal_failed {
            runtime.poll_and_persist_output(&mut progress);
            if Instant::now() >= readback_deadline {
                return Err("output journal readback did not recover".into());
            }
            thread::yield_now();
        }
        assert!(!runtime.journal_failed);
        assert!(runtime.pending_output.is_none());
        journal_owner
            .join()
            .map_err(|_| "journal owner thread panicked")?;
        stop_runtime(&mut runtime)?;
        fixture.finish()?;
        Ok(())
    }

    fn fixture_launch_failure(
        fixture: &WaitFixture,
    ) -> Result<super::PendingTerminal, Box<dyn Error>> {
        let before = fixture
            .workspace
            .client
            .execution_get(fixture.workspace.scope.clone(), fixture.execution_id)?
            .ok_or("launch fixture execution disappeared")?;
        let command = forge_domain::FailExecution::new(
            before.id(),
            before.revision(),
            timestamp(50)?,
            forge_domain::ExecutionFailureCode::ProcessSpawn,
        );
        Ok(super::PendingTerminal::launch_failure(
            before.id(),
            journal_authority_for_fixture(fixture)?,
            before,
            command,
        ))
    }

    #[test]
    fn scoped_stop_confirms_launch_failure_even_without_a_child() -> Result<(), Box<dyn Error>> {
        for activity_only in [false, true] {
            let fixture = WaitFixture::new()?;
            let mut runtime = runtime_for(&fixture)?;
            runtime.launch_failure = Some(fixture_launch_failure(&fixture)?);
            let cancelled = if activity_only {
                runtime.stop_activity_and_journal(
                    fixture.workspace.scope.workspace_id(),
                    fixture.authority.activity_id,
                )?
            } else {
                runtime.stop_workspace_and_journal(fixture.workspace.scope.workspace_id())?
            };
            let confirmed = runtime.launch_failure.is_none();
            let durable = fixture
                .workspace
                .client
                .execution_get(fixture.workspace.scope.clone(), fixture.execution_id)?
                .ok_or("scoped stop execution missing")?;
            stop_runtime(&mut runtime)?;
            fixture.finish()?;
            assert_eq!(cancelled, 0);
            assert!(
                confirmed,
                "zero-child scoped stop dropped its matching journal wait"
            );
            assert_eq!(durable.state(), ExecutionState::Failed);
            assert_eq!(durable.timestamps().updated_at(), timestamp(50)?);
        }
        Ok(())
    }

    #[test]
    fn disabled_location_stop_phases_cancel_and_journal_real_child() -> Result<(), Box<dyn Error>> {
        #[derive(Clone, Copy)]
        enum StopKind {
            Workspace,
            Activity,
            All,
        }

        const SCRIPT: &str = "printf 'stop-phase-ready\\n'; exec /bin/sleep 60";
        for kind in [StopKind::Workspace, StopKind::Activity, StopKind::All] {
            let fixture = WaitFixture::new_with_command("/bin/sh", &["-c", SCRIPT])?;
            let mut runtime = runtime_for(&fixture)?;
            let (identity, layout, request) = install_pending_start_command_fixture(
                &mut runtime,
                &fixture,
                ExecutionLaunchKind::Baseline,
                "/bin/sh",
                &["-c", SCRIPT],
            )?;
            runtime.supervisor.client().start_execution_with_identity(
                identity,
                layout,
                request,
                ExecutionLaunchKind::Baseline,
                None,
                None,
            )?;
            runtime.progress_pending_start();
            assert!(runtime.pending_start.is_none());

            let expected_output = b"stop-phase-ready\n";
            let output_deadline = Instant::now() + Duration::from_secs(3);
            loop {
                runtime.poll_and_journal();
                let (_record, output) = read_wait_fixture_store(&fixture)?;
                if output.events().iter().any(|event| {
                    matches!(
                        event,
                        ExecutionOutputEvent::Chunk(chunk) if chunk.bytes() == expected_output
                    )
                }) {
                    break;
                }
                if runtime.journal_failed {
                    return Err("durable pre-stop output journaling failed".into());
                }
                if Instant::now() >= output_deadline {
                    return Err("real child output did not become durable before stop".into());
                }
                thread::yield_now();
            }

            disable_wait_fixture_location(&fixture)?;
            let stop_result = match kind {
                StopKind::Workspace => {
                    runtime.stop_workspace_and_journal(fixture.workspace.scope.workspace_id())
                }
                StopKind::Activity => runtime.stop_activity_and_journal(
                    fixture.workspace.scope.workspace_id(),
                    fixture.authority.activity_id,
                ),
                StopKind::All => runtime.stop_all_and_journal(),
            };
            assert_eq!(stop_result?, 1);

            let (record, output) = read_wait_fixture_store(&fixture)?;
            assert_eq!(record.state(), ExecutionState::Cancelled);
            let closure = read_wait_fixture_closure(&fixture)?;
            assert_eq!(closure.after_revision(), record.revision());
            assert_eq!(
                closure.process(),
                forge_domain::NativeClosureProcess::ProcessGroupReaped
            );
            assert_eq!(closure.output_cursor(), output.next_cursor());
            assert!(output.events().iter().any(|event| {
                matches!(
                    event,
                    ExecutionOutputEvent::Chunk(chunk) if chunk.bytes() == expected_output
                )
            }));
            assert!(!runtime.journal_failed);
            stop_runtime(&mut runtime)?;
            fixture.finish()?;
        }
        Ok(())
    }

    #[test]
    fn closed_native_owner_disabled_scope_preserves_execution_error() -> Result<(), Box<dyn Error>>
    {
        let fixture = WaitFixture::new()?;
        let mut runtime = runtime_for(&fixture)?;
        let (identity, layout, request) =
            install_pending_start_fixture(&mut runtime, &fixture, ExecutionLaunchKind::Baseline)?;
        runtime.supervisor.client().start_execution_with_identity(
            identity,
            layout,
            request,
            ExecutionLaunchKind::Baseline,
            None,
            None,
        )?;
        runtime.progress_pending_start();
        assert!(runtime.pending_start.is_none());
        let _native_report = runtime.supervisor.shutdown()?;
        disable_wait_fixture_location(&fixture)?;

        let stop_result =
            runtime.stop_workspace_and_journal(fixture.workspace.scope.workspace_id());
        match stop_result {
            Err(ForgeExecutionCoordinatorError::CancellationAndJournal {
                cancellation,
                journal,
            }) => {
                assert!(matches!(*cancellation, ExecutionSupervisorError::Closed));
                assert!(matches!(
                    *journal,
                    ForgeExecutionCoordinatorError::JournalFailure(JournalFailure {
                        stage: JournalFailureStage::OutputRead,
                        ..
                    })
                ));
            }
            other => return Err(format!("unexpected disabled-owner stop result: {other:?}").into()),
        }
        let (record, _output) = read_wait_fixture_store(&fixture)?;
        assert_eq!(record.state(), ExecutionState::Running);
        drop(runtime);
        fixture.finish()?;
        Ok(())
    }

    #[test]
    fn unavailable_state_stop_cancels_real_child_without_synthesizing_terminal()
    -> Result<(), Box<dyn Error>> {
        const SCRIPT: &str = "printf 'state-loss-ready\\n'; exec /bin/sleep 60";
        let fixture = WaitFixture::new_with_command("/bin/sh", &["-c", SCRIPT])?;
        let mut runtime = runtime_for(&fixture)?;
        let (identity, layout, request) = install_pending_start_command_fixture(
            &mut runtime,
            &fixture,
            ExecutionLaunchKind::Baseline,
            "/bin/sh",
            &["-c", SCRIPT],
        )?;
        runtime.supervisor.client().start_execution_with_identity(
            identity,
            layout,
            request,
            ExecutionLaunchKind::Baseline,
            None,
            None,
        )?;
        runtime.progress_pending_start();
        assert!(runtime.pending_start.is_none());

        let expected_output = b"state-loss-ready\n";
        let output_deadline = Instant::now() + Duration::from_secs(3);
        loop {
            runtime.poll_and_journal();
            let (_record, output) = read_wait_fixture_store(&fixture)?;
            if output.events().iter().any(|event| {
                matches!(
                    event,
                    ExecutionOutputEvent::Chunk(chunk) if chunk.bytes() == expected_output
                )
            }) {
                break;
            }
            if runtime.journal_failed {
                return Err("pre-stop output journaling failed".into());
            }
            if Instant::now() >= output_deadline {
                return Err("state-loss child output did not become durable".into());
            }
            thread::yield_now();
        }

        disable_wait_fixture_location(&fixture)?;
        let mut moved_state = MovedStateDirectory::move_from(&fixture.workspace.workspace_root)?;
        let stop_result =
            runtime.stop_workspace_and_journal(fixture.workspace.scope.workspace_id());

        let event = wait_retained_terminal_event(&runtime, fixture.execution_id)?;
        assert!(matches!(
            event.result(),
            Ok(outcome)
                if outcome.status() == forge_domain::ExecutionCompletionStatus::Cancelled
        ));
        assert!(
            runtime
                .supervisor
                .client()
                .acknowledge_terminal_event(&event.key(), &event.identity())?
        );
        let _native_report = runtime.supervisor.shutdown()?;
        moved_state.restore()?;

        match stop_result {
            Err(ForgeExecutionCoordinatorError::JournalFailed) => {}
            other => {
                return Err(format!("unexpected unavailable-state stop result: {other:?}").into());
            }
        }
        let (record, output) = read_wait_fixture_store(&fixture)?;
        assert_eq!(record.state(), ExecutionState::Running);
        assert!(output.events().iter().any(|event| {
            matches!(
                event,
                ExecutionOutputEvent::Chunk(chunk) if chunk.bytes() == expected_output
            )
        }));
        drop(runtime);
        fixture.finish()?;
        Ok(())
    }

    fn wait_retained_terminal_event(
        runtime: &CoordinatorRuntime,
        execution_id: ExecutionId,
    ) -> Result<forge_execution::ExecutionSupervisorEvent, Box<dyn Error>> {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if let Some(event) = runtime
                .supervisor
                .client()
                .peek_terminal_events(MAX_TERMINAL_BACKLOG)?
                .into_iter()
                .find(|event| event.execution_id() == execution_id)
            {
                return Ok(event);
            }
            if Instant::now() >= deadline {
                return Err("cancelled terminal event was not retained by native owner".into());
            }
            thread::yield_now();
        }
    }

    #[test]
    fn launch_failure_wait_preserves_timestamp_fence_and_ack_order() -> Result<(), Box<dyn Error>> {
        let fixture = WaitFixture::new()?;
        let mut runtime = runtime_for(&fixture)?;
        runtime.launch_failure = Some(fixture_launch_failure(&fixture)?);
        let (blocked, receiver) = ForgeControlClient::journal_test_channel(0);
        runtime.control = blocked;
        assert!(!runtime.flush_launch_failure());
        assert!(!runtime.journal_failed);
        let start = start_request(
            ExecutionActionClass::DirectStructured,
            "test",
            "/usr/bin/true",
            "",
            ExecutionPermissions::new(false, false, false),
        )?;
        assert!(matches!(
            runtime.start_execution(start),
            Err(ForgeExecutionCoordinatorError::JournalFailed)
        ));
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        runtime.wait_for(
            |_, _| false,
            |pending| pending.belongs_to_workspace(WorkspaceId::from_uuid(id(0xDEAD))),
        )?;
        assert!(runtime.launch_failure.is_some());

        runtime.control = fixture.workspace.client.clone();
        let event = output_event(fixture.execution_id, b"retained")?;
        runtime.pending_output = Some(super::PendingOutput {
            ack_key: event.key(),
            events: vec![event],
            groups: Vec::new(),
            ack_state: super::OutputAckState::Readback,
        });
        assert!(!runtime.flush_launch_failure());
        let pending = runtime
            .launch_failure
            .as_ref()
            .ok_or("launch slot was dropped")?;
        assert_eq!(
            pending
                .command
                .as_ref()
                .ok_or("launch command missing")?
                .observed_at(),
            timestamp(50)?
        );
        assert_eq!(
            fixture
                .workspace
                .client
                .execution_get(fixture.workspace.scope.clone(), fixture.execution_id)?
                .ok_or("execution missing")?
                .state(),
            ExecutionState::Running
        );
        runtime.pending_output = None;
        runtime.wait_for(
            |_, _| false,
            |pending| pending.belongs_to_workspace(fixture.workspace.scope.workspace_id()),
        )?;
        assert!(runtime.launch_failure.is_none());
        let failed = fixture
            .workspace
            .client
            .execution_get(fixture.workspace.scope.clone(), fixture.execution_id)?
            .ok_or("failed execution missing")?;
        assert_eq!(failed.state(), ExecutionState::Failed);
        assert_eq!(failed.timestamps().updated_at(), timestamp(50)?);
        assert_eq!(runtime.terminal_records, 1);
        stop_runtime(&mut runtime)?;
        fixture.finish()?;
        Ok(())
    }

    #[test]
    fn dropped_terminal_reply_reconciles_original_failure_timestamp() -> Result<(), Box<dyn Error>>
    {
        let fixture = WaitFixture::new()?;
        let mut runtime = runtime_for(&fixture)?;
        runtime.launch_failure = Some(fixture_launch_failure(&fixture)?);
        let (control, requests) = ForgeControlClient::journal_test_channel(1);
        runtime.control = control;
        let owner = thread::spawn(move || -> Result<(), String> {
            let ForgeControlRequest::ExecutionJournalFail {
                authority,
                command,
                closure,
                response,
            } = requests.recv().map_err(|error| error.to_string())?
            else {
                return Err("expected failure write".into());
            };
            let _record = ForgeControl::execution_journal_fail(&authority, command, closure)
                .map_err(|error| error.to_string())?;
            drop(response);
            let ForgeControlRequest::ExecutionJournalReconcileTerminal {
                authority,
                before,
                command,
                closure,
                response,
            } = requests.recv().map_err(|error| error.to_string())?
            else {
                return Err("expected terminal readback".into());
            };
            response
                .send(ForgeControl::execution_journal_reconcile_terminal(
                    &authority, &before, &command, closure,
                ))
                .map_err(|error| error.to_string())?;
            Ok(())
        });
        assert!(!runtime.flush_launch_failure());
        assert!(!runtime.journal_failed);
        assert_eq!(
            runtime
                .launch_failure
                .as_ref()
                .ok_or("launch slot missing")?
                .state,
            JournalWorkState::Readback
        );
        assert!(runtime.flush_launch_failure());
        assert!(!runtime.journal_failed);
        assert!(runtime.launch_failure.is_none());
        owner.join().map_err(|_| "terminal owner panicked")??;
        let failed = fixture
            .workspace
            .client
            .execution_get(fixture.workspace.scope.clone(), fixture.execution_id)?
            .ok_or("failed execution missing")?;
        assert_eq!(failed.state(), ExecutionState::Failed);
        assert_eq!(failed.timestamps().updated_at(), timestamp(50)?);
        assert_eq!(runtime.terminal_records, 1);
        stop_runtime(&mut runtime)?;
        fixture.finish()?;
        Ok(())
    }

    #[test]
    fn coordinator_wait_timeout_performs_final_authorized_read() -> Result<(), Box<dyn Error>> {
        let fixture = WaitFixture::new()?;
        let mut runtime = runtime_for(&fixture)?;
        let deadline = Instant::now()
            .checked_sub(std::time::Duration::from_secs(1))
            .ok_or("timeout deadline underflow")?;
        let (request, completion) = wait_request(&fixture, deadline);
        runtime.waiters.push_back(pending_wait(
            request,
            ExecutionState::Running,
            fixture.running_revision,
        ));
        runtime.service_waiters(&JournalProgress::default());

        let result = completion.wait()?;
        assert!(result.timed_out());
        assert!(!result.changed());
        assert_eq!(result.state(), ExecutionState::Running);
        assert_eq!(result.revision(), fixture.running_revision);
        assert!(result.output().events().is_empty());
        stop_runtime(&mut runtime)?;
        fixture.finish()?;
        Ok(())
    }

    #[test]
    fn coordinator_wait_rejects_stale_authority_at_wake() -> Result<(), Box<dyn Error>> {
        let fixture = WaitFixture::new()?;
        let mut runtime = runtime_for(&fixture)?;
        let deadline = Instant::now()
            .checked_add(std::time::Duration::from_secs(5))
            .ok_or("wait deadline overflow")?;
        let (request, completion) = wait_request(&fixture, deadline);
        runtime.handle_execution_wait(request);
        assert_eq!(runtime.waiters.len(), 1);

        let actor = fixture
            .workspace
            .client
            .activity_coordinator_actor(crate::CoordinatorActorRequest {
                scope: fixture.workspace.scope.clone(),
                activity_id: fixture.authority.activity_id,
                principal: AuthenticatedPrincipal::TrustedStdio,
            })?
            .ok_or("wait fixture coordinator actor missing")?;
        let _focus = fixture
            .workspace
            .client
            .agent_set_focus(AgentFocusRequest {
                scope: fixture.workspace.scope.clone(),
                activity_id: fixture.authority.activity_id,
                actor,
                agent_id: fixture.authority.agent_id,
                expected_revision: fixture.authority.expected_revision,
                focus: AgentFocus::new(
                    Some(GoalAttribution::new(
                        fixture.authority.attribution.goal_id(),
                        fixture.authority.attribution.expected_goal_revision(),
                    )),
                    Some(fixture.authority.attribution.dag_revision()),
                    None,
                )?,
                observed_at: timestamp(18)?,
            })?;
        let mut progress = JournalProgress::default();
        progress.record(fixture.execution_id);
        runtime.service_waiters(&progress);

        let response = completion.wait();
        assert!(matches!(
            response,
            Err(ForgeExecutionCoordinatorError::Control(_))
        ));
        stop_runtime(&mut runtime)?;
        fixture.finish()?;
        Ok(())
    }

    #[test]
    fn coordinator_wait_immediate_read_precedes_waiter_capacity_rejection()
    -> Result<(), Box<dyn Error>> {
        let fixture = WaitFixture::new()?;
        let event = output_event(fixture.execution_id, b"already durable\n")?;
        fixture
            .workspace
            .client
            .execution_output_append_batch(fixture.workspace.scope.clone(), vec![event])?;
        let mut runtime = runtime_for(&fixture)?;
        for _ in 0..MAX_EXECUTION_WAITERS {
            let (request, completion) = wait_request(
                &fixture,
                Instant::now()
                    .checked_add(std::time::Duration::from_secs(5))
                    .ok_or("wait deadline overflow")?,
            );
            drop(completion);
            runtime.waiters.push_back(pending_wait(
                request,
                ExecutionState::Running,
                fixture.running_revision,
            ));
        }
        let (request, completion) = wait_request(
            &fixture,
            Instant::now()
                .checked_add(std::time::Duration::from_secs(5))
                .ok_or("wait deadline overflow")?,
        );
        runtime.handle_execution_wait(request);
        let result = completion.wait()?;
        assert!(result.changed());
        assert!(!result.timed_out());
        assert_eq!(runtime.waiters.len(), MAX_EXECUTION_WAITERS);
        stop_runtime(&mut runtime)?;
        fixture.finish()?;
        Ok(())
    }

    #[test]
    fn coordinator_wait_supports_multiple_waiters_for_one_execution() -> Result<(), Box<dyn Error>>
    {
        let fixture = WaitFixture::new()?;
        let mut runtime = runtime_for(&fixture)?;
        let deadline = Instant::now()
            .checked_add(std::time::Duration::from_secs(5))
            .ok_or("wait deadline overflow")?;
        let (first_request, first_completion) = wait_request(&fixture, deadline);
        let (second_request, second_completion) = wait_request(&fixture, deadline);
        runtime.handle_execution_wait(first_request);
        runtime.handle_execution_wait(second_request);
        assert_eq!(runtime.waiters.len(), 2);

        let event = output_event(fixture.execution_id, b"fanout\n")?;
        fixture
            .workspace
            .client
            .execution_output_append_batch(fixture.workspace.scope.clone(), vec![event])?;
        let mut progress = JournalProgress::default();
        progress.record(fixture.execution_id);
        runtime.service_waiters(&progress);

        let first = first_completion.wait()?;
        let second = second_completion.wait()?;
        assert!(first.changed());
        assert!(second.changed());
        assert!(runtime.waiters.is_empty());
        stop_runtime(&mut runtime)?;
        fixture.finish()?;
        Ok(())
    }

    #[test]
    fn coordinator_shutdown_resolves_pending_waiters() -> Result<(), Box<dyn Error>> {
        let fixture = WaitFixture::new()?;
        let mut runtime = runtime_for(&fixture)?;
        let deadline = Instant::now()
            .checked_add(std::time::Duration::from_secs(5))
            .ok_or("wait deadline overflow")?;
        let (request, completion) = wait_request(&fixture, deadline);
        runtime.handle_execution_wait(request);
        assert_eq!(runtime.waiters.len(), 1);
        runtime.resolve_waiters_as_closed();
        let response = completion.wait();
        assert!(matches!(
            response,
            Err(ForgeExecutionCoordinatorError::Closed)
        ));
        assert!(runtime.waiters.is_empty());
        stop_runtime(&mut runtime)?;
        fixture.finish()?;
        Ok(())
    }

    #[test]
    fn wait_observation_reports_output_and_terminal_progress() -> Result<(), Box<dyn Error>> {
        let id = ExecutionId::from_uuid(id(0xD001));
        let observation = ExecutionWaitObservation {
            output: ExecutionOutputRead::empty_for(id),
            state: ExecutionState::Running,
            revision: ExecutionRevision::INITIAL,
        };
        assert!(!observation.changed_without_baseline());
        assert!(!observation.changed_from(ExecutionState::Running, ExecutionRevision::INITIAL,));

        let terminal = ExecutionWaitObservation {
            output: ExecutionOutputRead::empty_for(id),
            state: ExecutionState::Completed,
            revision: ExecutionRevision::new(2)?,
        };
        assert!(terminal.changed_without_baseline());
        assert!(terminal.changed_from(ExecutionState::Running, ExecutionRevision::INITIAL,));
        let result = terminal.into_result(false, true);
        assert_eq!(result.state(), ExecutionState::Completed);
        assert_eq!(result.revision().get(), 2);
        assert!(result.changed());
        assert!(!result.timed_out());
        Ok(())
    }

    #[test]
    fn journal_progress_is_bounded_by_unique_execution_ids() {
        let first = ExecutionId::from_uuid(id(0xD101));
        let second = ExecutionId::from_uuid(id(0xD102));
        let mut progress = JournalProgress::default();
        progress.record(first);
        progress.record(first);
        progress.record(second);
        assert!(progress.contains(first));
        assert!(progress.contains(second));
        assert_eq!(progress.execution_ids.len(), 2);
    }

    #[test]
    fn wait_timeout_policy_is_explicitly_bounded() {
        assert_eq!(
            MAX_EXECUTION_WAIT_TIMEOUT,
            std::time::Duration::from_secs(30)
        );
        assert!(std::time::Duration::from_secs(30) <= MAX_EXECUTION_WAIT_TIMEOUT);
        assert!(std::time::Duration::from_secs(31) > MAX_EXECUTION_WAIT_TIMEOUT);
    }

    #[test]
    fn wait_future_registers_waker_and_is_woken_by_completion() {
        let (mut handle, completion) = standalone_wait_handle();
        let wake_count = Arc::new(AtomicU64::new(0));
        let wake_handle = Waker::from(Arc::new(CountingWake {
            wakes: Arc::clone(&wake_count),
        }));
        let mut context = Context::from_waker(&wake_handle);
        assert!(matches!(
            Future::poll(Pin::new(&mut handle), &mut context),
            Poll::Pending
        ));
        completion.complete(Ok(sample_wait_result()));
        assert_eq!(wake_count.load(Ordering::Relaxed), 1);
        let result = Future::poll(Pin::new(&mut handle), &mut context);
        assert!(matches!(result, Poll::Ready(Ok(result)) if result.changed()));
    }

    #[test]
    fn completion_does_not_propagate_a_panicking_waker() {
        let (mut handle, completion) = standalone_wait_handle();
        let panic_waker = Waker::from(Arc::new(PanicWake));
        let mut context = Context::from_waker(&panic_waker);
        assert!(matches!(
            Future::poll(Pin::new(&mut handle), &mut context),
            Poll::Pending
        ));
        completion.complete(Ok(sample_wait_result()));
        assert!(matches!(
            Future::poll(Pin::new(&mut handle), &mut context),
            Poll::Ready(Ok(_))
        ));
    }

    #[test]
    fn begin_wait_returns_immediately_and_cancel_before_admission_is_safe()
    -> Result<(), Box<dyn Error>> {
        let fixture = WaitFixture::new()?;
        let (sender, receiver) = mpsc::sync_channel(1);
        let (cancellation_sender, cancellation_receiver) =
            mpsc::sync_channel(EXECUTION_WAIT_CANCELLATION_CAPACITY);
        let accepting = Arc::new(AtomicBool::new(true));
        let client = ForgeExecutionCoordinatorClient {
            sender,
            cancellation_sender,
            accepting,
            verification_cancellation: Arc::new(AtomicBool::new(false)),
            next_waiter_id: Arc::new(AtomicU64::new(1)),
            rust_ci_available: false,
        };
        let started = Instant::now();
        let handle = begin_fixture_wait(&client, &fixture)?;
        assert!(started.elapsed() < Duration::from_secs(1));
        let waiter_id = handle.id();
        drop(handle);

        let request = receiver.try_recv().map_err(|_| "wait request missing")?;
        match request {
            CoordinatorRequest::WaitExecutionOutputAuthorizedAsync { request } => {
                assert_eq!(request.waiter_id, waiter_id);
                assert_eq!(
                    request.state.load(Ordering::Acquire),
                    EXECUTION_WAIT_CANCELLED
                );
            }
            CoordinatorRequest::WaitCancellationWake => {
                return Err("cancellation wake overtook wait request".into());
            }
            _ => return Err("unexpected coordinator request".into()),
        }
        assert_eq!(
            cancellation_receiver
                .try_recv()
                .map_err(|_| "cancellation missing")?,
            waiter_id
        );
        drop(client);
        fixture.finish()?;
        Ok(())
    }

    #[test]
    fn cancellation_removes_only_its_retained_waiter() -> Result<(), Box<dyn Error>> {
        let fixture = WaitFixture::new()?;
        let (mut runtime, client) = runtime_and_client(&fixture)?;
        let first = begin_fixture_wait(&client, &fixture)?;
        let second = begin_fixture_wait(&client, &fixture)?;
        for _ in 0..2 {
            let request = match runtime.receive_request() {
                CoordinatorReceive::Request(request) => request,
                CoordinatorReceive::Timeout => return Err("unexpected wait timeout".into()),
                CoordinatorReceive::Closed => return Err("runtime closed unexpectedly".into()),
            };
            runtime.handle_request(request);
        }
        assert_eq!(runtime.waiters.len(), 2);
        let first_id = first.id();
        drop(first);
        runtime.drain_wait_cancellations();
        assert_eq!(runtime.waiters.len(), 1);
        assert_eq!(
            runtime.waiters.front().map(|waiter| waiter.waiter_id),
            Some(second.id())
        );
        assert_ne!(first_id, second.id());
        drop(second);
        runtime.drain_wait_cancellations();
        assert!(runtime.waiters.is_empty());
        stop_runtime(&mut runtime)?;
        fixture.finish()?;
        Ok(())
    }

    #[test]
    fn completion_and_cancellation_race_delivers_at_most_one_result() -> Result<(), Box<dyn Error>>
    {
        let bridge = Arc::new(ExecutionWaitCompletionBridge::new());
        let execution_id = ExecutionId::from_uuid(id(0xD201));
        let mut joins = Vec::new();
        for index in 0..8 {
            let bridge_for_thread = Arc::clone(&bridge);
            joins.push(thread::spawn(move || {
                if index % 2 == 0 {
                    bridge_for_thread.complete(Ok(ExecutionWaitResult::new(
                        ExecutionOutputRead::empty_for(execution_id),
                        ExecutionState::Running,
                        ExecutionRevision::INITIAL,
                        false,
                        false,
                    )));
                } else {
                    let _cancelled = bridge_for_thread.cancel();
                }
            }));
        }
        for join in joins {
            join.join().map_err(|_| "wait race thread panicked")?;
        }
        let state = bridge.state.load(Ordering::Acquire);
        let result = bridge.wait();
        match state {
            EXECUTION_WAIT_CANCELLED => {
                assert!(matches!(
                    result,
                    Err(ForgeExecutionCoordinatorError::Closed)
                ));
            }
            EXECUTION_WAIT_COMPLETED => assert!(result.is_ok()),
            _ => return Err("wait race did not settle".into()),
        }
        Ok(())
    }

    #[test]
    fn handle_drop_never_blocks_when_bounded_lanes_are_full() -> Result<(), Box<dyn Error>> {
        let fixture = WaitFixture::new()?;
        let (mut runtime, client) = runtime_and_client(&fixture)?;
        for value in 100..(100 + EXECUTION_WAIT_CANCELLATION_CAPACITY as u64) {
            let waiter_id = ExecutionWaiterId::new(value).ok_or("invalid test waiter id")?;
            client
                .cancellation_sender
                .try_send(waiter_id)
                .map_err(|_| "failed to fill cancellation lane")?;
        }
        let handle = begin_fixture_wait(&client, &fixture)?;
        for _ in 0..COORDINATOR_QUEUE_CAPACITY.saturating_sub(1) {
            client
                .sender
                .try_send(CoordinatorRequest::WaitCancellationWake)
                .map_err(|_| "failed to fill coordinator lane")?;
        }
        let started = Instant::now();
        drop(handle);
        assert!(started.elapsed() < Duration::from_secs(1));
        let request = match runtime.receive_request() {
            CoordinatorReceive::Request(
                CoordinatorRequest::WaitExecutionOutputAuthorizedAsync { request },
            ) => request,
            CoordinatorReceive::Request(_) => return Err("unexpected coordinator request".into()),
            CoordinatorReceive::Timeout => return Err("unexpected wait timeout".into()),
            CoordinatorReceive::Closed => return Err("runtime closed unexpectedly".into()),
        };
        assert_eq!(
            request.state.load(Ordering::Acquire),
            EXECUTION_WAIT_CANCELLED
        );
        runtime.handle_async_execution_wait(*request);
        assert!(runtime.waiters.is_empty());
        stop_runtime(&mut runtime)?;
        fixture.finish()?;
        Ok(())
    }

    #[test]
    fn shutdown_completes_non_cancelled_async_wait_as_closed() -> Result<(), Box<dyn Error>> {
        let fixture = WaitFixture::new()?;
        let (mut runtime, client) = runtime_and_client(&fixture)?;
        let handle = begin_fixture_wait(&client, &fixture)?;
        let request = match runtime.receive_request() {
            CoordinatorReceive::Request(request) => request,
            CoordinatorReceive::Timeout => return Err("unexpected wait timeout".into()),
            CoordinatorReceive::Closed => return Err("runtime closed unexpectedly".into()),
        };
        runtime.handle_request(request);
        assert_eq!(runtime.waiters.len(), 1);
        runtime.resolve_waiters_as_closed();
        let result = handle.wait();
        assert!(matches!(
            result,
            Err(ForgeExecutionCoordinatorError::Closed)
        ));
        stop_runtime(&mut runtime)?;
        fixture.finish()?;
        Ok(())
    }

    #[test]
    fn synchronous_wait_adapter_preserves_single_snapshot_result() -> Result<(), Box<dyn Error>> {
        let fixture = WaitFixture::new()?;
        let event = output_event(fixture.execution_id, b"sync adapter\n")?;
        fixture
            .workspace
            .client
            .execution_output_append_batch(fixture.workspace.scope.clone(), vec![event])?;
        let (runtime, client) = runtime_and_client(&fixture)?;
        let worker = thread::spawn(move || {
            let mut runtime = runtime;
            if let CoordinatorReceive::Request(request) = runtime.receive_request() {
                runtime.handle_request(request);
            }
            runtime.resolve_waiters_as_closed();
            let _ignored = runtime.supervisor.shutdown();
        });
        let result = client.execution_wait_authorized(
            fixture.authority.clone(),
            fixture.execution_id,
            forge_domain::ExecutionOutputCursor::initial(fixture.execution_id),
            8_192,
            8,
            Duration::from_secs(30),
        )?;
        assert!(result.changed());
        assert!(!result.timed_out());
        assert_eq!(result.output().events().len(), 1);
        worker.join().map_err(|_| "sync adapter worker panicked")?;
        fixture.finish()?;
        Ok(())
    }
}
