use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use forge_domain::{
    ActivityId, ExecutionFailureCode, ExecutionId, ExecutionOutcome, ExecutionOutputEvent,
    ExecutionOutputEventKey, ExecutionOutputRead, ExecutionRequest, ExecutionRequestDigest,
    GeneratedPackageManifest, VerificationInputEvidence, WorkspaceId, WorkspaceRootFingerprint,
};
use forge_workspace::ExistingWorkspaceStateLayout;
use thiserror::Error;

use crate::package_v::{PackageVExecutableCapability, is_exact_package_request};
use crate::runner::{ProcessFinalization, RustCiRuntimeFinalization};
use crate::{
    ExecutionCompletionResult, ExecutionError, ExecutionRunner, MAX_OUTPUT_EVENT_BACKLOG,
    RunningExecution,
};
use crate::{ExecutionLaunchKind, RustCiToolchainCapability};

mod native_closure;
mod pre_spawn_rejection;

use native_closure::SupervisorOwnerToken;
pub use native_closure::{
    NativeExecutionClosure, NativeWorkspaceQuiescence, ProcessDisposition, RuntimeDisposition,
};
pub use pre_spawn_rejection::NativePreSpawnRejection;
use pre_spawn_rejection::PreSpawnRejectionPhase;

const SUPERVISOR_QUEUE_CAPACITY: usize = 32;
const MAX_COMPLETION_BACKLOG: usize = 64;
const MAX_START_RECEIPTS: usize = 64;
const MAX_RUST_CI_QUARANTINE: usize = 64;
const OUTPUT_POLL_QUANTUM: usize = 8;
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const THREAD_NAME: &str = "heterarchy-forge-execution-supervisor";

fn rust_ci_completion_requires_quarantine(
    process_finalization: Option<ProcessFinalization>,
    runtime_finalization: Option<RustCiRuntimeFinalization>,
) -> bool {
    let process_uncertain =
        process_finalization.is_none_or(ProcessFinalization::requires_rust_ci_quarantine);
    let runtime_uncertain = runtime_finalization.is_none_or(|finalization| {
        finalization.requires_rust_ci_quarantine()
            || matches!(finalization, RustCiRuntimeFinalization::NotApplicable)
    });
    process_uncertain || runtime_uncertain
}

fn additional_quiescence_uncertainty(
    launch_kind: ExecutionLaunchKind,
    process: Option<ProcessFinalization>,
    failed: bool,
    has_manifest: bool,
) -> bool {
    (!launch_uses_rust_ci(launch_kind)
        && process.is_none_or(ProcessFinalization::requires_rust_ci_quarantine))
        || (launch_kind == ExecutionLaunchKind::RustCiGeneratedPackage && (failed || !has_manifest))
}

fn completion_backlog_count<I, F>(active_count: usize, event_ids: I, active_contains: F) -> usize
where
    I: IntoIterator<Item = ExecutionId>,
    F: Fn(ExecutionId) -> bool,
{
    let event_ids: HashSet<_> = event_ids.into_iter().collect();
    let retained_terminal_owners = event_ids
        .iter()
        .filter(|execution_id| active_contains(**execution_id))
        .count();
    active_count
        .saturating_add(event_ids.len())
        .saturating_sub(retained_terminal_owners)
}

type Response<T> = SyncSender<Result<T, ExecutionSupervisorError>>;

/// Exact non-serializable identity of one native supervisor Start.
///
/// The identity carries only bounded semantic and physical binding evidence;
/// it never carries a path or request payload.  Its redacted Debug output is
/// suitable for local diagnostics without exposing digest or root bytes.
#[must_use]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SupervisorStartIdentity {
    execution_id: ExecutionId,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    request_digest: ExecutionRequestDigest,
    launch_kind: ExecutionLaunchKind,
    root_fingerprint: WorkspaceRootFingerprint,
    verification_input: Option<VerificationInputEvidence>,
}

impl std::fmt::Debug for SupervisorStartIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SupervisorStartIdentity")
            .field("execution_id", &self.execution_id)
            .field("workspace_id", &self.workspace_id)
            .field("activity_id", &self.activity_id)
            .field("launch_kind", &self.launch_kind)
            .field(
                "verification_input_present",
                &self.verification_input.is_some(),
            )
            .finish_non_exhaustive()
    }
}

impl SupervisorStartIdentity {
    /// Capture the exact identity before the Start request crosses the native
    /// supervisor channel or any owned value is moved.
    pub fn capture(
        layout: &ExistingWorkspaceStateLayout,
        request: &ExecutionRequest,
        launch_kind: ExecutionLaunchKind,
        verification_input: Option<&forge_workspace::PublishedVerificationInput>,
    ) -> Result<Self, ExecutionSupervisorError> {
        let root_fingerprint = layout
            .root_fingerprint()
            .map_err(ExecutionError::InspectRootFingerprint)?;
        let verification_input = verification_input
            .map(|input| {
                VerificationInputEvidence::new(input.id(), input.manifest())
                    .map_err(|_| ExecutionError::VerificationInputMismatch)
            })
            .transpose()?;
        Ok(Self {
            execution_id: request.id(),
            workspace_id: request.workspace_id(),
            activity_id: request.activity_id(),
            request_digest: crate::execution_request_digest(request),
            launch_kind,
            root_fingerprint,
            verification_input,
        })
    }

    pub const fn execution_id(self) -> ExecutionId {
        self.execution_id
    }

    pub const fn workspace_id(self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn activity_id(self) -> ActivityId {
        self.activity_id
    }

    pub const fn request_digest(self) -> ExecutionRequestDigest {
        self.request_digest
    }

    pub const fn launch_kind(self) -> ExecutionLaunchKind {
        self.launch_kind
    }

    pub const fn root_fingerprint(self) -> WorkspaceRootFingerprint {
        self.root_fingerprint
    }

    pub const fn verification_input(self) -> Option<VerificationInputEvidence> {
        self.verification_input
    }

    pub const fn verification_input_evidence(self) -> Option<VerificationInputEvidence> {
        self.verification_input()
    }

    fn validate_semantic_against(
        self,
        request: &ExecutionRequest,
        launch_kind: ExecutionLaunchKind,
        verification_input: Option<&forge_workspace::PublishedVerificationInput>,
    ) -> Result<(), ExecutionSupervisorError> {
        let expected_verification_input = verification_input
            .map(|input| VerificationInputEvidence::new(input.id(), input.manifest()))
            .transpose()
            .map_err(|_| ExecutionSupervisorError::StartIdentityMismatch {
                id: self.execution_id,
            })?;
        if self.execution_id == request.id()
            && self.workspace_id == request.workspace_id()
            && self.activity_id == request.activity_id()
            && self.request_digest == crate::execution_request_digest(request)
            && self.launch_kind == launch_kind
            && self.verification_input == expected_verification_input
        {
            Ok(())
        } else {
            Err(ExecutionSupervisorError::StartIdentityMismatch {
                id: self.execution_id,
            })
        }
    }

    fn validate_root_against(
        self,
        layout: &ExistingWorkspaceStateLayout,
    ) -> Result<(), ExecutionSupervisorError> {
        let observed = layout
            .root_fingerprint()
            .map_err(ExecutionError::InspectRootFingerprint)?;
        if observed == self.root_fingerprint {
            Ok(())
        } else {
            Err(ExecutionError::InvalidCwd.into())
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SupervisorStartOutcome {
    Accepted,
    Rejected { failure_code: ExecutionFailureCode },
}

#[must_use]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SupervisorStartReceipt {
    identity: SupervisorStartIdentity,
    outcome: SupervisorStartOutcome,
    pre_spawn_rejection: Option<PreSpawnRejectionPhase>,
}

impl std::fmt::Debug for SupervisorStartReceipt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SupervisorStartReceipt")
            .field("identity", &self.identity)
            .field("outcome", &self.outcome)
            .finish_non_exhaustive()
    }
}

impl SupervisorStartReceipt {
    const fn accepted(identity: SupervisorStartIdentity) -> Self {
        Self {
            identity,
            outcome: SupervisorStartOutcome::Accepted,
            pre_spawn_rejection: None,
        }
    }

    const fn rejected(
        identity: SupervisorStartIdentity,
        failure_code: ExecutionFailureCode,
        pre_spawn_rejection: Option<PreSpawnRejectionPhase>,
    ) -> Self {
        Self {
            identity,
            outcome: SupervisorStartOutcome::Rejected { failure_code },
            pre_spawn_rejection,
        }
    }

    pub const fn identity(&self) -> SupervisorStartIdentity {
        self.identity
    }

    pub const fn outcome(&self) -> SupervisorStartOutcome {
        self.outcome
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SupervisorReceivePolicy {
    BlockUntilRequest,
    Poll(Duration),
}

fn supervisor_receive_policy(
    has_active_work: bool,
    is_draining_shutdown: bool,
) -> SupervisorReceivePolicy {
    if has_active_work || is_draining_shutdown {
        SupervisorReceivePolicy::Poll(POLL_INTERVAL)
    } else {
        SupervisorReceivePolicy::BlockUntilRequest
    }
}

enum SupervisorReceive {
    Request(Box<SupervisorRequest>),
    Timeout,
    Disconnected,
}

#[derive(Debug)]
enum SupervisorRequest {
    ObserveWorkspaceQuiescence {
        workspace_id: WorkspaceId,
        response: Response<Option<NativeWorkspaceQuiescence>>,
    },
    ObserveNativeRejection {
        identity: Box<SupervisorStartIdentity>,
        response: Response<Option<NativePreSpawnRejection>>,
    },
    Start {
        identity: Box<SupervisorStartIdentity>,
        layout: ExistingWorkspaceStateLayout,
        request: Box<ExecutionRequest>,
        launch_kind: ExecutionLaunchKind,
        rust_ci_capability: Option<Box<RustCiToolchainCapability>>,
        package_verification: bool,
        verification_input: Option<Box<forge_workspace::PublishedVerificationInput>>,
        response: Response<ExecutionId>,
    },
    Cancel {
        id: ExecutionId,
        response: Response<bool>,
    },
    CancelWorkspace {
        workspace_id: WorkspaceId,
        response: Response<usize>,
    },
    StopAll {
        response: Response<usize>,
    },
    PeekTerminalEvents {
        maximum: usize,
        response: Response<Vec<ExecutionSupervisorEvent>>,
    },
    ObserveTerminalEvent {
        key: TerminalEventKey,
        identity: SupervisorStartIdentity,
        response: Response<Option<ExecutionSupervisorEvent>>,
    },
    ObserveNativeClosure {
        event: Box<ExecutionSupervisorEvent>,
        response: Response<Option<NativeExecutionClosure>>,
    },
    AcknowledgeTerminalEvent {
        key: TerminalEventKey,
        identity: SupervisorStartIdentity,
        response: Response<bool>,
    },
    ReadOutputEvents {
        maximum: usize,
        response: Response<ExecutionOutputRead>,
    },
    ObserveStart {
        identity: Box<SupervisorStartIdentity>,
        response: Response<Option<SupervisorStartReceipt>>,
    },
    AcknowledgeStart {
        identity: Box<SupervisorStartIdentity>,
        response: Response<bool>,
    },
    AckOutputEvents {
        key: ExecutionOutputEventKey,
        response: Response<usize>,
    },
    HasPendingOutput {
        id: ExecutionId,
        response: Response<bool>,
    },
    Shutdown {
        response: SyncSender<ExecutionSupervisorShutdown>,
    },
}

/// Opaque identity for one terminal event retained by one supervisor owner.
///
/// Keys are deliberately non-serializable capability values. They are valid
/// only when sent back through the same live supervisor owner that created
/// them. The generation is redacted from diagnostics so a key remains a
/// bounded handoff token rather than a durable identity.
#[must_use]
#[derive(Clone, PartialEq, Eq)]
pub struct TerminalEventKey {
    owner: SupervisorOwnerToken,
    execution_id: ExecutionId,
    generation: u64,
}

impl std::fmt::Debug for TerminalEventKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TerminalEventKey")
            .field("execution_id", &self.execution_id)
            .field("generation", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl TerminalEventKey {
    fn new(owner: SupervisorOwnerToken, execution_id: ExecutionId, generation: u64) -> Self {
        Self {
            owner,
            execution_id,
            generation,
        }
    }

    fn has_owner(&self, owner: &SupervisorOwnerToken) -> bool {
        self.owner.same_owner(owner)
    }
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionSupervisorEvent {
    identity: SupervisorStartIdentity,
    key: TerminalEventKey,
    workspace_id: WorkspaceId,
    execution_id: ExecutionId,
    result: Result<ExecutionOutcome, ExecutionFailureCode>,
    generated_package: Option<GeneratedPackageManifest>,
}

impl ExecutionSupervisorEvent {
    pub const fn identity(&self) -> SupervisorStartIdentity {
        self.identity
    }

    pub fn key(&self) -> TerminalEventKey {
        self.key.clone()
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn execution_id(&self) -> ExecutionId {
        self.execution_id
    }

    pub const fn result(&self) -> &Result<ExecutionOutcome, ExecutionFailureCode> {
        &self.result
    }

    pub fn into_result(self) -> Result<ExecutionOutcome, ExecutionFailureCode> {
        self.result
    }

    pub const fn generated_package(&self) -> Option<GeneratedPackageManifest> {
        self.generated_package
    }

    pub fn into_parts(
        self,
    ) -> (
        Result<ExecutionOutcome, ExecutionFailureCode>,
        Option<GeneratedPackageManifest>,
    ) {
        (self.result, self.generated_package)
    }

    fn has_owner(&self, owner: &SupervisorOwnerToken) -> bool {
        self.key.has_owner(owner)
    }
}

#[must_use]
#[derive(Debug)]
pub struct ExecutionSupervisorShutdown {
    active_cancelled: usize,
    events: Vec<ExecutionSupervisorEvent>,
    output_events: Vec<ExecutionOutputEvent>,
}

impl ExecutionSupervisorShutdown {
    pub const fn active_cancelled(&self) -> usize {
        self.active_cancelled
    }

    pub fn events(&self) -> &[ExecutionSupervisorEvent] {
        &self.events
    }

    pub fn output_events(&self) -> &[ExecutionOutputEvent] {
        &self.output_events
    }
}

#[derive(Debug, Clone)]
pub struct ExecutionSupervisorClient {
    sender: SyncSender<SupervisorRequest>,
    accepting: Arc<AtomicBool>,
}

impl ExecutionSupervisorClient {
    /// Observe this owner's empty Workspace lifecycle under the caller's fence.
    pub fn observe_workspace_quiescence(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<Option<NativeWorkspaceQuiescence>, ExecutionSupervisorError> {
        if workspace_id.into_uuid().is_nil() {
            return Err(ExecutionSupervisorError::InvalidWorkspaceIdentity);
        }
        self.submit(|response| SupervisorRequest::ObserveWorkspaceQuiescence {
            workspace_id,
            response,
        })
    }

    /// Check only allocation ownership; this does not refresh a stale observation.
    pub fn owns_workspace_quiescence(&self, proof: &NativeWorkspaceQuiescence) -> bool {
        self.accepting.load(Ordering::Acquire)
            && proof.has_owner(&SupervisorOwnerToken::new(Arc::clone(&self.accepting)))
    }

    /// Observe one exact retained Baseline rejection that happened before any
    /// runner preparation. The receipt remains pending until its normal Start
    /// acknowledgement, so a dropped reply is retried with the same identity.
    pub fn observe_native_rejection(
        &self,
        identity: &SupervisorStartIdentity,
    ) -> Result<Option<NativePreSpawnRejection>, ExecutionSupervisorError> {
        self.submit(|response| SupervisorRequest::ObserveNativeRejection {
            identity: Box::new(*identity),
            response,
        })
    }

    /// Check only allocation ownership; this does not refresh a stale proof.
    pub fn owns_native_rejection(&self, proof: &NativePreSpawnRejection) -> bool {
        self.accepting.load(Ordering::Acquire)
            && proof.has_owner(&SupervisorOwnerToken::new(Arc::clone(&self.accepting)))
    }

    pub fn start_execution(
        &self,
        layout: ExistingWorkspaceStateLayout,
        request: ExecutionRequest,
    ) -> Result<ExecutionId, ExecutionSupervisorError> {
        let identity = SupervisorStartIdentity::capture(
            &layout,
            &request,
            ExecutionLaunchKind::Baseline,
            None,
        )?;
        self.start_execution_with_identity(
            identity,
            layout,
            request,
            ExecutionLaunchKind::Baseline,
            None,
            None,
        )
    }

    /// Start an execution with an explicit launch policy. Rust CI starts
    /// require the discovered capability and one healthy process lifecycle per
    /// Workspace; an uncertain lifecycle quarantines that Workspace until the
    /// supervisor is restarted.
    pub fn start_execution_with_launch_kind(
        &self,
        layout: ExistingWorkspaceStateLayout,
        request: ExecutionRequest,
        launch_kind: ExecutionLaunchKind,
        rust_ci_capability: Option<RustCiToolchainCapability>,
    ) -> Result<ExecutionId, ExecutionSupervisorError> {
        let identity = SupervisorStartIdentity::capture(&layout, &request, launch_kind, None)?;
        self.start_execution_with_identity(
            identity,
            layout,
            request,
            launch_kind,
            rust_ci_capability,
            None,
        )
    }

    /// Submit a Start with the exact identity captured by the trusted caller.
    /// The identity is validated again by the native owner before any runner
    /// admission or process effect.
    pub fn start_execution_with_identity(
        &self,
        identity: SupervisorStartIdentity,
        layout: ExistingWorkspaceStateLayout,
        request: ExecutionRequest,
        launch_kind: ExecutionLaunchKind,
        rust_ci_capability: Option<RustCiToolchainCapability>,
        verification_input: Option<forge_workspace::PublishedVerificationInput>,
    ) -> Result<ExecutionId, ExecutionSupervisorError> {
        if launch_kind == ExecutionLaunchKind::Baseline && verification_input.is_some() {
            return Err(ExecutionError::VerificationInputMismatch.into());
        }
        identity.validate_semantic_against(&request, launch_kind, verification_input.as_ref())?;
        self.submit(|response| SupervisorRequest::Start {
            identity: Box::new(identity),
            layout,
            request: Box::new(request),
            launch_kind,
            rust_ci_capability: rust_ci_capability.map(Box::new),
            package_verification: false,
            verification_input: verification_input.map(Box::new),
            response,
        })
    }

    /// Start the one server-owned `PackageV` command against a published V1
    /// snapshot. Generic Baseline callers cannot pass a verification input;
    /// this dedicated seam revalidates the current executable and exact argv
    /// before the request crosses the native owner boundary.
    pub fn start_package_verification_with_identity(
        &self,
        identity: SupervisorStartIdentity,
        layout: ExistingWorkspaceStateLayout,
        request: ExecutionRequest,
        input: forge_workspace::PublishedVerificationInput,
    ) -> Result<ExecutionId, ExecutionSupervisorError> {
        if identity.launch_kind() != ExecutionLaunchKind::Baseline {
            return Err(ExecutionError::VerificationInputMismatch.into());
        }
        let capability = PackageVExecutableCapability::prepare_current()
            .map_err(ExecutionError::PackageVExecutable)?;
        capability
            .revalidate()
            .map_err(ExecutionError::PackageVExecutable)?;
        if !is_exact_package_request(&request, &capability) {
            return Err(ExecutionError::VerificationInputMismatch.into());
        }
        identity.validate_semantic_against(
            &request,
            ExecutionLaunchKind::Baseline,
            Some(&input),
        )?;
        self.submit(|response| SupervisorRequest::Start {
            identity: Box::new(identity),
            layout,
            request: Box::new(request),
            launch_kind: ExecutionLaunchKind::Baseline,
            rust_ci_capability: None,
            package_verification: true,
            verification_input: Some(Box::new(input)),
            response,
        })
    }

    /// Transfer a published input to the same bounded supervisor lifecycle as
    /// ordinary Rust CI. The runner retains it after process completion.
    pub fn start_verification(
        &self,
        layout: ExistingWorkspaceStateLayout,
        request: ExecutionRequest,
        capability: RustCiToolchainCapability,
        input: forge_workspace::PublishedVerificationInput,
    ) -> Result<ExecutionId, ExecutionSupervisorError> {
        self.start_verification_with_launch_kind(
            layout,
            request,
            ExecutionLaunchKind::RustCi,
            capability,
            input,
        )
    }

    pub fn start_verification_with_launch_kind(
        &self,
        layout: ExistingWorkspaceStateLayout,
        request: ExecutionRequest,
        launch_kind: ExecutionLaunchKind,
        capability: RustCiToolchainCapability,
        input: forge_workspace::PublishedVerificationInput,
    ) -> Result<ExecutionId, ExecutionSupervisorError> {
        if launch_kind == ExecutionLaunchKind::Baseline {
            return Err(ExecutionError::VerificationInputMismatch.into());
        }
        let identity =
            SupervisorStartIdentity::capture(&layout, &request, launch_kind, Some(&input))?;
        self.start_execution_with_identity(
            identity,
            layout,
            request,
            launch_kind,
            Some(capability),
            Some(input),
        )
    }

    pub fn observe_start(
        &self,
        identity: &SupervisorStartIdentity,
    ) -> Result<Option<SupervisorStartReceipt>, ExecutionSupervisorError> {
        self.submit(|response| SupervisorRequest::ObserveStart {
            identity: Box::new(*identity),
            response,
        })
    }

    /// Release one exact receipt after its owner has taken responsibility for
    /// the accepted or rejected Start outcome.  `false` means the receipt was
    /// already released or is unavailable; it never proves non-admission.
    pub fn acknowledge_start(
        &self,
        identity: &SupervisorStartIdentity,
    ) -> Result<bool, ExecutionSupervisorError> {
        self.submit(|response| SupervisorRequest::AcknowledgeStart {
            identity: Box::new(*identity),
            response,
        })
    }

    pub fn cancel_execution(&self, id: ExecutionId) -> Result<bool, ExecutionSupervisorError> {
        self.submit(|response| SupervisorRequest::Cancel { id, response })
    }

    pub fn cancel_workspace(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<usize, ExecutionSupervisorError> {
        self.submit(|response| SupervisorRequest::CancelWorkspace {
            workspace_id,
            response,
        })
    }

    /// Cancel every active process group and wait until each owned handle has
    /// reported terminal cleanup. New starts are rejected while draining.
    pub fn stop_all(&self) -> Result<usize, ExecutionSupervisorError> {
        self.submit(|response| SupervisorRequest::StopAll { response })
    }

    pub fn peek_terminal_events(
        &self,
        maximum: usize,
    ) -> Result<Vec<ExecutionSupervisorEvent>, ExecutionSupervisorError> {
        if maximum == 0 || maximum > MAX_COMPLETION_BACKLOG {
            return Err(ExecutionSupervisorError::InvalidTerminalEventLimit {
                actual: maximum,
                maximum: MAX_COMPLETION_BACKLOG,
            });
        }
        self.submit(|response| SupervisorRequest::PeekTerminalEvents { maximum, response })
    }

    pub fn observe_terminal_event(
        &self,
        key: &TerminalEventKey,
        identity: &SupervisorStartIdentity,
    ) -> Result<Option<ExecutionSupervisorEvent>, ExecutionSupervisorError> {
        self.submit(|response| SupervisorRequest::ObserveTerminalEvent {
            key: key.clone(),
            identity: *identity,
            response,
        })
    }

    /// Observe a stronger native closure proof without changing terminal-event
    /// acknowledgement. The event remains retained until the existing ACK.
    pub fn observe_native_closure(
        &self,
        event: &ExecutionSupervisorEvent,
    ) -> Result<Option<NativeExecutionClosure>, ExecutionSupervisorError> {
        self.submit(|response| SupervisorRequest::ObserveNativeClosure {
            event: Box::new(event.clone()),
            response,
        })
    }

    pub fn acknowledge_terminal_event(
        &self,
        key: &TerminalEventKey,
        identity: &SupervisorStartIdentity,
    ) -> Result<bool, ExecutionSupervisorError> {
        self.submit(|response| SupervisorRequest::AcknowledgeTerminalEvent {
            key: key.clone(),
            identity: *identity,
            response,
        })
    }

    pub fn read_output_events(
        &self,
        maximum: usize,
    ) -> Result<ExecutionOutputRead, ExecutionSupervisorError> {
        if maximum == 0 || maximum > MAX_OUTPUT_EVENT_BACKLOG {
            return Err(ExecutionSupervisorError::InvalidOutputDrainLimit {
                actual: maximum,
                maximum: MAX_OUTPUT_EVENT_BACKLOG,
            });
        }
        self.submit(|response| SupervisorRequest::ReadOutputEvents { maximum, response })
    }

    pub fn ack_output_events(
        &self,
        key: ExecutionOutputEventKey,
    ) -> Result<usize, ExecutionSupervisorError> {
        self.submit(|response| SupervisorRequest::AckOutputEvents { key, response })
    }

    /// Return whether output for an execution is still retained by the
    /// supervisor or by its owned runner handle.
    pub fn has_pending_output(&self, id: ExecutionId) -> Result<bool, ExecutionSupervisorError> {
        self.submit(|response| SupervisorRequest::HasPendingOutput { id, response })
    }

    fn submit<T>(
        &self,
        build: impl FnOnce(Response<T>) -> SupervisorRequest,
    ) -> Result<T, ExecutionSupervisorError> {
        if !self.accepting.load(Ordering::Acquire) {
            return Err(ExecutionSupervisorError::Closed);
        }
        let (response_sender, response_receiver) = mpsc::sync_channel(0);
        match self.sender.try_send(build(response_sender)) {
            Ok(()) => response_receiver
                .recv()
                .map_err(|_| ExecutionSupervisorError::ReplyDropped)?,
            Err(TrySendError::Full(_)) => Err(ExecutionSupervisorError::QueueFull),
            Err(TrySendError::Disconnected(_)) => Err(ExecutionSupervisorError::Closed),
        }
    }
}

#[derive(Debug)]
pub struct ExecutionSupervisor {
    client: ExecutionSupervisorClient,
    thread: Option<JoinHandle<()>>,
}

impl ExecutionSupervisor {
    pub fn start(maximum: usize) -> Result<Self, ExecutionSupervisorError> {
        let runner = ExecutionRunner::new(maximum)?;
        let (sender, receiver) = mpsc::sync_channel(SUPERVISOR_QUEUE_CAPACITY);
        let accepting = Arc::new(AtomicBool::new(true));
        let runtime_accepting = Arc::clone(&accepting);
        let thread = thread::Builder::new()
            .name(THREAD_NAME.to_owned())
            .spawn(move || SupervisorRuntime::new(runner, receiver, runtime_accepting).run())
            .map_err(ExecutionSupervisorError::SpawnThread)?;
        Ok(Self {
            client: ExecutionSupervisorClient { sender, accepting },
            thread: Some(thread),
        })
    }

    pub fn client(&self) -> ExecutionSupervisorClient {
        self.client.clone()
    }

    pub fn shutdown(&mut self) -> Result<ExecutionSupervisorShutdown, ExecutionSupervisorError> {
        self.client.accepting.store(false, Ordering::Release);
        let Some(thread) = self.thread.take() else {
            return Err(ExecutionSupervisorError::AlreadyShutdown);
        };
        let (response_sender, response_receiver) = mpsc::sync_channel(0);
        if self
            .client
            .sender
            .send(SupervisorRequest::Shutdown {
                response: response_sender,
            })
            .is_err()
        {
            return match thread.join() {
                Ok(()) => Err(ExecutionSupervisorError::Closed),
                Err(_) => Err(ExecutionSupervisorError::ThreadPanicked),
            };
        }
        let report = response_receiver.recv();
        let joined = thread.join();
        if joined.is_err() {
            return Err(ExecutionSupervisorError::ThreadPanicked);
        }
        report.map_err(|_| ExecutionSupervisorError::Closed)
    }
}

impl Drop for ExecutionSupervisor {
    fn drop(&mut self) {
        if self.thread.is_some() {
            let _ignored = self.shutdown();
        }
    }
}

struct ActiveExecution {
    identity: SupervisorStartIdentity,
    terminal_key: TerminalEventKey,
    receipt_pending: bool,
    workspace_id: WorkspaceId,
    handle: RunningExecution,
    terminal: bool,
    terminal_event_acknowledged: bool,
    launch_kind: ExecutionLaunchKind,
}

struct StopWaiter {
    cancelled: usize,
    response: Response<usize>,
}

#[derive(Debug)]
struct PendingOutputRead {
    keys: Vec<ExecutionOutputEventKey>,
    ack_key: ExecutionOutputEventKey,
}

struct SupervisorRuntime {
    runner: ExecutionRunner,
    receiver: Receiver<SupervisorRequest>,
    accepting: Arc<AtomicBool>,
    owner: SupervisorOwnerToken,
    active: HashMap<ExecutionId, ActiveExecution>,
    start_receipts: HashMap<ExecutionId, SupervisorStartReceipt>,
    active_rust_ci_workspaces: HashSet<WorkspaceId>,
    quarantined_rust_ci_workspaces: HashSet<WorkspaceId>,
    rust_ci_quarantine_saturated: bool,
    next_terminal_generation: u64,
    events: VecDeque<ExecutionSupervisorEvent>,
    output_events: VecDeque<ExecutionOutputEvent>,
    output_poll_cursor: Option<ExecutionId>,
    pending_output_read: Option<PendingOutputRead>,
    stop_waiters: Vec<StopWaiter>,
    shutdown: Option<(usize, Option<SyncSender<ExecutionSupervisorShutdown>>)>,
}

impl SupervisorRuntime {
    fn new(
        runner: ExecutionRunner,
        receiver: Receiver<SupervisorRequest>,
        accepting: Arc<AtomicBool>,
    ) -> Self {
        let owner = SupervisorOwnerToken::new(Arc::clone(&accepting));
        Self {
            runner,
            receiver,
            accepting,
            owner,
            active: HashMap::new(),
            start_receipts: HashMap::new(),
            active_rust_ci_workspaces: HashSet::new(),
            quarantined_rust_ci_workspaces: HashSet::new(),
            rust_ci_quarantine_saturated: false,
            next_terminal_generation: 0,
            events: VecDeque::new(),
            output_events: VecDeque::new(),
            output_poll_cursor: None,
            pending_output_read: None,
            stop_waiters: Vec::new(),
            shutdown: None,
        }
    }

    fn run(mut self) {
        loop {
            self.poll_completions();
            self.finish_drains();
            if self.shutdown.is_some() && !self.has_live_processes() {
                self.finish_shutdown();
                break;
            }
            match self.receive_request() {
                SupervisorReceive::Request(request) => self.handle_request(*request),
                SupervisorReceive::Timeout => {}
                SupervisorReceive::Disconnected => {
                    self.accepting.store(false, Ordering::Release);
                    self.begin_shutdown(None);
                }
            }
        }
        self.accepting.store(false, Ordering::Release);
    }

    fn receive_request(&self) -> SupervisorReceive {
        match self.receive_policy() {
            SupervisorReceivePolicy::BlockUntilRequest => self
                .receiver
                .recv()
                .map_or(SupervisorReceive::Disconnected, |request| {
                    SupervisorReceive::Request(Box::new(request))
                }),
            SupervisorReceivePolicy::Poll(interval) => match self.receiver.recv_timeout(interval) {
                Ok(request) => SupervisorReceive::Request(Box::new(request)),
                Err(RecvTimeoutError::Timeout) => SupervisorReceive::Timeout,
                Err(RecvTimeoutError::Disconnected) => SupervisorReceive::Disconnected,
            },
        }
    }

    fn receive_policy(&self) -> SupervisorReceivePolicy {
        supervisor_receive_policy(!self.active.is_empty(), self.shutdown.is_some())
    }

    fn handle_request(&mut self, request: SupervisorRequest) {
        match request {
            SupervisorRequest::ObserveWorkspaceQuiescence {
                workspace_id,
                response,
            } => {
                let proof = self.observe_workspace_quiescence(workspace_id);
                let _ignored = response.send(Ok(proof));
            }
            SupervisorRequest::ObserveNativeRejection { identity, response } => {
                let proof = self.observe_native_rejection(*identity);
                let _ignored = response.send(proof);
            }
            SupervisorRequest::Start {
                identity,
                layout,
                request,
                launch_kind,
                rust_ci_capability,
                package_verification,
                verification_input,
                response,
            } => {
                let result = self.start_execution(
                    &layout,
                    *identity,
                    *request,
                    launch_kind,
                    rust_ci_capability.as_deref(),
                    package_verification,
                    verification_input.map(|input| *input),
                );
                let _ignored = response.send(result);
            }
            SupervisorRequest::ObserveStart { identity, response } => {
                let result = self.observe_start(*identity);
                let _ignored = response.send(result);
            }
            SupervisorRequest::AcknowledgeStart { identity, response } => {
                let result = self.acknowledge_start(*identity);
                let _ignored = response.send(result);
            }
            SupervisorRequest::Cancel { id, response } => {
                let result = self.cancel_one(id);
                let _ignored = response.send(result);
            }
            SupervisorRequest::CancelWorkspace {
                workspace_id,
                response,
            } => {
                let result = self.cancel_matching(|active| active.workspace_id == workspace_id);
                let _ignored = response.send(result);
            }
            SupervisorRequest::StopAll { response } => {
                let cancelled = self.cancel_matching(|_| true).unwrap_or(0);
                self.stop_waiters.push(StopWaiter {
                    cancelled,
                    response,
                });
                self.finish_drains();
            }
            SupervisorRequest::PeekTerminalEvents { maximum, response } => {
                let events = self.events.iter().take(maximum).cloned().collect();
                let _ignored = response.send(Ok(events));
            }
            SupervisorRequest::ObserveTerminalEvent {
                key,
                identity,
                response,
            } => {
                let event = self.observe_terminal_event(&key, identity);
                let _ignored = response.send(event);
            }
            SupervisorRequest::ObserveNativeClosure { event, response } => {
                let closure = self.observe_native_closure(*event);
                let _ignored = response.send(closure);
            }
            SupervisorRequest::AcknowledgeTerminalEvent {
                key,
                identity,
                response,
            } => {
                let acknowledged = self.acknowledge_terminal_event(&key, identity);
                let _ignored = response.send(acknowledged);
            }
            SupervisorRequest::ReadOutputEvents { maximum, response } => {
                let result = self.read_output_events(maximum);
                let _ignored = response.send(Ok(result));
            }
            SupervisorRequest::AckOutputEvents { key, response } => {
                let result = self.ack_output_events(key);
                let _ignored = response.send(result);
            }
            SupervisorRequest::HasPendingOutput { id, response } => {
                let _ignored = response.send(Ok(self.has_pending_output(id)));
            }
            SupervisorRequest::Shutdown { response } => {
                self.accepting.store(false, Ordering::Release);
                self.begin_shutdown(Some(response));
            }
        }
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn start_execution(
        &mut self,
        layout: &ExistingWorkspaceStateLayout,
        identity: SupervisorStartIdentity,
        request: ExecutionRequest,
        launch_kind: ExecutionLaunchKind,
        rust_ci_capability: Option<&RustCiToolchainCapability>,
        package_verification: bool,
        verification_input: Option<forge_workspace::PublishedVerificationInput>,
    ) -> Result<ExecutionId, ExecutionSupervisorError> {
        if package_verification {
            let Some(input) = verification_input.as_ref() else {
                return Err(ExecutionError::VerificationInputMismatch.into());
            };
            let capability = PackageVExecutableCapability::prepare_current()
                .map_err(ExecutionError::PackageVExecutable)?;
            capability
                .revalidate()
                .map_err(ExecutionError::PackageVExecutable)?;
            if launch_kind != ExecutionLaunchKind::Baseline
                || !is_exact_package_request(&request, &capability)
            {
                return Err(ExecutionError::VerificationInputMismatch.into());
            }
            input
                .validate()
                .map_err(ExecutionError::VerificationInput)?;
        }
        identity.validate_semantic_against(&request, launch_kind, verification_input.as_ref())?;
        let id = identity.execution_id();
        if let Some(receipt) = self.start_receipts.get(&id) {
            return converge_start_receipt(identity, *receipt);
        }
        if let Some(active_identity) = self.active.get(&id).map(|active| active.identity) {
            if active_identity == identity {
                if let Some(active) = self.active.get_mut(&id) {
                    active.receipt_pending = true;
                }
                return Ok(id);
            }
            return Err(ExecutionSupervisorError::StartIdentityMismatch { id });
        }
        if self.start_receipts.len() >= MAX_START_RECEIPTS {
            return Err(ExecutionSupervisorError::StartReceiptCapacity);
        }
        if let Some((error, phase)) = self.pre_runner_rejection(layout, identity) {
            return self.reject_pre_spawn_baseline(identity, error, phase);
        }
        let workspace_id = request.workspace_id();
        if launch_uses_rust_ci(launch_kind)
            && let Err(error) = self.ensure_rust_ci_workspace_available(workspace_id)
        {
            return self.reject_start(identity, error);
        }
        let terminal_key = match self.allocate_terminal_key(id) {
            Ok(key) => key,
            Err(error) => {
                return self.reject_pre_spawn_baseline(
                    identity,
                    error,
                    PreSpawnRejectionPhase::TerminalGenerationExhaustion,
                );
            }
        };
        let handle_result = match verification_input {
            Some(input) => {
                if package_verification {
                    self.runner
                        .spawn_package_verification(layout, request, input)
                } else {
                    let Some(capability) = rust_ci_capability else {
                        return self.reject_start(
                            identity,
                            ExecutionError::RustCiCapabilityRequired.into(),
                        );
                    };
                    self.runner.spawn_verification_with_launch_kind(
                        layout,
                        request,
                        launch_kind,
                        capability,
                        input,
                    )
                }
            }
            None => {
                self.runner
                    .spawn_with_launch_kind(layout, request, launch_kind, rust_ci_capability)
            }
        };
        let handle = match self.finish_spawn_admission(workspace_id, launch_kind, handle_result) {
            Ok(handle) => handle,
            Err(error) => return self.reject_start(identity, error),
        };
        self.active.insert(
            id,
            ActiveExecution {
                identity,
                terminal_key,
                receipt_pending: false,
                workspace_id,
                handle,
                terminal: false,
                terminal_event_acknowledged: false,
                launch_kind,
            },
        );
        if launch_uses_rust_ci(launch_kind) {
            self.active_rust_ci_workspaces.insert(workspace_id);
        }
        let _previous = self
            .start_receipts
            .insert(id, SupervisorStartReceipt::accepted(identity));
        Ok(id)
    }

    fn pre_runner_rejection(
        &self,
        layout: &ExistingWorkspaceStateLayout,
        identity: SupervisorStartIdentity,
    ) -> Option<(ExecutionSupervisorError, PreSpawnRejectionPhase)> {
        if let Err(error) = identity.validate_root_against(layout) {
            return Some((error, PreSpawnRejectionPhase::RootValidation));
        }
        if self.shutdown.is_some() || !self.stop_waiters.is_empty() {
            return Some((
                ExecutionSupervisorError::Draining,
                PreSpawnRejectionPhase::Draining,
            ));
        }
        let backlog = completion_backlog_count(
            self.active.len(),
            self.events
                .iter()
                .map(ExecutionSupervisorEvent::execution_id),
            |id| self.active.contains_key(&id),
        );
        if backlog >= MAX_COMPLETION_BACKLOG {
            return Some((
                ExecutionSupervisorError::CompletionBacklog,
                PreSpawnRejectionPhase::CompletionBacklog,
            ));
        }
        None
    }

    fn allocate_terminal_key(
        &mut self,
        execution_id: ExecutionId,
    ) -> Result<TerminalEventKey, ExecutionSupervisorError> {
        let generation = self
            .next_terminal_generation
            .checked_add(1)
            .ok_or(ExecutionSupervisorError::TerminalEventGenerationExhausted { execution_id })?;
        self.next_terminal_generation = generation;
        Ok(TerminalEventKey::new(
            self.owner.clone(),
            execution_id,
            generation,
        ))
    }

    fn reject_start(
        &mut self,
        identity: SupervisorStartIdentity,
        error: ExecutionSupervisorError,
    ) -> Result<ExecutionId, ExecutionSupervisorError> {
        self.reject_start_with_phase(identity, error, None)
    }

    fn reject_pre_spawn_baseline(
        &mut self,
        identity: SupervisorStartIdentity,
        error: ExecutionSupervisorError,
        phase: PreSpawnRejectionPhase,
    ) -> Result<ExecutionId, ExecutionSupervisorError> {
        if identity.launch_kind() == ExecutionLaunchKind::Baseline {
            self.reject_start_with_phase(identity, error, Some(phase))
        } else {
            self.reject_start(identity, error)
        }
    }

    fn reject_start_with_phase(
        &mut self,
        identity: SupervisorStartIdentity,
        error: ExecutionSupervisorError,
        pre_spawn_rejection: Option<PreSpawnRejectionPhase>,
    ) -> Result<ExecutionId, ExecutionSupervisorError> {
        let failure_code = start_failure_code(&error);
        let _previous = self.start_receipts.insert(
            identity.execution_id(),
            SupervisorStartReceipt::rejected(identity, failure_code, pre_spawn_rejection),
        );
        Err(error)
    }

    fn observe_start(
        &self,
        identity: SupervisorStartIdentity,
    ) -> Result<Option<SupervisorStartReceipt>, ExecutionSupervisorError> {
        if let Some(receipt) = self.start_receipts.get(&identity.execution_id()) {
            if receipt.identity() != identity {
                return Err(ExecutionSupervisorError::StartIdentityMismatch {
                    id: identity.execution_id(),
                });
            }
            return Ok(Some(*receipt));
        }
        let Some(active) = self.active.get(&identity.execution_id()) else {
            return Ok(None);
        };
        if active.identity != identity {
            return Err(ExecutionSupervisorError::StartIdentityMismatch {
                id: identity.execution_id(),
            });
        }
        if active.receipt_pending {
            return Ok(Some(SupervisorStartReceipt::accepted(identity)));
        }
        Ok(None)
    }

    fn observe_native_rejection(
        &self,
        identity: SupervisorStartIdentity,
    ) -> Result<Option<NativePreSpawnRejection>, ExecutionSupervisorError> {
        let Some(receipt) = self.start_receipts.get(&identity.execution_id()) else {
            return Ok(None);
        };
        if receipt.identity() != identity {
            return Err(ExecutionSupervisorError::StartIdentityMismatch {
                id: identity.execution_id(),
            });
        }
        if identity.launch_kind() != ExecutionLaunchKind::Baseline
            || receipt.pre_spawn_rejection.is_none()
            || self.active.contains_key(&identity.execution_id())
        {
            return Ok(None);
        }
        let SupervisorStartOutcome::Rejected { failure_code } = receipt.outcome() else {
            return Ok(None);
        };
        Ok(Some(NativePreSpawnRejection::new(
            identity,
            failure_code,
            self.owner.clone(),
        )))
    }

    fn acknowledge_start(
        &mut self,
        identity: SupervisorStartIdentity,
    ) -> Result<bool, ExecutionSupervisorError> {
        if let Some(receipt) = self.start_receipts.get(&identity.execution_id()).copied() {
            if receipt.identity() != identity {
                return Err(ExecutionSupervisorError::StartIdentityMismatch {
                    id: identity.execution_id(),
                });
            }
            let _removed = self.start_receipts.remove(&identity.execution_id());
            return Ok(true);
        }
        let Some(active) = self.active.get_mut(&identity.execution_id()) else {
            return Ok(false);
        };
        if active.identity != identity {
            return Err(ExecutionSupervisorError::StartIdentityMismatch {
                id: identity.execution_id(),
            });
        }
        if !active.receipt_pending {
            return Ok(false);
        }
        active.receipt_pending = false;
        Ok(true)
    }

    fn finish_spawn_admission(
        &mut self,
        workspace_id: WorkspaceId,
        launch_kind: ExecutionLaunchKind,
        result: Result<RunningExecution, ExecutionError>,
    ) -> Result<RunningExecution, ExecutionSupervisorError> {
        match result {
            Ok(handle) => Ok(handle),
            Err(error) => {
                // Preparation can fail after creating owned runtime files.
                // A failed cleanup has no RunningExecution finalization event;
                // fence the Workspace here instead of losing that evidence.
                if launch_uses_rust_ci(launch_kind)
                    && matches!(&error, ExecutionError::RustCiCleanup(_))
                {
                    let _ignored = self.quarantine_rust_ci_workspace(workspace_id);
                }
                Err(error.into())
            }
        }
    }

    fn ensure_rust_ci_workspace_available(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<(), ExecutionSupervisorError> {
        if self.rust_ci_quarantine_saturated
            || self.quarantined_rust_ci_workspaces.contains(&workspace_id)
            || self.active_rust_ci_workspaces.contains(&workspace_id)
        {
            return Err(ExecutionSupervisorError::RustCiWorkspaceCapacity(
                workspace_id,
            ));
        }
        Ok(())
    }

    fn quarantine_rust_ci_workspace(
        &mut self,
        workspace_id: WorkspaceId,
    ) -> Result<(), ExecutionSupervisorError> {
        if self.quarantined_rust_ci_workspaces.contains(&workspace_id) {
            return Ok(());
        }
        if self.rust_ci_quarantine_saturated
            || self.quarantined_rust_ci_workspaces.len() >= MAX_RUST_CI_QUARANTINE
        {
            self.rust_ci_quarantine_saturated = true;
            return Err(ExecutionSupervisorError::RustCiWorkspaceCapacity(
                workspace_id,
            ));
        }
        self.quarantined_rust_ci_workspaces.insert(workspace_id);
        Ok(())
    }

    fn finalize_rust_ci_workspace(
        &mut self,
        workspace_id: WorkspaceId,
        process_finalization: Option<ProcessFinalization>,
        runtime_finalization: Option<RustCiRuntimeFinalization>,
    ) {
        self.active_rust_ci_workspaces.remove(&workspace_id);
        if rust_ci_completion_requires_quarantine(process_finalization, runtime_finalization) {
            let _ignored = self.quarantine_rust_ci_workspace(workspace_id);
        }
    }

    fn read_output_events(&mut self, maximum: usize) -> ExecutionOutputRead {
        if let Some(pending) = &self.pending_output_read {
            let events: Vec<_> = self
                .output_events
                .iter()
                .take(pending.keys.len())
                .cloned()
                .collect();
            return ExecutionOutputRead::new(events);
        }
        self.poll_output_events();
        let events: Vec<_> = self.output_events.iter().take(maximum).cloned().collect();
        let Some(ack_key) = events.last().map(ExecutionOutputEvent::key) else {
            return ExecutionOutputRead::empty();
        };
        self.pending_output_read = Some(PendingOutputRead {
            keys: events.iter().map(ExecutionOutputEvent::key).collect(),
            ack_key,
        });
        ExecutionOutputRead::new(events)
    }

    fn ack_output_events(
        &mut self,
        key: ExecutionOutputEventKey,
    ) -> Result<usize, ExecutionSupervisorError> {
        let Some(pending) = &self.pending_output_read else {
            return Err(ExecutionSupervisorError::OutputAckWithoutRead);
        };
        if pending.ack_key != key {
            return Err(ExecutionSupervisorError::OutputAckMismatch {
                expected: pending.ack_key,
                actual: key,
            });
        }
        for (index, expected_key) in pending.keys.iter().enumerate() {
            let Some(actual) = self.output_events.get(index) else {
                return Err(ExecutionSupervisorError::OutputReadInvalidated);
            };
            if actual.key() != *expected_key {
                return Err(ExecutionSupervisorError::OutputReadInvalidated);
            }
        }
        let count = pending.keys.len();
        let _acknowledged: Vec<_> = self.output_events.drain(..count).collect();
        self.pending_output_read = None;
        self.poll_output_events();
        Ok(count)
    }

    fn observe_terminal_event(
        &self,
        key: &TerminalEventKey,
        identity: SupervisorStartIdentity,
    ) -> Result<Option<ExecutionSupervisorEvent>, ExecutionSupervisorError> {
        if !key.has_owner(&self.owner) {
            return Err(ExecutionSupervisorError::TerminalEventOwnerMismatch {
                execution_id: key.execution_id,
            });
        }
        let Some(event) = self.events.iter().find(|event| &event.key == key) else {
            return Ok(None);
        };
        if event.identity != identity {
            return Err(ExecutionSupervisorError::TerminalEventIdentityMismatch {
                execution_id: key.execution_id,
            });
        }
        Ok(Some(event.clone()))
    }

    fn observe_native_closure(
        &self,
        event: ExecutionSupervisorEvent,
    ) -> Result<Option<NativeExecutionClosure>, ExecutionSupervisorError> {
        if !event.has_owner(&self.owner) {
            return Err(ExecutionSupervisorError::NativeClosureOwnerMismatch {
                execution_id: event.execution_id,
            });
        }
        let Some(retained) = self
            .events
            .iter()
            .find(|retained| retained.key == event.key)
        else {
            return Ok(None);
        };
        if retained.identity != event.identity {
            return Err(ExecutionSupervisorError::TerminalEventIdentityMismatch {
                execution_id: event.execution_id,
            });
        }
        if retained != &event {
            return Err(ExecutionSupervisorError::NativeClosureEventMismatch {
                execution_id: event.execution_id,
            });
        }
        let Some(active) = self.active.get(&event.execution_id) else {
            return Ok(None);
        };
        if active.terminal_key != event.key
            || active.identity != event.identity
            || !active.terminal
            || active.terminal_event_acknowledged
        {
            return Ok(None);
        }
        let Some((process, runtime)) = native_closure::dispositions(
            active.handle.process_finalization(),
            active.handle.rust_ci_runtime_finalization(),
            active.launch_kind,
        ) else {
            return Ok(None);
        };
        if active.launch_kind == ExecutionLaunchKind::RustCiGeneratedPackage
            && (event.result.is_err() || event.generated_package.is_none())
        {
            return Ok(None);
        }
        if !active.handle.output_events_complete()
            || self
                .output_events
                .iter()
                .any(|output| output.execution_id() == event.execution_id)
            || self.pending_output_read.as_ref().is_some_and(|pending| {
                pending
                    .keys
                    .iter()
                    .any(|key| key.execution_id() == event.execution_id)
            })
        {
            return Ok(None);
        }
        let Some(output_cursor) = active.handle.sealed_output_cursor() else {
            return Ok(None);
        };
        Ok(Some(NativeExecutionClosure::from_parts(
            event,
            output_cursor,
            process,
            runtime,
        )))
    }

    fn acknowledge_terminal_event(
        &mut self,
        key: &TerminalEventKey,
        identity: SupervisorStartIdentity,
    ) -> Result<bool, ExecutionSupervisorError> {
        if !key.has_owner(&self.owner) {
            return Err(ExecutionSupervisorError::TerminalEventOwnerMismatch {
                execution_id: key.execution_id,
            });
        }
        let Some(index) = self.events.iter().position(|event| &event.key == key) else {
            return Ok(false);
        };
        if self.events[index].identity != identity {
            return Err(ExecutionSupervisorError::TerminalEventIdentityMismatch {
                execution_id: key.execution_id,
            });
        }
        let _removed = self.events.remove(index);
        if let Some(active) = self.active.get_mut(&key.execution_id)
            && &active.terminal_key == key
            && active.identity == identity
        {
            active.terminal_event_acknowledged = true;
        }
        Ok(true)
    }

    fn observe_workspace_quiescence(
        &self,
        workspace_id: WorkspaceId,
    ) -> Option<NativeWorkspaceQuiescence> {
        if self
            .active
            .values()
            .any(|active| active.workspace_id == workspace_id)
            || self
                .events
                .iter()
                .any(|event| event.workspace_id == workspace_id)
            || self
                .start_receipts
                .values()
                .any(|receipt| receipt.identity().workspace_id() == workspace_id)
            || self.active_rust_ci_workspaces.contains(&workspace_id)
            || self.quarantined_rust_ci_workspaces.contains(&workspace_id)
            || self.rust_ci_quarantine_saturated
        {
            return None;
        }
        Some(NativeWorkspaceQuiescence::new(
            workspace_id,
            self.owner.clone(),
        ))
    }

    fn has_pending_output(&self, id: ExecutionId) -> bool {
        self.output_events
            .iter()
            .any(|event| event.execution_id() == id)
            || self
                .active
                .get(&id)
                .is_some_and(|active| !active.handle.output_events_complete())
    }

    fn cancel_one(&mut self, id: ExecutionId) -> Result<bool, ExecutionSupervisorError> {
        let Some(active) = self.active.get(&id) else {
            return Ok(false);
        };
        if active.terminal {
            return Ok(false);
        }
        active.handle.cancel()?;
        Ok(true)
    }

    fn cancel_matching(
        &mut self,
        predicate: impl Fn(&ActiveExecution) -> bool,
    ) -> Result<usize, ExecutionSupervisorError> {
        let mut cancelled = 0;
        for active in self
            .active
            .values()
            .filter(|active| !active.terminal && predicate(active))
        {
            active.handle.cancel()?;
            cancelled += 1;
        }
        Ok(cancelled)
    }

    fn poll_completions(&mut self) {
        self.poll_output_events();
        let ids: Vec<_> = self.active.keys().copied().collect();
        for id in ids {
            let Some(active) = self.active.get_mut(&id) else {
                continue;
            };
            if active.terminal {
                continue;
            }
            let completion = active
                .handle
                .try_wait_completion()
                .map_err(|error| error.failure_code());
            let terminal = match completion {
                Ok(Some(completion)) => Some(Ok(completion)),
                Ok(None) => None,
                Err(failure) => Some(Err(failure)),
            };
            let Some(completion) = terminal else {
                continue;
            };
            let process_finalization = active.handle.process_finalization();
            let runtime_finalization = active.handle.rust_ci_runtime_finalization();
            let identity = active.identity;
            let terminal_key = active.terminal_key.clone();
            let workspace_id = active.workspace_id;
            let launch_kind = active.launch_kind;
            active.terminal = true;
            if launch_uses_rust_ci(launch_kind) {
                self.finalize_rust_ci_workspace(
                    workspace_id,
                    process_finalization,
                    runtime_finalization,
                );
            }
            let (result, generated_package) = match completion {
                Ok(completion) => completion_event_parts(completion),
                Err(failure) => (Err(failure), None),
            };
            if additional_quiescence_uncertainty(
                launch_kind,
                process_finalization,
                result.is_err(),
                generated_package.is_some(),
            ) {
                // The existing bounded quarantine also fences quiescence when
                // process or generated-output cleanup cannot be established.
                let _quarantined = self.quarantine_rust_ci_workspace(workspace_id);
            }
            self.events.push_back(ExecutionSupervisorEvent {
                identity,
                key: terminal_key,
                workspace_id,
                execution_id: id,
                result,
                generated_package,
            });
        }
        self.poll_output_events();
        let completed_ids: Vec<_> = self
            .active
            .iter()
            .filter_map(|(id, active)| {
                (active.terminal
                    && active.terminal_event_acknowledged
                    && active.handle.output_events_complete()
                    && !self.has_pending_output(*id)
                    && !self.pending_output_read.as_ref().is_some_and(|pending| {
                        pending.keys.iter().any(|key| key.execution_id() == *id)
                    })
                    && !active.receipt_pending)
                    .then_some(*id)
            })
            .collect();
        for id in completed_ids {
            if let Some(active) = self.active.get(&id)
                && active.handle.sealed_output_cursor().is_none()
            {
                let workspace_id = active.workspace_id;
                let _quarantined = self.quarantine_rust_ci_workspace(workspace_id);
            }
            let _removed = self.active.remove(&id);
        }
    }

    fn finish_drains(&mut self) {
        if self.has_live_processes() {
            return;
        }
        for waiter in self.stop_waiters.drain(..) {
            let _ignored = waiter.response.send(Ok(waiter.cancelled));
        }
    }

    fn begin_shutdown(&mut self, response: Option<SyncSender<ExecutionSupervisorShutdown>>) {
        if self.shutdown.is_some() {
            return;
        }
        let cancelled = self.cancel_matching(|_| true).unwrap_or(0);
        self.shutdown = Some((cancelled, response));
    }

    fn finish_shutdown(&mut self) {
        let Some((active_cancelled, response)) = self.shutdown.take() else {
            return;
        };
        self.poll_output_events();
        let mut output_events: Vec<_> = self.output_events.drain(..).collect();
        for active in self.active.values_mut() {
            output_events.extend(active.handle.drain_output_events(MAX_OUTPUT_EVENT_BACKLOG));
        }
        self.active.clear();
        self.active_rust_ci_workspaces.clear();
        let report = ExecutionSupervisorShutdown {
            active_cancelled,
            events: self.events.drain(..).collect(),
            output_events,
        };
        if let Some(response) = response {
            let _ignored = response.send(report);
        }
    }

    fn has_live_processes(&self) -> bool {
        self.active.values().any(|active| !active.terminal)
    }

    fn poll_output_events(&mut self) {
        if self.output_events.len() >= MAX_OUTPUT_EVENT_BACKLOG {
            return;
        }
        let mut ids: Vec<_> = self.active.keys().copied().collect();
        ids.sort_unstable();
        if ids.is_empty() {
            return;
        }
        let start = self
            .output_poll_cursor
            .and_then(|cursor| ids.iter().position(|id| *id == cursor))
            .map_or(0, |index| (index + 1) % ids.len());
        for offset in 0..ids.len() {
            let remaining = MAX_OUTPUT_EVENT_BACKLOG.saturating_sub(self.output_events.len());
            if remaining == 0 {
                break;
            }
            let id = ids[(start + offset) % ids.len()];
            let Some(active) = self.active.get_mut(&id) else {
                continue;
            };
            let quantum = remaining.min(OUTPUT_POLL_QUANTUM);
            self.output_events
                .extend(active.handle.drain_output_events(quantum));
            self.output_poll_cursor = Some(id);
        }
    }
}

const fn launch_uses_rust_ci(launch_kind: ExecutionLaunchKind) -> bool {
    matches!(
        launch_kind,
        ExecutionLaunchKind::RustCi | ExecutionLaunchKind::RustCiGeneratedPackage
    )
}

fn converge_start_receipt(
    identity: SupervisorStartIdentity,
    receipt: SupervisorStartReceipt,
) -> Result<ExecutionId, ExecutionSupervisorError> {
    if receipt.identity() != identity {
        return Err(ExecutionSupervisorError::StartIdentityMismatch {
            id: identity.execution_id(),
        });
    }
    match receipt.outcome() {
        SupervisorStartOutcome::Accepted => Ok(identity.execution_id()),
        SupervisorStartOutcome::Rejected { failure_code } => {
            Err(ExecutionSupervisorError::StartRejected { failure_code })
        }
    }
}

fn start_failure_code(error: &ExecutionSupervisorError) -> ExecutionFailureCode {
    match error {
        ExecutionSupervisorError::Execution(error) => error.failure_code(),
        ExecutionSupervisorError::Draining
        | ExecutionSupervisorError::CompletionBacklog
        | ExecutionSupervisorError::DuplicateExecution(_)
        | ExecutionSupervisorError::RustCiWorkspaceCapacity(_)
        | ExecutionSupervisorError::StartReceiptCapacity
        | ExecutionSupervisorError::TerminalEventGenerationExhausted { .. }
        | ExecutionSupervisorError::StartIdentityMismatch { .. } => ExecutionFailureCode::Admission,
        ExecutionSupervisorError::StartRejected { failure_code } => *failure_code,
        _ => ExecutionFailureCode::Supervision,
    }
}

fn completion_event_parts(
    completion: ExecutionCompletionResult,
) -> (
    Result<ExecutionOutcome, ExecutionFailureCode>,
    Option<GeneratedPackageManifest>,
) {
    let generated_package = completion.generated_package();
    (Ok(completion.into_outcome()), generated_package)
}

#[derive(Debug, Error)]
pub enum ExecutionSupervisorError {
    #[error("workspace quiescence requires a non-nil Workspace identity")]
    InvalidWorkspaceIdentity,
    #[error("execution supervisor queue is full")]
    QueueFull,
    #[error("execution supervisor is closed")]
    Closed,
    #[error("execution supervisor reply dropped after admission")]
    ReplyDropped,
    #[error("execution supervisor is draining")]
    Draining,
    #[error("execution completion backlog is full")]
    CompletionBacklog,
    #[error("Execution {0} is already active")]
    DuplicateExecution(ExecutionId),
    #[error("execution supervisor start receipt capacity is full")]
    StartReceiptCapacity,
    #[error("execution {id} start identity does not match the retained owner")]
    StartIdentityMismatch { id: ExecutionId },
    #[error(
        "terminal event identity does not match the retained owner for execution {execution_id}"
    )]
    TerminalEventIdentityMismatch { execution_id: ExecutionId },
    #[error("terminal event key belongs to another supervisor owner for execution {execution_id}")]
    TerminalEventOwnerMismatch { execution_id: ExecutionId },
    #[error("native closure event belongs to another live supervisor for execution {execution_id}")]
    NativeClosureOwnerMismatch { execution_id: ExecutionId },
    #[error(
        "native closure event does not match the retained terminal event for execution {execution_id}"
    )]
    NativeClosureEventMismatch { execution_id: ExecutionId },
    #[error("execution {execution_id} terminal event generation is exhausted")]
    TerminalEventGenerationExhausted { execution_id: ExecutionId },
    #[error("execution start was already rejected with {failure_code:?}")]
    StartRejected { failure_code: ExecutionFailureCode },
    #[error("Rust CI is unavailable for Workspace {0}")]
    RustCiWorkspaceCapacity(WorkspaceId),
    #[error("terminal event peek limit {actual} is outside 1..={maximum}")]
    InvalidTerminalEventLimit { actual: usize, maximum: usize },
    #[error("execution output event drain limit {actual} is outside 1..={maximum}")]
    InvalidOutputDrainLimit { actual: usize, maximum: usize },
    #[error("execution output acknowledgement has no pending read")]
    OutputAckWithoutRead,
    #[error("execution output acknowledgement does not match the exact pending prefix")]
    OutputAckMismatch {
        expected: ExecutionOutputEventKey,
        actual: ExecutionOutputEventKey,
    },
    #[error("execution output read prefix changed before acknowledgement")]
    OutputReadInvalidated,
    #[error("execution supervisor is already shut down")]
    AlreadyShutdown,
    #[error("failed to spawn execution supervisor thread")]
    SpawnThread(#[source] std::io::Error),
    #[error("execution supervisor thread panicked")]
    ThreadPanicked,
    #[error(transparent)]
    Execution(#[from] ExecutionError),
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::thread;
    use std::time::{Duration, Instant};

    use forge_domain::{
        ActivityId, ExecutionArgument, ExecutionAttribution, ExecutionId, ExecutionKind,
        ExecutionLimits, ExecutionOutputCursor, ExecutionOutputLimit, ExecutionPermissions,
        ExecutionProgram, ExecutionRequestDigest, ExecutionScript, ExecutionTimeoutMillis,
        VerificationInputId, WorkspaceId, WorkspaceRootFingerprint,
    };
    use forge_workspace::{ConfinedWorkspace, WorkspaceStateLayout};
    use uuid::Uuid;

    use super::*;
    use crate::ExecutionOutputEvent;
    use crate::runner::RustCiRuntimeFinalization;
    use crate::{
        ExecutionLaunchKind, RUST_CI_SANDBOX_MARKER_ENV, RUST_CI_SANDBOX_MARKER_VALUE,
        RustCiDiscoveryInput, RustCiHostArchitecture, RustCiToolchainCapability,
    };
    use crate::{PACKAGE_V_MANIFEST_NAME, PACKAGE_V_SUBCOMMAND, PackageVExecutableCapability};
    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

    const RUST_CI_TEST_POLICY_ENV: &str = "HETERARCHY_FORGE_RUST_CI_TEST_POLICY";
    const RUST_CI_TEST_POLICY_VALUE: &str = "outer-rust-ci-v1";

    fn fixture() -> Result<(PathBuf, ExistingWorkspaceStateLayout), Box<dyn std::error::Error>> {
        let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "forge-execution-supervisor-{}-{serial}",
            std::process::id()
        ));
        fs::create_dir_all(&root)?;
        WorkspaceStateLayout::initialize(&root)?;
        let layout = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
        Ok((root, layout))
    }

    fn package_fixture()
    -> Result<(PathBuf, ExistingWorkspaceStateLayout), Box<dyn std::error::Error>> {
        let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root = PathBuf::from("/private/tmp").join(format!(
            "forge-execution-supervisor-package-{}-{serial}",
            std::process::id()
        ));
        fs::create_dir_all(&root)?;
        WorkspaceStateLayout::initialize(&root)?;
        let layout = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
        fs::write(layout.workspace_root().join(PACKAGE_V_MANIFEST_NAME), b"{}")?;
        Ok((root, layout))
    }

    fn package_input(
        layout: &ExistingWorkspaceStateLayout,
        id: u128,
    ) -> Result<forge_workspace::PublishedVerificationInput, Box<dyn std::error::Error>> {
        let workspace = ConfinedWorkspace::open(layout)?;
        let cancelled = AtomicBool::new(false);
        let staged = workspace.stage_verification_input(
            VerificationInputId::from_uuid(Uuid::from_u128(id)),
            &cancelled,
        )?;
        Ok(staged.publish()?)
    }

    fn remove_package_fixture(root: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
        fn unlock(path: &std::path::Path) -> std::io::Result<()> {
            let metadata = fs::symlink_metadata(path)?;
            if metadata.is_dir() {
                for entry in fs::read_dir(path)? {
                    unlock(&entry?.path())?;
                }
                fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
            } else {
                fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
            }
            Ok(())
        }
        unlock(root)?;
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn package_verification_uses_dedicated_baseline_native_start()
    -> Result<(), Box<dyn std::error::Error>> {
        if nested_sandbox_execution_is_unavailable() {
            return Ok(());
        }
        let (root, layout) = package_fixture()?;
        let input = package_input(&layout, 0xC101)?;
        let capability = PackageVExecutableCapability::prepare_current()?;
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(0xC102));
        let execution_id = ExecutionId::from_uuid(Uuid::from_u128(0xC103));
        let request = ExecutionRequest::new(
            ExecutionAttribution::new(
                execution_id,
                workspace_id,
                ActivityId::from_uuid(Uuid::from_u128(0xC104)),
            ),
            ExecutionKind::Structured {
                program: ExecutionProgram::new(capability.path().to_path_buf())?,
                arguments: vec![
                    ExecutionArgument::new(OsString::from(PACKAGE_V_SUBCOMMAND))?,
                    ExecutionArgument::new(OsString::from(PACKAGE_V_MANIFEST_NAME))?,
                ],
            },
            None,
            ExecutionLimits::new(
                ExecutionTimeoutMillis::new(5 * 60 * 1_000)?,
                ExecutionOutputLimit::new(64 * 1024)?,
            ),
            ExecutionPermissions::new(true, false, false),
        )?;
        let identity = SupervisorStartIdentity::capture(
            &layout,
            &request,
            ExecutionLaunchKind::Baseline,
            Some(&input),
        )?;
        let mut supervisor = ExecutionSupervisor::start(1)?;
        let client = supervisor.client();
        let started = match client
            .start_package_verification_with_identity(identity, layout, request, input)
        {
            Ok(id) => id,
            Err(ExecutionSupervisorError::Execution(ExecutionError::SpawnProcess(error)))
                if error.kind() == std::io::ErrorKind::PermissionDenied =>
            {
                let _report = supervisor.shutdown()?;
                remove_package_fixture(&root)?;
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        };
        assert_eq!(started, execution_id);
        let event = wait_for_retained_terminal_event(&client, execution_id)?;
        assert_eq!(
            event.identity().launch_kind(),
            ExecutionLaunchKind::Baseline
        );
        assert!(event.identity().verification_input().is_some());
        assert!(client.acknowledge_terminal_event(&event.key(), &identity)?);
        let _report = supervisor.shutdown()?;
        remove_package_fixture(&root)?;
        Ok(())
    }

    fn nested_sandbox_execution_is_unavailable() -> bool {
        std::env::var(RUST_CI_SANDBOX_MARKER_ENV).as_deref() == Ok(RUST_CI_SANDBOX_MARKER_VALUE)
            && std::env::var(RUST_CI_TEST_POLICY_ENV).as_deref() == Ok(RUST_CI_TEST_POLICY_VALUE)
    }

    fn request(
        id: u128,
        workspace_id: WorkspaceId,
        program: &str,
        arguments: &[&str],
        timeout: u64,
    ) -> Result<ExecutionRequest, Box<dyn std::error::Error>> {
        Ok(ExecutionRequest::new(
            ExecutionAttribution::new(
                ExecutionId::from_uuid(Uuid::from_u128(id)),
                workspace_id,
                ActivityId::from_uuid(Uuid::from_u128(id + 1)),
            ),
            ExecutionKind::Structured {
                program: ExecutionProgram::new(PathBuf::from(program))?,
                arguments: arguments
                    .iter()
                    .map(|value| ExecutionArgument::new(OsString::from(value)))
                    .collect::<Result<_, _>>()?,
            },
            None,
            ExecutionLimits::new(
                ExecutionTimeoutMillis::new(timeout)?,
                ExecutionOutputLimit::new(1024)?,
            ),
            ExecutionPermissions::new(false, false, false),
        )?)
    }

    fn shell_request(
        id: u128,
        workspace_id: WorkspaceId,
        script: &str,
        timeout: u64,
        output_limit: u64,
    ) -> Result<ExecutionRequest, Box<dyn std::error::Error>> {
        Ok(ExecutionRequest::new(
            ExecutionAttribution::new(
                ExecutionId::from_uuid(Uuid::from_u128(id)),
                workspace_id,
                ActivityId::from_uuid(Uuid::from_u128(id + 1)),
            ),
            ExecutionKind::Shell {
                script: ExecutionScript::new(script.to_owned())?,
            },
            None,
            ExecutionLimits::new(
                ExecutionTimeoutMillis::new(timeout)?,
                ExecutionOutputLimit::new(output_limit)?,
            ),
            ExecutionPermissions::new(true, true, false),
        )?)
    }

    fn rust_ci_capability(
        root: &std::path::Path,
    ) -> Result<RustCiToolchainCapability, Box<dyn std::error::Error>> {
        let root = std::fs::canonicalize(root)?;
        let host = root.join("rust-ci-host");
        std::fs::create_dir_all(host.join(".cargo/bin"))?;
        std::fs::create_dir_all(host.join(".cargo/registry"))?;
        std::fs::create_dir_all(host.join(format!(
            ".rustup/toolchains/{}-aarch64-apple-darwin",
            crate::rust_ci::RUST_CI_PINNED_VERSION
        )))?;
        std::fs::write(host.join(".cargo/bin/rustup"), b"rustup")?;
        std::fs::write(host.join(".rustup/settings.toml"), b"version = 12\n")?;
        let cache = root.join("rust-ci-cache");
        let input = RustCiDiscoveryInput::new(
            host,
            cache,
            RustCiHostArchitecture::Aarch64,
            forge_domain::RuntimeInstanceId::from_uuid(uuid::Uuid::from_u128(0x5101)),
        )?;
        Ok(RustCiToolchainCapability::prepare(&input)?)
    }

    fn wait_for_output_and_terminal(
        client: &ExecutionSupervisorClient,
        execution_id: ExecutionId,
        expected_output: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let output_deadline = Instant::now() + Duration::from_secs(2);
        let mut saw_output = false;
        while !saw_output {
            let read = client.read_output_events(8)?;
            if !read.events().is_empty() {
                saw_output = read.events().iter().any(|event| {
                    matches!(
                        event,
                        ExecutionOutputEvent::Chunk(chunk)
                            if chunk.execution_id() == execution_id
                                && chunk.stream() == crate::ExecutionOutputStream::Stdout
                                && chunk.bytes() == expected_output
                    )
                });
                let key = read.ack_key().ok_or("missing output acknowledgement key")?;
                client.ack_output_events(key)?;
            }
            if !saw_output && Instant::now() >= output_deadline {
                return Err("expected output did not arrive".into());
            }
            if !saw_output {
                thread::yield_now();
            }
        }

        let terminal_deadline = Instant::now() + Duration::from_secs(2);
        let mut saw_terminal = false;
        let mut terminal_succeeded = false;
        while !saw_terminal {
            for event in take_terminal_events(client, 8)? {
                if event.execution_id() == execution_id {
                    saw_terminal = true;
                    terminal_succeeded = matches!(
                        event.result(),
                        Ok(outcome)
                            if outcome.status() == forge_domain::ExecutionCompletionStatus::Exited
                    );
                }
            }
            if !saw_terminal && Instant::now() >= terminal_deadline {
                return Err("expected terminal event did not arrive".into());
            }
            if !saw_terminal {
                thread::yield_now();
            }
        }
        if !terminal_succeeded {
            return Err("terminal event did not report Exited".into());
        }
        Ok(())
    }

    fn wait_for_terminal_event(
        client: &ExecutionSupervisorClient,
        execution_id: ExecutionId,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if take_terminal_events(client, 8)?
                .into_iter()
                .any(|event| event.execution_id() == execution_id)
            {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err("terminal event did not arrive".into());
            }
            thread::yield_now();
        }
    }

    fn wait_for_retained_terminal_event(
        client: &ExecutionSupervisorClient,
        execution_id: ExecutionId,
    ) -> Result<ExecutionSupervisorEvent, Box<dyn std::error::Error>> {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Some(event) = client
                .peek_terminal_events(8)?
                .into_iter()
                .find(|event| event.execution_id() == execution_id)
            {
                return Ok(event);
            }
            if Instant::now() >= deadline {
                return Err("retained terminal event did not arrive".into());
            }
            thread::yield_now();
        }
    }

    fn take_terminal_events(
        client: &ExecutionSupervisorClient,
        maximum: usize,
    ) -> Result<Vec<ExecutionSupervisorEvent>, Box<dyn std::error::Error>> {
        let events = client.peek_terminal_events(maximum)?;
        for event in &events {
            if !client.acknowledge_terminal_event(&event.key(), &event.identity())? {
                return Err(format!(
                    "terminal event acknowledgement failed for {}",
                    event.execution_id()
                )
                .into());
            }
        }
        Ok(events)
    }

    fn expect_baseline_identity_mismatch(
        client: &ExecutionSupervisorClient,
        identity: SupervisorStartIdentity,
        layout: ExistingWorkspaceStateLayout,
        request: ExecutionRequest,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if matches!(
            client.start_execution_with_identity(
                identity,
                layout,
                request,
                ExecutionLaunchKind::Baseline,
                None,
                None,
            ),
            Err(ExecutionSupervisorError::StartIdentityMismatch { .. })
        ) {
            Ok(())
        } else {
            Err("baseline identity mismatch was not rejected".into())
        }
    }

    fn dispatch_raw_start(
        client: &ExecutionSupervisorClient,
        identity: SupervisorStartIdentity,
        layout: ExistingWorkspaceStateLayout,
        request: ExecutionRequest,
    ) -> Result<Result<ExecutionId, ExecutionSupervisorError>, Box<dyn std::error::Error>> {
        let (response_sender, response_receiver) = mpsc::sync_channel(0);
        client.sender.send(SupervisorRequest::Start {
            identity: Box::new(identity),
            layout,
            request: Box::new(request),
            launch_kind: ExecutionLaunchKind::Baseline,
            rust_ci_capability: None,
            package_verification: false,
            verification_input: None,
            response: response_sender,
        })?;
        Ok(response_receiver.recv()?)
    }

    fn synthetic_identity(index: u128) -> SupervisorStartIdentity {
        let byte = u8::try_from(index % 256).unwrap_or_default();
        SupervisorStartIdentity {
            execution_id: ExecutionId::from_uuid(Uuid::from_u128(index)),
            workspace_id: WorkspaceId::from_uuid(Uuid::from_u128(index + 1)),
            activity_id: ActivityId::from_uuid(Uuid::from_u128(index + 2)),
            request_digest: ExecutionRequestDigest::from_bytes([byte; 32]),
            launch_kind: ExecutionLaunchKind::Baseline,
            root_fingerprint: WorkspaceRootFingerprint::from_bytes([byte; 16]),
            verification_input: None,
        }
    }

    fn synthetic_terminal_event(
        owner: &SupervisorOwnerToken,
        index: u128,
    ) -> ExecutionSupervisorEvent {
        let identity = synthetic_identity(index);
        ExecutionSupervisorEvent {
            identity,
            key: TerminalEventKey::new(
                owner.clone(),
                identity.execution_id(),
                u64::try_from(index).unwrap_or(u64::MAX),
            ),
            workspace_id: identity.workspace_id(),
            execution_id: identity.execution_id(),
            result: Err(ExecutionFailureCode::Admission),
            generated_package: None,
        }
    }

    fn assert_pre_spawn_proof(
        runtime: &SupervisorRuntime,
        identity: SupervisorStartIdentity,
        failure_code: ExecutionFailureCode,
    ) -> Result<NativePreSpawnRejection, Box<dyn std::error::Error>> {
        let proof = runtime
            .observe_native_rejection(identity)?
            .ok_or("expected native pre-spawn rejection proof")?;
        assert_eq!(proof.identity(), identity);
        assert_eq!(proof.failure_code(), failure_code);
        assert!(proof.has_owner(&runtime.owner));
        Ok(proof)
    }

    struct ReplyDropProxy {
        client: ExecutionSupervisorClient,
        owner: Option<JoinHandle<Result<(), String>>>,
    }

    impl ReplyDropProxy {
        fn new(real_client: &ExecutionSupervisorClient) -> Self {
            let (sender, receiver) = mpsc::sync_channel(1);
            let real_sender = real_client.sender.clone();
            let owner = thread::spawn(move || -> Result<(), String> {
                let request = receiver
                    .recv_timeout(Duration::from_secs(2))
                    .map_err(|error| format!("reply-drop proxy did not receive Start: {error}"))?;
                let SupervisorRequest::Start {
                    identity,
                    layout,
                    request,
                    launch_kind,
                    rust_ci_capability,
                    package_verification,
                    verification_input,
                    response,
                } = request
                else {
                    return Err("reply-drop proxy received a non-Start request".to_owned());
                };
                let (internal_sender, internal_receiver) = mpsc::sync_channel(0);
                real_sender
                    .send(SupervisorRequest::Start {
                        identity,
                        layout,
                        request,
                        launch_kind,
                        rust_ci_capability,
                        package_verification,
                        verification_input,
                        response: internal_sender,
                    })
                    .map_err(|error| {
                        format!("real supervisor rejected forwarded Start: {error:?}")
                    })?;
                let result = internal_receiver.recv().map_err(|error| {
                    format!("real supervisor dropped forwarded Start reply: {error}")
                })?;
                match result {
                    Ok(_execution_id) => {
                        // The genuine SupervisorRuntime has admitted and
                        // started the child.  Drop only the original caller
                        // reply so the real client submit boundary observes
                        // its current `Closed` classification.
                        drop(response);
                        Ok(())
                    }
                    Err(error) => {
                        response.send(Err(error)).map_err(|error| {
                            format!("failed to return rejected Start: {error:?}")
                        })?;
                        Err("real supervisor rejected Start before admission".to_owned())
                    }
                }
            });
            Self {
                client: ExecutionSupervisorClient {
                    sender,
                    accepting: Arc::new(AtomicBool::new(true)),
                },
                owner: Some(owner),
            }
        }

        fn client(&self) -> ExecutionSupervisorClient {
            self.client.clone()
        }

        fn finish(mut self) -> Result<(), Box<dyn std::error::Error>> {
            let Some(owner) = self.owner.take() else {
                return Ok(());
            };
            let result = owner
                .join()
                .map_err(|_| std::io::Error::other("reply-drop proxy panicked"))?;
            result.map_err(std::io::Error::other)?;
            Ok(())
        }
    }

    impl Drop for ReplyDropProxy {
        fn drop(&mut self) {
            if let Some(owner) = self.owner.take() {
                let _ignored = owner.join();
            }
        }
    }

    struct AckReplyDropProxy {
        client: ExecutionSupervisorClient,
        owner: Option<JoinHandle<Result<(), String>>>,
    }

    impl AckReplyDropProxy {
        fn new(real_client: &ExecutionSupervisorClient) -> Self {
            let (sender, receiver) = mpsc::sync_channel(1);
            let real_sender = real_client.sender.clone();
            let owner = thread::spawn(move || -> Result<(), String> {
                let request = receiver
                    .recv_timeout(Duration::from_secs(2))
                    .map_err(|error| {
                        format!("ack-drop proxy did not receive acknowledgement: {error}")
                    })?;
                let SupervisorRequest::AcknowledgeStart { identity, response } = request else {
                    return Err("ack-drop proxy received a non-acknowledgement request".to_owned());
                };
                let (internal_sender, internal_receiver) = mpsc::sync_channel(0);
                real_sender
                    .send(SupervisorRequest::AcknowledgeStart {
                        identity,
                        response: internal_sender,
                    })
                    .map_err(|error| {
                        format!("real supervisor rejected forwarded acknowledgement: {error:?}")
                    })?;
                let result = internal_receiver.recv().map_err(|error| {
                    format!("real supervisor dropped forwarded acknowledgement: {error}")
                })?;
                match result {
                    Ok(true) => {
                        drop(response);
                        Ok(())
                    }
                    Ok(value) => {
                        response.send(Ok(value)).map_err(|error| {
                            format!("failed to return acknowledgement: {error:?}")
                        })?;
                        Err("real supervisor did not acknowledge the retained receipt".to_owned())
                    }
                    Err(error) => {
                        response.send(Err(error)).map_err(|error| {
                            format!("failed to return acknowledgement error: {error:?}")
                        })?;
                        Err("real supervisor rejected acknowledgement".to_owned())
                    }
                }
            });
            Self {
                client: ExecutionSupervisorClient {
                    sender,
                    accepting: Arc::new(AtomicBool::new(true)),
                },
                owner: Some(owner),
            }
        }

        fn client(&self) -> ExecutionSupervisorClient {
            self.client.clone()
        }

        fn finish(mut self) -> Result<(), Box<dyn std::error::Error>> {
            let Some(owner) = self.owner.take() else {
                return Ok(());
            };
            let result = owner
                .join()
                .map_err(|_| std::io::Error::other("ack-drop proxy panicked"))?;
            result.map_err(std::io::Error::other)?;
            Ok(())
        }
    }

    impl Drop for AckReplyDropProxy {
        fn drop(&mut self) {
            if let Some(owner) = self.owner.take() {
                let _ignored = owner.join();
            }
        }
    }

    struct PeekReplyDropProxy {
        client: ExecutionSupervisorClient,
        owner: Option<JoinHandle<Result<Vec<ExecutionSupervisorEvent>, String>>>,
    }

    struct NativeClosureReplyDropProxy {
        client: ExecutionSupervisorClient,
        owner: Option<JoinHandle<Result<(), String>>>,
    }

    impl NativeClosureReplyDropProxy {
        fn new(real_client: &ExecutionSupervisorClient) -> Self {
            let (sender, receiver) = mpsc::sync_channel(1);
            let real_sender = real_client.sender.clone();
            let owner = thread::spawn(move || -> Result<(), String> {
                let request = receiver
                    .recv_timeout(Duration::from_secs(2))
                    .map_err(|error| {
                        format!(
                            "native-closure reply-drop proxy did not receive observation: {error}"
                        )
                    })?;
                let SupervisorRequest::ObserveNativeClosure { event, response } = request else {
                    return Err(
                        "native-closure reply-drop proxy received another request".to_owned()
                    );
                };
                let (internal_sender, internal_receiver) = mpsc::sync_channel(0);
                real_sender
                    .send(SupervisorRequest::ObserveNativeClosure {
                        event,
                        response: internal_sender,
                    })
                    .map_err(|error| {
                        format!("real supervisor rejected native-closure observation: {error:?}")
                    })?;
                let proof = internal_receiver.recv().map_err(|error| {
                    format!("real supervisor dropped native-closure observation: {error}")
                })?;
                if !matches!(proof, Ok(Some(_))) {
                    return Err(format!(
                        "native-closure observation was not positive before reply drop: {proof:?}"
                    ));
                }
                drop(response);
                Ok(())
            });
            Self {
                client: ExecutionSupervisorClient {
                    sender,
                    accepting: Arc::new(AtomicBool::new(true)),
                },
                owner: Some(owner),
            }
        }

        fn client(&self) -> ExecutionSupervisorClient {
            self.client.clone()
        }

        fn finish(mut self) -> Result<(), Box<dyn std::error::Error>> {
            let Some(owner) = self.owner.take() else {
                return Ok(());
            };
            owner
                .join()
                .map_err(|_| std::io::Error::other("native-closure reply-drop proxy panicked"))?
                .map_err(std::io::Error::other)?;
            Ok(())
        }
    }

    impl Drop for NativeClosureReplyDropProxy {
        fn drop(&mut self) {
            if let Some(owner) = self.owner.take() {
                let _ignored = owner.join();
            }
        }
    }

    impl PeekReplyDropProxy {
        fn new(real_client: &ExecutionSupervisorClient) -> Self {
            let (sender, receiver) = mpsc::sync_channel(1);
            let real_sender = real_client.sender.clone();
            let owner = thread::spawn(move || -> Result<Vec<ExecutionSupervisorEvent>, String> {
                let request = receiver
                    .recv_timeout(Duration::from_secs(2))
                    .map_err(|error| {
                        format!("peek-reply-drop proxy did not receive peek: {error}")
                    })?;
                let SupervisorRequest::PeekTerminalEvents { maximum, response } = request else {
                    return Err("peek-reply-drop proxy received a non-peek request".to_owned());
                };
                let (internal_sender, internal_receiver) = mpsc::sync_channel(0);
                real_sender
                    .send(SupervisorRequest::PeekTerminalEvents {
                        maximum,
                        response: internal_sender,
                    })
                    .map_err(|error| {
                        format!("real supervisor rejected forwarded peek: {error:?}")
                    })?;
                let result = internal_receiver.recv().map_err(|error| {
                    format!("real supervisor dropped forwarded peek reply: {error}")
                })?;
                match result {
                    Ok(events) => {
                        // The genuine owner has received the actual terminal
                        // event. Drop only the original caller reply so its
                        // submit boundary observes ReplyDropped.
                        drop(response);
                        Ok(events)
                    }
                    Err(error) => {
                        drop(response);
                        Err(format!("real supervisor rejected peek: {error:?}"))
                    }
                }
            });
            Self {
                client: ExecutionSupervisorClient {
                    sender,
                    accepting: Arc::new(AtomicBool::new(true)),
                },
                owner: Some(owner),
            }
        }

        fn client(&self) -> ExecutionSupervisorClient {
            self.client.clone()
        }

        fn finish(mut self) -> Result<Vec<ExecutionSupervisorEvent>, Box<dyn std::error::Error>> {
            let Some(owner) = self.owner.take() else {
                return Ok(Vec::new());
            };
            let result = owner
                .join()
                .map_err(|_| std::io::Error::other("peek-reply-drop proxy panicked"))?;
            result.map_err(std::io::Error::other).map_err(Into::into)
        }
    }

    impl Drop for PeekReplyDropProxy {
        fn drop(&mut self) {
            if let Some(owner) = self.owner.take() {
                let _ignored = owner.join();
            }
        }
    }

    struct FixtureRootGuard(PathBuf);

    impl Drop for FixtureRootGuard {
        fn drop(&mut self) {
            let _ignored = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn scheduler_blocks_when_no_work_is_active() {
        assert_eq!(
            supervisor_receive_policy(false, false),
            SupervisorReceivePolicy::BlockUntilRequest
        );
    }

    #[test]
    fn scheduler_keeps_ten_millisecond_polling_for_active_work() {
        assert_eq!(
            supervisor_receive_policy(true, false),
            SupervisorReceivePolicy::Poll(POLL_INTERVAL)
        );
    }

    #[test]
    fn scheduler_keeps_ten_millisecond_polling_during_shutdown_drain() {
        assert_eq!(
            supervisor_receive_policy(false, true),
            SupervisorReceivePolicy::Poll(POLL_INTERVAL)
        );
    }

    #[test]
    fn completion_backlog_counts_retained_terminal_owners_once()
    -> Result<(), Box<dyn std::error::Error>> {
        let active_ids: std::collections::HashSet<_> = (0..(MAX_COMPLETION_BACKLOG - 1))
            .map(|index| {
                u128::try_from(index)
                    .map(|index| synthetic_identity(60_000 + index).execution_id())
                    .map_err(|error| -> Box<dyn std::error::Error> { Box::new(error) })
            })
            .collect::<Result<_, _>>()?;
        let retained_event_ids = active_ids.clone();

        assert_eq!(
            completion_backlog_count(active_ids.len(), retained_event_ids, |execution_id| {
                active_ids.contains(&execution_id)
            },),
            MAX_COMPLETION_BACKLOG - 1
        );
        Ok(())
    }

    #[test]
    fn rust_ci_quarantine_requires_complete_process_and_runtime_evidence() {
        assert!(!rust_ci_completion_requires_quarantine(
            Some(ProcessFinalization::ProcessGroupReaped),
            Some(RustCiRuntimeFinalization::Cleaned),
        ));
        assert!(rust_ci_completion_requires_quarantine(
            Some(ProcessFinalization::ProcessGroupReaped),
            Some(RustCiRuntimeFinalization::Preserved),
        ));
        assert!(rust_ci_completion_requires_quarantine(
            Some(ProcessFinalization::ReapUnconfirmed),
            Some(RustCiRuntimeFinalization::Cleaned),
        ));
        assert!(rust_ci_completion_requires_quarantine(
            Some(ProcessFinalization::NoChildSpawned),
            Some(RustCiRuntimeFinalization::Preserved),
        ));
        assert!(rust_ci_completion_requires_quarantine(
            Some(ProcessFinalization::ProcessGroupReaped),
            Some(RustCiRuntimeFinalization::NotApplicable),
        ));
        assert!(rust_ci_completion_requires_quarantine(None, None));
    }

    #[test]
    fn failed_pre_spawn_cleanup_quarantines_only_its_workspace()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_sender, receiver) = std::sync::mpsc::sync_channel(1);
        let mut runtime = SupervisorRuntime::new(
            ExecutionRunner::new(1)?,
            receiver,
            Arc::new(AtomicBool::new(true)),
        );
        let workspace = WorkspaceId::from_uuid(Uuid::from_u128(29_000));
        assert!(
            runtime
                .finish_spawn_admission(
                    workspace,
                    ExecutionLaunchKind::RustCi,
                    Err(ExecutionError::VerificationInputMismatch)
                )
                .is_err()
        );
        assert!(
            runtime
                .ensure_rust_ci_workspace_available(workspace)
                .is_ok()
        );
        assert!(
            runtime
                .finish_spawn_admission(
                    workspace,
                    ExecutionLaunchKind::RustCi,
                    Err(ExecutionError::RustCiCleanup(
                        crate::RustCiDiscoveryError::ProductRuntimeMismatch
                    ))
                )
                .is_err()
        );
        assert!(
            matches!(runtime.ensure_rust_ci_workspace_available(workspace),
            Err(ExecutionSupervisorError::RustCiWorkspaceCapacity(actual)) if actual == workspace)
        );
        assert!(
            runtime
                .ensure_rust_ci_workspace_available(WorkspaceId::from_uuid(Uuid::from_u128(29_001)))
                .is_ok()
        );
        assert!(runtime.active.is_empty());
        assert!(runtime.events.is_empty());
        Ok(())
    }

    #[test]
    fn rust_ci_quarantine_rejects_workspace_until_supervisor_restart()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_sender, receiver) = std::sync::mpsc::sync_channel(1);
        let accepting = Arc::new(AtomicBool::new(true));
        let mut runtime = SupervisorRuntime::new(ExecutionRunner::new(1)?, receiver, accepting);
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(30_000));

        runtime.active_rust_ci_workspaces.insert(workspace_id);
        runtime.finalize_rust_ci_workspace(
            workspace_id,
            Some(ProcessFinalization::ProcessGroupReaped),
            Some(RustCiRuntimeFinalization::Preserved),
        );
        assert!(!runtime.active_rust_ci_workspaces.contains(&workspace_id));
        assert!(matches!(
            runtime.ensure_rust_ci_workspace_available(workspace_id),
            Err(ExecutionSupervisorError::RustCiWorkspaceCapacity(actual))
                if actual == workspace_id
        ));

        let (_sender, receiver) = std::sync::mpsc::sync_channel(1);
        let restarted = SupervisorRuntime::new(
            ExecutionRunner::new(1)?,
            receiver,
            Arc::new(AtomicBool::new(true)),
        );
        assert!(
            restarted
                .ensure_rust_ci_workspace_available(workspace_id)
                .is_ok(),
            "quarantine is supervisor-lifetime state"
        );
        Ok(())
    }

    #[test]
    fn rust_ci_quarantine_capacity_saturates_and_fails_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_sender, receiver) = std::sync::mpsc::sync_channel(1);
        let mut runtime = SupervisorRuntime::new(
            ExecutionRunner::new(1)?,
            receiver,
            Arc::new(AtomicBool::new(true)),
        );
        for index in 0..MAX_RUST_CI_QUARANTINE {
            let workspace_id =
                WorkspaceId::from_uuid(Uuid::from_u128(31_000 + u128::try_from(index)?));
            runtime.quarantine_rust_ci_workspace(workspace_id)?;
        }
        let overflow = WorkspaceId::from_uuid(Uuid::from_u128(32_000));
        assert!(matches!(
            runtime.quarantine_rust_ci_workspace(overflow),
            Err(ExecutionSupervisorError::RustCiWorkspaceCapacity(actual))
                if actual == overflow
        ));
        assert!(runtime.rust_ci_quarantine_saturated);

        let other = WorkspaceId::from_uuid(Uuid::from_u128(32_001));
        assert!(matches!(
            runtime.ensure_rust_ci_workspace_available(other),
            Err(ExecutionSupervisorError::RustCiWorkspaceCapacity(actual))
                if actual == other
        ));
        Ok(())
    }

    #[test]
    #[ignore = "explicit performance evaluator"]
    fn performance_evaluator_supervisor_scheduler_policy() {
        assert_eq!(
            supervisor_receive_policy(false, false),
            SupervisorReceivePolicy::BlockUntilRequest
        );
        assert_eq!(
            supervisor_receive_policy(true, false),
            SupervisorReceivePolicy::Poll(POLL_INTERVAL)
        );
        assert_eq!(
            supervisor_receive_policy(false, true),
            SupervisorReceivePolicy::Poll(POLL_INTERVAL)
        );
        assert_eq!(
            supervisor_receive_policy(true, true),
            SupervisorReceivePolicy::Poll(POLL_INTERVAL)
        );
    }

    #[test]
    fn stop_all_drains_owned_groups_and_rejects_no_completed_event()
    -> Result<(), Box<dyn std::error::Error>> {
        if nested_sandbox_execution_is_unavailable() {
            return Ok(());
        }
        let (root, layout) = fixture()?;
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(100));
        let mut supervisor = ExecutionSupervisor::start(2)?;
        let client = supervisor.client();
        let id = client.start_execution(
            layout,
            request(101, workspace_id, "/bin/sleep", &["30"], 30_000)?,
        )?;
        assert_eq!(client.stop_all()?, 1);
        let events = take_terminal_events(&client, 8)?;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].execution_id(), id);
        assert!(matches!(
            events[0].result(),
            Ok(outcome) if outcome.status() == forge_domain::ExecutionCompletionStatus::Cancelled
        ));
        let report = supervisor.shutdown()?;
        assert_eq!(report.active_cancelled(), 0);
        assert!(report.events().is_empty());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn dropped_start_reply_after_admission_is_admitted_unknown_and_keeps_owner()
    -> Result<(), Box<dyn std::error::Error>> {
        if nested_sandbox_execution_is_unavailable() {
            return Ok(());
        }

        let (root, layout) = fixture()?;
        let _root_guard = FixtureRootGuard(root.clone());
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(150));
        let mut supervisor = ExecutionSupervisor::start(1)?;
        let client = supervisor.client();
        let execution_id = ExecutionId::from_uuid(Uuid::from_u128(151));
        let request = shell_request(
            151,
            workspace_id,
            "printf admitted; exec /bin/sleep 30",
            30_000,
            1_024,
        )?;
        let identity = SupervisorStartIdentity::capture(
            &layout,
            &request,
            ExecutionLaunchKind::Baseline,
            None,
        )?;
        let reply_drop_proxy = ReplyDropProxy::new(&client);
        let proxy_client = reply_drop_proxy.client();
        let start_result = proxy_client.start_execution(layout, request);
        reply_drop_proxy.finish()?;

        let output_deadline = Instant::now() + Duration::from_secs(2);
        let mut saw_output = false;
        while !saw_output {
            let read = client.read_output_events(8)?;
            if !read.events().is_empty() {
                saw_output = read.events().iter().any(|event| {
                    matches!(
                        event,
                        ExecutionOutputEvent::Chunk(chunk)
                            if chunk.execution_id() == execution_id
                                && chunk.stream() == crate::ExecutionOutputStream::Stdout
                                && chunk.bytes() == b"admitted"
                    )
                });
                let key = read.ack_key().ok_or("missing output acknowledgement key")?;
                client.ack_output_events(key)?;
            }
            if !saw_output && Instant::now() >= output_deadline {
                return Err("admitted execution output did not arrive".into());
            }
            if !saw_output {
                thread::yield_now();
            }
        }

        if !client.cancel_execution(execution_id)? {
            return Err("admitted execution was not retained by its owner".into());
        }
        let terminal_deadline = Instant::now() + Duration::from_secs(2);
        let mut saw_terminal = false;
        while !saw_terminal {
            saw_terminal = take_terminal_events(&client, 8)?.into_iter().any(|event| {
                event.execution_id() == execution_id
                    && matches!(
                        event.result(),
                        Ok(outcome)
                            if outcome.status()
                                == forge_domain::ExecutionCompletionStatus::Cancelled
                    )
            });
            if !saw_terminal && Instant::now() >= terminal_deadline {
                return Err("admitted execution terminal event did not arrive".into());
            }
            if !saw_terminal {
                thread::yield_now();
            }
        }

        let receipt = client
            .observe_start(&identity)?
            .ok_or("accepted Start receipt was released before ownership acknowledgement")?;
        if receipt.outcome() != SupervisorStartOutcome::Accepted {
            return Err("accepted Start did not retain an Accepted receipt".into());
        }
        if !client.acknowledge_start(&identity)? {
            return Err("accepted Start receipt acknowledgement was not recorded".into());
        }
        if client.observe_start(&identity)?.is_some() {
            return Err("accepted Start receipt survived exact acknowledgement".into());
        }

        let report = supervisor.shutdown()?;
        drop(supervisor);
        fs::remove_dir_all(&root)?;

        let client_error = match start_result {
            Err(error) => error.to_string(),
            Ok(_execution_id) => "unexpected successful Start reply".to_owned(),
        };
        assert!(
            client_error.contains("reply dropped after admission"),
            "successful native Start enqueue with an owned child was classified as {client_error}"
        );
        assert_eq!(report.active_cancelled(), 0);
        assert!(report.events().is_empty());
        Ok(())
    }

    #[test]
    fn dropped_peek_reply_retains_exact_terminal_event_until_ack()
    -> Result<(), Box<dyn std::error::Error>> {
        if nested_sandbox_execution_is_unavailable() {
            return Ok(());
        }

        let (root, layout) = fixture()?;
        let _root_guard = FixtureRootGuard(root.clone());
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(152));
        let request = request(153, workspace_id, "/bin/true", &[], 2_000)?;
        let mut supervisor = ExecutionSupervisor::start(1)?;
        let client = supervisor.client();
        let execution_id = client.start_execution(layout, request)?;

        let deadline = Instant::now() + Duration::from_secs(2);
        let mut forwarded_events = None;
        while Instant::now() < deadline {
            let peek_proxy = PeekReplyDropProxy::new(&client);
            let peek_result = peek_proxy.client().peek_terminal_events(8);
            let events = peek_proxy.finish()?;
            if !matches!(peek_result, Err(ExecutionSupervisorError::ReplyDropped)) {
                return Err(format!("dropped peek reply was classified as {peek_result:?}").into());
            }
            if !events.is_empty() {
                forwarded_events = Some(events);
                break;
            }
            thread::yield_now();
        }

        let retained = client.peek_terminal_events(8);
        let forwarded_events = forwarded_events.ok_or("terminal event did not arrive")?;
        let retained = retained?;
        if retained.len() == 1 {
            let retained_event = &retained[0];
            let forwarded_event = &forwarded_events[0];
            if !client
                .acknowledge_terminal_event(&retained_event.key(), &retained_event.identity())?
            {
                return Err("exact terminal event acknowledgement failed".into());
            }
            if retained_event != forwarded_event {
                return Err("retained terminal event payload changed after reply loss".into());
            }
        }
        let shutdown = supervisor.shutdown();
        drop(supervisor);
        fs::remove_dir_all(&root)?;

        let _shutdown = shutdown?;
        if forwarded_events.len() != 1 {
            return Err(format!(
                "forwarded drain returned {} terminal events instead of one",
                forwarded_events.len()
            )
            .into());
        }
        let forwarded = &forwarded_events[0];
        assert_eq!(forwarded.execution_id(), execution_id);
        assert!(matches!(
            forwarded.result(),
            Ok(outcome) if outcome.status() == forge_domain::ExecutionCompletionStatus::Exited
        ));
        if retained.len() != 1 {
            return Err(format!(
                "repeated genuine peek returned {} events after reply loss",
                retained.len()
            )
            .into());
        }
        let repeated = &retained[0];
        assert_eq!(repeated.execution_id(), execution_id);
        assert!(matches!(
            repeated.result(),
            Ok(outcome) if outcome.status() == forge_domain::ExecutionCompletionStatus::Exited
        ));
        Ok(())
    }

    #[test]
    fn terminal_acknowledgement_allows_a_later_event_before_an_earlier_event()
    -> Result<(), Box<dyn std::error::Error>> {
        if nested_sandbox_execution_is_unavailable() {
            return Ok(());
        }
        let (root, layout) = fixture()?;
        let _root_guard = FixtureRootGuard(root.clone());
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(154));
        let first_request = request(155, workspace_id, "/bin/true", &[], 2_000)?;
        let second_request = request(157, workspace_id, "/bin/true", &["later"], 2_000)?;
        let first_identity = SupervisorStartIdentity::capture(
            &layout,
            &first_request,
            ExecutionLaunchKind::Baseline,
            None,
        )?;
        let second_identity = SupervisorStartIdentity::capture(
            &layout,
            &second_request,
            ExecutionLaunchKind::Baseline,
            None,
        )?;
        let mut supervisor = ExecutionSupervisor::start(2)?;
        let client = supervisor.client();
        client.start_execution(layout.clone(), first_request)?;
        client.start_execution(layout, second_request)?;

        let deadline = Instant::now() + Duration::from_secs(2);
        let events = loop {
            let events = client.peek_terminal_events(8)?;
            if events.len() == 2 {
                break events;
            }
            if Instant::now() >= deadline {
                return Err("two terminal events did not arrive".into());
            }
            thread::yield_now();
        };
        let first = events
            .iter()
            .find(|event| event.identity() == first_identity)
            .cloned()
            .ok_or("first terminal event identity was not retained")?;
        let second = events
            .iter()
            .find(|event| event.identity() == second_identity)
            .cloned()
            .ok_or("second terminal event identity was not retained")?;
        assert_ne!(first.key(), second.key());
        let mismatched_identity = SupervisorStartIdentity {
            workspace_id: WorkspaceId::from_uuid(Uuid::from_u128(158)),
            ..second_identity
        };
        assert!(matches!(
            client.observe_terminal_event(&second.key(), &mismatched_identity),
            Err(ExecutionSupervisorError::TerminalEventIdentityMismatch { execution_id })
                if execution_id == second.execution_id()
        ));
        assert!(matches!(
            client.acknowledge_terminal_event(&second.key(), &mismatched_identity),
            Err(ExecutionSupervisorError::TerminalEventIdentityMismatch { execution_id })
                if execution_id == second.execution_id()
        ));
        assert!(
            client
                .observe_terminal_event(&second.key(), &second_identity)?
                .is_some()
        );
        assert!(client.acknowledge_terminal_event(&second.key(), &second_identity)?);
        let remaining = client.peek_terminal_events(8)?;
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0], first);
        assert!(client.acknowledge_terminal_event(&first.key(), &first_identity)?);
        assert!(client.acknowledge_start(&first_identity)?);
        assert!(client.acknowledge_start(&second_identity)?);
        let report = supervisor.shutdown()?;
        drop(supervisor);
        fs::remove_dir_all(&root)?;
        assert!(report.events().is_empty());
        Ok(())
    }

    #[test]
    fn same_execution_id_reuse_gets_the_next_generation_after_exact_ack()
    -> Result<(), Box<dyn std::error::Error>> {
        if nested_sandbox_execution_is_unavailable() {
            return Ok(());
        }
        let (root, layout) = fixture()?;
        let _root_guard = FixtureRootGuard(root.clone());
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(159));
        let first_request = request(160, workspace_id, "/bin/true", &[], 2_000)?;
        let first_identity = SupervisorStartIdentity::capture(
            &layout,
            &first_request,
            ExecutionLaunchKind::Baseline,
            None,
        )?;
        let mut supervisor = ExecutionSupervisor::start(1)?;
        let client = supervisor.client();
        let execution_id = client.start_execution(layout.clone(), first_request.clone())?;
        let first_event = wait_for_retained_terminal_event(&client, execution_id)?;
        assert_eq!(first_event.identity(), first_identity);
        let duplicate_id = client.start_execution_with_identity(
            first_identity,
            layout.clone(),
            first_request,
            ExecutionLaunchKind::Baseline,
            None,
            None,
        )?;
        assert_eq!(duplicate_id, execution_id);
        assert_eq!(
            client.observe_terminal_event(&first_event.key(), &first_identity)?,
            Some(first_event.clone())
        );
        assert!(client.acknowledge_terminal_event(&first_event.key(), &first_identity)?);
        assert!(client.acknowledge_start(&first_identity)?);
        let output = client.read_output_events(MAX_OUTPUT_EVENT_BACKLOG)?;
        if let Some(key) = output.ack_key() {
            let _acked = client.ack_output_events(key)?;
        }
        assert!(!client.has_pending_output(execution_id)?);

        let second_request = request(160, workspace_id, "/bin/true", &["reuse"], 2_000)?;
        let second_identity = SupervisorStartIdentity::capture(
            &layout,
            &second_request,
            ExecutionLaunchKind::Baseline,
            None,
        )?;
        assert_eq!(
            client.start_execution(layout, second_request)?,
            execution_id
        );
        let second_event = wait_for_retained_terminal_event(&client, execution_id)?;
        assert_eq!(second_event.identity(), second_identity);
        assert_ne!(first_event.key(), second_event.key());
        assert_eq!(
            second_event.key().generation,
            first_event.key().generation + 1
        );
        assert!(client.acknowledge_terminal_event(&second_event.key(), &second_identity)?);
        assert!(client.acknowledge_start(&second_identity)?);
        let report = supervisor.shutdown()?;
        drop(supervisor);
        fs::remove_dir_all(&root)?;
        assert!(report.events().is_empty());
        Ok(())
    }

    #[test]
    fn terminal_generation_exhaustion_rejects_before_runner_spawn()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, layout) = fixture()?;
        let _root_guard = FixtureRootGuard(root.clone());
        let (_sender, receiver) = mpsc::sync_channel(1);
        let mut runtime = SupervisorRuntime::new(
            ExecutionRunner::new(1)?,
            receiver,
            Arc::new(AtomicBool::new(true)),
        );
        runtime.next_terminal_generation = u64::MAX;
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(163));
        let request = request(164, workspace_id, "/bin/true", &[], 2_000)?;
        let identity = SupervisorStartIdentity::capture(
            &layout,
            &request,
            ExecutionLaunchKind::Baseline,
            None,
        )?;
        let result = runtime.start_execution(
            &layout,
            identity,
            request,
            ExecutionLaunchKind::Baseline,
            None,
            false,
            None,
        );
        assert!(matches!(
            result,
            Err(ExecutionSupervisorError::TerminalEventGenerationExhausted { execution_id })
                if execution_id == identity.execution_id()
        ));
        assert!(runtime.active.is_empty());
        let receipt = runtime
            .start_receipts
            .get(&identity.execution_id())
            .copied()
            .ok_or("generation exhaustion did not retain the original Start key")?;
        assert_eq!(receipt.identity(), identity);
        assert_eq!(
            receipt.outcome(),
            SupervisorStartOutcome::Rejected {
                failure_code: ExecutionFailureCode::Admission
            }
        );
        drop(runtime);
        fs::remove_dir_all(&root)?;
        Ok(())
    }

    #[test]
    fn terminal_owner_queue_full_mismatch_and_closed_fail_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut supervisor = ExecutionSupervisor::start(1)?;
        let client = supervisor.client();
        let mut responses = Vec::new();
        // One zero-capacity response blocks the in-flight worker. Account for
        // that consumed request as well as every queued slot before probing.
        let fill_deadline = Instant::now() + Duration::from_secs(2);
        while responses.len() < SUPERVISOR_QUEUE_CAPACITY + 1 {
            if Instant::now() >= fill_deadline {
                return Err("supervisor request queue did not saturate".into());
            }
            let (response_sender, response_receiver) = mpsc::sync_channel(0);
            match client
                .sender
                .try_send(SupervisorRequest::PeekTerminalEvents {
                    maximum: 1,
                    response: response_sender,
                }) {
                Ok(()) => responses.push(response_receiver),
                Err(TrySendError::Full(request)) => {
                    drop(request);
                    thread::yield_now();
                }
                Err(TrySendError::Disconnected(request)) => {
                    drop(request);
                    return Err("supervisor closed while filling its request queue".into());
                }
            }
        }
        assert!(matches!(
            client.peek_terminal_events(1),
            Err(ExecutionSupervisorError::QueueFull)
        ));
        drop(responses);
        let drain_deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if Instant::now() >= drain_deadline {
                return Err("supervisor request queue did not drain".into());
            }
            match client.peek_terminal_events(1) {
                Ok(_) => break,
                Err(ExecutionSupervisorError::QueueFull) => thread::yield_now(),
                Err(error) => return Err(error.into()),
            }
        }

        let (root, layout) = fixture()?;
        let _root_guard = FixtureRootGuard(root.clone());
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(165));
        let request = request(166, workspace_id, "/bin/true", &[], 2_000)?;
        let identity = SupervisorStartIdentity::capture(
            &layout,
            &request,
            ExecutionLaunchKind::Baseline,
            None,
        )?;
        let execution_id = client.start_execution(layout, request)?;
        let terminal_deadline = Instant::now() + Duration::from_secs(3);
        let event = loop {
            if Instant::now() >= terminal_deadline {
                return Err("native terminal event did not arrive".into());
            }
            if let Some(event) = client
                .peek_terminal_events(8)?
                .into_iter()
                .find(|event| event.execution_id() == execution_id)
            {
                break event;
            }
            thread::yield_now();
        };
        let mismatched_identity = SupervisorStartIdentity {
            activity_id: ActivityId::from_uuid(Uuid::from_u128(168)),
            ..identity
        };
        assert!(matches!(
            client.observe_terminal_event(&event.key(), &mismatched_identity),
            Err(ExecutionSupervisorError::TerminalEventIdentityMismatch { execution_id })
                if execution_id == event.execution_id()
        ));
        assert!(matches!(
            client.acknowledge_terminal_event(&event.key(), &mismatched_identity),
            Err(ExecutionSupervisorError::TerminalEventIdentityMismatch { execution_id })
                if execution_id == event.execution_id()
        ));
        assert!(client.acknowledge_terminal_event(&event.key(), &identity)?);
        assert!(client.acknowledge_start(&identity)?);
        let _report = supervisor.shutdown()?;
        drop(supervisor);
        assert!(matches!(
            client.peek_terminal_events(1),
            Err(ExecutionSupervisorError::Closed)
        ));
        assert!(matches!(
            client.observe_terminal_event(&event.key(), &identity),
            Err(ExecutionSupervisorError::Closed)
        ));
        assert!(matches!(
            client.acknowledge_terminal_event(&event.key(), &identity),
            Err(ExecutionSupervisorError::Closed)
        ));
        fs::remove_dir_all(&root)?;
        Ok(())
    }

    #[test]
    fn fast_terminal_receipt_survives_output_and_terminal_drain_until_ack()
    -> Result<(), Box<dyn std::error::Error>> {
        if nested_sandbox_execution_is_unavailable() {
            return Ok(());
        }
        let (root, layout) = fixture()?;
        let _root_guard = FixtureRootGuard(root.clone());
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(155));
        let request = request(
            156,
            workspace_id,
            "/usr/bin/printf",
            &["fast-terminal"],
            2_000,
        )?;
        let identity = SupervisorStartIdentity::capture(
            &layout,
            &request,
            ExecutionLaunchKind::Baseline,
            None,
        )?;
        let mut supervisor = ExecutionSupervisor::start(1)?;
        let client = supervisor.client();
        let execution_id = client.start_execution(layout.clone(), request.clone())?;
        if execution_id != identity.execution_id() {
            return Err("native Start returned a different execution identity".into());
        }
        wait_for_output_and_terminal(&client, execution_id, b"fast-terminal")?;

        let receipt = client
            .observe_start(&identity)?
            .ok_or("fast-terminal receipt was released before acknowledgement")?;
        if receipt.outcome() != SupervisorStartOutcome::Accepted {
            return Err("fast-terminal receipt was not Accepted".into());
        }

        let duplicate_id = client.start_execution_with_identity(
            identity,
            layout,
            request,
            ExecutionLaunchKind::Baseline,
            None,
            None,
        )?;
        if duplicate_id != execution_id {
            return Err("exact fast-terminal duplicate changed execution identity".into());
        }
        let quiet_deadline = Instant::now() + Duration::from_millis(100);
        loop {
            if !client.read_output_events(8)?.events().is_empty()
                || take_terminal_events(&client, 8)?
                    .into_iter()
                    .any(|event| event.execution_id() == execution_id)
            {
                return Err("exact duplicate produced a second output or terminal event".into());
            }
            if Instant::now() >= quiet_deadline {
                break;
            }
            thread::yield_now();
        }

        if !client.acknowledge_start(&identity)? {
            return Err("fast-terminal receipt acknowledgement was not recorded".into());
        }
        if client.observe_start(&identity)?.is_some() {
            return Err("fast-terminal receipt survived acknowledgement".into());
        }
        let report = supervisor.shutdown()?;
        drop(supervisor);
        fs::remove_dir_all(&root)?;
        if !report.events().is_empty() {
            return Err("fast-terminal duplicate left a terminal event at shutdown".into());
        }
        Ok(())
    }

    #[test]
    fn rejected_start_retains_exact_failure_receipt_until_acknowledged()
    -> Result<(), Box<dyn std::error::Error>> {
        if nested_sandbox_execution_is_unavailable() {
            return Ok(());
        }
        let (root, layout) = fixture()?;
        let _root_guard = FixtureRootGuard(root.clone());
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(160));
        let request = request(161, workspace_id, "/bin/sleep", &["30"], 30_000)?;
        let identity =
            SupervisorStartIdentity::capture(&layout, &request, ExecutionLaunchKind::RustCi, None)?;
        let mut supervisor = ExecutionSupervisor::start(1)?;
        let client = supervisor.client();
        let result = client.start_execution_with_identity(
            identity,
            layout.clone(),
            request.clone(),
            ExecutionLaunchKind::RustCi,
            None,
            None,
        );
        if !matches!(result, Err(ExecutionSupervisorError::Execution(_))) {
            return Err("missing Rust CI capability did not reject before spawn".into());
        }
        let receipt = client
            .observe_start(&identity)?
            .ok_or("known rejected Start receipt was not retained")?;
        if receipt.outcome()
            != (SupervisorStartOutcome::Rejected {
                failure_code: ExecutionFailureCode::Admission,
            })
        {
            return Err("rejected Start receipt did not retain Admission".into());
        }
        if !matches!(
            client.start_execution_with_identity(
                identity,
                layout.clone(),
                request,
                ExecutionLaunchKind::RustCi,
                None,
                None,
            ),
            Err(ExecutionSupervisorError::StartRejected {
                failure_code: ExecutionFailureCode::Admission
            })
        ) {
            return Err("exact rejected Start did not converge to its retained outcome".into());
        }
        let mismatched = SupervisorStartIdentity {
            workspace_id: WorkspaceId::from_uuid(Uuid::from_u128(162)),
            ..identity
        };
        if !matches!(
            client.observe_start(&mismatched),
            Err(ExecutionSupervisorError::StartIdentityMismatch { .. })
        ) {
            return Err("mismatched receipt observation did not fail closed".into());
        }
        if !client.acknowledge_start(&identity)? {
            return Err("rejected Start receipt acknowledgement was not recorded".into());
        }
        if client.observe_start(&identity)?.is_some() {
            return Err("rejected Start receipt survived exact acknowledgement".into());
        }
        let report = supervisor.shutdown()?;
        drop(supervisor);
        fs::remove_dir_all(&root)?;
        if !report.events().is_empty() {
            return Err("rejected Start unexpectedly produced a terminal event".into());
        }
        Ok(())
    }

    #[test]
    fn native_pre_spawn_rejection_proof_covers_root_and_draining_branches()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, layout) = fixture()?;
        let _root_guard = FixtureRootGuard(root);

        let (_sender, receiver) = mpsc::sync_channel(1);
        let mut root_runtime = SupervisorRuntime::new(
            ExecutionRunner::new(1)?,
            receiver,
            Arc::new(AtomicBool::new(true)),
        );
        let root_request = request(
            16_100,
            WorkspaceId::from_uuid(Uuid::from_u128(16_101)),
            "/bin/true",
            &[],
            2_000,
        )?;
        let root_identity = SupervisorStartIdentity::capture(
            &layout,
            &root_request,
            ExecutionLaunchKind::Baseline,
            None,
        )?;
        let changed_root = SupervisorStartIdentity {
            root_fingerprint: WorkspaceRootFingerprint::from_bytes([0xB6; 16]),
            ..root_identity
        };
        assert!(matches!(
            root_runtime.start_execution(
                &layout,
                changed_root,
                root_request,
                ExecutionLaunchKind::Baseline,
                None,
                false,
                None,
            ),
            Err(ExecutionSupervisorError::Execution(_))
        ));
        let _root_proof = assert_pre_spawn_proof(
            &root_runtime,
            changed_root,
            ExecutionFailureCode::InvalidWorkingDirectory,
        )?;

        let (_sender, receiver) = mpsc::sync_channel(1);
        let mut draining_runtime = SupervisorRuntime::new(
            ExecutionRunner::new(1)?,
            receiver,
            Arc::new(AtomicBool::new(true)),
        );
        let (stop_response, _stop_result) = mpsc::sync_channel(0);
        draining_runtime.stop_waiters.push(StopWaiter {
            cancelled: 0,
            response: stop_response,
        });
        let draining_request = request(
            16_110,
            WorkspaceId::from_uuid(Uuid::from_u128(16_111)),
            "/bin/true",
            &[],
            2_000,
        )?;
        let draining_identity = SupervisorStartIdentity::capture(
            &layout,
            &draining_request,
            ExecutionLaunchKind::Baseline,
            None,
        )?;
        assert!(matches!(
            draining_runtime.start_execution(
                &layout,
                draining_identity,
                draining_request,
                ExecutionLaunchKind::Baseline,
                None,
                false,
                None,
            ),
            Err(ExecutionSupervisorError::Draining)
        ));
        let _draining_proof = assert_pre_spawn_proof(
            &draining_runtime,
            draining_identity,
            ExecutionFailureCode::Admission,
        )?;
        Ok(())
    }

    #[test]
    fn native_pre_spawn_rejection_proof_covers_backlog_and_generation_branches()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, layout) = fixture()?;
        let _root_guard = FixtureRootGuard(root);

        let (_sender, receiver) = mpsc::sync_channel(1);
        let mut backlog_runtime = SupervisorRuntime::new(
            ExecutionRunner::new(1)?,
            receiver,
            Arc::new(AtomicBool::new(true)),
        );
        let owner = backlog_runtime.owner.clone();
        for index in 0..MAX_COMPLETION_BACKLOG {
            backlog_runtime.events.push_back(synthetic_terminal_event(
                &owner,
                16_200 + u128::try_from(index)?,
            ));
        }
        let backlog_request = request(
            16_300,
            WorkspaceId::from_uuid(Uuid::from_u128(16_301)),
            "/bin/true",
            &[],
            2_000,
        )?;
        let backlog_identity = SupervisorStartIdentity::capture(
            &layout,
            &backlog_request,
            ExecutionLaunchKind::Baseline,
            None,
        )?;
        assert!(matches!(
            backlog_runtime.start_execution(
                &layout,
                backlog_identity,
                backlog_request,
                ExecutionLaunchKind::Baseline,
                None,
                false,
                None,
            ),
            Err(ExecutionSupervisorError::CompletionBacklog)
        ));
        let _backlog_proof = assert_pre_spawn_proof(
            &backlog_runtime,
            backlog_identity,
            ExecutionFailureCode::Admission,
        )?;

        let (_sender, receiver) = mpsc::sync_channel(1);
        let mut generation_runtime = SupervisorRuntime::new(
            ExecutionRunner::new(1)?,
            receiver,
            Arc::new(AtomicBool::new(true)),
        );
        generation_runtime.next_terminal_generation = u64::MAX;
        let generation_request = request(
            16_310,
            WorkspaceId::from_uuid(Uuid::from_u128(16_311)),
            "/bin/true",
            &[],
            2_000,
        )?;
        let generation_identity = SupervisorStartIdentity::capture(
            &layout,
            &generation_request,
            ExecutionLaunchKind::Baseline,
            None,
        )?;
        assert!(matches!(
            generation_runtime.start_execution(
                &layout,
                generation_identity,
                generation_request,
                ExecutionLaunchKind::Baseline,
                None,
                false,
                None,
            ),
            Err(ExecutionSupervisorError::TerminalEventGenerationExhausted { .. })
        ));
        let _generation_proof = assert_pre_spawn_proof(
            &generation_runtime,
            generation_identity,
            ExecutionFailureCode::Admission,
        )?;
        Ok(())
    }

    #[test]
    fn native_pre_spawn_rejection_proof_rejects_foreign_restart_and_accepted_starts()
    -> Result<(), Box<dyn std::error::Error>> {
        if nested_sandbox_execution_is_unavailable() {
            return Ok(());
        }
        let (root, layout) = fixture()?;
        let _root_guard = FixtureRootGuard(root);
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(16_400));
        let accepted_request = request(16_401, workspace_id, "/bin/true", &[], 2_000)?;
        let identity = SupervisorStartIdentity::capture(
            &layout,
            &accepted_request,
            ExecutionLaunchKind::Baseline,
            None,
        )?;
        let changed_root = SupervisorStartIdentity {
            root_fingerprint: WorkspaceRootFingerprint::from_bytes([0xC7; 16]),
            ..identity
        };

        let mut supervisor = ExecutionSupervisor::start(1)?;
        let client = supervisor.client();
        assert!(matches!(
            client.start_execution_with_identity(
                changed_root,
                layout.clone(),
                accepted_request.clone(),
                ExecutionLaunchKind::Baseline,
                None,
                None,
            ),
            Err(ExecutionSupervisorError::Execution(_))
        ));
        let proof = client
            .observe_native_rejection(&changed_root)?
            .ok_or("root rejection proof was not retained")?;
        assert_eq!(proof.identity(), changed_root);
        assert_eq!(
            proof.failure_code(),
            ExecutionFailureCode::InvalidWorkingDirectory
        );
        assert!(client.owns_native_rejection(&proof));

        let mut foreign = ExecutionSupervisor::start(1)?;
        let foreign_client = foreign.client();
        assert!(!foreign_client.owns_native_rejection(&proof));
        assert!(
            foreign_client
                .observe_native_rejection(&changed_root)?
                .is_none()
        );
        let _foreign_report = foreign.shutdown()?;

        assert!(client.acknowledge_start(&changed_root)?);
        assert!(client.observe_native_rejection(&changed_root)?.is_none());

        let mut restarted = ExecutionSupervisor::start(1)?;
        let restarted_client = restarted.client();
        assert!(!restarted_client.owns_native_rejection(&proof));
        assert!(
            restarted_client
                .observe_native_rejection(&changed_root)?
                .is_none()
        );
        let _restarted_report = restarted.shutdown()?;

        let _first_report = supervisor.shutdown()?;

        let mut accepted = ExecutionSupervisor::start(1)?;
        let accepted_client = accepted.client();
        let accepted_id =
            accepted_client.start_execution(layout.clone(), accepted_request.clone())?;
        assert!(
            accepted_client
                .observe_native_rejection(&identity)?
                .is_none()
        );
        let accepted_event = wait_for_retained_terminal_event(&accepted_client, accepted_id)?;
        assert!(
            accepted_client
                .acknowledge_terminal_event(&accepted_event.key(), &accepted_event.identity())?
        );
        assert!(accepted_client.acknowledge_start(&identity)?);
        let _accepted_report = accepted.shutdown()?;
        Ok(())
    }

    #[test]
    fn native_pre_spawn_rejection_proof_rejects_rust_ci_and_runner_errors()
    -> Result<(), Box<dyn std::error::Error>> {
        if nested_sandbox_execution_is_unavailable() {
            return Ok(());
        }
        let (root, layout) = fixture()?;
        let _root_guard = FixtureRootGuard(root);
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(16_400));
        let accepted_request = request(16_401, workspace_id, "/bin/true", &[], 2_000)?;

        let mut rust_ci = ExecutionSupervisor::start(1)?;
        let rust_ci_client = rust_ci.client();
        let rust_ci_identity = SupervisorStartIdentity::capture(
            &layout,
            &accepted_request,
            ExecutionLaunchKind::RustCi,
            None,
        )?;
        assert!(matches!(
            rust_ci_client.start_execution_with_identity(
                rust_ci_identity,
                layout.clone(),
                accepted_request.clone(),
                ExecutionLaunchKind::RustCi,
                None,
                None,
            ),
            Err(ExecutionSupervisorError::Execution(_))
        ));
        assert!(
            rust_ci_client
                .observe_native_rejection(&rust_ci_identity)?
                .is_none()
        );
        assert!(rust_ci_client.acknowledge_start(&rust_ci_identity)?);
        let _rust_ci_report = rust_ci.shutdown()?;

        let mut runner_error = ExecutionSupervisor::start(1)?;
        let runner_error_client = runner_error.client();
        let runner_error_request = request(16_402, workspace_id, "/bin/true", &[], 2_000)?;
        let runner_error_request = ExecutionRequest::new(
            forge_domain::ExecutionAttribution::new(
                runner_error_request.id(),
                runner_error_request.workspace_id(),
                runner_error_request.activity_id(),
            ),
            runner_error_request.kind().clone(),
            Some(forge_domain::WorkspaceRelativePath::new(PathBuf::from(
                "missing-runner-working-directory",
            ))?),
            ExecutionLimits::new(
                runner_error_request.timeout(),
                runner_error_request.output_limit(),
            ),
            runner_error_request.permissions(),
        )?;
        let runner_error_identity = SupervisorStartIdentity::capture(
            &layout,
            &runner_error_request,
            ExecutionLaunchKind::Baseline,
            None,
        )?;
        assert!(matches!(
            runner_error_client.start_execution_with_identity(
                runner_error_identity,
                layout,
                runner_error_request,
                ExecutionLaunchKind::Baseline,
                None,
                None,
            ),
            Err(ExecutionSupervisorError::Execution(_))
        ));
        assert!(
            runner_error_client
                .observe_native_rejection(&runner_error_identity)?
                .is_none()
        );
        assert!(runner_error_client.acknowledge_start(&runner_error_identity)?);
        let _runner_error_report = runner_error.shutdown()?;
        Ok(())
    }

    #[test]
    fn start_receipt_capacity_rejects_before_runner_spawn() -> Result<(), Box<dyn std::error::Error>>
    {
        let (root, layout) = fixture()?;
        let _root_guard = FixtureRootGuard(root.clone());
        let (_sender, receiver) = mpsc::sync_channel(1);
        let mut runtime = SupervisorRuntime::new(
            ExecutionRunner::new(1)?,
            receiver,
            Arc::new(AtomicBool::new(true)),
        );
        for index in 0..MAX_START_RECEIPTS {
            let identity = synthetic_identity(10_000 + u128::try_from(index)?);
            runtime.start_receipts.insert(
                identity.execution_id(),
                SupervisorStartReceipt::accepted(identity),
            );
        }
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(170));
        let request = request(171, workspace_id, "/bin/true", &[], 2_000)?;
        let identity = SupervisorStartIdentity::capture(
            &layout,
            &request,
            ExecutionLaunchKind::Baseline,
            None,
        )?;
        let result = runtime.start_execution(
            &layout,
            identity,
            request,
            ExecutionLaunchKind::Baseline,
            None,
            false,
            None,
        );
        if !matches!(result, Err(ExecutionSupervisorError::StartReceiptCapacity)) {
            return Err("full Start receipt ledger did not reject before spawn".into());
        }
        if !runtime.active.is_empty() {
            return Err("receipt saturation admitted a runner".into());
        }
        drop(runtime);
        fs::remove_dir_all(&root)?;
        Ok(())
    }

    #[test]
    fn active_duplicate_reuses_pending_receipt_when_ledger_is_full()
    -> Result<(), Box<dyn std::error::Error>> {
        if nested_sandbox_execution_is_unavailable() {
            return Ok(());
        }
        let (root, layout) = fixture()?;
        let _root_guard = FixtureRootGuard(root.clone());
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(175));
        let active_request = request(176, workspace_id, "/bin/sleep", &["30"], 30_000)?;
        let identity = SupervisorStartIdentity::capture(
            &layout,
            &active_request,
            ExecutionLaunchKind::Baseline,
            None,
        )?;
        let mut supervisor = ExecutionSupervisor::start(1)?;
        let client = supervisor.client();
        let execution_id = client.start_execution(layout.clone(), active_request.clone())?;
        if !client.acknowledge_start(&identity)? {
            return Err("initial active receipt acknowledgement was not recorded".into());
        }
        for index in 0..MAX_START_RECEIPTS {
            let rejected_workspace =
                WorkspaceId::from_uuid(Uuid::from_u128(20_000 + u128::try_from(index)?));
            let rejected = client.start_execution_with_launch_kind(
                layout.clone(),
                request(
                    21_000 + u128::try_from(index)?,
                    rejected_workspace,
                    "/bin/true",
                    &[],
                    2_000,
                )?,
                ExecutionLaunchKind::RustCi,
                None,
            );
            if !matches!(rejected, Err(ExecutionSupervisorError::Execution(_))) {
                return Err("receipt saturation setup did not retain a known rejection".into());
            }
        }
        let duplicate = client.start_execution_with_identity(
            identity,
            layout.clone(),
            active_request.clone(),
            ExecutionLaunchKind::Baseline,
            None,
            None,
        )?;
        if duplicate != execution_id {
            return Err("active duplicate changed execution identity".into());
        }
        let receipt = client
            .observe_start(&identity)?
            .ok_or("active fallback receipt was not observable")?;
        if receipt.outcome() != SupervisorStartOutcome::Accepted {
            return Err("active fallback receipt was not Accepted".into());
        }
        if !client.acknowledge_start(&identity)? {
            return Err("active fallback receipt acknowledgement was not recorded".into());
        }
        if !client.cancel_execution(execution_id)? {
            return Err("active duplicate test lost the original child owner".into());
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut terminal_count = 0;
        while terminal_count == 0 {
            terminal_count += take_terminal_events(&client, 8)?
                .into_iter()
                .filter(|event| event.execution_id() == execution_id)
                .count();
            if terminal_count == 0 && Instant::now() >= deadline {
                return Err("active duplicate test terminal event did not arrive".into());
            }
            if terminal_count == 0 {
                thread::yield_now();
            }
        }
        if client.observe_start(&identity)?.is_some() {
            return Err("active fallback receipt survived exact acknowledgement".into());
        }
        let extra = take_terminal_events(&client, 8)?;
        if extra
            .iter()
            .any(|event| event.execution_id() == execution_id)
        {
            return Err("active duplicate produced a second terminal event".into());
        }
        let report = supervisor.shutdown()?;
        drop(supervisor);
        fs::remove_dir_all(&root)?;
        if !report.events().is_empty() {
            return Err("active duplicate test left a terminal event at shutdown".into());
        }
        Ok(())
    }

    #[test]
    fn semantic_identity_mismatch_does_not_reserve_and_root_mismatch_is_rejected()
    -> Result<(), Box<dyn std::error::Error>> {
        if nested_sandbox_execution_is_unavailable() {
            return Ok(());
        }
        let (root, layout) = fixture()?;
        let _root_guard = FixtureRootGuard(root.clone());
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(185));
        let execution_request = request(186, workspace_id, "/usr/bin/true", &[], 2_000)?;
        let identity = SupervisorStartIdentity::capture(
            &layout,
            &execution_request,
            ExecutionLaunchKind::Baseline,
            None,
        )?;
        let malformed = SupervisorStartIdentity {
            activity_id: ActivityId::from_uuid(Uuid::from_u128(999)),
            ..identity
        };
        let mut supervisor = ExecutionSupervisor::start(1)?;
        let client = supervisor.client();
        expect_baseline_identity_mismatch(
            &client,
            malformed,
            layout.clone(),
            execution_request.clone(),
        )?;
        if client.observe_start(&malformed)?.is_some() {
            return Err("semantic identity mismatch reserved a receipt".into());
        }
        let execution_id = client.start_execution(layout.clone(), execution_request.clone())?;
        wait_for_terminal_event(&client, execution_id)?;
        let changed_request = request(186, workspace_id, "/usr/bin/printf", &["changed"], 2_000)?;
        expect_baseline_identity_mismatch(&client, identity, layout.clone(), changed_request)?;
        if client.observe_start(&identity)?.is_none() {
            return Err("changed request disturbed the retained receipt".into());
        }
        if !client.acknowledge_start(&identity)? {
            return Err("correct identity receipt acknowledgement failed".into());
        }

        let root_request = request(188, workspace_id, "/usr/bin/true", &[], 2_000)?;
        let root_identity = SupervisorStartIdentity::capture(
            &layout,
            &root_request,
            ExecutionLaunchKind::Baseline,
            None,
        )?;
        let changed_root = SupervisorStartIdentity {
            root_fingerprint: WorkspaceRootFingerprint::from_bytes([0xA5; 16]),
            ..root_identity
        };
        if !matches!(
            client.start_execution_with_identity(
                changed_root,
                layout.clone(),
                root_request.clone(),
                ExecutionLaunchKind::Baseline,
                None,
                None,
            ),
            Err(ExecutionSupervisorError::Execution(_))
        ) {
            return Err("semantically valid root mismatch did not reject at native owner".into());
        }
        let rejected = client
            .observe_start(&changed_root)?
            .ok_or("root mismatch rejection did not retain its receipt")?;
        if rejected.outcome()
            != (SupervisorStartOutcome::Rejected {
                failure_code: ExecutionFailureCode::InvalidWorkingDirectory,
            })
        {
            return Err("root mismatch rejection retained the wrong failure code".into());
        }
        if !client.acknowledge_start(&changed_root)? {
            return Err("root mismatch rejection acknowledgement failed".into());
        }
        let root_execution_id = client.start_execution_with_identity(
            root_identity,
            layout,
            root_request,
            ExecutionLaunchKind::Baseline,
            None,
            None,
        )?;
        wait_for_terminal_event(&client, root_execution_id)?;
        let report = supervisor.shutdown()?;
        drop(supervisor);
        fs::remove_dir_all(&root)?;
        if !report.events().is_empty() {
            return Err("identity validation regression left terminal events at shutdown".into());
        }
        Ok(())
    }

    #[test]
    fn owner_semantic_fence_preserves_retained_active_start()
    -> Result<(), Box<dyn std::error::Error>> {
        if nested_sandbox_execution_is_unavailable() {
            return Ok(());
        }
        let (root, layout) = fixture()?;
        let _root_guard = FixtureRootGuard(root.clone());
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(205));
        let original_request = request(206, workspace_id, "/bin/sleep", &["30"], 30_000)?;
        let identity = SupervisorStartIdentity::capture(
            &layout,
            &original_request,
            ExecutionLaunchKind::Baseline,
            None,
        )?;
        let mut supervisor = ExecutionSupervisor::start(1)?;
        let client = supervisor.client();
        let execution_id = client.start_execution(layout.clone(), original_request.clone())?;

        let malformed_identity = SupervisorStartIdentity {
            activity_id: ActivityId::from_uuid(Uuid::from_u128(999)),
            ..identity
        };
        let key_result = dispatch_raw_start(
            &client,
            malformed_identity,
            layout.clone(),
            original_request.clone(),
        )?;
        if !matches!(
            key_result,
            Err(ExecutionSupervisorError::StartIdentityMismatch { .. })
        ) {
            return Err("owner accepted a malformed retained identity key".into());
        }
        let changed_request = request(206, workspace_id, "/usr/bin/printf", &["changed"], 2_000)?;
        let payload_result =
            dispatch_raw_start(&client, identity, layout.clone(), changed_request)?;
        if !matches!(
            payload_result,
            Err(ExecutionSupervisorError::StartIdentityMismatch { .. })
        ) {
            return Err("owner converged a changed retained request payload".into());
        }
        let receipt = client
            .observe_start(&identity)?
            .ok_or("owner semantic rejection lost the original receipt")?;
        if receipt.outcome() != SupervisorStartOutcome::Accepted {
            return Err("owner semantic rejection changed the original outcome".into());
        }
        if !client.cancel_execution(execution_id)? {
            return Err("owner semantic rejection lost the original child".into());
        }
        wait_for_terminal_event(&client, execution_id)?;
        if !client.acknowledge_start(&identity)? {
            return Err("owner semantic regression receipt acknowledgement failed".into());
        }
        let report = supervisor.shutdown()?;
        drop(supervisor);
        fs::remove_dir_all(&root)?;
        if !report.events().is_empty() {
            return Err("owner semantic regression left a terminal event at shutdown".into());
        }
        Ok(())
    }

    #[test]
    fn acknowledgement_reply_loss_releases_only_the_exact_receipt()
    -> Result<(), Box<dyn std::error::Error>> {
        if nested_sandbox_execution_is_unavailable() {
            return Ok(());
        }
        let (root, layout) = fixture()?;
        let _root_guard = FixtureRootGuard(root.clone());
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(180));
        let request = request(181, workspace_id, "/usr/bin/true", &[], 2_000)?;
        let identity = SupervisorStartIdentity::capture(
            &layout,
            &request,
            ExecutionLaunchKind::Baseline,
            None,
        )?;
        let mut supervisor = ExecutionSupervisor::start(1)?;
        let client = supervisor.client();
        client.start_execution(layout, request)?;
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if take_terminal_events(&client, 8)?
                .into_iter()
                .any(|event| event.execution_id() == identity.execution_id())
            {
                break;
            }
            if Instant::now() >= deadline {
                return Err("fast terminal Start did not produce an event".into());
            }
            thread::yield_now();
        }
        if client.observe_start(&identity)?.is_none() {
            return Err("fast terminal Start receipt was not retained".into());
        }

        let ack_proxy = AckReplyDropProxy::new(&client);
        let ack_result = ack_proxy.client().acknowledge_start(&identity);
        ack_proxy.finish()?;
        let Err(client_error) = ack_result else {
            return Err("dropped acknowledgement reply unexpectedly succeeded".into());
        };
        if !matches!(client_error, ExecutionSupervisorError::ReplyDropped) {
            return Err(format!("unexpected acknowledgement loss error: {client_error:?}").into());
        }
        if client.observe_start(&identity)?.is_some() {
            return Err("acknowledgement reply loss did not release the exact receipt".into());
        }
        let report = supervisor.shutdown()?;
        drop(supervisor);
        fs::remove_dir_all(&root)?;
        if !report.events().is_empty() {
            return Err("acknowledgement reply-loss test retained a terminal event".into());
        }
        Ok(())
    }

    #[test]
    fn workspace_cancel_is_scoped_and_completion_backpressure_is_bounded()
    -> Result<(), Box<dyn std::error::Error>> {
        if nested_sandbox_execution_is_unavailable() {
            return Ok(());
        }
        let (root, layout) = fixture()?;
        let first_workspace = WorkspaceId::from_uuid(Uuid::from_u128(200));
        let second_workspace = WorkspaceId::from_uuid(Uuid::from_u128(201));
        let mut supervisor = ExecutionSupervisor::start(2)?;
        let client = supervisor.client();
        client.start_execution(
            layout.clone(),
            request(202, first_workspace, "/bin/sleep", &["30"], 30_000)?,
        )?;
        client.start_execution(
            layout,
            request(204, second_workspace, "/bin/sleep", &["30"], 30_000)?,
        )?;
        assert_eq!(client.cancel_workspace(first_workspace)?, 1);
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        let first = loop {
            let events = take_terminal_events(&client, 8)?;
            if !events.is_empty() {
                break events;
            }
            if std::time::Instant::now() >= deadline {
                return Err("scoped cancel did not complete".into());
            }
            thread::sleep(POLL_INTERVAL);
        };
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].workspace_id(), first_workspace);
        assert_eq!(client.stop_all()?, 1);
        assert_eq!(take_terminal_events(&client, 8)?.len(), 1);
        let report = supervisor.shutdown()?;
        assert_eq!(report.active_cancelled(), 0);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn cancellation_keeps_incremental_output_and_terminal_events_separate()
    -> Result<(), Box<dyn std::error::Error>> {
        if nested_sandbox_execution_is_unavailable() {
            return Ok(());
        }
        let (root, layout) = fixture()?;
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(300));
        let mut supervisor = ExecutionSupervisor::start(1)?;
        let client = supervisor.client();
        let id = client.start_execution(
            layout,
            shell_request(
                301,
                workspace_id,
                "printf ready; exec /bin/sleep 30",
                30_000,
                1_024,
            )?,
        )?;

        let output_deadline = Instant::now() + Duration::from_secs(2);
        let output = loop {
            let read = client.read_output_events(8)?;
            if !read.events().is_empty() {
                let output = read.events().to_vec();
                let ack_key = read.ack_key().ok_or("missing output acknowledgement key")?;
                assert!(client.has_pending_output(id)?);
                assert_eq!(client.ack_output_events(ack_key)?, output.len());
                break output;
            }
            if Instant::now() >= output_deadline {
                return Err("incremental output did not arrive".into());
            }
            thread::yield_now();
        };
        assert!(
            output.iter().any(|event| {
                matches!(
                    event,
                    ExecutionOutputEvent::Chunk(chunk)
                        if chunk.execution_id() == id
                            && chunk.stream() == crate::ExecutionOutputStream::Stdout
                            && chunk.bytes() == b"ready"
                )
            }),
            "unexpected output events: {output:?}"
        );

        assert!(client.cancel_execution(id)?);
        let terminal_deadline = Instant::now() + Duration::from_secs(2);
        let terminal = loop {
            let events = take_terminal_events(&client, 8)?;
            if let Some(event) = events.into_iter().find(|event| event.execution_id() == id) {
                break event;
            }
            if Instant::now() >= terminal_deadline {
                return Err("cancelled execution did not report a terminal event".into());
            }
            thread::yield_now();
        };
        assert!(matches!(
            terminal.result(),
            Ok(outcome) if outcome.status() == forge_domain::ExecutionCompletionStatus::Cancelled
        ));
        assert!(!client.has_pending_output(id)?);
        let report = supervisor.shutdown()?;
        assert!(report.events().is_empty());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn output_read_replays_until_exact_prefix_acknowledgement()
    -> Result<(), Box<dyn std::error::Error>> {
        if nested_sandbox_execution_is_unavailable() {
            return Ok(());
        }
        let (root, layout) = fixture()?;
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(400));
        let mut supervisor = ExecutionSupervisor::start(1)?;
        let client = supervisor.client();
        let id = client.start_execution(
            layout,
            request(401, workspace_id, "/usr/bin/printf", &["replay"], 2_000)?,
        )?;

        let deadline = Instant::now() + Duration::from_secs(2);
        let first = loop {
            let read = client.read_output_events(8)?;
            if !read.events().is_empty() {
                break read;
            }
            if Instant::now() >= deadline {
                return Err("output read did not produce a prefix".into());
            }
            thread::yield_now();
        };
        let key = first
            .ack_key()
            .ok_or("missing output acknowledgement key")?;
        let mismatched = ExecutionOutputEventKey::new(
            ExecutionId::from_uuid(Uuid::from_u128(402)),
            key.sequence(),
        );
        assert!(matches!(
            client.ack_output_events(mismatched),
            Err(ExecutionSupervisorError::OutputAckMismatch { .. })
        ));
        assert_eq!(client.read_output_events(8)?, first);
        assert_eq!(client.ack_output_events(key)?, first.events().len());

        let report = supervisor.shutdown()?;
        assert_eq!(report.events().len(), 1);
        assert_eq!(report.events()[0].execution_id(), id);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn workspace_quiescence_retains_terminal_owner_until_output_and_start_ack()
    -> Result<(), Box<dyn std::error::Error>> {
        if nested_sandbox_execution_is_unavailable() {
            return Ok(());
        }
        let (root, layout) = fixture()?;
        let _root_guard = FixtureRootGuard(root);
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(42_000));
        let request = shell_request(
            42_001,
            workspace_id,
            "printf quiescence-output",
            2_000,
            1_024,
        )?;
        let mut supervisor = ExecutionSupervisor::start(1)?;
        let client = supervisor.client();
        assert!(client.observe_workspace_quiescence(workspace_id)?.is_some());
        let execution_id = client.start_execution(layout, request)?;
        let event = wait_for_retained_terminal_event(&client, execution_id)?;
        assert!(client.observe_workspace_quiescence(workspace_id)?.is_none());
        assert!(client.acknowledge_start(&event.identity())?);
        let output = client.read_output_events(MAX_OUTPUT_EVENT_BACKLOG)?;
        assert!(!output.events().is_empty());
        assert!(client.acknowledge_terminal_event(&event.key(), &event.identity())?);
        assert!(
            client.observe_workspace_quiescence(workspace_id)?.is_none(),
            "terminal ACK must retain the owner while its output prefix is unacknowledged"
        );
        let _acked = client.ack_output_events(output.ack_key().ok_or("output key missing")?)?;
        let deadline = Instant::now() + Duration::from_secs(2);
        let proof = loop {
            if let Some(proof) = client.observe_workspace_quiescence(workspace_id)? {
                break proof;
            }
            if Instant::now() >= deadline {
                return Err("Workspace did not quiesce after exact ACKs".into());
            }
            thread::yield_now();
        };
        assert_eq!(proof.workspace_id(), workspace_id);
        assert!(client.owns_workspace_quiescence(&proof));
        let mut foreign = ExecutionSupervisor::start(1)?;
        assert!(!foreign.client().owns_workspace_quiescence(&proof));
        let _foreign_shutdown = foreign.shutdown()?;
        let _shutdown = supervisor.shutdown()?;
        assert!(!client.owns_workspace_quiescence(&proof));
        assert!(matches!(
            client.observe_workspace_quiescence(workspace_id),
            Err(ExecutionSupervisorError::Closed)
        ));
        Ok(())
    }

    #[test]
    fn workspace_quiescence_rejects_uncertain_cleanup_and_nil_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_sender, receiver) = mpsc::sync_channel(1);
        let mut runtime = SupervisorRuntime::new(
            ExecutionRunner::new(1)?,
            receiver,
            Arc::new(AtomicBool::new(true)),
        );
        let workspace = WorkspaceId::from_uuid(Uuid::from_u128(42_100));
        assert!(additional_quiescence_uncertainty(
            ExecutionLaunchKind::Baseline,
            Some(ProcessFinalization::ReapUnconfirmed),
            false,
            false
        ));
        assert!(!additional_quiescence_uncertainty(
            ExecutionLaunchKind::Baseline,
            Some(ProcessFinalization::NoChildSpawned),
            true,
            false
        ));
        assert!(additional_quiescence_uncertainty(
            ExecutionLaunchKind::RustCiGeneratedPackage,
            Some(ProcessFinalization::ProcessGroupReaped),
            true,
            false
        ));
        assert!(!additional_quiescence_uncertainty(
            ExecutionLaunchKind::RustCiGeneratedPackage,
            Some(ProcessFinalization::ProcessGroupReaped),
            false,
            true
        ));
        runtime.finalize_rust_ci_workspace(
            workspace,
            Some(ProcessFinalization::ReapUnconfirmed),
            Some(RustCiRuntimeFinalization::Preserved),
        );
        assert!(runtime.observe_workspace_quiescence(workspace).is_none());
        assert!(
            runtime
                .observe_workspace_quiescence(WorkspaceId::from_uuid(Uuid::from_u128(42_101)))
                .is_some()
        );
        runtime.rust_ci_quarantine_saturated = true;
        assert!(
            runtime
                .observe_workspace_quiescence(WorkspaceId::from_uuid(Uuid::from_u128(42_101)))
                .is_none()
        );
        let mut supervisor = ExecutionSupervisor::start(1)?;
        assert!(matches!(
            supervisor
                .client()
                .observe_workspace_quiescence(WorkspaceId::from_uuid(Uuid::nil())),
            Err(ExecutionSupervisorError::InvalidWorkspaceIdentity)
        ));
        let _shutdown = supervisor.shutdown()?;
        Ok(())
    }

    #[test]
    fn native_closure_waits_for_output_handoff_and_disappears_after_terminal_ack()
    -> Result<(), Box<dyn std::error::Error>> {
        if nested_sandbox_execution_is_unavailable() {
            return Ok(());
        }
        let (root, layout) = fixture()?;
        let _root_guard = FixtureRootGuard(root);
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(41_000));
        let request = shell_request(41_001, workspace_id, "printf native-closure", 2_000, 1_024)?;
        let mut supervisor = ExecutionSupervisor::start(1)?;
        let client = supervisor.client();
        let execution_id = client.start_execution(layout, request)?;

        let terminal = wait_for_retained_terminal_event(&client, execution_id)?;
        let output_deadline = Instant::now() + Duration::from_secs(2);
        let output_read = loop {
            let read = client.read_output_events(8)?;
            if read.events().iter().any(|event| {
                matches!(
                    event,
                    ExecutionOutputEvent::Chunk(chunk)
                        if chunk.execution_id() == execution_id
                            && chunk.stream() == crate::ExecutionOutputStream::Stdout
                            && chunk.bytes() == b"native-closure"
                )
            }) {
                break read;
            }
            if Instant::now() >= output_deadline {
                return Err("native-closure output did not arrive".into());
            }
            thread::yield_now();
        };
        assert!(
            client.observe_native_closure(&terminal)?.is_none(),
            "unacknowledged output must prevent native closure proof"
        );
        let output_key = output_read
            .ack_key()
            .ok_or("native-closure output read had no acknowledgement key")?;
        assert_eq!(
            client.ack_output_events(output_key)?,
            output_read.events().len()
        );
        let output_last_sequence = output_read
            .events()
            .iter()
            .filter(|event| event.execution_id() == execution_id)
            .map(ExecutionOutputEvent::sequence)
            .max()
            .ok_or("native-closure output had no final sequence")?;

        let closure_deadline = Instant::now() + Duration::from_secs(2);
        let closure = loop {
            if let Some(closure) = client.observe_native_closure(&terminal)? {
                break closure;
            }
            if Instant::now() >= closure_deadline {
                return Err("native closure proof did not arrive after output ACK".into());
            }
            thread::yield_now();
        };
        assert_eq!(closure.event(), &terminal);
        assert_eq!(closure.identity(), terminal.identity());
        assert_eq!(closure.key(), terminal.key());
        assert_eq!(
            closure.process_disposition(),
            ProcessDisposition::ProcessGroupReaped
        );
        assert_eq!(
            closure.runtime_disposition(),
            RuntimeDisposition::NotApplicable
        );
        assert!(matches!(
            closure.result(),
            Ok(outcome) if outcome.status() == forge_domain::ExecutionCompletionStatus::Exited
        ));
        assert_eq!(closure.generated_package(), None);
        assert_eq!(closure.output_cursor().execution_id(), execution_id);
        assert_eq!(
            closure.output_cursor().after_sequence(),
            output_last_sequence.get()
        );

        assert!(client.acknowledge_terminal_event(&terminal.key(), &terminal.identity())?);
        assert_eq!(client.observe_native_closure(&terminal)?, None);
        let report = supervisor.shutdown()?;
        assert!(report.events().is_empty());
        assert!(report.output_events().is_empty());
        Ok(())
    }

    #[test]
    fn native_closure_owner_fence_rejects_same_identity_on_another_supervisor()
    -> Result<(), Box<dyn std::error::Error>> {
        if nested_sandbox_execution_is_unavailable() {
            return Ok(());
        }
        let (root, layout) = fixture()?;
        let _root_guard = FixtureRootGuard(root);
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(41_100));
        let request = request(41_101, workspace_id, "/usr/bin/true", &[], 2_000)?;
        let mut first = ExecutionSupervisor::start(1)?;
        let mut second = ExecutionSupervisor::start(1)?;
        let first_client = first.client();
        let second_client = second.client();
        let first_id = first_client.start_execution(layout.clone(), request.clone())?;
        let second_id = second_client.start_execution(layout, request)?;
        let first_event = wait_for_retained_terminal_event(&first_client, first_id)?;
        let second_event = wait_for_retained_terminal_event(&second_client, second_id)?;

        assert_eq!(first_event.execution_id(), second_event.execution_id());
        assert_eq!(first_event.identity(), second_event.identity());
        assert_ne!(first_event.key(), second_event.key());
        assert_eq!(first_event.key().generation, second_event.key().generation);
        assert!(matches!(
            second_client.observe_terminal_event(&first_event.key(), &first_event.identity()),
            Err(ExecutionSupervisorError::TerminalEventOwnerMismatch { execution_id })
                if execution_id == second_id
        ));
        assert!(matches!(
            second_client.acknowledge_terminal_event(&first_event.key(), &first_event.identity()),
            Err(ExecutionSupervisorError::TerminalEventOwnerMismatch { execution_id })
                if execution_id == second_id
        ));
        assert!(
            second_client
                .observe_terminal_event(&second_event.key(), &second_event.identity())?
                .is_some(),
            "foreign terminal ACK must not remove the retained target event"
        );
        assert!(matches!(
            second_client.observe_native_closure(&first_event),
            Err(ExecutionSupervisorError::NativeClosureOwnerMismatch { execution_id })
                if execution_id == second_id
        ));
        assert!(
            second_client
                .observe_native_closure(&second_event)?
                .is_some()
        );
        assert!(
            first_client
                .observe_terminal_event(&first_event.key(), &first_event.identity())?
                .is_some()
        );
        assert!(
            first_client.acknowledge_terminal_event(&first_event.key(), &first_event.identity())?
        );
        assert!(
            first_client
                .observe_terminal_event(&first_event.key(), &first_event.identity())?
                .is_none()
        );

        let first_report = first.shutdown()?;
        let second_report = second.shutdown()?;
        assert!(first_report.events().is_empty());
        assert_eq!(second_report.events().len(), 1);
        Ok(())
    }

    #[test]
    fn native_closure_changed_identity_and_closed_owner_fail_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        if nested_sandbox_execution_is_unavailable() {
            return Ok(());
        }
        let (root, layout) = fixture()?;
        let _root_guard = FixtureRootGuard(root);
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(41_200));
        let request = request(41_201, workspace_id, "/usr/bin/true", &[], 2_000)?;
        let mut supervisor = ExecutionSupervisor::start(1)?;
        let client = supervisor.client();
        let execution_id = client.start_execution(layout, request)?;
        let event = wait_for_retained_terminal_event(&client, execution_id)?;
        let changed = ExecutionSupervisorEvent {
            identity: SupervisorStartIdentity {
                activity_id: ActivityId::from_uuid(Uuid::from_u128(41_299)),
                ..event.identity()
            },
            ..event.clone()
        };
        assert!(matches!(
            client.observe_native_closure(&changed),
            Err(ExecutionSupervisorError::TerminalEventIdentityMismatch { execution_id: actual })
                if actual == execution_id
        ));
        assert!(client.read_output_events(8)?.events().is_empty());
        let closure = client
            .observe_native_closure(&event)?
            .ok_or("native closure without output did not arrive")?;
        assert_eq!(
            closure.output_cursor(),
            ExecutionOutputCursor::initial(execution_id)
        );
        let report = supervisor.shutdown()?;
        assert_eq!(report.events().len(), 1);
        assert!(matches!(
            client.observe_native_closure(&event),
            Err(ExecutionSupervisorError::Closed)
        ));
        Ok(())
    }

    #[test]
    fn terminal_key_rejects_a_stale_owner_after_supervisor_restart()
    -> Result<(), Box<dyn std::error::Error>> {
        if nested_sandbox_execution_is_unavailable() {
            return Ok(());
        }
        let (root, layout) = fixture()?;
        let _root_guard = FixtureRootGuard(root);
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(41_250));
        let request = request(41_251, workspace_id, "/usr/bin/true", &[], 2_000)?;

        let mut first = ExecutionSupervisor::start(1)?;
        let first_client = first.client();
        let first_id = first_client.start_execution(layout.clone(), request.clone())?;
        let first_event = wait_for_retained_terminal_event(&first_client, first_id)?;
        let first_report = first.shutdown()?;
        assert_eq!(first_report.events().len(), 1);

        let mut restarted = ExecutionSupervisor::start(1)?;
        let restarted_client = restarted.client();
        assert!(matches!(
            restarted_client.observe_terminal_event(&first_event.key(), &first_event.identity()),
            Err(ExecutionSupervisorError::TerminalEventOwnerMismatch { .. })
        ));
        assert!(matches!(
            restarted_client
                .acknowledge_terminal_event(&first_event.key(), &first_event.identity()),
            Err(ExecutionSupervisorError::TerminalEventOwnerMismatch { .. })
        ));
        let restarted_id = restarted_client.start_execution(layout, request)?;
        let restarted_event = wait_for_retained_terminal_event(&restarted_client, restarted_id)?;

        assert_eq!(first_event.execution_id(), restarted_event.execution_id());
        assert_eq!(first_event.identity(), restarted_event.identity());
        assert_ne!(first_event.key(), restarted_event.key());
        assert_eq!(
            first_event.key().generation,
            restarted_event.key().generation
        );
        assert!(matches!(
            restarted_client.observe_terminal_event(&first_event.key(), &first_event.identity()),
            Err(ExecutionSupervisorError::TerminalEventOwnerMismatch { execution_id })
                if execution_id == restarted_id
        ));
        assert!(matches!(
            restarted_client
                .acknowledge_terminal_event(&first_event.key(), &first_event.identity()),
            Err(ExecutionSupervisorError::TerminalEventOwnerMismatch { execution_id })
                if execution_id == restarted_id
        ));
        assert!(
            restarted_client
                .observe_terminal_event(&restarted_event.key(), &restarted_event.identity(),)?
                .is_some(),
            "a stale key must not remove the restarted supervisor event"
        );
        assert!(
            restarted_client
                .acknowledge_terminal_event(&restarted_event.key(), &restarted_event.identity(),)?
        );
        let restarted_report = restarted.shutdown()?;
        assert!(restarted_report.events().is_empty());
        Ok(())
    }

    #[test]
    fn native_closure_observation_reply_loss_keeps_exact_event_retryable()
    -> Result<(), Box<dyn std::error::Error>> {
        if nested_sandbox_execution_is_unavailable() {
            return Ok(());
        }
        let (root, layout) = fixture()?;
        let _root_guard = FixtureRootGuard(root);
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(41_300));
        let request = request(41_301, workspace_id, "/usr/bin/true", &[], 2_000)?;
        let mut supervisor = ExecutionSupervisor::start(1)?;
        let client = supervisor.client();
        let execution_id = client.start_execution(layout, request)?;
        let event = wait_for_retained_terminal_event(&client, execution_id)?;

        let proxy = NativeClosureReplyDropProxy::new(&client);
        let result = proxy.client().observe_native_closure(&event);
        proxy.finish()?;
        assert!(matches!(
            result,
            Err(ExecutionSupervisorError::ReplyDropped)
        ));
        let retry = client
            .observe_native_closure(&event)?
            .ok_or("reply loss did not retain native closure event")?;
        assert_eq!(retry.event(), &event);
        assert_eq!(retry.key(), event.key());
        assert_eq!(retry.identity(), event.identity());

        let report = supervisor.shutdown()?;
        assert_eq!(report.events().len(), 1);
        Ok(())
    }

    #[test]
    fn rust_ci_admission_is_one_per_workspace_and_releases_at_terminal()
    -> Result<(), Box<dyn std::error::Error>> {
        if nested_sandbox_execution_is_unavailable() {
            return Ok(());
        }
        let (root, layout) = fixture()?;
        let capability = rust_ci_capability(&root)?;
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(450));
        let first_runtime = capability.ensure_runtime_paths(
            workspace_id,
            layout.root_fingerprint()?,
            ExecutionId::from_uuid(Uuid::from_u128(451)),
        )?;
        let mut supervisor = ExecutionSupervisor::start(2)?;
        let client = supervisor.client();
        let first_id = client.start_execution_with_launch_kind(
            layout.clone(),
            request(451, workspace_id, "/bin/sleep", &["30"], 30_000)?,
            ExecutionLaunchKind::RustCi,
            Some(capability.clone()),
        )?;
        assert!(matches!(
            client.start_execution_with_launch_kind(
                layout.clone(),
                request(452, workspace_id, "/bin/sleep", &["30"], 30_000)?,
                ExecutionLaunchKind::RustCi,
                Some(capability.clone()),
            ),
            Err(ExecutionSupervisorError::RustCiWorkspaceCapacity(id)) if id == workspace_id
        ));
        assert!(client.cancel_execution(first_id)?);
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if take_terminal_events(&client, 8)?
                .into_iter()
                .any(|event| event.execution_id() == first_id)
            {
                break;
            }
            if Instant::now() >= deadline {
                return Err("Rust CI terminal event did not arrive".into());
            }
            thread::yield_now();
        }
        assert!(!first_runtime.execution_root().exists());
        assert!(!first_runtime.target_dir().exists());
        let second_id = client.start_execution_with_launch_kind(
            layout,
            request(453, workspace_id, "/bin/sleep", &["30"], 30_000)?,
            ExecutionLaunchKind::RustCi,
            Some(capability),
        )?;
        assert_ne!(second_id, first_id);
        assert!(client.cancel_execution(second_id)?);
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if take_terminal_events(&client, 8)?
                .into_iter()
                .any(|event| event.execution_id() == second_id)
            {
                break;
            }
            if Instant::now() >= deadline {
                return Err("second Rust CI terminal event did not arrive".into());
            }
            thread::yield_now();
        }
        let report = supervisor.shutdown()?;
        assert!(report.events().is_empty());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn round_robin_output_polling_keeps_two_saturated_executions_fair()
    -> Result<(), Box<dyn std::error::Error>> {
        if nested_sandbox_execution_is_unavailable() {
            return Ok(());
        }
        let (root, layout) = fixture()?;
        let first_workspace = WorkspaceId::from_uuid(Uuid::from_u128(500));
        let second_workspace = WorkspaceId::from_uuid(Uuid::from_u128(501));
        let mut supervisor = ExecutionSupervisor::start(2)?;
        let client = supervisor.client();
        let first_id = client.start_execution(
            layout.clone(),
            shell_request(
                502,
                first_workspace,
                "yes x | head -c 409600",
                5_000,
                1_048_576,
            )?,
        )?;
        let second_id = client.start_execution(
            layout,
            shell_request(
                504,
                second_workspace,
                "yes y | head -c 409600",
                5_000,
                1_048_576,
            )?,
        )?;

        let deadline = Instant::now() + Duration::from_secs(3);
        let mut seen_first = false;
        let mut seen_second = false;
        let mut first_bytes = 0_u64;
        let mut second_bytes = 0_u64;
        let mut terminal_count = 0;
        loop {
            let read = client.read_output_events(MAX_OUTPUT_EVENT_BACKLOG)?;
            if !read.events().is_empty() {
                for event in read.events() {
                    if matches!(event, ExecutionOutputEvent::Gap(_)) {
                        return Err("saturated fair output test observed an avoidable gap".into());
                    }
                    let execution_id = event.execution_id();
                    if execution_id == first_id {
                        seen_first = true;
                        if let ExecutionOutputEvent::Chunk(chunk) = event {
                            first_bytes = first_bytes.saturating_add(
                                u64::try_from(chunk.bytes().len()).unwrap_or(u64::MAX),
                            );
                        }
                    } else if execution_id == second_id {
                        seen_second = true;
                        if let ExecutionOutputEvent::Chunk(chunk) = event {
                            second_bytes = second_bytes.saturating_add(
                                u64::try_from(chunk.bytes().len()).unwrap_or(u64::MAX),
                            );
                        }
                    }
                }
                let key = read.ack_key().ok_or("missing output acknowledgement key")?;
                assert_eq!(client.ack_output_events(key)?, read.events().len());
            }

            for event in take_terminal_events(&client, 8)? {
                if event.execution_id() == first_id || event.execution_id() == second_id {
                    terminal_count += 1;
                }
            }
            if terminal_count == 2 && seen_first && seen_second {
                let remaining = client.read_output_events(MAX_OUTPUT_EVENT_BACKLOG)?;
                if remaining.events().is_empty() {
                    break;
                }
                // Terminal notifications may precede our final output read.
                // Count that read before acknowledging its consumed chunks.
                let (first, second) =
                    final_fair_output_counts(remaining.events(), first_id, second_id)?;
                first_bytes = first_bytes.saturating_add(first);
                second_bytes = second_bytes.saturating_add(second);
                let key = remaining
                    .ack_key()
                    .ok_or("missing output acknowledgement key")?;
                assert_eq!(client.ack_output_events(key)?, remaining.events().len());
            }
            if Instant::now() >= deadline {
                return Err("saturated fair output test did not settle".into());
            }
            thread::yield_now();
        }
        assert!(seen_first && seen_second);
        assert_eq!(first_bytes, 409_600);
        assert_eq!(second_bytes, 409_600);
        let report = supervisor.shutdown()?;
        assert!(report.events().is_empty());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    fn final_fair_output_counts(
        events: &[ExecutionOutputEvent],
        first_id: ExecutionId,
        second_id: ExecutionId,
    ) -> Result<(u64, u64), Box<dyn std::error::Error>> {
        let mut counts = (0_u64, 0_u64);
        for event in events {
            if matches!(event, ExecutionOutputEvent::Gap(_)) {
                return Err("saturated fair output test observed an avoidable gap".into());
            }
            if let ExecutionOutputEvent::Chunk(chunk) = event {
                let bytes = u64::try_from(chunk.bytes().len()).unwrap_or(u64::MAX);
                if event.execution_id() == first_id {
                    counts.0 = counts.0.saturating_add(bytes);
                } else if event.execution_id() == second_id {
                    counts.1 = counts.1.saturating_add(bytes);
                }
            }
        }
        Ok(counts)
    }
}
