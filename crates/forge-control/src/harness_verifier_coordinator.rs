//! Bounded coordinator for declared Harness verifier execution.
//!
//! The coordinator does not own a process runtime. It composes the existing
//! approval coordinator and execution supervisor chain, adds a dedicated
//! verifier Activity, and persists a bounded restart-safe run snapshot.

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError};
use std::thread::{self, JoinHandle};
use std::time::{SystemTime, UNIX_EPOCH};

use forge_domain::{
    ActivityListLimit, ApprovalRequestState, ExecutionArgument, ExecutionArgumentError,
    ExecutionAttribution, ExecutionKind, ExecutionLimits, ExecutionOutputLimit,
    ExecutionPermissions, ExecutionProgram, ExecutionProgramError, ExecutionRequest,
    ExecutionRequestDigest, ExecutionRequestError, ExecutionState, ExecutionTimeoutError,
    ExecutionTimeoutMillis, HarnessVerificationState, HarnessVerifierDomainError,
    HarnessVerifierItem, HarnessVerifierItemIdentity, HarnessVerifierItemState,
    HarnessVerifierName, HarnessVerifierNameError, HarnessVerifierRun,
    HarnessVerifierRunAttribution, HarnessVerifierRunId, RuntimeInstanceId, TimestampMillis,
    TimestampMillisError,
};
use forge_workspace::{
    HarnessBundleInspectionError, HarnessVerifierProgramError, HarnessVerifierSpec,
    inspect_harness_bundle, resolve_harness_verifier_program,
};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    ApprovalSubmissionStatus, ControlClientError, ForgeApprovalCoordinatorClient,
    ForgeApprovalCoordinatorError, ForgeControlClient, ResolvedWorkspaceScope,
    SubmitExecutionForApproval,
};

const COORDINATOR_QUEUE_CAPACITY: usize = 8;
const VERIFIER_ACTIVITY_LEASE_MILLIS: i64 = 15 * 60 * 1_000;
const VERIFIER_TIMEOUT_MILLIS: u64 = 5 * 60 * 1_000;
const THREAD_NAME: &str = "heterarchy-forge-harness-verifier-coordinator";

type Response<T> = SyncSender<Result<T, ForgeHarnessVerifierCoordinatorError>>;

#[must_use]
#[derive(Debug, Clone)]
pub struct HarnessVerifierRunRequest {
    scope: ResolvedWorkspaceScope,
    source_root: PathBuf,
}

impl HarnessVerifierRunRequest {
    pub const fn new(scope: ResolvedWorkspaceScope, source_root: PathBuf) -> Self {
        Self { scope, source_root }
    }

    pub const fn scope(&self) -> &ResolvedWorkspaceScope {
        &self.scope
    }

    pub fn source_root(&self) -> &std::path::Path {
        &self.source_root
    }
}

#[derive(Debug)]
enum CoordinatorRequest {
    Start {
        request: Box<HarnessVerifierRunRequest>,
        response: Response<HarnessVerifierRun>,
    },
    Refresh {
        request: Box<HarnessVerifierRunRequest>,
        response: Response<Option<HarnessVerifierRun>>,
    },
    Latest {
        scope: ResolvedWorkspaceScope,
        response: Response<Option<HarnessVerifierRun>>,
    },
    Shutdown {
        response: Response<()>,
    },
}

#[derive(Debug)]
pub struct PendingHarnessVerifierRun<T> {
    receiver: Receiver<Result<T, ForgeHarnessVerifierCoordinatorError>>,
}

impl<T> PendingHarnessVerifierRun<T> {
    pub fn try_recv(
        &self,
    ) -> Result<Option<Result<T, ForgeHarnessVerifierCoordinatorError>>, TryRecvError> {
        match self.receiver.try_recv() {
            Ok(value) => Ok(Some(value)),
            Err(TryRecvError::Empty) => Ok(None),
            Err(error @ TryRecvError::Disconnected) => Err(error),
        }
    }

    pub fn recv(self) -> Result<T, ForgeHarnessVerifierCoordinatorError> {
        self.receiver
            .recv()
            .map_err(|_| ForgeHarnessVerifierCoordinatorError::Closed)?
    }
}

#[derive(Debug, Clone)]
pub struct ForgeHarnessVerifierCoordinatorClient {
    sender: SyncSender<CoordinatorRequest>,
    accepting: Arc<AtomicBool>,
}

impl ForgeHarnessVerifierCoordinatorClient {
    pub fn start_run(
        &self,
        request: HarnessVerifierRunRequest,
    ) -> Result<HarnessVerifierRun, ForgeHarnessVerifierCoordinatorError> {
        self.submit_start(request)?.recv()
    }

    pub fn submit_start(
        &self,
        request: HarnessVerifierRunRequest,
    ) -> Result<PendingHarnessVerifierRun<HarnessVerifierRun>, ForgeHarnessVerifierCoordinatorError>
    {
        self.submit_pending(|response| CoordinatorRequest::Start {
            request: Box::new(request),
            response,
        })
    }

    pub fn refresh(
        &self,
        request: HarnessVerifierRunRequest,
    ) -> Result<Option<HarnessVerifierRun>, ForgeHarnessVerifierCoordinatorError> {
        self.submit_refresh(request)?.recv()
    }

    pub fn submit_refresh(
        &self,
        request: HarnessVerifierRunRequest,
    ) -> Result<
        PendingHarnessVerifierRun<Option<HarnessVerifierRun>>,
        ForgeHarnessVerifierCoordinatorError,
    > {
        self.submit_pending(|response| CoordinatorRequest::Refresh {
            request: Box::new(request),
            response,
        })
    }

    pub fn latest(
        &self,
        scope: ResolvedWorkspaceScope,
    ) -> Result<Option<HarnessVerifierRun>, ForgeHarnessVerifierCoordinatorError> {
        self.submit_latest(scope)?.recv()
    }

    pub fn submit_latest(
        &self,
        scope: ResolvedWorkspaceScope,
    ) -> Result<
        PendingHarnessVerifierRun<Option<HarnessVerifierRun>>,
        ForgeHarnessVerifierCoordinatorError,
    > {
        self.submit_pending(|response| CoordinatorRequest::Latest { scope, response })
    }

    fn submit_pending<T>(
        &self,
        build: impl FnOnce(Response<T>) -> CoordinatorRequest,
    ) -> Result<PendingHarnessVerifierRun<T>, ForgeHarnessVerifierCoordinatorError> {
        if !self.accepting.load(Ordering::Acquire) {
            return Err(ForgeHarnessVerifierCoordinatorError::Closed);
        }
        // A pending response is one bounded result owned by its caller.  A
        // one-slot buffer lets the coordinator finish a queued request even
        // when the caller intentionally defers receiving it, which is
        // required for a drain-aware shutdown to make progress.
        let (response_sender, response_receiver) = mpsc::sync_channel(1);
        match self.sender.try_send(build(response_sender)) {
            Ok(()) => Ok(PendingHarnessVerifierRun {
                receiver: response_receiver,
            }),
            Err(TrySendError::Full(_)) => Err(ForgeHarnessVerifierCoordinatorError::QueueFull),
            Err(TrySendError::Disconnected(_)) => Err(ForgeHarnessVerifierCoordinatorError::Closed),
        }
    }
}

#[derive(Debug)]
pub struct ForgeHarnessVerifierCoordinator {
    sender: SyncSender<CoordinatorRequest>,
    accepting: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl ForgeHarnessVerifierCoordinator {
    pub fn start(
        control: ForgeControlClient,
        approval: ForgeApprovalCoordinatorClient,
    ) -> Result<(ForgeHarnessVerifierCoordinatorClient, Self), ForgeHarnessVerifierCoordinatorError>
    {
        let (sender, receiver) = mpsc::sync_channel(COORDINATOR_QUEUE_CAPACITY);
        let accepting = Arc::new(AtomicBool::new(true));
        let thread_accepting = Arc::clone(&accepting);
        let join = thread::Builder::new()
            .name(THREAD_NAME.to_owned())
            .spawn(move || run_loop(&receiver, control, approval, &thread_accepting))
            .map_err(ForgeHarnessVerifierCoordinatorError::ThreadSpawn)?;
        let client = ForgeHarnessVerifierCoordinatorClient {
            sender: sender.clone(),
            accepting: Arc::clone(&accepting),
        };
        Ok((
            client,
            Self {
                sender,
                accepting,
                join: Some(join),
            },
        ))
    }

    pub fn shutdown(&mut self) -> Result<(), ForgeHarnessVerifierCoordinatorError> {
        if self.join.is_none() {
            return Ok(());
        }
        self.accepting.store(false, Ordering::Release);
        let (response_sender, response_receiver) = mpsc::sync_channel(1);
        let shutdown_result = match self.sender.send(CoordinatorRequest::Shutdown {
            response: response_sender,
        }) {
            Ok(()) => response_receiver
                .recv()
                .map_err(|_| ForgeHarnessVerifierCoordinatorError::Closed)
                .and_then(|result| result),
            Err(_) => Ok(()),
        };
        let join_result = match self.join.take() {
            Some(join) => join
                .join()
                .map_err(|_| ForgeHarnessVerifierCoordinatorError::ThreadPanicked),
            None => Ok(()),
        };
        match join_result {
            Ok(()) => shutdown_result,
            Err(error) => Err(error),
        }
    }
}

impl Drop for ForgeHarnessVerifierCoordinator {
    fn drop(&mut self) {
        let _ignored = self.shutdown();
    }
}

fn run_loop(
    receiver: &Receiver<CoordinatorRequest>,
    control: ForgeControlClient,
    approval: ForgeApprovalCoordinatorClient,
    accepting: &Arc<AtomicBool>,
) {
    let mut coordinator = CoordinatorState { control, approval };
    while let Ok(request) = receiver.recv() {
        match request {
            CoordinatorRequest::Start { request, response } => {
                let _ignored = response.send(coordinator.start_run(&request));
            }
            CoordinatorRequest::Refresh { request, response } => {
                let _ignored = response.send(coordinator.refresh(&request));
            }
            CoordinatorRequest::Latest { scope, response } => {
                let _ignored = response.send(
                    coordinator
                        .control
                        .harness_verifier_get_latest(scope)
                        .map_err(ForgeHarnessVerifierCoordinatorError::from),
                );
            }
            CoordinatorRequest::Shutdown { response } => {
                accepting.store(false, Ordering::Release);
                let _ignored = response.send(Ok(()));
                drain_queued_requests(receiver);
                break;
            }
        }
    }
    accepting.store(false, Ordering::Release);
}

fn drain_queued_requests(receiver: &Receiver<CoordinatorRequest>) {
    while let Ok(request) = receiver.try_recv() {
        reject_queued_request(request);
    }
}

fn reject_queued_request(request: CoordinatorRequest) {
    match request {
        CoordinatorRequest::Start { response, .. } => reject_response(&response),
        CoordinatorRequest::Refresh { response, .. }
        | CoordinatorRequest::Latest { response, .. } => reject_response(&response),
        CoordinatorRequest::Shutdown { response } => reject_response(&response),
    }
}

fn reject_response<T>(response: &Response<T>) {
    let _ignored = response.send(Err(ForgeHarnessVerifierCoordinatorError::Closed));
}

struct CoordinatorState {
    control: ForgeControlClient,
    approval: ForgeApprovalCoordinatorClient,
}

impl CoordinatorState {
    fn start_run(
        &mut self,
        request: &HarnessVerifierRunRequest,
    ) -> Result<HarnessVerifierRun, ForgeHarnessVerifierCoordinatorError> {
        if let Some(existing) = self
            .control
            .harness_verifier_get_latest(request.scope.clone())?
            && !existing.state().is_terminal()
        {
            return self.reconcile_run(request, existing);
        }
        let applied = self
            .control
            .submit_harness_get_applied(request.scope.clone())?
            .recv()?
            .ok_or(ForgeHarnessVerifierCoordinatorError::HarnessNotApplied)?;
        if applied.state() != HarnessVerificationState::Ready {
            return Err(ForgeHarnessVerifierCoordinatorError::SourceNotVerified);
        }
        let inspected = inspect_harness_bundle(&request.source_root)?;
        if inspected.descriptor() != applied.bundle() {
            return Err(ForgeHarnessVerifierCoordinatorError::SourceMismatch);
        }
        if inspected.verifiers().is_empty() {
            return Err(ForgeHarnessVerifierCoordinatorError::NoVerifiers);
        }

        let now = current_timestamp_millis()?;
        let lease_until = add_millis(now, VERIFIER_ACTIVITY_LEASE_MILLIS)?;
        let run_id = HarnessVerifierRunId::from_uuid(Uuid::now_v7());
        let activity_id = forge_domain::ActivityId::from_uuid(Uuid::now_v7());
        let runtime_instance_id = RuntimeInstanceId::from_uuid(Uuid::now_v7());
        let bootstrap = self.control.bootstrap_activity(
            request.scope.clone(),
            activity_id,
            runtime_instance_id,
            now,
            lease_until,
        )?;
        bootstrap
            .lease()
            .ok_or(ForgeHarnessVerifierCoordinatorError::ActivityLeaseMissing)?;

        let prepared = prepare_verifiers(
            request.scope.workspace_id(),
            activity_id,
            inspected.verifiers(),
        )?;
        let run = HarnessVerifierRun::starting(
            HarnessVerifierRunAttribution::new(
                run_id,
                request.scope.workspace_id(),
                inspected.descriptor().id(),
                inspected.descriptor().content_hash(),
                activity_id,
                runtime_instance_id,
            ),
            now,
            prepared
                .iter()
                .map(PreparedVerifier::pending_item)
                .collect::<Result<Vec<_>, _>>()?,
        )?;
        let mut run = self
            .control
            .harness_verifier_persist(request.scope.clone(), run, None)?;
        let submitted_items = submit_prepared(
            &self.approval,
            &request.scope,
            activity_id,
            runtime_instance_id,
            &prepared,
        )?;
        if submitted_items != run.items() {
            let next = run.reconcile(submitted_items, current_timestamp_millis()?)?;
            run = self.control.harness_verifier_persist(
                request.scope.clone(),
                next,
                Some(run.revision()),
            )?;
        }
        Ok(run)
    }

    fn refresh(
        &mut self,
        request: &HarnessVerifierRunRequest,
    ) -> Result<Option<HarnessVerifierRun>, ForgeHarnessVerifierCoordinatorError> {
        let Some(run) = self
            .control
            .harness_verifier_get_latest(request.scope.clone())?
        else {
            return Ok(None);
        };
        if run.state().is_terminal() {
            return Ok(Some(run));
        }
        self.reconcile_run(request, run).map(Some)
    }

    fn reconcile_run(
        &mut self,
        request: &HarnessVerifierRunRequest,
        run: HarnessVerifierRun,
    ) -> Result<HarnessVerifierRun, ForgeHarnessVerifierCoordinatorError> {
        let inspected = inspect_harness_bundle(&request.source_root)?;
        if inspected.descriptor().id() != run.bundle_id()
            || inspected.descriptor().content_hash() != run.content_hash()
            || inspected.verifiers().len() != run.items().len()
        {
            return Err(ForgeHarnessVerifierCoordinatorError::SourceMismatch);
        }
        let prepared = prepare_existing_verifiers(
            request.scope.workspace_id(),
            run.activity_id(),
            inspected.verifiers(),
            run.items(),
        )?;
        let items = prepared
            .iter()
            .map(|prepared| self.reconcile_item(&request.scope, &run, prepared))
            .collect::<Result<Vec<_>, _>>()?;
        if items == run.items() {
            return Ok(run);
        }
        let next = run.reconcile(items, current_timestamp_millis()?)?;
        let persisted = self.control.harness_verifier_persist(
            request.scope.clone(),
            next,
            Some(run.revision()),
        )?;
        if persisted.state().is_terminal() {
            self.close_terminal_activity(&request.scope, &persisted)?;
        }
        Ok(persisted)
    }

    fn reconcile_item(
        &self,
        scope: &ResolvedWorkspaceScope,
        run: &HarnessVerifierRun,
        prepared: &PreparedVerifier,
    ) -> Result<HarnessVerifierItem, ForgeHarnessVerifierCoordinatorError> {
        if let Some(execution) = self
            .control
            .execution_get(scope.clone(), prepared.execution_id)?
        {
            return item_from_execution(prepared, &execution);
        }
        if let Some(approval) = self
            .control
            .approval_get(scope.clone(), prepared.approval_id)?
        {
            let authorization = approval.request();
            if authorization.execution_id() != prepared.execution_id
                || authorization.request_digest() != prepared.request_digest
            {
                return Err(ForgeHarnessVerifierCoordinatorError::RequestDigestChanged);
            }
            return item_from_approval(prepared, approval.state());
        }
        let submission = self.approval.submit_execution(
            SubmitExecutionForApproval::direct(
                scope.clone(),
                run.activity_id(),
                run.runtime_instance_id(),
                prepared.request.clone(),
            )
            .with_approval_id(prepared.approval_id),
        )?;
        item_from_submission(prepared, &submission)
    }

    fn close_terminal_activity(
        &self,
        scope: &ResolvedWorkspaceScope,
        run: &HarnessVerifierRun,
    ) -> Result<(), ForgeHarnessVerifierCoordinatorError> {
        let observed_at = current_timestamp_millis()?;
        let limit = activity_lookup_limit()?;
        // The durable Activity row is the lease authority.  Re-read its
        // owner and revision here so a fresh coordinator can close a run
        // after restart without trusting a stale/in-memory fence.
        let activity = self
            .control
            .list_activity_projections(scope.clone(), observed_at, limit)?
            .into_iter()
            .find(|projection| projection.id() == run.activity_id())
            .map(forge_domain::ActivityProjection::into_activity)
            .ok_or(ForgeHarnessVerifierCoordinatorError::ActivityLeaseMissing)?;
        if activity.workspace_id() != scope.workspace_id() {
            return Err(ForgeHarnessVerifierCoordinatorError::ActivityLeaseConflict);
        }
        if activity.state() == forge_domain::ActivityState::Closed && activity.lease().is_unleased()
        {
            return Ok(());
        }
        if activity.state() != forge_domain::ActivityState::Open
            || activity.lease_owner_id() != Some(run.runtime_instance_id())
        {
            return Err(ForgeHarnessVerifierCoordinatorError::ActivityLeaseConflict);
        }
        if activity.lease().is_unleased() {
            return Err(ForgeHarnessVerifierCoordinatorError::ActivityLeaseConflict);
        }
        if !activity.lease().is_live_at(observed_at) {
            return Err(ForgeHarnessVerifierCoordinatorError::ActivityLeaseExpired);
        }
        let closed = self.control.close_activity(
            scope.clone(),
            run.activity_id(),
            run.runtime_instance_id(),
            activity.lease_revision(),
            observed_at,
        )?;
        let closed_activity = closed
            .activity()
            .ok_or(ForgeHarnessVerifierCoordinatorError::ActivityLeaseMissing)?;
        if closed_activity.id() != run.activity_id()
            || closed_activity.state() != forge_domain::ActivityState::Closed
            || !closed_activity.lease().is_unleased()
        {
            return Err(ForgeHarnessVerifierCoordinatorError::ActivityLeaseConflict);
        }
        Ok(())
    }
}

fn activity_lookup_limit() -> Result<ActivityListLimit, ForgeHarnessVerifierCoordinatorError> {
    let maximum = u32::try_from(crate::MAX_ACTIVITY_PROJECTION_RESULTS)
        .map_err(|_| ForgeHarnessVerifierCoordinatorError::ActivityLeaseMissing)?;
    ActivityListLimit::new(maximum)
        .map_err(|_| ForgeHarnessVerifierCoordinatorError::ActivityLeaseMissing)
}

#[derive(Debug, Clone)]
struct PreparedVerifier {
    name: HarnessVerifierName,
    approval_id: forge_domain::ApprovalRequestId,
    execution_id: forge_domain::ExecutionId,
    request_digest: ExecutionRequestDigest,
    request: ExecutionRequest,
    ordinal: u16,
}

impl PreparedVerifier {
    fn pending_item(&self) -> Result<HarnessVerifierItem, HarnessVerifierDomainError> {
        HarnessVerifierItem::new(
            HarnessVerifierItemIdentity::new(
                self.ordinal,
                self.name.clone(),
                self.approval_id,
                self.execution_id,
                self.request_digest,
            )?,
            HarnessVerifierItemState::PendingApproval,
            None,
            None,
        )
    }
}

fn prepare_verifiers(
    workspace_id: forge_domain::WorkspaceId,
    activity_id: forge_domain::ActivityId,
    verifiers: &[HarnessVerifierSpec],
) -> Result<Vec<PreparedVerifier>, ForgeHarnessVerifierCoordinatorError> {
    verifiers
        .iter()
        .enumerate()
        .map(|(index, verifier)| {
            let ordinal = u16::try_from(index)
                .map_err(|_| ForgeHarnessVerifierCoordinatorError::VerifierCount)?;
            let approval_id = forge_domain::ApprovalRequestId::from_uuid(Uuid::now_v7());
            let execution_id = forge_domain::ExecutionId::from_uuid(Uuid::now_v7());
            prepare_verifier(
                workspace_id,
                activity_id,
                verifier,
                ordinal,
                approval_id,
                execution_id,
            )
        })
        .collect()
}

fn prepare_existing_verifiers(
    workspace_id: forge_domain::WorkspaceId,
    activity_id: forge_domain::ActivityId,
    verifiers: &[HarnessVerifierSpec],
    items: &[HarnessVerifierItem],
) -> Result<Vec<PreparedVerifier>, ForgeHarnessVerifierCoordinatorError> {
    verifiers
        .iter()
        .zip(items)
        .map(|(verifier, item)| {
            if verifier.name() != item.name().as_str() {
                return Err(ForgeHarnessVerifierCoordinatorError::SourceMismatch);
            }
            let prepared = prepare_verifier(
                workspace_id,
                activity_id,
                verifier,
                item.ordinal(),
                item.approval_id(),
                item.execution_id(),
            )?;
            if prepared.request_digest != item.request_digest() {
                return Err(ForgeHarnessVerifierCoordinatorError::RequestDigestChanged);
            }
            Ok(prepared)
        })
        .collect()
}

fn prepare_verifier(
    workspace_id: forge_domain::WorkspaceId,
    activity_id: forge_domain::ActivityId,
    verifier: &HarnessVerifierSpec,
    ordinal: u16,
    approval_id: forge_domain::ApprovalRequestId,
    execution_id: forge_domain::ExecutionId,
) -> Result<PreparedVerifier, ForgeHarnessVerifierCoordinatorError> {
    let program = ExecutionProgram::new(resolve_harness_verifier_program(verifier.program())?)?;
    let arguments = verifier
        .arguments()
        .iter()
        .map(|argument| ExecutionArgument::new(OsString::from(argument)))
        .collect::<Result<Vec<_>, _>>()?;
    let request = ExecutionRequest::new(
        ExecutionAttribution::new(execution_id, workspace_id, activity_id),
        ExecutionKind::Structured { program, arguments },
        None,
        ExecutionLimits::new(
            ExecutionTimeoutMillis::new(VERIFIER_TIMEOUT_MILLIS)?,
            ExecutionOutputLimit::DEFAULT,
        ),
        ExecutionPermissions::new(true, false, false),
    )?;
    let request_digest = forge_execution::execution_request_digest(&request);
    Ok(PreparedVerifier {
        name: HarnessVerifierName::new(verifier.name().to_owned())?,
        approval_id,
        execution_id,
        request_digest,
        request,
        ordinal,
    })
}

fn submit_prepared(
    approval: &ForgeApprovalCoordinatorClient,
    scope: &ResolvedWorkspaceScope,
    activity_id: forge_domain::ActivityId,
    runtime_instance_id: RuntimeInstanceId,
    prepared: &[PreparedVerifier],
) -> Result<Vec<HarnessVerifierItem>, ForgeHarnessVerifierCoordinatorError> {
    prepared
        .iter()
        .map(|item| {
            let submission = approval.submit_execution(
                SubmitExecutionForApproval::direct(
                    scope.clone(),
                    activity_id,
                    runtime_instance_id,
                    item.request.clone(),
                )
                .with_approval_id(item.approval_id),
            )?;
            item_from_submission(item, &submission)
        })
        .collect()
}

fn item_from_submission(
    prepared: &PreparedVerifier,
    submission: &crate::ApprovalSubmission,
) -> Result<HarnessVerifierItem, ForgeHarnessVerifierCoordinatorError> {
    if submission.approval_id() != prepared.approval_id
        || submission.execution_id() != prepared.execution_id
    {
        return Err(ForgeHarnessVerifierCoordinatorError::SubmissionIdentityMismatch);
    }
    let state = match submission.status() {
        ApprovalSubmissionStatus::Pending => HarnessVerifierItemState::PendingApproval,
        ApprovalSubmissionStatus::Started => HarnessVerifierItemState::Running,
        ApprovalSubmissionStatus::Denied => HarnessVerifierItemState::Rejected,
    };
    HarnessVerifierItem::new(
        HarnessVerifierItemIdentity::new(
            prepared.ordinal,
            prepared.name.clone(),
            prepared.approval_id,
            prepared.execution_id,
            prepared.request_digest,
        )?,
        state,
        None,
        None,
    )
    .map_err(ForgeHarnessVerifierCoordinatorError::from)
}

fn item_from_approval(
    prepared: &PreparedVerifier,
    state: ApprovalRequestState,
) -> Result<HarnessVerifierItem, ForgeHarnessVerifierCoordinatorError> {
    let state = match state {
        ApprovalRequestState::Pending => HarnessVerifierItemState::PendingApproval,
        ApprovalRequestState::Approved | ApprovalRequestState::AutoApproved => {
            HarnessVerifierItemState::Running
        }
        ApprovalRequestState::Rejected
        | ApprovalRequestState::Denied
        | ApprovalRequestState::Cancelled
        | ApprovalRequestState::Expired
        | ApprovalRequestState::Superseded => HarnessVerifierItemState::Rejected,
    };
    HarnessVerifierItem::new(
        HarnessVerifierItemIdentity::new(
            prepared.ordinal,
            prepared.name.clone(),
            prepared.approval_id,
            prepared.execution_id,
            prepared.request_digest,
        )?,
        state,
        None,
        None,
    )
    .map_err(ForgeHarnessVerifierCoordinatorError::from)
}

fn item_from_execution(
    prepared: &PreparedVerifier,
    execution: &forge_domain::RegisteredExecution,
) -> Result<HarnessVerifierItem, ForgeHarnessVerifierCoordinatorError> {
    if execution.request_digest() != prepared.request_digest {
        return Err(ForgeHarnessVerifierCoordinatorError::RequestDigestChanged);
    }
    let (state, exit_code, duration_millis) = if execution.state().is_active() {
        (HarnessVerifierItemState::Running, None, None)
    } else {
        let outcome = execution.outcome();
        if execution.state() == ExecutionState::Completed
            && outcome.is_some_and(|value| value.exit_code() == Some(0))
        {
            (
                HarnessVerifierItemState::Passed,
                Some(0),
                outcome.map(forge_domain::ExecutionOutcome::duration_millis),
            )
        } else {
            (
                HarnessVerifierItemState::Failed,
                outcome.and_then(forge_domain::ExecutionOutcome::exit_code),
                outcome.map(forge_domain::ExecutionOutcome::duration_millis),
            )
        }
    };
    HarnessVerifierItem::new(
        HarnessVerifierItemIdentity::new(
            prepared.ordinal,
            prepared.name.clone(),
            prepared.approval_id,
            prepared.execution_id,
            prepared.request_digest,
        )?,
        state,
        exit_code,
        duration_millis,
    )
    .map_err(ForgeHarnessVerifierCoordinatorError::from)
}

fn current_timestamp_millis() -> Result<TimestampMillis, ForgeHarnessVerifierCoordinatorError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ForgeHarnessVerifierCoordinatorError::ClockBeforeEpoch)?;
    let millis = i64::try_from(elapsed.as_millis())
        .map_err(|_| ForgeHarnessVerifierCoordinatorError::TimestampOverflow)?;
    TimestampMillis::new(millis).map_err(ForgeHarnessVerifierCoordinatorError::Timestamp)
}

fn add_millis(
    timestamp: TimestampMillis,
    delta: i64,
) -> Result<TimestampMillis, ForgeHarnessVerifierCoordinatorError> {
    let value = timestamp
        .get()
        .checked_add(delta)
        .ok_or(ForgeHarnessVerifierCoordinatorError::TimestampOverflow)?;
    TimestampMillis::new(value).map_err(ForgeHarnessVerifierCoordinatorError::Timestamp)
}

#[derive(Debug, Error)]
pub enum ForgeHarnessVerifierCoordinatorError {
    #[error("Harness verifier coordinator queue is full")]
    QueueFull,
    #[error("Harness verifier coordinator is closed")]
    Closed,
    #[error("Harness verifier coordinator thread panicked")]
    ThreadPanicked,
    #[error("Harness verifier coordinator thread could not be started")]
    ThreadSpawn(#[source] std::io::Error),
    #[error("Harness verifier requires an applied Harness")]
    HarnessNotApplied,
    #[error("Harness source must pass source-integrity verification before declared verifiers run")]
    SourceNotVerified,
    #[error("Harness verifier source no longer matches the durable applied Harness")]
    SourceMismatch,
    #[error("Harness does not declare any verifier")]
    NoVerifiers,
    #[error("Harness verifier Activity bootstrap did not return an owned lease")]
    ActivityLeaseMissing,
    #[error("Harness verifier Activity lease owner or fence no longer matches the durable run")]
    ActivityLeaseConflict,
    #[error("Harness verifier Activity lease expired before terminal reconciliation")]
    ActivityLeaseExpired,
    #[error("Harness verifier count exceeds the bounded domain")]
    VerifierCount,
    #[error("Harness verifier approval/execution identities changed during submission")]
    SubmissionIdentityMismatch,
    #[error(
        "Harness verifier structured request digest changed after the run snapshot was persisted"
    )]
    RequestDigestChanged,
    #[error("system clock is before Unix epoch")]
    ClockBeforeEpoch,
    #[error("timestamp arithmetic overflowed")]
    TimestampOverflow,
    #[error(transparent)]
    Control(#[from] ControlClientError),
    #[error(transparent)]
    Approval(#[from] ForgeApprovalCoordinatorError),
    #[error(transparent)]
    Inspection(#[from] HarnessBundleInspectionError),
    #[error(transparent)]
    ProgramResolution(#[from] HarnessVerifierProgramError),
    #[error(transparent)]
    ExecutionProgram(#[from] ExecutionProgramError),
    #[error(transparent)]
    ExecutionArgument(#[from] ExecutionArgumentError),
    #[error(transparent)]
    ExecutionTimeout(#[from] ExecutionTimeoutError),
    #[error(transparent)]
    ExecutionRequest(#[from] ExecutionRequestError),
    #[error(transparent)]
    VerifierName(#[from] HarnessVerifierNameError),
    #[error(transparent)]
    Domain(#[from] HarnessVerifierDomainError),
    #[error("timestamp value is invalid")]
    Timestamp(#[source] TimestampMillisError),
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::thread;
    use std::time::{Duration, Instant};

    use forge_domain::{
        EstablishWorkspace, ExecutionMode, HarnessVerificationState, HarnessVerifierRunState,
        LocationId, LocationRevision, WorkspaceId, WorkspaceRoot,
    };
    use forge_persistence::{GlobalRegistry, WorkspaceStore};
    use forge_workspace::{LocationService, WorkspaceStateLayout, inspect_harness_bundle};

    use super::*;
    use crate::{
        ForgeApprovalCoordinator, ForgeControl, ForgeExecutionCoordinator, HarnessApplyRequest,
        HarnessPreviewRequest, HarnessVerifyRequest,
    };

    struct VerifierFixture {
        root: PathBuf,
        registry_path: PathBuf,
        source_root: PathBuf,
        scope: ResolvedWorkspaceScope,
    }

    fn timestamp(value: i64) -> Result<TimestampMillis, Box<dyn std::error::Error>> {
        Ok(TimestampMillis::new(value)?)
    }

    fn fixture(label: &str, program: &str) -> Result<VerifierFixture, Box<dyn std::error::Error>> {
        let serial = Uuid::now_v7();
        let root = std::env::temp_dir().join(format!(
            "heterarchy-forge-harness-verifier-{label}-{}-{serial}",
            std::process::id()
        ));
        let location_root = root.join("location");
        let workspace_root = location_root.join("workspace-0");
        let source_root = root.join("bundle");
        fs::create_dir_all(&workspace_root)?;
        fs::create_dir_all(source_root.join("rules"))?;
        fs::write(source_root.join("rules/base.md"), b"# Rules\n")?;
        fs::write(
            source_root.join(forge_workspace::HARNESS_MANIFEST_FILE_NAME),
            format!(
                "[harness]\nid = \"{}\"\nname = \"Verifier Harness\"\nversion = \"1.0.0\"\ninstall_root = \".agents/verifier_harness\"\nmanaged_files = [\"rules/base.md\"]\nskills = []\n\n[[verifiers]]\nname = \"truth\"\nprogram = \"{program}\"\nargs = []\n",
                Uuid::now_v7()
            ),
        )?;

        let registry_path = root.join("registry.sqlite3");
        let location_id = LocationId::from_uuid(Uuid::now_v7());
        let mut locations = LocationService::new(GlobalRegistry::open(&registry_path)?);
        let location = locations.register_selected_path(
            location_id,
            "Harness verifier fixture",
            &location_root,
            timestamp(1)?,
        )?;
        drop(locations);
        let layout = WorkspaceStateLayout::initialize(&workspace_root)?;
        let command = EstablishWorkspace::new(
            WorkspaceId::from_uuid(Uuid::now_v7()),
            location.id(),
            WorkspaceRoot::from_canonical(layout.workspace_root().to_path_buf())?,
            layout.root_fingerprint()?,
            timestamp(2)?,
        );
        drop(WorkspaceStore::open(&layout, &command)?);
        let control = ForgeControl::new(GlobalRegistry::open(&registry_path)?);
        let locator = control
            .workspace_list(location.id(), LocationRevision::INITIAL)?
            .into_iter()
            .find(|entry| entry.display_name() == "workspace-0")
            .ok_or("workspace locator missing")?
            .locator()
            .clone();
        let scope =
            control.resolve_workspace(location.id(), LocationRevision::INITIAL, &locator)?;
        Ok(VerifierFixture {
            root,
            registry_path,
            source_root,
            scope,
        })
    }

    fn prepare_applied_source(
        client: &ForgeControlClient,
        fixture: &VerifierFixture,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let descriptor = inspect_harness_bundle(&fixture.source_root)?
            .descriptor()
            .clone();
        let preview = client.harness_preview(HarnessPreviewRequest {
            scope: fixture.scope.clone(),
            source_root: fixture.source_root.clone(),
            expected_bundle: descriptor,
        })?;
        let applied = client.harness_apply(HarnessApplyRequest {
            scope: fixture.scope.clone(),
            source_root: fixture.source_root.clone(),
            expected_preview: preview,
            observed_at: timestamp(10)?,
        })?;
        assert_eq!(applied.state(), HarnessVerificationState::Applied);
        let ready = client.harness_verify_source(HarnessVerifyRequest {
            scope: fixture.scope.clone(),
            source_root: fixture.source_root.clone(),
            observed_at: timestamp(11)?,
        })?;
        assert_eq!(ready.state(), HarnessVerificationState::Ready);
        Ok(())
    }

    fn wait_for_terminal(
        client: &ForgeHarnessVerifierCoordinatorClient,
        request: &HarnessVerifierRunRequest,
    ) -> Result<HarnessVerifierRun, Box<dyn std::error::Error>> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let run = client
                .refresh(request.clone())?
                .ok_or("verifier run disappeared")?;
            if run.state().is_terminal() {
                return Ok(run);
            }
            if Instant::now() >= deadline {
                return Err("verifier run did not become terminal".into());
            }
            thread::yield_now();
        }
    }

    fn run_case(
        label: &str,
        program: &str,
        expected: HarnessVerifierRunState,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture(label, program)?;
        let control = ForgeControl::new(GlobalRegistry::open(&fixture.registry_path)?);
        let (control_client, mut control_worker) = control.start_worker()?;
        prepare_applied_source(&control_client, &fixture)?;

        let mut execution = ForgeExecutionCoordinator::start(control_client.clone(), 2)?;
        let mut approval =
            ForgeApprovalCoordinator::start(control_client.clone(), execution.client())?;
        let approval_client = approval.client();
        let (verifier_client, mut verifier) = ForgeHarnessVerifierCoordinator::start(
            control_client.clone(),
            approval_client.clone(),
        )?;
        let request =
            HarnessVerifierRunRequest::new(fixture.scope.clone(), fixture.source_root.clone());
        let started = verifier_client.start_run(request.clone())?;
        assert_eq!(started.state(), HarnessVerifierRunState::PendingApproval);
        assert_eq!(started.items().len(), 1);
        let item = &started.items()[0];
        let pending = approval_client.list_pending(fixture.scope.clone())?;
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].approval_id(), item.approval_id());
        assert_eq!(pending[0].execution_id(), item.execution_id());

        let execution_id = approval_client.approve_once(item.approval_id())?;
        assert_eq!(execution_id, item.execution_id());
        let terminal = wait_for_terminal(&verifier_client, &request)?;
        assert_eq!(terminal.state(), expected);
        assert_eq!(terminal.items().len(), 1);
        assert!(terminal.items()[0].duration_millis().is_some());
        match expected {
            HarnessVerifierRunState::Passed => {
                assert_eq!(
                    terminal.items()[0].state(),
                    HarnessVerifierItemState::Passed
                );
                assert_eq!(terminal.items()[0].exit_code(), Some(0));
            }
            HarnessVerifierRunState::Failed => {
                assert_eq!(
                    terminal.items()[0].state(),
                    HarnessVerifierItemState::Failed
                );
                assert_ne!(terminal.items()[0].exit_code(), Some(0));
            }
            HarnessVerifierRunState::PendingApproval | HarnessVerifierRunState::Running => {
                return Err("terminal test expected a non-terminal state".into());
            }
        }
        assert_eq!(
            verifier_client.latest(fixture.scope.clone())?,
            Some(terminal.clone())
        );
        let execution_record = control_client
            .execution_get(fixture.scope.clone(), execution_id)?
            .ok_or("durable verifier execution missing")?;
        assert_eq!(execution_record.mode(), ExecutionMode::Structured);
        let permissions = execution_record.permissions();
        assert!(permissions.workspace_read());
        assert!(!permissions.workspace_write());
        assert!(!permissions.network());

        verifier.shutdown()?;
        let _approval_report = approval.shutdown()?;
        let _execution_report = execution.shutdown()?;
        control_worker.shutdown()?;

        let restarted = ForgeControl::new(GlobalRegistry::open(&fixture.registry_path)?);
        assert_eq!(
            restarted.harness_verifier_get_latest(&fixture.scope)?,
            Some(terminal)
        );
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn restart_reconciles_terminal_run_and_closes_durable_activity()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("restart-close", "/usr/bin/true")?;
        let control = ForgeControl::new(GlobalRegistry::open(&fixture.registry_path)?);
        let (control_client, mut control_worker) = control.start_worker()?;
        prepare_applied_source(&control_client, &fixture)?;

        let mut execution = ForgeExecutionCoordinator::start(control_client.clone(), 2)?;
        let mut approval =
            ForgeApprovalCoordinator::start(control_client.clone(), execution.client())?;
        let approval_client = approval.client();
        let (verifier_client, mut verifier) = ForgeHarnessVerifierCoordinator::start(
            control_client.clone(),
            approval_client.clone(),
        )?;
        let request =
            HarnessVerifierRunRequest::new(fixture.scope.clone(), fixture.source_root.clone());
        let started = verifier_client.start_run(request.clone())?;
        let item = &started.items()[0];

        // The durable run and Activity survive replacement of the verifier
        // coordinator.  The replacement must recover the lease fence from
        // durable Activity authority instead of relying on its empty cache.
        verifier.shutdown()?;
        let (restarted_client, mut restarted_verifier) =
            ForgeHarnessVerifierCoordinator::start(control_client.clone(), approval_client)?;
        let execution_id = restarted_client
            .latest(fixture.scope.clone())?
            .ok_or("durable verifier run missing after restart")?
            .items()[0]
            .execution_id();
        assert_eq!(execution_id, item.execution_id());
        let approved_execution = approval.client().approve_once(item.approval_id())?;
        assert_eq!(approved_execution, execution_id);

        let terminal = wait_for_terminal(&restarted_client, &request)?;
        assert!(terminal.state().is_terminal());
        let activity = control_client
            .list_activity_projections(
                fixture.scope.clone(),
                current_timestamp_millis()?,
                ActivityListLimit::DEFAULT,
            )?
            .into_iter()
            .find(|projection| projection.id() == started.activity_id())
            .ok_or("durable verifier Activity missing after restart")?
            .into_activity();
        assert_eq!(activity.state(), forge_domain::ActivityState::Closed);
        assert!(activity.lease().is_unleased());

        restarted_verifier.shutdown()?;
        let _approval_report = approval.shutdown()?;
        let _execution_report = execution.shutdown()?;
        control_worker.shutdown()?;
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn shutdown_drains_saturated_queue_and_joins_owned_thread()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("shutdown-saturation", "/usr/bin/true")?;
        let control = ForgeControl::new(GlobalRegistry::open(&fixture.registry_path)?);
        let (control_client, mut control_worker) = control.start_worker()?;
        let mut execution = ForgeExecutionCoordinator::start(control_client.clone(), 1)?;
        let mut approval =
            ForgeApprovalCoordinator::start(control_client.clone(), execution.client())?;
        let approval_client = approval.client();

        // Fill the bounded queue before starting its consumer so saturation
        // is deterministic.  Each response is one bounded slot, allowing
        // the worker to drain without requiring callers to rendezvous first.
        let (sender, receiver) = mpsc::sync_channel(COORDINATOR_QUEUE_CAPACITY);
        let accepting = Arc::new(AtomicBool::new(true));
        let mut responses = Vec::with_capacity(COORDINATOR_QUEUE_CAPACITY);
        for _ in 0..COORDINATOR_QUEUE_CAPACITY {
            let (response_sender, response_receiver) = mpsc::sync_channel(1);
            sender.try_send(CoordinatorRequest::Latest {
                scope: fixture.scope.clone(),
                response: response_sender,
            })?;
            responses.push(response_receiver);
        }
        let (extra_response_sender, _extra_response_receiver) = mpsc::sync_channel(1);
        let extra = CoordinatorRequest::Latest {
            scope: fixture.scope.clone(),
            response: extra_response_sender,
        };
        assert!(matches!(sender.try_send(extra), Err(TrySendError::Full(_))));

        let thread_accepting = Arc::clone(&accepting);
        let run_control = control_client.clone();
        let run_approval = approval_client.clone();
        let join = thread::Builder::new()
            .name(THREAD_NAME.to_owned())
            .spawn(move || run_loop(&receiver, run_control, run_approval, &thread_accepting))?;
        let mut coordinator = ForgeHarnessVerifierCoordinator {
            sender,
            accepting,
            join: Some(join),
        };

        coordinator.shutdown()?;
        assert!(coordinator.join.is_none());
        for response in responses {
            assert!(response.recv()??.is_none());
        }

        let _approval_report = approval.shutdown()?;
        let _execution_report = execution.shutdown()?;
        control_worker.shutdown()?;
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn declared_verifier_true_runs_through_approval_sandbox_and_persists_pass()
    -> Result<(), Box<dyn std::error::Error>> {
        run_case("true", "/usr/bin/true", HarnessVerifierRunState::Passed)
    }

    #[test]
    fn declared_verifier_false_runs_through_approval_sandbox_and_persists_failure()
    -> Result<(), Box<dyn std::error::Error>> {
        run_case("false", "/usr/bin/false", HarnessVerifierRunState::Failed)
    }
}
