use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{BufReader, Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use forge_domain::{
    BoundedExecutionOutput, EXECUTION_OUTPUT_CHUNK_BYTES, ExecutionCompletionStatus,
    ExecutionFailureCode, ExecutionId, ExecutionKind, ExecutionOutcome, ExecutionOutputChunk,
    ExecutionOutputChunkError, ExecutionOutputCursor, ExecutionOutputEvent, ExecutionOutputGap,
    ExecutionOutputGapCause, ExecutionOutputGapError, ExecutionOutputGapParts,
    ExecutionOutputSequence, ExecutionOutputSequenceError, ExecutionOutputStream, ExecutionRequest,
    ExecutionTermination, FileByteCount, FileContentHash, GeneratedPackageManifest,
};
use forge_workspace::{ExistingWorkspaceStateLayout, PublishedVerificationInput};
use rustix_process::fs::{OFlags, fcntl_getfl, fcntl_setfl};
use rustix_process::io::Errno;
use rustix_process::process::{Pid, Signal, kill_process_group, test_kill_process_group};
use thiserror::Error;

use crate::package_v::{PackageVExecutableCapability, is_exact_package_request};
use crate::rust_ci::VerificationExecutionSource;
use crate::sandbox::{SANDBOX_EXEC_PATH, SandboxBackendError};
use crate::sandbox_linux::SandboxProfile;
use crate::{
    ExecutionLaunchKind, MAX_GENERATED_PACKAGE_BYTES, RUST_CI_DISK_MONITOR_INTERVAL,
    RUST_CI_SANDBOX_MARKER_ENV, RUST_CI_SANDBOX_MARKER_VALUE, RustCiDiscoveryError,
    RustCiDiskError, RustCiGeneratedPackageOutput, RustCiRuntimePaths, RustCiToolchainCapability,
    inspect_rust_ci_disk, inspect_rust_ci_disk_with_generated_output,
};

const MAX_CONCURRENT_EXECUTIONS: usize = 16;
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const RUST_CI_TEST_POLICY_ENV: &str = "HETERARCHY_FORGE_RUST_CI_TEST_POLICY";
const RUST_CI_TEST_POLICY_VALUE: &str = "outer-rust-ci-v1";
const TERMINATION_GRACE: Duration = Duration::from_millis(250);
const GROUP_REAP_GRACE: Duration = Duration::from_millis(250);
const RUST_CI_DISK_MONITOR_MAX_INTERVAL: Duration = Duration::from_secs(10);
const RUST_CI_DISK_MONITOR_SCAN_MULTIPLIER: u32 = 10;
const SAFE_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";
const APPLE_DEVELOPER_BIN: &str = "/Library/Developer/CommandLineTools/usr/bin";
const APPLE_DEVELOPER_DIR: &str = "/Library/Developer/CommandLineTools";
const APPLE_SDK_ROOT: &str = "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk";
#[cfg(target_os = "macos")]
const SHELL_PROGRAM: &str = "/bin/zsh";
#[cfg(not(target_os = "macos"))]
const SHELL_PROGRAM: &str = "/bin/sh";

/// The platform confinement wrapper program (frozen seam).
fn sandbox_program() -> &'static str {
    if cfg!(target_os = "macos") {
        SANDBOX_EXEC_PATH
    } else {
        crate::sandbox_linux::BWRAP_PATH
    }
}
const PACKAGE_CLOUDFLARED_ENV: &str = "FORGE_PACKAGE_CLOUDFLARED";
const CLOUDFLARED_EXECUTABLE: &str = "cloudflared";

/// Maximum number of output events retained by one running execution.
pub const MAX_OUTPUT_EVENT_BACKLOG: usize = 128;

/// The process-side evidence that controls whether a Rust CI runtime tree
/// may be removed.  This is deliberately private to the execution crate: the
/// public execution result must retain its existing semantics while the
/// supervisor still receives enough lifecycle evidence to fail closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProcessFinalization {
    /// The command was never successfully spawned.
    NoChildSpawned,
    /// The child and all descendants in its process group were positively
    /// observed to be gone.
    ProcessGroupReaped,
    /// A child was spawned, but reaping the process group or joining its
    /// owned cleanup path was not positively established.
    ReapUnconfirmed,
}

impl ProcessFinalization {
    const fn allows_runtime_cleanup(self) -> bool {
        matches!(self, Self::NoChildSpawned | Self::ProcessGroupReaped)
    }

    pub(crate) const fn requires_rust_ci_quarantine(self) -> bool {
        matches!(self, Self::ReapUnconfirmed)
    }
}

/// Private evidence for the Rust CI runtime tree.  Runtime cleanup is a
/// separate disposition from process reaping so a process group can remain
/// positively reaped even when an owned output/join path is uncertain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RustCiRuntimeFinalization {
    NotApplicable,
    Cleaned,
    Preserved,
}

impl RustCiRuntimeFinalization {
    pub(crate) const fn requires_rust_ci_quarantine(self) -> bool {
        matches!(self, Self::Preserved)
    }
}

#[derive(Debug)]
struct ExecutionCompletion {
    result: Result<ExecutionCompletionResult, ExecutionError>,
    process_finalization: ProcessFinalization,
    rust_ci_runtime_finalization: RustCiRuntimeFinalization,
}

/// Terminal process result with an optional server-captured generated package.
/// The manifest deliberately has no absolute filesystem path.
#[must_use]
#[derive(Debug, Clone)]
pub struct ExecutionCompletionResult {
    outcome: ExecutionOutcome,
    generated_package: Option<GeneratedPackageManifest>,
}

impl ExecutionCompletionResult {
    const fn new(
        outcome: ExecutionOutcome,
        generated_package: Option<GeneratedPackageManifest>,
    ) -> Self {
        Self {
            outcome,
            generated_package,
        }
    }

    pub const fn outcome(&self) -> &ExecutionOutcome {
        &self.outcome
    }

    pub const fn generated_package(&self) -> Option<GeneratedPackageManifest> {
        self.generated_package
    }

    pub fn into_outcome(self) -> ExecutionOutcome {
        self.outcome
    }
}

#[derive(Debug)]
struct OutputEventSink {
    execution_id: ExecutionId,
    sender: SyncSender<ExecutionOutputEvent>,
    state: Mutex<OutputEventSinkState>,
}

#[derive(Debug)]
struct OutputEventSinkState {
    next_sequence: ExecutionOutputSequence,
    queued_events: usize,
    pending_gap: Option<PendingOutputGap>,
    /// A gap that was fully materialized at producer finish but could not be
    /// enqueued because the bounded channel was full.
    ///
    /// Keeping the event, rather than only retrying its construction from the
    /// receiver side, makes the terminal path non-fallible after `finish`:
    /// sequence allocation and domain validation remain producer-owned, while
    /// the receiver only performs a bounded channel send.
    pending_terminal_gap: Option<ExecutionOutputEvent>,
    finished: bool,
    closed: bool,
}

#[derive(Debug, Clone, Copy)]
struct PendingOutputGap {
    first_missing: ExecutionOutputSequence,
    last_missing: ExecutionOutputSequence,
    stream: Option<ExecutionOutputStream>,
    omitted_bytes: u64,
    omitted_chunks: u64,
    cause: ExecutionOutputGapCause,
}

/// The receiver side of one execution-local bounded output queue.
#[derive(Debug)]
struct ExecutionOutputReceiver {
    receiver: Receiver<ExecutionOutputEvent>,
    sink: Arc<OutputEventSink>,
}

impl OutputEventSink {
    fn new(execution_id: ExecutionId) -> (Arc<Self>, ExecutionOutputReceiver) {
        let (sender, receiver) = mpsc::sync_channel(MAX_OUTPUT_EVENT_BACKLOG);
        let sink = Arc::new(Self {
            execution_id,
            sender,
            state: Mutex::new(OutputEventSinkState {
                next_sequence: ExecutionOutputSequence::INITIAL,
                queued_events: 0,
                pending_gap: None,
                pending_terminal_gap: None,
                finished: false,
                closed: false,
            }),
        });
        let output_receiver = ExecutionOutputReceiver {
            receiver,
            sink: Arc::clone(&sink),
        };
        (sink, output_receiver)
    }

    fn lock_state(&self) -> MutexGuard<'_, OutputEventSinkState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn next_sequence(
        state: &mut OutputEventSinkState,
    ) -> Result<ExecutionOutputSequence, ExecutionError> {
        let sequence = state.next_sequence;
        state.next_sequence = sequence
            .checked_next()
            .map_err(ExecutionError::OutputSequence)?;
        Ok(sequence)
    }

    fn publish_chunk(
        &self,
        stream: ExecutionOutputStream,
        bytes: &[u8],
    ) -> Result<(), ExecutionError> {
        if bytes.is_empty() {
            return Ok(());
        }
        let mut state = self.lock_state();
        if state.closed || state.finished {
            return Ok(());
        }
        if state.pending_gap.is_some() {
            let _ = self.flush_pending_gap(&mut state, false)?;
        }
        let sequence = Self::next_sequence(&mut state)?;
        if state.queued_events >= MAX_OUTPUT_EVENT_BACKLOG.saturating_sub(1) {
            Self::record_gap(
                &mut state,
                sequence,
                stream,
                bytes.len(),
                ExecutionOutputGapCause::Backpressure,
            );
            return Ok(());
        }
        let event = ExecutionOutputEvent::Chunk(
            ExecutionOutputChunk::new(self.execution_id, sequence, stream, bytes)
                .map_err(ExecutionError::OutputChunk)?,
        );
        match self.sender.try_send(event) {
            Ok(()) => {
                state.queued_events += 1;
            }
            Err(TrySendError::Full(_)) => {
                Self::record_gap(
                    &mut state,
                    sequence,
                    stream,
                    bytes.len(),
                    ExecutionOutputGapCause::Backpressure,
                );
            }
            Err(TrySendError::Disconnected(_)) => {
                state.closed = true;
                state.pending_gap = None;
            }
        }
        Ok(())
    }

    fn record_omitted(
        &self,
        stream: ExecutionOutputStream,
        bytes: usize,
        cause: ExecutionOutputGapCause,
    ) -> Result<(), ExecutionError> {
        if bytes == 0 {
            return Ok(());
        }
        let mut state = self.lock_state();
        if state.closed || state.finished {
            return Ok(());
        }
        let sequence = Self::next_sequence(&mut state)?;
        Self::record_gap(&mut state, sequence, stream, bytes, cause);
        Ok(())
    }

    fn record_gap(
        state: &mut OutputEventSinkState,
        sequence: ExecutionOutputSequence,
        stream: ExecutionOutputStream,
        bytes: usize,
        cause: ExecutionOutputGapCause,
    ) {
        let omitted_bytes = u64::try_from(bytes).unwrap_or(u64::MAX);
        let Some(pending) = state.pending_gap.as_mut() else {
            state.pending_gap = Some(PendingOutputGap {
                first_missing: sequence,
                last_missing: sequence,
                stream: Some(stream),
                omitted_bytes,
                omitted_chunks: 1,
                cause,
            });
            return;
        };
        pending.last_missing = sequence;
        pending.stream = (pending.stream == Some(stream)).then_some(stream);
        pending.omitted_bytes = pending.omitted_bytes.saturating_add(omitted_bytes);
        pending.omitted_chunks = pending.omitted_chunks.saturating_add(1);
        pending.cause = combine_gap_causes(pending.cause, cause);
    }

    fn flush_pending_gap(
        &self,
        state: &mut OutputEventSinkState,
        allow_reserved_slot: bool,
    ) -> Result<bool, ExecutionError> {
        let Some(pending) = state.pending_gap else {
            return Ok(true);
        };
        let capacity = if allow_reserved_slot {
            MAX_OUTPUT_EVENT_BACKLOG
        } else {
            MAX_OUTPUT_EVENT_BACKLOG.saturating_sub(1)
        };
        if state.queued_events >= capacity {
            return Ok(false);
        }
        let marker = Self::next_sequence(state)?;
        let event = ExecutionOutputEvent::Gap(
            ExecutionOutputGap::new(
                self.execution_id,
                marker,
                ExecutionOutputGapParts::new(
                    pending.first_missing,
                    pending.last_missing,
                    pending.stream,
                    pending.omitted_bytes,
                    pending.omitted_chunks,
                    pending.cause,
                ),
            )
            .map_err(ExecutionError::OutputGap)?,
        );
        match self.sender.try_send(event) {
            Ok(()) => {
                state.pending_gap = None;
                state.queued_events += 1;
                Ok(true)
            }
            Err(TrySendError::Full(_)) => {
                state.next_sequence = marker;
                Ok(false)
            }
            Err(TrySendError::Disconnected(_)) => {
                state.closed = true;
                state.pending_gap = None;
                Ok(false)
            }
        }
    }

    fn prepare_terminal_gap(&self, state: &mut OutputEventSinkState) -> Result<(), ExecutionError> {
        if state.pending_terminal_gap.is_some() {
            return Ok(());
        }
        let Some(pending) = state.pending_gap else {
            return Ok(());
        };
        let marker = Self::next_sequence(state)?;
        let event = ExecutionOutputEvent::Gap(
            ExecutionOutputGap::new(
                self.execution_id,
                marker,
                ExecutionOutputGapParts::new(
                    pending.first_missing,
                    pending.last_missing,
                    pending.stream,
                    pending.omitted_bytes,
                    pending.omitted_chunks,
                    pending.cause,
                ),
            )
            .map_err(ExecutionError::OutputGap)?,
        );
        state.pending_terminal_gap = Some(event);
        Ok(())
    }

    /// Enqueue the one terminal gap after a receiver frees a channel slot.
    ///
    /// The event was validated and sequence-numbered by `finish`, so this
    /// operation cannot fail except for the bounded channel being full or the
    /// receiver having gone away.  A full channel keeps the event for the
    /// next dequeue and therefore never loses the explicit omission evidence.
    fn enqueue_terminal_gap(&self, state: &mut OutputEventSinkState) {
        let Some(event) = state.pending_terminal_gap.take() else {
            return;
        };
        match self.sender.try_send(event) {
            Ok(()) => {
                state.pending_gap = None;
                state.queued_events += 1;
            }
            Err(TrySendError::Full(event)) => {
                state.pending_terminal_gap = Some(event);
            }
            Err(TrySendError::Disconnected(_)) => {
                state.closed = true;
                state.pending_gap = None;
            }
        }
    }

    fn finish(&self) -> Result<(), ExecutionError> {
        let mut state = self.lock_state();
        if state.finished {
            return Ok(());
        }
        if !state.closed && state.pending_gap.is_some() {
            let flushed = self.flush_pending_gap(&mut state, true)?;
            if !flushed && !state.closed {
                self.prepare_terminal_gap(&mut state)?;
            }
        }
        state.finished = true;
        Ok(())
    }

    fn receive(
        &self,
        receiver: &Receiver<ExecutionOutputEvent>,
    ) -> Result<ExecutionOutputEvent, TryRecvError> {
        let mut state = self.lock_state();
        let event = receiver.try_recv()?;
        state.queued_events = state.queued_events.saturating_sub(1);
        if state.finished && !state.closed && state.pending_terminal_gap.is_some() {
            self.enqueue_terminal_gap(&mut state);
        }
        Ok(event)
    }

    fn is_complete(&self) -> bool {
        let state = self.lock_state();
        state.finished
            && state.queued_events == 0
            && state.pending_gap.is_none()
            && state.pending_terminal_gap.is_none()
    }

    fn sealed_output_cursor(&self) -> Option<ExecutionOutputCursor> {
        let state = self.lock_state();
        if !state.finished
            || state.queued_events != 0
            || state.pending_gap.is_some()
            || state.pending_terminal_gap.is_some()
            || state.closed
        {
            return None;
        }
        let after_sequence = state.next_sequence.get().checked_sub(1)?;
        if after_sequence == 0 {
            return Some(ExecutionOutputCursor::initial(self.execution_id));
        }
        let sequence = ExecutionOutputSequence::new(after_sequence).ok()?;
        Some(ExecutionOutputCursor::from_sequence(
            self.execution_id,
            sequence,
        ))
    }
}

impl ExecutionOutputReceiver {
    fn drain(&mut self, maximum: usize) -> Vec<ExecutionOutputEvent> {
        let mut events = Vec::with_capacity(maximum);
        for _ in 0..maximum {
            match self.sink.receive(&self.receiver) {
                Ok(event) => events.push(event),
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
            }
        }
        events
    }

    fn is_complete(&self) -> bool {
        self.sink.is_complete()
    }
}

struct OutputEventFinishGuard {
    sink: Arc<OutputEventSink>,
}

impl OutputEventFinishGuard {
    const fn new(sink: Arc<OutputEventSink>) -> Self {
        Self { sink }
    }
}

impl Drop for OutputEventFinishGuard {
    fn drop(&mut self) {
        let _ignored = self.sink.finish();
    }
}

fn combine_gap_causes(
    first: ExecutionOutputGapCause,
    second: ExecutionOutputGapCause,
) -> ExecutionOutputGapCause {
    match (first, second) {
        (ExecutionOutputGapCause::Backpressure, ExecutionOutputGapCause::Backpressure)
        | (ExecutionOutputGapCause::OutputLimit, ExecutionOutputGapCause::OutputLimit) => first,
        _ => ExecutionOutputGapCause::BackpressureAndOutputLimit,
    }
}

#[derive(Clone)]
pub struct ExecutionRunner {
    admission: Arc<ExecutionAdmission>,
}

impl std::fmt::Debug for ExecutionRunner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExecutionRunner")
            .field("maximum", &self.admission.maximum)
            .field("active", &self.admission.active.load(Ordering::Acquire))
            .finish()
    }
}

impl ExecutionRunner {
    pub fn new(maximum: usize) -> Result<Self, ExecutionError> {
        if maximum == 0 || maximum > MAX_CONCURRENT_EXECUTIONS {
            return Err(ExecutionError::InvalidConcurrency {
                actual: maximum,
                maximum: MAX_CONCURRENT_EXECUTIONS,
            });
        }
        Ok(Self {
            admission: Arc::new(ExecutionAdmission {
                active: AtomicUsize::new(0),
                maximum,
            }),
        })
    }

    pub fn spawn(
        &self,
        layout: &ExistingWorkspaceStateLayout,
        request: ExecutionRequest,
    ) -> Result<RunningExecution, ExecutionError> {
        self.spawn_with_launch_kind(layout, request, ExecutionLaunchKind::Baseline, None)
    }

    /// Spawn an execution under an explicit runtime launch policy.
    ///
    /// Rust CI requires a previously discovered capability.  A missing
    /// capability is a typed admission failure; this method never falls back
    /// to the baseline environment.
    pub fn spawn_with_launch_kind(
        &self,
        layout: &ExistingWorkspaceStateLayout,
        request: ExecutionRequest,
        launch_kind: ExecutionLaunchKind,
        capability: Option<&RustCiToolchainCapability>,
    ) -> Result<RunningExecution, ExecutionError> {
        self.spawn_with_input(layout, request, launch_kind, capability, None)
    }

    /// Run against an owned published input while retaining the snapshot for
    /// durable evidence. Its source is never a writable runtime directory.
    pub fn spawn_verification(
        &self,
        layout: &ExistingWorkspaceStateLayout,
        request: ExecutionRequest,
        capability: &RustCiToolchainCapability,
        input: PublishedVerificationInput,
    ) -> Result<RunningExecution, ExecutionError> {
        self.spawn_verification_with_launch_kind(
            layout,
            request,
            ExecutionLaunchKind::RustCi,
            capability,
            input,
        )
    }

    pub fn spawn_verification_with_launch_kind(
        &self,
        layout: &ExistingWorkspaceStateLayout,
        request: ExecutionRequest,
        launch_kind: ExecutionLaunchKind,
        capability: &RustCiToolchainCapability,
        input: PublishedVerificationInput,
    ) -> Result<RunningExecution, ExecutionError> {
        self.spawn_with_input(layout, request, launch_kind, Some(capability), Some(input))
    }

    /// Spawn the exact `PackageV` command against its retained published input.
    /// The request is checked again inside `PreparedExecution`; callers cannot
    /// turn this into an arbitrary Baseline snapshot launch.
    pub fn spawn_package_verification(
        &self,
        layout: &ExistingWorkspaceStateLayout,
        request: ExecutionRequest,
        input: PublishedVerificationInput,
    ) -> Result<RunningExecution, ExecutionError> {
        self.spawn_with_input(
            layout,
            request,
            ExecutionLaunchKind::Baseline,
            None,
            Some(input),
        )
    }

    fn spawn_with_input(
        &self,
        layout: &ExistingWorkspaceStateLayout,
        request: ExecutionRequest,
        launch_kind: ExecutionLaunchKind,
        capability: Option<&RustCiToolchainCapability>,
        input: Option<PublishedVerificationInput>,
    ) -> Result<RunningExecution, ExecutionError> {
        let permit = self.admission.try_acquire()?;
        let prepared = PreparedExecution::new(layout, request, launch_kind, capability, input)?;
        let (cancel_sender, cancel_receiver) = mpsc::sync_channel(1);
        let (result_sender, result_receiver) = mpsc::sync_channel(1);
        let (output_sink, output_receiver) = OutputEventSink::new(prepared.request.id());
        let thread_name = format!("forge-execution-{}", prepared.request.id());
        let join = thread::Builder::new()
            .name(thread_name)
            .spawn(move || {
                let mut prepared = prepared;
                let completion = supervise(&mut prepared, &cancel_receiver, &output_sink);
                let _ignored = result_sender.send(completion);
                drop(permit);
            })
            .map_err(ExecutionError::SpawnSupervisor)?;
        Ok(RunningExecution {
            cancel_sender,
            result_receiver,
            output_receiver,
            process_finalization: None,
            rust_ci_runtime_finalization: None,
            join: Some(join),
        })
    }

    pub fn active_count(&self) -> usize {
        self.admission.active.load(Ordering::Acquire)
    }
}

struct ExecutionAdmission {
    active: AtomicUsize,
    maximum: usize,
}

impl ExecutionAdmission {
    fn try_acquire(self: &Arc<Self>) -> Result<ExecutionPermit, ExecutionError> {
        let mut current = self.active.load(Ordering::Acquire);
        loop {
            if current >= self.maximum {
                return Err(ExecutionError::Capacity {
                    maximum: self.maximum,
                });
            }
            match self.active.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Ok(ExecutionPermit {
                        admission: Arc::clone(self),
                    });
                }
                Err(observed) => current = observed,
            }
        }
    }
}

struct ExecutionPermit {
    admission: Arc<ExecutionAdmission>,
}

impl Drop for ExecutionPermit {
    fn drop(&mut self) {
        self.admission.active.fetch_sub(1, Ordering::AcqRel);
    }
}

pub struct RunningExecution {
    cancel_sender: SyncSender<()>,
    result_receiver: Receiver<ExecutionCompletion>,
    output_receiver: ExecutionOutputReceiver,
    process_finalization: Option<ProcessFinalization>,
    rust_ci_runtime_finalization: Option<RustCiRuntimeFinalization>,
    join: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for RunningExecution {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RunningExecution")
            .finish_non_exhaustive()
    }
}

impl RunningExecution {
    /// Drain at most `maximum` incremental output events for this execution.
    pub(crate) fn drain_output_events(&mut self, maximum: usize) -> Vec<ExecutionOutputEvent> {
        self.output_receiver
            .drain(maximum.min(MAX_OUTPUT_EVENT_BACKLOG))
    }

    pub(crate) fn output_events_complete(&self) -> bool {
        self.output_receiver.is_complete()
    }

    pub(crate) fn sealed_output_cursor(&self) -> Option<ExecutionOutputCursor> {
        self.output_receiver.sink.sealed_output_cursor()
    }

    pub fn cancel(&self) -> Result<(), ExecutionError> {
        match self.cancel_sender.try_send(()) {
            Ok(()) | Err(mpsc::TrySendError::Full(())) => Ok(()),
            Err(mpsc::TrySendError::Disconnected(())) => Err(ExecutionError::SupervisorClosed),
        }
    }

    pub fn wait(mut self) -> Result<ExecutionOutcome, ExecutionError> {
        let Ok(completion) = self.result_receiver.recv() else {
            self.process_finalization = Some(ProcessFinalization::ReapUnconfirmed);
            self.rust_ci_runtime_finalization = Some(RustCiRuntimeFinalization::Preserved);
            let _ignored = self.join_supervisor();
            return Err(ExecutionError::SupervisorClosed);
        };
        self.process_finalization = Some(completion.process_finalization);
        self.rust_ci_runtime_finalization = Some(completion.rust_ci_runtime_finalization);
        self.join_supervisor()?;
        completion
            .result
            .map(ExecutionCompletionResult::into_outcome)
    }

    pub fn try_wait(&mut self) -> Result<Option<ExecutionOutcome>, ExecutionError> {
        self.try_wait_completion()
            .map(|completion| completion.map(ExecutionCompletionResult::into_outcome))
    }

    pub(crate) fn try_wait_completion(
        &mut self,
    ) -> Result<Option<ExecutionCompletionResult>, ExecutionError> {
        match self.result_receiver.try_recv() {
            Ok(completion) => {
                self.process_finalization = Some(completion.process_finalization);
                self.rust_ci_runtime_finalization = Some(completion.rust_ci_runtime_finalization);
                self.join_supervisor()?;
                completion.result.map(Some)
            }
            Err(mpsc::TryRecvError::Empty) => Ok(None),
            Err(mpsc::TryRecvError::Disconnected) => {
                self.process_finalization = Some(ProcessFinalization::ReapUnconfirmed);
                self.rust_ci_runtime_finalization = Some(RustCiRuntimeFinalization::Preserved);
                self.join_supervisor()?;
                Err(ExecutionError::SupervisorClosed)
            }
        }
    }

    /// Return process-side finalization evidence after the execution becomes
    /// terminal.  A missing value is intentionally treated as unconfirmed by
    /// the supervisor because a running or panicked child cannot be proven
    /// absent from this handle alone.
    pub(crate) const fn process_finalization(&self) -> Option<ProcessFinalization> {
        self.process_finalization
    }

    pub(crate) const fn rust_ci_runtime_finalization(&self) -> Option<RustCiRuntimeFinalization> {
        self.rust_ci_runtime_finalization
    }

    fn join_supervisor(&mut self) -> Result<(), ExecutionError> {
        let Some(join) = self.join.take() else {
            return Ok(());
        };
        if let Ok(()) = join.join() {
            Ok(())
        } else {
            self.process_finalization = Some(ProcessFinalization::ReapUnconfirmed);
            self.rust_ci_runtime_finalization = Some(RustCiRuntimeFinalization::Preserved);
            Err(ExecutionError::SupervisorPanicked)
        }
    }
}

impl Drop for RunningExecution {
    fn drop(&mut self) {
        let _ignored = self.cancel_sender.try_send(());
        let _ignored = self.join_supervisor();
    }
}

struct PreparedExecution {
    request: ExecutionRequest,
    profile: SandboxProfile,
    workspace_root: PathBuf,
    cwd: PathBuf,
    launch_kind: ExecutionLaunchKind,
    rust_ci_capability: Option<RustCiToolchainCapability>,
    rust_ci_runtime: Option<RustCiRuntimePaths>,
    package_v_capability: Option<PackageVExecutableCapability>,
    generated_package_output: Option<RustCiGeneratedPackageOutput>,
    package_cloudflared: Option<PathBuf>,
    process_finalization: ProcessFinalization,
    rust_ci_runtime_finalization: RustCiRuntimeFinalization,
    runtime_cleanup_finalized: bool,
    verification_input: Option<PublishedVerificationInput>,
    verification_source: Option<VerificationExecutionSource>,
}

impl PreparedExecution {
    #[allow(clippy::too_many_lines)]
    fn new(
        layout: &ExistingWorkspaceStateLayout,
        request: ExecutionRequest,
        launch_kind: ExecutionLaunchKind,
        capability: Option<&RustCiToolchainCapability>,
        verification_input: Option<PublishedVerificationInput>,
    ) -> Result<Self, ExecutionError> {
        let workspace_root = layout.workspace_root().to_path_buf();
        let package_v_capability = match (launch_kind, verification_input.as_ref()) {
            (ExecutionLaunchKind::Baseline, Some(_)) => {
                let capability = PackageVExecutableCapability::prepare_current()
                    .map_err(ExecutionError::PackageVExecutable)?;
                if !is_exact_package_request(&request, &capability) {
                    return Err(ExecutionError::VerificationInputMismatch);
                }
                Some(capability)
            }
            _ => None,
        };
        let cwd = resolve_source_cwd(
            layout,
            &request,
            launch_kind,
            verification_input.as_ref(),
            package_v_capability.as_ref(),
        )?;
        let rust_ci_capability = match launch_kind {
            ExecutionLaunchKind::Baseline => None,
            ExecutionLaunchKind::RustCi | ExecutionLaunchKind::RustCiGeneratedPackage => Some(
                capability
                    .ok_or(ExecutionError::RustCiCapabilityRequired)?
                    .clone(),
            ),
        };
        let package_cloudflared = match launch_kind {
            ExecutionLaunchKind::RustCiGeneratedPackage => Some(resolve_bundled_cloudflared()?),
            _ => None,
        };
        let rust_ci_runtime =
            prepare_rust_ci_runtime(rust_ci_capability.as_ref(), layout, &request)?;
        let generated_package_output = match prepare_generated_package_output(
            launch_kind,
            rust_ci_capability.as_ref(),
            layout,
            &request,
        ) {
            Ok(output) => output,
            Err(error) => {
                cleanup_unstarted_runtime(rust_ci_runtime.as_ref())?;
                return Err(error);
            }
        };
        let launch_result = (|| {
            let (verification_source, cwd) = prepare_execution_source(
                &request,
                verification_input.as_ref(),
                rust_ci_runtime.as_ref(),
                package_v_capability.as_ref(),
                cwd,
            )?;
            let profile = match (
                verification_input.as_ref(),
                rust_ci_capability.as_ref(),
                rust_ci_runtime.as_ref(),
                package_v_capability.as_ref(),
            ) {
                (Some(_), Some(capability), Some(runtime), None) => {
                    SandboxProfile::for_verification_launch(
                        layout,
                        verification_source
                            .as_ref()
                            .ok_or(ExecutionError::VerificationInputMismatch)?
                            .root(),
                        launch_kind,
                        capability,
                        runtime,
                        generated_package_output.as_ref(),
                        package_cloudflared.as_deref(),
                    )
                }
                (Some(_), None, None, Some(capability)) => {
                    SandboxProfile::for_package_verification_launch(
                        layout,
                        verification_input
                            .as_ref()
                            .ok_or(ExecutionError::VerificationInputMismatch)?
                            .source_root(),
                        capability,
                    )
                }
                (Some(_), _, _, _) => return Err(ExecutionError::VerificationInputMismatch),
                (None, _, _, _) => SandboxProfile::for_launch(
                    layout,
                    request.permissions(),
                    launch_kind,
                    rust_ci_capability.as_ref(),
                    rust_ci_runtime.as_ref(),
                    generated_package_output.as_ref(),
                    package_cloudflared.as_deref(),
                ),
            }
            .map_err(ExecutionError::Sandbox)?;
            Ok((profile, cwd, verification_source))
        })();
        let (profile, cwd, verification_source) = match launch_result {
            Ok(prepared) => prepared,
            Err(error) => {
                cleanup_unstarted_runtime(rust_ci_runtime.as_ref())?;
                if let Some(output) = generated_package_output.as_ref() {
                    output.cleanup().map_err(ExecutionError::RustCiCleanup)?;
                }
                return Err(error);
            }
        };
        let has_rust_ci_runtime = rust_ci_runtime.is_some();
        Ok(Self {
            request,
            profile,
            workspace_root,
            cwd,
            launch_kind,
            rust_ci_capability,
            rust_ci_runtime,
            package_v_capability,
            generated_package_output,
            package_cloudflared,
            process_finalization: ProcessFinalization::NoChildSpawned,
            rust_ci_runtime_finalization: if has_rust_ci_runtime {
                RustCiRuntimeFinalization::Preserved
            } else {
                RustCiRuntimeFinalization::NotApplicable
            },
            runtime_cleanup_finalized: false,
            verification_input,
            verification_source,
        })
    }
}

fn prepare_rust_ci_runtime(
    capability: Option<&RustCiToolchainCapability>,
    layout: &ExistingWorkspaceStateLayout,
    request: &ExecutionRequest,
) -> Result<Option<RustCiRuntimePaths>, ExecutionError> {
    capability
        .map(|capability| {
            capability
                .revalidate_current()
                .map_err(ExecutionError::RustCiUnavailable)?;
            capability
                .ensure_runtime_paths(
                    request.workspace_id(),
                    layout
                        .root_fingerprint()
                        .map_err(ExecutionError::InspectRootFingerprint)?,
                    request.id(),
                )
                .map_err(ExecutionError::RustCiUnavailable)
        })
        .transpose()
}

fn cleanup_unstarted_runtime(runtime: Option<&RustCiRuntimePaths>) -> Result<(), ExecutionError> {
    runtime
        .map(RustCiRuntimePaths::cleanup)
        .transpose()
        .map(|_| ())
        .map_err(ExecutionError::RustCiCleanup)
}

fn prepare_execution_source(
    request: &ExecutionRequest,
    input: Option<&PublishedVerificationInput>,
    runtime: Option<&RustCiRuntimePaths>,
    package_v_capability: Option<&PackageVExecutableCapability>,
    default_cwd: PathBuf,
) -> Result<(Option<VerificationExecutionSource>, PathBuf), ExecutionError> {
    match (input, runtime) {
        (Some(input), Some(runtime)) => {
            let source = VerificationExecutionSource::prepare(runtime, input)
                .map_err(ExecutionError::VerificationSource)?;
            let cwd = resolve_cwd(source.root(), request.cwd())?;
            Ok((Some(source), cwd))
        }
        (Some(input), None) if package_v_capability.is_some() => {
            input
                .validate()
                .map_err(ExecutionError::VerificationInput)?;
            Ok((None, input.source_root().to_path_buf()))
        }
        (None, _) => Ok((None, default_cwd)),
        _ => Err(ExecutionError::VerificationInputMismatch),
    }
}

impl Drop for PreparedExecution {
    fn drop(&mut self) {
        if !self.runtime_cleanup_finalized {
            let _ignored = self.cleanup_runtime();
        }
    }
}

fn resolve_source_cwd(
    layout: &ExistingWorkspaceStateLayout,
    request: &ExecutionRequest,
    launch_kind: ExecutionLaunchKind,
    input: Option<&PublishedVerificationInput>,
    package_v_capability: Option<&PackageVExecutableCapability>,
) -> Result<PathBuf, ExecutionError> {
    if let Some(input) = input {
        let expected = layout
            .state_root()
            .join("artifacts/verification")
            .join(input.id().to_string())
            .join("source");
        if (!matches!(
            launch_kind,
            ExecutionLaunchKind::RustCi | ExecutionLaunchKind::RustCiGeneratedPackage
        ) && package_v_capability.is_none())
            || !request.permissions().workspace_read()
            || request.permissions().workspace_write()
            || request.permissions().network()
            || input.source_root() != expected
        {
            return Err(ExecutionError::VerificationInputMismatch);
        }
        if let Some(capability) = package_v_capability
            && !is_exact_package_request(request, capability)
        {
            return Err(ExecutionError::VerificationInputMismatch);
        }
        input
            .validate()
            .map_err(ExecutionError::VerificationInput)?;
    }
    resolve_cwd(
        input.map_or(
            layout.workspace_root(),
            PublishedVerificationInput::source_root,
        ),
        request.cwd(),
    )
}

fn prepare_generated_package_output(
    launch_kind: ExecutionLaunchKind,
    capability: Option<&RustCiToolchainCapability>,
    layout: &ExistingWorkspaceStateLayout,
    request: &ExecutionRequest,
) -> Result<Option<RustCiGeneratedPackageOutput>, ExecutionError> {
    match (launch_kind, capability) {
        (ExecutionLaunchKind::RustCiGeneratedPackage, Some(capability)) => capability
            .ensure_generated_package_output(
                request.workspace_id(),
                layout
                    .root_fingerprint()
                    .map_err(ExecutionError::InspectRootFingerprint)?,
                request.id(),
            )
            .map(Some)
            .map_err(ExecutionError::RustCiUnavailable),
        (ExecutionLaunchKind::RustCiGeneratedPackage, None) => {
            Err(ExecutionError::RustCiCapabilityRequired)
        }
        _ => Ok(None),
    }
}

fn resolve_cwd(
    workspace_root: &Path,
    relative: Option<&forge_domain::WorkspaceRelativePath>,
) -> Result<PathBuf, ExecutionError> {
    let candidate = relative.map_or_else(
        || workspace_root.to_path_buf(),
        |relative| workspace_root.join(relative.as_path()),
    );
    let metadata = fs::symlink_metadata(&candidate).map_err(ExecutionError::InspectCwd)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ExecutionError::InvalidCwd);
    }
    let canonical = fs::canonicalize(&candidate).map_err(ExecutionError::InspectCwd)?;
    if canonical != candidate || !canonical.starts_with(workspace_root) {
        return Err(ExecutionError::InvalidCwd);
    }
    Ok(candidate)
}

fn supervise(
    prepared: &mut PreparedExecution,
    cancellation: &Receiver<()>,
    output_sink: &Arc<OutputEventSink>,
) -> ExecutionCompletion {
    let finish_guard = OutputEventFinishGuard::new(Arc::clone(output_sink));
    let result = supervise_process(prepared, cancellation, output_sink);
    let finish = output_sink.finish();
    let retain_generated_package = matches!(
        &result,
        Ok(process) if process.generated_package.is_some()
    ) && finish.is_ok();
    let generated_cleanup = if retain_generated_package {
        Ok(())
    } else {
        prepared
            .generated_package_output
            .as_ref()
            .map_or(Ok(()), RustCiGeneratedPackageOutput::cleanup)
            .map_err(ExecutionError::RustCiCleanup)
    };
    let cleanup = prepared.cleanup_runtime();
    drop(finish_guard);
    let result = match (generated_cleanup, cleanup) {
        (Err(error), _) | (_, Err(error)) => Err(error),
        (Ok(()), Ok(())) => match (result, finish) {
            (Err(error), _) | (Ok(_), Err(error)) => Err(error),
            (Ok(process), Ok(())) => Ok(ExecutionCompletionResult::new(
                process.outcome,
                process.generated_package,
            )),
        },
    };
    if let Err(error) = &result {
        let (detail, errno) = error.native_failure_diagnostic();
        // Diagnostics are best-effort: a closed stderr must not replace the
        // original completion or prevent its delivery to the supervisor.
        let _diagnostic = writeln!(
            std::io::stderr(),
            "forge execution_id={} stage=completion code={:?} detail={detail} errno={errno:?} process={:?} runtime={:?}",
            prepared.request.id(),
            error.failure_code(),
            prepared.process_finalization,
            prepared.rust_ci_runtime_finalization,
        );
    }
    ExecutionCompletion {
        result,
        process_finalization: prepared.process_finalization,
        rust_ci_runtime_finalization: prepared.rust_ci_runtime_finalization,
    }
}

impl PreparedExecution {
    fn validate_verification_source(&self) -> Result<(), ExecutionError> {
        let Some(input) = self.verification_input.as_ref() else {
            return Ok(());
        };
        if self.package_v_capability.is_some() {
            input
                .validate()
                .map_err(ExecutionError::VerificationInput)?;
            return Ok(());
        }
        let source = self
            .verification_source
            .as_ref()
            .ok_or(ExecutionError::VerificationInputMismatch)?;
        let runtime = self
            .rust_ci_runtime
            .as_ref()
            .ok_or(ExecutionError::VerificationInputMismatch)?;
        source
            .validate(runtime, input)
            .map_err(ExecutionError::VerificationSource)
    }

    fn cleanup_runtime(&mut self) -> Result<(), ExecutionError> {
        if self.runtime_cleanup_finalized {
            return Ok(());
        }
        self.runtime_cleanup_finalized = true;
        let Some(runtime) = self.rust_ci_runtime.as_ref() else {
            self.rust_ci_runtime_finalization = RustCiRuntimeFinalization::NotApplicable;
            return Ok(());
        };
        if !self.process_finalization.allows_runtime_cleanup() {
            self.rust_ci_runtime_finalization = RustCiRuntimeFinalization::Preserved;
            return Ok(());
        }
        match runtime.cleanup() {
            Ok(()) => {
                self.rust_ci_runtime_finalization = RustCiRuntimeFinalization::Cleaned;
                Ok(())
            }
            Err(error) => {
                self.rust_ci_runtime_finalization = RustCiRuntimeFinalization::Preserved;
                Err(ExecutionError::RustCiCleanup(error))
            }
        }
    }
}

struct ProcessExecutionResult {
    outcome: ExecutionOutcome,
    generated_package: Option<GeneratedPackageManifest>,
}

fn supervise_process(
    prepared: &mut PreparedExecution,
    cancellation: &Receiver<()>,
    output_sink: &Arc<OutputEventSink>,
) -> Result<ProcessExecutionResult, ExecutionError> {
    prepared.validate_verification_source()?;
    if let (Some(capability), Some(runtime)) = (
        prepared.rust_ci_capability.as_ref(),
        prepared.rust_ci_runtime.as_ref(),
    ) {
        capability
            .revalidate_current()
            .map_err(ExecutionError::RustCiUnavailable)?;
        runtime
            .revalidate()
            .map_err(ExecutionError::RustCiUnavailable)?;
    }
    if let Some(capability) = prepared.package_v_capability.as_ref() {
        capability
            .revalidate()
            .map_err(ExecutionError::PackageVExecutable)?;
    }
    let start = Instant::now();
    let mut command = sandboxed_command(prepared)?;
    let shell_script = match prepared.request.kind() {
        ExecutionKind::Shell { script } => Some(script.as_str().as_bytes().to_vec()),
        ExecutionKind::Structured { .. } => None,
    };
    let mut child = match command.spawn() {
        Ok(child) => {
            prepared.process_finalization = ProcessFinalization::ReapUnconfirmed;
            child
        }
        Err(source) => return Err(ExecutionError::SpawnProcess(source)),
    };
    let pid = Pid::from_child(&child);
    let output_cancellation = Arc::new(AtomicBool::new(false));
    let output_limit = prepared.request.output_limit().get();
    let (stdout_reader, stderr_reader) = prepare_process_io(
        &mut child,
        pid,
        shell_script,
        output_limit,
        &output_cancellation,
        output_sink,
        prepared,
    )?;
    let (status, completion) = match wait_for_child(
        &mut child,
        pid,
        cancellation,
        prepared.request.timeout().get(),
        prepared.rust_ci_runtime.as_ref(),
        prepared.generated_package_output.as_ref(),
    ) {
        Ok(result) => result,
        Err(error) => {
            return Err(cleanup_after_spawn(
                error,
                &mut child,
                pid,
                &output_cancellation,
                vec![stdout_reader, stderr_reader],
                &mut prepared.process_finalization,
            ));
        }
    };
    if let Err(error) = cleanup_process_group(pid) {
        prepared.process_finalization = ProcessFinalization::ReapUnconfirmed;
        return Err(cleanup_after_spawn(
            error,
            &mut child,
            pid,
            &output_cancellation,
            vec![stdout_reader, stderr_reader],
            &mut prepared.process_finalization,
        ));
    }
    prepared.process_finalization = ProcessFinalization::ProcessGroupReaped;
    let stdout = join_reader(stdout_reader)?;
    let stderr = join_reader(stderr_reader)?;
    prepared.validate_verification_source()?;
    let duration_millis = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    let outcome = ExecutionOutcome::new(
        prepared.request.id(),
        ExecutionTermination::new(completion, status.code(), status.signal()),
        duration_millis,
        stdout,
        stderr,
    );
    let generated_package = match prepared.generated_package_output.as_ref() {
        Some(output)
            if status.success() && matches!(completion, ExecutionCompletionStatus::Exited) =>
        {
            Some(capture_generated_package(output, &prepared.request)?)
        }
        Some(_) | None => None,
    };
    Ok(ProcessExecutionResult {
        outcome,
        generated_package,
    })
}

fn capture_generated_package(
    output: &RustCiGeneratedPackageOutput,
    request: &ExecutionRequest,
) -> Result<GeneratedPackageManifest, ExecutionError> {
    output
        .revalidate()
        .map_err(ExecutionError::RustCiUnavailable)?;
    validate_generated_package_layout(output)?;
    let file = output
        .open_stable_package()
        .map_err(ExecutionError::GeneratedPackageOutput)?;
    let metadata = file
        .metadata()
        .map_err(ExecutionError::InspectGeneratedPackage)?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() == 0 {
        return Err(ExecutionError::InvalidGeneratedPackage);
    }
    if metadata.len() > MAX_GENERATED_PACKAGE_BYTES {
        return Err(ExecutionError::GeneratedPackageTooLarge {
            actual: metadata.len(),
            maximum: MAX_GENERATED_PACKAGE_BYTES,
        });
    }
    let hash = hash_regular_file(file)?;
    Ok(GeneratedPackageManifest::new(
        request.workspace_id(),
        request.id(),
        hash,
        FileByteCount::new(metadata.len()),
    ))
}

fn resolve_bundled_cloudflared() -> Result<PathBuf, ExecutionError> {
    let executable = std::env::current_exe().map_err(ExecutionError::PackageHelperInspection)?;
    resolve_bundled_cloudflared_for_executable(&executable)
}

fn resolve_bundled_cloudflared_for_executable(
    executable: &Path,
) -> Result<PathBuf, ExecutionError> {
    let parent = executable
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or(ExecutionError::PackageHelperUnavailable)?;
    let candidate = parent.join(CLOUDFLARED_EXECUTABLE);
    let metadata =
        fs::symlink_metadata(&candidate).map_err(ExecutionError::PackageHelperInspection)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o111 == 0
    {
        return Err(ExecutionError::PackageHelperUnavailable);
    }
    let canonical =
        fs::canonicalize(&candidate).map_err(ExecutionError::PackageHelperInspection)?;
    if canonical != candidate {
        return Err(ExecutionError::PackageHelperUnavailable);
    }
    Ok(candidate)
}

fn validate_generated_package_layout(
    output: &RustCiGeneratedPackageOutput,
) -> Result<(), ExecutionError> {
    let mut root_entries =
        fs::read_dir(output.root()).map_err(ExecutionError::InspectGeneratedPackage)?;
    let Some(dist) = root_entries
        .next()
        .transpose()
        .map_err(ExecutionError::InspectGeneratedPackage)?
    else {
        return Err(ExecutionError::InvalidGeneratedPackage);
    };
    if dist.file_name() != "dist"
        || dist
            .file_type()
            .map_err(ExecutionError::InspectGeneratedPackage)?
            .is_symlink()
    {
        return Err(ExecutionError::InvalidGeneratedPackage);
    }
    if root_entries
        .next()
        .transpose()
        .map_err(ExecutionError::InspectGeneratedPackage)?
        .is_some()
    {
        return Err(ExecutionError::InvalidGeneratedPackage);
    }
    let mut dist_entries =
        fs::read_dir(dist.path()).map_err(ExecutionError::InspectGeneratedPackage)?;
    let Some(package) = dist_entries
        .next()
        .transpose()
        .map_err(ExecutionError::InspectGeneratedPackage)?
    else {
        return Err(ExecutionError::InvalidGeneratedPackage);
    };
    if package.file_name() != "Heterarchy-Forge.pkg"
        || package
            .file_type()
            .map_err(ExecutionError::InspectGeneratedPackage)?
            .is_symlink()
        || dist_entries
            .next()
            .transpose()
            .map_err(ExecutionError::InspectGeneratedPackage)?
            .is_some()
    {
        return Err(ExecutionError::InvalidGeneratedPackage);
    }
    Ok(())
}

fn hash_regular_file(file: File) -> Result<FileContentHash, ExecutionError> {
    let mut reader = BufReader::new(file);
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(ExecutionError::InspectGeneratedPackage)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(FileContentHash::from_bytes(*hasher.finalize().as_bytes()))
}

type OutputReader = JoinHandle<Result<BoundedExecutionOutput, ExecutionError>>;

fn prepare_process_io(
    child: &mut Child,
    pid: Pid,
    shell_script: Option<Vec<u8>>,
    output_limit: u64,
    output_cancellation: &Arc<AtomicBool>,
    output_sink: &Arc<OutputEventSink>,
    prepared: &mut PreparedExecution,
) -> Result<(OutputReader, OutputReader), ExecutionError> {
    if let Some(script) = shell_script {
        let Some(mut stdin) = child.stdin.take() else {
            return Err(cleanup_after_spawn(
                ExecutionError::MissingPipe,
                child,
                pid,
                output_cancellation,
                Vec::new(),
                &mut prepared.process_finalization,
            ));
        };
        if let Err(source) = stdin.write_all(&script) {
            return Err(cleanup_after_spawn(
                ExecutionError::WriteStdin(source),
                child,
                pid,
                output_cancellation,
                Vec::new(),
                &mut prepared.process_finalization,
            ));
        }
    }
    let pipes = match (child.stdout.take(), child.stderr.take()) {
        (Some(stdout), Some(stderr)) => (stdout, stderr),
        _ => {
            return Err(cleanup_after_spawn(
                ExecutionError::MissingPipe,
                child,
                pid,
                output_cancellation,
                Vec::new(),
                &mut prepared.process_finalization,
            ));
        }
    };
    let stdout_reader = spawn_reader(
        "stdout",
        ExecutionOutputStream::Stdout,
        pipes.0,
        output_limit,
        Arc::clone(output_cancellation),
        Arc::clone(output_sink),
    )
    .map_err(|error| {
        cleanup_after_spawn(
            error,
            child,
            pid,
            output_cancellation,
            Vec::new(),
            &mut prepared.process_finalization,
        )
    })?;
    let stderr_reader = match spawn_reader(
        "stderr",
        ExecutionOutputStream::Stderr,
        pipes.1,
        output_limit,
        Arc::clone(output_cancellation),
        Arc::clone(output_sink),
    ) {
        Ok(reader) => reader,
        Err(error) => {
            return Err(cleanup_after_spawn(
                error,
                child,
                pid,
                output_cancellation,
                vec![stdout_reader],
                &mut prepared.process_finalization,
            ));
        }
    };
    Ok((stdout_reader, stderr_reader))
}

fn cleanup_after_spawn(
    original: ExecutionError,
    child: &mut Child,
    pid: Pid,
    output_cancellation: &AtomicBool,
    readers: Vec<OutputReader>,
    process_finalization: &mut ProcessFinalization,
) -> ExecutionError {
    let cleanup = emergency_cleanup(child, pid);
    let cleanup_succeeded = cleanup.is_ok();
    output_cancellation.store(true, Ordering::Release);
    let mut reader_failure = None;
    for reader in readers {
        if let Err(error) = join_reader(reader)
            && reader_failure.is_none()
        {
            reader_failure = Some(error);
        }
    }
    *process_finalization = if cleanup_succeeded {
        ProcessFinalization::ProcessGroupReaped
    } else {
        ProcessFinalization::ReapUnconfirmed
    };
    if let Err(error) = cleanup {
        error
    } else if let Some(error) = reader_failure {
        error
    } else {
        original
    }
}

fn emergency_cleanup(child: &mut Child, pid: Pid) -> Result<(), ExecutionError> {
    if child
        .try_wait()
        .map_err(ExecutionError::WaitProcess)?
        .is_none()
    {
        let _terminated = terminate(child, pid, ExecutionCompletionStatus::Cancelled)?;
    }
    cleanup_process_group(pid)
}

fn sandboxed_command(prepared: &PreparedExecution) -> Result<Command, ExecutionError> {
    let mut command = Command::new(sandbox_program());
    prepared.profile.apply_to(&mut command);
    match prepared.request.kind() {
        ExecutionKind::Structured { program, arguments } => {
            command.arg(program.as_path());
            command.args(
                arguments
                    .iter()
                    .map(forge_domain::ExecutionArgument::as_os_str),
            );
            command.stdin(Stdio::null());
        }
        ExecutionKind::Shell { .. } => {
            command.arg(SHELL_PROGRAM);
            // zsh -f skips rc files; POSIX sh has no such flag.
            if cfg!(target_os = "macos") {
                command.arg("-f");
            }
            command.stdin(Stdio::piped());
        }
    }
    command.current_dir(&prepared.cwd).env_clear();
    match prepared.launch_kind {
        ExecutionLaunchKind::Baseline => {
            command
                .env("PATH", SAFE_PATH)
                .env(
                    "HOME",
                    if prepared.package_v_capability.is_some() {
                        Path::new("/tmp")
                    } else {
                        prepared.workspace_root.as_path()
                    },
                )
                .env("LANG", "C")
                .env("LC_ALL", "C");
        }
        ExecutionLaunchKind::RustCi | ExecutionLaunchKind::RustCiGeneratedPackage => {
            let Some(capability) = prepared.rust_ci_capability.as_ref() else {
                return Err(ExecutionError::RustCiCapabilityRequired);
            };
            let Some(runtime) = prepared.rust_ci_runtime.as_ref() else {
                return Err(ExecutionError::RustCiUnavailable(
                    RustCiDiscoveryError::ProductRuntimeMismatch,
                ));
            };
            let mut path = OsString::from(capability.view().bin_dir().as_os_str());
            path.push(":");
            path.push(capability.view().toolchain_path().join("bin"));
            path.push(":");
            if cfg!(target_os = "macos") {
                path.push(APPLE_DEVELOPER_BIN);
                path.push(":");
            }
            path.push(SAFE_PATH);
            command
                .env("PATH", path)
                .env("RUSTUP", capability.view().rustup_path())
                .env("RUSTUP_TOOLCHAIN", capability.pinned_toolchain())
                .env("RUSTUP_HOME", capability.view().rustup_home())
                .env("CARGO_HOME", runtime.cargo_home())
                .env("CARGO_TARGET_DIR", runtime.target_dir())
                .env("TMPDIR", runtime.temporary_dir())
                .env("HOME", runtime.home_dir())
                .env("RUSTUP_NO_UPDATE_CHECK", "1")
                .env("CARGO_NET_OFFLINE", "true")
                .env("CARGO_INCREMENTAL", "0")
                .env("CARGO_PROFILE_DEV_DEBUG", "0")
                .env("CARGO_PROFILE_TEST_DEBUG", "0")
                .env(RUST_CI_SANDBOX_MARKER_ENV, RUST_CI_SANDBOX_MARKER_VALUE)
                .env(RUST_CI_TEST_POLICY_ENV, RUST_CI_TEST_POLICY_VALUE)
                .env("LANG", "C")
                .env("LC_ALL", "C")
                .env("GIT_TERMINAL_PROMPT", "0");
            if cfg!(target_os = "macos") {
                command
                    .env("DEVELOPER_DIR", APPLE_DEVELOPER_DIR)
                    .env("SDKROOT", APPLE_SDK_ROOT);
            }
            if let Some(output) = prepared.generated_package_output.as_ref() {
                command.env("FORGE_PACKAGE_OUTPUT_ROOT", output.root());
            }
            if let Some(cloudflared) = prepared.package_cloudflared.as_ref() {
                command.env(PACKAGE_CLOUDFLARED_ENV, cloudflared);
            }
        }
    }
    command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    Ok(command)
}

fn spawn_reader<R>(
    label: &'static str,
    stream: ExecutionOutputStream,
    reader: R,
    limit: u64,
    cancellation: Arc<AtomicBool>,
    output_sink: Arc<OutputEventSink>,
) -> Result<OutputReader, ExecutionError>
where
    R: Read + std::os::fd::AsFd + Send + 'static,
{
    let flags = fcntl_getfl(&reader).map_err(ExecutionError::ConfigureOutputPipe)?;
    fcntl_setfl(&reader, flags | OFlags::NONBLOCK).map_err(ExecutionError::ConfigureOutputPipe)?;
    thread::Builder::new()
        .name(format!("forge-execution-{label}"))
        .spawn(move || read_bounded(reader, stream, limit, &cancellation, &output_sink))
        .map_err(ExecutionError::SpawnOutputReader)
}

fn read_bounded<R: Read>(
    mut reader: R,
    stream: ExecutionOutputStream,
    limit: u64,
    cancellation: &AtomicBool,
    output_sink: &OutputEventSink,
) -> Result<BoundedExecutionOutput, ExecutionError> {
    let capacity = usize::try_from(limit).map_err(|_| ExecutionError::OutputLimitOverflow)?;
    let mut retained = Vec::with_capacity(capacity);
    let mut total = 0_u64;
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let read = match reader.read(&mut buffer) {
            Ok(read) => read,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if cancellation.load(Ordering::Acquire) {
                    break;
                }
                thread::sleep(POLL_INTERVAL);
                continue;
            }
            Err(error) => return Err(ExecutionError::ReadOutput(error)),
        };
        if read == 0 {
            break;
        }
        total = total.saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
        let available = capacity.saturating_sub(retained.len());
        let retained_count = read.min(available);
        retained.extend_from_slice(&buffer[..retained_count]);
        for chunk in buffer[..retained_count].chunks(EXECUTION_OUTPUT_CHUNK_BYTES) {
            output_sink.publish_chunk(stream, chunk)?;
        }
        for chunk in buffer[retained_count..read].chunks(EXECUTION_OUTPUT_CHUNK_BYTES) {
            output_sink.record_omitted(
                stream,
                chunk.len(),
                ExecutionOutputGapCause::OutputLimit,
            )?;
        }
    }
    Ok(BoundedExecutionOutput::new(retained, total, total > limit))
}

fn join_reader(
    reader: JoinHandle<Result<BoundedExecutionOutput, ExecutionError>>,
) -> Result<BoundedExecutionOutput, ExecutionError> {
    reader
        .join()
        .map_err(|_| ExecutionError::OutputReaderPanicked)?
}

fn wait_for_child(
    child: &mut Child,
    pid: Pid,
    cancellation: &Receiver<()>,
    timeout_millis: u64,
    rust_ci_runtime: Option<&RustCiRuntimePaths>,
    generated_package_output: Option<&RustCiGeneratedPackageOutput>,
) -> Result<(ExitStatus, ExecutionCompletionStatus), ExecutionError> {
    let deadline = Instant::now() + Duration::from_millis(timeout_millis);
    let mut next_disk_check = Instant::now();
    loop {
        if let Some(runtime) = rust_ci_runtime
            && Instant::now() >= next_disk_check
        {
            let scan_started = Instant::now();
            let disk = generated_package_output.map_or_else(
                || inspect_rust_ci_disk(runtime),
                |output| inspect_rust_ci_disk_with_generated_output(runtime, output),
            );
            if let Err(error) = disk {
                let _terminated = terminate(child, pid, ExecutionCompletionStatus::Cancelled)?;
                return Err(ExecutionError::RustCiDisk(error));
            }
            next_disk_check = Instant::now() + rust_ci_disk_monitor_delay(scan_started.elapsed());
        }
        if let Some(status) = child.try_wait().map_err(ExecutionError::WaitProcess)? {
            return Ok((status, ExecutionCompletionStatus::Exited));
        }
        match cancellation.try_recv() {
            Ok(()) | Err(TryRecvError::Disconnected) => {
                return terminate(child, pid, ExecutionCompletionStatus::Cancelled);
            }
            Err(TryRecvError::Empty) => {}
        }
        if Instant::now() >= deadline {
            return terminate(child, pid, ExecutionCompletionStatus::TimedOut);
        }
        thread::sleep(POLL_INTERVAL);
    }
}

fn rust_ci_disk_monitor_delay(scan_duration: Duration) -> Duration {
    scan_duration
        .saturating_mul(RUST_CI_DISK_MONITOR_SCAN_MULTIPLIER)
        .clamp(
            RUST_CI_DISK_MONITOR_INTERVAL,
            RUST_CI_DISK_MONITOR_MAX_INTERVAL,
        )
}

fn terminate(
    child: &mut Child,
    pid: Pid,
    completion: ExecutionCompletionStatus,
) -> Result<(ExitStatus, ExecutionCompletionStatus), ExecutionError> {
    signal_group(pid, Signal::TERM)?;
    let deadline = Instant::now() + TERMINATION_GRACE;
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().map_err(ExecutionError::WaitProcess)? {
            signal_group(pid, Signal::KILL)?;
            return Ok((status, completion));
        }
        thread::sleep(POLL_INTERVAL);
    }
    signal_group(pid, Signal::KILL)?;
    let status = child.wait().map_err(ExecutionError::WaitProcess)?;
    Ok((status, completion))
}

fn cleanup_process_group(pid: Pid) -> Result<(), ExecutionError> {
    match test_kill_process_group(pid) {
        Ok(()) => signal_group(pid, Signal::KILL)?,
        Err(source) if source == Errno::SRCH => return Ok(()),
        Err(source) => return Err(ExecutionError::SignalProcessGroup(source)),
    }
    let deadline = Instant::now() + GROUP_REAP_GRACE;
    while Instant::now() < deadline {
        match test_kill_process_group(pid) {
            Err(source) if source == Errno::SRCH => return Ok(()),
            Ok(()) => thread::sleep(POLL_INTERVAL),
            Err(source) => return Err(ExecutionError::SignalProcessGroup(source)),
        }
    }
    Err(ExecutionError::ProcessGroupSurvived)
}

fn signal_group(pid: Pid, signal: Signal) -> Result<(), ExecutionError> {
    match kill_process_group(pid, signal) {
        Ok(()) => Ok(()),
        Err(source) if source == Errno::SRCH => Ok(()),
        Err(source) => Err(ExecutionError::SignalProcessGroup(source)),
    }
}

#[derive(Debug, Error)]
pub enum ExecutionError {
    #[error("execution concurrency {actual} is outside 1..={maximum}")]
    InvalidConcurrency { actual: usize, maximum: usize },
    #[error("execution admission is at capacity {maximum}")]
    Capacity { maximum: usize },
    #[error(transparent)]
    Sandbox(#[from] SandboxBackendError),
    #[error("Rust CI launch requires a discovered toolchain capability")]
    RustCiCapabilityRequired,
    #[error("PackageV executable capability is unavailable or changed")]
    PackageVExecutable(#[source] crate::PackageVExecutableError),
    #[error("verification input is invalid or no longer matches its published source")]
    VerificationInput(#[source] forge_workspace::VerificationInputError),
    #[error("verification input does not match the execution scope or permissions")]
    VerificationInputMismatch,
    #[error("verification execution source is invalid or unavailable")]
    VerificationSource(#[source] crate::VerificationExecutionSourceError),
    #[error("Rust CI toolchain capability is unavailable")]
    RustCiUnavailable(#[source] RustCiDiscoveryError),
    #[error("Rust CI writable-root disk policy stopped the execution")]
    RustCiDisk(#[source] RustCiDiskError),
    #[error("Rust CI runtime cleanup failed")]
    RustCiCleanup(#[source] RustCiDiscoveryError),
    #[error("failed to inspect generated package output")]
    InspectGeneratedPackage(#[source] std::io::Error),
    #[error("generated package output root is unavailable")]
    GeneratedPackageOutput(#[source] RustCiDiscoveryError),
    #[error("failed to inspect the bundled cloudflared package helper")]
    PackageHelperInspection(#[source] std::io::Error),
    #[error("the current executable has no usable bundled cloudflared helper")]
    PackageHelperUnavailable,
    #[error("generated package output is missing or invalid")]
    InvalidGeneratedPackage,
    #[error("generated package has {actual} bytes; maximum is {maximum}")]
    GeneratedPackageTooLarge { actual: u64, maximum: u64 },
    #[error("execution cwd inspection failed")]
    InspectCwd(#[source] std::io::Error),
    #[error("failed to inspect the Workspace root fingerprint")]
    InspectRootFingerprint(#[source] forge_workspace::StateLayoutError),
    #[error("execution cwd is unavailable or escaped")]
    InvalidCwd,
    #[error("failed to spawn execution supervisor")]
    SpawnSupervisor(#[source] std::io::Error),
    #[error("failed to spawn sandboxed process")]
    SpawnProcess(#[source] std::io::Error),
    #[error("failed to spawn output reader")]
    SpawnOutputReader(#[source] std::io::Error),
    #[error("failed to configure output pipe")]
    ConfigureOutputPipe(#[source] Errno),
    #[error("sandboxed process pipe is missing")]
    MissingPipe,
    #[error("failed to write shell input")]
    WriteStdin(#[source] std::io::Error),
    #[error("failed to read process output")]
    ReadOutput(#[source] std::io::Error),
    #[error("execution output limit cannot be represented")]
    OutputLimitOverflow,
    #[error("execution output sequence overflowed")]
    OutputSequence(#[source] ExecutionOutputSequenceError),
    #[error("execution output chunk is invalid")]
    OutputChunk(#[source] ExecutionOutputChunkError),
    #[error("execution output gap is invalid")]
    OutputGap(#[source] ExecutionOutputGapError),
    #[error("failed to wait for sandboxed process")]
    WaitProcess(#[source] std::io::Error),
    #[error("failed to signal process group")]
    SignalProcessGroup(#[source] Errno),
    #[error("process group survived forced termination")]
    ProcessGroupSurvived,
    #[error("execution output reader panicked")]
    OutputReaderPanicked,
    #[error("execution supervisor panicked")]
    SupervisorPanicked,
    #[error("execution supervisor is closed")]
    SupervisorClosed,
}

impl ExecutionError {
    // Only static categories and numeric OS errors cross this logging boundary.
    // Error source strings may contain paths, scripts or other request payloads.
    fn native_failure_diagnostic(&self) -> (&'static str, Option<i32>) {
        match self {
            Self::WaitProcess(source) => ("wait_process", source.raw_os_error()),
            Self::SignalProcessGroup(source) => {
                ("signal_process_group", Some(source.raw_os_error()))
            }
            Self::ProcessGroupSurvived => ("process_group_survived", None),
            Self::SpawnOutputReader(source) => ("spawn_output_reader", source.raw_os_error()),
            Self::ConfigureOutputPipe(source) => {
                ("configure_output_pipe", Some(source.raw_os_error()))
            }
            Self::WriteStdin(source) => ("write_stdin", source.raw_os_error()),
            Self::ReadOutput(source) => ("read_output", source.raw_os_error()),
            Self::MissingPipe => ("missing_pipe", None),
            Self::OutputLimitOverflow => ("output_limit_overflow", None),
            Self::OutputSequence(_) => ("output_sequence", None),
            Self::OutputChunk(_) => ("output_chunk", None),
            Self::OutputGap(_) => ("output_gap", None),
            Self::OutputReaderPanicked => ("output_reader_panicked", None),
            Self::SupervisorPanicked => ("supervisor_panicked", None),
            Self::SupervisorClosed => ("supervisor_closed", None),
            _ => ("other", None),
        }
    }

    pub const fn failure_code(&self) -> ExecutionFailureCode {
        match self {
            Self::InvalidConcurrency { .. }
            | Self::Capacity { .. }
            | Self::RustCiCapabilityRequired
            | Self::PackageVExecutable(_)
            | Self::VerificationInput(_)
            | Self::VerificationInputMismatch
            | Self::VerificationSource(_)
            | Self::Sandbox(SandboxBackendError::VerificationSourceScope)
            | Self::RustCiUnavailable(_)
            | Self::RustCiCleanup(
                RustCiDiscoveryError::InvalidInput(_)
                | RustCiDiscoveryError::Missing { .. }
                | RustCiDiscoveryError::WrongType { .. }
                | RustCiDiscoveryError::NonCanonical { .. }
                | RustCiDiscoveryError::ProductViewMismatch
                | RustCiDiscoveryError::GeneratedPackageMismatch
                | RustCiDiscoveryError::ProductRuntimeNotEmpty,
            ) => ExecutionFailureCode::Admission,
            Self::Sandbox(SandboxBackendError::Unavailable) => {
                ExecutionFailureCode::SandboxUnavailable
            }
            Self::Sandbox(_)
            | Self::InspectCwd(_)
            | Self::InvalidCwd
            | Self::RustCiCleanup(RustCiDiscoveryError::ProductRuntimeMismatch) => {
                ExecutionFailureCode::InvalidWorkingDirectory
            }
            Self::InspectRootFingerprint(_) => ExecutionFailureCode::InvalidWorkingDirectory,
            Self::SpawnSupervisor(_)
            | Self::SpawnProcess(_)
            | Self::RustCiCleanup(RustCiDiscoveryError::Materialize { .. }) => {
                ExecutionFailureCode::ProcessSpawn
            }
            Self::RustCiDisk(_)
            | Self::RustCiCleanup(
                RustCiDiscoveryError::Inspect { .. }
                | RustCiDiscoveryError::ProductRuntimeUnexpectedEntry,
            )
            | Self::InspectGeneratedPackage(_)
            | Self::GeneratedPackageOutput(_)
            | Self::PackageHelperInspection(_)
            | Self::PackageHelperUnavailable
            | Self::InvalidGeneratedPackage
            | Self::GeneratedPackageTooLarge { .. }
            | Self::SpawnOutputReader(_)
            | Self::ConfigureOutputPipe(_)
            | Self::MissingPipe
            | Self::WriteStdin(_)
            | Self::ReadOutput(_)
            | Self::OutputLimitOverflow
            | Self::OutputSequence(_)
            | Self::OutputChunk(_)
            | Self::OutputGap(_)
            | Self::WaitProcess(_)
            | Self::SignalProcessGroup(_)
            | Self::ProcessGroupSurvived
            | Self::OutputReaderPanicked
            | Self::SupervisorPanicked
            | Self::SupervisorClosed => ExecutionFailureCode::Supervision,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::io;
    use std::net::{TcpListener, TcpStream};
    use std::str::FromStr;
    use std::sync::atomic::AtomicBool;
    use std::sync::{Arc, Barrier};
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::{RustCiDiscoveryInput, RustCiHostArchitecture};
    use forge_domain::{
        ActivityId, ExecutionArgument, ExecutionAttribution, ExecutionId, ExecutionLimits,
        ExecutionOutputCursor, ExecutionOutputLimit, ExecutionPermissions, ExecutionProgram,
        ExecutionScript, ExecutionTimeoutMillis, FileMutationId, FileMutationKind,
        FileMutationPlan, FilePrecondition, WorkspaceId,
    };
    use forge_workspace::{ConfinedWorkspace, WorkspaceStateLayout};
    use rustix_process::process::test_kill_process;
    use uuid::Uuid;

    use super::*;

    const RUST_CI_DESCRIPTOR_SIBLING_FILE: &str = "forge-rust-ci-descriptor-sibling";
    const RUST_CI_DESCRIPTOR_CREATED_FILE: &str = "forge-rust-ci-descriptor-created";
    const RUST_CI_DESCRIPTOR_STATE_FILE: &str = "forge-rust-ci-descriptor-state";
    const RUST_CI_DESCRIPTOR_NETWORK_FILE: &str = "forge-rust-ci-descriptor-network";

    #[test]
    fn rust_ci_disk_monitor_cadence_is_bounded_and_scan_cost_adaptive() {
        assert_eq!(
            rust_ci_disk_monitor_delay(Duration::from_millis(1)),
            Duration::from_secs(1)
        );
        assert_eq!(
            rust_ci_disk_monitor_delay(Duration::from_millis(250)),
            Duration::from_millis(2_500)
        );
        assert_eq!(
            rust_ci_disk_monitor_delay(Duration::from_secs(2)),
            Duration::from_secs(10)
        );
    }

    #[test]
    fn process_finalization_allows_runtime_cleanup_only_with_positive_reap_evidence() {
        assert!(ProcessFinalization::NoChildSpawned.allows_runtime_cleanup());
        assert!(ProcessFinalization::ProcessGroupReaped.allows_runtime_cleanup());
        assert!(!ProcessFinalization::ReapUnconfirmed.allows_runtime_cleanup());
        assert!(!ProcessFinalization::NoChildSpawned.requires_rust_ci_quarantine());
        assert!(!ProcessFinalization::ProcessGroupReaped.requires_rust_ci_quarantine());
        assert!(ProcessFinalization::ReapUnconfirmed.requires_rust_ci_quarantine());
    }

    #[test]
    fn generated_package_capture_rejects_missing_and_symlinked_output()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, layout) = layout("generated-package-capture")?;
        let capability = rust_ci_capability(&root)?;
        let workspace = WorkspaceId::from_uuid(Uuid::from_u128(0x711));
        let execution = ExecutionId::from_uuid(Uuid::from_u128(0x712));
        let output = capability.ensure_generated_package_output(
            workspace,
            layout.root_fingerprint()?,
            execution,
        )?;
        let request = ExecutionRequest::new(
            ExecutionAttribution::new(
                execution,
                workspace,
                ActivityId::from_uuid(Uuid::from_u128(0x713)),
            ),
            structured("/usr/bin/true", &[])?,
            None,
            ExecutionLimits::new(
                ExecutionTimeoutMillis::new(1_000)?,
                ExecutionOutputLimit::new(1_024)?,
            ),
            ExecutionPermissions::new(true, false, false),
        )?;
        assert!(matches!(
            capture_generated_package(&output, &request),
            Err(ExecutionError::InvalidGeneratedPackage)
        ));
        let dist = output.root().join("dist");
        fs::create_dir(&dist)?;
        let outside = root.join("outside.pkg");
        fs::write(&outside, b"must not be captured through a link")?;
        std::os::unix::fs::symlink(&outside, dist.join("Heterarchy-Forge.pkg"))?;
        assert!(matches!(
            capture_generated_package(&output, &request),
            Err(ExecutionError::InvalidGeneratedPackage)
        ));
        fs::remove_file(dist.join("Heterarchy-Forge.pkg"))?;
        fs::write(dist.join("Heterarchy-Forge.pkg"), b"package")?;
        let manifest = capture_generated_package(&output, &request)?;
        assert_eq!(manifest.workspace_id(), workspace);
        assert_eq!(manifest.execution_id(), execution);
        assert_eq!(manifest.byte_count().get(), 7);
        output.cleanup()?;
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn bundled_package_helper_requires_a_regular_executable_sibling()
    -> Result<(), Box<dyn std::error::Error>> {
        let raw_root =
            std::env::temp_dir().join(format!("forge-bundled-package-helper-{}", Uuid::now_v7()));
        fs::create_dir_all(&raw_root)?;
        let root = fs::canonicalize(raw_root)?;
        let executable = root.join("forge-desktop");
        fs::write(&executable, b"desktop")?;
        let helper = root.join(CLOUDFLARED_EXECUTABLE);
        fs::write(&helper, b"cloudflared")?;
        let mut permissions = fs::metadata(&helper)?.permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&helper, permissions)?;
        assert_eq!(
            resolve_bundled_cloudflared_for_executable(&executable)?,
            fs::canonicalize(&helper)?
        );
        fs::remove_file(&helper)?;
        std::os::unix::fs::symlink(&executable, &helper)?;
        assert!(matches!(
            resolve_bundled_cloudflared_for_executable(&executable),
            Err(ExecutionError::PackageHelperUnavailable)
        ));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    #[ignore = "measured performance evaluator; run explicitly"]
    fn rust_ci_disk_monitor_performance_evaluator() -> Result<(), Box<dyn std::error::Error>> {
        const FILE_COUNT: usize = 12_000;
        const FILE_CONTENT: &[u8] = b"forge rust ci disk monitor\n";

        let (root, layout) = layout("rust-ci-disk-monitor-measured")?;
        let capability = rust_ci_capability(&root)?;
        let runtime = capability.ensure_runtime_paths(
            WorkspaceId::from_uuid(Uuid::from_u128(601)),
            layout.root_fingerprint()?,
            ExecutionId::from_uuid(Uuid::from_u128(602)),
        )?;
        let baseline = inspect_rust_ci_disk(&runtime)?;
        let measured_tree = runtime.target_dir().join("representative");
        fs::create_dir(&measured_tree)?;
        for index in 0..FILE_COUNT {
            fs::write(
                measured_tree.join(format!("entry-{index:05}.bin")),
                FILE_CONTENT,
            )?;
        }

        let scan_started = Instant::now();
        let observed = inspect_rust_ci_disk(&runtime)?;
        let scan_duration = scan_started.elapsed();
        let adaptive_delay = rust_ci_disk_monitor_delay(scan_duration);
        eprintln!(
            "rust-ci disk monitor: entries={}, scan_ms={}, next_delay_ms={}",
            observed.entries(),
            scan_duration.as_millis(),
            adaptive_delay.as_millis()
        );

        let expected_added_entries = u64::try_from(FILE_COUNT.saturating_add(1))?;
        assert_eq!(
            observed.entries(),
            baseline.entries().saturating_add(expected_added_entries)
        );
        let expected_file_bytes =
            u64::try_from(FILE_COUNT)?.saturating_mul(u64::try_from(FILE_CONTENT.len())?);
        assert!(
            observed.logical_bytes()
                >= baseline.logical_bytes().saturating_add(expected_file_bytes),
            "the measured tree must contribute its file bytes to the scan"
        );

        assert!(
            adaptive_delay >= scan_duration.saturating_mul(RUST_CI_DISK_MONITOR_SCAN_MULTIPLIER),
            "adaptive delay {adaptive_delay:?} must cover ten scan costs {scan_duration:?}"
        );
        assert!(adaptive_delay >= RUST_CI_DISK_MONITOR_INTERVAL);
        assert!(adaptive_delay <= RUST_CI_DISK_MONITOR_MAX_INTERVAL);

        runtime.cleanup()?;
        assert!(!runtime.execution_root().exists());
        assert!(!runtime.target_dir().exists());
        assert!(!runtime.workspace_root().exists());
        assert!(!runtime.temporary_dir().exists());
        assert!(!runtime.home_dir().exists());
        assert!(!runtime.cargo_home().exists());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    fn layout(
        label: &str,
    ) -> Result<(PathBuf, ExistingWorkspaceStateLayout), Box<dyn std::error::Error>> {
        let unique = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let root = std::env::temp_dir().join(format!("forge-execution-{label}-{unique}"));
        fs::create_dir_all(&root)?;
        WorkspaceStateLayout::initialize(&root)?;
        let layout = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
        Ok((root, layout))
    }

    fn nested_sandbox_execution_is_unavailable() -> bool {
        std::env::var(RUST_CI_SANDBOX_MARKER_ENV).as_deref() == Ok(RUST_CI_SANDBOX_MARKER_VALUE)
            && std::env::var(RUST_CI_TEST_POLICY_ENV).as_deref() == Ok(RUST_CI_TEST_POLICY_VALUE)
    }

    fn request(
        seed: u128,
        kind: ExecutionKind,
        permissions: ExecutionPermissions,
        timeout: u64,
        output_limit: u64,
    ) -> Result<ExecutionRequest, Box<dyn std::error::Error>> {
        Ok(ExecutionRequest::new(
            ExecutionAttribution::new(
                ExecutionId::from_uuid(Uuid::from_u128(seed)),
                WorkspaceId::from_uuid(Uuid::from_u128(seed + 1)),
                ActivityId::from_uuid(Uuid::from_u128(seed + 2)),
            ),
            kind,
            None,
            ExecutionLimits::new(
                ExecutionTimeoutMillis::new(timeout)?,
                ExecutionOutputLimit::new(output_limit)?,
            ),
            permissions,
        )?)
    }

    fn structured(
        program: &str,
        arguments: &[&str],
    ) -> Result<ExecutionKind, Box<dyn std::error::Error>> {
        Ok(ExecutionKind::Structured {
            program: ExecutionProgram::new(PathBuf::from(program))?,
            arguments: arguments
                .iter()
                .map(|value| ExecutionArgument::new(OsString::from(value)))
                .collect::<Result<_, _>>()?,
        })
    }

    fn shell(script: String) -> Result<ExecutionKind, Box<dyn std::error::Error>> {
        Ok(ExecutionKind::Shell {
            script: ExecutionScript::new(script)?,
        })
    }

    fn rust_ci_capability(
        root: &Path,
    ) -> Result<RustCiToolchainCapability, Box<dyn std::error::Error>> {
        let root = fs::canonicalize(root)?;
        let host = root.join("rust-ci-host");
        fs::create_dir_all(host.join(".cargo/bin"))?;
        fs::create_dir_all(host.join(".cargo/registry"))?;
        fs::create_dir_all(host.join(format!(
            ".rustup/toolchains/{}",
            crate::rust_ci::pinned_toolchain_name(RustCiHostArchitecture::Aarch64)
        )))?;
        fs::write(host.join(".cargo/bin/rustup"), b"rustup")?;
        fs::write(host.join(".rustup/settings.toml"), b"version = 12\n")?;
        let cache = root.join("rust-ci-cache");
        let input = RustCiDiscoveryInput::new(
            host,
            cache,
            RustCiHostArchitecture::Aarch64,
            forge_domain::RuntimeInstanceId::from_uuid(uuid::Uuid::from_u128(0x5201)),
        )?;
        Ok(RustCiToolchainCapability::prepare(&input)?)
    }

    fn spawn_http_server(
        listener: TcpListener,
    ) -> Result<JoinHandle<Result<bool, io::Error>>, io::Error> {
        listener.set_nonblocking(true)?;
        thread::Builder::new()
            .name("forge-execution-test-http".to_owned())
            .spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(2);
                loop {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")?;
                            return Ok(true);
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            if Instant::now() >= deadline {
                                return Ok(false);
                            }
                            thread::sleep(POLL_INTERVAL);
                        }
                        Err(error) => return Err(error),
                    }
                }
            })
    }

    #[test]
    fn output_events_share_one_ordered_sequence_and_fixed_chunk_bound()
    -> Result<(), Box<dyn std::error::Error>> {
        let execution_id = ExecutionId::from_uuid(Uuid::from_u128(5_000));
        let (sink, mut receiver) = OutputEventSink::new(execution_id);
        let stdout = vec![b'o'; EXECUTION_OUTPUT_CHUNK_BYTES];
        let stderr = vec![b'e'; EXECUTION_OUTPUT_CHUNK_BYTES - 1];
        sink.publish_chunk(ExecutionOutputStream::Stdout, &stdout)?;
        sink.publish_chunk(ExecutionOutputStream::Stderr, &stderr)?;
        sink.finish()?;

        let events = receiver.drain(MAX_OUTPUT_EVENT_BACKLOG);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].sequence().get(), 1);
        assert_eq!(events[1].sequence().get(), 2);
        assert!(matches!(
            &events[0],
            ExecutionOutputEvent::Chunk(chunk)
                if chunk.stream() == ExecutionOutputStream::Stdout
                    && chunk.bytes().len() == EXECUTION_OUTPUT_CHUNK_BYTES
        ));
        assert!(matches!(
            &events[1],
            ExecutionOutputEvent::Chunk(chunk)
                if chunk.stream() == ExecutionOutputStream::Stderr
                    && chunk.bytes().len() < EXECUTION_OUTPUT_CHUNK_BYTES
        ));
        assert!(receiver.is_complete());
        Ok(())
    }

    #[test]
    fn sealed_output_cursor_requires_finished_drained_open_gap_free_sink()
    -> Result<(), Box<dyn std::error::Error>> {
        let execution_id = ExecutionId::from_uuid(Uuid::from_u128(5_010));
        let (unfinished, _receiver) = OutputEventSink::new(execution_id);
        assert_eq!(unfinished.sealed_output_cursor(), None);

        let (empty, _empty_receiver) = OutputEventSink::new(execution_id);
        empty.finish()?;
        assert_eq!(
            empty.sealed_output_cursor(),
            Some(ExecutionOutputCursor::initial(execution_id))
        );

        let (sink, mut receiver) = OutputEventSink::new(execution_id);
        sink.publish_chunk(ExecutionOutputStream::Stdout, b"sealed")?;
        sink.finish()?;
        assert_eq!(sink.sealed_output_cursor(), None);
        let events = receiver.drain(MAX_OUTPUT_EVENT_BACKLOG);
        let last = events.last().ok_or("sealed output event missing")?;
        assert_eq!(
            sink.sealed_output_cursor(),
            Some(ExecutionOutputCursor::from_sequence(
                execution_id,
                last.sequence(),
            ))
        );

        let (closed, closed_receiver) = OutputEventSink::new(execution_id);
        drop(closed_receiver);
        closed.publish_chunk(ExecutionOutputStream::Stdout, b"closed")?;
        closed.finish()?;
        assert_eq!(closed.sealed_output_cursor(), None);
        Ok(())
    }

    #[test]
    fn output_backpressure_is_reported_as_an_explicit_gap() -> Result<(), Box<dyn std::error::Error>>
    {
        let execution_id = ExecutionId::from_uuid(Uuid::from_u128(5_001));
        let (sink, mut receiver) = OutputEventSink::new(execution_id);
        for _ in 0..MAX_OUTPUT_EVENT_BACKLOG.saturating_sub(1) {
            sink.publish_chunk(ExecutionOutputStream::Stdout, b"x")?;
        }
        sink.publish_chunk(ExecutionOutputStream::Stdout, b"dropped")?;
        sink.finish()?;

        let events = receiver.drain(MAX_OUTPUT_EVENT_BACKLOG);
        assert_eq!(events.len(), MAX_OUTPUT_EVENT_BACKLOG);
        let Some(ExecutionOutputEvent::Gap(gap)) = events.last() else {
            return Err("missing backpressure gap".into());
        };
        assert_eq!(gap.first_missing().get(), MAX_OUTPUT_EVENT_BACKLOG as u64);
        assert_eq!(gap.last_missing().get(), MAX_OUTPUT_EVENT_BACKLOG as u64);
        assert_eq!(gap.omitted_bytes(), 7);
        assert_eq!(gap.cause(), ExecutionOutputGapCause::Backpressure);
        assert!(receiver.is_complete());
        assert_eq!(
            sink.sealed_output_cursor(),
            Some(ExecutionOutputCursor::from_sequence(
                execution_id,
                gap.sequence(),
            ))
        );
        Ok(())
    }

    #[test]
    fn output_finish_retries_terminal_gap_after_full_queue_drains()
    -> Result<(), Box<dyn std::error::Error>> {
        let execution_id = ExecutionId::from_uuid(Uuid::from_u128(5_006));
        let (sink, mut receiver) = OutputEventSink::new(execution_id);
        for _ in 0..MAX_OUTPUT_EVENT_BACKLOG.saturating_sub(1) {
            sink.publish_chunk(ExecutionOutputStream::Stdout, b"x")?;
        }

        // The producer normally reserves one slot for a pending gap.  Model
        // the audited state explicitly so this regression remains deterministic
        // even if that admission policy changes: the queue is full, the next
        // output sequence is still ordered, and then one omission is recorded.
        let final_chunk_sequence =
            ExecutionOutputSequence::new(u64::try_from(MAX_OUTPUT_EVENT_BACKLOG)?)?;
        let final_chunk = ExecutionOutputEvent::Chunk(ExecutionOutputChunk::new(
            execution_id,
            final_chunk_sequence,
            ExecutionOutputStream::Stdout,
            b"x",
        )?);
        if sink.sender.try_send(final_chunk).is_err() {
            return Err("queue unexpectedly closed".into());
        }
        {
            let mut state = sink.lock_state();
            assert_eq!(state.next_sequence, final_chunk_sequence);
            state.next_sequence = final_chunk_sequence.checked_next()?;
            state.queued_events += 1;
        }
        sink.record_omitted(
            ExecutionOutputStream::Stdout,
            7,
            ExecutionOutputGapCause::Backpressure,
        )?;
        sink.finish()?;
        assert!(!receiver.is_complete());
        assert_eq!(sink.sealed_output_cursor(), None);

        let mut events = Vec::new();
        for _ in 0..=MAX_OUTPUT_EVENT_BACKLOG {
            if receiver.is_complete() {
                break;
            }
            let drained = receiver.drain(1);
            assert_eq!(drained.len(), 1, "a non-empty queue must make progress");
            events.extend(drained);
        }

        assert!(receiver.is_complete());
        assert_eq!(events.len(), MAX_OUTPUT_EVENT_BACKLOG + 1);
        assert!(
            events
                .iter()
                .take(MAX_OUTPUT_EVENT_BACKLOG)
                .enumerate()
                .all(|(index, event)| event.sequence().get() == (index as u64) + 1)
        );
        let Some(ExecutionOutputEvent::Gap(gap)) = events.last() else {
            return Err("missing terminal backpressure gap".into());
        };
        assert_eq!(
            gap.first_missing().get(),
            (MAX_OUTPUT_EVENT_BACKLOG + 1) as u64
        );
        assert_eq!(
            gap.last_missing().get(),
            (MAX_OUTPUT_EVENT_BACKLOG + 1) as u64
        );
        assert_eq!(gap.sequence().get(), (MAX_OUTPUT_EVENT_BACKLOG + 2) as u64);
        assert_eq!(gap.omitted_bytes(), 7);
        assert_eq!(gap.cause(), ExecutionOutputGapCause::Backpressure);
        assert_eq!(
            sink.sealed_output_cursor(),
            Some(ExecutionOutputCursor::from_sequence(
                execution_id,
                events
                    .last()
                    .ok_or("missing final output event")?
                    .sequence(),
            ))
        );
        Ok(())
    }

    #[test]
    fn output_limit_is_reported_as_an_explicit_gap() -> Result<(), Box<dyn std::error::Error>> {
        let execution_id = ExecutionId::from_uuid(Uuid::from_u128(5_002));
        let (sink, mut receiver) = OutputEventSink::new(execution_id);
        sink.record_omitted(
            ExecutionOutputStream::Stderr,
            11,
            ExecutionOutputGapCause::OutputLimit,
        )?;
        sink.record_omitted(
            ExecutionOutputStream::Stderr,
            13,
            ExecutionOutputGapCause::OutputLimit,
        )?;
        sink.finish()?;

        let events = receiver.drain(MAX_OUTPUT_EVENT_BACKLOG);
        assert_eq!(events.len(), 1);
        let Some(ExecutionOutputEvent::Gap(gap)) = events.first() else {
            return Err("missing output-limit gap".into());
        };
        assert_eq!(gap.first_missing().get(), 1);
        assert_eq!(gap.last_missing().get(), 2);
        assert_eq!(gap.stream(), Some(ExecutionOutputStream::Stderr));
        assert_eq!(gap.omitted_bytes(), 24);
        assert_eq!(gap.omitted_chunks(), 2);
        assert_eq!(gap.cause(), ExecutionOutputGapCause::OutputLimit);
        assert!(receiver.is_complete());
        Ok(())
    }

    #[test]
    fn output_receiver_dequeue_releases_capacity_without_a_false_gap()
    -> Result<(), Box<dyn std::error::Error>> {
        let execution_id = ExecutionId::from_uuid(Uuid::from_u128(5_003));
        let (sink, mut receiver) = OutputEventSink::new(execution_id);
        for _ in 0..MAX_OUTPUT_EVENT_BACKLOG.saturating_sub(1) {
            sink.publish_chunk(ExecutionOutputStream::Stdout, b"x")?;
        }
        let first = receiver.drain(1);
        assert_eq!(first.len(), 1);
        sink.publish_chunk(ExecutionOutputStream::Stdout, b"after-dequeue")?;
        sink.finish()?;

        let mut events = first;
        events.extend(receiver.drain(MAX_OUTPUT_EVENT_BACKLOG));
        assert_eq!(events.len(), MAX_OUTPUT_EVENT_BACKLOG);
        assert!(
            events
                .iter()
                .all(|event| matches!(event, ExecutionOutputEvent::Chunk(_)))
        );
        assert!(receiver.is_complete());
        Ok(())
    }

    #[test]
    fn output_receiver_and_producer_interleave_without_false_gap()
    -> Result<(), Box<dyn std::error::Error>> {
        let execution_id = ExecutionId::from_uuid(Uuid::from_u128(5_005));
        let (sink, receiver) = OutputEventSink::new(execution_id);
        for _ in 0..MAX_OUTPUT_EVENT_BACKLOG.saturating_sub(1) {
            sink.publish_chunk(ExecutionOutputStream::Stdout, b"x")?;
        }
        let barrier = Arc::new(Barrier::new(2));
        let receiver_finished = Arc::new(AtomicBool::new(false));
        let receiver_barrier = Arc::clone(&barrier);
        let receiver_finished_flag = Arc::clone(&receiver_finished);
        let receiver_thread = thread::spawn(move || {
            receiver_barrier.wait();
            let mut receiver = receiver;
            let first = receiver.drain(1);
            receiver_finished_flag.store(true, Ordering::Release);
            (receiver, first)
        });
        barrier.wait();
        while !receiver_finished.load(Ordering::Acquire) {
            thread::yield_now();
        }
        sink.publish_chunk(ExecutionOutputStream::Stdout, b"after-interleave")?;
        let (mut receiver, first) = receiver_thread
            .join()
            .map_err(|_| "output receiver thread panicked")?;
        sink.finish()?;

        let mut events = first;
        events.extend(receiver.drain(MAX_OUTPUT_EVENT_BACKLOG));
        assert_eq!(events.len(), MAX_OUTPUT_EVENT_BACKLOG);
        assert!(
            events
                .iter()
                .all(|event| matches!(event, ExecutionOutputEvent::Chunk(_)))
        );
        assert!(receiver.is_complete());
        Ok(())
    }

    #[test]
    fn output_finish_guard_marks_a_panicking_producer_complete() {
        let execution_id = ExecutionId::from_uuid(Uuid::from_u128(5_004));
        let (sink, receiver) = OutputEventSink::new(execution_id);
        let guard = OutputEventFinishGuard::new(Arc::clone(&sink));
        let join = thread::spawn(move || {
            let _guard = guard;
            assert_eq!(std::hint::black_box(1), 2);
        });
        assert!(join.join().is_err());
        assert!(receiver.is_complete());
    }

    #[test]
    fn structured_argv_is_literal_and_environment_is_allowlisted()
    -> Result<(), Box<dyn std::error::Error>> {
        if nested_sandbox_execution_is_unavailable() {
            return Ok(());
        }
        let (root, layout) = layout("structured")?;
        let runner = ExecutionRunner::new(2)?;
        let injection = "literal; /usr/bin/touch should-not-exist";
        let outcome = runner
            .spawn(
                &layout,
                request(
                    10,
                    structured("/usr/bin/printf", &[injection])?,
                    ExecutionPermissions::new(true, false, false),
                    2_000,
                    4_096,
                )?,
            )?
            .wait()?;
        assert_eq!(outcome.status(), ExecutionCompletionStatus::Exited);
        assert_eq!(outcome.exit_code(), Some(0));
        assert_eq!(outcome.stdout().retained(), injection.as_bytes());
        assert!(!root.join("should-not-exist").exists());

        let environment = runner
            .spawn(
                &layout,
                request(
                    20,
                    structured("/usr/bin/env", &[])?,
                    ExecutionPermissions::new(true, false, false),
                    2_000,
                    8_192,
                )?,
            )?
            .wait()?;
        let environment = std::str::from_utf8(environment.stdout().retained())?;
        assert!(environment.contains("PATH=/usr/bin:/bin:/usr/sbin:/sbin"));
        assert!(environment.contains("LANG=C"));
        assert!(!environment.contains("SSH_AUTH_SOCK"));
        assert!(!environment.contains("API_KEY"));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn rust_ci_environment_is_product_owned_and_does_not_inherit_process_values()
    -> Result<(), Box<dyn std::error::Error>> {
        if nested_sandbox_execution_is_unavailable() {
            return Ok(());
        }
        let (root, layout) = layout("rust-ci-environment")?;
        let capability = rust_ci_capability(&root)?;
        let runtime = capability.ensure_runtime_paths(
            WorkspaceId::from_uuid(Uuid::from_u128(26)),
            layout.root_fingerprint()?,
            ExecutionId::from_uuid(Uuid::from_u128(25)),
        )?;
        let outcome = ExecutionRunner::new(1)?
            .spawn_with_launch_kind(
                &layout,
                request(
                    25,
                    structured("/usr/bin/env", &[])?,
                    ExecutionPermissions::new(false, false, true),
                    2_000,
                    8_192,
                )?,
                ExecutionLaunchKind::RustCi,
                Some(&capability),
            )?
            .wait()?;
        assert_eq!(outcome.status(), ExecutionCompletionStatus::Exited);
        assert_eq!(outcome.exit_code(), Some(0));
        let environment = std::str::from_utf8(outcome.stdout().retained())?;
        let mut actual = BTreeMap::new();
        for line in environment.lines() {
            let (key, value) = line.split_once('=').ok_or("malformed environment entry")?;
            assert!(actual.insert(key.to_owned(), value.to_owned()).is_none());
        }
        let expected = BTreeMap::from([
            (
                "PATH".to_owned(),
                format!(
                    "{}:{}/bin:{APPLE_DEVELOPER_BIN}:{SAFE_PATH}",
                    capability.view().bin_dir().display(),
                    capability.view().toolchain_path().display()
                ),
            ),
            (
                "RUSTUP".to_owned(),
                capability.view().rustup_path().display().to_string(),
            ),
            (
                "RUSTUP_TOOLCHAIN".to_owned(),
                capability.pinned_toolchain().to_owned(),
            ),
            (
                "RUSTUP_HOME".to_owned(),
                capability.view().rustup_home().display().to_string(),
            ),
            (
                "CARGO_HOME".to_owned(),
                runtime.cargo_home().display().to_string(),
            ),
            (
                "CARGO_TARGET_DIR".to_owned(),
                runtime.target_dir().display().to_string(),
            ),
            (
                "TMPDIR".to_owned(),
                runtime.temporary_dir().display().to_string(),
            ),
            ("HOME".to_owned(), runtime.home_dir().display().to_string()),
            ("RUSTUP_NO_UPDATE_CHECK".to_owned(), "1".to_owned()),
            ("CARGO_NET_OFFLINE".to_owned(), "true".to_owned()),
            ("CARGO_INCREMENTAL".to_owned(), "0".to_owned()),
            ("CARGO_PROFILE_DEV_DEBUG".to_owned(), "0".to_owned()),
            ("CARGO_PROFILE_TEST_DEBUG".to_owned(), "0".to_owned()),
            (
                RUST_CI_SANDBOX_MARKER_ENV.to_owned(),
                RUST_CI_SANDBOX_MARKER_VALUE.to_owned(),
            ),
            (
                RUST_CI_TEST_POLICY_ENV.to_owned(),
                RUST_CI_TEST_POLICY_VALUE.to_owned(),
            ),
            ("DEVELOPER_DIR".to_owned(), APPLE_DEVELOPER_DIR.to_owned()),
            ("SDKROOT".to_owned(), APPLE_SDK_ROOT.to_owned()),
            ("LANG".to_owned(), "C".to_owned()),
            ("LC_ALL".to_owned(), "C".to_owned()),
            ("GIT_TERMINAL_PROMPT".to_owned(), "0".to_owned()),
        ]);
        assert_eq!(actual, expected);
        assert!(!runtime.execution_root().exists());
        assert!(!runtime.target_dir().exists());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn rust_ci_descriptor_walk_child_probe() -> Result<(), Box<dyn std::error::Error>> {
        // This probe exercises the descriptor-walk contract that only
        // materializes inside the Rust-CI runtime (TMPDIR is set by that
        // lane); outside it, skip like the other nested-contract tests.
        if nested_sandbox_execution_is_unavailable() {
            return Ok(());
        }
        let unique = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let root = std::env::temp_dir().join(format!("forge-rust-ci-child-walk-{unique}"));
        fs::create_dir_all(&root)?;
        WorkspaceStateLayout::initialize(&root)?;
        let layout = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
        let confined = ConfinedWorkspace::open(&layout)?;
        drop(confined);

        let temporary =
            PathBuf::from(std::env::var_os("TMPDIR").ok_or("Rust CI TMPDIR is missing")?);
        let network_endpoint = temporary.join(RUST_CI_DESCRIPTOR_NETWORK_FILE);
        if !network_endpoint.try_exists()? {
            fs::remove_dir_all(root)?;
            return Ok(());
        }
        let execution_namespace = temporary
            .parent()
            .and_then(Path::parent)
            .ok_or("Rust CI TMPDIR has no execution namespace ancestor")?;
        let sibling = execution_namespace.join(RUST_CI_DESCRIPTOR_SIBLING_FILE);
        assert!(
            fs::read(&sibling).is_err(),
            "Rust CI sandbox unexpectedly read a sibling under the TMPDIR ancestor: {}",
            sibling.display()
        );
        assert!(
            fs::write(&sibling, b"mutated").is_err(),
            "Rust CI sandbox unexpectedly wrote a sibling under the TMPDIR ancestor"
        );
        let created = execution_namespace.join(RUST_CI_DESCRIPTOR_CREATED_FILE);
        assert!(
            fs::write(&created, b"created").is_err(),
            "Rust CI sandbox unexpectedly created a sibling under the TMPDIR ancestor"
        );

        let state_file = std::env::current_dir()?
            .join(".heterarchy-forge")
            .join(RUST_CI_DESCRIPTOR_STATE_FILE);
        assert!(
            fs::read(&state_file).is_err(),
            "Rust CI sandbox unexpectedly read Forge-owned Workspace state"
        );
        assert!(
            fs::write(&state_file, b"mutated").is_err(),
            "Rust CI sandbox unexpectedly wrote Forge-owned Workspace state"
        );

        let endpoint = fs::read_to_string(&network_endpoint)?;
        let connection = TcpStream::connect(endpoint.trim());
        assert!(
            connection.is_err(),
            "Rust CI sandbox unexpectedly allowed network access: {connection:?}"
        );

        let confined = ConfinedWorkspace::open(&layout)?;
        let mutation_root = root.join("prepared-mutation");
        fs::create_dir(&mutation_root)?;
        let mutation_path =
            forge_domain::WorkspaceRelativePath::new(PathBuf::from("prepared-mutation/probe.txt"))?;
        let created = confined
            .prepare_mutation(&FileMutationPlan::new(
                mutation_path.clone(),
                FileMutationKind::Create,
                FilePrecondition::Absent,
            ))?
            .apply(
                FileMutationId::from_uuid(Uuid::from_u128(9101)),
                Some(b"one"),
            )?;
        let created_hash = created.post_state().hash().ok_or("created hash missing")?;
        let replaced = confined
            .prepare_mutation(&FileMutationPlan::new(
                mutation_path.clone(),
                FileMutationKind::Replace,
                FilePrecondition::Matches(created_hash),
            ))?
            .apply(
                FileMutationId::from_uuid(Uuid::from_u128(9102)),
                Some(b"two"),
            )?;
        let replaced_hash = replaced
            .post_state()
            .hash()
            .ok_or("replaced hash missing")?;
        let deleted = confined
            .prepare_mutation(&FileMutationPlan::new(
                mutation_path,
                FileMutationKind::Delete,
                FilePrecondition::Matches(replaced_hash),
            ))?
            .apply(FileMutationId::from_uuid(Uuid::from_u128(9103)), None)?;
        assert_eq!(deleted.post_state(), forge_domain::FilePathState::Absent);
        assert!(!root.join("prepared-mutation/probe.txt").exists());

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn verification_runner_uses_frozen_input_and_preserves_it_after_exit()
    -> Result<(), Box<dyn std::error::Error>> {
        if nested_sandbox_execution_is_unavailable() {
            return Ok(());
        }
        let unique = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let root = std::env::temp_dir().join(format!("forge-verification-runner-{unique}"));
        let workspace = root.join("workspace");
        let product = root.join("product");
        fs::create_dir_all(&workspace)?;
        fs::create_dir_all(&product)?;
        WorkspaceStateLayout::initialize(&workspace)?;
        let layout = WorkspaceStateLayout::inspect_existing(&workspace)?.ok_or("layout missing")?;
        fs::write(workspace.join("input.txt"), b"frozen")?;
        let confined = forge_workspace::ConfinedWorkspace::open(&layout)?;
        let snapshot_id = forge_domain::VerificationInputId::from_uuid(Uuid::from_u128(0xA771));
        let staged = confined.stage_verification_input(snapshot_id, &AtomicBool::new(false))?;
        let snapshot = staged.publish()?;
        let fingerprint = snapshot.manifest().fingerprint();
        let source = snapshot.source_root().to_path_buf();
        fs::write(workspace.join("input.txt"), b"changed after capture")?;
        let capability = rust_ci_capability(&product)?;
        let script = r#"
            set -eu
            test "$(/bin/cat input.txt)" = frozen
            case "$PWD" in "$2"/runtime/executions/*/verification-source) ;; *) exit 30 ;; esac
            if /bin/cat "$1" >/dev/null 2>&1; then exit 31; fi
            if (printf invalid > input.txt) 2>/dev/null; then exit 32; fi
            if /bin/chmod u+w input.txt 2>/dev/null; then exit 33; fi
            if (printf extra > unexpected) 2>/dev/null; then exit 34; fi
            printf built > "$CARGO_TARGET_DIR/probe"
            printf temporary > "$TMPDIR/probe"
            printf home > "$HOME/probe"
            printf verified-frozen
        "#;
        let kind = ExecutionKind::Structured {
            program: forge_domain::ExecutionProgram::new("/bin/sh".into())?,
            arguments: vec![
                forge_domain::ExecutionArgument::new("-c".into())?,
                forge_domain::ExecutionArgument::new(script.into())?,
                forge_domain::ExecutionArgument::new("verification-probe".into())?,
                forge_domain::ExecutionArgument::new(workspace.join("input.txt").into_os_string())?,
                forge_domain::ExecutionArgument::new(
                    capability.view().root().as_os_str().to_owned(),
                )?,
            ],
        };
        let writable_request = request(
            0xA771,
            kind.clone(),
            ExecutionPermissions::new(true, true, false),
            5_000,
            4096,
        )?;
        let request = request(
            0xA771,
            kind,
            ExecutionPermissions::new(true, false, false),
            5_000,
            4096,
        )?;
        let runner = ExecutionRunner::new(1)?;
        assert!(matches!(
            runner.spawn_verification(
                &layout,
                writable_request,
                &capability,
                confined.open_verification_input(snapshot_id, fingerprint)?
            ),
            Err(ExecutionError::VerificationInputMismatch)
        ));
        let foreign = root.join("foreign-workspace");
        fs::create_dir(&foreign)?;
        WorkspaceStateLayout::initialize(&foreign)?;
        let foreign_layout =
            WorkspaceStateLayout::inspect_existing(&foreign)?.ok_or("foreign layout missing")?;
        assert!(matches!(
            runner.spawn_verification(
                &foreign_layout,
                request.clone(),
                &capability,
                confined.open_verification_input(snapshot_id, fingerprint)?
            ),
            Err(ExecutionError::VerificationInputMismatch)
        ));
        let running = runner.spawn_verification(&layout, request, &capability, snapshot)?;
        let result = running.wait()?;
        assert_eq!(
            result.exit_code(),
            Some(0),
            "snapshot execution failed: {result:?}"
        );
        assert_eq!(result.stdout().retained(), b"verified-frozen");
        let reopened = confined.open_verification_input(snapshot_id, fingerprint)?;
        assert_eq!(reopened.source_root(), source);
        assert_eq!(fs::read(source.join("input.txt"))?, b"frozen");
        assert_eq!(
            fs::read(workspace.join("input.txt"))?,
            b"changed after capture"
        );
        // Test-only cleanup of the exact fixture we created. Production keeps
        // published input until its durable retention owner releases it.
        fs::set_permissions(&source, fs::Permissions::from_mode(0o700))?;
        fs::set_permissions(
            source.parent().ok_or("snapshot parent missing")?,
            fs::Permissions::from_mode(0o700),
        )?;
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn rust_ci_sandbox_allows_descriptor_walk_only_into_product_temporary_root()
    -> Result<(), Box<dyn std::error::Error>> {
        if nested_sandbox_execution_is_unavailable() {
            return Ok(());
        }
        let unique = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let root =
            std::env::temp_dir().join(format!("forge-execution-rust-ci-descriptor-walk-{unique}"));
        let workspace_root = root.join("workspace");
        let product_root = root.join("product");
        fs::create_dir_all(&workspace_root)?;
        fs::create_dir_all(&product_root)?;
        WorkspaceStateLayout::initialize(&workspace_root)?;
        let layout =
            WorkspaceStateLayout::inspect_existing(&workspace_root)?.ok_or("layout missing")?;
        let capability = rust_ci_capability(&product_root)?;
        let execution_id = ExecutionId::from_uuid(Uuid::from_u128(27));
        let runtime = capability.ensure_runtime_paths(
            WorkspaceId::from_uuid(Uuid::from_u128(28)),
            layout.root_fingerprint()?,
            execution_id,
        )?;
        let execution_namespace = runtime
            .temporary_dir()
            .parent()
            .and_then(Path::parent)
            .ok_or("Rust CI TMPDIR has no execution namespace ancestor")?;
        let sibling = execution_namespace.join(RUST_CI_DESCRIPTOR_SIBLING_FILE);
        fs::write(&sibling, b"sibling")?;
        let created = execution_namespace.join(RUST_CI_DESCRIPTOR_CREATED_FILE);
        let state_file = layout.state_root().join(RUST_CI_DESCRIPTOR_STATE_FILE);
        fs::write(&state_file, b"state")?;

        let listener = TcpListener::bind("127.0.0.1:0")?;
        let endpoint = listener.local_addr()?.to_string();
        let server = spawn_http_server(listener)?;
        fs::write(
            runtime
                .temporary_dir()
                .join(RUST_CI_DESCRIPTOR_NETWORK_FILE),
            endpoint,
        )?;
        let child = runtime.temporary_dir().join("forge-execution-walk-probe");
        let current_executable = std::env::current_exe()?;
        fs::copy(&current_executable, &child)?;
        fs::set_permissions(&child, fs::metadata(&current_executable)?.permissions())?;
        let child_program = child.to_str().ok_or("child test path is not UTF-8")?;
        let execution = ExecutionRunner::new(1)?.spawn_with_launch_kind(
            &layout,
            request(
                execution_id.into_uuid().as_u128(),
                structured(
                    child_program,
                    &[
                        "runner::tests::rust_ci_descriptor_walk_child_probe",
                        "--exact",
                    ],
                )?,
                ExecutionPermissions::new(true, false, false),
                5_000,
                8_192,
            )?,
            ExecutionLaunchKind::RustCi,
            Some(&capability),
        )?;
        let outcome = execution.wait();
        let server_accepted = server.join().map_err(|_| "network server panicked")??;
        let outcome = outcome?;
        assert_eq!(outcome.status(), ExecutionCompletionStatus::Exited);
        assert_eq!(
            outcome.exit_code(),
            Some(0),
            "child stdout: {}\nchild stderr: {}",
            String::from_utf8_lossy(outcome.stdout().retained()),
            String::from_utf8_lossy(outcome.stderr().retained())
        );
        assert!(
            !server_accepted,
            "Rust CI sandbox unexpectedly accepted network access"
        );
        assert_eq!(fs::read(&sibling)?, b"sibling");
        assert!(!created.exists());
        assert_eq!(fs::read(&state_file)?, b"state");
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn rust_ci_keychain_access_is_denied_by_mach_service_policy()
    -> Result<(), Box<dyn std::error::Error>> {
        if nested_sandbox_execution_is_unavailable() {
            return Ok(());
        }
        if !cfg!(target_os = "macos") {
            return Ok(());
        }
        let (root, layout) = layout("rust-ci-keychain")?;
        let capability = rust_ci_capability(&root)?;
        let execution_id = ExecutionId::from_uuid(Uuid::from_u128(85));
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(86));
        let runtime = capability.ensure_runtime_paths(
            workspace_id,
            layout.root_fingerprint()?,
            execution_id,
        )?;
        let keychain = runtime.home_dir().join("forge-rust-ci.keychain-db");
        let keychain = keychain.to_str().ok_or("keychain path is not UTF-8")?;
        let create = Command::new("/usr/bin/security")
            .args(["create-keychain", "-p", "forge-test-password", keychain])
            .output()?;
        if !create.status.success() {
            return Err(format!(
                "failed to create disposable keychain: {}",
                String::from_utf8_lossy(&create.stderr)
            )
            .into());
        }
        let account = "forge-rust-ci-account";
        let service = "forge-rust-ci-service";
        let secret = "forge-rust-ci-secret";
        let add = Command::new("/usr/bin/security")
            .args([
                "add-generic-password",
                "-a",
                account,
                "-s",
                service,
                "-w",
                secret,
                keychain,
            ])
            .output()?;
        if !add.status.success() {
            return Err(format!(
                "failed to add disposable keychain item: {}",
                String::from_utf8_lossy(&add.stderr)
            )
            .into());
        }
        let outcome = ExecutionRunner::new(1)?
            .spawn_with_launch_kind(
                &layout,
                request(
                    execution_id.into_uuid().as_u128(),
                    structured(
                        "/usr/bin/security",
                        &[
                            "find-generic-password",
                            "-a",
                            account,
                            "-s",
                            service,
                            "-w",
                            keychain,
                        ],
                    )?,
                    ExecutionPermissions::new(true, false, false),
                    2_000,
                    8_192,
                )?,
                ExecutionLaunchKind::RustCi,
                Some(&capability),
            )?
            .wait()?;
        assert_eq!(outcome.status(), ExecutionCompletionStatus::Exited);
        assert_ne!(outcome.exit_code(), Some(0));
        assert!(!String::from_utf8_lossy(outcome.stdout().retained()).contains(secret));
        // Runtime cleanup removes the disposable keychain file with the
        // execution HOME; do not invoke `security delete-keychain` a second
        // time after that owned cleanup.
        assert!(!runtime.execution_root().exists());
        assert!(!runtime.target_dir().exists());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn rust_ci_spawn_failure_cleans_execution_and_target_paths()
    -> Result<(), Box<dyn std::error::Error>> {
        if nested_sandbox_execution_is_unavailable() {
            return Ok(());
        }
        let (root, layout) = layout("rust-ci-spawn-failure")?;
        let capability = rust_ci_capability(&root)?;
        let execution_id = ExecutionId::from_uuid(Uuid::from_u128(95));
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(96));
        let runtime = capability.ensure_runtime_paths(
            workspace_id,
            layout.root_fingerprint()?,
            execution_id,
        )?;
        let running = ExecutionRunner::new(1)?.spawn_with_launch_kind(
            &layout,
            request(
                execution_id.into_uuid().as_u128(),
                structured("/definitely/missing/forge-rust-ci-command", &[])?,
                ExecutionPermissions::new(true, false, false),
                2_000,
                8_192,
            )?,
            ExecutionLaunchKind::RustCi,
            Some(&capability),
        )?;
        let cleanup_allowed = match running.wait() {
            Ok(outcome) => {
                assert_ne!(outcome.exit_code(), Some(0));
                true
            }
            Err(ExecutionError::SignalProcessGroup(source)) if source == Errno::PERM => {
                // A very short-lived sandbox child can disappear before the
                // post-exit process-group probe. If the recycled group is not
                // signalable, production preserves the runtime paths because
                // the process group was not positively reaped.
                false
            }
            Err(error) => return Err(error.into()),
        };
        assert_eq!(runtime.execution_root().exists(), !cleanup_allowed);
        assert_eq!(runtime.target_dir().exists(), !cleanup_allowed);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn rust_ci_disk_policy_stops_before_a_sparse_limit_overrun_and_cleans()
    -> Result<(), Box<dyn std::error::Error>> {
        if nested_sandbox_execution_is_unavailable() {
            return Ok(());
        }
        let (root, layout) = layout("rust-ci-disk-limit")?;
        let capability = rust_ci_capability(&root)?;
        let execution_id = ExecutionId::from_uuid(Uuid::from_u128(105));
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(106));
        let runtime = capability.ensure_runtime_paths(
            workspace_id,
            layout.root_fingerprint()?,
            execution_id,
        )?;
        let oversized = runtime.target_dir().join("logical-limit");
        let file = std::fs::File::create(&oversized)?;
        file.set_len(crate::RUST_CI_MAX_LOGICAL_BYTES.saturating_add(1))?;
        let running = ExecutionRunner::new(1)?.spawn_with_launch_kind(
            &layout,
            request(
                execution_id.into_uuid().as_u128(),
                structured("/bin/sleep", &["1"])?,
                ExecutionPermissions::new(true, false, false),
                2_000,
                8_192,
            )?,
            ExecutionLaunchKind::RustCi,
            Some(&capability),
        )?;
        let Err(error) = running.wait() else {
            return Err("disk limit execution unexpectedly succeeded".into());
        };
        assert!(matches!(error, ExecutionError::RustCiDisk(_)));
        assert!(!runtime.execution_root().exists());
        assert!(!runtime.target_dir().exists());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn real_macos_sandbox_enforces_workspace_outside_and_state_boundaries()
    -> Result<(), Box<dyn std::error::Error>> {
        if nested_sandbox_execution_is_unavailable() {
            return Ok(());
        }
        let (root, layout) = layout("filesystem")?;
        let outside = root.with_extension("outside");
        let script = format!(
            "printf inside > \"$HOME/inside.txt\"; printf outside > '{}'",
            outside.display()
        );
        let runner = ExecutionRunner::new(1)?;
        let outcome = runner
            .spawn(
                &layout,
                request(
                    30,
                    shell(script)?,
                    ExecutionPermissions::new(true, true, false),
                    2_000,
                    8_192,
                )?,
            )?
            .wait()?;
        assert_eq!(outcome.status(), ExecutionCompletionStatus::Exited);
        assert_ne!(outcome.exit_code(), Some(0));
        assert_eq!(fs::read(root.join("inside.txt"))?, b"inside");
        assert!(!outside.exists());

        let outside_read = runner
            .spawn(
                &layout,
                request(
                    31,
                    structured("/bin/cat", &["/etc/hosts"])?,
                    ExecutionPermissions::new(true, false, false),
                    2_000,
                    8_192,
                )?,
            )?
            .wait()?;
        assert_ne!(outside_read.exit_code(), Some(0));
        assert!(outside_read.stdout().retained().is_empty());

        let state_secret = layout.state_root().join("execution-secret");
        fs::write(&state_secret, b"must-not-escape")?;
        let state_secret = state_secret.to_str().ok_or("state path is not UTF-8")?;
        let state_read = runner
            .spawn(
                &layout,
                request(
                    32,
                    structured("/bin/cat", &[state_secret])?,
                    ExecutionPermissions::new(true, false, false),
                    2_000,
                    8_192,
                )?,
            )?
            .wait()?;
        assert_ne!(state_read.exit_code(), Some(0));
        assert!(state_read.stdout().retained().is_empty());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn output_is_drained_but_retained_bytes_are_bounded() -> Result<(), Box<dyn std::error::Error>>
    {
        if nested_sandbox_execution_is_unavailable() {
            return Ok(());
        }
        let (root, layout) = layout("output")?;
        let outcome = ExecutionRunner::new(1)?
            .spawn(
                &layout,
                request(
                    40,
                    structured("/usr/bin/yes", &["bounded"])?,
                    ExecutionPermissions::new(false, false, false),
                    200,
                    1_024,
                )?,
            )?
            .wait()?;
        assert_eq!(outcome.status(), ExecutionCompletionStatus::TimedOut);
        assert_eq!(outcome.stdout().retained().len(), 1_024);
        assert!(outcome.stdout().truncated());
        assert!(outcome.stdout().total_bytes() > 1_024);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn process_output_events_are_bounded_and_report_output_limit_gap()
    -> Result<(), Box<dyn std::error::Error>> {
        if nested_sandbox_execution_is_unavailable() {
            return Ok(());
        }
        let (root, layout) = layout("output-events")?;
        let payload = "x".repeat(2_048);
        let runner = ExecutionRunner::new(1)?;
        let mut running = runner.spawn(
            &layout,
            request(
                41,
                structured("/usr/bin/printf", &[&payload])?,
                ExecutionPermissions::new(false, false, false),
                2_000,
                1_024,
            )?,
        )?;
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut terminal = None;
        let mut events = Vec::new();
        while terminal.is_none() || !running.output_events_complete() {
            events.extend(running.drain_output_events(MAX_OUTPUT_EVENT_BACKLOG));
            if terminal.is_none() {
                terminal = running.try_wait()?;
            }
            if Instant::now() >= deadline {
                return Err("bounded output event stream did not settle".into());
            }
            thread::yield_now();
        }
        events.extend(running.drain_output_events(MAX_OUTPUT_EVENT_BACKLOG));
        let outcome = terminal.ok_or("missing terminal outcome")?;
        assert_eq!(outcome.status(), ExecutionCompletionStatus::Exited);
        assert_eq!(outcome.stdout().retained().len(), 1_024);
        assert!(outcome.stdout().truncated());
        assert_eq!(events.len(), 2);
        assert!(matches!(
            &events[0],
            ExecutionOutputEvent::Chunk(chunk)
                if chunk.bytes().len() <= EXECUTION_OUTPUT_CHUNK_BYTES
        ));
        let Some(ExecutionOutputEvent::Gap(gap)) = events.get(1) else {
            return Err("missing output-limit gap".into());
        };
        assert_eq!(gap.omitted_bytes(), 1_024);
        assert_eq!(gap.cause(), ExecutionOutputGapCause::OutputLimit);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn real_macos_sandbox_network_permission_is_enforced() -> Result<(), Box<dyn std::error::Error>>
    {
        if nested_sandbox_execution_is_unavailable() {
            return Ok(());
        }
        let (root, layout) = layout("network")?;
        let runner = ExecutionRunner::new(1)?;
        let denied_listener = TcpListener::bind("127.0.0.1:0")?;
        let denied_port = denied_listener.local_addr()?.port();
        let denied_server = spawn_http_server(denied_listener)?;
        let denied_connect = format!("127.0.0.1:80:127.0.0.1:{denied_port}");
        let denied = runner
            .spawn(
                &layout,
                request(
                    45,
                    structured(
                        "/usr/bin/curl",
                        &[
                            "--silent",
                            "--max-time",
                            "1",
                            "http://127.0.0.1",
                            "--connect-to",
                            &denied_connect,
                        ],
                    )?,
                    ExecutionPermissions::new(false, false, false),
                    3_000,
                    4_096,
                )?,
            )?
            .wait()?;
        assert_ne!(denied.exit_code(), Some(0));
        assert!(!denied_server.join().map_err(|_| "server panicked")??);

        let allowed_listener = TcpListener::bind("127.0.0.1:0")?;
        let allowed_port = allowed_listener.local_addr()?.port();
        let allowed_server = spawn_http_server(allowed_listener)?;
        let allowed_connect = format!("127.0.0.1:80:127.0.0.1:{allowed_port}");
        let allowed = runner
            .spawn(
                &layout,
                request(
                    46,
                    structured(
                        "/usr/bin/curl",
                        &[
                            "--silent",
                            "--max-time",
                            "1",
                            "http://127.0.0.1",
                            "--connect-to",
                            &allowed_connect,
                        ],
                    )?,
                    ExecutionPermissions::new(false, false, true),
                    3_000,
                    4_096,
                )?,
            )?
            .wait()?;
        assert_eq!(
            allowed.exit_code(),
            Some(0),
            "stderr: {}",
            String::from_utf8_lossy(allowed.stderr().retained())
        );
        assert_eq!(allowed.stdout().retained(), b"ok");
        assert!(allowed_server.join().map_err(|_| "server panicked")??);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn cancellation_and_timeout_reap_process_groups_and_release_capacity()
    -> Result<(), Box<dyn std::error::Error>> {
        if nested_sandbox_execution_is_unavailable() {
            return Ok(());
        }
        let (root, layout) = layout("cancel")?;
        let runner = ExecutionRunner::new(1)?;
        let running = runner.spawn(
            &layout,
            request(
                50,
                shell("printf ready > \"$HOME/ready\"; exec /bin/sleep 30".to_owned())?,
                ExecutionPermissions::new(true, true, false),
                30_000,
                4_096,
            )?,
        )?;
        assert!(matches!(
            runner.spawn(
                &layout,
                request(
                    60,
                    structured("/usr/bin/true", &[])?,
                    ExecutionPermissions::new(false, false, false),
                    1_000,
                    1_024,
                )?
            ),
            Err(ExecutionError::Capacity { maximum: 1 })
        ));
        let ready_deadline = Instant::now() + Duration::from_secs(2);
        while !root.join("ready").exists() && Instant::now() < ready_deadline {
            thread::sleep(POLL_INTERVAL);
        }
        assert!(root.join("ready").is_file());
        running.cancel()?;
        let cancelled = running.wait()?;
        assert_eq!(cancelled.status(), ExecutionCompletionStatus::Cancelled);
        assert_eq!(runner.active_count(), 0);

        let timed_out = runner
            .spawn(
                &layout,
                request(
                    70,
                    shell("/bin/sleep 30 & echo $! > \"$HOME/child.pid\"; wait".to_owned())?,
                    ExecutionPermissions::new(true, true, false),
                    300,
                    4_096,
                )?,
            )?
            .wait()?;
        assert_eq!(timed_out.status(), ExecutionCompletionStatus::TimedOut);
        let child_pid = fs::read_to_string(root.join("child.pid"))?;
        let child_pid = i32::from_str(child_pid.trim())?;
        let child_pid = Pid::from_raw(child_pid).ok_or("invalid child pid")?;
        let reap_deadline = Instant::now() + Duration::from_secs(1);
        while test_kill_process(child_pid).is_ok() && Instant::now() < reap_deadline {
            thread::sleep(POLL_INTERVAL);
        }
        assert_eq!(test_kill_process(child_pid), Err(Errno::SRCH));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn rust_ci_launch_rejects_runtime_symlink_swap_without_following_outside()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, layout) = layout("rust-ci-runtime-symlink")?;
        let capability = rust_ci_capability(&root)?;
        let execution_id = ExecutionId::from_uuid(Uuid::from_u128(115));
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(116));
        let runtime = capability.ensure_runtime_paths(
            workspace_id,
            layout.root_fingerprint()?,
            execution_id,
        )?;
        let outside = root.join("outside-runtime");
        fs::create_dir_all(&outside)?;
        fs::write(outside.join("must-survive"), b"outside")?;
        fs::remove_dir(runtime.target_dir())?;
        std::os::unix::fs::symlink(&outside, runtime.target_dir())?;
        let Err(error) = ExecutionRunner::new(1)?.spawn_with_launch_kind(
            &layout,
            request(
                execution_id.into_uuid().as_u128(),
                structured("/bin/true", &[])?,
                ExecutionPermissions::new(true, false, false),
                2_000,
                8_192,
            )?,
            ExecutionLaunchKind::RustCi,
            Some(&capability),
        ) else {
            return Err("runtime symlink swap was accepted".into());
        };
        assert!(matches!(
            error,
            ExecutionError::RustCiUnavailable(RustCiDiscoveryError::ProductRuntimeMismatch)
        ));
        assert_eq!(fs::read(outside.join("must-survive"))?, b"outside");
        Ok(())
    }
}
