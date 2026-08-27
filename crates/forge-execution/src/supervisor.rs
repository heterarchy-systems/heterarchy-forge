use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use forge_domain::{
    ExecutionFailureCode, ExecutionId, ExecutionOutcome, ExecutionRequest, WorkspaceId,
};
use forge_workspace::ExistingWorkspaceStateLayout;
use thiserror::Error;

use crate::{ExecutionError, ExecutionRunner, RunningExecution};

const SUPERVISOR_QUEUE_CAPACITY: usize = 32;
const MAX_COMPLETION_BACKLOG: usize = 64;
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const THREAD_NAME: &str = "heterarchy-forge-execution-supervisor";

type Response<T> = SyncSender<Result<T, ExecutionSupervisorError>>;

#[derive(Debug)]
enum SupervisorRequest {
    Start {
        layout: ExistingWorkspaceStateLayout,
        request: Box<ExecutionRequest>,
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
    DrainEvents {
        maximum: usize,
        response: Response<Vec<ExecutionSupervisorEvent>>,
    },
    Shutdown {
        response: SyncSender<ExecutionSupervisorShutdown>,
    },
}

#[must_use]
#[derive(Debug, Clone)]
pub struct ExecutionSupervisorEvent {
    workspace_id: WorkspaceId,
    execution_id: ExecutionId,
    result: Result<ExecutionOutcome, ExecutionFailureCode>,
}

impl ExecutionSupervisorEvent {
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
}

#[must_use]
#[derive(Debug)]
pub struct ExecutionSupervisorShutdown {
    active_cancelled: usize,
    events: Vec<ExecutionSupervisorEvent>,
}

impl ExecutionSupervisorShutdown {
    pub const fn active_cancelled(&self) -> usize {
        self.active_cancelled
    }

    pub fn events(&self) -> &[ExecutionSupervisorEvent] {
        &self.events
    }
}

#[derive(Debug, Clone)]
pub struct ExecutionSupervisorClient {
    sender: SyncSender<SupervisorRequest>,
    accepting: Arc<AtomicBool>,
}

impl ExecutionSupervisorClient {
    pub fn start_execution(
        &self,
        layout: ExistingWorkspaceStateLayout,
        request: ExecutionRequest,
    ) -> Result<ExecutionId, ExecutionSupervisorError> {
        self.submit(|response| SupervisorRequest::Start {
            layout,
            request: Box::new(request),
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

    pub fn drain_events(
        &self,
        maximum: usize,
    ) -> Result<Vec<ExecutionSupervisorEvent>, ExecutionSupervisorError> {
        if maximum == 0 || maximum > MAX_COMPLETION_BACKLOG {
            return Err(ExecutionSupervisorError::InvalidDrainLimit {
                actual: maximum,
                maximum: MAX_COMPLETION_BACKLOG,
            });
        }
        self.submit(|response| SupervisorRequest::DrainEvents { maximum, response })
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
                .map_err(|_| ExecutionSupervisorError::Closed)?,
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
        let report = response_receiver
            .recv()
            .map_err(|_| ExecutionSupervisorError::Closed)?;
        thread
            .join()
            .map_err(|_| ExecutionSupervisorError::ThreadPanicked)?;
        Ok(report)
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
    workspace_id: WorkspaceId,
    handle: RunningExecution,
}

struct StopWaiter {
    cancelled: usize,
    response: Response<usize>,
}

struct SupervisorRuntime {
    runner: ExecutionRunner,
    receiver: Receiver<SupervisorRequest>,
    accepting: Arc<AtomicBool>,
    active: HashMap<ExecutionId, ActiveExecution>,
    events: VecDeque<ExecutionSupervisorEvent>,
    stop_waiters: Vec<StopWaiter>,
    shutdown: Option<(usize, Option<SyncSender<ExecutionSupervisorShutdown>>)>,
}

impl SupervisorRuntime {
    fn new(
        runner: ExecutionRunner,
        receiver: Receiver<SupervisorRequest>,
        accepting: Arc<AtomicBool>,
    ) -> Self {
        Self {
            runner,
            receiver,
            accepting,
            active: HashMap::new(),
            events: VecDeque::new(),
            stop_waiters: Vec::new(),
            shutdown: None,
        }
    }

    fn run(mut self) {
        loop {
            self.poll_completions();
            self.finish_drains();
            if self.shutdown.is_some() && self.active.is_empty() {
                self.finish_shutdown();
                break;
            }
            match self.receiver.recv_timeout(POLL_INTERVAL) {
                Ok(request) => self.handle_request(request),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    self.accepting.store(false, Ordering::Release);
                    self.begin_shutdown(None);
                }
            }
        }
        self.accepting.store(false, Ordering::Release);
    }

    fn handle_request(&mut self, request: SupervisorRequest) {
        match request {
            SupervisorRequest::Start {
                layout,
                request,
                response,
            } => {
                let result = self.start_execution(&layout, *request);
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
            SupervisorRequest::DrainEvents { maximum, response } => {
                let count = maximum.min(self.events.len());
                let events = self.events.drain(..count).collect();
                let _ignored = response.send(Ok(events));
            }
            SupervisorRequest::Shutdown { response } => {
                self.accepting.store(false, Ordering::Release);
                self.begin_shutdown(Some(response));
            }
        }
    }

    fn start_execution(
        &mut self,
        layout: &ExistingWorkspaceStateLayout,
        request: ExecutionRequest,
    ) -> Result<ExecutionId, ExecutionSupervisorError> {
        if self.shutdown.is_some() || !self.stop_waiters.is_empty() {
            return Err(ExecutionSupervisorError::Draining);
        }
        if self.active.len().saturating_add(self.events.len()) >= MAX_COMPLETION_BACKLOG {
            return Err(ExecutionSupervisorError::CompletionBacklog);
        }
        let id = request.id();
        if self.active.contains_key(&id) {
            return Err(ExecutionSupervisorError::DuplicateExecution(id));
        }
        let workspace_id = request.workspace_id();
        let handle = self.runner.spawn(layout, request)?;
        self.active.insert(
            id,
            ActiveExecution {
                workspace_id,
                handle,
            },
        );
        Ok(id)
    }

    fn cancel_one(&mut self, id: ExecutionId) -> Result<bool, ExecutionSupervisorError> {
        let Some(active) = self.active.get(&id) else {
            return Ok(false);
        };
        active.handle.cancel()?;
        Ok(true)
    }

    fn cancel_matching(
        &mut self,
        predicate: impl Fn(&ActiveExecution) -> bool,
    ) -> Result<usize, ExecutionSupervisorError> {
        let mut cancelled = 0;
        for active in self.active.values().filter(|active| predicate(active)) {
            active.handle.cancel()?;
            cancelled += 1;
        }
        Ok(cancelled)
    }

    fn poll_completions(&mut self) {
        let ids: Vec<_> = self.active.keys().copied().collect();
        for id in ids {
            let result = self.active.get_mut(&id).map(|active| {
                active
                    .handle
                    .try_wait()
                    .map_err(|error| error.failure_code())
            });
            let Some(result) = result else {
                continue;
            };
            let terminal = match result {
                Ok(Some(outcome)) => Some(Ok(outcome)),
                Ok(None) => None,
                Err(failure) => Some(Err(failure)),
            };
            let Some(result) = terminal else {
                continue;
            };
            let Some(active) = self.active.remove(&id) else {
                continue;
            };
            self.events.push_back(ExecutionSupervisorEvent {
                workspace_id: active.workspace_id,
                execution_id: id,
                result,
            });
        }
    }

    fn finish_drains(&mut self) {
        if !self.active.is_empty() {
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
        let report = ExecutionSupervisorShutdown {
            active_cancelled,
            events: self.events.drain(..).collect(),
        };
        if let Some(response) = response {
            let _ignored = response.send(report);
        }
    }
}

#[derive(Debug, Error)]
pub enum ExecutionSupervisorError {
    #[error("execution supervisor queue is full")]
    QueueFull,
    #[error("execution supervisor is closed")]
    Closed,
    #[error("execution supervisor is draining")]
    Draining,
    #[error("execution completion backlog is full")]
    CompletionBacklog,
    #[error("Execution {0} is already active")]
    DuplicateExecution(ExecutionId),
    #[error("execution event drain limit {actual} is outside 1..={maximum}")]
    InvalidDrainLimit { actual: usize, maximum: usize },
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
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    use forge_domain::{
        ActivityId, ExecutionArgument, ExecutionAttribution, ExecutionKind, ExecutionLimits,
        ExecutionOutputLimit, ExecutionPermissions, ExecutionProgram, ExecutionTimeoutMillis,
    };
    use forge_workspace::WorkspaceStateLayout;
    use uuid::Uuid;

    use super::*;

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

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

    #[test]
    fn stop_all_drains_owned_groups_and_rejects_no_completed_event()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, layout) = fixture()?;
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(100));
        let mut supervisor = ExecutionSupervisor::start(2)?;
        let client = supervisor.client();
        let id = client.start_execution(
            layout,
            request(101, workspace_id, "/bin/sleep", &["30"], 30_000)?,
        )?;
        assert_eq!(client.stop_all()?, 1);
        let events = client.drain_events(8)?;
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
    fn workspace_cancel_is_scoped_and_completion_backpressure_is_bounded()
    -> Result<(), Box<dyn std::error::Error>> {
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
            let events = client.drain_events(8)?;
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
        assert_eq!(client.drain_events(8)?.len(), 1);
        let report = supervisor.shutdown()?;
        assert_eq!(report.active_cancelled(), 0);
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
