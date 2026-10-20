//! Async-to-blocking command bridge with explicit bounds and deadline
//! semantics (design contract A5).
//!
//! Async handlers submit `(Command, oneshot)` over a bounded channel to
//! dedicated worker threads. Workers execute the synchronous forge-control
//! client call. A full queue is an immediate typed `CapacityExceeded`
//! rejection with no waiting. Once a worker accepts a command, a caller
//! deadline or lost connection no longer proves non-execution: the handler
//! reports `UNKNOWN_OUTCOME` with the command's durable readback hint while the
//! worker may still finish the durable effect.

use std::sync::Arc;
use std::time::Duration;

use crate::error::ForgeError;
use crate::ops::Command;
use forge_control::{
    ForgeApprovalCoordinatorClient, ForgeControlClient, ForgeExecutionCoordinatorClient,
};
use tokio::sync::{mpsc, oneshot};

/// One completed bridge outcome.
#[must_use]
#[derive(Debug, Clone)]
pub enum BridgeOutcome {
    /// The control call returned; the result is the serialized projection.
    Completed(Result<serde_json::Value, ForgeError>),
    /// The command was admitted but no result arrived before the deadline.
    UnknownOutcome,
}

/// Port seam for the control boundary. The production executor runs the
/// closed-command dispatch on bounded bridge workers; tests substitute a
/// bounded fake to exercise saturation, deadlines, and shutdown ordering.
pub trait CommandExecutor: std::fmt::Debug + Send + Sync + 'static {
    /// Submit one command. `Ok(receiver)` proves admission; `Err` is an
    /// immediate typed rejection (queue saturation or shutdown).
    fn submit(&self, command: Command) -> Result<oneshot::Receiver<BridgeOutcome>, ForgeError>;

    /// Nonblocking admission of a cancellable observation. The HTTP handler
    /// owns its handle and separate waiter budget until completion or drop.
    fn begin_wait(
        &self,
        _request: forge_control::ExecutionWaitParameters,
    ) -> Result<forge_control::ExecutionWaitHandle, ForgeError> {
        Err(ForgeError::capacity_exceeded("execution wait unavailable"))
    }

    /// Stop accepting new commands before the drain phase begins.
    fn stop_admission(&self) {}

    /// Number of commands currently admitted but not yet completed.
    fn inflight(&self) -> usize;

    /// Cancel/wait phase: stop accepting, wait (bounded) for admitted work,
    /// then attempt a bounded worker join. The return value reports work that
    /// remained active after the bound.
    fn drain_and_join(&self, drain_timeout: Duration) -> BridgeDrainReport;
}

/// Observed completion of the owned blocking workers and their admitted work.
#[must_use]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct BridgeDrainReport {
    pub pending_commands: usize,
    pub pending_workers: usize,
    pub worker_panics: usize,
    pub ownership_failed: bool,
}

impl BridgeDrainReport {
    pub const fn is_complete(self) -> bool {
        self.pending_commands == 0 && self.pending_workers == 0 && !self.ownership_failed
    }

    pub const fn is_successful(self) -> bool {
        self.is_complete() && self.worker_panics == 0
    }
}

/// Production executor backed by dedicated blocking bridge worker threads.
#[must_use]
pub struct ControlBridge {
    queue: std::sync::Mutex<Option<mpsc::Sender<Job>>>,
    joins: std::sync::Mutex<Vec<std::thread::JoinHandle<()>>>,
    shared: Arc<Shared>,
    max_inflight: usize,
    execution: ForgeExecutionCoordinatorClient,
}

#[derive(Debug)]
struct Job {
    command: Command,
    reply: oneshot::Sender<BridgeOutcome>,
    _reservation: AdmissionReservation,
}

#[derive(Debug)]
struct AdmissionReservation(Arc<Shared>);

impl AdmissionReservation {
    fn acquire(shared: &Arc<Shared>, limit: usize) -> Result<Self, ForgeError> {
        shared
            .inflight
            .fetch_update(
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
                |count| count.checked_add(1).filter(|next| *next <= limit),
            )
            .map_err(|_| ForgeError::capacity_exceeded("command bridge inflight limit"))?;
        Ok(Self(Arc::clone(shared)))
    }
}

impl Drop for AdmissionReservation {
    fn drop(&mut self) {
        self.0
            .inflight
            .fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

#[derive(Debug)]
struct Shared {
    inflight: std::sync::atomic::AtomicUsize,
    worker_panics: std::sync::atomic::AtomicUsize,
}

impl Default for Shared {
    fn default() -> Self {
        Self {
            inflight: std::sync::atomic::AtomicUsize::new(0),
            worker_panics: std::sync::atomic::AtomicUsize::new(0),
        }
    }
}

impl std::fmt::Debug for ControlBridge {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ControlBridge")
            .field("inflight", &self.inflight())
            .finish_non_exhaustive()
    }
}

impl ControlBridge {
    /// Start `workers` dedicated threads over one bounded queue.
    ///
    /// # Errors
    /// Fails when a bridge worker thread cannot be spawned.
    pub fn start(
        client: &ForgeControlClient,
        execution: &ForgeExecutionCoordinatorClient,
        approval: &ForgeApprovalCoordinatorClient,
        runtime_instance_id: forge_domain::RuntimeInstanceId,
        config: &crate::config::BackendConfig,
        product_cache_root: &std::path::Path,
        destination_id: uuid::Uuid,
    ) -> Result<Self, std::io::Error> {
        if destination_id.is_nil() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "destination id must be non-nil",
            ));
        }
        if !product_cache_root.is_absolute() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "product cache root must be absolute",
            ));
        }
        let backend_id = config.backend_id();
        let issuer = config.issuer();
        let queue_capacity = config.max_inflight_commands();
        let workers = config.bridge_workers();
        if queue_capacity == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "command queue capacity must be positive",
            ));
        }
        let (queue, queue_receiver) = mpsc::channel::<Job>(queue_capacity);
        let receiver = Arc::new(std::sync::Mutex::new(queue_receiver));
        let shared = Arc::new(Shared::default());
        let mut worker_joins: Vec<std::thread::JoinHandle<()>> = Vec::new();
        let deps = crate::ops::BridgeClients {
            control: client.clone(),
            execution: execution.clone(),
            approval: approval.clone(),
            runtime_instance_id,
            backend_id,
            issuer,
            product_cache_root: product_cache_root.to_path_buf(),
            destination_id,
        };
        for index in 0..workers.max(1) {
            let deps = deps.clone();
            let receiver = Arc::clone(&receiver);
            let join = match std::thread::Builder::new()
                .name(format!("forge-backend-bridge-{index}"))
                .spawn(move || {
                    run_worker(&deps, &receiver);
                }) {
                Ok(join) => join,
                Err(error) => {
                    drop(queue);
                    for join in worker_joins {
                        let _ = join.join();
                    }
                    return Err(error);
                }
            };
            worker_joins.push(join);
        }
        Ok(Self {
            queue: std::sync::Mutex::new(Some(queue)),
            joins: std::sync::Mutex::new(worker_joins),
            shared,
            max_inflight: queue_capacity,
            execution: execution.clone(),
        })
    }
}

fn run_worker(deps: &crate::ops::BridgeClients, receiver: &std::sync::Mutex<mpsc::Receiver<Job>>) {
    loop {
        let job = {
            let Ok(mut queue) = receiver.lock() else {
                return;
            };
            queue.blocking_recv()
        };
        let Some(job) = job else {
            return;
        };
        let outcome = execute_admitted(deps, &job.command);
        let _ = job.reply.send(outcome);
    }
}

impl Drop for ControlBridge {
    fn drop(&mut self) {
        let queue = match self.queue.get_mut() {
            Ok(queue) => queue,
            Err(poisoned) => poisoned.into_inner(),
        };
        drop(queue.take());
        let joins = match self.joins.get_mut() {
            Ok(joins) => joins,
            Err(poisoned) => poisoned.into_inner(),
        };
        for join in joins.drain(..) {
            let _joined = join.join();
        }
    }
}

/// Execute one admitted command synchronously on the control client.
fn execute_admitted(deps: &crate::ops::BridgeClients, command: &Command) -> BridgeOutcome {
    BridgeOutcome::Completed(crate::ops::execute_on_bridge(deps, command))
}

impl CommandExecutor for ControlBridge {
    fn begin_wait(
        &self,
        request: forge_control::ExecutionWaitParameters,
    ) -> Result<forge_control::ExecutionWaitHandle, ForgeError> {
        let queue = self.queue.lock().map_err(|_| ForgeError::internal())?;
        if queue.is_none() {
            return Err(ForgeError::capacity_exceeded(
                "command bridge shutting down",
            ));
        }
        self.execution
            .begin_execution_wait_authorized(request)
            .map_err(|error| ForgeError::from_control_view(&error.view()))
    }

    fn submit(&self, command: Command) -> Result<oneshot::Receiver<BridgeOutcome>, ForgeError> {
        submit_command(&self.queue, &self.shared, self.max_inflight, command)
    }

    fn stop_admission(&self) {
        if let Ok(mut queue) = self.queue.lock() {
            // Closing the sole sender wakes blocking receivers. They drain
            // already admitted jobs before exiting, without idle polling.
            let _closed = queue.take();
        }
    }

    fn inflight(&self) -> usize {
        self.shared
            .inflight
            .load(std::sync::atomic::Ordering::Acquire)
    }

    fn drain_and_join(&self, drain_timeout: Duration) -> BridgeDrainReport {
        self.stop_admission();
        let started = std::time::Instant::now();
        while self.inflight() > 0 && started.elapsed() < drain_timeout {
            std::thread::sleep(Duration::from_millis(2));
        }
        // Admission closure wakes idle workers; join every worker that has exited by
        // the bounded deadline. A noncancellable control call may remain
        // active; the returned count exposes that unresolved lifetime.
        while started.elapsed() < drain_timeout {
            let finished = self.joins.lock().map_or(true, |joins| {
                joins.iter().all(std::thread::JoinHandle::is_finished)
            });
            if finished {
                break;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        let mut report = BridgeDrainReport::default();
        if let Ok(mut joins) = self.joins.lock() {
            let pending = std::mem::take(&mut *joins);
            let mut unfinished = Vec::new();
            for join in pending {
                if join.is_finished() {
                    if join.join().is_err() {
                        self.shared
                            .worker_panics
                            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                    }
                } else {
                    unfinished.push(join);
                }
            }
            *joins = unfinished;
            report.pending_workers = joins.len();
        } else {
            report.ownership_failed = true;
        }
        report.pending_commands = self.inflight();
        report.worker_panics = self
            .shared
            .worker_panics
            .load(std::sync::atomic::Ordering::Acquire);
        report
    }
}

fn submit_command(
    queue: &std::sync::Mutex<Option<mpsc::Sender<Job>>>,
    shared: &Arc<Shared>,
    max_inflight: usize,
    command: Command,
) -> Result<oneshot::Receiver<BridgeOutcome>, ForgeError> {
    if command.uses_activity_lease_lane() {
        return Err(ForgeError::invalid_input(
            "Activity lifecycle commands require the dedicated lane",
        ));
    }
    if matches!(command, Command::ExecutionWait { .. }) {
        return Err(ForgeError::invalid_input(
            "execution.wait requires async admission",
        ));
    }
    let Ok(queue) = queue.lock() else {
        return Err(ForgeError::capacity_exceeded("command bridge admission"));
    };
    let Some(queue) = queue.as_ref() else {
        return Err(ForgeError::capacity_exceeded(
            "command bridge shutting down",
        ));
    };
    let (reply, receiver) = oneshot::channel();
    // try_send proves bounded admission: a saturated bridge rejects
    // immediately with a typed CapacityExceeded, never by waiting.
    queue
        .try_send(Job {
            command,
            reply,
            _reservation: AdmissionReservation::acquire(shared, max_inflight)?,
        })
        .map_err(|_| ForgeError::capacity_exceeded("command bridge queue"))?;
    Ok(receiver)
}

#[cfg(test)]
mod tests {
    use super::{Command, Shared, submit_command};
    use std::sync::{Arc, Mutex};
    use tokio::sync::mpsc;
    use uuid::Uuid;

    #[test]
    fn general_bridge_rejects_lease_before_queue_or_inflight_reservation()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sender, mut receiver) = mpsc::channel(1);
        let queue = Mutex::new(Some(sender));
        let shared = Arc::new(Shared::default());
        let command = crate::parse_command(
            crate::CommandOp::ActivityLeaseRenew,
            Uuid::from_u128(1),
            &serde_json::json!({
                "scope": {"workspace_id": Uuid::from_u128(2), "workspace_revision":1,
                    "locator":{"location_id":Uuid::from_u128(3),"expected_revision":1,"relative_root":"."}},
                "activity_id":Uuid::from_u128(4),"runtime_instance_id":Uuid::from_u128(5),
                "expected_lease_revision":1,"duration_ms":1000,
            }),
        )?;
        assert!(matches!(submit_command(&queue, &shared, 1, command),
            Err(error) if error.code() == crate::ErrorCode::InvalidInput));
        assert_eq!(
            shared.inflight.load(std::sync::atomic::Ordering::Acquire),
            0
        );
        assert!(matches!(
            receiver.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
        Ok(())
    }

    #[test]
    fn admission_count_survives_saturation_and_tracks_execution()
    -> Result<(), Box<dyn std::error::Error>> {
        let (queue, mut receiver) = mpsc::channel(1);
        let queue = Mutex::new(Some(queue));
        let shared = Arc::new(Shared::default());
        let submit = |command| submit_command(&queue, &shared, 1, command);
        let inflight = || shared.inflight.load(std::sync::atomic::Ordering::Acquire);
        let command = Command::WorkspaceResolve {
            request_id: Uuid::from_u128(1),
            location_id: Uuid::from_u128(2),
            expected_revision: 1,
            relative_root: ".".to_owned(),
        };
        let first = submit(command.clone());
        assert!(first.is_ok());
        assert_eq!(inflight(), 1, "queued work is admitted work");
        assert!(submit(command.clone()).is_err());
        assert_eq!(inflight(), 1, "rejection must release its reservation");
        let executing = receiver.try_recv();
        assert!(executing.is_ok());
        assert_eq!(inflight(), 1, "dequeue does not complete execution");
        assert!(
            submit(command.clone()).is_err(),
            "executing work consumes capacity"
        );
        drop(executing);
        assert_eq!(inflight(), 0, "completion releases exactly one reservation");
        drop(receiver);
        assert!(submit(command.clone()).is_err());
        assert_eq!(inflight(), 0, "closed queue rolls back the reservation");
        let _closed = queue.lock().map_err(|_| "test queue lock poisoned")?.take();
        assert!(submit(command).is_err());
        assert_eq!(inflight(), 0);
        Ok(())
    }
}
