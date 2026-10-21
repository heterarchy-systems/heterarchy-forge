//! Dedicated bounded Activity lease transport ownership.
//!
//! Activity lease commands use a narrow native control client and one owned
//! blocking worker.  The general bridge never receives these commands: routing
//! is decided before either bridge attempts admission.  Durable Activity and
//! lease semantics remain in forge-control and forge-persistence.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use forge_control::ActivityLeaseClient;
use tokio::sync::oneshot;

use crate::bridge::{BridgeDrainReport, BridgeOutcome, CommandExecutor};
use crate::error::ForgeError;
use crate::ops::Command;

const ACTIVITY_LEASE_BRIDGE_CAPACITY: usize = 4;
const ACTIVITY_LEASE_WORKER_NAME: &str = "forge-backend-activity-lease";

#[derive(Debug)]
struct LeaseJob {
    command: Command,
    reply: oneshot::Sender<BridgeOutcome>,
    _reservation: AdmissionReservation,
}

#[derive(Debug)]
struct Shared {
    inflight: AtomicUsize,
    worker_panics: AtomicUsize,
    worker_done: AtomicBool,
    ownership_failed: AtomicBool,
    changed: Condvar,
    changed_lock: Mutex<()>,
}

impl Shared {
    fn new() -> Self {
        Self {
            inflight: AtomicUsize::new(0),
            worker_panics: AtomicUsize::new(0),
            worker_done: AtomicBool::new(false),
            ownership_failed: AtomicBool::new(false),
            changed: Condvar::new(),
            changed_lock: Mutex::new(()),
        }
    }

    fn notify_changed(&self) {
        let _guard = self.changed_lock.lock().ok();
        self.changed.notify_all();
    }

    fn mark_ownership_failed(&self) {
        self.ownership_failed.store(true, Ordering::Release);
        self.changed.notify_all();
    }
}

#[derive(Debug)]
struct AdmissionReservation(Arc<Shared>);

impl AdmissionReservation {
    fn acquire(shared: &Arc<Shared>, limit: usize) -> Result<Self, ForgeError> {
        let result = shared
            .inflight
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                count.checked_add(1).filter(|next| *next <= limit)
            });
        result
            .map(|_| Self(Arc::clone(shared)))
            .map_err(|_| ForgeError::capacity_exceeded("Activity lease bridge inflight limit"))
    }
}

impl Drop for AdmissionReservation {
    fn drop(&mut self) {
        self.0.inflight.fetch_sub(1, Ordering::AcqRel);
        self.0.notify_changed();
    }
}

struct WorkerExit(Arc<Shared>);

impl Drop for WorkerExit {
    fn drop(&mut self) {
        self.0.worker_done.store(true, Ordering::Release);
        self.0.notify_changed();
    }
}

/// One bounded blocking bridge dedicated to the native Activity lease lane.
#[must_use]
pub struct ActivityLeaseBridge {
    queue: Mutex<Option<SyncSender<LeaseJob>>>,
    worker: Mutex<Option<JoinHandle<()>>>,
    shared: Arc<Shared>,
}

impl std::fmt::Debug for ActivityLeaseBridge {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ActivityLeaseBridge")
            .field("inflight", &self.inflight())
            .field(
                "worker_done",
                &self.shared.worker_done.load(Ordering::Acquire),
            )
            .finish_non_exhaustive()
    }
}

impl ActivityLeaseBridge {
    /// Start one owned worker over the narrow native Activity lease client.
    pub fn start(client: &ActivityLeaseClient) -> Result<Self, std::io::Error> {
        let (queue, receiver) = sync_channel(ACTIVITY_LEASE_BRIDGE_CAPACITY);
        let shared = Arc::new(Shared::new());
        let worker_shared = Arc::clone(&shared);
        let worker_client = client.clone();
        let worker = thread::Builder::new()
            .name(ACTIVITY_LEASE_WORKER_NAME.to_owned())
            .spawn(move || run_worker(&worker_client, &receiver, &worker_shared))?;
        Ok(Self {
            queue: Mutex::new(Some(queue)),
            worker: Mutex::new(Some(worker)),
            shared,
        })
    }

    fn wait_for_worker(&self, deadline: Instant) -> bool {
        let Ok(mut guard) = self.shared.changed_lock.lock() else {
            self.shared.mark_ownership_failed();
            return false;
        };
        while !self.shared.worker_done.load(Ordering::Acquire) {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return false;
            };
            if remaining.is_zero() {
                return false;
            }
            let waited = self.shared.changed.wait_timeout(guard, remaining);
            let Ok((next_guard, timeout)) = waited else {
                self.shared.mark_ownership_failed();
                return false;
            };
            guard = next_guard;
            if timeout.timed_out() {
                return self.shared.worker_done.load(Ordering::Acquire);
            }
        }
        true
    }

    fn join_finished_worker(&self, report: &mut BridgeDrainReport) {
        let Ok(mut worker) = self.worker.lock() else {
            self.shared.mark_ownership_failed();
            report.pending_workers = usize::MAX;
            return;
        };
        let finished = worker
            .as_ref()
            .is_some_and(std::thread::JoinHandle::is_finished);
        if finished
            && let Some(worker) = worker.take()
            && worker.join().is_err()
        {
            self.shared.worker_panics.fetch_add(1, Ordering::AcqRel);
        }
        if worker.is_some() {
            report.pending_workers = 1;
        }
    }

    // The run-loop exit notification precedes the thread's final return.
    // Keep the original drain deadline while waiting for the actual handle.
    fn wait_for_thread<F>(&self, deadline: Instant, mut on_pending: F)
    where
        F: FnMut(),
    {
        loop {
            let finished = if let Ok(worker) = self.worker.lock() {
                worker.as_ref().is_none_or(JoinHandle::is_finished)
            } else {
                self.shared.mark_ownership_failed();
                return;
            };
            if finished || Instant::now() >= deadline {
                return;
            }
            on_pending();
            thread::yield_now();
        }
    }
}

impl CommandExecutor for ActivityLeaseBridge {
    fn submit(&self, command: Command) -> Result<oneshot::Receiver<BridgeOutcome>, ForgeError> {
        if !command.uses_activity_lease_lane() {
            return Err(ForgeError::invalid_input(
                "command is not admitted to the Activity lease lane",
            ));
        }
        let reservation =
            AdmissionReservation::acquire(&self.shared, ACTIVITY_LEASE_BRIDGE_CAPACITY)?;
        let (reply, receiver) = oneshot::channel();
        let Ok(queue) = self.queue.lock() else {
            self.shared.mark_ownership_failed();
            return Err(ForgeError::internal());
        };
        let Some(queue) = queue.as_ref() else {
            return Err(ForgeError::capacity_exceeded(
                "Activity lease bridge shutting down",
            ));
        };
        let job = LeaseJob {
            command,
            reply,
            _reservation: reservation,
        };
        match queue.try_send(job) {
            Ok(()) => Ok(receiver),
            Err(TrySendError::Full(_)) => {
                Err(ForgeError::capacity_exceeded("Activity lease bridge queue"))
            }
            Err(TrySendError::Disconnected(_)) => Err(ForgeError::capacity_exceeded(
                "Activity lease bridge shutting down",
            )),
        }
    }

    fn stop_admission(&self) {
        match self.queue.lock() {
            Ok(mut queue) => {
                let _closed = queue.take();
            }
            Err(_) => self.shared.mark_ownership_failed(),
        }
    }

    fn inflight(&self) -> usize {
        self.shared.inflight.load(Ordering::Acquire)
    }

    fn drain_and_join(&self, drain_timeout: Duration) -> BridgeDrainReport {
        self.stop_admission();
        let deadline = match Instant::now().checked_add(drain_timeout) {
            Some(deadline) => deadline,
            None => Instant::now(),
        };
        if self.wait_for_worker(deadline) {
            self.wait_for_thread(deadline, || {});
        }
        let mut report = BridgeDrainReport {
            ownership_failed: self.shared.ownership_failed.load(Ordering::Acquire),
            ..BridgeDrainReport::default()
        };
        self.join_finished_worker(&mut report);
        report.pending_commands = self.inflight();
        report.worker_panics = self.shared.worker_panics.load(Ordering::Acquire);
        if !self.shared.worker_done.load(Ordering::Acquire) {
            report.pending_workers = report.pending_workers.max(1);
        }
        report
    }
}

impl Drop for ActivityLeaseBridge {
    fn drop(&mut self) {
        let queue = match self.queue.get_mut() {
            Ok(queue) => queue,
            Err(poisoned) => poisoned.into_inner(),
        };
        drop(queue.take());
        let worker = match self.worker.get_mut() {
            Ok(worker) => worker,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(worker) = worker.take() {
            let _joined = worker.join();
        }
    }
}

fn run_worker(client: &ActivityLeaseClient, receiver: &Receiver<LeaseJob>, shared: &Arc<Shared>) {
    let _exit = WorkerExit(Arc::clone(shared));
    while let Ok(job) = receiver.recv() {
        let outcome = crate::ops::execute_on_activity_lease(client, &job.command);
        let _ = job.reply.send(BridgeOutcome::Completed(outcome));
    }
}

/// Routes Activity lease commands to the dedicated bridge before the general
/// bridge can attempt admission. Both bridge owners remain retained here so a
/// bounded drain can report unfinished work without dropping a join handle.
#[must_use]
#[derive(Debug)]
pub struct RoutingExecutor {
    general: Arc<dyn CommandExecutor>,
    lease: Arc<dyn CommandExecutor>,
}

impl RoutingExecutor {
    pub fn new(general: Arc<dyn CommandExecutor>, lease: Arc<dyn CommandExecutor>) -> Self {
        Self { general, lease }
    }

    fn executor_for(&self, command: &Command) -> &Arc<dyn CommandExecutor> {
        if command.uses_activity_lease_lane() {
            &self.lease
        } else {
            &self.general
        }
    }
}

impl CommandExecutor for RoutingExecutor {
    fn submit(&self, command: Command) -> Result<oneshot::Receiver<BridgeOutcome>, ForgeError> {
        self.executor_for(&command).submit(command)
    }

    fn begin_wait(
        &self,
        request: forge_control::ExecutionWaitParameters,
    ) -> Result<forge_control::ExecutionWaitHandle, ForgeError> {
        self.general.begin_wait(request)
    }

    fn stop_admission(&self) {
        self.general.stop_admission();
        self.lease.stop_admission();
    }

    fn inflight(&self) -> usize {
        self.general
            .inflight()
            .saturating_add(self.lease.inflight())
    }

    fn drain_and_join(&self, drain_timeout: Duration) -> BridgeDrainReport {
        self.stop_admission();
        let started = Instant::now();
        let lease = self.lease.drain_and_join(drain_timeout);
        let remaining = drain_timeout.saturating_sub(started.elapsed());
        let general = self.general.drain_and_join(remaining);
        combine_reports(general, lease)
    }
}

fn combine_reports(general: BridgeDrainReport, lease: BridgeDrainReport) -> BridgeDrainReport {
    let mut ownership_failed = general.ownership_failed || lease.ownership_failed;
    let pending_commands = checked_report_count(
        general.pending_commands,
        lease.pending_commands,
        &mut ownership_failed,
    );
    let pending_workers = checked_report_count(
        general.pending_workers,
        lease.pending_workers,
        &mut ownership_failed,
    );
    let worker_panics = checked_report_count(
        general.worker_panics,
        lease.worker_panics,
        &mut ownership_failed,
    );
    BridgeDrainReport {
        pending_commands,
        pending_workers,
        worker_panics,
        ownership_failed,
    }
}

fn checked_report_count(left: usize, right: usize, ownership_failed: &mut bool) -> usize {
    if let Some(total) = left.checked_add(right) {
        total
    } else {
        *ownership_failed = true;
        usize::MAX
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::CommandOp;
    use serde_json::json;
    use std::sync::atomic::AtomicUsize;
    use uuid::Uuid;

    #[test]
    fn drop_closes_sender_before_joining_idle_worker() {
        let (sender, receiver) = sync_channel::<LeaseJob>(4);
        let disconnected = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&disconnected);
        let worker = thread::spawn(move || {
            observed.store(
                matches!(
                    receiver.recv_timeout(Duration::from_secs(1)),
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected)
                ),
                Ordering::Release,
            );
        });
        let bridge = ActivityLeaseBridge {
            queue: Mutex::new(Some(sender)),
            worker: Mutex::new(Some(worker)),
            shared: Arc::new(Shared::new()),
        };
        drop(bridge);
        assert!(
            disconnected.load(Ordering::Acquire),
            "sender must close before join, not after receiver timeout"
        );
    }

    #[derive(Debug)]
    struct FakeExecutor {
        submissions: AtomicUsize,
        stops: AtomicUsize,
        drains: AtomicUsize,
        inflight: AtomicUsize,
        report: BridgeDrainReport,
        budgets: Mutex<Vec<Duration>>,
    }

    impl FakeExecutor {
        fn new(report: BridgeDrainReport) -> Self {
            Self {
                submissions: AtomicUsize::new(0),
                stops: AtomicUsize::new(0),
                drains: AtomicUsize::new(0),
                inflight: AtomicUsize::new(0),
                report,
                budgets: Mutex::new(Vec::new()),
            }
        }

        fn submitted(&self) -> usize {
            self.submissions.load(Ordering::Acquire)
        }
    }

    impl CommandExecutor for FakeExecutor {
        fn submit(
            &self,
            _command: Command,
        ) -> Result<oneshot::Receiver<BridgeOutcome>, ForgeError> {
            self.submissions.fetch_add(1, Ordering::AcqRel);
            let (sender, receiver) = oneshot::channel();
            let _ = sender.send(BridgeOutcome::Completed(Ok(json!({"ok": true}))));
            Ok(receiver)
        }

        fn stop_admission(&self) {
            self.stops.fetch_add(1, Ordering::AcqRel);
        }

        fn inflight(&self) -> usize {
            self.inflight.load(Ordering::Acquire)
        }

        fn drain_and_join(&self, budget: Duration) -> BridgeDrainReport {
            self.drains.fetch_add(1, Ordering::AcqRel);
            if let Ok(mut budgets) = self.budgets.lock() {
                budgets.push(budget);
            }
            self.report
        }
    }

    fn general_command() -> Command {
        Command::WorkspaceResolve {
            request_id: Uuid::from_u128(1),
            location_id: Uuid::from_u128(2),
            expected_revision: 1,
            relative_root: ".".to_owned(),
        }
    }

    fn lease_command() -> Result<Command, ForgeError> {
        crate::ops::parse_command(
            CommandOp::ActivityLeaseRenew,
            Uuid::from_u128(3),
            &json!({
                "scope": {
                    "workspace_id": Uuid::from_u128(4),
                    "workspace_revision": 1,
                    "locator": {
                        "location_id": Uuid::from_u128(5),
                        "expected_revision": 1,
                        "relative_root": "."
                    }
                },
                "activity_id": Uuid::from_u128(6),
                "runtime_instance_id": Uuid::from_u128(7),
                "expected_lease_revision": 1,
                "duration_ms": 1_000
            }),
        )
    }

    #[test]
    fn exit_notification_retains_then_joins_thread_with_original_budget()
    -> Result<(), Box<dyn std::error::Error>> {
        let shared = Arc::new(Shared::new());
        let worker_shared = Arc::clone(&shared);
        let (sender, _receiver) = sync_channel(4);
        let (exited_sender, exited_receiver) = sync_channel(1);
        let (release_sender, release_receiver) = sync_channel(1);
        let worker = thread::spawn(move || {
            drop(WorkerExit(worker_shared));
            let notified = exited_sender.send(());
            let released = release_receiver.recv_timeout(Duration::from_secs(5));
            assert!(notified.is_ok());
            assert!(released.is_ok());
        });
        let bridge = ActivityLeaseBridge {
            queue: Mutex::new(Some(sender)),
            worker: Mutex::new(Some(worker)),
            shared,
        };
        exited_receiver.recv_timeout(Duration::from_secs(5))?;
        let pending = bridge.drain_and_join(Duration::ZERO);
        assert_eq!(pending.pending_commands, 0);
        assert_eq!(pending.pending_workers, 1);
        assert!(!pending.is_complete());

        let mut release_sender = Some(release_sender);
        bridge.wait_for_thread(Instant::now() + Duration::from_secs(1), || {
            if let Some(sender) = release_sender.take() {
                assert!(sender.send(()).is_ok());
            }
        });
        assert!(
            release_sender.is_none(),
            "the retained thread was not observed pending"
        );
        let joined = bridge.drain_and_join(Duration::from_secs(1));
        assert!(joined.is_successful(), "retained exit handle: {joined:?}");
        assert!(
            bridge
                .worker
                .lock()
                .map_err(|_| "worker lock poisoned")?
                .is_none()
        );
        Ok(())
    }

    #[test]
    fn admission_reservation_is_bounded_and_released() -> Result<(), Box<dyn std::error::Error>> {
        let shared = Arc::new(Shared::new());
        let mut reservations = Vec::new();
        for _ in 0..ACTIVITY_LEASE_BRIDGE_CAPACITY {
            reservations.push(AdmissionReservation::acquire(
                &shared,
                ACTIVITY_LEASE_BRIDGE_CAPACITY,
            )?);
        }
        assert!(AdmissionReservation::acquire(&shared, ACTIVITY_LEASE_BRIDGE_CAPACITY).is_err());
        assert_eq!(shared.inflight.load(Ordering::Acquire), 4);
        drop(reservations.pop());
        assert_eq!(shared.inflight.load(Ordering::Acquire), 3);
        let _last = AdmissionReservation::acquire(&shared, ACTIVITY_LEASE_BRIDGE_CAPACITY)?;
        Ok(())
    }

    #[test]
    fn routing_selects_dedicated_lane_before_general() -> Result<(), Box<dyn std::error::Error>> {
        let general = Arc::new(FakeExecutor::new(BridgeDrainReport::default()));
        let lease = Arc::new(FakeExecutor::new(BridgeDrainReport::default()));
        let routing = RoutingExecutor::new(
            Arc::clone(&general) as Arc<dyn CommandExecutor>,
            Arc::clone(&lease) as Arc<dyn CommandExecutor>,
        );
        drop(routing.submit(general_command())?);
        drop(routing.submit(lease_command()?)?);
        assert_eq!(general.submitted(), 1);
        assert_eq!(lease.submitted(), 1);
        Ok(())
    }

    #[test]
    fn non_lease_activity_bridge_submission_is_rejected_before_admission() {
        let shared = Arc::new(Shared::new());
        let (sender, receiver) = sync_channel(4);
        let bridge = ActivityLeaseBridge {
            queue: Mutex::new(Some(sender)),
            worker: Mutex::new(None),
            shared: Arc::clone(&shared),
        };
        let result = bridge.submit(general_command());
        assert!(matches!(result, Err(error) if error.code() == crate::ErrorCode::InvalidInput));
        assert!(matches!(
            receiver.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
        assert_eq!(shared.inflight.load(Ordering::Acquire), 0);
    }

    #[test]
    fn routing_closes_both_admission_boundaries_and_uses_remaining_budget()
    -> Result<(), Box<dyn std::error::Error>> {
        let general = Arc::new(FakeExecutor::new(BridgeDrainReport::default()));
        let lease = Arc::new(FakeExecutor::new(BridgeDrainReport::default()));
        let routing = RoutingExecutor::new(
            Arc::clone(&general) as Arc<dyn CommandExecutor>,
            Arc::clone(&lease) as Arc<dyn CommandExecutor>,
        );
        let report = routing.drain_and_join(Duration::from_millis(20));
        assert!(report.is_complete());
        assert_eq!(general.stops.load(Ordering::Acquire), 1);
        assert_eq!(lease.stops.load(Ordering::Acquire), 1);
        assert_eq!(general.drains.load(Ordering::Acquire), 1);
        assert_eq!(lease.drains.load(Ordering::Acquire), 1);
        let general_budget = general
            .budgets
            .lock()
            .map_err(|_| "general budget lock poisoned")?
            .first()
            .copied()
            .ok_or("general drain budget missing")?;
        let lease_budget = lease
            .budgets
            .lock()
            .map_err(|_| "lease budget lock poisoned")?
            .first()
            .copied()
            .ok_or("lease drain budget missing")?;
        assert_eq!(lease_budget, Duration::from_millis(20));
        assert!(general_budget <= lease_budget);
        Ok(())
    }

    #[test]
    fn report_overflow_is_ownership_failure_and_never_zeroed() {
        let report = combine_reports(
            BridgeDrainReport {
                pending_commands: usize::MAX,
                ..BridgeDrainReport::default()
            },
            BridgeDrainReport {
                pending_commands: 1,
                ..BridgeDrainReport::default()
            },
        );
        assert!(report.ownership_failed);
        assert_eq!(report.pending_commands, usize::MAX);
    }
}
