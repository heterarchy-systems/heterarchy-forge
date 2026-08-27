use std::io;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TryRecvError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use forge_domain::{
    RuntimeCommand, RuntimeEvent, RuntimeGeneration, RuntimeLifecycle, RuntimePhase,
    RuntimeProjection, RuntimeTransitionError,
};
use thiserror::Error;
use tokio::runtime::Builder as TokioRuntimeBuilder;
use tokio::sync::{mpsc as tokio_mpsc, watch};
use tokio::time::{Instant, MissedTickBehavior};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

const COMMAND_CAPACITY: usize = 32;
const INITIALIZATION_TIMEOUT: Duration = Duration::from_secs(5);
const TRANSITION_DELAY: Duration = Duration::from_millis(40);
const UPTIME_INTERVAL: Duration = Duration::from_secs(1);

pub trait RuntimeStopParticipant: Send + Sync + 'static {
    fn stop_and_drain(&self) -> Result<(), RuntimeStopParticipantError>;
}

#[derive(Debug, Default)]
struct NoopStopParticipant;

impl RuntimeStopParticipant for NoopStopParticipant {
    fn stop_and_drain(&self) -> Result<(), RuntimeStopParticipantError> {
        Ok(())
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeStopParticipantError {
    #[error("runtime stop participant failed to drain")]
    DrainFailed,
}

/// Cloneable command capability for the owned Forge runtime.
#[derive(Debug, Clone)]
pub struct RuntimeClient {
    command_tx: tokio_mpsc::Sender<RuntimeCommand>,
}

impl RuntimeClient {
    pub fn send(&self, command: RuntimeCommand) -> Result<(), RuntimeClientError> {
        self.command_tx
            .try_send(command)
            .map_err(|error| match error {
                tokio_mpsc::error::TrySendError::Full(_) => RuntimeClientError::QueueFull,
                tokio_mpsc::error::TrySendError::Closed(_) => RuntimeClientError::RuntimeClosed,
            })
    }
}

/// Single-consumer stream of semantic runtime projections.
#[derive(Debug)]
pub struct RuntimeEventStream {
    latest: watch::Receiver<RuntimeProjection>,
    notifications: Receiver<()>,
    last_delivered: Option<RuntimeProjection>,
}

impl RuntimeEventStream {
    fn new(
        latest: watch::Receiver<RuntimeProjection>,
        notifications: Receiver<()>,
        last_delivered: RuntimeProjection,
    ) -> Self {
        // RuntimeService may construct this receiver after the actor has
        // already published its first snapshots. Keep the actor's initial
        // state as the baseline so those snapshots remain observable.
        Self {
            latest,
            notifications,
            last_delivered: Some(last_delivered),
        }
    }

    pub fn recv(&mut self) -> Result<RuntimeProjection, RuntimeServiceError> {
        loop {
            if let Some(projection) = self.take_latest()? {
                return Ok(projection);
            }

            if self.notifications.recv().is_err() {
                return self
                    .take_latest()?
                    .ok_or(RuntimeServiceError::EventStreamClosed);
            }
        }
    }

    /// Returns the most recent unseen projection without waiting for a runtime event.
    pub fn take_latest(&mut self) -> Result<Option<RuntimeProjection>, RuntimeServiceError> {
        let mut notified = false;
        let mut notification_closed = false;
        loop {
            match self.notifications.try_recv() {
                Ok(()) => notified = true,
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    notification_closed = true;
                    break;
                }
            }
        }

        let watch_changed = self.latest.has_changed();
        if !notified
            && !notification_closed
            && let Ok(false) = watch_changed
        {
            return Ok(None);
        }

        let current = self.latest.borrow_and_update().clone();
        if self
            .last_delivered
            .as_ref()
            .is_some_and(|last| last == &current)
        {
            if watch_changed.is_err() || notification_closed {
                return Err(RuntimeServiceError::EventStreamClosed);
            }
            return Ok(None);
        }

        self.last_delivered = Some(current.clone());
        Ok(Some(current))
    }

    pub fn recv_timeout(
        &mut self,
        timeout: Duration,
    ) -> Result<RuntimeProjection, RuntimeServiceError> {
        let now = std::time::Instant::now();
        let deadline = now.checked_add(timeout).unwrap_or(now);
        loop {
            if let Some(projection) = self.take_latest()? {
                return Ok(projection);
            }

            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Err(RuntimeServiceError::EventTimeout);
            }

            match self.notifications.recv_timeout(remaining) {
                Ok(()) => {}
                Err(RecvTimeoutError::Timeout) => {
                    return self.take_latest()?.ok_or(RuntimeServiceError::EventTimeout);
                }
                Err(RecvTimeoutError::Disconnected) => {
                    return self
                        .take_latest()?
                        .ok_or(RuntimeServiceError::EventStreamClosed);
                }
            }
        }
    }
}

#[derive(Debug)]
struct ProjectionPublisher {
    latest: watch::Sender<RuntimeProjection>,
    notifications: SyncSender<()>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeInitialization {
    Ready,
    BuildFailed,
}

/// Owns the background thread, Tokio runtime, cancellation capability, and join path.
#[derive(Debug)]
pub struct RuntimeService {
    client: RuntimeClient,
    events: Option<RuntimeEventStream>,
    cancellation: CancellationToken,
    thread: Option<JoinHandle<Result<(), RuntimeServiceError>>>,
}

impl RuntimeService {
    pub fn start() -> Result<Self, RuntimeServiceError> {
        Self::start_with_stop_participant(Arc::new(NoopStopParticipant))
    }

    pub fn start_with_stop_participant(
        stop_participant: Arc<dyn RuntimeStopParticipant>,
    ) -> Result<Self, RuntimeServiceError> {
        let (command_tx, command_rx) = tokio_mpsc::channel(COMMAND_CAPACITY);
        let initial_projection = RuntimeProjection::Starting {
            generation: RuntimeGeneration::INITIAL,
        };
        let (event_tx, event_rx) = watch::channel(initial_projection.clone());
        let (notification_tx, notification_rx) = mpsc::sync_channel(1);
        let projections = ProjectionPublisher {
            latest: event_tx,
            notifications: notification_tx,
        };
        let (init_tx, init_rx) = mpsc::sync_channel(1);
        let cancellation = CancellationToken::new();
        let runtime_cancellation = cancellation.clone();

        let thread = thread::Builder::new()
            .name("heterarchy-forge-runtime".to_owned())
            .spawn(move || {
                let runtime = TokioRuntimeBuilder::new_multi_thread()
                    .worker_threads(2)
                    .thread_name("heterarchy-forge-worker")
                    .enable_all()
                    .build();

                let runtime = match runtime {
                    Ok(runtime) => {
                        if init_tx.send(RuntimeInitialization::Ready).is_err() {
                            return Err(RuntimeServiceError::InitializationChannelClosed);
                        }
                        runtime
                    }
                    Err(source) => {
                        let _ = init_tx.send(RuntimeInitialization::BuildFailed);
                        return Err(RuntimeServiceError::RuntimeBuild(source));
                    }
                };

                runtime.block_on(run_actor(
                    command_rx,
                    projections,
                    runtime_cancellation,
                    stop_participant,
                ))
            })
            .map_err(RuntimeServiceError::ThreadSpawn)?;

        match init_rx.recv_timeout(INITIALIZATION_TIMEOUT) {
            Ok(RuntimeInitialization::Ready) => Ok(Self {
                client: RuntimeClient { command_tx },
                events: Some(RuntimeEventStream::new(
                    event_rx,
                    notification_rx,
                    initial_projection,
                )),
                cancellation,
                thread: Some(thread),
            }),
            Ok(RuntimeInitialization::BuildFailed) => match thread.join() {
                Ok(Err(error)) => Err(error),
                Ok(Ok(())) => Err(RuntimeServiceError::InitializationFailureMissing),
                Err(_) => Err(RuntimeServiceError::ThreadPanicked),
            },
            Err(RecvTimeoutError::Timeout) => {
                cancellation.cancel();
                let _ = thread.join();
                Err(RuntimeServiceError::InitializationTimeout)
            }
            Err(RecvTimeoutError::Disconnected) => {
                cancellation.cancel();
                let _ = thread.join();
                Err(RuntimeServiceError::InitializationChannelClosed)
            }
        }
    }

    pub fn client(&self) -> RuntimeClient {
        self.client.clone()
    }

    pub fn take_event_stream(&mut self) -> Result<RuntimeEventStream, RuntimeServiceError> {
        self.events
            .take()
            .ok_or(RuntimeServiceError::EventStreamAlreadyTaken)
    }

    pub fn shutdown(&mut self) -> Result<(), RuntimeServiceError> {
        self.cancellation.cancel();
        let Some(thread) = self.thread.take() else {
            return Ok(());
        };

        match thread.join() {
            Ok(result) => result,
            Err(_) => Err(RuntimeServiceError::ThreadPanicked),
        }
    }
}

impl Drop for RuntimeService {
    fn drop(&mut self) {
        self.cancellation.cancel();
        if let Some(thread) = self.thread.take()
            && thread.join().is_err()
        {
            eprintln!("Heterarchy Forge runtime thread panicked during drop");
        }
    }
}

async fn run_actor(
    mut command_rx: tokio_mpsc::Receiver<RuntimeCommand>,
    projections: ProjectionPublisher,
    cancellation: CancellationToken,
    stop_participant: Arc<dyn RuntimeStopParticipant>,
) -> Result<(), RuntimeServiceError> {
    let mut lifecycle = RuntimeLifecycle::booting();
    publish(&projections, lifecycle.projection());
    lifecycle.apply(RuntimeEvent::BootCompleted)?;
    publish(&projections, lifecycle.projection());
    info!(
        generation = lifecycle.projection().generation().get(),
        "runtime started"
    );

    let first_tick = Instant::now() + UPTIME_INTERVAL;
    let mut ticker = tokio::time::interval_at(first_tick, UPTIME_INTERVAL);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            biased;
            () = cancellation.cancelled() => {
                transition_to_stopping(&mut lifecycle, &projections, stop_participant.as_ref())?;
                break;
            }
            command = command_rx.recv() => {
                match command {
                    Some(RuntimeCommand::Start) => start_runtime(&mut lifecycle, &projections).await?,
                    Some(RuntimeCommand::Stop) => stop_runtime(&mut lifecycle, &projections, stop_participant.as_ref(), false).await?,
                    Some(RuntimeCommand::EmergencyStop) => stop_runtime(&mut lifecycle, &projections, stop_participant.as_ref(), true).await?,
                    Some(RuntimeCommand::Restart) => restart_runtime(&mut lifecycle, &projections, stop_participant.as_ref()).await?,
                    Some(RuntimeCommand::Shutdown) | None => {
                        transition_to_stopping(&mut lifecycle, &projections, stop_participant.as_ref())?;
                        break;
                    }
                }
            }
            _ = ticker.tick(), if lifecycle.projection().phase() == RuntimePhase::Running => {
                lifecycle.apply(RuntimeEvent::Tick)?;
                publish(&projections, lifecycle.projection());
            }
        }
    }

    if lifecycle.projection().phase() == RuntimePhase::Stopping {
        lifecycle.apply(RuntimeEvent::StopCompleted)?;
        publish(&projections, lifecycle.projection());
    }
    info!(
        generation = lifecycle.projection().generation().get(),
        "runtime stopped"
    );
    Ok(())
}

async fn start_runtime(
    lifecycle: &mut RuntimeLifecycle,
    projections: &ProjectionPublisher,
) -> Result<(), RuntimeServiceError> {
    if let Err(error) = lifecycle.apply(RuntimeEvent::StartRequested) {
        log_rejected_command(RuntimeCommand::Start, error);
        return Ok(());
    }
    publish(projections, lifecycle.projection());
    tokio::time::sleep(TRANSITION_DELAY).await;
    lifecycle.apply(RuntimeEvent::StartCompleted)?;
    publish(projections, lifecycle.projection());
    info!(
        generation = lifecycle.projection().generation().get(),
        "runtime started"
    );
    Ok(())
}

async fn stop_runtime(
    lifecycle: &mut RuntimeLifecycle,
    projections: &ProjectionPublisher,
    stop_participant: &dyn RuntimeStopParticipant,
    emergency: bool,
) -> Result<(), RuntimeServiceError> {
    let event = if emergency {
        RuntimeEvent::EmergencyStopRequested
    } else {
        RuntimeEvent::StopRequested
    };
    let command = if emergency {
        RuntimeCommand::EmergencyStop
    } else {
        RuntimeCommand::Stop
    };
    if let Err(error) = lifecycle.apply(event) {
        log_rejected_command(command, error);
        return Ok(());
    }
    publish(projections, lifecycle.projection());
    stop_participant.stop_and_drain()?;
    tokio::time::sleep(TRANSITION_DELAY).await;
    lifecycle.apply(RuntimeEvent::StopCompleted)?;
    publish(projections, lifecycle.projection());
    info!(
        generation = lifecycle.projection().generation().get(),
        "runtime stopped"
    );
    Ok(())
}

async fn restart_runtime(
    lifecycle: &mut RuntimeLifecycle,
    projections: &ProjectionPublisher,
    stop_participant: &dyn RuntimeStopParticipant,
) -> Result<(), RuntimeServiceError> {
    if let Err(error) = lifecycle.apply(RuntimeEvent::RestartRequested) {
        log_rejected_command(RuntimeCommand::Restart, error);
        return Ok(());
    }
    publish(projections, lifecycle.projection());
    stop_participant.stop_and_drain()?;
    tokio::time::sleep(TRANSITION_DELAY).await;
    lifecycle.apply(RuntimeEvent::RestartCompleted)?;
    publish(projections, lifecycle.projection());
    info!(
        generation = lifecycle.projection().generation().get(),
        "runtime restarted"
    );
    Ok(())
}

fn transition_to_stopping(
    lifecycle: &mut RuntimeLifecycle,
    projections: &ProjectionPublisher,
    stop_participant: &dyn RuntimeStopParticipant,
) -> Result<(), RuntimeServiceError> {
    if lifecycle.projection().phase() == RuntimePhase::Stopped {
        debug!("runtime already stopped during shutdown");
        return Ok(());
    }
    lifecycle.apply(RuntimeEvent::ShutdownRequested)?;
    publish(projections, lifecycle.projection());
    stop_participant.stop_and_drain()?;
    Ok(())
}

fn publish(projections: &ProjectionPublisher, projection: &RuntimeProjection) {
    projections.latest.send_replace(projection.clone());
    let _ = projections.notifications.try_send(());
}

fn log_rejected_command(command: RuntimeCommand, error: RuntimeTransitionError) {
    warn!(?command, %error, "runtime command rejected by lifecycle state machine");
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeClientError {
    #[error("runtime command queue is full")]
    QueueFull,
    #[error("runtime command channel is closed")]
    RuntimeClosed,
}

#[derive(Debug, Error)]
pub enum RuntimeServiceError {
    #[error("failed to spawn runtime thread")]
    ThreadSpawn(#[source] io::Error),
    #[error("runtime initialization timed out")]
    InitializationTimeout,
    #[error("runtime initialization channel closed")]
    InitializationChannelClosed,
    #[error("failed to build Tokio runtime: {0}")]
    RuntimeBuild(#[source] io::Error),
    #[error("runtime initialization reported failure without an error")]
    InitializationFailureMissing,
    #[error("runtime event stream has already been taken")]
    EventStreamAlreadyTaken,
    #[error("runtime event stream closed")]
    EventStreamClosed,
    #[error("timed out waiting for runtime event")]
    EventTimeout,
    #[error("runtime thread panicked")]
    ThreadPanicked,
    #[error(transparent)]
    StopParticipant(#[from] RuntimeStopParticipantError),
    #[error(transparent)]
    Transition(#[from] RuntimeTransitionError),
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, mpsc};
    use std::time::{Duration, Instant};

    use forge_domain::{RuntimeCommand, RuntimeGeneration, RuntimePhase, RuntimeProjection};
    use tokio::sync::watch;

    use super::{
        ProjectionPublisher, RuntimeEventStream, RuntimeService, RuntimeStopParticipant,
        RuntimeStopParticipantError, publish,
    };

    #[derive(Debug)]
    struct CountingStopParticipant(Arc<AtomicUsize>);

    impl RuntimeStopParticipant for CountingStopParticipant {
        fn stop_and_drain(&self) -> Result<(), RuntimeStopParticipantError> {
            self.0.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }
    }

    #[test]
    fn runtime_supports_stop_start_restart_and_shutdown() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut service = RuntimeService::start()?;
        let client = service.client();
        let mut events = service.take_event_stream()?;

        let first_running = wait_for_phase(&mut events, RuntimePhase::Running)?;
        assert_eq!(first_running.generation().get(), 1);

        client.send(RuntimeCommand::EmergencyStop)?;
        let stopped = wait_for_phase(&mut events, RuntimePhase::Stopped)?;
        assert_eq!(stopped.generation().get(), 1);

        client.send(RuntimeCommand::Start)?;
        let second_running = wait_for_phase(&mut events, RuntimePhase::Running)?;
        assert_eq!(second_running.generation().get(), 2);

        client.send(RuntimeCommand::Restart)?;
        let third_running = wait_for_phase(&mut events, RuntimePhase::Running)?;
        assert_eq!(third_running.generation().get(), 3);

        assert!(matches!(
            service.take_event_stream(),
            Err(super::RuntimeServiceError::EventStreamAlreadyTaken)
        ));

        service.shutdown()?;
        Ok(())
    }

    #[test]
    fn stop_restart_and_shutdown_drain_the_injected_participant()
    -> Result<(), Box<dyn std::error::Error>> {
        let calls = Arc::new(AtomicUsize::new(0));
        let participant = Arc::new(CountingStopParticipant(Arc::clone(&calls)));
        let mut service = RuntimeService::start_with_stop_participant(participant)?;
        let client = service.client();
        let mut events = service.take_event_stream()?;
        let _running = wait_for_phase(&mut events, RuntimePhase::Running)?;
        client.send(RuntimeCommand::Stop)?;
        let _stopped = wait_for_phase(&mut events, RuntimePhase::Stopped)?;
        client.send(RuntimeCommand::Start)?;
        let _running = wait_for_phase(&mut events, RuntimePhase::Running)?;
        client.send(RuntimeCommand::Restart)?;
        let _running = wait_for_phase(&mut events, RuntimePhase::Running)?;
        service.shutdown()?;
        assert_eq!(calls.load(Ordering::Acquire), 3);
        Ok(())
    }

    #[test]
    fn dropped_projection_subscriber_does_not_block_shutdown()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut service = RuntimeService::start()?;
        drop(service.take_event_stream()?);

        service.shutdown()?;
        Ok(())
    }

    #[test]
    fn restart_observation_then_shutdown_completes_within_one_second()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut service = RuntimeService::start()?;
        let client = service.client();
        let mut events = service.take_event_stream()?;
        wait_for_phase(&mut events, RuntimePhase::Running)?;

        client.send(RuntimeCommand::Restart)?;
        let restarting = wait_for_phase(&mut events, RuntimePhase::Restarting)?;
        assert_eq!(restarting.generation().get(), 1);

        let shutdown_started = Instant::now();
        service.shutdown()?;
        assert!(shutdown_started.elapsed() <= Duration::from_secs(1));
        Ok(())
    }

    #[test]
    fn latest_transport_coalesces_ten_thousand_projections_without_consumer_progress()
    -> Result<(), Box<dyn std::error::Error>> {
        let initial = RuntimeProjection::Starting {
            generation: RuntimeGeneration::INITIAL,
        };
        let (latest, receiver) = watch::channel(initial.clone());
        let (notifications, notification_receiver) = mpsc::sync_channel(1);
        let publisher = ProjectionPublisher {
            latest,
            notifications,
        };

        let mut events = RuntimeEventStream::new(receiver, notification_receiver, initial);
        for uptime_seconds in 1..=10_000 {
            publish(
                &publisher,
                &RuntimeProjection::Running {
                    generation: RuntimeGeneration::INITIAL,
                    uptime_seconds,
                },
            );
        }

        let projection = events
            .take_latest()?
            .ok_or("latest projection was not published")?;
        assert_eq!(projection.uptime_seconds(), 10_000);
        assert_eq!(events.take_latest()?, None);
        Ok(())
    }

    #[test]
    fn stale_notification_does_not_duplicate_an_already_seen_projection()
    -> Result<(), Box<dyn std::error::Error>> {
        let (latest, receiver) = watch::channel(RuntimeProjection::Starting {
            generation: RuntimeGeneration::INITIAL,
        });
        let (notifications, notification_receiver) = mpsc::sync_channel(1);
        let publisher = ProjectionPublisher {
            latest,
            notifications,
        };
        publish(
            &publisher,
            &RuntimeProjection::Running {
                generation: RuntimeGeneration::INITIAL,
                uptime_seconds: 1,
            },
        );

        let seen = RuntimeProjection::Running {
            generation: RuntimeGeneration::INITIAL,
            uptime_seconds: 1,
        };
        let mut events = RuntimeEventStream::new(receiver, notification_receiver, seen);
        // This models the producer publishing its notification after a
        // consumer has observed the watch value but before it consumes the
        // notification slot.
        let already_seen = events.latest.borrow_and_update().clone();
        assert_eq!(already_seen.uptime_seconds(), 1);
        assert_eq!(events.take_latest()?, None);
        Ok(())
    }

    #[test]
    fn recv_timeout_delivers_final_projection_before_sender_closure()
    -> Result<(), Box<dyn std::error::Error>> {
        let (latest, receiver) = watch::channel(RuntimeProjection::Starting {
            generation: RuntimeGeneration::INITIAL,
        });
        let (notifications, notification_receiver) = mpsc::sync_channel(1);
        let publisher = ProjectionPublisher {
            latest,
            notifications,
        };
        let mut events = RuntimeEventStream::new(
            receiver,
            notification_receiver,
            RuntimeProjection::Starting {
                generation: RuntimeGeneration::INITIAL,
            },
        );
        publish(
            &publisher,
            &RuntimeProjection::Running {
                generation: RuntimeGeneration::INITIAL,
                uptime_seconds: 1,
            },
        );
        publish(
            &publisher,
            &RuntimeProjection::Running {
                generation: RuntimeGeneration::INITIAL,
                uptime_seconds: 2,
            },
        );
        drop(publisher);

        let final_projection = events.recv_timeout(Duration::from_secs(1))?;
        assert_eq!(final_projection.uptime_seconds(), 2);
        assert!(matches!(
            events.recv_timeout(Duration::ZERO),
            Err(super::RuntimeServiceError::EventStreamClosed)
        ));
        Ok(())
    }

    fn wait_for_phase(
        events: &mut RuntimeEventStream,
        phase: RuntimePhase,
    ) -> Result<RuntimeProjection, Box<dyn std::error::Error>> {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let now = Instant::now();
            if now >= deadline {
                return Err(format!("timed out waiting for runtime phase {phase:?}").into());
            }
            let projection = events.recv_timeout(deadline.saturating_duration_since(now))?;
            if projection.phase() == phase {
                return Ok(projection);
            }
        }
    }
}
