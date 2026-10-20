//! Root-owned shutdown continues even when the observing caller disconnects.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::task::JoinHandle;

use super::{AppState, ShutdownPhase};
use crate::bridge::BridgeDrainReport;

#[must_use]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum ServerJoinState {
    /// No listener was committed to this owner, including a failed bind.
    #[default]
    NotStarted,
    Joined,
    Pending,
    Failed,
}

/// Pending work is retained by its owner and can be drained by a later call.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShutdownReport {
    pub bridge: BridgeDrainReport,
    pub pending_event_tasks: usize,
    pub server: ServerJoinState,
    pub coordinator_failed: bool,
}

impl ShutdownReport {
    pub fn is_complete(self) -> bool {
        self.bridge.is_complete()
            && self.pending_event_tasks == 0
            && self.server != ServerJoinState::Pending
            && !self.coordinator_failed
    }

    /// Cleanup succeeded. `NotStarted` is valid when no listener was owned;
    /// callers must inspect the serve result to establish startup success.
    pub fn is_successful(self) -> bool {
        self.is_complete() && self.bridge.is_successful() && self.server != ServerJoinState::Failed
    }
}

#[derive(Debug, Default)]
pub(super) struct OwnedServer {
    pub(super) task: Option<JoinHandle<std::io::Result<()>>>,
    pub(super) state: ServerJoinState,
}

pub(super) type ShutdownTask = Option<JoinHandle<ShutdownReport>>;

impl AppState {
    /// Drain within the requested budget and report any work still owned.
    /// Cancellation of this observer does not cancel or duplicate cleanup.
    pub async fn shutdown(&self, drain_timeout: Duration) -> ShutdownReport {
        let mut slot = self.shutdown_task.lock().await;
        let handle = slot.get_or_insert_with(|| {
            let state = self.clone();
            tokio::spawn(async move { state.run_shutdown(drain_timeout).await })
        });
        let result = handle.await;
        *slot = None;
        match result {
            Ok(report) => report,
            Err(_) => ShutdownReport {
                bridge: BridgeDrainReport {
                    pending_commands: self.executor.inflight(),
                    ownership_failed: true,
                    ..BridgeDrainReport::default()
                },
                pending_event_tasks: self.event_tasks.len(),
                server: self.server_task.lock().await.state,
                coordinator_failed: true,
            },
        }
    }

    async fn run_shutdown(&self, drain_timeout: Duration) -> ShutdownReport {
        let started = Instant::now();
        self.stop_admission();
        self.set_phase(ShutdownPhase::CloseStreams);
        self.shutdown.cancel();
        self.event_tasks.close();
        self.set_phase(ShutdownPhase::CancelInflight);
        let executor = Arc::clone(&self.executor);
        let remaining = drain_timeout.saturating_sub(started.elapsed());
        let bridge = tokio::task::spawn_blocking(move || executor.drain_and_join(remaining))
            .await
            .unwrap_or_else(|_| BridgeDrainReport {
                ownership_failed: true,
                ..BridgeDrainReport::default()
            });
        if !self.event_tasks.is_empty() {
            let _ = tokio::time::timeout(
                drain_timeout.saturating_sub(started.elapsed()),
                self.event_tasks.wait(),
            )
            .await;
        }
        let server = self
            .join_server(drain_timeout.saturating_sub(started.elapsed()))
            .await;
        let report = ShutdownReport {
            bridge,
            pending_event_tasks: self.event_tasks.len(),
            server,
            coordinator_failed: false,
        };
        if report.is_complete() {
            self.set_phase(ShutdownPhase::Join);
        }
        report
    }

    async fn join_server(&self, remaining: Duration) -> ServerJoinState {
        let task = self.server_task.lock().await.task.take();
        let Some(mut task) = task else {
            return self.server_task.lock().await.state;
        };
        let result = if task.is_finished() {
            Some((&mut task).await)
        } else {
            tokio::time::timeout(remaining, &mut task).await.ok()
        };
        let mut owner = self.server_task.lock().await;
        owner.state = match result {
            Some(Ok(Ok(()))) => ServerJoinState::Joined,
            Some(Ok(Err(_)) | Err(_)) => ServerJoinState::Failed,
            None => {
                owner.task = Some(task);
                ServerJoinState::Pending
            }
        };
        owner.state
    }
}
