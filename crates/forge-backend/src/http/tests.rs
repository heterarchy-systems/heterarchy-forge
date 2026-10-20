use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll, Waker};

use futures_core::Stream;
use tokio_util::sync::CancellationToken;

use super::{ShutdownPhase, SseStream};

mod execution_cancel;

#[test]
fn late_stream_poll_does_not_miss_shutdown() -> Result<(), Box<dyn std::error::Error>> {
    let (_sender, receiver) = tokio::sync::mpsc::channel(1);
    let phase = Arc::new(RwLock::new(ShutdownPhase::StopAdmission));
    let exit = CancellationToken::new();
    let mut stream = SseStream {
        receiver,
        cancelled: Box::pin(exit.clone().cancelled_owned()),
        exit,
        phase: Arc::clone(&phase),
        poller: None,
        terminal_emitted: false,
    };
    let mut context = Context::from_waker(Waker::noop());
    assert!(Pin::new(&mut stream).poll_next(&mut context).is_pending());
    *phase
        .write()
        .map_err(|_| std::io::Error::other("shutdown phase lock poisoned"))? = ShutdownPhase::Join;
    assert!(matches!(
        Pin::new(&mut stream).poll_next(&mut context),
        Poll::Ready(Some(Ok(_)))
    ));
    assert!(matches!(
        Pin::new(&mut stream).poll_next(&mut context),
        Poll::Ready(None)
    ));
    Ok(())
}

#[derive(Debug)]
struct DrainProbe {
    calls: std::sync::atomic::AtomicUsize,
    entered: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    release: std::sync::Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
}

impl crate::bridge::CommandExecutor for DrainProbe {
    fn submit(
        &self,
        _command: crate::ops::Command,
    ) -> Result<tokio::sync::oneshot::Receiver<crate::bridge::BridgeOutcome>, crate::ForgeError>
    {
        Err(crate::ForgeError::internal())
    }

    fn inflight(&self) -> usize {
        0
    }

    fn drain_and_join(&self, _budget: std::time::Duration) -> crate::bridge::BridgeDrainReport {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if let Some(entered) = self.entered.lock().ok().and_then(|mut slot| slot.take()) {
            let _ = entered.send(());
        }
        if let Some(release) = self.release.lock().ok().and_then(|mut slot| slot.take()) {
            let _ = release.blocking_recv();
        }
        crate::bridge::BridgeDrainReport::default()
    }
}

#[derive(Debug)]
struct NoEvents;

impl crate::events::EventQuery for NoEvents {
    fn page(
        &self,
        _scope: &forge_control::ResolvedWorkspaceScope,
        _after: u64,
        _limit: u32,
    ) -> Result<crate::events::EventPage, crate::events::EventQueryError> {
        Err(crate::events::EventQueryError::Failed)
    }

    fn snapshot(
        &self,
        _scope: &forge_control::ResolvedWorkspaceScope,
    ) -> Result<(u64, u64, serde_json::Value), crate::events::EventQueryError> {
        Err(crate::events::EventQueryError::Failed)
    }
}

/// Occupy the real control worker at its external session-authority port.
/// Readiness reads queued behind it must retain their slot and shutdown owner.
struct BlockedSessionAuthority {
    entered: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    release: std::sync::Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
}

impl forge_control::AgentSessionAuthority for BlockedSessionAuthority {
    fn open(
        &self,
        _request: &forge_domain::OpenAgentSession,
    ) -> Result<forge_domain::AgentSessionOpenOutcome, forge_control::ControlError> {
        Err(forge_control::AgentSessionAuthorityFailure::Unavailable.into_control_error())
    }

    fn resolve(
        &self,
        _request: forge_control::AgentSessionResolveRequest,
    ) -> Result<Option<forge_domain::RegisteredAgentSession>, forge_control::ControlError> {
        if let Some(entered) = self.entered.lock().ok().and_then(|mut slot| slot.take()) {
            let _ = entered.send(());
        }
        if let Some(release) = self.release.lock().ok().and_then(|mut slot| slot.take()) {
            let _ = release.blocking_recv();
        }
        Ok(None)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn readiness_cancellation_and_timeout_retain_capacity_and_shutdown_ownership()
-> Result<(), Box<dyn std::error::Error>> {
    use std::time::Duration;

    for cancel_observer in [true, false] {
        let root = std::env::temp_dir().join(format!("forge-readiness-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&root)?;
        let registry = forge_persistence::GlobalRegistry::open(root.join("registry.sqlite3"))?;
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let control = forge_control::ForgeControl::with_session_authority(
            forge_workspace::LocationService::new(registry),
            Box::new(BlockedSessionAuthority {
                entered: std::sync::Mutex::new(Some(entered_tx)),
                release: std::sync::Mutex::new(Some(release_rx)),
            }),
        );
        let (client, mut worker) = forge_control::ForgeControlWorker::start(control)?;
        let blocked_client = client.clone();
        let blocked = tokio::task::spawn_blocking(move || {
            blocked_client.agent_session_resolve(forge_control::AgentSessionResolveRequest {
                session_id: forge_domain::AgentSessionId::from_uuid(uuid::Uuid::now_v7()),
                principal: forge_domain::AuthenticatedPrincipal::TrustedStdio,
            })
        });
        tokio::time::timeout(Duration::from_secs(2), entered_rx).await??;
        let config = crate::BackendConfig::new(
            std::net::IpAddr::from([127, 0, 0, 1]),
            0,
            "readiness-test-credential",
            forge_domain::ForgeBackendId::from_uuid(uuid::Uuid::now_v7()),
            forge_domain::OrchestrationIssuerId::from_uuid(uuid::Uuid::now_v7()),
        )?;
        let state = super::AppState::new(
            config,
            Arc::new(DrainProbe {
                calls: std::sync::atomic::AtomicUsize::new(0),
                entered: std::sync::Mutex::new(None),
                release: std::sync::Mutex::new(None),
            }),
            Arc::new(NoEvents),
        );
        state.set_probe(Arc::new(client));
        let observing_state = state.clone();
        let observer =
            tokio::spawn(async move { super::readyz(axum::extract::State(observing_state)).await });
        tokio::time::timeout(Duration::from_secs(2), async {
            while state.ready_probe.available_permits() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        if cancel_observer {
            observer.abort();
            assert!(observer.await.is_err_and(|error| error.is_cancelled()));
        } else {
            let response = tokio::time::timeout(Duration::from_secs(3), observer).await??;
            assert_eq!(
                response.status(),
                axum::http::StatusCode::SERVICE_UNAVAILABLE
            );
        }
        let available_while_blocked = state.ready_probe.available_permits();
        let pending = state.shutdown(Duration::ZERO).await;
        let response = super::readyz(axum::extract::State(state.clone())).await;
        let _ = release_tx.send(());
        let _resolve_result = blocked.await?;
        let settled = state.shutdown(Duration::from_secs(2)).await;
        worker.shutdown()?;
        std::fs::remove_dir_all(root)?;

        assert_eq!(
            available_while_blocked, 0,
            "an unfinished probe retains its slot"
        );
        assert_eq!(
            pending.pending_event_tasks, 1,
            "shutdown must account for the probe"
        );
        assert!(!pending.is_complete());
        assert_eq!(
            response.status(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        );
        assert!(settled.is_successful());
        assert_eq!(state.ready_probe.available_permits(), 1);
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelling_shutdown_observer_retains_one_cleanup_owner()
-> Result<(), Box<dyn std::error::Error>> {
    use std::time::Duration;

    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let probe = Arc::new(DrainProbe {
        calls: std::sync::atomic::AtomicUsize::new(0),
        entered: std::sync::Mutex::new(Some(entered_tx)),
        release: std::sync::Mutex::new(Some(release_rx)),
    });
    let config = crate::BackendConfig::new(
        std::net::IpAddr::from([127, 0, 0, 1]),
        0,
        "cleanup-test-credential",
        forge_domain::ForgeBackendId::from_uuid(uuid::Uuid::from_u128(1)),
        forge_domain::OrchestrationIssuerId::from_uuid(uuid::Uuid::from_u128(2)),
    )?;
    let state = super::AppState::new(config, probe.clone(), Arc::new(NoEvents));
    let observing_state = state.clone();
    let observer =
        tokio::spawn(async move { observing_state.shutdown(Duration::from_secs(5)).await });
    tokio::time::timeout(Duration::from_secs(2), entered_rx).await??;
    observer.abort();
    assert!(observer.await.is_err_and(|error| error.is_cancelled()));
    let _ = release_tx.send(());
    let report =
        tokio::time::timeout(Duration::from_secs(2), state.shutdown(Duration::ZERO)).await?;
    assert!(report.is_successful());
    assert_eq!(report.server, super::ServerJoinState::NotStarted);
    assert_eq!(probe.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(state.phase(), ShutdownPhase::Join);
    Ok(())
}
