//! Cancellation response expiry must not detach the admitted resource owner.

use std::time::Duration;

use super::{BlockedSessionAuthority, DrainProbe, NoEvents};
use crate::http::{AppState, execution_cancel};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

fn command() -> Result<Box<crate::ops::execution::ExecutionCancelCommand>, crate::ForgeError> {
    let payload = serde_json::json!({
        "scope": {
            "workspace_id": Uuid::from_u128(1), "workspace_revision": 1,
            "locator": {"location_id": Uuid::from_u128(2), "expected_revision": 1, "relative_root": "."}
        },
        "activity": {"activity_id": Uuid::from_u128(3), "runtime_instance_id": Uuid::from_u128(4), "observed_at_ms": 1},
        "actor": {
            "session_id": Uuid::from_u128(5), "principal": {"kind": "trusted_stdio"},
            "workspace_id": Uuid::from_u128(1), "agent_id": Uuid::from_u128(6), "expected_revision": 1
        },
        "goal_id": Uuid::from_u128(7), "expected_goal_revision": 1,
        "expected_dag_revision": 1, "node_id": Uuid::from_u128(8), "expected_node_revision": 1,
        "command_id": "cancel-owner-regression", "execution_id": Uuid::from_u128(9)
    });
    crate::ops::execution::parse_cancel(&serde_json::json!({"authority": payload})).map(Box::new)
}

fn state(response_deadline: Duration) -> Result<AppState, Box<dyn std::error::Error>> {
    let config = crate::BackendConfig::new(
        "127.0.0.1".parse()?,
        0,
        "cancel-owner-test-credential",
        forge_domain::ForgeBackendId::from_uuid(Uuid::from_u128(11)),
        forge_domain::OrchestrationIssuerId::from_uuid(Uuid::from_u128(12)),
    )?
    .with_command_deadline(response_deadline);
    Ok(AppState::new(
        config,
        Arc::new(DrainProbe {
            calls: std::sync::atomic::AtomicUsize::new(0),
            entered: Mutex::new(None),
            release: Mutex::new(None),
        }),
        Arc::new(NoEvents),
    ))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unfinished_cancellation_retains_capacity_and_shutdown_owner()
-> Result<(), Box<dyn std::error::Error>> {
    for cancel_observer in [false, true] {
        let cancellation = command()?;
        let state = state(if cancel_observer {
            Duration::from_secs(2)
        } else {
            Duration::from_millis(50)
        })?;
        let root = std::env::temp_dir().join(format!("forge-cancel-owner-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&root)?;
        let registry = forge_persistence::GlobalRegistry::open(root.join("registry.sqlite3"))?;
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let control = forge_control::ForgeControl::with_session_authority(
            forge_workspace::LocationService::new(registry),
            Box::new(BlockedSessionAuthority {
                entered: Mutex::new(Some(entered_tx)),
                release: Mutex::new(Some(release_rx)),
            }),
        );
        let (client, mut worker) = forge_control::ForgeControlWorker::start(control)?;
        let mut execution = forge_control::ForgeExecutionCoordinator::start(client.clone(), 2)?;
        let blocked = tokio::task::spawn_blocking(move || {
            client.agent_session_resolve(forge_control::AgentSessionResolveRequest {
                session_id: forge_domain::AgentSessionId::from_uuid(Uuid::from_u128(10)),
                principal: forge_domain::AuthenticatedPrincipal::TrustedStdio,
            })
        });
        // Drop the gate before worker owners on any early error.
        let release_gate = release_tx;
        tokio::time::timeout(Duration::from_secs(2), entered_rx).await??;
        state.set_execution_fast_lane(Arc::new(execution.client()));
        let mut observers = Vec::new();
        for _ in 0..execution_cancel::CANCEL_FAST_LANE_PERMITS {
            let observing = state.clone();
            let request = cancellation.clone();
            observers.push(tokio::spawn(async move {
                execution_cancel::handle(&observing, Uuid::now_v7(), request).await
            }));
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            while state.cancel_permits.available_permits() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        for observer in observers {
            if cancel_observer {
                assert!(
                    !observer.is_finished(),
                    "the observer must still await the owner"
                );
                observer.abort();
                assert!(observer.await.is_err_and(|error| error.is_cancelled()));
            } else {
                let response = observer.await?;
                assert_eq!(response.status(), axum::http::StatusCode::ACCEPTED);
                let body = axum::body::to_bytes(response.into_body(), 4096).await?;
                let reply: serde_json::Value = serde_json::from_slice(&body)?;
                assert_eq!(reply["error"]["code"], "UNKNOWN_OUTCOME");
                assert_eq!(
                    reply["error"]["readback"]["execution_id"],
                    Uuid::from_u128(9).to_string()
                );
            }
        }
        let available_while_blocked = state.cancel_permits.available_permits();
        let fifth = execution_cancel::handle(&state, Uuid::now_v7(), cancellation).await;
        let fifth_body = axum::body::to_bytes(fifth.into_body(), 4096).await?;
        let fifth_reply: serde_json::Value = serde_json::from_slice(&fifth_body)?;
        let pending = state.shutdown(Duration::ZERO).await;
        let _released = release_gate.send(());
        let _resolve_result = blocked.await?;
        let settled = state.shutdown(Duration::from_secs(2)).await;
        let _execution_report = execution.shutdown()?;
        worker.shutdown()?;
        std::fs::remove_dir_all(root)?;

        assert_eq!(
            available_while_blocked, 0,
            "unfinished cancellations retain their slots"
        );
        assert_eq!(fifth_reply["error"]["code"], "CAPACITY_EXCEEDED");
        assert_eq!(
            pending.pending_event_tasks,
            execution_cancel::CANCEL_FAST_LANE_PERMITS
        );
        assert!(!pending.is_complete());
        assert!(settled.is_successful());
        assert_eq!(
            state.cancel_permits.available_permits(),
            execution_cancel::CANCEL_FAST_LANE_PERMITS
        );
    }
    Ok(())
}
