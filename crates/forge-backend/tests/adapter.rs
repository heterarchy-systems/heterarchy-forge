//! Adapter integration tests over a real loopback listener with a real
//! event-stream client. The control seam is a bounded transport fake.

use std::sync::Arc;
use std::time::Duration;

use forge_backend::bridge::{BridgeDrainReport, BridgeOutcome, CommandExecutor};
use forge_backend::config::BackendConfig;
use forge_backend::error::ErrorCode;
use forge_backend::events::{EventPage, EventQuery, EventQueryError, EventRecord, Subjects};
use forge_backend::http::{AppState, ServerJoinState, ShutdownPhase, serve};
use forge_backend::ops::Command;
use forge_control::{ControlErrorCode, ControlErrorView, ResolvedWorkspaceScope};
use tokio::sync::oneshot;
use uuid::Uuid;

const SECRET: &str = "test-issuer-secret";

#[tokio::test]
async fn http_connection_limit_sheds_excess_sockets_and_recovers_capacity()
-> Result<(), Box<dyn std::error::Error>> {
    use tokio::io::AsyncWriteExt;
    let state = AppState::new(
        config(0)?.with_http_connection_limit(2),
        fake_executor(8, QueueBehavior::Complete),
        Arc::new(StaticEvents {
            events: Vec::new(),
            retained_low: 0,
            unknown_workspace: std::sync::atomic::AtomicBool::new(false),
        }),
    );
    let address = serve(state.clone()).await?;
    let mut occupied = Vec::new();
    for _ in 0..2 {
        let mut stream = tokio::net::TcpStream::connect(address).await?;
        stream.write_all(b"GET /healthz HTTP/1.1\r\nHost:").await?;
        occupied.push(stream);
    }
    tokio::time::timeout(Duration::from_secs(1), async {
        while state.http_connection_stats().active != 2 {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    let excess = tokio::time::timeout(
        Duration::from_millis(500),
        http_request(address, "GET", "/healthz", None, None),
    )
    .await;
    drop(occupied);
    let recovered = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Ok((200, _)) = http_request(address, "GET", "/healthz", None, None).await {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;
    let drained = state.shutdown(Duration::from_secs(2)).await;
    let shed = match &excess {
        Ok(Err(_)) => true,
        Ok(Ok((0, response))) => response.is_empty(),
        _ => false,
    };
    assert!(shed, "excess connection was not shed: {excess:?}");
    recovered?;
    assert!(drained.is_successful());
    let connection_snapshot = state.http_connection_stats();
    assert_eq!(connection_snapshot.active, 0);
    assert!(connection_snapshot.rejected >= 1);
    Ok(())
}

#[tokio::test]
async fn http_trickled_headers_have_an_absolute_deadline() -> Result<(), Box<dyn std::error::Error>>
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let state = AppState::new(
        config(0)?.with_http_input_deadline(Duration::from_millis(100)),
        fake_executor(8, QueueBehavior::Complete),
        Arc::new(StaticEvents {
            events: Vec::new(),
            retained_low: 0,
            unknown_workspace: std::sync::atomic::AtomicBool::new(false),
        }),
    );
    let address = serve(state.clone()).await?;
    let mut stream = tokio::net::TcpStream::connect(address).await?;
    stream
        .write_all(b"GET /healthz HTTP/1.1\r\nX-Test: ")
        .await?;
    let (mut read, mut write) = stream.into_split();
    let writer = tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_millis(10));
        for _ in 0..30 {
            tick.tick().await;
            if write.write_all(b"a").await.is_err() {
                break;
            }
        }
    });
    let mut bytes = Vec::new();
    let response = tokio::time::timeout(Duration::from_secs(1), read.read_to_end(&mut bytes)).await;
    drop(read);
    writer.await?;
    let drained = state.shutdown(Duration::from_secs(2)).await;
    assert!(
        response.is_ok(),
        "trickle traffic renewed the header deadline: {response:?}"
    );
    if let Ok(Err(error)) = &response {
        assert!(matches!(
            error.kind(),
            std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::UnexpectedEof
        ));
    }
    let text = String::from_utf8(bytes)?;
    assert!(
        text.is_empty() || text.starts_with("HTTP/1.1 408"),
        "{text}"
    );
    assert_eq!(state.http_connection_stats().active, 0);
    assert!(state.http_connection_stats().transport_failures >= 1);
    assert!(drained.is_successful());
    Ok(())
}

#[tokio::test]
async fn http_header_and_body_size_limits_reject_before_application_admission()
-> Result<(), Box<dyn std::error::Error>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let executor = fake_executor(8, QueueBehavior::Complete);
    let state = AppState::new(
        config(0)?,
        executor.clone(),
        Arc::new(StaticEvents {
            events: Vec::new(),
            retained_low: 0,
            unknown_workspace: std::sync::atomic::AtomicBool::new(false),
        }),
    );
    let address = serve(state.clone()).await?;
    let mut stream = tokio::net::TcpStream::connect(address).await?;
    let mut headers =
        String::from("GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n");
    for index in 0..forge_backend::config::MAX_HTTP_HEADERS {
        use std::fmt::Write;
        write!(headers, "X-Limit-{index}: a\r\n")?;
    }
    headers.push_str("\r\n");
    stream.write_all(headers.as_bytes()).await?;
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response)).await??;
    assert!(String::from_utf8(response)?.starts_with("HTTP/1.1 431"));
    let oversized = "a".repeat(forge_backend::config::MAX_BODY_BYTES + 1);
    let (status, _) = tokio::time::timeout(
        Duration::from_secs(2),
        http_request(
            address,
            "POST",
            "/api/v1/commands/location.list",
            Some(SECRET),
            Some(&oversized),
        ),
    )
    .await??;
    assert_eq!(status, 413);
    assert_eq!(
        executor.submitted.load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    assert_eq!(
        http_request(address, "GET", "/healthz", None, None)
            .await?
            .0,
        200
    );
    assert!(state.shutdown(Duration::from_secs(2)).await.is_successful());
    Ok(())
}

#[tokio::test]
async fn http_input_deadline_does_not_terminate_a_live_sse_projection()
-> Result<(), Box<dyn std::error::Error>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let state = AppState::new(
        config(0)?.with_http_input_deadline(Duration::from_millis(50)),
        fake_executor(8, QueueBehavior::Complete),
        Arc::new(StaticEvents {
            events: Vec::new(),
            retained_low: 0,
            unknown_workspace: std::sync::atomic::AtomicBool::new(false),
        }),
    );
    let address = serve(state.clone()).await?;
    let mut stream = tokio::net::TcpStream::connect(address).await?;
    let request = format!(
        "GET /api/v1/events/stream?{} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {SECRET}\r\n\r\n",
        scope_query()
    );
    stream.write_all(request.as_bytes()).await?;
    let mut head = Vec::new();
    tokio::time::timeout(Duration::from_secs(1), async {
        let mut byte = [0];
        while !head.ends_with(b"\r\n\r\n") && head.len() < 4096 {
            stream.read_exact(&mut byte).await?;
            head.push(byte[0]);
        }
        Ok::<_, std::io::Error>(())
    })
    .await??;
    assert!(String::from_utf8(head)?.starts_with("HTTP/1.1 200"));
    // Keep consuming valid frames beyond four header/body deadline windows.
    let until = tokio::time::Instant::now() + Duration::from_millis(200);
    let mut byte = [0];
    loop {
        match tokio::time::timeout_at(until, stream.read(&mut byte)).await {
            Err(_) => break,
            Ok(Ok(0)) => return Err("input deadline closed a live SSE projection".into()),
            Ok(Ok(_)) => {}
            Ok(Err(error)) => return Err(error.into()),
        }
    }
    let report = state.shutdown(Duration::from_secs(2)).await;
    let mut tail = Vec::new();
    tokio::time::timeout(Duration::from_secs(1), stream.read_to_end(&mut tail)).await??;
    assert!(report.is_successful());
    assert_eq!(state.http_connection_stats().active, 0);
    Ok(())
}

#[tokio::test]
async fn http_incomplete_body_times_out_before_application_admission()
-> Result<(), Box<dyn std::error::Error>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let executor = fake_executor(8, QueueBehavior::Complete);
    let state = AppState::new(
        config(0)?.with_http_input_deadline(Duration::from_millis(100)),
        executor.clone(),
        Arc::new(StaticEvents {
            events: Vec::new(),
            retained_low: 0,
            unknown_workspace: std::sync::atomic::AtomicBool::new(false),
        }),
    );
    let address = serve(state.clone()).await?;
    let mut stream = tokio::net::TcpStream::connect(address).await?;
    let headers = format!(
        "POST /api/v1/commands/location.list HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {SECRET}\r\nContent-Type: application/json\r\nContent-Length: 1000\r\nConnection: close\r\n\r\n{{"
    );
    stream.write_all(headers.as_bytes()).await?;
    let mut bytes = Vec::new();
    let response =
        tokio::time::timeout(Duration::from_secs(1), stream.read_to_end(&mut bytes)).await;
    drop(stream);
    let drained = state.shutdown(Duration::from_secs(2)).await;
    assert!(
        matches!(response, Ok(Ok(_))),
        "incomplete body did not produce a bounded reply"
    );
    let response = String::from_utf8(bytes)?;
    assert!(response.starts_with("HTTP/1.1 408"), "{response}");
    assert_eq!(
        executor.submitted.load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    assert!(drained.is_successful());
    Ok(())
}

#[tokio::test]
async fn http_shutdown_stops_partial_body_without_admitting_a_command()
-> Result<(), Box<dyn std::error::Error>> {
    use tokio::io::AsyncWriteExt;
    let executor = fake_executor(8, QueueBehavior::Complete);
    let state = AppState::new(
        config(0)?,
        executor.clone(),
        Arc::new(StaticEvents {
            events: Vec::new(),
            retained_low: 0,
            unknown_workspace: std::sync::atomic::AtomicBool::new(false),
        }),
    );
    let address = serve(state.clone()).await?;
    let mut stream = tokio::net::TcpStream::connect(address).await?;
    stream.write_all(b"POST /api/v1/commands/location.list HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n{").await?;
    // The following request confirms the accept loop is serving connections.
    assert_eq!(
        http_request(address, "GET", "/healthz", None, None)
            .await?
            .0,
        200
    );
    let while_partial = state.shutdown(Duration::from_millis(500)).await;
    drop(stream);
    let final_report = state.shutdown(Duration::from_secs(2)).await;
    assert!(
        while_partial.is_successful(),
        "partial ingress retained shutdown: {while_partial:?}"
    );
    assert!(final_report.is_successful());
    assert_eq!(
        executor.submitted.load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    Ok(())
}

fn config(port: u16) -> Result<BackendConfig, forge_backend::ConfigError> {
    let config = BackendConfig::new(
        std::net::IpAddr::from([127, 0, 0, 1]),
        port,
        SECRET,
        forge_domain::ForgeBackendId::from_uuid(Uuid::from_u128(1)),
        forge_domain::OrchestrationIssuerId::from_uuid(Uuid::from_u128(2)),
    )?;
    Ok(config
        .with_command_deadline(Duration::from_secs(2))
        .with_sse_poll_interval(Duration::from_millis(50)))
}

/// Deterministic fake executor with an explicit queue capacity and optional
/// per-command completion behavior.
struct FakeExecutor {
    capacity: usize,
    behavior: QueueBehavior,
    queue: std::sync::Mutex<std::collections::VecDeque<Job>>,
    inflight: std::sync::atomic::AtomicUsize,
    submitted: std::sync::atomic::AtomicUsize,
}

impl std::fmt::Debug for FakeExecutor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FakeExecutor")
            .field("capacity", &self.capacity)
            .field("behavior", &self.behavior)
            .field("inflight", &self.inflight())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QueueBehavior {
    /// Complete each command immediately with a fixed result.
    Complete,
    /// Never complete; commands stay admitted (for deadline/unknown tests).
    Stall,
    /// Durable command committed, but its post-commit observation failed.
    CommittedUnconfirmed,
    /// Deterministic Goal/Activity planning identity conflict.
    GoalConflict,
}

struct Job {
    _reply: oneshot::Sender<BridgeOutcome>,
}

fn fake_executor(capacity: usize, behavior: QueueBehavior) -> Arc<FakeExecutor> {
    Arc::new(FakeExecutor {
        capacity,
        behavior,
        queue: std::sync::Mutex::new(std::collections::VecDeque::new()),
        inflight: std::sync::atomic::AtomicUsize::new(0),
        submitted: std::sync::atomic::AtomicUsize::new(0),
    })
}

impl CommandExecutor for FakeExecutor {
    fn submit(
        &self,
        command: Command,
    ) -> Result<oneshot::Receiver<BridgeOutcome>, forge_backend::ForgeError> {
        self.submitted
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let Ok(mut queue) = self.queue.lock() else {
            return Err(forge_backend::ForgeError::internal());
        };
        if queue.len() >= self.capacity {
            return Err(forge_backend::ForgeError::capacity_exceeded(
                "command bridge queue",
            ));
        }
        let (reply, receiver) = oneshot::channel();
        match self.behavior {
            QueueBehavior::Complete => {
                let outcome = BridgeOutcome::Completed(Ok(
                    serde_json::json!({ "echo": command.request_id() }),
                ));
                let _ = reply.send(outcome);
            }
            QueueBehavior::Stall => {
                let _ = command;
                queue.push_back(Job { _reply: reply });
            }
            QueueBehavior::CommittedUnconfirmed => {
                let error = forge_backend::ForgeError::from_control_view(
                    &forge_control::ControlErrorView::from_service(
                        forge_control::ControlErrorCode::CommittedButUnconfirmed,
                        true,
                    ),
                );
                let _ = reply.send(BridgeOutcome::Completed(Err(error)));
            }
            QueueBehavior::GoalConflict => {
                let error = forge_backend::ForgeError::from_control_view(
                    &ControlErrorView::from_service(ControlErrorCode::GoalConflict, false),
                );
                let _ = reply.send(BridgeOutcome::Completed(Err(error)));
            }
        }
        Ok(receiver)
    }

    fn inflight(&self) -> usize {
        self.inflight.load(std::sync::atomic::Ordering::Acquire)
    }

    fn drain_and_join(&self, _drain_timeout: Duration) -> BridgeDrainReport {
        BridgeDrainReport {
            pending_commands: self.inflight(),
            pending_workers: 0,
            worker_panics: 0,
            ownership_failed: false,
        }
    }
}

/// Bounded static event source for page/SSE tests.
#[derive(Debug)]
struct StaticEvents {
    events: Vec<EventRecord>,
    retained_low: u64,
    unknown_workspace: std::sync::atomic::AtomicBool,
}

impl EventQuery for StaticEvents {
    fn page(
        &self,
        scope: &ResolvedWorkspaceScope,
        after: u64,
        limit: u32,
    ) -> Result<EventPage, EventQueryError> {
        if scope != &test_scope().map_err(|_| EventQueryError::Failed)?
            || self
                .unknown_workspace
                .load(std::sync::atomic::Ordering::Acquire)
        {
            return Err(EventQueryError::UnknownWorkspace);
        }
        let events = self
            .events
            .iter()
            .filter(|event| event.sequence > after)
            .take(usize::try_from(limit).unwrap_or(0))
            .cloned()
            .collect();
        Ok(EventPage {
            events,
            high_water: 3,
            retained_low: self.retained_low,
        })
    }

    fn snapshot(
        &self,
        scope: &ResolvedWorkspaceScope,
    ) -> Result<(u64, u64, serde_json::Value), EventQueryError> {
        if scope != &test_scope().map_err(|_| EventQueryError::Failed)?
            || self
                .unknown_workspace
                .load(std::sync::atomic::Ordering::Acquire)
        {
            return Err(EventQueryError::UnknownWorkspace);
        }
        Ok((3, self.retained_low, serde_json::json!({ "goal_count": 1 })))
    }
}

struct BlockingSnapshotEvents {
    entered: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    release: std::sync::Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
}

impl std::fmt::Debug for BlockingSnapshotEvents {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BlockingSnapshotEvents")
            .finish_non_exhaustive()
    }
}

impl EventQuery for BlockingSnapshotEvents {
    fn page(
        &self,
        _scope: &ResolvedWorkspaceScope,
        _after: u64,
        _limit: u32,
    ) -> Result<EventPage, EventQueryError> {
        Ok(EventPage {
            events: Vec::new(),
            high_water: 0,
            retained_low: 0,
        })
    }

    fn snapshot(
        &self,
        _scope: &ResolvedWorkspaceScope,
    ) -> Result<(u64, u64, serde_json::Value), EventQueryError> {
        let entered = self
            .entered
            .lock()
            .ok()
            .and_then(|mut sender| sender.take());
        if let Some(sender) = entered {
            let _ = sender.send(());
        }
        let release = self
            .release
            .lock()
            .map_err(|_| EventQueryError::Failed)?
            .take()
            .ok_or(EventQueryError::Failed)?;
        release
            .blocking_recv()
            .map_err(|_| EventQueryError::Failed)?;
        Ok((0, 0, serde_json::json!({ "goal_count": 0 })))
    }
}

fn test_scope() -> Result<ResolvedWorkspaceScope, Box<dyn std::error::Error>> {
    let locator = forge_control::WorkspaceLocator::new(
        forge_domain::LocationId::from_uuid(Uuid::from_u128(1)),
        forge_domain::LocationRevision::INITIAL,
        std::path::Path::new("."),
    )?;
    Ok(ResolvedWorkspaceScope::from_observation(
        forge_domain::WorkspaceId::from_uuid(WORKSPACE),
        forge_domain::WorkspaceRevision::INITIAL,
        locator,
    ))
}

fn scope_query() -> String {
    format!(
        "workspace={WORKSPACE}&workspace_revision=1&location_id={}&location_revision=1&relative_root=.",
        Uuid::from_u128(1)
    )
}

fn sample_events() -> Vec<EventRecord> {
    (1..=3)
        .map(|sequence| {
            let mut digest = [0_u8; 32];
            digest[0] = u8::try_from(sequence).unwrap_or(0);
            EventRecord {
                sequence,
                kind: "goal_created".to_owned(),
                revision: 1,
                observed_at_ms: 12,
                digest,
                subjects: Some(Subjects {
                    goal_id: Some(Uuid::from_u128(0x60)),
                    dag_revision: None,
                    node_id: None,
                    execution_id: None,
                    change_set_id: None,
                    diff_id: None,
                    verification: None,
                }),
            }
        })
        .collect()
}

/// One-shot raw HTTP client used for every real-listener request.
async fn http_request(
    address: std::net::SocketAddr,
    method: &str,
    path: &str,
    bearer: Option<&str>,
    body: Option<&str>,
) -> Result<(u16, String), Box<dyn std::error::Error>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(address).await;
    if stream.is_err() {
        tokio::time::sleep(Duration::from_millis(200)).await;
        stream = tokio::net::TcpStream::connect(address).await;
    }
    let mut stream = stream.map_err(Box::<dyn std::error::Error>::from)?;
    let mut request =
        format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n");
    if let Some(bearer) = bearer {
        request.push_str("Authorization: Bearer ");
        request.push_str(bearer);
        request.push_str("\r\n");
    }
    if let Some(body) = body {
        request.push_str("Content-Type: application/json\r\n");
        request.push_str("Content-Length: ");
        request.push_str(body.len().to_string().as_str());
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    if let Some(body) = body {
        request.push_str(body);
    }
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(Box::<dyn std::error::Error>::from)?;
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .map_err(Box::<dyn std::error::Error>::from)?;
    let text = String::from_utf8_lossy(&response).into_owned();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|status| status.parse::<u16>().ok())
        .unwrap_or(0);
    Ok((status, text))
}

fn assert_error_code(
    response: &str,
    expected: ErrorCode,
) -> Result<(), Box<dyn std::error::Error>> {
    let reply: serde_json::Value = serde_json::from_str(body_of(response).as_str())?;
    assert_eq!(
        reply["error"]["code"].as_str(),
        Some(expected.as_str()),
        "unexpected failure envelope: {response}"
    );
    Ok(())
}

fn body_of(response: &str) -> String {
    response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_owned())
        .unwrap_or_default()
}

async fn spawn_server(
    executor: Arc<FakeExecutor>,
    events: Arc<StaticEvents>,
) -> Result<(std::net::SocketAddr, AppState), Box<dyn std::error::Error>> {
    let state = AppState::new(config(0)?, executor, events);
    let address = serve(state.clone()).await?;
    Ok((address, state))
}

fn envelope_body(op: &str, payload: &str) -> String {
    let request_id = Uuid::from_u128(0x11);
    format!(r#"{{"forge_api":1,"request_id":"{request_id}","op":"{op}","payload":{payload}}}"#)
}

fn binding_rejection_envelope(payload: &serde_json::Value) -> String {
    serde_json::json!({
        "forge_api": 1,
        "request_id": Uuid::from_u128(1),
        "op": "agent.binding.reject",
        "payload": payload,
    })
    .to_string()
}

fn binding_rejection_payload() -> serde_json::Value {
    serde_json::json!({
        "scope": {
            "workspace_id": Uuid::from_u128(2),
            "workspace_revision": 1,
            "locator": {
                "location_id": Uuid::from_u128(10),
                "expected_revision": 1,
                "relative_root": "."
            }
        },
        "issuer_id": Uuid::from_u128(9),
        "destination_id": Uuid::from_u128(7),
        "reference": {
            "migration_id": Uuid::from_u128(6),
            "expected_freeze_revision": 8,
            "manifest_digest": "11".repeat(32)
        },
        "reservation": {
            "request_id": Uuid::from_u128(1),
            "activity_id": Uuid::from_u128(3),
            "agent_id": Uuid::from_u128(4),
            "session_id": Uuid::from_u128(5),
            "principal": {"kind": "trusted_stdio", "token_id": null, "grant_id": null},
            "requested_at_ms": 20
        },
        "activation": {
            "request_id": Uuid::from_u128(1),
            "membership_digest": "55".repeat(32),
            "display_name": "worker",
            "declared_role": "operator",
            "transport": "other"
        },
        "reason": "principal_transport_mismatch",
        "observed_at_ms": 40
    })
}

fn unstarted_continuation_payload(request_id: Uuid) -> serde_json::Value {
    serde_json::json!({
        "scope": {
            "workspace_id": Uuid::from_u128(1),
            "workspace_revision": 2,
            "locator": {
                "location_id": Uuid::from_u128(2),
                "expected_revision": 3,
                "relative_root": "repo"
            }
        },
        "request_id": request_id,
        "expected_workspace_root_fingerprint": "101112131415161718191a1b1c1d1e1f",
        "expected_binding_digest": "20".repeat(32),
        "expected_delegation": {
            "migration_id": Uuid::from_u128(4),
            "destination_id": Uuid::from_u128(5),
            "freeze_revision": 1,
            "freeze_created_at_ms": 7,
            "freeze_updated_at_ms": 7,
            "manifest_digest": "30".repeat(32),
            "delegated_at_ms": 9,
            "delegation_digest": "40".repeat(32)
        },
        "probe_observed_at_ms": 10,
        "expected_probe_digest": "50".repeat(32),
        "census_version": 1,
        "activity": {
            "activity_id": Uuid::from_u128(6),
            "expected_revision": 11,
            "expected_created_at_ms": 12,
            "expected_updated_at_ms": 13,
            "expected_lease_owner_id": Uuid::from_u128(7),
            "expected_lease_until_ms": 14,
            "expected_lease_revision": 15
        },
        "initiating_session_id": Uuid::from_u128(8),
        "principal": {"kind":"trusted_stdio","token_id":null,"grant_id":null},
        "expected_agent_count": 1,
        "expected_agent_digest": "60".repeat(32),
        "expected_plan_digest": "70".repeat(32),
        "expected_coordinator": {
            "agent_id": Uuid::from_u128(9),
            "revision": 16,
            "updated_at_ms": 17
        },
        "duration_ms": 30_000
    })
}

fn goal_read_payload(activity_id: Uuid, goal_id: Uuid) -> String {
    serde_json::json!({
        "scope": {
            "workspace_id": WORKSPACE,
            "workspace_revision": 1,
            "locator": {
                "location_id": Uuid::from_u128(1),
                "expected_revision": 1,
                "relative_root": "."
            }
        },
        "activity_id": activity_id,
        "goal_id": goal_id
    })
    .to_string()
}

fn execution_begin_payload() -> String {
    serde_json::json!({
        "authority": {
            "scope": {
                "workspace_id": Uuid::from_u128(0x101),
                "workspace_revision": 7,
                "locator": {
                    "location_id": Uuid::from_u128(0x102),
                    "expected_revision": 3,
                    "relative_root": "."
                }
            },
            "activity": {
                "activity_id": Uuid::from_u128(0x103),
                "runtime_instance_id": Uuid::from_u128(0x104),
                "observed_at_ms": 19
            },
            "actor": {
                "session_id": Uuid::from_u128(0x105),
                "principal": { "kind": "trusted_stdio" },
                "workspace_id": Uuid::from_u128(0x101),
                "agent_id": Uuid::from_u128(0x106),
                "expected_revision": 11
            },
            "goal_id": Uuid::from_u128(0x107),
            "expected_goal_revision": 13,
            "expected_dag_revision": 17,
            "node_id": Uuid::from_u128(0x108),
            "expected_node_revision": 19,
            "command_id": "ci",
            "execution_id": Uuid::from_u128(0x109)
        },
        "grant_id": Uuid::from_u128(0x10a),
        "expected_grant_revision": 23,
        "mode": {
            "kind": "sealed_project_command",
            "command_id": "ci",
            "expected_catalog_fingerprint": "1111111111111111111111111111111111111111111111111111111111111111"
        },
        "admission": {
            "backend_id": Uuid::from_u128(0x10b),
            "issuer": Uuid::from_u128(0x10c),
            "expected_digest": "2222222222222222222222222222222222222222222222222222222222222222",
            "issued_at_ms": 29,
            "expires_at_ms": 31
        }
    })
    .to_string()
}

const WORKSPACE: Uuid = Uuid::from_u128(0x50);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn envelope_and_op_contract_rejects_mismatches_and_unknown_ops()
-> Result<(), Box<dyn std::error::Error>> {
    let executor = fake_executor(8, QueueBehavior::Complete);
    let (address, _state) = spawn_server(
        Arc::clone(&executor),
        Arc::new(StaticEvents {
            events: Vec::new(),
            retained_low: 0,
            unknown_workspace: std::sync::atomic::AtomicBool::new(false),
        }),
    )
    .await?;

    // URL/body op mismatch is rejected before admission.
    let (status, response) = http_request(
        address,
        "POST",
        "/api/v1/commands/goal.read",
        Some(SECRET),
        Some(&envelope_body("node.start", "{}")),
    )
    .await?;
    assert_eq!(status, 400);
    let reply: serde_json::Value = serde_json::from_str(body_of(&response).as_str())?;
    assert_eq!(reply["forge_api"], 1);
    assert_eq!(reply["ok"], false);
    assert_eq!(reply["error"]["code"], "INVALID_INPUT");
    assert_eq!(
        reply["request_id"],
        serde_json::json!(Uuid::from_u128(0x11)),
        "failure envelopes keep version and request identity"
    );

    // Unknown op is a typed rejection.
    let (status, response) = http_request(
        address,
        "POST",
        "/api/v1/commands/does.not_exist",
        Some(SECRET),
        Some(&envelope_body("does.not_exist", "{}")),
    )
    .await?;
    assert_eq!(status, 400);
    let reply: serde_json::Value = serde_json::from_str(body_of(&response).as_str())?;
    assert_eq!(reply["forge_api"], 1);
    assert_eq!(
        reply["request_id"],
        serde_json::json!(Uuid::from_u128(0x11))
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn goal_read_planning_conflict_is_http_409_not_unknown_outcome()
-> Result<(), Box<dyn std::error::Error>> {
    let (address, _state) = spawn_server(
        fake_executor(8, QueueBehavior::GoalConflict),
        Arc::new(StaticEvents {
            events: Vec::new(),
            retained_low: 0,
            unknown_workspace: std::sync::atomic::AtomicBool::new(false),
        }),
    )
    .await?;

    let body = envelope_body(
        "goal.read",
        &goal_read_payload(Uuid::from_u128(0x103), Uuid::from_u128(0x107)),
    );
    let (status, response) = http_request(
        address,
        "POST",
        "/api/v1/commands/goal.read",
        Some(SECRET),
        Some(&body),
    )
    .await?;
    assert_eq!(status, 409);
    assert_error_code(&response, ErrorCode::PlanningConflict)?;
    let reply: serde_json::Value = serde_json::from_str(body_of(&response).as_str())?;
    assert_eq!(reply["error"]["retryable"], false);
    assert_eq!(reply["error"]["category"], "revision_conflict");
    assert_eq!(reply["error"]["recovery_action"], "refresh_work");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bearer_gate_all_non_health_endpoints() -> Result<(), Box<dyn std::error::Error>> {
    let (address, _state) = spawn_server(
        fake_executor(8, QueueBehavior::Complete),
        Arc::new(StaticEvents {
            events: Vec::new(),
            retained_low: 0,
            unknown_workspace: std::sync::atomic::AtomicBool::new(false),
        }),
    )
    .await?;

    // Missing bearer (capability and health are the only unauthenticated
    // routes; events require the issuer).
    let (status, response) = http_request(
        address,
        "GET",
        &format!("/api/v1/events?{}", scope_query()),
        None,
        None,
    )
    .await?;
    assert_eq!(status, 400);
    assert_error_code(&response, ErrorCode::AuthFailed)?;

    // Invalid bearer.
    let (status, response) = http_request(
        address,
        "GET",
        &format!(
            "/api/v1/events?workspace=00000000-0000-0000-0000-000000000000&workspace_revision=1&location_id={}&location_revision=1&relative_root=.",
            Uuid::from_u128(1)
        ),
        Some("wrong"),
        None,
    )
    .await?;
    assert_eq!(status, 400);
    assert_error_code(&response, ErrorCode::AuthFailed)?;

    // Health stays unauthenticated.
    let (status, _) = http_request(address, "GET", "/healthz", None, None).await?;
    assert_eq!(status, 200);

    // Commands require the same issuer bearer.
    let body = envelope_body("goal.read", "{}");
    let (status, response) = http_request(
        address,
        "POST",
        "/api/v1/commands/goal.read",
        None,
        Some(&body),
    )
    .await?;
    assert_eq!(status, 400);
    assert_error_code(&response, ErrorCode::AuthFailed)?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn event_page_bounds_resync_and_snapshot_shape() -> Result<(), Box<dyn std::error::Error>> {
    let executor = fake_executor(8, QueueBehavior::Complete);
    let (address, _state) = spawn_server(
        executor,
        Arc::new(StaticEvents {
            events: sample_events(),
            retained_low: 2,
            unknown_workspace: std::sync::atomic::AtomicBool::new(false),
        }),
    )
    .await?;

    // Workspace UUID alone is not an accepted event scope; every locator and
    // revision component is required at the HTTP boundary.
    let (status, _) = http_request(
        address,
        "GET",
        &format!("/api/v1/events?workspace={WORKSPACE}&after=2&max=2"),
        Some(SECRET),
        None,
    )
    .await?;
    assert_eq!(status, 400);

    // Bounded page read from a live cursor.
    let (status, response) = http_request(
        address,
        "GET",
        &format!("/api/v1/events?{}&after=2&max=2", scope_query()),
        Some(SECRET),
        None,
    )
    .await?;
    assert_eq!(status, 200);
    let body = body_of(&response);
    assert!(body.contains("\"sequence\":3"), "page body: {body}");
    assert!(body.contains("\"high_water\":3"));

    // Cursor behind the retained floor: typed RESYNC_REQUIRED.
    let (status, response) = http_request(
        address,
        "GET",
        &format!("/api/v1/events?{}&after=0&max=64", scope_query()),
        Some(SECRET),
        None,
    )
    .await?;
    assert_eq!(status, 409);
    assert_error_code(&response, ErrorCode::ResyncRequired)?;

    // A UUID that names the same Workspace with a different Location scope
    // cannot bypass the exact control scope; transport maps the fake's
    // mismatch to a resumable resync response.
    let (status, response) = http_request(
        address,
        "GET",
        &format!(
            "/api/v1/events?workspace={WORKSPACE}&workspace_revision=1&location_id={}&location_revision=1&relative_root=.&after=2&max=2",
            Uuid::from_u128(2)
        ),
        Some(SECRET),
        None,
    )
    .await?;
    assert_eq!(status, 409);
    assert_error_code(&response, ErrorCode::ResyncRequired)?;

    // Snapshot exposes watermark + summary in one consistent read.
    let (status, response) = http_request(
        address,
        "GET",
        &format!("/api/v1/snapshot?{}", scope_query()),
        Some(SECRET),
        None,
    )
    .await?;
    assert_eq!(status, 200);
    let body = body_of(&response);
    assert!(body.contains("\"watermark_seq\":3") && body.contains("\"goal_count\":1"));
    let snapshot: serde_json::Value = serde_json::from_str(&body)?;
    assert_eq!(
        snapshot["result"]["scope"],
        serde_json::json!({
            "workspace_id": WORKSPACE,
            "workspace_revision": 1,
            "locator": {"location_id": Uuid::from_u128(1), "expected_revision": 1,
                "relative_root": "."},
        })
    );

    // Unknown workspace: typed rejection.
    let (status, response) = http_request(
        address,
        "GET",
        &format!(
            "/api/v1/snapshot?workspace=00000000-0000-0000-0000-000000000099&workspace_revision=1&location_id={}&location_revision=1&relative_root=.",
            Uuid::from_u128(1)
        ),
        Some(SECRET),
        None,
    )
    .await?;
    assert_eq!(status, 400);
    assert_error_code(&response, ErrorCode::InvalidInput)?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disconnected_blocking_snapshot_reports_pending_event_task_until_release()
-> Result<(), Box<dyn std::error::Error>> {
    use tokio::io::AsyncWriteExt;

    let (entered_sender, entered_receiver) = tokio::sync::oneshot::channel();
    let (release_sender, release_receiver) = tokio::sync::oneshot::channel();
    let events = Arc::new(BlockingSnapshotEvents {
        entered: std::sync::Mutex::new(Some(entered_sender)),
        release: std::sync::Mutex::new(Some(release_receiver)),
    });
    let state = AppState::new(
        config(0)?,
        fake_executor(8, QueueBehavior::Complete),
        events,
    );
    let address = serve(state.clone()).await?;
    let mut stream = tokio::net::TcpStream::connect(address).await?;
    let request = format!(
        "GET /api/v1/snapshot?{} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {SECRET}\r\nConnection: close\r\n\r\n",
        scope_query()
    );
    stream.write_all(request.as_bytes()).await?;
    tokio::time::timeout(Duration::from_secs(2), entered_receiver).await??;
    drop(stream);

    let pending = state.shutdown(Duration::from_millis(20)).await;
    assert_eq!(pending.pending_event_tasks, 1);
    assert_ne!(state.phase(), ShutdownPhase::Join);
    assert!(!pending.is_complete());
    assert!(!pending.is_successful());

    let _ = release_sender.send(());
    let complete = state.shutdown(Duration::from_secs(2)).await;
    assert_eq!(complete.pending_event_tasks, 0);
    assert_eq!(complete.server, ServerJoinState::Joined);
    assert!(complete.is_complete());
    assert!(complete.is_successful());
    assert_eq!(state.phase(), ShutdownPhase::Join);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sse_stream_replays_replays_live_tail_and_closes_slow_consumers()
-> Result<(), Box<dyn std::error::Error>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let executor = fake_executor(8, QueueBehavior::Complete);
    let (address, state) = spawn_server(
        executor,
        Arc::new(StaticEvents {
            events: sample_events(),
            retained_low: 0,
            unknown_workspace: std::sync::atomic::AtomicBool::new(false),
        }),
    )
    .await?;

    // Real event-stream client over the real listener.
    let mut stream = tokio::net::TcpStream::connect(address).await?;
    let request = format!(
        "GET /api/v1/events/stream?workspace={WORKSPACE}&workspace_revision=1&location_id=00000000-0000-0000-0000-000000000001&location_revision=1&relative_root=.&after=1 HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {SECRET}\r\nAccept: text/event-stream\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await?;
    let mut wire = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), async {
        let mut chunk = [0_u8; 512];
        loop {
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(read) => {
                    wire.extend_from_slice(&chunk[..read]);
                    let text = String::from_utf8_lossy(&wire);
                    if text.contains("id: 3") && text.matches("id:").count() >= 2 {
                        break;
                    }
                }
            }
        }
    })
    .await;
    let text = String::from_utf8_lossy(&wire).into_owned();
    assert!(
        text.contains("text/event-stream"),
        "SSE content type: {text}"
    );
    // Replay begins strictly after the cursor: sequences 2 and 3.
    assert!(text.contains("id: 2"), "replay event ids: {text}");
    assert!(text.contains("id: 3"));
    assert!(!text.contains("id: 1"), "cursor must be exclusive");

    // Last-Event-ID vs cursor mismatch is a typed rejection.
    let (status, response) = http_request_with_extra_header(
        address,
        "/api/v1/events/stream?workspace=00000000-0000-0000-0000-000000000050&workspace_revision=1&location_id=00000000-0000-0000-0000-000000000001&location_revision=1&relative_root=.&after=3",
        ("last-event-id", "2"),
    )
    .await?;
    assert_eq!(status, 400);
    assert_error_code(&response, ErrorCode::InvalidInput)?;
    let shutdown = state.shutdown(Duration::from_millis(100)).await;
    assert!(shutdown.is_successful());
    let mut tail = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut tail)).await??;
    let tail = String::from_utf8_lossy(&tail);
    assert_eq!(
        tail.matches("server shutdown; reconnect and resume from your cursor")
            .count(),
        1,
        "shutdown emits one terminal SSE frame"
    );
    Ok(())
}

async fn http_request_with_extra_header(
    address: std::net::SocketAddr,
    path: &str,
    header: (&str, &str),
) -> Result<(u16, String), Box<dyn std::error::Error>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(address).await?;
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {SECRET}\r\n{}: {}\r\nConnection: close\r\n\r\n",
        header.0, header.1
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(Box::<dyn std::error::Error>::from)?;
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .map_err(Box::<dyn std::error::Error>::from)?;
    let text = String::from_utf8_lossy(&response).into_owned();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|status| status.parse::<u16>().ok())
        .unwrap_or(0);
    Ok((status, text))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inflight_saturation_and_shutdown_phase_order() -> Result<(), Box<dyn std::error::Error>> {
    let executor = fake_executor(1, QueueBehavior::Stall);
    let events = Arc::new(StaticEvents {
        events: Vec::new(),
        retained_low: 0,
        unknown_workspace: std::sync::atomic::AtomicBool::new(false),
    });
    let state = AppState::new(
        config(0)?,
        Arc::clone(&executor) as Arc<dyn CommandExecutor>,
        events,
    );
    let address = serve(state.clone()).await?;
    assert_eq!(state.phase(), ShutdownPhase::Admitting);

    // Phase 1: admission stopped; new requests rejected while the listener
    // is still alive.
    state.stop_admission();
    let (status, response) = http_request(
        address,
        "GET",
        &format!("/api/v1/events?{}", scope_query()),
        Some(SECRET),
        None,
    )
    .await?;
    assert_eq!(status, 503);
    assert_error_code(&response, ErrorCode::CapacityExceeded)?;

    // Saturate the single queue slot, then observe the immediate typed
    // CapacityExceeded (no waiting).
    let stalled = forge_backend::parse_command(
        forge_backend::CommandOp::GoalRead,
        Uuid::from_u128(0x21),
        &serde_json::json!({
            "scope": {"workspace_id": WORKSPACE, "workspace_revision": 1,
                "locator": {"location_id": Uuid::from_u128(1), "expected_revision": 1, "relative_root": "."}},
            "activity_id": Uuid::from_u128(2),
            "goal_id": Uuid::from_u128(3),
        }),
    )?;
    {
        let executor_ref: &dyn CommandExecutor = executor.as_ref();
        let first = executor_ref.submit(stalled.clone())?;
        let _first = first;
        let second = executor_ref.submit(stalled);
        assert!(
            second.is_err(),
            "saturated queue must reject the second submit"
        );
        let Err(error) = second else {
            return Ok(());
        };
        assert_eq!(error.code(), ErrorCode::CapacityExceeded);
        assert!(error.retryable());
    }

    // Phases 2..4: stream close, bounded inflight drain, worker join. The
    // graceful shutdown then closes the listener, so any later connect is
    // expected to fail.
    let shutdown = state.shutdown(Duration::from_millis(100)).await;
    assert_eq!(shutdown.bridge.pending_commands, 0);
    assert_eq!(shutdown.bridge.pending_workers, 0);
    assert_eq!(shutdown.pending_event_tasks, 0);
    assert_eq!(shutdown.server, ServerJoinState::Joined);
    assert!(shutdown.is_complete());
    assert!(
        shutdown.is_successful(),
        "stalled command was never admitted to a worker"
    );
    assert_eq!(state.phase(), ShutdownPhase::Join);
    assert!(
        tokio::net::TcpStream::connect(address).await.is_err(),
        "joined server task must close the listener"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn capability_and_health_shape() -> Result<(), Box<dyn std::error::Error>> {
    let executor = fake_executor(1, QueueBehavior::Stall);
    let (address, state) = spawn_server(
        executor,
        Arc::new(StaticEvents {
            events: Vec::new(),
            retained_low: 0,
            unknown_workspace: std::sync::atomic::AtomicBool::new(false),
        }),
    )
    .await?;
    assert!(matches!(serve(state.clone()).await,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists));
    let (status, _) = http_request(address, "GET", "/healthz", None, None).await?;
    assert_eq!(status, 200);
    let (status, response) = http_request(address, "GET", "/api/v1/capability", None, None).await?;
    assert_eq!(status, 200);
    let capability: serde_json::Value = serde_json::from_str(body_of(&response).as_str())?;
    assert_eq!(capability["forge_api"], 1);
    let Some(ops) = capability["supported_ops"].as_array() else {
        return Err("capability must list supported ops".into());
    };
    assert!(ops.len() >= 10);
    for operation in [
        "activity.expired_successor_recovery_probe",
        "activity.expired_successor_recover",
        "activity.expired_successor_recovery_get",
        "activity.unstarted_continuation_probe",
        "activity.unstarted_continuation_run",
        "activity.unstarted_continuation_get",
        "agent.binding.reject",
        "agent.binding.rejection_get",
    ] {
        assert_eq!(
            ops.iter()
                .filter(|value| value["op"].as_str() == Some(operation))
                .count(),
            1,
            "capability must advertise {operation} exactly once"
        );
    }
    assert!(
        capability["sse"]["slow_consumer"]
            .as_str()
            .is_some_and(|text| text.contains("RESYNC_REQUIRED"))
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn binding_rejection_http_rejects_source_owned_or_unknown_input()
-> Result<(), Box<dyn std::error::Error>> {
    let executor = fake_executor(8, QueueBehavior::Complete);
    let (address, state) = spawn_server(
        Arc::clone(&executor),
        Arc::new(StaticEvents {
            events: Vec::new(),
            retained_low: 0,
            unknown_workspace: std::sync::atomic::AtomicBool::new(false),
        }),
    )
    .await?;
    let mut payload = binding_rejection_payload();
    payload["reserved_at_ms"] = serde_json::json!(30);
    let (status, response) = http_request(
        address,
        "POST",
        "/api/v1/commands/agent.binding.reject",
        Some(SECRET),
        Some(&binding_rejection_envelope(&payload)),
    )
    .await?;
    assert_eq!(status, 400);
    let reply: serde_json::Value = serde_json::from_str(body_of(&response).as_str())?;
    assert_eq!(reply["error"]["code"], "INVALID_INPUT");
    assert_eq!(
        executor.submitted.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "malformed authority input must fail before bridge admission"
    );
    assert!(state.shutdown(Duration::from_secs(2)).await.is_successful());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn binding_rejection_lost_reply_preserves_exact_get_selector()
-> Result<(), Box<dyn std::error::Error>> {
    let state = AppState::new(
        config(0)?.with_command_deadline(Duration::from_millis(20)),
        fake_executor(8, QueueBehavior::Stall),
        Arc::new(StaticEvents {
            events: Vec::new(),
            retained_low: 0,
            unknown_workspace: std::sync::atomic::AtomicBool::new(false),
        }),
    );
    let address = serve(state.clone()).await?;
    let (status, response) = http_request(
        address,
        "POST",
        "/api/v1/commands/agent.binding.reject",
        Some(SECRET),
        Some(&binding_rejection_envelope(&binding_rejection_payload())),
    )
    .await?;
    assert_eq!(status, 202);
    let reply: serde_json::Value = serde_json::from_str(body_of(&response).as_str())?;
    assert_eq!(reply["error"]["code"], "UNKNOWN_OUTCOME");
    assert_eq!(reply["error"]["retryable"], false);
    assert_eq!(
        reply["error"]["readback"]["kind"],
        "agent_binding_rejection"
    );
    assert_eq!(
        reply["error"]["readback"]["workspace_id"],
        Uuid::from_u128(2).to_string()
    );
    assert_eq!(
        reply["error"]["readback"]["destination_id"],
        Uuid::from_u128(7).to_string()
    );
    assert_eq!(
        reply["error"]["readback"]["request_id"],
        Uuid::from_u128(1).to_string()
    );
    assert_eq!(
        reply["error"]["readback"]["session_id"],
        Uuid::from_u128(5).to_string()
    );
    let digest = reply["error"]["readback"]["request_digest"]
        .as_str()
        .ok_or("request digest missing")?;
    assert_eq!(
        digest,
        "1832e23b3d2acab13bda3fc25cfce47e3799fb99704626cc355560523e90e788"
    );
    assert!(state.shutdown(Duration::from_secs(2)).await.is_successful());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expired_activity_recovery_transport_loss_preserves_exact_readback_selector()
-> Result<(), Box<dyn std::error::Error>> {
    let state = AppState::new(
        config(0)?.with_command_deadline(Duration::from_millis(20)),
        fake_executor(8, QueueBehavior::Stall),
        Arc::new(StaticEvents {
            events: Vec::new(),
            retained_low: 0,
            unknown_workspace: std::sync::atomic::AtomicBool::new(false),
        }),
    );
    let address = serve(state.clone()).await?;
    let request_id = Uuid::from_u128(0x0d);
    let payload = serde_json::json!({
        "scope": {
            "workspace_id": "00000000-0000-0000-0000-000000000001",
            "workspace_revision": 1,
            "locator": {
                "location_id": "00000000-0000-0000-0000-000000000002",
                "expected_revision": 1,
                "relative_root": "."
            }
        },
        "request_id": request_id,
        "service": {
            "backend_id": "00000000-0000-0000-0000-000000000009",
            "issuer": "00000000-0000-0000-0000-00000000000a",
            "destination_id": "00000000-0000-0000-0000-000000000008",
            "runtime_instance_id": "00000000-0000-0000-0000-00000000000b"
        },
        "expected_workspace_root_fingerprint": "00000000000000000000000000000000",
        "expected_binding_digest": "11".repeat(32),
        "expected_delegation": {
            "migration_id": "00000000-0000-0000-0000-000000000007",
            "destination_id": "00000000-0000-0000-0000-000000000008",
            "freeze_revision": 1,
            "freeze_created_at_ms": 10,
            "freeze_updated_at_ms": 10,
            "manifest_digest": "22".repeat(32),
            "delegated_at_ms": 11,
            "delegation_digest": "33".repeat(32)
        },
        "probe_observed_at_ms": 20,
        "expected_probe_digest": "44".repeat(32),
        "predecessor": {
            "activity_id": "00000000-0000-0000-0000-000000000003",
            "expected_revision": 1,
            "expected_created_at_ms": 1,
            "expected_updated_at_ms": 2,
            "expected_lease_owner_id": "00000000-0000-0000-0000-000000000004",
            "expected_lease_until_ms": 3,
            "expected_lease_revision": 1
        },
        "successor_activity_id": "00000000-0000-0000-0000-000000000005",
        "initiating_session_id": "00000000-0000-0000-0000-000000000006",
        "principal": {"kind": "trusted_stdio", "token_id": null, "grant_id": null},
        "expected_agent_count": 1,
        "expected_agent_digest": "55".repeat(32),
        "expected_coordinator": null,
        "duration_ms": 1000
    });
    let envelope = serde_json::json!({
        "forge_api": 1,
        "request_id": request_id,
        "op": "activity.expired_successor_recover",
        "payload": payload
    });
    let (status, response) = http_request(
        address,
        "POST",
        "/api/v1/commands/activity.expired_successor_recover",
        Some(SECRET),
        Some(&envelope.to_string()),
    )
    .await?;
    assert_eq!(status, 202);
    let reply: serde_json::Value = serde_json::from_str(body_of(&response).as_str())?;
    assert_eq!(reply["error"]["code"], "UNKNOWN_OUTCOME");
    assert_eq!(reply["error"]["retryable"], false);
    assert_eq!(
        reply["error"]["readback"]["kind"],
        "expired_activity_recovery"
    );
    assert_eq!(
        reply["error"]["readback"]["request_id"],
        serde_json::json!(request_id)
    );
    assert_eq!(
        reply["error"]["readback"]["request_digest"],
        "5e6976c18d2f786607b74e2e652353f29addd8b699eeeeae370dd267f5a5cdf4"
    );
    assert_eq!(
        reply["error"]["readback"]["successor_activity_id"],
        "00000000-0000-0000-0000-000000000005"
    );
    assert!(state.shutdown(Duration::from_secs(2)).await.is_successful());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unstarted_continuation_unknown_outcome_preserves_pre_admission_intent_digest()
-> Result<(), Box<dyn std::error::Error>> {
    let state = AppState::new(
        config(0)?.with_command_deadline(Duration::from_millis(20)),
        fake_executor(8, QueueBehavior::Stall),
        Arc::new(StaticEvents {
            events: Vec::new(),
            retained_low: 0,
            unknown_workspace: std::sync::atomic::AtomicBool::new(false),
        }),
    );
    let address = serve(state.clone()).await?;
    let request_id = Uuid::from_u128(3);
    let envelope = serde_json::json!({
        "forge_api": 1,
        "request_id": request_id,
        "op": "activity.unstarted_continuation_run",
        "payload": unstarted_continuation_payload(request_id),
    });
    let (status, response) = http_request(
        address,
        "POST",
        "/api/v1/commands/activity.unstarted_continuation_run",
        Some(SECRET),
        Some(&envelope.to_string()),
    )
    .await?;
    assert_eq!(status, 202);
    let reply: serde_json::Value = serde_json::from_str(body_of(&response).as_str())?;
    assert_eq!(reply["error"]["code"], "UNKNOWN_OUTCOME");
    assert_eq!(reply["error"]["retryable"], false);
    assert_eq!(
        reply["error"]["readback"]["kind"],
        "unstarted_activity_continuation"
    );
    assert_eq!(
        reply["error"]["readback"]["request_id"],
        request_id.to_string()
    );
    assert_eq!(
        reply["error"]["readback"]["request_digest"],
        "e70d8e43db0806f602dd13b73039ad684058c518ec425c5fa5d9bd22e579ec2d"
    );
    assert_eq!(
        reply["error"]["readback"]["activity_id"],
        Uuid::from_u128(6).to_string()
    );
    assert!(state.shutdown(Duration::from_secs(2)).await.is_successful());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admitted_command_missing_deadline_result_maps_to_unknown_outcome()
-> Result<(), Box<dyn std::error::Error>> {
    let executor = fake_executor(8, QueueBehavior::Stall);
    let (address, _state) = spawn_server(
        executor,
        Arc::new(StaticEvents {
            events: Vec::new(),
            retained_low: 0,
            unknown_workspace: std::sync::atomic::AtomicBool::new(false),
        }),
    )
    .await?;
    let body = envelope_body(
        "goal.read",
        r#"{"scope":{"workspace_id":"00000000-0000-0000-0000-000000000050","workspace_revision":1,"locator":{"location_id":"00000000-0000-0000-0000-000000000001","expected_revision":1,"relative_root":"."}},"activity_id":"00000000-0000-0000-0000-000000000002","goal_id":"00000000-0000-0000-0000-000000000004"}"#,
    );
    let (status, response) = http_request(
        address,
        "POST",
        "/api/v1/commands/goal.read",
        Some(SECRET),
        Some(&body),
    )
    .await?;
    // The command was admitted; the stalled reply after the deadline proves
    // nothing about execution, so the outcome is unknown, never "not run".
    assert_eq!(status, 202);
    let reply: serde_json::Value = serde_json::from_str(body_of(&response).as_str())?;
    assert_eq!(reply["ok"], false);
    assert_eq!(reply["error"]["code"], "UNKNOWN_OUTCOME");
    assert_eq!(reply["error"]["retryable"], false);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admitted_workspace_registration_unknown_outcome_carries_request_readback()
-> Result<(), Box<dyn std::error::Error>> {
    let locator = forge_control::WorkspaceLocator::new(
        forge_domain::LocationId::from_uuid(Uuid::from_u128(0x701)),
        forge_domain::LocationRevision::INITIAL,
        std::path::Path::new("workspace-多字节"),
    )?;
    let locator_wire = locator.encode();
    let proposed_workspace_id = Uuid::from_u128(0x702);
    let expected_root_fingerprint = "0123456789abcdef0123456789abcdef";

    for behavior in [QueueBehavior::Stall, QueueBehavior::CommittedUnconfirmed] {
        let state = AppState::new(
            config(0)?.with_command_deadline(Duration::from_millis(20)),
            fake_executor(8, behavior),
            Arc::new(StaticEvents {
                events: Vec::new(),
                retained_low: 0,
                unknown_workspace: std::sync::atomic::AtomicBool::new(false),
            }),
        );
        let address = serve(state.clone()).await?;
        let payload = serde_json::json!({
            "locator": locator_wire.as_str(),
            "proposed_workspace_id": proposed_workspace_id,
            "expected_root_fingerprint": expected_root_fingerprint,
            "observed_at_ms": 42,
        });
        let body = envelope_body("workspace.register", &payload.to_string());
        let (status, response) = http_request(
            address,
            "POST",
            "/api/v1/commands/workspace.register",
            Some(SECRET),
            Some(&body),
        )
        .await?;
        assert_eq!(status, 202, "registration unknown response: {response}");
        let reply: serde_json::Value = serde_json::from_str(body_of(&response).as_str())?;
        assert_eq!(reply["ok"], false);
        assert_eq!(reply["error"]["code"], "UNKNOWN_OUTCOME");
        assert_eq!(reply["error"]["retryable"], false);
        assert_eq!(reply["error"]["recovery_action"], "read_back");
        // These fields guide a current-state readback; they are not a
        // historical registration receipt or proof that the effect committed.
        assert_eq!(
            reply["error"]["readback"],
            serde_json::json!({
                "kind": "workspace_registration",
                "locator": locator_wire.as_str(),
                "proposed_workspace_id": proposed_workspace_id,
                "expected_root_fingerprint": expected_root_fingerprint,
            })
        );
        assert!(reply["error"]["readback"].get("workspace").is_none());
        assert!(state.shutdown(Duration::from_secs(2)).await.is_successful());
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admitted_mutation_failures_carry_typed_request_readback()
-> Result<(), Box<dyn std::error::Error>> {
    for behavior in [QueueBehavior::Stall, QueueBehavior::CommittedUnconfirmed] {
        assert_mutation_readback(behavior).await?;
    }
    Ok(())
}

async fn assert_mutation_readback(
    behavior: QueueBehavior,
) -> Result<(), Box<dyn std::error::Error>> {
    let executor = fake_executor(8, behavior);
    let state = AppState::new(
        config(0)?.with_command_deadline(Duration::from_millis(20)),
        executor,
        Arc::new(StaticEvents {
            events: Vec::new(),
            retained_low: 0,
            unknown_workspace: std::sync::atomic::AtomicBool::new(false),
        }),
    );
    let address = serve(state.clone()).await?;
    let body = envelope_body("execution.begin", &execution_begin_payload());
    let (status, response) = http_request(
        address,
        "POST",
        "/api/v1/commands/execution.begin",
        Some(SECRET),
        Some(&body),
    )
    .await?;
    assert_eq!(status, 202);
    let reply: serde_json::Value = serde_json::from_str(body_of(&response).as_str())?;
    assert_eq!(reply["error"]["code"], "UNKNOWN_OUTCOME");
    assert_eq!(reply["error"]["readback"]["kind"], "execution");
    assert_eq!(
        reply["error"]["readback"]["execution_id"],
        serde_json::json!(Uuid::from_u128(0x109))
    );
    let execution: serde_json::Value = serde_json::from_str(&execution_begin_payload())?;
    let authority = &execution["authority"];
    assert_activity_close_readback(address, authority).await?;
    let lease_id = Uuid::from_u128(0x201);
    let payload = serde_json::json!({
        "scope": authority["scope"],
        "activity_id": authority["activity"]["activity_id"],
        "actor": {
            "session_id": authority["actor"]["session_id"],
            "principal": authority["actor"]["principal"],
            "agent_id": authority["actor"]["agent_id"],
        },
        "writer_lease_id": lease_id,
        "duration_ms": 1000,
        "scopes": [{"kind":"exact_path", "path_base64":"dGVzdC50eHQ"}],
    });
    let body = envelope_body("writer_lease.acquire", &payload.to_string());
    let (status, response) = http_request(
        address,
        "POST",
        "/api/v1/commands/writer_lease.acquire",
        Some(SECRET),
        Some(&body),
    )
    .await?;
    assert_eq!(status, 202, "lease deadline response: {response}");
    let reply: serde_json::Value = serde_json::from_str(body_of(&response).as_str())?;
    assert_eq!(reply["error"]["readback"]["kind"], "writer_lease");
    assert_eq!(
        reply["error"]["readback"]["writer_lease_id"],
        serde_json::json!(lease_id)
    );
    assert!(reply["error"]["readback"].get("execution_id").is_none());
    assert_source_mutation_readback(address, authority, lease_id).await?;
    assert_planning_readback(address, authority).await?;
    assert_goal_deletion_readback(address, authority).await?;
    let shutdown = state.shutdown(Duration::from_millis(100)).await;
    assert!(shutdown.is_successful());
    Ok(())
}

async fn assert_activity_close_readback(
    address: std::net::SocketAddr,
    authority: &serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let payload = serde_json::json!({"scope":authority["scope"],
        "activity_id":authority["activity"]["activity_id"],
        "runtime_instance_id":authority["activity"]["runtime_instance_id"],"expected_lease_revision":1});
    let body = envelope_body("activity.close", &payload.to_string());
    let (status, response) = http_request(
        address,
        "POST",
        "/api/v1/commands/activity.close",
        Some(SECRET),
        Some(&body),
    )
    .await?;
    let reply: serde_json::Value = serde_json::from_str(body_of(&response).as_str())?;
    assert_eq!(status, 202, "close outcome: {reply}");
    assert_eq!(reply["error"]["code"], "UNKNOWN_OUTCOME");
    assert_eq!(
        reply["error"]["readback"],
        serde_json::json!({"kind":"activity_lifecycle",
        "workspace_id":authority["scope"]["workspace_id"],"activity_id":payload["activity_id"],
        "runtime_instance_id":payload["runtime_instance_id"],"expected_lease_revision":1})
    );
    Ok(())
}

async fn assert_source_mutation_readback(
    address: std::net::SocketAddr,
    authority: &serde_json::Value,
    lease_id: Uuid,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut payload = authority.clone();
    let object = payload
        .as_object_mut()
        .ok_or("authority is not an object")?;
    object.remove("command_id");
    object.remove("execution_id");
    let change_set_id = Uuid::from_u128(0x301);
    let mutation_id = Uuid::from_u128(0x302);
    payload["writer_lease_id"] = serde_json::json!(lease_id);
    payload["expected_writer_lease_revision"] = serde_json::json!(1);
    payload["change_set_id"] = serde_json::json!(change_set_id);
    payload["mutation_id"] = serde_json::json!(mutation_id);
    payload["operation"] = serde_json::json!({
        "kind": "add", "path_base64": "dGVzdC50eHQ", "content": "source\n",
    });
    let body = envelope_body("file.apply_patch", &payload.to_string());
    let (status, response) = http_request(
        address,
        "POST",
        "/api/v1/commands/file.apply_patch",
        Some(SECRET),
        Some(&body),
    )
    .await?;
    assert_eq!(status, 202, "source outcome: {response}");
    let reply: serde_json::Value = serde_json::from_str(&body_of(&response))?;
    assert_eq!(reply["error"]["code"], "UNKNOWN_OUTCOME");
    assert_eq!(reply["error"]["retryable"], false);
    assert_eq!(
        reply["error"]["readback"],
        serde_json::json!({
            "kind": "file_mutation", "workspace_id": authority["scope"]["workspace_id"],
            "activity_id": authority["activity"]["activity_id"],
            "change_set_id": change_set_id, "mutation_id": mutation_id,
        })
    );
    assert_tree_mutation_readback(address, authority, lease_id).await?;
    payload["operation"]["content"] = serde_json::json!("a".repeat(16 * 1024));
    let body = envelope_body("file.apply_patch", &payload.to_string());
    let (status, response) = http_request(
        address,
        "POST",
        "/api/v1/commands/file.apply_patch",
        Some(SECRET),
        Some(&body),
    )
    .await?;
    assert_eq!(
        status, 400,
        "oversized patch must be rejected before admission: {response}"
    );
    let reply: serde_json::Value = serde_json::from_str(&body_of(&response))?;
    assert_eq!(reply["error"]["code"], "INVALID_INPUT");
    Ok(())
}

async fn assert_tree_mutation_readback(
    address: std::net::SocketAddr,
    authority: &serde_json::Value,
    lease_id: Uuid,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut payload = authority.clone();
    let object = payload
        .as_object_mut()
        .ok_or("authority is not an object")?;
    object.remove("command_id");
    object.remove("execution_id");
    let change_set_id = Uuid::from_u128(0x401);
    payload["writer_lease_id"] = serde_json::json!(lease_id);
    payload["expected_writer_lease_revision"] = serde_json::json!(1);
    payload["change_set_id"] = serde_json::json!(change_set_id);
    payload["mutations"] = serde_json::json!([{
        "kind":"create_file", "mutation_id":Uuid::from_u128(1),
        "path_base64":"c3JjL2xpYi5ycw", "content":"one\n",
    }]);
    let body = envelope_body("source_tree.apply", &payload.to_string());
    let (status, response) = http_request(
        address,
        "POST",
        "/api/v1/commands/source_tree.apply",
        Some(SECRET),
        Some(&body),
    )
    .await?;
    assert_eq!(status, 202, "tree outcome: {response}");
    let reply: serde_json::Value = serde_json::from_str(&body_of(&response))?;
    assert_eq!(reply["error"]["code"], "UNKNOWN_OUTCOME");
    assert_eq!(reply["error"]["retryable"], false);
    assert_eq!(
        reply["error"]["readback"],
        serde_json::json!({
            "kind":"tree_change_set", "workspace_id":authority["scope"]["workspace_id"],
            "activity_id":authority["activity"]["activity_id"], "change_set_id":change_set_id,
            // Captured from the old native MCP implementation before extraction.
            "request_digest":"4213614d32ddc2878a250136292ab370e534b27fad0ac1a13aae6d4d40e59d97",
        })
    );
    payload["request_digest"] = serde_json::json!("00".repeat(32));
    let body = envelope_body("source_tree.apply", &payload.to_string());
    let (status, response) = http_request(
        address,
        "POST",
        "/api/v1/commands/source_tree.apply",
        Some(SECRET),
        Some(&body),
    )
    .await?;
    assert_eq!(
        status, 400,
        "caller-supplied digest must be rejected: {response}"
    );
    Ok(())
}

async fn assert_planning_readback(
    address: std::net::SocketAddr,
    authority: &serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let planning = serde_json::json!({
        "scope":authority["scope"], "activity_id":authority["activity"]["activity_id"],
        "actor":{"session_id":authority["actor"]["session_id"],"principal":authority["actor"]["principal"],
            "agent_id":authority["actor"]["agent_id"],"expected_coordinator_revision":1},
    });
    let goal_id = Uuid::from_u128(0x501);
    let mutation_request_id = Uuid::from_u128(0x502);
    let create = serde_json::json!({
        "authority":planning,"goal_id":goal_id,"mutation_request_id":mutation_request_id,"observed_at_ms":1,
        "contract":{"objective":"Goal unknown outcome","success_criteria":["Keep receipt identity"],
            "constraints":[],"out_of_scope":[],"stop_conditions":[],"verification_requirements":[]},
    });
    let body = envelope_body("goal.create", &create.to_string());
    let (status, response) = http_request(
        address,
        "POST",
        "/api/v1/commands/goal.create",
        Some(SECRET),
        Some(&body),
    )
    .await?;
    assert_eq!(status, 202, "Goal outcome: {response}");
    let reply: serde_json::Value = serde_json::from_str(&body_of(&response))?;
    let hint = &reply["error"]["readback"];
    assert_eq!(hint["kind"], "goal_mutation");
    assert_eq!(hint["goal_id"], serde_json::json!(goal_id));
    assert_eq!(
        hint["mutation_request_id"],
        serde_json::json!(mutation_request_id)
    );
    assert_eq!(hint["workspace_id"], authority["scope"]["workspace_id"]);
    assert_eq!(hint["activity_id"], authority["activity"]["activity_id"]);
    assert_eq!(hint["request_digest"].as_str().map(str::len), Some(64));
    assert_eq!(reply["error"]["retryable"], false);
    let plan_id = Uuid::from_u128(0x503);
    let plan = serde_json::json!({
        "authority":planning,"goal_id":goal_id,"plan_request_id":plan_id,"expected_goal_revision":1,
        "observed_at_ms":1,"history_update_id":Uuid::from_u128(0x504),"history_update_sequence":1,
        "draft":{"revision_id":Uuid::from_u128(0x505),"dag_revision":1,"edges":[],"lineage":[],
            "nodes":[{"node_id":Uuid::from_u128(0x506),"ordinal":0,"title":"Plan","objective":"Keep identity",
                "acceptance":["Observe receipt"],"lifecycle":{"state":"pending"}}]},
    });
    let body = envelope_body("dag.plan_commit", &plan.to_string());
    let (status, response) = http_request(
        address,
        "POST",
        "/api/v1/commands/dag.plan_commit",
        Some(SECRET),
        Some(&body),
    )
    .await?;
    assert_eq!(status, 202, "DAG outcome: {response}");
    let reply: serde_json::Value = serde_json::from_str(&body_of(&response))?;
    let hint = &reply["error"]["readback"];
    assert_eq!(hint["kind"], "dag_plan");
    assert_eq!(hint["goal_id"], serde_json::json!(goal_id));
    assert_eq!(hint["plan_request_id"], serde_json::json!(plan_id));
    assert_eq!(hint["workspace_id"], authority["scope"]["workspace_id"]);
    assert_eq!(hint["activity_id"], authority["activity"]["activity_id"]);
    assert_eq!(hint["draft_digest"].as_str().map(str::len), Some(64));
    assert_eq!(reply["error"]["retryable"], false);
    Ok(())
}

async fn assert_goal_deletion_readback(
    address: std::net::SocketAddr,
    authority: &serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let goal_id = Uuid::from_u128(0x601);
    let payload = serde_json::json!({
        "authority": {
            "scope":authority["scope"], "activity_id":authority["activity"]["activity_id"],
            "actor":{"session_id":authority["actor"]["session_id"],"principal":authority["actor"]["principal"],
                "agent_id":authority["actor"]["agent_id"],"expected_coordinator_revision":1}
        },
        "target":"goal", "goal_id":goal_id, "goal_created_at_ms":11,
        "expected_goal_revision":2, "expected_dag_head_revision":3, "observed_at_ms":12
    });
    let body = envelope_body("goal.delete", &payload.to_string());
    let (status, response) = http_request(
        address,
        "POST",
        "/api/v1/commands/goal.delete",
        Some(SECRET),
        Some(&body),
    )
    .await?;
    assert_eq!(status, 202, "Goal deletion unknown: {response}");
    let reply: serde_json::Value = serde_json::from_str(&body_of(&response))?;
    assert_eq!(reply["error"]["retryable"], false);
    assert_eq!(
        reply["error"]["readback"],
        serde_json::json!({
            "kind":"goal_deletion", "workspace_id":authority["scope"]["workspace_id"],
            "activity_id":authority["activity"]["activity_id"],"goal_id":goal_id,
            "target":"goal", "goal_created_at_ms":11,"expected_goal_revision":2,"expected_dag_head_revision":3
        })
    );
    Ok(())
}

/// Cancellation is a control instruction: while the command bridge is fully
/// saturated (and rejects ordinary commands with a typed capacity error), an
/// execution.cancel must still reach the execution coordinator through the
/// dedicated fast lane.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(
    clippy::too_many_lines,
    reason = "One linear saturation/bypass proof keeps the assertion order reviewable."
)]
async fn execution_cancel_takes_the_fast_lane_when_the_bridge_is_saturated()
-> Result<(), Box<dyn std::error::Error>> {
    use std::sync::atomic::AtomicBool;

    let root = std::env::temp_dir().join(format!(
        "heterarchy-forge-cancel-fast-lane-{}",
        Uuid::now_v7()
    ));
    std::fs::create_dir_all(&root)?;
    let registry = forge_persistence::GlobalRegistry::open(root.join("registry.sqlite3"))?;
    let (control_client, mut control_worker) =
        forge_control::ForgeControlWorker::start(forge_control::ForgeControl::new(registry))?;
    let mut execution = forge_control::ForgeExecutionCoordinator::start(control_client.clone(), 2)?;

    let executor = fake_executor(1, QueueBehavior::Stall);
    let events = Arc::new(StaticEvents {
        events: Vec::new(),
        retained_low: 0,
        unknown_workspace: AtomicBool::new(false),
    });
    let state = AppState::new(
        config(0)?,
        Arc::clone(&executor) as Arc<dyn CommandExecutor>,
        events,
    );
    state.set_execution_fast_lane(Arc::new(execution.client()));
    let address = serve(state.clone()).await?;

    // Saturate the single bridge slot with a stalled command.
    let stalled = tokio::spawn(async move {
        http_request(
            address,
            "POST",
            "/api/v1/commands/location.list",
            Some(SECRET),
            Some(&envelope_body("location.list", "{}")),
        )
        .await
        .map_err(|error| error.to_string())
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let (status, response) = http_request(
        address,
        "POST",
        "/api/v1/commands/location.list",
        Some(SECRET),
        Some(&envelope_body("location.list", "{}")),
    )
    .await?;
    assert_eq!(status, 503, "the saturated bridge must reject: {response}");
    assert_error_code(&response, ErrorCode::CapacityExceeded)?;

    // The cancel bypasses the bridge and reaches the coordinator; the
    // unknown session surfaces as a typed control failure, never as the
    // bridge's capacity rejection.
    let cancel_payload = serde_json::json!({
        "scope": {
            "workspace_id": WORKSPACE,
            "workspace_revision": 1,
            "locator": {
                "location_id": Uuid::from_u128(1),
                "expected_revision": 1,
                "relative_root": "."
            }
        },
        "activity": {
            "activity_id": Uuid::from_u128(2),
            "runtime_instance_id": Uuid::from_u128(3),
            "observed_at_ms": 1
        },
        "actor": {
            "session_id": Uuid::from_u128(4),
            "principal": {"kind": "trusted_stdio"},
            "workspace_id": WORKSPACE,
            "agent_id": Uuid::from_u128(5),
            "expected_revision": 1
        },
        "goal_id": Uuid::from_u128(6),
        "expected_goal_revision": 1,
        "expected_dag_revision": 1,
        "node_id": Uuid::from_u128(7),
        "expected_node_revision": 1,
        "command_id": "cancel-fast-lane-proof",
        "execution_id": Uuid::from_u128(8)
    });
    let (status, response) = http_request(
        address,
        "POST",
        "/api/v1/commands/execution.cancel",
        Some(SECRET),
        Some(&envelope_body(
            "execution.cancel",
            &cancel_payload.to_string(),
        )),
    )
    .await?;
    assert_ne!(
        status, 503,
        "the cancel fast lane must bypass the saturated bridge: {response}"
    );
    let cancel_reply: serde_json::Value = serde_json::from_str(body_of(&response).as_str())?;
    assert_ne!(
        cancel_reply["error"]["code"].as_str().unwrap_or_default(),
        "CAPACITY_EXCEEDED"
    );

    // Release the stalled command, then drain every owner.
    drop(executor);
    let (stalled_status, _) = stalled
        .await
        .map_err(|_| "stalled request task panicked")?
        .map_err(|error| -> Box<dyn std::error::Error> { error.into() })?;
    assert_eq!(stalled_status, 202);
    let shutdown = state.shutdown(Duration::from_secs(5)).await;
    assert!(shutdown.is_successful(), "backend shutdown incomplete");
    let _execution_report = execution.shutdown()?;
    control_worker.shutdown()?;
    std::fs::remove_dir_all(root)?;
    Ok(())
}
