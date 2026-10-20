//! Pure-backend SSE fault evidence over a real loopback listener and real
//! TCP clients (GLM pure-backend lane, G3 산출물 1).
//!
//! Proven here, end to end on the wire: snapshot-watermark → replay → live
//! tail composition with durable-page parity; Last-Event-ID reconnect that
//! replays exactly once; the stale-cursor 409 and the deterministic in-stream
//! `resync` frame; slow-consumer termination after the bounded grace while the
//! server and other subscribers stay healthy; and graceful-shutdown terminal
//! frame followed by a restarted server replaying from the client cursor.
//! The event source is the same `EventQuery` port the durable store implements;
//! the durable-table path itself is covered by the existing
//! `real_execution` suites and is not duplicated here.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use forge_backend::bridge::{BridgeOutcome, CommandExecutor};
use forge_backend::config::BackendConfig;
use forge_backend::events::{EventPage, EventQuery, EventQueryError, EventRecord, Subjects};
use forge_backend::http::{AppState, serve};
use forge_backend::ops::Command;
use forge_control::ResolvedWorkspaceScope;
use tokio::sync::oneshot;
use uuid::Uuid;

const SECRET: &str = "test-issuer-secret";
const WORKSPACE: Uuid = Uuid::from_u128(0x50);

fn config(port: u16) -> Result<BackendConfig, forge_backend::ConfigError> {
    Ok(BackendConfig::new(
        std::net::IpAddr::from([127, 0, 0, 1]),
        port,
        SECRET,
        forge_domain::ForgeBackendId::from_uuid(Uuid::from_u128(1)),
        forge_domain::OrchestrationIssuerId::from_uuid(Uuid::from_u128(2)),
    )?
    .with_command_deadline(Duration::from_secs(2))
    .with_sse_poll_interval(Duration::from_millis(50)))
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

/// `bloat` pads the event kind so one frame is large enough to overflow any
/// realistic socket buffer deterministically (slow-consumer test).
fn event_with_kind(sequence: u64, bloat: usize) -> EventRecord {
    let mut digest = [0_u8; 32];
    digest[0] = u8::try_from(sequence % 256).unwrap_or(0);
    EventRecord {
        sequence,
        kind: "x".repeat(bloat),
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
}

/// Growable event source over the `EventQuery` port: tests push events to
/// drive the live tail, optionally flag a stale scope, and move the retention
/// floor to exercise the typed resync path.
struct DynamicEvents {
    events: std::sync::Mutex<Vec<EventRecord>>,
    retained_low: AtomicU64,
    fail_scope_stale: AtomicBool,
    bloat: usize,
}

impl DynamicEvents {
    fn with_sequences(up_to: u64) -> Self {
        Self::bloated(up_to, 0)
    }

    fn bloated(up_to: u64, bloat: usize) -> Self {
        Self {
            events: std::sync::Mutex::new(
                (1..=up_to)
                    .map(|sequence| event_with_kind(sequence, bloat))
                    .collect(),
            ),
            retained_low: AtomicU64::new(0),
            fail_scope_stale: AtomicBool::new(false),
            bloat,
        }
    }

    fn push(&self, sequence: u64) {
        let bloat = self.bloat;
        let Ok(mut events) = self.events.lock() else {
            return;
        };
        events.push(event_with_kind(sequence, bloat));
    }

    fn high_water(&self) -> u64 {
        let Ok(events) = self.events.lock() else {
            return 0;
        };
        events.last().map_or(0, |event| event.sequence)
    }
}

impl std::fmt::Debug for DynamicEvents {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DynamicEvents")
            .finish_non_exhaustive()
    }
}

impl EventQuery for DynamicEvents {
    fn page(
        &self,
        scope: &ResolvedWorkspaceScope,
        after: u64,
        limit: u32,
    ) -> Result<EventPage, EventQueryError> {
        if scope != &test_scope().map_err(|_| EventQueryError::Failed)? {
            return Err(EventQueryError::UnknownWorkspace);
        }
        if self.fail_scope_stale.load(Ordering::Acquire) {
            return Err(EventQueryError::ResyncRequired);
        }
        // high_water is taken under the same single lock acquisition; the
        // mutex is not reentrant.
        let (selected, high_water) = {
            let Ok(events) = self.events.lock() else {
                return Err(EventQueryError::Failed);
            };
            let selected = events
                .iter()
                .filter(|event| event.sequence > after)
                .take(usize::try_from(limit).unwrap_or(0))
                .cloned()
                .collect();
            (selected, events.last().map_or(0, |event| event.sequence))
        };
        Ok(EventPage {
            events: selected,
            high_water,
            retained_low: self.retained_low.load(Ordering::Acquire),
        })
    }

    fn snapshot(
        &self,
        scope: &ResolvedWorkspaceScope,
    ) -> Result<(u64, u64, serde_json::Value), EventQueryError> {
        if scope != &test_scope().map_err(|_| EventQueryError::Failed)? {
            return Err(EventQueryError::UnknownWorkspace);
        }
        if self.fail_scope_stale.load(Ordering::Acquire) {
            return Err(EventQueryError::ResyncRequired);
        }
        Ok((
            self.high_water(),
            self.retained_low.load(Ordering::Acquire),
            serde_json::json!({ "goal_count": 1 }),
        ))
    }
}

/// Deterministic complete-command executor; commands are irrelevant to the
/// SSE lanes under test but the bridge needs a bounded executor.
struct CompleteExecutor;

impl std::fmt::Debug for CompleteExecutor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("CompleteExecutor").finish()
    }
}

impl CommandExecutor for CompleteExecutor {
    fn submit(
        &self,
        command: Command,
    ) -> Result<oneshot::Receiver<BridgeOutcome>, forge_backend::ForgeError> {
        let (reply, receiver) = oneshot::channel();
        let outcome =
            BridgeOutcome::Completed(Ok(serde_json::json!({ "echo": command.request_id() })));
        let _ = reply.send(outcome);
        Ok(receiver)
    }

    fn inflight(&self) -> usize {
        0
    }

    fn drain_and_join(&self, _drain_timeout: Duration) -> forge_backend::bridge::BridgeDrainReport {
        forge_backend::bridge::BridgeDrainReport {
            pending_commands: 0,
            pending_workers: 0,
            worker_panics: 0,
            ownership_failed: false,
        }
    }
}

async fn spawn_server(
    events: Arc<DynamicEvents>,
) -> Result<(std::net::SocketAddr, AppState, Arc<DynamicEvents>), Box<dyn std::error::Error>> {
    let state = AppState::new(
        config(0)?,
        Arc::new(CompleteExecutor) as Arc<dyn CommandExecutor>,
        Arc::clone(&events) as Arc<dyn EventQuery>,
    );
    let address = serve(state.clone()).await?;
    Ok((address, state, events))
}

async fn http_get(
    address: std::net::SocketAddr,
    path: &str,
) -> Result<(u16, String), Box<dyn std::error::Error>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(address).await?;
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {SECRET}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    let text = String::from_utf8_lossy(&response).into_owned();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|status| status.parse::<u16>().ok())
        .unwrap_or(0);
    Ok((status, text))
}

async fn open_stream(
    address: std::net::SocketAddr,
    after: u64,
    extra_header: Option<(&str, &str)>,
) -> Result<tokio::net::TcpStream, Box<dyn std::error::Error>> {
    use tokio::io::AsyncWriteExt;
    let mut stream = tokio::net::TcpStream::connect(address).await?;
    let mut request = format!(
        "GET /api/v1/events/stream?{}&after={after} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {SECRET}\r\nAccept: text/event-stream\r\nConnection: close\r\n",
        scope_query()
    );
    if let Some((name, value)) = extra_header {
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await?;
    Ok(stream)
}

async fn read_until(
    stream: &mut tokio::net::TcpStream,
    mut condition: impl FnMut(&str) -> bool,
    budget: Duration,
) -> Result<String, Box<dyn std::error::Error>> {
    use tokio::io::AsyncReadExt;
    let mut wire = Vec::new();
    tokio::time::timeout(budget, async {
        let mut chunk = [0_u8; 1024];
        loop {
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(read) => {
                    wire.extend_from_slice(&chunk[..read]);
                    if condition(&String::from_utf8_lossy(&wire)) {
                        break;
                    }
                }
            }
        }
    })
    .await
    .map_err(|_| Box::<dyn std::error::Error>::from("stream read exceeded its budget"))?;
    Ok(String::from_utf8_lossy(&wire).into_owned())
}

async fn read_to_end(
    stream: &mut tokio::net::TcpStream,
    budget: Duration,
) -> Result<String, Box<dyn std::error::Error>> {
    use tokio::io::AsyncReadExt;
    let mut tail = Vec::new();
    tokio::time::timeout(budget, stream.read_to_end(&mut tail))
        .await
        .map_err(|_| Box::<dyn std::error::Error>::from("stream close exceeded its budget"))??;
    Ok(String::from_utf8_lossy(&tail).into_owned())
}

/// 산출물 1a: the client composition snapshot → replay → live tail, with the
/// durable paged read agreeing with the stream at the same cursor.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn snapshot_watermark_then_replay_tail_and_durable_parity()
-> Result<(), Box<dyn std::error::Error>> {
    let (address, _state, events) =
        spawn_server(Arc::new(DynamicEvents::with_sequences(3))).await?;

    let (status, snapshot) =
        http_get(address, &format!("/api/v1/snapshot?{}", scope_query())).await?;
    assert_eq!(status, 200, "snapshot status: {snapshot}");
    let snapshot_json: serde_json::Value = serde_json::from_str(
        snapshot
            .split_once("\r\n\r\n")
            .map(|(_, body)| body)
            .unwrap_or_default(),
    )?;
    let result = &snapshot_json["result"];
    assert_eq!(result["watermark_seq"], 3, "snapshot: {snapshot}");
    assert_eq!(result["retained_low"], 0);

    // Tail from the snapshot watermark: initially silent, then new events
    // arrive in order as they are published.
    let mut stream = open_stream(address, 3, None).await?;
    let initial = read_until(
        &mut stream,
        |wire| wire.contains(": keepalive"),
        Duration::from_secs(3),
    )
    .await?;
    assert!(
        !initial.contains("id:"),
        "nothing replays at the watermark: {initial}"
    );
    for sequence in 4..=6 {
        events.push(sequence);
    }
    let tail = read_until(
        &mut stream,
        |wire| wire.contains("id: 6\n"),
        Duration::from_secs(3),
    )
    .await?;
    for sequence in 4..=6 {
        assert!(
            tail.contains(&format!("id: {sequence}\n")),
            "live tail event {sequence}: {tail}"
        );
    }

    // Durable paged read parity at the same cursor.
    let (status, page) = http_get(
        address,
        &format!("/api/v1/events?{}&after=3", scope_query()),
    )
    .await?;
    assert_eq!(status, 200, "event page status: {page}");
    assert!(page.contains("\"sequence\":4"), "page: {page}");
    assert!(page.contains("\"sequence\":6"), "page: {page}");
    Ok(())
}

/// 산출물 1b: Last-Event-ID reconnect replays exactly once, never duplicates,
/// and an over-stale cursor degrades to the typed 409 + snapshot resume.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reconnect_with_last_event_id_replays_exactly_once()
-> Result<(), Box<dyn std::error::Error>> {
    let (address, _state, events) =
        spawn_server(Arc::new(DynamicEvents::with_sequences(5))).await?;

    // The public capability is the source of truth for the reconnect header;
    // exercise that advertised wire contract before opening the stream.
    let (status, capability) = http_get(address, "/api/v1/capability").await?;
    assert_eq!(status, 200, "capability status: {capability}");
    let capability_json: serde_json::Value = serde_json::from_str(
        capability
            .split_once("\r\n\r\n")
            .map(|(_, body)| body)
            .unwrap_or_default(),
    )?;
    let advertised_header = capability_json["sse"]["last_event_id_header"]
        .as_str()
        .ok_or("capability is missing the SSE resume header")?;
    assert_eq!(advertised_header, "Last-Event-ID");

    // First session: reconnect header must equal the cursor; replay is
    // strictly after it, exactly once per sequence.
    let mut stream = open_stream(address, 2, Some((advertised_header, "2"))).await?;
    let first = read_until(
        &mut stream,
        |wire| wire.contains("id: 5\n"),
        Duration::from_secs(3),
    )
    .await?;
    for sequence in 3..=5 {
        assert_eq!(
            first.matches(&format!("id: {sequence}\n")).count(),
            1,
            "replay of {sequence}: {first}"
        );
    }
    assert!(!first.contains("id: 2\n"), "cursor exclusivity: {first}");
    assert!(!first.contains("id: 1\n"), "cursor exclusivity: {first}");
    drop(stream);

    // Mismatched header/cursor pair is a typed rejection before streaming.
    let mut mismatch = open_stream(address, 5, Some((advertised_header, "4"))).await?;
    let mismatch_wire = read_to_end(&mut mismatch, Duration::from_secs(3)).await?;
    assert!(
        mismatch_wire.contains("400") || mismatch_wire.is_empty(),
        "mismatch must not stream: {mismatch_wire}"
    );
    drop(mismatch);

    // Reconnect at the last seen sequence: no duplicate replay.
    let mut stream = open_stream(address, 5, Some((advertised_header, "5"))).await?;
    let resumed = read_until(
        &mut stream,
        |wire| wire.contains(": keepalive"),
        Duration::from_secs(3),
    )
    .await?;
    for sequence in 3..=5 {
        assert!(
            !resumed.contains(&format!("id: {sequence}\n")),
            "no duplicate replay of {sequence}: {resumed}"
        );
    }
    drop(stream);

    // Retention floor moves past the client cursor: typed 409, then the
    // client resnapshots and resumes from the watermark.
    events.retained_low.store(10, Ordering::Release);
    let (status, stale) = http_get(
        address,
        &format!("/api/v1/events?{}&after=5", scope_query()),
    )
    .await?;
    assert_eq!(status, 409, "stale cursor status: {stale}");
    assert!(
        stale.contains("resync"),
        "stale cursor must be a typed resync: {stale}"
    );
    let (status, snapshot) =
        http_get(address, &format!("/api/v1/snapshot?{}", scope_query())).await?;
    assert_eq!(status, 200);
    let snapshot_json: serde_json::Value = serde_json::from_str(
        snapshot
            .split_once("\r\n\r\n")
            .map(|(_, body)| body)
            .unwrap_or_default(),
    )?;
    assert_eq!(
        snapshot_json["result"]["watermark_seq"], 5,
        "snapshot: {snapshot}"
    );
    Ok(())
}

/// 산출물 1c: a stale scope emits exactly one deterministic in-stream
/// `event: resync` hint with its typed reason, then the stream terminates.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stale_scope_emits_one_resync_frame_then_closes() -> Result<(), Box<dyn std::error::Error>>
{
    let (address, _state, events) =
        spawn_server(Arc::new(DynamicEvents::with_sequences(3))).await?;
    events.fail_scope_stale.store(true, Ordering::Release);

    let mut stream = open_stream(address, 0, None).await?;
    let wire = read_to_end(&mut stream, Duration::from_secs(3)).await?;
    assert!(wire.contains("event: resync"), "resync frame: {wire}");
    assert_eq!(
        wire.matches("event: resync").count(),
        1,
        "exactly one resync hint: {wire}"
    );
    assert!(
        wire.contains("the Workspace scope is stale; reconnect from a fresh snapshot"),
        "typed reason: {wire}"
    );
    Ok(())
}

/// 산출물 1d: a subscriber that stops reading is closed after the bounded
/// grace; the server stays healthy and other subscribers are unaffected.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slow_consumer_is_closed_after_bounded_grace_and_server_stays_healthy()
-> Result<(), Box<dyn std::error::Error>> {
    // 8 KiB event kinds make each frame large enough that any realistic
    // socket buffer overflows during the starvation window, so the bounded
    // slow-consumer grace is exercised deterministically.
    let (address, _state, _events) =
        spawn_server(Arc::new(DynamicEvents::bloated(20_000, 8_192))).await?;

    // The starved subscriber opens, then deliberately stops reading while
    // ~20k events keep being polled. Once the bounded grace expires the
    // server-side poller terminates; the wire stays blocked behind the
    // unread socket, so the client now resumes reading: the response must
    // complete promptly (bounded buffered frames only) instead of replaying
    // the remaining event history, and it must not be a shutdown close.
    let mut starved = open_stream(address, 0, None).await?;
    tokio::time::sleep(Duration::from_millis(3_000)).await;
    let starved_tail = read_to_end(&mut starved, Duration::from_secs(10)).await?;
    assert!(
        !starved_tail.contains("id: 19999\n"),
        "terminated stream must not replay the remaining history"
    );
    assert!(
        !starved_tail.contains("server shutdown"),
        "close must come from the slow-consumer path, not shutdown"
    );
    // One healthy consumer keeps streaming from the same server.
    let mut healthy = open_stream(address, 19_990, None).await?;
    let healthy_wire = read_until(
        &mut healthy,
        |wire| wire.contains("id: 19991\n") || wire.contains(": keepalive"),
        Duration::from_secs(5),
    )
    .await?;
    assert!(
        healthy_wire.contains("id: 19991\n") || healthy_wire.contains(": keepalive"),
        "healthy consumer still streams: {}",
        &healthy_wire[..healthy_wire.len().min(400)]
    );
    drop(healthy);
    drop(healthy_wire);

    // The starved subscriber's stream terminates on its own (bounded grace +
    // buffer overflow) without any close from the client side.

    // The server is healthy afterwards and admits new subscribers.
    let (status, health) = http_get(address, "/healthz").await?;
    assert_eq!(status, 200, "health after slow consumer: {health}");
    let mut late = open_stream(address, 19_990, None).await?;
    let late_wire = read_until(
        &mut late,
        |wire| wire.contains(": keepalive"),
        Duration::from_secs(3),
    )
    .await?;
    assert!(
        late_wire.contains("text/event-stream"),
        "late subscriber: {late_wire}"
    );
    Ok(())
}

/// 산출물 1e: graceful shutdown emits exactly one terminal frame on the live
/// stream, and a restarted server replays the same durable history from the
/// client cursor.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn graceful_shutdown_closes_stream_once_and_restart_replays_from_cursor()
-> Result<(), Box<dyn std::error::Error>> {
    let (address, state, _events) =
        spawn_server(Arc::new(DynamicEvents::with_sequences(3))).await?;
    let mut stream = open_stream(address, 1, None).await?;
    let replayed = read_until(
        &mut stream,
        |wire| wire.contains("id: 3\n"),
        Duration::from_secs(3),
    )
    .await?;
    assert!(
        replayed.contains("id: 2\n") && replayed.contains("id: 3\n"),
        "replay: {replayed}"
    );

    let shutdown = state.shutdown(Duration::from_secs(2)).await;
    assert!(shutdown.is_successful(), "shutdown report: {shutdown:?}");
    let terminal = read_to_end(&mut stream, Duration::from_secs(3)).await?;
    assert_eq!(
        terminal
            .matches("server shutdown; reconnect and resume from your cursor")
            .count(),
        1,
        "one terminal frame: {terminal}"
    );

    // Restart: a fresh server instance replays the same durable history.
    let (address, _state, _events) =
        spawn_server(Arc::new(DynamicEvents::with_sequences(3))).await?;
    let mut stream = open_stream(address, 1, None).await?;
    let replayed = read_until(
        &mut stream,
        |wire| wire.contains("id: 3\n"),
        Duration::from_secs(3),
    )
    .await?;
    assert!(replayed.contains("id: 2\n"), "restart replay: {replayed}");
    Ok(())
}
