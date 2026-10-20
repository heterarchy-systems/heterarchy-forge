//! Router composition, endpoint handlers, and the fixed shutdown order.
//!
//! Shutdown phases (design contract A5, fixed order):
//! 1. `StopAdmission` — reject new commands and subscribers immediately.
//! 2. `CloseStreams` — SSE streams observe the phase and emit a normal close.
//! 3. `CancelInflight` — bounded drain of admitted bridge commands.
//! 4. `Join` — the server task and bridge workers are joined by the owner.
//!
//! The order is observable through [`ShutdownPhase`] and covered by a test.

mod execution_cancel;
mod execution_wait;
mod ingress;
mod listener;
mod shutdown;
#[cfg(test)]
mod tests;
mod workspace_stop;

pub use listener::HttpConnectionStats;
pub use shutdown::{ServerJoinState, ShutdownReport};

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::rejection::JsonRejection;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::auth::IssuerAuth;
use crate::bridge::ControlBridge;
use crate::bridge::{BridgeOutcome, CommandExecutor};
use crate::config::BackendConfig;
use crate::envelope::{Reply, RequestEnvelope};
use crate::error::ForgeError;
use crate::events::{self, EventQuery, Frame, SubscriberGuard};
use crate::ops::{CommandOp, LocatorDto, ScopeDto, parse_command};

/// Observable shutdown phases.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ShutdownPhase {
    /// Phase 0: normal serving.
    Admitting,
    /// Phase 1: admission stopped; new commands/subscribers rejected.
    StopAdmission,
    /// Phase 2: SSE streams closing with a normal-close frame.
    CloseStreams,
    /// Phase 3: inflight commands draining with a bounded timeout.
    CancelInflight,
    /// Phase 4: every tracked event task, server, and bridge worker has exited.
    Join,
}

/// Application state: composition projection only.
#[derive(Debug, Clone)]
pub struct AppState {
    config: Arc<BackendConfig>,
    issuer: Arc<IssuerAuth>,
    executor: Arc<dyn CommandExecutor>,
    events: Arc<dyn EventQuery>,
    /// Production-only readiness probe over the control worker. Tests that
    /// substitute a fake executor leave this unset; `/readyz` then reports
    /// not-ready with an explicit reason instead of guessing.
    probe: std::sync::OnceLock<Arc<forge_control::ForgeControlClient>>,
    /// Production-only fast lane to the execution coordinator. Cancellation
    /// must not queue behind a saturated command bridge while the child
    /// process keeps running. Unset in fake-executor tests.
    execution_fast_lane: std::sync::OnceLock<Arc<forge_control::ForgeExecutionCoordinatorClient>>,
    workspace_stop_owner: std::sync::OnceLock<Arc<workspace_stop::Owner>>,
    stop_permits: Arc<tokio::sync::Semaphore>,
    cancel_permits: Arc<tokio::sync::Semaphore>,
    /// Per-process boot identity distinguishing restarts of the same
    /// configured backend. Unset in fake-executor tests.
    runtime_instance: std::sync::OnceLock<Uuid>,
    ready_probe: Arc<tokio::sync::Semaphore>,
    ready_cache: Arc<std::sync::Mutex<Option<(std::time::Instant, bool, String)>>>,
    event_reads: Arc<tokio::sync::Semaphore>,
    execution_waits: Arc<tokio::sync::Semaphore>,
    subscribers: Arc<tokio::sync::Semaphore>,
    phase: Arc<std::sync::RwLock<ShutdownPhase>>,
    shutdown: CancellationToken,
    server_task: Arc<tokio::sync::Mutex<shutdown::OwnedServer>>,
    shutdown_task: Arc<tokio::sync::Mutex<shutdown::ShutdownTask>>,
    event_tasks: tokio_util::task::TaskTracker,
    connection_metrics: Arc<listener::ConnectionMetrics>,
}

impl AppState {
    pub fn new(
        config: BackendConfig,
        executor: Arc<dyn CommandExecutor>,
        events: Arc<dyn EventQuery>,
    ) -> Self {
        Self {
            execution_waits: Arc::new(tokio::sync::Semaphore::new(
                config.max_inflight_commands().min(16),
            )),
            subscribers: Arc::new(tokio::sync::Semaphore::new(config.max_sse_subscribers())),
            issuer: Arc::new(config.issuer_auth().clone()),
            phase: Arc::new(std::sync::RwLock::new(ShutdownPhase::Admitting)),
            shutdown: CancellationToken::new(),
            server_task: Arc::new(tokio::sync::Mutex::new(shutdown::OwnedServer::default())),
            shutdown_task: Arc::new(tokio::sync::Mutex::new(None)),
            event_tasks: tokio_util::task::TaskTracker::new(),
            connection_metrics: Arc::new(listener::ConnectionMetrics::default()),
            config: Arc::new(config),
            executor,
            events,
            probe: std::sync::OnceLock::new(),
            execution_fast_lane: std::sync::OnceLock::new(),
            workspace_stop_owner: std::sync::OnceLock::new(),
            stop_permits: Arc::new(tokio::sync::Semaphore::new(workspace_stop::STOP_PERMITS)),
            cancel_permits: Arc::new(tokio::sync::Semaphore::new(
                execution_cancel::CANCEL_FAST_LANE_PERMITS,
            )),
            runtime_instance: std::sync::OnceLock::new(),
            ready_probe: Arc::new(tokio::sync::Semaphore::new(1)),
            ready_cache: Arc::new(std::sync::Mutex::new(None)),
            event_reads: Arc::new(tokio::sync::Semaphore::new(crate::events::MAX_EVENT_READS)),
        }
    }

    fn acquire_event_read(&self) -> Result<tokio::sync::OwnedSemaphorePermit, ForgeError> {
        self.event_reads
            .clone()
            .try_acquire_owned()
            .map_err(|_| ForgeError::capacity_exceeded("semantic event read admission"))
    }

    fn admission_read(&self) -> Result<std::sync::RwLockReadGuard<'_, ShutdownPhase>, ForgeError> {
        let guard = self.phase.read().map_err(|_| ForgeError::internal())?;
        if *guard != ShutdownPhase::Admitting {
            return Err(ForgeError::capacity_exceeded(
                "admission boundary (shutting down)",
            ));
        }
        Ok(guard)
    }

    pub fn config(&self) -> &BackendConfig {
        self.config.as_ref()
    }

    pub fn http_connection_stats(&self) -> HttpConnectionStats {
        self.connection_metrics.snapshot()
    }

    pub fn phase(&self) -> ShutdownPhase {
        self.phase
            .read()
            .map_or(ShutdownPhase::Join, |phase| *phase)
    }

    fn set_phase(&self, phase: ShutdownPhase) {
        if let Ok(mut guard) = self.phase.write()
            && phase > *guard
        {
            *guard = phase;
        }
    }

    pub fn shutdown_token(&self) -> CancellationToken {
        self.shutdown.clone()
    }

    /// Phase 1 alone: stop admission without tearing down the listener.
    pub fn stop_admission(&self) {
        self.set_phase(ShutdownPhase::StopAdmission);
        self.executor.stop_admission();
    }

    pub fn set_probe(&self, probe: Arc<forge_control::ForgeControlClient>) {
        let _set_once = self.probe.set(probe);
    }

    pub fn set_execution_fast_lane(
        &self,
        execution: Arc<forge_control::ForgeExecutionCoordinatorClient>,
    ) {
        let _set_once = self.execution_fast_lane.set(execution);
    }

    pub fn set_runtime_instance(&self, runtime_instance: Uuid) {
        let _set_once = self.runtime_instance.set(runtime_instance);
    }
}

/// Compose the router. Health is unauthenticated liveness; readiness is an
/// unauthenticated bounded control-worker probe; capability is unauthenticated
/// static info; every other route requires the issuer bearer.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/api/v1/capability", get(capability))
        .route("/api/v1/commands/{op}", post(commands))
        .route("/api/v1/events", get(events_page))
        .route("/api/v1/snapshot", get(snapshot))
        .route("/api/v1/events/stream", get(events_stream))
        .layer(axum::extract::DefaultBodyLimit::max(
            crate::config::MAX_BODY_BYTES,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            ingress::acquire_body,
        ))
        .with_state(state)
}

/// Bind and serve on the configured loopback address. Returns the bound
/// address so tests can target the real listener.
///
/// # Errors
/// Fails when the listener cannot bind.
pub async fn serve(state: AppState) -> Result<SocketAddr, std::io::Error> {
    let mut server_slot = state.server_task.lock().await;
    if server_slot.task.is_some() || state.phase() != ShutdownPhase::Admitting {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "backend listener is already owned or admission is closed",
        ));
    }
    let address = SocketAddr::new(state.config().bind_ip(), state.config().port());
    let listener = tokio::net::TcpListener::bind(address).await?;
    let _admission = state.admission_read().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::Interrupted,
            "backend admission closed during listener bind",
        )
    })?;
    let bound = listener.local_addr()?;
    let app = router(state.clone());
    let server_task = tokio::spawn(listener::run(listener, app, state.clone()));
    server_slot.task = Some(server_task);
    server_slot.state = ServerJoinState::Pending;
    Ok(bound)
}

/// Assemble transport over the provided control authority and bounded workers.
/// The host must inject its selected session authority into that control owner.
///
/// # Errors
/// Fails when a bridge worker thread cannot be spawned.
#[derive(Debug, Clone, Copy)]
pub struct BackendClients<'a> {
    pub control: &'a forge_control::ForgeControlClient,
    pub execution: &'a forge_control::ForgeExecutionCoordinatorClient,
    pub approval: &'a forge_control::ForgeApprovalCoordinatorClient,
    pub activity_leases: &'a forge_control::ActivityLeaseClient,
    pub runtime_instance_id: Uuid,
    pub product_cache_root: &'a std::path::Path,
    pub destination_id: Uuid,
}

pub fn assemble(
    config: BackendConfig,
    clients: BackendClients<'_>,
) -> Result<AppState, std::io::Error> {
    let BackendClients {
        control: client,
        execution,
        approval,
        activity_leases,
        runtime_instance_id,
        product_cache_root,
        destination_id,
    } = clients;
    let lease_bridge = crate::lease_bridge::ActivityLeaseBridge::start(activity_leases)?;
    let bridge = ControlBridge::start(
        client,
        execution,
        approval,
        forge_domain::RuntimeInstanceId::from_uuid(runtime_instance_id),
        &config,
        product_cache_root,
        destination_id,
    )?;
    let events = Arc::new(crate::events::ControlEventQuery::new(client.clone()));
    let executor =
        crate::lease_bridge::RoutingExecutor::new(Arc::new(bridge), Arc::new(lease_bridge));
    let stop_service = forge_control::WorkspaceStopServiceIdentity::new(
        config.backend_id(),
        config.issuer(),
        destination_id,
        forge_domain::RuntimeInstanceId::from_uuid(runtime_instance_id),
    )
    .map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Workspace stop service identity is invalid",
        )
    })?;
    let state = AppState::new(config, Arc::new(executor), events);
    let _stop_owner = state
        .workspace_stop_owner
        .set(Arc::new(workspace_stop::Owner::new(
            stop_service,
            approval.clone(),
        )));
    state.set_probe(Arc::new(client.clone()));
    state.set_execution_fast_lane(Arc::new(execution.clone()));
    state.set_runtime_instance(runtime_instance_id);
    Ok(state)
}

/// The exact request-scoped auth check. Returns the typed failure reply.
fn authorize(state: &AppState, headers: &HeaderMap) -> Result<(), Box<Response>> {
    if state.phase() != ShutdownPhase::Admitting {
        return Err(Box::new(reject(
            None,
            &ForgeError::capacity_exceeded("admission boundary (shutting down)"),
        )));
    }
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    if !state.issuer.verify_bearer(bearer) {
        return Err(Box::new(reject(None, &ForgeError::auth_failed())));
    }
    Ok(())
}

fn reject(request_id: Option<Uuid>, error: &ForgeError) -> Response {
    let request_id = request_id.unwrap_or_else(Uuid::nil);
    let reply = Reply::failure(request_id, error);
    let status = match error.code() {
        crate::error::ErrorCode::AuthFailed | crate::error::ErrorCode::InvalidInput => {
            StatusCode::BAD_REQUEST
        }
        crate::error::ErrorCode::CapacityExceeded
        | crate::error::ErrorCode::DependencyUnavailable => StatusCode::SERVICE_UNAVAILABLE,
        crate::error::ErrorCode::UnknownOutcome => StatusCode::ACCEPTED,
        crate::error::ErrorCode::ForgeUnavailable
        | crate::error::ErrorCode::WorkspaceConfinementDenied
        | crate::error::ErrorCode::WorkspaceScopeOverlap
        | crate::error::ErrorCode::WorkspaceRootConflict
        | crate::error::ErrorCode::WorkspaceIdentityConflict
        | crate::error::ErrorCode::WorkspaceRemovalBlocked
        | crate::error::ErrorCode::InvalidPathKind
        | crate::error::ErrorCode::StaleRevision
        | crate::error::ErrorCode::LeaseConflict
        | crate::error::ErrorCode::PlanningConflict
        | crate::error::ErrorCode::SourceConflict
        | crate::error::ErrorCode::ResyncRequired => StatusCode::CONFLICT,
    };
    (status, Json(reply)).into_response()
}

fn ok(request_id: Uuid, result: serde_json::Value) -> Response {
    (StatusCode::OK, Json(Reply::success(request_id, result))).into_response()
}

async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

/// Bounded readiness probe budget. A control worker that cannot answer one
/// trivial read within this budget is not ready to serve commands.
const READY_PROBE_BUDGET: std::time::Duration = std::time::Duration::from_secs(2);

/// How long a cached probe answer may stand in while a new probe is in
/// flight; past this age a saturated probe boundary reports not-ready.
const READY_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(5);

/// Readiness: liveness plus one real bounded control-worker read. Unlike
/// `/healthz`, a failing control dependency fails readiness while liveness
/// stays true, so Orchestration outage never removes the process from
/// supervision — only from traffic.
async fn readyz(State(state): State<AppState>) -> Response {
    if state.phase() != ShutdownPhase::Admitting {
        return readyz_body(false, "the backend is shutting down", None);
    }
    let Some(probe) = state.probe.get() else {
        return readyz_body(
            false,
            "the readiness probe is not configured for this instance",
            None,
        );
    };
    // One probe at a time; concurrent callers fall back to a fresh cached
    // answer so the control worker cannot be probed into saturation.
    let probe_admission = {
        // Serialize admission with shutdown so a late probe cannot appear
        // after the root owner has closed and drained its task tracker.
        let Ok(_admission) = state.admission_read() else {
            return readyz_body(false, "the backend is shutting down", None);
        };
        state
            .ready_probe
            .clone()
            .try_acquire_owned()
            .map(|permit| (permit, state.event_tasks.token()))
    };
    let Ok((permit, task_token)) = probe_admission else {
        let cached = state.ready_cache.lock().ok().and_then(|cache| {
            cache
                .as_ref()
                .map(|(at, ready, detail)| (*at, *ready, detail.clone()))
        });
        return match cached {
            Some((at, ready, detail)) if at.elapsed() < READY_CACHE_TTL => {
                readyz_body(ready, &detail, Some(at))
            }
            _ => readyz_body(false, "readiness probe is busy", None),
        };
    };
    let probe = Arc::clone(probe);
    let attempt = tokio::time::timeout(
        READY_PROBE_BUDGET,
        tokio::task::spawn_blocking(move || {
            // A timeout or disconnected observer cannot cancel blocking
            // control work. Retain capacity and root ownership until it ends.
            let (_permit, _task_token) = (permit, task_token);
            probe.location_list()
        }),
    )
    .await;
    let (ready, detail) = match attempt {
        Ok(Ok(Ok(_))) => (true, "control worker answered".to_owned()),
        Ok(Ok(Err(error))) => {
            let mapped = ForgeError::from_control_client_error(&error);
            (
                false,
                format!("{}: {}", mapped.code().as_str(), mapped.message()),
            )
        }
        Ok(Err(_)) => (false, "the readiness probe task failed".to_owned()),
        Err(_) => (
            false,
            "the control worker did not answer within the readiness budget".to_owned(),
        ),
    };
    let started = std::time::Instant::now();
    if let Ok(mut cache) = state.ready_cache.lock() {
        *cache = Some((started, ready, detail.clone()));
    }
    readyz_body(ready, &detail, Some(started))
}

fn readyz_body(ready: bool, detail: &str, observed_at: Option<std::time::Instant>) -> Response {
    let body = json!({
        "ready": ready,
        "checks": {
            "control_worker": {
                "ready": ready,
                "detail": detail,
                "observed_age_ms": observed_at
                    .map(|at| u64::try_from(at.elapsed().as_millis()).unwrap_or(u64::MAX)),
            },
        },
    });
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, Json(body)).into_response()
}

/// Static, unauthenticated capability document: version, ops, SSE policy
/// constants. No mutable or scoped state is exposed here.
async fn capability(State(state): State<AppState>) -> Response {
    let body = json!({
        "forge_api": crate::config::FORGE_API_VERSION,
        "http_bounds": {
            "max_connections": state.config.http_connection_limit(),
            "max_header_bytes": crate::config::MAX_HTTP_HEADER_BYTES,
            "max_headers": crate::config::MAX_HTTP_HEADERS,
            "max_body_bytes": crate::config::MAX_BODY_BYTES,
            "input_deadline_ms": state.config.http_input_deadline().as_millis(),
            "write_idle_deadline_ms": listener::WRITE_IDLE_DEADLINE.as_millis(),
            "overload": "close excess connection before request admission",
        },
        "runtime_instance": state.runtime_instance.get(),
        "execution": {"rust_ci_available":state.execution_fast_lane.get().map(|execution|execution.rust_ci_available())},
        "supported_ops": CommandOp::ALL
            .iter()
            .map(|op| json!({
                "op": op.as_str(),
                "session_bound": op.requires_session_authority(),
            }))
            .collect::<Vec<_>>(),
        "sse": {
            "event_id": "semantic sequence",
            "last_event_id_header": "Last-Event-ID",
            "keepalive": "cursor-neutral comment frame",
            "slow_consumer": "bounded buffer; overflow closes with a final RESYNC_REQUIRED hint",
            "poll_interval_ms": crate::config::DEFAULT_SSE_POLL_INTERVAL.as_millis(),
        },
        "execution_cancel": {
            "fast_lane_permits": execution_cancel::CANCEL_FAST_LANE_PERMITS,
            "bypasses_command_queue": true,
        },
        "workspace_stop": {
            "fast_lane_permits": workspace_stop::STOP_PERMITS,
            "bypasses_command_queue": true,
            "durable_status": "pending until exact native settlement",
        },
        "bounds": {
            "max_body_bytes": crate::config::MAX_BODY_BYTES,
            "max_event_page_rows": crate::config::MAX_EVENT_PAGE_ROWS,
        },
    });
    (StatusCode::OK, Json(body)).into_response()
}

async fn commands(
    State(state): State<AppState>,
    headers: HeaderMap,
    PathOp { op }: PathOp,
    body: Result<Json<RequestEnvelope>, JsonRejection>,
) -> Response {
    if let Err(response) = authorize(&state, &headers) {
        return *response;
    }
    let Json(envelope) = match body {
        Ok(body) => body,
        Err(rejection) => {
            return reject(None, &ForgeError::invalid_input(rejection.body_text()));
        }
    };
    let request_id = envelope.request_id;
    if !envelope.version_ok() {
        return reject(
            Some(request_id),
            &ForgeError::invalid_input(format!(
                "forge_api must be {}",
                crate::config::FORGE_API_VERSION
            )),
        );
    }
    // Canonical op resolution: URL op must equal the body op, pre-admission.
    if envelope.op != op {
        return reject(
            Some(request_id),
            &ForgeError::invalid_input("URL op and body op must match"),
        );
    }
    let Some(op_code) = CommandOp::parse(op.as_str()) else {
        return reject(
            Some(request_id),
            &ForgeError::invalid_input(format!("unsupported op {op}")),
        );
    };
    let command = match parse_command(op_code, request_id, &envelope.payload) {
        Ok(command) => command,
        Err(error) => return reject(Some(request_id), &error),
    };
    if let crate::ops::Command::ExecutionWait { request, .. } = &command {
        return execution_wait::handle(&state, request_id, request).await;
    }
    // Cancellation is a control instruction: it takes the dedicated
    // coordinator fast lane and never queues behind the command bridge.
    if let crate::ops::Command::ExecutionCancel { request, .. } = command {
        return execution_cancel::handle(&state, request_id, request).await;
    }
    if let crate::ops::Command::WorkspaceStop { request, .. } = command {
        return workspace_stop::handle(&state, request_id, request).await;
    }
    let readback = command.readback_hint();
    // Admission is the bounded queue submit; the control authority performs
    // current session and exact effect checks on the worker.
    let receiver = {
        let _admission = match state.admission_read() {
            Ok(guard) => guard,
            Err(error) => return reject(Some(request_id), &error),
        };
        match state.executor.submit(command) {
            Ok(receiver) => receiver,
            Err(error) => return reject(Some(request_id), &error),
        }
    };
    let deadline = state.config().command_deadline();
    match tokio::time::timeout(deadline, receiver).await {
        Ok(Ok(BridgeOutcome::Completed(result))) => match result {
            Ok(result) => ok(request_id, result),
            Err(error) if error.code() == crate::error::ErrorCode::UnknownOutcome => {
                let error = error.with_readback(readback);
                reject(Some(request_id), &error)
            }
            Err(error) => reject(Some(request_id), &error),
        },
        // The admitted command owns its durable identity. Neither an unknown
        // bridge result nor a lost reply proves non-execution.
        Ok(Ok(BridgeOutcome::UnknownOutcome) | Err(_)) | Err(_) => {
            let error = ForgeError::unknown_outcome(readback);
            reject(Some(request_id), &error)
        }
    }
}

/// Extractor wrapper for the `{op}` path segment.
#[derive(Debug, Clone)]
struct PathOp {
    op: String,
}

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for PathOp {
    type Rejection = Response;

    #[allow(
        clippy::unused_async_trait_impl,
        reason = "The axum extractor trait is async by contract."
    )]
    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let op = parts
            .uri
            .path()
            .rsplit('/')
            .next()
            .unwrap_or_default()
            .to_owned();
        Ok(Self { op })
    }
}

#[derive(Debug, Deserialize)]
struct ScopeQuery {
    workspace: Uuid,
    workspace_revision: String,
    location_id: Uuid,
    location_revision: String,
    relative_root: String,
}

impl ScopeQuery {
    fn decode(&self) -> Result<forge_control::ResolvedWorkspaceScope, ForgeError> {
        let workspace_revision = self
            .workspace_revision
            .parse::<i64>()
            .map_err(|_| ForgeError::invalid_input("scope workspace revision is invalid"))?;
        let location_revision = self
            .location_revision
            .parse::<i64>()
            .map_err(|_| ForgeError::invalid_input("scope location revision is invalid"))?;
        crate::ops::decode_scope(&ScopeDto {
            workspace_id: self.workspace,
            workspace_revision,
            locator: LocatorDto {
                location_id: self.location_id,
                expected_revision: location_revision,
                relative_root: self.relative_root.clone(),
            },
        })
    }
}

#[derive(Debug, Deserialize)]
struct EventsQuery {
    #[serde(flatten)]
    scope: ScopeQuery,
    after: Option<u64>,
    max: Option<u32>,
}

async fn events_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<EventsQuery>,
) -> Response {
    if let Err(response) = authorize(&state, &headers) {
        return *response;
    }
    let scope = match query.scope.decode() {
        Ok(scope) => scope,
        Err(error) => return reject(Some(Uuid::nil()), &error),
    };
    let max = query.max.unwrap_or(crate::config::MAX_EVENT_PAGE_ROWS);
    let after = query.after.unwrap_or(0);
    let query_source = Arc::clone(&state.events);
    let (permit, task_token) = {
        let _admission = match state.admission_read() {
            Ok(guard) => guard,
            Err(error) => return reject(Some(Uuid::nil()), &error),
        };
        match state.acquire_event_read() {
            Ok(permit) => (permit, state.event_tasks.token()),
            Err(error) => return reject(Some(Uuid::nil()), &error),
        }
    };
    let result = tokio::task::spawn_blocking(move || {
        let (_permit, _task_token) = (permit, task_token);
        events::page_or_resync(query_source.as_ref(), &scope, after, max)
    })
    .await;
    match result {
        Ok(Ok(page)) => ok(Uuid::nil(), events::event_page_json(&page)),
        Ok(Err(error)) => reject(Some(Uuid::nil()), &error),
        Err(_) => reject(Some(Uuid::nil()), &ForgeError::internal()),
    }
}

#[derive(Debug, Deserialize)]
struct SnapshotQuery {
    #[serde(flatten)]
    scope: ScopeQuery,
}

async fn snapshot(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<SnapshotQuery>,
) -> Response {
    if let Err(response) = authorize(&state, &headers) {
        return *response;
    }
    let scope = match query.scope.decode() {
        Ok(scope) => scope,
        Err(error) => return reject(Some(Uuid::nil()), &error),
    };
    let scope_json = match crate::ops::scope_json(&scope) {
        Ok(value) => value,
        Err(error) => return reject(Some(Uuid::nil()), &error),
    };
    let query_source = Arc::clone(&state.events);
    let (permit, task_token) = {
        let _admission = match state.admission_read() {
            Ok(guard) => guard,
            Err(error) => return reject(Some(Uuid::nil()), &error),
        };
        match state.acquire_event_read() {
            Ok(permit) => (permit, state.event_tasks.token()),
            Err(error) => return reject(Some(Uuid::nil()), &error),
        }
    };
    let result = tokio::task::spawn_blocking(move || {
        let (_permit, _task_token) = (permit, task_token);
        query_source.snapshot(&scope)
    })
    .await;
    match result {
        Ok(Ok((watermark, retained_low, summary))) => ok(
            Uuid::nil(),
            json!({
                "scope": scope_json,
                "watermark_seq": watermark,
                "retained_low": retained_low,
                "summary": summary,
            }),
        ),
        Ok(Err(crate::events::EventQueryError::UnknownWorkspace)) => reject(
            Some(Uuid::nil()),
            &ForgeError::invalid_input("the requested Workspace is unknown"),
        ),
        Ok(Err(crate::events::EventQueryError::ResyncRequired)) => reject(
            Some(Uuid::nil()),
            &ForgeError::resync_required(
                "the requested Workspace scope is stale; resynchronize from a snapshot",
            ),
        ),
        Ok(Err(crate::events::EventQueryError::CapacityExceeded)) => reject(
            Some(Uuid::nil()),
            &ForgeError::capacity_exceeded("semantic event read admission"),
        ),
        Ok(Err(crate::events::EventQueryError::Failed)) | Err(_) => {
            reject(Some(Uuid::nil()), &ForgeError::internal())
        }
    }
}

#[derive(Debug, Deserialize)]
struct StreamQuery {
    #[serde(flatten)]
    scope: ScopeQuery,
    after: Option<u64>,
}

async fn events_stream(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<StreamQuery>,
) -> Response {
    if let Err(response) = authorize(&state, &headers) {
        return *response;
    }
    let scope = match query.scope.decode() {
        Ok(scope) => scope,
        Err(error) => return reject(Some(Uuid::nil()), &error),
    };
    // Subscriber bound: typed saturation before any stream work.
    let (guard, task_token) = {
        let _admission = match state.admission_read() {
            Ok(guard) => guard,
            Err(error) => return reject(Some(Uuid::nil()), &error),
        };
        match SubscriberGuard::acquire(
            state.subscribers.clone(),
            state.config().max_sse_subscribers(),
        ) {
            Ok(guard) => (guard, state.event_tasks.token()),
            Err(error) => return reject(Some(Uuid::nil()), &error),
        }
    };
    let header_cursor = headers
        .get("last-event-id")
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    let cursor = match events::validate_cursor_pair(header_cursor.as_deref(), query.after) {
        Ok(cursor) => cursor.unwrap_or(0),
        Err(error) => return reject(Some(Uuid::nil()), &error),
    };
    let query_source = Arc::clone(&state.events);
    let poll_interval = state.config().sse_poll_interval();
    let phase = state.phase.clone();
    let (frames, receiver) = tokio::sync::mpsc::channel::<Frame>(16);
    let poller_exit = state.shutdown.child_token();
    let poller_exit_stream = poller_exit.clone();
    let poller_exit_reader = poller_exit.clone();
    // One owned blocking poller per admitted subscriber, bounded by the
    // subscriber semaphore above.
    let poller_exit_worker = poller_exit_reader.clone();
    let poller = tokio::task::spawn_blocking(move || {
        let (_guard, _task_token) = (guard, task_token);
        let exit = move || poller_exit_worker.is_cancelled();
        events::replay_and_tail(
            query_source.as_ref(),
            &scope,
            cursor,
            frames,
            poll_interval,
            &exit,
        )
    });
    let stream = SseStream {
        receiver,
        cancelled: Box::pin(poller_exit_stream.clone().cancelled_owned()),
        exit: poller_exit_stream,
        phase: std::sync::Arc::clone(&phase),
        poller: Some(poller),
        terminal_emitted: false,
    };
    let response = Sse::new(stream)
        .keep_alive(
            KeepAlive::new()
                .interval(std::time::Duration::from_secs(15))
                .text("keepalive"),
        )
        .into_response();
    let mut response = response;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    response
}

/// The response-side stream. Maps bounded frames to SSE events and observes
/// the shutdown phase for the normal close. Wake-aware over the bounded
/// channel; never blocks the executor.
struct SseStream {
    receiver: tokio::sync::mpsc::Receiver<Frame>,
    exit: CancellationToken,
    cancelled: std::pin::Pin<Box<tokio_util::sync::WaitForCancellationFutureOwned>>,
    phase: Arc<std::sync::RwLock<ShutdownPhase>>,
    poller: Option<tokio::task::JoinHandle<events::StreamEnd>>,
    terminal_emitted: bool,
}

impl futures_core::Stream for SseStream {
    type Item = Result<SseEvent, std::convert::Infallible>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        use std::future::Future;

        if self.terminal_emitted {
            return self.as_mut().get_mut().poll_poller(cx);
        }

        if self.phase() >= ShutdownPhase::CloseStreams
            || self.cancelled.as_mut().poll(cx).is_ready()
        {
            self.exit.cancel();
            self.terminal_emitted = true;
            return std::task::Poll::Ready(Some(Ok(SseEvent::default()
                .comment("server shutdown; reconnect and resume from your cursor"))));
        }
        match std::pin::Pin::new(&mut self.receiver).poll_recv(cx) {
            std::task::Poll::Ready(Some(Frame::Event { sequence, data })) => {
                std::task::Poll::Ready(Some(Ok(SseEvent::default()
                    .id(sequence.to_string())
                    .data(data))))
            }
            // Cursor-neutral: no id and no data on keepalive frames.
            std::task::Poll::Ready(Some(Frame::KeepAlive)) => {
                std::task::Poll::Ready(Some(Ok(SseEvent::default().comment("keepalive"))))
            }
            std::task::Poll::Ready(Some(Frame::Resync(hint))) => {
                self.exit.cancel();
                self.terminal_emitted = true;
                std::task::Poll::Ready(Some(Ok(SseEvent::default()
                    .event("resync")
                    .data(serde_json::to_string(&hint).unwrap_or_default()))))
            }
            std::task::Poll::Ready(None) => {
                self.exit.cancel();
                self.terminal_emitted = true;
                self.as_mut().get_mut().poll_poller(cx)
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

impl SseStream {
    fn poll_poller(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<SseEvent, std::convert::Infallible>>> {
        use std::future::Future;

        let Some(poller) = self.poller.as_mut() else {
            return std::task::Poll::Ready(None);
        };
        match std::pin::Pin::new(poller).poll(cx) {
            std::task::Poll::Ready(_) => {
                self.poller = None;
                std::task::Poll::Ready(None)
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }

    fn phase(&self) -> ShutdownPhase {
        self.phase
            .read()
            .map_or(ShutdownPhase::Join, |phase| *phase)
    }
}

impl Drop for SseStream {
    fn drop(&mut self) {
        self.exit.cancel();
    }
}
