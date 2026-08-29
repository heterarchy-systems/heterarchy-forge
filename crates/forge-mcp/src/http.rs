//! Opt-in loopback Streamable HTTP transport with scoped bearer authorization.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::Duration;

use axum::Router;
use axum::extract::{Request, State};
use axum::http::{StatusCode, Uri, header, uri::Authority};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use forge_control::{
    MAX_MCP_TOKEN_BEARER_BYTES, McpTokenAuthorization, McpTokenClient, McpTokenClientError,
    McpTokenWorkerError,
};
pub use forge_domain::McpPublicOrigin;
pub use forge_domain::{McpLocalPort as McpHttpPort, McpPublicBaseError as McpPublicOriginError};
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService, session::never::NeverSessionManager,
};
use thiserror::Error;
use tokio::sync::{Semaphore, oneshot};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::McpTokenBootstrapMode;
use crate::process::{
    McpLeasePolicy, McpServerProcess, McpShutdownReport, finish_tasks, track_owned_leases,
};
use crate::token::{McpTokenRuntime, McpTokenRuntimeError};

pub const MCP_HTTP_MAX_REQUEST_BODY_BYTES: usize = 64 * 1024;
/// Number of synchronous token-authentication jobs admitted at once.
///
/// This is deliberately below the token worker queue capacity.  A request
/// that arrives while all slots are occupied receives `503` instead of
/// creating an unbounded Tokio blocking-pool backlog.
pub const MCP_HTTP_AUTH_BLOCKING_CAPACITY: usize = 4;
/// Maximum time a synchronous desktop start waits for listener readiness.
pub const MCP_HTTP_STARTUP_TIMEOUT: Duration = Duration::from_secs(5);

const _: () = assert!(MCP_HTTP_AUTH_BLOCKING_CAPACITY <= forge_control::MCP_TOKEN_QUEUE_CAPACITY);

/// Default port used by the desktop connection surface.
pub const MCP_HTTP_DEFAULT_PORT: u16 = 7979;

/// Configuration for one loopback MCP listener and an optional public
/// reverse-proxy origin.  The listener remains bound to IPv4 loopback even
/// when a public origin is configured.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpHttpServerConfig {
    port: u16,
    public_origin: Option<McpPublicOrigin>,
}

impl Default for McpHttpServerConfig {
    fn default() -> Self {
        Self::new(MCP_HTTP_DEFAULT_PORT)
    }
}

impl McpHttpServerConfig {
    pub const fn new(port: u16) -> Self {
        Self {
            port,
            public_origin: None,
        }
    }

    pub const fn from_local_port(port: McpHttpPort) -> Self {
        Self::new(port.get())
    }

    pub const fn port(&self) -> u16 {
        self.port
    }

    pub fn with_public_origin(mut self, origin: McpPublicOrigin) -> Self {
        self.public_origin = Some(origin);
        self
    }

    /// Parse and attach a public origin at an adapter boundary.
    pub fn with_public_origin_text(
        self,
        value: impl AsRef<str>,
    ) -> Result<Self, McpPublicOriginError> {
        Ok(self.with_public_origin(McpPublicOrigin::parse(value)?))
    }

    /// Alias for callers that use the shorter connection-settings wording.
    pub fn with_origin(self, origin: McpPublicOrigin) -> Self {
        self.with_public_origin(origin)
    }

    pub const fn public_origin(&self) -> Option<&McpPublicOrigin> {
        self.public_origin.as_ref()
    }
}

impl From<forge_domain::McpConnectionSettings> for McpHttpServerConfig {
    fn from(settings: forge_domain::McpConnectionSettings) -> Self {
        Self::from(&settings)
    }
}

impl From<&forge_domain::McpConnectionSettings> for McpHttpServerConfig {
    fn from(settings: &forge_domain::McpConnectionSettings) -> Self {
        let config = Self::new(settings.local_port().get());
        match settings.public_base() {
            Some(public_base) => config.with_public_origin(public_base.clone()),
            None => config,
        }
    }
}

#[derive(Debug, Clone)]
struct HttpAuthorizationState {
    token_client: McpTokenClient,
    auth_blocking_slots: Arc<Semaphore>,
}

impl HttpAuthorizationState {
    fn new(token_client: McpTokenClient) -> Self {
        Self {
            token_client,
            auth_blocking_slots: Arc::new(Semaphore::new(MCP_HTTP_AUTH_BLOCKING_CAPACITY)),
        }
    }
}

/// Owned running loopback HTTP server.
#[must_use]
#[derive(Debug)]
pub struct McpHttpServerHandle {
    endpoint: String,
    public_endpoint: Option<String>,
    cancellation: CancellationToken,
    join: Option<JoinHandle<Result<McpShutdownReport, McpHttpServerError>>>,
}

impl McpHttpServerHandle {
    pub async fn start(
        control: forge_control::ForgeControlClient,
        token_client: McpTokenClient,
        port: u16,
    ) -> Result<Self, McpHttpServerError> {
        Self::start_with_config(control, token_client, McpHttpServerConfig::new(port)).await
    }

    /// Start the listener with an optional exact public origin.
    pub async fn start_with_config<C>(
        control: forge_control::ForgeControlClient,
        token_client: McpTokenClient,
        config: C,
    ) -> Result<Self, McpHttpServerError>
    where
        C: Into<McpHttpServerConfig>,
    {
        let config = config.into();
        let listener = tokio::net::TcpListener::bind(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            config.port(),
        ))
        .await
        .map_err(McpHttpServerError::Bind)?;
        let address = listener.local_addr().map_err(McpHttpServerError::Bind)?;
        let endpoint = format!("http://{address}/mcp");
        let public_endpoint = config
            .public_origin()
            .map(McpPublicOrigin::endpoint)
            .map(str::to_owned);
        let process = McpServerProcess::scoped_http(control, McpLeasePolicy::default());
        let cancellation = process.cancellation_token();
        let join = tokio::spawn(run_http_server(
            process,
            token_client,
            listener,
            address,
            config,
        ));
        Ok(Self {
            endpoint,
            public_endpoint,
            cancellation,
            join: Some(join),
        })
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn public_endpoint(&self) -> Option<&str> {
        self.public_endpoint.as_deref()
    }

    pub async fn shutdown(mut self) -> Result<McpShutdownReport, McpHttpServerError> {
        self.cancellation.cancel();
        let join = self.join.take().ok_or(McpHttpServerError::AlreadyStopped)?;
        join.await.map_err(McpHttpServerError::Join)?
    }
}

impl Drop for McpHttpServerHandle {
    fn drop(&mut self) {
        self.cancellation.cancel();
        if let Some(join) = self.join.take() {
            join.abort();
        }
    }
}

async fn run_http_server(
    process: McpServerProcess,
    token_client: McpTokenClient,
    listener: tokio::net::TcpListener,
    address: SocketAddr,
    config: McpHttpServerConfig,
) -> Result<McpShutdownReport, McpHttpServerError> {
    let McpServerProcess {
        service,
        cancellation,
        tracker_rx,
        lease_policy,
        mut tasks,
    } = process;
    let tracker_rx = tracker_rx.ok_or(McpHttpServerError::TrackerUnavailable)?;
    let tracker_token = cancellation.child_token();
    let control = service.control_client();
    let runtime_instance_id = service.runtime_instance_id();
    tasks.spawn(track_owned_leases(
        tracker_rx,
        tracker_token,
        control,
        runtime_instance_id,
        lease_policy,
        lease_policy.heartbeat_interval(),
    ));

    let admission = HttpAdmissionPolicy::new(address, config.public_origin());
    let allowed_hosts = admission.allowed_hosts.clone();
    let allowed_origins = admission.allowed_origins.clone();
    let config = StreamableHttpServerConfig::default()
        .with_legacy_session_mode(false)
        .with_json_response(true)
        .with_sse_keep_alive(None)
        .with_allowed_hosts(allowed_hosts)
        .with_allowed_origins(allowed_origins)
        .with_max_request_body_bytes(MCP_HTTP_MAX_REQUEST_BODY_BYTES)
        .with_stateless_protocol_metadata_required(true)
        .with_cancellation_token(cancellation.clone());
    let service_template = service;
    let streamable = StreamableHttpService::new(
        move || Ok(service_template.clone()),
        Arc::new(NeverSessionManager::default()),
        config,
    );
    let authorization = HttpAuthorizationState::new(token_client);
    let router = Router::new()
        .route("/mcp", get(method_not_allowed).post_service(streamable))
        .route_layer(middleware::from_fn_with_state(
            authorization,
            require_bearer,
        ));
    let router = router.route_layer(middleware::from_fn_with_state(
        admission,
        validate_http_admission,
    ));
    let serve = axum::serve(listener, router)
        .with_graceful_shutdown(cancellation.clone().cancelled_owned())
        .await
        .map_err(McpHttpServerError::Serve);
    cancellation.cancel();
    let tracker = finish_tasks(tasks)
        .await
        .map_err(McpHttpServerError::Process);
    serve?;
    tracker
}

async fn require_bearer(
    State(state): State<HttpAuthorizationState>,
    mut request: Request,
    next: Next,
) -> Response {
    let authorization = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .filter(|value| value.len() <= MAX_MCP_TOKEN_BEARER_BYTES)
        .map(str::to_owned);
    let Some(authorization) = authorization else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    match authenticate_bearer(&state, authorization).await {
        Ok(Some(claim)) => {
            request.extensions_mut().insert(claim);
            next.run(request).await
        }
        Ok(None) | Err(BearerAuthenticationError::Invalid) => {
            StatusCode::UNAUTHORIZED.into_response()
        }
        Err(BearerAuthenticationError::Unavailable) => {
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BearerAuthenticationError {
    Invalid,
    Unavailable,
}

async fn authenticate_bearer(
    state: &HttpAuthorizationState,
    authorization: String,
) -> Result<Option<McpTokenAuthorization>, BearerAuthenticationError> {
    let permit = state
        .auth_blocking_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| BearerAuthenticationError::Unavailable)?;
    let client = state.token_client.clone();
    let authenticated = tokio::task::spawn_blocking(move || {
        // Keep the admission permit until the blocking catalog operation has
        // completed.  Dropping it before the join would permit an unbounded
        // blocking-pool backlog under authentication load.
        let _permit = permit;
        client.authenticate(authorization)
    })
    .await
    .map_err(|_| BearerAuthenticationError::Unavailable)?;
    match authenticated {
        Ok(result) => Ok(result),
        Err(
            McpTokenClientError::QueueFull
            | McpTokenClientError::WorkerClosed
            | McpTokenClientError::WorkerShuttingDown
            | McpTokenClientError::ResponseDropped,
        ) => Err(BearerAuthenticationError::Unavailable),
        Err(McpTokenClientError::Service(_)) => Err(BearerAuthenticationError::Invalid),
    }
}

#[derive(Debug, Clone)]
struct HttpAdmissionPolicy {
    allowed_hosts: Vec<String>,
    allowed_origins: Vec<String>,
    public_authority: Option<String>,
    public_origin: Option<String>,
}

impl HttpAdmissionPolicy {
    fn new(address: SocketAddr, public_origin: Option<&McpPublicOrigin>) -> Self {
        let local_authority = address.to_string();
        let local_hosts = [
            local_authority.clone(),
            format!("localhost:{}", address.port()),
            format!("[::1]:{}", address.port()),
        ];
        let local_origins = local_hosts
            .iter()
            .map(|host| format!("http://{host}"))
            .collect::<Vec<_>>();
        let mut allowed_hosts = local_hosts.to_vec();
        let mut allowed_origins = local_origins;
        let (public_authority, public_origin) = if let Some(public_origin) = public_origin {
            let authority = public_origin.host().to_owned();
            let origin = public_origin.origin().to_owned();
            allowed_hosts.push(authority.clone());
            allowed_origins.push(origin.clone());
            (Some(authority), Some(origin))
        } else {
            (None, None)
        };
        Self {
            allowed_hosts,
            allowed_origins,
            public_authority,
            public_origin,
        }
    }

    fn host_allowed(&self, request: &Request) -> bool {
        let Some(host) = request
            .headers()
            .get(header::HOST)
            .and_then(|value| value.to_str().ok())
            .or_else(|| request.uri().authority().map(Authority::as_str))
        else {
            return false;
        };
        canonical_authority_text(host)
            .is_some_and(|host| self.allowed_hosts.iter().any(|allowed| allowed == &host))
    }

    fn origin_allowed(&self, request: &Request) -> bool {
        let Some(origin) = request.headers().get(header::ORIGIN) else {
            return true;
        };
        let Some(origin) = origin.to_str().ok().and_then(canonical_origin_text) else {
            return false;
        };
        let host = request
            .headers()
            .get(header::HOST)
            .and_then(|value| value.to_str().ok())
            .and_then(canonical_authority_text)
            .or_else(|| request.uri().authority().and_then(canonical_authority));
        if let (Some(public_authority), Some(public_origin)) =
            (&self.public_authority, &self.public_origin)
        {
            if host.as_deref() == Some(public_authority) {
                return &origin == public_origin;
            }
            if &origin == public_origin {
                return false;
            }
        }
        self.allowed_origins
            .iter()
            .any(|allowed| allowed == &origin)
    }
}

async fn validate_http_admission(
    State(policy): State<HttpAdmissionPolicy>,
    request: Request,
    next: Next,
) -> Response {
    if !policy.host_allowed(&request) || !policy.origin_allowed(&request) {
        return StatusCode::FORBIDDEN.into_response();
    }
    // Deliberately inspect only the actual Host/Origin headers.  No
    // X-Forwarded-* header is trusted to rewrite the admission identity.
    next.run(request).await
}

fn canonical_authority_text(value: &str) -> Option<String> {
    let authority = Authority::try_from(value).ok()?;
    canonical_authority(&authority)
}

fn canonical_authority(authority: &Authority) -> Option<String> {
    if authority.host().is_empty()
        || authority.port().is_some() && authority.port_u16().is_none()
        || authority.as_str().contains('@')
    {
        return None;
    }
    let host = authority.host().to_ascii_lowercase();
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host
    };
    Some(match authority.port_u16() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    })
}

fn canonical_origin_text(value: &str) -> Option<String> {
    let uri = Uri::try_from(value).ok()?;
    let scheme = uri.scheme_str()?.to_ascii_lowercase();
    if !matches!(uri.path(), "" | "/") || uri.query().is_some() {
        return None;
    }
    let authority = canonical_authority(uri.authority()?)?;
    Some(format!("{scheme}://{authority}"))
}

/// Synchronous owner suitable for the Slint/desktop composition boundary.
///
/// A dedicated thread owns one Tokio runtime, the HTTP task, and the token
/// worker.  Desktop callbacks therefore perform only bounded channel/thread
/// lifecycle operations and never need to construct or block an async runtime
/// on the UI thread.
#[must_use]
#[derive(Debug)]
pub struct McpHttpServerRuntime {
    endpoint: String,
    public_endpoint: Option<String>,
    stop: Option<oneshot::Sender<()>>,
    join: Option<thread::JoinHandle<Result<McpShutdownReport, McpHttpServerRuntimeError>>>,
    token_runtime: Option<McpTokenRuntime>,
}

impl McpHttpServerRuntime {
    /// Start an HTTP server and transfer ownership of the already bootstrapped
    /// token runtime to the dedicated lifecycle thread.
    pub fn start<C>(
        control: forge_control::ForgeControlClient,
        token_runtime: McpTokenRuntime,
        config: C,
    ) -> Result<Self, McpHttpServerRuntimeError>
    where
        C: Into<McpHttpServerConfig>,
    {
        let config = config.into();
        let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
        let (stop_sender, stop_receiver) = oneshot::channel();
        let thread_config = config;
        let token_client = token_runtime.client();
        let join = thread::Builder::new()
            .name("heterarchy-forge-mcp-http".to_owned())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        let _ignored = ready_sender.send(Err(error.to_string()));
                        return Err(McpHttpServerRuntimeError::Runtime(error));
                    }
                };
                runtime.block_on(async move {
                    let server = match McpHttpServerHandle::start_with_config(
                        control,
                        token_client,
                        thread_config,
                    )
                    .await
                    {
                        Ok(server) => server,
                        Err(error) => {
                            let message = error.to_string();
                            let _ignored = ready_sender.send(Err(message));
                            return Err(McpHttpServerRuntimeError::Server(error));
                        }
                    };
                    let endpoints = RuntimeEndpoints {
                        endpoint: server.endpoint().to_owned(),
                        public_endpoint: server.public_endpoint().map(str::to_owned),
                    };
                    if ready_sender.send(Ok(endpoints)).is_err() {
                        let _ignored = server.shutdown().await;
                        return Err(McpHttpServerRuntimeError::StartupChannelClosed);
                    }
                    let _ignored = stop_receiver.await;
                    server
                        .shutdown()
                        .await
                        .map_err(McpHttpServerRuntimeError::Server)
                })
            })
            .map_err(McpHttpServerRuntimeError::ThreadSpawn)?;

        let endpoints = match ready_receiver.recv_timeout(MCP_HTTP_STARTUP_TIMEOUT) {
            Ok(Ok(endpoints)) => endpoints,
            Ok(Err(message)) => {
                let _ignored = stop_sender.send(());
                let _ignored = join.join();
                return Err(McpHttpServerRuntimeError::Startup(message));
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let _ignored = stop_sender.send(());
                let _ignored = join.join();
                return Err(McpHttpServerRuntimeError::StartupTimeout);
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                let _ignored = stop_sender.send(());
                let _ignored = join.join();
                return Err(McpHttpServerRuntimeError::StartupChannelClosed);
            }
        };
        Ok(Self {
            endpoint: endpoints.endpoint,
            public_endpoint: endpoints.public_endpoint,
            stop: Some(stop_sender),
            join: Some(join),
            token_runtime: Some(token_runtime),
        })
    }

    /// Bootstrap the token runtime with the canonical Keychain/catalog policy
    /// and start the owned HTTP lifecycle in one synchronous call.
    pub fn start_with_paths(
        control: forge_control::ForgeControlClient,
        paths: &forge_platform::AppPaths,
        config: McpHttpServerConfig,
        bootstrap_mode: McpTokenBootstrapMode,
    ) -> Result<Self, McpHttpServerRuntimeError> {
        let token_runtime = McpTokenRuntime::start(paths, bootstrap_mode)
            .map_err(McpHttpServerRuntimeError::TokenBootstrap)?;
        Self::start(control, token_runtime, config)
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn public_endpoint(&self) -> Option<&str> {
        self.public_endpoint.as_deref()
    }

    /// Access the bounded token client while this runtime owns its worker.
    pub fn token_client(&self) -> Option<McpTokenClient> {
        self.token_runtime.as_ref().map(McpTokenRuntime::client)
    }

    /// Stop admission, join the HTTP runtime thread, then join the token
    /// worker.  The returned report describes the MCP lease cleanup.
    pub fn stop(mut self) -> Result<McpShutdownReport, McpHttpServerRuntimeError> {
        let _ignored = self.stop.take().map(|sender| sender.send(()));
        let join = self
            .join
            .take()
            .ok_or(McpHttpServerRuntimeError::AlreadyStopped)?;
        let server_result = join
            .join()
            .map_err(|_| McpHttpServerRuntimeError::ThreadJoin)?;
        let mut token_runtime = self
            .token_runtime
            .take()
            .ok_or(McpHttpServerRuntimeError::AlreadyStopped)?;
        let token_result = token_runtime
            .shutdown()
            .map_err(McpHttpServerRuntimeError::TokenWorker);
        match (server_result, token_result) {
            (Ok(report), Ok(())) => Ok(report),
            (Err(server), _) => Err(server),
            (Ok(_), Err(token)) => Err(token),
        }
    }
}

impl Drop for McpHttpServerRuntime {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ignored = stop.send(());
        }
        if let Some(join) = self.join.take() {
            let _ignored = join.join();
        }
        if let Some(mut token_runtime) = self.token_runtime.take() {
            let _ignored = token_runtime.shutdown();
        }
    }
}

/// Compatibility naming for desktop composition callers.
pub type McpHttpServerService = McpHttpServerRuntime;

#[derive(Debug)]
struct RuntimeEndpoints {
    endpoint: String,
    public_endpoint: Option<String>,
}

async fn method_not_allowed() -> StatusCode {
    StatusCode::METHOD_NOT_ALLOWED
}

#[derive(Debug, Error)]
pub enum McpHttpServerError {
    #[error("failed to bind loopback MCP HTTP listener")]
    Bind(#[source] std::io::Error),
    #[error("MCP HTTP lease tracker is unavailable")]
    TrackerUnavailable,
    #[error("MCP HTTP server failed")]
    Serve(#[source] std::io::Error),
    #[error("MCP HTTP task failed to join")]
    Join(#[source] tokio::task::JoinError),
    #[error("MCP HTTP server was already stopped")]
    AlreadyStopped,
    #[error("MCP HTTP process shutdown failed")]
    Process(#[source] crate::McpServerProcessError),
}

/// Failure from the synchronous desktop-facing HTTP lifecycle owner.
#[derive(Debug, Error)]
pub enum McpHttpServerRuntimeError {
    #[error("MCP HTTP runtime startup failed: {0}")]
    Startup(String),
    #[error("MCP HTTP runtime did not become ready before the startup deadline")]
    StartupTimeout,
    #[error("MCP HTTP runtime startup channel closed")]
    StartupChannelClosed,
    #[error("MCP HTTP runtime thread could not be created")]
    ThreadSpawn(#[source] io::Error),
    #[error("MCP HTTP runtime could not start Tokio")]
    Runtime(#[source] io::Error),
    #[error("MCP HTTP server failed")]
    Server(#[source] McpHttpServerError),
    #[error("MCP HTTP runtime thread failed to join")]
    ThreadJoin,
    #[error("MCP token runtime bootstrap failed")]
    TokenBootstrap(#[source] McpTokenRuntimeError),
    #[error("MCP token worker lifecycle failed")]
    TokenWorker(#[source] McpTokenWorkerError),
    #[error("MCP HTTP runtime was already stopped")]
    AlreadyStopped,
}

#[cfg(test)]
mod tests {
    use std::fs;

    use forge_control::{
        AgentDagGrantIssueRequest, ForgeControl, McpTokenIssueRequest, McpTokenService,
        McpTokenWorker,
    };
    use forge_domain::{
        ActivityId, AgentAuthoringCredential, AgentDagAuthoringActor, AgentDagAuthoringGrantId,
        AgentDagAuthoringGrantTtl, AgentInstanceId, DagAcceptanceCriterion, DagHeadRevision,
        DagNodeDefinition, DagNodeId, DagNodeObjective, DagNodeOrdinal, DagNodeTitle, DagRevision,
        DagRevisionId, DagRevisionNumber, EstablishWorkspace, GoalAttribution, GoalContract,
        GoalId, GoalObjective, GoalRevision, GoalStatement, LocationId, LocationRevision,
        McpTokenLabel, McpTokenWorkspaceScope, RegisteredDagNode, RegisteredGoal, TimestampMillis,
        WorkspaceId, WorkspaceRoot,
    };
    use forge_persistence::{GlobalRegistry, McpTokenCatalog, WorkspaceStore};
    use forge_workspace::{LocationService, WorkspaceLocator, WorkspaceStateLayout};
    use serde_json::{Value, json};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use uuid::Uuid;

    use super::*;

    struct SeededHttpWorkspace {
        control: ForgeControl,
        location_id: LocationId,
        workspace_id: WorkspaceId,
        goal_id: GoalId,
        prior_node_id: DagNodeId,
        locator: WorkspaceLocator,
    }

    fn seed_http_workspace(
        root: &std::path::Path,
    ) -> Result<SeededHttpWorkspace, Box<dyn std::error::Error>> {
        let location_root = root.join("location");
        let workspace_root = location_root.join("workspace");
        fs::create_dir_all(&workspace_root)?;
        let registry = GlobalRegistry::open(root.join("registry.sqlite3"))?;
        let mut locations = LocationService::new(registry);
        let location_id = LocationId::from_uuid(Uuid::from_u128(0xE100));
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(0xE101));
        locations.register_selected_path(
            location_id,
            "HTTP Agent Location",
            &location_root,
            TimestampMillis::new(1)?,
        )?;
        let layout = WorkspaceStateLayout::initialize(&workspace_root)?;
        let mut store = WorkspaceStore::open(
            &layout,
            EstablishWorkspace::new(
                workspace_id,
                location_id,
                WorkspaceRoot::from_canonical(layout.workspace_root().to_path_buf())?,
                layout.root_fingerprint()?,
                TimestampMillis::new(2)?,
            ),
        )?;
        let goal_id = GoalId::from_uuid(Uuid::from_u128(0xE102));
        let goal = RegisteredGoal::create(
            goal_id,
            workspace_id,
            GoalContract::new(
                GoalObjective::new("Continue through authenticated HTTP MCP".to_owned())?,
                vec![GoalStatement::new(
                    "One successor DAG is durable".to_owned(),
                )?],
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            )?,
            TimestampMillis::new(3)?,
        );
        let _ = store.insert_goal(&goal)?;
        let prior_node_id = DagNodeId::from_uuid(Uuid::from_u128(0xE103));
        let definition = DagNodeDefinition::new(
            prior_node_id,
            DagNodeOrdinal::new(0)?,
            DagNodeTitle::new("Inspect".to_owned())?,
            DagNodeObjective::new("Inspect the current Goal".to_owned())?,
            vec![DagAcceptanceCriterion::new("Goal is observed".to_owned())?],
        )?;
        let revision = DagRevision::new(
            DagRevisionId::from_uuid(Uuid::from_u128(0xE104)),
            goal_id,
            GoalRevision::INITIAL,
            DagRevisionNumber::INITIAL,
            None,
            vec![definition.clone()],
            Vec::new(),
            TimestampMillis::new(4)?,
        )?;
        let node = RegisteredDagNode::create(
            goal_id,
            DagRevisionNumber::INITIAL,
            definition,
            TimestampMillis::new(4)?,
        );
        let _ = store.insert_dag_revision(&revision, &[node], &[], None)?;
        drop(store);
        let locator = WorkspaceLocator::new(
            location_id,
            LocationRevision::INITIAL,
            std::path::Path::new("workspace"),
        )?;
        Ok(SeededHttpWorkspace {
            control: ForgeControl::from_location_service(locations),
            location_id,
            workspace_id,
            goal_id,
            prior_node_id,
            locator,
        })
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::too_many_lines)]
    async fn loopback_http_requires_bearer_and_serves_exact_tools()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "heterarchy-forge-mcp-http-{}-{}",
            std::process::id(),
            Uuid::now_v7()
        ));
        fs::create_dir_all(&root)?;
        let (control_client, mut control_worker) =
            ForgeControl::new(GlobalRegistry::open(root.join("registry.sqlite3"))?)
                .start_worker()?;
        let token_catalog = McpTokenCatalog::open(root.join("mcp-tokens.sqlite3"))?;
        let token_service = McpTokenService::new([0x5a; 32], token_catalog);
        let (token_client, mut token_worker) = McpTokenWorker::start(token_service)?;
        let location_id = LocationId::from_uuid(Uuid::from_u128(1));
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(2));
        let issued = token_client.issue(McpTokenIssueRequest::new(
            McpTokenLabel::new("HTTP test".to_owned())?,
            vec![McpTokenWorkspaceScope::new(location_id, workspace_id)],
            TimestampMillis::new(1)?,
        )?)?;
        let public_origin = McpPublicOrigin::parse("https://skygptcodex.store")?;
        let server = McpHttpServerHandle::start_with_config(
            control_client,
            token_client,
            McpHttpServerConfig::new(0).with_public_origin(public_origin),
        )
        .await?;
        let endpoint = server.endpoint().to_owned();
        let authority = endpoint
            .strip_prefix("http://")
            .and_then(|value| value.strip_suffix("/mcp"))
            .ok_or("invalid endpoint")?;

        let missing = raw_request(authority, "GET", None, None, None, "").await?;
        assert!(missing.starts_with("HTTP/1.1 401"));

        let bearer = format!("Bearer {}", issued.reveal().as_str());
        let get = raw_request(authority, "GET", Some(&bearer), None, None, "").await?;
        assert!(get.starts_with("HTTP/1.1 405"));

        let wrong = format!("Bearer {}", "A".repeat(43));
        let denied = raw_request(
            authority,
            "POST",
            Some(&wrong),
            None,
            Some("tools/list"),
            "{}",
        )
        .await?;
        assert!(denied.starts_with("HTTP/1.1 401"));

        let tools_body = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"test","version":"1.0"},"io.modelcontextprotocol/clientCapabilities":{}}}}"#;
        let tools = raw_request(
            authority,
            "POST",
            Some(&bearer),
            None,
            Some("tools/list"),
            tools_body,
        )
        .await?;
        assert!(tools.starts_with("HTTP/1.1 200"), "{tools}");
        for name in crate::MCP_TOOL_NAMES {
            assert!(tools.contains(name));
        }

        let public = raw_request_with_host(
            authority,
            "skygptcodex.store",
            "POST",
            Some(&bearer),
            Some("https://skygptcodex.store"),
            Some("tools/list"),
            tools_body,
        )
        .await?;
        assert!(public.starts_with("HTTP/1.1 200"), "{public}");

        let forbidden_origin = raw_request(
            authority,
            "POST",
            Some(&bearer),
            Some("https://example.invalid"),
            Some("tools/list"),
            tools_body,
        )
        .await?;
        assert!(forbidden_origin.starts_with("HTTP/1.1 403"));

        let oversized_body = "x".repeat(MCP_HTTP_MAX_REQUEST_BODY_BYTES + 1);
        let oversized = raw_request(
            authority,
            "POST",
            Some(&bearer),
            None,
            Some("tools/list"),
            &oversized_body,
        )
        .await?;
        assert!(oversized.starts_with("HTTP/1.1 413"));

        let unscoped_body = format!(
            r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"workspace_resolve","arguments":{{"location_id":"{}","expected_revision":1,"workspace_id":"{}","workspace_revision":1,"locator":"invalid"}},"_meta":{{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{{"name":"test","version":"1.0"}},"io.modelcontextprotocol/clientCapabilities":{{}}}}}}}}"#,
            Uuid::from_u128(3),
            Uuid::from_u128(4)
        );
        let unscoped = raw_request(
            authority,
            "POST",
            Some(&bearer),
            None,
            Some("tools/call"),
            &unscoped_body,
        )
        .await?;
        assert!(
            unscoped.contains("outside the authorized Workspace scope"),
            "{unscoped}"
        );

        let report = server.shutdown().await?;
        let _ = report;
        token_worker.shutdown()?;
        control_worker.shutdown()?;
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn zero_credential_http_server_starts_and_rejects_every_request()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "heterarchy-forge-mcp-http-empty-{}-{}",
            std::process::id(),
            Uuid::now_v7()
        ));
        fs::create_dir_all(&root)?;
        let (control_client, mut control_worker) =
            ForgeControl::new(GlobalRegistry::open(root.join("registry.sqlite3"))?)
                .start_worker()?;
        let token_catalog = McpTokenCatalog::open(root.join("mcp-tokens.sqlite3"))?;
        let token_service = McpTokenService::new([0x7c; 32], token_catalog);
        let (token_client, mut token_worker) = McpTokenWorker::start(token_service)?;
        let server = McpHttpServerHandle::start(control_client, token_client, 0).await?;
        let endpoint = server.endpoint().to_owned();
        let authority = endpoint
            .strip_prefix("http://")
            .and_then(|value| value.strip_suffix("/mcp"))
            .ok_or("invalid endpoint")?;

        let missing = raw_request(authority, "GET", None, None, None, "").await?;
        assert!(missing.starts_with("HTTP/1.1 401"), "{missing}");
        let unknown = format!("Bearer {}", "A".repeat(43));
        let denied = raw_request(authority, "GET", Some(&unknown), None, None, "").await?;
        assert!(denied.starts_with("HTTP/1.1 401"), "{denied}");

        server.shutdown().await?;
        token_worker.shutdown()?;
        control_worker.shutdown()?;
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::too_many_lines)]
    async fn http_token_agent_attaches_discovers_grant_and_replans_exactly_once()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "heterarchy-forge-mcp-http-agent-{}-{}",
            std::process::id(),
            Uuid::now_v7()
        ));
        fs::create_dir_all(&root)?;
        let seeded = seed_http_workspace(&root)?;
        let (control_client, mut control_worker) = seeded.control.start_worker()?;
        let assertion_client = control_client.clone();
        let token_catalog = McpTokenCatalog::open(root.join("mcp-tokens.sqlite3"))?;
        let (token_client, mut token_worker) =
            McpTokenWorker::start(McpTokenService::new([0x6b; 32], token_catalog))?;
        let issued = token_client.issue(McpTokenIssueRequest::new(
            McpTokenLabel::new("HTTP Agent E2E".to_owned())?,
            vec![McpTokenWorkspaceScope::new(
                seeded.location_id,
                seeded.workspace_id,
            )],
            TimestampMillis::new(5)?,
        )?)?;
        let server = McpHttpServerHandle::start_with_config(
            control_client,
            token_client,
            McpHttpServerConfig::new(0)
                .with_public_origin(McpPublicOrigin::parse("https://skygptcodex.store")?),
        )
        .await?;
        let authority = server
            .endpoint()
            .strip_prefix("http://")
            .and_then(|value| value.strip_suffix("/mcp"))
            .ok_or("invalid endpoint")?;
        let bearer = format!("Bearer {}", issued.reveal().as_str());
        let locator = seeded.locator.encode();
        let activity_id = ActivityId::from_uuid(Uuid::from_u128(0xE105));

        let bootstrap = raw_tool_call(
            authority,
            &bearer,
            1,
            "activity_bootstrap",
            json!({
                "location_id": seeded.location_id.to_string(),
                "expected_revision": 1,
                "workspace_id": seeded.workspace_id.to_string(),
                "workspace_revision": 1,
                "locator": locator,
                "activity_id": activity_id.to_string()
            }),
        )
        .await?;
        assert!(bootstrap.starts_with("HTTP/1.1 200"), "{bootstrap}");
        assert!(bootstrap.contains("tracked"), "{bootstrap}");

        let attached = raw_tool_call(
            authority,
            &bearer,
            2,
            "agent_attach",
            json!({
                "location_id": seeded.location_id.to_string(),
                "expected_revision": 1,
                "workspace_id": seeded.workspace_id.to_string(),
                "workspace_revision": 1,
                "locator": locator,
                "activity_id": activity_id.to_string(),
                "display_name": "HTTP Planner",
                "declared_role": "planner"
            }),
        )
        .await?;
        assert!(attached.starts_with("HTTP/1.1 200"), "{attached}");
        assert!(attached.contains("streamable_http"), "{attached}");
        let agent_id = response_string_field(&attached, "agentId")
            .ok_or("HTTP Agent response omitted agentId")?
            .parse::<AgentInstanceId>()?;

        let now = crate::process::current_timestamp_millis().ok_or("clock unavailable")?;
        let resolved = assertion_client.resolve_workspace(
            seeded.location_id,
            LocationRevision::INITIAL,
            seeded.locator.clone(),
        )?;
        let grant_id = AgentDagAuthoringGrantId::from_uuid(Uuid::from_u128(0xE106));
        let _grant = assertion_client.agent_dag_grant_issue(AgentDagGrantIssueRequest {
            scope: resolved.clone(),
            grant_id,
            actor: AgentDagAuthoringActor::new(
                seeded.workspace_id,
                agent_id,
                activity_id,
                AgentAuthoringCredential::Token(issued.metadata().id()),
            ),
            goal: GoalAttribution::new(seeded.goal_id, GoalRevision::INITIAL),
            expected_dag_revision: DagRevisionNumber::INITIAL,
            expected_head_revision: DagHeadRevision::INITIAL,
            issued_at: now,
            ttl: AgentDagAuthoringGrantTtl::DEFAULT,
        })?;

        let discovered = raw_tool_call(
            authority,
            &bearer,
            3,
            "dag_authoring_grant_discover",
            json!({
                "location_id": seeded.location_id.to_string(),
                "expected_revision": 1,
                "workspace_id": seeded.workspace_id.to_string(),
                "workspace_revision": 1,
                "locator": locator,
                "activity_id": activity_id.to_string(),
                "agent_id": agent_id.to_string(),
                "goal_id": seeded.goal_id.to_string(),
                "goal_revision": 1,
                "dag_revision": 1,
                "head_revision": 1,
                "observed_at_ms": now.get()
            }),
        )
        .await?;
        assert!(discovered.starts_with("HTTP/1.1 200"), "{discovered}");
        assert!(discovered.contains(&grant_id.to_string()), "{discovered}");

        let successor_id = DagNodeId::from_uuid(Uuid::from_u128(0xE107));
        let replan_arguments = json!({
            "location_id": seeded.location_id.to_string(),
            "expected_revision": 1,
            "workspace_id": seeded.workspace_id.to_string(),
            "workspace_revision": 1,
            "locator": locator,
            "activity_id": activity_id.to_string(),
            "agent_id": agent_id.to_string(),
            "grant_id": grant_id.to_string(),
            "expected_grant_revision": 1,
            "request_id": Uuid::from_u128(0xE108).to_string(),
            "history_update_id": Uuid::from_u128(0xE109).to_string(),
            "history_update_sequence": 1,
            "observed_at_ms": now.get(),
            "draft": {
                "revisionId": Uuid::from_u128(0xE10A).to_string(),
                "goalId": seeded.goal_id.to_string(),
                "goalRevision": 1,
                "dagRevision": 2,
                "parentRevision": 1,
                "nodes": [{
                    "nodeId": successor_id.to_string(),
                    "ordinal": 0,
                    "title": "Continue",
                    "objective": "Continue from the observed Goal",
                    "acceptance": ["Successor revision is durable"],
                    "lifecycle": {"state": "pending"}
                }],
                "edges": [],
                "lineage": [{
                    "priorNodeId": seeded.prior_node_id.to_string(),
                    "successorNodeId": successor_id.to_string(),
                    "kind": "replace"
                }]
            }
        });
        let committed = raw_tool_call(
            authority,
            &bearer,
            4,
            "dag_replan_commit",
            replan_arguments.clone(),
        )
        .await?;
        assert!(committed.starts_with("HTTP/1.1 200"), "{committed}");
        assert!(
            committed.contains("\"committedDagRevision\":2"),
            "{committed}"
        );
        assert!(committed.contains("\"replayed\":false"), "{committed}");

        let replayed =
            raw_tool_call(authority, &bearer, 5, "dag_replan_commit", replan_arguments).await?;
        assert!(replayed.starts_with("HTTP/1.1 200"), "{replayed}");
        assert!(replayed.contains("\"replayed\":true"), "{replayed}");
        assert_eq!(
            assertion_client
                .dag_get_current(resolved, seeded.goal_id)?
                .ok_or("committed HTTP DAG missing")?
                .revision()
                .number()
                .get(),
            2
        );

        let report = server.shutdown().await?;
        assert_eq!(report.tracked_activities(), 1);
        token_worker.shutdown()?;
        control_worker.shutdown()?;
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn public_origin_is_https_only_and_has_a_canonical_endpoint()
    -> Result<(), Box<dyn std::error::Error>> {
        let origin = McpPublicOrigin::parse("HTTPS://Example.COM")?;
        assert_eq!(origin.origin(), "https://example.com");
        assert_eq!(origin.host(), "example.com");
        assert_eq!(origin.endpoint(), "https://example.com/mcp");
        assert!(matches!(
            McpPublicOrigin::parse("http://example.com"),
            Err(McpPublicOriginError::HttpsRequired)
        ));
        assert!(matches!(
            McpPublicOrigin::parse("https://example.com/other"),
            Err(McpPublicOriginError::InvalidPath)
        ));
        assert!(matches!(
            McpPublicOrigin::parse("https://*.example.com"),
            Err(McpPublicOriginError::InvalidHostLabel)
        ));
        assert_eq!(McpHttpServerConfig::default().port(), 7979);
        Ok(())
    }

    #[test]
    fn admission_accepts_exact_public_and_loopback_values_only()
    -> Result<(), Box<dyn std::error::Error>> {
        let origin = McpPublicOrigin::parse("https://skygptcodex.store")?;
        let policy = HttpAdmissionPolicy::new("127.0.0.1:7979".parse()?, Some(&origin));
        assert!(policy.host_allowed(&request("127.0.0.1:7979", None)?));
        assert!(policy.host_allowed(&request("skygptcodex.store", None)?));
        assert!(!policy.host_allowed(&request("skygptcodex.store:8443", None)?));
        assert_eq!(
            canonical_origin_text("https://skygptcodex.store"),
            Some("https://skygptcodex.store".to_owned())
        );
        assert!(policy.origin_allowed(&request(
            "skygptcodex.store",
            Some("https://skygptcodex.store"),
        )?));
        assert!(!policy.origin_allowed(&request(
            "127.0.0.1:7979",
            Some("https://skygptcodex.store"),
        )?));
        assert!(policy.origin_allowed(&request("127.0.0.1:7979", Some("http://localhost:7979"),)?));
        assert!(!policy.origin_allowed(&request(
            "skygptcodex.store",
            Some("https://example.invalid"),
        )?));
        assert!(policy.host_allowed(&request_with_forwarded_host(
            "127.0.0.1:7979",
            "skygptcodex.store",
        )?));
        assert!(!policy.host_allowed(&request_with_forwarded_host(
            "example.invalid",
            "127.0.0.1:7979",
        )?));
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn bearer_authentication_returns_unavailable_when_slots_are_saturated()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "heterarchy-forge-mcp-auth-saturation-{}-{}",
            std::process::id(),
            Uuid::now_v7()
        ));
        fs::create_dir_all(&root)?;
        let catalog = McpTokenCatalog::open(root.join("mcp-tokens.sqlite3"))?;
        let (token_client, token_worker) =
            McpTokenWorker::start(McpTokenService::new([0x5a; 32], catalog))?;
        let state = HttpAuthorizationState::new(token_client);
        let _permits = (0..MCP_HTTP_AUTH_BLOCKING_CAPACITY)
            .map(|_| {
                state
                    .auth_blocking_slots
                    .clone()
                    .try_acquire_owned()
                    .map_err(|_| "admission permit unavailable")
            })
            .collect::<Result<Vec<_>, _>>()?;
        let result = authenticate_bearer(&state, "Bearer invalid".to_owned()).await;
        assert_eq!(result, Err(BearerAuthenticationError::Unavailable));
        drop(state);
        let mut token_worker = token_worker;
        token_worker.shutdown()?;
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn synchronous_runtime_starts_and_joins_owned_http_and_token_workers()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "heterarchy-forge-mcp-runtime-{}-{}",
            std::process::id(),
            Uuid::now_v7()
        ));
        fs::create_dir_all(&root)?;
        let (control_client, mut control_worker) =
            ForgeControl::new(GlobalRegistry::open(root.join("registry.sqlite3"))?)
                .start_worker()?;
        let catalog = McpTokenCatalog::open(root.join("mcp-tokens.sqlite3"))?;
        let (token_client, token_worker) =
            McpTokenWorker::start(McpTokenService::new([0x5a; 32], catalog))?;
        let token_runtime = McpTokenRuntime::from_parts(token_client, token_worker);
        let runtime = McpHttpServerRuntime::start(
            control_client,
            token_runtime,
            McpHttpServerConfig::new(0),
        )?;
        assert!(runtime.endpoint().starts_with("http://127.0.0.1:"));
        assert!(runtime.public_endpoint().is_none());
        let report = runtime.stop()?;
        assert_eq!(report.tracked_activities(), 0);
        control_worker.shutdown()?;
        fs::remove_dir_all(root)?;
        Ok(())
    }

    fn request(host: &str, origin: Option<&str>) -> Result<Request, Box<dyn std::error::Error>> {
        let mut builder = Request::builder().uri("/mcp").header(header::HOST, host);
        if let Some(origin) = origin {
            builder = builder.header(header::ORIGIN, origin);
        }
        Ok(builder.body(axum::body::Body::empty())?)
    }

    fn request_with_forwarded_host(
        host: &str,
        forwarded_host: &str,
    ) -> Result<Request, Box<dyn std::error::Error>> {
        Ok(Request::builder()
            .uri("/mcp")
            .header(header::HOST, host)
            .header("x-forwarded-host", forwarded_host)
            .body(axum::body::Body::empty())?)
    }

    async fn raw_tool_call(
        authority: &str,
        bearer: &str,
        request_id: u64,
        name: &str,
        arguments: Value,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {
                "name": name,
                "arguments": arguments,
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientInfo": {"name": "http-agent-e2e", "version": "1.0"},
                    "io.modelcontextprotocol/clientCapabilities": {}
                }
            }
        })
        .to_string();
        raw_request(
            authority,
            "POST",
            Some(bearer),
            None,
            Some("tools/call"),
            &body,
        )
        .await
    }

    fn response_string_field<'a>(response: &'a str, field: &str) -> Option<&'a str> {
        let marker = format!("\"{field}\":\"");
        let start = response.find(&marker)?.checked_add(marker.len())?;
        let tail = response.get(start..)?;
        let end = tail.find('"')?;
        tail.get(..end)
    }

    async fn raw_request(
        authority: &str,
        method: &str,
        authorization: Option<&str>,
        origin: Option<&str>,
        mcp_method: Option<&str>,
        body: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        raw_request_with_host(
            authority,
            authority,
            method,
            authorization,
            origin,
            mcp_method,
            body,
        )
        .await
    }

    async fn raw_request_with_host(
        authority: &str,
        host: &str,
        method: &str,
        authorization: Option<&str>,
        origin: Option<&str>,
        mcp_method: Option<&str>,
        body: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let mut stream = tokio::net::TcpStream::connect(authority).await?;
        let mut request = format!(
            "{method} /mcp HTTP/1.1\r\nHost: {host}\r\nAccept: application/json, text/event-stream\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
            body.len()
        );
        if method == "POST" {
            request.push_str("MCP-Protocol-Version: 2026-07-28\r\n");
            if let Some(mcp_method) = mcp_method {
                request.push_str("Mcp-Method: ");
                request.push_str(mcp_method);
                request.push_str("\r\n");
                if mcp_method == "tools/call" {
                    let tool_name = serde_json::from_str::<Value>(body)
                        .ok()
                        .and_then(|value| value["params"]["name"].as_str().map(ToOwned::to_owned))
                        .unwrap_or_else(|| "workspace_resolve".to_owned());
                    request.push_str("Mcp-Name: ");
                    request.push_str(&tool_name);
                    request.push_str("\r\n");
                }
            }
        }
        if let Some(authorization) = authorization {
            request.push_str("Authorization: ");
            request.push_str(authorization);
            request.push_str("\r\n");
        }
        if let Some(origin) = origin {
            request.push_str("Origin: ");
            request.push_str(origin);
            request.push_str("\r\n");
        }
        request.push_str("\r\n");
        request.push_str(body);
        stream.write_all(request.as_bytes()).await?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await?;
        Ok(String::from_utf8(response)?)
    }
}
