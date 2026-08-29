//! Bounded single-owner desktop worker for MCP connection configuration.
//!
//! The Slint thread submits typed actions and polls one-shot replies.  This
//! owner is the only desktop component that opens the app-global connection
//! settings catalog, starts the Keychain-backed token worker, or owns the
//! loopback HTTP runtime.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TryRecvError, TrySendError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use forge_control::{
    ForgeControlClient, McpTokenClient, McpTokenClientError, McpTokenIssueRequest, McpTokenIssued,
    McpTokenMetadata, McpTokenRotation,
};
use forge_domain::{
    McpConnectionRevision, McpConnectionSettings, McpLocalPort, McpTokenId, McpTokenRevision,
    RegisteredMcpConnectionSettings, TimestampMillis,
};
use forge_execution::{CloudflarePublicTunnel, CloudflarePublicTunnelError};
use forge_mcp::{
    McpHttpServerConfig, McpHttpServerRuntime, McpHttpServerRuntimeError, McpTokenBootstrapMode,
    McpTokenRuntime, McpTokenRuntimeError,
};
use forge_persistence::{McpConnectionSettingsCatalog, McpConnectionSettingsCatalogError};
use forge_platform::AppPaths;
use thiserror::Error;

const REQUEST_QUEUE_CAPACITY: usize = 8;
const SHUTDOWN_POLL_INTERVAL: Duration = Duration::from_millis(50);
const THREAD_NAME: &str = "heterarchy-forge-mcp-connection";

type Reply = Result<ConnectionWorkerOutcome, ConnectionWorkerError>;

#[derive(Debug)]
pub(crate) enum ConnectionWorkerAction {
    Load,
    Save {
        settings: McpConnectionSettings,
        expected_revision: Option<McpConnectionRevision>,
        observed_at: TimestampMillis,
    },
    Issue {
        request: McpTokenIssueRequest,
    },
    Rotate {
        id: McpTokenId,
        expected_revision: McpTokenRevision,
        observed_at: TimestampMillis,
    },
    Revoke {
        id: McpTokenId,
        expected_revision: McpTokenRevision,
        observed_at: TimestampMillis,
    },
    Start,
    Stop,
}

#[derive(Debug)]
pub(crate) enum ConnectionWorkerOutcome {
    Loaded {
        settings: Option<RegisteredMcpConnectionSettings>,
        tokens: Vec<McpTokenMetadata>,
        server: ConnectionServerProjection,
    },
    Saved(RegisteredMcpConnectionSettings),
    Issued(McpTokenIssued),
    Rotated(McpTokenRotation),
    Revoked,
    Started(ConnectionServerProjection),
    Stopped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ConnectionServerProjection {
    Stopped,
    Running {
        local_endpoint: String,
        public_endpoint: Option<String>,
    },
}

#[derive(Debug, Error)]
pub(crate) enum ConnectionWorkerError {
    #[error("MCP Connection worker queue is full")]
    QueueFull,
    #[error("MCP Connection worker is unavailable")]
    Unavailable,
    #[error("MCP Connection worker is shutting down")]
    ShuttingDown,
    #[error("failed to spawn MCP Connection worker")]
    ThreadSpawn(#[source] io::Error),
    #[error("MCP Connection worker thread panicked")]
    ThreadPanicked,
    #[error("MCP Connection settings failed")]
    Settings(#[source] McpConnectionSettingsCatalogError),
    #[error("MCP token runtime failed")]
    TokenRuntime(#[source] McpTokenRuntimeError),
    #[error("MCP token operation failed")]
    Token(#[source] McpTokenClientError),
    #[error("MCP HTTP runtime failed")]
    Http(#[source] McpHttpServerRuntimeError),
    #[error("MCP Cloudflare tunnel failed")]
    Tunnel(#[source] CloudflarePublicTunnelError),
    #[error("MCP Connection settings changed elsewhere")]
    RevisionConflict,
    #[error("MCP server is already running")]
    AlreadyRunning,
    #[error("MCP server is already stopped")]
    AlreadyStopped,
    #[error("MCP Connection settings cannot change while the server is running")]
    RunningSettingsLocked,
}

#[derive(Debug)]
pub(crate) struct PendingConnectionRequest {
    receiver: Receiver<Reply>,
}

impl PendingConnectionRequest {
    pub(crate) fn try_recv(&self) -> Result<Option<Reply>, ConnectionWorkerError> {
        match self.receiver.try_recv() {
            Ok(reply) => Ok(Some(reply)),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => Err(ConnectionWorkerError::Unavailable),
        }
    }
}

#[derive(Debug)]
struct WorkRequest {
    action: ConnectionWorkerAction,
    response: SyncSender<Reply>,
}

#[derive(Debug, Clone)]
pub(crate) struct McpConnectionClient {
    sender: SyncSender<WorkRequest>,
    accepting: Arc<AtomicBool>,
}

impl McpConnectionClient {
    pub(crate) fn submit(
        &self,
        action: ConnectionWorkerAction,
    ) -> Result<PendingConnectionRequest, ConnectionWorkerError> {
        if !self.accepting.load(Ordering::Acquire) {
            return Err(ConnectionWorkerError::ShuttingDown);
        }
        let (response, receiver) = mpsc::sync_channel(1);
        match self.sender.try_send(WorkRequest { action, response }) {
            Ok(()) => Ok(PendingConnectionRequest { receiver }),
            Err(TrySendError::Full(_)) => Err(ConnectionWorkerError::QueueFull),
            Err(TrySendError::Disconnected(_)) => Err(ConnectionWorkerError::Unavailable),
        }
    }
}

#[derive(Debug)]
pub(crate) struct McpConnectionWorker {
    client: McpConnectionClient,
    sender_guard: Option<SyncSender<WorkRequest>>,
    thread: Option<JoinHandle<()>>,
}

impl McpConnectionWorker {
    pub(crate) fn start(
        paths: AppPaths,
        control: ForgeControlClient,
    ) -> Result<Self, ConnectionWorkerError> {
        let (sender, receiver) = mpsc::sync_channel(REQUEST_QUEUE_CAPACITY);
        let accepting = Arc::new(AtomicBool::new(true));
        let worker_accepting = Arc::clone(&accepting);
        let thread = thread::Builder::new()
            .name(THREAD_NAME.to_owned())
            .spawn(move || run_worker(paths, control, &receiver, &worker_accepting))
            .map_err(ConnectionWorkerError::ThreadSpawn)?;
        Ok(Self {
            client: McpConnectionClient {
                sender: sender.clone(),
                accepting,
            },
            sender_guard: Some(sender),
            thread: Some(thread),
        })
    }

    pub(crate) fn client(&self) -> McpConnectionClient {
        self.client.clone()
    }

    pub(crate) fn shutdown(&mut self) -> Result<(), ConnectionWorkerError> {
        self.client.accepting.store(false, Ordering::Release);
        self.sender_guard.take();
        let Some(thread) = self.thread.take() else {
            return Ok(());
        };
        thread
            .join()
            .map_err(|_| ConnectionWorkerError::ThreadPanicked)
    }
}

impl Drop for McpConnectionWorker {
    fn drop(&mut self) {
        self.client.accepting.store(false, Ordering::Release);
        self.sender_guard.take();
        if let Some(thread) = self.thread.take() {
            let _ignored = thread.join();
        }
    }
}

struct ConnectionWorkerState {
    paths: AppPaths,
    control: ForgeControlClient,
    token_runtime: Option<McpTokenRuntime>,
    tunnel: Option<CloudflarePublicTunnel>,
    server: Option<McpHttpServerRuntime>,
}

impl ConnectionWorkerState {
    fn new(paths: AppPaths, control: ForgeControlClient) -> Self {
        Self {
            paths,
            control,
            token_runtime: None,
            tunnel: None,
            server: None,
        }
    }

    fn run(&mut self, action: ConnectionWorkerAction) -> Reply {
        match action {
            ConnectionWorkerAction::Load => self.load(),
            ConnectionWorkerAction::Save {
                settings,
                expected_revision,
                observed_at,
            } => self.save(settings, expected_revision, observed_at),
            ConnectionWorkerAction::Issue { request } => {
                let client = self.token_client(McpTokenBootstrapMode::InitializeAuthority)?;
                client
                    .issue(request)
                    .map(ConnectionWorkerOutcome::Issued)
                    .map_err(ConnectionWorkerError::Token)
            }
            ConnectionWorkerAction::Rotate {
                id,
                expected_revision,
                observed_at,
            } => {
                let client = self.token_client(McpTokenBootstrapMode::ExistingAuthority)?;
                client
                    .rotate(id, expected_revision, observed_at)
                    .map(ConnectionWorkerOutcome::Rotated)
                    .map_err(ConnectionWorkerError::Token)
            }
            ConnectionWorkerAction::Revoke {
                id,
                expected_revision,
                observed_at,
            } => {
                let client = self.token_client(McpTokenBootstrapMode::ExistingAuthority)?;
                client
                    .revoke(id, expected_revision, observed_at)
                    .map(|_| ConnectionWorkerOutcome::Revoked)
                    .map_err(ConnectionWorkerError::Token)
            }
            ConnectionWorkerAction::Start => self.start_server(),
            ConnectionWorkerAction::Stop => self.stop_server(),
        }
    }

    fn load(&mut self) -> Reply {
        let settings_path = self.paths.mcp_connection_settings_catalog_path();
        let settings = if settings_path.is_file() {
            McpConnectionSettingsCatalog::open(settings_path)
                .map_err(ConnectionWorkerError::Settings)?
                .get()
                .map_err(ConnectionWorkerError::Settings)?
        } else {
            None
        };
        let tokens = match self.token_client(McpTokenBootstrapMode::ExistingAuthority) {
            Ok(client) => client
                .list(forge_control::MAX_MCP_TOKEN_LIST_RESULTS)
                .map_err(ConnectionWorkerError::Token)?,
            Err(ConnectionWorkerError::TokenRuntime(McpTokenRuntimeError::NotConfigured)) => {
                Vec::new()
            }
            Err(error) => return Err(error),
        };
        Ok(ConnectionWorkerOutcome::Loaded {
            settings,
            tokens,
            server: self.server_projection(),
        })
    }

    fn save(
        &mut self,
        settings: McpConnectionSettings,
        expected_revision: Option<McpConnectionRevision>,
        observed_at: TimestampMillis,
    ) -> Reply {
        if self.server.is_some() || self.tunnel.is_some() {
            return Err(ConnectionWorkerError::RunningSettingsLocked);
        }
        let mut catalog =
            McpConnectionSettingsCatalog::open(self.paths.mcp_connection_settings_catalog_path())
                .map_err(ConnectionWorkerError::Settings)?;
        let saved = match expected_revision {
            Some(revision) => catalog.update(settings, revision, observed_at),
            None => catalog.create(settings, observed_at),
        }
        .map_err(|error| {
            if matches!(
                error,
                McpConnectionSettingsCatalogError::RevisionConflict
                    | McpConnectionSettingsCatalogError::AlreadyConfigured
            ) {
                ConnectionWorkerError::RevisionConflict
            } else {
                ConnectionWorkerError::Settings(error)
            }
        })?;
        Ok(ConnectionWorkerOutcome::Saved(saved))
    }

    fn start_server(&mut self) -> Reply {
        if self.server.is_some() || self.tunnel.is_some() {
            return Err(ConnectionWorkerError::AlreadyRunning);
        }
        let settings_path = self.paths.mcp_connection_settings_catalog_path();
        let settings = if settings_path.is_file() {
            McpConnectionSettingsCatalog::open(settings_path)
                .map_err(ConnectionWorkerError::Settings)?
                .get()
                .map_err(ConnectionWorkerError::Settings)?
                .map_or_else(
                    || McpConnectionSettings::new(None, McpLocalPort::DEFAULT),
                    |record| record.settings().clone(),
                )
        } else {
            McpConnectionSettings::new(None, McpLocalPort::DEFAULT)
        };
        let token_runtime = match self.token_runtime.take() {
            Some(runtime) => runtime,
            None => McpTokenRuntime::start(&self.paths, McpTokenBootstrapMode::InitializeAuthority)
                .map_err(ConnectionWorkerError::TokenRuntime)?,
        };
        let tunnel =
            match CloudflarePublicTunnel::start(settings.public_base(), settings.local_port()) {
                Ok(tunnel) => tunnel,
                Err(error) => {
                    self.token_runtime = Some(token_runtime);
                    return Err(ConnectionWorkerError::Tunnel(error));
                }
            };
        let config = McpHttpServerConfig::new(settings.local_port().get())
            .with_public_origin(tunnel.public_base().clone());
        let server = match McpHttpServerRuntime::start(self.control.clone(), token_runtime, config)
        {
            Ok(server) => server,
            Err(error) => {
                let _ignored = tunnel.stop();
                return Err(ConnectionWorkerError::Http(error));
            }
        };
        let projection = ConnectionServerProjection::Running {
            local_endpoint: server.endpoint().to_owned(),
            public_endpoint: server.public_endpoint().map(str::to_owned),
        };
        self.tunnel = Some(tunnel);
        self.server = Some(server);
        Ok(ConnectionWorkerOutcome::Started(projection))
    }

    fn stop_server(&mut self) -> Reply {
        if self.server.is_none() && self.tunnel.is_none() {
            return Err(ConnectionWorkerError::AlreadyStopped);
        }
        let tunnel_result = match self.tunnel.take() {
            Some(tunnel) => tunnel.stop().map_err(ConnectionWorkerError::Tunnel),
            None => Ok(()),
        };
        let server_result = match self.server.take() {
            Some(server) => server
                .stop()
                .map(|_report| ())
                .map_err(ConnectionWorkerError::Http),
            None => Ok(()),
        };
        tunnel_result?;
        server_result?;
        Ok(ConnectionWorkerOutcome::Stopped)
    }

    fn token_client(
        &mut self,
        bootstrap_mode: McpTokenBootstrapMode,
    ) -> Result<McpTokenClient, ConnectionWorkerError> {
        if let Some(server) = self.server.as_ref() {
            return server
                .token_client()
                .ok_or(ConnectionWorkerError::Unavailable);
        }
        if self.token_runtime.is_none() {
            self.token_runtime = Some(
                McpTokenRuntime::start(&self.paths, bootstrap_mode)
                    .map_err(ConnectionWorkerError::TokenRuntime)?,
            );
        }
        self.token_runtime
            .as_ref()
            .map(McpTokenRuntime::client)
            .ok_or(ConnectionWorkerError::Unavailable)
    }

    fn server_projection(&self) -> ConnectionServerProjection {
        self.server
            .as_ref()
            .map_or(ConnectionServerProjection::Stopped, |server| {
                ConnectionServerProjection::Running {
                    local_endpoint: server.endpoint().to_owned(),
                    public_endpoint: server.public_endpoint().map(str::to_owned),
                }
            })
    }

    fn shutdown(&mut self) {
        if let Some(tunnel) = self.tunnel.take() {
            let _ignored = tunnel.stop();
        }
        if let Some(server) = self.server.take() {
            let _ignored = server.stop();
        }
        if let Some(mut token_runtime) = self.token_runtime.take() {
            let _ignored = token_runtime.shutdown();
        }
    }
}

fn run_worker(
    paths: AppPaths,
    control: ForgeControlClient,
    receiver: &Receiver<WorkRequest>,
    accepting: &Arc<AtomicBool>,
) {
    let mut state = ConnectionWorkerState::new(paths, control);
    while accepting.load(Ordering::Acquire) {
        let request = match receiver.recv_timeout(SHUTDOWN_POLL_INTERVAL) {
            Ok(request) => request,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => break,
        };
        let result = state.run(request.action);
        let _ignored = request.response.send(result);
    }
    accepting.store(false, Ordering::Release);
    while let Ok(request) = receiver.try_recv() {
        let _ignored = request
            .response
            .send(Err(ConnectionWorkerError::ShuttingDown));
    }
    state.shutdown();
}
