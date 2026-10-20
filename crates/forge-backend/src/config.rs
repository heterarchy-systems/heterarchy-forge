//! Backend composition configuration and bound enforcement.
//!
//! The adapter is loopback-only in this slice: a non-loopback bind address is
//! rejected at startup (fail-closed). TLS / trusted proxy termination is a
//! later lane decision and has no configuration surface here yet.

use std::net::IpAddr;
use std::time::Duration;

use thiserror::Error;

/// Wire protocol version advertised by the envelope and capability document.
pub const FORGE_API_VERSION: u32 = 1;

/// Maximum request body size accepted on the command path.
pub const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Maximum semantic event page size (`1..=64` rows).
pub const MAX_EVENT_PAGE_ROWS: u32 = 64;

/// Default command bridge deadline. Commands admitted to the bridge that hit
/// this deadline return `UNKNOWN_OUTCOME`; the bridge worker may still finish
/// the synchronous control call and its durable effect.
pub const DEFAULT_COMMAND_DEADLINE: Duration = Duration::from_secs(30);

/// Default live-tail polling cadence over the durable semantic event table.
pub const DEFAULT_SSE_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Maximum admitted connection tasks, including idle sockets and SSE.
/// The accept loop may hold one extra transient socket while rejecting it.
pub const DEFAULT_HTTP_CONNECTION_LIMIT: usize = 128;
/// Absolute deadline for acquiring headers and, separately, a request body.
pub const DEFAULT_HTTP_INPUT_DEADLINE: Duration = Duration::from_secs(5);
/// Maximum Hyper HTTP/1 connection buffer and header count.
pub const MAX_HTTP_HEADER_BYTES: usize = 32 * 1024;
pub const MAX_HTTP_HEADERS: usize = 64;

/// Backend configuration.
#[must_use]
#[derive(Clone)]
pub struct BackendConfig {
    bind_ip: IpAddr,
    port: u16,
    backend_id: forge_domain::ForgeBackendId,
    issuer: forge_domain::OrchestrationIssuerId,
    issuer_auth: crate::auth::IssuerAuth,
    command_deadline: Duration,
    sse_poll_interval: Duration,
    max_inflight_commands: usize,
    max_sse_subscribers: usize,
    bridge_workers: usize,
    http_connection_limit: usize,
    http_input_deadline: Duration,
}

impl std::fmt::Debug for BackendConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BackendConfig")
            .field("bind_ip", &self.bind_ip)
            .field("port", &self.port)
            .field("backend_id", &self.backend_id)
            .field("issuer", &self.issuer)
            .field("command_deadline", &self.command_deadline)
            .field("max_inflight_commands", &self.max_inflight_commands)
            .field("max_sse_subscribers", &self.max_sse_subscribers)
            .field("bridge_workers", &self.bridge_workers)
            .field("http_connection_limit", &self.http_connection_limit)
            .field("http_input_deadline", &self.http_input_deadline)
            .finish_non_exhaustive()
    }
}

impl BackendConfig {
    pub fn new(
        bind_ip: IpAddr,
        port: u16,
        bearer_secret: impl Into<String>,
        backend_id: forge_domain::ForgeBackendId,
        issuer: forge_domain::OrchestrationIssuerId,
    ) -> Result<Self, ConfigError> {
        let bearer_secret = bearer_secret.into();
        if !bind_ip.is_loopback() {
            return Err(ConfigError::NonLoopbackBind(bind_ip));
        }
        if bearer_secret.is_empty() {
            return Err(ConfigError::EmptyBearerSecret);
        }
        if backend_id.into_uuid().is_nil() || issuer.into_uuid().is_nil() {
            return Err(ConfigError::MissingIdentity);
        }
        Ok(Self {
            bind_ip,
            port,
            backend_id,
            issuer,
            issuer_auth: crate::auth::IssuerAuth::new(&bearer_secret),
            command_deadline: DEFAULT_COMMAND_DEADLINE,
            sse_poll_interval: DEFAULT_SSE_POLL_INTERVAL,
            max_inflight_commands: 64,
            max_sse_subscribers: 64,
            bridge_workers: 2,
            http_connection_limit: DEFAULT_HTTP_CONNECTION_LIMIT,
            http_input_deadline: DEFAULT_HTTP_INPUT_DEADLINE,
        })
    }

    pub const fn bind_ip(&self) -> IpAddr {
        self.bind_ip
    }

    pub const fn port(&self) -> u16 {
        self.port
    }

    pub const fn backend_id(&self) -> forge_domain::ForgeBackendId {
        self.backend_id
    }

    pub const fn issuer(&self) -> forge_domain::OrchestrationIssuerId {
        self.issuer
    }

    pub(crate) const fn issuer_auth(&self) -> &crate::auth::IssuerAuth {
        &self.issuer_auth
    }

    pub fn with_command_deadline(mut self, deadline: Duration) -> Self {
        self.command_deadline = deadline;
        self
    }

    pub(crate) const fn command_deadline(&self) -> Duration {
        self.command_deadline
    }

    pub fn with_sse_poll_interval(mut self, interval: Duration) -> Self {
        self.sse_poll_interval = interval.max(Duration::from_millis(50));
        self
    }

    pub(crate) const fn sse_poll_interval(&self) -> Duration {
        self.sse_poll_interval
    }

    pub fn with_max_inflight_commands(mut self, limit: usize) -> Self {
        self.max_inflight_commands = limit.max(1);
        self
    }

    pub(crate) const fn max_inflight_commands(&self) -> usize {
        self.max_inflight_commands
    }

    pub fn with_max_sse_subscribers(mut self, limit: usize) -> Self {
        self.max_sse_subscribers = limit.max(1);
        self
    }

    pub(crate) const fn max_sse_subscribers(&self) -> usize {
        self.max_sse_subscribers
    }

    pub fn with_bridge_workers(mut self, workers: usize) -> Self {
        self.bridge_workers = workers.max(1);
        self
    }

    pub(crate) const fn bridge_workers(&self) -> usize {
        self.bridge_workers
    }

    pub fn with_http_connection_limit(mut self, limit: usize) -> Self {
        self.http_connection_limit = limit.max(1);
        self
    }

    pub(crate) const fn http_connection_limit(&self) -> usize {
        self.http_connection_limit
    }

    pub fn with_http_input_deadline(mut self, deadline: Duration) -> Self {
        self.http_input_deadline = deadline.max(Duration::from_millis(1));
        self
    }

    pub(crate) const fn http_input_deadline(&self) -> Duration {
        self.http_input_deadline
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ConfigError {
    #[error(
        "non-loopback bind address {0} is rejected in this slice; TLS/proxy termination is a later lane decision"
    )]
    NonLoopbackBind(IpAddr),
    #[error("bearer secret must not be empty")]
    EmptyBearerSecret,
    #[error("backend and issuer identities must be explicitly configured")]
    MissingIdentity,
}
