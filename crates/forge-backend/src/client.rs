//! Bounded asynchronous client for the Forge HTTP command boundary.
//!
//! This client is deliberately a one-shot HTTP/1 transport. It owns no
//! connection pool, retry loop, redirect policy, background task, or local
//! authority. The caller supplies the exact delegated request and receives the
//! authenticated effect-fact wire projection after the response identity and
//! bounded payload have been checked.

#![allow(
    clippy::result_large_err,
    reason = "The public mutation error preserves exact intent for unknown-outcome readback compatibility."
)]

use std::{fmt, net::SocketAddr, sync::Arc, time::Duration};

use forge_control::{
    AgentOperationsExportRequest, AgentOperationsFreezeReadRequest,
    AgentOperationsFreezeReleaseRequest, AgentOperationsFreezeRequest, EffectFactOutboxReadRequest,
    ResolvedWorkspaceScope, WorkspaceRootRecoveryCommitRequest,
    WorkspaceRootRecoveryPrepareRequest, WorkspaceRootRecoveryProbeRequest,
    WorkspaceRootRecoveryReadbackRequest,
};
use forge_domain::ForgeBackendId;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Bytes;
use hyper::header::{
    AUTHORIZATION, CONNECTION, CONTENT_LENGTH, CONTENT_TYPE, HOST, HeaderMap, HeaderValue,
};
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use serde_json::{Value, from_slice, json, to_vec};
use thiserror::Error;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use uuid::Uuid;

use crate::config::{FORGE_API_VERSION, MAX_BODY_BYTES};
use crate::ops::CommandOp;

#[path = "client/root_recovery.rs"]
mod root_recovery;

const EFFECT_FACT_OUTBOX_PATH: &str = "/api/v1/commands/effect_fact.outbox";
const MAX_HEADER_BYTES: usize = 8 * 1024;
const MAX_HEADER_FIELDS: usize = 16;
const MAX_EFFECT_FACT_PAGE: u32 = 64;
const MAX_REQUEST_BYTES: usize = 64 * 1024;
const MAX_CLIENT_TIMEOUT: Duration = Duration::from_secs(5);
const EFFECT_FACT_CLIENT_CONCURRENCY: usize = 4;
const MIGRATION_MAX_PAGE_ROWS: usize = 64;
const MIGRATION_CLIENT_CONCURRENCY: usize = 4;

/// Maximum response body accepted by this transport.
pub const MAX_CLIENT_RESPONSE_BYTES: usize = MAX_BODY_BYTES;

/// Explicit, redacted client configuration failures.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum ForgeHttpClientConfigError {
    #[error("Forge HTTP authority must be loopback")]
    NonLoopbackAuthority,
    #[error("Forge HTTP authority port must be nonzero")]
    MissingAuthorityPort,
    #[error("Forge HTTP service bearer is empty")]
    EmptyServiceBearer,
    #[error("Forge HTTP service bearer is invalid")]
    InvalidServiceBearer,
    #[error("Forge HTTP backend identity is nil")]
    NilBackendIdentity,
    #[error("Forge HTTP destination identity is nil")]
    NilDestinationIdentity,
    #[error("Forge HTTP timeout must be nonzero")]
    ZeroTimeout,
}

/// Bounded transport and service failures. No raw response body, path, or
/// bearer value is retained in this projection.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum ForgeHttpClientError {
    #[error("Forge HTTP client capacity is unavailable")]
    Capacity,
    #[error("Forge HTTP transport failed")]
    Transport,
    #[error("Forge HTTP call deadline elapsed")]
    Timeout,
    #[error("Forge HTTP request could not be constructed")]
    Request,
    #[error("Forge HTTP request exceeded its bounded body size")]
    RequestTooLarge,
    #[error("Forge HTTP response headers exceeded their bound")]
    ResponseHeadersTooLarge,
    #[error("Forge HTTP response exceeded its bounded body size")]
    ResponseTooLarge,
    #[error("Forge HTTP authentication failed")]
    Authentication,
    #[error("Forge HTTP response protocol was invalid")]
    Protocol,
    #[error("Forge HTTP service rejected the request")]
    Service {
        status: u16,
        code: ForgeHttpServiceCode,
    },
    #[error("Forge HTTP request destination does not match the trusted client destination")]
    DestinationMismatch,
    #[error("Forge HTTP request is invalid")]
    InvalidRequest,
}

/// Original intent retained when a mutation reply cannot establish whether
/// the durable source effect committed.  Callers must read the exact migration
/// identity before deciding what to do next; this type never retries.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForgeHttpMutationRequest {
    Freeze(AgentOperationsFreezeRequest),
    Release(AgentOperationsFreezeReleaseRequest),
    WorkspaceRootRecoveryPrepare(Box<WorkspaceRootRecoveryPrepareRequest>),
    WorkspaceRootRecoveryCommit(Box<WorkspaceRootRecoveryCommitRequest>),
}

/// Mutation-specific outcome preserving the original intent across transport
/// uncertainty while keeping the existing copyable client error unchanged.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ForgeHttpMutationError {
    #[error("Forge HTTP mutation was rejected")]
    Rejected(#[source] ForgeHttpClientError),
    #[error("Forge HTTP mutation outcome is unknown; read back the original migration identity")]
    UnknownOutcome {
        request: ForgeHttpMutationRequest,
        #[source]
        cause: ForgeHttpClientError,
    },
}

impl ForgeHttpMutationError {
    pub const fn is_unknown_outcome(&self) -> bool {
        matches!(self, Self::UnknownOutcome { .. })
    }

    pub const fn request(&self) -> Option<&ForgeHttpMutationRequest> {
        match self {
            Self::Rejected(_) => None,
            Self::UnknownOutcome { request, .. } => Some(request),
        }
    }

    pub const fn cause(&self) -> &ForgeHttpClientError {
        match self {
            Self::Rejected(error) => error,
            Self::UnknownOutcome { cause, .. } => cause,
        }
    }
}

/// Stable service-code subset retained without forwarding server text.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum ForgeHttpServiceCode {
    #[error("invalid input")]
    InvalidInput,
    #[error("capacity exceeded")]
    CapacityExceeded,
    #[error("unknown outcome")]
    UnknownOutcome,
    #[error("authentication failed")]
    AuthFailed,
    #[error("workspace confinement denied")]
    WorkspaceConfinementDenied,
    #[error("workspace effect scopes overlap")]
    WorkspaceScopeOverlap,
    #[error("unexpected source path kind")]
    InvalidPathKind,
    #[error("stale revision")]
    StaleRevision,
    #[error("planning conflict")]
    PlanningConflict,
    #[error("source conflict")]
    SourceConflict,
    #[error("lease conflict")]
    LeaseConflict,
    #[error("resync required")]
    ResyncRequired,
    #[error("Forge unavailable")]
    ForgeUnavailable,
    #[error("unknown service code")]
    Unknown,
}

impl ForgeHttpServiceCode {
    /// Decode the closed backend error contract without retaining server text.
    /// Distinct rejection families require distinct caller recovery actions.
    #[must_use]
    pub fn from_wire_code(value: &str) -> Self {
        match value {
            "INVALID_INPUT" => Self::InvalidInput,
            "CAPACITY_EXCEEDED" => Self::CapacityExceeded,
            "UNKNOWN_OUTCOME" => Self::UnknownOutcome,
            "AUTH_FAILED" => Self::AuthFailed,
            "WORKSPACE_CONFINEMENT_DENIED" => Self::WorkspaceConfinementDenied,
            "WORKSPACE_SCOPE_OVERLAP" => Self::WorkspaceScopeOverlap,
            "INVALID_PATH_KIND" => Self::InvalidPathKind,
            "STALE_REVISION" => Self::StaleRevision,
            "PLANNING_CONFLICT" => Self::PlanningConflict,
            "SOURCE_CONFLICT" => Self::SourceConflict,
            "LEASE_CONFLICT" => Self::LeaseConflict,
            "RESYNC_REQUIRED" => Self::ResyncRequired,
            "FORGE_UNAVAILABLE" => Self::ForgeUnavailable,
            _ => Self::Unknown,
        }
    }

    /// Stable diagnostic identity; unknown peer text is never reflected.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidInput => "INVALID_INPUT",
            Self::CapacityExceeded => "CAPACITY_EXCEEDED",
            Self::UnknownOutcome => "UNKNOWN_OUTCOME",
            Self::AuthFailed => "AUTH_FAILED",
            Self::WorkspaceConfinementDenied => "WORKSPACE_CONFINEMENT_DENIED",
            Self::WorkspaceScopeOverlap => "WORKSPACE_SCOPE_OVERLAP",
            Self::InvalidPathKind => "INVALID_PATH_KIND",
            Self::StaleRevision => "STALE_REVISION",
            Self::PlanningConflict => "PLANNING_CONFLICT",
            Self::SourceConflict => "SOURCE_CONFLICT",
            Self::LeaseConflict => "LEASE_CONFLICT",
            Self::ResyncRequired => "RESYNC_REQUIRED",
            Self::ForgeUnavailable => "FORGE_UNAVAILABLE",
            Self::Unknown => "UNKNOWN_SERVICE_CODE",
        }
    }
}

/// One bounded Forge HTTP client. The service bearer is retained only as a
/// sensitive header value; it is never included in Debug or error output.
#[must_use]
#[derive(Clone)]
pub struct ForgeHttpClient {
    authority: SocketAddr,
    service_bearer: HeaderValue,
    expected_backend_id: ForgeBackendId,
    destination_id: Uuid,
    timeout: Duration,
    slots: Arc<Semaphore>,
    migration_slots: Arc<Semaphore>,
}

impl fmt::Debug for ForgeHttpClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ForgeHttpClient")
            .field("authority", &self.authority)
            .field("expected_backend_id", &self.expected_backend_id)
            .field("destination_id", &self.destination_id)
            .field("timeout", &self.timeout)
            .field("service_bearer_configured", &true)
            .finish_non_exhaustive()
    }
}

impl ForgeHttpClient {
    /// Build a loopback-only client for one exact Forge backend and delegated
    /// destination. The deadline is capped so callers cannot install an
    /// unbounded network wait through configuration.
    pub fn new(
        authority: SocketAddr,
        service_secret: &str,
        expected_backend_id: ForgeBackendId,
        destination_id: Uuid,
        timeout: Duration,
    ) -> Result<Self, ForgeHttpClientConfigError> {
        if !authority.ip().is_loopback() {
            return Err(ForgeHttpClientConfigError::NonLoopbackAuthority);
        }
        if authority.port() == 0 {
            return Err(ForgeHttpClientConfigError::MissingAuthorityPort);
        }
        if service_secret.is_empty() {
            return Err(ForgeHttpClientConfigError::EmptyServiceBearer);
        }
        if expected_backend_id.into_uuid().is_nil() {
            return Err(ForgeHttpClientConfigError::NilBackendIdentity);
        }
        if destination_id.is_nil() {
            return Err(ForgeHttpClientConfigError::NilDestinationIdentity);
        }
        if timeout.is_zero() {
            return Err(ForgeHttpClientConfigError::ZeroTimeout);
        }
        let mut service_bearer = HeaderValue::from_str(&format!("Bearer {service_secret}"))
            .map_err(|_| ForgeHttpClientConfigError::InvalidServiceBearer)?;
        service_bearer.set_sensitive(true);
        Ok(Self {
            authority,
            service_bearer,
            expected_backend_id,
            destination_id,
            timeout: timeout.min(MAX_CLIENT_TIMEOUT),
            slots: Arc::new(Semaphore::new(EFFECT_FACT_CLIENT_CONCURRENCY)),
            migration_slots: Arc::new(Semaphore::new(MIGRATION_CLIENT_CONCURRENCY)),
        })
    }

    #[must_use]
    pub const fn authority(&self) -> SocketAddr {
        self.authority
    }

    pub const fn expected_backend_id(&self) -> ForgeBackendId {
        self.expected_backend_id
    }

    #[must_use]
    pub const fn destination_id(&self) -> Uuid {
        self.destination_id
    }

    /// Read one exact delegated effect-fact page. This is observational: it
    /// never acknowledges, advances, or mutates Forge state.
    pub async fn effect_fact_outbox(
        &self,
        request: &EffectFactOutboxReadRequest,
    ) -> Result<crate::ops::effect_facts::wire::EffectFactOutboxResponse, ForgeHttpClientError>
    {
        validate_request(request, self.destination_id)?;
        let _permit = self
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| ForgeHttpClientError::Capacity)?;
        let request_id = Uuid::now_v7();
        let body = request_body(request, request_id)?;
        let exchange = self.exchange(body);
        let result = tokio::time::timeout(self.timeout, exchange)
            .await
            .map_err(|_| ForgeHttpClientError::Timeout)??;
        decode_response(result, request, request_id, self.expected_backend_id)
    }

    /// Create or exactly replay one Forge Agent-operations source freeze.
    pub async fn agent_operations_freeze(
        &self,
        request: &AgentOperationsFreezeRequest,
    ) -> Result<forge_persistence::AgentOperationsFreeze, ForgeHttpMutationError> {
        if request.destination_id != self.destination_id {
            return Err(ForgeHttpMutationError::Rejected(
                ForgeHttpClientError::DestinationMismatch,
            ));
        }
        let intent = ForgeHttpMutationRequest::Freeze(request.clone());
        let _permit = self
            .migration_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| ForgeHttpMutationError::Rejected(ForgeHttpClientError::Capacity))?;
        let request_id = Uuid::now_v7();
        let body = migration_request_body(
            CommandOp::AgentOperationsFreeze,
            migration_scope_payload(&request.scope).map_err(ForgeHttpMutationError::Rejected)?,
            json!({
                "migration_id": request.migration_id,
                "destination_id": request.destination_id,
                "observed_at_ms": request.observed_at.get(),
            }),
            request_id,
        )
        .map_err(ForgeHttpMutationError::Rejected)?;
        let value = self
            .mutation_exchange(
                CommandOp::AgentOperationsFreeze,
                body,
                request_id,
                intent.clone(),
            )
            .await?;
        let response: crate::ops::agent_operations_migration::AgentOperationsFreezeWire =
            serde_json::from_value(value).map_err(|_| ForgeHttpMutationError::UnknownOutcome {
                request: intent.clone(),
                cause: ForgeHttpClientError::Protocol,
            })?;
        validate_freeze_create_wire(
            &response,
            &request.scope,
            request.migration_id,
            request.destination_id,
            request.observed_at.get(),
            self.expected_backend_id,
        )
        .map_err(|_| ForgeHttpMutationError::UnknownOutcome {
            request: intent.clone(),
            cause: ForgeHttpClientError::Protocol,
        })?;
        response
            .into_native()
            .map_err(|_| ForgeHttpMutationError::UnknownOutcome {
                request: intent,
                cause: ForgeHttpClientError::Protocol,
            })
    }

    /// Read one exact Forge Agent-operations source freeze.
    pub async fn agent_operations_freeze_read(
        &self,
        request: &AgentOperationsFreezeReadRequest,
    ) -> Result<Option<forge_persistence::AgentOperationsFreeze>, ForgeHttpClientError> {
        if request.destination_id != self.destination_id {
            return Err(ForgeHttpClientError::DestinationMismatch);
        }
        let _permit = self
            .migration_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| ForgeHttpClientError::Capacity)?;
        let request_id = Uuid::now_v7();
        let body = migration_request_body(
            CommandOp::AgentOperationsFreezeGet,
            migration_scope_payload(&request.scope)?,
            json!({
                "migration_id": request.migration_id,
                "destination_id": request.destination_id,
            }),
            request_id,
        )?;
        let result = tokio::time::timeout(
            self.timeout,
            self.exchange_command(CommandOp::AgentOperationsFreezeGet, body),
        )
        .await
        .map_err(|_| ForgeHttpClientError::Timeout)??;
        let value = decode_command_response(result, request_id)?;
        let response: crate::ops::agent_operations_migration::AgentOperationsFreezeGetResponseWire =
            serde_json::from_value(value).map_err(|_| ForgeHttpClientError::Protocol)?;
        validate_freeze_get_wire(
            &response,
            &request.scope,
            request.migration_id,
            request.destination_id,
            self.expected_backend_id,
        )?;
        response.into_native()
    }

    /// Read one bounded Forge Agent-operations export page.
    pub async fn agent_operations_export(
        &self,
        request: &AgentOperationsExportRequest,
    ) -> Result<forge_persistence::AgentOperationsExportPage, ForgeHttpClientError> {
        if request.destination_id != self.destination_id {
            return Err(ForgeHttpClientError::DestinationMismatch);
        }
        let _permit = self
            .migration_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| ForgeHttpClientError::Capacity)?;
        let request_id = Uuid::now_v7();
        let cursor = crate::ops::agent_operations_migration::ExportCursorWire::from(request.cursor);
        let body = migration_request_body(
            CommandOp::AgentOperationsExport,
            migration_scope_payload(&request.scope)?,
            json!({
                "migration_id": request.migration_id,
                "destination_id": request.destination_id,
                "cursor": cursor,
            }),
            request_id,
        )?;
        let result = tokio::time::timeout(
            self.timeout,
            self.exchange_command(CommandOp::AgentOperationsExport, body),
        )
        .await
        .map_err(|_| ForgeHttpClientError::Timeout)??;
        let value = decode_command_response(result, request_id)?;
        let response: crate::ops::agent_operations_migration::AgentOperationsExportPageWire =
            serde_json::from_value(value).map_err(|_| ForgeHttpClientError::Protocol)?;
        validate_export_wire(
            &response,
            &request.scope,
            request.migration_id,
            request.destination_id,
            request.cursor,
            self.expected_backend_id,
        )?;
        response.into_native()
    }

    /// Release one Forge Agent-operations source freeze with exact CAS fields.
    pub async fn agent_operations_freeze_release(
        &self,
        request: &AgentOperationsFreezeReleaseRequest,
    ) -> Result<forge_persistence::AgentOperationsFreeze, ForgeHttpMutationError> {
        if request.destination_id != self.destination_id {
            return Err(ForgeHttpMutationError::Rejected(
                ForgeHttpClientError::DestinationMismatch,
            ));
        }
        if request.expected_revision == 0 || request.expected_revision > i64::MAX as u64 {
            return Err(ForgeHttpMutationError::Rejected(
                ForgeHttpClientError::InvalidRequest,
            ));
        }
        let intent = ForgeHttpMutationRequest::Release(request.clone());
        let _permit = self
            .migration_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| ForgeHttpMutationError::Rejected(ForgeHttpClientError::Capacity))?;
        let request_id = Uuid::now_v7();
        let body = migration_request_body(
            CommandOp::AgentOperationsFreezeRelease,
            migration_scope_payload(&request.scope).map_err(ForgeHttpMutationError::Rejected)?,
            json!({
                "migration_id": request.migration_id,
                "destination_id": request.destination_id,
                "expected_revision": request.expected_revision,
                "observed_at_ms": request.observed_at.get(),
            }),
            request_id,
        )
        .map_err(ForgeHttpMutationError::Rejected)?;
        let value = self
            .mutation_exchange(
                CommandOp::AgentOperationsFreezeRelease,
                body,
                request_id,
                intent.clone(),
            )
            .await?;
        let response: crate::ops::agent_operations_migration::AgentOperationsFreezeWire =
            serde_json::from_value(value).map_err(|_| ForgeHttpMutationError::UnknownOutcome {
                request: intent.clone(),
                cause: ForgeHttpClientError::Protocol,
            })?;
        validate_freeze_release_wire(
            &response,
            &request.scope,
            request.migration_id,
            request.destination_id,
            request.expected_revision,
            request.observed_at.get(),
            self.expected_backend_id,
        )
        .map_err(|_| ForgeHttpMutationError::UnknownOutcome {
            request: intent.clone(),
            cause: ForgeHttpClientError::Protocol,
        })?;
        response
            .into_native()
            .map_err(|_| ForgeHttpMutationError::UnknownOutcome {
                request: intent,
                cause: ForgeHttpClientError::Protocol,
            })
    }

    /// Observe one selected Workspace root and its durable identity without
    /// preparing a schema or changing the binding.
    pub async fn workspace_root_recovery_probe(
        &self,
        request: &WorkspaceRootRecoveryProbeRequest,
    ) -> Result<crate::WorkspaceRootRecoveryProbeWire, ForgeHttpClientError> {
        let _permit = self
            .migration_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| ForgeHttpClientError::Capacity)?;
        let request_id = Uuid::now_v7();
        let mut payload = json!({
            "locator": request.locator().encode(),
            "expected_workspace_id": request
                .expected_workspace_id()
                .map(forge_domain::WorkspaceId::into_uuid),
        });
        if let Some(mode) =
            crate::ops::workspace_root_recovery::authority_mode_json(request.authority_mode(), true)
        {
            payload["authority_mode"] = mode;
        }
        let body =
            root_recovery_request_body(CommandOp::WorkspaceRootRecoveryProbe, payload, request_id)?;
        let result = tokio::time::timeout(
            self.timeout,
            self.exchange_command(CommandOp::WorkspaceRootRecoveryProbe, body),
        )
        .await
        .map_err(|_| ForgeHttpClientError::Timeout)??;
        let value = decode_command_response(result, request_id)?;
        let response = serde_json::from_value(value).map_err(|_| ForgeHttpClientError::Protocol)?;
        root_recovery::validate_probe(&response, request)?;
        Ok(response)
    }

    /// Explicitly prepare the additive root-recovery schema upgrade. A lost
    /// reply is retained as an unknown mutation outcome; callers must probe or
    /// read back before deciding whether to continue.
    pub async fn workspace_root_recovery_prepare(
        &self,
        request: &WorkspaceRootRecoveryPrepareRequest,
    ) -> Result<crate::WorkspaceRootRecoveryProbeWire, ForgeHttpMutationError> {
        let intent =
            ForgeHttpMutationRequest::WorkspaceRootRecoveryPrepare(Box::new(request.clone()));
        let _permit = self
            .migration_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| ForgeHttpMutationError::Rejected(ForgeHttpClientError::Capacity))?;
        let request_id = Uuid::now_v7();
        let mut payload = json!({
            "locator": request.locator().encode(),
            "expected_workspace": crate::ops::workspace_root_recovery::workspace_json(request.expected_workspace()),
            "observed": crate::ops::workspace_root_recovery::observation_json_for_mode(request.observation(), request.authority_mode()),
            "operator_confirmed": request.operator_confirmed(),
        });
        if let Some(mode) =
            crate::ops::workspace_root_recovery::authority_mode_json(request.authority_mode(), true)
        {
            payload["authority_mode"] = mode;
        }
        let body = root_recovery_request_body(
            CommandOp::WorkspaceRootRecoveryPrepare,
            payload,
            request_id,
        )
        .map_err(ForgeHttpMutationError::Rejected)?;
        let value = self
            .mutation_exchange(
                CommandOp::WorkspaceRootRecoveryPrepare,
                body,
                request_id,
                intent.clone(),
            )
            .await?;
        let response =
            serde_json::from_value(value).map_err(|_| ForgeHttpMutationError::UnknownOutcome {
                request: intent.clone(),
                cause: ForgeHttpClientError::Protocol,
            })?;
        root_recovery::validate_prepare(&response, request).map_err(|cause| {
            ForgeHttpMutationError::UnknownOutcome {
                request: intent,
                cause,
            }
        })?;
        Ok(response)
    }

    /// Commit one exact, owner-confirmed root-binding recovery intent.
    pub async fn workspace_root_recovery_commit(
        &self,
        request: &WorkspaceRootRecoveryCommitRequest,
    ) -> Result<crate::WorkspaceRootRecoveryCommitWire, ForgeHttpMutationError> {
        let intent =
            ForgeHttpMutationRequest::WorkspaceRootRecoveryCommit(Box::new(request.clone()));
        let _permit = self
            .migration_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| ForgeHttpMutationError::Rejected(ForgeHttpClientError::Capacity))?;
        let recovery = request.intent();
        let request_id = recovery.request_id();
        let mut payload = json!({
            "locator": request.locator().encode(),
            "request_id": recovery.request_id(),
            "location_revision": recovery.location_revision().get(),
            "expected_workspace": crate::ops::workspace_root_recovery::workspace_json(recovery.expected()),
            "observed": crate::ops::workspace_root_recovery::observation_json_for_mode(recovery.observed(), recovery.authority_mode()),
            "observed_at_ms": recovery.observed_at().get(),
            "operator_confirmed": request.operator_confirmed(),
        });
        if let Some(mode) = crate::ops::workspace_root_recovery::authority_mode_json(
            recovery.authority_mode(),
            true,
        ) {
            payload["authority_mode"] = mode;
        }
        let body =
            root_recovery_request_body(CommandOp::WorkspaceRootRecoveryCommit, payload, request_id)
                .map_err(ForgeHttpMutationError::Rejected)?;
        let value = self
            .mutation_exchange(
                CommandOp::WorkspaceRootRecoveryCommit,
                body,
                request_id,
                intent.clone(),
            )
            .await?;
        let response =
            serde_json::from_value(value).map_err(|_| ForgeHttpMutationError::UnknownOutcome {
                request: intent.clone(),
                cause: ForgeHttpClientError::Protocol,
            })?;
        root_recovery::validate_commit(&response, request).map_err(|cause| {
            ForgeHttpMutationError::UnknownOutcome {
                request: intent,
                cause,
            }
        })?;
        Ok(response)
    }

    /// Read the historical root-recovery receipt. This does not claim that
    /// the selected Location is currently ready for normal Workspace use.
    pub async fn workspace_root_recovery_readback(
        &self,
        request: &WorkspaceRootRecoveryReadbackRequest,
    ) -> Result<crate::WorkspaceRootRecoveryReadbackWire, ForgeHttpClientError> {
        let _permit = self
            .migration_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| ForgeHttpClientError::Capacity)?;
        let request_id = request.request_id();
        let intent = request.intent().map_or(
            Value::Null,
            crate::ops::workspace_root_recovery::intent_json,
        );
        let mut payload = json!({
            "locator": request.locator().encode(),
            "request_id": request.request_id(),
            "intent": intent,
        });
        if let Some(mode) =
            crate::ops::workspace_root_recovery::authority_mode_json(request.authority_mode(), true)
        {
            payload["authority_mode"] = mode;
        }
        let body = root_recovery_request_body(
            CommandOp::WorkspaceRootRecoveryReadback,
            payload,
            request_id,
        )?;
        let result = tokio::time::timeout(
            self.timeout,
            self.exchange_command(CommandOp::WorkspaceRootRecoveryReadback, body),
        )
        .await
        .map_err(|_| ForgeHttpClientError::Timeout)??;
        let value = decode_command_response(result, request_id)?;
        let response = serde_json::from_value(value).map_err(|_| ForgeHttpClientError::Protocol)?;
        root_recovery::validate_readback(&response, request)?;
        Ok(response)
    }

    async fn exchange(
        &self,
        body: Vec<u8>,
    ) -> Result<(StatusCode, HeaderMap, Bytes), ForgeHttpClientError> {
        self.exchange_path(EFFECT_FACT_OUTBOX_PATH, body).await
    }

    async fn exchange_command(
        &self,
        op: CommandOp,
        body: Vec<u8>,
    ) -> Result<(StatusCode, HeaderMap, Bytes), ForgeHttpClientError> {
        let path = format!("/api/v1/commands/{}", op.as_str());
        self.exchange_path(&path, body).await
    }

    async fn mutation_exchange(
        &self,
        op: CommandOp,
        body: Vec<u8>,
        request_id: Uuid,
        request: ForgeHttpMutationRequest,
    ) -> Result<Value, ForgeHttpMutationError> {
        let result = match tokio::time::timeout(self.timeout, self.exchange_command(op, body)).await
        {
            Ok(Ok(result)) => result,
            Ok(Err(error)) => {
                return Err(ForgeHttpMutationError::UnknownOutcome {
                    request,
                    cause: error,
                });
            }
            Err(_) => {
                return Err(ForgeHttpMutationError::UnknownOutcome {
                    request,
                    cause: ForgeHttpClientError::Timeout,
                });
            }
        };
        decode_mutation_command_response(result, request_id, request)
    }

    async fn exchange_path(
        &self,
        path: &str,
        body: Vec<u8>,
    ) -> Result<(StatusCode, HeaderMap, Bytes), ForgeHttpClientError> {
        let stream = TcpStream::connect(self.authority)
            .await
            .map_err(|_| ForgeHttpClientError::Transport)?;
        let mut builder = hyper::client::conn::http1::Builder::new();
        builder
            .max_headers(MAX_HEADER_FIELDS)
            .max_buf_size(MAX_HEADER_BYTES);
        let (mut sender, connection) = builder
            .handshake::<_, Full<Bytes>>(TokioIo::new(stream))
            .await
            .map_err(|_| ForgeHttpClientError::Transport)?;
        let request = Request::builder()
            .method(Method::POST)
            .uri(path)
            .header(HOST, self.authority.to_string())
            .header(CONTENT_TYPE, "application/json")
            .header(CONTENT_LENGTH, body.len().to_string())
            .header(CONNECTION, "close")
            .header(AUTHORIZATION, self.service_bearer.clone())
            .body(Full::new(Bytes::from(body)))
            .map_err(|_| ForgeHttpClientError::Request)?;
        if request.headers().len() > MAX_HEADER_FIELDS
            || header_bytes(request.headers()) > MAX_HEADER_BYTES
        {
            return Err(ForgeHttpClientError::Request);
        }
        let exchange = async move {
            let response = sender
                .send_request(request)
                .await
                .map_err(|_| ForgeHttpClientError::Transport)?;
            if response.headers().len() > MAX_HEADER_FIELDS
                || header_bytes(response.headers()) > MAX_HEADER_BYTES
            {
                return Err(ForgeHttpClientError::ResponseHeadersTooLarge);
            }
            if !json_content_type(response.headers()) {
                return Err(ForgeHttpClientError::Protocol);
            }
            let status = response.status();
            let headers = response.headers().clone();
            let body = Limited::new(response.into_body(), MAX_CLIENT_RESPONSE_BYTES)
                .collect()
                .await
                .map_err(|_| ForgeHttpClientError::ResponseTooLarge)?
                .to_bytes();
            Ok::<_, ForgeHttpClientError>((status, headers, body))
        };
        let mut connection = Box::pin(connection);
        let mut exchange = Box::pin(exchange);
        tokio::select! {
            result = &mut exchange => result,
            _connection_result = &mut connection => exchange.await,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SuccessReply {
    forge_api: u32,
    request_id: Uuid,
    ok: bool,
    result: Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FailureError {
    code: String,
    #[serde(rename = "message")]
    _message: String,
    #[serde(rename = "category")]
    _category: String,
    #[serde(rename = "retryable")]
    _retryable: bool,
    #[serde(rename = "recovery_action")]
    _recovery_action: String,
    #[serde(rename = "recovery_hint")]
    _recovery_hint: String,
    #[serde(rename = "readback")]
    _readback: Option<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FailureReply {
    forge_api: u32,
    request_id: Uuid,
    ok: bool,
    error: FailureError,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Reply {
    Success(SuccessReply),
    Failure(FailureReply),
}

fn migration_scope_payload(scope: &ResolvedWorkspaceScope) -> Result<Value, ForgeHttpClientError> {
    let relative_root = scope
        .locator()
        .relative_root()
        .to_str()
        .ok_or(ForgeHttpClientError::InvalidRequest)?;
    Ok(json!({
        "workspace_id": scope.workspace_id().into_uuid(),
        "workspace_revision": scope.workspace_revision().get(),
        "locator": {
            "location_id": scope.locator().location_id().into_uuid(),
            "expected_revision": scope.locator().expected_revision().get(),
            "relative_root": relative_root,
        },
    }))
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "The payload is assembled into an owned bounded HTTP envelope."
)]
fn migration_request_body(
    op: CommandOp,
    scope: Value,
    fields: Value,
    request_id: Uuid,
) -> Result<Vec<u8>, ForgeHttpClientError> {
    let mut payload = fields
        .as_object()
        .cloned()
        .ok_or(ForgeHttpClientError::InvalidRequest)?;
    payload.insert("scope".to_owned(), scope);
    let envelope = json!({
        "forge_api": FORGE_API_VERSION,
        "request_id": request_id,
        "op": op.as_str(),
        "payload": Value::Object(payload),
    });
    let body = to_vec(&envelope).map_err(|_| ForgeHttpClientError::Request)?;
    if body.len() > MAX_REQUEST_BYTES {
        return Err(ForgeHttpClientError::RequestTooLarge);
    }
    Ok(body)
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "The payload is assembled into an owned bounded HTTP envelope."
)]
fn root_recovery_request_body(
    op: CommandOp,
    payload: Value,
    request_id: Uuid,
) -> Result<Vec<u8>, ForgeHttpClientError> {
    let envelope = json!({
        "forge_api": FORGE_API_VERSION,
        "request_id": request_id,
        "op": op.as_str(),
        "payload": payload,
    });
    let body = to_vec(&envelope).map_err(|_| ForgeHttpClientError::Request)?;
    if body.len() > MAX_REQUEST_BYTES {
        return Err(ForgeHttpClientError::RequestTooLarge);
    }
    Ok(body)
}

fn decode_command_response(
    (status, _headers, body): (StatusCode, HeaderMap, Bytes),
    request_id: Uuid,
) -> Result<Value, ForgeHttpClientError> {
    if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
        return Err(ForgeHttpClientError::Authentication);
    }
    let reply: Reply = from_slice(&body).map_err(|_| ForgeHttpClientError::Protocol)?;
    match reply {
        Reply::Success(reply) => {
            if status != StatusCode::OK
                || reply.forge_api != FORGE_API_VERSION
                || reply.request_id != request_id
                || !reply.ok
            {
                return Err(ForgeHttpClientError::Protocol);
            }
            Ok(reply.result)
        }
        Reply::Failure(reply) => {
            if status == StatusCode::OK
                || reply.forge_api != FORGE_API_VERSION
                || reply.request_id != request_id
                || reply.ok
            {
                return Err(ForgeHttpClientError::Protocol);
            }
            let code = ForgeHttpServiceCode::from_wire_code(reply.error.code.as_str());
            if status == StatusCode::UNAUTHORIZED
                || status == StatusCode::FORBIDDEN
                || matches!(code, ForgeHttpServiceCode::AuthFailed)
            {
                return Err(ForgeHttpClientError::Authentication);
            }
            Err(ForgeHttpClientError::Service {
                status: status.as_u16(),
                code,
            })
        }
    }
}

fn decode_mutation_command_response(
    (status, headers, body): (StatusCode, HeaderMap, Bytes),
    request_id: Uuid,
    request: ForgeHttpMutationRequest,
) -> Result<Value, ForgeHttpMutationError> {
    if status.is_server_error() {
        return Err(ForgeHttpMutationError::UnknownOutcome {
            request,
            cause: ForgeHttpClientError::Service {
                status: status.as_u16(),
                code: ForgeHttpServiceCode::ForgeUnavailable,
            },
        });
    }
    if status == StatusCode::REQUEST_TIMEOUT {
        return Err(ForgeHttpMutationError::UnknownOutcome {
            request,
            cause: ForgeHttpClientError::Service {
                status: status.as_u16(),
                code: ForgeHttpServiceCode::ForgeUnavailable,
            },
        });
    }
    match decode_command_response((status, headers, body), request_id) {
        Ok(value) => Ok(value),
        Err(ForgeHttpClientError::Authentication) => Err(ForgeHttpMutationError::Rejected(
            ForgeHttpClientError::Authentication,
        )),
        Err(ForgeHttpClientError::Service { status, code })
            if status < 500 && !matches!(code, ForgeHttpServiceCode::UnknownOutcome) =>
        {
            Err(ForgeHttpMutationError::Rejected(
                ForgeHttpClientError::Service { status, code },
            ))
        }
        Err(error) => Err(ForgeHttpMutationError::UnknownOutcome {
            request,
            cause: error,
        }),
    }
}

fn validate_scope_echo(
    actual: &crate::ops::ScopeDto,
    expected: &ResolvedWorkspaceScope,
) -> Result<(), ForgeHttpClientError> {
    let relative_root = expected
        .locator()
        .relative_root()
        .to_str()
        .ok_or(ForgeHttpClientError::InvalidRequest)?;
    if actual.workspace_id != expected.workspace_id().into_uuid()
        || actual.workspace_revision != expected.workspace_revision().get()
        || actual.locator.location_id != expected.locator().location_id().into_uuid()
        || actual.locator.expected_revision != expected.locator().expected_revision().get()
        || actual.locator.relative_root != relative_root
    {
        return Err(ForgeHttpClientError::Protocol);
    }
    Ok(())
}

fn validate_freeze_wire(
    value: &crate::ops::agent_operations_migration::AgentOperationsFreezeWire,
    scope: &ResolvedWorkspaceScope,
    migration_id: Uuid,
    destination_id: Uuid,
    backend_id: forge_domain::ForgeBackendId,
) -> Result<(), ForgeHttpClientError> {
    if value.backend_id != backend_id.into_uuid()
        || value.workspace_id != scope.workspace_id().into_uuid()
        || value.migration_id != migration_id
        || value.destination_id != destination_id
        || value.revision == 0
        || value.created_at_ms < 0
        || value.updated_at_ms < value.created_at_ms
    {
        return Err(ForgeHttpClientError::Protocol);
    }
    validate_scope_echo(&value.scope, scope)
}

fn validate_freeze_create_wire(
    value: &crate::ops::agent_operations_migration::AgentOperationsFreezeWire,
    scope: &ResolvedWorkspaceScope,
    migration_id: Uuid,
    destination_id: Uuid,
    observed_at_ms: i64,
    backend_id: forge_domain::ForgeBackendId,
) -> Result<(), ForgeHttpClientError> {
    validate_freeze_wire(value, scope, migration_id, destination_id, backend_id)?;
    if value.created_at_ms != observed_at_ms {
        return Err(ForgeHttpClientError::Protocol);
    }
    match value.state {
        crate::ops::agent_operations_migration::wire::FreezeStateWire::Frozen => {
            if value.revision != 1 || value.updated_at_ms != observed_at_ms {
                return Err(ForgeHttpClientError::Protocol);
            }
        }
        crate::ops::agent_operations_migration::wire::FreezeStateWire::Released => {
            if value.revision != 2 || value.updated_at_ms < observed_at_ms {
                return Err(ForgeHttpClientError::Protocol);
            }
        }
    }
    Ok(())
}

fn validate_freeze_release_wire(
    value: &crate::ops::agent_operations_migration::AgentOperationsFreezeWire,
    scope: &ResolvedWorkspaceScope,
    migration_id: Uuid,
    destination_id: Uuid,
    expected_revision: u64,
    observed_at_ms: i64,
    backend_id: forge_domain::ForgeBackendId,
) -> Result<(), ForgeHttpClientError> {
    validate_freeze_wire(value, scope, migration_id, destination_id, backend_id)?;
    if value.state != crate::ops::agent_operations_migration::wire::FreezeStateWire::Released
        || value.revision != expected_revision.saturating_add(1)
        || value.updated_at_ms != observed_at_ms
        || value.created_at_ms > observed_at_ms
    {
        return Err(ForgeHttpClientError::Protocol);
    }
    Ok(())
}

fn validate_freeze_get_wire(
    value: &crate::ops::agent_operations_migration::AgentOperationsFreezeGetResponseWire,
    scope: &ResolvedWorkspaceScope,
    migration_id: Uuid,
    destination_id: Uuid,
    backend_id: forge_domain::ForgeBackendId,
) -> Result<(), ForgeHttpClientError> {
    if value.backend_id != backend_id.into_uuid()
        || value.workspace_id != scope.workspace_id().into_uuid()
        || value.migration_id != migration_id
        || value.destination_id != destination_id
    {
        return Err(ForgeHttpClientError::Protocol);
    }
    validate_scope_echo(&value.scope, scope)?;
    if let Some(freeze) = &value.freeze {
        validate_freeze_wire(freeze, scope, migration_id, destination_id, backend_id)?;
    }
    Ok(())
}

fn validate_export_wire(
    value: &crate::ops::agent_operations_migration::AgentOperationsExportPageWire,
    scope: &ResolvedWorkspaceScope,
    migration_id: Uuid,
    destination_id: Uuid,
    requested_cursor: forge_persistence::AgentOperationsExportCursor,
    backend_id: forge_domain::ForgeBackendId,
) -> Result<(), ForgeHttpClientError> {
    if value.backend_id != backend_id.into_uuid()
        || value.workspace_id != scope.workspace_id().into_uuid()
        || value.migration_id != migration_id
        || value.destination_id != destination_id
        || value.freeze_revision == 0
        || value.records.len() > MIGRATION_MAX_PAGE_ROWS
        || value.requested_cursor
            != crate::ops::agent_operations_migration::ExportCursorWire::from(requested_cursor)
    {
        return Err(ForgeHttpClientError::Protocol);
    }
    validate_scope_echo(&value.scope, scope)?;
    validate_cursor_transition(value)?;
    validate_records(value, scope.workspace_id().into_uuid())
}

fn validate_cursor_transition(
    value: &crate::ops::agent_operations_migration::AgentOperationsExportPageWire,
) -> Result<(), ForgeHttpClientError> {
    let requested = cursor_family(&value.requested_cursor);
    for record in &value.records {
        if record_family(record) != requested {
            return Err(ForgeHttpClientError::Protocol);
        }
    }
    if let Some(next) = value.next_cursor.as_ref() {
        let next_family = cursor_family(next);
        if next_family != requested && next_family != requested.saturating_add(1) {
            return Err(ForgeHttpClientError::Protocol);
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_records(
    value: &crate::ops::agent_operations_migration::AgentOperationsExportPageWire,
    workspace_id: Uuid,
) -> Result<(), ForgeHttpClientError> {
    use crate::ops::agent_operations_migration::AgentOperationsExportRecordWire as Record;
    let mut previous_id = None;
    let mut previous_inbox = None;
    for record in &value.records {
        match record {
            Record::Participant {
                agent_id,
                workspace_id: actual,
                principal,
                focus,
                display_name,
                declared_role,
                created_at_ms,
                updated_at_ms,
                revision,
                ..
            } => {
                if *actual != workspace_id
                    || *created_at_ms < 0
                    || *updated_at_ms < *created_at_ms
                    || *revision < 1
                    || display_name.trim().is_empty()
                    || declared_role.trim().is_empty()
                    || !valid_principal(principal)
                    || !valid_focus(focus)
                    || previous_id.is_some_and(|previous| previous >= *agent_id)
                {
                    return Err(ForgeHttpClientError::Protocol);
                }
                previous_id = Some(*agent_id);
            }
            Record::Presence {
                agent_id,
                workspace_id: actual,
                last_seen_ms,
                revision,
                ..
            } => {
                if *actual != workspace_id
                    || *last_seen_ms < 0
                    || *revision < 1
                    || previous_id.is_some_and(|previous| previous >= *agent_id)
                {
                    return Err(ForgeHttpClientError::Protocol);
                }
                previous_id = Some(*agent_id);
            }
            Record::Event {
                event_id,
                workspace_id: actual,
                membership_revision,
                from,
                to,
                coordination_before,
                coordination_after,
                coordinator_before,
                coordinator_after,
                observed_at_ms,
                ..
            } => {
                if *actual != workspace_id
                    || *membership_revision < 1
                    || *observed_at_ms < 0
                    || previous_id.is_some_and(|previous| previous >= *event_id)
                    || !from.as_ref().is_none_or(valid_participant_ref)
                    || !to.as_ref().is_none_or(valid_participant_ref)
                    || !valid_coordination(coordination_before)
                    || !valid_coordination(coordination_after)
                    || !valid_coordinator_snapshot(coordinator_before)
                    || !valid_coordinator_snapshot(coordinator_after)
                {
                    return Err(ForgeHttpClientError::Protocol);
                }
                previous_id = Some(*event_id);
            }
            Record::Inbox {
                recipient_agent_id,
                recipient_session_id,
                event_id,
                revision,
                acknowledged_at_ms,
            } => {
                let key = (*recipient_agent_id, *recipient_session_id, *event_id);
                if *revision < 1
                    || acknowledged_at_ms.is_some_and(|at| at < 0)
                    || previous_inbox.is_some_and(|previous| previous >= key)
                {
                    return Err(ForgeHttpClientError::Protocol);
                }
                previous_inbox = Some(key);
            }
            Record::Coordinator {
                workspace_id: actual,
                activity_id,
                revision,
                updated_at_ms,
                ..
            } => {
                if *actual != workspace_id
                    || *revision < 1
                    || *updated_at_ms < 0
                    || previous_id.is_some_and(|previous| previous >= *activity_id)
                {
                    return Err(ForgeHttpClientError::Protocol);
                }
                previous_id = Some(*activity_id);
            }
        }
    }
    Ok(())
}

fn cursor_family(cursor: &crate::ops::agent_operations_migration::ExportCursorWire) -> u8 {
    use crate::ops::agent_operations_migration::ExportCursorWire;
    match cursor {
        ExportCursorWire::Participants { .. } => 0,
        ExportCursorWire::Presence { .. } => 1,
        ExportCursorWire::Events { .. } => 2,
        ExportCursorWire::Inbox { .. } => 3,
        ExportCursorWire::Coordinators { .. } => 4,
    }
}

fn record_family(
    record: &crate::ops::agent_operations_migration::AgentOperationsExportRecordWire,
) -> u8 {
    use crate::ops::agent_operations_migration::AgentOperationsExportRecordWire;
    match record {
        AgentOperationsExportRecordWire::Participant { .. } => 0,
        AgentOperationsExportRecordWire::Presence { .. } => 1,
        AgentOperationsExportRecordWire::Event { .. } => 2,
        AgentOperationsExportRecordWire::Inbox { .. } => 3,
        AgentOperationsExportRecordWire::Coordinator { .. } => 4,
    }
}

fn valid_principal(value: &crate::ops::agent_operations_migration::PrincipalWire) -> bool {
    use crate::ops::agent_operations_migration::PrincipalKindWire;
    match value.kind {
        PrincipalKindWire::TrustedStdio => value.token_id.is_none() && value.grant_id.is_none(),
        PrincipalKindWire::DirectToken => value.token_id.is_some() && value.grant_id.is_none(),
        PrincipalKindWire::OAuthGrant => value.grant_id.is_some() && value.token_id.is_none(),
    }
}

fn valid_focus(value: &crate::ops::agent_operations_migration::FocusWire) -> bool {
    let goal = value.goal_id.is_some();
    let dag = value.dag_revision.is_some();
    let node = value.node_id.is_some();
    goal == value.goal_revision.is_some()
        && node == value.node_revision.is_some()
        && value.goal_revision.is_none_or(|revision| revision >= 1)
        && value.dag_revision.is_none_or(|revision| revision >= 1)
        && value.node_revision.is_none_or(|revision| revision >= 1)
        && (!dag || goal)
        && (!node || dag)
}

fn valid_participant_ref(
    value: &crate::ops::agent_operations_migration::ParticipantRefWire,
) -> bool {
    valid_principal(&value.principal)
}

fn valid_coordination(value: &crate::ops::agent_operations_migration::CoordinationWire) -> bool {
    let goal = value.goal_id.is_some();
    let dag = value.dag_revision.is_some();
    let head = value.dag_head_revision.is_some();
    let node = value.node_id.is_some();
    goal == value.goal_revision.is_some()
        && dag == head
        && value.goal_revision.is_none_or(|revision| revision >= 1)
        && value.dag_revision.is_none_or(|revision| revision >= 1)
        && value.dag_head_revision.is_none_or(|revision| revision >= 1)
        && value.node_revision.is_none_or(|revision| revision >= 1)
        && (!dag || goal)
        && (!node || dag)
}

fn valid_coordinator_snapshot(
    value: &crate::ops::agent_operations_migration::CoordinatorSnapshotWire,
) -> bool {
    value.agent_id.is_some() == value.revision.is_some()
        && value.revision.is_none_or(|revision| revision >= 1)
}

fn request_body(
    request: &EffectFactOutboxReadRequest,
    request_id: Uuid,
) -> Result<Vec<u8>, ForgeHttpClientError> {
    let relative_root = request
        .scope
        .locator()
        .relative_root()
        .to_str()
        .ok_or(ForgeHttpClientError::InvalidRequest)?;
    let payload = json!({
        "scope": {
            "workspace_id": request.scope.workspace_id().into_uuid(),
            "workspace_revision": request.scope.workspace_revision().get(),
            "locator": {
                "location_id": request.scope.locator().location_id().into_uuid(),
                "expected_revision": request.scope.locator().expected_revision().get(),
                "relative_root": relative_root,
            },
        },
        "migration_id": request.migration_id,
        "destination_id": request.destination_id,
        "after": request.after,
        "limit": request.limit,
    });
    let envelope = json!({
        "forge_api": FORGE_API_VERSION,
        "request_id": request_id,
        "op": "effect_fact.outbox",
        "payload": payload,
    });
    let body = to_vec(&envelope).map_err(|_| ForgeHttpClientError::Request)?;
    if body.len() > MAX_REQUEST_BYTES {
        return Err(ForgeHttpClientError::RequestTooLarge);
    }
    Ok(body)
}

fn decode_response(
    (status, _headers, body): (StatusCode, HeaderMap, Bytes),
    request: &EffectFactOutboxReadRequest,
    request_id: Uuid,
    expected_backend_id: ForgeBackendId,
) -> Result<crate::ops::effect_facts::wire::EffectFactOutboxResponse, ForgeHttpClientError> {
    if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
        return Err(ForgeHttpClientError::Authentication);
    }
    let reply: Reply = from_slice(&body).map_err(|_| ForgeHttpClientError::Protocol)?;
    match reply {
        Reply::Success(reply) => {
            if status != StatusCode::OK
                || reply.forge_api != FORGE_API_VERSION
                || reply.request_id != request_id
                || !reply.ok
            {
                return Err(ForgeHttpClientError::Protocol);
            }
            let response =
                serde_json::from_value(reply.result).map_err(|_| ForgeHttpClientError::Protocol)?;
            validate_response(&response, request, expected_backend_id)?;
            Ok(response)
        }
        Reply::Failure(reply) => {
            if status == StatusCode::OK
                || reply.forge_api != FORGE_API_VERSION
                || reply.request_id != request_id
                || reply.ok
            {
                return Err(ForgeHttpClientError::Protocol);
            }
            let code = ForgeHttpServiceCode::from_wire_code(reply.error.code.as_str());
            if status == StatusCode::UNAUTHORIZED
                || status == StatusCode::FORBIDDEN
                || matches!(code, ForgeHttpServiceCode::AuthFailed)
            {
                return Err(ForgeHttpClientError::Authentication);
            }
            Err(ForgeHttpClientError::Service {
                status: status.as_u16(),
                code,
            })
        }
    }
}

fn validate_request(
    request: &EffectFactOutboxReadRequest,
    trusted_destination_id: Uuid,
) -> Result<(), ForgeHttpClientError> {
    if request.limit == 0 || request.limit > MAX_EFFECT_FACT_PAGE {
        return Err(ForgeHttpClientError::InvalidRequest);
    }
    if request.after > i64::MAX as u64
        || request.migration_id.is_nil()
        || request.destination_id.is_nil()
        || request.destination_id != trusted_destination_id
        || request.scope.workspace_id().into_uuid().is_nil()
        || request.scope.locator().location_id().into_uuid().is_nil()
    {
        return Err(if request.destination_id == trusted_destination_id {
            ForgeHttpClientError::InvalidRequest
        } else {
            ForgeHttpClientError::DestinationMismatch
        });
    }
    Ok(())
}

fn validate_response(
    response: &crate::ops::effect_facts::wire::EffectFactOutboxResponse,
    request: &EffectFactOutboxReadRequest,
    expected_backend_id: ForgeBackendId,
) -> Result<(), ForgeHttpClientError> {
    let relative_root = request
        .scope
        .locator()
        .relative_root()
        .to_str()
        .ok_or(ForgeHttpClientError::InvalidRequest)?;
    if response.backend_id != expected_backend_id.into_uuid()
        || response.migration_id != request.migration_id
        || response.destination_id != request.destination_id
        || response.after != request.after
        || response.scope.workspace_id != request.scope.workspace_id().into_uuid()
        || response.scope.workspace_revision != request.scope.workspace_revision().get()
        || response.scope.locator.location_id != request.scope.locator().location_id().into_uuid()
        || response.scope.locator.expected_revision
            != request.scope.locator().expected_revision().get()
        || response.scope.locator.relative_root != relative_root
        || response.entries.len() > usize::try_from(request.limit).unwrap_or(usize::MAX)
    {
        return Err(ForgeHttpClientError::Protocol);
    }
    let mut previous = request.after;
    for entry in &response.entries {
        if entry.sequence <= previous
            || entry.migration_id != request.migration_id
            || entry.destination_id != request.destination_id
            || entry.workspace_id != request.scope.workspace_id().into_uuid()
        {
            return Err(ForgeHttpClientError::Protocol);
        }
        previous = entry.sequence;
        validate_entry(entry)?;
    }
    Ok(())
}

fn validate_entry(
    entry: &crate::ops::effect_facts::wire::EffectFactOutboxEntryWire,
) -> Result<(), ForgeHttpClientError> {
    use crate::ops::effect_facts::wire::EffectFactWire;
    if entry.sequence == 0
        || entry.sequence > i64::MAX as u64
        || entry.migration_id.is_nil()
        || entry.destination_id.is_nil()
        || entry.workspace_id.is_nil()
    {
        return Err(ForgeHttpClientError::Protocol);
    }
    match &entry.fact {
        EffectFactWire::ExecutionTerminal { .. } => validate_execution_entry(entry),
        EffectFactWire::ChangeSetTerminal { .. } => validate_change_set_entry(entry),
        EffectFactWire::AssignmentReviewed { .. } => validate_assignment_reviewed(entry),
        EffectFactWire::AssignmentOffered { .. } => validate_assignment_offered(entry),
        EffectFactWire::AssignmentSubmitted { .. } => validate_assignment_submitted(entry),
    }
}

fn validate_execution_entry(
    entry: &crate::ops::effect_facts::wire::EffectFactOutboxEntryWire,
) -> Result<(), ForgeHttpClientError> {
    let crate::ops::effect_facts::wire::EffectFactWire::ExecutionTerminal {
        execution_id,
        activity_id,
        execution_revision,
        observed_at_ms,
        agent_id,
        agent_revision,
        session_id,
        goal_id,
        goal_revision,
        dag_revision,
        node_id,
        node_revision,
        verification,
        state,
    } = &entry.fact
    else {
        return Err(ForgeHttpClientError::Protocol);
    };
    if matches!(
        state,
        crate::ops::effect_facts::wire::ExecutionStateWire::Starting
            | crate::ops::effect_facts::wire::ExecutionStateWire::Running
    ) || !all_ids(&[*execution_id, *activity_id, *agent_id, *goal_id, *node_id])
        || !optional_id(*session_id)
        || !positive(&[
            *execution_revision,
            *agent_revision,
            *goal_revision,
            *dag_revision,
            *node_revision,
        ])
        || *observed_at_ms < 0
    {
        return Err(ForgeHttpClientError::Protocol);
    }
    verification
        .as_ref()
        .map(validate_verification)
        .transpose()?;
    reject_non_submitted_refs(entry)
}

fn validate_change_set_entry(
    entry: &crate::ops::effect_facts::wire::EffectFactOutboxEntryWire,
) -> Result<(), ForgeHttpClientError> {
    let crate::ops::effect_facts::wire::EffectFactWire::ChangeSetTerminal {
        change_set_id,
        workspace_id,
        workspace_revision,
        activity_id,
        runtime_instance_id,
        activity_lease_revision,
        change_set_revision,
        state,
        failure_code,
        diff_id,
        diff_state,
        diff_revision,
        observed_at_ms,
        producer_agent_id,
        producer_session_id,
    } = &entry.fact
    else {
        return Err(ForgeHttpClientError::Protocol);
    };
    if !all_ids(&[
        *change_set_id,
        *workspace_id,
        *activity_id,
        *runtime_instance_id,
        *diff_id,
    ]) || !optional_id(*producer_agent_id)
        || !optional_id(*producer_session_id)
        || (producer_agent_id.is_none() && producer_session_id.is_some())
        || !positive(&[
            *workspace_revision,
            *activity_lease_revision,
            *change_set_revision,
            *diff_revision,
        ])
        || *observed_at_ms < 0
        || matches!(
            state,
            crate::ops::effect_facts::wire::ChangeSetStateWire::Starting
        )
        || matches!(
            diff_state,
            crate::ops::effect_facts::wire::DiffEvidenceStateWire::Intent
                | crate::ops::effect_facts::wire::DiffEvidenceStateWire::PurgePending
                | crate::ops::effect_facts::wire::DiffEvidenceStateWire::Tombstoned
        )
        || matches!(
            (state, failure_code),
            (
                crate::ops::effect_facts::wire::ChangeSetStateWire::Applied,
                Some(_)
            ) | (
                crate::ops::effect_facts::wire::ChangeSetStateWire::Failed,
                None
            )
        )
        || *workspace_id != entry.workspace_id
    {
        return Err(ForgeHttpClientError::Protocol);
    }
    reject_non_submitted_refs(entry)
}

fn validate_assignment_reviewed(
    entry: &crate::ops::effect_facts::wire::EffectFactOutboxEntryWire,
) -> Result<(), ForgeHttpClientError> {
    let crate::ops::effect_facts::wire::EffectFactWire::AssignmentReviewed {
        assignment_id,
        workspace_id,
        activity_id,
        goal_id,
        node_id,
        target_agent_id,
        target_session_id,
        reviewer_agent_id,
        reviewer_session_id,
        result_digest,
        observed_at_ms,
        ..
    } = &entry.fact
    else {
        return Err(ForgeHttpClientError::Protocol);
    };
    if !all_ids(&[
        *assignment_id,
        *workspace_id,
        *activity_id,
        *goal_id,
        *node_id,
        *target_agent_id,
        *reviewer_agent_id,
    ]) || !optional_id(*target_session_id)
        || !optional_id(*reviewer_session_id)
        || !optional_hash(result_digest.as_deref())
        || *observed_at_ms < 0
        || *workspace_id != entry.workspace_id
    {
        return Err(ForgeHttpClientError::Protocol);
    }
    reject_non_submitted_refs(entry)
}

fn validate_assignment_offered(
    entry: &crate::ops::effect_facts::wire::EffectFactOutboxEntryWire,
) -> Result<(), ForgeHttpClientError> {
    let crate::ops::effect_facts::wire::EffectFactWire::AssignmentOffered {
        assignment_id,
        workspace_id,
        activity_id,
        goal_id,
        node_id,
        target_agent_id,
        target_session_id,
        offered_at_ms,
        ..
    } = &entry.fact
    else {
        return Err(ForgeHttpClientError::Protocol);
    };
    if !all_ids(&[
        *assignment_id,
        *workspace_id,
        *activity_id,
        *goal_id,
        *node_id,
        *target_agent_id,
    ]) || !optional_id(*target_session_id)
        || *offered_at_ms < 0
        || *workspace_id != entry.workspace_id
    {
        return Err(ForgeHttpClientError::Protocol);
    }
    reject_non_submitted_refs(entry)
}

fn validate_assignment_submitted(
    entry: &crate::ops::effect_facts::wire::EffectFactOutboxEntryWire,
) -> Result<(), ForgeHttpClientError> {
    let crate::ops::effect_facts::wire::EffectFactWire::AssignmentSubmitted {
        assignment_id,
        workspace_id,
        activity_id,
        goal_id,
        node_id,
        target_agent_id,
        target_session_id,
        source_count,
        source_digests,
        source_kinds,
        result_digest,
        submitted_at_ms,
    } = &entry.fact
    else {
        return Err(ForgeHttpClientError::Protocol);
    };
    if !all_ids(&[
        *assignment_id,
        *workspace_id,
        *activity_id,
        *goal_id,
        *node_id,
        *target_agent_id,
    ]) || !optional_id(*target_session_id)
        || usize::from(*source_count) > 32
        || !optional_hash(result_digest.as_deref())
        || *submitted_at_ms < 0
        || *workspace_id != entry.workspace_id
        || !source_shape(
            *source_count,
            source_digests.as_deref(),
            source_kinds.as_deref(),
        )
    {
        return Err(ForgeHttpClientError::Protocol);
    }
    validate_submitted_source_refs(entry, *source_count, source_kinds.as_deref())
}

fn reject_non_submitted_refs(
    entry: &crate::ops::effect_facts::wire::EffectFactOutboxEntryWire,
) -> Result<(), ForgeHttpClientError> {
    if entry.submitted_source_refs.is_some() {
        return Err(ForgeHttpClientError::Protocol);
    }
    Ok(())
}

fn validate_submitted_source_refs(
    entry: &crate::ops::effect_facts::wire::EffectFactOutboxEntryWire,
    source_count: u8,
    source_kinds: Option<&[crate::ops::effect_facts::wire::SourceKindWire]>,
) -> Result<(), ForgeHttpClientError> {
    let Some(refs) = entry.submitted_source_refs.as_deref() else {
        return Ok(());
    };
    if source_count == 0 && source_kinds.is_none() && refs.is_empty() {
        return Ok(());
    }
    let Some(kinds) = source_kinds else {
        return Err(ForgeHttpClientError::Protocol);
    };
    let expected_refs = kinds
        .iter()
        .filter(|kind| {
            matches!(
                kind,
                crate::ops::effect_facts::wire::SourceKindWire::Provenance
            )
        })
        .count();
    if refs.len() != expected_refs {
        return Err(ForgeHttpClientError::Protocol);
    }
    let mut previous = None;
    for (reference_index, reference) in refs.iter().enumerate() {
        if usize::from(reference.ordinal) >= usize::from(source_count)
            || previous.is_some_and(|value| value >= reference.ordinal)
            || reference.evidence.id.is_nil()
            || !matches!(
                kinds[usize::from(reference.ordinal)],
                crate::ops::effect_facts::wire::SourceKindWire::Provenance
            )
            || usize::from(reference.ordinal)
                != kinds
                    .iter()
                    .enumerate()
                    .filter(|(_, kind)| {
                        matches!(
                            kind,
                            crate::ops::effect_facts::wire::SourceKindWire::Provenance
                        )
                    })
                    .nth(reference_index)
                    .map_or(usize::MAX, |(ordinal, _)| ordinal)
        {
            return Err(ForgeHttpClientError::Protocol);
        }
        previous = Some(reference.ordinal);
    }
    Ok(())
}

fn validate_verification(
    value: &crate::ops::effect_facts::wire::VerificationEvidenceWire,
) -> Result<(), ForgeHttpClientError> {
    if value.input_id.is_nil()
        || !hash(&value.input_fingerprint)
        || value.output_integrity.is_some() != value.output_fingerprint.is_some()
        || value
            .output_fingerprint
            .as_deref()
            .is_some_and(|fingerprint| !hash(fingerprint))
        || (!matches!(
            value.disposition,
            crate::ops::effect_facts::wire::VerificationRunDispositionWire::RecoveryRequired
        ) && (value.output_integrity.is_none() || value.output_fingerprint.is_none()))
    {
        return Err(ForgeHttpClientError::Protocol);
    }
    Ok(())
}

fn source_shape(
    count: u8,
    digests: Option<&str>,
    kinds: Option<&[crate::ops::effect_facts::wire::SourceKindWire]>,
) -> bool {
    match (count, digests, kinds) {
        (0, None, None) => true,
        (1..=32, Some(digest), Some(kinds)) => hash(digest) && kinds.len() == usize::from(count),
        _ => false,
    }
}

fn all_ids(values: &[Uuid]) -> bool {
    values.iter().all(|value| !value.is_nil())
}

fn optional_id(value: Option<Uuid>) -> bool {
    value.is_none_or(|value| !value.is_nil())
}

fn positive(values: &[i64]) -> bool {
    values.iter().all(|value| *value > 0)
}

fn optional_hash(value: Option<&str>) -> bool {
    value.is_none_or(hash)
}

fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|value| matches!(value, b'0'..=b'9' | b'a'..=b'f'))
}

fn header_bytes(headers: &HeaderMap) -> usize {
    headers.iter().fold(0_usize, |total, (name, value)| {
        total
            .saturating_add(name.as_str().len())
            .saturating_add(value.as_bytes().len())
            .saturating_add(4)
    })
}

fn json_content_type(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
}

#[cfg(test)]
mod tests {
    use std::{
        error::Error,
        path::Path,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use axum::{
        Router,
        body::{Body, to_bytes},
        extract::State,
        http::{Request, header::HeaderValue},
        response::Response,
        routing::post,
    };
    use forge_control::{
        AgentOperationsFreezeRequest, EffectFactOutboxReadRequest, ResolvedWorkspaceScope,
        WorkspaceLocator,
    };
    use forge_domain::{
        ForgeBackendId, LocationId, LocationRevision, TimestampMillis, WorkspaceId,
        WorkspaceRevision,
    };
    use serde_json::Value;
    use tokio::sync::oneshot;

    use super::*;

    #[derive(Debug, Clone, Copy)]
    enum HostileResponse {
        WrongRequestId,
        WrongVersion,
        WrongBackend,
        WrongScope,
        WrongSequence,
        AcceptedWithoutOutput,
        IncompleteSourceReferences,
        UppercaseHash,
        MalformedFailure,
        ValidZeroSourceReferences,
        LegacySourceReferencesUnknown,
        RecoveryRequiredWithoutOutput,
        MissingSourceReferenceField,
        Oversized,
    }

    struct HostState {
        request: EffectFactOutboxReadRequest,
        backend_id: Uuid,
        modes: Vec<HostileResponse>,
        next_mode: Mutex<usize>,
    }

    struct HostHandle {
        address: SocketAddr,
        stop: oneshot::Sender<()>,
        join: tokio::task::JoinHandle<Result<(), std::io::Error>>,
    }

    fn request(after: u64) -> Result<EffectFactOutboxReadRequest, Box<dyn Error>> {
        let workspace = WorkspaceId::from_uuid(Uuid::from_u128(0x101));
        let locator = WorkspaceLocator::new(
            LocationId::from_uuid(Uuid::from_u128(0x102)),
            LocationRevision::INITIAL,
            Path::new("."),
        )?;
        Ok(EffectFactOutboxReadRequest {
            scope: ResolvedWorkspaceScope::from_observation(
                workspace,
                WorkspaceRevision::INITIAL,
                locator,
            ),
            migration_id: Uuid::from_u128(0x103),
            destination_id: Uuid::from_u128(0x104),
            after,
            limit: 1,
        })
    }

    fn scope_dto(scope: &ResolvedWorkspaceScope) -> crate::ops::ScopeDto {
        crate::ops::ScopeDto {
            workspace_id: scope.workspace_id().into_uuid(),
            workspace_revision: scope.workspace_revision().get(),
            locator: crate::ops::LocatorDto {
                location_id: scope.locator().location_id().into_uuid(),
                expected_revision: scope.locator().expected_revision().get(),
                relative_root: ".".to_owned(),
            },
        }
    }

    fn valid_page(
        request: &EffectFactOutboxReadRequest,
        backend_id: Uuid,
    ) -> crate::ops::effect_facts::wire::EffectFactOutboxResponse {
        crate::ops::effect_facts::wire::EffectFactOutboxResponse {
            scope: scope_dto(&request.scope),
            backend_id,
            migration_id: request.migration_id,
            destination_id: request.destination_id,
            after: request.after,
            entries: vec![crate::ops::effect_facts::wire::EffectFactOutboxEntryWire {
                sequence: request.after.saturating_add(1),
                migration_id: request.migration_id,
                destination_id: request.destination_id,
                workspace_id: request.scope.workspace_id().into_uuid(),
                fact: crate::ops::effect_facts::wire::EffectFactWire::AssignmentOffered {
                    assignment_id: Uuid::from_u128(0x105),
                    workspace_id: request.scope.workspace_id().into_uuid(),
                    activity_id: Uuid::from_u128(0x106),
                    goal_id: Uuid::from_u128(0x107),
                    node_id: Uuid::from_u128(0x108),
                    target_agent_id: Uuid::from_u128(0x109),
                    target_session_id: None,
                    credit_budget: Some(crate::ops::effect_facts::wire::WorkCreditBudgetWire::One),
                    offered_at_ms: 1,
                },
                submitted_source_refs: None,
            }],
        }
    }

    fn execution_fact(
        disposition: crate::ops::effect_facts::wire::VerificationRunDispositionWire,
    ) -> crate::ops::effect_facts::wire::EffectFactWire {
        crate::ops::effect_facts::wire::EffectFactWire::ExecutionTerminal {
            execution_id: Uuid::from_u128(0x105),
            activity_id: Uuid::from_u128(0x106),
            execution_revision: 2,
            state: crate::ops::effect_facts::wire::ExecutionStateWire::Completed,
            observed_at_ms: 1,
            agent_id: Uuid::from_u128(0x107),
            agent_revision: 2,
            session_id: None,
            goal_id: Uuid::from_u128(0x108),
            goal_revision: 1,
            dag_revision: 1,
            node_id: Uuid::from_u128(0x109),
            node_revision: 1,
            verification: Some(crate::ops::effect_facts::wire::VerificationEvidenceWire {
                input_id: Uuid::from_u128(0x10A),
                input_fingerprint: "aa".repeat(32),
                disposition,
                output_integrity: None,
                output_fingerprint: None,
            }),
        }
    }

    fn submitted_fact(
        request: &EffectFactOutboxReadRequest,
        source_digests: String,
    ) -> crate::ops::effect_facts::wire::EffectFactWire {
        crate::ops::effect_facts::wire::EffectFactWire::AssignmentSubmitted {
            assignment_id: Uuid::from_u128(0x105),
            workspace_id: request.scope.workspace_id().into_uuid(),
            activity_id: Uuid::from_u128(0x106),
            goal_id: Uuid::from_u128(0x107),
            node_id: Uuid::from_u128(0x108),
            target_agent_id: Uuid::from_u128(0x109),
            target_session_id: None,
            source_count: 1,
            source_digests: Some(source_digests),
            source_kinds: Some(vec![
                crate::ops::effect_facts::wire::SourceKindWire::Provenance,
            ]),
            result_digest: Some("11".repeat(32)),
            submitted_at_ms: 1,
        }
    }

    fn zero_source_fact(
        request: &EffectFactOutboxReadRequest,
    ) -> crate::ops::effect_facts::wire::EffectFactWire {
        crate::ops::effect_facts::wire::EffectFactWire::AssignmentSubmitted {
            assignment_id: Uuid::from_u128(0x105),
            workspace_id: request.scope.workspace_id().into_uuid(),
            activity_id: Uuid::from_u128(0x106),
            goal_id: Uuid::from_u128(0x107),
            node_id: Uuid::from_u128(0x108),
            target_agent_id: Uuid::from_u128(0x109),
            target_session_id: None,
            source_count: 0,
            source_digests: None,
            source_kinds: None,
            result_digest: None,
            submitted_at_ms: 1,
        }
    }

    async fn hostile_response(
        State(state): State<Arc<HostState>>,
        request: Request<Body>,
    ) -> Response {
        let body = to_bytes(request.into_body(), MAX_REQUEST_BYTES)
            .await
            .unwrap_or_default();
        let request_id = serde_json::from_slice::<Value>(&body)
            .ok()
            .and_then(|value| {
                value
                    .get("request_id")
                    .and_then(Value::as_str)
                    .and_then(|value| Uuid::parse_str(value).ok())
            })
            .unwrap_or_else(Uuid::nil);
        let mode = state
            .next_mode
            .lock()
            .map_or(HostileResponse::Oversized, |mut index| {
                let mode = state
                    .modes
                    .get(*index)
                    .copied()
                    .unwrap_or(HostileResponse::Oversized);
                *index = index.saturating_add(1);
                mode
            });
        hostile_response_for_mode(&state, mode, request_id)
    }

    fn hostile_response_for_mode(
        state: &HostState,
        mode: HostileResponse,
        mut response_id: Uuid,
    ) -> Response {
        if matches!(mode, HostileResponse::Oversized) {
            return json_response(
                StatusCode::OK,
                vec![b'x'; MAX_CLIENT_RESPONSE_BYTES.saturating_add(1)],
            );
        }
        let mut page = valid_page(&state.request, state.backend_id);
        let mut version = FORGE_API_VERSION;
        match mode {
            HostileResponse::WrongRequestId => response_id = Uuid::from_u128(0x201),
            HostileResponse::WrongVersion => version = FORGE_API_VERSION.saturating_add(1),
            HostileResponse::WrongBackend => page.backend_id = Uuid::from_u128(0x202),
            HostileResponse::WrongScope => page.scope.workspace_id = Uuid::from_u128(0x203),
            HostileResponse::WrongSequence => page.entries[0].sequence = state.request.after,
            HostileResponse::AcceptedWithoutOutput => {
                page.entries[0].fact = execution_fact(
                    crate::ops::effect_facts::wire::VerificationRunDispositionWire::Accepted,
                );
            }
            HostileResponse::IncompleteSourceReferences => {
                page.entries[0].fact = submitted_fact(&state.request, "00".repeat(32));
                page.entries[0].submitted_source_refs = Some(vec![
                    crate::ops::effect_facts::wire::AssignmentSubmittedSourceRefWire {
                        ordinal: 1,
                        evidence: crate::ops::effect_facts::wire::GoalEvidenceWire {
                            kind: crate::ops::effect_facts::wire::GoalEvidenceKindWire::Execution,
                            id: Uuid::from_u128(0x10A),
                        },
                    },
                ]);
            }
            HostileResponse::UppercaseHash => {
                page.entries[0].fact = submitted_fact(&state.request, "AA".repeat(32));
            }
            HostileResponse::MalformedFailure => {
                return json_response(
                    StatusCode::BAD_REQUEST,
                    serde_json::to_vec(&serde_json::json!({
                        "forge_api": FORGE_API_VERSION,
                        "request_id": response_id,
                        "ok": false,
                        "error": {"code": "AUTH_FAILED"},
                    }))
                    .unwrap_or_default(),
                );
            }
            HostileResponse::ValidZeroSourceReferences => {
                page.entries[0].fact = zero_source_fact(&state.request);
                page.entries[0].submitted_source_refs = Some(Vec::new());
            }
            HostileResponse::LegacySourceReferencesUnknown => {
                page.entries[0].fact = submitted_fact(&state.request, "00".repeat(32));
            }
            HostileResponse::RecoveryRequiredWithoutOutput => {
                page.entries[0].fact = execution_fact(
                    crate::ops::effect_facts::wire::VerificationRunDispositionWire::RecoveryRequired,
                );
            }
            HostileResponse::MissingSourceReferenceField => {}
            HostileResponse::Oversized => {
                return json_response(
                    StatusCode::OK,
                    vec![b'x'; MAX_CLIENT_RESPONSE_BYTES.saturating_add(1)],
                );
            }
        }
        let mut result = serde_json::to_value(page).unwrap_or_default();
        if matches!(mode, HostileResponse::MissingSourceReferenceField)
            && let Some(entry) = result
                .get_mut("entries")
                .and_then(Value::as_array_mut)
                .and_then(|entries| entries.get_mut(0))
                .and_then(Value::as_object_mut)
        {
            entry.remove("submitted_source_refs");
        }
        json_response(
            StatusCode::OK,
            serde_json::to_vec(&serde_json::json!({
                "forge_api": version,
                "request_id": response_id,
                "ok": true,
                "result": result,
            }))
            .unwrap_or_default(),
        )
    }

    fn json_response(status: StatusCode, body: Vec<u8>) -> Response {
        let mut response = Response::new(Body::from(body));
        *response.status_mut() = status;
        response
            .headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        response
    }

    async fn start_host(state: Arc<HostState>) -> Result<HostHandle, Box<dyn Error>> {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let (stop, stopped) = oneshot::channel();
        let router = Router::new()
            .route(EFFECT_FACT_OUTBOX_PATH, post(hostile_response))
            .with_state(state);
        let join = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async move {
                    let _ = stopped.await;
                })
                .await
        });
        Ok(HostHandle {
            address,
            stop,
            join,
        })
    }

    #[derive(Debug, Clone)]
    struct MigrationHostState {
        result: Value,
        calls: Arc<AtomicUsize>,
    }

    async fn migration_response(
        State(state): State<Arc<MigrationHostState>>,
        request: Request<Body>,
    ) -> Response {
        state.calls.fetch_add(1, Ordering::AcqRel);
        let body = to_bytes(request.into_body(), MAX_REQUEST_BYTES)
            .await
            .unwrap_or_default();
        let request_id = serde_json::from_slice::<Value>(&body)
            .ok()
            .and_then(|value| value.get("request_id").cloned())
            .unwrap_or(Value::Null);
        json_response(
            StatusCode::OK,
            serde_json::to_vec(&json!({
                "forge_api": FORGE_API_VERSION,
                "request_id": request_id,
                "ok": true,
                "result": state.result,
            }))
            .unwrap_or_default(),
        )
    }

    async fn start_migration_host(
        result: Value,
    ) -> Result<(HostHandle, Arc<AtomicUsize>), Box<dyn Error>> {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let (stop, stopped) = oneshot::channel();
        let calls = Arc::new(AtomicUsize::new(0));
        let state = Arc::new(MigrationHostState {
            result,
            calls: Arc::clone(&calls),
        });
        let router = Router::new()
            .route(
                "/api/v1/commands/agent.operations.freeze",
                post(migration_response),
            )
            .with_state(state);
        let join = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async move {
                    let _ = stopped.await;
                })
                .await
        });
        Ok((
            HostHandle {
                address,
                stop,
                join,
            },
            calls,
        ))
    }

    fn migration_request() -> Result<AgentOperationsFreezeRequest, Box<dyn Error>> {
        let source = request(0)?;
        Ok(AgentOperationsFreezeRequest {
            scope: source.scope,
            migration_id: Uuid::from_u128(0x301),
            destination_id: Uuid::from_u128(0x302),
            observed_at: TimestampMillis::new(10)?,
        })
    }

    fn migration_result(
        request: &AgentOperationsFreezeRequest,
        state: &str,
        revision: u64,
        created_at_ms: i64,
        updated_at_ms: i64,
    ) -> Value {
        json!({
            "scope": scope_dto(&request.scope),
            "backend_id": Uuid::from_u128(0x303),
            "workspace_id": request.scope.workspace_id().into_uuid(),
            "migration_id": request.migration_id,
            "destination_id": request.destination_id,
            "revision": revision,
            "state": state,
            "created_at_ms": created_at_ms,
            "updated_at_ms": updated_at_ms,
        })
    }

    #[tokio::test]
    async fn mutation_success_identity_mismatch_is_unknown_with_one_exchange()
    -> Result<(), Box<dyn Error>> {
        let request = migration_request()?;
        for (state, revision, created_at_ms, updated_at_ms) in [
            ("frozen", 1, 11, 11),
            ("frozen", 2, 10, 10),
            ("released", 1, 10, 10),
        ] {
            let (host, calls) = start_migration_host(migration_result(
                &request,
                state,
                revision,
                created_at_ms,
                updated_at_ms,
            ))
            .await?;
            let client = ForgeHttpClient::new(
                host.address,
                "test-service-secret",
                ForgeBackendId::from_uuid(Uuid::from_u128(0x303)),
                request.destination_id,
                Duration::from_secs(1),
            )?;
            let result = client.agent_operations_freeze(&request).await;
            assert!(matches!(
                result,
                Err(ForgeHttpMutationError::UnknownOutcome { .. })
            ));
            assert_eq!(calls.load(Ordering::Acquire), 1);
            host.stop
                .send(())
                .map_err(|()| "host did not accept shutdown")?;
            host.join.await??;
        }
        Ok(())
    }

    #[test]
    fn committed_uncertain_failure_retains_original_mutation_intent() -> Result<(), Box<dyn Error>>
    {
        let request = migration_request()?;
        let intent = ForgeHttpMutationRequest::Freeze(request);
        let request_id = Uuid::from_u128(0x304);
        let body = serde_json::to_vec(&json!({
            "forge_api": FORGE_API_VERSION,
            "request_id": request_id,
            "ok": false,
            "error": {
                "code": "UNKNOWN_OUTCOME",
                "message": "unknown",
                "category": "unknown_outcome",
                "retryable": false,
                "recovery_action": "read_back",
                "recovery_hint": "read back",
                "readback": null,
            }
        }))?;
        let result = decode_mutation_command_response(
            (StatusCode::CONFLICT, HeaderMap::new(), Bytes::from(body)),
            request_id,
            intent.clone(),
        );
        assert!(matches!(
            result,
            Err(ForgeHttpMutationError::UnknownOutcome { request, .. }) if request == intent
        ));
        Ok(())
    }

    #[tokio::test]
    async fn hostile_response_contract_is_bounded_and_fenced() -> Result<(), Box<dyn Error>> {
        let request = request(0)?;
        let backend_id = Uuid::from_u128(0x200);
        let state = Arc::new(HostState {
            request: request.clone(),
            backend_id,
            modes: vec![
                HostileResponse::WrongRequestId,
                HostileResponse::WrongVersion,
                HostileResponse::WrongBackend,
                HostileResponse::WrongScope,
                HostileResponse::WrongSequence,
                HostileResponse::AcceptedWithoutOutput,
                HostileResponse::IncompleteSourceReferences,
                HostileResponse::UppercaseHash,
                HostileResponse::MalformedFailure,
                HostileResponse::ValidZeroSourceReferences,
                HostileResponse::LegacySourceReferencesUnknown,
                HostileResponse::RecoveryRequiredWithoutOutput,
                HostileResponse::MissingSourceReferenceField,
                HostileResponse::Oversized,
            ],
            next_mode: Mutex::new(0),
        });
        let HostHandle {
            address,
            stop,
            join,
        } = start_host(state).await?;
        let client = ForgeHttpClient::new(
            address,
            "test-service-secret",
            ForgeBackendId::from_uuid(backend_id),
            request.destination_id,
            Duration::from_secs(1),
        )?;
        for _ in 0..9 {
            match client.effect_fact_outbox(&request).await {
                Err(error) => assert_eq!(error, ForgeHttpClientError::Protocol),
                Ok(_) => return Err("hostile response was accepted".into()),
            }
        }
        if client.effect_fact_outbox(&request).await.is_err() {
            return Err("zero-source Some([]) was rejected".into());
        }
        if client.effect_fact_outbox(&request).await.is_err() {
            return Err("legacy source-reference absence was rejected".into());
        }
        if client.effect_fact_outbox(&request).await.is_err() {
            return Err("RecoveryRequired without output was rejected".into());
        }
        match client.effect_fact_outbox(&request).await {
            Err(error) => assert_eq!(error, ForgeHttpClientError::Protocol),
            Ok(_) => return Err("missing submitted-source field was accepted".into()),
        }
        match client.effect_fact_outbox(&request).await {
            Err(error) => assert_eq!(error, ForgeHttpClientError::ResponseTooLarge),
            Ok(_) => return Err("oversized response was accepted".into()),
        }
        stop.send(()).map_err(|()| "host did not accept shutdown")?;
        join.await??;
        Ok(())
    }
}
