//! Local MCP bearer-token lifecycle control.
//!
//! This module owns the boundary between the token secret representation and
//! the durable catalog.  The raw bearer is generated and consumed only at the
//! control boundary; the catalog receives the keyed digest and typed metadata,
//! never the bearer reveal or the pepper.  A small catalog port keeps the
//! control crate independent from the `SQLite` adapter (which can implement the
//! port in an outer composition crate without a dependency cycle).

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::thread::{self, JoinHandle};

use base64::Engine;
use forge_domain::{
    MAX_MCP_TOKEN_SCOPES, MCP_TOKEN_DIGEST_BYTES, McpTokenDigest, McpTokenId, McpTokenRevision,
    McpTokenState, McpTokenTransitionError, McpTokenWorkspaceScope, RegisteredMcpToken,
    TimestampMillis,
};
use thiserror::Error;
use uuid::Uuid;

/// Number of random bytes in a bearer reveal.
pub const MCP_TOKEN_REVEAL_BYTES: usize = MCP_TOKEN_DIGEST_BYTES;

/// Base64url-without-padding length for [`MCP_TOKEN_REVEAL_BYTES`] bytes.
pub const MCP_TOKEN_REVEAL_CHARS: usize = 43;

/// Maximum accepted `Authorization` header size, including `Bearer `.
pub const MAX_MCP_TOKEN_BEARER_BYTES: usize = 7 + MCP_TOKEN_REVEAL_CHARS;

/// Maximum number of records returned by one control list call.
pub const MAX_MCP_TOKEN_LIST_RESULTS: usize = 256;

/// Bounded single-owner token worker queue capacity.
pub const MCP_TOKEN_QUEUE_CAPACITY: usize = 16;

const BEARER_PREFIX: &str = "Bearer ";
const TOKEN_HASH_DOMAIN: &[u8] = b"heterarchy-forge/mcp-bearer/v1";
const WORKER_THREAD_NAME: &str = "heterarchy-forge-mcp-token";

/// Catalog operations required by [`McpTokenService`].
///
/// Implementations are expected to make `rotate` and `revoke` one durable
/// compare-and-swap transaction.  `authenticate`/`get`/`list` must consult the
/// durable authority on every invocation; the control service deliberately
/// keeps no metadata or authorization cache.
pub trait McpTokenCatalog: Send + 'static {
    /// Adapter-specific failure type.  Control maps it to a stable redacted
    /// service error so storage details cannot cross the application boundary.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Persist a newly issued token record and return the durable projection.
    fn issue(&mut self, token: RegisteredMcpToken) -> Result<RegisteredMcpToken, Self::Error>;

    /// Look up a token by digest in the durable catalog.
    fn authenticate(
        &mut self,
        digest: McpTokenDigest,
    ) -> Result<Option<RegisteredMcpToken>, Self::Error>;

    /// Atomically replace an active record with its rotated predecessor and
    /// replacement record.  The predecessor carries the expected revision and
    /// old digest, allowing the adapter to fence stale callers.
    fn rotate(
        &mut self,
        predecessor: RegisteredMcpToken,
        replacement: RegisteredMcpToken,
    ) -> Result<(RegisteredMcpToken, RegisteredMcpToken), Self::Error>;

    /// Persist a terminal revoked predecessor through a revision-fenced write.
    fn revoke(
        &mut self,
        predecessor: RegisteredMcpToken,
        revoked: RegisteredMcpToken,
    ) -> Result<RegisteredMcpToken, Self::Error>;

    /// Read one durable metadata record.
    fn get(&mut self, id: McpTokenId) -> Result<Option<RegisteredMcpToken>, Self::Error>;

    /// Read a bounded durable metadata listing.
    fn list(&mut self, limit: usize) -> Result<Vec<RegisteredMcpToken>, Self::Error>;
}

/// Typed token issue input.  It contains metadata and a caller-observed time,
/// but never a caller-supplied secret or digest.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpTokenIssueRequest {
    label: forge_domain::McpTokenLabel,
    scopes: Vec<McpTokenWorkspaceScope>,
    created_at: TimestampMillis,
}

impl McpTokenIssueRequest {
    pub fn new(
        label: forge_domain::McpTokenLabel,
        scopes: Vec<McpTokenWorkspaceScope>,
        created_at: TimestampMillis,
    ) -> Result<Self, McpTokenIssueRequestError> {
        if scopes.is_empty() {
            return Err(McpTokenIssueRequestError::EmptyScopes);
        }
        if scopes.len() > MAX_MCP_TOKEN_SCOPES {
            return Err(McpTokenIssueRequestError::ScopeCapacity {
                actual: scopes.len(),
                maximum: MAX_MCP_TOKEN_SCOPES,
            });
        }
        Ok(Self {
            label,
            scopes,
            created_at,
        })
    }

    pub const fn label(&self) -> &forge_domain::McpTokenLabel {
        &self.label
    }

    pub fn scopes(&self) -> &[McpTokenWorkspaceScope] {
        &self.scopes
    }

    pub const fn created_at(&self) -> TimestampMillis {
        self.created_at
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum McpTokenIssueRequestError {
    #[error("MCP token issue requires at least one Workspace scope")]
    EmptyScopes,
    #[error("MCP token issue has {actual} scopes; maximum is {maximum}")]
    ScopeCapacity { actual: usize, maximum: usize },
}

/// One-time raw bearer reveal returned after a successful issue or rotation.
///
/// This type intentionally has no `Display` implementation.  Callers must
/// explicitly ask for [`Self::as_str`] or consume it, and diagnostics remain
/// redacted through its `Debug` implementation.
#[must_use]
#[derive(Clone, PartialEq, Eq)]
pub struct McpTokenReveal(String);

impl McpTokenReveal {
    fn from_string(value: String) -> Result<Self, McpTokenServiceError> {
        if value.len() == MCP_TOKEN_REVEAL_CHARS && value.is_ascii() {
            Ok(Self(value))
        } else {
            Err(McpTokenServiceError::InternalInvariant)
        }
    }

    /// Borrow the one-time reveal for explicit handoff to the transport.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume the reveal for explicit handoff to the transport.
    pub fn into_string(self) -> String {
        self.0
    }

    pub const fn len(&self) -> usize {
        self.0.len()
    }

    pub const fn is_empty(&self) -> bool {
        false
    }
}

impl AsRef<str> for McpTokenReveal {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Debug for McpTokenReveal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("McpTokenReveal(<redacted>)")
    }
}

/// Non-secret projection of a durable token record.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpTokenMetadata {
    id: McpTokenId,
    label: forge_domain::McpTokenLabel,
    state: McpTokenState,
    scopes: Vec<McpTokenWorkspaceScope>,
    created_at: TimestampMillis,
    disabled_at: Option<TimestampMillis>,
    replacement_token_id: Option<McpTokenId>,
    revision: McpTokenRevision,
}

impl McpTokenMetadata {
    fn from_record(record: &RegisteredMcpToken) -> Self {
        Self {
            id: record.id(),
            label: record.label().clone(),
            state: record.state(),
            scopes: record.scopes().to_vec(),
            created_at: record.created_at(),
            disabled_at: record.disabled_at(),
            replacement_token_id: record.replacement_token_id(),
            revision: record.revision(),
        }
    }

    pub const fn id(&self) -> McpTokenId {
        self.id
    }

    pub const fn label(&self) -> &forge_domain::McpTokenLabel {
        &self.label
    }

    pub const fn state(&self) -> McpTokenState {
        self.state
    }

    pub fn scopes(&self) -> &[McpTokenWorkspaceScope] {
        &self.scopes
    }

    pub const fn created_at(&self) -> TimestampMillis {
        self.created_at
    }

    pub const fn disabled_at(&self) -> Option<TimestampMillis> {
        self.disabled_at
    }

    pub const fn replacement_token_id(&self) -> Option<McpTokenId> {
        self.replacement_token_id
    }

    pub const fn revision(&self) -> McpTokenRevision {
        self.revision
    }
}

/// Issue result carrying metadata and the one-time reveal.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpTokenIssued {
    metadata: McpTokenMetadata,
    reveal: McpTokenReveal,
}

impl McpTokenIssued {
    pub const fn metadata(&self) -> &McpTokenMetadata {
        &self.metadata
    }

    pub const fn reveal(&self) -> &McpTokenReveal {
        &self.reveal
    }

    pub fn into_parts(self) -> (McpTokenMetadata, McpTokenReveal) {
        (self.metadata, self.reveal)
    }
}

/// Rotated token result.  The predecessor metadata is safe to retain, while
/// the replacement reveal is returned exactly once.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpTokenRotation {
    predecessor: McpTokenMetadata,
    replacement: McpTokenIssued,
}

impl McpTokenRotation {
    pub const fn predecessor(&self) -> &McpTokenMetadata {
        &self.predecessor
    }

    pub const fn replacement(&self) -> &McpTokenIssued {
        &self.replacement
    }

    pub fn into_parts(self) -> (McpTokenMetadata, McpTokenIssued) {
        (self.predecessor, self.replacement)
    }
}

/// Non-secret authorization result returned after durable digest lookup.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpTokenAuthorization {
    token_id: McpTokenId,
    scopes: Vec<McpTokenWorkspaceScope>,
}

impl McpTokenAuthorization {
    fn from_record(record: &RegisteredMcpToken) -> Self {
        Self {
            token_id: record.id(),
            scopes: record.scopes().to_vec(),
        }
    }

    pub const fn token_id(&self) -> McpTokenId {
        self.token_id
    }

    pub fn scopes(&self) -> &[McpTokenWorkspaceScope] {
        &self.scopes
    }

    pub fn permits_workspace(
        &self,
        location_id: forge_domain::LocationId,
        workspace_id: forge_domain::WorkspaceId,
    ) -> bool {
        self.scopes
            .iter()
            .any(|scope| scope.location_id() == location_id && scope.workspace_id() == workspace_id)
    }

    pub fn permits_location(&self, location_id: forge_domain::LocationId) -> bool {
        self.scopes
            .iter()
            .any(|scope| scope.location_id() == location_id)
    }
}

/// Stable, redacted lifecycle/service failure.
#[derive(Debug, Error)]
pub enum McpTokenServiceError {
    #[error("secure randomness for MCP token generation is unavailable")]
    Randomness(#[source] getrandom::Error),
    #[error("MCP token catalog operation failed")]
    Catalog,
    #[error("MCP bearer authorization is malformed")]
    MalformedBearer,
    #[error("MCP token is not active")]
    Inactive,
    #[error("MCP token was not found")]
    NotFound,
    #[error("MCP token revision conflicts with durable state")]
    RevisionConflict,
    #[error("MCP token list limit is outside the bounded range")]
    InvalidListLimit { actual: usize, maximum: usize },
    #[error("MCP token worker is shutting down")]
    WorkerShuttingDown,
    #[error("MCP token lifecycle invariant was violated")]
    InternalInvariant,
}

/// Synchronous owner of one token catalog and its secret pepper.
///
/// The pepper is consumed at construction and has no accessor.  Its `Debug`
/// output is intentionally non-exhaustive, so neither pepper nor catalog
/// representation can enter logs accidentally.
pub struct McpTokenService<C> {
    pepper: [u8; MCP_TOKEN_DIGEST_BYTES],
    catalog: C,
}

impl<C> fmt::Debug for McpTokenService<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpTokenService")
            .field("pepper", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl<C> McpTokenService<C> {
    /// Construct a service with an owned, fixed-width pepper.
    pub const fn new(pepper: [u8; MCP_TOKEN_DIGEST_BYTES], catalog: C) -> Self {
        Self { pepper, catalog }
    }
}

impl<C> Drop for McpTokenService<C> {
    fn drop(&mut self) {
        self.pepper.fill(0);
    }
}

impl<C> McpTokenService<C>
where
    C: McpTokenCatalog,
{
    /// Issue one random bearer, persisting only its keyed digest and metadata.
    pub fn issue(
        &mut self,
        request: McpTokenIssueRequest,
    ) -> Result<McpTokenIssued, McpTokenServiceError> {
        let (reveal, digest) = self.generate_secret()?;
        let record = RegisteredMcpToken::issue(
            McpTokenId::from_uuid(Uuid::now_v7()),
            request.label,
            digest,
            request.scopes,
            request.created_at,
        )
        .map_err(map_transition_error)?;
        let persisted = self
            .catalog
            .issue(record)
            .map_err(|_| McpTokenServiceError::Catalog)?;
        Ok(McpTokenIssued {
            metadata: McpTokenMetadata::from_record(&persisted),
            reveal,
        })
    }

    /// Convenience issue path for callers holding an already validated label.
    pub fn issue_token(
        &mut self,
        label: forge_domain::McpTokenLabel,
        scopes: Vec<McpTokenWorkspaceScope>,
        created_at: TimestampMillis,
    ) -> Result<McpTokenIssued, McpTokenServiceError> {
        let request = McpTokenIssueRequest::new(label, scopes, created_at)
            .map_err(|_| McpTokenServiceError::InternalInvariant)?;
        self.issue(request)
    }

    /// Authenticate a canonical `Bearer <43-char-base64url>` header.
    ///
    /// The durable catalog is queried for every call.  Missing, revoked, and
    /// rotated records intentionally collapse to `Ok(None)` so the transport
    /// cannot use the response as a token-state oracle.
    pub fn authenticate(
        &mut self,
        authorization: &str,
    ) -> Result<Option<McpTokenAuthorization>, McpTokenServiceError> {
        let reveal = parse_bearer(authorization)?;
        let digest = self.digest(reveal.as_str());
        let Some(record) = self
            .catalog
            .authenticate(digest)
            .map_err(|_| McpTokenServiceError::Catalog)?
        else {
            return Ok(None);
        };
        if record.state() != McpTokenState::Active {
            return Ok(None);
        }
        Ok(Some(McpTokenAuthorization::from_record(&record)))
    }

    /// Explicit alias naming the transport operation.
    pub fn authenticate_bearer(
        &mut self,
        authorization: &str,
    ) -> Result<Option<McpTokenAuthorization>, McpTokenServiceError> {
        self.authenticate(authorization)
    }

    /// Atomically rotate one active token and return only the replacement
    /// reveal.  The old reveal is never reconstructed or returned.
    pub fn rotate(
        &mut self,
        id: McpTokenId,
        expected_revision: McpTokenRevision,
        rotated_at: TimestampMillis,
    ) -> Result<McpTokenRotation, McpTokenServiceError> {
        let current = self
            .catalog
            .get(id)
            .map_err(|_| McpTokenServiceError::Catalog)?
            .ok_or(McpTokenServiceError::NotFound)?;
        if current.state() != McpTokenState::Active {
            return Err(McpTokenServiceError::Inactive);
        }
        if current.revision() != expected_revision {
            return Err(McpTokenServiceError::RevisionConflict);
        }

        let (reveal, digest) = self.generate_secret()?;
        let replacement_id = McpTokenId::from_uuid(Uuid::now_v7());
        let predecessor = current
            .rotate(replacement_id, expected_revision, rotated_at)
            .map_err(map_transition_error)?;
        let replacement = RegisteredMcpToken::issue(
            replacement_id,
            current.label().clone(),
            digest,
            current.scopes().to_vec(),
            rotated_at,
        )
        .map_err(map_transition_error)?;
        let (persisted_predecessor, persisted_replacement) = self
            .catalog
            .rotate(predecessor, replacement)
            .map_err(|_| McpTokenServiceError::Catalog)?;
        Ok(McpTokenRotation {
            predecessor: McpTokenMetadata::from_record(&persisted_predecessor),
            replacement: McpTokenIssued {
                metadata: McpTokenMetadata::from_record(&persisted_replacement),
                reveal,
            },
        })
    }

    /// Revoke one active token through a revision-fenced durable transition.
    pub fn revoke(
        &mut self,
        id: McpTokenId,
        expected_revision: McpTokenRevision,
        disabled_at: TimestampMillis,
    ) -> Result<McpTokenMetadata, McpTokenServiceError> {
        let current = self
            .catalog
            .get(id)
            .map_err(|_| McpTokenServiceError::Catalog)?
            .ok_or(McpTokenServiceError::NotFound)?;
        if current.state() != McpTokenState::Active {
            return Err(McpTokenServiceError::Inactive);
        }
        if current.revision() != expected_revision {
            return Err(McpTokenServiceError::RevisionConflict);
        }
        let revoked = current
            .revoke(expected_revision, disabled_at)
            .map_err(map_transition_error)?;
        let persisted = self
            .catalog
            .revoke(current, revoked)
            .map_err(|_| McpTokenServiceError::Catalog)?;
        Ok(McpTokenMetadata::from_record(&persisted))
    }

    /// Read one non-secret metadata projection from durable authority.
    pub fn get(
        &mut self,
        id: McpTokenId,
    ) -> Result<Option<McpTokenMetadata>, McpTokenServiceError> {
        self.catalog
            .get(id)
            .map_err(|_| McpTokenServiceError::Catalog)
            .map(|record| record.as_ref().map(McpTokenMetadata::from_record))
    }

    /// Read a bounded non-secret metadata listing from durable authority.
    pub fn list(&mut self, limit: usize) -> Result<Vec<McpTokenMetadata>, McpTokenServiceError> {
        if limit == 0 || limit > MAX_MCP_TOKEN_LIST_RESULTS {
            return Err(McpTokenServiceError::InvalidListLimit {
                actual: limit,
                maximum: MAX_MCP_TOKEN_LIST_RESULTS,
            });
        }
        let records = self
            .catalog
            .list(limit)
            .map_err(|_| McpTokenServiceError::Catalog)?;
        if records.len() > limit || records.len() > MAX_MCP_TOKEN_LIST_RESULTS {
            return Err(McpTokenServiceError::InternalInvariant);
        }
        Ok(records.iter().map(McpTokenMetadata::from_record).collect())
    }

    fn generate_secret(&self) -> Result<(McpTokenReveal, McpTokenDigest), McpTokenServiceError> {
        let mut bytes = [0_u8; MCP_TOKEN_REVEAL_BYTES];
        getrandom::fill(&mut bytes).map_err(McpTokenServiceError::Randomness)?;
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        let reveal = McpTokenReveal::from_string(encoded)?;
        let digest = self.digest(reveal.as_str());
        Ok((reveal, digest))
    }

    fn digest(&self, reveal: &str) -> McpTokenDigest {
        let mut hasher = blake3::Hasher::new_keyed(&self.pepper);
        hasher.update(TOKEN_HASH_DOMAIN);
        hasher.update(&[0]);
        hasher.update(reveal.as_bytes());
        McpTokenDigest::new(*hasher.finalize().as_bytes())
    }
}

/// Direct adapter for the durable `SQLite` catalog.  The implementation lives
/// in this application-control crate so persistence remains independent of
/// control; callers can therefore construct `McpTokenService<McpTokenCatalog>`
/// without a second mutable state owner.
impl McpTokenCatalog for forge_persistence::McpTokenCatalog {
    type Error = forge_persistence::McpTokenCatalogError;

    fn issue(&mut self, token: RegisteredMcpToken) -> Result<RegisteredMcpToken, Self::Error> {
        forge_persistence::McpTokenCatalog::issue(self, &token)?;
        Ok(token)
    }

    fn authenticate(
        &mut self,
        digest: McpTokenDigest,
    ) -> Result<Option<RegisteredMcpToken>, Self::Error> {
        forge_persistence::McpTokenCatalog::find_active_by_digest(self, digest)
    }

    fn rotate(
        &mut self,
        predecessor: RegisteredMcpToken,
        replacement: RegisteredMcpToken,
    ) -> Result<(RegisteredMcpToken, RegisteredMcpToken), Self::Error> {
        let expected_revision = predecessor
            .revision()
            .get()
            .checked_sub(1)
            .and_then(|value| McpTokenRevision::new(value).ok())
            .ok_or(forge_persistence::McpTokenCatalogError::Transition(
                McpTokenTransitionError::RevisionConflict,
            ))?;
        let disabled_at = predecessor.disabled_at().ok_or(
            forge_persistence::McpTokenCatalogError::Transition(
                McpTokenTransitionError::LifecycleShape,
            ),
        )?;
        forge_persistence::McpTokenCatalog::rotate(
            self,
            predecessor.id(),
            expected_revision,
            &replacement,
            disabled_at,
        )
    }

    fn revoke(
        &mut self,
        predecessor: RegisteredMcpToken,
        revoked: RegisteredMcpToken,
    ) -> Result<RegisteredMcpToken, Self::Error> {
        let disabled_at =
            revoked
                .disabled_at()
                .ok_or(forge_persistence::McpTokenCatalogError::Transition(
                    McpTokenTransitionError::LifecycleShape,
                ))?;
        let persisted = forge_persistence::McpTokenCatalog::revoke(
            self,
            predecessor.id(),
            predecessor.revision(),
            disabled_at,
        )?;
        if persisted != revoked {
            return Err(forge_persistence::McpTokenCatalogError::Transition(
                McpTokenTransitionError::RevisionConflict,
            ));
        }
        Ok(persisted)
    }

    fn get(&mut self, id: McpTokenId) -> Result<Option<RegisteredMcpToken>, Self::Error> {
        forge_persistence::McpTokenCatalog::get(self, id)
    }

    fn list(&mut self, limit: usize) -> Result<Vec<RegisteredMcpToken>, Self::Error> {
        forge_persistence::McpTokenCatalog::list(self, limit)
    }
}

fn parse_bearer(value: &str) -> Result<McpTokenReveal, McpTokenServiceError> {
    if value.len() != MAX_MCP_TOKEN_BEARER_BYTES
        || !value.is_ascii()
        || !value.starts_with(BEARER_PREFIX)
    {
        return Err(McpTokenServiceError::MalformedBearer);
    }
    let encoded = &value[BEARER_PREFIX.len()..];
    if !encoded.bytes().all(is_base64url_byte) {
        return Err(McpTokenServiceError::MalformedBearer);
    }
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| McpTokenServiceError::MalformedBearer)?;
    if decoded.len() != MCP_TOKEN_REVEAL_BYTES
        || base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(decoded) != encoded
    {
        return Err(McpTokenServiceError::MalformedBearer);
    }
    McpTokenReveal::from_string(encoded.to_owned())
}

const fn is_base64url_byte(value: u8) -> bool {
    matches!(value, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_')
}

fn map_transition_error(error: McpTokenTransitionError) -> McpTokenServiceError {
    match error {
        McpTokenTransitionError::RevisionConflict => McpTokenServiceError::RevisionConflict,
        McpTokenTransitionError::TerminalState => McpTokenServiceError::Inactive,
        McpTokenTransitionError::EmptyScopes
        | McpTokenTransitionError::ScopeCapacity { .. }
        | McpTokenTransitionError::DuplicateScope
        | McpTokenTransitionError::LifecycleShape
        | McpTokenTransitionError::TimestampOrder
        | McpTokenTransitionError::ReplacementIdentity
        | McpTokenTransitionError::Revision(_) => McpTokenServiceError::InternalInvariant,
    }
}

type Response<T> = SyncSender<Result<T, McpTokenServiceError>>;

/// Typed requests accepted by [`McpTokenWorker`].
#[derive(Debug)]
pub enum McpTokenRequest {
    Issue {
        request: McpTokenIssueRequest,
        response: Response<McpTokenIssued>,
    },
    Authenticate {
        authorization: String,
        response: Response<Option<McpTokenAuthorization>>,
    },
    Rotate {
        id: McpTokenId,
        expected_revision: McpTokenRevision,
        rotated_at: TimestampMillis,
        response: Response<McpTokenRotation>,
    },
    Revoke {
        id: McpTokenId,
        expected_revision: McpTokenRevision,
        disabled_at: TimestampMillis,
        response: Response<McpTokenMetadata>,
    },
    Get {
        id: McpTokenId,
        response: Response<Option<McpTokenMetadata>>,
    },
    List {
        limit: usize,
        response: Response<Vec<McpTokenMetadata>>,
    },
    Shutdown {
        response: Option<SyncSender<()>>,
    },
}

/// Client-side admission/response failure for the bounded token worker.
#[derive(Debug)]
pub enum McpTokenClientError {
    QueueFull,
    WorkerClosed,
    WorkerShuttingDown,
    ResponseDropped,
    Service(McpTokenServiceError),
}

impl McpTokenClientError {
    pub const fn is_capacity(&self) -> bool {
        matches!(self, Self::QueueFull)
    }

    pub const fn service_error(&self) -> Option<&McpTokenServiceError> {
        match self {
            Self::Service(error) => Some(error),
            Self::QueueFull
            | Self::WorkerClosed
            | Self::WorkerShuttingDown
            | Self::ResponseDropped => None,
        }
    }
}

impl fmt::Display for McpTokenClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::QueueFull => "MCP token worker queue is at capacity",
            Self::WorkerClosed => "MCP token worker is closed",
            Self::WorkerShuttingDown => "MCP token worker is shutting down",
            Self::ResponseDropped => "MCP token worker response was dropped",
            Self::Service(error) => return error.fmt(formatter),
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for McpTokenClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Service(error) => Some(error),
            Self::QueueFull
            | Self::WorkerClosed
            | Self::WorkerShuttingDown
            | Self::ResponseDropped => None,
        }
    }
}

/// One admitted one-slot response.
#[derive(Debug)]
pub struct PendingMcpToken<T> {
    receiver: Receiver<Result<T, McpTokenServiceError>>,
}

impl<T> PendingMcpToken<T> {
    fn new(receiver: Receiver<Result<T, McpTokenServiceError>>) -> Self {
        Self { receiver }
    }

    /// Blocking completion path for non-UI callers.
    pub fn recv(self) -> Result<T, McpTokenClientError> {
        self.receiver
            .recv()
            .map_err(|_| McpTokenClientError::ResponseDropped)?
            .map_err(McpTokenClientError::Service)
    }

    /// Nonblocking completion poll.
    pub fn try_recv(&self) -> Result<Option<Result<T, McpTokenServiceError>>, McpTokenClientError> {
        match self.receiver.try_recv() {
            Ok(result) => Ok(Some(result)),
            Err(mpsc::TryRecvError::Empty) => Ok(None),
            Err(mpsc::TryRecvError::Disconnected) => Err(McpTokenClientError::WorkerClosed),
        }
    }
}

/// Worker lifecycle/join failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpTokenWorkerError {
    AlreadyShutdown,
    WorkerClosed,
    JoinFailed,
}

impl fmt::Display for McpTokenWorkerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::AlreadyShutdown => "MCP token worker is already shut down",
            Self::WorkerClosed => "MCP token worker closed before shutdown acknowledgement",
            Self::JoinFailed => "MCP token worker failed to join",
        })
    }
}

impl std::error::Error for McpTokenWorkerError {}

/// Cloneable bounded client.  Clones share only admission state and a channel
/// sender; the catalog remains exclusively owned by the worker thread.
#[derive(Debug, Clone)]
pub struct McpTokenClient {
    sender: SyncSender<McpTokenRequest>,
    accepting: Arc<AtomicBool>,
}

impl McpTokenClient {
    fn new(sender: SyncSender<McpTokenRequest>, accepting: Arc<AtomicBool>) -> Self {
        Self { sender, accepting }
    }

    pub fn issue(
        &self,
        request: McpTokenIssueRequest,
    ) -> Result<McpTokenIssued, McpTokenClientError> {
        self.submit_issue(request)?.recv()
    }

    pub fn submit_issue(
        &self,
        request: McpTokenIssueRequest,
    ) -> Result<PendingMcpToken<McpTokenIssued>, McpTokenClientError> {
        self.submit_pending(|response| McpTokenRequest::Issue { request, response })
    }

    pub fn authenticate(
        &self,
        authorization: impl Into<String>,
    ) -> Result<Option<McpTokenAuthorization>, McpTokenClientError> {
        self.submit_authenticate(authorization.into())?.recv()
    }

    pub fn submit_authenticate(
        &self,
        authorization: String,
    ) -> Result<PendingMcpToken<Option<McpTokenAuthorization>>, McpTokenClientError> {
        self.submit_pending(|response| McpTokenRequest::Authenticate {
            authorization,
            response,
        })
    }

    pub fn rotate(
        &self,
        id: McpTokenId,
        expected_revision: McpTokenRevision,
        rotated_at: TimestampMillis,
    ) -> Result<McpTokenRotation, McpTokenClientError> {
        self.submit_rotate(id, expected_revision, rotated_at)?
            .recv()
    }

    pub fn submit_rotate(
        &self,
        id: McpTokenId,
        expected_revision: McpTokenRevision,
        rotated_at: TimestampMillis,
    ) -> Result<PendingMcpToken<McpTokenRotation>, McpTokenClientError> {
        self.submit_pending(|response| McpTokenRequest::Rotate {
            id,
            expected_revision,
            rotated_at,
            response,
        })
    }

    pub fn revoke(
        &self,
        id: McpTokenId,
        expected_revision: McpTokenRevision,
        disabled_at: TimestampMillis,
    ) -> Result<McpTokenMetadata, McpTokenClientError> {
        self.submit_revoke(id, expected_revision, disabled_at)?
            .recv()
    }

    pub fn submit_revoke(
        &self,
        id: McpTokenId,
        expected_revision: McpTokenRevision,
        disabled_at: TimestampMillis,
    ) -> Result<PendingMcpToken<McpTokenMetadata>, McpTokenClientError> {
        self.submit_pending(|response| McpTokenRequest::Revoke {
            id,
            expected_revision,
            disabled_at,
            response,
        })
    }

    pub fn get(&self, id: McpTokenId) -> Result<Option<McpTokenMetadata>, McpTokenClientError> {
        self.submit_get(id)?.recv()
    }

    pub fn submit_get(
        &self,
        id: McpTokenId,
    ) -> Result<PendingMcpToken<Option<McpTokenMetadata>>, McpTokenClientError> {
        self.submit_pending(|response| McpTokenRequest::Get { id, response })
    }

    pub fn list(&self, limit: usize) -> Result<Vec<McpTokenMetadata>, McpTokenClientError> {
        self.submit_list(limit)?.recv()
    }

    pub fn submit_list(
        &self,
        limit: usize,
    ) -> Result<PendingMcpToken<Vec<McpTokenMetadata>>, McpTokenClientError> {
        self.submit_pending(|response| McpTokenRequest::List { limit, response })
    }

    pub fn is_accepting(&self) -> bool {
        self.accepting.load(Ordering::Acquire)
    }

    fn submit_pending<T, Build>(
        &self,
        build: Build,
    ) -> Result<PendingMcpToken<T>, McpTokenClientError>
    where
        Build: FnOnce(Response<T>) -> McpTokenRequest,
    {
        if !self.accepting.load(Ordering::Acquire) {
            return Err(McpTokenClientError::WorkerShuttingDown);
        }
        let (response_sender, response_receiver) = mpsc::sync_channel(1);
        self.sender
            .try_send(build(response_sender))
            .map_err(|error| match error {
                TrySendError::Full(_) => McpTokenClientError::QueueFull,
                TrySendError::Disconnected(_) => McpTokenClientError::WorkerClosed,
            })?;
        Ok(PendingMcpToken::new(response_receiver))
    }
}

/// Owner of one single-thread token service and bounded request queue.
#[derive(Debug)]
pub struct McpTokenWorker<C> {
    sender: SyncSender<McpTokenRequest>,
    accepting: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
    marker: std::marker::PhantomData<fn() -> C>,
}

impl<C> McpTokenWorker<C>
where
    C: McpTokenCatalog,
{
    pub fn start(
        service: McpTokenService<C>,
    ) -> Result<(McpTokenClient, Self), McpTokenWorkerError> {
        let (sender, receiver) = mpsc::sync_channel(MCP_TOKEN_QUEUE_CAPACITY);
        let accepting = Arc::new(AtomicBool::new(true));
        let worker_accepting = Arc::clone(&accepting);
        let join = thread::Builder::new()
            .name(WORKER_THREAD_NAME.to_owned())
            .spawn(move || {
                TokenWorkerRuntime {
                    service,
                    receiver,
                    accepting: worker_accepting,
                }
                .run();
            })
            .map_err(|_| McpTokenWorkerError::WorkerClosed)?;
        let client = McpTokenClient::new(sender.clone(), accepting.clone());
        Ok((
            client,
            Self {
                sender,
                accepting,
                join: Some(join),
                marker: std::marker::PhantomData,
            },
        ))
    }

    pub fn spawn(
        service: McpTokenService<C>,
    ) -> Result<(McpTokenClient, Self), McpTokenWorkerError> {
        Self::start(service)
    }

    pub const fn queue_capacity() -> usize {
        MCP_TOKEN_QUEUE_CAPACITY
    }

    pub fn is_accepting(&self) -> bool {
        self.accepting.load(Ordering::Acquire)
    }

    /// Stop admission, drain/reject queued requests, and join the owned
    /// worker thread.  The catalog remains exclusively owned by that thread
    /// until the join completes.
    pub fn shutdown(&mut self) -> Result<(), McpTokenWorkerError> {
        self.accepting.store(false, Ordering::Release);
        let Some(join) = self.join.take() else {
            return Err(McpTokenWorkerError::AlreadyShutdown);
        };
        let (ack_sender, ack_receiver) = mpsc::sync_channel(0);
        if self
            .sender
            .send(McpTokenRequest::Shutdown {
                response: Some(ack_sender),
            })
            .is_err()
        {
            return match join.join() {
                Ok(()) => Err(McpTokenWorkerError::WorkerClosed),
                Err(_) => Err(McpTokenWorkerError::JoinFailed),
            };
        }
        ack_receiver
            .recv()
            .map_err(|_| McpTokenWorkerError::WorkerClosed)?;
        join.join().map_err(|_| McpTokenWorkerError::JoinFailed)
    }
}

impl<C> Drop for McpTokenWorker<C> {
    fn drop(&mut self) {
        self.accepting.store(false, Ordering::Release);
        let Some(join) = self.join.take() else {
            return;
        };
        let _ignored = self
            .sender
            .send(McpTokenRequest::Shutdown { response: None });
        let _ignored = join.join();
    }
}

struct TokenWorkerRuntime<C> {
    service: McpTokenService<C>,
    receiver: Receiver<McpTokenRequest>,
    accepting: Arc<AtomicBool>,
}

impl<C> TokenWorkerRuntime<C>
where
    C: McpTokenCatalog,
{
    fn run(self) {
        let Self {
            mut service,
            receiver,
            accepting,
        } = self;
        while let Ok(request) = receiver.recv() {
            match request {
                McpTokenRequest::Shutdown { response } => {
                    accepting.store(false, Ordering::Release);
                    drain_queued_requests(&receiver);
                    if let Some(response) = response {
                        let _ignored = response.send(());
                    }
                    break;
                }
                McpTokenRequest::Issue { request, response } => {
                    let _ignored = response.send(service.issue(request));
                }
                McpTokenRequest::Authenticate {
                    authorization,
                    response,
                } => {
                    let _ignored = response.send(service.authenticate(&authorization));
                }
                McpTokenRequest::Rotate {
                    id,
                    expected_revision,
                    rotated_at,
                    response,
                } => {
                    let _ignored = response.send(service.rotate(id, expected_revision, rotated_at));
                }
                McpTokenRequest::Revoke {
                    id,
                    expected_revision,
                    disabled_at,
                    response,
                } => {
                    let _ignored =
                        response.send(service.revoke(id, expected_revision, disabled_at));
                }
                McpTokenRequest::Get { id, response } => {
                    let _ignored = response.send(service.get(id));
                }
                McpTokenRequest::List { limit, response } => {
                    let _ignored = response.send(service.list(limit));
                }
            }
        }
        accepting.store(false, Ordering::Release);
    }
}

fn drain_queued_requests(receiver: &Receiver<McpTokenRequest>) {
    while let Ok(request) = receiver.try_recv() {
        match request {
            McpTokenRequest::Issue { response, .. } => {
                let _ignored = response.send(Err(McpTokenServiceError::WorkerShuttingDown));
            }
            McpTokenRequest::Authenticate { response, .. } => {
                let _ignored = response.send(Err(McpTokenServiceError::WorkerShuttingDown));
            }
            McpTokenRequest::Rotate { response, .. } => {
                let _ignored = response.send(Err(McpTokenServiceError::WorkerShuttingDown));
            }
            McpTokenRequest::Revoke { response, .. } => {
                let _ignored = response.send(Err(McpTokenServiceError::WorkerShuttingDown));
            }
            McpTokenRequest::Get { response, .. } => {
                let _ignored = response.send(Err(McpTokenServiceError::WorkerShuttingDown));
            }
            McpTokenRequest::List { response, .. } => {
                let _ignored = response.send(Err(McpTokenServiceError::WorkerShuttingDown));
            }
            McpTokenRequest::Shutdown { response } => {
                if let Some(response) = response {
                    let _ignored = response.send(());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::error::Error;
    use std::sync::mpsc::{self, SyncSender};

    use forge_domain::{LocationId, McpTokenLabel, WorkspaceId};

    use super::*;

    #[derive(Debug, Error)]
    #[error("catalog test failure")]
    struct CatalogTestError;

    #[derive(Debug, Default)]
    struct MemoryCatalog {
        records: BTreeMap<McpTokenId, RegisteredMcpToken>,
    }

    impl McpTokenCatalog for MemoryCatalog {
        type Error = CatalogTestError;

        fn issue(&mut self, token: RegisteredMcpToken) -> Result<RegisteredMcpToken, Self::Error> {
            if self.records.insert(token.id(), token.clone()).is_some() {
                return Err(CatalogTestError);
            }
            Ok(token)
        }

        fn authenticate(
            &mut self,
            digest: McpTokenDigest,
        ) -> Result<Option<RegisteredMcpToken>, Self::Error> {
            Ok(self
                .records
                .values()
                .find(|record| record.digest() == digest)
                .cloned())
        }

        fn rotate(
            &mut self,
            predecessor: RegisteredMcpToken,
            replacement: RegisteredMcpToken,
        ) -> Result<(RegisteredMcpToken, RegisteredMcpToken), Self::Error> {
            let Some(current) = self.records.get(&predecessor.id()) else {
                return Err(CatalogTestError);
            };
            let Ok(next_revision) = current.revision().checked_next() else {
                return Err(CatalogTestError);
            };
            if next_revision != predecessor.revision()
                || current.state() != McpTokenState::Active
                || self.records.contains_key(&replacement.id())
            {
                return Err(CatalogTestError);
            }
            self.records.insert(predecessor.id(), predecessor.clone());
            self.records.insert(replacement.id(), replacement.clone());
            Ok((predecessor, replacement))
        }

        fn revoke(
            &mut self,
            predecessor: RegisteredMcpToken,
            revoked: RegisteredMcpToken,
        ) -> Result<RegisteredMcpToken, Self::Error> {
            let Some(current) = self.records.get(&predecessor.id()) else {
                return Err(CatalogTestError);
            };
            if current != &predecessor || revoked.state() != McpTokenState::Revoked {
                return Err(CatalogTestError);
            }
            self.records.insert(revoked.id(), revoked.clone());
            Ok(revoked)
        }

        fn get(&mut self, id: McpTokenId) -> Result<Option<RegisteredMcpToken>, Self::Error> {
            Ok(self.records.get(&id).cloned())
        }

        fn list(&mut self, limit: usize) -> Result<Vec<RegisteredMcpToken>, Self::Error> {
            Ok(self.records.values().take(limit).cloned().collect())
        }
    }

    #[derive(Debug)]
    struct BlockingCatalog {
        inner: MemoryCatalog,
        entered: Option<SyncSender<()>>,
        release: Option<Receiver<()>>,
    }

    impl McpTokenCatalog for BlockingCatalog {
        type Error = CatalogTestError;

        fn issue(&mut self, token: RegisteredMcpToken) -> Result<RegisteredMcpToken, Self::Error> {
            self.inner.issue(token)
        }

        fn authenticate(
            &mut self,
            digest: McpTokenDigest,
        ) -> Result<Option<RegisteredMcpToken>, Self::Error> {
            self.inner.authenticate(digest)
        }

        fn rotate(
            &mut self,
            predecessor: RegisteredMcpToken,
            replacement: RegisteredMcpToken,
        ) -> Result<(RegisteredMcpToken, RegisteredMcpToken), Self::Error> {
            self.inner.rotate(predecessor, replacement)
        }

        fn revoke(
            &mut self,
            predecessor: RegisteredMcpToken,
            revoked: RegisteredMcpToken,
        ) -> Result<RegisteredMcpToken, Self::Error> {
            self.inner.revoke(predecessor, revoked)
        }

        fn get(&mut self, id: McpTokenId) -> Result<Option<RegisteredMcpToken>, Self::Error> {
            if let Some(entered) = self.entered.take() {
                entered.send(()).map_err(|_| CatalogTestError)?;
                if let Some(release) = self.release.take() {
                    release.recv().map_err(|_| CatalogTestError)?;
                }
            }
            self.inner.get(id)
        }

        fn list(&mut self, limit: usize) -> Result<Vec<RegisteredMcpToken>, Self::Error> {
            self.inner.list(limit)
        }
    }

    fn timestamp(value: i64) -> Result<TimestampMillis, Box<dyn Error>> {
        Ok(TimestampMillis::new(value)?)
    }

    fn scope(value: u128) -> McpTokenWorkspaceScope {
        McpTokenWorkspaceScope::new(
            LocationId::from_uuid(Uuid::from_u128(value)),
            WorkspaceId::from_uuid(Uuid::from_u128(value + 1)),
        )
    }

    fn request() -> Result<McpTokenIssueRequest, Box<dyn Error>> {
        Ok(McpTokenIssueRequest::new(
            McpTokenLabel::new("Codex local".to_owned())?,
            vec![scope(10)],
            timestamp(1)?,
        )?)
    }

    #[test]
    fn issue_request_rejects_empty_and_oversized_scope_sets() -> Result<(), Box<dyn Error>> {
        let label = McpTokenLabel::new("Codex local".to_owned())?;
        assert!(McpTokenIssueRequest::new(label.clone(), Vec::new(), timestamp(1)?).is_err());
        assert!(
            McpTokenIssueRequest::new(
                label,
                vec![scope(10); MAX_MCP_TOKEN_SCOPES + 1],
                timestamp(1)?,
            )
            .is_err()
        );
        Ok(())
    }

    fn service() -> McpTokenService<MemoryCatalog> {
        McpTokenService::new([0x5a; MCP_TOKEN_DIGEST_BYTES], MemoryCatalog::default())
    }

    #[test]
    fn issue_generates_canonical_one_time_reveal_and_redacted_debug() -> Result<(), Box<dyn Error>>
    {
        let mut service = service();
        let issued = service.issue(request()?)?;
        assert_eq!(issued.reveal().len(), MCP_TOKEN_REVEAL_CHARS);
        assert_eq!(issued.metadata().scopes(), &[scope(10)]);
        let debug = format!("{issued:?}");
        assert!(!debug.contains(issued.reveal().as_str()));
        assert!(!format!("{service:?}").contains("5a"));
        Ok(())
    }

    #[test]
    fn authenticate_wrong_and_malformed_are_distinct_and_bounded() -> Result<(), Box<dyn Error>> {
        let mut service = service();
        let issued = service.issue(request()?)?;
        let authorization = format!("Bearer {}", issued.reveal().as_str());
        let authorized = service
            .authenticate(&authorization)?
            .ok_or("missing auth")?;
        assert_eq!(authorized.token_id(), issued.metadata().id());
        assert_eq!(authorized.scopes(), &[scope(10)]);

        let mut wrong = issued.reveal().as_str().as_bytes().to_vec();
        let first = wrong.first_mut().ok_or("empty reveal")?;
        *first = if *first == b'A' { b'B' } else { b'A' };
        let wrong = String::from_utf8(wrong)?;
        assert!(
            service
                .authenticate(&format!("Bearer {wrong}"))
                .is_ok_and(|value| value.is_none())
        );
        assert!(matches!(
            service.authenticate("Bearer too-short"),
            Err(McpTokenServiceError::MalformedBearer)
        ));
        assert!(matches!(
            service.authenticate(&format!("bearer {}", issued.reveal().as_str())),
            Err(McpTokenServiceError::MalformedBearer)
        ));
        Ok(())
    }

    #[test]
    fn revoke_and_rotate_fence_old_reveals_and_preserve_scopes() -> Result<(), Box<dyn Error>> {
        let mut service = service();
        let issued = service.issue(request()?)?;
        let rotated = service.rotate(
            issued.metadata().id(),
            issued.metadata().revision(),
            timestamp(2)?,
        )?;
        let old_authorization = format!("Bearer {}", issued.reveal().as_str());
        let new_authorization = format!("Bearer {}", rotated.replacement().reveal().as_str());
        assert!(service.authenticate(&old_authorization)?.is_none());
        assert_eq!(
            service
                .authenticate(&new_authorization)?
                .ok_or("rotated auth missing")?
                .scopes(),
            &[scope(10)]
        );
        assert_eq!(rotated.predecessor().state(), McpTokenState::Rotated);

        let revoked = service.revoke(
            rotated.replacement().metadata().id(),
            rotated.replacement().metadata().revision(),
            timestamp(3)?,
        )?;
        assert_eq!(revoked.state(), McpTokenState::Revoked);
        assert!(
            service
                .authenticate(&format!(
                    "Bearer {}",
                    rotated.replacement().reveal().as_str()
                ))?
                .is_none()
        );
        Ok(())
    }

    #[test]
    fn worker_is_bounded_and_shutdown_joins_after_saturation() -> Result<(), Box<dyn Error>> {
        let (entered_tx, entered_rx) = mpsc::sync_channel(0);
        let (release_tx, release_rx) = mpsc::sync_channel(0);
        let service = McpTokenService::new(
            [0x5a; MCP_TOKEN_DIGEST_BYTES],
            BlockingCatalog {
                inner: MemoryCatalog::default(),
                entered: Some(entered_tx),
                release: Some(release_rx),
            },
        );
        let (client, mut worker) = McpTokenWorker::start(service)?;
        let first = client.submit_get(McpTokenId::from_uuid(Uuid::from_u128(99)))?;
        entered_rx.recv()?;
        let mut queued = Vec::with_capacity(MCP_TOKEN_QUEUE_CAPACITY);
        for _ in 0..MCP_TOKEN_QUEUE_CAPACITY {
            queued.push(client.submit_get(McpTokenId::from_uuid(Uuid::from_u128(100)))?);
        }
        assert!(matches!(
            client.submit_get(McpTokenId::from_uuid(Uuid::from_u128(101))),
            Err(McpTokenClientError::QueueFull)
        ));
        release_tx.send(())?;
        assert!(first.recv()?.is_none());
        for pending in queued {
            assert!(pending.recv()?.is_none());
        }
        worker.shutdown()?;
        assert!(!client.is_accepting());
        assert!(matches!(
            client.submit_get(McpTokenId::from_uuid(Uuid::from_u128(102))),
            Err(McpTokenClientError::WorkerShuttingDown)
        ));
        Ok(())
    }

    #[test]
    fn list_and_get_are_typed_non_secret_projections() -> Result<(), Box<dyn Error>> {
        let mut service = service();
        let issued = service.issue(request()?)?;
        let listed = service.list(1)?;
        assert_eq!(listed, vec![issued.metadata().clone()]);
        assert_eq!(
            service.get(issued.metadata().id())?,
            Some(issued.metadata().clone())
        );
        assert!(matches!(
            service.list(MAX_MCP_TOKEN_LIST_RESULTS + 1),
            Err(McpTokenServiceError::InvalidListLimit { .. })
        ));
        Ok(())
    }
}
