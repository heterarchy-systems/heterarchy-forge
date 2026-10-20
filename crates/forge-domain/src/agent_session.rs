//! Durable application-global identity for one logical agent session.
//!
//! An [`AgentSessionId`] identifies a logical session issued by FORGE before
//! that session is attached to any Workspace or Activity.  It is deliberately
//! separate from [`crate::AgentInstanceId`], which identifies the immutable
//! attachment record inside a Workspace.  This module contains no bearer
//! credential, `ChatGPT` metadata, Workspace state, or I/O authority.

use std::fmt;
use std::str::FromStr;

use thiserror::Error;
use uuid::Uuid;

use crate::{AuthenticatedPrincipal, TimestampMillis};

/// Opaque, server-issued identity for one logical Agent session.
///
/// This value is an identifier only.  It is not a secret and must not be
/// treated as a bearer credential.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AgentSessionId(Uuid);

impl AgentSessionId {
    pub const fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }

    pub const fn into_uuid(self) -> Uuid {
        self.0
    }
}

impl fmt::Display for AgentSessionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for AgentSessionId {
    type Err = AgentSessionIdParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(value)
            .map(Self)
            .map_err(AgentSessionIdParseError::InvalidUuid)
    }
}

#[derive(Debug, Error)]
pub enum AgentSessionIdParseError {
    #[error("invalid Agent session UUID")]
    InvalidUuid(#[source] uuid::Error),
}

/// Caller supplied retry nonce for opening a logical Agent session.
///
/// This is scoped to the authenticated principal in the catalog.  It is not
/// the durable session identity; a retry may propose a different session ID
/// and still receives the original session for the same principal and nonce.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AgentSessionOpenRequestId(Uuid);

impl AgentSessionOpenRequestId {
    pub const fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }

    pub const fn into_uuid(self) -> Uuid {
        self.0
    }
}

impl fmt::Display for AgentSessionOpenRequestId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for AgentSessionOpenRequestId {
    type Err = AgentSessionOpenRequestIdParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(value)
            .map(Self)
            .map_err(AgentSessionOpenRequestIdParseError::InvalidUuid)
    }
}

#[derive(Debug, Error)]
pub enum AgentSessionOpenRequestIdParseError {
    #[error("invalid Agent session open request UUID")]
    InvalidUuid(#[source] uuid::Error),
}

/// Positive compare-and-set revision for one logical Agent session.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AgentSessionRevision(i64);

impl AgentSessionRevision {
    pub const INITIAL: Self = Self(1);

    pub const fn new(value: i64) -> Result<Self, AgentSessionRevisionError> {
        if value > 0 {
            Ok(Self(value))
        } else {
            Err(AgentSessionRevisionError::Invalid(value))
        }
    }

    pub const fn get(self) -> i64 {
        self.0
    }

    pub const fn checked_next(self) -> Result<Self, AgentSessionRevisionError> {
        match self.0.checked_add(1) {
            Some(value) => Ok(Self(value)),
            None => Err(AgentSessionRevisionError::Overflow(self.0)),
        }
    }
}

impl fmt::Display for AgentSessionRevision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum AgentSessionRevisionError {
    #[error("Agent session revision must be positive, got {0}")]
    Invalid(i64),
    #[error("Agent session revision overflowed from {0}")]
    Overflow(i64),
}

/// Lifecycle state of one logical Agent session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AgentSessionState {
    Open,
    Closed,
}

/// Checked rehydration input for the Agent session persistence codec.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentSessionRecordParts {
    pub id: AgentSessionId,
    pub principal: AuthenticatedPrincipal,
    pub request_id: AgentSessionOpenRequestId,
    pub state: AgentSessionState,
    pub created_at: TimestampMillis,
    pub updated_at: TimestampMillis,
    pub revision: AgentSessionRevision,
}

/// Durable projection for one logical Agent session.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredAgentSession {
    id: AgentSessionId,
    principal: AuthenticatedPrincipal,
    request_id: AgentSessionOpenRequestId,
    state: AgentSessionState,
    created_at: TimestampMillis,
    updated_at: TimestampMillis,
    revision: AgentSessionRevision,
}

impl RegisteredAgentSession {
    /// Construct the initial open session issued by the application boundary.
    pub fn open(
        id: AgentSessionId,
        request_id: AgentSessionOpenRequestId,
        principal: AuthenticatedPrincipal,
        observed_at: TimestampMillis,
    ) -> Self {
        Self {
            id,
            principal,
            request_id,
            state: AgentSessionState::Open,
            created_at: observed_at,
            updated_at: observed_at,
            revision: AgentSessionRevision::INITIAL,
        }
    }

    /// Rehydrate a persisted session after checking its lifecycle shape.
    pub fn from_parts(parts: AgentSessionRecordParts) -> Result<Self, AgentSessionTransitionError> {
        if parts.updated_at.get() < parts.created_at.get() {
            return Err(AgentSessionTransitionError::TimestampOrder);
        }
        if parts.revision == AgentSessionRevision::INITIAL
            && (parts.state != AgentSessionState::Open || parts.updated_at != parts.created_at)
        {
            return Err(AgentSessionTransitionError::InvalidInitialProjection);
        }
        Ok(Self {
            id: parts.id,
            principal: parts.principal,
            request_id: parts.request_id,
            state: parts.state,
            created_at: parts.created_at,
            updated_at: parts.updated_at,
            revision: parts.revision,
        })
    }

    /// Close the session using an exact revision and monotonic observation.
    pub fn close(
        &self,
        expected_revision: AgentSessionRevision,
        observed_at: TimestampMillis,
    ) -> Result<Self, AgentSessionTransitionError> {
        if self.revision != expected_revision {
            return Err(AgentSessionTransitionError::RevisionConflict);
        }
        if self.state == AgentSessionState::Closed {
            return Err(AgentSessionTransitionError::AlreadyClosed);
        }
        if observed_at.get() < self.updated_at.get() {
            return Err(AgentSessionTransitionError::TimestampOrder);
        }
        Ok(Self {
            id: self.id,
            principal: self.principal,
            request_id: self.request_id,
            state: AgentSessionState::Closed,
            created_at: self.created_at,
            updated_at: observed_at,
            revision: self.revision.checked_next()?,
        })
    }

    pub const fn id(&self) -> AgentSessionId {
        self.id
    }

    pub const fn principal(&self) -> AuthenticatedPrincipal {
        self.principal
    }

    pub const fn request_id(&self) -> AgentSessionOpenRequestId {
        self.request_id
    }

    pub const fn state(&self) -> AgentSessionState {
        self.state
    }

    pub const fn created_at(&self) -> TimestampMillis {
        self.created_at
    }

    pub const fn updated_at(&self) -> TimestampMillis {
        self.updated_at
    }

    pub const fn revision(&self) -> AgentSessionRevision {
        self.revision
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum AgentSessionTransitionError {
    #[error("Agent session timestamps are out of order")]
    TimestampOrder,
    #[error("Agent session initial projection is invalid")]
    InvalidInitialProjection,
    #[error("Agent session revision does not match")]
    RevisionConflict,
    #[error("Agent session is already closed")]
    AlreadyClosed,
    #[error(transparent)]
    Revision(#[from] AgentSessionRevisionError),
}

/// Command to issue or idempotently recover one logical Agent session.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenAgentSession {
    proposed_id: AgentSessionId,
    request_id: AgentSessionOpenRequestId,
    principal: AuthenticatedPrincipal,
    observed_at: TimestampMillis,
}

impl OpenAgentSession {
    pub const fn new(
        proposed_id: AgentSessionId,
        request_id: AgentSessionOpenRequestId,
        principal: AuthenticatedPrincipal,
        observed_at: TimestampMillis,
    ) -> Self {
        Self {
            proposed_id,
            request_id,
            principal,
            observed_at,
        }
    }

    pub const fn proposed_id(&self) -> AgentSessionId {
        self.proposed_id
    }

    pub const fn request_id(&self) -> AgentSessionOpenRequestId {
        self.request_id
    }

    pub const fn principal(&self) -> AuthenticatedPrincipal {
        self.principal
    }

    pub const fn observed_at(&self) -> TimestampMillis {
        self.observed_at
    }
}

/// Result of an idempotent session open.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentSessionOpenOutcome {
    session: RegisteredAgentSession,
    created: bool,
}

impl AgentSessionOpenOutcome {
    pub const fn new(session: RegisteredAgentSession, created: bool) -> Self {
        Self { session, created }
    }

    pub const fn session(&self) -> &RegisteredAgentSession {
        &self.session
    }

    pub const fn created(&self) -> bool {
        self.created
    }

    pub fn into_session(self) -> RegisteredAgentSession {
        self.session
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::str::FromStr;

    use super::*;
    use crate::{DirectTokenId, TimestampMillis};

    fn timestamp(value: i64) -> Result<TimestampMillis, Box<dyn Error>> {
        Ok(TimestampMillis::new(value)?)
    }

    #[test]
    fn session_and_request_ids_are_distinct_typed_round_trips() -> Result<(), Box<dyn Error>> {
        let session = AgentSessionId::from_uuid(Uuid::from_u128(1));
        let request = AgentSessionOpenRequestId::from_uuid(Uuid::from_u128(2));
        assert_eq!(session.to_string(), Uuid::from_u128(1).to_string());
        assert_eq!(request.to_string(), Uuid::from_u128(2).to_string());
        assert_eq!(AgentSessionId::from_str(&session.to_string())?, session);
        assert_eq!(
            AgentSessionOpenRequestId::from_str(&request.to_string())?,
            request
        );
        assert_ne!(session.into_uuid(), request.into_uuid());
        Ok(())
    }

    #[test]
    fn open_is_idempotent_at_the_domain_boundary_and_close_is_cas_fenced()
    -> Result<(), Box<dyn Error>> {
        let principal =
            AuthenticatedPrincipal::DirectToken(DirectTokenId::from_uuid(Uuid::from_u128(3)));
        let session = RegisteredAgentSession::open(
            AgentSessionId::from_uuid(Uuid::from_u128(4)),
            AgentSessionOpenRequestId::from_uuid(Uuid::from_u128(5)),
            principal,
            timestamp(10)?,
        );
        assert_eq!(session.state(), AgentSessionState::Open);
        assert_eq!(session.revision(), AgentSessionRevision::INITIAL);
        let closed = session.close(AgentSessionRevision::INITIAL, timestamp(11)?)?;
        assert_eq!(closed.state(), AgentSessionState::Closed);
        assert_eq!(closed.revision().get(), 2);
        assert_eq!(
            closed.close(AgentSessionRevision::INITIAL, timestamp(12)?),
            Err(AgentSessionTransitionError::RevisionConflict)
        );
        assert_eq!(
            closed.close(closed.revision(), timestamp(12)?),
            Err(AgentSessionTransitionError::AlreadyClosed)
        );
        Ok(())
    }

    #[test]
    fn persisted_initial_projection_is_checked() -> Result<(), Box<dyn Error>> {
        let parts = AgentSessionRecordParts {
            id: AgentSessionId::from_uuid(Uuid::from_u128(6)),
            principal: AuthenticatedPrincipal::TrustedStdio,
            request_id: AgentSessionOpenRequestId::from_uuid(Uuid::from_u128(7)),
            state: AgentSessionState::Closed,
            created_at: timestamp(20)?,
            updated_at: timestamp(20)?,
            revision: AgentSessionRevision::INITIAL,
        };
        assert_eq!(
            RegisteredAgentSession::from_parts(parts),
            Err(AgentSessionTransitionError::InvalidInitialProjection)
        );
        Ok(())
    }

    #[test]
    fn request_command_keeps_principal_bound() -> Result<(), Box<dyn Error>> {
        let principal = AuthenticatedPrincipal::TrustedStdio;
        let command = OpenAgentSession::new(
            AgentSessionId::from_uuid(Uuid::from_u128(8)),
            AgentSessionOpenRequestId::from_uuid(Uuid::from_u128(9)),
            principal,
            timestamp(30)?,
        );
        assert_eq!(command.principal(), principal);
        assert_eq!(command.observed_at(), timestamp(30)?);
        Ok(())
    }
}
