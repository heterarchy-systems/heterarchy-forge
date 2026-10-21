//! Versioned, transport-neutral remote Agent-session authority wire.
//!
//! This module carries only durable session identity and lifecycle metadata.
//! It never carries a bearer credential, raw token, or provider error detail.

use std::fmt;

use forge_control::AgentSessionResolveRequest;
use forge_domain::{
    AgentSessionId, AgentSessionOpenRequestId, AgentSessionRecordParts, AgentSessionRevision,
    AgentSessionState, AuthenticatedPrincipal, DirectTokenId, OAuthGrantId, RegisteredAgentSession,
    TimestampMillis,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const REMOTE_SESSION_PROTOCOL_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionIdentityField {
    SessionId,
    RequestId,
    TokenId,
    GrantId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionProtocolError {
    MalformedWire,
    UnsupportedVersion { expected: u16, actual: u16 },
    NilIdentity(SessionIdentityField),
    InvalidRevision,
    InvalidTimestamp,
    InvalidLifecycle,
}

impl fmt::Display for SessionProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedWire => formatter.write_str("remote session wire is malformed"),
            Self::UnsupportedVersion { expected, actual } => {
                write!(
                    formatter,
                    "remote session protocol version {actual} is unsupported; expected {expected}"
                )
            }
            Self::NilIdentity(field) => {
                write!(formatter, "remote session identity {field:?} is nil")
            }
            Self::InvalidRevision => formatter.write_str("remote session revision is invalid"),
            Self::InvalidTimestamp => formatter.write_str("remote session timestamp is invalid"),
            Self::InvalidLifecycle => formatter.write_str("remote session lifecycle is invalid"),
        }
    }
}

impl std::error::Error for SessionProtocolError {}

/// Principal identity carried on the remote session wire.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RemoteSessionPrincipal {
    TrustedStdio,
    DirectToken {
        token_id: Uuid,
    },
    #[serde(rename = "oauth_grant")]
    OAuthGrant {
        grant_id: Uuid,
    },
}

impl RemoteSessionPrincipal {
    fn from_domain(value: AuthenticatedPrincipal) -> Result<Self, SessionProtocolError> {
        match value {
            AuthenticatedPrincipal::TrustedStdio => Ok(Self::TrustedStdio),
            AuthenticatedPrincipal::DirectToken(id) => {
                let uuid = id.into_uuid();
                reject_nil(uuid, SessionIdentityField::TokenId)?;
                Ok(Self::DirectToken { token_id: uuid })
            }
            AuthenticatedPrincipal::OAuthGrant(id) => {
                let uuid = id.into_uuid();
                reject_nil(uuid, SessionIdentityField::GrantId)?;
                Ok(Self::OAuthGrant { grant_id: uuid })
            }
        }
    }

    fn into_domain(self) -> Result<AuthenticatedPrincipal, SessionProtocolError> {
        match self {
            Self::TrustedStdio => Ok(AuthenticatedPrincipal::TrustedStdio),
            Self::DirectToken { token_id } => {
                reject_nil(token_id, SessionIdentityField::TokenId)?;
                Ok(AuthenticatedPrincipal::DirectToken(
                    DirectTokenId::from_uuid(token_id),
                ))
            }
            Self::OAuthGrant { grant_id } => {
                reject_nil(grant_id, SessionIdentityField::GrantId)?;
                Ok(AuthenticatedPrincipal::OAuthGrant(OAuthGrantId::from_uuid(
                    grant_id,
                )))
            }
        }
    }
}

/// Request sent to a remote session authority.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteSessionResolveRequest {
    pub version: u16,
    pub session_id: Uuid,
    pub principal: RemoteSessionPrincipal,
}

impl RemoteSessionResolveRequest {
    pub fn from_request(value: &AgentSessionResolveRequest) -> Result<Self, SessionProtocolError> {
        reject_nil(
            value.session_id.into_uuid(),
            SessionIdentityField::SessionId,
        )?;
        Ok(Self {
            version: REMOTE_SESSION_PROTOCOL_VERSION,
            session_id: value.session_id.into_uuid(),
            principal: RemoteSessionPrincipal::from_domain(value.principal)?,
        })
    }

    pub fn into_request(self) -> Result<AgentSessionResolveRequest, SessionProtocolError> {
        validate_version(self.version)?;
        reject_nil(self.session_id, SessionIdentityField::SessionId)?;
        Ok(AgentSessionResolveRequest {
            session_id: AgentSessionId::from_uuid(self.session_id),
            principal: self.principal.into_domain()?,
        })
    }
}

/// Session lifecycle state carried by a found reply.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum RemoteSessionState {
    Open,
    Closed,
}

/// Durable metadata returned for one found session.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteSessionMetadata {
    pub session_id: Uuid,
    pub principal: RemoteSessionPrincipal,
    pub request_id: Uuid,
    pub state: RemoteSessionState,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub revision: i64,
}

impl RemoteSessionMetadata {
    fn from_domain(value: &RegisteredAgentSession) -> Result<Self, SessionProtocolError> {
        reject_nil(value.id().into_uuid(), SessionIdentityField::SessionId)?;
        reject_nil(
            value.request_id().into_uuid(),
            SessionIdentityField::RequestId,
        )?;
        Ok(Self {
            session_id: value.id().into_uuid(),
            principal: RemoteSessionPrincipal::from_domain(value.principal())?,
            request_id: value.request_id().into_uuid(),
            state: RemoteSessionState::from_domain(value.state()),
            created_at_ms: value.created_at().get(),
            updated_at_ms: value.updated_at().get(),
            revision: value.revision().get(),
        })
    }

    fn into_domain(self) -> Result<RegisteredAgentSession, SessionProtocolError> {
        reject_nil(self.session_id, SessionIdentityField::SessionId)?;
        reject_nil(self.request_id, SessionIdentityField::RequestId)?;
        let created_at = decode_timestamp(self.created_at_ms)?;
        let updated_at = decode_timestamp(self.updated_at_ms)?;
        let revision = AgentSessionRevision::new(self.revision)
            .map_err(|_| SessionProtocolError::InvalidRevision)?;
        RegisteredAgentSession::from_parts(AgentSessionRecordParts {
            id: AgentSessionId::from_uuid(self.session_id),
            principal: self.principal.into_domain()?,
            request_id: AgentSessionOpenRequestId::from_uuid(self.request_id),
            state: self.state.into_domain(),
            created_at,
            updated_at,
            revision,
        })
        .map_err(|_| SessionProtocolError::InvalidLifecycle)
    }
}

impl RemoteSessionState {
    const fn from_domain(value: AgentSessionState) -> Self {
        match value {
            AgentSessionState::Open => Self::Open,
            AgentSessionState::Closed => Self::Closed,
        }
    }

    const fn into_domain(self) -> AgentSessionState {
        match self {
            Self::Open => AgentSessionState::Open,
            Self::Closed => AgentSessionState::Closed,
        }
    }
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RemoteSessionResolveOutcome {
    Found { session: RemoteSessionMetadata },
    NotFound,
}

/// Reply from a remote session authority.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteSessionResolveReply {
    pub version: u16,
    pub outcome: RemoteSessionResolveOutcome,
}

impl RemoteSessionResolveReply {
    pub fn from_session(
        value: Option<&RegisteredAgentSession>,
    ) -> Result<Self, SessionProtocolError> {
        let outcome = match value {
            Some(session) => RemoteSessionResolveOutcome::Found {
                session: RemoteSessionMetadata::from_domain(session)?,
            },
            None => RemoteSessionResolveOutcome::NotFound,
        };
        Ok(Self {
            version: REMOTE_SESSION_PROTOCOL_VERSION,
            outcome,
        })
    }

    pub fn into_session(self) -> Result<Option<RegisteredAgentSession>, SessionProtocolError> {
        validate_version(self.version)?;
        match self.outcome {
            RemoteSessionResolveOutcome::Found { session } => session.into_domain().map(Some),
            RemoteSessionResolveOutcome::NotFound => Ok(None),
        }
    }
}

pub fn decode_request(
    value: serde_json::Value,
) -> Result<RemoteSessionResolveRequest, SessionProtocolError> {
    serde_json::from_value(value).map_err(|_| SessionProtocolError::MalformedWire)
}

pub fn decode_reply(
    value: serde_json::Value,
) -> Result<RemoteSessionResolveReply, SessionProtocolError> {
    serde_json::from_value(value).map_err(|_| SessionProtocolError::MalformedWire)
}

fn validate_version(value: u16) -> Result<(), SessionProtocolError> {
    if value == REMOTE_SESSION_PROTOCOL_VERSION {
        Ok(())
    } else {
        Err(SessionProtocolError::UnsupportedVersion {
            expected: REMOTE_SESSION_PROTOCOL_VERSION,
            actual: value,
        })
    }
}

fn reject_nil(value: Uuid, field: SessionIdentityField) -> Result<(), SessionProtocolError> {
    if value.is_nil() {
        Err(SessionProtocolError::NilIdentity(field))
    } else {
        Ok(())
    }
}

fn decode_timestamp(value: i64) -> Result<TimestampMillis, SessionProtocolError> {
    TimestampMillis::new(value).map_err(|_| SessionProtocolError::InvalidTimestamp)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn timestamp(value: i64) -> Result<TimestampMillis, SessionProtocolError> {
        TimestampMillis::new(value).map_err(|_| SessionProtocolError::InvalidTimestamp)
    }

    fn closed_session() -> Result<RegisteredAgentSession, SessionProtocolError> {
        let session = RegisteredAgentSession::open(
            AgentSessionId::from_uuid(Uuid::from_u128(11)),
            AgentSessionOpenRequestId::from_uuid(Uuid::from_u128(12)),
            AuthenticatedPrincipal::OAuthGrant(OAuthGrantId::from_uuid(Uuid::from_u128(13))),
            timestamp(20)?,
        );
        session
            .close(AgentSessionRevision::INITIAL, timestamp(21)?)
            .map_err(|_| SessionProtocolError::InvalidLifecycle)
    }

    #[test]
    fn closed_oauth_session_and_resolve_request_round_trip_all_metadata()
    -> Result<(), Box<dyn std::error::Error>> {
        let session = closed_session()?;
        let reply = RemoteSessionResolveReply::from_session(Some(&session))?;
        let encoded = serde_json::to_value(&reply)?;
        assert_eq!(
            encoded["outcome"]["session"]["principal"]["kind"],
            "oauth_grant"
        );
        let decoded = decode_reply(encoded)?;
        assert_eq!(decoded.into_session()?, Some(session.clone()));

        let request = AgentSessionResolveRequest {
            session_id: session.id(),
            principal: session.principal(),
        };
        let wire = RemoteSessionResolveRequest::from_request(&request)?;
        let request_round_trip = wire.into_request()?;
        assert_eq!(request_round_trip.session_id, request.session_id);
        assert_eq!(request_round_trip.principal, request.principal);
        Ok(())
    }

    #[test]
    fn malformed_old_and_wrong_version_requests_are_rejected()
    -> Result<(), Box<dyn std::error::Error>> {
        let old = serde_json::json!({"valid": true});
        assert_eq!(
            decode_request(old),
            Err(SessionProtocolError::MalformedWire)
        );

        let wrong_version = decode_request(serde_json::json!({
            "version": 2,
            "session_id": Uuid::from_u128(21),
            "principal": {"kind": "trusted_stdio"}
        }))?;
        assert!(matches!(
            wrong_version.into_request(),
            Err(SessionProtocolError::UnsupportedVersion {
                expected: REMOTE_SESSION_PROTOCOL_VERSION,
                actual: 2,
            })
        ));

        let bad_principal = decode_request(serde_json::json!({
            "version": REMOTE_SESSION_PROTOCOL_VERSION,
            "session_id": Uuid::from_u128(22),
            "principal": {"kind": "direct_token", "token_id": Uuid::nil()}
        }))?;
        assert!(matches!(
            bad_principal.into_request(),
            Err(SessionProtocolError::NilIdentity(
                SessionIdentityField::TokenId
            ))
        ));
        Ok(())
    }
}
