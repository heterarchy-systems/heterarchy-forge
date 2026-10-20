//! Stable authenticated identities used by durable Agent and Coordinator
//! authority.
//!
//! A principal is an identity, not a bearer credential.  Direct token
//! identities and OAuth grant identities are deliberately distinct so a
//! rotating OAuth access token can never silently replace the durable grant
//! that owns an attachment.  No raw token, verifier, or other secret is
//! represented here.

/// Stable authentication identity for one FORGE participant.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AuthenticatedPrincipal {
    /// The in-process/bounded stdio transport established by FORGE itself.
    TrustedStdio,
    /// A directly issued local token identity.
    DirectToken(DirectTokenId),
    /// A durable OAuth grant identity.  Access tokens issued for the grant
    /// may rotate without changing this principal.
    OAuthGrant(OAuthGrantId),
}

impl AuthenticatedPrincipal {
    /// Returns the direct token identity, if this principal is token based.
    pub const fn direct_token_id(self) -> Option<DirectTokenId> {
        match self {
            Self::DirectToken(id) => Some(id),
            Self::TrustedStdio | Self::OAuthGrant(_) => None,
        }
    }

    /// Returns the durable OAuth grant identity, if this principal is OAuth
    /// based.
    pub const fn oauth_grant_id(self) -> Option<OAuthGrantId> {
        match self {
            Self::OAuthGrant(id) => Some(id),
            Self::TrustedStdio | Self::DirectToken(_) => None,
        }
    }

    /// Whether this identity was established by the trusted stdio boundary.
    pub const fn is_trusted_stdio(self) -> bool {
        matches!(self, Self::TrustedStdio)
    }

    /// Whether this identity requires a token-capable transport.
    pub const fn is_token_or_grant_authenticated(self) -> bool {
        matches!(self, Self::DirectToken(_) | Self::OAuthGrant(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn principal_keeps_direct_and_oauth_identities_distinct() {
        let token = DirectTokenId::from_uuid(Uuid::from_u128(1));
        let grant = OAuthGrantId::from_uuid(Uuid::from_u128(2));
        let direct = AuthenticatedPrincipal::DirectToken(token);
        let oauth = AuthenticatedPrincipal::OAuthGrant(grant);

        assert_eq!(direct.direct_token_id(), Some(token));
        assert_eq!(direct.oauth_grant_id(), None);
        assert_eq!(oauth.direct_token_id(), None);
        assert_eq!(oauth.oauth_grant_id(), Some(grant));
        assert!(AuthenticatedPrincipal::TrustedStdio.is_trusted_stdio());
        assert!(!AuthenticatedPrincipal::TrustedStdio.is_token_or_grant_authenticated());
        assert!(oauth.is_token_or_grant_authenticated());
    }
}

// ---------------------------------------------------------------------------
// Legacy identity discriminants.
//
// The retired server/token/OAuth implementation is gone, but persisted rows
// and the session wire still reference these principal discriminants, so the
// typed identities remain as inert data-compat surface owned by the session
// identity module. No behavior attaches to them any more.
// ---------------------------------------------------------------------------

use std::fmt;
use std::str::FromStr;
use thiserror::Error;
use uuid::Uuid;

/// Durable identity of a directly issued local token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DirectTokenId(Uuid);

impl DirectTokenId {
    pub const fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }

    pub const fn into_uuid(self) -> Uuid {
        self.0
    }
}

impl fmt::Display for DirectTokenId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum DirectTokenIdParseError {
    #[error("direct token id is not a valid UUID")]
    InvalidUuid,
}

impl FromStr for DirectTokenId {
    type Err = DirectTokenIdParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(value)
            .map(Self)
            .map_err(|_| DirectTokenIdParseError::InvalidUuid)
    }
}

/// Durable identity of an OAuth grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OAuthGrantId(Uuid);

impl OAuthGrantId {
    pub const fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }

    pub const fn into_uuid(self) -> Uuid {
        self.0
    }
}

impl fmt::Display for OAuthGrantId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum OAuthGrantIdParseError {
    #[error("OAuth grant id is not a valid UUID")]
    InvalidUuid,
}

impl FromStr for OAuthGrantId {
    type Err = OAuthGrantIdParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(value)
            .map(Self)
            .map_err(|_| OAuthGrantIdParseError::InvalidUuid)
    }
}
