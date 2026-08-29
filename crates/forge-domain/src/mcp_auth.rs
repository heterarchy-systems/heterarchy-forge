//! Typed local MCP bearer-token metadata and lifecycle invariants.
//!
//! Raw bearer bytes and the keyed-hash pepper never enter this domain model.

use std::fmt;
use std::str::FromStr;

use thiserror::Error;
use uuid::Uuid;

use crate::{LocationId, TimestampMillis, WorkspaceId};

pub const MCP_TOKEN_DIGEST_BYTES: usize = 32;
pub const MAX_MCP_TOKEN_LABEL_BYTES: usize = 128;
pub const MAX_MCP_TOKEN_SCOPES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct McpTokenId(Uuid);

impl McpTokenId {
    pub const fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }

    pub const fn into_uuid(self) -> Uuid {
        self.0
    }
}

impl fmt::Display for McpTokenId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for McpTokenId {
    type Err = McpTokenIdParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(value)
            .map(Self)
            .map_err(McpTokenIdParseError::InvalidUuid)
    }
}

#[derive(Debug, Error)]
pub enum McpTokenIdParseError {
    #[error("invalid MCP token UUID")]
    InvalidUuid(#[source] uuid::Error),
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpTokenLabel(String);

impl McpTokenLabel {
    pub fn new(value: String) -> Result<Self, McpTokenLabelError> {
        if value.is_empty() {
            return Err(McpTokenLabelError::Empty);
        }
        if value.len() > MAX_MCP_TOKEN_LABEL_BYTES {
            return Err(McpTokenLabelError::TooLong {
                actual: value.len(),
                maximum: MAX_MCP_TOKEN_LABEL_BYTES,
            });
        }
        if value.chars().any(char::is_control) {
            return Err(McpTokenLabelError::ControlCharacter);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum McpTokenLabelError {
    #[error("MCP token label is empty")]
    Empty,
    #[error("MCP token label is {actual} bytes; maximum is {maximum}")]
    TooLong { actual: usize, maximum: usize },
    #[error("MCP token label contains a control character")]
    ControlCharacter,
}

/// Keyed digest persisted for bearer-token lookup. Debug output is redacted.
#[must_use]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct McpTokenDigest([u8; MCP_TOKEN_DIGEST_BYTES]);

impl McpTokenDigest {
    pub const fn new(bytes: [u8; MCP_TOKEN_DIGEST_BYTES]) -> Self {
        Self(bytes)
    }

    pub const fn into_bytes(self) -> [u8; MCP_TOKEN_DIGEST_BYTES] {
        self.0
    }
}

impl fmt::Debug for McpTokenDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("McpTokenDigest(<redacted>)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct McpTokenRevision(i64);

impl McpTokenRevision {
    pub const INITIAL: Self = Self(1);

    pub const fn new(value: i64) -> Result<Self, McpTokenRevisionError> {
        if value > 0 {
            Ok(Self(value))
        } else {
            Err(McpTokenRevisionError::Invalid(value))
        }
    }

    pub const fn get(self) -> i64 {
        self.0
    }

    pub const fn checked_next(self) -> Result<Self, McpTokenRevisionError> {
        match self.0.checked_add(1) {
            Some(value) => Ok(Self(value)),
            None => Err(McpTokenRevisionError::Overflow(self.0)),
        }
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum McpTokenRevisionError {
    #[error("MCP token revision must be positive, got {0}")]
    Invalid(i64),
    #[error("MCP token revision overflowed from {0}")]
    Overflow(i64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum McpTokenState {
    Active,
    Revoked,
    Rotated,
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct McpTokenWorkspaceScope {
    location_id: LocationId,
    workspace_id: WorkspaceId,
}

impl McpTokenWorkspaceScope {
    pub const fn new(location_id: LocationId, workspace_id: WorkspaceId) -> Self {
        Self {
            location_id,
            workspace_id,
        }
    }

    pub const fn location_id(self) -> LocationId {
        self.location_id
    }

    pub const fn workspace_id(self) -> WorkspaceId {
        self.workspace_id
    }
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredMcpToken {
    id: McpTokenId,
    label: McpTokenLabel,
    digest: McpTokenDigest,
    state: McpTokenState,
    scopes: Vec<McpTokenWorkspaceScope>,
    created_at: TimestampMillis,
    disabled_at: Option<TimestampMillis>,
    replacement_token_id: Option<McpTokenId>,
    revision: McpTokenRevision,
}

/// Checked rehydration input for persistence codecs.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpTokenRecordParts {
    pub id: McpTokenId,
    pub label: McpTokenLabel,
    pub digest: McpTokenDigest,
    pub state: McpTokenState,
    pub scopes: Vec<McpTokenWorkspaceScope>,
    pub created_at: TimestampMillis,
    pub disabled_at: Option<TimestampMillis>,
    pub replacement_token_id: Option<McpTokenId>,
    pub revision: McpTokenRevision,
}

impl RegisteredMcpToken {
    pub fn issue(
        id: McpTokenId,
        label: McpTokenLabel,
        digest: McpTokenDigest,
        scopes: Vec<McpTokenWorkspaceScope>,
        created_at: TimestampMillis,
    ) -> Result<Self, McpTokenTransitionError> {
        Self::from_parts(McpTokenRecordParts {
            id,
            label,
            digest,
            state: McpTokenState::Active,
            scopes,
            created_at,
            disabled_at: None,
            replacement_token_id: None,
            revision: McpTokenRevision::INITIAL,
        })
    }

    pub fn from_parts(parts: McpTokenRecordParts) -> Result<Self, McpTokenTransitionError> {
        let McpTokenRecordParts {
            id,
            label,
            digest,
            state,
            mut scopes,
            created_at,
            disabled_at,
            replacement_token_id,
            revision,
        } = parts;
        validate_scopes(&mut scopes)?;
        validate_lifecycle(id, state, created_at, disabled_at, replacement_token_id)?;
        Ok(Self {
            id,
            label,
            digest,
            state,
            scopes,
            created_at,
            disabled_at,
            replacement_token_id,
            revision,
        })
    }

    pub fn revoke(
        &self,
        expected_revision: McpTokenRevision,
        disabled_at: TimestampMillis,
    ) -> Result<Self, McpTokenTransitionError> {
        self.ensure_active_revision(expected_revision, disabled_at)?;
        Self::from_parts(McpTokenRecordParts {
            id: self.id,
            label: self.label.clone(),
            digest: self.digest,
            state: McpTokenState::Revoked,
            scopes: self.scopes.clone(),
            created_at: self.created_at,
            disabled_at: Some(disabled_at),
            replacement_token_id: None,
            revision: self.revision.checked_next()?,
        })
    }

    pub fn rotate(
        &self,
        replacement_token_id: McpTokenId,
        expected_revision: McpTokenRevision,
        disabled_at: TimestampMillis,
    ) -> Result<Self, McpTokenTransitionError> {
        self.ensure_active_revision(expected_revision, disabled_at)?;
        if replacement_token_id == self.id {
            return Err(McpTokenTransitionError::ReplacementIdentity);
        }
        Self::from_parts(McpTokenRecordParts {
            id: self.id,
            label: self.label.clone(),
            digest: self.digest,
            state: McpTokenState::Rotated,
            scopes: self.scopes.clone(),
            created_at: self.created_at,
            disabled_at: Some(disabled_at),
            replacement_token_id: Some(replacement_token_id),
            revision: self.revision.checked_next()?,
        })
    }

    fn ensure_active_revision(
        &self,
        expected_revision: McpTokenRevision,
        disabled_at: TimestampMillis,
    ) -> Result<(), McpTokenTransitionError> {
        if self.revision != expected_revision {
            return Err(McpTokenTransitionError::RevisionConflict);
        }
        if self.state != McpTokenState::Active {
            return Err(McpTokenTransitionError::TerminalState);
        }
        if disabled_at.get() < self.created_at.get() {
            return Err(McpTokenTransitionError::TimestampOrder);
        }
        Ok(())
    }

    pub const fn id(&self) -> McpTokenId {
        self.id
    }

    pub const fn label(&self) -> &McpTokenLabel {
        &self.label
    }

    pub const fn digest(&self) -> McpTokenDigest {
        self.digest
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

fn validate_scopes(scopes: &mut [McpTokenWorkspaceScope]) -> Result<(), McpTokenTransitionError> {
    if scopes.is_empty() {
        return Err(McpTokenTransitionError::EmptyScopes);
    }
    if scopes.len() > MAX_MCP_TOKEN_SCOPES {
        return Err(McpTokenTransitionError::ScopeCapacity {
            actual: scopes.len(),
            maximum: MAX_MCP_TOKEN_SCOPES,
        });
    }
    scopes.sort_unstable();
    if scopes.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(McpTokenTransitionError::DuplicateScope);
    }
    Ok(())
}

fn validate_lifecycle(
    id: McpTokenId,
    state: McpTokenState,
    created_at: TimestampMillis,
    disabled_at: Option<TimestampMillis>,
    replacement_token_id: Option<McpTokenId>,
) -> Result<(), McpTokenTransitionError> {
    if disabled_at.is_some_and(|value| value.get() < created_at.get()) {
        return Err(McpTokenTransitionError::TimestampOrder);
    }
    match state {
        McpTokenState::Active if disabled_at.is_none() && replacement_token_id.is_none() => Ok(()),
        McpTokenState::Revoked if disabled_at.is_some() && replacement_token_id.is_none() => Ok(()),
        McpTokenState::Rotated
            if disabled_at.is_some()
                && replacement_token_id.is_some_and(|replacement| replacement != id) =>
        {
            Ok(())
        }
        McpTokenState::Active | McpTokenState::Revoked | McpTokenState::Rotated => {
            Err(McpTokenTransitionError::LifecycleShape)
        }
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum McpTokenTransitionError {
    #[error("MCP token requires at least one Workspace scope")]
    EmptyScopes,
    #[error("MCP token has {actual} scopes; maximum is {maximum}")]
    ScopeCapacity { actual: usize, maximum: usize },
    #[error("MCP token contains a duplicate Workspace scope")]
    DuplicateScope,
    #[error("MCP token persisted lifecycle shape is invalid")]
    LifecycleShape,
    #[error("MCP token disabled timestamp precedes creation")]
    TimestampOrder,
    #[error("MCP token revision does not match")]
    RevisionConflict,
    #[error("MCP token is already terminal")]
    TerminalState,
    #[error("MCP token replacement identity must differ")]
    ReplacementIdentity,
    #[error(transparent)]
    Revision(#[from] McpTokenRevisionError),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn timestamp(value: i64) -> Result<TimestampMillis, Box<dyn std::error::Error>> {
        Ok(TimestampMillis::new(value)?)
    }

    fn scope(value: u128) -> McpTokenWorkspaceScope {
        McpTokenWorkspaceScope::new(
            LocationId::from_uuid(Uuid::from_u128(value)),
            WorkspaceId::from_uuid(Uuid::from_u128(value + 1)),
        )
    }

    #[test]
    fn token_issue_sorts_scopes_and_redacts_digest() -> Result<(), Box<dyn std::error::Error>> {
        let token = RegisteredMcpToken::issue(
            McpTokenId::from_uuid(Uuid::from_u128(1)),
            McpTokenLabel::new("Local Codex".to_owned())?,
            McpTokenDigest::new([7; MCP_TOKEN_DIGEST_BYTES]),
            vec![scope(20), scope(10)],
            timestamp(1)?,
        )?;
        assert_eq!(token.scopes(), &[scope(10), scope(20)]);
        assert_eq!(
            format!("{:?}", token.digest()),
            "McpTokenDigest(<redacted>)"
        );
        Ok(())
    }

    #[test]
    fn token_scope_and_terminal_transitions_fail_closed() -> Result<(), Box<dyn std::error::Error>>
    {
        let id = McpTokenId::from_uuid(Uuid::from_u128(1));
        let label = McpTokenLabel::new("Local Codex".to_owned())?;
        let digest = McpTokenDigest::new([7; MCP_TOKEN_DIGEST_BYTES]);
        assert!(
            RegisteredMcpToken::issue(id, label.clone(), digest, Vec::new(), timestamp(1)?)
                .is_err()
        );
        assert!(
            RegisteredMcpToken::issue(
                id,
                label.clone(),
                digest,
                vec![scope(1), scope(1)],
                timestamp(1)?
            )
            .is_err()
        );
        let token = RegisteredMcpToken::issue(id, label, digest, vec![scope(1)], timestamp(1)?)?;
        let revoked = token.revoke(token.revision(), timestamp(2)?)?;
        assert_eq!(revoked.state(), McpTokenState::Revoked);
        assert!(revoked.revoke(revoked.revision(), timestamp(3)?).is_err());
        assert!(token.rotate(id, token.revision(), timestamp(2)?).is_err());
        Ok(())
    }
}
