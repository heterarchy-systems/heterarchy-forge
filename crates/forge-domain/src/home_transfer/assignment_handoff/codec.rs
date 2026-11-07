//! Canonical decoder for the fixed-width Home accept-and-take request.

use thiserror::Error;
use uuid::Uuid;

use crate::{
    AgentInstanceId, AgentInstanceRevision, AgentSessionId, AuthenticatedPrincipal, DirectTokenId,
    ForgeBackendId, OAuthGrantId, WorkspaceId, WorkspaceRevision,
};

use super::super::HomeTransferSourceScope;
use super::{
    HomeHandoffDomainError, HomeHandoffProposalRequestDigest, HomeHandoffTakeRequest, TAKE_MAGIC,
    TAKE_SNAPSHOT_BYTES,
};

impl HomeHandoffTakeRequest {
    /// Decode the exact bounded versioned snapshot emitted by
    /// [`Self::canonical_snapshot`]. The embedded digest is recomputed by the
    /// checked constructor; persistence owners compare it with their stored
    /// digest separately.
    pub fn from_canonical_snapshot(
        bytes: &[u8],
    ) -> Result<Self, HomeHandoffTakeRequestSnapshotError> {
        if bytes.len() > TAKE_SNAPSHOT_BYTES {
            return Err(HomeHandoffTakeRequestSnapshotError::TooLarge);
        }
        if bytes.len() != TAKE_SNAPSHOT_BYTES {
            return Err(HomeHandoffTakeRequestSnapshotError::InvalidSnapshot);
        }

        let mut reader = TakeRequestSnapshotReader::new(bytes);
        if reader.take(TAKE_MAGIC.len())? != TAKE_MAGIC || reader.u8()? != 1 {
            return Err(HomeHandoffTakeRequestSnapshotError::InvalidSnapshot);
        }

        let acceptance_id = reader.uuid()?;
        let handoff_id = reader.uuid()?;
        let proposal_id = reader.uuid()?;
        let expected_case_revision = reader.i64()?;
        let proposal_digest = HomeHandoffProposalRequestDigest::from_bytes(reader.digest()?)?;
        let workspace_id = WorkspaceId::from_uuid(reader.uuid()?);
        let workspace_revision = WorkspaceRevision::new(reader.i64()?)
            .map_err(|_| HomeHandoffTakeRequestSnapshotError::InvalidWorkspaceRevision)?;
        let backend_id = ForgeBackendId::from_uuid(reader.uuid()?);
        let destination_id = reader.uuid()?;
        let scope = HomeTransferSourceScope::new(
            workspace_id,
            workspace_revision,
            backend_id,
            destination_id,
        )
        .map_err(|_| HomeHandoffTakeRequestSnapshotError::InvalidSourceScope)?;
        let recipient_agent_id = AgentInstanceId::from_uuid(reader.uuid()?);
        let recipient_session_id = AgentSessionId::from_uuid(reader.uuid()?);
        let recipient_principal = reader.principal()?;
        let recipient_revision = AgentInstanceRevision::new(reader.i64()?)
            .map_err(|_| HomeHandoffTakeRequestSnapshotError::InvalidRecipientAgentRevision)?;
        if !reader.is_finished() {
            return Err(HomeHandoffTakeRequestSnapshotError::InvalidSnapshot);
        }

        let request = Self::new(
            acceptance_id,
            handoff_id,
            proposal_id,
            expected_case_revision,
            proposal_digest,
            scope,
            crate::AgentAssignmentTarget::new(
                recipient_agent_id,
                recipient_session_id,
                recipient_principal,
                recipient_revision,
            ),
        )?;
        if request.canonical_snapshot().as_slice() != bytes {
            return Err(HomeHandoffTakeRequestSnapshotError::NonCanonical);
        }
        Ok(request)
    }
}

/// Typed failures while decoding a canonical Home take-request snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum HomeHandoffTakeRequestSnapshotError {
    #[error("Home handoff take-request snapshot exceeds its fixed bound")]
    TooLarge,
    #[error("Home handoff take-request snapshot is truncated or malformed")]
    InvalidSnapshot,
    #[error("Home handoff take-request snapshot is not canonical")]
    NonCanonical,
    #[error("Home handoff take-request source scope is invalid")]
    InvalidSourceScope,
    #[error("Home handoff take-request Workspace revision is invalid")]
    InvalidWorkspaceRevision,
    #[error("Home handoff take-request recipient Agent revision is invalid")]
    InvalidRecipientAgentRevision,
    #[error(transparent)]
    InvalidRequest(#[from] HomeHandoffDomainError),
}

struct TakeRequestSnapshotReader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> TakeRequestSnapshotReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], HomeHandoffTakeRequestSnapshotError> {
        let end = self
            .cursor
            .checked_add(length)
            .ok_or(HomeHandoffTakeRequestSnapshotError::InvalidSnapshot)?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or(HomeHandoffTakeRequestSnapshotError::InvalidSnapshot)?;
        self.cursor = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, HomeHandoffTakeRequestSnapshotError> {
        self.take(1)?
            .first()
            .copied()
            .ok_or(HomeHandoffTakeRequestSnapshotError::InvalidSnapshot)
    }

    fn i64(&mut self) -> Result<i64, HomeHandoffTakeRequestSnapshotError> {
        Ok(i64::from_be_bytes(self.fixed()?))
    }

    fn uuid(&mut self) -> Result<Uuid, HomeHandoffTakeRequestSnapshotError> {
        Uuid::from_slice(self.take(16)?)
            .map_err(|_| HomeHandoffTakeRequestSnapshotError::InvalidSnapshot)
    }

    fn digest(&mut self) -> Result<[u8; 32], HomeHandoffTakeRequestSnapshotError> {
        self.fixed()
    }

    fn principal(&mut self) -> Result<AuthenticatedPrincipal, HomeHandoffTakeRequestSnapshotError> {
        let tag = self.u8()?;
        let identity = self.uuid()?;
        match tag {
            0 if identity.is_nil() => Ok(AuthenticatedPrincipal::TrustedStdio),
            0 => Err(HomeHandoffTakeRequestSnapshotError::NonCanonical),
            1 => Ok(AuthenticatedPrincipal::DirectToken(
                DirectTokenId::from_uuid(identity),
            )),
            2 => Ok(AuthenticatedPrincipal::OAuthGrant(OAuthGrantId::from_uuid(
                identity,
            ))),
            _ => Err(HomeHandoffTakeRequestSnapshotError::InvalidSnapshot),
        }
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], HomeHandoffTakeRequestSnapshotError> {
        self.take(N)?
            .try_into()
            .map_err(|_| HomeHandoffTakeRequestSnapshotError::InvalidSnapshot)
    }

    const fn is_finished(&self) -> bool {
        self.cursor == self.bytes.len()
    }
}
