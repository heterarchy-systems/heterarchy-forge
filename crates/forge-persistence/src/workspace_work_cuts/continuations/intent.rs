use forge_domain::{
    AgentAssignmentId, AgentAssignmentRevision, AgentAssignmentTarget, AuthenticatedPrincipal,
    DagNodeRevision,
};
use thiserror::Error;
use uuid::Uuid;

/// One stable, caller-supplied continuation prepare intent.
///
/// This is an identity envelope, not a domain plan and not a custody or
/// transfer capability. The persistence owner resolves the source rows and
/// current DAG/node inside its immediate transaction.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AssignmentContinuationIntent {
    cut_id: Uuid,
    cut_revision: i64,
    cut_request_digest: [u8; 32],
    cut_snapshot_digest: [u8; 32],
    transfer_id: Uuid,
    successor_id: AgentAssignmentId,
    source_assignment_id: AgentAssignmentId,
    source_revision: AgentAssignmentRevision,
    expected_node_revision: DagNodeRevision,
    recipient: AgentAssignmentTarget,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum AssignmentContinuationIntentError {
    #[error("continuation intent contains a nil identity")]
    NilIdentity,
    #[error("continuation intent contains a zero digest")]
    ZeroDigest,
    #[error("continuation intent cut revision must be positive")]
    InvalidCutRevision,
    #[error("continuation intent recipient contains a nil identity")]
    NilRecipient,
}

impl AssignmentContinuationIntent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cut_id: Uuid,
        cut_revision: i64,
        cut_request_digest: [u8; 32],
        cut_snapshot_digest: [u8; 32],
        transfer_id: Uuid,
        successor_id: AgentAssignmentId,
        source_assignment_id: AgentAssignmentId,
        source_revision: AgentAssignmentRevision,
        expected_node_revision: DagNodeRevision,
        recipient: AgentAssignmentTarget,
    ) -> Result<Self, AssignmentContinuationIntentError> {
        if cut_id.is_nil()
            || transfer_id.is_nil()
            || successor_id.into_uuid().is_nil()
            || source_assignment_id.into_uuid().is_nil()
        {
            return Err(AssignmentContinuationIntentError::NilIdentity);
        }
        if cut_request_digest == [0; 32] || cut_snapshot_digest == [0; 32] {
            return Err(AssignmentContinuationIntentError::ZeroDigest);
        }
        if cut_revision < 1 || source_revision.get() < 1 || expected_node_revision.get() < 1 {
            return Err(AssignmentContinuationIntentError::InvalidCutRevision);
        }
        if recipient.agent_id().into_uuid().is_nil()
            || recipient.session_id().into_uuid().is_nil()
            || principal_is_nil(recipient.principal())
            || recipient.agent_revision().get() < 1
        {
            return Err(AssignmentContinuationIntentError::NilRecipient);
        }
        Ok(Self {
            cut_id,
            cut_revision,
            cut_request_digest,
            cut_snapshot_digest,
            transfer_id,
            successor_id,
            source_assignment_id,
            source_revision,
            expected_node_revision,
            recipient,
        })
    }

    pub const fn cut_id(self) -> Uuid {
        self.cut_id
    }
    pub const fn cut_revision(self) -> i64 {
        self.cut_revision
    }
    pub const fn cut_request_digest(self) -> [u8; 32] {
        self.cut_request_digest
    }
    pub const fn cut_snapshot_digest(self) -> [u8; 32] {
        self.cut_snapshot_digest
    }
    pub const fn transfer_id(self) -> Uuid {
        self.transfer_id
    }
    pub const fn successor_id(self) -> AgentAssignmentId {
        self.successor_id
    }
    pub const fn source_assignment_id(self) -> AgentAssignmentId {
        self.source_assignment_id
    }
    pub const fn source_revision(self) -> AgentAssignmentRevision {
        self.source_revision
    }
    pub const fn expected_node_revision(self) -> DagNodeRevision {
        self.expected_node_revision
    }
    pub const fn recipient(self) -> AgentAssignmentTarget {
        self.recipient
    }
}

fn principal_is_nil(principal: AuthenticatedPrincipal) -> bool {
    match principal {
        AuthenticatedPrincipal::TrustedStdio => false,
        AuthenticatedPrincipal::DirectToken(id) => id.into_uuid().is_nil(),
        AuthenticatedPrincipal::OAuthGrant(id) => id.into_uuid().is_nil(),
    }
}
