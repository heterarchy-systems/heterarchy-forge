//! Immutable admission provenance, separate from current planning authority.

use uuid::Uuid;

use super::{AgentAssignmentId, AgentAssignmentTransitionError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AgentAssignmentOrigin {
    CoordinatorOffer,
    CutContinuation(AgentAssignmentContinuationOrigin),
}

/// A checked lineage description, not a grant to create or claim an assignment.
/// Persistence must join this identity to its actual reciprocal commit receipt.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AgentAssignmentContinuationOrigin {
    cut: Uuid,
    transfer: Uuid,
    predecessor: AgentAssignmentId,
}

impl AgentAssignmentContinuationOrigin {
    pub fn new(
        cut_id: Uuid,
        transfer_id: Uuid,
        predecessor_id: AgentAssignmentId,
    ) -> Result<Self, AgentAssignmentTransitionError> {
        if cut_id.is_nil() || transfer_id.is_nil() || predecessor_id.into_uuid().is_nil() {
            return Err(AgentAssignmentTransitionError::InvalidContinuationOrigin);
        }
        Ok(Self {
            cut: cut_id,
            transfer: transfer_id,
            predecessor: predecessor_id,
        })
    }

    pub const fn cut_id(self) -> Uuid {
        self.cut
    }
    pub const fn transfer_id(self) -> Uuid {
        self.transfer
    }
    pub const fn predecessor_id(self) -> AgentAssignmentId {
        self.predecessor
    }
}
