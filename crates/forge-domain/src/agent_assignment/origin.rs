//! Immutable admission provenance, separate from current planning authority.

use uuid::Uuid;

use super::{AgentAssignmentId, AgentAssignmentTransitionError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AgentAssignmentOrigin {
    CoordinatorOffer,
    CutContinuation(AgentAssignmentContinuationOrigin),
    HomeHandoff(AgentAssignmentHomeHandoffOrigin),
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

/// Source-owned Home handoff identity carried by the successor assignment.
/// This value describes lineage; it does not authorize or prove a handoff.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AgentAssignmentHomeHandoffOrigin {
    preparation_id: Uuid,
    handoff_id: Uuid,
    predecessor: AgentAssignmentId,
    root_assignment: AgentAssignmentId,
}

impl AgentAssignmentHomeHandoffOrigin {
    pub fn new(
        preparation_id: Uuid,
        handoff_id: Uuid,
        predecessor_id: AgentAssignmentId,
        root_assignment_id: AgentAssignmentId,
    ) -> Result<Self, AgentAssignmentTransitionError> {
        if preparation_id.is_nil()
            || handoff_id.is_nil()
            || predecessor_id.into_uuid().is_nil()
            || root_assignment_id.into_uuid().is_nil()
        {
            return Err(AgentAssignmentTransitionError::InvalidHomeHandoffOrigin);
        }
        Ok(Self {
            preparation_id,
            handoff_id,
            predecessor: predecessor_id,
            root_assignment: root_assignment_id,
        })
    }

    pub const fn preparation_id(self) -> Uuid {
        self.preparation_id
    }

    pub const fn handoff_id(self) -> Uuid {
        self.handoff_id
    }

    pub const fn predecessor_id(self) -> AgentAssignmentId {
        self.predecessor
    }

    pub const fn root_assignment_id(self) -> AgentAssignmentId {
        self.root_assignment
    }
}
