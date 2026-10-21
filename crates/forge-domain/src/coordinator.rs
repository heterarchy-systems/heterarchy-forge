use std::fmt;

use thiserror::Error;

use crate::{
    ActivityId, AgentInstanceId, AgentSessionId, AuthenticatedPrincipal, TimestampMillis,
    WorkspaceId,
};

/// Monotonic fencing revision for the planning Coordinator bound to one Activity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ActivityCoordinatorRevision(i64);

impl ActivityCoordinatorRevision {
    pub const INITIAL: Self = Self(1);

    pub const fn new(value: i64) -> Result<Self, ActivityCoordinatorRevisionError> {
        if value < 1 {
            Err(ActivityCoordinatorRevisionError::Invalid { actual: value })
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> i64 {
        self.0
    }

    pub const fn checked_next(self) -> Result<Self, ActivityCoordinatorRevisionError> {
        match self.0.checked_add(1) {
            Some(value) => Ok(Self(value)),
            None => Err(ActivityCoordinatorRevisionError::Overflow { current: self.0 }),
        }
    }
}

impl fmt::Display for ActivityCoordinatorRevision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ActivityCoordinatorRevisionError {
    #[error("Activity coordinator revision must be at least 1, got {actual}")]
    Invalid { actual: i64 },
    #[error("Activity coordinator revision overflowed at {current}")]
    Overflow { current: i64 },
}

/// Durable Activity-local planning authority projection.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ActivityCoordinatorBinding {
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    agent_id: AgentInstanceId,
    revision: ActivityCoordinatorRevision,
    updated_at: TimestampMillis,
}

impl ActivityCoordinatorBinding {
    pub const fn new(
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        agent_id: AgentInstanceId,
        revision: ActivityCoordinatorRevision,
        updated_at: TimestampMillis,
    ) -> Self {
        Self {
            workspace_id,
            activity_id,
            agent_id,
            revision,
            updated_at,
        }
    }

    pub const fn workspace_id(self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn activity_id(self) -> ActivityId {
        self.activity_id
    }

    pub const fn agent_id(self) -> AgentInstanceId {
        self.agent_id
    }

    pub const fn revision(self) -> ActivityCoordinatorRevision {
        self.revision
    }

    pub const fn updated_at(self) -> TimestampMillis {
        self.updated_at
    }
}

/// Fenced identity presented for Coordinator-authorized mutations.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ActivityCoordinatorActor {
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    agent_id: AgentInstanceId,
    expected_revision: ActivityCoordinatorRevision,
    principal: AuthenticatedPrincipal,
    session_id: AgentSessionId,
}

impl ActivityCoordinatorActor {
    pub const fn new(
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        agent_id: AgentInstanceId,
        expected_revision: ActivityCoordinatorRevision,
        principal: AuthenticatedPrincipal,
        session_id: AgentSessionId,
    ) -> Self {
        Self {
            workspace_id,
            activity_id,
            agent_id,
            expected_revision,
            principal,
            session_id,
        }
    }

    pub const fn workspace_id(self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn activity_id(self) -> ActivityId {
        self.activity_id
    }

    pub const fn agent_id(self) -> AgentInstanceId {
        self.agent_id
    }

    pub const fn expected_revision(self) -> ActivityCoordinatorRevision {
        self.expected_revision
    }

    pub const fn principal(self) -> AuthenticatedPrincipal {
        self.principal
    }

    pub const fn session_id(self) -> AgentSessionId {
        self.session_id
    }
}

/// First-writer-wins explicit Coordinator claim for an unbound Activity.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ClaimActivityCoordinator {
    session_id: AgentSessionId,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    agent_id: AgentInstanceId,
    principal: AuthenticatedPrincipal,
    observed_at: TimestampMillis,
}

impl ClaimActivityCoordinator {
    pub const fn new(
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        agent_id: AgentInstanceId,
        principal: AuthenticatedPrincipal,
        observed_at: TimestampMillis,
        session_id: AgentSessionId,
    ) -> Self {
        Self {
            session_id,
            workspace_id,
            activity_id,
            agent_id,
            principal,
            observed_at,
        }
    }

    pub const fn session_id(self) -> AgentSessionId {
        self.session_id
    }

    pub const fn workspace_id(self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn activity_id(self) -> ActivityId {
        self.activity_id
    }

    pub const fn agent_id(self) -> AgentInstanceId {
        self.agent_id
    }

    pub const fn principal(self) -> AuthenticatedPrincipal {
        self.principal
    }

    pub const fn observed_at(self) -> TimestampMillis {
        self.observed_at
    }
}

/// Explicit fenced transfer from the current Coordinator to another attached Agent.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TransferActivityCoordinator {
    current: ActivityCoordinatorActor,
    next_agent_id: AgentInstanceId,
    observed_at: TimestampMillis,
}

impl TransferActivityCoordinator {
    pub const fn new(
        current: ActivityCoordinatorActor,
        next_agent_id: AgentInstanceId,
        observed_at: TimestampMillis,
    ) -> Self {
        Self {
            current,
            next_agent_id,
            observed_at,
        }
    }

    pub const fn current(self) -> ActivityCoordinatorActor {
        self.current
    }

    pub const fn next_agent_id(self) -> AgentInstanceId {
        self.next_agent_id
    }

    pub const fn observed_at(self) -> TimestampMillis {
        self.observed_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn coordinator_revision_is_monotonic_and_actor_is_typed()
    -> Result<(), Box<dyn std::error::Error>> {
        assert!(ActivityCoordinatorRevision::new(0).is_err());
        let revision = ActivityCoordinatorRevision::INITIAL;
        assert_eq!(revision.checked_next()?.get(), 2);
        let actor = ActivityCoordinatorActor::new(
            WorkspaceId::from_uuid(Uuid::from_u128(1)),
            ActivityId::from_uuid(Uuid::from_u128(2)),
            AgentInstanceId::from_uuid(Uuid::from_u128(3)),
            revision,
            AuthenticatedPrincipal::TrustedStdio,
            AgentSessionId::from_uuid(Uuid::from_u128(4)),
        );
        assert_eq!(actor.expected_revision(), revision);
        Ok(())
    }
}
