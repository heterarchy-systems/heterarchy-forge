//! Typed continuation provenance for terminal Activity successors.
use thiserror::Error;

use crate::{
    ActivityId, ActivityRevision, AgentSessionId, RegisteredActivity, RuntimeInstanceId,
    TimestampMillis, WorkspaceId, WorkspaceRevision,
};

/// Explicit command to create a fresh successor for a terminal Activity.
///
/// The command carries only immutable predecessor context and initiating
/// runtime provenance. It never carries or clones Goal, DAG, Agent, Approval,
/// or Evidence authority.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CreateActivitySuccessor {
    workspace_id: WorkspaceId,
    expected_workspace_revision: WorkspaceRevision,
    predecessor_activity_id: ActivityId,
    predecessor_activity_revision: ActivityRevision,
    successor_activity_id: ActivityId,
    initiating_session_id: AgentSessionId,
    runtime_instance_id: RuntimeInstanceId,
    observed_at: TimestampMillis,
}

impl CreateActivitySuccessor {
    /// Build a successor command while rejecting self-links at the domain
    /// boundary.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        workspace_id: WorkspaceId,
        expected_workspace_revision: WorkspaceRevision,
        predecessor_activity_id: ActivityId,
        predecessor_activity_revision: ActivityRevision,
        successor_activity_id: ActivityId,
        initiating_session_id: AgentSessionId,
        runtime_instance_id: RuntimeInstanceId,
        observed_at: TimestampMillis,
    ) -> Result<Self, ActivitySuccessorCommandError> {
        if predecessor_activity_id == successor_activity_id {
            return Err(ActivitySuccessorCommandError::SelfLink {
                activity_id: predecessor_activity_id,
            });
        }
        Ok(Self {
            workspace_id,
            expected_workspace_revision,
            predecessor_activity_id,
            predecessor_activity_revision,
            successor_activity_id,
            initiating_session_id,
            runtime_instance_id,
            observed_at,
        })
    }

    pub const fn workspace_id(self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn expected_workspace_revision(self) -> WorkspaceRevision {
        self.expected_workspace_revision
    }

    pub const fn predecessor_activity_id(self) -> ActivityId {
        self.predecessor_activity_id
    }

    pub const fn predecessor_activity_revision(self) -> ActivityRevision {
        self.predecessor_activity_revision
    }

    pub const fn successor_activity_id(self) -> ActivityId {
        self.successor_activity_id
    }

    pub const fn initiating_session_id(self) -> AgentSessionId {
        self.initiating_session_id
    }

    pub const fn runtime_instance_id(self) -> RuntimeInstanceId {
        self.runtime_instance_id
    }

    pub const fn observed_at(self) -> TimestampMillis {
        self.observed_at
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ActivitySuccessorCommandError {
    #[error("Activity successor cannot link Activity {activity_id} to itself")]
    SelfLink { activity_id: ActivityId },
}

/// Immutable append-only predecessor relation for one successor Activity.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ActivitySuccessor {
    workspace_id: WorkspaceId,
    predecessor_activity_id: ActivityId,
    predecessor_activity_revision: ActivityRevision,
    successor_activity_id: ActivityId,
    initiating_session_id: AgentSessionId,
    runtime_instance_id: RuntimeInstanceId,
    created_at: TimestampMillis,
}

impl ActivitySuccessor {
    pub fn from_parts(
        workspace_id: WorkspaceId,
        predecessor_activity_id: ActivityId,
        predecessor_activity_revision: ActivityRevision,
        successor_activity_id: ActivityId,
        initiating_session_id: AgentSessionId,
        runtime_instance_id: RuntimeInstanceId,
        created_at: TimestampMillis,
    ) -> Result<Self, ActivitySuccessorError> {
        if predecessor_activity_id == successor_activity_id {
            return Err(ActivitySuccessorError::SelfLink {
                activity_id: predecessor_activity_id,
            });
        }
        Ok(Self {
            workspace_id,
            predecessor_activity_id,
            predecessor_activity_revision,
            successor_activity_id,
            initiating_session_id,
            runtime_instance_id,
            created_at,
        })
    }

    pub const fn workspace_id(self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn predecessor_activity_id(self) -> ActivityId {
        self.predecessor_activity_id
    }

    pub const fn predecessor_activity_revision(self) -> ActivityRevision {
        self.predecessor_activity_revision
    }

    pub const fn successor_activity_id(self) -> ActivityId {
        self.successor_activity_id
    }

    pub const fn initiating_session_id(self) -> AgentSessionId {
        self.initiating_session_id
    }

    pub const fn runtime_instance_id(self) -> RuntimeInstanceId {
        self.runtime_instance_id
    }

    pub const fn created_at(self) -> TimestampMillis {
        self.created_at
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ActivitySuccessorError {
    #[error("Activity successor cannot link Activity {activity_id} to itself")]
    SelfLink { activity_id: ActivityId },
}

/// Durable successor relation together with the Activity projection observed
/// in the same `SQLite` transaction and an explicit admission outcome.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivitySuccessorResult {
    relation: ActivitySuccessor,
    successor: RegisteredActivity,
    created: bool,
}

impl ActivitySuccessorResult {
    pub fn new(relation: ActivitySuccessor, successor: RegisteredActivity, created: bool) -> Self {
        Self {
            relation,
            successor,
            created,
        }
    }

    pub const fn relation(&self) -> ActivitySuccessor {
        self.relation
    }

    pub const fn successor(&self) -> &RegisteredActivity {
        &self.successor
    }

    pub const fn created(&self) -> bool {
        self.created
    }
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;

    fn ids() -> (
        WorkspaceId,
        ActivityId,
        ActivityId,
        AgentSessionId,
        RuntimeInstanceId,
    ) {
        (
            WorkspaceId::from_uuid(Uuid::from_u128(1)),
            ActivityId::from_uuid(Uuid::from_u128(2)),
            ActivityId::from_uuid(Uuid::from_u128(3)),
            AgentSessionId::from_uuid(Uuid::from_u128(4)),
            RuntimeInstanceId::from_uuid(Uuid::from_u128(5)),
        )
    }

    #[test]
    fn self_link_is_rejected_before_persistence() {
        let (workspace_id, predecessor, _, session_id, runtime_instance_id) = ids();
        let error = CreateActivitySuccessor::new(
            workspace_id,
            WorkspaceRevision::INITIAL,
            predecessor,
            ActivityRevision::INITIAL,
            predecessor,
            session_id,
            runtime_instance_id,
            TimestampMillis::new(10).unwrap_or_else(|_| unreachable!()),
        );
        assert!(matches!(
            error,
            Err(ActivitySuccessorCommandError::SelfLink { activity_id }) if activity_id == predecessor
        ));
    }

    #[test]
    fn relation_preserves_exact_predecessor_revision_and_provenance() {
        let (workspace_id, predecessor, successor, session_id, runtime_instance_id) = ids();
        let relation = ActivitySuccessor::from_parts(
            workspace_id,
            predecessor,
            ActivityRevision::INITIAL,
            successor,
            session_id,
            runtime_instance_id,
            TimestampMillis::new(10).unwrap_or_else(|_| unreachable!()),
        )
        .unwrap_or_else(|_| unreachable!());
        assert_eq!(relation.workspace_id(), workspace_id);
        assert_eq!(
            relation.predecessor_activity_revision(),
            ActivityRevision::INITIAL
        );
        assert_eq!(relation.initiating_session_id(), session_id);
        assert_eq!(relation.runtime_instance_id(), runtime_instance_id);
    }
}
