//! Typed request and target policy for permanent Goal/DAG deletion.
//!
//! Deletion is an explicit, destructive semantic operation.  This module only
//! carries the exact identity and revision fences needed by the persistence
//! adapter; it does not perform `SQLite`, filesystem, Git, or runtime effects.

use crate::{ActivityId, DagHeadRevision, GoalId, GoalRevision, TimestampMillis, WorkspaceId};

/// Permanent deletion target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GoalDeletionTarget {
    /// Remove the Goal contract, all of its DAG history, and owned evidence.
    Goal,
    /// Remove every DAG revision while retaining the Goal contract.
    Dag,
}

impl GoalDeletionTarget {
    pub const fn deletes_goal(self) -> bool {
        matches!(self, Self::Goal)
    }

    pub const fn deletes_dag(self) -> bool {
        true
    }
}

/// Exact durable identity/revision fence for one permanent deletion request.
///
/// `goal_created_at` is intentionally part of the fence.  A stale request
/// must not delete a newly created record that happens to reuse a Goal UUID.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GoalDeletionRequest {
    target: GoalDeletionTarget,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    goal_id: GoalId,
    goal_created_at: TimestampMillis,
    expected_goal_revision: GoalRevision,
    expected_dag_head_revision: Option<DagHeadRevision>,
}

impl GoalDeletionRequest {
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        target: GoalDeletionTarget,
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        goal_id: GoalId,
        goal_created_at: TimestampMillis,
        expected_goal_revision: GoalRevision,
        expected_dag_head_revision: Option<DagHeadRevision>,
    ) -> Self {
        Self {
            target,
            workspace_id,
            activity_id,
            goal_id,
            goal_created_at,
            expected_goal_revision,
            expected_dag_head_revision,
        }
    }

    pub const fn target(self) -> GoalDeletionTarget {
        self.target
    }

    pub const fn workspace_id(self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn activity_id(self) -> ActivityId {
        self.activity_id
    }

    pub const fn goal_id(self) -> GoalId {
        self.goal_id
    }

    pub const fn goal_created_at(self) -> TimestampMillis {
        self.goal_created_at
    }

    pub const fn expected_goal_revision(self) -> GoalRevision {
        self.expected_goal_revision
    }

    pub const fn expected_dag_head_revision(self) -> Option<DagHeadRevision> {
        self.expected_dag_head_revision
    }
}
