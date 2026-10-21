//! Workspace-local durable authority for connected Agent assignments.
//!
//! This module records offers, exact claims, bounded participant results, and
//! explicit Main review. It does not create Goals/DAGs, provision worktrees,
//! launch providers, or infer native effect completion.

use forge_domain::{
    AcknowledgeAgentAssignmentCancellation, ActivityCoordinatorActor, ActivityCoordinatorRevision,
    ActivityId, AgentAssignmentCoordinator, AgentAssignmentId, AgentAssignmentResult,
    AgentAssignmentResultError, AgentAssignmentRevision, AgentAssignmentSourceRef,
    AgentAssignmentSourceUrl, AgentAssignmentState, AgentAssignmentSummary, AgentAssignmentTarget,
    AgentAssignmentTransitionError, AgentAssignmentWorktreeReceipt, AgentInstanceId,
    AgentInstanceRevision, AgentSessionId, AuthenticatedPrincipal, CancelAgentAssignment,
    ClaimAgentAssignment, DagHeadRevision, DagNodeId, DagNodeRevision, DagRevisionNumber,
    GoalEvidenceRef, GoalId, GoalRevision, InterruptAgentAssignment, MAX_AGENT_ASSIGNMENT_SOURCES,
    MAX_AGENT_ASSIGNMENTS_PER_WORKSPACE, OfferAgentAssignment, RegisteredAgentAssignment,
    ReviewAgentAssignment, SubmitAgentAssignment, TimestampMillis, WorkCreditBudget, WorkspaceId,
};
use rusqlite::{Connection, OptionalExtension, Row, Transaction, TransactionBehavior, params};
use thiserror::Error;
use uuid::Uuid;

use crate::workspace_agents::{self, AgentStoreError};
use crate::workspace_coordinators::{self, CoordinatorStoreError};
use crate::workspace_dags::{self, DagStoreError};
use crate::workspace_goals::{self, GoalStoreError};

/// Exact Goal/DAG/node read context plus the current head and active assignment
/// observed in one Workspace `SQLite` read snapshot.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DagNodeAssignmentSnapshot {
    workspace_id: WorkspaceId,
    activity_id: forge_domain::ActivityId,
    goal_revision: GoalRevision,
    goal_created_at: TimestampMillis,
    dag_base_goal_revision: GoalRevision,
    scope: crate::DagNodeEvidenceScope,
    head: crate::DagHead,
    node_revision: DagNodeRevision,
    assignment: Option<AgentAssignmentSummary>,
}

impl DagNodeAssignmentSnapshot {
    pub(crate) fn new(
        goal: &forge_domain::RegisteredGoal,
        dag: &crate::StoredDagRevision,
        node: &forge_domain::RegisteredDagNode,
        assignment: Option<AgentAssignmentSummary>,
    ) -> Self {
        Self {
            workspace_id: goal.workspace_id(),
            activity_id: goal.activity_id(),
            goal_revision: goal.revision(),
            goal_created_at: goal.timestamps().created_at(),
            dag_base_goal_revision: dag.revision().base_goal_revision(),
            scope: crate::DagNodeEvidenceScope::new(goal.id(), dag.revision().number(), node.id()),
            head: dag.head(),
            node_revision: node.revision(),
            assignment,
        }
    }

    pub const fn workspace_id(self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn activity_id(self) -> forge_domain::ActivityId {
        self.activity_id
    }

    pub const fn goal_revision(self) -> GoalRevision {
        self.goal_revision
    }

    pub const fn goal_created_at(self) -> TimestampMillis {
        self.goal_created_at
    }

    pub const fn dag_base_goal_revision(self) -> GoalRevision {
        self.dag_base_goal_revision
    }

    pub const fn scope(self) -> crate::DagNodeEvidenceScope {
        self.scope
    }

    /// Current Goal DAG head observed alongside the requested historical node.
    pub const fn head(self) -> crate::DagHead {
        self.head
    }

    pub const fn node_revision(self) -> DagNodeRevision {
        self.node_revision
    }

    pub const fn assignment(self) -> Option<AgentAssignmentSummary> {
        self.assignment
    }
}

/// Provenance of the first successful seal insert.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentAssignmentOfferSealAuthority {
    /// The seal was installed through the trusted native `LocalOperator` path.
    LocalOperator,
    /// The seal was installed by the exact current Activity Coordinator.
    Coordinator {
        agent_id: AgentInstanceId,
        session_id: AgentSessionId,
        expected_coordinator_revision: ActivityCoordinatorRevision,
    },
}

impl AgentAssignmentOfferSealAuthority {
    fn from_actor(actor: Option<ActivityCoordinatorActor>) -> Self {
        actor.map_or(Self::LocalOperator, |actor| Self::Coordinator {
            agent_id: actor.agent_id(),
            session_id: actor.session_id(),
            expected_coordinator_revision: actor.expected_revision(),
        })
    }
}

/// Bounded observation returned after sealing one exact Activity's future
/// Assignment admission. `current_assignment` is global to the Workspace and
/// can belong to a different Activity; `None` means absent now while sealed,
/// not that the Assignment was never offered.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentAssignmentOfferSealSnapshot {
    workspace_id: WorkspaceId,
    requested_activity_id: ActivityId,
    assignment_id: AgentAssignmentId,
    sealed_at: TimestampMillis,
    authority: AgentAssignmentOfferSealAuthority,
    current_assignment: Option<RegisteredAgentAssignment>,
}

impl AgentAssignmentOfferSealSnapshot {
    fn new(
        workspace_id: WorkspaceId,
        requested_activity_id: ActivityId,
        assignment_id: AgentAssignmentId,
        sealed_at: TimestampMillis,
        authority: AgentAssignmentOfferSealAuthority,
        current_assignment: Option<RegisteredAgentAssignment>,
    ) -> Self {
        Self {
            workspace_id,
            requested_activity_id,
            assignment_id,
            sealed_at,
            authority,
            current_assignment,
        }
    }

    /// Workspace that owns the permanent seal.
    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    /// Activity whose future fresh offers are sealed.
    pub const fn requested_activity_id(&self) -> ActivityId {
        self.requested_activity_id
    }

    /// Globally unique Assignment ID checked by the seal.
    pub const fn assignment_id(&self) -> AgentAssignmentId {
        self.assignment_id
    }

    /// Timestamp of the first successful seal insert.
    pub const fn sealed_at(&self) -> TimestampMillis {
        self.sealed_at
    }

    /// Original validated authority metadata; retries never replace it.
    pub const fn seal_authority(&self) -> AgentAssignmentOfferSealAuthority {
        self.authority
    }

    pub fn current_assignment(&self) -> Option<&RegisteredAgentAssignment> {
        self.current_assignment.as_ref()
    }

    /// `None` means no current global row exists while this Activity is sealed.
    /// It is not historical evidence that no offer or completion ever occurred.
    pub const fn absent_now_sealed(&self) -> bool {
        self.current_assignment.is_none()
    }
}

/// Frozen `WorkCredit` budget column shared by the current table definition and
/// the additive v42 `ALTER TABLE` migration (v41 databases predate it).
pub(crate) const CREDIT_BUDGET_COLUMN_SQL: &str =
    "credit_budget INTEGER CHECK(credit_budget IS NULL OR credit_budget IN (1,3,5))";

/// Additive `v41` to `v42` migration step. `SQLite` rewrites the stored schema text
/// by inserting this column after the last column definition, which is exactly
/// its position in [`AGENT_ASSIGNMENTS_TABLE_SQL`], so migrated and freshly
/// created tables share one normalized shape.
pub(crate) const AGENT_ASSIGNMENTS_CREDIT_BUDGET_ALTER_SQL: &str = "ALTER TABLE agent_assignments ADD COLUMN credit_budget INTEGER CHECK(credit_budget IS NULL OR credit_budget IN (1,3,5))";

pub(crate) const AGENT_ASSIGNMENTS_TABLE_SQL: &str = "CREATE TABLE agent_assignments (assignment_id BLOB PRIMARY KEY NOT NULL CHECK(length(assignment_id) = 16), workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16), activity_id BLOB NOT NULL REFERENCES activities(activity_id) CHECK(length(activity_id) = 16), goal_id BLOB NOT NULL REFERENCES goals(goal_id) CHECK(length(goal_id) = 16), goal_created_at_ms INTEGER NOT NULL CHECK(goal_created_at_ms >= 0), goal_revision INTEGER NOT NULL CHECK(goal_revision >= 1), dag_revision INTEGER NOT NULL CHECK(dag_revision >= 1), dag_head_revision INTEGER NOT NULL CHECK(dag_head_revision >= 1), node_id BLOB NOT NULL CHECK(length(node_id) = 16), node_revision INTEGER NOT NULL CHECK(node_revision >= 1), coordinator_agent_id BLOB NOT NULL CHECK(length(coordinator_agent_id) = 16), coordinator_session_id BLOB NOT NULL CHECK(length(coordinator_session_id) = 16), coordinator_principal_kind INTEGER NOT NULL CHECK(coordinator_principal_kind IN (0, 1, 2)), coordinator_principal_id BLOB CHECK(coordinator_principal_id IS NULL OR length(coordinator_principal_id) = 16), coordinator_revision INTEGER NOT NULL CHECK(coordinator_revision >= 1), target_agent_id BLOB NOT NULL CHECK(length(target_agent_id) = 16), target_session_id BLOB NOT NULL CHECK(length(target_session_id) = 16), target_principal_kind INTEGER NOT NULL CHECK(target_principal_kind IN (0, 1, 2)), target_principal_id BLOB CHECK(target_principal_id IS NULL OR length(target_principal_id) = 16), target_agent_revision INTEGER NOT NULL CHECK(target_agent_revision >= 1), state INTEGER NOT NULL CHECK(state IN (0, 1, 2, 3, 4, 5, 6)), cancellation_requested INTEGER NOT NULL CHECK(cancellation_requested IN (0, 1)), report TEXT CHECK(report IS NULL OR length(CAST(report AS BLOB)) BETWEEN 1 AND 32768), worktree_root_fingerprint BLOB CHECK(worktree_root_fingerprint IS NULL OR length(worktree_root_fingerprint) = 16), worktree_repository_fingerprint BLOB CHECK(worktree_repository_fingerprint IS NULL OR length(worktree_repository_fingerprint) = 16), worktree_baseline BLOB CHECK(worktree_baseline IS NULL OR length(worktree_baseline) = 20), reviewed_agent_id BLOB CHECK(reviewed_agent_id IS NULL OR length(reviewed_agent_id) = 16), reviewed_session_id BLOB CHECK(reviewed_session_id IS NULL OR length(reviewed_session_id) = 16), reviewed_principal_kind INTEGER CHECK(reviewed_principal_kind IS NULL OR reviewed_principal_kind IN (0, 1, 2)), reviewed_principal_id BLOB CHECK(reviewed_principal_id IS NULL OR length(reviewed_principal_id) = 16), reviewed_revision INTEGER CHECK(reviewed_revision IS NULL OR reviewed_revision >= 1), created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0), updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= created_at_ms), revision INTEGER NOT NULL CHECK(revision >= 1), credit_budget INTEGER CHECK(credit_budget IS NULL OR credit_budget IN (1,3,5)), FOREIGN KEY(coordinator_agent_id, workspace_id, activity_id) REFERENCES agent_instances(agent_id, workspace_id, activity_id), FOREIGN KEY(target_agent_id, workspace_id, activity_id) REFERENCES agent_instances(agent_id, workspace_id, activity_id), FOREIGN KEY(reviewed_agent_id, workspace_id, activity_id) REFERENCES agent_instances(agent_id, workspace_id, activity_id), CHECK((coordinator_principal_kind = 0 AND coordinator_principal_id IS NULL) OR (coordinator_principal_kind IN (1, 2) AND coordinator_principal_id IS NOT NULL)), CHECK((target_principal_kind = 0 AND target_principal_id IS NULL) OR (target_principal_kind IN (1, 2) AND target_principal_id IS NOT NULL)), CHECK((reviewed_principal_kind IS NULL AND reviewed_principal_id IS NULL AND reviewed_agent_id IS NULL AND reviewed_session_id IS NULL AND reviewed_revision IS NULL) OR (reviewed_principal_kind IS NOT NULL AND reviewed_principal_id IS NOT NULL OR reviewed_principal_kind = 0 AND reviewed_principal_id IS NULL) AND reviewed_agent_id IS NOT NULL AND reviewed_session_id IS NOT NULL AND reviewed_revision IS NOT NULL), CHECK((worktree_root_fingerprint IS NULL AND worktree_repository_fingerprint IS NULL AND worktree_baseline IS NULL) OR (worktree_root_fingerprint IS NOT NULL AND worktree_repository_fingerprint IS NOT NULL AND worktree_baseline IS NOT NULL)), CHECK(((state IN (2, 3, 4)) AND report IS NOT NULL) OR ((state IN (0, 1, 5, 6)) AND report IS NULL)), CHECK((state IN (3, 4) AND reviewed_agent_id IS NOT NULL) OR (state NOT IN (3, 4) AND reviewed_agent_id IS NULL)), CHECK((cancellation_requested = 0 AND state IN (0, 1, 2, 3, 4)) OR (cancellation_requested = 1 AND state IN (1, 5, 6))))";
pub(crate) const AGENT_ASSIGNMENT_SOURCES_TABLE_SQL: &str = "CREATE TABLE agent_assignment_sources (assignment_id BLOB NOT NULL REFERENCES agent_assignments(assignment_id), ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 0 AND 31), source_kind INTEGER NOT NULL CHECK(source_kind IN (0, 1)), source_url TEXT CHECK(source_url IS NULL OR length(CAST(source_url AS BLOB)) BETWEEN 1 AND 2048), provenance_kind INTEGER CHECK(provenance_kind IS NULL OR provenance_kind IN (0, 1, 2, 3)), provenance_id BLOB CHECK(provenance_id IS NULL OR length(provenance_id) = 16), PRIMARY KEY(assignment_id, ordinal), CHECK((source_kind = 0 AND source_url IS NOT NULL AND provenance_kind IS NULL AND provenance_id IS NULL) OR (source_kind = 1 AND source_url IS NULL AND provenance_kind IS NOT NULL AND provenance_id IS NOT NULL)))";
pub(crate) const AGENT_ASSIGNMENTS_WORKSPACE_STATE_INDEX_SQL: &str = "CREATE INDEX agent_assignments_workspace_state_idx ON agent_assignments(workspace_id, state, updated_at_ms DESC, assignment_id DESC)";
pub(crate) const AGENT_ASSIGNMENTS_WORKSPACE_ACTIVITY_INDEX_SQL: &str = "CREATE INDEX agent_assignments_workspace_activity_idx ON agent_assignments(workspace_id, activity_id, updated_at_ms DESC, assignment_id DESC)";
pub(crate) const AGENT_ASSIGNMENTS_ACTIVE_NODE_INDEX_SQL: &str = "CREATE UNIQUE INDEX agent_assignments_active_node_idx ON agent_assignments(workspace_id, goal_id, dag_revision, node_id) WHERE state IN (0, 1, 2)";
pub(crate) const AGENT_ASSIGNMENTS_ACTIVE_AGENT_INDEX_SQL: &str = "CREATE UNIQUE INDEX agent_assignments_active_agent_idx ON agent_assignments(workspace_id, target_agent_id) WHERE state IN (0, 1, 2)";
pub(crate) const AGENT_ASSIGNMENT_OFFER_SEALS_TABLE_SQL: &str = "CREATE TABLE agent_assignment_offer_seals (workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16), activity_id BLOB NOT NULL REFERENCES activities(activity_id) CHECK(length(activity_id) = 16), assignment_id BLOB NOT NULL CHECK(length(assignment_id) = 16), authority_kind INTEGER NOT NULL CHECK(authority_kind IN (0, 1)), coordinator_agent_id BLOB CHECK(coordinator_agent_id IS NULL OR length(coordinator_agent_id) = 16), coordinator_session_id BLOB CHECK(coordinator_session_id IS NULL OR length(coordinator_session_id) = 16), expected_coordinator_revision INTEGER CHECK(expected_coordinator_revision IS NULL OR expected_coordinator_revision >= 1), sealed_at_ms INTEGER NOT NULL CHECK(sealed_at_ms >= 0), PRIMARY KEY(workspace_id, activity_id, assignment_id), CHECK((authority_kind = 0 AND coordinator_agent_id IS NULL AND coordinator_session_id IS NULL AND expected_coordinator_revision IS NULL) OR (authority_kind = 1 AND coordinator_agent_id IS NOT NULL AND coordinator_session_id IS NOT NULL AND expected_coordinator_revision IS NOT NULL)))";
const AGENT_ASSIGNMENT_OFFER_SEALS_NO_UPDATE_TRIGGER_SQL: &str = "CREATE TRIGGER agent_assignment_offer_seals_no_update BEFORE UPDATE ON agent_assignment_offer_seals BEGIN SELECT RAISE(ABORT, 'assignment offer seals are immutable'); END";
const AGENT_ASSIGNMENT_OFFER_SEALS_NO_DELETE_TRIGGER_SQL: &str = "CREATE TRIGGER agent_assignment_offer_seals_no_delete BEFORE DELETE ON agent_assignment_offer_seals BEGIN SELECT RAISE(ABORT, 'assignment offer seals are permanent'); END";

const ID_BYTES: usize = 16;
const GIT_OBJECT_BYTES: usize = 20;
const MAX_SCHEMA_SQL_BYTES: usize = 16 * 1024;
const MAX_SCHEMA_METADATA_ROWS: usize = 64;
const MAX_LIST_RESULTS: u32 = 256;

pub(crate) fn create_schema(connection: &Connection) -> Result<(), AgentAssignmentStoreError> {
    connection.execute_batch(AGENT_ASSIGNMENTS_TABLE_SQL)?;
    connection.execute_batch(AGENT_ASSIGNMENT_SOURCES_TABLE_SQL)?;
    connection.execute_batch(AGENT_ASSIGNMENTS_WORKSPACE_STATE_INDEX_SQL)?;
    connection.execute_batch(AGENT_ASSIGNMENTS_WORKSPACE_ACTIVITY_INDEX_SQL)?;
    connection.execute_batch(AGENT_ASSIGNMENTS_ACTIVE_NODE_INDEX_SQL)?;
    connection.execute_batch(AGENT_ASSIGNMENTS_ACTIVE_AGENT_INDEX_SQL)?;
    Ok(())
}

pub(crate) fn create_offer_seal_schema(
    connection: &Connection,
) -> Result<(), AgentAssignmentStoreError> {
    connection.execute_batch(AGENT_ASSIGNMENT_OFFER_SEALS_TABLE_SQL)?;
    connection.execute_batch(AGENT_ASSIGNMENT_OFFER_SEALS_NO_UPDATE_TRIGGER_SQL)?;
    connection.execute_batch(AGENT_ASSIGNMENT_OFFER_SEALS_NO_DELETE_TRIGGER_SQL)?;
    Ok(())
}

pub(crate) const fn schema_objects() -> [(&'static str, &'static str); 9] {
    [
        ("table", "agent_assignments"),
        ("table", "agent_assignment_sources"),
        ("index", "agent_assignments_workspace_state_idx"),
        ("index", "agent_assignments_workspace_activity_idx"),
        ("index", "agent_assignments_active_node_idx"),
        ("index", "agent_assignments_active_agent_idx"),
        ("table", "agent_assignment_offer_seals"),
        ("trigger", "agent_assignment_offer_seals_no_update"),
        ("trigger", "agent_assignment_offer_seals_no_delete"),
    ]
}

pub(crate) const fn schema_objects_pre_offer_seals() -> [(&'static str, &'static str); 6] {
    [
        ("table", "agent_assignments"),
        ("table", "agent_assignment_sources"),
        ("index", "agent_assignments_workspace_state_idx"),
        ("index", "agent_assignments_workspace_activity_idx"),
        ("index", "agent_assignments_active_node_idx"),
        ("index", "agent_assignments_active_agent_idx"),
    ]
}

#[cfg(test)]
pub(crate) const fn offer_seal_schema_objects() -> [(&'static str, &'static str); 3] {
    [
        ("table", "agent_assignment_offer_seals"),
        ("trigger", "agent_assignment_offer_seals_no_update"),
        ("trigger", "agent_assignment_offer_seals_no_delete"),
    ]
}

pub(crate) fn validate_schema(connection: &Connection) -> Result<(), AgentAssignmentStoreError> {
    validate_schema_objects(connection)?;
    validate_schema_columns(connection)?;
    validate_schema_foreign_keys(connection)?;
    validate_offer_seal_schema(connection)
}

pub(crate) fn validate_schema_pre_offer_seals(
    connection: &Connection,
) -> Result<(), AgentAssignmentStoreError> {
    validate_schema_objects(connection)?;
    validate_schema_columns(connection)?;
    validate_schema_foreign_keys(connection)
}

/// Exact v34..v41 shape: the assignment table predates the `WorkCredit` budget
/// column. The expected SQL is derived from the current canonical definition
/// so there is only one hand-written authority for the table contract.
pub(crate) fn validate_schema_pre_work_credit(
    connection: &Connection,
) -> Result<(), AgentAssignmentStoreError> {
    let fragment = format!(", {CREDIT_BUDGET_COLUMN_SQL}");
    let expected_table_sql = AGENT_ASSIGNMENTS_TABLE_SQL.replace(&fragment, "");
    validate_schema_objects_with(connection, &expected_table_sql)?;
    validate_schema_columns_pre_work_credit(connection)?;
    validate_schema_foreign_keys(connection)
}

/// One additive v41 -> v42 migration step; see
/// [`AGENT_ASSIGNMENTS_CREDIT_BUDGET_ALTER_SQL`].
pub(crate) fn add_credit_budget_column(
    connection: &Connection,
) -> Result<(), AgentAssignmentStoreError> {
    connection.execute_batch(AGENT_ASSIGNMENTS_CREDIT_BUDGET_ALTER_SQL)?;
    Ok(())
}

fn validate_schema_objects(connection: &Connection) -> Result<(), AgentAssignmentStoreError> {
    validate_schema_objects_with(connection, AGENT_ASSIGNMENTS_TABLE_SQL)
}

fn validate_schema_objects_with(
    connection: &Connection,
    expected_table_sql: &str,
) -> Result<(), AgentAssignmentStoreError> {
    for (kind, name, expected) in [
        ("table", "agent_assignments", expected_table_sql),
        (
            "table",
            "agent_assignment_sources",
            AGENT_ASSIGNMENT_SOURCES_TABLE_SQL,
        ),
        (
            "index",
            "agent_assignments_workspace_state_idx",
            AGENT_ASSIGNMENTS_WORKSPACE_STATE_INDEX_SQL,
        ),
        (
            "index",
            "agent_assignments_workspace_activity_idx",
            AGENT_ASSIGNMENTS_WORKSPACE_ACTIVITY_INDEX_SQL,
        ),
        (
            "index",
            "agent_assignments_active_node_idx",
            AGENT_ASSIGNMENTS_ACTIVE_NODE_INDEX_SQL,
        ),
        (
            "index",
            "agent_assignments_active_agent_idx",
            AGENT_ASSIGNMENTS_ACTIVE_AGENT_INDEX_SQL,
        ),
    ] {
        let actual: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type = ?1 AND name = ?2",
                params![kind, name],
                |row| row.get(0),
            )
            .optional()?;
        let Some(actual) = actual else {
            return Err(AgentAssignmentStoreError::DamagedSchema(name));
        };
        validate_sql_length(name, &actual)?;
        if !schema_sql_matches(&actual, expected) {
            return Err(AgentAssignmentStoreError::DamagedSchema(name));
        }
    }
    Ok(())
}

fn validate_schema_columns(connection: &Connection) -> Result<(), AgentAssignmentStoreError> {
    validate_columns(
        connection,
        "agent_assignments",
        &[
            ("assignment_id", "BLOB", 1, 1),
            ("workspace_id", "BLOB", 1, 0),
            ("activity_id", "BLOB", 1, 0),
            ("goal_id", "BLOB", 1, 0),
            ("goal_created_at_ms", "INTEGER", 1, 0),
            ("goal_revision", "INTEGER", 1, 0),
            ("dag_revision", "INTEGER", 1, 0),
            ("dag_head_revision", "INTEGER", 1, 0),
            ("node_id", "BLOB", 1, 0),
            ("node_revision", "INTEGER", 1, 0),
            ("coordinator_agent_id", "BLOB", 1, 0),
            ("coordinator_session_id", "BLOB", 1, 0),
            ("coordinator_principal_kind", "INTEGER", 1, 0),
            ("coordinator_principal_id", "BLOB", 0, 0),
            ("coordinator_revision", "INTEGER", 1, 0),
            ("target_agent_id", "BLOB", 1, 0),
            ("target_session_id", "BLOB", 1, 0),
            ("target_principal_kind", "INTEGER", 1, 0),
            ("target_principal_id", "BLOB", 0, 0),
            ("target_agent_revision", "INTEGER", 1, 0),
            ("state", "INTEGER", 1, 0),
            ("cancellation_requested", "INTEGER", 1, 0),
            ("report", "TEXT", 0, 0),
            ("worktree_root_fingerprint", "BLOB", 0, 0),
            ("worktree_repository_fingerprint", "BLOB", 0, 0),
            ("worktree_baseline", "BLOB", 0, 0),
            ("reviewed_agent_id", "BLOB", 0, 0),
            ("reviewed_session_id", "BLOB", 0, 0),
            ("reviewed_principal_kind", "INTEGER", 0, 0),
            ("reviewed_principal_id", "BLOB", 0, 0),
            ("reviewed_revision", "INTEGER", 0, 0),
            ("created_at_ms", "INTEGER", 1, 0),
            ("updated_at_ms", "INTEGER", 1, 0),
            ("revision", "INTEGER", 1, 0),
            ("credit_budget", "INTEGER", 0, 0),
        ],
    )?;
    validate_columns(
        connection,
        "agent_assignment_sources",
        &[
            ("assignment_id", "BLOB", 1, 1),
            ("ordinal", "INTEGER", 1, 2),
            ("source_kind", "INTEGER", 1, 0),
            ("source_url", "TEXT", 0, 0),
            ("provenance_kind", "INTEGER", 0, 0),
            ("provenance_id", "BLOB", 0, 0),
        ],
    )
}

fn validate_schema_columns_pre_work_credit(
    connection: &Connection,
) -> Result<(), AgentAssignmentStoreError> {
    validate_columns(
        connection,
        "agent_assignments",
        &[
            ("assignment_id", "BLOB", 1, 1),
            ("workspace_id", "BLOB", 1, 0),
            ("activity_id", "BLOB", 1, 0),
            ("goal_id", "BLOB", 1, 0),
            ("goal_created_at_ms", "INTEGER", 1, 0),
            ("goal_revision", "INTEGER", 1, 0),
            ("dag_revision", "INTEGER", 1, 0),
            ("dag_head_revision", "INTEGER", 1, 0),
            ("node_id", "BLOB", 1, 0),
            ("node_revision", "INTEGER", 1, 0),
            ("coordinator_agent_id", "BLOB", 1, 0),
            ("coordinator_session_id", "BLOB", 1, 0),
            ("coordinator_principal_kind", "INTEGER", 1, 0),
            ("coordinator_principal_id", "BLOB", 0, 0),
            ("coordinator_revision", "INTEGER", 1, 0),
            ("target_agent_id", "BLOB", 1, 0),
            ("target_session_id", "BLOB", 1, 0),
            ("target_principal_kind", "INTEGER", 1, 0),
            ("target_principal_id", "BLOB", 0, 0),
            ("target_agent_revision", "INTEGER", 1, 0),
            ("state", "INTEGER", 1, 0),
            ("cancellation_requested", "INTEGER", 1, 0),
            ("report", "TEXT", 0, 0),
            ("worktree_root_fingerprint", "BLOB", 0, 0),
            ("worktree_repository_fingerprint", "BLOB", 0, 0),
            ("worktree_baseline", "BLOB", 0, 0),
            ("reviewed_agent_id", "BLOB", 0, 0),
            ("reviewed_session_id", "BLOB", 0, 0),
            ("reviewed_principal_kind", "INTEGER", 0, 0),
            ("reviewed_principal_id", "BLOB", 0, 0),
            ("reviewed_revision", "INTEGER", 0, 0),
            ("created_at_ms", "INTEGER", 1, 0),
            ("updated_at_ms", "INTEGER", 1, 0),
            ("revision", "INTEGER", 1, 0),
        ],
    )
}

fn validate_schema_foreign_keys(connection: &Connection) -> Result<(), AgentAssignmentStoreError> {
    validate_foreign_keys(
        connection,
        "agent_assignments",
        &[
            ("workspace", "workspace_id"),
            ("activities", "activity_id"),
            ("goals", "goal_id"),
            ("agent_instances", "coordinator_agent_id"),
            ("agent_instances", "target_agent_id"),
            ("agent_instances", "reviewed_agent_id"),
        ],
    )?;
    validate_foreign_keys(
        connection,
        "agent_assignment_sources",
        &[("agent_assignments", "assignment_id")],
    )?;
    Ok(())
}

fn validate_sql_length(name: &'static str, sql: &str) -> Result<(), AgentAssignmentStoreError> {
    let bytes = sql.len();
    if bytes > MAX_SCHEMA_SQL_BYTES {
        return Err(AgentAssignmentStoreError::SchemaSqlTooLarge {
            object: name,
            actual: bytes,
            maximum: MAX_SCHEMA_SQL_BYTES,
        });
    }
    Ok(())
}

fn schema_sql_matches(actual: &str, expected: &str) -> bool {
    actual
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .map(|byte| byte.to_ascii_lowercase())
        .eq(expected
            .bytes()
            .filter(|byte| !byte.is_ascii_whitespace())
            .map(|byte| byte.to_ascii_lowercase()))
}

fn validate_offer_seal_schema(connection: &Connection) -> Result<(), AgentAssignmentStoreError> {
    for (kind, name, expected) in [
        (
            "table",
            "agent_assignment_offer_seals",
            AGENT_ASSIGNMENT_OFFER_SEALS_TABLE_SQL,
        ),
        (
            "trigger",
            "agent_assignment_offer_seals_no_update",
            AGENT_ASSIGNMENT_OFFER_SEALS_NO_UPDATE_TRIGGER_SQL,
        ),
        (
            "trigger",
            "agent_assignment_offer_seals_no_delete",
            AGENT_ASSIGNMENT_OFFER_SEALS_NO_DELETE_TRIGGER_SQL,
        ),
    ] {
        let actual: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type = ?1 AND name = ?2",
                params![kind, name],
                |row| row.get(0),
            )
            .optional()?;
        let Some(actual) = actual else {
            return Err(AgentAssignmentStoreError::DamagedSchema(name));
        };
        validate_sql_length(name, &actual)?;
        if !schema_sql_matches(&actual, expected) {
            return Err(AgentAssignmentStoreError::DamagedSchema(name));
        }
    }
    validate_columns(
        connection,
        "agent_assignment_offer_seals",
        &[
            ("workspace_id", "BLOB", 1, 1),
            ("activity_id", "BLOB", 1, 2),
            ("assignment_id", "BLOB", 1, 3),
            ("authority_kind", "INTEGER", 1, 0),
            ("coordinator_agent_id", "BLOB", 0, 0),
            ("coordinator_session_id", "BLOB", 0, 0),
            ("expected_coordinator_revision", "INTEGER", 0, 0),
            ("sealed_at_ms", "INTEGER", 1, 0),
        ],
    )?;
    validate_exact_foreign_keys(
        connection,
        "agent_assignment_offer_seals",
        &[("workspace", "workspace_id"), ("activities", "activity_id")],
    )
}

fn validate_exact_foreign_keys(
    connection: &Connection,
    table: &'static str,
    expected: &[(&str, &str)],
) -> Result<(), AgentAssignmentStoreError> {
    let mut statement = connection.prepare(&format!("PRAGMA foreign_key_list({table})"))?;
    let actual = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(2)?, row.get::<_, String>(3)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if actual.len() != expected.len()
        || !expected.iter().all(|expected| {
            actual
                .iter()
                .any(|actual| actual.0 == expected.0 && actual.1 == expected.1)
        })
    {
        return Err(AgentAssignmentStoreError::DamagedSchema(table));
    }
    Ok(())
}

fn validate_columns(
    connection: &Connection,
    table: &'static str,
    expected: &[(&str, &str, i64, i64)],
) -> Result<(), AgentAssignmentStoreError> {
    let mut statement = connection.prepare(&format!("PRAGMA table_info({table})"))?;
    let mut rows = statement.query([])?;
    let mut actual = Vec::new();
    while let Some(row) = rows.next()? {
        if actual.len() >= MAX_SCHEMA_METADATA_ROWS {
            return Err(AgentAssignmentStoreError::SchemaMetadataTooLarge { object: table });
        }
        actual.push((
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, i64>(5)?,
        ));
    }
    if actual.len() != expected.len()
        || !actual.iter().zip(expected).all(
            |((name, data_type, not_null, primary_key), expected)| {
                name == expected.0
                    && data_type == expected.1
                    && *not_null == expected.2
                    && *primary_key == expected.3
            },
        )
    {
        return Err(AgentAssignmentStoreError::DamagedSchema(table));
    }
    Ok(())
}

fn validate_foreign_keys(
    connection: &Connection,
    table: &'static str,
    expected: &[(&str, &str)],
) -> Result<(), AgentAssignmentStoreError> {
    let mut statement = connection.prepare(&format!("PRAGMA foreign_key_list({table})"))?;
    let actual = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(2)?, row.get::<_, String>(3)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if !expected.iter().all(|expected| {
        actual
            .iter()
            .any(|actual| actual.0 == expected.0 && actual.1 == expected.1)
    }) {
        return Err(AgentAssignmentStoreError::DamagedSchema(table));
    }
    Ok(())
}

const ASSIGNMENT_QUERY: &str = "SELECT assignment_id, workspace_id, activity_id, goal_id,
       goal_created_at_ms, goal_revision, dag_revision, dag_head_revision, node_id, node_revision,
       coordinator_agent_id, coordinator_session_id, coordinator_principal_kind,
       coordinator_principal_id, coordinator_revision, target_agent_id, target_session_id,
       target_principal_kind, target_principal_id, target_agent_revision, state,
       cancellation_requested, report, worktree_root_fingerprint,
       worktree_repository_fingerprint, worktree_baseline, reviewed_agent_id,
       reviewed_session_id, reviewed_principal_kind, reviewed_principal_id, reviewed_revision,
       created_at_ms, updated_at_ms, revision, credit_budget
FROM agent_assignments
WHERE assignment_id = ?1";

const ACTIVE_ASSIGNMENT_FOR_NODE_SUMMARY_QUERY: &str =
    "SELECT assignment_id, workspace_id, activity_id, goal_id, goal_revision,
       dag_revision, dag_head_revision, node_id, node_revision,
       target_agent_id, target_session_id, state, cancellation_requested,
       report IS NOT NULL,
       (SELECT COUNT(*) FROM agent_assignment_sources AS s
        WHERE s.assignment_id = a.assignment_id),
       created_at_ms, updated_at_ms, revision, goal_created_at_ms
FROM agent_assignments AS a
WHERE workspace_id = ?1 AND goal_id = ?2 AND dag_revision = ?3 AND node_id = ?4
  AND state IN (0, 1, 2)";

const SOURCES_QUERY: &str =
    "SELECT ordinal, source_kind, source_url, provenance_kind, provenance_id
FROM agent_assignment_sources
WHERE assignment_id = ?1
ORDER BY ordinal ASC";

#[derive(Debug)]
struct RawAssignment {
    assignment_id: Vec<u8>,
    workspace_id: Vec<u8>,
    activity_id: Vec<u8>,
    goal_id: Vec<u8>,
    goal_created_at_ms: i64,
    goal_revision: i64,
    dag_revision: i64,
    dag_head_revision: i64,
    node_id: Vec<u8>,
    node_revision: i64,
    coordinator_agent_id: Vec<u8>,
    coordinator_session_id: Vec<u8>,
    coordinator_principal_kind: i64,
    coordinator_principal_id: Option<Vec<u8>>,
    coordinator_revision: i64,
    target_agent_id: Vec<u8>,
    target_session_id: Vec<u8>,
    target_principal_kind: i64,
    target_principal_id: Option<Vec<u8>>,
    target_agent_revision: i64,
    state: i64,
    cancellation_requested: i64,
    report: Option<String>,
    worktree_root_fingerprint: Option<Vec<u8>>,
    worktree_repository_fingerprint: Option<Vec<u8>>,
    worktree_baseline: Option<Vec<u8>>,
    reviewed_agent_id: Option<Vec<u8>>,
    reviewed_session_id: Option<Vec<u8>>,
    reviewed_principal_kind: Option<i64>,
    reviewed_principal_id: Option<Vec<u8>>,
    reviewed_revision: Option<i64>,
    created_at_ms: i64,
    updated_at_ms: i64,
    revision: i64,
    credit_budget: Option<i64>,
}

pub(crate) fn get(
    connection: &Connection,
    assignment_id: AgentAssignmentId,
) -> Result<Option<RegisteredAgentAssignment>, AgentAssignmentStoreError> {
    let Some(raw) = connection
        .query_row(
            ASSIGNMENT_QUERY,
            params![assignment_id.into_uuid().as_bytes()],
            decode_raw,
        )
        .optional()?
    else {
        return Ok(None);
    };
    decode_assignment(connection, raw).map(Some)
}

pub(crate) fn get_in_transaction(
    connection: &Connection,
    assignment_id: AgentAssignmentId,
) -> Result<Option<RegisteredAgentAssignment>, AgentAssignmentStoreError> {
    get(connection, assignment_id)
}

pub(crate) fn list(
    connection: &Connection,
    workspace_id: WorkspaceId,
    limit: u32,
) -> Result<Vec<AgentAssignmentSummary>, AgentAssignmentStoreError> {
    list_summaries(connection, workspace_id, None, None, limit)
}

pub(crate) fn list_for_activity(
    connection: &Connection,
    workspace_id: WorkspaceId,
    activity_id: forge_domain::ActivityId,
    target_agent_id: Option<AgentInstanceId>,
    limit: u32,
) -> Result<Vec<AgentAssignmentSummary>, AgentAssignmentStoreError> {
    list_summaries(
        connection,
        workspace_id,
        Some(activity_id),
        target_agent_id,
        limit,
    )
}

pub(crate) fn active_for_node(
    connection: &Connection,
    workspace_id: WorkspaceId,
    scope: crate::DagNodeEvidenceScope,
    goal_created_at: TimestampMillis,
) -> Result<Option<AgentAssignmentSummary>, AgentAssignmentStoreError> {
    let workspace_bytes = workspace_id.into_uuid().into_bytes();
    let goal_bytes = scope.goal_id().into_uuid().into_bytes();
    let node_bytes = scope.node_id().into_uuid().into_bytes();
    let mut statement = connection.prepare(ACTIVE_ASSIGNMENT_FOR_NODE_SUMMARY_QUERY)?;
    let mut rows = statement.query(params![
        workspace_bytes.as_slice(),
        goal_bytes.as_slice(),
        scope.dag_revision().get(),
        node_bytes.as_slice(),
    ])?;
    let Some(row) = rows.next()? else {
        return Ok(None);
    };
    if decode_timestamp("assignment.goal_created_at_ms", row.get(18)?)? != goal_created_at {
        return Err(AgentAssignmentStoreError::GoalConflict);
    }
    decode_summary(row, workspace_id).map(Some)
}

fn list_summaries(
    connection: &Connection,
    workspace_id: WorkspaceId,
    activity_id: Option<forge_domain::ActivityId>,
    target_agent_id: Option<AgentInstanceId>,
    limit: u32,
) -> Result<Vec<AgentAssignmentSummary>, AgentAssignmentStoreError> {
    let limit = limit.min(MAX_LIST_RESULTS);
    let mut statement = connection.prepare(
        "SELECT assignment_id, workspace_id, activity_id, goal_id, goal_revision,
                dag_revision, dag_head_revision, node_id, node_revision,
                target_agent_id, target_session_id, state, cancellation_requested,
                report IS NOT NULL,
                (SELECT COUNT(*) FROM agent_assignment_sources AS s
                 WHERE s.assignment_id = a.assignment_id),
                created_at_ms, updated_at_ms, revision
         FROM agent_assignments AS a
         WHERE workspace_id = ?1
           AND (?2 IS NULL OR activity_id = ?2)
           AND (?3 IS NULL OR target_agent_id = ?3)
         ORDER BY updated_at_ms DESC, assignment_id DESC
         LIMIT ?4",
    )?;
    let workspace_bytes = workspace_id.into_uuid().into_bytes();
    let activity_bytes = activity_id.map(|id| id.into_uuid().into_bytes().to_vec());
    let target_bytes = target_agent_id.map(|id| id.into_uuid().into_bytes().to_vec());
    let mut rows = statement.query(params![
        workspace_bytes.as_slice(),
        activity_bytes.as_deref(),
        target_bytes.as_deref(),
        limit,
    ])?;
    let mut result = Vec::new();
    while let Some(row) = rows.next()? {
        result.push(decode_summary(row, workspace_id)?);
    }
    Ok(result)
}

fn decode_summary(
    row: &Row<'_>,
    expected_workspace_id: WorkspaceId,
) -> Result<AgentAssignmentSummary, AgentAssignmentStoreError> {
    let assignment_id = AgentAssignmentId::from_uuid(decode_uuid(
        "assignment.assignment_id",
        &row.get::<_, Vec<u8>>(0)?,
    )?);
    let workspace_id = WorkspaceId::from_uuid(decode_uuid(
        "assignment.workspace_id",
        &row.get::<_, Vec<u8>>(1)?,
    )?);
    if workspace_id != expected_workspace_id {
        return Err(AgentAssignmentStoreError::WorkspaceMismatch);
    }
    let activity_id = forge_domain::ActivityId::from_uuid(decode_uuid(
        "assignment.activity_id",
        &row.get::<_, Vec<u8>>(2)?,
    )?);
    let goal_id = GoalId::from_uuid(decode_uuid(
        "assignment.goal_id",
        &row.get::<_, Vec<u8>>(3)?,
    )?);
    let source_count = u8::try_from(row.get::<_, i64>(14)?)
        .map_err(|_| AgentAssignmentStoreError::TooManySources)?;
    Ok(AgentAssignmentSummary::new_for_persistence(
        assignment_id,
        workspace_id,
        activity_id,
        goal_id,
        decode_goal_revision(row.get(4)?)?,
        decode_dag_revision(row.get(5)?)?,
        decode_dag_head_revision(row.get(6)?)?,
        DagNodeId::from_uuid(decode_uuid(
            "assignment.node_id",
            &row.get::<_, Vec<u8>>(7)?,
        )?),
        decode_dag_node_revision(row.get(8)?)?,
        AgentInstanceId::from_uuid(decode_uuid(
            "assignment.target_agent_id",
            &row.get::<_, Vec<u8>>(9)?,
        )?),
        AgentSessionId::from_uuid(decode_uuid(
            "assignment.target_session_id",
            &row.get::<_, Vec<u8>>(10)?,
        )?),
        decode_state(row.get(11)?)?,
        decode_bool("assignment.cancellation_requested", row.get(12)?)?,
        decode_bool("assignment.has_result", row.get(13)?)?,
        source_count,
        decode_timestamp("assignment.created_at_ms", row.get(15)?)?,
        decode_timestamp("assignment.updated_at_ms", row.get(16)?)?,
        decode_assignment_revision(row.get(17)?)?,
        forge_domain::AgentAssignmentOrigin::CoordinatorOffer,
    ))
}

fn decode_raw(row: &Row<'_>) -> rusqlite::Result<RawAssignment> {
    Ok(RawAssignment {
        assignment_id: row.get(0)?,
        workspace_id: row.get(1)?,
        activity_id: row.get(2)?,
        goal_id: row.get(3)?,
        goal_created_at_ms: row.get(4)?,
        goal_revision: row.get(5)?,
        dag_revision: row.get(6)?,
        dag_head_revision: row.get(7)?,
        node_id: row.get(8)?,
        node_revision: row.get(9)?,
        coordinator_agent_id: row.get(10)?,
        coordinator_session_id: row.get(11)?,
        coordinator_principal_kind: row.get(12)?,
        coordinator_principal_id: row.get(13)?,
        coordinator_revision: row.get(14)?,
        target_agent_id: row.get(15)?,
        target_session_id: row.get(16)?,
        target_principal_kind: row.get(17)?,
        target_principal_id: row.get(18)?,
        target_agent_revision: row.get(19)?,
        state: row.get(20)?,
        cancellation_requested: row.get(21)?,
        report: row.get(22)?,
        worktree_root_fingerprint: row.get(23)?,
        worktree_repository_fingerprint: row.get(24)?,
        worktree_baseline: row.get(25)?,
        reviewed_agent_id: row.get(26)?,
        reviewed_session_id: row.get(27)?,
        reviewed_principal_kind: row.get(28)?,
        reviewed_principal_id: row.get(29)?,
        reviewed_revision: row.get(30)?,
        created_at_ms: row.get(31)?,
        updated_at_ms: row.get(32)?,
        revision: row.get(33)?,
        credit_budget: row.get(34)?,
    })
}

fn decode_assignment(
    connection: &Connection,
    raw: RawAssignment,
) -> Result<RegisteredAgentAssignment, AgentAssignmentStoreError> {
    let assignment_id =
        AgentAssignmentId::from_uuid(decode_uuid("assignment.assignment_id", &raw.assignment_id)?);
    let workspace_id =
        WorkspaceId::from_uuid(decode_uuid("assignment.workspace_id", &raw.workspace_id)?);
    let activity_id = forge_domain::ActivityId::from_uuid(decode_uuid(
        "assignment.activity_id",
        &raw.activity_id,
    )?);
    let goal_id = GoalId::from_uuid(decode_uuid("assignment.goal_id", &raw.goal_id)?);
    let coordinator = decode_assignment_coordinator(&raw)?;
    let target = decode_assignment_target(&raw)?;
    let reviewed_by = decode_assignment_review(&raw)?;
    let state = decode_state(raw.state)?;
    let result = decode_assignment_result(
        connection,
        assignment_id,
        raw.report,
        raw.worktree_root_fingerprint,
        raw.worktree_repository_fingerprint,
        raw.worktree_baseline,
    )?;
    RegisteredAgentAssignment::from_parts(
        assignment_id,
        workspace_id,
        activity_id,
        goal_id,
        decode_timestamp("assignment.goal_created_at_ms", raw.goal_created_at_ms)?,
        decode_goal_revision(raw.goal_revision)?,
        decode_dag_revision(raw.dag_revision)?,
        decode_dag_head_revision(raw.dag_head_revision)?,
        DagNodeId::from_uuid(decode_uuid("assignment.node_id", &raw.node_id)?),
        decode_dag_node_revision(raw.node_revision)?,
        coordinator,
        target,
        state,
        decode_bool(
            "assignment.cancellation_requested",
            raw.cancellation_requested,
        )?,
        decode_credit_budget(raw.credit_budget)?,
        result,
        reviewed_by,
        decode_timestamp("assignment.created_at_ms", raw.created_at_ms)?,
        decode_timestamp("assignment.updated_at_ms", raw.updated_at_ms)?,
        decode_assignment_revision(raw.revision)?,
        forge_domain::AgentAssignmentOrigin::CoordinatorOffer,
    )
    .map_err(AgentAssignmentStoreError::Transition)
}

fn decode_assignment_coordinator(
    raw: &RawAssignment,
) -> Result<AgentAssignmentCoordinator, AgentAssignmentStoreError> {
    Ok(AgentAssignmentCoordinator::new(
        AgentInstanceId::from_uuid(decode_uuid(
            "assignment.coordinator_agent_id",
            &raw.coordinator_agent_id,
        )?),
        AgentSessionId::from_uuid(decode_uuid(
            "assignment.coordinator_session_id",
            &raw.coordinator_session_id,
        )?),
        decode_principal(
            raw.coordinator_principal_kind,
            raw.coordinator_principal_id.as_deref(),
        )?,
        decode_activity_coordinator_revision(raw.coordinator_revision)?,
    ))
}

fn decode_assignment_target(
    raw: &RawAssignment,
) -> Result<AgentAssignmentTarget, AgentAssignmentStoreError> {
    Ok(AgentAssignmentTarget::new(
        AgentInstanceId::from_uuid(decode_uuid(
            "assignment.target_agent_id",
            &raw.target_agent_id,
        )?),
        AgentSessionId::from_uuid(decode_uuid(
            "assignment.target_session_id",
            &raw.target_session_id,
        )?),
        decode_principal(
            raw.target_principal_kind,
            raw.target_principal_id.as_deref(),
        )?,
        decode_agent_revision(raw.target_agent_revision)?,
    ))
}

fn decode_assignment_review(
    raw: &RawAssignment,
) -> Result<Option<AgentAssignmentCoordinator>, AgentAssignmentStoreError> {
    match (
        raw.reviewed_agent_id.as_deref(),
        raw.reviewed_session_id.as_deref(),
        raw.reviewed_principal_kind,
        raw.reviewed_principal_id.as_deref(),
        raw.reviewed_revision,
    ) {
        (None, None, None, None, None) => Ok(None),
        (Some(agent), Some(session), Some(kind), principal, Some(revision)) => {
            Ok(Some(AgentAssignmentCoordinator::new(
                AgentInstanceId::from_uuid(decode_uuid("assignment.reviewed_agent_id", agent)?),
                AgentSessionId::from_uuid(decode_uuid("assignment.reviewed_session_id", session)?),
                decode_principal(kind, principal)?,
                decode_activity_coordinator_revision(revision)?,
            )))
        }
        _ => Err(AgentAssignmentStoreError::CorruptRecord(
            "assignment.reviewed_by",
        )),
    }
}

fn decode_assignment_result(
    connection: &Connection,
    assignment_id: AgentAssignmentId,
    report: Option<String>,
    worktree_root_fingerprint: Option<Vec<u8>>,
    worktree_repository_fingerprint: Option<Vec<u8>>,
    worktree_baseline: Option<Vec<u8>>,
) -> Result<Option<AgentAssignmentResult>, AgentAssignmentStoreError> {
    let Some(report) = report else {
        if worktree_root_fingerprint.is_some()
            || worktree_repository_fingerprint.is_some()
            || worktree_baseline.is_some()
        {
            return Err(AgentAssignmentStoreError::CorruptRecord(
                "assignment.worktree",
            ));
        }
        return Ok(None);
    };
    let sources = load_sources(connection, assignment_id)?;
    let worktree = decode_worktree(
        worktree_root_fingerprint,
        worktree_repository_fingerprint,
        worktree_baseline,
    )?;
    Ok(Some(AgentAssignmentResult::new(report, sources, worktree)?))
}

fn load_sources(
    connection: &Connection,
    assignment_id: AgentAssignmentId,
) -> Result<Vec<AgentAssignmentSourceRef>, AgentAssignmentStoreError> {
    let mut statement = connection.prepare(SOURCES_QUERY)?;
    let mut rows = statement.query(params![assignment_id.into_uuid().as_bytes()])?;
    let mut sources = Vec::new();
    while let Some(row) = rows.next()? {
        if sources.len() >= MAX_AGENT_ASSIGNMENT_SOURCES {
            return Err(AgentAssignmentStoreError::TooManySources);
        }
        let kind: i64 = row.get(1)?;
        let source_url: Option<String> = row.get(2)?;
        let provenance_kind: Option<i64> = row.get(3)?;
        let provenance_id: Option<Vec<u8>> = row.get(4)?;
        let source = match kind {
            0 => AgentAssignmentSourceRef::Url(AgentAssignmentSourceUrl::new(source_url.ok_or(
                AgentAssignmentStoreError::CorruptRecord("assignment.source_url"),
            )?)?),
            1 => AgentAssignmentSourceRef::Provenance(decode_evidence(
                provenance_kind.ok_or(AgentAssignmentStoreError::CorruptRecord(
                    "assignment.source_kind",
                ))?,
                provenance_id
                    .as_deref()
                    .ok_or(AgentAssignmentStoreError::CorruptRecord(
                        "assignment.provenance_id",
                    ))?,
            )?),
            _ => {
                return Err(AgentAssignmentStoreError::CorruptRecord(
                    "assignment.source_kind",
                ));
            }
        };
        sources.push(source);
    }
    Ok(sources)
}

fn decode_worktree(
    root: Option<Vec<u8>>,
    repository: Option<Vec<u8>>,
    baseline: Option<Vec<u8>>,
) -> Result<Option<AgentAssignmentWorktreeReceipt>, AgentAssignmentStoreError> {
    match (root, repository, baseline) {
        (None, None, None) => Ok(None),
        (Some(root), Some(repository), Some(baseline)) => {
            Ok(Some(AgentAssignmentWorktreeReceipt::new(
                decode_fingerprint("assignment.worktree_root_fingerprint", &root)?,
                decode_fingerprint("assignment.worktree_repository_fingerprint", &repository)?,
                forge_domain::GitCommitId::from_sha1_bytes(decode_fixed_bytes(
                    "assignment.worktree_baseline",
                    &baseline,
                    GIT_OBJECT_BYTES,
                )?),
            )))
        }
        _ => Err(AgentAssignmentStoreError::CorruptRecord(
            "assignment.worktree",
        )),
    }
}

pub(crate) fn seal_offer(
    connection: &mut Connection,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    assignment_id: AgentAssignmentId,
    actor: Option<ActivityCoordinatorActor>,
    observed_at: TimestampMillis,
) -> Result<AgentAssignmentOfferSealSnapshot, AgentAssignmentStoreError> {
    validate_offer_seal_identity(workspace_id, activity_id, assignment_id)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    validate_offer_seal_activity_scope(&transaction, workspace_id, activity_id)?;
    if let Some(actor) = actor {
        validate_offer_seal_actor(workspace_id, activity_id, actor)?;
        validate_current_coordinator(&transaction, actor)?;
    }
    let authority = AgentAssignmentOfferSealAuthority::from_actor(actor);
    let (authority_kind, coordinator_agent_id, coordinator_session_id, coordinator_revision) =
        match authority {
            AgentAssignmentOfferSealAuthority::LocalOperator => (0, None, None, None),
            AgentAssignmentOfferSealAuthority::Coordinator {
                agent_id,
                session_id,
                expected_coordinator_revision,
            } => (
                1,
                Some(agent_id.into_uuid().as_bytes().to_vec()),
                Some(session_id.into_uuid().as_bytes().to_vec()),
                Some(expected_coordinator_revision.get()),
            ),
        };
    transaction.execute(
        "INSERT INTO agent_assignment_offer_seals(\
            workspace_id, activity_id, assignment_id, authority_kind, coordinator_agent_id, \
            coordinator_session_id, expected_coordinator_revision, sealed_at_ms\
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) \
         ON CONFLICT(workspace_id, activity_id, assignment_id) DO NOTHING",
        params![
            workspace_id.into_uuid().as_bytes(),
            activity_id.into_uuid().as_bytes(),
            assignment_id.into_uuid().as_bytes(),
            authority_kind,
            coordinator_agent_id,
            coordinator_session_id,
            coordinator_revision,
            observed_at.get(),
        ],
    )?;
    let snapshot =
        offer_seal_snapshot_in_transaction(&transaction, workspace_id, activity_id, assignment_id)?
            .ok_or(AgentAssignmentStoreError::CorruptRecord(
                "agent_assignment_offer_seals.inserted",
            ))?;
    transaction.commit().map_err(|source| {
        AgentAssignmentStoreError::OfferSealCommitUnconfirmed {
            workspace_id,
            activity_id,
            assignment_id,
            source: Box::new(source),
        }
    })?;
    Ok(snapshot)
}

pub(crate) fn get_offer_seal(
    connection: &Connection,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    assignment_id: AgentAssignmentId,
    actor: Option<ActivityCoordinatorActor>,
    _observed_at: TimestampMillis,
) -> Result<Option<AgentAssignmentOfferSealSnapshot>, AgentAssignmentStoreError> {
    validate_offer_seal_identity(workspace_id, activity_id, assignment_id)?;
    let transaction = connection.unchecked_transaction()?;
    validate_offer_seal_activity_scope(&transaction, workspace_id, activity_id)?;
    if let Some(actor) = actor {
        validate_offer_seal_actor(workspace_id, activity_id, actor)?;
        validate_current_coordinator(&transaction, actor)?;
    }
    let snapshot =
        offer_seal_snapshot_in_transaction(&transaction, workspace_id, activity_id, assignment_id)?;
    transaction.commit()?;
    Ok(snapshot)
}

fn offer_seal_snapshot_in_transaction(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    assignment_id: AgentAssignmentId,
) -> Result<Option<AgentAssignmentOfferSealSnapshot>, AgentAssignmentStoreError> {
    let seal_row = transaction
        .query_row(
            "SELECT sealed_at_ms, authority_kind, coordinator_agent_id, coordinator_session_id, \
                    expected_coordinator_revision \
             FROM agent_assignment_offer_seals \
             WHERE workspace_id = ?1 AND activity_id = ?2 AND assignment_id = ?3",
            params![
                workspace_id.into_uuid().as_bytes(),
                activity_id.into_uuid().as_bytes(),
                assignment_id.into_uuid().as_bytes(),
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Option<Vec<u8>>>(2)?,
                    row.get::<_, Option<Vec<u8>>>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                ))
            },
        )
        .optional()?;
    let Some((
        sealed_at_ms,
        authority_kind,
        coordinator_agent_id,
        coordinator_session_id,
        coordinator_revision,
    )) = seal_row
    else {
        return Ok(None);
    };
    let sealed_at = TimestampMillis::new(sealed_at_ms)
        .map_err(|_| AgentAssignmentStoreError::CorruptRecord("assignment_offer_seal.sealed_at"))?;
    let authority = decode_offer_seal_authority(
        authority_kind,
        coordinator_agent_id.as_deref(),
        coordinator_session_id.as_deref(),
        coordinator_revision,
    )?;
    let current_assignment = get_in_transaction(transaction, assignment_id)?;
    if current_assignment
        .as_ref()
        .is_some_and(|assignment| assignment.workspace_id() != workspace_id)
    {
        return Err(AgentAssignmentStoreError::WorkspaceMismatch);
    }
    Ok(Some(AgentAssignmentOfferSealSnapshot::new(
        workspace_id,
        activity_id,
        assignment_id,
        sealed_at,
        authority,
        current_assignment,
    )))
}

fn decode_offer_seal_authority(
    kind: i64,
    coordinator_agent_id: Option<&[u8]>,
    coordinator_session_id: Option<&[u8]>,
    coordinator_revision: Option<i64>,
) -> Result<AgentAssignmentOfferSealAuthority, AgentAssignmentStoreError> {
    match (
        kind,
        coordinator_agent_id,
        coordinator_session_id,
        coordinator_revision,
    ) {
        (0, None, None, None) => Ok(AgentAssignmentOfferSealAuthority::LocalOperator),
        (1, Some(agent_id), Some(session_id), Some(revision)) => {
            Ok(AgentAssignmentOfferSealAuthority::Coordinator {
                agent_id: AgentInstanceId::from_uuid(decode_uuid(
                    "assignment_offer_seal.coordinator_agent_id",
                    agent_id,
                )?),
                session_id: AgentSessionId::from_uuid(decode_uuid(
                    "assignment_offer_seal.coordinator_session_id",
                    session_id,
                )?),
                expected_coordinator_revision: decode_activity_coordinator_revision(revision)?,
            })
        }
        _ => Err(AgentAssignmentStoreError::CorruptRecord(
            "assignment_offer_seal.authority",
        )),
    }
}

fn validate_offer_seal_identity(
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    assignment_id: AgentAssignmentId,
) -> Result<(), AgentAssignmentStoreError> {
    if workspace_id.into_uuid().is_nil()
        || activity_id.into_uuid().is_nil()
        || assignment_id.into_uuid().is_nil()
    {
        return Err(AgentAssignmentStoreError::InvalidOfferSealIdentity);
    }
    Ok(())
}

fn validate_offer_seal_activity_scope(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
) -> Result<(), AgentAssignmentStoreError> {
    let activity_workspace: Option<Vec<u8>> = transaction
        .query_row(
            "SELECT substr(workspace_id, 1, 17) FROM activities WHERE activity_id = ?1",
            params![activity_id.into_uuid().as_bytes()],
            |row| row.get(0),
        )
        .optional()?;
    let Some(activity_workspace) = activity_workspace else {
        return Err(AgentAssignmentStoreError::ActivityMismatch);
    };
    let actual_workspace = WorkspaceId::from_uuid(decode_uuid(
        "agent_assignment_offer_seals.activity_workspace_id",
        &activity_workspace,
    )?);
    if actual_workspace != workspace_id {
        return Err(AgentAssignmentStoreError::ActivityMismatch);
    }
    Ok(())
}

fn validate_offer_seal_actor(
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    actor: ActivityCoordinatorActor,
) -> Result<(), AgentAssignmentStoreError> {
    if actor.workspace_id() != workspace_id || actor.activity_id() != activity_id {
        return Err(AgentAssignmentStoreError::ActivityMismatch);
    }
    Ok(())
}

pub(crate) fn offer(
    connection: &mut Connection,
    command: &OfferAgentAssignment,
    admitted_at: TimestampMillis,
) -> Result<RegisteredAgentAssignment, AgentAssignmentStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let actor = command.coordinator();
    validate_current_coordinator_live(&transaction, actor, admitted_at)?;
    let target = command.target();
    if let Some(existing) = get_in_transaction(&transaction, command.assignment_id())? {
        if offer_payload_matches(&existing, command) {
            transaction.commit()?;
            return Ok(existing);
        }
        return Err(AgentAssignmentStoreError::IdentityConflict);
    }
    if crate::workspace_work_cuts::continuation_successor_reserved(
        &transaction,
        command.assignment_id(),
    )? {
        return Err(AgentAssignmentStoreError::IdentityConflict);
    }
    if offer_seal_exists(
        &transaction,
        actor.workspace_id(),
        actor.activity_id(),
        command.assignment_id(),
    )? {
        return Err(AgentAssignmentStoreError::OfferAdmissionSealed {
            activity_id: actor.activity_id(),
            assignment_id: command.assignment_id(),
        });
    }
    if actor.agent_id() == target.agent_id() {
        return Err(AgentAssignmentStoreError::CoordinatorTargetSameAgent);
    }
    let _ = workspace_agents::ensure_bound_attached_agent(
        &transaction,
        actor.workspace_id(),
        actor.activity_id(),
        target.agent_id(),
        target.session_id(),
        target.principal(),
        Some(target.agent_revision()),
    )?;
    let goal = validate_goal_scope(
        &transaction,
        actor.workspace_id(),
        actor.activity_id(),
        command.goal_id(),
        command.expected_goal_revision(),
        command.expected_goal_created_at(),
    )?;
    let current = validate_dag_scope(
        &transaction,
        &goal,
        command.dag_revision(),
        command.expected_head_revision(),
        command.node_id(),
        command.expected_node_revision(),
        true,
    )?;
    ensure_offer_custody_open(&transaction, command)?;
    let active_count: i64 = transaction.query_row(
        "SELECT COUNT(*) FROM agent_assignments WHERE workspace_id = ?1 AND state IN (0, 1, 2)",
        params![actor.workspace_id().into_uuid().as_bytes()],
        |row| row.get(0),
    )?;
    if usize::try_from(active_count).unwrap_or(usize::MAX) >= MAX_AGENT_ASSIGNMENTS_PER_WORKSPACE {
        return Err(AgentAssignmentStoreError::ActiveLimit);
    }
    let assignment = RegisteredAgentAssignment::offered(
        command.assignment_id(),
        actor.workspace_id(),
        actor.activity_id(),
        goal.id(),
        goal.timestamps().created_at(),
        goal.revision(),
        current.revision().number(),
        current.head().revision(),
        command.node_id(),
        command.expected_node_revision(),
        AgentAssignmentCoordinator::from_actor(actor),
        target,
        command.credit_budget(),
        command.observed_at(),
    )?;
    insert_assignment(&transaction, &assignment)?;
    let result = get_in_transaction(&transaction, assignment.id())?.ok_or(
        AgentAssignmentStoreError::CorruptRecord("assignment.inserted"),
    )?;
    // The durable first-work receipt belongs to the same caller transaction as
    // the insert above; a fact failure rolls the offer back with it.
    crate::workspace_effect_fact_outbox::append_assignment_offered(&transaction, &result)?;
    transaction
        .commit()
        .map_err(|source| AgentAssignmentStoreError::OfferCommitUnconfirmed {
            workspace_id: assignment.workspace_id(),
            activity_id: assignment.activity_id(),
            assignment_id: assignment.id(),
            source: Box::new(source),
        })?;
    Ok(result)
}

pub(crate) fn offer_seal_exists(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    assignment_id: AgentAssignmentId,
) -> Result<bool, AgentAssignmentStoreError> {
    transaction
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM agent_assignment_offer_seals WHERE workspace_id = ?1 AND activity_id = ?2 AND assignment_id = ?3)",
            params![
                workspace_id.into_uuid().as_bytes(),
                activity_id.into_uuid().as_bytes(),
                assignment_id.into_uuid().as_bytes(),
            ],
            |row| row.get(0),
        )
        .map_err(Into::into)
}

fn ensure_offer_custody_open(
    transaction: &Transaction<'_>,
    command: &OfferAgentAssignment,
) -> Result<(), AgentAssignmentStoreError> {
    let actor = command.coordinator();
    let target = command.target();
    crate::workspace_work_cuts::guards::ensure_node_open(
        transaction,
        actor.workspace_id(),
        command.goal_id(),
        command.dag_revision(),
        command.node_id(),
    )?;
    crate::workspace_work_cuts::guards::ensure_actor_open(
        transaction,
        actor.workspace_id(),
        actor.agent_id(),
    )?;
    crate::workspace_work_cuts::guards::ensure_actor_open(
        transaction,
        actor.workspace_id(),
        target.agent_id(),
    )?;
    Ok(())
}

fn offer_payload_matches(
    current: &RegisteredAgentAssignment,
    command: &OfferAgentAssignment,
) -> bool {
    let actor = command.coordinator();
    current.id() == command.assignment_id()
        && current.workspace_id() == actor.workspace_id()
        && current.activity_id() == actor.activity_id()
        && current.goal_id() == command.goal_id()
        && current.goal_created_at() == command.expected_goal_created_at()
        && current.goal_revision() == command.expected_goal_revision()
        && current.dag_revision() == command.dag_revision()
        && current.dag_head_revision() == command.expected_head_revision()
        && current.node_id() == command.node_id()
        && current.node_revision() == command.expected_node_revision()
        && current.coordinator() == AgentAssignmentCoordinator::from_actor(actor)
        && current.target() == command.target()
        && current.credit_budget() == command.credit_budget()
        && current.created_at() == command.observed_at()
}

pub(crate) fn claim(
    connection: &mut Connection,
    command: &ClaimAgentAssignment,
    admitted_at: TimestampMillis,
) -> Result<RegisteredAgentAssignment, AgentAssignmentStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let current = get_in_transaction(&transaction, command.assignment_id())?.ok_or(
        AgentAssignmentStoreError::AssignmentNotFound(command.assignment_id()),
    )?;
    let agent = validate_claim_context(&transaction, &current, command, admitted_at)?;
    crate::workspace_work_cuts::guards::ensure_node_open(
        &transaction,
        current.workspace_id(),
        current.goal_id(),
        current.dag_revision(),
        current.node_id(),
    )?;
    start_claimed_node_and_focus(&transaction, &current, command, &agent)?;
    let updated = current.claim(
        command.target(),
        command.expected_revision(),
        command.observed_at(),
    )?;
    update_assignment(&transaction, &current, &updated)?;
    let result = get_in_transaction(&transaction, updated.id())?.ok_or(
        AgentAssignmentStoreError::CorruptRecord("assignment.claimed"),
    )?;
    transaction.commit()?;
    Ok(result)
}

fn validate_claim_context(
    transaction: &Transaction<'_>,
    current: &RegisteredAgentAssignment,
    command: &ClaimAgentAssignment,
    admitted_at: TimestampMillis,
) -> Result<forge_domain::RegisteredAgentInstance, AgentAssignmentStoreError> {
    if current.target().agent_revision() != command.target().agent_revision() {
        return Err(AgentAssignmentStoreError::TargetRevisionConflict);
    }
    if current.target().agent_id() != command.target().agent_id()
        || current.target().session_id() != command.target().session_id()
        || current.target().principal() != command.target().principal()
    {
        return Err(AgentAssignmentStoreError::TargetConflict);
    }
    let offer_actor = actor_for_assignment(current);
    validate_current_coordinator_live(transaction, offer_actor, admitted_at)?;
    let agent = workspace_agents::ensure_bound_attached_agent(
        transaction,
        current.workspace_id(),
        current.activity_id(),
        command.target().agent_id(),
        command.target().session_id(),
        command.target().principal(),
        Some(command.target().agent_revision()),
    )?;
    let goal = validate_goal_scope(
        transaction,
        current.workspace_id(),
        current.activity_id(),
        current.goal_id(),
        current.goal_revision(),
        current.goal_created_at(),
    )?;
    let _ = validate_dag_scope(
        transaction,
        &goal,
        current.dag_revision(),
        current.dag_head_revision(),
        current.node_id(),
        current.node_revision(),
        true,
    )?;
    validate_no_active_effects(
        transaction,
        current.workspace_id(),
        current.target().agent_id(),
    )?;
    Ok(agent)
}

fn start_claimed_node_and_focus(
    transaction: &Transaction<'_>,
    current: &RegisteredAgentAssignment,
    command: &ClaimAgentAssignment,
    agent: &forge_domain::RegisteredAgentInstance,
) -> Result<(), AgentAssignmentStoreError> {
    let scope = workspace_dags::DagTransitionScope::new(
        current.workspace_id(),
        current.activity_id(),
        current.goal_id(),
        current.goal_revision(),
        current.dag_revision(),
    );
    let transition = workspace_dags::DagNodeTransition::new(
        scope,
        current.node_id(),
        current.node_revision(),
        command.observed_at(),
    );
    let updated_node = workspace_dags::start_node_authorized_in_transaction(
        transaction,
        transition,
        command.target().session_id(),
        command.target().principal(),
    )?;
    if updated_node.revision() == current.node_revision() {
        return Err(AgentAssignmentStoreError::CorruptRecord(
            "assignment.claimed_node_revision",
        ));
    }
    let focus = forge_domain::AgentFocus::new(
        Some(forge_domain::GoalAttribution::new(
            current.goal_id(),
            current.goal_revision(),
        )),
        Some(current.dag_revision()),
        Some(forge_domain::AgentFocusNode::new(
            current.node_id(),
            updated_node.revision(),
        )),
    )?;
    let focus_command = forge_domain::SetAgentFocus::new(
        agent.id(),
        current.activity_id(),
        agent.revision(),
        focus,
        command.observed_at(),
    );
    let _focused = workspace_agents::set_focus_in_transaction(transaction, &focus_command)?;
    Ok(())
}

pub(crate) fn submit(
    connection: &mut Connection,
    command: &SubmitAgentAssignment,
    admitted_at: TimestampMillis,
) -> Result<RegisteredAgentAssignment, AgentAssignmentStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let current = get_in_transaction(&transaction, command.assignment_id())?.ok_or(
        AgentAssignmentStoreError::AssignmentNotFound(command.assignment_id()),
    )?;
    workspace_coordinators::ensure_live_activity_in_transaction(
        &transaction,
        current.activity_id(),
        current.workspace_id(),
        admitted_at,
    )?;
    ensure_target_endpoint(&current, command.target())?;
    let _agent = workspace_agents::ensure_bound_attached_agent(
        &transaction,
        current.workspace_id(),
        current.activity_id(),
        command.target().agent_id(),
        command.target().session_id(),
        command.target().principal(),
        Some(command.target().agent_revision()),
    )?;
    let updated = current.submit(
        command.target(),
        command.expected_revision(),
        command.result().clone(),
        command.observed_at(),
    )?;
    update_assignment(&transaction, &current, &updated)?;
    insert_sources(
        &transaction,
        updated.id(),
        current.goal_id(),
        command.result(),
    )?;
    let result = get_in_transaction(&transaction, updated.id())?.ok_or(
        AgentAssignmentStoreError::CorruptRecord("assignment.submitted"),
    )?;
    // The durable submitted-result receipt is part of the same transaction as
    // the assignment CAS and its source rows. A fact failure must roll back
    // the complete submit so a retry cannot observe a partial lifecycle.
    crate::workspace_effect_fact_outbox::append_assignment_submitted(&transaction, &result)?;
    transaction.commit()?;
    Ok(result)
}

pub(crate) fn accept(
    connection: &mut Connection,
    command: &ReviewAgentAssignment,
    admitted_at: TimestampMillis,
) -> Result<RegisteredAgentAssignment, AgentAssignmentStoreError> {
    review(connection, command, true, admitted_at)
}

pub(crate) fn reject(
    connection: &mut Connection,
    command: &ReviewAgentAssignment,
    admitted_at: TimestampMillis,
) -> Result<RegisteredAgentAssignment, AgentAssignmentStoreError> {
    review(connection, command, false, admitted_at)
}

fn review(
    connection: &mut Connection,
    command: &ReviewAgentAssignment,
    accepted: bool,
    admitted_at: TimestampMillis,
) -> Result<RegisteredAgentAssignment, AgentAssignmentStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let current = get_in_transaction(&transaction, command.assignment_id())?.ok_or(
        AgentAssignmentStoreError::AssignmentNotFound(command.assignment_id()),
    )?;
    validate_current_coordinator_live(&transaction, command.coordinator(), admitted_at)?;
    let updated = if accepted {
        current.accept(
            command.coordinator(),
            command.expected_revision(),
            command.observed_at(),
        )?
    } else {
        current.reject(
            command.coordinator(),
            command.expected_revision(),
            command.observed_at(),
        )?
    };
    update_assignment(&transaction, &current, &updated)?;
    let result = get_in_transaction(&transaction, updated.id())?.ok_or(
        AgentAssignmentStoreError::CorruptRecord("assignment.reviewed"),
    )?;
    // The durable review fact belongs to the same caller transaction as the
    // state CAS above; a fact failure rolls the review back with it.
    crate::workspace_effect_fact_outbox::append_assignment_reviewed(&transaction, &result)?;
    transaction.commit()?;
    Ok(result)
}

pub(crate) fn cancel(
    connection: &mut Connection,
    command: &CancelAgentAssignment,
) -> Result<RegisteredAgentAssignment, AgentAssignmentStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let current = get_in_transaction(&transaction, command.assignment_id())?.ok_or(
        AgentAssignmentStoreError::AssignmentNotFound(command.assignment_id()),
    )?;
    validate_current_coordinator(&transaction, command.coordinator())?;
    let updated = current.request_cancel(
        command.coordinator(),
        command.expected_revision(),
        command.observed_at(),
    )?;
    update_assignment(&transaction, &current, &updated)?;
    let result = get_in_transaction(&transaction, updated.id())?.ok_or(
        AgentAssignmentStoreError::CorruptRecord("assignment.cancelled"),
    )?;
    transaction.commit()?;
    Ok(result)
}

pub(crate) fn acknowledge_cancellation(
    connection: &mut Connection,
    command: &AcknowledgeAgentAssignmentCancellation,
) -> Result<RegisteredAgentAssignment, AgentAssignmentStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let current = get_in_transaction(&transaction, command.assignment_id())?.ok_or(
        AgentAssignmentStoreError::AssignmentNotFound(command.assignment_id()),
    )?;
    ensure_target_endpoint(&current, command.target())?;
    let _ = workspace_agents::ensure_bound_attached_agent(
        &transaction,
        current.workspace_id(),
        current.activity_id(),
        command.target().agent_id(),
        command.target().session_id(),
        command.target().principal(),
        Some(command.target().agent_revision()),
    )?;
    validate_no_active_effects(
        &transaction,
        current.workspace_id(),
        command.target().agent_id(),
    )?;
    let updated = current.acknowledge_cancel(
        command.target(),
        command.expected_revision(),
        command.observed_at(),
    )?;
    update_assignment(&transaction, &current, &updated)?;
    let result = get_in_transaction(&transaction, updated.id())?.ok_or(
        AgentAssignmentStoreError::CorruptRecord("assignment.cancel_ack"),
    )?;
    transaction.commit()?;
    Ok(result)
}

pub(crate) fn interrupt(
    connection: &mut Connection,
    command: &InterruptAgentAssignment,
) -> Result<RegisteredAgentAssignment, AgentAssignmentStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let current = get_in_transaction(&transaction, command.assignment_id())?.ok_or(
        AgentAssignmentStoreError::AssignmentNotFound(command.assignment_id()),
    )?;
    let updated = current.interrupt(command.expected_revision(), command.observed_at())?;
    update_assignment(&transaction, &current, &updated)?;
    let result = get_in_transaction(&transaction, updated.id())?.ok_or(
        AgentAssignmentStoreError::CorruptRecord("assignment.interrupted"),
    )?;
    transaction.commit()?;
    Ok(result)
}

fn actor_for_assignment(assignment: &RegisteredAgentAssignment) -> ActivityCoordinatorActor {
    ActivityCoordinatorActor::new(
        assignment.workspace_id(),
        assignment.activity_id(),
        assignment.coordinator().agent_id(),
        assignment.coordinator().revision(),
        assignment.coordinator().principal(),
        assignment.coordinator().session_id(),
    )
}

fn validate_current_coordinator(
    connection: &Connection,
    actor: ActivityCoordinatorActor,
) -> Result<(), AgentAssignmentStoreError> {
    let _ = workspace_coordinators::authorize_in_transaction(connection, actor)?;
    Ok(())
}

fn validate_current_coordinator_live(
    connection: &Connection,
    actor: ActivityCoordinatorActor,
    admitted_at: TimestampMillis,
) -> Result<(), AgentAssignmentStoreError> {
    let _ = workspace_coordinators::authorize_live_in_transaction(connection, actor, admitted_at)?;
    Ok(())
}

fn ensure_target_endpoint(
    assignment: &RegisteredAgentAssignment,
    target: AgentAssignmentTarget,
) -> Result<(), AgentAssignmentStoreError> {
    let expected = assignment.target();
    if expected.agent_id() != target.agent_id()
        || expected.session_id() != target.session_id()
        || expected.principal() != target.principal()
    {
        return Err(AgentAssignmentStoreError::TargetConflict);
    }
    Ok(())
}

fn validate_goal_scope(
    connection: &Connection,
    workspace_id: WorkspaceId,
    activity_id: forge_domain::ActivityId,
    goal_id: GoalId,
    expected_revision: GoalRevision,
    expected_created_at: TimestampMillis,
) -> Result<forge_domain::RegisteredGoal, AgentAssignmentStoreError> {
    let goal = workspace_goals::get_goal(connection, goal_id)?
        .ok_or(AgentAssignmentStoreError::GoalConflict)?;
    if goal.workspace_id() != workspace_id
        || goal.activity_id() != activity_id
        || goal.revision() != expected_revision
        || goal.timestamps().created_at() != expected_created_at
        || !matches!(
            goal.status().kind(),
            forge_domain::GoalStatusKind::Active | forge_domain::GoalStatusKind::Paused
        )
    {
        return Err(AgentAssignmentStoreError::GoalConflict);
    }
    Ok(goal)
}

fn validate_dag_scope(
    connection: &Connection,
    goal: &forge_domain::RegisteredGoal,
    expected_dag_revision: DagRevisionNumber,
    expected_head_revision: DagHeadRevision,
    node_id: DagNodeId,
    expected_node_revision: DagNodeRevision,
    require_pending: bool,
) -> Result<workspace_dags::StoredDagRevision, AgentAssignmentStoreError> {
    let current = workspace_dags::get_current_in_transaction(connection, goal.id())?
        .ok_or(AgentAssignmentStoreError::DagConflict)?;
    if current.revision().number() != expected_dag_revision
        || current.head().dag_revision() != expected_dag_revision
        || current.head().revision() != expected_head_revision
    {
        return Err(AgentAssignmentStoreError::DagConflict);
    }
    let node = current
        .nodes()
        .iter()
        .find(|node| node.id() == node_id)
        .ok_or(AgentAssignmentStoreError::NodeConflict)?;
    if node.revision() != expected_node_revision
        || (require_pending && node.lifecycle() != &forge_domain::DagNodeLifecycle::Pending)
    {
        return Err(AgentAssignmentStoreError::NodeConflict);
    }
    Ok(current)
}

fn validate_no_active_effects(
    connection: &Connection,
    workspace_id: WorkspaceId,
    agent_id: AgentInstanceId,
) -> Result<(), AgentAssignmentStoreError> {
    let workspace = workspace_id.into_uuid().into_bytes();
    let agent = agent_id.into_uuid().into_bytes();
    let active_writer: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM writer_leases WHERE workspace_id = ?1 AND agent_id = ?2 AND state = 0)",
        params![workspace.as_slice(), agent.as_slice()],
        |row| row.get(0),
    )?;
    let active_execution: bool = connection.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM execution_provenance AS p
             JOIN executions AS e ON e.execution_id = p.execution_id
             WHERE p.agent_id = ?1 AND e.workspace_id = ?2 AND e.state IN (0, 1)
         )",
        params![agent.as_slice(), workspace.as_slice()],
        |row| row.get(0),
    )?;
    if active_writer || active_execution {
        return Err(AgentAssignmentStoreError::NoActiveEffects);
    }
    Ok(())
}

fn insert_assignment(
    transaction: &Transaction<'_>,
    assignment: &RegisteredAgentAssignment,
) -> Result<(), AgentAssignmentStoreError> {
    ensure_ordinary_origin(assignment)?;
    let assignment_id = assignment.id().into_uuid().into_bytes();
    let workspace_id = assignment.workspace_id().into_uuid().into_bytes();
    let activity_id = assignment.activity_id().into_uuid().into_bytes();
    let goal_id = assignment.goal_id().into_uuid().into_bytes();
    let node_id = assignment.node_id().into_uuid().into_bytes();
    let coordinator_agent_id = assignment.coordinator().agent_id().into_uuid().into_bytes();
    let coordinator_session_id = assignment
        .coordinator()
        .session_id()
        .into_uuid()
        .into_bytes();
    let target_agent_id = assignment.target().agent_id().into_uuid().into_bytes();
    let target_session_id = assignment.target().session_id().into_uuid().into_bytes();
    let (coordinator_kind, coordinator_principal) =
        encode_principal(assignment.coordinator().principal());
    let (target_kind, target_principal) = encode_principal(assignment.target().principal());
    let result = assignment.result();
    let report = result.map(|result| result.report().to_owned());
    let worktree_root = result.and_then(|result| {
        result
            .worktree()
            .map(|receipt| receipt.root_fingerprint().into_bytes().to_vec())
    });
    let worktree_repository = result.and_then(|result| {
        result
            .worktree()
            .map(|receipt| receipt.repository_fingerprint().into_bytes().to_vec())
    });
    let worktree_baseline = result.and_then(|result| {
        result
            .worktree()
            .map(|receipt| receipt.baseline().object_id().as_bytes().to_vec())
    });
    let review = assignment.reviewed_by();
    let reviewed_agent_id =
        review.map(|review| review.agent_id().into_uuid().into_bytes().to_vec());
    let reviewed_session_id =
        review.map(|review| review.session_id().into_uuid().into_bytes().to_vec());
    let reviewed_principal_kind = review.map(|review| encode_principal(review.principal()).0);
    let reviewed_principal_id = review.and_then(|review| encode_principal(review.principal()).1);
    let reviewed_revision = review.map(|review| review.revision().get());
    let state = encode_state(assignment.state());
    let cancellation_requested = encode_bool(assignment.cancellation_requested());
    transaction.execute(
        "INSERT INTO agent_assignments (
            assignment_id, workspace_id, activity_id, goal_id, goal_created_at_ms, goal_revision,
            dag_revision, dag_head_revision, node_id, node_revision,
            coordinator_agent_id, coordinator_session_id, coordinator_principal_kind,
            coordinator_principal_id, coordinator_revision, target_agent_id, target_session_id,
            target_principal_kind, target_principal_id, target_agent_revision, state,
            cancellation_requested, report, worktree_root_fingerprint,
            worktree_repository_fingerprint, worktree_baseline, reviewed_agent_id,
            reviewed_session_id, reviewed_principal_kind, reviewed_principal_id, reviewed_revision,
            created_at_ms, updated_at_ms, revision, credit_budget
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15,
            ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28,
            ?29, ?30, ?31, ?32, ?33, ?34, ?35
         )",
        params![
            assignment_id.as_slice(),
            workspace_id.as_slice(),
            activity_id.as_slice(),
            goal_id.as_slice(),
            assignment.goal_created_at().get(),
            assignment.goal_revision().get(),
            assignment.dag_revision().get(),
            assignment.dag_head_revision().get(),
            node_id.as_slice(),
            assignment.node_revision().get(),
            coordinator_agent_id.as_slice(),
            coordinator_session_id.as_slice(),
            coordinator_kind,
            coordinator_principal,
            assignment.coordinator().revision().get(),
            target_agent_id.as_slice(),
            target_session_id.as_slice(),
            target_kind,
            target_principal,
            assignment.target().agent_revision().get(),
            state,
            cancellation_requested,
            report,
            worktree_root,
            worktree_repository,
            worktree_baseline,
            reviewed_agent_id,
            reviewed_session_id,
            reviewed_principal_kind,
            reviewed_principal_id,
            reviewed_revision,
            assignment.created_at().get(),
            assignment.updated_at().get(),
            assignment.revision().get(),
            assignment.credit_budget().map(WorkCreditBudget::value),
        ],
    )?;
    Ok(())
}

fn ensure_ordinary_origin(
    assignment: &RegisteredAgentAssignment,
) -> Result<(), AgentAssignmentStoreError> {
    if assignment.origin() != forge_domain::AgentAssignmentOrigin::CoordinatorOffer {
        return Err(AgentAssignmentTransitionError::ContinuationAuthorityRequired.into());
    }
    Ok(())
}

fn update_assignment(
    transaction: &Transaction<'_>,
    current: &RegisteredAgentAssignment,
    updated: &RegisteredAgentAssignment,
) -> Result<(), AgentAssignmentStoreError> {
    ensure_ordinary_origin(current)?;
    ensure_ordinary_origin(updated)?;
    let (coordinator_kind, coordinator_principal) =
        encode_principal(updated.coordinator().principal());
    let (target_kind, target_principal) = encode_principal(updated.target().principal());
    let changed = transaction.execute(
        "UPDATE agent_assignments SET state = ?1, cancellation_requested = ?2,
            report = ?3, worktree_root_fingerprint = ?4, worktree_repository_fingerprint = ?5,
            worktree_baseline = ?6, reviewed_agent_id = ?7, reviewed_session_id = ?8,
            reviewed_principal_kind = ?9, reviewed_principal_id = ?10, reviewed_revision = ?11,
            updated_at_ms = ?12, revision = ?13
         WHERE assignment_id = ?14 AND revision = ?15",
        params![
            encode_state(updated.state()),
            encode_bool(updated.cancellation_requested()),
            updated.result().map(AgentAssignmentResult::report),
            updated.result().and_then(|result| result
                .worktree()
                .map(|receipt| receipt.root_fingerprint().into_bytes().to_vec())),
            updated.result().and_then(|result| result
                .worktree()
                .map(|receipt| receipt.repository_fingerprint().into_bytes().to_vec())),
            updated
                .result()
                .and_then(|result| result.worktree().map(|receipt| receipt
                    .baseline()
                    .object_id()
                    .as_bytes()
                    .to_vec())),
            updated
                .reviewed_by()
                .map(|review| review.agent_id().into_uuid().into_bytes().to_vec()),
            updated.reviewed_by().map(|review| review
                .session_id()
                .into_uuid()
                .into_bytes()
                .to_vec()),
            updated
                .reviewed_by()
                .map(|review| encode_principal(review.principal()).0),
            updated
                .reviewed_by()
                .and_then(|review| encode_principal(review.principal()).1),
            updated.reviewed_by().map(|review| review.revision().get()),
            updated.updated_at().get(),
            updated.revision().get(),
            updated.id().into_uuid().as_bytes(),
            current.revision().get(),
        ],
    )?;
    if changed != 1 {
        return Err(AgentAssignmentStoreError::RevisionConflict);
    }
    let _ = (
        coordinator_kind,
        coordinator_principal,
        target_kind,
        target_principal,
    );
    Ok(())
}

fn insert_sources(
    transaction: &Transaction<'_>,
    assignment_id: AgentAssignmentId,
    goal_id: GoalId,
    result: &AgentAssignmentResult,
) -> Result<(), AgentAssignmentStoreError> {
    for (ordinal, source) in result.sources().iter().enumerate() {
        let ordinal =
            i64::try_from(ordinal).map_err(|_| AgentAssignmentStoreError::IntegerOverflow)?;
        let (kind, url, provenance_kind, provenance_id) = match source {
            AgentAssignmentSourceRef::Url(url) => (0_i64, Some(url.as_str()), None, None),
            AgentAssignmentSourceRef::Provenance(evidence) => {
                let (evidence_kind, evidence_id) = encode_evidence(*evidence);
                let linked: bool = transaction.query_row(
                    "SELECT EXISTS(
                         SELECT 1 FROM goal_evidence_refs
                         WHERE goal_id = ?1 AND evidence_kind = ?2 AND evidence_id = ?3
                     )",
                    params![
                        goal_id.into_uuid().as_bytes(),
                        evidence_kind,
                        evidence_id.as_slice(),
                    ],
                    |row| row.get(0),
                )?;
                if !linked {
                    return Err(AgentAssignmentStoreError::EvidenceMissing(*evidence));
                }
                let (kind, id) = encode_evidence(*evidence);
                (1_i64, None, Some(kind), Some(id))
            }
        };
        transaction.execute(
            "INSERT INTO agent_assignment_sources (
                assignment_id, ordinal, source_kind, source_url, provenance_kind, provenance_id
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                assignment_id.into_uuid().as_bytes(),
                ordinal,
                kind,
                url,
                provenance_kind,
                provenance_id,
            ],
        )?;
    }
    Ok(())
}

fn encode_principal(value: AuthenticatedPrincipal) -> (i64, Option<Vec<u8>>) {
    match value {
        AuthenticatedPrincipal::TrustedStdio => (0, None),
        AuthenticatedPrincipal::DirectToken(id) => (1, Some(id.into_uuid().into_bytes().to_vec())),
        AuthenticatedPrincipal::OAuthGrant(id) => (2, Some(id.into_uuid().into_bytes().to_vec())),
    }
}

fn decode_principal(
    kind: i64,
    id: Option<&[u8]>,
) -> Result<AuthenticatedPrincipal, AgentAssignmentStoreError> {
    match (kind, id) {
        (0, None) => Ok(AuthenticatedPrincipal::TrustedStdio),
        (1, Some(id)) => Ok(AuthenticatedPrincipal::DirectToken(
            forge_domain::DirectTokenId::from_uuid(decode_uuid("assignment.principal_id", id)?),
        )),
        (2, Some(id)) => Ok(AuthenticatedPrincipal::OAuthGrant(
            forge_domain::OAuthGrantId::from_uuid(decode_uuid("assignment.principal_id", id)?),
        )),
        _ => Err(AgentAssignmentStoreError::CorruptRecord(
            "assignment.principal",
        )),
    }
}

fn encode_evidence(evidence: GoalEvidenceRef) -> (i64, Vec<u8>) {
    match evidence {
        GoalEvidenceRef::ChangeSet(id) => (0, id.into_uuid().into_bytes().to_vec()),
        GoalEvidenceRef::Execution(id) => (1, id.into_uuid().into_bytes().to_vec()),
        GoalEvidenceRef::Approval(id) => (2, id.into_uuid().into_bytes().to_vec()),
        GoalEvidenceRef::Checkpoint(id) => (3, id.into_uuid().into_bytes().to_vec()),
    }
}

fn decode_evidence(kind: i64, id: &[u8]) -> Result<GoalEvidenceRef, AgentAssignmentStoreError> {
    let id = decode_uuid("assignment.provenance_id", id)?;
    match kind {
        0 => Ok(GoalEvidenceRef::ChangeSet(
            forge_domain::ChangeSetId::from_uuid(id),
        )),
        1 => Ok(GoalEvidenceRef::Execution(
            forge_domain::ExecutionId::from_uuid(id),
        )),
        2 => Ok(GoalEvidenceRef::Approval(
            forge_domain::ApprovalRequestId::from_uuid(id),
        )),
        3 => Ok(GoalEvidenceRef::Checkpoint(
            forge_domain::CheckpointId::from_uuid(id),
        )),
        _ => Err(AgentAssignmentStoreError::CorruptRecord(
            "assignment.provenance_kind",
        )),
    }
}

fn encode_state(state: AgentAssignmentState) -> i64 {
    match state {
        AgentAssignmentState::Offered => 0,
        AgentAssignmentState::Running => 1,
        AgentAssignmentState::Submitted => 2,
        AgentAssignmentState::Accepted => 3,
        AgentAssignmentState::Rejected => 4,
        AgentAssignmentState::Cancelled => 5,
        AgentAssignmentState::Interrupted => 6,
    }
}

fn decode_state(value: i64) -> Result<AgentAssignmentState, AgentAssignmentStoreError> {
    match value {
        0 => Ok(AgentAssignmentState::Offered),
        1 => Ok(AgentAssignmentState::Running),
        2 => Ok(AgentAssignmentState::Submitted),
        3 => Ok(AgentAssignmentState::Accepted),
        4 => Ok(AgentAssignmentState::Rejected),
        5 => Ok(AgentAssignmentState::Cancelled),
        6 => Ok(AgentAssignmentState::Interrupted),
        _ => Err(AgentAssignmentStoreError::CorruptRecord("assignment.state")),
    }
}

fn encode_bool(value: bool) -> i64 {
    i64::from(value)
}

fn decode_bool(field: &'static str, value: i64) -> Result<bool, AgentAssignmentStoreError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(AgentAssignmentStoreError::CorruptRecord(field)),
    }
}

fn decode_credit_budget(
    value: Option<i64>,
) -> Result<Option<WorkCreditBudget>, AgentAssignmentStoreError> {
    value
        .map(WorkCreditBudget::try_from_i64)
        .transpose()
        .map_err(|_| AgentAssignmentStoreError::CorruptRecord("assignment.credit_budget"))
}

fn decode_uuid(field: &'static str, value: &[u8]) -> Result<Uuid, AgentAssignmentStoreError> {
    if value.len() != ID_BYTES {
        return Err(AgentAssignmentStoreError::InvalidFieldLength {
            field,
            actual: value.len(),
            expected: ID_BYTES,
        });
    }
    Uuid::from_slice(value).map_err(|_| AgentAssignmentStoreError::CorruptRecord(field))
}

fn decode_fixed_bytes<const N: usize>(
    field: &'static str,
    value: &[u8],
    expected: usize,
) -> Result<[u8; N], AgentAssignmentStoreError> {
    if value.len() != expected {
        return Err(AgentAssignmentStoreError::InvalidFieldLength {
            field,
            actual: value.len(),
            expected,
        });
    }
    value
        .try_into()
        .map_err(|_| AgentAssignmentStoreError::CorruptRecord(field))
}

fn decode_fingerprint(
    field: &'static str,
    value: &[u8],
) -> Result<forge_domain::WorkspaceRootFingerprint, AgentAssignmentStoreError> {
    Ok(forge_domain::WorkspaceRootFingerprint::from_bytes(
        decode_fixed_bytes(field, value, ID_BYTES)?,
    ))
}

fn decode_timestamp(
    field: &'static str,
    value: i64,
) -> Result<TimestampMillis, AgentAssignmentStoreError> {
    TimestampMillis::new(value).map_err(|_| AgentAssignmentStoreError::CorruptRecord(field))
}

fn decode_agent_revision(value: i64) -> Result<AgentInstanceRevision, AgentAssignmentStoreError> {
    AgentInstanceRevision::new(value)
        .map_err(|_| AgentAssignmentStoreError::CorruptRecord("assignment.agent_revision"))
}

fn decode_activity_coordinator_revision(
    value: i64,
) -> Result<forge_domain::ActivityCoordinatorRevision, AgentAssignmentStoreError> {
    forge_domain::ActivityCoordinatorRevision::new(value)
        .map_err(|_| AgentAssignmentStoreError::CorruptRecord("assignment.coordinator_revision"))
}

fn decode_assignment_revision(
    value: i64,
) -> Result<AgentAssignmentRevision, AgentAssignmentStoreError> {
    AgentAssignmentRevision::new(value)
        .map_err(|_| AgentAssignmentStoreError::CorruptRecord("assignment.revision"))
}

fn decode_goal_revision(value: i64) -> Result<GoalRevision, AgentAssignmentStoreError> {
    GoalRevision::new(value)
        .map_err(|_| AgentAssignmentStoreError::CorruptRecord("assignment.goal_revision"))
}

fn decode_dag_revision(value: i64) -> Result<DagRevisionNumber, AgentAssignmentStoreError> {
    DagRevisionNumber::new(value)
        .map_err(|_| AgentAssignmentStoreError::CorruptRecord("assignment.dag_revision"))
}

fn decode_dag_head_revision(value: i64) -> Result<DagHeadRevision, AgentAssignmentStoreError> {
    DagHeadRevision::new(value)
        .map_err(|_| AgentAssignmentStoreError::CorruptRecord("assignment.dag_head_revision"))
}

fn decode_dag_node_revision(value: i64) -> Result<DagNodeRevision, AgentAssignmentStoreError> {
    DagNodeRevision::new(value)
        .map_err(|_| AgentAssignmentStoreError::CorruptRecord("assignment.node_revision"))
}

#[derive(Debug, Error)]
pub enum AgentAssignmentStoreError {
    #[error(transparent)]
    WorkCut(#[from] Box<crate::WorkCutError>),
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Agent(#[from] AgentStoreError),
    #[error(transparent)]
    Coordinator(#[from] CoordinatorStoreError),
    #[error(transparent)]
    Dag(#[from] DagStoreError),
    #[error(transparent)]
    Goal(#[from] GoalStoreError),
    #[error(transparent)]
    Transition(#[from] AgentAssignmentTransitionError),
    #[error(transparent)]
    Result(#[from] AgentAssignmentResultError),
    #[error(transparent)]
    Source(#[from] forge_domain::AgentAssignmentSourceError),
    #[error(transparent)]
    Focus(#[from] forge_domain::AgentFocusError),
    #[error(transparent)]
    EffectFact(#[from] crate::EffectFactOutboxError),
    #[error("Agent assignment {0} was not found")]
    AssignmentNotFound(AgentAssignmentId),
    #[error("Agent assignment identity conflicts with durable state")]
    IdentityConflict,
    #[error(
        "Agent assignment offer is sealed for Activity {activity_id} and Assignment {assignment_id}"
    )]
    OfferAdmissionSealed {
        activity_id: ActivityId,
        assignment_id: AgentAssignmentId,
    },
    #[error("Agent assignment offer-seal identity is invalid")]
    InvalidOfferSealIdentity,
    #[error(
        "Agent assignment offer-seal commit is unconfirmed for Workspace {workspace_id}, Activity {activity_id}, Assignment {assignment_id}: {source}"
    )]
    OfferSealCommitUnconfirmed {
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        assignment_id: AgentAssignmentId,
        #[source]
        source: Box<rusqlite::Error>,
    },
    #[error(
        "Agent assignment offer commit is unconfirmed for Workspace {workspace_id}, Activity {activity_id}, Assignment {assignment_id}: {source}"
    )]
    OfferCommitUnconfirmed {
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        assignment_id: AgentAssignmentId,
        #[source]
        source: Box<rusqlite::Error>,
    },
    #[error("Agent assignment Workspace conflicts")]
    WorkspaceMismatch,
    #[error("Agent assignment Activity conflicts")]
    ActivityMismatch,
    #[error("Agent assignment Coordinator is missing")]
    CoordinatorMissing,
    #[error("Agent assignment Coordinator fence conflicts")]
    CoordinatorFenceConflict,
    #[error("Agent assignment Coordinator and target must be distinct")]
    CoordinatorTargetSameAgent,
    #[error("Agent assignment target conflicts")]
    TargetConflict,
    #[error("Agent assignment target revision conflicts")]
    TargetRevisionConflict,
    #[error("Agent assignment Goal fence conflicts")]
    GoalConflict,
    #[error("Agent assignment DAG fence conflicts")]
    DagConflict,
    #[error("Agent assignment DAG node conflicts")]
    NodeConflict,
    #[error("Agent assignment target has active effects")]
    NoActiveEffects,
    #[error("Workspace has reached the active assignment bound")]
    ActiveLimit,
    #[error("Agent assignment revision conflicts")]
    RevisionConflict,
    #[error("Agent assignment has too many source references")]
    TooManySources,
    #[error("Agent assignment source evidence is not linked to its Goal: {0:?}")]
    EvidenceMissing(GoalEvidenceRef),
    #[error("Agent assignment integer value overflowed")]
    IntegerOverflow,
    #[error("Agent assignment persisted field {field} has {actual} bytes; expected {expected}")]
    InvalidFieldLength {
        field: &'static str,
        actual: usize,
        expected: usize,
    },
    #[error("Agent assignment record is corrupt: {0}")]
    CorruptRecord(&'static str),
    #[error("Agent assignment schema object is damaged: {0}")]
    DamagedSchema(&'static str),
    #[error("Agent assignment schema SQL object {object} is {actual} bytes; maximum is {maximum}")]
    SchemaSqlTooLarge {
        object: &'static str,
        actual: usize,
        maximum: usize,
    },
    #[error("Agent assignment schema metadata exceeded its bound for {object}")]
    SchemaMetadataTooLarge { object: &'static str },
}

impl From<crate::WorkCutError> for AgentAssignmentStoreError {
    fn from(error: crate::WorkCutError) -> Self {
        Self::WorkCut(Box::new(error))
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use forge_domain::{
        AcknowledgeAgentAssignmentCancellation, ActivityCoordinatorActor, ActivityId,
        AgentAssignmentId, AgentAssignmentResult, AgentAssignmentSourceRef,
        AgentAssignmentSourceUrl, AgentAssignmentState, AgentAssignmentTarget, AgentDeclaredRole,
        AgentDisplayName, AgentInstanceId, AgentSessionId, AgentTransportKind,
        AuthenticatedPrincipal, BootstrapActivity, CancelAgentAssignment, ClaimActivityCoordinator,
        ClaimAgentAssignment, CloseActivity, DagAcceptanceCriterion, DagHeadRevision,
        DagNodeDefinition, DagNodeId, DagNodeObjective, DagNodeOrdinal, DagNodeTitle, DagRevision,
        DagRevisionId, DagRevisionNumber, EstablishWorkspace, GoalContract, GoalId, GoalObjective,
        GoalRevision, GoalStatement, LocationId, OfferAgentAssignment, RegisteredAgentInstance,
        RegisteredDagNode, RegisteredGoal, RuntimeInstanceId, SubmitAgentAssignment,
        TimestampMillis, WorkspaceId, WorkspaceRevision, WorkspaceRoot,
    };
    use forge_workspace::WorkspaceStateLayout;
    use sha2::Digest;
    use uuid::Uuid;

    use crate::{AgentAssignmentStoreError, WorkspaceStore, WorkspaceStoreError};

    use super::*;

    #[test]
    fn schema_round_trips_and_rejects_missing_index() -> Result<(), Box<dyn std::error::Error>> {
        let connection = Connection::open_in_memory()?;
        connection.pragma_update(None, "foreign_keys", true)?;
        create_schema(&connection)?;
        create_offer_seal_schema(&connection)?;
        validate_schema(&connection)?;
        connection.execute_batch("DROP INDEX agent_assignments_active_agent_idx;")?;
        assert!(matches!(
            validate_schema(&connection),
            Err(AgentAssignmentStoreError::DamagedSchema(
                "agent_assignments_active_agent_idx"
            ))
        ));
        Ok(())
    }

    struct AssignmentFixture {
        root: PathBuf,
        layout: WorkspaceStateLayout,
        store: WorkspaceStore,
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        coordinator: ActivityCoordinatorActor,
        coordinator_agent: RegisteredAgentInstance,
        target_a: RegisteredAgentInstance,
        target_b: RegisteredAgentInstance,
        goal: RegisteredGoal,
        nodes: [RegisteredDagNode; 2],
    }

    fn ts(value: i64) -> Result<TimestampMillis, Box<dyn std::error::Error>> {
        Ok(TimestampMillis::new(value)?)
    }

    fn admitted_at() -> Result<TimestampMillis, Box<dyn std::error::Error>> {
        ts(100)
    }

    fn seed_goal_and_nodes(
        store: &mut WorkspaceStore,
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        coordinator: ActivityCoordinatorActor,
    ) -> Result<(RegisteredGoal, [RegisteredDagNode; 2]), Box<dyn std::error::Error>> {
        seed_goal_and_nodes_with_ids(store, workspace_id, activity_id, coordinator, 0xA240)
    }

    fn seed_goal_and_nodes_with_ids(
        store: &mut WorkspaceStore,
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        coordinator: ActivityCoordinatorActor,
        id_base: u128,
    ) -> Result<(RegisteredGoal, [RegisteredDagNode; 2]), Box<dyn std::error::Error>> {
        let goal = RegisteredGoal::create(
            GoalId::from_uuid(Uuid::from_u128(id_base)),
            workspace_id,
            activity_id,
            GoalContract::new(
                GoalObjective::new("Coordinate connected participant work".to_owned())?,
                vec![GoalStatement::new(
                    "The participant reports a bounded result".to_owned(),
                )?],
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            )?,
            ts(7)?,
        );
        let goal = store.insert_goal(coordinator, &goal, admitted_at()?)?;
        let definitions = [
            DagNodeDefinition::new(
                DagNodeId::from_uuid(Uuid::from_u128(id_base + 0x10)),
                DagNodeOrdinal::new(0)?,
                DagNodeTitle::new("Research A".to_owned())?,
                DagNodeObjective::new("Research one bounded source".to_owned())?,
                vec![DagAcceptanceCriterion::new("A report exists".to_owned())?],
            )?,
            DagNodeDefinition::new(
                DagNodeId::from_uuid(Uuid::from_u128(id_base + 0x11)),
                DagNodeOrdinal::new(1)?,
                DagNodeTitle::new("Research B".to_owned())?,
                DagNodeObjective::new("Research another bounded source".to_owned())?,
                vec![DagAcceptanceCriterion::new("B report exists".to_owned())?],
            )?,
        ];
        let dag = DagRevision::new(
            DagRevisionId::from_uuid(Uuid::from_u128(id_base + 0x20)),
            goal.id(),
            goal.revision(),
            DagRevisionNumber::INITIAL,
            None,
            definitions.to_vec(),
            Vec::new(),
            ts(8)?,
        )?;
        let nodes = [
            RegisteredDagNode::create(goal.id(), dag.number(), definitions[0].clone(), ts(8)?),
            RegisteredDagNode::create(goal.id(), dag.number(), definitions[1].clone(), ts(8)?),
        ];
        let _ = store.insert_dag_revision(&dag, &nodes, &[], None)?;
        Ok((goal, nodes))
    }

    fn fixture() -> Result<AssignmentFixture, Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "forge-assignment-e2e-{}-{}",
            std::process::id(),
            Uuid::now_v7(),
        ));
        fs::create_dir(&root)?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(0xA200));
        let activity_id = ActivityId::from_uuid(Uuid::from_u128(0xA201));
        let location_id = LocationId::from_uuid(Uuid::from_u128(0xA202));
        let command = EstablishWorkspace::new(
            workspace_id,
            location_id,
            WorkspaceRoot::from_canonical(layout.workspace_root().to_path_buf())?,
            layout.root_fingerprint()?,
            ts(1)?,
        );
        let mut store = WorkspaceStore::open(&layout, &command)?;
        store.bootstrap_activity(&BootstrapActivity::new(
            activity_id,
            workspace_id,
            WorkspaceRevision::INITIAL,
            RuntimeInstanceId::from_uuid(Uuid::from_u128(0xA2FF)),
            ts(101)?,
            ts(2)?,
        ))?;
        let principal = AuthenticatedPrincipal::TrustedStdio;
        let coordinator_agent = bound_agent(0xA210, workspace_id, activity_id, ts(3)?, principal)?;
        let target_a = bound_agent(0xA220, workspace_id, activity_id, ts(4)?, principal)?;
        let target_b = bound_agent(0xA230, workspace_id, activity_id, ts(5)?, principal)?;
        let seed_connection = Connection::open(layout.database_path())?;
        seed_connection.pragma_update(None, "foreign_keys", true)?;
        crate::legacy_agent_seed::seed_agent(
            &seed_connection,
            &coordinator_agent,
            Some(crate::workspace_agent_events::derived_event_id(
                coordinator_agent.id(),
                coordinator_agent.revision(),
                forge_domain::AgentEventKind::Joined,
            )),
        )?;
        crate::legacy_agent_seed::seed_agent(
            &seed_connection,
            &target_a,
            Some(crate::workspace_agent_events::derived_event_id(
                target_a.id(),
                target_a.revision(),
                forge_domain::AgentEventKind::Joined,
            )),
        )?;
        crate::legacy_agent_seed::seed_agent(
            &seed_connection,
            &target_b,
            Some(crate::workspace_agent_events::derived_event_id(
                target_b.id(),
                target_b.revision(),
                forge_domain::AgentEventKind::Joined,
            )),
        )?;
        drop(seed_connection);
        let binding = store.claim_activity_coordinator(
            ClaimActivityCoordinator::new(
                workspace_id,
                activity_id,
                coordinator_agent.id(),
                principal,
                ts(6)?,
                coordinator_agent
                    .session_id()
                    .ok_or("coordinator session missing")?,
            ),
            admitted_at()?,
        )?;
        let coordinator = ActivityCoordinatorActor::new(
            workspace_id,
            activity_id,
            coordinator_agent.id(),
            binding.revision(),
            principal,
            coordinator_agent
                .session_id()
                .ok_or("coordinator session missing")?,
        );
        let (goal, nodes) =
            seed_goal_and_nodes(&mut store, workspace_id, activity_id, coordinator)?;
        Ok(AssignmentFixture {
            root,
            layout,
            store,
            workspace_id,
            activity_id,
            coordinator,
            coordinator_agent,
            target_a,
            target_b,
            goal,
            nodes,
        })
    }

    #[test]
    fn expired_exact_offer_replay_is_blocked_while_assignment_readback_remains_available()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = fixture()?;
        let offer = offer_command(
            &fixture,
            0xA260,
            target(&fixture.target_a),
            &fixture.nodes[0],
            10,
        );
        let offered = fixture
            .store
            .offer_agent_assignment(&offer, admitted_at()?)?;

        let replay = fixture.store.offer_agent_assignment(&offer, ts(101)?);
        assert!(matches!(
            replay,
            Err(WorkspaceStoreError::AgentAssignment(
                AgentAssignmentStoreError::Coordinator(
                    CoordinatorStoreError::ActivityLeaseNotLive(activity_id)
                )
            )) if activity_id == fixture.activity_id
        ));
        assert_eq!(
            fixture.store.get_agent_assignment(offer.assignment_id())?,
            Some(offered)
        );
        assert!(fixture.store.effect_fact_outbox(0, 64)?.is_empty());
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn expired_activity_blocks_coordinator_dag_commit_before_ledger_write()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = fixture()?;
        let goal_id = GoalId::from_uuid(Uuid::from_u128(0xA261));
        let definition = DagNodeDefinition::new(
            DagNodeId::from_uuid(Uuid::from_u128(0xA265)),
            DagNodeOrdinal::new(0)?,
            DagNodeTitle::new("Expired plan node".to_owned())?,
            DagNodeObjective::new("Must not be admitted after lease expiry".to_owned())?,
            vec![DagAcceptanceCriterion::new("The plan is live".to_owned())?],
        )?;
        let revision = DagRevision::new(
            DagRevisionId::from_uuid(Uuid::from_u128(0xA262)),
            goal_id,
            GoalRevision::INITIAL,
            DagRevisionNumber::INITIAL,
            None,
            vec![definition.clone()],
            Vec::new(),
            ts(0)?,
        )?;
        let node =
            RegisteredDagNode::create(goal_id, DagRevisionNumber::INITIAL, definition, ts(0)?);
        let draft = forge_domain::AgentDagDraft::new(revision, vec![node], Vec::new())?;
        let request = forge_domain::AgentDagPlanRequest::new(
            forge_domain::AgentDagPlanRequestId::from_uuid(Uuid::from_u128(0xA263)),
            fixture.coordinator,
            forge_domain::GoalAttribution::new(goal_id, GoalRevision::INITIAL),
            None,
            None,
            draft,
            forge_domain::AgentWorkUpdateId::from_uuid(Uuid::from_u128(0xA264)),
            forge_domain::AgentWorkUpdateSequence::INITIAL,
            ts(0)?,
        );

        assert!(matches!(
            fixture
                .store
                .commit_coordinator_dag_plan(&request, ts(101)?),
            Err(WorkspaceStoreError::AgentDag(
                crate::AgentDagStoreError::Coordinator(
                    CoordinatorStoreError::ActivityLeaseNotLive(activity_id)
                )
            )) if activity_id == fixture.activity_id
        ));
        let connection = Connection::open(fixture.layout.database_path())?;
        let rows: i64 = connection.query_row(
            "SELECT COUNT(*) FROM agent_dag_plan_ledger WHERE request_id = ?1",
            params![request.id().into_uuid().as_bytes()],
            |row| row.get(0),
        )?;
        assert_eq!(rows, 0);
        drop(connection);
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn expired_activity_blocks_agent_dag_node_start_complete_and_update()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = fixture()?;
        let before = fixture
            .store
            .get_current_dag(fixture.goal.id())?
            .ok_or("initial DAG missing")?;
        let node = &fixture.nodes[0];
        let scope = crate::DagTransitionScope::new(
            fixture.workspace_id,
            fixture.activity_id,
            fixture.goal.id(),
            fixture.goal.revision(),
            node.dag_revision(),
        );
        let transition = crate::DagNodeTransition::new(scope, node.id(), node.revision(), ts(0)?);
        let session_id = fixture
            .target_a
            .session_id()
            .ok_or("target Agent session missing")?;

        assert!(matches!(
            fixture.store.start_dag_node_authorized(
                transition,
                session_id,
                fixture.target_a.principal(),
                ts(101)?,
            ),
            Err(WorkspaceStoreError::Dag(crate::DagStoreError::Coordinator(
                CoordinatorStoreError::ActivityLeaseNotLive(activity_id)
            ))) if activity_id == fixture.activity_id
        ));
        assert!(matches!(
            fixture.store.complete_dag_node_authorized(
                transition,
                session_id,
                fixture.target_a.principal(),
                ts(101)?,
            ),
            Err(WorkspaceStoreError::Dag(crate::DagStoreError::Coordinator(
                CoordinatorStoreError::ActivityLeaseNotLive(activity_id)
            ))) if activity_id == fixture.activity_id
        ));
        assert!(matches!(
            fixture
                .store
                .update_dag_node(node, node.revision(), ts(101)?),
            Err(WorkspaceStoreError::Dag(crate::DagStoreError::Coordinator(
                CoordinatorStoreError::ActivityLeaseNotLive(activity_id)
            ))) if activity_id == fixture.activity_id
        ));
        assert_eq!(
            fixture.store.get_current_dag(fixture.goal.id())?,
            Some(before),
            "expired Agent writes must leave the DAG projection unchanged"
        );
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    fn bound_agent(
        value: u128,
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        observed_at: TimestampMillis,
        principal: AuthenticatedPrincipal,
    ) -> Result<RegisteredAgentInstance, Box<dyn std::error::Error>> {
        Ok(RegisteredAgentInstance::create_bound(
            AgentInstanceId::from_uuid(Uuid::from_u128(value)),
            workspace_id,
            activity_id,
            AgentSessionId::from_uuid(Uuid::from_u128(value + 0x5000)),
            AgentDisplayName::new(format!("Connected {value}"))?,
            AgentDeclaredRole::new("participant".to_owned())?,
            AgentTransportKind::Stdio,
            principal,
            observed_at,
        ))
    }

    fn target(agent: &RegisteredAgentInstance) -> AgentAssignmentTarget {
        AgentAssignmentTarget::new(
            agent.id(),
            agent
                .session_id()
                .unwrap_or_else(|| unreachable!("fixture agent has a session")),
            agent.principal(),
            agent.revision(),
        )
    }

    fn offer_command(
        fixture: &AssignmentFixture,
        assignment_id: u128,
        target: AgentAssignmentTarget,
        node: &RegisteredDagNode,
        observed_at: i64,
    ) -> OfferAgentAssignment {
        offer_command_budgeted(fixture, assignment_id, target, node, observed_at, None)
    }

    fn offer_command_budgeted(
        fixture: &AssignmentFixture,
        assignment_id: u128,
        target: AgentAssignmentTarget,
        node: &RegisteredDagNode,
        observed_at: i64,
        credit_budget: Option<forge_domain::WorkCreditBudget>,
    ) -> OfferAgentAssignment {
        OfferAgentAssignment::new(
            AgentAssignmentId::from_uuid(Uuid::from_u128(assignment_id)),
            fixture.coordinator,
            target,
            fixture.goal.id(),
            fixture.goal.revision(),
            fixture.goal.timestamps().created_at(),
            node.dag_revision(),
            DagHeadRevision::INITIAL,
            node.id(),
            node.revision(),
            credit_budget,
            TimestampMillis::new(observed_at)
                .unwrap_or_else(|_| unreachable!("valid test timestamp")),
        )
    }

    struct ForeignAssignmentFixture {
        activity_id: ActivityId,
        coordinator: ActivityCoordinatorActor,
        target_agent: RegisteredAgentInstance,
        goal: RegisteredGoal,
        nodes: [RegisteredDagNode; 2],
        offer: OfferAgentAssignment,
    }

    fn foreign_assignment_fixture(
        fixture: &mut AssignmentFixture,
        assignment_id: AgentAssignmentId,
    ) -> Result<ForeignAssignmentFixture, Box<dyn std::error::Error>> {
        let activity_id = ActivityId::from_uuid(Uuid::from_u128(0xA270));
        fixture.store.bootstrap_activity(&BootstrapActivity::new(
            activity_id,
            fixture.workspace_id,
            WorkspaceRevision::INITIAL,
            RuntimeInstanceId::from_uuid(Uuid::from_u128(0xA27F)),
            ts(101)?,
            ts(30)?,
        ))?;
        let coordinator_agent = bound_agent(
            0xA280,
            fixture.workspace_id,
            activity_id,
            ts(31)?,
            AuthenticatedPrincipal::TrustedStdio,
        )?;
        let target_agent = bound_agent(
            0xA281,
            fixture.workspace_id,
            activity_id,
            ts(32)?,
            AuthenticatedPrincipal::TrustedStdio,
        )?;
        let seed_connection = Connection::open(fixture.layout.database_path())?;
        seed_connection.pragma_update(None, "foreign_keys", true)?;
        for agent in [&coordinator_agent, &target_agent] {
            crate::legacy_agent_seed::seed_agent(
                &seed_connection,
                agent,
                Some(crate::workspace_agent_events::derived_event_id(
                    agent.id(),
                    agent.revision(),
                    forge_domain::AgentEventKind::Joined,
                )),
            )?;
        }
        drop(seed_connection);
        let binding = fixture.store.claim_activity_coordinator(
            ClaimActivityCoordinator::new(
                fixture.workspace_id,
                activity_id,
                coordinator_agent.id(),
                AuthenticatedPrincipal::TrustedStdio,
                ts(33)?,
                coordinator_agent
                    .session_id()
                    .ok_or("foreign coordinator session missing")?,
            ),
            admitted_at()?,
        )?;
        let coordinator = ActivityCoordinatorActor::new(
            fixture.workspace_id,
            activity_id,
            coordinator_agent.id(),
            binding.revision(),
            AuthenticatedPrincipal::TrustedStdio,
            coordinator_agent
                .session_id()
                .ok_or("foreign coordinator session missing")?,
        );
        let (goal, nodes) = seed_goal_and_nodes_with_ids(
            &mut fixture.store,
            fixture.workspace_id,
            activity_id,
            coordinator,
            0xA290,
        )?;
        let offer = OfferAgentAssignment::new(
            assignment_id,
            coordinator,
            target(&target_agent),
            goal.id(),
            goal.revision(),
            goal.timestamps().created_at(),
            nodes[0].dag_revision(),
            DagHeadRevision::INITIAL,
            nodes[0].id(),
            nodes[0].revision(),
            None,
            ts(40)?,
        );
        Ok(ForeignAssignmentFixture {
            activity_id,
            coordinator,
            target_agent,
            goal,
            nodes,
            offer,
        })
    }

    fn assert_goal_dag_scope_unchanged(
        store: &WorkspaceStore,
        goal_a: &RegisteredGoal,
        dag_a: &crate::StoredDagRevision,
        goal_b: &RegisteredGoal,
        dag_b: &crate::StoredDagRevision,
    ) -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            store
                .get_goal(goal_a.id())?
                .ok_or("local Goal missing after seal")?
                .revision(),
            goal_a.revision()
        );
        assert_eq!(
            store
                .get_current_dag(goal_a.id())?
                .ok_or("local DAG missing after seal")?
                .head(),
            dag_a.head()
        );
        assert_eq!(
            store
                .get_goal(goal_b.id())?
                .ok_or("foreign Goal missing after seal")?
                .revision(),
            goal_b.revision()
        );
        assert_eq!(
            store
                .get_current_dag(goal_b.id())?
                .ok_or("foreign DAG missing after seal")?
                .head(),
            dag_b.head()
        );
        Ok(())
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "One atomic seal regression preserves foreign work and first-sealer provenance across replay."
    )]
    fn offer_seal_reports_foreign_assignment_without_mutating_work_scope()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = fixture()?;
        let assignment_id = AgentAssignmentId::from_uuid(Uuid::from_u128(0xA2C0));
        let foreign = foreign_assignment_fixture(&mut fixture, assignment_id)?;
        let offered = fixture
            .store
            .offer_agent_assignment(&foreign.offer, admitted_at()?)?;
        assert_eq!(offered.activity_id(), foreign.activity_id);
        assert_eq!(
            fixture
                .store
                .offer_agent_assignment(&foreign.offer, admitted_at()?)?,
            offered
        );
        let changed_offer = OfferAgentAssignment::new(
            assignment_id,
            foreign.coordinator,
            target(&foreign.target_agent),
            foreign.goal.id(),
            foreign.goal.revision(),
            foreign.goal.timestamps().created_at(),
            foreign.nodes[0].dag_revision(),
            DagHeadRevision::INITIAL,
            foreign.nodes[0].id(),
            foreign.nodes[0].revision(),
            None,
            ts(41)?,
        );
        assert!(matches!(
            fixture
                .store
                .offer_agent_assignment(&changed_offer, admitted_at()?),
            Err(WorkspaceStoreError::AgentAssignment(
                AgentAssignmentStoreError::IdentityConflict
            ))
        ));
        assert!(
            fixture
                .store
                .get_agent_assignment_offer_seal_local(
                    fixture.workspace_id,
                    fixture.activity_id,
                    assignment_id,
                )?
                .is_none(),
            "no seal row is distinct from the foreign Assignment already being present"
        );

        let goal_a = fixture
            .store
            .get_goal(fixture.goal.id())?
            .ok_or("local Goal missing")?;
        let dag_a = fixture
            .store
            .get_current_dag(goal_a.id())?
            .ok_or("local DAG missing")?;
        let goal_b = fixture
            .store
            .get_goal(foreign.goal.id())?
            .ok_or("foreign Goal missing")?;
        let dag_b = fixture
            .store
            .get_current_dag(goal_b.id())?
            .ok_or("foreign DAG missing")?;
        let sealed = fixture.store.seal_agent_assignment_offer_authorized(
            fixture.workspace_id,
            fixture.activity_id,
            assignment_id,
            fixture.coordinator,
            ts(50)?,
        )?;
        let present = sealed
            .current_assignment()
            .ok_or("foreign Assignment should remain present")?;
        assert_eq!(sealed.requested_activity_id(), fixture.activity_id);
        assert_eq!(sealed.sealed_at(), ts(50)?);
        assert_eq!(
            sealed.seal_authority(),
            AgentAssignmentOfferSealAuthority::Coordinator {
                agent_id: fixture.coordinator_agent.id(),
                session_id: fixture.coordinator.session_id(),
                expected_coordinator_revision: fixture.coordinator.expected_revision(),
            }
        );
        assert_eq!(present.activity_id(), foreign.activity_id);
        assert_eq!(
            present.goal_created_at(),
            foreign.goal.timestamps().created_at()
        );
        assert_eq!(present.state(), AgentAssignmentState::Offered);
        assert!(!present.cancellation_requested());
        assert!(present.result().is_none());
        assert_goal_dag_scope_unchanged(&fixture.store, &goal_a, &dag_a, &goal_b, &dag_b)?;

        let replayed = fixture.store.seal_agent_assignment_offer_local(
            fixture.workspace_id,
            fixture.activity_id,
            assignment_id,
            ts(51)?,
        )?;
        assert_eq!(replayed.sealed_at(), ts(50)?);
        assert_eq!(replayed.seal_authority(), sealed.seal_authority());
        assert_eq!(replayed.current_assignment(), Some(present));
        assert_eq!(
            fixture.store.get_agent_assignment_offer_seal_local(
                fixture.workspace_id,
                fixture.activity_id,
                assignment_id,
            )?,
            Some(sealed),
            "exact readback returns the immutable first seal and current global row"
        );
        let root = fixture.layout.workspace_root().to_path_buf();
        drop(fixture.store);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn offer_seal_survives_assignment_deletion_and_blocks_delayed_local_offer()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = fixture()?;
        let assignment_id = AgentAssignmentId::from_uuid(Uuid::from_u128(0xA2C0));
        let foreign = foreign_assignment_fixture(&mut fixture, assignment_id)?;
        let _ = fixture
            .store
            .offer_agent_assignment(&foreign.offer, admitted_at()?)?;
        let delayed_local_offer = OfferAgentAssignment::new(
            assignment_id,
            fixture.coordinator,
            target(&fixture.target_a),
            fixture.goal.id(),
            fixture.goal.revision(),
            fixture.goal.timestamps().created_at(),
            fixture.nodes[0].dag_revision(),
            DagHeadRevision::INITIAL,
            fixture.nodes[0].id(),
            fixture.nodes[0].revision(),
            None,
            ts(60)?,
        );
        let sealed = fixture.store.seal_agent_assignment_offer_local(
            fixture.workspace_id,
            fixture.activity_id,
            assignment_id,
            ts(50)?,
        )?;
        let present = sealed
            .current_assignment()
            .ok_or("foreign Assignment should remain present")?;
        assert_eq!(
            sealed.seal_authority(),
            AgentAssignmentOfferSealAuthority::LocalOperator
        );
        assert_eq!(present.activity_id(), foreign.activity_id);
        assert_eq!(present.state(), AgentAssignmentState::Offered);
        assert!(!present.cancellation_requested());
        let coordinator_replay = fixture.store.seal_agent_assignment_offer_authorized(
            fixture.workspace_id,
            fixture.activity_id,
            assignment_id,
            fixture.coordinator,
            ts(51)?,
        )?;
        assert_eq!(coordinator_replay.sealed_at(), ts(50)?);
        assert_eq!(
            coordinator_replay.seal_authority(),
            AgentAssignmentOfferSealAuthority::LocalOperator
        );

        let root = fixture.layout.workspace_root().to_path_buf();
        let layout = WorkspaceStateLayout::inspect_existing(&root)?
            .ok_or("existing Workspace state missing")?;
        drop(fixture.store);
        let delete_connection = Connection::open(fixture.layout.database_path())?;
        delete_connection.pragma_update(None, "foreign_keys", true)?;
        assert_eq!(
            delete_connection.execute(
                "DELETE FROM agent_assignments WHERE assignment_id = ?1",
                params![assignment_id.into_uuid().as_bytes()],
            )?,
            1
        );
        drop(delete_connection);

        let mut reopened = WorkspaceStore::open_existing(&layout)?;
        let absent_now_sealed = reopened
            .get_agent_assignment_offer_seal_local(
                fixture.workspace_id,
                fixture.activity_id,
                assignment_id,
            )?
            .ok_or("seal should survive Assignment deletion and reopen")?;
        assert_eq!(absent_now_sealed.sealed_at(), ts(50)?);
        assert_eq!(
            absent_now_sealed.seal_authority(),
            AgentAssignmentOfferSealAuthority::LocalOperator
        );
        assert!(absent_now_sealed.absent_now_sealed());
        assert!(matches!(
            reopened.offer_agent_assignment(&delayed_local_offer, admitted_at()?),
            Err(WorkspaceStoreError::AgentAssignment(
                AgentAssignmentStoreError::OfferAdmissionSealed {
                    activity_id,
                    assignment_id: blocked_id,
                }
            )) if activity_id == fixture.activity_id && blocked_id == assignment_id
        ));
        let foreign_reoffer = reopened.offer_agent_assignment(&foreign.offer, admitted_at()?)?;
        assert_eq!(foreign_reoffer.activity_id(), foreign.activity_id);
        let current_foreign = reopened
            .get_agent_assignment_offer_seal_local(
                fixture.workspace_id,
                fixture.activity_id,
                assignment_id,
            )?
            .and_then(|snapshot| snapshot.current_assignment().cloned())
            .ok_or("foreign Activity's independent admission remains available")?;
        assert_eq!(current_foreign.activity_id(), foreign.activity_id);

        drop(reopened);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    fn close_fresh_activity_with_coordinator(
        fixture: &mut AssignmentFixture,
        activity_id: ActivityId,
        owner: forge_domain::RuntimeInstanceId,
    ) -> Result<ActivityCoordinatorActor, Box<dyn std::error::Error>> {
        let leased = fixture.store.bootstrap_activity(&BootstrapActivity::new(
            activity_id,
            fixture.workspace_id,
            WorkspaceRevision::INITIAL,
            owner,
            ts(100)?,
            ts(70)?,
        ))?;
        let coordinator_agent = bound_agent(
            0xA2D2,
            fixture.workspace_id,
            activity_id,
            ts(71)?,
            AuthenticatedPrincipal::TrustedStdio,
        )?;
        let seed_connection = Connection::open(fixture.layout.database_path())?;
        seed_connection.pragma_update(None, "foreign_keys", true)?;
        crate::legacy_agent_seed::seed_agent(
            &seed_connection,
            &coordinator_agent,
            Some(crate::workspace_agent_events::derived_event_id(
                coordinator_agent.id(),
                coordinator_agent.revision(),
                forge_domain::AgentEventKind::Joined,
            )),
        )?;
        drop(seed_connection);
        let coordinator_session = coordinator_agent
            .session_id()
            .ok_or("closed Activity Coordinator session missing")?;
        let binding = fixture.store.claim_activity_coordinator(
            ClaimActivityCoordinator::new(
                fixture.workspace_id,
                activity_id,
                coordinator_agent.id(),
                AuthenticatedPrincipal::TrustedStdio,
                ts(72)?,
                coordinator_session,
            ),
            ts(99)?,
        )?;
        let coordinator = ActivityCoordinatorActor::new(
            fixture.workspace_id,
            activity_id,
            coordinator_agent.id(),
            binding.revision(),
            AuthenticatedPrincipal::TrustedStdio,
            coordinator_session,
        );
        let closed = fixture.store.close_activity(&CloseActivity::new(
            activity_id,
            owner,
            leased.lease_revision(),
            ts(80)?,
        ))?;
        assert_eq!(closed.state(), forge_domain::ActivityState::Closed);
        Ok(coordinator)
    }

    #[test]
    fn closed_activity_offer_seal_recovery_requires_local_operator()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = fixture()?;
        let closed_activity_id = ActivityId::from_uuid(Uuid::from_u128(0xA2D1));
        let owner = forge_domain::RuntimeInstanceId::from_uuid(Uuid::from_u128(0xA2D0));
        let coordinator =
            close_fresh_activity_with_coordinator(&mut fixture, closed_activity_id, owner)?;
        let assignment_id = AgentAssignmentId::from_uuid(Uuid::from_u128(0xA2D3));
        assert!(matches!(
            fixture.store.seal_agent_assignment_offer_authorized(
                fixture.workspace_id,
                closed_activity_id,
                assignment_id,
                coordinator,
                ts(81)?,
            ),
            Err(WorkspaceStoreError::AgentAssignment(
                AgentAssignmentStoreError::Coordinator(_)
            ))
        ));
        let sealed = fixture.store.seal_agent_assignment_offer_local(
            fixture.workspace_id,
            closed_activity_id,
            assignment_id,
            ts(82)?,
        )?;
        assert!(sealed.absent_now_sealed());
        assert_eq!(
            sealed.seal_authority(),
            AgentAssignmentOfferSealAuthority::LocalOperator
        );
        assert!(matches!(
            fixture.store.get_agent_assignment_offer_seal_authorized(
                fixture.workspace_id,
                closed_activity_id,
                assignment_id,
                coordinator,
                ts(83)?,
            ),
            Err(WorkspaceStoreError::AgentAssignment(
                AgentAssignmentStoreError::Coordinator(_)
            ))
        ));
        assert_eq!(
            fixture
                .store
                .get_agent_assignment_offer_seal_local(
                    fixture.workspace_id,
                    closed_activity_id,
                    assignment_id,
                )?
                .as_ref(),
            Some(&sealed)
        );

        let root = fixture.layout.workspace_root().to_path_buf();
        drop(fixture.store);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    fn install_delegation_seal(
        store: &mut WorkspaceStore,
        seed: u128,
        at: i64,
    ) -> Result<crate::AgentOperationsDelegation, Box<dyn std::error::Error>> {
        let freeze = store.freeze_agent_operations(&crate::AgentOperationsFreezeRequest::new(
            Uuid::from_u128(seed),
            Uuid::from_u128(seed + 1),
            ts(at)?,
        )?)?;
        Ok(store.delegate_agent_operations(&freeze, [0x5C; 32], ts(at + 1)?)?)
    }

    fn assert_node_assignment_snapshot(
        store: &WorkspaceStore,
        snapshot: &crate::DagNodeAssignmentSnapshot,
        scope: crate::DagNodeEvidenceScope,
        expected_head: crate::DagHead,
        expected_node_revision: forge_domain::DagNodeRevision,
        expected_assignment: Option<forge_domain::AgentAssignmentSummary>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let workspace = store.workspace()?;
        let goal = store.get_goal(scope.goal_id())?.ok_or("goal missing")?;
        let activity = store
            .get_activity(goal.activity_id())?
            .ok_or("activity missing")?;
        let requested_dag = store
            .get_dag_revision(scope.goal_id(), scope.dag_revision())?
            .ok_or("requested DAG revision missing")?;
        assert_eq!(snapshot.workspace_id(), workspace.id());
        assert_eq!(snapshot.activity_id(), activity.id());
        assert_eq!(snapshot.goal_revision(), goal.revision());
        assert_eq!(snapshot.goal_created_at(), goal.timestamps().created_at());
        assert_eq!(
            snapshot.dag_base_goal_revision(),
            requested_dag.revision().base_goal_revision()
        );
        assert_eq!(snapshot.scope(), scope);
        assert_eq!(snapshot.head(), expected_head);
        assert_eq!(snapshot.node_revision(), expected_node_revision);
        assert_eq!(snapshot.assignment(), expected_assignment);
        Ok(())
    }

    #[allow(
        clippy::too_many_lines,
        reason = "One lifecycle regression observes exact assignment state across offer, DAG advance, and reopen."
    )]
    #[test]
    fn two_participants_claim_distinct_nodes_without_moving_main_focus_and_reopen()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = fixture()?;
        let main_before = fixture
            .store
            .get_agent(fixture.coordinator_agent.id())?
            .ok_or("coordinator missing")?;
        let scope_a = crate::DagNodeEvidenceScope::new(
            fixture.goal.id(),
            fixture.nodes[0].dag_revision(),
            fixture.nodes[0].id(),
        );
        let scope_b = crate::DagNodeEvidenceScope::new(
            fixture.goal.id(),
            fixture.nodes[1].dag_revision(),
            fixture.nodes[1].id(),
        );
        let initial_head = fixture
            .store
            .get_current_dag(fixture.goal.id())?
            .ok_or("initial DAG missing")?
            .head();
        let runner_session = fixture
            .target_a
            .session_id()
            .ok_or("target A session missing")?;
        let submitted_session = fixture
            .target_b
            .session_id()
            .ok_or("target B session missing")?;
        let offered_a = fixture.store.offer_agent_assignment(
            &offer_command(
                &fixture,
                0xA270,
                target(&fixture.target_a),
                &fixture.nodes[0],
                10,
            ),
            admitted_at()?,
        )?;
        let offered_b = fixture.store.offer_agent_assignment(
            &offer_command(
                &fixture,
                0xA271,
                target(&fixture.target_b),
                &fixture.nodes[1],
                11,
            ),
            admitted_at()?,
        )?;
        let offered_snapshot = fixture
            .store
            .dag_node_assignment_snapshot(scope_a)?
            .ok_or("offered node snapshot missing")?;
        assert_node_assignment_snapshot(
            &fixture.store,
            &offered_snapshot,
            scope_a,
            initial_head,
            fixture.nodes[0].revision(),
            Some(offered_a.summary(0)),
        )?;
        let corruption_layout = WorkspaceStateLayout::inspect_existing(&fixture.root)?
            .ok_or("assignment fixture layout missing")?;
        let corruption = Connection::open(corruption_layout.database_path())?;
        let goal_created_at_ms = fixture.goal.timestamps().created_at().get();
        corruption.execute(
            "UPDATE agent_assignments SET goal_created_at_ms = ?1 WHERE assignment_id = ?2",
            params![
                goal_created_at_ms + 1,
                offered_a.id().into_uuid().as_bytes()
            ],
        )?;
        assert!(matches!(
            fixture.store.dag_node_assignment_snapshot(scope_a),
            Err(crate::WorkspaceStoreError::AgentAssignment(
                AgentAssignmentStoreError::GoalConflict
            ))
        ));
        corruption.execute(
            "UPDATE agent_assignments SET goal_created_at_ms = ?1 WHERE assignment_id = ?2",
            params![goal_created_at_ms, offered_a.id().into_uuid().as_bytes()],
        )?;
        drop(corruption);
        let offered_summary = offered_snapshot.assignment().ok_or("assignment missing")?;
        assert_eq!(offered_summary.target_agent_id(), fixture.target_a.id());
        assert_eq!(offered_summary.target_session_id(), runner_session);
        assert_eq!(offered_summary.state(), AgentAssignmentState::Offered);
        assert!(!offered_summary.cancellation_requested());

        let claimed_a = fixture.store.claim_agent_assignment(
            &ClaimAgentAssignment::new(
                offered_a.id(),
                target(&fixture.target_a),
                offered_a.revision(),
                ts(12)?,
            ),
            admitted_at()?,
        )?;
        let claimed_b = fixture.store.claim_agent_assignment(
            &ClaimAgentAssignment::new(
                offered_b.id(),
                target(&fixture.target_b),
                offered_b.revision(),
                ts(13)?,
            ),
            admitted_at()?,
        )?;
        assert_eq!(claimed_a.state(), AgentAssignmentState::Running);
        assert_eq!(claimed_b.state(), AgentAssignmentState::Running);
        // Each claim starts its Pending DAG node, and RegisteredDagNode::start
        // advances that node's revision exactly once.
        let runner_node_revision = fixture.nodes[0].revision().checked_next()?;
        let submitter_node_revision = fixture.nodes[1].revision().checked_next()?;
        assert_eq!(
            fixture.store.get_agent(fixture.coordinator_agent.id())?,
            Some(main_before)
        );
        assert_eq!(
            fixture
                .store
                .get_agent(fixture.target_a.id())?
                .ok_or("target A missing")?
                .focus()
                .node()
                .ok_or("target A focus missing")?
                .node_id(),
            fixture.nodes[0].id()
        );
        assert_eq!(
            fixture
                .store
                .get_agent(fixture.target_b.id())?
                .ok_or("target B missing")?
                .focus()
                .node()
                .ok_or("target B focus missing")?
                .node_id(),
            fixture.nodes[1].id()
        );
        let cancelled_a = fixture
            .store
            .cancel_agent_assignment(&CancelAgentAssignment::new(
                claimed_a.id(),
                fixture.coordinator,
                claimed_a.revision(),
                ts(14)?,
            ))?;
        assert_eq!(cancelled_a.state(), AgentAssignmentState::Running);
        assert!(cancelled_a.cancellation_requested());
        let current_target_b = target(
            &fixture
                .store
                .get_agent(fixture.target_b.id())?
                .ok_or("target B missing after claim")?,
        );
        let submitted_b = fixture.store.submit_agent_assignment(
            &SubmitAgentAssignment::new(
                claimed_b.id(),
                current_target_b,
                claimed_b.revision(),
                AgentAssignmentResult::new(
                    "bounded participant report".to_owned(),
                    vec![AgentAssignmentSourceRef::Url(
                        AgentAssignmentSourceUrl::new("https://example.test/node-b".to_owned())?,
                    )],
                    None,
                )?,
                ts(15)?,
            ),
            admitted_at()?,
        )?;
        assert_eq!(submitted_b.state(), AgentAssignmentState::Submitted);

        let next_number = DagRevisionNumber::new(2)?;
        let next_definitions = fixture
            .nodes
            .iter()
            .map(|node| node.definition().clone())
            .collect::<Vec<_>>();
        let next_dag = DagRevision::new(
            DagRevisionId::from_uuid(Uuid::from_u128(0xA262)),
            fixture.goal.id(),
            fixture.goal.revision(),
            next_number,
            Some(initial_head.dag_revision()),
            next_definitions,
            Vec::new(),
            ts(16)?,
        )?;
        let next_nodes = [
            RegisteredDagNode::create(
                fixture.goal.id(),
                next_number,
                fixture.nodes[0].definition().clone(),
                ts(16)?,
            ),
            RegisteredDagNode::create(
                fixture.goal.id(),
                next_number,
                fixture.nodes[1].definition().clone(),
                ts(16)?,
            ),
        ];
        let advanced_dag = fixture.store.insert_dag_revision(
            &next_dag,
            &next_nodes,
            &[],
            Some(initial_head.revision()),
        )?;
        assert_eq!(advanced_dag.head().dag_revision(), next_number);

        let mut goal_connection = Connection::open(corruption_layout.database_path())?;
        let current_goal = crate::workspace_goals::get_goal(&goal_connection, fixture.goal.id())?
            .ok_or("Goal missing before revision advance")?;
        let paused_goal = current_goal.pause(current_goal.revision(), ts(17)?)?;
        let paused_goal = crate::workspace_goals::update_goal(
            &mut goal_connection,
            &paused_goal,
            current_goal.revision(),
        )?;
        drop(goal_connection);

        let historical_snapshot_a = fixture
            .store
            .dag_node_assignment_snapshot(scope_a)?
            .ok_or("historical running node snapshot missing")?;
        assert_node_assignment_snapshot(
            &fixture.store,
            &historical_snapshot_a,
            scope_a,
            advanced_dag.head(),
            runner_node_revision,
            Some(cancelled_a.summary(0)),
        )?;
        assert_eq!(
            historical_snapshot_a.goal_revision(),
            paused_goal.revision()
        );
        assert_eq!(
            historical_snapshot_a.dag_base_goal_revision(),
            GoalRevision::INITIAL
        );
        assert_ne!(
            historical_snapshot_a.goal_revision(),
            historical_snapshot_a.dag_base_goal_revision()
        );
        assert_ne!(
            historical_snapshot_a.head().dag_revision(),
            scope_a.dag_revision()
        );
        let historical_a = historical_snapshot_a
            .assignment()
            .ok_or("assignment missing")?;
        assert_eq!(historical_a.target_agent_id(), fixture.target_a.id());
        assert_eq!(historical_a.target_session_id(), runner_session);
        assert_eq!(historical_a.state(), AgentAssignmentState::Running);
        assert!(historical_a.cancellation_requested());

        let historical_snapshot_b = fixture
            .store
            .dag_node_assignment_snapshot(scope_b)?
            .ok_or("historical submitted node snapshot missing")?;
        assert_node_assignment_snapshot(
            &fixture.store,
            &historical_snapshot_b,
            scope_b,
            advanced_dag.head(),
            submitter_node_revision,
            Some(submitted_b.summary(1)),
        )?;
        let historical_b = historical_snapshot_b
            .assignment()
            .ok_or("assignment missing")?;
        assert_eq!(historical_b.target_agent_id(), fixture.target_b.id());
        assert_eq!(historical_b.target_session_id(), submitted_session);
        assert_eq!(historical_b.state(), AgentAssignmentState::Submitted);
        assert!(!historical_b.cancellation_requested());

        let new_scope =
            crate::DagNodeEvidenceScope::new(fixture.goal.id(), next_number, next_nodes[0].id());
        let new_node_snapshot = fixture
            .store
            .dag_node_assignment_snapshot(new_scope)?
            .ok_or("unassigned new node snapshot missing")?;
        assert_node_assignment_snapshot(
            &fixture.store,
            &new_node_snapshot,
            new_scope,
            advanced_dag.head(),
            next_nodes[0].revision(),
            None,
        )?;
        let missing_node_scope = crate::DagNodeEvidenceScope::new(
            fixture.goal.id(),
            next_number,
            DagNodeId::from_uuid(Uuid::from_u128(0xA2FC)),
        );
        assert!(
            fixture
                .store
                .dag_node_assignment_snapshot(missing_node_scope)?
                .is_none()
        );

        drop(fixture.store);
        let existing =
            WorkspaceStateLayout::inspect_existing(&fixture.root)?.ok_or("layout missing")?;
        let reopened = WorkspaceStore::open_existing(&existing)?;
        assert_eq!(
            reopened.get_agent_assignment(cancelled_a.id())?.as_ref(),
            Some(&cancelled_a)
        );
        assert_eq!(
            reopened.get_agent_assignment(submitted_b.id())?.as_ref(),
            Some(&submitted_b)
        );
        let reopened_snapshot_a = reopened
            .dag_node_assignment_snapshot(scope_a)?
            .ok_or("reopened historical node snapshot missing")?;
        assert_node_assignment_snapshot(
            &reopened,
            &reopened_snapshot_a,
            scope_a,
            advanced_dag.head(),
            runner_node_revision,
            Some(cancelled_a.summary(0)),
        )?;
        let reopened_snapshot_b = reopened
            .dag_node_assignment_snapshot(scope_b)?
            .ok_or("reopened submitted node snapshot missing")?;
        assert_node_assignment_snapshot(
            &reopened,
            &reopened_snapshot_b,
            scope_b,
            advanced_dag.head(),
            submitter_node_revision,
            Some(submitted_b.summary(1)),
        )?;
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[allow(
        clippy::too_many_lines,
        reason = "One regression enumerates all independent claim admission fences in one lifecycle trace."
    )]
    #[test]
    fn claim_fences_wrong_session_stale_coordinator_goal_dag_and_duplicate()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = fixture()?;
        let offered = fixture.store.offer_agent_assignment(
            &offer_command(
                &fixture,
                0xA280,
                target(&fixture.target_a),
                &fixture.nodes[0],
                10,
            ),
            admitted_at()?,
        )?;
        let wrong_target = AgentAssignmentTarget::new(
            fixture.target_a.id(),
            AgentSessionId::from_uuid(Uuid::from_u128(0xA2FF)),
            fixture.target_a.principal(),
            fixture.target_a.revision(),
        );
        assert!(matches!(
            fixture
                .store
                .claim_agent_assignment(&ClaimAgentAssignment::new(
                    offered.id(),
                    wrong_target,
                offered.revision(),
                ts(11)?,
                ), admitted_at()?),
            Err(WorkspaceStoreError::AgentAssignment(
                AgentAssignmentStoreError::TargetConflict
            ))
        ));
        assert_eq!(
            fixture
                .store
                .get_agent_assignment(offered.id())?
                .map(|row| row.state()),
            Some(AgentAssignmentState::Offered)
        );

        let stale_coordinator = ActivityCoordinatorActor::new(
            fixture.workspace_id,
            fixture.activity_id,
            fixture.coordinator_agent.id(),
            forge_domain::ActivityCoordinatorRevision::new(99)?,
            fixture.coordinator.principal(),
            fixture.coordinator.session_id(),
        );
        let stale_offer = OfferAgentAssignment::new(
            AgentAssignmentId::from_uuid(Uuid::from_u128(0xA281)),
            stale_coordinator,
            target(&fixture.target_b),
            fixture.goal.id(),
            fixture.goal.revision(),
            fixture.goal.timestamps().created_at(),
            fixture.nodes[1].dag_revision(),
            DagHeadRevision::INITIAL,
            fixture.nodes[1].id(),
            fixture.nodes[1].revision(),
            None,
            ts(12)?,
        );
        assert!(matches!(
            fixture
                .store
                .offer_agent_assignment(&stale_offer, admitted_at()?),
            Err(WorkspaceStoreError::AgentAssignment(
                AgentAssignmentStoreError::Coordinator(_)
            ))
        ));
        let stale_goal = OfferAgentAssignment::new(
            AgentAssignmentId::from_uuid(Uuid::from_u128(0xA282)),
            fixture.coordinator,
            target(&fixture.target_b),
            fixture.goal.id(),
            GoalRevision::new(2)?,
            fixture.goal.timestamps().created_at(),
            fixture.nodes[1].dag_revision(),
            DagHeadRevision::INITIAL,
            fixture.nodes[1].id(),
            fixture.nodes[1].revision(),
            None,
            ts(13)?,
        );
        assert!(matches!(
            fixture
                .store
                .offer_agent_assignment(&stale_goal, admitted_at()?),
            Err(WorkspaceStoreError::AgentAssignment(
                AgentAssignmentStoreError::GoalConflict
            ))
        ));
        let stale_dag = OfferAgentAssignment::new(
            AgentAssignmentId::from_uuid(Uuid::from_u128(0xA283)),
            fixture.coordinator,
            target(&fixture.target_b),
            fixture.goal.id(),
            fixture.goal.revision(),
            fixture.goal.timestamps().created_at(),
            fixture.nodes[1].dag_revision(),
            DagHeadRevision::new(99)?,
            fixture.nodes[1].id(),
            fixture.nodes[1].revision(),
            None,
            ts(14)?,
        );
        assert!(matches!(
            fixture
                .store
                .offer_agent_assignment(&stale_dag, admitted_at()?),
            Err(WorkspaceStoreError::AgentAssignment(
                AgentAssignmentStoreError::DagConflict
            ))
        ));
        let claimed = fixture.store.claim_agent_assignment(
            &ClaimAgentAssignment::new(
                offered.id(),
                target(&fixture.target_a),
                offered.revision(),
                ts(15)?,
            ),
            admitted_at()?,
        )?;
        let duplicate = fixture.store.claim_agent_assignment(
            &ClaimAgentAssignment::new(
                claimed.id(),
                target(&fixture.target_a),
                offered.revision(),
                ts(16)?,
            ),
            admitted_at()?,
        );
        assert!(matches!(
            duplicate,
            Err(WorkspaceStoreError::AgentAssignment(
                AgentAssignmentStoreError::Agent(_)
            ))
        ));
        assert_eq!(
            fixture
                .store
                .get_agent_assignment(claimed.id())?
                .map(|row| row.state()),
            Some(AgentAssignmentState::Running)
        );
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[allow(
        clippy::too_many_lines,
        reason = "One regression keeps submission validation and cancellation/effect acknowledgement as one lifecycle trace."
    )]
    #[test]
    fn result_sources_are_goal_validated_and_running_cancel_waits_for_effect_ack()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = fixture()?;
        let offered = fixture.store.offer_agent_assignment(
            &offer_command(
                &fixture,
                0xA290,
                target(&fixture.target_a),
                &fixture.nodes[0],
                10,
            ),
            admitted_at()?,
        )?;
        let claimed = fixture.store.claim_agent_assignment(
            &ClaimAgentAssignment::new(
                offered.id(),
                target(&fixture.target_a),
                offered.revision(),
                ts(11)?,
            ),
            admitted_at()?,
        )?;
        let current_target = target(
            &fixture
                .store
                .get_agent(fixture.target_a.id())?
                .ok_or("target missing after claim")?,
        );
        let invalid_source = AgentAssignmentResult::new(
            "report".to_owned(),
            vec![AgentAssignmentSourceRef::Provenance(
                forge_domain::GoalEvidenceRef::Execution(forge_domain::ExecutionId::from_uuid(
                    Uuid::from_u128(0xA2EE),
                )),
            )],
            None,
        )?;
        assert!(matches!(
            fixture.store.submit_agent_assignment(
                &SubmitAgentAssignment::new(
                    claimed.id(),
                    current_target,
                    claimed.revision(),
                    invalid_source,
                    ts(12)?,
                ),
                admitted_at()?
            ),
            Err(WorkspaceStoreError::AgentAssignment(
                AgentAssignmentStoreError::EvidenceMissing(_)
            ))
        ));
        let valid_result = AgentAssignmentResult::new(
            "bounded participant report".to_owned(),
            vec![AgentAssignmentSourceRef::Url(
                AgentAssignmentSourceUrl::new("https://example.test/source".to_owned())?,
            )],
            None,
        )?;
        let submitted = fixture.store.submit_agent_assignment(
            &SubmitAgentAssignment::new(
                claimed.id(),
                current_target,
                claimed.revision(),
                valid_result,
                ts(13)?,
            ),
            admitted_at()?,
        )?;
        assert_eq!(submitted.state(), AgentAssignmentState::Submitted);
        assert_eq!(
            submitted.result().map(AgentAssignmentResult::report),
            Some("bounded participant report")
        );
        assert!(matches!(
            fixture.store.submit_agent_assignment(
                &SubmitAgentAssignment::new(
                    submitted.id(),
                    current_target,
                    submitted.revision(),
                    AgentAssignmentResult::new("changed".to_owned(), Vec::new(), None)?,
                    ts(14)?,
                ),
                admitted_at()?
            ),
            Err(WorkspaceStoreError::AgentAssignment(
                AgentAssignmentStoreError::Transition(
                    forge_domain::AgentAssignmentTransitionError::InvalidState
                )
            ))
        ));

        let offered_cancel = fixture.store.offer_agent_assignment(
            &offer_command(
                &fixture,
                0xA291,
                target(&fixture.target_b),
                &fixture.nodes[1],
                15,
            ),
            admitted_at()?,
        )?;
        let claimed_cancel = fixture.store.claim_agent_assignment(
            &ClaimAgentAssignment::new(
                offered_cancel.id(),
                target(&fixture.target_b),
                offered_cancel.revision(),
                ts(16)?,
            ),
            admitted_at()?,
        )?;
        let current_target_b = target(
            &fixture
                .store
                .get_agent(fixture.target_b.id())?
                .ok_or("target B missing after claim")?,
        );
        let external = rusqlite::Connection::open(fixture.layout.database_path())?;
        external.execute(
            "INSERT INTO writer_leases (
                lease_id, workspace_id, activity_id, agent_id, state,
                acquired_at_ms, updated_at_ms, lease_until_ms, revision
             ) VALUES (?1, ?2, ?3, ?4, 0, 20, 20, 1000, 1)",
            rusqlite::params![
                Uuid::from_u128(0xA2F0).as_bytes(),
                fixture.workspace_id.into_uuid().as_bytes(),
                fixture.activity_id.into_uuid().as_bytes(),
                fixture.target_b.id().into_uuid().as_bytes(),
            ],
        )?;
        drop(external);
        let requested = fixture
            .store
            .cancel_agent_assignment(&CancelAgentAssignment::new(
                claimed_cancel.id(),
                fixture.coordinator,
                claimed_cancel.revision(),
                ts(21)?,
            ))?;
        assert_eq!(requested.state(), AgentAssignmentState::Running);
        assert!(requested.cancellation_requested());
        assert!(matches!(
            fixture.store.acknowledge_agent_assignment_cancellation(
                &AcknowledgeAgentAssignmentCancellation::new(
                    requested.id(),
                    current_target_b,
                    requested.revision(),
                    ts(22)?,
                ),
            ),
            Err(WorkspaceStoreError::AgentAssignment(
                AgentAssignmentStoreError::NoActiveEffects
            ))
        ));
        let cleanup = rusqlite::Connection::open(fixture.layout.database_path())?;
        cleanup.execute(
            "DELETE FROM writer_leases WHERE lease_id = ?1",
            rusqlite::params![Uuid::from_u128(0xA2F0).as_bytes()],
        )?;
        drop(cleanup);
        let cancelled = fixture.store.acknowledge_agent_assignment_cancellation(
            &AcknowledgeAgentAssignmentCancellation::new(
                requested.id(),
                current_target_b,
                requested.revision(),
                ts(23)?,
            ),
        )?;
        assert_eq!(cancelled.state(), AgentAssignmentState::Cancelled);
        drop(fixture.store);
        let existing =
            WorkspaceStateLayout::inspect_existing(&fixture.root)?.ok_or("layout missing")?;
        let reopened = WorkspaceStore::open_existing(&existing)?;
        assert_eq!(
            reopened
                .get_agent_assignment(submitted.id())?
                .and_then(|row| row.result().map(|result| result.report().to_owned())),
            Some("bounded participant report".to_owned())
        );
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn credit_budget_round_trips_and_rejects_out_of_band_values()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = fixture()?;
        for (seed, at, budget, expected) in [
            (
                0xA2A0,
                10,
                Some(forge_domain::WorkCreditBudget::One),
                Some(1_i64),
            ),
            (
                0xA2A1,
                20,
                Some(forge_domain::WorkCreditBudget::Three),
                Some(3_i64),
            ),
            (
                0xA2A2,
                30,
                Some(forge_domain::WorkCreditBudget::Five),
                Some(5_i64),
            ),
        ] {
            let offered = fixture.store.offer_agent_assignment(
                &offer_command_budgeted(
                    &fixture,
                    seed,
                    target(&fixture.target_a),
                    &fixture.nodes[0],
                    10,
                    budget,
                ),
                admitted_at()?,
            )?;
            assert_eq!(offered.credit_budget(), budget);
            let assignment_id = offered.id();
            let offered_revision = offered.revision();
            assert_eq!(
                fixture.store.get_agent_assignment(assignment_id)?,
                Some(offered),
                "the frozen budget must survive a durable read-back"
            );
            let stored = stored_budget(&fixture.layout.database_path(), assignment_id)?;
            assert_eq!(stored, expected);
            // Cancel frees the single active target/node pair for the next
            // budget case.
            let cancelled = fixture
                .store
                .cancel_agent_assignment(&CancelAgentAssignment::new(
                    assignment_id,
                    fixture.coordinator,
                    offered_revision,
                    ts(at)?,
                ))?;
            assert_eq!(cancelled.state(), AgentAssignmentState::Cancelled);
        }
        let unbudgeted = fixture.store.offer_agent_assignment(
            &offer_command_budgeted(
                &fixture,
                0xA2A3,
                target(&fixture.target_a),
                &fixture.nodes[0],
                40,
                None,
            ),
            admitted_at()?,
        )?;
        assert_eq!(unbudgeted.credit_budget(), None);
        let stored = stored_budget(&fixture.layout.database_path(), unbudgeted.id())?;
        assert_eq!(stored, None, "a credit-ineligible offer must store NULL");

        assert_credit_budget_check_rejects_two(&fixture.layout.database_path())?;
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    /// The column CHECK is the last line of defense behind the domain
    /// constructor: only NULL/1/3/5 may be persisted.
    fn assert_credit_budget_check_rejects_two(
        database: &std::path::Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let forbidden = Connection::open(database)?.execute(
            "INSERT INTO agent_assignments (
                assignment_id, workspace_id, activity_id, goal_id, goal_created_at_ms,
                goal_revision, dag_revision, dag_head_revision, node_id, node_revision,
                coordinator_agent_id, coordinator_session_id, coordinator_principal_kind,
                coordinator_principal_id, coordinator_revision, target_agent_id,
                target_session_id, target_principal_kind, target_principal_id,
                target_agent_revision, state, cancellation_requested, created_at_ms,
                updated_at_ms, revision, credit_budget
             ) VALUES (?1, ?2, ?3, ?4, 1, 1, 1, 1, ?5, 1, ?6, ?7, 0, NULL, 1,
                ?8, ?9, 0, NULL, 1, 0, 0, 1, 1, 1, 2)",
            params![
                Uuid::from_u128(0xA2A9).as_bytes(),
                Uuid::from_u128(0xA200).as_bytes(),
                Uuid::from_u128(0xA201).as_bytes(),
                Uuid::from_u128(0xA240).as_bytes(),
                Uuid::from_u128(0xA251).as_bytes(),
                Uuid::from_u128(0xA210).as_bytes(),
                Uuid::from_u128(0xA210 + 0x5000).as_bytes(),
                Uuid::from_u128(0xA230).as_bytes(),
                Uuid::from_u128(0xA230 + 0x5000).as_bytes(),
            ],
        );
        assert!(
            forbidden.is_err(),
            "credit_budget = 2 must be rejected by the column CHECK"
        );
        Ok(())
    }

    fn stored_budget(
        database: &std::path::Path,
        assignment_id: AgentAssignmentId,
    ) -> Result<Option<i64>, Box<dyn std::error::Error>> {
        let connection = Connection::open(database)?;
        let stored = connection
            .query_row(
                "SELECT credit_budget FROM agent_assignments WHERE assignment_id = ?1",
                params![assignment_id.into_uuid().as_bytes()],
                |row| row.get::<_, Option<i64>>(0),
            )
            .optional()?
            .flatten();
        drop(connection);
        Ok(stored)
    }

    fn submitted_assignment_with_budget(
        fixture: &mut AssignmentFixture,
        seed: u128,
        budget: Option<forge_domain::WorkCreditBudget>,
        report: &str,
        sources: Vec<AgentAssignmentSourceRef>,
    ) -> Result<RegisteredAgentAssignment, Box<dyn std::error::Error>> {
        let offered = fixture.store.offer_agent_assignment(
            &offer_command_budgeted(
                fixture,
                seed,
                target(&fixture.target_a),
                &fixture.nodes[0],
                10,
                budget,
            ),
            admitted_at()?,
        )?;
        let claimed = fixture.store.claim_agent_assignment(
            &ClaimAgentAssignment::new(
                offered.id(),
                target(&fixture.target_a),
                offered.revision(),
                ts(11)?,
            ),
            admitted_at()?,
        )?;
        let current_target = target(
            &fixture
                .store
                .get_agent(fixture.target_a.id())?
                .ok_or("target missing after claim")?,
        );
        let submitted = fixture.store.submit_agent_assignment(
            &SubmitAgentAssignment::new(
                claimed.id(),
                current_target,
                claimed.revision(),
                AgentAssignmentResult::new(report.to_owned(), sources, None)?,
                ts(12)?,
            ),
            admitted_at()?,
        )?;
        assert_eq!(submitted.state(), AgentAssignmentState::Submitted);
        Ok(submitted)
    }

    #[test]
    fn submit_emits_exactly_one_assignment_submitted_fact_with_exact_replay()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = fixture()?;
        let delegation = install_delegation_seal(&mut fixture.store, 0xA2A8, 8)?;
        let sources = linked_submission_sources(&fixture)?;
        let submitted = submitted_assignment_with_budget(
            &mut fixture,
            0xA2A9,
            Some(forge_domain::WorkCreditBudget::Three),
            "bounded participant report",
            sources,
        )?;
        let facts = fixture.store.effect_fact_outbox(0, 64)?;
        assert_eq!(facts.len(), 2, "offer + submit emit exactly two facts");
        assert!(matches!(
            facts[0].fact(),
            crate::EffectFact::AssignmentOffered(_)
        ));
        let crate::EffectFact::AssignmentSubmitted(fact) = facts[1].fact() else {
            return Err("the submit must emit an assignment-submitted fact".into());
        };
        assert_eq!(facts[1].sequence(), 2);
        assert_eq!(facts[1].migration_id(), delegation.migration_id());
        assert_eq!(facts[1].destination_id(), delegation.destination_id());
        assert_eq!(facts[1].workspace_id(), fixture.workspace_id);
        assert_eq!(fact.assignment_id(), submitted.id());
        assert_eq!(fact.workspace_id(), fixture.workspace_id);
        assert_eq!(fact.activity_id(), fixture.activity_id);
        assert_eq!(fact.goal_id(), fixture.goal.id());
        assert_eq!(fact.node_id(), fixture.nodes[0].id());
        assert_eq!(fact.target_agent_id(), fixture.target_a.id());
        assert_eq!(fact.target_session_id(), fixture.target_a.session_id());
        assert_eq!(fact.source_count(), 2);
        assert_eq!(fact.source_kinds(), Some([0, 1].as_slice()));
        assert!(fact.source_digests().is_some());
        assert_eq!(
            fact.result_digest(),
            Some(sha2::Sha256::digest("bounded participant report".as_bytes()).into())
        );
        assert_eq!(fact.submitted_at(), ts(12)?);
        assert_submitted_exact_replay_then_conflict(&fixture, submitted.id())?;
        let connection = Connection::open(fixture.layout.database_path())?;
        let stored: String = connection.query_row(
            "SELECT hex(source_digests) FROM effect_fact_outbox_assignment_submitted WHERE assignment_id=?1 AND source_count=2 AND source_kinds=x'0001'",
            params![submitted.id().into_uuid().as_bytes()],
            |row| row.get(0),
        )?;
        assert_eq!(
            stored,
            "6570D12AA8C1D82E0E7379267E29E144A8BAA51AE0E449B443C98893618C25E9"
        );
        drop(connection);
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    fn linked_submission_sources(
        fixture: &AssignmentFixture,
    ) -> Result<Vec<AgentAssignmentSourceRef>, Box<dyn std::error::Error>> {
        let evidence_id = Uuid::from_u128(7);
        let connection = Connection::open(fixture.layout.database_path())?;
        connection.pragma_update(None, "foreign_keys", true)?;
        connection.execute(
            "INSERT INTO goal_evidence_refs(goal_id,evidence_kind,evidence_id,associated_at_ms) VALUES(?1,0,?2,9)",
            params![fixture.goal.id().into_uuid().as_bytes(), evidence_id.as_bytes()],
        )?;
        Ok(vec![
            AgentAssignmentSourceRef::Url(AgentAssignmentSourceUrl::new(
                "https://example.com/artifact".to_owned(),
            )?),
            AgentAssignmentSourceRef::Provenance(forge_domain::GoalEvidenceRef::ChangeSet(
                forge_domain::ChangeSetId::from_uuid(evidence_id),
            )),
        ])
    }

    /// Exact replay of the durable submitted row must be a no-op, while a
    /// payload that differs from the durable identity must conflict.
    fn assert_submitted_exact_replay_then_conflict(
        fixture: &AssignmentFixture,
        assignment_id: AgentAssignmentId,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut replay_connection = Connection::open(fixture.layout.database_path())?;
        replay_connection.pragma_update(None, "foreign_keys", true)?;
        let replay_transaction =
            replay_connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let durable = get_in_transaction(&replay_transaction, assignment_id)?
            .ok_or("submitted assignment missing")?;
        crate::workspace_effect_fact_outbox::append_assignment_submitted(
            &replay_transaction,
            &durable,
        )?;
        replay_transaction.commit()?;
        drop(replay_connection);
        assert_eq!(
            fixture.store.effect_fact_outbox(0, 64)?.len(),
            2,
            "exact replay must not duplicate the submitted fact"
        );

        let changed = changed_submitted_assignment(&durable)?;
        let mut conflict_connection = Connection::open(fixture.layout.database_path())?;
        let conflict_transaction =
            conflict_connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert!(matches!(
            crate::workspace_effect_fact_outbox::append_assignment_submitted(
                &conflict_transaction,
                &changed,
            ),
            Err(crate::EffectFactOutboxError::ReplayConflict)
        ));
        conflict_transaction.rollback()?;
        drop(conflict_connection);
        assert_eq!(
            fixture.store.effect_fact_outbox(0, 64)?.len(),
            2,
            "a conflicting retry must not mutate the submitted fact"
        );
        Ok(())
    }

    fn changed_submitted_assignment(
        durable: &RegisteredAgentAssignment,
    ) -> Result<RegisteredAgentAssignment, Box<dyn std::error::Error>> {
        Ok(RegisteredAgentAssignment::from_parts(
            durable.id(),
            durable.workspace_id(),
            durable.activity_id(),
            durable.goal_id(),
            durable.goal_created_at(),
            durable.goal_revision(),
            durable.dag_revision(),
            durable.dag_head_revision(),
            durable.node_id(),
            durable.node_revision(),
            durable.coordinator(),
            durable.target(),
            durable.state(),
            durable.cancellation_requested(),
            durable.credit_budget(),
            Some(AgentAssignmentResult::new(
                "changed report".to_owned(),
                Vec::new(),
                None,
            )?),
            durable.reviewed_by(),
            durable.created_at(),
            durable.updated_at(),
            durable.revision(),
            durable.origin(),
        )?)
    }

    fn assert_assignment_review_append_rejected(
        fixture: &AssignmentFixture,
        assignment_id: AgentAssignmentId,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut connection = Connection::open(fixture.layout.database_path())?;
        connection.pragma_update(None, "foreign_keys", true)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let durable = get_in_transaction(&transaction, assignment_id)?
            .ok_or("cancelled assignment missing")?;
        assert!(matches!(
            crate::workspace_effect_fact_outbox::append_assignment_reviewed(&transaction, &durable,),
            Err(crate::EffectFactOutboxError::AssignmentNotReviewed)
        ));
        transaction.rollback()?;
        drop(connection);
        Ok(())
    }

    fn assert_offer_submit_offer_fact_order(facts: &[crate::EffectFactOutboxEntry]) {
        assert_eq!(
            facts.len(),
            3,
            "no non-review path may emit an assignment-review fact"
        );
        assert!(matches!(
            facts[0].fact(),
            crate::EffectFact::AssignmentOffered(_)
        ));
        assert!(matches!(
            facts[1].fact(),
            crate::EffectFact::AssignmentSubmitted(_)
        ));
        assert!(matches!(
            facts[2].fact(),
            crate::EffectFact::AssignmentOffered(_)
        ));
    }

    #[allow(
        clippy::too_many_lines,
        reason = "One regression proves offer and claim survival while the submit transaction rolls back."
    )]
    #[test]
    fn submit_fact_append_failure_rolls_back_assignment_and_sources()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = fixture()?;
        let _delegation = install_delegation_seal(&mut fixture.store, 0xA2AA, 8)?;
        let offered = fixture.store.offer_agent_assignment(
            &offer_command(
                &fixture,
                0xA2AB,
                target(&fixture.target_a),
                &fixture.nodes[0],
                10,
            ),
            admitted_at()?,
        )?;
        let claimed = fixture.store.claim_agent_assignment(
            &ClaimAgentAssignment::new(
                offered.id(),
                target(&fixture.target_a),
                offered.revision(),
                ts(11)?,
            ),
            admitted_at()?,
        )?;
        let current_target = target(
            &fixture
                .store
                .get_agent(fixture.target_a.id())?
                .ok_or("target missing after claim")?,
        );

        // Abort the payload insert after the outbox header is attempted. The
        // submit must roll its assignment/source writes and the kind-4 header
        // back with the failed payload append.
        let raw = Connection::open(fixture.layout.database_path())?;
        raw.execute_batch(
            "CREATE TRIGGER fail_assignment_submitted_payload
             BEFORE INSERT ON effect_fact_outbox_assignment_submitted
             BEGIN
                 SELECT RAISE(ABORT, 'submit payload failure');
             END;",
        )?;
        drop(raw);
        let result = fixture.store.submit_agent_assignment(
            &SubmitAgentAssignment::new(
                claimed.id(),
                current_target,
                claimed.revision(),
                AgentAssignmentResult::new(
                    "bounded participant report".to_owned(),
                    vec![AgentAssignmentSourceRef::Url(
                        AgentAssignmentSourceUrl::new("https://example.test/source".to_owned())?,
                    )],
                    None,
                )?,
                ts(12)?,
            ),
            admitted_at()?,
        );
        assert!(matches!(
            result,
            Err(WorkspaceStoreError::AgentAssignment(
                AgentAssignmentStoreError::EffectFact(_)
            ))
        ));

        let connection = Connection::open(fixture.layout.database_path())?;
        let (state, revision, source_rows, fact_rows, submitted_rows): (i64, i64, i64, i64, i64) =
            connection.query_row(
                "SELECT
                    (SELECT state FROM agent_assignments WHERE assignment_id=?1),
                    (SELECT revision FROM agent_assignments WHERE assignment_id=?1),
                    (SELECT COUNT(*) FROM agent_assignment_sources WHERE assignment_id=?1),
                    (SELECT COUNT(*) FROM effect_fact_outbox_entries),
                    (SELECT COUNT(*) FROM effect_fact_outbox_entries WHERE fact_kind=4)",
                params![claimed.id().into_uuid().as_bytes()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )?;
        assert_eq!(
            (state, revision, source_rows),
            (1, claimed.revision().get(), 0),
            "failed submit must preserve the Running row, revision, and source set"
        );
        assert_eq!(fact_rows, 1, "the old kind-3 offer receipt must remain");
        assert_eq!(submitted_rows, 0, "no kind-4 receipt may survive rollback");
        let submitted_payload_rows: i64 = connection.query_row(
            "SELECT COUNT(*) FROM effect_fact_outbox_assignment_submitted",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(
            submitted_payload_rows, 0,
            "no kind-4 payload may survive rollback"
        );
        let result: Option<String> = connection.query_row(
            "SELECT report FROM agent_assignments WHERE assignment_id=?1",
            params![claimed.id().into_uuid().as_bytes()],
            |row| row.get(0),
        )?;
        assert_eq!(result, None, "the submitted result must roll back");
        drop(connection);
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn undelegated_submit_has_no_fact_and_autocommit_is_rejected()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = fixture()?;
        let offered = fixture.store.offer_agent_assignment(
            &offer_command(
                &fixture,
                0xA2AC,
                target(&fixture.target_a),
                &fixture.nodes[0],
                10,
            ),
            admitted_at()?,
        )?;
        let claimed = fixture.store.claim_agent_assignment(
            &ClaimAgentAssignment::new(
                offered.id(),
                target(&fixture.target_a),
                offered.revision(),
                ts(11)?,
            ),
            admitted_at()?,
        )?;
        let current_target = target(
            &fixture
                .store
                .get_agent(fixture.target_a.id())?
                .ok_or("target missing after claim")?,
        );
        let submitted = fixture.store.submit_agent_assignment(
            &SubmitAgentAssignment::new(
                claimed.id(),
                current_target,
                claimed.revision(),
                AgentAssignmentResult::new("report".to_owned(), Vec::new(), None)?,
                ts(12)?,
            ),
            admitted_at()?,
        )?;
        assert!(fixture.store.effect_fact_outbox(0, 64)?.is_empty());

        let mut connection = Connection::open(fixture.layout.database_path())?;
        assert!(matches!(
            crate::workspace_effect_fact_outbox::append_assignment_submitted(
                &connection,
                &submitted,
            ),
            Err(crate::EffectFactOutboxError::MissingTransaction)
        ));
        let transaction = connection.transaction()?;
        assert!(matches!(
            crate::workspace_effect_fact_outbox::append_assignment_submitted(
                &transaction,
                &claimed,
            ),
            Err(crate::EffectFactOutboxError::AssignmentNotSubmitted)
        ));
        transaction.rollback()?;
        drop(connection);
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn ordinary_writer_refuses_to_drop_cut_continuation_origin()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = fixture()?;
        let source = fixture.store.offer_agent_assignment(
            &offer_command(
                &fixture,
                0xA9B0,
                target(&fixture.target_a),
                &fixture.nodes[0],
                10,
            ),
            admitted_at()?,
        )?;
        let origin = forge_domain::AgentAssignmentOrigin::CutContinuation(
            forge_domain::AgentAssignmentContinuationOrigin::new(
                Uuid::from_u128(0xA9B1),
                Uuid::from_u128(0xA9B2),
                source.id(),
            )?,
        );
        let candidate = RegisteredAgentAssignment::from_parts(
            AgentAssignmentId::from_uuid(Uuid::from_u128(0xA9B3)),
            source.workspace_id(),
            source.activity_id(),
            source.goal_id(),
            source.goal_created_at(),
            source.goal_revision(),
            source.dag_revision(),
            source.dag_head_revision(),
            source.node_id(),
            source.node_revision(),
            source.coordinator(),
            target(&fixture.coordinator_agent),
            AgentAssignmentState::Offered,
            false,
            source.credit_budget(),
            None,
            None,
            ts(11)?,
            ts(11)?,
            AgentAssignmentRevision::INITIAL,
            origin,
        )?;
        let mut connection = Connection::open(fixture.layout.database_path())?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert!(matches!(
            insert_assignment(&tx, &candidate),
            Err(AgentAssignmentStoreError::Transition(
                AgentAssignmentTransitionError::ContinuationAuthorityRequired
            ))
        ));
        assert!(matches!(
            crate::workspace_effect_fact_outbox::append_assignment_offered(&tx, &candidate),
            Err(crate::EffectFactOutboxError::ContinuationAdmissionFactRequired)
        ));
        assert!(matches!(
            update_assignment(&tx, &source, &candidate),
            Err(AgentAssignmentStoreError::Transition(
                AgentAssignmentTransitionError::ContinuationAuthorityRequired
            ))
        ));
        assert!(matches!(
            update_assignment(&tx, &candidate, &candidate),
            Err(AgentAssignmentStoreError::Transition(
                AgentAssignmentTransitionError::ContinuationAuthorityRequired
            ))
        ));
        assert!(get_in_transaction(&tx, candidate.id())?.is_none());
        assert_eq!(get_in_transaction(&tx, source.id())?, Some(source.clone()));
        tx.commit()?;
        drop(connection);
        assert_eq!(
            fixture.store.get_agent_assignment(source.id())?,
            Some(source)
        );
        drop(fixture.store);
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn promoted_assignment_target_cannot_review_its_own_submitted_result()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = fixture()?;
        let _delegation = install_delegation_seal(&mut fixture.store, 0xA8B0, 8)?;
        let submitted = submitted_assignment_with_budget(
            &mut fixture,
            0xA8C0,
            Some(forge_domain::WorkCreditBudget::Three),
            "submitted before promotion",
            Vec::new(),
        )?;
        let promoted = fixture.store.transfer_activity_coordinator(
            forge_domain::TransferActivityCoordinator::new(
                fixture.coordinator,
                fixture.target_a.id(),
                ts(13)?,
            ),
            admitted_at()?,
        )?;
        let actor = ActivityCoordinatorActor::new(
            fixture.workspace_id,
            fixture.activity_id,
            fixture.target_a.id(),
            promoted.revision(),
            fixture.target_a.principal(),
            fixture
                .target_a
                .session_id()
                .ok_or("target Session missing")?,
        );
        let before_facts = fixture.store.effect_fact_outbox(0, 64)?;
        for accepted in [true, false] {
            let command =
                ReviewAgentAssignment::new(submitted.id(), actor, submitted.revision(), ts(14)?);
            let result = if accepted {
                fixture
                    .store
                    .accept_agent_assignment(&command, admitted_at()?)
            } else {
                fixture
                    .store
                    .reject_agent_assignment(&command, admitted_at()?)
            };
            assert!(
                matches!(
                    result,
                    Err(WorkspaceStoreError::AgentAssignment(
                        AgentAssignmentStoreError::Transition(
                            AgentAssignmentTransitionError::CoordinatorTargetSameAgent
                        )
                    ))
                ),
                "promotion must not permit self-review"
            );
            assert_eq!(
                fixture.store.get_agent_assignment(submitted.id())?,
                Some(submitted.clone())
            );
            assert_eq!(fixture.store.effect_fact_outbox(0, 64)?, before_facts);
        }
        let returned = fixture.store.transfer_activity_coordinator(
            forge_domain::TransferActivityCoordinator::new(
                actor,
                fixture.coordinator_agent.id(),
                ts(15)?,
            ),
            admitted_at()?,
        )?;
        let independent = ActivityCoordinatorActor::new(
            fixture.workspace_id,
            fixture.activity_id,
            fixture.coordinator_agent.id(),
            returned.revision(),
            fixture.coordinator_agent.principal(),
            fixture
                .coordinator_agent
                .session_id()
                .ok_or("Coordinator Session missing")?,
        );
        let accepted = fixture.store.accept_agent_assignment(
            &ReviewAgentAssignment::new(submitted.id(), independent, submitted.revision(), ts(16)?),
            admitted_at()?,
        )?;
        assert_eq!(accepted.state(), AgentAssignmentState::Accepted);
        let reviews: Vec<_> = fixture
            .store
            .effect_fact_outbox(0, 64)?
            .into_iter()
            .filter_map(|entry| {
                if let crate::EffectFact::AssignmentReviewed(fact) = entry.fact() {
                    Some(*fact.as_ref())
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(reviews.len(), 1);
        assert_eq!(reviews[0].reviewer_agent_id(), independent.agent_id());
        assert_eq!(reviews[0].target_agent_id(), fixture.target_a.id());
        drop(fixture.store);
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn accept_emits_exactly_one_assignment_reviewed_fact_with_exact_replay()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = fixture()?;
        let delegation = install_delegation_seal(&mut fixture.store, 0xA2B0, 8)?;
        let report = "bounded participant report";
        let submitted = submitted_assignment_with_budget(
            &mut fixture,
            0xA2C0,
            Some(forge_domain::WorkCreditBudget::Three),
            report,
            Vec::new(),
        )?;
        let expected_digest: [u8; 32] = {
            use sha2::{Digest, Sha256};
            Sha256::digest(report.as_bytes()).into()
        };
        let accepted = fixture.store.accept_agent_assignment(
            &ReviewAgentAssignment::new(
                submitted.id(),
                fixture.coordinator,
                submitted.revision(),
                ts(13)?,
            ),
            admitted_at()?,
        )?;
        assert_eq!(accepted.state(), AgentAssignmentState::Accepted);

        let mut replay_connection = Connection::open(fixture.layout.database_path())?;
        replay_connection.pragma_update(None, "foreign_keys", true)?;
        let replay_transaction =
            replay_connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let durable_accepted = get_in_transaction(&replay_transaction, accepted.id())?
            .ok_or("accepted assignment missing")?;
        crate::workspace_effect_fact_outbox::append_assignment_submitted(
            &replay_transaction,
            &durable_accepted,
        )?;
        replay_transaction.commit()?;
        drop(replay_connection);

        // The offer and submit inside this lifecycle emit kind-3 and kind-4
        // receipts; the review appends exactly one kind-2 fact beside them.
        let facts = fixture.store.effect_fact_outbox(0, 64)?;
        assert_eq!(facts.len(), 3, "offer + submit + review emit three facts");
        assert!(matches!(
            facts[0].fact(),
            crate::EffectFact::AssignmentOffered(_)
        ));
        assert!(matches!(
            facts[1].fact(),
            crate::EffectFact::AssignmentSubmitted(_)
        ));
        let Some(submitted_fact) = facts.iter().find_map(|entry| match entry.fact() {
            crate::EffectFact::AssignmentSubmitted(fact) => Some(fact.as_ref()),
            _ => None,
        }) else {
            return Err("the submitted lifecycle must retain its kind-4 fact".into());
        };
        assert_eq!(submitted_fact.submitted_at(), ts(12)?);
        let entry = &facts[2];
        assert_eq!(entry.sequence(), 3);
        assert_eq!(entry.migration_id(), delegation.migration_id());
        assert_eq!(entry.destination_id(), delegation.destination_id());
        assert_eq!(entry.workspace_id(), fixture.workspace_id);
        let crate::EffectFact::AssignmentReviewed(fact) = entry.fact() else {
            return Err("the review must emit an assignment-review fact".into());
        };
        assert_eq!(fact.assignment_id(), submitted.id());
        assert_eq!(fact.workspace_id(), fixture.workspace_id);
        assert_eq!(fact.activity_id(), fixture.activity_id);
        assert_eq!(fact.goal_id(), fixture.goal.id());
        assert_eq!(fact.node_id(), fixture.nodes[0].id());
        assert_eq!(fact.target_agent_id(), fixture.target_a.id());
        assert_eq!(
            fact.target_session_id(),
            fixture.target_a.session_id(),
            "the fact must carry the exact bound target session"
        );
        assert_eq!(fact.outcome(), crate::AssignmentReviewedOutcome::Accepted);
        assert_eq!(
            fact.credit_budget(),
            Some(forge_domain::WorkCreditBudget::Three)
        );
        assert_eq!(fact.reviewer_agent_id(), fixture.coordinator.agent_id());
        assert_eq!(
            fact.reviewer_session_id(),
            Some(fixture.coordinator.session_id())
        );
        assert_eq!(fact.result_digest(), Some(expected_digest));
        assert_eq!(fact.observed_at(), ts(13)?);

        assert_exact_replay_then_conflict(&fixture, submitted.id())?;
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    /// Exact replay of the durable post-review row must be a no-op, while a
    /// payload that differs from the durable identity must conflict.
    fn assert_exact_replay_then_conflict(
        fixture: &AssignmentFixture,
        assignment_id: AgentAssignmentId,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut replay_connection = Connection::open(fixture.layout.database_path())?;
        replay_connection.pragma_update(None, "foreign_keys", true)?;
        let replay_transaction =
            replay_connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let durable = get_in_transaction(&replay_transaction, assignment_id)?
            .ok_or("submitted assignment missing")?;
        crate::workspace_effect_fact_outbox::append_assignment_reviewed(
            &replay_transaction,
            &durable,
        )?;
        replay_transaction.commit()?;
        drop(replay_connection);
        assert_eq!(
            fixture.store.effect_fact_outbox(0, 64)?.len(),
            3,
            "exact replay must not duplicate the review fact"
        );

        let tamper = Connection::open(fixture.layout.database_path())?;
        tamper.execute(
            "UPDATE effect_fact_outbox_assignment_review SET outcome = 'Rejected'",
            [],
        )?;
        drop(tamper);
        let mut conflict_connection = Connection::open(fixture.layout.database_path())?;
        let conflict_transaction =
            conflict_connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let durable = get_in_transaction(&conflict_transaction, assignment_id)?
            .ok_or("submitted assignment missing")?;
        assert!(matches!(
            crate::workspace_effect_fact_outbox::append_assignment_reviewed(
                &conflict_transaction,
                &durable,
            ),
            Err(crate::EffectFactOutboxError::ReplayConflict)
        ));
        conflict_transaction.rollback()?;
        drop(conflict_connection);
        assert_eq!(
            fixture.store.effect_fact_outbox(0, 64)?.len(),
            3,
            "a conflicting retry must not mutate the durable fact"
        );
        Ok(())
    }

    #[test]
    fn review_fact_append_failure_rolls_back_the_accept() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut fixture = fixture()?;
        let _delegation = install_delegation_seal(&mut fixture.store, 0xA2D0, 8)?;
        let submitted = submitted_assignment_with_budget(
            &mut fixture,
            0xA2E0,
            None,
            "bounded participant report",
            Vec::new(),
        )?;

        // Remove the delegation authority the fact protocol depends on while
        // the database still claims a current schema. The review must fail
        // closed and roll the state CAS back with it.
        let raw = Connection::open(fixture.layout.database_path())?;
        raw.execute_batch("DROP TABLE agent_operations_delegations")?;
        drop(raw);
        let result = fixture.store.accept_agent_assignment(
            &ReviewAgentAssignment::new(
                submitted.id(),
                fixture.coordinator,
                submitted.revision(),
                ts(13)?,
            ),
            admitted_at()?,
        );
        assert!(matches!(
            result,
            Err(WorkspaceStoreError::AgentAssignment(
                AgentAssignmentStoreError::EffectFact(_)
            ))
        ));

        let conn = Connection::open(fixture.layout.database_path())?;
        let (state, revision): (i64, i64) = conn.query_row(
            "SELECT state, revision FROM agent_assignments WHERE assignment_id = ?1",
            params![submitted.id().into_uuid().as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        assert_eq!(
            (state, revision),
            (2, submitted.revision().get()),
            "the assignment must remain Submitted at its pre-review revision"
        );
        let fact_rows: i64 = conn.query_row(
            "SELECT COUNT(*) FROM effect_fact_outbox_entries",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(
            fact_rows, 2,
            "the pre-existing offer and submitted facts must survive the rollback"
        );
        let review_rows: i64 = conn.query_row(
            "SELECT COUNT(*) FROM effect_fact_outbox_assignment_review",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(
            review_rows, 0,
            "no review fact rows may survive the rollback"
        );
        drop(conn);
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn interrupt_round_trips_as_interrupted_with_cancellation_requested()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = fixture()?;
        let _delegation = install_delegation_seal(&mut fixture.store, 0xA2FD, 8)?;
        let offered = fixture.store.offer_agent_assignment(
            &offer_command(
                &fixture,
                0xA300,
                target(&fixture.target_a),
                &fixture.nodes[0],
                10,
            ),
            admitted_at()?,
        )?;
        let claimed = fixture.store.claim_agent_assignment(
            &ClaimAgentAssignment::new(
                offered.id(),
                target(&fixture.target_a),
                offered.revision(),
                ts(11)?,
            ),
            admitted_at()?,
        )?;
        let interrupted =
            fixture
                .store
                .interrupt_agent_assignment(&InterruptAgentAssignment::new(
                    claimed.id(),
                    claimed.revision(),
                    ts(12)?,
                ))?;
        assert_eq!(interrupted.state(), AgentAssignmentState::Interrupted);
        assert!(interrupted.cancellation_requested());
        drop(fixture.store);
        let existing =
            WorkspaceStateLayout::inspect_existing(&fixture.root)?.ok_or("layout missing")?;
        let reopened = WorkspaceStore::open_existing(&existing)?;
        let read_back = reopened
            .get_agent_assignment(claimed.id())?
            .ok_or("interrupted assignment missing after reopen")?;
        assert_eq!(read_back.state(), AgentAssignmentState::Interrupted);
        assert!(
            read_back.cancellation_requested(),
            "the durable Interrupted row must keep the cancellation flag the schema CHECK allows"
        );
        let facts = reopened.effect_fact_outbox(0, 64)?;
        assert_eq!(facts.len(), 1, "interrupt must not add a kind-4 fact");
        assert!(matches!(
            facts[0].fact(),
            crate::EffectFact::AssignmentOffered(_)
        ));
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn offer_emits_exactly_one_assignment_offered_fact_with_exact_replay()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = fixture()?;
        // Without the delegation seal the offer fact is a deliberate no-op.
        let unsealed = fixture.store.offer_agent_assignment(
            &offer_command_budgeted(
                &fixture,
                0xA310,
                target(&fixture.target_b),
                &fixture.nodes[1],
                9,
                Some(forge_domain::WorkCreditBudget::One),
            ),
            admitted_at()?,
        )?;
        assert_eq!(unsealed.state(), AgentAssignmentState::Offered);
        assert!(
            fixture.store.effect_fact_outbox(0, 64)?.is_empty(),
            "an offer without a delegation seal must not emit a fact"
        );

        let delegation = install_delegation_seal(&mut fixture.store, 0xA311, 9)?;
        let offered = fixture.store.offer_agent_assignment(
            &offer_command_budgeted(
                &fixture,
                0xA312,
                target(&fixture.target_a),
                &fixture.nodes[0],
                10,
                Some(forge_domain::WorkCreditBudget::Three),
            ),
            admitted_at()?,
        )?;
        assert_eq!(offered.state(), AgentAssignmentState::Offered);

        let facts = fixture.store.effect_fact_outbox(0, 64)?;
        assert_eq!(facts.len(), 1, "one offer must emit exactly one fact");
        let entry = &facts[0];
        assert_eq!(entry.sequence(), 1);
        assert_eq!(entry.migration_id(), delegation.migration_id());
        assert_eq!(entry.destination_id(), delegation.destination_id());
        assert_eq!(entry.workspace_id(), fixture.workspace_id);
        let crate::EffectFact::AssignmentOffered(fact) = entry.fact() else {
            return Err("the offer must emit an assignment-offer fact".into());
        };
        assert_eq!(fact.assignment_id(), offered.id());
        assert_eq!(fact.workspace_id(), fixture.workspace_id);
        assert_eq!(fact.activity_id(), fixture.activity_id);
        assert_eq!(fact.goal_id(), fixture.goal.id());
        assert_eq!(fact.node_id(), fixture.nodes[0].id());
        assert_eq!(fact.target_agent_id(), fixture.target_a.id());
        assert_eq!(
            fact.target_session_id(),
            fixture.target_a.session_id(),
            "the fact must carry the exact bound target session"
        );
        assert_eq!(
            fact.credit_budget(),
            Some(forge_domain::WorkCreditBudget::Three)
        );
        assert_eq!(fact.offered_at(), ts(10)?);

        assert_offer_exact_replay_then_conflict(&fixture, offered.id())?;
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    /// Exact replay of the durable post-offer row must be a no-op, while a
    /// payload that differs from the durable identity must conflict.
    fn assert_offer_exact_replay_then_conflict(
        fixture: &AssignmentFixture,
        assignment_id: AgentAssignmentId,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut replay_connection = Connection::open(fixture.layout.database_path())?;
        replay_connection.pragma_update(None, "foreign_keys", true)?;
        let replay_transaction =
            replay_connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let durable = get_in_transaction(&replay_transaction, assignment_id)?
            .ok_or("offered assignment missing")?;
        crate::workspace_effect_fact_outbox::append_assignment_offered(
            &replay_transaction,
            &durable,
        )?;
        replay_transaction.commit()?;
        drop(replay_connection);
        assert_eq!(
            fixture.store.effect_fact_outbox(0, 64)?.len(),
            1,
            "exact replay must not duplicate the fact"
        );

        let tamper = Connection::open(fixture.layout.database_path())?;
        tamper.execute(
            "UPDATE effect_fact_outbox_assignment_offered SET credit_budget = 5",
            [],
        )?;
        drop(tamper);
        let mut conflict_connection = Connection::open(fixture.layout.database_path())?;
        let conflict_transaction =
            conflict_connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let durable = get_in_transaction(&conflict_transaction, assignment_id)?
            .ok_or("offered assignment missing")?;
        assert!(matches!(
            crate::workspace_effect_fact_outbox::append_assignment_offered(
                &conflict_transaction,
                &durable,
            ),
            Err(crate::EffectFactOutboxError::ReplayConflict)
        ));
        conflict_transaction.rollback()?;
        drop(conflict_connection);
        assert_eq!(
            fixture.store.effect_fact_outbox(0, 64)?.len(),
            1,
            "a conflicting retry must not mutate the durable fact"
        );
        Ok(())
    }

    #[test]
    fn offer_fact_append_failure_rolls_back_the_offer() -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = fixture()?;
        let _delegation = install_delegation_seal(&mut fixture.store, 0xA320, 8)?;

        // Remove the delegation authority the fact protocol depends on while
        // the database still claims a current schema. The offer must fail
        // closed and roll the durable insert back with it.
        let raw = Connection::open(fixture.layout.database_path())?;
        raw.execute_batch("DROP TABLE agent_operations_delegations")?;
        drop(raw);
        let result = fixture.store.offer_agent_assignment(
            &offer_command(
                &fixture,
                0xA321,
                target(&fixture.target_a),
                &fixture.nodes[0],
                10,
            ),
            admitted_at()?,
        );
        assert!(matches!(
            result,
            Err(WorkspaceStoreError::AgentAssignment(
                AgentAssignmentStoreError::EffectFact(_)
            ))
        ));

        let conn = Connection::open(fixture.layout.database_path())?;
        let assignment_rows: i64 =
            conn.query_row("SELECT COUNT(*) FROM agent_assignments", [], |row| {
                row.get(0)
            })?;
        assert_eq!(
            assignment_rows, 0,
            "the offer must not survive the failed fact append"
        );
        let fact_rows: i64 = conn.query_row(
            "SELECT COUNT(*) FROM effect_fact_outbox_entries",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(fact_rows, 0, "no fact rows may survive the rollback");
        drop(conn);
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn claim_submit_and_review_add_no_assignment_offered_facts()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = fixture()?;
        let delegation = install_delegation_seal(&mut fixture.store, 0xA330, 8)?;
        let offered = fixture.store.offer_agent_assignment(
            &offer_command_budgeted(
                &fixture,
                0xA331,
                target(&fixture.target_a),
                &fixture.nodes[0],
                10,
                Some(forge_domain::WorkCreditBudget::Five),
            ),
            admitted_at()?,
        )?;
        assert_eq!(fixture.store.effect_fact_outbox(0, 64)?.len(), 1);
        let claimed = fixture.store.claim_agent_assignment(
            &ClaimAgentAssignment::new(
                offered.id(),
                target(&fixture.target_a),
                offered.revision(),
                ts(11)?,
            ),
            admitted_at()?,
        )?;
        assert_eq!(
            fixture.store.effect_fact_outbox(0, 64)?.len(),
            1,
            "claim must not add an offer fact"
        );
        let current_target = target(
            &fixture
                .store
                .get_agent(fixture.target_a.id())?
                .ok_or("target missing after claim")?,
        );
        let submitted = fixture.store.submit_agent_assignment(
            &SubmitAgentAssignment::new(
                claimed.id(),
                current_target,
                claimed.revision(),
                AgentAssignmentResult::new("report".to_owned(), Vec::new(), None)?,
                ts(12)?,
            ),
            admitted_at()?,
        )?;
        assert_eq!(submitted.state(), AgentAssignmentState::Submitted);
        assert_eq!(
            fixture.store.effect_fact_outbox(0, 64)?.len(),
            2,
            "submit must not add another offer fact"
        );
        let accepted = fixture.store.accept_agent_assignment(
            &ReviewAgentAssignment::new(
                submitted.id(),
                fixture.coordinator,
                submitted.revision(),
                ts(13)?,
            ),
            admitted_at()?,
        )?;
        assert_eq!(accepted.state(), AgentAssignmentState::Accepted);
        let facts = fixture.store.effect_fact_outbox(0, 64)?;
        assert_eq!(
            facts.len(),
            3,
            "submit and review each add exactly one lifecycle fact"
        );
        assert_eq!(facts[0].migration_id(), delegation.migration_id());
        assert!(matches!(
            facts[0].fact(),
            crate::EffectFact::AssignmentOffered(_)
        ));
        assert!(matches!(
            facts[1].fact(),
            crate::EffectFact::AssignmentSubmitted(_)
        ));
        assert!(matches!(
            facts[2].fact(),
            crate::EffectFact::AssignmentReviewed(_)
        ));

        // Terminal non-offer states are rejected at the fact layer itself.
        let mut rejection_connection = Connection::open(fixture.layout.database_path())?;
        rejection_connection.pragma_update(None, "foreign_keys", true)?;
        let rejection_transaction =
            rejection_connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let durable_accepted = get_in_transaction(&rejection_transaction, accepted.id())?
            .ok_or("accepted assignment missing")?;
        assert!(matches!(
            crate::workspace_effect_fact_outbox::append_assignment_offered(
                &rejection_transaction,
                &durable_accepted,
            ),
            Err(crate::EffectFactOutboxError::AssignmentNotOffered)
        ));
        rejection_transaction.rollback()?;
        drop(rejection_connection);
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn claim_submit_and_cancel_emit_no_assignment_review_facts()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = fixture()?;
        let _delegation = install_delegation_seal(&mut fixture.store, 0xA2F0, 8)?;
        let offered = fixture.store.offer_agent_assignment(
            &offer_command_budgeted(
                &fixture,
                0xA2F1,
                target(&fixture.target_a),
                &fixture.nodes[0],
                10,
                Some(forge_domain::WorkCreditBudget::Five),
            ),
            admitted_at()?,
        )?;
        assert_eq!(
            fixture.store.effect_fact_outbox(0, 64)?.len(),
            1,
            "the offer itself emits exactly one offer fact"
        );
        let claimed = fixture.store.claim_agent_assignment(
            &ClaimAgentAssignment::new(
                offered.id(),
                target(&fixture.target_a),
                offered.revision(),
                ts(11)?,
            ),
            admitted_at()?,
        )?;
        assert_eq!(
            fixture.store.effect_fact_outbox(0, 64)?.len(),
            1,
            "claim must not emit a review fact"
        );
        let current_target = target(
            &fixture
                .store
                .get_agent(fixture.target_a.id())?
                .ok_or("target missing after claim")?,
        );
        let submitted = fixture.store.submit_agent_assignment(
            &SubmitAgentAssignment::new(
                claimed.id(),
                current_target,
                claimed.revision(),
                AgentAssignmentResult::new("report".to_owned(), Vec::new(), None)?,
                ts(12)?,
            ),
            admitted_at()?,
        )?;
        assert_eq!(submitted.state(), AgentAssignmentState::Submitted);
        assert_eq!(
            fixture.store.effect_fact_outbox(0, 64)?.len(),
            2,
            "submit emits one submitted fact and no review fact"
        );

        // The cancel path is a terminal non-review mutation: it must never
        // emit an assignment-review fact.
        let offered_cancel = fixture.store.offer_agent_assignment(
            &offer_command(
                &fixture,
                0xA2F2,
                target(&fixture.target_b),
                &fixture.nodes[1],
                14,
            ),
            admitted_at()?,
        )?;
        assert_eq!(
            fixture.store.effect_fact_outbox(0, 64)?.len(),
            3,
            "the second offer emits exactly its own offer fact"
        );
        let cancelled = fixture
            .store
            .cancel_agent_assignment(&CancelAgentAssignment::new(
                offered_cancel.id(),
                fixture.coordinator,
                offered_cancel.revision(),
                ts(15)?,
            ))?;
        assert_eq!(cancelled.state(), AgentAssignmentState::Cancelled);
        let facts = fixture.store.effect_fact_outbox(0, 64)?;
        assert_offer_submit_offer_fact_order(&facts);

        // Terminal non-review states are rejected at the fact layer itself.
        assert_assignment_review_append_rejected(&fixture, cancelled.id())?;
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }
}
