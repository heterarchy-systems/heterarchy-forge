//! Bounded source-owned work inventory for a trusted Operations roster.
//!
//! Every read observes one `SQLite` snapshot. This is deliberately an observation,
//! not a durable cut, admission fence, transfer grant, or completed handoff.
//! The future custody transaction must call the in-transaction reader and collect
//! unsettled effects before installing fences; it must not persist an old preview.
//! Team node witnesses filter work held by this roster. Unclaimed queue items
//! and work held by other Team members are not assigned a fictitious roster owner.
//! An empty result does not mean an empty Team queue or a completed transfer.
//! Entries retain each Agent/node relationship; shared focus is not exclusive
//! ownership. Focus and assignment merge only for the same Agent and node.

use std::collections::BTreeMap;

use forge_domain::{
    ActivityId, AgentAssignmentId, AgentAssignmentRevision, AgentAssignmentState, AgentFocus,
    AgentInstanceId, AgentInstanceRevision, DagHeadRevision, DagNodeId, DagNodeRevision,
    DagNodeStatus, DagRevisionNumber, GoalId, GoalRevision, MAX_WORK_CUT_BINDINGS,
    RegisteredAgentInstance, TimestampMillis, WorkCutBinding, WorkCutNodeScope, WorkCutRequest,
    WorkCutRequestDigest, WorkCutScope,
};
use rusqlite::{
    Connection, OptionalExtension, Transaction, params, params_from_iter, types::Value,
};
use thiserror::Error;
use uuid::Uuid;

use crate::{workspace_agent_assignments, workspace_agent_migration, workspace_agents};

const MAX_WORK_INVENTORY_ENTRIES: usize = 256;

#[derive(Debug, Error)]
pub enum WorkInventoryError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Agent(#[from] Box<crate::AgentStoreError>),
    #[error(transparent)]
    Assignment(#[from] Box<crate::AgentAssignmentStoreError>),
    #[error(transparent)]
    Migration(#[from] Box<crate::AgentOperationsMigrationError>),
    #[error("work inventory authority conflict: {0}")]
    Conflict(&'static str),
    #[error("work inventory corrupt source: {0}")]
    Corrupt(&'static str),
    #[error("work inventory exceeds its complete-result bound")]
    Bounds,
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkInventoryAgent {
    pub(crate) binding: WorkCutBinding,
    pub(crate) revision: AgentInstanceRevision,
    pub(crate) focus: AgentFocus,
}
impl WorkInventoryAgent {
    pub const fn binding(self) -> WorkCutBinding {
        self.binding
    }
    pub const fn revision(self) -> AgentInstanceRevision {
        self.revision
    }
    pub const fn focus(self) -> AgentFocus {
        self.focus
    }
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkInventoryAssignment {
    pub(crate) assignment_id: AgentAssignmentId,
    pub(crate) revision: AgentAssignmentRevision,
    pub(crate) state: AgentAssignmentState,
    pub(crate) cancellation_requested: bool,
}
impl WorkInventoryAssignment {
    pub const fn assignment_id(self) -> AgentAssignmentId {
        self.assignment_id
    }
    pub const fn revision(self) -> AgentAssignmentRevision {
        self.revision
    }
    pub const fn state(self) -> AgentAssignmentState {
        self.state
    }
    #[must_use]
    pub const fn cancellation_requested(self) -> bool {
        self.cancellation_requested
    }
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkInventoryNode {
    pub(crate) agent_id: AgentInstanceId,
    pub(crate) scope: WorkCutNodeScope,
    pub(crate) goal_revision: GoalRevision,
    pub(crate) head_dag_revision: DagRevisionNumber,
    pub(crate) head_revision: DagHeadRevision,
    pub(crate) node_revision: DagNodeRevision,
    pub(crate) node_state: DagNodeStatus,
    pub(crate) direct_focus: bool,
    pub(crate) assignment: Option<WorkInventoryAssignment>,
}
impl WorkInventoryNode {
    pub const fn agent_id(self) -> AgentInstanceId {
        self.agent_id
    }
    pub const fn scope(self) -> WorkCutNodeScope {
        self.scope
    }
    pub const fn goal_revision(self) -> GoalRevision {
        self.goal_revision
    }
    pub const fn head_dag_revision(self) -> DagRevisionNumber {
        self.head_dag_revision
    }
    pub const fn head_revision(self) -> DagHeadRevision {
        self.head_revision
    }
    pub const fn node_revision(self) -> DagNodeRevision {
        self.node_revision
    }
    pub const fn node_state(self) -> DagNodeStatus {
        self.node_state
    }
    #[must_use]
    pub const fn direct_focus(self) -> bool {
        self.direct_focus
    }
    #[must_use]
    pub const fn assignment(self) -> Option<WorkInventoryAssignment> {
        self.assignment
    }
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkCutInventory {
    pub(crate) request_digest: WorkCutRequestDigest,
    pub(crate) agents: Vec<WorkInventoryAgent>,
    pub(crate) nodes: Vec<WorkInventoryNode>,
}
impl WorkCutInventory {
    pub const fn request_digest(&self) -> WorkCutRequestDigest {
        self.request_digest
    }
    pub fn agents(&self) -> &[WorkInventoryAgent] {
        &self.agents
    }
    pub fn nodes(&self) -> &[WorkInventoryNode] {
        &self.nodes
    }
}

type NodeEntries = BTreeMap<(WorkCutNodeScope, AgentInstanceId), WorkInventoryNode>;

pub(crate) fn observe(
    connection: &Connection,
    request: &WorkCutRequest,
) -> Result<WorkCutInventory, WorkInventoryError> {
    let transaction = connection.unchecked_transaction()?;
    let result = observe_in_transaction(&transaction, request)?;
    transaction.commit()?;
    Ok(result)
}

/// Use inside the eventual custody write transaction, never from an old preview.
pub(crate) fn observe_in_transaction(
    tx: &Transaction<'_>,
    request: &WorkCutRequest,
) -> Result<WorkCutInventory, WorkInventoryError> {
    validate_source(tx, request)?;
    let agents = load_agents(tx, request)?;
    validate_team_nodes(tx, request)?;
    ensure_active_targets(tx, request)?;
    let mut nodes = BTreeMap::new();
    for agent in &agents {
        collect_focus(tx, request, *agent, &mut nodes)?;
        collect_assignments(tx, request, *agent, &mut nodes)?;
    }
    Ok(WorkCutInventory {
        request_digest: request.request_digest(),
        agents,
        nodes: nodes.into_values().collect(),
    })
}

fn validate_source(
    tx: &Transaction<'_>,
    request: &WorkCutRequest,
) -> Result<(), WorkInventoryError> {
    let (workspace, revision): (Vec<u8>, i64) = tx.query_row(
        "SELECT substr(workspace_id,1,17),revision FROM workspace WHERE singleton=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if id(&workspace)? != request.workspace_id().into_uuid()
        || revision != request.workspace_revision().get()
    {
        return Err(WorkInventoryError::Conflict(
            "workspace identity or revision",
        ));
    }
    let delegation = workspace_agent_migration::delegation(tx)
        .map_err(|error| WorkInventoryError::Migration(Box::new(error)))?
        .ok_or(WorkInventoryError::Conflict("workspace is not delegated"))?;
    if delegation.workspace_id() != request.workspace_id()
        || delegation.destination_id() != request.destination_id()
    {
        return Err(WorkInventoryError::Conflict("Operations destination"));
    }
    Ok(())
}

fn load_agents(
    tx: &Transaction<'_>,
    request: &WorkCutRequest,
) -> Result<Vec<WorkInventoryAgent>, WorkInventoryError> {
    // Only placeholders are composed. All identities are bound values. The
    // domain bounds Sessions to128, and the query probes one past the Agent cap.
    let slots = vec!["?"; request.sessions().len()].join(",");
    let sql = format!(
        "SELECT substr(agent_id,1,17) FROM agent_instances WHERE workspace_id=? AND attachment_state=0 AND session_id IN ({slots}) ORDER BY agent_id LIMIT 257"
    );
    let values = std::iter::once(Value::Blob(
        request.workspace_id().into_uuid().as_bytes().to_vec(),
    ))
    .chain(
        request
            .sessions()
            .iter()
            .map(|s| Value::Blob(s.session_id().into_uuid().as_bytes().to_vec())),
    );
    let mut statement = tx.prepare(&sql)?;
    let ids = statement
        .query_map(params_from_iter(values), |row| row.get::<_, Vec<u8>>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    if ids.len() > MAX_WORK_CUT_BINDINGS {
        return Err(WorkInventoryError::Bounds);
    }
    if ids.len() != request.bindings().len() {
        return Err(WorkInventoryError::Conflict(
            "source binding roster differs",
        ));
    }
    ids.into_iter()
        .zip(request.bindings())
        .map(|(raw, expected)| {
            let agent =
                workspace_agents::get_in_transaction(tx, AgentInstanceId::from_uuid(id(&raw)?))
                    .map_err(|error| WorkInventoryError::Agent(Box::new(error)))?
                    .ok_or(WorkInventoryError::Corrupt("source Agent disappeared"))?;
            checked_agent(&agent, *expected)
        })
        .collect()
}

fn checked_agent(
    agent: &RegisteredAgentInstance,
    expected: WorkCutBinding,
) -> Result<WorkInventoryAgent, WorkInventoryError> {
    if agent.id() != expected.agent_id()
        || agent.activity_id() != expected.activity_id()
        || agent.session_id() != Some(expected.session_id())
        || agent.principal() != expected.principal()
    {
        return Err(WorkInventoryError::Conflict("source binding identity"));
    }
    Ok(WorkInventoryAgent {
        binding: expected,
        revision: agent.revision(),
        focus: agent.focus(),
    })
}

fn validate_team_nodes(
    tx: &Transaction<'_>,
    request: &WorkCutRequest,
) -> Result<(), WorkInventoryError> {
    if let WorkCutScope::Team { nodes, .. } = request.scope() {
        for expected in nodes {
            let actual = load_node(
                tx,
                request,
                Some(expected.activity_id()),
                expected.goal_id(),
                expected.dag_revision(),
                expected.node_id(),
            )?;
            if actual.scope != *expected {
                return Err(WorkInventoryError::Conflict("Team node generation"));
            }
        }
    }
    Ok(())
}

/// A retired binding is not evidence that its active assignment ended.
/// Test both Session references so a mismatched actor/target cannot disappear.
fn ensure_active_targets(
    tx: &Transaction<'_>,
    request: &WorkCutRequest,
) -> Result<(), WorkInventoryError> {
    let slots = vec!["?"; request.sessions().len()].join(",");
    let predicate = format!(
        "a.workspace_id=? AND a.state IN(0,1,2) AND (a.target_session_id IN ({slots}) OR g.session_id IN ({slots})) AND (g.agent_id IS NULL OR g.attachment_state!=0 OR g.session_id IS NOT a.target_session_id)"
    );
    let mut values = vec![Value::Blob(
        request.workspace_id().into_uuid().as_bytes().to_vec(),
    )];
    for _ in 0..2 {
        values.extend(
            request
                .sessions()
                .iter()
                .map(|s| Value::Blob(s.session_id().into_uuid().as_bytes().to_vec())),
        );
    }
    let source = "FROM agent_assignments a LEFT JOIN agent_instances g ON g.agent_id=a.target_agent_id AND g.workspace_id=a.workspace_id";
    let found = match request.scope() {
        WorkCutScope::Workspace => tx.query_row(
            &format!("SELECT EXISTS(SELECT 1 {source} WHERE {predicate})"),
            params_from_iter(&values),
            |r| r.get::<_, bool>(0),
        )?,
        WorkCutScope::Team { nodes, .. } => {
            let query = format!(
                "SELECT EXISTS(SELECT 1 {source} WHERE {predicate} AND a.activity_id=? AND a.goal_id=? AND a.goal_created_at_ms=? AND a.dag_revision=? AND a.node_id=?)"
            );
            let mut statement = tx.prepare(&query)?;
            let mut unresolved = false;
            for node in nodes {
                let scope = [
                    Value::Blob(node.activity_id().into_uuid().as_bytes().to_vec()),
                    Value::Blob(node.goal_id().into_uuid().as_bytes().to_vec()),
                    Value::Integer(node.goal_created_at().get()),
                    Value::Integer(node.dag_revision().get()),
                    Value::Blob(node.node_id().into_uuid().as_bytes().to_vec()),
                ];
                if statement
                    .query_row(params_from_iter(values.iter().chain(scope.iter())), |r| {
                        r.get::<_, bool>(0)
                    })?
                {
                    unresolved = true;
                    break;
                }
            }
            unresolved
        }
    };
    if found {
        return Err(WorkInventoryError::Conflict(
            "active assignment lacks attached source target",
        ));
    }
    Ok(())
}

fn collect_focus(
    tx: &Transaction<'_>,
    request: &WorkCutRequest,
    agent: WorkInventoryAgent,
    output: &mut NodeEntries,
) -> Result<(), WorkInventoryError> {
    let Some(goal) = agent.focus.goal() else {
        return Ok(());
    };
    let (Some(dag), Some(node)) = (agent.focus.dag_revision(), agent.focus.node()) else {
        let relevant = match request.scope() {
            WorkCutScope::Workspace => true,
            WorkCutScope::Team { nodes, .. } => nodes.iter().any(|n| n.goal_id() == goal.goal_id()),
        };
        return if relevant {
            Err(WorkInventoryError::Conflict(
                "Goal-only focus needs disposition",
            ))
        } else {
            Ok(())
        };
    };
    let observed = load_node(tx, request, None, goal.goal_id(), dag, node.node_id())?;
    if selected(request, observed.scope) {
        insert_node(
            output,
            observed.for_actor(agent.binding.agent_id(), true, None),
        )?;
    }
    Ok(())
}

fn collect_assignments(
    tx: &Transaction<'_>,
    request: &WorkCutRequest,
    agent: WorkInventoryAgent,
    output: &mut NodeEntries,
) -> Result<(), WorkInventoryError> {
    let mut q=tx.prepare("SELECT substr(assignment_id,1,17) FROM agent_assignments WHERE workspace_id=?1 AND target_agent_id=?2 AND state IN(0,1,2) ORDER BY assignment_id LIMIT 257")?;
    let ids = q
        .query_map(
            params![
                request.workspace_id().into_uuid().as_bytes(),
                agent.binding.agent_id().into_uuid().as_bytes()
            ],
            |row| row.get::<_, Vec<u8>>(0),
        )?
        .collect::<Result<Vec<_>, _>>()?;
    if ids.len() > MAX_WORK_INVENTORY_ENTRIES {
        return Err(WorkInventoryError::Bounds);
    }
    for raw in ids {
        let a = workspace_agent_assignments::get_in_transaction(
            tx,
            AgentAssignmentId::from_uuid(id(&raw)?),
        )
        .map_err(|error| WorkInventoryError::Assignment(Box::new(error)))?
        .ok_or(WorkInventoryError::Corrupt("source assignment disappeared"))?;
        if a.activity_id() != agent.binding.activity_id()
            || a.target().session_id() != agent.binding.session_id()
            || a.target().principal() != agent.binding.principal()
        {
            return Err(WorkInventoryError::Conflict("assignment target"));
        }
        let observed = load_node(
            tx,
            request,
            Some(a.activity_id()),
            a.goal_id(),
            a.dag_revision(),
            a.node_id(),
        )?;
        if observed.scope.goal_created_at() != a.goal_created_at() {
            return Err(WorkInventoryError::Conflict("assignment Goal generation"));
        }
        if selected(request, observed.scope) {
            let assignment = WorkInventoryAssignment {
                assignment_id: a.id(),
                revision: a.revision(),
                state: a.state(),
                cancellation_requested: a.cancellation_requested(),
            };
            insert_node(
                output,
                observed.for_actor(agent.binding.agent_id(), false, Some(assignment)),
            )?;
        }
    }
    Ok(())
}

fn selected(request: &WorkCutRequest, scope: WorkCutNodeScope) -> bool {
    match request.scope() {
        WorkCutScope::Workspace => true,
        WorkCutScope::Team { nodes, .. } => nodes.binary_search(&scope).is_ok(),
    }
}

fn insert_node(
    output: &mut NodeEntries,
    value: WorkInventoryNode,
) -> Result<(), WorkInventoryError> {
    let key = (value.scope, value.agent_id);
    if let Some(existing) = output.get_mut(&key) {
        if existing.assignment.is_some()
            && value.assignment.is_some()
            && existing.assignment != value.assignment
        {
            return Err(WorkInventoryError::Conflict(
                "node has multiple active assignments",
            ));
        }
        existing.direct_focus |= value.direct_focus;
        existing.assignment = existing.assignment.or(value.assignment);
    } else {
        if output.len() == MAX_WORK_INVENTORY_ENTRIES {
            return Err(WorkInventoryError::Bounds);
        }
        output.insert(key, value);
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct NodeDetails {
    scope: WorkCutNodeScope,
    goal_revision: GoalRevision,
    head_dag_revision: DagRevisionNumber,
    head_revision: DagHeadRevision,
    node_revision: DagNodeRevision,
    node_state: DagNodeStatus,
}
impl NodeDetails {
    fn for_actor(
        self,
        agent_id: AgentInstanceId,
        direct_focus: bool,
        assignment: Option<WorkInventoryAssignment>,
    ) -> WorkInventoryNode {
        WorkInventoryNode {
            agent_id,
            scope: self.scope,
            goal_revision: self.goal_revision,
            head_dag_revision: self.head_dag_revision,
            head_revision: self.head_revision,
            node_revision: self.node_revision,
            node_state: self.node_state,
            direct_focus,
            assignment,
        }
    }
}

struct RawNode {
    workspace: Vec<u8>,
    activity: Vec<u8>,
    created: i64,
    goal_revision: i64,
    base: i64,
    head_dag: i64,
    head_revision: i64,
    node_revision: i64,
    lifecycle: i64,
}

fn load_node(
    tx: &Transaction<'_>,
    request: &WorkCutRequest,
    expected_activity: Option<ActivityId>,
    goal: GoalId,
    dag: DagRevisionNumber,
    node: DagNodeId,
) -> Result<NodeDetails, WorkInventoryError> {
    let raw=tx.query_row(
        "SELECT substr(g.workspace_id,1,17),substr(g.activity_id,1,17),g.created_at_ms,g.revision,r.base_goal_revision,h.dag_revision,h.head_revision,n.node_revision,n.lifecycle_state FROM goals g JOIN goal_dag_revisions r ON r.goal_id=g.goal_id JOIN goal_dag_nodes n ON n.goal_id=r.goal_id AND n.dag_revision=r.dag_revision JOIN goal_dag_heads h ON h.goal_id=g.goal_id WHERE g.goal_id=?1 AND r.dag_revision=?2 AND n.node_id=?3",
        params![goal.into_uuid().as_bytes(),dag.get(),node.into_uuid().as_bytes()],
        |r|Ok(RawNode{workspace:r.get(0)?,activity:r.get(1)?,created:r.get(2)?,goal_revision:r.get(3)?,base:r.get(4)?,head_dag:r.get(5)?,head_revision:r.get(6)?,node_revision:r.get(7)?,lifecycle:r.get(8)?}),
    ).optional()?.ok_or(WorkInventoryError::Conflict("work node missing"))?;
    let activity = ActivityId::from_uuid(id(&raw.activity)?);
    if id(&raw.workspace)? != request.workspace_id().into_uuid()
        || expected_activity.is_some_and(|expected| expected != activity)
    {
        return Err(WorkInventoryError::Conflict("work node Activity"));
    }
    let scope = WorkCutNodeScope::new(
        activity,
        goal,
        TimestampMillis::new(raw.created)
            .map_err(|_| WorkInventoryError::Corrupt("Goal creation"))?,
        GoalRevision::new(raw.base).map_err(|_| WorkInventoryError::Corrupt("DAG base"))?,
        dag,
        node,
    )
    .map_err(|_| WorkInventoryError::Corrupt("work node scope"))?;
    let status = match raw.lifecycle {
        0 => DagNodeStatus::Pending,
        1 => DagNodeStatus::Active,
        2 => DagNodeStatus::Blocked,
        3 => DagNodeStatus::Completed,
        4 => DagNodeStatus::Failed,
        5 => DagNodeStatus::Skipped,
        6 => DagNodeStatus::Cancelled,
        _ => return Err(WorkInventoryError::Corrupt("node lifecycle")),
    };
    Ok(NodeDetails {
        scope,
        goal_revision: GoalRevision::new(raw.goal_revision)
            .map_err(|_| WorkInventoryError::Corrupt("Goal revision"))?,
        head_dag_revision: DagRevisionNumber::new(raw.head_dag)
            .map_err(|_| WorkInventoryError::Corrupt("head DAG"))?,
        head_revision: DagHeadRevision::new(raw.head_revision)
            .map_err(|_| WorkInventoryError::Corrupt("head revision"))?,
        node_revision: DagNodeRevision::new(raw.node_revision)
            .map_err(|_| WorkInventoryError::Corrupt("node revision"))?,
        node_state: status,
    })
}

fn id(raw: &[u8]) -> Result<Uuid, WorkInventoryError> {
    let value = Uuid::from_slice(raw).map_err(|_| WorkInventoryError::Corrupt("UUID"))?;
    if value.is_nil() {
        return Err(WorkInventoryError::Corrupt("nil UUID"));
    }
    Ok(value)
}
