//! Admission fences that hold fresh work behind a held leadership work cut.
//!
//! A held cut fences fresh work on the identities it captured; it never
//! mutates captured source state. Every check runs inside the caller's write
//! transaction so the fence and the mutation observe one `SQLite` snapshot.

use rusqlite::{Connection, params};

use forge_domain::{
    ActivityId, AgentFocus, AgentInstanceId, DagNodeId, DagRevisionNumber,
    ExecutionAgentProvenance, GoalId, SourceWriteAuthority, WorkspaceId, WriterLeaseId,
};

use super::WorkCutError;

/// Fences fresh Goal or DAG-plan work on a Goal captured by a held cut.
pub(crate) fn ensure_goal_open(
    connection: &Connection,
    workspace_id: WorkspaceId,
    goal_id: GoalId,
) -> Result<(), WorkCutError> {
    let fenced = connection.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM leadership_work_cuts c
              JOIN leadership_work_cut_nodes n ON n.cut_id = c.cut_id
             WHERE c.workspace_id = ?1 AND c.state = 0 AND n.goal_id = ?2
         ) OR EXISTS(
             SELECT 1 FROM leadership_work_cuts c
              JOIN leadership_work_cut_team_nodes t ON t.cut_id = c.cut_id
             WHERE c.workspace_id = ?1 AND c.state = 0 AND t.goal_id = ?2
         )",
        params![
            workspace_id.into_uuid().as_bytes(),
            goal_id.into_uuid().as_bytes()
        ],
        |row| row.get::<_, bool>(0),
    )?;
    if fenced {
        Err(WorkCutError::Conflict("Goal is fenced by a held cut"))
    } else {
        Ok(())
    }
}

/// Fences fresh node transitions on a node captured by a held cut.
pub(crate) fn ensure_node_open(
    connection: &Connection,
    workspace_id: WorkspaceId,
    goal_id: GoalId,
    dag_revision: DagRevisionNumber,
    node_id: DagNodeId,
) -> Result<(), WorkCutError> {
    let fenced = connection.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM leadership_work_cuts c
              JOIN leadership_work_cut_nodes n ON n.cut_id = c.cut_id
             WHERE c.workspace_id = ?1 AND c.state = 0
               AND n.goal_id = ?2 AND n.dag_revision = ?3 AND n.node_id = ?4
         ) OR EXISTS(
             SELECT 1 FROM leadership_work_cuts c
              JOIN leadership_work_cut_team_nodes t ON t.cut_id = c.cut_id
             WHERE c.workspace_id = ?1 AND c.state = 0
               AND t.goal_id = ?2 AND t.dag_revision = ?3 AND t.node_id = ?4
         )",
        params![
            workspace_id.into_uuid().as_bytes(),
            goal_id.into_uuid().as_bytes(),
            dag_revision.get(),
            node_id.into_uuid().as_bytes()
        ],
        |row| row.get::<_, bool>(0),
    )?;
    if fenced {
        Err(WorkCutError::Conflict("node is fenced by a held cut"))
    } else {
        Ok(())
    }
}

/// Fences an entire captured actor only for a Workspace-wide cut.
/// Team custody is node-scoped; merely appearing in its roster is not a work fence.
pub(crate) fn ensure_actor_open(
    connection: &Connection,
    workspace_id: WorkspaceId,
    agent_id: AgentInstanceId,
) -> Result<(), WorkCutError> {
    let fenced = connection.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM leadership_work_cuts c
              JOIN leadership_work_cut_agents a ON a.cut_id = c.cut_id
             WHERE c.workspace_id = ?1 AND c.state = 0 AND c.scope_kind = 0 AND a.agent_id = ?2
         )",
        params![
            workspace_id.into_uuid().as_bytes(),
            agent_id.into_uuid().as_bytes()
        ],
        |row| row.get::<_, bool>(0),
    )?;
    if fenced {
        Err(WorkCutError::Conflict("actor is fenced by a held cut"))
    } else {
        Ok(())
    }
}

/// Fences new leases for actors whose node custody captures their Writer Leases.
pub(crate) fn ensure_lease_acquisition_open(
    connection: &Connection,
    workspace_id: WorkspaceId,
    agent_id: AgentInstanceId,
) -> Result<(), WorkCutError> {
    ensure_actor_open(connection, workspace_id, agent_id)?;
    let fenced = connection.query_row(
        "SELECT EXISTS(
        SELECT 1 FROM leadership_work_cuts c
        JOIN leadership_work_cut_nodes n ON n.cut_id=c.cut_id
        WHERE c.workspace_id=?1 AND c.state=0 AND c.scope_kind=1 AND n.agent_id=?2
    )",
        params![
            workspace_id.into_uuid().as_bytes(),
            agent_id.into_uuid().as_bytes()
        ],
        |row| row.get::<_, bool>(0),
    )?;
    if fenced {
        Err(WorkCutError::Conflict(
            "Writer Lease acquisition is fenced by Team custody",
        ))
    } else {
        Ok(())
    }
}

/// Fences Writer Lease renewals captured as effects of a held cut.
pub(crate) fn ensure_lease_renewal_open(
    connection: &Connection,
    workspace_id: WorkspaceId,
    lease_id: WriterLeaseId,
) -> Result<(), WorkCutError> {
    let fenced = connection.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM leadership_work_cuts c
              JOIN leadership_work_cut_effects e ON e.cut_id = c.cut_id
             WHERE c.workspace_id = ?1 AND c.state = 0
               AND e.effect_kind = 0 AND e.effect_id = ?2
         )",
        params![
            workspace_id.into_uuid().as_bytes(),
            lease_id.into_uuid().as_bytes()
        ],
        |row| row.get::<_, bool>(0),
    )?;
    if fenced {
        Err(WorkCutError::Conflict(
            "Writer Lease renewal is fenced by a held cut",
        ))
    } else {
        Ok(())
    }
}

/// Fences focus changes that move an Agent into or out of a held cut scope.
///
/// An Agent captured by the cut keeps the focus snapshot the cut recorded.
/// A different Agent may not newly focus a Goal or node the cut froze,
/// because that focus would admit fresh work inside the fenced scope.
pub(crate) fn ensure_focus_open(
    connection: &Connection,
    workspace_id: WorkspaceId,
    agent_id: AgentInstanceId,
    current_focus: AgentFocus,
    focus: AgentFocus,
) -> Result<(), WorkCutError> {
    ensure_actor_open(connection, workspace_id, agent_id)?;
    ensure_focus_scope_open(connection, workspace_id, current_focus)?;
    ensure_focus_scope_open(connection, workspace_id, focus)
}

fn ensure_focus_scope_open(
    connection: &Connection,
    workspace_id: WorkspaceId,
    focus: AgentFocus,
) -> Result<(), WorkCutError> {
    let Some(goal) = focus.goal() else {
        return Ok(());
    };
    match (focus.dag_revision(), focus.node()) {
        (Some(dag_revision), Some(node)) => ensure_node_open(
            connection,
            workspace_id,
            goal.goal_id(),
            dag_revision,
            node.node_id(),
        ),
        _ => ensure_goal_open(connection, workspace_id, goal.goal_id()),
    }
}

/// Called only for a new Started intent, in that same transaction. Exact
/// existing intent recovery must not enter this fresh-effect gate.
pub(crate) fn ensure_source_write_open(
    connection: &Connection,
    workspace_id: WorkspaceId,
    authority: SourceWriteAuthority,
) -> Result<(), WorkCutError> {
    ensure_actor_open(connection, workspace_id, authority.agent_id())?;
    let node = authority.attribution();
    ensure_node_open(
        connection,
        workspace_id,
        node.goal_id(),
        node.dag_revision(),
        node.node_id(),
    )
}

/// Fences fresh execution beginnings inside a held cut scope.
///
/// Known provenance is checked at actor/Node scope, never by Activity alone.
/// Only unattributed commands use the conservative Activity fence because
/// their independence from the held work cannot be established.
pub(crate) fn ensure_execution_open(
    connection: &Connection,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    provenance: Option<&ExecutionAgentProvenance>,
) -> Result<(), WorkCutError> {
    if let Some(provenance) = provenance {
        ensure_actor_open(connection, workspace_id, provenance.agent_id())?;
        let attribution = provenance.attribution();
        ensure_node_open(
            connection,
            workspace_id,
            attribution.goal_id(),
            attribution.dag_revision(),
            attribution.node_id(),
        )?;
        return Ok(());
    }
    let fenced = connection.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM leadership_work_cuts c
              JOIN leadership_work_cut_agents a ON a.cut_id = c.cut_id
             WHERE c.workspace_id = ?1 AND c.state = 0 AND a.activity_id = ?2
         ) OR EXISTS(
             SELECT 1 FROM leadership_work_cuts c
              JOIN leadership_work_cut_nodes n ON n.cut_id = c.cut_id
             WHERE c.workspace_id = ?1 AND c.state = 0 AND n.activity_id = ?2
         ) OR EXISTS(
             SELECT 1 FROM leadership_work_cuts c
              JOIN leadership_work_cut_team_nodes t ON t.cut_id = c.cut_id
             WHERE c.workspace_id = ?1 AND c.state = 0 AND t.activity_id = ?2
         )",
        params![
            workspace_id.into_uuid().as_bytes(),
            activity_id.into_uuid().as_bytes()
        ],
        |row| row.get::<_, bool>(0),
    )?;
    if fenced {
        Err(WorkCutError::Conflict("Activity is fenced by a held cut"))
    } else {
        Ok(())
    }
}
