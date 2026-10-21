//! Complete, bounded inventory of source effects inside the custody transaction.

use std::collections::{BTreeMap, BTreeSet};

use forge_domain::{
    ActivityId, AgentInstanceId, ChangeSetId, DagNodeId, DagRevisionNumber, GoalEvidenceRef,
    GoalId, GoalRevision, TimestampMillis, WorkCutNodeScope, WorkCutRequest, WorkCutScope,
};
use rusqlite::{Transaction, params_from_iter, types::Value};
use uuid::Uuid;

use crate::{WorkCutInventory, workspace_goals};

use super::{MAX_WORK_CUT_EFFECTS, WorkCutEffect, WorkCutEffectKind, WorkCutError, decode_id};

const EFFECT_QUERY_LIMIT: usize = MAX_WORK_CUT_EFFECTS + 1;
// Keep VALUES binding below SQLite's traditional 999-parameter ceiling.
const NODE_SCOPE_QUERY_CHUNK: usize = 128;

/// Read the source effects that must be fenced by one custody cut.
///
/// All queries use the caller's immediate write transaction. Selected node
/// identities come from the current request/inventory, while source Activity
/// and actor identities remain those stored on each effect itself.
pub(super) fn collect(
    tx: &Transaction<'_>,
    request: &WorkCutRequest,
    inventory: &WorkCutInventory,
) -> Result<Vec<WorkCutEffect>, WorkCutError> {
    if inventory.request_digest() != request.request_digest() {
        return Err(WorkCutError::Conflict("inventory request digest"));
    }

    let scopes = selected_node_scopes(request, inventory);
    let (actors, activities) = selected_effect_owners(request.scope(), &scopes, inventory)?;
    let mut effects = BTreeMap::new();

    collect_writer_leases(tx, request, &actors, &mut effects)?;
    collect_scoped_executions(tx, request, &scopes, &mut effects)?;
    collect_activity_executions(tx, request, &actors, &activities, &scopes, &mut effects)?;
    collect_scoped_change_sets(tx, request, &scopes, &mut effects)?;
    collect_activity_change_sets(tx, request, &activities, &mut effects)?;

    Ok(effects.into_values().collect())
}

fn selected_node_scopes(
    request: &WorkCutRequest,
    inventory: &WorkCutInventory,
) -> BTreeSet<WorkCutNodeScope> {
    match request.scope() {
        WorkCutScope::Workspace => inventory.nodes().iter().map(|node| node.scope()).collect(),
        WorkCutScope::Team { nodes, .. } => nodes.iter().copied().collect(),
    }
}

fn selected_effect_owners(
    scope: &WorkCutScope,
    scopes: &BTreeSet<WorkCutNodeScope>,
    inventory: &WorkCutInventory,
) -> Result<(Vec<AgentInstanceId>, Vec<ActivityId>), WorkCutError> {
    let mut binding_activities = BTreeMap::new();
    for agent in inventory.agents() {
        let binding = agent.binding();
        if binding_activities
            .insert(binding.agent_id(), binding.activity_id())
            .is_some()
        {
            return Err(WorkCutError::Conflict("duplicate inventory actor"));
        }
    }

    let mut actors = BTreeSet::new();
    let mut activities = scopes
        .iter()
        .map(|scope| scope.activity_id())
        .collect::<BTreeSet<_>>();
    if matches!(scope, WorkCutScope::Workspace) {
        for binding in inventory.agents().iter().map(|agent| agent.binding()) {
            actors.insert(binding.agent_id());
            activities.insert(binding.activity_id());
        }
    }
    for node in inventory.nodes() {
        if !scopes.contains(&node.scope()) {
            return Err(WorkCutError::Conflict("inventory node outside cut scope"));
        }
        let actor = node.agent_id();
        let binding_activity = binding_activities
            .get(&actor)
            .copied()
            .ok_or(WorkCutError::Corrupt("inventory actor binding"))?;
        actors.insert(actor);
        activities.insert(binding_activity);
    }

    Ok((
        actors.into_iter().collect(),
        activities.into_iter().collect(),
    ))
}

fn collect_writer_leases(
    tx: &Transaction<'_>,
    request: &WorkCutRequest,
    actors: &[AgentInstanceId],
    effects: &mut BTreeMap<(WorkCutEffectKind, Uuid), WorkCutEffect>,
) -> Result<(), WorkCutError> {
    if actors.is_empty() {
        return Ok(());
    }

    // State 0 is the durable Active state. Expiry does not release a lease;
    // only an explicit state transition removes its fencing authority.
    let sql = format!(
        "SELECT lease_id, state, revision, activity_id, agent_id
           FROM writer_leases
          WHERE workspace_id = ? AND state = 0 AND agent_id IN ({})
          ORDER BY lease_id
          LIMIT ?",
        placeholders(actors.len())
    );
    let mut values = Vec::with_capacity(actors.len() + 2);
    values.push(Value::Blob(id_bytes(request.workspace_id().into_uuid())));
    values.extend(
        actors
            .iter()
            .map(|actor| Value::Blob(id_bytes(actor.into_uuid()))),
    );
    values.push(Value::Integer(query_limit()?));

    let mut statement = tx.prepare(&sql)?;
    let mut rows = statement.query(params_from_iter(values))?;
    let mut seen = 0;
    while let Some(row) = rows.next()? {
        seen += 1;
        if seen > MAX_WORK_CUT_EFFECTS {
            return Err(WorkCutError::Bounds);
        }
        let id = decode_id(&row.get::<_, Vec<u8>>(0)?)?;
        let state = row.get(1)?;
        let revision = row.get(2)?;
        let activity_id = ActivityId::from_uuid(decode_id(&row.get::<_, Vec<u8>>(3)?)?);
        let agent_id = AgentInstanceId::from_uuid(decode_id(&row.get::<_, Vec<u8>>(4)?)?);
        insert_effect(
            effects,
            WorkCutEffect::new(
                WorkCutEffectKind::WriterLease,
                id,
                revision,
                state,
                activity_id,
                Some(agent_id),
                None,
            )?,
        )?;
    }
    Ok(())
}

fn collect_scoped_executions(
    tx: &Transaction<'_>,
    request: &WorkCutRequest,
    scopes: &BTreeSet<WorkCutNodeScope>,
    effects: &mut BTreeMap<(WorkCutEffectKind, Uuid), WorkCutEffect>,
) -> Result<(), WorkCutError> {
    if scopes.is_empty() {
        return Ok(());
    }

    // Starting, Running, and Interrupted are the source's in-flight/recovery
    // states for work-cut capture (persisted state codes 0, 1, and 6).
    let ordered_scopes = scopes.iter().copied().collect::<Vec<_>>();
    for chunk in ordered_scopes.chunks(NODE_SCOPE_QUERY_CHUNK) {
        let sql = format!(
            "WITH selected_nodes (
                 activity_id, goal_id, goal_created_at_ms, base_goal_revision,
                 dag_revision, node_id
             ) AS (VALUES {})
             SELECT e.execution_id, e.state, e.revision, e.activity_id, p.agent_id,
                    s.activity_id, s.goal_id, s.goal_created_at_ms,
                    s.base_goal_revision, s.dag_revision, s.node_id
               FROM selected_nodes AS s
               JOIN execution_provenance AS p
                 ON p.goal_id = s.goal_id
                AND p.dag_revision = s.dag_revision
                AND p.node_id = s.node_id
               JOIN executions AS e
                 ON e.execution_id = p.execution_id
                AND e.workspace_id = ?
                AND e.state IN (0, 1, 6)
               JOIN goals AS g ON g.goal_id = p.goal_id
               JOIN goal_dag_revisions AS d
                 ON d.goal_id = p.goal_id AND d.dag_revision = p.dag_revision
              WHERE g.workspace_id = ?
                AND g.activity_id = s.activity_id
                AND g.created_at_ms = s.goal_created_at_ms
                AND d.base_goal_revision = s.base_goal_revision
              ORDER BY e.execution_id, s.goal_id, s.dag_revision, s.node_id
              LIMIT ?",
            node_scope_values(chunk.len())
        );
        let mut values = node_scope_params(chunk);
        values.push(Value::Blob(id_bytes(request.workspace_id().into_uuid())));
        values.push(Value::Blob(id_bytes(request.workspace_id().into_uuid())));
        values.push(Value::Integer(query_limit()?));

        let mut statement = tx.prepare(&sql)?;
        let mut rows = statement.query(params_from_iter(values))?;
        let mut seen = 0;
        while let Some(row) = rows.next()? {
            seen += 1;
            if seen > MAX_WORK_CUT_EFFECTS {
                return Err(WorkCutError::Bounds);
            }
            let id = decode_id(&row.get::<_, Vec<u8>>(0)?)?;
            let state = row.get(1)?;
            let revision = row.get(2)?;
            let activity_id = ActivityId::from_uuid(decode_id(&row.get::<_, Vec<u8>>(3)?)?);
            let agent_id = AgentInstanceId::from_uuid(decode_id(&row.get::<_, Vec<u8>>(4)?)?);
            let node_scope = Some(node_scope_from_row(row, 5)?);
            insert_effect(
                effects,
                WorkCutEffect::new(
                    WorkCutEffectKind::Execution,
                    id,
                    revision,
                    state,
                    activity_id,
                    Some(agent_id),
                    node_scope,
                )?,
            )?;
        }
    }
    Ok(())
}

fn collect_activity_executions(
    tx: &Transaction<'_>,
    request: &WorkCutRequest,
    actors: &[AgentInstanceId],
    activities: &[ActivityId],
    scopes: &BTreeSet<WorkCutNodeScope>,
    effects: &mut BTreeMap<(WorkCutEffectKind, Uuid), WorkCutEffect>,
) -> Result<(), WorkCutError> {
    if activities.is_empty() {
        return Ok(());
    }

    // Known unrelated work must be excluded before the result bound. Scoped
    // execution queries already include every actor on a captured Team node.
    let include_actors = matches!(request.scope(), WorkCutScope::Workspace) && !actors.is_empty();
    let actor_predicate = if include_actors {
        format!(" OR p.agent_id IN ({})", placeholders(actors.len()))
    } else {
        String::new()
    };
    let sql = format!(
        "SELECT e.execution_id, e.state, e.revision, e.activity_id,
                p.execution_id, p.agent_id, p.goal_id, p.dag_revision,
                p.node_id, g.activity_id, g.created_at_ms, d.base_goal_revision
           FROM executions AS e
           LEFT JOIN execution_provenance AS p ON p.execution_id = e.execution_id
           LEFT JOIN goals AS g ON g.goal_id = p.goal_id
           LEFT JOIN goal_dag_revisions AS d
             ON d.goal_id = p.goal_id AND d.dag_revision = p.dag_revision
          WHERE e.workspace_id = ? AND e.state IN (0, 1, 6)
            AND e.activity_id IN ({})
            AND (p.execution_id IS NULL OR g.goal_id IS NULL
                 OR d.goal_id IS NULL{actor_predicate})
          ORDER BY e.execution_id
          LIMIT ?",
        placeholders(activities.len())
    );
    let mut values = Vec::with_capacity(activities.len() + 2);
    values.push(Value::Blob(id_bytes(request.workspace_id().into_uuid())));
    values.extend(
        activities
            .iter()
            .map(|activity| Value::Blob(id_bytes(activity.into_uuid()))),
    );
    if include_actors {
        values.extend(
            actors
                .iter()
                .map(|actor| Value::Blob(id_bytes(actor.into_uuid()))),
        );
    }
    values.push(Value::Integer(query_limit()?));

    let mut statement = tx.prepare(&sql)?;
    let mut rows = statement.query(params_from_iter(values))?;
    let mut seen = 0;
    while let Some(row) = rows.next()? {
        seen += 1;
        if seen > MAX_WORK_CUT_EFFECTS {
            return Err(WorkCutError::Bounds);
        }
        let id = decode_id(&row.get::<_, Vec<u8>>(0)?)?;
        let kind = WorkCutEffectKind::Execution;
        let key = (kind, id);
        if effects.contains_key(&key) {
            continue;
        }

        insert_effect(effects, decode_activity_execution(row, id, scopes)?)?;
    }
    Ok(())
}

fn decode_activity_execution(
    row: &rusqlite::Row<'_>,
    id: Uuid,
    scopes: &BTreeSet<WorkCutNodeScope>,
) -> Result<WorkCutEffect, WorkCutError> {
    let state = row.get(1)?;
    let revision = row.get(2)?;
    let activity_id = ActivityId::from_uuid(decode_id(&row.get::<_, Vec<u8>>(3)?)?);
    let provenance_id: Option<Vec<u8>> = row.get(4)?;
    let actor_bytes: Option<Vec<u8>> = row.get(5)?;
    let agent_id = match (provenance_id, actor_bytes) {
        (None, None) => None,
        (Some(_), Some(bytes)) => Some(AgentInstanceId::from_uuid(decode_id(&bytes)?)),
        _ => return Err(WorkCutError::Corrupt("execution provenance actor")),
    };
    let node_scope = if agent_id.is_some() {
        let goal_id: Option<Vec<u8>> = row.get(6)?;
        let dag_revision: Option<i64> = row.get(7)?;
        let node_id: Option<Vec<u8>> = row.get(8)?;
        let goal_activity: Option<Vec<u8>> = row.get(9)?;
        let goal_created_at: Option<i64> = row.get(10)?;
        let base_goal_revision: Option<i64> = row.get(11)?;
        match (
            goal_id,
            dag_revision,
            node_id,
            goal_activity,
            goal_created_at,
            base_goal_revision,
        ) {
            (Some(goal), Some(dag), Some(node), Some(goal_activity), Some(created), Some(base)) => {
                let observed = decode_node_scope(&goal_activity, &goal, created, base, dag, &node)?;
                scopes.contains(&observed).then_some(observed)
            }
            _ => return Err(WorkCutError::Corrupt("execution provenance scope")),
        }
    } else {
        None
    };
    WorkCutEffect::new(
        WorkCutEffectKind::Execution,
        id,
        revision,
        state,
        activity_id,
        agent_id,
        node_scope,
    )
}

fn collect_scoped_change_sets(
    tx: &Transaction<'_>,
    request: &WorkCutRequest,
    scopes: &BTreeSet<WorkCutNodeScope>,
    effects: &mut BTreeMap<(WorkCutEffectKind, Uuid), WorkCutEffect>,
) -> Result<(), WorkCutError> {
    if scopes.is_empty() {
        return Ok(());
    }
    let (evidence_kind, _) = workspace_goals::encode_evidence(GoalEvidenceRef::ChangeSet(
        ChangeSetId::from_uuid(Uuid::from_u128(1)),
    ));

    let ordered_scopes = scopes.iter().copied().collect::<Vec<_>>();
    for chunk in ordered_scopes.chunks(NODE_SCOPE_QUERY_CHUNK) {
        let sql = format!(
            "WITH selected_nodes (
                 activity_id, goal_id, goal_created_at_ms, base_goal_revision,
                 dag_revision, node_id
             ) AS (VALUES {})
             SELECT c.changeset_id, c.state, c.revision, c.activity_id,
                    s.activity_id, s.goal_id, s.goal_created_at_ms,
                    s.base_goal_revision, s.dag_revision, s.node_id
               FROM selected_nodes AS s
               JOIN goal_dag_node_evidence_refs AS n
                 ON n.goal_id = s.goal_id
                AND n.dag_revision = s.dag_revision
                AND n.node_id = s.node_id
                AND n.evidence_kind = ?
               JOIN goal_evidence_refs AS ge
                 ON ge.goal_id = n.goal_id
                AND ge.evidence_kind = n.evidence_kind
                AND ge.evidence_id = n.evidence_id
               JOIN goals AS g ON g.goal_id = s.goal_id
               JOIN goal_dag_revisions AS d
                 ON d.goal_id = s.goal_id AND d.dag_revision = s.dag_revision
               JOIN change_sets AS c ON c.changeset_id = n.evidence_id
              WHERE c.workspace_id = ? AND c.state = 0
                AND g.workspace_id = ?
                AND g.activity_id = s.activity_id
                AND g.created_at_ms = s.goal_created_at_ms
                AND d.base_goal_revision = s.base_goal_revision
              ORDER BY c.changeset_id, s.goal_id, s.dag_revision, s.node_id
              LIMIT ?",
            node_scope_values(chunk.len())
        );
        let mut values = node_scope_params(chunk);
        values.push(Value::Integer(evidence_kind));
        values.push(Value::Blob(id_bytes(request.workspace_id().into_uuid())));
        values.push(Value::Blob(id_bytes(request.workspace_id().into_uuid())));
        values.push(Value::Integer(query_limit()?));

        let mut statement = tx.prepare(&sql)?;
        let mut rows = statement.query(params_from_iter(values))?;
        let mut seen = 0;
        while let Some(row) = rows.next()? {
            seen += 1;
            if seen > MAX_WORK_CUT_EFFECTS {
                return Err(WorkCutError::Bounds);
            }
            let id = decode_id(&row.get::<_, Vec<u8>>(0)?)?;
            let state = row.get(1)?;
            let revision = row.get(2)?;
            let activity_id = ActivityId::from_uuid(decode_id(&row.get::<_, Vec<u8>>(3)?)?);
            let node_scope = Some(node_scope_from_row(row, 4)?);
            insert_effect(
                effects,
                WorkCutEffect::new(
                    WorkCutEffectKind::ChangeSet,
                    id,
                    revision,
                    state,
                    activity_id,
                    None,
                    node_scope,
                )?,
            )?;
        }
    }
    Ok(())
}

fn collect_activity_change_sets(
    tx: &Transaction<'_>,
    request: &WorkCutRequest,
    activities: &[ActivityId],
    effects: &mut BTreeMap<(WorkCutEffectKind, Uuid), WorkCutEffect>,
) -> Result<(), WorkCutError> {
    if activities.is_empty() {
        return Ok(());
    }

    let (evidence_kind, _) = workspace_goals::encode_evidence(GoalEvidenceRef::ChangeSet(
        ChangeSetId::from_uuid(Uuid::from_u128(1)),
    ));
    let team_scope = matches!(request.scope(), WorkCutScope::Team { .. });
    let sql = format!(
        "SELECT c.changeset_id, c.state, c.revision, c.activity_id
           FROM change_sets c
          WHERE c.workspace_id = ? AND c.state = 0 AND c.activity_id IN ({})
            AND (? = 0 OR NOT EXISTS(
                SELECT 1 FROM goal_dag_node_evidence_refs n
                JOIN goal_evidence_refs ge ON ge.goal_id = n.goal_id
                  AND ge.evidence_kind = n.evidence_kind AND ge.evidence_id = n.evidence_id
                JOIN goals g ON g.goal_id = n.goal_id AND g.workspace_id = c.workspace_id
                JOIN goal_dag_revisions d ON d.goal_id = n.goal_id AND d.dag_revision = n.dag_revision
                WHERE n.evidence_id = c.changeset_id AND n.evidence_kind = ?
            ))
          ORDER BY c.changeset_id
          LIMIT ?",
        placeholders(activities.len())
    );
    let mut values = Vec::with_capacity(activities.len() + 2);
    values.push(Value::Blob(id_bytes(request.workspace_id().into_uuid())));
    values.extend(
        activities
            .iter()
            .map(|activity| Value::Blob(id_bytes(activity.into_uuid()))),
    );
    values.push(Value::Integer(i64::from(team_scope)));
    values.push(Value::Integer(evidence_kind));
    values.push(Value::Integer(query_limit()?));

    let mut statement = tx.prepare(&sql)?;
    let mut rows = statement.query(params_from_iter(values))?;
    let mut seen = 0;
    while let Some(row) = rows.next()? {
        seen += 1;
        if seen > MAX_WORK_CUT_EFFECTS {
            return Err(WorkCutError::Bounds);
        }
        let id = decode_id(&row.get::<_, Vec<u8>>(0)?)?;
        let kind = WorkCutEffectKind::ChangeSet;
        if effects.contains_key(&(kind, id)) {
            continue;
        }
        let state = row.get(1)?;
        let revision = row.get(2)?;
        let activity_id = ActivityId::from_uuid(decode_id(&row.get::<_, Vec<u8>>(3)?)?);
        insert_effect(
            effects,
            WorkCutEffect::new(kind, id, revision, state, activity_id, None, None)?,
        )?;
    }
    Ok(())
}

fn node_scope_from_row(
    row: &rusqlite::Row<'_>,
    first_column: usize,
) -> Result<WorkCutNodeScope, WorkCutError> {
    let activity_id: Vec<u8> = row.get(first_column)?;
    let goal_id: Vec<u8> = row.get(first_column + 1)?;
    let goal_created_at: i64 = row.get(first_column + 2)?;
    let base_goal_revision: i64 = row.get(first_column + 3)?;
    let dag_revision: i64 = row.get(first_column + 4)?;
    let node_id: Vec<u8> = row.get(first_column + 5)?;
    decode_node_scope(
        &activity_id,
        &goal_id,
        goal_created_at,
        base_goal_revision,
        dag_revision,
        &node_id,
    )
}

fn decode_node_scope(
    activity_id: &[u8],
    goal_id: &[u8],
    goal_created_at: i64,
    base_goal_revision: i64,
    dag_revision: i64,
    node_id: &[u8],
) -> Result<WorkCutNodeScope, WorkCutError> {
    let activity_id = ActivityId::from_uuid(decode_id(activity_id)?);
    let goal_id = GoalId::from_uuid(decode_id(goal_id)?);
    let node_id = DagNodeId::from_uuid(decode_id(node_id)?);
    let created_at = TimestampMillis::new(goal_created_at)
        .map_err(|_| WorkCutError::Corrupt("Goal creation time"))?;
    let base_goal_revision = GoalRevision::new(base_goal_revision)
        .map_err(|_| WorkCutError::Corrupt("DAG base Goal revision"))?;
    let dag_revision =
        DagRevisionNumber::new(dag_revision).map_err(|_| WorkCutError::Corrupt("DAG revision"))?;
    WorkCutNodeScope::new(
        activity_id,
        goal_id,
        created_at,
        base_goal_revision,
        dag_revision,
        node_id,
    )
    .map_err(|_| WorkCutError::Corrupt("node scope"))
}

fn insert_effect(
    effects: &mut BTreeMap<(WorkCutEffectKind, Uuid), WorkCutEffect>,
    effect: WorkCutEffect,
) -> Result<(), WorkCutError> {
    let key = (effect.kind(), effect.id());
    if let Some(existing) = effects.get(&key) {
        if existing != &effect {
            return Err(WorkCutError::Conflict(
                "effect identity has inconsistent source scope",
            ));
        }
        return Ok(());
    }
    if effects.len() == MAX_WORK_CUT_EFFECTS {
        return Err(WorkCutError::Bounds);
    }
    effects.insert(key, effect);
    Ok(())
}

fn node_scope_values(count: usize) -> String {
    vec!["(?, ?, ?, ?, ?, ?)"; count].join(", ")
}

fn node_scope_params(scopes: &[WorkCutNodeScope]) -> Vec<Value> {
    let mut values = Vec::with_capacity(scopes.len() * 6);
    for scope in scopes {
        values.push(Value::Blob(id_bytes(scope.activity_id().into_uuid())));
        values.push(Value::Blob(id_bytes(scope.goal_id().into_uuid())));
        values.push(Value::Integer(scope.goal_created_at().get()));
        values.push(Value::Integer(scope.dag_base_goal_revision().get()));
        values.push(Value::Integer(scope.dag_revision().get()));
        values.push(Value::Blob(id_bytes(scope.node_id().into_uuid())));
    }
    values
}

fn placeholders(count: usize) -> String {
    vec!["?"; count].join(", ")
}

fn query_limit() -> Result<i64, WorkCutError> {
    i64::try_from(EFFECT_QUERY_LIMIT).map_err(|_| WorkCutError::Bounds)
}

fn id_bytes(id: Uuid) -> Vec<u8> {
    id.as_bytes().to_vec()
}
