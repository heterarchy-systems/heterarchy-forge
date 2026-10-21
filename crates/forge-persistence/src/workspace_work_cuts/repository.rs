//! Durable prepare, idempotent retry, and exact readback of work cuts.
//!
//! One `IMMEDIATE` transaction observes the canonical inventory, captures the
//! unsettled source effects, and installs the cut atomically. The persisted
//! rows are the single source of truth: both prepare and readback build the
//! record from those rows and verify the canonical snapshot digest.

use sha2::{Digest, Sha256};

use forge_domain::{
    ActivityId, AgentAssignmentId, AgentAssignmentRevision, AgentAssignmentState, AgentFocus,
    AgentFocusNode, AgentInstanceId, AgentInstanceRevision, AgentSessionId, AuthenticatedPrincipal,
    DagHeadRevision, DagNodeId, DagNodeRevision, DagNodeStatus, DagRevisionNumber, DirectTokenId,
    ForgeBackendId, GoalAttribution, GoalId, GoalRevision, MAX_WORK_CUT_BINDINGS,
    MAX_WORK_CUT_SESSIONS, MAX_WORK_CUT_TEAM_NODES, OAuthGrantId, OrchestrationIssuerId,
    TimestampMillis, WorkCutBinding, WorkCutGrant, WorkCutNodeScope, WorkCutParty, WorkCutRequest,
    WorkCutScope, WorkCutSession, WorkCutSide, WorkspaceId, WorkspaceRevision,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use uuid::Uuid;

use crate::workspace_work_inventory::{
    self, WorkCutInventory, WorkInventoryAgent, WorkInventoryAssignment, WorkInventoryNode,
};

use super::{
    MAX_WORK_CUT_EFFECTS, WorkCutEffect, WorkCutEffectKind, WorkCutError, WorkCutPrepareOutcome,
    WorkCutRecord, WorkCutState, decode_id, effects,
};

/// One effect reduced to its persisted form.
///
/// The durable rows do not repeat a captured node scope: the scope is the
/// `leadership_work_cut_nodes` row referenced by `node_ordinal`, or absent
/// when the scope belongs to a Team witness without a roster node row.
struct PersistedEffect {
    kind: WorkCutEffectKind,
    id: Uuid,
    agent: Option<AgentInstanceId>,
    node_ordinal: Option<i64>,
    activity_id: ActivityId,
    revision: i64,
    state: i64,
}

pub(super) fn prepare(
    connection: &mut Connection,
    request: &WorkCutRequest,
    grant: WorkCutGrant,
    authenticated_issuer: OrchestrationIssuerId,
    actual_backend: ForgeBackendId,
    now: TimestampMillis,
) -> Result<WorkCutPrepareOutcome, WorkCutError> {
    grant
        .validate_for(authenticated_issuer, request.request_digest(), now)
        .map_err(WorkCutError::Domain)?;
    if actual_backend != request.backend_id() {
        return Err(WorkCutError::Conflict("backend identity"));
    }
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if let Some(existing) = read_record(&transaction, request.cut_id())? {
        if existing.request().request_digest() != request.request_digest() {
            return Err(WorkCutError::Conflict("cut id"));
        }
        if existing.issuer() != authenticated_issuer {
            return Err(WorkCutError::Conflict("cut issuer"));
        }
        if existing.state() != WorkCutState::Held {
            return Err(WorkCutError::Conflict("cut identity is spent"));
        }
        return Ok(WorkCutPrepareOutcome::Existing(existing));
    }
    let election_held: bool = transaction.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM leadership_work_cuts
              WHERE workspace_id = ?1 AND election_id = ?2 AND state = 0
         )",
        params![
            request.workspace_id().into_uuid().as_bytes(),
            request.election_id().as_bytes()
        ],
        |row| row.get(0),
    )?;
    if election_held {
        return Err(WorkCutError::Conflict("election cut"));
    }
    let inventory = workspace_work_inventory::observe_in_transaction(&transaction, request)
        .map_err(|error| WorkCutError::Inventory(Box::new(error)))?;
    let captured = effects::collect(&transaction, request, &inventory)?;
    persist(
        &transaction,
        request,
        &grant,
        authenticated_issuer,
        now,
        &inventory,
        &captured,
    )?;
    let record = read_record(&transaction, request.cut_id())?
        .ok_or(WorkCutError::Corrupt("cut readback"))?;
    transaction
        .commit()
        .map_err(|error| WorkCutError::CommitUnconfirmed {
            cut_id: request.cut_id(),
            source: Box::new(error),
        })?;
    Ok(WorkCutPrepareOutcome::Prepared(record))
}

pub(super) fn get(
    connection: &Connection,
    cut_id: Uuid,
) -> Result<Option<WorkCutRecord>, WorkCutError> {
    let transaction = connection.unchecked_transaction()?;
    let record = read_record(&transaction, cut_id)?;
    transaction.commit()?;
    Ok(record)
}

#[allow(
    clippy::too_many_lines,
    reason = "one reconstruction covers every persisted work-cut table"
)]
pub(super) fn read_record(
    connection: &Connection,
    cut_id: Uuid,
) -> Result<Option<WorkCutRecord>, WorkCutError> {
    let cut = connection
        .query_row(
            "SELECT workspace_id, election_id, destination_id, backend_id, issuer_id,
                    grant_issued_at_ms, grant_expires_at_ms, workspace_revision,
                    leadership_revision, scope_kind, team_id,
                    incumbent_participation_id, elected_participation_id,
                    incumbent_profile_id, elected_profile_id,
                    roster_digest, request_digest, snapshot_digest,
                    state, revision, prepared_at_ms, updated_at_ms
               FROM leadership_work_cuts WHERE cut_id = ?1",
            params![cut_id.as_bytes()],
            |row| {
                Ok(CutRow {
                    workspace_id: row.get(0)?,
                    election_id: row.get(1)?,
                    destination_id: row.get(2)?,
                    backend_id: row.get(3)?,
                    issuer_id: row.get(4)?,
                    grant_issued_at: row.get(5)?,
                    grant_expires_at: row.get(6)?,
                    workspace_revision: row.get(7)?,
                    leadership_revision: row.get(8)?,
                    scope_kind: row.get(9)?,
                    team_id: row.get(10)?,
                    incumbent_participation_id: row.get(11)?,
                    elected_participation_id: row.get(12)?,
                    incumbent_profile_id: row.get(13)?,
                    elected_profile_id: row.get(14)?,
                    roster_digest: row.get(15)?,
                    request_digest: row.get(16)?,
                    snapshot_digest: row.get(17)?,
                    state: row.get(18)?,
                    revision: row.get(19)?,
                    prepared_at: row.get(20)?,
                    updated_at: row.get(21)?,
                })
            },
        )
        .optional()?;
    let Some(cut) = cut else {
        return Ok(None);
    };

    let mut sessions_raw = connection.prepare(
        "SELECT side, session_id FROM leadership_work_cut_sessions
          WHERE cut_id = ?1 ORDER BY session_id LIMIT ?2",
    )?;
    let sessions = sessions_raw
        .query_map(
            params![cut_id.as_bytes(), result_limit(MAX_WORK_CUT_SESSIONS)?],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )?
        .collect::<Result<Vec<_>, _>>()?;
    ensure_result_bound(sessions.len(), MAX_WORK_CUT_SESSIONS)?;
    let mut sessions = sessions
        .into_iter()
        .map(|(side, session)| {
            WorkCutSession::new(
                decode_side(side)?,
                AgentSessionId::from_uuid(decode_id(&session)?),
            )
            .map_err(WorkCutError::Domain)
        })
        .collect::<Result<Vec<_>, _>>()?;
    sessions.sort_unstable_by_key(|session| session.session_id());

    let mut agents_raw = connection.prepare(
        "SELECT side, activity_id, agent_id, session_id, principal_kind, principal_id,
                agent_revision, focus_goal_id, focus_goal_revision, focus_dag_revision,
                focus_node_id, focus_node_revision
           FROM leadership_work_cut_agents WHERE cut_id = ?1 ORDER BY agent_id LIMIT ?2",
    )?;
    let agents = agents_raw
        .query_map(
            params![cut_id.as_bytes(), result_limit(MAX_WORK_CUT_BINDINGS)?],
            |row| {
                Ok(AgentRow {
                    side: row.get(0)?,
                    activity_id: row.get(1)?,
                    agent_id: row.get(2)?,
                    session_id: row.get(3)?,
                    principal_kind: row.get(4)?,
                    principal_id: row.get(5)?,
                    agent_revision: row.get(6)?,
                    focus_goal_id: row.get(7)?,
                    focus_goal_revision: row.get(8)?,
                    focus_dag_revision: row.get(9)?,
                    focus_node_id: row.get(10)?,
                    focus_node_revision: row.get(11)?,
                })
            },
        )?
        .collect::<Result<Vec<_>, _>>()?;
    ensure_result_bound(agents.len(), MAX_WORK_CUT_BINDINGS)?;
    let bindings = agents
        .iter()
        .map(|agent| {
            WorkCutBinding::new(
                decode_side(agent.side)?,
                ActivityId::from_uuid(decode_id(&agent.activity_id)?),
                AgentInstanceId::from_uuid(decode_id(&agent.agent_id)?),
                AgentSessionId::from_uuid(decode_id(&agent.session_id)?),
                decode_principal(agent.principal_kind, agent.principal_id.as_deref())?,
            )
            .map_err(WorkCutError::Domain)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let inventory_agents = agents
        .iter()
        .map(|agent| {
            Ok(WorkInventoryAgent {
                binding: WorkCutBinding::new(
                    decode_side(agent.side)?,
                    ActivityId::from_uuid(decode_id(&agent.activity_id)?),
                    AgentInstanceId::from_uuid(decode_id(&agent.agent_id)?),
                    AgentSessionId::from_uuid(decode_id(&agent.session_id)?),
                    decode_principal(agent.principal_kind, agent.principal_id.as_deref())?,
                )
                .map_err(WorkCutError::Domain)?,
                revision: AgentInstanceRevision::new(agent.agent_revision)
                    .map_err(|_| WorkCutError::Corrupt("Agent revision"))?,
                focus: decode_focus(agent)?,
            })
        })
        .collect::<Result<Vec<_>, WorkCutError>>()?;

    let mut nodes_raw = connection.prepare(
        "SELECT ordinal, agent_id, activity_id, goal_id, goal_created_at_ms, goal_revision,
                dag_revision, dag_base_goal_revision, head_dag_revision, dag_head_revision,
                node_id, node_revision, lifecycle_state, direct_focus,
                assignment_id, assignment_revision, assignment_state, assignment_cancellation
           FROM leadership_work_cut_nodes WHERE cut_id = ?1 ORDER BY ordinal LIMIT ?2",
    )?;
    let nodes = nodes_raw
        .query_map(
            params![cut_id.as_bytes(), result_limit(MAX_WORK_CUT_TEAM_NODES)?],
            |row| {
                Ok(NodeRow {
                    ordinal: row.get(0)?,
                    agent_id: row.get(1)?,
                    activity_id: row.get(2)?,
                    goal_id: row.get(3)?,
                    goal_created_at: row.get(4)?,
                    goal_revision: row.get(5)?,
                    dag_revision: row.get(6)?,
                    dag_base_goal_revision: row.get(7)?,
                    head_dag_revision: row.get(8)?,
                    dag_head_revision: row.get(9)?,
                    node_id: row.get(10)?,
                    node_revision: row.get(11)?,
                    lifecycle_state: row.get(12)?,
                    direct_focus: row.get::<_, i64>(13)? != 0,
                    assignment_id: row.get(14)?,
                    assignment_revision: row.get(15)?,
                    assignment_state: row.get(16)?,
                    assignment_cancellation: row.get(17)?,
                })
            },
        )?
        .collect::<Result<Vec<_>, _>>()?;
    ensure_result_bound(nodes.len(), MAX_WORK_CUT_TEAM_NODES)?;
    if nodes
        .iter()
        .enumerate()
        .any(|(index, node)| usize::try_from(node.ordinal) != Ok(index))
    {
        return Err(WorkCutError::Corrupt("cut node order"));
    }
    let inventory_nodes = nodes
        .iter()
        .map(decode_node)
        .collect::<Result<Vec<_>, WorkCutError>>()?;

    let mut team_raw = connection.prepare(
        "SELECT activity_id, goal_id, goal_created_at_ms, dag_base_goal_revision,
                dag_revision, node_id
           FROM leadership_work_cut_team_nodes WHERE cut_id = ?1 ORDER BY ordinal LIMIT ?2",
    )?;
    let team_nodes = team_raw
        .query_map(
            params![cut_id.as_bytes(), result_limit(MAX_WORK_CUT_TEAM_NODES)?],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                ))
            },
        )?
        .collect::<Result<Vec<_>, _>>()?;
    ensure_result_bound(team_nodes.len(), MAX_WORK_CUT_TEAM_NODES)?;
    let team_nodes = team_nodes
        .iter()
        .map(|(activity, goal, created, base, dag, node)| {
            decode_scope(activity, goal, *created, *base, *dag, node)
        })
        .collect::<Result<Vec<_>, WorkCutError>>()?;

    let mut effects_raw = connection.prepare(
        "SELECT effect_kind, effect_id, agent_id, node_ordinal, activity_id,
                effect_revision, effect_state
           FROM leadership_work_cut_effects WHERE cut_id = ?1 ORDER BY effect_kind, effect_id LIMIT ?2",
    )?;
    let persisted = effects_raw
        .query_map(
            params![cut_id.as_bytes(), result_limit(MAX_WORK_CUT_EFFECTS)?],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Option<Vec<u8>>>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            },
        )?
        .collect::<Result<Vec<_>, _>>()?;
    ensure_result_bound(persisted.len(), MAX_WORK_CUT_EFFECTS)?;
    let persisted_effects = persisted
        .iter()
        .map(|(kind, id, agent, ordinal, activity, revision, state)| {
            Ok(PersistedEffect {
                kind: decode_kind(*kind)?,
                id: decode_id(id)?,
                agent: match agent {
                    Some(bytes) => Some(AgentInstanceId::from_uuid(decode_id(bytes)?)),
                    None => None,
                },
                node_ordinal: *ordinal,
                activity_id: ActivityId::from_uuid(decode_id(activity)?),
                revision: *revision,
                state: *state,
            })
        })
        .collect::<Result<Vec<_>, WorkCutError>>()?;

    let scope = decode_scope_kind(&cut, &team_nodes)?;
    let parties = [
        WorkCutPartyRow {
            participation: decode_id(&cut.incumbent_participation_id)?,
            profile: decode_id(&cut.incumbent_profile_id)?,
        },
        WorkCutPartyRow {
            participation: decode_id(&cut.elected_participation_id)?,
            profile: decode_id(&cut.elected_profile_id)?,
        },
    ];
    let request = rebuild_request(cut_id, &cut, &parties, &sessions, &bindings, scope)?;

    let inventory = WorkCutInventory {
        request_digest: request.request_digest(),
        agents: inventory_agents,
        nodes: inventory_nodes,
    };
    let node_scopes: Vec<WorkCutNodeScope> =
        inventory.nodes().iter().map(|node| node.scope()).collect();
    let captured_effects = persisted_effects
        .iter()
        .map(|effect| {
            let node_scope = effect
                .node_ordinal
                .map(|ordinal| {
                    usize::try_from(ordinal)
                        .ok()
                        .and_then(|index| node_scopes.get(index).copied())
                        .ok_or(WorkCutError::Corrupt("effect node ordinal"))
                })
                .transpose()?;
            WorkCutEffect::new(
                effect.kind,
                effect.id,
                effect.revision,
                effect.state,
                effect.activity_id,
                effect.agent,
                node_scope,
            )
        })
        .collect::<Result<Vec<_>, WorkCutError>>()?;

    let request_digest = request.request_digest();
    let parts = SnapshotParts {
        cut_id: request.cut_id(),
        election_id: request.election_id(),
        destination_id: request.destination_id(),
        backend_id: request.backend_id().into_uuid(),
        workspace_id: request.workspace_id().into_uuid(),
        issuer_id: decode_id(&cut.issuer_id)?,
        workspace_revision: cut.workspace_revision,
        leadership_revision: cut.leadership_revision,
        grant_issued_at: cut.grant_issued_at,
        grant_expires_at: cut.grant_expires_at,
        prepared_at: cut.prepared_at,
        roster_digest: request.roster_digest(),
        request_digest: request_digest.as_bytes(),
        parties: [
            (parties[0].participation, parties[0].profile),
            (parties[1].participation, parties[1].profile),
        ],
        sessions: request.sessions(),
        agents: inventory.agents(),
        nodes: inventory.nodes(),
        team_nodes: &team_nodes,
        effects: &persisted_effects,
        state: cut.state,
        revision: cut.revision,
        updated_at: cut.updated_at,
    };
    let snapshot = digest_snapshot(&parts)?;
    if snapshot != cut.snapshot_digest.as_slice() {
        return Err(WorkCutError::Corrupt("snapshot digest"));
    }
    let issuer_id = parts.issuer_id;

    Ok(Some(WorkCutRecord {
        request,
        inventory,
        effects: captured_effects,
        issuer: OrchestrationIssuerId::from_uuid(issuer_id),
        prepared_at: TimestampMillis::new(cut.prepared_at)
            .map_err(|_| WorkCutError::Corrupt("cut prepared time"))?,
        snapshot_digest: cut
            .snapshot_digest
            .try_into()
            .map_err(|_| WorkCutError::Corrupt("cut snapshot digest length"))?,
        authorization_issued_at: TimestampMillis::new(cut.grant_issued_at)
            .map_err(|_| WorkCutError::Corrupt("cut grant issue time"))?,
        authorization_expires_at: TimestampMillis::new(cut.grant_expires_at)
            .map_err(|_| WorkCutError::Corrupt("cut grant expiry"))?,
        state: decode_cut_state(cut.state)?,
        revision: cut.revision,
        updated_at: TimestampMillis::new(cut.updated_at)
            .map_err(|_| WorkCutError::Corrupt("cut update time"))?,
    }))
}

fn result_limit(bound: usize) -> Result<i64, WorkCutError> {
    i64::try_from(bound.saturating_add(1)).map_err(|_| WorkCutError::Bounds)
}

fn ensure_result_bound(actual: usize, bound: usize) -> Result<(), WorkCutError> {
    if actual > bound {
        return Err(WorkCutError::Bounds);
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "one canonical digest commits to every persisted work-cut column"
)]
fn digest_snapshot(parts: &SnapshotParts<'_>) -> Result<Vec<u8>, WorkCutError> {
    let mut hash = Sha256::new();
    hash.update(b"heterarchy-forge-work-cut-snapshot-v1\0");
    for id in [
        parts.cut_id,
        parts.election_id,
        parts.destination_id,
        parts.backend_id,
        parts.workspace_id,
        parts.issuer_id,
    ] {
        hash.update(id.as_bytes());
    }
    for value in [
        parts.workspace_revision,
        parts.leadership_revision,
        parts.grant_issued_at,
        parts.grant_expires_at,
        parts.prepared_at,
    ] {
        hash.update(value.to_be_bytes());
    }
    hash.update(parts.roster_digest);
    hash.update(parts.request_digest);
    for (participation, profile) in parts.parties {
        hash.update(participation.as_bytes());
        hash.update(profile.as_bytes());
    }
    hash_count(&mut hash, parts.sessions.len());
    for session in parts.sessions {
        hash.update([side_code(session.side())]);
        hash.update(session.session_id().into_uuid().as_bytes());
    }
    hash_count(&mut hash, parts.agents.len());
    for agent in parts.agents {
        let binding = agent.binding();
        hash.update([side_code(binding.side())]);
        hash.update(binding.activity_id().into_uuid().as_bytes());
        hash.update(binding.agent_id().into_uuid().as_bytes());
        hash.update(binding.session_id().into_uuid().as_bytes());
        hash_principal(&mut hash, binding.principal());
        hash.update(agent.revision().get().to_be_bytes());
        let focus = agent.focus();
        match focus.goal() {
            Some(goal) => {
                hash.update([1u8]);
                hash.update(goal.goal_id().into_uuid().as_bytes());
                hash.update(goal.expected_revision().get().to_be_bytes());
            }
            None => hash.update([0u8]),
        }
        match focus.dag_revision() {
            Some(dag) => {
                hash.update([1u8]);
                hash.update(dag.get().to_be_bytes());
            }
            None => hash.update([0u8]),
        }
        match focus.node() {
            Some(node) => {
                hash.update([1u8]);
                hash.update(node.node_id().into_uuid().as_bytes());
                hash.update(node.expected_revision().get().to_be_bytes());
            }
            None => hash.update([0u8]),
        }
    }
    hash_count(&mut hash, parts.nodes.len());
    for node in parts.nodes {
        hash.update(node.agent_id().into_uuid().as_bytes());
        hash.update(node.scope().activity_id().into_uuid().as_bytes());
        hash.update(node.scope().goal_id().into_uuid().as_bytes());
        hash.update(node.scope().goal_created_at().get().to_be_bytes());
        hash.update(node.scope().dag_base_goal_revision().get().to_be_bytes());
        hash.update(node.scope().dag_revision().get().to_be_bytes());
        hash.update(node.scope().node_id().into_uuid().as_bytes());
        hash.update(node.goal_revision().get().to_be_bytes());
        hash.update(node.head_dag_revision().get().to_be_bytes());
        hash.update(node.head_revision().get().to_be_bytes());
        hash.update(node.node_revision().get().to_be_bytes());
        hash.update(lifecycle_code(node.node_state())?.to_be_bytes());
        hash.update([u8::from(node.direct_focus())]);
        match node.assignment() {
            Some(assignment) => {
                hash.update([1u8]);
                hash.update(assignment.assignment_id().into_uuid().as_bytes());
                hash.update(assignment.revision().get().to_be_bytes());
                hash.update(assignment_state_code(assignment.state()).to_be_bytes());
                hash.update([u8::from(assignment.cancellation_requested())]);
            }
            None => hash.update([0u8]),
        }
    }
    hash_count(&mut hash, parts.team_nodes.len());
    for scope in parts.team_nodes {
        hash.update(scope.activity_id().into_uuid().as_bytes());
        hash.update(scope.goal_id().into_uuid().as_bytes());
        hash.update(scope.goal_created_at().get().to_be_bytes());
        hash.update(scope.dag_base_goal_revision().get().to_be_bytes());
        hash.update(scope.dag_revision().get().to_be_bytes());
        hash.update(scope.node_id().into_uuid().as_bytes());
    }
    hash_count(&mut hash, parts.effects.len());
    for effect in parts.effects {
        hash.update([kind_code(effect.kind)]);
        match effect.agent {
            Some(agent) => {
                hash.update([1u8]);
                hash.update(agent.into_uuid().as_bytes());
            }
            None => hash.update([0]),
        }
        match effect.node_ordinal {
            Some(ordinal) => {
                hash.update([1u8]);
                hash.update(ordinal.to_be_bytes());
            }
            None => hash.update([0]),
        }
        hash.update(effect.activity_id.into_uuid().as_bytes());
        hash.update(effect.revision.to_be_bytes());
        hash.update(effect.state.to_be_bytes());
    }
    hash.update(parts.state.to_be_bytes());
    hash.update(parts.revision.to_be_bytes());
    hash.update(parts.updated_at.to_be_bytes());
    Ok(hash.finalize().to_vec())
}

#[allow(
    clippy::too_many_lines,
    reason = "one persistence pass covers every work-cut table"
)]
fn persist(
    transaction: &Transaction<'_>,
    request: &WorkCutRequest,
    grant: &WorkCutGrant,
    issuer: OrchestrationIssuerId,
    now: TimestampMillis,
    inventory: &WorkCutInventory,
    captured: &[WorkCutEffect],
) -> Result<(), WorkCutError> {
    let team_nodes: Vec<WorkCutNodeScope> = match request.scope() {
        WorkCutScope::Workspace => Vec::new(),
        WorkCutScope::Team { nodes, .. } => nodes.clone(),
    };
    let persisted_effects = persisted_effects(captured, inventory.nodes());
    let parties = [
        (
            request.parties()[0].participation_id(),
            request.parties()[0].profile_id(),
        ),
        (
            request.parties()[1].participation_id(),
            request.parties()[1].profile_id(),
        ),
    ];
    let request_digest = request.request_digest();
    let parts = SnapshotParts {
        cut_id: request.cut_id(),
        election_id: request.election_id(),
        destination_id: request.destination_id(),
        backend_id: request.backend_id().into_uuid(),
        workspace_id: request.workspace_id().into_uuid(),
        issuer_id: issuer.into_uuid(),
        workspace_revision: request.workspace_revision().get(),
        leadership_revision: request.leadership_revision(),
        grant_issued_at: grant.issued_at().get(),
        grant_expires_at: grant.expires_at().get(),
        prepared_at: now.get(),
        roster_digest: request.roster_digest(),
        request_digest: request_digest.as_bytes(),
        parties,
        sessions: request.sessions(),
        agents: inventory.agents(),
        nodes: inventory.nodes(),
        team_nodes: &team_nodes,
        effects: &persisted_effects,
        state: 0,
        revision: 1,
        updated_at: now.get(),
    };
    let snapshot = digest_snapshot(&parts)?;
    let (scope_kind, team_id) = match request.scope() {
        WorkCutScope::Workspace => (0, None),
        WorkCutScope::Team { team_id, .. } => (1, Some(team_id.as_bytes().to_vec())),
    };
    transaction.execute(
        "INSERT INTO leadership_work_cuts (
             cut_id, workspace_id, election_id, destination_id, backend_id, issuer_id,
             grant_issued_at_ms, grant_expires_at_ms, workspace_revision, leadership_revision,
             scope_kind, team_id,
             incumbent_participation_id, elected_participation_id,
             incumbent_profile_id, elected_profile_id,
             roster_digest, request_digest, snapshot_digest,
             state, revision, prepared_at_ms, updated_at_ms,
             team_node_count, session_count, agent_count, node_count, effect_count
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16,
                   ?17, ?18, ?19, 0, 1, ?20, ?20, ?21, ?22, ?23, ?24, ?25)",
        params![
            request.cut_id().as_bytes(),
            request.workspace_id().into_uuid().as_bytes(),
            request.election_id().as_bytes(),
            request.destination_id().as_bytes(),
            request.backend_id().into_uuid().as_bytes(),
            issuer.into_uuid().as_bytes(),
            grant.issued_at().get(),
            grant.expires_at().get(),
            request.workspace_revision().get(),
            request.leadership_revision(),
            scope_kind,
            team_id,
            parties[0].0.as_bytes(),
            parties[1].0.as_bytes(),
            parties[0].1.as_bytes(),
            parties[1].1.as_bytes(),
            request.roster_digest().as_slice(),
            request.request_digest().as_bytes().as_slice(),
            snapshot.as_slice(),
            now.get(),
            bounded_count(team_nodes.len())?,
            bounded_count(request.sessions().len())?,
            bounded_count(inventory.agents().len())?,
            bounded_count(inventory.nodes().len())?,
            bounded_count(persisted_effects.len())?,
        ],
    )?;

    for session in request.sessions() {
        transaction.execute(
            "INSERT INTO leadership_work_cut_sessions (cut_id, session_id, side)
             VALUES (?1, ?2, ?3)",
            params![
                request.cut_id().as_bytes(),
                session.session_id().into_uuid().as_bytes(),
                i64::from(side_code(session.side())),
            ],
        )?;
    }

    for agent in inventory.agents() {
        let binding = agent.binding();
        let (principal_kind, principal_id) = encode_principal(binding.principal());
        let focus = agent.focus();
        let (focus_goal_id, focus_goal_revision) = match focus.goal() {
            Some(goal) => (
                Some(goal.goal_id().into_uuid().as_bytes().to_vec()),
                Some(goal.expected_revision().get()),
            ),
            None => (None, None),
        };
        let focus_node_id = focus
            .node()
            .map(|node| node.node_id().into_uuid().as_bytes().to_vec());
        let focus_node_revision = focus.node().map(|node| node.expected_revision().get());
        transaction.execute(
            "INSERT INTO leadership_work_cut_agents (
                 cut_id, agent_id, activity_id, session_id, side,
                 principal_kind, principal_id, agent_revision,
                 focus_goal_id, focus_goal_revision, focus_dag_revision,
                 focus_node_id, focus_node_revision
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                request.cut_id().as_bytes(),
                binding.agent_id().into_uuid().as_bytes(),
                binding.activity_id().into_uuid().as_bytes(),
                binding.session_id().into_uuid().as_bytes(),
                i64::from(side_code(binding.side())),
                principal_kind,
                principal_id,
                agent.revision().get(),
                focus_goal_id,
                focus_goal_revision,
                focus.dag_revision().map(DagRevisionNumber::get),
                focus_node_id,
                focus_node_revision,
            ],
        )?;
    }

    for (ordinal, node) in inventory.nodes().iter().enumerate() {
        let assignment = node.assignment();
        let (assignment_id, assignment_revision, assignment_state, assignment_cancellation) =
            match assignment {
                Some(assignment) => (
                    Some(assignment.assignment_id().into_uuid().as_bytes().to_vec()),
                    Some(assignment.revision().get()),
                    Some(assignment_state_code(assignment.state())),
                    Some(i64::from(assignment.cancellation_requested())),
                ),
                None => (None, None, None, None),
            };
        transaction.execute(
            "INSERT INTO leadership_work_cut_nodes (
                 cut_id, ordinal, agent_id, activity_id, goal_id, goal_created_at_ms,
                 goal_revision, dag_revision, dag_base_goal_revision, head_dag_revision,
                 dag_head_revision, node_id, node_revision, lifecycle_state, direct_focus,
                 assignment_id, assignment_revision, assignment_state, assignment_cancellation
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15,
                       ?16, ?17, ?18, ?19)",
            params![
                request.cut_id().as_bytes(),
                i64::try_from(ordinal).map_err(|_| WorkCutError::Bounds)?,
                node.agent_id().into_uuid().as_bytes(),
                node.scope().activity_id().into_uuid().as_bytes(),
                node.scope().goal_id().into_uuid().as_bytes(),
                node.scope().goal_created_at().get(),
                node.goal_revision().get(),
                node.scope().dag_revision().get(),
                node.scope().dag_base_goal_revision().get(),
                node.head_dag_revision().get(),
                node.head_revision().get(),
                node.scope().node_id().into_uuid().as_bytes(),
                node.node_revision().get(),
                lifecycle_code(node.node_state())?,
                i64::from(node.direct_focus()),
                assignment_id,
                assignment_revision,
                assignment_state,
                assignment_cancellation,
            ],
        )?;
    }

    for (ordinal, scope) in team_nodes.iter().enumerate() {
        transaction.execute(
            "INSERT INTO leadership_work_cut_team_nodes (
                 cut_id, ordinal, activity_id, goal_id, goal_created_at_ms,
                 dag_base_goal_revision, dag_revision, node_id
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                request.cut_id().as_bytes(),
                i64::try_from(ordinal).map_err(|_| WorkCutError::Bounds)?,
                scope.activity_id().into_uuid().as_bytes(),
                scope.goal_id().into_uuid().as_bytes(),
                scope.goal_created_at().get(),
                scope.dag_base_goal_revision().get(),
                scope.dag_revision().get(),
                scope.node_id().into_uuid().as_bytes(),
            ],
        )?;
    }

    for effect in &persisted_effects {
        transaction.execute(
            "INSERT INTO leadership_work_cut_effects (
                 cut_id, effect_kind, effect_id, agent_id, node_ordinal, activity_id,
                 effect_revision, effect_state
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                request.cut_id().as_bytes(),
                i64::from(kind_code(effect.kind)),
                effect.id.as_bytes(),
                effect
                    .agent
                    .map(|agent| agent.into_uuid().as_bytes().to_vec()),
                effect.node_ordinal,
                effect.activity_id.into_uuid().as_bytes(),
                effect.revision,
                effect.state,
            ],
        )?;
    }
    Ok(())
}

fn persisted_effects(
    captured: &[WorkCutEffect],
    nodes: &[WorkInventoryNode],
) -> Vec<PersistedEffect> {
    captured
        .iter()
        .map(|effect| PersistedEffect {
            kind: effect.kind(),
            id: effect.id(),
            agent: effect.agent_id(),
            node_ordinal: effect.node_scope().and_then(|scope| {
                nodes
                    .iter()
                    .position(|node| node.scope() == scope)
                    .and_then(|ordinal| i64::try_from(ordinal).ok())
            }),
            activity_id: effect.activity_id(),
            revision: effect.revision(),
            state: effect.state(),
        })
        .collect()
}

struct CutRow {
    workspace_id: Vec<u8>,
    election_id: Vec<u8>,
    destination_id: Vec<u8>,
    backend_id: Vec<u8>,
    issuer_id: Vec<u8>,
    grant_issued_at: i64,
    grant_expires_at: i64,
    workspace_revision: i64,
    leadership_revision: i64,
    scope_kind: i64,
    team_id: Option<Vec<u8>>,
    incumbent_participation_id: Vec<u8>,
    elected_participation_id: Vec<u8>,
    incumbent_profile_id: Vec<u8>,
    elected_profile_id: Vec<u8>,
    roster_digest: Vec<u8>,
    request_digest: Vec<u8>,
    snapshot_digest: Vec<u8>,
    state: i64,
    revision: i64,
    prepared_at: i64,
    updated_at: i64,
}

struct AgentRow {
    side: i64,
    activity_id: Vec<u8>,
    agent_id: Vec<u8>,
    session_id: Vec<u8>,
    principal_kind: i64,
    principal_id: Option<Vec<u8>>,
    agent_revision: i64,
    focus_goal_id: Option<Vec<u8>>,
    focus_goal_revision: Option<i64>,
    focus_dag_revision: Option<i64>,
    focus_node_id: Option<Vec<u8>>,
    focus_node_revision: Option<i64>,
}

struct NodeRow {
    ordinal: i64,
    agent_id: Vec<u8>,
    activity_id: Vec<u8>,
    goal_id: Vec<u8>,
    goal_created_at: i64,
    goal_revision: i64,
    dag_revision: i64,
    dag_base_goal_revision: i64,
    head_dag_revision: i64,
    dag_head_revision: i64,
    node_id: Vec<u8>,
    node_revision: i64,
    lifecycle_state: i64,
    direct_focus: bool,
    assignment_id: Option<Vec<u8>>,
    assignment_revision: Option<i64>,
    assignment_state: Option<i64>,
    assignment_cancellation: Option<i64>,
}

struct WorkCutPartyRow {
    participation: Uuid,
    profile: Uuid,
}

struct SnapshotParts<'a> {
    cut_id: Uuid,
    election_id: Uuid,
    destination_id: Uuid,
    backend_id: Uuid,
    workspace_id: Uuid,
    issuer_id: Uuid,
    workspace_revision: i64,
    leadership_revision: i64,
    grant_issued_at: i64,
    grant_expires_at: i64,
    prepared_at: i64,
    roster_digest: &'a [u8; 32],
    request_digest: &'a [u8; 32],
    parties: [(Uuid, Uuid); 2],
    sessions: &'a [WorkCutSession],
    agents: &'a [WorkInventoryAgent],
    nodes: &'a [WorkInventoryNode],
    team_nodes: &'a [WorkCutNodeScope],
    effects: &'a [PersistedEffect],
    state: i64,
    revision: i64,
    updated_at: i64,
}

#[allow(
    clippy::too_many_lines,
    reason = "one request reconstruction covers every persisted attestation field"
)]
fn rebuild_request(
    cut_id: Uuid,
    cut: &CutRow,
    parties: &[WorkCutPartyRow; 2],
    sessions: &[WorkCutSession],
    bindings: &[WorkCutBinding],
    scope: WorkCutScope,
) -> Result<WorkCutRequest, WorkCutError> {
    let roster_digest: [u8; 32] = cut
        .roster_digest
        .clone()
        .try_into()
        .map_err(|_| WorkCutError::Corrupt("cut roster digest length"))?;
    let request = WorkCutRequest::new(
        cut_id,
        decode_id(&cut.election_id)?,
        decode_id(&cut.destination_id)?,
        ForgeBackendId::from_uuid(decode_id(&cut.backend_id)?),
        WorkspaceId::from_uuid(decode_id(&cut.workspace_id)?),
        WorkspaceRevision::new(cut.workspace_revision)
            .map_err(|_| WorkCutError::Corrupt("cut workspace revision"))?,
        cut.leadership_revision,
        roster_digest,
        [
            WorkCutParty::new(parties[0].participation, parties[0].profile)
                .map_err(WorkCutError::Domain)?,
            WorkCutParty::new(parties[1].participation, parties[1].profile)
                .map_err(WorkCutError::Domain)?,
        ],
        sessions.to_vec(),
        bindings.to_vec(),
        scope,
    )
    .map_err(WorkCutError::Domain)?;
    if request.request_digest().as_bytes() != cut.request_digest.as_slice() {
        return Err(WorkCutError::Corrupt("cut request digest"));
    }
    Ok(request)
}

fn decode_scope_kind(
    cut: &CutRow,
    team_nodes: &[WorkCutNodeScope],
) -> Result<WorkCutScope, WorkCutError> {
    match cut.scope_kind {
        0 => Ok(WorkCutScope::Workspace),
        1 => {
            let team_id = cut
                .team_id
                .as_ref()
                .ok_or(WorkCutError::Corrupt("cut team id"))?;
            Ok(WorkCutScope::Team {
                team_id: decode_id(team_id)?,
                nodes: team_nodes.to_vec(),
            })
        }
        _ => Err(WorkCutError::Corrupt("cut scope kind")),
    }
}

fn decode_focus(agent: &AgentRow) -> Result<AgentFocus, WorkCutError> {
    let goal = match (&agent.focus_goal_id, agent.focus_goal_revision) {
        (Some(goal_id), Some(revision)) => Some(GoalAttribution::new(
            GoalId::from_uuid(decode_id(goal_id)?),
            GoalRevision::new(revision)
                .map_err(|_| WorkCutError::Corrupt("focus Goal revision"))?,
        )),
        (None, None) => None,
        _ => return Err(WorkCutError::Corrupt("agent focus Goal")),
    };
    let node = match (&agent.focus_node_id, agent.focus_node_revision) {
        (Some(node_id), Some(revision)) => Some(AgentFocusNode::new(
            DagNodeId::from_uuid(decode_id(node_id)?),
            DagNodeRevision::new(revision)
                .map_err(|_| WorkCutError::Corrupt("focus node revision"))?,
        )),
        (None, None) => None,
        _ => return Err(WorkCutError::Corrupt("agent focus node")),
    };
    let dag_revision = match agent.focus_dag_revision {
        Some(dag) => Some(
            DagRevisionNumber::new(dag).map_err(|_| WorkCutError::Corrupt("focus DAG revision"))?,
        ),
        None => None,
    };
    AgentFocus::new(goal, dag_revision, node).map_err(|_| WorkCutError::Corrupt("agent focus"))
}

fn decode_node(node: &NodeRow) -> Result<WorkInventoryNode, WorkCutError> {
    let scope = decode_scope(
        &node.activity_id,
        &node.goal_id,
        node.goal_created_at,
        node.dag_base_goal_revision,
        node.dag_revision,
        &node.node_id,
    )?;
    let assignment = match (
        &node.assignment_id,
        node.assignment_revision,
        node.assignment_state,
        node.assignment_cancellation,
    ) {
        (Some(id), Some(revision), Some(state), Some(cancellation)) => {
            Some(WorkInventoryAssignment {
                assignment_id: AgentAssignmentId::from_uuid(decode_id(id)?),
                revision: AgentAssignmentRevision::new(revision)
                    .map_err(|_| WorkCutError::Corrupt("assignment revision"))?,
                state: decode_assignment_state(state)?,
                cancellation_requested: cancellation != 0,
            })
        }
        (None, None, None, None) => None,
        _ => return Err(WorkCutError::Corrupt("cut node assignment")),
    };
    Ok(WorkInventoryNode {
        agent_id: AgentInstanceId::from_uuid(decode_id(&node.agent_id)?),
        scope,
        goal_revision: GoalRevision::new(node.goal_revision)
            .map_err(|_| WorkCutError::Corrupt("cut Goal revision"))?,
        head_dag_revision: DagRevisionNumber::new(node.head_dag_revision)
            .map_err(|_| WorkCutError::Corrupt("cut head DAG revision"))?,
        head_revision: DagHeadRevision::new(node.dag_head_revision)
            .map_err(|_| WorkCutError::Corrupt("cut head revision"))?,
        node_revision: DagNodeRevision::new(node.node_revision)
            .map_err(|_| WorkCutError::Corrupt("cut node revision"))?,
        node_state: decode_lifecycle(node.lifecycle_state)?,
        direct_focus: node.direct_focus,
        assignment,
    })
}

fn decode_scope(
    activity: &[u8],
    goal: &[u8],
    created: i64,
    base: i64,
    dag: i64,
    node: &[u8],
) -> Result<WorkCutNodeScope, WorkCutError> {
    WorkCutNodeScope::new(
        ActivityId::from_uuid(decode_id(activity)?),
        GoalId::from_uuid(decode_id(goal)?),
        TimestampMillis::new(created).map_err(|_| WorkCutError::Corrupt("Goal creation time"))?,
        GoalRevision::new(base).map_err(|_| WorkCutError::Corrupt("DAG base Goal revision"))?,
        DagRevisionNumber::new(dag).map_err(|_| WorkCutError::Corrupt("DAG revision"))?,
        DagNodeId::from_uuid(decode_id(node)?),
    )
    .map_err(|_| WorkCutError::Corrupt("node scope"))
}

fn decode_cut_state(state: i64) -> Result<WorkCutState, WorkCutError> {
    match state {
        0 => Ok(WorkCutState::Held),
        1 => Ok(WorkCutState::Released),
        _ => Err(WorkCutError::Corrupt("cut state")),
    }
}

fn decode_kind(kind: i64) -> Result<WorkCutEffectKind, WorkCutError> {
    match kind {
        0 => Ok(WorkCutEffectKind::WriterLease),
        1 => Ok(WorkCutEffectKind::Execution),
        2 => Ok(WorkCutEffectKind::ChangeSet),
        _ => Err(WorkCutError::Corrupt("cut effect kind")),
    }
}

const fn kind_code(kind: WorkCutEffectKind) -> u8 {
    match kind {
        WorkCutEffectKind::WriterLease => 0,
        WorkCutEffectKind::Execution => 1,
        WorkCutEffectKind::ChangeSet => 2,
    }
}

const fn side_code(side: WorkCutSide) -> u8 {
    match side {
        WorkCutSide::Incumbent => 0,
        WorkCutSide::Elected => 1,
    }
}

const fn decode_side(side: i64) -> Result<WorkCutSide, WorkCutError> {
    match side {
        0 => Ok(WorkCutSide::Incumbent),
        1 => Ok(WorkCutSide::Elected),
        _ => Err(WorkCutError::Corrupt("cut session side")),
    }
}

const fn decode_lifecycle(state: i64) -> Result<DagNodeStatus, WorkCutError> {
    match state {
        0 => Ok(DagNodeStatus::Pending),
        1 => Ok(DagNodeStatus::Active),
        2 => Ok(DagNodeStatus::Blocked),
        3 => Ok(DagNodeStatus::Completed),
        4 => Ok(DagNodeStatus::Failed),
        5 => Ok(DagNodeStatus::Skipped),
        6 => Ok(DagNodeStatus::Cancelled),
        _ => Err(WorkCutError::Corrupt("cut node lifecycle")),
    }
}

fn lifecycle_code(state: DagNodeStatus) -> Result<i64, WorkCutError> {
    match state {
        DagNodeStatus::Pending => Ok(0),
        DagNodeStatus::Active => Ok(1),
        DagNodeStatus::Blocked => Ok(2),
        DagNodeStatus::Completed => Ok(3),
        DagNodeStatus::Failed => Ok(4),
        DagNodeStatus::Skipped => Ok(5),
        DagNodeStatus::Cancelled => Ok(6),
        DagNodeStatus::Ready => Err(WorkCutError::Corrupt("cut node lifecycle")),
    }
}

const fn decode_assignment_state(state: i64) -> Result<AgentAssignmentState, WorkCutError> {
    match state {
        0 => Ok(AgentAssignmentState::Offered),
        1 => Ok(AgentAssignmentState::Running),
        2 => Ok(AgentAssignmentState::Submitted),
        3 => Ok(AgentAssignmentState::Accepted),
        4 => Ok(AgentAssignmentState::Rejected),
        5 => Ok(AgentAssignmentState::Cancelled),
        6 => Ok(AgentAssignmentState::Interrupted),
        _ => Err(WorkCutError::Corrupt("cut assignment state")),
    }
}

const fn assignment_state_code(state: AgentAssignmentState) -> i64 {
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

fn encode_principal(principal: AuthenticatedPrincipal) -> (i64, Option<Vec<u8>>) {
    match principal {
        AuthenticatedPrincipal::TrustedStdio => (0, None),
        AuthenticatedPrincipal::DirectToken(id) => (1, Some(id.into_uuid().as_bytes().to_vec())),
        AuthenticatedPrincipal::OAuthGrant(id) => (2, Some(id.into_uuid().as_bytes().to_vec())),
    }
}

fn decode_principal(kind: i64, id: Option<&[u8]>) -> Result<AuthenticatedPrincipal, WorkCutError> {
    match (kind, id) {
        (0, None) => Ok(AuthenticatedPrincipal::TrustedStdio),
        (1, Some(id)) => Ok(AuthenticatedPrincipal::DirectToken(
            DirectTokenId::from_uuid(decode_id(id)?),
        )),
        (2, Some(id)) => Ok(AuthenticatedPrincipal::OAuthGrant(OAuthGrantId::from_uuid(
            decode_id(id)?,
        ))),
        _ => Err(WorkCutError::Corrupt("cut principal")),
    }
}

fn hash_principal(hash: &mut Sha256, principal: AuthenticatedPrincipal) {
    match principal {
        AuthenticatedPrincipal::TrustedStdio => hash.update([0u8]),
        AuthenticatedPrincipal::DirectToken(id) => {
            hash.update([1u8]);
            hash.update(id.into_uuid().as_bytes());
        }
        AuthenticatedPrincipal::OAuthGrant(id) => {
            hash.update([2u8]);
            hash.update(id.into_uuid().as_bytes());
        }
    }
}

fn hash_count(hash: &mut Sha256, count: usize) {
    let encoded = u32::try_from(count).unwrap_or(u32::MAX);
    hash.update(encoded.to_be_bytes());
}

fn bounded_count(count: usize) -> Result<i64, WorkCutError> {
    i64::try_from(count).map_err(|_| WorkCutError::Bounds)
}
