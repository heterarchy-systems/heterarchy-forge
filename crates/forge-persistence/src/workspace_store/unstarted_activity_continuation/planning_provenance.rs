//! Closed validation and canonical digest for retained Goal/DAG/Assignment planning provenance.

use forge_domain::{
    ActivityId, AgentAssignmentOrigin, AgentAssignmentState, AgentDagPlanRequestId, AgentWorkPhase,
    AgentWorkSummary, AgentWorkUpdate, AgentWorkUpdateSequence, DagHeadRevision, DagNodeLifecycle,
    DagNodeRevision, DagRevisionNumber, GoalId, GoalMutationKind, GoalMutationRequestId,
    GoalRevision, GoalStatusKind, WorkspaceId,
};
use rusqlite::{Connection, OptionalExtension, params, types::ValueRef};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::UnstartedActivityContinuationStoreError;

const DOMAIN: &[u8] = b"heterarchy.forge.unstarted-activity-continuation.planning-provenance.v1";
const MAX_GOALS: usize = forge_domain::MAX_GOAL_LIST_RESULTS as usize;
const MAX_ASSIGNMENTS: usize = forge_domain::MAX_AGENT_ASSIGNMENTS_PER_WORKSPACE;
const PLAN_SUMMARY: &str = "Committed a Coordinator-authorized DAG plan";

pub(super) fn validate_and_digest_planning_provenance(
    connection: &Connection,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
) -> Result<[u8; 32], UnstartedActivityContinuationStoreError> {
    let goals = validate_goals(connection, workspace_id, activity_id)?;
    validate_assignments(connection, workspace_id, activity_id, &goals)?;
    validate_closed_counterparts(connection, workspace_id, activity_id)?;
    validate_semantic_cursor(connection, workspace_id)?;

    let workspace = workspace_id.into_uuid().into_bytes();
    let activity = activity_id.into_uuid().into_bytes();
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    for (table, sql) in DIGEST_QUERIES {
        hash_rows(&mut hasher, connection, table, sql, &workspace, &activity)?;
    }
    Ok(hasher.finalize().into())
}

fn validate_semantic_cursor(
    connection: &Connection,
    workspace_id: WorkspaceId,
) -> Result<(), UnstartedActivityContinuationStoreError> {
    let event_count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM semantic_events WHERE workspace_id=?1",
        params![workspace_id.into_uuid().as_bytes()],
        |row| row.get(0),
    )?;
    let meta = connection
        .query_row(
            "SELECT high_water_seq,retained_low FROM semantic_events_meta WHERE workspace_id=?1",
            params![workspace_id.into_uuid().as_bytes()],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()?;
    if event_count == 0 {
        if meta.is_some_and(|(high_water, retained_low)| high_water != 0 || retained_low != 0) {
            return Err(conflict("semantic event cursor differs from empty stream"));
        }
        return Ok(());
    }
    let maximum: i64 = connection.query_row(
        "SELECT MAX(sequence) FROM semantic_events WHERE workspace_id=?1",
        params![workspace_id.into_uuid().as_bytes()],
        |row| row.get(0),
    )?;
    if meta != Some((maximum, 0)) {
        return Err(conflict(
            "semantic event cursor is missing, pruned, or not at Workspace high-water",
        ));
    }
    Ok(())
}

fn validate_goals(
    connection: &Connection,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
) -> Result<Vec<ValidatedGoal>, UnstartedActivityContinuationStoreError> {
    let goal_ids = scoped_ids(
        connection,
        "SELECT goal_id FROM goals WHERE workspace_id=?1 AND activity_id=?2 ORDER BY goal_id",
        workspace_id,
        activity_id,
        MAX_GOALS,
        "Goal census",
    )?;
    if goal_ids.is_empty() {
        return Err(UnstartedActivityContinuationStoreError::Conflict(
            "planning provenance has no Goal",
        ));
    }

    let mut validated = Vec::with_capacity(goal_ids.len());
    for raw_goal_id in goal_ids {
        let goal_id = GoalId::from_uuid(decode_uuid(&raw_goal_id, "goals.goal_id")?);
        let goal = crate::workspace_goals::get_goal(connection, goal_id)
            .map_err(|_| corrupt("Goal canonical projection"))?
            .ok_or_else(|| corrupt("Goal canonical projection missing"))?;
        if goal.workspace_id() != workspace_id
            || goal.activity_id() != activity_id
            || goal.revision() != GoalRevision::INITIAL
            || goal.status().kind() != GoalStatusKind::Active
            || goal.timestamps().created_at() != goal.timestamps().updated_at()
        {
            return Err(conflict("Goal is not an active initial projection"));
        }
        validate_creation_watermark(connection, workspace_id, &goal)?;
        let receipt = validate_goal_receipt(connection, workspace_id, activity_id, &goal)?;
        let plan = validate_plan(
            connection,
            workspace_id,
            activity_id,
            &goal,
            receipt.data().actor,
        )?;
        validate_goal_events(connection, workspace_id, &goal, &plan)?;
        validated.push(ValidatedGoal {
            goal_id,
            created_at_ms: goal.timestamps().created_at().get(),
            plan,
        });
    }
    Ok(validated)
}

fn validate_creation_watermark(
    connection: &Connection,
    workspace_id: WorkspaceId,
    goal: &forge_domain::RegisteredGoal,
) -> Result<(), UnstartedActivityContinuationStoreError> {
    let watermark: Option<i64> = connection
        .query_row(
            "SELECT greatest_created_at_ms FROM goal_creation_watermarks WHERE workspace_id=?1 AND goal_id=?2",
            params![workspace_id.into_uuid().as_bytes(), goal.id().into_uuid().as_bytes()],
            |row| row.get(0),
        )
        .optional()?;
    if watermark != Some(goal.timestamps().created_at().get()) {
        return Err(conflict("Goal creation watermark differs"));
    }
    Ok(())
}

fn validate_goal_receipt(
    connection: &Connection,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    goal: &forge_domain::RegisteredGoal,
) -> Result<forge_domain::GoalMutationReceipt, UnstartedActivityContinuationStoreError> {
    let request_ids = scoped_child_ids(
        connection,
        "SELECT request_id FROM goal_mutation_receipts WHERE workspace_id=?1 AND activity_id=?2 AND goal_id=?3 ORDER BY request_id",
        workspace_id,
        activity_id,
        goal.id().into_uuid().as_bytes(),
        "Goal CREATE receipt",
    )?;
    if request_ids.len() != 1 {
        return Err(conflict("Goal does not have exactly one mutation receipt"));
    }
    let request_id = GoalMutationRequestId::from_uuid(decode_uuid(
        &request_ids[0],
        "goal_mutation_receipts.request_id",
    )?);
    let receipt = crate::workspace_goal_mutations::read_receipt(connection, request_id)
        .map_err(|_| corrupt("Goal mutation receipt canonical projection"))?
        .ok_or_else(|| corrupt("Goal mutation receipt missing"))?;
    let data = receipt.data();
    if data.request_id != request_id
        || data.actor.workspace_id() != workspace_id
        || data.actor.activity_id() != activity_id
        || data.goal_id != goal.id()
        || data.kind != GoalMutationKind::Create
        || data.expected_revision.is_some()
        || data.result_revision != GoalRevision::INITIAL
        || data.result_status != GoalStatusKind::Active
        || data.observed_at != goal.timestamps().created_at()
        || data.review_id.is_some()
    {
        return Err(conflict("Goal CREATE receipt differs from Goal"));
    }
    Ok(receipt)
}

fn validate_plan(
    connection: &Connection,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    goal: &forge_domain::RegisteredGoal,
    create_actor: forge_domain::ActivityCoordinatorActor,
) -> Result<ValidatedPlan, UnstartedActivityContinuationStoreError> {
    let request_ids = scoped_child_ids(
        connection,
        "SELECT request_id FROM agent_dag_plan_ledger WHERE workspace_id=?1 AND activity_id=?2 AND goal_id=?3 ORDER BY request_id",
        workspace_id,
        activity_id,
        goal.id().into_uuid().as_bytes(),
        "DAG plan ledger",
    )?;
    if request_ids.len() != 1 {
        return Err(conflict("Goal does not have exactly one DAG plan ledger"));
    }
    let request_id = AgentDagPlanRequestId::from_uuid(decode_uuid(
        &request_ids[0],
        "agent_dag_plan_ledger.request_id",
    )?);
    let plan = crate::workspace_agent_dag::read_plan_record(connection, request_id)
        .map_err(|_| corrupt("DAG plan ledger canonical projection"))?
        .ok_or_else(|| corrupt("DAG plan ledger missing"))?;
    if plan.request_id() != request_id
        || plan.actor() != create_actor
        || plan.actor().workspace_id() != workspace_id
        || plan.actor().activity_id() != activity_id
        || plan.goal().goal_id() != goal.id()
        || plan.goal().expected_revision() != GoalRevision::INITIAL
        || plan.expected_parent_revision().is_some()
        || plan.expected_head_revision().is_some()
        || plan.committed_dag_revision() != DagRevisionNumber::INITIAL
    {
        return Err(conflict(
            "initial DAG plan ledger differs from Goal CREATE authority",
        ));
    }

    let dag = crate::workspace_dags::get_revision_in_transaction(
        connection,
        goal.id(),
        DagRevisionNumber::INITIAL,
    )
    .map_err(|_| corrupt("initial DAG canonical projection"))?
    .ok_or_else(|| corrupt("initial DAG missing"))?;
    if dag.revision().id() != plan.committed_dag_revision_id()
        || dag.revision().goal_id() != goal.id()
        || dag.revision().number() != DagRevisionNumber::INITIAL
        || dag.revision().parent().is_some()
        || dag.revision().base_goal_revision() != GoalRevision::INITIAL
        || dag.revision().created_at() != plan.committed_at()
        || dag.head().goal_id() != goal.id()
        || dag.head().dag_revision() != DagRevisionNumber::INITIAL
        || dag.head().revision() != DagHeadRevision::INITIAL
        || dag.head().updated_at() != plan.committed_at()
        || dag.nodes().is_empty()
        || dag.nodes().len() > forge_domain::MAX_DAG_NODES
        || !dag.lineage().is_empty()
        || !dag.evidence().is_empty()
        || dag.nodes().iter().any(|node| {
            node.goal_id() != goal.id()
                || node.dag_revision() != DagRevisionNumber::INITIAL
                || node.revision() != DagNodeRevision::INITIAL
                || node.created_at() != plan.committed_at()
                || node.updated_at() != plan.committed_at()
                || node.lifecycle() != &DagNodeLifecycle::Pending
        })
    {
        return Err(conflict("initial DAG projection differs from plan ledger"));
    }
    validate_history_update(connection, workspace_id, activity_id, &plan)?;
    Ok(ValidatedPlan {
        actor: plan.actor(),
        committed_at_ms: plan.committed_at().get(),
        node_ids: dag
            .nodes()
            .iter()
            .map(forge_domain::RegisteredDagNode::id)
            .collect(),
    })
}

fn validate_history_update(
    connection: &Connection,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    plan: &crate::workspace_agent_dag::AgentDagPlanRecord,
) -> Result<(), UnstartedActivityContinuationStoreError> {
    let raw = connection
        .query_row(
            "SELECT agent_id,workspace_id,activity_id,update_sequence,phase,summary,evidence_count,observed_at_ms FROM agent_work_updates WHERE update_id=?1",
            params![plan.history_update_id().into_uuid().as_bytes()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?, row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?, row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?, row.get::<_, i64>(7)?,
                ))
            },
        )
        .optional()?;
    let Some((agent, workspace, activity, sequence, phase, summary, evidence_count, observed_at)) =
        raw
    else {
        return Err(corrupt("DAG plan history update missing"));
    };
    let update = AgentWorkUpdate::new(
        plan.history_update_id(),
        forge_domain::AgentInstanceId::from_uuid(decode_uuid(
            &agent,
            "agent_work_updates.agent_id",
        )?),
        WorkspaceId::from_uuid(decode_uuid(&workspace, "agent_work_updates.workspace_id")?),
        ActivityId::from_uuid(decode_uuid(&activity, "agent_work_updates.activity_id")?),
        AgentWorkUpdateSequence::new(sequence)
            .map_err(|_| corrupt("agent_work_updates.update_sequence"))?,
        decode_work_phase(phase)?,
        AgentWorkSummary::new(summary).map_err(|_| corrupt("agent_work_updates.summary"))?,
        Vec::new(),
        forge_domain::TimestampMillis::new(observed_at)
            .map_err(|_| corrupt("agent_work_updates.observed_at_ms"))?,
    )
    .map_err(|_| corrupt("DAG plan history update projection"))?;
    if evidence_count != 0
        || update.agent_id() != plan.actor().agent_id()
        || update.workspace_id() != workspace_id
        || update.activity_id() != activity_id
        || update.sequence() != plan.history_update_sequence()
        || update.phase() != AgentWorkPhase::Planning
        || update.summary().as_str() != PLAN_SUMMARY
        || update.observed_at() != plan.committed_at()
    {
        return Err(conflict("DAG plan history update differs from ledger"));
    }
    Ok(())
}

fn validate_goal_events(
    connection: &Connection,
    workspace_id: WorkspaceId,
    goal: &forge_domain::RegisteredGoal,
    plan: &ValidatedPlan,
) -> Result<(), UnstartedActivityContinuationStoreError> {
    let mut statement = connection.prepare(
        "SELECT sequence,event_kind FROM semantic_events WHERE workspace_id=?1 AND subject_goal_id=?2 ORDER BY sequence",
    )?;
    let rows = statement
        .query_map(
            params![
                workspace_id.into_uuid().as_bytes(),
                goal.id().into_uuid().as_bytes()
            ],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )?
        .collect::<Result<Vec<_>, _>>()?;
    if rows.len() != 3
        || rows[0].1 != "goal_created"
        || rows[1].1 != "dag_committed"
        || rows[2].1 != "plan_published"
    {
        return Err(conflict("Goal semantic event set/order differs"));
    }
    let expected = [
        (
            crate::workspace_semantic_events::SemanticEventKind::GoalCreated,
            None,
            goal.timestamps().created_at().get(),
        ),
        (
            crate::workspace_semantic_events::SemanticEventKind::DagCommitted,
            Some(DagRevisionNumber::INITIAL),
            plan.committed_at_ms,
        ),
        (
            crate::workspace_semantic_events::SemanticEventKind::PlanPublished,
            Some(DagRevisionNumber::INITIAL),
            plan.committed_at_ms,
        ),
    ];
    for ((sequence, _), (kind, dag_revision, observed_at)) in rows.into_iter().zip(expected) {
        let sequence = u64::try_from(sequence).map_err(|_| corrupt("semantic_events.sequence"))?;
        let page = crate::workspace_semantic_events::semantic_events_after(
            connection,
            workspace_id,
            sequence.saturating_sub(1),
            1,
        )
        .map_err(|_| corrupt("semantic event canonical projection"))?;
        let record = page
            .events()
            .first()
            .ok_or_else(|| corrupt("semantic event missing"))?;
        let event = record.event();
        let subjects = event.subjects();
        if record.sequence() != sequence
            || event.kind() != kind
            || event.workspace_id() != workspace_id
            || subjects.goal_id != Some(goal.id())
            || subjects.dag_revision != dag_revision
            || subjects.node_id.is_some()
            || subjects.execution_id.is_some()
            || subjects.change_set_id.is_some()
            || subjects.diff_id.is_some()
            || subjects.verification.is_some()
            || event.revision() != 1
            || event.observed_at().get() != observed_at
        {
            return Err(conflict("semantic event differs from canonical producer"));
        }
    }
    Ok(())
}

fn validate_assignments(
    connection: &Connection,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    goals: &[ValidatedGoal],
) -> Result<(), UnstartedActivityContinuationStoreError> {
    let assignment_ids = scoped_ids(
        connection,
        "SELECT assignment_id FROM agent_assignments WHERE workspace_id=?1 AND activity_id=?2 ORDER BY assignment_id",
        workspace_id,
        activity_id,
        MAX_ASSIGNMENTS,
        "Assignment census",
    )?;
    if assignment_ids.is_empty() {
        return Err(conflict("planning provenance has no offered Assignment"));
    }
    let delegation = crate::workspace_agent_delegation::get(connection, workspace_id)
        .map_err(|_| corrupt("Agent operations delegation canonical projection"))?
        .ok_or_else(|| conflict("Assignment offer lacks source delegation"))?;

    for raw_assignment_id in assignment_ids {
        let assignment_id = forge_domain::AgentAssignmentId::from_uuid(decode_uuid(
            &raw_assignment_id,
            "agent_assignments.assignment_id",
        )?);
        let assignment = crate::workspace_agent_assignments::get(connection, assignment_id)
            .map_err(|_| corrupt("Assignment canonical projection"))?
            .ok_or_else(|| corrupt("Assignment missing"))?;
        let goal = goals
            .iter()
            .find(|goal| goal.goal_id == assignment.goal_id())
            .ok_or_else(|| conflict("Assignment Goal is outside retained plan"))?;
        if assignment.workspace_id() != workspace_id
            || assignment.activity_id() != activity_id
            || assignment.origin() != AgentAssignmentOrigin::CoordinatorOffer
            || assignment.state() != AgentAssignmentState::Offered
            || assignment.revision() != forge_domain::AgentAssignmentRevision::INITIAL
            || assignment.created_at() != assignment.updated_at()
            || assignment.goal_created_at().get() != goal.created_at_ms
            || assignment.goal_revision() != GoalRevision::INITIAL
            || assignment.dag_revision() != DagRevisionNumber::INITIAL
            || assignment.dag_head_revision() != DagHeadRevision::INITIAL
            || assignment.node_revision() != DagNodeRevision::INITIAL
            || !goal.plan.node_ids.contains(&assignment.node_id())
            || assignment.coordinator()
                != forge_domain::AgentAssignmentCoordinator::from_actor(goal.plan.actor)
            || assignment.cancellation_requested()
            || assignment.result().is_some()
            || assignment.reviewed_by().is_some()
        {
            return Err(conflict("Assignment differs from retained initial plan"));
        }
        validate_optional_offer_seal(connection, workspace_id, activity_id, &assignment)?;
        validate_assignment_fact(connection, workspace_id, &assignment, &delegation)?;
    }
    Ok(())
}

fn validate_optional_offer_seal(
    connection: &Connection,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    assignment: &forge_domain::RegisteredAgentAssignment,
) -> Result<(), UnstartedActivityContinuationStoreError> {
    let raw = connection
        .query_row(
            "SELECT authority_kind,coordinator_agent_id,coordinator_session_id,expected_coordinator_revision,sealed_at_ms FROM agent_assignment_offer_seals WHERE workspace_id=?1 AND activity_id=?2 AND assignment_id=?3",
            params![
                workspace_id.into_uuid().as_bytes(),
                activity_id.into_uuid().as_bytes(),
                assignment.id().into_uuid().as_bytes(),
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<Vec<u8>>>(1)?,
                    row.get::<_, Option<Vec<u8>>>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()?;
    let Some((authority_kind, agent_id, session_id, coordinator_revision, sealed_at_ms)) = raw
    else {
        return Ok(());
    };
    let expected = assignment.coordinator();
    let agent_id = agent_id
        .as_deref()
        .map(|value| decode_uuid(value, "agent_assignment_offer_seals.coordinator_agent_id"))
        .transpose()?;
    let session_id = session_id
        .as_deref()
        .map(|value| decode_uuid(value, "agent_assignment_offer_seals.coordinator_session_id"))
        .transpose()?;
    let coordinator_revision = coordinator_revision
        .map(forge_domain::ActivityCoordinatorRevision::new)
        .transpose()
        .map_err(|_| corrupt("agent_assignment_offer_seals.expected_coordinator_revision"))?;
    let sealed_at = forge_domain::TimestampMillis::new(sealed_at_ms)
        .map_err(|_| corrupt("agent_assignment_offer_seals.sealed_at_ms"))?;
    if authority_kind != 1
        || agent_id != Some(expected.agent_id().into_uuid())
        || session_id != Some(expected.session_id().into_uuid())
        || coordinator_revision != Some(expected.revision())
        || sealed_at.get() < assignment.created_at().get()
    {
        return Err(conflict("Assignment offer seal differs from Assignment"));
    }
    Ok(())
}

fn validate_assignment_fact(
    connection: &Connection,
    workspace_id: WorkspaceId,
    assignment: &forge_domain::RegisteredAgentAssignment,
    delegation: &crate::workspace_agent_delegation::AgentOperationsDelegation,
) -> Result<(), UnstartedActivityContinuationStoreError> {
    let sequences = connection
        .prepare(
            "SELECT outbox_sequence FROM effect_fact_outbox_assignment_offered WHERE workspace_id=?1 AND activity_id=?2 AND assignment_id=?3 ORDER BY outbox_sequence",
        )?
        .query_map(
            params![
                workspace_id.into_uuid().as_bytes(),
                assignment.activity_id().into_uuid().as_bytes(),
                assignment.id().into_uuid().as_bytes(),
            ],
            |row| row.get::<_, i64>(0),
        )?
        .collect::<Result<Vec<_>, _>>()?;
    if sequences.len() != 1 {
        return Err(conflict(
            "Assignment does not have exactly one offered fact",
        ));
    }
    let sequence = u64::try_from(sequences[0]).map_err(|_| corrupt("effect_fact sequence"))?;
    let entries = crate::workspace_effect_fact_outbox::read(
        connection,
        workspace_id,
        sequence.saturating_sub(1),
        1,
    )
    .map_err(|_| corrupt("AssignmentOffered canonical projection"))?;
    let entry = entries
        .first()
        .ok_or_else(|| corrupt("AssignmentOffered missing"))?;
    let crate::EffectFact::AssignmentOffered(fact) = entry.fact() else {
        return Err(conflict("Assignment offered fact kind differs"));
    };
    if entry.sequence() != sequence
        || entry.workspace_id() != workspace_id
        || entry.migration_id() != delegation.migration_id()
        || entry.destination_id() != delegation.destination_id()
        || entry.submitted_source_refs().is_some()
        || fact.assignment_id() != assignment.id()
        || fact.workspace_id() != workspace_id
        || fact.activity_id() != assignment.activity_id()
        || fact.goal_id() != assignment.goal_id()
        || fact.node_id() != assignment.node_id()
        || fact.target_agent_id() != assignment.target().agent_id()
        || fact.target_session_id() != Some(assignment.target().session_id())
        || fact.credit_budget() != assignment.credit_budget()
        || fact.offered_at() != assignment.created_at()
    {
        return Err(conflict(
            "AssignmentOffered fact differs from Assignment/delegation",
        ));
    }
    Ok(())
}

fn validate_closed_counterparts(
    connection: &Connection,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
) -> Result<(), UnstartedActivityContinuationStoreError> {
    let workspace = workspace_id.into_uuid().into_bytes();
    let activity = activity_id.into_uuid().into_bytes();
    for (label, sql) in INVALID_COUNTERPART_QUERIES {
        let mut statement = connection.prepare(sql)?;
        if statement.parameter_count() != 2 {
            return Err(corrupt(label));
        }
        let invalid: i64 = statement
            .query_row(params![workspace.as_slice(), activity.as_slice()], |row| {
                row.get(0)
            })?;
        if invalid != 0 {
            return Err(conflict(label));
        }
    }
    Ok(())
}

const INVALID_COUNTERPART_QUERIES: &[(&str, &str)] = &[
    (
        "Goal receipt/plan/DAG/history counterparts are missing, orphaned, or redundant",
        "SELECT EXISTS(
           SELECT 1 FROM goals g WHERE g.workspace_id=?1 AND g.activity_id=?2 AND (
             (SELECT COUNT(*) FROM goal_mutation_receipts r WHERE r.workspace_id=g.workspace_id AND r.activity_id=g.activity_id AND r.goal_id=g.goal_id)<>1 OR
             (SELECT COUNT(*) FROM agent_dag_plan_ledger p WHERE p.workspace_id=g.workspace_id AND p.activity_id=g.activity_id AND p.goal_id=g.goal_id)<>1 OR
             (SELECT COUNT(*) FROM goal_dag_revisions d WHERE d.goal_id=g.goal_id)<>1 OR
             (SELECT COUNT(*) FROM goal_dag_heads h WHERE h.goal_id=g.goal_id)<>1))
         OR EXISTS(SELECT 1 FROM goal_mutation_receipts r LEFT JOIN goals g ON g.workspace_id=r.workspace_id AND g.activity_id=r.activity_id AND g.goal_id=r.goal_id WHERE r.workspace_id=?1 AND r.activity_id=?2 AND g.goal_id IS NULL)
         OR EXISTS(SELECT 1 FROM agent_dag_plan_ledger p LEFT JOIN goals g ON g.workspace_id=p.workspace_id AND g.activity_id=p.activity_id AND g.goal_id=p.goal_id WHERE p.workspace_id=?1 AND p.activity_id=?2 AND g.goal_id IS NULL)
         OR EXISTS(SELECT 1 FROM agent_dag_plan_sessions s LEFT JOIN agent_dag_plan_ledger p ON p.request_id=s.request_id WHERE p.request_id IS NULL)
         OR EXISTS(SELECT 1 FROM agent_work_updates u WHERE u.workspace_id=?1 AND u.activity_id=?2 AND (SELECT COUNT(*) FROM agent_dag_plan_ledger p WHERE p.workspace_id=u.workspace_id AND p.activity_id=u.activity_id AND p.history_update_id=u.update_id)<>1)",
    ),
    (
        "Assignment offered facts/seals are missing, orphaned, redundant, or key-mismatched",
        "SELECT EXISTS(
           SELECT 1 FROM agent_assignments a WHERE a.workspace_id=?1 AND a.activity_id=?2 AND (
             (SELECT COUNT(*) FROM effect_fact_outbox_assignment_offered f WHERE f.workspace_id=a.workspace_id AND f.activity_id=a.activity_id AND f.assignment_id=a.assignment_id)<>1))
         OR EXISTS(SELECT 1 FROM agent_assignment_offer_seals s LEFT JOIN agent_assignments a ON a.workspace_id=s.workspace_id AND a.activity_id=s.activity_id AND a.assignment_id=s.assignment_id WHERE s.workspace_id=?1 AND s.activity_id=?2 AND (a.assignment_id IS NULL OR s.authority_kind<>1 OR s.coordinator_agent_id<>a.coordinator_agent_id OR s.coordinator_session_id<>a.coordinator_session_id OR s.expected_coordinator_revision<>a.coordinator_revision OR s.sealed_at_ms<a.created_at_ms))
         OR EXISTS(SELECT 1 FROM agent_assignment_sources s LEFT JOIN agent_assignments a ON a.assignment_id=s.assignment_id WHERE a.assignment_id IS NULL)
         OR EXISTS(SELECT 1 FROM agent_assignment_sources s JOIN agent_assignments a ON a.assignment_id=s.assignment_id WHERE a.workspace_id=?1 AND a.activity_id=?2)
         OR EXISTS(SELECT 1 FROM effect_fact_outbox_assignment_offered f LEFT JOIN agent_assignments a ON a.workspace_id=f.workspace_id AND a.activity_id=f.activity_id AND a.assignment_id=f.assignment_id LEFT JOIN effect_fact_outbox_entries e ON e.sequence=f.outbox_sequence WHERE f.workspace_id=?1 AND f.activity_id=?2 AND (a.assignment_id IS NULL OR e.sequence IS NULL OR e.fact_kind<>3 OR e.workspace_id<>f.workspace_id OR e.migration_id<>f.migration_id OR e.destination_id<>f.destination_id))
         OR EXISTS(SELECT 1 FROM effect_fact_outbox_entries e LEFT JOIN effect_fact_outbox_assignment_offered f ON f.outbox_sequence=e.sequence WHERE e.workspace_id=?1 AND e.fact_kind=3 AND f.outbox_sequence IS NULL)",
    ),
    (
        "planning semantic events are missing, orphaned, redundant, or foreign",
        "SELECT EXISTS(
           SELECT 1 FROM goals g WHERE g.workspace_id=?1 AND g.activity_id=?2 AND (
             (SELECT COUNT(*) FROM semantic_events e WHERE e.workspace_id=g.workspace_id AND e.subject_goal_id=g.goal_id AND e.event_kind='goal_created')<>1 OR
             (SELECT COUNT(*) FROM semantic_events e WHERE e.workspace_id=g.workspace_id AND e.subject_goal_id=g.goal_id AND e.event_kind='dag_committed')<>1 OR
             (SELECT COUNT(*) FROM semantic_events e WHERE e.workspace_id=g.workspace_id AND e.subject_goal_id=g.goal_id AND e.event_kind='plan_published')<>1))
         OR EXISTS(SELECT 1 FROM semantic_events e LEFT JOIN goals g ON g.workspace_id=e.workspace_id AND g.goal_id=e.subject_goal_id WHERE e.workspace_id=?1 AND e.event_kind IN ('goal_created','dag_committed','plan_published') AND g.goal_id IS NULL)",
    ),
];

struct ValidatedGoal {
    goal_id: GoalId,
    created_at_ms: i64,
    plan: ValidatedPlan,
}

struct ValidatedPlan {
    actor: forge_domain::ActivityCoordinatorActor,
    committed_at_ms: i64,
    node_ids: Vec<forge_domain::DagNodeId>,
}

fn scoped_ids(
    connection: &Connection,
    sql: &str,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    maximum: usize,
    label: &'static str,
) -> Result<Vec<Vec<u8>>, UnstartedActivityContinuationStoreError> {
    let mut statement = connection.prepare(sql)?;
    if statement.parameter_count() != 2 {
        return Err(corrupt(label));
    }
    let rows = statement
        .query_map(
            params![
                workspace_id.into_uuid().as_bytes(),
                activity_id.into_uuid().as_bytes()
            ],
            |row| row.get::<_, Vec<u8>>(0),
        )?
        .collect::<Result<Vec<_>, _>>()?;
    if rows.len() > maximum {
        return Err(conflict(label));
    }
    Ok(rows)
}

fn scoped_child_ids(
    connection: &Connection,
    sql: &str,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    child_id: &[u8],
    label: &'static str,
) -> Result<Vec<Vec<u8>>, UnstartedActivityContinuationStoreError> {
    let mut statement = connection.prepare(sql)?;
    if statement.parameter_count() != 3 {
        return Err(corrupt(label));
    }
    let rows = statement
        .query_map(
            params![
                workspace_id.into_uuid().as_bytes(),
                activity_id.into_uuid().as_bytes(),
                child_id
            ],
            |row| row.get::<_, Vec<u8>>(0),
        )?
        .collect::<Result<Vec<_>, _>>()?;
    if rows.len() > 1 {
        return Err(conflict(label));
    }
    Ok(rows)
}

fn decode_work_phase(
    value: i64,
) -> Result<AgentWorkPhase, UnstartedActivityContinuationStoreError> {
    match value {
        0 => Ok(AgentWorkPhase::Planning),
        1 => Ok(AgentWorkPhase::Executing),
        2 => Ok(AgentWorkPhase::Waiting),
        3 => Ok(AgentWorkPhase::Verifying),
        4 => Ok(AgentWorkPhase::Completed),
        5 => Ok(AgentWorkPhase::Blocked),
        6 => Ok(AgentWorkPhase::Failed),
        _ => Err(corrupt("agent_work_updates.phase")),
    }
}

fn decode_uuid(
    value: &[u8],
    field: &'static str,
) -> Result<Uuid, UnstartedActivityContinuationStoreError> {
    Uuid::from_slice(value).map_err(|_| corrupt(field))
}

fn conflict(detail: &'static str) -> UnstartedActivityContinuationStoreError {
    UnstartedActivityContinuationStoreError::Conflict(detail)
}

fn corrupt(detail: &'static str) -> UnstartedActivityContinuationStoreError {
    UnstartedActivityContinuationStoreError::Corrupt(detail)
}

const DIGEST_QUERIES: &[(&str, &str)] = &[
    (
        "goals",
        "SELECT * FROM goals WHERE workspace_id=?1 AND activity_id=?2 ORDER BY goal_id",
    ),
    (
        "goal_statements",
        "SELECT s.* FROM goal_statements s JOIN goals g ON g.goal_id=s.goal_id WHERE g.workspace_id=?1 AND g.activity_id=?2 ORDER BY s.goal_id,s.statement_kind,s.ordinal",
    ),
    (
        "goal_verification_requirements",
        "SELECT r.* FROM goal_verification_requirements r JOIN goals g ON g.goal_id=r.goal_id WHERE g.workspace_id=?1 AND g.activity_id=?2 ORDER BY r.goal_id,r.ordinal",
    ),
    (
        "goal_creation_watermarks",
        "SELECT w.* FROM goal_creation_watermarks w JOIN goals g ON g.workspace_id=w.workspace_id AND g.goal_id=w.goal_id WHERE g.workspace_id=?1 AND g.activity_id=?2 ORDER BY w.workspace_id,w.goal_id",
    ),
    (
        "goal_mutation_receipts",
        "SELECT * FROM goal_mutation_receipts WHERE workspace_id=?1 AND activity_id=?2 ORDER BY request_id",
    ),
    (
        "goal_dag_revisions",
        "SELECT d.* FROM goal_dag_revisions d JOIN goals g ON g.goal_id=d.goal_id WHERE g.workspace_id=?1 AND g.activity_id=?2 ORDER BY d.goal_id,d.dag_revision",
    ),
    (
        "goal_dag_heads",
        "SELECT h.* FROM goal_dag_heads h JOIN goals g ON g.goal_id=h.goal_id WHERE g.workspace_id=?1 AND g.activity_id=?2 ORDER BY h.goal_id",
    ),
    (
        "goal_dag_nodes",
        "SELECT n.* FROM goal_dag_nodes n JOIN goals g ON g.goal_id=n.goal_id WHERE g.workspace_id=?1 AND g.activity_id=?2 ORDER BY n.goal_id,n.dag_revision,n.ordinal,n.node_id",
    ),
    (
        "goal_dag_node_acceptance",
        "SELECT a.* FROM goal_dag_node_acceptance a JOIN goals g ON g.goal_id=a.goal_id WHERE g.workspace_id=?1 AND g.activity_id=?2 ORDER BY a.goal_id,a.dag_revision,a.node_id,a.ordinal",
    ),
    (
        "goal_dag_edges",
        "SELECT e.* FROM goal_dag_edges e JOIN goals g ON g.goal_id=e.goal_id WHERE g.workspace_id=?1 AND g.activity_id=?2 ORDER BY e.goal_id,e.dag_revision,e.upstream_node_id,e.downstream_node_id",
    ),
    (
        "agent_dag_plan_ledger",
        "SELECT * FROM agent_dag_plan_ledger WHERE workspace_id=?1 AND activity_id=?2 ORDER BY request_id",
    ),
    (
        "agent_dag_plan_sessions",
        "SELECT s.* FROM agent_dag_plan_sessions s JOIN agent_dag_plan_ledger p ON p.request_id=s.request_id WHERE p.workspace_id=?1 AND p.activity_id=?2 ORDER BY s.request_id",
    ),
    (
        "agent_work_updates",
        "SELECT * FROM agent_work_updates WHERE workspace_id=?1 AND activity_id=?2 ORDER BY update_id",
    ),
    (
        "agent_assignments",
        "SELECT * FROM agent_assignments WHERE workspace_id=?1 AND activity_id=?2 ORDER BY assignment_id",
    ),
    (
        "agent_assignment_sources",
        "SELECT s.* FROM agent_assignment_sources s JOIN agent_assignments a ON a.assignment_id=s.assignment_id WHERE a.workspace_id=?1 AND a.activity_id=?2 ORDER BY s.assignment_id,s.ordinal",
    ),
    (
        "agent_assignment_offer_seals",
        "SELECT * FROM agent_assignment_offer_seals WHERE workspace_id=?1 AND activity_id=?2 ORDER BY workspace_id,activity_id,assignment_id",
    ),
    (
        "effect_fact_outbox_assignment_offered",
        "SELECT * FROM effect_fact_outbox_assignment_offered WHERE workspace_id=?1 AND activity_id=?2 ORDER BY outbox_sequence",
    ),
    (
        "effect_fact_outbox_entries",
        "SELECT e.* FROM effect_fact_outbox_entries e JOIN effect_fact_outbox_assignment_offered f ON f.outbox_sequence=e.sequence WHERE f.workspace_id=?1 AND f.activity_id=?2 ORDER BY e.sequence",
    ),
    (
        "agent_operations_delegations",
        "SELECT * FROM agent_operations_delegations WHERE workspace_id=?1 AND length(?2)=16 ORDER BY migration_id",
    ),
    (
        "semantic_events",
        "SELECT e.* FROM semantic_events e JOIN goals g ON g.workspace_id=e.workspace_id AND g.goal_id=e.subject_goal_id WHERE g.workspace_id=?1 AND g.activity_id=?2 AND e.event_kind IN ('goal_created','dag_committed','plan_published') ORDER BY e.sequence",
    ),
    (
        "semantic_events_meta",
        "SELECT * FROM semantic_events_meta WHERE workspace_id=?1 AND length(?2)=16 ORDER BY workspace_id",
    ),
];

fn hash_rows(
    hasher: &mut Sha256,
    connection: &Connection,
    table: &str,
    sql: &str,
    workspace: &[u8; 16],
    activity: &[u8; 16],
) -> Result<(), UnstartedActivityContinuationStoreError> {
    let mut statement = connection.prepare(sql)?;
    let column_count = statement.column_count();
    let mut rows = match statement.parameter_count() {
        1 => statement.query(params![workspace.as_slice()])?,
        2 => statement.query(params![workspace.as_slice(), activity.as_slice()])?,
        _ => return Err(corrupt("planning provenance digest query parameters")),
    };
    let mut row_count = 0_u64;
    hasher.update((table.len() as u64).to_be_bytes());
    hasher.update(table.as_bytes());
    while let Some(row) = rows.next()? {
        row_count = row_count
            .checked_add(1)
            .ok_or_else(|| conflict("planning provenance row count overflow"))?;
        hasher.update((column_count as u64).to_be_bytes());
        for index in 0..column_count {
            match row.get_ref(index)? {
                ValueRef::Null => hasher.update([0]),
                ValueRef::Integer(value) => {
                    hasher.update([1]);
                    hasher.update(value.to_be_bytes());
                }
                ValueRef::Real(value) => {
                    hasher.update([2]);
                    hasher.update(value.to_bits().to_be_bytes());
                }
                ValueRef::Text(value) => {
                    hasher.update([3]);
                    hasher.update((value.len() as u64).to_be_bytes());
                    hasher.update(value);
                }
                ValueRef::Blob(value) => {
                    hasher.update([4]);
                    hasher.update((value.len() as u64).to_be_bytes());
                    hasher.update(value);
                }
            }
        }
    }
    hasher.update(row_count.to_be_bytes());
    Ok(())
}
