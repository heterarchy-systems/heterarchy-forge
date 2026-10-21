//! Durable candidate proposals and exact-recipient read acknowledgments.
//!
//! Neither preparing nor acknowledging a proposal moves work, proves handback
//! or releases custody. Native callers authenticate their issuer/session before
//! entering this persistence boundary. A later reciprocal commit must revalidate
//! current authority, source/recipient fences, drain and preserved work evidence.

use forge_domain::{
    AgentAssignmentContinuationPlan, AgentAssignmentId, AgentAssignmentRevision,
    AgentAssignmentState, AgentAssignmentTarget, AgentInstanceId, AgentInstanceRevision,
    DagNodeRevision, DagNodeStatus, ForgeBackendId, OrchestrationIssuerId, TimestampMillis,
    WorkCreditBudget, WorkCutNodeScope, WorkspaceId,
};
use rusqlite::{Connection, Transaction, TransactionBehavior, params};
use uuid::Uuid;

use super::{WorkCutError, WorkCutRecord, WorkCutState, repository};
use crate::{workspace_agent_assignments, workspace_agents, workspace_dags, workspace_goals};

mod intent;
mod record;
pub(crate) mod schema;

pub use intent::{AssignmentContinuationIntent, AssignmentContinuationIntentError};

const MAX_PROPOSALS_PER_CUT: i64 = 256;

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssignmentContinuationProposal {
    successor_id: AgentAssignmentId,
    transfer_id: Uuid,
    cut_id: Uuid,
    cut_revision: i64,
    workspace_id: WorkspaceId,
    issuer: OrchestrationIssuerId,
    backend: ForgeBackendId,
    cut_request_digest: [u8; 32],
    cut_snapshot_digest: [u8; 32],
    source_ordinal: i64,
    source_scope: WorkCutNodeScope,
    source_agent_id: AgentInstanceId,
    source_assignment_id: AgentAssignmentId,
    source_revision: AgentAssignmentRevision,
    source_digest: [u8; 32],
    recipient: AgentAssignmentTarget,
    node_revision: DagNodeRevision,
    node_state: DagNodeStatus,
    successor_state: AgentAssignmentState,
    credit_budget: Option<WorkCreditBudget>,
    planned_at: TimestampMillis,
    recorded_at: TimestampMillis,
    request_digest: [u8; 32],
    digest: [u8; 32],
}

impl AssignmentContinuationProposal {
    pub const fn successor_id(&self) -> AgentAssignmentId {
        self.successor_id
    }
    pub const fn transfer_id(&self) -> Uuid {
        self.transfer_id
    }
    pub const fn cut_id(&self) -> Uuid {
        self.cut_id
    }
    pub const fn cut_revision(&self) -> i64 {
        self.cut_revision
    }
    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }
    pub const fn issuer(&self) -> OrchestrationIssuerId {
        self.issuer
    }
    pub const fn backend_id(&self) -> ForgeBackendId {
        self.backend
    }
    pub const fn cut_request_digest(&self) -> &[u8; 32] {
        &self.cut_request_digest
    }
    pub const fn cut_snapshot_digest(&self) -> &[u8; 32] {
        &self.cut_snapshot_digest
    }
    pub const fn source_digest(&self) -> &[u8; 32] {
        &self.source_digest
    }
    pub const fn request_digest(&self) -> &[u8; 32] {
        &self.request_digest
    }
    pub const fn source_scope(&self) -> WorkCutNodeScope {
        self.source_scope
    }
    pub const fn source_agent_id(&self) -> AgentInstanceId {
        self.source_agent_id
    }
    pub const fn source_assignment_id(&self) -> AgentAssignmentId {
        self.source_assignment_id
    }
    pub const fn source_revision(&self) -> AgentAssignmentRevision {
        self.source_revision
    }
    pub const fn recipient(&self) -> AgentAssignmentTarget {
        self.recipient
    }
    pub const fn node_revision(&self) -> DagNodeRevision {
        self.node_revision
    }
    pub const fn node_state(&self) -> DagNodeStatus {
        self.node_state
    }
    pub const fn successor_state(&self) -> AgentAssignmentState {
        self.successor_state
    }
    pub const fn credit_budget(&self) -> Option<WorkCreditBudget> {
        self.credit_budget
    }
    pub const fn planned_at(&self) -> TimestampMillis {
        self.planned_at
    }
    pub const fn recorded_at(&self) -> TimestampMillis {
        self.recorded_at
    }
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssignmentContinuationPrepareOutcome {
    Prepared(AssignmentContinuationProposal),
    Existing(AssignmentContinuationProposal),
}

/// Receipt of the proposal, not acceptance of a submitted result or worktree.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssignmentContinuationAcknowledgment {
    request_id: Uuid,
    successor_id: AgentAssignmentId,
    proposal_digest: [u8; 32],
    recipient: AgentAssignmentTarget,
    recorded_at: TimestampMillis,
    digest: [u8; 32],
}
impl AssignmentContinuationAcknowledgment {
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
    pub const fn request_id(&self) -> Uuid {
        self.request_id
    }
    pub const fn successor_id(&self) -> AgentAssignmentId {
        self.successor_id
    }
    pub const fn proposal_digest(&self) -> &[u8; 32] {
        &self.proposal_digest
    }
    pub const fn recipient(&self) -> AgentAssignmentTarget {
        self.recipient
    }
    pub const fn recorded_at(&self) -> TimestampMillis {
        self.recorded_at
    }
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssignmentContinuationAcknowledgeOutcome {
    Recorded(AssignmentContinuationAcknowledgment),
    Existing(AssignmentContinuationAcknowledgment),
}

pub(crate) fn prepare(
    connection: &mut Connection,
    plan: &AgentAssignmentContinuationPlan,
    expected_cut_revision: i64,
    authenticated_issuer: OrchestrationIssuerId,
    actual_backend: ForgeBackendId,
    now: TimestampMillis,
) -> Result<AssignmentContinuationPrepareOutcome, WorkCutError> {
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    prepare_in_tx(
        tx,
        plan,
        expected_cut_revision,
        authenticated_issuer,
        actual_backend,
        now,
    )
}

/// Stable application-intent entrypoint: ONE immediate transaction that first
/// replays an identical original proposal by the exact caller-controlled
/// selectors, then composes the checked domain plan from the live source, cut
/// witness and current DAG/node with worker time before handing it to the
/// shared plan-based validation/insertion owner. Two same-intent callers can
/// therefore never create replay conflicts out of their server clocks. The
/// caller authenticates its issuer before entering this boundary.
pub(crate) fn prepare_intent(
    connection: &mut Connection,
    intent: &AssignmentContinuationIntent,
    authenticated_issuer: OrchestrationIssuerId,
    actual_backend: ForgeBackendId,
    now: TimestampMillis,
) -> Result<AssignmentContinuationPrepareOutcome, WorkCutError> {
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if let Some(existing) = record::load_proposal(&tx, intent.successor_id())? {
        if intent_matches(&existing, intent, authenticated_issuer, actual_backend) {
            tx.commit()?;
            return Ok(AssignmentContinuationPrepareOutcome::Existing(existing));
        }
        return Err(WorkCutError::Conflict("continuation intent replay"));
    }
    let plan = compose_intent_plan(&tx, intent, now)?;
    prepare_in_tx(
        tx,
        &plan,
        intent.cut_revision(),
        authenticated_issuer,
        actual_backend,
        now,
    )
}

/// Exact caller-selector replay comparison. Server planned time and the source
/// snapshot are receipt evidence, never fresh request fields.
fn intent_matches(
    existing: &AssignmentContinuationProposal,
    intent: &AssignmentContinuationIntent,
    authenticated_issuer: OrchestrationIssuerId,
    actual_backend: ForgeBackendId,
) -> bool {
    existing.transfer_id == intent.transfer_id()
        && existing.cut_id == intent.cut_id()
        && existing.cut_revision == intent.cut_revision()
        && existing.cut_request_digest == intent.cut_request_digest()
        && existing.cut_snapshot_digest == intent.cut_snapshot_digest()
        && existing.source_assignment_id == intent.source_assignment_id()
        && existing.source_revision == intent.source_revision()
        && existing.node_revision == intent.expected_node_revision()
        && existing.recipient == intent.recipient()
        && existing.issuer == authenticated_issuer
        && existing.backend == actual_backend
}

/// Load the intent's current source, cut witness and DAG/node and compose the
/// checked domain plan with worker time. No caller-supplied rows, timestamps or
/// digests are trusted beyond the witness comparison against the stored cut.
fn compose_intent_plan(
    tx: &Connection,
    intent: &AssignmentContinuationIntent,
    now: TimestampMillis,
) -> Result<AgentAssignmentContinuationPlan, WorkCutError> {
    let source = workspace_agent_assignments::get_in_transaction(tx, intent.source_assignment_id())
        .map_err(|error| WorkCutError::Assignment(Box::new(error)))?
        .ok_or(WorkCutError::Conflict("continuation intent source absent"))?;
    let cut = repository::read_record(tx, intent.cut_id())?
        .ok_or(WorkCutError::Conflict("continuation intent cut missing"))?;
    if cut.request().request_digest().as_bytes() != &intent.cut_request_digest()
        || cut.snapshot_digest() != &intent.cut_snapshot_digest()
    {
        return Err(WorkCutError::Conflict("continuation intent cut witness"));
    }
    let captured = cut
        .inventory()
        .nodes()
        .iter()
        .find(|node| {
            node.agent_id() == source.target().agent_id()
                && node.assignment().is_some_and(|captured| {
                    captured.assignment_id() == intent.source_assignment_id()
                })
        })
        .ok_or(WorkCutError::Conflict(
            "continuation intent source absent from cut",
        ))?;
    let assignment = captured.assignment().ok_or(WorkCutError::Conflict(
        "continuation intent captured assignment",
    ))?;
    if assignment.revision() != intent.source_revision() {
        return Err(WorkCutError::Conflict(
            "continuation intent captured assignment",
        ));
    }
    let dag = workspace_dags::get_current_in_transaction(tx, source.goal_id())
        .map_err(|error| WorkCutError::Dag(Box::new(error)))?
        .ok_or(WorkCutError::Conflict("continuation intent DAG missing"))?;
    let node = dag
        .nodes()
        .iter()
        .find(|node| node.id() == source.node_id())
        .ok_or(WorkCutError::Conflict("continuation intent node missing"))?;
    if node.revision() != intent.expected_node_revision() {
        return Err(WorkCutError::Conflict("continuation intent node revision"));
    }
    Ok(AgentAssignmentContinuationPlan::new(
        intent.transfer_id(),
        intent.successor_id(),
        cut.request(),
        *cut.snapshot_digest(),
        &source,
        intent.source_revision(),
        captured.scope(),
        dag.revision(),
        node,
        intent.recipient(),
        now,
    )?)
}

/// Shared plan-based validation/insertion owner. The caller owns the immediate
/// transaction; this function commits it.
fn prepare_in_tx(
    tx: Transaction<'_>,
    plan: &AgentAssignmentContinuationPlan,
    expected_cut_revision: i64,
    authenticated_issuer: OrchestrationIssuerId,
    actual_backend: ForgeBackendId,
    now: TimestampMillis,
) -> Result<AssignmentContinuationPrepareOutcome, WorkCutError> {
    let input_digest = record::plan_digest(plan, expected_cut_revision);
    if let Some(existing) = record::load_proposal(&tx, plan.successor_id())? {
        if existing.request_digest != input_digest
            || existing.issuer != authenticated_issuer
            || existing.backend != actual_backend
        {
            return Err(WorkCutError::Conflict("continuation proposal replay"));
        }
        tx.commit()?;
        return Ok(AssignmentContinuationPrepareOutcome::Existing(existing));
    }
    if workspace_agent_assignments::offer_seal_exists(
        &tx,
        plan.source_assignment().workspace_id(),
        plan.source_assignment().activity_id(),
        plan.successor_id(),
    )
    .map_err(|error| WorkCutError::Assignment(Box::new(error)))?
    {
        return Err(WorkCutError::Conflict(
            "continuation successor admission sealed",
        ));
    }
    if workspace_agent_assignments::get_in_transaction(&tx, plan.successor_id())
        .map_err(|error| WorkCutError::Assignment(Box::new(error)))?
        .is_some()
    {
        return Err(WorkCutError::Conflict(
            "continuation successor identity occupied",
        ));
    }
    let cut = repository::read_record(&tx, plan.cut_id())?
        .ok_or(WorkCutError::Conflict("continuation cut missing"))?;
    if cut.state() != WorkCutState::Held
        || cut.revision() != expected_cut_revision
        || cut.issuer() != authenticated_issuer
        || cut.request().backend_id() != actual_backend
        || cut.request().request_digest() != plan.cut_request_digest()
        || cut.snapshot_digest() != plan.cut_snapshot_digest()
        || plan.observed_at() < cut.prepared_at()
        || now < plan.observed_at()
    {
        return Err(WorkCutError::Conflict(
            "continuation cut authority or clock",
        ));
    }
    let (ordinal, node_state) = validate_live_plan(&tx, &cut, plan, now)?;
    let count: i64 = tx.query_row(
        "SELECT COUNT(*) FROM assignment_continuation_proposals WHERE cut_id=?1",
        params![plan.cut_id().as_bytes()],
        |row| row.get(0),
    )?;
    if count >= MAX_PROPOSALS_PER_CUT {
        return Err(WorkCutError::Bounds);
    }
    record::ensure_batch(&tx, plan.transfer_id(), &cut, now)?;
    let mut proposal = AssignmentContinuationProposal {
        successor_id: plan.successor_id(),
        transfer_id: plan.transfer_id(),
        cut_id: plan.cut_id(),
        cut_revision: expected_cut_revision,
        workspace_id: cut.request().workspace_id(),
        issuer: cut.issuer(),
        backend: cut.request().backend_id(),
        cut_request_digest: *plan.cut_request_digest().as_bytes(),
        cut_snapshot_digest: *plan.cut_snapshot_digest(),
        source_ordinal: ordinal,
        source_scope: plan.source_scope(),
        source_agent_id: plan.source_assignment().target().agent_id(),
        source_assignment_id: plan.source_assignment().id(),
        source_revision: plan.source_assignment().revision(),
        source_digest: record::source_digest(plan.source_assignment()),
        recipient: plan.recipient(),
        node_revision: plan.node_revision(),
        node_state,
        successor_state: plan.successor_state(),
        credit_budget: plan.credit_budget(),
        planned_at: plan.observed_at(),
        recorded_at: now,
        request_digest: input_digest,
        digest: [0; 32],
    };
    proposal.digest = record::proposal_digest(&proposal);
    record::insert_proposal(&tx, &proposal)?;
    let stored = record::load_proposal(&tx, proposal.successor_id)?
        .ok_or(WorkCutError::Corrupt("continuation proposal readback"))?;
    commit(tx, proposal.successor_id, None)?;
    Ok(AssignmentContinuationPrepareOutcome::Prepared(stored))
}

fn validate_live_plan(
    tx: &Connection,
    cut: &WorkCutRecord,
    plan: &AgentAssignmentContinuationPlan,
    now: TimestampMillis,
) -> Result<(i64, DagNodeStatus), WorkCutError> {
    let (ordinal, captured) = cut
        .inventory()
        .nodes()
        .iter()
        .enumerate()
        .find(|(_, node)| {
            node.scope() == plan.source_scope()
                && node.agent_id() == plan.source_assignment().target().agent_id()
        })
        .ok_or(WorkCutError::Conflict(
            "continuation source absent from cut",
        ))?;
    let assignment = captured.assignment().ok_or(WorkCutError::Conflict(
        "continuation source has no assignment",
    ))?;
    if assignment.assignment_id() != plan.source_assignment().id()
        || assignment.revision() != plan.source_assignment().revision()
        || assignment.state() != plan.source_assignment().state()
        || assignment.cancellation_requested()
    {
        return Err(WorkCutError::Conflict("continuation captured assignment"));
    }
    let source = workspace_agent_assignments::get_in_transaction(tx, assignment.assignment_id())
        .map_err(|e| WorkCutError::Assignment(Box::new(e)))?
        .ok_or(WorkCutError::Conflict("continuation source disappeared"))?;
    if &source != plan.source_assignment() {
        return Err(WorkCutError::Conflict("continuation source changed"));
    }
    validate_plan_actors(tx, plan, now)?;
    let goal = workspace_goals::get_goal(tx, source.goal_id())
        .map_err(|e| WorkCutError::Goal(Box::new(e)))?
        .ok_or(WorkCutError::Conflict("continuation Goal missing"))?;
    if goal.workspace_id() != source.workspace_id()
        || goal.activity_id() != source.activity_id()
        || goal.timestamps().created_at() != plan.source_scope().goal_created_at()
        || goal.revision() != captured.goal_revision()
        || !matches!(
            goal.status().kind(),
            forge_domain::GoalStatusKind::Active | forge_domain::GoalStatusKind::Paused
        )
    {
        return Err(WorkCutError::Conflict("continuation Goal changed"));
    }
    let dag = workspace_dags::get_current_in_transaction(tx, source.goal_id())
        .map_err(|e| WorkCutError::Dag(Box::new(e)))?
        .ok_or(WorkCutError::Conflict("continuation DAG missing"))?;
    if dag.revision().number() != source.dag_revision()
        || dag.head().dag_revision() != captured.head_dag_revision()
        || dag.head().revision() != captured.head_revision()
    {
        return Err(WorkCutError::Conflict("continuation current DAG changed"));
    }
    let node = dag
        .nodes()
        .iter()
        .find(|node| node.id() == source.node_id())
        .ok_or(WorkCutError::Conflict("continuation node missing"))?;
    let rebuilt = AgentAssignmentContinuationPlan::new(
        plan.transfer_id(),
        plan.successor_id(),
        cut.request(),
        *cut.snapshot_digest(),
        &source,
        assignment.revision(),
        captured.scope(),
        dag.revision(),
        node,
        plan.recipient(),
        plan.observed_at(),
    )?;
    if &rebuilt != plan {
        return Err(WorkCutError::Conflict("continuation live draft differs"));
    }
    let state = match node.lifecycle() {
        forge_domain::DagNodeLifecycle::Pending => DagNodeStatus::Pending,
        forge_domain::DagNodeLifecycle::Active => DagNodeStatus::Active,
        forge_domain::DagNodeLifecycle::Blocked(_) => DagNodeStatus::Blocked,
        _ => return Err(WorkCutError::Conflict("continuation node settled")),
    };
    Ok((
        i64::try_from(ordinal).map_err(|_| WorkCutError::Bounds)?,
        state,
    ))
}

fn validate_plan_actors(
    tx: &Connection,
    plan: &AgentAssignmentContinuationPlan,
    now: TimestampMillis,
) -> Result<(), WorkCutError> {
    let source = plan.source_assignment();
    let source_actor = validate_actor(
        tx,
        source.workspace_id(),
        source.activity_id(),
        source.target(),
        None,
    )?;
    let recipient = validate_actor(
        tx,
        source.workspace_id(),
        source.activity_id(),
        plan.recipient(),
        Some(plan.recipient().agent_revision()),
    )?;
    if now < source_actor.updated_at() || plan.observed_at() < recipient.updated_at() {
        return Err(WorkCutError::Conflict(
            "continuation actor observation clock",
        ));
    }
    Ok(())
}

fn validate_actor(
    tx: &Connection,
    workspace: WorkspaceId,
    activity: forge_domain::ActivityId,
    target: AgentAssignmentTarget,
    revision: Option<AgentInstanceRevision>,
) -> Result<forge_domain::RegisteredAgentInstance, WorkCutError> {
    workspace_agents::ensure_bound_attached_agent(
        tx,
        workspace,
        activity,
        target.agent_id(),
        target.session_id(),
        target.principal(),
        revision,
    )
    .map_err(|error| WorkCutError::Agent(Box::new(error)))
}

/// Reserve candidate identities against ordinary assignment creation, even if
/// the immutable proposal has not yet been selected for a reciprocal transfer.
pub(crate) fn successor_reserved(
    connection: &Connection,
    id: AgentAssignmentId,
) -> Result<bool, rusqlite::Error> {
    connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM assignment_continuation_proposals WHERE successor_id=?1)",
        params![id.into_uuid().as_bytes()],
        |row| row.get(0),
    )
}

pub(crate) fn get(
    connection: &Connection,
    id: AgentAssignmentId,
) -> Result<Option<AssignmentContinuationProposal>, WorkCutError> {
    let tx = connection.unchecked_transaction()?;
    let record = record::load_proposal(&tx, id)?;
    tx.commit()?;
    Ok(record)
}

pub(crate) fn acknowledge(
    connection: &mut Connection,
    request_id: Uuid,
    successor_id: AgentAssignmentId,
    expected_digest: [u8; 32],
    recipient: AgentAssignmentTarget,
    now: TimestampMillis,
) -> Result<AssignmentContinuationAcknowledgeOutcome, WorkCutError> {
    if request_id.is_nil() {
        return Err(WorkCutError::Conflict(
            "continuation acknowledgment identity",
        ));
    }
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if let Some(existing) = record::load_ack(&tx, request_id)? {
        if existing.successor_id != successor_id
            || existing.proposal_digest != expected_digest
            || existing.recipient != recipient
        {
            return Err(WorkCutError::Conflict("continuation acknowledgment replay"));
        }
        tx.commit()?;
        return Ok(AssignmentContinuationAcknowledgeOutcome::Existing(existing));
    }
    let proposal = record::load_proposal(&tx, successor_id)?
        .ok_or(WorkCutError::Conflict("continuation proposal missing"))?;
    let cut = repository::read_record(&tx, proposal.cut_id)?
        .ok_or(WorkCutError::Corrupt("continuation parent cut missing"))?;
    if cut.state() != WorkCutState::Held
        || cut.revision() != proposal.cut_revision
        || expected_digest != proposal.digest
        || now < proposal.recorded_at
        || recipient.agent_id() != proposal.recipient.agent_id()
        || recipient.session_id() != proposal.recipient.session_id()
        || recipient.principal() != proposal.recipient.principal()
    {
        return Err(WorkCutError::Conflict(
            "continuation acknowledgment context",
        ));
    }
    let agent = validate_actor(
        &tx,
        proposal.workspace_id,
        proposal.source_scope.activity_id(),
        recipient,
        Some(recipient.agent_revision()),
    )?;
    if now < agent.updated_at() {
        return Err(WorkCutError::Conflict("continuation acknowledgment clock"));
    }
    let exists: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM assignment_continuation_acknowledgments WHERE successor_id=?1)",
        params![successor_id.into_uuid().as_bytes()], |row| row.get(0))?;
    if exists {
        return Err(WorkCutError::Conflict(
            "continuation already acknowledged by another request",
        ));
    }
    let mut receipt = AssignmentContinuationAcknowledgment {
        request_id,
        successor_id,
        proposal_digest: expected_digest,
        recipient,
        recorded_at: now,
        digest: [0; 32],
    };
    receipt.digest = record::ack_digest(&receipt);
    record::insert_ack(&tx, &receipt)?;
    let stored = record::load_ack(&tx, request_id)?.ok_or(WorkCutError::Corrupt(
        "continuation acknowledgment readback",
    ))?;
    commit(tx, successor_id, Some(request_id))?;
    Ok(AssignmentContinuationAcknowledgeOutcome::Recorded(stored))
}

pub(crate) fn get_ack(
    connection: &Connection,
    request_id: Uuid,
) -> Result<Option<AssignmentContinuationAcknowledgment>, WorkCutError> {
    let tx = connection.unchecked_transaction()?;
    let receipt = record::load_ack(&tx, request_id)?;
    tx.commit()?;
    Ok(receipt)
}

fn commit(
    tx: rusqlite::Transaction<'_>,
    successor_id: AgentAssignmentId,
    request_id: Option<Uuid>,
) -> Result<(), WorkCutError> {
    tx.commit()
        .map_err(|source| WorkCutError::ContinuationCommitUnconfirmed {
            successor_id,
            request_id,
            source: Box::new(source),
        })
}
