//! Canonical hashes and bounded row codecs for the continuation journal.

use forge_domain::{
    AgentAssignmentCoordinator, AgentSessionId, AuthenticatedPrincipal, DirectTokenId,
    OAuthGrantId, RegisteredAgentAssignment,
};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};

use super::super::decode_id;
use super::{
    AgentAssignmentContinuationPlan, AgentAssignmentId, AgentAssignmentRevision,
    AgentAssignmentState, AgentAssignmentTarget, AgentInstanceId, AgentInstanceRevision,
    AssignmentContinuationAcknowledgment, AssignmentContinuationProposal, DagNodeRevision,
    DagNodeStatus, TimestampMillis, Uuid, WorkCreditBudget, WorkCutError, WorkCutNodeScope,
    WorkCutRecord, repository,
};

struct ProposalInput {
    transfer: Uuid,
    successor: AgentAssignmentId,
    cut: Uuid,
    cut_revision: i64,
    request: [u8; 32],
    snapshot: [u8; 32],
    scope: WorkCutNodeScope,
    source: [u8; 32],
    recipient: AgentAssignmentTarget,
    node_revision: DagNodeRevision,
    planned_at: TimestampMillis,
}
impl ProposalInput {
    fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"forge-continuation-proposal-input-v1\0");
        for id in [self.transfer, self.successor.into_uuid(), self.cut] {
            h.update(id.as_bytes());
        }
        number(&mut h, self.cut_revision);
        h.update(self.request);
        h.update(self.snapshot);
        scope(&mut h, self.scope);
        h.update(self.source);
        target(&mut h, self.recipient);
        number(&mut h, self.node_revision.get());
        number(&mut h, self.planned_at.get());
        h.finalize().into()
    }
}

pub(super) fn plan_digest(plan: &AgentAssignmentContinuationPlan, cut_revision: i64) -> [u8; 32] {
    ProposalInput {
        transfer: plan.transfer_id(),
        successor: plan.successor_id(),
        cut: plan.cut_id(),
        cut_revision,
        request: *plan.cut_request_digest().as_bytes(),
        snapshot: *plan.cut_snapshot_digest(),
        scope: plan.source_scope(),
        source: source_digest(plan.source_assignment()),
        recipient: plan.recipient(),
        node_revision: plan.node_revision(),
        planned_at: plan.observed_at(),
    }
    .digest()
}

fn stored_input_digest(p: &AssignmentContinuationProposal) -> [u8; 32] {
    ProposalInput {
        transfer: p.transfer_id,
        successor: p.successor_id,
        cut: p.cut_id,
        cut_revision: p.cut_revision,
        request: p.cut_request_digest,
        snapshot: p.cut_snapshot_digest,
        scope: p.source_scope,
        source: p.source_digest,
        recipient: p.recipient,
        node_revision: p.node_revision,
        planned_at: p.planned_at,
    }
    .digest()
}

pub(super) fn source_digest(source: &RegisteredAgentAssignment) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"forge-continuation-source-assignment-v1\0");
    for id in [
        source.id().into_uuid(),
        source.workspace_id().into_uuid(),
        source.activity_id().into_uuid(),
        source.goal_id().into_uuid(),
        source.node_id().into_uuid(),
    ] {
        h.update(id.as_bytes());
    }
    for value in [
        source.goal_created_at().get(),
        source.goal_revision().get(),
        source.dag_revision().get(),
        source.dag_head_revision().get(),
        source.node_revision().get(),
        source.created_at().get(),
        source.updated_at().get(),
        source.revision().get(),
        assignment_state(source.state()),
        i64::from(source.cancellation_requested()),
        budget(source.credit_budget()),
    ] {
        number(&mut h, value);
    }
    coordinator(&mut h, source.coordinator());
    target(&mut h, source.target());
    // Preserve the schema55 encoding of ordinary offers byte-for-byte. A
    // continued source extends that fixed record with its explicit lineage.
    if let forge_domain::AgentAssignmentOrigin::CutContinuation(origin) = source.origin() {
        h.update(b"cut-continuation-origin-v1\0");
        h.update(origin.cut_id().as_bytes());
        h.update(origin.transfer_id().as_bytes());
        h.update(origin.predecessor_id().into_uuid().as_bytes());
    }
    // Domain continuation planning admits only Offered/Running, whose checked
    // representation has no result, worktree receipt or review to hash or move.
    h.finalize().into()
}

pub(super) fn proposal_digest(p: &AssignmentContinuationProposal) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"forge-continuation-proposal-record-v1\0");
    h.update(stored_input_digest(p));
    for id in [
        p.workspace_id.into_uuid(),
        p.issuer.into_uuid(),
        p.backend.into_uuid(),
        p.source_agent_id.into_uuid(),
        p.source_assignment_id.into_uuid(),
    ] {
        h.update(id.as_bytes());
    }
    for value in [
        p.source_ordinal,
        p.source_revision.get(),
        node_state(p.node_state),
        assignment_state(p.successor_state),
        budget(p.credit_budget),
        p.recorded_at.get(),
    ] {
        number(&mut h, value);
    }
    h.finalize().into()
}

pub(super) fn ack_digest(a: &AssignmentContinuationAcknowledgment) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"forge-continuation-acknowledgment-v1\0");
    h.update(a.request_id.as_bytes());
    h.update(a.successor_id.into_uuid().as_bytes());
    h.update(a.proposal_digest);
    target(&mut h, a.recipient);
    number(&mut h, a.recorded_at.get());
    h.finalize().into()
}

fn number(h: &mut Sha256, value: i64) {
    h.update(value.to_be_bytes());
}
fn target(h: &mut Sha256, value: AgentAssignmentTarget) {
    h.update(value.agent_id().into_uuid().as_bytes());
    h.update(value.session_id().into_uuid().as_bytes());
    principal(h, value.principal());
    number(h, value.agent_revision().get());
}
fn coordinator(h: &mut Sha256, value: AgentAssignmentCoordinator) {
    h.update(value.agent_id().into_uuid().as_bytes());
    h.update(value.session_id().into_uuid().as_bytes());
    principal(h, value.principal());
    number(h, value.revision().get());
}
fn principal(h: &mut Sha256, value: AuthenticatedPrincipal) {
    let (kind, id) = principal_parts(value);
    number(h, kind);
    if let Some(id) = id {
        h.update(id.as_bytes());
    }
}
fn scope(h: &mut Sha256, s: WorkCutNodeScope) {
    for id in [
        s.activity_id().into_uuid(),
        s.goal_id().into_uuid(),
        s.node_id().into_uuid(),
    ] {
        h.update(id.as_bytes());
    }
    for n in [
        s.goal_created_at().get(),
        s.dag_base_goal_revision().get(),
        s.dag_revision().get(),
    ] {
        number(h, n);
    }
}
fn budget(v: Option<WorkCreditBudget>) -> i64 {
    v.map_or(0, WorkCreditBudget::value)
}
fn assignment_state(v: AgentAssignmentState) -> i64 {
    match v {
        AgentAssignmentState::Offered => 0,
        AgentAssignmentState::Running => 1,
        AgentAssignmentState::Submitted => 2,
        AgentAssignmentState::Accepted => 3,
        AgentAssignmentState::Rejected => 4,
        AgentAssignmentState::Cancelled => 5,
        AgentAssignmentState::Interrupted => 6,
    }
}
fn node_state(v: DagNodeStatus) -> i64 {
    match v {
        DagNodeStatus::Pending => 0,
        DagNodeStatus::Active => 1,
        DagNodeStatus::Blocked => 2,
        _ => -1,
    }
}
fn principal_parts(v: AuthenticatedPrincipal) -> (i64, Option<Uuid>) {
    match v {
        AuthenticatedPrincipal::TrustedStdio => (0, None),
        AuthenticatedPrincipal::DirectToken(id) => (1, Some(id.into_uuid())),
        AuthenticatedPrincipal::OAuthGrant(id) => (2, Some(id.into_uuid())),
    }
}

struct RawBatch {
    transfer: Vec<u8>,
    cut: Vec<u8>,
    revision: i64,
    request_digest: Vec<u8>,
    snapshot_digest: Vec<u8>,
}

pub(super) fn ensure_batch(
    tx: &Connection,
    transfer: Uuid,
    cut: &WorkCutRecord,
    now: TimestampMillis,
) -> Result<(), WorkCutError> {
    let existing=tx.query_row(
        "SELECT substr(transfer_id,1,17),substr(cut_id,1,17),cut_revision,substr(cut_request_digest,1,33),substr(cut_snapshot_digest,1,33) FROM assignment_continuation_batches WHERE transfer_id=?1 OR cut_id=?2",
        params![transfer.as_bytes(),cut.request().cut_id().as_bytes()],
        |r|Ok(RawBatch { transfer: r.get(0)?, cut: r.get(1)?, revision: r.get(2)?, request_digest: r.get(3)?, snapshot_digest: r.get(4)? }),
    ).optional()?;
    if let Some(existing) = existing {
        if decode_id(&existing.transfer)? != transfer
            || decode_id(&existing.cut)? != cut.request().cut_id()
            || existing.revision != cut.revision()
            || digest(&existing.request_digest)? != *cut.request().request_digest().as_bytes()
            || digest(&existing.snapshot_digest)? != *cut.snapshot_digest()
        {
            return Err(WorkCutError::Conflict("continuation batch identity"));
        }
        return Ok(());
    }
    tx.execute("INSERT INTO assignment_continuation_batches(transfer_id,cut_id,cut_revision,cut_request_digest,cut_snapshot_digest,recorded_at_ms) VALUES(?1,?2,?3,?4,?5,?6)",
        params![transfer.as_bytes(),cut.request().cut_id().as_bytes(),cut.revision(),cut.request().request_digest().as_bytes().as_slice(),cut.snapshot_digest().as_slice(),now.get()])?;
    Ok(())
}

pub(super) fn insert_proposal(
    tx: &Connection,
    p: &AssignmentContinuationProposal,
) -> Result<(), WorkCutError> {
    let (kind, id) = principal_parts(p.recipient.principal());
    tx.execute("INSERT INTO assignment_continuation_proposals(successor_id,transfer_id,cut_id,source_ordinal,source_assignment_id,source_revision,source_digest,recipient_agent_id,recipient_session_id,recipient_principal_kind,recipient_principal_id,recipient_revision,node_revision,node_state,successor_state,credit_budget,planned_at_ms,recorded_at_ms,request_digest,record_digest) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20)",
        params![p.successor_id.into_uuid().as_bytes(),p.transfer_id.as_bytes(),p.cut_id.as_bytes(),p.source_ordinal,p.source_assignment_id.into_uuid().as_bytes(),p.source_revision.get(),p.source_digest.as_slice(),p.recipient.agent_id().into_uuid().as_bytes(),p.recipient.session_id().into_uuid().as_bytes(),kind,id.as_ref().map(|v|v.as_bytes().as_slice()),p.recipient.agent_revision().get(),p.node_revision.get(),node_state(p.node_state),assignment_state(p.successor_state),p.credit_budget.map(WorkCreditBudget::value),p.planned_at.get(),p.recorded_at.get(),p.request_digest.as_slice(),p.digest.as_slice()])?;
    Ok(())
}

struct RawProposal {
    transfer: Vec<u8>,
    cut: Vec<u8>,
    ordinal: i64,
    source: Vec<u8>,
    source_revision: i64,
    source_digest: Vec<u8>,
    recipient: Vec<u8>,
    session: Vec<u8>,
    principal_kind: i64,
    principal: Option<Vec<u8>>,
    recipient_revision: i64,
    node_revision: i64,
    node_state: i64,
    successor_state: i64,
    budget: Option<i64>,
    planned: i64,
    recorded: i64,
    request_digest: Vec<u8>,
    record_digest: Vec<u8>,
    cut_revision: i64,
    cut_request: Vec<u8>,
    cut_snapshot: Vec<u8>,
    batch_recorded: i64,
}

pub(super) fn load_proposal(
    tx: &Connection,
    id: AgentAssignmentId,
) -> Result<Option<AssignmentContinuationProposal>, WorkCutError> {
    let raw=tx.query_row(
        "SELECT substr(p.transfer_id,1,17),substr(p.cut_id,1,17),p.source_ordinal,substr(p.source_assignment_id,1,17),p.source_revision,substr(p.source_digest,1,33),substr(p.recipient_agent_id,1,17),substr(p.recipient_session_id,1,17),p.recipient_principal_kind,substr(p.recipient_principal_id,1,17),p.recipient_revision,p.node_revision,p.node_state,p.successor_state,p.credit_budget,p.planned_at_ms,p.recorded_at_ms,substr(p.request_digest,1,33),substr(p.record_digest,1,33),b.cut_revision,substr(b.cut_request_digest,1,33),substr(b.cut_snapshot_digest,1,33),b.recorded_at_ms FROM assignment_continuation_proposals p JOIN assignment_continuation_batches b ON b.transfer_id=p.transfer_id AND b.cut_id=p.cut_id WHERE p.successor_id=?1",
        params![id.into_uuid().as_bytes()],|r|Ok(RawProposal{
            transfer:r.get(0)?,cut:r.get(1)?,ordinal:r.get(2)?,source:r.get(3)?,source_revision:r.get(4)?,source_digest:r.get(5)?,
            recipient:r.get(6)?,session:r.get(7)?,principal_kind:r.get(8)?,principal:r.get(9)?,recipient_revision:r.get(10)?,
            node_revision:r.get(11)?,node_state:r.get(12)?,successor_state:r.get(13)?,budget:r.get(14)?,planned:r.get(15)?,recorded:r.get(16)?,
            request_digest:r.get(17)?,record_digest:r.get(18)?,cut_revision:r.get(19)?,cut_request:r.get(20)?,cut_snapshot:r.get(21)?,batch_recorded:r.get(22)?,
        }),
    ).optional()?;
    if let Some(raw) = raw {
        return decode_proposal(tx, id, &raw).map(Some);
    }
    let orphan: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM assignment_continuation_proposals WHERE successor_id=?1)",
        params![id.into_uuid().as_bytes()],
        |row| row.get(0),
    )?;
    if orphan {
        return Err(WorkCutError::Corrupt("continuation batch missing"));
    }
    Ok(None)
}

fn decode_proposal(
    tx: &Connection,
    id: AgentAssignmentId,
    raw: &RawProposal,
) -> Result<AssignmentContinuationProposal, WorkCutError> {
    let cut_id = decode_id(&raw.cut)?;
    let cut = repository::read_record(tx, cut_id)?
        .ok_or(WorkCutError::Corrupt("continuation parent cut"))?;
    let ordinal =
        usize::try_from(raw.ordinal).map_err(|_| WorkCutError::Corrupt("continuation ordinal"))?;
    let node = cut
        .inventory()
        .nodes()
        .get(ordinal)
        .ok_or(WorkCutError::Corrupt("continuation ordinal"))?;
    let assignment = node
        .assignment()
        .ok_or(WorkCutError::Corrupt("continuation captured assignment"))?;
    let source = AgentAssignmentId::from_uuid(decode_id(&raw.source)?);
    let source_revision = AgentAssignmentRevision::new(raw.source_revision)
        .map_err(|_| WorkCutError::Corrupt("continuation source revision"))?;
    let successor_state = match raw.successor_state {
        0 => AgentAssignmentState::Offered,
        1 => AgentAssignmentState::Running,
        _ => return Err(WorkCutError::Corrupt("continuation successor state")),
    };
    let node_state = match raw.node_state {
        0 => DagNodeStatus::Pending,
        1 => DagNodeStatus::Active,
        2 => DagNodeStatus::Blocked,
        _ => return Err(WorkCutError::Corrupt("continuation node state")),
    };
    let recipient = AgentAssignmentTarget::new(
        AgentInstanceId::from_uuid(decode_id(&raw.recipient)?),
        AgentSessionId::from_uuid(decode_id(&raw.session)?),
        decode_principal(raw.principal_kind, raw.principal.as_deref())?,
        AgentInstanceRevision::new(raw.recipient_revision)
            .map_err(|_| WorkCutError::Corrupt("continuation recipient revision"))?,
    );
    let p = AssignmentContinuationProposal {
        successor_id: id,
        transfer_id: decode_id(&raw.transfer)?,
        cut_id,
        cut_revision: raw.cut_revision,
        workspace_id: cut.request().workspace_id(),
        issuer: cut.issuer(),
        backend: cut.request().backend_id(),
        cut_request_digest: digest(&raw.cut_request)?,
        cut_snapshot_digest: digest(&raw.cut_snapshot)?,
        source_ordinal: raw.ordinal,
        source_scope: node.scope(),
        source_agent_id: node.agent_id(),
        source_assignment_id: source,
        source_revision,
        source_digest: digest(&raw.source_digest)?,
        recipient,
        node_revision: DagNodeRevision::new(raw.node_revision)
            .map_err(|_| WorkCutError::Corrupt("continuation node revision"))?,
        node_state,
        successor_state,
        credit_budget: raw
            .budget
            .map(WorkCreditBudget::try_from_i64)
            .transpose()
            .map_err(|_| WorkCutError::Corrupt("continuation budget"))?,
        planned_at: timestamp(raw.planned)?,
        recorded_at: timestamp(raw.recorded)?,
        request_digest: digest(&raw.request_digest)?,
        digest: digest(&raw.record_digest)?,
    };
    if id.into_uuid().is_nil()
        || id == source
        || p.cut_revision < 1
        || p.cut_request_digest != *cut.request().request_digest().as_bytes()
        || p.cut_snapshot_digest != *cut.snapshot_digest()
        || p.planned_at < cut.prepared_at()
        || p.recorded_at < p.planned_at
        || raw.batch_recorded < cut.prepared_at().get()
        || raw.batch_recorded > p.recorded_at.get()
        || assignment.assignment_id() != source
        || assignment.revision() != source_revision
        || assignment.state() != successor_state
        || assignment.cancellation_requested()
        || p.request_digest != stored_input_digest(&p)
        || p.digest != proposal_digest(&p)
        || !matches!(
            (successor_state, node_state),
            (
                AgentAssignmentState::Offered,
                DagNodeStatus::Pending | DagNodeStatus::Blocked
            ) | (
                AgentAssignmentState::Running,
                DagNodeStatus::Active | DagNodeStatus::Blocked
            )
        )
    {
        return Err(WorkCutError::Corrupt(
            "continuation proposal attribution or digest",
        ));
    }
    Ok(p)
}

pub(super) fn insert_ack(
    tx: &Connection,
    a: &AssignmentContinuationAcknowledgment,
) -> Result<(), WorkCutError> {
    tx.execute("INSERT INTO assignment_continuation_acknowledgments(request_id,successor_id,proposal_digest,recipient_revision,recorded_at_ms,record_digest) VALUES(?1,?2,?3,?4,?5,?6)",params![a.request_id.as_bytes(),a.successor_id.into_uuid().as_bytes(),a.proposal_digest.as_slice(),a.recipient.agent_revision().get(),a.recorded_at.get(),a.digest.as_slice()])?;
    Ok(())
}

struct RawAcknowledgment {
    successor: Vec<u8>,
    proposal_digest: Vec<u8>,
    recipient_revision: i64,
    recorded_at: i64,
    record_digest: Vec<u8>,
}

pub(super) fn load_ack(
    tx: &Connection,
    request: Uuid,
) -> Result<Option<AssignmentContinuationAcknowledgment>, WorkCutError> {
    let raw=tx.query_row("SELECT substr(successor_id,1,17),substr(proposal_digest,1,33),recipient_revision,recorded_at_ms,substr(record_digest,1,33) FROM assignment_continuation_acknowledgments WHERE request_id=?1",params![request.as_bytes()],|r|Ok(RawAcknowledgment { successor: r.get(0)?, proposal_digest: r.get(1)?, recipient_revision: r.get(2)?, recorded_at: r.get(3)?, record_digest: r.get(4)? })).optional()?;
    let Some(raw) = raw else { return Ok(None) };
    let successor = AgentAssignmentId::from_uuid(decode_id(&raw.successor)?);
    let proposal = load_proposal(tx, successor)?.ok_or(WorkCutError::Corrupt(
        "continuation acknowledged proposal missing",
    ))?;
    let recipient = AgentAssignmentTarget::new(
        proposal.recipient.agent_id(),
        proposal.recipient.session_id(),
        proposal.recipient.principal(),
        AgentInstanceRevision::new(raw.recipient_revision)
            .map_err(|_| WorkCutError::Corrupt("continuation acknowledgment revision"))?,
    );
    let receipt = AssignmentContinuationAcknowledgment {
        request_id: request,
        successor_id: successor,
        proposal_digest: digest(&raw.proposal_digest)?,
        recipient,
        recorded_at: timestamp(raw.recorded_at)?,
        digest: digest(&raw.record_digest)?,
    };
    if request.is_nil()
        || receipt.proposal_digest != proposal.digest
        || receipt.recorded_at < proposal.recorded_at
        || receipt.digest != ack_digest(&receipt)
    {
        return Err(WorkCutError::Corrupt("continuation acknowledgment digest"));
    }
    Ok(Some(receipt))
}

fn digest(bytes: &[u8]) -> Result<[u8; 32], WorkCutError> {
    bytes
        .try_into()
        .map_err(|_| WorkCutError::Corrupt("continuation digest width"))
}
fn timestamp(value: i64) -> Result<TimestampMillis, WorkCutError> {
    TimestampMillis::new(value).map_err(|_| WorkCutError::Corrupt("continuation timestamp"))
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
        _ => Err(WorkCutError::Corrupt("continuation principal")),
    }
}
