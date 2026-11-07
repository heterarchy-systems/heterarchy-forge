//! Checked terminal Home-handoff outcomes and their immutable assignment pins.

use forge_domain::{
    AgentAssignmentCoordinator, AgentAssignmentHomeHandoffOrigin, AgentAssignmentId,
    AgentAssignmentOrigin, AgentAssignmentRevision, AgentAssignmentState, AgentAssignmentTarget,
    HomeHandoffAcceptanceGrant, HomeHandoffTakeRequest, OrchestrationIssuerId, TimestampMillis,
    WorkCreditBudget, WorkspaceId,
};
use uuid::Uuid;

use crate::workspace_home_transfers::{HomeTransferSourceRecord, HomeTransferSourceState};

use super::super::proposal_model::{
    HomeHandoffAssignmentLineage, HomeHandoffProposalRecord, HomeHandoffSourceAssignmentPin,
};
use super::HomeHandoffApplicationStoreError as Error;

const DIGEST_BYTES: usize = 32;

/// Terminal state stored in the immutable Source acceptance ledger.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HomeHandoffAcceptanceOutcomeKind {
    Applied,
    Aborted,
}

impl HomeHandoffAcceptanceOutcomeKind {
    pub(crate) const fn encode(self) -> i64 {
        match self {
            Self::Applied => 1,
            Self::Aborted => 2,
        }
    }

    pub(super) const fn encode_tag(self) -> u8 {
        match self {
            Self::Applied => 1,
            Self::Aborted => 2,
        }
    }
}

/// Checked parts supplied by the Source take/abort owner inside its write
/// transaction. These values do not authenticate the issuer or prove current
/// authority; those checks stay with that owner.
#[must_use]
#[derive(Debug)]
pub(crate) struct HomeHandoffAcceptanceOutcomeRecordParts {
    pub(crate) request: HomeHandoffTakeRequest,
    pub(crate) authenticated_issuer: OrchestrationIssuerId,
    pub(crate) proposal: HomeHandoffProposalRecord,
    pub(crate) preparation: HomeTransferSourceRecord,
    pub(crate) source_at: TimestampMillis,
    pub(crate) terminal: HomeHandoffAcceptanceTerminal,
}

#[must_use]
#[derive(Debug)]
#[allow(
    dead_code,
    clippy::large_enum_variant,
    reason = "Applied variant is constructed by the take slice"
)]
pub(crate) enum HomeHandoffAcceptanceTerminal {
    Applied {
        predecessor_before: forge_domain::RegisteredAgentAssignment,
        transition: forge_domain::AgentAssignmentHomeHandoffTransition,
        grant: HomeHandoffAcceptanceGrant,
    },
    Aborted,
}

/// Immutable, fully typed row representation for one acceptance id.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HomeHandoffAcceptanceOutcomeRecord {
    request: HomeHandoffTakeRequest,
    issuer: OrchestrationIssuerId,
    preparation_id: Uuid,
    workspace_id: WorkspaceId,
    predecessor_id: AgentAssignmentId,
    root_assignment_id: AgentAssignmentId,
    source_at: TimestampMillis,
    outcome: HomeHandoffAcceptanceOutcome,
    payload_digest: [u8; DIGEST_BYTES],
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(
    clippy::large_enum_variant,
    reason = "Applied outcome carries fixed-size initial successor and grant snapshots"
)]
pub enum HomeHandoffAcceptanceOutcome {
    Applied(HomeHandoffAppliedAcceptance),
    Aborted,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HomeHandoffAppliedAcceptance {
    pub(super) predecessor_revision_before: AgentAssignmentRevision,
    pub(super) predecessor_revision_after: AgentAssignmentRevision,
    pub(super) predecessor_terminal_disposition: AgentAssignmentState,
    pub(super) successor: HomeHandoffInitialSuccessorSnapshot,
    pub(super) grant: HomeHandoffAcceptanceGrant,
}

/// Exact immutable identity and admission pins for the new revision-1
/// successor. Lifecycle state, result, review and current revision are not
/// required to remain at these initial values on later reads.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HomeHandoffInitialSuccessorSnapshot {
    assignment_id: AgentAssignmentId,
    origin: AgentAssignmentHomeHandoffOrigin,
    workspace_id: WorkspaceId,
    activity_id: forge_domain::ActivityId,
    goal_id: forge_domain::GoalId,
    goal_created_at: TimestampMillis,
    goal_revision: forge_domain::GoalRevision,
    dag_revision: forge_domain::DagRevisionNumber,
    dag_head_revision: forge_domain::DagHeadRevision,
    node_id: forge_domain::DagNodeId,
    node_revision: forge_domain::DagNodeRevision,
    coordinator: AgentAssignmentCoordinator,
    target: AgentAssignmentTarget,
    credit_budget: Option<WorkCreditBudget>,
    created_at: TimestampMillis,
}

impl HomeHandoffInitialSuccessorSnapshot {
    pub(super) fn from_assignment(
        assignment: &forge_domain::RegisteredAgentAssignment,
        source_at: TimestampMillis,
    ) -> Result<Self, Error> {
        let origin = match assignment.origin() {
            AgentAssignmentOrigin::HomeHandoff(origin) => origin,
            AgentAssignmentOrigin::CoordinatorOffer | AgentAssignmentOrigin::CutContinuation(_) => {
                return Err(Error::Conflict("Home successor origin"));
            }
        };
        if assignment.state() != AgentAssignmentState::Running
            || assignment.cancellation_requested()
            || assignment.result().is_some()
            || assignment.reviewed_by().is_some()
            || assignment.revision() != AgentAssignmentRevision::INITIAL
            || assignment.created_at() != source_at
            || assignment.updated_at() != source_at
        {
            return Err(Error::Conflict("Home successor initial state"));
        }
        Ok(Self {
            assignment_id: assignment.id(),
            origin,
            workspace_id: assignment.workspace_id(),
            activity_id: assignment.activity_id(),
            goal_id: assignment.goal_id(),
            goal_created_at: assignment.goal_created_at(),
            goal_revision: assignment.goal_revision(),
            dag_revision: assignment.dag_revision(),
            dag_head_revision: assignment.dag_head_revision(),
            node_id: assignment.node_id(),
            node_revision: assignment.node_revision(),
            coordinator: assignment.coordinator(),
            target: assignment.target(),
            credit_budget: assignment.credit_budget(),
            created_at: assignment.created_at(),
        })
    }

    pub const fn assignment_id(self) -> AgentAssignmentId {
        self.assignment_id
    }

    pub const fn origin(self) -> AgentAssignmentHomeHandoffOrigin {
        self.origin
    }

    pub const fn workspace_id(self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn activity_id(self) -> forge_domain::ActivityId {
        self.activity_id
    }

    pub const fn goal_id(self) -> forge_domain::GoalId {
        self.goal_id
    }

    pub const fn goal_created_at(self) -> TimestampMillis {
        self.goal_created_at
    }

    pub const fn goal_revision(self) -> forge_domain::GoalRevision {
        self.goal_revision
    }

    pub const fn dag_revision(self) -> forge_domain::DagRevisionNumber {
        self.dag_revision
    }

    pub const fn dag_head_revision(self) -> forge_domain::DagHeadRevision {
        self.dag_head_revision
    }

    pub const fn node_id(self) -> forge_domain::DagNodeId {
        self.node_id
    }

    pub const fn node_revision(self) -> forge_domain::DagNodeRevision {
        self.node_revision
    }

    pub const fn coordinator(self) -> AgentAssignmentCoordinator {
        self.coordinator
    }

    pub const fn target(self) -> AgentAssignmentTarget {
        self.target
    }

    pub const fn credit_budget(self) -> Option<WorkCreditBudget> {
        self.credit_budget
    }

    pub const fn created_at(self) -> TimestampMillis {
        self.created_at
    }

    pub(crate) fn matches_current_assignment(
        self,
        pins: &crate::workspace_agent_assignments::home_origin::HomeOriginAssignmentPins,
        acceptance_id: Uuid,
    ) -> bool {
        let lifecycle_reachable = matches!(
            (pins.state, pins.cancellation_requested),
            (AgentAssignmentState::Running, _)
                | (
                    AgentAssignmentState::Submitted
                        | AgentAssignmentState::Accepted
                        | AgentAssignmentState::Rejected,
                    false,
                )
                | (
                    AgentAssignmentState::Cancelled | AgentAssignmentState::Interrupted,
                    true,
                )
        );
        pins.origin_kind == 1
            && pins.home_receipt_id == Some(acceptance_id)
            && pins.assignment_id == self.assignment_id
            && pins.workspace_id == self.workspace_id
            && pins.activity_id == self.activity_id
            && pins.goal_id == self.goal_id
            && pins.goal_created_at == self.goal_created_at
            && pins.goal_revision == self.goal_revision
            && pins.dag_revision == self.dag_revision
            && pins.dag_head_revision == self.dag_head_revision
            && pins.node_id == self.node_id
            && pins.coordinator == self.coordinator
            && pins.target == self.target
            && pins.credit_budget == self.credit_budget
            && pins.created_at == self.created_at
            && pins.revision.get() >= AgentAssignmentRevision::INITIAL.get()
            && pins.node_revision == self.node_revision
            && pins.updated_at >= self.created_at
            && lifecycle_reachable
    }
}

impl HomeHandoffAcceptanceOutcomeRecord {
    pub(crate) fn from_parts(
        parts: HomeHandoffAcceptanceOutcomeRecordParts,
    ) -> Result<Self, Error> {
        let request = parts.request;
        let proposal = parts.proposal;
        let preparation = parts.preparation;
        let source_pin = proposal.source();
        let preparation_id = proposal.request().preparation_id();
        let workspace_id = source_pin.workspace_id();
        let predecessor_id = source_pin.assignment_id();
        let root_assignment_id = source_pin.root_assignment_id();

        if parts.authenticated_issuer.into_uuid().is_nil()
            || preparation.state() != HomeTransferSourceState::Prepared
            || preparation.issuer() != parts.authenticated_issuer
            || preparation.request().scope() != request.scope()
            || preparation.request().witness().preparation_id() != preparation_id
            || proposal.prepared_outcome_digest() != preparation.outcome_digest()
            || preparation_id.is_nil()
            || request.handoff_id() != proposal.request().handoff_id()
            || request.proposal_id() != proposal.request().proposal_id()
            || request.expected_case_revision() != proposal.case_revision()
            || request.proposal_digest() != proposal.request().request_digest()
            || request.scope().workspace_id() != workspace_id
            || !request
                .recipient()
                .has_same_identity(proposal.request().recipient())
            || parts.source_at < preparation.observed_at()
            || parts.source_at < proposal.created_at()
        {
            return Err(Error::Conflict("acceptance request and proposal pins"));
        }

        let outcome = match parts.terminal {
            HomeHandoffAcceptanceTerminal::Aborted => HomeHandoffAcceptanceOutcome::Aborted,
            HomeHandoffAcceptanceTerminal::Applied {
                predecessor_before,
                transition,
                grant,
            } => {
                grant.validate_for(parts.authenticated_issuer, &request, parts.source_at)?;
                validate_source_pin(source_pin, &predecessor_before)?;
                validate_transition(
                    &request,
                    parts.source_at,
                    preparation_id,
                    root_assignment_id,
                    proposal.request().successor_id(),
                    proposal.request().coordinator(),
                    &predecessor_before,
                    &transition,
                )?;
                if grant.issuer() != parts.authenticated_issuer
                    || grant.take_request_digest() != request.request_digest()
                {
                    return Err(Error::Conflict("acceptance grant identity"));
                }
                let successor = HomeHandoffInitialSuccessorSnapshot::from_assignment(
                    transition.successor(),
                    parts.source_at,
                )?;
                HomeHandoffAcceptanceOutcome::Applied(HomeHandoffAppliedAcceptance {
                    predecessor_revision_before: predecessor_before.revision(),
                    predecessor_revision_after: transition.predecessor().revision(),
                    predecessor_terminal_disposition: transition.predecessor().state(),
                    successor,
                    grant,
                })
            }
        };

        let mut record = Self {
            request,
            issuer: parts.authenticated_issuer,
            preparation_id,
            workspace_id,
            predecessor_id,
            root_assignment_id,
            source_at: parts.source_at,
            outcome,
            payload_digest: [0; DIGEST_BYTES],
        };
        record.payload_digest = super::codec::payload_digest(&record)?;
        Ok(record)
    }

    pub(super) fn from_stored_parts(
        parts: HomeHandoffAcceptanceOutcomeRecordStoredParts,
    ) -> Result<Self, Error> {
        if parts.issuer.into_uuid().is_nil()
            || parts.preparation_id.is_nil()
            || parts.workspace_id.into_uuid().is_nil()
            || parts.predecessor_id.into_uuid().is_nil()
            || parts.root_assignment_id.into_uuid().is_nil()
        {
            return Err(Error::Corrupt("acceptance identity"));
        }
        let mut record = Self {
            request: parts.request,
            issuer: parts.issuer,
            preparation_id: parts.preparation_id,
            workspace_id: parts.workspace_id,
            predecessor_id: parts.predecessor_id,
            root_assignment_id: parts.root_assignment_id,
            source_at: parts.source_at,
            outcome: parts.outcome,
            payload_digest: [0; DIGEST_BYTES],
        };
        validate_common_record(&record).map_err(|_| Error::Corrupt("acceptance identity pins"))?;
        if let HomeHandoffAcceptanceOutcome::Applied(applied) = &record.outcome {
            validate_applied_record(&record, applied)
                .map_err(|_| Error::Corrupt("applied acceptance pins"))?;
        }
        record.payload_digest = super::codec::payload_digest(&record)?;
        Ok(record)
    }

    pub const fn request(&self) -> HomeHandoffTakeRequest {
        self.request
    }

    pub const fn acceptance_id(&self) -> Uuid {
        self.request.acceptance_id()
    }

    pub const fn issuer(&self) -> OrchestrationIssuerId {
        self.issuer
    }

    pub const fn handoff_id(&self) -> Uuid {
        self.request.handoff_id()
    }

    pub const fn proposal_id(&self) -> Uuid {
        self.request.proposal_id()
    }

    pub const fn case_revision(&self) -> i64 {
        self.request.expected_case_revision()
    }

    pub const fn preparation_id(&self) -> Uuid {
        self.preparation_id
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn predecessor_id(&self) -> AgentAssignmentId {
        self.predecessor_id
    }

    pub const fn root_assignment_id(&self) -> AgentAssignmentId {
        self.root_assignment_id
    }

    pub const fn source_at(&self) -> TimestampMillis {
        self.source_at
    }

    pub const fn outcome_kind(&self) -> HomeHandoffAcceptanceOutcomeKind {
        match &self.outcome {
            HomeHandoffAcceptanceOutcome::Applied(_) => HomeHandoffAcceptanceOutcomeKind::Applied,
            HomeHandoffAcceptanceOutcome::Aborted => HomeHandoffAcceptanceOutcomeKind::Aborted,
        }
    }

    pub fn applied(&self) -> Option<&HomeHandoffAppliedAcceptance> {
        match &self.outcome {
            HomeHandoffAcceptanceOutcome::Applied(applied) => Some(applied),
            HomeHandoffAcceptanceOutcome::Aborted => None,
        }
    }

    pub const fn payload_digest(&self) -> &[u8; DIGEST_BYTES] {
        &self.payload_digest
    }

    pub const fn outcome(&self) -> &HomeHandoffAcceptanceOutcome {
        &self.outcome
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct HomeHandoffAcceptanceOutcomeRecordStoredParts {
    pub(super) request: HomeHandoffTakeRequest,
    pub(super) issuer: OrchestrationIssuerId,
    pub(super) preparation_id: Uuid,
    pub(super) workspace_id: WorkspaceId,
    pub(super) predecessor_id: AgentAssignmentId,
    pub(super) root_assignment_id: AgentAssignmentId,
    pub(super) source_at: TimestampMillis,
    pub(super) outcome: HomeHandoffAcceptanceOutcome,
}

impl HomeHandoffAppliedAcceptance {
    pub const fn predecessor_revision_before(&self) -> AgentAssignmentRevision {
        self.predecessor_revision_before
    }

    pub const fn predecessor_revision_after(&self) -> AgentAssignmentRevision {
        self.predecessor_revision_after
    }

    pub const fn predecessor_terminal_disposition(&self) -> AgentAssignmentState {
        self.predecessor_terminal_disposition
    }

    pub const fn successor(&self) -> HomeHandoffInitialSuccessorSnapshot {
        self.successor
    }

    pub const fn grant(&self) -> HomeHandoffAcceptanceGrant {
        self.grant
    }
}

#[allow(
    clippy::large_types_passed_by_value,
    reason = "HomeHandoffSourceAssignmentPin is a Copy value object"
)]
fn validate_source_pin(
    pin: HomeHandoffSourceAssignmentPin,
    source: &forge_domain::RegisteredAgentAssignment,
) -> Result<(), Error> {
    let lineage = match source.origin() {
        AgentAssignmentOrigin::CoordinatorOffer => HomeHandoffAssignmentLineage::CoordinatorOffer,
        AgentAssignmentOrigin::HomeHandoff(origin) => {
            HomeHandoffAssignmentLineage::HomeHandoff(origin)
        }
        AgentAssignmentOrigin::CutContinuation(_) => {
            return Err(Error::Conflict("cut continuation is unsupported for Home"));
        }
    };
    if pin.assignment_id() != source.id()
        || pin.root_assignment_id()
            != match source.origin() {
                AgentAssignmentOrigin::CoordinatorOffer => source.id(),
                AgentAssignmentOrigin::HomeHandoff(origin) => origin.root_assignment_id(),
                AgentAssignmentOrigin::CutContinuation(_) => {
                    return Err(Error::Conflict("cut continuation is unsupported for Home"));
                }
            }
        || pin.workspace_id() != source.workspace_id()
        || pin.activity_id() != source.activity_id()
        || pin.goal_id() != source.goal_id()
        || pin.goal_created_at() != source.goal_created_at()
        || pin.goal_revision() != source.goal_revision()
        || pin.dag_revision() != source.dag_revision()
        || pin.dag_head_revision() != source.dag_head_revision()
        || pin.node_id() != source.node_id()
        || pin.node_revision() != source.node_revision()
        || pin.coordinator() != source.coordinator()
        || pin.target() != source.target()
        || pin.state() != source.state()
        || pin.cancellation_requested() != source.cancellation_requested()
        || pin.credit_budget() != source.credit_budget()
        || pin.created_at() != source.created_at()
        || pin.updated_at() != source.updated_at()
        || pin.revision() != source.revision()
        || pin.lineage() != lineage
    {
        return Err(Error::Conflict("acceptance predecessor pins"));
    }
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "transition validation checks all exact request, lineage, and assignment pins together"
)]
fn validate_transition(
    request: &HomeHandoffTakeRequest,
    source_at: TimestampMillis,
    preparation_id: Uuid,
    root_assignment_id: AgentAssignmentId,
    expected_successor_id: AgentAssignmentId,
    expected_coordinator: forge_domain::ActivityCoordinatorActor,
    source: &forge_domain::RegisteredAgentAssignment,
    transition: &forge_domain::AgentAssignmentHomeHandoffTransition,
) -> Result<(), Error> {
    let predecessor = transition.predecessor();
    let successor = transition.successor();
    let expected_disposition = match source.state() {
        AgentAssignmentState::Offered => AgentAssignmentState::Cancelled,
        AgentAssignmentState::Running => AgentAssignmentState::Interrupted,
        _ => return Err(Error::Conflict("acceptance predecessor state")),
    };
    let origin = AgentAssignmentHomeHandoffOrigin::new(
        preparation_id,
        request.handoff_id(),
        source.id(),
        root_assignment_id,
    )
    .map_err(|_| Error::Conflict("acceptance origin"))?;
    let expected_predecessor_revision = source
        .revision()
        .checked_next()
        .map_err(|_| Error::Conflict("acceptance predecessor revision"))?;

    if predecessor.id() != source.id()
        || predecessor.origin() != source.origin()
        || predecessor.state() != expected_disposition
        || !predecessor.cancellation_requested()
        || predecessor.revision() != expected_predecessor_revision
        || predecessor.updated_at() != source_at
        || predecessor.workspace_id() != source.workspace_id()
        || predecessor.activity_id() != source.activity_id()
        || predecessor.goal_id() != source.goal_id()
        || predecessor.goal_created_at() != source.goal_created_at()
        || predecessor.goal_revision() != source.goal_revision()
        || predecessor.dag_revision() != source.dag_revision()
        || predecessor.dag_head_revision() != source.dag_head_revision()
        || predecessor.node_id() != source.node_id()
        || predecessor.node_revision() != source.node_revision()
        || predecessor.coordinator() != source.coordinator()
        || predecessor.target() != source.target()
        || predecessor.credit_budget() != source.credit_budget()
        || predecessor.created_at() != source.created_at()
        || successor.id() != expected_successor_id
        || successor.origin() != AgentAssignmentOrigin::HomeHandoff(origin)
        || successor.state() != AgentAssignmentState::Running
        || successor.cancellation_requested()
        || successor.result().is_some()
        || successor.reviewed_by().is_some()
        || successor.revision() != AgentAssignmentRevision::INITIAL
        || successor.created_at() != source_at
        || successor.updated_at() != source_at
        || successor.workspace_id() != source.workspace_id()
        || successor.activity_id() != source.activity_id()
        || successor.goal_id() != source.goal_id()
        || successor.goal_created_at() != source.goal_created_at()
        || successor.goal_revision() != source.goal_revision()
        || successor.dag_revision() != source.dag_revision()
        || successor.dag_head_revision() != source.dag_head_revision()
        || successor.node_id() != source.node_id()
        || successor.node_revision().get() < source.node_revision().get()
        || successor.coordinator() != AgentAssignmentCoordinator::from_actor(expected_coordinator)
        || successor.target() != request.recipient()
        || successor.credit_budget() != source.credit_budget()
    {
        return Err(Error::Conflict("acceptance transition pins"));
    }
    Ok(())
}

fn validate_common_record(record: &HomeHandoffAcceptanceOutcomeRecord) -> Result<(), Error> {
    if record.issuer.into_uuid().is_nil()
        || record.preparation_id.is_nil()
        || record.workspace_id.into_uuid().is_nil()
        || record.predecessor_id.into_uuid().is_nil()
        || record.root_assignment_id.into_uuid().is_nil()
        || record.request.handoff_id().is_nil()
        || record.request.proposal_id().is_nil()
        || record.request.expected_case_revision() < 1
        || record.request.scope().workspace_id() != record.workspace_id
    {
        return Err(Error::Corrupt("acceptance identity"));
    }
    Ok(())
}

fn validate_applied_record(
    record: &HomeHandoffAcceptanceOutcomeRecord,
    applied: &HomeHandoffAppliedAcceptance,
) -> Result<(), Error> {
    applied
        .grant
        .validate_for(record.issuer, &record.request, record.source_at)?;
    let successor = applied.successor;
    let expected_origin = AgentAssignmentHomeHandoffOrigin::new(
        record.preparation_id,
        record.request.handoff_id(),
        record.predecessor_id,
        record.root_assignment_id,
    )
    .map_err(|_| Error::Corrupt("applied origin"))?;
    if applied.predecessor_revision_before.get().checked_add(1)
        != Some(applied.predecessor_revision_after.get())
        || !matches!(
            applied.predecessor_terminal_disposition,
            AgentAssignmentState::Cancelled | AgentAssignmentState::Interrupted
        )
        || successor.origin != expected_origin
        || successor.workspace_id != record.workspace_id
        || successor.created_at != record.source_at
        || successor.target != record.request.recipient()
        || successor.assignment_id == record.predecessor_id
        || successor.assignment_id == record.root_assignment_id
        || applied.grant.issuer() != record.issuer
        || applied.grant.take_request_digest() != record.request.request_digest()
    {
        return Err(Error::Corrupt("applied outcome pins"));
    }
    Ok(())
}
