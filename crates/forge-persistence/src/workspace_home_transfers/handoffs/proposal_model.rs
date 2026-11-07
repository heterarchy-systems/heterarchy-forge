//! Checked views of immutable proposal history and its mutable CAS head.

use forge_domain::{
    ActivityId, AgentAssignmentCoordinator, AgentAssignmentHomeHandoffOrigin, AgentAssignmentId,
    AgentAssignmentRevision, AgentAssignmentState, AgentAssignmentTarget, DagHeadRevision,
    DagNodeId, DagNodeRevision, DagRevisionNumber, GoalId, GoalRevision, HomeArtifactId,
    HomeHandoffProposalRequest, TimestampMillis, WorkCreditBudget, WorkspaceId,
};
use uuid::Uuid;

use super::HomeHandoffProposalStoreError;

const DIGEST_BYTES: usize = 32;

/// Persistable source lineage. Cut continuations are intentionally unsupported
/// by Home handoffs until a separate custody contract is accepted.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HomeHandoffAssignmentLineage {
    CoordinatorOffer,
    HomeHandoff(AgentAssignmentHomeHandoffOrigin),
}

impl HomeHandoffAssignmentLineage {
    pub const fn root_assignment_id(self, assignment_id: AgentAssignmentId) -> AgentAssignmentId {
        match self {
            Self::CoordinatorOffer => assignment_id,
            Self::HomeHandoff(origin) => origin.root_assignment_id(),
        }
    }
}

/// Exact predecessor pins sampled from the durable assignment row.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HomeHandoffSourceAssignmentPin {
    assignment_id: AgentAssignmentId,
    root_assignment_id: AgentAssignmentId,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    goal_id: GoalId,
    goal_created_at: TimestampMillis,
    goal_revision: GoalRevision,
    dag_revision: DagRevisionNumber,
    dag_head_revision: DagHeadRevision,
    node_id: DagNodeId,
    node_revision: DagNodeRevision,
    coordinator: AgentAssignmentCoordinator,
    target: AgentAssignmentTarget,
    state: AgentAssignmentState,
    cancellation_requested: bool,
    credit_budget: Option<WorkCreditBudget>,
    created_at: TimestampMillis,
    updated_at: TimestampMillis,
    revision: AgentAssignmentRevision,
    lineage: HomeHandoffAssignmentLineage,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct SourceAssignmentPinParts {
    pub assignment_id: AgentAssignmentId,
    pub root_assignment_id: AgentAssignmentId,
    pub workspace_id: WorkspaceId,
    pub activity_id: ActivityId,
    pub goal_id: GoalId,
    pub goal_created_at: TimestampMillis,
    pub goal_revision: GoalRevision,
    pub dag_revision: DagRevisionNumber,
    pub dag_head_revision: DagHeadRevision,
    pub node_id: DagNodeId,
    pub node_revision: DagNodeRevision,
    pub coordinator: AgentAssignmentCoordinator,
    pub target: AgentAssignmentTarget,
    pub state: AgentAssignmentState,
    pub cancellation_requested: bool,
    pub credit_budget: Option<WorkCreditBudget>,
    pub created_at: TimestampMillis,
    pub updated_at: TimestampMillis,
    pub revision: AgentAssignmentRevision,
    pub lineage: HomeHandoffAssignmentLineage,
}

impl HomeHandoffSourceAssignmentPin {
    pub(super) fn from_assignment(
        assignment: &forge_domain::RegisteredAgentAssignment,
        root_assignment_id: AgentAssignmentId,
        lineage: HomeHandoffAssignmentLineage,
    ) -> Result<Self, HomeHandoffProposalStoreError> {
        Self::from_parts(SourceAssignmentPinParts {
            assignment_id: assignment.id(),
            root_assignment_id,
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
            state: assignment.state(),
            cancellation_requested: assignment.cancellation_requested(),
            credit_budget: assignment.credit_budget(),
            created_at: assignment.created_at(),
            updated_at: assignment.updated_at(),
            revision: assignment.revision(),
            lineage,
        })
    }

    #[allow(
        clippy::large_types_passed_by_value,
        reason = "SourceAssignmentPinParts is a Copy value builder"
    )]
    pub(super) fn from_parts(
        parts: SourceAssignmentPinParts,
    ) -> Result<Self, HomeHandoffProposalStoreError> {
        if parts.assignment_id.into_uuid().is_nil()
            || parts.root_assignment_id.into_uuid().is_nil()
            || parts.workspace_id.into_uuid().is_nil()
            || parts.activity_id.into_uuid().is_nil()
            || parts.goal_id.into_uuid().is_nil()
            || parts.node_id.into_uuid().is_nil()
            || parts.created_at > parts.updated_at
            || parts.cancellation_requested
            || !matches!(
                parts.state,
                AgentAssignmentState::Offered | AgentAssignmentState::Running
            )
            || parts.lineage.root_assignment_id(parts.assignment_id) != parts.root_assignment_id
        {
            return Err(HomeHandoffProposalStoreError::Corrupt(
                "source assignment pins",
            ));
        }
        Ok(Self {
            assignment_id: parts.assignment_id,
            root_assignment_id: parts.root_assignment_id,
            workspace_id: parts.workspace_id,
            activity_id: parts.activity_id,
            goal_id: parts.goal_id,
            goal_created_at: parts.goal_created_at,
            goal_revision: parts.goal_revision,
            dag_revision: parts.dag_revision,
            dag_head_revision: parts.dag_head_revision,
            node_id: parts.node_id,
            node_revision: parts.node_revision,
            coordinator: parts.coordinator,
            target: parts.target,
            state: parts.state,
            cancellation_requested: parts.cancellation_requested,
            credit_budget: parts.credit_budget,
            created_at: parts.created_at,
            updated_at: parts.updated_at,
            revision: parts.revision,
            lineage: parts.lineage,
        })
    }

    pub const fn assignment_id(self) -> AgentAssignmentId {
        self.assignment_id
    }

    pub const fn root_assignment_id(self) -> AgentAssignmentId {
        self.root_assignment_id
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

    pub const fn goal_revision(self) -> GoalRevision {
        self.goal_revision
    }

    pub const fn dag_revision(self) -> DagRevisionNumber {
        self.dag_revision
    }

    pub const fn dag_head_revision(self) -> DagHeadRevision {
        self.dag_head_revision
    }

    pub const fn node_id(self) -> DagNodeId {
        self.node_id
    }

    pub const fn node_revision(self) -> DagNodeRevision {
        self.node_revision
    }

    pub const fn coordinator(self) -> AgentAssignmentCoordinator {
        self.coordinator
    }

    pub const fn target(self) -> AgentAssignmentTarget {
        self.target
    }

    pub const fn state(self) -> AgentAssignmentState {
        self.state
    }

    pub const fn cancellation_requested(self) -> bool {
        self.cancellation_requested
    }

    pub const fn credit_budget(self) -> Option<WorkCreditBudget> {
        self.credit_budget
    }

    pub const fn created_at(self) -> TimestampMillis {
        self.created_at
    }

    pub const fn updated_at(self) -> TimestampMillis {
        self.updated_at
    }

    pub const fn revision(self) -> AgentAssignmentRevision {
        self.revision
    }

    pub const fn lineage(self) -> HomeHandoffAssignmentLineage {
        self.lineage
    }
}

/// The artifact request status recorded by a proposal.
///
/// `NoArtifactRequested` is deliberately not a no-prior-work observation.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HomeHandoffProposalEvidence {
    NoArtifactRequested,
    SealedArtifact {
        artifact_id: HomeArtifactId,
        archive_digest: [u8; DIGEST_BYTES],
    },
}

/// One immutable proposal version within its stable handoff case.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HomeHandoffProposalRecord {
    request: HomeHandoffProposalRequest,
    case_revision: i64,
    source: HomeHandoffSourceAssignmentPin,
    prepared_outcome_digest: [u8; DIGEST_BYTES],
    evidence: HomeHandoffProposalEvidence,
    created_at: TimestampMillis,
    payload_digest: [u8; DIGEST_BYTES],
}

impl HomeHandoffProposalRecord {
    #[allow(
        clippy::large_types_passed_by_value,
        reason = "HomeHandoffProposalRequest and HomeHandoffSourceAssignmentPin are Copy value objects"
    )]
    pub(super) fn new(
        request: HomeHandoffProposalRequest,
        case_revision: i64,
        source: HomeHandoffSourceAssignmentPin,
        prepared_outcome_digest: [u8; DIGEST_BYTES],
        evidence: HomeHandoffProposalEvidence,
        created_at: TimestampMillis,
    ) -> Result<Self, HomeHandoffProposalStoreError> {
        let expected_revision_matches = match request.expected_case_revision() {
            None => case_revision == 1,
            Some(expected) => expected.checked_add(1) == Some(case_revision),
        };
        let target = source.target();
        let recipient = request.recipient();
        let coordinator = request.coordinator();
        let evidence_matches = match (request.artifact_id(), evidence) {
            (None, HomeHandoffProposalEvidence::NoArtifactRequested) => true,
            (
                Some(expected),
                HomeHandoffProposalEvidence::SealedArtifact {
                    artifact_id,
                    archive_digest,
                },
            ) => expected == artifact_id && archive_digest != [0; DIGEST_BYTES],
            _ => false,
        };
        if !expected_revision_matches
            || request.predecessor_id() != source.assignment_id()
            || request.predecessor_revision() != source.revision()
            || request.coordinator().workspace_id() != source.workspace_id()
            || request.coordinator().activity_id() != source.activity_id()
            || source.goal_created_at().get() < 0
            || prepared_outcome_digest == [0; DIGEST_BYTES]
            || !evidence_matches
            || recipient.agent_id() == target.agent_id()
            || recipient.session_id() == target.session_id()
            || recipient.agent_id() == coordinator.agent_id()
            || recipient.session_id() == coordinator.session_id()
            || created_at < source.updated_at()
        {
            return Err(HomeHandoffProposalStoreError::Conflict(
                "proposal does not match the exact current predecessor and recipient",
            ));
        }
        let payload_digest = super::proposal_codec::record_digest(
            &request,
            case_revision,
            &source,
            &prepared_outcome_digest,
            evidence,
            created_at,
        )?;
        Ok(Self {
            request,
            case_revision,
            source,
            prepared_outcome_digest,
            evidence,
            created_at,
            payload_digest,
        })
    }

    pub const fn request(&self) -> HomeHandoffProposalRequest {
        self.request
    }

    pub const fn case_revision(&self) -> i64 {
        self.case_revision
    }

    pub const fn source(&self) -> HomeHandoffSourceAssignmentPin {
        self.source
    }

    pub const fn prepared_outcome_digest(&self) -> &[u8; DIGEST_BYTES] {
        &self.prepared_outcome_digest
    }

    pub const fn evidence(&self) -> HomeHandoffProposalEvidence {
        self.evidence
    }

    pub const fn created_at(&self) -> TimestampMillis {
        self.created_at
    }

    pub const fn payload_digest(&self) -> &[u8; DIGEST_BYTES] {
        &self.payload_digest
    }
}

/// Current head plus its stable case identity. Historical Get remains
/// available by proposal ID after the head advances.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HomeHandoffCaseSnapshot {
    handoff_id: Uuid,
    preparation_id: Uuid,
    workspace_id: WorkspaceId,
    predecessor_id: AgentAssignmentId,
    root_assignment_id: AgentAssignmentId,
    opened_at: TimestampMillis,
    head: HomeHandoffProposalRecord,
}

impl HomeHandoffCaseSnapshot {
    #[allow(
        clippy::large_types_passed_by_value,
        reason = "HomeHandoffProposalRecord is a Copy value object"
    )]
    pub(super) fn new(
        handoff_id: Uuid,
        preparation_id: Uuid,
        workspace_id: WorkspaceId,
        predecessor_id: AgentAssignmentId,
        root_assignment_id: AgentAssignmentId,
        opened_at: TimestampMillis,
        head: HomeHandoffProposalRecord,
    ) -> Result<Self, HomeHandoffProposalStoreError> {
        let request = head.request();
        let source = head.source();
        if handoff_id.is_nil()
            || preparation_id.is_nil()
            || workspace_id.into_uuid().is_nil()
            || request.handoff_id() != handoff_id
            || request.preparation_id() != preparation_id
            || request.predecessor_id() != predecessor_id
            || source.workspace_id() != workspace_id
            || source.assignment_id() != predecessor_id
            || source.root_assignment_id() != root_assignment_id
            || head.created_at() < opened_at
        {
            return Err(HomeHandoffProposalStoreError::Corrupt(
                "proposal case identity or head pointer",
            ));
        }
        Ok(Self {
            handoff_id,
            preparation_id,
            workspace_id,
            predecessor_id,
            root_assignment_id,
            opened_at,
            head,
        })
    }

    pub const fn handoff_id(self) -> Uuid {
        self.handoff_id
    }

    pub const fn preparation_id(self) -> Uuid {
        self.preparation_id
    }

    pub const fn workspace_id(self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn predecessor_id(self) -> AgentAssignmentId {
        self.predecessor_id
    }

    pub const fn root_assignment_id(self) -> AgentAssignmentId {
        self.root_assignment_id
    }

    pub const fn opened_at(self) -> TimestampMillis {
        self.opened_at
    }

    pub const fn head(self) -> HomeHandoffProposalRecord {
        self.head
    }
}

/// Stable result labels for an inserted proposal or exact replay.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HomeHandoffProposalOutcome {
    Created(HomeHandoffProposalRecord),
    Existing(HomeHandoffProposalRecord),
}

impl HomeHandoffProposalOutcome {
    pub const fn record(self) -> HomeHandoffProposalRecord {
        match self {
            Self::Created(record) | Self::Existing(record) => record,
        }
    }
}
