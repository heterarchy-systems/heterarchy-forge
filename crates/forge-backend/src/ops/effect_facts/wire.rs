//! Typed wire projections for the Forge effect-fact outbox.

use forge_domain::{
    ChangeSetState, DiffEvidenceState, FileMutationFailureCode, GoalEvidenceRef,
    VerificationOutputIntegrity, VerificationRunDisposition, WorkCreditBudget,
};
use forge_persistence::{
    AssignmentOfferedEffectFact, AssignmentReviewedEffectFact, AssignmentReviewedOutcome,
    AssignmentSubmittedEffectFact, AssignmentSubmittedSourceRef, ChangeSetTerminalEffectFact,
    EffectFact, EffectFactOutboxEntry, ExecutionTerminalEffectFact,
};
use serde::{Deserialize, Deserializer, Serialize};
use uuid::Uuid;

use super::super::ScopeDto;
use crate::error::ForgeError;

#[must_use]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EffectFactOutboxResponse {
    pub scope: ScopeDto,
    pub backend_id: Uuid,
    pub migration_id: Uuid,
    pub destination_id: Uuid,
    pub after: u64,
    pub entries: Vec<EffectFactOutboxEntryWire>,
}

impl EffectFactOutboxResponse {
    pub(crate) fn from_entries(
        scope: ScopeDto,
        backend_id: Uuid,
        migration_id: Uuid,
        destination_id: Uuid,
        after: u64,
        entries: &[EffectFactOutboxEntry],
    ) -> Result<Self, ForgeError> {
        Ok(Self {
            scope,
            backend_id,
            migration_id,
            destination_id,
            after,
            entries: entries
                .iter()
                .map(EffectFactOutboxEntryWire::from_native)
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

#[must_use]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EffectFactOutboxEntryWire {
    pub sequence: u64,
    pub migration_id: Uuid,
    pub destination_id: Uuid,
    pub workspace_id: Uuid,
    pub fact: EffectFactWire,
    #[serde(deserialize_with = "required_option")]
    pub submitted_source_refs: Option<Vec<AssignmentSubmittedSourceRefWire>>,
}

fn required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

impl EffectFactOutboxEntryWire {
    fn from_native(value: &EffectFactOutboxEntry) -> Result<Self, ForgeError> {
        Ok(Self {
            sequence: value.sequence(),
            migration_id: value.migration_id(),
            destination_id: value.destination_id(),
            workspace_id: value.workspace_id().into_uuid(),
            fact: EffectFactWire::from_native(value.fact())?,
            submitted_source_refs: value
                .submitted_source_refs()
                .map(|refs| refs.iter().map(source_ref_wire).collect()),
        })
    }
}

#[must_use]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EffectFactWire {
    ExecutionTerminal {
        execution_id: Uuid,
        activity_id: Uuid,
        execution_revision: i64,
        state: ExecutionStateWire,
        observed_at_ms: i64,
        agent_id: Uuid,
        agent_revision: i64,
        session_id: Option<Uuid>,
        goal_id: Uuid,
        goal_revision: i64,
        dag_revision: i64,
        node_id: Uuid,
        node_revision: i64,
        verification: Option<VerificationEvidenceWire>,
    },
    ChangeSetTerminal {
        change_set_id: Uuid,
        workspace_id: Uuid,
        workspace_revision: i64,
        activity_id: Uuid,
        runtime_instance_id: Uuid,
        activity_lease_revision: i64,
        change_set_revision: i64,
        state: ChangeSetStateWire,
        failure_code: Option<FileMutationFailureCodeWire>,
        diff_id: Uuid,
        diff_state: DiffEvidenceStateWire,
        diff_revision: i64,
        observed_at_ms: i64,
        producer_agent_id: Option<Uuid>,
        producer_session_id: Option<Uuid>,
    },
    AssignmentReviewed {
        assignment_id: Uuid,
        workspace_id: Uuid,
        activity_id: Uuid,
        goal_id: Uuid,
        node_id: Uuid,
        target_agent_id: Uuid,
        target_session_id: Option<Uuid>,
        outcome: AssignmentReviewedOutcomeWire,
        credit_budget: Option<WorkCreditBudgetWire>,
        reviewer_agent_id: Uuid,
        reviewer_session_id: Option<Uuid>,
        result_digest: Option<String>,
        observed_at_ms: i64,
    },
    AssignmentOffered {
        assignment_id: Uuid,
        workspace_id: Uuid,
        activity_id: Uuid,
        goal_id: Uuid,
        node_id: Uuid,
        target_agent_id: Uuid,
        target_session_id: Option<Uuid>,
        credit_budget: Option<WorkCreditBudgetWire>,
        offered_at_ms: i64,
    },
    AssignmentSubmitted {
        assignment_id: Uuid,
        workspace_id: Uuid,
        activity_id: Uuid,
        goal_id: Uuid,
        node_id: Uuid,
        target_agent_id: Uuid,
        target_session_id: Option<Uuid>,
        source_count: u8,
        source_digests: Option<String>,
        source_kinds: Option<Vec<SourceKindWire>>,
        result_digest: Option<String>,
        submitted_at_ms: i64,
    },
}

impl EffectFactWire {
    fn from_native(value: &EffectFact) -> Result<Self, ForgeError> {
        match value {
            EffectFact::ExecutionTerminal(fact) => Ok(execution_terminal_wire(fact)),
            EffectFact::ChangeSetTerminal(fact) => Ok(change_set_terminal_wire(fact)),
            EffectFact::AssignmentReviewed(fact) => Ok(assignment_reviewed_wire(fact)),
            EffectFact::AssignmentOffered(fact) => Ok(assignment_offered_wire(fact)),
            EffectFact::AssignmentSubmitted(fact) => assignment_submitted_wire(fact),
        }
    }
}

#[must_use]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VerificationEvidenceWire {
    pub input_id: Uuid,
    pub input_fingerprint: String,
    pub disposition: VerificationRunDispositionWire,
    pub output_integrity: Option<VerificationOutputIntegrityWire>,
    pub output_fingerprint: Option<String>,
}

#[must_use]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VerificationRunDispositionWire {
    Accepted,
    Rejected,
    Incomplete,
    RecoveryRequired,
}

#[must_use]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VerificationOutputIntegrityWire {
    Complete,
    Gapped,
    Truncated,
    GappedAndTruncated,
}

#[must_use]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStateWire {
    Starting,
    Running,
    Completed,
    Failed,
    TimedOut,
    Cancelled,
    Interrupted,
}

#[must_use]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChangeSetStateWire {
    Starting,
    Applied,
    Failed,
}

#[must_use]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FileMutationFailureCodeWire {
    InvalidPath,
    ProtectedPath,
    PathConflict,
    StaleWrite,
    CapacityExceeded,
    IoFailure,
}

#[must_use]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DiffEvidenceStateWire {
    Intent,
    Ready,
    SummaryOnly,
    Abandoned,
    PurgePending,
    Tombstoned,
}

#[must_use]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AssignmentReviewedOutcomeWire {
    Accepted,
    Rejected,
}

#[must_use]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkCreditBudgetWire {
    One,
    Three,
    Five,
}

#[must_use]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SourceKindWire {
    Url,
    Provenance,
}

#[must_use]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GoalEvidenceKindWire {
    ChangeSet,
    Execution,
    Approval,
    Checkpoint,
}

#[must_use]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AssignmentSubmittedSourceRefWire {
    pub ordinal: u8,
    pub evidence: GoalEvidenceWire,
}

#[must_use]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GoalEvidenceWire {
    pub kind: GoalEvidenceKindWire,
    pub id: Uuid,
}

fn execution_terminal_wire(value: &ExecutionTerminalEffectFact) -> EffectFactWire {
    EffectFactWire::ExecutionTerminal {
        execution_id: value.execution_id().into_uuid(),
        activity_id: value.activity_id().into_uuid(),
        execution_revision: value.execution_revision().get(),
        state: execution_state_wire(value.state()),
        observed_at_ms: value.observed_at().get(),
        agent_id: value.agent_id().into_uuid(),
        agent_revision: value.agent_revision().get(),
        session_id: value
            .session_id()
            .map(forge_domain::AgentSessionId::into_uuid),
        goal_id: value.goal_id().into_uuid(),
        goal_revision: value.goal_revision().get(),
        dag_revision: value.dag_revision().get(),
        node_id: value.node_id().into_uuid(),
        node_revision: value.node_revision().get(),
        verification: value.verification().map(verification_wire),
    }
}

fn verification_wire(
    value: forge_persistence::EffectFactVerificationEvidence,
) -> VerificationEvidenceWire {
    VerificationEvidenceWire {
        input_id: value.input_id().into_uuid(),
        input_fingerprint: hex(value.input_fingerprint().as_bytes()),
        disposition: verification_disposition_wire(value.disposition()),
        output_integrity: value
            .output_integrity()
            .map(verification_output_integrity_wire),
        output_fingerprint: value
            .output_fingerprint()
            .map(|fingerprint| hex(fingerprint.as_bytes())),
    }
}

fn change_set_terminal_wire(value: &ChangeSetTerminalEffectFact) -> EffectFactWire {
    EffectFactWire::ChangeSetTerminal {
        change_set_id: value.change_set_id().into_uuid(),
        workspace_id: value.workspace_id().into_uuid(),
        workspace_revision: value.workspace_revision().get(),
        activity_id: value.activity_id().into_uuid(),
        runtime_instance_id: value.runtime_instance_id().into_uuid(),
        activity_lease_revision: value.activity_lease_revision().get(),
        change_set_revision: value.change_set_revision().get(),
        state: change_set_state_wire(value.state()),
        failure_code: value.failure_code().map(file_failure_wire),
        diff_id: value.diff_id().into_uuid(),
        diff_state: diff_state_wire(value.diff_state()),
        diff_revision: value.diff_revision().get(),
        observed_at_ms: value.observed_at().get(),
        producer_agent_id: value
            .producer_agent_id()
            .map(forge_domain::AgentInstanceId::into_uuid),
        producer_session_id: value
            .producer_session_id()
            .map(forge_domain::AgentSessionId::into_uuid),
    }
}

fn assignment_reviewed_wire(value: &AssignmentReviewedEffectFact) -> EffectFactWire {
    EffectFactWire::AssignmentReviewed {
        assignment_id: value.assignment_id().into_uuid(),
        workspace_id: value.workspace_id().into_uuid(),
        activity_id: value.activity_id().into_uuid(),
        goal_id: value.goal_id().into_uuid(),
        node_id: value.node_id().into_uuid(),
        target_agent_id: value.target_agent_id().into_uuid(),
        target_session_id: value
            .target_session_id()
            .map(forge_domain::AgentSessionId::into_uuid),
        outcome: assignment_outcome_wire(value.outcome()),
        credit_budget: value.credit_budget().map(credit_budget_wire),
        reviewer_agent_id: value.reviewer_agent_id().into_uuid(),
        reviewer_session_id: value
            .reviewer_session_id()
            .map(forge_domain::AgentSessionId::into_uuid),
        result_digest: value.result_digest().map(|digest| hex(&digest)),
        observed_at_ms: value.observed_at().get(),
    }
}

fn assignment_offered_wire(value: &AssignmentOfferedEffectFact) -> EffectFactWire {
    EffectFactWire::AssignmentOffered {
        assignment_id: value.assignment_id().into_uuid(),
        workspace_id: value.workspace_id().into_uuid(),
        activity_id: value.activity_id().into_uuid(),
        goal_id: value.goal_id().into_uuid(),
        node_id: value.node_id().into_uuid(),
        target_agent_id: value.target_agent_id().into_uuid(),
        target_session_id: value
            .target_session_id()
            .map(forge_domain::AgentSessionId::into_uuid),
        credit_budget: value.credit_budget().map(credit_budget_wire),
        offered_at_ms: value.offered_at().get(),
    }
}

fn assignment_submitted_wire(
    value: &AssignmentSubmittedEffectFact,
) -> Result<EffectFactWire, ForgeError> {
    let source_kinds = value
        .source_kinds()
        .map(|values| values.iter().copied().map(source_kind_wire).collect())
        .transpose()?;
    Ok(EffectFactWire::AssignmentSubmitted {
        assignment_id: value.assignment_id().into_uuid(),
        workspace_id: value.workspace_id().into_uuid(),
        activity_id: value.activity_id().into_uuid(),
        goal_id: value.goal_id().into_uuid(),
        node_id: value.node_id().into_uuid(),
        target_agent_id: value.target_agent_id().into_uuid(),
        target_session_id: value
            .target_session_id()
            .map(forge_domain::AgentSessionId::into_uuid),
        source_count: value.source_count(),
        source_digests: value.source_digests().map(|digest| hex(&digest)),
        source_kinds,
        result_digest: value.result_digest().map(|digest| hex(&digest)),
        submitted_at_ms: value.submitted_at().get(),
    })
}

fn source_ref_wire(value: &AssignmentSubmittedSourceRef) -> AssignmentSubmittedSourceRefWire {
    AssignmentSubmittedSourceRefWire {
        ordinal: value.ordinal(),
        evidence: evidence_wire(value.evidence()),
    }
}

fn evidence_wire(value: GoalEvidenceRef) -> GoalEvidenceWire {
    match value {
        GoalEvidenceRef::ChangeSet(id) => GoalEvidenceWire {
            kind: GoalEvidenceKindWire::ChangeSet,
            id: id.into_uuid(),
        },
        GoalEvidenceRef::Execution(id) => GoalEvidenceWire {
            kind: GoalEvidenceKindWire::Execution,
            id: id.into_uuid(),
        },
        GoalEvidenceRef::Approval(id) => GoalEvidenceWire {
            kind: GoalEvidenceKindWire::Approval,
            id: id.into_uuid(),
        },
        GoalEvidenceRef::Checkpoint(id) => GoalEvidenceWire {
            kind: GoalEvidenceKindWire::Checkpoint,
            id: id.into_uuid(),
        },
    }
}

const fn execution_state_wire(value: forge_domain::ExecutionState) -> ExecutionStateWire {
    match value {
        forge_domain::ExecutionState::Starting => ExecutionStateWire::Starting,
        forge_domain::ExecutionState::Running => ExecutionStateWire::Running,
        forge_domain::ExecutionState::Completed => ExecutionStateWire::Completed,
        forge_domain::ExecutionState::Failed => ExecutionStateWire::Failed,
        forge_domain::ExecutionState::TimedOut => ExecutionStateWire::TimedOut,
        forge_domain::ExecutionState::Cancelled => ExecutionStateWire::Cancelled,
        forge_domain::ExecutionState::Interrupted => ExecutionStateWire::Interrupted,
    }
}

const fn change_set_state_wire(value: ChangeSetState) -> ChangeSetStateWire {
    match value {
        ChangeSetState::Starting => ChangeSetStateWire::Starting,
        ChangeSetState::Applied => ChangeSetStateWire::Applied,
        ChangeSetState::Failed => ChangeSetStateWire::Failed,
    }
}

const fn file_failure_wire(value: FileMutationFailureCode) -> FileMutationFailureCodeWire {
    match value {
        FileMutationFailureCode::InvalidPath => FileMutationFailureCodeWire::InvalidPath,
        FileMutationFailureCode::ProtectedPath => FileMutationFailureCodeWire::ProtectedPath,
        FileMutationFailureCode::PathConflict => FileMutationFailureCodeWire::PathConflict,
        FileMutationFailureCode::StaleWrite => FileMutationFailureCodeWire::StaleWrite,
        FileMutationFailureCode::CapacityExceeded => FileMutationFailureCodeWire::CapacityExceeded,
        FileMutationFailureCode::IoFailure => FileMutationFailureCodeWire::IoFailure,
    }
}

const fn diff_state_wire(value: DiffEvidenceState) -> DiffEvidenceStateWire {
    match value {
        DiffEvidenceState::Intent => DiffEvidenceStateWire::Intent,
        DiffEvidenceState::Ready => DiffEvidenceStateWire::Ready,
        DiffEvidenceState::SummaryOnly => DiffEvidenceStateWire::SummaryOnly,
        DiffEvidenceState::Abandoned => DiffEvidenceStateWire::Abandoned,
        DiffEvidenceState::PurgePending => DiffEvidenceStateWire::PurgePending,
        DiffEvidenceState::Tombstoned => DiffEvidenceStateWire::Tombstoned,
    }
}

const fn assignment_outcome_wire(
    value: AssignmentReviewedOutcome,
) -> AssignmentReviewedOutcomeWire {
    match value {
        AssignmentReviewedOutcome::Accepted => AssignmentReviewedOutcomeWire::Accepted,
        AssignmentReviewedOutcome::Rejected => AssignmentReviewedOutcomeWire::Rejected,
    }
}

const fn credit_budget_wire(value: WorkCreditBudget) -> WorkCreditBudgetWire {
    match value {
        WorkCreditBudget::One => WorkCreditBudgetWire::One,
        WorkCreditBudget::Three => WorkCreditBudgetWire::Three,
        WorkCreditBudget::Five => WorkCreditBudgetWire::Five,
    }
}

fn source_kind_wire(value: u8) -> Result<SourceKindWire, ForgeError> {
    match value {
        0 => Ok(SourceKindWire::Url),
        1 => Ok(SourceKindWire::Provenance),
        _ => Err(ForgeError::internal()),
    }
}

const fn verification_disposition_wire(
    value: VerificationRunDisposition,
) -> VerificationRunDispositionWire {
    match value {
        VerificationRunDisposition::Accepted => VerificationRunDispositionWire::Accepted,
        VerificationRunDisposition::Rejected => VerificationRunDispositionWire::Rejected,
        VerificationRunDisposition::Incomplete => VerificationRunDispositionWire::Incomplete,
        VerificationRunDisposition::RecoveryRequired => {
            VerificationRunDispositionWire::RecoveryRequired
        }
    }
}

const fn verification_output_integrity_wire(
    value: VerificationOutputIntegrity,
) -> VerificationOutputIntegrityWire {
    match value {
        VerificationOutputIntegrity::Complete => VerificationOutputIntegrityWire::Complete,
        VerificationOutputIntegrity::Gapped => VerificationOutputIntegrityWire::Gapped,
        VerificationOutputIntegrity::Truncated => VerificationOutputIntegrityWire::Truncated,
        VerificationOutputIntegrity::GappedAndTruncated => {
            VerificationOutputIntegrityWire::GappedAndTruncated
        }
    }
}

fn hex(value: &[u8]) -> String {
    super::super::encode_hex(value)
}
