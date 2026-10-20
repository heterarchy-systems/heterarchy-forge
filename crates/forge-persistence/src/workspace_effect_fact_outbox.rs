//! Durable source-of-truth effect facts exported after Agent operations delegation.
//!
//! This outbox is intentionally separate from the participation/focus handoff outbox.
//! It records facts produced by Forge-owned effects so Orchestration can rebuild an
//! operational projection without becoming a source mutation authority.

use forge_domain::{
    ActivityId, ActivityLeaseRevision, AgentAssignmentId, AgentInstanceId, AgentInstanceRevision,
    AgentSessionId, ChangeSetId, ChangeSetProducer, ChangeSetRevision, ChangeSetState, DagNodeId,
    DagNodeRevision, DagRevisionNumber, DiffEvidenceState, DiffId, DiffRevision, ExecutionId,
    ExecutionRevision, ExecutionState, FileMutationFailureCode, GoalId, GoalRevision,
    RegisteredAgentAssignment, RegisteredChangeSet, RegisteredDiffEvidence, RegisteredExecution,
    RuntimeInstanceId, TimestampMillis, VerificationInputFingerprint, VerificationInputId,
    VerificationOutputFingerprint, VerificationOutputIntegrity, VerificationRun,
    VerificationRunDisposition, WorkCreditBudget, WorkspaceId, WorkspaceRevision,
};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

mod assignment_submitted;

pub(crate) use assignment_submitted::append_assignment_submitted;
pub use assignment_submitted::{
    AssignmentSourceRefError, AssignmentSubmittedEffectFact, AssignmentSubmittedSourceRef,
};

const MAX_PAGE_SIZE: u32 = 64;
const MAX_SCHEMA_SQL_BYTES: i64 = 16 * 1024;
const UUID_BYTES: usize = 16;
const DIGEST_BYTES: usize = 32;
const EXECUTION_TERMINAL_KIND: i64 = 0;
const CHANGE_SET_TERMINAL_KIND: i64 = 1;
const ASSIGNMENT_REVIEWED_KIND: i64 = 2;
const ASSIGNMENT_OFFERED_KIND: i64 = 3;
const ASSIGNMENT_SUBMITTED_KIND: i64 = 4;

const ENTRIES_SQL: &str = "CREATE TABLE effect_fact_outbox_entries (sequence INTEGER PRIMARY KEY NOT NULL CHECK(sequence >= 1), migration_id BLOB NOT NULL CHECK(length(migration_id) = 16 AND migration_id != zeroblob(16)), destination_id BLOB NOT NULL CHECK(length(destination_id) = 16 AND destination_id != zeroblob(16)), workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16 AND workspace_id != zeroblob(16)), fact_kind INTEGER NOT NULL CHECK(fact_kind BETWEEN 0 AND 7))";
const EXECUTION_TERMINAL_SQL: &str = "CREATE TABLE effect_fact_outbox_execution_terminal (outbox_sequence INTEGER PRIMARY KEY NOT NULL REFERENCES effect_fact_outbox_entries(sequence), execution_id BLOB NOT NULL UNIQUE CHECK(length(execution_id) = 16 AND execution_id != zeroblob(16)), activity_id BLOB NOT NULL CHECK(length(activity_id) = 16 AND activity_id != zeroblob(16)), execution_revision INTEGER NOT NULL CHECK(execution_revision >= 1), execution_state INTEGER NOT NULL CHECK(execution_state IN (2,3,4,5,6)), observed_at_ms INTEGER NOT NULL CHECK(observed_at_ms >= 0), agent_id BLOB NOT NULL CHECK(length(agent_id) = 16 AND agent_id != zeroblob(16)), agent_revision INTEGER NOT NULL CHECK(agent_revision >= 1), session_id BLOB CHECK(session_id IS NULL OR (length(session_id) = 16 AND session_id != zeroblob(16))), goal_id BLOB NOT NULL CHECK(length(goal_id) = 16 AND goal_id != zeroblob(16)), goal_revision INTEGER NOT NULL CHECK(goal_revision >= 1), dag_revision INTEGER NOT NULL CHECK(dag_revision >= 1), node_id BLOB NOT NULL CHECK(length(node_id) = 16 AND node_id != zeroblob(16)), node_revision INTEGER NOT NULL CHECK(node_revision >= 1), verification_input_id BLOB CHECK(verification_input_id IS NULL OR (length(verification_input_id) = 16 AND verification_input_id != zeroblob(16))), verification_input_fingerprint BLOB CHECK(verification_input_fingerprint IS NULL OR length(verification_input_fingerprint) = 32), verification_disposition INTEGER CHECK(verification_disposition IS NULL OR verification_disposition BETWEEN 0 AND 3), verification_output_integrity INTEGER CHECK(verification_output_integrity IS NULL OR verification_output_integrity BETWEEN 0 AND 3), verification_output_fingerprint BLOB CHECK(verification_output_fingerprint IS NULL OR length(verification_output_fingerprint) = 32), CHECK((verification_input_id IS NULL AND verification_input_fingerprint IS NULL AND verification_disposition IS NULL AND verification_output_integrity IS NULL AND verification_output_fingerprint IS NULL) OR (verification_input_id IS NOT NULL AND verification_input_fingerprint IS NOT NULL AND verification_disposition IS NOT NULL AND ((verification_disposition = 3 AND ((verification_output_integrity IS NULL AND verification_output_fingerprint IS NULL) OR (verification_output_integrity IS NOT NULL AND verification_output_fingerprint IS NOT NULL))) OR (verification_disposition != 3 AND verification_output_integrity IS NOT NULL AND verification_output_fingerprint IS NOT NULL)))))";
const CHANGE_SET_TERMINAL_SQL: &str = "CREATE TABLE effect_fact_outbox_change_set (outbox_sequence INTEGER PRIMARY KEY NOT NULL REFERENCES effect_fact_outbox_entries(sequence), migration_id BLOB NOT NULL CHECK(length(migration_id) = 16 AND migration_id != zeroblob(16)), destination_id BLOB NOT NULL CHECK(length(destination_id) = 16 AND destination_id != zeroblob(16)), workspace_id BLOB NOT NULL CHECK(length(workspace_id) = 16 AND workspace_id != zeroblob(16)), activity_id BLOB NOT NULL CHECK(length(activity_id) = 16 AND activity_id != zeroblob(16)), change_set_id BLOB NOT NULL UNIQUE CHECK(length(change_set_id) = 16 AND change_set_id != zeroblob(16)), change_set_revision INTEGER NOT NULL CHECK(change_set_revision >= 1), change_set_state INTEGER NOT NULL CHECK(change_set_state IN (1,2)), failure_code TEXT CHECK((change_set_state = 1 AND failure_code IS NULL) OR (change_set_state = 2 AND failure_code IN ('InvalidPath','ProtectedPath','PathConflict','StaleWrite','CapacityExceeded','IoFailure'))), diff_id BLOB NOT NULL CHECK(length(diff_id) = 16 AND diff_id != zeroblob(16)), diff_state TEXT NOT NULL CHECK(diff_state IN ('Ready','SummaryOnly','Abandoned')), diff_revision INTEGER NOT NULL CHECK(diff_revision >= 1), workspace_revision INTEGER NOT NULL CHECK(workspace_revision >= 1), runtime_instance_id BLOB CHECK(runtime_instance_id IS NULL OR (length(runtime_instance_id) = 16 AND runtime_instance_id != zeroblob(16))), activity_lease_revision INTEGER CHECK(activity_lease_revision IS NULL OR activity_lease_revision >= 1), observed_at_ms INTEGER NOT NULL CHECK(observed_at_ms >= 0), producer_agent_id BLOB CHECK(producer_agent_id IS NULL OR (length(producer_agent_id) = 16 AND producer_agent_id != zeroblob(16))), producer_session_id BLOB CHECK(producer_session_id IS NULL OR (length(producer_session_id) = 16 AND producer_session_id != zeroblob(16))))";
/// Additive `v46` to `v47` producer-attribution columns. `SQLite` rewrites the
/// stored schema text by appending these column definitions in order, which is
/// exactly their position in [`CHANGE_SET_TERMINAL_SQL`], so migrated and
/// freshly created tables share one normalized shape. The columns stay
/// nullable in SQL so the additive `ALTER` can run over legacy rows; the
/// append path always supplies the producer Agent and decode fails closed on
/// a `NULL` producer written after v47.
const CHANGE_SET_PRODUCER_AGENT_COLUMN_SQL: &str = "producer_agent_id BLOB CHECK(producer_agent_id IS NULL OR (length(producer_agent_id) = 16 AND producer_agent_id != zeroblob(16)))";
const CHANGE_SET_PRODUCER_SESSION_COLUMN_SQL: &str = "producer_session_id BLOB CHECK(producer_session_id IS NULL OR (length(producer_session_id) = 16 AND producer_session_id != zeroblob(16)))";
pub(crate) const CHANGE_SET_PRODUCER_AGENT_ALTER_SQL: &str = "ALTER TABLE effect_fact_outbox_change_set ADD COLUMN producer_agent_id BLOB CHECK(producer_agent_id IS NULL OR (length(producer_agent_id) = 16 AND producer_agent_id != zeroblob(16)))";
pub(crate) const CHANGE_SET_PRODUCER_SESSION_ALTER_SQL: &str = "ALTER TABLE effect_fact_outbox_change_set ADD COLUMN producer_session_id BLOB CHECK(producer_session_id IS NULL OR (length(producer_session_id) = 16 AND producer_session_id != zeroblob(16)))";

/// Exact `v46` shape of the change-set payload table, derived from the current
/// canonical definition so there is only one hand-written authority for the
/// table contract.
pub(crate) fn change_set_terminal_sql_pre_producer() -> String {
    CHANGE_SET_TERMINAL_SQL
        .replace(&format!(", {CHANGE_SET_PRODUCER_AGENT_COLUMN_SQL}"), "")
        .replace(&format!(", {CHANGE_SET_PRODUCER_SESSION_COLUMN_SQL}"), "")
}

pub(crate) fn add_change_set_producer_columns(
    connection: &Connection,
) -> Result<(), EffectFactOutboxError> {
    connection.execute_batch(CHANGE_SET_PRODUCER_AGENT_ALTER_SQL)?;
    connection.execute_batch(CHANGE_SET_PRODUCER_SESSION_ALTER_SQL)?;
    Ok(())
}
const ASSIGNMENT_REVIEWED_SQL: &str = "CREATE TABLE effect_fact_outbox_assignment_review (outbox_sequence INTEGER PRIMARY KEY NOT NULL REFERENCES effect_fact_outbox_entries(sequence), migration_id BLOB NOT NULL CHECK(length(migration_id) = 16 AND migration_id != zeroblob(16)), destination_id BLOB NOT NULL CHECK(length(destination_id) = 16 AND destination_id != zeroblob(16)), workspace_id BLOB NOT NULL CHECK(length(workspace_id) = 16 AND workspace_id != zeroblob(16)), activity_id BLOB NOT NULL CHECK(length(activity_id) = 16 AND activity_id != zeroblob(16)), assignment_id BLOB NOT NULL UNIQUE CHECK(length(assignment_id) = 16 AND assignment_id != zeroblob(16)), goal_id BLOB NOT NULL CHECK(length(goal_id) = 16 AND goal_id != zeroblob(16)), node_id BLOB NOT NULL CHECK(length(node_id) = 16 AND node_id != zeroblob(16)), target_agent_id BLOB NOT NULL CHECK(length(target_agent_id) = 16 AND target_agent_id != zeroblob(16)), target_session_id BLOB CHECK(target_session_id IS NULL OR (length(target_session_id) = 16 AND target_session_id != zeroblob(16))), outcome TEXT NOT NULL CHECK(outcome IN ('Accepted','Rejected')), credit_budget INTEGER CHECK(credit_budget IS NULL OR credit_budget IN (1,3,5)), reviewer_agent_id BLOB NOT NULL CHECK(length(reviewer_agent_id) = 16 AND reviewer_agent_id != zeroblob(16)), reviewer_session_id BLOB CHECK(reviewer_session_id IS NULL OR (length(reviewer_session_id) = 16 AND reviewer_session_id != zeroblob(16))), result_digest BLOB CHECK(result_digest IS NULL OR length(result_digest) = 32), observed_at_ms INTEGER NOT NULL CHECK(observed_at_ms >= 0))";
const ASSIGNMENT_OFFERED_SQL: &str = "CREATE TABLE effect_fact_outbox_assignment_offered (outbox_sequence INTEGER PRIMARY KEY NOT NULL REFERENCES effect_fact_outbox_entries(sequence), migration_id BLOB NOT NULL CHECK(length(migration_id) = 16 AND migration_id != zeroblob(16)), destination_id BLOB NOT NULL CHECK(length(destination_id) = 16 AND destination_id != zeroblob(16)), workspace_id BLOB NOT NULL CHECK(length(workspace_id) = 16 AND workspace_id != zeroblob(16)), activity_id BLOB NOT NULL CHECK(length(activity_id) = 16 AND activity_id != zeroblob(16)), assignment_id BLOB NOT NULL UNIQUE CHECK(length(assignment_id) = 16 AND assignment_id != zeroblob(16)), goal_id BLOB NOT NULL CHECK(length(goal_id) = 16 AND goal_id != zeroblob(16)), node_id BLOB NOT NULL CHECK(length(node_id) = 16 AND node_id != zeroblob(16)), target_agent_id BLOB NOT NULL CHECK(length(target_agent_id) = 16 AND target_agent_id != zeroblob(16)), target_session_id BLOB CHECK(target_session_id IS NULL OR (length(target_session_id) = 16 AND target_session_id != zeroblob(16))), credit_budget INTEGER CHECK(credit_budget IS NULL OR credit_budget IN (1,3,5)), offered_at_ms INTEGER NOT NULL CHECK(offered_at_ms >= 0))";
const WORKSPACE_SEQUENCE_INDEX_SQL: &str = "CREATE INDEX effect_fact_outbox_workspace_sequence_idx ON effect_fact_outbox_entries(workspace_id, sequence ASC)";

const OBJECTS: [(&str, &str, &str); 8] = [
    ("table", "effect_fact_outbox_entries", ENTRIES_SQL),
    (
        "table",
        "effect_fact_outbox_execution_terminal",
        EXECUTION_TERMINAL_SQL,
    ),
    (
        "table",
        "effect_fact_outbox_change_set",
        CHANGE_SET_TERMINAL_SQL,
    ),
    (
        "table",
        "effect_fact_outbox_assignment_review",
        ASSIGNMENT_REVIEWED_SQL,
    ),
    (
        "table",
        "effect_fact_outbox_assignment_offered",
        ASSIGNMENT_OFFERED_SQL,
    ),
    (
        "index",
        "effect_fact_outbox_workspace_sequence_idx",
        WORKSPACE_SEQUENCE_INDEX_SQL,
    ),
    (
        "table",
        "effect_fact_outbox_assignment_submitted",
        assignment_submitted::SCHEMA_SQL,
    ),
    (
        "table",
        "effect_fact_outbox_assignment_submitted_source_ref",
        assignment_submitted::SOURCE_REFS_SQL,
    ),
];

const BASE_OBJECTS: [(&str, &str); 3] = [
    ("table", "effect_fact_outbox_entries"),
    ("table", "effect_fact_outbox_execution_terminal"),
    ("index", "effect_fact_outbox_workspace_sequence_idx"),
];

const CHANGE_SET_OBJECTS: [(&str, &str); 1] = [("table", "effect_fact_outbox_change_set")];

const WORK_CREDIT_OBJECTS: [(&str, &str); 1] = [("table", "effect_fact_outbox_assignment_review")];

const ASSIGNMENT_OFFERED_OBJECTS: [(&str, &str); 1] =
    [("table", "effect_fact_outbox_assignment_offered")];

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EffectFactVerificationEvidence {
    input_id: VerificationInputId,
    input_fingerprint: VerificationInputFingerprint,
    disposition: VerificationRunDisposition,
    output_integrity: Option<VerificationOutputIntegrity>,
    output_fingerprint: Option<VerificationOutputFingerprint>,
}

impl EffectFactVerificationEvidence {
    fn from_run(run: &VerificationRun) -> Result<Self, EffectFactOutboxError> {
        let status = run
            .terminal_status()
            .ok_or(EffectFactOutboxError::VerificationNotTerminal)?;
        Ok(Self {
            input_id: run.input_id(),
            input_fingerprint: run.input_fingerprint(),
            disposition: status.disposition(),
            output_integrity: status.output_integrity(),
            output_fingerprint: status.output_fingerprint(),
        })
    }

    pub const fn input_id(self) -> VerificationInputId {
        self.input_id
    }

    pub const fn input_fingerprint(self) -> VerificationInputFingerprint {
        self.input_fingerprint
    }

    pub const fn disposition(self) -> VerificationRunDisposition {
        self.disposition
    }

    pub const fn output_integrity(self) -> Option<VerificationOutputIntegrity> {
        self.output_integrity
    }

    pub const fn output_fingerprint(self) -> Option<VerificationOutputFingerprint> {
        self.output_fingerprint
    }
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionTerminalEffectFact {
    execution_id: ExecutionId,
    activity_id: ActivityId,
    execution_revision: ExecutionRevision,
    state: ExecutionState,
    observed_at: TimestampMillis,
    agent_id: AgentInstanceId,
    agent_revision: AgentInstanceRevision,
    session_id: Option<AgentSessionId>,
    goal_id: GoalId,
    goal_revision: GoalRevision,
    dag_revision: DagRevisionNumber,
    node_id: DagNodeId,
    node_revision: DagNodeRevision,
    verification: Option<EffectFactVerificationEvidence>,
}

impl ExecutionTerminalEffectFact {
    fn from_execution(
        execution: &RegisteredExecution,
        verification: Option<&VerificationRun>,
    ) -> Result<Option<Self>, EffectFactOutboxError> {
        if !execution.state().is_terminal() {
            return Err(EffectFactOutboxError::ExecutionNotTerminal);
        }
        let Some(provenance) = execution.provenance() else {
            return Ok(None);
        };
        if let Some(run) = verification
            && (run.execution_id() != execution.id()
                || run.workspace_id() != execution.workspace_id())
        {
            return Err(EffectFactOutboxError::VerificationIdentityConflict);
        }
        let attribution = provenance.attribution();
        let verification = verification
            .map(EffectFactVerificationEvidence::from_run)
            .transpose()?;
        Ok(Some(Self {
            execution_id: execution.id(),
            activity_id: execution.activity_id(),
            execution_revision: execution.revision(),
            state: execution.state(),
            observed_at: execution.timestamps().updated_at(),
            agent_id: provenance.agent_id(),
            agent_revision: provenance.agent_revision(),
            session_id: provenance.session_id(),
            goal_id: attribution.goal_id(),
            goal_revision: attribution.expected_goal_revision(),
            dag_revision: attribution.dag_revision(),
            node_id: attribution.node_id(),
            node_revision: attribution.expected_node_revision(),
            verification,
        }))
    }

    pub const fn execution_id(self) -> ExecutionId {
        self.execution_id
    }

    pub const fn activity_id(self) -> ActivityId {
        self.activity_id
    }

    pub const fn execution_revision(self) -> ExecutionRevision {
        self.execution_revision
    }

    pub const fn state(self) -> ExecutionState {
        self.state
    }

    pub const fn observed_at(self) -> TimestampMillis {
        self.observed_at
    }

    pub const fn agent_id(self) -> AgentInstanceId {
        self.agent_id
    }

    pub const fn agent_revision(self) -> AgentInstanceRevision {
        self.agent_revision
    }

    pub const fn session_id(self) -> Option<AgentSessionId> {
        self.session_id
    }

    pub const fn goal_id(self) -> GoalId {
        self.goal_id
    }

    pub const fn goal_revision(self) -> GoalRevision {
        self.goal_revision
    }

    pub const fn dag_revision(self) -> DagRevisionNumber {
        self.dag_revision
    }

    pub const fn node_id(self) -> DagNodeId {
        self.node_id
    }

    pub const fn node_revision(self) -> DagNodeRevision {
        self.node_revision
    }

    pub const fn verification(self) -> Option<EffectFactVerificationEvidence> {
        self.verification
    }
}

/// Durable terminal fact for one Activity-attributed `ChangeSet` and its
/// exactly-attributed Diff evidence. Every field is read from the live domain
/// projections; no artifact fingerprint is invented or recomputed here.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChangeSetTerminalEffectFact {
    change_set_id: ChangeSetId,
    workspace_id: WorkspaceId,
    workspace_revision: WorkspaceRevision,
    activity_id: ActivityId,
    runtime_instance_id: RuntimeInstanceId,
    activity_lease_revision: ActivityLeaseRevision,
    change_set_revision: ChangeSetRevision,
    state: ChangeSetState,
    failure_code: Option<FileMutationFailureCode>,
    diff_id: DiffId,
    diff_state: DiffEvidenceState,
    diff_revision: DiffRevision,
    observed_at: TimestampMillis,
    producer_agent_id: Option<AgentInstanceId>,
    producer_session_id: Option<AgentSessionId>,
}

impl ChangeSetTerminalEffectFact {
    /// Build the terminal fact from the live projections plus the exact
    /// producer identity supplied by the same authoritative transaction. The
    /// producer is required — a `ChangeSet` completion always has an
    /// authenticated actor in these paths — so absence is unrepresentable in
    /// the [`ChangeSetProducer`] input type.
    fn from_change_set(
        change_set: &RegisteredChangeSet,
        diff: &RegisteredDiffEvidence,
        producer: ChangeSetProducer,
    ) -> Result<Self, EffectFactOutboxError> {
        if change_set.state() == ChangeSetState::Starting {
            return Err(EffectFactOutboxError::ChangeSetNotTerminal);
        }
        if diff.change_set_id() != change_set.id()
            || diff.workspace_id() != change_set.workspace_id()
            || diff.activity_id() != change_set.activity_id()
        {
            return Err(EffectFactOutboxError::DiffIdentityConflict);
        }
        let diff_state = match diff.state() {
            state @ (DiffEvidenceState::Ready
            | DiffEvidenceState::SummaryOnly
            | DiffEvidenceState::Abandoned) => state,
            DiffEvidenceState::Intent
            | DiffEvidenceState::PurgePending
            | DiffEvidenceState::Tombstoned => {
                return Err(EffectFactOutboxError::DiffNotTerminal);
            }
        };
        Ok(Self {
            change_set_id: change_set.id(),
            workspace_id: change_set.workspace_id(),
            workspace_revision: change_set.workspace_revision(),
            activity_id: change_set.activity_id(),
            runtime_instance_id: change_set.runtime_instance_id(),
            activity_lease_revision: change_set.activity_lease_revision(),
            change_set_revision: change_set.revision(),
            state: change_set.state(),
            failure_code: change_set.failure_code(),
            diff_id: diff.id(),
            diff_state,
            diff_revision: diff.revision(),
            observed_at: change_set.updated_at(),
            producer_agent_id: Some(producer.agent_id()),
            producer_session_id: producer.session_id(),
        })
    }

    pub const fn change_set_id(self) -> ChangeSetId {
        self.change_set_id
    }

    pub const fn workspace_id(self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn workspace_revision(self) -> WorkspaceRevision {
        self.workspace_revision
    }

    pub const fn activity_id(self) -> ActivityId {
        self.activity_id
    }

    pub const fn runtime_instance_id(self) -> RuntimeInstanceId {
        self.runtime_instance_id
    }

    pub const fn activity_lease_revision(self) -> ActivityLeaseRevision {
        self.activity_lease_revision
    }

    pub const fn change_set_revision(self) -> ChangeSetRevision {
        self.change_set_revision
    }

    pub const fn state(self) -> ChangeSetState {
        self.state
    }

    pub const fn failure_code(self) -> Option<FileMutationFailureCode> {
        self.failure_code
    }

    pub const fn diff_id(self) -> DiffId {
        self.diff_id
    }

    pub const fn diff_state(self) -> DiffEvidenceState {
        self.diff_state
    }

    pub const fn diff_revision(self) -> DiffRevision {
        self.diff_revision
    }

    pub const fn observed_at(self) -> TimestampMillis {
        self.observed_at
    }

    /// The authenticated producer of this `ChangeSet` (v47 attribution).
    /// Facts decoded from pre-`v47` payload rows carry `None`; such rows can
    /// never be re-admitted under the new attribution contract and replay of
    /// one conflicts (they are dev-era rows and disposable pre-deployment).
    pub const fn producer_agent_id(self) -> Option<AgentInstanceId> {
        self.producer_agent_id
    }

    /// The authenticated producer session, when the producing authority
    /// recorded one.
    pub const fn producer_session_id(self) -> Option<AgentSessionId> {
        self.producer_session_id
    }
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EffectFact {
    ExecutionTerminal(Box<ExecutionTerminalEffectFact>),
    ChangeSetTerminal(Box<ChangeSetTerminalEffectFact>),
    AssignmentReviewed(Box<AssignmentReviewedEffectFact>),
    AssignmentOffered(Box<AssignmentOfferedEffectFact>),
    AssignmentSubmitted(Box<AssignmentSubmittedEffectFact>),
}

/// Terminal Main review outcome recorded by one assignment-review fact.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AssignmentReviewedOutcome {
    Accepted,
    Rejected,
}

/// Durable terminal fact for one explicit Main assignment review. Every field
/// is read from the durable post-review assignment row inside the review
/// transaction; the result digest is the SHA-256 of the submitted report text
/// and is `None` only when the row carries no report.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AssignmentReviewedEffectFact {
    assignment_id: AgentAssignmentId,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    goal_id: GoalId,
    node_id: DagNodeId,
    target_agent_id: AgentInstanceId,
    target_session_id: Option<AgentSessionId>,
    outcome: AssignmentReviewedOutcome,
    credit_budget: Option<WorkCreditBudget>,
    reviewer_agent_id: AgentInstanceId,
    reviewer_session_id: Option<AgentSessionId>,
    result_digest: Option<[u8; DIGEST_BYTES]>,
    observed_at: TimestampMillis,
}

impl AssignmentReviewedEffectFact {
    fn from_assignment_review(
        assignment: &RegisteredAgentAssignment,
    ) -> Result<Self, EffectFactOutboxError> {
        let outcome = match assignment.state() {
            forge_domain::AgentAssignmentState::Accepted => AssignmentReviewedOutcome::Accepted,
            forge_domain::AgentAssignmentState::Rejected => AssignmentReviewedOutcome::Rejected,
            forge_domain::AgentAssignmentState::Offered
            | forge_domain::AgentAssignmentState::Running
            | forge_domain::AgentAssignmentState::Submitted
            | forge_domain::AgentAssignmentState::Cancelled
            | forge_domain::AgentAssignmentState::Interrupted => {
                return Err(EffectFactOutboxError::AssignmentNotReviewed);
            }
        };
        let review = assignment
            .reviewed_by()
            .ok_or(EffectFactOutboxError::CorruptRecord(
                "effect_fact.assignment_reviewer",
            ))?;
        let result_digest = assignment
            .result()
            .map(|result| Sha256::digest(result.report().as_bytes()).into());
        Ok(Self {
            assignment_id: assignment.id(),
            workspace_id: assignment.workspace_id(),
            activity_id: assignment.activity_id(),
            goal_id: assignment.goal_id(),
            node_id: assignment.node_id(),
            target_agent_id: assignment.target().agent_id(),
            target_session_id: Some(assignment.target().session_id()),
            outcome,
            credit_budget: assignment.credit_budget(),
            reviewer_agent_id: review.agent_id(),
            reviewer_session_id: Some(review.session_id()),
            result_digest,
            observed_at: assignment.updated_at(),
        })
    }

    pub const fn assignment_id(self) -> AgentAssignmentId {
        self.assignment_id
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

    pub const fn node_id(self) -> DagNodeId {
        self.node_id
    }

    pub const fn target_agent_id(self) -> AgentInstanceId {
        self.target_agent_id
    }

    pub const fn target_session_id(self) -> Option<AgentSessionId> {
        self.target_session_id
    }

    pub const fn outcome(self) -> AssignmentReviewedOutcome {
        self.outcome
    }

    pub const fn credit_budget(self) -> Option<WorkCreditBudget> {
        self.credit_budget
    }

    pub const fn reviewer_agent_id(self) -> AgentInstanceId {
        self.reviewer_agent_id
    }

    pub const fn reviewer_session_id(self) -> Option<AgentSessionId> {
        self.reviewer_session_id
    }

    pub const fn result_digest(self) -> Option<[u8; DIGEST_BYTES]> {
        self.result_digest
    }

    pub const fn observed_at(self) -> TimestampMillis {
        self.observed_at
    }
}

/// Durable first-work receipt for one assignment offer. It is the bootstrap
/// identity Orchestration leads from: exactly the pre-work offer row, with no
/// report and no reviewer. Every field is read from the durable post-offer
/// assignment row inside the offer transaction.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AssignmentOfferedEffectFact {
    assignment_id: AgentAssignmentId,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    goal_id: GoalId,
    node_id: DagNodeId,
    target_agent_id: AgentInstanceId,
    target_session_id: Option<AgentSessionId>,
    credit_budget: Option<WorkCreditBudget>,
    offered_at: TimestampMillis,
}

impl AssignmentOfferedEffectFact {
    fn from_assignment_offer(
        assignment: &RegisteredAgentAssignment,
    ) -> Result<Self, EffectFactOutboxError> {
        if assignment.origin() != forge_domain::AgentAssignmentOrigin::CoordinatorOffer {
            return Err(EffectFactOutboxError::ContinuationAdmissionFactRequired);
        }
        if assignment.state() != forge_domain::AgentAssignmentState::Offered {
            return Err(EffectFactOutboxError::AssignmentNotOffered);
        }
        Ok(Self {
            assignment_id: assignment.id(),
            workspace_id: assignment.workspace_id(),
            activity_id: assignment.activity_id(),
            goal_id: assignment.goal_id(),
            node_id: assignment.node_id(),
            target_agent_id: assignment.target().agent_id(),
            target_session_id: Some(assignment.target().session_id()),
            credit_budget: assignment.credit_budget(),
            offered_at: assignment.updated_at(),
        })
    }

    pub const fn assignment_id(self) -> AgentAssignmentId {
        self.assignment_id
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

    pub const fn node_id(self) -> DagNodeId {
        self.node_id
    }

    pub const fn target_agent_id(self) -> AgentInstanceId {
        self.target_agent_id
    }

    pub const fn target_session_id(self) -> Option<AgentSessionId> {
        self.target_session_id
    }

    pub const fn credit_budget(self) -> Option<WorkCreditBudget> {
        self.credit_budget
    }

    pub const fn offered_at(self) -> TimestampMillis {
        self.offered_at
    }
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectFactOutboxEntry {
    sequence: u64,
    migration_id: Uuid,
    destination_id: Uuid,
    workspace_id: WorkspaceId,
    fact: EffectFact,
    submitted_source_refs: Option<Box<[AssignmentSubmittedSourceRef]>>,
}

impl EffectFactOutboxEntry {
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub const fn migration_id(&self) -> Uuid {
        self.migration_id
    }

    pub const fn destination_id(&self) -> Uuid {
        self.destination_id
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn fact(&self) -> &EffectFact {
        &self.fact
    }

    pub fn submitted_source_refs(&self) -> Option<&[AssignmentSubmittedSourceRef]> {
        self.submitted_source_refs.as_deref()
    }
}

/// Schema objects present since the effect-fact outbox was introduced (v40).
pub(crate) fn base_schema_objects() -> [(&'static str, &'static str); 3] {
    BASE_OBJECTS
}

/// Schema objects added by the `ChangeSet` terminal fact (v41).
pub(crate) fn change_set_schema_objects() -> [(&'static str, &'static str); 1] {
    CHANGE_SET_OBJECTS
}

/// Schema objects added by the assignment-review fact (v42).
pub(crate) fn work_credit_schema_objects() -> [(&'static str, &'static str); 1] {
    WORK_CREDIT_OBJECTS
}

/// Schema objects added by the assignment-offer fact (v43).
pub(crate) fn assignment_offered_schema_objects() -> [(&'static str, &'static str); 1] {
    ASSIGNMENT_OFFERED_OBJECTS
}

pub(crate) fn assignment_submitted_schema_objects() -> [(&'static str, &'static str); 2] {
    [
        ("table", "effect_fact_outbox_assignment_submitted"),
        (
            "table",
            "effect_fact_outbox_assignment_submitted_source_ref",
        ),
    ]
}

pub(crate) fn assignment_submitted_schema_objects_pre_source_refs()
-> [(&'static str, &'static str); 1] {
    [("table", "effect_fact_outbox_assignment_submitted")]
}

pub(crate) fn create_assignment_submitted_schema(
    connection: &Connection,
) -> Result<(), EffectFactOutboxError> {
    connection.execute_batch(assignment_submitted::SCHEMA_SQL)?;
    connection.execute_batch(assignment_submitted::SOURCE_REFS_SQL)?;
    Ok(())
}

pub(crate) fn add_assignment_submitted_source_refs(
    connection: &Connection,
) -> Result<(), EffectFactOutboxError> {
    assignment_submitted::add_source_refs_schema(connection)?;
    Ok(())
}

pub(crate) fn create_schema(connection: &Connection) -> Result<(), EffectFactOutboxError> {
    connection.execute_batch(ENTRIES_SQL)?;
    connection.execute_batch(EXECUTION_TERMINAL_SQL)?;
    create_change_set_schema(connection)?;
    create_work_credit_schema(connection)?;
    create_assignment_offered_schema(connection)?;
    create_assignment_submitted_schema(connection)?;
    connection.execute_batch(WORKSPACE_SEQUENCE_INDEX_SQL)?;
    Ok(())
}

pub(crate) fn create_change_set_schema(
    connection: &Connection,
) -> Result<(), EffectFactOutboxError> {
    connection.execute_batch(CHANGE_SET_TERMINAL_SQL)?;
    Ok(())
}

pub(crate) fn create_work_credit_schema(
    connection: &Connection,
) -> Result<(), EffectFactOutboxError> {
    connection.execute_batch(ASSIGNMENT_REVIEWED_SQL)?;
    Ok(())
}

pub(crate) fn create_assignment_offered_schema(
    connection: &Connection,
) -> Result<(), EffectFactOutboxError> {
    connection.execute_batch(ASSIGNMENT_OFFERED_SQL)?;
    Ok(())
}

pub(crate) fn validate_schema(connection: &Connection) -> Result<(), EffectFactOutboxError> {
    validate_objects(connection, &OBJECTS)
}

/// Exact v43 objects, before the additive submitted-fact payload. The
/// change-set payload table still predates the producer columns here.
pub(crate) fn validate_assignment_offered_schema(
    connection: &Connection,
) -> Result<(), EffectFactOutboxError> {
    validate_objects(
        connection,
        &[
            ("table", "effect_fact_outbox_entries", ENTRIES_SQL),
            (
                "table",
                "effect_fact_outbox_execution_terminal",
                EXECUTION_TERMINAL_SQL,
            ),
            (
                "table",
                "effect_fact_outbox_change_set",
                change_set_terminal_sql_pre_producer().as_str(),
            ),
            (
                "table",
                "effect_fact_outbox_assignment_review",
                ASSIGNMENT_REVIEWED_SQL,
            ),
            (
                "table",
                "effect_fact_outbox_assignment_offered",
                ASSIGNMENT_OFFERED_SQL,
            ),
            (
                "index",
                "effect_fact_outbox_workspace_sequence_idx",
                WORKSPACE_SEQUENCE_INDEX_SQL,
            ),
        ],
    )
}

pub(crate) fn validate_base_schema(connection: &Connection) -> Result<(), EffectFactOutboxError> {
    validate_objects(
        connection,
        &[
            ("table", "effect_fact_outbox_entries", ENTRIES_SQL),
            (
                "table",
                "effect_fact_outbox_execution_terminal",
                EXECUTION_TERMINAL_SQL,
            ),
            (
                "index",
                "effect_fact_outbox_workspace_sequence_idx",
                WORKSPACE_SEQUENCE_INDEX_SQL,
            ),
        ],
    )
}

pub(crate) fn validate_change_set_schema(
    connection: &Connection,
) -> Result<(), EffectFactOutboxError> {
    validate_objects(
        connection,
        &[
            ("table", "effect_fact_outbox_entries", ENTRIES_SQL),
            (
                "table",
                "effect_fact_outbox_execution_terminal",
                EXECUTION_TERMINAL_SQL,
            ),
            (
                "table",
                "effect_fact_outbox_change_set",
                change_set_terminal_sql_pre_producer().as_str(),
            ),
            (
                "index",
                "effect_fact_outbox_workspace_sequence_idx",
                WORKSPACE_SEQUENCE_INDEX_SQL,
            ),
        ],
    )
}

/// Exact v42 shape: the outbox predates the assignment-offered payload table.
pub(crate) fn validate_work_credit_schema(
    connection: &Connection,
) -> Result<(), EffectFactOutboxError> {
    validate_objects(
        connection,
        &[
            ("table", "effect_fact_outbox_entries", ENTRIES_SQL),
            (
                "table",
                "effect_fact_outbox_execution_terminal",
                EXECUTION_TERMINAL_SQL,
            ),
            (
                "table",
                "effect_fact_outbox_change_set",
                change_set_terminal_sql_pre_producer().as_str(),
            ),
            (
                "table",
                "effect_fact_outbox_assignment_review",
                ASSIGNMENT_REVIEWED_SQL,
            ),
            (
                "index",
                "effect_fact_outbox_workspace_sequence_idx",
                WORKSPACE_SEQUENCE_INDEX_SQL,
            ),
        ],
    )
}

/// Exact pre-v47 shape: every payload table exists but the assignment-submitted
/// table predates the source-ref marker and child table.
pub(crate) fn validate_schema_pre_producer(
    connection: &Connection,
) -> Result<(), EffectFactOutboxError> {
    validate_objects(
        connection,
        &[
            ("table", "effect_fact_outbox_entries", ENTRIES_SQL),
            (
                "table",
                "effect_fact_outbox_execution_terminal",
                EXECUTION_TERMINAL_SQL,
            ),
            (
                "table",
                "effect_fact_outbox_change_set",
                change_set_terminal_sql_pre_producer().as_str(),
            ),
            (
                "table",
                "effect_fact_outbox_assignment_review",
                ASSIGNMENT_REVIEWED_SQL,
            ),
            (
                "table",
                "effect_fact_outbox_assignment_offered",
                ASSIGNMENT_OFFERED_SQL,
            ),
            (
                "table",
                "effect_fact_outbox_assignment_submitted",
                assignment_submitted::schema_sql_pre_source_refs().as_str(),
            ),
            (
                "index",
                "effect_fact_outbox_workspace_sequence_idx",
                WORKSPACE_SEQUENCE_INDEX_SQL,
            ),
        ],
    )
}

/// Exact v46/v47 shape: the `ChangeSet` table has producer attribution, while
/// submitted facts still have no source-ref marker or child table.
pub(crate) fn validate_schema_pre_source_refs(
    connection: &Connection,
) -> Result<(), EffectFactOutboxError> {
    validate_objects(
        connection,
        &[
            ("table", "effect_fact_outbox_entries", ENTRIES_SQL),
            (
                "table",
                "effect_fact_outbox_execution_terminal",
                EXECUTION_TERMINAL_SQL,
            ),
            (
                "table",
                "effect_fact_outbox_change_set",
                CHANGE_SET_TERMINAL_SQL,
            ),
            (
                "table",
                "effect_fact_outbox_assignment_review",
                ASSIGNMENT_REVIEWED_SQL,
            ),
            (
                "table",
                "effect_fact_outbox_assignment_offered",
                ASSIGNMENT_OFFERED_SQL,
            ),
            (
                "table",
                "effect_fact_outbox_assignment_submitted",
                assignment_submitted::schema_sql_pre_source_refs().as_str(),
            ),
            (
                "index",
                "effect_fact_outbox_workspace_sequence_idx",
                WORKSPACE_SEQUENCE_INDEX_SQL,
            ),
        ],
    )
}

fn validate_objects<S: AsRef<str>>(
    connection: &Connection,
    expected: &[(&'static str, &'static str, S)],
) -> Result<(), EffectFactOutboxError> {
    for &(kind, name, ref expected_sql) in expected {
        let expected_sql = expected_sql.as_ref();
        let length: Option<i64> = connection
            .query_row(
                "SELECT length(CAST(sql AS BLOB)) FROM sqlite_schema WHERE type=?1 AND name=?2",
                params![kind, name],
                |row| row.get(0),
            )
            .optional()?;
        let Some(length) = length else {
            return Err(EffectFactOutboxError::DamagedSchema(name));
        };
        if !(0..=MAX_SCHEMA_SQL_BYTES).contains(&length) {
            return Err(EffectFactOutboxError::SchemaSqlTooLarge {
                object: name,
                actual: length,
                maximum: MAX_SCHEMA_SQL_BYTES,
            });
        }
        let actual: String = connection.query_row(
            "SELECT substr(sql,1,?3) FROM sqlite_schema WHERE type=?1 AND name=?2",
            params![kind, name, MAX_SCHEMA_SQL_BYTES],
            |row| row.get(0),
        )?;
        if normalize_sql(&actual) != normalize_sql(expected_sql) {
            return Err(EffectFactOutboxError::DamagedSchema(name));
        }
    }
    Ok(())
}

pub(crate) fn append_execution_terminal(
    connection: &Connection,
    execution: &RegisteredExecution,
    verification: Option<&VerificationRun>,
) -> Result<(), EffectFactOutboxError> {
    if connection.is_autocommit() {
        return Err(EffectFactOutboxError::MissingTransaction);
    }
    let Some(fact) = ExecutionTerminalEffectFact::from_execution(execution, verification)? else {
        return Ok(());
    };
    if let Some(run) = verification
        && (run.execution_id() != execution.id() || run.workspace_id() != execution.workspace_id())
    {
        return Err(EffectFactOutboxError::VerificationIdentityConflict);
    }
    let Some(delegation) = source_delegation(connection, execution.workspace_id())? else {
        return Ok(());
    };

    if let Some(existing_sequence) = connection
        .query_row(
            "SELECT outbox_sequence FROM effect_fact_outbox_execution_terminal WHERE execution_id=?1",
            params![execution.id().into_uuid().as_bytes()],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
    {
        let existing = load_entry(connection, existing_sequence)?;
        let expected = EffectFactOutboxEntry {
            sequence: u64::try_from(existing_sequence)
                .map_err(|_| EffectFactOutboxError::CorruptRecord("effect_fact.sequence"))?,
            migration_id: delegation.migration_id(),
            destination_id: delegation.destination_id(),
            workspace_id: delegation.workspace_id(),
            fact: EffectFact::ExecutionTerminal(Box::new(fact)),
            submitted_source_refs: None,
        };
        return if existing == expected {
            Ok(())
        } else {
            Err(EffectFactOutboxError::ReplayConflict)
        };
    }

    connection.execute(
        "INSERT INTO effect_fact_outbox_entries(migration_id,destination_id,workspace_id,fact_kind) VALUES(?1,?2,?3,?4)",
        params![
            delegation.migration_id().as_bytes(),
            delegation.destination_id().as_bytes(),
            delegation.workspace_id().into_uuid().as_bytes(),
            EXECUTION_TERMINAL_KIND,
        ],
    )?;
    let sequence = connection.last_insert_rowid();
    let verification = fact.verification();
    connection.execute(
        "INSERT INTO effect_fact_outbox_execution_terminal(outbox_sequence,execution_id,activity_id,execution_revision,execution_state,observed_at_ms,agent_id,agent_revision,session_id,goal_id,goal_revision,dag_revision,node_id,node_revision,verification_input_id,verification_input_fingerprint,verification_disposition,verification_output_integrity,verification_output_fingerprint) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19)",
        params![
            sequence,
            fact.execution_id().into_uuid().as_bytes(),
            fact.activity_id().into_uuid().as_bytes(),
            fact.execution_revision().get(),
            encode_execution_state(fact.state())?,
            fact.observed_at().get(),
            fact.agent_id().into_uuid().as_bytes(),
            fact.agent_revision().get(),
            fact.session_id().map(|id| id.into_uuid().as_bytes().to_vec()),
            fact.goal_id().into_uuid().as_bytes(),
            fact.goal_revision().get(),
            fact.dag_revision().get(),
            fact.node_id().into_uuid().as_bytes(),
            fact.node_revision().get(),
            verification.map(|value| value.input_id().into_uuid().as_bytes().to_vec()),
            verification.map(|value| value.input_fingerprint().as_bytes().to_vec()),
            verification.map(|value| encode_disposition(value.disposition())),
            verification.and_then(|value| value.output_integrity().map(encode_integrity)),
            verification.and_then(|value| value.output_fingerprint().map(|fingerprint| fingerprint.as_bytes().to_vec())),
        ],
    )?;
    Ok(())
}

pub(crate) fn append_change_set_terminal(
    connection: &Connection,
    change_set: &RegisteredChangeSet,
    diff: &RegisteredDiffEvidence,
    producer: ChangeSetProducer,
) -> Result<(), EffectFactOutboxError> {
    if connection.is_autocommit() {
        return Err(EffectFactOutboxError::MissingTransaction);
    }
    let fact = ChangeSetTerminalEffectFact::from_change_set(change_set, diff, producer)?;
    let Some(delegation) = source_delegation(connection, change_set.workspace_id())? else {
        return Ok(());
    };

    if let Some(existing_sequence) = connection
        .query_row(
            "SELECT outbox_sequence FROM effect_fact_outbox_change_set WHERE change_set_id=?1",
            params![fact.change_set_id().into_uuid().as_bytes()],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
    {
        let existing = load_entry(connection, existing_sequence)?;
        let expected = EffectFactOutboxEntry {
            sequence: u64::try_from(existing_sequence)
                .map_err(|_| EffectFactOutboxError::CorruptRecord("effect_fact.sequence"))?,
            migration_id: delegation.migration_id(),
            destination_id: delegation.destination_id(),
            workspace_id: delegation.workspace_id(),
            fact: EffectFact::ChangeSetTerminal(Box::new(fact)),
            submitted_source_refs: None,
        };
        return if existing == expected {
            Ok(())
        } else {
            Err(EffectFactOutboxError::ReplayConflict)
        };
    }

    connection.execute(
        "INSERT INTO effect_fact_outbox_entries(migration_id,destination_id,workspace_id,fact_kind) VALUES(?1,?2,?3,?4)",
        params![
            delegation.migration_id().as_bytes(),
            delegation.destination_id().as_bytes(),
            delegation.workspace_id().into_uuid().as_bytes(),
            CHANGE_SET_TERMINAL_KIND,
        ],
    )?;
    let sequence = connection.last_insert_rowid();
    connection.execute(
        "INSERT INTO effect_fact_outbox_change_set(outbox_sequence,migration_id,destination_id,workspace_id,activity_id,change_set_id,change_set_revision,change_set_state,failure_code,diff_id,diff_state,diff_revision,workspace_revision,runtime_instance_id,activity_lease_revision,observed_at_ms,producer_agent_id,producer_session_id) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18)",
        params![
            sequence,
            delegation.migration_id().as_bytes(),
            delegation.destination_id().as_bytes(),
            fact.workspace_id().into_uuid().as_bytes(),
            fact.activity_id().into_uuid().as_bytes(),
            fact.change_set_id().into_uuid().as_bytes(),
            fact.change_set_revision().get(),
            encode_change_set_state(fact.state())?,
            fact.failure_code().map(encode_failure_code),
            fact.diff_id().into_uuid().as_bytes(),
            encode_diff_state(fact.diff_state())?,
            fact.diff_revision().get(),
            fact.workspace_revision().get(),
            Some(fact.runtime_instance_id().into_uuid().as_bytes().to_vec()),
            Some(fact.activity_lease_revision().get()),
            fact.observed_at().get(),
            fact.producer_agent_id().map(|id| id.into_uuid().as_bytes().to_vec()),
            fact.producer_session_id().map(|id| id.into_uuid().as_bytes().to_vec()),
        ],
    )?;
    Ok(())
}

pub(crate) fn append_assignment_reviewed(
    connection: &Connection,
    assignment: &RegisteredAgentAssignment,
) -> Result<(), EffectFactOutboxError> {
    if connection.is_autocommit() {
        return Err(EffectFactOutboxError::MissingTransaction);
    }
    let fact = AssignmentReviewedEffectFact::from_assignment_review(assignment)?;
    let Some(delegation) = source_delegation(connection, fact.workspace_id())? else {
        return Ok(());
    };

    if let Some(existing_sequence) = connection
        .query_row(
            "SELECT outbox_sequence FROM effect_fact_outbox_assignment_review WHERE assignment_id=?1",
            params![fact.assignment_id().into_uuid().as_bytes()],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
    {
        let existing = load_entry(connection, existing_sequence)?;
        let expected = EffectFactOutboxEntry {
            sequence: u64::try_from(existing_sequence)
                .map_err(|_| EffectFactOutboxError::CorruptRecord("effect_fact.sequence"))?,
            migration_id: delegation.migration_id(),
            destination_id: delegation.destination_id(),
            workspace_id: delegation.workspace_id(),
            fact: EffectFact::AssignmentReviewed(Box::new(fact)),
            submitted_source_refs: None,
        };
        return if existing == expected {
            Ok(())
        } else {
            Err(EffectFactOutboxError::ReplayConflict)
        };
    }

    connection.execute(
        "INSERT INTO effect_fact_outbox_entries(migration_id,destination_id,workspace_id,fact_kind) VALUES(?1,?2,?3,?4)",
        params![
            delegation.migration_id().as_bytes(),
            delegation.destination_id().as_bytes(),
            delegation.workspace_id().into_uuid().as_bytes(),
            ASSIGNMENT_REVIEWED_KIND,
        ],
    )?;
    let sequence = connection.last_insert_rowid();
    connection.execute(
        "INSERT INTO effect_fact_outbox_assignment_review(outbox_sequence,migration_id,destination_id,workspace_id,activity_id,assignment_id,goal_id,node_id,target_agent_id,target_session_id,outcome,credit_budget,reviewer_agent_id,reviewer_session_id,result_digest,observed_at_ms) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)",
        params![
            sequence,
            delegation.migration_id().as_bytes(),
            delegation.destination_id().as_bytes(),
            fact.workspace_id().into_uuid().as_bytes(),
            fact.activity_id().into_uuid().as_bytes(),
            fact.assignment_id().into_uuid().as_bytes(),
            fact.goal_id().into_uuid().as_bytes(),
            fact.node_id().into_uuid().as_bytes(),
            fact.target_agent_id().into_uuid().as_bytes(),
            fact.target_session_id().map(|id| id.into_uuid().as_bytes().to_vec()),
            encode_assignment_reviewed_outcome(fact.outcome()),
            fact.credit_budget().map(WorkCreditBudget::value),
            fact.reviewer_agent_id().into_uuid().as_bytes(),
            fact.reviewer_session_id().map(|id| id.into_uuid().as_bytes().to_vec()),
            fact.result_digest().map(|digest| digest.to_vec()),
            fact.observed_at().get(),
        ],
    )?;
    Ok(())
}

pub(crate) fn append_assignment_offered(
    connection: &Connection,
    assignment: &RegisteredAgentAssignment,
) -> Result<(), EffectFactOutboxError> {
    if connection.is_autocommit() {
        return Err(EffectFactOutboxError::MissingTransaction);
    }
    let fact = AssignmentOfferedEffectFact::from_assignment_offer(assignment)?;
    let Some(delegation) = source_delegation(connection, fact.workspace_id())? else {
        return Ok(());
    };

    if let Some(existing_sequence) = connection
        .query_row(
            "SELECT outbox_sequence FROM effect_fact_outbox_assignment_offered WHERE assignment_id=?1",
            params![fact.assignment_id().into_uuid().as_bytes()],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
    {
        let existing = load_entry(connection, existing_sequence)?;
        let expected = EffectFactOutboxEntry {
            sequence: u64::try_from(existing_sequence)
                .map_err(|_| EffectFactOutboxError::CorruptRecord("effect_fact.sequence"))?,
            migration_id: delegation.migration_id(),
            destination_id: delegation.destination_id(),
            workspace_id: delegation.workspace_id(),
            fact: EffectFact::AssignmentOffered(Box::new(fact)),
            submitted_source_refs: None,
        };
        return if existing == expected {
            Ok(())
        } else {
            Err(EffectFactOutboxError::ReplayConflict)
        };
    }

    connection.execute(
        "INSERT INTO effect_fact_outbox_entries(migration_id,destination_id,workspace_id,fact_kind) VALUES(?1,?2,?3,?4)",
        params![
            delegation.migration_id().as_bytes(),
            delegation.destination_id().as_bytes(),
            delegation.workspace_id().into_uuid().as_bytes(),
            ASSIGNMENT_OFFERED_KIND,
        ],
    )?;
    let sequence = connection.last_insert_rowid();
    connection.execute(
        "INSERT INTO effect_fact_outbox_assignment_offered(outbox_sequence,migration_id,destination_id,workspace_id,activity_id,assignment_id,goal_id,node_id,target_agent_id,target_session_id,credit_budget,offered_at_ms) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
        params![
            sequence,
            delegation.migration_id().as_bytes(),
            delegation.destination_id().as_bytes(),
            fact.workspace_id().into_uuid().as_bytes(),
            fact.activity_id().into_uuid().as_bytes(),
            fact.assignment_id().into_uuid().as_bytes(),
            fact.goal_id().into_uuid().as_bytes(),
            fact.node_id().into_uuid().as_bytes(),
            fact.target_agent_id().into_uuid().as_bytes(),
            fact.target_session_id().map(|id| id.into_uuid().as_bytes().to_vec()),
            fact.credit_budget().map(WorkCreditBudget::value),
            fact.offered_at().get(),
        ],
    )?;
    Ok(())
}

pub(crate) fn read(
    connection: &Connection,
    workspace_id: WorkspaceId,
    after: u64,
    limit: u32,
) -> Result<Vec<EffectFactOutboxEntry>, EffectFactOutboxError> {
    if limit == 0 || limit > MAX_PAGE_SIZE {
        return Err(EffectFactOutboxError::InvalidLimit { limit });
    }
    let after = i64::try_from(after).map_err(|_| EffectFactOutboxError::InvalidCursor)?;
    let mut statement = connection.prepare(
        "SELECT sequence FROM effect_fact_outbox_entries WHERE workspace_id=?1 AND sequence>?2 ORDER BY sequence ASC LIMIT ?3",
    )?;
    let sequences = statement
        .query_map(
            params![workspace_id.into_uuid().as_bytes(), after, limit],
            |row| row.get::<_, i64>(0),
        )?
        .collect::<Result<Vec<_>, _>>()?;
    sequences
        .into_iter()
        .map(|sequence| load_entry(connection, sequence))
        .collect()
}

fn source_delegation(
    connection: &Connection,
    workspace_id: WorkspaceId,
) -> Result<
    Option<crate::workspace_agent_delegation::AgentOperationsDelegation>,
    EffectFactOutboxError,
> {
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version < crate::workspace_agent_delegation::AGENT_OPERATIONS_DELEGATION_SCHEMA_VERSION {
        return Ok(None);
    }
    crate::workspace_agent_delegation::get(connection, workspace_id).map_err(Into::into)
}

fn load_entry(
    connection: &Connection,
    sequence: i64,
) -> Result<EffectFactOutboxEntry, EffectFactOutboxError> {
    let metadata = connection.query_row(
        "SELECT substr(migration_id,1,17),substr(destination_id,1,17),substr(workspace_id,1,17),fact_kind FROM effect_fact_outbox_entries WHERE sequence=?1",
        params![sequence],
        |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, Vec<u8>>(2)?, row.get::<_, i64>(3)?)),
    )?;
    let migration_id = decode_uuid(&metadata.0, "effect_fact.migration_id")?;
    let destination_id = decode_uuid(&metadata.1, "effect_fact.destination_id")?;
    let workspace_id =
        WorkspaceId::from_uuid(decode_uuid(&metadata.2, "effect_fact.workspace_id")?);
    let fact = match metadata.3 {
        EXECUTION_TERMINAL_KIND => {
            EffectFact::ExecutionTerminal(Box::new(load_execution_terminal(connection, sequence)?))
        }
        CHANGE_SET_TERMINAL_KIND => EffectFact::ChangeSetTerminal(Box::new(
            load_change_set_terminal(connection, sequence, workspace_id)?,
        )),
        ASSIGNMENT_REVIEWED_KIND => EffectFact::AssignmentReviewed(Box::new(
            load_assignment_reviewed(connection, sequence, workspace_id)?,
        )),
        ASSIGNMENT_OFFERED_KIND => EffectFact::AssignmentOffered(Box::new(
            load_assignment_offered(connection, sequence, workspace_id)?,
        )),
        ASSIGNMENT_SUBMITTED_KIND => {
            let (fact, submitted_source_refs) = assignment_submitted::load_with_source_refs(
                connection,
                sequence,
                migration_id,
                destination_id,
                workspace_id,
            )?;
            return Ok(EffectFactOutboxEntry {
                sequence: u64::try_from(sequence)
                    .map_err(|_| EffectFactOutboxError::CorruptRecord("effect_fact.sequence"))?,
                migration_id,
                destination_id,
                workspace_id,
                fact: EffectFact::AssignmentSubmitted(Box::new(fact)),
                submitted_source_refs,
            });
        }
        _ => {
            return Err(EffectFactOutboxError::CorruptRecord(
                "effect_fact.fact_kind",
            ));
        }
    };
    Ok(EffectFactOutboxEntry {
        sequence: u64::try_from(sequence)
            .map_err(|_| EffectFactOutboxError::CorruptRecord("effect_fact.sequence"))?,
        migration_id,
        destination_id,
        workspace_id,
        fact,
        submitted_source_refs: None,
    })
}

fn load_execution_terminal(
    connection: &Connection,
    sequence: i64,
) -> Result<ExecutionTerminalEffectFact, EffectFactOutboxError> {
    let raw = connection.query_row(
        "SELECT substr(execution_id,1,17),substr(activity_id,1,17),execution_revision,execution_state,observed_at_ms,substr(agent_id,1,17),agent_revision,substr(session_id,1,17),substr(goal_id,1,17),goal_revision,dag_revision,substr(node_id,1,17),node_revision,substr(verification_input_id,1,17),substr(verification_input_fingerprint,1,33),verification_disposition,verification_output_integrity,substr(verification_output_fingerprint,1,33) FROM effect_fact_outbox_execution_terminal WHERE outbox_sequence=?1",
        params![sequence],
        |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?, row.get::<_, i64>(4)?, row.get::<_, Vec<u8>>(5)?,
                row.get::<_, i64>(6)?, row.get::<_, Option<Vec<u8>>>(7)?, row.get::<_, Vec<u8>>(8)?,
                row.get::<_, i64>(9)?, row.get::<_, i64>(10)?, row.get::<_, Vec<u8>>(11)?,
                row.get::<_, i64>(12)?, row.get::<_, Option<Vec<u8>>>(13)?, row.get::<_, Option<Vec<u8>>>(14)?,
                row.get::<_, Option<i64>>(15)?, row.get::<_, Option<i64>>(16)?, row.get::<_, Option<Vec<u8>>>(17)?,
            ))
        },
    )?;
    let verification = decode_verification(raw.13, raw.14, raw.15, raw.16, raw.17)?;
    Ok(ExecutionTerminalEffectFact {
        execution_id: ExecutionId::from_uuid(decode_uuid(&raw.0, "effect_fact.execution_id")?),
        activity_id: ActivityId::from_uuid(decode_uuid(&raw.1, "effect_fact.activity_id")?),
        execution_revision: ExecutionRevision::new(raw.2)
            .map_err(|_| EffectFactOutboxError::CorruptRecord("effect_fact.execution_revision"))?,
        state: decode_execution_state(raw.3)?,
        observed_at: TimestampMillis::new(raw.4)
            .map_err(|_| EffectFactOutboxError::CorruptRecord("effect_fact.observed_at"))?,
        agent_id: AgentInstanceId::from_uuid(decode_uuid(&raw.5, "effect_fact.agent_id")?),
        agent_revision: AgentInstanceRevision::new(raw.6)
            .map_err(|_| EffectFactOutboxError::CorruptRecord("effect_fact.agent_revision"))?,
        session_id: raw
            .7
            .map(|value| {
                decode_uuid(&value, "effect_fact.session_id").map(AgentSessionId::from_uuid)
            })
            .transpose()?,
        goal_id: GoalId::from_uuid(decode_uuid(&raw.8, "effect_fact.goal_id")?),
        goal_revision: GoalRevision::new(raw.9)
            .map_err(|_| EffectFactOutboxError::CorruptRecord("effect_fact.goal_revision"))?,
        dag_revision: DagRevisionNumber::new(raw.10)
            .map_err(|_| EffectFactOutboxError::CorruptRecord("effect_fact.dag_revision"))?,
        node_id: DagNodeId::from_uuid(decode_uuid(&raw.11, "effect_fact.node_id")?),
        node_revision: DagNodeRevision::new(raw.12)
            .map_err(|_| EffectFactOutboxError::CorruptRecord("effect_fact.node_revision"))?,
        verification,
    })
}

fn load_change_set_terminal(
    connection: &Connection,
    sequence: i64,
    header_workspace_id: WorkspaceId,
) -> Result<ChangeSetTerminalEffectFact, EffectFactOutboxError> {
    let raw = connection.query_row(
        "SELECT substr(change_set_id,1,17),substr(workspace_id,1,17),substr(activity_id,1,17),change_set_revision,change_set_state,failure_code,substr(diff_id,1,17),diff_state,diff_revision,workspace_revision,substr(runtime_instance_id,1,17),activity_lease_revision,observed_at_ms,substr(producer_agent_id,1,17),substr(producer_session_id,1,17) FROM effect_fact_outbox_change_set WHERE outbox_sequence=?1",
        params![sequence],
        |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)?, row.get::<_, i64>(4)?, row.get::<_, Option<String>>(5)?,
                row.get::<_, Vec<u8>>(6)?, row.get::<_, String>(7)?, row.get::<_, i64>(8)?,
                row.get::<_, i64>(9)?, row.get::<_, Option<Vec<u8>>>(10)?, row.get::<_, Option<i64>>(11)?,
                row.get::<_, i64>(12)?, row.get::<_, Option<Vec<u8>>>(13)?,
                row.get::<_, Option<Vec<u8>>>(14)?,
            ))
        },
    )?;
    let workspace_id = WorkspaceId::from_uuid(decode_uuid(&raw.1, "effect_fact.workspace_id")?);
    if workspace_id != header_workspace_id {
        return Err(EffectFactOutboxError::CorruptRecord(
            "effect_fact.workspace_id",
        ));
    }
    let change_set_revision = ChangeSetRevision::new(raw.3)
        .map_err(|_| EffectFactOutboxError::CorruptRecord("effect_fact.change_set_revision"))?;
    let state = decode_change_set_state(raw.4)?;
    let failure_code = match &raw.5 {
        None if state == ChangeSetState::Applied => None,
        Some(code) if state == ChangeSetState::Failed => Some(decode_failure_code(code)?),
        _ => {
            return Err(EffectFactOutboxError::CorruptRecord(
                "effect_fact.failure_code",
            ));
        }
    };
    Ok(ChangeSetTerminalEffectFact {
        change_set_id: ChangeSetId::from_uuid(decode_uuid(&raw.0, "effect_fact.change_set_id")?),
        workspace_id,
        workspace_revision: WorkspaceRevision::new(raw.9)
            .map_err(|_| EffectFactOutboxError::CorruptRecord("effect_fact.workspace_revision"))?,
        activity_id: ActivityId::from_uuid(decode_uuid(&raw.2, "effect_fact.activity_id")?),
        runtime_instance_id: raw
            .10
            .map(|value| {
                decode_uuid(&value, "effect_fact.runtime_instance_id")
                    .map(RuntimeInstanceId::from_uuid)
            })
            .transpose()?
            .ok_or(EffectFactOutboxError::CorruptRecord(
                "effect_fact.runtime_instance_id",
            ))?,
        activity_lease_revision: raw
            .11
            .map(ActivityLeaseRevision::new)
            .transpose()
            .map_err(|_| {
                EffectFactOutboxError::CorruptRecord("effect_fact.activity_lease_revision")
            })?
            .ok_or(EffectFactOutboxError::CorruptRecord(
                "effect_fact.activity_lease_revision",
            ))?,
        change_set_revision,
        state,
        failure_code,
        diff_id: DiffId::from_uuid(decode_uuid(&raw.6, "effect_fact.diff_id")?),
        diff_state: decode_diff_state(&raw.7)?,
        diff_revision: DiffRevision::new(raw.8)
            .map_err(|_| EffectFactOutboxError::CorruptRecord("effect_fact.diff_revision"))?,
        observed_at: TimestampMillis::new(raw.12)
            .map_err(|_| EffectFactOutboxError::CorruptRecord("effect_fact.observed_at"))?,
        // Pre-v47 payload rows carry no producer attribution; they decode with
        // `None` so reads stay exact and a re-append conflicts instead of
        // fabricating a producer. Post-v47 rows always carry the agent.
        producer_agent_id: raw
            .13
            .map(|value| {
                decode_uuid(&value, "effect_fact.producer_agent_id").map(AgentInstanceId::from_uuid)
            })
            .transpose()?,
        producer_session_id: raw
            .14
            .map(|value| {
                decode_uuid(&value, "effect_fact.producer_session_id")
                    .map(AgentSessionId::from_uuid)
            })
            .transpose()?,
    })
}

fn load_assignment_offered(
    connection: &Connection,
    sequence: i64,
    header_workspace_id: WorkspaceId,
) -> Result<AssignmentOfferedEffectFact, EffectFactOutboxError> {
    let raw = connection.query_row(
        "SELECT substr(assignment_id,1,17),substr(workspace_id,1,17),substr(activity_id,1,17),substr(goal_id,1,17),substr(node_id,1,17),substr(target_agent_id,1,17),substr(target_session_id,1,17),credit_budget,offered_at_ms FROM effect_fact_outbox_assignment_offered WHERE outbox_sequence=?1",
        params![sequence],
        |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?, row.get::<_, Vec<u8>>(4)?, row.get::<_, Vec<u8>>(5)?,
                row.get::<_, Option<Vec<u8>>>(6)?, row.get::<_, Option<i64>>(7)?,
                row.get::<_, i64>(8)?,
            ))
        },
    )?;
    let workspace_id = WorkspaceId::from_uuid(decode_uuid(&raw.1, "effect_fact.workspace_id")?);
    if workspace_id != header_workspace_id {
        return Err(EffectFactOutboxError::CorruptRecord(
            "effect_fact.workspace_id",
        ));
    }
    Ok(AssignmentOfferedEffectFact {
        assignment_id: AgentAssignmentId::from_uuid(decode_uuid(
            &raw.0,
            "effect_fact.assignment_id",
        )?),
        workspace_id,
        activity_id: ActivityId::from_uuid(decode_uuid(&raw.2, "effect_fact.activity_id")?),
        goal_id: GoalId::from_uuid(decode_uuid(&raw.3, "effect_fact.goal_id")?),
        node_id: DagNodeId::from_uuid(decode_uuid(&raw.4, "effect_fact.node_id")?),
        target_agent_id: AgentInstanceId::from_uuid(decode_uuid(
            &raw.5,
            "effect_fact.target_agent_id",
        )?),
        target_session_id: raw
            .6
            .map(|value| {
                decode_uuid(&value, "effect_fact.target_session_id").map(AgentSessionId::from_uuid)
            })
            .transpose()?,
        credit_budget: raw
            .7
            .map(WorkCreditBudget::try_from_i64)
            .transpose()
            .map_err(|_| EffectFactOutboxError::CorruptRecord("effect_fact.credit_budget"))?,
        offered_at: TimestampMillis::new(raw.8)
            .map_err(|_| EffectFactOutboxError::CorruptRecord("effect_fact.offered_at"))?,
    })
}

fn load_assignment_reviewed(
    connection: &Connection,
    sequence: i64,
    header_workspace_id: WorkspaceId,
) -> Result<AssignmentReviewedEffectFact, EffectFactOutboxError> {
    let raw = connection.query_row(
        "SELECT substr(assignment_id,1,17),substr(workspace_id,1,17),substr(activity_id,1,17),substr(goal_id,1,17),substr(node_id,1,17),substr(target_agent_id,1,17),substr(target_session_id,1,17),outcome,credit_budget,substr(reviewer_agent_id,1,17),substr(reviewer_session_id,1,17),substr(result_digest,1,33),observed_at_ms FROM effect_fact_outbox_assignment_review WHERE outbox_sequence=?1",
        params![sequence],
        |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?, row.get::<_, Vec<u8>>(4)?, row.get::<_, Vec<u8>>(5)?,
                row.get::<_, Option<Vec<u8>>>(6)?, row.get::<_, String>(7)?,
                row.get::<_, Option<i64>>(8)?, row.get::<_, Vec<u8>>(9)?,
                row.get::<_, Option<Vec<u8>>>(10)?, row.get::<_, Option<Vec<u8>>>(11)?,
                row.get::<_, i64>(12)?,
            ))
        },
    )?;
    let workspace_id = WorkspaceId::from_uuid(decode_uuid(&raw.1, "effect_fact.workspace_id")?);
    if workspace_id != header_workspace_id {
        return Err(EffectFactOutboxError::CorruptRecord(
            "effect_fact.workspace_id",
        ));
    }
    Ok(AssignmentReviewedEffectFact {
        assignment_id: AgentAssignmentId::from_uuid(decode_uuid(
            &raw.0,
            "effect_fact.assignment_id",
        )?),
        workspace_id,
        activity_id: ActivityId::from_uuid(decode_uuid(&raw.2, "effect_fact.activity_id")?),
        goal_id: GoalId::from_uuid(decode_uuid(&raw.3, "effect_fact.goal_id")?),
        node_id: DagNodeId::from_uuid(decode_uuid(&raw.4, "effect_fact.node_id")?),
        target_agent_id: AgentInstanceId::from_uuid(decode_uuid(
            &raw.5,
            "effect_fact.target_agent_id",
        )?),
        target_session_id: raw
            .6
            .map(|value| {
                decode_uuid(&value, "effect_fact.target_session_id").map(AgentSessionId::from_uuid)
            })
            .transpose()?,
        outcome: decode_assignment_reviewed_outcome(&raw.7)?,
        credit_budget: raw
            .8
            .map(WorkCreditBudget::try_from_i64)
            .transpose()
            .map_err(|_| EffectFactOutboxError::CorruptRecord("effect_fact.credit_budget"))?,
        reviewer_agent_id: AgentInstanceId::from_uuid(decode_uuid(
            &raw.9,
            "effect_fact.reviewer_agent_id",
        )?),
        reviewer_session_id: raw
            .10
            .map(|value| {
                decode_uuid(&value, "effect_fact.reviewer_session_id")
                    .map(AgentSessionId::from_uuid)
            })
            .transpose()?,
        result_digest: raw
            .11
            .map(|value| decode_digest(value, "effect_fact.result_digest"))
            .transpose()?,
        observed_at: TimestampMillis::new(raw.12)
            .map_err(|_| EffectFactOutboxError::CorruptRecord("effect_fact.observed_at"))?,
    })
}

fn decode_verification(
    input_id: Option<Vec<u8>>,
    input_fingerprint: Option<Vec<u8>>,
    disposition: Option<i64>,
    output_integrity: Option<i64>,
    output_fingerprint: Option<Vec<u8>>,
) -> Result<Option<EffectFactVerificationEvidence>, EffectFactOutboxError> {
    let Some(input_id) = input_id else {
        if input_fingerprint.is_some()
            || disposition.is_some()
            || output_integrity.is_some()
            || output_fingerprint.is_some()
        {
            return Err(EffectFactOutboxError::CorruptRecord(
                "effect_fact.verification",
            ));
        }
        return Ok(None);
    };
    let input_fingerprint = decode_digest(
        input_fingerprint.ok_or(EffectFactOutboxError::CorruptRecord(
            "effect_fact.verification_input_fingerprint",
        ))?,
        "effect_fact.verification_input_fingerprint",
    )?;
    let disposition = decode_disposition(disposition.ok_or(
        EffectFactOutboxError::CorruptRecord("effect_fact.verification_disposition"),
    )?)?;
    let output_integrity = output_integrity.map(decode_integrity).transpose()?;
    let output_fingerprint = output_fingerprint
        .map(|value| {
            decode_digest(value, "effect_fact.verification_output_fingerprint")
                .map(VerificationOutputFingerprint::from_bytes)
        })
        .transpose()?;
    Ok(Some(EffectFactVerificationEvidence {
        input_id: VerificationInputId::from_uuid(decode_uuid(
            &input_id,
            "effect_fact.verification_input_id",
        )?),
        input_fingerprint: VerificationInputFingerprint::from_bytes(input_fingerprint),
        disposition,
        output_integrity,
        output_fingerprint,
    }))
}

fn encode_execution_state(state: ExecutionState) -> Result<i64, EffectFactOutboxError> {
    match state {
        ExecutionState::Completed => Ok(2),
        ExecutionState::Failed => Ok(3),
        ExecutionState::TimedOut => Ok(4),
        ExecutionState::Cancelled => Ok(5),
        ExecutionState::Interrupted => Ok(6),
        ExecutionState::Starting | ExecutionState::Running => {
            Err(EffectFactOutboxError::ExecutionNotTerminal)
        }
    }
}

fn decode_execution_state(value: i64) -> Result<ExecutionState, EffectFactOutboxError> {
    match value {
        2 => Ok(ExecutionState::Completed),
        3 => Ok(ExecutionState::Failed),
        4 => Ok(ExecutionState::TimedOut),
        5 => Ok(ExecutionState::Cancelled),
        6 => Ok(ExecutionState::Interrupted),
        _ => Err(EffectFactOutboxError::CorruptRecord(
            "effect_fact.execution_state",
        )),
    }
}

const fn encode_disposition(value: VerificationRunDisposition) -> i64 {
    match value {
        VerificationRunDisposition::Accepted => 0,
        VerificationRunDisposition::Rejected => 1,
        VerificationRunDisposition::Incomplete => 2,
        VerificationRunDisposition::RecoveryRequired => 3,
    }
}

fn decode_disposition(value: i64) -> Result<VerificationRunDisposition, EffectFactOutboxError> {
    match value {
        0 => Ok(VerificationRunDisposition::Accepted),
        1 => Ok(VerificationRunDisposition::Rejected),
        2 => Ok(VerificationRunDisposition::Incomplete),
        3 => Ok(VerificationRunDisposition::RecoveryRequired),
        _ => Err(EffectFactOutboxError::CorruptRecord(
            "effect_fact.verification_disposition",
        )),
    }
}

const fn encode_integrity(value: VerificationOutputIntegrity) -> i64 {
    match value {
        VerificationOutputIntegrity::Complete => 0,
        VerificationOutputIntegrity::Gapped => 1,
        VerificationOutputIntegrity::Truncated => 2,
        VerificationOutputIntegrity::GappedAndTruncated => 3,
    }
}

fn decode_integrity(value: i64) -> Result<VerificationOutputIntegrity, EffectFactOutboxError> {
    match value {
        0 => Ok(VerificationOutputIntegrity::Complete),
        1 => Ok(VerificationOutputIntegrity::Gapped),
        2 => Ok(VerificationOutputIntegrity::Truncated),
        3 => Ok(VerificationOutputIntegrity::GappedAndTruncated),
        _ => Err(EffectFactOutboxError::CorruptRecord(
            "effect_fact.verification_output_integrity",
        )),
    }
}

const fn encode_change_set_state(state: ChangeSetState) -> Result<i64, EffectFactOutboxError> {
    match state {
        ChangeSetState::Applied => Ok(1),
        ChangeSetState::Failed => Ok(2),
        ChangeSetState::Starting => Err(EffectFactOutboxError::ChangeSetNotTerminal),
    }
}

fn decode_change_set_state(value: i64) -> Result<ChangeSetState, EffectFactOutboxError> {
    match value {
        1 => Ok(ChangeSetState::Applied),
        2 => Ok(ChangeSetState::Failed),
        _ => Err(EffectFactOutboxError::CorruptRecord(
            "effect_fact.change_set_state",
        )),
    }
}

const fn encode_failure_code(value: FileMutationFailureCode) -> &'static str {
    match value {
        FileMutationFailureCode::InvalidPath => "InvalidPath",
        FileMutationFailureCode::ProtectedPath => "ProtectedPath",
        FileMutationFailureCode::PathConflict => "PathConflict",
        FileMutationFailureCode::StaleWrite => "StaleWrite",
        FileMutationFailureCode::CapacityExceeded => "CapacityExceeded",
        FileMutationFailureCode::IoFailure => "IoFailure",
    }
}

fn decode_failure_code(value: &str) -> Result<FileMutationFailureCode, EffectFactOutboxError> {
    match value {
        "InvalidPath" => Ok(FileMutationFailureCode::InvalidPath),
        "ProtectedPath" => Ok(FileMutationFailureCode::ProtectedPath),
        "PathConflict" => Ok(FileMutationFailureCode::PathConflict),
        "StaleWrite" => Ok(FileMutationFailureCode::StaleWrite),
        "CapacityExceeded" => Ok(FileMutationFailureCode::CapacityExceeded),
        "IoFailure" => Ok(FileMutationFailureCode::IoFailure),
        _ => Err(EffectFactOutboxError::CorruptRecord(
            "effect_fact.failure_code",
        )),
    }
}

const fn encode_diff_state(
    value: DiffEvidenceState,
) -> Result<&'static str, EffectFactOutboxError> {
    match value {
        DiffEvidenceState::Ready => Ok("Ready"),
        DiffEvidenceState::SummaryOnly => Ok("SummaryOnly"),
        DiffEvidenceState::Abandoned => Ok("Abandoned"),
        DiffEvidenceState::Intent
        | DiffEvidenceState::PurgePending
        | DiffEvidenceState::Tombstoned => Err(EffectFactOutboxError::DiffNotTerminal),
    }
}

fn decode_diff_state(value: &str) -> Result<DiffEvidenceState, EffectFactOutboxError> {
    match value {
        "Ready" => Ok(DiffEvidenceState::Ready),
        "SummaryOnly" => Ok(DiffEvidenceState::SummaryOnly),
        "Abandoned" => Ok(DiffEvidenceState::Abandoned),
        _ => Err(EffectFactOutboxError::CorruptRecord(
            "effect_fact.diff_state",
        )),
    }
}

const fn encode_assignment_reviewed_outcome(value: AssignmentReviewedOutcome) -> &'static str {
    match value {
        AssignmentReviewedOutcome::Accepted => "Accepted",
        AssignmentReviewedOutcome::Rejected => "Rejected",
    }
}

fn decode_assignment_reviewed_outcome(
    value: &str,
) -> Result<AssignmentReviewedOutcome, EffectFactOutboxError> {
    match value {
        "Accepted" => Ok(AssignmentReviewedOutcome::Accepted),
        "Rejected" => Ok(AssignmentReviewedOutcome::Rejected),
        _ => Err(EffectFactOutboxError::CorruptRecord(
            "effect_fact.assignment_review_outcome",
        )),
    }
}

fn decode_uuid(bytes: &[u8], field: &'static str) -> Result<Uuid, EffectFactOutboxError> {
    if bytes.len() != UUID_BYTES {
        return Err(EffectFactOutboxError::CorruptRecord(field));
    }
    Uuid::from_slice(bytes).map_err(|_| EffectFactOutboxError::CorruptRecord(field))
}

fn decode_digest(
    bytes: Vec<u8>,
    field: &'static str,
) -> Result<[u8; DIGEST_BYTES], EffectFactOutboxError> {
    bytes
        .try_into()
        .map_err(|_| EffectFactOutboxError::CorruptRecord(field))
}

fn normalize_sql(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

#[derive(Debug, Error)]
pub enum EffectFactOutboxError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Delegation(#[from] crate::workspace_agent_delegation::AgentOperationsDelegationError),
    #[error("effect fact append requires the caller-owned source transaction")]
    MissingTransaction,
    #[error("effect fact execution is not terminal")]
    ExecutionNotTerminal,
    #[error("effect fact change set is not terminal")]
    ChangeSetNotTerminal,
    #[error("effect fact assignment has no terminal review")]
    AssignmentNotReviewed,
    #[error("effect fact assignment is not an outstanding offer")]
    AssignmentNotOffered,
    #[error("cut continuation requires its own durable admission fact")]
    ContinuationAdmissionFactRequired,
    #[error("effect fact assignment has no durable submission snapshot")]
    AssignmentNotSubmitted,
    #[error("effect fact diff evidence is not terminal")]
    DiffNotTerminal,
    #[error("effect fact diff identity does not match the terminal change set")]
    DiffIdentityConflict,
    #[error("effect fact verification run is not terminal")]
    VerificationNotTerminal,
    #[error("effect fact verification identity does not match the terminal execution")]
    VerificationIdentityConflict,
    #[error("effect fact retry conflicts with the durable identity")]
    ReplayConflict,
    #[error("effect fact cursor exceeds SQLite range")]
    InvalidCursor,
    #[error("effect fact page limit {limit} is outside 1..={MAX_PAGE_SIZE}")]
    InvalidLimit { limit: u32 },
    #[error("effect fact schema object is damaged: {0}")]
    DamagedSchema(&'static str),
    #[error("effect fact schema object {object} is {actual} bytes; maximum is {maximum}")]
    SchemaSqlTooLarge {
        object: &'static str,
        actual: i64,
        maximum: i64,
    },
    #[error("effect fact record is corrupt: {0}")]
    CorruptRecord(&'static str),
}
