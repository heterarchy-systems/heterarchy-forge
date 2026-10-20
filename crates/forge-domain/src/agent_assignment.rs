//! Durable asynchronous assignment contracts for connected participant Agents.
//!
//! An assignment binds one existing current DAG node to one distinct
//! session-bound Agent. It is deliberately not a Goal, DAG, Activity, or
//! scheduler authority. The persistence boundary owns durable transitions;
//! these types only validate bounded values and deterministic lifecycle facts.

use std::fmt;
use std::str::FromStr;

use thiserror::Error;
use uuid::Uuid;

mod continuation;
mod origin;
pub use continuation::{AgentAssignmentContinuationError, AgentAssignmentContinuationPlan};
pub use origin::{AgentAssignmentContinuationOrigin, AgentAssignmentOrigin};

use crate::{
    ActivityCoordinatorActor, ActivityCoordinatorRevision, AgentInstanceId, AgentInstanceRevision,
    AgentSessionId, AuthenticatedPrincipal, DagHeadRevision, DagNodeId, DagNodeRevision,
    DagRevisionNumber, GitCommitId, GoalEvidenceRef, GoalId, GoalRevision, TimestampMillis,
    WorkspaceId, WorkspaceRootFingerprint,
};

pub const MAX_AGENT_ASSIGNMENT_RESULT_BYTES: usize = 32 * 1024;
pub const MAX_AGENT_ASSIGNMENT_SOURCES: usize = 32;
pub const MAX_AGENT_ASSIGNMENT_SOURCE_URL_BYTES: usize = 2 * 1024;
pub const MAX_AGENT_ASSIGNMENT_SOURCE_BYTES: usize = 8 * 1024;
pub const MAX_AGENT_ASSIGNMENTS_PER_WORKSPACE: usize = 32;

/// Frozen `WorkCredit` budget reserved for one assignment. The budget is chosen
/// before work starts (`OfferAgentAssignment`) and can never be rewritten by a
/// later transition. `None` on an offer marks a credit-ineligible assignment
/// (legacy or undelegated work).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum WorkCreditBudget {
    One,
    Three,
    Five,
}

impl WorkCreditBudget {
    pub const fn value(self) -> i64 {
        match self {
            Self::One => 1,
            Self::Three => 3,
            Self::Five => 5,
        }
    }

    pub fn try_from_i64(value: i64) -> Result<Self, WorkCreditBudgetError> {
        match value {
            1 => Ok(Self::One),
            3 => Ok(Self::Three),
            5 => Ok(Self::Five),
            actual => Err(WorkCreditBudgetError::Invalid { actual }),
        }
    }
}

impl fmt::Display for WorkCreditBudget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::One => "1",
            Self::Three => "3",
            Self::Five => "5",
        })
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum WorkCreditBudgetError {
    #[error("WorkCredit budget must be 1, 3, or 5, got {actual}")]
    Invalid { actual: i64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AgentAssignmentId(Uuid);

impl AgentAssignmentId {
    pub const fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }

    pub const fn into_uuid(self) -> Uuid {
        self.0
    }
}

impl fmt::Display for AgentAssignmentId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for AgentAssignmentId {
    type Err = AgentAssignmentIdParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(value)
            .map(Self)
            .map_err(AgentAssignmentIdParseError::InvalidUuid)
    }
}

#[derive(Debug, Error)]
pub enum AgentAssignmentIdParseError {
    #[error("invalid Agent assignment UUID")]
    InvalidUuid(#[source] uuid::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AgentAssignmentRevision(i64);

impl AgentAssignmentRevision {
    pub const INITIAL: Self = Self(1);

    pub const fn new(value: i64) -> Result<Self, AgentAssignmentRevisionError> {
        if value < 1 {
            Err(AgentAssignmentRevisionError::Invalid { actual: value })
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> i64 {
        self.0
    }

    pub const fn checked_next(self) -> Result<Self, AgentAssignmentRevisionError> {
        match self.0.checked_add(1) {
            Some(value) => Ok(Self(value)),
            None => Err(AgentAssignmentRevisionError::Overflow { current: self.0 }),
        }
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum AgentAssignmentRevisionError {
    #[error("Agent assignment revision must be at least 1, got {actual}")]
    Invalid { actual: i64 },
    #[error("Agent assignment revision overflowed at {current}")]
    Overflow { current: i64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AgentAssignmentState {
    Offered,
    Running,
    Submitted,
    Accepted,
    Rejected,
    Cancelled,
    Interrupted,
}

impl AgentAssignmentState {
    pub const fn is_active(self) -> bool {
        matches!(self, Self::Offered | Self::Running | Self::Submitted)
    }

    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Accepted | Self::Rejected | Self::Cancelled | Self::Interrupted
        )
    }
}

/// A validated bounded HTTP(S) source URL returned by a participant.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AgentAssignmentSourceUrl(String);

impl AgentAssignmentSourceUrl {
    pub fn new(value: String) -> Result<Self, AgentAssignmentSourceError> {
        if value.trim().is_empty() {
            return Err(AgentAssignmentSourceError::EmptyUrl);
        }
        if value.len() > MAX_AGENT_ASSIGNMENT_SOURCE_URL_BYTES {
            return Err(AgentAssignmentSourceError::UrlTooLarge {
                actual: value.len(),
                maximum: MAX_AGENT_ASSIGNMENT_SOURCE_URL_BYTES,
            });
        }
        if !(value.starts_with("http://") || value.starts_with("https://")) {
            return Err(AgentAssignmentSourceError::UnsupportedScheme);
        }
        if value.as_bytes().contains(&0)
            || value
                .chars()
                .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
        {
            return Err(AgentAssignmentSourceError::ControlCharacter);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AgentAssignmentSourceUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AgentAssignmentSourceUrl")
            .field("bytes", &self.0.len())
            .finish()
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AgentAssignmentSourceError {
    #[error("assignment source URL is empty")]
    EmptyUrl,
    #[error("assignment source URL uses an unsupported scheme")]
    UnsupportedScheme,
    #[error("assignment source URL contains a forbidden control character")]
    ControlCharacter,
    #[error("assignment source URL has {actual} bytes; maximum is {maximum}")]
    UrlTooLarge { actual: usize, maximum: usize },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AgentAssignmentSourceRef {
    Url(AgentAssignmentSourceUrl),
    Provenance(GoalEvidenceRef),
}

/// Optional receipt for a provider-owned linked worktree. The receipt carries
/// observations only; persistence never provisions or resolves a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AgentAssignmentWorktreeReceipt {
    root_fingerprint: WorkspaceRootFingerprint,
    repository_fingerprint: WorkspaceRootFingerprint,
    baseline: GitCommitId,
}

impl AgentAssignmentWorktreeReceipt {
    pub const fn new(
        root_fingerprint: WorkspaceRootFingerprint,
        repository_fingerprint: WorkspaceRootFingerprint,
        baseline: GitCommitId,
    ) -> Self {
        Self {
            root_fingerprint,
            repository_fingerprint,
            baseline,
        }
    }

    pub const fn root_fingerprint(self) -> WorkspaceRootFingerprint {
        self.root_fingerprint
    }

    pub const fn repository_fingerprint(self) -> WorkspaceRootFingerprint {
        self.repository_fingerprint
    }

    pub const fn baseline(self) -> GitCommitId {
        self.baseline
    }
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentAssignmentResult {
    report: String,
    sources: Vec<AgentAssignmentSourceRef>,
    worktree: Option<AgentAssignmentWorktreeReceipt>,
}

impl AgentAssignmentResult {
    pub fn new(
        report: String,
        sources: Vec<AgentAssignmentSourceRef>,
        worktree: Option<AgentAssignmentWorktreeReceipt>,
    ) -> Result<Self, AgentAssignmentResultError> {
        if report.trim().is_empty() {
            return Err(AgentAssignmentResultError::EmptyReport);
        }
        if report.len() > MAX_AGENT_ASSIGNMENT_RESULT_BYTES {
            return Err(AgentAssignmentResultError::ReportTooLarge {
                actual: report.len(),
                maximum: MAX_AGENT_ASSIGNMENT_RESULT_BYTES,
            });
        }
        if report.as_bytes().contains(&0)
            || report
                .chars()
                .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
        {
            return Err(AgentAssignmentResultError::ControlCharacter);
        }
        if sources.len() > MAX_AGENT_ASSIGNMENT_SOURCES {
            return Err(AgentAssignmentResultError::TooManySources {
                actual: sources.len(),
                maximum: MAX_AGENT_ASSIGNMENT_SOURCES,
            });
        }
        let source_bytes = sources
            .iter()
            .map(|source| match source {
                AgentAssignmentSourceRef::Url(url) => url.as_str().len(),
                AgentAssignmentSourceRef::Provenance(_) => 16,
            })
            .sum::<usize>();
        if source_bytes > MAX_AGENT_ASSIGNMENT_SOURCE_BYTES {
            return Err(AgentAssignmentResultError::SourcesTooLarge {
                actual: source_bytes,
                maximum: MAX_AGENT_ASSIGNMENT_SOURCE_BYTES,
            });
        }
        Ok(Self {
            report,
            sources,
            worktree,
        })
    }

    pub fn report(&self) -> &str {
        &self.report
    }

    pub fn sources(&self) -> &[AgentAssignmentSourceRef] {
        &self.sources
    }

    pub const fn worktree(&self) -> Option<AgentAssignmentWorktreeReceipt> {
        self.worktree
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AgentAssignmentResultError {
    #[error("assignment result report is empty")]
    EmptyReport,
    #[error("assignment result report has {actual} bytes; maximum is {maximum}")]
    ReportTooLarge { actual: usize, maximum: usize },
    #[error("assignment result report contains a forbidden control character")]
    ControlCharacter,
    #[error("assignment result has {actual} sources; maximum is {maximum}")]
    TooManySources { actual: usize, maximum: usize },
    #[error("assignment sources have {actual} bytes; maximum is {maximum}")]
    SourcesTooLarge { actual: usize, maximum: usize },
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AgentAssignmentTarget {
    agent_id: AgentInstanceId,
    session_id: AgentSessionId,
    principal: AuthenticatedPrincipal,
    agent_revision: AgentInstanceRevision,
}

impl AgentAssignmentTarget {
    pub const fn new(
        agent_id: AgentInstanceId,
        session_id: AgentSessionId,
        principal: AuthenticatedPrincipal,
        agent_revision: AgentInstanceRevision,
    ) -> Self {
        Self {
            agent_id,
            session_id,
            principal,
            agent_revision,
        }
    }

    pub const fn agent_id(self) -> AgentInstanceId {
        self.agent_id
    }

    pub const fn session_id(self) -> AgentSessionId {
        self.session_id
    }

    pub const fn principal(self) -> AuthenticatedPrincipal {
        self.principal
    }

    pub const fn agent_revision(self) -> AgentInstanceRevision {
        self.agent_revision
    }
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AgentAssignmentCoordinator {
    agent_id: AgentInstanceId,
    session_id: AgentSessionId,
    principal: AuthenticatedPrincipal,
    revision: ActivityCoordinatorRevision,
}

impl AgentAssignmentCoordinator {
    pub const fn new(
        agent_id: AgentInstanceId,
        session_id: AgentSessionId,
        principal: AuthenticatedPrincipal,
        revision: ActivityCoordinatorRevision,
    ) -> Self {
        Self {
            agent_id,
            session_id,
            principal,
            revision,
        }
    }

    pub const fn agent_id(self) -> AgentInstanceId {
        self.agent_id
    }

    pub const fn session_id(self) -> AgentSessionId {
        self.session_id
    }

    pub const fn principal(self) -> AuthenticatedPrincipal {
        self.principal
    }

    pub const fn revision(self) -> ActivityCoordinatorRevision {
        self.revision
    }

    pub const fn from_actor(actor: ActivityCoordinatorActor) -> Self {
        Self::new(
            actor.agent_id(),
            actor.session_id(),
            actor.principal(),
            actor.expected_revision(),
        )
    }
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OfferAgentAssignment {
    assignment_id: AgentAssignmentId,
    coordinator: ActivityCoordinatorActor,
    target: AgentAssignmentTarget,
    goal_id: GoalId,
    expected_goal_revision: GoalRevision,
    expected_goal_created_at: TimestampMillis,
    dag_revision: DagRevisionNumber,
    expected_head_revision: DagHeadRevision,
    node_id: DagNodeId,
    expected_node_revision: DagNodeRevision,
    credit_budget: Option<WorkCreditBudget>,
    observed_at: TimestampMillis,
}

impl OfferAgentAssignment {
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        assignment_id: AgentAssignmentId,
        coordinator: ActivityCoordinatorActor,
        target: AgentAssignmentTarget,
        goal_id: GoalId,
        expected_goal_revision: GoalRevision,
        expected_goal_created_at: TimestampMillis,
        dag_revision: DagRevisionNumber,
        expected_head_revision: DagHeadRevision,
        node_id: DagNodeId,
        expected_node_revision: DagNodeRevision,
        credit_budget: Option<WorkCreditBudget>,
        observed_at: TimestampMillis,
    ) -> Self {
        Self {
            assignment_id,
            coordinator,
            target,
            goal_id,
            expected_goal_revision,
            expected_goal_created_at,
            dag_revision,
            expected_head_revision,
            node_id,
            expected_node_revision,
            credit_budget,
            observed_at,
        }
    }

    pub const fn assignment_id(self) -> AgentAssignmentId {
        self.assignment_id
    }

    pub const fn coordinator(self) -> ActivityCoordinatorActor {
        self.coordinator
    }

    pub const fn target(self) -> AgentAssignmentTarget {
        self.target
    }

    pub const fn goal_id(self) -> GoalId {
        self.goal_id
    }

    pub const fn expected_goal_revision(self) -> GoalRevision {
        self.expected_goal_revision
    }

    pub const fn expected_goal_created_at(self) -> TimestampMillis {
        self.expected_goal_created_at
    }

    pub const fn dag_revision(self) -> DagRevisionNumber {
        self.dag_revision
    }

    pub const fn expected_head_revision(self) -> DagHeadRevision {
        self.expected_head_revision
    }

    pub const fn node_id(self) -> DagNodeId {
        self.node_id
    }

    pub const fn expected_node_revision(self) -> DagNodeRevision {
        self.expected_node_revision
    }

    /// Budget frozen before work starts; `None` marks a credit-ineligible
    /// assignment.
    pub const fn credit_budget(self) -> Option<WorkCreditBudget> {
        self.credit_budget
    }

    pub const fn observed_at(self) -> TimestampMillis {
        self.observed_at
    }
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ClaimAgentAssignment {
    assignment_id: AgentAssignmentId,
    target: AgentAssignmentTarget,
    expected_revision: AgentAssignmentRevision,
    observed_at: TimestampMillis,
}

impl ClaimAgentAssignment {
    pub const fn new(
        assignment_id: AgentAssignmentId,
        target: AgentAssignmentTarget,
        expected_revision: AgentAssignmentRevision,
        observed_at: TimestampMillis,
    ) -> Self {
        Self {
            assignment_id,
            target,
            expected_revision,
            observed_at,
        }
    }

    pub const fn assignment_id(self) -> AgentAssignmentId {
        self.assignment_id
    }

    pub const fn target(self) -> AgentAssignmentTarget {
        self.target
    }

    pub const fn expected_revision(self) -> AgentAssignmentRevision {
        self.expected_revision
    }

    pub const fn observed_at(self) -> TimestampMillis {
        self.observed_at
    }
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmitAgentAssignment {
    assignment_id: AgentAssignmentId,
    target: AgentAssignmentTarget,
    expected_revision: AgentAssignmentRevision,
    result: AgentAssignmentResult,
    observed_at: TimestampMillis,
}

impl SubmitAgentAssignment {
    pub const fn new(
        assignment_id: AgentAssignmentId,
        target: AgentAssignmentTarget,
        expected_revision: AgentAssignmentRevision,
        result: AgentAssignmentResult,
        observed_at: TimestampMillis,
    ) -> Self {
        Self {
            assignment_id,
            target,
            expected_revision,
            result,
            observed_at,
        }
    }

    pub const fn assignment_id(&self) -> AgentAssignmentId {
        self.assignment_id
    }

    pub const fn target(&self) -> AgentAssignmentTarget {
        self.target
    }

    pub const fn expected_revision(&self) -> AgentAssignmentRevision {
        self.expected_revision
    }

    pub const fn result(&self) -> &AgentAssignmentResult {
        &self.result
    }

    pub const fn observed_at(&self) -> TimestampMillis {
        self.observed_at
    }
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReviewAgentAssignment {
    assignment_id: AgentAssignmentId,
    coordinator: ActivityCoordinatorActor,
    expected_revision: AgentAssignmentRevision,
    observed_at: TimestampMillis,
}

impl ReviewAgentAssignment {
    pub const fn new(
        assignment_id: AgentAssignmentId,
        coordinator: ActivityCoordinatorActor,
        expected_revision: AgentAssignmentRevision,
        observed_at: TimestampMillis,
    ) -> Self {
        Self {
            assignment_id,
            coordinator,
            expected_revision,
            observed_at,
        }
    }

    pub const fn assignment_id(self) -> AgentAssignmentId {
        self.assignment_id
    }

    pub const fn coordinator(self) -> ActivityCoordinatorActor {
        self.coordinator
    }

    pub const fn expected_revision(self) -> AgentAssignmentRevision {
        self.expected_revision
    }

    pub const fn observed_at(self) -> TimestampMillis {
        self.observed_at
    }
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CancelAgentAssignment {
    assignment_id: AgentAssignmentId,
    coordinator: ActivityCoordinatorActor,
    expected_revision: AgentAssignmentRevision,
    observed_at: TimestampMillis,
}

impl CancelAgentAssignment {
    pub const fn new(
        assignment_id: AgentAssignmentId,
        coordinator: ActivityCoordinatorActor,
        expected_revision: AgentAssignmentRevision,
        observed_at: TimestampMillis,
    ) -> Self {
        Self {
            assignment_id,
            coordinator,
            expected_revision,
            observed_at,
        }
    }

    pub const fn assignment_id(self) -> AgentAssignmentId {
        self.assignment_id
    }

    pub const fn coordinator(self) -> ActivityCoordinatorActor {
        self.coordinator
    }

    pub const fn expected_revision(self) -> AgentAssignmentRevision {
        self.expected_revision
    }

    pub const fn observed_at(self) -> TimestampMillis {
        self.observed_at
    }
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AcknowledgeAgentAssignmentCancellation {
    assignment_id: AgentAssignmentId,
    target: AgentAssignmentTarget,
    expected_revision: AgentAssignmentRevision,
    observed_at: TimestampMillis,
}

impl AcknowledgeAgentAssignmentCancellation {
    pub const fn new(
        assignment_id: AgentAssignmentId,
        target: AgentAssignmentTarget,
        expected_revision: AgentAssignmentRevision,
        observed_at: TimestampMillis,
    ) -> Self {
        Self {
            assignment_id,
            target,
            expected_revision,
            observed_at,
        }
    }

    pub const fn assignment_id(self) -> AgentAssignmentId {
        self.assignment_id
    }

    pub const fn target(self) -> AgentAssignmentTarget {
        self.target
    }

    pub const fn expected_revision(self) -> AgentAssignmentRevision {
        self.expected_revision
    }

    pub const fn observed_at(self) -> TimestampMillis {
        self.observed_at
    }
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InterruptAgentAssignment {
    assignment_id: AgentAssignmentId,
    expected_revision: AgentAssignmentRevision,
    observed_at: TimestampMillis,
}

impl InterruptAgentAssignment {
    pub const fn new(
        assignment_id: AgentAssignmentId,
        expected_revision: AgentAssignmentRevision,
        observed_at: TimestampMillis,
    ) -> Self {
        Self {
            assignment_id,
            expected_revision,
            observed_at,
        }
    }

    pub const fn assignment_id(self) -> AgentAssignmentId {
        self.assignment_id
    }

    pub const fn expected_revision(self) -> AgentAssignmentRevision {
        self.expected_revision
    }

    pub const fn observed_at(self) -> TimestampMillis {
        self.observed_at
    }
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredAgentAssignment {
    id: AgentAssignmentId,
    origin: AgentAssignmentOrigin,
    workspace_id: WorkspaceId,
    activity_id: crate::ActivityId,
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
    result: Option<AgentAssignmentResult>,
    reviewed_by: Option<AgentAssignmentCoordinator>,
    created_at: TimestampMillis,
    updated_at: TimestampMillis,
    revision: AgentAssignmentRevision,
}

/// Bounded metadata projection for listing assignments. Reports, source URLs,
/// and worktree receipts are available only through a single-assignment read.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AgentAssignmentSummary {
    id: AgentAssignmentId,
    origin: AgentAssignmentOrigin,
    workspace_id: WorkspaceId,
    activity_id: crate::ActivityId,
    goal_id: GoalId,
    goal_revision: GoalRevision,
    dag_revision: DagRevisionNumber,
    dag_head_revision: DagHeadRevision,
    node_id: DagNodeId,
    node_revision: DagNodeRevision,
    target_agent_id: AgentInstanceId,
    target_session_id: AgentSessionId,
    state: AgentAssignmentState,
    cancellation_requested: bool,
    has_result: bool,
    source_count: u8,
    created_at: TimestampMillis,
    updated_at: TimestampMillis,
    revision: AgentAssignmentRevision,
}

impl AgentAssignmentSummary {
    #[allow(clippy::too_many_arguments)]
    pub const fn new_for_persistence(
        id: AgentAssignmentId,
        workspace_id: WorkspaceId,
        activity_id: crate::ActivityId,
        goal_id: GoalId,
        goal_revision: GoalRevision,
        dag_revision: DagRevisionNumber,
        dag_head_revision: DagHeadRevision,
        node_id: DagNodeId,
        node_revision: DagNodeRevision,
        target_agent_id: AgentInstanceId,
        target_session_id: AgentSessionId,
        state: AgentAssignmentState,
        cancellation_requested: bool,
        has_result: bool,
        source_count: u8,
        created_at: TimestampMillis,
        updated_at: TimestampMillis,
        revision: AgentAssignmentRevision,
        origin: AgentAssignmentOrigin,
    ) -> Self {
        Self {
            id,
            origin,
            workspace_id,
            activity_id,
            goal_id,
            goal_revision,
            dag_revision,
            dag_head_revision,
            node_id,
            node_revision,
            target_agent_id,
            target_session_id,
            state,
            cancellation_requested,
            has_result,
            source_count,
            created_at,
            updated_at,
            revision,
        }
    }

    pub const fn id(self) -> AgentAssignmentId {
        self.id
    }
    pub const fn origin(self) -> AgentAssignmentOrigin {
        self.origin
    }
    pub const fn workspace_id(self) -> WorkspaceId {
        self.workspace_id
    }
    pub const fn activity_id(self) -> crate::ActivityId {
        self.activity_id
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
    pub const fn dag_head_revision(self) -> DagHeadRevision {
        self.dag_head_revision
    }
    pub const fn node_id(self) -> DagNodeId {
        self.node_id
    }
    pub const fn node_revision(self) -> DagNodeRevision {
        self.node_revision
    }
    pub const fn target_agent_id(self) -> AgentInstanceId {
        self.target_agent_id
    }
    pub const fn target_session_id(self) -> AgentSessionId {
        self.target_session_id
    }
    pub const fn state(self) -> AgentAssignmentState {
        self.state
    }
    pub const fn cancellation_requested(self) -> bool {
        self.cancellation_requested
    }
    pub const fn has_result(self) -> bool {
        self.has_result
    }
    pub const fn source_count(self) -> u8 {
        self.source_count
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
}

impl RegisteredAgentAssignment {
    pub fn summary(&self, source_count: u8) -> AgentAssignmentSummary {
        AgentAssignmentSummary {
            id: self.id,
            origin: self.origin,
            workspace_id: self.workspace_id,
            activity_id: self.activity_id,
            goal_id: self.goal_id,
            goal_revision: self.goal_revision,
            dag_revision: self.dag_revision,
            dag_head_revision: self.dag_head_revision,
            node_id: self.node_id,
            node_revision: self.node_revision,
            target_agent_id: self.target.agent_id,
            target_session_id: self.target.session_id,
            state: self.state,
            cancellation_requested: self.cancellation_requested,
            has_result: self.result.is_some(),
            source_count,
            created_at: self.created_at,
            updated_at: self.updated_at,
            revision: self.revision,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn offered(
        id: AgentAssignmentId,
        workspace_id: WorkspaceId,
        activity_id: crate::ActivityId,
        goal_id: GoalId,
        goal_created_at: TimestampMillis,
        goal_revision: GoalRevision,
        dag_revision: DagRevisionNumber,
        dag_head_revision: DagHeadRevision,
        node_id: DagNodeId,
        node_revision: DagNodeRevision,
        coordinator: AgentAssignmentCoordinator,
        target: AgentAssignmentTarget,
        credit_budget: Option<WorkCreditBudget>,
        observed_at: TimestampMillis,
    ) -> Result<Self, AgentAssignmentTransitionError> {
        let value = Self {
            id,
            origin: AgentAssignmentOrigin::CoordinatorOffer,
            workspace_id,
            activity_id,
            goal_id,
            goal_created_at,
            goal_revision,
            dag_revision,
            dag_head_revision,
            node_id,
            node_revision,
            coordinator,
            target,
            state: AgentAssignmentState::Offered,
            cancellation_requested: false,
            credit_budget,
            result: None,
            reviewed_by: None,
            created_at: observed_at,
            updated_at: observed_at,
            revision: AgentAssignmentRevision::INITIAL,
        };
        value.validate()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        id: AgentAssignmentId,
        workspace_id: WorkspaceId,
        activity_id: crate::ActivityId,
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
        result: Option<AgentAssignmentResult>,
        reviewed_by: Option<AgentAssignmentCoordinator>,
        created_at: TimestampMillis,
        updated_at: TimestampMillis,
        revision: AgentAssignmentRevision,
        origin: AgentAssignmentOrigin,
    ) -> Result<Self, AgentAssignmentTransitionError> {
        let value = Self {
            id,
            origin,
            workspace_id,
            activity_id,
            goal_id,
            goal_created_at,
            goal_revision,
            dag_revision,
            dag_head_revision,
            node_id,
            node_revision,
            coordinator,
            target,
            state,
            cancellation_requested,
            credit_budget,
            result,
            reviewed_by,
            created_at,
            updated_at,
            revision,
        };
        value.validate()
    }

    fn validate(self) -> Result<Self, AgentAssignmentTransitionError> {
        if self.updated_at.get() < self.created_at.get()
            || self.goal_created_at.get() > self.created_at.get()
        {
            return Err(AgentAssignmentTransitionError::TimestampOrder);
        }
        if self.origin == AgentAssignmentOrigin::CoordinatorOffer
            && self.coordinator.agent_id == self.target.agent_id
        {
            return Err(AgentAssignmentTransitionError::CoordinatorTargetSameAgent);
        }
        if let AgentAssignmentOrigin::CutContinuation(origin) = self.origin
            && origin.predecessor_id() == self.id
        {
            return Err(AgentAssignmentTransitionError::InvalidContinuationOrigin);
        }
        if self.state == AgentAssignmentState::Offered
            && (self.revision != AgentAssignmentRevision::INITIAL
                || self.result.is_some()
                || self.reviewed_by.is_some()
                || self.cancellation_requested)
        {
            return Err(AgentAssignmentTransitionError::InvalidProjection);
        }
        if self.state == AgentAssignmentState::Running && self.result.is_some() {
            return Err(AgentAssignmentTransitionError::InvalidProjection);
        }
        if self.state.is_active() == self.state.is_terminal() {
            return Err(AgentAssignmentTransitionError::InvalidProjection);
        }
        if matches!(
            self.state,
            AgentAssignmentState::Submitted
                | AgentAssignmentState::Accepted
                | AgentAssignmentState::Rejected
        ) != self.result.is_some()
        {
            return Err(AgentAssignmentTransitionError::InvalidProjection);
        }
        if matches!(
            self.state,
            AgentAssignmentState::Accepted | AgentAssignmentState::Rejected
        ) != self.reviewed_by.is_some()
        {
            return Err(AgentAssignmentTransitionError::InvalidProjection);
        }
        // `interrupt()` keeps the cancellation flag on the terminal Interrupted
        // state exactly as the durable CHECK constraint allows
        // (cancellation_requested = 1 with state 6).
        if self.cancellation_requested
            && !matches!(
                self.state,
                AgentAssignmentState::Running
                    | AgentAssignmentState::Cancelled
                    | AgentAssignmentState::Interrupted
            )
        {
            return Err(AgentAssignmentTransitionError::InvalidProjection);
        }
        Ok(self)
    }

    fn next(
        &self,
        expected: AgentAssignmentRevision,
        observed_at: TimestampMillis,
    ) -> Result<AgentAssignmentRevision, AgentAssignmentTransitionError> {
        if self.revision != expected {
            return Err(AgentAssignmentTransitionError::RevisionConflict);
        }
        if observed_at.get() < self.updated_at.get() {
            return Err(AgentAssignmentTransitionError::TimestampOrder);
        }
        self.revision
            .checked_next()
            .map_err(AgentAssignmentTransitionError::RevisionOverflow)
    }

    fn ensure_target(
        &self,
        target: AgentAssignmentTarget,
    ) -> Result<(), AgentAssignmentTransitionError> {
        if self.target.agent_id == target.agent_id
            && self.target.session_id == target.session_id
            && self.target.principal == target.principal
        {
            Ok(())
        } else {
            Err(AgentAssignmentTransitionError::TargetConflict)
        }
    }

    pub fn claim(
        &self,
        target: AgentAssignmentTarget,
        expected: AgentAssignmentRevision,
        observed_at: TimestampMillis,
    ) -> Result<Self, AgentAssignmentTransitionError> {
        if self.origin != AgentAssignmentOrigin::CoordinatorOffer {
            return Err(AgentAssignmentTransitionError::ContinuationAuthorityRequired);
        }
        if self.state != AgentAssignmentState::Offered {
            return Err(AgentAssignmentTransitionError::InvalidState);
        }
        self.ensure_target(target)?;
        let revision = self.next(expected, observed_at)?;
        Ok(Self {
            state: AgentAssignmentState::Running,
            updated_at: observed_at,
            revision,
            ..self.clone()
        })
    }

    pub fn submit(
        &self,
        target: AgentAssignmentTarget,
        expected: AgentAssignmentRevision,
        result: AgentAssignmentResult,
        observed_at: TimestampMillis,
    ) -> Result<Self, AgentAssignmentTransitionError> {
        if self.state != AgentAssignmentState::Running || self.cancellation_requested {
            return Err(AgentAssignmentTransitionError::InvalidState);
        }
        self.ensure_target(target)?;
        let revision = self.next(expected, observed_at)?;
        Ok(Self {
            state: AgentAssignmentState::Submitted,
            updated_at: observed_at,
            revision,
            result: Some(result),
            ..self.clone()
        })
    }

    pub fn accept(
        &self,
        coordinator: ActivityCoordinatorActor,
        expected: AgentAssignmentRevision,
        observed_at: TimestampMillis,
    ) -> Result<Self, AgentAssignmentTransitionError> {
        if self.state != AgentAssignmentState::Submitted {
            return Err(AgentAssignmentTransitionError::InvalidState);
        }
        self.ensure_independent_reviewer(coordinator)?;
        let revision = self.next(expected, observed_at)?;
        Ok(Self {
            state: AgentAssignmentState::Accepted,
            reviewed_by: Some(AgentAssignmentCoordinator::from_actor(coordinator)),
            updated_at: observed_at,
            revision,
            ..self.clone()
        })
    }

    pub fn reject(
        &self,
        coordinator: ActivityCoordinatorActor,
        expected: AgentAssignmentRevision,
        observed_at: TimestampMillis,
    ) -> Result<Self, AgentAssignmentTransitionError> {
        if self.state != AgentAssignmentState::Submitted {
            return Err(AgentAssignmentTransitionError::InvalidState);
        }
        self.ensure_independent_reviewer(coordinator)?;
        let revision = self.next(expected, observed_at)?;
        Ok(Self {
            state: AgentAssignmentState::Rejected,
            reviewed_by: Some(AgentAssignmentCoordinator::from_actor(coordinator)),
            updated_at: observed_at,
            revision,
            ..self.clone()
        })
    }

    // This is a fresh review precondition, not a readback invariant: historical
    // reviews remain readable even if an older writer allowed self-review.
    fn ensure_independent_reviewer(
        &self,
        reviewer: ActivityCoordinatorActor,
    ) -> Result<(), AgentAssignmentTransitionError> {
        if reviewer.agent_id() == self.target.agent_id() {
            return Err(AgentAssignmentTransitionError::CoordinatorTargetSameAgent);
        }
        Ok(())
    }

    pub fn request_cancel(
        &self,
        _coordinator: ActivityCoordinatorActor,
        expected: AgentAssignmentRevision,
        observed_at: TimestampMillis,
    ) -> Result<Self, AgentAssignmentTransitionError> {
        if !matches!(
            self.state,
            AgentAssignmentState::Offered | AgentAssignmentState::Running
        ) {
            return Err(AgentAssignmentTransitionError::InvalidState);
        }
        let revision = self.next(expected, observed_at)?;
        Ok(Self {
            state: if self.state == AgentAssignmentState::Offered {
                AgentAssignmentState::Cancelled
            } else {
                AgentAssignmentState::Running
            },
            cancellation_requested: true,
            updated_at: observed_at,
            revision,
            ..self.clone()
        })
    }

    pub fn acknowledge_cancel(
        &self,
        target: AgentAssignmentTarget,
        expected: AgentAssignmentRevision,
        observed_at: TimestampMillis,
    ) -> Result<Self, AgentAssignmentTransitionError> {
        if self.state != AgentAssignmentState::Running || !self.cancellation_requested {
            return Err(AgentAssignmentTransitionError::CancellationNotRequested);
        }
        self.ensure_target(target)?;
        let revision = self.next(expected, observed_at)?;
        Ok(Self {
            state: AgentAssignmentState::Cancelled,
            updated_at: observed_at,
            revision,
            ..self.clone()
        })
    }

    pub fn interrupt(
        &self,
        expected: AgentAssignmentRevision,
        observed_at: TimestampMillis,
    ) -> Result<Self, AgentAssignmentTransitionError> {
        if !matches!(
            self.state,
            AgentAssignmentState::Offered | AgentAssignmentState::Running
        ) {
            return Err(AgentAssignmentTransitionError::InvalidState);
        }
        let revision = self.next(expected, observed_at)?;
        Ok(Self {
            state: AgentAssignmentState::Interrupted,
            cancellation_requested: true,
            updated_at: observed_at,
            revision,
            ..self.clone()
        })
    }

    pub const fn id(&self) -> AgentAssignmentId {
        self.id
    }
    pub const fn origin(&self) -> AgentAssignmentOrigin {
        self.origin
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn activity_id(&self) -> crate::ActivityId {
        self.activity_id
    }

    pub const fn goal_id(&self) -> GoalId {
        self.goal_id
    }

    pub const fn goal_created_at(&self) -> TimestampMillis {
        self.goal_created_at
    }

    pub const fn goal_revision(&self) -> GoalRevision {
        self.goal_revision
    }

    pub const fn dag_revision(&self) -> DagRevisionNumber {
        self.dag_revision
    }

    pub const fn dag_head_revision(&self) -> DagHeadRevision {
        self.dag_head_revision
    }

    pub const fn node_id(&self) -> DagNodeId {
        self.node_id
    }

    pub const fn node_revision(&self) -> DagNodeRevision {
        self.node_revision
    }

    /// Original planning context. For a continuation this is retained from its
    /// predecessor; it does not attest a fresh offer by the current Coordinator.
    pub const fn coordinator(&self) -> AgentAssignmentCoordinator {
        self.coordinator
    }

    pub const fn target(&self) -> AgentAssignmentTarget {
        self.target
    }

    pub const fn state(&self) -> AgentAssignmentState {
        self.state
    }

    pub const fn cancellation_requested(&self) -> bool {
        self.cancellation_requested
    }

    /// Budget frozen at offer time; `None` marks a credit-ineligible
    /// (legacy/undelegated) assignment.
    pub const fn credit_budget(&self) -> Option<WorkCreditBudget> {
        self.credit_budget
    }

    pub fn result(&self) -> Option<&AgentAssignmentResult> {
        self.result.as_ref()
    }

    pub const fn reviewed_by(&self) -> Option<AgentAssignmentCoordinator> {
        self.reviewed_by
    }

    pub const fn created_at(&self) -> TimestampMillis {
        self.created_at
    }

    pub const fn updated_at(&self) -> TimestampMillis {
        self.updated_at
    }

    pub const fn revision(&self) -> AgentAssignmentRevision {
        self.revision
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum AgentAssignmentTransitionError {
    #[error("Agent assignment continuation lineage is invalid")]
    InvalidContinuationOrigin,
    #[error("Agent assignment requires exact cut-continuation authority")]
    ContinuationAuthorityRequired,
    #[error("Agent assignment revision conflicts")]
    RevisionConflict,
    #[error("Agent assignment state does not permit this transition")]
    InvalidState,
    #[error("Agent assignment timestamp moved backwards")]
    TimestampOrder,
    #[error("Agent assignment revision overflowed")]
    RevisionOverflow(#[source] AgentAssignmentRevisionError),
    #[error("Agent assignment target fence conflicts")]
    TargetConflict,
    #[error("Agent assignment Coordinator fence conflicts")]
    CoordinatorConflict,
    #[error("Agent assignment Coordinator and target must be distinct")]
    CoordinatorTargetSameAgent,
    #[error("Agent assignment cancellation was not requested")]
    CancellationNotRequested,
    #[error("Agent assignment projection is invalid")]
    InvalidProjection,
}

#[cfg(test)]
mod tests {
    mod continuation;
    mod origin;

    use super::*;
    use crate::ActivityId;

    fn ids() -> (
        AgentAssignmentId,
        WorkspaceId,
        ActivityId,
        GoalId,
        AgentInstanceId,
        AgentSessionId,
        AgentInstanceId,
        AgentSessionId,
    ) {
        (
            AgentAssignmentId::from_uuid(Uuid::from_u128(1)),
            WorkspaceId::from_uuid(Uuid::from_u128(2)),
            ActivityId::from_uuid(Uuid::from_u128(3)),
            GoalId::from_uuid(Uuid::from_u128(4)),
            AgentInstanceId::from_uuid(Uuid::from_u128(5)),
            AgentSessionId::from_uuid(Uuid::from_u128(6)),
            AgentInstanceId::from_uuid(Uuid::from_u128(7)),
            AgentSessionId::from_uuid(Uuid::from_u128(8)),
        )
    }

    fn scope() -> Result<
        (
            RegisteredAgentAssignment,
            ActivityCoordinatorActor,
            AgentAssignmentTarget,
        ),
        Box<dyn std::error::Error>,
    > {
        let (
            id,
            workspace,
            activity,
            goal,
            coordinator_id,
            coordinator_session,
            target_id,
            target_session,
        ) = ids();
        let principal = AuthenticatedPrincipal::TrustedStdio;
        let coordinator = ActivityCoordinatorActor::new(
            workspace,
            activity,
            coordinator_id,
            ActivityCoordinatorRevision::INITIAL,
            principal,
            coordinator_session,
        );
        let target = AgentAssignmentTarget::new(
            target_id,
            target_session,
            principal,
            AgentInstanceRevision::INITIAL,
        );
        let assignment = RegisteredAgentAssignment::offered(
            id,
            workspace,
            activity,
            goal,
            TimestampMillis::new(1)?,
            GoalRevision::INITIAL,
            DagRevisionNumber::INITIAL,
            DagHeadRevision::INITIAL,
            DagNodeId::from_uuid(Uuid::from_u128(9)),
            DagNodeRevision::INITIAL,
            AgentAssignmentCoordinator::from_actor(coordinator),
            target,
            Some(WorkCreditBudget::Three),
            TimestampMillis::new(2)?,
        )?;
        Ok((assignment, coordinator, target))
    }

    #[test]
    fn work_credit_budget_is_bounded_and_displayed() {
        assert_eq!(WorkCreditBudget::One.value(), 1);
        assert_eq!(WorkCreditBudget::Three.value(), 3);
        assert_eq!(WorkCreditBudget::Five.value(), 5);
        assert_eq!(WorkCreditBudget::try_from_i64(1), Ok(WorkCreditBudget::One));
        assert_eq!(
            WorkCreditBudget::try_from_i64(3),
            Ok(WorkCreditBudget::Three)
        );
        assert_eq!(
            WorkCreditBudget::try_from_i64(5),
            Ok(WorkCreditBudget::Five)
        );
        assert_eq!(WorkCreditBudget::One.to_string(), "1");
        assert_eq!(WorkCreditBudget::Five.to_string(), "5");
        for invalid in [0, 2, 4, -1, 6] {
            assert_eq!(
                WorkCreditBudget::try_from_i64(invalid),
                Err(WorkCreditBudgetError::Invalid { actual: invalid })
            );
        }
    }

    #[test]
    fn lifecycle_preserves_running_cancellation_unknown_outcome()
    -> Result<(), Box<dyn std::error::Error>> {
        let (assignment, coordinator, target) = scope()?;
        let running = assignment.claim(target, assignment.revision(), TimestampMillis::new(3)?)?;
        let requested =
            running.request_cancel(coordinator, running.revision(), TimestampMillis::new(4)?)?;
        assert_eq!(requested.state(), AgentAssignmentState::Running);
        assert!(requested.cancellation_requested());
        let interrupted = requested.interrupt(requested.revision(), TimestampMillis::new(5)?)?;
        assert_eq!(interrupted.state(), AgentAssignmentState::Interrupted);
        assert!(interrupted.result().is_none());
        Ok(())
    }

    #[test]
    fn result_is_bounded_and_urls_are_http_only() {
        assert!(AgentAssignmentSourceUrl::new("file:///tmp/x".to_owned()).is_err());
        assert!(AgentAssignmentSourceUrl::new("https://example.test/ref".to_owned()).is_ok());
        assert!(AgentAssignmentResult::new("report".to_owned(), Vec::new(), None,).is_ok());
        assert!(AgentAssignmentResult::new(String::new(), Vec::new(), None,).is_err());
    }
}
