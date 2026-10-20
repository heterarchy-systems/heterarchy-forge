//! Bounded durable Goal contract.
//!
//! A Goal is optional semantic authority for one coherent objective. It does
//! not grant filesystem/process authority and never creates continuation work.

use std::fmt;
use std::str::FromStr;

use thiserror::Error;
use uuid::Uuid;

use crate::{
    ActivityId, ApprovalRequestId, ChangeSetId, CheckpointId, ExecutionId, ExecutionRequestDigest,
    FileContentHash, TimestampMillis, WorkspaceId, WorkspaceRelativePath,
};

pub const MAX_GOAL_OBJECTIVE_BYTES: usize = 4 * 1024;
pub const MAX_GOAL_STATEMENT_BYTES: usize = 1024;
pub const MAX_GOAL_REASON_BYTES: usize = 2 * 1024;
pub const MAX_GOAL_STATEMENTS_PER_KIND: usize = 32;
pub const MAX_GOAL_VERIFICATION_REQUIREMENTS: usize = 32;
pub const MAX_GOAL_CONTRACT_BYTES: usize = 32 * 1024;
pub const MAX_GOAL_LIST_RESULTS: u32 = 100;
pub const MAX_GOAL_REVIEW_CHECKS: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GoalId(Uuid);

impl GoalId {
    pub const fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }

    pub const fn into_uuid(self) -> Uuid {
        self.0
    }
}

impl fmt::Display for GoalId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for GoalId {
    type Err = GoalIdParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(value)
            .map(Self)
            .map_err(GoalIdParseError::InvalidUuid)
    }
}

#[derive(Debug, Error)]
pub enum GoalIdParseError {
    #[error("invalid Goal UUID")]
    InvalidUuid(#[source] uuid::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GoalRevision(i64);

impl GoalRevision {
    pub const INITIAL: Self = Self(1);

    pub const fn new(value: i64) -> Result<Self, GoalRevisionError> {
        if value < 1 {
            Err(GoalRevisionError::Invalid { actual: value })
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> i64 {
        self.0
    }

    pub const fn checked_next(self) -> Result<Self, GoalRevisionError> {
        match self.0.checked_add(1) {
            Some(value) => Ok(Self(value)),
            None => Err(GoalRevisionError::Overflow { current: self.0 }),
        }
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum GoalRevisionError {
    #[error("Goal revision must be at least 1, got {actual}")]
    Invalid { actual: i64 },
    #[error("Goal revision overflowed at {current}")]
    Overflow { current: i64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GoalListLimit(u32);

impl GoalListLimit {
    pub const DEFAULT: Self = Self(50);

    pub const fn new(value: u32) -> Result<Self, GoalListLimitError> {
        if value == 0 || value > MAX_GOAL_LIST_RESULTS {
            Err(GoalListLimitError::OutOfRange {
                actual: value,
                maximum: MAX_GOAL_LIST_RESULTS,
            })
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum GoalListLimitError {
    #[error("Goal list limit {actual} is outside 1..={maximum}")]
    OutOfRange { actual: u32, maximum: u32 },
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct GoalObjective(String);

impl GoalObjective {
    pub fn new(value: String) -> Result<Self, GoalTextError> {
        validate_goal_text(&value, MAX_GOAL_OBJECTIVE_BYTES)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn byte_len(&self) -> usize {
        self.0.len()
    }
}

impl fmt::Debug for GoalObjective {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GoalObjective")
            .field("bytes", &self.0.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct GoalStatement(String);

impl GoalStatement {
    pub fn new(value: String) -> Result<Self, GoalTextError> {
        validate_goal_text(&value, MAX_GOAL_STATEMENT_BYTES)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn byte_len(&self) -> usize {
        self.0.len()
    }
}

impl fmt::Debug for GoalStatement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GoalStatement")
            .field("bytes", &self.0.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct GoalPublicReason(String);

impl GoalPublicReason {
    pub fn new(value: String) -> Result<Self, GoalTextError> {
        validate_goal_text(&value, MAX_GOAL_REASON_BYTES)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for GoalPublicReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GoalPublicReason")
            .field("bytes", &self.0.len())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum GoalTextError {
    #[error("Goal text must contain non-whitespace content")]
    Empty,
    #[error("Goal text contains a forbidden control character")]
    ControlCharacter,
    #[error("Goal text has {actual} bytes; maximum is {maximum}")]
    TooLarge { actual: usize, maximum: usize },
}

fn validate_goal_text(value: &str, maximum: usize) -> Result<(), GoalTextError> {
    if value.trim().is_empty() {
        return Err(GoalTextError::Empty);
    }
    if value.len() > maximum {
        return Err(GoalTextError::TooLarge {
            actual: value.len(),
            maximum,
        });
    }
    if value.chars().any(|character| {
        character == '\0' || (character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    }) {
        return Err(GoalTextError::ControlCharacter);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GoalBlockerKind {
    ApprovalWait,
    ExternalDependency,
    VerificationFailure,
    ResourceLimit,
    UserDecision,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GoalBlocker {
    kind: GoalBlockerKind,
    reason: GoalPublicReason,
}

impl GoalBlocker {
    pub const fn new(kind: GoalBlockerKind, reason: GoalPublicReason) -> Self {
        Self { kind, reason }
    }

    pub const fn kind(&self) -> GoalBlockerKind {
        self.kind
    }

    pub const fn reason(&self) -> &GoalPublicReason {
        &self.reason
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GoalFailure {
    reason: GoalPublicReason,
}

impl GoalFailure {
    pub const fn new(reason: GoalPublicReason) -> Self {
        Self { reason }
    }

    pub const fn reason(&self) -> &GoalPublicReason {
        &self.reason
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum GoalStatus {
    Active,
    Paused,
    Blocked(GoalBlocker),
    Completed,
    Failed(GoalFailure),
    Cancelled,
}

impl GoalStatus {
    pub const fn is_terminal(&self) -> bool {
        matches!(
            Self::kind(self),
            GoalStatusKind::Completed | GoalStatusKind::Failed | GoalStatusKind::Cancelled
        )
    }

    pub const fn kind(&self) -> GoalStatusKind {
        match self {
            Self::Active => GoalStatusKind::Active,
            Self::Paused => GoalStatusKind::Paused,
            Self::Blocked(_) => GoalStatusKind::Blocked,
            Self::Completed => GoalStatusKind::Completed,
            Self::Failed(_) => GoalStatusKind::Failed,
            Self::Cancelled => GoalStatusKind::Cancelled,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GoalStatusKind {
    Active,
    Paused,
    Blocked,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum GoalVerificationRequirement {
    ExecutionSucceeded {
        request_digest: ExecutionRequestDigest,
        description: GoalStatement,
    },
    FilePresent {
        path: WorkspaceRelativePath,
        expected_hash: Option<FileContentHash>,
        description: GoalStatement,
    },
    ChangeSetSealed {
        change_set_id: ChangeSetId,
        description: GoalStatement,
    },
    CheckpointReady {
        checkpoint_id: CheckpointId,
        description: GoalStatement,
    },
}

impl GoalVerificationRequirement {
    pub const fn description(&self) -> &GoalStatement {
        match self {
            Self::ExecutionSucceeded { description, .. }
            | Self::FilePresent { description, .. }
            | Self::ChangeSetSealed { description, .. }
            | Self::CheckpointReady { description, .. } => description,
        }
    }

    fn contract_byte_len(&self) -> Option<usize> {
        let payload_bytes = match self {
            Self::ExecutionSucceeded { .. } => ExecutionRequestDigest::BYTE_LEN,
            Self::FilePresent {
                path,
                expected_hash,
                ..
            } => path
                .as_path()
                .as_os_str()
                .as_encoded_bytes()
                .len()
                .checked_add(expected_hash.map_or(0, |_| FileContentHash::BYTE_LEN))?,
            Self::ChangeSetSealed { .. } | Self::CheckpointReady { .. } => 16,
        };
        self.description().byte_len().checked_add(payload_bytes)
    }
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoalContract {
    objective: GoalObjective,
    success_criteria: Vec<GoalStatement>,
    constraints: Vec<GoalStatement>,
    out_of_scope: Vec<GoalStatement>,
    verification_requirements: Vec<GoalVerificationRequirement>,
    stop_conditions: Vec<GoalStatement>,
}

impl GoalContract {
    pub fn new(
        objective: GoalObjective,
        success_criteria: Vec<GoalStatement>,
        constraints: Vec<GoalStatement>,
        out_of_scope: Vec<GoalStatement>,
        verification_requirements: Vec<GoalVerificationRequirement>,
        stop_conditions: Vec<GoalStatement>,
    ) -> Result<Self, GoalContractError> {
        validate_count("success criteria", success_criteria.len(), true)?;
        validate_count("constraints", constraints.len(), false)?;
        validate_count("out of scope", out_of_scope.len(), false)?;
        validate_count("stop conditions", stop_conditions.len(), false)?;
        if verification_requirements.len() > MAX_GOAL_VERIFICATION_REQUIREMENTS {
            return Err(GoalContractError::TooManyVerificationRequirements {
                actual: verification_requirements.len(),
                maximum: MAX_GOAL_VERIFICATION_REQUIREMENTS,
            });
        }
        let total = objective
            .byte_len()
            .checked_add(statement_bytes(&success_criteria))
            .and_then(|value| value.checked_add(statement_bytes(&constraints)))
            .and_then(|value| value.checked_add(statement_bytes(&out_of_scope)))
            .and_then(|value| value.checked_add(statement_bytes(&stop_conditions)))
            .and_then(|value| {
                verification_requirements
                    .iter()
                    .try_fold(value, |total, requirement| {
                        total.checked_add(requirement.contract_byte_len()?)
                    })
            })
            .ok_or(GoalContractError::ContractTooLarge {
                actual: usize::MAX,
                maximum: MAX_GOAL_CONTRACT_BYTES,
            })?;
        if total > MAX_GOAL_CONTRACT_BYTES {
            return Err(GoalContractError::ContractTooLarge {
                actual: total,
                maximum: MAX_GOAL_CONTRACT_BYTES,
            });
        }
        Ok(Self {
            objective,
            success_criteria,
            constraints,
            out_of_scope,
            verification_requirements,
            stop_conditions,
        })
    }

    pub const fn objective(&self) -> &GoalObjective {
        &self.objective
    }

    pub fn success_criteria(&self) -> &[GoalStatement] {
        &self.success_criteria
    }

    pub fn constraints(&self) -> &[GoalStatement] {
        &self.constraints
    }

    pub fn out_of_scope(&self) -> &[GoalStatement] {
        &self.out_of_scope
    }

    pub fn verification_requirements(&self) -> &[GoalVerificationRequirement] {
        &self.verification_requirements
    }

    pub fn stop_conditions(&self) -> &[GoalStatement] {
        &self.stop_conditions
    }
}

fn validate_count(
    name: &'static str,
    actual: usize,
    required: bool,
) -> Result<(), GoalContractError> {
    if required && actual == 0 {
        return Err(GoalContractError::MissingRequiredCollection { name });
    }
    if actual > MAX_GOAL_STATEMENTS_PER_KIND {
        return Err(GoalContractError::TooManyStatements {
            name,
            actual,
            maximum: MAX_GOAL_STATEMENTS_PER_KIND,
        });
    }
    Ok(())
}

fn statement_bytes(values: &[GoalStatement]) -> usize {
    values.iter().fold(0_usize, |total, value| {
        total.saturating_add(value.byte_len())
    })
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum GoalContractError {
    #[error("Goal contract requires at least one {name}")]
    MissingRequiredCollection { name: &'static str },
    #[error("Goal contract has {actual} {name}; maximum is {maximum}")]
    TooManyStatements {
        name: &'static str,
        actual: usize,
        maximum: usize,
    },
    #[error("Goal contract has {actual} verification requirements; maximum is {maximum}")]
    TooManyVerificationRequirements { actual: usize, maximum: usize },
    #[error("Goal contract has {actual} bytes; maximum is {maximum}")]
    ContractTooLarge { actual: usize, maximum: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum GoalEvidenceRef {
    ChangeSet(ChangeSetId),
    Execution(ExecutionId),
    Approval(ApprovalRequestId),
    Checkpoint(CheckpointId),
}

impl GoalEvidenceRef {
    pub const fn kind(self) -> GoalEvidenceKind {
        match self {
            Self::ChangeSet(_) => GoalEvidenceKind::ChangeSet,
            Self::Execution(_) => GoalEvidenceKind::Execution,
            Self::Approval(_) => GoalEvidenceKind::Approval,
            Self::Checkpoint(_) => GoalEvidenceKind::Checkpoint,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum GoalEvidenceKind {
    ChangeSet,
    Execution,
    Approval,
    Checkpoint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GoalAttribution {
    goal_id: GoalId,
    expected_revision: GoalRevision,
}

impl GoalAttribution {
    pub const fn new(goal_id: GoalId, expected_revision: GoalRevision) -> Self {
        Self {
            goal_id,
            expected_revision,
        }
    }

    pub const fn goal_id(self) -> GoalId {
        self.goal_id
    }

    pub const fn expected_revision(self) -> GoalRevision {
        self.expected_revision
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GoalTimestamps {
    created_at: TimestampMillis,
    updated_at: TimestampMillis,
}

impl GoalTimestamps {
    pub fn new(
        created_at: TimestampMillis,
        updated_at: TimestampMillis,
    ) -> Result<Self, GoalTransitionError> {
        if updated_at.get() < created_at.get() {
            Err(GoalTransitionError::TimestampOrder)
        } else {
            Ok(Self {
                created_at,
                updated_at,
            })
        }
    }

    pub const fn initial(observed_at: TimestampMillis) -> Self {
        Self {
            created_at: observed_at,
            updated_at: observed_at,
        }
    }

    pub const fn created_at(self) -> TimestampMillis {
        self.created_at
    }

    pub const fn updated_at(self) -> TimestampMillis {
        self.updated_at
    }
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredGoal {
    id: GoalId,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    contract: GoalContract,
    status: GoalStatus,
    timestamps: GoalTimestamps,
    revision: GoalRevision,
}

impl RegisteredGoal {
    pub fn create(
        id: GoalId,
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        contract: GoalContract,
        observed_at: TimestampMillis,
    ) -> Self {
        Self {
            id,
            workspace_id,
            activity_id,
            contract,
            status: GoalStatus::Active,
            timestamps: GoalTimestamps::initial(observed_at),
            revision: GoalRevision::INITIAL,
        }
    }

    pub fn from_parts(
        id: GoalId,
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        contract: GoalContract,
        status: GoalStatus,
        timestamps: GoalTimestamps,
        revision: GoalRevision,
    ) -> Result<Self, GoalTransitionError> {
        if revision == GoalRevision::INITIAL
            && (status.kind() != GoalStatusKind::Active
                || timestamps.created_at() != timestamps.updated_at())
        {
            return Err(GoalTransitionError::InvalidLifecycleProjection);
        }
        Ok(Self {
            id,
            workspace_id,
            activity_id,
            contract,
            status,
            timestamps,
            revision,
        })
    }

    pub const fn id(&self) -> GoalId {
        self.id
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn activity_id(&self) -> ActivityId {
        self.activity_id
    }

    pub const fn contract(&self) -> &GoalContract {
        &self.contract
    }

    pub const fn status(&self) -> &GoalStatus {
        &self.status
    }

    pub const fn timestamps(&self) -> GoalTimestamps {
        self.timestamps
    }

    pub const fn revision(&self) -> GoalRevision {
        self.revision
    }

    pub const fn accepts_new_evidence(&self) -> bool {
        matches!(self.status, GoalStatus::Active)
    }

    pub fn pause(
        &self,
        expected: GoalRevision,
        observed_at: TimestampMillis,
    ) -> Result<Self, GoalTransitionError> {
        match self.status {
            GoalStatus::Active | GoalStatus::Blocked(_) => {
                self.transition(expected, GoalStatus::Paused, observed_at)
            }
            GoalStatus::Paused => Err(GoalTransitionError::AlreadyInRequestedState),
            _ => Err(self.invalid_transition()),
        }
    }

    pub fn resume(
        &self,
        expected: GoalRevision,
        observed_at: TimestampMillis,
    ) -> Result<Self, GoalTransitionError> {
        match self.status {
            GoalStatus::Paused | GoalStatus::Blocked(_) => {
                self.transition(expected, GoalStatus::Active, observed_at)
            }
            GoalStatus::Active => Err(GoalTransitionError::AlreadyInRequestedState),
            _ => Err(self.invalid_transition()),
        }
    }

    pub fn block(
        &self,
        expected: GoalRevision,
        blocker: GoalBlocker,
        observed_at: TimestampMillis,
    ) -> Result<Self, GoalTransitionError> {
        match self.status {
            GoalStatus::Active | GoalStatus::Paused => {
                self.transition(expected, GoalStatus::Blocked(blocker), observed_at)
            }
            GoalStatus::Blocked(_) => Err(GoalTransitionError::AlreadyInRequestedState),
            _ => Err(self.invalid_transition()),
        }
    }

    pub fn fail(
        &self,
        expected: GoalRevision,
        failure: GoalFailure,
        observed_at: TimestampMillis,
    ) -> Result<Self, GoalTransitionError> {
        if self.status.is_terminal() {
            return Err(self.invalid_transition());
        }
        self.transition(expected, GoalStatus::Failed(failure), observed_at)
    }

    pub fn cancel(
        &self,
        expected: GoalRevision,
        observed_at: TimestampMillis,
    ) -> Result<Self, GoalTransitionError> {
        if self.status.is_terminal() {
            return Err(self.invalid_transition());
        }
        self.transition(expected, GoalStatus::Cancelled, observed_at)
    }

    /// Replace the contract of a non-terminal Goal through the same revision
    /// and timestamp fence used by lifecycle transitions.
    pub fn revise_contract(
        &self,
        expected: GoalRevision,
        contract: GoalContract,
        observed_at: TimestampMillis,
    ) -> Result<Self, GoalTransitionError> {
        if self.status.is_terminal() {
            return Err(self.invalid_transition());
        }
        if self.revision != expected {
            return Err(GoalTransitionError::RevisionConflict);
        }
        if observed_at.get() < self.timestamps.updated_at().get() {
            return Err(GoalTransitionError::TimestampOrder);
        }
        if self.contract == contract {
            return Err(GoalTransitionError::AlreadyInRequestedState);
        }
        let revision = self
            .revision
            .checked_next()
            .map_err(|_| GoalTransitionError::RevisionOverflow)?;
        Ok(Self {
            id: self.id,
            workspace_id: self.workspace_id,
            activity_id: self.activity_id,
            contract,
            status: self.status.clone(),
            timestamps: GoalTimestamps::new(self.timestamps.created_at(), observed_at)?,
            revision,
        })
    }

    /// Record the permanent removal of every DAG revision while retaining the
    /// Goal contract itself.
    ///
    /// A DAG deletion is a semantic Goal transition even though it does not
    /// change the contract or lifecycle status.  Persistence must therefore
    /// calculate this projection before applying its compare-and-set update;
    /// it must not manufacture a revision with direct SQL arithmetic.
    pub fn advance_after_dag_deletion(
        &self,
        expected: GoalRevision,
        observed_at: TimestampMillis,
    ) -> Result<Self, GoalTransitionError> {
        if self.revision != expected {
            return Err(GoalTransitionError::RevisionConflict);
        }
        if observed_at.get() < self.timestamps.updated_at().get() {
            return Err(GoalTransitionError::TimestampOrder);
        }
        let revision = self
            .revision
            .checked_next()
            .map_err(|_| GoalTransitionError::RevisionOverflow)?;
        Ok(Self {
            id: self.id,
            workspace_id: self.workspace_id,
            activity_id: self.activity_id,
            contract: self.contract.clone(),
            status: self.status.clone(),
            timestamps: GoalTimestamps::new(self.timestamps.created_at(), observed_at)?,
            revision,
        })
    }

    pub fn complete(
        &self,
        expected: GoalRevision,
        review: &GoalReview,
        observed_at: TimestampMillis,
    ) -> Result<Self, GoalTransitionError> {
        if !matches!(self.status, GoalStatus::Active) {
            return Err(self.invalid_transition());
        }
        if review.goal_id != self.id || review.goal_revision != self.revision {
            return Err(GoalTransitionError::ReviewMismatch);
        }
        if !review.can_complete() {
            return Err(GoalTransitionError::CompletionBlocked);
        }
        self.transition(expected, GoalStatus::Completed, observed_at)
    }

    fn transition(
        &self,
        expected: GoalRevision,
        status: GoalStatus,
        observed_at: TimestampMillis,
    ) -> Result<Self, GoalTransitionError> {
        if self.revision != expected {
            return Err(GoalTransitionError::RevisionConflict);
        }
        if observed_at.get() < self.timestamps.updated_at().get() {
            return Err(GoalTransitionError::TimestampOrder);
        }
        let revision = self
            .revision
            .checked_next()
            .map_err(|_| GoalTransitionError::RevisionOverflow)?;
        Ok(Self {
            id: self.id,
            workspace_id: self.workspace_id,
            activity_id: self.activity_id,
            contract: self.contract.clone(),
            status,
            timestamps: GoalTimestamps::new(self.timestamps.created_at(), observed_at)?,
            revision,
        })
    }

    fn invalid_transition(&self) -> GoalTransitionError {
        GoalTransitionError::InvalidTransition {
            from: self.status.kind(),
        }
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum GoalTransitionError {
    #[error("Goal revision conflict")]
    RevisionConflict,
    #[error("Goal revision overflow")]
    RevisionOverflow,
    #[error("Goal timestamp order is invalid")]
    TimestampOrder,
    #[error("Goal lifecycle projection is invalid")]
    InvalidLifecycleProjection,
    #[error("Goal transition is invalid from {from:?}")]
    InvalidTransition { from: GoalStatusKind },
    #[error("Goal is already in the requested state")]
    AlreadyInRequestedState,
    #[error("Goal completion review does not match the current Goal")]
    ReviewMismatch,
    #[error("Goal completion is blocked by hard checks")]
    CompletionBlocked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GoalHardCheck {
    Passed { requirement_index: u16 },
    Missing { requirement_index: u16 },
    Failed { requirement_index: u16 },
}

impl GoalHardCheck {
    pub const fn is_passed(&self) -> bool {
        matches!(self, Self::Passed { .. })
    }

    pub const fn requirement_index(&self) -> u16 {
        match self {
            Self::Passed { requirement_index }
            | Self::Missing { requirement_index }
            | Self::Failed { requirement_index } => *requirement_index,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum GoalCompletionBlocker {
    RequiredVerification { requirement_index: u16 },
    PendingApproval(ApprovalRequestId),
    ActiveExecution(ExecutionId),
    UnsealedEvidence(GoalEvidenceRef),
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoalReview {
    goal_id: GoalId,
    goal_revision: GoalRevision,
    hard_checks: Vec<GoalHardCheck>,
    blockers: Vec<GoalCompletionBlocker>,
    manual_assessment_required: bool,
}

impl GoalReview {
    pub fn new(
        goal_id: GoalId,
        goal_revision: GoalRevision,
        mut hard_checks: Vec<GoalHardCheck>,
        mut blockers: Vec<GoalCompletionBlocker>,
        manual_assessment_required: bool,
    ) -> Result<Self, GoalReviewError> {
        if hard_checks.len() > MAX_GOAL_REVIEW_CHECKS || blockers.len() > MAX_GOAL_REVIEW_CHECKS {
            return Err(GoalReviewError::TooManyChecks {
                maximum: MAX_GOAL_REVIEW_CHECKS,
            });
        }
        hard_checks.sort_by_key(GoalHardCheck::requirement_index);
        blockers.sort_unstable();
        blockers.dedup();
        Ok(Self {
            goal_id,
            goal_revision,
            hard_checks,
            blockers,
            manual_assessment_required,
        })
    }

    pub const fn goal_id(&self) -> GoalId {
        self.goal_id
    }

    pub const fn goal_revision(&self) -> GoalRevision {
        self.goal_revision
    }

    pub fn hard_checks(&self) -> &[GoalHardCheck] {
        &self.hard_checks
    }

    pub fn blockers(&self) -> &[GoalCompletionBlocker] {
        &self.blockers
    }

    pub const fn manual_assessment_required(&self) -> bool {
        self.manual_assessment_required
    }

    pub fn can_complete(&self) -> bool {
        self.blockers.is_empty() && self.hard_checks.iter().all(GoalHardCheck::is_passed)
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum GoalReviewError {
    #[error("Goal review exceeds the {maximum}-check bound")]
    TooManyChecks { maximum: usize },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CheckpointId, TimestampMillis, WorkspaceRelativePath};

    fn timestamp(value: i64) -> Result<TimestampMillis, Box<dyn std::error::Error>> {
        Ok(TimestampMillis::new(value)?)
    }

    fn statement(value: &str) -> Result<GoalStatement, Box<dyn std::error::Error>> {
        Ok(GoalStatement::new(value.to_owned())?)
    }

    fn contract() -> Result<GoalContract, Box<dyn std::error::Error>> {
        Ok(GoalContract::new(
            GoalObjective::new("Ship bounded Goal authority".to_owned())?,
            vec![statement("All required tests pass")?],
            vec![statement("Keep Rust-only production")?],
            vec![statement("No DAG implementation")?],
            vec![GoalVerificationRequirement::FilePresent {
                path: WorkspaceRelativePath::new("Cargo.toml".into())?,
                expected_hash: None,
                description: statement("Cargo manifest exists")?,
            }],
            vec![statement("Stop on destructive authority ambiguity")?],
        )?)
    }

    fn goal() -> Result<RegisteredGoal, Box<dyn std::error::Error>> {
        Ok(RegisteredGoal::create(
            GoalId::from_uuid(Uuid::from_u128(1)),
            WorkspaceId::from_uuid(Uuid::from_u128(2)),
            ActivityId::from_uuid(Uuid::from_u128(3)),
            contract()?,
            timestamp(10)?,
        ))
    }

    #[test]
    fn identity_revision_limit_and_text_bounds_are_typed() -> Result<(), Box<dyn std::error::Error>>
    {
        let id = GoalId::from_uuid(Uuid::from_u128(0xBEEF));
        assert_eq!(GoalId::from_str(&id.to_string())?, id);
        assert!(GoalRevision::new(0).is_err());
        assert!(GoalRevision::new(-1).is_err());
        assert!(matches!(
            GoalRevision::new(i64::MAX)?.checked_next(),
            Err(GoalRevisionError::Overflow { .. })
        ));
        assert!(GoalListLimit::new(0).is_err());
        assert!(GoalListLimit::new(MAX_GOAL_LIST_RESULTS + 1).is_err());
        assert_eq!(
            GoalListLimit::new(MAX_GOAL_LIST_RESULTS)?.get(),
            MAX_GOAL_LIST_RESULTS
        );
        assert_eq!(
            GoalObjective::new(" ".to_owned()),
            Err(GoalTextError::Empty)
        );
        assert_eq!(
            GoalStatement::new("bad\u{7}".to_owned()),
            Err(GoalTextError::ControlCharacter)
        );
        assert!(matches!(
            GoalObjective::new("x".repeat(MAX_GOAL_OBJECTIVE_BYTES + 1)),
            Err(GoalTextError::TooLarge { .. })
        ));
        Ok(())
    }

    #[test]
    fn dag_deletion_is_a_fenced_goal_revision_transition() -> Result<(), Box<dyn std::error::Error>>
    {
        let goal = goal()?;
        let deleted = goal.advance_after_dag_deletion(goal.revision(), timestamp(11)?)?;
        assert_eq!(deleted.id(), goal.id());
        assert_eq!(deleted.workspace_id(), goal.workspace_id());
        assert_eq!(deleted.activity_id(), goal.activity_id());
        assert_eq!(deleted.contract(), goal.contract());
        assert_eq!(deleted.status(), goal.status());
        assert_eq!(
            deleted.timestamps().created_at(),
            goal.timestamps().created_at()
        );
        assert_eq!(deleted.timestamps().updated_at(), timestamp(11)?);
        assert_eq!(deleted.revision().get(), goal.revision().get() + 1);
        assert_eq!(
            goal.advance_after_dag_deletion(GoalRevision::new(2)?, timestamp(11)?),
            Err(GoalTransitionError::RevisionConflict)
        );
        Ok(())
    }

    #[test]
    fn contract_requires_bounded_success_criteria_and_aggregate()
    -> Result<(), Box<dyn std::error::Error>> {
        assert!(matches!(
            GoalContract::new(
                GoalObjective::new("objective".to_owned())?,
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ),
            Err(GoalContractError::MissingRequiredCollection { .. })
        ));
        let too_many = (0..=MAX_GOAL_STATEMENTS_PER_KIND)
            .map(|index| statement(&format!("criterion {index}")))
            .collect::<Result<Vec<_>, _>>()?;
        assert!(matches!(
            GoalContract::new(
                GoalObjective::new("objective".to_owned())?,
                too_many,
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ),
            Err(GoalContractError::TooManyStatements { .. })
        ));
        let path_heavy = (0..8)
            .map(|index| {
                Ok::<_, Box<dyn std::error::Error>>(GoalVerificationRequirement::FilePresent {
                    path: WorkspaceRelativePath::new(
                        format!("{index}{}", "a".repeat(4_094)).into(),
                    )?,
                    expected_hash: None,
                    description: statement("present")?,
                })
            })
            .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
        assert!(matches!(
            GoalContract::new(
                GoalObjective::new("objective".to_owned())?,
                vec![statement("criterion")?],
                Vec::new(),
                Vec::new(),
                path_heavy,
                Vec::new(),
            ),
            Err(GoalContractError::ContractTooLarge { .. })
        ));
        Ok(())
    }

    #[test]
    fn lifecycle_cas_blocked_and_terminal_rules_are_exhaustive()
    -> Result<(), Box<dyn std::error::Error>> {
        let initial = goal()?;
        assert!(initial.accepts_new_evidence());
        let paused = initial.pause(initial.revision(), timestamp(11)?)?;
        assert_eq!(paused.status().kind(), GoalStatusKind::Paused);
        assert!(!paused.accepts_new_evidence());
        assert!(matches!(
            paused.resume(GoalRevision::INITIAL, timestamp(12)?),
            Err(GoalTransitionError::RevisionConflict)
        ));
        let blocker = GoalBlocker::new(
            GoalBlockerKind::ApprovalWait,
            GoalPublicReason::new("Waiting for explicit operator approval".to_owned())?,
        );
        let blocked_goal = paused.block(paused.revision(), blocker.clone(), timestamp(12)?)?;
        assert_eq!(blocked_goal.status(), &GoalStatus::Blocked(blocker));
        let resumed = blocked_goal.resume(blocked_goal.revision(), timestamp(13)?)?;
        let failed = resumed.fail(
            resumed.revision(),
            GoalFailure::new(GoalPublicReason::new(
                "Hard verification failed".to_owned(),
            )?),
            timestamp(14)?,
        )?;
        assert!(failed.status().is_terminal());
        assert!(matches!(
            failed.cancel(failed.revision(), timestamp(15)?),
            Err(GoalTransitionError::InvalidTransition { .. })
        ));

        let same_tick = initial.pause(initial.revision(), initial.timestamps().updated_at())?;
        assert_eq!(
            RegisteredGoal::from_parts(
                same_tick.id(),
                same_tick.workspace_id(),
                same_tick.activity_id(),
                same_tick.contract().clone(),
                same_tick.status().clone(),
                same_tick.timestamps(),
                same_tick.revision(),
            )?,
            same_tick
        );
        Ok(())
    }

    #[test]
    fn completion_requires_matching_blocker_free_review() -> Result<(), Box<dyn std::error::Error>>
    {
        let goal = goal()?;
        let blocked = GoalReview::new(
            goal.id(),
            goal.revision(),
            vec![GoalHardCheck::Missing {
                requirement_index: 0,
            }],
            vec![GoalCompletionBlocker::RequiredVerification {
                requirement_index: 0,
            }],
            true,
        )?;
        assert!(!blocked.can_complete());
        assert!(matches!(
            goal.complete(goal.revision(), &blocked, timestamp(11)?),
            Err(GoalTransitionError::CompletionBlocked)
        ));
        let review = GoalReview::new(
            goal.id(),
            goal.revision(),
            vec![GoalHardCheck::Passed {
                requirement_index: 0,
            }],
            Vec::new(),
            true,
        )?;
        assert!(review.can_complete());
        let completed = goal.complete(goal.revision(), &review, timestamp(11)?)?;
        assert_eq!(completed.status().kind(), GoalStatusKind::Completed);
        assert!(completed.status().is_terminal());
        Ok(())
    }

    #[test]
    fn review_order_and_evidence_kinds_are_deterministic() -> Result<(), Box<dyn std::error::Error>>
    {
        let goal = goal()?;
        let approval = ApprovalRequestId::from_uuid(Uuid::from_u128(3));
        let execution = ExecutionId::from_uuid(Uuid::from_u128(4));
        let checkpoint = CheckpointId::from_uuid(Uuid::from_u128(5));
        let review = GoalReview::new(
            goal.id(),
            goal.revision(),
            vec![
                GoalHardCheck::Passed {
                    requirement_index: 2,
                },
                GoalHardCheck::Passed {
                    requirement_index: 0,
                },
            ],
            vec![
                GoalCompletionBlocker::ActiveExecution(execution),
                GoalCompletionBlocker::PendingApproval(approval),
                GoalCompletionBlocker::PendingApproval(approval),
            ],
            false,
        )?;
        assert_eq!(review.hard_checks()[0].requirement_index(), 0);
        assert_eq!(review.blockers().len(), 2);
        assert_eq!(
            GoalEvidenceRef::Checkpoint(checkpoint).kind(),
            GoalEvidenceKind::Checkpoint
        );
        assert_eq!(
            GoalEvidenceRef::Execution(execution).kind(),
            GoalEvidenceKind::Execution
        );
        Ok(())
    }

    #[test]
    fn rehydration_and_timestamp_invariants_fail_closed() -> Result<(), Box<dyn std::error::Error>>
    {
        let goal = goal()?;
        assert!(matches!(
            RegisteredGoal::from_parts(
                goal.id(),
                goal.workspace_id(),
                goal.activity_id(),
                goal.contract().clone(),
                GoalStatus::Paused,
                GoalTimestamps::initial(timestamp(10)?),
                GoalRevision::INITIAL,
            ),
            Err(GoalTransitionError::InvalidLifecycleProjection)
        ));
        assert!(GoalTimestamps::new(timestamp(11)?, timestamp(10)?).is_err());
        let paused = goal.pause(goal.revision(), timestamp(11)?)?;
        let reopened = RegisteredGoal::from_parts(
            paused.id(),
            paused.workspace_id(),
            paused.activity_id(),
            paused.contract().clone(),
            paused.status().clone(),
            paused.timestamps(),
            paused.revision(),
        )?;
        assert_eq!(reopened, paused);
        Ok(())
    }
}
