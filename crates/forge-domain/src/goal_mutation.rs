//! Immutable, Coordinator-authorized Goal mutation commands and receipts.
//!
//! The command digest is computed from a borrowed canonical encoding.  This
//! module owns no clock, persistence, transport, or other external effect.

use blake3::Hasher;
use thiserror::Error;
use uuid::Uuid;

use crate::{
    ActivityCoordinatorActor, AuthenticatedPrincipal, FileContentHash, GoalBlocker,
    GoalBlockerKind, GoalContract, GoalFailure, GoalId, GoalRevision, GoalStatement, GoalStatus,
    GoalStatusKind, GoalVerificationRequirement, RegisteredGoal, TimestampMillis,
    WorkspaceRevision,
};

const DIGEST_DOMAIN: &[u8] = b"heterarchy-forge:goal-mutation:v1\0";

/// Idempotency identity for one Goal mutation request.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GoalMutationRequestId(Uuid);

impl GoalMutationRequestId {
    pub const fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }

    pub const fn into_uuid(self) -> Uuid {
        self.0
    }
}

/// BLAKE3 digest of a Goal mutation's canonical command encoding.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GoalMutationDigest([u8; 32]);

impl GoalMutationDigest {
    pub const BYTE_LEN: usize = 32;

    pub const fn from_bytes(value: [u8; Self::BYTE_LEN]) -> Self {
        Self(value)
    }

    pub const fn as_bytes(&self) -> &[u8; Self::BYTE_LEN] {
        &self.0
    }
}

/// Lifecycle operation carried by a Goal mutation.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GoalLifecycleAction {
    Pause,
    Resume,
    Block(GoalBlocker),
    Fail(GoalFailure),
    Cancel,
}

/// Payload of one immutable Goal mutation command.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GoalMutationAction {
    Create(Box<GoalContract>),
    Revise(Box<GoalContract>),
    Transition(GoalLifecycleAction),
    Complete { review_id: Uuid },
}

impl GoalMutationAction {
    pub const fn kind(&self) -> GoalMutationKind {
        match self {
            Self::Create(_) => GoalMutationKind::Create,
            Self::Revise(_) => GoalMutationKind::Revise,
            Self::Transition(GoalLifecycleAction::Pause) => GoalMutationKind::Pause,
            Self::Transition(GoalLifecycleAction::Resume) => GoalMutationKind::Resume,
            Self::Transition(GoalLifecycleAction::Block(_)) => GoalMutationKind::Block,
            Self::Transition(GoalLifecycleAction::Fail(_)) => GoalMutationKind::Fail,
            Self::Transition(GoalLifecycleAction::Cancel) => GoalMutationKind::Cancel,
            Self::Complete { .. } => GoalMutationKind::Complete,
        }
    }
}

/// Stable kind tag for Goal mutation commands.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum GoalMutationKind {
    Create,
    Revise,
    Pause,
    Resume,
    Block,
    Fail,
    Cancel,
    Complete,
}

impl GoalMutationKind {
    pub const fn code(self) -> u8 {
        match self {
            Self::Create => 0,
            Self::Revise => 1,
            Self::Pause => 2,
            Self::Resume => 3,
            Self::Block => 4,
            Self::Fail => 5,
            Self::Cancel => 6,
            Self::Complete => 7,
        }
    }
}

/// Failure returned when a Goal mutation kind code is unknown.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum GoalMutationKindError {
    #[error("unknown Goal mutation kind code {actual}")]
    Unknown { actual: u8 },
}

impl TryFrom<u8> for GoalMutationKind {
    type Error = GoalMutationKindError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Create),
            1 => Ok(Self::Revise),
            2 => Ok(Self::Pause),
            3 => Ok(Self::Resume),
            4 => Ok(Self::Block),
            5 => Ok(Self::Fail),
            6 => Ok(Self::Cancel),
            7 => Ok(Self::Complete),
            actual => Err(GoalMutationKindError::Unknown { actual }),
        }
    }
}

/// Domain validation failure for Goal mutation commands and receipts.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum GoalMutationError {
    #[error("Goal mutation request identity must not be nil")]
    NilRequestId,
    #[error("Goal mutation Goal identity must not be nil")]
    NilGoalId,
    #[error("Goal mutation actor Workspace identity must not be nil")]
    NilActorWorkspaceId,
    #[error("Goal mutation actor Activity identity must not be nil")]
    NilActorActivityId,
    #[error("Goal mutation actor Agent identity must not be nil")]
    NilActorAgentId,
    #[error("Goal mutation actor session identity must not be nil")]
    NilActorSessionId,
    #[error("Goal mutation actor principal identity must not be nil")]
    NilActorPrincipalId,
    #[error("Goal mutation completion review identity must not be nil")]
    NilReviewId,
    #[error("Goal mutation expected revision shape is invalid for its action")]
    ExpectedRevisionShape,
    #[error("Goal mutation receipt revision step is invalid")]
    InvalidReceiptRevisionStep,
    #[error("Goal mutation receipt review identity shape is invalid")]
    InvalidReceiptReviewShape,
    #[error("Goal mutation receipt result status is invalid for its kind")]
    InvalidReceiptResultStatus,
    #[error("committed Goal does not match the Goal mutation command")]
    CommittedGoalMismatch,
}

/// Immutable Coordinator-authorized mutation request with a cached digest.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoalMutationCommand {
    request_id: GoalMutationRequestId,
    actor: ActivityCoordinatorActor,
    workspace_revision: WorkspaceRevision,
    goal_id: GoalId,
    expected_revision: Option<GoalRevision>,
    observed_at: TimestampMillis,
    action: GoalMutationAction,
    digest: GoalMutationDigest,
}

impl GoalMutationCommand {
    pub fn new(
        request_id: GoalMutationRequestId,
        actor: ActivityCoordinatorActor,
        workspace_revision: WorkspaceRevision,
        goal_id: GoalId,
        expected_revision: Option<GoalRevision>,
        observed_at: TimestampMillis,
        action: GoalMutationAction,
    ) -> Result<Self, GoalMutationError> {
        validate_request_id(request_id)?;
        validate_goal_id(goal_id)?;
        validate_actor(actor)?;
        validate_expected_revision(action.kind(), expected_revision)?;
        validate_action_review(&action)?;
        let digest = GoalMutationDigest::from_bytes(compute_digest(
            request_id,
            actor,
            workspace_revision,
            goal_id,
            expected_revision,
            observed_at,
            &action,
        ));
        Ok(Self {
            request_id,
            actor,
            workspace_revision,
            goal_id,
            expected_revision,
            observed_at,
            action,
            digest,
        })
    }

    pub const fn request_id(&self) -> GoalMutationRequestId {
        self.request_id
    }

    pub const fn actor(&self) -> ActivityCoordinatorActor {
        self.actor
    }

    pub const fn workspace_revision(&self) -> WorkspaceRevision {
        self.workspace_revision
    }

    pub const fn goal_id(&self) -> GoalId {
        self.goal_id
    }

    pub const fn expected_revision(&self) -> Option<GoalRevision> {
        self.expected_revision
    }

    pub const fn observed_at(&self) -> TimestampMillis {
        self.observed_at
    }

    pub const fn action(&self) -> &GoalMutationAction {
        &self.action
    }

    pub const fn kind(&self) -> GoalMutationKind {
        self.action.kind()
    }

    pub const fn digest(&self) -> GoalMutationDigest {
        self.digest
    }
}

/// Public read-model fields for one committed Goal mutation receipt.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoalMutationReceiptData {
    pub request_id: GoalMutationRequestId,
    pub digest: GoalMutationDigest,
    pub actor: ActivityCoordinatorActor,
    pub workspace_revision: WorkspaceRevision,
    pub goal_id: GoalId,
    pub kind: GoalMutationKind,
    pub expected_revision: Option<GoalRevision>,
    pub result_revision: GoalRevision,
    pub result_status: GoalStatusKind,
    pub observed_at: TimestampMillis,
    pub review_id: Option<Uuid>,
}

/// Validated metadata for one committed Goal mutation.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoalMutationReceipt {
    data: GoalMutationReceiptData,
}

impl GoalMutationReceipt {
    pub fn from_data(data: GoalMutationReceiptData) -> Result<Self, GoalMutationError> {
        validate_receipt_data(&data)?;
        Ok(Self { data })
    }

    pub const fn data(&self) -> &GoalMutationReceiptData {
        &self.data
    }

    pub fn from_committed(
        command: &GoalMutationCommand,
        goal: &RegisteredGoal,
    ) -> Result<Self, GoalMutationError> {
        if goal.id() != command.goal_id()
            || goal.workspace_id() != command.actor().workspace_id()
            || goal.activity_id() != command.actor().activity_id()
            || goal.timestamps().updated_at() != command.observed_at()
        {
            return Err(GoalMutationError::CommittedGoalMismatch);
        }
        if !action_matches_goal(command.action(), goal) {
            return Err(GoalMutationError::CommittedGoalMismatch);
        }
        let review_id = match command.action() {
            GoalMutationAction::Complete { review_id } => Some(*review_id),
            GoalMutationAction::Create(_)
            | GoalMutationAction::Revise(_)
            | GoalMutationAction::Transition(_) => None,
        };
        Self::from_data(GoalMutationReceiptData {
            request_id: command.request_id(),
            digest: command.digest(),
            actor: command.actor(),
            workspace_revision: command.workspace_revision(),
            goal_id: goal.id(),
            kind: command.kind(),
            expected_revision: command.expected_revision(),
            result_revision: goal.revision(),
            result_status: goal.status().kind(),
            observed_at: command.observed_at(),
            review_id,
        })
    }
}

fn validate_request_id(request_id: GoalMutationRequestId) -> Result<(), GoalMutationError> {
    if request_id.into_uuid().is_nil() {
        Err(GoalMutationError::NilRequestId)
    } else {
        Ok(())
    }
}

fn validate_goal_id(goal_id: GoalId) -> Result<(), GoalMutationError> {
    if goal_id.into_uuid().is_nil() {
        Err(GoalMutationError::NilGoalId)
    } else {
        Ok(())
    }
}

fn validate_actor(actor: ActivityCoordinatorActor) -> Result<(), GoalMutationError> {
    if actor.workspace_id().into_uuid().is_nil() {
        return Err(GoalMutationError::NilActorWorkspaceId);
    }
    if actor.activity_id().into_uuid().is_nil() {
        return Err(GoalMutationError::NilActorActivityId);
    }
    if actor.agent_id().into_uuid().is_nil() {
        return Err(GoalMutationError::NilActorAgentId);
    }
    if actor.session_id().into_uuid().is_nil() {
        return Err(GoalMutationError::NilActorSessionId);
    }
    match actor.principal() {
        AuthenticatedPrincipal::TrustedStdio => Ok(()),
        AuthenticatedPrincipal::DirectToken(id) => validate_principal_uuid(id.into_uuid()),
        AuthenticatedPrincipal::OAuthGrant(id) => validate_principal_uuid(id.into_uuid()),
    }
}

fn validate_principal_uuid(value: Uuid) -> Result<(), GoalMutationError> {
    if value.is_nil() {
        Err(GoalMutationError::NilActorPrincipalId)
    } else {
        Ok(())
    }
}

fn validate_expected_revision(
    kind: GoalMutationKind,
    expected_revision: Option<GoalRevision>,
) -> Result<(), GoalMutationError> {
    let valid = match kind {
        GoalMutationKind::Create => expected_revision.is_none(),
        GoalMutationKind::Revise
        | GoalMutationKind::Pause
        | GoalMutationKind::Resume
        | GoalMutationKind::Block
        | GoalMutationKind::Fail
        | GoalMutationKind::Cancel
        | GoalMutationKind::Complete => expected_revision.is_some(),
    };
    if valid {
        Ok(())
    } else {
        Err(GoalMutationError::ExpectedRevisionShape)
    }
}

fn validate_action_review(action: &GoalMutationAction) -> Result<(), GoalMutationError> {
    if let GoalMutationAction::Complete { review_id } = action
        && review_id.is_nil()
    {
        return Err(GoalMutationError::NilReviewId);
    }
    Ok(())
}

fn validate_receipt_data(data: &GoalMutationReceiptData) -> Result<(), GoalMutationError> {
    validate_request_id(data.request_id)?;
    validate_goal_id(data.goal_id)?;
    validate_actor(data.actor)?;
    validate_expected_revision(data.kind, data.expected_revision)?;
    let expected_result_revision = match data.kind {
        GoalMutationKind::Create => GoalRevision::INITIAL,
        GoalMutationKind::Revise
        | GoalMutationKind::Pause
        | GoalMutationKind::Resume
        | GoalMutationKind::Block
        | GoalMutationKind::Fail
        | GoalMutationKind::Cancel
        | GoalMutationKind::Complete => {
            let Some(expected_revision) = data.expected_revision else {
                return Err(GoalMutationError::ExpectedRevisionShape);
            };
            expected_revision
                .checked_next()
                .map_err(|_| GoalMutationError::InvalidReceiptRevisionStep)?
        }
    };
    if data.result_revision != expected_result_revision {
        return Err(GoalMutationError::InvalidReceiptRevisionStep);
    }
    if !result_status_matches(data.kind, data.result_status) {
        return Err(GoalMutationError::InvalidReceiptResultStatus);
    }
    match (data.kind, data.review_id) {
        (GoalMutationKind::Complete, Some(review_id)) if !review_id.is_nil() => Ok(()),
        (GoalMutationKind::Complete, _) | (_, Some(_)) => {
            Err(GoalMutationError::InvalidReceiptReviewShape)
        }
        (_, None) => Ok(()),
    }
}

fn result_status_matches(kind: GoalMutationKind, status: GoalStatusKind) -> bool {
    match kind {
        GoalMutationKind::Create | GoalMutationKind::Resume => status == GoalStatusKind::Active,
        GoalMutationKind::Revise => !status_is_terminal(status),
        GoalMutationKind::Pause => status == GoalStatusKind::Paused,
        GoalMutationKind::Block => status == GoalStatusKind::Blocked,
        GoalMutationKind::Fail => status == GoalStatusKind::Failed,
        GoalMutationKind::Cancel => status == GoalStatusKind::Cancelled,
        GoalMutationKind::Complete => status == GoalStatusKind::Completed,
    }
}

fn status_is_terminal(status: GoalStatusKind) -> bool {
    matches!(
        status,
        GoalStatusKind::Completed | GoalStatusKind::Failed | GoalStatusKind::Cancelled
    )
}

fn action_matches_goal(action: &GoalMutationAction, goal: &RegisteredGoal) -> bool {
    match action {
        GoalMutationAction::Create(contract) => {
            goal.revision() == GoalRevision::INITIAL
                && goal.status().kind() == GoalStatusKind::Active
                && goal.contract() == contract.as_ref()
        }
        GoalMutationAction::Revise(contract) => {
            !goal.status().is_terminal() && goal.contract() == contract.as_ref()
        }
        GoalMutationAction::Transition(GoalLifecycleAction::Pause) => {
            matches!(goal.status(), GoalStatus::Paused)
        }
        GoalMutationAction::Transition(GoalLifecycleAction::Resume) => {
            matches!(goal.status(), GoalStatus::Active)
        }
        GoalMutationAction::Transition(GoalLifecycleAction::Block(blocker)) => {
            matches!(goal.status(), GoalStatus::Blocked(actual) if actual == blocker)
        }
        GoalMutationAction::Transition(GoalLifecycleAction::Fail(failure)) => {
            matches!(goal.status(), GoalStatus::Failed(actual) if actual == failure)
        }
        GoalMutationAction::Transition(GoalLifecycleAction::Cancel) => {
            matches!(goal.status(), GoalStatus::Cancelled)
        }
        GoalMutationAction::Complete { .. } => {
            matches!(goal.status(), GoalStatus::Completed)
        }
    }
}

fn compute_digest(
    request_id: GoalMutationRequestId,
    actor: ActivityCoordinatorActor,
    workspace_revision: WorkspaceRevision,
    goal_id: GoalId,
    expected_revision: Option<GoalRevision>,
    observed_at: TimestampMillis,
    action: &GoalMutationAction,
) -> [u8; GoalMutationDigest::BYTE_LEN] {
    let mut hasher = Hasher::new();
    hasher.update(DIGEST_DOMAIN);
    hash_uuid(&mut hasher, request_id.into_uuid());
    hash_actor(&mut hasher, actor);
    hash_i64(&mut hasher, workspace_revision.get());
    hash_uuid(&mut hasher, goal_id.into_uuid());
    hash_optional_i64(&mut hasher, expected_revision.map(GoalRevision::get));
    hash_i64(&mut hasher, observed_at.get());
    hash_action(&mut hasher, action);
    *hasher.finalize().as_bytes()
}

fn hash_actor(hasher: &mut Hasher, actor: ActivityCoordinatorActor) {
    hash_uuid(hasher, actor.workspace_id().into_uuid());
    hash_uuid(hasher, actor.activity_id().into_uuid());
    hash_uuid(hasher, actor.agent_id().into_uuid());
    hash_i64(hasher, actor.expected_revision().get());
    hash_principal(hasher, actor.principal());
    hash_uuid(hasher, actor.session_id().into_uuid());
}

fn hash_principal(hasher: &mut Hasher, principal: AuthenticatedPrincipal) {
    match principal {
        AuthenticatedPrincipal::TrustedStdio => hash_u8(hasher, 0),
        AuthenticatedPrincipal::DirectToken(id) => {
            hash_u8(hasher, 1);
            hash_uuid(hasher, id.into_uuid());
        }
        AuthenticatedPrincipal::OAuthGrant(id) => {
            hash_u8(hasher, 2);
            hash_uuid(hasher, id.into_uuid());
        }
    }
}

fn hash_action(hasher: &mut Hasher, action: &GoalMutationAction) {
    hash_u8(hasher, action.kind().code());
    match action {
        GoalMutationAction::Create(contract) | GoalMutationAction::Revise(contract) => {
            hash_contract(hasher, contract);
        }
        GoalMutationAction::Transition(lifecycle) => hash_lifecycle(hasher, lifecycle),
        GoalMutationAction::Complete { review_id } => hash_uuid(hasher, *review_id),
    }
}

fn hash_lifecycle(hasher: &mut Hasher, action: &GoalLifecycleAction) {
    match action {
        GoalLifecycleAction::Pause => hash_u8(hasher, 0),
        GoalLifecycleAction::Resume => hash_u8(hasher, 1),
        GoalLifecycleAction::Block(blocker) => {
            hash_u8(hasher, 2);
            hash_blocker(hasher, blocker);
        }
        GoalLifecycleAction::Fail(failure) => {
            hash_u8(hasher, 3);
            hash_text(hasher, failure.reason().as_str());
        }
        GoalLifecycleAction::Cancel => hash_u8(hasher, 4),
    }
}

fn hash_blocker(hasher: &mut Hasher, blocker: &GoalBlocker) {
    hash_u8(
        hasher,
        match blocker.kind() {
            GoalBlockerKind::ApprovalWait => 0,
            GoalBlockerKind::ExternalDependency => 1,
            GoalBlockerKind::VerificationFailure => 2,
            GoalBlockerKind::ResourceLimit => 3,
            GoalBlockerKind::UserDecision => 4,
            GoalBlockerKind::Other => 5,
        },
    );
    hash_text(hasher, blocker.reason().as_str());
}

fn hash_contract(hasher: &mut Hasher, contract: &GoalContract) {
    hash_text(hasher, contract.objective().as_str());
    hash_statements(hasher, contract.success_criteria());
    hash_statements(hasher, contract.constraints());
    hash_statements(hasher, contract.out_of_scope());
    hash_u64(hasher, contract.verification_requirements().len() as u64);
    for requirement in contract.verification_requirements() {
        hash_verification_requirement(hasher, requirement);
    }
    hash_statements(hasher, contract.stop_conditions());
}

fn hash_statements(hasher: &mut Hasher, statements: &[GoalStatement]) {
    hash_u64(hasher, statements.len() as u64);
    for statement in statements {
        hash_text(hasher, statement.as_str());
    }
}

fn hash_verification_requirement(hasher: &mut Hasher, requirement: &GoalVerificationRequirement) {
    match requirement {
        GoalVerificationRequirement::ExecutionSucceeded {
            request_digest,
            description,
        } => {
            hash_u8(hasher, 0);
            hash_bytes(hasher, request_digest.as_bytes());
            hash_text(hasher, description.as_str());
        }
        GoalVerificationRequirement::FilePresent {
            path,
            expected_hash,
            description,
        } => {
            hash_u8(hasher, 1);
            hash_bytes(hasher, path.as_path().as_os_str().as_encoded_bytes());
            hash_optional_bytes(
                hasher,
                expected_hash.as_ref().map(FileContentHash::as_bytes),
            );
            hash_text(hasher, description.as_str());
        }
        GoalVerificationRequirement::ChangeSetSealed {
            change_set_id,
            description,
        } => {
            hash_u8(hasher, 2);
            hash_uuid(hasher, change_set_id.into_uuid());
            hash_text(hasher, description.as_str());
        }
        GoalVerificationRequirement::CheckpointReady {
            checkpoint_id,
            description,
        } => {
            hash_u8(hasher, 3);
            hash_uuid(hasher, checkpoint_id.into_uuid());
            hash_text(hasher, description.as_str());
        }
    }
}

fn hash_optional_i64(hasher: &mut Hasher, value: Option<i64>) {
    match value {
        Some(value) => {
            hash_u8(hasher, 1);
            hash_i64(hasher, value);
        }
        None => hash_u8(hasher, 0),
    }
}

fn hash_optional_bytes(hasher: &mut Hasher, value: Option<&[u8; 32]>) {
    match value {
        Some(value) => {
            hash_u8(hasher, 1);
            hash_bytes(hasher, value);
        }
        None => hash_u8(hasher, 0),
    }
}

fn hash_uuid(hasher: &mut Hasher, value: Uuid) {
    hash_bytes(hasher, value.as_bytes());
}

fn hash_text(hasher: &mut Hasher, value: &str) {
    hash_bytes(hasher, value.as_bytes());
}

fn hash_bytes(hasher: &mut Hasher, value: &[u8]) {
    hash_u64(hasher, value.len() as u64);
    hasher.update(value);
}

fn hash_u8(hasher: &mut Hasher, value: u8) {
    hasher.update(&[value]);
}

fn hash_u64(hasher: &mut Hasher, value: u64) {
    hasher.update(&value.to_le_bytes());
}

fn hash_i64(hasher: &mut Hasher, value: i64) {
    hasher.update(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ActivityCoordinatorRevision, ActivityId, AgentInstanceId, AgentSessionId, DirectTokenId,
        WorkspaceId,
    };

    fn contract(statement: &str) -> Result<GoalContract, Box<dyn std::error::Error>> {
        Ok(GoalContract::new(
            crate::GoalObjective::new("objective".to_owned())?,
            vec![crate::GoalStatement::new(statement.to_owned())?],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )?)
    }

    fn actor() -> ActivityCoordinatorActor {
        ActivityCoordinatorActor::new(
            WorkspaceId::from_uuid(Uuid::from_u128(1)),
            ActivityId::from_uuid(Uuid::from_u128(2)),
            AgentInstanceId::from_uuid(Uuid::from_u128(3)),
            ActivityCoordinatorRevision::INITIAL,
            AuthenticatedPrincipal::DirectToken(DirectTokenId::from_uuid(Uuid::from_u128(4))),
            AgentSessionId::from_uuid(Uuid::from_u128(5)),
        )
    }

    #[test]
    fn digest_covers_contract_and_rejects_nil_actor_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        let request_id = GoalMutationRequestId::from_uuid(Uuid::from_u128(6));
        let goal_id = GoalId::from_uuid(Uuid::from_u128(7));
        let first = GoalMutationCommand::new(
            request_id,
            actor(),
            WorkspaceRevision::INITIAL,
            goal_id,
            None,
            TimestampMillis::new(10)?,
            GoalMutationAction::Create(Box::new(contract("first")?)),
        )?;
        let changed = GoalMutationCommand::new(
            request_id,
            actor(),
            WorkspaceRevision::INITIAL,
            goal_id,
            None,
            TimestampMillis::new(10)?,
            GoalMutationAction::Create(Box::new(contract("changed")?)),
        )?;
        assert_ne!(first.digest(), changed.digest());

        let nil_actor = ActivityCoordinatorActor::new(
            WorkspaceId::from_uuid(Uuid::nil()),
            ActivityId::from_uuid(Uuid::from_u128(2)),
            AgentInstanceId::from_uuid(Uuid::from_u128(3)),
            ActivityCoordinatorRevision::INITIAL,
            AuthenticatedPrincipal::DirectToken(DirectTokenId::from_uuid(Uuid::from_u128(4))),
            AgentSessionId::from_uuid(Uuid::from_u128(5)),
        );
        assert_eq!(
            GoalMutationCommand::new(
                request_id,
                nil_actor,
                WorkspaceRevision::INITIAL,
                goal_id,
                None,
                TimestampMillis::new(10)?,
                GoalMutationAction::Create(Box::new(contract("first")?)),
            ),
            Err(GoalMutationError::NilActorWorkspaceId)
        );
        Ok(())
    }
}
