//! Goal planning HTTP adapters over the Coordinator-owned control boundary.
//!
//! This module owns only strict wire decoding and bounded JSON projection.
//! Goal lifecycle, Coordinator fencing, idempotency, completion evidence, and
//! historical receipt authority remain in Forge domain/control/persistence.

use forge_control::{ForgeControlClient, ResolvedWorkspaceScope};
use forge_domain::{
    ActivityId, AuthenticatedPrincipal, ChangeSetId, CheckpointId, GoalBlocker, GoalBlockerKind,
    GoalCompletionBlocker, GoalContract, GoalEvidenceRef, GoalFailure, GoalHardCheck, GoalId,
    GoalLifecycleAction, GoalMutationAction, GoalMutationCommand, GoalMutationDigest,
    GoalMutationKind, GoalMutationRequestId, GoalObjective, GoalPublicReason, GoalReview,
    GoalStatement, GoalVerificationRequirement,
};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use super::planning::{PlanningAuthorityDto, decode_authority};
use super::{decode_digest_hex, decode_goal_revision, decode_timestamp, parse_body};
use crate::error::ForgeError;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateBody {
    authority: PlanningAuthorityDto,
    mutation_request_id: Uuid,
    goal_id: Uuid,
    observed_at_ms: i64,
    contract: GoalContractDto,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviseBody {
    authority: PlanningAuthorityDto,
    mutation_request_id: Uuid,
    goal_id: Uuid,
    expected_goal_revision: i64,
    observed_at_ms: i64,
    contract: GoalContractDto,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransitionBody {
    authority: PlanningAuthorityDto,
    mutation_request_id: Uuid,
    goal_id: Uuid,
    expected_goal_revision: i64,
    observed_at_ms: i64,
    action: TransitionActionDto,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompleteBody {
    authority: PlanningAuthorityDto,
    mutation_request_id: Uuid,
    goal_id: Uuid,
    expected_goal_revision: i64,
    observed_at_ms: i64,
    review_id: Uuid,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadbackBody {
    scope: super::ScopeDto,
    activity_id: Uuid,
    goal_id: Uuid,
    mutation_request_id: Uuid,
    expected_request_digest: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GoalContractDto {
    objective: String,
    success_criteria: Vec<String>,
    constraints: Vec<String>,
    out_of_scope: Vec<String>,
    verification_requirements: Vec<VerificationRequirementDto>,
    stop_conditions: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum VerificationRequirementDto {
    ExecutionSucceeded {
        request_digest: String,
        description: String,
    },
    FilePresent {
        path_base64: String,
        #[serde(default)]
        expected_hash: Option<String>,
        description: String,
    },
    ChangeSetSealed {
        change_set_id: Uuid,
        description: String,
    },
    CheckpointReady {
        checkpoint_id: Uuid,
        description: String,
    },
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum TransitionActionDto {
    Pause,
    Resume,
    Block {
        blocker_kind: BlockerKindDto,
        reason: String,
    },
    Fail {
        reason: String,
    },
    Cancel,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum BlockerKindDto {
    ApprovalWait,
    ExternalDependency,
    VerificationFailure,
    ResourceLimit,
    UserDecision,
    Other,
}

/// Parse a Coordinator-authorized initial Goal contract mutation.
pub(super) fn parse_create(
    value: &Value,
) -> Result<forge_control::GoalMutationRequest, ForgeError> {
    let body: CreateBody = parse_body(value, "goal.create payload is invalid")?;
    let (scope, actor) = decode_authority(&body.authority)?;
    let contract = parse_contract(body.contract)?;
    build_request(
        scope,
        actor,
        body.mutation_request_id,
        body.goal_id,
        None,
        body.observed_at_ms,
        GoalMutationAction::Create(Box::new(contract)),
    )
}

/// Parse a Coordinator-authorized Goal contract revision mutation.
pub(super) fn parse_revise(
    value: &Value,
) -> Result<forge_control::GoalMutationRequest, ForgeError> {
    let body: ReviseBody = parse_body(value, "goal.revise payload is invalid")?;
    let (scope, actor) = decode_authority(&body.authority)?;
    let contract = parse_contract(body.contract)?;
    build_request(
        scope,
        actor,
        body.mutation_request_id,
        body.goal_id,
        Some(body.expected_goal_revision),
        body.observed_at_ms,
        GoalMutationAction::Revise(Box::new(contract)),
    )
}

/// Parse a Coordinator-authorized Goal lifecycle transition mutation.
pub(super) fn parse_transition(
    value: &Value,
) -> Result<forge_control::GoalMutationRequest, ForgeError> {
    let body: TransitionBody = parse_body(value, "goal.transition payload is invalid")?;
    let (scope, actor) = decode_authority(&body.authority)?;
    let action = parse_transition_action(body.action)?;
    build_request(
        scope,
        actor,
        body.mutation_request_id,
        body.goal_id,
        Some(body.expected_goal_revision),
        body.observed_at_ms,
        GoalMutationAction::Transition(action),
    )
}

/// Parse a Coordinator-authorized Goal completion mutation.
pub(super) fn parse_complete(
    value: &Value,
) -> Result<forge_control::GoalMutationRequest, ForgeError> {
    let body: CompleteBody = parse_body(value, "goal.complete payload is invalid")?;
    let (scope, actor) = decode_authority(&body.authority)?;
    if body.review_id.is_nil() {
        return Err(ForgeError::invalid_input("goal review id must not be nil"));
    }
    build_request(
        scope,
        actor,
        body.mutation_request_id,
        body.goal_id,
        Some(body.expected_goal_revision),
        body.observed_at_ms,
        GoalMutationAction::Complete {
            review_id: body.review_id,
        },
    )
}

/// Parse one historical Goal mutation receipt identity.  The optional digest
/// is an equality fence; it never grants retry authority.
pub(super) fn parse_readback(
    value: &Value,
) -> Result<forge_control::GoalMutationReadbackRequest, ForgeError> {
    let body: ReadbackBody = parse_body(value, "goal.mutation_readback payload is invalid")?;
    require_id(body.scope.workspace_id, "scope workspace id")?;
    require_id(body.scope.locator.location_id, "scope location id")?;
    let expected_request_digest = body
        .expected_request_digest
        .as_deref()
        .map(parse_mutation_digest)
        .transpose()?;
    Ok(forge_control::GoalMutationReadbackRequest {
        scope: super::decode_scope(&body.scope)?,
        activity_id: forge_domain::ActivityId::from_uuid(require_id(
            body.activity_id,
            "activity id",
        )?),
        goal_id: GoalId::from_uuid(require_id(body.goal_id, "goal id")?),
        mutation_request_id: GoalMutationRequestId::from_uuid(require_id(
            body.mutation_request_id,
            "mutation request id",
        )?),
        expected_request_digest,
    })
}

/// Execute one Goal mutation and return its immutable receipt plus the
/// explicitly labeled current projection observed by that control call.
pub(super) fn execute_mutation(
    client: &ForgeControlClient,
    request: &forge_control::GoalMutationRequest,
) -> Result<Value, ForgeError> {
    let scope = super::source::scope_json(&request.scope)?;
    let result = client
        .goal_mutation(request.clone())
        .map_err(|error| super::forge_error_of_client(&error))?;
    Ok(json!({
        "scope": scope,
        "receipt": receipt_json(result.receipt()),
        "current_goal": result.current_goal().map(super::plan::goal_json),
        "replayed": result.replayed(),
    }))
}

/// Execute a historical receipt query.  The query never performs an
/// additional Goal read, and therefore never presents a later Goal as the
/// historical mutation result.
pub(super) fn execute_readback(
    client: &ForgeControlClient,
    request: &forge_control::GoalMutationReadbackRequest,
) -> Result<Value, ForgeError> {
    let scope = super::source::scope_json(&request.scope)?;
    let receipt = client
        .goal_mutation_readback(request.clone())
        .map_err(|error| super::forge_error_of_client(&error))?;
    Ok(json!({
        "scope": scope,
        "activity_id": request.activity_id.into_uuid(),
        "goal_id": request.goal_id.into_uuid(),
        "mutation_request_id": request.mutation_request_id.into_uuid(),
        "found": receipt.is_some(),
        "receipt": receipt.as_ref().map(receipt_json),
        "retry_authorized": false,
    }))
}

/// Execute the canonical bounded Goal completion review used by
/// `goal.complete`.  The projection retains every hard-check and blocker
/// identity so a caller can explain why completion is currently unavailable.
pub(super) fn execute_review(
    client: &ForgeControlClient,
    scope: &ResolvedWorkspaceScope,
    activity_id: ActivityId,
    goal_id: GoalId,
) -> Result<Value, ForgeError> {
    let review = client
        .goal_review(scope.clone(), activity_id, goal_id)
        .map_err(|error| super::forge_error_of_client(&error))?;
    Ok(review_json(&review))
}

fn review_json(value: &GoalReview) -> Value {
    json!({
        "goal_id": value.goal_id().into_uuid(),
        "goal_revision": value.goal_revision().get(),
        "hard_checks": value.hard_checks().iter().map(hard_check_json).collect::<Vec<_>>(),
        "blockers": value.blockers().iter().map(blocker_json).collect::<Vec<_>>(),
        "manual_assessment_required": value.manual_assessment_required(),
        "can_complete": value.can_complete(),
    })
}

fn hard_check_json(value: &GoalHardCheck) -> Value {
    let result = match value {
        GoalHardCheck::Passed { .. } => "passed",
        GoalHardCheck::Missing { .. } => "missing",
        GoalHardCheck::Failed { .. } => "failed",
    };
    json!({
        "requirement_index": value.requirement_index(),
        "result": result,
    })
}

fn blocker_json(value: &GoalCompletionBlocker) -> Value {
    match value {
        GoalCompletionBlocker::RequiredVerification { requirement_index } => json!({
            "kind": "required_verification",
            "requirement_index": requirement_index,
        }),
        GoalCompletionBlocker::PendingApproval(id) => json!({
            "kind": "pending_approval",
            "approval_id": id.into_uuid(),
        }),
        GoalCompletionBlocker::ActiveExecution(id) => json!({
            "kind": "active_execution",
            "execution_id": id.into_uuid(),
        }),
        GoalCompletionBlocker::UnsealedEvidence(value) => json!({
            "kind": "unsealed_evidence",
            "evidence": evidence_json(*value),
        }),
    }
}

fn evidence_json(value: GoalEvidenceRef) -> Value {
    match value {
        GoalEvidenceRef::ChangeSet(id) => json!({
            "kind": "change_set",
            "id": id.into_uuid(),
        }),
        GoalEvidenceRef::Execution(id) => json!({
            "kind": "execution",
            "id": id.into_uuid(),
        }),
        GoalEvidenceRef::Approval(id) => json!({
            "kind": "approval",
            "id": id.into_uuid(),
        }),
        GoalEvidenceRef::Checkpoint(id) => json!({
            "kind": "checkpoint",
            "id": id.into_uuid(),
        }),
    }
}

fn build_request(
    scope: ResolvedWorkspaceScope,
    actor: forge_domain::ActivityCoordinatorActor,
    request_id: Uuid,
    goal_id: Uuid,
    expected_revision: Option<i64>,
    observed_at_ms: i64,
    action: GoalMutationAction,
) -> Result<forge_control::GoalMutationRequest, ForgeError> {
    let command = GoalMutationCommand::new(
        GoalMutationRequestId::from_uuid(require_id(request_id, "mutation request id")?),
        actor,
        scope.workspace_revision(),
        GoalId::from_uuid(require_id(goal_id, "goal id")?),
        expected_revision.map(decode_goal_revision).transpose()?,
        decode_timestamp(observed_at_ms)?,
        action,
    )
    .map_err(|_| ForgeError::invalid_input("goal mutation is invalid"))?;
    Ok(forge_control::GoalMutationRequest { scope, command })
}

fn parse_contract(value: GoalContractDto) -> Result<GoalContract, ForgeError> {
    let objective = GoalObjective::new(value.objective)
        .map_err(|_| ForgeError::invalid_input("goal contract objective is invalid"))?;
    let success_criteria = parse_statements(value.success_criteria)?;
    let constraints = parse_statements(value.constraints)?;
    let out_of_scope = parse_statements(value.out_of_scope)?;
    let verification_requirements = value
        .verification_requirements
        .into_iter()
        .map(parse_verification_requirement)
        .collect::<Result<Vec<_>, _>>()?;
    let stop_conditions = parse_statements(value.stop_conditions)?;
    GoalContract::new(
        objective,
        success_criteria,
        constraints,
        out_of_scope,
        verification_requirements,
        stop_conditions,
    )
    .map_err(|_| ForgeError::invalid_input("goal contract is invalid"))
}

fn parse_statements(values: Vec<String>) -> Result<Vec<GoalStatement>, ForgeError> {
    values
        .into_iter()
        .map(|value| {
            GoalStatement::new(value)
                .map_err(|_| ForgeError::invalid_input("goal contract statement is invalid"))
        })
        .collect()
}

fn parse_verification_requirement(
    value: VerificationRequirementDto,
) -> Result<GoalVerificationRequirement, ForgeError> {
    match value {
        VerificationRequirementDto::ExecutionSucceeded {
            request_digest,
            description,
        } => Ok(GoalVerificationRequirement::ExecutionSucceeded {
            request_digest: decode_digest_hex(&request_digest)?,
            description: GoalStatement::new(description)
                .map_err(|_| ForgeError::invalid_input("verification description is invalid"))?,
        }),
        VerificationRequirementDto::FilePresent {
            path_base64,
            expected_hash,
            description,
        } => Ok(GoalVerificationRequirement::FilePresent {
            path: super::source::decode_relative_path(&path_base64)?,
            expected_hash: expected_hash
                .as_deref()
                .map(super::source_write::parse_content_hash)
                .transpose()?,
            description: GoalStatement::new(description)
                .map_err(|_| ForgeError::invalid_input("verification description is invalid"))?,
        }),
        VerificationRequirementDto::ChangeSetSealed {
            change_set_id,
            description,
        } => Ok(GoalVerificationRequirement::ChangeSetSealed {
            change_set_id: ChangeSetId::from_uuid(require_id(change_set_id, "change set id")?),
            description: GoalStatement::new(description)
                .map_err(|_| ForgeError::invalid_input("verification description is invalid"))?,
        }),
        VerificationRequirementDto::CheckpointReady {
            checkpoint_id,
            description,
        } => Ok(GoalVerificationRequirement::CheckpointReady {
            checkpoint_id: CheckpointId::from_uuid(require_id(checkpoint_id, "checkpoint id")?),
            description: GoalStatement::new(description)
                .map_err(|_| ForgeError::invalid_input("verification description is invalid"))?,
        }),
    }
}

fn parse_transition_action(
    value: TransitionActionDto,
) -> Result<forge_domain::GoalLifecycleAction, ForgeError> {
    Ok(match value {
        TransitionActionDto::Pause => GoalLifecycleAction::Pause,
        TransitionActionDto::Resume => GoalLifecycleAction::Resume,
        TransitionActionDto::Block {
            blocker_kind,
            reason,
        } => GoalLifecycleAction::Block(GoalBlocker::new(
            blocker_kind.into_domain(),
            GoalPublicReason::new(reason)
                .map_err(|_| ForgeError::invalid_input("goal blocker reason is invalid"))?,
        )),
        TransitionActionDto::Fail { reason } => GoalLifecycleAction::Fail(GoalFailure::new(
            GoalPublicReason::new(reason)
                .map_err(|_| ForgeError::invalid_input("goal failure reason is invalid"))?,
        )),
        TransitionActionDto::Cancel => GoalLifecycleAction::Cancel,
    })
}

impl BlockerKindDto {
    const fn into_domain(self) -> GoalBlockerKind {
        match self {
            Self::ApprovalWait => GoalBlockerKind::ApprovalWait,
            Self::ExternalDependency => GoalBlockerKind::ExternalDependency,
            Self::VerificationFailure => GoalBlockerKind::VerificationFailure,
            Self::ResourceLimit => GoalBlockerKind::ResourceLimit,
            Self::UserDecision => GoalBlockerKind::UserDecision,
            Self::Other => GoalBlockerKind::Other,
        }
    }
}

fn parse_mutation_digest(value: &str) -> Result<GoalMutationDigest, ForgeError> {
    if value.len() != GoalMutationDigest::BYTE_LEN * 2 {
        return Err(ForgeError::invalid_input(
            "goal mutation digest must be 64 lowercase hex characters",
        ));
    }
    let bytes = super::decode_hex(value)?;
    let bytes: [u8; GoalMutationDigest::BYTE_LEN] = bytes.try_into().map_err(|_| {
        ForgeError::invalid_input("goal mutation digest must be 64 lowercase hex characters")
    })?;
    if super::encode_hex(&bytes) != value {
        return Err(ForgeError::invalid_input(
            "goal mutation digest must be lowercase hex",
        ));
    }
    Ok(GoalMutationDigest::from_bytes(bytes))
}

fn receipt_json(value: &forge_domain::GoalMutationReceipt) -> Value {
    let data = value.data();
    json!({
        "request_id": data.request_id.into_uuid(),
        "mutation_request_id": data.request_id.into_uuid(),
        "request_digest": super::encode_hex(data.digest.as_bytes()),
        "actor": actor_json(data.actor),
        "workspace_revision": data.workspace_revision.get(),
        "goal_id": data.goal_id.into_uuid(),
        "kind": mutation_kind_json(data.kind),
        "expected_goal_revision": data.expected_revision.map(forge_domain::GoalRevision::get),
        "result_goal_revision": data.result_revision.get(),
        "result_status": goal_status_json(data.result_status),
        "observed_at_ms": data.observed_at.get(),
        "review_id": data.review_id,
    })
}

fn actor_json(value: forge_domain::ActivityCoordinatorActor) -> Value {
    json!({
        "workspace_id": value.workspace_id().into_uuid(),
        "activity_id": value.activity_id().into_uuid(),
        "agent_id": value.agent_id().into_uuid(),
        "expected_coordinator_revision": value.expected_revision().get(),
        "principal": principal_json(value.principal()),
        "session_id": value.session_id().into_uuid(),
    })
}

pub(super) fn principal_json(value: AuthenticatedPrincipal) -> Value {
    match value {
        AuthenticatedPrincipal::TrustedStdio => json!({ "kind": "trusted_stdio" }),
        AuthenticatedPrincipal::DirectToken(id) => {
            json!({ "kind": "direct_token", "token_id": id.into_uuid() })
        }
        AuthenticatedPrincipal::OAuthGrant(id) => {
            json!({ "kind": "oauth_grant", "grant_id": id.into_uuid() })
        }
    }
}

fn mutation_kind_json(value: GoalMutationKind) -> &'static str {
    match value {
        GoalMutationKind::Create => "create",
        GoalMutationKind::Revise => "revise",
        GoalMutationKind::Pause => "pause",
        GoalMutationKind::Resume => "resume",
        GoalMutationKind::Block => "block",
        GoalMutationKind::Fail => "fail",
        GoalMutationKind::Cancel => "cancel",
        GoalMutationKind::Complete => "complete",
    }
}

fn goal_status_json(value: forge_domain::GoalStatusKind) -> &'static str {
    match value {
        forge_domain::GoalStatusKind::Active => "active",
        forge_domain::GoalStatusKind::Paused => "paused",
        forge_domain::GoalStatusKind::Blocked => "blocked",
        forge_domain::GoalStatusKind::Completed => "completed",
        forge_domain::GoalStatusKind::Failed => "failed",
        forge_domain::GoalStatusKind::Cancelled => "cancelled",
    }
}

fn require_id(value: Uuid, label: &str) -> Result<Uuid, ForgeError> {
    if value.is_nil() {
        return Err(ForgeError::invalid_input(format!(
            "{label} must not be nil"
        )));
    }
    Ok(value)
}
