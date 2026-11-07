//! Strict HTTP boundary for exact Forge-owned evaluation source evidence.

use forge_control::{
    EvaluationEvidenceOperation, EvaluationEvidenceRequest, EvaluationEvidenceService,
    ResolvedWorkspaceScope,
};
use forge_domain::{
    ActivityId, AgentAssignmentId, AgentAssignmentRevision, AgentInstanceId, AgentSessionId,
    EvaluationCutId, EvaluationDigest, EvaluationManifestId, EvaluationManifestMember,
    EvaluationManifestProposal, EvaluationObligationId, EvaluationPlanBinding, EvaluationPlanId,
    EvaluationReviewCutId, EvaluationRevision, EvaluationSourceIdentity, EvaluationT1CloseRequest,
    EvaluationWorkUnitId, ForgeBackendId, TimestampMillis, WorkspaceId,
};
use forge_persistence::EvaluationEvidenceMutationIdentity;
use serde::Deserialize;
use serde_json::Value;
use std::error::Error;
use uuid::Uuid;

use super::{BridgeClients, CommandOp, ScopeDto, decode_scope, parse_body};
use crate::error::{ErrorCode, ForgeError, ReadbackHint};

pub mod wire;

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ServiceBody {
    backend_id: Uuid,
    destination_id: Uuid,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceBody {
    backend_id: Uuid,
    workspace_id: Uuid,
    activity_id: Uuid,
    delegation_migration_id: Uuid,
    delegation_destination_id: Uuid,
    delegation_freeze_revision: i64,
    delegation_manifest_digest: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanBody {
    plan_id: Uuid,
    revision: i64,
    digest: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MemberBody {
    work_unit_id: Uuid,
    obligation_id: Uuid,
    assignment_id: Uuid,
    assignment_revision: i64,
    target_agent_id: Uuid,
    target_session_id: Uuid,
    criteria_digest: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProposalBody {
    manifest_id: Uuid,
    revision: i64,
    source: SourceBody,
    plan: PlanBody,
    deadline_ms: i64,
    digest: String,
    members: Vec<MemberBody>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SealBody {
    scope: ScopeDto,
    service: ServiceBody,
    proposal: ProposalBody,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestGetBody {
    scope: ScopeDto,
    service: ServiceBody,
    source: SourceBody,
    manifest_id: Uuid,
    revision: i64,
    digest: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct T1Body {
    scope: ScopeDto,
    service: ServiceBody,
    source: SourceBody,
    cut_id: Uuid,
    manifest_id: Uuid,
    manifest_revision: i64,
    manifest_digest: String,
    deadline_ms: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewCutBody {
    scope: ScopeDto,
    service: ServiceBody,
    source: SourceBody,
    review_cut_id: Uuid,
    t1_cut_id: Uuid,
    manifest_id: Uuid,
    manifest_revision: i64,
    manifest_digest: String,
    deadline_ms: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SubmissionReceiptBody {
    scope: ScopeDto,
    service: ServiceBody,
    source: SourceBody,
    manifest_id: Uuid,
    manifest_revision: i64,
    manifest_digest: String,
    assignment_id: Uuid,
    submitted_revision: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewReceiptBody {
    scope: ScopeDto,
    service: ServiceBody,
    source: SourceBody,
    manifest_id: Uuid,
    manifest_revision: i64,
    manifest_digest: String,
    assignment_id: Uuid,
    submitted_revision: i64,
    review_revision: i64,
}

/// Strictly parsed HTTP command plus the echoed service identity that must be
/// checked against the authenticated backend configuration before dispatch.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluationEvidenceCommand {
    service: ServiceBody,
    request: EvaluationEvidenceRequest,
}

impl EvaluationEvidenceCommand {
    pub const fn op(&self) -> CommandOp {
        match &self.request.operation {
            EvaluationEvidenceOperation::SealManifest { .. } => CommandOp::EvaluationManifestSeal,
            EvaluationEvidenceOperation::GetManifest { .. } => CommandOp::EvaluationManifestGet,
            EvaluationEvidenceOperation::CloseT1 { .. } => CommandOp::EvaluationT1Close,
            EvaluationEvidenceOperation::GetT1Cut { .. } => CommandOp::EvaluationT1Get,
            EvaluationEvidenceOperation::CreateReviewCut { .. } => {
                CommandOp::EvaluationReviewCutCreate
            }
            EvaluationEvidenceOperation::GetReviewCut { .. } => CommandOp::EvaluationReviewCutGet,
            EvaluationEvidenceOperation::GetSubmissionReceipt { .. } => {
                CommandOp::EvaluationSubmissionReceiptGet
            }
            EvaluationEvidenceOperation::GetReviewReceipt { .. } => {
                CommandOp::EvaluationReviewReceiptGet
            }
        }
    }

    pub const fn scope(&self) -> &ResolvedWorkspaceScope {
        &self.request.scope
    }

    pub fn readback_hint(&self) -> Option<ReadbackHint> {
        self.request.mutation_identity().as_ref().map(|identity| {
            ReadbackHint::evaluation_evidence(
                self.request.scope.workspace_id().into_uuid(),
                identity,
            )
        })
    }
}

pub(super) fn parse(
    op: CommandOp,
    payload: &Value,
) -> Result<EvaluationEvidenceCommand, ForgeError> {
    match op {
        CommandOp::EvaluationManifestSeal => parse_seal(payload),
        CommandOp::EvaluationManifestGet => parse_manifest_get(payload),
        CommandOp::EvaluationT1Close | CommandOp::EvaluationT1Get => parse_t1(op, payload),
        CommandOp::EvaluationReviewCutCreate | CommandOp::EvaluationReviewCutGet => {
            parse_review_cut(op, payload)
        }
        CommandOp::EvaluationSubmissionReceiptGet => parse_submission_receipt(payload),
        CommandOp::EvaluationReviewReceiptGet => parse_review_receipt(payload),
        _ => Err(ForgeError::invalid_input(
            "operation is not an evaluation evidence operation",
        )),
    }
}

fn parse_seal(payload: &Value) -> Result<EvaluationEvidenceCommand, ForgeError> {
    let body: SealBody = parse_body(payload, "evaluation manifest seal payload is invalid")?;
    let scope = decode_scope(&body.scope)?;
    let proposal = decode_proposal(body.proposal)?;
    if proposal.source().workspace_id() != scope.workspace_id() {
        return Err(ForgeError::invalid_input(
            "evaluation manifest source does not match the selected Workspace",
        ));
    }
    Ok(command(
        body.service,
        EvaluationEvidenceRequest::new(
            scope,
            proposal.source(),
            EvaluationEvidenceOperation::SealManifest { proposal },
        ),
    ))
}

fn parse_manifest_get(payload: &Value) -> Result<EvaluationEvidenceCommand, ForgeError> {
    let body: ManifestGetBody = parse_body(payload, "evaluation manifest read payload is invalid")?;
    let scope = decode_scope(&body.scope)?;
    let source = decode_source(&body.source)?;
    require_source_scope(&scope, source)?;
    let operation = EvaluationEvidenceOperation::GetManifest {
        manifest_id: manifest_id(body.manifest_id)?,
        revision: evaluation_revision(body.revision)?,
        digest: decode_digest(&body.digest)?,
    };
    Ok(command(
        body.service,
        EvaluationEvidenceRequest::new(scope, source, operation),
    ))
}

fn parse_t1(op: CommandOp, payload: &Value) -> Result<EvaluationEvidenceCommand, ForgeError> {
    let body: T1Body = parse_body(payload, "evaluation T1 payload is invalid")?;
    let scope = decode_scope(&body.scope)?;
    let source = decode_source(&body.source)?;
    require_source_scope(&scope, source)?;
    let request = EvaluationT1CloseRequest::new(
        EvaluationCutId::new(require_non_nil(body.cut_id, "evaluation cut id")?)
            .map_err(|_| ForgeError::invalid_input("evaluation cut id is invalid"))?,
        manifest_id(body.manifest_id)?,
        evaluation_revision(body.manifest_revision)?,
        decode_digest(&body.manifest_digest)?,
        decode_timestamp(body.deadline_ms)?,
    );
    let operation = if op == CommandOp::EvaluationT1Close {
        EvaluationEvidenceOperation::CloseT1 { request }
    } else {
        EvaluationEvidenceOperation::GetT1Cut { request }
    };
    Ok(command(
        body.service,
        EvaluationEvidenceRequest::new(scope, source, operation),
    ))
}

fn parse_review_cut(
    op: CommandOp,
    payload: &Value,
) -> Result<EvaluationEvidenceCommand, ForgeError> {
    let body: ReviewCutBody = parse_body(payload, "evaluation review cut payload is invalid")?;
    let scope = decode_scope(&body.scope)?;
    let source = decode_source(&body.source)?;
    require_source_scope(&scope, source)?;
    let review_cut_id = EvaluationReviewCutId::new(require_non_nil(
        body.review_cut_id,
        "evaluation review cut id",
    )?)
    .map_err(|_| ForgeError::invalid_input("evaluation review cut id is invalid"))?;
    let t1_request = EvaluationT1CloseRequest::new(
        EvaluationCutId::new(require_non_nil(body.t1_cut_id, "evaluation T1 cut id")?)
            .map_err(|_| ForgeError::invalid_input("evaluation T1 cut id is invalid"))?,
        manifest_id(body.manifest_id)?,
        evaluation_revision(body.manifest_revision)?,
        decode_digest(&body.manifest_digest)?,
        decode_timestamp(body.deadline_ms)?,
    );
    let operation = if op == CommandOp::EvaluationReviewCutCreate {
        EvaluationEvidenceOperation::CreateReviewCut {
            review_cut_id,
            t1_request,
        }
    } else {
        EvaluationEvidenceOperation::GetReviewCut {
            review_cut_id,
            t1_request,
        }
    };
    Ok(command(
        body.service,
        EvaluationEvidenceRequest::new(scope, source, operation),
    ))
}

fn parse_submission_receipt(payload: &Value) -> Result<EvaluationEvidenceCommand, ForgeError> {
    let body: SubmissionReceiptBody =
        parse_body(payload, "evaluation submission receipt payload is invalid")?;
    let scope = decode_scope(&body.scope)?;
    let source = decode_source(&body.source)?;
    require_source_scope(&scope, source)?;
    let operation = EvaluationEvidenceOperation::GetSubmissionReceipt {
        manifest_id: manifest_id(body.manifest_id)?,
        manifest_revision: evaluation_revision(body.manifest_revision)?,
        manifest_digest: decode_digest(&body.manifest_digest)?,
        assignment_id: AgentAssignmentId::from_uuid(require_non_nil(
            body.assignment_id,
            "evaluation assignment id",
        )?),
        submitted_revision: assignment_revision(body.submitted_revision)?,
    };
    Ok(command(
        body.service,
        EvaluationEvidenceRequest::new(scope, source, operation),
    ))
}

fn parse_review_receipt(payload: &Value) -> Result<EvaluationEvidenceCommand, ForgeError> {
    let body: ReviewReceiptBody =
        parse_body(payload, "evaluation review receipt payload is invalid")?;
    let scope = decode_scope(&body.scope)?;
    let source = decode_source(&body.source)?;
    require_source_scope(&scope, source)?;
    let operation = EvaluationEvidenceOperation::GetReviewReceipt {
        manifest_id: manifest_id(body.manifest_id)?,
        manifest_revision: evaluation_revision(body.manifest_revision)?,
        manifest_digest: decode_digest(&body.manifest_digest)?,
        assignment_id: AgentAssignmentId::from_uuid(require_non_nil(
            body.assignment_id,
            "evaluation assignment id",
        )?),
        submitted_revision: assignment_revision(body.submitted_revision)?,
        review_revision: assignment_revision(body.review_revision)?,
    };
    Ok(command(
        body.service,
        EvaluationEvidenceRequest::new(scope, source, operation),
    ))
}

pub(super) fn execute(
    clients: &BridgeClients,
    command: &EvaluationEvidenceCommand,
) -> Result<Value, ForgeError> {
    validate_service_identity(command, clients.backend_id, clients.destination_id)?;
    let service = EvaluationEvidenceService::new(clients.backend_id, clients.destination_id);
    let response = clients
        .control
        .evaluation_evidence(command.request.clone(), service)
        .map_err(|error| map_control_error(command, &error))?;
    let response = wire::project_response(command, response)?;
    serde_json::to_value(response).map_err(|_| ForgeError::internal())
}

fn validate_service_identity(
    command: &EvaluationEvidenceCommand,
    trusted_backend_id: ForgeBackendId,
    trusted_destination_id: Uuid,
) -> Result<(), ForgeError> {
    if command.service.backend_id != trusted_backend_id.into_uuid()
        || command.service.destination_id != trusted_destination_id
        || command.request.source.backend_id() != trusted_backend_id
        || command.request.source.delegation_destination_id() != trusted_destination_id
    {
        return Err(ForgeError::auth_failed());
    }
    Ok(())
}

fn command(service: ServiceBody, request: EvaluationEvidenceRequest) -> EvaluationEvidenceCommand {
    EvaluationEvidenceCommand { service, request }
}

fn require_non_nil(value: Uuid, label: &str) -> Result<Uuid, ForgeError> {
    if value.is_nil() {
        return Err(ForgeError::invalid_input(format!(
            "{label} must not be nil"
        )));
    }
    Ok(value)
}

fn require_source_scope(
    scope: &ResolvedWorkspaceScope,
    source: EvaluationSourceIdentity,
) -> Result<(), ForgeError> {
    if scope.workspace_id() != source.workspace_id() {
        return Err(ForgeError::invalid_input(
            "evaluation source does not match the selected Workspace",
        ));
    }
    Ok(())
}

fn decode_source(body: &SourceBody) -> Result<EvaluationSourceIdentity, ForgeError> {
    EvaluationSourceIdentity::new(
        ForgeBackendId::from_uuid(require_non_nil(body.backend_id, "evaluation backend id")?),
        WorkspaceId::from_uuid(require_non_nil(
            body.workspace_id,
            "evaluation Workspace id",
        )?),
        ActivityId::from_uuid(require_non_nil(body.activity_id, "evaluation Activity id")?),
        require_non_nil(body.delegation_migration_id, "delegation migration id")?,
        require_non_nil(body.delegation_destination_id, "delegation destination id")?,
        evaluation_revision(body.delegation_freeze_revision)?,
        decode_digest(&body.delegation_manifest_digest)?,
    )
    .map_err(|_| ForgeError::invalid_input("evaluation source identity is invalid"))
}

fn decode_proposal(body: ProposalBody) -> Result<EvaluationManifestProposal, ForgeError> {
    if body.members.is_empty() || body.members.len() > forge_domain::MAX_EVALUATION_MANIFEST_MEMBERS
    {
        return Err(ForgeError::invalid_input(
            "evaluation manifest member count is outside the supported bound",
        ));
    }
    let declared_digest = decode_digest(&body.digest)?;
    let source = decode_source(&body.source)?;
    let plan = EvaluationPlanBinding::new(
        EvaluationPlanId::new(require_non_nil(body.plan.plan_id, "evaluation plan id")?)
            .map_err(|_| ForgeError::invalid_input("evaluation plan id is invalid"))?,
        evaluation_revision(body.plan.revision)?,
        decode_digest(&body.plan.digest)?,
    );
    let members = body
        .members
        .into_iter()
        .map(|member| {
            EvaluationManifestMember::new(
                EvaluationWorkUnitId::new(require_non_nil(
                    member.work_unit_id,
                    "evaluation work unit id",
                )?)
                .map_err(|_| ForgeError::invalid_input("evaluation work unit id is invalid"))?,
                EvaluationObligationId::new(require_non_nil(
                    member.obligation_id,
                    "evaluation obligation id",
                )?)
                .map_err(|_| ForgeError::invalid_input("evaluation obligation id is invalid"))?,
                AgentAssignmentId::from_uuid(require_non_nil(
                    member.assignment_id,
                    "evaluation assignment id",
                )?),
                assignment_revision(member.assignment_revision)?,
                AgentInstanceId::from_uuid(require_non_nil(
                    member.target_agent_id,
                    "evaluation target Agent id",
                )?),
                AgentSessionId::from_uuid(require_non_nil(
                    member.target_session_id,
                    "evaluation target Session id",
                )?),
                decode_digest(&member.criteria_digest)?,
            )
            .map_err(|_| ForgeError::invalid_input("evaluation manifest member is invalid"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let proposal = EvaluationManifestProposal::new(
        manifest_id(body.manifest_id)?,
        evaluation_revision(body.revision)?,
        source,
        plan,
        decode_timestamp(body.deadline_ms)?,
        members,
    )
    .map_err(|_| ForgeError::invalid_input("evaluation manifest proposal is invalid"))?;
    if proposal.digest() != declared_digest {
        return Err(ForgeError::invalid_input(
            "evaluation manifest digest does not match its canonical proposal",
        ));
    }
    Ok(proposal)
}

fn manifest_id(value: Uuid) -> Result<EvaluationManifestId, ForgeError> {
    EvaluationManifestId::new(require_non_nil(value, "evaluation manifest id")?)
        .map_err(|_| ForgeError::invalid_input("evaluation manifest id is invalid"))
}

fn evaluation_revision(value: i64) -> Result<EvaluationRevision, ForgeError> {
    EvaluationRevision::new(value)
        .map_err(|_| ForgeError::invalid_input("evaluation revision is invalid"))
}

fn assignment_revision(value: i64) -> Result<AgentAssignmentRevision, ForgeError> {
    AgentAssignmentRevision::new(value)
        .map_err(|_| ForgeError::invalid_input("evaluation assignment revision is invalid"))
}

fn decode_timestamp(value: i64) -> Result<TimestampMillis, ForgeError> {
    TimestampMillis::new(value)
        .map_err(|_| ForgeError::invalid_input("evaluation timestamp is invalid"))
}

fn decode_digest(value: &str) -> Result<EvaluationDigest, ForgeError> {
    if value.len() != 64 {
        return Err(ForgeError::invalid_input("evaluation digest is invalid"));
    }
    let bytes = super::decode_hex(value)?;
    let digest = <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| ForgeError::invalid_input("evaluation digest is invalid"))?;
    EvaluationDigest::new(digest)
        .map_err(|_| ForgeError::invalid_input("evaluation digest is invalid"))
}

fn map_control_error(
    command: &EvaluationEvidenceCommand,
    error: &forge_control::ControlClientError,
) -> ForgeError {
    let mapped = super::forge_error_of_client(error);
    if mapped.code() != ErrorCode::UnknownOutcome {
        return mapped;
    }
    let readback = store_mutation_identity(error)
        .map(|identity| {
            ReadbackHint::evaluation_evidence(
                command.request.scope.workspace_id().into_uuid(),
                identity,
            )
        })
        .or_else(|| command.readback_hint());
    mapped.with_readback(readback)
}

fn store_mutation_identity(
    error: &forge_control::ControlClientError,
) -> Option<&EvaluationEvidenceMutationIdentity> {
    let service = error.service_error()?;
    let mut source = Error::source(service)?;
    loop {
        if let Some(store_error) = source.downcast_ref::<forge_persistence::WorkspaceStoreError>()
            && let forge_persistence::WorkspaceStoreError::EvaluationEvidenceCommittedUnconfirmed {
                identity,
                ..
            } = store_error
        {
            return Some(identity);
        }
        source = Error::source(source)?;
    }
}

#[cfg(test)]
mod tests;
