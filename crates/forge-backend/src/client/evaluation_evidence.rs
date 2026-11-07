//! Official bounded Forge HTTP client operations for exact evaluation source evidence.

use std::fmt;

use forge_control::{EvaluationEvidenceOperation, EvaluationEvidenceRequest};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::ops::{CommandOp, evaluation_evidence::wire};

use super::{
    ForgeHttpClient, ForgeHttpClientError, ForgeHttpServiceCode, decode_command_response,
    migration_request_body, migration_scope_payload,
};

// A 256-member cohort, maximum-width source revision, and largest accepted
// JSON-escaped locator measure 112,139 bytes. Keep this manifest-only
// allowance below the backend's 1 MiB ingress bound; other command bodies
// retain the shared 64 KiB limit.
const MAX_EVALUATION_MANIFEST_REQUEST_BYTES: usize = 128 * 1024;

/// Failure preserving the exact typed source request for explicit recovery.
/// This client never retries or resends an evaluation mutation automatically.
#[must_use]
#[derive(Clone, PartialEq, Eq)]
pub enum ForgeHttpEvaluationEvidenceError {
    Rejected {
        request: Box<EvaluationEvidenceRequest>,
        cause: ForgeHttpClientError,
    },
    ReadFailed {
        request: Box<EvaluationEvidenceRequest>,
        cause: ForgeHttpClientError,
    },
    UnknownOutcome {
        request: Box<EvaluationEvidenceRequest>,
        cause: ForgeHttpClientError,
    },
}

impl ForgeHttpEvaluationEvidenceError {
    pub const fn request(&self) -> &EvaluationEvidenceRequest {
        match self {
            Self::Rejected { request, .. }
            | Self::ReadFailed { request, .. }
            | Self::UnknownOutcome { request, .. } => request,
        }
    }

    pub const fn cause(&self) -> &ForgeHttpClientError {
        match self {
            Self::Rejected { cause, .. }
            | Self::ReadFailed { cause, .. }
            | Self::UnknownOutcome { cause, .. } => cause,
        }
    }

    pub const fn is_unknown_outcome(&self) -> bool {
        matches!(self, Self::UnknownOutcome { .. })
    }
}

impl fmt::Debug for ForgeHttpEvaluationEvidenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (kind, cause) = match self {
            Self::Rejected { cause, .. } => ("Rejected", cause),
            Self::ReadFailed { cause, .. } => ("ReadFailed", cause),
            Self::UnknownOutcome { cause, .. } => ("UnknownOutcome", cause),
        };
        formatter
            .debug_struct("ForgeHttpEvaluationEvidenceError")
            .field("kind", &kind)
            .field("cause", cause)
            .field("request_retained", &true)
            .finish()
    }
}

impl fmt::Display for ForgeHttpEvaluationEvidenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected { .. } => formatter.write_str("Forge evaluation evidence request was rejected"),
            Self::ReadFailed { .. } => formatter.write_str("Forge evaluation evidence read failed"),
            Self::UnknownOutcome { .. } => formatter.write_str(
                "Forge evaluation evidence mutation outcome is unknown; read back the retained identity",
            ),
        }
    }
}

impl std::error::Error for ForgeHttpEvaluationEvidenceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.cause())
    }
}

impl ForgeHttpClient {
    pub async fn seal_evaluation_manifest(
        &self,
        request: &EvaluationEvidenceRequest,
    ) -> Result<wire::EvaluationEvidenceResponseWire, ForgeHttpEvaluationEvidenceError> {
        self.evaluation_evidence_for(request, CommandOp::EvaluationManifestSeal)
            .await
    }

    pub async fn get_evaluation_manifest(
        &self,
        request: &EvaluationEvidenceRequest,
    ) -> Result<wire::EvaluationEvidenceResponseWire, ForgeHttpEvaluationEvidenceError> {
        self.evaluation_evidence_for(request, CommandOp::EvaluationManifestGet)
            .await
    }

    pub async fn close_evaluation_t1(
        &self,
        request: &EvaluationEvidenceRequest,
    ) -> Result<wire::EvaluationEvidenceResponseWire, ForgeHttpEvaluationEvidenceError> {
        self.evaluation_evidence_for(request, CommandOp::EvaluationT1Close)
            .await
    }

    pub async fn get_evaluation_t1_cut(
        &self,
        request: &EvaluationEvidenceRequest,
    ) -> Result<wire::EvaluationEvidenceResponseWire, ForgeHttpEvaluationEvidenceError> {
        self.evaluation_evidence_for(request, CommandOp::EvaluationT1Get)
            .await
    }

    pub async fn create_evaluation_review_cut(
        &self,
        request: &EvaluationEvidenceRequest,
    ) -> Result<wire::EvaluationEvidenceResponseWire, ForgeHttpEvaluationEvidenceError> {
        self.evaluation_evidence_for(request, CommandOp::EvaluationReviewCutCreate)
            .await
    }

    pub async fn get_evaluation_review_cut(
        &self,
        request: &EvaluationEvidenceRequest,
    ) -> Result<wire::EvaluationEvidenceResponseWire, ForgeHttpEvaluationEvidenceError> {
        self.evaluation_evidence_for(request, CommandOp::EvaluationReviewCutGet)
            .await
    }

    pub async fn get_evaluation_submission_receipt(
        &self,
        request: &EvaluationEvidenceRequest,
    ) -> Result<wire::EvaluationEvidenceResponseWire, ForgeHttpEvaluationEvidenceError> {
        self.evaluation_evidence_for(request, CommandOp::EvaluationSubmissionReceiptGet)
            .await
    }

    pub async fn get_evaluation_review_receipt(
        &self,
        request: &EvaluationEvidenceRequest,
    ) -> Result<wire::EvaluationEvidenceResponseWire, ForgeHttpEvaluationEvidenceError> {
        self.evaluation_evidence_for(request, CommandOp::EvaluationReviewReceiptGet)
            .await
    }

    async fn evaluation_evidence_for(
        &self,
        request: &EvaluationEvidenceRequest,
        op: CommandOp,
    ) -> Result<wire::EvaluationEvidenceResponseWire, ForgeHttpEvaluationEvidenceError> {
        let mutation = is_mutation(&request.operation);
        validate_evaluation_request(request, op, self.expected_backend_id, self.destination_id)
            .map_err(|cause| rejected_error(request, cause))?;
        let request_id = Uuid::now_v7();
        let body = evaluation_request_body(
            request,
            op,
            self.expected_backend_id,
            self.destination_id,
            request_id,
        )
        .map_err(|cause| rejected_error(request, cause))?;
        let Ok(_permit) = self.slots.clone().try_acquire_owned() else {
            return Err(rejected_error(request, ForgeHttpClientError::Capacity));
        };
        let value = self
            .exchange_evaluation_request(request, op, request_id, body, mutation)
            .await?;
        decode_evaluation_response(
            request,
            value,
            mutation,
            self.expected_backend_id,
            self.destination_id,
        )
    }

    async fn exchange_evaluation_request(
        &self,
        request: &EvaluationEvidenceRequest,
        op: CommandOp,
        request_id: Uuid,
        body: Vec<u8>,
        mutation: bool,
    ) -> Result<Value, ForgeHttpEvaluationEvidenceError> {
        let exchange = tokio::time::timeout(self.timeout, self.exchange_command(op, body)).await;
        let result = match exchange {
            Ok(Ok(result)) => result,
            Ok(Err(cause)) => return Err(transport_error(request, mutation, cause)),
            Err(_) => {
                return Err(transport_error(
                    request,
                    mutation,
                    ForgeHttpClientError::Timeout,
                ));
            }
        };
        decode_command_response(result, request_id).map_err(|cause| {
            if mutation && (is_unknown_service_error(cause) || !is_rejected_service_error(cause)) {
                unknown_error(request, cause)
            } else if mutation {
                rejected_error(request, cause)
            } else {
                read_failed_error(request, cause)
            }
        })
    }
}

fn validate_evaluation_request(
    request: &EvaluationEvidenceRequest,
    op: CommandOp,
    expected_backend_id: forge_domain::ForgeBackendId,
    destination_id: Uuid,
) -> Result<(), ForgeHttpClientError> {
    if command_op(&request.operation) != op
        || request.source.backend_id() != expected_backend_id
        || request.source.delegation_destination_id() != destination_id
        || request.source.workspace_id() != request.scope.workspace_id()
    {
        return Err(ForgeHttpClientError::DestinationMismatch);
    }
    if let EvaluationEvidenceOperation::SealManifest { proposal } = &request.operation
        && proposal.source() != request.source
    {
        return Err(ForgeHttpClientError::InvalidRequest);
    }
    Ok(())
}

fn evaluation_request_body(
    request: &EvaluationEvidenceRequest,
    op: CommandOp,
    backend_id: forge_domain::ForgeBackendId,
    destination_id: Uuid,
    request_id: Uuid,
) -> Result<Vec<u8>, ForgeHttpClientError> {
    let fields = request_fields(request, backend_id, destination_id)?;
    let scope = migration_scope_payload(&request.scope)?;
    if matches!(
        &request.operation,
        EvaluationEvidenceOperation::SealManifest { .. }
    ) {
        evaluation_manifest_request_body(op, scope, fields, request_id)
    } else {
        migration_request_body(op, scope, fields, request_id)
    }
}

fn evaluation_manifest_request_body(
    op: CommandOp,
    scope: Value,
    fields: Value,
    request_id: Uuid,
) -> Result<Vec<u8>, ForgeHttpClientError> {
    if op != CommandOp::EvaluationManifestSeal {
        return Err(ForgeHttpClientError::InvalidRequest);
    }
    let Value::Object(mut payload) = fields else {
        return Err(ForgeHttpClientError::InvalidRequest);
    };
    payload.insert("scope".to_owned(), scope);
    let envelope = json!({
        "forge_api": super::FORGE_API_VERSION,
        "request_id": request_id,
        "op": op.as_str(),
        "payload": Value::Object(payload),
    });
    let body = serde_json::to_vec(&envelope).map_err(|_| ForgeHttpClientError::Request)?;
    if body.len() > MAX_EVALUATION_MANIFEST_REQUEST_BYTES
        || body.len() > crate::config::MAX_BODY_BYTES
    {
        return Err(ForgeHttpClientError::RequestTooLarge);
    }
    Ok(body)
}

fn rejected_error(
    request: &EvaluationEvidenceRequest,
    cause: ForgeHttpClientError,
) -> ForgeHttpEvaluationEvidenceError {
    ForgeHttpEvaluationEvidenceError::Rejected {
        request: Box::new(request.clone()),
        cause,
    }
}

fn read_failed_error(
    request: &EvaluationEvidenceRequest,
    cause: ForgeHttpClientError,
) -> ForgeHttpEvaluationEvidenceError {
    ForgeHttpEvaluationEvidenceError::ReadFailed {
        request: Box::new(request.clone()),
        cause,
    }
}

fn unknown_error(
    request: &EvaluationEvidenceRequest,
    cause: ForgeHttpClientError,
) -> ForgeHttpEvaluationEvidenceError {
    ForgeHttpEvaluationEvidenceError::UnknownOutcome {
        request: Box::new(request.clone()),
        cause,
    }
}

fn transport_error(
    request: &EvaluationEvidenceRequest,
    mutation: bool,
    cause: ForgeHttpClientError,
) -> ForgeHttpEvaluationEvidenceError {
    if mutation {
        unknown_error(request, cause)
    } else {
        read_failed_error(request, cause)
    }
}

fn decode_evaluation_response(
    request: &EvaluationEvidenceRequest,
    value: Value,
    mutation: bool,
    expected_backend_id: forge_domain::ForgeBackendId,
    destination_id: Uuid,
) -> Result<wire::EvaluationEvidenceResponseWire, ForgeHttpEvaluationEvidenceError> {
    let Ok(response) = serde_json::from_value::<wire::EvaluationEvidenceResponseWire>(value) else {
        return Err(transport_error(
            request,
            mutation,
            ForgeHttpClientError::Protocol,
        ));
    };
    if validate_response(request, &response, expected_backend_id, destination_id).is_err() {
        return Err(transport_error(
            request,
            mutation,
            ForgeHttpClientError::Protocol,
        ));
    }
    Ok(response)
}

fn command_op(operation: &EvaluationEvidenceOperation) -> CommandOp {
    match operation {
        EvaluationEvidenceOperation::SealManifest { .. } => CommandOp::EvaluationManifestSeal,
        EvaluationEvidenceOperation::GetManifest { .. } => CommandOp::EvaluationManifestGet,
        EvaluationEvidenceOperation::CloseT1 { .. } => CommandOp::EvaluationT1Close,
        EvaluationEvidenceOperation::GetT1Cut { .. } => CommandOp::EvaluationT1Get,
        EvaluationEvidenceOperation::CreateReviewCut { .. } => CommandOp::EvaluationReviewCutCreate,
        EvaluationEvidenceOperation::GetReviewCut { .. } => CommandOp::EvaluationReviewCutGet,
        EvaluationEvidenceOperation::GetSubmissionReceipt { .. } => {
            CommandOp::EvaluationSubmissionReceiptGet
        }
        EvaluationEvidenceOperation::GetReviewReceipt { .. } => {
            CommandOp::EvaluationReviewReceiptGet
        }
    }
}

fn is_mutation(operation: &EvaluationEvidenceOperation) -> bool {
    matches!(
        operation,
        EvaluationEvidenceOperation::SealManifest { .. }
            | EvaluationEvidenceOperation::CloseT1 { .. }
            | EvaluationEvidenceOperation::CreateReviewCut { .. }
    )
}

fn request_fields(
    request: &EvaluationEvidenceRequest,
    backend_id: forge_domain::ForgeBackendId,
    destination_id: Uuid,
) -> Result<Value, ForgeHttpClientError> {
    let source = serde_json::to_value(wire::source_identity_wire(request.source))
        .map_err(|_| ForgeHttpClientError::Request)?;
    let mut fields = serde_json::Map::new();
    fields.insert(
        "service".to_owned(),
        json!({
            "backend_id": backend_id.into_uuid(),
            "destination_id": destination_id,
        }),
    );
    match &request.operation {
        EvaluationEvidenceOperation::SealManifest { proposal } => {
            fields.insert(
                "proposal".to_owned(),
                serde_json::to_value(wire::proposal_wire(proposal))
                    .map_err(|_| ForgeHttpClientError::Request)?,
            );
        }
        EvaluationEvidenceOperation::GetManifest {
            manifest_id,
            revision,
            digest,
        } => insert_manifest_get_fields(&mut fields, source, *manifest_id, *revision, *digest),
        EvaluationEvidenceOperation::CloseT1 { request }
        | EvaluationEvidenceOperation::GetT1Cut { request } => {
            insert_t1_fields(&mut fields, source, request);
        }
        EvaluationEvidenceOperation::CreateReviewCut {
            review_cut_id,
            t1_request,
        }
        | EvaluationEvidenceOperation::GetReviewCut {
            review_cut_id,
            t1_request,
        } => {
            insert_review_cut_fields(&mut fields, source, *review_cut_id, t1_request);
        }
        EvaluationEvidenceOperation::GetSubmissionReceipt {
            manifest_id,
            manifest_revision,
            manifest_digest,
            assignment_id,
            submitted_revision,
        } => {
            insert_receipt_identity(
                &mut fields,
                source,
                ReceiptRequestIdentity {
                    manifest_id: *manifest_id,
                    manifest_revision: *manifest_revision,
                    manifest_digest: *manifest_digest,
                    assignment_id: *assignment_id,
                    submitted_revision: *submitted_revision,
                },
            );
        }
        EvaluationEvidenceOperation::GetReviewReceipt {
            manifest_id,
            manifest_revision,
            manifest_digest,
            assignment_id,
            submitted_revision,
            review_revision,
        } => {
            insert_receipt_identity(
                &mut fields,
                source,
                ReceiptRequestIdentity {
                    manifest_id: *manifest_id,
                    manifest_revision: *manifest_revision,
                    manifest_digest: *manifest_digest,
                    assignment_id: *assignment_id,
                    submitted_revision: *submitted_revision,
                },
            );
            fields.insert("review_revision".to_owned(), json!(review_revision.get()));
        }
    }
    Ok(Value::Object(fields))
}

fn insert_manifest_get_fields(
    fields: &mut serde_json::Map<String, Value>,
    source: Value,
    manifest_id: forge_domain::EvaluationManifestId,
    revision: forge_domain::EvaluationRevision,
    digest: forge_domain::EvaluationDigest,
) {
    fields.insert("source".to_owned(), source);
    fields.insert("manifest_id".to_owned(), json!(manifest_id.into_uuid()));
    fields.insert("revision".to_owned(), json!(revision.get()));
    fields.insert("digest".to_owned(), json!(digest_hex(&digest)));
}

fn insert_t1_fields(
    fields: &mut serde_json::Map<String, Value>,
    source: Value,
    request: &forge_domain::EvaluationT1CloseRequest,
) {
    fields.insert("source".to_owned(), source);
    fields.insert("cut_id".to_owned(), json!(request.cut_id().into_uuid()));
    fields.insert(
        "manifest_id".to_owned(),
        json!(request.manifest_id().into_uuid()),
    );
    fields.insert(
        "manifest_revision".to_owned(),
        json!(request.manifest_revision().get()),
    );
    fields.insert(
        "manifest_digest".to_owned(),
        json!(digest_hex(&request.manifest_digest())),
    );
    fields.insert("deadline_ms".to_owned(), json!(request.deadline().get()));
}

fn insert_review_cut_fields(
    fields: &mut serde_json::Map<String, Value>,
    source: Value,
    review_cut_id: forge_domain::EvaluationReviewCutId,
    t1_request: &forge_domain::EvaluationT1CloseRequest,
) {
    fields.insert("source".to_owned(), source);
    fields.insert("review_cut_id".to_owned(), json!(review_cut_id.into_uuid()));
    fields.insert(
        "t1_cut_id".to_owned(),
        json!(t1_request.cut_id().into_uuid()),
    );
    fields.insert(
        "manifest_id".to_owned(),
        json!(t1_request.manifest_id().into_uuid()),
    );
    fields.insert(
        "manifest_revision".to_owned(),
        json!(t1_request.manifest_revision().get()),
    );
    fields.insert(
        "manifest_digest".to_owned(),
        json!(digest_hex(&t1_request.manifest_digest())),
    );
    fields.insert("deadline_ms".to_owned(), json!(t1_request.deadline().get()));
}

#[derive(Clone, Copy)]
struct ReceiptRequestIdentity {
    manifest_id: forge_domain::EvaluationManifestId,
    manifest_revision: forge_domain::EvaluationRevision,
    manifest_digest: forge_domain::EvaluationDigest,
    assignment_id: forge_domain::AgentAssignmentId,
    submitted_revision: forge_domain::AgentAssignmentRevision,
}

fn insert_receipt_identity(
    fields: &mut serde_json::Map<String, Value>,
    source: Value,
    identity: ReceiptRequestIdentity,
) {
    fields.insert("source".to_owned(), source);
    fields.insert(
        "manifest_id".to_owned(),
        json!(identity.manifest_id.into_uuid()),
    );
    fields.insert(
        "manifest_revision".to_owned(),
        json!(identity.manifest_revision.get()),
    );
    fields.insert(
        "manifest_digest".to_owned(),
        json!(digest_hex(&identity.manifest_digest)),
    );
    fields.insert(
        "assignment_id".to_owned(),
        json!(identity.assignment_id.into_uuid()),
    );
    fields.insert(
        "submitted_revision".to_owned(),
        json!(identity.submitted_revision.get()),
    );
}

fn validate_response(
    request: &EvaluationEvidenceRequest,
    response: &wire::EvaluationEvidenceResponseWire,
    expected_backend_id: forge_domain::ForgeBackendId,
    destination_id: Uuid,
) -> Result<(), ForgeHttpClientError> {
    validate_response_source(request, response, expected_backend_id, destination_id)?;
    let valid = response_matches_manifest(&request.operation, response)
        .or_else(|| response_matches_t1(&request.operation, response))
        .or_else(|| response_matches_review_cut(&request.operation, response))
        .or_else(|| response_matches_receipt(&request.operation, response))
        .unwrap_or(false);
    if valid {
        Ok(())
    } else {
        Err(ForgeHttpClientError::Protocol)
    }
}

fn validate_response_source(
    request: &EvaluationEvidenceRequest,
    response: &wire::EvaluationEvidenceResponseWire,
    expected_backend_id: forge_domain::ForgeBackendId,
    destination_id: Uuid,
) -> Result<(), ForgeHttpClientError> {
    let expected_source = wire::source_identity_wire(request.source);
    if expected_source.backend_id != expected_backend_id.into_uuid()
        || expected_source.delegation_destination_id != destination_id
        || expected_source.workspace_id != request.scope.workspace_id().into_uuid()
    {
        return Err(ForgeHttpClientError::Protocol);
    }
    let response_source = match response {
        wire::EvaluationEvidenceResponseWire::ManifestSealed { source, .. }
        | wire::EvaluationEvidenceResponseWire::ManifestRead { source, .. }
        | wire::EvaluationEvidenceResponseWire::T1Closed { source, .. }
        | wire::EvaluationEvidenceResponseWire::T1Read { source, .. }
        | wire::EvaluationEvidenceResponseWire::ReviewCutCreated { source, .. }
        | wire::EvaluationEvidenceResponseWire::ReviewCutRead { source, .. }
        | wire::EvaluationEvidenceResponseWire::SubmissionReceiptRead { source, .. }
        | wire::EvaluationEvidenceResponseWire::ReviewReceiptRead { source, .. } => source,
    };
    if response_source == &expected_source {
        Ok(())
    } else {
        Err(ForgeHttpClientError::Protocol)
    }
}

fn response_matches_manifest(
    operation: &EvaluationEvidenceOperation,
    response: &wire::EvaluationEvidenceResponseWire,
) -> Option<bool> {
    match (operation, response) {
        (
            EvaluationEvidenceOperation::SealManifest { proposal },
            wire::EvaluationEvidenceResponseWire::ManifestSealed { manifest, .. },
        ) => Some(proposal_matches_wire(proposal, &manifest.proposal)),
        (
            EvaluationEvidenceOperation::GetManifest {
                manifest_id,
                revision,
                digest,
            },
            wire::EvaluationEvidenceResponseWire::ManifestRead {
                status, manifest, ..
            },
        ) => Some(match manifest {
            Some(manifest) => {
                *status == wire::EvaluationRecordReadStatus::Found
                    && manifest.proposal.manifest_id == manifest_id.into_uuid()
                    && manifest.proposal.revision == revision.get()
                    && manifest.proposal.digest == digest_hex(digest)
            }
            None => *status == wire::EvaluationRecordReadStatus::Missing,
        }),
        _ => None,
    }
}

fn response_matches_t1(
    operation: &EvaluationEvidenceOperation,
    response: &wire::EvaluationEvidenceResponseWire,
) -> Option<bool> {
    match (operation, response) {
        (
            EvaluationEvidenceOperation::CloseT1 {
                request: close_request,
            },
            wire::EvaluationEvidenceResponseWire::T1Closed { outcome, .. },
        ) => Some(match outcome {
            wire::EvaluationT1ClosureWire::Closed { cut } => t1_cut_matches(
                cut,
                close_request.cut_id(),
                close_request.manifest_id(),
                close_request.manifest_revision(),
                close_request.manifest_digest(),
                close_request.deadline(),
            ),
            wire::EvaluationT1ClosureWire::NotClosed { .. } => true,
        }),
        (
            EvaluationEvidenceOperation::GetT1Cut {
                request: t1_request,
            },
            wire::EvaluationEvidenceResponseWire::T1Read { status, cut, .. },
        ) => Some(match cut {
            Some(cut) => {
                *status == wire::EvaluationRecordReadStatus::Found
                    && t1_cut_matches(
                        cut,
                        t1_request.cut_id(),
                        t1_request.manifest_id(),
                        t1_request.manifest_revision(),
                        t1_request.manifest_digest(),
                        t1_request.deadline(),
                    )
            }
            None => *status == wire::EvaluationRecordReadStatus::Missing,
        }),
        _ => None,
    }
}

fn response_matches_review_cut(
    operation: &EvaluationEvidenceOperation,
    response: &wire::EvaluationEvidenceResponseWire,
) -> Option<bool> {
    match (operation, response) {
        (
            EvaluationEvidenceOperation::CreateReviewCut {
                review_cut_id,
                t1_request,
                ..
            },
            wire::EvaluationEvidenceResponseWire::ReviewCutCreated { review_cut, .. },
        ) => Some(
            review_cut.review_cut_id == review_cut_id.into_uuid()
                && review_cut.t1_cut_id == t1_request.cut_id().into_uuid(),
        ),
        (
            EvaluationEvidenceOperation::GetReviewCut {
                review_cut_id,
                t1_request,
                ..
            },
            wire::EvaluationEvidenceResponseWire::ReviewCutRead {
                status, review_cut, ..
            },
        ) => Some(match review_cut {
            Some(review_cut) => {
                *status == wire::EvaluationRecordReadStatus::Found
                    && review_cut.review_cut_id == review_cut_id.into_uuid()
                    && review_cut.t1_cut_id == t1_request.cut_id().into_uuid()
            }
            None => *status == wire::EvaluationRecordReadStatus::Missing,
        }),
        _ => None,
    }
}

fn response_matches_receipt(
    operation: &EvaluationEvidenceOperation,
    response: &wire::EvaluationEvidenceResponseWire,
) -> Option<bool> {
    match (operation, response) {
        (
            EvaluationEvidenceOperation::GetSubmissionReceipt {
                assignment_id,
                submitted_revision,
                ..
            },
            wire::EvaluationEvidenceResponseWire::SubmissionReceiptRead {
                status, receipt, ..
            },
        ) => Some(match receipt {
            Some(receipt) => {
                *status == wire::EvaluationRecordReadStatus::Found
                    && receipt.assignment_id == assignment_id.into_uuid()
                    && receipt.submitted_revision == submitted_revision.get()
            }
            None => *status == wire::EvaluationRecordReadStatus::Missing,
        }),
        (
            EvaluationEvidenceOperation::GetReviewReceipt {
                assignment_id,
                submitted_revision,
                review_revision,
                ..
            },
            wire::EvaluationEvidenceResponseWire::ReviewReceiptRead {
                status, receipt, ..
            },
        ) => Some(match receipt {
            Some(receipt) => {
                *status == wire::EvaluationRecordReadStatus::Found
                    && receipt.assignment_id == assignment_id.into_uuid()
                    && receipt.submitted_revision == submitted_revision.get()
                    && receipt.review_revision == review_revision.get()
            }
            None => *status == wire::EvaluationRecordReadStatus::Missing,
        }),
        _ => None,
    }
}

fn proposal_matches_wire(
    proposal: &forge_domain::EvaluationManifestProposal,
    wire: &wire::EvaluationManifestProposalWire,
) -> bool {
    wire.manifest_id == proposal.manifest_id().into_uuid()
        && wire.revision == proposal.revision().get()
        && wire.source == wire::source_identity_wire(proposal.source())
        && wire.plan.plan_id == proposal.plan().plan_id().into_uuid()
        && wire.plan.revision == proposal.plan().revision().get()
        && wire.plan.digest == digest_hex(&proposal.plan().digest())
        && wire.deadline_ms == proposal.deadline().get()
        && wire.digest == digest_hex(&proposal.digest())
        && wire.members.len() == proposal.members().len()
        && wire
            .members
            .iter()
            .zip(proposal.members())
            .all(|(member, expected)| {
                member.work_unit_id == expected.work_unit_id().into_uuid()
                    && member.obligation_id == expected.obligation_id().into_uuid()
                    && member.assignment_id == expected.assignment_id().into_uuid()
                    && member.assignment_revision == expected.assignment_revision().get()
                    && member.target_agent_id == expected.target_agent_id().into_uuid()
                    && member.target_session_id == expected.target_session_id().into_uuid()
                    && member.criteria_digest == digest_hex(&expected.criteria_digest())
            })
}

fn t1_cut_matches(
    cut: &wire::EvaluationT1CoverageCutWire,
    cut_id: forge_domain::EvaluationCutId,
    manifest_id: forge_domain::EvaluationManifestId,
    manifest_revision: forge_domain::EvaluationRevision,
    manifest_digest: forge_domain::EvaluationDigest,
    deadline: forge_domain::TimestampMillis,
) -> bool {
    cut.cut_id == cut_id.into_uuid()
        && cut.manifest_id == manifest_id.into_uuid()
        && cut.manifest_revision == manifest_revision.get()
        && cut.manifest_digest == digest_hex(&manifest_digest)
        && cut.deadline_ms == deadline.get()
}

fn is_unknown_service_error(error: ForgeHttpClientError) -> bool {
    matches!(
        error,
        ForgeHttpClientError::Service {
            code: ForgeHttpServiceCode::UnknownOutcome,
            ..
        }
    )
}

fn is_rejected_service_error(error: ForgeHttpClientError) -> bool {
    matches!(error, ForgeHttpClientError::Service { .. })
}

fn digest_hex(digest: &forge_domain::EvaluationDigest) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(64);
    for byte in digest.as_bytes() {
        let _ignored = write!(output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use forge_control::ResolvedWorkspaceScope;
    use forge_domain::{
        ActivityId, AgentAssignmentId, AgentAssignmentRevision, AgentInstanceId, AgentSessionId,
        EvaluationCutId, EvaluationDigest, EvaluationManifestId, EvaluationManifestMember,
        EvaluationObligationId, EvaluationPlanBinding, EvaluationPlanId, EvaluationRevision,
        EvaluationSourceIdentity, ForgeBackendId, LocationId, LocationRevision, TimestampMillis,
        WorkspaceId, WorkspaceRevision,
    };
    use forge_workspace::WorkspaceLocator;

    #[test]
    fn read_error_retains_original_receipt_identity_without_dumping_workspace_path()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = receipt_request()?;
        let error = ForgeHttpEvaluationEvidenceError::ReadFailed {
            request: Box::new(request.clone()),
            cause: ForgeHttpClientError::Protocol,
        };
        assert_eq!(error.request(), &request);
        assert!(!format!("{error:?}").contains("private-workspace-path"));
        Ok(())
    }

    #[test]
    fn unknown_t1_mutation_retains_manifest_deadline_and_cut_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = t1_close_request()?;
        let error = ForgeHttpEvaluationEvidenceError::UnknownOutcome {
            request: Box::new(request.clone()),
            cause: ForgeHttpClientError::Timeout,
        };
        assert!(error.is_unknown_outcome());
        assert_eq!(error.request(), &request);
        let Some(forge_persistence::EvaluationEvidenceMutationIdentity::T1Closure {
            request: identity,
        }) = request.mutation_identity()
        else {
            return Err("T1 mutation identity is missing or has the wrong variant".into());
        };
        assert_eq!(identity.cut_id(), EvaluationCutId::new(Uuid::from_u128(7))?);
        assert_eq!(
            identity.manifest_id(),
            EvaluationManifestId::new(Uuid::from_u128(8))?
        );
        assert_eq!(identity.manifest_revision(), EvaluationRevision::new(2)?);
        assert_eq!(identity.manifest_digest(), EvaluationDigest::new([9; 32])?);
        assert_eq!(identity.deadline(), TimestampMillis::new(900)?);
        Ok(())
    }

    #[test]
    fn response_with_foreign_assignment_receipt_is_rejected()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = receipt_request()?;
        let source = wire::source_identity_wire(request.source);
        let response = wire::EvaluationEvidenceResponseWire::SubmissionReceiptRead {
            source,
            status: wire::EvaluationRecordReadStatus::Found,
            receipt: Some(wire::EvaluationSubmissionReceiptWire {
                assignment_id: Uuid::from_u128(999),
                submitted_revision: 2,
                author_agent_id: Uuid::from_u128(4),
                author_session_id: Uuid::from_u128(5),
                original_binding_digest: Some("11".repeat(32)),
                criteria_digest: Some("22".repeat(32)),
                source_sequence: 4,
                timing: wire::EvaluationAdmissionTimingWire::Trusted {
                    observed_at_ms: 901,
                },
                result_digest: "33".repeat(32),
                sources_digest: None,
            }),
        };
        assert!(
            validate_response(
                &request,
                &response,
                ForgeBackendId::from_uuid(Uuid::from_u128(3)),
                Uuid::from_u128(6),
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn manifest_body_limit_is_route_specific_and_oversized_body_fails_before_exchange() {
        const {
            assert!(MAX_EVALUATION_MANIFEST_REQUEST_BYTES > super::super::MAX_REQUEST_BYTES);
            assert!(MAX_EVALUATION_MANIFEST_REQUEST_BYTES <= crate::config::MAX_BODY_BYTES);
        }
        let result = evaluation_manifest_request_body(
            CommandOp::EvaluationManifestSeal,
            serde_json::json!({"workspace_id": Uuid::from_u128(2)}),
            serde_json::json!({
                "padding": "x".repeat(MAX_EVALUATION_MANIFEST_REQUEST_BYTES)
            }),
            Uuid::from_u128(99),
        );
        assert!(matches!(result, Err(ForgeHttpClientError::RequestTooLarge)));
    }

    #[test]
    fn maximum_manifest_uses_its_operation_specific_serialized_body_limit()
    -> Result<(), Box<dyn std::error::Error>> {
        let source = EvaluationSourceIdentity::new(
            ForgeBackendId::from_uuid(Uuid::from_u128(3)),
            WorkspaceId::from_uuid(Uuid::from_u128(2)),
            ActivityId::from_uuid(Uuid::from_u128(4)),
            Uuid::from_u128(5),
            Uuid::from_u128(6),
            EvaluationRevision::new(i64::MAX)?,
            EvaluationDigest::new([0x11; 32])?,
        )?;
        let members = (0..forge_domain::MAX_EVALUATION_MANIFEST_MEMBERS)
            .map(|index| -> Result<_, Box<dyn std::error::Error>> {
                let index = u128::try_from(index)?;
                Ok(EvaluationManifestMember::new(
                    forge_domain::EvaluationWorkUnitId::new(Uuid::from_u128(0xA000 + index))?,
                    EvaluationObligationId::new(Uuid::from_u128(0xB000 + index))?,
                    AgentAssignmentId::from_uuid(Uuid::from_u128(0xC000 + index)),
                    AgentAssignmentRevision::new(i64::MAX)?,
                    AgentInstanceId::from_uuid(Uuid::from_u128(14)),
                    AgentSessionId::from_uuid(Uuid::from_u128(15)),
                    EvaluationDigest::new([0xD4; 32])?,
                )?)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let proposal = forge_domain::EvaluationManifestProposal::new(
            EvaluationManifestId::new(Uuid::from_u128(0xE001))?,
            EvaluationRevision::new(i64::MAX)?,
            source,
            EvaluationPlanBinding::new(
                EvaluationPlanId::new(Uuid::from_u128(0xE002))?,
                EvaluationRevision::new(i64::MAX)?,
                EvaluationDigest::new([0xE3; 32])?,
            ),
            TimestampMillis::new(i64::MAX)?,
            members,
        )?;
        let request = EvaluationEvidenceRequest::new(
            maximum_escaped_scope(source.workspace_id())?,
            source,
            EvaluationEvidenceOperation::SealManifest { proposal },
        );
        let body = evaluation_request_body(
            &request,
            CommandOp::EvaluationManifestSeal,
            source.backend_id(),
            source.delegation_destination_id(),
            Uuid::from_u128(0xF001),
        )?;
        assert_eq!(body.len(), 112_139);
        assert!(body.len() > super::super::MAX_REQUEST_BYTES);
        assert!(body.len() <= MAX_EVALUATION_MANIFEST_REQUEST_BYTES);
        assert!(body.len() <= crate::config::MAX_BODY_BYTES);
        Ok(())
    }

    fn maximum_escaped_scope(
        workspace_id: WorkspaceId,
    ) -> Result<ResolvedWorkspaceScope, Box<dyn std::error::Error>> {
        let relative_root = "\u{1}".repeat(1_024);
        let locator = WorkspaceLocator::new(
            LocationId::from_uuid(Uuid::from_u128(1)),
            LocationRevision::new(i64::MAX)?,
            std::path::Path::new(&relative_root),
        )?;
        Ok(ResolvedWorkspaceScope::from_observation(
            workspace_id,
            WorkspaceRevision::new(i64::MAX)?,
            locator,
        ))
    }

    fn receipt_request() -> Result<EvaluationEvidenceRequest, Box<dyn std::error::Error>> {
        Ok(EvaluationEvidenceRequest::new(
            scope()?,
            source()?,
            EvaluationEvidenceOperation::GetSubmissionReceipt {
                manifest_id: EvaluationManifestId::new(Uuid::from_u128(8))?,
                manifest_revision: EvaluationRevision::new(2)?,
                manifest_digest: EvaluationDigest::new([9; 32])?,
                assignment_id: forge_domain::AgentAssignmentId::from_uuid(Uuid::from_u128(10)),
                submitted_revision: forge_domain::AgentAssignmentRevision::new(2)?,
            },
        ))
    }

    fn t1_close_request() -> Result<EvaluationEvidenceRequest, Box<dyn std::error::Error>> {
        Ok(EvaluationEvidenceRequest::new(
            scope()?,
            source()?,
            EvaluationEvidenceOperation::CloseT1 {
                request: forge_domain::EvaluationT1CloseRequest::new(
                    EvaluationCutId::new(Uuid::from_u128(7))?,
                    EvaluationManifestId::new(Uuid::from_u128(8))?,
                    EvaluationRevision::new(2)?,
                    EvaluationDigest::new([9; 32])?,
                    TimestampMillis::new(900)?,
                ),
            },
        ))
    }

    fn source() -> Result<EvaluationSourceIdentity, Box<dyn std::error::Error>> {
        Ok(EvaluationSourceIdentity::new(
            ForgeBackendId::from_uuid(Uuid::from_u128(3)),
            WorkspaceId::from_uuid(Uuid::from_u128(2)),
            ActivityId::from_uuid(Uuid::from_u128(4)),
            Uuid::from_u128(5),
            Uuid::from_u128(6),
            EvaluationRevision::new(1)?,
            EvaluationDigest::new([8; 32])?,
        )?)
    }

    fn scope() -> Result<ResolvedWorkspaceScope, Box<dyn std::error::Error>> {
        let locator = WorkspaceLocator::new(
            LocationId::from_uuid(Uuid::from_u128(1)),
            LocationRevision::new(1)?,
            "private-workspace-path",
        )?;
        Ok(ResolvedWorkspaceScope::from_observation(
            WorkspaceId::from_uuid(Uuid::from_u128(2)),
            WorkspaceRevision::new(1)?,
            locator,
        ))
    }
}
