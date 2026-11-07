//! Authenticated, exact-source reads and cuts for Forge-owned evaluation evidence.

use forge_domain::{
    AgentAssignmentId, AgentAssignmentRevision, EvaluationDigest, EvaluationManifestId,
    EvaluationManifestProposal, EvaluationOriginalBindingStatus, EvaluationRegisteredManifest,
    EvaluationReviewCut, EvaluationReviewCutId, EvaluationReviewReceipt, EvaluationRevision,
    EvaluationSourceIdentity, EvaluationSubmissionReceipt, EvaluationT1CloseRequest,
    EvaluationT1CoverageCut, ForgeBackendId, TimestampMillis,
};
use forge_persistence::{EvaluationEvidenceMutationIdentity, EvaluationT1ClosureOutcome};
use uuid::Uuid;

use crate::{ControlError, ControlErrorCode, ForgeControl, ResolvedWorkspaceScope};

/// Service identity supplied by the authenticated backend composition root.
///
/// HTTP callers cannot choose this value. The backend validates its echoed
/// service fields against its configuration before creating this type.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvaluationEvidenceService {
    backend_id: ForgeBackendId,
    destination_id: Uuid,
}

impl EvaluationEvidenceService {
    pub const fn new(backend_id: ForgeBackendId, destination_id: Uuid) -> Self {
        Self {
            backend_id,
            destination_id,
        }
    }

    pub const fn backend_id(self) -> ForgeBackendId {
        self.backend_id
    }

    pub const fn destination_id(self) -> Uuid {
        self.destination_id
    }
}

/// Exact operation identity for one source-evidence command.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvaluationEvidenceOperation {
    SealManifest {
        proposal: EvaluationManifestProposal,
    },
    GetManifest {
        manifest_id: EvaluationManifestId,
        revision: EvaluationRevision,
        digest: EvaluationDigest,
    },
    CloseT1 {
        request: EvaluationT1CloseRequest,
    },
    GetT1Cut {
        request: EvaluationT1CloseRequest,
    },
    CreateReviewCut {
        review_cut_id: EvaluationReviewCutId,
        t1_request: EvaluationT1CloseRequest,
    },
    GetReviewCut {
        review_cut_id: EvaluationReviewCutId,
        t1_request: EvaluationT1CloseRequest,
    },
    GetSubmissionReceipt {
        manifest_id: EvaluationManifestId,
        manifest_revision: EvaluationRevision,
        manifest_digest: EvaluationDigest,
        assignment_id: AgentAssignmentId,
        submitted_revision: AgentAssignmentRevision,
    },
    GetReviewReceipt {
        manifest_id: EvaluationManifestId,
        manifest_revision: EvaluationRevision,
        manifest_digest: EvaluationDigest,
        assignment_id: AgentAssignmentId,
        submitted_revision: AgentAssignmentRevision,
        review_revision: AgentAssignmentRevision,
    },
}

/// Workspace and delegation identity carried by every evaluation command.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluationEvidenceRequest {
    pub scope: ResolvedWorkspaceScope,
    pub source: EvaluationSourceIdentity,
    pub operation: EvaluationEvidenceOperation,
}

impl EvaluationEvidenceRequest {
    pub const fn new(
        scope: ResolvedWorkspaceScope,
        source: EvaluationSourceIdentity,
        operation: EvaluationEvidenceOperation,
    ) -> Self {
        Self {
            scope,
            source,
            operation,
        }
    }

    /// The durable identity to use if an admitted mutation response is lost.
    pub fn mutation_identity(&self) -> Option<EvaluationEvidenceMutationIdentity> {
        match &self.operation {
            EvaluationEvidenceOperation::SealManifest { proposal } => {
                Some(EvaluationEvidenceMutationIdentity::Manifest {
                    manifest_id: proposal.manifest_id(),
                    revision: proposal.revision(),
                    digest: proposal.digest(),
                })
            }
            EvaluationEvidenceOperation::CloseT1 { request } => {
                Some(EvaluationEvidenceMutationIdentity::T1Closure { request: *request })
            }
            EvaluationEvidenceOperation::CreateReviewCut {
                review_cut_id,
                t1_request,
                ..
            } => Some(EvaluationEvidenceMutationIdentity::ReviewCut {
                review_cut_id: *review_cut_id,
                t1_cut_id: t1_request.cut_id(),
            }),
            EvaluationEvidenceOperation::GetManifest { .. }
            | EvaluationEvidenceOperation::GetT1Cut { .. }
            | EvaluationEvidenceOperation::GetReviewCut { .. }
            | EvaluationEvidenceOperation::GetSubmissionReceipt { .. }
            | EvaluationEvidenceOperation::GetReviewReceipt { .. } => None,
        }
    }
}

/// Typed result for the closed evaluation-evidence operation family.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvaluationEvidenceResponse {
    ManifestSealed(EvaluationRegisteredManifest),
    ManifestRead(Option<EvaluationRegisteredManifest>),
    T1Closed(EvaluationT1ClosureOutcome),
    T1Read(Option<EvaluationT1CoverageCut>),
    ReviewCutCreated(EvaluationReviewCut),
    ReviewCutRead(Option<EvaluationReviewCut>),
    SubmissionReceiptRead(Option<EvaluationSubmissionReceipt>),
    ReviewReceiptRead(Option<EvaluationReviewReceipt>),
}

impl ForgeControl {
    /// Read or mutate one exact evaluation source identity through the single
    /// Workspace owner. Clock sampling is passed to persistence and therefore
    /// occurs only at its transaction-defined admission point.
    pub fn evaluation_evidence<C>(
        &self,
        request: &EvaluationEvidenceRequest,
        service: EvaluationEvidenceService,
        sample_clock: C,
    ) -> Result<EvaluationEvidenceResponse, ControlError>
    where
        C: FnOnce() -> forge_domain::EvaluationClockReading,
    {
        validate_request_identity(request, service)?;
        let (scope, mut store) = self.open_resolved_workspace(
            request.scope.locator().location_id(),
            request.scope.locator().expected_revision(),
            request.scope.locator(),
        )?;
        if scope != request.scope {
            return Err(ControlError::new(
                ControlErrorCode::WorkspaceRevisionConflict,
            ));
        }
        validate_active_delegation(&store, request.source, service)?;
        let result = execute_operation(&mut store, request, service, sample_clock)?;

        if is_mutation(&request.operation) {
            if self.committed_scope_matches_with_store(&scope, &store) {
                Ok(result)
            } else {
                Err(ControlError::committed())
            }
        } else if self.committed_scope_matches_with_store(&scope, &store) {
            Ok(result)
        } else {
            Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict))
        }
    }
}

fn execute_operation<C>(
    store: &mut forge_persistence::WorkspaceStore,
    request: &EvaluationEvidenceRequest,
    service: EvaluationEvidenceService,
    sample_clock: C,
) -> Result<EvaluationEvidenceResponse, ControlError>
where
    C: FnOnce() -> forge_domain::EvaluationClockReading,
{
    match &request.operation {
        EvaluationEvidenceOperation::SealManifest { .. }
        | EvaluationEvidenceOperation::GetManifest { .. } => {
            execute_manifest_operation(store, request, service, sample_clock)
        }
        EvaluationEvidenceOperation::CloseT1 { .. }
        | EvaluationEvidenceOperation::GetT1Cut { .. } => {
            execute_t1_operation(store, request, service, sample_clock)
        }
        EvaluationEvidenceOperation::CreateReviewCut { .. }
        | EvaluationEvidenceOperation::GetReviewCut { .. } => {
            execute_review_cut_operation(store, request, service, sample_clock)
        }
        EvaluationEvidenceOperation::GetSubmissionReceipt { .. }
        | EvaluationEvidenceOperation::GetReviewReceipt { .. } => {
            execute_receipt_operation(store, request, service)
        }
    }
}

fn execute_manifest_operation<C>(
    store: &mut forge_persistence::WorkspaceStore,
    request: &EvaluationEvidenceRequest,
    service: EvaluationEvidenceService,
    sample_clock: C,
) -> Result<EvaluationEvidenceResponse, ControlError>
where
    C: FnOnce() -> forge_domain::EvaluationClockReading,
{
    match &request.operation {
        EvaluationEvidenceOperation::SealManifest { proposal } => {
            if proposal.source() != request.source {
                return Err(conflict());
            }
            let manifest = store
                .seal_evaluation_manifest(service.backend_id, proposal, sample_clock)
                .map_err(map_evaluation_store_error)?;
            validate_registered_manifest(
                &manifest,
                request.source,
                proposal.manifest_id(),
                proposal.revision(),
                proposal.digest(),
                Some(proposal.deadline()),
            )?;
            Ok(EvaluationEvidenceResponse::ManifestSealed(manifest))
        }
        EvaluationEvidenceOperation::GetManifest {
            manifest_id,
            revision,
            digest,
        } => {
            let manifest = store
                .get_evaluation_manifest(service.backend_id, *manifest_id, *revision)
                .map_err(map_evaluation_store_error)?;
            if let Some(manifest) = &manifest {
                validate_registered_manifest(
                    manifest,
                    request.source,
                    *manifest_id,
                    *revision,
                    *digest,
                    None,
                )?;
            }
            Ok(EvaluationEvidenceResponse::ManifestRead(manifest))
        }
        _ => Err(conflict()),
    }
}

fn execute_t1_operation<C>(
    store: &mut forge_persistence::WorkspaceStore,
    request: &EvaluationEvidenceRequest,
    service: EvaluationEvidenceService,
    sample_clock: C,
) -> Result<EvaluationEvidenceResponse, ControlError>
where
    C: FnOnce() -> forge_domain::EvaluationClockReading,
{
    match &request.operation {
        EvaluationEvidenceOperation::CloseT1 {
            request: close_request,
        } => {
            let _manifest = load_exact_manifest(
                store,
                service.backend_id,
                request.source,
                close_request.manifest_id(),
                close_request.manifest_revision(),
                close_request.manifest_digest(),
                Some(close_request.deadline()),
            )?;
            let outcome = store
                .close_evaluation_t1(service.backend_id, close_request, sample_clock)
                .map_err(map_evaluation_store_error)?;
            if let EvaluationT1ClosureOutcome::Closed(cut) = &outcome {
                validate_t1_cut(
                    store,
                    service.backend_id,
                    cut,
                    request.source,
                    close_request,
                )?;
            }
            Ok(EvaluationEvidenceResponse::T1Closed(outcome))
        }
        EvaluationEvidenceOperation::GetT1Cut {
            request: cut_request,
        } => {
            let cut = store
                .get_evaluation_t1_cut(service.backend_id, cut_request.cut_id())
                .map_err(map_evaluation_store_error)?;
            if let Some(cut) = &cut {
                validate_t1_cut(store, service.backend_id, cut, request.source, cut_request)?;
            }
            Ok(EvaluationEvidenceResponse::T1Read(cut))
        }
        _ => Err(conflict()),
    }
}

fn execute_review_cut_operation<C>(
    store: &mut forge_persistence::WorkspaceStore,
    request: &EvaluationEvidenceRequest,
    service: EvaluationEvidenceService,
    sample_clock: C,
) -> Result<EvaluationEvidenceResponse, ControlError>
where
    C: FnOnce() -> forge_domain::EvaluationClockReading,
{
    match &request.operation {
        EvaluationEvidenceOperation::CreateReviewCut {
            review_cut_id,
            t1_request,
        } => {
            let _t1_cut = load_exact_t1_cut(store, service.backend_id, request.source, t1_request)?;
            let review_cut = store
                .create_evaluation_review_cut(
                    service.backend_id,
                    *review_cut_id,
                    t1_request.cut_id(),
                    sample_clock,
                )
                .map_err(map_evaluation_store_error)?;
            validate_review_cut(
                store,
                service.backend_id,
                request.source,
                &review_cut,
                *review_cut_id,
                t1_request,
            )?;
            Ok(EvaluationEvidenceResponse::ReviewCutCreated(review_cut))
        }
        EvaluationEvidenceOperation::GetReviewCut {
            review_cut_id,
            t1_request,
        } => {
            let review_cut = store
                .get_evaluation_review_cut(service.backend_id, *review_cut_id)
                .map_err(map_evaluation_store_error)?;
            if let Some(review_cut) = &review_cut {
                validate_review_cut(
                    store,
                    service.backend_id,
                    request.source,
                    review_cut,
                    *review_cut_id,
                    t1_request,
                )?;
            }
            Ok(EvaluationEvidenceResponse::ReviewCutRead(review_cut))
        }
        _ => Err(conflict()),
    }
}

fn execute_receipt_operation(
    store: &forge_persistence::WorkspaceStore,
    request: &EvaluationEvidenceRequest,
    service: EvaluationEvidenceService,
) -> Result<EvaluationEvidenceResponse, ControlError> {
    match &request.operation {
        EvaluationEvidenceOperation::GetSubmissionReceipt {
            manifest_id,
            manifest_revision,
            manifest_digest,
            assignment_id,
            submitted_revision,
        } => {
            let manifest = load_exact_manifest(
                store,
                service.backend_id,
                request.source,
                *manifest_id,
                *manifest_revision,
                *manifest_digest,
                None,
            )?;
            let receipt = store
                .get_evaluation_submission_receipt(
                    service.backend_id,
                    *assignment_id,
                    *submitted_revision,
                )
                .map_err(map_evaluation_store_error)?;
            if let Some(receipt) = &receipt {
                validate_submission_receipt(
                    &manifest,
                    *assignment_id,
                    *submitted_revision,
                    receipt,
                )?;
            }
            Ok(EvaluationEvidenceResponse::SubmissionReceiptRead(receipt))
        }
        EvaluationEvidenceOperation::GetReviewReceipt {
            manifest_id,
            manifest_revision,
            manifest_digest,
            assignment_id,
            submitted_revision,
            review_revision,
        } => {
            let manifest = load_exact_manifest(
                store,
                service.backend_id,
                request.source,
                *manifest_id,
                *manifest_revision,
                *manifest_digest,
                None,
            )?;
            let receipt = store
                .get_evaluation_review_receipt(
                    service.backend_id,
                    *assignment_id,
                    *submitted_revision,
                    *review_revision,
                )
                .map_err(map_evaluation_store_error)?;
            if let Some(receipt) = &receipt {
                let submission = store
                    .get_evaluation_submission_receipt(
                        service.backend_id,
                        *assignment_id,
                        *submitted_revision,
                    )
                    .map_err(map_evaluation_store_error)?
                    .ok_or_else(conflict)?;
                validate_submission_receipt(
                    &manifest,
                    *assignment_id,
                    *submitted_revision,
                    &submission,
                )?;
                validate_review_receipt(
                    *assignment_id,
                    *submitted_revision,
                    *review_revision,
                    &submission,
                    receipt,
                )?;
            }
            Ok(EvaluationEvidenceResponse::ReviewReceiptRead(receipt))
        }
        _ => Err(conflict()),
    }
}

fn validate_request_identity(
    request: &EvaluationEvidenceRequest,
    service: EvaluationEvidenceService,
) -> Result<(), ControlError> {
    if service.backend_id.into_uuid().is_nil()
        || service.destination_id.is_nil()
        || request.source.backend_id() != service.backend_id
        || request.source.delegation_destination_id() != service.destination_id
        || request.source.workspace_id() != request.scope.workspace_id()
    {
        return Err(conflict());
    }
    if let EvaluationEvidenceOperation::SealManifest { proposal } = &request.operation
        && proposal.source() != request.source
    {
        return Err(conflict());
    }
    Ok(())
}

fn validate_active_delegation(
    store: &forge_persistence::WorkspaceStore,
    source: EvaluationSourceIdentity,
    service: EvaluationEvidenceService,
) -> Result<(), ControlError> {
    let delegation = store
        .agent_operations_delegation()
        .map_err(map_evaluation_store_error)?
        .ok_or_else(conflict)?;
    let expected_digest = source.delegation_manifest_digest();
    let expected_freeze_revision = u64::try_from(source.delegation_freeze_revision().get()).ok();
    if delegation.workspace_id() != source.workspace_id()
        || delegation.migration_id() != source.delegation_migration_id()
        || delegation.destination_id() != service.destination_id
        || Some(delegation.freeze().revision()) != expected_freeze_revision
        || delegation.manifest_digest().as_slice() != expected_digest.as_bytes()
    {
        return Err(conflict());
    }
    Ok(())
}

fn load_exact_manifest(
    store: &forge_persistence::WorkspaceStore,
    backend_id: ForgeBackendId,
    source: EvaluationSourceIdentity,
    manifest_id: EvaluationManifestId,
    revision: EvaluationRevision,
    digest: EvaluationDigest,
    deadline: Option<TimestampMillis>,
) -> Result<EvaluationRegisteredManifest, ControlError> {
    let manifest = store
        .get_evaluation_manifest(backend_id, manifest_id, revision)
        .map_err(map_evaluation_store_error)?
        .ok_or_else(conflict)?;
    validate_registered_manifest(&manifest, source, manifest_id, revision, digest, deadline)?;
    Ok(manifest)
}

fn validate_registered_manifest(
    manifest: &EvaluationRegisteredManifest,
    source: EvaluationSourceIdentity,
    manifest_id: EvaluationManifestId,
    revision: EvaluationRevision,
    digest: EvaluationDigest,
    deadline: Option<TimestampMillis>,
) -> Result<(), ControlError> {
    let proposal = manifest.proposal();
    if proposal.source() != source
        || proposal.manifest_id() != manifest_id
        || proposal.revision() != revision
        || proposal.digest() != digest
        || deadline.is_some_and(|expected| proposal.deadline() != expected)
    {
        return Err(conflict());
    }
    Ok(())
}

fn load_exact_t1_cut(
    store: &forge_persistence::WorkspaceStore,
    backend_id: ForgeBackendId,
    source: EvaluationSourceIdentity,
    request: &EvaluationT1CloseRequest,
) -> Result<EvaluationT1CoverageCut, ControlError> {
    let cut = store
        .get_evaluation_t1_cut(backend_id, request.cut_id())
        .map_err(map_evaluation_store_error)?
        .ok_or_else(conflict)?;
    validate_t1_cut(store, backend_id, &cut, source, request)?;
    Ok(cut)
}

fn validate_t1_cut(
    store: &forge_persistence::WorkspaceStore,
    backend_id: ForgeBackendId,
    cut: &EvaluationT1CoverageCut,
    source: EvaluationSourceIdentity,
    request: &EvaluationT1CloseRequest,
) -> Result<(), ControlError> {
    if cut.cut_id() != request.cut_id()
        || cut.manifest_id() != request.manifest_id()
        || cut.manifest_revision() != request.manifest_revision()
        || cut.manifest_digest() != request.manifest_digest()
        || cut.deadline() != request.deadline()
    {
        return Err(conflict());
    }
    let _ = load_exact_manifest(
        store,
        backend_id,
        source,
        request.manifest_id(),
        request.manifest_revision(),
        request.manifest_digest(),
        Some(request.deadline()),
    )?;
    Ok(())
}

fn validate_review_cut(
    store: &forge_persistence::WorkspaceStore,
    backend_id: ForgeBackendId,
    source: EvaluationSourceIdentity,
    review_cut: &EvaluationReviewCut,
    review_cut_id: EvaluationReviewCutId,
    t1_request: &EvaluationT1CloseRequest,
) -> Result<(), ControlError> {
    if review_cut.review_cut_id() != review_cut_id || review_cut.t1_cut_id() != t1_request.cut_id()
    {
        return Err(conflict());
    }
    let t1_cut = load_exact_t1_cut(store, backend_id, source, t1_request)?;
    let same_members =
        review_cut
            .members()
            .iter()
            .zip(t1_cut.members())
            .all(|(review_member, t1_member)| {
                review_member.member() == t1_member.member()
                    && review_member.coverage() == t1_member.coverage()
            });
    if review_cut.source_high_water().get() <= t1_cut.source_high_water().get()
        || review_cut.members().len() != t1_cut.members().len()
        || !same_members
    {
        return Err(conflict());
    }
    Ok(())
}

fn validate_submission_receipt(
    manifest: &EvaluationRegisteredManifest,
    assignment_id: AgentAssignmentId,
    submitted_revision: AgentAssignmentRevision,
    receipt: &EvaluationSubmissionReceipt,
) -> Result<(), ControlError> {
    let member = manifest
        .members()
        .iter()
        .find(|member| member.declaration().assignment_id() == assignment_id)
        .ok_or_else(conflict)?;
    let declaration = member.declaration();
    if receipt.assignment_id() != assignment_id
        || receipt.submitted_revision() != submitted_revision
        || receipt.author_agent_id() != declaration.target_agent_id()
        || receipt.author_session_id() != declaration.target_session_id()
    {
        return Err(conflict());
    }
    match member.binding() {
        EvaluationOriginalBindingStatus::Bound(binding)
            if receipt.original_binding_digest() == Some(binding.digest())
                && receipt.criteria_digest() == Some(declaration.criteria_digest()) => {}
        EvaluationOriginalBindingStatus::UnknownHistorical
            if receipt.original_binding_digest().is_none()
                && receipt.criteria_digest().is_none() => {}
        _ => return Err(conflict()),
    }
    Ok(())
}

fn validate_review_receipt(
    assignment_id: AgentAssignmentId,
    submitted_revision: AgentAssignmentRevision,
    review_revision: AgentAssignmentRevision,
    submission: &EvaluationSubmissionReceipt,
    review: &EvaluationReviewReceipt,
) -> Result<(), ControlError> {
    if review.assignment_id() != assignment_id
        || review.submitted_revision() != submitted_revision
        || review.review_revision() != review_revision
        || review.author_agent_id() != submission.author_agent_id()
        || review.author_session_id() != submission.author_session_id()
        || review.reviewer_agent_id() == review.author_agent_id()
        || review.result_digest() != submission.result_digest()
    {
        return Err(conflict());
    }
    Ok(())
}

fn is_mutation(operation: &EvaluationEvidenceOperation) -> bool {
    matches!(
        operation,
        EvaluationEvidenceOperation::SealManifest { .. }
            | EvaluationEvidenceOperation::CloseT1 { .. }
            | EvaluationEvidenceOperation::CreateReviewCut { .. }
    )
}

fn map_evaluation_store_error(error: forge_persistence::WorkspaceStoreError) -> ControlError {
    if matches!(
        &error,
        forge_persistence::WorkspaceStoreError::EvaluationEvidenceCommittedUnconfirmed { .. }
    ) {
        return ControlError::committed_with_source(error);
    }
    if matches!(
        &error,
        forge_persistence::WorkspaceStoreError::AgentAssignmentCommittedUnconfirmed { .. }
    ) {
        return ControlError::committed_with_source(error);
    }
    ControlError::with_source(ControlErrorCode::PersistenceFailure, error)
}

fn conflict() -> ControlError {
    ControlError::new(ControlErrorCode::AgentEvidenceConflict)
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;
    use forge_domain::{
        AgentAssignmentRevision, AgentInstanceId, AgentSessionId, EvaluationAdmissionTiming,
        EvaluationCutId, EvaluationManifestMember, EvaluationObligationId,
        EvaluationOriginalAssignmentBinding, EvaluationPlanBinding, EvaluationPlanId,
        EvaluationSourceSequence, EvaluationWorkUnitId, WorkspaceId,
    };

    #[test]
    fn close_t1_recovery_identity_keeps_frozen_deadline_and_manifest_digest()
    -> Result<(), Box<dyn Error>> {
        let cut_id = EvaluationCutId::new(Uuid::from_u128(11))?;
        let manifest_id = EvaluationManifestId::new(Uuid::from_u128(12))?;
        let revision = EvaluationRevision::new(2)?;
        let digest = EvaluationDigest::new([7; 32])?;
        let deadline = TimestampMillis::new(500)?;
        let close_request =
            EvaluationT1CloseRequest::new(cut_id, manifest_id, revision, digest, deadline);
        let identity = EvaluationEvidenceMutationIdentity::T1Closure {
            request: close_request,
        };
        let request = EvaluationEvidenceRequest {
            scope: test_scope()?,
            source: test_source()?,
            operation: EvaluationEvidenceOperation::CloseT1 {
                request: close_request,
            },
        };
        assert_eq!(request.mutation_identity(), Some(identity));
        Ok(())
    }

    #[test]
    fn read_operations_have_no_mutation_recovery_identity() -> Result<(), Box<dyn Error>> {
        let request = EvaluationEvidenceRequest {
            scope: test_scope()?,
            source: test_source()?,
            operation: EvaluationEvidenceOperation::GetT1Cut {
                request: EvaluationT1CloseRequest::new(
                    EvaluationCutId::new(Uuid::from_u128(21))?,
                    EvaluationManifestId::new(Uuid::from_u128(22))?,
                    EvaluationRevision::new(1)?,
                    EvaluationDigest::new([9; 32])?,
                    TimestampMillis::new(500)?,
                ),
            },
        };
        assert_eq!(request.mutation_identity(), None);
        Ok(())
    }

    #[test]
    fn configured_backend_destination_and_workspace_fence_source_requests()
    -> Result<(), Box<dyn Error>> {
        use forge_domain::ForgeBackendId;
        let request = EvaluationEvidenceRequest {
            scope: test_scope()?,
            source: test_source()?,
            operation: EvaluationEvidenceOperation::GetManifest {
                manifest_id: EvaluationManifestId::new(Uuid::from_u128(31))?,
                revision: EvaluationRevision::new(1)?,
                digest: EvaluationDigest::new([3; 32])?,
            },
        };
        let service = EvaluationEvidenceService::new(
            ForgeBackendId::from_uuid(Uuid::from_u128(3)),
            Uuid::from_u128(6),
        );
        assert!(validate_request_identity(&request, service).is_ok());
        assert!(
            validate_request_identity(
                &request,
                EvaluationEvidenceService::new(
                    ForgeBackendId::from_uuid(Uuid::from_u128(33)),
                    Uuid::from_u128(6),
                ),
            )
            .is_err()
        );
        assert!(
            validate_request_identity(
                &request,
                EvaluationEvidenceService::new(
                    ForgeBackendId::from_uuid(Uuid::from_u128(3)),
                    Uuid::from_u128(66),
                ),
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn registered_manifest_readback_requires_exact_source_digest_and_deadline()
    -> Result<(), Box<dyn Error>> {
        let manifest = registered_manifest()?;
        let proposal = manifest.proposal();
        let source = test_source()?;
        assert!(
            validate_registered_manifest(
                &manifest,
                source,
                proposal.manifest_id(),
                proposal.revision(),
                proposal.digest(),
                Some(proposal.deadline()),
            )
            .is_ok()
        );
        assert!(
            validate_registered_manifest(
                &manifest,
                source,
                proposal.manifest_id(),
                proposal.revision(),
                EvaluationDigest::new([12; 32])?,
                Some(proposal.deadline()),
            )
            .is_err()
        );
        assert!(
            validate_registered_manifest(
                &manifest,
                source_with_workspace(WorkspaceId::from_uuid(Uuid::from_u128(999)))?,
                proposal.manifest_id(),
                proposal.revision(),
                proposal.digest(),
                Some(proposal.deadline()),
            )
            .is_err()
        );
        assert!(
            validate_registered_manifest(
                &manifest,
                source,
                proposal.manifest_id(),
                proposal.revision(),
                proposal.digest(),
                Some(TimestampMillis::new(501)?),
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn submission_receipt_binds_original_assignment_agent_session_and_criteria()
    -> Result<(), Box<dyn Error>> {
        let manifest = registered_manifest()?;
        let member = manifest.members()[0].declaration();
        let receipt = EvaluationSubmissionReceipt::from_source_record(
            member.assignment_id(),
            AgentAssignmentRevision::new(2)?,
            member.target_agent_id(),
            member.target_session_id(),
            Some(EvaluationDigest::new([5; 32])?),
            Some(member.criteria_digest()),
            EvaluationSourceSequence::new(2)?,
            EvaluationAdmissionTiming::Trusted(TimestampMillis::new(300)?),
            EvaluationDigest::new([6; 32])?,
            None,
        )?;
        assert!(
            validate_submission_receipt(
                &manifest,
                member.assignment_id(),
                AgentAssignmentRevision::new(2)?,
                &receipt,
            )
            .is_ok()
        );

        let foreign_session = EvaluationSubmissionReceipt::from_source_record(
            member.assignment_id(),
            AgentAssignmentRevision::new(2)?,
            member.target_agent_id(),
            forge_domain::AgentSessionId::from_uuid(Uuid::from_u128(777)),
            Some(EvaluationDigest::new([5; 32])?),
            Some(member.criteria_digest()),
            EvaluationSourceSequence::new(2)?,
            EvaluationAdmissionTiming::Trusted(TimestampMillis::new(300)?),
            EvaluationDigest::new([6; 32])?,
            None,
        )?;
        assert!(
            validate_submission_receipt(
                &manifest,
                member.assignment_id(),
                AgentAssignmentRevision::new(2)?,
                &foreign_session,
            )
            .is_err()
        );
        Ok(())
    }

    fn test_scope() -> Result<ResolvedWorkspaceScope, Box<dyn Error>> {
        use forge_domain::{LocationId, LocationRevision, WorkspaceId, WorkspaceRevision};
        use forge_workspace::WorkspaceLocator;
        let locator = WorkspaceLocator::new(
            LocationId::from_uuid(Uuid::from_u128(1)),
            LocationRevision::new(1)?,
            "workspace",
        )?;
        Ok(ResolvedWorkspaceScope::from_observation(
            WorkspaceId::from_uuid(Uuid::from_u128(2)),
            WorkspaceRevision::new(1)?,
            locator,
        ))
    }

    fn test_source() -> Result<EvaluationSourceIdentity, Box<dyn Error>> {
        source_with_workspace(WorkspaceId::from_uuid(Uuid::from_u128(2)))
    }

    fn source_with_workspace(
        workspace_id: WorkspaceId,
    ) -> Result<EvaluationSourceIdentity, Box<dyn Error>> {
        use forge_domain::{ActivityId, ForgeBackendId};
        Ok(EvaluationSourceIdentity::new(
            ForgeBackendId::from_uuid(Uuid::from_u128(3)),
            workspace_id,
            ActivityId::from_uuid(Uuid::from_u128(4)),
            Uuid::from_u128(5),
            Uuid::from_u128(6),
            EvaluationRevision::new(1)?,
            EvaluationDigest::new([8; 32])?,
        )?)
    }

    fn registered_manifest() -> Result<EvaluationRegisteredManifest, Box<dyn Error>> {
        let assignment_id = AgentAssignmentId::from_uuid(Uuid::from_u128(700));
        let revision = AgentAssignmentRevision::new(1)?;
        let target_agent_id = AgentInstanceId::from_uuid(Uuid::from_u128(701));
        let target_session_id = AgentSessionId::from_uuid(Uuid::from_u128(702));
        let criteria_digest = EvaluationDigest::new([4; 32])?;
        let member = EvaluationManifestMember::new(
            EvaluationWorkUnitId::new(Uuid::from_u128(703))?,
            EvaluationObligationId::new(Uuid::from_u128(704))?,
            assignment_id,
            revision,
            target_agent_id,
            target_session_id,
            criteria_digest,
        )?;
        let proposal = EvaluationManifestProposal::new(
            EvaluationManifestId::new(Uuid::from_u128(705))?,
            EvaluationRevision::new(1)?,
            test_source()?,
            EvaluationPlanBinding::new(
                EvaluationPlanId::new(Uuid::from_u128(706))?,
                EvaluationRevision::new(1)?,
                EvaluationDigest::new([7; 32])?,
            ),
            TimestampMillis::new(900)?,
            vec![member],
        )?;
        let source_sequence = EvaluationSourceSequence::new(1)?;
        let binding = EvaluationOriginalAssignmentBinding::new(
            EvaluationDigest::new([5; 32])?,
            revision,
            source_sequence,
        );
        Ok(EvaluationRegisteredManifest::from_source_records(
            proposal,
            vec![forge_domain::EvaluationRegisteredManifestMember::new(
                member,
                EvaluationOriginalBindingStatus::Bound(binding),
            )],
            source_sequence,
            EvaluationAdmissionTiming::Trusted(TimestampMillis::new(100)?),
        )?)
    }
}
