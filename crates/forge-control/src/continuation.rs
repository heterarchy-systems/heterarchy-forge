//! Application-owned continuation proposals and receipt acknowledgments.

use crate::{
    AgentSessionResolveRequest, ControlError, ControlErrorCode, ForgeControl,
    ResolvedWorkspaceScope, WorkCutService,
};
use forge_domain::{
    AgentAssignmentId, AgentAssignmentRevision, AgentAssignmentTarget, DagNodeRevision,
    WorkCutRequestDigest,
};
use forge_persistence::{
    AssignmentContinuationAcknowledgeOutcome, AssignmentContinuationAcknowledgment,
    AssignmentContinuationPrepareOutcome, AssignmentContinuationProposal,
};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContinuationCutWitness {
    pub cut_id: Uuid,
    pub cut_revision: i64,
    pub request_digest: WorkCutRequestDigest,
    pub snapshot_digest: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContinuationPrepare {
    pub transfer_id: Uuid,
    pub successor_id: AgentAssignmentId,
    pub source_assignment_id: AgentAssignmentId,
    pub source_revision: AgentAssignmentRevision,
    pub expected_node_revision: DagNodeRevision,
    pub recipient: AgentAssignmentTarget,
}

#[derive(Debug, Clone)]
pub struct ContinuationCommand {
    pub scope: ResolvedWorkspaceScope,
    pub service: WorkCutService,
    pub cut: ContinuationCutWitness,
    pub operation: ContinuationOperation,
}

#[derive(Debug, Clone, Copy)]
pub enum ContinuationOperation {
    Prepare(ContinuationPrepare),
    Get {
        successor_id: AgentAssignmentId,
    },
    Acknowledge {
        request_id: Uuid,
        successor_id: AgentAssignmentId,
        proposal_digest: [u8; 32],
        recipient: AgentAssignmentTarget,
    },
    AcknowledgmentGet {
        request_id: Uuid,
        successor_id: AgentAssignmentId,
        proposal_digest: [u8; 32],
    },
}

#[must_use]
#[derive(Debug, Clone)]
pub enum ContinuationResponse {
    Prepared(AssignmentContinuationPrepareOutcome),
    Proposal(Option<AssignmentContinuationProposal>),
    Acknowledged(AssignmentContinuationAcknowledgeOutcome),
    Acknowledgment(Option<AssignmentContinuationAcknowledgment>),
}

impl ForgeControl {
    pub fn assignment_continuation(
        &self,
        command: &ContinuationCommand,
        now: forge_domain::TimestampMillis,
    ) -> Result<ContinuationResponse, ControlError> {
        validate_command(command)?;
        let (fresh, mut store) = self.open_resolved_workspace(
            command.scope.locator().location_id(),
            command.scope.locator().expected_revision(),
            command.scope.locator(),
        )?;
        if fresh != command.scope {
            return Err(ControlError::new(
                ControlErrorCode::WorkspaceRevisionConflict,
            ));
        }
        let cut = store
            .get_leadership_work_cut(command.cut.cut_id)
            .map_err(map_store_error)?
            .ok_or_else(conflict)?;
        validate_cut(command, &cut)?;
        let response = match command.operation {
            ContinuationOperation::Prepare(request) => {
                for binding in cut.request().bindings() {
                    self.resolve_continuation_session(binding.session_id(), binding.principal())?;
                }
                ContinuationResponse::Prepared(prepare(&mut store, command, request, now)?)
            }
            ContinuationOperation::Get { successor_id } => {
                let proposal = store
                    .get_assignment_continuation(successor_id)
                    .map_err(map_store_error)?;
                if let Some(proposal) = &proposal {
                    validate_proposal(command, successor_id, proposal)?;
                }
                ContinuationResponse::Proposal(proposal)
            }
            ContinuationOperation::Acknowledge {
                request_id,
                successor_id,
                proposal_digest,
                recipient,
            } => {
                let proposal = store
                    .get_assignment_continuation(successor_id)
                    .map_err(map_store_error)?
                    .ok_or_else(conflict)?;
                validate_proposal(command, successor_id, &proposal)?;
                if proposal.digest() != &proposal_digest {
                    return Err(conflict());
                }
                self.resolve_continuation_session(recipient.session_id(), recipient.principal())?;
                ContinuationResponse::Acknowledged(
                    store
                        .acknowledge_assignment_continuation(
                            request_id,
                            successor_id,
                            proposal_digest,
                            recipient,
                            now,
                        )
                        .map_err(map_store_error)?,
                )
            }
            ContinuationOperation::AcknowledgmentGet {
                request_id,
                successor_id,
                proposal_digest,
            } => {
                let receipt = store
                    .get_assignment_continuation_acknowledgment(request_id)
                    .map_err(map_store_error)?;
                if let Some(receipt) = &receipt {
                    if receipt.request_id() != request_id
                        || receipt.successor_id() != successor_id
                        || receipt.proposal_digest() != &proposal_digest
                    {
                        return Err(conflict());
                    }
                    let proposal = store
                        .get_assignment_continuation(successor_id)
                        .map_err(map_store_error)?
                        .ok_or_else(conflict)?;
                    validate_proposal(command, successor_id, &proposal)?;
                    if proposal.digest() != &proposal_digest {
                        return Err(conflict());
                    }
                }
                ContinuationResponse::Acknowledgment(receipt)
            }
        };
        if !self.committed_scope_matches_with_store(&command.scope, &store) {
            return Err(
                if matches!(
                    command.operation,
                    ContinuationOperation::Prepare(_) | ContinuationOperation::Acknowledge { .. }
                ) {
                    ControlError::committed()
                } else {
                    ControlError::new(ControlErrorCode::WorkspaceRootConflict)
                },
            );
        }
        Ok(response)
    }

    fn resolve_continuation_session(
        &self,
        session_id: forge_domain::AgentSessionId,
        principal: forge_domain::AuthenticatedPrincipal,
    ) -> Result<(), ControlError> {
        let resolved = self.agent_session_resolve(AgentSessionResolveRequest {
            session_id,
            principal,
        })?;
        if resolved.id() != session_id || resolved.principal() != principal {
            return Err(conflict());
        }
        Ok(())
    }
}

fn validate_cut(
    command: &ContinuationCommand,
    cut: &forge_persistence::WorkCutRecord,
) -> Result<(), ControlError> {
    let request = cut.request();
    if request.cut_id() != command.cut.cut_id
        || request.workspace_id() != command.scope.workspace_id()
        || request.workspace_revision() != command.scope.workspace_revision()
        || request.request_digest() != command.cut.request_digest
        || cut.snapshot_digest() != &command.cut.snapshot_digest
        || cut.issuer() != command.service.issuer
        || request.backend_id() != command.service.backend_id
        || request.destination_id() != command.service.destination_id
    {
        return Err(conflict());
    }
    Ok(())
}

fn validate_proposal(
    command: &ContinuationCommand,
    successor_id: AgentAssignmentId,
    proposal: &AssignmentContinuationProposal,
) -> Result<(), ControlError> {
    if proposal.successor_id() != successor_id
        || proposal.workspace_id() != command.scope.workspace_id()
        || proposal.cut_id() != command.cut.cut_id
        || proposal.cut_revision() != command.cut.cut_revision
        || proposal.cut_request_digest() != command.cut.request_digest.as_bytes()
        || proposal.cut_snapshot_digest() != &command.cut.snapshot_digest
        || proposal.issuer() != command.service.issuer
        || proposal.backend_id() != command.service.backend_id
    {
        return Err(conflict());
    }
    Ok(())
}

fn prepare(
    store: &mut forge_persistence::WorkspaceStore,
    command: &ContinuationCommand,
    request: ContinuationPrepare,
    now: forge_domain::TimestampMillis,
) -> Result<AssignmentContinuationPrepareOutcome, ControlError> {
    let intent = forge_persistence::AssignmentContinuationIntent::new(
        command.cut.cut_id,
        command.cut.cut_revision,
        *command.cut.request_digest.as_bytes(),
        command.cut.snapshot_digest,
        request.transfer_id,
        request.successor_id,
        request.source_assignment_id,
        request.source_revision,
        request.expected_node_revision,
        request.recipient,
    )
    .map_err(|_| conflict())?;
    store
        .prepare_assignment_continuation_intent(
            &intent,
            command.service.issuer,
            command.service.backend_id,
            now,
        )
        .map_err(map_store_error)
}

fn validate_command(command: &ContinuationCommand) -> Result<(), ControlError> {
    if command.cut.cut_id.is_nil()
        || command.cut.cut_revision < 1
        || command.cut.request_digest.as_bytes() == &[0; 32]
        || command.cut.snapshot_digest == [0; 32]
        || command.service.issuer.into_uuid().is_nil()
        || command.service.backend_id.into_uuid().is_nil()
        || command.service.destination_id.is_nil()
    {
        return Err(conflict());
    }
    match command.operation {
        ContinuationOperation::Prepare(request) => {
            if request.transfer_id.is_nil()
                || request.successor_id.into_uuid().is_nil()
                || request.source_assignment_id.into_uuid().is_nil()
                || request.successor_id == request.source_assignment_id
            {
                return Err(conflict());
            }
            validate_recipient(request.recipient)?;
        }
        ContinuationOperation::Get { successor_id } => {
            if successor_id.into_uuid().is_nil() {
                return Err(conflict());
            }
        }
        ContinuationOperation::Acknowledge {
            request_id,
            successor_id,
            proposal_digest,
            recipient,
        } => {
            validate_receipt_key(request_id, successor_id, proposal_digest)?;
            validate_recipient(recipient)?;
        }
        ContinuationOperation::AcknowledgmentGet {
            request_id,
            successor_id,
            proposal_digest,
        } => {
            validate_receipt_key(request_id, successor_id, proposal_digest)?;
        }
    }
    Ok(())
}

fn validate_recipient(recipient: AgentAssignmentTarget) -> Result<(), ControlError> {
    if recipient.agent_id().into_uuid().is_nil() || recipient.session_id().into_uuid().is_nil() {
        return Err(conflict());
    }
    Ok(())
}

fn validate_receipt_key(
    request_id: Uuid,
    successor_id: AgentAssignmentId,
    proposal_digest: [u8; 32],
) -> Result<(), ControlError> {
    if request_id.is_nil() || successor_id.into_uuid().is_nil() || proposal_digest == [0; 32] {
        return Err(conflict());
    }
    Ok(())
}

fn conflict() -> ControlError {
    ControlError::new(ControlErrorCode::AgentDagReplayConflict)
}

fn map_store_error(error: forge_persistence::WorkspaceStoreError) -> ControlError {
    use forge_persistence::{WorkCutError, WorkspaceStoreError};
    if matches!(
        error,
        WorkspaceStoreError::AssignmentContinuationReadbackRequired { .. }
            | WorkspaceStoreError::WorkCut(WorkCutError::ContinuationCommitUnconfirmed { .. })
    ) {
        return ControlError::committed();
    }
    let code = match &error {
        WorkspaceStoreError::WorkCut(WorkCutError::Bounds) => ControlErrorCode::CapacityExceeded,
        WorkspaceStoreError::WorkCut(
            WorkCutError::Conflict(_) | WorkCutError::ContinuationDomain(_),
        ) => ControlErrorCode::AgentDagReplayConflict,
        _ => ControlErrorCode::PersistenceFailure,
    };
    ControlError::with_source(code, error)
}
