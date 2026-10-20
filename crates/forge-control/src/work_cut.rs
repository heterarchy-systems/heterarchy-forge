//! Attested leadership source-cut application owner; no custody-release shortcut.

use crate::{
    AgentSessionResolveRequest, ControlError, ControlErrorCode, ForgeControl,
    ResolvedWorkspaceScope,
};
use forge_domain::{
    ForgeBackendId, OrchestrationIssuerId, TimestampMillis, WorkCutGrant, WorkCutRequest,
    WorkCutRequestDigest,
};
use forge_persistence::{
    WorkCutDrainObservation, WorkCutInventory, WorkCutPrepareOutcome, WorkCutRecord,
    WorkspaceStoreError,
};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkCutService {
    pub issuer: OrchestrationIssuerId,
    pub backend_id: ForgeBackendId,
    pub destination_id: Uuid,
}

#[derive(Debug, Clone)]
pub struct WorkCutCommand {
    pub scope: ResolvedWorkspaceScope,
    pub service: WorkCutService,
    pub operation: WorkCutOperation,
}

#[derive(Debug, Clone)]
pub enum WorkCutOperation {
    Inventory {
        request: WorkCutRequest,
    },
    Prepare {
        request: WorkCutRequest,
        grant: WorkCutGrant,
    },
    Get {
        cut_id: Uuid,
        request_digest: WorkCutRequestDigest,
    },
    Drain {
        cut_id: Uuid,
        request_digest: WorkCutRequestDigest,
        expected_revision: i64,
    },
}

#[must_use]
#[derive(Debug, Clone)]
pub enum WorkCutResponse {
    Inventory(WorkCutInventory),
    Prepared(WorkCutPrepareOutcome),
    Record(Option<WorkCutRecord>),
    Drain(WorkCutDrainObservation),
}

impl ForgeControl {
    pub fn leadership_work_cut(
        &self,
        command: &WorkCutCommand,
        now: TimestampMillis,
    ) -> Result<WorkCutResponse, ControlError> {
        validate_command(command)?;
        if let WorkCutOperation::Prepare { request, grant } = &command.operation {
            grant
                .validate_for(command.service.issuer, request.request_digest(), now)
                .map_err(|_| conflict())?;
        }
        if let WorkCutOperation::Prepare { request, .. } | WorkCutOperation::Inventory { request } =
            &command.operation
        {
            for binding in request.bindings() {
                let session = self.agent_session_resolve(AgentSessionResolveRequest {
                    session_id: binding.session_id(),
                    principal: binding.principal(),
                })?;
                if session.id() != binding.session_id()
                    || session.principal() != binding.principal()
                {
                    return Err(conflict());
                }
            }
        }
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
        let response = match &command.operation {
            WorkCutOperation::Inventory { request } => WorkCutResponse::Inventory(
                store
                    .observe_leadership_work_inventory(request)
                    .map_err(map_work_cut_error)?,
            ),
            WorkCutOperation::Prepare { request, grant } => WorkCutResponse::Prepared(
                store
                    .prepare_leadership_work_cut(
                        request,
                        *grant,
                        command.service.issuer,
                        command.service.backend_id,
                        now,
                    )
                    .map_err(map_work_cut_error)?,
            ),
            WorkCutOperation::Get {
                cut_id,
                request_digest,
            } => {
                let record = store
                    .get_leadership_work_cut(*cut_id)
                    .map_err(map_work_cut_error)?;
                if let Some(record) = &record {
                    validate_record(command, record, *request_digest)?;
                }
                WorkCutResponse::Record(record)
            }
            WorkCutOperation::Drain {
                cut_id,
                request_digest,
                expected_revision,
            } => {
                let record = store
                    .get_leadership_work_cut(*cut_id)
                    .map_err(map_work_cut_error)?
                    .ok_or_else(conflict)?;
                validate_record(command, &record, *request_digest)?;
                WorkCutResponse::Drain(
                    store
                        .observe_leadership_work_cut_drain(*cut_id, *expected_revision, now)
                        .map_err(map_work_cut_error)?,
                )
            }
        };
        if !self.committed_scope_matches_with_store(&command.scope, &store) {
            return Err(
                if matches!(command.operation, WorkCutOperation::Prepare { .. }) {
                    ControlError::committed()
                } else {
                    ControlError::new(ControlErrorCode::WorkspaceRootConflict)
                },
            );
        }
        Ok(response)
    }
}

fn validate_command(command: &WorkCutCommand) -> Result<(), ControlError> {
    if command.service.issuer.into_uuid().is_nil()
        || command.service.backend_id.into_uuid().is_nil()
        || command.service.destination_id.is_nil()
    {
        return Err(conflict());
    }
    match &command.operation {
        WorkCutOperation::Inventory { request } | WorkCutOperation::Prepare { request, .. } => {
            if request.workspace_id() != command.scope.workspace_id()
                || request.workspace_revision() != command.scope.workspace_revision()
                || request.backend_id() != command.service.backend_id
                || request.destination_id() != command.service.destination_id
            {
                return Err(conflict());
            }
        }
        WorkCutOperation::Get {
            cut_id,
            request_digest,
        }
        | WorkCutOperation::Drain {
            cut_id,
            request_digest,
            ..
        } => {
            if cut_id.is_nil() || request_digest.as_bytes() == &[0; 32] {
                return Err(conflict());
            }
            if matches!(command.operation, WorkCutOperation::Drain { expected_revision, .. } if expected_revision < 1)
            {
                return Err(conflict());
            }
        }
    }
    Ok(())
}

fn validate_record(
    command: &WorkCutCommand,
    record: &WorkCutRecord,
    digest: WorkCutRequestDigest,
) -> Result<(), ControlError> {
    let expected_cut = match &command.operation {
        WorkCutOperation::Get { cut_id, .. } | WorkCutOperation::Drain { cut_id, .. } => *cut_id,
        WorkCutOperation::Inventory { request } | WorkCutOperation::Prepare { request, .. } => {
            request.cut_id()
        }
    };
    if record.request().cut_id() != expected_cut
        || record.request().workspace_id() != command.scope.workspace_id()
        || record.request().workspace_revision() != command.scope.workspace_revision()
        || record.request().request_digest() != digest
        || record.issuer() != command.service.issuer
        || record.request().backend_id() != command.service.backend_id
        || record.request().destination_id() != command.service.destination_id
    {
        return Err(conflict());
    }
    Ok(())
}

fn conflict() -> ControlError {
    ControlError::new(ControlErrorCode::AgentDagReplayConflict)
}

fn map_work_cut_error(error: WorkspaceStoreError) -> ControlError {
    if matches!(
        error,
        WorkspaceStoreError::WorkCutReadbackRequired { .. }
            | WorkspaceStoreError::WorkCut(
                forge_persistence::WorkCutError::CommitUnconfirmed { .. }
            )
    ) {
        return ControlError::committed();
    }
    let code = match &error {
        WorkspaceStoreError::WorkCut(forge_persistence::WorkCutError::Bounds) => {
            ControlErrorCode::CapacityExceeded
        }
        WorkspaceStoreError::WorkCut(
            forge_persistence::WorkCutError::Domain(_)
            | forge_persistence::WorkCutError::Conflict(_),
        ) => ControlErrorCode::AgentDagReplayConflict,
        _ => ControlErrorCode::PersistenceFailure,
    };
    ControlError::with_source(code, error)
}
