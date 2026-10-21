//! Native local-owner recovery. No external HTTP DTO exposes these requests.

use crate::{
    AgentSessionResolveRequest, ControlError, ControlErrorCode, ForgeControl,
    ResolvedWorkspaceScope,
};
use forge_domain::{
    ActivityId, AgentInstanceId, ConfirmedCoordinatorRecovery, CoordinatorRecoveryFence,
    CoordinatorRecoveryReceipt,
};
use forge_persistence::{
    CoordinatorRecoveryStoreError, CoordinatorStoreError, WorkspaceStore, WorkspaceStoreError,
};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoordinatorRecoveryPrepareRequest {
    pub scope: ResolvedWorkspaceScope,
    pub activity_id: ActivityId,
    pub target_agent_id: AgentInstanceId,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoordinatorRecoveryConfirmRequest {
    pub scope: ResolvedWorkspaceScope,
    pub confirmation: ConfirmedCoordinatorRecovery,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoordinatorRecoveryReadRequest {
    pub scope: ResolvedWorkspaceScope,
    pub activity_id: ActivityId,
    pub recovery_id: Uuid,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoordinatorRecoveryHistoryRequest {
    pub scope: ResolvedWorkspaceScope,
    pub activity_id: ActivityId,
    pub limit: u32,
}

impl ForgeControl {
    /// Native GUI preview. A role string or an OAuth caller cannot confer this authority.
    pub fn prepare_coordinator_recovery(
        &self,
        request: &CoordinatorRecoveryPrepareRequest,
    ) -> Result<CoordinatorRecoveryFence, ControlError> {
        let (scope, store) = self.open_owner_recovery_workspace(&request.scope)?;
        let fence = store
            .coordinator_recovery_preview(request.activity_id, request.target_agent_id)
            .map_err(map_recovery_error)?;
        let _target_session = self.agent_session_resolve(AgentSessionResolveRequest {
            session_id: fence.target().session_id(),
            principal: fence.target().principal(),
        })?;
        self.confirm_owner_recovery_read(&scope, &store)?;
        Ok(fence)
    }

    /// Confirm the exact state reviewed by the native owner. No impersonation of
    /// the source OAuth principal, implicit claim, or fresh-fence retry occurs.
    pub fn confirm_coordinator_recovery(
        &self,
        request: &CoordinatorRecoveryConfirmRequest,
    ) -> Result<CoordinatorRecoveryReceipt, ControlError> {
        let (scope, mut store) = self.open_owner_recovery_workspace(&request.scope)?;
        if scope.workspace_id() != request.confirmation.fence().binding().workspace_id() {
            return Err(ControlError::new(
                ControlErrorCode::WorkspaceIdentityConflict,
            ));
        }
        if let Some(receipt) = store
            .coordinator_recovery_receipt(request.confirmation.id())
            .map_err(map_recovery_error)?
        {
            if receipt.request() != &request.confirmation {
                return Err(ControlError::new(ControlErrorCode::CoordinatorConflict));
            }
            self.confirm_owner_recovery_read(&scope, &store)?;
            return Ok(receipt);
        }
        let target = request.confirmation.fence().target();
        let _target_session = self.agent_session_resolve(AgentSessionResolveRequest {
            session_id: target.session_id(),
            principal: target.principal(),
        })?;
        let receipt = store
            .confirm_local_coordinator_recovery(&request.confirmation)
            .map_err(map_recovery_error)?;
        if !self.committed_scope_matches_with_store(&scope, &store) {
            return Err(ControlError::committed());
        }
        Ok(receipt)
    }

    pub fn coordinator_recovery_receipt(
        &self,
        request: &CoordinatorRecoveryReadRequest,
    ) -> Result<Option<CoordinatorRecoveryReceipt>, ControlError> {
        let (scope, store) = self.open_owner_recovery_workspace(&request.scope)?;
        let receipt = store
            .coordinator_recovery_receipt(request.recovery_id)
            .map_err(map_recovery_error)?;
        if receipt.as_ref().is_some_and(|receipt| {
            receipt.request().fence().binding().activity_id() != request.activity_id
        }) {
            return Err(ControlError::new(ControlErrorCode::CoordinatorConflict));
        }
        self.confirm_owner_recovery_read(&scope, &store)?;
        Ok(receipt)
    }

    pub fn coordinator_recovery_history(
        &self,
        request: &CoordinatorRecoveryHistoryRequest,
    ) -> Result<Vec<CoordinatorRecoveryReceipt>, ControlError> {
        let (scope, store) = self.open_owner_recovery_workspace(&request.scope)?;
        let receipts = store
            .coordinator_recovery_history(request.activity_id, request.limit)
            .map_err(map_recovery_error)?;
        self.confirm_owner_recovery_read(&scope, &store)?;
        Ok(receipts)
    }

    fn open_owner_recovery_workspace(
        &self,
        requested: &ResolvedWorkspaceScope,
    ) -> Result<(ResolvedWorkspaceScope, WorkspaceStore), ControlError> {
        let (scope, store) = self.open_resolved_workspace(
            requested.locator().location_id(),
            requested.locator().expected_revision(),
            requested.locator(),
        )?;
        if &scope != requested {
            return Err(ControlError::new(
                ControlErrorCode::WorkspaceRevisionConflict,
            ));
        }
        Ok((scope, store))
    }

    fn confirm_owner_recovery_read(
        &self,
        scope: &ResolvedWorkspaceScope,
        store: &WorkspaceStore,
    ) -> Result<(), ControlError> {
        if self.committed_scope_matches_with_store(scope, store) {
            Ok(())
        } else {
            Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict))
        }
    }
}

fn map_recovery_error(error: WorkspaceStoreError) -> ControlError {
    let code = match &error {
        WorkspaceStoreError::CoordinatorRecoveryReadbackRequired { .. } => {
            ControlErrorCode::CommittedButUnconfirmed
        }
        WorkspaceStoreError::CoordinatorRecovery(CoordinatorRecoveryStoreError::Coordinator(
            CoordinatorStoreError::ActiveWriterLease(_),
        )) => ControlErrorCode::WriterLeaseConflict,
        WorkspaceStoreError::CoordinatorRecovery(CoordinatorRecoveryStoreError::Coordinator(
            CoordinatorStoreError::ActiveExecution(_),
        )) => ControlErrorCode::ExecutionConflict,
        WorkspaceStoreError::CoordinatorRecovery(CoordinatorRecoveryStoreError::Coordinator(
            CoordinatorStoreError::CoordinatorMissing(_),
        )) => ControlErrorCode::CoordinatorNotFound,
        WorkspaceStoreError::CoordinatorRecovery(
            CoordinatorRecoveryStoreError::Domain(_)
            | CoordinatorRecoveryStoreError::FenceConflict
            | CoordinatorRecoveryStoreError::ReplayConflict,
        ) => ControlErrorCode::CoordinatorConflict,
        _ => return crate::service::map_store_error(error),
    };
    ControlError::with_source(code, error)
}
