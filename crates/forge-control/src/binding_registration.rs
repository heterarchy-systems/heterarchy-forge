//! Session-authorized preparation of future Orchestration effect bindings.
use forge_domain::{AgentSessionId, AuthenticatedPrincipal, TimestampMillis};
use forge_persistence::{
    AgentBindingReservation, AgentBindingReservationRequest, AgentOperationsFreeze,
    WorkspaceStoreError,
};
use uuid::Uuid;

use crate::{
    AgentSessionResolveRequest, ControlError, ControlErrorCode, ForgeControl,
    ResolvedWorkspaceScope,
};

#[derive(Debug, Clone)]
pub struct AgentBindingReserveRequest {
    pub scope: ResolvedWorkspaceScope,
    pub freeze: AgentOperationsFreeze,
    pub reservation: AgentBindingReservationRequest,
    pub observed_at: TimestampMillis,
}

#[derive(Debug, Clone)]
pub struct AgentBindingReservationReadRequest {
    pub scope: ResolvedWorkspaceScope,
    pub request_id: Uuid,
    pub session_id: AgentSessionId,
    pub principal: AuthenticatedPrincipal,
}

impl ForgeControl {
    /// Reserve identity without granting work eligibility or emitting a JOINED event.
    pub fn reserve_agent_binding(
        &self,
        request: &AgentBindingReserveRequest,
    ) -> Result<AgentBindingReservation, ControlError> {
        let _session = self.agent_session_resolve(AgentSessionResolveRequest {
            session_id: request.reservation.session_id(),
            principal: request.reservation.principal(),
        })?;
        let (scope, mut store) = self.open_resolved_workspace(
            request.scope.locator().location_id(),
            request.scope.locator().expected_revision(),
            request.scope.locator(),
        )?;
        if scope != request.scope || request.freeze.workspace_id() != scope.workspace_id() {
            return Err(ControlError::new(
                ControlErrorCode::WorkspaceRevisionConflict,
            ));
        }
        let result = store
            .reserve_agent_binding(&request.freeze, &request.reservation, request.observed_at)
            .map_err(map_reservation_error)?;
        self.confirm_agent_write(&scope, &store)?;
        Ok(result)
    }

    /// Read one reserved identity for the same authenticated session. The record is not a grant.
    pub fn agent_binding_reservation(
        &self,
        request: &AgentBindingReservationReadRequest,
    ) -> Result<Option<AgentBindingReservation>, ControlError> {
        let _session = self.agent_session_resolve(AgentSessionResolveRequest {
            session_id: request.session_id,
            principal: request.principal,
        })?;
        let (scope, store) = self.open_resolved_workspace(
            request.scope.locator().location_id(),
            request.scope.locator().expected_revision(),
            request.scope.locator(),
        )?;
        if scope != request.scope {
            return Err(ControlError::new(
                ControlErrorCode::WorkspaceRevisionConflict,
            ));
        }
        let value = store
            .agent_binding_reservation(request.request_id)
            .map_err(map_reservation_error)?;
        self.confirm_agent_read(&scope, &store)?;
        if value.as_ref().is_some_and(|v| {
            v.workspace_id() != scope.workspace_id()
                || v.request().session_id() != request.session_id
                || v.request().principal() != request.principal
        }) {
            return Ok(None);
        }
        Ok(value)
    }
}

fn map_reservation_error(error: WorkspaceStoreError) -> ControlError {
    if matches!(
        error,
        WorkspaceStoreError::AgentBindingReservationCommittedUnconfirmed { .. }
    ) {
        tracing::warn!(%error, "Agent binding reservation requires same-ID readback");
        return ControlError::committed();
    }
    if let WorkspaceStoreError::AgentBindingReservation(ref source) = error {
        use forge_persistence::AgentBindingReservationError as Error;
        let code = match source {
            Error::InvalidRequestId
            | Error::InvalidActivityId
            | Error::InvalidAgentId
            | Error::InvalidSessionId
            | Error::InvalidPrincipalId
            | Error::InvalidFreeze => ControlErrorCode::InvalidInput,
            Error::ActivityMissing(_) => ControlErrorCode::ActivityNotFound,
            Error::ActivityWorkspaceMismatch { .. } | Error::ActivityNotOpen(_) => {
                ControlErrorCode::ActivityConflict
            }
            Error::MigrationMissing(_)
            | Error::FreezeReleased(_)
            | Error::StaleFreeze(_)
            | Error::RequestConflict(_)
            | Error::AgentIdConflict(_)
            | Error::ActivitySessionConflict { .. }
            | Error::ReservationConflict(_)
            | Error::TimestampOrder => ControlErrorCode::AgentConflict,
            Error::CommitUnconfirmed { .. } => return ControlError::committed(),
            _ => ControlErrorCode::PersistenceFailure,
        };
        return ControlError::with_source(code, error);
    }
    crate::agent::map_agent_store_error(error)
}

pub(crate) fn map_reservation_error_for_rejection(error: WorkspaceStoreError) -> ControlError {
    map_reservation_error(error)
}
