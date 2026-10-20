//! Session-authenticated terminal settlement for an invalid Agent binding.
//!
//! The public control input is the exact Orchestration attestation. Source
//! derives its reservation timestamp, root fingerprint, binding digest, and
//! delegation digest from its own durable state before sealing the receipt.

use forge_domain::{
    AgentBindingRejectionReason, AgentBindingRejectionReceipt, AgentBindingRejectionRequest,
    AgentSessionId, AuthenticatedPrincipal, TimestampMillis,
};
use forge_persistence::{
    AgentBindingActivationRequest, AgentBindingRejectionOperation,
    AgentBindingRejectionStoreRequest, AgentBindingReservationRequest, WorkspaceStoreError,
};
use uuid::Uuid;

use crate::{
    AgentSessionResolveRequest, ControlError, ControlErrorCode, ForgeControl,
    ResolvedWorkspaceScope,
};

/// Stable Orchestration-owned attestation. Source-owned receipt fences are
/// intentionally absent and are filled from the Workspace transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentBindingRejectRequest {
    pub scope: ResolvedWorkspaceScope,
    pub issuer_id: Uuid,
    pub migration_id: Uuid,
    pub destination_id: Uuid,
    pub expected_freeze_revision: u64,
    pub manifest_digest: [u8; 32],
    pub reservation: AgentBindingReservationRequest,
    pub activation: AgentBindingActivationRequest,
    pub reason: AgentBindingRejectionReason,
    pub observed_at: TimestampMillis,
}

impl AgentBindingRejectRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: ResolvedWorkspaceScope,
        issuer_id: Uuid,
        migration_id: Uuid,
        destination_id: Uuid,
        expected_freeze_revision: u64,
        manifest_digest: [u8; 32],
        reservation: AgentBindingReservationRequest,
        activation: AgentBindingActivationRequest,
        reason: AgentBindingRejectionReason,
        observed_at: TimestampMillis,
    ) -> Self {
        Self {
            scope,
            issuer_id,
            migration_id,
            destination_id,
            expected_freeze_revision,
            manifest_digest,
            reservation,
            activation,
            reason,
            observed_at,
        }
    }

    /// Return the canonical stable caller-intent digest used by `rejection_get`
    /// readback. It does not include any Source-derived fence.
    pub fn request_digest(&self) -> Result<[u8; 32], ControlError> {
        Ok(
            forge_persistence::agent_binding_rejection_intent_digest_for_attestation(
                self.scope.workspace_id(),
                self.issuer_id,
                self.migration_id,
                self.destination_id,
                self.expected_freeze_revision,
                self.manifest_digest,
                &self.reservation,
                &self.activation,
                self.reason,
                self.observed_at,
            ),
        )
    }
}

/// Historical owner selector plus the canonical stable caller-intent digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentBindingRejectionReadRequest {
    pub scope: ResolvedWorkspaceScope,
    pub request_id: Uuid,
    pub request_digest: [u8; 32],
    pub session_id: AgentSessionId,
    pub principal: AuthenticatedPrincipal,
}

impl ForgeControl {
    /// Record or exactly replay one terminal rejection for the source-owned
    /// reservation. The open-Session check is skipped only after a complete
    /// immutable receipt has been found and validated.
    #[allow(clippy::too_many_lines)]
    pub fn reject_agent_binding(
        &self,
        request: &AgentBindingRejectRequest,
    ) -> Result<AgentBindingRejectionOperation, ControlError> {
        if request.reservation.request_id() != request.activation.request_id()
            || request.destination_id.is_nil()
            || request.migration_id.is_nil()
            || request.issuer_id.is_nil()
            || request.expected_freeze_revision == 0
            || request.manifest_digest == [0; 32]
        {
            return Err(ControlError::new(ControlErrorCode::InvalidInput));
        }
        let identity = AgentSessionResolveRequest {
            session_id: request.reservation.session_id(),
            principal: request.reservation.principal(),
        };
        let _ = self.agent_session_authenticate_historical(identity)?;
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
        if let Some(existing) = store
            .agent_binding_rejection(request.reservation.request_id())
            .map_err(map_rejection_error)?
        {
            let expected_digest =
                forge_persistence::agent_binding_rejection_intent_digest(existing.request());
            if existing.request_digest() != expected_digest
                || !intent_matches_receipt(&existing, request)
            {
                return Err(ControlError::new(ControlErrorCode::AgentConflict));
            }
            self.confirm_agent_read(&scope, &store)?;
            return Ok(AgentBindingRejectionOperation::Replay(existing));
        }

        let _ = self.agent_session_resolve(identity)?;
        let reservation = store
            .agent_binding_reservation(request.reservation.request_id())
            .map_err(crate::binding_registration::map_reservation_error_for_rejection)?
            .ok_or_else(|| ControlError::new(ControlErrorCode::AgentConflict))?;
        if reservation.workspace_id() != scope.workspace_id()
            || reservation.request() != &request.reservation
            || reservation.migration_id() != request.migration_id
            || reservation.destination_id() != request.destination_id
            || reservation.freeze_revision() != request.expected_freeze_revision
        {
            return Err(ControlError::new(ControlErrorCode::AgentConflict));
        }
        if request.activation.request_id() != reservation.request().request_id()
            || request.activation.membership_digest() == [0; 32]
        {
            return Err(ControlError::new(ControlErrorCode::AgentConflict));
        }
        let delegation = store
            .agent_operations_delegation()
            .map_err(map_delegation_error)?
            .ok_or_else(|| ControlError::new(ControlErrorCode::AgentConflict))?;
        if delegation.workspace_id() != scope.workspace_id()
            || delegation.migration_id() != request.migration_id
            || delegation.destination_id() != request.destination_id
            || delegation.freeze().revision() != request.expected_freeze_revision
            || delegation.manifest_digest() != request.manifest_digest
        {
            return Err(ControlError::new(ControlErrorCode::AgentConflict));
        }
        let workspace = store.workspace().map_err(crate::service::map_store_error)?;
        let binding = store
            .journal_binding()
            .map_err(crate::service::map_store_error)?;
        let delegation_digest =
            forge_persistence::agent_binding_rejection_delegation_digest(&delegation);
        let native_request = AgentBindingRejectionRequest::new(
            request.reservation.request_id(),
            scope.workspace_id(),
            reservation.request().activity_id(),
            reservation.request().agent_id(),
            reservation.request().session_id(),
            reservation.request().principal(),
            request.migration_id,
            request.destination_id,
            request.expected_freeze_revision,
            request.manifest_digest,
            request.issuer_id,
            workspace.root_fingerprint(),
            binding.recovery_history_digest(),
            delegation_digest,
            request.activation.membership_digest(),
            request.activation.display_name().clone(),
            request.activation.declared_role().clone(),
            request.activation.transport(),
            request.reason,
            reservation.reserved_at(),
            reservation.request().requested_at(),
            request.observed_at,
        )
        .map_err(|_| ControlError::new(ControlErrorCode::InvalidInput))?;
        let native = AgentBindingRejectionStoreRequest {
            binding_digest: native_request.binding_digest(),
            observed_root_fingerprint: workspace.root_fingerprint(),
            current_delegation: delegation,
            request: native_request,
        };
        let result = store
            .reject_agent_binding(&binding, &native)
            .map_err(map_rejection_error)?;
        self.confirm_agent_write(&scope, &store)?;
        Ok(result)
    }

    /// Read one immutable rejection under historical Session ownership. The
    /// current delegation, boot identity, and Session-open state are not
    /// consulted after the identity provider authenticates the selector.
    pub fn agent_binding_rejection(
        &self,
        request: &AgentBindingRejectionReadRequest,
    ) -> Result<Option<AgentBindingRejectionReceipt>, ControlError> {
        if request.request_id.is_nil() || request.request_digest == [0; 32] {
            return Err(ControlError::new(ControlErrorCode::InvalidInput));
        }
        let _ = self.agent_session_authenticate_historical(AgentSessionResolveRequest {
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
            .agent_binding_rejection(request.request_id)
            .map_err(map_rejection_error)?;
        self.confirm_agent_read(&scope, &store)?;
        if value.as_ref().is_some_and(|receipt| {
            receipt.request_digest() != request.request_digest
                || receipt.workspace_id() != scope.workspace_id()
                || receipt.session_id() != request.session_id
                || receipt.principal() != request.principal
        }) {
            return Ok(None);
        }
        Ok(value)
    }
}

fn intent_matches_receipt(
    receipt: &AgentBindingRejectionReceipt,
    request: &AgentBindingRejectRequest,
) -> bool {
    let stored = receipt.request();
    stored.request_id() == request.reservation.request_id()
        && stored.activity_id() == request.reservation.activity_id()
        && stored.agent_id() == request.reservation.agent_id()
        && stored.session_id() == request.reservation.session_id()
        && stored.principal() == request.reservation.principal()
        && stored.migration_id() == request.migration_id
        && stored.destination_id() == request.destination_id
        && stored.expected_freeze_revision() == request.expected_freeze_revision
        && stored.manifest_digest() == request.manifest_digest
        && stored.issuer_id() == request.issuer_id
        && stored.membership_digest() == request.activation.membership_digest()
        && stored.display_name() == request.activation.display_name()
        && stored.declared_role() == request.activation.declared_role()
        && stored.transport() == request.activation.transport()
        && stored.reason() == request.reason
        && stored.requested_at() == request.reservation.requested_at()
        && stored.observed_at() == request.observed_at
}

fn map_rejection_error(error: WorkspaceStoreError) -> ControlError {
    if matches!(
        error,
        WorkspaceStoreError::AgentBindingRejectionCommittedUnconfirmed { .. }
    ) {
        tracing::warn!(%error, "Agent binding rejection requires same-ID readback");
        return ControlError::committed();
    }
    if let WorkspaceStoreError::AgentBindingRejection(ref source) = error {
        use forge_persistence::AgentBindingRejectionStoreError as Error;
        let code = match source {
            Error::Domain(_)
            | Error::Conflict(_)
            | Error::Reservation(_)
            | Error::Delegation(_)
            | Error::Activation(_)
            | Error::Agent(_) => ControlErrorCode::AgentConflict,
            Error::CommitUnconfirmed(_) => return ControlError::committed(),
            Error::DamagedSchema(_) | Error::Corrupt(_) | Error::Clock | Error::Sqlite(_) => {
                ControlErrorCode::PersistenceFailure
            }
        };
        return ControlError::with_source(code, error);
    }
    crate::service::map_store_error(error)
}

fn map_delegation_error(error: WorkspaceStoreError) -> ControlError {
    if matches!(
        error,
        WorkspaceStoreError::AgentOperationsDelegationCommittedUnconfirmed { .. }
    ) {
        return ControlError::committed();
    }
    if matches!(error, WorkspaceStoreError::AgentOperationsDelegation(_)) {
        return ControlError::with_source(ControlErrorCode::AgentConflict, error);
    }
    crate::service::map_store_error(error)
}
