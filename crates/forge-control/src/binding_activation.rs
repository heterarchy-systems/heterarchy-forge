//! Trusted native composition for delegated Agent operations.
//!
//! This boundary is deliberately below the tool adapters.  Orchestration
//! supplies a verified delegation seal and a typed activation request; Forge
//! re-resolves the selected session, checks the exact Workspace and reserved
//! binding, then lets the Workspace transaction create the effect binding.
//! Reservation, activation, presence, event, and inbox state are therefore
//! never collapsed into one caller-controlled flag.

use forge_domain::{AgentSessionId, AuthenticatedPrincipal, TimestampMillis};
use forge_persistence::{
    AgentBindingActivation, AgentBindingActivationRequest, AgentDepartureCommand,
    AgentDepartureReconciliation, AgentDepartureReconciliationRequest, AgentEffectOutboxEntry,
    AgentOperationsDelegation, AgentOperationsFreeze, AgentSessionReconciliation,
    AgentSessionReconciliationRequest, EffectFactOutboxEntry, WorkspaceStoreError,
};
use uuid::Uuid;

use crate::{
    AgentSessionResolveRequest, ControlError, ControlErrorCode, ForgeControl,
    ResolvedWorkspaceScope,
};

const MAX_AGENT_EFFECT_OUTBOX_RESULTS: usize = 64;
const MAX_EFFECT_FACT_OUTBOX_RESULTS: u32 = 64;

/// Trusted Orchestration composition input for sealing one verified source
/// freeze.  The manifest digest is the typed verification result; there is no
/// caller-supplied `verified`/`committed` boolean.
#[derive(Debug, Clone)]
pub struct AgentOperationsDelegationRequest {
    pub scope: ResolvedWorkspaceScope,
    pub freeze: AgentOperationsFreeze,
    pub manifest_digest: [u8; 32],
    pub observed_at: TimestampMillis,
}

/// Read one immutable source delegation seal for the selected Workspace.
#[derive(Debug, Clone)]
pub struct AgentOperationsDelegationReadRequest {
    pub scope: ResolvedWorkspaceScope,
}

/// Trusted native activation of one reservation already committed by
/// Orchestration.  The session and principal are still supplied as the
/// authenticated caller identity and are checked against the durable
/// reservation before the effect row can be created.
#[derive(Debug, Clone)]
pub struct AgentBindingActivateRequest {
    pub scope: ResolvedWorkspaceScope,
    pub delegation: AgentOperationsDelegation,
    pub activation: AgentBindingActivationRequest,
    pub session_id: AgentSessionId,
    pub principal: AuthenticatedPrincipal,
    pub observed_at: TimestampMillis,
}

/// Read one activation receipt for the same authenticated session.  A receipt
/// belonging to another principal or session is intentionally returned as
/// `None` to avoid turning this read into an identity oracle.
#[derive(Debug, Clone)]
pub struct AgentBindingActivationReadRequest {
    pub scope: ResolvedWorkspaceScope,
    pub request_id: Uuid,
    pub session_id: AgentSessionId,
    pub principal: AuthenticatedPrincipal,
}

/// Trusted reconciliation of one imported unresolved legacy Agent into an
/// authenticated Forge effect-session binding. The durable Workspace delegation
/// is resolved by Forge rather than supplied as caller-owned trust.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentSessionReconcileRequest {
    pub scope: ResolvedWorkspaceScope,
    pub reconciliation: AgentSessionReconciliationRequest,
}

/// Same-session readback for an immutable reconciliation receipt.
#[derive(Debug, Clone)]
pub struct AgentSessionReconcileReadRequest {
    pub scope: ResolvedWorkspaceScope,
    pub request_id: Uuid,
    pub session_id: AgentSessionId,
    pub principal: AuthenticatedPrincipal,
}

/// Trusted reconciliation of one Agent departure (a plain detach or the
/// atomic Coordinator handoff) after operations were delegated to
/// Orchestration. The departure journal, delegation, and durable effect
/// binding are resolved by Forge; the participation plane is never written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentDepartureReconcileRequest {
    pub scope: ResolvedWorkspaceScope,
    pub reconciliation: AgentDepartureReconciliationRequest,
}

/// Same-session readback for an immutable departure reconciliation receipt.
/// A receipt belonging to another session is intentionally returned as `None`.
#[derive(Debug, Clone)]
pub struct AgentDepartureReconcileReadRequest {
    pub scope: ResolvedWorkspaceScope,
    pub request_id: Uuid,
    pub session_id: AgentSessionId,
    pub principal: AuthenticatedPrincipal,
}

/// Read a bounded page of immutable Forge work facts after delegation.
#[derive(Debug, Clone)]
pub struct AgentEffectOutboxReadRequest {
    pub scope: ResolvedWorkspaceScope,
    pub destination_id: Uuid,
    pub after: i64,
    pub limit: usize,
}

/// Read a bounded page of immutable Forge-owned effect facts after delegation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectFactOutboxReadRequest {
    pub scope: ResolvedWorkspaceScope,
    pub migration_id: Uuid,
    pub destination_id: Uuid,
    pub after: u64,
    pub limit: u32,
}

impl ForgeControl {
    /// Seal a verified destination manifest against the exact current source
    /// freeze.  This is a native composition operation, not a public
    /// authorization claim.
    pub fn delegate_agent_operations(
        &self,
        request: &AgentOperationsDelegationRequest,
    ) -> Result<AgentOperationsDelegation, ControlError> {
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
            .delegate_agent_operations(
                &request.freeze,
                request.manifest_digest,
                request.observed_at,
            )
            .map_err(map_delegation_error)?;
        self.confirm_agent_write(&scope, &store)?;
        Ok(result)
    }

    /// Read the immutable source delegation seal for the selected Workspace.
    pub fn agent_operations_delegation(
        &self,
        request: &AgentOperationsDelegationReadRequest,
    ) -> Result<Option<AgentOperationsDelegation>, ControlError> {
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
        let result = store
            .agent_operations_delegation()
            .map_err(map_delegation_error)?;
        self.confirm_agent_read(&scope, &store)?;
        Ok(result)
    }

    /// Activate one reserved binding only after fresh session admission,
    /// exact reservation ownership, and current delegation readback.
    pub fn activate_agent_binding(
        &self,
        request: &AgentBindingActivateRequest,
    ) -> Result<AgentBindingActivation, ControlError> {
        let _session = self.agent_session_resolve(AgentSessionResolveRequest {
            session_id: request.session_id,
            principal: request.principal,
        })?;

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
        if request.delegation.workspace_id() != scope.workspace_id() {
            return Err(ControlError::new(ControlErrorCode::AgentConflict));
        }

        let current = store
            .agent_operations_delegation()
            .map_err(map_delegation_error)?
            .ok_or_else(|| ControlError::new(ControlErrorCode::AgentConflict))?;
        if current != request.delegation {
            return Err(ControlError::new(ControlErrorCode::AgentConflict));
        }

        let reservation = store
            .agent_binding_reservation(request.activation.request_id())
            .map_err(map_reservation_error)?
            .ok_or_else(|| ControlError::new(ControlErrorCode::AgentConflict))?;
        if reservation.workspace_id() != scope.workspace_id() {
            return Err(ControlError::new(ControlErrorCode::AgentConflict));
        }
        if reservation.request().session_id() != request.session_id
            || reservation.request().principal() != request.principal
        {
            return Err(ControlError::new(ControlErrorCode::AgentSessionConflict));
        }

        let result = store
            .activate_agent_binding(
                &request.delegation,
                &request.activation,
                request.observed_at,
            )
            .map_err(map_activation_error)?;
        self.confirm_agent_write(&scope, &store)?;
        Ok(result)
    }

    /// Read one activation receipt for the authenticated session.  A durable
    /// receipt for a different session or principal is hidden as `None`.
    pub fn agent_binding_activation(
        &self,
        request: &AgentBindingActivationReadRequest,
    ) -> Result<Option<AgentBindingActivation>, ControlError> {
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
            .agent_binding_activation(request.request_id)
            .map_err(map_activation_error)?;
        self.confirm_agent_read(&scope, &store)?;
        if value.as_ref().is_some_and(|activation| {
            activation.workspace_id() != scope.workspace_id()
                || activation.reservation().request().session_id() != request.session_id
                || activation.reservation().request().principal() != request.principal
        }) {
            return Ok(None);
        }
        Ok(value)
    }

    /// Reconcile only the Forge-owned effect-session identity for one imported
    /// unresolved Agent. Operational membership, presence, events, and inbox
    /// remain Orchestration-owned and are never written by this method.
    pub fn reconcile_agent_session(
        &self,
        request: &AgentSessionReconcileRequest,
    ) -> Result<AgentSessionReconciliation, ControlError> {
        let command = request.reconciliation.command();
        let _session = self.agent_session_resolve(AgentSessionResolveRequest {
            session_id: command.session_id(),
            principal: command.principal(),
        })?;
        let (scope, mut store) = self.open_resolved_workspace(
            request.scope.locator().location_id(),
            request.scope.locator().expected_revision(),
            request.scope.locator(),
        )?;
        if scope != request.scope || command.workspace_id() != scope.workspace_id() {
            return Err(ControlError::new(ControlErrorCode::AgentConflict));
        }
        let delegation = store
            .agent_operations_delegation()
            .map_err(map_delegation_error)?
            .ok_or_else(|| ControlError::new(ControlErrorCode::AgentConflict))?;
        let result = store
            .reconcile_agent_session(&delegation, request.reconciliation)
            .map_err(map_reconciliation_error)?;
        self.confirm_agent_write(&scope, &store)?;
        Ok(result)
    }

    /// Read one reconciliation receipt only for the authenticated session that
    /// owns the resulting effect binding.
    pub fn agent_session_reconciliation(
        &self,
        request: &AgentSessionReconcileReadRequest,
    ) -> Result<Option<AgentSessionReconciliation>, ControlError> {
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
            .agent_session_reconciliation(request.request_id)
            .map_err(map_reconciliation_error)?;
        self.confirm_agent_read(&scope, &store)?;
        if value
            .as_ref()
            .is_some_and(|receipt| receipt.session_id() != request.session_id)
        {
            return Ok(None);
        }
        Ok(value)
    }

    /// Reconcile one Agent departure (plain detach or Coordinator handoff)
    /// after operations were delegated to Orchestration. The authenticated
    /// session is resolved first, the exact Workspace is revalidated, the
    /// durable source delegation is read for the migration identity, and only
    /// then does the Workspace transaction write the effect/planning-plane
    /// facts and the immutable journal receipt. Left/`HandoffStarted`/
    /// `HandoffCompleted` membership events, presence, inbox receipts, and
    /// membership transition facts are never written by this method.
    pub(crate) fn reconcile_agent_departure(
        &self,
        request: &AgentDepartureReconcileRequest,
        admitted_at: forge_domain::TimestampMillis,
    ) -> Result<AgentDepartureReconciliation, ControlError> {
        let reconciliation = &request.reconciliation;
        let _session = self.agent_session_resolve(AgentSessionResolveRequest {
            session_id: reconciliation.session_id(),
            principal: reconciliation.principal(),
        })?;
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
        match reconciliation.command() {
            AgentDepartureCommand::Detach(detach) => {
                let agent = store
                    .get_agent(detach.agent_id())
                    .map_err(crate::service::map_store_error)?
                    .ok_or_else(|| ControlError::new(ControlErrorCode::AgentNotFound))?;
                if agent.workspace_id() != scope.workspace_id()
                    || agent.activity_id() != detach.activity_id()
                {
                    return Err(ControlError::new(ControlErrorCode::AgentConflict));
                }
            }
            AgentDepartureCommand::Handoff(handoff) => {
                if handoff.actor().workspace_id() != scope.workspace_id() {
                    return Err(ControlError::new(ControlErrorCode::AgentConflict));
                }
                let _target_session = self.agent_session_resolve(AgentSessionResolveRequest {
                    session_id: handoff.target_session_id(),
                    principal: handoff.target_principal(),
                })?;
            }
        }
        let delegation = store
            .agent_operations_delegation()
            .map_err(map_delegation_error)?
            .ok_or_else(|| ControlError::new(ControlErrorCode::AgentConflict))?;
        let result = store
            .reconcile_agent_departure(&delegation, reconciliation, admitted_at)
            .map_err(map_departure_error)?;
        self.confirm_agent_write(&scope, &store)?;
        Ok(result)
    }

    /// Read one departure reconciliation receipt only for the authenticated
    /// session that performed the departure.
    pub fn agent_departure_reconciliation(
        &self,
        request: &AgentDepartureReconcileReadRequest,
    ) -> Result<Option<AgentDepartureReconciliation>, ControlError> {
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
            .agent_departure_reconciliation(request.request_id)
            .map_err(map_departure_error)?;
        self.confirm_agent_read(&scope, &store)?;
        if value
            .as_ref()
            .is_some_and(|receipt| receipt.session_id() != request.session_id)
        {
            return Ok(None);
        }
        Ok(value)
    }

    /// Read one bounded immutable source work-fact page.  Work facts are
    /// available only after the source delegation seal exists and never grant
    /// effect authority by themselves.
    pub fn agent_effect_outbox(
        &self,
        request: &AgentEffectOutboxReadRequest,
    ) -> Result<Vec<AgentEffectOutboxEntry>, ControlError> {
        if request.after < 0 {
            return Err(ControlError::new(ControlErrorCode::InvalidInput));
        }
        if request.limit > MAX_AGENT_EFFECT_OUTBOX_RESULTS {
            return Err(ControlError::new(ControlErrorCode::CapacityExceeded));
        }
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
        let delegation = store
            .agent_operations_delegation()
            .map_err(map_delegation_error)?
            .ok_or_else(|| ControlError::new(ControlErrorCode::AgentConflict))?;
        if delegation.destination_id() != request.destination_id {
            return Err(ControlError::new(ControlErrorCode::AgentConflict));
        }
        store
            .agent_effect_outbox(request.after, request.limit)
            .map_err(map_outbox_error)
    }

    /// Read one bounded page of Forge-owned effect facts for the exact delegated
    /// destination. Reading is observational and never advances a source cursor.
    pub fn effect_fact_outbox(
        &self,
        request: &EffectFactOutboxReadRequest,
    ) -> Result<Vec<EffectFactOutboxEntry>, ControlError> {
        if request.limit == 0 {
            return Err(ControlError::new(ControlErrorCode::InvalidInput));
        }
        if request.limit > MAX_EFFECT_FACT_OUTBOX_RESULTS {
            return Err(ControlError::new(ControlErrorCode::CapacityExceeded));
        }
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
        let delegation = store
            .agent_operations_delegation()
            .map_err(map_delegation_error)?
            .ok_or_else(|| ControlError::new(ControlErrorCode::AgentConflict))?;
        if delegation.migration_id() != request.migration_id
            || delegation.destination_id() != request.destination_id
        {
            return Err(ControlError::new(ControlErrorCode::AgentConflict));
        }
        store
            .effect_fact_outbox(request.after, request.limit)
            .map_err(map_effect_fact_outbox_error)
    }
}

fn map_delegation_error(error: WorkspaceStoreError) -> ControlError {
    if matches!(
        error,
        WorkspaceStoreError::AgentOperationsDelegationCommittedUnconfirmed { .. }
    ) {
        tracing::warn!(%error, "Agent operations delegation requires same-ID readback");
        return ControlError::committed();
    }
    if let WorkspaceStoreError::AgentOperationsDelegation(ref source) = error {
        use forge_persistence::AgentOperationsDelegationError as Error;
        let code = match source {
            Error::InvalidWorkspaceId
            | Error::InvalidMigrationId
            | Error::InvalidDestinationId
            | Error::ZeroManifestDigest => ControlErrorCode::InvalidInput,
            Error::MigrationMissing(_)
            | Error::FreezeReleased(_)
            | Error::StaleFreeze(_)
            | Error::WorkspaceMismatch { .. }
            | Error::DelegationConflict { .. }
            | Error::TimestampOrder => ControlErrorCode::AgentConflict,
            Error::CommitUnconfirmed { .. } => return ControlError::committed(),
            _ => ControlErrorCode::PersistenceFailure,
        };
        return ControlError::with_source(code, error);
    }
    crate::service::map_store_error(error)
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
    crate::service::map_store_error(error)
}

fn map_activation_error(error: WorkspaceStoreError) -> ControlError {
    if matches!(
        error,
        WorkspaceStoreError::AgentBindingActivationCommittedUnconfirmed { .. }
    ) {
        tracing::warn!(%error, "Agent binding activation requires same-ID readback");
        return ControlError::committed();
    }
    if let WorkspaceStoreError::AgentBindingActivation(ref source) = error {
        use forge_persistence::AgentBindingActivationError as Error;
        let code = match source {
            Error::InvalidRequestId
            | Error::ZeroMembershipDigest
            | Error::InvalidMetadata { .. }
            | Error::InvalidTransport(_)
            | Error::InvalidUuidLength { .. }
            | Error::InvalidDigestLength { .. } => ControlErrorCode::InvalidInput,
            Error::ActivityMissing(_) => ControlErrorCode::ActivityNotFound,
            Error::ActivityWorkspaceMismatch { .. } | Error::ActivityNotOpen(_) => {
                ControlErrorCode::ActivityConflict
            }
            Error::AgentMissing(_) => ControlErrorCode::AgentNotFound,
            Error::DelegationMissing(_)
            | Error::StaleDelegation(_)
            | Error::ReservationMissing(_)
            | Error::ReservationSourceConflict(_)
            | Error::RequestConflict(_)
            | Error::AgentIdConflict(_)
            | Error::ActivitySessionConflict { .. }
            | Error::AgentDetached(_)
            | Error::AgentMetadataConflict(_)
            | Error::PrincipalTransportMismatch
            | Error::TimestampOrder
            | Error::Delegation(_)
            | Error::Reservation(_) => ControlErrorCode::AgentConflict,
            Error::CommitUnconfirmed { .. } => return ControlError::committed(),
            _ => ControlErrorCode::PersistenceFailure,
        };
        return ControlError::with_source(code, error);
    }
    crate::service::map_store_error(error)
}

fn map_reconciliation_error(error: WorkspaceStoreError) -> ControlError {
    if matches!(
        error,
        WorkspaceStoreError::AgentSessionReconciliationReadbackRequired { .. }
    ) {
        tracing::warn!(%error, "Agent session reconciliation requires same-ID readback");
        return ControlError::committed();
    }
    if let WorkspaceStoreError::AgentSessionReconciliation(ref source) = error {
        use forge_persistence::AgentSessionReconciliationError as Error;
        let code = match source {
            Error::InvalidRequestId => ControlErrorCode::InvalidInput,
            Error::Agent(forge_persistence::AgentStoreError::AgentNotFound(_)) => {
                ControlErrorCode::AgentNotFound
            }
            Error::Agent(forge_persistence::AgentStoreError::ActivityNotFound(_)) => {
                ControlErrorCode::ActivityNotFound
            }
            Error::DelegationMissing(_)
            | Error::StaleDelegation(_)
            | Error::WorkspaceMismatch
            | Error::TimestampOrder
            | Error::RequestConflict
            | Error::Delegation(_)
            | Error::Agent(_) => ControlErrorCode::AgentConflict,
            Error::CommitUnconfirmed { .. } => return ControlError::committed(),
            _ => ControlErrorCode::PersistenceFailure,
        };
        return ControlError::with_source(code, error);
    }
    crate::service::map_store_error(error)
}

fn map_departure_error(error: WorkspaceStoreError) -> ControlError {
    if matches!(
        error,
        WorkspaceStoreError::AgentDepartureReconciliationReadbackRequired { .. }
    ) {
        tracing::warn!(%error, "Agent departure reconciliation requires same-ID readback");
        return ControlError::committed();
    }
    if let WorkspaceStoreError::AgentDepartureReconciliation(ref source) = error {
        use forge_persistence::AgentDepartureReconciliationError as Error;
        let code = match source {
            Error::InvalidRequestId | Error::ZeroIdentityDigest => ControlErrorCode::InvalidInput,
            Error::Agent(forge_persistence::AgentStoreError::AgentNotFound(_))
            | Error::Coordinator(forge_persistence::CoordinatorStoreError::AgentNotFound(_)) => {
                ControlErrorCode::AgentNotFound
            }
            Error::Agent(forge_persistence::AgentStoreError::ActivityNotFound(_))
            | Error::Coordinator(forge_persistence::CoordinatorStoreError::ActivityNotFound(_)) => {
                ControlErrorCode::ActivityNotFound
            }
            Error::Coordinator(forge_persistence::CoordinatorStoreError::CoordinatorMissing(_)) => {
                ControlErrorCode::CoordinatorNotFound
            }
            Error::DelegationMissing(_)
            | Error::StaleDelegation(_)
            | Error::WorkspaceMismatch
            | Error::TimestampOrder
            | Error::RequestConflict
            | Error::CallerMismatch
            | Error::KindMismatch
            | Error::Delegation(_)
            | Error::Agent(_)
            | Error::Coordinator(_) => ControlErrorCode::AgentConflict,
            Error::CommitUnconfirmed { .. } => return ControlError::committed(),
            _ => ControlErrorCode::PersistenceFailure,
        };
        return ControlError::with_source(code, error);
    }
    crate::service::map_store_error(error)
}

fn map_effect_fact_outbox_error(error: WorkspaceStoreError) -> ControlError {
    if let WorkspaceStoreError::EffectFactOutbox(ref source) = error {
        use forge_persistence::EffectFactOutboxError as Error;
        let code = match source {
            Error::InvalidCursor | Error::InvalidLimit { .. } => ControlErrorCode::InvalidInput,
            Error::Delegation(_) => ControlErrorCode::AgentConflict,
            _ => ControlErrorCode::PersistenceFailure,
        };
        return ControlError::with_source(code, error);
    }
    crate::service::map_store_error(error)
}

fn map_outbox_error(error: WorkspaceStoreError) -> ControlError {
    if let WorkspaceStoreError::AgentEffectOutbox(ref source) = error {
        use forge_persistence::AgentEffectOutboxError as Error;
        let code = match source {
            Error::InvalidCursor | Error::InvalidWorkspace => ControlErrorCode::InvalidInput,
            Error::TooManyRecipientHints { .. } => ControlErrorCode::CapacityExceeded,
            Error::Delegation(_) => ControlErrorCode::AgentConflict,
            _ => ControlErrorCode::PersistenceFailure,
        };
        return ControlError::with_source(code, error);
    }
    crate::service::map_store_error(error)
}
