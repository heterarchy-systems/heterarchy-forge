//! Control boundary for service-scoped Home-transfer source custody.
//!
//! This surface prepares or reads Forge's immutable source record. It does not
//! admit a target Session, transfer membership, or settle a Home cutover.

use forge_domain::{
    ForgeBackendId, HomeTransferReservationRetirementGrant,
    HomeTransferReservationRetirementRequest, HomeTransferReservationRetirementRequestDigest,
    HomeTransferSourceAction, HomeTransferSourceGrant, HomeTransferSourceRequest,
    HomeTransferSourceRequestDigest, OrchestrationIssuerId, TimestampMillis,
};
use forge_persistence::{
    HomeTransferReservationRetirementRecord, HomeTransferSourceInventoryError,
    HomeTransferSourceRecord, HomeTransferStoreError, WorkspaceStore, WorkspaceStoreError,
};
use uuid::Uuid;

use crate::error::{ControlError, ControlErrorCode};
use crate::service::{ForgeControl, ResolvedWorkspaceScope};

/// Configured caller identity for the source-only Home-transfer service.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HomeTransferSourceService {
    pub issuer: OrchestrationIssuerId,
    pub backend_id: ForgeBackendId,
    pub destination_id: Uuid,
}

/// One exact source operation submitted through the bounded control worker.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HomeTransferSourceCommand {
    pub scope: ResolvedWorkspaceScope,
    pub service: HomeTransferSourceService,
    pub operation: HomeTransferSourceOperation,
}

/// The only source-custody verbs exposed by this service boundary.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HomeTransferSourceOperation {
    Prepare {
        request: HomeTransferSourceRequest,
        grant: HomeTransferSourceGrant,
    },
    AbortUnstarted {
        request: HomeTransferSourceRequest,
        grant: HomeTransferSourceGrant,
    },
    Get {
        preparation_id: Uuid,
        request_digest: HomeTransferSourceRequestDigest,
    },
    RetireUnusedReservation {
        request: HomeTransferReservationRetirementRequest,
        grant: HomeTransferReservationRetirementGrant,
    },
    GetReservationRetirement {
        preparation_id: Uuid,
        reservation_request_id: Uuid,
        request_digest: HomeTransferReservationRetirementRequestDigest,
    },
}

/// Exact historical source outcome or a possibly absent exact readback.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HomeTransferSourceResponse {
    Outcome(HomeTransferSourceRecord),
    Record(Option<HomeTransferSourceRecord>),
    ReservationRetirementOutcome(HomeTransferReservationRetirementRecord),
    ReservationRetirementRecord(Option<HomeTransferReservationRetirementRecord>),
}

impl ForgeControl {
    /// Dispatch one source-custody request under the configured service scope.
    ///
    /// Mutations sample time inside the persistence owner's write transaction
    /// after validating the relevant source evidence. Historical Get operations
    /// never sample a clock or confer new effect authority.
    pub fn home_transfer_source<C>(
        &self,
        command: &HomeTransferSourceCommand,
        sample_clock: C,
    ) -> Result<HomeTransferSourceResponse, ControlError>
    where
        C: FnOnce() -> Result<TimestampMillis, HomeTransferStoreError>,
    {
        validate_command(command)?;
        let (fresh_scope, mut store) = self.open_resolved_workspace(
            command.scope.locator().location_id(),
            command.scope.locator().expected_revision(),
            command.scope.locator(),
        )?;
        if fresh_scope != command.scope {
            return Err(ControlError::new(
                ControlErrorCode::WorkspaceRevisionConflict,
            ));
        }

        let response = execute_source_operation(&mut store, command, sample_clock)?;
        if !self.committed_scope_matches_with_store(&command.scope, &store) {
            return Err(
                if matches!(
                    command.operation,
                    HomeTransferSourceOperation::Get { .. }
                        | HomeTransferSourceOperation::GetReservationRetirement { .. }
                ) {
                    ControlError::new(ControlErrorCode::WorkspaceRootConflict)
                } else {
                    ControlError::committed()
                },
            );
        }
        Ok(response)
    }
}

fn execute_source_operation<C>(
    store: &mut WorkspaceStore,
    command: &HomeTransferSourceCommand,
    sample_clock: C,
) -> Result<HomeTransferSourceResponse, ControlError>
where
    C: FnOnce() -> Result<TimestampMillis, HomeTransferStoreError>,
{
    match &command.operation {
        HomeTransferSourceOperation::Prepare { request, grant } => {
            let outcome = store
                .prepare_home_transfer_source(
                    request,
                    *grant,
                    command.service.issuer,
                    command.service.backend_id,
                    command.service.destination_id,
                    sample_clock,
                )
                .map_err(map_store_error)?;
            Ok(HomeTransferSourceResponse::Outcome(
                outcome.record().clone(),
            ))
        }
        HomeTransferSourceOperation::AbortUnstarted { request, grant } => {
            let outcome = store
                .abort_unstarted_home_transfer_source(
                    request,
                    *grant,
                    command.service.issuer,
                    command.service.backend_id,
                    command.service.destination_id,
                    sample_clock,
                )
                .map_err(map_store_error)?;
            Ok(HomeTransferSourceResponse::Outcome(
                outcome.record().clone(),
            ))
        }
        HomeTransferSourceOperation::Get {
            preparation_id,
            request_digest,
        } => {
            let record = store
                .get_home_transfer_source(
                    *preparation_id,
                    command.service.issuer,
                    command.service.backend_id,
                    command.service.destination_id,
                )
                .map_err(map_store_error)?;
            if record.as_ref().is_some_and(|record| {
                record.request().witness().preparation_id() != *preparation_id
                    || record.request().request_digest() != *request_digest
                    || record.request().scope().workspace_id() != command.scope.workspace_id()
            }) {
                return Err(ControlError::new(ControlErrorCode::AgentDagReplayConflict));
            }
            Ok(HomeTransferSourceResponse::Record(record))
        }
        HomeTransferSourceOperation::RetireUnusedReservation { request, grant } => {
            let outcome = store
                .retire_home_transfer_unused_reservation(
                    request,
                    *grant,
                    command.service.issuer,
                    command.service.backend_id,
                    command.service.destination_id,
                    sample_clock,
                )
                .map_err(map_store_error)?;
            Ok(HomeTransferSourceResponse::ReservationRetirementOutcome(
                outcome.record().clone(),
            ))
        }
        HomeTransferSourceOperation::GetReservationRetirement {
            preparation_id,
            reservation_request_id,
            request_digest,
        } => get_reservation_retirement(
            store,
            command,
            *preparation_id,
            *reservation_request_id,
            *request_digest,
        ),
    }
}

fn get_reservation_retirement(
    store: &WorkspaceStore,
    command: &HomeTransferSourceCommand,
    preparation_id: Uuid,
    reservation_request_id: Uuid,
    request_digest: HomeTransferReservationRetirementRequestDigest,
) -> Result<HomeTransferSourceResponse, ControlError> {
    let record = store
        .get_home_transfer_reservation_retirement(
            preparation_id,
            reservation_request_id,
            command.service.issuer,
            command.service.backend_id,
            command.service.destination_id,
        )
        .map_err(map_store_error)?;
    if record.as_ref().is_some_and(|record| {
        record.request().preparation_id() != preparation_id
            || record.request().reservation_request_id() != reservation_request_id
            || record.request().request_digest() != request_digest
            || record.request().scope().workspace_id() != command.scope.workspace_id()
    }) {
        return Err(ControlError::new(ControlErrorCode::AgentDagReplayConflict));
    }
    Ok(HomeTransferSourceResponse::ReservationRetirementRecord(
        record,
    ))
}

fn validate_command(command: &HomeTransferSourceCommand) -> Result<(), ControlError> {
    let service = command.service;
    if service.issuer.into_uuid().is_nil()
        || service.backend_id.into_uuid().is_nil()
        || service.destination_id.is_nil()
        || command.scope.workspace_id().into_uuid().is_nil()
    {
        return Err(ControlError::new(ControlErrorCode::AuthorizationRequired));
    }

    match &command.operation {
        HomeTransferSourceOperation::Prepare { request, grant } => {
            validate_request_service_scope(command, request)?;
            validate_grant(
                *grant,
                service.issuer,
                HomeTransferSourceAction::Prepare,
                request.request_digest(),
            )
        }
        HomeTransferSourceOperation::AbortUnstarted { request, grant } => {
            validate_request_service_scope(command, request)?;
            validate_grant(
                *grant,
                service.issuer,
                HomeTransferSourceAction::AbortUnstarted,
                request.request_digest(),
            )
        }
        HomeTransferSourceOperation::Get {
            preparation_id,
            request_digest,
        } => {
            if preparation_id.is_nil() || request_digest.as_bytes() == &[0; 32] {
                return Err(ControlError::new(ControlErrorCode::InvalidInput));
            }
            Ok(())
        }
        HomeTransferSourceOperation::RetireUnusedReservation { request, grant } => {
            let scope = request.scope();
            if scope.workspace_id() != command.scope.workspace_id()
                || scope.workspace_revision() != command.scope.workspace_revision()
                || scope.backend_id() != service.backend_id
                || scope.destination_id() != service.destination_id
            {
                return Err(ControlError::new(ControlErrorCode::AuthorizationRequired));
            }
            grant
                .validate_for(service.issuer, request.request_digest(), grant.issued_at())
                .map_err(|_| ControlError::new(ControlErrorCode::AuthorizationRequired))
        }
        HomeTransferSourceOperation::GetReservationRetirement {
            preparation_id,
            reservation_request_id,
            request_digest,
        } => {
            if preparation_id.is_nil()
                || reservation_request_id.is_nil()
                || request_digest.as_bytes() == &[0; 32]
            {
                return Err(ControlError::new(ControlErrorCode::InvalidInput));
            }
            Ok(())
        }
    }
}

fn validate_request_service_scope(
    command: &HomeTransferSourceCommand,
    request: &HomeTransferSourceRequest,
) -> Result<(), ControlError> {
    let scope = request.scope();
    if scope.workspace_id() != command.scope.workspace_id()
        || scope.backend_id() != command.service.backend_id
        || scope.destination_id() != command.service.destination_id
    {
        return Err(ControlError::new(ControlErrorCode::AuthorizationRequired));
    }
    Ok(())
}

fn validate_grant(
    grant: HomeTransferSourceGrant,
    issuer: OrchestrationIssuerId,
    action: HomeTransferSourceAction,
    request_digest: HomeTransferSourceRequestDigest,
) -> Result<(), ControlError> {
    // This checks immutable grant identity/action/digest only. Fresh admission
    // time is sampled later under the persistence write lock; exact replays
    // remain readable after the original grant expires.
    grant
        .validate_for(issuer, action, request_digest, grant.issued_at())
        .map_err(|_| ControlError::new(ControlErrorCode::AuthorizationRequired))
}

fn map_store_error(error: WorkspaceStoreError) -> ControlError {
    if matches!(
        &error,
        WorkspaceStoreError::HomeTransferReadbackRequired { .. }
            | WorkspaceStoreError::HomeReservationRetirementReadbackRequired { .. }
            | WorkspaceStoreError::HomeTransfer(
                HomeTransferStoreError::CommitUnconfirmed { .. }
                    | HomeTransferStoreError::RetirementCommitUnconfirmed { .. }
            )
    ) {
        return ControlError::committed_with_source(error);
    }

    let code = match &error {
        WorkspaceStoreError::HomeTransfer(HomeTransferStoreError::Bounds(_)) => {
            ControlErrorCode::CapacityExceeded
        }
        WorkspaceStoreError::HomeTransfer(HomeTransferStoreError::Inventory(error))
            if matches!(
                error.as_ref(),
                HomeTransferSourceInventoryError::Bounds(_)
                    | HomeTransferSourceInventoryError::PayloadTooLarge { .. }
            ) =>
        {
            ControlErrorCode::CapacityExceeded
        }
        WorkspaceStoreError::HomeTransfer(
            HomeTransferStoreError::Domain(_) | HomeTransferStoreError::RetirementDomain(_),
        ) => ControlErrorCode::InvalidInput,
        WorkspaceStoreError::HomeTransfer(HomeTransferStoreError::Fenced { .. }) => {
            ControlErrorCode::HomeTransferFenced
        }
        WorkspaceStoreError::HomeTransfer(HomeTransferStoreError::Conflict(_)) => {
            ControlErrorCode::AgentDagReplayConflict
        }
        WorkspaceStoreError::HomeTransfer(HomeTransferStoreError::Inventory(error))
            if matches!(
                error.as_ref(),
                HomeTransferSourceInventoryError::WorkspaceConflict
                    | HomeTransferSourceInventoryError::BindingConflict
                    | HomeTransferSourceInventoryError::RequestMismatch
            ) =>
        {
            ControlErrorCode::AgentDagReplayConflict
        }
        WorkspaceStoreError::HomeTransfer(HomeTransferStoreError::Clock) => {
            ControlErrorCode::Internal
        }
        _ => ControlErrorCode::PersistenceFailure,
    };
    ControlError::with_source(code, error)
}
