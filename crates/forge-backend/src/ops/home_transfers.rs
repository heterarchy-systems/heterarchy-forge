//! Typed HTTP boundary for the Forge-owned Home-transfer source journal.

#[cfg(test)]
mod tests;
pub(crate) mod wire;

use base64::Engine as _;
use serde_json::{Value, json};
use uuid::Uuid;

use forge_control::{
    HomeTransferSourceCommand, HomeTransferSourceOperation, HomeTransferSourceResponse,
};
use forge_domain::{AuthenticatedPrincipal, HomeTransferReservationRetirementRequest};
use forge_persistence::{
    HomeTransferReservationRetirementRecord, HomeTransferSourceRecord, HomeTransferSourceState,
};

use crate::error::{ErrorCode, ForgeError, ReadbackHint};

use super::{BridgeClients, CommandOp};

pub(crate) const fn operation_op(command: &HomeTransferSourceCommand) -> CommandOp {
    match &command.operation {
        HomeTransferSourceOperation::Prepare { .. } => CommandOp::HomeTransferSourcePrepare,
        HomeTransferSourceOperation::AbortUnstarted { .. } => {
            CommandOp::HomeTransferSourceAbortUnstarted
        }
        HomeTransferSourceOperation::Get { .. } => CommandOp::HomeTransferSourceGet,
        HomeTransferSourceOperation::RetireUnusedReservation { .. } => {
            CommandOp::HomeTransferReservationRetireUnused
        }
        HomeTransferSourceOperation::GetReservationRetirement { .. } => {
            CommandOp::HomeTransferReservationRetirementGet
        }
    }
}

pub(super) fn parse(
    operation: CommandOp,
    payload: &Value,
) -> Result<HomeTransferSourceCommand, ForgeError> {
    wire::parse(operation, payload)
}

pub(super) fn execute(
    clients: &BridgeClients,
    command: &HomeTransferSourceCommand,
) -> Result<Value, ForgeError> {
    validate_configured_authority(clients, command)?;
    let readback_hint = readback_hint(command);
    let response = clients
        .control
        .home_transfer_source(command.clone())
        .map_err(|error| map_control_error(&error, readback_hint.clone()))?;
    project_response(clients, command, response)
}

fn validate_configured_authority(
    clients: &BridgeClients,
    command: &HomeTransferSourceCommand,
) -> Result<(), ForgeError> {
    let service = command.service;
    if !service_matches_configuration(
        service,
        clients.issuer,
        clients.backend_id,
        clients.destination_id,
    ) {
        return Err(ForgeError::auth_failed());
    }

    let request = match &command.operation {
        HomeTransferSourceOperation::Prepare { request, .. }
        | HomeTransferSourceOperation::AbortUnstarted { request, .. } => Some(request),
        HomeTransferSourceOperation::Get { .. }
        | HomeTransferSourceOperation::GetReservationRetirement { .. } => None,
        HomeTransferSourceOperation::RetireUnusedReservation { request, .. } => {
            if !retirement_request_matches_configured_scope(
                request,
                command.scope.workspace_id(),
                command.scope.workspace_revision(),
                clients.backend_id,
                clients.destination_id,
            ) {
                return Err(ForgeError::auth_failed());
            }
            None
        }
    };
    if request.is_some_and(|request| {
        !request_matches_configured_scope(
            request,
            command.scope.workspace_id(),
            clients.backend_id,
            clients.destination_id,
        )
    }) {
        return Err(ForgeError::auth_failed());
    }
    Ok(())
}

fn service_matches_configuration(
    service: forge_control::HomeTransferSourceService,
    issuer: forge_domain::OrchestrationIssuerId,
    backend_id: forge_domain::ForgeBackendId,
    destination_id: Uuid,
) -> bool {
    service.issuer == issuer
        && service.backend_id == backend_id
        && service.destination_id == destination_id
}

fn request_matches_configured_scope(
    request: &forge_domain::HomeTransferSourceRequest,
    workspace_id: forge_domain::WorkspaceId,
    backend_id: forge_domain::ForgeBackendId,
    destination_id: Uuid,
) -> bool {
    request.scope().workspace_id() == workspace_id
        && request.scope().backend_id() == backend_id
        && request.scope().destination_id() == destination_id
}

fn project_response(
    clients: &BridgeClients,
    command: &HomeTransferSourceCommand,
    response: HomeTransferSourceResponse,
) -> Result<Value, ForgeError> {
    match (&command.operation, response) {
        (
            HomeTransferSourceOperation::Prepare { request, .. }
            | HomeTransferSourceOperation::AbortUnstarted { request, .. },
            HomeTransferSourceResponse::Outcome(record),
        ) => {
            validate_record_service(clients, command.scope.workspace_id().into_uuid(), &record)?;
            if record.request() != request {
                return Err(ForgeError::resync_required(
                    "Home source response did not preserve the exact request",
                ));
            }
            Ok(json!({"record": record_json(&record)}))
        }
        (
            HomeTransferSourceOperation::Get {
                preparation_id,
                request_digest,
            },
            HomeTransferSourceResponse::Record(record),
        ) => {
            if let Some(record) = &record {
                validate_record_service(clients, command.scope.workspace_id().into_uuid(), record)?;
                if record.request().witness().preparation_id() != *preparation_id
                    || record.request().request_digest() != *request_digest
                {
                    return Err(ForgeError::resync_required(
                        "Home source response did not match the requested readback identity",
                    ));
                }
            }
            Ok(json!({"record": record.as_ref().map(record_json)}))
        }
        (
            HomeTransferSourceOperation::RetireUnusedReservation { request, .. },
            HomeTransferSourceResponse::ReservationRetirementOutcome(record),
        ) => {
            validate_retirement_record_service(
                clients,
                command.scope.workspace_id().into_uuid(),
                &record,
            )?;
            if record.request() != request {
                return Err(ForgeError::resync_required(
                    "Home reservation retirement response did not preserve the exact request",
                ));
            }
            Ok(json!({"record": wire::retirement_record_json(&record)}))
        }
        (
            HomeTransferSourceOperation::GetReservationRetirement {
                preparation_id,
                reservation_request_id,
                request_digest,
            },
            HomeTransferSourceResponse::ReservationRetirementRecord(record),
        ) => {
            if let Some(record) = &record {
                validate_retirement_record_service(
                    clients,
                    command.scope.workspace_id().into_uuid(),
                    record,
                )?;
                if record.request().preparation_id() != *preparation_id
                    || record.request().reservation_request_id() != *reservation_request_id
                    || record.request().request_digest() != *request_digest
                {
                    return Err(ForgeError::resync_required(
                        "Home reservation retirement response did not match the requested readback identity",
                    ));
                }
            }
            Ok(json!({
                "record": record.as_ref().map(wire::retirement_record_json),
            }))
        }
        _ => Err(ForgeError::internal()),
    }
}

fn retirement_request_matches_configured_scope(
    request: &HomeTransferReservationRetirementRequest,
    workspace_id: forge_domain::WorkspaceId,
    workspace_revision: forge_domain::WorkspaceRevision,
    backend_id: forge_domain::ForgeBackendId,
    destination_id: Uuid,
) -> bool {
    let scope = request.scope();
    scope.workspace_id() == workspace_id
        && scope.workspace_revision() == workspace_revision
        && scope.backend_id() == backend_id
        && scope.destination_id() == destination_id
}

fn validate_record_service(
    clients: &BridgeClients,
    workspace_id: Uuid,
    record: &HomeTransferSourceRecord,
) -> Result<(), ForgeError> {
    let request = record.request();
    if record.issuer() != clients.issuer
        || request.scope().workspace_id().into_uuid() != workspace_id
        || request.scope().backend_id() != clients.backend_id
        || request.scope().destination_id() != clients.destination_id
    {
        return Err(ForgeError::resync_required(
            "Home source history did not match the configured service scope",
        ));
    }
    Ok(())
}

fn validate_retirement_record_service(
    clients: &BridgeClients,
    workspace_id: Uuid,
    record: &HomeTransferReservationRetirementRecord,
) -> Result<(), ForgeError> {
    let request = record.request();
    let scope = request.scope();
    if record.issuer() != clients.issuer
        || scope.workspace_id().into_uuid() != workspace_id
        || scope.backend_id() != clients.backend_id
        || scope.destination_id() != clients.destination_id
    {
        return Err(ForgeError::resync_required(
            "Home reservation retirement history did not match the configured service scope",
        ));
    }
    Ok(())
}

pub(crate) fn record_json(record: &HomeTransferSourceRecord) -> Value {
    let (inventory_payload, inventory_digest) =
        inventory_fields(record.inventory_payload(), record.inventory_digest());
    json!({
        "request": request_json(record.request()),
        "request_digest": super::encode_hex(record.request().request_digest().as_bytes()),
        "issuer": record.issuer().into_uuid(),
        "state": match record.state() {
            HomeTransferSourceState::Prepared => "prepared",
            HomeTransferSourceState::AbortedUnstarted => "aborted_unstarted",
        },
        "observed_at_ms": record.observed_at().get(),
        "grant_issued_at_ms": record.grant_issued_at().get(),
        "grant_expires_at_ms": record.grant_expires_at().get(),
        "delegation_witness": {
            "migration_id": record.migration_id(),
            "freeze_revision": record.freeze_revision(),
            "delegation_digest": super::encode_hex(record.delegation_digest()),
        },
        "inventory_payload_base64": inventory_payload,
        "inventory_digest": inventory_digest,
        "outcome_digest": super::encode_hex(record.outcome_digest()),
    })
}

fn inventory_fields(
    payload: Option<&[u8]>,
    digest: Option<&[u8; 32]>,
) -> (Option<String>, Option<String>) {
    (
        payload.map(|payload| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload)),
        digest.map(|digest| super::encode_hex(digest)),
    )
}

pub(crate) fn request_json(request: &forge_domain::HomeTransferSourceRequest) -> Value {
    let witness = request.witness();
    let scope = request.scope();
    let subject = request.subject();
    json!({
        "witness": {
            "preparation_id": witness.preparation_id(),
            "intent_digest": super::encode_hex(witness.intent_digest()),
            "preparation_digest": super::encode_hex(witness.preparation_digest()),
        },
        "scope": {
            "workspace_id": scope.workspace_id().into_uuid(),
            "workspace_revision": scope.workspace_revision().get(),
            "backend_id": scope.backend_id().into_uuid(),
            "destination_id": scope.destination_id(),
        },
        "subject": {
            "transfer_id": subject.transfer_id(),
            "transfer_generation": subject.transfer_generation(),
            "target_profile_id": subject.target_profile_id(),
            "target_participation_id": subject.target_participation_id(),
            "source_team_id": subject.source_team_id(),
            "destination_team_id": subject.destination_team_id(),
            "source_membership_revision": subject.source_membership_revision(),
            "participation_revision": subject.participation_revision(),
        },
        "sessions": request.sessions().iter().map(|session| session.into_uuid()).collect::<Vec<_>>(),
        "bindings": request.bindings().iter().map(|binding| json!({
            "activity_id": binding.activity_id().into_uuid(),
            "agent_id": binding.agent_id().into_uuid(),
            "session_id": binding.session_id().into_uuid(),
            "principal": principal_json(binding.principal()),
        })).collect::<Vec<_>>(),
        "request_digest": super::encode_hex(request.request_digest().as_bytes()),
    })
}

fn principal_json(principal: AuthenticatedPrincipal) -> Value {
    match principal {
        AuthenticatedPrincipal::TrustedStdio => json!({
            "kind": "trusted_stdio",
            "token_id": null,
            "grant_id": null,
        }),
        AuthenticatedPrincipal::DirectToken(token) => json!({
            "kind": "direct_token",
            "token_id": token.into_uuid(),
            "grant_id": null,
        }),
        AuthenticatedPrincipal::OAuthGrant(grant) => json!({
            "kind": "oauth_grant",
            "token_id": null,
            "grant_id": grant.into_uuid(),
        }),
    }
}

pub(super) fn readback_hint(command: &HomeTransferSourceCommand) -> Option<ReadbackHint> {
    match &command.operation {
        HomeTransferSourceOperation::Prepare { request, .. }
        | HomeTransferSourceOperation::AbortUnstarted { request, .. } => {
            Some(ReadbackHint::HomeTransferSource {
                workspace_id: request.scope().workspace_id().into_uuid(),
                preparation_id: request.witness().preparation_id(),
                request_digest: super::encode_hex(request.request_digest().as_bytes()),
            })
        }
        HomeTransferSourceOperation::RetireUnusedReservation { request, .. } => {
            ReadbackHint::home_transfer_reservation_retirement(command, request)
        }
        HomeTransferSourceOperation::Get { .. }
        | HomeTransferSourceOperation::GetReservationRetirement { .. } => None,
    }
}

fn map_control_error(
    error: &forge_control::ControlClientError,
    readback_hint: Option<ReadbackHint>,
) -> ForgeError {
    let mapped = super::forge_error_of_client(error);
    if mapped.code() == ErrorCode::UnknownOutcome
        && let Some(readback_hint) = readback_hint
    {
        return mapped.with_readback(Some(readback_hint));
    }
    mapped
}
