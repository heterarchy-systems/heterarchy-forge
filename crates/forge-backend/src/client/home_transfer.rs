//! Official bounded HTTP client for exact Home-transfer source commands.

#[cfg(test)]
mod tests;

use std::{fmt, net::SocketAddr};

use base64::Engine as _;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::OwnedSemaphorePermit;
use uuid::Uuid;

use forge_control::{
    HomeTransferSourceCommand, HomeTransferSourceOperation, HomeTransferSourceResponse,
};
use forge_domain::{
    HomeTransferReservationRetirementGrant, HomeTransferReservationRetirementRequest,
    HomeTransferSourceAction, HomeTransferSourceGrant, HomeTransferSourceRequest, TimestampMillis,
};
use forge_persistence::{
    HomeTransferReservationRetirementRecord, HomeTransferSourceRecord,
    HomeTransferSourceRecordParts, HomeTransferSourceState,
};

use crate::ops::CommandOp;

use super::{
    ForgeHttpClient, ForgeHttpClientError, ForgeHttpServiceCode, decode_command_response,
    migration_request_body, migration_scope_payload,
};

/// One immutable, caller-identified HTTP attempt for a Home source operation.
///
/// The body contains the complete versioned command envelope and is pinned to
/// the client authority, backend, and destination selected during preparation.
#[must_use]
#[derive(Clone, PartialEq, Eq)]
pub struct PreparedHomeTransferSourceCommand {
    command: HomeTransferSourceCommand,
    request_id: Uuid,
    operation: CommandOp,
    body: Vec<u8>,
    authority: SocketAddr,
    backend_id: forge_domain::ForgeBackendId,
    destination_id: Uuid,
}

impl fmt::Debug for PreparedHomeTransferSourceCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedHomeTransferSourceCommand")
            .field("request_id", &self.request_id)
            .field("operation", &self.operation.as_str())
            .field("authority", &self.authority)
            .field("backend_id", &self.backend_id)
            .field("destination_id", &self.destination_id)
            .field("body_bytes", &self.body.len())
            .finish_non_exhaustive()
    }
}

impl PreparedHomeTransferSourceCommand {
    pub const fn command(&self) -> &HomeTransferSourceCommand {
        &self.command
    }

    pub const fn request_id(&self) -> Uuid {
        self.request_id
    }

    pub const fn operation(&self) -> CommandOp {
        self.operation
    }

    pub fn body_bytes(&self) -> &[u8] {
        &self.body
    }

    pub const fn authority(&self) -> SocketAddr {
        self.authority
    }

    pub const fn backend_id(&self) -> forge_domain::ForgeBackendId {
        self.backend_id
    }

    pub const fn destination_id(&self) -> Uuid {
        self.destination_id
    }

    /// Build the exact read-only retirement lookup for a retained retirement
    /// attempt using a freshly resolved Workspace scope. The caller supplies a
    /// fresh transport request ID when preparing this command; this method
    /// never sends or retries the mutation.
    pub fn reservation_retirement_readback_command(
        &self,
        current_scope: &forge_control::ResolvedWorkspaceScope,
    ) -> Option<HomeTransferSourceCommand> {
        let HomeTransferSourceOperation::RetireUnusedReservation { request, .. } =
            &self.command.operation
        else {
            return None;
        };
        if current_scope.workspace_id() != request.scope().workspace_id() {
            return None;
        }
        Some(HomeTransferSourceCommand {
            scope: current_scope.clone(),
            service: self.command.service,
            operation: HomeTransferSourceOperation::GetReservationRetirement {
                preparation_id: request.preparation_id(),
                reservation_request_id: request.reservation_request_id(),
                request_digest: request.request_digest(),
            },
        })
    }
}

/// Pre-admitted send slot and exact prepared Home source attempt.
///
/// Dropping this value releases the existing bounded migration slot and sends
/// nothing. Calling `send` consumes it and performs exactly one HTTP exchange.
#[must_use]
pub struct ReservedHomeTransferSourceSend {
    client: ForgeHttpClient,
    prepared: PreparedHomeTransferSourceCommand,
    permit: OwnedSemaphorePermit,
}

impl ReservedHomeTransferSourceSend {
    pub const fn prepared(&self) -> &PreparedHomeTransferSourceCommand {
        &self.prepared
    }

    pub async fn send(
        self,
    ) -> Result<HomeTransferSourceResponse, ForgeHttpHomeTransferSourceError> {
        let Self {
            client,
            prepared,
            permit,
        } = self;
        client.send_prepared_with_permit(&prepared, permit).await
    }
}

impl fmt::Debug for ReservedHomeTransferSourceSend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReservedHomeTransferSourceSend")
            .field("prepared", &self.prepared)
            .field("slot_reserved", &true)
            .finish_non_exhaustive()
    }
}

/// Recovery result for an official Home source HTTP call.
///
/// Mutations retain the exact prepared attempt on both rejection and unknown
/// outcome. A Get failure is read-only and is reported as `ReadFailed`.
#[must_use]
#[derive(Clone, PartialEq, Eq)]
pub enum ForgeHttpHomeTransferSourceError {
    Rejected {
        command: Box<HomeTransferSourceCommand>,
        request_id: Uuid,
        prepared: Option<Box<PreparedHomeTransferSourceCommand>>,
        cause: ForgeHttpClientError,
    },
    UnknownOutcome {
        prepared: Box<PreparedHomeTransferSourceCommand>,
        cause: ForgeHttpClientError,
    },
    ReadFailed {
        prepared: Box<PreparedHomeTransferSourceCommand>,
        cause: ForgeHttpClientError,
    },
}

impl ForgeHttpHomeTransferSourceError {
    pub fn command(&self) -> &HomeTransferSourceCommand {
        match self {
            Self::Rejected {
                command, prepared, ..
            } => prepared
                .as_ref()
                .map_or(command.as_ref(), |prepared| &prepared.command),
            Self::UnknownOutcome { prepared, .. } | Self::ReadFailed { prepared, .. } => {
                &prepared.command
            }
        }
    }

    pub fn request_id(&self) -> Uuid {
        match self {
            Self::Rejected {
                request_id,
                prepared,
                ..
            } => prepared
                .as_ref()
                .map_or(*request_id, |prepared| prepared.request_id),
            Self::UnknownOutcome { prepared, .. } | Self::ReadFailed { prepared, .. } => {
                prepared.request_id
            }
        }
    }

    pub fn prepared(&self) -> Option<&PreparedHomeTransferSourceCommand> {
        match self {
            Self::Rejected { prepared, .. } => prepared.as_deref(),
            Self::UnknownOutcome { prepared, .. } | Self::ReadFailed { prepared, .. } => {
                Some(prepared.as_ref())
            }
        }
    }

    pub const fn cause(&self) -> &ForgeHttpClientError {
        match self {
            Self::Rejected { cause, .. }
            | Self::UnknownOutcome { cause, .. }
            | Self::ReadFailed { cause, .. } => cause,
        }
    }

    pub const fn is_unknown_outcome(&self) -> bool {
        matches!(self, Self::UnknownOutcome { .. })
    }

    pub const fn is_rejected(&self) -> bool {
        matches!(self, Self::Rejected { .. })
    }

    pub const fn is_read_failed(&self) -> bool {
        matches!(self, Self::ReadFailed { .. })
    }
}

impl fmt::Debug for ForgeHttpHomeTransferSourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (kind, cause) = match self {
            Self::Rejected { cause, .. } => ("Rejected", cause),
            Self::UnknownOutcome { cause, .. } => ("UnknownOutcome", cause),
            Self::ReadFailed { cause, .. } => ("ReadFailed", cause),
        };
        formatter
            .debug_struct("ForgeHttpHomeTransferSourceError")
            .field("kind", &kind)
            .field("cause", cause)
            .field("request_id", &self.request_id())
            .field("intent_retained", &true)
            .field("prepared_body_retained", &self.prepared().is_some())
            .finish_non_exhaustive()
    }
}

impl fmt::Display for ForgeHttpHomeTransferSourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected { .. } => formatter.write_str("Forge Home source command was rejected"),
            Self::UnknownOutcome { .. } => formatter.write_str(
                "Forge Home source mutation outcome is unknown; read back the exact preparation identity",
            ),
            Self::ReadFailed { .. } => formatter.write_str("Forge Home source read failed"),
        }
    }
}

impl std::error::Error for ForgeHttpHomeTransferSourceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.cause())
    }
}

impl ForgeHttpClient {
    /// Validate and encode one exact source operation without sending it.
    ///
    /// `request_id` belongs to the caller's attempt journal and is never
    /// generated or replaced by this client. The returned bytes can be stored
    /// unchanged and later passed to `send_prepared_home_transfer_source`.
    pub fn prepare_home_transfer_source_command(
        &self,
        command: &HomeTransferSourceCommand,
        request_id: Uuid,
    ) -> Result<PreparedHomeTransferSourceCommand, ForgeHttpHomeTransferSourceError> {
        let operation = validate_command(self, command, request_id)
            .map_err(|cause| rejected_command(command, request_id, cause))?;
        let fields = command_fields(command);
        let scope = migration_scope_payload(&command.scope)
            .map_err(|cause| rejected_command(command, request_id, cause))?;
        let body = migration_request_body(operation, scope, fields, request_id)
            .map_err(|cause| rejected_command(command, request_id, cause))?;
        Ok(PreparedHomeTransferSourceCommand {
            command: command.clone(),
            request_id,
            operation,
            body,
            authority: self.authority,
            backend_id: self.expected_backend_id,
            destination_id: self.destination_id,
        })
    }

    /// Reserve one of the existing bounded migration send slots without
    /// sending. Call this before committing a caller-owned one-shot attempt.
    /// Dropping the returned value releases the slot and performs no effect.
    pub fn reserve_home_transfer_source_send(
        &self,
        prepared: PreparedHomeTransferSourceCommand,
    ) -> Result<ReservedHomeTransferSourceSend, ForgeHttpHomeTransferSourceError> {
        if self.authority != prepared.authority
            || self.expected_backend_id != prepared.backend_id
            || self.destination_id != prepared.destination_id
        {
            return Err(rejected(
                &prepared,
                ForgeHttpClientError::DestinationMismatch,
            ));
        }
        if prepared.body.len() > super::MAX_REQUEST_BYTES {
            return Err(rejected(&prepared, ForgeHttpClientError::RequestTooLarge));
        }
        if let Err(cause) = validate_command(self, &prepared.command, prepared.request_id) {
            return Err(rejected(&prepared, cause));
        }
        if crate::ops::home_transfers::operation_op(&prepared.command) != prepared.operation {
            return Err(rejected(&prepared, ForgeHttpClientError::InvalidRequest));
        }
        let Ok(permit) = self.migration_slots.clone().try_acquire_owned() else {
            return Err(rejected(&prepared, ForgeHttpClientError::Capacity));
        };
        Ok(ReservedHomeTransferSourceSend {
            client: self.clone(),
            prepared,
            permit,
        })
    }

    /// Convenience one-shot send. Ops integrations that need to commit their
    /// own attempt receipt first should reserve explicitly and then consume it.
    pub async fn send_prepared_home_transfer_source(
        &self,
        prepared: &PreparedHomeTransferSourceCommand,
    ) -> Result<HomeTransferSourceResponse, ForgeHttpHomeTransferSourceError> {
        self.reserve_home_transfer_source_send(prepared.clone())?
            .send()
            .await
    }

    async fn send_prepared_with_permit(
        &self,
        prepared: &PreparedHomeTransferSourceCommand,
        permit: OwnedSemaphorePermit,
    ) -> Result<HomeTransferSourceResponse, ForgeHttpHomeTransferSourceError> {
        // Keep this owned permit alive for the entire single exchange. Dropping
        // the reservation before calling send drops it without issuing a request.
        let _permit = permit;
        let exchange = tokio::time::timeout(
            self.timeout,
            self.exchange_command(prepared.operation, prepared.body.clone()),
        )
        .await;
        let raw = match exchange {
            Ok(Ok(raw)) => raw,
            Ok(Err(cause)) => return Err(classify_dispatched_error(prepared, cause)),
            Err(_) => {
                return Err(classify_dispatched_error(
                    prepared,
                    ForgeHttpClientError::Timeout,
                ));
            }
        };
        let result = match decode_command_response(raw, prepared.request_id) {
            Ok(result) => result,
            Err(cause) => return Err(classify_dispatched_error(prepared, cause)),
        };
        decode_home_source_response(self, prepared, &result)
            .map_err(|cause| classify_dispatched_error(prepared, cause))
    }
}

fn validate_command(
    client: &ForgeHttpClient,
    command: &HomeTransferSourceCommand,
    request_id: Uuid,
) -> Result<CommandOp, ForgeHttpClientError> {
    if request_id.is_nil()
        || command.scope.workspace_id().into_uuid().is_nil()
        || command.scope.locator().location_id().into_uuid().is_nil()
        || command.service.issuer.into_uuid().is_nil()
    {
        return Err(ForgeHttpClientError::InvalidRequest);
    }
    if command.service.backend_id != client.expected_backend_id
        || command.service.destination_id != client.destination_id
    {
        return Err(ForgeHttpClientError::DestinationMismatch);
    }
    let operation = crate::ops::home_transfers::operation_op(command);
    match &command.operation {
        HomeTransferSourceOperation::Prepare { request, grant } => validate_mutation(
            command,
            client,
            request,
            *grant,
            HomeTransferSourceAction::Prepare,
        )?,
        HomeTransferSourceOperation::AbortUnstarted { request, grant } => validate_mutation(
            command,
            client,
            request,
            *grant,
            HomeTransferSourceAction::AbortUnstarted,
        )?,
        HomeTransferSourceOperation::Get {
            preparation_id,
            request_digest,
        } => {
            if preparation_id.is_nil() || request_digest.as_bytes() == &[0; 32] {
                return Err(ForgeHttpClientError::InvalidRequest);
            }
        }
        HomeTransferSourceOperation::RetireUnusedReservation { request, grant } => {
            validate_retirement(command, client, request, *grant)?;
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
                return Err(ForgeHttpClientError::InvalidRequest);
            }
        }
    }
    Ok(operation)
}

fn validate_mutation(
    command: &HomeTransferSourceCommand,
    client: &ForgeHttpClient,
    request: &HomeTransferSourceRequest,
    grant: HomeTransferSourceGrant,
    action: HomeTransferSourceAction,
) -> Result<(), ForgeHttpClientError> {
    if request.scope().workspace_id() != command.scope.workspace_id() {
        return Err(ForgeHttpClientError::InvalidRequest);
    }
    if request.scope().backend_id() != client.expected_backend_id
        || request.scope().destination_id() != client.destination_id
    {
        return Err(ForgeHttpClientError::DestinationMismatch);
    }
    grant
        .validate_for(
            command.service.issuer,
            action,
            request.request_digest(),
            grant.issued_at(),
        )
        .map_err(|_| ForgeHttpClientError::InvalidRequest)
}

fn validate_retirement(
    command: &HomeTransferSourceCommand,
    client: &ForgeHttpClient,
    request: &HomeTransferReservationRetirementRequest,
    grant: HomeTransferReservationRetirementGrant,
) -> Result<(), ForgeHttpClientError> {
    let scope = request.scope();
    if scope.workspace_id() != command.scope.workspace_id()
        || scope.workspace_revision() != command.scope.workspace_revision()
    {
        return Err(ForgeHttpClientError::InvalidRequest);
    }
    if scope.backend_id() != client.expected_backend_id
        || scope.destination_id() != client.destination_id
    {
        return Err(ForgeHttpClientError::DestinationMismatch);
    }
    grant
        .validate_for(
            command.service.issuer,
            request.request_digest(),
            grant.issued_at(),
        )
        .map_err(|_| ForgeHttpClientError::InvalidRequest)
}

fn command_fields(command: &HomeTransferSourceCommand) -> Value {
    let service = json!({
        "issuer": command.service.issuer.into_uuid(),
        "backend_id": command.service.backend_id.into_uuid(),
        "destination_id": command.service.destination_id,
    });
    let mut fields = json!({"service": service});
    match &command.operation {
        HomeTransferSourceOperation::Prepare { request, grant } => {
            fields["request"] = crate::ops::home_transfers::request_json(request);
            fields["grant"] = grant_json(grant, "prepare");
        }
        HomeTransferSourceOperation::AbortUnstarted { request, grant } => {
            fields["request"] = crate::ops::home_transfers::request_json(request);
            fields["grant"] = grant_json(grant, "abort_unstarted");
        }
        HomeTransferSourceOperation::Get {
            preparation_id,
            request_digest,
        } => {
            fields["preparation_id"] = json!(preparation_id);
            fields["request_digest"] = json!(crate::ops::home_transfers::wire::encode_digest(
                request_digest.as_bytes()
            ));
        }
        HomeTransferSourceOperation::RetireUnusedReservation { request, grant } => {
            fields["request"] = crate::ops::home_transfers::wire::retirement_request_json(request);
            fields["grant"] = crate::ops::home_transfers::wire::retirement_grant_json(*grant);
        }
        HomeTransferSourceOperation::GetReservationRetirement {
            preparation_id,
            reservation_request_id,
            request_digest,
        } => {
            fields["preparation_id"] = json!(preparation_id);
            fields["reservation_request_id"] = json!(reservation_request_id);
            fields["request_digest"] = json!(crate::ops::home_transfers::wire::encode_digest(
                request_digest.as_bytes()
            ));
        }
    }
    fields
}

fn grant_json(grant: &HomeTransferSourceGrant, action: &str) -> Value {
    json!({
        "issuer": grant.issuer().into_uuid(),
        "action": action,
        "request_digest": crate::ops::home_transfers::wire::encode_digest(
            grant.request_digest().as_bytes(),
        ),
        "issued_at_ms": grant.issued_at().get(),
        "expires_at_ms": grant.expires_at().get(),
    })
}

fn is_mutation(operation: &HomeTransferSourceOperation) -> bool {
    matches!(
        operation,
        HomeTransferSourceOperation::Prepare { .. }
            | HomeTransferSourceOperation::AbortUnstarted { .. }
            | HomeTransferSourceOperation::RetireUnusedReservation { .. }
    )
}

fn classify_dispatched_error(
    prepared: &PreparedHomeTransferSourceCommand,
    cause: ForgeHttpClientError,
) -> ForgeHttpHomeTransferSourceError {
    if !is_mutation(&prepared.command.operation) {
        return read_failed(prepared, cause);
    }
    if confirmed_rejection(cause) {
        rejected(prepared, cause)
    } else {
        unknown_outcome(prepared, cause)
    }
}

fn confirmed_rejection(error: ForgeHttpClientError) -> bool {
    match error {
        ForgeHttpClientError::Authentication
        | ForgeHttpClientError::Capacity
        | ForgeHttpClientError::DestinationMismatch
        | ForgeHttpClientError::InvalidRequest
        | ForgeHttpClientError::Request
        | ForgeHttpClientError::RequestTooLarge => true,
        ForgeHttpClientError::Service { status, code } => {
            matches!(code, ForgeHttpServiceCode::CapacityExceeded)
                || (status < 500
                    && status != 408
                    && !matches!(code, ForgeHttpServiceCode::UnknownOutcome))
        }
        ForgeHttpClientError::Transport
        | ForgeHttpClientError::Timeout
        | ForgeHttpClientError::ResponseHeadersTooLarge
        | ForgeHttpClientError::ResponseTooLarge
        | ForgeHttpClientError::Protocol => false,
    }
}

fn rejected(
    prepared: &PreparedHomeTransferSourceCommand,
    cause: ForgeHttpClientError,
) -> ForgeHttpHomeTransferSourceError {
    ForgeHttpHomeTransferSourceError::Rejected {
        command: Box::new(prepared.command.clone()),
        request_id: prepared.request_id,
        prepared: Some(Box::new(prepared.clone())),
        cause,
    }
}

fn rejected_command(
    command: &HomeTransferSourceCommand,
    request_id: Uuid,
    cause: ForgeHttpClientError,
) -> ForgeHttpHomeTransferSourceError {
    ForgeHttpHomeTransferSourceError::Rejected {
        command: Box::new(command.clone()),
        request_id,
        prepared: None,
        cause,
    }
}

fn unknown_outcome(
    prepared: &PreparedHomeTransferSourceCommand,
    cause: ForgeHttpClientError,
) -> ForgeHttpHomeTransferSourceError {
    ForgeHttpHomeTransferSourceError::UnknownOutcome {
        prepared: Box::new(prepared.clone()),
        cause,
    }
}

fn read_failed(
    prepared: &PreparedHomeTransferSourceCommand,
    cause: ForgeHttpClientError,
) -> ForgeHttpHomeTransferSourceError {
    ForgeHttpHomeTransferSourceError::ReadFailed {
        prepared: Box::new(prepared.clone()),
        cause,
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SourceStateWire {
    Prepared,
    AbortedUnstarted,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DelegationWitnessWire {
    migration_id: Uuid,
    freeze_revision: u64,
    delegation_digest: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HomeTransferSourceRecordWire {
    request: Value,
    request_digest: String,
    issuer: Uuid,
    state: SourceStateWire,
    observed_at_ms: i64,
    grant_issued_at_ms: i64,
    grant_expires_at_ms: i64,
    delegation_witness: DelegationWitnessWire,
    inventory_payload_base64: Option<String>,
    inventory_digest: Option<String>,
    outcome_digest: String,
}

fn decode_home_source_response(
    client: &ForgeHttpClient,
    prepared: &PreparedHomeTransferSourceCommand,
    result: &Value,
) -> Result<HomeTransferSourceResponse, ForgeHttpClientError> {
    if !has_exact_fields(result, &["record"]) {
        return Err(ForgeHttpClientError::Protocol);
    }
    let record = &result["record"];
    match &prepared.command.operation {
        HomeTransferSourceOperation::Prepare { request, .. }
        | HomeTransferSourceOperation::AbortUnstarted { request, .. } => {
            if record.is_null() {
                return Err(ForgeHttpClientError::Protocol);
            }
            let record = decode_record(record)?;
            validate_record_service(client, &prepared.command, &record)?;
            if record.request() != request {
                return Err(ForgeHttpClientError::Protocol);
            }
            Ok(HomeTransferSourceResponse::Outcome(record))
        }
        HomeTransferSourceOperation::Get {
            preparation_id,
            request_digest,
        } => {
            if record.is_null() {
                return Ok(HomeTransferSourceResponse::Record(None));
            }
            let record = decode_record(record)?;
            validate_record_service(client, &prepared.command, &record)?;
            if record.request().witness().preparation_id() != *preparation_id
                || record.request().request_digest() != *request_digest
            {
                return Err(ForgeHttpClientError::Protocol);
            }
            Ok(HomeTransferSourceResponse::Record(Some(record)))
        }
        HomeTransferSourceOperation::RetireUnusedReservation { request, .. } => {
            if record.is_null() {
                return Err(ForgeHttpClientError::Protocol);
            }
            let record = decode_retirement_record(record)?;
            validate_retirement_record_service(client, &prepared.command, &record)?;
            if record.request() != request {
                return Err(ForgeHttpClientError::Protocol);
            }
            Ok(HomeTransferSourceResponse::ReservationRetirementOutcome(
                record,
            ))
        }
        HomeTransferSourceOperation::GetReservationRetirement {
            preparation_id,
            reservation_request_id,
            request_digest,
        } => {
            if record.is_null() {
                return Ok(HomeTransferSourceResponse::ReservationRetirementRecord(
                    None,
                ));
            }
            let record = decode_retirement_record(record)?;
            validate_retirement_record_service(client, &prepared.command, &record)?;
            if record.request().preparation_id() != *preparation_id
                || record.request().reservation_request_id() != *reservation_request_id
                || record.request().request_digest() != *request_digest
            {
                return Err(ForgeHttpClientError::Protocol);
            }
            Ok(HomeTransferSourceResponse::ReservationRetirementRecord(
                Some(record),
            ))
        }
    }
}

fn decode_retirement_record(
    value: &Value,
) -> Result<HomeTransferReservationRetirementRecord, ForgeHttpClientError> {
    crate::ops::home_transfers::wire::decode_retirement_record_json(value)
        .map_err(|_| ForgeHttpClientError::Protocol)
}

fn validate_retirement_record_service(
    client: &ForgeHttpClient,
    command: &HomeTransferSourceCommand,
    record: &HomeTransferReservationRetirementRecord,
) -> Result<(), ForgeHttpClientError> {
    let request = record.request();
    let scope = request.scope();
    if record.issuer() != command.service.issuer
        || scope.workspace_id() != command.scope.workspace_id()
        || scope.backend_id() != client.expected_backend_id
        || scope.destination_id() != client.destination_id
    {
        return Err(ForgeHttpClientError::Protocol);
    }
    Ok(())
}

fn validate_record_service(
    client: &ForgeHttpClient,
    command: &HomeTransferSourceCommand,
    record: &HomeTransferSourceRecord,
) -> Result<(), ForgeHttpClientError> {
    let request = record.request();
    if record.issuer() != command.service.issuer
        || request.scope().workspace_id() != command.scope.workspace_id()
        || request.scope().backend_id() != client.expected_backend_id
        || request.scope().destination_id() != client.destination_id
    {
        return Err(ForgeHttpClientError::Protocol);
    }
    Ok(())
}

fn decode_record(value: &Value) -> Result<HomeTransferSourceRecord, ForgeHttpClientError> {
    if !has_exact_fields(
        value,
        &[
            "request",
            "request_digest",
            "issuer",
            "state",
            "observed_at_ms",
            "grant_issued_at_ms",
            "grant_expires_at_ms",
            "delegation_witness",
            "inventory_payload_base64",
            "inventory_digest",
            "outcome_digest",
        ],
    ) || !has_exact_fields(
        &value["delegation_witness"],
        &["migration_id", "freeze_revision", "delegation_digest"],
    ) {
        return Err(ForgeHttpClientError::Protocol);
    }
    let wire: HomeTransferSourceRecordWire =
        serde_json::from_value(value.clone()).map_err(|_| ForgeHttpClientError::Protocol)?;
    let request = crate::ops::home_transfers::wire::decode_request_json(&wire.request)
        .map_err(|_| ForgeHttpClientError::Protocol)?;
    let request_digest = decode_digest(&wire.request_digest)?;
    if request.request_digest().as_bytes() != &request_digest {
        return Err(ForgeHttpClientError::Protocol);
    }
    let inventory_payload = wire
        .inventory_payload_base64
        .as_deref()
        .map(decode_inventory_payload)
        .transpose()?;
    let inventory_digest = wire
        .inventory_digest
        .as_deref()
        .map(decode_digest)
        .transpose()?;
    let state = match wire.state {
        SourceStateWire::Prepared => HomeTransferSourceState::Prepared,
        SourceStateWire::AbortedUnstarted => HomeTransferSourceState::AbortedUnstarted,
    };
    HomeTransferSourceRecord::from_parts(HomeTransferSourceRecordParts {
        request,
        issuer: forge_domain::OrchestrationIssuerId::from_uuid(wire.issuer),
        state,
        observed_at: decode_timestamp(wire.observed_at_ms)?,
        grant_issued_at: decode_timestamp(wire.grant_issued_at_ms)?,
        grant_expires_at: decode_timestamp(wire.grant_expires_at_ms)?,
        migration_id: wire.delegation_witness.migration_id,
        freeze_revision: wire.delegation_witness.freeze_revision,
        delegation_digest: decode_digest(&wire.delegation_witness.delegation_digest)?,
        inventory_payload,
        inventory_digest,
        outcome_digest: decode_digest(&wire.outcome_digest)?,
    })
    .map_err(|_| ForgeHttpClientError::Protocol)
}

fn decode_inventory_payload(value: &str) -> Result<Vec<u8>, ForgeHttpClientError> {
    if value.is_empty() || value.len() > super::MAX_CLIENT_RESPONSE_BYTES {
        return Err(ForgeHttpClientError::Protocol);
    }
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let bytes = engine
        .decode(value.as_bytes())
        .map_err(|_| ForgeHttpClientError::Protocol)?;
    if bytes.is_empty() || engine.encode(&bytes) != value {
        return Err(ForgeHttpClientError::Protocol);
    }
    // `HomeTransferSourceRecord::from_parts` owns and enforces the 512 KiB
    // decoded capsule bound after this canonical base64 conversion.
    Ok(bytes)
}

fn decode_digest(value: &str) -> Result<[u8; 32], ForgeHttpClientError> {
    crate::ops::home_transfers::wire::decode_digest(value, "record digest")
        .map_err(|_| ForgeHttpClientError::Protocol)
}

fn decode_timestamp(value: i64) -> Result<TimestampMillis, ForgeHttpClientError> {
    TimestampMillis::new(value).map_err(|_| ForgeHttpClientError::Protocol)
}

fn has_exact_fields(value: &Value, expected: &[&str]) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    object.len() == expected.len() && expected.iter().all(|field| object.contains_key(*field))
}
