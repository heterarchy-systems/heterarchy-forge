//! Typed HTTP adapter for exact terminal Agent binding rejection settlement.
//!
//! The mutation payload carries only the stable Orchestration-owned
//! attestation. Source-owned reservation, root, binding, delegation, and
//! rejection-time fences are derived by `forge-control` and only projected
//! from the immutable receipt.

use forge_control::{
    AgentBindingRejectRequest, AgentBindingRejectionReadRequest, ForgeControlClient,
    ResolvedWorkspaceScope,
};
use forge_domain::{
    ActivityId, AgentBindingRejectionReason, AgentBindingRejectionReceipt, AgentDeclaredRole,
    AgentDisplayName, AgentInstanceId, AgentSessionId, AgentTransportKind, AuthenticatedPrincipal,
    OrchestrationIssuerId, TimestampMillis,
};
use forge_persistence::{
    AgentBindingActivationRequest, AgentBindingRejectionOperation, AgentBindingReservationRequest,
};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use super::{CommandOp, PrincipalDto, ScopeDto, decode_principal, decode_scope};
use crate::error::{ForgeError, ReadbackHint};

const DIGEST_BYTES: usize = 32;

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingRejectionCommand {
    scope: ResolvedWorkspaceScope,
    issuer_id: OrchestrationIssuerId,
    destination_id: Uuid,
    request_digest: Option<[u8; DIGEST_BYTES]>,
    request: BindingRejectionRequest,
}

impl BindingRejectionCommand {
    pub const fn op(&self) -> CommandOp {
        match self.request {
            BindingRejectionRequest::Reject(_) => CommandOp::AgentBindingReject,
            BindingRejectionRequest::Get(_) => CommandOp::AgentBindingRejectionGet,
        }
    }
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
enum BindingRejectionRequest {
    Reject(Box<AgentBindingRejectRequest>),
    Get(AgentBindingRejectionReadRequest),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RejectBody {
    scope: ScopeDto,
    issuer_id: Uuid,
    destination_id: Uuid,
    reference: DelegationReferenceDto,
    reservation: ReservationDto,
    activation: ActivationDto,
    reason: RejectionReasonDto,
    observed_at_ms: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GetBody {
    scope: ScopeDto,
    issuer_id: Uuid,
    destination_id: Uuid,
    request_id: Uuid,
    request_digest: String,
    session_id: Uuid,
    principal: PrincipalDto,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DelegationReferenceDto {
    migration_id: Uuid,
    expected_freeze_revision: u64,
    manifest_digest: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReservationDto {
    request_id: Uuid,
    activity_id: Uuid,
    agent_id: Uuid,
    session_id: Uuid,
    principal: PrincipalDto,
    requested_at_ms: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivationDto {
    request_id: Uuid,
    membership_digest: String,
    display_name: String,
    declared_role: String,
    transport: TransportDto,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum TransportDto {
    #[serde(rename = "mcp")]
    Retired,
    Stdio,
    StreamableHttp,
    Other,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RejectionReasonDto {
    PrincipalTransportMismatch,
}

pub(super) fn parse(
    op: CommandOp,
    envelope_request_id: Uuid,
    payload: &Value,
) -> Result<BindingRejectionCommand, ForgeError> {
    if envelope_request_id.is_nil() {
        return Err(ForgeError::invalid_input(
            "transport request identity must be non-nil",
        ));
    }
    match op {
        CommandOp::AgentBindingReject => parse_reject(envelope_request_id, payload),
        CommandOp::AgentBindingRejectionGet => parse_get(envelope_request_id, payload),
        _ => Err(ForgeError::internal()),
    }
}

fn parse_reject(
    envelope_request_id: Uuid,
    payload: &Value,
) -> Result<BindingRejectionCommand, ForgeError> {
    let body: RejectBody = super::parse_body(payload, "agent.binding.reject payload is invalid")?;
    let (scope, issuer_id, destination_id) =
        decode_common(&body.scope, body.issuer_id, body.destination_id)?;
    if body.reservation.request_id != envelope_request_id
        || body.activation.request_id != envelope_request_id
    {
        return Err(ForgeError::invalid_input(
            "binding rejection request_id must match the transport request identity",
        ));
    }
    let reservation = AgentBindingReservationRequest::new(
        envelope_request_id,
        activity_id(body.reservation.activity_id)?,
        agent_id(body.reservation.agent_id)?,
        session_id(body.reservation.session_id)?,
        decode_principal(&body.reservation.principal)?,
        timestamp(body.reservation.requested_at_ms)?,
    )
    .map_err(|_| ForgeError::invalid_input("binding rejection reservation is invalid"))?;
    let activation = AgentBindingActivationRequest::new(
        envelope_request_id,
        digest(&body.activation.membership_digest, "membership digest")?,
        AgentDisplayName::new(body.activation.display_name)
            .map_err(|_| ForgeError::invalid_input("binding rejection display name is invalid"))?,
        AgentDeclaredRole::new(body.activation.declared_role)
            .map_err(|_| ForgeError::invalid_input("binding rejection declared role is invalid"))?,
        transport(body.activation.transport),
    )
    .map_err(|_| ForgeError::invalid_input("binding rejection activation is invalid"))?;
    let reference = body.reference;
    let request = AgentBindingRejectRequest::new(
        scope.clone(),
        require_id(issuer_id.into_uuid(), "issuer id")?,
        require_id(reference.migration_id, "migration id")?,
        destination_id,
        reference.expected_freeze_revision,
        digest(&reference.manifest_digest, "manifest digest")?,
        reservation,
        activation,
        reason(body.reason),
        timestamp(body.observed_at_ms)?,
    );
    let request_digest = request
        .request_digest()
        .map_err(|_| ForgeError::invalid_input("binding rejection intent is invalid"))?;
    Ok(BindingRejectionCommand {
        scope,
        issuer_id,
        destination_id,
        request_digest: Some(request_digest),
        request: BindingRejectionRequest::Reject(Box::new(request)),
    })
}

fn parse_get(
    envelope_request_id: Uuid,
    payload: &Value,
) -> Result<BindingRejectionCommand, ForgeError> {
    let body: GetBody =
        super::parse_body(payload, "agent.binding.rejection_get payload is invalid")?;
    if body.request_id != envelope_request_id {
        return Err(ForgeError::invalid_input(
            "binding rejection request_id must match the transport request identity",
        ));
    }
    let (scope, issuer_id, destination_id) =
        decode_common(&body.scope, body.issuer_id, body.destination_id)?;
    let request = AgentBindingRejectionReadRequest {
        scope: scope.clone(),
        request_id: envelope_request_id,
        request_digest: digest(&body.request_digest, "request digest")?,
        session_id: session_id(body.session_id)?,
        principal: decode_principal(&body.principal)?,
    };
    Ok(BindingRejectionCommand {
        scope,
        issuer_id,
        destination_id,
        request_digest: None,
        request: BindingRejectionRequest::Get(request),
    })
}

pub(super) fn readback_hint(command: &BindingRejectionCommand) -> Option<ReadbackHint> {
    let BindingRejectionRequest::Reject(request) = &command.request else {
        return None;
    };
    let request_digest = command.request_digest?;
    Some(ReadbackHint::AgentBindingRejection {
        workspace_id: command.scope.workspace_id().into_uuid(),
        destination_id: command.destination_id,
        request_id: request.reservation.request_id(),
        request_digest: super::encode_hex(&request_digest),
        session_id: request.reservation.session_id().into_uuid(),
    })
}

pub(super) fn execute(
    client: &ForgeControlClient,
    trusted_issuer: OrchestrationIssuerId,
    trusted_destination: Uuid,
    command: &BindingRejectionCommand,
) -> Result<Value, ForgeError> {
    if command.issuer_id != trusted_issuer || command.destination_id != trusted_destination {
        return Err(ForgeError::auth_failed());
    }
    match &command.request {
        BindingRejectionRequest::Reject(request) => {
            let outcome = client
                .reject_agent_binding(request.as_ref().clone())
                .map_err(|error| super::forge_error_of_client(&error))?;
            match outcome {
                AgentBindingRejectionOperation::Recorded(receipt) => {
                    mutation_projection(command, "recorded", false, &receipt)
                }
                AgentBindingRejectionOperation::Replay(receipt) => {
                    mutation_projection(command, "replay", true, &receipt)
                }
            }
        }
        BindingRejectionRequest::Get(request) => {
            let receipt = client
                .agent_binding_rejection(request.clone())
                .map_err(|error| super::forge_error_of_client(&error))?;
            readback_projection(command, receipt.as_ref())
        }
    }
}

fn mutation_projection(
    command: &BindingRejectionCommand,
    status: &'static str,
    replayed: bool,
    receipt: &AgentBindingRejectionReceipt,
) -> Result<Value, ForgeError> {
    let scope = super::scope_json(&command.scope)?;
    Ok(json!({
        "scope": scope,
        "issuer_id": command.issuer_id.into_uuid(),
        "destination_id": command.destination_id,
        "status": status,
        "replayed": replayed,
        "receipt": receipt_json(receipt),
        "retry_authorized": false,
    }))
}

fn readback_projection(
    command: &BindingRejectionCommand,
    receipt: Option<&AgentBindingRejectionReceipt>,
) -> Result<Value, ForgeError> {
    let scope = super::scope_json(&command.scope)?;
    Ok(json!({
        "scope": scope,
        "issuer_id": command.issuer_id.into_uuid(),
        "destination_id": command.destination_id,
        "found": receipt.is_some(),
        "status": "historical_receipt",
        "receipt": receipt.map(receipt_json),
        "retry_authorized": false,
        "request_equivalence_proven": false,
    }))
}

fn receipt_json(receipt: &AgentBindingRejectionReceipt) -> Value {
    let request = receipt.request();
    json!({
        "request_id": request.request_id(),
        "request_digest": super::encode_hex(&receipt.request_digest()),
        "workspace_id": request.workspace_id().into_uuid(),
        "activity_id": request.activity_id().into_uuid(),
        "agent_id": request.agent_id().into_uuid(),
        "session_id": request.session_id().into_uuid(),
        "principal": principal_json(request.principal()),
        "migration_id": request.migration_id(),
        "destination_id": request.destination_id(),
        "expected_freeze_revision": request.expected_freeze_revision(),
        "manifest_digest": super::encode_hex(&request.manifest_digest()),
        "issuer_id": request.issuer_id(),
        "workspace_root_fingerprint": super::encode_hex(request.workspace_root_fingerprint().as_bytes()),
        "binding_digest": super::encode_hex(&request.binding_digest()),
        "delegation_digest": super::encode_hex(&request.delegation_digest()),
        "membership_digest": super::encode_hex(&request.membership_digest()),
        "display_name": request.display_name().as_str(),
        "declared_role": request.declared_role().as_str(),
        "transport": transport_str(request.transport()),
        "reason": reason_str(request.reason()),
        "reserved_at_ms": request.reserved_at().get(),
        "requested_at_ms": request.requested_at().get(),
        "observed_at_ms": request.observed_at().get(),
        "rejected_at_ms": receipt.rejected_at().get(),
        "receipt_digest": super::encode_hex(&receipt.receipt_digest()),
    })
}

fn decode_common(
    scope: &ScopeDto,
    issuer_id: Uuid,
    destination_id: Uuid,
) -> Result<(ResolvedWorkspaceScope, OrchestrationIssuerId, Uuid), ForgeError> {
    let issuer_id = require_id(issuer_id, "issuer id")?;
    let destination_id = require_id(destination_id, "destination id")?;
    Ok((
        decode_scope(scope)?,
        OrchestrationIssuerId::from_uuid(issuer_id),
        destination_id,
    ))
}

fn require_id(value: Uuid, label: &'static str) -> Result<Uuid, ForgeError> {
    if value.is_nil() {
        return Err(ForgeError::invalid_input(format!(
            "{label} must be non-nil"
        )));
    }
    Ok(value)
}

fn activity_id(value: Uuid) -> Result<ActivityId, ForgeError> {
    Ok(ActivityId::from_uuid(require_id(value, "activity id")?))
}

fn agent_id(value: Uuid) -> Result<AgentInstanceId, ForgeError> {
    Ok(AgentInstanceId::from_uuid(require_id(value, "agent id")?))
}

fn session_id(value: Uuid) -> Result<AgentSessionId, ForgeError> {
    Ok(AgentSessionId::from_uuid(require_id(value, "session id")?))
}

fn timestamp(value: i64) -> Result<TimestampMillis, ForgeError> {
    TimestampMillis::new(value).map_err(|_| ForgeError::invalid_input("timestamp is invalid"))
}

fn digest(value: &str, label: &'static str) -> Result<[u8; DIGEST_BYTES], ForgeError> {
    if value.len() != DIGEST_BYTES * 2
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        || value.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return Err(ForgeError::invalid_input(format!(
            "{label} must be 64 lowercase hexadecimal characters"
        )));
    }
    let mut decoded = [0_u8; DIGEST_BYTES];
    for (index, slot) in decoded.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| ForgeError::invalid_input(format!("{label} is invalid")))?;
    }
    if decoded == [0; DIGEST_BYTES] {
        return Err(ForgeError::invalid_input(format!(
            "{label} must be nonzero"
        )));
    }
    Ok(decoded)
}

const fn transport(value: TransportDto) -> AgentTransportKind {
    match value {
        TransportDto::Retired => AgentTransportKind::Retired,
        TransportDto::Stdio => AgentTransportKind::Stdio,
        TransportDto::StreamableHttp => AgentTransportKind::StreamableHttp,
        TransportDto::Other => AgentTransportKind::Other,
    }
}

const fn reason(value: RejectionReasonDto) -> AgentBindingRejectionReason {
    match value {
        RejectionReasonDto::PrincipalTransportMismatch => {
            AgentBindingRejectionReason::PrincipalTransportMismatch
        }
    }
}

const fn transport_str(value: AgentTransportKind) -> &'static str {
    match value {
        AgentTransportKind::Retired => "mcp",
        AgentTransportKind::Stdio => "stdio",
        AgentTransportKind::StreamableHttp => "streamable_http",
        AgentTransportKind::Other => "other",
    }
}

const fn reason_str(value: AgentBindingRejectionReason) -> &'static str {
    match value {
        AgentBindingRejectionReason::PrincipalTransportMismatch => "principal_transport_mismatch",
    }
}

fn principal_json(value: AuthenticatedPrincipal) -> Value {
    match value {
        AuthenticatedPrincipal::TrustedStdio => json!({
            "kind": "trusted_stdio",
            "token_id": null,
            "grant_id": null,
        }),
        AuthenticatedPrincipal::DirectToken(token_id) => json!({
            "kind": "direct_token",
            "token_id": token_id.into_uuid(),
            "grant_id": null,
        }),
        AuthenticatedPrincipal::OAuthGrant(grant_id) => json!({
            "kind": "oauth_grant",
            "token_id": null,
            "grant_id": grant_id.into_uuid(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use forge_domain::{WorkspaceId, WorkspaceRootFingerprint};

    fn payload() -> Value {
        json!({
            "scope": {
                "workspace_id": Uuid::from_u128(2),
                "workspace_revision": 1,
                "locator": {
                    "location_id": Uuid::from_u128(10),
                    "expected_revision": 1,
                    "relative_root": "."
                }
            },
            "issuer_id": Uuid::from_u128(9),
            "destination_id": Uuid::from_u128(7),
            "reference": {
                "migration_id": Uuid::from_u128(6),
                "expected_freeze_revision": 8,
                "manifest_digest": "11".repeat(32)
            },
            "reservation": {
                "request_id": Uuid::from_u128(1),
                "activity_id": Uuid::from_u128(3),
                "agent_id": Uuid::from_u128(4),
                "session_id": Uuid::from_u128(5),
                "principal": {"kind": "trusted_stdio", "token_id": null, "grant_id": null},
                "requested_at_ms": 20
            },
            "activation": {
                "request_id": Uuid::from_u128(1),
                "membership_digest": "55".repeat(32),
                "display_name": "worker",
                "declared_role": "operator",
                "transport": "other"
            },
            "reason": "principal_transport_mismatch",
            "observed_at_ms": 40
        })
    }

    #[test]
    fn reject_accepts_only_caller_owned_attestation() -> Result<(), ForgeError> {
        let command = parse(
            CommandOp::AgentBindingReject,
            Uuid::from_u128(1),
            &payload(),
        )?;
        assert_eq!(command.op(), CommandOp::AgentBindingReject);
        let mut hostile = payload();
        hostile["reserved_at_ms"] = json!(30);
        assert!(parse(CommandOp::AgentBindingReject, Uuid::from_u128(1), &hostile).is_err());
        Ok(())
    }

    #[test]
    fn reject_and_get_require_exact_transport_identity() {
        assert!(
            parse(
                CommandOp::AgentBindingReject,
                Uuid::from_u128(99),
                &payload()
            )
            .is_err()
        );
        let get = json!({
            "scope": payload()["scope"].clone(),
            "issuer_id": Uuid::from_u128(9),
            "destination_id": Uuid::from_u128(7),
            "request_id": Uuid::from_u128(1),
            "request_digest": "66".repeat(32),
            "session_id": Uuid::from_u128(5),
            "principal": {"kind": "trusted_stdio", "token_id": null, "grant_id": null},
        });
        assert!(
            parse(
                CommandOp::AgentBindingRejectionGet,
                Uuid::from_u128(2),
                &get
            )
            .is_err()
        );
        assert!(
            parse(
                CommandOp::AgentBindingRejectionGet,
                Uuid::from_u128(1),
                &get
            )
            .is_ok()
        );
    }

    #[test]
    fn projections_expose_the_full_receipt_and_explicit_nullable_absence()
    -> Result<(), Box<dyn std::error::Error>> {
        let command = parse(
            CommandOp::AgentBindingReject,
            Uuid::from_u128(1),
            &payload(),
        )?;
        let request = forge_domain::AgentBindingRejectionRequest::new(
            Uuid::from_u128(1),
            WorkspaceId::from_uuid(Uuid::from_u128(2)),
            ActivityId::from_uuid(Uuid::from_u128(3)),
            AgentInstanceId::from_uuid(Uuid::from_u128(4)),
            AgentSessionId::from_uuid(Uuid::from_u128(5)),
            AuthenticatedPrincipal::TrustedStdio,
            Uuid::from_u128(6),
            Uuid::from_u128(7),
            8,
            [0x11; 32],
            Uuid::from_u128(9),
            WorkspaceRootFingerprint::from_bytes([0x22; 16]),
            [0x33; 32],
            [0x44; 32],
            [0x55; 32],
            AgentDisplayName::new("worker".to_owned())?,
            AgentDeclaredRole::new("operator".to_owned())?,
            AgentTransportKind::Other,
            AgentBindingRejectionReason::PrincipalTransportMismatch,
            TimestampMillis::new(30)?,
            TimestampMillis::new(20)?,
            TimestampMillis::new(40)?,
        )?;
        let receipt = AgentBindingRejectionReceipt::from_parts(
            request,
            [0x66; 32],
            TimestampMillis::new(50)?,
            [0x77; 32],
        );
        let found = readback_projection(&command, Some(&receipt))?;
        assert_eq!(found["found"], true);
        assert_eq!(found["receipt"]["reserved_at_ms"], 30);
        assert_eq!(found["receipt"]["requested_at_ms"], 20);
        assert_eq!(found["receipt"]["observed_at_ms"], 40);
        assert_eq!(found["receipt"]["rejected_at_ms"], 50);
        assert_eq!(found["receipt"]["request_digest"], "66".repeat(32));
        assert_eq!(found["receipt"]["receipt_digest"], "77".repeat(32));
        assert_eq!(found["retry_authorized"], false);
        let absent = readback_projection(&command, None)?;
        assert_eq!(absent["found"], false);
        assert!(absent["receipt"].is_null());
        assert_eq!(absent["request_equivalence_proven"], false);
        Ok(())
    }
}
