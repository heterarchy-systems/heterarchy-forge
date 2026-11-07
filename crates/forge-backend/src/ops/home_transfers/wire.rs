use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use forge_control::{
    HomeTransferSourceCommand, HomeTransferSourceOperation, HomeTransferSourceService,
};
use forge_domain::{
    ActivityId, AgentInstanceId, AgentSessionId, ForgeBackendId,
    HomeTransferReservationRetirementGrant, HomeTransferReservationRetirementRequest,
    HomeTransferReservationRetirementRequestDigest, HomeTransferSourceAction,
    HomeTransferSourceBinding, HomeTransferSourceGrant, HomeTransferSourceRequest,
    HomeTransferSourceRequestDigest, HomeTransferSourceScope, HomeTransferSourceSubject,
    HomeTransferSourceWitness, OrchestrationIssuerId, TimestampMillis, WorkspaceId,
    WorkspaceRevision,
};
use forge_persistence::{
    HomeTransferReservationRetirementRecord, HomeTransferReservationRetirementRecordParts,
};

use crate::error::ForgeError;

use super::super::{CommandOp, ScopeDto};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrepareBody {
    scope: ScopeDto,
    service: ServiceBody,
    request: RequestBody,
    grant: GrantBody,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GetBody {
    scope: ScopeDto,
    service: ServiceBody,
    preparation_id: Uuid,
    request_digest: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RetireReservationBody {
    scope: ScopeDto,
    service: ServiceBody,
    request: Value,
    grant: Value,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RetirementGetBody {
    scope: ScopeDto,
    service: ServiceBody,
    preparation_id: Uuid,
    reservation_request_id: Uuid,
    request_digest: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetirementRequestBody {
    scope: SourceScopeBody,
    preparation_id: Uuid,
    source_request_digest: String,
    source_outcome_digest: String,
    reservation_request_id: Uuid,
    request_digest: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetirementGrantBody {
    issuer: Uuid,
    request_digest: String,
    issued_at_ms: i64,
    expires_at_ms: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetirementRecordWire {
    request: Value,
    issuer: Uuid,
    observed_at_ms: i64,
    grant_issued_at_ms: i64,
    grant_expires_at_ms: i64,
    source_inventory_digest: String,
    reservation_digest: String,
    receipt_digest: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ServiceBody {
    issuer: Uuid,
    backend_id: Uuid,
    destination_id: Uuid,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestBody {
    witness: WitnessBody,
    scope: SourceScopeBody,
    subject: SubjectBody,
    sessions: Vec<Uuid>,
    bindings: Vec<BindingBody>,
    request_digest: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WitnessBody {
    preparation_id: Uuid,
    intent_digest: String,
    preparation_digest: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceScopeBody {
    workspace_id: Uuid,
    workspace_revision: i64,
    backend_id: Uuid,
    destination_id: Uuid,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SubjectBody {
    transfer_id: Uuid,
    transfer_generation: u64,
    target_profile_id: Uuid,
    target_participation_id: Uuid,
    source_team_id: Uuid,
    destination_team_id: Uuid,
    source_membership_revision: u64,
    participation_revision: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BindingBody {
    activity_id: Uuid,
    agent_id: Uuid,
    session_id: Uuid,
    principal: super::super::PrincipalDto,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantBody {
    issuer: Uuid,
    action: GrantActionBody,
    request_digest: String,
    issued_at_ms: i64,
    expires_at_ms: i64,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum GrantActionBody {
    Prepare,
    AbortUnstarted,
}

pub(super) fn parse(
    operation: CommandOp,
    payload: &Value,
) -> Result<HomeTransferSourceCommand, ForgeError> {
    match operation {
        CommandOp::HomeTransferSourcePrepare => {
            let body: PrepareBody = super::super::parse_body(
                payload,
                "home_transfer.source_prepare payload is invalid",
            )?;
            decode_prepare(body, HomeTransferSourceAction::Prepare)
        }
        CommandOp::HomeTransferSourceAbortUnstarted => {
            let body: PrepareBody = super::super::parse_body(
                payload,
                "home_transfer.source_abort_unstarted payload is invalid",
            )?;
            decode_prepare(body, HomeTransferSourceAction::AbortUnstarted)
        }
        CommandOp::HomeTransferSourceGet => {
            let body: GetBody =
                super::super::parse_body(payload, "home_transfer.source_get payload is invalid")?;
            let scope = super::super::decode_scope(&body.scope)?;
            let service = decode_service(&body.service)?;
            if body.preparation_id.is_nil() {
                return Err(ForgeError::invalid_input(
                    "Home source preparation id must not be nil",
                ));
            }
            let request_digest = HomeTransferSourceRequestDigest::from_bytes(decode_digest(
                &body.request_digest,
                "request_digest",
            )?);
            Ok(HomeTransferSourceCommand {
                scope,
                service,
                operation: HomeTransferSourceOperation::Get {
                    preparation_id: body.preparation_id,
                    request_digest,
                },
            })
        }
        CommandOp::HomeTransferReservationRetireUnused => {
            let body: RetireReservationBody = super::super::parse_body(
                payload,
                "home_transfer.reservation_retire_unused payload is invalid",
            )?;
            ensure_canonical_body(&body, payload, "reservation retirement mutation")?;
            let scope = super::super::decode_scope(&body.scope)?;
            let service = decode_service(&body.service)?;
            let request = decode_retirement_request_json(&body.request)?;
            let grant = decode_retirement_grant_json(&body.grant)?;
            if request.scope().workspace_id() != scope.workspace_id()
                || request.scope().workspace_revision() != scope.workspace_revision()
                || request.scope().backend_id() != service.backend_id
                || request.scope().destination_id() != service.destination_id
                || grant.issuer() != service.issuer
                || grant.request_digest() != request.request_digest()
            {
                return Err(ForgeError::auth_failed());
            }
            Ok(HomeTransferSourceCommand {
                scope,
                service,
                operation: HomeTransferSourceOperation::RetireUnusedReservation { request, grant },
            })
        }
        CommandOp::HomeTransferReservationRetirementGet => {
            let body: RetirementGetBody = super::super::parse_body(
                payload,
                "home_transfer.reservation_retirement_get payload is invalid",
            )?;
            ensure_canonical_body(&body, payload, "reservation retirement readback")?;
            let scope = super::super::decode_scope(&body.scope)?;
            let service = decode_service(&body.service)?;
            if body.preparation_id.is_nil() || body.reservation_request_id.is_nil() {
                return Err(ForgeError::invalid_input(
                    "Home reservation retirement readback identities must not be nil",
                ));
            }
            let request_digest = HomeTransferReservationRetirementRequestDigest::from_bytes(
                decode_canonical_digest(&body.request_digest, "request_digest")?,
            );
            Ok(HomeTransferSourceCommand {
                scope,
                service,
                operation: HomeTransferSourceOperation::GetReservationRetirement {
                    preparation_id: body.preparation_id,
                    reservation_request_id: body.reservation_request_id,
                    request_digest,
                },
            })
        }
        _ => Err(ForgeError::invalid_input(
            "operation is not a Home-transfer source operation",
        )),
    }
}

/// Decode only the canonical request envelope used inside Home source records.
/// The same closed wire structs and checked domain conversion serve the server
/// parser and the official HTTP client readback decoder.
pub(crate) fn decode_request_json(
    payload: &Value,
) -> Result<HomeTransferSourceRequest, ForgeError> {
    let body: RequestBody =
        super::super::parse_body(payload, "Home source record request is invalid")?;
    decode_request(body)
}

pub(crate) fn retirement_request_json(request: &HomeTransferReservationRetirementRequest) -> Value {
    let scope = request.scope();
    json!({
        "scope": {
            "workspace_id": scope.workspace_id().into_uuid(),
            "workspace_revision": scope.workspace_revision().get(),
            "backend_id": scope.backend_id().into_uuid(),
            "destination_id": scope.destination_id(),
        },
        "preparation_id": request.preparation_id(),
        "source_request_digest": encode_digest(request.source_request_digest().as_bytes()),
        "source_outcome_digest": encode_digest(&request.source_outcome_digest()),
        "reservation_request_id": request.reservation_request_id(),
        "request_digest": encode_digest(request.request_digest().as_bytes()),
    })
}

pub(crate) fn retirement_grant_json(grant: HomeTransferReservationRetirementGrant) -> Value {
    json!({
        "issuer": grant.issuer().into_uuid(),
        "request_digest": encode_digest(grant.request_digest().as_bytes()),
        "issued_at_ms": grant.issued_at().get(),
        "expires_at_ms": grant.expires_at().get(),
    })
}

pub(crate) fn retirement_record_json(record: &HomeTransferReservationRetirementRecord) -> Value {
    json!({
        "request": retirement_request_json(record.request()),
        "issuer": record.issuer().into_uuid(),
        "observed_at_ms": record.observed_at().get(),
        "grant_issued_at_ms": record.grant_issued_at().get(),
        "grant_expires_at_ms": record.grant_expires_at().get(),
        "source_inventory_digest": encode_digest(record.source_inventory_digest()),
        "reservation_digest": encode_digest(record.reservation_digest()),
        "receipt_digest": encode_digest(record.receipt_digest()),
    })
}

pub(crate) fn decode_retirement_request_json(
    payload: &Value,
) -> Result<HomeTransferReservationRetirementRequest, ForgeError> {
    let body: RetirementRequestBody =
        super::super::parse_body(payload, "Home reservation retirement request is invalid")?;
    let request = decode_retirement_request(&body)?;
    if retirement_request_json(&request) != *payload {
        return Err(ForgeError::invalid_input(
            "Home reservation retirement request is not canonical",
        ));
    }
    Ok(request)
}

pub(crate) fn decode_retirement_grant_json(
    payload: &Value,
) -> Result<HomeTransferReservationRetirementGrant, ForgeError> {
    let body: RetirementGrantBody =
        super::super::parse_body(payload, "Home reservation retirement grant is invalid")?;
    let grant = decode_retirement_grant(&body)?;
    if retirement_grant_json(grant) != *payload {
        return Err(ForgeError::invalid_input(
            "Home reservation retirement grant is not canonical",
        ));
    }
    Ok(grant)
}

pub(crate) fn decode_retirement_record_json(
    payload: &Value,
) -> Result<HomeTransferReservationRetirementRecord, ForgeError> {
    if !exact_fields(
        payload,
        &[
            "request",
            "issuer",
            "observed_at_ms",
            "grant_issued_at_ms",
            "grant_expires_at_ms",
            "source_inventory_digest",
            "reservation_digest",
            "receipt_digest",
        ],
    ) {
        return Err(ForgeError::invalid_input(
            "Home reservation retirement record fields are invalid",
        ));
    }
    let wire: RetirementRecordWire = serde_json::from_value(payload.clone())
        .map_err(|_| ForgeError::invalid_input("Home reservation retirement record is invalid"))?;
    let request = decode_retirement_request_json(&wire.request)?;
    let record = HomeTransferReservationRetirementRecord::from_parts(
        &HomeTransferReservationRetirementRecordParts {
            request,
            issuer: OrchestrationIssuerId::from_uuid(wire.issuer),
            observed_at: decode_timestamp(wire.observed_at_ms)?,
            grant_issued_at: decode_timestamp(wire.grant_issued_at_ms)?,
            grant_expires_at: decode_timestamp(wire.grant_expires_at_ms)?,
            source_inventory_digest: decode_canonical_digest(
                &wire.source_inventory_digest,
                "source_inventory_digest",
            )?,
            reservation_digest: decode_canonical_digest(
                &wire.reservation_digest,
                "reservation_digest",
            )?,
            receipt_digest: decode_canonical_digest(&wire.receipt_digest, "receipt_digest")?,
        },
    )
    .map_err(|_| ForgeError::invalid_input("Home reservation retirement record is inconsistent"))?;
    if retirement_record_json(&record) != *payload {
        return Err(ForgeError::invalid_input(
            "Home reservation retirement record is not canonical",
        ));
    }
    Ok(record)
}

fn decode_prepare(
    body: PrepareBody,
    expected_action: HomeTransferSourceAction,
) -> Result<HomeTransferSourceCommand, ForgeError> {
    let scope = super::super::decode_scope(&body.scope)?;
    let service = decode_service(&body.service)?;
    let request = decode_request(body.request)?;
    let grant = decode_grant(&body.grant, expected_action)?;
    if grant.issuer() != service.issuer || grant.request_digest() != request.request_digest() {
        return Err(ForgeError::auth_failed());
    }
    Ok(HomeTransferSourceCommand {
        scope,
        service,
        operation: match expected_action {
            HomeTransferSourceAction::Prepare => {
                HomeTransferSourceOperation::Prepare { request, grant }
            }
            HomeTransferSourceAction::AbortUnstarted => {
                HomeTransferSourceOperation::AbortUnstarted { request, grant }
            }
        },
    })
}

fn decode_service(body: &ServiceBody) -> Result<HomeTransferSourceService, ForgeError> {
    Ok(HomeTransferSourceService {
        issuer: OrchestrationIssuerId::from_uuid(require_non_nil(body.issuer, "issuer")?),
        backend_id: ForgeBackendId::from_uuid(require_non_nil(body.backend_id, "backend_id")?),
        destination_id: require_non_nil(body.destination_id, "destination_id")?,
    })
}

fn decode_request(body: RequestBody) -> Result<HomeTransferSourceRequest, ForgeError> {
    if body.sessions.len() > forge_domain::MAX_HOME_TRANSFER_SOURCE_SESSIONS
        || body.bindings.len() > forge_domain::MAX_HOME_TRANSFER_SOURCE_BINDINGS
    {
        return Err(ForgeError::invalid_input(
            "Home source request exceeds its session or binding bounds",
        ));
    }

    let witness = HomeTransferSourceWitness::new(
        body.witness.preparation_id,
        decode_digest(&body.witness.intent_digest, "intent_digest")?,
        decode_digest(&body.witness.preparation_digest, "preparation_digest")?,
    )
    .map_err(|_| ForgeError::invalid_input("Home source witness is invalid"))?;
    let source_scope = HomeTransferSourceScope::new(
        WorkspaceId::from_uuid(require_non_nil(
            body.scope.workspace_id,
            "request workspace_id",
        )?),
        WorkspaceRevision::new(body.scope.workspace_revision)
            .map_err(|_| ForgeError::invalid_input("Home source workspace revision is invalid"))?,
        ForgeBackendId::from_uuid(require_non_nil(
            body.scope.backend_id,
            "request backend_id",
        )?),
        require_non_nil(body.scope.destination_id, "request destination_id")?,
    )
    .map_err(|_| ForgeError::invalid_input("Home source scope is invalid"))?;
    let subject = HomeTransferSourceSubject::new(
        body.subject.transfer_id,
        body.subject.transfer_generation,
        body.subject.target_profile_id,
        body.subject.target_participation_id,
        body.subject.source_team_id,
        body.subject.destination_team_id,
        body.subject.source_membership_revision,
        body.subject.participation_revision,
    )
    .map_err(|_| ForgeError::invalid_input("Home source subject is invalid"))?;

    let sessions = body
        .sessions
        .into_iter()
        .map(AgentSessionId::from_uuid)
        .collect();
    let bindings = body
        .bindings
        .into_iter()
        .map(|binding| {
            HomeTransferSourceBinding::new(
                ActivityId::from_uuid(binding.activity_id),
                AgentInstanceId::from_uuid(binding.agent_id),
                AgentSessionId::from_uuid(binding.session_id),
                super::super::decode_principal(&binding.principal)?,
            )
            .map_err(|_| ForgeError::invalid_input("Home source binding is invalid"))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let request =
        HomeTransferSourceRequest::new(witness, source_scope, subject, sessions, bindings)
            .map_err(|_| ForgeError::invalid_input("Home source request is invalid"))?;
    let expected_digest = decode_digest(&body.request_digest, "request_digest")?;
    if request.request_digest().as_bytes() != &expected_digest {
        return Err(ForgeError::invalid_input(
            "Home source request digest does not match its canonical fields",
        ));
    }
    Ok(request)
}

fn decode_retirement_request(
    body: &RetirementRequestBody,
) -> Result<HomeTransferReservationRetirementRequest, ForgeError> {
    let scope = decode_source_scope(&body.scope)?;
    let source_request_digest = HomeTransferSourceRequestDigest::from_bytes(
        decode_canonical_digest(&body.source_request_digest, "source_request_digest")?,
    );
    let source_outcome_digest =
        decode_canonical_digest(&body.source_outcome_digest, "source_outcome_digest")?;
    let request = HomeTransferReservationRetirementRequest::new(
        scope,
        body.preparation_id,
        source_request_digest,
        source_outcome_digest,
        body.reservation_request_id,
    )
    .map_err(|_| ForgeError::invalid_input("Home reservation retirement request is invalid"))?;
    let expected_digest = decode_canonical_digest(&body.request_digest, "request_digest")?;
    if request.request_digest().as_bytes() != &expected_digest {
        return Err(ForgeError::invalid_input(
            "Home reservation retirement request digest does not match its canonical fields",
        ));
    }
    Ok(request)
}

fn decode_retirement_grant(
    body: &RetirementGrantBody,
) -> Result<HomeTransferReservationRetirementGrant, ForgeError> {
    HomeTransferReservationRetirementGrant::new(
        OrchestrationIssuerId::from_uuid(require_non_nil(body.issuer, "grant issuer")?),
        HomeTransferReservationRetirementRequestDigest::from_bytes(decode_canonical_digest(
            &body.request_digest,
            "grant request_digest",
        )?),
        decode_timestamp(body.issued_at_ms)?,
        decode_timestamp(body.expires_at_ms)?,
    )
    .map_err(|_| ForgeError::invalid_input("Home reservation retirement grant is invalid"))
}

fn decode_source_scope(body: &SourceScopeBody) -> Result<HomeTransferSourceScope, ForgeError> {
    HomeTransferSourceScope::new(
        WorkspaceId::from_uuid(require_non_nil(body.workspace_id, "request workspace_id")?),
        WorkspaceRevision::new(body.workspace_revision)
            .map_err(|_| ForgeError::invalid_input("Home source workspace revision is invalid"))?,
        ForgeBackendId::from_uuid(require_non_nil(body.backend_id, "request backend_id")?),
        require_non_nil(body.destination_id, "request destination_id")?,
    )
    .map_err(|_| ForgeError::invalid_input("Home source scope is invalid"))
}

fn decode_grant(
    body: &GrantBody,
    expected_action: HomeTransferSourceAction,
) -> Result<HomeTransferSourceGrant, ForgeError> {
    let action = match body.action {
        GrantActionBody::Prepare => HomeTransferSourceAction::Prepare,
        GrantActionBody::AbortUnstarted => HomeTransferSourceAction::AbortUnstarted,
    };
    if action != expected_action {
        return Err(ForgeError::invalid_input(
            "Home source grant action does not match the operation",
        ));
    }
    let issued_at = decode_timestamp(body.issued_at_ms)?;
    let expires_at = decode_timestamp(body.expires_at_ms)?;
    HomeTransferSourceGrant::new(
        OrchestrationIssuerId::from_uuid(require_non_nil(body.issuer, "grant issuer")?),
        action,
        HomeTransferSourceRequestDigest::from_bytes(decode_digest(
            &body.request_digest,
            "grant request_digest",
        )?),
        issued_at,
        expires_at,
    )
    .map_err(|_| ForgeError::invalid_input("Home source grant is invalid"))
}

fn decode_timestamp(value: i64) -> Result<TimestampMillis, ForgeError> {
    TimestampMillis::new(value).map_err(|_| ForgeError::invalid_input("timestamp is invalid"))
}

fn exact_fields(value: &Value, expected: &[&str]) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    object.len() == expected.len() && expected.iter().all(|field| object.contains_key(*field))
}

fn ensure_canonical_body<T>(
    body: &T,
    payload: &Value,
    label: &'static str,
) -> Result<(), ForgeError>
where
    T: Serialize,
{
    let canonical = serde_json::to_value(body).map_err(|_| ForgeError::internal())?;
    if canonical != *payload {
        return Err(ForgeError::invalid_input(format!(
            "Home {label} body is not canonical"
        )));
    }
    Ok(())
}

pub(crate) fn decode_digest(value: &str, label: &'static str) -> Result<[u8; 32], ForgeError> {
    if value.len() != 64 {
        return Err(ForgeError::invalid_input(format!(
            "Home source {label} must be 64 lowercase hexadecimal characters"
        )));
    }
    let bytes = super::super::decode_hex(value)?;
    let digest: [u8; 32] = bytes
        .try_into()
        .map_err(|_| ForgeError::invalid_input(format!("Home source {label} is invalid")))?;
    if digest == [0; 32] {
        return Err(ForgeError::invalid_input(format!(
            "Home source {label} must be nonzero"
        )));
    }
    Ok(digest)
}

fn decode_canonical_digest(value: &str, label: &'static str) -> Result<[u8; 32], ForgeError> {
    let digest = decode_digest(value, label)?;
    if encode_digest(&digest) != value {
        return Err(ForgeError::invalid_input(format!(
            "Home source {label} is not canonical lowercase hexadecimal"
        )));
    }
    Ok(digest)
}

pub(crate) fn encode_digest(bytes: &[u8; 32]) -> String {
    super::super::encode_hex(bytes)
}

fn require_non_nil(value: Uuid, label: &'static str) -> Result<Uuid, ForgeError> {
    if value.is_nil() {
        return Err(ForgeError::invalid_input(format!(
            "Home source {label} must not be nil"
        )));
    }
    Ok(value)
}
