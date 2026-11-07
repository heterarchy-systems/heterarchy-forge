use base64::Engine as _;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use forge_control::HomeTransferSourceService;
use forge_domain::{
    ActivityId, AgentInstanceId, AgentSessionId, AuthenticatedPrincipal, ForgeBackendId,
    HomeTransferReservationRetirementGrant, HomeTransferReservationRetirementRequest,
    HomeTransferSourceAction, HomeTransferSourceBinding, HomeTransferSourceRequest,
    HomeTransferSourceScope, HomeTransferSourceSubject, HomeTransferSourceWitness,
    MAX_HOME_TRANSFER_SOURCE_BINDINGS, MAX_HOME_TRANSFER_SOURCE_SESSIONS, OrchestrationIssuerId,
    TimestampMillis, WorkspaceId, WorkspaceRevision,
};
use forge_persistence::{
    HomeTransferReservationRetirementRecord, HomeTransferReservationRetirementRecordParts,
};

use super::{
    inventory_fields, operation_op, principal_json, readback_hint, request_json,
    request_matches_configured_scope, service_matches_configuration, wire,
};
use crate::ops::{CommandOp, encode_hex};

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

fn id(value: u128) -> Uuid {
    Uuid::from_u128(value)
}

fn source_request() -> TestResult<HomeTransferSourceRequest> {
    let scope = HomeTransferSourceScope::new(
        WorkspaceId::from_uuid(id(1)),
        WorkspaceRevision::new(1)?,
        ForgeBackendId::from_uuid(id(2)),
        id(3),
    )?;
    let subject = HomeTransferSourceSubject::new(id(4), 2, id(5), id(6), id(7), id(8), 9, 10)?;
    let witness = HomeTransferSourceWitness::new(id(9), [0xA1; 32], [0xB2; 32])?;
    let session = AgentSessionId::from_uuid(id(11));
    let binding = HomeTransferSourceBinding::new(
        ActivityId::from_uuid(id(12)),
        AgentInstanceId::from_uuid(id(13)),
        session,
        AuthenticatedPrincipal::TrustedStdio,
    )?;
    Ok(HomeTransferSourceRequest::new(
        witness,
        scope,
        subject,
        vec![session],
        vec![binding],
    )?)
}

fn maximum_request() -> TestResult<HomeTransferSourceRequest> {
    let sessions: Vec<_> = (0..MAX_HOME_TRANSFER_SOURCE_SESSIONS)
        .map(|index| {
            u128::try_from(index).map(|index| AgentSessionId::from_uuid(id(1_000 + index)))
        })
        .collect::<Result<_, _>>()?;
    let bindings: Vec<_> = (0..MAX_HOME_TRANSFER_SOURCE_BINDINGS)
        .map(|index| -> TestResult<_> {
            let index = u128::try_from(index)?;
            let binding = HomeTransferSourceBinding::new(
                ActivityId::from_uuid(id(2_000 + index)),
                AgentInstanceId::from_uuid(id(3_000 + index)),
                sessions[usize::try_from(index)? % sessions.len()],
                AuthenticatedPrincipal::TrustedStdio,
            )?;
            Ok(binding)
        })
        .collect::<TestResult<Vec<_>>>()?;
    Ok(HomeTransferSourceRequest::new(
        HomeTransferSourceWitness::new(id(4_000), [0xA1; 32], [0xB2; 32])?,
        HomeTransferSourceScope::new(
            WorkspaceId::from_uuid(id(1)),
            WorkspaceRevision::new(1)?,
            ForgeBackendId::from_uuid(id(2)),
            id(3),
        )?,
        HomeTransferSourceSubject::new(id(4), 2, id(5), id(6), id(7), id(8), 9, 10)?,
        sessions,
        bindings,
    )?)
}

fn runtime_scope() -> Value {
    json!({
        "workspace_id": id(1),
        "workspace_revision": 8,
        "locator": {
            "location_id": id(20),
            "expected_revision": 3,
            "relative_root": "."
        }
    })
}

fn service_json() -> Value {
    json!({"issuer": id(30), "backend_id": id(2), "destination_id": id(3)})
}

fn source_request_json(request: &HomeTransferSourceRequest) -> Value {
    let witness = request.witness();
    let scope = request.scope();
    let subject = request.subject();
    json!({
        "witness": {
            "preparation_id": witness.preparation_id(),
            "intent_digest": encode_hex(witness.intent_digest()),
            "preparation_digest": encode_hex(witness.preparation_digest()),
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
        "request_digest": encode_hex(request.request_digest().as_bytes()),
    })
}

fn prepare_payload(request: &HomeTransferSourceRequest, action: &str) -> Value {
    let digest = encode_hex(request.request_digest().as_bytes());
    json!({
        "scope": runtime_scope(),
        "service": service_json(),
        "request": source_request_json(request),
        "grant": {
            "issuer": id(30),
            "action": action,
            "request_digest": digest,
            "issued_at_ms": 10,
            "expires_at_ms": 20
        }
    })
}

fn retirement_request(
    source_request: &HomeTransferSourceRequest,
) -> TestResult<HomeTransferReservationRetirementRequest> {
    Ok(HomeTransferReservationRetirementRequest::new(
        HomeTransferSourceScope::new(
            WorkspaceId::from_uuid(id(1)),
            WorkspaceRevision::new(8)?,
            ForgeBackendId::from_uuid(id(2)),
            id(3),
        )?,
        source_request.witness().preparation_id(),
        source_request.request_digest(),
        [0xC3; 32],
        id(13),
    )?)
}

fn retirement_grant(
    request: &HomeTransferReservationRetirementRequest,
) -> TestResult<HomeTransferReservationRetirementGrant> {
    Ok(HomeTransferReservationRetirementGrant::new(
        OrchestrationIssuerId::from_uuid(id(30)),
        request.request_digest(),
        TimestampMillis::new(10)?,
        TimestampMillis::new(20)?,
    )?)
}

fn retirement_payload(
    request: &HomeTransferReservationRetirementRequest,
    grant: HomeTransferReservationRetirementGrant,
) -> Value {
    json!({
        "scope": runtime_scope(),
        "service": service_json(),
        "request": wire::retirement_request_json(request),
        "grant": wire::retirement_grant_json(grant),
    })
}

fn retirement_record(
    request: &HomeTransferReservationRetirementRequest,
) -> TestResult<HomeTransferReservationRetirementRecord> {
    let issuer = OrchestrationIssuerId::from_uuid(id(30));
    let observed_at = TimestampMillis::new(15)?;
    let grant_issued_at = TimestampMillis::new(10)?;
    let grant_expires_at = TimestampMillis::new(20)?;
    let source_inventory_digest = [0xC4; 32];
    let reservation_digest = [0xC5; 32];
    let receipt_digest = retirement_receipt_digest(
        request,
        issuer,
        observed_at,
        grant_issued_at,
        grant_expires_at,
        &source_inventory_digest,
        &reservation_digest,
    );
    Ok(HomeTransferReservationRetirementRecord::from_parts(
        &HomeTransferReservationRetirementRecordParts {
            request: *request,
            issuer,
            observed_at,
            grant_issued_at,
            grant_expires_at,
            source_inventory_digest,
            reservation_digest,
            receipt_digest,
        },
    )?)
}

fn retirement_receipt_digest(
    request: &HomeTransferReservationRetirementRequest,
    issuer: OrchestrationIssuerId,
    observed_at: TimestampMillis,
    grant_issued_at: TimestampMillis,
    grant_expires_at: TimestampMillis,
    source_inventory_digest: &[u8; 32],
    reservation_digest: &[u8; 32],
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"forge.home-transfer.reservation-retirement.receipt.v1\0");
    hash.update([1]);
    let request_digest = request.request_digest();
    let issuer_uuid = issuer.into_uuid();
    let observed_at_bytes = observed_at.get().to_be_bytes();
    let grant_issued_at_bytes = grant_issued_at.get().to_be_bytes();
    let grant_expires_at_bytes = grant_expires_at.get().to_be_bytes();
    let fields: [(u8, u8, &[u8]); 7] = [
        (1, 32, request_digest.as_bytes()),
        (2, 16, issuer_uuid.as_bytes()),
        (3, 8, &observed_at_bytes),
        (4, 8, &grant_issued_at_bytes),
        (5, 8, &grant_expires_at_bytes),
        (6, 32, source_inventory_digest),
        (7, 32, reservation_digest),
    ];
    for (tag, length, value) in fields {
        hash.update([tag, length]);
        hash.update(value);
    }
    hash.finalize().into()
}

#[test]
fn command_names_are_registered_exactly() {
    assert_eq!(
        CommandOp::parse("home_transfer.source_prepare"),
        Some(CommandOp::HomeTransferSourcePrepare)
    );
    assert_eq!(
        CommandOp::parse("home_transfer.source_abort_unstarted"),
        Some(CommandOp::HomeTransferSourceAbortUnstarted)
    );
    assert_eq!(
        CommandOp::parse("home_transfer.source_get"),
        Some(CommandOp::HomeTransferSourceGet)
    );
    assert_eq!(
        CommandOp::parse("home_transfer.reservation_retire_unused"),
        Some(CommandOp::HomeTransferReservationRetireUnused)
    );
    assert_eq!(
        CommandOp::parse("home_transfer.reservation_retirement_get"),
        Some(CommandOp::HomeTransferReservationRetirementGet)
    );
    assert!(!CommandOp::HomeTransferSourcePrepare.requires_session_authority());
    assert!(!CommandOp::HomeTransferSourceAbortUnstarted.requires_session_authority());
    assert!(!CommandOp::HomeTransferSourceGet.requires_session_authority());
    assert!(!CommandOp::HomeTransferReservationRetireUnused.requires_session_authority());
    assert!(!CommandOp::HomeTransferReservationRetirementGet.requires_session_authority());
}

#[test]
fn prepare_parser_accepts_full_canonical_request_and_preserves_historical_source_revision()
-> TestResult<()> {
    let request = source_request()?;
    let payload = prepare_payload(&request, "prepare");
    let command = wire::parse(CommandOp::HomeTransferSourcePrepare, &payload)?;
    assert_eq!(operation_op(&command), CommandOp::HomeTransferSourcePrepare);
    match command.operation {
        forge_control::HomeTransferSourceOperation::Prepare {
            request: decoded,
            grant,
        } => {
            assert_eq!(decoded, request);
            assert_eq!(decoded.scope().workspace_revision().get(), 1);
            assert_eq!(command.scope.workspace_revision().get(), 8);
            assert_eq!(grant.action(), HomeTransferSourceAction::Prepare);
            assert_eq!(grant.request_digest(), decoded.request_digest());
        }
        _ => return Err("Prepare parser returned the wrong operation".into()),
    }
    Ok(())
}

#[test]
fn parser_rejects_unknown_nested_fields_bad_action_and_noncanonical_digest() -> TestResult<()> {
    let request = source_request()?;
    let mut unknown = prepare_payload(&request, "prepare");
    unknown["request"]["subject"]["unexpected"] = json!(true);
    assert!(wire::parse(CommandOp::HomeTransferSourcePrepare, &unknown).is_err());

    let wrong_action = prepare_payload(&request, "prepare");
    assert!(wire::parse(CommandOp::HomeTransferSourceAbortUnstarted, &wrong_action).is_err());

    let mut wrong_digest = prepare_payload(&request, "prepare");
    wrong_digest["request"]["request_digest"] = json!("00".repeat(32));
    assert!(wire::parse(CommandOp::HomeTransferSourcePrepare, &wrong_digest).is_err());
    Ok(())
}

#[test]
fn get_parser_requires_exact_non_nil_readback_identity() -> TestResult<()> {
    let request = source_request()?;
    let good = json!({
        "scope": runtime_scope(),
        "service": service_json(),
        "preparation_id": id(9),
        "request_digest": encode_hex(request.request_digest().as_bytes()),
    });
    let parsed = wire::parse(CommandOp::HomeTransferSourceGet, &good)?;
    assert_eq!(operation_op(&parsed), CommandOp::HomeTransferSourceGet);

    let mut nil_id = good.clone();
    nil_id["preparation_id"] = json!(Uuid::nil());
    assert!(wire::parse(CommandOp::HomeTransferSourceGet, &nil_id).is_err());
    Ok(())
}

#[test]
fn retirement_parser_uses_exact_domain_request_and_separate_grant() -> TestResult<()> {
    let parent = source_request()?;
    let request = retirement_request(&parent)?;
    let grant = retirement_grant(&request)?;
    let payload = retirement_payload(&request, grant);
    let parsed = wire::parse(CommandOp::HomeTransferReservationRetireUnused, &payload)?;
    assert_eq!(
        operation_op(&parsed),
        CommandOp::HomeTransferReservationRetireUnused
    );
    match &parsed.operation {
        forge_control::HomeTransferSourceOperation::RetireUnusedReservation {
            request: decoded,
            grant: decoded_grant,
        } => {
            assert_eq!(decoded, &request);
            assert_eq!(decoded_grant, &grant);
            assert_eq!(decoded.scope().workspace_revision().get(), 8);
            assert_eq!(decoded.preparation_id(), id(9));
            assert_eq!(decoded.reservation_request_id(), id(13));
        }
        _ => return Err("retirement parser returned the wrong operation".into()),
    }

    match readback_hint(&parsed) {
        Some(crate::error::ReadbackHint::HomeTransferReservationRetirement {
            scope,
            issuer,
            backend_id,
            destination_id,
            preparation_id,
            reservation_request_id,
            request_digest,
        }) => {
            assert_eq!(scope.workspace_revision, 8);
            assert_eq!(scope.locator.location_id, id(20));
            assert_eq!(scope.locator.expected_revision, 3);
            assert_eq!(scope.locator.relative_root, ".");
            assert_eq!(issuer, id(30));
            assert_eq!(backend_id, id(2));
            assert_eq!(destination_id, id(3));
            assert_eq!(preparation_id, id(9));
            assert_eq!(reservation_request_id, id(13));
            assert_eq!(
                request_digest,
                encode_hex(request.request_digest().as_bytes())
            );
        }
        _ => return Err("retirement mutation omitted its exact readback hint".into()),
    }
    Ok(())
}

#[test]
fn retirement_readback_parser_requires_the_full_business_key_and_digest() -> TestResult<()> {
    let source = source_request()?;
    let request = retirement_request(&source)?;
    let good = json!({
        "scope": runtime_scope(),
        "service": service_json(),
        "preparation_id": request.preparation_id(),
        "reservation_request_id": request.reservation_request_id(),
        "request_digest": encode_hex(request.request_digest().as_bytes()),
    });
    let parsed = wire::parse(CommandOp::HomeTransferReservationRetirementGet, &good)?;
    assert_eq!(
        operation_op(&parsed),
        CommandOp::HomeTransferReservationRetirementGet
    );
    match &parsed.operation {
        forge_control::HomeTransferSourceOperation::GetReservationRetirement {
            preparation_id,
            reservation_request_id,
            request_digest,
        } => {
            assert_eq!(*preparation_id, request.preparation_id());
            assert_eq!(*reservation_request_id, request.reservation_request_id());
            assert_eq!(*request_digest, request.request_digest());
        }
        _ => return Err("retirement Get parser returned the wrong operation".into()),
    }

    let mut nil_reservation = good.clone();
    nil_reservation["reservation_request_id"] = json!(Uuid::nil());
    assert!(
        wire::parse(
            CommandOp::HomeTransferReservationRetirementGet,
            &nil_reservation
        )
        .is_err()
    );
    let mut extra = good.clone();
    extra["unexpected"] = json!(true);
    assert!(wire::parse(CommandOp::HomeTransferReservationRetirementGet, &extra).is_err());
    let mut uppercase = good;
    uppercase["request_digest"] =
        json!(encode_hex(request.request_digest().as_bytes()).to_uppercase());
    assert!(wire::parse(CommandOp::HomeTransferReservationRetirementGet, &uppercase).is_err());
    Ok(())
}

#[test]
fn retirement_request_grant_and_record_json_are_canonical_and_checked() -> TestResult<()> {
    let parent = source_request()?;
    let request = retirement_request(&parent)?;
    let grant = retirement_grant(&request)?;
    let payload = retirement_payload(&request, grant);
    let decoded = wire::parse(CommandOp::HomeTransferReservationRetireUnused, &payload)?;
    assert_eq!(
        decoded.operation,
        forge_control::HomeTransferSourceOperation::RetireUnusedReservation { request, grant }
    );

    let mut unknown_request = payload.clone();
    unknown_request["request"]["extra"] = json!("not allowed");
    assert!(
        wire::parse(
            CommandOp::HomeTransferReservationRetireUnused,
            &unknown_request
        )
        .is_err()
    );
    let mut uppercase_grant = payload.clone();
    uppercase_grant["grant"]["request_digest"] =
        json!(encode_hex(grant.request_digest().as_bytes()).to_uppercase());
    assert!(
        wire::parse(
            CommandOp::HomeTransferReservationRetireUnused,
            &uppercase_grant
        )
        .is_err()
    );
    let mut bad_digest = payload;
    bad_digest["request"]["request_digest"] = json!("dd".repeat(32));
    assert!(wire::parse(CommandOp::HomeTransferReservationRetireUnused, &bad_digest).is_err());

    let record = retirement_record(&request)?;
    let record_json = wire::retirement_record_json(&record);
    assert_eq!(wire::decode_retirement_record_json(&record_json)?, record);
    let mut extra_record = record_json.clone();
    extra_record["unexpected"] = json!(true);
    assert!(wire::decode_retirement_record_json(&extra_record).is_err());
    let mut noncanonical_record = record_json.clone();
    noncanonical_record["source_inventory_digest"] = json!("C4".repeat(32));
    assert!(wire::decode_retirement_record_json(&noncanonical_record).is_err());
    let mut damaged_receipt = record_json;
    damaged_receipt["receipt_digest"] = json!("e4".repeat(32));
    assert!(wire::decode_retirement_record_json(&damaged_receipt).is_err());
    Ok(())
}

#[test]
fn configured_service_scope_is_checked_without_session_admission() -> TestResult<()> {
    let request = source_request()?;
    let service = HomeTransferSourceService {
        issuer: OrchestrationIssuerId::from_uuid(id(30)),
        backend_id: ForgeBackendId::from_uuid(id(2)),
        destination_id: id(3),
    };
    assert!(service_matches_configuration(
        service,
        service.issuer,
        service.backend_id,
        service.destination_id,
    ));
    assert!(!service_matches_configuration(
        service,
        OrchestrationIssuerId::from_uuid(id(31)),
        service.backend_id,
        service.destination_id,
    ));
    assert!(request_matches_configured_scope(
        &request,
        WorkspaceId::from_uuid(id(1)),
        service.backend_id,
        service.destination_id,
    ));
    assert!(!request_matches_configured_scope(
        &request,
        WorkspaceId::from_uuid(id(32)),
        service.backend_id,
        service.destination_id,
    ));
    Ok(())
}

#[test]
fn output_preserves_request_and_encodes_maximum_inventory_as_unpadded_url_safe_base64()
-> TestResult<()> {
    let request = maximum_request()?;
    let projected = request_json(&request);
    assert_eq!(
        projected["request_digest"],
        encode_hex(request.request_digest().as_bytes())
    );
    assert_eq!(projected["witness"]["preparation_id"], json!(id(4_000)));
    assert_eq!(projected["scope"]["workspace_revision"], 1);
    assert_eq!(
        projected["bindings"][0]["principal"]["kind"],
        "trusted_stdio"
    );
    assert_eq!(
        projected["bindings"].as_array().map(Vec::len),
        Some(MAX_HOME_TRANSFER_SOURCE_BINDINGS)
    );
    assert_eq!(
        projected["sessions"].as_array().map(Vec::len),
        Some(MAX_HOME_TRANSFER_SOURCE_SESSIONS)
    );

    let bytes = vec![0xA5; 512 * 1024];
    let digest = [0xCD; 32];
    let (encoded, encoded_digest) = inventory_fields(Some(&bytes), Some(&digest));
    let encoded = encoded.ok_or("inventory payload was omitted")?;
    assert_eq!(encoded.len(), (bytes.len() * 4).div_ceil(3));
    assert!(!encoded.contains('='));
    assert!(!encoded.contains('+'));
    assert!(!encoded.contains('/'));
    assert_eq!(
        base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(encoded)?,
        bytes
    );
    assert_eq!(encoded_digest, Some("cd".repeat(32)));

    let response = json!({"record": {
        "request": projected,
        "request_digest": encode_hex(request.request_digest().as_bytes()),
        "issuer": id(30),
        "state": "prepared",
        "observed_at_ms": 20,
        "grant_issued_at_ms": 10,
        "grant_expires_at_ms": 30,
        "delegation_witness": {
            "migration_id": id(40),
            "freeze_revision": 2,
            "delegation_digest": "11".repeat(32),
        },
        "inventory_payload_base64": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes),
        "inventory_digest": "cd".repeat(32),
        "outcome_digest": "22".repeat(32),
    }});
    assert!(serde_json::to_vec(&response)?.len() <= crate::client::MAX_CLIENT_RESPONSE_BYTES);

    let small_request = source_request()?;
    let abort = prepare_payload(&small_request, "abort_unstarted");
    let abort = wire::parse(CommandOp::HomeTransferSourceAbortUnstarted, &abort)?;
    match readback_hint(&abort) {
        Some(crate::error::ReadbackHint::HomeTransferSource {
            workspace_id,
            preparation_id,
            request_digest,
        }) => {
            assert_eq!(workspace_id, id(1));
            assert_eq!(preparation_id, id(9));
            assert_eq!(
                request_digest,
                encode_hex(small_request.request_digest().as_bytes())
            );
        }
        _ => return Err("source mutation omitted its exact readback hint".into()),
    }
    Ok(())
}
