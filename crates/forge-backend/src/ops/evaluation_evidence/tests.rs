use std::error::Error;

use super::*;
use serde_json::{Value, json};

fn ids() -> (Uuid, Uuid, Uuid, Uuid) {
    (
        Uuid::from_u128(0x10),
        Uuid::from_u128(0x20),
        Uuid::from_u128(0x30),
        Uuid::from_u128(0x40),
    )
}

fn scope_value(workspace_id: Uuid) -> Value {
    json!({
        "workspace_id": workspace_id,
        "workspace_revision": 1,
        "locator": {
            "location_id": Uuid::from_u128(0x11),
            "expected_revision": 1,
            "relative_root": "workspace"
        }
    })
}

fn source_value(backend_id: Uuid, workspace_id: Uuid) -> Value {
    json!({
        "backend_id": backend_id,
        "workspace_id": workspace_id,
        "activity_id": Uuid::from_u128(0x30),
        "delegation_migration_id": Uuid::from_u128(0x40),
        "delegation_destination_id": Uuid::from_u128(0x50),
        "delegation_freeze_revision": 1,
        "delegation_manifest_digest": "11".repeat(32)
    })
}

fn member_value(index: usize) -> Value {
    json!({
        "work_unit_id": Uuid::from_u128(0x100 + index as u128),
        "obligation_id": Uuid::from_u128(0x200 + index as u128),
        "assignment_id": Uuid::from_u128(0x300 + index as u128),
        "assignment_revision": 1,
        "target_agent_id": Uuid::from_u128(0x400 + index as u128),
        "target_session_id": Uuid::from_u128(0x500 + index as u128),
        "criteria_digest": "33".repeat(32)
    })
}

fn proposal_digest(member_count: usize) -> Result<String, Box<dyn Error>> {
    let (backend_id, workspace_id, _, _) = ids();
    let source = EvaluationSourceIdentity::new(
        ForgeBackendId::from_uuid(backend_id),
        WorkspaceId::from_uuid(workspace_id),
        ActivityId::from_uuid(Uuid::from_u128(0x30)),
        Uuid::from_u128(0x40),
        Uuid::from_u128(0x50),
        EvaluationRevision::new(1)?,
        EvaluationDigest::new([0x11; 32])?,
    )?;
    let plan = EvaluationPlanBinding::new(
        EvaluationPlanId::new(Uuid::from_u128(0x61))?,
        EvaluationRevision::new(1)?,
        EvaluationDigest::new([0x22; 32])?,
    );
    let members = (0..member_count)
        .map(|index| -> Result<_, Box<dyn Error>> {
            Ok(EvaluationManifestMember::new(
                EvaluationWorkUnitId::new(Uuid::from_u128(0x100 + index as u128))?,
                EvaluationObligationId::new(Uuid::from_u128(0x200 + index as u128))?,
                AgentAssignmentId::from_uuid(Uuid::from_u128(0x300 + index as u128)),
                AgentAssignmentRevision::new(1)?,
                AgentInstanceId::from_uuid(Uuid::from_u128(0x400 + index as u128)),
                AgentSessionId::from_uuid(Uuid::from_u128(0x500 + index as u128)),
                EvaluationDigest::new([0x33; 32])?,
            )?)
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let proposal = EvaluationManifestProposal::new(
        EvaluationManifestId::new(Uuid::from_u128(0x60))?,
        EvaluationRevision::new(1)?,
        source,
        plan,
        TimestampMillis::new(900)?,
        members,
    )?;
    Ok(crate::events::hex_encode(proposal.digest().as_bytes()))
}

fn seal_payload(member_count: usize) -> Result<Value, Box<dyn Error>> {
    let (backend_id, workspace_id, _, _) = ids();
    let digest =
        if member_count == 0 || member_count > forge_domain::MAX_EVALUATION_MANIFEST_MEMBERS {
            "44".repeat(32)
        } else {
            proposal_digest(member_count)?
        };
    Ok(json!({
        "scope": scope_value(workspace_id),
        "service": {
            "backend_id": backend_id,
            "destination_id": Uuid::from_u128(0x50)
        },
        "proposal": {
            "manifest_id": Uuid::from_u128(0x60),
            "revision": 1,
            "source": source_value(backend_id, workspace_id),
            "plan": {
                "plan_id": Uuid::from_u128(0x61),
                "revision": 1,
                "digest": "22".repeat(32)
            },
            "deadline_ms": 900,
            "digest": digest,
            "members": (0..member_count).map(member_value).collect::<Vec<_>>()
        }
    }))
}

#[test]
fn seal_parser_preserves_target_agent_and_session_binding() -> Result<(), Box<dyn Error>> {
    let (backend_id, workspace_id, _, _) = ids();
    let payload = seal_payload(1)?;
    let parsed = parse(CommandOp::EvaluationManifestSeal, &payload)?;
    assert_eq!(parsed.op(), CommandOp::EvaluationManifestSeal);
    assert!(!parsed.op().requires_session_authority());
    assert_eq!(parsed.request.source.backend_id().into_uuid(), backend_id);
    assert_eq!(
        parsed.request.scope.workspace_id().into_uuid(),
        workspace_id
    );
    let EvaluationEvidenceOperation::SealManifest { proposal } = &parsed.request.operation else {
        return Err("seal route did not carry a manifest proposal".into());
    };
    let member = proposal.members()[0];
    assert_eq!(member.target_agent_id().into_uuid(), Uuid::from_u128(0x400));
    assert_eq!(
        member.target_session_id().into_uuid(),
        Uuid::from_u128(0x500)
    );
    assert_eq!(proposal.deadline().get(), 900);
    Ok(())
}

#[test]
fn seal_parser_rejects_unknown_fields_at_each_boundary() -> Result<(), Box<dyn Error>> {
    let mut payload = seal_payload(1)?;
    payload["unexpected"] = json!(true);
    assert!(parse(CommandOp::EvaluationManifestSeal, &payload).is_err());

    let mut payload = seal_payload(1)?;
    payload["proposal"]["members"][0]["extra"] = json!("hostile");
    assert!(parse(CommandOp::EvaluationManifestSeal, &payload).is_err());

    let mut payload = seal_payload(1)?;
    payload["proposal"]["source"]["observed_at_ms"] = json!(1);
    assert!(parse(CommandOp::EvaluationManifestSeal, &payload).is_err());
    Ok(())
}

#[test]
fn seal_parser_rejects_a_digest_that_does_not_match_the_canonical_proposal()
-> Result<(), Box<dyn Error>> {
    let mut payload = seal_payload(1)?;
    payload["proposal"]["digest"] = json!("aa".repeat(32));
    assert!(parse(CommandOp::EvaluationManifestSeal, &payload).is_err());
    Ok(())
}

#[test]
fn seal_parser_enforces_workspace_binding_and_cohort_bound() -> Result<(), Box<dyn Error>> {
    let (backend_id, workspace_id, _, _) = ids();
    let mut payload = seal_payload(1)?;
    payload["proposal"]["source"]["workspace_id"] = json!(Uuid::from_u128(0x21));
    assert!(parse(CommandOp::EvaluationManifestSeal, &payload).is_err());

    let over_limit = forge_domain::MAX_EVALUATION_MANIFEST_MEMBERS + 1;
    let payload = seal_payload(over_limit)?;
    assert!(parse(CommandOp::EvaluationManifestSeal, &payload).is_err());

    let mut payload = seal_payload(1)?;
    payload["service"]["backend_id"] = json!(Uuid::from_u128(0x99));
    let parsed = parse(CommandOp::EvaluationManifestSeal, &payload)?;
    assert_ne!(parsed.service.backend_id, backend_id);
    assert_eq!(
        parsed.request.source.workspace_id().into_uuid(),
        workspace_id
    );
    Ok(())
}

#[test]
fn configured_backend_and_destination_reject_hostile_service_echoes() -> Result<(), Box<dyn Error>>
{
    let (backend_id, workspace_id, _, _) = ids();
    let payload = seal_payload(1)?;
    let mut command = parse(CommandOp::EvaluationManifestSeal, &payload)?;
    assert!(
        super::validate_service_identity(
            &command,
            ForgeBackendId::from_uuid(backend_id),
            Uuid::from_u128(0x50),
        )
        .is_ok()
    );

    command.service.backend_id = Uuid::from_u128(0x99);
    let backend_result = super::validate_service_identity(
        &command,
        ForgeBackendId::from_uuid(backend_id),
        Uuid::from_u128(0x50),
    );
    let backend_error = match backend_result {
        Ok(()) => return Err("foreign backend echo was accepted".into()),
        Err(error) => error,
    };
    assert_eq!(backend_error.code(), crate::error::ErrorCode::AuthFailed,);
    command.service.backend_id = backend_id;
    command.service.destination_id = Uuid::from_u128(0x98);
    let destination_result = super::validate_service_identity(
        &command,
        ForgeBackendId::from_uuid(backend_id),
        Uuid::from_u128(0x50),
    );
    let destination_error = match destination_result {
        Ok(()) => return Err("foreign destination echo was accepted".into()),
        Err(error) => error,
    };
    assert_eq!(
        destination_error.code(),
        crate::error::ErrorCode::AuthFailed,
    );
    assert_eq!(
        command.request.scope.workspace_id().into_uuid(),
        workspace_id
    );
    Ok(())
}

#[test]
fn t1_readback_body_rejects_caller_clock_fields() {
    let (backend_id, workspace_id, _, _) = ids();
    let mut payload = json!({
        "scope": scope_value(workspace_id),
        "service": {
            "backend_id": backend_id,
            "destination_id": Uuid::from_u128(0x50)
        },
        "source": source_value(backend_id, workspace_id),
        "cut_id": Uuid::from_u128(0x70),
        "manifest_id": Uuid::from_u128(0x60),
        "manifest_revision": 1,
        "manifest_digest": "22".repeat(32),
        "deadline_ms": 900
    });
    assert!(parse(CommandOp::EvaluationT1Get, &payload).is_ok());
    payload["observed_at_ms"] = json!(1);
    assert!(parse(CommandOp::EvaluationT1Get, &payload).is_err());
}

#[test]
fn missing_t1_cut_is_an_explicit_read_status_without_no_effect_claim() -> Result<(), Box<dyn Error>>
{
    let (backend_id, workspace_id, _, _) = ids();
    let payload = json!({
        "scope": scope_value(workspace_id),
        "service": {
            "backend_id": backend_id,
            "destination_id": Uuid::from_u128(0x50)
        },
        "source": source_value(backend_id, workspace_id),
        "cut_id": Uuid::from_u128(0x70),
        "manifest_id": Uuid::from_u128(0x60),
        "manifest_revision": 1,
        "manifest_digest": "22".repeat(32),
        "deadline_ms": 900
    });
    let command = parse(CommandOp::EvaluationT1Get, &payload)?;
    let response = wire::project_response(
        &command,
        forge_control::EvaluationEvidenceResponse::T1Read(None),
    )?;
    assert!(matches!(
        response,
        wire::EvaluationEvidenceResponseWire::T1Read {
            status: wire::EvaluationRecordReadStatus::Missing,
            cut: None,
            ..
        }
    ));
    Ok(())
}

#[test]
fn not_closed_response_preserves_unknown_clock_state() -> Result<(), Box<dyn Error>> {
    let (backend_id, workspace_id, _, _) = ids();
    let payload = json!({
        "scope": scope_value(workspace_id),
        "service": {
            "backend_id": backend_id,
            "destination_id": Uuid::from_u128(0x50)
        },
        "source": source_value(backend_id, workspace_id),
        "cut_id": Uuid::from_u128(0x70),
        "manifest_id": Uuid::from_u128(0x60),
        "manifest_revision": 1,
        "manifest_digest": "22".repeat(32),
        "deadline_ms": 900
    });
    let command = parse(CommandOp::EvaluationT1Close, &payload)?;
    let response = wire::project_response(
        &command,
        forge_control::EvaluationEvidenceResponse::T1Closed(
            forge_persistence::EvaluationT1ClosureOutcome::NotClosed(
                forge_domain::EvaluationAdmissionTiming::Unknown(
                    forge_domain::EvaluationClockUncertainty::Unknown,
                ),
            ),
        ),
    )?;
    assert!(matches!(
        response,
        wire::EvaluationEvidenceResponseWire::T1Closed {
            outcome: wire::EvaluationT1ClosureWire::NotClosed {
                timing: wire::EvaluationAdmissionTimingWire::Unknown {
                    reason: wire::EvaluationClockUncertaintyWire::Unknown,
                },
            },
            ..
        }
    ));
    Ok(())
}
