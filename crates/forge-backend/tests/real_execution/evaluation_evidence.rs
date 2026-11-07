//! Real loopback HTTP proof for Forge-owned evaluation source evidence.
//!
//! Native fixture APIs create the Workspace, delegation, attached Agents and
//! pending assignment nodes. A separate native source-clock seed establishes
//! one T1-eligible receipt; the tested source mutations and readbacks cross the
//! configured Forge HTTP boundary. No execution/provider is started.

use super::binding_lifecycle::HttpBindingFixture;
use super::lease_readback::{post_ok, scope_json};
use super::*;
use forge_backend::ops::evaluation_evidence::wire as evaluation_wire;
use forge_control::{
    AgentAssignmentMutation, AgentAssignmentMutationRequest, AgentBindingActivateRequest,
    AgentBindingReserveRequest, AgentOperationsDelegationReadRequest, CoordinatorActorRequest,
    EvaluationEvidenceOperation, EvaluationEvidenceRequest,
};
use forge_domain::{
    ActivityCoordinatorActor, AgentAssignmentId, AgentAssignmentRevision, AgentAssignmentTarget,
    AgentInstanceId, AgentInstanceRevision, AgentSessionId, EvaluationClockReading,
    EvaluationCutId, EvaluationDigest, EvaluationManifestId, EvaluationManifestMember,
    EvaluationManifestProposal, EvaluationObligationId, EvaluationPlanBinding, EvaluationPlanId,
    EvaluationReviewCutId, EvaluationRevision, EvaluationSourceIdentity, EvaluationT1CloseRequest,
    EvaluationWorkUnitId, ForgeBackendId, TimestampMillis,
};
use forge_persistence::{
    AgentBindingActivationRequest, AgentBindingReservationRequest, AgentOperationsDelegation,
    DagNodeEvidenceScope,
};
use serde_json::{Value, json};
use tokio::time::timeout;

#[derive(Clone)]
struct PreparedEvidence {
    delegation: AgentOperationsDelegation,
    source: EvaluationSourceIdentity,
    proposal: EvaluationManifestProposal,
    assignment_id: AgentAssignmentId,
    target_agent_id: AgentInstanceId,
    target_session_id: AgentSessionId,
    target_revision: AgentInstanceRevision,
    coordinator: ActivityCoordinatorActor,
    assignment_observed_at: TimestampMillis,
}

struct OfferedEvaluationAssignment {
    assignment_id: AgentAssignmentId,
    revision: AgentAssignmentRevision,
    target_agent_id: AgentInstanceId,
    target_session_id: AgentSessionId,
    target_revision: AgentInstanceRevision,
    coordinator: ActivityCoordinatorActor,
    observed_at: TimestampMillis,
}

struct NativeT1Original {
    source: EvaluationSourceIdentity,
    proposal: EvaluationManifestProposal,
    assignment_id: AgentAssignmentId,
    target: AgentAssignmentTarget,
    offered_revision: AgentAssignmentRevision,
    observed_at: TimestampMillis,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_http_evaluation_source_round_trip_uses_trusted_receipts_and_readbacks()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = prepare_fixture()?;
    let prepared = prepare_evidence(&fixture)?;
    seed_native_t1_eligible_original(&fixture, prepared.source, &prepared.delegation)?;
    let product_cache_root = fixture.root.join("product-cache");
    fs::create_dir_all(&product_cache_root)?;
    let destination_id = prepared.delegation.destination_id();
    let state = assemble_fixture(
        backend_config()?,
        &fixture,
        &product_cache_root,
        destination_id,
    )?;
    let address = serve(state.clone()).await?;

    let exercise = exercise_source_api(address, &fixture, &prepared).await;
    let shutdown = state.shutdown(Duration::from_secs(5)).await;
    let fixture_shutdown = fixture.shutdown();
    if !shutdown.is_successful() {
        return Err(format!("evaluation HTTP server shutdown was incomplete: {shutdown:?}").into());
    }
    exercise?;
    fixture_shutdown?;
    Ok(())
}

struct ManifestPhase {
    get_request: EvaluationEvidenceRequest,
    first_read: evaluation_wire::EvaluationEvidenceResponseWire,
    original_binding_digest: String,
}

struct SubmissionPhase {
    revision: i64,
    expected_review_revision: i64,
}

struct ClaimedSubmission {
    assignment: i64,
    expected_submission: AgentAssignmentRevision,
    target: AgentInstanceRevision,
}

struct SubmissionReceiptPhase {
    revision: i64,
    expected_review_revision: i64,
    request: EvaluationEvidenceRequest,
    readback: evaluation_wire::EvaluationEvidenceResponseWire,
}

struct T1Phase {
    cut_id: EvaluationCutId,
    cut: evaluation_wire::EvaluationT1CoverageCutWire,
}

struct ReviewReceiptPhase {
    request: EvaluationEvidenceRequest,
    readback: evaluation_wire::EvaluationEvidenceResponseWire,
    receipt: evaluation_wire::EvaluationReviewReceiptWire,
}

async fn exercise_source_api(
    address: SocketAddr,
    fixture: &Fixture,
    prepared: &PreparedEvidence,
) -> Result<(), Box<dyn std::error::Error>> {
    let http = evidence_client(
        address,
        prepared.delegation.destination_id(),
        Duration::from_secs(5),
    )?;
    let manifest = exercise_manifest_phase(address, fixture, prepared, &http).await?;
    let submission = submit_assignment_over_http(address, fixture, prepared, &http).await?;
    let receipt = read_submission_receipt(fixture, prepared, &http, &manifest, &submission).await?;
    let t1 = close_past_t1(fixture, prepared, &http, &receipt).await?;
    exercise_review_phase(address, fixture, prepared, &http, &manifest, &receipt, &t1).await?;
    exercise_maximum_manifest_http(fixture, prepared, &http).await
}

async fn exercise_maximum_manifest_http(
    fixture: &Fixture,
    prepared: &PreparedEvidence,
    http: &forge_backend::ForgeHttpClient,
) -> Result<(), Box<dyn std::error::Error>> {
    const GENERIC_REQUEST_LIMIT: usize = 64 * 1024;
    const MANIFEST_REQUEST_LIMIT: usize = 128 * 1024;

    let transport_source = maximum_transport_source(prepared.source)?;
    let proposal = maximum_cohort_proposal(
        transport_source,
        prepared.target_agent_id,
        prepared.target_session_id,
    )?;
    assert_eq!(proposal.members().len(), 256);
    let escaped_scope = maximum_escaped_scope(&fixture.scope)?;
    let escaped_body_bytes = serialized_manifest_body_bytes(
        &escaped_scope,
        &proposal,
        prepared.delegation.destination_id(),
    )?;
    assert_eq!(
        escaped_body_bytes, 112_139,
        "256-member body with the maximum JSON-escaped locator"
    );
    assert!(escaped_body_bytes > GENERIC_REQUEST_LIMIT);
    assert!(escaped_body_bytes <= MANIFEST_REQUEST_LIMIT);
    assert!(escaped_body_bytes <= forge_backend::config::MAX_BODY_BYTES);

    let request = EvaluationEvidenceRequest::new(
        escaped_scope,
        transport_source,
        EvaluationEvidenceOperation::SealManifest {
            proposal: proposal.clone(),
        },
    );
    // The maximum-width source revision and stale, constructor-valid locator
    // are transport stress values. This request must stop at the scope guard;
    // it is not a successful source seal or proof of a live 256-member cohort.
    let error = match http.seal_evaluation_manifest(&request).await {
        Ok(response) => {
            return Err(format!("maximum cohort unexpectedly sealed: {response:?}").into());
        }
        Err(error) => error,
    };
    assert!(!error.is_unknown_outcome());
    assert_eq!(error.request(), &request);
    match error.cause() {
        forge_backend::ForgeHttpClientError::Service { status, code } => {
            assert_eq!(*status, 409);
            assert_eq!(
                *code,
                forge_backend::ForgeHttpServiceCode::StaleRevision,
                "the maximum body reached the configured Workspace revision guard"
            );
        }
        cause => {
            return Err(
                format!("maximum manifest did not reach the HTTP scope guard: {cause:?}").into(),
            );
        }
    }

    let read_request = EvaluationEvidenceRequest::new(
        fixture.scope.clone(),
        prepared.source,
        EvaluationEvidenceOperation::GetManifest {
            manifest_id: proposal.manifest_id(),
            revision: proposal.revision(),
            digest: proposal.digest(),
        },
    );
    assert!(matches!(
        http.get_evaluation_manifest(&read_request).await?,
        evaluation_wire::EvaluationEvidenceResponseWire::ManifestRead {
            status: evaluation_wire::EvaluationRecordReadStatus::Missing,
            manifest: None,
            ..
        }
    ));
    Ok(())
}

fn maximum_transport_source(
    source: EvaluationSourceIdentity,
) -> Result<EvaluationSourceIdentity, Box<dyn std::error::Error>> {
    Ok(EvaluationSourceIdentity::new(
        source.backend_id(),
        source.workspace_id(),
        source.activity_id(),
        source.delegation_migration_id(),
        source.delegation_destination_id(),
        EvaluationRevision::new(i64::MAX)?,
        source.delegation_manifest_digest(),
    )?)
}

fn maximum_cohort_proposal(
    source: EvaluationSourceIdentity,
    target_agent_id: AgentInstanceId,
    target_session_id: AgentSessionId,
) -> Result<EvaluationManifestProposal, Box<dyn std::error::Error>> {
    let assignment_revision = AgentAssignmentRevision::new(i64::MAX)?;
    let criteria_digest = EvaluationDigest::new([0xD4; 32])?;
    let members = (0..forge_domain::MAX_EVALUATION_MANIFEST_MEMBERS)
        .map(
            |index| -> Result<EvaluationManifestMember, Box<dyn std::error::Error>> {
                let index = u128::try_from(index)?;
                Ok(EvaluationManifestMember::new(
                    EvaluationWorkUnitId::new(Uuid::from_u128(0xA000 + index))?,
                    EvaluationObligationId::new(Uuid::from_u128(0xB000 + index))?,
                    AgentAssignmentId::from_uuid(Uuid::from_u128(0xC000 + index)),
                    assignment_revision,
                    target_agent_id,
                    target_session_id,
                    criteria_digest,
                )?)
            },
        )
        .collect::<Result<Vec<_>, _>>()?;
    Ok(EvaluationManifestProposal::new(
        EvaluationManifestId::new(Uuid::now_v7())?,
        EvaluationRevision::new(i64::MAX)?,
        source,
        EvaluationPlanBinding::new(
            EvaluationPlanId::new(Uuid::now_v7())?,
            EvaluationRevision::new(i64::MAX)?,
            EvaluationDigest::new([0xE3; 32])?,
        ),
        TimestampMillis::new(i64::MAX)?,
        members,
    )?)
}

fn maximum_escaped_scope(
    current: &ResolvedWorkspaceScope,
) -> Result<ResolvedWorkspaceScope, Box<dyn std::error::Error>> {
    let escaped_relative_root = "\u{1}".repeat(1_024);
    let locator = forge_workspace::WorkspaceLocator::new(
        current.locator().location_id(),
        forge_domain::LocationRevision::new(i64::MAX)?,
        Path::new(&escaped_relative_root),
    )?;
    Ok(ResolvedWorkspaceScope::from_observation(
        current.workspace_id(),
        forge_domain::WorkspaceRevision::new(i64::MAX)?,
        locator,
    ))
}

fn serialized_manifest_body_bytes(
    scope: &ResolvedWorkspaceScope,
    proposal: &EvaluationManifestProposal,
    destination_id: Uuid,
) -> Result<usize, Box<dyn std::error::Error>> {
    let payload = json!({
        "scope": scope_value(scope),
        "service": {
            "backend_id": BACKEND_ID,
            "destination_id": destination_id,
        },
        "proposal": proposal_json(proposal),
    });
    let envelope = json!({
        "forge_api": 1,
        "request_id": Uuid::from_u128(0xF001),
        "op": "evaluation.manifest.seal",
        "payload": payload,
    });
    Ok(serde_json::to_vec(&envelope)?.len())
}

fn scope_value(scope: &ResolvedWorkspaceScope) -> Value {
    json!({
        "workspace_id": scope.workspace_id().into_uuid(),
        "workspace_revision": scope.workspace_revision().get(),
        "locator": {
            "location_id": scope.locator().location_id().into_uuid(),
            "expected_revision": scope.locator().expected_revision().get(),
            "relative_root": scope.locator().relative_root().to_string_lossy(),
        }
    })
}

async fn exercise_manifest_phase(
    address: SocketAddr,
    fixture: &Fixture,
    prepared: &PreparedEvidence,
    http: &forge_backend::ForgeHttpClient,
) -> Result<ManifestPhase, Box<dyn std::error::Error>> {
    let seal_request = seal_request(fixture, prepared);
    let get_request = manifest_get_request(fixture, prepared);
    assert!(matches!(
        http.get_evaluation_manifest(&get_request).await?,
        evaluation_wire::EvaluationEvidenceResponseWire::ManifestRead {
            status: evaluation_wire::EvaluationRecordReadStatus::Missing,
            manifest: None,
            ..
        }
    ));
    let seal_response = http
        .seal_evaluation_manifest(&seal_request)
        .await
        .map_err(|error| {
            std::io::Error::other(format!("evaluation manifest seal failed: {error:?}"))
        })?;
    let manifest = match &seal_response {
        evaluation_wire::EvaluationEvidenceResponseWire::ManifestSealed { source, manifest } => {
            assert_source_identity(source, prepared.source);
            manifest
        }
        response => return Err(format!("unexpected manifest seal response: {response:?}").into()),
    };
    assert_manifest_matches_proposal(manifest, &prepared.proposal)?;
    let original_binding_digest = match &manifest.members[0].binding {
        evaluation_wire::EvaluationOriginalBindingWire::Bound { digest, .. } => digest.clone(),
        evaluation_wire::EvaluationOriginalBindingWire::UnknownHistorical => {
            return Err("fresh HTTP manifest did not retain its exact original binding".into());
        }
    };
    let first_read = http.get_evaluation_manifest(&get_request).await?;
    assert!(matches!(
        &first_read,
        evaluation_wire::EvaluationEvidenceResponseWire::ManifestRead {
            status: evaluation_wire::EvaluationRecordReadStatus::Found,
            manifest: Some(observed),
            ..
        } if observed == manifest
    ));
    assert_configured_identity_rejections(address, fixture, prepared).await?;
    Ok(ManifestPhase {
        get_request,
        first_read,
        original_binding_digest,
    })
}

async fn submit_assignment_over_http(
    address: SocketAddr,
    fixture: &Fixture,
    prepared: &PreparedEvidence,
    http: &forge_backend::ForgeHttpClient,
) -> Result<SubmissionPhase, Box<dyn std::error::Error>> {
    let claimed = claim_assignment_for_submission(fixture, prepared, http).await?;
    let observed_at = prepared.assignment_observed_at;
    assert_eq!(observed_at, prepared.proposal.deadline());
    assert!(
        timestamp_now()?.get() > prepared.proposal.deadline().get(),
        "fixture source clock did not pass the frozen T1 before submission"
    );
    let submitted = post_ok(
        address,
        "agent.assignment.mutate",
        json!({
            "scope": scope_json(fixture),
            "activity_id": fixture.activity_id.into_uuid(),
            "assignment_id": prepared.assignment_id.into_uuid(),
            "observed_at_ms": observed_at.get(),
            "action": {
                "kind": "submit",
                "target": target_json(
                    prepared.target_agent_id,
                    prepared.target_session_id,
                    claimed.target,
                ),
                "expected_assignment_revision": claimed.assignment,
                "report": "source receipt submitted through configured Forge HTTP",
                "sources": [],
            }
        }),
    )
    .await?;
    assert_eq!(submitted["assignment"]["state"], "submitted");
    assert_eq!(
        submitted["assignment"]["assignment_id"],
        prepared.assignment_id.into_uuid().to_string()
    );
    let revision = assignment_revision(&submitted["assignment"])?;
    assert_eq!(revision, claimed.expected_submission.get());
    let expected_review_revision = revision
        .checked_add(1)
        .ok_or("expected review revision overflow")?;
    assert!(matches!(
        http.get_evaluation_review_receipt(&review_receipt_request(
            fixture,
            prepared,
            revision,
            expected_review_revision,
        )?)
        .await?,
        evaluation_wire::EvaluationEvidenceResponseWire::ReviewReceiptRead {
            status: evaluation_wire::EvaluationRecordReadStatus::Missing,
            receipt: None,
            ..
        }
    ));
    Ok(SubmissionPhase {
        revision,
        expected_review_revision,
    })
}

async fn claim_assignment_for_submission(
    fixture: &Fixture,
    prepared: &PreparedEvidence,
    http: &forge_backend::ForgeHttpClient,
) -> Result<ClaimedSubmission, Box<dyn std::error::Error>> {
    let claim_target = AgentAssignmentTarget::new(
        prepared.target_agent_id,
        prepared.target_session_id,
        AuthenticatedPrincipal::TrustedStdio,
        prepared.target_revision,
    );
    let claimed = fixture
        .client
        .agent_assignment_mutate(AgentAssignmentMutationRequest {
            scope: fixture.scope.clone(),
            mutation: AgentAssignmentMutation::Claim(forge_domain::ClaimAgentAssignment::new(
                prepared.assignment_id,
                claim_target,
                prepared.proposal.members()[0].assignment_revision(),
                prepared.assignment_observed_at,
            )),
        })?;
    assert_eq!(claimed.state(), forge_domain::AgentAssignmentState::Running);
    let expected_submission_revision = AgentAssignmentRevision::new(
        claimed
            .revision()
            .get()
            .checked_add(1)
            .ok_or("expected submission revision overflow")?,
    )?;
    assert!(matches!(
        http.get_evaluation_submission_receipt(&submission_receipt_request(
            fixture,
            prepared,
            expected_submission_revision.get(),
        )?)
        .await?,
        evaluation_wire::EvaluationEvidenceResponseWire::SubmissionReceiptRead {
            status: evaluation_wire::EvaluationRecordReadStatus::Missing,
            receipt: None,
            ..
        }
    ));
    Ok(ClaimedSubmission {
        assignment: claimed.revision().get(),
        expected_submission: expected_submission_revision,
        target: current_agent_revision(fixture, prepared.target_agent_id)?,
    })
}

async fn read_submission_receipt(
    fixture: &Fixture,
    prepared: &PreparedEvidence,
    http: &forge_backend::ForgeHttpClient,
    manifest: &ManifestPhase,
    submission: &SubmissionPhase,
) -> Result<SubmissionReceiptPhase, Box<dyn std::error::Error>> {
    let request = submission_receipt_request(fixture, prepared, submission.revision)?;
    let readback = http.get_evaluation_submission_receipt(&request).await?;
    let receipt = match &readback {
        evaluation_wire::EvaluationEvidenceResponseWire::SubmissionReceiptRead {
            status: evaluation_wire::EvaluationRecordReadStatus::Found,
            receipt: Some(receipt),
            source,
        } => {
            assert_source_identity(source, prepared.source);
            receipt.clone()
        }
        response => return Err(format!("submission receipt readback failed: {response:?}").into()),
    };
    assert_eq!(receipt.assignment_id, prepared.assignment_id.into_uuid());
    assert_eq!(receipt.submitted_revision, submission.revision);
    assert_eq!(
        receipt.author_agent_id,
        prepared.target_agent_id.into_uuid()
    );
    assert_eq!(
        receipt.author_session_id,
        prepared.target_session_id.into_uuid()
    );
    assert_eq!(
        receipt.original_binding_digest.as_deref(),
        Some(manifest.original_binding_digest.as_str())
    );
    assert_eq!(
        receipt.criteria_digest.as_deref(),
        Some(digest_hex(&prepared.proposal.members()[0].criteria_digest()).as_str())
    );
    let trusted_admission = match &receipt.timing {
        evaluation_wire::EvaluationAdmissionTimingWire::Trusted { observed_at_ms } => {
            *observed_at_ms
        }
        timing @ evaluation_wire::EvaluationAdmissionTimingWire::Unknown { .. } => {
            return Err(format!("submission timing was unknown: {timing:?}").into());
        }
    };
    assert!(
        trusted_admission > prepared.assignment_observed_at.get(),
        "the source receipt used the backdated descriptive assignment timestamp"
    );
    assert!(trusted_admission > prepared.proposal.deadline().get());
    Ok(SubmissionReceiptPhase {
        revision: submission.revision,
        expected_review_revision: submission.expected_review_revision,
        request,
        readback,
    })
}

async fn close_past_t1(
    fixture: &Fixture,
    prepared: &PreparedEvidence,
    http: &forge_backend::ForgeHttpClient,
    receipt: &SubmissionReceiptPhase,
) -> Result<T1Phase, Box<dyn std::error::Error>> {
    let cut_id = EvaluationCutId::new(Uuid::now_v7())?;
    let get_request = t1_read_request(fixture, prepared, cut_id);
    assert!(matches!(
        http.get_evaluation_t1_cut(&get_request).await?,
        evaluation_wire::EvaluationEvidenceResponseWire::T1Read {
            status: evaluation_wire::EvaluationRecordReadStatus::Missing,
            cut: None,
            ..
        }
    ));
    let close = EvaluationEvidenceRequest::new(
        fixture.scope.clone(),
        prepared.source,
        EvaluationEvidenceOperation::CloseT1 {
            request: EvaluationT1CloseRequest::new(
                cut_id,
                prepared.proposal.manifest_id(),
                prepared.proposal.revision(),
                prepared.proposal.digest(),
                prepared.proposal.deadline(),
            ),
        },
    );
    let response = http
        .close_evaluation_t1(&close)
        .await
        .map_err(|error| std::io::Error::other(format!("evaluation T1 close failed: {error:?}")))?;
    let cut = match &response {
        evaluation_wire::EvaluationEvidenceResponseWire::T1Closed {
            source,
            outcome: evaluation_wire::EvaluationT1ClosureWire::Closed { cut },
        } => {
            assert_source_identity(source, prepared.source);
            cut.clone()
        }
        observed => return Err(format!("T1 closure did not produce a cut: {observed:?}").into()),
    };
    assert_eq!(cut.cut_id, cut_id.into_uuid());
    assert_eq!(cut.manifest_id, prepared.proposal.manifest_id().into_uuid());
    assert_eq!(cut.manifest_revision, prepared.proposal.revision().get());
    assert_eq!(cut.manifest_digest, digest_hex(&prepared.proposal.digest()));
    assert_eq!(cut.deadline_ms, prepared.proposal.deadline().get());
    assert_eq!(cut.members.len(), 1);
    assert!(matches!(
        cut.members[0].coverage,
        evaluation_wire::EvaluationT1CoverageWire::NoEligibleSubmission
    ));
    let cut_read = http.get_evaluation_t1_cut(&get_request).await?;
    assert!(matches!(
        &cut_read,
        evaluation_wire::EvaluationEvidenceResponseWire::T1Read {
            status: evaluation_wire::EvaluationRecordReadStatus::Found,
            cut: Some(observed),
            ..
        } if observed == &cut
    ));
    assert_eq!(
        http.get_evaluation_submission_receipt(&receipt.request)
            .await?,
        receipt.readback,
        "exact source reads must return the same immutable receipt"
    );
    Ok(T1Phase { cut_id, cut })
}

async fn exercise_review_phase(
    address: SocketAddr,
    fixture: &Fixture,
    prepared: &PreparedEvidence,
    http: &forge_backend::ForgeHttpClient,
    manifest: &ManifestPhase,
    receipt: &SubmissionReceiptPhase,
    t1: &T1Phase,
) -> Result<(), Box<dyn std::error::Error>> {
    create_and_read_pending_review_cut(fixture, prepared, http, receipt, t1).await?;
    let review_revision = accept_assignment_review(address, fixture, prepared, receipt).await?;
    let review_receipt =
        read_review_receipt(fixture, prepared, http, receipt, review_revision).await?;
    create_and_read_accepted_review_cut(fixture, prepared, http, manifest, &review_receipt, t1)
        .await?;
    Ok(())
}

async fn create_and_read_pending_review_cut(
    fixture: &Fixture,
    prepared: &PreparedEvidence,
    http: &forge_backend::ForgeHttpClient,
    submission: &SubmissionReceiptPhase,
    t1: &T1Phase,
) -> Result<(), Box<dyn std::error::Error>> {
    let review_cut_id = EvaluationReviewCutId::new(Uuid::now_v7())?;
    let read_request = review_cut_get_request(fixture, prepared, review_cut_id, t1.cut_id);
    assert!(matches!(
        http.get_evaluation_review_cut(&read_request).await?,
        evaluation_wire::EvaluationEvidenceResponseWire::ReviewCutRead {
            status: evaluation_wire::EvaluationRecordReadStatus::Missing,
            review_cut: None,
            ..
        }
    ));
    let response = http
        .create_evaluation_review_cut(&review_cut_request(
            fixture,
            prepared,
            review_cut_id,
            t1.cut_id,
        ))
        .await
        .map_err(|error| {
            std::io::Error::other(format!("pending evaluation review cut failed: {error:?}"))
        })?;
    let review_cut = match &response {
        evaluation_wire::EvaluationEvidenceResponseWire::ReviewCutCreated {
            source,
            review_cut,
        } => {
            assert_source_identity(source, prepared.source);
            review_cut
        }
        observed => return Err(format!("pending review cut failed: {observed:?}").into()),
    };
    assert_eq!(review_cut.review_cut_id, review_cut_id.into_uuid());
    assert_eq!(review_cut.t1_cut_id, t1.cut_id.into_uuid());
    assert_eq!(
        review_cut.source_high_water,
        t1.cut.source_high_water + 1,
        "source GETs must not advance the durable evaluation cursor"
    );
    assert_eq!(review_cut.members.len(), 1);
    assert!(review_cut.members[0].submission.is_some());
    assert!(matches!(
        review_cut.members[0].review,
        evaluation_wire::EvaluationReviewStateWire::Pending {
            submitted_revision,
            ..
        } if submitted_revision == submission.revision
    ));
    let readback = http.get_evaluation_review_cut(&read_request).await?;
    assert!(matches!(
        &readback,
        evaluation_wire::EvaluationEvidenceResponseWire::ReviewCutRead {
            status: evaluation_wire::EvaluationRecordReadStatus::Found,
            review_cut: Some(observed),
            ..
        } if observed == review_cut
    ));
    Ok(())
}

async fn accept_assignment_review(
    address: SocketAddr,
    fixture: &Fixture,
    prepared: &PreparedEvidence,
    submission: &SubmissionReceiptPhase,
) -> Result<i64, Box<dyn std::error::Error>> {
    let accepted = post_ok(
        address,
        "agent.assignment.mutate",
        json!({
            "scope": scope_json(fixture),
            "activity_id": fixture.activity_id.into_uuid(),
            "assignment_id": prepared.assignment_id.into_uuid(),
            "observed_at_ms": prepared.assignment_observed_at.get(),
            "action": {
                "kind": "review_accept",
                "coordinator": coordinator_json(prepared.coordinator),
                "expected_assignment_revision": submission.revision,
            }
        }),
    )
    .await?;
    assert_eq!(accepted["assignment"]["state"], "accepted");
    let review_revision = assignment_revision(&accepted["assignment"])?;
    assert_eq!(review_revision, submission.expected_review_revision);
    Ok(review_revision)
}

async fn read_review_receipt(
    fixture: &Fixture,
    prepared: &PreparedEvidence,
    http: &forge_backend::ForgeHttpClient,
    submission: &SubmissionReceiptPhase,
    review_revision: i64,
) -> Result<ReviewReceiptPhase, Box<dyn std::error::Error>> {
    let request = review_receipt_request(fixture, prepared, submission.revision, review_revision)?;
    let readback = http.get_evaluation_review_receipt(&request).await?;
    let receipt = match &readback {
        evaluation_wire::EvaluationEvidenceResponseWire::ReviewReceiptRead {
            status: evaluation_wire::EvaluationRecordReadStatus::Found,
            receipt: Some(receipt),
            source,
        } => {
            assert_source_identity(source, prepared.source);
            receipt.clone()
        }
        observed => return Err(format!("review receipt readback failed: {observed:?}").into()),
    };
    assert_eq!(receipt.assignment_id, prepared.assignment_id.into_uuid());
    assert_eq!(receipt.submitted_revision, submission.revision);
    assert_eq!(receipt.review_revision, review_revision);
    assert_eq!(
        receipt.author_agent_id,
        prepared.target_agent_id.into_uuid()
    );
    assert_eq!(
        receipt.author_session_id,
        prepared.target_session_id.into_uuid()
    );
    assert_eq!(
        receipt.reviewer_agent_id,
        prepared.coordinator.agent_id().into_uuid()
    );
    assert_eq!(
        receipt.reviewer_session_id,
        prepared.coordinator.session_id().into_uuid()
    );
    assert_eq!(
        receipt.outcome,
        evaluation_wire::EvaluationReviewOutcomeWire::Accepted
    );
    Ok(ReviewReceiptPhase {
        request,
        readback,
        receipt,
    })
}

async fn create_and_read_accepted_review_cut(
    fixture: &Fixture,
    prepared: &PreparedEvidence,
    http: &forge_backend::ForgeHttpClient,
    manifest: &ManifestPhase,
    review_receipt: &ReviewReceiptPhase,
    t1: &T1Phase,
) -> Result<(), Box<dyn std::error::Error>> {
    let review_cut_id = EvaluationReviewCutId::new(Uuid::now_v7())?;
    let request = review_cut_request(fixture, prepared, review_cut_id, t1.cut_id);
    let response = http
        .create_evaluation_review_cut(&request)
        .await
        .map_err(|error| {
            std::io::Error::other(format!("accepted evaluation review cut failed: {error:?}"))
        })?;
    let review_cut = match &response {
        evaluation_wire::EvaluationEvidenceResponseWire::ReviewCutCreated {
            review_cut, ..
        } => review_cut,
        observed => return Err(format!("accepted review cut failed: {observed:?}").into()),
    };
    assert_eq!(
        review_cut.source_high_water,
        review_receipt.receipt.source_sequence + 1,
        "receipt GETs must not advance the durable evaluation cursor"
    );
    assert!(matches!(
        &review_cut.members[0].review,
        evaluation_wire::EvaluationReviewStateWire::Reviewed { receipt }
            if receipt.outcome == evaluation_wire::EvaluationReviewOutcomeWire::Accepted
                && receipt.reviewer_agent_id == prepared.coordinator.agent_id().into_uuid()
                && receipt.reviewer_session_id == prepared.coordinator.session_id().into_uuid()
    ));
    let readback = http
        .get_evaluation_review_cut(&review_cut_get_request(
            fixture,
            prepared,
            review_cut_id,
            t1.cut_id,
        ))
        .await?;
    assert!(matches!(
        &readback,
        evaluation_wire::EvaluationEvidenceResponseWire::ReviewCutRead {
            status: evaluation_wire::EvaluationRecordReadStatus::Found,
            review_cut: Some(observed),
            ..
        } if observed == review_cut
    ));
    assert_eq!(
        http.get_evaluation_review_receipt(&review_receipt.request)
            .await?,
        review_receipt.readback
    );
    assert_eq!(
        http.get_evaluation_manifest(&manifest.get_request).await?,
        manifest.first_read
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_http_unknown_manifest_seal_returns_correlated_readback()
-> Result<(), Box<dyn std::error::Error>> {
    let (running, held, admitted) =
        HttpBindingFixture::start_holding_first_reply(Some(Duration::from_secs(1))).await?;
    let result = async {
        let prepared = prepare_evidence(&running.fixture)?;
        let payload = seal_payload(
            &running.fixture,
            &prepared,
            BACKEND_ID,
            prepared.source.delegation_destination_id(),
        );
        let (post_result, admitted_result) = tokio::join!(
            super::post_command(running.address, "evaluation.manifest.seal", payload),
            timeout(Duration::from_secs(5), admitted),
        );
        let (status, body) = post_result?;
        admitted_result??;
        assert_eq!(status, 202, "seal response: {body}");
        assert_eq!(body["error"]["code"], "UNKNOWN_OUTCOME");
        assert_eq!(body["error"]["readback"]["kind"], "evaluation_evidence");
        assert_eq!(body["error"]["readback"]["identity"]["kind"], "manifest");
        assert_eq!(
            body["error"]["readback"]["identity"]["manifest_id"],
            prepared.proposal.manifest_id().into_uuid().to_string()
        );
        assert_eq!(
            body["error"]["readback"]["identity"]["revision"],
            prepared.proposal.revision().get()
        );
        assert_eq!(
            body["error"]["readback"]["identity"]["digest"],
            digest_hex(&prepared.proposal.digest())
        );

        let reader = evidence_client(
            running.address,
            prepared.source.delegation_destination_id(),
            Duration::from_secs(5),
        )?;
        let get_request = manifest_get_request(&running.fixture, &prepared);
        let readback_deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let response = reader.get_evaluation_manifest(&get_request).await?;
            if let forge_backend::ops::evaluation_evidence::wire::EvaluationEvidenceResponseWire::ManifestRead {
                status: forge_backend::ops::evaluation_evidence::wire::EvaluationRecordReadStatus::Found,
                manifest: Some(manifest),
                ..
            } = response
            {
                assert_manifest_matches_proposal(&manifest, &prepared.proposal)?;
                break;
            }
            if Instant::now() >= readback_deadline {
                return Err("same-identity manifest remained missing after unknown outcome".into());
            }
            tokio::task::yield_now().await;
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;
    let release = held.release_and_wait().await;
    let finish = running.finish().await;
    result?;
    release?;
    finish?;
    Ok(())
}

fn prepare_evidence(fixture: &Fixture) -> Result<PreparedEvidence, Box<dyn std::error::Error>> {
    let delegation = fixture
        .client
        .agent_operations_delegation(AgentOperationsDelegationReadRequest {
            scope: fixture.scope.clone(),
        })?
        .ok_or("native fixture delegation is missing")?;
    let (source, original) = offer_source_assignment(fixture, &delegation)?;
    let proposal = manifest_for_original(source, &original)?;
    Ok(PreparedEvidence {
        delegation,
        source,
        proposal,
        assignment_id: original.assignment_id,
        target_agent_id: original.target_agent_id,
        target_session_id: original.target_session_id,
        target_revision: original.target_revision,
        coordinator: original.coordinator,
        assignment_observed_at: original.observed_at,
    })
}

fn offer_source_assignment(
    fixture: &Fixture,
    delegation: &AgentOperationsDelegation,
) -> Result<(EvaluationSourceIdentity, OfferedEvaluationAssignment), Box<dyn std::error::Error>> {
    let (target_agent_id, target_session_id, target_revision, target_updated_at) =
        activate_second_agent(fixture, delegation)?;
    let coordinator = fixture
        .client
        .activity_coordinator_actor(CoordinatorActorRequest {
            scope: fixture.scope.clone(),
            activity_id: fixture.activity_id,
            principal: AuthenticatedPrincipal::TrustedStdio,
        })?
        .ok_or("native fixture coordinator actor is missing")?;
    let (goal, pending_node) =
        create_pending_evaluation_node(fixture, coordinator, target_updated_at)?;
    let exact = fixture
        .client
        .dag_node_assignment_snapshot(
            fixture.scope.clone(),
            DagNodeEvidenceScope::new(
                goal.id(),
                forge_domain::DagRevisionNumber::INITIAL,
                pending_node.id(),
            ),
        )?
        .ok_or("native fixture assignment snapshot is missing")?;
    let assignment_observed_at = std::cmp::max(
        std::cmp::max(exact.goal_created_at(), target_updated_at),
        timestamp_now()?,
    );
    let assignment_id = AgentAssignmentId::from_uuid(Uuid::now_v7());
    let target = AgentAssignmentTarget::new(
        target_agent_id,
        target_session_id,
        AuthenticatedPrincipal::TrustedStdio,
        target_revision,
    );
    let offer = forge_domain::OfferAgentAssignment::new(
        assignment_id,
        coordinator,
        target,
        goal.id(),
        goal.revision(),
        exact.goal_created_at(),
        forge_domain::DagRevisionNumber::INITIAL,
        exact.head().revision(),
        pending_node.id(),
        exact.node_revision(),
        None,
        assignment_observed_at,
    );
    let offered = fixture
        .client
        .agent_assignment_mutate(AgentAssignmentMutationRequest {
            scope: fixture.scope.clone(),
            mutation: AgentAssignmentMutation::Offer(offer),
        })?;
    if offered.state() != forge_domain::AgentAssignmentState::Offered {
        return Err("native source fixture assignment was not offered".into());
    }
    let source = EvaluationSourceIdentity::new(
        ForgeBackendId::from_uuid(BACKEND_ID),
        fixture.scope.workspace_id(),
        fixture.activity_id,
        delegation.migration_id(),
        delegation.destination_id(),
        EvaluationRevision::new(i64::try_from(delegation.freeze().revision())?)?,
        EvaluationDigest::new(delegation.manifest_digest())?,
    )?;
    Ok((
        source,
        OfferedEvaluationAssignment {
            assignment_id,
            revision: offered.revision(),
            target_agent_id,
            target_session_id,
            target_revision,
            coordinator,
            observed_at: assignment_observed_at,
        },
    ))
}

fn manifest_for_original(
    source: EvaluationSourceIdentity,
    original: &OfferedEvaluationAssignment,
) -> Result<EvaluationManifestProposal, Box<dyn std::error::Error>> {
    // The descriptive caller timestamp is the inclusive frozen cutoff. HTTP
    // sealing and submission happen later and use Forge's trusted source clock.
    let deadline = original.observed_at;
    let member = EvaluationManifestMember::new(
        EvaluationWorkUnitId::new(Uuid::now_v7())?,
        EvaluationObligationId::new(Uuid::now_v7())?,
        original.assignment_id,
        original.revision,
        original.target_agent_id,
        original.target_session_id,
        EvaluationDigest::new([0xD4; 32])?,
    )?;
    Ok(EvaluationManifestProposal::new(
        EvaluationManifestId::new(Uuid::now_v7())?,
        EvaluationRevision::new(1)?,
        source,
        EvaluationPlanBinding::new(
            EvaluationPlanId::new(Uuid::now_v7())?,
            EvaluationRevision::new(1)?,
            EvaluationDigest::new([0xD3; 32])?,
        ),
        deadline,
        vec![member],
    )?)
}

fn create_pending_evaluation_node(
    fixture: &Fixture,
    coordinator: ActivityCoordinatorActor,
    target_updated_at: TimestampMillis,
) -> Result<(RegisteredGoal, RegisteredDagNode), Box<dyn std::error::Error>> {
    let now = TimestampMillis::new(timestamp_now()?.get().max(target_updated_at.get()))?;
    let goal = RegisteredGoal::create(
        GoalId::from_uuid(Uuid::now_v7()),
        fixture.scope.workspace_id(),
        fixture.activity_id,
        GoalContract::new(
            GoalObjective::new("Evaluate a source-bound assignment".to_owned())?,
            vec![GoalStatement::new(
                "The assignment remains bound to its original Agent and Session".to_owned(),
            )?],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )?,
        add_millis(now, 1)?,
    );
    let _ = stage(
        fixture
            .client
            .goal_create(fixture.scope.clone(), coordinator, goal.clone()),
        "evaluation_goal_create",
    )?;
    let definition = DagNodeDefinition::new(
        DagNodeId::from_uuid(Uuid::now_v7()),
        DagNodeOrdinal::new(0)?,
        DagNodeTitle::new("Submit source evidence".to_owned())?,
        DagNodeObjective::new("Submit the assignment before its frozen T1".to_owned())?,
        vec![DagAcceptanceCriterion::new(
            "Forge records the exact source receipt".to_owned(),
        )?],
    )?;
    let revision = DagRevision::new(
        DagRevisionId::from_uuid(Uuid::now_v7()),
        goal.id(),
        goal.revision(),
        forge_domain::DagRevisionNumber::INITIAL,
        None,
        vec![definition.clone()],
        Vec::new(),
        add_millis(now, 2)?,
    )?;
    let pending = RegisteredDagNode::create(
        goal.id(),
        forge_domain::DagRevisionNumber::INITIAL,
        definition,
        add_millis(now, 2)?,
    );
    let history_sequence = next_coordinator_work_update_sequence(fixture, coordinator)?;
    let plan = AgentDagPlanRequest::new(
        AgentDagPlanRequestId::from_uuid(Uuid::now_v7()),
        coordinator,
        GoalAttribution::new(goal.id(), goal.revision()),
        None,
        None,
        AgentDagDraft::new(revision, vec![pending.clone()], Vec::new())?,
        AgentWorkUpdateId::from_uuid(Uuid::now_v7()),
        history_sequence,
        add_millis(now, 3)?,
    );
    let _ = stage(
        fixture
            .client
            .agent_dag_plan_commit(AgentDagPlanCommitRequest {
                scope: fixture.scope.clone(),
                request: plan,
            }),
        "evaluation_dag_plan_commit",
    )?;
    Ok((goal, pending))
}

fn next_coordinator_work_update_sequence(
    fixture: &Fixture,
    coordinator: ActivityCoordinatorActor,
) -> Result<AgentWorkUpdateSequence, Box<dyn std::error::Error>> {
    let context = fixture
        .client
        .agent_get_context(forge_control::AgentContextRequest {
            scope: fixture.scope.clone(),
            activity_id: fixture.activity_id,
            agent_id: coordinator.agent_id(),
            now: timestamp_now()?,
            focus_event_limit: AgentListLimit::DEFAULT,
            work_update_limit: AgentListLimit::DEFAULT,
        })?
        .ok_or("coordinator Agent context is missing before planning")?;
    let latest_sequence = context
        .work_updates()
        .iter()
        .map(|update| update.sequence().get())
        .max()
        .unwrap_or(0);
    let next_sequence = latest_sequence
        .checked_add(1)
        .ok_or("coordinator work update sequence overflow")?;
    Ok(AgentWorkUpdateSequence::new(next_sequence)?)
}

/// Seed a separate, valid source-bound original through native APIs at a
/// controlled clock. This proves inclusive T1 eligibility without waiting;
/// the later HTTP assignment exercises the real `SystemTime` sampler.
fn seed_native_t1_eligible_original(
    fixture: &Fixture,
    source: EvaluationSourceIdentity,
    delegation: &AgentOperationsDelegation,
) -> Result<(), Box<dyn std::error::Error>> {
    let original = prepare_native_t1_original(fixture, source, delegation)?;
    record_native_t1_eligible_original(fixture, &original)
}

fn prepare_native_t1_original(
    fixture: &Fixture,
    source: EvaluationSourceIdentity,
    delegation: &AgentOperationsDelegation,
) -> Result<NativeT1Original, Box<dyn std::error::Error>> {
    let (target_agent_id, target_session_id, target_revision, target_updated_at) =
        activate_second_agent(fixture, delegation)?;
    let coordinator = fixture
        .client
        .activity_coordinator_actor(CoordinatorActorRequest {
            scope: fixture.scope.clone(),
            activity_id: fixture.activity_id,
            principal: AuthenticatedPrincipal::TrustedStdio,
        })?
        .ok_or("native T1 fixture coordinator actor is missing")?;
    let (goal, pending_node) =
        create_pending_evaluation_node(fixture, coordinator, target_updated_at)?;
    let exact = fixture
        .client
        .dag_node_assignment_snapshot(
            fixture.scope.clone(),
            DagNodeEvidenceScope::new(
                goal.id(),
                forge_domain::DagRevisionNumber::INITIAL,
                pending_node.id(),
            ),
        )?
        .ok_or("native T1 fixture assignment snapshot is missing")?;
    let assignment_observed_at = std::cmp::max(
        std::cmp::max(exact.goal_created_at(), target_updated_at),
        timestamp_now()?,
    );
    let assignment_id = AgentAssignmentId::from_uuid(Uuid::now_v7());
    let target = AgentAssignmentTarget::new(
        target_agent_id,
        target_session_id,
        AuthenticatedPrincipal::TrustedStdio,
        target_revision,
    );
    let offered = fixture
        .client
        .agent_assignment_mutate(AgentAssignmentMutationRequest {
            scope: fixture.scope.clone(),
            mutation: AgentAssignmentMutation::Offer(forge_domain::OfferAgentAssignment::new(
                assignment_id,
                coordinator,
                target,
                goal.id(),
                goal.revision(),
                exact.goal_created_at(),
                forge_domain::DagRevisionNumber::INITIAL,
                exact.head().revision(),
                pending_node.id(),
                exact.node_revision(),
                None,
                assignment_observed_at,
            )),
        })?;
    if offered.state() != forge_domain::AgentAssignmentState::Offered {
        return Err("native T1 source assignment was not offered".into());
    }
    let native_deadline = TimestampMillis::new(1_500)?;
    let member = EvaluationManifestMember::new(
        EvaluationWorkUnitId::new(Uuid::now_v7())?,
        EvaluationObligationId::new(Uuid::now_v7())?,
        assignment_id,
        offered.revision(),
        target_agent_id,
        target_session_id,
        EvaluationDigest::new([0xE4; 32])?,
    )?;
    let proposal = EvaluationManifestProposal::new(
        EvaluationManifestId::new(Uuid::now_v7())?,
        EvaluationRevision::new(1)?,
        source,
        EvaluationPlanBinding::new(
            EvaluationPlanId::new(Uuid::now_v7())?,
            EvaluationRevision::new(1)?,
            EvaluationDigest::new([0xE3; 32])?,
        ),
        native_deadline,
        vec![member],
    )?;
    Ok(NativeT1Original {
        source,
        proposal,
        assignment_id,
        target,
        offered_revision: offered.revision(),
        observed_at: assignment_observed_at,
    })
}

fn record_native_t1_eligible_original(
    fixture: &Fixture,
    original: &NativeT1Original,
) -> Result<(), Box<dyn std::error::Error>> {
    let seal_time = TimestampMillis::new(1_000)?;
    let submission_time = original.proposal.deadline();
    let close_time = TimestampMillis::new(1_501)?;
    let layout = WorkspaceStateLayout::inspect_existing(&fixture.workspace_root)?
        .ok_or("Workspace layout missing before native T1 fixture")?;
    let mut store = WorkspaceStore::open_existing(&layout)?;
    let sealed =
        store.seal_evaluation_manifest(original.source.backend_id(), &original.proposal, || {
            EvaluationClockReading::Trusted(seal_time)
        })?;
    assert!(matches!(
        sealed.seal_timing(),
        forge_domain::EvaluationAdmissionTiming::Trusted(observed_at) if observed_at == seal_time
    ));
    assert!(matches!(
        sealed.members()[0].binding(),
        forge_domain::EvaluationOriginalBindingStatus::Bound(_)
    ));
    let native_submission =
        submit_native_t1_original(fixture, &mut store, original, submission_time)?;
    let receipt = native_submission
        .receipt()
        .ok_or("native T1 fixture omitted its source receipt")?;
    assert!(matches!(
        receipt.timing(),
        forge_domain::EvaluationAdmissionTiming::Trusted(observed_at)
            if observed_at == original.proposal.deadline()
    ));
    let native_cut = close_native_t1_original(&mut store, original, close_time)?;
    assert!(matches!(
        native_cut.members()[0].coverage(),
        forge_domain::EvaluationT1Coverage::Eligible {
            admitted_at,
            submitted_revision,
            ..
        } if admitted_at == original.proposal.deadline()
            && submitted_revision == native_submission.assignment().revision()
    ));
    Ok(())
}

fn submit_native_t1_original(
    fixture: &Fixture,
    store: &mut WorkspaceStore,
    original: &NativeT1Original,
    sample_time: TimestampMillis,
) -> Result<forge_persistence::EvaluationAssignmentSubmission, Box<dyn std::error::Error>> {
    let claimed = fixture
        .client
        .agent_assignment_mutate(AgentAssignmentMutationRequest {
            scope: fixture.scope.clone(),
            mutation: AgentAssignmentMutation::Claim(forge_domain::ClaimAgentAssignment::new(
                original.assignment_id,
                original.target,
                original.offered_revision,
                original.observed_at,
            )),
        })?;
    let current_target = AgentAssignmentTarget::new(
        original.target.agent_id(),
        original.target.session_id(),
        AuthenticatedPrincipal::TrustedStdio,
        current_agent_revision(fixture, original.target.agent_id())?,
    );
    let submission = forge_domain::SubmitAgentAssignment::new(
        original.assignment_id,
        current_target,
        claimed.revision(),
        forge_domain::AgentAssignmentResult::new(
            "native source-clock T1 eligible fixture".to_owned(),
            Vec::new(),
            None,
        )?,
        original.observed_at,
    );
    Ok(store.submit_agent_assignment_with_source_clock(
        &submission,
        timestamp_now()?,
        original.source.backend_id(),
        || EvaluationClockReading::Trusted(sample_time),
    )?)
}

fn close_native_t1_original(
    store: &mut WorkspaceStore,
    original: &NativeT1Original,
    close_time: TimestampMillis,
) -> Result<forge_domain::EvaluationT1CoverageCut, Box<dyn std::error::Error>> {
    let close_request = EvaluationT1CloseRequest::new(
        EvaluationCutId::new(Uuid::now_v7())?,
        original.proposal.manifest_id(),
        original.proposal.revision(),
        original.proposal.digest(),
        original.proposal.deadline(),
    );
    match store.close_evaluation_t1(original.source.backend_id(), &close_request, || {
        EvaluationClockReading::Trusted(close_time)
    })? {
        forge_persistence::EvaluationT1ClosureOutcome::Closed(cut) => Ok(cut),
        forge_persistence::EvaluationT1ClosureOutcome::NotClosed(timing) => {
            Err(format!("native T1 fixture unexpectedly remained open: {timing:?}").into())
        }
    }
}

fn activate_second_agent(
    fixture: &Fixture,
    delegation: &AgentOperationsDelegation,
) -> Result<
    (
        AgentInstanceId,
        AgentSessionId,
        AgentInstanceRevision,
        TimestampMillis,
    ),
    Box<dyn std::error::Error>,
> {
    let observed_now = timestamp_now()?;
    let now = TimestampMillis::new(observed_now.get().max(delegation.delegated_at().get()))?;
    let session_id = AgentSessionId::from_uuid(Uuid::now_v7());
    let agent_id = AgentInstanceId::from_uuid(Uuid::now_v7());
    let _session = fixture.client.agent_session_open(OpenAgentSession::new(
        session_id,
        AgentSessionOpenRequestId::from_uuid(Uuid::now_v7()),
        AuthenticatedPrincipal::TrustedStdio,
        now,
    ))?;
    let request_id = Uuid::now_v7();
    let reservation = AgentBindingReservationRequest::new(
        request_id,
        fixture.activity_id,
        agent_id,
        session_id,
        AuthenticatedPrincipal::TrustedStdio,
        add_millis(now, 1)?,
    )?;
    let _reservation = fixture
        .client
        .reserve_agent_binding(AgentBindingReserveRequest {
            scope: fixture.scope.clone(),
            freeze: delegation.freeze().clone(),
            reservation,
            observed_at: add_millis(now, 2)?,
        })?;
    let activation = AgentBindingActivationRequest::new(
        request_id,
        [0xD5; 32],
        AgentDisplayName::new("evaluation-source-target".to_owned())?,
        AgentDeclaredRole::new("executor".to_owned())?,
        AgentTransportKind::Stdio,
    )?;
    let _activation = fixture
        .client
        .activate_agent_binding(AgentBindingActivateRequest {
            scope: fixture.scope.clone(),
            delegation: delegation.clone(),
            activation,
            session_id,
            principal: AuthenticatedPrincipal::TrustedStdio,
            observed_at: add_millis(now, 3)?,
        })?;
    let target = fixture
        .client
        .agent_list(AgentListRequest {
            scope: fixture.scope.clone(),
            activity_id: Some(fixture.activity_id),
            now: add_millis(now, 4)?,
            limit: AgentListLimit::DEFAULT,
        })?
        .into_iter()
        .find(|entry| entry.agent().id() == agent_id)
        .ok_or("additional Agent activation did not create a Workspace participant")?
        .agent()
        .clone();
    Ok((agent_id, session_id, target.revision(), target.updated_at()))
}

fn evidence_client(
    address: SocketAddr,
    destination_id: Uuid,
    timeout: Duration,
) -> Result<forge_backend::ForgeHttpClient, Box<dyn std::error::Error>> {
    Ok(forge_backend::ForgeHttpClient::new(
        address,
        SECRET,
        ForgeBackendId::from_uuid(BACKEND_ID),
        destination_id,
        timeout,
    )?)
}

fn seal_request(fixture: &Fixture, prepared: &PreparedEvidence) -> EvaluationEvidenceRequest {
    EvaluationEvidenceRequest::new(
        fixture.scope.clone(),
        prepared.source,
        EvaluationEvidenceOperation::SealManifest {
            proposal: prepared.proposal.clone(),
        },
    )
}

fn manifest_get_request(
    fixture: &Fixture,
    prepared: &PreparedEvidence,
) -> EvaluationEvidenceRequest {
    EvaluationEvidenceRequest::new(
        fixture.scope.clone(),
        prepared.source,
        EvaluationEvidenceOperation::GetManifest {
            manifest_id: prepared.proposal.manifest_id(),
            revision: prepared.proposal.revision(),
            digest: prepared.proposal.digest(),
        },
    )
}

fn t1_read_request(
    fixture: &Fixture,
    prepared: &PreparedEvidence,
    cut_id: EvaluationCutId,
) -> EvaluationEvidenceRequest {
    EvaluationEvidenceRequest::new(
        fixture.scope.clone(),
        prepared.source,
        EvaluationEvidenceOperation::GetT1Cut {
            request: EvaluationT1CloseRequest::new(
                cut_id,
                prepared.proposal.manifest_id(),
                prepared.proposal.revision(),
                prepared.proposal.digest(),
                prepared.proposal.deadline(),
            ),
        },
    )
}

fn review_cut_request(
    fixture: &Fixture,
    prepared: &PreparedEvidence,
    review_cut_id: EvaluationReviewCutId,
    t1_cut_id: EvaluationCutId,
) -> EvaluationEvidenceRequest {
    EvaluationEvidenceRequest::new(
        fixture.scope.clone(),
        prepared.source,
        EvaluationEvidenceOperation::CreateReviewCut {
            review_cut_id,
            t1_request: EvaluationT1CloseRequest::new(
                t1_cut_id,
                prepared.proposal.manifest_id(),
                prepared.proposal.revision(),
                prepared.proposal.digest(),
                prepared.proposal.deadline(),
            ),
        },
    )
}

fn review_cut_get_request(
    fixture: &Fixture,
    prepared: &PreparedEvidence,
    review_cut_id: EvaluationReviewCutId,
    t1_cut_id: EvaluationCutId,
) -> EvaluationEvidenceRequest {
    EvaluationEvidenceRequest::new(
        fixture.scope.clone(),
        prepared.source,
        EvaluationEvidenceOperation::GetReviewCut {
            review_cut_id,
            t1_request: EvaluationT1CloseRequest::new(
                t1_cut_id,
                prepared.proposal.manifest_id(),
                prepared.proposal.revision(),
                prepared.proposal.digest(),
                prepared.proposal.deadline(),
            ),
        },
    )
}

fn submission_receipt_request(
    fixture: &Fixture,
    prepared: &PreparedEvidence,
    submitted_revision: i64,
) -> Result<EvaluationEvidenceRequest, Box<dyn std::error::Error>> {
    Ok(EvaluationEvidenceRequest::new(
        fixture.scope.clone(),
        prepared.source,
        EvaluationEvidenceOperation::GetSubmissionReceipt {
            manifest_id: prepared.proposal.manifest_id(),
            manifest_revision: prepared.proposal.revision(),
            manifest_digest: prepared.proposal.digest(),
            assignment_id: prepared.assignment_id,
            submitted_revision: AgentAssignmentRevision::new(submitted_revision)?,
        },
    ))
}

fn review_receipt_request(
    fixture: &Fixture,
    prepared: &PreparedEvidence,
    submitted_revision: i64,
    review_revision: i64,
) -> Result<EvaluationEvidenceRequest, Box<dyn std::error::Error>> {
    Ok(EvaluationEvidenceRequest::new(
        fixture.scope.clone(),
        prepared.source,
        EvaluationEvidenceOperation::GetReviewReceipt {
            manifest_id: prepared.proposal.manifest_id(),
            manifest_revision: prepared.proposal.revision(),
            manifest_digest: prepared.proposal.digest(),
            assignment_id: prepared.assignment_id,
            submitted_revision: AgentAssignmentRevision::new(submitted_revision)?,
            review_revision: AgentAssignmentRevision::new(review_revision)?,
        },
    ))
}

fn current_agent_revision(
    fixture: &Fixture,
    agent_id: AgentInstanceId,
) -> Result<AgentInstanceRevision, Box<dyn std::error::Error>> {
    fixture
        .client
        .agent_list(AgentListRequest {
            scope: fixture.scope.clone(),
            activity_id: Some(fixture.activity_id),
            now: timestamp_now()?,
            limit: AgentListLimit::DEFAULT,
        })?
        .into_iter()
        .find(|entry| entry.agent().id() == agent_id)
        .map(|entry| entry.agent().revision())
        .ok_or_else(|| "current target Agent projection missing".into())
}

fn target_json(
    agent_id: AgentInstanceId,
    session_id: AgentSessionId,
    expected_revision: AgentInstanceRevision,
) -> Value {
    json!({
        "agent_id": agent_id.into_uuid(),
        "session_id": session_id.into_uuid(),
        "expected_revision": expected_revision.get(),
        "principal": {"kind": "trusted_stdio"},
    })
}

fn coordinator_json(actor: ActivityCoordinatorActor) -> Value {
    json!({
        "session_id": actor.session_id().into_uuid(),
        "agent_id": actor.agent_id().into_uuid(),
        "expected_revision": actor.expected_revision().get(),
        "principal": {"kind": "trusted_stdio"},
    })
}

fn assignment_revision(value: &Value) -> Result<i64, Box<dyn std::error::Error>> {
    value["revision"]
        .as_i64()
        .ok_or_else(|| "assignment revision missing".into())
}

fn source_json(source: EvaluationSourceIdentity) -> Value {
    json!({
        "backend_id": source.backend_id().into_uuid(),
        "workspace_id": source.workspace_id().into_uuid(),
        "activity_id": source.activity_id().into_uuid(),
        "delegation_migration_id": source.delegation_migration_id(),
        "delegation_destination_id": source.delegation_destination_id(),
        "delegation_freeze_revision": source.delegation_freeze_revision().get(),
        "delegation_manifest_digest": digest_hex(&source.delegation_manifest_digest()),
    })
}

fn proposal_json(proposal: &EvaluationManifestProposal) -> Value {
    json!({
        "manifest_id": proposal.manifest_id().into_uuid(),
        "revision": proposal.revision().get(),
        "source": source_json(proposal.source()),
        "plan": {
            "plan_id": proposal.plan().plan_id().into_uuid(),
            "revision": proposal.plan().revision().get(),
            "digest": digest_hex(&proposal.plan().digest()),
        },
        "deadline_ms": proposal.deadline().get(),
        "digest": digest_hex(&proposal.digest()),
        "members": proposal.members().iter().map(|member| json!({
            "work_unit_id": member.work_unit_id().into_uuid(),
            "obligation_id": member.obligation_id().into_uuid(),
            "assignment_id": member.assignment_id().into_uuid(),
            "assignment_revision": member.assignment_revision().get(),
            "target_agent_id": member.target_agent_id().into_uuid(),
            "target_session_id": member.target_session_id().into_uuid(),
            "criteria_digest": digest_hex(&member.criteria_digest()),
        })).collect::<Vec<_>>(),
    })
}

fn seal_payload(
    fixture: &Fixture,
    prepared: &PreparedEvidence,
    service_backend_id: Uuid,
    service_destination_id: Uuid,
) -> Value {
    json!({
        "scope": scope_json(fixture),
        "service": {
            "backend_id": service_backend_id,
            "destination_id": service_destination_id,
        },
        "proposal": proposal_json(&prepared.proposal),
    })
}

async fn assert_configured_identity_rejections(
    address: SocketAddr,
    fixture: &Fixture,
    prepared: &PreparedEvidence,
) -> Result<(), Box<dyn std::error::Error>> {
    let configured_destination = prepared.delegation.destination_id();
    let rejected_backend = seal_payload(fixture, prepared, Uuid::now_v7(), configured_destination);
    let (backend_status, backend_response) =
        post_command(address, "evaluation.manifest.seal", rejected_backend).await?;
    assert_eq!(
        backend_status, 400,
        "unexpected backend mismatch response: {backend_response}"
    );
    assert_eq!(backend_response["error"]["code"], "AUTH_FAILED");

    let rejected_destination = seal_payload(fixture, prepared, BACKEND_ID, Uuid::now_v7());
    let (destination_status, destination_response) =
        post_command(address, "evaluation.manifest.seal", rejected_destination).await?;
    assert_eq!(
        destination_status, 400,
        "unexpected destination mismatch response: {destination_response}"
    );
    assert_eq!(destination_response["error"]["code"], "AUTH_FAILED");

    let http = evidence_client(address, configured_destination, Duration::from_secs(5))?;
    let readback = http
        .get_evaluation_manifest(&manifest_get_request(fixture, prepared))
        .await?;
    assert!(matches!(
        readback,
        forge_backend::ops::evaluation_evidence::wire::EvaluationEvidenceResponseWire::ManifestRead {
            status: forge_backend::ops::evaluation_evidence::wire::EvaluationRecordReadStatus::Found,
            manifest: Some(_),
            ..
        }
    ));
    Ok(())
}

fn assert_source_identity(
    source: &forge_backend::ops::evaluation_evidence::wire::EvaluationSourceIdentityWire,
    expected: EvaluationSourceIdentity,
) {
    assert_eq!(source.backend_id, expected.backend_id().into_uuid());
    assert_eq!(source.workspace_id, expected.workspace_id().into_uuid());
    assert_eq!(source.activity_id, expected.activity_id().into_uuid());
    assert_eq!(
        source.delegation_migration_id,
        expected.delegation_migration_id()
    );
    assert_eq!(
        source.delegation_destination_id,
        expected.delegation_destination_id()
    );
    assert_eq!(
        source.delegation_freeze_revision,
        expected.delegation_freeze_revision().get()
    );
    assert_eq!(
        source.delegation_manifest_digest,
        digest_hex(&expected.delegation_manifest_digest())
    );
}

fn assert_manifest_matches_proposal(
    manifest: &forge_backend::ops::evaluation_evidence::wire::EvaluationRegisteredManifestWire,
    proposal: &EvaluationManifestProposal,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        manifest.proposal.manifest_id,
        proposal.manifest_id().into_uuid()
    );
    assert_eq!(manifest.proposal.revision, proposal.revision().get());
    assert_eq!(manifest.proposal.digest, digest_hex(&proposal.digest()));
    assert_eq!(manifest.proposal.deadline_ms, proposal.deadline().get());
    assert_source_identity(&manifest.proposal.source, proposal.source());
    assert_eq!(
        manifest.proposal.plan.plan_id,
        proposal.plan().plan_id().into_uuid()
    );
    assert_eq!(
        manifest.proposal.plan.revision,
        proposal.plan().revision().get()
    );
    assert_eq!(
        manifest.proposal.plan.digest,
        digest_hex(&proposal.plan().digest())
    );
    assert_eq!(manifest.proposal.members.len(), proposal.members().len());
    assert_eq!(manifest.members.len(), proposal.members().len());
    for (wire_member, member) in manifest.proposal.members.iter().zip(proposal.members()) {
        assert_eq!(wire_member.work_unit_id, member.work_unit_id().into_uuid());
        assert_eq!(
            wire_member.obligation_id,
            member.obligation_id().into_uuid()
        );
        assert_eq!(
            wire_member.assignment_id,
            member.assignment_id().into_uuid()
        );
        assert_eq!(
            wire_member.assignment_revision,
            member.assignment_revision().get()
        );
        assert_eq!(
            wire_member.target_agent_id,
            member.target_agent_id().into_uuid()
        );
        assert_eq!(
            wire_member.target_session_id,
            member.target_session_id().into_uuid()
        );
        assert_eq!(
            wire_member.criteria_digest,
            digest_hex(&member.criteria_digest())
        );
    }
    for (registered, declared) in manifest.members.iter().zip(&manifest.proposal.members) {
        assert_eq!(&registered.declaration, declared);
        match &registered.binding {
            forge_backend::ops::evaluation_evidence::wire::EvaluationOriginalBindingWire::Bound {
                digest,
                assignment_revision,
                source_sequence,
            } => {
                assert!(!digest.is_empty());
                assert_eq!(*assignment_revision, declared.assignment_revision);
                assert!(*source_sequence <= manifest.source_sequence);
            }
            forge_backend::ops::evaluation_evidence::wire::EvaluationOriginalBindingWire::UnknownHistorical => {
                return Err("freshly sealed source assignment had no exact original binding".into());
            }
        }
    }
    Ok(())
}

fn digest_hex(digest: &EvaluationDigest) -> String {
    forge_backend::events::hex_encode(digest.as_bytes())
}
