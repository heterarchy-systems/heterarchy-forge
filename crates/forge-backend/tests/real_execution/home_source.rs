//! Real HTTP proof for source-only Home-transfer custody and reply-loss recovery.

use std::time::Duration;

use serde_json::{Value, json};
use uuid::Uuid;

use forge_domain::{
    AgentSessionState, AuthenticatedPrincipal, ForgeBackendId, HomeTransferSourceBinding,
    HomeTransferSourceRequest, HomeTransferSourceScope, HomeTransferSourceSubject,
    HomeTransferSourceWitness, WorkspaceRevision,
};
use forge_persistence::AgentSessionCatalog;

use super::binding_lifecycle::{HttpBindingFixture, open_command_without_read};
use super::lease_readback::{post_ok, scope_json};
use super::*;

#[path = "home_source/retirement.rs"]
mod retirement;

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_http_home_source_reads_original_after_prepare_reply_loss_without_open_session()
-> TestResult<()> {
    let (running, held, admitted) = HttpBindingFixture::start_holding_first_reply(None).await?;

    let result = async {
        let observed = async {
            close_target_session(&running.fixture)?;
            let destination = delegated_destination_id(&running.fixture)?;
            let request = source_request(&running.fixture, destination, Uuid::now_v7(), 0xA100)?;
            let prepare = prepare_payload(&running.fixture, destination, &request, "prepare")?;
            let stream = open_command_without_read(
                running.address,
                "home_transfer.source_prepare",
                prepare.clone(),
            )
            .await?;
            tokio::time::timeout(Duration::from_secs(5), admitted).await??;
            drop(stream);
            Ok::<_, Box<dyn std::error::Error>>((destination, request, prepare))
        }
        .await;
        let readback = match &observed {
            Ok((destination, request, _)) => {
                Some(get_until_record(&running, *destination, request).await)
            }
            Err(_) => None,
        };
        let released = held.release_and_wait().await;
        let (destination, request, prepare) = observed?;
        released?;

        // Resolve the uncertain write by its exact durable identity while its
        // original HTTP reply is still withheld, before any replay.
        let original = readback.ok_or("Home source readback was skipped")??;
        assert_source_record(&original, &request, "prepared", true);

        let replay = post_ok(running.address, "home_transfer.source_prepare", prepare).await?;
        assert_eq!(
            replay["record"], original,
            "exact replay changed the source receipt"
        );

        let abort = prepare_payload(&running.fixture, destination, &request, "abort_unstarted")?;
        let after_abort = post_ok(
            running.address,
            "home_transfer.source_abort_unstarted",
            abort,
        )
        .await?;
        assert_eq!(
            after_abort["record"], original,
            "AbortUnstarted replaced the original Prepared outcome"
        );
        let after_get = get_until_record(&running, destination, &request).await?;
        assert_eq!(
            after_get, original,
            "Get changed the original source receipt"
        );
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;
    let finish = running.finish().await;
    result?;
    finish?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_http_home_source_abort_tombstone_and_service_rejections_preserve_history()
-> TestResult<()> {
    let running = HttpBindingFixture::start().await?;
    let result = async {
        close_target_session(&running.fixture)?;
        let destination = delegated_destination_id(&running.fixture)?;

        let aborted_request =
            source_request(&running.fixture, destination, Uuid::now_v7(), 0xB100)?;
        let abort = prepare_payload(
            &running.fixture,
            destination,
            &aborted_request,
            "abort_unstarted",
        )?;
        let original = post_ok(
            running.address,
            "home_transfer.source_abort_unstarted",
            abort,
        )
        .await?["record"]
            .clone();
        assert_source_record(&original, &aborted_request, "aborted_unstarted", false);

        let late_prepare =
            prepare_payload(&running.fixture, destination, &aborted_request, "prepare")?;
        let after_late_prepare = post_ok(
            running.address,
            "home_transfer.source_prepare",
            late_prepare,
        )
        .await?;
        assert_eq!(
            after_late_prepare["record"], original,
            "late Prepare promoted or replaced the immutable abort tombstone"
        );
        assert_eq!(
            get_until_record(&running, destination, &aborted_request).await?,
            original
        );

        // A distinct Prepare for the same subject and Session is admitted only
        // if the Abort tombstone installed no lingering source fence. This
        // second record's Prepared state is caused by its own Prepare.
        let fresh_request = request_with_new_preparation(&aborted_request, Uuid::now_v7())?;
        let fresh_prepare =
            prepare_payload(&running.fixture, destination, &fresh_request, "prepare")?;
        let fresh_receipt = post_ok(
            running.address,
            "home_transfer.source_prepare",
            fresh_prepare,
        )
        .await?;
        assert_source_record(&fresh_receipt["record"], &fresh_request, "prepared", true);
        assert_eq!(
            get_until_record(&running, destination, &aborted_request).await?,
            original,
            "a later distinct Prepare changed the original abort tombstone"
        );

        // Scope failures and a mismatched action grant are rejected before the
        // journal write. Each identity remains absent under the configured
        // service scope after the failure.
        for (seed, mismatch) in [
            (0xB200, ServiceMismatch::Issuer),
            (0xB300, ServiceMismatch::Backend),
            (0xB400, ServiceMismatch::GrantDigest),
        ] {
            let request = source_request(&running.fixture, destination, Uuid::now_v7(), seed)?;
            let mut payload = prepare_payload(&running.fixture, destination, &request, "prepare")?;
            apply_service_mismatch(&mut payload, mismatch);
            let (status, response) =
                super::post_command(running.address, "home_transfer.source_prepare", payload)
                    .await?;
            assert_eq!(status, 400, "{mismatch:?}: {response}");
            assert_eq!(response["error"]["code"], "AUTH_FAILED", "{response}");
            let absent = post_ok(
                running.address,
                "home_transfer.source_get",
                get_payload(&running.fixture, destination, &request),
            )
            .await?;
            assert_eq!(absent["record"], Value::Null, "{mismatch:?}: {absent}");
        }

        // A Get with the wrong request digest conflicts, and the correct exact
        // readback still returns the same historical result afterwards.
        let mut wrong_digest = get_payload(&running.fixture, destination, &aborted_request);
        wrong_digest["request_digest"] = json!(forge_backend::events::hex_encode(&[0xEE; 32]));
        let (status, response) =
            super::post_command(running.address, "home_transfer.source_get", wrong_digest).await?;
        assert_eq!(status, 409, "{response}");
        assert_eq!(response["error"]["code"], "PLANNING_CONFLICT", "{response}");
        let unchanged = get_until_record(&running, destination, &aborted_request).await?;
        assert_eq!(unchanged, original);
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;

    let finish = running.finish().await;
    result?;
    finish?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(
    clippy::too_many_lines,
    reason = "one HTTP lifecycle compares original reservation replay with a fresh fenced reservation"
)]
async fn real_http_home_source_preserves_pre_cut_reservation_replay_and_fences_fresh_binding()
-> TestResult<()> {
    let running = HttpBindingFixture::start().await?;
    let result = async {
        let destination = delegated_destination_id(&running.fixture)?;
        let pending_activity = bootstrap_extra_activity(&running.fixture)?;
        let fresh_activity = bootstrap_extra_activity(&running.fixture)?;
        let reference = freeze_reference(&running.fixture)?;
        let target_session = running.fixture.session_id;
        let pre_cut_request_id = Uuid::now_v7();
        let pre_cut_agent_id = AgentInstanceId::from_uuid(Uuid::now_v7());
        let pre_cut_reservation = agent_binding_reservation_payload(
            &running.fixture,
            destination,
            &reference,
            pre_cut_request_id,
            pending_activity,
            pre_cut_agent_id,
            target_session,
        )?;
        let pre_cut_receipt = post_ok(
            running.address,
            "agent.binding.reserve",
            pre_cut_reservation.clone(),
        )
        .await?;
        let pre_cut_read = post_ok(
            running.address,
            "agent.binding.reservation_get",
            agent_binding_reservation_get_payload(
                &running.fixture,
                destination,
                pre_cut_request_id,
                target_session,
            ),
        )
        .await?;
        assert_eq!(pre_cut_read["found"], true);
        assert_eq!(
            pre_cut_read["agent_id"],
            json!(pre_cut_agent_id.into_uuid())
        );

        // Home Prepare captures the existing Agent A1 plus the pending A2
        // reservation for the same target Session.
        let home_request = source_request(&running.fixture, destination, Uuid::now_v7(), 0xC100)?;
        assert_eq!(home_request.bindings().len(), 1);
        assert_eq!(
            home_request.bindings()[0].agent_id(),
            running.fixture.agent_id
        );
        assert_eq!(home_request.sessions(), &[target_session]);
        let home_prepare =
            prepare_payload(&running.fixture, destination, &home_request, "prepare")?;
        let home_record = post_ok(
            running.address,
            "home_transfer.source_prepare",
            home_prepare,
        )
        .await?["record"]
            .clone();
        assert_source_record(&home_record, &home_request, "prepared", true);

        // Exact pre-cut reservation replay remains readable after the Session
        // fence. A new Agent in an otherwise empty Activity is rejected by
        // that Session fence with the current conflict family.
        let reservation_replay = post_ok(
            running.address,
            "agent.binding.reserve",
            pre_cut_reservation,
        )
        .await?;
        assert_eq!(reservation_replay, pre_cut_receipt);

        let fresh_request_id = Uuid::now_v7();
        let fresh_agent_id = AgentInstanceId::from_uuid(Uuid::now_v7());
        let fresh_reservation = agent_binding_reservation_payload(
            &running.fixture,
            destination,
            &reference,
            fresh_request_id,
            fresh_activity,
            fresh_agent_id,
            target_session,
        )?;
        let (status, blocked) =
            super::post_command(running.address, "agent.binding.reserve", fresh_reservation)
                .await?;
        assert_eq!(status, 409, "{blocked}");
        assert_eq!(blocked["error"]["code"], "PLANNING_CONFLICT", "{blocked}");
        assert_eq!(blocked["error"]["readback"], Value::Null, "{blocked}");
        let fresh_reservation_read = post_ok(
            running.address,
            "agent.binding.reservation_get",
            agent_binding_reservation_get_payload(
                &running.fixture,
                destination,
                fresh_request_id,
                target_session,
            ),
        )
        .await?;
        assert_eq!(fresh_reservation_read["found"], false);

        assert_eq!(
            get_until_record(&running, destination, &home_request).await?,
            home_record,
            "blocked fresh binding changed the original Home source receipt"
        );
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;

    let finish = running.finish().await;
    result?;
    finish?;
    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum ServiceMismatch {
    Issuer,
    Backend,
    GrantDigest,
}

fn apply_service_mismatch(payload: &mut Value, mismatch: ServiceMismatch) {
    match mismatch {
        ServiceMismatch::Issuer => {
            let wrong = Uuid::now_v7();
            payload["service"]["issuer"] = json!(wrong);
            payload["grant"]["issuer"] = json!(wrong);
        }
        ServiceMismatch::Backend => payload["service"]["backend_id"] = json!(Uuid::now_v7()),
        ServiceMismatch::GrantDigest => {
            payload["grant"]["request_digest"] = json!("ee".repeat(32));
        }
    }
}

fn close_target_session(fixture: &Fixture) -> TestResult<()> {
    // Forge currently exposes open/resolve through ForgeControl but no close
    // command. Use the existing typed durable Session owner CAS to set up the
    // closed-session fixture; no SQL or production state is touched.
    let mut catalog = AgentSessionCatalog::open(fixture.root.join("agent-sessions.sqlite3"))?;
    let current = catalog
        .resolve(fixture.session_id, AuthenticatedPrincipal::TrustedStdio)?
        .ok_or("fixture target Session is missing")?;
    if current.state() != AgentSessionState::Open {
        return Err("fixture target Session was not open before close setup".into());
    }
    let closed = catalog.close(
        fixture.session_id,
        AuthenticatedPrincipal::TrustedStdio,
        current.revision(),
        timestamp_now()?,
    )?;
    if closed.state() != AgentSessionState::Closed {
        return Err("fixture target Session did not close".into());
    }
    Ok(())
}

fn source_request(
    fixture: &Fixture,
    destination: Uuid,
    preparation_id: Uuid,
    seed: u128,
) -> TestResult<HomeTransferSourceRequest> {
    let scope = HomeTransferSourceScope::new(
        fixture.scope.workspace_id(),
        WorkspaceRevision::new(fixture.scope.workspace_revision().get())?,
        ForgeBackendId::from_uuid(BACKEND_ID),
        destination,
    )?;
    let witness = HomeTransferSourceWitness::new(preparation_id, [0xA1; 32], [0xB2; 32])?;
    let subject = HomeTransferSourceSubject::new(
        Uuid::from_u128(seed),
        1,
        Uuid::from_u128(seed + 1),
        Uuid::from_u128(seed + 2),
        Uuid::from_u128(seed + 3),
        Uuid::from_u128(seed + 4),
        1,
        1,
    )?;
    let binding = HomeTransferSourceBinding::new(
        fixture.activity_id,
        fixture.agent_id,
        fixture.session_id,
        AuthenticatedPrincipal::TrustedStdio,
    )?;
    Ok(HomeTransferSourceRequest::new(
        witness,
        scope,
        subject,
        vec![fixture.session_id],
        vec![binding],
    )?)
}

fn request_with_new_preparation(
    request: &HomeTransferSourceRequest,
    preparation_id: Uuid,
) -> TestResult<HomeTransferSourceRequest> {
    Ok(HomeTransferSourceRequest::new(
        HomeTransferSourceWitness::new(preparation_id, [0xA3; 32], [0xB4; 32])?,
        request.scope(),
        request.subject(),
        request.sessions().to_vec(),
        request.bindings().to_vec(),
    )?)
}

fn bootstrap_extra_activity(fixture: &Fixture) -> TestResult<ActivityId> {
    let activity_id = ActivityId::from_uuid(Uuid::now_v7());
    let now = timestamp_now()?;
    let runtime_instance_id = forge_domain::RuntimeInstanceId::from_uuid(Uuid::now_v7());
    let _bootstrap = fixture.client.bootstrap_activity(
        fixture.scope.clone(),
        activity_id,
        runtime_instance_id,
        now,
        add_millis(now, 120_000)?,
    )?;
    Ok(activity_id)
}

fn freeze_reference(fixture: &Fixture) -> TestResult<Value> {
    let delegation = fixture
        .client
        .agent_operations_delegation(forge_control::AgentOperationsDelegationReadRequest {
            scope: fixture.scope.clone(),
        })?
        .ok_or("fixture delegation seal is missing")?;
    Ok(json!({
        "migration_id": delegation.migration_id(),
        "expected_freeze_revision": i64::try_from(delegation.freeze().revision())?,
    }))
}

fn agent_binding_reservation_payload(
    fixture: &Fixture,
    destination: Uuid,
    reference: &Value,
    request_id: Uuid,
    activity_id: ActivityId,
    agent_id: AgentInstanceId,
    session_id: AgentSessionId,
) -> TestResult<Value> {
    let requested_at = timestamp_now()?;
    let observed_at = timestamp_now()?;
    Ok(json!({
        "scope": scope_json(fixture),
        "issuer_id": ISSUER_ID,
        "destination_id": destination,
        "reference": reference,
        "reservation": {
            "request_id": request_id,
            "activity_id": activity_id.into_uuid(),
            "agent_id": agent_id.into_uuid(),
            "session_id": session_id.into_uuid(),
            "principal": {"kind": "trusted_stdio"},
            "requested_at_ms": requested_at.get(),
        },
        "observed_at_ms": observed_at.get(),
    }))
}

fn agent_binding_reservation_get_payload(
    fixture: &Fixture,
    destination: Uuid,
    request_id: Uuid,
    session_id: AgentSessionId,
) -> Value {
    json!({
        "scope": scope_json(fixture),
        "issuer_id": ISSUER_ID,
        "destination_id": destination,
        "request_id": request_id,
        "session_id": session_id.into_uuid(),
        "principal": {"kind": "trusted_stdio"},
    })
}

fn request_json(request: &HomeTransferSourceRequest) -> Value {
    let witness = request.witness();
    let scope = request.scope();
    let subject = request.subject();
    json!({
        "witness": {
            "preparation_id": witness.preparation_id(),
            "intent_digest": forge_backend::events::hex_encode(witness.intent_digest()),
            "preparation_digest": forge_backend::events::hex_encode(witness.preparation_digest()),
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
        "sessions": request.sessions().iter().map(|session|session.into_uuid()).collect::<Vec<_>>(),
        "bindings": request.bindings().iter().map(|binding|json!({
            "activity_id":binding.activity_id().into_uuid(),
            "agent_id":binding.agent_id().into_uuid(),
            "session_id":binding.session_id().into_uuid(),
            "principal":{"kind":"trusted_stdio"}
        })).collect::<Vec<_>>(),
        "request_digest": forge_backend::events::hex_encode(request.request_digest().as_bytes()),
    })
}

fn base_payload(fixture: &Fixture, destination: Uuid) -> Value {
    json!({
        "scope": scope_json(fixture),
        "service": {
            "issuer": ISSUER_ID,
            "backend_id": BACKEND_ID,
            "destination_id": destination,
        }
    })
}

fn prepare_payload(
    fixture: &Fixture,
    destination: Uuid,
    request: &HomeTransferSourceRequest,
    action: &str,
) -> TestResult<Value> {
    let mut payload = base_payload(fixture, destination);
    let now = timestamp_now()?;
    payload["request"] = request_json(request);
    payload["grant"] = json!({
        "issuer": ISSUER_ID,
        "action": action,
        "request_digest": forge_backend::events::hex_encode(request.request_digest().as_bytes()),
        "issued_at_ms": now.get(),
        "expires_at_ms": add_millis(now, 60_000)?.get(),
    });
    Ok(payload)
}

fn get_payload(fixture: &Fixture, destination: Uuid, request: &HomeTransferSourceRequest) -> Value {
    let mut payload = base_payload(fixture, destination);
    payload["preparation_id"] = json!(request.witness().preparation_id());
    payload["request_digest"] = json!(forge_backend::events::hex_encode(
        request.request_digest().as_bytes()
    ));
    payload
}

async fn get_until_record(
    running: &HttpBindingFixture,
    destination: Uuid,
    request: &HomeTransferSourceRequest,
) -> TestResult<Value> {
    let payload = get_payload(&running.fixture, destination, request);
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut last_response = Value::Null;
        for _ in 0..100 {
            let (status, response) =
                super::post_command(running.address, "home_transfer.source_get", payload.clone())
                    .await?;
            if status == 200 {
                let record = response.get("result").and_then(|result| result.get("record"));
                if let Some(record) = record.filter(|record| record.is_object()) {
                    return Ok(record.clone());
                }
                last_response = response;
            } else if status == 202 && response["error"]["code"] == "UNKNOWN_OUTCOME" {
                last_response = response;
            } else {
                return Err(format!("exact Home source Get failed ({status}): {response}").into());
            }
            tokio::task::yield_now().await;
        }
        Err(format!(
            "Home source record was not readable by exact identity after bounded polling: {last_response}"
        )
        .into())
    })
    .await
    .map_err(|_| "Home source exact Get polling exceeded its five second bound")?
}

fn assert_source_record(
    record: &Value,
    request: &HomeTransferSourceRequest,
    state: &str,
    capsule_expected: bool,
) {
    assert_eq!(
        record["request_digest"],
        json!(forge_backend::events::hex_encode(
            request.request_digest().as_bytes()
        ))
    );
    assert_eq!(
        record["request"]["witness"]["preparation_id"],
        json!(request.witness().preparation_id())
    );
    assert_eq!(record["state"], json!(state));
    assert_eq!(
        record["inventory_payload_base64"].is_string(),
        capsule_expected
    );
    assert_eq!(record["inventory_digest"].is_string(), capsule_expected);
    assert!(record["outcome_digest"].is_string());
    assert!(record["delegation_witness"]["migration_id"].is_string());
    assert!(record["delegation_witness"]["delegation_digest"].is_string());
}
