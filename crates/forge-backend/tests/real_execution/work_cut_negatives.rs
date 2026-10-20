//! Real HTTP negative coverage for the leadership Work Cut boundary.

use super::*;
use forge_domain::{AuthenticatedPrincipal, OpenAgentSession, WorkCutRequest};
use serde_json::{Value, json};
use uuid::Uuid;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_http_work_cut_rejects_service_grant_and_drain_inputs_without_capture()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = prepare_fixture()?;
    let destination = delegated_destination_id(&fixture)?;
    let elected = forge_domain::AgentSessionId::from_uuid(Uuid::now_v7());
    let _elected_session = fixture.client.agent_session_open(OpenAgentSession::new(
        elected,
        forge_domain::AgentSessionOpenRequestId::from_uuid(Uuid::now_v7()),
        AuthenticatedPrincipal::TrustedStdio,
        timestamp_now()?,
    ))?;
    let cache = fixture.root.join("work-cut-negative-cache");
    fs::create_dir(&cache)?;
    let state = assemble_fixture(backend_config()?, &fixture, &cache, destination)?;
    let address = serve(state.clone()).await?;

    let result = async {
        let now = timestamp_now()?;
        assert_roster_bounds(&fixture, address, destination, elected, now).await?;
        let wrong_grant_request = super::cut_request(&fixture, destination, elected, Uuid::now_v7())?;
        let mut wrong_grant = valid_prepare(&fixture, destination, &wrong_grant_request, now)?;
        wrong_grant["grant"]["issuer"] = json!(Uuid::now_v7());
        let (status, reply) = post_command(address, "work_cut.prepare", wrong_grant).await?;
        assert_ne!(status, 200, "{reply}");
        assert_eq!(reply["error"]["readback"], Value::Null);
        assert_absent(&fixture, address, destination, wrong_grant_request.cut_id(), wrong_grant_request.request_digest()).await?;
        let expired_request = super::cut_request(&fixture, destination, elected, Uuid::now_v7())?;
        let mut expired = super::base_payload(&fixture, destination);
        expired["request"] = super::request_json(&expired_request);
        expired["grant"] = json!({
            "issuer": ISSUER_ID,
            "request_digest": forge_backend::events::hex_encode(expired_request.request_digest().as_bytes()),
            "issued_at_ms": now.get() - 60_000,
            "expires_at_ms": now.get() - 1,
        });
        let (status, _) = post_command(address, "work_cut.prepare", expired).await?;
        assert_ne!(status, 200, "expired grant unexpectedly captured a Work Cut");
        assert_absent(&fixture, address, destination, expired_request.cut_id(), expired_request.request_digest()).await?;

        let future_request = super::cut_request(&fixture, destination, elected, Uuid::now_v7())?;
        let mut future = super::base_payload(&fixture, destination);
        future["request"] = super::request_json(&future_request);
        future["grant"] = json!({
            "issuer": ISSUER_ID,
            "request_digest": forge_backend::events::hex_encode(future_request.request_digest().as_bytes()),
            "issued_at_ms": now.get() + 60_000,
            "expires_at_ms": now.get() + 120_000,
        });
        let (status, _) = post_command(address, "work_cut.prepare", future).await?;
        assert_ne!(status, 200, "future grant unexpectedly captured a Work Cut");
        assert_absent(&fixture, address, destination, future_request.cut_id(), future_request.request_digest()).await?;

        let wrong_issuer_request =
            super::cut_request(&fixture, destination, elected, Uuid::now_v7())?;
        let mut wrong_issuer = valid_prepare(&fixture, destination, &wrong_issuer_request, now)?;
        wrong_issuer["service"]["issuer"] = json!(Uuid::now_v7());
        let (status, _) = post_command(address, "work_cut.prepare", wrong_issuer).await?;
        assert_ne!(status, 200, "wrong issuer unexpectedly reached Work Cut owner");
        assert_absent(
            &fixture,
            address,
            destination,
            wrong_issuer_request.cut_id(),
            wrong_issuer_request.request_digest(),
        )
        .await?;

        let wrong_backend_request =
            super::cut_request(&fixture, destination, elected, Uuid::now_v7())?;
        let mut wrong_backend = valid_prepare(&fixture, destination, &wrong_backend_request, now)?;
        wrong_backend["service"]["backend_id"] = json!(Uuid::now_v7());
        let (status, _) = post_command(address, "work_cut.prepare", wrong_backend).await?;
        assert_ne!(status, 200, "wrong backend unexpectedly reached Work Cut owner");
        assert_absent(
            &fixture,
            address,
            destination,
            wrong_backend_request.cut_id(),
            wrong_backend_request.request_digest(),
        )
        .await?;

        let zero_digest_request =
            super::cut_request(&fixture, destination, elected, Uuid::now_v7())?;
        let mut zero_get = super::base_payload(&fixture, destination);
        zero_get["cut_id"] = json!(zero_digest_request.cut_id());
        zero_get["request_digest"] = json!("00".repeat(32));
        let (status, _) = post_command(address, "work_cut.get", zero_get).await?;
        assert_ne!(status, 200, "zero Work Cut digest was accepted");

        let mut revision_zero = super::base_payload(&fixture, destination);
        revision_zero["cut_id"] = json!(Uuid::now_v7());
        revision_zero["request_digest"] = json!(forge_backend::events::hex_encode(
            zero_digest_request.request_digest().as_bytes()
        ));
        revision_zero["expected_revision"] = json!(0);
        let (status, _) = post_command(address, "work_cut.drain", revision_zero).await?;
        assert_ne!(status, 200, "zero Work Cut drain revision was accepted");
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;

    let shutdown = state.shutdown(Duration::from_secs(5)).await;
    let cleanup = fixture.shutdown();
    result?;
    assert!(shutdown.is_successful());
    cleanup?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_http_work_cut_same_cut_metadata_conflict_preserves_original_receipt()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = prepare_fixture()?;
    let destination = delegated_destination_id(&fixture)?;
    let elected = forge_domain::AgentSessionId::from_uuid(Uuid::now_v7());
    let _elected_session = fixture.client.agent_session_open(OpenAgentSession::new(
        elected,
        forge_domain::AgentSessionOpenRequestId::from_uuid(Uuid::now_v7()),
        AuthenticatedPrincipal::TrustedStdio,
        timestamp_now()?,
    ))?;
    let cache = fixture.root.join("work-cut-metadata-negative-cache");
    fs::create_dir(&cache)?;
    let state = assemble_fixture(backend_config()?, &fixture, &cache, destination)?;
    let address = serve(state.clone()).await?;

    let result = async {
        let now = timestamp_now()?;
        let original = super::cut_request(&fixture, destination, elected, Uuid::now_v7())?;
        let prepare = valid_prepare(&fixture, destination, &original, now)?;
        let prepared = post_ok(address, "work_cut.prepare", prepare.clone()).await?;
        let original_digest = original.request_digest();

        let changed = super::cut_request(&fixture, destination, elected, original.cut_id())?;
        assert_ne!(changed.request_digest(), original_digest);
        let changed_prepare = valid_prepare(&fixture, destination, &changed, now)?;
        let (status, _) = post_command(address, "work_cut.prepare", changed_prepare).await?;
        assert_ne!(
            status, 200,
            "changed same-cut metadata unexpectedly replayed"
        );

        let mut get = super::base_payload(&fixture, destination);
        get["cut_id"] = json!(original.cut_id());
        get["request_digest"] = json!(forge_backend::events::hex_encode(
            original_digest.as_bytes()
        ));
        let history = post_ok(address, "work_cut.get", get).await?;
        assert_eq!(history["found"], true);
        assert_eq!(
            history["record"]["snapshot_digest"],
            prepared["record"]["snapshot_digest"]
        );
        assert_eq!(
            history["record"]["request"]["request_digest"],
            forge_backend::events::hex_encode(original_digest.as_bytes())
        );
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;

    let shutdown = state.shutdown(Duration::from_secs(5)).await;
    let cleanup = fixture.shutdown();
    result?;
    assert!(shutdown.is_successful());
    cleanup?;
    Ok(())
}

async fn assert_roster_bounds(
    fixture: &Fixture,
    address: SocketAddr,
    destination: Uuid,
    elected: forge_domain::AgentSessionId,
    now: forge_domain::TimestampMillis,
) -> Result<(), Box<dyn std::error::Error>> {
    for (field, count) in [("sessions", 129), ("bindings", 257)] {
        let request = super::cut_request(fixture, destination, elected, Uuid::now_v7())?;
        let mut oversized = valid_prepare(fixture, destination, &request, now)?;
        let element = oversized["request"][field][0].clone();
        oversized["request"][field] = json!(vec![element; count]);
        let (status, reply) = post_command(address, "work_cut.prepare", oversized).await?;
        assert_eq!(status, 400, "{reply}");
        assert_eq!(reply["error"]["code"], "INVALID_INPUT");
        assert_eq!(reply["error"]["readback"], Value::Null);
        assert_absent(
            fixture,
            address,
            destination,
            request.cut_id(),
            request.request_digest(),
        )
        .await?;
    }
    Ok(())
}

fn valid_prepare(
    fixture: &Fixture,
    destination: Uuid,
    request: &WorkCutRequest,
    now: forge_domain::TimestampMillis,
) -> Result<Value, Box<dyn std::error::Error>> {
    let mut payload = super::base_payload(fixture, destination);
    payload["request"] = super::request_json(request);
    payload["grant"] = json!({
        "issuer": ISSUER_ID,
        "request_digest": forge_backend::events::hex_encode(request.request_digest().as_bytes()),
        "issued_at_ms": now.get(),
        "expires_at_ms": super::add_millis(now, 60_000)?.get(),
    });
    Ok(payload)
}

async fn assert_absent(
    fixture: &Fixture,
    address: SocketAddr,
    destination: Uuid,
    cut_id: Uuid,
    request_digest: forge_domain::WorkCutRequestDigest,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut get = super::base_payload(fixture, destination);
    get["cut_id"] = json!(cut_id);
    get["request_digest"] = json!(forge_backend::events::hex_encode(request_digest.as_bytes()));
    let response = post_ok(address, "work_cut.get", get).await?;
    assert_eq!(response["found"], false);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_http_work_cut_closed_binding_rejects_new_capture_but_history_remains_readable()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = prepare_fixture()?;
    let destination = delegated_destination_id(&fixture)?;
    let elected = forge_domain::AgentSessionId::from_uuid(Uuid::now_v7());
    let _opened = fixture.client.agent_session_open(OpenAgentSession::new(
        elected,
        forge_domain::AgentSessionOpenRequestId::from_uuid(Uuid::now_v7()),
        AuthenticatedPrincipal::TrustedStdio,
        timestamp_now()?,
    ))?;
    let cache = fixture.root.join("cut-closed-cache");
    fs::create_dir(&cache)?;
    let state = assemble_fixture(backend_config()?, &fixture, &cache, destination)?;
    let address = serve(state.clone()).await?;
    let result = async {
        let now = timestamp_now()?;
        let original = super::cut_request(&fixture, destination, elected, Uuid::now_v7())?;
        let prepared = post_ok(
            address,
            "work_cut.prepare",
            valid_prepare(&fixture, destination, &original, now)?,
        )
        .await?;
        let live =
            fixture
                .client
                .agent_session_resolve(forge_control::AgentSessionResolveRequest {
                    session_id: fixture.session_id,
                    principal: AuthenticatedPrincipal::TrustedStdio,
                })?;
        let catalog_path = fixture.root.join("agent-sessions.sqlite3");
        let mut catalog = forge_persistence::AgentSessionCatalog::open_existing(&catalog_path)?
            .ok_or("session catalog missing")?;
        let _closed = catalog.close(
            fixture.session_id,
            AuthenticatedPrincipal::TrustedStdio,
            live.revision(),
            timestamp_now()?,
        )?;
        drop(catalog);
        let fresh = super::cut_request(&fixture, destination, elected, Uuid::now_v7())?;
        let payload = valid_prepare(&fixture, destination, &fresh, now)?;
        let (status, reply) = post_command(address, "work_cut.prepare", payload.clone()).await?;
        assert_ne!(status, 200, "{reply}");
        assert_eq!(reply["error"]["readback"], Value::Null);
        assert_absent(
            &fixture,
            address,
            destination,
            fresh.cut_id(),
            fresh.request_digest(),
        )
        .await?;
        let mut inventory = payload;
        inventory
            .as_object_mut()
            .ok_or("inventory body missing")?
            .remove("grant");
        let (status, reply) = post_command(address, "work_cut.inventory", inventory).await?;
        assert_ne!(status, 200, "{reply}");
        let mut read = super::base_payload(&fixture, destination);
        read["cut_id"] = json!(original.cut_id());
        read["request_digest"] = json!(forge_backend::events::hex_encode(
            original.request_digest().as_bytes()
        ));
        let history = post_ok(address, "work_cut.get", read).await?;
        assert_eq!(history["record"], prepared["record"]);
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;
    let shutdown = state.shutdown(Duration::from_secs(5)).await;
    let cleanup = fixture.shutdown();
    result?;
    assert!(shutdown.is_successful());
    cleanup?;
    Ok(())
}
