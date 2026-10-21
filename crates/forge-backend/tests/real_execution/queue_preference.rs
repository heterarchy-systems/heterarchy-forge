//! Real loopback HTTP proof for Workspace queue-preference replacement.
//!
//! The preference row remains owned by the Workspace SQLite store and the
//! effective queue remains owned by the native control worker.  These tests
//! exercise the HTTP adapter across both authorities and keep the saved result
//! distinct from the separate runtime observation.

use super::binding_lifecycle::{HttpBindingFixture, open_command_without_read};
use super::lease_readback::{post_ok, scope_json};
use super::*;

use forge_control::ActivityReadRequest;
use forge_domain::ExecutionListLimit;
use forge_persistence::WorkspaceStore;
use forge_workspace::WorkspaceStateLayout;
use serde_json::{Value, json};
use tokio::time::timeout;

const QUEUE_PREFERENCE_OP: &str = "workspace.queue.settings.replace";

struct QueueHttpFixture {
    fixture: Fixture,
    state: forge_backend::AppState,
    address: SocketAddr,
}

impl QueueHttpFixture {
    async fn start() -> Result<Self, Box<dyn std::error::Error>> {
        let fixture = prepare_fixture()?;
        let product_cache_root = fixture.root.join("product-cache-queue-preference");
        fs::create_dir_all(&product_cache_root)?;
        let destination_id = delegated_destination_id(&fixture)?;
        let state = super::assemble_fixture(
            backend_config()?,
            &fixture,
            &product_cache_root,
            destination_id,
        )?;
        let address = serve(state.clone()).await?;
        Ok(Self {
            fixture,
            state,
            address,
        })
    }

    async fn finish(self) -> Result<(), Box<dyn std::error::Error>> {
        let Self {
            fixture,
            state,
            address: _,
        } = self;
        let shutdown = state.shutdown(Duration::from_secs(5)).await;
        let fixture_result = fixture.shutdown();
        if !shutdown.is_successful() {
            return Err("queue preference backend shutdown was incomplete".into());
        }
        fixture_result
    }
}

fn native_saved_settings(
    fixture: &Fixture,
) -> Result<forge_persistence::RegisteredQueueSettings, Box<dyn std::error::Error>> {
    let layout = WorkspaceStateLayout::inspect_existing(&fixture.workspace_root)?
        .ok_or("Workspace layout missing during queue preference readback")?;
    let store = WorkspaceStore::open_existing(&layout)?;
    store
        .get_workspace_queue_settings()?
        .ok_or_else(|| "queue preference row missing after committed mutation".into())
}

fn scope_payload(fixture: &Fixture) -> Value {
    scope_json(fixture)
}

fn preference_payload(fixture: &Fixture, capacity: u16, expected_revision: Value) -> Value {
    let mut payload = json!({
        "scope": scope_payload(fixture),
        "capacity": capacity,
    });
    payload["expected_revision"] = expected_revision;
    payload
}

fn assert_request_id(response: &Value, request_id: Uuid) {
    assert_eq!(response["request_id"], json!(request_id));
}

fn assert_failure(status: u16, response: &Value, request_id: Uuid, code: &str) {
    assert_ne!(status, 200, "unexpected successful response: {response}");
    assert_eq!(response["ok"], false);
    assert_request_id(response, request_id);
    assert_eq!(response["error"]["code"], code, "response: {response}");
}

fn assert_saved_preference(
    result: &Value,
    fixture: &Fixture,
    capacity: u16,
    revision: u64,
    created_at_ms: Option<i64>,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(result["scope"], scope_payload(fixture));
    assert_eq!(result["save_status"], "committed");
    assert_eq!(result["retry_authorized"], false);
    assert_eq!(result["request_equivalence_proven"], false);
    assert_eq!(result["observation"], "separate_non_atomic_reads");

    let saved = &result["saved_preference"];
    assert_eq!(saved["capacity"], json!(capacity));
    assert_eq!(saved["revision"], json!(revision));
    assert!(saved["capacity_preset"].as_str().is_some());
    let created = saved["created_at_ms"]
        .as_i64()
        .ok_or("saved preference created_at_ms missing")?;
    let updated = saved["updated_at_ms"]
        .as_i64()
        .ok_or("saved preference updated_at_ms missing")?;
    assert!(
        created >= 1,
        "server-owned save timestamp was not refreshed"
    );
    assert!(updated >= created);
    if let Some(previous_created) = created_at_ms {
        assert_eq!(created, previous_created);
    }

    let application_status = result["runtime_application"]["status"]
        .as_str()
        .ok_or("runtime application status missing")?;
    assert!(matches!(
        application_status,
        "matched" | "different_or_pending" | "unavailable" | "scope_changed"
    ));
    let effective = &result["effective_runtime"];
    if !effective.is_null() {
        assert!(effective["capacity"].as_u64().is_some());
        assert!(effective["generation"].as_u64().is_some());
        assert!(effective["pending"].as_u64().is_some());
        assert!(effective["draining"].as_bool().is_some());
    }
    if application_status == "matched" {
        assert_eq!(effective["capacity"], json!(capacity));
        assert_eq!(effective["source"], "user_provided");
        assert_eq!(effective["persisted_revision"], json!(revision));
        assert_eq!(effective["draining"], false);
    }
    Ok(())
}

async fn replace(
    address: SocketAddr,
    fixture: &Fixture,
    capacity: u16,
    expected_revision: Value,
) -> Result<(u16, Value, Uuid), Box<dyn std::error::Error>> {
    let request_id = Uuid::now_v7();
    let (status, response) = post_with_auth(
        address,
        QUEUE_PREFERENCE_OP,
        preference_payload(fixture, capacity, expected_revision),
        request_id,
        Some(SECRET),
    )
    .await?;
    assert_request_id(&response, request_id);
    Ok((status, response, request_id))
}

async fn workspace_queue_status(
    address: SocketAddr,
    fixture: &Fixture,
) -> Result<Value, Box<dyn std::error::Error>> {
    let result = post_ok(
        address,
        "workspace.queue.status",
        json!({"scope": scope_payload(fixture)}),
    )
    .await?;
    assert_eq!(result["scope"], scope_payload(fixture));
    Ok(result)
}

fn assert_queue_is_drained(status: &Value) {
    assert_eq!(status["draining"], false);
    assert_eq!(status["pending"], 0);
    assert!(status["active"].as_bool().is_some());
    assert!(status["rejected_count"].as_u64().is_some());
    assert!(status["high_water"].as_u64().is_some());
}

fn assert_queue_counters_preserved(
    before: &Value,
    after: &Value,
) -> Result<(), Box<dyn std::error::Error>> {
    for field in ["pending", "rejected_count"] {
        assert_eq!(before[field], after[field], "queue counter changed {field}");
    }
    for lane in [
        "liveness",
        "authority_control",
        "interactive",
        "work",
        "background",
    ] {
        assert_eq!(
            before["per_lane"][lane], after["per_lane"][lane],
            "queue lane counter changed {lane}"
        );
    }
    assert_eq!(
        before["global"]["pending"], after["global"]["pending"],
        "global pending counter changed"
    );
    assert_eq!(
        before["global"]["rejected_count"], after["global"]["rejected_count"],
        "global rejected counter changed"
    );
    for (field, before_counter, after_counter) in [
        ("high_water", &before["high_water"], &after["high_water"]),
        (
            "global_high_water",
            &before["global"]["high_water"],
            &after["global"]["high_water"],
        ),
    ] {
        let before_value = before_counter
            .as_u64()
            .ok_or_else(|| format!("queue counter missing {field}"))?;
        let after_value = after_counter
            .as_u64()
            .ok_or_else(|| format!("queue counter missing {field}"))?;
        assert!(
            after_value >= before_value,
            "queue counter regressed {field}"
        );
        assert!(
            after_value <= 256,
            "queue counter exceeded native bound {field}"
        );
    }
    Ok(())
}

fn read_activity(
    fixture: &Fixture,
) -> Result<forge_control::ActivityReadSnapshot, Box<dyn std::error::Error>> {
    Ok(fixture.client.activity_read(ActivityReadRequest {
        scope: fixture.scope.clone(),
        activity_id: fixture.activity_id,
    })?)
}

fn read_pending_approvals(
    fixture: &Fixture,
) -> Result<Vec<forge_domain::RegisteredApprovalRequest>, Box<dyn std::error::Error>> {
    Ok(fixture
        .client
        .list_pending_approvals(fixture.scope.clone(), ExecutionListLimit::DEFAULT)?)
}

fn read_agent(
    fixture: &Fixture,
) -> Result<forge_domain::RegisteredAgentInstance, Box<dyn std::error::Error>> {
    let layout = WorkspaceStateLayout::inspect_existing(&fixture.workspace_root)?
        .ok_or("Workspace layout missing during Agent readback")?;
    let store = WorkspaceStore::open_existing(&layout)?;
    store
        .get_agent(fixture.agent_id)?
        .ok_or_else(|| "fixture Agent missing during queue preference proof".into())
}

async fn assert_insert_and_cas(
    running: &QueueHttpFixture,
    before_status: &Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = &running.fixture;
    let address = running.address;
    let (status, response, request_id) = replace(address, fixture, 64, Value::Null).await?;
    assert_eq!(status, 200, "insert response: {response}");
    assert_eq!(response["ok"], true);
    assert_saved_preference(&response["result"], fixture, 64, 1, None)?;
    let inserted_created = response["result"]["saved_preference"]["created_at_ms"]
        .as_i64()
        .ok_or("initial queue preference timestamp missing")?;
    assert_eq!(response["request_id"], json!(request_id));

    let persisted = native_saved_settings(fixture)?;
    assert_eq!(persisted.capacity().slots(), 64);
    assert_eq!(persisted.revision().get(), 1);
    assert_eq!(persisted.created_at().get(), inserted_created);
    assert_eq!(persisted.updated_at().get(), inserted_created);

    let read = post_ok(
        address,
        "workspace.queue.settings",
        json!({"scope": scope_payload(fixture)}),
    )
    .await?;
    assert_eq!(read["saved_preference"]["capacity"], 64);
    assert_eq!(read["saved_preference"]["revision"], 1);

    let (status, null_on_existing, request_id) =
        replace(address, fixture, 128, Value::Null).await?;
    assert_failure(status, &null_on_existing, request_id, "STALE_REVISION");
    let after_null = native_saved_settings(fixture)?;
    assert_eq!(after_null.capacity().slots(), 64);
    assert_eq!(after_null.revision().get(), 1);

    let (status, response, request_id) = replace(address, fixture, 128, json!(1)).await?;
    assert_eq!(status, 200, "CAS update response: {response}");
    assert_eq!(response["ok"], true);
    assert_saved_preference(&response["result"], fixture, 128, 2, Some(inserted_created))?;
    assert_eq!(response["request_id"], json!(request_id));

    let reopened = native_saved_settings(fixture)?;
    assert_eq!(reopened.capacity().slots(), 128);
    assert_eq!(reopened.revision().get(), 2);
    assert_eq!(reopened.created_at().get(), inserted_created);
    assert!(reopened.updated_at().get() >= inserted_created);

    let after_status = workspace_queue_status(address, fixture).await?;
    assert_queue_is_drained(&after_status);
    // `active` is a live worker observation and may change between these
    // separate queue-status reads. Durable queue counters and drain state are
    // asserted below; this volatile bit is not a persistence invariant.
    assert!(matches!(
        after_status["source"].as_str(),
        Some("default" | "user_provided")
    ));
    assert!(after_status["generation"].as_u64().is_some());
    let persisted_revision = &after_status["persisted_revision"];
    if let Some(persisted_revision) = persisted_revision.as_u64() {
        assert_eq!(persisted_revision, 2);
        assert_eq!(after_status["capacity"], 128);
        assert_eq!(after_status["source"], "user_provided");
    } else {
        assert!(persisted_revision.is_null());
    }
    assert_queue_counters_preserved(before_status, &after_status)?;
    Ok(())
}

fn assert_preserved_state(
    fixture: &Fixture,
    before_activity: &forge_control::ActivityReadSnapshot,
    before_agent: &forge_domain::RegisteredAgentInstance,
    before_approvals: &[forge_domain::RegisteredApprovalRequest],
) -> Result<(), Box<dyn std::error::Error>> {
    let activity = read_activity(fixture)?;
    let agent = read_agent(fixture)?;
    let approvals = read_pending_approvals(fixture)?;
    assert_eq!(activity, *before_activity);
    assert_eq!(agent, *before_agent);
    assert_eq!(approvals.as_slice(), before_approvals);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_http_queue_preference_insert_cas_reopen_and_preserve_state()
-> Result<(), Box<dyn std::error::Error>> {
    let running = QueueHttpFixture::start().await?;
    let before_status = workspace_queue_status(running.address, &running.fixture).await?;
    let before_activity = read_activity(&running.fixture)?;
    let before_agent = read_agent(&running.fixture)?;
    let before_approvals = read_pending_approvals(&running.fixture)?;

    let result = assert_insert_and_cas(&running, &before_status).await;
    let state_result = assert_preserved_state(
        &running.fixture,
        &before_activity,
        &before_agent,
        &before_approvals,
    );
    let finish = running.finish().await;
    result?;
    state_result?;
    finish
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_http_queue_preference_rejects_invalid_stale_foreign_and_unauthenticated_inputs()
-> Result<(), Box<dyn std::error::Error>> {
    let running = QueueHttpFixture::start().await?;
    let address = running.address;
    let fixture = &running.fixture;
    let result = async {
        assert_input_rejections(address, fixture).await?;
        assert_stale_and_foreign_rejections(address, fixture).await?;
        assert_auth_rejections(address, fixture).await
    }
    .await;
    let finish = running.finish().await;
    result?;
    finish
}

fn post_with_auth_request(
    op: &str,
    payload: &Value,
    request_id: Uuid,
    bearer: Option<&str>,
) -> String {
    let body = json!({
        "forge_api": 1,
        "request_id": request_id,
        "op": op,
        "payload": payload,
    })
    .to_string();
    let authorization = match bearer {
        Some(secret) => format!("Authorization: Bearer {secret}\r\n"),
        None => String::new(),
    };
    format!(
        "POST /api/v1/commands/{op} HTTP/1.1\r\nHost: 127.0.0.1\r\n{authorization}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

async fn post_with_auth(
    address: SocketAddr,
    op: &str,
    payload: Value,
    request_id: Uuid,
    bearer: Option<&str>,
) -> Result<(u16, Value), Box<dyn std::error::Error>> {
    let request = post_with_auth_request(op, &payload, request_id, bearer);
    exchange_json(address, &request).await
}

async fn assert_input_rejections(
    address: SocketAddr,
    fixture: &Fixture,
) -> Result<(), Box<dyn std::error::Error>> {
    let (status, invalid_capacity, request_id) = replace(address, fixture, 31, Value::Null).await?;
    assert_failure(status, &invalid_capacity, request_id, "INVALID_INPUT");

    let (status, invalid_revision, request_id) = replace(address, fixture, 64, json!(0)).await?;
    assert_failure(status, &invalid_revision, request_id, "INVALID_INPUT");

    let mut missing_revision = preference_payload(fixture, 64, Value::Null);
    missing_revision
        .as_object_mut()
        .ok_or("queue preference payload is not an object")?
        .remove("expected_revision");
    let request_id = Uuid::now_v7();
    let (status, response) = post_with_auth(
        address,
        QUEUE_PREFERENCE_OP,
        missing_revision,
        request_id,
        Some(SECRET),
    )
    .await?;
    assert_failure(status, &response, request_id, "INVALID_INPUT");

    let mut caller_clock = preference_payload(fixture, 128, json!(1));
    caller_clock["observed_at_ms"] = json!(1);
    let request_id = Uuid::now_v7();
    let (status, response) = post_with_auth(
        address,
        QUEUE_PREFERENCE_OP,
        caller_clock,
        request_id,
        Some(SECRET),
    )
    .await?;
    assert_failure(status, &response, request_id, "INVALID_INPUT");
    Ok(())
}

async fn assert_stale_and_foreign_rejections(
    address: SocketAddr,
    fixture: &Fixture,
) -> Result<(), Box<dyn std::error::Error>> {
    let (status, initial, _request_id) = replace(address, fixture, 64, Value::Null).await?;
    assert_eq!(status, 200, "initial preference response: {initial}");
    assert_eq!(initial["ok"], true);
    assert_eq!(initial["result"]["saved_preference"]["revision"], 1);

    let (status, stale, request_id) = replace(address, fixture, 128, json!(99)).await?;
    assert_failure(status, &stale, request_id, "STALE_REVISION");
    let unchanged = native_saved_settings(fixture)?;
    assert_eq!(unchanged.capacity().slots(), 64);
    assert_eq!(unchanged.revision().get(), 1);

    let mut wrong_scope = preference_payload(fixture, 128, json!(1));
    wrong_scope["scope"]["workspace_id"] = json!(Uuid::now_v7());
    let request_id = Uuid::now_v7();
    let (status, foreign_scope) = post_with_auth(
        address,
        QUEUE_PREFERENCE_OP,
        wrong_scope,
        request_id,
        Some(SECRET),
    )
    .await?;
    assert_failure(status, &foreign_scope, request_id, "STALE_REVISION");
    let unchanged = native_saved_settings(fixture)?;
    assert_eq!(unchanged.capacity().slots(), 64);
    assert_eq!(unchanged.revision().get(), 1);
    Ok(())
}

async fn assert_auth_rejections(
    address: SocketAddr,
    fixture: &Fixture,
) -> Result<(), Box<dyn std::error::Error>> {
    for bearer in [None, Some("wrong-credential")] {
        let request_id = Uuid::now_v7();
        let (status, response) = post_with_auth(
            address,
            QUEUE_PREFERENCE_OP,
            preference_payload(fixture, 128, json!(1)),
            request_id,
            bearer,
        )
        .await?;
        assert_ne!(status, 200);
        assert_eq!(response["ok"], false);
        assert_eq!(response["error"]["code"], "AUTH_FAILED");
        assert_eq!(response["request_id"], json!(Uuid::nil()));
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_http_queue_preference_deadline_returns_typed_readback_and_durable_save()
-> Result<(), Box<dyn std::error::Error>> {
    let (running, held, admitted) =
        HttpBindingFixture::start_holding_first_reply(Some(Duration::from_secs(1))).await?;
    let fixture = &running.fixture;
    let payload = preference_payload(fixture, 128, Value::Null);

    let result = async {
        let mut stream =
            open_command_without_read(running.address, QUEUE_PREFERENCE_OP, payload).await?;
        timeout(Duration::from_secs(5), admitted).await??;
        let raw = timeout(Duration::from_secs(5), read_response_bounded(&mut stream)).await??;
        let text = String::from_utf8(raw)?;
        let status = text
            .split_whitespace()
            .nth(1)
            .ok_or("HTTP status missing from queue preference deadline response")?
            .parse::<u16>()?;
        let body = text
            .split_once("\r\n\r\n")
            .ok_or("HTTP body missing from queue preference deadline response")?
            .1;
        let response: Value = serde_json::from_str(body)?;
        assert_eq!(status, 202, "deadline response: {response}");
        assert_eq!(response["ok"], false);
        assert_eq!(response["error"]["code"], "UNKNOWN_OUTCOME");
        assert_eq!(response["error"]["recovery_action"], "read_back");
        assert_eq!(
            response["error"]["readback"]["kind"],
            "workspace_queue_settings"
        );
        assert_eq!(
            response["error"]["readback"]["workspace_id"],
            json!(fixture.scope.workspace_id().into_uuid())
        );
        assert_eq!(
            response["error"]["readback"]["expected_preference_revision"],
            Value::Null
        );
        assert_eq!(response["error"]["readback"]["requested_capacity"], 128);
        drop(stream);
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;

    let release_result: Result<(), Box<dyn std::error::Error>> = held.release_and_wait().await;
    let persisted = native_saved_settings(fixture);
    let finish = running.finish().await;
    result?;
    release_result?;
    let persisted = persisted?;
    assert_eq!(persisted.capacity().slots(), 128);
    assert_eq!(persisted.revision().get(), 1);
    assert!(persisted.created_at().get() >= 1);
    finish
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_http_queue_preference_disconnect_after_admission_reads_back_without_retry()
-> Result<(), Box<dyn std::error::Error>> {
    let (running, held, admitted) = HttpBindingFixture::start_holding_first_reply(None).await?;
    let fixture = &running.fixture;
    let payload = preference_payload(fixture, 128, Value::Null);

    let result = async {
        let mut stream =
            open_command_without_read(running.address, QUEUE_PREFERENCE_OP, payload).await?;
        timeout(Duration::from_secs(5), admitted).await??;
        stream.shutdown().await?;
        drop(stream);
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;

    let release_result = held.release_and_wait().await;
    let persisted = native_saved_settings(fixture);
    let settings = post_ok(
        running.address,
        "workspace.queue.settings",
        json!({"scope": scope_payload(fixture)}),
    )
    .await;
    let retry = replace(running.address, fixture, 128, Value::Null).await;
    let finish = running.finish().await;

    result?;
    release_result?;
    let persisted = persisted?;
    let settings = settings?;
    let (status, retry_response, retry_request_id) = retry?;

    assert_eq!(persisted.capacity().slots(), 128);
    assert_eq!(persisted.revision().get(), 1);
    assert!(persisted.created_at().get() >= 1);
    assert_eq!(settings["saved_preference"]["capacity"], 128);
    assert_eq!(settings["saved_preference"]["revision"], 1);
    assert_eq!(settings["retry_authorized"], false);
    assert_eq!(settings["request_equivalence_proven"], false);
    assert_failure(status, &retry_response, retry_request_id, "STALE_REVISION");
    assert_eq!(retry_response["error"]["retryable"], false);
    assert_eq!(retry_response["error"]["readback"], Value::Null);
    finish
}
