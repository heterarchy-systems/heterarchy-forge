//! Real listener proofs for queue observations and Activity lifecycle reads.
//!
//! These tests exercise the HTTP adapter over the existing Forge control and
//! Workspace SQLite authorities.  The Activity lifecycle uses a fresh row in
//! the real fixture Workspace so closing it cannot accidentally close the
//! fixture's work Activity or imply process cancellation.

use super::lease_readback::scope_json;
use super::*;

use serde_json::{Value, json};
use uuid::Uuid;

const QUEUE_LANES: [&str; 5] = [
    "liveness",
    "authority_control",
    "interactive",
    "work",
    "background",
];

fn backend_state(fixture: &Fixture) -> Result<forge_backend::AppState, Box<dyn std::error::Error>> {
    let product_cache_root = fixture.root.join("product-cache-api-lifecycle");
    fs::create_dir_all(&product_cache_root)?;
    let destination_id = delegated_destination_id(fixture)?;
    super::assemble_fixture(
        backend_config()?,
        fixture,
        &product_cache_root,
        destination_id,
    )
}

fn command_body(op: &str, payload: &Value, request_id: Uuid) -> String {
    json!({
        "forge_api": 1,
        "request_id": request_id,
        "op": op,
        "payload": payload,
    })
    .to_string()
}

async fn post_with_auth(
    address: SocketAddr,
    op: &str,
    payload: Value,
    request_id: Uuid,
    bearer: Option<&str>,
) -> Result<(u16, Value), Box<dyn std::error::Error>> {
    let body = command_body(op, &payload, request_id);
    let authorization = bearer
        .map(|secret| format!("Authorization: Bearer {secret}\r\n"))
        .unwrap_or_default();
    let request = format!(
        "POST /api/v1/commands/{op} HTTP/1.1\r\nHost: 127.0.0.1\r\n{authorization}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    exchange_json(address, &request).await
}

fn assert_request_id(response: &Value, request_id: Uuid) {
    assert!(
        !request_id.is_nil(),
        "test request identity must be non-nil"
    );
    assert_eq!(response["request_id"], json!(request_id));
}

fn assert_failure(status: u16, response: &Value, request_id: Uuid, error_code: &str) {
    assert_ne!(status, 200, "unexpected successful response: {response}");
    assert_eq!(response["ok"], false);
    assert_request_id(response, request_id);
    assert_eq!(response["error"]["code"], error_code);
}

fn assert_queue_projection(
    projection: &Value,
    expected_scope: Option<&Value>,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(scope) = expected_scope {
        assert_eq!(&projection["scope"], scope);
    }
    assert!(projection["capacity"].as_u64().is_some());
    assert!(projection["capacity_preset"].as_str().is_some());
    assert_eq!(projection["source"], "default");
    assert!(projection["active"].as_bool().is_some());
    let pending = projection["pending"]
        .as_u64()
        .ok_or("queue pending count missing")?;

    let lanes = projection["per_lane"]
        .as_object()
        .ok_or("queue per-lane projection is missing")?;
    let mut total = 0;
    for lane in QUEUE_LANES {
        total += lanes
            .get(lane)
            .and_then(Value::as_u64)
            .ok_or("queue lane count missing")?;
    }
    assert_eq!(total, pending);

    assert!(projection["generation"].as_u64().is_some());
    assert_eq!(projection["draining"], false);
    let ages = projection["oldest_age_micros"]
        .as_object()
        .ok_or("queue oldest-age projection is missing")?;
    for lane in QUEUE_LANES {
        let age = ages.get(lane).ok_or("queue age missing")?;
        assert!(age.is_null() || age.as_u64().is_some(), "lane {lane}");
    }
    assert!(projection["rejected_count"].as_u64().is_some());
    assert!(projection["high_water"].as_u64().is_some());
    assert!(projection["aging_count"].as_u64().is_some());
    assert!(projection["initialized"].as_bool().is_some());

    let global = projection["global"]
        .as_object()
        .ok_or("global queue projection is missing")?;
    assert!(global.get("capacity").and_then(Value::as_u64).is_some());
    assert!(
        global
            .get("capacity_preset")
            .and_then(Value::as_str)
            .is_some()
    );
    assert!(
        global
            .get("pending")
            .and_then(Value::as_u64)
            .is_some_and(|global_pending| global_pending >= pending)
    );
    assert!(
        global
            .get("rejected_count")
            .and_then(Value::as_u64)
            .is_some()
    );
    assert!(global.get("high_water").and_then(Value::as_u64).is_some());
    assert!(
        projection["persisted_revision"].is_null()
            || projection["persisted_revision"].as_u64().is_some()
    );
    Ok(())
}

fn assert_same_queue_state(before: &Value, after: &Value) {
    for field in [
        "capacity",
        "capacity_preset",
        "source",
        "generation",
        "draining",
        "initialized",
        "persisted_revision",
    ] {
        assert_eq!(
            before[field], after[field],
            "queue observation changed {field}"
        );
    }
    for field in ["capacity", "capacity_preset"] {
        assert_eq!(
            before["global"][field], after["global"][field],
            "queue observation changed global {field}"
        );
    }
}

async fn get_activity(
    address: SocketAddr,
    fixture: &Fixture,
    activity_id: Uuid,
) -> Result<Value, Box<dyn std::error::Error>> {
    let request_id = Uuid::now_v7();
    let (status, response) = post_with_auth(
        address,
        "activity.get",
        json!({
            "scope": scope_json(fixture),
            "activity_id": activity_id,
        }),
        request_id,
        Some(SECRET),
    )
    .await?;
    assert_eq!(status, 200, "activity.get response: {response}");
    assert_eq!(response["ok"], true);
    assert_request_id(&response, request_id);
    assert_eq!(response["result"]["scope"], scope_json(fixture));
    assert_eq!(response["result"]["activity_id"], json!(activity_id));
    assert_eq!(response["result"]["found"], true);
    assert_eq!(response["result"]["retry_authorized"], false);
    assert_eq!(response["result"]["request_equivalence_proven"], false);
    Ok(response["result"]["activity"].clone())
}

fn assert_activity_projection(
    activity: &Value,
    activity_id: Uuid,
    workspace_id: Uuid,
    state: &str,
    lease_owner: Option<Uuid>,
    lease_until: Option<i64>,
    lease_revision: i64,
) {
    assert_eq!(activity["activity_id"], json!(activity_id));
    assert_eq!(activity["workspace_id"], json!(workspace_id));
    assert_eq!(activity["state"], state);
    assert!(activity["revision"].as_i64().is_some());
    assert!(activity["created_at_ms"].as_i64().is_some());
    assert!(activity["updated_at_ms"].as_i64().is_some());
    assert_eq!(
        activity["lease_owner_id"],
        lease_owner.map_or(Value::Null, |owner| json!(owner))
    );
    assert_eq!(
        activity["lease_until_ms"],
        lease_until.map_or(Value::Null, |until| json!(until))
    );
    assert_eq!(activity["lease_revision"], json!(lease_revision));
}

fn assert_bootstrap_activity(
    activity: &Value,
    activity_id: Uuid,
    workspace_id: Uuid,
    lease_owner: Uuid,
    lease_until: i64,
    lease_revision: i64,
) {
    assert_eq!(activity["activity_id"], json!(activity_id));
    assert_eq!(activity["workspace_id"], json!(workspace_id));
    assert!(activity["revision"].as_i64().is_some());
    assert_eq!(activity["lease_owner_id"], json!(lease_owner));
    assert_eq!(activity["lease_until_ms"], json!(lease_until));
    assert_eq!(activity["lease_revision"], json!(lease_revision));
}

async fn bootstrap_isolated_activity(
    address: SocketAddr,
    fixture: &Fixture,
    scope: &Value,
) -> Result<(Uuid, Uuid, i64, Value), Box<dyn std::error::Error>> {
    let activity_id = Uuid::now_v7();
    let runtime_instance_id = Uuid::now_v7();
    let observed_at = timestamp_now()?;
    let lease_until = add_millis(observed_at, 120_000)?;
    let bootstrap_request_id = Uuid::now_v7();
    let (status, bootstrap_response) = post_with_auth(
        address,
        "activity.bootstrap",
        json!({
            "scope": scope.clone(),
            "activity_id": activity_id,
            "runtime_instance_id": runtime_instance_id,
            "observed_at_ms": observed_at.get(),
            "lease_until_ms": lease_until.get(),
        }),
        bootstrap_request_id,
        Some(SECRET),
    )
    .await?;
    assert_eq!(
        status, 200,
        "activity.bootstrap response: {bootstrap_response}"
    );
    assert_eq!(bootstrap_response["ok"], true);
    assert_request_id(&bootstrap_response, bootstrap_request_id);
    assert_eq!(bootstrap_response["result"]["status"], "created");
    assert_eq!(bootstrap_response["result"]["committed"], true);
    let bootstrap_activity = bootstrap_response["result"]["activity"].clone();
    let actual_until = bootstrap_activity["lease_until_ms"]
        .as_i64()
        .ok_or("bootstrap lease expiry missing")?;
    assert_bootstrap_activity(
        &bootstrap_activity,
        activity_id,
        fixture.scope.workspace_id().into_uuid(),
        runtime_instance_id,
        actual_until,
        1,
    );

    let initial_activity = get_activity(address, fixture, activity_id).await?;
    let created = initial_activity["created_at_ms"]
        .as_i64()
        .ok_or("Activity creation time missing")?;
    assert_eq!(
        actual_until - created,
        lease_until.get() - observed_at.get()
    );
    assert!(created >= observed_at.get());
    assert_activity_projection(
        &initial_activity,
        activity_id,
        fixture.scope.workspace_id().into_uuid(),
        "open",
        Some(runtime_instance_id),
        Some(actual_until),
        1,
    );
    assert_eq!(initial_activity["revision"], bootstrap_activity["revision"]);
    assert_eq!(
        initial_activity["lease_owner_id"],
        bootstrap_activity["lease_owner_id"]
    );
    assert_eq!(
        initial_activity["lease_until_ms"],
        bootstrap_activity["lease_until_ms"]
    );
    Ok((
        activity_id,
        runtime_instance_id,
        actual_until,
        initial_activity,
    ))
}

async fn assert_activity_scope_rejection(
    address: SocketAddr,
    scope: &Value,
    activity_id: Uuid,
) -> Result<(), Box<dyn std::error::Error>> {
    let request_id = Uuid::now_v7();
    let mut wrong_scope = scope.clone();
    wrong_scope["workspace_id"] = json!(Uuid::now_v7());
    let (status, response) = post_with_auth(
        address,
        "activity.get",
        json!({
            "scope": wrong_scope,
            "activity_id": activity_id,
        }),
        request_id,
        Some(SECRET),
    )
    .await?;
    assert_failure(status, &response, request_id, "STALE_REVISION");
    Ok(())
}

async fn assert_activity_close_rejection(
    address: SocketAddr,
    fixture: &Fixture,
    activity_id: Uuid,
    payload: Value,
    expected_code: &str,
    baseline: &Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let request_id = Uuid::now_v7();
    let (status, response) =
        post_with_auth(address, "activity.close", payload, request_id, Some(SECRET)).await?;
    assert_failure(status, &response, request_id, expected_code);
    assert_eq!(
        get_activity(address, fixture, activity_id).await?,
        baseline.clone()
    );
    Ok(())
}

async fn assert_activity_close_rejections(
    address: SocketAddr,
    fixture: &Fixture,
    scope: &Value,
    activity_id: Uuid,
    runtime_instance_id: Uuid,
    baseline: &Value,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_activity_close_rejection(
        address,
        fixture,
        activity_id,
        json!({
            "scope": scope.clone(),
            "activity_id": activity_id,
            "runtime_instance_id": Uuid::now_v7(),
            "expected_lease_revision": 1,
        }),
        "LEASE_CONFLICT",
        baseline,
    )
    .await?;
    assert_activity_close_rejection(
        address,
        fixture,
        activity_id,
        json!({
            "scope": scope.clone(),
            "activity_id": activity_id,
            "runtime_instance_id": runtime_instance_id,
            "expected_lease_revision": 2,
        }),
        "LEASE_CONFLICT",
        baseline,
    )
    .await?;
    assert_activity_close_rejection(
        address,
        fixture,
        activity_id,
        json!({
            "scope": scope.clone(),
            "activity_id": activity_id,
            "runtime_instance_id": Uuid::nil(),
            "expected_lease_revision": 1,
        }),
        "INVALID_INPUT",
        baseline,
    )
    .await?;
    assert_activity_close_rejection(
        address,
        fixture,
        activity_id,
        json!({
            "scope": scope.clone(),
            "activity_id": activity_id,
            "runtime_instance_id": runtime_instance_id,
            "expected_lease_revision": 0,
        }),
        "INVALID_INPUT",
        baseline,
    )
    .await?;
    Ok(())
}

async fn close_isolated_activity(
    address: SocketAddr,
    fixture: &Fixture,
    scope: &Value,
    activity_id: Uuid,
    runtime_instance_id: Uuid,
) -> Result<(), Box<dyn std::error::Error>> {
    let request_id = Uuid::now_v7();
    let (status, response) = post_with_auth(
        address,
        "activity.close",
        json!({
            "scope": scope.clone(),
            "activity_id": activity_id,
            "runtime_instance_id": runtime_instance_id,
            "expected_lease_revision": 1,
        }),
        request_id,
        Some(SECRET),
    )
    .await?;
    assert_eq!(status, 200, "activity.close response: {response}");
    assert_eq!(response["ok"], true);
    assert_request_id(&response, request_id);
    assert_eq!(&response["result"]["scope"], scope);
    assert_eq!(response["result"]["activity_id"], json!(activity_id));
    assert_eq!(response["result"]["status"], "closed");
    assert_eq!(response["result"]["committed"], true);
    assert_eq!(response["result"]["unconfirmed"], false);
    assert_activity_projection(
        &response["result"]["activity"],
        activity_id,
        fixture.scope.workspace_id().into_uuid(),
        "closed",
        None,
        None,
        2,
    );

    let current_activity = get_activity(address, fixture, activity_id).await?;
    assert_activity_projection(
        &current_activity,
        activity_id,
        fixture.scope.workspace_id().into_uuid(),
        "closed",
        None,
        None,
        2,
    );
    assert_eq!(current_activity["revision"], json!(2));

    let fixture_activity = get_activity(address, fixture, fixture.activity_id.into_uuid()).await?;
    assert_eq!(fixture_activity["state"], "open");
    assert_eq!(
        fixture_activity["lease_owner_id"],
        json!(fixture.runtime_instance_id.into_uuid())
    );
    assert!(fixture_activity["lease_until_ms"].as_i64().is_some());
    Ok(())
}

async fn assert_queue_observations(
    address: SocketAddr,
    scope: &Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let global_request_id = Uuid::now_v7();
    let (status, global_response) = post_with_auth(
        address,
        "queue.status",
        json!({}),
        global_request_id,
        Some(SECRET),
    )
    .await?;
    assert_eq!(status, 200, "queue.status response: {global_response}");
    assert_eq!(global_response["ok"], true);
    assert_request_id(&global_response, global_request_id);
    let global_before = global_response["result"].clone();
    assert_queue_projection(&global_before, None)?;

    let scoped_request_id = Uuid::now_v7();
    let (status, scoped_response) = post_with_auth(
        address,
        "workspace.queue.status",
        json!({ "scope": scope.clone() }),
        scoped_request_id,
        Some(SECRET),
    )
    .await?;
    assert_eq!(
        status, 200,
        "workspace.queue.status response: {scoped_response}"
    );
    assert_eq!(scoped_response["ok"], true);
    assert_request_id(&scoped_response, scoped_request_id);
    assert_queue_projection(&scoped_response["result"], Some(scope))?;

    let settings_request_id = Uuid::now_v7();
    let (status, settings_response) = post_with_auth(
        address,
        "workspace.queue.settings",
        json!({ "scope": scope.clone() }),
        settings_request_id,
        Some(SECRET),
    )
    .await?;
    assert_eq!(
        status, 200,
        "workspace.queue.settings response: {settings_response}"
    );
    assert_eq!(settings_response["ok"], true);
    assert_request_id(&settings_response, settings_request_id);
    let settings = &settings_response["result"];
    assert_eq!(&settings["scope"], scope);
    assert!(settings["saved_preference"].is_null());
    assert_eq!(settings["observation"], "separate_non_atomic_reads");
    assert_queue_projection(&settings["effective_runtime"], None)?;

    let global_after_request_id = Uuid::now_v7();
    let (status, global_after_response) = post_with_auth(
        address,
        "queue.status",
        json!({}),
        global_after_request_id,
        Some(SECRET),
    )
    .await?;
    assert_eq!(
        status, 200,
        "queue.status after response: {global_after_response}"
    );
    assert_eq!(global_after_response["ok"], true);
    assert_request_id(&global_after_response, global_after_request_id);
    let global_after = &global_after_response["result"];
    assert_queue_projection(global_after, None)?;
    assert_same_queue_state(&global_before, global_after);
    Ok(())
}

async fn assert_queue_scope_rejections(
    address: SocketAddr,
    scope: &Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut wrong_scope = scope.clone();
    wrong_scope["workspace_id"] = json!(Uuid::now_v7());
    let wrong_scope_request_id = Uuid::now_v7();
    let (status, wrong_scope_response) = post_with_auth(
        address,
        "workspace.queue.settings",
        json!({ "scope": wrong_scope }),
        wrong_scope_request_id,
        Some(SECRET),
    )
    .await?;
    assert_failure(
        status,
        &wrong_scope_response,
        wrong_scope_request_id,
        "STALE_REVISION",
    );

    let mut wrong_status_scope = scope.clone();
    wrong_status_scope["workspace_id"] = json!(Uuid::now_v7());
    let wrong_status_scope_request_id = Uuid::now_v7();
    let (status, wrong_status_scope_response) = post_with_auth(
        address,
        "workspace.queue.status",
        json!({ "scope": wrong_status_scope }),
        wrong_status_scope_request_id,
        Some(SECRET),
    )
    .await?;
    assert_failure(
        status,
        &wrong_status_scope_response,
        wrong_status_scope_request_id,
        "STALE_REVISION",
    );
    Ok(())
}

async fn assert_queue_auth_rejections(
    address: SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    let missing_auth_request_id = Uuid::now_v7();
    let (status, missing_auth) = post_with_auth(
        address,
        "queue.status",
        json!({}),
        missing_auth_request_id,
        None,
    )
    .await?;
    assert_ne!(status, 200);
    assert_eq!(missing_auth["ok"], false);
    assert_eq!(missing_auth["error"]["code"], "AUTH_FAILED");
    assert_eq!(missing_auth["request_id"], json!(Uuid::nil()));

    let wrong_auth_request_id = Uuid::now_v7();
    let (status, wrong_auth) = post_with_auth(
        address,
        "queue.status",
        json!({}),
        wrong_auth_request_id,
        Some("wrong-credential"),
    )
    .await?;
    assert_ne!(status, 200);
    assert_eq!(wrong_auth["ok"], false);
    assert_eq!(wrong_auth["error"]["code"], "AUTH_FAILED");
    assert_eq!(wrong_auth["request_id"], json!(Uuid::nil()));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_http_queue_observations_are_read_only_scoped_and_authenticated()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = prepare_fixture()?;
    let state = backend_state(&fixture)?;
    let address = serve(state.clone()).await?;
    let scope = scope_json(&fixture);

    assert_queue_observations(address, &scope).await?;
    assert_queue_scope_rejections(address, &scope).await?;
    assert_queue_auth_rejections(address).await?;

    let shutdown = state.shutdown(Duration::from_secs(5)).await;
    assert!(
        shutdown.is_successful(),
        "backend shutdown did not complete"
    );
    fixture.shutdown()?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_http_activity_bootstrap_read_close_preserves_lease_cas_and_source_state()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = prepare_fixture()?;
    let state = backend_state(&fixture)?;
    let address = serve(state.clone()).await?;
    let scope = scope_json(&fixture);
    let (activity_id, runtime_instance_id, _actual_until, baseline_activity) =
        bootstrap_isolated_activity(address, &fixture, &scope).await?;

    assert_activity_scope_rejection(address, &scope, activity_id).await?;

    assert_activity_close_rejections(
        address,
        &fixture,
        &scope,
        activity_id,
        runtime_instance_id,
        &baseline_activity,
    )
    .await?;

    close_isolated_activity(address, &fixture, &scope, activity_id, runtime_instance_id).await?;

    let shutdown = state.shutdown(Duration::from_secs(5)).await;
    assert!(
        shutdown.is_successful(),
        "backend shutdown did not complete"
    );
    fixture.shutdown()?;
    Ok(())
}
