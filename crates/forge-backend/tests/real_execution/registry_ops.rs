//! Focused backend-boundary proof for the Location topology ops over a real
//! control worker: `location.register`, `location.state`, `location.list`,
//! the unauthenticated `/readyz` control probe, and the capability document.
//! No execution, approval, or session authority participates: these ops are
//! issuer-only by contract.
//!
//! Workspace registration/inventory and native-byte identity consumption have
//! separate real SQLite/control/HTTP coverage in `workspace_registration.rs`.

use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(
    clippy::too_many_lines,
    reason = "One linear proof per boundary op keeps the assertion order reviewable."
)]
async fn location_topology_ops_serve_over_real_control() -> Result<(), Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!(
        "heterarchy-forge-backend-registry-{}-{}",
        std::process::id(),
        Uuid::now_v7()
    ));
    let extra_root = root.join("extra-location");
    fs::create_dir_all(&extra_root)?;
    let product_cache_root = root.join("product-cache");
    fs::create_dir_all(&product_cache_root)?;
    let registry_path = root.join("registry.sqlite3");
    let now = timestamp_now()?;
    drop(GlobalRegistry::open(&registry_path)?);
    let (client, mut worker) = ForgeControlWorker::start(ForgeControl::new(
        GlobalRegistry::open_existing(&registry_path)?,
    ))?;
    let (activity_leases, mut lease_worker) = ForgeControlWorker::start_activity_lease(
        ForgeControl::new(GlobalRegistry::open_existing(&registry_path)?),
    )?;
    let mut execution = ForgeExecutionCoordinator::start(client.clone(), 2)?;
    let mut approval =
        forge_control::ForgeApprovalCoordinator::start(client.clone(), execution.client())?;
    let boot_instance = Uuid::now_v7();
    let state = assemble(
        backend_config()?,
        forge_backend::http::BackendClients {
            control: &client,
            execution: &execution.client(),
            approval: &approval.client(),
            activity_leases: &activity_leases,
            runtime_instance_id: boot_instance,
            product_cache_root: &product_cache_root,
            destination_id: Uuid::now_v7(),
        },
    )?;
    let address = serve(state.clone()).await?;

    let extra_id = Uuid::now_v7();
    let (status, response) = register_location(address, extra_id, &extra_root, now.get()).await?;
    assert_eq!(status, 200, "location.register response: {response}");
    assert_eq!(response["ok"], true);
    assert_eq!(response["result"]["state"], "enabled");
    assert_eq!(response["result"]["revision"], 1);

    // Duplicate root: typed durable conflict, not generic unavailability.
    let (status, response) =
        register_location(address, Uuid::now_v7(), &extra_root, now.get()).await?;
    assert_eq!(status, 409, "duplicate root response: {response}");
    assert_eq!(response["error"]["code"], "WORKSPACE_ROOT_CONFLICT");

    // Duplicate identity with a fresh existing path: the other typed conflict.
    let other_path = root.join("other-path");
    fs::create_dir_all(&other_path)?;
    let (status, response) = post_command(
        address,
        "location.register",
        json!({
            "location_id": extra_id,
            "name": "extra",
            "path": other_path.to_string_lossy(),
            "observed_at_ms": now.get(),
        }),
    )
    .await?;
    assert_eq!(status, 409, "duplicate identity response: {response}");
    assert_eq!(response["error"]["code"], "WORKSPACE_IDENTITY_CONFLICT");

    // Registration is visible to the read-only list op.
    let (status, response) = post_command(address, "location.list", json!({})).await?;
    assert_eq!(status, 200, "location.list response: {response}");
    let listed = response["result"]["entries"]
        .as_array()
        .ok_or("location entries missing")?;
    assert!(
        listed
            .iter()
            .any(|entry| entry["location_id"] == json!(extra_id)),
        "registered Location missing from location.list: {listed:?}"
    );

    // Disable through the optimistic-concurrency state op.
    let (status, response) = post_command(
        address,
        "location.state",
        json!({
            "location_id": extra_id,
            "expected_revision": 1,
            "state": "disabled",
            "observed_at_ms": now.get(),
        }),
    )
    .await?;
    assert_eq!(status, 200, "location.state response: {response}");
    assert_eq!(response["result"]["state"], "disabled");
    assert_eq!(response["result"]["revision"], 2);

    // Stale revision is a typed stale-revision rejection.
    let (status, response) = post_command(
        address,
        "location.state",
        json!({
            "location_id": extra_id,
            "expected_revision": 1,
            "state": "enabled",
            "observed_at_ms": now.get(),
        }),
    )
    .await?;
    assert_eq!(status, 409, "stale location.state response: {response}");
    assert_eq!(response["error"]["code"], "STALE_REVISION");

    // Readiness proves the control dependency answers; liveness stays plain.
    let (status, ready) = get_unauthenticated(address, "/readyz").await?;
    assert_eq!(status, 200, "readyz response: {ready}");
    assert_eq!(ready["ready"], true);
    assert_eq!(ready["checks"]["control_worker"]["ready"], true);
    let (status, health) = get_unauthenticated(address, "/healthz").await?;
    assert_eq!(status, 200);
    assert_eq!(health, "ok");

    let shutdown = state.shutdown(Duration::from_secs(5)).await;
    assert!(shutdown.is_successful(), "backend shutdown incomplete");
    let _approval_report = approval.shutdown()?;
    let _execution_report = execution.shutdown()?;
    worker.shutdown()?;
    lease_worker.shutdown()?;
    fs::remove_dir_all(root)?;
    Ok(())
}

async fn register_location(
    address: SocketAddr,
    location_id: Uuid,
    path: &Path,
    observed_at_ms: i64,
) -> Result<(u16, Value), Box<dyn std::error::Error>> {
    post_command(
        address,
        "location.register",
        json!({
            "location_id": location_id,
            "name": "extra",
            "path": path.to_string_lossy(),
            "observed_at_ms": observed_at_ms,
        }),
    )
    .await
}

pub(super) async fn get_unauthenticated(
    address: SocketAddr,
    path: &str,
) -> Result<(u16, Value), Box<dyn std::error::Error>> {
    let request = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    let mut stream = tokio::net::TcpStream::connect(address).await?;
    stream.write_all(request.as_bytes()).await?;
    let response = read_response_bounded(&mut stream).await?;
    let text = String::from_utf8(response)?;
    let status = text
        .split_whitespace()
        .nth(1)
        .ok_or("HTTP status missing")?
        .parse::<u16>()?;
    let body = text.split_once("\r\n\r\n").ok_or("HTTP body missing")?.1;
    if path == "/healthz" {
        return Ok((status, Value::String(body.to_owned())));
    }
    Ok((status, serde_json::from_str(body)?))
}
