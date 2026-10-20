//! Real HTTP proofs for registered Location-root removal.

use super::binding_lifecycle::{HttpBindingFixture, open_command_without_read};
use super::*;

use forge_control::RegisterLocationRequest;
use forge_domain::{EstablishWorkspace, LocationId, WorkspaceId, WorkspaceRoot};
use forge_persistence::WorkspaceStore;
use forge_workspace::WorkspaceStateLayout;
use serde_json::{Value, json};
use std::path::PathBuf;
use tokio::time::timeout;

struct RemovalTarget {
    location_id: Uuid,
    revision: i64,
    root: PathBuf,
    fingerprint: String,
    workspace_id: Uuid,
    workspace_revision: i64,
}

fn backend_state(fixture: &Fixture) -> Result<forge_backend::AppState, Box<dyn std::error::Error>> {
    let product_cache_root = fixture.root.join("product-cache-location-removal");
    fs::create_dir_all(&product_cache_root)?;
    let destination_id = delegated_destination_id(fixture)?;
    super::assemble_fixture(
        backend_config()?,
        fixture,
        &product_cache_root,
        destination_id,
    )
}

fn workspace_expected_state(target: &RemovalTarget) -> Value {
    json!({
        "kind": "workspace",
        "workspace_id": target.workspace_id,
        "workspace_revision": target.workspace_revision,
    })
}

fn list_only_payload(target: &RemovalTarget) -> Value {
    json!({
        "location_id": target.location_id,
        "expected_revision": target.revision,
        "mode": {"kind": "list_only"},
    })
}

fn delete_state_payload(target: &RemovalTarget) -> Value {
    json!({
        "location_id": target.location_id,
        "expected_revision": target.revision,
        "mode": {
            "kind": "delete_state",
            "expected_root_fingerprint": target.fingerprint,
            "expected_state": workspace_expected_state(target),
        },
    })
}

fn absent_delete_state_payload(target: &RemovalTarget, expected_revision: i64) -> Value {
    json!({
        "location_id": target.location_id,
        "expected_revision": expected_revision,
        "mode": {
            "kind": "delete_state",
            "expected_root_fingerprint": target.fingerprint,
            "expected_state": {"kind": "absent"},
        },
    })
}

fn location_result(response: &Value) -> &Value {
    &response["result"]
}

fn location_revision(response: &Value) -> Result<i64, Box<dyn std::error::Error>> {
    location_result(response)["location"]["revision"]
        .as_i64()
        .ok_or_else(|| "Location revision missing from removal response".into())
}

fn probe_root_fingerprint(response: &Value) -> Result<String, Box<dyn std::error::Error>> {
    location_result(response)["root_fingerprint"]
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| "Location root fingerprint missing from probe".into())
}

async fn removal_probe(
    address: SocketAddr,
    target: &RemovalTarget,
) -> Result<(u16, Value), Box<dyn std::error::Error>> {
    post_command(
        address,
        "location.removal_probe",
        json!({"location_id": target.location_id}),
    )
    .await
}

async fn remove(
    address: SocketAddr,
    payload: Value,
) -> Result<(u16, Value), Box<dyn std::error::Error>> {
    post_command(address, "location.remove", payload).await
}

async fn post_without_auth(
    address: SocketAddr,
    operation: &str,
    payload: Value,
) -> Result<(u16, Value), Box<dyn std::error::Error>> {
    let body = super::envelope(operation, &payload);
    let request = format!(
        "POST /api/v1/commands/{operation} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    super::exchange_json(address, &request).await
}

fn assert_failure(status: u16, response: &Value) {
    assert_ne!(
        status, 200,
        "unexpected Location removal success: {response}"
    );
    assert_eq!(response["ok"], false);
}

fn prepare_removal_target(fixture: &Fixture) -> Result<RemovalTarget, Box<dyn std::error::Error>> {
    let root = fixture
        .root
        .join(format!("removal-location-{}", Uuid::now_v7()));
    fs::create_dir_all(&root)?;
    for child in [".git", ".agents", "src", "child-workspace"] {
        fs::create_dir_all(root.join(child))?;
        fs::write(root.join(child).join("preserved"), child)?;
    }
    let location = fixture.client.register_location(RegisterLocationRequest {
        id: LocationId::from_uuid(Uuid::now_v7()),
        name: "HTTP removal fixture".to_owned(),
        selected_path: root.clone(),
        observed_at: timestamp_now()?,
    })?;
    let layout = WorkspaceStateLayout::initialize(&root)?;
    let workspace_id = WorkspaceId::from_uuid(Uuid::now_v7());
    let establish = EstablishWorkspace::new(
        workspace_id,
        location.id(),
        WorkspaceRoot::from_canonical(root.clone())?,
        layout.root_fingerprint()?,
        timestamp_now()?,
    );
    let store = WorkspaceStore::open(&layout, &establish)?;
    let workspace = store.workspace()?;
    drop(store);
    let fingerprint = forge_backend::events::hex_encode(layout.root_fingerprint()?.as_bytes());
    Ok(RemovalTarget {
        location_id: location.id().into_uuid(),
        revision: location.revision().get(),
        root,
        fingerprint,
        workspace_id: workspace.id().into_uuid(),
        workspace_revision: workspace.revision().get(),
    })
}

fn assert_preserved_children(target: &RemovalTarget) -> Result<(), Box<dyn std::error::Error>> {
    for child in [".git", ".agents", "src", "child-workspace"] {
        assert_eq!(
            fs::read_to_string(target.root.join(child).join("preserved"))?,
            child
        );
    }
    Ok(())
}

fn location_list_state(
    fixture: &Fixture,
    location_id: Uuid,
) -> Result<forge_domain::RegisteredLocation, Box<dyn std::error::Error>> {
    fixture
        .client
        .location_list()?
        .into_iter()
        .find(|location| location.id().into_uuid() == location_id)
        .ok_or_else(|| "removal fixture Location disappeared".into())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_http_location_removal_probe_list_only_delete_state_and_retry()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = prepare_fixture()?;
    let state = backend_state(&fixture)?;
    let address = serve(state.clone()).await?;
    let target = prepare_removal_target(&fixture)?;
    let (status, probe) = removal_probe(address, &target).await?;
    assert_eq!(status, 200, "removal probe response: {probe}");
    assert_eq!(
        location_result(&probe)["location_id"],
        json!(target.location_id)
    );
    assert_eq!(location_result(&probe)["revision"], json!(target.revision));
    assert_eq!(probe_root_fingerprint(&probe)?, target.fingerprint);
    assert_eq!(
        location_result(&probe)["expected_state"]["kind"],
        "workspace"
    );

    let (status, listed) = remove(address, list_only_payload(&target)).await?;
    assert_eq!(status, 200, "list-only response: {listed}");
    assert_eq!(location_result(&listed)["cleanup"], "listing_only");
    assert_preserved_children(&target)?;
    let disabled = location_list_state(&fixture, target.location_id)?;
    assert_eq!(disabled.state(), forge_domain::LocationState::Disabled);

    let mut outdated_confirmation = list_only_payload(&target);
    outdated_confirmation["expected_revision"] = json!(target.revision);
    let (status, stale_response) = remove(address, outdated_confirmation).await?;
    assert_failure(status, &stale_response);
    assert_preserved_children(&target)?;

    let mut delete = delete_state_payload(&target);
    delete["expected_revision"] = json!(disabled.revision().get());
    let (status, deleted) = remove(address, delete).await?;
    assert_eq!(status, 200, "delete-state response: {deleted}");
    assert_eq!(location_result(&deleted)["cleanup"], "state_removed");
    assert!(!target.root.join(".heterarchy-forge").exists());
    assert_preserved_children(&target)?;

    let (status, after_probe) = removal_probe(address, &target).await?;
    assert_eq!(status, 200, "post-delete removal probe: {after_probe}");
    assert_eq!(
        location_result(&after_probe)["expected_state"]["kind"],
        "absent"
    );
    let current_revision = location_revision(&deleted)?;
    assert_eq!(
        location_result(&after_probe)["revision"],
        json!(current_revision)
    );
    let mut old_workspace_expectation = delete_state_payload(&target);
    old_workspace_expectation["expected_revision"] = json!(current_revision);
    let (status, old_state) = remove(address, old_workspace_expectation).await?;
    assert_failure(status, &old_state);
    assert_preserved_children(&target)?;

    let retry = absent_delete_state_payload(&target, current_revision);
    let (status, retried) = remove(address, retry).await?;
    assert_eq!(status, 200, "disabled absent-state retry: {retried}");
    assert_eq!(location_result(&retried)["cleanup"], "state_already_absent");
    assert_preserved_children(&target)?;

    let shutdown = state.shutdown(Duration::from_secs(5)).await;
    assert!(
        shutdown.is_successful(),
        "backend shutdown did not complete"
    );
    fixture.shutdown()?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_http_location_removal_rejects_identity_fences_and_auth()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = prepare_fixture()?;
    let state = backend_state(&fixture)?;
    let address = serve(state.clone()).await?;
    let target = prepare_removal_target(&fixture)?;
    let mut wrong_fingerprint = delete_state_payload(&target);
    wrong_fingerprint["mode"]["expected_root_fingerprint"] = json!("00".repeat(16));
    let (status, response) = remove(address, wrong_fingerprint).await?;
    assert_failure(status, &response);
    assert!(target.root.join(".heterarchy-forge").exists());

    let mut wrong_workspace = delete_state_payload(&target);
    wrong_workspace["mode"]["expected_state"]["workspace_id"] = json!(Uuid::now_v7());
    let (status, response) = remove(address, wrong_workspace).await?;
    assert_failure(status, &response);
    assert!(target.root.join(".heterarchy-forge").exists());

    let mut wrong_revision = delete_state_payload(&target);
    wrong_revision["expected_revision"] = json!(target.revision + 1);
    let (status, response) = remove(address, wrong_revision).await?;
    assert_failure(status, &response);
    assert!(target.root.join(".heterarchy-forge").exists());

    let (status, unauthenticated) =
        post_without_auth(address, "location.remove", list_only_payload(&target)).await?;
    assert_ne!(status, 200);
    assert_eq!(unauthenticated["error"]["code"], "AUTH_FAILED");
    assert!(target.root.join(".heterarchy-forge").exists());

    let shutdown = state.shutdown(Duration::from_secs(5)).await;
    assert!(
        shutdown.is_successful(),
        "backend shutdown did not complete"
    );
    fixture.shutdown()?;
    Ok(())
}

async fn read_raw_response(
    stream: &mut tokio::net::TcpStream,
) -> Result<(u16, Value), Box<dyn std::error::Error>> {
    let raw = super::read_response_bounded(stream).await?;
    let text = String::from_utf8(raw)?;
    let status = text
        .split_whitespace()
        .nth(1)
        .ok_or("HTTP status missing")?
        .parse::<u16>()?;
    let body = text.split_once("\r\n\r\n").ok_or("HTTP body missing")?.1;
    Ok((status, serde_json::from_str(body)?))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_http_location_removal_deadline_reads_original_keys()
-> Result<(), Box<dyn std::error::Error>> {
    let (running, held, admitted) =
        HttpBindingFixture::start_holding_first_reply(Some(Duration::from_secs(1))).await?;
    let target = prepare_removal_target(&running.fixture)?;
    let payload = list_only_payload(&target);
    let result = async {
        let mut stream =
            open_command_without_read(running.address, "location.remove", payload).await?;
        timeout(Duration::from_secs(5), admitted).await??;
        let (status, response) =
            timeout(Duration::from_secs(5), read_raw_response(&mut stream)).await??;
        assert_eq!(status, 202, "removal deadline response: {response}");
        assert_eq!(response["error"]["code"], "UNKNOWN_OUTCOME");
        assert_eq!(response["error"]["readback"]["kind"], "location_removal");
        assert_eq!(
            response["error"]["readback"]["location_id"],
            json!(target.location_id)
        );
        assert_eq!(
            response["error"]["readback"]["expected_revision"],
            json!(target.revision)
        );
        assert_eq!(response["error"]["readback"]["mode"], "list_only");
        assert_eq!(
            response["error"]["readback"]["expected_root_fingerprint"],
            Value::Null
        );
        assert_eq!(response["error"]["readback"]["expected_state"], Value::Null);
        drop(stream);
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;
    let release_result = held.release_and_wait().await;
    let location = location_list_state(&running.fixture, target.location_id);
    let finish = running.finish().await;
    result?;
    release_result?;
    assert_eq!(location?.state(), forge_domain::LocationState::Disabled);
    finish
}

fn assert_delete_readback(response: &Value, target: &RemovalTarget) {
    assert_eq!(response["error"]["code"], "UNKNOWN_OUTCOME");
    let readback = &response["error"]["readback"];
    assert_eq!(readback["kind"], "location_removal");
    assert_eq!(readback["location_id"], json!(target.location_id));
    assert_eq!(readback["expected_revision"], json!(target.revision));
    assert_eq!(readback["mode"], "delete_state");
    assert_eq!(
        readback["expected_root_fingerprint"],
        json!(target.fingerprint)
    );
    assert_eq!(readback["expected_state"]["kind"], "workspace");
    assert_eq!(
        readback["expected_state"]["workspace_id"],
        json!(target.workspace_id)
    );
    assert_eq!(
        readback["expected_state"]["workspace_revision"],
        json!(target.workspace_revision)
    );
}

async fn assert_deleted_target(
    running: &HttpBindingFixture,
    target: &RemovalTarget,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        location_list_state(&running.fixture, target.location_id)?.state(),
        forge_domain::LocationState::Disabled
    );
    assert!(!target.root.join(".heterarchy-forge").exists());
    assert_preserved_children(target)?;
    let (status, probe) = removal_probe(running.address, target).await?;
    assert_eq!(status, 200, "post-delete probe response: {probe}");
    assert_eq!(location_result(&probe)["expected_state"]["kind"], "absent");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_http_location_delete_state_deadline_reads_original_keys()
-> Result<(), Box<dyn std::error::Error>> {
    let (running, held, admitted) =
        HttpBindingFixture::start_holding_first_reply(Some(Duration::from_secs(1))).await?;
    let target = prepare_removal_target(&running.fixture)?;
    let result = async {
        let mut stream = open_command_without_read(
            running.address,
            "location.remove",
            delete_state_payload(&target),
        )
        .await?;
        timeout(Duration::from_secs(5), admitted).await??;
        let (status, response) =
            timeout(Duration::from_secs(5), read_raw_response(&mut stream)).await??;
        assert_eq!(status, 202, "delete-state deadline response: {response}");
        assert_delete_readback(&response, &target);
        drop(stream);
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;
    let release_result = held.release_and_wait().await;
    let post = assert_deleted_target(&running, &target).await;
    let finish = running.finish().await;
    result?;
    release_result?;
    post?;
    finish
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_http_location_delete_state_disconnect_reads_same_root_state()
-> Result<(), Box<dyn std::error::Error>> {
    let (running, held, admitted) = HttpBindingFixture::start_holding_first_reply(None).await?;
    let target = prepare_removal_target(&running.fixture)?;
    let result = async {
        let mut stream = open_command_without_read(
            running.address,
            "location.remove",
            delete_state_payload(&target),
        )
        .await?;
        timeout(Duration::from_secs(5), admitted).await??;
        stream.shutdown().await?;
        drop(stream);
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;
    let release_result = held.release_and_wait().await;
    let post = assert_deleted_target(&running, &target).await;
    let finish = running.finish().await;
    result?;
    release_result?;
    post?;
    finish
}
