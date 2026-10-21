//! Actual HTTP administrative bootstrap with lossless locator/identity fences.

use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use std::os::unix::ffi::OsStrExt;
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStringExt;

#[cfg(target_os = "linux")]
fn registration_relative_root() -> PathBuf {
    // Linux retains the invalid-byte fixture to exercise the lossless native
    // locator codec over a real HTTP registration round trip.
    PathBuf::from(std::ffi::OsString::from_vec(b"workspace-\xff".to_vec()))
}

#[cfg(target_os = "macos")]
fn registration_relative_root() -> PathBuf {
    // APFS rejects invalid UTF-8 path components, so macOS uses a valid
    // multibyte name while retaining the native-path HTTP/readback coverage.
    PathBuf::from("workspace-多字节")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[expect(
    clippy::too_many_lines,
    reason = "One linear real-listener proof preserves registration, replay, physical/revision fences and read-only assertion ordering."
)]
async fn registration_probe_register_replay_and_fences_use_the_application_owner()
-> Result<(), Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!("forge-http-registration-{}", Uuid::now_v7()));
    let location_root = root.join("location");
    let relative = registration_relative_root();
    let workspace_root = location_root.join(&relative);
    fs::create_dir_all(&workspace_root)?;
    let cache = root.join("product-cache");
    fs::create_dir_all(&cache)?;
    let (client, mut worker) = ForgeControlWorker::start(ForgeControl::new(GlobalRegistry::open(
        root.join("registry.sqlite3"),
    )?))?;
    let (activity_leases, mut lease_worker) =
        ForgeControlWorker::start_activity_lease(ForgeControl::new(
            GlobalRegistry::open_existing(root.join("registry.sqlite3"))?,
        ))?;
    let mut execution = ForgeExecutionCoordinator::start(client.clone(), 2)?;
    let mut approval = ForgeApprovalCoordinator::start(client.clone(), execution.client())?;
    let state = assemble(
        backend_config()?,
        forge_backend::http::BackendClients {
            control: &client,
            execution: &execution.client(),
            approval: &approval.client(),
            activity_leases: &activity_leases,
            runtime_instance_id: Uuid::now_v7(),
            product_cache_root: &cache,
            destination_id: Uuid::now_v7(),
        },
    )?;
    let address = serve(state.clone()).await?;
    let location_id = Uuid::now_v7();
    let (status, _) = post_command(
        address,
        "location.register",
        json!({
            "location_id": location_id, "name": "registered via HTTP",
            "path": location_root.to_str().ok_or("fixture Location path not UTF-8")?,
            "observed_at_ms": 1,
        }),
    )
    .await?;
    assert_eq!(status, 200);
    let locator = forge_control::WorkspaceLocator::new(
        LocationId::from_uuid(location_id),
        LocationRevision::INITIAL,
        &relative,
    )?;
    let (status, probe) = post_command(
        address,
        "workspace.registration_probe",
        json!({ "locator": locator.encode() }),
    )
    .await?;
    assert_eq!(status, 200, "{probe}");
    assert_eq!(probe["result"]["workspace"], Value::Null);
    assert!(!workspace_root.join(".heterarchy-forge").exists());
    let proposed = Uuid::now_v7();
    let request = json!({
        "locator": locator.encode(), "proposed_workspace_id": proposed,
        "expected_root_fingerprint": probe["result"]["root_fingerprint"],
        "observed_at_ms": 2,
    });
    let mut wrong_fingerprint = request.clone();
    wrong_fingerprint["expected_root_fingerprint"] = json!("00".repeat(16));
    let (status, denied) = post_command(address, "workspace.register", wrong_fingerprint).await?;
    assert_eq!(status, 409, "{denied}");
    assert_eq!(denied["error"]["code"], "WORKSPACE_ROOT_CONFLICT");
    assert!(!workspace_root.join(".heterarchy-forge").exists());
    let mut invalid_identity = request.clone();
    invalid_identity["proposed_workspace_id"] = json!(Uuid::nil());
    assert_eq!(
        post_command(address, "workspace.register", invalid_identity)
            .await?
            .0,
        400
    );
    assert!(!workspace_root.join(".heterarchy-forge").exists());

    let (status, registered) = post_command(address, "workspace.register", request.clone()).await?;
    assert_eq!(status, 200, "{registered}");
    assert_eq!(registered["result"]["status"], "confirmed");
    assert_eq!(
        registered["result"]["workspace"]["workspace_id"],
        json!(proposed)
    );
    let native_path = URL_SAFE_NO_PAD.decode(
        registered["result"]["workspace"]["root_path_base64"]
            .as_str()
            .ok_or("native root path missing")?,
    )?;
    assert_eq!(
        native_path,
        fs::canonicalize(&workspace_root)?.as_os_str().as_bytes()
    );
    let database = workspace_root.join(".heterarchy-forge/state.sqlite3");
    let before_probe = fs::read(&database)?;
    let (_, current) = post_command(
        address,
        "workspace.registration_probe",
        json!({"locator": locator.encode()}),
    )
    .await?;
    assert_eq!(
        current["result"]["workspace"],
        registered["result"]["workspace"]
    );
    assert_eq!(fs::read(&database)?, before_probe);
    let (_, replay) = post_command(address, "workspace.register", request.clone()).await?;
    assert_eq!(replay["result"], registered["result"]);
    let mut another_proposal = request.clone();
    another_proposal["proposed_workspace_id"] = json!(Uuid::now_v7());
    another_proposal["observed_at_ms"] = json!(3);
    let (_, reopened) = post_command(address, "workspace.register", another_proposal).await?;
    assert_eq!(
        reopened["result"]["workspace"],
        registered["result"]["workspace"]
    );

    let (status, inventory) = post_command(
        address,
        "workspace.inventory",
        json!({
            "location_id": location_id, "expected_revision": 1,
        }),
    )
    .await?;
    assert_eq!(status, 200, "{inventory}");
    let entries = inventory["result"]["entries"]
        .as_array()
        .ok_or("inventory entries missing")?;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["locator"], locator.encode());
    assert_eq!(entries[0]["workspace"]["workspace_id"], json!(proposed));
    assert_eq!(fs::read(&database)?, before_probe);

    // A symlink substitution is not a selectable Workspace, even inside the Location.
    let alias = location_root.join("alias");
    std::os::unix::fs::symlink(&workspace_root, &alias)?;
    let alias_locator = forge_control::WorkspaceLocator::new(
        LocationId::from_uuid(location_id),
        LocationRevision::INITIAL,
        "alias",
    )?;
    assert_ne!(
        post_command(
            address,
            "workspace.registration_probe",
            json!({"locator": alias_locator.encode()})
        )
        .await?
        .0,
        200
    );
    let (status, _) = post_command(address, "location.state", json!({
        "location_id": location_id, "expected_revision": 1, "state": "disabled", "observed_at_ms": 4,
    })).await?;
    assert_eq!(status, 200);
    let (status, revision_rejection) = post_command(address, "workspace.register", request).await?;
    assert_eq!(status, 409);
    assert_eq!(revision_rejection["error"]["code"], "STALE_REVISION");
    assert_eq!(fs::read(&database)?, before_probe);

    assert!(state.shutdown(Duration::from_secs(5)).await.is_successful());
    let _approval = approval.shutdown()?;
    let _execution = execution.shutdown()?;
    worker.shutdown()?;
    lease_worker.shutdown()?;
    fs::remove_dir_all(root)?;
    Ok(())
}
