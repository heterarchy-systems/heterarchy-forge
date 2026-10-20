//! Real control/SQLite/HTTP proof for issuer-only Activity projection.

use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn activity_list_projects_current_rows_and_rejects_wrong_workspace_scope()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = prepare_fixture()?;
    let product_cache_root = fixture.root.join("product-cache");
    fs::create_dir_all(&product_cache_root)?;
    let state = super::assemble_fixture(
        backend_config()?,
        &fixture,
        &product_cache_root,
        super::delegated_destination_id(&fixture)?,
    )?;
    let address = serve(state.clone()).await?;
    let scope = &fixture.scope;
    let payload = json!({
        "locator": scope.locator().encode(),
        "workspace_id": scope.workspace_id().into_uuid(),
        "workspace_revision": scope.workspace_revision().get(),
        "limit": 16,
    });
    let (status, response) = post_command(address, "activity.list", payload).await?;
    assert_eq!(status, 200, "activity.list response: {response}");
    assert_eq!(response["ok"], true);
    assert_eq!(
        response["result"]["scope"]["workspace_id"],
        json!(scope.workspace_id().into_uuid())
    );
    assert_eq!(
        response["result"]["scope"]["workspace_revision"],
        json!(scope.workspace_revision().get())
    );
    assert_eq!(
        response["result"]["scope"]["locator"],
        json!(scope.locator().encode())
    );
    let activities = response["result"]["activities"]
        .as_array()
        .ok_or("activity rows missing")?;
    let row = activities
        .iter()
        .find(|row| row["activity_id"] == json!(fixture.activity_id.into_uuid()))
        .ok_or("bootstrapped activity row missing")?;
    assert_eq!(row["workspace_id"], json!(scope.workspace_id().into_uuid()));
    assert_eq!(row["state"], "open");
    assert_eq!(row["liveness"], "live");
    assert!(row["revision"].as_i64().is_some());
    assert!(row["created_at_ms"].as_i64().is_some());
    assert!(row["updated_at_ms"].as_i64().is_some());
    assert_eq!(
        row["lease_owner_id"],
        json!(fixture.runtime_instance_id.into_uuid())
    );
    assert!(row["lease_until_ms"].as_i64().is_some());
    assert!(row["lease_revision"].as_i64().is_some());

    let wrong_scope = json!({
        "locator": scope.locator().encode(),
        "workspace_id": Uuid::from_u128(0xdead),
        "workspace_revision": scope.workspace_revision().get(),
        "limit": 16,
    });
    let (status, response) = post_command(address, "activity.list", wrong_scope).await?;
    assert_eq!(status, 409, "wrong activity scope response: {response}");
    assert_eq!(response["error"]["code"], "WORKSPACE_IDENTITY_CONFLICT");

    assert!(state.shutdown(Duration::from_secs(5)).await.is_successful());
    fixture.shutdown()?;
    Ok(())
}
