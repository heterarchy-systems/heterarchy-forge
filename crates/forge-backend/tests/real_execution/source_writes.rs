use super::lease_readback::{MUTATION_PATH, path_token, post_ok, scope_json};
use super::*;
use serde_json::{Value, json};

const ORIGINAL: &str = "historical source outcome\r\n";
const UPDATED: &str = "updated source outcome\r\n";

pub(super) fn activity_json(fixture: &Fixture) -> Result<Value, Box<dyn std::error::Error>> {
    Ok(json!({
        "activity_id": fixture.activity_id.into_uuid(),
        "runtime_instance_id": fixture.runtime_instance_id.into_uuid(),
        "observed_at_ms": timestamp_now()?.get(),
    }))
}

fn patch_payload(
    fixture: &Fixture,
    lease_id: Uuid,
    lease_revision: i64,
    change_set_id: Uuid,
    mutation_id: Uuid,
    operation: &Value,
) -> Result<Value, Box<dyn std::error::Error>> {
    let mut payload = source_authority_payload(fixture, lease_id, lease_revision)?;
    payload["change_set_id"] = json!(change_set_id);
    payload["mutation_id"] = json!(mutation_id);
    payload["operation"] = operation.clone();
    Ok(payload)
}

pub(super) fn source_authority_payload(
    fixture: &Fixture,
    lease_id: Uuid,
    lease_revision: i64,
) -> Result<Value, Box<dyn std::error::Error>> {
    let attribution = fixture.attribution;
    Ok(json!({
        "scope": scope_json(fixture),
        "activity": activity_json(fixture)?,
        "actor": {
            "session_id": fixture.session_id.into_uuid(),
            "principal": { "kind": "trusted_stdio" },
            "workspace_id": fixture.scope.workspace_id().into_uuid(),
            "agent_id": fixture.agent_id.into_uuid(),
            "expected_revision": fixture.agent_revision.get(),
        },
        "goal_id": attribution.goal_id().into_uuid(),
        "expected_goal_revision": attribution.expected_goal_revision().get(),
        "expected_dag_revision": attribution.dag_revision().get(),
        "node_id": attribution.node_id().into_uuid(),
        "expected_node_revision": attribution.expected_node_revision().get(),
        "writer_lease_id": lease_id,
        "expected_writer_lease_revision": lease_revision,
    }))
}

fn fresh_identity(payload: &mut Value) {
    payload["change_set_id"] = json!(Uuid::now_v7());
    payload["mutation_id"] = json!(Uuid::now_v7());
}

async fn assert_rejected(
    address: SocketAddr,
    payload: Value,
    fixture: &Fixture,
    expected: &str,
    expected_code: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (status, reply) = post_command(address, "file.apply_patch", payload).await?;
    assert_ne!(
        status, 200,
        "rejected mutation unexpectedly succeeded: {reply}"
    );
    assert_eq!(reply["ok"], false);
    assert_eq!(reply["error"]["code"], expected_code);
    assert_eq!(
        fs::read(fixture.workspace_root.join(MUTATION_PATH))?,
        expected.as_bytes()
    );
    Ok(())
}

async fn update_source(
    address: SocketAddr,
    fixture: &Fixture,
    add_payload: &Value,
) -> Result<Value, Box<dyn std::error::Error>> {
    let source = post_ok(
        address,
        "file.read_slice",
        json!({
            "scope": scope_json(fixture), "activity": activity_json(fixture)?,
            "path_base64": path_token(MUTATION_PATH), "start_line": 1, "end_line": 1,
        }),
    )
    .await?;
    assert_eq!(source["content"], ORIGINAL);
    assert_eq!(source["eol"], "crlf");
    let mut payload = add_payload.clone();
    fresh_identity(&mut payload);
    payload["operation"] = json!({
        "kind": "update", "path_base64": path_token(MUTATION_PATH),
        "expected_whole_file_hash": source["whole_file_hash"],
        "hunks": [{"start_line": 1, "end_line": 1,
            "expected_range_hash": source["range_hash"], "replacement": UPDATED}],
    });
    let path = fixture.workspace_root.join(MUTATION_PATH);
    let oversized = vec![b'x'; forge_domain::MAX_SOURCE_PATCH_BYTES + 1];
    fs::write(&path, &oversized)?;
    let (status, reply) = post_command(address, "file.apply_patch", payload.clone()).await?;
    assert_eq!(status, 503);
    assert_eq!(reply["error"]["code"], "CAPACITY_EXCEEDED");
    assert_eq!(reply["error"]["retryable"], false);
    assert_eq!(fs::read(&path)?, oversized);
    fs::write(path, ORIGINAL)?;
    fresh_identity(&mut payload);
    let updated = post_ok(address, "file.apply_patch", payload.clone()).await?;
    assert_eq!(updated["status"], "applied");
    assert_eq!(updated["kind"], "replace");
    assert_eq!(
        fs::read(fixture.workspace_root.join(MUTATION_PATH))?,
        UPDATED.as_bytes()
    );
    // The original Update request is not durably fingerprinted; replay is denied.
    assert_rejected(
        address,
        payload.clone(),
        fixture,
        UPDATED,
        "SOURCE_CONFLICT",
    )
    .await?;
    fresh_identity(&mut payload);
    // Fresh mutation IDs still cannot bypass the stale content hash.
    assert_rejected(address, payload, fixture, UPDATED, "SOURCE_CONFLICT").await?;
    Ok(updated)
}

async fn delete_source(
    address: SocketAddr,
    fixture: &Fixture,
    add_payload: &Value,
    updated: &Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut payload = add_payload.clone();
    fresh_identity(&mut payload);
    payload["operation"] = json!({
        "kind": "delete", "path_base64": path_token(MUTATION_PATH),
        "expected_whole_file_hash": updated["post_state"]["content_hash"],
    });
    let mut stale_lease = payload.clone();
    let revision = stale_lease["expected_writer_lease_revision"]
        .as_i64()
        .ok_or("lease revision missing")?;
    stale_lease["expected_writer_lease_revision"] = json!(revision + 1);
    assert_rejected(address, stale_lease, fixture, UPDATED, "LEASE_CONFLICT").await?;
    let deleted = post_ok(address, "file.apply_patch", payload).await?;
    assert_eq!(deleted["status"], "applied");
    assert_eq!(deleted["kind"], "delete");
    assert_eq!(deleted["post_state"]["exists"], false);
    assert!(!fixture.workspace_root.join(MUTATION_PATH).exists());
    Ok(())
}

async fn add_source(
    address: SocketAddr,
    fixture: &Fixture,
    lease_id: Uuid,
    lease_revision: i64,
    change_set_id: Uuid,
    mutation_id: Uuid,
) -> Result<Value, Box<dyn std::error::Error>> {
    let payload = patch_payload(
        fixture,
        lease_id,
        lease_revision,
        change_set_id,
        mutation_id,
        &json!({
            "kind": "add", "path_base64": path_token(MUTATION_PATH), "content": ORIGINAL,
        }),
    )?;
    let added = post_ok(address, "file.apply_patch", payload.clone()).await?;
    assert_eq!(added["status"], "applied");
    assert_eq!(added["change_set_id"], json!(change_set_id));
    assert_eq!(added["mutation_id"], json!(mutation_id));
    assert_eq!(added["retry_authorized"], false);
    assert_eq!(
        fs::read(fixture.workspace_root.join(MUTATION_PATH))?,
        ORIGINAL.as_bytes()
    );
    Ok(payload)
}

pub(super) async fn assert_http_single_create_for_historical_readback(
    address: SocketAddr,
    fixture: &Fixture,
    lease_id: Uuid,
    lease_revision: i64,
) -> Result<(forge_domain::ChangeSetId, forge_domain::FileMutationId), Box<dyn std::error::Error>> {
    assert!(
        !fixture.workspace_root.join(MUTATION_PATH).exists(),
        "the active source-write phase must delete the reused historical path"
    );
    let change_set_id = Uuid::now_v7();
    let mutation_id = Uuid::now_v7();
    let _payload = add_source(
        address,
        fixture,
        lease_id,
        lease_revision,
        change_set_id,
        mutation_id,
    )
    .await?;
    Ok((
        forge_domain::ChangeSetId::from_uuid(change_set_id),
        forge_domain::FileMutationId::from_uuid(mutation_id),
    ))
}

pub(super) async fn assert_http_source_writes(
    address: SocketAddr,
    fixture: &Fixture,
    lease_id: Uuid,
    lease_revision: i64,
) -> Result<(), Box<dyn std::error::Error>> {
    let change_set_id = Uuid::now_v7();
    let mutation_id = Uuid::now_v7();
    let add_payload = add_source(
        address,
        fixture,
        lease_id,
        lease_revision,
        change_set_id,
        mutation_id,
    )
    .await?;
    let updated = update_source(address, fixture, &add_payload).await?;
    delete_source(address, fixture, &add_payload, &updated).await?;
    Ok(())
}
