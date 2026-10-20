use super::lease_readback::{path_token, post_ok, scope_json, wait_until_expired};
use super::source_writes::{activity_json, source_authority_payload};
use super::*;
use serde_json::{Value, json};

const ROOT: &str = "tree-fixture";
const OLD: &str = "tree original\r\n";

fn prepare_files(fixture: &Fixture) -> Result<(), Box<dyn std::error::Error>> {
    let root = fixture.workspace_root.join(ROOT);
    fs::create_dir_all(root.join("old-dir"))?;
    fs::create_dir(root.join("empty-dir"))?;
    fs::write(root.join("old-dir/inside.txt"), b"inside\n")?;
    for name in ["update.txt", "patch.txt", "delete.txt", "move.txt"] {
        fs::write(root.join(name), OLD)?;
    }
    Ok(())
}

async fn read_source(
    address: SocketAddr,
    fixture: &Fixture,
    name: &str,
) -> Result<Value, Box<dyn std::error::Error>> {
    post_ok(
        address,
        "file.read_slice",
        json!({
            "scope": scope_json(fixture), "activity": activity_json(fixture)?,
            "path_base64": path_token(&format!("{ROOT}/{name}")),
            "start_line": 1, "end_line": 1,
        }),
    )
    .await
}

async fn mutations(
    address: SocketAddr,
    fixture: &Fixture,
) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
    let source = read_source(address, fixture, "patch.txt").await?;
    assert_eq!(source["content"], OLD);
    // All four initial files have identical bytes; these observed hashes apply to each.
    let whole = &source["whole_file_hash"];
    let path = |name: &str| path_token(&format!("{ROOT}/{name}"));
    Ok(vec![
        json!({"kind":"create_directory","mutation_id":Uuid::now_v7(),"path_base64":path("new-dir")}),
        json!({"kind":"create_file","mutation_id":Uuid::now_v7(),"path_base64":path("new.txt"),"content":"created\n"}),
        json!({"kind":"update_file","mutation_id":Uuid::now_v7(),"path_base64":path("update.txt"),"expected_whole_file_hash":whole,"content":"updated\n"}),
        json!({"kind":"patch_file","mutation_id":Uuid::now_v7(),"path_base64":path("patch.txt"),"expected_whole_file_hash":whole,
            "hunks":[{"start_line":1,"end_line":1,"expected_range_hash":source["range_hash"],"replacement":"patched\r\n"}]}),
        json!({"kind":"delete_file","mutation_id":Uuid::now_v7(),"path_base64":path("delete.txt"),"expected_whole_file_hash":whole}),
        json!({"kind":"move_file","mutation_id":Uuid::now_v7(),"source_base64":path("move.txt"),"destination_base64":path("moved.txt"),"expected_whole_file_hash":whole}),
        json!({"kind":"move_directory","mutation_id":Uuid::now_v7(),"source_base64":path("old-dir"),"destination_base64":path("moved-dir")}),
        json!({"kind":"delete_directory","mutation_id":Uuid::now_v7(),"path_base64":path("empty-dir")}),
    ])
}

fn assert_files(fixture: &Fixture) -> Result<(), Box<dyn std::error::Error>> {
    let root = fixture.workspace_root.join(ROOT);
    assert!(root.join("new-dir").is_dir());
    for (path, expected) in [
        ("new.txt", "created\n"),
        ("update.txt", "updated\n"),
        ("patch.txt", "patched\r\n"),
        ("moved.txt", OLD),
        ("moved-dir/inside.txt", "inside\n"),
    ] {
        assert_eq!(fs::read(root.join(path))?, expected.as_bytes(), "{path}");
    }
    for absent in ["delete.txt", "move.txt", "old-dir", "empty-dir"] {
        assert!(
            !root.join(absent).exists(),
            "{absent} remained after tree apply"
        );
    }
    Ok(())
}

fn readback_payload(fixture: &Fixture, change_set_id: Uuid) -> Value {
    json!({"scope":scope_json(fixture), "activity_id":fixture.activity_id.into_uuid(),
        "change_set_id":change_set_id})
}

async fn assert_history(
    address: SocketAddr,
    fixture: &Fixture,
    change_set_id: Uuid,
    applied: &Value,
) -> Result<(), Box<dyn std::error::Error>> {
    // ID-only observation works even if the caller lost the digest-bearing response.
    let payload = readback_payload(fixture, change_set_id);
    let history = post_ok(address, "source_tree.readback", payload.clone()).await?;
    assert_eq!(history["found"], true);
    assert_eq!(history["change_set_state"], "applied");
    assert_eq!(history["request_digest"], applied["request_digest"]);
    assert_eq!(history["mutation_count"], 8);
    assert_eq!(history["applied_mutations"], applied["applied_mutations"]);
    assert_eq!(history["retry_authorized"], false);
    assert_eq!(history["request_equivalence_proven"], false);
    assert_eq!(history["diff"]["origin"], "tree_change_set");
    let mut exact = payload.clone();
    exact["expected_request_digest"] = applied["request_digest"].clone();
    assert_eq!(
        post_ok(address, "source_tree.readback", exact.clone()).await?,
        history
    );
    exact["expected_request_digest"] = json!("00".repeat(32));
    let (status, rejected) = post_command(address, "source_tree.readback", exact).await?;
    assert_eq!(status, 409);
    assert_eq!(rejected["error"]["code"], "SOURCE_CONFLICT");
    let mut wrong_activity = payload;
    wrong_activity["activity_id"] = json!(Uuid::now_v7());
    let (status, rejected) = post_command(address, "source_tree.readback", wrong_activity).await?;
    assert_eq!(status, 409);
    assert_eq!(rejected["error"]["code"], "SOURCE_CONFLICT");
    Ok(())
}

pub(super) async fn assert_http_tree_writes(
    address: SocketAddr,
    fixture: &Fixture,
) -> Result<(), Box<dyn std::error::Error>> {
    prepare_files(fixture)?;
    let changes = mutations(address, fixture).await?;
    let lease_id = Uuid::now_v7();
    let lease = post_ok(address, "writer_lease.acquire", json!({
        "scope":scope_json(fixture), "activity_id":fixture.activity_id.into_uuid(),
        "actor":{"session_id":fixture.session_id.into_uuid(),"principal":{"kind":"trusted_stdio"},"agent_id":fixture.agent_id.into_uuid()},
        "writer_lease_id":lease_id,"duration_ms":2000,
        "scopes":[{"kind":"directory_subtree","path_base64":path_token(ROOT)}],
    })).await?;
    let revision = lease["revision"]
        .as_i64()
        .ok_or("tree lease revision missing")?;
    let change_set_id = Uuid::now_v7();
    let mut payload = source_authority_payload(fixture, lease_id, revision)?;
    payload["change_set_id"] = json!(change_set_id);
    payload["mutations"] = json!(changes);
    let applied = post_ok(address, "source_tree.apply", payload.clone()).await?;
    assert_eq!(applied["status"], "applied");
    assert_eq!(applied["change_set_id"], json!(change_set_id));
    assert_eq!(
        applied["applied_mutations"].as_array().map(Vec::len),
        Some(8)
    );
    assert!(applied["uncertain_mutation"].is_null());
    assert_files(fixture)?;
    assert_history(address, fixture, change_set_id, &applied).await?;
    let replay = post_ok(address, "source_tree.apply", payload.clone()).await?;
    assert_eq!(replay["status"], "already_applied");
    assert_eq!(replay["request_digest"], applied["request_digest"]);
    payload["mutations"][1]["content"] = json!("different\n");
    let (status, rejected) = post_command(address, "source_tree.apply", payload).await?;
    assert_eq!(status, 409);
    assert_eq!(rejected["error"]["code"], "SOURCE_CONFLICT");
    assert_files(fixture)?;
    wait_until_expired(
        lease["lease_until_ms"]
            .as_i64()
            .ok_or("tree lease expiry missing")?,
    )
    .await?;
    assert_history(address, fixture, change_set_id, &applied).await?;
    let released = post_ok(address, "writer_lease.release", json!({
        "scope":scope_json(fixture), "activity_id":fixture.activity_id.into_uuid(),
        "actor":{"session_id":fixture.session_id.into_uuid(),"principal":{"kind":"trusted_stdio"},"agent_id":fixture.agent_id.into_uuid()},
        "writer_lease_id":lease_id,"expected_revision":revision,
    })).await?;
    assert_eq!(released["state"], "released");
    Ok(())
}
