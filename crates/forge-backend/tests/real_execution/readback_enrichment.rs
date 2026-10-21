//! A2 readback enrichment proofs over the real HTTP boundary.
//!
//! Round-trips the enriched `command.list` per-command classification and the
//! lossless `diff.read` content/evidence projection from the seeded workspace,
//! mirroring what the native downstream projection consumes.

use super::lease_readback::{MUTATION_PATH, path_token, post_ok, scope_json};
use super::*;
use serde_json::json;

const MAKEFILE: &str = "ci:\n\t@true\npackage:\n\t@true\n";

pub(super) async fn assert_http_readback_enrichment(
    address: SocketAddr,
    fixture: &Fixture,
    diff_id: Uuid,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_command_list_classification(address, fixture).await?;
    assert_diff_read_content_and_evidence(address, fixture, diff_id).await?;
    Ok(())
}

/// `command.list` must expose the sealed catalog classification per command
/// so the consumer can rebuild the native command projection from HTTP data.
async fn assert_command_list_classification(
    address: SocketAddr,
    fixture: &Fixture,
) -> Result<(), Box<dyn std::error::Error>> {
    fs::write(fixture.workspace_root.join("Makefile"), MAKEFILE)?;
    let result = post_ok(
        address,
        "command.list",
        json!({
            "scope": scope_json(fixture),
            "activity": {
                "activity_id": fixture.activity_id.into_uuid(),
                "runtime_instance_id": fixture.runtime_instance_id.into_uuid(),
                "observed_at_ms": timestamp_now()?.get(),
            },
        }),
    )
    .await?;
    assert_eq!(
        result["activity_id"],
        json!(fixture.activity_id.into_uuid())
    );
    assert_eq!(result["command_count"], 3);
    let fingerprint = result["catalog_fingerprint"]
        .as_str()
        .ok_or("catalog fingerprint missing")?;
    assert_eq!(fingerprint.len(), 64);
    let commands = result["commands"]
        .as_array()
        .ok_or("command catalog entries missing")?;
    assert_eq!(commands.len(), 3);
    assert_eq!(commands[0]["id"], "make:ci");
    assert_eq!(commands[0]["class"], "verify");
    assert_eq!(commands[1]["id"], "make:package");
    assert_eq!(commands[1]["class"], "generated_package");
    assert_eq!(commands[2]["id"], "forge:research-package-v1");
    assert_eq!(commands[2]["class"], "verify");
    for command in commands {
        let digest = command["request_digest"]
            .as_str()
            .ok_or("sealed command request digest missing")?;
        assert_eq!(digest.len(), 64);
        assert!(
            digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
    }
    Ok(())
}

/// `diff.read` must return the diff content plus the full durable evidence
/// record, matching the fields the native diff projection consumes.
async fn assert_diff_read_content_and_evidence(
    address: SocketAddr,
    fixture: &Fixture,
    diff_id: Uuid,
) -> Result<(), Box<dyn std::error::Error>> {
    let result = post_ok(
        address,
        "diff.read",
        json!({
            "scope": scope_json(fixture),
            "diff_id": diff_id,
        }),
    )
    .await?;
    assert_eq!(result["diff_id"], json!(diff_id));
    assert_eq!(result["health"], "available");
    assert_eq!(result["has_content"], true);
    let content = result["content"]
        .as_str()
        .ok_or("available diff content missing")?;
    assert!(!content.is_empty(), "diff content was empty");

    let diff = &result["diff"];
    assert_eq!(diff["diff_id"], json!(diff_id));
    assert_eq!(
        diff["workspace_id"],
        json!(fixture.scope.workspace_id().into_uuid())
    );
    assert_eq!(diff["activity_id"], json!(fixture.activity_id.into_uuid()));
    assert!(diff["change_set_id"].as_str().is_some());
    assert_eq!(diff["origin"], "file_mutation");
    assert!(diff["origin_mutation_id"].as_str().is_some());
    assert_eq!(diff["state"], "ready");
    assert_eq!(diff["render_kind"], "text");
    assert!(diff["compressed_hash"].as_str().is_some());
    assert!(diff["uncompressed_hash"].as_str().is_some());
    assert!(
        diff["uncompressed_size_bytes"]
            .as_u64()
            .is_some_and(|size| size > 0)
    );
    assert!(diff["renderer_version"].as_u64().is_some());
    assert!(diff["redaction_policy_version"].as_u64().is_some());
    assert!(diff["created_at_ms"].as_i64().is_some());
    assert!(diff["updated_at_ms"].as_i64().is_some());
    assert!(diff["revision"].as_i64().is_some());

    let entries = diff["entries"]
        .as_array()
        .ok_or("diff evidence entries missing")?;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["subject"], "file");
    assert_eq!(entries[0]["primary_path_base64"], path_token(MUTATION_PATH));
    assert!(entries[0]["secondary_path_base64"].is_null());
    assert_eq!(entries[0]["change_kind"], "created");
    assert!(
        entries[0]["additions"]
            .as_i64()
            .is_some_and(|lines| lines >= 1)
    );
    assert_eq!(entries[0]["deletions"], 0);
    Ok(())
}
