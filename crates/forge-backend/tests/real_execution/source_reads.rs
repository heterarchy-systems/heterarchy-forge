use super::*;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};

const SOURCE_DIR: &str = "source-read-fixture";
const LF_FILE: &str = "a-source.txt";
const CRLF_FILE: &str = "b-source-crlf.txt";
const CRLF_CONTENT: &[u8] = b"first line\r\ndistinct-second-line\r\nthird line\r\n";

fn path_token(path: &str) -> String {
    URL_SAFE_NO_PAD.encode(path.as_bytes())
}

fn source_scope(fixture: &Fixture) -> Value {
    let scope = &fixture.scope;
    json!({
        "workspace_id": scope.workspace_id().into_uuid(),
        "workspace_revision": scope.workspace_revision().get(),
        "locator": {
            "location_id": scope.locator().location_id().into_uuid(),
            "expected_revision": scope.locator().expected_revision().get(),
            "relative_root": scope.locator().relative_root().to_string_lossy(),
        }
    })
}

fn source_activity(fixture: &Fixture) -> Result<Value, Box<dyn std::error::Error>> {
    Ok(json!({
        "activity_id": fixture.activity_id.into_uuid(),
        "runtime_instance_id": fixture.runtime_instance_id.into_uuid(),
        "observed_at_ms": timestamp_now()?.get(),
    }))
}

fn success_result<'a>(
    status: u16,
    response: &'a Value,
    operation: &str,
    scope: &Value,
    fixture: &Fixture,
) -> &'a Value {
    assert_eq!(status, 200, "{operation} response: {response}");
    assert_eq!(response["ok"], true);
    let result = &response["result"];
    assert_eq!(result["scope"], *scope);
    assert_eq!(
        result["activity_id"],
        json!(fixture.activity_id.into_uuid())
    );
    result
}

pub(super) async fn assert_http_source_reads(
    address: SocketAddr,
    fixture: &Fixture,
) -> Result<(), Box<dyn std::error::Error>> {
    let source_root = fixture.workspace_root.join(SOURCE_DIR);
    std::fs::create_dir(&source_root)?;
    std::fs::write(source_root.join(LF_FILE), b"ordinary source\n")?;
    std::fs::write(source_root.join(CRLF_FILE), CRLF_CONTENT)?;

    let scope = source_scope(fixture);
    let activity = source_activity(fixture)?;
    let directory_base64 = path_token(SOURCE_DIR);
    let lf_path = format!("{SOURCE_DIR}/{LF_FILE}");
    let crlf_path = format!("{SOURCE_DIR}/{CRLF_FILE}");

    let (status, listed) = post_command(
        address,
        "file.list",
        json!({
            "scope": scope.clone(),
            "activity": activity.clone(),
            "directory_base64": directory_base64,
            "max_results": 1,
        }),
    )
    .await?;
    let listed = success_result(status, &listed, "file.list", &scope, fixture);
    assert_eq!(listed["entries"].as_array().map(Vec::len), Some(1));
    assert_eq!(listed["truncated"], true);
    assert!(
        listed["scanned_entries"]
            .as_u64()
            .ok_or("file.list scan missing")?
            >= 2
    );
    assert_eq!(listed["entries"][0]["path_base64"], path_token(&lf_path));

    let (status, searched) = post_command(
        address,
        "text.search",
        json!({
            "scope": scope.clone(),
            "activity": activity.clone(),
            "root_base64": path_token(SOURCE_DIR),
            "query": "distinct-second-line",
        }),
    )
    .await?;
    let searched = success_result(status, &searched, "text.search", &scope, fixture);
    let matches = searched["matches"]
        .as_array()
        .ok_or("text.search matches missing")?;
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0]["path_base64"], path_token(&crlf_path));
    assert_eq!(matches[0]["line"], 2);
    assert!(
        matches[0]["preview"]
            .as_str()
            .ok_or("text.search preview missing")?
            .contains("distinct-second-line")
    );

    let (status, sliced) = post_command(
        address,
        "file.read_slice",
        json!({
            "scope": scope.clone(),
            "activity": activity.clone(),
            "path_base64": path_token(&crlf_path),
            "start_line": 2,
            "end_line": 2,
        }),
    )
    .await?;
    let sliced = success_result(status, &sliced, "file.read_slice", &scope, fixture);
    assert_eq!(sliced["path_base64"], path_token(&crlf_path));
    assert_eq!(sliced["content"], "distinct-second-line\r\n");
    assert_eq!(sliced["start_line"], 2);
    assert_eq!(sliced["end_line"], 2);
    assert_eq!(sliced["total_lines"], 3);
    assert_eq!(sliced["eol"], "crlf");
    assert_eq!(sliced["has_final_newline"], true);
    assert_eq!(sliced["line_hashes"].as_array().map(Vec::len), Some(1));
    let whole_hash = sliced["whole_file_hash"]
        .as_str()
        .ok_or("whole_file_hash missing")?;
    let range_hash = sliced["range_hash"].as_str().ok_or("range_hash missing")?;
    assert_ne!(whole_hash, range_hash);

    let (status, rejected) = post_command(
        address,
        "file.read_slice",
        json!({
            "scope": scope,
            "activity": activity,
            "path_base64": path_token("../"),
            "start_line": 1,
            "end_line": 1,
        }),
    )
    .await?;
    assert_eq!(status, 400, "parent path must be rejected: {rejected}");
    assert_eq!(rejected["ok"], false);
    assert_eq!(rejected["error"]["code"], "INVALID_INPUT");
    Ok(())
}
