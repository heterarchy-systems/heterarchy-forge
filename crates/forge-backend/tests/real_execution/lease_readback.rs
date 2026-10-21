use super::*;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use forge_domain::FileMutationId;
use serde_json::{Value, json};

pub(super) const MUTATION_PATH: &str = "lease-readback-created.txt";
const LEASE_PATHS: [&str; 5] = [
    MUTATION_PATH,
    "lease-readback-b.txt",
    "lease-readback-c.txt",
    "lease-readback-d.txt",
    "lease-readback-e.txt",
];
const SHORT_LEASE_DURATION_MS: i64 = 2_000;
const ACTIVE_WRITE_LEASE_DURATION_MS: i64 = forge_domain::MAX_WRITER_LEASE_DURATION_MILLIS;
const ACTIVE_WRITE_LEASE_ACQUIRE_DURATION_MS: i64 =
    ACTIVE_WRITE_LEASE_DURATION_MS - SHORT_LEASE_DURATION_MS;

pub(super) fn path_token(path: &str) -> String {
    URL_SAFE_NO_PAD.encode(path.as_bytes())
}

pub(super) fn scope_json(fixture: &Fixture) -> Value {
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

fn lease_actor(fixture: &Fixture) -> Value {
    json!({
        "session_id": fixture.session_id.into_uuid(),
        "principal": { "kind": "trusted_stdio" },
        "agent_id": fixture.agent_id.into_uuid(),
    })
}

fn ok_result<'a>(
    status: u16,
    response: &'a Value,
    operation: &str,
) -> Result<&'a Value, Box<dyn std::error::Error>> {
    if status != 200 {
        return Err(format!("{operation} failed ({status}): {response}").into());
    }
    if response["ok"] != true {
        return Err(format!("{operation} returned a failure: {response}").into());
    }
    Ok(&response["result"])
}

pub(super) async fn post_ok(
    address: SocketAddr,
    operation: &str,
    payload: Value,
) -> Result<Value, Box<dyn std::error::Error>> {
    let (status, response) = post_command(address, operation, payload).await?;
    Ok(ok_result(status, &response, operation)?.clone())
}

pub(super) async fn wait_until_expired(
    lease_until_ms: i64,
) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if timestamp_now()?.get() >= lease_until_ms {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("short Writer Lease did not expire within its bound".into());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn acquire_and_read_lease(
    address: SocketAddr,
    fixture: &Fixture,
    duration_ms: i64,
) -> Result<(Uuid, i64), Box<dyn std::error::Error>> {
    let scope = scope_json(fixture);
    let actor = lease_actor(fixture);
    let lease_id = Uuid::now_v7();
    let scope_entries: Vec<Value> = LEASE_PATHS
        .iter()
        .map(|path| json!({ "kind": "exact_path", "path_base64": path_token(path) }))
        .collect();

    let acquired = post_ok(
        address,
        "writer_lease.acquire",
        json!({
            "scope": scope.clone(),
            "activity_id": fixture.activity_id.into_uuid(),
            "actor": actor.clone(),
            "writer_lease_id": lease_id,
            "duration_ms": duration_ms,
            "scopes": scope_entries,
        }),
    )
    .await?;
    assert_eq!(acquired["scope"], scope);
    assert_eq!(acquired["writer_lease_id"], lease_id.to_string());
    assert_eq!(acquired["total_scope_count"], 5);
    assert_eq!(acquired["scopes"].as_array().map(Vec::len), Some(4));
    assert_eq!(acquired["next_scope_offset"], 4);
    assert_eq!(
        acquired["owner_activity_id"],
        json!(fixture.activity_id.into_uuid())
    );
    assert_eq!(
        acquired["owner_session_id"],
        json!(fixture.session_id.into_uuid())
    );
    assert_eq!(acquired["status"], "active");
    assert!(acquired["blocking_reason"].is_null());
    assert_eq!(acquired["recovery_action"], "none");
    assert_eq!(acquired["scope_page_limit"], 4);
    assert!(acquired["observed_at_ms"].as_i64().is_some());
    let acquired_revision = acquired["revision"]
        .as_i64()
        .ok_or("acquire revision missing")?;

    let listed = post_ok(
        address,
        "writer_lease.list",
        json!({
            "scope": scope.clone(),
            "limit": 1,
        }),
    )
    .await?;
    assert_eq!(listed["leases"].as_array().map(Vec::len), Some(1));
    assert_eq!(listed["leases"][0]["scope"], scope);
    assert_eq!(listed["leases"][0]["writer_lease_id"], lease_id.to_string());
    assert_eq!(listed["leases"][0]["status"], "active");
    assert_eq!(listed["leases"][0]["scope_page_limit"], 4);

    let page = post_ok(
        address,
        "writer_lease.get",
        json!({
            "scope": scope.clone(),
            "writer_lease_id": lease_id,
            "expected_revision": acquired_revision,
        }),
    )
    .await?;
    assert_eq!(page["found"], true);
    assert_eq!(page["scope"], scope);
    assert_eq!(page["scopes"].as_array().map(Vec::len), Some(4));
    assert_eq!(page["next_scope_offset"], 4);

    let tail = post_ok(
        address,
        "writer_lease.get",
        json!({
            "scope": scope.clone(),
            "writer_lease_id": lease_id,
            "scope_offset": 4,
        }),
    )
    .await?;
    assert_eq!(tail["found"], true);
    assert_eq!(tail["scopes"].as_array().map(Vec::len), Some(1));
    assert!(tail["next_scope_offset"].is_null());

    Ok((lease_id, acquired_revision))
}

async fn renew_lease(
    address: SocketAddr,
    fixture: &Fixture,
    lease_id: Uuid,
    acquired_revision: i64,
    duration_ms: i64,
) -> Result<(i64, i64), Box<dyn std::error::Error>> {
    let scope = scope_json(fixture);
    let actor = lease_actor(fixture);
    let renewed = post_ok(
        address,
        "writer_lease.renew",
        json!({
            "scope": scope.clone(),
            "activity_id": fixture.activity_id.into_uuid(),
            "actor": actor.clone(),
            "writer_lease_id": lease_id,
            "expected_revision": acquired_revision,
            "duration_ms": duration_ms,
        }),
    )
    .await?;
    let renewed_revision = renewed["revision"]
        .as_i64()
        .ok_or("renew revision missing")?;
    assert_eq!(renewed_revision, acquired_revision + 1);
    let lease_until_ms = renewed["lease_until_ms"]
        .as_i64()
        .ok_or("renew lease_until_ms missing")?;

    let (status, stale) = post_command(
        address,
        "writer_lease.renew",
        json!({
            "scope": scope.clone(),
            "activity_id": fixture.activity_id.into_uuid(),
            "actor": actor.clone(),
            "writer_lease_id": lease_id,
            "expected_revision": acquired_revision,
            "duration_ms": duration_ms,
        }),
    )
    .await?;
    assert_ne!(status, 200, "stale lease revision was accepted: {stale}");
    assert_eq!(stale["ok"], false);

    Ok((renewed_revision, lease_until_ms))
}

async fn acquire_historical_readback_lease(
    address: SocketAddr,
    fixture: &Fixture,
) -> Result<(Uuid, i64, i64), Box<dyn std::error::Error>> {
    let scope = scope_json(fixture);
    let lease_id = Uuid::now_v7();
    let acquired = post_ok(
        address,
        "writer_lease.acquire",
        json!({
            "scope": scope.clone(),
            "activity_id": fixture.activity_id.into_uuid(),
            "actor": lease_actor(fixture),
            "writer_lease_id": lease_id,
            "duration_ms": SHORT_LEASE_DURATION_MS,
            "scopes": [{
                "kind": "exact_path",
                "path_base64": path_token(MUTATION_PATH),
            }],
        }),
    )
    .await?;
    assert_eq!(acquired["scope"], scope);
    assert_eq!(acquired["writer_lease_id"], lease_id.to_string());
    assert_eq!(acquired["status"], "active");
    assert_eq!(acquired["total_scope_count"], 1);
    let revision = acquired["revision"]
        .as_i64()
        .ok_or("historical readback lease revision missing")?;
    let lease_until_ms = acquired["lease_until_ms"]
        .as_i64()
        .ok_or("historical readback lease expiry missing")?;
    assert!(timestamp_now()?.get() < lease_until_ms);
    Ok((lease_id, revision, lease_until_ms))
}

async fn assert_historical_readback(
    address: SocketAddr,
    fixture: &Fixture,
    change_set_id: forge_domain::ChangeSetId,
    mutation_id: FileMutationId,
) -> Result<Uuid, Box<dyn std::error::Error>> {
    let scope = scope_json(fixture);

    let readback = post_ok(
        address,
        "file.mutation_readback",
        json!({
            "scope": scope.clone(),
            "activity_id": fixture.activity_id.into_uuid(),
            "change_set_id": change_set_id.into_uuid(),
            "mutation_id": mutation_id.into_uuid(),
        }),
    )
    .await?;
    assert_eq!(readback["found"], true);
    assert_eq!(readback["scope"], scope);
    assert_eq!(
        readback["activity_id"],
        json!(fixture.activity_id.into_uuid())
    );
    assert_eq!(readback["change_set_id"], json!(change_set_id.into_uuid()));
    assert_eq!(readback["mutation_id"], json!(mutation_id.into_uuid()));
    assert_eq!(readback["retry_authorized"], false);
    assert_eq!(readback["request_equivalence_proven"], false);
    assert_eq!(readback["change_set_state"], "applied");
    assert_eq!(readback["kind"], "create");
    assert_eq!(readback["path_base64"], path_token(MUTATION_PATH));
    assert_eq!(readback["post_state"]["exists"], true);
    assert_eq!(
        readback["diff"]["origin_mutation_id"],
        json!(mutation_id.into_uuid())
    );
    let diff_id = readback["diff"]["id"]
        .as_str()
        .ok_or("mutation readback diff id missing")?
        .parse::<Uuid>()?;

    let (status, wrong_mutation) = post_command(
        address,
        "file.mutation_readback",
        json!({
            "scope": scope.clone(),
            "activity_id": fixture.activity_id.into_uuid(),
            "change_set_id": change_set_id.into_uuid(),
            "mutation_id": Uuid::now_v7(),
        }),
    )
    .await?;
    assert_ne!(
        status, 200,
        "wrong mutation tuple was accepted: {wrong_mutation}"
    );
    assert_eq!(wrong_mutation["ok"], false);

    let (status, wrong_activity) = post_command(
        address,
        "file.mutation_readback",
        json!({
            "scope": scope,
            "activity_id": Uuid::now_v7(),
            "change_set_id": change_set_id.into_uuid(),
            "mutation_id": mutation_id.into_uuid(),
        }),
    )
    .await?;
    assert_ne!(
        status, 200,
        "wrong Activity tuple was accepted: {wrong_activity}"
    );
    assert_eq!(wrong_activity["ok"], false);
    Ok(diff_id)
}

pub(super) async fn assert_http_lease_and_mutation_readback(
    address: SocketAddr,
    fixture: &Fixture,
) -> Result<Uuid, Box<dyn std::error::Error>> {
    let (active_lease_id, acquired_revision) =
        acquire_and_read_lease(address, fixture, ACTIVE_WRITE_LEASE_ACQUIRE_DURATION_MS).await?;
    let (active_lease_revision, active_lease_until_ms) = renew_lease(
        address,
        fixture,
        active_lease_id,
        acquired_revision,
        ACTIVE_WRITE_LEASE_DURATION_MS,
    )
    .await?;
    super::source_writes::assert_http_source_writes(
        address,
        fixture,
        active_lease_id,
        active_lease_revision,
    )
    .await?;
    assert!(timestamp_now()?.get() < active_lease_until_ms);
    let active_release = post_ok(
        address,
        "writer_lease.release",
        json!({
            "scope": scope_json(fixture),
            "activity_id": fixture.activity_id.into_uuid(),
            "actor": lease_actor(fixture),
            "writer_lease_id": active_lease_id,
            "expected_revision": active_lease_revision,
        }),
    )
    .await?;
    assert_eq!(active_release["state"], "released");
    assert_eq!(active_release["status"], "released");
    assert_eq!(active_release["revision"], active_lease_revision + 1);

    let (short_lease_id, short_lease_revision, short_lease_until_ms) =
        acquire_historical_readback_lease(address, fixture).await?;
    let (change_set_id, mutation_id) =
        super::source_writes::assert_http_single_create_for_historical_readback(
            address,
            fixture,
            short_lease_id,
            short_lease_revision,
        )
        .await?;
    wait_until_expired(short_lease_until_ms).await?;
    assert!(timestamp_now()?.get() >= short_lease_until_ms);
    let diff_id = assert_historical_readback(address, fixture, change_set_id, mutation_id).await?;
    let released = post_ok(
        address,
        "writer_lease.release",
        json!({
            "scope": scope_json(fixture),
            "activity_id": fixture.activity_id.into_uuid(),
            "actor": lease_actor(fixture),
            "writer_lease_id": short_lease_id,
            "expected_revision": short_lease_revision,
        }),
    )
    .await?;
    assert_eq!(released["state"], "released");
    assert_eq!(released["status"], "released");
    assert_eq!(released["revision"], short_lease_revision + 1);
    super::tree_writes::assert_http_tree_writes(address, fixture).await?;
    Ok(diff_id)
}
