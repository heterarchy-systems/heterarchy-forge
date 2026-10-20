//! Real HTTP proofs for the dedicated Activity lease lane.
//!
//! These tests exercise the four frozen lease operations through the listener,
//! the narrow native `ActivityLeaseClient` worker, and the durable Workspace
//! Activity rows.  Every assertion reads the resulting row by its original
//! identity so a successful HTTP reply cannot stand in for durable evidence.

use super::*;

use forge_backend::CommandExecutor;
use serde_json::{Value, json};
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use tokio::time::timeout;

const SINGLE_DURATION_MS: i64 = 60_000;
const BATCH_DURATIONS_MS: [i64; 3] = [70_000, 30_000, 90_000];

fn backend_state(fixture: &Fixture) -> Result<forge_backend::AppState, Box<dyn std::error::Error>> {
    let product_cache_root = fixture.root.join("product-cache-activity-leases");
    fs::create_dir_all(&product_cache_root)?;
    let destination_id = delegated_destination_id(fixture)?;
    super::assemble_fixture(
        backend_config()?,
        fixture,
        &product_cache_root,
        destination_id,
    )
}

fn scope_json(fixture: &Fixture) -> Value {
    scope_json_from_scope(&fixture.scope)
}

fn scope_json_from_scope(scope: &ResolvedWorkspaceScope) -> Value {
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

fn activity_value(response: &Value) -> Result<Value, Box<dyn std::error::Error>> {
    response["result"]["activity"]
        .as_object()
        .cloned()
        .map(Value::Object)
        .ok_or_else(|| "Activity projection missing".into())
}

fn activity_id(activity: &Value) -> Result<Uuid, Box<dyn std::error::Error>> {
    activity["activity_id"]
        .as_str()
        .ok_or("Activity identity missing")?
        .parse()
        .map_err(Into::into)
}

fn lease_revision(activity: &Value) -> Result<i64, Box<dyn std::error::Error>> {
    activity["lease_revision"]
        .as_i64()
        .ok_or_else(|| "Activity lease revision missing".into())
}

fn lease_until(activity: &Value) -> Result<i64, Box<dyn std::error::Error>> {
    activity["lease_until_ms"]
        .as_i64()
        .ok_or_else(|| "Activity lease expiry missing".into())
}

fn assert_failure(status: u16, response: &Value, expected_code: &str) {
    assert_ne!(status, 200, "unexpected successful response: {response}");
    assert_eq!(response["ok"], false);
    assert_eq!(response["error"]["code"], expected_code);
}

fn assert_open_unleased(activity: &Value, expected_id: Uuid, expected_revision: i64) {
    assert_eq!(activity["activity_id"], json!(expected_id));
    assert_eq!(activity["state"], "open");
    assert_eq!(activity["lease_owner_id"], Value::Null);
    assert_eq!(activity["lease_until_ms"], Value::Null);
    assert_eq!(activity["lease_revision"], json!(expected_revision));
}

async fn get_activity(
    address: SocketAddr,
    fixture: &Fixture,
    activity_id: Uuid,
) -> Result<Value, Box<dyn std::error::Error>> {
    let (status, response) = post_command(
        address,
        "activity.get",
        json!({
            "scope": scope_json(fixture),
            "activity_id": activity_id,
        }),
    )
    .await?;
    assert_eq!(status, 200, "activity.get response: {response}");
    assert_eq!(response["ok"], true);
    assert_eq!(response["result"]["found"], true);
    activity_value(&response)
}

async fn bootstrap_activity(
    address: SocketAddr,
    fixture: &Fixture,
    duration_ms: i64,
) -> Result<(Uuid, Uuid, Value), Box<dyn std::error::Error>> {
    bootstrap_activity_with_runtime(address, fixture, duration_ms, Uuid::now_v7()).await
}

async fn bootstrap_activity_with_runtime(
    address: SocketAddr,
    fixture: &Fixture,
    duration_ms: i64,
    runtime_instance_id: Uuid,
) -> Result<(Uuid, Uuid, Value), Box<dyn std::error::Error>> {
    let activity_id = Uuid::now_v7();
    let observed_at = timestamp_now()?;
    let requested_until = add_millis(observed_at, duration_ms)?;
    let (status, response) = post_command(
        address,
        "activity.bootstrap",
        json!({
            "scope": scope_json(fixture),
            "activity_id": activity_id,
            "runtime_instance_id": runtime_instance_id,
            "observed_at_ms": observed_at.get(),
            "lease_until_ms": requested_until.get(),
        }),
    )
    .await?;
    assert_eq!(status, 200, "activity.bootstrap response: {response}");
    assert_eq!(response["ok"], true);
    assert_eq!(response["result"]["status"], "created");
    let activity = activity_value(&response)?;
    let created_at = activity["created_at_ms"]
        .as_i64()
        .ok_or("Activity creation time missing")?;
    let actual_until = lease_until(&activity)?;
    assert_eq!(actual_until - created_at, duration_ms);
    Ok((activity_id, runtime_instance_id, activity))
}

async fn wait_until_expired(lease_until_ms: i64) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if timestamp_now()?.get() >= lease_until_ms {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("Activity lease did not expire within its bound".into());
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

async fn renew(
    address: SocketAddr,
    fixture: &Fixture,
    activity_id: Uuid,
    runtime_instance_id: Uuid,
    expected_lease_revision: i64,
    duration_ms: i64,
) -> Result<(u16, Value), Box<dyn std::error::Error>> {
    post_command(
        address,
        "activity.lease.renew",
        json!({
            "scope": scope_json(fixture),
            "activity_id": activity_id,
            "runtime_instance_id": runtime_instance_id,
            "expected_lease_revision": expected_lease_revision,
            "duration_ms": duration_ms,
        }),
    )
    .await
}

async fn release(
    address: SocketAddr,
    fixture: &Fixture,
    activity_id: Uuid,
    runtime_instance_id: Uuid,
    expected_lease_revision: i64,
) -> Result<(u16, Value), Box<dyn std::error::Error>> {
    post_command(
        address,
        "activity.lease.release",
        json!({
            "scope": scope_json(fixture),
            "activity_id": activity_id,
            "runtime_instance_id": runtime_instance_id,
            "expected_lease_revision": expected_lease_revision,
        }),
    )
    .await
}

async fn renew_batch(
    address: SocketAddr,
    fixture: &Fixture,
    commands: Value,
) -> Result<(u16, Value), Box<dyn std::error::Error>> {
    post_command(
        address,
        "activity.lease.renew_batch",
        json!({
            "scope": scope_json(fixture),
            "commands": commands,
        }),
    )
    .await
}

async fn release_batch(
    address: SocketAddr,
    fixture: &Fixture,
    commands: Value,
) -> Result<(u16, Value), Box<dyn std::error::Error>> {
    post_command(
        address,
        "activity.lease.release_batch",
        json!({
            "scope": scope_json(fixture),
            "commands": commands,
        }),
    )
    .await
}

async fn close(
    address: SocketAddr,
    fixture: &Fixture,
    activity_id: Uuid,
    runtime_instance_id: Uuid,
    expected_lease_revision: i64,
) -> Result<(u16, Value), Box<dyn std::error::Error>> {
    post_command(
        address,
        "activity.close",
        json!({
            "scope": scope_json(fixture),
            "activity_id": activity_id,
            "runtime_instance_id": runtime_instance_id,
            "expected_lease_revision": expected_lease_revision,
        }),
    )
    .await
}

fn bootstrap_native_activity(
    fixture: &Fixture,
) -> Result<(Uuid, Uuid, i64), Box<dyn std::error::Error>> {
    let activity_id = ActivityId::from_uuid(Uuid::now_v7());
    let runtime_instance_id = fixture.runtime_instance_id;
    let observed_at = timestamp_now()?;
    let result = fixture.client.bootstrap_activity(
        fixture.scope.clone(),
        activity_id,
        runtime_instance_id,
        observed_at,
        add_millis(observed_at, 120_000)?,
    )?;
    let activity = result
        .activity()
        .ok_or("native Activity bootstrap row missing")?;
    Ok((
        activity_id.into_uuid(),
        runtime_instance_id.into_uuid(),
        activity.lease_revision().get(),
    ))
}

fn lease_batch_payload(
    fixture: &Fixture,
    second_id: Uuid,
    second_runtime: Uuid,
    first_revision: i64,
    second_revision: i64,
) -> Value {
    json!({
        "scope": scope_json(fixture),
        "commands": [
            {
                "activity_id": fixture.activity_id.into_uuid(),
                "runtime_instance_id": fixture.runtime_instance_id.into_uuid(),
                "expected_lease_revision": first_revision,
                "duration_ms": 4_000,
            },
            {
                "activity_id": second_id,
                "runtime_instance_id": second_runtime,
                "expected_lease_revision": second_revision,
                "duration_ms": 6_000,
            },
        ],
    })
}

async fn read_http_response(
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

struct HeldBatch {
    second_id: Uuid,
    second_runtime: Uuid,
    first_revision: i64,
    second_revision: i64,
    payload: Value,
}

fn prepare_held_batch(
    running: &super::binding_lifecycle::HttpBindingFixture,
) -> Result<HeldBatch, Box<dyn std::error::Error>> {
    let (second_id, second_runtime, _) = bootstrap_native_activity(&running.fixture)?;
    let observed = running.fixture.activity_leases.observe_activity_leases(
        running.fixture.scope.clone(),
        vec![
            ActivityId::from_uuid(running.fixture.activity_id.into_uuid()),
            ActivityId::from_uuid(second_id),
        ],
    )?;
    if observed.len() != 2
        || observed[0].id() != running.fixture.activity_id
        || observed[1].id().into_uuid() != second_id
    {
        return Err("native Activity lease observations did not preserve batch order".into());
    }
    let first_revision = observed[0].lease_revision().get();
    let second_revision = observed[1].lease_revision().get();
    let payload = lease_batch_payload(
        &running.fixture,
        second_id,
        second_runtime,
        first_revision,
        second_revision,
    );
    Ok(HeldBatch {
        second_id,
        second_runtime,
        first_revision,
        second_revision,
        payload,
    })
}

fn assert_batch_readback(
    response: &Value,
    fixture: &Fixture,
    second_id: Uuid,
    second_runtime: Uuid,
    first_revision: i64,
    second_revision: i64,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(response["error"]["code"], "UNKNOWN_OUTCOME");
    assert_eq!(response["error"]["recovery_action"], "read_back");
    let readback = &response["error"]["readback"];
    assert_eq!(readback["kind"], "activity_lease_batch");
    assert_eq!(
        readback["workspace_id"],
        json!(fixture.scope.workspace_id().into_uuid())
    );
    assert_eq!(readback["operation"], "renew");
    let leases = readback["leases"]
        .as_array()
        .ok_or("Activity lease batch readback keys missing")?;
    assert_eq!(leases.len(), 2);
    assert_eq!(
        leases[0]["activity_id"],
        json!(fixture.activity_id.into_uuid())
    );
    assert_eq!(
        leases[0]["runtime_instance_id"],
        json!(fixture.runtime_instance_id.into_uuid())
    );
    assert_eq!(leases[0]["expected_lease_revision"], json!(first_revision));
    assert_eq!(leases[1]["activity_id"], json!(second_id));
    assert_eq!(leases[1]["runtime_instance_id"], json!(second_runtime));
    assert_eq!(leases[1]["expected_lease_revision"], json!(second_revision));
    Ok(())
}

struct OwnedActivity {
    id: Uuid,
    runtime: Uuid,
    initial: Value,
}

async fn assert_single_renew_and_stale(
    address: SocketAddr,
    fixture: &Fixture,
) -> Result<Value, Box<dyn std::error::Error>> {
    let initial = get_activity(address, fixture, fixture.activity_id.into_uuid()).await?;
    let initial_revision = lease_revision(&initial)?;
    let (status, renewed) = renew(
        address,
        fixture,
        fixture.activity_id.into_uuid(),
        fixture.runtime_instance_id.into_uuid(),
        initial_revision,
        SINGLE_DURATION_MS,
    )
    .await?;
    assert_eq!(status, 200, "single renew response: {renewed}");
    assert_eq!(renewed["result"]["status"], "renewed");
    let renewed_activity = activity_value(&renewed)?;
    let now = timestamp_now()?.get();
    assert!(lease_until(&renewed_activity)? > now);
    assert!(lease_until(&renewed_activity)? - now <= SINGLE_DURATION_MS + 1_000);
    assert_eq!(lease_revision(&renewed_activity)?, initial_revision + 1);

    let (status, stale) = renew(
        address,
        fixture,
        fixture.activity_id.into_uuid(),
        fixture.runtime_instance_id.into_uuid(),
        initial_revision,
        SINGLE_DURATION_MS,
    )
    .await?;
    assert_failure(status, &stale, "LEASE_CONFLICT");
    assert_eq!(
        get_activity(address, fixture, fixture.activity_id.into_uuid()).await?,
        renewed_activity
    );
    Ok(renewed_activity)
}

async fn new_owned_activity(
    address: SocketAddr,
    fixture: &Fixture,
) -> Result<OwnedActivity, Box<dyn std::error::Error>> {
    let (id, runtime, initial) = bootstrap_activity_with_runtime(
        address,
        fixture,
        120_000,
        fixture.runtime_instance_id.into_uuid(),
    )
    .await?;
    Ok(OwnedActivity {
        id,
        runtime,
        initial,
    })
}

async fn assert_ordered_renew_batch(
    address: SocketAddr,
    fixture: &Fixture,
    renewed_fixture: &Value,
    second: &OwnedActivity,
    third: &OwnedActivity,
) -> Result<Value, Box<dyn std::error::Error>> {
    let (status, batch) = renew_batch(
        address,
        fixture,
        json!([
            {
                "activity_id": fixture.activity_id.into_uuid(),
                "runtime_instance_id": fixture.runtime_instance_id.into_uuid(),
                "expected_lease_revision": lease_revision(renewed_fixture)?,
                "duration_ms": BATCH_DURATIONS_MS[0],
            },
            {
                "activity_id": second.id,
                "runtime_instance_id": second.runtime,
                "expected_lease_revision": lease_revision(&second.initial)?,
                "duration_ms": BATCH_DURATIONS_MS[1],
            },
            {
                "activity_id": third.id,
                "runtime_instance_id": third.runtime,
                "expected_lease_revision": lease_revision(&third.initial)?,
                "duration_ms": BATCH_DURATIONS_MS[2],
            },
        ]),
    )
    .await?;
    assert_eq!(status, 200, "renew batch response: {batch}");
    assert_eq!(batch["result"]["status"], "renewed");
    let rows = batch["result"]["activities"]
        .as_array()
        .ok_or("renew batch activity rows missing")?;
    assert_eq!(rows.len(), 3);
    let returned_ids = rows
        .iter()
        .map(activity_id)
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        returned_ids,
        vec![fixture.activity_id.into_uuid(), second.id, third.id]
    );
    for (row, expected_duration) in rows.iter().zip(BATCH_DURATIONS_MS) {
        let now = timestamp_now()?.get();
        assert!(lease_until(row)? > now);
        assert!(lease_until(row)? - now <= expected_duration + 1_000);
    }
    let second_after = get_activity(address, fixture, second.id).await?;
    let (status, one_batch) = renew_batch(
        address,
        fixture,
        json!([{
            "activity_id": second.id,
            "runtime_instance_id": second.runtime,
            "expected_lease_revision": lease_revision(&second_after)?,
            "duration_ms": SINGLE_DURATION_MS,
        }]),
    )
    .await?;
    assert_eq!(status, 200, "one-element renew batch response: {one_batch}");
    assert_eq!(one_batch["result"]["status"], "renewed");
    let one_batch_rows = one_batch["result"]["activities"]
        .as_array()
        .ok_or("one-element batch activity rows missing")?;
    assert_eq!(one_batch_rows.len(), 1);
    assert_eq!(activity_id(&one_batch_rows[0])?, second.id);
    let one_batch_now = timestamp_now()?.get();
    assert!(lease_until(&one_batch_rows[0])? > one_batch_now);
    assert!(lease_until(&one_batch_rows[0])? - one_batch_now <= SINGLE_DURATION_MS + 1_000);
    assert!(one_batch["result"]["activity"].is_null());
    Ok(rows[0].clone())
}

async fn assert_batch_rollbacks(
    address: SocketAddr,
    fixture: &Fixture,
    second: &OwnedActivity,
    third: &OwnedActivity,
) -> Result<(), Box<dyn std::error::Error>> {
    let before_duplicate = get_activity(address, fixture, second.id).await?;
    let duplicate_revision = lease_revision(&before_duplicate)?;
    let (status, duplicate) = renew_batch(
        address,
        fixture,
        json!([
            {
                "activity_id": second.id,
                "runtime_instance_id": second.runtime,
                "expected_lease_revision": duplicate_revision,
                "duration_ms": 2_000,
            },
            {
                "activity_id": second.id,
                "runtime_instance_id": second.runtime,
                "expected_lease_revision": duplicate_revision,
                "duration_ms": 3_000,
            },
        ]),
    )
    .await?;
    assert_failure(status, &duplicate, "LEASE_CONFLICT");
    assert_eq!(
        get_activity(address, fixture, second.id).await?,
        before_duplicate
    );

    let before_foreign = get_activity(address, fixture, third.id).await?;
    let before_valid = get_activity(address, fixture, second.id).await?;
    let (status, foreign) = renew_batch(
        address,
        fixture,
        json!([
            {
                "activity_id": second.id,
                "runtime_instance_id": second.runtime,
                "expected_lease_revision": lease_revision(&before_valid)?,
                "duration_ms": 2_000,
            },
            {
                "activity_id": third.id,
                "runtime_instance_id": Uuid::now_v7(),
                "expected_lease_revision": lease_revision(&before_foreign)?,
                "duration_ms": 2_000,
            },
        ]),
    )
    .await?;
    assert_failure(status, &foreign, "LEASE_CONFLICT");
    assert_eq!(
        get_activity(address, fixture, second.id).await?,
        before_valid
    );
    assert_eq!(
        get_activity(address, fixture, third.id).await?,
        before_foreign
    );

    let before_stale = get_activity(address, fixture, second.id).await?;
    let before_stale_valid = get_activity(address, fixture, third.id).await?;
    let (status, stale_batch) = renew_batch(
        address,
        fixture,
        json!([
            {
                "activity_id": second.id,
                "runtime_instance_id": second.runtime,
                "expected_lease_revision": lease_revision(&before_stale)? - 1,
                "duration_ms": 2_000,
            },
            {
                "activity_id": third.id,
                "runtime_instance_id": third.runtime,
                "expected_lease_revision": lease_revision(&before_stale_valid)?,
                "duration_ms": 2_000,
            },
        ]),
    )
    .await?;
    assert_failure(status, &stale_batch, "LEASE_CONFLICT");
    assert_eq!(
        get_activity(address, fixture, second.id).await?,
        before_stale
    );
    assert_eq!(
        get_activity(address, fixture, third.id).await?,
        before_stale_valid
    );
    Ok(())
}

async fn assert_expiry_and_release_batch(
    address: SocketAddr,
    fixture: &Fixture,
    current_fixture: &Value,
    fourth: &OwnedActivity,
) -> Result<(), Box<dyn std::error::Error>> {
    let (expired_id, expired_runtime, expired_initial) =
        bootstrap_activity(address, fixture, 25).await?;
    wait_until_expired(lease_until(&expired_initial)?).await?;
    let (status, expired) = renew(
        address,
        fixture,
        expired_id,
        expired_runtime,
        lease_revision(&expired_initial)?,
        2_000,
    )
    .await?;
    assert_failure(status, &expired, "LEASE_CONFLICT");

    let fixture_before = get_activity(address, fixture, fixture.activity_id.into_uuid()).await?;
    let fourth_before = get_activity(address, fixture, fourth.id).await?;
    let (status, released) = release_batch(
        address,
        fixture,
        json!([
            {
                "activity_id": fixture.activity_id.into_uuid(),
                "runtime_instance_id": fixture.runtime_instance_id.into_uuid(),
                "expected_lease_revision": lease_revision(current_fixture)?,
            },
            {
                "activity_id": fourth.id,
                "runtime_instance_id": fourth.runtime,
                "expected_lease_revision": lease_revision(&fourth_before)?,
            },
        ]),
    )
    .await?;
    assert_eq!(status, 200, "release batch response: {released}");
    assert_eq!(released["result"]["status"], "released");
    let rows = released["result"]["activities"]
        .as_array()
        .ok_or("release batch activity rows missing")?;
    assert_eq!(rows.len(), 2);
    assert_open_unleased(
        &rows[0],
        fixture.activity_id.into_uuid(),
        lease_revision(&fixture_before)? + 1,
    );
    assert_open_unleased(&rows[1], fourth.id, lease_revision(&fourth_before)? + 1);
    Ok(())
}

async fn assert_single_release_and_close(
    address: SocketAddr,
    fixture: &Fixture,
    second: &OwnedActivity,
    third: &OwnedActivity,
) -> Result<(), Box<dyn std::error::Error>> {
    let before_release = get_activity(address, fixture, second.id).await?;
    let release_revision = lease_revision(&before_release)?;
    let (status, released) = release(
        address,
        fixture,
        second.id,
        second.runtime,
        release_revision,
    )
    .await?;
    assert_eq!(status, 200, "release response: {released}");
    let released_activity = activity_value(&released)?;
    assert_open_unleased(&released_activity, second.id, release_revision + 1);
    let (status, close_released) = close(
        address,
        fixture,
        second.id,
        second.runtime,
        release_revision + 1,
    )
    .await?;
    assert_failure(status, &close_released, "LEASE_CONFLICT");

    let close_before = get_activity(address, fixture, third.id).await?;
    let close_revision = lease_revision(&close_before)?;
    let (status, closed) = close(address, fixture, third.id, third.runtime, close_revision).await?;
    assert_eq!(status, 200, "close response: {closed}");
    assert_eq!(closed["result"]["status"], "closed");
    assert_eq!(closed["result"]["activity"]["state"], "closed");
    Ok(())
}

async fn release_fifo_execution_and_assert_survival(
    address: SocketAddr,
    fixture: &Fixture,
    fifo_path: std::path::PathBuf,
    approved: ApprovedShell,
) -> Result<(), Box<dyn std::error::Error>> {
    let before_release = get_activity(address, fixture, fixture.activity_id.into_uuid()).await?;
    let lease_revision = lease_revision(&before_release)?;
    let (status, released) = release(
        address,
        fixture,
        fixture.activity_id.into_uuid(),
        fixture.runtime_instance_id.into_uuid(),
        lease_revision,
    )
    .await?;
    assert_eq!(status, 200, "release response: {released}");
    assert_eq!(released["result"]["status"], "released");
    assert_open_unleased(
        &activity_value(&released)?,
        fixture.activity_id.into_uuid(),
        lease_revision + 1,
    );
    let agent = fixture
        .client
        .agent_list(AgentListRequest {
            scope: fixture.scope.clone(),
            activity_id: Some(fixture.activity_id),
            now: timestamp_now()?,
            limit: AgentListLimit::DEFAULT,
        })?
        .into_iter()
        .find(|projection| projection.agent().id() == fixture.agent_id)
        .ok_or("source Agent disappeared after Activity lease release")?;
    assert_eq!(agent.agent().session_id(), Some(fixture.session_id));
    assert!(agent.agent().attachment_state().is_attached());

    let still_running = wait_for_execution_state(
        &fixture.client,
        &fixture.scope,
        approved.execution_id,
        forge_domain::ExecutionState::Running,
    )
    .await?;
    assert_eq!(still_running.state(), forge_domain::ExecutionState::Running);
    let writer = std::thread::spawn(move || -> Result<(), String> {
        let mut file = OpenOptions::new()
            .write(true)
            .open(fifo_path)
            .map_err(|error| format!("FIFO writer open failed: {error}"))?;
        file.write_all(b"backend-http-execution\n")
            .map_err(|error| format!("FIFO writer failed: {error}"))
    });
    writer.join().map_err(|_| "FIFO writer thread panicked")??;

    let completed = wait_for_execution_state(
        &fixture.client,
        &fixture.scope,
        approved.execution_id,
        forge_domain::ExecutionState::Completed,
    )
    .await?;
    assert_eq!(completed.state(), forge_domain::ExecutionState::Completed);
    assert_durable_output(fixture, approved)?;
    let after_release = get_activity(address, fixture, fixture.activity_id.into_uuid()).await?;
    assert_open_unleased(
        &after_release,
        fixture.activity_id.into_uuid(),
        lease_revision + 1,
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_http_activity_leases_prove_cas_server_time_batch_atomicity_and_release_open()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = prepare_fixture()?;
    let state = backend_state(&fixture)?;
    let address = serve(state.clone()).await?;
    let renewed_fixture = assert_single_renew_and_stale(address, &fixture).await?;
    let second = new_owned_activity(address, &fixture).await?;
    let third = new_owned_activity(address, &fixture).await?;
    let fourth = new_owned_activity(address, &fixture).await?;
    let current_fixture =
        assert_ordered_renew_batch(address, &fixture, &renewed_fixture, &second, &third).await?;
    assert_batch_rollbacks(address, &fixture, &second, &third).await?;
    assert_expiry_and_release_batch(address, &fixture, &current_fixture, &fourth).await?;
    assert_single_release_and_close(address, &fixture, &second, &third).await?;

    let shutdown = state.shutdown(Duration::from_secs(5)).await;
    assert!(
        shutdown.is_successful(),
        "backend shutdown did not complete"
    );
    fixture.shutdown()?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_http_activity_release_keeps_inflight_execution_alive()
-> Result<(), Box<dyn std::error::Error>> {
    let mkfifo = Path::new("/usr/bin/mkfifo");
    if !mkfifo.is_file() {
        return Err("/usr/bin/mkfifo is required for the Activity release fixture".into());
    }
    let fixture = prepare_fixture()?;
    let state = backend_state(&fixture)?;
    let address = serve(state.clone()).await?;
    let fifo_name = format!("activity-release-{}.fifo", Uuid::now_v7());
    let fifo_path = fixture.workspace_root.join(&fifo_name);
    let fifo_status = Command::new(mkfifo).arg(&fifo_path).status()?;
    if !fifo_status.success() {
        return Err(format!("mkfifo failed with status {fifo_status}").into());
    }
    let approved = prepare_approved_shell_for_script(&fixture, &format!("cat < {fifo_name}"))?;
    let (status, begin) = post_command(
        address,
        "execution.begin",
        execution_begin_payload(&approved),
    )
    .await?;
    assert_eq!(status, 200, "execution.begin response: {begin}");
    assert_eq!(begin["ok"], true);
    let _running = wait_for_execution_state(
        &fixture.client,
        &fixture.scope,
        approved.execution_id,
        forge_domain::ExecutionState::Running,
    )
    .await?;

    release_fifo_execution_and_assert_survival(address, &fixture, fifo_path, approved).await?;

    let shutdown = state.shutdown(Duration::from_secs(5)).await;
    assert!(
        shutdown.is_successful(),
        "backend shutdown did not complete"
    );
    fixture.shutdown()?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_http_activity_lease_disconnect_after_admission_reads_exact_batch_keys()
-> Result<(), Box<dyn std::error::Error>> {
    let (running, held, admitted) =
        super::binding_lifecycle::HttpBindingFixture::start_holding_first_reply(None).await?;
    let HeldBatch {
        second_id,
        second_runtime,
        first_revision,
        second_revision,
        payload,
    } = match prepare_held_batch(&running) {
        Ok(value) => value,
        Err(error) => {
            let release_result = held.release_and_wait().await;
            let finish = running.finish().await;
            release_result?;
            finish?;
            return Err(error);
        }
    };

    let result = async {
        let mut stream = super::binding_lifecycle::open_command_without_read(
            running.address,
            "activity.lease.renew_batch",
            payload,
        )
        .await?;
        timeout(Duration::from_secs(5), admitted).await??;
        stream.shutdown().await?;
        drop(stream);
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;
    let release_result = held.release_and_wait().await;
    let first_after = get_activity(
        running.address,
        &running.fixture,
        running.fixture.activity_id.into_uuid(),
    )
    .await;
    let second_after = get_activity(running.address, &running.fixture, second_id).await;
    let finish = running.finish().await;

    result?;
    release_result?;
    let first_after = first_after?;
    let second_after = second_after?;
    assert_eq!(lease_revision(&first_after)?, first_revision + 1);
    assert_eq!(lease_revision(&second_after)?, second_revision + 1);
    assert_eq!(second_after["lease_owner_id"], json!(second_runtime));
    finish
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_http_activity_lease_deadline_returns_exact_batch_readback_keys()
-> Result<(), Box<dyn std::error::Error>> {
    let (running, held, admitted) =
        super::binding_lifecycle::HttpBindingFixture::start_holding_first_reply(Some(
            Duration::from_secs(1),
        ))
        .await?;
    let HeldBatch {
        second_id,
        second_runtime,
        first_revision,
        second_revision,
        payload,
    } = match prepare_held_batch(&running) {
        Ok(value) => value,
        Err(error) => {
            let release_result = held.release_and_wait().await;
            let finish = running.finish().await;
            release_result?;
            finish?;
            return Err(error);
        }
    };

    let result = async {
        let mut stream = super::binding_lifecycle::open_command_without_read(
            running.address,
            "activity.lease.renew_batch",
            payload,
        )
        .await?;
        timeout(Duration::from_secs(5), admitted).await??;
        let (status, response) =
            timeout(Duration::from_secs(5), read_http_response(&mut stream)).await??;
        assert_eq!(status, 202, "deadline response: {response}");
        assert_batch_readback(
            &response,
            &running.fixture,
            second_id,
            second_runtime,
            first_revision,
            second_revision,
        )?;
        drop(stream);
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;
    let release_result = held.release_and_wait().await;
    let first_after = get_activity(
        running.address,
        &running.fixture,
        running.fixture.activity_id.into_uuid(),
    )
    .await;
    let second_after = get_activity(running.address, &running.fixture, second_id).await;
    let finish = running.finish().await;

    result?;
    release_result?;
    let first_after = first_after?;
    let second_after = second_after?;
    assert_eq!(lease_revision(&first_after)?, first_revision + 1);
    assert_eq!(lease_revision(&second_after)?, second_revision + 1);
    finish
}

struct WorkspaceBLock {
    scope: ResolvedWorkspaceScope,
    connection: rusqlite::Connection,
}

fn lock_workspace_b(fixture: &Fixture) -> Result<WorkspaceBLock, Box<dyn std::error::Error>> {
    let location_root = fixture
        .workspace_root
        .parent()
        .ok_or("fixture Location root missing")?;
    let workspace_root = location_root.join("workspace-b");
    fs::create_dir_all(&workspace_root)?;
    let layout = WorkspaceStateLayout::initialize(&workspace_root)?;
    let workspace = WorkspaceRoot::from_canonical(layout.workspace_root().to_path_buf())?;
    let establish = forge_domain::EstablishWorkspace::new(
        WorkspaceId::from_uuid(Uuid::now_v7()),
        fixture.scope.locator().location_id(),
        workspace,
        layout.root_fingerprint()?,
        timestamp_now()?,
    );
    drop(WorkspaceStore::open(&layout, &establish)?);

    let entries = fixture.client.workspace_discover(
        fixture.scope.locator().location_id(),
        fixture.scope.locator().expected_revision(),
    )?;
    let entry = entries
        .into_iter()
        .find(|entry| entry.display_name() == "workspace-b")
        .ok_or("Workspace B discovery entry missing")?;
    let scope = fixture.client.resolve_workspace(
        fixture.scope.locator().location_id(),
        fixture.scope.locator().expected_revision(),
        entry.locator().clone(),
    )?;
    let connection = rusqlite::Connection::open(layout.database_path())?;
    connection.execute_batch("BEGIN IMMEDIATE")?;
    Ok(WorkspaceBLock { scope, connection })
}

fn queue_replace_payload(scope: &ResolvedWorkspaceScope) -> Value {
    json!({
        "scope": scope_json_from_scope(scope),
        "capacity": 128,
        "expected_revision": Value::Null,
    })
}

fn single_renew_payload(
    fixture: &Fixture,
    activity_id: Uuid,
    runtime_instance_id: Uuid,
    expected_revision: i64,
) -> Value {
    json!({
        "scope": scope_json(fixture),
        "activity_id": activity_id,
        "runtime_instance_id": runtime_instance_id,
        "expected_lease_revision": expected_revision,
        "duration_ms": 4_000,
    })
}

#[derive(Debug)]
struct AdmissionSignalingExecutor {
    inner: std::sync::Arc<dyn forge_backend::CommandExecutor>,
    admitted: SyncSender<()>,
}

impl forge_backend::CommandExecutor for AdmissionSignalingExecutor {
    fn submit(
        &self,
        command: forge_backend::Command,
    ) -> Result<
        tokio::sync::oneshot::Receiver<forge_backend::BridgeOutcome>,
        forge_backend::ForgeError,
    > {
        let receiver = self.inner.submit(command)?;
        let _ = self.admitted.try_send(());
        Ok(receiver)
    }

    fn begin_wait(
        &self,
        request: forge_control::ExecutionWaitParameters,
    ) -> Result<forge_control::ExecutionWaitHandle, forge_backend::ForgeError> {
        self.inner.begin_wait(request)
    }

    fn stop_admission(&self) {
        self.inner.stop_admission();
    }

    fn inflight(&self) -> usize {
        self.inner.inflight()
    }

    fn drain_and_join(&self, drain_timeout: Duration) -> forge_backend::BridgeDrainReport {
        self.inner.drain_and_join(drain_timeout)
    }
}

async fn wait_for_lease_inflight(
    lease: &std::sync::Arc<forge_backend::lease_bridge::ActivityLeaseBridge>,
    expected: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if lease.inflight() == expected {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "Activity lease bridge did not reach inflight bound {expected}; observed {}",
                lease.inflight()
            )
            .into());
        }
        tokio::task::yield_now().await;
    }
}

async fn wait_for_admission(admissions: &Receiver<()>) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match admissions.try_recv() {
            Ok(()) => return Ok(()),
            Err(std::sync::mpsc::TryRecvError::Empty) => {}
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                return Err("lease admission observer disconnected".into());
            }
        }
        if Instant::now() >= deadline {
            return Err("lease admission was not observed within its bound".into());
        }
        tokio::task::yield_now().await;
    }
}

struct LeaseCapacityFixture {
    fixture: Fixture,
    state: forge_backend::AppState,
    address: SocketAddr,
    lease: std::sync::Arc<forge_backend::lease_bridge::ActivityLeaseBridge>,
    activities: Vec<(Uuid, Uuid)>,
    lock: Option<rusqlite::Connection>,
    admissions: Receiver<()>,
}

impl LeaseCapacityFixture {
    async fn start() -> Result<Self, Box<dyn std::error::Error>> {
        let fixture = prepare_fixture()?;
        let mut activities = vec![(
            fixture.activity_id.into_uuid(),
            fixture.runtime_instance_id.into_uuid(),
        )];
        for _ in 0..3 {
            let (activity_id, runtime_instance_id, _) = bootstrap_native_activity(&fixture)?;
            activities.push((activity_id, runtime_instance_id));
        }
        let product_cache_root = fixture.root.join("product-cache-activity-lease-capacity");
        fs::create_dir_all(&product_cache_root)?;
        let config = backend_config()?;
        let destination_id = delegated_destination_id(&fixture)?;
        let general = std::sync::Arc::new(forge_backend::ControlBridge::start(
            &fixture.client,
            &fixture.execution.client(),
            &fixture.approval.client(),
            RuntimeInstanceId::from_uuid(Uuid::now_v7()),
            &config,
            &product_cache_root,
            destination_id,
        )?);
        let lease = std::sync::Arc::new(forge_backend::lease_bridge::ActivityLeaseBridge::start(
            &fixture.activity_leases,
        )?);
        let executor = std::sync::Arc::new(forge_backend::lease_bridge::RoutingExecutor::new(
            general as std::sync::Arc<dyn forge_backend::CommandExecutor>,
            lease.clone() as std::sync::Arc<dyn forge_backend::CommandExecutor>,
        ));
        let (admitted, admissions) = sync_channel(8);
        let executor = std::sync::Arc::new(AdmissionSignalingExecutor {
            inner: executor as std::sync::Arc<dyn forge_backend::CommandExecutor>,
            admitted,
        });
        let state = forge_backend::AppState::new(
            config,
            executor,
            std::sync::Arc::new(forge_backend::events::ControlEventQuery::new(
                fixture.client.clone(),
            )),
        );
        state.set_probe(std::sync::Arc::new(fixture.client.clone()));
        state.set_execution_fast_lane(std::sync::Arc::new(fixture.execution.client()));
        let address = serve(state.clone()).await?;
        let layout = WorkspaceStateLayout::inspect_existing(&fixture.workspace_root)?
            .ok_or("Workspace A layout missing for lease capacity lock")?;
        let connection = rusqlite::Connection::open(layout.database_path())?;
        connection.execute_batch("BEGIN IMMEDIATE")?;
        Ok(Self {
            fixture,
            state,
            address,
            lease,
            activities,
            lock: Some(connection),
            admissions,
        })
    }

    async fn exercise_retained_join(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let (activity_id, runtime_id) = self.activities[0];
        let mut stream = super::binding_lifecycle::open_command_without_read(
            self.address,
            "activity.lease.renew",
            single_renew_payload(&self.fixture, activity_id, runtime_id, 1),
        )
        .await?;
        wait_for_admission(&self.admissions).await?;
        wait_for_lease_inflight(&self.lease, 1).await?;
        let pending = self.lease.drain_and_join(Duration::ZERO);
        assert_eq!(pending.pending_commands, 1);
        assert_eq!(pending.pending_workers, 1);
        assert!(!pending.is_complete());
        drop(self.lock.take());
        let (status, response) =
            timeout(Duration::from_secs(5), read_http_response(&mut stream)).await??;
        assert_eq!(
            status, 200,
            "admitted lease after bounded drain: {response}"
        );
        assert_eq!(response["result"]["activity"]["lease_revision"], 2);
        let observed = self.fixture.activity_leases.observe_activity_leases(
            self.fixture.scope.clone(),
            vec![ActivityId::from_uuid(activity_id)],
        )?;
        assert_eq!(observed.len(), 1);
        assert_eq!(observed[0].lease_revision().get(), 2);
        let lease = self.lease.clone();
        let joined =
            tokio::task::spawn_blocking(move || lease.drain_and_join(Duration::from_secs(5)))
                .await?;
        assert!(
            joined.is_successful(),
            "retained native lease owner did not join: {joined:?}"
        );
        Ok(())
    }

    async fn exercise(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let mut admitted = Vec::new();
        for (index, (activity_id, runtime_instance_id)) in self.activities.iter().enumerate() {
            let stream = super::binding_lifecycle::open_command_without_read(
                self.address,
                "activity.lease.renew",
                single_renew_payload(&self.fixture, *activity_id, *runtime_instance_id, 1),
            )
            .await?;
            admitted.push(stream);
            wait_for_admission(&self.admissions).await?;
            wait_for_lease_inflight(&self.lease, index + 1).await?;
        }
        let mut fifth = super::binding_lifecycle::open_command_without_read(
            self.address,
            "activity.lease.renew",
            single_renew_payload(&self.fixture, self.activities[0].0, self.activities[0].1, 1),
        )
        .await?;
        let (status, response) =
            timeout(Duration::from_secs(5), read_http_response(&mut fifth)).await??;
        assert_eq!(status, 503, "fifth lease admission response: {response}");
        assert_eq!(response["error"]["code"], "CAPACITY_EXCEEDED");
        assert_eq!(response["error"]["readback"], Value::Null);
        drop(fifth);

        drop(self.lock.take());
        for stream in &mut admitted {
            let (status, response) =
                timeout(Duration::from_secs(5), read_http_response(stream)).await??;
            assert_eq!(status, 200, "admitted lease response: {response}");
            assert_eq!(response["result"]["status"], "renewed");
            let activity = activity_value(&response)?;
            assert_eq!(lease_revision(&activity)?, 2);
        }
        assert_eq!(self.lease.inflight(), 0);
        for (activity_id, _) in &self.activities {
            let activity = get_activity(self.address, &self.fixture, *activity_id).await?;
            assert_eq!(lease_revision(&activity)?, 2);
        }
        Ok(())
    }

    async fn finish(self) -> Result<(), Box<dyn std::error::Error>> {
        drop(self.lock);
        let shutdown = self.state.shutdown(Duration::from_secs(5)).await;
        let fixture_result = self.fixture.shutdown();
        if !shutdown.is_successful() {
            return Err("Activity lease capacity backend shutdown was incomplete".into());
        }
        fixture_result
    }
}

async fn exercise_lease_lane_while_workspace_b_is_locked(
    address: SocketAddr,
    fixture: &Fixture,
) -> Result<(), Box<dyn std::error::Error>> {
    let (second_id, second_runtime, second_initial) =
        bootstrap_activity(address, fixture, 120_000).await?;
    let second_before = get_activity(address, fixture, second_id).await?;
    assert_eq!(
        lease_revision(&second_before)?,
        lease_revision(&second_initial)?
    );
    let (status, renewed) = renew(
        address,
        fixture,
        second_id,
        second_runtime,
        lease_revision(&second_before)?,
        4_000,
    )
    .await?;
    assert_eq!(status, 200, "dedicated renew response: {renewed}");
    assert_eq!(
        lease_revision(&activity_value(&renewed)?)?,
        lease_revision(&second_before)? + 1
    );

    let first_before = get_activity(address, fixture, fixture.activity_id.into_uuid()).await?;
    let (status, released) = release(
        address,
        fixture,
        fixture.activity_id.into_uuid(),
        fixture.runtime_instance_id.into_uuid(),
        lease_revision(&first_before)?,
    )
    .await?;
    assert_eq!(status, 200, "dedicated release response: {released}");
    assert_open_unleased(
        &activity_value(&released)?,
        fixture.activity_id.into_uuid(),
        lease_revision(&first_before)? + 1,
    );

    let (third_id, third_runtime, third_initial) =
        bootstrap_activity(address, fixture, 120_000).await?;
    let (status, third_renewed) = renew(
        address,
        fixture,
        third_id,
        third_runtime,
        lease_revision(&third_initial)?,
        SINGLE_DURATION_MS,
    )
    .await?;
    assert_eq!(
        status, 200,
        "dedicated third renew response: {third_renewed}"
    );
    let (status, closed) = close(
        address,
        fixture,
        third_id,
        third_runtime,
        lease_revision(&activity_value(&third_renewed)?)?,
    )
    .await?;
    assert_eq!(status, 200, "dedicated close response: {closed}");
    assert_eq!(closed["result"]["activity"]["state"], "closed");
    Ok(())
}

async fn open_general_queue_pair(
    address: SocketAddr,
    scope: &ResolvedWorkspaceScope,
) -> Result<(tokio::net::TcpStream, tokio::net::TcpStream), Box<dyn std::error::Error>> {
    let first = super::binding_lifecycle::open_command_without_read(
        address,
        "workspace.queue.settings.replace",
        queue_replace_payload(scope),
    )
    .await?;
    let second = match super::binding_lifecycle::open_command_without_read(
        address,
        "workspace.queue.settings.replace",
        queue_replace_payload(scope),
    )
    .await
    {
        Ok(stream) => stream,
        Err(error) => {
            drop(first);
            return Err(error);
        }
    };
    Ok((first, second))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_http_activity_lease_lane_progresses_while_general_workspace_b_is_locked()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = prepare_fixture()?;
    let state = backend_state(&fixture)?;
    let address = serve(state.clone()).await?;
    let workspace_b = lock_workspace_b(&fixture)?;
    let (mut general_one, mut general_two) =
        match open_general_queue_pair(address, &workspace_b.scope).await {
            Ok(streams) => streams,
            Err(error) => {
                drop(workspace_b.connection);
                let _ = state.shutdown(Duration::from_secs(5)).await;
                let _ = fixture.shutdown();
                return Err(error);
            }
        };

    let (started_sender, started_receiver) = std::sync::mpsc::channel();
    let (status_sender, status_receiver) = std::sync::mpsc::channel();
    let status_client = fixture.client.clone();
    let status_scope = workspace_b.scope.clone();
    let status_worker = std::thread::spawn(move || {
        let _ = started_sender.send(());
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let result = status_client.workspace_queue_status(status_scope.workspace_id());
            if result.as_ref().is_ok_and(|status| status.active_worker())
                || result.is_err()
                || Instant::now() >= deadline
            {
                let _ = status_sender.send(result);
                break;
            }
            std::thread::yield_now();
        }
    });
    let barrier_result: Result<(), Box<dyn std::error::Error>> =
        match started_receiver.recv_timeout(Duration::from_secs(1)) {
            Ok(()) => match status_receiver.recv_timeout(Duration::from_secs(5)) {
                Ok(Ok(status)) => {
                    assert!(status.active_worker());
                    Ok(())
                }
                Ok(Err(error)) => Err(format!("Workspace B queue status failed: {error:?}").into()),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(
                    "native general worker was not observed active before lease commands".into(),
                ),
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    Err("Workspace B queue status worker disconnected".into())
                }
            },
            Err(error) => Err(format!("Workspace B queue status did not start: {error:?}").into()),
        };

    let lease_result = exercise_lease_lane_while_workspace_b_is_locked(address, &fixture).await;

    drop(workspace_b.connection);
    let general_result = async {
        let _ = timeout(Duration::from_secs(5), read_http_response(&mut general_one)).await??;
        let _ = timeout(Duration::from_secs(5), read_http_response(&mut general_two)).await??;
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;
    let status_result = status_worker
        .join()
        .map_err(|_| "Workspace B queue status worker panicked");
    let shutdown = state.shutdown(Duration::from_secs(5)).await;
    let fixture_result = fixture.shutdown();
    barrier_result?;
    lease_result?;
    general_result?;
    status_result?;
    if !shutdown.is_successful() {
        return Err("backend shutdown did not complete".into());
    }
    fixture_result?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_http_activity_lease_bounded_drain_retains_then_joins_active_native_call()
-> Result<(), Box<dyn std::error::Error>> {
    let mut running = LeaseCapacityFixture::start().await?;
    let result = running.exercise_retained_join().await;
    let finish = running.finish().await;
    result?;
    finish
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_http_activity_lease_bridge_enforces_capacity_four_with_durable_rows()
-> Result<(), Box<dyn std::error::Error>> {
    let mut running = LeaseCapacityFixture::start().await?;
    let result = running.exercise().await;
    let finish = running.finish().await;
    result?;
    finish
}
