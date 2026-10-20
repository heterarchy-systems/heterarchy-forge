//! Real HTTP proofs for the Workspace recovery-maintenance lease fence.

use super::binding_lifecycle::{HttpBindingFixture, open_command_without_read};
use super::lease_readback::scope_json;
use super::*;

use forge_domain::{ClaimRecoveryLease, ExecutionListLimit, RecoveryLeaseDurationMillis};
use forge_persistence::WorkspaceStore;
use forge_workspace::WorkspaceStateLayout;
use serde_json::{Value, json};
use tokio::time::timeout;

const CLAIM_DURATION_MS: i64 = 60_000;
const RENEW_DURATION_MS: i64 = 120_000;
const EXPIRY_DURATION_MS: i64 = 1_000;

fn backend_state(fixture: &Fixture) -> Result<forge_backend::AppState, Box<dyn std::error::Error>> {
    let product_cache_root = fixture.root.join("product-cache-recovery-leases");
    fs::create_dir_all(&product_cache_root)?;
    let destination_id = delegated_destination_id(fixture)?;
    super::assemble_fixture(
        backend_config()?,
        fixture,
        &product_cache_root,
        destination_id,
    )
}

fn lease_json(result: &Value) -> Result<Value, Box<dyn std::error::Error>> {
    let Some(lease) = result.get("lease") else {
        return Err("recovery lease snapshot missing".into());
    };
    if !lease.is_object() {
        return Err("recovery lease snapshot is not an object".into());
    }
    Ok(lease.clone())
}

fn owner_id(lease: &Value) -> Result<Uuid, Box<dyn std::error::Error>> {
    lease["owner_id"]
        .as_str()
        .ok_or("recovery lease owner_id missing")?
        .parse()
        .map_err(Into::into)
}

fn epoch(lease: &Value) -> Result<i64, Box<dyn std::error::Error>> {
    lease["epoch"]
        .as_i64()
        .ok_or_else(|| "recovery lease epoch missing".into())
}

fn revision(lease: &Value) -> Result<i64, Box<dyn std::error::Error>> {
    lease["revision"]
        .as_i64()
        .ok_or_else(|| "recovery lease revision missing".into())
}

fn lease_until(lease: &Value) -> Result<i64, Box<dyn std::error::Error>> {
    lease["lease_until_ms"]
        .as_i64()
        .ok_or_else(|| "recovery lease expiry missing".into())
}

fn assert_window(lease: &Value, duration_ms: i64) -> Result<(), Box<dyn std::error::Error>> {
    let now = timestamp_now()?.get();
    let until = lease_until(lease)?;
    let updated_at = lease["updated_at_ms"]
        .as_i64()
        .ok_or("recovery lease updated_at_ms missing")?;
    assert!(until > now);
    assert!(until - now <= duration_ms + 1_000);
    assert_eq!(until - updated_at, duration_ms);
    Ok(())
}

fn assert_failure(status: u16, response: &Value, code: &str) {
    assert_ne!(status, 200, "unexpected recovery lease success: {response}");
    assert_eq!(response["ok"], false);
    assert_eq!(response["error"]["code"], code);
}

async fn get_activity(
    address: SocketAddr,
    fixture: &Fixture,
    activity_id: Uuid,
) -> Result<Value, Box<dyn std::error::Error>> {
    let (status, response) = post_command(
        address,
        "activity.get",
        json!({"scope": scope_json(fixture), "activity_id": activity_id}),
    )
    .await?;
    assert_eq!(status, 200, "activity.get response: {response}");
    Ok(response["result"]["activity"].clone())
}

async fn get_recovery_lease(
    address: SocketAddr,
    fixture: &Fixture,
) -> Result<Value, Box<dyn std::error::Error>> {
    let (status, response) = post_command(
        address,
        "recovery.lease.get",
        json!({"scope": scope_json(fixture)}),
    )
    .await?;
    assert_eq!(status, 200, "recovery.lease.get response: {response}");
    assert_eq!(response["result"]["scope"], scope_json(fixture));
    lease_json(&response["result"])
}

async fn claim(
    address: SocketAddr,
    fixture: &Fixture,
    owner: Uuid,
    duration_ms: i64,
) -> Result<(u16, Value), Box<dyn std::error::Error>> {
    post_command(
        address,
        "recovery.lease.claim",
        json!({
            "scope": scope_json(fixture),
            "owner_id": owner,
            "duration_ms": duration_ms,
        }),
    )
    .await
}

async fn renew(
    address: SocketAddr,
    fixture: &Fixture,
    owner: Uuid,
    expected_epoch: i64,
    expected_revision: i64,
    duration_ms: i64,
) -> Result<(u16, Value), Box<dyn std::error::Error>> {
    post_command(
        address,
        "recovery.lease.renew",
        json!({
            "scope": scope_json(fixture),
            "owner_id": owner,
            "expected_epoch": expected_epoch,
            "expected_revision": expected_revision,
            "duration_ms": duration_ms,
        }),
    )
    .await
}

async fn release(
    address: SocketAddr,
    fixture: &Fixture,
    owner: Uuid,
    expected_epoch: i64,
    expected_revision: i64,
) -> Result<(u16, Value), Box<dyn std::error::Error>> {
    post_command(
        address,
        "recovery.lease.release",
        json!({
            "scope": scope_json(fixture),
            "owner_id": owner,
            "expected_epoch": expected_epoch,
            "expected_revision": expected_revision,
        }),
    )
    .await
}

async fn wait_until_expired(until_ms: i64) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if timestamp_now()?.get() >= until_ms {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("recovery lease did not expire within its bound".into());
        }
        tokio::task::yield_now().await;
    }
}

fn reopened_lease(
    fixture: &Fixture,
) -> Result<forge_domain::RecoveryMaintenanceLease, Box<dyn std::error::Error>> {
    let layout = WorkspaceStateLayout::inspect_existing(&fixture.workspace_root)?
        .ok_or("Workspace layout missing during recovery lease reopen")?;
    let store = WorkspaceStore::open_existing(&layout)?;
    Ok(store.get_recovery_maintenance_lease()?)
}

fn baseline_execution_rows(
    fixture: &Fixture,
) -> Result<Vec<forge_domain::RegisteredExecution>, Box<dyn std::error::Error>> {
    Ok(fixture
        .client
        .execution_list(
            fixture.scope.clone(),
            fixture.activity_id,
            ExecutionListLimit::DEFAULT,
        )
        .map_err(|error| format!("execution baseline failed: {error:?}"))?)
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

fn assert_recovery_readback(
    response: &Value,
    fixture: &Fixture,
    owner: Uuid,
    operation: &str,
    duration_ms: i64,
) {
    assert_eq!(response["error"]["code"], "UNKNOWN_OUTCOME");
    assert_eq!(response["error"]["recovery_action"], "read_back");
    let readback = &response["error"]["readback"];
    assert_eq!(readback["kind"], "recovery_lease");
    assert_eq!(
        readback["workspace_id"],
        json!(fixture.scope.workspace_id().into_uuid())
    );
    assert_eq!(readback["owner_id"], json!(owner));
    assert_eq!(readback["operation"], operation);
    assert_eq!(readback["expected_epoch"], Value::Null);
    assert_eq!(readback["expected_revision"], Value::Null);
    assert_eq!(readback["duration_ms"], json!(duration_ms));
}

fn assert_recovery_renew_readback(
    response: &Value,
    fixture: &Fixture,
    owner: Uuid,
    expected_epoch: i64,
    expected_revision: i64,
    duration_ms: i64,
) {
    assert_eq!(response["error"]["code"], "UNKNOWN_OUTCOME");
    let readback = &response["error"]["readback"];
    assert_eq!(readback["kind"], "recovery_lease");
    assert_eq!(
        readback["workspace_id"],
        json!(fixture.scope.workspace_id().into_uuid())
    );
    assert_eq!(readback["owner_id"], json!(owner));
    assert_eq!(readback["operation"], "renew");
    assert_eq!(readback["expected_epoch"], json!(expected_epoch));
    assert_eq!(readback["expected_revision"], json!(expected_revision));
    assert_eq!(readback["duration_ms"], json!(duration_ms));
}

fn assert_recovery_release_readback(
    response: &Value,
    fixture: &Fixture,
    owner: Uuid,
    expected_epoch: i64,
    expected_revision: i64,
) {
    assert_eq!(response["error"]["code"], "UNKNOWN_OUTCOME");
    let readback = &response["error"]["readback"];
    assert_eq!(readback["kind"], "recovery_lease");
    assert_eq!(
        readback["workspace_id"],
        json!(fixture.scope.workspace_id().into_uuid())
    );
    assert_eq!(readback["owner_id"], json!(owner));
    assert_eq!(readback["operation"], "release");
    assert_eq!(readback["expected_epoch"], json!(expected_epoch));
    assert_eq!(readback["expected_revision"], json!(expected_revision));
    assert_eq!(readback["duration_ms"], Value::Null);
}

fn native_claimed_recovery_lease(
    fixture: &Fixture,
    owner: Uuid,
) -> Result<forge_domain::RecoveryMaintenanceLease, Box<dyn std::error::Error>> {
    let command = ClaimRecoveryLease::new(
        fixture.scope.workspace_id(),
        forge_domain::RuntimeInstanceId::from_uuid(owner),
        RecoveryLeaseDurationMillis::new(CLAIM_DURATION_MS)?,
        timestamp_now()?,
    )?;
    Ok(fixture
        .client
        .claim_recovery_maintenance_lease(fixture.scope.clone(), command)?
        .lease()
        .clone())
}

fn recovery_renew_payload(
    fixture: &Fixture,
    owner: Uuid,
    expected_epoch: i64,
    expected_revision: i64,
) -> Value {
    json!({
        "scope": scope_json(fixture),
        "owner_id": owner,
        "expected_epoch": expected_epoch,
        "expected_revision": expected_revision,
        "duration_ms": RENEW_DURATION_MS,
    })
}

async fn assert_claim_classifications(
    address: SocketAddr,
    fixture: &Fixture,
    owner_a: Uuid,
    owner_b: Uuid,
) -> Result<Value, Box<dyn std::error::Error>> {
    let (status, claimed) = claim(address, fixture, owner_a, CLAIM_DURATION_MS).await?;
    assert_eq!(status, 200, "claim response: {claimed}");
    assert_eq!(claimed["result"]["status"], "acquired");
    let first = lease_json(&claimed["result"])?;
    assert_eq!(owner_id(&first)?, owner_a);
    assert_eq!(epoch(&first)?, 1);
    assert_eq!(revision(&first)?, 2);
    assert_window(&first, CLAIM_DURATION_MS)?;

    let (status, replay) = claim(address, fixture, owner_a, CLAIM_DURATION_MS).await?;
    assert_eq!(status, 200, "claim replay response: {replay}");
    assert!(matches!(
        replay["result"]["status"].as_str(),
        Some("already_owned" | "claim_conflict")
    ));
    assert_eq!(lease_json(&replay["result"])?, first);

    let (status, conflict) = claim(address, fixture, owner_a, RENEW_DURATION_MS).await?;
    assert_eq!(status, 200, "claim conflict response: {conflict}");
    assert_eq!(conflict["result"]["status"], "claim_conflict");
    assert_eq!(lease_json(&conflict["result"])?, first);

    let (status, busy) = claim(address, fixture, owner_b, CLAIM_DURATION_MS).await?;
    assert_eq!(status, 200, "busy claim response: {busy}");
    assert_eq!(busy["result"]["status"], "busy");
    assert_eq!(lease_json(&busy["result"])?, first);
    Ok(first)
}

async fn assert_renew_and_release(
    address: SocketAddr,
    fixture: &Fixture,
    owner_a: Uuid,
    first: &Value,
) -> Result<Value, Box<dyn std::error::Error>> {
    let (status, renewed) = renew(
        address,
        fixture,
        owner_a,
        epoch(first)?,
        revision(first)?,
        RENEW_DURATION_MS,
    )
    .await?;
    assert_eq!(status, 200, "renew response: {renewed}");
    assert_eq!(renewed["result"]["status"], "renewed");
    let renewed_lease = lease_json(&renewed["result"])?;
    assert_eq!(owner_id(&renewed_lease)?, owner_a);
    assert_eq!(epoch(&renewed_lease)?, epoch(first)?);
    assert_eq!(revision(&renewed_lease)?, revision(first)? + 1);
    assert_window(&renewed_lease, RENEW_DURATION_MS)?;

    let (status, nonforward) = renew(
        address,
        fixture,
        owner_a,
        epoch(&renewed_lease)?,
        revision(&renewed_lease)?,
        EXPIRY_DURATION_MS,
    )
    .await?;
    assert_failure(status, &nonforward, "LEASE_CONFLICT");
    assert_eq!(get_recovery_lease(address, fixture).await?, renewed_lease);

    let (status, stale_renew) = renew(
        address,
        fixture,
        owner_a,
        epoch(first)?,
        revision(first)?,
        RENEW_DURATION_MS,
    )
    .await?;
    assert_failure(status, &stale_renew, "LEASE_CONFLICT");
    assert_eq!(get_recovery_lease(address, fixture).await?, renewed_lease);

    let (status, released) = release(
        address,
        fixture,
        owner_a,
        epoch(&renewed_lease)?,
        revision(&renewed_lease)?,
    )
    .await?;
    assert_eq!(status, 200, "release response: {released}");
    assert_eq!(released["result"]["status"], "released");
    let released_lease = lease_json(&released["result"])?;
    assert_eq!(released_lease["owner_id"], Value::Null);
    assert_eq!(epoch(&released_lease)?, epoch(&renewed_lease)?);
    assert_eq!(revision(&released_lease)?, revision(&renewed_lease)? + 1);
    Ok(released_lease)
}

async fn assert_expiry_takeover_and_release(
    address: SocketAddr,
    fixture: &Fixture,
    owner_a: Uuid,
    owner_b: Uuid,
    released_lease: &Value,
) -> Result<Value, Box<dyn std::error::Error>> {
    let (status, short_claim) = claim(address, fixture, owner_a, EXPIRY_DURATION_MS).await?;
    assert_eq!(status, 200, "short claim response: {short_claim}");
    let short_lease = lease_json(&short_claim["result"])?;
    assert_eq!(short_claim["result"]["status"], "acquired");
    assert_eq!(epoch(&short_lease)?, epoch(released_lease)? + 1);
    wait_until_expired(lease_until(&short_lease)?).await?;

    let (status, takeover) = claim(address, fixture, owner_b, CLAIM_DURATION_MS).await?;
    assert_eq!(status, 200, "takeover response: {takeover}");
    let taken = lease_json(&takeover["result"])?;
    assert_eq!(takeover["result"]["status"], "acquired");
    assert_eq!(owner_id(&taken)?, owner_b);
    assert_eq!(epoch(&taken)?, epoch(&short_lease)? + 1);

    let (status, stale_release) = release(
        address,
        fixture,
        owner_a,
        epoch(&short_lease)?,
        revision(&short_lease)?,
    )
    .await?;
    assert_failure(status, &stale_release, "LEASE_CONFLICT");

    let (status, final_release) =
        release(address, fixture, owner_b, epoch(&taken)?, revision(&taken)?).await?;
    assert_eq!(status, 200, "final release response: {final_release}");
    let final_lease = lease_json(&final_release["result"])?;
    assert_eq!(final_lease["owner_id"], Value::Null);
    assert_eq!(revision(&final_lease)?, revision(&taken)? + 1);
    Ok(final_lease)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_http_recovery_lease_claim_cas_expiry_release_and_reopen()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = prepare_fixture()?;
    let state = backend_state(&fixture)?;
    let address = serve(state.clone()).await?;
    let owner_a = fixture.runtime_instance_id.into_uuid();
    let owner_b = Uuid::now_v7();
    let baseline_activity =
        get_activity(address, &fixture, fixture.activity_id.into_uuid()).await?;
    let baseline_agents = fixture
        .client
        .agent_list(AgentListRequest {
            scope: fixture.scope.clone(),
            activity_id: Some(fixture.activity_id),
            now: timestamp_now()?,
            limit: AgentListLimit::DEFAULT,
        })
        .map_err(|error| format!("baseline Agent projection failed: {error:?}"))?;
    let baseline_executions = baseline_execution_rows(&fixture)?;
    let initial = get_recovery_lease(address, &fixture).await?;
    assert_eq!(initial["owner_id"], Value::Null);
    assert_eq!(initial["epoch"], 0);
    assert_eq!(initial["revision"], 1);
    let first = assert_claim_classifications(address, &fixture, owner_a, owner_b).await?;
    let released = assert_renew_and_release(address, &fixture, owner_a, &first).await?;
    let final_lease =
        assert_expiry_takeover_and_release(address, &fixture, owner_a, owner_b, &released).await?;
    let reopened = reopened_lease(&fixture)?;
    assert_eq!(reopened.workspace_id(), fixture.scope.workspace_id());
    assert!(reopened.is_released());
    assert_eq!(reopened.epoch().get(), epoch(&final_lease)?);
    assert_eq!(reopened.revision().get(), revision(&final_lease)?);

    assert_eq!(
        get_activity(address, &fixture, fixture.activity_id.into_uuid()).await?,
        baseline_activity
    );
    assert_eq!(
        fixture.client.agent_list(AgentListRequest {
            scope: fixture.scope.clone(),
            activity_id: Some(fixture.activity_id),
            now: timestamp_now()?,
            limit: AgentListLimit::DEFAULT,
        })?,
        baseline_agents
    );
    assert_eq!(baseline_execution_rows(&fixture)?, baseline_executions);
    let shutdown = state.shutdown(Duration::from_secs(5)).await;
    assert!(
        shutdown.is_successful(),
        "backend shutdown did not complete"
    );
    fixture.shutdown()?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_http_recovery_lease_auth_scope_and_bounds_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = prepare_fixture()?;
    let state = backend_state(&fixture)?;
    let address = serve(state.clone()).await?;
    let (status, missing_auth) = post_without_auth(
        address,
        "recovery.lease.get",
        json!({"scope": scope_json(&fixture)}),
    )
    .await?;
    assert_ne!(status, 200);
    assert_eq!(missing_auth["error"]["code"], "AUTH_FAILED");

    let (status, invalid_duration) = claim(address, &fixture, Uuid::now_v7(), 999).await?;
    assert_failure(status, &invalid_duration, "INVALID_INPUT");
    let (status, nil_owner) = claim(address, &fixture, Uuid::nil(), CLAIM_DURATION_MS).await?;
    assert_failure(status, &nil_owner, "INVALID_INPUT");

    let mut wrong_scope = scope_json(&fixture);
    wrong_scope["workspace_id"] = json!(Uuid::now_v7());
    let (status, stale_scope) =
        post_command(address, "recovery.lease.get", json!({"scope": wrong_scope})).await?;
    assert_failure(status, &stale_scope, "STALE_REVISION");

    let shutdown = state.shutdown(Duration::from_secs(5)).await;
    assert!(
        shutdown.is_successful(),
        "backend shutdown did not complete"
    );
    fixture.shutdown()?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_http_recovery_lease_deadline_returns_exact_readback()
-> Result<(), Box<dyn std::error::Error>> {
    let (running, held, admitted) =
        HttpBindingFixture::start_holding_first_reply(Some(Duration::from_secs(1))).await?;
    let owner = running.fixture.runtime_instance_id.into_uuid();
    let payload = json!({
        "scope": scope_json(&running.fixture),
        "owner_id": owner,
        "duration_ms": CLAIM_DURATION_MS,
    });
    let result = async {
        let mut stream =
            open_command_without_read(running.address, "recovery.lease.claim", payload).await?;
        timeout(Duration::from_secs(5), admitted).await??;
        let response = timeout(
            Duration::from_secs(5),
            super::read_response_bounded(&mut stream),
        )
        .await??;
        let text = String::from_utf8(response)?;
        let status = text
            .split_whitespace()
            .nth(1)
            .ok_or("HTTP status missing")?
            .parse::<u16>()?;
        let body = text.split_once("\r\n\r\n").ok_or("HTTP body missing")?.1;
        let body: Value = serde_json::from_str(body)?;
        assert_eq!(status, 202, "deadline response: {body}");
        assert_recovery_readback(&body, &running.fixture, owner, "claim", CLAIM_DURATION_MS);
        drop(stream);
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;
    let release_result = held.release_and_wait().await;
    let observed = running
        .fixture
        .client
        .recovery_maintenance_lease(running.fixture.scope.clone());
    let finish = running.finish().await;
    result?;
    release_result?;
    let observed = observed?;
    assert_eq!(
        observed.owner_id().map(RuntimeInstanceId::into_uuid),
        Some(owner)
    );
    finish
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_http_recovery_lease_renew_deadline_returns_fenced_readback()
-> Result<(), Box<dyn std::error::Error>> {
    let (running, held, admitted) =
        HttpBindingFixture::start_holding_first_reply(Some(Duration::from_secs(1))).await?;
    let owner = running.fixture.runtime_instance_id.into_uuid();
    let claimed = native_claimed_recovery_lease(&running.fixture, owner)?;
    let expected_epoch = claimed.epoch().get();
    let expected_revision = claimed.revision().get();
    let payload =
        recovery_renew_payload(&running.fixture, owner, expected_epoch, expected_revision);
    let result = async {
        let mut stream =
            open_command_without_read(running.address, "recovery.lease.renew", payload).await?;
        timeout(Duration::from_secs(5), admitted).await??;
        let response = timeout(
            Duration::from_secs(5),
            super::read_response_bounded(&mut stream),
        )
        .await??;
        let text = String::from_utf8(response)?;
        let status = text
            .split_whitespace()
            .nth(1)
            .ok_or("HTTP status missing")?
            .parse::<u16>()?;
        let body = text.split_once("\r\n\r\n").ok_or("HTTP body missing")?.1;
        let body: Value = serde_json::from_str(body)?;
        assert_eq!(status, 202, "renew deadline response: {body}");
        assert_recovery_renew_readback(
            &body,
            &running.fixture,
            owner,
            expected_epoch,
            expected_revision,
            RENEW_DURATION_MS,
        );
        drop(stream);
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;
    let release_result = held.release_and_wait().await;
    let observed = running
        .fixture
        .client
        .recovery_maintenance_lease(running.fixture.scope.clone());
    let finish = running.finish().await;
    result?;
    release_result?;
    let observed = observed?;
    assert_eq!(
        observed.owner_id().map(RuntimeInstanceId::into_uuid),
        Some(owner)
    );
    assert_eq!(observed.epoch().get(), expected_epoch);
    assert_eq!(observed.revision().get(), expected_revision + 1);
    finish
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_http_recovery_lease_renew_disconnect_reads_same_fence()
-> Result<(), Box<dyn std::error::Error>> {
    let (running, held, admitted) = HttpBindingFixture::start_holding_first_reply(None).await?;
    let owner = running.fixture.runtime_instance_id.into_uuid();
    let claimed = native_claimed_recovery_lease(&running.fixture, owner)?;
    let expected_epoch = claimed.epoch().get();
    let expected_revision = claimed.revision().get();
    let payload =
        recovery_renew_payload(&running.fixture, owner, expected_epoch, expected_revision);
    let result = async {
        let mut stream =
            open_command_without_read(running.address, "recovery.lease.renew", payload).await?;
        timeout(Duration::from_secs(5), admitted).await??;
        stream.shutdown().await?;
        drop(stream);
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;
    let release_result = held.release_and_wait().await;
    let observed = running
        .fixture
        .client
        .recovery_maintenance_lease(running.fixture.scope.clone());
    let finish = running.finish().await;
    result?;
    release_result?;
    let observed = observed?;
    assert_eq!(
        observed.owner_id().map(RuntimeInstanceId::into_uuid),
        Some(owner)
    );
    assert_eq!(observed.epoch().get(), expected_epoch);
    assert_eq!(observed.revision().get(), expected_revision + 1);
    finish
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_http_recovery_lease_release_deadline_returns_exact_readback()
-> Result<(), Box<dyn std::error::Error>> {
    let (running, held, admitted) =
        HttpBindingFixture::start_holding_first_reply(Some(Duration::from_secs(1))).await?;
    let owner = running.fixture.runtime_instance_id.into_uuid();
    let claimed = native_claimed_recovery_lease(&running.fixture, owner)?;
    let expected_epoch = claimed.epoch().get();
    let expected_revision = claimed.revision().get();
    let payload = json!({
        "scope": scope_json(&running.fixture),
        "owner_id": owner,
        "expected_epoch": expected_epoch,
        "expected_revision": expected_revision,
    });
    let result = async {
        let mut stream =
            open_command_without_read(running.address, "recovery.lease.release", payload).await?;
        timeout(Duration::from_secs(5), admitted).await??;
        let response = timeout(
            Duration::from_secs(5),
            super::read_response_bounded(&mut stream),
        )
        .await??;
        let text = String::from_utf8(response)?;
        let status = text
            .split_whitespace()
            .nth(1)
            .ok_or("HTTP status missing")?
            .parse::<u16>()?;
        let body = text.split_once("\r\n\r\n").ok_or("HTTP body missing")?.1;
        let body: Value = serde_json::from_str(body)?;
        assert_eq!(status, 202, "release deadline response: {body}");
        assert_recovery_release_readback(
            &body,
            &running.fixture,
            owner,
            expected_epoch,
            expected_revision,
        );
        drop(stream);
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;
    let release_result = held.release_and_wait().await;
    let observed = running
        .fixture
        .client
        .recovery_maintenance_lease(running.fixture.scope.clone());
    let finish = running.finish().await;
    result?;
    release_result?;
    let observed = observed?;
    assert!(observed.is_released());
    assert_eq!(observed.epoch().get(), expected_epoch);
    assert_eq!(observed.revision().get(), expected_revision + 1);
    finish
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_http_recovery_lease_disconnect_after_admission_reads_same_owner()
-> Result<(), Box<dyn std::error::Error>> {
    let (running, held, admitted) = HttpBindingFixture::start_holding_first_reply(None).await?;
    let owner = running.fixture.runtime_instance_id.into_uuid();
    let payload = json!({
        "scope": scope_json(&running.fixture),
        "owner_id": owner,
        "duration_ms": CLAIM_DURATION_MS,
    });
    let result = async {
        let mut stream =
            open_command_without_read(running.address, "recovery.lease.claim", payload).await?;
        timeout(Duration::from_secs(5), admitted).await??;
        stream.shutdown().await?;
        drop(stream);
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;
    let release_result = held.release_and_wait().await;
    let observed = running
        .fixture
        .client
        .recovery_maintenance_lease(running.fixture.scope.clone());
    let finish = running.finish().await;
    result?;
    release_result?;
    let observed = observed?;
    assert_eq!(
        observed.owner_id().map(RuntimeInstanceId::into_uuid),
        Some(owner)
    );
    finish
}
