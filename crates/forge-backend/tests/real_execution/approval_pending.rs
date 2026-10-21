//! Real HTTP conversion of bounded pending approval observation and expiry.

use super::lease_readback::scope_json;
use super::*;
use forge_domain::{ApprovalRequestId, ApprovalRequestState, RegisteredApprovalRequest};
use forge_workspace::WorkspaceStateLayout;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_http_pending_approval_expires_elapsed_rows_without_acquiring_cleanup_authority()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = prepare_fixture()?;
    let cache = fixture.root.join("pending-approval-cache");
    fs::create_dir(&cache)?;
    let state = assemble_fixture(
        backend_config()?,
        &fixture,
        &cache,
        delegated_destination_id(&fixture)?,
    )?;
    let address = serve(state.clone()).await?;
    let result = run_pending_flow(&fixture, address).await;
    let http_shutdown = state.shutdown(Duration::from_secs(5)).await;
    let owner_shutdown = super::admitted_journal::shutdown_disabled_fixture(fixture);
    let failures: Vec<_> = [
        ("flow", result),
        ("owner shutdown", owner_shutdown),
        (
            "HTTP shutdown",
            if http_shutdown.is_successful() {
                Ok(())
            } else {
                Err("HTTP shutdown was incomplete".into())
            },
        ),
    ]
    .into_iter()
    .filter_map(|(phase, result)| result.err().map(|e| format!("{phase}: {e}")))
    .collect();
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; ").into())
    }
}

async fn run_pending_flow(
    fixture: &Fixture,
    address: SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    let (elapsed, active) = seed_pending_rows(fixture)?;
    seed_expiry_page(fixture, &elapsed)?;
    let payload = json!({ "scope": scope_json(fixture) });
    let mut forbidden_clock = payload.clone();
    forbidden_clock["observed_at_ms"] = json!(4_000_000_000_000_i64);
    let (status, response) = post_command(address, "approval.pending", forbidden_clock).await?;
    assert_eq!(status, 400);
    assert_eq!(response["ok"], false);
    assert_pending_rows(fixture, &elapsed, &active, false)?;

    let (status, response) = post_command(address, "approval.pending", payload.clone()).await?;
    assert_eq!(status, 200, "{response}");
    assert_eq!(response["ok"], true);
    assert_eq!(response["result"]["bounded"], true);
    assert_eq!(response["result"]["limit"], 256);
    let pending = response["result"]["pending"]
        .as_array()
        .ok_or("pending projection missing")?;
    assert_eq!(pending.len(), 2);
    assert!(pending.iter().any(
        |row| row["approval_id"] == active.id().into_uuid().to_string()
            && row["local_payload_available"] == false
    ));
    assert_pending_rows(fixture, &elapsed, &active, false)?;

    let mut stale = payload.clone();
    stale["scope"]["workspace_revision"] = json!(999);
    let (status, response) = post_command(address, "approval.pending", stale).await?;
    assert_ne!(status, 200);
    assert_eq!(response["ok"], false);
    assert_pending_rows(fixture, &elapsed, &active, false)?;
    let (status, response) = post_command(address, "approval.pending", payload.clone()).await?;
    assert_eq!(status, 200, "{response}");
    assert_eq!(
        response["result"]["pending"]
            .as_array()
            .ok_or("next page missing")?
            .len(),
        1
    );
    assert_pending_rows(fixture, &elapsed, &active, true)?;
    let stopped = fixture.approval.client().stop_owned()?;
    assert_eq!(stopped.pending_cancelled(), 0);
    assert_eq!(stopped.executions_cancelled(), 0);
    assert_pending_rows(fixture, &elapsed, &active, true)?;

    let location = fixture
        .client
        .location_list()?
        .into_iter()
        .find(|row| row.id() == fixture.scope.locator().location_id())
        .ok_or("pending fixture Location missing")?;
    let (status, response) = post_command(address, "location.state", json!({
        "location_id": location.id().into_uuid(), "expected_revision": location.revision().get(),
        "state": "disabled", "observed_at_ms": timestamp_now()?.get(),
    })).await?;
    assert_eq!(status, 200, "{response}");
    let (status, response) = post_command(address, "approval.pending", payload).await?;
    assert_ne!(status, 200);
    assert_eq!(response["ok"], false);
    assert_pending_rows(fixture, &elapsed, &active, true)?;
    Ok(())
}

fn seed_pending_rows(
    fixture: &Fixture,
) -> Result<(RegisteredApprovalRequest, RegisteredApprovalRequest), Box<dyn std::error::Error>> {
    let layout = WorkspaceStateLayout::inspect_existing(&fixture.workspace_root)?
        .ok_or("pending fixture Workspace layout missing")?;
    let mut store = WorkspaceStore::open_existing(&layout)?;
    let now = timestamp_now()?;
    let policy = store.ensure_workspace_policy(now)?;
    let make = |expires_at: TimestampMillis|
     -> Result<RegisteredApprovalRequest, Box<dyn std::error::Error>> {
        Ok(RegisteredApprovalRequest::pending(
            ApprovalRequestId::from_uuid(Uuid::now_v7()),
            forge_domain::ExecutionAuthorizationRequest::new(
                ExecutionId::from_uuid(Uuid::now_v7()),
                fixture.scope.workspace_id(),
                fixture.activity_id,
                forge_domain::ExecutionRequestDigest::from_bytes([0xD1; 32]),
                forge_domain::ExecutionActionClass::DirectStructured,
                forge_domain::RequestedExecutionPermissions::new(
                    forge_domain::ExecutionPermissions::new(false, false, false),
                ),
            ),
            policy.revision(),
            TimestampMillis::new(now.get() - 3_000)?,
            expires_at,
        )?)
    };
    let elapsed = make(TimestampMillis::new(now.get() - 1_000)?)?;
    let active = make(add_millis(now, 60_000)?)?;
    let elapsed = store.insert_pending_approval(&elapsed)?;
    let active = store.insert_pending_approval(&active)?;
    Ok((elapsed, active))
}

fn seed_expiry_page(
    fixture: &Fixture,
    elapsed: &RegisteredApprovalRequest,
) -> Result<(), Box<dyn std::error::Error>> {
    let layout = WorkspaceStateLayout::inspect_existing(&fixture.workspace_root)?
        .ok_or("expiry page Workspace missing")?;
    let mut store = WorkspaceStore::open_existing(&layout)?;
    // Exact lower UUIDs sort ahead of the original v7 tail row.
    for id in 1..=256_u128 {
        let request = RegisteredApprovalRequest::pending(
            ApprovalRequestId::from_uuid(Uuid::from_u128(0xD000 + id)),
            forge_domain::ExecutionAuthorizationRequest::new(
                ExecutionId::from_uuid(Uuid::from_u128(0xE000 + id)),
                fixture.scope.workspace_id(),
                fixture.activity_id,
                elapsed.request().request_digest(),
                elapsed.request().action(),
                elapsed.request().requested(),
            ),
            elapsed.policy_revision(),
            elapsed.created_at(),
            elapsed.expires_at(),
        )?;
        let _inserted = store.insert_pending_approval(&request)?;
    }
    Ok(())
}

fn assert_pending_rows(
    fixture: &Fixture,
    elapsed: &RegisteredApprovalRequest,
    active: &RegisteredApprovalRequest,
    expired: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let layout = WorkspaceStateLayout::inspect_existing(&fixture.workspace_root)?
        .ok_or("pending fixture Workspace layout missing")?;
    let store = WorkspaceStore::open_existing(&layout)?;
    let after_active = store
        .get_approval_request(active.id())?
        .ok_or("active row missing")?;
    assert_eq!(&after_active, active);
    let after_elapsed = store
        .get_approval_request(elapsed.id())?
        .ok_or("elapsed row missing")?;
    if expired {
        assert_eq!(after_elapsed.state(), ApprovalRequestState::Expired);
        assert_eq!(after_elapsed.revision(), elapsed.revision().checked_next()?);
        assert_eq!(after_elapsed.request(), elapsed.request());
        assert!(
            after_elapsed
                .decided_at()
                .is_some_and(|at| at.get() >= elapsed.expires_at().get())
        );
    } else {
        assert_eq!(&after_elapsed, elapsed);
    }
    Ok(())
}
