//! Real loopback HTTP proof for the authenticated Workspace-stop intent.
//!
//! The fixture starts one approved FIFO-backed shell so the HTTP stop route
//! has to cross the existing owner/permit boundary.  The assertions retain
//! the durable Pending execution/authority pair separately from the native
//! cancellation result and read the pair back through the get operation.

use super::*;

use forge_control::{WorkspaceStopIntent, WorkspaceStopServiceIdentity};
use forge_domain::{AuthenticatedPrincipal, ExecutionState, ForgeBackendId, OrchestrationIssuerId};
use forge_persistence::WorkspaceStore;
use forge_workspace::WorkspaceStateLayout;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::fs;

fn assemble_with_boot(
    config: forge_backend::config::BackendConfig,
    fixture: &Fixture,
    product_cache_root: &std::path::Path,
    destination_id: Uuid,
    runtime_instance_id: Uuid,
) -> Result<forge_backend::AppState, Box<dyn std::error::Error>> {
    Ok(forge_backend::http::assemble(
        config,
        forge_backend::http::BackendClients {
            control: &fixture.client,
            execution: &fixture.execution.client(),
            approval: &fixture.approval.client(),
            activity_leases: &fixture.activity_leases,
            runtime_instance_id,
            product_cache_root,
            destination_id,
        },
    )?)
}

fn scope_payload(fixture: &Fixture) -> Value {
    let locator = fixture.scope.locator();
    json!({
        "workspace_id": fixture.scope.workspace_id().into_uuid(),
        "workspace_revision": fixture.scope.workspace_revision().get(),
        "locator": {
            "location_id": locator.location_id().into_uuid(),
            "expected_revision": locator.expected_revision().get(),
            "relative_root": locator.relative_root().to_string_lossy(),
        },
    })
}

fn stop_payload(
    fixture: &Fixture,
    destination_id: Uuid,
    runtime_instance_id: Uuid,
    stop_id: Uuid,
    durable_request_id: Uuid,
) -> Value {
    json!({
        "scope": scope_payload(fixture),
        "stop_id": stop_id,
        "durable_request_id": durable_request_id,
        "service": {
            "backend_id": BACKEND_ID,
            "issuer": ISSUER_ID,
            "destination_id": destination_id,
            // In the in-process fixture this is the backend boot identity
            // threaded through BackendClients.  It is deliberately not the
            // Activity runtime identity supplied by the wire payload.
            "runtime_instance_id": runtime_instance_id,
        },
        "actor": {
            "session_id": fixture.session_id.into_uuid(),
            "principal": {"kind": "trusted_stdio"},
        },
    })
}

fn assert_response_failure(status: u16, response: &Value, label: &str) {
    assert_ne!(status, 200, "{label} unexpectedly succeeded: {response}");
    assert_eq!(response["ok"], false, "{label} response: {response}");
}

fn assert_completed_projection(
    response: &Value,
    stop_id: Uuid,
    durable_request_id: Uuid,
    attempted: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(response["ok"], true);
    let result = &response["result"];
    assert_eq!(result["found"], true);
    assert_eq!(result["status"], "completed");
    assert_eq!(result["durable_status"], "completed");
    assert_eq!(result["stop_id"], json!(stop_id));
    assert_eq!(result["durable_request_id"], json!(durable_request_id));
    assert_eq!(result["admission_fence_released"], true);
    assert_ne!(result["durable_status"], "released");

    let execution = &result["execution"];
    assert_eq!(execution["stop_id"], json!(stop_id));
    assert_eq!(execution["durable_request_id"], json!(durable_request_id));
    assert_eq!(execution["status"], "completed");
    assert!(
        execution["target_count"]
            .as_u64()
            .is_some_and(|count| count > 0)
    );
    let execution_targets = execution["targets"]
        .as_array()
        .ok_or("execution stop targets missing")?;
    assert!(!execution_targets.is_empty());
    assert!(execution_targets.iter().all(|target| {
        target["status"] == json!("closed") && target["expected_state"] != json!("completed")
    }));

    let authority = &result["authority"];
    assert_eq!(authority["stop_id"], json!(stop_id));
    assert_eq!(execution["target_count"], json!(1));
    assert_eq!(authority["target_count"], json!(3));
    let authority_targets = authority["targets"]
        .as_array()
        .ok_or("authority stop targets missing")?;
    assert!(!authority_targets.is_empty());
    let kinds: BTreeSet<&str> = authority_targets
        .iter()
        .filter_map(|target| target["kind"].as_str())
        .collect();
    assert!(
        kinds.contains("approval"),
        "approval target missing: {authority}"
    );
    assert!(kinds.contains("grant"), "grant target missing: {authority}");
    assert!(
        kinds.contains("auto_scope"),
        "AutoScope target missing: {authority}"
    );
    assert!(authority_targets.iter().all(|target| {
        target["before_revision"].as_i64().is_some()
            && target["after_revision"].as_i64()
                == target["before_revision"].as_i64().map(|value| value + 1)
            && target["before_digest"]
                .as_str()
                .is_some_and(|digest| digest.len() == 64)
            && target["after_digest"]
                .as_str()
                .is_some_and(|digest| digest.len() == 64)
    }));

    let native = &result["native"];
    if !attempted {
        assert_eq!(native["status"], "not_attempted");
        assert_eq!(native["owner_operation_attempted"], false);
        assert_eq!(native["count"], Value::Null);
        assert_eq!(native["cancellation_requested"], false);
        return Ok(());
    }
    let count = native["count"].as_u64().ok_or("native count missing")?;
    assert_eq!(native["owner_operation_attempted"], true);
    assert_eq!(
        native["status"],
        if count == 0 {
            "no_owned_execution"
        } else {
            "requested"
        }
    );
    assert_eq!(native["cancellation_requested"], json!(count > 0));
    assert!(native["count"].as_u64().is_some());
    assert_eq!(native["error"], Value::Null);
    assert_eq!(result["owner_quiescence"]["status"], "observed");
    assert_eq!(
        result["owner_quiescence"]["workspace_id"],
        result["workspace_id"]
    );
    Ok(())
}

fn stable_readback_fields(response: &Value) -> Value {
    let result = &response["result"];
    json!({
        "found": result["found"],
        "status": result["status"],
        "durable_status": result["durable_status"],
        "stop_id": result["stop_id"],
        "workspace_id": result["workspace_id"],
        "durable_request_id": result["durable_request_id"],
        "execution": result["execution"],
        "authority": result["authority"],
    })
}

fn hold_workspace_write_lock(
    fixture: &Fixture,
) -> Result<rusqlite::Connection, Box<dyn std::error::Error>> {
    let layout = WorkspaceStateLayout::inspect_existing(&fixture.workspace_root)?
        .ok_or("Workspace-stop lock fixture layout missing")?;
    let connection = rusqlite::Connection::open(layout.database_path())?;
    connection.busy_timeout(Duration::from_millis(20))?;
    connection.execute_batch("BEGIN IMMEDIATE")?;
    Ok(connection)
}

async fn start_fifo_execution(
    fixture: &Fixture,
    address: SocketAddr,
    marker: &str,
) -> Result<super::ApprovedShell, Box<dyn std::error::Error>> {
    let fifo_name = format!("http-workspace-stop-{marker}-{}.fifo", Uuid::now_v7());
    let fifo_path = fixture.workspace_root.join(&fifo_name);
    let fifo_status = std::process::Command::new("/usr/bin/mkfifo")
        .arg(&fifo_path)
        .status()?;
    if !fifo_status.success() {
        return Err(format!("mkfifo failed with status {fifo_status}").into());
    }
    let approved = super::approved_owner::raw_approved_shell(
        fixture,
        &format!("printf 'http-stop-{marker}-ready\\n'; cat < {fifo_name}"),
    )?;
    let (status, begin) = post_command(
        address,
        "execution.begin",
        super::execution_begin_payload(&approved),
    )
    .await?;
    if status == 200 {
        assert_eq!(begin["ok"], true);
    } else {
        assert_eq!(
            begin["error"]["code"], "UNKNOWN_OUTCOME",
            "execution.begin: {begin}"
        );
        assert_eq!(
            begin["error"]["readback"]["execution_id"],
            json!(approved.execution_id.into_uuid())
        );
    }
    let _running =
        wait_for_original_state(fixture, approved.execution_id, ExecutionState::Running).await?;
    let expected = format!("http-stop-{marker}-ready\n");
    super::approved_owner::wait_for_durable_prefix(
        fixture,
        approved.execution_id,
        expected.as_bytes(),
    )
    .await?;
    Ok(approved)
}

async fn wait_for_stop_readback(
    address: SocketAddr,
    payload: Value,
) -> Result<Value, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let (status, response) =
            post_command(address, "execution.stop_workspace_get", payload.clone()).await?;
        if status == 200 && response["ok"] == true && response["result"]["found"] == true {
            return Ok(response);
        }
        if Instant::now() >= deadline {
            return Err(format!("Workspace-stop readback did not settle: {response}").into());
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

async fn wait_for_original_terminal(
    fixture: &Fixture,
    execution_id: forge_domain::ExecutionId,
) -> Result<forge_domain::RegisteredExecution, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let layout = WorkspaceStateLayout::inspect_existing(&fixture.workspace_root)?
            .ok_or("original layout missing")?;
        let store = WorkspaceStore::open_existing(&layout)?;
        let record = store
            .get_execution(execution_id)?
            .ok_or("original execution missing")?;
        if record.state().is_terminal() {
            return Ok(record);
        }
        if Instant::now() >= deadline {
            return Err(format!("original execution remains {:?}", record.state()).into());
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

async fn wait_for_original_state(
    fixture: &Fixture,
    execution_id: forge_domain::ExecutionId,
    expected: ExecutionState,
) -> Result<forge_domain::RegisteredExecution, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let layout = WorkspaceStateLayout::inspect_existing(&fixture.workspace_root)?
            .ok_or("original layout missing")?;
        let store = WorkspaceStore::open_existing(&layout)?;
        if let Some(record) = store.get_execution(execution_id)? {
            if record.state() == expected {
                return Ok(record);
            }
            if record.state().is_terminal() {
                return Err(format!(
                    "original execution reached {:?} before {:?}",
                    record.state(),
                    expected
                )
                .into());
            }
        }
        if Instant::now() >= deadline {
            return Err("admitted begin did not journal the expected state".into());
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn assert_unknown_stop_reply(
    status: u16,
    response: &Value,
    stop_id: Uuid,
    durable_request_id: Uuid,
    runtime_instance_id: Uuid,
) {
    assert_eq!(status, 202, "expected unknown stop outcome: {response}");
    assert_eq!(response["ok"], false);
    assert_eq!(response["error"]["code"], "UNKNOWN_OUTCOME");
    assert_eq!(response["error"]["recovery_action"], "read_back");
    assert_eq!(response["error"]["readback"]["kind"], "workspace_stop");
    assert_eq!(response["error"]["readback"]["stop_id"], json!(stop_id));
    assert_eq!(
        response["error"]["readback"]["durable_request_id"],
        json!(durable_request_id)
    );
    assert_eq!(
        response["error"]["readback"]["runtime_instance_id"],
        json!(runtime_instance_id)
    );
    assert_eq!(
        response["error"]["readback"]["request_digest"]
            .as_str()
            .map(str::len),
        Some(64)
    );
}

struct AuthorityCohort {
    pending: forge_domain::RegisteredApprovalRequest,
    unused: super::ApprovedShell,
    auto_scope: forge_domain::AutoApprovalScope,
    before: super::approved_owner::AuthoritySnapshot,
}

impl AuthorityCohort {
    fn snapshot(
        &self,
        fixture: &Fixture,
    ) -> Result<super::approved_owner::AuthoritySnapshot, Box<dyn std::error::Error>> {
        super::approved_owner::authority_snapshot(
            fixture,
            &self.pending,
            &self.unused,
            &self.auto_scope,
        )
    }

    fn assert_unchanged(&self, fixture: &Fixture) -> Result<(), Box<dyn std::error::Error>> {
        let current = self.snapshot(fixture)?;
        super::approved_owner::assert_counts_unchanged(self.before, current)?;
        assert_eq!(current.pending_state, self.before.pending_state);
        assert_eq!(current.pending_revision, self.before.pending_revision);
        assert_eq!(current.unused_grant_state, self.before.unused_grant_state);
        assert_eq!(
            current.unused_grant_revision,
            self.before.unused_grant_revision
        );
        assert_eq!(current.auto_scope_state, self.before.auto_scope_state);
        assert_eq!(current.auto_scope_revision, self.before.auto_scope_revision);
        Ok(())
    }
}

fn prepare_authority_cohort(
    fixture: &Fixture,
) -> Result<AuthorityCohort, Box<dyn std::error::Error>> {
    let unused = super::approved_owner::raw_approved_shell(fixture, "printf 'unused\\n'")?;
    let pending = super::approved_owner::raw_pending_shell(fixture, "printf 'pending\\n'")?;
    let auto_scope = super::approved_owner::raw_auto_scope(fixture, timestamp_now()?)?;
    let before =
        super::approved_owner::authority_snapshot(fixture, &pending, &unused, &auto_scope)?;
    Ok(AuthorityCohort {
        pending,
        unused,
        auto_scope,
        before,
    })
}

fn prepare_owned_approved_shell(
    fixture: &Fixture,
) -> Result<super::ApprovedShell, Box<dyn std::error::Error>> {
    let fifo_name = format!("http-workspace-stop-{}.fifo", Uuid::now_v7());
    let fifo_path = fixture.workspace_root.join(&fifo_name);
    let fifo_status = std::process::Command::new("/usr/bin/mkfifo")
        .arg(&fifo_path)
        .status()?;
    if !fifo_status.success() {
        return Err(format!("mkfifo failed with status {fifo_status}").into());
    }
    super::approved_owner::raw_approved_shell(
        fixture,
        &format!("printf 'http-stop-ready\\n'; cat < {fifo_name}"),
    )
}

async fn begin_owned_execution(
    fixture: &Fixture,
    address: SocketAddr,
    cohort: &AuthorityCohort,
    approved: super::ApprovedShell,
) -> Result<super::ApprovedShell, Box<dyn std::error::Error>> {
    let (status, begin) = post_command(
        address,
        "execution.begin",
        super::execution_begin_payload(&approved),
    )
    .await?;
    assert_eq!(status, 200, "execution.begin response: {begin}");
    assert_eq!(begin["ok"], true);
    let _running = wait_for_execution_state(
        &fixture.client,
        &fixture.scope,
        approved.execution_id,
        ExecutionState::Running,
    )
    .await?;
    super::approved_owner::wait_for_durable_prefix(
        fixture,
        approved.execution_id,
        b"http-stop-ready\n",
    )
    .await?;
    cohort.assert_unchanged(fixture)?;
    super::approved_owner::disable_owner_location(fixture, address).await?;
    Ok(approved)
}

async fn stop_and_readback(
    fixture: &Fixture,
    address: SocketAddr,
    destination_id: Uuid,
    runtime_instance_id: Uuid,
    cohort: &AuthorityCohort,
) -> Result<(Value, Value, Uuid, Uuid), Box<dyn std::error::Error>> {
    let stop_id = Uuid::now_v7();
    let durable_request_id = Uuid::now_v7();
    let payload = stop_payload(
        fixture,
        destination_id,
        runtime_instance_id,
        stop_id,
        durable_request_id,
    );
    let (status, stopped) =
        post_command(address, "execution.stop_workspace", payload.clone()).await?;
    assert_eq!(status, 200, "execution.stop_workspace response: {stopped}");
    assert_completed_projection(&stopped, stop_id, durable_request_id, true)?;
    assert_eq!(
        stopped["result"]["execution"]["owner_runtime_instance_id"],
        json!(runtime_instance_id)
    );
    let after_first_stop = cohort.snapshot(fixture)?;

    let (status, observed) =
        post_command(address, "execution.stop_workspace_get", payload.clone()).await?;
    assert_eq!(
        status, 200,
        "execution.stop_workspace_get response: {observed}"
    );
    assert_eq!(observed["ok"], true);
    assert_eq!(observed["result"]["native"], Value::Null);
    assert_eq!(observed["result"]["owner_quiescence"], Value::Null);
    assert_eq!(
        stable_readback_fields(&observed),
        stable_readback_fields(&stopped)
    );
    assert_eq!(cohort.snapshot(fixture)?, after_first_stop);
    Ok((stopped, payload, stop_id, durable_request_id))
}

async fn assert_changed_identity_rejections(
    address: SocketAddr,
    payload: &Value,
    stopped: &Value,
) -> Result<(), Box<dyn std::error::Error>> {
    for (label, changed) in [
        ("changed stop id", {
            let mut value = payload.clone();
            value["stop_id"] = json!(Uuid::now_v7());
            value
        }),
        ("changed session", {
            let mut value = payload.clone();
            value["actor"]["session_id"] = json!(Uuid::now_v7());
            value
        }),
        ("changed server boot", {
            let mut value = payload.clone();
            value["service"]["runtime_instance_id"] = json!(Uuid::now_v7());
            value
        }),
    ] {
        let (status, response) = post_command(address, "execution.stop_workspace", changed).await?;
        assert_response_failure(status, &response, label);
        assert_ne!(
            response["error"]["code"], "UNKNOWN_OUTCOME",
            "{label}: {response}"
        );
        assert_eq!(response["error"]["readback"], Value::Null);
    }
    let (status, original_get) =
        post_command(address, "execution.stop_workspace_get", payload.clone()).await?;
    assert_eq!(
        status, 200,
        "original get after identity rejects: {original_get}"
    );
    assert_eq!(
        stable_readback_fields(&original_get),
        stable_readback_fields(stopped)
    );
    Ok(())
}

async fn assert_terminal_cleanup(
    fixture: &Fixture,
    cohort: &AuthorityCohort,
    approved: &super::ApprovedShell,
) -> Result<(), Box<dyn std::error::Error>> {
    let terminal = wait_for_original_terminal(fixture, approved.execution_id).await?;
    assert_eq!(terminal.state(), ExecutionState::Cancelled);
    let output = super::approved_owner::read_cancelled_output(fixture, approved)?;
    assert!(output.starts_with(b"http-stop-ready\n"));

    let after_stop = cohort.snapshot(fixture)?;
    super::approved_owner::assert_counts_unchanged(cohort.before, after_stop)?;
    assert_eq!(
        after_stop.pending_state,
        forge_domain::ApprovalRequestState::Cancelled
    );
    assert_eq!(
        after_stop.pending_revision,
        cohort.before.pending_revision.checked_next()?
    );
    assert_eq!(after_stop.unused_grant_state, 2);
    assert_eq!(
        after_stop.unused_grant_revision,
        cohort.before.unused_grant_revision.checked_next()?
    );
    assert_eq!(
        after_stop.auto_scope_state,
        forge_domain::AutoApprovalScopeState::Revoked
    );
    assert_eq!(
        after_stop.auto_scope_revision,
        cohort.before.auto_scope_revision.checked_next()?
    );
    Ok(())
}

async fn run_owned_stop_http_flow(
    fixture: &Fixture,
    address: SocketAddr,
    destination_id: Uuid,
    runtime_instance_id: Uuid,
) -> Result<(), Box<dyn std::error::Error>> {
    let approved = prepare_owned_approved_shell(fixture)?;
    let cohort = prepare_authority_cohort(fixture)?;
    let approved = begin_owned_execution(fixture, address, &cohort, approved).await?;
    let (stopped, payload, stop_id, durable_request_id) = stop_and_readback(
        fixture,
        address,
        destination_id,
        runtime_instance_id,
        &cohort,
    )
    .await?;
    assert_changed_identity_rejections(address, &payload, &stopped).await?;

    let (status, retry) = post_command(address, "execution.stop_workspace", payload).await?;
    assert_eq!(status, 200, "exact stop retry response: {retry}");
    assert_completed_projection(&retry, stop_id, durable_request_id, false)?;
    assert_eq!(
        stable_readback_fields(&retry),
        stable_readback_fields(&stopped)
    );
    assert_terminal_cleanup(fixture, &cohort, &approved).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_http_completed_stop_replay_does_not_cancel_new_execution_and_allows_new_cycle()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = prepare_fixture()?;
    let cache = fixture.root.join("stop-replay-cache");
    fs::create_dir(&cache)?;
    let destination = delegated_destination_id(&fixture)?;
    let boot = Uuid::now_v7();
    let state = assemble_with_boot(backend_config()?, &fixture, &cache, destination, boot)?;
    let address = serve(state.clone()).await?;
    let result = async {
        let first = start_fifo_execution(&fixture, address, "first-cycle").await?;
        let old_payload = stop_payload(&fixture, destination, boot, Uuid::now_v7(), Uuid::now_v7());
        let (status, stopped) =
            post_command(address, "execution.stop_workspace", old_payload.clone()).await?;
        assert_eq!(status, 200, "{stopped}");
        assert_eq!(stopped["result"]["durable_status"], "completed");
        assert_eq!(stopped["result"]["admission_fence_released"], true);
        assert_eq!(
            wait_for_original_terminal(&fixture, first.execution_id)
                .await?
                .state(),
            ExecutionState::Cancelled
        );
        let second = start_fifo_execution(&fixture, address, "second-cycle").await?;
        let (status, replay) =
            post_command(address, "execution.stop_workspace", old_payload.clone()).await?;
        assert_eq!(status, 200, "{replay}");
        assert_eq!(replay["result"]["durable_status"], "completed");
        assert_eq!(
            replay["result"]["native"]["owner_operation_attempted"],
            false
        );
        assert_eq!(
            wait_for_original_state(&fixture, second.execution_id, ExecutionState::Running)
                .await?
                .state(),
            ExecutionState::Running
        );
        let next_payload =
            stop_payload(&fixture, destination, boot, Uuid::now_v7(), Uuid::now_v7());
        let (status, next) =
            post_command(address, "execution.stop_workspace", next_payload).await?;
        assert_eq!(status, 200, "{next}");
        assert_eq!(next["result"]["durable_status"], "completed");
        assert_eq!(next["result"]["admission_fence_released"], true);
        assert_eq!(
            wait_for_original_terminal(&fixture, second.execution_id)
                .await?
                .state(),
            ExecutionState::Cancelled
        );
        let (status, historical) =
            post_command(address, "execution.stop_workspace_get", old_payload).await?;
        assert_eq!(status, 200, "{historical}");
        assert_eq!(
            historical["result"]["stop_id"],
            stopped["result"]["stop_id"]
        );
        assert_eq!(historical["result"]["durable_status"], "completed");
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;
    let shutdown = state.shutdown(Duration::from_secs(5)).await;
    let owners = fixture.shutdown();
    result?;
    assert!(shutdown.is_successful());
    owners?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_http_workspace_stop_preserves_completed_pair_and_exact_retry()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = prepare_fixture()?;
    let config = backend_config()?;
    let destination_id = delegated_destination_id(&fixture)?;
    let runtime_instance_id = Uuid::now_v7();
    assert_ne!(runtime_instance_id, fixture.runtime_instance_id.into_uuid());
    let cache = fixture.root.join("workspace-stop-http-cache");
    fs::create_dir(&cache)?;
    let state = assemble_with_boot(
        config,
        &fixture,
        &cache,
        destination_id,
        runtime_instance_id,
    )?;
    let address = serve(state.clone()).await?;
    let flow =
        run_owned_stop_http_flow(&fixture, address, destination_id, runtime_instance_id).await;
    let http_shutdown = state.shutdown(Duration::from_secs(5)).await;
    let owner_shutdown = super::admitted_journal::shutdown_disabled_fixture(fixture);

    let mut failures = Vec::new();
    if let Err(error) = flow {
        failures.push(format!("flow: {error}"));
    }
    if !http_shutdown.is_successful() {
        failures.push("HTTP shutdown was incomplete".to_owned());
    }
    if let Err(error) = owner_shutdown {
        failures.push(format!("owner shutdown: {error}"));
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; ").into())
    }
}

fn assert_rejected_without_readback(status: u16, response: &Value, label: &str) {
    assert_response_failure(status, response, label);
    assert_ne!(response["error"]["code"], "UNKNOWN_OUTCOME");
    assert_eq!(response["error"]["readback"], Value::Null);
}

async fn assert_service_echo_rejections(
    address: SocketAddr,
    valid: &Value,
) -> Result<(), Box<dyn std::error::Error>> {
    for field in [
        "backend_id",
        "issuer",
        "destination_id",
        "runtime_instance_id",
    ] {
        let mut wrong_service = valid.clone();
        wrong_service["service"][field] = json!(Uuid::now_v7());
        let (status, response) =
            post_command(address, "execution.stop_workspace", wrong_service).await?;
        assert_rejected_without_readback(status, &response, field);
    }
    Ok(())
}

async fn assert_scope_and_payload_rejections(
    address: SocketAddr,
    fixture: &Fixture,
    valid: &Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut unowned = valid.clone();
    unowned["scope"]["workspace_id"] = json!(Uuid::now_v7());
    let (status, response) = post_command(address, "execution.stop_workspace", unowned).await?;
    assert_rejected_without_readback(status, &response, "unowned workspace");

    let mut stale_scope = valid.clone();
    stale_scope["scope"]["workspace_revision"] =
        json!(fixture.scope.workspace_revision().get() + 1);
    let (status, response) = post_command(address, "execution.stop_workspace", stale_scope).await?;
    assert_rejected_without_readback(status, &response, "stale scope");

    let mut unknown_field = valid.clone();
    unknown_field["unexpected"] = json!(true);
    let (status, response) =
        post_command(address, "execution.stop_workspace_get", unknown_field).await?;
    assert_rejected_without_readback(status, &response, "unknown field");

    let mut unsupported_principal = valid.clone();
    unsupported_principal["actor"]["principal"] = json!({"kind": "unsupported"});
    let (status, response) =
        post_command(address, "execution.stop_workspace", unsupported_principal).await?;
    assert_rejected_without_readback(status, &response, "unsupported principal");

    for (label, field) in [
        ("nil stop id", "stop_id"),
        ("nil durable request id", "durable_request_id"),
    ] {
        let mut nil_identity = valid.clone();
        nil_identity[field] = json!(Uuid::nil());
        let (status, response) =
            post_command(address, "execution.stop_workspace", nil_identity).await?;
        assert_rejected_without_readback(status, &response, label);
    }
    Ok(())
}

async fn assert_provider_rejections(
    address: SocketAddr,
    fixture: &Fixture,
    valid: &Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let _disabled_auto_preference = fixture
        .approval
        .client()
        .submit_set_auto_approval(fixture.scope.clone(), false)?
        .recv()?;
    let (status, absence) =
        post_command(address, "execution.stop_workspace_get", valid.clone()).await?;
    assert_eq!(status, 200, "original owner readback: {absence}");
    assert_eq!(absence["result"]["found"], false);

    let mut wrong_principal = valid.clone();
    wrong_principal["actor"]["principal"] = json!({
        "kind": "direct_token",
        "token_id": Uuid::now_v7(),
    });
    let (status, response) =
        post_command(address, "execution.stop_workspace", wrong_principal).await?;
    assert_rejected_without_readback(status, &response, "wrong principal");
    Ok(())
}

async fn assert_closed_session_rejection(
    address: SocketAddr,
    fixture: &Fixture,
    valid: Value,
) -> Result<(), Box<dyn std::error::Error>> {
    close_fixture_session(fixture)?;
    let (status, response) = post_command(address, "execution.stop_workspace_get", valid).await?;
    assert_rejected_without_readback(status, &response, "closed session");
    Ok(())
}

fn assert_negative_stop_absent(
    fixture: &Fixture,
    destination_id: Uuid,
    runtime_instance_id: Uuid,
    stop_id: Uuid,
    durable_request_id: Uuid,
) -> Result<(), Box<dyn std::error::Error>> {
    let service = WorkspaceStopServiceIdentity::new(
        ForgeBackendId::from_uuid(BACKEND_ID),
        OrchestrationIssuerId::from_uuid(ISSUER_ID),
        destination_id,
        forge_domain::RuntimeInstanceId::from_uuid(runtime_instance_id),
    )?;
    let intent = WorkspaceStopIntent::new(
        fixture.scope.clone(),
        stop_id,
        durable_request_id,
        service,
        fixture.session_id,
        AuthenticatedPrincipal::TrustedStdio,
    )?;
    let layout = WorkspaceStateLayout::inspect_existing(&fixture.workspace_root)?
        .ok_or("negative stop fixture Workspace layout missing")?;
    let store = WorkspaceStore::open_existing(&layout)?;
    assert!(
        store
            .owned_workspace_stop_for_request(&intent.execution_request(timestamp_now()?))?
            .is_none()
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_http_workspace_stop_rejects_unowned_closed_and_mismatched_intents_before_effects()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = prepare_fixture()?;
    let cohort = prepare_authority_cohort(&fixture)?;
    let destination_id = delegated_destination_id(&fixture)?;
    let runtime_instance_id = Uuid::now_v7();
    assert_ne!(runtime_instance_id, fixture.runtime_instance_id.into_uuid());
    let cache = fixture.root.join("workspace-stop-negative-cache");
    fs::create_dir(&cache)?;
    let state = assemble_with_boot(
        backend_config()?,
        &fixture,
        &cache,
        destination_id,
        runtime_instance_id,
    )?;
    let address = serve(state.clone()).await?;
    let stop_id = Uuid::now_v7();
    let durable_request_id = Uuid::now_v7();
    let valid = stop_payload(
        &fixture,
        destination_id,
        runtime_instance_id,
        stop_id,
        durable_request_id,
    );

    let result = async {
        assert_service_echo_rejections(address, &valid).await?;
        assert_scope_and_payload_rejections(address, &fixture, &valid).await?;
        assert_provider_rejections(address, &fixture, &valid).await?;
        assert_closed_session_rejection(address, &fixture, valid).await?;
        cohort.assert_unchanged(&fixture)?;
        assert_negative_stop_absent(
            &fixture,
            destination_id,
            runtime_instance_id,
            stop_id,
            durable_request_id,
        )?;
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;

    let http_shutdown = state.shutdown(Duration::from_secs(5)).await;
    let owner_shutdown = super::admitted_journal::shutdown_disabled_fixture(fixture);
    result?;
    if !http_shutdown.is_successful() {
        return Err("HTTP shutdown was incomplete".into());
    }
    owner_shutdown?;
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_http_workspace_stop_deadline_returns_exact_readback_after_sqlite_lock()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = prepare_fixture()?;
    let unused = super::approved_owner::raw_approved_shell(&fixture, "printf 'unused\\n'")?;
    let pending = super::approved_owner::raw_pending_shell(&fixture, "printf 'pending\\n'")?;
    let auto_scope = super::approved_owner::raw_auto_scope(&fixture, timestamp_now()?)?;
    let destination_id = delegated_destination_id(&fixture)?;
    let runtime_instance_id = Uuid::now_v7();
    assert_ne!(runtime_instance_id, fixture.runtime_instance_id.into_uuid());
    let cache = fixture.root.join("workspace-stop-deadline-cache");
    fs::create_dir(&cache)?;
    let config = backend_config()?.with_command_deadline(Duration::from_millis(100));
    let state = assemble_with_boot(
        config,
        &fixture,
        &cache,
        destination_id,
        runtime_instance_id,
    )?;
    let address = serve(state.clone()).await?;
    let result = async {
        let approved = start_fifo_execution(&fixture, address, "deadline").await?;
        let before =
            super::approved_owner::authority_snapshot(&fixture, &pending, &unused, &auto_scope)?;
        super::approved_owner::disable_owner_location(&fixture, address).await?;
        let stop_id = Uuid::now_v7();
        let durable_request_id = Uuid::now_v7();
        let payload = stop_payload(
            &fixture,
            destination_id,
            runtime_instance_id,
            stop_id,
            durable_request_id,
        );
        let lock = hold_workspace_write_lock(&fixture)?;
        for _ in 0..4 {
            let (status, unknown) =
                post_command(address, "execution.stop_workspace", payload.clone()).await?;
            assert_unknown_stop_reply(
                status,
                &unknown,
                stop_id,
                durable_request_id,
                runtime_instance_id,
            );
        }
        // Expired HTTP observers cannot release the four actual owner slots.
        let (status, saturated) =
            post_command(address, "execution.stop_workspace", payload.clone()).await?;
        assert_response_failure(status, &saturated, "retained owner capacity");
        assert_eq!(saturated["error"]["code"], "CAPACITY_EXCEEDED");
        assert_eq!(saturated["error"]["readback"], Value::Null);
        drop(lock);

        let observed = wait_for_stop_readback(address, payload).await?;
        assert_eq!(observed["result"]["native"], Value::Null);
        assert_eq!(
            observed["result"]["execution"]["owner_runtime_instance_id"],
            json!(runtime_instance_id)
        );
        assert_eq!(observed["result"]["execution"]["status"], "completed");
        assert_eq!(observed["result"]["authority"]["target_count"], json!(3));
        let terminal = wait_for_original_terminal(&fixture, approved.execution_id).await?;
        assert_eq!(terminal.state(), ExecutionState::Cancelled);
        let after =
            super::approved_owner::authority_snapshot(&fixture, &pending, &unused, &auto_scope)?;
        super::approved_owner::assert_counts_unchanged(before, after)?;
        assert_eq!(
            after.pending_state,
            forge_domain::ApprovalRequestState::Cancelled
        );
        assert_eq!(after.unused_grant_state, 2);
        assert_eq!(
            after.auto_scope_state,
            forge_domain::AutoApprovalScopeState::Revoked
        );
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;
    let http_shutdown = state.shutdown(Duration::from_secs(5)).await;
    let owner_shutdown = super::admitted_journal::shutdown_disabled_fixture(fixture);
    let mut failures = Vec::new();
    if let Err(error) = result {
        failures.push(format!("flow: {error}"));
    }
    if !http_shutdown.is_successful() {
        failures.push("HTTP shutdown was incomplete".to_owned());
    }
    if let Err(error) = owner_shutdown {
        failures.push(format!("owner shutdown: {error}"));
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; ").into())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_http_workspace_stop_disconnect_keeps_owner_and_readback_alive()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = prepare_fixture()?;
    let unused = super::approved_owner::raw_approved_shell(&fixture, "printf 'unused\\n'")?;
    let pending = super::approved_owner::raw_pending_shell(&fixture, "printf 'pending\\n'")?;
    let auto_scope = super::approved_owner::raw_auto_scope(&fixture, timestamp_now()?)?;
    let destination_id = delegated_destination_id(&fixture)?;
    let runtime_instance_id = Uuid::now_v7();
    assert_ne!(runtime_instance_id, fixture.runtime_instance_id.into_uuid());
    let cache = fixture.root.join("workspace-stop-disconnect-cache");
    fs::create_dir(&cache)?;
    let state = assemble_with_boot(
        backend_config()?,
        &fixture,
        &cache,
        destination_id,
        runtime_instance_id,
    )?;
    let address = serve(state.clone()).await?;
    let result = async {
        let approved = start_fifo_execution(&fixture, address, "disconnect").await?;
        let before =
            super::approved_owner::authority_snapshot(&fixture, &pending, &unused, &auto_scope)?;
        super::approved_owner::disable_owner_location(&fixture, address).await?;
        let stop_id = Uuid::now_v7();
        let durable_request_id = Uuid::now_v7();
        let payload = stop_payload(
            &fixture,
            destination_id,
            runtime_instance_id,
            stop_id,
            durable_request_id,
        );
        let lock = hold_workspace_write_lock(&fixture)?;
        let mut stream = super::binding_lifecycle::open_command_without_read(
            address,
            "execution.stop_workspace",
            payload.clone(),
        )
        .await?;
        // The SQLite lock keeps the admitted owner in prepare/apply while
        // the HTTP observer disappears.  The owner task must retain its
        // permit and finish after this stream is dropped.
        tokio::time::sleep(Duration::from_millis(100)).await;
        stream.shutdown().await?;
        drop(stream);
        drop(lock);

        let observed = wait_for_stop_readback(address, payload).await?;
        assert_eq!(observed["result"]["native"], Value::Null);
        assert_eq!(
            observed["result"]["execution"]["owner_runtime_instance_id"],
            json!(runtime_instance_id)
        );
        assert_eq!(observed["result"]["stop_id"], json!(stop_id));
        assert_eq!(
            observed["result"]["durable_request_id"],
            json!(durable_request_id)
        );
        let terminal = wait_for_original_terminal(&fixture, approved.execution_id).await?;
        assert_eq!(terminal.state(), ExecutionState::Cancelled);
        let after =
            super::approved_owner::authority_snapshot(&fixture, &pending, &unused, &auto_scope)?;
        super::approved_owner::assert_counts_unchanged(before, after)?;
        assert_eq!(
            after.pending_state,
            forge_domain::ApprovalRequestState::Cancelled
        );
        assert_eq!(after.unused_grant_state, 2);
        assert_eq!(
            after.auto_scope_state,
            forge_domain::AutoApprovalScopeState::Revoked
        );
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;
    let http_shutdown = state.shutdown(Duration::from_secs(5)).await;
    let owner_shutdown = super::admitted_journal::shutdown_disabled_fixture(fixture);
    let mut failures = Vec::new();
    if let Err(error) = result {
        failures.push(format!("flow: {error}"));
    }
    if !http_shutdown.is_successful() {
        failures.push("HTTP shutdown was incomplete".to_owned());
    }
    if let Err(error) = owner_shutdown {
        failures.push(format!("owner shutdown: {error}"));
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; ").into())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_http_workspace_stop_shutdown_retains_blocked_owner_until_reply()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = prepare_fixture()?;
    let destination_id = delegated_destination_id(&fixture)?;
    let boot = Uuid::now_v7();
    let cache = fixture.root.join("workspace-stop-shutdown-cache");
    fs::create_dir(&cache)?;
    let state = assemble_with_boot(
        backend_config()?.with_command_deadline(Duration::from_millis(100)),
        &fixture,
        &cache,
        destination_id,
        boot,
    )?;
    let address = serve(state.clone()).await?;
    let result = async {
        let approved = start_fifo_execution(&fixture, address, "shutdown").await?;
        super::approved_owner::disable_owner_location(&fixture, address).await?;
        let stop_id = Uuid::now_v7();
        let request_id = Uuid::now_v7();
        let payload = stop_payload(&fixture, destination_id, boot, stop_id, request_id);
        let lock = hold_workspace_write_lock(&fixture)?;
        let (status, reply) = post_command(address, "execution.stop_workspace", payload).await?;
        assert_unknown_stop_reply(status, &reply, stop_id, request_id, boot);
        let pending = state.shutdown(Duration::ZERO).await;
        assert!(!pending.is_complete());
        assert!(pending.pending_event_tasks > 0);
        drop(lock);
        let final_shutdown = state.shutdown(Duration::from_secs(5)).await;
        assert!(final_shutdown.is_successful(), "{final_shutdown:?}");
        let terminal = wait_for_original_terminal(&fixture, approved.execution_id).await?;
        assert_eq!(terminal.state(), ExecutionState::Cancelled);
        let service = WorkspaceStopServiceIdentity::new(
            ForgeBackendId::from_uuid(BACKEND_ID),
            OrchestrationIssuerId::from_uuid(ISSUER_ID),
            destination_id,
            forge_domain::RuntimeInstanceId::from_uuid(boot),
        )?;
        let intent = WorkspaceStopIntent::new(
            fixture.scope.clone(),
            stop_id,
            request_id,
            service,
            fixture.session_id,
            AuthenticatedPrincipal::TrustedStdio,
        )?;
        let layout = WorkspaceStateLayout::inspect_existing(&fixture.workspace_root)?
            .ok_or("original layout missing")?;
        let store = WorkspaceStore::open_existing(&layout)?;
        let pair = store
            .owned_workspace_stop_for_request(&intent.execution_request(timestamp_now()?))?
            .ok_or("retained stop missing")?;
        assert_eq!(
            pair.0.status(),
            forge_persistence::ExecutionStopStatus::Completed
        );
        assert_eq!(pair.0.stop_id(), stop_id);
        assert_eq!(pair.1.stop_id(), stop_id);
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;
    let http_shutdown = state.shutdown(Duration::from_secs(5)).await;
    let owner_shutdown = super::admitted_journal::shutdown_disabled_fixture(fixture);
    let mut failures = Vec::new();
    if let Err(error) = result {
        failures.push(format!("flow: {error}"));
    }
    if !http_shutdown.is_successful() {
        failures.push(format!("HTTP shutdown: {http_shutdown:?}"));
    }
    if let Err(error) = owner_shutdown {
        failures.push(format!("owner shutdown: {error}"));
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; ").into())
    }
}
