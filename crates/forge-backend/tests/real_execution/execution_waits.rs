use super::lease_readback::post_ok;
use super::*;
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

pub(super) fn wait_payload(authority: &Value, timeout_ms: u64, after_sequence: u64) -> Value {
    json!({
        "authority": authority,
        "after_sequence": after_sequence,
        "max_bytes": forge_domain::MIN_EXECUTION_OUTPUT_READ_BYTES,
        "max_events": forge_domain::MAX_EXECUTION_OUTPUT_READ_EVENTS,
        "timeout_ms": timeout_ms,
    })
}

async fn assert_execution_get(
    address: SocketAddr,
    approved: &ApprovedShell,
    fixture: &Fixture,
) -> Result<(), Box<dyn std::error::Error>> {
    let (status, response) = post_command(
        address,
        "execution.get",
        json!({"authority": approved.authority.clone()}),
    )
    .await?;
    assert_eq!(status, 200, "execution.get response: {response}");
    let result = &response["result"];
    assert_eq!(
        result["execution_id"],
        approved.execution_id.into_uuid().to_string()
    );
    assert_eq!(
        result["workspace_id"],
        fixture.scope.workspace_id().into_uuid().to_string()
    );
    assert_eq!(
        result["activity_id"],
        fixture.activity_id.into_uuid().to_string()
    );
    assert_eq!(result["state"], "completed");
    assert_eq!(result["terminal"], true);
    assert_eq!(result["failure_code"], Value::Null);
    let created_at = result["created_at_ms"]
        .as_i64()
        .ok_or("execution created_at missing")?;
    let updated_at = result["updated_at_ms"]
        .as_i64()
        .ok_or("execution updated_at missing")?;
    assert!(updated_at >= created_at);
    assert!(result["revision"].as_i64().is_some());
    Ok(())
}

fn assert_terminal_wait(result: &Value, execution_id: Uuid) {
    assert_eq!(result["execution_id"], execution_id.to_string());
    assert_eq!(result["state"], "Completed");
    assert_eq!(result["terminal"], true);
    assert_eq!(result["timed_out"], false);
    assert_eq!(result["changed"], true);
    assert!(result["revision"].as_i64().is_some());
    assert!(
        result["event_count"]
            .as_u64()
            .is_some_and(|count| count > 0)
    );
}

async fn assert_rejected_wait(
    address: SocketAddr,
    payload: Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let (status, response) = post_command(address, "execution.wait", payload).await?;
    assert_eq!(
        status, 409,
        "invalid execution wait was accepted: {response}"
    );
    assert_eq!(response["ok"], false);
    Ok(())
}

async fn assert_terminal_and_authority_waits(
    address: SocketAddr,
    approved: &ApprovedShell,
    fixture: &Fixture,
) -> Result<(), Box<dyn std::error::Error>> {
    let terminal = post_ok(
        address,
        "execution.wait",
        wait_payload(&approved.authority, 1_000, 0),
    )
    .await?;
    assert_terminal_wait(&terminal, approved.execution_id.into_uuid());
    assert_execution_get(address, approved, fixture).await?;

    let mut wrong_provenance = approved.authority.clone();
    wrong_provenance["goal_id"] = json!(Uuid::now_v7());
    assert_rejected_wait(address, wait_payload(&wrong_provenance, 0, 0)).await?;

    let mut wrong_session = approved.authority.clone();
    wrong_session["actor"]["session_id"] = json!(Uuid::now_v7());
    assert_rejected_wait(address, wait_payload(&wrong_session, 0, 0)).await
}

async fn run_running_wait_lifecycle(
    address: SocketAddr,
    fixture: &Fixture,
    fifo_name: &str,
) -> Result<ApprovedShell, Box<dyn std::error::Error>> {
    let approved = prepare_approved_shell_for_script(fixture, &format!("cat < {fifo_name}"))?;
    let (status, response) = post_command(
        address,
        "execution.begin",
        execution_begin_payload(&approved),
    )
    .await?;
    assert_eq!(status, 200, "running wait begin response: {response}");
    let _running = wait_for_execution_state(
        &fixture.client,
        &fixture.scope,
        approved.execution_id,
        forge_domain::ExecutionState::Running,
    )
    .await?;

    let unchanged = post_ok(
        address,
        "execution.wait",
        wait_payload(&approved.authority, 0, 0),
    )
    .await?;
    assert_eq!(unchanged["state"], "Running");
    assert_eq!(unchanged["terminal"], false);
    assert_eq!(unchanged["timed_out"], true);
    assert_eq!(unchanged["changed"], false);
    assert_eq!(unchanged["event_count"], 0);

    let pending_payload = wait_payload(&approved.authority, 30_000, 0);
    let retry = Arc::new(AtomicBool::new(true));
    let pending = tokio::spawn(run_long_wait_until_admitted(
        address,
        pending_payload,
        Arc::clone(&retry),
    ));
    tokio::task::yield_now().await;
    let capacity = assert_wait_capacity_exceeded(address, &approved.authority).await;
    if pending.is_finished() {
        let outcome = pending.await.map_err(|error| error.to_string())?;
        let message = outcome.err().map_or_else(
            || "long execution.wait completed before the lifecycle changed".to_owned(),
            |error| format!("long execution.wait admission failed: {error}"),
        );
        return Err(message.into());
    }
    capacity?;
    let read = post_command(
        address,
        "execution.read",
        json!({
            "authority": approved.authority.clone(),
            "after_sequence": 0,
            "max_bytes": forge_domain::MIN_EXECUTION_OUTPUT_READ_BYTES,
            "max_events": forge_domain::MAX_EXECUTION_OUTPUT_READ_EVENTS,
        }),
    )
    .await?;
    assert_eq!(
        read.0, 200,
        "bridge read stalled behind execution.wait: {read:?}"
    );
    if pending.is_finished() {
        let outcome = pending.await.map_err(|error| error.to_string())?;
        let message = outcome.err().map_or_else(
            || "execution.wait completed before its lifecycle changed".to_owned(),
            |error| format!("long execution.wait failed: {error}"),
        );
        return Err(message.into());
    }
    pending.abort();
    let joined = pending.await;
    assert!(joined.is_err_and(|error| error.is_cancelled()));
    wait_until_wait_slot_released(address, &approved.authority).await?;

    let still_running = fixture
        .client
        .execution_get(fixture.scope.clone(), approved.execution_id)?
        .ok_or("running execution disappeared after wait cancellation")?;
    assert_eq!(still_running.state(), forge_domain::ExecutionState::Running);

    Ok(approved)
}

async fn run_long_wait_until_admitted(
    address: SocketAddr,
    payload: Value,
    retry: Arc<AtomicBool>,
) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let (status, response) = post_command(address, "execution.wait", payload.clone())
            .await
            .map_err(|error| format!("connection closed during execution.wait: {error}"))?;
        if status == 200 {
            return Ok(());
        }
        let is_capacity = status == 503
            && response["error"]["code"]
                == json!(forge_backend::ErrorCode::CapacityExceeded.as_str());
        if !is_capacity {
            return Err(format!(
                "unexpected long execution.wait response: {status} {response}"
            ));
        }
        if !retry.load(Ordering::Acquire) {
            return Err(format!(
                "shutdown execution.wait response: {status} {response}"
            ));
        }
        if Instant::now() >= deadline {
            return Err("long execution.wait admission budget expired".to_owned());
        }
        tokio::task::yield_now().await;
    }
}

async fn assert_wait_capacity_exceeded(
    address: SocketAddr,
    authority: &Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let (status, response) =
            post_command(address, "execution.wait", wait_payload(authority, 0, 0)).await?;
        if status == 503 {
            assert_eq!(response["ok"], false);
            assert_eq!(
                response["error"]["code"],
                json!(forge_backend::ErrorCode::CapacityExceeded.as_str())
            );
            return Ok(());
        }
        if status != 200 {
            return Err(
                format!("unexpected second execution.wait response: {status} {response}").into(),
            );
        }
        if Instant::now() >= deadline {
            return Err("execution.wait did not expose its bounded capacity while pending".into());
        }
        tokio::task::yield_now().await;
    }
}

async fn wait_until_wait_slot_released(
    address: SocketAddr,
    authority: &Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let (status, response) =
            post_command(address, "execution.wait", wait_payload(authority, 0, 0)).await?;
        if status == 200 {
            let result = &response["result"];
            assert_eq!(result["state"], "Running");
            assert_eq!(result["timed_out"], true);
            assert_eq!(result["changed"], false);
            return Ok(());
        }
        assert_eq!(status, 503, "wait slot release response: {response}");
        if Instant::now() >= deadline {
            return Err("dropped execution.wait did not release its HTTP permit".into());
        }
        tokio::task::yield_now().await;
    }
}

async fn assert_running_zero_timeout_and_drop(
    address: SocketAddr,
    fixture: &Fixture,
) -> Result<ApprovedShell, Box<dyn std::error::Error>> {
    let mkfifo = Path::new("/usr/bin/mkfifo");
    if !mkfifo.is_file() {
        return Err("/usr/bin/mkfifo is required for the execution wait fixture".into());
    }
    let fifo_name = format!("execution-wait-{}.fifo", Uuid::now_v7());
    let fifo_path = fixture.workspace_root.join(&fifo_name);
    let fifo_status = Command::new(mkfifo).arg(&fifo_path).status()?;
    if !fifo_status.success() {
        return Err(format!("mkfifo failed with status {fifo_status}").into());
    }
    let result = run_running_wait_lifecycle(address, fixture, &fifo_name).await;
    let remove = fs::remove_file(&fifo_path);
    match result {
        Ok(approved) => {
            remove?;
            Ok(approved)
        }
        Err(error) => {
            let _ = remove;
            Err(error)
        }
    }
}

pub(super) async fn assert_http_execution_wait(
    address: SocketAddr,
    approved: &ApprovedShell,
    fixture: &Fixture,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_terminal_and_authority_waits(address, approved, fixture).await
}

pub(super) async fn assert_http_execution_wait_lifecycle(
    state: &forge_backend::http::AppState,
    address: SocketAddr,
    fixture: &Fixture,
) -> Result<(), Box<dyn std::error::Error>> {
    let approved = assert_running_zero_timeout_and_drop(address, fixture).await?;
    let retry = Arc::new(AtomicBool::new(true));
    let pending_payload = wait_payload(&approved.authority, 30_000, 0);
    let pending = tokio::spawn(run_long_wait_until_admitted(
        address,
        pending_payload,
        Arc::clone(&retry),
    ));
    tokio::task::yield_now().await;
    assert_wait_capacity_exceeded(address, &approved.authority).await?;
    if pending.is_finished() {
        let outcome = pending.await.map_err(|error| error.to_string())?;
        return Err(outcome
            .err()
            .unwrap_or_else(|| "shutdown wait completed before shutdown".to_owned())
            .into());
    }

    let report = state.shutdown(Duration::from_secs(5)).await;
    assert!(report.is_successful(), "local backend shutdown: {report:?}");
    retry.store(false, Ordering::Release);
    let joined = tokio::time::timeout(Duration::from_secs(2), pending)
        .await
        .map_err(|_| "pending execution.wait did not resolve after shutdown")?
        .map_err(|error| error.to_string())?;
    match joined {
        Ok(()) => return Err("execution.wait completed successfully during shutdown".into()),
        Err(error)
            if error.starts_with("shutdown execution.wait response:")
                || error.starts_with("connection closed during execution.wait:") => {}
        Err(error) => return Err(format!("unexpected shutdown wait result: {error}").into()),
    }

    let running = fixture
        .client
        .execution_get(fixture.scope.clone(), approved.execution_id)?
        .ok_or("execution disappeared during backend shutdown")?;
    assert_eq!(running.state(), forge_domain::ExecutionState::Running);
    let cancelled = fixture
        .execution
        .client()
        .cancel_agent_execution(approved.authority_request.clone(), approved.execution_id)?;
    assert!(cancelled);
    let terminal = wait_for_execution_state(
        &fixture.client,
        &fixture.scope,
        approved.execution_id,
        forge_domain::ExecutionState::Cancelled,
    )
    .await?;
    assert_eq!(terminal.state(), forge_domain::ExecutionState::Cancelled);
    Ok(())
}
