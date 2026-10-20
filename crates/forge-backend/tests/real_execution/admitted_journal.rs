//! Regression proof for durable execution completion after Location disable.

use super::*;

use forge_domain::{ExecutionOutputCursor, ExecutionOutputEvent, LocationState};
use forge_persistence::WorkspaceStore;
use forge_workspace::WorkspaceStateLayout;
use serde_json::json;
use std::fs::OpenOptions;
use std::io::Write;

async fn wait_durable_execution(
    fixture: &Fixture,
    execution_id: forge_domain::ExecutionId,
) -> Result<
    (
        forge_domain::RegisteredExecution,
        forge_domain::ExecutionOutputRead,
    ),
    Box<dyn std::error::Error>,
> {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let layout = WorkspaceStateLayout::inspect_existing(&fixture.workspace_root)?
            .ok_or("Workspace layout missing during durable execution read")?;
        let store = WorkspaceStore::open_existing(&layout)?;
        let execution = store
            .get_execution(execution_id)?
            .ok_or("durable execution row missing")?;
        let output = store.read_execution_output_events(
            ExecutionOutputCursor::initial(execution_id),
            forge_domain::MIN_EXECUTION_OUTPUT_READ_BYTES,
            forge_domain::MAX_EXECUTION_OUTPUT_READ_EVENTS,
        )?;
        if execution.state().is_terminal() {
            if output.events().is_empty() {
                return Err("terminal execution has no durable output prefix".into());
            }
            return Ok((execution, output));
        }
        if Instant::now() >= deadline {
            return Err("durable execution did not reach terminal output state".into());
        }
        tokio::task::yield_now().await;
    }
}

struct DisabledStopProof {
    execution_id: forge_domain::ExecutionId,
    record: forge_domain::RegisteredExecution,
    output: forge_domain::ExecutionOutputRead,
    stopped: usize,
}

async fn wait_for_stop_prefix(
    fixture: &Fixture,
    execution_id: forge_domain::ExecutionId,
) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let layout = WorkspaceStateLayout::inspect_existing(&fixture.workspace_root)?
            .ok_or("stop fixture layout missing")?;
        let store = WorkspaceStore::open_existing(&layout)?;
        let output = store.read_execution_output_events(
            ExecutionOutputCursor::initial(execution_id),
            forge_domain::MIN_EXECUTION_OUTPUT_READ_BYTES,
            4,
        )?;
        let bytes: Vec<_> = output
            .events()
            .iter()
            .filter_map(|event| match event {
                ExecutionOutputEvent::Chunk(chunk) => Some(chunk.bytes()),
                ExecutionOutputEvent::Gap(_) => None,
            })
            .flatten()
            .copied()
            .collect();
        if bytes == b"stop-phase-ready\n" {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("real child durable pre-stop prefix missing".into());
        }
        tokio::task::yield_now().await;
    }
}

async fn stop_disabled_running_child(
    fixture: &Fixture,
    address: SocketAddr,
) -> Result<DisabledStopProof, Box<dyn std::error::Error>> {
    let fifo_name = format!("stop-phase-{}.fifo", Uuid::now_v7());
    let status = std::process::Command::new("/usr/bin/mkfifo")
        .arg(fixture.workspace_root.join(&fifo_name))
        .status()?;
    if !status.success() {
        return Err("stop fixture FIFO creation failed".into());
    }
    let approved = super::prepare_approved_shell_for_script(
        fixture,
        &format!("printf 'stop-phase-ready\\n'; cat < {fifo_name}"),
    )?;
    let (status, response) = super::post_command(
        address,
        "execution.begin",
        super::execution_begin_payload(&approved),
    )
    .await?;
    if status != 200 || response["ok"] != true {
        return Err(format!("stop fixture HTTP admission failed: {response}").into());
    }
    wait_for_stop_prefix(fixture, approved.execution_id).await?;
    let location = fixture
        .client
        .location_list()?
        .into_iter()
        .find(|location| location.id() == fixture.scope.locator().location_id())
        .ok_or("stop fixture Location missing")?;
    let (status, response) = super::post_command(
        address,
        "location.state",
        json!({
            "location_id": location.id().into_uuid(),
            "expected_revision": location.revision().get(),
            "state": "disabled", "observed_at_ms": timestamp_now()?.get(),
        }),
    )
    .await?;
    if status != 200 || response["result"]["state"] != "disabled" {
        return Err(format!("stop fixture disable failed: {response}").into());
    }
    let stopped = fixture
        .approval
        .client()
        .stop_workspace(fixture.scope.workspace_id())?;
    let layout = WorkspaceStateLayout::inspect_existing(&fixture.workspace_root)?
        .ok_or("stop fixture layout disappeared")?;
    let store = WorkspaceStore::open_existing(&layout)?;
    let record = store
        .get_execution(approved.execution_id)?
        .ok_or("stop fixture execution missing")?;
    let output = store.read_execution_output_events(
        ExecutionOutputCursor::initial(approved.execution_id),
        forge_domain::MAX_EXECUTION_OUTPUT_READ_BYTES,
        forge_domain::MAX_EXECUTION_OUTPUT_READ_EVENTS,
    )?;
    Ok(DisabledStopProof {
        execution_id: approved.execution_id,
        record,
        output,
        stopped,
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_http_admitted_child_is_cancelled_and_journaled_despite_disabled_approval_cleanup()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = prepare_fixture()?;
    let cache = fixture.root.join("stop-phase-cache");
    fs::create_dir(&cache)?;
    let state = super::assemble_fixture(
        backend_config()?,
        &fixture,
        &cache,
        delegated_destination_id(&fixture)?,
    )?;
    let address = serve(state.clone()).await?;
    let proof = stop_disabled_running_child(&fixture, address).await;
    let http_shutdown = state.shutdown(Duration::from_secs(5)).await;
    let owner_shutdown = shutdown_disabled_fixture(fixture);
    let proof = proof?;
    owner_shutdown?;
    assert!(http_shutdown.is_successful());
    assert!(proof.stopped > 0);
    assert_eq!(proof.record.id(), proof.execution_id);
    assert!(
        proof.record.state().is_terminal(),
        "cleanup error left the actual child unjournaled"
    );
    assert_eq!(
        proof
            .record
            .outcome()
            .map(forge_domain::ExecutionOutcome::status),
        Some(forge_domain::ExecutionCompletionStatus::Cancelled)
    );
    let bytes: Vec<_> = proof
        .output
        .events()
        .iter()
        .filter_map(|event| match event {
            ExecutionOutputEvent::Chunk(chunk) => Some(chunk.bytes()),
            ExecutionOutputEvent::Gap(_) => None,
        })
        .flatten()
        .copied()
        .collect();
    assert_eq!(bytes, b"stop-phase-ready\n");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_http_disabled_stop_cleans_pending_grant_and_auto_scope()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = prepare_fixture()?;
    let result = disabled_stop_authority_flow(&fixture).await;
    let shutdown = shutdown_disabled_fixture(fixture);
    match (result, shutdown) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(format!("authority flow: {error}").into()),
        (Ok(()), Err(error)) => Err(format!("owner shutdown: {error}").into()),
        (Err(flow), Err(shutdown)) => {
            Err(format!("authority flow: {flow}; owner shutdown: {shutdown}").into())
        }
    }
}

#[test]
fn list_only_observer_cannot_acquire_cleanup_authority() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = prepare_fixture()?;
    let result = list_only_cleanup_flow(&fixture);
    let shutdown = shutdown_disabled_fixture(fixture);
    match (result, shutdown) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(flow), Err(shutdown)) => {
            Err(format!("list-only: {flow}; shutdown: {shutdown}").into())
        }
    }
}

fn list_only_cleanup_flow(fixture: &Fixture) -> Result<(), Box<dyn std::error::Error>> {
    let layout = WorkspaceStateLayout::inspect_existing(&fixture.workspace_root)?
        .ok_or("list-only Workspace layout missing")?;
    let mut store = WorkspaceStore::open_existing(&layout)?;
    let now = timestamp_now()?;
    let policy = store.ensure_workspace_policy(now)?;
    let pending = forge_domain::RegisteredApprovalRequest::pending(
        forge_domain::ApprovalRequestId::from_uuid(Uuid::now_v7()),
        forge_domain::ExecutionAuthorizationRequest::new(
            ExecutionId::from_uuid(Uuid::now_v7()),
            fixture.scope.workspace_id(),
            fixture.activity_id,
            forge_domain::ExecutionRequestDigest::from_bytes([0xC1; 32]),
            forge_domain::ExecutionActionClass::DirectStructured,
            forge_domain::RequestedExecutionPermissions::new(
                forge_domain::ExecutionPermissions::new(false, false, false),
            ),
        ),
        policy.revision(),
        now,
        add_millis(now, 60_000)?,
    )?;
    let _inserted = store.insert_pending_approval(&pending)?;
    drop(store);
    let listed = fixture
        .approval
        .client()
        .list_pending(fixture.scope.clone())?;
    assert_eq!(listed.len(), 1);
    let stopped = fixture.approval.client().stop_owned()?;
    assert_eq!(stopped.pending_cancelled(), 0);
    assert_eq!(stopped.executions_cancelled(), 0);
    let store = WorkspaceStore::open_existing(&layout)?;
    let after = store
        .get_approval_request(pending.id())?
        .ok_or("list-only pending missing")?;
    assert_eq!(after, pending);
    Ok(())
}

async fn disabled_stop_authority_flow(fixture: &Fixture) -> Result<(), Box<dyn std::error::Error>> {
    let unused = super::prepare_approved_shell_for_script(fixture, "printf 'unused-grant\\n'")?;
    let analyzed = forge_control::analyze_shell_script("printf 'pending-cleanup\\n'".to_owned())?;
    let request = super::shell_request(
        ExecutionId::from_uuid(Uuid::now_v7()),
        fixture.scope.workspace_id(),
        fixture.activity_id,
        &analyzed,
    )?;
    let submission = fixture.approval.client().submit_execution(
        SubmitExecutionForApproval::analyzed_shell(
            fixture.scope.clone(),
            fixture.activity_id,
            fixture.runtime_instance_id,
            request,
        )?
        .with_goal_node(fixture.attribution)
        .with_agent_authority(AgentExecutionAuthorityRequest {
            session_id: fixture.session_id,
            scope: fixture.scope.clone(),
            activity_id: fixture.activity_id,
            agent_id: fixture.agent_id,
            expected_revision: fixture.agent_revision,
            principal: AuthenticatedPrincipal::TrustedStdio,
            attribution: fixture.attribution,
            command_id: analyzed.intent_id().clone(),
        }),
    )?;
    assert_eq!(submission.status(), ApprovalSubmissionStatus::Pending);
    let pending = fixture
        .client
        .approval_get(fixture.scope.clone(), submission.approval_id())?
        .ok_or("cleanup pending approval missing")?
        .0;
    let policy = fixture
        .client
        .ensure_workspace_policy(fixture.scope.clone())?;
    let created_at = timestamp_now()?;
    let auto_scope = fixture.approval.client().register_auto_scope(
        forge_control::AutoApprovalScopeCreateRequest {
            scope: fixture.scope.clone(),
            auto_scope: forge_domain::AutoApprovalScope::active(
                forge_domain::AutoApprovalScopeId::from_uuid(Uuid::now_v7()),
                fixture.scope.workspace_id(),
                None,
                forge_domain::ExecutionActionClass::DiscoveredProjectCommand,
                forge_domain::ExecutionPermissions::new(true, false, false),
                policy.revision(),
                add_millis(created_at, 60_000)?,
                forge_domain::AutoApprovalUseLimit::new(5)?,
                forge_domain::AutoApprovalScopeRevision::INITIAL,
            )?,
            created_at,
        },
    )?;
    let cache = fixture.root.join("stop-authority-cache");
    fs::create_dir(&cache)?;
    let state = super::assemble_fixture(
        backend_config()?,
        fixture,
        &cache,
        delegated_destination_id(fixture)?,
    )?;
    let address = serve(state.clone()).await?;
    let proof = stop_disabled_running_child(fixture, address).await;
    let http_shutdown = state.shutdown(Duration::from_secs(5)).await;
    let proof = proof?;
    assert!(http_shutdown.is_successful());
    assert!(proof.stopped > 0);
    assert_eq!(
        proof.record.state(),
        forge_domain::ExecutionState::Cancelled
    );
    assert_durable_authority_cleanup(fixture, &pending, &unused.grant, &auto_scope)
}

fn assert_durable_authority_cleanup(
    fixture: &Fixture,
    pending: &forge_domain::RegisteredApprovalRequest,
    grant: &forge_domain::ExecutionGrant,
    auto_scope: &forge_domain::AutoApprovalScope,
) -> Result<(), Box<dyn std::error::Error>> {
    let layout = WorkspaceStateLayout::inspect_existing(&fixture.workspace_root)?
        .ok_or("cleanup Workspace layout missing")?;
    let store = WorkspaceStore::open_existing(&layout)?;
    let after_pending = store
        .get_approval_request(pending.id())?
        .ok_or("cleanup pending row disappeared")?;
    assert_eq!(
        after_pending.state(),
        forge_domain::ApprovalRequestState::Cancelled
    );
    assert_eq!(after_pending.revision(), pending.revision().checked_next()?);
    let after_scope = store
        .get_auto_approval_scope(auto_scope.id())?
        .ok_or("cleanup AutoScope row disappeared")?;
    assert_eq!(
        after_scope.state(),
        forge_domain::AutoApprovalScopeState::Revoked
    );
    assert_eq!(
        after_scope.revision(),
        auto_scope.revision().checked_next()?
    );
    let connection = rusqlite::Connection::open_with_flags(
        layout.database_path(),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let (grant_state, grant_revision): (i64, i64) = connection.query_row(
        "SELECT state, revision FROM execution_grants WHERE grant_id = ?1",
        [grant.id().into_uuid().as_bytes().as_slice()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    // The existing Workspace schema encodes ExecutionGrantState::Revoked as 2.
    assert_eq!(grant_state, 2);
    assert_eq!(grant_revision, grant.revision().checked_next()?.get());
    assert_eq!(
        store
            .prepare_approval_cleanup(
                forge_persistence::ApprovalCleanupSelector::Workspace,
                timestamp_now()?,
                forge_domain::ExecutionListLimit::new(256)?
            )?
            .report()
            .total(),
        0
    );
    Ok(())
}

pub(super) fn shutdown_disabled_fixture(
    fixture: Fixture,
) -> Result<(), Box<dyn std::error::Error>> {
    shutdown_disabled_fixture_owned(fixture)
}

fn shutdown_disabled_fixture_owned(fixture: Fixture) -> Result<(), Box<dyn std::error::Error>> {
    let Fixture {
        root,
        mut worker,
        mut lease_worker,
        mut execution,
        mut approval,
        ..
    } = fixture;
    let approval_result = approval.shutdown();
    let execution_result = execution.shutdown();
    let worker_result = worker.shutdown();
    let lease_result = lease_worker.shutdown();
    let _approval_report = approval_result?;
    let _execution_report = execution_result?;
    worker_result?;
    lease_result?;
    fs::remove_dir_all(root)?;
    Ok(())
}

async fn finish_fifo_execution_after_disable(
    fixture: &Fixture,
    fifo_path: std::path::PathBuf,
    execution_id: forge_domain::ExecutionId,
    location_id: Uuid,
    expected_state: forge_domain::ExecutionState,
    expected_exit_code: Option<i32>,
    expected_stderr: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let writer = std::thread::spawn(move || -> Result<(), String> {
        let mut file = OpenOptions::new()
            .write(true)
            .open(fifo_path)
            .map_err(|error| format!("FIFO writer open failed: {error}"))?;
        file.write_all(b"backend-http-execution\n")
            .map_err(|error| format!("FIFO writer failed: {error}"))
    });
    writer.join().map_err(|_| "FIFO writer thread panicked")??;
    let (execution, output) = wait_durable_execution(fixture, execution_id).await?;
    assert_eq!(execution.state(), expected_state);
    assert_eq!(
        execution
            .outcome()
            .and_then(forge_domain::ExecutionOutcome::exit_code),
        expected_exit_code
    );
    let mut stdout_bytes = Vec::new();
    let mut stderr_bytes = Vec::new();
    for event in output.events() {
        let ExecutionOutputEvent::Chunk(chunk) = event else {
            return Err("durable execution output contained an unexpected gap".into());
        };
        match chunk.stream() {
            forge_domain::ExecutionOutputStream::Stdout => {
                stdout_bytes.extend_from_slice(chunk.bytes());
            }
            forge_domain::ExecutionOutputStream::Stderr => {
                stderr_bytes.extend_from_slice(chunk.bytes());
            }
        }
    }
    assert_eq!(stdout_bytes, b"backend-http-execution\n");
    let stderr = String::from_utf8(stderr_bytes)?;
    if let Some(expected_stderr) = expected_stderr {
        assert!(stderr.contains(expected_stderr), "stderr: {stderr}");
    } else {
        assert!(stderr.is_empty(), "unexpected stderr: {stderr}");
    }
    let current_location = fixture
        .client
        .location_list()?
        .into_iter()
        .find(|candidate| candidate.id().into_uuid() == location_id)
        .ok_or("fixture Location missing after disable")?;
    assert_eq!(current_location.state(), LocationState::Disabled);
    Ok(())
}

async fn assert_new_execution_refused_after_location_disable(
    address: SocketAddr,
    fixture: &Fixture,
    refused: &super::ApprovedShell,
) -> Result<(), Box<dyn std::error::Error>> {
    let (status, response) = super::post_command(
        address,
        "execution.begin",
        super::execution_begin_payload(refused),
    )
    .await?;
    assert_eq!(
        status, 409,
        "new execution after Location disable: {response}"
    );
    assert_eq!(response["error"]["code"], "STALE_REVISION");
    let layout = WorkspaceStateLayout::inspect_existing(&fixture.workspace_root)?
        .ok_or("Workspace layout missing after Location disable")?;
    let store = WorkspaceStore::open_existing(&layout)?;
    assert!(store.get_execution(refused.execution_id)?.is_none());
    Ok(())
}

async fn run_location_disabled_journal(
    script_suffix: &str,
    expected_state: forge_domain::ExecutionState,
    expected_exit_code: Option<i32>,
    expected_stderr: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mkfifo = std::path::Path::new("/usr/bin/mkfifo");
    if !mkfifo.is_file() {
        return Err("/usr/bin/mkfifo is required for the journal fixture".into());
    }
    let fixture = prepare_fixture()?;
    let product_cache_root = fixture.root.join("product-cache-admitted-journal");
    fs::create_dir_all(&product_cache_root)?;
    let state = super::assemble_fixture(
        backend_config()?,
        &fixture,
        &product_cache_root,
        delegated_destination_id(&fixture)?,
    )?;
    let address = serve(state.clone()).await?;
    let fifo_name = format!("admitted-journal-{}.fifo", Uuid::now_v7());
    let fifo_path = fixture.workspace_root.join(&fifo_name);
    let fifo_status = std::process::Command::new(mkfifo)
        .arg(&fifo_path)
        .status()?;
    if !fifo_status.success() {
        return Err(format!("mkfifo failed with status {fifo_status}").into());
    }
    let approved = super::prepare_approved_shell_for_script(
        &fixture,
        &format!("cat < {fifo_name}{script_suffix}"),
    )?;
    let refused = super::prepare_approved_shell_for_script(&fixture, "printf 'must-not-start\\n'")?;
    let (status, begin) = super::post_command(
        address,
        "execution.begin",
        super::execution_begin_payload(&approved),
    )
    .await?;
    assert_eq!(status, 200, "execution.begin response: {begin}");
    assert_eq!(begin["ok"], true);
    let _running = super::wait_for_execution_state(
        &fixture.client,
        &fixture.scope,
        approved.execution_id,
        forge_domain::ExecutionState::Running,
    )
    .await?;

    let location_id = fixture.scope.locator().location_id().into_uuid();
    let location = fixture
        .client
        .location_list()?
        .into_iter()
        .find(|location| location.id().into_uuid() == location_id)
        .ok_or("fixture Location missing before disable")?;
    let (status, disabled) = super::post_command(
        address,
        "location.state",
        json!({
            "location_id": location_id,
            "expected_revision": location.revision().get(),
            "state": "disabled",
            "observed_at_ms": timestamp_now()?.get(),
        }),
    )
    .await?;
    assert_eq!(status, 200, "Location disable response: {disabled}");
    assert_eq!(disabled["result"]["state"], "disabled");

    assert_new_execution_refused_after_location_disable(address, &fixture, &refused).await?;

    finish_fifo_execution_after_disable(
        &fixture,
        fifo_path,
        approved.execution_id,
        location_id,
        expected_state,
        expected_exit_code,
        expected_stderr,
    )
    .await?;
    let shutdown = state.shutdown(Duration::from_secs(5)).await;
    assert!(
        shutdown.is_successful(),
        "backend shutdown did not complete"
    );
    shutdown_disabled_fixture(fixture)?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_http_execution_survives_location_disable_and_retains_output()
-> Result<(), Box<dyn std::error::Error>> {
    run_location_disabled_journal("", forge_domain::ExecutionState::Completed, Some(0), None).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_http_failed_execution_after_location_disable_retains_exit_and_output()
-> Result<(), Box<dyn std::error::Error>> {
    run_location_disabled_journal(
        " - missing-admitted-journal-input",
        forge_domain::ExecutionState::Failed,
        Some(1),
        Some("missing-admitted-journal-input"),
    )
    .await
}
