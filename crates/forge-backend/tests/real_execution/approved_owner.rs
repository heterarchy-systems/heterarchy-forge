//! Real HTTP regression for the preapproved execution owner path.
//!
//! This module deliberately prepares the approval rows through the direct
//! Forge control client.  It does not use `ForgeApprovalCoordinator::submit_execution`,
//! so a successful `execution.begin` proves that the HTTP route acquired the
//! existing owner boundary itself.

use super::*;

use std::fs;

use forge_control::{
    ApprovalActivityScope, ApprovalCreateRequest, ApprovalOnceRequest,
    AutoApprovalScopeCreateRequest,
};
use forge_domain::{
    ApprovalAgentBindingDigest, ApprovalRequestState, AutoApprovalScope, AutoApprovalScopeRevision,
    AutoApprovalScopeState, AutoApprovalUseLimit, ExecutionActionClass, ExecutionAgentProvenance,
    ExecutionAuthorizationRequest, ExecutionPermissions, RequestedExecutionPermissions,
};
use forge_persistence::WorkspaceStore;
use forge_workspace::WorkspaceStateLayout;
use rusqlite::{Connection, OpenFlags};
use serde_json::json;

const RAW_APPROVAL_WINDOW_MILLIS: i64 = 300_000;
const RAW_GRANT_WINDOW_MILLIS: i64 = 60_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct AuthoritySnapshot {
    pub(super) approval_count: i64,
    pub(super) grant_count: i64,
    pub(super) auto_scope_count: i64,
    pub(super) pending_state: ApprovalRequestState,
    pub(super) pending_revision: forge_domain::ApprovalRevision,
    pub(super) unused_grant_state: i64,
    pub(super) unused_grant_revision: forge_domain::ExecutionGrantRevision,
    pub(super) auto_scope_state: AutoApprovalScopeState,
    pub(super) auto_scope_revision: AutoApprovalScopeRevision,
}

fn raw_provenance(
    fixture: &Fixture,
    execution_id: forge_domain::ExecutionId,
    command_id: &forge_domain::ExecutionCommandId,
) -> ExecutionAgentProvenance {
    ExecutionAgentProvenance::new(
        execution_id,
        fixture.agent_id,
        fixture.agent_revision,
        forge_domain::AuthenticatedPrincipal::TrustedStdio,
        fixture.attribution,
        command_id.clone(),
        fixture.session_id,
    )
}

fn raw_authority_request(
    fixture: &Fixture,
    request: &forge_domain::ExecutionRequest,
    command_id: &forge_domain::ExecutionCommandId,
) -> (
    forge_control::AgentExecutionAuthorityRequest,
    ExecutionAuthorizationRequest,
    ExecutionAgentProvenance,
) {
    let authority = forge_control::AgentExecutionAuthorityRequest {
        session_id: fixture.session_id,
        scope: fixture.scope.clone(),
        activity_id: fixture.activity_id,
        agent_id: fixture.agent_id,
        expected_revision: fixture.agent_revision,
        principal: forge_domain::AuthenticatedPrincipal::TrustedStdio,
        attribution: fixture.attribution,
        command_id: command_id.clone(),
    };
    let authorization = ExecutionAuthorizationRequest::new(
        request.id(),
        fixture.scope.workspace_id(),
        fixture.activity_id,
        forge_execution::execution_request_digest(request),
        ExecutionActionClass::AnalyzedShell,
        RequestedExecutionPermissions::new(request.permissions()),
    );
    let provenance = raw_provenance(fixture, request.id(), command_id);
    (authority, authorization, provenance)
}

pub(super) fn raw_pending_shell(
    fixture: &Fixture,
    script: &str,
) -> Result<forge_domain::RegisteredApprovalRequest, Box<dyn std::error::Error>> {
    let analyzed = forge_control::analyze_shell_script(script.to_owned())?;
    let execution_id = forge_domain::ExecutionId::from_uuid(Uuid::now_v7());
    let command_id = analyzed.intent_id().clone();
    let request = super::shell_request(
        execution_id,
        fixture.scope.workspace_id(),
        fixture.activity_id,
        &analyzed,
    )?;
    let (_authority, authorization, provenance) =
        raw_authority_request(fixture, &request, &command_id);
    let observed_at = timestamp_now()?;
    Ok(fixture
        .client
        .create_pending_approval(ApprovalCreateRequest {
            scope: fixture.scope.clone(),
            activity: ApprovalActivityScope {
                activity_id: fixture.activity_id,
                runtime_instance_id: fixture.runtime_instance_id,
                observed_at,
            },
            goal: Some(fixture.attribution.into()),
            approval_id: forge_domain::ApprovalRequestId::from_uuid(Uuid::now_v7()),
            request: authorization,
            agent_binding: Some(ApprovalAgentBindingDigest::from_provenance(&provenance)),
            expires_at: add_millis(observed_at, RAW_APPROVAL_WINDOW_MILLIS)?,
        })?)
}

pub(super) fn raw_approved_shell(
    fixture: &Fixture,
    script: &str,
) -> Result<super::ApprovedShell, Box<dyn std::error::Error>> {
    let analyzed = forge_control::analyze_shell_script(script.to_owned())?;
    let execution_id = forge_domain::ExecutionId::from_uuid(Uuid::now_v7());
    let command_id = analyzed.intent_id().clone();
    let request = super::shell_request(
        execution_id,
        fixture.scope.workspace_id(),
        fixture.activity_id,
        &analyzed,
    )?;
    let (authority_request, authorization, provenance) =
        raw_authority_request(fixture, &request, &command_id);
    let issued_at = timestamp_now()?;
    let pending = fixture
        .client
        .create_pending_approval(ApprovalCreateRequest {
            scope: fixture.scope.clone(),
            activity: ApprovalActivityScope {
                activity_id: fixture.activity_id,
                runtime_instance_id: fixture.runtime_instance_id,
                observed_at: issued_at,
            },
            goal: Some(fixture.attribution.into()),
            approval_id: forge_domain::ApprovalRequestId::from_uuid(Uuid::now_v7()),
            request: authorization,
            agent_binding: Some(ApprovalAgentBindingDigest::from_provenance(&provenance)),
            expires_at: add_millis(issued_at, RAW_APPROVAL_WINDOW_MILLIS)?,
        })?;
    let grant = fixture
        .client
        .approve_once(ApprovalOnceRequest {
            scope: fixture.scope.clone(),
            approval_id: pending.id(),
            expected_revision: pending.revision(),
            grant_id: forge_domain::ExecutionGrantId::from_uuid(Uuid::now_v7()),
            observed_at: add_millis(issued_at, 1)?,
            grant_expires_at: add_millis(issued_at, RAW_GRANT_WINDOW_MILLIS)?,
        })?
        .1;
    Ok(super::ApprovedShell {
        execution_id,
        authority_request,
        authority: super::authority_json(fixture, execution_id, &command_id, issued_at),
        script: script.to_owned(),
        grant,
        issued_at,
        expected_digest: forge_backend::events::hex_encode(
            authorization.request_digest().as_bytes(),
        ),
    })
}

pub(super) fn raw_auto_scope(
    fixture: &Fixture,
    observed_at: TimestampMillis,
) -> Result<AutoApprovalScope, Box<dyn std::error::Error>> {
    let policy = fixture
        .client
        .ensure_workspace_policy(fixture.scope.clone())?;
    let auto_scope = AutoApprovalScope::active(
        forge_domain::AutoApprovalScopeId::from_uuid(Uuid::now_v7()),
        fixture.scope.workspace_id(),
        Some(fixture.activity_id),
        ExecutionActionClass::AnalyzedShell,
        ExecutionPermissions::new(true, true, false),
        policy.revision(),
        add_millis(observed_at, RAW_APPROVAL_WINDOW_MILLIS)?,
        AutoApprovalUseLimit::new(5)?,
        AutoApprovalScopeRevision::INITIAL,
    )?;
    Ok(fixture
        .client
        .create_auto_approval_scope(AutoApprovalScopeCreateRequest {
            scope: fixture.scope.clone(),
            auto_scope,
            created_at: observed_at,
        })?)
}

pub(super) fn authority_snapshot(
    fixture: &Fixture,
    pending: &forge_domain::RegisteredApprovalRequest,
    unused: &super::ApprovedShell,
    auto_scope: &AutoApprovalScope,
) -> Result<AuthoritySnapshot, Box<dyn std::error::Error>> {
    let layout = WorkspaceStateLayout::inspect_existing(&fixture.workspace_root)?
        .ok_or("authority snapshot Workspace layout missing")?;
    let store = WorkspaceStore::open_existing(&layout)?;
    let pending_row = store
        .get_approval_request(pending.id())?
        .ok_or("snapshot pending approval missing")?;
    let current_auto = store
        .get_auto_approval_scope(auto_scope.id())?
        .ok_or("snapshot auto scope missing")?;
    let connection =
        Connection::open_with_flags(layout.database_path(), OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let count = |table: &str| -> Result<i64, rusqlite::Error> {
        connection.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })
    };
    let (unused_state, unused_revision): (i64, i64) = connection.query_row(
        "SELECT state, revision FROM execution_grants WHERE grant_id = ?1",
        [unused.grant.id().into_uuid().as_bytes().as_slice()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    Ok(AuthoritySnapshot {
        approval_count: count("approval_requests")?,
        grant_count: count("execution_grants")?,
        auto_scope_count: count("auto_approval_scopes")?,
        pending_state: pending_row.state(),
        pending_revision: pending_row.revision(),
        unused_grant_state: unused_state,
        unused_grant_revision: forge_domain::ExecutionGrantRevision::new(unused_revision)?,
        auto_scope_state: current_auto.state(),
        auto_scope_revision: current_auto.revision(),
    })
}

pub(super) fn assert_counts_unchanged(
    before: AuthoritySnapshot,
    after: AuthoritySnapshot,
) -> Result<(), Box<dyn std::error::Error>> {
    ensure_equal(
        "approval row count",
        &(after.approval_count),
        &(before.approval_count),
    )?;
    ensure_equal(
        "grant row count",
        &(after.grant_count),
        &(before.grant_count),
    )?;
    ensure_equal(
        "auto scope row count",
        &(after.auto_scope_count),
        &(before.auto_scope_count),
    )?;
    Ok(())
}

pub(super) fn read_cancelled_output(
    fixture: &Fixture,
    approved: &super::ApprovedShell,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let layout = WorkspaceStateLayout::inspect_existing(&fixture.workspace_root)?
        .ok_or("cancelled output Workspace layout missing")?;
    let store = WorkspaceStore::open_existing(&layout)?;
    let read = store.read_execution_output_events(
        forge_domain::ExecutionOutputCursor::initial(approved.execution_id),
        forge_domain::MAX_EXECUTION_OUTPUT_READ_BYTES,
        forge_domain::MAX_EXECUTION_OUTPUT_READ_EVENTS,
    )?;
    let record = store
        .get_execution(approved.execution_id)?
        .ok_or("cancelled execution disappeared")?;
    if record.state() != forge_domain::ExecutionState::Cancelled {
        return Err(format!("execution reached {:?}, expected Cancelled", record.state()).into());
    }
    let mut output = Vec::new();
    for event in read.events() {
        let forge_domain::ExecutionOutputEvent::Chunk(chunk) = event else {
            return Err("cancelled output contained an unexpected gap".into());
        };
        output.extend_from_slice(chunk.bytes());
    }
    Ok(output)
}

pub(super) async fn wait_for_durable_prefix(
    fixture: &Fixture,
    execution_id: forge_domain::ExecutionId,
    expected: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let layout = WorkspaceStateLayout::inspect_existing(&fixture.workspace_root)?
            .ok_or("durable prefix Workspace layout missing")?;
        let store = WorkspaceStore::open_existing(&layout)?;
        let read = store.read_execution_output_events(
            forge_domain::ExecutionOutputCursor::initial(execution_id),
            forge_domain::MAX_EXECUTION_OUTPUT_READ_BYTES,
            forge_domain::MAX_EXECUTION_OUTPUT_READ_EVENTS,
        )?;
        let mut bytes = Vec::new();
        for event in read.events() {
            let forge_domain::ExecutionOutputEvent::Chunk(chunk) = event else {
                return Err("durable prefix contained an unexpected gap".into());
            };
            bytes.extend_from_slice(chunk.bytes());
        }
        if bytes.starts_with(expected) {
            return Ok(bytes);
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "durable output did not reach expected prefix {expected:?}; observed {bytes:?}"
            )
            .into());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn ensure_equal<T>(label: &str, actual: &T, expected: &T) -> Result<(), Box<dyn std::error::Error>>
where
    T: std::fmt::Debug + PartialEq,
{
    if actual == expected {
        Ok(())
    } else {
        Err(format!("{label}: observed {actual:?}, expected {expected:?}").into())
    }
}

fn ensure_true(label: &str, value: bool) -> Result<(), Box<dyn std::error::Error>> {
    if value {
        Ok(())
    } else {
        Err(label.to_owned().into())
    }
}

pub(super) async fn disable_owner_location(
    fixture: &Fixture,
    address: SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    let location = fixture
        .client
        .location_list()?
        .into_iter()
        .find(|candidate| candidate.id() == fixture.scope.locator().location_id())
        .ok_or("approved-owner Location missing")?;
    let disabled = post_command(
        address,
        "location.state",
        json!({
            "location_id": location.id().into_uuid(),
            "expected_revision": location.revision().get(),
            "state": "disabled",
            "observed_at_ms": timestamp_now()?.get(),
        }),
    )
    .await?;
    ensure_equal("Location disable HTTP status", &(disabled.0), &(200_u16))?;
    ensure_equal(
        "Location disable state",
        &(disabled.1["result"]["state"]),
        &(json!("disabled")),
    )?;

    Ok(())
}

fn ensure_unconsumed_authority_unchanged(
    before: AuthoritySnapshot,
    after_begin: AuthoritySnapshot,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_counts_unchanged(before, after_begin)?;
    ensure_equal(
        "pending state before stop",
        &(after_begin.pending_state),
        &(before.pending_state),
    )?;
    ensure_equal(
        "pending revision before stop",
        &(after_begin.pending_revision),
        &(before.pending_revision),
    )?;
    ensure_equal(
        "unused grant state before stop",
        &(after_begin.unused_grant_state),
        &(before.unused_grant_state),
    )?;
    ensure_equal(
        "unused grant revision before stop",
        &(after_begin.unused_grant_revision),
        &(before.unused_grant_revision),
    )?;
    ensure_equal(
        "auto scope state before stop",
        &(after_begin.auto_scope_state),
        &(before.auto_scope_state),
    )?;
    ensure_equal(
        "auto scope revision before stop",
        &(after_begin.auto_scope_revision),
        &(before.auto_scope_revision),
    )?;

    Ok(())
}

async fn run_preapproved_owner_flow(
    fixture: &Fixture,
    address: SocketAddr,
    approved: &super::ApprovedShell,
    pending: &forge_domain::RegisteredApprovalRequest,
    unused: &super::ApprovedShell,
    auto_scope: &AutoApprovalScope,
    before: AuthoritySnapshot,
) -> Result<(), Box<dyn std::error::Error>> {
    let preflight = fixture
        .approval
        .client()
        .stop_workspace(fixture.scope.workspace_id())?;
    ensure_equal("preflight owned stop count", &(preflight), &(0_usize))?;
    let after_preflight = authority_snapshot(fixture, pending, unused, auto_scope)?;
    ensure_equal(
        "preflight authority snapshot",
        &(after_preflight),
        &(before),
    )?;

    let begin = post_command(
        address,
        "execution.begin",
        execution_begin_payload(approved),
    )
    .await?;
    ensure_equal("preapproved begin HTTP status", &(begin.0), &(200_u16))?;
    ensure_equal("preapproved begin result", &(begin.1["ok"]), &(json!(true)))?;
    let _running = wait_for_execution_state(
        &fixture.client,
        &fixture.scope,
        approved.execution_id,
        forge_domain::ExecutionState::Running,
    )
    .await?;

    let durable_prefix =
        wait_for_durable_prefix(fixture, approved.execution_id, b"pre-stop\n").await?;
    ensure_true(
        "durable stdout did not retain the expected prefix",
        durable_prefix.starts_with(b"pre-stop\n"),
    )?;

    let after_begin = authority_snapshot(fixture, pending, unused, auto_scope)?;
    ensure_unconsumed_authority_unchanged(before, after_begin)?;

    disable_owner_location(fixture, address).await?;

    let stopped = fixture
        .approval
        .client()
        .stop_workspace(fixture.scope.workspace_id())?;
    ensure_true("owner stop did not request the running child", stopped > 0)?;
    let output = read_cancelled_output(fixture, approved)?;
    ensure_equal(
        "cancelled durable stdout",
        &(output),
        &(b"pre-stop\n".to_vec()),
    )?;

    let after_stop = authority_snapshot(fixture, pending, unused, auto_scope)?;
    assert_counts_unchanged(before, after_stop)?;
    ensure_equal(
        "pending state after stop",
        &(after_stop.pending_state),
        &(ApprovalRequestState::Cancelled),
    )?;
    ensure_equal(
        "pending revision after stop",
        &(after_stop.pending_revision),
        &(before.pending_revision.checked_next()?),
    )?;
    ensure_equal(
        "unused grant state after stop",
        &(after_stop.unused_grant_state),
        &(2_i64),
    )?;
    ensure_equal(
        "unused grant revision after stop",
        &(after_stop.unused_grant_revision),
        &(before.unused_grant_revision.checked_next()?),
    )?;
    ensure_equal(
        "auto scope state after stop",
        &(after_stop.auto_scope_state),
        &(AutoApprovalScopeState::Revoked),
    )?;
    ensure_equal(
        "auto scope revision after stop",
        &(after_stop.auto_scope_revision),
        &(before.auto_scope_revision.checked_next()?),
    )?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_http_preapproved_begin_acquires_owned_cleanup_without_reissuing_authority()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = prepare_fixture()?;
    let unused = raw_approved_shell(&fixture, "printf 'unused-grant\\n'")?;
    let pending = raw_pending_shell(&fixture, "printf 'pending-only\\n'")?;
    let auto_scope = raw_auto_scope(&fixture, timestamp_now()?)?;
    let fifo_name = format!("approved-owner-{}.fifo", Uuid::now_v7());
    let fifo_path = fixture.workspace_root.join(&fifo_name);
    let status = std::process::Command::new("/usr/bin/mkfifo")
        .arg(&fifo_path)
        .status()?;
    if !status.success() {
        return Err(format!("mkfifo failed with status {status}").into());
    }
    let approved = raw_approved_shell(
        &fixture,
        &format!("printf 'pre-stop\\n'; cat < {fifo_name}"),
    )?;
    let before = authority_snapshot(&fixture, &pending, &unused, &auto_scope)?;
    let cache = fixture.root.join("approved-owner-cache");
    fs::create_dir(&cache)?;
    let state = assemble_fixture(
        backend_config()?,
        &fixture,
        &cache,
        delegated_destination_id(&fixture)?,
    )?;
    let address = serve(state.clone()).await?;
    let flow = run_preapproved_owner_flow(
        &fixture,
        address,
        &approved,
        &pending,
        &unused,
        &auto_scope,
        before,
    )
    .await;

    let http_shutdown = state.shutdown(Duration::from_secs(5)).await;
    let owner_shutdown = super::admitted_journal::shutdown_disabled_fixture(fixture);
    let mut failures = Vec::new();
    if let Err(error) = flow {
        failures.push(format!("flow: {error}"));
    }
    if let Err(error) = owner_shutdown {
        failures.push(format!("owner shutdown: {error}"));
    }
    if !http_shutdown.is_successful() {
        failures.push("HTTP shutdown was incomplete".to_owned());
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; ").into())
    }
}

async fn run_closed_session_flow(
    fixture: &Fixture,
    address: SocketAddr,
    approved: &super::ApprovedShell,
    pending: &forge_domain::RegisteredApprovalRequest,
    auto_scope: &AutoApprovalScope,
    before: AuthoritySnapshot,
) -> Result<(), Box<dyn std::error::Error>> {
    let begin = post_command(
        address,
        "execution.begin",
        execution_begin_payload(approved),
    )
    .await?;
    ensure_true(
        "closed-session begin unexpectedly succeeded",
        begin.0 != 200,
    )?;
    ensure_equal(
        "closed-session begin result",
        &(begin.1["ok"]),
        &(json!(false)),
    )?;
    let stopped = fixture
        .approval
        .client()
        .stop_workspace(fixture.scope.workspace_id())?;
    ensure_equal("closed-session owner stop count", &(stopped), &(0_usize))?;
    let layout = WorkspaceStateLayout::inspect_existing(&fixture.workspace_root)?
        .ok_or("closed-session Workspace layout missing")?;
    let store = WorkspaceStore::open_existing(&layout)?;
    ensure_true(
        "closed-session request created an execution row",
        store.get_execution(approved.execution_id)?.is_none(),
    )?;
    drop(store);
    let after = authority_snapshot(fixture, pending, approved, auto_scope)?;
    ensure_equal("closed-session authority snapshot", &(after), &(before))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_http_preapproved_begin_closed_session_rejects_before_owner_attach()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = prepare_fixture()?;
    let approved = raw_approved_shell(&fixture, "printf 'closed-session\\n'")?;
    let pending = raw_pending_shell(&fixture, "printf 'closed-pending\\n'")?;
    let auto_scope = raw_auto_scope(&fixture, timestamp_now()?)?;
    let before = authority_snapshot(&fixture, &pending, &approved, &auto_scope)?;
    close_fixture_session(&fixture)?;

    let cache = fixture.root.join("closed-session-cache");
    fs::create_dir(&cache)?;
    let state = assemble_fixture(
        backend_config()?,
        &fixture,
        &cache,
        delegated_destination_id(&fixture)?,
    )?;
    let address = serve(state.clone()).await?;
    let flow =
        run_closed_session_flow(&fixture, address, &approved, &pending, &auto_scope, before).await;

    let http_shutdown = state.shutdown(Duration::from_secs(5)).await;
    let owner_shutdown = super::admitted_journal::shutdown_disabled_fixture(fixture);
    let mut failures = Vec::new();
    if let Err(error) = flow {
        failures.push(format!("flow: {error}"));
    }
    if let Err(error) = owner_shutdown {
        failures.push(format!("owner shutdown: {error}"));
    }
    if !http_shutdown.is_successful() {
        failures.push("HTTP shutdown was incomplete".to_owned());
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; ").into())
    }
}
