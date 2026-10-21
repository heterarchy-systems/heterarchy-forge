//! Real HTTP approval mutation and exact local grant readback.

use super::lease_readback::scope_json;
use super::*;
use forge_domain::ExecutionGrantState;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_http_local_approval_grant_readback_stays_separate_from_execution()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = prepare_fixture()?;
    let pending = approved_owner::raw_pending_shell(&fixture, SCRIPT)?;
    let cache = fixture.root.join("approval-projection-cache");
    fs::create_dir(&cache)?;
    let state = assemble_fixture(
        backend_config()?,
        &fixture,
        &cache,
        delegated_destination_id(&fixture)?,
    )?;
    let address = serve(state.clone()).await?;
    assert_http_reject(&fixture, address).await?;
    let issued_at = timestamp_now()?;
    let approved = approve_and_readback(&fixture, address, &pending, issued_at).await?;
    assert_execution_replay_fences(address, &fixture, &pending, &approved).await?;
    let shutdown = state.shutdown(Duration::from_secs(5)).await;
    assert!(
        shutdown.is_successful(),
        "backend shutdown did not complete"
    );
    fixture.shutdown()?;
    Ok(())
}

async fn assert_http_reject(
    fixture: &Fixture,
    address: SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    let rejected = approved_owner::raw_pending_shell(fixture, "printf 'reject-me\\n'")?;
    let (status, response) = post_command(
        address,
        "approval.reject",
        json!({
            "scope": scope_json(fixture),
            "approval_id": rejected.id().into_uuid(),
            "expected_revision": rejected.revision().get(),
            "observed_at_ms": timestamp_now()?.get(),
        }),
    )
    .await?;
    assert_eq!(status, 200, "approval.reject: {response}");
    assert_eq!(response["result"]["state"], "rejected");
    assert_eq!(response["result"]["grant"], Value::Null);
    let readback = fixture
        .client
        .approval_get_with_grant(fixture.scope.clone(), rejected.id())?
        .ok_or("rejected approval readback missing")?;
    assert_eq!(
        readback.0.state(),
        forge_domain::ApprovalRequestState::Rejected
    );
    assert!(readback.2.is_none());
    Ok(())
}

async fn approve_and_readback(
    fixture: &Fixture,
    address: SocketAddr,
    pending: &forge_domain::RegisteredApprovalRequest,
    issued_at: TimestampMillis,
) -> Result<ApprovedShell, Box<dyn std::error::Error>> {
    let grant_id = Uuid::now_v7();
    let (status, response) = post_command(
        address,
        "approval.approve_once",
        json!({
            "scope": scope_json(fixture),
            "approval_id": pending.id().into_uuid(),
            "expected_revision": pending.revision().get(),
            "grant_id": grant_id,
            "observed_at_ms": issued_at.get(),
            "grant_expires_at_ms": add_millis(issued_at, 60_000)?.get(),
        }),
    )
    .await?;
    assert_eq!(status, 200, "approval.approve_once: {response}");
    assert_eq!(response["ok"], true);
    assert_eq!(response["result"]["state"], "approved");
    assert_eq!(response["result"]["execution"], Value::Null);
    assert_eq!(response["result"]["grant"]["grant_id"], json!(grant_id));
    assert_eq!(response["result"]["grant"]["state"], "active");
    assert_eq!(response["result"]["grant"]["revision"], 1);
    let expected_digest =
        forge_backend::events::hex_encode(pending.request().request_digest().as_bytes());
    assert_eq!(
        response["result"]["request"]["request_digest"],
        expected_digest
    );
    assert_eq!(
        response["result"]["grant"]["request_digest"],
        expected_digest
    );

    let (status, get_response) = post_command(
        address,
        "approval.get",
        json!({ "scope": scope_json(fixture), "approval_id": pending.id().into_uuid() }),
    )
    .await?;
    assert_eq!(status, 200, "approval.get: {get_response}");
    assert_eq!(get_response["result"]["found"], true);
    assert_eq!(get_response["result"]["execution"], Value::Null);
    assert_eq!(get_response["result"]["grant"]["grant_id"], json!(grant_id));
    assert_eq!(
        get_response["result"]["grant"]["request_digest"],
        expected_digest
    );

    let exact = fixture
        .client
        .approval_get_with_grant(fixture.scope.clone(), pending.id())?
        .ok_or("exact approval readback missing")?;
    assert!(exact.1.is_none(), "local approval must not start execution");
    let grant = exact.2.ok_or("local grant readback missing")?;
    assert_eq!(grant.id().into_uuid(), grant_id);
    assert_eq!(grant.state(), ExecutionGrantState::Active);
    let layout = forge_workspace::WorkspaceStateLayout::inspect_existing(&fixture.workspace_root)?
        .ok_or("approval projection Workspace layout missing")?;
    let reopened = forge_persistence::WorkspaceStore::open_existing(&layout)?;
    let reopened = reopened
        .get_approval_request_with_execution_and_grant(pending.id())?
        .ok_or("reopened approval readback missing")?;
    assert!(reopened.1.is_none());
    assert_eq!(
        reopened.2.as_ref().map(|grant| grant.id().into_uuid()),
        Some(grant_id)
    );
    assert_eq!(
        reopened.2.as_ref().map(forge_domain::ExecutionGrant::state),
        Some(ExecutionGrantState::Active)
    );

    let analyzed = forge_control::analyze_shell_script(SCRIPT.to_owned())?;
    let execution_id = pending.request().execution_id();
    let command_id = analyzed.intent_id().clone();
    let authority_request = forge_control::AgentExecutionAuthorityRequest {
        session_id: fixture.session_id,
        scope: fixture.scope.clone(),
        activity_id: fixture.activity_id,
        agent_id: fixture.agent_id,
        expected_revision: fixture.agent_revision,
        principal: forge_domain::AuthenticatedPrincipal::TrustedStdio,
        attribution: fixture.attribution,
        command_id: command_id.clone(),
    };
    Ok(ApprovedShell {
        execution_id,
        authority_request,
        authority: authority_json(fixture, execution_id, &command_id, issued_at),
        script: SCRIPT.to_owned(),
        grant,
        issued_at,
        expected_digest,
    })
}

async fn assert_execution_replay_fences(
    address: SocketAddr,
    fixture: &Fixture,
    pending: &forge_domain::RegisteredApprovalRequest,
    approved: &ApprovedShell,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut changed_grant = execution_begin_payload(approved);
    changed_grant["grant_id"] = json!(Uuid::now_v7());
    let (status, response) = post_command(address, "execution.begin", changed_grant).await?;
    assert_ne!(status, 200, "changed grant identity must be rejected");
    assert_eq!(response["ok"], false);

    let mut changed_digest = execution_begin_payload(approved);
    changed_digest["admission"]["expected_digest"] =
        json!("0000000000000000000000000000000000000000000000000000000000000000");
    let (status, response) = post_command(address, "execution.begin", changed_digest).await?;
    assert_ne!(status, 200, "changed request digest must be rejected");
    assert_eq!(response["ok"], false);

    let (status, response) = post_command(
        address,
        "execution.begin",
        execution_begin_payload(approved),
    )
    .await?;
    assert_eq!(status, 200, "execution.begin: {response}");
    assert_eq!(
        response["result"]["execution_id"],
        json!(approved.execution_id.into_uuid())
    );
    let consumed = fixture
        .client
        .approval_get_with_grant(fixture.scope.clone(), pending.id())?
        .ok_or("consumed approval readback missing")?;
    let consumed_grant = consumed.2.ok_or("consumed grant readback missing")?;
    assert_eq!(consumed_grant.id(), approved.grant.id());
    assert_eq!(consumed_grant.state(), ExecutionGrantState::Consumed);
    assert_eq!(consumed_grant.revision().get(), 2);

    let mut replay_wrong_grant = execution_begin_payload(approved);
    replay_wrong_grant["grant_id"] = json!(Uuid::now_v7());
    let (status, response) = post_command(address, "execution.begin", replay_wrong_grant).await?;
    assert_ne!(
        status, 200,
        "existing execution must reject a different grant selector"
    );
    assert_eq!(response["ok"], false);

    let mut replay_wrong_revision = execution_begin_payload(approved);
    replay_wrong_revision["expected_grant_revision"] = json!(2);
    let (status, response) =
        post_command(address, "execution.begin", replay_wrong_revision).await?;
    assert_ne!(
        status, 200,
        "existing execution must reject consumed revision"
    );
    assert_eq!(response["ok"], false);

    let (status, response) = post_command(
        address,
        "execution.begin",
        execution_begin_payload(approved),
    )
    .await?;
    assert_eq!(status, 200, "idempotent execution replay: {response}");
    let replayed = fixture
        .client
        .approval_get_with_grant(fixture.scope.clone(), pending.id())?
        .ok_or("replayed approval readback missing")?;
    let replayed_grant = replayed.2.ok_or("replayed grant readback missing")?;
    assert_eq!(replayed_grant.state(), ExecutionGrantState::Consumed);
    assert_eq!(replayed_grant.revision().get(), 2);
    Ok(())
}
