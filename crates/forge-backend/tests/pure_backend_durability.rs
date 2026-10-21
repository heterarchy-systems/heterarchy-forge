//! Durable-outcome proof for the pure backend (GLM pure-backend lane,
//! G3 산출물 3).
//!
//! One real composition (registry + control worker + coordinators) serves two
//! loopback listeners: a deadline-constrained writer server and a normal
//! readback server over the same durable state. Proven here:
//!
//! 1. A real admitted write whose command deadline expires answers HTTP 202
//!    `UNKNOWN_OUTCOME` with the typed readback hint (original
//!    `writer_lease_id` / `goal_id` / server-side `request_digest`), and the
//!    bridge worker still completes the durable effect: the exact original
//!    identity read back as active/found afterwards.
//! 2. A client that disconnects right after submit (reply never read) cannot
//!    prevent the durable effect: the same identity reads back later.
//! 3. With a remote session authority, killing the authority makes
//!    session-bound writes fail closed (503 `DEPENDENCY_UNAVAILABLE`,
//!    retryable, no local fallback, `readback` null) while non-session reads
//!    keep working; restarting the authority restores successful writes. The
//!    authority here is a real TCP listener speaking the versioned resolve
//!    protocol, stopped and restarted for the outage/recovery cycle.

use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use forge_backend::config::BackendConfig;
use forge_backend::http::{assemble, serve};
use forge_control::{
    AgentBindingActivateRequest, AgentBindingReserveRequest, AgentDagPlanCommitRequest,
    CoordinatorClaimRequest, DagNodeStartRequest, ForgeApprovalCoordinator, ForgeControl,
    ForgeControlClient, ForgeControlWorker, ForgeExecutionCoordinator, ResolvedWorkspaceScope,
};
use forge_domain::{
    ActivityCoordinatorActor, ActivityId, AgentDagDraft, AgentDagPlanRequest,
    AgentDagPlanRequestId, AgentDeclaredRole, AgentDisplayName, AgentInstanceId, AgentSessionId,
    AgentSessionOpenRequestId, AgentTransportKind, AgentWorkUpdateId, AgentWorkUpdateSequence,
    AuthenticatedPrincipal, DagAcceptanceCriterion, DagNodeDefinition, DagNodeId, DagNodeObjective,
    DagNodeOrdinal, DagNodeTitle, DagRevision, DagRevisionId, DagRevisionNumber, GoalAttribution,
    GoalContract, GoalId, GoalObjective, GoalStatement, LocationId, OpenAgentSession,
    RegisteredDagNode, RegisteredGoal, RuntimeInstanceId, TimestampMillis, WorkspaceId,
    WorkspaceRoot,
};
use forge_persistence::{
    AgentBindingActivationRequest, AgentBindingReservationRequest, AgentOperationsFreezeRequest,
    GlobalRegistry, WorkspaceStore,
};
use forge_workspace::{LocationService, WorkspaceStateLayout};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::runtime::Handle;
use uuid::Uuid;

const SECRET: &str = "pure-backend-durability-secret";
const SESSION_SERVICE_SECRET: &str = "session-authority-service-secret";
const HTTP_ROUNDTRIP_TIMEOUT: Duration = Duration::from_secs(30);
const READBACK_POLL_BUDGET: Duration = Duration::from_secs(10);
const READBACK_POLL_INTERVAL: Duration = Duration::from_millis(50);

struct WorkspaceSlot {
    workspace_root: PathBuf,
    scope: ResolvedWorkspaceScope,
    activity_id: ActivityId,
    session_id: AgentSessionId,
    agent_id: AgentInstanceId,
    actor: ActivityCoordinatorActor,
}

struct Fixture {
    root: PathBuf,
    workspace: WorkspaceSlot,
    worker: ForgeControlWorker,
    execution: ForgeExecutionCoordinator,
    approval: ForgeApprovalCoordinator,
    deadline_server: SocketAddr,
    read_server: SocketAddr,
}

fn timestamp_now() -> Result<TimestampMillis, Box<dyn std::error::Error>> {
    let millis = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
    Ok(TimestampMillis::new(i64::try_from(millis)?)?)
}

fn add_millis(
    timestamp: TimestampMillis,
    millis: i64,
) -> Result<TimestampMillis, Box<dyn std::error::Error>> {
    Ok(TimestampMillis::new(
        timestamp
            .get()
            .checked_add(millis)
            .ok_or("timestamp overflow")?,
    )?)
}

fn stage<T, E>(result: Result<T, E>, label: &str) -> Result<T, Box<dyn std::error::Error>>
where
    E: Into<Box<dyn std::error::Error>>,
{
    result.map_err(|error| {
        let error = error.into();
        let mut details = format!("{label}: {error}");
        let mut source = error.source();
        for _ in 0..8 {
            let Some(cause) = source else {
                break;
            };
            let _ = std::fmt::Write::write_fmt(&mut details, format_args!("; caused_by={cause}"));
            source = cause.source();
        }
        details.into()
    })
}

fn base_config(port: u16) -> Result<BackendConfig, forge_backend::ConfigError> {
    BackendConfig::new(
        std::net::IpAddr::from([127, 0, 0, 1]),
        port,
        SECRET,
        forge_domain::ForgeBackendId::from_uuid(Uuid::from_u128(0xE001)),
        forge_domain::OrchestrationIssuerId::from_uuid(Uuid::from_u128(0xE002)),
    )
}

fn prepare_workspace(
    root: &Path,
    registry_path: &Path,
    now: TimestampMillis,
) -> Result<(ResolvedWorkspaceScope, PathBuf), Box<dyn std::error::Error>> {
    let location_root = root.join("location");
    let workspace_dir = "workspace";
    let workspace_root = location_root.join(workspace_dir);
    fs::create_dir_all(&workspace_root)?;
    let location_id = LocationId::from_uuid(Uuid::now_v7());
    let workspace_id = WorkspaceId::from_uuid(Uuid::now_v7());
    let mut locations = LocationService::new(GlobalRegistry::open(registry_path)?);
    let location = stage(
        locations.register_selected_path(location_id, "durability", &location_root, now),
        "register durability location",
    )?;
    let layout = stage(
        WorkspaceStateLayout::initialize(&workspace_root),
        "initialize durability workspace",
    )?;
    let establish = forge_domain::EstablishWorkspace::new(
        workspace_id,
        location.id(),
        WorkspaceRoot::from_canonical(layout.workspace_root().to_path_buf())?,
        layout.root_fingerprint()?,
        add_millis(now, 1)?,
    );
    drop(WorkspaceStore::open(&layout, &establish)?);
    drop(locations);
    let control = ForgeControl::new(GlobalRegistry::open(registry_path)?);
    let located = control
        .workspace_discover(location_id, forge_domain::LocationRevision::INITIAL)?
        .into_iter()
        .find(|entry| entry.display_name() == workspace_dir)
        .ok_or("durability workspace discovery entry missing")?
        .locator()
        .clone();
    let scope = stage(
        control.resolve_workspace(
            location_id,
            forge_domain::LocationRevision::INITIAL,
            &located,
        ),
        "resolve durability workspace",
    )?;
    Ok((scope, workspace_root))
}

fn activate_agent(
    client: &ForgeControlClient,
    slot: &mut WorkspaceSlot,
    runtime_instance_id: RuntimeInstanceId,
    now: TimestampMillis,
    open_sessions: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    open_and_bind_workspace(client, slot, runtime_instance_id, now, open_sessions)?;
    plan_workspace_work(client, slot, now)
}

/// Bootstrap the Activity, open the logical session, and bind the native
/// Agent.
fn open_and_bind_workspace(
    client: &ForgeControlClient,
    slot: &mut WorkspaceSlot,
    runtime_instance_id: RuntimeInstanceId,
    now: TimestampMillis,
    open_sessions: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let _ = stage(
        client.bootstrap_activity(
            slot.scope.clone(),
            slot.activity_id,
            runtime_instance_id,
            now,
            add_millis(now, 120_000)?,
        ),
        "bootstrap durability activity",
    )?;
    // With a remote session authority, Forge control never opens sessions
    // locally: the remote provider owns them and answers resolves.
    if open_sessions {
        let _ = stage(
            client.agent_session_open(OpenAgentSession::new(
                slot.session_id,
                AgentSessionOpenRequestId::from_uuid(Uuid::now_v7()),
                AuthenticatedPrincipal::TrustedStdio,
                add_millis(now, 1)?,
            )),
            "open durability session",
        )?;
    }
    let layout = WorkspaceStateLayout::inspect_existing(&slot.workspace_root)?
        .ok_or("durability workspace layout missing")?;
    let mut store = WorkspaceStore::open_existing(&layout)?;
    let freeze = stage(
        store.freeze_agent_operations(&AgentOperationsFreezeRequest::new(
            Uuid::now_v7(),
            Uuid::now_v7(),
            add_millis(now, 20)?,
        )?),
        "freeze durability agent operations",
    )?;
    drop(store);
    let request_id = Uuid::now_v7();
    let reservation = stage(
        AgentBindingReservationRequest::new(
            request_id,
            slot.activity_id,
            slot.agent_id,
            slot.session_id,
            AuthenticatedPrincipal::TrustedStdio,
            add_millis(now, 21)?,
        ),
        "durability reservation request",
    )?;
    let _ = stage(
        client.reserve_agent_binding(AgentBindingReserveRequest {
            scope: slot.scope.clone(),
            freeze: freeze.clone(),
            reservation,
            observed_at: add_millis(now, 22)?,
        }),
        "reserve durability binding",
    )?;
    let delegation = stage(
        client.delegate_agent_operations(forge_control::AgentOperationsDelegationRequest {
            scope: slot.scope.clone(),
            freeze,
            manifest_digest: [0xA1; 32],
            observed_at: add_millis(now, 23)?,
        }),
        "delegate durability operations",
    )?;
    let activation = stage(
        AgentBindingActivationRequest::new(
            request_id,
            [0xA2; 32],
            AgentDisplayName::new("durability-agent".to_owned())?,
            AgentDeclaredRole::new("executor".to_owned())?,
            AgentTransportKind::Stdio,
        ),
        "durability activation request",
    )?;
    let _ = stage(
        client.activate_agent_binding(AgentBindingActivateRequest {
            scope: slot.scope.clone(),
            delegation,
            activation,
            session_id: slot.session_id,
            principal: AuthenticatedPrincipal::TrustedStdio,
            observed_at: add_millis(now, 24)?,
        }),
        "activate durability binding",
    )?;
    Ok(())
}

/// Claim the Activity Coordinator and plan one Goal/DAG/node so the durable
/// semantic event stream carries real per-Workspace planning events.
fn plan_workspace_work(
    client: &ForgeControlClient,
    slot: &mut WorkspaceSlot,
    now: TimestampMillis,
) -> Result<(), Box<dyn std::error::Error>> {
    let binding = stage(
        client.activity_coordinator_claim(CoordinatorClaimRequest {
            session_id: slot.session_id,
            scope: slot.scope.clone(),
            activity_id: slot.activity_id,
            agent_id: slot.agent_id,
            principal: AuthenticatedPrincipal::TrustedStdio,
            observed_at: add_millis(now, 30)?,
        }),
        "claim durability coordinator",
    )?;
    let actor = ActivityCoordinatorActor::new(
        slot.scope.workspace_id(),
        slot.activity_id,
        binding.agent_id(),
        binding.revision(),
        AuthenticatedPrincipal::TrustedStdio,
        slot.session_id,
    );
    let goal = RegisteredGoal::create(
        GoalId::from_uuid(Uuid::now_v7()),
        slot.scope.workspace_id(),
        slot.activity_id,
        GoalContract::new(
            GoalObjective::new("Durability proof".to_owned())?,
            vec![GoalStatement::new(
                "Durable effects survive lost replies".to_owned(),
            )?],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )?,
        add_millis(now, 31)?,
    );
    let _ = stage(
        client.goal_create(slot.scope.clone(), actor, goal.clone()),
        "durability goal_create",
    )?;
    let definition = DagNodeDefinition::new(
        DagNodeId::from_uuid(Uuid::now_v7()),
        DagNodeOrdinal::new(0)?,
        DagNodeTitle::new("Durable work".to_owned())?,
        DagNodeObjective::new("Prove durable readback".to_owned())?,
        vec![DagAcceptanceCriterion::new("Effects read back".to_owned())?],
    )?;
    let revision = DagRevision::new(
        DagRevisionId::from_uuid(Uuid::now_v7()),
        goal.id(),
        goal.revision(),
        DagRevisionNumber::INITIAL,
        None,
        vec![definition.clone()],
        Vec::new(),
        add_millis(now, 32)?,
    )?;
    let pending = RegisteredDagNode::create(
        goal.id(),
        DagRevisionNumber::INITIAL,
        definition,
        add_millis(now, 32)?,
    );
    let plan = AgentDagPlanRequest::new(
        AgentDagPlanRequestId::from_uuid(Uuid::now_v7()),
        actor,
        GoalAttribution::new(goal.id(), goal.revision()),
        None,
        None,
        AgentDagDraft::new(revision, vec![pending.clone()], Vec::new())?,
        AgentWorkUpdateId::from_uuid(Uuid::now_v7()),
        AgentWorkUpdateSequence::INITIAL,
        add_millis(now, 33)?,
    );
    let _ = stage(
        client.agent_dag_plan_commit(AgentDagPlanCommitRequest {
            scope: slot.scope.clone(),
            request: plan,
        }),
        "durability dag plan commit",
    )?;
    let _ = stage(
        client.dag_node_start(DagNodeStartRequest {
            scope: slot.scope.clone(),
            activity_id: slot.activity_id,
            session_id: slot.session_id,
            principal: AuthenticatedPrincipal::TrustedStdio,
            goal_id: goal.id(),
            expected_goal_revision: goal.revision(),
            expected_dag_revision: DagRevisionNumber::INITIAL,
            node_id: pending.id(),
            expected_revision: pending.revision(),
            observed_at: add_millis(now, 34)?,
        }),
        "durability dag node start",
    )?;
    slot.actor = actor;
    Ok(())
}

async fn build_fixture(
    command_deadline: Option<Duration>,
) -> Result<Fixture, Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!(
        "heterarchy-forge-backend-durability-{}-{}",
        std::process::id(),
        Uuid::now_v7()
    ));
    fs::create_dir_all(&root)?;
    let now = timestamp_now()?;
    let registry_path = root.join("registry.sqlite3");
    let (scope, workspace_root) = prepare_workspace(&root, &registry_path, now)?;
    let mut slot = WorkspaceSlot {
        workspace_root,
        scope,
        activity_id: ActivityId::from_uuid(Uuid::now_v7()),
        session_id: AgentSessionId::from_uuid(Uuid::now_v7()),
        agent_id: AgentInstanceId::from_uuid(Uuid::now_v7()),
        actor: ActivityCoordinatorActor::new(
            WorkspaceId::from_uuid(Uuid::nil()),
            ActivityId::from_uuid(Uuid::nil()),
            AgentInstanceId::from_uuid(Uuid::nil()),
            forge_domain::ActivityCoordinatorRevision::INITIAL,
            AuthenticatedPrincipal::TrustedStdio,
            AgentSessionId::from_uuid(Uuid::nil()),
        ),
    };
    let (client, worker) =
        ForgeControlWorker::start(ForgeControl::new(GlobalRegistry::open(&registry_path)?))?;
    let runtime_instance_id = RuntimeInstanceId::from_uuid(Uuid::now_v7());
    activate_agent(
        &client,
        &mut slot,
        runtime_instance_id,
        add_millis(now, 100)?,
        true,
    )?;
    let execution = ForgeExecutionCoordinator::start(client.clone(), 2)?;
    let approval = ForgeApprovalCoordinator::start(client.clone(), execution.client())?;
    let (activity_leases, lease_worker) = ForgeControlWorker::start_activity_lease(
        ForgeControl::new(GlobalRegistry::open_existing(&registry_path)?),
    )?;
    let execution_client = execution.client();
    let approval_client = approval.client();
    let product_cache = root.join("product-cache");
    let mut write_config = base_config(0)?;
    if let Some(deadline) = command_deadline {
        write_config = write_config.with_command_deadline(deadline);
    }
    let write_state = assemble(
        write_config,
        backend_clients(
            &client,
            &execution_client,
            &approval_client,
            &activity_leases,
            runtime_instance_id.into_uuid(),
            &product_cache,
            Uuid::from_u128(0xE003),
        ),
    )?;
    let deadline_server = serve(write_state).await?;
    let read_state = assemble(
        base_config(0)?,
        backend_clients(
            &client,
            &execution_client,
            &approval_client,
            &activity_leases,
            runtime_instance_id.into_uuid(),
            &product_cache,
            Uuid::from_u128(0xE003),
        ),
    )?;
    let read_server = serve(read_state).await?;
    let _ = lease_worker;
    Ok(Fixture {
        root,
        workspace: slot,
        worker,
        execution,
        approval,
        deadline_server,
        read_server,
    })
}

impl Fixture {
    fn shutdown(self) -> Result<(), Box<dyn std::error::Error>> {
        let Fixture {
            root,
            mut worker,
            mut execution,
            mut approval,
            ..
        } = self;
        let _ = approval.shutdown();
        let _ = execution.shutdown();
        worker.shutdown()?;
        fs::remove_dir_all(root)?;
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn backend_clients<'a>(
    client: &'a ForgeControlClient,
    execution: &'a forge_control::ForgeExecutionCoordinatorClient,
    approval: &'a forge_control::ForgeApprovalCoordinatorClient,
    activity_leases: &'a forge_control::ActivityLeaseClient,
    runtime_instance_id: Uuid,
    product_cache_root: &'a Path,
    destination_id: Uuid,
) -> forge_backend::http::BackendClients<'a> {
    forge_backend::http::BackendClients {
        control: client,
        execution,
        approval,
        activity_leases,
        runtime_instance_id,
        product_cache_root,
        destination_id,
    }
}

fn scope_json(slot: &WorkspaceSlot) -> Value {
    let scope = &slot.scope;
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

fn lease_acquire_payload(slot: &WorkspaceSlot, lease_id: Uuid, path: &str) -> Value {
    json!({
        "scope": scope_json(slot),
        "activity_id": slot.activity_id.into_uuid(),
        "actor": {
            "session_id": slot.session_id.into_uuid(),
            "principal": { "kind": "trusted_stdio" },
            "agent_id": slot.agent_id.into_uuid(),
        },
        "writer_lease_id": lease_id,
        "duration_ms": 30_000,
        "scopes": [{
            "kind": "exact_path",
            "path_base64": URL_SAFE_NO_PAD.encode(path.as_bytes()),
        }],
    })
}

async fn post_json(
    address: SocketAddr,
    op: &str,
    payload: Value,
) -> Result<(u16, Value), Box<dyn std::error::Error>> {
    let body = json!({
        "forge_api": 1,
        "request_id": Uuid::now_v7(),
        "op": op,
        "payload": payload,
    })
    .to_string();
    let mut stream = tokio::net::TcpStream::connect(address).await?;
    let request = format!(
        "POST /api/v1/commands/{op} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {SECRET}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).await?;
    let mut response = Vec::new();
    tokio::time::timeout(HTTP_ROUNDTRIP_TIMEOUT, stream.read_to_end(&mut response))
        .await
        .map_err(|_| "HTTP command round-trip exceeded its bound")??;
    let text = String::from_utf8_lossy(&response).into_owned();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|status| status.parse::<u16>().ok())
        .unwrap_or(0);
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_owned())
        .unwrap_or_default();
    Ok((status, serde_json::from_str(&body)?))
}

async fn lease_get_found(
    address: SocketAddr,
    slot: &WorkspaceSlot,
    lease_id: Uuid,
) -> Result<Value, Box<dyn std::error::Error>> {
    let (status, response) = post_json(
        address,
        "writer_lease.get",
        json!({
            "scope": scope_json(slot),
            "writer_lease_id": lease_id,
        }),
    )
    .await?;
    if status != 200 || response["ok"] != true {
        return Err(format!("writer_lease.get failed ({status}): {response}").into());
    }
    Ok(response["result"].clone())
}

async fn wait_until_lease_found(
    address: SocketAddr,
    slot: &WorkspaceSlot,
    lease_id: Uuid,
) -> Result<Value, Box<dyn std::error::Error>> {
    let deadline = std::time::Instant::now() + READBACK_POLL_BUDGET;
    loop {
        let found = lease_get_found(address, slot, lease_id).await?;
        if found["found"] == true {
            return Ok(found);
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!(
                "lease {lease_id} never read back as found within its budget: {found}"
            )
            .into());
        }
        tokio::time::sleep(READBACK_POLL_INTERVAL).await;
    }
}

/// 산출물 3a: a real admitted write that outlives its command deadline answers
/// 202 `UNKNOWN_OUTCOME` with the typed readback hint, and the worker still
/// completes the durable effect under the original identity.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deadline_exceeded_write_returns_202_then_durable_readback()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = build_fixture(Some(Duration::from_millis(1))).await?;
    // The 1ms deadline races the real worker; a rare worker win yields 200,
    // so retry a few times — every attempt's durable readback is asserted.
    let mut saw_unknown_outcome = false;
    let mut last_lease = None;
    for _ in 0..5 {
        let lease_id = Uuid::now_v7();
        let (status, reply) = post_json(
            fixture.deadline_server,
            "writer_lease.acquire",
            lease_acquire_payload(&fixture.workspace, lease_id, "deadline-lease.txt"),
        )
        .await?;
        if status == 200 {
            last_lease = Some(lease_id);
            continue;
        }
        assert_eq!(status, 202, "deadline outcome: {reply}");
        assert_eq!(reply["ok"], false);
        assert_eq!(reply["error"]["code"], "UNKNOWN_OUTCOME");
        assert_eq!(reply["error"]["retryable"], false);
        assert_eq!(reply["error"]["recovery_action"], "read_back");
        assert_eq!(reply["error"]["readback"]["kind"], "writer_lease");
        assert_eq!(
            reply["error"]["readback"]["writer_lease_id"],
            serde_json::json!(lease_id)
        );
        saw_unknown_outcome = true;
        last_lease = Some(lease_id);
        break;
    }
    assert!(
        saw_unknown_outcome,
        "the 1ms deadline never produced UNKNOWN_OUTCOME across attempts"
    );
    let Some(lease_id) = last_lease else {
        return Err("no lease attempt recorded".into());
    };
    // The durable effect completed under the original identity despite the
    // unknown outcome.
    let readback =
        wait_until_lease_found(fixture.read_server, &fixture.workspace, lease_id).await?;
    assert_eq!(readback["status"], "active", "readback: {readback}");
    fixture.shutdown()?;
    Ok(())
}

/// 산출물 3b: a client that disconnects right after submit cannot prevent the
/// durable effect — the same identity reads back afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn client_disconnect_after_submit_still_completes_durable_effect()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = build_fixture(None).await?;
    let lease_id = Uuid::now_v7();
    {
        // Submit and abandon the connection without ever consuming the reply.
        use tokio::io::AsyncWriteExt;
        let payload = lease_acquire_payload(&fixture.workspace, lease_id, "disconnect-lease.txt");
        let body = json!({
            "forge_api": 1,
            "request_id": Uuid::now_v7(),
            "op": "writer_lease.acquire",
            "payload": payload,
        })
        .to_string();
        let mut stream = tokio::net::TcpStream::connect(fixture.read_server).await?;
        let request = format!(
            "POST /api/v1/commands/writer_lease.acquire HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {SECRET}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(request.as_bytes()).await?;
        // Give the server time to read the fully-written request and admit
        // it; the client then abandons the connection without ever
        // consuming the reply body.
        tokio::time::sleep(Duration::from_millis(300)).await;
        drop(stream);
    }
    let readback =
        wait_until_lease_found(fixture.read_server, &fixture.workspace, lease_id).await?;
    assert_eq!(readback["status"], "active", "readback: {readback}");
    assert_eq!(
        readback["writer_lease_id"],
        serde_json::json!(lease_id),
        "the original identity read back"
    );
    fixture.shutdown()?;
    Ok(())
}

/// 산출물 3c: with a remote session authority, killing it makes session-bound
/// writes fail closed (503 `DEPENDENCY_UNAVAILABLE`, no local fallback, reads
/// keep working) and restarting it restores successful writes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn session_authority_outage_fails_closed_then_recovers_after_restart()
-> Result<(), Box<dyn std::error::Error>> {
    let (authority, address, slot, _worker_guard) = build_outage_fixture().await?;

    // 1. Authority alive: a session-bound write succeeds through the remote
    // resolve.
    let lease_alive = Uuid::now_v7();
    let (status, reply) = post_json(
        address,
        "writer_lease.acquire",
        lease_acquire_payload(&slot, lease_alive, "outage-alive.txt"),
    )
    .await?;
    assert_eq!(status, 200, "authority-alive acquire: {reply}");
    assert_eq!(reply["result"]["status"], "active", "reply: {reply}");

    // 2. Authority outage: session-bound writes fail closed with no local
    // fallback, while the non-session read path keeps working.
    authority.stop();
    let mut outage_status = None;
    let mut outage_reply = Value::Null;
    for _ in 0..20 {
        let (status, reply) = post_json(
            address,
            "writer_lease.acquire",
            lease_acquire_payload(&slot, Uuid::now_v7(), "outage-attempt.txt"),
        )
        .await?;
        if status == 503 {
            outage_status = Some(status);
            outage_reply = reply;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(outage_status, Some(503), "outage acquire: {outage_reply}");
    assert_eq!(outage_reply["ok"], false);
    assert_eq!(outage_reply["error"]["code"], "DEPENDENCY_UNAVAILABLE");
    assert_eq!(outage_reply["error"]["retryable"], true);
    assert_eq!(
        outage_reply["error"]["recovery_action"],
        "retry_when_available"
    );
    assert_eq!(outage_reply["error"]["readback"], Value::Null);
    // Non-session read path is unaffected by the outage.
    let alive_read = lease_get_found(address, &slot, lease_alive).await?;
    assert_eq!(
        alive_read["found"], true,
        "reads survive the outage: {alive_read}"
    );

    // 3. Recovery: restarting the authority restores successful resolves.
    authority.restart().await?;
    let lease_recovered = Uuid::now_v7();
    let (status, reply) = post_json(
        address,
        "writer_lease.acquire",
        lease_acquire_payload(&slot, lease_recovered, "outage-recovered.txt"),
    )
    .await?;
    assert_eq!(status, 200, "authority-restarted acquire: {reply}");
    assert_eq!(reply["result"]["status"], "active", "reply: {reply}");
    Ok(())
}

/// Owners kept alive for the outage scenario; dropped at test end. The
/// fields are deliberately unread: their purpose is lifetime, not data.
#[allow(dead_code)]
struct OutageGuards {
    root: PathBuf,
    worker: ForgeControlWorker,
    lease_worker: ForgeControlWorker,
    execution: ForgeExecutionCoordinator,
    approval: ForgeApprovalCoordinator,
    state: forge_backend::AppState,
}

/// Compose the outage scenario: a real Workspace whose control and lease
/// authorities are the given remote authority, served over loopback.
async fn build_outage_fixture()
-> Result<(FakeAuthority, SocketAddr, WorkspaceSlot, OutageGuards), Box<dyn std::error::Error>> {
    let authority = FakeAuthority::spawn().await?;
    let root = std::env::temp_dir().join(format!(
        "heterarchy-forge-backend-durability-outage-{}-{}",
        std::process::id(),
        Uuid::now_v7()
    ));
    fs::create_dir_all(&root)?;
    let now = timestamp_now()?;
    let registry_path = root.join("registry.sqlite3");
    let (scope, workspace_root) = prepare_workspace(&root, &registry_path, now)?;
    let remote = |locations: LocationService<GlobalRegistry>| {
        let client = forge_backend::remote_authority::RemoteAgentSessionAuthority::new(
            Handle::current(),
            authority.address(),
            SESSION_SERVICE_SECRET,
            Duration::from_secs(2),
        )
        .map_err(|error| format!("remote authority config: {error:?}"))?;
        Ok::<_, Box<dyn std::error::Error>>(ForgeControl::with_session_authority(
            locations,
            Box::new(client) as Box<dyn forge_control::AgentSessionAuthority>,
        ))
    };
    let (client, worker) = ForgeControlWorker::start(remote(LocationService::new(
        GlobalRegistry::open(&registry_path)?,
    ))?)?;
    let (activity_leases, lease_worker) = ForgeControlWorker::start_activity_lease(remote(
        LocationService::new(GlobalRegistry::open(&registry_path)?),
    )?)?;
    let runtime_instance_id = RuntimeInstanceId::from_uuid(Uuid::now_v7());
    let mut slot = WorkspaceSlot {
        workspace_root,
        scope,
        activity_id: ActivityId::from_uuid(Uuid::now_v7()),
        session_id: AgentSessionId::from_uuid(Uuid::now_v7()),
        agent_id: AgentInstanceId::from_uuid(Uuid::now_v7()),
        actor: ActivityCoordinatorActor::new(
            WorkspaceId::from_uuid(Uuid::nil()),
            ActivityId::from_uuid(Uuid::nil()),
            AgentInstanceId::from_uuid(Uuid::nil()),
            forge_domain::ActivityCoordinatorRevision::INITIAL,
            AuthenticatedPrincipal::TrustedStdio,
            AgentSessionId::from_uuid(Uuid::nil()),
        ),
    };
    // Fixture bootstrap resolves its sessions through the live fake authority;
    // a remote authority never opens sessions locally.
    open_and_bind_workspace(
        &client,
        &mut slot,
        runtime_instance_id,
        add_millis(now, 100)?,
        false,
    )?;
    plan_workspace_work(&client, &mut slot, add_millis(now, 200)?)?;
    let execution = ForgeExecutionCoordinator::start(client.clone(), 2)?;
    let approval = ForgeApprovalCoordinator::start(client.clone(), execution.client())?;
    let state = assemble(
        base_config(0)?,
        forge_backend::http::BackendClients {
            control: &client,
            execution: &execution.client(),
            approval: &approval.client(),
            activity_leases: &activity_leases,
            runtime_instance_id: runtime_instance_id.into_uuid(),
            product_cache_root: &root.join("product-cache"),
            destination_id: Uuid::from_u128(0xE003),
        },
    )?;
    let address = serve(state.clone()).await?;
    Ok((
        authority,
        address,
        slot,
        OutageGuards {
            root,
            worker,
            lease_worker,
            execution,
            approval,
            state,
        },
    ))
}

/// Controllable real-TCP session authority: speaks the versioned resolve
/// protocol and can be stopped (connection refused) and restarted on the same
/// address.
struct FakeAuthority {
    address: SocketAddr,
    task: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl FakeAuthority {
    async fn spawn() -> Result<Self, Box<dyn std::error::Error>> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let task = tokio::spawn(Self::serve(listener));
        Ok(Self {
            address,
            task: std::sync::Mutex::new(Some(task)),
        })
    }

    fn address(&self) -> SocketAddr {
        self.address
    }

    /// Stop accepting: new resolves see connection refused (outage).
    fn stop(&self) {
        if let Ok(mut task) = self.task.lock()
            && let Some(running) = task.take()
        {
            running.abort();
        }
    }

    /// Restart on the same address after a stop.
    async fn restart(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Wait until the stopped listener actually released the port.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let listener = loop {
            match tokio::net::TcpListener::bind(self.address).await {
                Ok(listener) => break listener,
                Err(_) if std::time::Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(error) => return Err(format!("authority restart bind failed: {error}").into()),
            }
        };
        let task = tokio::spawn(Self::serve(listener));
        if let Ok(mut slot) = self.task.lock() {
            *slot = Some(task);
        }
        Ok(())
    }

    async fn serve(listener: tokio::net::TcpListener) {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let _ = Self::handle(&mut stream).await;
        }
    }

    async fn handle(stream: &mut tokio::net::TcpStream) -> std::io::Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut head = Vec::new();
        let mut chunk = [0_u8; 1024];
        let body_start = loop {
            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                return Ok(());
            }
            head.extend_from_slice(&chunk[..read]);
            if let Some(position) = find_double_crlf(&head) {
                break position + 4;
            }
        };
        let content_length = String::from_utf8_lossy(&head)
            .split("\r\n")
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.trim()
                    .eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())?
            })
            .unwrap_or(0);
        let mut body = head.split_off(body_start);
        while body.len() < content_length {
            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..read]);
        }
        let request: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
        let session_id = request["session_id"].as_str().unwrap_or_default();
        let reply = if session_id.is_empty() {
            json!({ "version": 1, "outcome": { "kind": "not_found" } })
        } else {
            json!({
                "version": 1,
                "outcome": {
                    "kind": "found",
                    "session": {
                        "session_id": session_id,
                        "principal": {"kind": "trusted_stdio"},
                        "request_id": Uuid::from_u128(0xA11CE),
                        "state": "open",
                        "created_at_ms": 1,
                        "updated_at_ms": 2,
                        // from_parts rejects revision INITIAL unless
                        // updated_at == created_at, so project revision 2.
                        "revision": 2,
                    }
                }
            })
        };
        let body_text = reply.to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body_text}",
            body_text.len()
        );
        stream.write_all(response.as_bytes()).await?;
        // Hold the connection open: an immediate shutdown sends FIN before
        // the client finishes collecting the body, and hyper's connection
        // future would then tear down the in-flight exchange.
        tokio::time::sleep(Duration::from_millis(500)).await;
        Ok(())
    }
}

fn find_double_crlf(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}
