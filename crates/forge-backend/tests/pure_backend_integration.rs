//! Final headless integration proof for the pure backend (GLM pure-backend
//! lane, G3 산출물 5).
//!
//! One GUI-free flow over the real composition — registry, control/lease
//! workers, coordinators, real loopback listener, real SQLite:
//!
//! 1. serve → `healthz` / `readyz` / capability document;
//! 2. durable workspace evidence: planning events visible through the
//!    paged read and the snapshot watermark;
//! 3. live SSE tail connected at the watermark;
//! 4. `WriterLease` acquire → readback (found/active) → release → readback
//!    (found/released);
//! 5. a real planning write observed on the SSE tail (publish→frame);
//! 6. graceful shutdown: successful drain report, the live tail receives
//!    exactly one terminal frame, and the pre-shutdown watermark is stable;
//! 7. restart: a fresh server composition over the SAME durable state
//!    serves again, the full event history replays from a pre-shutdown
//!    cursor, and the released lease readback is intact.
//!
//! Binary-level SIGTERM/fence restart evidence lives in the existing
//! `host_lifecycle` suite; this flow proves durable continuity across a
//! server restart at the HTTP level.

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
    AgentSessionOpenRequestId, AgentWorkUpdateId, AgentWorkUpdateSequence, AuthenticatedPrincipal,
    DagAcceptanceCriterion, DagNodeDefinition, DagNodeId, DagNodeObjective, DagNodeOrdinal,
    DagNodeTitle, DagRevision, DagRevisionId, DagRevisionNumber, GoalAttribution, GoalContract,
    GoalId, GoalObjective, GoalStatement, LocationId, OpenAgentSession, RegisteredDagNode,
    RegisteredGoal, RuntimeInstanceId, TimestampMillis, WorkspaceId, WorkspaceRoot,
};
use forge_persistence::{
    AgentBindingActivationRequest, AgentBindingReservationRequest, AgentOperationsFreezeRequest,
    GlobalRegistry, WorkspaceStore,
};
use forge_workspace::{LocationService, WorkspaceStateLayout};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

const SECRET: &str = "pure-backend-integration-secret";
const HTTP_ROUNDTRIP_TIMEOUT: Duration = Duration::from_secs(30);
const STREAM_READ_BUDGET: Duration = Duration::from_secs(5);

struct Shared {
    root: PathBuf,
    registry_path: PathBuf,
    scope: ResolvedWorkspaceScope,
    activity_id: ActivityId,
    session_id: AgentSessionId,
    agent_id: AgentInstanceId,
    actor: ActivityCoordinatorActor,
}

/// One server composition: workers, coordinators, listener. Drop/shutdown
/// releases the durable writers so a second composition can serve.
struct Composition {
    state: forge_backend::AppState,
    address: SocketAddr,
    worker: ForgeControlWorker,
    lease_worker: ForgeControlWorker,
    execution: ForgeExecutionCoordinator,
    approval: ForgeApprovalCoordinator,
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

fn publish_goal_through_control_worker(
    shared: &Shared,
    goal: RegisteredGoal,
    label: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let control = ForgeControl::new(GlobalRegistry::open_existing(&shared.registry_path)?);
    let (client, mut worker) = ForgeControlWorker::start(control)?;
    let result = client.goal_create(shared.scope.clone(), shared.actor, goal);
    worker.shutdown()?;
    let _ = stage(result, label)?;
    Ok(())
}

fn scope_json(shared: &Shared) -> Value {
    let scope = &shared.scope;
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

fn scope_query(shared: &Shared) -> String {
    let scope = &shared.scope;
    format!(
        "workspace={}&workspace_revision={}&location_id={}&location_revision={}&relative_root={}",
        scope.workspace_id().into_uuid(),
        scope.workspace_revision().get(),
        scope.locator().location_id().into_uuid(),
        scope.locator().expected_revision().get(),
        scope.locator().relative_root().to_string_lossy(),
    )
}

/// Register the Location + Workspace, open the logical session, bind the
/// native Agent, claim the Coordinator, and plan one Goal/DAG/node — the
/// durable seed the whole flow reads back.
/// Register the Location, initialize the Workspace state layout, establish
/// the Workspace identity and resolve its scope.
fn register_workspace_seed(
    registry_path: &Path,
    now: TimestampMillis,
) -> Result<(ResolvedWorkspaceScope, PathBuf), Box<dyn std::error::Error>> {
    let location_root = registry_path
        .parent()
        .ok_or("registry path has no parent")?
        .join("location");
    let workspace_root = location_root.join("workspace");
    fs::create_dir_all(&workspace_root)?;
    let location_id = LocationId::from_uuid(Uuid::now_v7());
    let workspace_id = WorkspaceId::from_uuid(Uuid::now_v7());
    let mut locations = LocationService::new(GlobalRegistry::open(registry_path)?);
    let location = stage(
        locations.register_selected_path(location_id, "integration", &location_root, now),
        "register integration location",
    )?;
    let layout = stage(
        WorkspaceStateLayout::initialize(&workspace_root),
        "initialize integration workspace",
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
        .find(|entry| entry.display_name() == "workspace")
        .ok_or("integration workspace discovery entry missing")?
        .locator()
        .clone();
    let scope = stage(
        control.resolve_workspace(
            location_id,
            forge_domain::LocationRevision::INITIAL,
            &located,
        ),
        "resolve integration workspace",
    )?;
    Ok((scope, workspace_root))
}

/// Reserve/delegate/activate one native Agent binding over an existing
/// operations freeze.
#[allow(clippy::too_many_arguments)]
fn bind_native_agent(
    client: &ForgeControlClient,
    scope: &ResolvedWorkspaceScope,
    activity_id: ActivityId,
    agent_id: AgentInstanceId,
    session_id: AgentSessionId,
    freeze: forge_persistence::AgentOperationsFreeze,
    now: TimestampMillis,
) -> Result<(), Box<dyn std::error::Error>> {
    let request_id = Uuid::now_v7();
    let reservation = stage(
        AgentBindingReservationRequest::new(
            request_id,
            activity_id,
            agent_id,
            session_id,
            AuthenticatedPrincipal::TrustedStdio,
            add_millis(now, 21)?,
        ),
        "integration reservation request",
    )?;
    let _ = stage(
        client.reserve_agent_binding(AgentBindingReserveRequest {
            scope: scope.clone(),
            freeze: freeze.clone(),
            reservation,
            observed_at: add_millis(now, 22)?,
        }),
        "reserve integration binding",
    )?;
    let delegation = stage(
        client.delegate_agent_operations(forge_control::AgentOperationsDelegationRequest {
            scope: scope.clone(),
            freeze,
            manifest_digest: [0xA1; 32],
            observed_at: add_millis(now, 23)?,
        }),
        "delegate integration operations",
    )?;
    let activation = stage(
        AgentBindingActivationRequest::new(
            request_id,
            [0xA2; 32],
            AgentDisplayName::new("integration-agent".to_owned())?,
            AgentDeclaredRole::new("executor".to_owned())?,
            forge_domain::AgentTransportKind::Stdio,
        ),
        "integration activation request",
    )?;
    let _ = stage(
        client.activate_agent_binding(AgentBindingActivateRequest {
            scope: scope.clone(),
            delegation,
            activation,
            session_id,
            principal: AuthenticatedPrincipal::TrustedStdio,
            observed_at: add_millis(now, 24)?,
        }),
        "activate integration binding",
    )?;
    Ok(())
}

fn prepare_shared(root: &Path) -> Result<Shared, Box<dyn std::error::Error>> {
    let now = timestamp_now()?;
    let registry_path = root.join("registry.sqlite3");
    let (scope, workspace_root) = register_workspace_seed(&registry_path, now)?;
    let control = ForgeControl::new(GlobalRegistry::open(&registry_path)?);
    let activity_id = ActivityId::from_uuid(Uuid::now_v7());
    let session_id = AgentSessionId::from_uuid(Uuid::now_v7());
    let agent_id = AgentInstanceId::from_uuid(Uuid::now_v7());
    let _ = stage(
        control.bootstrap_activity(
            &scope,
            activity_id,
            RuntimeInstanceId::from_uuid(Uuid::now_v7()),
            now,
            add_millis(now, 600_000)?,
        ),
        "bootstrap integration activity",
    )?;
    let _ = stage(
        control.agent_session_open(&OpenAgentSession::new(
            session_id,
            AgentSessionOpenRequestId::from_uuid(Uuid::now_v7()),
            AuthenticatedPrincipal::TrustedStdio,
            add_millis(now, 1)?,
        )),
        "open integration session",
    )?;
    let layout = WorkspaceStateLayout::inspect_existing(&workspace_root)?
        .ok_or("integration workspace layout missing")?;
    let mut store = WorkspaceStore::open_existing(&layout)?;
    let freeze = stage(
        store.freeze_agent_operations(&AgentOperationsFreezeRequest::new(
            Uuid::now_v7(),
            Uuid::now_v7(),
            add_millis(now, 20)?,
        )?),
        "freeze integration agent operations",
    )?;
    drop(store);
    let (client, mut worker) =
        ForgeControlWorker::start(ForgeControl::new(GlobalRegistry::open(&registry_path)?))?;
    bind_native_agent(
        &client,
        &scope,
        activity_id,
        agent_id,
        session_id,
        freeze,
        now,
    )?;
    let actor = plan_workspace_work(
        &client,
        &scope,
        activity_id,
        session_id,
        agent_id,
        add_millis(now, 200)?,
    )?;
    worker.shutdown()?;
    Ok(Shared {
        root: root.to_path_buf(),
        registry_path,
        scope,
        activity_id,
        session_id,
        agent_id,
        actor,
    })
}

/// Claim the Coordinator and plan one Goal/DAG/node: the durable planning
/// seed every later stage reads back.
#[allow(clippy::too_many_arguments)]
fn plan_workspace_work(
    client: &ForgeControlClient,
    scope: &ResolvedWorkspaceScope,
    activity_id: ActivityId,
    session_id: AgentSessionId,
    agent_id: AgentInstanceId,
    now: TimestampMillis,
) -> Result<ActivityCoordinatorActor, Box<dyn std::error::Error>> {
    let binding = stage(
        client.activity_coordinator_claim(CoordinatorClaimRequest {
            session_id,
            scope: scope.clone(),
            activity_id,
            agent_id,
            principal: AuthenticatedPrincipal::TrustedStdio,
            observed_at: add_millis(now, 30)?,
        }),
        "claim integration coordinator",
    )?;
    let actor = ActivityCoordinatorActor::new(
        scope.workspace_id(),
        activity_id,
        binding.agent_id(),
        binding.revision(),
        AuthenticatedPrincipal::TrustedStdio,
        session_id,
    );
    let goal = RegisteredGoal::create(
        GoalId::from_uuid(Uuid::now_v7()),
        scope.workspace_id(),
        activity_id,
        GoalContract::new(
            GoalObjective::new("Integration proof".to_owned())?,
            vec![GoalStatement::new(
                "The headless flow survives a restart".to_owned(),
            )?],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )?,
        add_millis(now, 31)?,
    );
    let _ = stage(
        client.goal_create(scope.clone(), actor, goal.clone()),
        "integration goal_create",
    )?;
    let definition = DagNodeDefinition::new(
        DagNodeId::from_uuid(Uuid::now_v7()),
        DagNodeOrdinal::new(0)?,
        DagNodeTitle::new("Integrated work".to_owned())?,
        DagNodeObjective::new("One GUI-free flow".to_owned())?,
        vec![DagAcceptanceCriterion::new(
            "Restart keeps history".to_owned(),
        )?],
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
            scope: scope.clone(),
            request: plan,
        }),
        "integration dag plan commit",
    )?;
    let _ = stage(
        client.dag_node_start(DagNodeStartRequest {
            scope: scope.clone(),
            activity_id,
            session_id,
            principal: AuthenticatedPrincipal::TrustedStdio,
            goal_id: goal.id(),
            expected_goal_revision: goal.revision(),
            expected_dag_revision: DagRevisionNumber::INITIAL,
            node_id: pending.id(),
            expected_revision: pending.revision(),
            observed_at: add_millis(now, 34)?,
        }),
        "integration dag node start",
    )?;
    Ok(actor)
}

/// Compose one full server over the shared durable state.
async fn start_composition(shared: &Shared) -> Result<Composition, Box<dyn std::error::Error>> {
    let control = ForgeControl::new(GlobalRegistry::open_existing(&shared.registry_path)?);
    let (client, worker) = ForgeControlWorker::start(control)?;
    let (activity_leases, lease_worker) = ForgeControlWorker::start_activity_lease(
        ForgeControl::new(GlobalRegistry::open_existing(&shared.registry_path)?),
    )?;
    let execution = ForgeExecutionCoordinator::start(client.clone(), 2)?;
    let approval = ForgeApprovalCoordinator::start(client.clone(), execution.client())?;
    let execution_client = execution.client();
    let approval_client = approval.client();
    let product_cache = shared.root.join("product-cache");
    let state = assemble(
        BackendConfig::new(
            std::net::IpAddr::from([127, 0, 0, 1]),
            0,
            SECRET,
            forge_domain::ForgeBackendId::from_uuid(Uuid::from_u128(0xE001)),
            forge_domain::OrchestrationIssuerId::from_uuid(Uuid::from_u128(0xE002)),
        )?,
        forge_backend::http::BackendClients {
            control: &client,
            execution: &execution_client,
            approval: &approval_client,
            activity_leases: &activity_leases,
            runtime_instance_id: Uuid::now_v7(),
            product_cache_root: &product_cache,
            destination_id: Uuid::from_u128(0xE003),
        },
    )?;
    let address = serve(state.clone()).await?;
    Ok(Composition {
        state,
        address,
        worker,
        lease_worker,
        execution,
        approval,
    })
}

async fn shutdown_composition(composition: Composition) -> Result<(), Box<dyn std::error::Error>> {
    let Composition {
        state,
        mut worker,
        mut lease_worker,
        mut execution,
        mut approval,
        ..
    } = composition;
    let report = state.shutdown(Duration::from_secs(5)).await;
    assert!(report.is_successful(), "drain report: {report:?}");
    let _ = approval.shutdown();
    let _ = execution.shutdown();
    worker.shutdown()?;
    lease_worker.shutdown()?;
    Ok(())
}

async fn get_text(
    address: SocketAddr,
    path: &str,
) -> Result<(u16, String), Box<dyn std::error::Error>> {
    let mut stream = tokio::net::TcpStream::connect(address).await?;
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {SECRET}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
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
    Ok((status, body))
}

async fn get_json(
    address: SocketAddr,
    path: &str,
) -> Result<(u16, Value), Box<dyn std::error::Error>> {
    let mut stream = tokio::net::TcpStream::connect(address).await?;
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {SECRET}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
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

async fn post_ok(
    address: SocketAddr,
    op: &str,
    payload: Value,
) -> Result<Value, Box<dyn std::error::Error>> {
    let (status, response) = post_json(address, op, payload).await?;
    if status != 200 || response["ok"] != true {
        return Err(format!("{op} failed ({status}): {response}").into());
    }
    Ok(response["result"].clone())
}

async fn open_tail(
    address: SocketAddr,
    shared: &Shared,
    after: u64,
) -> Result<tokio::net::TcpStream, Box<dyn std::error::Error>> {
    let mut stream = tokio::net::TcpStream::connect(address).await?;
    let request = format!(
        "GET /api/v1/events/stream?{}&after={after} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {SECRET}\r\nAccept: text/event-stream\r\nConnection: close\r\n\r\n",
        scope_query(shared)
    );
    stream.write_all(request.as_bytes()).await?;
    Ok(stream)
}

async fn read_until(
    stream: &mut tokio::net::TcpStream,
    condition: impl Fn(&str) -> bool,
    budget: Duration,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut wire = Vec::new();
    let read_result = tokio::time::timeout(budget, async {
        let mut chunk = [0_u8; 4096];
        loop {
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(read) => {
                    wire.extend_from_slice(&chunk[..read]);
                    if condition(&String::from_utf8_lossy(&wire)) {
                        break;
                    }
                }
            }
        }
    })
    .await;
    if read_result.is_err() {
        let diagnostic_start = wire.len().saturating_sub(4096);
        return Err(format!(
            "stream read exceeded its budget; received {} bytes; wire tail: {:?}",
            wire.len(),
            String::from_utf8_lossy(&wire[diagnostic_start..])
        )
        .into());
    }
    Ok(String::from_utf8_lossy(&wire).into_owned())
}

/// Stage 4: acquire → readback(active) → release → readback(released) over
/// real HTTP, returning the durable lease identity.
async fn exercise_writer_lease(
    address: SocketAddr,
    shared: &Shared,
) -> Result<Uuid, Box<dyn std::error::Error>> {
    let lease_id = Uuid::now_v7();
    let lease_actor = json!({
        "session_id": shared.session_id.into_uuid(),
        "principal": { "kind": "trusted_stdio" },
        "agent_id": shared.agent_id.into_uuid(),
    });
    let acquired = post_ok(
        address,
        "writer_lease.acquire",
        json!({
            "scope": scope_json(shared),
            "activity_id": shared.activity_id.into_uuid(),
            "actor": lease_actor,
            "writer_lease_id": lease_id,
            "duration_ms": 60_000,
            "scopes": [{
                "kind": "exact_path",
                "path_base64": URL_SAFE_NO_PAD.encode(b"integration-flow.txt".as_slice()),
            }],
        }),
    )
    .await?;
    assert_eq!(acquired["status"], "active", "acquire: {acquired}");
    let revision = acquired["revision"]
        .as_i64()
        .ok_or("acquire revision missing")?;
    let mut seen = post_ok(
        address,
        "writer_lease.get",
        json!({ "scope": scope_json(shared), "writer_lease_id": lease_id }),
    )
    .await?;
    assert_eq!(seen["found"], true);
    assert_eq!(seen["status"], "active", "readback: {seen}");
    let released = post_ok(
        address,
        "writer_lease.release",
        json!({
            "scope": scope_json(shared),
            "activity_id": shared.activity_id.into_uuid(),
            "actor": lease_actor,
            "writer_lease_id": lease_id,
            "expected_revision": revision,
        }),
    )
    .await?;
    assert_eq!(released["status"], "released", "release: {released}");
    seen = post_ok(
        address,
        "writer_lease.get",
        json!({ "scope": scope_json(shared), "writer_lease_id": lease_id }),
    )
    .await?;
    assert_eq!(seen["found"], true);
    assert_eq!(seen["status"], "released", "readback after release: {seen}");
    Ok(lease_id)
}

/// Stage 5: publish one real planning write and prove the live tail
/// observes it after its cursor.
async fn observe_write_on_tail(
    address: SocketAddr,
    shared: &Shared,
    tail: &mut tokio::net::TcpStream,
    after: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let goal = RegisteredGoal::create(
        GoalId::from_uuid(Uuid::now_v7()),
        shared.scope.workspace_id(),
        shared.activity_id,
        GoalContract::new(
            GoalObjective::new("Observed while leased-free".to_owned())?,
            vec![GoalStatement::new("The tail sees this".to_owned())?],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )?,
        add_millis(timestamp_now()?, 1)?,
    );
    let goal_id = goal.id().into_uuid();
    publish_goal_through_control_worker(shared, goal, "publish observed goal")?;
    let observed = read_until(
        tail,
        |wire| wire.matches("\nid: ").count() >= 1,
        STREAM_READ_BUDGET,
    )
    .await;
    let observed = match observed {
        Ok(wire) => wire,
        Err(error) => {
            let durable = get_json(
                address,
                &format!("/api/v1/events?{}&after={after}", scope_query(shared)),
            )
            .await;
            return Err(format!(
                "SSE observation for goal {goal_id} after {after} failed: {error}; durable readback: {durable:?}"
            )
            .into());
        }
    };
    assert!(
        observed.contains("\nid: "),
        "tail observed the write: {observed}"
    );
    Ok(())
}

/// Stage 7: a fresh composition over the SAME durable state serves again,
/// replays the full event history, keeps the lease readback intact, and a
/// resumed tail observes a post-restart write.
async fn verify_restart(
    shared: &Shared,
    lease_id: Uuid,
    pre_shutdown_watermark: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let second = start_composition(shared).await?;
    let (status, health) = get_text(second.address, "/healthz").await?;
    assert_eq!(status, 200, "restarted healthz: {health}");
    assert_eq!(health.trim(), "ok");
    let (status, replay) = get_json(
        second.address,
        &format!("/api/v1/events?{}&after=0", scope_query(shared)),
    )
    .await?;
    assert_eq!(status, 200, "restart events: {replay}");
    let replayed = replay["result"]["events"]
        .as_array()
        .ok_or("restart events array missing")?;
    assert!(
        replayed.len() as u64 >= pre_shutdown_watermark,
        "restart replays the full durable history: {} < {pre_shutdown_watermark}",
        replayed.len()
    );
    let (lease_status, lease_reply) = post_json(
        second.address,
        "writer_lease.get",
        json!({ "scope": scope_json(shared), "writer_lease_id": lease_id }),
    )
    .await?;
    assert_eq!(lease_status, 200, "restart lease readback: {lease_reply}");
    assert_eq!(
        lease_reply["result"]["found"], true,
        "restart readback: {lease_reply}"
    );
    assert_eq!(
        lease_reply["result"]["status"], "released",
        "restart readback status: {lease_reply}"
    );
    let mut resumed = open_tail(second.address, shared, pre_shutdown_watermark).await?;
    let quiet = read_until(
        &mut resumed,
        |wire| wire.contains(": keepalive"),
        STREAM_READ_BUDGET,
    )
    .await?;
    assert!(
        quiet.contains("text/event-stream") && !quiet.contains("\nid: "),
        "resumed tail replays nothing at the cursor: {quiet}"
    );
    let resume_goal = RegisteredGoal::create(
        GoalId::from_uuid(Uuid::now_v7()),
        shared.scope.workspace_id(),
        shared.activity_id,
        GoalContract::new(
            GoalObjective::new("Post-restart write".to_owned())?,
            vec![GoalStatement::new(
                "Published after the restart".to_owned(),
            )?],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )?,
        add_millis(timestamp_now()?, 1)?,
    );
    publish_goal_through_control_worker(shared, resume_goal, "post-restart goal_create")?;
    let resumed_wire = read_until(
        &mut resumed,
        |wire| wire.matches("\nid: ").count() >= 1,
        STREAM_READ_BUDGET,
    )
    .await?;
    assert!(
        resumed_wire.contains("\nid: "),
        "resumed tail observes the post-restart write: {resumed_wire}"
    );
    shutdown_composition(second).await?;
    Ok(())
}

/// 산출물 5: the single GUI-free flow, end to end.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn headless_flow_serves_observes_shuts_down_and_recovers()
-> Result<(), Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!(
        "heterarchy-forge-backend-integration-{}-{}",
        std::process::id(),
        Uuid::now_v7()
    ));
    fs::create_dir_all(&root)?;
    let shared = prepare_shared(&root)?;

    // ── 1. serve: liveness, readiness, capability ──────────────────────────
    let first = start_composition(&shared).await?;
    let (status, health) = get_text(first.address, "/healthz").await?;
    assert_eq!(status, 200, "healthz: {health}");
    assert_eq!(health.trim(), "ok", "healthz body: {health}");
    let (status, ready) = get_json(first.address, "/readyz").await?;
    assert_eq!(status, 200, "readyz: {ready}");
    assert_eq!(ready["ready"], true, "ready: {ready}");
    let (status, capability) = get_json(first.address, "/api/v1/capability").await?;
    assert_eq!(status, 200, "capability: {capability}");
    assert!(
        capability["supported_ops"].as_array().is_some(),
        "capability ops: {capability}"
    );
    println!("stage-1 serve: healthz=ok ready=true capability=ok");

    // ── 2. durable workspace evidence through reads ────────────────────────
    let (status, page) = get_json(
        first.address,
        &format!("/api/v1/events?{}&after=0", scope_query(&shared)),
    )
    .await?;
    assert_eq!(status, 200, "events page: {page}");
    let events = page["result"]["events"]
        .as_array()
        .ok_or("events array missing")?;
    assert!(!events.is_empty(), "planning events are durable");
    let (status, snapshot) = get_json(
        first.address,
        &format!("/api/v1/snapshot?{}", scope_query(&shared)),
    )
    .await?;
    assert_eq!(status, 200, "snapshot: {snapshot}");
    let watermark = snapshot["result"]["watermark_seq"]
        .as_u64()
        .ok_or("watermark missing")?;
    assert!(watermark >= 1, "watermark: {snapshot}");
    println!(
        "stage-2 durable-reads: events={} watermark={watermark}",
        events.len()
    );

    // ── 3. live SSE tail at the watermark ──────────────────────────────────
    let mut tail = open_tail(first.address, &shared, watermark).await?;
    let initial = read_until(
        &mut tail,
        |wire| wire.contains(": keepalive"),
        STREAM_READ_BUDGET,
    )
    .await?;
    assert!(
        initial.contains("text/event-stream") && !initial.contains("\nid: "),
        "tail replays nothing at the watermark: {initial}"
    );
    println!("stage-3 sse-tail: connected at watermark, silent");

    let lease_id = exercise_writer_lease(first.address, &shared).await?;
    println!("stage-4 writer-lease: acquire→get(active)→release→get(released)");

    // ── 5. a real planning write observed on the SSE tail ──────────────────
    let pre_publish_watermark = watermark;
    observe_write_on_tail(first.address, &shared, &mut tail, watermark).await?;
    println!("stage-5 sse-observation: new frames after watermark {pre_publish_watermark}");

    // ── 6. graceful shutdown: drain + one terminal frame ───────────────────
    let (status, pre_shutdown_snapshot) = get_json(
        first.address,
        &format!("/api/v1/snapshot?{}", scope_query(&shared)),
    )
    .await?;
    assert_eq!(status, 200);
    let pre_shutdown_watermark = pre_shutdown_snapshot["result"]["watermark_seq"]
        .as_u64()
        .ok_or("pre-shutdown watermark missing")?;
    shutdown_composition(first).await?;
    let terminal = read_until(
        &mut tail,
        |wire| wire.contains("server shutdown; reconnect and resume from your cursor"),
        STREAM_READ_BUDGET,
    )
    .await?;
    assert_eq!(
        terminal
            .matches("server shutdown; reconnect and resume from your cursor")
            .count(),
        1,
        "exactly one terminal frame: {terminal}"
    );
    println!("stage-6 shutdown: drained, one terminal frame, watermark={pre_shutdown_watermark}");

    // ── 7. restart over the SAME durable state ─────────────────────────────
    verify_restart(&shared, lease_id, pre_shutdown_watermark).await?;
    println!("integration-flow: PASS (all stages)");

    fs::remove_dir_all(&root)?;
    Ok(())
}
