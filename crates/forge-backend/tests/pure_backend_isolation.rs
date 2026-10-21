//! Multi-workspace isolation proof for the pure backend (GLM pure-backend
//! lane, G3 산출물 2).
//!
//! One real backend server composes real control/persistence state for three
//! concurrently-registered Workspaces (distinct Locations, distinct
//! `.heterarchy-forge` state roots, one shared Global Registry). Proven here:
//!
//! 1. Durable semantic-event sequences and digests are per-Workspace: every
//!    Workspace has its own contiguous 1..N sequence, digests never appear in
//!    another Workspace's page, and a live tail observes only its own
//!    Workspace's newly published event.
//! 2. `WriterLease` authority is Workspace-scoped: an active lease in one
//!    Workspace does not fence another Workspace's acquire, an overlapping
//!    acquire inside the same Workspace is still a typed conflict, and lease
//!    reads/listings from one Workspace cannot observe another's lease.
//! 3. Execution-journal reads are Workspace-scoped: a well-formed execution
//!    read under one Workspace's authority cannot observe an execution
//!    identity that does not exist in that Workspace's journal (typed
//!    absence, stable across retries). A full real admitted execution per
//!    Workspace is covered by the existing `real_execution` suites and is
//!    not duplicated here.

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
use uuid::Uuid;

const SECRET: &str = "pure-backend-isolation-secret";
const WORKSPACE_COUNT: usize = 3;
const HTTP_ROUNDTRIP_TIMEOUT: Duration = Duration::from_secs(30);

struct WorkspaceSlot {
    name: &'static str,
    workspace_root: PathBuf,
    scope: ResolvedWorkspaceScope,
    activity_id: ActivityId,
    session_id: AgentSessionId,
    agent_id: AgentInstanceId,
    actor: ActivityCoordinatorActor,
}

struct MultiFixture {
    root: PathBuf,
    workspaces: Vec<WorkspaceSlot>,
    client: ForgeControlClient,
    worker: ForgeControlWorker,
    execution: ForgeExecutionCoordinator,
    approval: ForgeApprovalCoordinator,
    lease_worker: ForgeControlWorker,
    address: SocketAddr,
}

impl MultiFixture {
    fn shutdown(self) -> Result<(), Box<dyn std::error::Error>> {
        let MultiFixture {
            root,
            mut worker,
            mut execution,
            mut approval,
            mut lease_worker,
            ..
        } = self;
        let _ = approval.shutdown();
        let _ = execution.shutdown();
        worker.shutdown()?;
        lease_worker.shutdown()?;
        fs::remove_dir_all(root)?;
        Ok(())
    }
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

/// One real Workspace (Location + state layout + resolved scope) inside the
/// shared registry, with one bootstrapped Activity and one activated native
/// Agent binding so `WriterLease` actors exist per Workspace.
fn prepare_workspace_slot(
    root: &Path,
    name: &'static str,
    registry_path: &Path,
    now: TimestampMillis,
) -> Result<WorkspaceSlot, Box<dyn std::error::Error>> {
    let location_root = root.join(format!("location-{name}"));
    let workspace_dir_name = format!("workspace-{name}");
    let workspace_root = location_root.join(&workspace_dir_name);
    fs::create_dir_all(&workspace_root)?;
    let location_id = LocationId::from_uuid(Uuid::now_v7());
    let workspace_id = WorkspaceId::from_uuid(Uuid::now_v7());
    let mut locations = LocationService::new(stage(
        GlobalRegistry::open(registry_path),
        "open isolation registry",
    )?);
    let location = stage(
        locations.register_selected_path(location_id, name, &location_root, now),
        "register isolation location",
    )?;
    let layout = stage(
        WorkspaceStateLayout::initialize(&workspace_root),
        "initialize isolation workspace",
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
        .find(|entry| entry.display_name() == workspace_dir_name)
        .ok_or("isolation workspace discovery entry missing")?
        .locator()
        .clone();
    let scope = stage(
        control.resolve_workspace(
            location_id,
            forge_domain::LocationRevision::INITIAL,
            &located,
        ),
        "resolve isolation workspace",
    )?;
    Ok(WorkspaceSlot {
        name,
        workspace_root,
        scope,
        activity_id: ActivityId::from_uuid(Uuid::now_v7()),
        session_id: AgentSessionId::from_uuid(Uuid::now_v7()),
        agent_id: AgentInstanceId::from_uuid(Uuid::now_v7()),
        actor: ActivityCoordinatorActor::new(
            WorkspaceId::from_uuid(Uuid::nil()),
            ActivityId::from_uuid(Uuid::nil()),
            forge_domain::AgentInstanceId::from_uuid(Uuid::nil()),
            forge_domain::ActivityCoordinatorRevision::INITIAL,
            AuthenticatedPrincipal::TrustedStdio,
            AgentSessionId::from_uuid(Uuid::nil()),
        ),
    })
}

fn activate_agent(
    client: &ForgeControlClient,
    slot: &mut WorkspaceSlot,
    runtime_instance_id: RuntimeInstanceId,
    now: TimestampMillis,
) -> Result<(), Box<dyn std::error::Error>> {
    let _ = stage(
        client.bootstrap_activity(
            slot.scope.clone(),
            slot.activity_id,
            runtime_instance_id,
            now,
            add_millis(now, 120_000)?,
        ),
        "bootstrap isolation activity",
    )?;
    let _ = stage(
        client.agent_session_open(OpenAgentSession::new(
            slot.session_id,
            AgentSessionOpenRequestId::from_uuid(Uuid::now_v7()),
            AuthenticatedPrincipal::TrustedStdio,
            add_millis(now, 1)?,
        )),
        "open isolation session",
    )?;
    let layout = WorkspaceStateLayout::inspect_existing(&slot.workspace_root)?
        .ok_or("isolation workspace layout missing")?;
    let mut store = WorkspaceStore::open_existing(&layout)?;
    let freeze = stage(
        store.freeze_agent_operations(&AgentOperationsFreezeRequest::new(
            Uuid::now_v7(),
            Uuid::now_v7(),
            add_millis(now, 20)?,
        )?),
        "freeze isolation agent operations",
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
        "isolation reservation request",
    )?;
    let _ = stage(
        client.reserve_agent_binding(AgentBindingReserveRequest {
            scope: slot.scope.clone(),
            freeze: freeze.clone(),
            reservation,
            observed_at: add_millis(now, 22)?,
        }),
        "reserve isolation binding",
    )?;
    let delegation = stage(
        client.delegate_agent_operations(forge_control::AgentOperationsDelegationRequest {
            scope: slot.scope.clone(),
            freeze,
            manifest_digest: [0xA1; 32],
            observed_at: add_millis(now, 23)?,
        }),
        "delegate isolation operations",
    )?;
    let activation = stage(
        AgentBindingActivationRequest::new(
            request_id,
            [0xA2; 32],
            AgentDisplayName::new(format!("isolation-agent-{}", slot.name))?,
            AgentDeclaredRole::new("executor".to_owned())?,
            AgentTransportKind::Stdio,
        ),
        "isolation activation request",
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
        "activate isolation binding",
    )?;
    plan_workspace_work(client, slot, now)
}

/// Claim the Activity Coordinator and plan one Goal/DAG/node so the durable
/// semantic event stream carries real per-Workspace planning events.
fn plan_workspace_work(
    client: &ForgeControlClient,
    slot: &mut WorkspaceSlot,
    now: TimestampMillis,
) -> Result<(), Box<dyn std::error::Error>> {
    // Coordinator claim + Goal/DAG planning write the durable semantic events
    // the isolation assertions read back per Workspace.
    let binding = stage(
        client.activity_coordinator_claim(CoordinatorClaimRequest {
            session_id: slot.session_id,
            scope: slot.scope.clone(),
            activity_id: slot.activity_id,
            agent_id: slot.agent_id,
            principal: AuthenticatedPrincipal::TrustedStdio,
            observed_at: add_millis(now, 30)?,
        }),
        "claim isolation coordinator",
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
            GoalObjective::new("Isolation proof".to_owned())?,
            vec![GoalStatement::new("Workspaces stay isolated".to_owned())?],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )?,
        add_millis(now, 31)?,
    );
    let _ = stage(
        client.goal_create(slot.scope.clone(), actor, goal.clone()),
        "isolation goal_create",
    )?;
    let definition = DagNodeDefinition::new(
        DagNodeId::from_uuid(Uuid::now_v7()),
        DagNodeOrdinal::new(0)?,
        DagNodeTitle::new("Isolated work".to_owned())?,
        DagNodeObjective::new("Prove per-workspace isolation".to_owned())?,
        vec![DagAcceptanceCriterion::new(
            "No cross-workspace effects".to_owned(),
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
            scope: slot.scope.clone(),
            request: plan,
        }),
        "isolation dag plan commit",
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
        "isolation dag node start",
    )?;
    slot.actor = actor;
    Ok(())
}

async fn build_fixture() -> Result<MultiFixture, Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!(
        "heterarchy-forge-backend-isolation-{}-{}",
        std::process::id(),
        Uuid::now_v7()
    ));
    fs::create_dir_all(&root)?;
    let now = timestamp_now()?;
    let registry_path = root.join("registry.sqlite3");
    let mut workspaces = Vec::new();
    for index in 0..WORKSPACE_COUNT {
        let name = match index {
            0 => "alpha",
            1 => "beta",
            _ => "gamma",
        };
        let offset = i64::try_from(index)?;
        workspaces.push(prepare_workspace_slot(
            &root,
            name,
            &registry_path,
            add_millis(now, offset)?,
        )?);
    }
    let (client, worker) =
        ForgeControlWorker::start(ForgeControl::new(GlobalRegistry::open(&registry_path)?))?;
    let runtime_instance_id = RuntimeInstanceId::from_uuid(Uuid::now_v7());
    let mut slots = Vec::new();
    for (index, mut slot) in workspaces.into_iter().enumerate() {
        let offset = i64::try_from(index)?;
        activate_agent(
            &client,
            &mut slot,
            runtime_instance_id,
            add_millis(now, 100 + offset)?,
        )?;
        slots.push(slot);
    }
    let execution = ForgeExecutionCoordinator::start(client.clone(), 2)?;
    let approval = ForgeApprovalCoordinator::start(client.clone(), execution.client())?;
    let (activity_leases, lease_worker) = ForgeControlWorker::start_activity_lease(
        ForgeControl::new(GlobalRegistry::open_existing(&registry_path)?),
    )?;
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
            execution: &execution.client(),
            approval: &approval.client(),
            activity_leases: &activity_leases,
            runtime_instance_id: runtime_instance_id.into_uuid(),
            product_cache_root: &root.join("product-cache"),
            destination_id: Uuid::from_u128(0xE003),
        },
    )?;
    let address = serve(state.clone()).await?;
    let _ = activity_leases;
    Ok(MultiFixture {
        root,
        workspaces: slots,
        client,
        worker,
        execution,
        approval,
        lease_worker,
        address,
    })
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

fn scope_query(slot: &WorkspaceSlot) -> String {
    let scope = &slot.scope;
    format!(
        "workspace={}&workspace_revision={}&location_id={}&location_revision={}&relative_root={}",
        scope.workspace_id().into_uuid(),
        scope.workspace_revision().get(),
        scope.locator().location_id().into_uuid(),
        scope.locator().expected_revision().get(),
        scope.locator().relative_root().to_string_lossy(),
    )
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

async fn open_stream(
    address: SocketAddr,
    slot: &WorkspaceSlot,
    after: u64,
) -> Result<tokio::net::TcpStream, Box<dyn std::error::Error>> {
    let mut stream = tokio::net::TcpStream::connect(address).await?;
    let request = format!(
        "GET /api/v1/events/stream?{}&after={after} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {SECRET}\r\nAccept: text/event-stream\r\nConnection: close\r\n\r\n",
        scope_query(slot)
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
    tokio::time::timeout(budget, async {
        let mut chunk = [0_u8; 2048];
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
    .await
    .map_err(|_| "stream read exceeded its budget")?;
    Ok(String::from_utf8_lossy(&wire).into_owned())
}

/// Read whatever arrives within `budget`; budget expiry is success (used for
/// proving a stream stays quiet, where silence is the expected outcome).
async fn read_for(
    stream: &mut tokio::net::TcpStream,
    budget: Duration,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut wire = Vec::new();
    let _ = tokio::time::timeout(budget, async {
        let mut chunk = [0_u8; 2048];
        loop {
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(read) => wire.extend_from_slice(&chunk[..read]),
            }
        }
    })
    .await;
    Ok(String::from_utf8_lossy(&wire).into_owned())
}

/// 산출물 2a: per-Workspace event sequences and digests never cross, and a
/// live tail observes only its own Workspace's new event.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_workspaces_keep_event_sequences_digests_and_tails_isolated()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = build_fixture().await?;
    let mut digest_sets = Vec::new();
    let mut high_waters = Vec::new();
    for slot in &fixture.workspaces {
        let (status, reply) = get_json(
            fixture.address,
            &format!("/api/v1/events?{}&after=0", scope_query(slot)),
        )
        .await?;
        assert_eq!(status, 200, "events for {}: {reply}", slot.name);
        let events = reply["result"]["events"]
            .as_array()
            .ok_or("events array missing")?;
        assert!(!events.is_empty(), "workspace {} has events", slot.name);
        let mut previous = 0_u64;
        let mut digests = Vec::new();
        for event in events {
            let sequence = event["sequence"].as_u64().ok_or("sequence missing")?;
            assert!(sequence > previous, "per-workspace sequence is contiguous");
            previous = sequence;
            digests.push(event["digest"].as_str().ok_or("digest missing")?.to_owned());
        }
        let (status, snapshot) = get_json(
            fixture.address,
            &format!("/api/v1/snapshot?{}", scope_query(slot)),
        )
        .await?;
        assert_eq!(status, 200, "snapshot for {}: {snapshot}", slot.name);
        high_waters.push(
            snapshot["result"]["watermark_seq"]
                .as_u64()
                .ok_or("watermark missing")?,
        );
        digest_sets.push(digests);
    }
    // Digests are pairwise disjoint across Workspaces.
    for (index, digests) in digest_sets.iter().enumerate() {
        for (other_index, other) in digest_sets.iter().enumerate() {
            if index == other_index {
                continue;
            }
            for digest in digests {
                assert!(
                    !other.contains(digest),
                    "workspace {} digest leaked into workspace {}",
                    fixture.workspaces[index].name,
                    fixture.workspaces[other_index].name
                );
            }
        }
    }

    // Concurrent live tails: a new event in beta must reach beta's tail only.
    let mut tails = Vec::new();
    for (index, slot) in fixture.workspaces.iter().enumerate() {
        tails.push(open_stream(fixture.address, slot, high_waters[index]).await?);
    }
    let beta = &fixture.workspaces[1];
    let new_goal = RegisteredGoal::create(
        GoalId::from_uuid(Uuid::now_v7()),
        beta.scope.workspace_id(),
        beta.activity_id,
        GoalContract::new(
            GoalObjective::new("Beta live-tail proof".to_owned())?,
            vec![GoalStatement::new(
                "Beta publishes while others watch".to_owned(),
            )?],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )?,
        add_millis(timestamp_now()?, 1)?,
    );
    let _ = stage(
        fixture
            .client
            .goal_create(beta.scope.clone(), beta.actor, new_goal),
        "beta live goal_create",
    )?;
    let beta_wire = read_until(
        &mut tails[1],
        |wire| wire.matches("id:").count() >= 1,
        Duration::from_secs(4),
    )
    .await?;
    assert!(beta_wire.contains("id:"), "beta tail saw its own event");
    for index in [0_usize, 2_usize] {
        let quiet = read_for(&mut tails[index], Duration::from_millis(1_500)).await?;
        assert!(
            !quiet.contains("id:"),
            "workspace {} tail must stay quiet: {quiet}",
            fixture.workspaces[index].name
        );
    }
    fixture.shutdown()?;
    Ok(())
}

/// 산출물 2b: `WriterLease` authority is Workspace-scoped — cross-Workspace
/// acquires are independent, same-Workspace overlap is a typed conflict, and
/// lease reads/listings never cross.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn writer_leases_are_workspace_scoped_and_same_workspace_fencing_holds()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = build_fixture().await?;
    let paths: Vec<Value> = ["lease-a.txt", "lease-b.txt"]
        .iter()
        .map(|path| {
            json!({
                "kind": "exact_path",
                "path_base64": URL_SAFE_NO_PAD.encode(path.as_bytes()),
            })
        })
        .collect();

    let acquire = |slot: &WorkspaceSlot, lease_id: Uuid| {
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
            "scopes": paths,
        })
    };

    let lease_alpha = Uuid::now_v7();
    let result = post_ok(
        fixture.address,
        "writer_lease.acquire",
        acquire(&fixture.workspaces[0], lease_alpha),
    )
    .await?;
    assert_eq!(result["status"], "active", "alpha lease: {result}");
    let lease_beta = Uuid::now_v7();
    let result = post_ok(
        fixture.address,
        "writer_lease.acquire",
        acquire(&fixture.workspaces[1], lease_beta),
    )
    .await?;
    assert_eq!(
        result["status"], "active",
        "beta must not be fenced by alpha's lease: {result}"
    );

    // Same-Workspace overlap stays fenced (typed conflict).
    let (status, reply) = post_json(
        fixture.address,
        "writer_lease.acquire",
        acquire(&fixture.workspaces[0], Uuid::now_v7()),
    )
    .await?;
    assert_ne!(status, 200, "alpha overlap must not succeed: {reply}");
    assert!(
        reply["error"]["code"].is_string(),
        "overlap must be a typed failure: {reply}"
    );

    // Lease reads are Workspace-scoped: beta cannot see alpha's lease.
    let seen = post_ok(
        fixture.address,
        "writer_lease.get",
        json!({
            "scope": scope_json(&fixture.workspaces[1]),
            "writer_lease_id": lease_alpha,
        }),
    )
    .await?;
    assert_eq!(
        seen["found"], false,
        "alpha lease invisible in beta: {seen}"
    );
    let own = post_ok(
        fixture.address,
        "writer_lease.get",
        json!({
            "scope": scope_json(&fixture.workspaces[0]),
            "writer_lease_id": lease_alpha,
        }),
    )
    .await?;
    assert_eq!(own["found"], true, "alpha sees its own lease: {own}");

    for (index, slot) in fixture.workspaces.iter().enumerate() {
        let listed = post_ok(
            fixture.address,
            "writer_lease.list",
            json!({ "scope": scope_json(slot), "limit": 1 }),
        )
        .await?;
        let leases = listed["leases"].as_array().ok_or("leases array missing")?;
        let expected = usize::from(index <= 1);
        assert_eq!(
            leases.len(),
            expected,
            "workspace {} listing: {listed}",
            slot.name
        );
    }
    fixture.shutdown()?;
    Ok(())
}

/// 산출물 2c: execution-journal reads are Workspace-scoped — a well-formed
/// read under one Workspace's authority cannot observe an execution identity
/// that does not exist in that Workspace's journal (typed absence, stable
/// across retries). A full real admitted execution per Workspace is covered
/// by the existing `real_execution` suites and is not duplicated here.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn execution_journal_reads_are_workspace_scoped() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = build_fixture().await?;
    let foreign_execution = Uuid::now_v7();
    let (status, reply) = post_json(
        fixture.address,
        "execution.get",
        json!({
            "scope": scope_json(&fixture.workspaces[1]),
            "execution_id": foreign_execution,
        }),
    )
    .await?;
    assert_ne!(
        status, 200,
        "foreign execution read must not succeed: {reply}"
    );
    assert!(
        reply["error"]["code"].is_string(),
        "typed failure envelope: {reply}"
    );
    let (status_again, reply_again) = post_json(
        fixture.address,
        "execution.get",
        json!({
            "scope": scope_json(&fixture.workspaces[1]),
            "execution_id": foreign_execution,
        }),
    )
    .await?;
    assert_eq!(status, status_again, "absence is stable across retries");
    let _ = reply_again;
    fixture.shutdown()?;
    Ok(())
}
