//! Representative-load measurement suite for the pure backend (GLM
//! pure-backend lane, G3 산출물 4).
//!
//! Every scenario drives a REAL composition (registry + control worker +
//! coordinators + a real loopback listener + real SQLite reads/writes) and
//! RECORDS measured distributions. Nothing asserts an absolute performance
//! number: the only assertions are structural (typed replies, durable
//! budget constants, fencing outcomes) plus one hang-detector ceiling.
//! Machine context and peak-RSS sampling are printed alongside the raw
//! numbers so every figure carries its provenance. Run explicitly:
//!
//! ```text
//! cargo test --locked -p forge-backend --test pure_backend_load \
//!   -- --ignored --nocapture
//! ```

use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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

const SECRET: &str = "pure-backend-load-secret";
const HTTP_ROUNDTRIP_TIMEOUT: Duration = Duration::from_secs(30);
/// Hang-detector ceiling only — never a performance assertion.
const P99_SANITY_CEILING: Duration = Duration::from_secs(5);
/// Durable page budget from the product constants; the readback scenario
/// asserts responses stay within it.
const MAX_EVENT_PAGE_ROWS: u32 = forge_backend::config::MAX_EVENT_PAGE_ROWS;

struct WorkspaceSlot {
    workspace_root: PathBuf,
    scope: ResolvedWorkspaceScope,
    activity_id: ActivityId,
    session_id: AgentSessionId,
    agent_id: AgentInstanceId,
    actor: ActivityCoordinatorActor,
}

struct LoadFixture {
    root: PathBuf,
    workspace: WorkspaceSlot,
    client: ForgeControlClient,
    worker: ForgeControlWorker,
    execution: ForgeExecutionCoordinator,
    approval: ForgeApprovalCoordinator,
    state: forge_backend::AppState,
    address: SocketAddr,
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
        locations.register_selected_path(location_id, "load", &location_root, now),
        "register load location",
    )?;
    let layout = stage(
        WorkspaceStateLayout::initialize(&workspace_root),
        "initialize load workspace",
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
        .ok_or("load workspace discovery entry missing")?
        .locator()
        .clone();
    let scope = stage(
        control.resolve_workspace(
            location_id,
            forge_domain::LocationRevision::INITIAL,
            &located,
        ),
        "resolve load workspace",
    )?;
    Ok((scope, workspace_root))
}

fn open_and_bind_workspace(
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
            add_millis(now, 600_000)?,
        ),
        "bootstrap load activity",
    )?;
    let _ = stage(
        client.agent_session_open(OpenAgentSession::new(
            slot.session_id,
            AgentSessionOpenRequestId::from_uuid(Uuid::now_v7()),
            AuthenticatedPrincipal::TrustedStdio,
            add_millis(now, 1)?,
        )),
        "open load session",
    )?;
    let layout = WorkspaceStateLayout::inspect_existing(&slot.workspace_root)?
        .ok_or("load workspace layout missing")?;
    let mut store = WorkspaceStore::open_existing(&layout)?;
    let freeze = stage(
        store.freeze_agent_operations(&AgentOperationsFreezeRequest::new(
            Uuid::now_v7(),
            Uuid::now_v7(),
            add_millis(now, 20)?,
        )?),
        "freeze load agent operations",
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
        "load reservation request",
    )?;
    let _ = stage(
        client.reserve_agent_binding(AgentBindingReserveRequest {
            scope: slot.scope.clone(),
            freeze: freeze.clone(),
            reservation,
            observed_at: add_millis(now, 22)?,
        }),
        "reserve load binding",
    )?;
    let delegation = stage(
        client.delegate_agent_operations(forge_control::AgentOperationsDelegationRequest {
            scope: slot.scope.clone(),
            freeze,
            manifest_digest: [0xA1; 32],
            observed_at: add_millis(now, 23)?,
        }),
        "delegate load operations",
    )?;
    let activation = stage(
        AgentBindingActivationRequest::new(
            request_id,
            [0xA2; 32],
            AgentDisplayName::new("load-agent".to_owned())?,
            AgentDeclaredRole::new("executor".to_owned())?,
            AgentTransportKind::Stdio,
        ),
        "load activation request",
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
        "activate load binding",
    )?;
    Ok(())
}

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
        "claim load coordinator",
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
            GoalObjective::new("Load proof".to_owned())?,
            vec![GoalStatement::new(
                "Measurements have provenance".to_owned(),
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
        "load goal_create",
    )?;
    let definition = DagNodeDefinition::new(
        DagNodeId::from_uuid(Uuid::now_v7()),
        DagNodeOrdinal::new(0)?,
        DagNodeTitle::new("Load work".to_owned())?,
        DagNodeObjective::new("Load scenario".to_owned())?,
        vec![DagAcceptanceCriterion::new("Measured".to_owned())?],
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
        "load dag plan commit",
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
        "load dag node start",
    )?;
    slot.actor = actor;
    Ok(())
}

async fn build_fixture(sse_poll: Duration) -> Result<LoadFixture, Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!(
        "heterarchy-forge-backend-load-{}-{}",
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
    open_and_bind_workspace(
        &client,
        &mut slot,
        runtime_instance_id,
        add_millis(now, 100)?,
    )?;
    plan_workspace_work(&client, &mut slot, add_millis(now, 200)?)?;
    let execution = ForgeExecutionCoordinator::start(client.clone(), 2)?;
    let approval = ForgeApprovalCoordinator::start(client.clone(), execution.client())?;
    let (activity_leases, _lease_worker) = ForgeControlWorker::start_activity_lease(
        ForgeControl::new(GlobalRegistry::open_existing(&registry_path)?),
    )?;
    let execution_client = execution.client();
    let approval_client = approval.client();
    let product_cache = root.join("product-cache");
    let config = BackendConfig::new(
        std::net::IpAddr::from([127, 0, 0, 1]),
        0,
        SECRET,
        forge_domain::ForgeBackendId::from_uuid(Uuid::from_u128(0xE001)),
        forge_domain::OrchestrationIssuerId::from_uuid(Uuid::from_u128(0xE002)),
    )?
    .with_sse_poll_interval(sse_poll);
    let state = assemble(
        config,
        forge_backend::http::BackendClients {
            control: &client,
            execution: &execution_client,
            approval: &approval_client,
            activity_leases: &activity_leases,
            runtime_instance_id: runtime_instance_id.into_uuid(),
            product_cache_root: &product_cache,
            destination_id: Uuid::from_u128(0xE003),
        },
    )?;
    let address = serve(state.clone()).await?;
    Ok(LoadFixture {
        root,
        workspace: slot,
        client,
        worker,
        execution,
        approval,
        state,
        address,
    })
}

impl LoadFixture {
    fn shutdown(self) -> Result<(), Box<dyn std::error::Error>> {
        let LoadFixture {
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

async fn get_bytes(
    address: SocketAddr,
    path: &str,
) -> Result<(u16, Vec<u8>), Box<dyn std::error::Error>> {
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
        .map(|(_, body)| body.as_bytes().to_vec())
        .unwrap_or_default();
    Ok((status, body))
}

/// rank = ceil(`per_mille` * n / 1000), clamped into 1..=n in the integer
/// domain — no float conversions on the measurement path.
fn percentile(sorted: &[u128], per_mille: u32) -> u128 {
    let n = sorted.len() as u128;
    let rank = n
        .checked_mul(u128::from(per_mille))
        .map_or(n, |scaled| scaled.div_ceil(1000))
        .clamp(1, n);
    sorted[usize::try_from(rank).unwrap_or(sorted.len()) - 1]
}

fn print_percentiles(label: &str, mut samples: Vec<u128>) {
    samples.sort_unstable();
    let count = samples.len();
    if count == 0 {
        println!("{label}: no samples");
        return;
    }
    println!(
        "{label}: n={count} min={}us p50={}us p95={}us p99={}us max={}us",
        samples[0],
        percentile(&samples, 500),
        percentile(&samples, 950),
        percentile(&samples, 990),
        samples[count - 1],
    );
}

/// Sample this process's RSS in KiB every `interval` until `stop` flips and
/// return the observed peak. External sampling via ps; the granularity is
/// part of the number's provenance.
fn spawn_rss_sampler(stop: Arc<AtomicBool>, interval: Duration) -> std::thread::JoinHandle<u64> {
    std::thread::spawn(move || {
        let pid = std::process::id();
        let mut peak = 0_u64;
        while !stop.load(Ordering::Acquire) {
            if let Ok(output) = std::process::Command::new("/bin/ps")
                .args(["-o", "rss=", "-p", &pid.to_string()])
                .output()
            {
                let text = String::from_utf8_lossy(&output.stdout);
                if let Ok(kib) = text.trim().parse::<u64>() {
                    peak = peak.max(kib);
                }
            }
            std::thread::sleep(interval);
        }
        peak
    })
}

fn print_machine_context() {
    let product = std::process::Command::new("/usr/sbin/sysctl")
        .args(["-n", "machdep.cpu.brand_string"])
        .output()
        .ok()
        .map_or_else(
            || "unknown-cpu".to_owned(),
            |output| String::from_utf8_lossy(&output.stdout).trim().to_owned(),
        );
    let version = std::process::Command::new("/usr/bin/sw_vers")
        .args(["-productVersion"])
        .output()
        .ok()
        .map_or_else(
            || "unknown-os".to_owned(),
            |output| String::from_utf8_lossy(&output.stdout).trim().to_owned(),
        );
    println!(
        "machine-context: os=macOS {version} cpu={product} pid={} at={:?}",
        std::process::id(),
        SystemTime::now()
    );
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
        "duration_ms": 60_000,
        "scopes": [{
            "kind": "exact_path",
            "path_base64": URL_SAFE_NO_PAD.encode(path.as_bytes()),
        }],
    })
}

fn lease_release_payload(slot: &WorkspaceSlot, lease_id: Uuid, revision: i64) -> Value {
    json!({
        "scope": scope_json(slot),
        "activity_id": slot.activity_id.into_uuid(),
        "actor": {
            "session_id": slot.session_id.into_uuid(),
            "principal": { "kind": "trusted_stdio" },
            "agent_id": slot.agent_id.into_uuid(),
        },
        "writer_lease_id": lease_id,
        "expected_revision": revision,
    })
}

/// S1: command roundtrip percentiles — 2000 sequential bounded reads
/// (`writer_lease.get` on an absent id: a real SQLite-backed bridge
/// command), then 32 concurrent workers × 100 reads each.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "load measurement; run explicitly with --ignored --nocapture"]
async fn load_command_roundtrip_percentiles() -> Result<(), Box<dyn std::error::Error>> {
    print_machine_context();
    let fixture = build_fixture(Duration::from_millis(50)).await?;
    let stop = Arc::new(AtomicBool::new(false));
    let rss = spawn_rss_sampler(Arc::clone(&stop), Duration::from_millis(100));

    let read_payload = json!({
        "scope": scope_json(&fixture.workspace),
        "writer_lease_id": Uuid::now_v7(),
    });
    for _ in 0..100 {
        post_ok(fixture.address, "writer_lease.get", read_payload.clone()).await?;
    }

    let mut sequential = Vec::new();
    for _ in 0..2000 {
        let started = Instant::now();
        post_ok(fixture.address, "writer_lease.get", read_payload.clone()).await?;
        sequential.push(started.elapsed().as_micros());
    }
    print_percentiles("S1-sequential writer_lease.get", sequential.clone());
    assert!(
        Duration::from_micros(u64::try_from(sequential[sequential.len() - 1]).unwrap_or(u64::MAX))
            < P99_SANITY_CEILING,
        "sequential reads hit the hang-detector ceiling"
    );

    let concurrent: Arc<Mutex<Vec<u128>>> = Arc::new(Mutex::new(Vec::new()));
    let mut workers = tokio::task::JoinSet::new();
    for _ in 0..32 {
        let shared = Arc::clone(&concurrent);
        let address = fixture.address;
        let payload = read_payload.clone();
        workers.spawn(async move {
            for _ in 0..100 {
                let started = Instant::now();
                let outcome = post_json(address, "writer_lease.get", payload.clone()).await;
                let elapsed = started.elapsed().as_micros();
                if let Ok((200, reply)) = outcome
                    && reply["ok"] == true
                    && let Ok(mut samples) = shared.lock()
                {
                    samples.push(elapsed);
                }
            }
        });
    }
    while workers.join_next().await.is_some() {}
    let concurrent_samples = Arc::try_unwrap(concurrent)
        .map_err(|_| "concurrent sample lock leaked")?
        .into_inner()
        .map_err(|_| "sample lock poisoned")?;
    assert_eq!(
        concurrent_samples.len(),
        3200,
        "all concurrent reads succeed"
    );
    print_percentiles("S1-concurrent(32) writer_lease.get", concurrent_samples);

    let connection_stats = fixture.state.http_connection_stats();
    println!(
        "S1-connection-stats: active={} admitted={} rejected={} transport_failures={}",
        connection_stats.active,
        connection_stats.admitted,
        connection_stats.rejected,
        connection_stats.transport_failures,
    );
    stop.store(true, Ordering::Release);
    println!(
        "peak-rss-kib(sampled-100ms): {}",
        rss.join().map_err(|_| "rss sampler panicked")?
    );
    fixture.shutdown()?;
    Ok(())
}

/// S2: SSE delivery latency — real planning writes (`goal_create` through the
/// control authority) published while one live tail is connected; measures
/// publish→frame detection, which includes the durable-poll cadence
/// (50 ms floor in this configuration).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "load measurement; run explicitly with --ignored --nocapture"]
async fn load_sse_delivery_latency_percentiles() -> Result<(), Box<dyn std::error::Error>> {
    print_machine_context();
    let fixture = build_fixture(Duration::from_millis(50)).await?;

    let mut stream = tokio::net::TcpStream::connect(fixture.address).await?;
    let request = format!(
        "GET /api/v1/events/stream?{}&after=0 HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {SECRET}\r\nAccept: text/event-stream\r\nConnection: close\r\n\r\n",
        scope_query(&fixture.workspace)
    );
    stream.write_all(request.as_bytes()).await?;

    // Drain the fixture's replay: the 50 ms poll emits keepalive comments
    // forever, so the tail never goes quiet — wait for at least one replayed
    // id frame followed by the first keepalive tick after it.
    let mut wire = Vec::new();
    let mut chunk = [0_u8; 4096];
    let drain_deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if Instant::now() >= drain_deadline {
            return Err("SSE replay drain exceeded its budget".into());
        }
        match tokio::time::timeout(Duration::from_millis(250), stream.read(&mut chunk)).await {
            Ok(Ok(0) | Err(_)) => return Err("live tail ended during drain".into()),
            Ok(Ok(read)) => wire.extend_from_slice(&chunk[..read]),
            Err(_) => {}
        }
        let text = String::from_utf8_lossy(&wire);
        if text.contains("\nid: ")
            && text
                .rfind("\nid: ")
                .is_some_and(|last| text[last..].contains(": keepalive"))
        {
            break;
        }
    }
    let mut known_ids = String::from_utf8_lossy(&wire).matches("\nid: ").count();
    println!("S2-replay-frames-drained: {known_ids}");

    let mut latencies = Vec::new();
    for round in 0..50 {
        let started = Instant::now();
        let goal = RegisteredGoal::create(
            GoalId::from_uuid(Uuid::now_v7()),
            fixture.workspace.scope.workspace_id(),
            fixture.workspace.activity_id,
            GoalContract::new(
                GoalObjective::new(format!("Load goal {round}"))?,
                vec![GoalStatement::new("Publishes durable events".to_owned())?],
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            )?,
            add_millis(timestamp_now()?, 1)?,
        );
        let _ = stage(
            fixture.client.goal_create(
                fixture.workspace.scope.clone(),
                fixture.workspace.actor,
                goal,
            ),
            "S2 goal_create",
        )?;
        loop {
            let mut chunk = [0_u8; 4096];
            match tokio::time::timeout(Duration::from_millis(250), stream.read(&mut chunk)).await {
                Ok(Ok(0) | Err(_)) => return Err("live tail ended unexpectedly".into()),
                Ok(Ok(read)) => {
                    wire.extend_from_slice(&chunk[..read]);
                }
                Err(_) => {}
            }
            let seen = String::from_utf8_lossy(&wire).matches("\nid: ").count();
            if seen > known_ids {
                known_ids = seen;
                break;
            }
            if started.elapsed() > P99_SANITY_CEILING {
                return Err("SSE delivery hit the hang-detector ceiling".into());
            }
        }
        latencies.push(started.elapsed().as_micros());
    }
    print_percentiles("S2-publish-to-frame(goal_create, poll=50ms)", latencies);
    fixture.shutdown()?;
    Ok(())
}

/// S3: same-Workspace fencing under contention — 16 workers × 25 rounds of
/// overlapping-scope acquires; every round is either a win (200, released
/// immediately) or a typed conflict. Measures the critical CAS path under
/// load and asserts the fencing outcome distribution.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "load measurement; run explicitly with --ignored --nocapture"]
async fn load_same_workspace_fencing_contention() -> Result<(), Box<dyn std::error::Error>> {
    print_machine_context();
    let fixture = build_fixture(Duration::from_millis(50)).await?;
    let stop = Arc::new(AtomicBool::new(false));
    let rss = spawn_rss_sampler(Arc::clone(&stop), Duration::from_millis(100));

    let wins: Arc<Mutex<Vec<u128>>> = Arc::new(Mutex::new(Vec::new()));
    let conflicts: Arc<Mutex<Vec<u128>>> = Arc::new(Mutex::new(Vec::new()));
    // One overlapping scope for every contender: fencing under contention is
    // the scenario, so the acquire paths are deliberately identical.
    let shared_scope = scope_json(&fixture.workspace);
    let shared_activity = json!(fixture.workspace.activity_id.into_uuid());
    let shared_actor = json!({
        "session_id": fixture.workspace.session_id.into_uuid(),
        "principal": { "kind": "trusted_stdio" },
        "agent_id": fixture.workspace.agent_id.into_uuid(),
    });
    let shared_paths = json!([{
        "kind": "exact_path",
        "path_base64": URL_SAFE_NO_PAD.encode(b"contention.txt".as_slice()),
    }]);
    let mut workers = tokio::task::JoinSet::new();
    for _ in 0..16_usize {
        let wins = Arc::clone(&wins);
        let conflicts = Arc::clone(&conflicts);
        let address = fixture.address;
        let scope = shared_scope.clone();
        let activity = shared_activity.clone();
        let actor = shared_actor.clone();
        let paths = shared_paths.clone();
        workers.spawn(async move {
            for _ in 0..25_usize {
                let acquire = json!({
                    "scope": scope,
                    "activity_id": activity,
                    "actor": actor,
                    "writer_lease_id": Uuid::now_v7(),
                    "duration_ms": 60_000,
                    "scopes": paths,
                });
                let started = Instant::now();
                let (status, reply) = post_json(address, "writer_lease.acquire", acquire)
                    .await
                    .map_err(|error| format!("contention acquire: {error}"))?;
                let elapsed = started.elapsed().as_micros();
                if status == 200 && reply["ok"] == true {
                    let revision = reply["result"]["revision"]
                        .as_i64()
                        .ok_or("contention acquire revision missing")?;
                    let release = json!({
                        "scope": scope,
                        "activity_id": activity,
                        "actor": actor,
                        "writer_lease_id": reply["result"]["writer_lease_id"],
                        "expected_revision": revision,
                    });
                    post_json(address, "writer_lease.release", release)
                        .await
                        .map_err(|error| format!("contention release: {error}"))?;
                    if let Ok(mut samples) = wins.lock() {
                        samples.push(elapsed);
                    }
                } else if status != 200 && reply["error"]["code"].is_string() {
                    if let Ok(mut samples) = conflicts.lock() {
                        samples.push(elapsed);
                    }
                } else {
                    return Err(format!("unexpected acquire outcome: {reply}"));
                }
            }
            Ok::<(), String>(())
        });
    }
    while let Some(result) = workers.join_next().await {
        result
            .map_err(|error| format!("contention worker join: {error}"))?
            .map_err(std::io::Error::other)?;
    }
    let wins = Arc::try_unwrap(wins)
        .map_err(|_| "wins lock leaked")?
        .into_inner()
        .map_err(|_| "sample lock poisoned")?;
    let conflicts = Arc::try_unwrap(conflicts)
        .map_err(|_| "conflicts lock leaked")?
        .into_inner()
        .map_err(|_| "sample lock poisoned")?;
    println!(
        "S3-outcomes: total=400 wins={} typed_conflicts={} (every outcome typed)",
        wins.len(),
        conflicts.len()
    );
    print_percentiles("S3-win-acquire", wins);
    print_percentiles("S3-conflict-acquire", conflicts);
    stop.store(true, Ordering::Release);
    println!(
        "peak-rss-kib(sampled-100ms): {}",
        rss.join().map_err(|_| "rss sampler panicked")?
    );
    fixture.shutdown()?;
    Ok(())
}

/// S4: lease acquire→release cycle latency and durable readback latency with
/// the page budget asserted against the product constant.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "load measurement; run explicitly with --ignored --nocapture"]
async fn load_lease_cycle_and_readback_latency() -> Result<(), Box<dyn std::error::Error>> {
    print_machine_context();
    let fixture = build_fixture(Duration::from_millis(50)).await?;
    let stop = Arc::new(AtomicBool::new(false));
    let rss = spawn_rss_sampler(Arc::clone(&stop), Duration::from_millis(100));

    let mut cycles = Vec::new();
    for round in 0..200 {
        let lease_id = Uuid::now_v7();
        let started = Instant::now();
        let acquired = post_ok(
            fixture.address,
            "writer_lease.acquire",
            lease_acquire_payload(&fixture.workspace, lease_id, &format!("cycle-{round}.txt")),
        )
        .await?;
        assert_eq!(acquired["status"], "active", "acquire: {acquired}");
        let revision = acquired["revision"].as_i64().ok_or("revision missing")?;
        let released = post_ok(
            fixture.address,
            "writer_lease.release",
            lease_release_payload(&fixture.workspace, lease_id, revision),
        )
        .await?;
        assert_eq!(released["status"], "released", "release: {released}");
        cycles.push(started.elapsed().as_micros());
    }
    print_percentiles("S4-lease-acquire-release-cycle", cycles);

    let query = scope_query(&fixture.workspace);
    let mut readbacks = Vec::new();
    let mut max_page_bytes = 0_usize;
    for _ in 0..200 {
        let started = Instant::now();
        let (status, body) =
            get_bytes(fixture.address, &format!("/api/v1/events?{query}&after=0")).await?;
        let elapsed = started.elapsed().as_micros();
        assert_eq!(
            status,
            200,
            "events page: {}",
            String::from_utf8_lossy(&body)
        );
        let page: Value = serde_json::from_slice(&body)?;
        let rows = page["result"]["events"]
            .as_array()
            .ok_or("events array missing")?
            .len();
        assert!(
            rows <= usize::try_from(MAX_EVENT_PAGE_ROWS)?,
            "page exceeded the durable budget constant"
        );
        max_page_bytes = max_page_bytes.max(body.len());
        readbacks.push(elapsed);
    }
    print_percentiles("S4-events-page-readback", readbacks);
    println!(
        "S4-budgets: max_event_page_rows={MAX_EVENT_PAGE_ROWS} max_observed_page_bytes={max_page_bytes}"
    );

    stop.store(true, Ordering::Release);
    println!(
        "peak-rss-kib(sampled-100ms): {}",
        rss.join().map_err(|_| "rss sampler panicked")?
    );
    fixture.shutdown()?;
    Ok(())
}
