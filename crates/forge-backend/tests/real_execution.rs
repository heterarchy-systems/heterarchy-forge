//! Real backend listener proof for the analyzed-shell execution path.
//!
//! This test deliberately composes Forge control, native Agent activation,
//! the execution coordinator, the backend bridge, and a loopback HTTP client.
//! The Forge control client is the native session/agent authority for this
//! composition.

#[path = "real_execution/activity_leases.rs"]
mod activity_leases;
#[path = "real_execution/activity_projection.rs"]
mod activity_projection;
#[path = "real_execution/admitted_journal.rs"]
mod admitted_journal;
#[path = "real_execution/api_lifecycle_reads.rs"]
mod api_lifecycle_reads;
#[path = "real_execution/approval_pending.rs"]
mod approval_pending;
#[path = "real_execution/binding_lifecycle.rs"]
mod binding_lifecycle;
#[path = "real_execution/effect_fact_reads.rs"]
mod effect_fact_reads;
#[path = "real_execution/evaluation_evidence.rs"]
mod evaluation_evidence;
#[path = "real_execution/lease_readback.rs"]
mod lease_readback;
#[path = "real_execution/location_removal.rs"]
mod location_removal;
#[path = "real_execution/planning_writes.rs"]
mod planning_writes;
#[path = "real_execution/queue_preference.rs"]
mod queue_preference;
#[path = "real_execution/readback_enrichment.rs"]
mod readback_enrichment;
#[path = "real_execution/recovery_leases.rs"]
mod recovery_leases;
#[path = "real_execution/recovery_maintenance.rs"]
mod recovery_maintenance;
#[path = "real_execution/registry_ops.rs"]
mod registry_ops;
#[path = "real_execution/research_package.rs"]
mod research_package;
#[path = "real_execution/source_reads.rs"]
mod source_reads;
#[path = "real_execution/source_writes.rs"]
mod source_writes;
#[path = "real_execution/standalone.rs"]
pub(crate) mod standalone;
pub(crate) use standalone::native_rust_ci::{
    restore_fixture_verification_directories, start_package_backend,
};
#[path = "real_execution/home_source.rs"]
mod home_source;
#[path = "real_execution/tree_writes.rs"]
mod tree_writes;
#[path = "real_execution/work_cut_outage.rs"]
mod work_cut_outage;
#[path = "real_execution/work_cuts.rs"]
mod work_cuts;
#[path = "real_execution/workspace_registration.rs"]
mod workspace_registration;

use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use forge_backend::config::BackendConfig;
use forge_backend::http::{assemble, serve};
use forge_control::{
    ActivityLeaseClient, AgentBindingActivateRequest, AgentBindingReserveRequest,
    AgentDagPlanCommitRequest, AgentFocusRequest, AgentListRequest,
    AgentOperationsDelegationReadRequest, AgentOperationsDelegationRequest, CoordinatorClaimRequest,
    DagNodeStartRequest, ForgeApprovalCoordinator, ForgeControl, ForgeControlClient,
    ForgeControlWorker, ForgeExecutionCoordinator, ResolvedWorkspaceScope,
};
use forge_domain::{
    ActivityCoordinatorActor, ActivityId, AgentDagDraft, AgentDagPlanRequest,
    AgentDagPlanRequestId, AgentDeclaredRole, AgentDisplayName, AgentFocus, AgentFocusNode,
    AgentInstanceId, AgentInstanceRevision, AgentListLimit, AgentSessionId,
    AgentSessionOpenRequestId, AgentTransportKind, AgentWorkUpdateId, AgentWorkUpdateSequence,
    AuthenticatedPrincipal, DagAcceptanceCriterion, DagNodeDefinition, DagNodeId, DagNodeObjective,
    DagNodeOrdinal, DagNodeTitle, DagRevision, DagRevisionId, DagRevisionNumber,
    ExecutionCommandId, ExecutionId, GoalAttribution, GoalContract, GoalId, GoalNodeAttribution,
    GoalObjective, GoalStatement, LocationId, LocationRevision, OpenAgentSession,
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

const SECRET: &str = "real-backend-execution-secret";

const BACKEND_ID: Uuid = Uuid::from_u128(0xE001);
const ISSUER_ID: Uuid = Uuid::from_u128(0xE002);
const MAX_HTTP_RESPONSE_BYTES: usize = 512 * 1024;
const HTTP_ROUNDTRIP_TIMEOUT: Duration = Duration::from_secs(30);

struct Fixture {
    root: PathBuf,
    workspace_root: PathBuf,
    scope: ResolvedWorkspaceScope,
    activity_id: ActivityId,
    runtime_instance_id: RuntimeInstanceId,
    session_id: AgentSessionId,
    agent_id: AgentInstanceId,
    agent_revision: AgentInstanceRevision,
    attribution: GoalNodeAttribution,
    client: ForgeControlClient,
    worker: ForgeControlWorker,
    activity_leases: ActivityLeaseClient,
    lease_worker: ForgeControlWorker,
    execution: ForgeExecutionCoordinator,
    approval: ForgeApprovalCoordinator,
}

impl Fixture {
    fn shutdown(self) -> Result<(), Box<dyn std::error::Error>> {
        let Fixture {
            root,
            mut worker,
            mut lease_worker,
            mut execution,
            mut approval,
            ..
        } = self;
        let _approval_report = approval.shutdown()?;
        let _report = execution.shutdown()?;
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
            let _written =
                std::fmt::Write::write_fmt(&mut details, format_args!("; caused_by={cause}"));
            source = cause.source();
        }
        details.into()
    })
}

struct WorkspaceSetup {
    root: PathBuf,
    workspace_root: PathBuf,
    scope: ResolvedWorkspaceScope,
    now: TimestampMillis,
}

fn package_fixture_temp_base() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let configured = std::env::var_os("TMPDIR").ok_or("TMPDIR must be configured")?;
    let configured = PathBuf::from(configured);
    if !configured.is_absolute() {
        return Err("TMPDIR must be absolute".into());
    }
    let base = fs::canonicalize(&configured)?;
    if base != configured || !base.is_dir() {
        return Err("TMPDIR must be an existing canonical directory".into());
    }
    Ok(base)
}

fn prepare_workspace() -> Result<WorkspaceSetup, Box<dyn std::error::Error>> {
    let temp_root = package_fixture_temp_base()?;
    let root = temp_root.join(format!(
        "heterarchy-forge-backend-execution-{}-{}",
        std::process::id(),
        Uuid::now_v7()
    ));
    let location_root = root.join("location");
    let workspace_root = location_root.join("workspace");
    stage(
        fs::create_dir_all(&workspace_root),
        &format!("create_fixture_workspace {}", workspace_root.display()),
    )?;
    let registry_path = root.join("registry.sqlite3");
    let location_id = LocationId::from_uuid(Uuid::now_v7());
    let workspace_id = WorkspaceId::from_uuid(Uuid::now_v7());
    let now = timestamp_now()?;
    let mut locations = LocationService::new(stage(
        GlobalRegistry::open(&registry_path),
        "open_fixture_registry",
    )?);
    let location = stage(
        locations.register_selected_path(
            location_id,
            "real backend execution",
            &location_root,
            now,
        ),
        "register_fixture_location",
    )?;
    let layout = stage(
        WorkspaceStateLayout::initialize(&workspace_root),
        "initialize_fixture_workspace",
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
    let control = ForgeControl::new(GlobalRegistry::open(&registry_path)?);
    let located = control
        .workspace_discover(location_id, LocationRevision::INITIAL)?
        .into_iter()
        .find(|entry| entry.display_name() == "workspace")
        .ok_or("workspace discovery entry missing")?
        .locator()
        .clone();
    let scope = stage(
        control.resolve_workspace(location_id, LocationRevision::INITIAL, &located),
        "resolve_workspace",
    )?;
    Ok(WorkspaceSetup {
        root,
        workspace_root,
        scope,
        now,
    })
}

#[test]
fn real_execution_workspace_fixture_uses_configured_tmpdir()
-> Result<(), Box<dyn std::error::Error>> {
    let configured_base = package_fixture_temp_base()?;
    let setup = prepare_workspace()?;
    assert!(
        setup.root.starts_with(&configured_base),
        "fixture root {} escaped configured TMPDIR {}",
        setup.root.display(),
        configured_base.display()
    );
    assert_eq!(fs::canonicalize(&setup.root)?, setup.root);
    assert!(setup.workspace_root.starts_with(&setup.root));
    fs::remove_dir_all(&setup.root)?;
    Ok(())
}

fn prepare_fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let WorkspaceSetup {
        root,
        workspace_root,
        scope,
        now,
    } = prepare_workspace()?;
    let (client, worker) = ForgeControlWorker::start(ForgeControl::new(GlobalRegistry::open(
        root.join("registry.sqlite3"),
    )?))?;
    let activity_id = ActivityId::from_uuid(Uuid::now_v7());
    let runtime_instance_id = RuntimeInstanceId::from_uuid(Uuid::now_v7());
    let _ = stage(
        client.bootstrap_activity(
            scope.clone(),
            activity_id,
            runtime_instance_id,
            now,
            add_millis(now, 120_000)?,
        ),
        "bootstrap_activity",
    )?;
    let session_id = AgentSessionId::from_uuid(Uuid::now_v7());
    let _ = stage(
        client.agent_session_open(OpenAgentSession::new(
            session_id,
            AgentSessionOpenRequestId::from_uuid(Uuid::now_v7()),
            AuthenticatedPrincipal::TrustedStdio,
            add_millis(now, 1)?,
        )),
        "agent_session_open",
    )?;
    let agent_id = AgentInstanceId::from_uuid(Uuid::now_v7());
    activate_native_agent(
        &client,
        &workspace_root,
        &scope,
        activity_id,
        agent_id,
        session_id,
        now,
    )?;
    let (attribution, agent_revision) =
        prepare_work_focus(&client, &scope, activity_id, session_id, agent_id, now)?;
    let execution = stage(
        ForgeExecutionCoordinator::start(client.clone(), 2),
        "execution_coordinator_start",
    )?;
    let approval = stage(
        ForgeApprovalCoordinator::start(client.clone(), execution.client()),
        "approval_coordinator_start",
    )?;
    let (activity_leases, lease_worker) =
        ForgeControlWorker::start_activity_lease(ForgeControl::new(
            GlobalRegistry::open_existing(root.join("registry.sqlite3"))?,
        ))?;
    Ok(Fixture {
        root,
        workspace_root,
        scope,
        activity_id,
        runtime_instance_id,
        session_id,
        agent_id,
        agent_revision,
        attribution,
        client,
        worker,
        activity_leases,
        lease_worker,
        execution,
        approval,
    })
}

fn assemble_fixture(
    config: BackendConfig,
    fixture: &Fixture,
    product_cache_root: &Path,
    destination_id: Uuid,
) -> Result<forge_backend::AppState, Box<dyn std::error::Error>> {
    Ok(assemble(
        config,
        forge_backend::http::BackendClients {
            control: &fixture.client,
            execution: &fixture.execution.client(),
            approval: &fixture.approval.client(),
            activity_leases: &fixture.activity_leases,
            runtime_instance_id: fixture.runtime_instance_id.into_uuid(),
            product_cache_root,
            destination_id,
        },
    )?)
}

fn activate_native_agent(
    client: &ForgeControlClient,
    workspace_root: &Path,
    scope: &ResolvedWorkspaceScope,
    activity_id: ActivityId,
    agent_id: AgentInstanceId,
    session_id: AgentSessionId,
    now: TimestampMillis,
) -> Result<(), Box<dyn std::error::Error>> {
    let layout = WorkspaceStateLayout::inspect_existing(workspace_root)?
        .ok_or("workspace layout missing before native activation")?;
    let mut store = WorkspaceStore::open_existing(&layout)?;
    let freeze = stage(
        store.freeze_agent_operations(&AgentOperationsFreezeRequest::new(
            Uuid::now_v7(),
            Uuid::now_v7(),
            add_millis(now, 20)?,
        )?),
        "freeze_agent_operations",
    )?;
    drop(store);
    let request_id = Uuid::now_v7();
    let reservation = AgentBindingReservationRequest::new(
        request_id,
        activity_id,
        agent_id,
        session_id,
        AuthenticatedPrincipal::TrustedStdio,
        add_millis(now, 21)?,
    )?;
    let _ = stage(
        client.reserve_agent_binding(AgentBindingReserveRequest {
            scope: scope.clone(),
            freeze: freeze.clone(),
            reservation,
            observed_at: add_millis(now, 22)?,
        }),
        "reserve_agent_binding",
    )?;
    let delegation = stage(
        client.delegate_agent_operations(AgentOperationsDelegationRequest {
            scope: scope.clone(),
            freeze,
            manifest_digest: [0xA1; 32],
            observed_at: add_millis(now, 23)?,
        }),
        "delegate_agent_operations",
    )?;
    let activation = AgentBindingActivationRequest::new(
        request_id,
        [0xA2; 32],
        AgentDisplayName::new("backend-http-agent".to_owned())?,
        AgentDeclaredRole::new("executor".to_owned())?,
        AgentTransportKind::Stdio,
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
        "activate_agent_binding",
    )?;
    Ok(())
}

fn delegated_destination_id(fixture: &Fixture) -> Result<Uuid, Box<dyn std::error::Error>> {
    fixture
        .client
        .agent_operations_delegation(AgentOperationsDelegationReadRequest {
            scope: fixture.scope.clone(),
        })?
        .map(|delegation| delegation.destination_id())
        .ok_or_else(|| "fixture Agent operations delegation is missing".into())
}

fn claim_coordinator(
    client: &ForgeControlClient,
    scope: &ResolvedWorkspaceScope,
    activity_id: ActivityId,
    session_id: AgentSessionId,
    agent_id: AgentInstanceId,
    now: TimestampMillis,
) -> Result<ActivityCoordinatorActor, Box<dyn std::error::Error>> {
    let binding = client.activity_coordinator_claim(CoordinatorClaimRequest {
        session_id,
        scope: scope.clone(),
        activity_id,
        agent_id,
        principal: AuthenticatedPrincipal::TrustedStdio,
        observed_at: add_millis(now, 30)?,
    })?;
    Ok(ActivityCoordinatorActor::new(
        scope.workspace_id(),
        activity_id,
        binding.agent_id(),
        binding.revision(),
        AuthenticatedPrincipal::TrustedStdio,
        session_id,
    ))
}

fn create_active_node(
    client: &ForgeControlClient,
    scope: &ResolvedWorkspaceScope,
    activity_id: ActivityId,
    session_id: AgentSessionId,
    actor: ActivityCoordinatorActor,
    now: TimestampMillis,
) -> Result<(RegisteredGoal, RegisteredDagNode), Box<dyn std::error::Error>> {
    let goal = RegisteredGoal::create(
        GoalId::from_uuid(Uuid::now_v7()),
        scope.workspace_id(),
        activity_id,
        GoalContract::new(
            GoalObjective::new("Run the backend execution proof".to_owned())?,
            vec![GoalStatement::new(
                "The shell command completes".to_owned(),
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
        "goal_create",
    )?;
    let definition = DagNodeDefinition::new(
        DagNodeId::from_uuid(Uuid::now_v7()),
        DagNodeOrdinal::new(0)?,
        DagNodeTitle::new("Run shell".to_owned())?,
        DagNodeObjective::new("Run the analyzed shell command".to_owned())?,
        vec![DagAcceptanceCriterion::new("Command completes".to_owned())?],
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
        "agent_dag_plan_commit",
    )?;
    let active = stage(
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
        "dag_node_start",
    )?;
    Ok((goal, active))
}

fn prepare_work_focus(
    client: &ForgeControlClient,
    scope: &ResolvedWorkspaceScope,
    activity_id: ActivityId,
    session_id: AgentSessionId,
    agent_id: AgentInstanceId,
    now: TimestampMillis,
) -> Result<(GoalNodeAttribution, AgentInstanceRevision), Box<dyn std::error::Error>> {
    let actor = stage(
        claim_coordinator(client, scope, activity_id, session_id, agent_id, now),
        "activity_coordinator_claim",
    )?;
    let (goal, active) = stage(
        create_active_node(client, scope, activity_id, session_id, actor, now),
        "goal_dag_node_setup",
    )?;
    let agent_projection = stage(
        client.agent_list(AgentListRequest {
            scope: scope.clone(),
            activity_id: Some(activity_id),
            now: add_millis(now, 40)?,
            limit: AgentListLimit::DEFAULT,
        }),
        "agent_revision_readback",
    )?
    .into_iter()
    .find(|projection| projection.agent().id() == agent_id)
    .ok_or("post-plan Agent projection missing")?;
    let agent_revision = agent_projection.agent().revision();
    // Fixture setup assigns explicit logical timestamps. A fast wall clock
    // must not move the next fixture transition behind its retained Agent row.
    let observed_at = TimestampMillis::new(
        timestamp_now()?
            .get()
            .max(agent_projection.agent().updated_at().get()),
    )?;
    let focus = AgentFocus::new(
        Some(GoalAttribution::new(goal.id(), goal.revision())),
        Some(active.dag_revision()),
        Some(AgentFocusNode::new(active.id(), active.revision())),
    )?;
    let focused = stage(
        client.agent_set_focus(AgentFocusRequest {
            scope: scope.clone(),
            activity_id,
            actor,
            agent_id,
            expected_revision: agent_revision,
            focus,
            observed_at,
        }),
        "agent_set_focus",
    )?;
    let attribution = GoalNodeAttribution::new(
        goal.id(),
        goal.revision(),
        active.dag_revision(),
        active.id(),
        focused
            .focus()
            .node()
            .ok_or("focused node missing")?
            .expected_revision(),
    );
    Ok((attribution, focused.revision()))
}

fn authority_json(
    fixture: &Fixture,
    execution_id: ExecutionId,
    command_id: &ExecutionCommandId,
    observed_at: TimestampMillis,
) -> Value {
    let locator = fixture.scope.locator();
    json!({
        "scope": {
            "workspace_id": fixture.scope.workspace_id().into_uuid(),
            "workspace_revision": fixture.scope.workspace_revision().get(),
            "locator": {
                "location_id": locator.location_id().into_uuid(),
                "expected_revision": locator.expected_revision().get(),
                "relative_root": locator.relative_root().to_string_lossy(),
            }
        },
        "activity": {
            "activity_id": fixture.activity_id.into_uuid(),
            "runtime_instance_id": fixture.runtime_instance_id.into_uuid(),
            "observed_at_ms": observed_at.get(),
        },
        "actor": {
            "session_id": fixture.session_id.into_uuid(),
            "principal": { "kind": "trusted_stdio" },
            "workspace_id": fixture.scope.workspace_id().into_uuid(),
            "agent_id": fixture.agent_id.into_uuid(),
            "expected_revision": fixture.agent_revision.get(),
        },
        "goal_id": fixture.attribution.goal_id().into_uuid(),
        "expected_goal_revision": fixture.attribution.expected_goal_revision().get(),
        "expected_dag_revision": fixture.attribution.dag_revision().get(),
        "node_id": fixture.attribution.node_id().into_uuid(),
        "expected_node_revision": fixture.attribution.expected_node_revision().get(),
        "command_id": command_id.as_str(),
        "execution_id": execution_id.into_uuid(),
    })
}

fn envelope(op: &str, payload: &Value) -> String {
    json!({
        "forge_api": 1,
        "request_id": Uuid::now_v7(),
        "op": op,
        "payload": payload,
    })
    .to_string()
}

async fn post_command(
    address: SocketAddr,
    op: &str,
    payload: Value,
) -> Result<(u16, Value), Box<dyn std::error::Error>> {
    tokio::time::timeout(
        HTTP_ROUNDTRIP_TIMEOUT,
        post_command_unbounded(address, op, payload),
    )
    .await
    .map_err(|_| "HTTP command round-trip exceeded its bound")?
}

async fn post_command_unbounded(
    address: SocketAddr,
    op: &str,
    payload: Value,
) -> Result<(u16, Value), Box<dyn std::error::Error>> {
    let body = envelope(op, &payload);
    let request = format!(
        "POST /api/v1/commands/{op} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {SECRET}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    exchange_json(address, &request).await
}

async fn exchange_json(
    address: SocketAddr,
    request: &str,
) -> Result<(u16, Value), Box<dyn std::error::Error>> {
    let mut stream = tokio::net::TcpStream::connect(address).await?;
    stream.write_all(request.as_bytes()).await?;
    let response = read_response_bounded(&mut stream).await?;
    let text = String::from_utf8(response)?;
    let status = text
        .split_whitespace()
        .nth(1)
        .ok_or("HTTP status missing")?
        .parse::<u16>()?;
    let body = text.split_once("\r\n\r\n").ok_or("HTTP body missing")?.1;
    Ok((status, serde_json::from_str(body)?))
}

async fn assert_http_snapshot(
    address: SocketAddr,
    fixture: &Fixture,
) -> Result<(), Box<dyn std::error::Error>> {
    let scope = &fixture.scope;
    let query = format!(
        "workspace={}&workspace_revision={}&location_id={}&location_revision={}&relative_root={}",
        scope.workspace_id().into_uuid(),
        scope.workspace_revision().get(),
        scope.locator().location_id().into_uuid(),
        scope.locator().expected_revision().get(),
        scope.locator().relative_root().display(),
    );
    let request = format!(
        "GET /api/v1/snapshot?{query} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {SECRET}\r\nConnection: close\r\n\r\n"
    );
    let (status, body) =
        tokio::time::timeout(HTTP_ROUNDTRIP_TIMEOUT, exchange_json(address, &request)).await??;
    assert_eq!(status, 200, "snapshot: {body}");
    assert_eq!(body["ok"], true);
    assert_eq!(body["result"]["summary"]["goal_count"], 1);
    assert_eq!(body["result"]["summary"]["goals_truncated"], false);
    assert_eq!(
        body["result"]["summary"]["goals"][0]["goal_id"],
        json!(fixture.attribution.goal_id().into_uuid())
    );
    assert!(body["result"]["watermark_seq"].as_u64().is_some());
    Ok(())
}

async fn read_response_bounded(
    stream: &mut tokio::net::TcpStream,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut response = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        if response.len().saturating_add(read) > MAX_HTTP_RESPONSE_BYTES {
            return Err("HTTP response exceeded its bound".into());
        }
        response.extend_from_slice(&chunk[..read]);
    }
    Ok(response)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_http_snapshot_plan_source_and_mutation_readback()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = prepare_fixture()?;
    let config = backend_config()?;
    let product_cache_root = fixture.root.join("product-cache");
    let destination_id = delegated_destination_id(&fixture)?;
    let state = assemble_fixture(config, &fixture, &product_cache_root, destination_id)?;
    let address = serve(state.clone()).await?;
    assert_http_snapshot(address, &fixture).await?;
    assert_http_plan_reads(address, &fixture).await?;
    source_reads::assert_http_source_reads(address, &fixture).await?;
    let diff_id =
        lease_readback::assert_http_lease_and_mutation_readback(address, &fixture).await?;
    readback_enrichment::assert_http_readback_enrichment(address, &fixture, diff_id).await?;
    planning_writes::assert_http_planning(address, &fixture).await?;
    effect_fact_reads::assert_http_effect_fact_outbox(address, &fixture).await?;
    let shutdown = state.shutdown(Duration::from_secs(5)).await;
    assert!(
        shutdown.is_successful(),
        "backend shutdown did not complete"
    );
    fixture.shutdown()?;
    Ok(())
}

async fn assert_http_plan_reads(
    address: SocketAddr,
    fixture: &Fixture,
) -> Result<(), Box<dyn std::error::Error>> {
    let goal_id = fixture.attribution.goal_id();
    let scope = &fixture.scope;
    let scope_json = json!({
        "workspace_id": scope.workspace_id().into_uuid(),
        "workspace_revision": scope.workspace_revision().get(),
        "locator": {
            "location_id": scope.locator().location_id().into_uuid(),
            "expected_revision": scope.locator().expected_revision().get(),
            "relative_root": scope.locator().relative_root().to_string_lossy(),
        }
    });
    let (status, goal_wire) = post_command(
        address,
        "goal.read",
        json!({
            "scope": scope_json.clone(),
            "activity_id": fixture.activity_id.into_uuid(),
            "goal_id": goal_id.into_uuid(),
        }),
    )
    .await?;
    assert_eq!(status, 200, "goal.read response: {goal_wire}");
    let goal = fixture
        .client
        .goal_get(scope.clone(), fixture.activity_id, goal_id)?
        .ok_or("typed Goal disappeared during HTTP projection read")?;
    let result = &goal_wire["result"];
    assert_eq!(result["found"], true);
    assert_eq!(result["goal_id"], json!(goal_id.into_uuid()));
    assert_eq!(
        result["activity_id"],
        json!(fixture.activity_id.into_uuid())
    );
    assert_eq!(result["revision"], goal.revision().get());
    assert_eq!(result["objective"], goal.contract().objective().as_str());
    let criteria: Vec<_> = goal
        .contract()
        .success_criteria()
        .iter()
        .map(GoalStatement::as_str)
        .collect();
    assert_eq!(result["success_criteria"], json!(criteria));

    let (status, dag_wire) = post_command(
        address,
        "dag.read_current",
        json!({
            "scope": scope_json, "goal_id": goal_id.into_uuid(),
        }),
    )
    .await?;
    assert_eq!(status, 200, "dag.read_current response: {dag_wire}");
    let dag = fixture
        .client
        .dag_get_current(scope.clone(), goal_id)?
        .ok_or("typed DAG disappeared during HTTP projection read")?;
    let result = &dag_wire["result"];
    assert_eq!(result["found"], true);
    assert_eq!(result["dag_revision"], dag.revision().number().get());
    assert_eq!(result["node_count"], dag.nodes().len());
    let projected = dag.revision().project(dag.nodes())?;
    let node = projected
        .iter()
        .find(|item| item.node().id() == fixture.attribution.node_id())
        .ok_or("fixture node projection missing")?;
    let nodes = result["nodes"].as_array().ok_or("DAG nodes missing")?;
    let wire_node = nodes
        .iter()
        .find(|item| item["node_id"] == json!(node.node().id().into_uuid()))
        .ok_or("HTTP DAG node missing")?;
    assert_eq!(
        wire_node["objective"],
        node.node().definition().objective().as_str()
    );
    assert_eq!(wire_node["status"], "active");
    assert_eq!(wire_node["waiting_on"], json!([]));
    assert_eq!(result["edges"], json!([]));
    let count = dag
        .evidence()
        .iter()
        .find(|item| item.node_id() == node.node().id())
        .map_or(0, |item| item.count());
    assert_eq!(wire_node["evidence_count"], count);
    assert_http_node_assignment(address, fixture, &scope_json, &dag).await?;
    Ok(())
}

fn backend_config() -> Result<BackendConfig, Box<dyn std::error::Error>> {
    Ok(BackendConfig::new(
        std::net::IpAddr::from([127, 0, 0, 1]),
        0,
        SECRET,
        forge_domain::ForgeBackendId::from_uuid(BACKEND_ID),
        forge_domain::OrchestrationIssuerId::from_uuid(ISSUER_ID),
    )?
    .with_command_deadline(Duration::from_secs(30)))
}

async fn assert_http_node_assignment(
    address: SocketAddr,
    fixture: &Fixture,
    scope_json: &serde_json::Value,
    dag: &forge_persistence::StoredDagRevision,
) -> Result<(), Box<dyn std::error::Error>> {
    let goal_id = dag.revision().goal_id();
    let scope = &fixture.scope;
    let (status, assignment_wire) = post_command(
        address,
        "node.assignment_read",
        json!({
            "scope": scope_json,
            "goal_id": goal_id.into_uuid(),
            "dag_revision": dag.revision().number().get(),
            "node_id": fixture.attribution.node_id().into_uuid(),
        }),
    )
    .await?;
    assert_eq!(
        status, 200,
        "node.assignment_read response: {assignment_wire}"
    );
    let exact = fixture
        .client
        .dag_node_assignment_snapshot(
            scope.clone(),
            forge_persistence::DagNodeEvidenceScope::new(
                goal_id,
                dag.revision().number(),
                fixture.attribution.node_id(),
            ),
        )?
        .ok_or("exact node snapshot missing")?;
    let assignment_result = &assignment_wire["result"];
    assert_eq!(assignment_result["found"], true);
    assert_eq!(
        assignment_result["workspace_id"],
        json!(scope.workspace_id().into_uuid())
    );
    assert_eq!(
        assignment_result["activity_id"],
        json!(fixture.activity_id.into_uuid())
    );
    assert_eq!(
        assignment_result["goal_created_at_ms"],
        exact.goal_created_at().get()
    );
    assert_eq!(
        assignment_result["goal_revision"],
        exact.goal_revision().get()
    );
    assert_eq!(
        assignment_result["dag_base_goal_revision"],
        exact.dag_base_goal_revision().get()
    );
    assert_eq!(
        assignment_result["head_revision"],
        exact.head().revision().get()
    );
    assert_eq!(
        assignment_result["current_dag_revision"],
        exact.head().dag_revision().get()
    );
    assert_eq!(
        assignment_result["node_revision"],
        exact.node_revision().get()
    );
    assert!(assignment_result["assignment"].is_null());
    Ok(())
}
