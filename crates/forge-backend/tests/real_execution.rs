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
#[path = "real_execution/approval_projection.rs"]
mod approval_projection;
#[path = "real_execution/approved_owner.rs"]
mod approved_owner;
#[path = "real_execution/binding_lifecycle.rs"]
mod binding_lifecycle;
#[path = "real_execution/effect_fact_reads.rs"]
mod effect_fact_reads;
#[path = "real_execution/execution_waits.rs"]
mod execution_waits;
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
#[path = "real_execution/tree_writes.rs"]
mod tree_writes;
#[path = "real_execution/work_cut_outage.rs"]
mod work_cut_outage;
#[path = "real_execution/work_cuts.rs"]
mod work_cuts;
#[path = "real_execution/workspace_registration.rs"]
mod workspace_registration;
#[path = "real_execution/workspace_stop.rs"]
mod workspace_stop;

use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use forge_backend::config::BackendConfig;
use forge_backend::http::{assemble, serve};
use forge_control::{
    ActivityLeaseClient, AgentBindingActivateRequest, AgentBindingReserveRequest,
    AgentDagPlanCommitRequest, AgentExecutionAuthorityRequest, AgentFocusRequest, AgentListRequest,
    AgentOperationsDelegationReadRequest, AgentOperationsDelegationRequest, ApprovalOnceRequest,
    ApprovalSubmissionStatus, CoordinatorClaimRequest, DagNodeStartRequest,
    ForgeApprovalCoordinator, ForgeControl, ForgeControlClient, ForgeControlWorker,
    ForgeExecutionCoordinator, ResolvedWorkspaceScope, SubmitExecutionForApproval,
};
use forge_domain::{
    ActivityCoordinatorActor, ActivityId, AgentDagDraft, AgentDagPlanRequest,
    AgentDagPlanRequestId, AgentDeclaredRole, AgentDisplayName, AgentFocus, AgentFocusNode,
    AgentInstanceId, AgentInstanceRevision, AgentListLimit, AgentSessionId,
    AgentSessionOpenRequestId, AgentTransportKind, AgentWorkUpdateId, AgentWorkUpdateSequence,
    AuthenticatedPrincipal, DagAcceptanceCriterion, DagNodeDefinition, DagNodeId, DagNodeObjective,
    DagNodeOrdinal, DagNodeTitle, DagRevision, DagRevisionId, DagRevisionNumber,
    ExecutionAttribution, ExecutionCommandId, ExecutionId, ExecutionKind, ExecutionLimits,
    ExecutionOutputCursor, ExecutionOutputEvent, ExecutionOutputLimit, ExecutionRequest,
    ExecutionTimeoutMillis, GoalAttribution, GoalContract, GoalId, GoalNodeAttribution,
    GoalObjective, GoalStatement, LocationId, LocationRevision, OpenAgentSession,
    RegisteredDagNode, RegisteredGoal, RuntimeInstanceId, TimestampMillis, WorkspaceId,
    WorkspaceRoot,
};
use forge_persistence::{
    AgentBindingActivationRequest, AgentBindingReservationRequest, AgentOperationsFreezeRequest,
    AgentSessionCatalog, GlobalRegistry, WorkspaceStore,
};
use forge_workspace::{LocationService, WorkspaceStateLayout};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

const SECRET: &str = "real-backend-execution-secret";
const SCRIPT: &str = "printf 'backend-http-execution\\n'";

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

fn prepare_workspace() -> Result<WorkspaceSetup, Box<dyn std::error::Error>> {
    // PackageV rejects the external SSD source root. The ignored native
    // PackageV fixture may opt into a canonical local root without changing
    // the default for the existing real-execution tests.
    let temp_root = std::env::var_os("FORGE_PACKAGE_V_WORKSPACE_ROOT")
        .map_or_else(std::env::temp_dir, PathBuf::from);
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

fn shell_request(
    execution_id: ExecutionId,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    analyzed: &forge_control::AnalyzedShellExecution,
) -> Result<ExecutionRequest, Box<dyn std::error::Error>> {
    Ok(ExecutionRequest::new(
        ExecutionAttribution::new(execution_id, workspace_id, activity_id),
        ExecutionKind::Shell {
            script: analyzed.script().clone(),
        },
        None,
        ExecutionLimits::new(
            ExecutionTimeoutMillis::new(10 * 60 * 1_000)?,
            ExecutionOutputLimit::DEFAULT,
        ),
        analyzed.permissions(),
    )?)
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

async fn wait_terminal(
    client: &ForgeControlClient,
    scope: &ResolvedWorkspaceScope,
    execution_id: ExecutionId,
) -> Result<forge_domain::RegisteredExecution, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let record = client
            .execution_get(scope.clone(), execution_id)?
            .ok_or("execution row missing")?;
        if record.state().is_terminal() {
            return Ok(record);
        }
        if Instant::now() >= deadline {
            return Err("execution did not reach terminal state".into());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn wait_for_execution_state(
    client: &ForgeControlClient,
    scope: &ResolvedWorkspaceScope,
    execution_id: ExecutionId,
    expected: forge_domain::ExecutionState,
) -> Result<forge_domain::RegisteredExecution, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let record = client
            .execution_get(scope.clone(), execution_id)?
            .ok_or("execution row missing")?;
        if record.state() == expected {
            return Ok(record);
        }
        if record.state().is_terminal() {
            return Err(format!(
                "execution reached {:?} before {:?}",
                record.state(),
                expected
            )
            .into());
        }
        if Instant::now() >= deadline {
            return Err(format!("execution did not reach {expected:?}").into());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn close_fixture_session(fixture: &Fixture) -> Result<(), Box<dyn std::error::Error>> {
    let session =
        fixture
            .client
            .agent_session_resolve(forge_control::AgentSessionResolveRequest {
                session_id: fixture.session_id,
                principal: AuthenticatedPrincipal::TrustedStdio,
            })?;
    let registry = GlobalRegistry::open_existing(fixture.root.join("registry.sqlite3"))?;
    let catalog_path = registry
        .database_path()
        .with_file_name("agent-sessions.sqlite3");
    let mut catalog = AgentSessionCatalog::open_existing(&catalog_path)?
        .ok_or("fixture Agent session catalog disappeared before session close")?;
    let closed = catalog.close(
        session.id(),
        AuthenticatedPrincipal::TrustedStdio,
        session.revision(),
        timestamp_now()?,
    )?;
    assert_eq!(closed.state(), forge_domain::AgentSessionState::Closed);
    Ok(())
}

struct ApprovedShell {
    execution_id: ExecutionId,
    authority_request: AgentExecutionAuthorityRequest,
    authority: Value,
    script: String,
    grant: forge_domain::ExecutionGrant,
    issued_at: TimestampMillis,
    expected_digest: String,
}

fn prepare_approved_shell(fixture: &Fixture) -> Result<ApprovedShell, Box<dyn std::error::Error>> {
    prepare_approved_shell_for_script(fixture, SCRIPT)
}

fn prepare_approved_shell_for_script(
    fixture: &Fixture,
    script: &str,
) -> Result<ApprovedShell, Box<dyn std::error::Error>> {
    let analyzed = forge_control::analyze_shell_script(script.to_owned())?;
    let execution_id = ExecutionId::from_uuid(Uuid::now_v7());
    let command_id = analyzed.intent_id().clone();
    let request = shell_request(
        execution_id,
        fixture.scope.workspace_id(),
        fixture.activity_id,
        &analyzed,
    )?;
    let authority_request = AgentExecutionAuthorityRequest {
        session_id: fixture.session_id,
        scope: fixture.scope.clone(),
        activity_id: fixture.activity_id,
        agent_id: fixture.agent_id,
        expected_revision: fixture.agent_revision,
        principal: AuthenticatedPrincipal::TrustedStdio,
        attribution: fixture.attribution,
        command_id: command_id.clone(),
    };
    let submission = fixture.approval.client().submit_execution(
        SubmitExecutionForApproval::analyzed_shell(
            fixture.scope.clone(),
            fixture.activity_id,
            fixture.runtime_instance_id,
            request,
        )?
        .with_goal_node(fixture.attribution)
        .with_agent_authority(authority_request.clone()),
    )?;
    assert_eq!(submission.status(), ApprovalSubmissionStatus::Pending);
    let pending = fixture
        .client
        .approval_get(fixture.scope.clone(), submission.approval_id())?
        .map(|(approval, _)| approval)
        .ok_or("pending approval row missing")?;
    let approval_at = timestamp_now()?;
    let grant = fixture
        .client
        .approve_once(ApprovalOnceRequest {
            scope: fixture.scope.clone(),
            approval_id: pending.id(),
            expected_revision: pending.revision(),
            grant_id: forge_domain::ExecutionGrantId::from_uuid(Uuid::now_v7()),
            observed_at: add_millis(approval_at, 1)?,
            grant_expires_at: add_millis(approval_at, 60_000)?,
        })?
        .1;
    Ok(ApprovedShell {
        execution_id,
        authority_request,
        authority: authority_json(fixture, execution_id, &command_id, approval_at),
        script: script.to_owned(),
        grant,
        issued_at: approval_at,
        expected_digest: forge_backend::events::hex_encode(
            pending.request().request_digest().as_bytes(),
        ),
    })
}

async fn assert_http_execution(
    address: SocketAddr,
    approved: &ApprovedShell,
    fixture: &Fixture,
) -> Result<(), Box<dyn std::error::Error>> {
    let begin_payload = execution_begin_payload(approved);
    let (status, begin) = post_command(address, "execution.begin", begin_payload).await?;
    assert_eq!(status, 200, "begin response: {begin}");
    assert_eq!(begin["ok"], true);
    assert_eq!(
        begin["result"]["execution_id"],
        json!(approved.execution_id.into_uuid())
    );
    let terminal = wait_terminal(&fixture.client, &fixture.scope, approved.execution_id).await?;
    assert_eq!(terminal.state(), forge_domain::ExecutionState::Completed);
    let read_payload = json!({
        "authority": approved.authority.clone(),
        "after_sequence": 0,
        "max_bytes": forge_domain::MIN_EXECUTION_OUTPUT_READ_BYTES,
        "max_events": forge_domain::MAX_EXECUTION_OUTPUT_READ_EVENTS,
    });
    let (status, read) = post_command(address, "execution.read", read_payload.clone()).await?;
    assert_eq!(status, 200, "read response: {read}");
    assert_eq!(read["ok"], true);
    assert_eq!(read["result"]["state"], json!("completed"));
    assert_eq!(read["result"]["terminal"], true);
    assert!(
        read["result"]["event_count"]
            .as_u64()
            .is_some_and(|count| count > 0)
    );
    assert_http_output_bytes(&read);
    let (status, output) = post_command(address, "execution.output", read_payload).await?;
    assert_eq!(status, 200, "output response: {output}");
    assert_eq!(output["ok"], true);
    assert_eq!(output["result"]["state"], json!("completed"));
    assert_eq!(output["result"]["terminal"], true);
    assert!(
        output["result"]["event_count"]
            .as_u64()
            .is_some_and(|count| count > 0)
    );
    assert_http_output_bytes(&output);
    Ok(())
}

fn execution_begin_payload(approved: &ApprovedShell) -> Value {
    json!({
        "authority": approved.authority.clone(),
        "grant_id": approved.grant.id().into_uuid(),
        "expected_grant_revision": approved.grant.revision().get(),
        "mode": { "kind": "analyzed_shell", "script": approved.script.clone() },
        "admission": {
            "backend_id": BACKEND_ID,
            "issuer": ISSUER_ID,
            "expected_digest": approved.expected_digest.clone(),
            "issued_at_ms": approved.issued_at.get(),
            "expires_at_ms": approved.grant.expires_at().get(),
        }
    })
}

fn assert_durable_output(
    fixture: &Fixture,
    approved: ApprovedShell,
) -> Result<(), Box<dyn std::error::Error>> {
    let durable = fixture.client.execution_read_authorized(
        approved.authority_request,
        approved.execution_id,
        ExecutionOutputCursor::initial(approved.execution_id),
        forge_domain::MIN_EXECUTION_OUTPUT_READ_BYTES,
        forge_domain::MAX_EXECUTION_OUTPUT_READ_EVENTS,
    )?;
    assert!(durable.output().events().iter().any(|event| {
        matches!(event, ExecutionOutputEvent::Chunk(chunk) if chunk.bytes().windows(b"backend-http-execution".len()).any(|window| window == b"backend-http-execution"))
    }));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_http_analyzed_shell_reaches_terminal_and_durable_output()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = prepare_fixture()?;
    let approved = prepare_approved_shell(&fixture)?;
    let config = backend_config()?;
    let product_cache_root = fixture.root.join("product-cache");
    let destination_id = delegated_destination_id(&fixture)?;
    let state = assemble_fixture(config, &fixture, &product_cache_root, destination_id)?;
    let address = serve(state.clone()).await?;
    assert_http_execution(address, &approved, &fixture).await?;
    assert_http_snapshot(address, &fixture).await?;
    assert_http_plan_reads(address, &fixture).await?;
    source_reads::assert_http_source_reads(address, &fixture).await?;
    let diff_id =
        lease_readback::assert_http_lease_and_mutation_readback(address, &fixture).await?;
    readback_enrichment::assert_http_readback_enrichment(address, &fixture, diff_id).await?;
    execution_waits::assert_http_execution_wait(address, &approved, &fixture).await?;
    let local_state = assemble_fixture(
        backend_config()?
            .with_max_inflight_commands(1)
            .with_bridge_workers(1),
        &fixture,
        &product_cache_root,
        destination_id,
    )?;
    let local_address = serve(local_state.clone()).await?;
    execution_waits::assert_http_execution_wait_lifecycle(&local_state, local_address, &fixture)
        .await?;
    assert_durable_output(&fixture, approved)?;
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_http_cancel_running_fifo_rejects_wrong_and_closed_authority()
-> Result<(), Box<dyn std::error::Error>> {
    let mkfifo = Path::new("/usr/bin/mkfifo");
    if !mkfifo.is_file() {
        return Err("/usr/bin/mkfifo is required for the cancellation fixture".into());
    }
    let fixture = prepare_fixture()?;
    let fifo_name = format!("standalone-cancel-{}.fifo", Uuid::now_v7());
    let fifo_path = fixture.workspace_root.join(&fifo_name);
    let fifo_status = Command::new(mkfifo).arg(&fifo_path).status()?;
    if !fifo_status.success() {
        return Err(format!("mkfifo failed with status {fifo_status}").into());
    }
    let approved = prepare_approved_shell_for_script(&fixture, &format!("cat < {fifo_name}"))?;
    let product_cache_root = fixture.root.join("product-cache");
    let destination_id = delegated_destination_id(&fixture)?;
    let state = assemble_fixture(
        backend_config()?,
        &fixture,
        &product_cache_root,
        destination_id,
    )?;
    let address = serve(state.clone()).await?;
    let begin = execution_begin_payload(&approved);
    let (status, response) = post_command(address, "execution.begin", begin).await?;
    assert_eq!(status, 200, "begin response: {response}");
    assert_eq!(response["ok"], true);
    let _running = wait_for_execution_state(
        &fixture.client,
        &fixture.scope,
        approved.execution_id,
        forge_domain::ExecutionState::Running,
    )
    .await?;

    let mut wrong_authority = approved.authority.clone();
    wrong_authority["actor"]["session_id"] = json!(Uuid::now_v7());
    let wrong_cancel = json!({ "authority": wrong_authority });
    let (status, rejected) = post_command(address, "execution.cancel", wrong_cancel).await?;
    assert_ne!(status, 200);
    assert_eq!(rejected["ok"], false);

    let cancel = json!({ "authority": approved.authority.clone() });
    let (status, accepted) = post_command(address, "execution.cancel", cancel).await?;
    assert_eq!(status, 200, "cancel response: {accepted}");
    assert_eq!(accepted["ok"], true);
    assert_eq!(accepted["result"]["cancellation_requested"], true);
    let _cancelled = wait_for_execution_state(
        &fixture.client,
        &fixture.scope,
        approved.execution_id,
        forge_domain::ExecutionState::Cancelled,
    )
    .await?;

    close_fixture_session(&fixture)?;
    let closed_read = fixture.client.execution_read_authorized(
        approved.authority_request.clone(),
        approved.execution_id,
        ExecutionOutputCursor::initial(approved.execution_id),
        forge_domain::MIN_EXECUTION_OUTPUT_READ_BYTES,
        forge_domain::MAX_EXECUTION_OUTPUT_READ_EVENTS,
    );
    assert!(
        matches!(closed_read, Err(error) if error.code() == forge_control::ControlErrorCode::AgentSessionClosed)
    );
    for operation in ["execution.read", "execution.output"] {
        let (status, rejected) = post_command(
            address,
            operation,
            json!({
                "authority": approved.authority.clone(),
            }),
        )
        .await?;
        assert_ne!(
            status, 200,
            "closed session accepted by {operation}: {rejected}"
        );
        assert_eq!(rejected["ok"], false);
    }
    let closed_cancel = json!({ "authority": approved.authority });
    let (status, rejected) = post_command(address, "execution.cancel", closed_cancel).await?;
    assert_ne!(status, 200);
    assert_eq!(rejected["ok"], false);

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

fn assert_http_output_bytes(response: &Value) {
    let events = response["result"]["events"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default();
    assert!(events.iter().any(|event| {
        event["kind"] == json!("chunk")
            && event["stream"] == json!("stdout")
            && event["bytes_base64"] == json!("YmFja2VuZC1odHRwLWV4ZWN1dGlvbgo=")
    }));
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
