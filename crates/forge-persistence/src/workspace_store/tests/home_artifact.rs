//! Workspace-level Home-artifact stage, publication, seal and recovery tests.

use super::*;

use crate::HomeArtifactCaptureOutcome;
use forge_domain::{
    ActivityCoordinatorActor, AgentAssignmentId, AgentDagDraft, AgentDagPlanRequest,
    AgentDagPlanRequestId, AgentWorkUpdateId, AgentWorkUpdateSequence, DagAcceptanceCriterion,
    DagHeadRevision, DagNodeDefinition, DagNodeId, DagNodeObjective, DagNodeOrdinal, DagNodeTitle,
    DagRevision, DagRevisionId, DagRevisionNumber, ForgeBackendId, GoalAttribution, GoalContract,
    GoalId, GoalObjective, GoalStatement, HomeArtifactCaptureIntent, HomeArtifactId,
    HomeTransferSourceAction, HomeTransferSourceBinding, HomeTransferSourceGrant,
    HomeTransferSourceRequest, HomeTransferSourceScope, HomeTransferSourceSubject,
    HomeTransferSourceWitness, RegisteredGoal, RuntimeInstanceId, TimestampMillis, WorkspaceId,
    WorkspaceRelativePath, WorkspaceRevision,
};
use forge_workspace::{
    GitCheckpointStore, HOME_ARTIFACT_REF_PREFIX, HomeArtifactPathRead, HomeArtifactStore,
    WorkspaceStateExclusiveGate, WorkspaceStateLayout,
};
use rusqlite::Connection;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;
use uuid::Uuid;

mod alias_custody;
mod lineage;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const STARTED_TREE_EFFECT_PATH: &str = "src/tree.rs";

#[derive(Debug, Clone, Copy)]
enum AssignmentSetup {
    Offered,
    Running,
    Submitted,
    RunningWithCancelPending,
}

#[derive(Debug, Clone, Copy)]
enum PreSourceEffect {
    None,
    ActiveWriterLease(&'static str),
    UnclosedExecution,
    StartedTreeEffect,
}

struct Fixture {
    root: PathBuf,
    layout: WorkspaceStateLayout,
    store: WorkspaceStore,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    target_agent: forge_domain::RegisteredAgentInstance,
    unaffected_agent: forge_domain::RegisteredAgentInstance,
    actor: ActivityCoordinatorActor,
    assignment: forge_domain::RegisteredAgentAssignment,
    source: crate::HomeTransferSourceRecord,
}

struct HomeArtifactWorkspaceSetup {
    root: PathBuf,
    layout: WorkspaceStateLayout,
    store: WorkspaceStore,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    coordinator_agent: forge_domain::RegisteredAgentInstance,
    target_agent: forge_domain::RegisteredAgentInstance,
    unaffected_agent: forge_domain::RegisteredAgentInstance,
    actor: ActivityCoordinatorActor,
}

struct HomeArtifactGoalDag {
    goal: RegisteredGoal,
    node: forge_domain::RegisteredDagNode,
}

struct StartedTreeIntent {
    path: WorkspaceRelativePath,
    intent: forge_domain::TreeChangeSetIntent,
    diff_begin: forge_domain::BeginDiffEvidence,
}

struct StartedTreeWriter {
    agent: forge_domain::RegisteredAgentInstance,
    lease: forge_domain::WriterLease,
    authority: forge_domain::SourceWriteAuthority,
}

fn loose_object_paths(store: &GitCheckpointStore) -> TestResult<Vec<PathBuf>> {
    let mut paths = Vec::new();
    let objects = store.git_store_path().join("objects");
    for fanout in fs::read_dir(objects)? {
        let fanout = fanout?;
        let fanout_name = fanout.file_name();
        let Some(fanout_name) = fanout_name.to_str() else {
            continue;
        };
        if fanout_name.len() != 2
            || !fanout_name.bytes().all(|byte| byte.is_ascii_hexdigit())
            || !fanout.file_type()?.is_dir()
        {
            continue;
        }
        for object in fs::read_dir(fanout.path())? {
            let object = object?;
            let object_name = object.file_name();
            let Some(object_name) = object_name.to_str() else {
                continue;
            };
            if object_name.len() == 38
                && object_name.bytes().all(|byte| byte.is_ascii_hexdigit())
                && object.file_type()?.is_file()
            {
                paths.push(object.path());
            }
        }
    }
    paths.sort();
    Ok(paths)
}

fn home_artifact_fixture(label: &str, seed: u128, setup: AssignmentSetup) -> TestResult<Fixture> {
    home_artifact_fixture_with_effect(label, seed, setup, PreSourceEffect::None)
}

fn home_artifact_fixture_with_effect(
    label: &str,
    seed: u128,
    setup: AssignmentSetup,
    pre_source_effect: PreSourceEffect,
) -> TestResult<Fixture> {
    let mut workspace = prepare_home_artifact_workspace(label, seed)?;
    let scope = prepare_home_artifact_goal_dag(&mut workspace, seed)?;
    let offered = offer_home_predecessor(&mut workspace, &scope, seed)?;
    let assignment = advance_home_predecessor(&mut workspace, offered, setup)?;
    record_pre_source_effect(&mut workspace, &assignment, seed, pre_source_effect)?;
    let source = prepare_home_source(&mut workspace, seed)?;

    Ok(Fixture {
        root: workspace.root,
        layout: workspace.layout,
        store: workspace.store,
        workspace_id: workspace.workspace_id,
        activity_id: workspace.activity_id,
        target_agent: workspace.target_agent,
        unaffected_agent: workspace.unaffected_agent,
        actor: workspace.actor,
        assignment,
        source,
    })
}

fn prepare_home_artifact_workspace(
    label: &str,
    seed: u128,
) -> TestResult<HomeArtifactWorkspaceSetup> {
    let root = unique_root(label)?;
    let git = Command::new(FORGE_GIT_PROGRAM)
        .args(["init", "-q"])
        .current_dir(&root)
        .output()?;
    if !git.status.success() {
        return Err(format!("git init failed: {}", String::from_utf8_lossy(&git.stderr)).into());
    }
    let layout = WorkspaceStateLayout::initialize(&root)?;
    let workspace_command = command(&layout, workspace_id(seed), location_id(seed + 1), 1)?;
    let mut store = WorkspaceStore::open(&layout, &workspace_command)?;
    let workspace_id = workspace_command.id();
    let activity_id = activity_id(seed + 2);
    let owner_id = RuntimeInstanceId::from_uuid(Uuid::from_u128(seed + 3));
    store.bootstrap_activity(&forge_domain::BootstrapActivity::new(
        activity_id,
        workspace_id,
        WorkspaceRevision::INITIAL,
        owner_id,
        timestamp(100)?,
        timestamp(2)?,
    ))?;

    let coordinator_agent = inventory_seeded_agent(&store, workspace_id, activity_id, seed + 10)?;
    let target_agent = inventory_seeded_agent(&store, workspace_id, activity_id, seed + 20)?;
    let unaffected_agent = inventory_seeded_agent(&store, workspace_id, activity_id, seed + 25)?;
    let coordinator_session = coordinator_agent
        .session_id()
        .ok_or("fixture Coordinator Session is missing")?;
    let coordinator_binding = store.claim_activity_coordinator(
        forge_domain::ClaimActivityCoordinator::new(
            workspace_id,
            activity_id,
            coordinator_agent.id(),
            coordinator_agent.principal(),
            timestamp(5)?,
            coordinator_session,
        ),
        timestamp(5)?,
    )?;
    let actor = ActivityCoordinatorActor::new(
        workspace_id,
        activity_id,
        coordinator_agent.id(),
        coordinator_binding.revision(),
        coordinator_agent.principal(),
        coordinator_session,
    );

    Ok(HomeArtifactWorkspaceSetup {
        root,
        layout,
        store,
        workspace_id,
        activity_id,
        coordinator_agent,
        target_agent,
        unaffected_agent,
        actor,
    })
}

fn prepare_home_artifact_goal_dag(
    workspace: &mut HomeArtifactWorkspaceSetup,
    seed: u128,
) -> TestResult<HomeArtifactGoalDag> {
    let contract = GoalContract::new(
        GoalObjective::new("Preserve declared Home handback bytes".to_owned())?,
        vec![GoalStatement::new(
            "The selected artifact remains retrievable".to_owned(),
        )?],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    )?;
    let goal = RegisteredGoal::create(
        GoalId::from_uuid(Uuid::from_u128(seed + 30)),
        workspace.workspace_id,
        workspace.activity_id,
        contract,
        timestamp(10)?,
    );
    let goal = workspace
        .store
        .insert_goal(workspace.actor, &goal, timestamp(10)?)?;

    let definition = DagNodeDefinition::new(
        DagNodeId::from_uuid(Uuid::from_u128(seed + 31)),
        DagNodeOrdinal::new(0)?,
        DagNodeTitle::new("Home handback".to_owned())?,
        DagNodeObjective::new("Keep declared work available".to_owned())?,
        vec![DagAcceptanceCriterion::new(
            "The selected bytes can be read back".to_owned(),
        )?],
    )?;
    let revision = DagRevision::new(
        DagRevisionId::from_uuid(Uuid::from_u128(seed + 32)),
        goal.id(),
        goal.revision(),
        DagRevisionNumber::INITIAL,
        None,
        vec![definition.clone()],
        Vec::new(),
        timestamp(15)?,
    )?;
    let node = forge_domain::RegisteredDagNode::create(
        goal.id(),
        revision.number(),
        definition,
        timestamp(15)?,
    );
    let draft = AgentDagDraft::new(revision, vec![node.clone()], Vec::new())?;
    let plan = AgentDagPlanRequest::new(
        AgentDagPlanRequestId::from_uuid(Uuid::from_u128(seed + 33)),
        workspace.actor,
        GoalAttribution::new(goal.id(), goal.revision()),
        None,
        None,
        draft,
        AgentWorkUpdateId::from_uuid(Uuid::from_u128(seed + 34)),
        AgentWorkUpdateSequence::INITIAL,
        timestamp(16)?,
    );
    let _committed_plan = workspace
        .store
        .commit_coordinator_dag_plan(&plan, timestamp(16)?)?;

    let focus = forge_domain::AgentFocus::new(
        Some(GoalAttribution::new(goal.id(), goal.revision())),
        Some(node.dag_revision()),
        Some(forge_domain::AgentFocusNode::new(
            node.id(),
            node.revision(),
        )),
    )?;
    workspace.target_agent = workspace.store.set_agent_focus(
        workspace.actor,
        &forge_domain::SetAgentFocus::new(
            workspace.target_agent.id(),
            workspace.activity_id,
            workspace.target_agent.revision(),
            focus,
            timestamp(17)?,
        ),
        timestamp(17)?,
    )?;
    workspace.unaffected_agent = workspace.store.set_agent_focus(
        workspace.actor,
        &forge_domain::SetAgentFocus::new(
            workspace.unaffected_agent.id(),
            workspace.activity_id,
            workspace.unaffected_agent.revision(),
            focus,
            timestamp(17)?,
        ),
        timestamp(17)?,
    )?;

    Ok(HomeArtifactGoalDag { goal, node })
}

fn offer_home_predecessor(
    workspace: &mut HomeArtifactWorkspaceSetup,
    scope: &HomeArtifactGoalDag,
    seed: u128,
) -> TestResult<forge_domain::RegisteredAgentAssignment> {
    let target_session = workspace
        .target_agent
        .session_id()
        .ok_or("fixture target Session is missing")?;
    Ok(workspace.store.offer_agent_assignment(
        &forge_domain::OfferAgentAssignment::new(
            AgentAssignmentId::from_uuid(Uuid::from_u128(seed + 35)),
            workspace.actor,
            forge_domain::AgentAssignmentTarget::new(
                workspace.target_agent.id(),
                target_session,
                workspace.target_agent.principal(),
                workspace.target_agent.revision(),
            ),
            scope.goal.id(),
            scope.goal.revision(),
            scope.goal.timestamps().created_at(),
            DagRevisionNumber::INITIAL,
            DagHeadRevision::INITIAL,
            scope.node.id(),
            scope.node.revision(),
            None,
            timestamp(20)?,
        ),
        timestamp(20)?,
    )?)
}

fn advance_home_predecessor(
    workspace: &mut HomeArtifactWorkspaceSetup,
    offered: forge_domain::RegisteredAgentAssignment,
    setup: AssignmentSetup,
) -> TestResult<forge_domain::RegisteredAgentAssignment> {
    let transitioned = transition_home_predecessor(workspace, offered, setup)?;
    refresh_home_predecessor_owners(workspace, &transitioned, setup)
}

fn transition_home_predecessor(
    workspace: &mut HomeArtifactWorkspaceSetup,
    offered: forge_domain::RegisteredAgentAssignment,
    setup: AssignmentSetup,
) -> TestResult<forge_domain::RegisteredAgentAssignment> {
    Ok(match setup {
        AssignmentSetup::Offered => offered,
        AssignmentSetup::Submitted => {
            let running = workspace.store.claim_agent_assignment(
                &forge_domain::ClaimAgentAssignment::new(
                    offered.id(),
                    offered.target(),
                    offered.revision(),
                    timestamp(22)?,
                ),
                timestamp(22)?,
            )?;
            let current_target_agent = workspace
                .store
                .get_agent(workspace.target_agent.id())?
                .ok_or("target Agent missing after claim")?;
            let current_target = forge_domain::AgentAssignmentTarget::new(
                current_target_agent.id(),
                current_target_agent
                    .session_id()
                    .ok_or("target Session missing after claim")?,
                current_target_agent.principal(),
                current_target_agent.revision(),
            );
            workspace.store.submit_agent_assignment(
                &forge_domain::SubmitAgentAssignment::new(
                    running.id(),
                    current_target,
                    running.revision(),
                    forge_domain::AgentAssignmentResult::new(
                        "Submitted before Home Source preparation".to_owned(),
                        Vec::new(),
                        None,
                    )?,
                    timestamp(23)?,
                ),
                timestamp(23)?,
            )?
        }
        AssignmentSetup::Running => workspace.store.claim_agent_assignment(
            &forge_domain::ClaimAgentAssignment::new(
                offered.id(),
                offered.target(),
                offered.revision(),
                timestamp(22)?,
            ),
            timestamp(22)?,
        )?,
        AssignmentSetup::RunningWithCancelPending => {
            let running = workspace.store.claim_agent_assignment(
                &forge_domain::ClaimAgentAssignment::new(
                    offered.id(),
                    offered.target(),
                    offered.revision(),
                    timestamp(22)?,
                ),
                timestamp(22)?,
            )?;
            workspace
                .store
                .cancel_agent_assignment(&forge_domain::CancelAgentAssignment::new(
                    running.id(),
                    workspace.actor,
                    running.revision(),
                    timestamp(24)?,
                ))?
        }
    })
}

fn refresh_home_predecessor_owners(
    workspace: &mut HomeArtifactWorkspaceSetup,
    assignment: &forge_domain::RegisteredAgentAssignment,
    setup: AssignmentSetup,
) -> TestResult<forge_domain::RegisteredAgentAssignment> {
    // Claiming starts the Node and advances the target Agent focus revision.
    // Keep the fixture commands bound to those current owner readbacks.
    workspace.target_agent = workspace
        .store
        .get_agent(workspace.target_agent.id())?
        .ok_or("target Agent missing after Assignment transition")?;
    let assignment = workspace
        .store
        .get_agent_assignment(assignment.id())?
        .ok_or("Assignment missing after lifecycle transition")?;
    if matches!(
        setup,
        AssignmentSetup::Running
            | AssignmentSetup::Submitted
            | AssignmentSetup::RunningWithCancelPending
    ) {
        workspace.unaffected_agent = workspace
            .store
            .get_agent(workspace.unaffected_agent.id())?
            .ok_or("unaffected Agent missing after Node start")?;
        workspace.unaffected_agent = workspace.store.set_agent_focus(
            workspace.actor,
            &forge_domain::SetAgentFocus::new(
                workspace.unaffected_agent.id(),
                workspace.activity_id,
                workspace.unaffected_agent.revision(),
                workspace.target_agent.focus(),
                timestamp(28)?,
            ),
            timestamp(28)?,
        )?;
    }

    Ok(assignment)
}

fn record_pre_source_effect(
    workspace: &mut HomeArtifactWorkspaceSetup,
    assignment: &forge_domain::RegisteredAgentAssignment,
    seed: u128,
    pre_source_effect: PreSourceEffect,
) -> TestResult<()> {
    match pre_source_effect {
        PreSourceEffect::None => {}
        PreSourceEffect::ActiveWriterLease(path) => {
            let _lease = acquire_writer_lease_for_path(
                &mut workspace.store,
                workspace.workspace_id,
                workspace.activity_id,
                &workspace.target_agent,
                Uuid::from_u128(seed + 60),
                WorkspaceRelativePath::new(PathBuf::from(path))?,
                25,
            )?;
        }
        PreSourceEffect::UnclosedExecution => {
            begin_unclosed_execution(
                &mut workspace.store,
                workspace.workspace_id,
                workspace.activity_id,
                seed + 70,
            )?;
        }
        PreSourceEffect::StartedTreeEffect => {
            begin_started_tree_effect(
                &mut workspace.store,
                workspace.actor,
                &workspace.target_agent,
                assignment,
                seed + 80,
                25,
            )?;
        }
    }
    Ok(())
}

fn prepare_home_source(
    workspace: &mut HomeArtifactWorkspaceSetup,
    seed: u128,
) -> TestResult<crate::HomeTransferSourceRecord> {
    let freeze_request = crate::AgentOperationsFreezeRequest::new(
        Uuid::from_u128(seed + 40),
        Uuid::from_u128(seed + 41),
        timestamp(35)?,
    )?;
    let freeze = workspace.store.freeze_agent_operations(&freeze_request)?;
    let delegation =
        workspace
            .store
            .delegate_agent_operations(&freeze, [0x5C; 32], timestamp(36)?)?;
    let backend = ForgeBackendId::from_uuid(Uuid::from_u128(seed + 42));
    let destination = Uuid::from_u128(seed + 41);
    let issuer = forge_domain::OrchestrationIssuerId::from_uuid(Uuid::from_u128(seed + 44));
    let preparation_id = Uuid::from_u128(seed + 45);
    let request = source_request(
        &workspace.store,
        preparation_id,
        backend,
        destination,
        &workspace.coordinator_agent,
        &workspace.target_agent,
        seed + 46,
    )?;
    let grant = HomeTransferSourceGrant::new(
        issuer,
        HomeTransferSourceAction::Prepare,
        request.request_digest(),
        timestamp(40)?,
        timestamp(95)?,
    )?;
    Ok(workspace
        .store
        .prepare_home_transfer_source(
            &request,
            grant,
            issuer,
            backend,
            delegation.destination_id(),
            || source_clock(45),
        )?
        .record()
        .clone())
}

fn assert_retained_artifact_blocks_removal(
    mut fixture: Fixture,
    expected_intent: &HomeArtifactCaptureIntent,
) -> TestResult<Fixture> {
    let root = fixture.root.clone();
    let location_id = fixture.store.workspace()?.location_id();
    let source_record = fixture.source.clone();
    let sealed = fixture
        .store
        .get_home_transfer_artifact(expected_intent)?
        .ok_or("artifact missing before removal check")?
        .seal()
        .is_some();
    drop(fixture.store);

    let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
    let reference = existing
        .checkpoints()
        .join("store.git")
        .join(forge_workspace::HOME_ARTIFACT_REF_PREFIX)
        .join(expected_intent.artifact_id().into_uuid().to_string());
    let saved_reference = root.join("saved-home-reference-fixture");
    if sealed {
        fs::rename(&reference, &saved_reference)?;
        let git = GitCheckpointStore::open_existing_read_only(&existing)?
            .ok_or("sealed artifact store missing")?;
        let inventory = HomeArtifactStore::new(&git)
            .inventory_refs_read_only(forge_workspace::HomeArtifactRefInventoryLimit::DEFAULT)?;
        assert!(
            inventory.entries().is_empty(),
            "SQL pin must be the remaining blocker"
        );
    }
    let gate = WorkspaceStateExclusiveGate::acquire(
        existing.workspace_root(),
        existing.root_fingerprint()?,
    )?;
    assert!(matches!(
        WorkspaceStore::preflight_state_removal_under_exclusive(&existing, &gate, location_id,),
        Err(WorkspaceStoreError::StateRemovalBlocked(
            WorkspaceStateRemovalBlocker::RetainedHomeArtifact
        ))
    ));
    assert!(existing.database_path().is_file());
    drop(gate);
    if sealed {
        fs::rename(saved_reference, reference)?;
    }

    fixture.store = WorkspaceStore::open_existing(&existing)?;
    let source = fixture
        .store
        .get_home_transfer_source(
            source_record.request().witness().preparation_id(),
            source_record.issuer(),
            source_record.request().scope().backend_id(),
            source_record.request().scope().destination_id(),
        )?
        .ok_or("Home Source record disappeared after removal preflight")?;
    assert_eq!(source, source_record);
    let artifact = fixture
        .store
        .get_home_transfer_artifact(expected_intent)?
        .ok_or("Home artifact stage disappeared after removal preflight")?;
    assert_eq!(artifact.stage().intent(), expected_intent);
    Ok(fixture)
}

#[test]
fn orphan_sql_seal_cannot_authorize_state_removal() -> TestResult {
    let mut fixture = home_artifact_fixture(
        "home-artifact-orphan-seal",
        0xAE10,
        AssignmentSetup::Offered,
    )?;
    fs::write(fixture.root.join("handoff.md"), b"retained orphan fixture")?;
    let selected = intent(
        &fixture,
        0xAE20,
        0xAE30,
        fixture.assignment.id(),
        fixture.assignment.id(),
        "handoff.md",
    )?;
    let outcome = fixture
        .store
        .capture_home_transfer_artifact(&selected, fixture.actor, {
            let mut ticks = [timestamp(50)?, timestamp(55)?].into_iter();
            move || ticks.next().ok_or(crate::HomeArtifactJournalError::Clock)
        })?;
    assert!(matches!(outcome, HomeArtifactCaptureOutcome::Sealed(_)));
    let location_id = fixture.store.workspace()?.location_id();
    let guard: String = fixture.store.connection.query_row(
        "SELECT sql FROM sqlite_schema WHERE type='trigger' AND name='home_transfer_artifact_stages_no_delete'",
        [], |row| row.get(0),
    )?;
    // Deliberately corrupt this disposable fixture, restoring the exact
    // canonical schema so the dangling data, not a missing trigger, is tested.
    fixture
        .store
        .connection
        .pragma_update(None, "foreign_keys", false)?;
    fixture
        .store
        .connection
        .execute_batch("DROP TRIGGER home_transfer_artifact_stages_no_delete")?;
    fixture.store.connection.execute(
        "DELETE FROM home_transfer_artifact_stages WHERE handoff_id=?1",
        [selected.handoff_id().as_bytes()],
    )?;
    fixture.store.connection.execute_batch(&guard)?;
    fixture
        .store
        .connection
        .pragma_update(None, "foreign_keys", true)?;
    assert!(matches!(
        crate::workspace_home_transfers::artifacts::blocks_state_removal(
            &fixture.store.connection,
            fixture.workspace_id
        ),
        Err(crate::HomeArtifactJournalError::Corrupt(_))
    ));
    drop(fixture.store);
    let existing =
        WorkspaceStateLayout::inspect_existing(&fixture.root)?.ok_or("layout missing")?;
    // Remove the ref from the tested namespace: SQL corruption must still
    // prevent removal even without a Git inventory blocker.
    let reference = existing
        .checkpoints()
        .join("store.git")
        .join(forge_workspace::HOME_ARTIFACT_REF_PREFIX)
        .join(selected.artifact_id().into_uuid().to_string());
    fs::rename(reference, fixture.root.join("saved-orphan-ref-fixture"))?;
    let gate = WorkspaceStateExclusiveGate::acquire(&fixture.root, existing.root_fingerprint()?)?;
    assert!(
        WorkspaceStore::preflight_state_removal_under_exclusive(&existing, &gate, location_id)
            .is_err()
    );
    assert!(existing.database_path().is_file());
    assert_eq!(
        fs::read(fixture.root.join("handoff.md"))?,
        b"retained orphan fixture"
    );
    let connection = Connection::open(existing.database_path())?;
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM home_transfer_artifact_seals WHERE handoff_id=?1",
        [selected.handoff_id().as_bytes()],
        |row| row.get(0),
    )?;
    assert_eq!(count, 1);
    drop(connection);
    drop(gate);
    fs::remove_dir_all(fixture.root)?;
    Ok(())
}

fn source_clock(value: i64) -> Result<TimestampMillis, crate::HomeTransferStoreError> {
    TimestampMillis::new(value).map_err(|_| crate::HomeTransferStoreError::Clock)
}

fn artifact_clock(value: i64) -> Result<TimestampMillis, crate::HomeArtifactJournalError> {
    TimestampMillis::new(value).map_err(|_| crate::HomeArtifactJournalError::Clock)
}

fn acquire_writer_lease_for_path(
    store: &mut WorkspaceStore,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    agent: &forge_domain::RegisteredAgentInstance,
    lease_id: Uuid,
    path: WorkspaceRelativePath,
    observed_at: i64,
) -> TestResult<forge_domain::WriterLease> {
    let session = agent
        .session_id()
        .ok_or("Writer Lease Agent Session missing")?;
    let scope =
        forge_domain::WriterLeaseScope::new(vec![forge_domain::WriterLeaseScopeEntry::new(
            forge_domain::WriterLeaseScopeKind::ExactPath,
            path,
        )])?;
    let command = forge_domain::AcquireWriterLease::new(
        forge_domain::WriterLeaseId::from_uuid(lease_id),
        workspace_id,
        activity_id,
        agent.id(),
        scope,
        forge_domain::WriterLeaseDurationMillis::new(10_000)?,
        timestamp(observed_at)?,
        session,
        agent.principal(),
    )?;
    Ok(store.acquire_writer_lease(&command)?)
}

fn begin_unclosed_execution(
    store: &mut WorkspaceStore,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    seed: u128,
) -> TestResult<()> {
    let execution_id = forge_domain::ExecutionId::from_uuid(Uuid::from_u128(seed));
    let request = forge_domain::ExecutionRequest::new(
        forge_domain::ExecutionAttribution::new(execution_id, workspace_id, activity_id),
        forge_domain::ExecutionKind::Structured {
            program: forge_domain::ExecutionProgram::new(PathBuf::from("/usr/bin/true"))?,
            arguments: Vec::new(),
        },
        None,
        forge_domain::ExecutionLimits::new(
            forge_domain::ExecutionTimeoutMillis::new(1_000)?,
            forge_domain::ExecutionOutputLimit::new(16)?,
        ),
        forge_domain::ExecutionPermissions::new(true, false, false),
    )?;
    let admitted = store.begin_execution(&forge_domain::BeginExecution::from_request(
        &request,
        forge_domain::ExecutionRequestDigest::from_bytes([0x91; 32]),
        timestamp(25)?,
    ))?;
    let running = store.mark_execution_running(forge_domain::MarkExecutionRunning::new(
        admitted.record().id(),
        admitted.record().revision(),
        timestamp(26)?,
    ))?;
    let outcome = forge_domain::ExecutionOutcome::new(
        execution_id,
        forge_domain::ExecutionTermination::new(
            forge_domain::ExecutionCompletionStatus::Exited,
            Some(0),
            None,
        ),
        1,
        forge_domain::BoundedExecutionOutput::new(Vec::new(), 0, false),
        forge_domain::BoundedExecutionOutput::new(Vec::new(), 0, false),
    );
    let _terminal_without_native_closure = store.complete_execution(
        &forge_domain::CompleteExecution::new(running.revision(), timestamp(27)?, outcome),
    )?;
    Ok(())
}

/// Persist one real Starting tree `ChangeSet` through the public Source facade
/// using a live Agent focus, current Active node, and scoped Writer Lease. The
/// fixture records no filesystem mutation, leaving truthful owner evidence for
/// the Home artifact quiescence check.
fn begin_started_tree_effect(
    store: &mut WorkspaceStore,
    actor: ActivityCoordinatorActor,
    agent: &forge_domain::RegisteredAgentInstance,
    assignment: &forge_domain::RegisteredAgentAssignment,
    seed: u128,
    observed_at: i64,
) -> TestResult<()> {
    let workspace_id = assignment.workspace_id();
    let activity_id = assignment.activity_id();
    if actor.workspace_id() != workspace_id || actor.activity_id() != activity_id {
        return Err("tree writer Coordinator scope differs from assignment".into());
    }
    let activity = store
        .get_activity(activity_id)?
        .ok_or("tree fixture Activity is missing")?;
    let owner_id = activity
        .lease_owner_id()
        .ok_or("tree fixture Activity lease owner is missing")?;
    let tree = build_started_tree_intent(assignment, &activity, owner_id, seed, observed_at)?;
    let writer = authorize_started_tree_writer(
        store,
        actor,
        agent,
        assignment,
        &tree.path,
        Uuid::from_u128(seed + 2),
        observed_at,
    )?;
    let _tree_admission = store
        .begin_source_tree_change_set(
            &tree.intent,
            &tree.diff_begin,
            forge_domain::SourceTreeRequestDigest::from_bytes([0xA5; 32]),
            writer.authority,
        )
        .map_err(|source| format!("persist Started Source tree ChangeSet: {source}"))?;
    store
        .release_writer_lease(
            workspace_id,
            activity_id,
            forge_domain::ReleaseWriterLease::new(
                writer.lease.id(),
                writer.agent.id(),
                writer.lease.revision(),
                timestamp(observed_at + 1)?,
                writer.authority.session_id(),
                writer.agent.principal(),
            ),
        )
        .map_err(|source| format!("release Source Writer Lease: {source}"))?;
    Ok(())
}

fn build_started_tree_intent(
    assignment: &forge_domain::RegisteredAgentAssignment,
    activity: &forge_domain::RegisteredActivity,
    owner_id: RuntimeInstanceId,
    seed: u128,
    observed_at: i64,
) -> TestResult<StartedTreeIntent> {
    let workspace_id = assignment.workspace_id();
    let activity_id = assignment.activity_id();
    if activity.id() != activity_id || activity.workspace_id() != workspace_id {
        return Err("tree fixture Activity scope differs from assignment".into());
    }
    let path = WorkspaceRelativePath::new(PathBuf::from(STARTED_TREE_EFFECT_PATH))?;
    let change_set_id = forge_domain::ChangeSetId::from_uuid(Uuid::from_u128(seed));
    let mutation_id = forge_domain::TreeMutationId::from_uuid(Uuid::from_u128(seed + 1));
    let plan =
        forge_domain::TreeChangeSetPlan::new(vec![forge_domain::TreeMutationPlan::CreateFile {
            path: path.clone(),
            intended_hash: forge_domain::FileContentHash::from_bytes([0x92; 32]),
        }])?;
    let intent = forge_domain::TreeChangeSetIntent::from_plan(
        forge_domain::ChangeSetAttribution::new(
            change_set_id,
            workspace_id,
            WorkspaceRevision::INITIAL,
            activity_id,
            owner_id,
            activity.lease_revision(),
        ),
        vec![mutation_id],
        &plan,
        timestamp(observed_at)?,
    )?;
    let diff_id = forge_domain::DiffId::for_change_set(change_set_id);
    let diff_begin = forge_domain::BeginDiffEvidence::new(
        forge_domain::DiffAttribution::for_tree_change_set(
            diff_id,
            workspace_id,
            activity_id,
            change_set_id,
        ),
        intent.diff_entries().to_vec(),
        forge_domain::DiffPayloadProjection::IntentSummary {
            render_kind: forge_domain::DiffRenderKind::Structured,
        },
        timestamp(observed_at)?,
        forge_domain::DiffContractVersions::V1,
    )?;
    Ok(StartedTreeIntent {
        path,
        intent,
        diff_begin,
    })
}

fn authorize_started_tree_writer(
    store: &mut WorkspaceStore,
    actor: ActivityCoordinatorActor,
    agent: &forge_domain::RegisteredAgentInstance,
    assignment: &forge_domain::RegisteredAgentAssignment,
    path: &WorkspaceRelativePath,
    lease_id: Uuid,
    observed_at: i64,
) -> TestResult<StartedTreeWriter> {
    let workspace_id = assignment.workspace_id();
    let activity_id = assignment.activity_id();
    let current_dag = store
        .get_current_dag(assignment.goal_id())?
        .ok_or("tree writer current DAG is missing")?;
    if current_dag.revision().number() != assignment.dag_revision() {
        return Err("tree writer assignment no longer names the current DAG".into());
    }
    let current_node = current_dag
        .nodes()
        .iter()
        .find(|node| node.id() == assignment.node_id())
        .ok_or("tree writer current Node is missing")?;
    if current_node.lifecycle() != &forge_domain::DagNodeLifecycle::Active {
        return Err(format!(
            "tree writer Node is not Active: {:?}",
            current_node.lifecycle()
        )
        .into());
    }
    let mut live_agent = store
        .get_agent(agent.id())?
        .ok_or("tree writer Agent is missing")?;
    if live_agent.workspace_id() != workspace_id || live_agent.activity_id() != activity_id {
        return Err("tree writer Agent scope differs from assignment".into());
    }
    let focus = forge_domain::AgentFocus::new(
        Some(GoalAttribution::new(
            assignment.goal_id(),
            assignment.goal_revision(),
        )),
        Some(assignment.dag_revision()),
        Some(forge_domain::AgentFocusNode::new(
            current_node.id(),
            current_node.revision(),
        )),
    )?;
    if live_agent.focus() != focus {
        let focused_at = timestamp(observed_at - 1)?;
        live_agent = store
            .set_agent_focus(
                actor,
                &forge_domain::SetAgentFocus::new(
                    live_agent.id(),
                    activity_id,
                    live_agent.revision(),
                    focus,
                    focused_at,
                ),
                focused_at,
            )
            .map_err(|source| format!("restore exact live Active-node focus: {source}"))?;
    }
    let lease = acquire_writer_lease_for_path(
        store,
        workspace_id,
        activity_id,
        &live_agent,
        lease_id,
        path.clone(),
        observed_at - 1,
    )
    .map_err(|source| format!("acquire scoped Source Writer Lease: {source}"))?;
    let authority = source_tree_write_authority(&live_agent, assignment, &lease)?;
    Ok(StartedTreeWriter {
        agent: live_agent,
        lease,
        authority,
    })
}

fn source_tree_write_authority(
    agent: &forge_domain::RegisteredAgentInstance,
    assignment: &forge_domain::RegisteredAgentAssignment,
    lease: &forge_domain::WriterLease,
) -> TestResult<forge_domain::SourceWriteAuthority> {
    let focus = agent.focus();
    let goal = focus.goal().ok_or("tree writer Goal focus is missing")?;
    let dag_revision = focus
        .dag_revision()
        .ok_or("tree writer DAG focus is missing")?;
    let node = focus.node().ok_or("tree writer Node focus is missing")?;
    if goal.goal_id() != assignment.goal_id()
        || goal.expected_revision() != assignment.goal_revision()
        || dag_revision != assignment.dag_revision()
        || node.node_id() != assignment.node_id()
        || node.expected_revision().get() < assignment.node_revision().get()
    {
        return Err("tree writer focus differs from predecessor Goal/Node scope".into());
    }
    let session = agent.session_id().ok_or("tree writer Session is missing")?;
    Ok(forge_domain::SourceWriteAuthority::new(
        agent.id(),
        agent.revision(),
        agent.principal(),
        forge_domain::GoalNodeAttribution::new(
            goal.goal_id(),
            goal.expected_revision(),
            dag_revision,
            node.node_id(),
            node.expected_revision(),
        ),
        lease.id(),
        lease.revision(),
        session,
    ))
}

fn source_request(
    store: &WorkspaceStore,
    preparation_id: Uuid,
    backend: ForgeBackendId,
    destination: Uuid,
    coordinator: &forge_domain::RegisteredAgentInstance,
    target: &forge_domain::RegisteredAgentInstance,
    seed: u128,
) -> TestResult<HomeTransferSourceRequest> {
    let workspace = store.workspace()?;
    let scope =
        HomeTransferSourceScope::new(workspace.id(), workspace.revision(), backend, destination)?;
    let subject = HomeTransferSourceSubject::new(
        Uuid::from_u128(seed),
        1,
        Uuid::from_u128(seed + 1),
        Uuid::from_u128(seed + 2),
        Uuid::from_u128(seed + 3),
        Uuid::from_u128(seed + 4),
        1,
        1,
    )?;
    let witness = HomeTransferSourceWitness::new(preparation_id, [0x51; 32], [0x52; 32])?;
    let binding = |agent: &forge_domain::RegisteredAgentInstance| -> TestResult<_> {
        Ok(HomeTransferSourceBinding::new(
            agent.activity_id(),
            agent.id(),
            agent.session_id().ok_or("Source Agent Session missing")?,
            agent.principal(),
        )?)
    };
    Ok(HomeTransferSourceRequest::new(
        witness,
        scope,
        subject,
        vec![
            coordinator
                .session_id()
                .ok_or("Coordinator Session missing")?,
            target.session_id().ok_or("target Session missing")?,
        ],
        vec![binding(coordinator)?, binding(target)?],
    )?)
}

fn intent(
    fixture: &Fixture,
    artifact_id: u128,
    handoff_id: u128,
    predecessor: AgentAssignmentId,
    root: AgentAssignmentId,
    path: &str,
) -> TestResult<HomeArtifactCaptureIntent> {
    Ok(HomeArtifactCaptureIntent::new(
        HomeArtifactId::new(Uuid::from_u128(artifact_id))?,
        fixture.source.request().witness().preparation_id(),
        Uuid::from_u128(handoff_id),
        fixture.workspace_id,
        predecessor,
        fixture.assignment.revision(),
        root,
        vec![WorkspaceRelativePath::new(PathBuf::from(path))?],
    )?)
}

fn live_actor_after_transfer(
    fixture: &mut Fixture,
    observed_at: i64,
) -> TestResult<ActivityCoordinatorActor> {
    let binding = fixture.store.transfer_activity_coordinator(
        forge_domain::TransferActivityCoordinator::new(
            fixture.actor,
            fixture.target_agent.id(),
            timestamp(observed_at)?,
        ),
        timestamp(observed_at)?,
    )?;
    let session = fixture
        .target_agent
        .session_id()
        .ok_or("new Coordinator Session is missing")?;
    Ok(ActivityCoordinatorActor::new(
        fixture.workspace_id,
        fixture.activity_id,
        fixture.target_agent.id(),
        binding.revision(),
        fixture.target_agent.principal(),
        session,
    ))
}

#[test]
fn stage_is_create_only_and_replay_with_missing_ref_stays_pending() -> TestResult {
    let mut fixture =
        home_artifact_fixture("home-artifact-pending", 0xA710, AssignmentSetup::Offered)?;
    let path = WorkspaceRelativePath::new(PathBuf::from("handoff.md"))?;
    fs::write(fixture.root.join(path.as_path()), b"pending live bytes")?;
    let selected = intent(
        &fixture,
        0xA720,
        0xA730,
        fixture.assignment.id(),
        fixture.assignment.id(),
        "handoff.md",
    )?;
    let created = crate::workspace_home_transfers::artifacts::stage(
        &mut fixture.store.connection,
        &selected,
        fixture.actor,
        || artifact_clock(50),
    )?;
    assert!(matches!(
        created,
        crate::workspace_home_transfers::artifacts::HomeArtifactStageOutcome::Created(_)
    ));
    assert!(!fixture.layout.checkpoints().join("store.git").exists());

    let replay = crate::workspace_home_transfers::artifacts::stage(
        &mut fixture.store.connection,
        &selected,
        fixture.actor,
        || Err(crate::HomeArtifactJournalError::Clock),
    )?;
    assert!(matches!(
        replay,
        crate::workspace_home_transfers::artifacts::HomeArtifactStageOutcome::Existing(_)
    ));

    let pending = fixture
        .store
        .capture_home_transfer_artifact(&selected, fixture.actor, || artifact_clock(55))?;
    assert!(matches!(pending, HomeArtifactCaptureOutcome::Pending(_)));
    assert!(!fixture.layout.checkpoints().join("store.git").exists());
    let readback = fixture
        .store
        .get_home_transfer_artifact(&selected)?
        .ok_or("exact pending stage missing")?;
    assert!(readback.seal().is_none());
    assert_eq!(readback.stage().intent(), &selected);

    let changed = intent(
        &fixture,
        0xA720,
        0xA730,
        fixture.assignment.id(),
        fixture.assignment.id(),
        "changed.md",
    )?;
    assert!(matches!(
        crate::workspace_home_transfers::artifacts::stage(
            &mut fixture.store.connection,
            &changed,
            fixture.actor,
            || artifact_clock(55),
        ),
        Err(crate::HomeArtifactJournalError::Conflict(_))
    ));

    fixture = assert_retained_artifact_blocks_removal(fixture, &selected)?;
    assert!(!fixture.layout.checkpoints().join("store.git").exists());
    assert_eq!(
        fs::read(fixture.root.join(path.as_path()))?,
        b"pending live bytes"
    );
    let readback = fixture
        .store
        .get_home_transfer_artifact(&selected)?
        .ok_or("pending artifact disappeared after removal preflight")?;
    assert!(readback.seal().is_none());
    let root = fixture.root.clone();
    drop(fixture.store);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn created_stage_does_not_capture_or_publish_over_a_broken_exact_ref() -> TestResult {
    let mut fixture = home_artifact_fixture(
        "home-artifact-created-broken-ref",
        0xA740,
        AssignmentSetup::Offered,
    )?;
    let path = WorkspaceRelativePath::new(PathBuf::from("handoff.md"))?;
    fs::write(fixture.root.join(path.as_path()), b"must not be captured")?;
    let selected = intent(
        &fixture,
        0xA750,
        0xA760,
        fixture.assignment.id(),
        fixture.assignment.id(),
        "handoff.md",
    )?;
    let git = GitCheckpointStore::new(&fixture.root, fixture.layout.checkpoints())?;
    let exact_ref = git
        .git_store_path()
        .join(HOME_ARTIFACT_REF_PREFIX)
        .join(selected.artifact_id().into_uuid().to_string());
    fs::create_dir_all(
        exact_ref
            .parent()
            .ok_or("Home artifact ref has no parent directory")?,
    )?;
    fs::write(&exact_ref, b"")?;
    let objects_before = loose_object_paths(&git)?;

    let result = fixture
        .store
        .capture_home_transfer_artifact(&selected, fixture.actor, || artifact_clock(50));
    assert!(matches!(
        result,
        Err(WorkspaceStoreError::HomeArtifact(source))
            if matches!(
                source.as_ref(),
                crate::HomeArtifactJournalError::PublicationUnconfirmed { .. }
            )
    ));
    let readback = fixture
        .store
        .get_home_transfer_artifact(&selected)?
        .ok_or("Created Home artifact stage disappeared after broken-ref read")?;
    assert!(readback.seal().is_none());
    assert_eq!(readback.stage().intent(), &selected);
    assert_eq!(fs::read(&exact_ref)?, b"");
    assert_eq!(loose_object_paths(&git)?, objects_before);

    let root = fixture.root.clone();
    drop(fixture.store);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn missing_parent_predecessor_forged_root_and_stale_actor_fail_closed() -> TestResult {
    let mut fixture =
        home_artifact_fixture("home-artifact-authority", 0xA810, AssignmentSetup::Offered)?;
    let valid = intent(
        &fixture,
        0xA820,
        0xA830,
        fixture.assignment.id(),
        fixture.assignment.id(),
        "handoff.md",
    )?;

    let missing_parent = HomeArtifactCaptureIntent::new(
        HomeArtifactId::new(Uuid::from_u128(0xA821))?,
        Uuid::from_u128(0xA822),
        Uuid::from_u128(0xA832),
        fixture.workspace_id,
        fixture.assignment.id(),
        fixture.assignment.revision(),
        fixture.assignment.id(),
        vec![WorkspaceRelativePath::new(PathBuf::from("handoff.md"))?],
    )?;
    assert!(matches!(
        crate::workspace_home_transfers::artifacts::stage(
            &mut fixture.store.connection,
            &missing_parent,
            fixture.actor,
            || artifact_clock(50),
        ),
        Err(crate::HomeArtifactJournalError::Conflict(_))
    ));

    let missing_predecessor = HomeArtifactCaptureIntent::new(
        HomeArtifactId::new(Uuid::from_u128(0xA823))?,
        fixture.source.request().witness().preparation_id(),
        Uuid::from_u128(0xA833),
        fixture.workspace_id,
        AgentAssignmentId::from_uuid(Uuid::from_u128(0xA824)),
        fixture.assignment.revision(),
        AgentAssignmentId::from_uuid(Uuid::from_u128(0xA824)),
        vec![WorkspaceRelativePath::new(PathBuf::from("handoff.md"))?],
    )?;
    assert!(matches!(
        crate::workspace_home_transfers::artifacts::stage(
            &mut fixture.store.connection,
            &missing_predecessor,
            fixture.actor,
            || artifact_clock(50),
        ),
        Err(crate::HomeArtifactJournalError::Conflict(_))
    ));

    let forged_root = intent(
        &fixture,
        0xA825,
        0xA835,
        fixture.assignment.id(),
        AgentAssignmentId::from_uuid(Uuid::from_u128(0xA826)),
        "handoff.md",
    )?;
    assert!(matches!(
        crate::workspace_home_transfers::artifacts::stage(
            &mut fixture.store.connection,
            &forged_root,
            fixture.actor,
            || artifact_clock(50),
        ),
        Err(crate::HomeArtifactJournalError::Conflict(_))
    ));

    let wrong_actor = ActivityCoordinatorActor::new(
        fixture.workspace_id,
        fixture.activity_id,
        fixture.target_agent.id(),
        fixture.actor.expected_revision(),
        fixture.target_agent.principal(),
        fixture
            .target_agent
            .session_id()
            .ok_or("target Session missing")?,
    );
    assert!(
        crate::workspace_home_transfers::artifacts::stage(
            &mut fixture.store.connection,
            &valid,
            wrong_actor,
            || artifact_clock(50),
        )
        .is_err()
    );

    fs::remove_dir_all(fixture.root)?;
    Ok(())
}

#[test]
fn submitted_and_cancel_pending_assignments_cannot_stage() -> TestResult {
    for (label, seed, setup) in [
        (
            "home-artifact-submitted",
            0xA910,
            AssignmentSetup::Submitted,
        ),
        (
            "home-artifact-cancel-pending",
            0xA930,
            AssignmentSetup::RunningWithCancelPending,
        ),
    ] {
        let mut fixture = home_artifact_fixture(label, seed, setup)?;
        let selected = intent(
            &fixture,
            seed + 0x50,
            seed + 0x60,
            fixture.assignment.id(),
            fixture.assignment.id(),
            "handoff.md",
        )?;
        assert!(matches!(
            crate::workspace_home_transfers::artifacts::stage(
                &mut fixture.store.connection,
                &selected,
                fixture.actor,
                || artifact_clock(50),
            ),
            Err(crate::HomeArtifactJournalError::UnsupportedLineage
                | crate::HomeArtifactJournalError::Conflict(_))
        ));
        let count: i64 = fixture.store.connection.query_row(
            "SELECT COUNT(*) FROM home_transfer_artifact_stages",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(count, 0);
        fs::remove_dir_all(fixture.root)?;
    }
    Ok(())
}

#[test]
fn quiescence_scopes_writer_leases_and_rejects_unclosed_or_started_work() -> TestResult {
    let mut overlapping_lease = home_artifact_fixture_with_effect(
        "home-artifact-overlapping-lease",
        0xA950,
        AssignmentSetup::Offered,
        PreSourceEffect::ActiveWriterLease("handoff.md"),
    )?;
    let selected = intent(
        &overlapping_lease,
        0xA960,
        0xA970,
        overlapping_lease.assignment.id(),
        overlapping_lease.assignment.id(),
        "handoff.md",
    )?;
    assert!(matches!(
        crate::workspace_home_transfers::artifacts::stage(
            &mut overlapping_lease.store.connection,
            &selected,
            overlapping_lease.actor,
            || artifact_clock(50),
        ),
        Err(crate::HomeArtifactJournalError::Quiescence(_))
    ));
    fs::remove_dir_all(overlapping_lease.root)?;

    let mut disjoint_lease = home_artifact_fixture_with_effect(
        "home-artifact-disjoint-lease",
        0xA980,
        AssignmentSetup::Offered,
        PreSourceEffect::ActiveWriterLease("other.md"),
    )?;
    let selected = intent(
        &disjoint_lease,
        0xA990,
        0xA9A0,
        disjoint_lease.assignment.id(),
        disjoint_lease.assignment.id(),
        "handoff.md",
    )?;
    assert!(matches!(
        crate::workspace_home_transfers::artifacts::stage(
            &mut disjoint_lease.store.connection,
            &selected,
            disjoint_lease.actor,
            || artifact_clock(50),
        ),
        Ok(crate::workspace_home_transfers::artifacts::HomeArtifactStageOutcome::Created(_))
    ));
    fs::remove_dir_all(disjoint_lease.root)?;

    let mut unclosed = home_artifact_fixture_with_effect(
        "home-artifact-unclosed-execution",
        0xA9B0,
        AssignmentSetup::Offered,
        PreSourceEffect::UnclosedExecution,
    )?;
    let selected = intent(
        &unclosed,
        0xA9C0,
        0xA9D0,
        unclosed.assignment.id(),
        unclosed.assignment.id(),
        "handoff.md",
    )?;
    assert!(matches!(
        crate::workspace_home_transfers::artifacts::stage(
            &mut unclosed.store.connection,
            &selected,
            unclosed.actor,
            || artifact_clock(50),
        ),
        Err(crate::HomeArtifactJournalError::Quiescence(_))
    ));
    fs::remove_dir_all(unclosed.root)?;

    let mut started_tree = home_artifact_fixture_with_effect(
        "home-artifact-started-tree-before-stage",
        0xA9E0,
        AssignmentSetup::Running,
        PreSourceEffect::StartedTreeEffect,
    )?;
    let selected = intent(
        &started_tree,
        0xA9F0,
        0xAA00,
        started_tree.assignment.id(),
        started_tree.assignment.id(),
        STARTED_TREE_EFFECT_PATH,
    )?;
    assert!(matches!(
        crate::workspace_home_transfers::artifacts::stage(
            &mut started_tree.store.connection,
            &selected,
            started_tree.actor,
            || artifact_clock(50),
        ),
        Err(crate::HomeArtifactJournalError::Quiescence(_))
    ));
    fs::remove_dir_all(started_tree.root)?;
    Ok(())
}

#[test]
fn seal_rechecks_owner_census_and_preserves_ref_when_started_effect_appears() -> TestResult {
    let mut fixture = home_artifact_fixture(
        "home-artifact-started-tree-at-seal",
        0xAA10,
        AssignmentSetup::Running,
    )?;
    fs::create_dir_all(fixture.root.join("src"))?;
    let selected = intent(
        &fixture,
        0xAA20,
        0xAA30,
        fixture.assignment.id(),
        fixture.assignment.id(),
        STARTED_TREE_EFFECT_PATH,
    )?;
    let staged = crate::workspace_home_transfers::artifacts::stage(
        &mut fixture.store.connection,
        &selected,
        fixture.actor,
        || artifact_clock(50),
    )?;
    let stage = staged.record().clone();
    begin_started_tree_effect(
        &mut fixture.store,
        fixture.actor,
        &fixture.unaffected_agent,
        &fixture.assignment,
        0xAA40,
        55,
    )?;
    let git = GitCheckpointStore::new(&fixture.root, fixture.layout.checkpoints())?;
    let artifact_store = HomeArtifactStore::new(&git);
    let published = artifact_store.publish(&selected, stage.staged_at())?;
    assert_eq!(published.manifest().intent(), &selected);

    let result = fixture
        .store
        .capture_home_transfer_artifact(&selected, fixture.actor, || artifact_clock(60));
    assert!(matches!(
        result,
        Err(WorkspaceStoreError::HomeArtifact(source))
            if matches!(source.as_ref(), crate::HomeArtifactJournalError::Quiescence(_))
    ));
    let readback = fixture
        .store
        .get_home_transfer_artifact(&selected)?
        .ok_or("stage disappeared after rejected seal")?;
    assert!(readback.seal().is_none());
    assert!(artifact_store.read(&selected)?.is_some());

    fs::remove_dir_all(fixture.root)?;
    Ok(())
}

#[test]
fn barrier_rejection_preserves_source_stage_and_recovers_the_same_archive_ref() -> TestResult {
    let mut fixture = home_artifact_fixture(
        "home-artifact-barrier-recovery",
        0xA7A0,
        AssignmentSetup::Offered,
    )?;
    let path = WorkspaceRelativePath::new(PathBuf::from("handoff.md"))?;
    fs::write(fixture.root.join(path.as_path()), b"same retained bytes")?;
    let selected = intent(
        &fixture,
        0xA7B0,
        0xA7C0,
        fixture.assignment.id(),
        fixture.assignment.id(),
        "handoff.md",
    )?;
    let stage = crate::workspace_home_transfers::artifacts::stage(
        &mut fixture.store.connection,
        &selected,
        fixture.actor,
        || artifact_clock(50),
    )?;
    let staged = stage.record().clone();
    let git = GitCheckpointStore::new(&fixture.root, fixture.layout.checkpoints())?;
    let artifact_store = HomeArtifactStore::new(&git);
    let published = artifact_store.publish(&selected, staged.staged_at())?;
    let object_path = loose_object_paths(&git)?
        .into_iter()
        .next()
        .ok_or("published Home artifact has no loose objects")?;
    let hard_link = object_path.with_extension("source-barrier-test-link");
    fs::hard_link(&object_path, &hard_link)?;
    assert_eq!(artifact_store.read(&selected)?, Some(published.clone()));

    let rejected = fixture
        .store
        .capture_home_transfer_artifact(&selected, fixture.actor, || artifact_clock(55));
    assert!(matches!(
        rejected,
        Err(WorkspaceStoreError::HomeArtifact(source))
            if matches!(source.as_ref(), crate::HomeArtifactJournalError::External(_))
    ));
    let readback = fixture
        .store
        .get_home_transfer_artifact(&selected)?
        .ok_or("Source stage disappeared after durability rejection")?;
    assert_eq!(readback.stage(), &staged);
    assert!(readback.seal().is_none());
    assert_eq!(artifact_store.read(&selected)?, Some(published.clone()));

    fs::remove_file(&hard_link)?;
    let recovered =
        fixture
            .store
            .capture_home_transfer_artifact(&selected, fixture.actor, || artifact_clock(60))?;
    let HomeArtifactCaptureOutcome::Sealed(seal) = recovered else {
        return Err("same staged capture did not recover after the barrier became valid".into());
    };
    assert_eq!(seal.stage(), &staged);
    assert_eq!(seal.archive(), &published);
    assert_eq!(artifact_store.read(&selected)?, Some(published));

    let root = fixture.root.clone();
    drop(fixture.store);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn exact_ref_survives_coordinator_turnover_and_member_reads_use_current_authority() -> TestResult {
    let mut fixture = home_artifact_fixture(
        "home-artifact-coordinator-recovery",
        0xAA10,
        AssignmentSetup::Offered,
    )?;
    let path = WorkspaceRelativePath::new(PathBuf::from("handoff.md"))?;
    fs::write(
        fixture.root.join(path.as_path()),
        b"original retained bytes",
    )?;
    let selected = intent(
        &fixture,
        0xAA20,
        0xAA30,
        fixture.assignment.id(),
        fixture.assignment.id(),
        "handoff.md",
    )?;
    let stage = crate::workspace_home_transfers::artifacts::stage(
        &mut fixture.store.connection,
        &selected,
        fixture.actor,
        || artifact_clock(50),
    )?;
    let staged = stage.record().clone();
    assert!(matches!(
        stage,
        crate::workspace_home_transfers::artifacts::HomeArtifactStageOutcome::Created(_)
    ));

    let git = GitCheckpointStore::new(&fixture.root, fixture.layout.checkpoints())?;
    let artifact_store = HomeArtifactStore::new(&git);
    let published = artifact_store.publish(&selected, staged.staged_at())?;
    assert_eq!(
        published.manifest().source_observed_at(),
        staged.staged_at()
    );

    let current_actor = live_actor_after_transfer(&mut fixture, 55)?;
    fs::write(fixture.root.join(path.as_path()), b"changed live bytes")?;
    let sealed = fixture
        .store
        .capture_home_transfer_artifact(&selected, current_actor, || artifact_clock(60))?;
    let HomeArtifactCaptureOutcome::Sealed(seal) = sealed else {
        return Err("published exact ref did not seal on authorized recovery".into());
    };
    assert_eq!(seal.stage().coordinator(), fixture.actor);
    assert_eq!(seal.sealed_by(), current_actor);
    assert_eq!(seal.archive(), &published);

    let between_stage_and_seal = timestamp(59)?;
    assert!(staged.staged_at() < between_stage_and_seal);
    assert!(between_stage_and_seal < seal.sealed_at());
    assert!(matches!(
        fixture
            .store
            .read_home_transfer_artifact_member(&selected, current_actor, &path, || {
                artifact_clock(59)
            }),
        Err(WorkspaceStoreError::HomeArtifact(source))
            if matches!(
                source.as_ref(),
                crate::HomeArtifactJournalError::Conflict(
                    "member read time precedes immutable seal"
                )
            )
    ));

    let member = fixture
        .store
        .read_home_transfer_artifact_member(&selected, current_actor, &path, || artifact_clock(61))?
        .ok_or("sealed member missing")?;
    match member {
        HomeArtifactPathRead::Regular { content, .. } => {
            assert_eq!(content, b"original retained bytes");
        }
        HomeArtifactPathRead::Absent => return Err("declared regular file became absent".into()),
    }

    let old_actor_read =
        fixture
            .store
            .read_home_transfer_artifact_member(&selected, fixture.actor, &path, || {
                artifact_clock(62)
            });
    assert!(old_actor_read.is_err());

    fs::remove_dir_all(fixture.root)?;
    Ok(())
}

#[test]
fn sealed_archive_reopens_and_reads_the_original_snapshot_after_live_files_change() -> TestResult {
    let mut fixture =
        home_artifact_fixture("home-artifact-reopen", 0xAA80, AssignmentSetup::Offered)?;
    let path = WorkspaceRelativePath::new(PathBuf::from("handoff.md"))?;
    fs::write(fixture.root.join(path.as_path()), b"durable original bytes")?;
    let selected = intent(
        &fixture,
        0xAA90,
        0xAAA0,
        fixture.assignment.id(),
        fixture.assignment.id(),
        "handoff.md",
    )?;
    let first = fixture
        .store
        .capture_home_transfer_artifact(&selected, fixture.actor, {
            let mut ticks = [timestamp(50)?, timestamp(55)?].into_iter();
            move || ticks.next().ok_or(crate::HomeArtifactJournalError::Clock)
        })?;
    let HomeArtifactCaptureOutcome::Sealed(first_seal) = first else {
        return Err("first artifact was not sealed".into());
    };
    assert_eq!(
        first_seal.archive().manifest().source_observed_at(),
        first_seal.stage().staged_at(),
    );
    assert_eq!(
        first_seal.stage().source_observed_at(),
        fixture.source.observed_at()
    );
    fs::write(
        fixture.root.join(path.as_path()),
        b"different live bytes after capture",
    )?;

    fixture = assert_retained_artifact_blocks_removal(fixture, &selected)?;
    let actor = fixture.actor;
    let replay = fixture
        .store
        .capture_home_transfer_artifact(&selected, actor, || artifact_clock(70))?;
    let HomeArtifactCaptureOutcome::Sealed(reopened_seal) = replay else {
        return Err("exact sealed artifact was not recovered".into());
    };
    assert_eq!(reopened_seal, first_seal);
    let member = fixture
        .store
        .read_home_transfer_artifact_member(&selected, actor, &path, || artifact_clock(71))?
        .ok_or("reopened sealed member missing")?;
    match member {
        HomeArtifactPathRead::Regular { content, .. } => {
            assert_eq!(content, b"durable original bytes");
        }
        HomeArtifactPathRead::Absent => return Err("reopened member became absent".into()),
    }
    assert_eq!(
        fs::read(fixture.root.join(path.as_path()))?,
        b"different live bytes after capture"
    );
    let root = fixture.root.clone();
    drop(fixture.store);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn legitimate_workspace_root_rebind_advances_revision_without_rewriting_prepared_source()
-> TestResult {
    let mut fixture = home_artifact_fixture(
        "home-artifact-workspace-revision",
        0xAAA8,
        AssignmentSetup::Offered,
    )?;
    let path = WorkspaceRelativePath::new(PathBuf::from("handoff.md"))?;
    fs::write(
        fixture.root.join(path.as_path()),
        b"same physical workspace bytes",
    )?;
    let selected = intent(
        &fixture,
        0xAAB8,
        0xAAC8,
        fixture.assignment.id(),
        fixture.assignment.id(),
        "handoff.md",
    )?;
    let staged = crate::workspace_home_transfers::artifacts::stage(
        &mut fixture.store.connection,
        &selected,
        fixture.actor,
        || artifact_clock(50),
    )?;
    let stage = staged.record().clone();
    let original_root_fingerprint = fixture.store.workspace()?.root_fingerprint();
    let original_source_request_digest = *fixture.source.request().request_digest().as_bytes();
    let original_source_revision = fixture.source.request().scope().workspace_revision();
    assert_eq!(original_source_revision, WorkspaceRevision::INITIAL);
    assert_eq!(stage.workspace_revision(), WorkspaceRevision::INITIAL);
    assert_eq!(
        stage.workspace_root_fingerprint(),
        original_root_fingerprint
    );

    let old_root = fixture.root.clone();
    let new_root = old_root.with_file_name(format!(
        "workspace-root-rebound-{}",
        Uuid::from_u128(0xAAD8)
    ));
    let workspace_id = fixture.workspace_id;
    let actor = fixture.actor;
    drop(fixture.store);
    fs::rename(&old_root, &new_root)?;

    let layout = WorkspaceStateLayout::initialize(&new_root)?;
    let rebound_command = command(&layout, workspace_id, location_id(0xAAA9), 80)?;
    let mut rebound_store = WorkspaceStore::open(&layout, &rebound_command)?;
    let rebound_workspace = rebound_store.workspace()?;
    assert_eq!(rebound_workspace.revision(), WorkspaceRevision::new(2)?);
    assert_eq!(
        rebound_workspace.root_fingerprint(),
        original_root_fingerprint,
        "path-only rename must preserve physical root identity",
    );

    // Stage and parent pins remain the original immutable Source outcome even
    // though the current native observation now uses Workspace revision 2.
    let git = GitCheckpointStore::new(&new_root, layout.checkpoints())?;
    let published = HomeArtifactStore::new(&git).publish(&selected, stage.staged_at())?;
    assert_eq!(published.manifest().intent(), &selected);
    let sealed =
        rebound_store.capture_home_transfer_artifact(&selected, actor, || artifact_clock(85))?;
    let HomeArtifactCaptureOutcome::Sealed(seal) = sealed else {
        return Err("staged archive did not seal after legitimate Workspace rebind".into());
    };
    assert_eq!(
        seal.stage().source_request_digest(),
        &original_source_request_digest
    );
    assert_eq!(
        seal.stage().source_observed_at(),
        fixture.source.observed_at()
    );
    assert_eq!(
        seal.stage().workspace_revision(),
        WorkspaceRevision::INITIAL
    );
    assert_eq!(
        seal.stage().workspace_root_fingerprint(),
        original_root_fingerprint
    );
    assert_eq!(seal.stage().intent(), &selected);

    let member = rebound_store
        .read_home_transfer_artifact_member(&selected, actor, &path, || artifact_clock(86))?
        .ok_or("sealed bytes missing after Workspace rebind")?;
    match member {
        HomeArtifactPathRead::Regular { content, .. } => {
            assert_eq!(content, b"same physical workspace bytes");
        }
        HomeArtifactPathRead::Absent => return Err("rebound member became absent".into()),
    }
    drop(rebound_store);
    fs::remove_dir_all(new_root)?;
    Ok(())
}

#[test]
fn stale_seal_keeps_stage_and_published_git_ref_without_cleanup() -> TestResult {
    let mut fixture =
        home_artifact_fixture("home-artifact-stale-seal", 0xAB10, AssignmentSetup::Offered)?;
    let path = WorkspaceRelativePath::new(PathBuf::from("handoff.md"))?;
    fs::write(
        fixture.root.join(path.as_path()),
        b"stable before stale seal",
    )?;
    let selected = intent(
        &fixture,
        0xAB20,
        0xAB30,
        fixture.assignment.id(),
        fixture.assignment.id(),
        "handoff.md",
    )?;
    let stage = crate::workspace_home_transfers::artifacts::stage(
        &mut fixture.store.connection,
        &selected,
        fixture.actor,
        || artifact_clock(50),
    )?;
    let staged = stage.record().clone();
    let git = GitCheckpointStore::new(&fixture.root, fixture.layout.checkpoints())?;
    let artifact_store = HomeArtifactStore::new(&git);
    let published = artifact_store.publish(&selected, staged.staged_at())?;
    assert_eq!(published.manifest().intent(), &selected);

    let result = fixture
        .store
        .capture_home_transfer_artifact(&selected, fixture.actor, {
            let mut ticks = [timestamp(99)?, timestamp(101)?].into_iter();
            move || ticks.next().ok_or(crate::HomeArtifactJournalError::Clock)
        });
    assert!(result.is_err(), "expired Activity lease must block seal");
    let readback = fixture
        .store
        .get_home_transfer_artifact(&selected)?
        .ok_or("stage disappeared after rejected seal")?;
    assert!(readback.seal().is_none());
    assert!(artifact_store.read(&selected)?.is_some());

    fs::remove_dir_all(fixture.root)?;
    Ok(())
}

#[test]
fn prior_sealed_snapshot_remains_retrievable_after_a_new_handoff_capture() -> TestResult {
    let mut fixture = home_artifact_fixture(
        "home-artifact-prior-snapshot",
        0xAC10,
        AssignmentSetup::Offered,
    )?;
    let path = WorkspaceRelativePath::new(PathBuf::from("handoff.md"))?;
    let live_path = fixture.root.join(path.as_path());
    fs::write(&live_path, b"first handback")?;
    let first_intent = intent(
        &fixture,
        0xAC20,
        0xAC30,
        fixture.assignment.id(),
        fixture.assignment.id(),
        "handoff.md",
    )?;
    let first = fixture
        .store
        .capture_home_transfer_artifact(&first_intent, fixture.actor, {
            let mut ticks = [timestamp(50)?, timestamp(55)?].into_iter();
            move || ticks.next().ok_or(crate::HomeArtifactJournalError::Clock)
        })?;
    let HomeArtifactCaptureOutcome::Sealed(first_seal) = first else {
        return Err("first artifact was not sealed".into());
    };
    fs::write(&live_path, b"second handback")?;
    let second_intent = intent(
        &fixture,
        0xAC21,
        0xAC31,
        fixture.assignment.id(),
        fixture.assignment.id(),
        "handoff.md",
    )?;
    let second = fixture
        .store
        .capture_home_transfer_artifact(&second_intent, fixture.actor, {
            let mut ticks = [timestamp(60)?, timestamp(65)?].into_iter();
            move || ticks.next().ok_or(crate::HomeArtifactJournalError::Clock)
        })?;
    let HomeArtifactCaptureOutcome::Sealed(second_seal) = second else {
        return Err("second artifact was not sealed".into());
    };
    assert_ne!(
        first_seal.archive().commit_id(),
        second_seal.archive().commit_id()
    );

    let first_member = fixture
        .store
        .read_home_transfer_artifact_member(&first_intent, fixture.actor, &path, {
            let mut ticks = [timestamp(70)?, timestamp(71)?].into_iter();
            move || ticks.next().ok_or(crate::HomeArtifactJournalError::Clock)
        })?
        .ok_or("prior member disappeared")?;
    match first_member {
        HomeArtifactPathRead::Regular { content, .. } => assert_eq!(content, b"first handback"),
        HomeArtifactPathRead::Absent => return Err("prior member became absent".into()),
    }
    let second_member = fixture
        .store
        .read_home_transfer_artifact_member(&second_intent, fixture.actor, &path, {
            let mut ticks = [timestamp(72)?, timestamp(73)?].into_iter();
            move || ticks.next().ok_or(crate::HomeArtifactJournalError::Clock)
        })?
        .ok_or("second member missing")?;
    match second_member {
        HomeArtifactPathRead::Regular { content, .. } => assert_eq!(content, b"second handback"),
        HomeArtifactPathRead::Absent => return Err("second member became absent".into()),
    }

    fs::remove_dir_all(fixture.root)?;
    Ok(())
}

#[test]
fn concurrent_exact_stage_has_one_initial_publication_permit() -> TestResult {
    let mut fixture = home_artifact_fixture(
        "home-artifact-concurrent-stage",
        0xAD10,
        AssignmentSetup::Offered,
    )?;
    let selected = intent(
        &fixture,
        0xAD20,
        0xAD30,
        fixture.assignment.id(),
        fixture.assignment.id(),
        "handoff.md",
    )?;
    let mut second_connection = Connection::open(fixture.layout.database_path())?;
    second_connection.busy_timeout(Duration::from_secs(5))?;
    second_connection.pragma_update(None, "foreign_keys", true)?;
    second_connection.pragma_update(None, "synchronous", "FULL")?;
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let child_barrier = std::sync::Arc::clone(&barrier);
    let intent_for_child = selected.clone();
    let actor = fixture.actor;
    let child = std::thread::spawn(move || {
        child_barrier.wait();
        crate::workspace_home_transfers::artifacts::stage(
            &mut second_connection,
            &intent_for_child,
            actor,
            || artifact_clock(50),
        )
    });
    barrier.wait();
    let parent = crate::workspace_home_transfers::artifacts::stage(
        &mut fixture.store.connection,
        &selected,
        actor,
        || artifact_clock(50),
    )?;
    let child = child.join().map_err(|_| "stage worker panicked")??;
    let parent_created = matches!(
        parent,
        crate::workspace_home_transfers::artifacts::HomeArtifactStageOutcome::Created(_)
    );
    let child_created = matches!(
        child,
        crate::workspace_home_transfers::artifacts::HomeArtifactStageOutcome::Created(_)
    );
    let created = u8::from(parent_created) + u8::from(child_created);
    assert_eq!(created, 1);
    let count: i64 = fixture.store.connection.query_row(
        "SELECT COUNT(*) FROM home_transfer_artifact_stages WHERE handoff_id=?1",
        [selected.handoff_id().as_bytes()],
        |row| row.get(0),
    )?;
    assert_eq!(count, 1);

    fs::remove_dir_all(fixture.root)?;
    Ok(())
}
