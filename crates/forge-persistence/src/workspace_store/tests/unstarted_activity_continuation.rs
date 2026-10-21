//! Canonical schema-v66 SQL proof for the positive unstarted census.

use super::*;

use crate::{ExpiredActivityRecoveryOperation, ExpiredActivityRecoveryStoreRequest};
use crate::{UnstartedActivityContinuationOperation, UnstartedActivityContinuationStoreRequest};
use forge_domain::{
    ActivityCoordinatorActor, AgentInstanceId, AgentSessionId, AuthenticatedPrincipal,
    DagAcceptanceCriterion, DagNodeDefinition, DagNodeId, DagNodeObjective, DagNodeOrdinal,
    DagNodeTitle, DagRevision, DagRevisionId, DagRevisionNumber, ExpiredActivityRecoveryProbeScope,
    ExpiredActivityRecoverySessionEvidence, ForgeBackendId, OrchestrationIssuerId,
    RecoveryLeaseDurationMillis, RuntimeInstanceId, UnstartedActivityContinuationBlocker,
    UnstartedActivityContinuationRequestId, UnstartedActivityContinuationServiceIdentity,
};
use rusqlite::params;
use uuid::Uuid;

#[allow(
    dead_code,
    reason = "Legacy non-p28 fixture retained for migration comparison."
)]
fn prepared_fixture(
    label: &str,
    seed: u128,
    arbitrary_work: bool,
) -> Result<
    (
        FileFactFixture,
        crate::AgentOperationsDelegation,
        forge_domain::RegisteredAgentAssignment,
    ),
    Box<dyn std::error::Error>,
> {
    let mut fixture = file_fact_fixture(label, seed)?;
    let workspace = fixture.store.workspace()?;
    let assignment = seed_assignment_for_offer_seal_migration(
        &mut fixture.store,
        workspace.id(),
        fixture.activity.id(),
    )?;
    if arbitrary_work {
        fixture.store.connection.execute(
            "INSERT INTO agent_work_updates (
                update_id, agent_id, workspace_id, activity_id, update_sequence,
                phase, summary, evidence_count, observed_at_ms
             ) VALUES (?1, ?2, ?3, ?4, 1, 0, 'arbitrary non-plan work', 0, 8)",
            params![
                Uuid::from_u128(seed + 0x90).as_bytes(),
                assignment.coordinator().agent_id().into_uuid().as_bytes(),
                workspace.id().into_uuid().as_bytes(),
                fixture.activity.id().into_uuid().as_bytes(),
            ],
        )?;
    }
    let delegation = install_delegation_seal(&mut fixture.store, seed + 0xA0, 20)?;
    Ok((fixture, delegation, assignment))
}

struct P28Seed {
    root: PathBuf,
    layout: WorkspaceStateLayout,
    store: WorkspaceStore,
    workspace: forge_domain::RegisteredWorkspace,
    predecessor: forge_domain::RegisteredActivity,
    coordinator_session: forge_domain::AgentSessionId,
    freeze: crate::AgentOperationsFreeze,
    delegation: crate::AgentOperationsDelegation,
    binding: crate::WorkspaceJournalBinding,
}

fn seed_p28_predecessor(label: &str, seed: u128) -> Result<P28Seed, Box<dyn std::error::Error>> {
    let root = unique_root(label)?;
    let layout = WorkspaceStateLayout::initialize(&root)?;
    let workspace_command = command(&layout, workspace_id(seed), location_id(seed + 1), 1)?;
    let mut store = WorkspaceStore::open(&layout, &workspace_command)?;
    let predecessor_owner = runtime_id(seed + 2);
    let predecessor = store.bootstrap_activity(&forge_domain::BootstrapActivity::new(
        activity_id(seed + 3),
        workspace_command.id(),
        WorkspaceRevision::INITIAL,
        predecessor_owner,
        timestamp(50)?,
        timestamp(10)?,
    ))?;
    let coordinator_agent =
        migration_test_agent(workspace_command.id(), predecessor.id(), seed + 10)?;
    let target_agent = migration_test_agent(workspace_command.id(), predecessor.id(), seed + 20)?;
    for (agent, event) in [(&coordinator_agent, seed + 11), (&target_agent, seed + 21)] {
        crate::legacy_agent_seed::seed_agent(
            &store.connection,
            agent,
            Some(forge_domain::AgentEventId::from_uuid(Uuid::from_u128(
                event,
            ))),
        )?;
    }
    let coordinator_session = coordinator_agent
        .session_id()
        .ok_or("Coordinator Session missing")?;
    let _coordinator_binding = store.claim_activity_coordinator(
        forge_domain::ClaimActivityCoordinator::new(
            workspace_command.id(),
            predecessor.id(),
            coordinator_agent.id(),
            AuthenticatedPrincipal::TrustedStdio,
            timestamp(20)?,
            coordinator_session,
        ),
        timestamp(20)?,
    )?;
    let freeze = store.freeze_agent_operations(&crate::AgentOperationsFreezeRequest::new(
        Uuid::from_u128(seed + 30),
        Uuid::from_u128(seed + 31),
        timestamp(30)?,
    )?)?;
    let delegation = store.delegate_agent_operations(&freeze, [0x5C; 32], timestamp(31)?)?;
    let binding = store.journal_binding()?;
    let workspace = store.workspace()?;
    Ok(P28Seed {
        root,
        layout,
        store,
        workspace,
        predecessor,
        coordinator_session,
        freeze,
        delegation,
        binding,
    })
}

fn recover_expired_predecessor(
    fixture: &mut P28Seed,
    seed: u128,
) -> Result<(forge_domain::RegisteredActivity, RuntimeInstanceId), Box<dyn std::error::Error>> {
    let p28_scope = ExpiredActivityRecoveryProbeScope::new(
        fixture.workspace.id(),
        fixture.workspace.revision(),
        fixture.workspace.location_id(),
        forge_domain::LocationRevision::INITIAL,
        b".".to_vec(),
        fixture.workspace.root_fingerprint(),
        fixture.binding.recovery_history_digest(),
    )?;
    let p28_probe = fixture.store.probe_expired_activity_recovery(
        &fixture.binding,
        &p28_scope,
        fixture.predecessor.id(),
        timestamp(100)?,
    )?;
    let successor_id = activity_id(seed + 4);
    let p28_expectation = forge_domain::ExpiredActivityRecoveryExpectation::new(
        p28_probe.predecessor(),
        successor_id,
        fixture.coordinator_session,
        AuthenticatedPrincipal::TrustedStdio,
        p28_probe.agent_count(),
        *p28_probe.agent_digest(),
        p28_probe.coordinator(),
    )?;
    let p28_owner = runtime_id(seed + 5);
    let p28_request = ExpiredActivityRecoveryStoreRequest {
        request_id: Uuid::from_u128(seed + 32),
        request_digest: [0xA8; 32],
        probe_scope: p28_scope,
        probe_observed_at: p28_probe.probe_observed_at(),
        probe_digest: *p28_probe.probe_digest(),
        delegation: p28_probe.delegation(),
        delegation_digest: *p28_probe.delegation_digest(),
        service_backend_id: ForgeBackendId::from_uuid(Uuid::from_u128(seed + 33)),
        service_issuer: OrchestrationIssuerId::from_uuid(Uuid::from_u128(seed + 34)),
        service_destination_id: fixture.delegation.destination_id(),
        owner_id: p28_owner,
        duration: RecoveryLeaseDurationMillis::new(1_000)?,
        expectation: p28_expectation,
        session: ExpiredActivityRecoverySessionEvidence::new(
            fixture.coordinator_session,
            AuthenticatedPrincipal::TrustedStdio,
            1,
            timestamp(20)?,
        )?,
    };
    let successor = match fixture.store.run_expired_activity_recovery_with_clock(
        &fixture.binding,
        &p28_request,
        || {
            timestamp(100).map_err(|error| WorkspaceStoreError::DamagedSchema {
                detail: error.to_string(),
            })
        },
    )? {
        ExpiredActivityRecoveryOperation::Recorded(receipt) => receipt.successor().clone(),
        other => return Err(format!("unexpected p28 outcome: {other:?}").into()),
    };
    Ok((successor, p28_owner))
}

fn activate_successor_agents(
    fixture: &mut P28Seed,
    successor: &forge_domain::RegisteredActivity,
    seed: u128,
) -> Result<Vec<forge_domain::RegisteredAgentInstance>, Box<dyn std::error::Error>> {
    let mut activated = Vec::new();
    for (offset, name, role) in [
        (60_u128, "continued coordinator", "coordinator"),
        (70_u128, "continued worker", "worker"),
    ] {
        let reservation = crate::AgentBindingReservationRequest::new(
            Uuid::from_u128(seed + offset),
            successor.id(),
            forge_domain::AgentInstanceId::from_uuid(Uuid::from_u128(seed + offset + 1)),
            forge_domain::AgentSessionId::from_uuid(Uuid::from_u128(seed + offset + 2)),
            AuthenticatedPrincipal::TrustedStdio,
            timestamp(101)?,
        )?;
        let _reservation =
            fixture
                .store
                .reserve_agent_binding(&fixture.freeze, &reservation, timestamp(101)?)?;
        let _activation = fixture.store.activate_agent_binding(
            &fixture.delegation,
            &crate::AgentBindingActivationRequest::new(
                reservation.request_id(),
                [u8::try_from(offset).unwrap_or(1); 32],
                forge_domain::AgentDisplayName::new(name.to_owned())?,
                forge_domain::AgentDeclaredRole::new(role.to_owned())?,
                forge_domain::AgentTransportKind::Stdio,
            )?,
            timestamp(102)?,
        )?;
        activated.push(
            fixture
                .store
                .get_agent(reservation.agent_id())?
                .ok_or("activated successor Agent missing")?,
        );
    }
    Ok(activated)
}

fn create_continuation_goal(
    store: &mut WorkspaceStore,
    actor: forge_domain::ActivityCoordinatorActor,
    workspace_revision: WorkspaceRevision,
    seed: u128,
) -> Result<forge_domain::RegisteredGoal, Box<dyn std::error::Error>> {
    let command = forge_domain::GoalMutationCommand::new(
        forge_domain::GoalMutationRequestId::from_uuid(Uuid::from_u128(seed + 46)),
        actor,
        workspace_revision,
        forge_domain::GoalId::from_uuid(Uuid::from_u128(seed + 40)),
        None,
        timestamp(110)?,
        forge_domain::GoalMutationAction::Create(Box::new(forge_domain::GoalContract::new(
            forge_domain::GoalObjective::new("Continue retained plan".to_owned())?,
            vec![forge_domain::GoalStatement::new(
                "Remain unstarted".to_owned(),
            )?],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )?)),
    )?;
    store
        .apply_goal_mutation(&command, None, timestamp(110)?)?
        .current_goal()
        .cloned()
        .ok_or_else(|| "created Goal missing from canonical mutation result".into())
}

fn offer_assignment(
    store: &mut WorkspaceStore,
    actor: forge_domain::ActivityCoordinatorActor,
    target: &forge_domain::RegisteredAgentInstance,
    goal: &forge_domain::RegisteredGoal,
    node: &forge_domain::RegisteredDagNode,
    seed: u128,
) -> Result<forge_domain::RegisteredAgentAssignment, Box<dyn std::error::Error>> {
    store
        .offer_agent_assignment(
            &forge_domain::OfferAgentAssignment::new(
                forge_domain::AgentAssignmentId::from_uuid(Uuid::from_u128(seed + 45)),
                actor,
                forge_domain::AgentAssignmentTarget::new(
                    target.id(),
                    target.session_id().ok_or("target Session missing")?,
                    target.principal(),
                    target.revision(),
                ),
                goal.id(),
                goal.revision(),
                goal.timestamps().created_at(),
                forge_domain::DagRevisionNumber::INITIAL,
                forge_domain::DagHeadRevision::INITIAL,
                node.id(),
                node.revision(),
                None,
                timestamp(112)?,
            ),
            timestamp(112)?,
        )
        .map_err(Into::into)
}

fn seed_unstarted_plan(
    fixture: &mut P28Seed,
    successor: &forge_domain::RegisteredActivity,
    activated: &[forge_domain::RegisteredAgentInstance],
    seed: u128,
) -> Result<forge_domain::RegisteredAgentAssignment, Box<dyn std::error::Error>> {
    let current_coordinator_agent = &activated[0];
    let current_coordinator_session = current_coordinator_agent
        .session_id()
        .ok_or("continued Coordinator Session missing")?;
    let current_coordinator = fixture.store.claim_activity_coordinator(
        forge_domain::ClaimActivityCoordinator::new(
            fixture.workspace.id(),
            successor.id(),
            current_coordinator_agent.id(),
            AuthenticatedPrincipal::TrustedStdio,
            timestamp(103)?,
            current_coordinator_session,
        ),
        timestamp(103)?,
    )?;
    let actor = forge_domain::ActivityCoordinatorActor::new(
        fixture.workspace.id(),
        successor.id(),
        current_coordinator.agent_id(),
        current_coordinator.revision(),
        AuthenticatedPrincipal::TrustedStdio,
        current_coordinator_session,
    );
    let goal = create_continuation_goal(
        &mut fixture.store,
        actor,
        fixture.workspace.revision(),
        seed,
    )?;
    let definition = forge_domain::DagNodeDefinition::new(
        forge_domain::DagNodeId::from_uuid(Uuid::from_u128(seed + 41)),
        forge_domain::DagNodeOrdinal::new(0)?,
        forge_domain::DagNodeTitle::new("Pending node".to_owned())?,
        forge_domain::DagNodeObjective::new("Stay pending".to_owned())?,
        vec![forge_domain::DagAcceptanceCriterion::new(
            "Not executed".to_owned(),
        )?],
    )?;
    let revision = forge_domain::DagRevision::new(
        forge_domain::DagRevisionId::from_uuid(Uuid::from_u128(seed + 42)),
        goal.id(),
        goal.revision(),
        forge_domain::DagRevisionNumber::INITIAL,
        None,
        vec![definition.clone()],
        Vec::new(),
        timestamp(111)?,
    )?;
    let node = forge_domain::RegisteredDagNode::create(
        goal.id(),
        revision.number(),
        definition,
        timestamp(111)?,
    );
    let draft = forge_domain::AgentDagDraft::new(revision, vec![node.clone()], Vec::new())?;
    let plan = forge_domain::AgentDagPlanRequest::new(
        forge_domain::AgentDagPlanRequestId::from_uuid(Uuid::from_u128(seed + 43)),
        actor,
        forge_domain::GoalAttribution::new(goal.id(), goal.revision()),
        None,
        None,
        draft,
        forge_domain::AgentWorkUpdateId::from_uuid(Uuid::from_u128(seed + 44)),
        forge_domain::AgentWorkUpdateSequence::INITIAL,
        timestamp(111)?,
    );
    let _plan = fixture
        .store
        .commit_coordinator_dag_plan(&plan, timestamp(111)?)?;
    let target = &activated[1];
    offer_assignment(&mut fixture.store, actor, target, &goal, &node, seed)
}

#[allow(
    clippy::too_many_lines,
    reason = "The fixture mirrors the complete normal bootstrap, binding, planning, and offer lifecycle."
)]
fn normal_bootstrap_fixture(
    label: &str,
    seed: u128,
) -> Result<
    (
        FileFactFixture,
        crate::AgentOperationsDelegation,
        forge_domain::RegisteredAgentAssignment,
    ),
    Box<dyn std::error::Error>,
> {
    let root = unique_root(label)?;
    let layout = WorkspaceStateLayout::initialize(&root)?;
    let workspace_command = command(&layout, workspace_id(seed), location_id(seed + 1), 1)?;
    let mut store = WorkspaceStore::open(&layout, &workspace_command)?;
    let owner = runtime_id(seed + 2);
    let activity = store.bootstrap_activity(&forge_domain::BootstrapActivity::new(
        activity_id(seed + 3),
        workspace_command.id(),
        WorkspaceRevision::INITIAL,
        owner,
        timestamp(1_000)?,
        timestamp(10)?,
    ))?;
    let activity = store.renew_activity_lease(&forge_domain::RenewActivityLease::new(
        activity.id(),
        owner,
        activity.lease_revision(),
        timestamp(2_000)?,
        timestamp(20)?,
    ))?;
    let activity = store.renew_activity_lease(&forge_domain::RenewActivityLease::new(
        activity.id(),
        owner,
        activity.lease_revision(),
        timestamp(3_000)?,
        timestamp(25)?,
    ))?;

    let freeze = store.freeze_agent_operations(&crate::AgentOperationsFreezeRequest::new(
        Uuid::from_u128(seed + 30),
        Uuid::from_u128(seed + 31),
        timestamp(30)?,
    )?)?;
    let delegation = store.delegate_agent_operations(&freeze, [0x5C; 32], timestamp(31)?)?;
    let assignment = seed_normal_planning_activity(
        &mut store,
        workspace_command.id(),
        &activity,
        &freeze,
        &delegation,
        seed,
    )?;
    Ok((
        FileFactFixture {
            root,
            layout,
            store,
            activity,
            owner,
        },
        delegation,
        assignment,
    ))
}

#[allow(
    clippy::too_many_lines,
    reason = "The helper mirrors the complete bound-Agent, Coordinator, planning, and offer lifecycle for one Activity."
)]
fn seed_normal_planning_activity(
    store: &mut WorkspaceStore,
    workspace_id: WorkspaceId,
    activity: &forge_domain::RegisteredActivity,
    freeze: &crate::AgentOperationsFreeze,
    delegation: &crate::AgentOperationsDelegation,
    seed: u128,
) -> Result<forge_domain::RegisteredAgentAssignment, Box<dyn std::error::Error>> {
    let mut agents = Vec::new();
    for (offset, name, role) in [
        (60_u128, "normal coordinator", "coordinator"),
        (70_u128, "normal worker", "worker"),
        (80_u128, "normal reviewer", "reviewer"),
    ] {
        let reservation = crate::AgentBindingReservationRequest::new(
            Uuid::from_u128(seed + offset),
            activity.id(),
            AgentInstanceId::from_uuid(Uuid::from_u128(seed + offset + 1)),
            AgentSessionId::from_uuid(Uuid::from_u128(seed + offset + 2)),
            AuthenticatedPrincipal::TrustedStdio,
            timestamp(40)?,
        )?;
        let _reservation = store.reserve_agent_binding(freeze, &reservation, timestamp(40)?)?;
        let _activation = store.activate_agent_binding(
            delegation,
            &crate::AgentBindingActivationRequest::new(
                reservation.request_id(),
                [u8::try_from(offset).unwrap_or(1); 32],
                forge_domain::AgentDisplayName::new(name.to_owned())?,
                forge_domain::AgentDeclaredRole::new(role.to_owned())?,
                forge_domain::AgentTransportKind::Stdio,
            )?,
            timestamp(41)?,
        )?;
        agents.push(
            store
                .get_agent(reservation.agent_id())?
                .ok_or("normal bootstrap Agent missing")?,
        );
    }
    let coordinator_agent = &agents[0];
    let coordinator_session = coordinator_agent
        .session_id()
        .ok_or("normal bootstrap Coordinator Session missing")?;
    let coordinator = store.claim_activity_coordinator(
        forge_domain::ClaimActivityCoordinator::new(
            workspace_id,
            activity.id(),
            coordinator_agent.id(),
            AuthenticatedPrincipal::TrustedStdio,
            timestamp(42)?,
            coordinator_session,
        ),
        timestamp(42)?,
    )?;
    let actor = ActivityCoordinatorActor::new(
        workspace_id,
        activity.id(),
        coordinator.agent_id(),
        coordinator.revision(),
        AuthenticatedPrincipal::TrustedStdio,
        coordinator_session,
    );
    let workspace = store.workspace()?;
    let goal = create_continuation_goal(store, actor, workspace.revision(), seed)?;
    let definition = DagNodeDefinition::new(
        DagNodeId::from_uuid(Uuid::from_u128(seed + 41)),
        DagNodeOrdinal::new(0)?,
        DagNodeTitle::new("Normal pending node".to_owned())?,
        DagNodeObjective::new("Remain pending".to_owned())?,
        vec![DagAcceptanceCriterion::new("Not executed".to_owned())?],
    )?;
    let revision = DagRevision::new(
        DagRevisionId::from_uuid(Uuid::from_u128(seed + 42)),
        goal.id(),
        goal.revision(),
        DagRevisionNumber::INITIAL,
        None,
        vec![definition.clone()],
        Vec::new(),
        timestamp(111)?,
    )?;
    let node = forge_domain::RegisteredDagNode::create(
        goal.id(),
        revision.number(),
        definition,
        timestamp(111)?,
    );
    let draft = forge_domain::AgentDagDraft::new(revision, vec![node.clone()], Vec::new())?;
    let plan = forge_domain::AgentDagPlanRequest::new(
        forge_domain::AgentDagPlanRequestId::from_uuid(Uuid::from_u128(seed + 43)),
        actor,
        forge_domain::GoalAttribution::new(goal.id(), goal.revision()),
        None,
        None,
        draft,
        forge_domain::AgentWorkUpdateId::from_uuid(Uuid::from_u128(seed + 44)),
        forge_domain::AgentWorkUpdateSequence::INITIAL,
        timestamp(111)?,
    );
    let _ = store.commit_coordinator_dag_plan(&plan, timestamp(111)?)?;
    offer_assignment(store, actor, &agents[1], &goal, &node, seed)
}

#[allow(
    clippy::too_many_lines,
    clippy::type_complexity,
    reason = "The fixture proves two independent normal Activities share one Workspace authority without cross-Activity history rejection."
)]
fn same_workspace_normal_bootstrap_fixture(
    label: &str,
    seed: u128,
) -> Result<
    (
        FileFactFixture,
        forge_domain::RegisteredActivity,
        crate::AgentOperationsDelegation,
        forge_domain::RegisteredAgentAssignment,
        forge_domain::RegisteredAgentAssignment,
    ),
    Box<dyn std::error::Error>,
> {
    let root = unique_root(label)?;
    let layout = WorkspaceStateLayout::initialize(&root)?;
    let workspace_command = command(&layout, workspace_id(seed), location_id(seed + 1), 1)?;
    let mut store = WorkspaceStore::open(&layout, &workspace_command)?;
    let first_owner = runtime_id(seed + 2);
    let first_activity = store.bootstrap_activity(&forge_domain::BootstrapActivity::new(
        activity_id(seed + 3),
        workspace_command.id(),
        WorkspaceRevision::INITIAL,
        first_owner,
        timestamp(1_000)?,
        timestamp(10)?,
    ))?;
    let first_activity = store.renew_activity_lease(&forge_domain::RenewActivityLease::new(
        first_activity.id(),
        first_owner,
        first_activity.lease_revision(),
        timestamp(2_000)?,
        timestamp(20)?,
    ))?;
    let first_activity = store.renew_activity_lease(&forge_domain::RenewActivityLease::new(
        first_activity.id(),
        first_owner,
        first_activity.lease_revision(),
        timestamp(3_000)?,
        timestamp(25)?,
    ))?;
    let second_owner = runtime_id(seed + 4);
    let second_activity = store.bootstrap_activity(&forge_domain::BootstrapActivity::new(
        activity_id(seed + 5),
        workspace_command.id(),
        WorkspaceRevision::INITIAL,
        second_owner,
        timestamp(4_000)?,
        timestamp(12)?,
    ))?;
    let second_activity = store.renew_activity_lease(&forge_domain::RenewActivityLease::new(
        second_activity.id(),
        second_owner,
        second_activity.lease_revision(),
        timestamp(5_000)?,
        timestamp(20)?,
    ))?;
    let second_activity = store.renew_activity_lease(&forge_domain::RenewActivityLease::new(
        second_activity.id(),
        second_owner,
        second_activity.lease_revision(),
        timestamp(6_000)?,
        timestamp(25)?,
    ))?;
    let freeze = store.freeze_agent_operations(&crate::AgentOperationsFreezeRequest::new(
        Uuid::from_u128(seed + 30),
        Uuid::from_u128(seed + 31),
        timestamp(30)?,
    )?)?;
    let delegation = store.delegate_agent_operations(&freeze, [0x5C; 32], timestamp(31)?)?;
    let workspace_id = workspace_command.id();
    let first_assignment = seed_normal_planning_activity(
        &mut store,
        workspace_id,
        &first_activity,
        &freeze,
        &delegation,
        seed + 0x100,
    )?;
    let second_assignment = seed_normal_planning_activity(
        &mut store,
        workspace_id,
        &second_activity,
        &freeze,
        &delegation,
        seed + 0x200,
    )?;
    Ok((
        FileFactFixture {
            root,
            layout,
            store,
            activity: first_activity,
            owner: first_owner,
        },
        second_activity,
        delegation,
        first_assignment,
        second_assignment,
    ))
}

pub(super) fn recovered_predecessor_fixture(
    label: &str,
    seed: u128,
) -> Result<
    (
        FileFactFixture,
        crate::AgentOperationsDelegation,
        forge_domain::RegisteredAgentAssignment,
    ),
    Box<dyn std::error::Error>,
> {
    let mut fixture = seed_p28_predecessor(label, seed)?;
    let (successor, p28_owner) = recover_expired_predecessor(&mut fixture, seed)?;
    let activated = activate_successor_agents(&mut fixture, &successor, seed)?;
    let assignment = seed_unstarted_plan(&mut fixture, &successor, &activated, seed)?;
    Ok((
        FileFactFixture {
            root: fixture.root,
            layout: fixture.layout,
            store: fixture.store,
            activity: successor,
            owner: p28_owner,
        },
        fixture.delegation,
        assignment,
    ))
}

pub(super) fn probe(
    fixture: &FileFactFixture,
    assignment: &forge_domain::RegisteredAgentAssignment,
) -> Result<forge_domain::UnstartedActivityContinuationProbe, WorkspaceStoreError> {
    probe_for_activity(fixture, fixture.activity.id(), assignment)
}

fn probe_for_activity(
    fixture: &FileFactFixture,
    activity_id: forge_domain::ActivityId,
    assignment: &forge_domain::RegisteredAgentAssignment,
) -> Result<forge_domain::UnstartedActivityContinuationProbe, WorkspaceStoreError> {
    let activity = fixture
        .store
        .get_activity(activity_id)?
        .ok_or(WorkspaceStoreError::ActivityNotFound(activity_id))?;
    let observed_at = TimestampMillis::new(
        activity
            .lease_until()
            .ok_or(WorkspaceStoreError::DamagedSchema {
                detail: "test Activity lease missing".to_owned(),
            })?
            .get()
            + 1,
    )
    .map_err(|error| WorkspaceStoreError::DamagedSchema {
        detail: error.to_string(),
    })?;
    probe_for_activity_at(fixture, activity_id, assignment, observed_at)
}

fn probe_at(
    fixture: &FileFactFixture,
    assignment: &forge_domain::RegisteredAgentAssignment,
    observed_at: TimestampMillis,
) -> Result<forge_domain::UnstartedActivityContinuationProbe, WorkspaceStoreError> {
    probe_for_activity_at(fixture, fixture.activity.id(), assignment, observed_at)
}

fn probe_for_activity_at(
    fixture: &FileFactFixture,
    activity_id: forge_domain::ActivityId,
    assignment: &forge_domain::RegisteredAgentAssignment,
    observed_at: TimestampMillis,
) -> Result<forge_domain::UnstartedActivityContinuationProbe, WorkspaceStoreError> {
    let workspace = fixture.store.workspace()?;
    let binding = fixture.store.journal_binding()?;
    let scope = ExpiredActivityRecoveryProbeScope::new(
        workspace.id(),
        workspace.revision(),
        workspace.location_id(),
        forge_domain::LocationRevision::INITIAL,
        b".".to_vec(),
        workspace.root_fingerprint(),
        binding.recovery_history_digest(),
    )
    .map_err(|_| WorkspaceStoreError::DamagedSchema {
        detail: "test probe scope".to_owned(),
    })?;
    fixture.store.probe_unstarted_activity_continuation(
        &binding,
        &scope,
        activity_id,
        assignment.coordinator().session_id(),
        AuthenticatedPrincipal::TrustedStdio,
        UnstartedActivityContinuationServiceIdentity::new(
            ForgeBackendId::from_uuid(Uuid::from_u128(0xFA01)),
            OrchestrationIssuerId::from_uuid(Uuid::from_u128(0xFA02)),
            RuntimeInstanceId::from_uuid(Uuid::from_u128(0xFA03)),
        )
        .map_err(|error| WorkspaceStoreError::DamagedSchema {
            detail: error.to_string(),
        })?,
        observed_at,
    )
}

fn store_request(
    snapshot: &forge_domain::UnstartedActivityContinuationProbe,
    assignment: &forge_domain::RegisteredAgentAssignment,
    delegation: &crate::AgentOperationsDelegation,
    seed: u128,
) -> Result<UnstartedActivityContinuationStoreRequest, Box<dyn std::error::Error>> {
    Ok(UnstartedActivityContinuationStoreRequest {
        request_id: UnstartedActivityContinuationRequestId::new(Uuid::from_u128(seed))?,
        request_digest: [0xD4; 32],
        probe_scope: snapshot.scope().clone(),
        probe_observed_at: snapshot.observed_at(),
        probe_digest: snapshot.probe_digest(),
        delegation: snapshot.delegation(),
        delegation_digest: snapshot.delegation_digest(),
        service: snapshot.service(),
        service_destination_id: delegation.destination_id(),
        duration: RecoveryLeaseDurationMillis::new(1_000)?,
        expectation: snapshot.expectation().clone(),
        session: ExpiredActivityRecoverySessionEvidence::new(
            assignment.coordinator().session_id(),
            AuthenticatedPrincipal::TrustedStdio,
            1,
            timestamp(3)?,
        )?,
    })
}

#[test]
fn canonical_v66_positive_census_accepts_real_goal_dag_assignment_and_team()
-> Result<(), Box<dyn std::error::Error>> {
    let (fixture, delegation, assignment) =
        recovered_predecessor_fixture("unstarted-continuation-positive", 0xF100)?;
    let snapshot = probe(&fixture, &assignment)?;
    assert!(snapshot.continuable_now(), "{:?}", snapshot.blocker());
    assert_eq!(
        snapshot.delegation().destination_id(),
        delegation.destination_id()
    );
    assert_eq!(
        snapshot.expectation().activity().activity_id(),
        fixture.activity.id()
    );
    assert_eq!(snapshot.expectation().expected_agent_count(), 2);
    assert_ne!(snapshot.expectation().expected_plan_digest(), [0; 32]);
    let root = fixture.root.clone();
    drop(fixture);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn canonical_v66_normal_bootstrap_origin_continues_same_activity_with_future_lease()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut fixture, delegation, assignment) =
        normal_bootstrap_fixture("unstarted-continuation-normal-bootstrap", 0xF700)?;
    let snapshot = probe(&fixture, &assignment)?;
    assert!(snapshot.continuable_now(), "{:?}", snapshot.blocker());
    assert_eq!(snapshot.expectation().activity().lease_revision().get(), 3);
    assert_eq!(snapshot.expectation().expected_agent_count(), 3);
    assert_ne!(snapshot.expectation().expected_plan_digest(), [0; 32]);

    let binding = fixture.store.journal_binding()?;
    let before = fixture.store.get_activity(fixture.activity.id())?;
    let request = store_request(&snapshot, &assignment, &delegation, 0xF7C0)?;
    let recorded = fixture
        .store
        .run_unstarted_activity_continuation_with_clock(&binding, &request, || {
            Ok(snapshot.observed_at())
        })?;
    let receipt = match recorded {
        UnstartedActivityContinuationOperation::Recorded(receipt) => receipt,
        other => return Err(format!("unexpected normal bootstrap outcome: {other:?}").into()),
    };
    assert_eq!(receipt.activity_after().id(), fixture.activity.id());
    assert_eq!(
        receipt.activity_after().revision().get(),
        before
            .ok_or("Activity missing before continuation")?
            .revision()
            .get()
            + 1
    );
    assert_eq!(receipt.lease_gap_ms(), 1);
    assert!(
        receipt
            .activity_after()
            .lease_until()
            .ok_or("continued lease missing")?
            > receipt.continued_at()
    );
    assert_ne!(receipt.receipt_digest(), [0; 32]);

    let root = fixture.root.clone();
    drop(fixture);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn canonical_v66_same_workspace_normal_activities_keep_planning_provenance_scoped()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut fixture, second_activity, delegation, first_assignment, second_assignment) =
        same_workspace_normal_bootstrap_fixture("unstarted-continuation-same-workspace", 0xF740)?;
    let first_snapshot = probe(&fixture, &first_assignment)?;
    let second_snapshot = probe_for_activity(&fixture, second_activity.id(), &second_assignment)?;
    assert!(
        first_snapshot.continuable_now(),
        "{:?}",
        first_snapshot.blocker()
    );
    assert!(
        second_snapshot.continuable_now(),
        "{:?}",
        second_snapshot.blocker()
    );
    assert_ne!(
        first_snapshot.expectation().activity().activity_id(),
        second_snapshot.expectation().activity().activity_id()
    );

    let binding = fixture.store.journal_binding()?;
    let first_before = fixture.store.get_activity(fixture.activity.id())?;
    let second_request = store_request(&second_snapshot, &second_assignment, &delegation, 0xF7D0)?;
    let recorded = fixture
        .store
        .run_unstarted_activity_continuation_with_clock(&binding, &second_request, || {
            Ok(second_snapshot.observed_at())
        })?;
    let receipt = match recorded {
        UnstartedActivityContinuationOperation::Recorded(receipt) => receipt,
        other => return Err(format!("unexpected second Activity outcome: {other:?}").into()),
    };
    assert_eq!(receipt.activity_after().id(), second_activity.id());
    assert_eq!(
        fixture.store.get_activity(fixture.activity.id())?,
        first_before
    );

    let root = fixture.root.clone();
    drop(fixture);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn canonical_v66_run_rejects_probe_scope_with_stale_live_binding_digest()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut fixture, delegation, assignment) =
        normal_bootstrap_fixture("unstarted-continuation-stale-binding", 0xF760)?;
    let workspace = fixture.store.workspace()?;
    let binding = fixture.store.journal_binding()?;
    let stale_scope = ExpiredActivityRecoveryProbeScope::new(
        workspace.id(),
        workspace.revision(),
        workspace.location_id(),
        forge_domain::LocationRevision::INITIAL,
        b".".to_vec(),
        workspace.root_fingerprint(),
        [0xE7; 32],
    )?;
    let service = UnstartedActivityContinuationServiceIdentity::new(
        ForgeBackendId::from_uuid(Uuid::from_u128(0xFA01)),
        OrchestrationIssuerId::from_uuid(Uuid::from_u128(0xFA02)),
        RuntimeInstanceId::from_uuid(Uuid::from_u128(0xFA03)),
    )?;
    let transaction = fixture.store.connection.unchecked_transaction()?;
    let raw_probe = crate::workspace_store::unstarted_activity_continuation::probe_raw_for_test(
        &transaction,
        &stale_scope,
        fixture.activity.id(),
        assignment.coordinator().session_id(),
        AuthenticatedPrincipal::TrustedStdio,
        service,
        TimestampMillis::new(1_001)?,
    );
    transaction.rollback()?;
    let stale_probe = raw_probe?;
    let request = store_request(&stale_probe, &assignment, &delegation, 0xF7C1)?;
    let before_activity = fixture.store.get_activity(fixture.activity.id())?;
    let before_maintenance = fixture.store.get_recovery_maintenance_lease()?;
    let result = fixture
        .store
        .run_unstarted_activity_continuation_with_clock(&binding, &request, || {
            Ok(stale_probe.observed_at())
        });
    assert!(result.is_err(), "stale binding digest must be rejected");
    assert_eq!(
        fixture.store.get_activity(fixture.activity.id())?,
        before_activity
    );
    assert_eq!(
        fixture.store.get_recovery_maintenance_lease()?,
        before_maintenance
    );
    let root = fixture.root.clone();
    drop(fixture);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn canonical_v66_agent_census_overflow_reads_the_257th_row_and_rejects()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut fixture, delegation, assignment) =
        normal_bootstrap_fixture("unstarted-continuation-agent-overflow", 0xF780)?;
    let freeze = fixture
        .store
        .agent_operations_freeze(delegation.migration_id())?
        .ok_or("normal bootstrap freeze missing")?;
    let workspace = fixture.store.workspace()?;
    for ordinal in 3_u128..=256_u128 {
        let requested_at = timestamp(200 + i64::try_from(ordinal)?)?;
        let reservation = crate::AgentBindingReservationRequest::new(
            Uuid::from_u128(0xF780_0000 + ordinal),
            fixture.activity.id(),
            AgentInstanceId::from_uuid(Uuid::from_u128(0xF790_0000 + ordinal * 2)),
            AgentSessionId::from_uuid(Uuid::from_u128(0xF790_0001 + ordinal * 2)),
            AuthenticatedPrincipal::TrustedStdio,
            requested_at,
        )?;
        let _reservation =
            fixture
                .store
                .reserve_agent_binding(&freeze, &reservation, requested_at)?;
        let _activation = fixture.store.activate_agent_binding(
            &delegation,
            &crate::AgentBindingActivationRequest::new(
                reservation.request_id(),
                [0xA5; 32],
                forge_domain::AgentDisplayName::new(format!("overflow agent {ordinal}"))?,
                forge_domain::AgentDeclaredRole::new("worker".to_owned())?,
                forge_domain::AgentTransportKind::Stdio,
            )?,
            TimestampMillis::new(requested_at.get() + 1)?,
        )?;
    }
    assert_eq!(
        fixture.store.connection.query_row(
            "SELECT COUNT(*) FROM agent_instances WHERE workspace_id=?1 AND activity_id=?2",
            params![
                workspace.id().into_uuid().as_bytes(),
                fixture.activity.id().into_uuid().as_bytes()
            ],
            |row| row.get::<_, i64>(0),
        )?,
        257
    );
    let Err(error) = probe(&fixture, &assignment) else {
        return Err("257 Agents must fail closed".into());
    };
    assert!(error.to_string().contains("Agent census bounds"), "{error}");
    let root = fixture.root.clone();
    drop(fixture);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn canonical_v66_normal_bootstrap_rejects_lease_before_activity_update()
-> Result<(), Box<dyn std::error::Error>> {
    let (fixture, _delegation, assignment) =
        normal_bootstrap_fixture("unstarted-continuation-corrupt-lease", 0xF7A0)?;
    fixture.store.connection.execute(
        "UPDATE activities SET created_at_ms=1000, updated_at_ms=1000, lease_until_ms=10 WHERE activity_id=?1",
        params![fixture.activity.id().into_uuid().as_bytes()],
    )?;
    let Err(error) = probe_at(&fixture, &assignment, timestamp(11)?) else {
        return Err("a normal bootstrap lease must outlive the Activity historical update".into());
    };
    assert!(
        error
            .to_string()
            .contains("normal bootstrap Activity origin"),
        "{error}"
    );
    let root = fixture.root.clone();
    drop(fixture);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn canonical_v66_corrupt_successor_lineage_cannot_fall_back_to_normal_origin()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut fixture, delegation, assignment) =
        normal_bootstrap_fixture("unstarted-continuation-normal-lineage", 0xF800)?;
    let workspace = fixture.store.workspace()?;
    let predecessor = fixture
        .store
        .bootstrap_activity(&forge_domain::BootstrapActivity::new(
            activity_id(0xF8F1),
            workspace.id(),
            workspace.revision(),
            runtime_id(0xF8F2),
            timestamp(1_000)?,
            timestamp(10)?,
        ))?;
    fixture.store.connection.execute(
        "INSERT INTO activity_successors (
            workspace_id, predecessor_activity_id, predecessor_activity_revision,
            successor_activity_id, initiating_session_id, runtime_instance_id, created_at_ms
         ) VALUES (?1,?2,1,?3,?4,?5,100)",
        params![
            workspace.id().into_uuid().as_bytes(),
            predecessor.id().into_uuid().as_bytes(),
            fixture.activity.id().into_uuid().as_bytes(),
            assignment.coordinator().session_id().into_uuid().as_bytes(),
            runtime_id(0xF8F3).into_uuid().as_bytes(),
        ],
    )?;
    assert!(probe(&fixture, &assignment).is_err());
    let root = fixture.root.clone();
    drop((fixture, delegation));
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn canonical_v66_arbitrary_work_update_blocks_positive_census()
-> Result<(), Box<dyn std::error::Error>> {
    let (fixture, _delegation, assignment) =
        recovered_predecessor_fixture("unstarted-continuation-work", 0xF200)?;
    fixture.store.connection.execute(
        "INSERT INTO agent_work_updates (
            update_id, agent_id, workspace_id, activity_id, update_sequence,
            phase, summary, evidence_count, observed_at_ms
         ) VALUES (?1,?2,?3,?4,99,0,'arbitrary non-plan work',0,200)",
        params![
            Uuid::from_u128(0xF2FF).as_bytes(),
            assignment.coordinator().agent_id().into_uuid().as_bytes(),
            fixture.store.workspace()?.id().into_uuid().as_bytes(),
            fixture.activity.id().into_uuid().as_bytes()
        ],
    )?;
    let snapshot = probe(&fixture, &assignment)?;
    assert_eq!(
        snapshot.blocker(),
        Some(UnstartedActivityContinuationBlocker::ArbitraryWorkHistory)
    );
    let root = fixture.root.clone();
    drop(fixture);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn canonical_v66_unknown_schema_object_fails_before_census()
-> Result<(), Box<dyn std::error::Error>> {
    let (fixture, _delegation, assignment) =
        recovered_predecessor_fixture("unstarted-continuation-unknown", 0xF300)?;
    fixture
        .store
        .connection
        .execute_batch("CREATE TABLE future_source_effect(workspace_id BLOB, activity_id BLOB)")?;
    assert!(matches!(
        probe(&fixture, &assignment),
        Err(WorkspaceStoreError::DamagedSchema { .. })
    ));
    let root = fixture.root.clone();
    drop(fixture);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn canonical_v66_goal_evidence_and_orphan_assignment_source_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let (fixture, _delegation, assignment) =
        recovered_predecessor_fixture("unstarted-continuation-evidence", 0xF350)?;
    fixture.store.connection.execute(
        "INSERT INTO goal_evidence_refs(goal_id,evidence_kind,evidence_id,associated_at_ms)
         VALUES (?1,0,?2,200)",
        params![
            assignment.goal_id().into_uuid().as_bytes(),
            Uuid::from_u128(0xF35E).as_bytes()
        ],
    )?;
    assert_eq!(
        probe(&fixture, &assignment)?.blocker(),
        Some(UnstartedActivityContinuationBlocker::DagEvidencePresent)
    );
    let root = fixture.root.clone();
    drop(fixture);
    std::fs::remove_dir_all(root)?;

    let (fixture, _delegation, assignment) =
        recovered_predecessor_fixture("unstarted-continuation-orphan", 0xF360)?;
    fixture
        .store
        .connection
        .pragma_update(None, "foreign_keys", false)?;
    fixture.store.connection.execute(
        "INSERT INTO agent_assignment_sources(
            assignment_id,ordinal,source_kind,source_url,provenance_kind,provenance_id
         ) VALUES (?1,0,0,'https://invalid.example',NULL,NULL)",
        params![Uuid::from_u128(0xF36E).as_bytes()],
    )?;
    fixture
        .store
        .connection
        .pragma_update(None, "foreign_keys", true)?;
    assert_eq!(
        probe(&fixture, &assignment)?.blocker(),
        Some(UnstartedActivityContinuationBlocker::OrphanRecord)
    );
    let root = fixture.root.clone();
    drop(fixture);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn assert_fresh_boot_rejected(
    fixture: &mut FileFactFixture,
    binding: &crate::WorkspaceJournalBinding,
    request: &UnstartedActivityContinuationStoreRequest,
    snapshot: &forge_domain::UnstartedActivityContinuationProbe,
    original_service: UnstartedActivityContinuationServiceIdentity,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut wrong_fresh_boot = request.clone();
    wrong_fresh_boot.service = UnstartedActivityContinuationServiceIdentity::new(
        original_service.backend_id(),
        original_service.issuer(),
        RuntimeInstanceId::from_uuid(Uuid::from_u128(0xF4AF)),
    )?;
    assert!(
        fixture
            .store
            .run_unstarted_activity_continuation_with_clock(binding, &wrong_fresh_boot, || Ok(
                snapshot.observed_at()
            ),)
            .is_err(),
        "a new boot cannot consume an old probe when no receipt exists"
    );
    assert!(
        fixture
            .store
            .unstarted_activity_continuation_readback_for_request(
                binding,
                request.request_id,
                request.request_digest,
            )?
            .is_none()
    );
    Ok(())
}

fn record_continuation(
    fixture: &mut FileFactFixture,
    binding: &crate::WorkspaceJournalBinding,
    request: &UnstartedActivityContinuationStoreRequest,
    snapshot: &forge_domain::UnstartedActivityContinuationProbe,
    before: &forge_domain::RegisteredActivity,
    original_service: UnstartedActivityContinuationServiceIdentity,
) -> Result<crate::UnstartedActivityContinuationReceipt, Box<dyn std::error::Error>> {
    let continued_at = snapshot.observed_at();
    let recorded = fixture
        .store
        .run_unstarted_activity_continuation_with_clock(binding, request, || {
            let contender = rusqlite::Connection::open(fixture.layout.database_path())?;
            contender.busy_timeout(std::time::Duration::from_millis(0))?;
            assert!(
                contender
                    .execute(
                        "UPDATE activities SET updated_at_ms=updated_at_ms WHERE activity_id=?1",
                        params![fixture.activity.id().into_uuid().as_bytes()],
                    )
                    .is_err(),
                "continuation clock must run after BEGIN IMMEDIATE"
            );
            Ok(continued_at)
        })?;
    let receipt = match recorded {
        UnstartedActivityContinuationOperation::Recorded(receipt) => receipt,
        other => return Err(format!("unexpected first outcome: {other:?}").into()),
    };
    assert_eq!(receipt.activity_after().id(), before.id());
    assert_eq!(
        receipt.activity_after().revision().get(),
        before.revision().get() + 1
    );
    assert_eq!(
        receipt.activity_after().lease_revision().get(),
        before.lease_revision().get() + 1
    );
    assert_eq!(
        receipt.activity_after().lease_owner_id(),
        Some(original_service.runtime_instance_id())
    );
    assert_eq!(receipt.lease_gap_ms(), 1);
    assert_eq!(
        receipt.expectation().expected_plan_digest(),
        snapshot.expectation().expected_plan_digest()
    );
    Ok(receipt)
}

fn run_replay_assertions(
    mut fixture: FileFactFixture,
    binding: &crate::WorkspaceJournalBinding,
    request: &UnstartedActivityContinuationStoreRequest,
    original_service: UnstartedActivityContinuationServiceIdentity,
    receipt: &crate::UnstartedActivityContinuationReceipt,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut different_boot = request.clone();
    different_boot.service = UnstartedActivityContinuationServiceIdentity::new(
        original_service.backend_id(),
        original_service.issuer(),
        RuntimeInstanceId::from_uuid(Uuid::from_u128(0xF4B3)),
    )?;
    let replay = fixture
        .store
        .run_unstarted_activity_continuation_with_clock(binding, &different_boot, || {
            Err(WorkspaceStoreError::DamagedSchema {
                detail: "replay sampled clock".to_owned(),
            })
        })?;
    let replayed = match replay {
        UnstartedActivityContinuationOperation::Replay(receipt) => receipt,
        other => return Err(format!("unexpected replay outcome: {other:?}").into()),
    };
    assert_eq!(replayed.service(), original_service);
    assert_eq!(replayed.receipt_digest(), receipt.receipt_digest());

    let root = fixture.root.clone();
    let layout = fixture.layout.clone();
    drop(fixture);
    let existing = WorkspaceStateLayout::inspect_existing(layout.workspace_root())?
        .ok_or("Workspace missing")?;
    let reopened = WorkspaceStore::open_existing(&existing)?;
    let readback = reopened
        .unstarted_activity_continuation_readback_for_request(
            &reopened.journal_binding()?,
            request.request_id,
            request.request_digest,
        )?
        .ok_or("continuation receipt missing after restart")?;
    assert_eq!(
        readback.receipt().receipt_digest(),
        receipt.receipt_digest()
    );
    assert_eq!(
        readback.receipt().activity_after(),
        receipt.activity_after()
    );
    reopened.connection.execute(
        "UPDATE unstarted_activity_continuation_receipts
         SET receipt_digest=zeroblob(32) WHERE request_id=?1",
        params![request.request_id.into_uuid().as_bytes()],
    )?;
    assert!(
        reopened
            .unstarted_activity_continuation_readback_for_request(
                &reopened.journal_binding()?,
                request.request_id,
                request.request_digest,
            )
            .is_err(),
        "receipt corruption must fail exact historical readback"
    );
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn canonical_v66_continuation_records_gap_preserves_ids_and_replays_after_boot_change()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut fixture, delegation, assignment) =
        recovered_predecessor_fixture("unstarted-continuation-run", 0xF400)?;
    let snapshot = probe(&fixture, &assignment)?;
    assert!(snapshot.continuable_now());
    let binding = fixture.store.journal_binding()?;
    let before = fixture.activity.clone();
    let original_service = snapshot.service();
    let mut request = store_request(&snapshot, &assignment, &delegation, 0xF4C0)?;
    request.request_digest = [0xC4; 32];
    assert_fresh_boot_rejected(
        &mut fixture,
        &binding,
        &request,
        &snapshot,
        original_service,
    )?;
    let receipt = record_continuation(
        &mut fixture,
        &binding,
        &request,
        &snapshot,
        &before,
        original_service,
    )?;
    run_replay_assertions(fixture, &binding, &request, original_service, &receipt)
}

#[test]
fn canonical_v66_stale_probe_and_clock_failure_roll_back_maintenance_claim()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut fixture, delegation, assignment) =
        recovered_predecessor_fixture("unstarted-continuation-rollback", 0xF500)?;
    let snapshot = probe(&fixture, &assignment)?;
    let binding = fixture.store.journal_binding()?;
    let request = store_request(&snapshot, &assignment, &delegation, 0xF5C0)?;
    let before_activity = fixture.store.get_activity(fixture.activity.id())?;
    let before_maintenance = fixture.store.get_recovery_maintenance_lease()?;
    let clock_failure = fixture
        .store
        .run_unstarted_activity_continuation_with_clock(&binding, &request, || {
            Err(WorkspaceStoreError::DamagedSchema {
                detail: "clock failure".to_owned(),
            })
        });
    assert!(clock_failure.is_err());
    assert_eq!(
        fixture.store.get_activity(fixture.activity.id())?,
        before_activity
    );
    assert_eq!(
        fixture.store.get_recovery_maintenance_lease()?,
        before_maintenance
    );

    fixture.store.connection.execute(
        "UPDATE goals SET state=1, updated_at_ms=updated_at_ms+1, revision=revision+1 WHERE activity_id=?1",
        params![fixture.activity.id().into_uuid().as_bytes()],
    )?;
    let stale = fixture
        .store
        .run_unstarted_activity_continuation_with_clock(&binding, &request, || {
            Ok(snapshot.observed_at())
        });
    assert!(stale.is_err());
    assert_eq!(
        fixture.store.get_activity(fixture.activity.id())?,
        before_activity
    );
    assert_eq!(
        fixture.store.get_recovery_maintenance_lease()?,
        before_maintenance
    );
    let root = fixture.root.clone();
    drop(fixture);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn canonical_v66_root_replacement_after_writer_lock_rolls_back_continuation()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut fixture, delegation, assignment) =
        recovered_predecessor_fixture("unstarted-continuation-root-race", 0xF600)?;
    let snapshot = probe(&fixture, &assignment)?;
    let binding = fixture.store.journal_binding()?;
    let request = store_request(&snapshot, &assignment, &delegation, 0xF6C0)?;
    let before_activity = fixture.store.get_activity(fixture.activity.id())?;
    let before_maintenance = fixture.store.get_recovery_maintenance_lease()?;
    let root = fixture.root.clone();
    let displaced = root.with_extension("displaced");
    let result = fixture
        .store
        .run_unstarted_activity_continuation_with_clock(&binding, &request, || {
            std::fs::rename(&root, &displaced)
                .and_then(|()| std::fs::create_dir(&root))
                .map_err(|source| WorkspaceStoreError::DamagedSchema {
                    detail: format!("root replacement fixture failed: {source}"),
                })?;
            Ok(snapshot.observed_at())
        });
    std::fs::remove_dir(&root)?;
    std::fs::rename(&displaced, &root)?;
    assert!(result.is_err(), "replaced root must fail before commit");
    assert_eq!(
        fixture.store.get_activity(fixture.activity.id())?,
        before_activity
    );
    assert_eq!(
        fixture.store.get_recovery_maintenance_lease()?,
        before_maintenance
    );
    assert!(
        fixture
            .store
            .unstarted_activity_continuation_readback_for_request(
                &binding,
                request.request_id,
                request.request_digest,
            )?
            .is_none()
    );
    drop(fixture);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
