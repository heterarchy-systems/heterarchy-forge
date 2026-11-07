//! Native Source proposal history, CAS, and no-effect tests.

use super::*;
use crate::workspace_home_transfers::handoffs::{
    HomeHandoffProposalEvidence, HomeHandoffProposalHooks, HomeHandoffProposalOutcome,
    HomeHandoffProposalStoreError,
    get_current_in_transaction as get_current_proposal_in_transaction,
    propose as propose_in_transaction,
};
use forge_domain::{
    ActivityCoordinatorActor, AgentAssignmentId, AgentAssignmentState, AgentAssignmentTarget,
    AgentDagDraft, AgentDagPlanRequest, AgentDagPlanRequestId, AgentWorkUpdateId,
    AgentWorkUpdateSequence, ClaimActivityCoordinator, ClaimAgentAssignment,
    DagAcceptanceCriterion, DagHeadRevision, DagNodeDefinition, DagNodeId, DagNodeObjective,
    DagNodeOrdinal, DagNodeTitle, DagRevision, DagRevisionId, DagRevisionNumber, ForgeBackendId,
    GoalAttribution, GoalContract, GoalId, GoalObjective, GoalStatement, HomeArtifactId,
    HomeHandoffProposalRequest, HomeHandoffTakeRequest, HomeTransferSourceAction,
    HomeTransferSourceBinding, HomeTransferSourceGrant, HomeTransferSourceRequest,
    HomeTransferSourceScope, HomeTransferSourceSubject, HomeTransferSourceWitness, RegisteredGoal,
    TimestampMillis, WorkspaceId,
};
use rusqlite::{Connection, params};
use std::path::PathBuf;
use std::thread;
use std::time::Duration;
use uuid::Uuid;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Direct internal calls in corruption tests still delegate to the actual
/// durable application owner; this adapter never returns a default `false`.
struct DurableApplicationHooks;

impl HomeHandoffProposalHooks for DurableApplicationHooks {
    fn handoff_is_applied(
        &self,
        connection: &Connection,
        handoff_id: Uuid,
    ) -> Result<bool, HomeHandoffProposalStoreError> {
        Ok(crate::workspace_home_transfers::handoffs::handoff_is_applied(connection, handoff_id)?)
    }

    fn home_origin_matches_applied_receipt(
        &self,
        connection: &Connection,
        successor_assignment_id: AgentAssignmentId,
        origin: forge_domain::AgentAssignmentHomeHandoffOrigin,
    ) -> Result<bool, HomeHandoffProposalStoreError> {
        Ok(
            crate::workspace_home_transfers::handoffs::home_origin_matches_applied_receipt(
                connection,
                successor_assignment_id,
                origin,
            )?,
        )
    }
}

struct Fixture {
    root: PathBuf,
    store: WorkspaceStore,
    workspace_id: WorkspaceId,
    activity_id: forge_domain::ActivityId,
    actor: ActivityCoordinatorActor,
    next_coordinator: forge_domain::RegisteredAgentInstance,
    recipient: forge_domain::RegisteredAgentInstance,
    alternate_recipient: forge_domain::RegisteredAgentInstance,
    assignment: forge_domain::RegisteredAgentAssignment,
    unbound_predecessor: Option<forge_domain::RegisteredAgentAssignment>,
    preparation_id: Uuid,
    backend: ForgeBackendId,
    destination: Uuid,
    issuer: forge_domain::OrchestrationIssuerId,
}

#[allow(
    clippy::too_many_lines,
    reason = "one native fixture establishes Workspace, Coordinator, Goal/DAG, assignment, and Prepared parent"
)]
fn build_fixture(label: &str, seed: u128, running: bool) -> TestResult<Fixture> {
    build_fixture_with_unbound_predecessor(label, seed, running, false, false)
}

#[allow(
    clippy::too_many_lines,
    reason = "one native fixture establishes Workspace, Coordinator, Goal/DAG, assignment, and Prepared parent"
)]
fn build_fixture_with_unbound_predecessor(
    label: &str,
    seed: u128,
    running: bool,
    include_unbound_predecessor: bool,
    include_unbound_session: bool,
) -> TestResult<Fixture> {
    let (root, _layout, mut store, activity_id) = super::store_with_live_activity(label)?;
    let workspace_id = store.workspace()?.id();
    let coordinator = super::inventory_seeded_agent(&store, workspace_id, activity_id, seed + 10)?;
    let next_coordinator =
        super::inventory_seeded_agent(&store, workspace_id, activity_id, seed + 15)?;
    let predecessor_target =
        super::inventory_seeded_agent(&store, workspace_id, activity_id, seed + 20)?;
    let recipient = super::inventory_seeded_agent(&store, workspace_id, activity_id, seed + 25)?;
    let alternate_recipient =
        super::inventory_seeded_agent(&store, workspace_id, activity_id, seed + 30)?;

    let coordinator_session = coordinator
        .session_id()
        .ok_or("Coordinator fixture is missing its Session")?;
    let binding = store.claim_activity_coordinator(
        ClaimActivityCoordinator::new(
            workspace_id,
            activity_id,
            coordinator.id(),
            coordinator.principal(),
            super::timestamp(5)?,
            coordinator_session,
        ),
        super::timestamp(5)?,
    )?;
    let actor = ActivityCoordinatorActor::new(
        workspace_id,
        activity_id,
        coordinator.id(),
        binding.revision(),
        coordinator.principal(),
        coordinator_session,
    );

    let contract = GoalContract::new(
        GoalObjective::new("Continue one exact predecessor assignment".to_owned())?,
        vec![GoalStatement::new(
            "The proposal preserves the current Goal and node scope".to_owned(),
        )?],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    )?;
    let goal = RegisteredGoal::create(
        GoalId::from_uuid(Uuid::from_u128(seed + 40)),
        workspace_id,
        activity_id,
        contract,
        super::timestamp(10)?,
    );
    let goal = store.insert_goal(actor, &goal, super::timestamp(10)?)?;
    let definition = DagNodeDefinition::new(
        DagNodeId::from_uuid(Uuid::from_u128(seed + 41)),
        DagNodeOrdinal::new(0)?,
        DagNodeTitle::new("Home handoff proposal".to_owned())?,
        DagNodeObjective::new("Keep the assignment scope stable".to_owned())?,
        vec![DagAcceptanceCriterion::new(
            "The successor remains bound to this current node".to_owned(),
        )?],
    )?;
    let revision = DagRevision::new(
        DagRevisionId::from_uuid(Uuid::from_u128(seed + 42)),
        goal.id(),
        goal.revision(),
        DagRevisionNumber::INITIAL,
        None,
        vec![definition.clone()],
        Vec::new(),
        super::timestamp(15)?,
    )?;
    let node = forge_domain::RegisteredDagNode::create(
        goal.id(),
        revision.number(),
        definition,
        super::timestamp(15)?,
    );
    let draft = AgentDagDraft::new(revision, vec![node.clone()], Vec::new())?;
    let plan = AgentDagPlanRequest::new(
        AgentDagPlanRequestId::from_uuid(Uuid::from_u128(seed + 43)),
        actor,
        GoalAttribution::new(goal.id(), goal.revision()),
        None,
        None,
        draft,
        AgentWorkUpdateId::from_uuid(Uuid::from_u128(seed + 44)),
        AgentWorkUpdateSequence::INITIAL,
        super::timestamp(16)?,
    );
    let _committed_plan = store.commit_coordinator_dag_plan(&plan, super::timestamp(16)?)?;

    let predecessor_session = predecessor_target
        .session_id()
        .ok_or("predecessor fixture is missing its Session")?;
    let offered = store.offer_agent_assignment(
        &forge_domain::OfferAgentAssignment::new(
            AgentAssignmentId::from_uuid(Uuid::from_u128(seed + 45)),
            actor,
            AgentAssignmentTarget::new(
                predecessor_target.id(),
                predecessor_session,
                predecessor_target.principal(),
                predecessor_target.revision(),
            ),
            goal.id(),
            goal.revision(),
            goal.timestamps().created_at(),
            node.dag_revision(),
            DagHeadRevision::INITIAL,
            node.id(),
            node.revision(),
            None,
            super::timestamp(20)?,
        ),
        super::timestamp(20)?,
    )?;
    let assignment = if running {
        store.claim_agent_assignment(
            &ClaimAgentAssignment::new(
                offered.id(),
                offered.target(),
                offered.revision(),
                super::timestamp(22)?,
            ),
            super::timestamp(22)?,
        )?
    } else {
        offered
    };
    let predecessor_target = store
        .get_agent(predecessor_target.id())?
        .ok_or("predecessor Agent missing after offer or claim")?;
    let assignment = store
        .get_agent_assignment(assignment.id())?
        .ok_or("predecessor Assignment disappeared")?;

    let unbound_predecessor = if include_unbound_predecessor {
        let unbound_contract = GoalContract::new(
            GoalObjective::new(
                "Keep an uncaptured predecessor out of the source binding".to_owned(),
            )?,
            vec![GoalStatement::new(
                "The Prepared Session roster must cover the moving Agent".to_owned(),
            )?],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )?;
        let unbound_goal = RegisteredGoal::create(
            GoalId::from_uuid(Uuid::from_u128(seed + 60)),
            workspace_id,
            activity_id,
            unbound_contract,
            super::timestamp(25)?,
        );
        let unbound_goal = store.insert_goal(actor, &unbound_goal, super::timestamp(25)?)?;
        let unbound_definition = DagNodeDefinition::new(
            DagNodeId::from_uuid(Uuid::from_u128(seed + 61)),
            DagNodeOrdinal::new(0)?,
            DagNodeTitle::new("Unbound predecessor fixture".to_owned())?,
            DagNodeObjective::new("Remain outside the Prepared binding".to_owned())?,
            vec![DagAcceptanceCriterion::new(
                "The exact Source Session roster is required".to_owned(),
            )?],
        )?;
        let unbound_revision = DagRevision::new(
            DagRevisionId::from_uuid(Uuid::from_u128(seed + 62)),
            unbound_goal.id(),
            unbound_goal.revision(),
            DagRevisionNumber::INITIAL,
            None,
            vec![unbound_definition.clone()],
            Vec::new(),
            super::timestamp(26)?,
        )?;
        let unbound_node = forge_domain::RegisteredDagNode::create(
            unbound_goal.id(),
            unbound_revision.number(),
            unbound_definition,
            super::timestamp(26)?,
        );
        let unbound_draft =
            AgentDagDraft::new(unbound_revision, vec![unbound_node.clone()], Vec::new())?;
        let unbound_plan = AgentDagPlanRequest::new(
            AgentDagPlanRequestId::from_uuid(Uuid::from_u128(seed + 63)),
            actor,
            GoalAttribution::new(unbound_goal.id(), unbound_goal.revision()),
            None,
            None,
            unbound_draft,
            AgentWorkUpdateId::from_uuid(Uuid::from_u128(seed + 64)),
            AgentWorkUpdateSequence::INITIAL.checked_next()?,
            super::timestamp(27)?,
        );
        let _committed_unbound_plan =
            store.commit_coordinator_dag_plan(&unbound_plan, super::timestamp(27)?)?;
        let unbound_session = alternate_recipient
            .session_id()
            .ok_or("uncaptured predecessor fixture is missing its Session")?;
        Some(store.offer_agent_assignment(
            &forge_domain::OfferAgentAssignment::new(
                AgentAssignmentId::from_uuid(Uuid::from_u128(seed + 65)),
                actor,
                AgentAssignmentTarget::new(
                    alternate_recipient.id(),
                    unbound_session,
                    alternate_recipient.principal(),
                    alternate_recipient.revision(),
                ),
                unbound_goal.id(),
                unbound_goal.revision(),
                unbound_goal.timestamps().created_at(),
                unbound_node.dag_revision(),
                DagHeadRevision::INITIAL,
                unbound_node.id(),
                unbound_node.revision(),
                None,
                super::timestamp(30)?,
            ),
            super::timestamp(30)?,
        )?)
    } else {
        None
    };

    let destination = Uuid::from_u128(seed + 51);
    let freeze = store.freeze_agent_operations(&crate::AgentOperationsFreezeRequest::new(
        Uuid::from_u128(seed + 50),
        destination,
        super::timestamp(35)?,
    )?)?;
    let delegation = store.delegate_agent_operations(&freeze, [0x5C; 32], super::timestamp(36)?)?;
    let backend = ForgeBackendId::from_uuid(Uuid::from_u128(seed + 52));
    let preparation_id = Uuid::from_u128(seed + 53);
    let scope = HomeTransferSourceScope::new(
        workspace_id,
        store.workspace()?.revision(),
        backend,
        destination,
    )?;
    let subject = HomeTransferSourceSubject::new(
        Uuid::from_u128(seed + 54),
        1,
        Uuid::from_u128(seed + 55),
        Uuid::from_u128(seed + 56),
        Uuid::from_u128(seed + 57),
        Uuid::from_u128(seed + 58),
        1,
        1,
    )?;
    let witness = HomeTransferSourceWitness::new(preparation_id, [0x51; 32], [0x52; 32])?;
    let coordinator_binding = HomeTransferSourceBinding::new(
        activity_id,
        coordinator.id(),
        coordinator_session,
        coordinator.principal(),
    )?;
    let target_binding = HomeTransferSourceBinding::new(
        activity_id,
        predecessor_target.id(),
        predecessor_target
            .session_id()
            .ok_or("predecessor Session missing after refresh")?,
        predecessor_target.principal(),
    )?;
    let mut source_sessions = vec![coordinator_session, target_binding.session_id()];
    if include_unbound_session {
        source_sessions.push(
            alternate_recipient
                .session_id()
                .ok_or("uncaptured predecessor fixture is missing its Session")?,
        );
    }
    let source_request = HomeTransferSourceRequest::new(
        witness,
        scope,
        subject,
        source_sessions,
        vec![coordinator_binding, target_binding],
    )?;
    let issuer = forge_domain::OrchestrationIssuerId::from_uuid(Uuid::from_u128(seed + 59));
    let grant = HomeTransferSourceGrant::new(
        issuer,
        HomeTransferSourceAction::Prepare,
        source_request.request_digest(),
        super::timestamp(40)?,
        super::timestamp(95)?,
    )?;
    let _prepared_source = store.prepare_home_transfer_source(
        &source_request,
        grant,
        issuer,
        backend,
        delegation.destination_id(),
        || TimestampMillis::new(45).map_err(|_| crate::HomeTransferStoreError::Clock),
    )?;

    Ok(Fixture {
        root,
        store,
        workspace_id,
        activity_id,
        actor,
        next_coordinator,
        recipient,
        alternate_recipient,
        assignment,
        unbound_predecessor,
        preparation_id,
        backend,
        destination,
        issuer,
    })
}

fn request(
    fixture: &Fixture,
    proposal_id: u128,
    handoff_id: u128,
    successor_id: u128,
    recipient: &forge_domain::RegisteredAgentInstance,
    artifact_id: Option<HomeArtifactId>,
    expected_case_revision: Option<i64>,
) -> TestResult<HomeHandoffProposalRequest> {
    request_for_predecessor(
        fixture,
        &fixture.assignment,
        proposal_id,
        handoff_id,
        successor_id,
        recipient,
        artifact_id,
        expected_case_revision,
    )
}

#[allow(clippy::too_many_arguments)]
fn request_for_predecessor(
    fixture: &Fixture,
    predecessor: &forge_domain::RegisteredAgentAssignment,
    proposal_id: u128,
    handoff_id: u128,
    successor_id: u128,
    recipient: &forge_domain::RegisteredAgentInstance,
    artifact_id: Option<HomeArtifactId>,
    expected_case_revision: Option<i64>,
) -> TestResult<HomeHandoffProposalRequest> {
    Ok(HomeHandoffProposalRequest::new(
        Uuid::from_u128(proposal_id),
        Uuid::from_u128(handoff_id),
        fixture.preparation_id,
        predecessor.id(),
        predecessor.revision(),
        AgentAssignmentId::from_uuid(Uuid::from_u128(successor_id)),
        fixture.actor,
        AgentAssignmentTarget::new(
            recipient.id(),
            recipient.session_id().ok_or("recipient Session missing")?,
            recipient.principal(),
            recipient.revision(),
        ),
        artifact_id,
        expected_case_revision,
    )?)
}

fn proposal_clock(value: i64) -> Result<TimestampMillis, HomeHandoffProposalStoreError> {
    TimestampMillis::new(value).map_err(|_| HomeHandoffProposalStoreError::Clock)
}

fn take_request(
    fixture: &Fixture,
    proposal: &crate::HomeHandoffProposalRecord,
    acceptance_id: Uuid,
) -> TestResult<HomeHandoffTakeRequest> {
    take_request_for_recipient(
        fixture,
        proposal,
        acceptance_id,
        proposal.request().recipient(),
    )
}

fn take_request_for_recipient(
    fixture: &Fixture,
    proposal: &crate::HomeHandoffProposalRecord,
    acceptance_id: Uuid,
    recipient: AgentAssignmentTarget,
) -> TestResult<HomeHandoffTakeRequest> {
    let scope = HomeTransferSourceScope::new(
        fixture.workspace_id,
        fixture.store.workspace()?.revision(),
        fixture.backend,
        fixture.destination,
    )?;
    Ok(HomeHandoffTakeRequest::new(
        acceptance_id,
        proposal.request().handoff_id(),
        proposal.request().proposal_id(),
        proposal.case_revision(),
        proposal.request().request_digest(),
        scope,
        recipient,
    )?)
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one native test checks immutable replay, replacement, stale CAS, and no effects"
)]
fn immutable_replay_replacement_and_effect_facts_are_source_scoped() -> TestResult {
    let mut fixture = build_fixture("home-handoff-proposal-history", 0xB001, false)?;
    let assignment_before = fixture
        .store
        .get_agent_assignment(fixture.assignment.id())?
        .ok_or("predecessor Assignment missing before proposal")?;
    let effects_before = fixture.store.effect_fact_outbox(0, 64)?;
    let first_request = request(
        &fixture,
        0xB101,
        0xB100,
        0xB102,
        &fixture.recipient,
        None,
        None,
    )?;
    let first = fixture
        .store
        .propose_home_assignment_handoff(&first_request, || proposal_clock(60))?
        .record();
    assert_eq!(first.case_revision(), 1);
    assert_eq!(
        fixture.store.get_home_assignment_handoff_proposal(
            first_request.handoff_id(),
            first_request.proposal_id(),
        )?,
        Some(first)
    );
    let snapshot_transaction = fixture.store.connection.unchecked_transaction()?;
    let same_transaction_head =
        get_current_proposal_in_transaction(&snapshot_transaction, first_request.handoff_id())?
            .ok_or("same-transaction proposal head missing")?;
    assert_eq!(same_transaction_head.head(), first);
    snapshot_transaction.commit()?;

    let replay = fixture
        .store
        .propose_home_assignment_handoff(&first_request, || {
            Err(HomeHandoffProposalStoreError::Clock)
        })?;
    assert_eq!(replay, HomeHandoffProposalOutcome::Existing(first));

    let changed_body = request(
        &fixture,
        first_request.proposal_id().as_u128(),
        0xB100,
        0xB103,
        &fixture.alternate_recipient,
        None,
        None,
    )?;
    assert!(matches!(
        fixture.store.propose_home_assignment_handoff(&changed_body, || {
            Err(HomeHandoffProposalStoreError::Clock)
        }),
        Err(WorkspaceStoreError::HomeHandoffProposal(error))
            if matches!(error.as_ref(), HomeHandoffProposalStoreError::Conflict(_))
    ));

    let replacement_request = request(
        &fixture,
        0xB104,
        0xB100,
        0xB105,
        &fixture.recipient,
        None,
        Some(1),
    )?;
    let replacement = fixture
        .store
        .propose_home_assignment_handoff(&replacement_request, || proposal_clock(61))?
        .record();
    assert_eq!(replacement.case_revision(), 2);
    assert_eq!(
        fixture
            .store
            .get_current_home_assignment_handoff(first_request.handoff_id())?
            .ok_or("proposal case missing")?
            .head(),
        replacement
    );
    assert_eq!(
        fixture.store.get_home_assignment_handoff_proposal(
            first_request.handoff_id(),
            first_request.proposal_id(),
        )?,
        Some(first),
        "superseded proposal history must remain immutable",
    );

    let stale_head = request(
        &fixture,
        0xB106,
        0xB100,
        0xB107,
        &fixture.recipient,
        None,
        Some(1),
    )?;
    assert!(matches!(
        fixture.store.propose_home_assignment_handoff(&stale_head, || {
            Err(HomeHandoffProposalStoreError::Clock)
        }),
        Err(WorkspaceStoreError::HomeHandoffProposal(error))
            if matches!(error.as_ref(), HomeHandoffProposalStoreError::Conflict(_))
    ));

    assert_eq!(
        fixture
            .store
            .get_agent_assignment(fixture.assignment.id())?
            .ok_or("predecessor Assignment missing after proposal")?,
        assignment_before,
    );
    assert_eq!(fixture.store.effect_fact_outbox(0, 64)?, effects_before);
    let running_assignments: i64 = fixture.store.connection.query_row(
        "SELECT COUNT(*) FROM agent_assignments WHERE state=1",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        running_assignments, 0,
        "a proposal must not create Running work"
    );

    drop(fixture.store);
    std::fs::remove_dir_all(fixture.root)?;
    Ok(())
}

#[test]
fn proposal_rejects_predecessor_outside_prepared_session_and_assignment_scope() -> TestResult {
    let mut fixture = build_fixture_with_unbound_predecessor(
        "home-handoff-unbound-predecessor",
        0xB401,
        false,
        true,
        false,
    )?;
    let predecessor = fixture
        .unbound_predecessor
        .as_ref()
        .ok_or("uncaptured predecessor fixture was not created")?;
    let assignment_before = fixture
        .store
        .get_agent_assignment(predecessor.id())?
        .ok_or("uncaptured predecessor Assignment is missing")?;
    let effects_before = fixture.store.effect_fact_outbox(0, 64)?;
    let handoff_request = request_for_predecessor(
        &fixture,
        predecessor,
        0xB501,
        0xB500,
        0xB502,
        &fixture.recipient,
        None,
        None,
    )?;

    assert!(matches!(
        fixture
            .store
            .propose_home_assignment_handoff(&handoff_request, || proposal_clock(60)),
        Err(WorkspaceStoreError::HomeHandoffProposal(error))
            if matches!(
                error.as_ref(),
                HomeHandoffProposalStoreError::Conflict(
                    "Prepared inventory does not contain the predecessor Assignment"
                )
            )
    ));
    assert_eq!(
        fixture
            .store
            .get_agent_assignment(predecessor.id())?
            .ok_or("uncaptured predecessor Assignment disappeared")?,
        assignment_before,
    );
    assert_eq!(fixture.store.effect_fact_outbox(0, 64)?, effects_before);
    assert_eq!(
        fixture.store.get_home_assignment_handoff_proposal(
            handoff_request.handoff_id(),
            handoff_request.proposal_id(),
        )?,
        None,
        "a rejected source scope must not create immutable proposal history",
    );
    assert_eq!(
        fixture
            .store
            .get_current_home_assignment_handoff(handoff_request.handoff_id())?,
        None,
        "a rejected source scope must not create a proposal case/head",
    );

    drop(fixture.store);
    std::fs::remove_dir_all(fixture.root)?;
    Ok(())
}

#[test]
fn proposal_accepts_captured_session_alias_without_explicit_binding() -> TestResult {
    let mut fixture = build_fixture_with_unbound_predecessor(
        "home-handoff-captured-session-alias",
        0xB601,
        false,
        true,
        true,
    )?;
    let predecessor = fixture
        .unbound_predecessor
        .clone()
        .ok_or("captured alias predecessor fixture was not created")?;
    let assignment_before = fixture
        .store
        .get_agent_assignment(predecessor.id())?
        .ok_or("captured alias predecessor Assignment is missing")?;
    let effects_before = fixture.store.effect_fact_outbox(0, 64)?;
    let handoff_request = request_for_predecessor(
        &fixture,
        &predecessor,
        0xB701,
        0xB700,
        0xB702,
        &fixture.recipient,
        None,
        None,
    )?;

    let proposal = fixture
        .store
        .propose_home_assignment_handoff(&handoff_request, || proposal_clock(60))?
        .record();
    assert_eq!(proposal.source().assignment_id(), predecessor.id());
    assert_eq!(
        fixture.store.get_home_assignment_handoff_proposal(
            handoff_request.handoff_id(),
            handoff_request.proposal_id(),
        )?,
        Some(proposal)
    );
    assert_eq!(
        fixture
            .store
            .get_agent_assignment(predecessor.id())?
            .ok_or("captured alias predecessor Assignment disappeared")?,
        assignment_before,
    );
    assert_eq!(fixture.store.effect_fact_outbox(0, 64)?, effects_before);

    drop(fixture.store);
    std::fs::remove_dir_all(fixture.root)?;
    Ok(())
}

#[test]
fn changed_current_coordinator_can_author_a_new_proposal_version() -> TestResult {
    let mut fixture = build_fixture("home-handoff-coordinator-reproposal", 0xB201, false)?;
    let first_request = request(
        &fixture,
        0xB301,
        0xB300,
        0xB302,
        &fixture.recipient,
        None,
        None,
    )?;
    let first = fixture
        .store
        .propose_home_assignment_handoff(&first_request, || proposal_clock(60))?
        .record();

    let next_binding = fixture.store.transfer_activity_coordinator(
        forge_domain::TransferActivityCoordinator::new(
            fixture.actor,
            fixture.next_coordinator.id(),
            super::timestamp(65)?,
        ),
        super::timestamp(65)?,
    )?;
    let next_session = fixture
        .next_coordinator
        .session_id()
        .ok_or("next Coordinator Session missing")?;
    fixture.actor = ActivityCoordinatorActor::new(
        fixture.workspace_id,
        fixture.activity_id,
        fixture.next_coordinator.id(),
        next_binding.revision(),
        fixture.next_coordinator.principal(),
        next_session,
    );
    let second_request = request(
        &fixture,
        0xB303,
        0xB300,
        0xB304,
        &fixture.recipient,
        None,
        Some(1),
    )?;
    let second = fixture
        .store
        .propose_home_assignment_handoff(&second_request, || proposal_clock(70))?
        .record();
    assert_eq!(second.case_revision(), 2);
    assert_eq!(second.request().coordinator(), fixture.actor);
    assert_eq!(
        fixture.store.get_home_assignment_handoff_proposal(
            first_request.handoff_id(),
            first_request.proposal_id(),
        )?,
        Some(first)
    );
    assert_eq!(
        fixture
            .store
            .get_current_home_assignment_handoff(first_request.handoff_id())?
            .ok_or("proposal case missing")?
            .head(),
        second
    );

    drop(fixture.store);
    std::fs::remove_dir_all(fixture.root)?;
    Ok(())
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one native test checks fail-closed admission then Offered/Running distinction"
)]
fn stale_predecessor_invalid_recipient_and_unlinked_artifact_fail_closed() -> TestResult {
    let mut fixture = build_fixture("home-handoff-proposal-admission", 0xB401, true)?;
    let base = request(
        &fixture,
        0xB501,
        0xB500,
        0xB502,
        &fixture.recipient,
        None,
        None,
    )?;
    let stale = HomeHandoffProposalRequest::new(
        base.proposal_id(),
        base.handoff_id(),
        base.preparation_id(),
        base.predecessor_id(),
        forge_domain::AgentAssignmentRevision::new(base.predecessor_revision().get() + 1)?,
        base.successor_id(),
        base.coordinator(),
        base.recipient(),
        None,
        None,
    )?;
    assert!(matches!(
        fixture.store.propose_home_assignment_handoff(&stale, || {
            Err(HomeHandoffProposalStoreError::Clock)
        }),
        Err(WorkspaceStoreError::HomeHandoffProposal(error))
            if matches!(error.as_ref(), HomeHandoffProposalStoreError::Conflict(_))
    ));

    let recipient = &fixture.recipient;
    let wrong_session = AgentAssignmentTarget::new(
        recipient.id(),
        forge_domain::AgentSessionId::from_uuid(Uuid::from_u128(0xB5FF)),
        recipient.principal(),
        recipient.revision(),
    );
    let invalid_recipient = HomeHandoffProposalRequest::new(
        Uuid::from_u128(0xB503),
        Uuid::from_u128(0xB503 + 100_000),
        fixture.preparation_id,
        fixture.assignment.id(),
        fixture.assignment.revision(),
        AgentAssignmentId::from_uuid(Uuid::from_u128(0xB504)),
        fixture.actor,
        wrong_session,
        None,
        None,
    )?;
    assert!(matches!(
        fixture.store.propose_home_assignment_handoff(&invalid_recipient, || {
            Err(HomeHandoffProposalStoreError::Clock)
        }),
        Err(WorkspaceStoreError::HomeHandoffProposal(error))
            if matches!(error.as_ref(), HomeHandoffProposalStoreError::Conflict(_))
    ));

    let unlinked_artifact = request(
        &fixture,
        0xB505,
        0xB500,
        0xB506,
        &fixture.recipient,
        Some(HomeArtifactId::new(Uuid::from_u128(0xB507))?),
        None,
    )?;
    assert!(matches!(
        fixture.store.propose_home_assignment_handoff(&unlinked_artifact, || {
            Err(HomeHandoffProposalStoreError::Clock)
        }),
        Err(WorkspaceStoreError::HomeHandoffProposal(error))
            if matches!(error.as_ref(), HomeHandoffProposalStoreError::Conflict(_))
    ));
    let count: i64 = fixture.store.connection.query_row(
        "SELECT COUNT(*) FROM home_handoff_cases WHERE predecessor_assignment_id=?1",
        params![fixture.assignment.id().into_uuid().as_bytes()],
        |row| row.get(0),
    )?;
    assert_eq!(count, 0, "rejected proposals must not leave an open case");

    let valid_running_request = request(
        &fixture,
        0xB508,
        0xB500,
        0xB509,
        &fixture.recipient,
        None,
        None,
    )?;
    let running_proposal = fixture
        .store
        .propose_home_assignment_handoff(&valid_running_request, || proposal_clock(60))?
        .record();
    assert_eq!(
        running_proposal.source().state(),
        AgentAssignmentState::Running,
        "Source proposal admission supports exact Running predecessors",
    );
    assert_eq!(
        running_proposal.evidence(),
        HomeHandoffProposalEvidence::NoArtifactRequested,
        "no artifact request is not a no-prior-work proof",
    );

    let current_dag = fixture
        .store
        .get_current_dag(running_proposal.source().goal_id())?
        .ok_or("Running predecessor DAG missing")?;
    let active_node = current_dag
        .nodes()
        .iter()
        .find(|node| node.id() == running_proposal.source().node_id())
        .ok_or("Running predecessor node missing")?
        .clone();
    assert_eq!(
        active_node.lifecycle(),
        &forge_domain::DagNodeLifecycle::Active
    );
    let blocked_node = active_node.block(
        active_node.revision(),
        forge_domain::GoalPublicReason::new("dependency is temporarily unavailable".to_owned())?,
        super::timestamp(50)?,
    )?;
    let _persisted_blocked_node = fixture.store.update_dag_node(
        &blocked_node,
        active_node.revision(),
        super::timestamp(50)?,
    )?;
    let blocked_reproposal = request(
        &fixture,
        0xB50A,
        0xB500,
        0xB50B,
        &fixture.recipient,
        None,
        Some(1),
    )?;
    let blocked_proposal = fixture
        .store
        .propose_home_assignment_handoff(&blocked_reproposal, || proposal_clock(61))?
        .record();
    assert_eq!(blocked_proposal.case_revision(), 2);
    assert_eq!(
        blocked_proposal.source().state(),
        AgentAssignmentState::Running
    );

    drop(fixture.store);
    std::fs::remove_dir_all(fixture.root)?;
    Ok(())
}

#[test]
fn offered_predecessor_rejects_a_current_node_advanced_after_the_offer() -> TestResult {
    let mut fixture = build_fixture("home-handoff-stale-offered-node", 0xB551, false)?;
    let dag = fixture
        .store
        .get_current_dag(fixture.assignment.goal_id())?
        .ok_or("Offered predecessor DAG missing")?;
    let pending_node = dag
        .nodes()
        .iter()
        .find(|node| node.id() == fixture.assignment.node_id())
        .ok_or("Offered predecessor node missing")?;
    assert_eq!(
        pending_node.lifecycle(),
        &forge_domain::DagNodeLifecycle::Pending
    );
    let scope = crate::DagTransitionScope::new(
        fixture.workspace_id,
        fixture.activity_id,
        fixture.assignment.goal_id(),
        fixture.assignment.goal_revision(),
        fixture.assignment.dag_revision(),
    );
    let started = fixture.store.start_dag_node(crate::DagNodeTransition::new(
        scope,
        pending_node.id(),
        pending_node.revision(),
        super::timestamp(50)?,
    ))?;
    assert_eq!(started.revision().get(), pending_node.revision().get() + 1);
    assert_eq!(started.lifecycle(), &forge_domain::DagNodeLifecycle::Active);
    let assignment_before = fixture
        .store
        .get_agent_assignment(fixture.assignment.id())?
        .ok_or("Offered predecessor Assignment disappeared")?;
    let effects_before = fixture.store.effect_fact_outbox(0, 64)?;
    let request = request(
        &fixture,
        0xB561,
        0xB560,
        0xB562,
        &fixture.recipient,
        None,
        None,
    )?;
    assert!(matches!(
        fixture.store.propose_home_assignment_handoff(&request, || {
            Err(HomeHandoffProposalStoreError::Clock)
        }),
        Err(WorkspaceStoreError::HomeHandoffProposal(error))
            if matches!(
                error.as_ref(),
                HomeHandoffProposalStoreError::Conflict(
                    "Offered predecessor no longer matches the exact Pending DAG node"
                )
            )
    ));
    assert_eq!(
        fixture
            .store
            .get_agent_assignment(fixture.assignment.id())?
            .ok_or("Offered predecessor Assignment missing after rejection")?,
        assignment_before,
    );
    assert_eq!(fixture.store.effect_fact_outbox(0, 64)?, effects_before);
    drop(fixture.store);
    std::fs::remove_dir_all(fixture.root)?;
    Ok(())
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one native test covers concurrent head CAS and transactional rollback"
)]
fn concurrent_replacements_have_one_cas_winner_and_rollback_leaves_no_case() -> TestResult {
    let mut fixture = build_fixture("home-handoff-proposal-cas", 0xB601, false)?;
    let first = request(
        &fixture,
        0xB701,
        0xB700,
        0xB702,
        &fixture.recipient,
        None,
        None,
    )?;
    let _first_outcome = fixture
        .store
        .propose_home_assignment_handoff(&first, || proposal_clock(60))?;
    let left = request(
        &fixture,
        0xB703,
        0xB700,
        0xB704,
        &fixture.recipient,
        None,
        Some(1),
    )?;
    let right = request(
        &fixture,
        0xB705,
        0xB700,
        0xB706,
        &fixture.recipient,
        None,
        Some(1),
    )?;
    let existing = forge_workspace::WorkspaceStateLayout::inspect_existing(&fixture.root)?
        .ok_or("proposal Workspace state root disappeared")?;
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let spawn = |request: HomeHandoffProposalRequest,
                 barrier: std::sync::Arc<std::sync::Barrier>,
                 existing: forge_workspace::ExistingWorkspaceStateLayout| {
        thread::spawn(move || -> Result<_, String> {
            let mut store =
                WorkspaceStore::open_existing(&existing).map_err(|error| error.to_string())?;
            store
                .connection
                .busy_timeout(Duration::from_secs(2))
                .map_err(|error| error.to_string())?;
            barrier.wait();
            store
                .propose_home_assignment_handoff(&request, || proposal_clock(61))
                .map_err(|error| error.to_string())
        })
    };
    let left_thread = spawn(left, barrier.clone(), existing.clone());
    let right_thread = spawn(right, barrier, existing);
    let left_result = left_thread.join().map_err(|_| "left proposer panicked")?;
    let right_result = right_thread.join().map_err(|_| "right proposer panicked")?;
    let created = match &left_result {
        Ok(HomeHandoffProposalOutcome::Created(_)) => 1,
        _ => 0,
    } + match &right_result {
        Ok(HomeHandoffProposalOutcome::Created(_)) => 1,
        _ => 0,
    };
    let conflicted = match &left_result {
        Err(error) if error.contains("proposal case-head revision is stale") => 1,
        _ => 0,
    } + match &right_result {
        Err(error) if error.contains("proposal case-head revision is stale") => 1,
        _ => 0,
    };
    assert_eq!(created, 1);
    assert_eq!(conflicted, 1);

    let mut rollback = build_fixture("home-handoff-proposal-rollback", 0xB801, false)?;
    rollback.store.connection.execute_batch(
        "CREATE TRIGGER test_abort_home_handoff_proposal BEFORE INSERT ON home_handoff_proposals BEGIN SELECT RAISE(ABORT,'test rollback'); END",
    )?;
    let request = request(
        &rollback,
        0xB901,
        0xB900,
        0xB902,
        &rollback.recipient,
        None,
        None,
    )?;
    assert!(
        rollback
            .store
            .propose_home_assignment_handoff(&request, || proposal_clock(60))
            .is_err()
    );
    for table in [
        "home_handoff_cases",
        "home_handoff_proposals",
        "home_handoff_proposal_heads",
    ] {
        let count: i64 = rollback.store.connection.query_row(
            &format!("SELECT COUNT(*) FROM {table}"),
            [],
            |row| row.get(0),
        )?;
        assert_eq!(count, 0, "failed insert must roll back {table}");
    }

    drop(fixture.store);
    std::fs::remove_dir_all(fixture.root)?;
    drop(rollback.store);
    std::fs::remove_dir_all(rollback.root)?;
    Ok(())
}

#[test]
fn missing_applied_ledger_rejects_replacement_without_assignment_or_effect_mutation() -> TestResult
{
    let mut fixture = build_fixture("home-handoff-missing-application-ledger", 0xBA01, false)?;
    let first_request = request(
        &fixture,
        0xBB01,
        0xBB00,
        0xBB02,
        &fixture.recipient,
        None,
        None,
    )?;
    let first = fixture
        .store
        .propose_home_assignment_handoff(&first_request, || proposal_clock(60))?
        .record();
    let assignment_before = fixture
        .store
        .get_agent_assignment(fixture.assignment.id())?
        .ok_or("predecessor Assignment missing before ledger damage")?;
    let effects_before = fixture.store.effect_fact_outbox(0, 64)?;

    // This is deliberate persisted-state corruption: a replacement must fail
    // closed when the actual Applied-receipt owner cannot answer its predicate.
    fixture
        .store
        .connection
        .execute_batch("DROP TABLE home_handoff_acceptance_outcomes")?;
    let replacement = request(
        &fixture,
        0xBB03,
        0xBB00,
        0xBB04,
        &fixture.recipient,
        None,
        Some(1),
    )?;
    assert!(matches!(
        propose_in_transaction(
            &mut fixture.store.connection,
            &replacement,
            &DurableApplicationHooks,
            || proposal_clock(61),
        ),
        Err(HomeHandoffProposalStoreError::Sqlite(_))
    ));

    assert_eq!(
        fixture
            .store
            .get_agent_assignment(fixture.assignment.id())?
            .ok_or("predecessor Assignment missing after rejected replacement")?,
        assignment_before,
    );
    assert_eq!(fixture.store.effect_fact_outbox(0, 64)?, effects_before);
    let (revision, proposal_id): (i64, Vec<u8>) = fixture.store.connection.query_row(
        "SELECT case_revision,proposal_id FROM home_handoff_proposal_heads WHERE handoff_id=?1",
        params![first_request.handoff_id().as_bytes()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(revision, 1);
    assert_eq!(
        Uuid::from_slice(&proposal_id)?,
        first.request().proposal_id(),
        "a missing Applied ledger must not advance the proposal head",
    );

    drop(fixture.store);
    std::fs::remove_dir_all(fixture.root)?;
    Ok(())
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one native abort test verifies exact terminal replay across head replacement"
)]
fn aborted_acceptance_replays_after_head_replacement_and_changed_request_conflicts() -> TestResult {
    let mut fixture = build_fixture("home-handoff-abort-replay", 0xBC01, false)?;
    let first_request = request(
        &fixture,
        0xBD01,
        0xBD00,
        0xBD02,
        &fixture.recipient,
        None,
        None,
    )?;
    let first_proposal = fixture
        .store
        .propose_home_assignment_handoff(&first_request, || proposal_clock(60))?
        .record();
    let proposal_snapshot = first_proposal.to_snapshot_bytes()?;
    assert_eq!(
        crate::HomeHandoffProposalRecord::from_snapshot_bytes(&proposal_snapshot)?,
        first_proposal,
        "native proposal readback must have a portable canonical roundtrip",
    );
    assert_invalid_proposal_snapshot(&proposal_snapshot)?;
    let assignment_before = fixture
        .store
        .get_agent_assignment(fixture.assignment.id())?
        .ok_or("predecessor Assignment missing before abort")?;
    let effects_before = fixture.store.effect_fact_outbox(0, 64)?;

    let acceptance_id = Uuid::from_u128(0xBD10);
    let proposed_recipient = first_proposal.request().recipient();
    let recipient_at_take = AgentAssignmentTarget::new(
        proposed_recipient.agent_id(),
        proposed_recipient.session_id(),
        proposed_recipient.principal(),
        proposed_recipient.agent_revision().checked_next()?,
    );
    assert_ne!(
        proposed_recipient.agent_revision(),
        recipient_at_take.agent_revision(),
        "the abort request records the later take-time Agent revision",
    );
    assert!(proposed_recipient.has_same_identity(recipient_at_take));
    // Abort retains the exact historical target identity but does not require
    // current recipient eligibility at the later take-request revision.
    let first_take =
        take_request_for_recipient(&fixture, &first_proposal, acceptance_id, recipient_at_take)?;
    let proposal_revision_take = take_request(&fixture, &first_proposal, acceptance_id)?;
    assert_ne!(
        proposal_revision_take.request_digest(),
        first_take.request_digest(),
        "the exact take digest must bind the later expected Agent revision",
    );
    let abort_time = super::timestamp(70)?;
    let aborted = fixture.store.abort_unstarted_home_assignment_handoff(
        &first_take,
        fixture.issuer,
        fixture.backend,
        fixture.destination,
        || Ok(abort_time),
    )?;
    assert_eq!(
        aborted.outcome_kind(),
        crate::HomeHandoffAcceptanceOutcomeKind::Aborted
    );
    assert!(aborted.applied().is_none());
    let outcome_snapshot = aborted.to_snapshot_bytes()?;
    assert_eq!(
        crate::HomeHandoffAcceptanceOutcomeRecord::from_snapshot_bytes(&outcome_snapshot)?,
        aborted,
        "native Aborted readback must have a portable canonical roundtrip",
    );
    assert_invalid_acceptance_snapshot(&outcome_snapshot)?;

    let replacement_request = request(
        &fixture,
        0xBD03,
        0xBD00,
        0xBD04,
        &fixture.recipient,
        None,
        Some(1),
    )?;
    let replacement = fixture
        .store
        .propose_home_assignment_handoff(&replacement_request, || proposal_clock(71))?
        .record();
    assert_eq!(replacement.case_revision(), 2);

    let replay = fixture.store.abort_unstarted_home_assignment_handoff(
        &first_take,
        fixture.issuer,
        fixture.backend,
        fixture.destination,
        || {
            Err(crate::HomeHandoffApplicationStoreError::Sqlite(
                rusqlite::Error::InvalidQuery,
            ))
        },
    )?;
    assert_eq!(
        replay, aborted,
        "exact abort replay must retain its old proposal"
    );
    assert_eq!(
        fixture.store.get_home_assignment_handoff_acceptance(
            acceptance_id,
            fixture.issuer,
            fixture.backend,
            fixture.destination,
        )?,
        Some(aborted.clone())
    );

    let changed_take = take_request(&fixture, &replacement, acceptance_id)?;
    assert!(matches!(
        fixture.store.abort_unstarted_home_assignment_handoff(
            &changed_take,
            fixture.issuer,
            fixture.backend,
            fixture.destination,
            || Err(crate::HomeHandoffApplicationStoreError::Sqlite(
                rusqlite::Error::InvalidQuery,
            )),
        ),
        Err(WorkspaceStoreError::HomeHandoffApplication(error))
            if matches!(error.as_ref(), crate::HomeHandoffApplicationStoreError::Conflict(_))
    ));
    assert_eq!(
        fixture
            .store
            .get_current_home_assignment_handoff(first_request.handoff_id())?
            .ok_or("proposal case missing")?
            .head(),
        replacement,
        "an abort replay cannot change the current proposal head",
    );
    assert_eq!(
        fixture
            .store
            .get_agent_assignment(fixture.assignment.id())?
            .ok_or("predecessor Assignment missing after abort")?,
        assignment_before,
    );
    assert_eq!(fixture.store.effect_fact_outbox(0, 64)?, effects_before);

    drop(fixture.store);
    std::fs::remove_dir_all(fixture.root)?;
    Ok(())
}

fn assert_invalid_proposal_snapshot(bytes: &[u8]) -> TestResult {
    assert!(
        bytes.len() >= 9,
        "valid snapshot has a complete envelope header"
    );
    let request_length = snapshot_length_at(bytes, 5)?;
    let source_length_offset = 9 + request_length + 32 + 8;
    let source_length = snapshot_length_at(bytes, source_length_offset)?;
    let evidence_tag_offset = source_length_offset + 4 + source_length + 32;
    assert_invalid_snapshot(bytes, evidence_tag_offset, |snapshot| {
        crate::HomeHandoffProposalRecord::from_snapshot_bytes(snapshot).is_err()
    })
}

fn assert_invalid_acceptance_snapshot(bytes: &[u8]) -> TestResult {
    assert!(
        bytes.len() >= 9,
        "valid snapshot has a complete envelope header"
    );
    let request_length = snapshot_length_at(bytes, 5)?;
    let outcome_tag_offset = 9 + request_length + 32 + (5 * 16) + 8;
    assert_invalid_snapshot(bytes, outcome_tag_offset, |snapshot| {
        crate::HomeHandoffAcceptanceOutcomeRecord::from_snapshot_bytes(snapshot).is_err()
    })
}

fn assert_invalid_snapshot<F>(bytes: &[u8], unknown_tag_offset: usize, is_invalid: F) -> TestResult
where
    F: Fn(&[u8]) -> bool,
{
    let mut tampered = bytes.to_vec();
    let last = tampered
        .last_mut()
        .ok_or("valid snapshot is unexpectedly empty")?;
    *last ^= 1;
    assert!(is_invalid(&tampered), "tampering must be rejected");

    assert!(
        is_invalid(&bytes[..bytes.len() - 1]),
        "truncation must be rejected"
    );

    let mut wrong_version = bytes.to_vec();
    wrong_version[4] = u8::MAX;
    assert!(
        is_invalid(&wrong_version),
        "unknown versions must be rejected"
    );

    let mut bad_length = bytes.to_vec();
    bad_length[5..9].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(
        is_invalid(&bad_length),
        "oversized component lengths must be rejected before allocation"
    );

    let mut unknown_tag = bytes.to_vec();
    unknown_tag[unknown_tag_offset] = u8::MAX;
    assert!(is_invalid(&unknown_tag), "unknown tags must be rejected");

    let mut trailing = bytes.to_vec();
    trailing.push(0);
    assert!(is_invalid(&trailing), "trailing bytes must be rejected");

    assert!(
        is_invalid(&vec![0; 2_049]),
        "oversized envelopes must be rejected"
    );
    Ok(())
}

fn snapshot_length_at(bytes: &[u8], offset: usize) -> TestResult<usize> {
    let end = offset
        .checked_add(4)
        .ok_or("snapshot length offset overflow")?;
    let length = u32::from_be_bytes(
        bytes
            .get(offset..end)
            .ok_or("valid snapshot is missing a length")?
            .try_into()?,
    );
    Ok(usize::try_from(length)?)
}
