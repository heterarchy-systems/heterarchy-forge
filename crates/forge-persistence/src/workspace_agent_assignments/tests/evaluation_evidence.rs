//! Assignment CAS and evaluation receipts share one SQLite transaction.

use super::*;
use crate::{EvaluationAssignmentSubmission, EvaluationT1ClosureOutcome};
use forge_domain::{
    EvaluationAdmissionTiming, EvaluationClockReading, EvaluationCutId, EvaluationDigest,
    EvaluationManifestId, EvaluationManifestMember, EvaluationManifestProposal,
    EvaluationObligationId, EvaluationPlanBinding, EvaluationPlanId, EvaluationReviewCutId,
    EvaluationReviewOutcome, EvaluationReviewState, EvaluationRevision, EvaluationSourceIdentity,
    EvaluationT1CloseRequest, EvaluationT1Coverage, EvaluationWorkUnitId, ForgeBackendId,
};
use rusqlite::{Connection, params};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct EvaluationScenario {
    assignment: AssignmentFixture,
    backend_id: ForgeBackendId,
    claimed: [RegisteredAgentAssignment; 2],
    proposal: EvaluationManifestProposal,
    deadline: TimestampMillis,
}

impl EvaluationScenario {
    fn new(seed: u128) -> TestResult<Self> {
        let mut assignment = fixture()?;
        let delegation = install_delegation_seal(&mut assignment.store, seed, 8)?;
        let backend_id = ForgeBackendId::from_uuid(Uuid::from_u128(seed + 0x10));
        let offered_a = assignment.store.offer_agent_assignment(
            &offer_command(
                &assignment,
                seed + 2,
                target(&assignment.target_a),
                &assignment.nodes[0],
                10,
            ),
            admitted_at()?,
        )?;
        let offered_b = assignment.store.offer_agent_assignment(
            &offer_command(
                &assignment,
                seed + 3,
                target(&assignment.target_b),
                &assignment.nodes[1],
                10,
            ),
            admitted_at()?,
        )?;
        let proposal = proposal(
            &assignment,
            &delegation,
            backend_id,
            [&offered_a, &offered_b],
            seed + 4,
        )?;
        let seal_at = ts(20)?;
        let _ = assignment
            .store
            .seal_evaluation_manifest(backend_id, &proposal, || {
                EvaluationClockReading::Trusted(seal_at)
            })?;
        let claimed_a = assignment.store.claim_agent_assignment(
            &ClaimAgentAssignment::new(
                offered_a.id(),
                offered_a.target(),
                offered_a.revision(),
                ts(30)?,
            ),
            admitted_at()?,
        )?;
        let claimed_b = assignment.store.claim_agent_assignment(
            &ClaimAgentAssignment::new(
                offered_b.id(),
                offered_b.target(),
                offered_b.revision(),
                ts(31)?,
            ),
            admitted_at()?,
        )?;
        Ok(Self {
            assignment,
            backend_id,
            claimed: [claimed_a, claimed_b],
            proposal,
            deadline: ts(50)?,
        })
    }

    fn submit_command(&self, observed_at: i64) -> TestResult<SubmitAgentAssignment> {
        self.submit_command_for(0, observed_at)
    }

    fn submit_command_for(
        &self,
        member_index: usize,
        observed_at: i64,
    ) -> TestResult<SubmitAgentAssignment> {
        let claimed = self
            .claimed
            .get(member_index)
            .ok_or("evaluation member index out of bounds")?;
        let current_target = self
            .assignment
            .store
            .get_agent(claimed.target().agent_id())?
            .ok_or("assignment target missing")?;
        Ok(SubmitAgentAssignment::new(
            claimed.id(),
            target(&current_target),
            claimed.revision(),
            AgentAssignmentResult::new("bounded source report".to_owned(), Vec::new(), None)?,
            ts(observed_at)?,
        ))
    }

    fn review_command(
        &self,
        submitted: &RegisteredAgentAssignment,
        observed_at: i64,
    ) -> TestResult<ReviewAgentAssignment> {
        Ok(ReviewAgentAssignment::new(
            submitted.id(),
            self.assignment.coordinator,
            submitted.revision(),
            ts(observed_at)?,
        ))
    }

    fn source_sequence(&self) -> TestResult<i64> {
        let connection = Connection::open(self.assignment.layout.database_path())?;
        Ok(connection.query_row(
            "SELECT source_sequence FROM workspace_evaluation_source_state WHERE workspace_id = ?1",
            params![self.assignment.workspace_id.into_uuid().as_bytes()],
            |row| row.get(0),
        )?)
    }

    fn cleanup(self) -> TestResult {
        drop(self.assignment.store);
        fs::remove_dir_all(self.assignment.root)?;
        Ok(())
    }
}

fn proposal(
    assignment: &AssignmentFixture,
    delegation: &crate::AgentOperationsDelegation,
    backend_id: ForgeBackendId,
    offered: [&RegisteredAgentAssignment; 2],
    seed: u128,
) -> TestResult<EvaluationManifestProposal> {
    let source = evaluation_source(assignment, delegation, backend_id)?;
    let plan = EvaluationPlanBinding::new(
        EvaluationPlanId::new(Uuid::from_u128(seed))?,
        EvaluationRevision::new(1)?,
        EvaluationDigest::new([0xE2; 32])?,
    );
    let criteria = EvaluationDigest::new([0xE3; 32])?;
    let members = [
        EvaluationManifestMember::new(
            EvaluationWorkUnitId::new(Uuid::from_u128(seed + 1))?,
            EvaluationObligationId::new(Uuid::from_u128(seed + 2))?,
            offered[0].id(),
            offered[0].revision(),
            offered[0].target().agent_id(),
            offered[0].target().session_id(),
            criteria,
        )?,
        EvaluationManifestMember::new(
            EvaluationWorkUnitId::new(Uuid::from_u128(seed + 3))?,
            EvaluationObligationId::new(Uuid::from_u128(seed + 4))?,
            offered[1].id(),
            offered[1].revision(),
            offered[1].target().agent_id(),
            offered[1].target().session_id(),
            criteria,
        )?,
    ];
    Ok(EvaluationManifestProposal::new(
        EvaluationManifestId::new(Uuid::from_u128(seed + 9))?,
        EvaluationRevision::new(1)?,
        source,
        plan,
        ts(50)?,
        members.to_vec(),
    )?)
}

fn evaluation_source(
    assignment: &AssignmentFixture,
    delegation: &crate::AgentOperationsDelegation,
    backend_id: ForgeBackendId,
) -> TestResult<EvaluationSourceIdentity> {
    let delegation_revision =
        EvaluationRevision::new(i64::try_from(delegation.freeze().revision())?)?;
    Ok(EvaluationSourceIdentity::new(
        backend_id,
        assignment.workspace_id,
        assignment.activity_id,
        delegation.migration_id(),
        delegation.destination_id(),
        delegation_revision,
        EvaluationDigest::new(delegation.manifest_digest())?,
    )?)
}

fn one_member_proposal(
    assignment: &AssignmentFixture,
    delegation: &crate::AgentOperationsDelegation,
    backend_id: ForgeBackendId,
    member: EvaluationManifestMember,
    seed: u128,
) -> TestResult<EvaluationManifestProposal> {
    Ok(EvaluationManifestProposal::new(
        EvaluationManifestId::new(Uuid::from_u128(seed + 9))?,
        EvaluationRevision::new(1)?,
        evaluation_source(assignment, delegation, backend_id)?,
        EvaluationPlanBinding::new(
            EvaluationPlanId::new(Uuid::from_u128(seed))?,
            EvaluationRevision::new(1)?,
            EvaluationDigest::new([0xE4; 32])?,
        ),
        ts(5_000)?,
        vec![member],
    )?)
}

fn cumulative_proposal(
    assignment: &AssignmentFixture,
    delegation: &crate::AgentOperationsDelegation,
    backend_id: ForgeBackendId,
    members: Vec<EvaluationManifestMember>,
) -> TestResult<EvaluationManifestProposal> {
    Ok(EvaluationManifestProposal::new(
        EvaluationManifestId::new(Uuid::from_u128(0xED00))?,
        EvaluationRevision::new(1)?,
        evaluation_source(assignment, delegation, backend_id)?,
        EvaluationPlanBinding::new(
            EvaluationPlanId::new(Uuid::from_u128(0xED01))?,
            EvaluationRevision::new(2)?,
            EvaluationDigest::new([0xE5; 32])?,
        ),
        ts(5_000)?,
        members,
    )?)
}

fn historical_source_times(index: usize) -> TestResult<[TimestampMillis; 3]> {
    let step = i64::try_from(index)?;
    let start = 1_000 + step * 3;
    Ok([ts(start)?, ts(start + 1)?, ts(start + 2)?])
}

fn complete_bound_original(
    assignment: &mut AssignmentFixture,
    nodes: &[RegisteredDagNode],
    delegation: &crate::AgentOperationsDelegation,
    backend_id: ForgeBackendId,
    index: usize,
    criteria: EvaluationDigest,
) -> TestResult<EvaluationManifestMember> {
    let suffix = u128::try_from(index)?;
    let node = nodes.get(index).ok_or("historical DAG node missing")?;
    let command = historical_offer_command(assignment, node, 0xE600 + suffix)?;
    let offered = assignment
        .store
        .offer_agent_assignment(&command, admitted_at()?)?;
    let member = EvaluationManifestMember::new(
        EvaluationWorkUnitId::new(Uuid::from_u128(0xE700 + suffix))?,
        EvaluationObligationId::new(Uuid::from_u128(0xE800 + suffix))?,
        offered.id(),
        offered.revision(),
        offered.target().agent_id(),
        offered.target().session_id(),
        criteria,
    )?;
    let proposal = one_member_proposal(
        assignment,
        delegation,
        backend_id,
        member,
        0xF000 + suffix * 16,
    )?;
    let [sealed_at, submitted_at, reviewed_at] = historical_source_times(index)?;
    let registered = assignment
        .store
        .seal_evaluation_manifest(backend_id, &proposal, || {
            EvaluationClockReading::Trusted(sealed_at)
        })?;
    assert_eq!(registered.members().len(), 1);
    assert!(matches!(
        registered.members()[0].binding(),
        forge_domain::EvaluationOriginalBindingStatus::Bound(_)
    ));

    let claimed = assignment.store.claim_agent_assignment(
        &ClaimAgentAssignment::new(offered.id(), offered.target(), offered.revision(), ts(30)?),
        admitted_at()?,
    )?;
    let current_target = assignment
        .store
        .get_agent(assignment.target_a.id())?
        .ok_or("assignment target missing after claim")?;
    let submit = SubmitAgentAssignment::new(
        claimed.id(),
        target(&current_target),
        claimed.revision(),
        AgentAssignmentResult::new("bounded historical report".to_owned(), Vec::new(), None)?,
        ts(31)?,
    );
    let submitted = assignment.store.submit_agent_assignment_with_source_clock(
        &submit,
        admitted_at()?,
        backend_id,
        || EvaluationClockReading::Trusted(submitted_at),
    )?;
    assert!(submitted.receipt().is_some());

    let review = ReviewAgentAssignment::new(
        submitted.assignment().id(),
        assignment.coordinator,
        submitted.assignment().revision(),
        ts(32)?,
    );
    let reviewed = assignment.store.accept_agent_assignment_with_source_clock(
        &review,
        admitted_at()?,
        backend_id,
        || EvaluationClockReading::Trusted(reviewed_at),
    )?;
    assert_eq!(
        reviewed.assignment().state(),
        AgentAssignmentState::Accepted
    );
    assert!(reviewed.receipt().is_some());
    assert_eq!(
        assignment
            .store
            .get_agent_assignment(member.assignment_id())?
            .ok_or("accepted historical original missing")?
            .state(),
        AgentAssignmentState::Accepted
    );
    Ok(member)
}

fn historical_offer_command(
    assignment: &AssignmentFixture,
    node: &RegisteredDagNode,
    assignment_id: u128,
) -> TestResult<OfferAgentAssignment> {
    let current_target = assignment
        .store
        .get_agent(assignment.target_a.id())?
        .ok_or("assignment target missing before offer")?;
    let current_dag = assignment
        .store
        .get_current_dag(assignment.goal.id())?
        .ok_or("historical DAG missing before offer")?;
    if current_dag.revision().number() != node.dag_revision() {
        return Err("historical node is not in the current DAG revision".into());
    }
    Ok(OfferAgentAssignment::new(
        AgentAssignmentId::from_uuid(Uuid::from_u128(assignment_id)),
        assignment.coordinator,
        target(&current_target),
        assignment.goal.id(),
        assignment.goal.revision(),
        assignment.goal.timestamps().created_at(),
        node.dag_revision(),
        current_dag.head().revision(),
        node.id(),
        node.revision(),
        None,
        ts(10)?,
    ))
}

fn install_33_node_dag(assignment: &mut AssignmentFixture) -> TestResult<Vec<RegisteredDagNode>> {
    let current = assignment
        .store
        .get_current_dag(assignment.goal.id())?
        .ok_or("initial DAG missing")?;
    let parent_number = current.revision().number();
    let number = parent_number.checked_next()?;
    let mut nodes = current
        .nodes()
        .iter()
        .map(|node| node.carry_to_revision(number))
        .collect::<Vec<_>>();
    let mut definitions = nodes
        .iter()
        .map(|node| node.definition().clone())
        .collect::<Vec<_>>();
    for ordinal in 2_u16..33 {
        let suffix = u128::from(ordinal);
        let definition = DagNodeDefinition::new(
            DagNodeId::from_uuid(Uuid::from_u128(0xEB00 + suffix)),
            DagNodeOrdinal::new(ordinal)?,
            DagNodeTitle::new(format!("Historical task {ordinal}"))?,
            DagNodeObjective::new(format!("Complete historical task {ordinal}"))?,
            vec![DagAcceptanceCriterion::new(
                "The source result is reviewed".to_owned(),
            )?],
        )?;
        nodes.push(RegisteredDagNode::create(
            assignment.goal.id(),
            number,
            definition.clone(),
            ts(9)?,
        ));
        definitions.push(definition);
    }
    let revision = DagRevision::new(
        DagRevisionId::from_uuid(Uuid::from_u128(0xEBF0)),
        assignment.goal.id(),
        assignment.goal.revision(),
        number,
        Some(parent_number),
        definitions,
        Vec::new(),
        ts(9)?,
    )?;
    let stored = assignment.store.insert_dag_revision(
        &revision,
        &nodes,
        &[],
        Some(current.head().revision()),
    )?;
    assert_eq!(stored.revision().number(), number);
    assert_eq!(stored.nodes().len(), 33);
    Ok(nodes)
}

fn assert_completed_originals(
    store: &WorkspaceStore,
    members: &[EvaluationManifestMember],
) -> TestResult {
    for member in members {
        let assignment = store
            .get_agent_assignment(member.assignment_id())?
            .ok_or("historical original assignment missing")?;
        assert_eq!(assignment.state(), AgentAssignmentState::Accepted);
        assert!(assignment.revision().get() > member.assignment_revision().get());
    }
    Ok(())
}

fn install_assignment_update_failure(
    layout: &WorkspaceStateLayout,
    trigger_name: &'static str,
) -> TestResult {
    let connection = Connection::open(layout.database_path())?;
    connection.execute_batch(&format!(
        "CREATE TRIGGER {trigger_name} BEFORE UPDATE ON agent_assignments
         BEGIN SELECT RAISE(ABORT, 'evaluation assignment update failure'); END;"
    ))?;
    Ok(())
}

fn remove_assignment_update_failure(
    layout: &WorkspaceStateLayout,
    trigger_name: &'static str,
) -> TestResult {
    let connection = Connection::open(layout.database_path())?;
    connection.execute_batch(&format!("DROP TRIGGER {trigger_name}"))?;
    Ok(())
}

fn assert_legacy_submission_requires_source_clock(
    scenario: &mut EvaluationScenario,
    command: &SubmitAgentAssignment,
) -> TestResult {
    let assignment = scenario.claimed[0].id();
    let sequence_before = scenario.source_sequence()?;
    let legacy = scenario
        .assignment
        .store
        .submit_agent_assignment(command, admitted_at()?);
    assert!(matches!(
        legacy,
        Err(WorkspaceStoreError::AgentAssignment(
            AgentAssignmentStoreError::EvaluationEvidenceObservationRequired {
                workspace_id,
                assignment_id,
            }
        )) if workspace_id == scenario.assignment.workspace_id && assignment_id == assignment
    ));
    assert_eq!(scenario.source_sequence()?, sequence_before);
    assert_eq!(
        scenario
            .assignment
            .store
            .get_agent_assignment(assignment)?
            .ok_or("claimed assignment missing")?
            .state(),
        AgentAssignmentState::Running
    );
    Ok(())
}

fn assert_failed_submission_rolls_back(
    scenario: &mut EvaluationScenario,
    command: &SubmitAgentAssignment,
) -> TestResult {
    let assignment = scenario.claimed[0].id();
    let trigger = "fail_evaluation_submission_assignment_update";
    install_assignment_update_failure(&scenario.assignment.layout, trigger)?;
    let sequence_before = scenario.source_sequence()?;
    let submitted_revision = AgentAssignmentRevision::new(
        scenario.claimed[0]
            .revision()
            .get()
            .checked_add(1)
            .ok_or("assignment revision overflow")?,
    )?;
    let sample_count = std::cell::Cell::new(0_u8);
    let admitted_at = admitted_at()?;
    let source_time = scenario.deadline;
    let failed = scenario
        .assignment
        .store
        .submit_agent_assignment_with_source_clock(
            command,
            admitted_at,
            scenario.backend_id,
            || {
                sample_count.set(sample_count.get() + 1);
                EvaluationClockReading::Trusted(source_time)
            },
        );
    assert!(matches!(
        failed,
        Err(WorkspaceStoreError::AgentAssignment(
            AgentAssignmentStoreError::Sqlite(_)
        ))
    ));
    assert_eq!(sample_count.get(), 1);
    assert_eq!(scenario.source_sequence()?, sequence_before);
    assert_eq!(
        scenario
            .assignment
            .store
            .get_agent_assignment(assignment)?
            .ok_or("claimed assignment missing")?
            .state(),
        AgentAssignmentState::Running
    );
    assert!(scenario
        .assignment
        .store
        .get_evaluation_submission_receipt(
            scenario.backend_id,
            assignment,
            submitted_revision,
        )?
        .is_none());
    remove_assignment_update_failure(&scenario.assignment.layout, trigger)
}

fn assert_submission_has_t1_coverage(
    scenario: &mut EvaluationScenario,
    submission: &EvaluationAssignmentSubmission,
) -> TestResult {
    let receipt = submission
        .receipt()
        .ok_or("bound original submission receipt missing")?;
    assert_eq!(
        receipt.timing(),
        EvaluationAdmissionTiming::Trusted(scenario.deadline)
    );
    assert_eq!(submission.assignment().updated_at(), ts(31)?);

    let close_request = EvaluationT1CloseRequest::new(
        EvaluationCutId::new(Uuid::from_u128(0xE199))?,
        scenario.proposal.manifest_id(),
        scenario.proposal.revision(),
        scenario.proposal.digest(),
        scenario.deadline,
    );
    let closed_at = ts(51)?;
    let cut = match scenario.assignment.store.close_evaluation_t1(
        scenario.backend_id,
        &close_request,
        || EvaluationClockReading::Trusted(closed_at),
    )? {
        EvaluationT1ClosureOutcome::Closed(cut) => cut,
        EvaluationT1ClosureOutcome::NotClosed(timing) => {
            return Err(format!("trusted T1 closure did not close: {timing:?}").into());
        }
    };
    let member = cut
        .members()
        .iter()
        .find(|member| member.member().assignment_id() == scenario.claimed[0].id())
        .ok_or("T1 coverage member missing")?;
    assert!(matches!(
        member.coverage(),
        EvaluationT1Coverage::Eligible { admitted_at, .. } if admitted_at == scenario.deadline
    ));
    Ok(())
}

#[test]
fn submission_receipt_and_assignment_cas_roll_back_together() -> TestResult {
    let mut scenario = EvaluationScenario::new(0xE100)?;
    let command = scenario.submit_command(31)?;
    assert_legacy_submission_requires_source_clock(&mut scenario, &command)?;
    assert_failed_submission_rolls_back(&mut scenario, &command)?;
    let deadline = scenario.deadline;
    let submission = submit_boundary_case(&mut scenario, 0, 31, deadline)?;
    assert_submission_has_t1_coverage(&mut scenario, &submission)?;
    scenario.cleanup()
}

#[test]
fn review_receipt_and_assignment_cas_roll_back_together() -> TestResult {
    let mut scenario = EvaluationScenario::new(0xE200)?;
    let submit = scenario.submit_command(31)?;
    let submitted = submit_for_review(&mut scenario, &submit)?;
    let review = scenario.review_command(&submitted, 32)?;
    let reviewed_revision = review_next_revision(&submitted)?;
    assert_legacy_review_is_fenced(&mut scenario, &submitted, &review)?;
    assert_review_write_failure_rolls_back(&mut scenario, &submitted, &review, reviewed_revision)?;
    assert_unknown_review_commits(&mut scenario, &review)?;
    scenario.cleanup()
}

fn submit_for_review(
    scenario: &mut EvaluationScenario,
    command: &SubmitAgentAssignment,
) -> TestResult<RegisteredAgentAssignment> {
    let submission = scenario
        .assignment
        .store
        .submit_agent_assignment_with_source_clock(
            command,
            admitted_at()?,
            scenario.backend_id,
            || EvaluationClockReading::Unknown,
        )?;
    assert_eq!(
        submission
            .receipt()
            .ok_or("unknown source timing receipt missing")?
            .timing(),
        EvaluationAdmissionTiming::Unknown(forge_domain::EvaluationClockUncertainty::Unknown)
    );
    Ok(submission.assignment().clone())
}

fn review_next_revision(
    submitted: &RegisteredAgentAssignment,
) -> TestResult<AgentAssignmentRevision> {
    Ok(AgentAssignmentRevision::new(
        submitted
            .revision()
            .get()
            .checked_add(1)
            .ok_or("assignment revision overflow")?,
    )?)
}

fn assert_legacy_review_is_fenced(
    scenario: &mut EvaluationScenario,
    submitted: &RegisteredAgentAssignment,
    review: &ReviewAgentAssignment,
) -> TestResult {
    let sequence_before = scenario.source_sequence()?;
    let legacy = scenario
        .assignment
        .store
        .accept_agent_assignment(review, admitted_at()?);
    assert!(matches!(
        legacy,
        Err(WorkspaceStoreError::AgentAssignment(
            AgentAssignmentStoreError::EvaluationEvidenceObservationRequired {
                workspace_id,
                assignment_id,
            }
        )) if workspace_id == scenario.assignment.workspace_id
            && assignment_id == submitted.id()
    ));
    assert_eq!(scenario.source_sequence()?, sequence_before);
    assert_eq!(
        scenario
            .assignment
            .store
            .get_agent_assignment(submitted.id())?
            .ok_or("submitted assignment missing")?
            .state(),
        AgentAssignmentState::Submitted
    );
    Ok(())
}

fn assert_review_write_failure_rolls_back(
    scenario: &mut EvaluationScenario,
    submitted: &RegisteredAgentAssignment,
    review: &ReviewAgentAssignment,
    review_revision: AgentAssignmentRevision,
) -> TestResult {
    let trigger = "fail_evaluation_review_assignment_update";
    install_assignment_update_failure(&scenario.assignment.layout, trigger)?;
    let sequence_before = scenario.source_sequence()?;
    let review_at = ts(55)?;
    let failed = scenario
        .assignment
        .store
        .accept_agent_assignment_with_source_clock(
            review,
            admitted_at()?,
            scenario.backend_id,
            || EvaluationClockReading::Trusted(review_at),
        );
    assert!(matches!(
        failed,
        Err(WorkspaceStoreError::AgentAssignment(
            AgentAssignmentStoreError::Sqlite(_)
        ))
    ));
    assert_eq!(scenario.source_sequence()?, sequence_before);
    assert_eq!(
        scenario
            .assignment
            .store
            .get_agent_assignment(submitted.id())?
            .ok_or("submitted assignment missing")?
            .state(),
        AgentAssignmentState::Submitted
    );
    assert!(
        scenario
            .assignment
            .store
            .get_evaluation_review_receipt(
                scenario.backend_id,
                submitted.id(),
                submitted.revision(),
                review_revision,
            )?
            .is_none()
    );
    remove_assignment_update_failure(&scenario.assignment.layout, trigger)
}

fn assert_unknown_review_commits(
    scenario: &mut EvaluationScenario,
    review: &ReviewAgentAssignment,
) -> TestResult {
    let reviewed = scenario
        .assignment
        .store
        .accept_agent_assignment_with_source_clock(
            review,
            admitted_at()?,
            scenario.backend_id,
            || EvaluationClockReading::Unknown,
        )?;
    assert_eq!(
        reviewed.assignment().state(),
        AgentAssignmentState::Accepted
    );
    assert!(reviewed.receipt().is_some());
    Ok(())
}

#[test]
fn unregistered_assignment_write_keeps_evaluation_time_absent() -> TestResult {
    let mut fixture = fixture()?;
    let offered = fixture.store.offer_agent_assignment(
        &offer_command(
            &fixture,
            0xE2F1,
            target(&fixture.target_a),
            &fixture.nodes[0],
            10,
        ),
        admitted_at()?,
    )?;
    let claimed = fixture.store.claim_agent_assignment(
        &ClaimAgentAssignment::new(offered.id(), offered.target(), offered.revision(), ts(30)?),
        admitted_at()?,
    )?;
    let current_target = fixture
        .store
        .get_agent(fixture.target_a.id())?
        .ok_or("assignment target missing after claim")?;
    let submit = SubmitAgentAssignment::new(
        claimed.id(),
        target(&current_target),
        claimed.revision(),
        AgentAssignmentResult::new("ordinary source report".to_owned(), Vec::new(), None)?,
        ts(31)?,
    );
    let submitted = fixture
        .store
        .submit_agent_assignment(&submit, admitted_at()?)?;
    assert_eq!(submitted.state(), AgentAssignmentState::Submitted);

    let review = ReviewAgentAssignment::new(
        submitted.id(),
        fixture.coordinator,
        submitted.revision(),
        ts(32)?,
    );
    let reviewed = fixture
        .store
        .accept_agent_assignment(&review, admitted_at()?)?;
    assert_eq!(reviewed.state(), AgentAssignmentState::Accepted);

    let replay = fixture
        .store
        .submit_agent_assignment(&submit, admitted_at()?);
    assert!(matches!(
        replay,
        Err(WorkspaceStoreError::AgentAssignment(
            AgentAssignmentStoreError::Transition(
                forge_domain::AgentAssignmentTransitionError::InvalidState
            )
        ))
    ));
    assert_eq!(
        fixture
            .store
            .get_agent_assignment(submitted.id())?
            .ok_or("accepted unregistered assignment missing")?,
        reviewed
    );
    let connection = Connection::open(fixture.layout.database_path())?;
    let (state_rows, original_bindings, submission_receipts, review_receipts): (
        i64,
        i64,
        i64,
        i64,
    ) = connection.query_row(
        "SELECT
            (SELECT COUNT(*) FROM workspace_evaluation_source_state),
            (SELECT COUNT(*) FROM workspace_evaluation_original_bindings),
            (SELECT COUNT(*) FROM workspace_evaluation_submission_receipts),
            (SELECT COUNT(*) FROM workspace_evaluation_review_receipts)",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    assert_eq!(
        (
            state_rows,
            original_bindings,
            submission_receipts,
            review_receipts
        ),
        (0, 0, 0, 0)
    );
    drop(connection);
    fs::remove_dir_all(fixture.root)?;
    Ok(())
}

#[test]
fn cumulative_manifest_reuses_33_completed_original_assignments_via_workspace_store() -> TestResult
{
    let mut assignment = fixture()?;
    let nodes = install_33_node_dag(&mut assignment)?;
    let delegation = install_delegation_seal(&mut assignment.store, 0xE500, 8)?;
    let backend_id = ForgeBackendId::from_uuid(Uuid::from_u128(0xE520));
    let criteria = EvaluationDigest::new([0xE6; 32])?;
    let mut members = Vec::with_capacity(33);
    for index in 0..33 {
        members.push(complete_bound_original(
            &mut assignment,
            &nodes,
            &delegation,
            backend_id,
            index,
            criteria,
        )?);
    }
    assert_completed_originals(&assignment.store, &members)?;

    let proposal = cumulative_proposal(&assignment, &delegation, backend_id, members)?;
    let cumulative_at = ts(1_100)?;
    let cumulative = assignment
        .store
        .seal_evaluation_manifest(backend_id, &proposal, || {
            EvaluationClockReading::Trusted(cumulative_at)
        })?;
    assert_eq!(cumulative.members().len(), 33);
    assert!(cumulative.members().iter().all(|member| matches!(
        member.binding(),
        forge_domain::EvaluationOriginalBindingStatus::Bound(_)
    )));
    assert_completed_originals(&assignment.store, proposal.members())?;

    let root = assignment.root.clone();
    let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("Workspace missing")?;
    drop(assignment.store);
    let reopened = WorkspaceStore::open_existing(&existing)?;
    assert_eq!(
        reopened.get_evaluation_manifest(
            backend_id,
            proposal.manifest_id(),
            proposal.revision(),
        )?,
        Some(cumulative)
    );
    drop(reopened);
    fs::remove_dir_all(root)?;
    Ok(())
}

fn mismatched_t1_fences_do_not_sample_or_advance_source_state(
    scenario: &mut EvaluationScenario,
    cut_id: EvaluationCutId,
) -> TestResult {
    let sequence_before = scenario.source_sequence()?;
    let wrong_digest = EvaluationDigest::new([0xF1; 32])?;
    let wrong_deadline = ts(51)?;
    let wrong_manifest_id = EvaluationManifestId::new(Uuid::from_u128(0xE3F3))?;
    let cases = [
        (
            scenario.proposal.manifest_id(),
            scenario.proposal.digest(),
            wrong_deadline,
        ),
        (
            scenario.proposal.manifest_id(),
            wrong_digest,
            scenario.deadline,
        ),
        (
            wrong_manifest_id,
            scenario.proposal.digest(),
            scenario.deadline,
        ),
    ];
    let recovery_at = ts(52)?;
    for (manifest_id, digest, deadline) in cases {
        let request = EvaluationT1CloseRequest::new(
            cut_id,
            manifest_id,
            scenario.proposal.revision(),
            digest,
            deadline,
        );
        let sample_count = std::cell::Cell::new(0_u8);
        let rejected =
            scenario
                .assignment
                .store
                .close_evaluation_t1(scenario.backend_id, &request, || {
                    sample_count.set(sample_count.get() + 1);
                    EvaluationClockReading::Trusted(recovery_at)
                });
        assert!(matches!(
            rejected,
            Err(WorkspaceStoreError::EvaluationEvidence(_))
        ));
        assert_eq!(sample_count.get(), 0);
        assert_eq!(scenario.source_sequence()?, sequence_before);
        assert!(
            scenario
                .assignment
                .store
                .get_evaluation_t1_cut(scenario.backend_id, cut_id)?
                .is_none()
        );
    }
    Ok(())
}

fn submit_boundary_case(
    scenario: &mut EvaluationScenario,
    member_index: usize,
    observed_at: i64,
    source_at: TimestampMillis,
) -> TestResult<EvaluationAssignmentSubmission> {
    let command = scenario.submit_command_for(member_index, observed_at)?;
    Ok(scenario
        .assignment
        .store
        .submit_agent_assignment_with_source_clock(
            &command,
            admitted_at()?,
            scenario.backend_id,
            || EvaluationClockReading::Trusted(source_at),
        )?)
}

fn close_exact_deadline_does_not_produce_a_cut(
    scenario: &mut EvaluationScenario,
    request: &EvaluationT1CloseRequest,
) -> TestResult {
    let sequence_before = scenario.source_sequence()?;
    let sample_count = std::cell::Cell::new(0_u8);
    let outcome =
        scenario
            .assignment
            .store
            .close_evaluation_t1(scenario.backend_id, request, || {
                sample_count.set(sample_count.get() + 1);
                EvaluationClockReading::Trusted(scenario.deadline)
            })?;
    assert_eq!(
        outcome,
        EvaluationT1ClosureOutcome::NotClosed(EvaluationAdmissionTiming::Trusted(
            scenario.deadline
        ))
    );
    assert_eq!(sample_count.get(), 1);
    assert!(scenario.source_sequence()? > sequence_before);
    assert!(
        scenario
            .assignment
            .store
            .get_evaluation_t1_cut(scenario.backend_id, request.cut_id())?
            .is_none()
    );
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "One source-cut regression covers frozen deadlines, delayed admission, review, and restart readback."
)]
#[test]
fn frozen_t1_and_review_cuts_preserve_exact_source_versions() -> TestResult {
    let mut scenario = EvaluationScenario::new(0xE300)?;
    let cut_id = EvaluationCutId::new(Uuid::from_u128(0xE3F0))?;
    mismatched_t1_fences_do_not_sample_or_advance_source_state(&mut scenario, cut_id)?;

    let close_request = EvaluationT1CloseRequest::new(
        cut_id,
        scenario.proposal.manifest_id(),
        scenario.proposal.revision(),
        scenario.proposal.digest(),
        scenario.deadline,
    );
    let late_at = ts(51)?;
    let cases = [
        (0_usize, 40_i64, scenario.deadline, true),
        (1_usize, 41_i64, late_at, false),
    ];
    let mut submissions = Vec::with_capacity(cases.len());
    for (member_index, observed_at, source_at, timely) in cases {
        if !timely {
            close_exact_deadline_does_not_produce_a_cut(&mut scenario, &close_request)?;
        }
        assert_eq!(source_at <= scenario.deadline, timely);
        let submission = submit_boundary_case(&mut scenario, member_index, observed_at, source_at)?;
        let receipt = submission
            .receipt()
            .ok_or("original submission receipt missing")?;
        assert_eq!(
            receipt.timing(),
            EvaluationAdmissionTiming::Trusted(source_at)
        );
        assert_eq!(submission.assignment().updated_at(), ts(observed_at)?);
        submissions.push(submission);
    }
    let timely = submissions.remove(0);
    let late = submissions.remove(0);
    let timely_assignment = timely.assignment().clone();
    let timely_receipt = timely
        .receipt()
        .copied()
        .ok_or("inclusive-T1 submission receipt missing")?;
    let late_assignment = late.assignment().clone();
    let _late_receipt = late
        .receipt()
        .ok_or("late original submission receipt missing")?;

    let closed_at = ts(52)?;
    let t1_cut = match scenario.assignment.store.close_evaluation_t1(
        scenario.backend_id,
        &close_request,
        || EvaluationClockReading::Trusted(closed_at),
    )? {
        EvaluationT1ClosureOutcome::Closed(cut) => cut,
        EvaluationT1ClosureOutcome::NotClosed(timing) => {
            return Err(format!("delayed T1 closure did not close: {timing:?}").into());
        }
    };
    let timely_member = t1_cut
        .members()
        .iter()
        .find(|member| member.member().assignment_id() == timely_assignment.id())
        .ok_or("timely T1 member missing")?;
    assert!(matches!(
        timely_member.coverage(),
        EvaluationT1Coverage::Eligible { admitted_at, .. } if admitted_at == scenario.deadline
    ));
    let late_member = t1_cut
        .members()
        .iter()
        .find(|member| member.member().assignment_id() == late_assignment.id())
        .ok_or("late T1 member missing")?;
    assert_eq!(
        late_member.coverage(),
        EvaluationT1Coverage::NoEligibleSubmission
    );

    let pending_cut_id = EvaluationReviewCutId::new(Uuid::from_u128(0xE3F1))?;
    let pending_at = ts(53)?;
    let pending_cut = scenario.assignment.store.create_evaluation_review_cut(
        scenario.backend_id,
        pending_cut_id,
        cut_id,
        || EvaluationClockReading::Trusted(pending_at),
    )?;
    let pending_member = pending_cut
        .members()
        .iter()
        .find(|member| member.member().assignment_id() == timely_assignment.id())
        .ok_or("timely review member missing")?;
    assert!(matches!(
        pending_member.review(),
        EvaluationReviewState::Pending { submitted_revision, .. }
            if submitted_revision == timely_assignment.revision()
    ));

    let review_command = scenario.review_command(&timely_assignment, 42)?;
    let reviewed_at = ts(54)?;
    let reviewed = scenario
        .assignment
        .store
        .accept_agent_assignment_with_source_clock(
            &review_command,
            admitted_at()?,
            scenario.backend_id,
            || EvaluationClockReading::Trusted(reviewed_at),
        )?;
    let review_receipt = reviewed
        .receipt()
        .copied()
        .ok_or("source review receipt missing")?;
    assert_eq!(review_receipt.outcome(), EvaluationReviewOutcome::Accepted);
    assert_eq!(
        review_receipt.submitted_revision(),
        timely_assignment.revision()
    );
    assert_eq!(
        review_receipt.review_revision(),
        reviewed.assignment().revision()
    );
    assert_eq!(
        review_receipt.author_agent_id(),
        scenario.assignment.target_a.id()
    );
    assert_eq!(
        review_receipt.author_session_id(),
        scenario
            .assignment
            .target_a
            .session_id()
            .ok_or("author session missing")?
    );
    assert_eq!(
        review_receipt.reviewer_agent_id(),
        scenario.assignment.coordinator.agent_id()
    );
    assert_eq!(
        review_receipt.reviewer_session_id(),
        scenario.assignment.coordinator.session_id()
    );
    assert_eq!(
        review_receipt.result_digest(),
        timely_receipt.result_digest()
    );

    let reviewed_cut_id = EvaluationReviewCutId::new(Uuid::from_u128(0xE3F2))?;
    let reviewed_at = ts(55)?;
    let reviewed_cut = scenario.assignment.store.create_evaluation_review_cut(
        scenario.backend_id,
        reviewed_cut_id,
        cut_id,
        || EvaluationClockReading::Trusted(reviewed_at),
    )?;
    let reviewed_member = reviewed_cut
        .members()
        .iter()
        .find(|member| member.member().assignment_id() == timely_assignment.id())
        .ok_or("timely reviewed-cut member missing")?;
    assert!(matches!(
        reviewed_member.review(),
        EvaluationReviewState::Reviewed(receipt) if receipt == review_receipt
    ));

    let sequence_before_stale_submit = scenario.source_sequence()?;
    let stale_submit_clock_calls = std::cell::Cell::new(0_u8);
    let stale_submit = scenario.submit_command_for(0, 40)?;
    assert!(matches!(
        scenario
            .assignment
            .store
            .submit_agent_assignment_with_source_clock(
                &stale_submit,
                admitted_at()?,
                scenario.backend_id,
                || {
                    stale_submit_clock_calls.set(stale_submit_clock_calls.get() + 1);
                    EvaluationClockReading::Unknown
                },
            ),
        Err(WorkspaceStoreError::AgentAssignment(
            AgentAssignmentStoreError::Transition(
                forge_domain::AgentAssignmentTransitionError::InvalidState
            )
        ))
    ));
    assert_eq!(stale_submit_clock_calls.get(), 0);
    assert_eq!(scenario.source_sequence()?, sequence_before_stale_submit);

    let sequence_before_readback = scenario.source_sequence()?;
    assert_eq!(
        scenario
            .assignment
            .store
            .get_evaluation_submission_receipt(
                scenario.backend_id,
                timely_assignment.id(),
                timely_assignment.revision(),
            )?,
        Some(timely_receipt)
    );
    assert_eq!(scenario.source_sequence()?, sequence_before_readback);

    let root = scenario.assignment.root.clone();
    let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("Workspace missing")?;
    drop(scenario.assignment.store);
    let reopened = WorkspaceStore::open_existing(&existing)?;
    assert_eq!(
        reopened.get_evaluation_submission_receipt(
            scenario.backend_id,
            timely_assignment.id(),
            timely_assignment.revision(),
        )?,
        Some(timely_receipt)
    );
    assert_eq!(
        reopened.get_evaluation_review_receipt(
            scenario.backend_id,
            timely_assignment.id(),
            timely_assignment.revision(),
            reviewed.assignment().revision(),
        )?,
        Some(review_receipt)
    );
    assert_eq!(
        reopened.get_evaluation_t1_cut(scenario.backend_id, cut_id)?,
        Some(t1_cut)
    );
    assert_eq!(
        reopened.get_evaluation_review_cut(scenario.backend_id, reviewed_cut_id)?,
        Some(reviewed_cut)
    );
    drop(reopened);
    fs::remove_dir_all(root)?;
    Ok(())
}
