use super::*;
use crate::{
    DagAcceptanceCriterion, DagNodeDefinition, DagNodeLifecycle, DagNodeObjective, DagNodeOrdinal,
    DagNodeTitle, DagRevision, DagRevisionId, ForgeBackendId, GoalPublicReason, RegisteredDagNode,
    WorkCutBinding, WorkCutNodeScope, WorkCutParty, WorkCutRequest, WorkCutScope, WorkCutSession,
    WorkCutSide, WorkspaceRevision,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Fixture {
    source: RegisteredAgentAssignment,
    coordinator: ActivityCoordinatorActor,
    source_target: AgentAssignmentTarget,
    recipient: AgentAssignmentTarget,
    scope: WorkCutNodeScope,
    dag: DagRevision,
    node: RegisteredDagNode,
}

impl Fixture {
    fn new(running: bool) -> TestResult<Self> {
        let (mut offered, coordinator, source_target) = scope()?;
        // A later Goal edit does not recreate the existing DAG generation.
        offered.goal_revision = GoalRevision::new(2)?;
        let source = if running {
            offered.claim(source_target, offered.revision(), TimestampMillis::new(3)?)?
        } else {
            offered
        };
        let recipient = AgentAssignmentTarget::new(
            coordinator.agent_id(),
            coordinator.session_id(),
            coordinator.principal(),
            AgentInstanceRevision::INITIAL,
        );
        let scope = WorkCutNodeScope::new(
            source.activity_id(),
            source.goal_id(),
            source.goal_created_at(),
            GoalRevision::INITIAL,
            source.dag_revision(),
            source.node_id(),
        )?;
        let definition = DagNodeDefinition::new(
            source.node_id(),
            DagNodeOrdinal::new(0)?,
            DagNodeTitle::new("Task".to_owned())?,
            DagNodeObjective::new("Preserve ongoing work".to_owned())?,
            vec![DagAcceptanceCriterion::new("Verify the result".to_owned())?],
        )?;
        let node = RegisteredDagNode::from_parts(
            source.goal_id(),
            source.dag_revision(),
            definition,
            if running {
                DagNodeLifecycle::Active
            } else {
                DagNodeLifecycle::Pending
            },
            TimestampMillis::new(1)?,
            TimestampMillis::new(if running { 3 } else { 1 })?,
            DagNodeRevision::new(if running { 2 } else { 1 })?,
        )?;
        let dag = DagRevision::new(
            DagRevisionId::from_uuid(Uuid::from_u128(200)),
            source.goal_id(),
            GoalRevision::INITIAL,
            source.dag_revision(),
            None,
            vec![node.definition().clone()],
            Vec::new(),
            TimestampMillis::new(1)?,
        )?;
        Ok(Self {
            source,
            coordinator,
            source_target,
            recipient,
            scope,
            dag,
            node,
        })
    }

    fn cut(&self, recipient_activity: ActivityId) -> TestResult<WorkCutRequest> {
        self.cut_with_scope(
            recipient_activity,
            WorkCutScope::Team {
                team_id: Uuid::from_u128(108),
                nodes: vec![self.scope],
            },
        )
    }

    fn cut_with_scope(
        &self,
        recipient_activity: ActivityId,
        cut_scope: WorkCutScope,
    ) -> TestResult<WorkCutRequest> {
        Ok(WorkCutRequest::new(
            Uuid::from_u128(100),
            Uuid::from_u128(101),
            Uuid::from_u128(102),
            ForgeBackendId::from_uuid(Uuid::from_u128(103)),
            self.source.workspace_id(),
            WorkspaceRevision::INITIAL,
            1,
            [1; 32],
            [
                WorkCutParty::new(Uuid::from_u128(104), Uuid::from_u128(105))?,
                WorkCutParty::new(Uuid::from_u128(106), Uuid::from_u128(107))?,
            ],
            vec![
                WorkCutSession::new(WorkCutSide::Incumbent, self.source_target.session_id())?,
                WorkCutSession::new(WorkCutSide::Elected, self.recipient.session_id())?,
            ],
            vec![
                WorkCutBinding::new(
                    WorkCutSide::Incumbent,
                    self.source.activity_id(),
                    self.source_target.agent_id(),
                    self.source_target.session_id(),
                    self.source_target.principal(),
                )?,
                WorkCutBinding::new(
                    WorkCutSide::Elected,
                    recipient_activity,
                    self.recipient.agent_id(),
                    self.recipient.session_id(),
                    self.recipient.principal(),
                )?,
            ],
            cut_scope,
        )?)
    }

    fn plan(&self) -> TestResult<AgentAssignmentContinuationPlan> {
        Ok(AgentAssignmentContinuationPlan::new(
            Uuid::from_u128(109),
            AgentAssignmentId::from_uuid(Uuid::from_u128(110)),
            &self.cut(self.source.activity_id())?,
            [9; 32],
            &self.source,
            self.source.revision(),
            self.scope,
            &self.dag,
            &self.node,
            self.recipient,
            TimestampMillis::new(10)?,
        )?)
    }
}

#[test]
fn running_continuation_keeps_source_history_and_does_not_restart_node() -> TestResult {
    let fixture = Fixture::new(true)?;
    let source_before = fixture.source.clone();
    let node_before = fixture.node.clone();
    let plan = fixture.plan()?;
    assert_eq!(plan.source_assignment(), &source_before);
    assert_eq!(plan.retired_assignment().id(), source_before.id());
    assert_eq!(plan.retired_assignment().target(), source_before.target());
    assert_eq!(
        plan.retired_assignment().state(),
        AgentAssignmentState::Interrupted
    );
    assert!(plan.retired_assignment().cancellation_requested());
    assert_eq!(plan.successor_state(), AgentAssignmentState::Running);
    assert_eq!(plan.node_revision(), node_before.revision());
    assert_eq!(plan.credit_budget(), source_before.credit_budget());
    assert_eq!(plan.recipient(), fixture.recipient);
    assert_ne!(plan.successor_id(), source_before.id());
    assert_eq!(fixture.source, source_before);
    assert_eq!(fixture.node, node_before);
    assert!(
        plan.retired_assignment()
            .submit(
                fixture.source_target,
                plan.retired_assignment().revision(),
                AgentAssignmentResult::new("stale result".to_owned(), Vec::new(), None)?,
                TimestampMillis::new(11)?,
            )
            .is_err()
    );
    // Receiving the work as Coordinator is representable, but ordinary
    // self-offer authority remains unchanged; a draft cannot grant that power.
    assert!(matches!(
        RegisteredAgentAssignment::offered(
            plan.successor_id(),
            source_before.workspace_id(),
            source_before.activity_id(),
            source_before.goal_id(),
            source_before.goal_created_at(),
            source_before.goal_revision(),
            source_before.dag_revision(),
            source_before.dag_head_revision(),
            source_before.node_id(),
            source_before.node_revision(),
            source_before.coordinator(),
            fixture.recipient,
            source_before.credit_budget(),
            TimestampMillis::new(10)?,
        ),
        Err(AgentAssignmentTransitionError::CoordinatorTargetSameAgent)
    ));
    Ok(())
}

#[test]
fn offered_and_blocked_continuations_preserve_their_lifecycle() -> TestResult {
    for running in [false, true] {
        let mut fixture = Fixture::new(running)?;
        let initial = fixture.plan()?;
        assert_eq!(initial.successor_state(), fixture.source.state());
        fixture.node = RegisteredDagNode::from_parts(
            fixture.node.goal_id(),
            fixture.node.dag_revision(),
            fixture.node.definition().clone(),
            DagNodeLifecycle::Blocked(GoalPublicReason::new("waiting for dependency".to_owned())?),
            fixture.node.created_at(),
            TimestampMillis::new(4)?,
            DagNodeRevision::new(3)?,
        )?;
        let blocked = fixture.plan()?;
        assert_eq!(blocked.successor_state(), fixture.source.state());
        assert_eq!(blocked.node_revision(), fixture.node.revision());
        assert!(matches!(
            fixture.node.lifecycle(),
            DagNodeLifecycle::Blocked(_)
        ));
    }
    Ok(())
}

#[test]
fn continuation_rejects_stale_or_unrelated_work_and_preserves_submitted_result() -> TestResult {
    let fixture = Fixture::new(true)?;
    let cut = fixture.cut(fixture.source.activity_id())?;
    let original = fixture.source.clone();
    let build = |source: &RegisteredAgentAssignment,
                 revision,
                 scope,
                 node: &RegisteredDagNode,
                 recipient,
                 at| {
        AgentAssignmentContinuationPlan::new(
            Uuid::from_u128(109),
            AgentAssignmentId::from_uuid(Uuid::from_u128(110)),
            &cut,
            [9; 32],
            source,
            revision,
            scope,
            &fixture.dag,
            node,
            recipient,
            at,
        )
    };
    assert!(
        build(
            &original,
            AgentAssignmentRevision::INITIAL,
            fixture.scope,
            &fixture.node,
            fixture.recipient,
            TimestampMillis::new(10)?
        )
        .is_err()
    );
    assert!(
        build(
            &original,
            original.revision(),
            fixture.scope,
            &fixture.node,
            fixture.source_target,
            TimestampMillis::new(10)?
        )
        .is_err()
    );
    assert!(
        build(
            &original,
            original.revision(),
            fixture.scope,
            &fixture.node,
            fixture.recipient,
            TimestampMillis::new(2)?
        )
        .is_err()
    );
    let wrong_scope = WorkCutNodeScope::new(
        original.activity_id(),
        original.goal_id(),
        TimestampMillis::new(99)?,
        GoalRevision::INITIAL,
        original.dag_revision(),
        original.node_id(),
    )?;
    assert!(
        build(
            &original,
            original.revision(),
            wrong_scope,
            &fixture.node,
            fixture.recipient,
            TimestampMillis::new(10)?
        )
        .is_err()
    );
    let foreign = fixture.cut(ActivityId::from_uuid(Uuid::from_u128(999)))?;
    assert!(
        AgentAssignmentContinuationPlan::new(
            Uuid::from_u128(109),
            AgentAssignmentId::from_uuid(Uuid::from_u128(110)),
            &foreign,
            [9; 32],
            &original,
            original.revision(),
            fixture.scope,
            &fixture.dag,
            &fixture.node,
            fixture.recipient,
            TimestampMillis::new(10)?
        )
        .is_err()
    );
    assert_cancel_and_submission_preserved(fixture, &original)
}

fn assert_cancel_and_submission_preserved(
    mut fixture: Fixture,
    original: &RegisteredAgentAssignment,
) -> TestResult {
    fixture.source = original.request_cancel(
        fixture.coordinator,
        original.revision(),
        TimestampMillis::new(4)?,
    )?;
    assert!(fixture.plan().is_err());
    fixture.source = original.submit(
        fixture.source_target,
        original.revision(),
        AgentAssignmentResult::new("original author's result".to_owned(), Vec::new(), None)?,
        TimestampMillis::new(4)?,
    )?;
    let submitted = fixture.source.clone();
    assert!(fixture.plan().is_err());
    assert_eq!(fixture.source, submitted);
    assert_eq!(fixture.source.target(), fixture.source_target);
    Ok(())
}

#[test]
fn continuation_checks_dag_base_independently_of_current_goal_revision() -> TestResult {
    let fixture = Fixture::new(true)?;
    assert_eq!(fixture.source.goal_revision(), GoalRevision::new(2)?);
    assert_eq!(fixture.dag.base_goal_revision(), GoalRevision::INITIAL);
    let _ = fixture.plan()?;
    let cut = fixture.cut_with_scope(fixture.source.activity_id(), WorkCutScope::Workspace)?;
    let wrong_base = WorkCutNodeScope::new(
        fixture.scope.activity_id(),
        fixture.scope.goal_id(),
        fixture.scope.goal_created_at(),
        fixture.source.goal_revision(),
        fixture.scope.dag_revision(),
        fixture.scope.node_id(),
    )?;
    assert!(
        AgentAssignmentContinuationPlan::new(
            Uuid::from_u128(109),
            AgentAssignmentId::from_uuid(Uuid::from_u128(110)),
            &cut,
            [9; 32],
            &fixture.source,
            fixture.source.revision(),
            wrong_base,
            &fixture.dag,
            &fixture.node,
            fixture.recipient,
            TimestampMillis::new(10)?,
        )
        .is_err()
    );
    Ok(())
}
