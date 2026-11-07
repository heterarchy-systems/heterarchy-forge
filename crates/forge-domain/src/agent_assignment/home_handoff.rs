//! Pure assignment after-images for an explicitly accepted Home handoff.
//!
//! These values do not establish Coordinator authority, Node readiness or a
//! Node transition, closure, retained-artifact proof, or a durable commit.
//! Source must validate and apply those facts separately.

use crate::{ActivityCoordinatorActor, DagNodeRevision, TimestampMillis};

use super::{
    AgentAssignmentCoordinator, AgentAssignmentHomeHandoffOrigin, AgentAssignmentId,
    AgentAssignmentOrigin, AgentAssignmentRevision, AgentAssignmentState, AgentAssignmentTarget,
    AgentAssignmentTransitionError, RegisteredAgentAssignment,
};

/// The explicit recipient acceptance and Source-sampled transition facts.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AgentAssignmentHomeHandoffAcceptance {
    origin: AgentAssignmentHomeHandoffOrigin,
    successor_id: AgentAssignmentId,
    recipient: AgentAssignmentTarget,
    coordinator: ActivityCoordinatorActor,
    node_revision: DagNodeRevision,
    effective_at: TimestampMillis,
}

impl AgentAssignmentHomeHandoffAcceptance {
    pub const fn new(
        origin: AgentAssignmentHomeHandoffOrigin,
        successor_id: AgentAssignmentId,
        recipient: AgentAssignmentTarget,
        coordinator: ActivityCoordinatorActor,
        node_revision: DagNodeRevision,
        effective_at: TimestampMillis,
    ) -> Self {
        Self {
            origin,
            successor_id,
            recipient,
            coordinator,
            node_revision,
            effective_at,
        }
    }

    pub const fn origin(self) -> AgentAssignmentHomeHandoffOrigin {
        self.origin
    }

    pub const fn successor_id(self) -> AgentAssignmentId {
        self.successor_id
    }

    pub const fn recipient(self) -> AgentAssignmentTarget {
        self.recipient
    }

    pub const fn coordinator(self) -> ActivityCoordinatorActor {
        self.coordinator
    }

    pub const fn node_revision(self) -> DagNodeRevision {
        self.node_revision
    }

    pub const fn effective_at(self) -> TimestampMillis {
        self.effective_at
    }
}

/// Immutable predecessor and successor values calculated for Home acceptance.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentAssignmentHomeHandoffTransition {
    predecessor: RegisteredAgentAssignment,
    successor: RegisteredAgentAssignment,
}

impl AgentAssignmentHomeHandoffTransition {
    /// Calculates the neutral predecessor disposition and Running successor.
    ///
    /// Coordinator and Source authority, current binding, handback evidence,
    /// closure, Node readiness/transition, and durable application remain the
    /// responsibility of the owner layer.
    pub fn new(
        source: &RegisteredAgentAssignment,
        expected_source_revision: AgentAssignmentRevision,
        acceptance: AgentAssignmentHomeHandoffAcceptance,
    ) -> Result<Self, AgentAssignmentTransitionError> {
        if acceptance.origin.predecessor_id() != source.id() {
            return Err(AgentAssignmentTransitionError::InvalidHomeHandoffOrigin);
        }

        let root_assignment_id = match source.origin() {
            AgentAssignmentOrigin::CoordinatorOffer => source.id(),
            AgentAssignmentOrigin::HomeHandoff(origin) => origin.root_assignment_id(),
            AgentAssignmentOrigin::CutContinuation(_) => {
                return Err(AgentAssignmentTransitionError::HomeHandoffLineageUnsupported);
            }
        };
        if acceptance.origin.root_assignment_id() != root_assignment_id {
            return Err(AgentAssignmentTransitionError::InvalidHomeHandoffOrigin);
        }
        if acceptance.successor_id.into_uuid().is_nil()
            || acceptance.successor_id == source.id()
            || acceptance.successor_id == root_assignment_id
        {
            return Err(AgentAssignmentTransitionError::HomeHandoffIdentityConflict);
        }
        if acceptance.coordinator.workspace_id() != source.workspace_id()
            || acceptance.coordinator.activity_id() != source.activity_id()
        {
            return Err(AgentAssignmentTransitionError::HomeHandoffCoordinatorScopeConflict);
        }
        if acceptance.recipient.agent_id() == source.target().agent_id()
            || acceptance.recipient.session_id() == source.target().session_id()
        {
            return Err(AgentAssignmentTransitionError::HomeHandoffRecipientConflict);
        }
        if acceptance.node_revision.get() < source.node_revision().get() {
            return Err(AgentAssignmentTransitionError::HomeHandoffNodeRevisionConflict);
        }
        if source.cancellation_requested()
            || !matches!(
                source.state(),
                AgentAssignmentState::Offered | AgentAssignmentState::Running
            )
        {
            return Err(AgentAssignmentTransitionError::InvalidState);
        }

        let predecessor = match source.state() {
            AgentAssignmentState::Offered => source.request_cancel(
                acceptance.coordinator,
                expected_source_revision,
                acceptance.effective_at,
            )?,
            AgentAssignmentState::Running => {
                source.interrupt(expected_source_revision, acceptance.effective_at)?
            }
            AgentAssignmentState::Submitted
            | AgentAssignmentState::Accepted
            | AgentAssignmentState::Rejected
            | AgentAssignmentState::Cancelled
            | AgentAssignmentState::Interrupted => {
                return Err(AgentAssignmentTransitionError::InvalidState);
            }
        };

        let successor = RegisteredAgentAssignment::from_parts(
            acceptance.successor_id,
            source.workspace_id(),
            source.activity_id(),
            source.goal_id(),
            source.goal_created_at(),
            source.goal_revision(),
            source.dag_revision(),
            source.dag_head_revision(),
            source.node_id(),
            acceptance.node_revision,
            AgentAssignmentCoordinator::from_actor(acceptance.coordinator),
            acceptance.recipient,
            AgentAssignmentState::Running,
            false,
            source.credit_budget(),
            None,
            None,
            acceptance.effective_at,
            acceptance.effective_at,
            AgentAssignmentRevision::INITIAL,
            AgentAssignmentOrigin::HomeHandoff(acceptance.origin),
        )?;

        Ok(Self {
            predecessor,
            successor,
        })
    }

    pub const fn predecessor(&self) -> &RegisteredAgentAssignment {
        &self.predecessor
    }

    pub const fn successor(&self) -> &RegisteredAgentAssignment {
        &self.successor
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::error::Error;

    use crate::{
        ActivityCoordinatorRevision, ActivityId, AgentAssignmentContinuationOrigin,
        AgentAssignmentResult, AgentInstanceId, AgentInstanceRevision, AgentSessionId,
        AuthenticatedPrincipal, DagHeadRevision, DagNodeId, DagRevisionNumber, GoalId,
        GoalRevision, WorkCreditBudget, WorkspaceId,
    };
    use uuid::Uuid;

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    fn uuid(value: u128) -> Uuid {
        Uuid::from_u128(value)
    }

    fn actor(
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        agent_id: u128,
        session_id: u128,
    ) -> ActivityCoordinatorActor {
        ActivityCoordinatorActor::new(
            workspace_id,
            activity_id,
            AgentInstanceId::from_uuid(uuid(agent_id)),
            ActivityCoordinatorRevision::INITIAL,
            AuthenticatedPrincipal::TrustedStdio,
            AgentSessionId::from_uuid(uuid(session_id)),
        )
    }

    fn target(agent_id: u128, session_id: u128) -> AgentAssignmentTarget {
        AgentAssignmentTarget::new(
            AgentInstanceId::from_uuid(uuid(agent_id)),
            AgentSessionId::from_uuid(uuid(session_id)),
            AuthenticatedPrincipal::TrustedStdio,
            AgentInstanceRevision::INITIAL,
        )
    }

    fn fixture() -> TestResult<(RegisteredAgentAssignment, ActivityCoordinatorActor)> {
        let workspace_id = WorkspaceId::from_uuid(uuid(1));
        let activity_id = ActivityId::from_uuid(uuid(2));
        let coordinator = actor(workspace_id, activity_id, 3, 4);
        let source = RegisteredAgentAssignment::offered(
            AgentAssignmentId::from_uuid(uuid(5)),
            workspace_id,
            activity_id,
            GoalId::from_uuid(uuid(6)),
            TimestampMillis::new(1)?,
            GoalRevision::INITIAL,
            DagRevisionNumber::INITIAL,
            DagHeadRevision::INITIAL,
            DagNodeId::from_uuid(uuid(7)),
            DagNodeRevision::new(4)?,
            AgentAssignmentCoordinator::from_actor(coordinator),
            target(8, 9),
            Some(WorkCreditBudget::Three),
            TimestampMillis::new(10)?,
        )?;
        Ok((source, coordinator))
    }

    #[allow(clippy::too_many_arguments)]
    fn acceptance(
        source: &RegisteredAgentAssignment,
        successor_id: AgentAssignmentId,
        recipient: AgentAssignmentTarget,
        coordinator: ActivityCoordinatorActor,
        root_assignment_id: AgentAssignmentId,
        node_revision: DagNodeRevision,
        preparation_id: u128,
        handoff_id: u128,
        effective_at: TimestampMillis,
    ) -> Result<AgentAssignmentHomeHandoffAcceptance, AgentAssignmentTransitionError> {
        let origin = AgentAssignmentHomeHandoffOrigin::new(
            uuid(preparation_id),
            uuid(handoff_id),
            source.id(),
            root_assignment_id,
        )?;
        Ok(AgentAssignmentHomeHandoffAcceptance::new(
            origin,
            successor_id,
            recipient,
            coordinator,
            node_revision,
            effective_at,
        ))
    }

    fn with_origin(
        source: &RegisteredAgentAssignment,
        origin: AgentAssignmentOrigin,
    ) -> Result<RegisteredAgentAssignment, AgentAssignmentTransitionError> {
        RegisteredAgentAssignment::from_parts(
            source.id(),
            source.workspace_id(),
            source.activity_id(),
            source.goal_id(),
            source.goal_created_at(),
            source.goal_revision(),
            source.dag_revision(),
            source.dag_head_revision(),
            source.node_id(),
            source.node_revision(),
            source.coordinator(),
            source.target(),
            source.state(),
            source.cancellation_requested(),
            source.credit_budget(),
            source.result().cloned(),
            source.reviewed_by(),
            source.created_at(),
            source.updated_at(),
            source.revision(),
            origin,
        )
    }

    fn assert_same_scope(
        source: &RegisteredAgentAssignment,
        successor: &RegisteredAgentAssignment,
    ) {
        assert_eq!(successor.workspace_id(), source.workspace_id());
        assert_eq!(successor.activity_id(), source.activity_id());
        assert_eq!(successor.goal_id(), source.goal_id());
        assert_eq!(successor.goal_created_at(), source.goal_created_at());
        assert_eq!(successor.goal_revision(), source.goal_revision());
        assert_eq!(successor.dag_revision(), source.dag_revision());
        assert_eq!(successor.dag_head_revision(), source.dag_head_revision());
        assert_eq!(successor.node_id(), source.node_id());
        assert_eq!(successor.credit_budget(), source.credit_budget());
    }

    #[test]
    fn offered_handoff_cancels_predecessor_and_starts_successor_at_effective_time() -> TestResult {
        let (source, _) = fixture()?;
        let current_coordinator = ActivityCoordinatorActor::new(
            source.workspace_id(),
            source.activity_id(),
            AgentInstanceId::from_uuid(uuid(15)),
            ActivityCoordinatorRevision::new(2)?,
            AuthenticatedPrincipal::TrustedStdio,
            AgentSessionId::from_uuid(uuid(16)),
        );
        let recipient = target(10, 11);
        let effective_at = TimestampMillis::new(20)?;
        let acceptance = acceptance(
            &source,
            AgentAssignmentId::from_uuid(uuid(12)),
            recipient,
            current_coordinator,
            source.id(),
            source.node_revision(),
            13,
            14,
            effective_at,
        )?;

        let transition =
            AgentAssignmentHomeHandoffTransition::new(&source, source.revision(), acceptance)?;
        let predecessor = transition.predecessor();
        let successor = transition.successor();

        assert_eq!(predecessor.state(), AgentAssignmentState::Cancelled);
        assert!(predecessor.cancellation_requested());
        assert_eq!(predecessor.origin(), source.origin());
        assert_eq!(predecessor.created_at(), source.created_at());
        assert_eq!(predecessor.updated_at(), effective_at);
        assert_eq!(predecessor.credit_budget(), source.credit_budget());
        assert_eq!(predecessor.revision(), source.revision().checked_next()?);
        assert_eq!(predecessor.coordinator(), source.coordinator());
        assert_same_scope(&source, predecessor);

        assert_eq!(successor.state(), AgentAssignmentState::Running);
        assert!(!successor.cancellation_requested());
        assert_eq!(successor.revision(), AgentAssignmentRevision::INITIAL);
        assert_eq!(successor.created_at(), effective_at);
        assert_eq!(successor.updated_at(), effective_at);
        assert_eq!(successor.target(), recipient);
        assert_eq!(
            successor.coordinator(),
            AgentAssignmentCoordinator::from_actor(current_coordinator)
        );
        assert_ne!(successor.coordinator(), source.coordinator());
        assert_eq!(successor.node_revision(), source.node_revision());
        assert_eq!(
            successor.origin(),
            AgentAssignmentOrigin::HomeHandoff(acceptance.origin())
        );
        assert_same_scope(&source, successor);
        assert!(matches!(
            successor.claim(recipient, successor.revision(), TimestampMillis::new(21)?),
            Err(AgentAssignmentTransitionError::ContinuationAuthorityRequired)
        ));
        let submitted = successor.submit(
            recipient,
            successor.revision(),
            AgentAssignmentResult::new("handed-off work".to_owned(), Vec::new(), None)?,
            TimestampMillis::new(21)?,
        )?;
        assert_eq!(submitted.origin(), successor.origin());
        assert_eq!(source.state(), AgentAssignmentState::Offered);
        assert_eq!(source.updated_at(), TimestampMillis::new(10)?);
        Ok(())
    }

    #[test]
    fn running_handoff_interrupts_predecessor_and_preserves_original_root() -> TestResult {
        let (source, coordinator) = fixture()?;
        let first_origin_acceptance = acceptance(
            &source,
            AgentAssignmentId::from_uuid(uuid(20)),
            target(21, 22),
            coordinator,
            source.id(),
            source.node_revision(),
            23,
            24,
            TimestampMillis::new(20)?,
        )?;
        let first = AgentAssignmentHomeHandoffTransition::new(
            &source,
            source.revision(),
            first_origin_acceptance,
        )?;
        let running = first.successor();
        let next_node_revision = DagNodeRevision::new(6)?;
        let effective_at = TimestampMillis::new(30)?;
        let second_acceptance = acceptance(
            running,
            AgentAssignmentId::from_uuid(uuid(25)),
            target(26, 27),
            coordinator,
            source.id(),
            next_node_revision,
            28,
            29,
            effective_at,
        )?;

        let second = AgentAssignmentHomeHandoffTransition::new(
            running,
            running.revision(),
            second_acceptance,
        )?;
        let predecessor = second.predecessor();
        let successor = second.successor();

        assert_eq!(predecessor.state(), AgentAssignmentState::Interrupted);
        assert!(predecessor.cancellation_requested());
        assert_eq!(predecessor.origin(), running.origin());
        assert_eq!(predecessor.updated_at(), effective_at);
        assert_eq!(predecessor.credit_budget(), source.credit_budget());
        assert_same_scope(running, predecessor);
        assert_eq!(successor.state(), AgentAssignmentState::Running);
        assert_eq!(successor.created_at(), effective_at);
        assert_eq!(successor.updated_at(), effective_at);
        assert_eq!(successor.node_revision(), next_node_revision);
        assert_eq!(successor.target(), second_acceptance.recipient());
        assert_eq!(
            successor.origin(),
            AgentAssignmentOrigin::HomeHandoff(second_acceptance.origin())
        );
        assert!(matches!(
            successor.origin(),
            AgentAssignmentOrigin::HomeHandoff(origin)
                if origin.root_assignment_id() == source.id()
        ));
        assert_same_scope(running, successor);
        assert_eq!(running.state(), AgentAssignmentState::Running);
        assert!(!running.cancellation_requested());
        Ok(())
    }

    #[test]
    fn rejects_stale_revision_and_regressed_node_revision() -> TestResult {
        let (source, coordinator) = fixture()?;
        let recipient = target(10, 11);
        let effective_at = TimestampMillis::new(20)?;
        let valid_acceptance = acceptance(
            &source,
            AgentAssignmentId::from_uuid(uuid(30)),
            recipient,
            coordinator,
            source.id(),
            source.node_revision(),
            31,
            32,
            effective_at,
        )?;
        assert!(matches!(
            AgentAssignmentHomeHandoffTransition::new(
                &source,
                source.revision().checked_next()?,
                valid_acceptance,
            ),
            Err(AgentAssignmentTransitionError::RevisionConflict)
        ));

        let regressed = acceptance(
            &source,
            AgentAssignmentId::from_uuid(uuid(33)),
            recipient,
            coordinator,
            source.id(),
            DagNodeRevision::new(3)?,
            34,
            35,
            effective_at,
        )?;
        assert!(matches!(
            AgentAssignmentHomeHandoffTransition::new(&source, source.revision(), regressed),
            Err(AgentAssignmentTransitionError::HomeHandoffNodeRevisionConflict)
        ));

        let early = acceptance(
            &source,
            AgentAssignmentId::from_uuid(uuid(36)),
            recipient,
            coordinator,
            source.id(),
            source.node_revision(),
            37,
            38,
            TimestampMillis::new(9)?,
        )?;
        assert!(matches!(
            AgentAssignmentHomeHandoffTransition::new(&source, source.revision(), early),
            Err(AgentAssignmentTransitionError::TimestampOrder)
        ));
        Ok(())
    }

    #[test]
    fn rejects_pending_cancellation_and_submitted_predecessors() -> TestResult {
        let (source, coordinator) = fixture()?;
        let running = source.claim(
            source.target(),
            source.revision(),
            TimestampMillis::new(20)?,
        )?;
        let pending =
            running.request_cancel(coordinator, running.revision(), TimestampMillis::new(21)?)?;
        let pending_acceptance = acceptance(
            &pending,
            AgentAssignmentId::from_uuid(uuid(40)),
            target(41, 42),
            coordinator,
            source.id(),
            pending.node_revision(),
            43,
            44,
            TimestampMillis::new(30)?,
        )?;
        assert!(matches!(
            AgentAssignmentHomeHandoffTransition::new(
                &pending,
                pending.revision(),
                pending_acceptance,
            ),
            Err(AgentAssignmentTransitionError::InvalidState)
        ));

        let running = source.claim(
            source.target(),
            source.revision(),
            TimestampMillis::new(20)?,
        )?;
        let submitted = running.submit(
            running.target(),
            running.revision(),
            AgentAssignmentResult::new("submitted".to_owned(), Vec::new(), None)?,
            TimestampMillis::new(21)?,
        )?;
        let submitted_acceptance = acceptance(
            &submitted,
            AgentAssignmentId::from_uuid(uuid(45)),
            target(46, 47),
            coordinator,
            source.id(),
            submitted.node_revision(),
            48,
            49,
            TimestampMillis::new(30)?,
        )?;
        assert!(matches!(
            AgentAssignmentHomeHandoffTransition::new(
                &submitted,
                submitted.revision(),
                submitted_acceptance,
            ),
            Err(AgentAssignmentTransitionError::InvalidState)
        ));

        let cancelled =
            source.request_cancel(coordinator, source.revision(), TimestampMillis::new(20)?)?;
        let cancelled_acceptance = acceptance(
            &cancelled,
            AgentAssignmentId::from_uuid(uuid(50)),
            target(51, 52),
            coordinator,
            source.id(),
            cancelled.node_revision(),
            53,
            54,
            TimestampMillis::new(30)?,
        )?;
        assert!(matches!(
            AgentAssignmentHomeHandoffTransition::new(
                &cancelled,
                cancelled.revision(),
                cancelled_acceptance,
            ),
            Err(AgentAssignmentTransitionError::InvalidState)
        ));
        Ok(())
    }

    #[test]
    fn rejects_successor_aliases_origin_cycles_and_invalid_origin_ids() -> TestResult {
        let (source, coordinator) = fixture()?;
        let invalid_origins = [
            (Uuid::nil(), uuid(51), source.id(), source.id()),
            (uuid(51), Uuid::nil(), source.id(), source.id()),
            (
                uuid(51),
                uuid(52),
                AgentAssignmentId::from_uuid(Uuid::nil()),
                source.id(),
            ),
            (
                uuid(51),
                uuid(52),
                source.id(),
                AgentAssignmentId::from_uuid(Uuid::nil()),
            ),
        ];
        for (preparation_id, handoff_id, predecessor_id, root_assignment_id) in invalid_origins {
            assert!(matches!(
                AgentAssignmentHomeHandoffOrigin::new(
                    preparation_id,
                    handoff_id,
                    predecessor_id,
                    root_assignment_id,
                ),
                Err(AgentAssignmentTransitionError::InvalidHomeHandoffOrigin)
            ));
        }

        for (predecessor_id, root_assignment_id) in [
            (source.id(), AgentAssignmentId::from_uuid(uuid(53))),
            (AgentAssignmentId::from_uuid(uuid(54)), source.id()),
        ] {
            let cyclic_origin = AgentAssignmentHomeHandoffOrigin::new(
                uuid(55),
                uuid(56),
                predecessor_id,
                root_assignment_id,
            )?;
            assert!(matches!(
                with_origin(&source, AgentAssignmentOrigin::HomeHandoff(cyclic_origin)),
                Err(AgentAssignmentTransitionError::InvalidHomeHandoffOrigin)
            ));
        }

        let aliased_successor = acceptance(
            &source,
            source.id(),
            target(54, 55),
            coordinator,
            source.id(),
            source.node_revision(),
            56,
            57,
            TimestampMillis::new(20)?,
        )?;
        assert!(matches!(
            AgentAssignmentHomeHandoffTransition::new(
                &source,
                source.revision(),
                aliased_successor,
            ),
            Err(AgentAssignmentTransitionError::HomeHandoffIdentityConflict)
        ));

        let first_acceptance = acceptance(
            &source,
            AgentAssignmentId::from_uuid(uuid(58)),
            target(59, 60),
            coordinator,
            source.id(),
            source.node_revision(),
            61,
            62,
            TimestampMillis::new(20)?,
        )?;
        let first = AgentAssignmentHomeHandoffTransition::new(
            &source,
            source.revision(),
            first_acceptance,
        )?;
        let running = first.successor();
        let aliased_root = acceptance(
            running,
            source.id(),
            target(63, 64),
            coordinator,
            source.id(),
            running.node_revision(),
            65,
            66,
            TimestampMillis::new(30)?,
        )?;
        assert!(matches!(
            AgentAssignmentHomeHandoffTransition::new(running, running.revision(), aliased_root,),
            Err(AgentAssignmentTransitionError::HomeHandoffIdentityConflict)
        ));
        Ok(())
    }

    #[test]
    fn rejects_wrong_coordinator_scope_and_same_recipient_identity() -> TestResult {
        let (source, coordinator) = fixture()?;
        let other_coordinator = actor(WorkspaceId::from_uuid(uuid(70)), source.activity_id(), 3, 4);
        let wrong_scope = acceptance(
            &source,
            AgentAssignmentId::from_uuid(uuid(71)),
            target(72, 73),
            other_coordinator,
            source.id(),
            source.node_revision(),
            74,
            75,
            TimestampMillis::new(20)?,
        )?;
        assert!(matches!(
            AgentAssignmentHomeHandoffTransition::new(&source, source.revision(), wrong_scope,),
            Err(AgentAssignmentTransitionError::HomeHandoffCoordinatorScopeConflict)
        ));

        let same_recipient = acceptance(
            &source,
            AgentAssignmentId::from_uuid(uuid(76)),
            source.target(),
            coordinator,
            source.id(),
            source.node_revision(),
            77,
            78,
            TimestampMillis::new(20)?,
        )?;
        assert!(matches!(
            AgentAssignmentHomeHandoffTransition::new(&source, source.revision(), same_recipient,),
            Err(AgentAssignmentTransitionError::HomeHandoffRecipientConflict)
        ));

        for recipient in [target(8, 79), target(80, 9)] {
            let conflicting_recipient = acceptance(
                &source,
                AgentAssignmentId::from_uuid(uuid(81)),
                recipient,
                coordinator,
                source.id(),
                source.node_revision(),
                82,
                83,
                TimestampMillis::new(20)?,
            )?;
            assert!(matches!(
                AgentAssignmentHomeHandoffTransition::new(
                    &source,
                    source.revision(),
                    conflicting_recipient,
                ),
                Err(AgentAssignmentTransitionError::HomeHandoffRecipientConflict)
            ));
        }
        Ok(())
    }

    #[test]
    fn refuses_cut_continuation_without_an_applied_home_root_proof() -> TestResult {
        let (source, coordinator) = fixture()?;
        let cut_origin =
            AgentAssignmentOrigin::CutContinuation(AgentAssignmentContinuationOrigin::new(
                uuid(80),
                uuid(81),
                AgentAssignmentId::from_uuid(uuid(82)),
            )?);
        let cut_source = with_origin(&source, cut_origin)?;
        let requested = acceptance(
            &cut_source,
            AgentAssignmentId::from_uuid(uuid(83)),
            target(84, 85),
            coordinator,
            AgentAssignmentId::from_uuid(uuid(86)),
            cut_source.node_revision(),
            87,
            88,
            TimestampMillis::new(20)?,
        )?;

        assert!(matches!(
            AgentAssignmentHomeHandoffTransition::new(
                &cut_source,
                cut_source.revision(),
                requested,
            ),
            Err(AgentAssignmentTransitionError::HomeHandoffLineageUnsupported)
        ));
        Ok(())
    }
}
