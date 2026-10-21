use super::*;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn lineage(source: &RegisteredAgentAssignment) -> TestResult<AgentAssignmentOrigin> {
    Ok(AgentAssignmentOrigin::CutContinuation(
        AgentAssignmentContinuationOrigin::new(
            Uuid::from_u128(0xC1),
            Uuid::from_u128(0xC2),
            source.id(),
        )?,
    ))
}

fn successor(
    source: &RegisteredAgentAssignment,
    id: AgentAssignmentId,
    state: AgentAssignmentState,
    origin: AgentAssignmentOrigin,
) -> Result<RegisteredAgentAssignment, AgentAssignmentTransitionError> {
    let coordinator = source.coordinator();
    let recipient = AgentAssignmentTarget::new(
        coordinator.agent_id(),
        coordinator.session_id(),
        coordinator.principal(),
        AgentInstanceRevision::INITIAL,
    );
    RegisteredAgentAssignment::from_parts(
        id,
        source.workspace_id(),
        source.activity_id(),
        source.goal_id(),
        source.goal_created_at(),
        source.goal_revision(),
        source.dag_revision(),
        source.dag_head_revision(),
        source.node_id(),
        source.node_revision(),
        coordinator,
        recipient,
        state,
        false,
        source.credit_budget(),
        None,
        None,
        source.created_at(),
        source.updated_at(),
        AgentAssignmentRevision::INITIAL,
        origin,
    )
}

#[test]
fn cut_origin_preserves_history_and_does_not_grant_ordinary_claim_or_self_review() -> TestResult {
    let (source, original_coordinator, worker) = scope()?;
    assert_eq!(source.origin(), AgentAssignmentOrigin::CoordinatorOffer);
    let origin = lineage(&source)?;
    let offered = successor(
        &source,
        AgentAssignmentId::from_uuid(Uuid::from_u128(0xC3)),
        AgentAssignmentState::Offered,
        origin,
    )?;
    assert_eq!(offered.summary(0).origin(), origin);
    assert_eq!(offered.coordinator(), source.coordinator());
    assert_eq!(
        offered.coordinator().agent_id(),
        offered.target().agent_id()
    );
    assert!(matches!(
        offered.claim(
            offered.target(),
            offered.revision(),
            TimestampMillis::new(30)?
        ),
        Err(AgentAssignmentTransitionError::ContinuationAuthorityRequired)
    ));
    let running = successor(&source, offered.id(), AgentAssignmentState::Running, origin)?;
    let submitted = running.submit(
        running.target(),
        running.revision(),
        AgentAssignmentResult::new("continued work result".to_owned(), Vec::new(), None)?,
        TimestampMillis::new(31)?,
    )?;
    assert_eq!(submitted.origin(), origin);
    assert!(matches!(
        submitted.accept(
            original_coordinator,
            submitted.revision(),
            TimestampMillis::new(32)?
        ),
        Err(AgentAssignmentTransitionError::CoordinatorTargetSameAgent)
    ));
    assert!(matches!(
        submitted.reject(
            original_coordinator,
            submitted.revision(),
            TimestampMillis::new(32)?
        ),
        Err(AgentAssignmentTransitionError::CoordinatorTargetSameAgent)
    ));
    // This only calculates a domain transition. Persistence still has to
    // authenticate an independently scoped reviewer before any durable effect.
    let independent = ActivityCoordinatorActor::new(
        source.workspace_id(),
        source.activity_id(),
        worker.agent_id(),
        ActivityCoordinatorRevision::INITIAL,
        worker.principal(),
        worker.session_id(),
    );
    let reviewed =
        submitted.accept(independent, submitted.revision(), TimestampMillis::new(32)?)?;
    assert_eq!(reviewed.origin(), origin);
    assert_eq!(reviewed.summary(0).origin(), origin);
    assert_eq!(reviewed.credit_budget(), source.credit_budget());
    assert_eq!(source.state(), AgentAssignmentState::Offered);
    Ok(())
}

#[test]
fn origin_cannot_relabel_ordinary_self_offer_or_point_to_itself() -> TestResult {
    let (source, _, _) = scope()?;
    let next_id = AgentAssignmentId::from_uuid(Uuid::from_u128(0xC3));
    assert!(matches!(
        successor(
            &source,
            next_id,
            AgentAssignmentState::Offered,
            AgentAssignmentOrigin::CoordinatorOffer
        ),
        Err(AgentAssignmentTransitionError::CoordinatorTargetSameAgent)
    ));
    assert!(matches!(
        successor(
            &source,
            source.id(),
            AgentAssignmentState::Running,
            lineage(&source)?
        ),
        Err(AgentAssignmentTransitionError::InvalidContinuationOrigin)
    ));
    for (cut, transfer, predecessor) in [
        (Uuid::nil(), Uuid::from_u128(1), source.id()),
        (Uuid::from_u128(1), Uuid::nil(), source.id()),
        (
            Uuid::from_u128(1),
            Uuid::from_u128(2),
            AgentAssignmentId::from_uuid(Uuid::nil()),
        ),
    ] {
        assert!(matches!(
            AgentAssignmentContinuationOrigin::new(cut, transfer, predecessor),
            Err(AgentAssignmentTransitionError::InvalidContinuationOrigin)
        ));
    }
    Ok(())
}
