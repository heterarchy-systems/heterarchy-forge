use super::*;
use crate::{
    ActivityCoordinatorRevision, ActivityId, AgentDeclaredRole, AgentDisplayName,
    AgentTransportKind, OAuthGrantId, WorkspaceId,
};

fn agent(
    id: u128,
    workspace: WorkspaceId,
    activity: ActivityId,
    principal: AuthenticatedPrincipal,
) -> Result<RegisteredAgentInstance, Box<dyn std::error::Error>> {
    Ok(RegisteredAgentInstance::create_bound(
        AgentInstanceId::from_uuid(Uuid::from_u128(id)),
        workspace,
        activity,
        AgentSessionId::from_uuid(Uuid::from_u128(id + 100)),
        AgentDisplayName::new(format!("agent-{id}"))?,
        AgentDeclaredRole::new("coordinator".into())?,
        AgentTransportKind::Retired,
        principal,
        TimestampMillis::new(10)?,
    ))
}

#[test]
fn owner_recovery_requires_distinct_local_target_and_exact_scope()
-> Result<(), Box<dyn std::error::Error>> {
    let workspace = WorkspaceId::from_uuid(Uuid::from_u128(1));
    let activity = ActivityId::from_uuid(Uuid::from_u128(2));
    let oauth = AuthenticatedPrincipal::OAuthGrant(OAuthGrantId::from_uuid(Uuid::from_u128(3)));
    let source = agent(4, workspace, activity, oauth)?;
    let target = agent(5, workspace, activity, AuthenticatedPrincipal::TrustedStdio)?;
    let binding = ActivityCoordinatorBinding::new(
        workspace,
        activity,
        source.id(),
        ActivityCoordinatorRevision::INITIAL,
        TimestampMillis::new(10)?,
    );
    let fence = CoordinatorRecoveryFence::from_agents(binding, &source, &target)?;
    let command = ConfirmedCoordinatorRecovery::new(
        Uuid::from_u128(6),
        fence,
        CoordinatorRecoveryReason::new("Original OAuth connection is unavailable".into())?,
        TimestampMillis::new(11)?,
    )?;
    let receipt = CoordinatorRecoveryReceipt::new(command)?;
    assert_eq!(receipt.binding().agent_id(), target.id());
    assert_eq!(receipt.binding().revision().get(), 2);
    assert_eq!(receipt.request().fence().source().principal(), oauth);
    assert_eq!(source.revision(), AgentInstanceRevision::INITIAL);
    assert_eq!(target.revision(), AgentInstanceRevision::INITIAL);
    assert_eq!(
        CoordinatorRecoveryFence::from_agents(binding, &source, &source),
        Err(CoordinatorRecoveryError::SameParticipant)
    );
    let remote = agent(7, workspace, activity, oauth)?;
    assert_eq!(
        CoordinatorRecoveryFence::from_agents(binding, &source, &remote),
        Err(CoordinatorRecoveryError::NonLocalTarget)
    );
    let foreign = agent(
        8,
        WorkspaceId::from_uuid(Uuid::from_u128(9)),
        activity,
        AuthenticatedPrincipal::TrustedStdio,
    )?;
    assert_eq!(
        CoordinatorRecoveryFence::from_agents(binding, &source, &foreign),
        Err(CoordinatorRecoveryError::ScopeMismatch)
    );
    Ok(())
}

#[test]
fn confirmation_rejects_empty_multiline_oversized_reason_and_old_timestamp()
-> Result<(), Box<dyn std::error::Error>> {
    for value in [
        String::new(),
        " ".to_owned(),
        "a\nb".to_owned(),
        "a\u{85}b".to_owned(),
        "a\u{2028}b".to_owned(),
        "a\u{2029}b".to_owned(),
        "x".repeat(1025),
    ] {
        assert!(CoordinatorRecoveryReason::new(value).is_err());
    }
    let workspace = WorkspaceId::from_uuid(Uuid::from_u128(1));
    let activity = ActivityId::from_uuid(Uuid::from_u128(2));
    let source = agent(4, workspace, activity, AuthenticatedPrincipal::TrustedStdio)?;
    let target = agent(5, workspace, activity, AuthenticatedPrincipal::TrustedStdio)?;
    let binding = ActivityCoordinatorBinding::new(
        workspace,
        activity,
        source.id(),
        ActivityCoordinatorRevision::INITIAL,
        TimestampMillis::new(10)?,
    );
    let fence = CoordinatorRecoveryFence::from_agents(binding, &source, &target)?;
    assert_eq!(
        ConfirmedCoordinatorRecovery::new(
            Uuid::from_u128(6),
            fence,
            CoordinatorRecoveryReason::new("owner recovery".into())?,
            TimestampMillis::new(9)?
        ),
        Err(CoordinatorRecoveryError::TimestampOrder)
    );
    Ok(())
}
