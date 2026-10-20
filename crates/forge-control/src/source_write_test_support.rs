use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use forge_domain::{
    AcquireWriterLease, ActivityCoordinatorActor, ActivityId, AgentDagDraft, AgentDagPlanRequest,
    AgentDagPlanRequestId, AgentDeclaredRole, AgentDisplayName, AgentFocus, AgentFocusNode,
    AgentInstanceId, AgentInstanceRevision, AgentSessionId, AgentSessionOpenRequestId,
    AgentTransportKind, AgentWorkUpdateId, AgentWorkUpdateSequence, AuthenticatedPrincipal,
    DagAcceptanceCriterion, DagNodeDefinition, DagNodeId, DagNodeObjective, DagNodeOrdinal,
    DagNodeTitle, DagRevision, DagRevisionId, DagRevisionNumber, GoalAttribution, GoalContract,
    GoalId, GoalNodeAttribution, GoalObjective, GoalStatement, OpenAgentSession,
    RegisteredAgentInstance, RegisteredDagNode, RegisteredGoal, SourceWriteAuthority,
    TimestampMillis, WorkspaceRelativePath, WriterLease, WriterLeaseDurationMillis, WriterLeaseId,
    WriterLeaseScope, WriterLeaseScopeEntry, WriterLeaseScopeKind,
};
use uuid::Uuid;

use crate::{
    AgentDagPlanCommitRequest, AgentFocusRequest, CoordinatorClaimRequest, DagNodeStartRequest,
    ForgeControl, ResolvedWorkspaceScope, WriterLeaseAcquireRequest,
};

fn id(seed: u128, offset: u128) -> Uuid {
    Uuid::from_u128(seed.wrapping_add(offset))
}

fn session_id(request: &SourceWriteTestRequest<'_>) -> AgentSessionId {
    AgentSessionId::from_uuid(id(request.seed, 100))
}

fn timestamp_now() -> Result<TimestampMillis, Box<dyn std::error::Error>> {
    let millis = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    Ok(TimestampMillis::new(millis)?)
}

pub(crate) struct SourceWriteTestRequest<'a> {
    activity_id: ActivityId,
    observed_at: TimestampMillis,
    seed: u128,
    exact_paths: &'a [&'a str],
}

impl<'a> SourceWriteTestRequest<'a> {
    pub(crate) const fn new(
        activity_id: ActivityId,
        observed_at: TimestampMillis,
        seed: u128,
        exact_paths: &'a [&'a str],
    ) -> Self {
        Self {
            activity_id,
            observed_at,
            seed,
            exact_paths,
        }
    }
}

fn attach_source_agent(
    control: &ForgeControl,
    scope: &ResolvedWorkspaceScope,
    request: &SourceWriteTestRequest<'_>,
) -> Result<(AgentInstanceId, ActivityCoordinatorActor), Box<dyn std::error::Error>> {
    let agent_id = AgentInstanceId::from_uuid(id(request.seed, 1));
    let agent = RegisteredAgentInstance::create_bound(
        agent_id,
        scope.workspace_id(),
        request.activity_id,
        session_id(request),
        AgentDisplayName::new("source-writer-test".to_owned())?,
        AgentDeclaredRole::new("source-writer-test".to_owned())?,
        AgentTransportKind::Stdio,
        AuthenticatedPrincipal::TrustedStdio,
        request.observed_at,
    );
    let _session = control.agent_session_open(&OpenAgentSession::new(
        session_id(request),
        AgentSessionOpenRequestId::from_uuid(id(request.seed, 101)),
        AuthenticatedPrincipal::TrustedStdio,
        request.observed_at,
    ))?;
    let _attached = crate::legacy_agent_fixture::seed_agent(
        control,
        scope,
        &agent,
        forge_domain::AgentEventId::from_uuid(agent_id.into_uuid()),
    )?;
    let coordinator = control.activity_coordinator_claim(
        &CoordinatorClaimRequest {
            session_id: session_id(request),
            scope: scope.clone(),
            activity_id: request.activity_id,
            agent_id,
            principal: AuthenticatedPrincipal::TrustedStdio,
            observed_at: request.observed_at,
        },
        timestamp_now()?,
    )?;
    Ok((
        agent_id,
        ActivityCoordinatorActor::new(
            scope.workspace_id(),
            request.activity_id,
            coordinator.agent_id(),
            coordinator.revision(),
            AuthenticatedPrincipal::TrustedStdio,
            session_id(request),
        ),
    ))
}

fn focus_source_agent(
    control: &ForgeControl,
    scope: &ResolvedWorkspaceScope,
    request: &SourceWriteTestRequest<'_>,
    agent_id: AgentInstanceId,
    actor: ActivityCoordinatorActor,
) -> Result<(RegisteredAgentInstance, RegisteredDagNode, RegisteredGoal), Box<dyn std::error::Error>>
{
    let goal = RegisteredGoal::create(
        GoalId::from_uuid(id(request.seed, 2)),
        scope.workspace_id(),
        request.activity_id,
        GoalContract::new(
            GoalObjective::new("Authorize source mutation fixture".to_owned())?,
            vec![GoalStatement::new(
                "Source mutation remains revision fenced".to_owned(),
            )?],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )?,
        request.observed_at,
    );
    let _created = control.goal_create(scope, actor, &goal, timestamp_now()?)?;
    let definition = DagNodeDefinition::new(
        DagNodeId::from_uuid(id(request.seed, 3)),
        DagNodeOrdinal::new(0)?,
        DagNodeTitle::new("Mutate source".to_owned())?,
        DagNodeObjective::new("Apply one revision-fenced source mutation".to_owned())?,
        vec![DagAcceptanceCriterion::new(
            "Durable source authority is verified".to_owned(),
        )?],
    )?;
    let revision = DagRevision::new(
        DagRevisionId::from_uuid(id(request.seed, 4)),
        goal.id(),
        goal.revision(),
        DagRevisionNumber::INITIAL,
        None,
        vec![definition.clone()],
        Vec::new(),
        request.observed_at,
    )?;
    let pending = RegisteredDagNode::create(
        goal.id(),
        revision.number(),
        definition,
        request.observed_at,
    );
    let draft = AgentDagDraft::new(revision, vec![pending.clone()], Vec::new())?;
    let plan = AgentDagPlanRequest::new(
        AgentDagPlanRequestId::from_uuid(id(request.seed, 5)),
        actor,
        GoalAttribution::new(goal.id(), goal.revision()),
        None,
        None,
        draft,
        AgentWorkUpdateId::from_uuid(id(request.seed, 6)),
        AgentWorkUpdateSequence::INITIAL,
        request.observed_at,
    );
    let _stored = control.agent_dag_plan_commit(
        &AgentDagPlanCommitRequest {
            scope: scope.clone(),
            request: plan,
        },
        timestamp_now()?,
    )?;
    let active = control.dag_node_start(
        &DagNodeStartRequest {
            scope: scope.clone(),
            activity_id: request.activity_id,
            session_id: actor.session_id(),
            principal: actor.principal(),
            goal_id: goal.id(),
            expected_goal_revision: goal.revision(),
            expected_dag_revision: pending.dag_revision(),
            node_id: pending.id(),
            expected_revision: pending.revision(),
            observed_at: request.observed_at,
        },
        timestamp_now()?,
    )?;
    let focused = control.agent_set_focus(
        &AgentFocusRequest {
            scope: scope.clone(),
            activity_id: request.activity_id,
            actor,
            agent_id,
            expected_revision: AgentInstanceRevision::INITIAL,
            focus: AgentFocus::new(
                Some(GoalAttribution::new(goal.id(), goal.revision())),
                Some(active.dag_revision()),
                Some(AgentFocusNode::new(active.id(), active.revision())),
            )?,
            observed_at: request.observed_at,
        },
        timestamp_now()?,
    )?;
    Ok((focused, active, goal))
}

fn acquire_source_writer_lease(
    control: &ForgeControl,
    scope: &ResolvedWorkspaceScope,
    request: &SourceWriteTestRequest<'_>,
    agent_id: AgentInstanceId,
) -> Result<WriterLease, Box<dyn std::error::Error>> {
    let lease_scope = WriterLeaseScope::new(
        request
            .exact_paths
            .iter()
            .map(|path| {
                WorkspaceRelativePath::new(PathBuf::from(path))
                    .map(|path| WriterLeaseScopeEntry::new(WriterLeaseScopeKind::ExactPath, path))
            })
            .collect::<Result<Vec<_>, _>>()?,
    )?;
    Ok(control.writer_lease_acquire(&WriterLeaseAcquireRequest {
        scope: scope.clone(),
        activity_id: request.activity_id,
        agent_id,
        principal: AuthenticatedPrincipal::TrustedStdio,
        command: AcquireWriterLease::new(
            WriterLeaseId::from_uuid(id(request.seed, 7)),
            scope.workspace_id(),
            request.activity_id,
            agent_id,
            lease_scope,
            WriterLeaseDurationMillis::MAX,
            request.observed_at,
            session_id(request),
            AuthenticatedPrincipal::TrustedStdio,
        )?,
    })?)
}

pub(crate) fn seed_source_write_authority(
    control: &ForgeControl,
    scope: &ResolvedWorkspaceScope,
    request: &SourceWriteTestRequest<'_>,
) -> Result<SourceWriteAuthority, Box<dyn std::error::Error>> {
    let (agent_id, actor) = attach_source_agent(control, scope, request)?;
    let (focused, active, goal) = focus_source_agent(control, scope, request, agent_id, actor)?;
    let lease = acquire_source_writer_lease(control, scope, request, agent_id)?;
    Ok(SourceWriteAuthority::new(
        focused.id(),
        focused.revision(),
        AuthenticatedPrincipal::TrustedStdio,
        GoalNodeAttribution::new(
            goal.id(),
            goal.revision(),
            active.dag_revision(),
            active.id(),
            active.revision(),
        ),
        lease.id(),
        lease.revision(),
        session_id(request),
    ))
}
