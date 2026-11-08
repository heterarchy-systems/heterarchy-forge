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

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(crate) fn seed_applied_file_diff(
    control: &ForgeControl,
    scope: &ResolvedWorkspaceScope,
    activity: crate::FileActivityScope,
    goal: Option<forge_domain::GoalWorkAttribution>,
    write_authority: SourceWriteAuthority,
    change_set_id: forge_domain::ChangeSetId,
    mutation_id: forge_domain::FileMutationId,
    relative_path: WorkspaceRelativePath,
    content: &[u8],
) -> Result<forge_domain::FileMutationRecord, Box<dyn std::error::Error>> {
    let (fresh_scope, layout, mut store) = control.open_effect_workspace(scope)?;
    let activity_row = crate::filesystem::authorize_activity(&store, activity)?;
    let filesystem = forge_workspace::ConfinedWorkspace::open(&layout)?;
    let diff_artifacts = filesystem.diff_artifact_store()?;
    let (pre_state, pre_source, kind, precondition) = match filesystem.read(&relative_path) {
        Ok(read) => (
            read.state(),
            forge_workspace::CapturedDiffSource::Text(String::from_utf8(read.content().to_vec())?),
            forge_domain::FileMutationKind::Replace,
            forge_domain::FilePrecondition::Matches(read.hash()),
        ),
        Err(forge_workspace::ConfinedFilesystemError::NotFound) => (
            forge_domain::FilePathState::Absent,
            forge_workspace::CapturedDiffSource::Absent,
            forge_domain::FileMutationKind::Create,
            forge_domain::FilePrecondition::Absent,
        ),
        Err(error) => return Err(error.into()),
    };
    let post_source =
        forge_workspace::CapturedDiffSource::Text(String::from_utf8(content.to_vec())?);
    let diff_kind = match kind {
        forge_domain::FileMutationKind::Create => forge_domain::DiffChangeKind::Created,
        forge_domain::FileMutationKind::Replace => forge_domain::DiffChangeKind::Modified,
        forge_domain::FileMutationKind::Delete => forge_domain::DiffChangeKind::Deleted,
    };
    let rendered = forge_workspace::render_diff_evidence(
        &relative_path,
        diff_kind,
        &pre_source,
        &post_source,
    )?;
    let forge_workspace::RenderedDiffEvidence::Text(rendered_text) = rendered else {
        return Err("expected text diff".into());
    };
    let diff_id = forge_domain::DiffId::for_change_set(change_set_id);
    let staged = diff_artifacts.stage(diff_id, &rendered_text)?;
    let file_entry = forge_domain::DiffEntrySummary::new(
        forge_domain::DiffEntrySubject::File,
        relative_path.clone(),
        None,
        diff_kind,
        rendered_text.additions(),
        rendered_text.deletions(),
    )?;
    let begin_diff = forge_domain::BeginDiffEvidence::new(
        forge_domain::DiffAttribution::for_file_mutation(
            diff_id,
            fresh_scope.workspace_id(),
            activity.activity_id,
            change_set_id,
            mutation_id,
        ),
        vec![file_entry],
        forge_domain::DiffPayloadProjection::IntentText {
            pending_relative_path: staged.pending_relative_path()?,
            final_relative_path: staged.final_relative_path()?,
            compressed_hash: staged.compressed_hash(),
            uncompressed_hash: staged.uncompressed_hash(),
            compressed_size: staged.compressed_size(),
            uncompressed_size: staged.uncompressed_size(),
        },
        activity.observed_at,
        forge_domain::DiffContractVersions::V1,
    )?;
    let intended_hash =
        forge_domain::FileContentHash::from_bytes(*blake3::hash(content).as_bytes());
    let identity = forge_domain::FileMutationIdentity::new(change_set_id, mutation_id);
    let begin_cmd = forge_domain::BeginFileMutation::new(
        identity,
        forge_domain::FileMutationScope::new(
            fresh_scope.workspace_id(),
            fresh_scope.workspace_revision(),
            activity_row.id(),
            activity.runtime_instance_id,
            activity_row.lease_revision(),
        ),
        forge_domain::FileMutationPlan::new(relative_path, kind, precondition),
        Some(intended_hash),
        pre_state,
        activity.observed_at,
    )?;
    let begin =
        store.begin_file_mutation_for_goal(&begin_cmd, &begin_diff, goal, write_authority)?;
    let path = begin.record().mutation().path();
    let starting_checkpoint = match forge_workspace::GitCheckpointStore::new(
        layout.workspace_root(),
        layout.checkpoints(),
    ) {
        Ok(git_store) => {
            let attribution = forge_domain::CheckpointAttribution::new(
                forge_domain::CheckpointId::from_uuid(Uuid::now_v7()),
                change_set_id,
                fresh_scope.workspace_id(),
                fresh_scope.workspace_revision(),
                activity.activity_id,
            );
            let starting =
                git_store.begin_checkpoint(attribution, path.clone(), activity.observed_at)?;
            let starting = store.begin_checkpoint_for_goal(&starting, goal)?;
            Some((git_store, starting))
        }
        Err(forge_workspace::GitSafetyError::NotGitRepository) => None,
        Err(error) => return Err(error.into()),
    };
    let target = layout.workspace_root().join(path.as_path());
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&target, content)?;
    let post_read = filesystem.read(path)?;
    let published = diff_artifacts.publish(staged)?;
    let expected = published.expectation();
    let complete_cmd = forge_domain::CompleteFileMutation::new(
        identity,
        begin.record().change_set().revision(),
        begin.record().mutation().revision(),
        post_read.state(),
        activity.observed_at,
    );
    let diff_revision = begin.diff().map_or(
        forge_domain::DiffRevision::INITIAL,
        forge_domain::RegisteredDiffEvidence::revision,
    );
    let complete_diff = forge_domain::CompleteDiffEvidence::new(
        diff_id,
        diff_revision,
        forge_domain::DiffPayloadProjection::Ready {
            relative_path: published.relative_path()?,
            compressed_hash: expected.compressed_hash(),
            uncompressed_hash: expected.uncompressed_hash(),
            compressed_size: expected.compressed_size(),
            uncompressed_size: expected.uncompressed_size(),
        },
        activity.observed_at,
    )?;
    let record = store.complete_file_mutation(
        &complete_cmd,
        &complete_diff,
        forge_domain::ChangeSetProducer::new(
            write_authority.agent_id(),
            write_authority.session_id(),
        ),
    )?;
    if let Some((git_store, starting)) = starting_checkpoint {
        let completed = git_store.complete_checkpoint(&starting, activity.observed_at)?;
        let _ready = store.complete_checkpoint(&completed, starting.revision())?;
    }
    Ok(record.file().clone())
}
