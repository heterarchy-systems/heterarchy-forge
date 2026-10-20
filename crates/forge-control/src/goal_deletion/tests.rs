use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use forge_domain::{
    AcquireWriterLease, ActivityCoordinatorActor, ActivityId, AgentDagDraft, AgentDagPlanRequest,
    AgentDagPlanRequestId, AgentDeclaredRole, AgentDisplayName, AgentEventId, AgentFocus,
    AgentFocusNode, AgentInstanceId, AgentInstanceRevision, AgentSessionId,
    AgentSessionOpenRequestId, AgentTransportKind, AgentWorkUpdateId, AgentWorkUpdateSequence,
    AuthenticatedPrincipal, ChangeSetId, DagAcceptanceCriterion, DagHeadRevision,
    DagNodeDefinition, DagNodeId, DagNodeObjective, DagNodeOrdinal, DagNodeTitle, DagRevision,
    DagRevisionId, DagRevisionNumber, DiffArtifactHealth, DiffEvidenceState, DiffId, DiffListLimit,
    DiffPayloadProjection, EstablishWorkspace, FileContentHash, FileMutationId, FilePatch,
    FilePatchHunk, GoalAttribution, GoalContract, GoalDeletionRequest, GoalDeletionTarget, GoalId,
    GoalNodeAttribution, GoalObjective, GoalRevision, GoalStatement, GoalWorkAttribution,
    LocationId, LocationRevision, OpenAgentSession, RegisteredAgentInstance, RegisteredDagNode,
    RegisteredGoal, ReleaseWriterLease, RuntimeInstanceId, SourceLineRange, SourceRangeHash,
    SourceWriteAuthority, TimestampMillis, WorkspaceId, WorkspaceRelativePath, WorkspaceRevision,
    WorkspaceRoot, WriterLeaseDurationMillis, WriterLeaseId, WriterLeaseScope,
    WriterLeaseScopeEntry, WriterLeaseScopeKind, WriterLeaseState, WriterLeaseStatus,
};
use forge_persistence::{GlobalRegistry, GoalDeletionArtifactKind, WorkspaceStore};
use forge_workspace::{
    LocationService, WorkspaceLocator, WorkspaceStateExclusiveGate, WorkspaceStateLayout,
};
use uuid::Uuid;

use crate::{
    DiffListRequest, DiffReadRequest, FileActivityScope, FileApplyPatchOperation,
    FileApplyPatchRequest, FileMutationStatus, WriterLeaseReleaseRequest,
};

use super::*;

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

struct Fixture {
    root: PathBuf,
    workspace_root: PathBuf,
    control: ForgeControl,
    scope: ResolvedWorkspaceScope,
    activity_id: ActivityId,
    runtime_instance_id: RuntimeInstanceId,
    actor: ActivityCoordinatorActor,
    agent_id: AgentInstanceId,
    session_id: AgentSessionId,
}

fn timestamp(value: i64) -> Result<TimestampMillis, Box<dyn std::error::Error>> {
    Ok(TimestampMillis::new(value)?)
}

fn timestamp_now() -> Result<TimestampMillis, Box<dyn std::error::Error>> {
    let millis = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    Ok(TimestampMillis::new(millis)?)
}

fn fixture(label: &str) -> Result<Fixture, Box<dyn std::error::Error>> {
    fixture_with_relative_workspace(label, Path::new("workspace"))
}

fn fixture_with_relative_workspace(
    label: &str,
    relative_workspace: &Path,
) -> Result<Fixture, Box<dyn std::error::Error>> {
    let serial = u128::from(NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed));
    let root = std::env::temp_dir().join(format!(
        "forge-goal-delete-{label}-{}-{serial}",
        std::process::id()
    ));
    let location_root = root.join("location");
    let workspace_root = if relative_workspace == Path::new(".") {
        location_root.clone()
    } else {
        location_root.join(relative_workspace)
    };
    fs::create_dir_all(&workspace_root)?;
    let registry_path = root.join("registry.sqlite3");
    let location_id = LocationId::from_uuid(Uuid::from_u128(0xD3_0100 + serial));
    let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(0xD3_0200 + serial));
    let activity_id = ActivityId::from_uuid(Uuid::from_u128(0xD3_0300 + serial));
    let runtime_id = RuntimeInstanceId::from_uuid(Uuid::from_u128(0xD3_0400 + serial));
    let mut locations = LocationService::new(GlobalRegistry::open(&registry_path)?);
    locations.register_selected_path(
        location_id,
        "Goal deletion fixture",
        &location_root,
        timestamp(1)?,
    )?;
    drop(locations);

    let layout = WorkspaceStateLayout::initialize(&workspace_root)?;
    let store = WorkspaceStore::open(
        &layout,
        EstablishWorkspace::new(
            workspace_id,
            location_id,
            WorkspaceRoot::from_canonical(layout.workspace_root().to_path_buf())?,
            layout.root_fingerprint()?,
            timestamp(2)?,
        ),
    )?;
    drop(store);

    let control = ForgeControl::new(GlobalRegistry::open(&registry_path)?);
    let locator =
        WorkspaceLocator::new(location_id, LocationRevision::INITIAL, relative_workspace)?;
    let scope = control.resolve_workspace(location_id, LocationRevision::INITIAL, &locator)?;
    let admitted_at = timestamp_now()?;
    let lease_until = TimestampMillis::new(admitted_at.get() + 60_000)?;
    let _ = control
        .bootstrap_activity(&scope, activity_id, runtime_id, admitted_at, lease_until)
        .map_err(|error| std::io::Error::other(format!("bootstrap: {error:?}")))?;

    let (agent_id, session_id, actor) =
        setup_actor(&control, &scope, workspace_id, activity_id, serial)?;
    Ok(Fixture {
        root,
        workspace_root,
        control,
        scope,
        activity_id,
        runtime_instance_id: runtime_id,
        actor,
        agent_id,
        session_id,
    })
}

fn setup_actor(
    control: &ForgeControl,
    scope: &ResolvedWorkspaceScope,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    serial: u128,
) -> Result<(AgentInstanceId, AgentSessionId, ActivityCoordinatorActor), Box<dyn std::error::Error>>
{
    let session_id = AgentSessionId::from_uuid(Uuid::from_u128(0xD3_0500 + serial));
    let _ = control
        .agent_session_open(&OpenAgentSession::new(
            session_id,
            AgentSessionOpenRequestId::from_uuid(Uuid::from_u128(0xD3_0600 + serial)),
            AuthenticatedPrincipal::TrustedStdio,
            timestamp(5)?,
        ))
        .map_err(|error| std::io::Error::other(format!("session: {error:?}")))?;
    let agent_id = AgentInstanceId::from_uuid(Uuid::from_u128(0xD3_0700 + serial));
    let agent = RegisteredAgentInstance::create_bound(
        agent_id,
        workspace_id,
        activity_id,
        session_id,
        AgentDisplayName::new("Goal deletion test agent".to_owned())?,
        AgentDeclaredRole::new("coordinator".to_owned())?,
        AgentTransportKind::Retired,
        AuthenticatedPrincipal::TrustedStdio,
        timestamp(5)?,
    );
    let _ = crate::legacy_agent_fixture::seed_agent(
        control,
        scope,
        &agent,
        AgentEventId::from_uuid(Uuid::from_u128(0xD3_0800 + serial)),
    )
    .map_err(|error| std::io::Error::other(format!("attach: {error:?}")))?;
    let binding = control
        .activity_coordinator_claim(
            &crate::CoordinatorClaimRequest {
                session_id,
                scope: scope.clone(),
                activity_id,
                agent_id,
                principal: AuthenticatedPrincipal::TrustedStdio,
                observed_at: timestamp(6)?,
            },
            timestamp_now()?,
        )
        .map_err(|error| std::io::Error::other(format!("claim: {error:?}")))?;
    Ok((
        agent_id,
        session_id,
        ActivityCoordinatorActor::new(
            workspace_id,
            activity_id,
            agent_id,
            binding.revision(),
            AuthenticatedPrincipal::TrustedStdio,
            session_id,
        ),
    ))
}

fn goal(
    fixture: &Fixture,
    id: u128,
    created_at: TimestampMillis,
) -> Result<RegisteredGoal, Box<dyn std::error::Error>> {
    let goal = RegisteredGoal::create(
        GoalId::from_uuid(Uuid::from_u128(id)),
        fixture.scope.workspace_id(),
        fixture.activity_id,
        GoalContract::new(
            GoalObjective::new("Delete one bounded fixture Goal".to_owned())?,
            vec![GoalStatement::new(
                "The deletion closure is bounded".to_owned(),
            )?],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )?,
        created_at,
    );
    let stored = fixture
        .control
        .goal_create(&fixture.scope, fixture.actor, &goal, timestamp_now()?)
        .map_err(|error| std::io::Error::other(format!("goal create: {error:?}")))?;
    assert_eq!(stored, goal);
    Ok(goal)
}

fn delete_request(
    fixture: &Fixture,
    goal: &RegisteredGoal,
    target: GoalDeletionTarget,
    expected_head: Option<DagHeadRevision>,
) -> Result<GoalDeleteRequest, Box<dyn std::error::Error>> {
    Ok(GoalDeleteRequest::new(
        fixture.scope.clone(),
        GoalDeletionRequest::new(
            target,
            fixture.scope.workspace_id(),
            fixture.activity_id,
            goal.id(),
            goal.timestamps().created_at(),
            goal.revision(),
            expected_head,
        ),
        GoalDeletionAuthority::LocalOperator,
        TimestampMillis::new(40)?,
    ))
}

#[test]
fn sql_only_goal_delete_commits_and_has_no_cleanup_job() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture("sql-only")?;
    let goal = goal(&fixture, 0xD3_1000, timestamp(10)?)?;
    let pending = fixture.control.goal_delete_pending(&fixture.scope, 8)?;
    assert!(pending.summaries().is_empty());
    let request = delete_request(&fixture, &goal, GoalDeletionTarget::Goal, None)?;
    let outcome = fixture.control.goal_delete(&request, None)?;
    assert_eq!(outcome.phase(), GoalDeletePhase::Complete);
    assert_eq!(outcome.cleanup_id(), None);
    assert_eq!(outcome.next_goal_revision(), None);
    assert_eq!(
        fixture
            .control
            .goal_get(&fixture.scope, fixture.activity_id, goal.id())?,
        None
    );
    fs::remove_dir_all(fixture.root)?;
    Ok(())
}

#[test]
fn dag_only_delete_keeps_goal_and_advances_revision() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture("dag-only")?;
    let goal = goal(&fixture, 0xD3_1100, timestamp(10)?)?;
    seed_dag(&fixture, &goal)?;
    let request = delete_request(
        &fixture,
        &goal,
        GoalDeletionTarget::Dag,
        Some(DagHeadRevision::INITIAL),
    )?;
    let outcome = fixture
        .control
        .goal_delete(&request, Some(&fixture.root.join("product-cache")))?;
    assert_eq!(outcome.phase(), GoalDeletePhase::Complete);
    assert_eq!(outcome.cleanup_id(), None);
    assert_eq!(outcome.next_goal_revision(), Some(GoalRevision::new(2)?));
    let retained = fixture
        .control
        .goal_get(&fixture.scope, fixture.activity_id, goal.id())?
        .ok_or("DAG deletion removed Goal")?;
    assert_eq!(retained.revision(), GoalRevision::new(2)?);
    fs::remove_dir_all(fixture.root)?;
    Ok(())
}

#[test]
fn unknown_product_root_preserves_generated_artifact_and_resumes_with_exact_authority()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture("unknown-product-root")?;
    let authority = seed_source_writer(&fixture, 0xD3_7100, &["unused.rs"])?;
    let (execution, package) = seed_generated_package_for_cleanup(&fixture, authority)?;
    release_source_writer(&fixture, authority)?;
    let goal = fixture
        .control
        .goal_get(
            &fixture.scope,
            fixture.activity_id,
            authority.attribution().goal_id(),
        )?
        .ok_or("missing cleanup Goal")?;
    let request = delete_request(
        &fixture,
        &goal,
        GoalDeletionTarget::Goal,
        Some(DagHeadRevision::INITIAL),
    )?;
    let blocked = fixture.control.goal_delete(&request, None)?;
    assert_eq!(blocked.phase(), GoalDeletePhase::Blocked);
    assert_eq!(
        blocked.issue(),
        Some(GoalDeleteIssue::ProductCacheUnavailable)
    );
    assert_eq!(blocked.remaining_count(), 1);
    assert!(package.is_file());
    let pending = pending_readback(&fixture, request.target)?;
    let artifact = pending
        .artifacts()
        .iter()
        .find(|artifact| artifact.kind() == GoalDeletionArtifactKind::GeneratedPackage)
        .ok_or("missing retained package cleanup metadata")?;
    assert!(artifact.requires_filesystem());
    let bytes = fs::read(&package)?;
    assert_eq!(
        artifact.expected_hash(),
        Some(blake3::hash(&bytes).as_bytes().as_slice())
    );
    assert_eq!(artifact.expected_size(), Some(u64::try_from(bytes.len())?));
    let layout =
        WorkspaceStateLayout::inspect_existing(&fixture.workspace_root)?.ok_or("missing layout")?;
    let store = WorkspaceStore::open_existing(&layout)?;
    // Existing staging transfers metadata to the pending journal and removes
    // catalog rows. Root absence must preserve that journal and its file.
    assert_eq!(store.generated_package_manifest(execution)?, None);
    drop(store);
    // Simulate the known cache becoming unavailable without deleting it.
    let cache_root = fixture.root.join("product-cache");
    let parked = fixture.root.join("parked-product-cache");
    fs::rename(&cache_root, &parked)?;
    let unavailable = fixture.control.goal_delete(&request, Some(&cache_root))?;
    assert_eq!(unavailable.phase(), GoalDeletePhase::Blocked);
    assert_eq!(unavailable.remaining_count(), 1);
    assert!(
        pending_readback(&fixture, request.target)?
            .artifacts()
            .iter()
            .any(
                |artifact| artifact.kind() == GoalDeletionArtifactKind::GeneratedPackage
                    && artifact.requires_filesystem()
            )
    );
    fs::rename(&parked, &cache_root)?;
    assert!(package.is_file());
    let complete = fixture
        .control
        .goal_delete(&request, Some(&fixture.root.join("product-cache")))?;
    assert_eq!(complete.phase(), GoalDeletePhase::Complete);
    assert!(!package.exists());
    assert!(
        fixture
            .control
            .goal_delete_pending(&fixture.scope, 8)?
            .summaries()
            .is_empty()
    );
    let store = WorkspaceStore::open_existing(&layout)?;
    assert_eq!(store.generated_package_manifest(execution)?, None);
    drop(store);
    fs::remove_dir_all(fixture.root)?;
    Ok(())
}

/// Synthetic persistence fixture; this is cleanup authority proof, not a
/// compiler, package-build, or process-runtime success claim.
fn seed_generated_package_for_cleanup(
    fixture: &Fixture,
    authority: SourceWriteAuthority,
) -> Result<(forge_domain::ExecutionId, PathBuf), Box<dyn std::error::Error>> {
    use forge_domain::{
        BeginExecution, BoundedExecutionOutput, CompleteExecution, ExecutionAgentProvenance,
        ExecutionAttribution, ExecutionCommandId, ExecutionCompletionStatus, ExecutionId,
        ExecutionKind, ExecutionLimits, ExecutionOutcome, ExecutionOutputLimit,
        ExecutionPermissions, ExecutionRequest, ExecutionTermination, ExecutionTimeoutMillis,
        FileByteCount, GeneratedPackageManifest, MarkExecutionRunning,
        ProjectCommandCatalogFingerprint, ProjectCommandClass, ProjectCommandEvidence,
    };
    let execution = ExecutionId::from_uuid(Uuid::from_u128(0xD3_7200));
    let request = ExecutionRequest::new(
        ExecutionAttribution::new(execution, fixture.scope.workspace_id(), fixture.activity_id),
        ExecutionKind::Shell {
            script: forge_domain::ExecutionScript::new("true".to_owned())?,
        },
        None,
        ExecutionLimits::new(
            ExecutionTimeoutMillis::new(1_000)?,
            ExecutionOutputLimit::new(4_096)?,
        ),
        ExecutionPermissions::new(true, false, false),
    )?;
    let provenance = ExecutionAgentProvenance::new(
        execution,
        authority.agent_id(),
        authority.expected_agent_revision(),
        authority.principal(),
        authority.attribution(),
        ExecutionCommandId::new("make:package".to_owned())?,
        authority.session_id(),
    )
    .with_project_command(ProjectCommandEvidence::new(
        ProjectCommandClass::GeneratedPackage,
        ProjectCommandCatalogFingerprint::from_hash(FileContentHash::from_bytes([0x71; 32])),
    ));
    let begin = BeginExecution::from_request(
        &request,
        forge_execution::execution_request_digest(&request),
        timestamp(30)?,
    )
    .with_runtime_owner(fixture.runtime_instance_id)
    .with_provenance(provenance)?;
    let layout =
        WorkspaceStateLayout::inspect_existing(&fixture.workspace_root)?.ok_or("missing layout")?;
    let mut store = WorkspaceStore::open_existing(&layout)?;
    let started = store.begin_execution_for_goal(&begin, Some(authority.attribution().into()))?;
    let running = store.mark_execution_running(MarkExecutionRunning::new(
        execution,
        started.record().revision(),
        timestamp(31)?,
    ))?;
    let content = b"synthetic-package-cleanup-fixture";
    let hash = FileContentHash::from_bytes(*blake3::hash(content).as_bytes());
    let manifest = GeneratedPackageManifest::new(
        fixture.scope.workspace_id(),
        execution,
        hash,
        FileByteCount::new(u64::try_from(content.len())?),
    );
    let completed = store.complete_execution_with_generated_package(
        &CompleteExecution::new(
            running.revision(),
            timestamp(32)?,
            ExecutionOutcome::new(
                execution,
                ExecutionTermination::new(ExecutionCompletionStatus::Exited, Some(0), None),
                1,
                BoundedExecutionOutput::new(Vec::new(), 0, false),
                BoundedExecutionOutput::new(Vec::new(), 0, false),
            ),
        ),
        manifest,
    )?;
    assert_eq!(completed.state(), forge_domain::ExecutionState::Completed);
    assert_eq!(store.generated_package_manifest(execution)?, Some(manifest));
    drop(store);
    let output = prepare_cleanup_package_output(fixture, execution, &layout)?;
    fs::create_dir(output.root().join("dist"))?;
    let package = output.root().join("dist/Heterarchy-Forge.pkg");
    fs::write(&package, content)?;
    Ok((execution, package))
}

fn prepare_cleanup_package_output(
    fixture: &Fixture,
    execution: forge_domain::ExecutionId,
    layout: &forge_workspace::ExistingWorkspaceStateLayout,
) -> Result<forge_execution::RustCiGeneratedPackageOutput, Box<dyn std::error::Error>> {
    use forge_execution::{
        RustCiDiscoveryInput, RustCiHostArchitecture, RustCiToolchainCapability,
    };
    let host = fixture.root.join("synthetic-toolchain");
    for path in [
        ".cargo/bin",
        ".cargo/registry",
        ".rustup/toolchains/1.98.0-aarch64-apple-darwin",
    ] {
        fs::create_dir_all(host.join(path))?;
    }
    fs::write(host.join(".cargo/bin/rustup"), b"synthetic discovery only")?;
    fs::write(host.join(".rustup/settings.toml"), b"version = 12\n")?;
    let capability = RustCiToolchainCapability::prepare(&RustCiDiscoveryInput::new(
        fs::canonicalize(host)?,
        fixture.root.join("product-cache"),
        RustCiHostArchitecture::Aarch64,
        fixture.runtime_instance_id,
    )?)?;
    Ok(capability.ensure_generated_package_output(
        fixture.scope.workspace_id(),
        layout.root_fingerprint()?,
        execution,
    )?)
}

#[test]
fn scope_fence_and_active_writer_lease_reject_before_goal_mutation()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture("fences")?;
    let goal = goal(&fixture, 0xD3_1200, timestamp(10)?)?;
    let stale_scope = ResolvedWorkspaceScope::from_observation(
        fixture.scope.workspace_id(),
        WorkspaceRevision::new(2)?,
        fixture.scope.locator().clone(),
    );
    let stale_request = GoalDeleteRequest::new(
        stale_scope,
        GoalDeletionRequest::new(
            GoalDeletionTarget::Goal,
            fixture.scope.workspace_id(),
            fixture.activity_id,
            goal.id(),
            goal.timestamps().created_at(),
            goal.revision(),
            None,
        ),
        GoalDeletionAuthority::LocalOperator,
        timestamp(40)?,
    );
    let stale = fixture
        .control
        .goal_delete(&stale_request, Some(&fixture.root.join("product-cache")))
        .err()
        .ok_or("stale scope unexpectedly deleted Goal")?;
    assert_eq!(stale.code(), ControlErrorCode::WorkspaceRevisionConflict);

    let scope = WriterLeaseScope::new(vec![WriterLeaseScopeEntry::new(
        WriterLeaseScopeKind::ExactPath,
        WorkspaceRelativePath::new(PathBuf::from("held.txt"))?,
    )])?;
    let _ = fixture
        .control
        .writer_lease_acquire(&crate::WriterLeaseAcquireRequest {
            scope: fixture.scope.clone(),
            activity_id: fixture.activity_id,
            agent_id: fixture.agent_id,
            principal: AuthenticatedPrincipal::TrustedStdio,
            command: AcquireWriterLease::new(
                WriterLeaseId::from_uuid(Uuid::from_u128(0xD3_1201)),
                fixture.scope.workspace_id(),
                fixture.activity_id,
                fixture.agent_id,
                scope,
                WriterLeaseDurationMillis::MAX,
                timestamp(41)?,
                fixture.session_id,
                AuthenticatedPrincipal::TrustedStdio,
            )?,
        })?;
    let blocked = fixture
        .control
        .goal_delete(
            &delete_request(&fixture, &goal, GoalDeletionTarget::Goal, None)?,
            Some(&fixture.root.join("product-cache")),
        )
        .err()
        .ok_or("active Writer Lease did not block deletion")?;
    assert_ne!(blocked.code(), ControlErrorCode::CommittedButUnconfirmed);
    assert!(
        fixture
            .control
            .goal_get(&fixture.scope, fixture.activity_id, goal.id())?
            .is_some()
    );
    fs::remove_dir_all(fixture.root)?;
    Ok(())
}

fn seed_dag(fixture: &Fixture, goal: &RegisteredGoal) -> Result<(), Box<dyn std::error::Error>> {
    let definition = DagNodeDefinition::new(
        DagNodeId::from_uuid(Uuid::from_u128(0xD3_2001)),
        DagNodeOrdinal::new(0)?,
        DagNodeTitle::new("Delete node".to_owned())?,
        DagNodeObjective::new("Seed a DAG for deletion".to_owned())?,
        vec![DagAcceptanceCriterion::new(
            "The DAG is bounded".to_owned(),
        )?],
    )?;
    let revision = DagRevision::new(
        DagRevisionId::from_uuid(Uuid::from_u128(0xD3_2000)),
        goal.id(),
        goal.revision(),
        DagRevisionNumber::INITIAL,
        None,
        vec![definition.clone()],
        Vec::new(),
        timestamp(20)?,
    )?;
    let node = RegisteredDagNode::create(
        goal.id(),
        DagRevisionNumber::INITIAL,
        definition,
        timestamp(20)?,
    );
    let draft = AgentDagDraft::new(revision, vec![node], Vec::new())?;
    let request = AgentDagPlanRequest::new(
        AgentDagPlanRequestId::from_uuid(Uuid::from_u128(0xD3_2002)),
        fixture.actor,
        GoalAttribution::new(goal.id(), goal.revision()),
        None,
        None,
        draft,
        AgentWorkUpdateId::from_uuid(Uuid::from_u128(0xD3_2003)),
        AgentWorkUpdateSequence::INITIAL,
        timestamp(20)?,
    );
    let _ = fixture.control.agent_dag_plan_commit(
        &crate::AgentDagPlanCommitRequest {
            scope: fixture.scope.clone(),
            request,
        },
        timestamp_now()?,
    )?;
    Ok(())
}

fn workspace_root(fixture: &Fixture) -> PathBuf {
    fixture.workspace_root.clone()
}

#[derive(Clone, Copy)]
struct SourceWriterIdentity {
    seed: u128,
    observed_at: TimestampMillis,
    principal: AuthenticatedPrincipal,
    session_id: AgentSessionId,
    agent_id: AgentInstanceId,
}

impl SourceWriterIdentity {
    fn new(seed: u128, observed_at: TimestampMillis) -> Self {
        Self {
            seed,
            observed_at,
            principal: AuthenticatedPrincipal::TrustedStdio,
            session_id: AgentSessionId::from_uuid(Uuid::from_u128(seed + 100)),
            agent_id: AgentInstanceId::from_uuid(Uuid::from_u128(seed + 1)),
        }
    }
}

fn seed_source_goal(
    fixture: &Fixture,
    identity: SourceWriterIdentity,
) -> Result<RegisteredGoal, Box<dyn std::error::Error>> {
    let goal = RegisteredGoal::create(
        GoalId::from_uuid(Uuid::from_u128(identity.seed + 2)),
        fixture.scope.workspace_id(),
        fixture.activity_id,
        GoalContract::new(
            GoalObjective::new("Authorize Goal deletion source mutation".to_owned())?,
            vec![GoalStatement::new(
                "The source mutation remains revision fenced".to_owned(),
            )?],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )?,
        identity.observed_at,
    );
    let _ = fixture
        .control
        .goal_create(&fixture.scope, fixture.actor, &goal, timestamp_now()?)?;
    Ok(goal)
}

fn seed_source_agent(
    fixture: &Fixture,
    identity: SourceWriterIdentity,
) -> Result<(), Box<dyn std::error::Error>> {
    let _ = fixture.control.agent_session_open(&OpenAgentSession::new(
        identity.session_id,
        AgentSessionOpenRequestId::from_uuid(Uuid::from_u128(identity.seed + 101)),
        identity.principal,
        identity.observed_at,
    ))?;
    let _ = crate::legacy_agent_fixture::seed_agent(
        &fixture.control,
        &fixture.scope,
        &RegisteredAgentInstance::create_bound(
            identity.agent_id,
            fixture.scope.workspace_id(),
            fixture.activity_id,
            identity.session_id,
            AgentDisplayName::new("Goal deletion source writer".to_owned())?,
            AgentDeclaredRole::new("source-writer".to_owned())?,
            AgentTransportKind::Stdio,
            identity.principal,
            identity.observed_at,
        ),
        AgentEventId::from_uuid(Uuid::from_u128(identity.seed + 102)),
    )?;
    Ok(())
}

fn seed_source_active_node(
    fixture: &Fixture,
    identity: SourceWriterIdentity,
    goal: &RegisteredGoal,
) -> Result<RegisteredDagNode, Box<dyn std::error::Error>> {
    let definition = DagNodeDefinition::new(
        DagNodeId::from_uuid(Uuid::from_u128(identity.seed + 3)),
        DagNodeOrdinal::new(0)?,
        DagNodeTitle::new("Mutate source".to_owned())?,
        DagNodeObjective::new("Apply one exact source mutation".to_owned())?,
        vec![DagAcceptanceCriterion::new(
            "The source mutation is durably evidenced".to_owned(),
        )?],
    )?;
    let revision = DagRevision::new(
        DagRevisionId::from_uuid(Uuid::from_u128(identity.seed + 4)),
        goal.id(),
        goal.revision(),
        DagRevisionNumber::INITIAL,
        None,
        vec![definition.clone()],
        Vec::new(),
        identity.observed_at,
    )?;
    let node = RegisteredDagNode::create(
        goal.id(),
        DagRevisionNumber::INITIAL,
        definition,
        identity.observed_at,
    );
    let _ = fixture.control.agent_dag_plan_commit(
        &crate::AgentDagPlanCommitRequest {
            scope: fixture.scope.clone(),
            request: AgentDagPlanRequest::new(
                AgentDagPlanRequestId::from_uuid(Uuid::from_u128(identity.seed + 5)),
                fixture.actor,
                GoalAttribution::new(goal.id(), goal.revision()),
                None,
                None,
                AgentDagDraft::new(revision, vec![node.clone()], Vec::new())?,
                AgentWorkUpdateId::from_uuid(Uuid::from_u128(identity.seed + 6)),
                AgentWorkUpdateSequence::INITIAL,
                identity.observed_at,
            ),
        },
        timestamp_now()?,
    )?;
    Ok(fixture.control.dag_node_start(
        &crate::DagNodeStartRequest {
            scope: fixture.scope.clone(),
            activity_id: fixture.activity_id,
            session_id: identity.session_id,
            principal: identity.principal,
            goal_id: goal.id(),
            expected_goal_revision: goal.revision(),
            expected_dag_revision: node.dag_revision(),
            node_id: node.id(),
            expected_revision: node.revision(),
            observed_at: identity.observed_at,
        },
        timestamp_now()?,
    )?)
}

fn seed_source_authority(
    fixture: &Fixture,
    identity: SourceWriterIdentity,
    goal: &RegisteredGoal,
    active: &RegisteredDagNode,
    exact_paths: &[&str],
) -> Result<SourceWriteAuthority, Box<dyn std::error::Error>> {
    let focused = fixture.control.agent_set_focus(
        &crate::AgentFocusRequest {
            scope: fixture.scope.clone(),
            activity_id: fixture.activity_id,
            actor: fixture.actor,
            agent_id: identity.agent_id,
            expected_revision: AgentInstanceRevision::INITIAL,
            focus: AgentFocus::new(
                Some(GoalAttribution::new(goal.id(), goal.revision())),
                Some(active.dag_revision()),
                Some(AgentFocusNode::new(active.id(), active.revision())),
            )?,
            observed_at: identity.observed_at,
        },
        timestamp_now()?,
    )?;
    let lease_scope = WriterLeaseScope::new(
        exact_paths
            .iter()
            .map(|path| {
                WorkspaceRelativePath::new(PathBuf::from(path))
                    .map(|path| WriterLeaseScopeEntry::new(WriterLeaseScopeKind::ExactPath, path))
            })
            .collect::<Result<Vec<_>, _>>()?,
    )?;
    let lease = fixture
        .control
        .writer_lease_acquire(&crate::WriterLeaseAcquireRequest {
            scope: fixture.scope.clone(),
            activity_id: fixture.activity_id,
            agent_id: identity.agent_id,
            principal: identity.principal,
            command: AcquireWriterLease::new(
                WriterLeaseId::from_uuid(Uuid::from_u128(identity.seed + 7)),
                fixture.scope.workspace_id(),
                fixture.activity_id,
                identity.agent_id,
                lease_scope,
                WriterLeaseDurationMillis::MAX,
                identity.observed_at,
                identity.session_id,
                identity.principal,
            )?,
        })?;
    Ok(SourceWriteAuthority::new(
        focused.id(),
        focused.revision(),
        identity.principal,
        GoalNodeAttribution::new(
            goal.id(),
            goal.revision(),
            active.dag_revision(),
            active.id(),
            active.revision(),
        ),
        lease.id(),
        lease.revision(),
        identity.session_id,
    ))
}

fn seed_source_writer(
    fixture: &Fixture,
    seed: u128,
    exact_paths: &[&str],
) -> Result<SourceWriteAuthority, Box<dyn std::error::Error>> {
    let identity = SourceWriterIdentity::new(seed, timestamp(20)?);
    let goal = seed_source_goal(fixture, identity)?;
    seed_source_agent(fixture, identity)?;
    let active = seed_source_active_node(fixture, identity, &goal)?;
    seed_source_authority(fixture, identity, &goal, &active, exact_paths)
}

#[derive(Clone, Copy)]
struct SourceUpdate<'a> {
    goal: GoalWorkAttribution,
    path: &'a str,
    before: &'a [u8],
    after: &'a [u8],
    change_set_id: ChangeSetId,
    mutation_id: FileMutationId,
}

impl<'a> SourceUpdate<'a> {
    fn new(
        goal: GoalWorkAttribution,
        path: &'a str,
        before: &'a [u8],
        after: &'a [u8],
        change_set_seed: u128,
        mutation_seed: u128,
    ) -> Self {
        Self {
            goal,
            path,
            before,
            after,
            change_set_id: ChangeSetId::from_uuid(Uuid::from_u128(change_set_seed)),
            mutation_id: FileMutationId::from_uuid(Uuid::from_u128(mutation_seed)),
        }
    }
}

fn apply_source_update(
    fixture: &Fixture,
    authority: SourceWriteAuthority,
    update: SourceUpdate<'_>,
) -> Result<DiffId, Box<dyn std::error::Error>> {
    let whole_file_hash = *blake3::hash(update.before).as_bytes();
    let request = FileApplyPatchRequest {
        scope: fixture.scope.clone(),
        activity: FileActivityScope {
            activity_id: fixture.activity_id,
            runtime_instance_id: fixture.runtime_instance_id,
            observed_at: timestamp(20)?,
        },
        goal: Some(update.goal),
        write_authority: authority,
        change_set_id: update.change_set_id,
        mutation_id: update.mutation_id,
        operation: FileApplyPatchOperation::Update {
            path: WorkspaceRelativePath::new(PathBuf::from(update.path))?,
            patch: FilePatch::new(
                FileContentHash::from_bytes(whole_file_hash),
                vec![FilePatchHunk::new(
                    SourceLineRange::new(1, 1)?,
                    SourceRangeHash::from_bytes(whole_file_hash),
                    update.after.to_vec(),
                )?],
            )?,
        },
    };
    let result = fixture.control.file_apply_patch(&request)?;
    assert_eq!(result.status(), FileMutationStatus::Applied);
    assert_eq!(
        fs::read(workspace_root(fixture).join(update.path))?,
        update.after
    );

    let diff_id = DiffId::for_change_set(request.change_set_id);
    let diff = fixture.control.diff_read(&DiffReadRequest {
        scope: fixture.scope.clone(),
        diff_id,
    })?;
    assert_eq!(diff.evidence().state(), DiffEvidenceState::Ready);
    assert_eq!(diff.health(), DiffArtifactHealth::Available);
    Ok(diff_id)
}

fn diff_artifact(
    fixture: &Fixture,
    diff_id: DiffId,
) -> Result<(PathBuf, [u8; FileContentHash::BYTE_LEN], u64), Box<dyn std::error::Error>> {
    let diff = fixture.control.diff_read(&DiffReadRequest {
        scope: fixture.scope.clone(),
        diff_id,
    })?;
    assert_eq!(diff.evidence().state(), DiffEvidenceState::Ready);
    assert_eq!(diff.health(), DiffArtifactHealth::Available);
    let DiffPayloadProjection::Ready {
        relative_path,
        compressed_hash,
        compressed_size,
        ..
    } = diff.evidence().payload()
    else {
        return Err("source update did not publish a filesystem Diff artifact".into());
    };
    let layout = WorkspaceStateLayout::inspect_existing(workspace_root(fixture))?
        .ok_or("missing initialized Workspace state layout")?;
    Ok((
        layout.state_root().join(relative_path.as_path()),
        compressed_hash.into_bytes(),
        compressed_size.get(),
    ))
}

fn release_source_writer(
    fixture: &Fixture,
    authority: SourceWriteAuthority,
) -> Result<(), Box<dyn std::error::Error>> {
    let released = fixture
        .control
        .writer_lease_release(&WriterLeaseReleaseRequest {
            scope: fixture.scope.clone(),
            activity_id: fixture.activity_id,
            principal: AuthenticatedPrincipal::TrustedStdio,
            command: ReleaseWriterLease::new(
                authority.writer_lease_id(),
                authority.agent_id(),
                authority.expected_writer_lease_revision(),
                timestamp(30)?,
                authority.session_id(),
                AuthenticatedPrincipal::TrustedStdio,
            ),
        })?;
    assert_eq!(released.id(), authority.writer_lease_id());
    assert_eq!(released.state(), WriterLeaseState::Released);
    assert_eq!(released.status(timestamp(30)?), WriterLeaseStatus::Released);
    Ok(())
}

fn pending_readback(
    fixture: &Fixture,
    request: GoalDeletionRequest,
) -> Result<forge_persistence::GoalDeletionCleanupReadback, Box<dyn std::error::Error>> {
    let layout = WorkspaceStateLayout::inspect_existing(workspace_root(fixture))?
        .ok_or("missing initialized Workspace state layout")?;
    let root_fingerprint = layout.root_fingerprint()?;
    let gate = WorkspaceStateExclusiveGate::acquire(layout.workspace_root(), root_fingerprint)?;
    let store = WorkspaceStore::open_goal_deletion(&layout, &gate)?;
    store
        .pending_for_request(request)?
        .ok_or_else(|| "expected pending Goal deletion readback".into())
}

#[derive(Clone, Copy)]
struct OwnedDeleteEvidence<'a> {
    source_goal: &'a RegisteredGoal,
    other_goal: &'a RegisteredGoal,
    owned_diff: DiffId,
    other_diff: DiffId,
    owned_artifact: &'a Path,
    other_artifact: &'a Path,
}

fn assert_owned_delete_projection(
    fixture: &Fixture,
    evidence: OwnedDeleteEvidence<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let root = workspace_root(fixture);
    assert_eq!(fs::read(root.join("src/owned.rs"))?, b"owned-after\n");
    assert_eq!(fs::read(root.join("src/other.rs"))?, b"other-after\n");
    assert!(!evidence.owned_artifact.exists());
    assert!(evidence.other_artifact.is_file());
    assert!(
        fixture
            .control
            .goal_get(
                &fixture.scope,
                fixture.activity_id,
                evidence.source_goal.id(),
            )?
            .is_none()
    );
    assert!(
        fixture
            .control
            .goal_get(
                &fixture.scope,
                fixture.activity_id,
                evidence.other_goal.id()
            )?
            .is_some()
    );
    assert_eq!(
        fixture
            .control
            .diff_read(&DiffReadRequest {
                scope: fixture.scope.clone(),
                diff_id: evidence.owned_diff,
            })
            .err()
            .map(|error| error.code()),
        Some(ControlErrorCode::DiffNotFound)
    );
    let preserved = fixture.control.diff_read(&DiffReadRequest {
        scope: fixture.scope.clone(),
        diff_id: evidence.other_diff,
    })?;
    assert_eq!(preserved.health(), DiffArtifactHealth::Available);
    assert!(
        preserved
            .content()
            .is_some_and(|content| content.contains("other-after"))
    );
    let listed = fixture.control.diff_list(&DiffListRequest {
        scope: fixture.scope.clone(),
        activity_id: fixture.activity_id,
        limit: DiffListLimit::new(8)?,
    })?;
    assert_eq!(listed.diffs().len(), 1);
    assert_eq!(listed.diffs()[0].id(), evidence.other_diff);
    Ok(())
}

fn assert_pending_cleanup(
    fixture: &Fixture,
    request: GoalDeletionRequest,
    blocked: GoalDeleteOutcome,
    expected_root: forge_domain::WorkspaceRootFingerprint,
    compressed_hash: [u8; FileContentHash::BYTE_LEN],
    compressed_size: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let cleanup_id = blocked
        .cleanup_id()
        .ok_or("blocked Goal deletion did not retain cleanup identity")?;
    let pending = fixture.control.goal_delete_pending(&fixture.scope, 8)?;
    assert_eq!(pending.summaries().len(), 1);
    assert_eq!(pending.summaries()[0].cleanup_id(), cleanup_id);
    assert_eq!(pending.summaries()[0].request(), request);
    assert_eq!(pending.summaries()[0].remaining(), 1);
    let readback = pending_readback(fixture, request)?;
    assert_eq!(readback.cleanup_id(), cleanup_id);
    assert_eq!(readback.request(), request);
    assert_eq!(readback.root_fingerprint(), expected_root);
    let artifact = readback
        .artifacts()
        .iter()
        .find(|artifact| artifact.kind() == GoalDeletionArtifactKind::DiffCompressed)
        .ok_or("pending Diff artifact was not read back")?;
    assert_eq!(artifact.expected_hash(), Some(compressed_hash.as_slice()));
    assert_eq!(artifact.expected_size(), Some(compressed_size));
    assert!(artifact.relative_path().is_some());
    Ok(())
}

#[test]
fn goal_delete_removes_owned_source_diff_but_preserves_source_bytes_and_other_goal_evidence()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture("source-owned-closure")?;
    let root = workspace_root(&fixture);
    fs::create_dir_all(root.join("src"))?;
    fs::write(root.join("src/owned.rs"), b"owned-before\n")?;
    fs::write(root.join("src/other.rs"), b"other-before\n")?;

    let authority = seed_source_writer(&fixture, 0xD3_4000, &["src/owned.rs", "src/other.rs"])
        .map_err(|error| std::io::Error::other(format!("seed source writer: {error:?}")))?;
    let source_goal = fixture
        .control
        .goal_get(
            &fixture.scope,
            fixture.activity_id,
            authority.attribution().goal_id(),
        )?
        .ok_or("source writer Goal was not persisted")?;
    let other_goal = goal(&fixture, 0xD3_4100, timestamp(19)?)?;

    let owned_diff = apply_source_update(
        &fixture,
        authority,
        SourceUpdate::new(
            GoalWorkAttribution::from(authority.attribution()),
            "src/owned.rs",
            b"owned-before\n",
            b"owned-after\n",
            0xD3_4200,
            0xD3_4201,
        ),
    )
    .map_err(|error| std::io::Error::other(format!("owned source update: {error:?}")))?;
    let other_diff = apply_source_update(
        &fixture,
        authority,
        SourceUpdate::new(
            GoalWorkAttribution::from(GoalAttribution::new(other_goal.id(), other_goal.revision())),
            "src/other.rs",
            b"other-before\n",
            b"other-after\n",
            0xD3_4300,
            0xD3_4301,
        ),
    )
    .map_err(|error| std::io::Error::other(format!("other source update: {error:?}")))?;
    let (owned_artifact, _, _) = diff_artifact(&fixture, owned_diff)?;
    let (other_artifact, _, _) = diff_artifact(&fixture, other_diff)?;
    assert!(owned_artifact.is_file());
    assert!(other_artifact.is_file());

    // The source authority intentionally exercised an active node, exact focus,
    // and exact-path Writer Lease for both real mutations. Goal deletion is
    // admitted only after the owner explicitly releases that lease.
    release_source_writer(&fixture, authority)
        .map_err(|error| std::io::Error::other(format!("release source writer: {error:?}")))?;
    let request = delete_request(
        &fixture,
        &source_goal,
        GoalDeletionTarget::Goal,
        Some(DagHeadRevision::INITIAL),
    )?;
    let outcome = fixture
        .control
        .goal_delete(&request, Some(&fixture.root.join("product-cache")))
        .map_err(|error| {
            std::io::Error::other(format!(
                "owned Goal delete: {error:?}; source={:?}",
                std::error::Error::source(&error)
            ))
        })?;
    assert_eq!(outcome.phase(), GoalDeletePhase::Complete);
    assert!(outcome.cleanup_id().is_some());
    assert_eq!(outcome.remaining_count(), 0);
    assert_owned_delete_projection(
        &fixture,
        OwnedDeleteEvidence {
            source_goal: &source_goal,
            other_goal: &other_goal,
            owned_diff,
            other_diff,
            owned_artifact: &owned_artifact,
            other_artifact: &other_artifact,
        },
    )?;
    fs::remove_dir_all(fixture.root)?;
    Ok(())
}

#[test]
fn interrupted_goal_cleanup_reads_back_hash_and_root_fences_then_resumes_after_reopen()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture("source-cleanup-recovery")?;
    let root = workspace_root(&fixture);
    fs::create_dir_all(root.join("src"))?;
    fs::write(root.join("src/recovery.rs"), b"recovery-before\n")?;

    let authority =
        seed_source_writer(&fixture, 0xD3_5000, &["src/recovery.rs"]).map_err(|error| {
            std::io::Error::other(format!("seed recovery source writer: {error:?}"))
        })?;
    let source_goal = fixture
        .control
        .goal_get(
            &fixture.scope,
            fixture.activity_id,
            authority.attribution().goal_id(),
        )?
        .ok_or("source writer Goal was not persisted")?;
    let diff_id = apply_source_update(
        &fixture,
        authority,
        SourceUpdate::new(
            GoalWorkAttribution::from(authority.attribution()),
            "src/recovery.rs",
            b"recovery-before\n",
            b"recovery-after\n",
            0xD3_5200,
            0xD3_5201,
        ),
    )
    .map_err(|error| std::io::Error::other(format!("recovery source update: {error:?}")))?;
    let (artifact_path, compressed_hash, compressed_size) = diff_artifact(&fixture, diff_id)?;
    let original_artifact = fs::read(&artifact_path)?;
    let layout = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("missing layout")?;
    let expected_root = layout.root_fingerprint()?;
    release_source_writer(&fixture, authority).map_err(|error| {
        std::io::Error::other(format!("release recovery source writer: {error:?}"))
    })?;

    // A substituted payload must leave the durable Goal deletion journal
    // pending; cleanup cannot prove ownership of bytes with the wrong hash.
    fs::write(&artifact_path, b"corrupt cleanup payload")?;
    let request = delete_request(
        &fixture,
        &source_goal,
        GoalDeletionTarget::Goal,
        Some(DagHeadRevision::INITIAL),
    )?;
    let blocked = fixture
        .control
        .goal_delete(&request, Some(&fixture.root.join("product-cache")))
        .map_err(|error| {
            std::io::Error::other(format!(
                "blocked Goal delete: {error:?}; source={:?}",
                std::error::Error::source(&error)
            ))
        })?;
    assert_eq!(blocked.phase(), GoalDeletePhase::Blocked);
    assert_eq!(blocked.issue(), Some(GoalDeleteIssue::Filesystem));
    assert_eq!(blocked.remaining_count(), 1);
    assert_eq!(fs::read(&artifact_path)?, b"corrupt cleanup payload");

    assert_pending_cleanup(
        &fixture,
        request.target,
        blocked,
        expected_root,
        compressed_hash,
        compressed_size,
    )?;

    fs::write(&artifact_path, &original_artifact)?;
    let reopened = ForgeControl::new(GlobalRegistry::open(fixture.root.join("registry.sqlite3"))?);
    let resumed = reopened.goal_delete(&request, Some(&fixture.root.join("product-cache")))?;
    assert_eq!(resumed.phase(), GoalDeletePhase::Complete);
    assert_eq!(resumed.remaining_count(), 0);
    assert!(
        reopened
            .goal_delete_pending(&fixture.scope, 8)?
            .summaries()
            .is_empty()
    );
    assert_eq!(fs::read(root.join("src/recovery.rs"))?, b"recovery-after\n");
    assert!(!artifact_path.exists());
    assert!(
        reopened
            .goal_get(&fixture.scope, fixture.activity_id, source_goal.id())?
            .is_none()
    );
    assert_eq!(
        reopened
            .diff_read(&DiffReadRequest {
                scope: fixture.scope.clone(),
                diff_id,
            })
            .err()
            .map(|error| error.code()),
        Some(ControlErrorCode::DiffNotFound)
    );
    let reopened_layout = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("missing layout")?;
    assert_eq!(reopened_layout.root_fingerprint()?, expected_root);
    fs::remove_dir_all(fixture.root)?;
    Ok(())
}

/// Prepare isolated, deliberately blocked state for manual native GUI acceptance.
/// This is a fixture initializer, not a passing recovery test; the ordinary
/// recovery test above remains mandatory and always verifies complete cleanup.
#[test]
#[ignore = "explicit native GUI fixture initializer; leaves only its printed temporary root"]
fn native_goal_deletion_recovery_fixture() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture_with_relative_workspace("native-gui-recovery", Path::new("."))?;
    let root = workspace_root(&fixture);
    fs::write(root.join("native.rs"), b"before\n")?;
    let authority = seed_source_writer(&fixture, 0xD3_6000, &["native.rs"])?;
    let source_goal = fixture
        .control
        .goal_get(
            &fixture.scope,
            fixture.activity_id,
            authority.attribution().goal_id(),
        )?
        .ok_or("native fixture Goal missing")?;
    let diff_id = apply_source_update(
        &fixture,
        authority,
        SourceUpdate::new(
            GoalWorkAttribution::from(authority.attribution()),
            "native.rs",
            b"before\n",
            b"after\n",
            0xD3_6200,
            0xD3_6201,
        ),
    )?;
    let (artifact, _, _) = diff_artifact(&fixture, diff_id)?;
    fs::write(fixture.root.join("original.diff.zst"), fs::read(&artifact)?)?;
    fs::write(&artifact, b"blocked native acceptance fixture")?;
    release_source_writer(&fixture, authority)?;
    let request = delete_request(
        &fixture,
        &source_goal,
        GoalDeletionTarget::Goal,
        Some(DagHeadRevision::INITIAL),
    )?;
    let blocked = fixture
        .control
        .goal_delete(&request, Some(&fixture.root.join("product-cache")))?;
    assert_eq!(blocked.phase(), GoalDeletePhase::Blocked);
    assert_eq!(blocked.remaining_count(), 1);
    println!("NATIVE_FIXTURE_ROOT={}", fixture.root.display());
    println!("NATIVE_FIXTURE_ARTIFACT={}", artifact.display());
    println!("NATIVE_FIXTURE_ACTIVITY={}", fixture.activity_id);
    Ok(())
}
