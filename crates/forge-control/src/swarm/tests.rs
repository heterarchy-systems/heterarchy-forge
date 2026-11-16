use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use forge_domain::{
    ActivityCoordinatorActor, ActivityId, AgentDeclaredRole, AgentDisplayName, AgentInstanceId,
    AgentSessionId, AgentSessionOpenRequestId, AgentTransportKind, AuthenticatedPrincipal,
    DagAcceptanceCriterion, DagNodeDefinition, DagNodeId, DagNodeObjective, DagNodeOrdinal,
    DagNodeRevision, DagNodeTitle, DagRevision, DagRevisionId, DagRevisionNumber,
    EstablishWorkspace, GoalAttribution, GoalContract, GoalId, GoalObjective, GoalStatement,
    LocationId, LocationRevision, OpenAgentSession, RegisteredDagNode, RegisteredGoal,
    RuntimeInstanceId, SwarmMemberId, SwarmRunId, SwarmSettlementTarget, SwarmWorkspaceMode,
    TimestampMillis, WorkspaceId, WorkspaceRoot,
};
use forge_persistence::{AgentOperationsFreezeRequest, EffectFact, GlobalRegistry, WorkspaceStore};
use forge_workspace::{
    LocationService, SettlementJournalState, SwarmConvergenceOutcome, WorkspaceLocator,
    WorkspaceStateLayout,
};
use uuid::Uuid;

use super::{
    MAX_SWARM_CONVERGENCE_CANDIDATES, SwarmConvergeRequest, SwarmConvergenceCandidate,
    SwarmMaterializeHybridRequest, SwarmMemberCaptureRequest, SwarmPurgeRequest,
    SwarmSettleRequest, SwarmSettlementGetRequest, SwarmWorkspaceGetRequest,
    SwarmWorkspaceProvisionRequest,
};
use crate::{
    AgentDagPlanCommitRequest, AgentOperationsDelegationRequest, AgentSessionResolveRequest,
    ControlErrorCode, CoordinatorClaimRequest, DagNodeCompleteRequest, DagNodeStartRequest,
    DagSettleRequest, EffectFactOutboxReadRequest, ForgeControl, ForgeControlClient,
    ForgeControlWorker, ResolvedWorkspaceScope,
};

static NEXT_TEST_SEQ: AtomicU64 = AtomicU64::new(1);

struct SwarmTestEnv {
    root: PathBuf,
    workspace_root: PathBuf,
    registry_path: PathBuf,
    location_id: LocationId,
}

impl SwarmTestEnv {
    fn new(label: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let seq = NEXT_TEST_SEQ.fetch_add(1, Ordering::Relaxed);
        // Must remain outside /Volumes/256.SSD/RustBuild so Forge path_policy accepts
        // both node_worktrees_root and swarm_worktrees_root under /var/tmp.
        let root = PathBuf::from(format!(
            "/var/tmp/heterarchy-forge-swarm-ctl-{label}-{}-{seq}",
            std::process::id()
        ));
        fs::create_dir_all(&root)?;
        let location_root = root.join("location");
        let workspace_root = location_root.join("workspace-0");
        fs::create_dir_all(&workspace_root)?;

        let registry_path = root.join("registry.sqlite3");
        let location_id = LocationId::from_uuid(id(0xF100 + u128::from(seq)));
        let mut locations = LocationService::new(GlobalRegistry::open(&registry_path)?);
        let location = locations.register_selected_path(
            location_id,
            "Swarm Control Test Location",
            &location_root,
            ts(1)?,
        )?;
        drop(locations);

        let layout = WorkspaceStateLayout::initialize(&workspace_root)?;
        let canonical_ws_root =
            WorkspaceRoot::from_canonical(layout.workspace_root().to_path_buf())?;
        let workspace_id = WorkspaceId::from_uuid(id(0xF200 + u128::from(seq)));
        let _store = WorkspaceStore::open(
            &layout,
            EstablishWorkspace::new(
                workspace_id,
                location.id(),
                canonical_ws_root,
                layout.root_fingerprint()?,
                ts(2)?,
            ),
        )?;
        Ok(Self {
            root,
            workspace_root,
            registry_path,
            location_id,
        })
    }

    fn start_worker(
        &self,
    ) -> Result<(ForgeControlClient, ForgeControlWorker), Box<dyn std::error::Error>> {
        let control = ForgeControl::new(GlobalRegistry::open(&self.registry_path)?);
        Ok(ForgeControlWorker::start(control)?)
    }

    fn locator(
        &self,
        client: &ForgeControlClient,
    ) -> Result<WorkspaceLocator, Box<dyn std::error::Error>> {
        let entries = client.workspace_discover(self.location_id, LocationRevision::INITIAL)?;
        let entry = entries
            .into_iter()
            .find(|entry| entry.display_name() == "workspace-0")
            .ok_or("workspace-0 missing in location")?;
        Ok(entry.locator().clone())
    }
}

impl Drop for SwarmTestEnv {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

struct SwarmActorHarness {
    env: SwarmTestEnv,
    client: ForgeControlClient,
    worker: ForgeControlWorker,
    scope: ResolvedWorkspaceScope,
    activity_id: ActivityId,
    coordinator_id: AgentInstanceId,
    session_id: AgentSessionId,
    principal: AuthenticatedPrincipal,
    actor: ActivityCoordinatorActor,
}

impl SwarmActorHarness {
    fn start(label: &str, seed: u128) -> Result<Self, Box<dyn std::error::Error>> {
        let env = SwarmTestEnv::new(label)?;
        fs::write(
            env.workspace_root.join("shared.txt"),
            "line1\nline2\nline3\nline4\nline5\n",
        )?;
        let (client, worker) = env.start_worker()?;
        let locator = env.locator(&client)?;
        let scope =
            client.resolve_workspace(env.location_id, LocationRevision::INITIAL, locator)?;
        let lease_until = ts(now_ts()?.get() + 600_000)?;
        let activity_id = ActivityId::from_uuid(id(seed + 1));
        let _activity = client.bootstrap_activity(
            scope.clone(),
            activity_id,
            RuntimeInstanceId::from_uuid(id(seed + 2)),
            ts(1)?,
            lease_until,
        )?;
        let coordinator_id = AgentInstanceId::from_uuid(id(seed + 3));
        let (session_id, principal, actor) =
            open_stdio_session_coordinator(&client, &scope, activity_id, coordinator_id, ts(2)?)?;
        Ok(Self {
            env,
            client,
            worker,
            scope,
            activity_id,
            coordinator_id,
            session_id,
            principal,
            actor,
        })
    }

    fn provision(
        &self,
        swarm_run_id: SwarmRunId,
        member_id: SwarmMemberId,
        mode: SwarmWorkspaceMode,
        target: SwarmSettlementTarget,
        observed_at_ms: i64,
    ) -> Result<forge_workspace::SwarmWorkspaceReceipt, Box<dyn std::error::Error>> {
        Ok(self
            .client
            .swarm_workspace_provision(SwarmWorkspaceProvisionRequest {
                scope: self.scope.clone(),
                session_id: self.session_id,
                principal: self.principal,
                swarm_run_id,
                member_id,
                mode,
                target,
                candidate_commit_oid: None,
                observed_at: ts(observed_at_ms)?,
            })?)
    }

    fn capture(
        &self,
        swarm_run_id: SwarmRunId,
        member_id: SwarmMemberId,
        captured_at: TimestampMillis,
    ) -> Result<forge_workspace::SwarmMemberOutputReceipt, crate::ControlClientError> {
        self.client.swarm_member_capture(SwarmMemberCaptureRequest {
            scope: self.scope.clone(),
            session_id: self.session_id,
            principal: self.principal,
            swarm_run_id,
            member_id,
            captured_at,
        })
    }
}

fn id(seed: u128) -> Uuid {
    Uuid::from_u128(0x0000_0000_0000_4000_8000_0000_0000_0000 | seed)
}

fn ts(ms: i64) -> Result<TimestampMillis, Box<dyn std::error::Error>> {
    Ok(TimestampMillis::new(ms)?)
}

fn now_ts() -> Result<TimestampMillis, Box<dyn std::error::Error>> {
    let millis = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
    Ok(TimestampMillis::new(i64::try_from(millis)?)?)
}

fn delegate_workspace(
    h: &SwarmActorHarness,
    seed: u128,
) -> Result<forge_persistence::AgentOperationsDelegation, Box<dyn std::error::Error>> {
    let layout = WorkspaceStateLayout::inspect_existing(&h.env.workspace_root)?
        .ok_or("workspace layout missing")?;
    let mut store = WorkspaceStore::open_existing(&layout)?;
    let freeze = store.freeze_agent_operations(&AgentOperationsFreezeRequest::new(
        id(seed + 1),
        id(seed + 2),
        ts(10)?,
    )?)?;
    drop(store);
    Ok(h.client
        .delegate_agent_operations(AgentOperationsDelegationRequest {
            scope: h.scope.clone(),
            freeze,
            manifest_digest: [0xAB; 32],
            observed_at: ts(11)?,
        })?)
}

fn open_stdio_session_coordinator(
    client: &ForgeControlClient,
    scope: &ResolvedWorkspaceScope,
    activity_id: ActivityId,
    agent_id: AgentInstanceId,
    observed_at: TimestampMillis,
) -> Result<
    (
        AgentSessionId,
        AuthenticatedPrincipal,
        ActivityCoordinatorActor,
    ),
    Box<dyn std::error::Error>,
> {
    let session_id = AgentSessionId::from_uuid(agent_id.into_uuid());
    let principal = AuthenticatedPrincipal::TrustedStdio;
    let _session = client.agent_session_open(OpenAgentSession::new(
        session_id,
        AgentSessionOpenRequestId::from_uuid(id(agent_id
            .into_uuid()
            .as_u128()
            .wrapping_add(0x500))),
        principal,
        observed_at,
    ))?;
    let agent = forge_domain::RegisteredAgentInstance::create_bound(
        agent_id,
        scope.workspace_id(),
        activity_id,
        session_id,
        AgentDisplayName::new("Swarm Coordinator".to_owned())?,
        AgentDeclaredRole::new("coordinator".to_owned())?,
        AgentTransportKind::Stdio,
        principal,
        observed_at,
    );
    let _ = crate::legacy_agent_fixture::seed_client_agent(
        client,
        scope,
        &agent,
        forge_domain::AgentEventId::from_uuid(agent_id.into_uuid()),
    )?;
    let binding = client.activity_coordinator_claim(CoordinatorClaimRequest {
        session_id,
        scope: scope.clone(),
        activity_id,
        agent_id,
        principal,
        observed_at,
    })?;
    let actor = ActivityCoordinatorActor::new(
        scope.workspace_id(),
        activity_id,
        binding.agent_id(),
        binding.revision(),
        principal,
        session_id,
    );
    Ok((session_id, principal, actor))
}

fn verify_inherit_read_only_guards(
    h: &SwarmActorHarness,
    swarm_run_id: SwarmRunId,
    inherit_id: SwarmMemberId,
) -> Result<(), Box<dyn std::error::Error>> {
    let inherit_receipt = h.provision(
        swarm_run_id,
        inherit_id,
        SwarmWorkspaceMode::Inherit,
        SwarmSettlementTarget::StandaloneSwarm,
        20,
    )?;
    let _clean = h.capture(swarm_run_id, inherit_id, ts(23)?)?;
    let inherit_converge_err = h
        .client
        .swarm_converge(SwarmConvergeRequest {
            scope: h.scope.clone(),
            session_id: h.session_id,
            principal: h.principal,
            swarm_run_id,
            candidates: vec![SwarmConvergenceCandidate {
                member_id: inherit_id,
                expected_output_commit_oid: None,
                expected_diff_digest: None,
            }],
            observed_at: ts(24)?,
        })
        .err()
        .ok_or("Inherit member must not be allowed in convergence")?;
    assert_eq!(inherit_converge_err.code(), ControlErrorCode::DagConflict);

    fs::write(
        inherit_receipt.worktree_path().join("shared.txt"),
        "mutated\n",
    )?;
    let inherit_mut_err = h
        .capture(swarm_run_id, inherit_id, ts(25)?)
        .err()
        .ok_or("mutated Inherit view must fail capture")?;
    assert_eq!(inherit_mut_err.code(), ControlErrorCode::DagConflict);
    Ok(())
}

fn verify_settle_replay_and_purge(
    h: &SwarmActorHarness,
    delegation: &forge_persistence::AgentOperationsDelegation,
    swarm_run_id: SwarmRunId,
    share_receipt: &forge_workspace::SwarmWorkspaceReceipt,
    branch_worktree: &Path,
    converged_commit_oid: &str,
    converged_diff_digest: [u8; 32],
) -> Result<(), Box<dyn std::error::Error>> {
    let settlement_id = id(0x5E01);
    let settle_req = |sid, settled_at| SwarmSettleRequest {
        scope: h.scope.clone(),
        activity_id: Some(h.activity_id),
        session_id: h.session_id,
        principal: h.principal,
        coordinator_agent_id: h.coordinator_id,
        swarm_run_id,
        settlement_id: sid,
        converged_commit_oid: converged_commit_oid.to_owned(),
        expected_diff_digest: Some(converged_diff_digest),
        settled_at,
    };
    let settled = h.client.swarm_settle(settle_req(settlement_id, ts(40)?))?;
    assert_eq!(settled.receipt.state(), SettlementJournalState::Applied);
    assert_eq!(settled.outbox_sequence, Some(1));
    assert_eq!(
        fs::read_to_string(h.env.workspace_root.join("shared.txt"))?,
        "line1-share\nline2\nline3\nline4\nline5-branch\n"
    );

    let generic_facts = h.client.effect_fact_outbox(EffectFactOutboxReadRequest {
        scope: h.scope.clone(),
        migration_id: delegation.migration_id(),
        destination_id: delegation.destination_id(),
        after: 0,
        limit: 16,
    })?;
    assert_eq!(generic_facts.len(), 1);
    assert!(matches!(
        generic_facts[0].fact(),
        EffectFact::SwarmSettled(fact)
            if fact.swarm_run_id() == swarm_run_id && fact.settlement_id() == settlement_id
    ));
    assert_eq!(
        h.client.swarm_settle(settle_req(settlement_id, ts(41)?))?,
        settled
    );
    let replay_conflict = h
        .client
        .swarm_settle(settle_req(id(0x5E99), ts(42)?))
        .err()
        .ok_or("mismatched settlement_id must conflict")?;
    assert_eq!(
        replay_conflict.code(),
        ControlErrorCode::AgentDagReplayConflict
    );

    let view_before = h.client.swarm_settlement_get(SwarmSettlementGetRequest {
        scope: h.scope.clone(),
        swarm_run_id,
    })?;
    assert_eq!(view_before.receipt.as_ref(), Some(&settled.receipt));

    h.client.swarm_purge(SwarmPurgeRequest {
        scope: h.scope.clone(),
        session_id: h.session_id,
        principal: h.principal,
        swarm_run_id,
    })?;
    assert!(!share_receipt.worktree_path().exists() && !branch_worktree.exists());
    assert!(
        h.client
            .swarm_workspace_get(SwarmWorkspaceGetRequest {
                scope: h.scope.clone(),
                swarm_run_id,
                member_id: share_receipt.member_id(),
            })?
            .is_none()
    );
    let view_after = h.client.swarm_settlement_get(SwarmSettlementGetRequest {
        scope: h.scope.clone(),
        swarm_run_id,
    })?;
    assert!(view_after.receipt.is_none());
    assert_eq!(
        view_after
            .outbox_entry
            .map(forge_persistence::SwarmSettledOutboxEntry::sequence),
        Some(1)
    );
    Ok(())
}

#[test]
fn standalone_swarm_lifecycle_settles_outbox_and_survives_purge()
-> Result<(), Box<dyn std::error::Error>> {
    let mut h = SwarmActorHarness::start("standalone", 0xE100)?;
    let delegation = delegate_workspace(&h, 0xD100)?;
    let swarm_run_id = SwarmRunId::from_uuid(id(0x5A01));
    let share_id = SwarmMemberId::from_uuid(id(0x5B02));
    let branch_id = SwarmMemberId::from_uuid(id(0x5B03));

    verify_inherit_read_only_guards(&h, swarm_run_id, SwarmMemberId::from_uuid(id(0x5B01)))?;
    let share_receipt = h.provision(
        swarm_run_id,
        share_id,
        SwarmWorkspaceMode::Share,
        SwarmSettlementTarget::StandaloneSwarm,
        21,
    )?;
    let branch_receipt = h.provision(
        swarm_run_id,
        branch_id,
        SwarmWorkspaceMode::Branch,
        SwarmSettlementTarget::StandaloneSwarm,
        22,
    )?;
    assert!(
        !share_receipt
            .worktree_path()
            .starts_with(&h.env.workspace_root)
    );
    assert!(
        !branch_receipt
            .worktree_path()
            .starts_with(&h.env.workspace_root)
    );
    assert_eq!(
        h.client.swarm_workspace_get(SwarmWorkspaceGetRequest {
            scope: h.scope.clone(),
            swarm_run_id,
            member_id: share_id,
        })?,
        Some(share_receipt.clone())
    );

    fs::write(
        share_receipt.worktree_path().join("shared.txt"),
        "line1-share\nline2\nline3\nline4\nline5\n",
    )?;
    fs::write(
        branch_receipt.worktree_path().join("shared.txt"),
        "line1\nline2\nline3\nline4\nline5-branch\n",
    )?;
    let share_out = h.capture(swarm_run_id, share_id, ts(30)?)?;
    let branch_out = h.capture(swarm_run_id, branch_id, ts(31)?)?;
    let SwarmConvergenceOutcome::Converged {
        converged_commit_oid,
        converged_diff_digest,
        ..
    } = h.client.swarm_converge(SwarmConvergeRequest {
        scope: h.scope.clone(),
        session_id: h.session_id,
        principal: h.principal,
        swarm_run_id,
        candidates: vec![
            SwarmConvergenceCandidate {
                member_id: share_id,
                expected_output_commit_oid: Some(share_out.output_commit_oid().to_owned()),
                expected_diff_digest: Some(share_out.diff_digest()),
            },
            SwarmConvergenceCandidate {
                member_id: branch_id,
                expected_output_commit_oid: Some(branch_out.output_commit_oid().to_owned()),
                expected_diff_digest: Some(branch_out.diff_digest()),
            },
        ],
        observed_at: ts(32)?,
    })?
    else {
        return Err("expected Converged outcome".into());
    };

    verify_settle_replay_and_purge(
        &h,
        &delegation,
        swarm_run_id,
        &share_receipt,
        branch_receipt.worktree_path(),
        &converged_commit_oid,
        converged_diff_digest,
    )?;
    h.worker.shutdown()?;
    Ok(())
}

fn create_active_hybrid_dag_node(
    h: &SwarmActorHarness,
) -> Result<
    (
        RegisteredGoal,
        RegisteredDagNode,
        forge_workspace::NodeWorkspaceReceipt,
    ),
    Box<dyn std::error::Error>,
> {
    let goal = RegisteredGoal::create(
        GoalId::from_uuid(id(0xA201)),
        h.scope.workspace_id(),
        h.activity_id,
        GoalContract::new(
            GoalObjective::new("Hybrid Swarm DAG".to_owned())?,
            vec![GoalStatement::new(
                "Node A settled via Hybrid Swarm".to_owned(),
            )?],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )?,
        ts(3)?,
    );
    let _ = h
        .client
        .goal_create(h.scope.clone(), h.actor, goal.clone())?;
    let node_a_id = DagNodeId::from_uuid(id(0xA202));
    let def_a = DagNodeDefinition::new(
        node_a_id,
        DagNodeOrdinal::new(0)?,
        DagNodeTitle::new("Node A".to_owned())?,
        DagNodeObjective::new("Execute hybrid swarm".to_owned())?,
        vec![DagAcceptanceCriterion::new("Node A converged".to_owned())?],
    )?;
    let dag_rev = DagRevisionNumber::INITIAL;
    let revision = DagRevision::new(
        DagRevisionId::from_uuid(id(0xA203)),
        goal.id(),
        goal.revision(),
        dag_rev,
        None,
        vec![def_a.clone()],
        Vec::new(),
        ts(4)?,
    )?;
    let nodes = vec![RegisteredDagNode::create(goal.id(), dag_rev, def_a, ts(4)?)];
    let draft = forge_domain::AgentDagDraft::new(revision, nodes, Vec::new())?;
    let plan_request = forge_domain::AgentDagPlanRequest::new(
        forge_domain::AgentDagPlanRequestId::from_uuid(id(0xA204)),
        h.actor,
        GoalAttribution::new(goal.id(), goal.revision()),
        None,
        None,
        draft,
        forge_domain::AgentWorkUpdateId::from_uuid(id(0xA205)),
        forge_domain::AgentWorkUpdateSequence::INITIAL,
        ts(4)?,
    );
    let _committed = h.client.agent_dag_plan_commit(AgentDagPlanCommitRequest {
        scope: h.scope.clone(),
        request: plan_request,
    })?;
    let active_a = h.client.dag_node_start(DagNodeStartRequest {
        scope: h.scope.clone(),
        activity_id: h.activity_id,
        session_id: h.session_id,
        principal: h.principal,
        goal_id: goal.id(),
        expected_goal_revision: goal.revision(),
        expected_dag_revision: dag_rev,
        node_id: node_a_id,
        expected_revision: DagNodeRevision::INITIAL,
        observed_at: ts(5)?,
    })?;
    let node_receipt = h
        .client
        .dag_node_workspace(h.scope.clone(), goal.id(), dag_rev, node_a_id)?
        .ok_or("node A workspace missing")?;
    assert!(
        !node_receipt
            .worktree_path()
            .starts_with(&h.env.workspace_root)
    );
    Ok((goal, active_a, node_receipt))
}

fn complete_and_settle_hybrid_dag_node(
    h: &SwarmActorHarness,
    goal: &RegisteredGoal,
    active_a: &RegisteredDagNode,
    dag_rev: DagRevisionNumber,
) -> Result<(), Box<dyn std::error::Error>> {
    let _done_a = h.client.dag_node_complete(DagNodeCompleteRequest {
        scope: h.scope.clone(),
        activity_id: h.activity_id,
        session_id: h.session_id,
        principal: h.principal,
        goal_id: goal.id(),
        expected_goal_revision: goal.revision(),
        expected_dag_revision: dag_rev,
        node_id: active_a.id(),
        expected_revision: active_a.revision(),
        observed_at: ts(26)?,
    })?;
    let _dag_settled = h.client.dag_settle(DagSettleRequest {
        scope: h.scope.clone(),
        activity_id: h.activity_id,
        session_id: h.session_id,
        principal: h.principal,
        goal_id: goal.id(),
        expected_goal_revision: goal.revision(),
        expected_dag_revision: dag_rev,
        settlement_id: id(0xA299),
        observed_at: ts(27)?,
    })?;
    assert_eq!(
        fs::read_to_string(h.env.workspace_root.join("shared.txt"))?,
        "line1-h1\nline2\nline3\nline4\nline5-h2\n"
    );
    Ok(())
}

#[test]
fn hybrid_dag_materialization_settles_via_dag_node() -> Result<(), Box<dyn std::error::Error>> {
    let mut h = SwarmActorHarness::start("hybrid", 0xE200)?;
    let (goal, active_a, node_receipt) = create_active_hybrid_dag_node(&h)?;
    let dag_rev = DagRevisionNumber::INITIAL;
    let hybrid_run_id = SwarmRunId::from_uuid(id(0x5C01));
    let m1 = SwarmMemberId::from_uuid(id(0x5C11));
    let m2 = SwarmMemberId::from_uuid(id(0x5C12));
    let target = SwarmSettlementTarget::DagNodeHybrid {
        goal_id: goal.id(),
        dag_revision: dag_rev,
        node_id: active_a.id(),
    };
    let r1 = h.provision(hybrid_run_id, m1, SwarmWorkspaceMode::Share, target, 20)?;
    let r2 = h.provision(hybrid_run_id, m2, SwarmWorkspaceMode::Branch, target, 21)?;
    fs::write(
        r1.worktree_path().join("shared.txt"),
        "line1-h1\nline2\nline3\nline4\nline5\n",
    )?;
    fs::write(
        r2.worktree_path().join("shared.txt"),
        "line1\nline2\nline3\nline4\nline5-h2\n",
    )?;
    let _ = h.capture(hybrid_run_id, m1, ts(22)?)?;
    let _ = h.capture(hybrid_run_id, m2, ts(23)?)?;
    let SwarmConvergenceOutcome::Converged {
        converged_commit_oid,
        converged_diff_digest,
        ..
    } = h.client.swarm_converge(SwarmConvergeRequest {
        scope: h.scope.clone(),
        session_id: h.session_id,
        principal: h.principal,
        swarm_run_id: hybrid_run_id,
        candidates: vec![
            SwarmConvergenceCandidate {
                member_id: m1,
                expected_output_commit_oid: None,
                expected_diff_digest: None,
            },
            SwarmConvergenceCandidate {
                member_id: m2,
                expected_output_commit_oid: None,
                expected_diff_digest: None,
            },
        ],
        observed_at: ts(24)?,
    })?
    else {
        return Err("hybrid convergence should succeed".into());
    };

    let hybrid_settled = h
        .client
        .swarm_materialize_hybrid(SwarmMaterializeHybridRequest {
            scope: h.scope.clone(),
            activity_id: h.activity_id,
            session_id: h.session_id,
            principal: h.principal,
            swarm_run_id: hybrid_run_id,
            settlement_id: id(0x5C55),
            goal_id: goal.id(),
            expected_goal_revision: goal.revision(),
            expected_dag_revision: dag_rev,
            node_id: active_a.id(),
            converged_commit_oid,
            expected_diff_digest: Some(converged_diff_digest),
            settled_at: ts(25)?,
        })?;
    assert_eq!(hybrid_settled.state(), SettlementJournalState::Applied);
    assert_eq!(
        fs::read_to_string(node_receipt.worktree_path().join("shared.txt"))?,
        "line1-h1\nline2\nline3\nline4\nline5-h2\n"
    );
    assert_eq!(
        fs::read_to_string(h.env.workspace_root.join("shared.txt"))?,
        "line1\nline2\nline3\nline4\nline5\n"
    );
    complete_and_settle_hybrid_dag_node(&h, &goal, &active_a, dag_rev)?;
    h.worker.shutdown()?;
    Ok(())
}

#[test]
fn conflicting_convergence_returns_conflict() -> Result<(), Box<dyn std::error::Error>> {
    let mut h = SwarmActorHarness::start("conflict", 0xE300)?;
    let conflict_run = SwarmRunId::from_uuid(id(0x5D01));
    let cm1 = SwarmMemberId::from_uuid(id(0x5D11));
    let cm2 = SwarmMemberId::from_uuid(id(0x5D12));
    let cr1 = h.provision(
        conflict_run,
        cm1,
        SwarmWorkspaceMode::Share,
        SwarmSettlementTarget::StandaloneSwarm,
        30,
    )?;
    let cr2 = h.provision(
        conflict_run,
        cm2,
        SwarmWorkspaceMode::Branch,
        SwarmSettlementTarget::StandaloneSwarm,
        31,
    )?;
    fs::write(
        cr1.worktree_path().join("shared.txt"),
        "line1-conflict-a\nline2\nline3\nline4\nline5\n",
    )?;
    fs::write(
        cr2.worktree_path().join("shared.txt"),
        "line1-conflict-b\nline2\nline3\nline4\nline5\n",
    )?;
    let _ = h.capture(conflict_run, cm1, ts(32)?)?;
    let _ = h.capture(conflict_run, cm2, ts(33)?)?;
    let conflict_outcome = h.client.swarm_converge(SwarmConvergeRequest {
        scope: h.scope.clone(),
        session_id: h.session_id,
        principal: h.principal,
        swarm_run_id: conflict_run,
        candidates: vec![
            SwarmConvergenceCandidate {
                member_id: cm1,
                expected_output_commit_oid: None,
                expected_diff_digest: None,
            },
            SwarmConvergenceCandidate {
                member_id: cm2,
                expected_output_commit_oid: None,
                expected_diff_digest: None,
            },
        ],
        observed_at: ts(34)?,
    })?;
    assert!(matches!(
        conflict_outcome,
        SwarmConvergenceOutcome::Conflict { conflicting_member_id, .. }
            if conflicting_member_id == cm2
    ));
    h.worker.shutdown()?;
    Ok(())
}

#[test]
fn invalid_swarm_control_inputs_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let mut h = SwarmActorHarness::start("invalid-inputs", 0xE310)?;
    let conflict_run = SwarmRunId::from_uuid(id(0x5D02));

    let bad_oid_err = h
        .client
        .swarm_workspace_provision(SwarmWorkspaceProvisionRequest {
            scope: h.scope.clone(),
            session_id: h.session_id,
            principal: h.principal,
            swarm_run_id: conflict_run,
            member_id: SwarmMemberId::from_uuid(id(0x5D13)),
            mode: SwarmWorkspaceMode::Inherit,
            target: SwarmSettlementTarget::StandaloneSwarm,
            candidate_commit_oid: Some("../bad-oid".to_owned()),
            observed_at: ts(35)?,
        })
        .err()
        .ok_or("malformed OID must fail")?;
    assert_eq!(bad_oid_err.code(), ControlErrorCode::InvalidInput);

    let wrong_session_err = h
        .client
        .swarm_workspace_provision(SwarmWorkspaceProvisionRequest {
            scope: h.scope.clone(),
            session_id: AgentSessionId::from_uuid(id(0x9999)),
            principal: h.principal,
            swarm_run_id: conflict_run,
            member_id: SwarmMemberId::from_uuid(id(0x5D14)),
            mode: SwarmWorkspaceMode::Inherit,
            target: SwarmSettlementTarget::StandaloneSwarm,
            candidate_commit_oid: None,
            observed_at: ts(36)?,
        })
        .err()
        .ok_or("unknown session must fail")?;
    assert_eq!(
        wrong_session_err.code(),
        ControlErrorCode::AgentSessionNotFound
    );

    let too_many = (0..=MAX_SWARM_CONVERGENCE_CANDIDATES)
        .map(|i| SwarmConvergenceCandidate {
            member_id: SwarmMemberId::from_uuid(id(0x6000 + i as u128)),
            expected_output_commit_oid: None,
            expected_diff_digest: None,
        })
        .collect();
    let oversized_err = h
        .client
        .swarm_converge(SwarmConvergeRequest {
            scope: h.scope.clone(),
            session_id: h.session_id,
            principal: h.principal,
            swarm_run_id: conflict_run,
            candidates: too_many,
            observed_at: ts(37)?,
        })
        .err()
        .ok_or("oversized candidates must fail")?;
    assert_eq!(oversized_err.code(), ControlErrorCode::InvalidInput);
    h.worker.shutdown()?;
    Ok(())
}

#[test]
fn forbidden_ssd_worktree_root_and_closed_session_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    struct ClosedSessionAuthority;
    impl crate::AgentSessionAuthority for ClosedSessionAuthority {
        fn open(
            &self,
            _request: &OpenAgentSession,
        ) -> Result<forge_domain::AgentSessionOpenOutcome, crate::ControlError> {
            Err(crate::ControlError::new(
                ControlErrorCode::AgentSessionConflict,
            ))
        }

        fn resolve(
            &self,
            request: AgentSessionResolveRequest,
        ) -> Result<Option<forge_domain::RegisteredAgentSession>, crate::ControlError> {
            let t1 = ts(1).map_err(|_| crate::ControlError::new(ControlErrorCode::Internal))?;
            let t2 = ts(2).map_err(|_| crate::ControlError::new(ControlErrorCode::Internal))?;
            let open = forge_domain::RegisteredAgentSession::open(
                request.session_id,
                AgentSessionOpenRequestId::from_uuid(id(0x7001)),
                request.principal,
                t1,
            );
            let closed = open
                .close(forge_domain::AgentSessionRevision::INITIAL, t2)
                .map_err(|_| crate::ControlError::new(ControlErrorCode::Internal))?;
            Ok(Some(closed))
        }
    }
    let env = SwarmTestEnv::new("guards")?;

    let control = ForgeControl::with_session_authority(
        LocationService::new(GlobalRegistry::open(&env.registry_path)?),
        Box::new(ClosedSessionAuthority),
    )
    .with_swarm_worktrees_root(
        Path::new("/Volumes/256.SSD/RustBuild/forge/bad-swarm").to_path_buf(),
    );
    let locator = control
        .workspace_discover(env.location_id, LocationRevision::INITIAL)?
        .into_iter()
        .find(|entry| entry.display_name() == "workspace-0")
        .ok_or("workspace-0 missing")?
        .locator()
        .clone();
    let scope = control.resolve_workspace(env.location_id, LocationRevision::INITIAL, &locator)?;
    let session_id = AgentSessionId::from_uuid(id(0x7101));
    let err = control
        .swarm_workspace_provision(&SwarmWorkspaceProvisionRequest {
            scope: scope.clone(),
            session_id,
            principal: AuthenticatedPrincipal::TrustedStdio,
            swarm_run_id: SwarmRunId::from_uuid(id(0x7201)),
            member_id: SwarmMemberId::from_uuid(id(0x7202)),
            mode: SwarmWorkspaceMode::Share,
            target: SwarmSettlementTarget::StandaloneSwarm,
            candidate_commit_oid: None,
            observed_at: ts(10)?,
        })
        .err()
        .ok_or("closed session must reject swarm_workspace_provision")?;
    assert_eq!(err.code(), ControlErrorCode::AgentSessionClosed);

    let ssd_control = ForgeControl::new(GlobalRegistry::open(&env.registry_path)?)
        .with_swarm_worktrees_root(
            Path::new("/Volumes/256.SSD/RustBuild/forge/bad-swarm").to_path_buf(),
        );
    let _ = ssd_control.agent_session_open(&OpenAgentSession::new(
        session_id,
        AgentSessionOpenRequestId::from_uuid(id(0x7102)),
        AuthenticatedPrincipal::TrustedStdio,
        ts(10)?,
    ))?;
    let ssd_err = ssd_control
        .swarm_workspace_provision(&SwarmWorkspaceProvisionRequest {
            scope,
            session_id,
            principal: AuthenticatedPrincipal::TrustedStdio,
            swarm_run_id: SwarmRunId::from_uuid(id(0x7201)),
            member_id: SwarmMemberId::from_uuid(id(0x7202)),
            mode: SwarmWorkspaceMode::Share,
            target: SwarmSettlementTarget::StandaloneSwarm,
            candidate_commit_oid: None,
            observed_at: ts(11)?,
        })
        .err()
        .ok_or("SSD root must be rejected")?;
    assert_eq!(ssd_err.code(), ControlErrorCode::InvalidInput);
    Ok(())
}

fn seed_bound_worker(
    h: &SwarmActorHarness,
    worker_id: AgentInstanceId,
    worker_session: AgentSessionId,
    observed_at: TimestampMillis,
) -> Result<(), Box<dyn std::error::Error>> {
    let _ = h.client.agent_session_open(OpenAgentSession::new(
        worker_session,
        AgentSessionOpenRequestId::from_uuid(id(worker_id.into_uuid().as_u128() ^ 0x4444)),
        h.principal,
        observed_at,
    ))?;
    let worker_agent = forge_domain::RegisteredAgentInstance::create_bound(
        worker_id,
        h.scope.workspace_id(),
        h.activity_id,
        worker_session,
        AgentDisplayName::new("Non-coordinator worker".to_owned())?,
        AgentDeclaredRole::new("worker".to_owned())?,
        AgentTransportKind::Stdio,
        h.principal,
        observed_at,
    );
    let _ = crate::legacy_agent_fixture::seed_client_agent(
        &h.client,
        &h.scope,
        &worker_agent,
        forge_domain::AgentEventId::from_uuid(worker_id.into_uuid()),
    )?;
    Ok(())
}

#[test]
fn swarm_settle_requires_registered_attached_coordinator_even_without_activity_id()
-> Result<(), Box<dyn std::error::Error>> {
    let mut h = SwarmActorHarness::start("settle-auth", 0xE400)?;
    let swarm_run_id = SwarmRunId::from_uuid(id(0x5E51));
    let member_id = SwarmMemberId::from_uuid(id(0x5E52));
    let receipt = h.provision(
        swarm_run_id,
        member_id,
        SwarmWorkspaceMode::Share,
        SwarmSettlementTarget::StandaloneSwarm,
        20,
    )?;
    fs::write(
        receipt.worktree_path().join("shared.txt"),
        "line1-auth\nline2\nline3\nline4\nline5\n",
    )?;
    let _out = h.capture(swarm_run_id, member_id, ts(21)?)?;
    let SwarmConvergenceOutcome::Converged {
        converged_commit_oid,
        converged_diff_digest,
        ..
    } = h.client.swarm_converge(SwarmConvergeRequest {
        scope: h.scope.clone(),
        session_id: h.session_id,
        principal: h.principal,
        swarm_run_id,
        candidates: vec![SwarmConvergenceCandidate {
            member_id,
            expected_output_commit_oid: None,
            expected_diff_digest: None,
        }],
        observed_at: ts(22)?,
    })?
    else {
        return Err("expected converged outcome".into());
    };

    // Unregistered coordinator UUID must fail closed even when activity_id is None.
    let missing_err = h
        .client
        .swarm_settle(SwarmSettleRequest {
            scope: h.scope.clone(),
            activity_id: None,
            session_id: h.session_id,
            principal: h.principal,
            coordinator_agent_id: AgentInstanceId::from_uuid(id(0x9991)),
            swarm_run_id,
            settlement_id: id(0x5E61),
            converged_commit_oid: converged_commit_oid.clone(),
            expected_diff_digest: Some(converged_diff_digest),
            settled_at: ts(23)?,
        })
        .err()
        .ok_or("unregistered coordinator_agent_id must fail")?;
    assert_eq!(missing_err.code(), ControlErrorCode::AgentNotFound);

    // Non-coordinator attached agent on the same Activity must also fail closed.
    let worker_id = AgentInstanceId::from_uuid(id(0x9992));
    let worker_session = AgentSessionId::from_uuid(worker_id.into_uuid());
    seed_bound_worker(&h, worker_id, worker_session, ts(24)?)?;
    let non_coord_err = h
        .client
        .swarm_settle(SwarmSettleRequest {
            scope: h.scope.clone(),
            activity_id: Some(h.activity_id),
            session_id: worker_session,
            principal: h.principal,
            coordinator_agent_id: worker_id,
            swarm_run_id,
            settlement_id: id(0x5E62),
            converged_commit_oid: converged_commit_oid.clone(),
            expected_diff_digest: Some(converged_diff_digest),
            settled_at: ts(25)?,
        })
        .err()
        .ok_or("non-coordinator agent must fail swarm_settle")?;
    assert_eq!(non_coord_err.code(), ControlErrorCode::CoordinatorConflict);

    // Valid registered attached Coordinator succeeds with activity_id: None.
    let settled = h.client.swarm_settle(SwarmSettleRequest {
        scope: h.scope.clone(),
        activity_id: None,
        session_id: h.session_id,
        principal: h.principal,
        coordinator_agent_id: h.coordinator_id,
        swarm_run_id,
        settlement_id: id(0x5E63),
        converged_commit_oid,
        expected_diff_digest: Some(converged_diff_digest),
        settled_at: ts(26)?,
    })?;
    assert_eq!(settled.receipt.state(), SettlementJournalState::Applied);
    h.worker.shutdown()?;
    Ok(())
}
