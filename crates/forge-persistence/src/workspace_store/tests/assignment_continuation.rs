//! Durable Assignment-continuation behavior at the `WorkspaceStore` boundary.

use super::*;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[test]
fn schema_v54_adds_empty_continuation_journal_without_changing_held_work_cut() -> TestResult {
    let f = ContinuationFixture::new("continuation-v54", 0xD800, false)?;
    let ContinuationFixture {
        root,
        layout,
        store,
        source,
        cut,
        ..
    } = f;
    drop(store);
    let database = layout.database_path();
    let connection = Connection::open(&database)?;
    downgrade_admission_identity(&connection)?;
    connection.pragma_update(None, "journal_mode", "DELETE")?;
    remove_continuation_schema(&connection)?;
    connection.pragma_update(
        None,
        "user_version",
        PREVIOUS_WORK_CUT_CONTINUATIONS_SCHEMA_VERSION,
    )?;
    drop(connection);
    let existing =
        WorkspaceStateLayout::inspect_existing(layout.workspace_root())?.ok_or("layout missing")?;
    assert!(matches!(
        WorkspaceStore::inspect_existing_read_only(&existing),
        Err(WorkspaceStoreError::OutdatedSchema {
            actual: PREVIOUS_WORK_CUT_CONTINUATIONS_SCHEMA_VERSION,
            current: CURRENT_SCHEMA_VERSION
        })
    ));
    let store = WorkspaceStore::open_existing(&existing)?;
    assert_eq!(store.health()?.schema_version(), CURRENT_SCHEMA_VERSION);
    assert_eq!(
        store.get_leadership_work_cut(cut.request().cut_id())?,
        Some(cut)
    );
    assert_eq!(store.get_agent_assignment(source.id())?, Some(source));
    for (kind, name) in crate::workspace_work_cuts::continuation_schema_objects()
        .into_iter()
        .filter(|(kind, _)| *kind == "table")
    {
        let count: i64 =
            store
                .connection
                .query_row(&format!("SELECT COUNT(*) FROM {name}"), [], |row| {
                    row.get(0)
                })?;
        assert_eq!(count, 0, "migration must not invent rows in {kind} {name}");
    }
    drop(store);
    fs::remove_dir_all(root)?;
    Ok(())
}

struct ContinuationFixture {
    root: PathBuf,
    layout: WorkspaceStateLayout,
    store: WorkspaceStore,
    source: forge_domain::RegisteredAgentAssignment,
    request: forge_domain::WorkCutRequest,
    cut: crate::WorkCutRecord,
    issuer: forge_domain::OrchestrationIssuerId,
    recipient: forge_domain::AgentAssignmentTarget,
    plan: forge_domain::AgentAssignmentContinuationPlan,
}

fn running_source(
    store: &mut WorkspaceStore,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
) -> TestResult<forge_domain::RegisteredAgentAssignment> {
    let offered = seed_assignment_for_offer_seal_migration(store, workspace_id, activity_id)?;
    let interrupted =
        store.interrupt_agent_assignment(&forge_domain::InterruptAgentAssignment::new(
            offered.id(),
            offered.revision(),
            timestamp(8)?,
        ))?;
    assert_eq!(
        interrupted.state(),
        forge_domain::AgentAssignmentState::Interrupted
    );
    let offered =
        store.offer_agent_assignment(&offer_from(&offered, aid(0xD810), 9)?, timestamp(99)?)?;
    let source = store.claim_agent_assignment(
        &forge_domain::ClaimAgentAssignment::new(
            offered.id(),
            offered.target(),
            offered.revision(),
            timestamp(10)?,
        ),
        timestamp(99)?,
    )?;
    Ok(source)
}

fn continuation_scope(
    store: &WorkspaceStore,
    source: &forge_domain::RegisteredAgentAssignment,
    team: bool,
) -> TestResult<forge_domain::WorkCutScope> {
    if !team {
        return Ok(forge_domain::WorkCutScope::Workspace);
    }
    let dag = store
        .get_dag_revision(source.goal_id(), source.dag_revision())?
        .ok_or("DAG missing")?;
    let node = forge_domain::WorkCutNodeScope::new(
        source.activity_id(),
        source.goal_id(),
        source.goal_created_at(),
        dag.revision().base_goal_revision(),
        source.dag_revision(),
        source.node_id(),
    )?;
    Ok(forge_domain::WorkCutScope::Team {
        team_id: Uuid::from_u128(0xD801),
        nodes: vec![node],
    })
}

impl ContinuationFixture {
    fn new(label: &str, seed: u128, team: bool) -> TestResult<Self> {
        let (root, layout, mut store, activity_id) = store_with_live_activity(label)?;
        let workspace_id = store.workspace()?.id();
        let source = running_source(&mut store, workspace_id, activity_id)?;
        let coordinator = source.coordinator();
        let coordinator_agent = store
            .get_agent(coordinator.agent_id())?
            .ok_or("continuation Coordinator disappeared")?;
        let source_agent = store
            .get_agent(source.target().agent_id())?
            .ok_or("continuation source Agent disappeared")?;
        let (coordinator_session, coordinator_binding) =
            inventory_endpoint(&coordinator_agent, forge_domain::WorkCutSide::Incumbent)?;
        let (source_session, source_binding) =
            inventory_endpoint(&source_agent, forge_domain::WorkCutSide::Elected)?;
        let delegation = install_delegation_seal(&mut store, seed + 0x80, 20)?;
        let request = work_cut_request_for_inventory(
            &store,
            delegation.destination_id(),
            seed + 0x90,
            vec![coordinator_session, source_session],
            vec![coordinator_binding, source_binding],
            continuation_scope(&store, &source, team)?,
        )?;
        let issuer = forge_domain::OrchestrationIssuerId::from_uuid(Uuid::from_u128(seed + 0xA0));
        let grant = forge_domain::WorkCutGrant::new(
            issuer,
            request.request_digest(),
            timestamp(30)?,
            timestamp(90)?,
        )?;
        let cut = match store.prepare_leadership_work_cut(
            &request,
            grant,
            issuer,
            request.backend_id(),
            timestamp(40)?,
        )? {
            crate::WorkCutPrepareOutcome::Prepared(record) => record,
            crate::WorkCutPrepareOutcome::Existing(_) => {
                return Err("first WorkCut prepare must not resolve to Existing".into());
            }
        };
        let captured = cut
            .inventory()
            .nodes()
            .iter()
            .find(|node| {
                node.assignment()
                    .is_some_and(|assignment| assignment.assignment_id() == source.id())
            })
            .ok_or("running source missing from WorkCut inventory")?;
        let source_scope = captured.scope();
        let stored_dag = store
            .get_dag_revision(source.goal_id(), source.dag_revision())?
            .ok_or("source DAG revision missing")?;
        let dag = stored_dag.revision().clone();
        let node = stored_dag
            .nodes()
            .iter()
            .find(|node| node.id() == source.node_id())
            .cloned()
            .ok_or("source DAG node missing")?;
        let session_id = coordinator_agent
            .session_id()
            .ok_or("continuation recipient session missing")?;
        let recipient = forge_domain::AgentAssignmentTarget::new(
            coordinator_agent.id(),
            session_id,
            coordinator_agent.principal(),
            coordinator_agent.revision(),
        );
        let plan = forge_domain::AgentAssignmentContinuationPlan::new(
            Uuid::from_u128(seed + 0xB0),
            forge_domain::AgentAssignmentId::from_uuid(Uuid::from_u128(seed + 0xB1)),
            &request,
            *cut.snapshot_digest(),
            &source,
            source.revision(),
            source_scope,
            &dag,
            &node,
            recipient,
            timestamp(45)?,
        )?;
        Ok(Self {
            root,
            layout,
            store,
            source,
            request,
            cut,
            issuer,
            recipient,
            plan,
        })
    }
}

fn aid(value: u128) -> forge_domain::AgentAssignmentId {
    forge_domain::AgentAssignmentId::from_uuid(Uuid::from_u128(value))
}

fn offer_from(
    source: &forge_domain::RegisteredAgentAssignment,
    successor: forge_domain::AgentAssignmentId,
    at: i64,
) -> TestResult<forge_domain::OfferAgentAssignment> {
    let c = source.coordinator();
    let actor = forge_domain::ActivityCoordinatorActor::new(
        source.workspace_id(),
        source.activity_id(),
        c.agent_id(),
        c.revision(),
        c.principal(),
        c.session_id(),
    );
    Ok(forge_domain::OfferAgentAssignment::new(
        successor,
        actor,
        source.target(),
        source.goal_id(),
        source.goal_revision(),
        source.goal_created_at(),
        source.dag_revision(),
        source.dag_head_revision(),
        source.node_id(),
        source.node_revision(),
        source.credit_budget(),
        timestamp(at)?,
    ))
}

impl ContinuationFixture {
    fn alternative(
        &self,
        successor: forge_domain::AgentAssignmentId,
    ) -> TestResult<forge_domain::AgentAssignmentContinuationPlan> {
        let dag = self
            .store
            .get_dag_revision(self.source.goal_id(), self.source.dag_revision())?
            .ok_or("DAG missing")?;
        let node = dag
            .nodes()
            .iter()
            .find(|n| n.id() == self.source.node_id())
            .ok_or("node missing")?;
        Ok(forge_domain::AgentAssignmentContinuationPlan::new(
            self.plan.transfer_id(),
            successor,
            &self.request,
            *self.cut.snapshot_digest(),
            &self.source,
            self.source.revision(),
            self.plan.source_scope(),
            dag.revision(),
            node,
            self.recipient,
            self.plan.observed_at(),
        )?)
    }
    fn prepare(
        &mut self,
        plan: &forge_domain::AgentAssignmentContinuationPlan,
    ) -> Result<crate::AssignmentContinuationPrepareOutcome, WorkspaceStoreError> {
        self.store.prepare_assignment_continuation(
            plan,
            self.cut.revision(),
            self.issuer,
            self.request.backend_id(),
            plan.observed_at(),
        )
    }

    fn advance_recipient(&mut self) -> TestResult<forge_domain::AgentAssignmentTarget> {
        let previous = self.recipient;
        let agent = self
            .store
            .get_agent(previous.agent_id())?
            .ok_or("recipient missing")?;
        let c = self.source.coordinator();
        let actor = forge_domain::ActivityCoordinatorActor::new(
            self.source.workspace_id(),
            self.source.activity_id(),
            c.agent_id(),
            c.revision(),
            c.principal(),
            c.session_id(),
        );
        let advanced = self.store.set_agent_focus(
            actor,
            &forge_domain::SetAgentFocus::new(
                agent.id(),
                agent.activity_id(),
                agent.revision(),
                agent.focus(),
                timestamp(60)?,
            ),
            timestamp(99)?,
        )?;
        self.recipient = forge_domain::AgentAssignmentTarget::new(
            agent.id(),
            previous.session_id(),
            previous.principal(),
            advanced.revision(),
        );
        assert!(self.recipient.agent_revision() > previous.agent_revision());
        Ok(previous)
    }
    fn prepared(&mut self) -> TestResult<crate::AssignmentContinuationProposal> {
        let plan = self.plan.clone();
        let crate::AssignmentContinuationPrepareOutcome::Prepared(proposal) =
            self.prepare(&plan)?
        else {
            return Err("expected new proposal".into());
        };
        Ok(proposal)
    }
    fn reopen(self) -> TestResult<Self> {
        let Self {
            root,
            layout,
            store,
            source,
            request,
            cut,
            issuer,
            recipient,
            plan,
        } = self;
        drop(store);
        let existing = WorkspaceStateLayout::inspect_existing(layout.workspace_root())?
            .ok_or("layout missing")?;
        let store = WorkspaceStore::open_existing(&existing)?;
        Ok(Self {
            root,
            layout,
            store,
            source,
            request,
            cut,
            issuer,
            recipient,
            plan,
        })
    }
    fn unchanged(&self) -> TestResult {
        assert!(
            self.store
                .get_agent_assignment(self.plan.successor_id())?
                .is_none()
        );
        assert_eq!(
            self.store.get_leadership_work_cut(self.request.cut_id())?,
            Some(self.cut.clone())
        );
        assert_eq!(
            self.store
                .get_agent_assignment(self.source.id())?
                .ok_or("source missing")?
                .target(),
            self.source.target()
        );
        Ok(())
    }
    fn finish(self) -> TestResult {
        drop(self.store);
        fs::remove_dir_all(self.root)?;
        Ok(())
    }
}

#[test]
fn continuation_prepare_replay_remains_historical_after_source_submission() -> TestResult {
    let mut f = ContinuationFixture::new("continuation-history", 0xD800, false)?;
    let proposal = f.prepared()?;
    f.unchanged()?;
    assert_eq!(
        f.store.get_agent_assignment(f.source.id())?,
        Some(f.source.clone())
    );
    let mut f = f.reopen()?;
    let plan = f.plan.clone();
    assert_eq!(
        f.store.get_assignment_continuation(plan.successor_id())?,
        Some(proposal.clone())
    );
    assert_eq!(
        f.prepare(&plan)?,
        crate::AssignmentContinuationPrepareOutcome::Existing(proposal.clone())
    );
    assert!(matches!(
        f.store.prepare_assignment_continuation(
            &plan,
            f.cut.revision() + 1,
            f.issuer,
            f.request.backend_id(),
            timestamp(55)?
        ),
        Err(WorkspaceStoreError::WorkCut(crate::WorkCutError::Conflict(
            _
        )))
    ));
    let agent = f
        .store
        .get_agent(f.source.target().agent_id())?
        .ok_or("source missing")?;
    let target = forge_domain::AgentAssignmentTarget::new(
        agent.id(),
        agent.session_id().ok_or("session missing")?,
        agent.principal(),
        agent.revision(),
    );
    let submitted = f.store.submit_agent_assignment(
        &forge_domain::SubmitAgentAssignment::new(
            f.source.id(),
            target,
            f.source.revision(),
            forge_domain::AgentAssignmentResult::new(
                "completed while handoff was being prepared".to_owned(),
                Vec::new(),
                None,
            )?,
            timestamp(60)?,
        ),
        timestamp(99)?,
    )?;
    assert_eq!(
        submitted.state(),
        forge_domain::AgentAssignmentState::Submitted
    );
    assert_eq!(
        f.prepare(&plan)?,
        crate::AssignmentContinuationPrepareOutcome::Existing(proposal.clone())
    );
    assert_eq!(
        f.store.get_assignment_continuation(plan.successor_id())?,
        Some(proposal)
    );
    let stale = f.alternative(aid(0xD861))?;
    assert!(matches!(
        f.prepare(&stale),
        Err(WorkspaceStoreError::WorkCut(crate::WorkCutError::Conflict(
            "continuation source changed"
        )))
    ));
    f.unchanged()?;
    f.finish()
}

#[test]
fn continuation_acknowledgment_checks_recipient_and_survives_restart() -> TestResult {
    use crate::AssignmentContinuationAcknowledgeOutcome as Ack;
    let mut f = ContinuationFixture::new("continuation-ack", 0xD800, true)?;
    let proposal = f.prepared()?;
    let successor = f.plan.successor_id();
    let request = Uuid::from_u128(0xD870);
    let stale = forge_domain::AgentAssignmentTarget::new(
        f.recipient.agent_id(),
        f.recipient.session_id(),
        f.recipient.principal(),
        forge_domain::AgentInstanceRevision::new(f.recipient.agent_revision().get() + 1)?,
    );
    for (digest, recipient) in [
        ([0; 32], f.recipient),
        (*proposal.digest(), f.source.target()),
        (*proposal.digest(), stale),
    ] {
        assert!(
            f.store
                .acknowledge_assignment_continuation(
                    request,
                    successor,
                    digest,
                    recipient,
                    timestamp(60)?
                )
                .is_err()
        );
        assert!(
            f.store
                .get_assignment_continuation_acknowledgment(request)?
                .is_none()
        );
    }
    let previous = f.advance_recipient()?;
    assert!(
        f.store
            .acknowledge_assignment_continuation(
                request,
                successor,
                *proposal.digest(),
                previous,
                timestamp(61)?
            )
            .is_err()
    );
    let Ack::Recorded(receipt) = f.store.acknowledge_assignment_continuation(
        request,
        successor,
        *proposal.digest(),
        f.recipient,
        timestamp(61)?,
    )?
    else {
        return Err("expected fresh ack".into());
    };
    assert_eq!(receipt.recipient(), f.recipient);
    let mut f = f.reopen()?;
    assert_eq!(
        f.store
            .get_assignment_continuation_acknowledgment(request)?,
        Some(receipt.clone())
    );
    assert_eq!(
        f.store.acknowledge_assignment_continuation(
            request,
            successor,
            *proposal.digest(),
            f.recipient,
            timestamp(62)?
        )?,
        Ack::Existing(receipt)
    );
    assert!(matches!(
        f.store.acknowledge_assignment_continuation(
            request,
            successor,
            [0; 32],
            f.recipient,
            timestamp(63)?
        ),
        Err(WorkspaceStoreError::WorkCut(crate::WorkCutError::Conflict(
            _
        )))
    ));
    assert!(matches!(
        f.store.acknowledge_assignment_continuation(
            Uuid::from_u128(0xD871),
            successor,
            *proposal.digest(),
            f.recipient,
            timestamp(63)?
        ),
        Err(WorkspaceStoreError::WorkCut(crate::WorkCutError::Conflict(
            _
        )))
    ));
    f.unchanged()?;
    f.finish()
}

#[test]
fn continuation_failures_roll_back_and_corrupt_receipts_are_refused() -> TestResult {
    let mut f = ContinuationFixture::new("continuation-rollback", 0xD800, false)?;
    let plan = f.plan.clone();
    f.store.connection.execute_batch("CREATE TEMP TRIGGER fail_proposal BEFORE INSERT ON assignment_continuation_proposals BEGIN SELECT RAISE(ABORT,'fixture failure'); END")?;
    assert!(f.prepare(&plan).is_err());
    let count: i64 = f.store.connection.query_row(
        "SELECT COUNT(*) FROM assignment_continuation_batches",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(count, 0, "failed proposal must roll back its batch too");
    assert!(
        f.store
            .get_assignment_continuation(plan.successor_id())?
            .is_none()
    );
    f.store
        .connection
        .execute_batch("DROP TRIGGER fail_proposal")?;
    let proposal = f.prepared()?;
    let request = Uuid::from_u128(0xD870);
    f.store.connection.execute_batch("CREATE TEMP TRIGGER fail_ack BEFORE INSERT ON assignment_continuation_acknowledgments BEGIN SELECT RAISE(ABORT,'fixture failure'); END")?;
    assert!(
        f.store
            .acknowledge_assignment_continuation(
                request,
                plan.successor_id(),
                *proposal.digest(),
                f.recipient,
                timestamp(60)?
            )
            .is_err()
    );
    assert!(
        f.store
            .get_assignment_continuation_acknowledgment(request)?
            .is_none()
    );
    assert_eq!(
        f.store.get_assignment_continuation(plan.successor_id())?,
        Some(proposal.clone())
    );
    f.store.connection.execute_batch("DROP TRIGGER fail_ack")?;
    assert!(matches!(
        f.store.acknowledge_assignment_continuation(
            request,
            plan.successor_id(),
            *proposal.digest(),
            f.recipient,
            timestamp(61)?
        )?,
        crate::AssignmentContinuationAcknowledgeOutcome::Recorded(_)
    ));
    f.store.connection.execute("UPDATE assignment_continuation_acknowledgments SET record_digest=zeroblob(32) WHERE request_id=?1",params![request.as_bytes()])?;
    assert!(matches!(
        f.store.get_assignment_continuation_acknowledgment(request),
        Err(WorkspaceStoreError::WorkCut(crate::WorkCutError::Corrupt(
            _
        )))
    ));
    f.store.connection.execute("UPDATE assignment_continuation_proposals SET record_digest=zeroblob(32) WHERE successor_id=?1",params![plan.successor_id().into_uuid().as_bytes()])?;
    assert!(matches!(
        f.store.get_assignment_continuation(plan.successor_id()),
        Err(WorkspaceStoreError::WorkCut(crate::WorkCutError::Corrupt(
            _
        )))
    ));
    f.unchanged()?;
    f.finish()
}

#[test]
fn continuation_successor_and_seals_fence_both_admission_orders() -> TestResult {
    let mut f = ContinuationFixture::new("continuation-identity", 0xD800, false)?;
    let occupied = f.alternative(aid(0xB533))?;
    assert!(matches!(
        f.prepare(&occupied),
        Err(WorkspaceStoreError::WorkCut(crate::WorkCutError::Conflict(
            "continuation successor identity occupied"
        )))
    ));
    let sealed = f.alternative(aid(0xD861))?;
    let _ = f.store.seal_agent_assignment_offer_local(
        f.source.workspace_id(),
        f.source.activity_id(),
        sealed.successor_id(),
        timestamp(46)?,
    )?;
    assert!(matches!(
        f.prepare(&sealed),
        Err(WorkspaceStoreError::WorkCut(crate::WorkCutError::Conflict(
            "continuation successor admission sealed"
        )))
    ));
    let proposal = f.prepared()?;
    let plan = f.plan.clone();
    assert!(matches!(
        f.store.offer_agent_assignment(
            &offer_from(&f.source, plan.successor_id(), 60)?,
            timestamp(99)?,
        ),
        Err(WorkspaceStoreError::AgentAssignment(
            crate::AgentAssignmentStoreError::IdentityConflict
        ))
    ));
    let _ = f.store.seal_agent_assignment_offer_local(
        f.source.workspace_id(),
        f.source.activity_id(),
        plan.successor_id(),
        timestamp(61)?,
    )?;
    assert_eq!(
        f.prepare(&plan)?,
        crate::AssignmentContinuationPrepareOutcome::Existing(proposal)
    );
    f.unchanged()?;
    f.finish()
}
