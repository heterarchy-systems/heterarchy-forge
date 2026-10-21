use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use forge_control::{
    AgentBindingActivateRequest, AgentBindingReserveRequest, AgentOperationsDelegationRequest,
    AgentOperationsFreezeRequest, CoordinatorClaimRequest, ForgeControl, ForgeControlWorker,
};
use forge_domain::{
    ActivityCoordinatorActor, ActivityId, AgentDagDraft, AgentDagPlanRequest,
    AgentDagPlanRequestId, AgentDeclaredRole, AgentDisplayName, AgentInstanceId, AgentSessionId,
    AgentSessionOpenRequestId, AgentTransportKind, AgentWorkUpdateId, AgentWorkUpdateSequence,
    AuthenticatedPrincipal, DagAcceptanceCriterion, DagNodeDefinition, DagNodeId, DagNodeObjective,
    DagNodeOrdinal, DagNodeTitle, DagRevision, DagRevisionId, DagRevisionNumber,
    EstablishWorkspace, ForgeBackendId, GoalAttribution, GoalContract, GoalObjective,
    GoalStatement, LocationId, LocationRevision, OpenAgentSession, OrchestrationIssuerId,
    RegisteredActivity, RegisteredDagNode, RegisteredGoal, RuntimeInstanceId,
    StartedActivityLeaseResumeServiceIdentity, TimestampMillis,
    UnstartedActivityContinuationServiceIdentity, WorkspaceId, WorkspaceRoot,
};
use forge_persistence::{
    AgentBindingActivationRequest, AgentBindingReservationRequest, AgentOperationsFreezeState,
    GlobalRegistry, StoredDagRevision, WorkspaceStore,
};
use forge_workspace::{LocationService, WorkspaceStateLayout};
use rusqlite::Connection;
use uuid::Uuid;

use super::*;

struct WorkspaceFixture {
    root: PathBuf,
    registry_path: PathBuf,
    database_path: PathBuf,
    location_id: LocationId,
    workspace_id: WorkspaceId,
    scope: forge_control::ResolvedWorkspaceScope,
    control: forge_control::ForgeControlClient,
    control_worker: ForgeControlWorker,
    leases: forge_control::ActivityLeaseClient,
    lease_worker: ForgeControlWorker,
}

impl WorkspaceFixture {
    fn create() -> Result<Self, Box<dyn Error>> {
        let root =
            std::env::temp_dir().join(format!("forge-host-lease-supervisor-{}", Uuid::now_v7()));
        let location_root = root.join("location-root");
        let registry_path = root.join("registry.sqlite3");
        fs::create_dir_all(&location_root)?;

        let now = timestamp_now()?;
        let location_id = LocationId::from_uuid(Uuid::now_v7());
        let workspace_id = WorkspaceId::from_uuid(Uuid::now_v7());
        let location = LocationService::new(GlobalRegistry::open(&registry_path)?)
            .register_selected_path(
                location_id,
                "Host lease supervisor fixture",
                &location_root,
                now,
            )?;
        let layout = WorkspaceStateLayout::initialize(&location_root)?;
        let establish = EstablishWorkspace::new(
            workspace_id,
            location.id(),
            WorkspaceRoot::from_canonical(layout.workspace_root().to_path_buf())?,
            layout.root_fingerprint()?,
            now,
        );
        drop(WorkspaceStore::open(&layout, &establish)?);
        register_unavailable_sibling(&location_root, location.id(), now)?;

        let (control, control_worker) = ForgeControlWorker::start(ForgeControl::new(
            GlobalRegistry::open_existing(&registry_path)?,
        ))?;
        let (leases, lease_worker) = ForgeControlWorker::start_activity_lease(ForgeControl::new(
            GlobalRegistry::open_existing(&registry_path)?,
        ))?;
        let scope = find_scope(&control, location_id, workspace_id)?;
        let inventory =
            control.registered_workspace_inventory(location_id, LocationRevision::INITIAL)?;
        if !inventory.entries().iter().any(|entry| {
            matches!(
                entry,
                forge_control::WorkspaceInventoryEntry::Unavailable { .. }
            )
        }) {
            return Err("the fixture did not retain its unavailable sibling row".into());
        }
        Ok(Self {
            root,
            registry_path,
            database_path: layout.database_path(),
            location_id,
            workspace_id,
            scope,
            control,
            control_worker,
            leases,
            lease_worker,
        })
    }
}

fn register_unavailable_sibling(
    location_root: &std::path::Path,
    location_id: LocationId,
    now: TimestampMillis,
) -> Result<(), Box<dyn Error>> {
    let sibling_root = location_root.join("unavailable-sibling");
    fs::create_dir_all(&sibling_root)?;
    let layout = WorkspaceStateLayout::initialize(&sibling_root)?;
    let establish = EstablishWorkspace::new(
        WorkspaceId::from_uuid(Uuid::now_v7()),
        location_id,
        WorkspaceRoot::from_canonical(layout.workspace_root().to_path_buf())?,
        layout.root_fingerprint()?,
        now,
    );
    drop(WorkspaceStore::open(&layout, &establish)?);
    Connection::open(layout.database_path())?.pragma_update(None, "user_version", i64::MAX)?;
    Ok(())
}

struct NativeCoordinatorFixture {
    session_id: AgentSessionId,
    agent_id: AgentInstanceId,
    coordinator_revision: i64,
    destination_id: Uuid,
}

fn register_native_coordinator(
    workspace: &WorkspaceFixture,
    activity_id: ActivityId,
    now: TimestampMillis,
) -> Result<NativeCoordinatorFixture, Box<dyn Error>> {
    let principal = AuthenticatedPrincipal::TrustedStdio;
    let session_id = AgentSessionId::from_uuid(Uuid::now_v7());
    let _opened_session = workspace.control.agent_session_open(OpenAgentSession::new(
        session_id,
        AgentSessionOpenRequestId::from_uuid(Uuid::now_v7()),
        principal,
        now,
    ))?;
    let migration_id = Uuid::now_v7();
    let destination_id = Uuid::now_v7();
    let freeze = workspace
        .control
        .agent_operations_freeze(AgentOperationsFreezeRequest {
            scope: workspace.scope.clone(),
            migration_id,
            destination_id,
            observed_at: now,
        })?;
    if freeze.state() != AgentOperationsFreezeState::Frozen {
        return Err("the fixture Source freeze is not active".into());
    }
    let delegation =
        workspace
            .control
            .delegate_agent_operations(AgentOperationsDelegationRequest {
                scope: workspace.scope.clone(),
                freeze: freeze.clone(),
                manifest_digest: [0x41; 32],
                observed_at: now,
            })?;
    let agent_id = AgentInstanceId::from_uuid(Uuid::now_v7());
    let binding_request_id = Uuid::now_v7();
    let reservation = AgentBindingReservationRequest::new(
        binding_request_id,
        activity_id,
        agent_id,
        session_id,
        principal,
        now,
    )?;
    let _reserved = workspace
        .control
        .reserve_agent_binding(AgentBindingReserveRequest {
            scope: workspace.scope.clone(),
            freeze,
            reservation,
            observed_at: now,
        })?;
    let activation = AgentBindingActivationRequest::new(
        binding_request_id,
        [0x52; 32],
        AgentDisplayName::new("Native Main".to_owned())?,
        AgentDeclaredRole::new("coordinator".to_owned())?,
        AgentTransportKind::Stdio,
    )?;
    let _activated = workspace
        .control
        .activate_agent_binding(AgentBindingActivateRequest {
            scope: workspace.scope.clone(),
            delegation,
            activation,
            session_id,
            principal,
            observed_at: now,
        })?;
    let binding = workspace
        .control
        .activity_coordinator_claim(CoordinatorClaimRequest {
            session_id,
            scope: workspace.scope.clone(),
            activity_id,
            agent_id,
            principal,
            observed_at: now,
        })?;
    Ok(NativeCoordinatorFixture {
        session_id,
        agent_id,
        coordinator_revision: binding.revision().get(),
        destination_id,
    })
}

fn create_goal_and_dag(
    workspace: &WorkspaceFixture,
    native: &NativeCoordinatorFixture,
    activity_id: ActivityId,
    now: TimestampMillis,
) -> Result<(RegisteredGoal, StoredDagRevision), Box<dyn Error>> {
    let actor = ActivityCoordinatorActor::new(
        workspace.workspace_id,
        activity_id,
        native.agent_id,
        forge_domain::ActivityCoordinatorRevision::new(native.coordinator_revision)?,
        AuthenticatedPrincipal::TrustedStdio,
        native.session_id,
    );
    let goal = workspace.control.goal_create(
        workspace.scope.clone(),
        actor,
        RegisteredGoal::create(
            forge_domain::GoalId::from_uuid(Uuid::now_v7()),
            workspace.workspace_id,
            activity_id,
            GoalContract::new(
                GoalObjective::new("Keep one native Goal recoverable".to_owned())?,
                vec![GoalStatement::new(
                    "The same Activity and Goal remain open".to_owned(),
                )?],
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            )?,
            now,
        ),
    )?;
    let definition = DagNodeDefinition::new(
        DagNodeId::from_uuid(Uuid::now_v7()),
        DagNodeOrdinal::new(0)?,
        DagNodeTitle::new("Maintain continuity".to_owned())?,
        DagNodeObjective::new("Retain the current Goal and lease history".to_owned())?,
        vec![DagAcceptanceCriterion::new(
            "The current Goal and Activity remain unchanged".to_owned(),
        )?],
    )?;
    let revision = DagRevision::new(
        DagRevisionId::from_uuid(Uuid::now_v7()),
        goal.id(),
        goal.revision(),
        DagRevisionNumber::INITIAL,
        None,
        vec![definition.clone()],
        Vec::new(),
        now,
    )?;
    let draft = AgentDagDraft::new(
        revision,
        vec![RegisteredDagNode::create(
            goal.id(),
            DagRevisionNumber::INITIAL,
            definition,
            now,
        )],
        Vec::new(),
    )?;
    let _planned =
        workspace
            .control
            .agent_dag_plan_commit(forge_control::AgentDagPlanCommitRequest {
                scope: workspace.scope.clone(),
                request: AgentDagPlanRequest::new(
                    AgentDagPlanRequestId::from_uuid(Uuid::now_v7()),
                    actor,
                    GoalAttribution::new(goal.id(), goal.revision()),
                    None,
                    None,
                    draft,
                    AgentWorkUpdateId::from_uuid(Uuid::now_v7()),
                    AgentWorkUpdateSequence::INITIAL,
                    now,
                ),
            })?;
    let dag = workspace
        .control
        .dag_get_current(workspace.scope.clone(), goal.id())?
        .ok_or("native fixture DAG missing after plan commit")?;
    Ok((goal, dag))
}

struct NativePlanFixture {
    activity_id: ActivityId,
    old_runtime: RuntimeInstanceId,
    prior_activity: RegisteredActivity,
    native: NativeCoordinatorFixture,
    goal: RegisteredGoal,
    before_goal: RegisteredGoal,
    before_dag: StoredDagRevision,
    before_work_history: Vec<WorkHistoryRow>,
    before_assignment_count: i64,
    before_execution_count: i64,
}

fn seed_native_plan(workspace: &WorkspaceFixture) -> Result<NativePlanFixture, Box<dyn Error>> {
    let now = timestamp_now()?;
    let activity_id = ActivityId::from_uuid(Uuid::now_v7());
    let old_runtime = RuntimeInstanceId::from_uuid(Uuid::now_v7());
    let initial_until = TimestampMillis::new(now.get().saturating_add(60_000))?;
    let _bootstrapped = workspace.leases.bootstrap_activity(
        workspace.scope.clone(),
        activity_id,
        old_runtime,
        now,
        initial_until,
    )?;
    let native = register_native_coordinator(workspace, activity_id, now)?;
    let (goal, before_dag) = create_goal_and_dag(workspace, &native, activity_id, now)?;
    let prior_activity = observe_activity(&workspace.leases, &workspace.scope, activity_id)?;
    set_lease_until(
        &workspace.database_path,
        activity_id,
        now.get().saturating_sub(1),
    )?;
    let before_goal = workspace
        .control
        .goal_get(workspace.scope.clone(), activity_id, goal.id())?
        .ok_or("native fixture Goal disappeared")?;
    let before_work_history = work_history_rows(&workspace.database_path, activity_id)?;
    let before_assignment_count =
        activity_row_count(&workspace.database_path, "agent_assignments", activity_id)?;
    let before_execution_count =
        activity_row_count(&workspace.database_path, "executions", activity_id)?;
    if before_work_history.is_empty() || before_assignment_count != 0 || before_execution_count != 0
    {
        return Err(
            "native quiescent fixture must preserve work history without assignments or executions"
                .into(),
        );
    }
    Ok(NativePlanFixture {
        activity_id,
        old_runtime,
        prior_activity,
        native,
        goal,
        before_goal,
        before_dag,
        before_work_history,
        before_assignment_count,
        before_execution_count,
    })
}

struct HostLeaseFixture {
    workspace: WorkspaceFixture,
    native: NativePlanFixture,
    config: HostActivityLeaseSupervisionConfig,
    first_runtime: RuntimeInstanceId,
    service: StartedActivityLeaseResumeServiceIdentity,
    supervisor: Option<HostActivityLeaseSupervisor>,
}

impl HostLeaseFixture {
    fn create() -> Result<Self, Box<dyn Error>> {
        let workspace = WorkspaceFixture::create()?;
        let native = seed_native_plan(&workspace)?;
        let first_runtime = RuntimeInstanceId::from_uuid(Uuid::now_v7());
        let recovery =
            forge_backend::recovery::run_startup_recovery(&workspace.control, first_runtime);
        if recovery.failures.len() != 1
            || recovery.workspaces_scanned < 2
            || recovery.classified_activities != 0
        {
            return Err("startup recovery did not preserve the attached Activity".into());
        }
        let after_recovery =
            observe_activity(&workspace.leases, &workspace.scope, native.activity_id)?;
        if after_recovery.lease_owner_id() != Some(native.old_runtime)
            || after_recovery.lease_revision() != native.prior_activity.lease_revision()
            || after_recovery.state() != forge_domain::ActivityState::Open
        {
            return Err("startup recovery changed the registered Activity lease".into());
        }
        let registration = HostActivityLeaseRegistration {
            supervision_id: Uuid::now_v7(),
            scope: HostActivityLeaseScope {
                location_id: workspace.location_id.into_uuid(),
                location_revision: LocationRevision::INITIAL.get(),
                workspace_id: workspace.workspace_id.into_uuid(),
                workspace_revision: workspace.scope.workspace_revision().get(),
            },
            activity_id: native.activity_id.into_uuid(),
            goal_id: native.goal.id().into_uuid(),
            goal_created_at_ms: native.goal.timestamps().created_at().get(),
            initiating_session_id: native.native.session_id.into_uuid(),
            principal: HostPrincipalConfig {
                kind: HostPrincipalKind::TrustedStdio,
                id: None,
            },
            coordinator: HostCoordinatorPin {
                agent_id: native.native.agent_id.into_uuid(),
                session_id: native.native.session_id.into_uuid(),
                revision: native.native.coordinator_revision,
            },
        };
        let config = HostActivityLeaseSupervisionConfig {
            journal_root: workspace.root.join("private-journal"),
            lease_duration_ms: 30_000,
            renew_interval_ms: 1_000,
            registrations: vec![registration],
        };
        let service = StartedActivityLeaseResumeServiceIdentity::new(
            UnstartedActivityContinuationServiceIdentity::new(
                ForgeBackendId::from_uuid(Uuid::now_v7()),
                OrchestrationIssuerId::from_uuid(Uuid::now_v7()),
                first_runtime,
            )?,
            native.native.destination_id,
        )?;
        Ok(Self {
            workspace,
            native,
            config,
            first_runtime,
            service,
            supervisor: None,
        })
    }

    fn start_supervisor(
        &mut self,
        runtime: RuntimeInstanceId,
        service: StartedActivityLeaseResumeServiceIdentity,
    ) -> Result<(), Box<dyn Error>> {
        let prepared = PreparedHostActivityLeaseSupervisor::prepare(
            Some(&self.config),
            &self.workspace.registry_path,
        )?
        .ok_or("configured supervisor unexpectedly disabled")?;
        self.supervisor = Some(prepared.start(
            &tokio::runtime::Handle::current(),
            self.workspace.control.clone(),
            self.workspace.leases.clone(),
            runtime,
            service,
        ));
        Ok(())
    }

    async fn stop_supervisor(&mut self) -> Result<(), Box<dyn Error>> {
        let supervisor = self
            .supervisor
            .take()
            .ok_or("host supervisor was not started")?;
        stop_supervisor(supervisor).await
    }

    async fn resume_and_renew_first_boot(&mut self) -> Result<(), Box<dyn Error>> {
        self.start_supervisor(self.first_runtime, self.service)?;
        let resumed = wait_for_owned_lease(
            self.workspace.leases.clone(),
            self.workspace.scope.clone(),
            self.native.activity_id,
            self.first_runtime,
            self.native.prior_activity.lease_revision().get(),
            Duration::from_secs(8),
        )
        .await?;
        if receipt_count(&self.workspace.database_path)? != 1
            || resumed.id() != self.native.activity_id
            || resumed.state() != forge_domain::ActivityState::Open
        {
            return Err("the quiescent same-Activity resume did not persist its receipt".into());
        }

        let before_renewal = resumed.lease_revision().get();
        let renew_now = timestamp_now()?;
        set_lease_until(
            &self.workspace.database_path,
            self.native.activity_id,
            renew_now.get().saturating_add(2_000),
        )?;
        let renewed = wait_for_owned_lease(
            self.workspace.leases.clone(),
            self.workspace.scope.clone(),
            self.native.activity_id,
            self.first_runtime,
            before_renewal,
            Duration::from_secs(5),
        )
        .await?;
        if renewed
            .lease_until()
            .is_none_or(|until| until.get() <= renew_now.get() + 2_000)
        {
            return Err("the current boot lease was not extended".into());
        }
        self.stop_supervisor().await
    }

    async fn resume_after_boot_change(&mut self) -> Result<(), Box<dyn Error>> {
        let second_runtime = RuntimeInstanceId::from_uuid(Uuid::now_v7());
        let old_boot = observe_activity(
            &self.workspace.leases,
            &self.workspace.scope,
            self.native.activity_id,
        )?;
        let recovery =
            forge_backend::recovery::run_startup_recovery(&self.workspace.control, second_runtime);
        let after_recovery = observe_activity(
            &self.workspace.leases,
            &self.workspace.scope,
            self.native.activity_id,
        )?;
        if recovery.failures.len() != 1
            || recovery.workspaces_scanned < 2
            || after_recovery.lease_owner_id() != old_boot.lease_owner_id()
            || after_recovery.lease_revision() != old_boot.lease_revision()
        {
            return Err(
                "startup recovery changed the attached Activity lease after restart".into(),
            );
        }
        let second_service = StartedActivityLeaseResumeServiceIdentity::new(
            UnstartedActivityContinuationServiceIdentity::new(
                self.service.backend_id(),
                self.service.issuer(),
                second_runtime,
            )?,
            self.native.native.destination_id,
        )?;
        self.start_supervisor(second_runtime, second_service)?;
        tokio::time::sleep(Duration::from_millis(100)).await;
        let still_old_boot = observe_activity(
            &self.workspace.leases,
            &self.workspace.scope,
            self.native.activity_id,
        )?;
        if still_old_boot.lease_owner_id() != Some(self.first_runtime)
            || still_old_boot.lease_revision() != old_boot.lease_revision()
        {
            return Err("a fresh runtime took over a still-live foreign lease".into());
        }
        set_lease_until(
            &self.workspace.database_path,
            self.native.activity_id,
            timestamp_now()?.get().saturating_sub(1),
        )?;
        let resumed = wait_for_owned_lease(
            self.workspace.leases.clone(),
            self.workspace.scope.clone(),
            self.native.activity_id,
            second_runtime,
            old_boot.lease_revision().get(),
            Duration::from_secs(8),
        )
        .await?;
        if receipt_count(&self.workspace.database_path)? != 2
            || resumed.id() != self.native.activity_id
            || resumed.state() != forge_domain::ActivityState::Open
        {
            return Err("the fresh runtime did not resume the same Activity".into());
        }
        self.assert_history_preserved()?;
        self.stop_supervisor().await
    }

    fn assert_history_preserved(&self) -> Result<(), Box<dyn Error>> {
        let after_goal = self
            .workspace
            .control
            .goal_get(
                self.workspace.scope.clone(),
                self.native.activity_id,
                self.native.goal.id(),
            )?
            .ok_or("native Goal disappeared across lease recovery")?;
        let after_dag = self
            .workspace
            .control
            .dag_get_current(self.workspace.scope.clone(), self.native.goal.id())?
            .ok_or("native DAG disappeared across lease recovery")?;
        if after_goal != self.native.before_goal || after_dag != self.native.before_dag {
            return Err("lease supervision changed Goal or DAG history".into());
        }
        if work_history_rows(&self.workspace.database_path, self.native.activity_id)?
            != self.native.before_work_history
            || activity_row_count(
                &self.workspace.database_path,
                "agent_assignments",
                self.native.activity_id,
            )? != self.native.before_assignment_count
            || activity_row_count(
                &self.workspace.database_path,
                "executions",
                self.native.activity_id,
            )? != self.native.before_execution_count
        {
            return Err("lease supervision changed work history or created work".into());
        }
        Ok(())
    }

    fn finish(self) -> Result<(), Box<dyn Error>> {
        let journal = read_journal(
            &self
                .config
                .journal_root
                .join("activity-lease-supervision.json"),
        )?;
        if !journal.pending.is_empty() {
            return Err("the host journal retained a settled operation".into());
        }
        let mut lease_worker = self.workspace.lease_worker;
        let mut control_worker = self.workspace.control_worker;
        let lease_report = lease_worker.shutdown_owned(Vec::new())?;
        let control_report = control_worker.shutdown_owned(Vec::new())?;
        if !lease_report.failures().is_empty()
            || lease_report.committed_but_unconfirmed() != 0
            || !control_report.failures().is_empty()
            || control_report.committed_but_unconfirmed() != 0
        {
            return Err("the in-process Source workers did not join cleanly".into());
        }
        fs::remove_dir_all(self.workspace.root)?;
        Ok(())
    }
}

pub(super) async fn run() -> Result<(), Box<dyn Error>> {
    let mut fixture = HostLeaseFixture::create()?;
    fixture.resume_and_renew_first_boot().await?;
    fixture.resume_after_boot_change().await?;
    fixture.finish()
}
