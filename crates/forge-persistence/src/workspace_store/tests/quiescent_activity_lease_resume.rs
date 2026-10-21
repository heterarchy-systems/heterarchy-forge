//! Quiescent same-Activity resume fences, migration and durable readback.

use super::*;
use crate::WorkspaceJournalBinding;
use forge_domain::{
    AgentSessionRevision, AgentSessionState, AgentWorkPhase, AgentWorkSummary, AgentWorkUpdate,
    AgentWorkUpdateId, AgentWorkUpdateSequence, ChangeSetId, ForgeBackendId, GoalEvidenceRef,
    LocationRevision, OrchestrationIssuerId, QuiescentActivityLeaseResumeGetRequest,
    QuiescentActivityLeaseResumeOperation, QuiescentActivityLeaseResumeProbeRequest,
    QuiescentActivityLeaseResumeRunRequest, StartedActivityLeaseResumeAssignmentCensus,
    StartedActivityLeaseResumeDagCensus, StartedActivityLeaseResumeGetRequest,
    StartedActivityLeaseResumeGoalCensus, StartedActivityLeaseResumePhysicalCensus,
    StartedActivityLeaseResumeProbeRequest, StartedActivityLeaseResumeRunRequest,
    StartedActivityLeaseResumeServiceIdentity, StartedActivityLeaseResumeSessionSnapshot,
    UnstartedActivityContinuationServiceIdentity, WorkspaceId,
};
use rusqlite::{Connection, params};
use std::fs;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::thread;
use std::time::{Duration, Instant};
use uuid::Uuid;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const PROBE_AT: i64 = 450;
const RUN_AT: i64 = 500;
static SQLITE_BUSY_WAIT_OBSERVED: AtomicBool = AtomicBool::new(false);

fn observe_sqlite_busy_wait(_: i32) -> bool {
    SQLITE_BUSY_WAIT_OBSERVED.store(true, Ordering::Release);
    thread::sleep(Duration::from_millis(1));
    true
}

struct QuiescentScenario {
    fixture: FileFactFixture,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    agents: Vec<forge_domain::RegisteredAgentInstance>,
    binding: WorkspaceJournalBinding,
    scope: forge_domain::ExpiredActivityRecoveryProbeScope,
    service: StartedActivityLeaseResumeServiceIdentity,
    session: StartedActivityLeaseResumeSessionSnapshot,
    request: QuiescentActivityLeaseResumeProbeRequest,
}

impl QuiescentScenario {
    fn probe(
        &self,
    ) -> Result<forge_domain::QuiescentActivityLeaseResumeProbe, WorkspaceStoreError> {
        self.fixture.store.probe_quiescent_activity_lease_resume(
            &self.binding,
            &self.request,
            self.service,
            self.session,
            Some(self.session),
            test_clock_timestamp(PROBE_AT)?,
        )
    }

    fn run_request(
        &self,
        probe: forge_domain::QuiescentActivityLeaseResumeProbe,
        request_id: Uuid,
        request_digest: [u8; 32],
        current_service: StartedActivityLeaseResumeServiceIdentity,
    ) -> Result<
        QuiescentActivityLeaseResumeRunRequest,
        forge_domain::QuiescentActivityLeaseResumeValidationError,
    > {
        QuiescentActivityLeaseResumeRunRequest::new(
            self.scope.clone(),
            request_id,
            request_digest,
            probe,
            current_service,
        )
    }

    fn get_request(
        &self,
        request_id: Uuid,
        request_digest: [u8; 32],
    ) -> Result<
        QuiescentActivityLeaseResumeGetRequest,
        forge_domain::QuiescentActivityLeaseResumeValidationError,
    > {
        QuiescentActivityLeaseResumeGetRequest::new(
            self.scope.clone(),
            request_id,
            request_digest,
            self.activity_id,
            self.agents[0].id(),
            self.session.session_id(),
            self.session.principal(),
        )
    }
}

fn quiescent_scenario(label: &str, seed: u128) -> TestResult<QuiescentScenario> {
    let mut fixture = file_fact_fixture(label, seed)?;
    let workspace = fixture.store.workspace()?;
    let activity_id = fixture.activity.id();
    let evidence_id = seed_quiescent_goal_evidence(
        &mut fixture.store,
        workspace.id(),
        activity_id,
        fixture.owner,
        fixture.activity.lease_revision().get(),
        workspace.revision().get(),
        seed,
    )?;
    let (agents, coordinator_session_id) = seed_quiescent_agents_and_history(
        &mut fixture.store,
        workspace.id(),
        activity_id,
        seed,
        evidence_id,
    )?;
    let delegation = install_delegation_seal(&mut fixture.store, seed + 0x800, 200)?;
    let binding = fixture.store.journal_binding()?;
    let root = fixture.store.workspace()?;
    let scope = forge_domain::ExpiredActivityRecoveryProbeScope::new(
        root.id(),
        root.revision(),
        root.location_id(),
        LocationRevision::INITIAL,
        b".".to_vec(),
        root.root_fingerprint(),
        binding.recovery_history_digest(),
    )?;
    let source_identity = UnstartedActivityContinuationServiceIdentity::new(
        ForgeBackendId::from_uuid(Uuid::from_u128(seed + 0x900)),
        OrchestrationIssuerId::from_uuid(Uuid::from_u128(seed + 0x901)),
        runtime_id(seed + 0x902),
    )?;
    let service = StartedActivityLeaseResumeServiceIdentity::new(
        source_identity,
        delegation.destination_id(),
    )?;
    let session = StartedActivityLeaseResumeSessionSnapshot::new(
        coordinator_session_id,
        agents[0].principal(),
        AgentSessionState::Open,
        AgentSessionRevision::INITIAL,
        timestamp(24)?,
    )?;
    let request = QuiescentActivityLeaseResumeProbeRequest::new(
        scope.clone(),
        activity_id,
        coordinator_session_id,
        agents[0].principal(),
    )?;
    fixture.store.connection.execute(
        "UPDATE activities SET lease_until_ms=?1 WHERE activity_id=?2",
        params![400_i64, activity_id.into_uuid().as_bytes().as_slice()],
    )?;
    Ok(QuiescentScenario {
        fixture,
        workspace_id: workspace.id(),
        activity_id,
        agents,
        binding,
        scope,
        service,
        session,
        request,
    })
}

fn seed_quiescent_goal_evidence(
    store: &mut WorkspaceStore,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    owner: RuntimeInstanceId,
    activity_lease_revision: i64,
    workspace_revision: i64,
    seed: u128,
) -> TestResult<ChangeSetId> {
    let attribution = insert_file_test_goal_seeded(store, workspace_id, activity_id, seed + 0x100)?;
    let goal_id = attribution.goal().goal_id();
    let evidence_id = ChangeSetId::from_uuid(Uuid::from_u128(seed + 0x7000));
    store.connection.execute(
        "INSERT INTO change_sets (
            changeset_id, workspace_id, activity_id, runtime_instance_id,
            activity_lease_revision, workspace_revision, state, failure_code,
            created_at_ms, updated_at_ms, revision
         ) VALUES (?1,?2,?3,?4,?5,?6,1,NULL,20,20,1)",
        params![
            evidence_id.into_uuid().as_bytes().as_slice(),
            workspace_id.into_uuid().as_bytes().as_slice(),
            activity_id.into_uuid().as_bytes().as_slice(),
            owner.into_uuid().as_bytes().as_slice(),
            activity_lease_revision,
            workspace_revision,
        ],
    )?;
    store.connection.execute(
        "INSERT INTO goal_evidence_refs (goal_id,evidence_kind,evidence_id,associated_at_ms)
         VALUES (?1,0,?2,21)",
        params![
            goal_id.into_uuid().as_bytes().as_slice(),
            evidence_id.into_uuid().as_bytes().as_slice(),
        ],
    )?;
    Ok(evidence_id)
}

fn seed_quiescent_agents_and_history(
    store: &mut WorkspaceStore,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    seed: u128,
    evidence_id: ChangeSetId,
) -> TestResult<(Vec<forge_domain::RegisteredAgentInstance>, AgentSessionId)> {
    let agents = [0_u128, 1, 2]
        .into_iter()
        .map(|offset| {
            inventory_seeded_agent(
                store,
                workspace_id,
                activity_id,
                seed + 0x200 + offset * 0x10,
            )
        })
        .collect::<TestResult<Vec<_>>>()?;
    let coordinator_session_id = agents[0]
        .session_id()
        .ok_or("fixture Coordinator Agent has no Session")?;
    let coordinator_binding = store.claim_activity_coordinator(
        forge_domain::ClaimActivityCoordinator::new(
            workspace_id,
            activity_id,
            agents[0].id(),
            agents[0].principal(),
            timestamp(22)?,
            coordinator_session_id,
        ),
        timestamp(100)?,
    )?;
    assert_eq!(coordinator_binding.agent_id(), agents[0].id());

    let phases = [
        AgentWorkPhase::Planning,
        AgentWorkPhase::Verifying,
        AgentWorkPhase::Verifying,
    ];
    for (index, (agent, phase)) in agents.iter().zip(phases).enumerate() {
        let phase_offset = i64::try_from(index)?;
        let session_id = agent.session_id().ok_or("fixture Agent has no Session")?;
        let update = AgentWorkUpdate::new(
            AgentWorkUpdateId::from_uuid(Uuid::from_u128(seed + 0x500 + index as u128)),
            agent.id(),
            workspace_id,
            activity_id,
            AgentWorkUpdateSequence::INITIAL,
            phase,
            AgentWorkSummary::new(format!("preserved {phase:?} history"))?,
            vec![GoalEvidenceRef::ChangeSet(evidence_id)],
            timestamp(30 + phase_offset)?,
        )?;
        let published = store.publish_agent_work_update(
            &update,
            session_id,
            agent.principal(),
            timestamp(40 + phase_offset)?,
        )?;
        assert_eq!(published, update);
    }
    Ok((agents, coordinator_session_id))
}

fn census_snapshot(
    store: &WorkspaceStore,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
) -> TestResult<(
    StartedActivityLeaseResumeGoalCensus,
    StartedActivityLeaseResumeDagCensus,
    forge_domain::QuiescentActivityLeaseResumeAgentCensus,
    StartedActivityLeaseResumeAssignmentCensus,
    forge_domain::QuiescentActivityLeaseResumeWorkHistoryCensus,
    StartedActivityLeaseResumePhysicalCensus,
)> {
    let goals = super::super::started_activity_lease_resume::goal_census(
        &store.connection,
        workspace_id,
        activity_id,
    )?;
    let dags = super::super::started_activity_lease_resume::dag_census(
        &store.connection,
        workspace_id,
        activity_id,
    )?;
    let agents = super::super::quiescent_activity_lease_resume::agent_census(
        &store.connection,
        workspace_id,
        activity_id,
    )?;
    let (assignments, _) = super::super::started_activity_lease_resume::assignment_census(
        &store.connection,
        workspace_id,
        activity_id,
    )?;
    let history = super::super::quiescent_activity_lease_resume::work_history_census(
        &store.connection,
        workspace_id,
        activity_id,
    )?;
    let physical = super::super::started_activity_lease_resume::physical_census(
        &store.connection,
        workspace_id,
        activity_id,
    )?;
    Ok((goals, dags, agents, assignments, history, physical))
}

fn receipt_count(store: &WorkspaceStore) -> Result<i64, rusqlite::Error> {
    store.connection.query_row(
        "SELECT COUNT(*) FROM quiescent_activity_lease_resume_receipts",
        [],
        |row| row.get(0),
    )
}

#[test]
fn quiescent_receipt_schema_is_idempotent_and_rejects_corrupt_shape() -> TestResult {
    let canonical = Connection::open_in_memory()?;
    crate::workspace_quiescent_activity_lease_resumes::create_schema(&canonical)?;
    crate::workspace_quiescent_activity_lease_resumes::create_schema(&canonical)?;
    crate::workspace_quiescent_activity_lease_resumes::validate_schema(&canonical)?;

    let damaged = Connection::open_in_memory()?;
    damaged.execute_batch(
        "CREATE TABLE quiescent_activity_lease_resume_receipts (request_id BLOB PRIMARY KEY)",
    )?;
    assert!(crate::workspace_quiescent_activity_lease_resumes::create_schema(&damaged).is_err());
    assert!(
        crate::workspace_quiescent_activity_lease_resumes::validate_schema_if_present(&damaged)
            .is_err()
    );
    Ok(())
}

#[test]
fn schema_v68_adds_empty_quiescent_resume_ledger_and_preserves_existing_rows() -> TestResult {
    let scenario = quiescent_scenario("quiescent-resume-v68", 0xD6_0000)?;
    let before_activity = scenario
        .fixture
        .store
        .get_activity(scenario.activity_id)?
        .ok_or("Activity missing")?;
    let before_censuses = census_snapshot(
        &scenario.fixture.store,
        scenario.workspace_id,
        scenario.activity_id,
    )?;
    let root = scenario.fixture.root.clone();
    let database_path = scenario.fixture.layout.database_path().clone();
    drop(scenario);

    let old = Connection::open(&database_path)?;
    old.pragma_update(None, "journal_mode", "DELETE")?;
    old.execute_batch("DROP TABLE quiescent_activity_lease_resume_receipts")?;
    old.pragma_update(
        None,
        "user_version",
        super::super::PREVIOUS_QUIESCENT_ACTIVITY_LEASE_RESUME_SCHEMA_VERSION,
    )?;
    drop(old);

    let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("Workspace missing")?;
    let migrated = WorkspaceStore::open_existing(&existing)?;
    assert_eq!(migrated.health()?.schema_version(), CURRENT_SCHEMA_VERSION);
    assert_eq!(
        migrated.get_activity(before_activity.id())?,
        Some(before_activity.clone())
    );
    assert_eq!(
        census_snapshot(&migrated, migrated.workspace()?.id(), before_activity.id())?,
        before_censuses,
        "the additive receipt migration must preserve all existing Activity rows"
    );
    assert_eq!(receipt_count(&migrated)?, 0);
    let mut foreign_keys = migrated.connection.prepare("PRAGMA foreign_key_check")?;
    assert!(foreign_keys.query([])?.next()?.is_none());
    drop(foreign_keys);
    let quick_check: String =
        migrated
            .connection
            .pragma_query_value(None, "quick_check", |row| row.get(0))?;
    assert_eq!(quick_check, "ok");
    drop(migrated);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn schema_v68_quiescent_migration_preserves_started_receipt_across_reopen() -> TestResult {
    let seed = 0xD6_0800_u128;
    let mut fixture = file_fact_fixture("quiescent-preserves-started-receipt", seed)?;
    let activity_id = fixture.activity.id();
    let record = create_started_receipt_for_migration(&mut fixture.store, activity_id, seed)?;
    let before_row = started_receipt_row(&fixture.store.connection, record.request_id)?;
    let root = fixture.root.clone();
    let database_path = fixture.layout.database_path().clone();
    drop(fixture);

    let old = Connection::open(&database_path)?;
    old.pragma_update(None, "journal_mode", "DELETE")?;
    old.execute_batch("DROP TABLE quiescent_activity_lease_resume_receipts")?;
    old.pragma_update(
        None,
        "user_version",
        super::super::PREVIOUS_QUIESCENT_ACTIVITY_LEASE_RESUME_SCHEMA_VERSION,
    )?;
    drop(old);

    let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("Workspace missing")?;
    let migrated = WorkspaceStore::open_existing(&existing)?;
    assert_eq!(migrated.health()?.schema_version(), CURRENT_SCHEMA_VERSION);
    assert_eq!(
        started_receipt_row(&migrated.connection, record.request_id)?,
        before_row
    );
    assert_eq!(
        migrated
            .started_activity_lease_resume_readback_for_request(
                &record.binding,
                &record.get_request
            )?
            .ok_or("Started receipt lost during migration")?
            .receipt(),
        &record.receipt
    );
    drop(migrated);

    let reopened = WorkspaceStore::open_existing(&existing)?;
    assert_eq!(
        started_receipt_row(&reopened.connection, record.request_id)?,
        before_row
    );
    assert_eq!(
        reopened
            .started_activity_lease_resume_readback_for_request(
                &record.binding,
                &record.get_request
            )?
            .ok_or("Started receipt lost after reopen")?
            .receipt(),
        &record.receipt
    );
    drop(reopened);
    fs::remove_dir_all(root)?;
    Ok(())
}

struct StartedReceiptMigrationRecord {
    binding: WorkspaceJournalBinding,
    get_request: StartedActivityLeaseResumeGetRequest,
    receipt: forge_domain::StartedActivityLeaseResumeReceipt,
    request_id: Uuid,
}

struct StartedReceiptMigrationSetup {
    binding: WorkspaceJournalBinding,
    scope: forge_domain::ExpiredActivityRecoveryProbeScope,
    service: StartedActivityLeaseResumeServiceIdentity,
    coordinator_session: StartedActivityLeaseResumeSessionSnapshot,
    initiating_session: StartedActivityLeaseResumeSessionSnapshot,
    probe_request: StartedActivityLeaseResumeProbeRequest,
    initiating_agent_id: forge_domain::AgentInstanceId,
    initiating_session_id: forge_domain::AgentSessionId,
    initiating_principal: forge_domain::AuthenticatedPrincipal,
}

fn create_started_receipt_for_migration(
    store: &mut WorkspaceStore,
    activity_id: ActivityId,
    seed: u128,
) -> TestResult<StartedReceiptMigrationRecord> {
    let setup = prepare_started_receipt_migration(store, activity_id, seed)?;
    store.connection.execute(
        "UPDATE activities SET lease_until_ms=?1 WHERE activity_id=?2",
        params![400_i64, activity_id.into_uuid().as_bytes().as_slice()],
    )?;
    let probe = store.probe_started_activity_lease_resume(
        &setup.binding,
        &setup.probe_request,
        setup.service,
        setup.initiating_session,
        Some(setup.coordinator_session),
        timestamp(500)?,
    )?;
    assert!(probe.started_work_proven());
    assert!(probe.resumable_now());
    let request_id = Uuid::from_u128(seed + 0x300);
    let request_digest = [0xA8; 32];
    let run_request = StartedActivityLeaseResumeRunRequest::new(
        setup.scope.clone(),
        request_id,
        request_digest,
        probe,
        setup.service,
    )?;
    let receipt = match store.run_started_activity_lease_resume_with_clock(
        &setup.binding,
        &run_request,
        setup.initiating_session,
        Some(setup.coordinator_session),
        || test_clock_timestamp(501),
    )? {
        forge_domain::StartedActivityLeaseResumeOperation::Recorded(receipt) => receipt,
        forge_domain::StartedActivityLeaseResumeOperation::Replay(_) => {
            return Err("fresh Started resume unexpectedly replayed".into());
        }
    };
    let get_request = StartedActivityLeaseResumeGetRequest::new(
        setup.scope,
        request_id,
        request_digest,
        activity_id,
        setup.initiating_agent_id,
        setup.initiating_session_id,
        setup.initiating_principal,
    )?;
    assert_eq!(
        store
            .started_activity_lease_resume_readback_for_request(&setup.binding, &get_request)?
            .ok_or("Started receipt missing")?
            .receipt(),
        &receipt
    );
    Ok(StartedReceiptMigrationRecord {
        binding: setup.binding,
        get_request,
        receipt,
        request_id,
    })
}

fn prepare_started_receipt_migration(
    store: &mut WorkspaceStore,
    activity_id: ActivityId,
    seed: u128,
) -> TestResult<StartedReceiptMigrationSetup> {
    let workspace_id = store.workspace()?.id();
    let offered = seed_assignment_for_offer_seal_migration(store, workspace_id, activity_id)?;
    let running = store.claim_agent_assignment(
        &forge_domain::ClaimAgentAssignment::new(
            offered.id(),
            offered.target(),
            forge_domain::AgentAssignmentRevision::INITIAL,
            timestamp(200)?,
        ),
        timestamp(200)?,
    )?;
    assert_eq!(running.state(), forge_domain::AgentAssignmentState::Running);
    let delegation = install_delegation_seal(store, seed + 0x100, 300)?;
    let binding = store.journal_binding()?;
    let workspace = store.workspace()?;
    let scope = forge_domain::ExpiredActivityRecoveryProbeScope::new(
        workspace.id(),
        workspace.revision(),
        workspace.location_id(),
        LocationRevision::INITIAL,
        b".".to_vec(),
        workspace.root_fingerprint(),
        binding.recovery_history_digest(),
    )?;
    let coordinator = store
        .get_activity_coordinator(activity_id)?
        .ok_or("Coordinator missing")?;
    let coordinator_agent = store
        .get_agent(coordinator.agent_id())?
        .ok_or("Coordinator Agent missing")?;
    let coordinator_session = StartedActivityLeaseResumeSessionSnapshot::new(
        coordinator_agent
            .session_id()
            .ok_or("Coordinator Session missing")?,
        coordinator_agent.principal(),
        AgentSessionState::Open,
        AgentSessionRevision::INITIAL,
        timestamp(150)?,
    )?;
    let initiating_session = StartedActivityLeaseResumeSessionSnapshot::new(
        running.target().session_id(),
        running.target().principal(),
        AgentSessionState::Open,
        AgentSessionRevision::INITIAL,
        timestamp(150)?,
    )?;
    let service = StartedActivityLeaseResumeServiceIdentity::new(
        UnstartedActivityContinuationServiceIdentity::new(
            ForgeBackendId::from_uuid(Uuid::from_u128(seed + 0x200)),
            OrchestrationIssuerId::from_uuid(Uuid::from_u128(seed + 0x201)),
            runtime_id(seed + 0x202),
        )?,
        delegation.destination_id(),
    )?;
    let probe_request = StartedActivityLeaseResumeProbeRequest::new(
        scope.clone(),
        activity_id,
        running.target().session_id(),
        running.target().principal(),
    )?;
    Ok(StartedReceiptMigrationSetup {
        binding,
        scope,
        service,
        coordinator_session,
        initiating_session,
        probe_request,
        initiating_agent_id: running.target().agent_id(),
        initiating_session_id: running.target().session_id(),
        initiating_principal: running.target().principal(),
    })
}

fn started_receipt_row(
    connection: &Connection,
    request_id: Uuid,
) -> TestResult<Vec<rusqlite::types::Value>> {
    let mut statement = connection
        .prepare("SELECT * FROM started_activity_lease_resume_receipts WHERE request_id=?1")?;
    let mut rows = statement.query(params![request_id.as_bytes().as_slice()])?;
    let row = rows.next()?.ok_or("Started receipt row missing")?;
    (0..row.as_ref().column_count())
        .map(|index| row.get(index))
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

#[test]
fn quiescent_work_history_resumes_same_activity_and_replays_after_reopen() -> TestResult {
    let mut scenario = quiescent_scenario("quiescent-resume-replay", 0xD6_1000)?;
    let before = scenario
        .fixture
        .store
        .get_activity(scenario.activity_id)?
        .ok_or("Activity missing")?;
    let before_censuses = census_snapshot(
        &scenario.fixture.store,
        scenario.workspace_id,
        scenario.activity_id,
    )?;
    let probe = scenario.probe()?;
    assert!(probe.resumable_now());
    assert_eq!(probe.blocker(), None);
    assert_eq!(probe.expectation().agent_census().row_count(), 3);
    assert_eq!(probe.expectation().assignment_census().row_count(), 0);
    assert_eq!(probe.expectation().work_history_census().update_count(), 3);
    assert_eq!(
        probe
            .expectation()
            .work_history_census()
            .evidence_ref_count(),
        3
    );
    assert_eq!(
        receipt_count(&scenario.fixture.store)?,
        0,
        "Probe must be read-only"
    );

    let request_id = Uuid::from_u128(0xD6_1F00);
    let request_digest = [0xA5; 32];
    let run_request = scenario.run_request(probe, request_id, request_digest, scenario.service)?;
    let operation = scenario
        .fixture
        .store
        .run_quiescent_activity_lease_resume_with_clock(
            &scenario.binding,
            &run_request,
            scenario.session,
            Some(scenario.session),
            || test_clock_timestamp(RUN_AT),
        )?;
    assert!(matches!(
        operation,
        QuiescentActivityLeaseResumeOperation::Recorded(_)
    ));
    let receipt = operation.receipt().clone();
    assert_eq!(receipt.activity_id(), scenario.activity_id);
    assert_eq!(receipt.activity().revision(), before.revision());
    assert_eq!(receipt.activity().state(), before.state());
    assert_eq!(receipt.activity().created_at(), before.created_at());
    assert_eq!(receipt.activity().updated_at(), before.updated_at());
    assert_eq!(
        receipt.source_runtime_instance_id(),
        scenario.service.runtime_instance_id()
    );
    assert_eq!(receipt.resumed_at(), timestamp(RUN_AT)?);
    assert_eq!(
        census_snapshot(
            &scenario.fixture.store,
            scenario.workspace_id,
            scenario.activity_id,
        )?,
        before_censuses,
        "resume changes only the Activity lease tuple"
    );
    assert_eq!(receipt_count(&scenario.fixture.store)?, 1);

    // The run reply is treated as lost. A later lease observation and process
    // reopen still return the immutable receipt without rerunning the CAS.
    let get_request = scenario.get_request(request_id, request_digest)?;
    let first_readback = scenario
        .fixture
        .store
        .quiescent_activity_lease_resume_readback_for_request(&scenario.binding, &get_request)?
        .ok_or("receipt missing after committed run")?;
    assert_eq!(first_readback.receipt(), &receipt);
    verify_quiescent_receipt_replay_after_reopen(
        scenario,
        request_id,
        request_digest,
        &run_request,
        &get_request,
        &receipt,
    )
}

fn verify_quiescent_receipt_replay_after_reopen(
    scenario: QuiescentScenario,
    request_id: Uuid,
    request_digest: [u8; 32],
    run_request: &QuiescentActivityLeaseResumeRunRequest,
    get_request: &QuiescentActivityLeaseResumeGetRequest,
    receipt: &forge_domain::QuiescentActivityLeaseResumeReceipt,
) -> TestResult {
    let binding = scenario.binding.clone();
    let scope = scenario.scope.clone();
    let session = scenario.session;
    let destination_id = scenario.service.destination_id();
    let activity_id = scenario.activity_id;
    let coordinator_agent_id = scenario.agents[0].id();
    let root = scenario.fixture.root.clone();
    scenario.fixture.store.connection.execute(
        "UPDATE activities SET lease_until_ms=?1 WHERE activity_id=?2",
        params![
            RUN_AT + forge_domain::QUIESCENT_ACTIVITY_LEASE_RESUME_LEASE_DURATION_MS + 1,
            scenario.activity_id.into_uuid().as_bytes().as_slice(),
        ],
    )?;
    let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("Workspace missing")?;
    drop(scenario.fixture.store);

    let mut reopened = WorkspaceStore::open_existing(&existing)?;
    let readback = reopened
        .quiescent_activity_lease_resume_readback_for_request(&binding, get_request)?
        .ok_or("receipt missing after reopen")?;
    assert_eq!(readback.receipt(), receipt);
    let changed_boot = StartedActivityLeaseResumeServiceIdentity::new(
        UnstartedActivityContinuationServiceIdentity::new(
            ForgeBackendId::from_uuid(Uuid::from_u128(0xD6_1900)),
            OrchestrationIssuerId::from_uuid(Uuid::from_u128(0xD6_1901)),
            runtime_id(0xD6_1902),
        )?,
        destination_id,
    )?;
    let replay_request = QuiescentActivityLeaseResumeRunRequest::new(
        scope.clone(),
        request_id,
        request_digest,
        run_request.probe().clone(),
        changed_boot,
    )?;
    let replay = reopened.run_quiescent_activity_lease_resume_with_clock(
        &binding,
        &replay_request,
        session,
        Some(session),
        || test_clock_timestamp(-1),
    )?;
    assert!(matches!(
        replay,
        QuiescentActivityLeaseResumeOperation::Replay(_)
    ));
    assert_eq!(replay.receipt(), receipt);
    assert_eq!(receipt_count(&reopened)?, 1);

    let changed_digest = QuiescentActivityLeaseResumeGetRequest::new(
        scope.clone(),
        request_id,
        [0xA6; 32],
        activity_id,
        coordinator_agent_id,
        session.session_id(),
        session.principal(),
    )?;
    assert!(matches!(
        reopened.quiescent_activity_lease_resume_readback_for_request(&binding, &changed_digest),
        Err(WorkspaceStoreError::QuiescentActivityLeaseResume(_))
    ));
    fs::remove_dir_all(root)?;
    Ok(())
}

#[derive(Clone, Copy)]
enum StaleFence {
    Lease,
    Session,
    Coordinator,
    Goal,
    Dag,
    Agent,
    WorkHistory,
}

#[test]
fn quiescent_run_rejects_stale_lease_session_coordinator_goal_dag_agent_and_history() -> TestResult
{
    for (index, stale) in [
        StaleFence::Lease,
        StaleFence::Session,
        StaleFence::Coordinator,
        StaleFence::Goal,
        StaleFence::Dag,
        StaleFence::Agent,
        StaleFence::WorkHistory,
    ]
    .into_iter()
    .enumerate()
    {
        let seed = 0xD6_2000 + index as u128 * 0x100;
        let mut scenario = quiescent_scenario("quiescent-stale-fence", seed)?;
        let mut probe = scenario.probe()?;
        assert!(probe.resumable_now());
        if !matches!(stale, StaleFence::Lease | StaleFence::Session) {
            probe = changed_probe_census(&probe, stale)?;
        }
        let request_id = Uuid::from_u128(seed + 0x70);
        let index_byte = u8::try_from(index)?;
        let request =
            scenario.run_request(probe, request_id, [index_byte + 1; 32], scenario.service)?;
        let mut initiating_session = scenario.session;
        match stale {
            StaleFence::Lease => {
                scenario.fixture.store.connection.execute(
                    "UPDATE activities SET lease_until_ms=?1 WHERE activity_id=?2",
                    params![
                        600_i64,
                        scenario.activity_id.into_uuid().as_bytes().as_slice()
                    ],
                )?;
            }
            StaleFence::Session => {
                initiating_session = StartedActivityLeaseResumeSessionSnapshot::new(
                    scenario.session.session_id(),
                    scenario.session.principal(),
                    AgentSessionState::Closed,
                    AgentSessionRevision::new(scenario.session.revision().get() + 1)?,
                    timestamp(scenario.session.updated_at().get() + 1)?,
                )?;
            }
            StaleFence::Coordinator
            | StaleFence::Goal
            | StaleFence::Dag
            | StaleFence::Agent
            | StaleFence::WorkHistory => {}
        }
        let before_failure = scenario
            .fixture
            .store
            .get_activity(scenario.activity_id)?
            .ok_or("Activity missing")?;
        assert!(matches!(
            scenario
                .fixture
                .store
                .run_quiescent_activity_lease_resume_with_clock(
                    &scenario.binding,
                    &request,
                    initiating_session,
                    Some(scenario.session),
                    || test_clock_timestamp(RUN_AT),
                ),
            Err(WorkspaceStoreError::QuiescentActivityLeaseResume(_))
        ));
        assert_eq!(
            scenario.fixture.store.get_activity(scenario.activity_id)?,
            Some(before_failure),
            "stale fence must reject before the lease CAS"
        );
        assert_eq!(receipt_count(&scenario.fixture.store)?, 0);
        fs::remove_dir_all(&scenario.fixture.root)?;
    }
    Ok(())
}

#[test]
fn quiescent_resume_rechecks_ttl_after_waiting_for_immediate_transaction_lock() -> TestResult {
    let seed = 0xD6_2F00_u128;
    let mut scenario = quiescent_scenario("quiescent-resume-lock-delay", seed)?;
    let probe = scenario.probe()?;
    assert!(probe.resumable_now());
    let request = scenario.run_request(
        probe.clone(),
        Uuid::from_u128(seed + 0x70),
        [0xA7; 32],
        scenario.service,
    )?;
    let before = scenario
        .fixture
        .store
        .get_activity(scenario.activity_id)?
        .ok_or("Activity missing")?;
    let database_path = scenario.fixture.layout.database_path().clone();
    let blocker = Connection::open(&database_path)?;
    blocker.busy_timeout(Duration::ZERO)?;
    blocker.execute_batch("BEGIN IMMEDIATE")?;

    SQLITE_BUSY_WAIT_OBSERVED.store(false, Ordering::Release);
    scenario
        .fixture
        .store
        .connection
        .busy_handler(Some(observe_sqlite_busy_wait))?;
    let clock_now = Arc::new(AtomicI64::new(
        probe.probe_expires_at().get().saturating_sub(1),
    ));
    let clock_called = Arc::new(AtomicBool::new(false));
    let clock_now_for_run = Arc::clone(&clock_now);
    let clock_called_for_run = Arc::clone(&clock_called);
    let run_thread = thread::spawn(move || {
        let result = scenario
            .fixture
            .store
            .run_quiescent_activity_lease_resume_with_clock(
                &scenario.binding,
                &request,
                scenario.session,
                Some(scenario.session),
                || {
                    clock_called_for_run.store(true, Ordering::Release);
                    test_clock_timestamp(clock_now_for_run.load(Ordering::Acquire))
                },
            );
        (scenario, result)
    });

    let deadline = Instant::now() + Duration::from_secs(5);
    while !SQLITE_BUSY_WAIT_OBSERVED.load(Ordering::Acquire) && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(1));
    }
    if !SQLITE_BUSY_WAIT_OBSERVED.load(Ordering::Acquire) {
        blocker.execute_batch("ROLLBACK")?;
        let _ = run_thread.join();
        return Err("resume did not wait on the immediate transaction lock".into());
    }
    assert!(
        !clock_called.load(Ordering::Acquire),
        "Source time must not be sampled until BEGIN IMMEDIATE acquires the lock"
    );
    clock_now.store(
        probe.probe_expires_at().get().saturating_add(1),
        Ordering::Release,
    );
    blocker.execute_batch("ROLLBACK")?;

    let (scenario, result) = run_thread.join().map_err(|_| "resume worker panicked")?;
    assert!(clock_called.load(Ordering::Acquire));
    assert!(matches!(
        result,
        Err(WorkspaceStoreError::QuiescentActivityLeaseResume(_))
    ));
    assert_eq!(
        scenario.fixture.store.get_activity(scenario.activity_id)?,
        Some(before),
        "expired after lock wait must leave the Activity lease unchanged"
    );
    assert_eq!(receipt_count(&scenario.fixture.store)?, 0);
    fs::remove_dir_all(&scenario.fixture.root)?;
    Ok(())
}

fn changed_probe_census(
    probe: &forge_domain::QuiescentActivityLeaseResumeProbe,
    stale: StaleFence,
) -> TestResult<forge_domain::QuiescentActivityLeaseResumeProbe> {
    let expectation = probe.expectation();
    let mut goal = expectation.goal_census();
    let mut dag = expectation.dag_census();
    let mut agent = expectation.agent_census();
    let mut coordinator = expectation.coordinator().copied();
    let mut work_history = expectation.work_history_census();
    match stale {
        StaleFence::Coordinator => {
            let current = coordinator.ok_or("Coordinator missing in positive probe")?;
            coordinator = Some(
                forge_domain::StartedActivityLeaseResumeCoordinatorSnapshot::new(
                    current.agent_id(),
                    current.session_id(),
                    current.principal(),
                    current.agent_revision(),
                    forge_domain::ActivityCoordinatorRevision::new(current.revision().get() + 1)?,
                    timestamp(current.updated_at().get() + 1)?,
                    current.session_revision(),
                    current.session_updated_at(),
                )?,
            );
        }
        StaleFence::Goal => {
            goal = StartedActivityLeaseResumeGoalCensus::new(
                goal.row_count(),
                [0x51; 32],
                goal.truncated(),
                goal.complete(),
            )?;
        }
        StaleFence::Dag => {
            dag = StartedActivityLeaseResumeDagCensus::new(
                dag.head_count(),
                dag.node_count(),
                dag.edge_count(),
                [0x52; 32],
                dag.truncated(),
                dag.complete(),
            )?;
        }
        StaleFence::Agent => {
            agent = forge_domain::QuiescentActivityLeaseResumeAgentCensus::new(
                agent.row_count(),
                [0x53; 32],
                agent.truncated(),
                agent.complete(),
            )?;
        }
        StaleFence::WorkHistory => {
            work_history = forge_domain::QuiescentActivityLeaseResumeWorkHistoryCensus::new(
                work_history.update_count() + 1,
                work_history.evidence_ref_count(),
                [0x54; 32],
                false,
                true,
            )?;
        }
        StaleFence::Lease | StaleFence::Session => return Ok(probe.clone()),
    }
    let current = forge_domain::QuiescentActivityLeaseResumeExpectation::new(
        expectation.activity().clone(),
        expectation.initiating_agent().copied(),
        *expectation.initiating_session(),
        coordinator,
        expectation.coordinator_agent_attached(),
        expectation.coordinator_session_open(),
        goal,
        dag,
        agent,
        expectation.coordination_work(),
        expectation.assignment_census(),
        work_history,
        expectation.physical_census(),
    )?;
    Ok(forge_domain::QuiescentActivityLeaseResumeProbe::new(
        probe.scope().clone(),
        probe.service(),
        probe.delegation(),
        current,
        probe.probe_observed_at(),
        probe.probe_digest(),
        true,
        None,
    )?)
}

#[test]
fn quiescent_probe_rejects_assignments_and_physical_activity_effects() -> TestResult {
    let mut fixture = file_fact_fixture("quiescent-assignment-blocker", 0xD6_3000)?;
    let workspace_id = fixture.store.workspace()?.id();
    let activity_id = fixture.activity.id();
    let assignment =
        seed_assignment_for_offer_seal_migration(&mut fixture.store, workspace_id, activity_id)?;
    assert_eq!(
        assignment.state(),
        forge_domain::AgentAssignmentState::Offered
    );
    let coordinator = fixture
        .store
        .get_activity_coordinator(activity_id)?
        .ok_or("Coordinator missing")?;
    let agent = fixture
        .store
        .get_agent(coordinator.agent_id())?
        .ok_or("Coordinator Agent missing")?;
    let assignment = finish_scenario(fixture, workspace_id, activity_id, agent, vec![], 0xD6_3100)?;
    let blocked = assignment.probe()?;
    assert!(!blocked.resumable_now());
    assert_eq!(
        blocked.blocker(),
        Some(forge_domain::QuiescentActivityLeaseResumeBlocker::AssignmentPresent)
    );
    assert_eq!(receipt_count(&assignment.fixture.store)?, 0);
    fs::remove_dir_all(&assignment.fixture.root)?;

    let mut scenario = quiescent_scenario("quiescent-physical-blocker", 0xD6_3200)?;
    let workspace_command = command(
        &scenario.fixture.layout,
        scenario.workspace_id,
        scenario.fixture.store.workspace()?.location_id(),
        1,
    )?;
    insert_stale_doctor_records(
        &mut scenario.fixture.store,
        &workspace_command,
        &scenario.fixture.activity,
    )?;
    let blocked = scenario.probe()?;
    assert!(!blocked.resumable_now());
    assert_eq!(
        blocked.blocker(),
        Some(forge_domain::QuiescentActivityLeaseResumeBlocker::PhysicalActivityEffectPresent)
    );
    assert_eq!(receipt_count(&scenario.fixture.store)?, 0);
    fs::remove_dir_all(&scenario.fixture.root)?;
    Ok(())
}

#[test]
fn quiescent_receipt_insert_failure_rolls_back_activity_lease_cas() -> TestResult {
    let mut scenario = quiescent_scenario("quiescent-rollback", 0xD6_4000)?;
    let probe = scenario.probe()?;
    assert!(probe.resumable_now());
    let run = scenario.run_request(
        probe,
        Uuid::from_u128(0xD6_4F00),
        [0xA7; 32],
        scenario.service,
    )?;
    let before = scenario
        .fixture
        .store
        .get_activity(scenario.activity_id)?
        .ok_or("Activity missing")?;
    scenario.fixture.store.connection.execute_batch(
        "CREATE TEMP TRIGGER quiescent_resume_abort BEFORE INSERT ON
         main.quiescent_activity_lease_resume_receipts BEGIN
             SELECT RAISE(ABORT,'injected receipt failure');
         END",
    )?;
    assert!(matches!(
        scenario
            .fixture
            .store
            .run_quiescent_activity_lease_resume_with_clock(
                &scenario.binding,
                &run,
                scenario.session,
                Some(scenario.session),
                || test_clock_timestamp(RUN_AT),
            ),
        Err(WorkspaceStoreError::QuiescentActivityLeaseResume(_))
    ));
    assert_eq!(
        scenario.fixture.store.get_activity(scenario.activity_id)?,
        Some(before)
    );
    assert_eq!(receipt_count(&scenario.fixture.store)?, 0);
    fs::remove_dir_all(&scenario.fixture.root)?;
    Ok(())
}

fn finish_scenario(
    mut fixture: FileFactFixture,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    coordinator_agent: forge_domain::RegisteredAgentInstance,
    agents: Vec<forge_domain::RegisteredAgentInstance>,
    seed: u128,
) -> TestResult<QuiescentScenario> {
    let delegation = install_delegation_seal(&mut fixture.store, seed + 0x10, 200)?;
    let binding = fixture.store.journal_binding()?;
    let workspace = fixture.store.workspace()?;
    let scope = forge_domain::ExpiredActivityRecoveryProbeScope::new(
        workspace.id(),
        workspace.revision(),
        workspace.location_id(),
        LocationRevision::INITIAL,
        b".".to_vec(),
        workspace.root_fingerprint(),
        binding.recovery_history_digest(),
    )?;
    let source_identity = UnstartedActivityContinuationServiceIdentity::new(
        ForgeBackendId::from_uuid(Uuid::from_u128(seed + 0x20)),
        OrchestrationIssuerId::from_uuid(Uuid::from_u128(seed + 0x21)),
        runtime_id(seed + 0x22),
    )?;
    let service = StartedActivityLeaseResumeServiceIdentity::new(
        source_identity,
        delegation.destination_id(),
    )?;
    let session_id = coordinator_agent
        .session_id()
        .ok_or("Coordinator Agent has no Session")?;
    let session = StartedActivityLeaseResumeSessionSnapshot::new(
        session_id,
        coordinator_agent.principal(),
        AgentSessionState::Open,
        AgentSessionRevision::INITIAL,
        timestamp(24)?,
    )?;
    let request = QuiescentActivityLeaseResumeProbeRequest::new(
        scope.clone(),
        activity_id,
        session_id,
        coordinator_agent.principal(),
    )?;
    fixture.store.connection.execute(
        "UPDATE activities SET lease_until_ms=?1 WHERE activity_id=?2",
        params![400_i64, activity_id.into_uuid().as_bytes().as_slice()],
    )?;
    Ok(QuiescentScenario {
        fixture,
        workspace_id,
        activity_id,
        agents: if agents.is_empty() {
            vec![coordinator_agent]
        } else {
            agents
        },
        binding,
        scope,
        service,
        session,
        request,
    })
}
