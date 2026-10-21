//! Schema-v67 migration and immutable-receipt durability coverage.

use super::*;

static SQLITE_BUSY_WAIT_OBSERVED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

fn observe_sqlite_busy_wait(_: i32) -> bool {
    SQLITE_BUSY_WAIT_OBSERVED.store(true, std::sync::atomic::Ordering::Release);
    std::thread::sleep(std::time::Duration::from_millis(1));
    true
}

fn wait_for_sqlite_lock_wait() -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !SQLITE_BUSY_WAIT_OBSERVED.load(std::sync::atomic::Ordering::Acquire)
        && std::time::Instant::now() < deadline
    {
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    SQLITE_BUSY_WAIT_OBSERVED.load(std::sync::atomic::Ordering::Acquire)
}

#[test]
fn started_resume_receipt_schema_creation_is_idempotent_and_checks_existing_shape()
-> Result<(), Box<dyn std::error::Error>> {
    let canonical = Connection::open_in_memory()?;
    crate::workspace_started_activity_lease_resumes::create_schema(&canonical)?;
    crate::workspace_started_activity_lease_resumes::create_schema(&canonical)?;
    crate::workspace_started_activity_lease_resumes::validate_schema(&canonical)?;

    let damaged = Connection::open_in_memory()?;
    damaged.execute_batch(
        "CREATE TABLE started_activity_lease_resume_receipts (request_id BLOB PRIMARY KEY)",
    )?;
    assert!(crate::workspace_started_activity_lease_resumes::create_schema(&damaged).is_err());
    assert!(
        crate::workspace_started_activity_lease_resumes::validate_schema_if_present(&damaged)
            .is_err()
    );
    Ok(())
}

#[test]
fn schema_v66_adds_empty_started_lease_resume_receipt_ledger_and_reopens()
-> Result<(), Box<dyn std::error::Error>> {
    let (root, layout, store, activity_id) = store_with_activity("started-resume-v66")?;
    let before = store.get_activity(activity_id)?.ok_or("Activity missing")?;
    drop(store);

    let connection = Connection::open(layout.database_path())?;
    downgrade_admission_identity(&connection)?;
    connection.execute_batch("DROP TABLE started_activity_lease_resume_receipts")?;
    connection.pragma_update(
        None,
        "user_version",
        super::super::PREVIOUS_STARTED_ACTIVITY_LEASE_RESUME_SCHEMA_VERSION,
    )?;
    drop(connection);

    let existing = WorkspaceStateLayout::inspect_existing(layout.workspace_root())?
        .ok_or("Workspace missing")?;
    let migrated = WorkspaceStore::open_existing(&existing)?;
    assert_eq!(migrated.health()?.schema_version(), CURRENT_SCHEMA_VERSION);
    assert_eq!(migrated.get_activity(activity_id)?, Some(before.clone()));
    let receipt_count: i64 = migrated.connection.query_row(
        "SELECT COUNT(*) FROM started_activity_lease_resume_receipts",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        receipt_count, 0,
        "migration must not invent resume receipts"
    );
    drop(migrated);

    let reopened = WorkspaceStore::open_existing(&existing)?;
    assert_eq!(reopened.health()?.schema_version(), CURRENT_SCHEMA_VERSION);
    assert_eq!(reopened.get_activity(activity_id)?, Some(before));
    drop(reopened);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn started_running_assignment_resumes_same_activity_and_replays_exact_receipt_after_lease_change_and_reopen()
-> Result<(), Box<dyn std::error::Error>> {
    let seed = 0xD4_0000_u128;
    let mut scenario = started_resume_scenario(seed)?;
    assert_physical_blocker_preserves_lease(&mut scenario, seed)?;
    assert_run_rechecks_stop_fence_added_after_probe(&mut scenario, seed)?;
    let result = resume_once(&mut scenario, seed)?;
    assert_replay_after_mutable_changes(&mut scenario, &result)?;
    assert_reopened_receipt_and_cleanup(scenario, &result)?;
    Ok(())
}

#[test]
fn started_resume_rechecks_ttl_after_waiting_for_immediate_transaction_lock()
-> Result<(), Box<dyn std::error::Error>> {
    let seed = 0xD4_0800_u128;
    let mut scenario = started_resume_scenario(seed)?;
    let probe = scenario.fixture.store.probe_started_activity_lease_resume(
        &scenario.binding,
        &scenario.probe_request,
        scenario.service,
        scenario.initiating_session,
        Some(scenario.coordinator_session),
        timestamp(520)?,
    )?;
    assert!(probe.resumable_now());
    let request_id = Uuid::from_u128(seed + 0x500);
    let run_request = forge_domain::StartedActivityLeaseResumeRunRequest::new(
        scenario.scope.clone(),
        request_id,
        [0xA9; 32],
        probe.clone(),
        scenario.service,
    )?;
    let before = scenario
        .fixture
        .store
        .get_activity(scenario.fixture.activity.id())?
        .ok_or("Activity missing")?;
    let database_path = scenario.fixture.layout.database_path().clone();
    let blocker = Connection::open(&database_path)?;
    blocker.busy_timeout(std::time::Duration::ZERO)?;
    blocker.execute_batch("BEGIN IMMEDIATE")?;

    SQLITE_BUSY_WAIT_OBSERVED.store(false, std::sync::atomic::Ordering::Release);
    scenario
        .fixture
        .store
        .connection
        .busy_handler(Some(observe_sqlite_busy_wait))?;
    let clock_now = std::sync::Arc::new(std::sync::atomic::AtomicI64::new(
        probe.probe_expires_at().get().saturating_sub(1),
    ));
    let clock_called = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let clock_now_for_run = std::sync::Arc::clone(&clock_now);
    let clock_called_for_run = std::sync::Arc::clone(&clock_called);
    let run_thread = std::thread::spawn(move || {
        let result = scenario
            .fixture
            .store
            .run_started_activity_lease_resume_with_clock(
                &scenario.binding,
                &run_request,
                scenario.initiating_session,
                Some(scenario.coordinator_session),
                || {
                    clock_called_for_run.store(true, std::sync::atomic::Ordering::Release);
                    test_clock_timestamp(
                        clock_now_for_run.load(std::sync::atomic::Ordering::Acquire),
                    )
                },
            );
        (scenario, result)
    });

    if !wait_for_sqlite_lock_wait() {
        blocker.execute_batch("ROLLBACK")?;
        let _ = run_thread.join();
        return Err("Started resume did not wait on the immediate transaction lock".into());
    }
    assert!(
        !clock_called.load(std::sync::atomic::Ordering::Acquire),
        "Source time must not be sampled until BEGIN IMMEDIATE acquires the lock"
    );
    clock_now.store(
        probe.probe_expires_at().get().saturating_add(1),
        std::sync::atomic::Ordering::Release,
    );
    blocker.execute_batch("ROLLBACK")?;

    let (scenario, result) = run_thread.join().map_err(|_| "resume worker panicked")?;
    assert!(clock_called.load(std::sync::atomic::Ordering::Acquire));
    assert!(matches!(
        result,
        Err(WorkspaceStoreError::StartedActivityLeaseResume(_))
    ));
    assert_eq!(
        scenario
            .fixture
            .store
            .get_activity(scenario.fixture.activity.id())?,
        Some(before),
        "expired after lock wait must leave the Activity lease unchanged"
    );
    let receipt_count: i64 = scenario.fixture.store.connection.query_row(
        "SELECT COUNT(*) FROM started_activity_lease_resume_receipts",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(receipt_count, 0);
    fs::remove_dir_all(&scenario.fixture.root)?;
    Ok(())
}

struct StartedResumeScenario {
    fixture: FileFactFixture,
    workspace_id: forge_domain::WorkspaceId,
    binding: crate::WorkspaceJournalBinding,
    scope: forge_domain::ExpiredActivityRecoveryProbeScope,
    initiating_agent_id: forge_domain::AgentInstanceId,
    initiating_session_id: AgentSessionId,
    initiating_principal: AuthenticatedPrincipal,
    initiating_session: forge_domain::StartedActivityLeaseResumeSessionSnapshot,
    coordinator_session: forge_domain::StartedActivityLeaseResumeSessionSnapshot,
    service: forge_domain::StartedActivityLeaseResumeServiceIdentity,
    probe_request: forge_domain::StartedActivityLeaseResumeProbeRequest,
}

struct StartedResumeResult {
    receipt: forge_domain::StartedActivityLeaseResumeReceipt,
    run_request: forge_domain::StartedActivityLeaseResumeRunRequest,
    get_request: forge_domain::StartedActivityLeaseResumeGetRequest,
    current: forge_domain::RegisteredActivity,
}

fn started_resume_scenario(
    seed: u128,
) -> Result<StartedResumeScenario, Box<dyn std::error::Error>> {
    let mut fixture = file_fact_fixture("started-lease-resume-running", seed)?;
    let workspace = fixture.store.workspace()?;
    let offered = seed_assignment_for_offer_seal_migration(
        &mut fixture.store,
        workspace.id(),
        fixture.activity.id(),
    )?;
    let running = fixture.store.claim_agent_assignment(
        &forge_domain::ClaimAgentAssignment::new(
            offered.id(),
            offered.target(),
            forge_domain::AgentAssignmentRevision::INITIAL,
            timestamp(200)?,
        ),
        timestamp(200)?,
    )?;
    assert_eq!(running.state(), forge_domain::AgentAssignmentState::Running);
    let delegation = install_delegation_seal(&mut fixture.store, seed + 0x100, 300)?;
    let binding = fixture.store.journal_binding()?;
    let scope = forge_domain::ExpiredActivityRecoveryProbeScope::new(
        workspace.id(),
        workspace.revision(),
        workspace.location_id(),
        forge_domain::LocationRevision::INITIAL,
        b".".to_vec(),
        workspace.root_fingerprint(),
        binding.recovery_history_digest(),
    )?;
    let coordinator_binding = fixture
        .store
        .get_activity_coordinator(fixture.activity.id())?
        .ok_or("Coordinator missing")?;
    let coordinator_agent = fixture
        .store
        .get_agent(coordinator_binding.agent_id())?
        .ok_or("Coordinator Agent missing")?;
    let coordinator_session_id = coordinator_agent
        .session_id()
        .ok_or("Coordinator Session missing")?;
    let initiating_session_id = running.target().session_id();
    let initiating_principal = running.target().principal();
    let coordinator_session = session_snapshot(
        coordinator_session_id,
        coordinator_agent.principal(),
        seed + 0x201,
        150,
    )?;
    let initiating_session = session_snapshot(
        initiating_session_id,
        initiating_principal,
        seed + 0x202,
        150,
    )?;
    let service = forge_domain::StartedActivityLeaseResumeServiceIdentity::new(
        forge_domain::UnstartedActivityContinuationServiceIdentity::new(
            forge_domain::ForgeBackendId::from_uuid(Uuid::from_u128(seed + 0x300)),
            forge_domain::OrchestrationIssuerId::from_uuid(Uuid::from_u128(seed + 0x301)),
            runtime_id(seed + 0x302),
        )?,
        delegation.destination_id(),
    )?;
    // Assignment ownership was advanced through the durable production claim path.
    fixture.store.connection.execute(
        "UPDATE activities SET lease_until_ms=?1 WHERE activity_id=?2",
        params![
            400_i64,
            fixture.activity.id().into_uuid().as_bytes().as_slice()
        ],
    )?;
    let probe_request = forge_domain::StartedActivityLeaseResumeProbeRequest::new(
        scope.clone(),
        fixture.activity.id(),
        initiating_session_id,
        initiating_principal,
    )?;
    Ok(StartedResumeScenario {
        fixture,
        workspace_id: workspace.id(),
        binding,
        scope,
        initiating_agent_id: running.target().agent_id(),
        initiating_session_id,
        initiating_principal,
        initiating_session,
        coordinator_session,
        service,
        probe_request,
    })
}

fn assert_physical_blocker_preserves_lease(
    scenario: &mut StartedResumeScenario,
    seed: u128,
) -> Result<(), Box<dyn std::error::Error>> {
    let unknown_effect_migration = Uuid::from_u128(seed + 0x351);
    let activity_id = scenario.fixture.activity.id();
    let stop_request = crate::ExecutionStopRequest::new(
        Uuid::from_u128(seed + 0x350),
        scenario.workspace_id,
        Uuid::from_u128(seed + 0x352),
        scenario.fixture.owner,
        [0x60; 32],
        timestamp(450)?,
    );
    let _capture = scenario
        .fixture
        .store
        .capture_owned_workspace_stop(&stop_request)?;
    scenario.fixture.store.connection.execute(
        "INSERT INTO effect_fact_outbox_entries (migration_id,destination_id,workspace_id,fact_kind)
         VALUES (?1,?2,?3,7)",
        params![
            unknown_effect_migration.as_bytes().as_slice(),
            scenario.service.destination_id().as_bytes().as_slice(),
            scenario.workspace_id.into_uuid().as_bytes().as_slice(),
        ],
    )?;
    let before = scenario
        .fixture
        .store
        .get_activity(activity_id)?
        .ok_or("Activity missing before blocked run")?;
    let blocked_probe = scenario.fixture.store.probe_started_activity_lease_resume(
        &scenario.binding,
        &scenario.probe_request,
        scenario.service,
        scenario.initiating_session,
        Some(scenario.coordinator_session),
        timestamp(500)?,
    )?;
    assert!(!blocked_probe.resumable_now());
    assert_eq!(
        blocked_probe.blocker(),
        Some(forge_domain::StartedActivityLeaseResumeBlocker::PhysicalActivityEffectPresent),
    );
    assert!(
        forge_domain::StartedActivityLeaseResumeRunRequest::new(
            scenario.scope.clone(),
            Uuid::from_u128(seed + 0x3FF),
            [0xA3; 32],
            blocked_probe,
            scenario.service,
        )
        .is_err()
    );
    assert_eq!(
        scenario.fixture.store.get_activity(activity_id)?,
        Some(before),
        "blocked probe/run must leave the original lease tuple unchanged",
    );
    let receipt_count: i64 = scenario.fixture.store.connection.query_row(
        "SELECT COUNT(*) FROM started_activity_lease_resume_receipts",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(receipt_count, 0);
    scenario.fixture.store.connection.execute(
        "DELETE FROM effect_fact_outbox_entries WHERE migration_id=?1",
        params![unknown_effect_migration.as_bytes().as_slice()],
    )?;
    let _settlement =
        scenario
            .fixture
            .store
            .settle_owned_workspace_stop(&stop_request, true, timestamp(502)?)?;
    Ok(())
}

fn assert_run_rechecks_stop_fence_added_after_probe(
    scenario: &mut StartedResumeScenario,
    seed: u128,
) -> Result<(), Box<dyn std::error::Error>> {
    let activity_id = scenario.fixture.activity.id();
    let probe = scenario.fixture.store.probe_started_activity_lease_resume(
        &scenario.binding,
        &scenario.probe_request,
        scenario.service,
        scenario.initiating_session,
        Some(scenario.coordinator_session),
        timestamp(510)?,
    )?;
    assert!(probe.resumable_now());
    let before = scenario
        .fixture
        .store
        .get_activity(activity_id)?
        .ok_or("Activity missing before stale-probe run")?;
    let stop_request = crate::ExecutionStopRequest::new(
        Uuid::from_u128(seed + 0x410),
        scenario.workspace_id,
        Uuid::from_u128(seed + 0x411),
        scenario.fixture.owner,
        [0x61; 32],
        timestamp(511)?,
    );
    let _capture = scenario
        .fixture
        .store
        .capture_owned_workspace_stop(&stop_request)?;
    let request = forge_domain::StartedActivityLeaseResumeRunRequest::new(
        scenario.scope.clone(),
        Uuid::from_u128(seed + 0x420),
        [0xA6; 32],
        probe,
        scenario.service,
    )?;

    assert!(
        scenario
            .fixture
            .store
            .run_started_activity_lease_resume_with_clock(
                &scenario.binding,
                &request,
                scenario.initiating_session,
                Some(scenario.coordinator_session),
                || test_clock_timestamp(512),
            )
            .is_err()
    );
    assert_eq!(
        scenario.fixture.store.get_activity(activity_id)?,
        Some(before),
        "transactional recheck must preserve the lease when a stop arrives after Probe",
    );
    let receipt_count: i64 = scenario.fixture.store.connection.query_row(
        "SELECT COUNT(*) FROM started_activity_lease_resume_receipts",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        receipt_count, 0,
        "stale-probe rejection must write no receipt"
    );
    let _settlement =
        scenario
            .fixture
            .store
            .settle_owned_workspace_stop(&stop_request, true, timestamp(513)?)?;
    Ok(())
}

fn resume_once(
    scenario: &mut StartedResumeScenario,
    seed: u128,
) -> Result<StartedResumeResult, Box<dyn std::error::Error>> {
    let activity_id = scenario.fixture.activity.id();
    let probe = scenario.fixture.store.probe_started_activity_lease_resume(
        &scenario.binding,
        &scenario.probe_request,
        scenario.service,
        scenario.initiating_session,
        Some(scenario.coordinator_session),
        timestamp(520)?,
    )?;
    assert!(probe.started_work_proven());
    assert!(probe.resumable_now());
    assert_eq!(probe.blocker(), None);
    assert_eq!(
        scenario.fixture.store.get_activity(activity_id)?.as_ref(),
        Some(probe.expectation().activity()),
    );
    let request_id = Uuid::from_u128(seed + 0x400);
    let request_digest = [0xA4; 32];
    let run_request = forge_domain::StartedActivityLeaseResumeRunRequest::new(
        scenario.scope.clone(),
        request_id,
        request_digest,
        probe,
        scenario.service,
    )?;
    let operation = scenario
        .fixture
        .store
        .run_started_activity_lease_resume_with_clock(
            &scenario.binding,
            &run_request,
            scenario.initiating_session,
            Some(scenario.coordinator_session),
            || test_clock_timestamp(521),
        )?;
    let receipt = match operation {
        forge_domain::StartedActivityLeaseResumeOperation::Recorded(receipt) => receipt,
        forge_domain::StartedActivityLeaseResumeOperation::Replay(_) => {
            return Err("first run replayed".into());
        }
    };
    let current = scenario
        .fixture
        .store
        .get_activity(activity_id)?
        .ok_or("Activity missing after resume")?;
    assert_eq!(current.id(), scenario.fixture.activity.id());
    assert_eq!(current.revision(), scenario.fixture.activity.revision());
    assert_eq!(current.created_at(), scenario.fixture.activity.created_at());
    assert_eq!(current.updated_at(), scenario.fixture.activity.updated_at());
    assert_eq!(
        current.lease_owner_id(),
        Some(scenario.service.runtime_instance_id())
    );
    assert_eq!(current.lease_until(), Some(timestamp(300_521)?));
    assert_eq!(
        current.lease_revision().get(),
        scenario.fixture.activity.lease_revision().get() + 1,
    );
    let get_request = forge_domain::StartedActivityLeaseResumeGetRequest::new(
        scenario.scope.clone(),
        request_id,
        request_digest,
        activity_id,
        scenario.initiating_agent_id,
        scenario.initiating_session_id,
        scenario.initiating_principal,
    )?;
    let readback = scenario
        .fixture
        .store
        .started_activity_lease_resume_readback_for_request(&scenario.binding, &get_request)?
        .ok_or("receipt missing immediately after commit")?;
    assert_eq!(readback.receipt(), &receipt);
    Ok(StartedResumeResult {
        receipt,
        run_request,
        get_request,
        current,
    })
}

fn assert_replay_after_mutable_changes(
    scenario: &mut StartedResumeScenario,
    result: &StartedResumeResult,
) -> Result<(), Box<dyn std::error::Error>> {
    let current_coordinator = scenario
        .fixture
        .store
        .get_activity_coordinator(scenario.fixture.activity.id())?
        .ok_or("Coordinator missing before transfer")?;
    let current_agent = scenario
        .fixture
        .store
        .get_agent(current_coordinator.agent_id())?
        .ok_or("Coordinator Agent missing before transfer")?;
    let transferred = scenario.fixture.store.transfer_activity_coordinator(
        forge_domain::TransferActivityCoordinator::new(
            forge_domain::ActivityCoordinatorActor::new(
                scenario.workspace_id,
                scenario.fixture.activity.id(),
                current_coordinator.agent_id(),
                current_coordinator.revision(),
                current_agent.principal(),
                current_agent
                    .session_id()
                    .ok_or("Coordinator Session missing")?,
            ),
            scenario.initiating_agent_id,
            timestamp(523)?,
        ),
        timestamp(523)?,
    )?;
    assert_eq!(transferred.agent_id(), scenario.initiating_agent_id);
    assert_eq!(
        transferred.revision().get(),
        current_coordinator.revision().get() + 1
    );
    scenario
        .fixture
        .store
        .renew_activity_lease(&RenewActivityLease::new(
            scenario.fixture.activity.id(),
            scenario.service.runtime_instance_id(),
            result.current.lease_revision(),
            timestamp(600_000)?,
            timestamp(524)?,
        ))?;
    let replay = scenario
        .fixture
        .store
        .run_started_activity_lease_resume_with_clock(
            &scenario.binding,
            &result.run_request,
            scenario.initiating_session,
            Some(scenario.coordinator_session),
            || test_clock_timestamp(-1),
        )?;
    assert!(replay.is_replay());
    assert_eq!(replay.receipt(), &result.receipt);
    Ok(())
}

fn assert_reopened_receipt_and_cleanup(
    scenario: StartedResumeScenario,
    result: &StartedResumeResult,
) -> Result<(), Box<dyn std::error::Error>> {
    let root = scenario.fixture.root.clone();
    let existing =
        WorkspaceStateLayout::inspect_existing(scenario.fixture.layout.workspace_root())?
            .ok_or("Workspace missing")?;
    drop(scenario.fixture.store);
    let reopened = WorkspaceStore::open_existing(&existing)?;
    let reopened_readback = reopened
        .started_activity_lease_resume_readback_for_request(&scenario.binding, &result.get_request)?
        .ok_or("receipt missing after reopen")?;
    assert_eq!(reopened_readback.receipt(), &result.receipt);
    assert_eq!(
        reopened
            .get_activity(scenario.fixture.activity.id())?
            .ok_or("Activity missing after reopen")?
            .lease_until(),
        Some(timestamp(600_000)?),
    );
    let changed_digest = forge_domain::StartedActivityLeaseResumeGetRequest::new(
        scenario.scope,
        result.get_request.request_id(),
        [0xA5; 32],
        scenario.fixture.activity.id(),
        scenario.initiating_agent_id,
        scenario.initiating_session_id,
        scenario.initiating_principal,
    )?;
    assert!(
        reopened
            .started_activity_lease_resume_readback_for_request(&scenario.binding, &changed_digest)
            .is_err()
    );
    drop(reopened);
    fs::remove_dir_all(root)?;
    Ok(())
}

fn session_snapshot(
    id: AgentSessionId,
    principal: AuthenticatedPrincipal,
    request_seed: u128,
    updated_at: i64,
) -> Result<forge_domain::StartedActivityLeaseResumeSessionSnapshot, Box<dyn std::error::Error>> {
    let session = forge_domain::RegisteredAgentSession::open(
        id,
        forge_domain::AgentSessionOpenRequestId::from_uuid(Uuid::from_u128(request_seed)),
        principal,
        timestamp(updated_at)?,
    );
    Ok(
        forge_domain::StartedActivityLeaseResumeSessionSnapshot::new(
            session.id(),
            session.principal(),
            session.state(),
            session.revision(),
            session.updated_at(),
        )?,
    )
}
