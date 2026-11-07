use std::{
    cell::Cell,
    fs,
    sync::{Arc, Barrier},
    thread,
    time::Duration,
};

use forge_domain::{
    ActivityId, AgentInstanceId, AgentSessionId, AuthenticatedPrincipal, ForgeBackendId,
    HomeTransferSourceAction, HomeTransferSourceBinding, HomeTransferSourceGrant,
    HomeTransferSourceRequest, HomeTransferSourceScope, HomeTransferSourceSubject,
    HomeTransferSourceWitness, OrchestrationIssuerId, TimestampMillis,
};
use rusqlite::{Connection, ErrorCode, TransactionBehavior, params};
use uuid::Uuid;

use super::*;

mod artifact_migration;

struct Fixture {
    root: PathBuf,
    layout: WorkspaceStateLayout,
    store: WorkspaceStore,
    activity_id: ActivityId,
    agent: forge_domain::RegisteredAgentInstance,
    delegation: crate::AgentOperationsDelegation,
    issuer: OrchestrationIssuerId,
    backend: ForgeBackendId,
}

fn id(value: u128) -> Uuid {
    Uuid::from_u128(value)
}

fn source_clock(value: i64) -> Result<TimestampMillis, crate::HomeTransferStoreError> {
    TimestampMillis::new(value).map_err(|_| crate::HomeTransferStoreError::Clock)
}

fn fixture(label: &str, seed: u128) -> Result<Fixture, Box<dyn std::error::Error>> {
    let (root, layout, mut store, activity_id) = store_with_live_activity(label)?;
    let workspace_id = store.workspace()?.id();
    let agent = inventory_seeded_agent(&store, workspace_id, activity_id, seed + 0x10)?;
    let freeze = store.freeze_agent_operations(&crate::AgentOperationsFreezeRequest::new(
        id(seed + 0x20),
        id(seed + 0x21),
        timestamp(200)?,
    )?)?;
    let delegation = store.delegate_agent_operations(&freeze, [0x5C; 32], timestamp(201)?)?;
    Ok(Fixture {
        root,
        layout,
        store,
        activity_id,
        agent,
        delegation,
        issuer: OrchestrationIssuerId::from_uuid(id(seed + 0x30)),
        backend: ForgeBackendId::from_uuid(id(seed + 0x31)),
    })
}

fn binding_for(
    agent: &forge_domain::RegisteredAgentInstance,
) -> Result<HomeTransferSourceBinding, Box<dyn std::error::Error>> {
    Ok(HomeTransferSourceBinding::new(
        agent.activity_id(),
        agent.id(),
        agent.session_id().ok_or("source Agent has no Session")?,
        agent.principal(),
    )?)
}

fn source_request(
    store: &WorkspaceStore,
    identity: u128,
    witness_variant: u8,
    backend: ForgeBackendId,
    destination: Uuid,
    sessions: Vec<AgentSessionId>,
    bindings: Vec<HomeTransferSourceBinding>,
) -> Result<HomeTransferSourceRequest, Box<dyn std::error::Error>> {
    let workspace = store.workspace()?;
    let scope =
        HomeTransferSourceScope::new(workspace.id(), workspace.revision(), backend, destination)?;
    let subject = HomeTransferSourceSubject::new(
        id(identity + 1),
        1,
        id(identity + 2),
        id(identity + 3),
        id(identity + 4),
        id(identity + 5),
        1,
        1,
    )?;
    let witness = HomeTransferSourceWitness::new(
        id(identity),
        [witness_variant; 32],
        [witness_variant.wrapping_add(1); 32],
    )?;
    Ok(HomeTransferSourceRequest::new(
        witness, scope, subject, sessions, bindings,
    )?)
}

fn one_agent_request(
    fixture: &Fixture,
    identity: u128,
    witness_variant: u8,
) -> Result<HomeTransferSourceRequest, Box<dyn std::error::Error>> {
    let binding = binding_for(&fixture.agent)?;
    let session = binding.session_id();
    source_request(
        &fixture.store,
        identity,
        witness_variant,
        fixture.backend,
        fixture.delegation.destination_id(),
        vec![session],
        vec![binding],
    )
}

fn source_grant(
    request: &HomeTransferSourceRequest,
    issuer: OrchestrationIssuerId,
    action: HomeTransferSourceAction,
    issued_at: i64,
    expires_at: i64,
) -> Result<HomeTransferSourceGrant, Box<dyn std::error::Error>> {
    Ok(HomeTransferSourceGrant::new(
        issuer,
        action,
        request.request_digest(),
        timestamp(issued_at)?,
        timestamp(expires_at)?,
    )?)
}

fn owner_counts(connection: &Connection) -> Result<[i64; 5], rusqlite::Error> {
    connection.query_row(
        "SELECT
             (SELECT COUNT(*) FROM home_transfer_source_operations),
             (SELECT COUNT(*) FROM home_transfer_source_subjects),
             (SELECT COUNT(*) FROM home_transfer_source_sessions),
             (SELECT COUNT(*) FROM home_transfer_source_agents),
             (SELECT COUNT(*) FROM home_transfer_source_activities)",
        [],
        |row| {
            Ok([
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ])
        },
    )
}

fn home_fences(connection: &Connection) -> Result<[i64; 4], rusqlite::Error> {
    connection.query_row(
        "SELECT
             (SELECT COUNT(*) FROM home_transfer_source_subjects),
             (SELECT COUNT(*) FROM home_transfer_source_sessions),
             (SELECT COUNT(*) FROM home_transfer_source_agents),
             (SELECT COUNT(*) FROM home_transfer_source_activities)",
        [],
        |row| Ok([row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?]),
    )
}

#[test]
fn replacing_a_live_wal_during_capture_never_returns_confirmed_preparation()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = fixture("home-source-replaced-wal", 0xF100)?;
    let request = one_agent_request(&fixture, 0xF200, 9)?;
    let wal = super::super::sidecar_path(&fixture.layout.database_path(), "-wal");
    let saved = fixture.root.join("original-home-source-wal");
    assert!(wal.is_file());
    let result = fixture.store.prepare_home_transfer_source(
        &request,
        source_grant(
            &request,
            fixture.issuer,
            HomeTransferSourceAction::Prepare,
            250,
            500,
        )?,
        fixture.issuer,
        fixture.backend,
        fixture.delegation.destination_id(),
        || {
            fs::rename(&wal, &saved).map_err(|_| crate::HomeTransferStoreError::Clock)?;
            fs::copy(&saved, &wal).map_err(|_| crate::HomeTransferStoreError::Clock)?;
            source_clock(300)
        },
    );
    assert!(
        matches!(result,Err(WorkspaceStoreError::HomeTransferReadbackRequired {preparation_id,..}) if preparation_id==request.witness().preparation_id())
    );
    drop(fixture.store);
    fs::remove_dir_all(fixture.root)?;
    Ok(())
}

#[test]
fn abort_before_prepare_is_an_immutable_tombstone_without_fences()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = fixture("home-source-abort-first", 0xE100)?;
    let request = one_agent_request(&fixture, 0xE200, 1)?;
    let before = owner_counts(&fixture.store.connection)?;
    let abort_grant = source_grant(
        &request,
        fixture.issuer,
        HomeTransferSourceAction::AbortUnstarted,
        250,
        500,
    )?;
    let aborted = fixture.store.abort_unstarted_home_transfer_source(
        &request,
        abort_grant,
        fixture.issuer,
        fixture.backend,
        fixture.delegation.destination_id(),
        || source_clock(300),
    )?;
    let original = aborted.record().clone();
    assert!(matches!(
        aborted,
        crate::HomeTransferSourceOutcome::Created(_)
    ));
    assert_eq!(
        original.state(),
        crate::HomeTransferSourceState::AbortedUnstarted
    );
    assert!(original.inventory_payload().is_none());
    assert!(original.inventory_digest().is_none());
    assert_eq!(
        owner_counts(&fixture.store.connection)?,
        [before[0] + 1, 0, 0, 0, 0]
    );

    let replay_grant = source_grant(
        &request,
        fixture.issuer,
        HomeTransferSourceAction::Prepare,
        250,
        500,
    )?;
    let clock_called = Cell::new(false);
    let replay = fixture.store.prepare_home_transfer_source(
        &request,
        replay_grant,
        fixture.issuer,
        fixture.backend,
        fixture.delegation.destination_id(),
        || {
            clock_called.set(true);
            source_clock(301)
        },
    )?;
    assert!(matches!(
        replay,
        crate::HomeTransferSourceOutcome::Existing(_)
    ));
    assert!(
        !clock_called.get(),
        "replay must not sample a fresh source time"
    );
    assert_eq!(replay.record(), &original);
    assert_eq!(home_fences(&fixture.store.connection)?, [0; 4]);
    let exact = fixture.store.get_home_transfer_source(
        id(0xE200),
        fixture.issuer,
        fixture.backend,
        fixture.delegation.destination_id(),
    )?;
    assert_eq!(exact.as_ref(), Some(&original));

    drop(fixture.store);
    fs::remove_dir_all(fixture.root)?;
    Ok(())
}

#[test]
fn prepared_replay_and_abort_preserve_the_original_capsule_after_source_revision_changes()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = fixture("home-source-prepare-replay", 0xE300)?;
    let request = one_agent_request(&fixture, 0xE400, 2)?;
    let prepare_grant = source_grant(
        &request,
        fixture.issuer,
        HomeTransferSourceAction::Prepare,
        250,
        500,
    )?;
    let prepared = fixture.store.prepare_home_transfer_source(
        &request,
        prepare_grant,
        fixture.issuer,
        fixture.backend,
        fixture.delegation.destination_id(),
        || source_clock(300),
    )?;
    assert!(matches!(
        &prepared,
        crate::HomeTransferSourceOutcome::Created(_)
    ));
    let original = prepared.record().clone();
    let payload = original
        .inventory_payload()
        .ok_or("Prepared capsule missing")?
        .to_vec();
    assert_eq!(original.state(), crate::HomeTransferSourceState::Prepared);
    assert!(original.inventory_digest().is_some());
    let fences_before = home_fences(&fixture.store.connection)?;
    assert_eq!(fences_before, [1, 1, 1, 1]);

    let abort_grant = source_grant(
        &request,
        fixture.issuer,
        HomeTransferSourceAction::AbortUnstarted,
        250,
        500,
    )?;
    let clock_called = Cell::new(false);
    let abort_replay = fixture.store.abort_unstarted_home_transfer_source(
        &request,
        abort_grant,
        fixture.issuer,
        fixture.backend,
        fixture.delegation.destination_id(),
        || {
            clock_called.set(true);
            source_clock(301)
        },
    )?;
    assert!(matches!(
        abort_replay,
        crate::HomeTransferSourceOutcome::Existing(_)
    ));
    assert!(!clock_called.get());
    assert_eq!(abort_replay.record(), &original);
    assert_eq!(home_fences(&fixture.store.connection)?, fences_before);

    // Advance the live Workspace revision behind the historical journal.
    // Exact Get must continue returning the original request-scoped capsule.
    fixture.store.connection.execute(
        "UPDATE workspace SET revision = revision + 1, updated_at_ms = updated_at_ms + 1
         WHERE singleton = 1",
        [],
    )?;
    fixture.store.capture_sidecar_identities()?;
    assert!(
        fixture.store.workspace()?.revision().get() > request.scope().workspace_revision().get()
    );

    let exact = fixture
        .store
        .get_home_transfer_source(
            id(0xE400),
            fixture.issuer,
            fixture.backend,
            fixture.delegation.destination_id(),
        )?
        .ok_or("exact source history missing")?;
    assert_eq!(exact, original);
    assert_eq!(exact.inventory_payload(), Some(payload.as_slice()));
    let prepare_replay_grant = source_grant(
        &request,
        fixture.issuer,
        HomeTransferSourceAction::Prepare,
        250,
        500,
    )?;
    let replay = fixture.store.prepare_home_transfer_source(
        &request,
        prepare_replay_grant,
        fixture.issuer,
        fixture.backend,
        fixture.delegation.destination_id(),
        || Err(crate::HomeTransferStoreError::Clock),
    )?;
    assert!(matches!(
        replay,
        crate::HomeTransferSourceOutcome::Existing(_)
    ));
    assert_eq!(replay.record(), &original);

    drop(fixture.store);
    fs::remove_dir_all(fixture.root)?;
    Ok(())
}

#[test]
fn same_preparation_id_with_changed_request_payload_conflicts_without_replacing_history()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = fixture("home-source-payload-conflict", 0xE500)?;
    let original_request = one_agent_request(&fixture, 0xE600, 3)?;
    let original = fixture.store.prepare_home_transfer_source(
        &original_request,
        source_grant(
            &original_request,
            fixture.issuer,
            HomeTransferSourceAction::Prepare,
            250,
            500,
        )?,
        fixture.issuer,
        fixture.backend,
        fixture.delegation.destination_id(),
        || source_clock(300),
    )?;
    let row_counts = owner_counts(&fixture.store.connection)?;
    let changed_request = one_agent_request(&fixture, 0xE600, 4)?;
    assert_eq!(
        changed_request.witness().preparation_id(),
        original_request.witness().preparation_id(),
    );
    assert_ne!(
        changed_request.request_digest(),
        original_request.request_digest()
    );
    let clock_called = Cell::new(false);
    let conflict = fixture.store.prepare_home_transfer_source(
        &changed_request,
        source_grant(
            &changed_request,
            fixture.issuer,
            HomeTransferSourceAction::Prepare,
            250,
            500,
        )?,
        fixture.issuer,
        fixture.backend,
        fixture.delegation.destination_id(),
        || {
            clock_called.set(true);
            source_clock(301)
        },
    );
    assert!(matches!(
        conflict,
        Err(WorkspaceStoreError::HomeTransfer(
            crate::HomeTransferStoreError::Conflict(_)
        ))
    ));
    assert!(!clock_called.get());
    assert_eq!(owner_counts(&fixture.store.connection)?, row_counts);
    let exact = fixture
        .store
        .get_home_transfer_source(
            id(0xE600),
            fixture.issuer,
            fixture.backend,
            fixture.delegation.destination_id(),
        )?
        .ok_or("original source history missing")?;
    assert_eq!(&exact, original.record());

    drop(fixture.store);
    fs::remove_dir_all(fixture.root)?;
    Ok(())
}

#[test]
fn issuer_backend_destination_and_expiry_rejections_leave_no_source_mutations()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = fixture("home-source-admission-rejections", 0xE700)?;
    let request = one_agent_request(&fixture, 0xE800, 5)?;
    let before = owner_counts(&fixture.store.connection)?;

    let wrong_issuer = OrchestrationIssuerId::from_uuid(id(0xE8FF));
    let issuer_error = fixture.store.prepare_home_transfer_source(
        &request,
        source_grant(
            &request,
            fixture.issuer,
            HomeTransferSourceAction::Prepare,
            250,
            500,
        )?,
        wrong_issuer,
        fixture.backend,
        fixture.delegation.destination_id(),
        || Err(crate::HomeTransferStoreError::Clock),
    );
    assert!(matches!(
        issuer_error,
        Err(WorkspaceStoreError::HomeTransfer(
            crate::HomeTransferStoreError::Domain(
                forge_domain::HomeTransferSourceError::IssuerMismatch
            )
        ))
    ));
    assert_eq!(owner_counts(&fixture.store.connection)?, before);

    let wrong_backend = ForgeBackendId::from_uuid(id(0xE8FE));
    let backend_error = fixture.store.prepare_home_transfer_source(
        &request,
        source_grant(
            &request,
            fixture.issuer,
            HomeTransferSourceAction::Prepare,
            250,
            500,
        )?,
        fixture.issuer,
        wrong_backend,
        fixture.delegation.destination_id(),
        || Err(crate::HomeTransferStoreError::Clock),
    );
    assert!(matches!(
        backend_error,
        Err(WorkspaceStoreError::HomeTransfer(
            crate::HomeTransferStoreError::Conflict("configured service scope")
        ))
    ));
    assert_eq!(owner_counts(&fixture.store.connection)?, before);

    let wrong_destination = id(0xE8FD);
    let destination_error = fixture.store.prepare_home_transfer_source(
        &request,
        source_grant(
            &request,
            fixture.issuer,
            HomeTransferSourceAction::Prepare,
            250,
            500,
        )?,
        fixture.issuer,
        fixture.backend,
        wrong_destination,
        || Err(crate::HomeTransferStoreError::Clock),
    );
    assert!(matches!(
        destination_error,
        Err(WorkspaceStoreError::HomeTransfer(
            crate::HomeTransferStoreError::Conflict("configured service scope")
        ))
    ));
    assert_eq!(owner_counts(&fixture.store.connection)?, before);

    let expired = fixture.store.prepare_home_transfer_source(
        &request,
        source_grant(
            &request,
            fixture.issuer,
            HomeTransferSourceAction::Prepare,
            250,
            300,
        )?,
        fixture.issuer,
        fixture.backend,
        fixture.delegation.destination_id(),
        || source_clock(300),
    );
    assert!(matches!(
        expired,
        Err(WorkspaceStoreError::HomeTransfer(
            crate::HomeTransferStoreError::Domain(forge_domain::HomeTransferSourceError::Expired)
        ))
    ));
    assert_eq!(owner_counts(&fixture.store.connection)?, before);

    drop(fixture.store);
    fs::remove_dir_all(fixture.root)?;
    Ok(())
}

#[test]
fn source_clock_is_sampled_only_after_capture_under_the_immediate_writer_lock()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = fixture("home-source-clock-order", 0xE900)?;
    let actual_binding = binding_for(&fixture.agent)?;
    let session = actual_binding.session_id();
    let wrong_binding = HomeTransferSourceBinding::new(
        fixture.activity_id,
        AgentInstanceId::from_uuid(id(0xE9FF)),
        session,
        fixture.agent.principal(),
    )?;
    let invalid_capture = source_request(
        &fixture.store,
        0xEA00,
        6,
        fixture.backend,
        fixture.delegation.destination_id(),
        vec![session],
        vec![wrong_binding],
    )?;
    let clock_called = Cell::new(false);
    let capture_error = fixture.store.prepare_home_transfer_source(
        &invalid_capture,
        source_grant(
            &invalid_capture,
            fixture.issuer,
            HomeTransferSourceAction::Prepare,
            250,
            500,
        )?,
        fixture.issuer,
        fixture.backend,
        fixture.delegation.destination_id(),
        || {
            clock_called.set(true);
            source_clock(300)
        },
    );
    assert!(matches!(
        capture_error,
        Err(WorkspaceStoreError::HomeTransfer(crate::HomeTransferStoreError::Inventory(error)))
            if matches!(*error, crate::HomeTransferSourceInventoryError::BindingConflict)
    ));
    assert!(
        !clock_called.get(),
        "failed capture must not sample admission time"
    );
    assert_eq!(owner_counts(&fixture.store.connection)?, [0; 5]);

    let request = one_agent_request(&fixture, 0xEA10, 7)?;
    let mut probe = Connection::open(fixture.layout.database_path())?;
    probe.busy_timeout(Duration::ZERO)?;
    let mut clock_calls = 0_u8;
    let outcome = fixture.store.prepare_home_transfer_source(
        &request,
        source_grant(
            &request,
            fixture.issuer,
            HomeTransferSourceAction::Prepare,
            250,
            500,
        )?,
        fixture.issuer,
        fixture.backend,
        fixture.delegation.destination_id(),
        || {
            clock_calls += 1;
            match probe.transaction_with_behavior(TransactionBehavior::Immediate) {
                Ok(tx) => {
                    drop(tx);
                    Err(crate::HomeTransferStoreError::Conflict(
                        "clock callback ran without the source write lock",
                    ))
                }
                Err(rusqlite::Error::SqliteFailure(code, _))
                    if matches!(
                        code.code,
                        ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked
                    ) =>
                {
                    source_clock(300)
                }
                Err(error) => Err(crate::HomeTransferStoreError::Sqlite(error)),
            }
        },
    )?;
    assert!(matches!(
        outcome,
        crate::HomeTransferSourceOutcome::Created(_)
    ));
    assert_eq!(clock_calls, 1);

    drop(probe);
    drop(fixture.store);
    fs::remove_dir_all(fixture.root)?;
    Ok(())
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one source capture proves pending obligation preservation and narrow admission together"
)]
fn pending_reservation_and_running_assignment_are_only_captured_and_session_fence_is_narrow()
-> Result<(), Box<dyn std::error::Error>> {
    let (root, _layout, mut store, activity_id) =
        store_with_live_activity("home-source-pending-and-running")?;
    let workspace_id = store.workspace()?.id();
    let offered = seed_assignment_for_offer_seal_migration(&mut store, workspace_id, activity_id)?;
    let running = store.claim_agent_assignment(
        &forge_domain::ClaimAgentAssignment::new(
            offered.id(),
            offered.target(),
            offered.revision(),
            timestamp(8)?,
        ),
        timestamp(99)?,
    )?;
    assert_eq!(running.state(), forge_domain::AgentAssignmentState::Running);
    let target = store
        .get_agent(running.target().agent_id())?
        .ok_or("running Assignment target is missing")?;
    let target_session = target.session_id().ok_or("target Session is missing")?;

    let freeze = store.freeze_agent_operations(&crate::AgentOperationsFreezeRequest::new(
        id(0xEB00),
        id(0xEB01),
        timestamp(20)?,
    )?)?;
    let pending_agent_id = AgentInstanceId::from_uuid(id(0xEB10));
    let pending_session_id = AgentSessionId::from_uuid(id(0xEB11));
    let pending_request = crate::AgentBindingReservationRequest::new(
        id(0xEB12),
        activity_id,
        pending_agent_id,
        pending_session_id,
        AuthenticatedPrincipal::TrustedStdio,
        timestamp(21)?,
    )?;
    let reservation = store.reserve_agent_binding(&freeze, &pending_request, timestamp(22)?)?;
    let delegation = store.delegate_agent_operations(&freeze, [0x5C; 32], timestamp(23)?)?;

    let binding = binding_for(&target)?;
    let issuer = OrchestrationIssuerId::from_uuid(id(0xEB20));
    let backend = ForgeBackendId::from_uuid(id(0xEB21));
    let request = source_request(
        &store,
        0xEB30,
        8,
        backend,
        delegation.destination_id(),
        vec![target_session, pending_session_id],
        vec![binding],
    )?;
    let assignment_before: (i64, i64) = store.connection.query_row(
        "SELECT state, revision FROM agent_assignments WHERE assignment_id = ?1",
        params![running.id().into_uuid().as_bytes()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let reservation_before = store
        .agent_binding_reservation(reservation.request().request_id())?
        .ok_or("pending reservation disappeared before capture")?;
    assert_eq!(
        reservation_before.request().request_id(),
        reservation.request().request_id()
    );

    let outcome = store.prepare_home_transfer_source(
        &request,
        source_grant(
            &request,
            issuer,
            HomeTransferSourceAction::Prepare,
            250,
            500,
        )?,
        issuer,
        backend,
        delegation.destination_id(),
        || source_clock(300),
    )?;
    let record = outcome.record();
    assert_eq!(record.state(), crate::HomeTransferSourceState::Prepared);
    assert!(record.inventory_payload().is_some());
    assert!(record.inventory_digest().is_some());
    assert_eq!(
        store
            .agent_binding_reservation(reservation.request().request_id())?
            .as_ref(),
        Some(&reservation_before),
        "Prepare records the pending reservation without activating it",
    );
    assert!(store.get_agent(pending_agent_id)?.is_none());
    let assignment_after: (i64, i64) = store.connection.query_row(
        "SELECT state, revision FROM agent_assignments WHERE assignment_id = ?1",
        params![running.id().into_uuid().as_bytes()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(assignment_after, assignment_before);
    assert_eq!(
        assignment_after.0, 1,
        "the source Assignment remains Running"
    );
    assert_eq!(home_fences(&store.connection)?, [1, 2, 1, 1]);

    let held_binding = crate::AgentBindingReservationRequest::new(
        id(0xEB40),
        activity_id,
        AgentInstanceId::from_uuid(id(0xEB41)),
        target_session,
        AuthenticatedPrincipal::TrustedStdio,
        timestamp(24)?,
    )?;
    let held_error = store
        .reserve_agent_binding(&freeze, &held_binding, timestamp(25)?)
        .err()
        .ok_or("the captured Session unexpectedly admitted a binding")?;
    assert!(
        held_error.to_string().contains("fences fresh work"),
        "held Session rejection should name the Home source fence: {held_error:?}",
    );

    let unrelated_session = AgentSessionId::from_uuid(id(0xEB51));
    let unrelated_binding = crate::AgentBindingReservationRequest::new(
        id(0xEB50),
        activity_id,
        AgentInstanceId::from_uuid(id(0xEB52)),
        unrelated_session,
        AuthenticatedPrincipal::TrustedStdio,
        timestamp(24)?,
    )?;
    let unrelated = store.reserve_agent_binding(&freeze, &unrelated_binding, timestamp(25)?)?;
    assert_eq!(unrelated.request().session_id(), unrelated_session);

    drop(store);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn concurrent_prepare_and_abort_on_two_sqlite_connections_have_one_durable_winner()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture("home-source-concurrent-prepare-abort", 0xEC00)?;
    let request = one_agent_request(&fixture, 0xEC80, 9)?;
    let preparation_id = request.witness().preparation_id();
    let destination = fixture.delegation.destination_id();
    let prepare_grant = source_grant(
        &request,
        fixture.issuer,
        HomeTransferSourceAction::Prepare,
        250,
        500,
    )?;
    let abort_grant = source_grant(
        &request,
        fixture.issuer,
        HomeTransferSourceAction::AbortUnstarted,
        250,
        500,
    )?;
    let database = fixture.layout.database_path();
    let issuer = fixture.issuer;
    let backend = fixture.backend;
    drop(fixture.store);

    let mut prepare_connection = Connection::open(&database)?;
    prepare_connection.busy_timeout(Duration::from_secs(5))?;
    let mut abort_connection = Connection::open(&database)?;
    abort_connection.busy_timeout(Duration::from_secs(5))?;
    let barrier = Arc::new(Barrier::new(3));

    let prepare_barrier = Arc::clone(&barrier);
    let prepare_request = request.clone();
    let prepare_thread = thread::spawn(move || {
        prepare_barrier.wait();
        crate::workspace_home_transfers::apply(
            &mut prepare_connection,
            &prepare_request,
            HomeTransferSourceAction::Prepare,
            prepare_grant,
            issuer,
            backend,
            destination,
            || source_clock(300),
        )
    });

    let abort_barrier = Arc::clone(&barrier);
    let abort_thread_request = request.clone();
    let abort_thread = thread::spawn(move || {
        abort_barrier.wait();
        crate::workspace_home_transfers::apply(
            &mut abort_connection,
            &abort_thread_request,
            HomeTransferSourceAction::AbortUnstarted,
            abort_grant,
            issuer,
            backend,
            destination,
            || source_clock(300),
        )
    });

    barrier.wait();
    let prepare_outcome = prepare_thread
        .join()
        .map_err(|_| "Prepare thread panicked")??;
    let abort_outcome = abort_thread.join().map_err(|_| "Abort thread panicked")??;
    let prepare_created = matches!(
        &prepare_outcome,
        crate::HomeTransferSourceOutcome::Created(_)
    );
    let abort_created = matches!(&abort_outcome, crate::HomeTransferSourceOutcome::Created(_));
    assert_ne!(
        prepare_created, abort_created,
        "IMMEDIATE owner admits one winner"
    );
    assert_eq!(prepare_outcome.record(), abort_outcome.record());

    let readback = Connection::open(&database)?;
    readback.busy_timeout(Duration::from_secs(5))?;
    let durable = crate::workspace_home_transfers::get(&readback, preparation_id)?
        .ok_or("concurrent winner was not durably readable")?;
    assert_eq!(prepare_outcome.record(), &durable);
    assert_eq!(abort_outcome.record(), &durable);
    match durable.state() {
        crate::HomeTransferSourceState::Prepared => {
            assert!(prepare_created);
            assert!(!abort_created);
            assert_eq!(home_fences(&readback)?, [1, 1, 1, 1]);
        }
        crate::HomeTransferSourceState::AbortedUnstarted => {
            assert!(!prepare_created);
            assert!(abort_created);
            assert_eq!(home_fences(&readback)?, [0; 4]);
        }
    }

    drop(readback);
    fs::remove_dir_all(fixture.root)?;
    Ok(())
}
mod retirement;
