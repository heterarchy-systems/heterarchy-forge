use super::*;
mod integrity;
mod migration;
use forge_domain::{
    AgentBindingRejectionReason, AgentDeclaredRole, AgentDisplayName, AgentInstanceId,
    AgentSessionId, AgentTransportKind, AuthenticatedPrincipal, DirectTokenId,
    HomeTransferReservationRetirementGrant, HomeTransferReservationRetirementRequest,
    HomeTransferSourceScope, TimestampMillis,
};
use rusqlite::{TransactionBehavior, params};

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

fn pending_reservation(
    fixture: &mut Fixture,
    seed: u128,
    principal: AuthenticatedPrincipal,
) -> TestResult<crate::AgentBindingReservation> {
    let request = crate::AgentBindingReservationRequest::new(
        id(seed),
        fixture.activity_id,
        AgentInstanceId::from_uuid(id(seed + 1)),
        AgentSessionId::from_uuid(id(seed + 2)),
        principal,
        timestamp(202)?,
    )?;
    let freeze = fixture.delegation.freeze().clone();
    Ok(fixture
        .store
        .reserve_agent_binding(&freeze, &request, timestamp(203)?)?)
}

fn prepare_parent(
    fixture: &mut Fixture,
    identity: u128,
    reservation: &crate::AgentBindingReservation,
    extra_agents: &[forge_domain::RegisteredAgentInstance],
) -> TestResult<crate::HomeTransferSourceRecord> {
    let mut sessions = vec![
        fixture
            .agent
            .session_id()
            .ok_or("fixture Source Agent has no Session")?,
        reservation.request().session_id(),
    ];
    let mut bindings = vec![binding_for(&fixture.agent)?];
    for agent in extra_agents {
        if let Some(session_id) = agent.session_id() {
            if !sessions.contains(&session_id) {
                sessions.push(session_id);
            }
            bindings.push(binding_for(agent)?);
        }
    }
    let request = source_request(
        &fixture.store,
        identity,
        0x72,
        fixture.backend,
        fixture.delegation.destination_id(),
        sessions,
        bindings,
    )?;
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
        || source_clock(300),
    )?;
    Ok(outcome.record().clone())
}

fn retirement_request(
    fixture: &Fixture,
    parent: &crate::HomeTransferSourceRecord,
    reservation: &crate::AgentBindingReservation,
) -> TestResult<HomeTransferReservationRetirementRequest> {
    let workspace = fixture.store.workspace()?;
    Ok(HomeTransferReservationRetirementRequest::new(
        HomeTransferSourceScope::new(
            workspace.id(),
            workspace.revision(),
            fixture.backend,
            fixture.delegation.destination_id(),
        )?,
        parent.request().witness().preparation_id(),
        parent.request().request_digest(),
        *parent.outcome_digest(),
        reservation.request().request_id(),
    )?)
}

fn retirement_grant(
    request: &HomeTransferReservationRetirementRequest,
    issuer: OrchestrationIssuerId,
) -> TestResult<HomeTransferReservationRetirementGrant> {
    Ok(HomeTransferReservationRetirementGrant::new(
        issuer,
        request.request_digest(),
        timestamp(350)?,
        timestamp(600)?,
    )?)
}

fn retirement(
    fixture: &mut Fixture,
    request: &HomeTransferReservationRetirementRequest,
    grant: HomeTransferReservationRetirementGrant,
    observed_at: i64,
) -> Result<crate::HomeTransferReservationRetirementOutcome, crate::HomeTransferStoreError> {
    crate::workspace_home_transfers::retirements::retire(
        &mut fixture.store.connection,
        request,
        grant,
        fixture.issuer,
        fixture.backend,
        fixture.delegation.destination_id(),
        || source_clock(observed_at),
    )
}

struct RetirementCase {
    fixture: Fixture,
    selected: crate::AgentBindingReservation,
    unrelated: crate::AgentBindingReservation,
    parent: crate::HomeTransferSourceRecord,
    parent_bytes: Vec<u8>,
    request: HomeTransferReservationRetirementRequest,
    grant: HomeTransferReservationRetirementGrant,
}

fn retirement_case(label: &str, seed: u128) -> TestResult<RetirementCase> {
    let mut fixture = fixture(label, seed)?;
    let selected = pending_reservation(
        &mut fixture,
        seed + 0x100,
        AuthenticatedPrincipal::TrustedStdio,
    )?;
    let unrelated = pending_reservation(
        &mut fixture,
        seed + 0x200,
        AuthenticatedPrincipal::TrustedStdio,
    )?;
    assert_eq!(
        selected.request().activity_id(),
        unrelated.request().activity_id()
    );
    let parent = prepare_parent(&mut fixture, seed + 0x300, &selected, &[])?;
    let parent_bytes = parent.to_snapshot_bytes()?;
    let request = retirement_request(&fixture, &parent, &selected)?;
    let grant = retirement_grant(&request, fixture.issuer)?;
    Ok(RetirementCase {
        fixture,
        selected,
        unrelated,
        parent,
        parent_bytes,
        request,
        grant,
    })
}

fn create_retirement(
    case: &mut RetirementCase,
) -> TestResult<crate::HomeTransferReservationRetirementRecord> {
    match retirement(&mut case.fixture, &case.request, case.grant, 400)? {
        crate::HomeTransferReservationRetirementOutcome::Created(record) => Ok(record),
        crate::HomeTransferReservationRetirementOutcome::Existing(record) => {
            Err(format!("expected Created, received Existing({record:?})").into())
        }
    }
}

#[test]
fn unused_retirement_replays_and_reads_by_exact_identity() -> TestResult<()> {
    let mut case = retirement_case("home-source-reservation-retirement-replay", 0xFA00)?;
    let record = create_retirement(&mut case)?;
    // The retirement owner was introduced in schema v72. Its exact stored
    // receipt remains readable when a historical v72 Workspace is inspected.
    case.fixture
        .store
        .connection
        .pragma_update(None, "user_version", 72_i64)?;
    let reservation_id = case.selected.request().request_id();
    let parent_id = case.parent.request().witness().preparation_id();
    assert_eq!(record.request(), &case.request);
    assert_eq!(record.issuer(), case.fixture.issuer);
    assert_eq!(record.observed_at(), timestamp(400)?);
    assert_eq!(record.grant_issued_at(), timestamp(350)?);
    assert_eq!(record.grant_expires_at(), timestamp(600)?);
    assert_eq!(
        record.source_inventory_digest(),
        case.parent
            .inventory_digest()
            .ok_or("missing source inventory digest")?
    );

    let clock_sampled = std::cell::Cell::new(false);
    let replay = crate::workspace_home_transfers::retirements::retire(
        &mut case.fixture.store.connection,
        &case.request,
        case.grant,
        case.fixture.issuer,
        case.fixture.backend,
        case.fixture.delegation.destination_id(),
        || {
            clock_sampled.set(true);
            source_clock(401)
        },
    )?;
    assert!(
        !clock_sampled.get(),
        "exact replay must not sample a new Source clock"
    );
    match replay {
        crate::HomeTransferReservationRetirementOutcome::Created(created) => {
            return Err(format!("replay created a second receipt: {created:?}").into());
        }
        crate::HomeTransferReservationRetirementOutcome::Existing(existing) => {
            assert_eq!(existing, record);
        }
    }
    assert_eq!(
        crate::workspace_home_transfers::retirements::get(
            &case.fixture.store.connection,
            parent_id,
            reservation_id,
        )?,
        Some(record.clone()),
    );
    assert_eq!(
        crate::workspace_home_transfers::retirements::get_for_reservation(
            &case.fixture.store.connection,
            reservation_id,
        )?,
        Some(record),
    );
    assert!(
        crate::workspace_home_transfers::retirements::is_valid_settlement(
            &case.fixture.store.connection,
            &case.selected,
        )?
    );

    drop(case.fixture.store);
    std::fs::remove_dir_all(case.fixture.root)?;
    Ok(())
}

#[test]
fn same_reservation_business_keys_conflict_after_retirement() -> TestResult<()> {
    let mut case = retirement_case("home-source-retirement-business-key-conflict", 0xFA00)?;
    let _record = create_retirement(&mut case)?;
    let changed_request = HomeTransferReservationRetirementRequest::new(
        case.request.scope(),
        case.request.preparation_id(),
        case.request.source_request_digest(),
        [0x9A; 32],
        case.request.reservation_request_id(),
    )?;
    let changed_grant = retirement_grant(&changed_request, case.fixture.issuer)?;
    assert!(matches!(
        retirement(&mut case.fixture, &changed_request, changed_grant, 402),
        Err(crate::HomeTransferStoreError::Conflict(
            "reservation retirement business key"
        ))
    ));

    let duplicate_parent_request = HomeTransferReservationRetirementRequest::new(
        case.request.scope(),
        id(0xFD99),
        case.request.source_request_digest(),
        case.request.source_outcome_digest(),
        case.request.reservation_request_id(),
    )?;
    let duplicate_parent_grant = retirement_grant(&duplicate_parent_request, case.fixture.issuer)?;
    assert!(matches!(
        retirement(
            &mut case.fixture,
            &duplicate_parent_request,
            duplicate_parent_grant,
            402
        ),
        Err(crate::HomeTransferStoreError::Conflict(
            "reservation already retired under another preparation"
        ))
    ));

    drop(case.fixture.store);
    std::fs::remove_dir_all(case.fixture.root)?;
    Ok(())
}

#[test]
fn retirement_preserves_prepared_snapshot_fences_and_unrelated_work() -> TestResult<()> {
    let mut case = retirement_case("home-source-retirement-preserve-state", 0xFA00)?;
    let fences_before = home_fences(&case.fixture.store.connection)?;
    let owner_counts_before = owner_counts(&case.fixture.store.connection)?;
    let record = create_retirement(&mut case)?;
    let reservation_id = case.selected.request().request_id();
    let parent_id = case.parent.request().witness().preparation_id();

    let source_parent = case
        .fixture
        .store
        .get_home_transfer_source(
            parent_id,
            case.fixture.issuer,
            case.fixture.backend,
            case.fixture.delegation.destination_id(),
        )?
        .ok_or("original Prepared source disappeared")?;
    assert_eq!(source_parent.to_snapshot_bytes()?, case.parent_bytes);
    assert_eq!(home_fences(&case.fixture.store.connection)?, fences_before);
    assert_eq!(
        owner_counts(&case.fixture.store.connection)?,
        owner_counts_before
    );
    assert_eq!(
        case.fixture
            .store
            .agent_binding_reservation(reservation_id)?,
        Some(case.selected.clone()),
        "retirement keeps the historical reservation row unchanged",
    );
    assert_eq!(
        case.fixture
            .store
            .agent_binding_reservation(case.unrelated.request().request_id())?,
        Some(case.unrelated.clone()),
        "unrelated same-Activity reservation remains pending",
    );
    assert_eq!(
        crate::workspace_home_transfers::retirements::get(
            &case.fixture.store.connection,
            parent_id,
            reservation_id,
        )?,
        Some(record),
    );

    drop(case.fixture.store);
    std::fs::remove_dir_all(case.fixture.root)?;
    Ok(())
}

#[test]
fn retirement_sql_guards_close_identity_and_terminal_writes() -> TestResult<()> {
    let mut case = retirement_case("home-source-retirement-sql-guards", 0xFA00)?;
    let _record = create_retirement(&mut case)?;
    let reservation_id = case.selected.request().request_id();
    assert!(matches!(
        crate::workspace_home_transfers::retirements::ensure_binding_identity_open(
            &case.fixture.store.connection,
            case.selected.workspace_id(),
            case.selected.request().activity_id(),
            case.selected.request().agent_id(),
            Some(case.selected.request().session_id()),
        ),
        Err(crate::HomeTransferStoreError::Conflict(
            "retired binding identity"
        ))
    ));
    crate::workspace_home_transfers::retirements::ensure_binding_identity_open(
        &case.fixture.store.connection,
        case.selected.workspace_id(),
        case.selected.request().activity_id(),
        AgentInstanceId::from_uuid(id(0xFBC1)),
        Some(AgentSessionId::from_uuid(id(0xFBC2))),
    )?;

    for (sql, message) in [
        (
            "UPDATE home_transfer_reservation_retirements SET observed_at_ms=observed_at_ms+1 WHERE reservation_request_id=?1",
            "Home reservation retirements are immutable",
        ),
        (
            "DELETE FROM home_transfer_reservation_retirements WHERE reservation_request_id=?1",
            "Home reservation retirements are immutable",
        ),
        (
            "INSERT INTO agent_binding_activations(request_id) VALUES (?1)",
            "Home reservation was retired",
        ),
        (
            "INSERT INTO agent_binding_rejections(request_id) VALUES (?1)",
            "Home reservation was retired",
        ),
    ] {
        let error = case
            .fixture
            .store
            .connection
            .execute(sql, params![reservation_id.as_bytes()])
            .err()
            .ok_or("retirement immutability or terminal guard allowed a write")?;
        assert!(
            error.to_string().contains(message),
            "unexpected guard error: {error}"
        );
    }
    let materialization_error = case
        .fixture
        .store
        .connection
        .execute(
            "INSERT INTO agent_instances(agent_id, workspace_id, activity_id) VALUES (?1,?2,?3)",
            params![
                case.selected.request().agent_id().into_uuid().as_bytes(),
                case.selected.workspace_id().into_uuid().as_bytes(),
                case.selected.request().activity_id().into_uuid().as_bytes(),
            ],
        )
        .err()
        .ok_or("retired Agent materialization was admitted")?;
    assert!(
        materialization_error
            .to_string()
            .contains("Home reservation Agent or Activity/Session tuple was retired"),
        "unexpected materialization guard error: {materialization_error}",
    );

    drop(case.fixture.store);
    std::fs::remove_dir_all(case.fixture.root)?;
    Ok(())
}

#[test]
fn activated_then_detached_reservation_is_never_retired() -> TestResult<()> {
    let mut fixture = fixture("home-source-retirement-activated-detached", 0xFE00)?;
    let reservation =
        pending_reservation(&mut fixture, 0xFF00, AuthenticatedPrincipal::TrustedStdio)?;
    let _activation = fixture.store.activate_agent_binding(
        &fixture.delegation,
        &crate::AgentBindingActivationRequest::new(
            reservation.request().request_id(),
            [0x51; 32],
            AgentDisplayName::new("retirement activation".to_owned())?,
            AgentDeclaredRole::new("worker".to_owned())?,
            AgentTransportKind::Stdio,
        )?,
        timestamp(204)?,
    )?;
    let transaction = fixture
        .store
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let active = crate::workspace_agents::get_in_transaction(
        &transaction,
        reservation.request().agent_id(),
    )?
    .ok_or("activated Agent missing before detach")?;
    let detached =
        crate::workspace_agents::detach_in_transaction(&transaction, &active, timestamp(205)?)?;
    transaction.commit()?;
    assert_eq!(
        detached.attachment_state(),
        forge_domain::AgentAttachmentState::Detached
    );

    let parent = prepare_parent(&mut fixture, 0xFEE0, &reservation, &[detached])?;
    let request = retirement_request(&fixture, &parent, &reservation)?;
    let grant = retirement_grant(&request, fixture.issuer)?;
    let clock_sampled = std::cell::Cell::new(false);
    let result = crate::workspace_home_transfers::retirements::retire(
        &mut fixture.store.connection,
        &request,
        grant,
        fixture.issuer,
        fixture.backend,
        fixture.delegation.destination_id(),
        || {
            clock_sampled.set(true);
            source_clock(400)
        },
    );
    assert!(
        !clock_sampled.get(),
        "non-Pending capture must fail before Source time sample"
    );
    assert!(matches!(
        result,
        Err(crate::HomeTransferStoreError::Conflict(
            "captured reservation was not Pending"
        ))
    ));
    assert!(
        crate::workspace_agent_binding_activation::get(
            &fixture.store.connection,
            reservation.request().request_id(),
        )?
        .is_some()
    );
    assert!(
        crate::workspace_home_transfers::retirements::get_for_reservation(
            &fixture.store.connection,
            reservation.request().request_id(),
        )?
        .is_none()
    );

    drop(fixture.store);
    std::fs::remove_dir_all(fixture.root)?;
    Ok(())
}

fn reject_reservation(
    fixture: &mut Fixture,
    reservation: &crate::AgentBindingReservation,
    principal: AuthenticatedPrincipal,
) -> TestResult<()> {
    let workspace = fixture.store.workspace()?;
    let binding = fixture.store.journal_binding()?;
    let request = forge_domain::AgentBindingRejectionRequest::new(
        reservation.request().request_id(),
        workspace.id(),
        reservation.request().activity_id(),
        reservation.request().agent_id(),
        reservation.request().session_id(),
        principal,
        reservation.migration_id(),
        reservation.destination_id(),
        reservation.freeze_revision(),
        fixture.delegation.manifest_digest(),
        id(0xA120),
        workspace.root_fingerprint(),
        binding.recovery_history_digest(),
        crate::workspace_agent_binding_rejections::agent_binding_rejection_delegation_digest(
            &fixture.delegation,
        ),
        [0x61; 32],
        AgentDisplayName::new("retirement rejected".to_owned())?,
        AgentDeclaredRole::new("worker".to_owned())?,
        AgentTransportKind::Other,
        AgentBindingRejectionReason::PrincipalTransportMismatch,
        reservation.reserved_at(),
        reservation.request().requested_at(),
        timestamp(220)?,
    )?;
    let source = crate::AgentBindingRejectionStoreRequest {
        binding_digest: request.binding_digest(),
        observed_root_fingerprint: workspace.root_fingerprint(),
        current_delegation: fixture.delegation.clone(),
        request,
    };
    crate::workspace_agent_binding_rejections::reject_with_clock(
        &mut fixture.store.connection,
        &source,
        || TimestampMillis::new(230).map_err(|_| crate::AgentBindingRejectionStoreError::Clock),
    )?;
    Ok(())
}

#[test]
fn rejected_reservation_remains_rejected_and_cannot_be_relabelled_retired() -> TestResult<()> {
    let mut fixture = fixture("home-source-retirement-rejected", 0xA200)?;
    let principal = AuthenticatedPrincipal::DirectToken(DirectTokenId::from_uuid(id(0xA201)));
    let reservation = pending_reservation(&mut fixture, 0xA210, principal)?;
    reject_reservation(&mut fixture, &reservation, principal)?;
    let parent = prepare_parent(&mut fixture, 0xA220, &reservation, &[])?;
    let request = retirement_request(&fixture, &parent, &reservation)?;
    let grant = retirement_grant(&request, fixture.issuer)?;

    assert!(matches!(
        retirement(&mut fixture, &request, grant, 400),
        Err(crate::HomeTransferStoreError::Conflict(
            "captured reservation was not Pending"
        ))
    ));
    assert!(
        crate::workspace_agent_binding_rejections::get(
            &fixture.store.connection,
            reservation.request().request_id(),
        )?
        .is_some()
    );
    assert!(
        crate::workspace_home_transfers::retirements::get_for_reservation(
            &fixture.store.connection,
            reservation.request().request_id(),
        )?
        .is_none()
    );

    drop(fixture.store);
    std::fs::remove_dir_all(fixture.root)?;
    Ok(())
}

#[test]
fn orphaned_agent_work_history_blocks_unused_retirement() -> TestResult<()> {
    let mut fixture = fixture("home-source-retirement-agent-history", 0xA300)?;
    let reservation =
        pending_reservation(&mut fixture, 0xA310, AuthenticatedPrincipal::TrustedStdio)?;
    fixture
        .store
        .connection
        .pragma_update(None, "foreign_keys", false)?;
    fixture.store.connection.execute(
        "INSERT INTO agent_work_updates (
            update_id, agent_id, workspace_id, activity_id, update_sequence,
            phase, summary, evidence_count, observed_at_ms
         ) VALUES (?1,?2,?3,?4,1,1,'orphaned reserved-Agent work',0,205)",
        params![
            id(0xA319).as_bytes(),
            reservation.request().agent_id().into_uuid().as_bytes(),
            reservation.workspace_id().into_uuid().as_bytes(),
            reservation.request().activity_id().into_uuid().as_bytes(),
        ],
    )?;
    fixture
        .store
        .connection
        .pragma_update(None, "foreign_keys", true)?;
    assert!(
        fixture
            .store
            .get_agent(reservation.request().agent_id())?
            .is_none()
    );

    let parent = prepare_parent(&mut fixture, 0xA320, &reservation, &[])?;
    let request = retirement_request(&fixture, &parent, &reservation)?;
    let grant = retirement_grant(&request, fixture.issuer)?;
    let clock_sampled = std::cell::Cell::new(false);
    let result = crate::workspace_home_transfers::retirements::retire(
        &mut fixture.store.connection,
        &request,
        grant,
        fixture.issuer,
        fixture.backend,
        fixture.delegation.destination_id(),
        || {
            clock_sampled.set(true);
            source_clock(400)
        },
    );
    assert!(
        !clock_sampled.get(),
        "historical work must fail before Source time sample"
    );
    assert!(matches!(
        result,
        Err(crate::HomeTransferStoreError::Conflict(
            "reserved Agent has assignment, work, or effect history"
        ))
    ));
    assert!(
        crate::workspace_home_transfers::retirements::get_for_reservation(
            &fixture.store.connection,
            reservation.request().request_id(),
        )?
        .is_none()
    );

    drop(fixture.store);
    std::fs::remove_dir_all(fixture.root)?;
    Ok(())
}

#[test]
fn validated_v71_reads_no_retirement_but_damaged_v72_never_looks_empty() -> TestResult<()> {
    let mut fixture = fixture("home-source-retirement-versioned-read", 0xA400)?;
    let reservation =
        pending_reservation(&mut fixture, 0xA410, AuthenticatedPrincipal::TrustedStdio)?;
    let database = fixture.layout.database_path();
    let workspace_id = fixture.store.workspace()?.id();
    let activity_id = reservation.request().activity_id();
    drop(fixture.store);

    let connection = Connection::open(database)?;
    connection.pragma_update(None, "foreign_keys", true)?;
    for (kind, name) in crate::workspace_home_transfers::retirements::schema::schema_objects()
        .into_iter()
        .rev()
    {
        connection.execute_batch(&format!("DROP {kind} {name}"))?;
    }
    connection.pragma_update(None, "user_version", 71_i64)?;
    assert!(
        crate::workspace_home_transfers::retirements::get(
            &connection,
            id(0xA4F0),
            reservation.request().request_id(),
        )?
        .is_none()
    );
    assert!(
        crate::workspace_home_transfers::retirements::get_for_reservation(
            &connection,
            reservation.request().request_id(),
        )?
        .is_none()
    );
    assert!(
        !crate::workspace_home_transfers::retirements::is_valid_settlement(
            &connection,
            &reservation,
        )?
    );
    crate::workspace_home_transfers::retirements::ensure_binding_identity_open(
        &connection,
        workspace_id,
        activity_id,
        reservation.request().agent_id(),
        Some(reservation.request().session_id()),
    )?;

    crate::workspace_home_transfers::retirements::schema::create_schema(&connection)?;
    connection.pragma_update(None, "user_version", 72_i64)?;
    connection.execute_batch("DROP TRIGGER home_transfer_reservation_retirements_no_update")?;
    assert!(matches!(
        crate::workspace_home_transfers::retirements::get_for_reservation(
            &connection,
            reservation.request().request_id(),
        ),
        Err(crate::HomeTransferStoreError::Corrupt(
            "retirement schema object"
        ))
    ));

    drop(connection);
    std::fs::remove_dir_all(fixture.root)?;
    Ok(())
}

#[test]
fn sqlite_retirement_contenders_commit_one_exact_business_key() -> TestResult<()> {
    let mut fixture = fixture("home-source-retirement-contenders", 0xA500)?;
    let reservation =
        pending_reservation(&mut fixture, 0xA510, AuthenticatedPrincipal::TrustedStdio)?;
    let parent = prepare_parent(&mut fixture, 0xA520, &reservation, &[])?;
    let request = retirement_request(&fixture, &parent, &reservation)?;
    let grant = retirement_grant(&request, fixture.issuer)?;
    let database = fixture.layout.database_path();
    let issuer = fixture.issuer;
    let backend = fixture.backend;
    let destination = fixture.delegation.destination_id();
    drop(fixture.store);

    let mut first_connection = Connection::open(&database)?;
    first_connection.busy_timeout(std::time::Duration::from_secs(5))?;
    first_connection.pragma_update(None, "foreign_keys", true)?;
    let mut second_connection = Connection::open(&database)?;
    second_connection.busy_timeout(std::time::Duration::from_secs(5))?;
    second_connection.pragma_update(None, "foreign_keys", true)?;
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));

    let first_barrier = std::sync::Arc::clone(&barrier);
    let first = std::thread::spawn(move || {
        first_barrier.wait();
        crate::workspace_home_transfers::retirements::retire(
            &mut first_connection,
            &request,
            grant,
            issuer,
            backend,
            destination,
            || source_clock(400),
        )
    });
    let second_barrier = std::sync::Arc::clone(&barrier);
    let second = std::thread::spawn(move || {
        second_barrier.wait();
        crate::workspace_home_transfers::retirements::retire(
            &mut second_connection,
            &request,
            grant,
            issuer,
            backend,
            destination,
            || source_clock(400),
        )
    });
    barrier.wait();
    let first = first
        .join()
        .map_err(|_| "first retirement contender panicked")??;
    let second = second
        .join()
        .map_err(|_| "second retirement contender panicked")??;
    assert_ne!(
        matches!(
            &first,
            crate::HomeTransferReservationRetirementOutcome::Created(_)
        ),
        matches!(
            &second,
            crate::HomeTransferReservationRetirementOutcome::Created(_)
        ),
        "one IMMEDIATE transaction creates the receipt and the other replays it",
    );
    assert_eq!(first.record(), second.record());

    let readback = Connection::open(&database)?;
    readback.pragma_update(None, "foreign_keys", true)?;
    assert_eq!(
        crate::workspace_home_transfers::retirements::get(
            &readback,
            request.preparation_id(),
            request.reservation_request_id(),
        )?,
        Some((*first.record()).clone()),
    );
    drop(readback);
    std::fs::remove_dir_all(fixture.root)?;
    Ok(())
}

#[test]
fn clock_failure_rolls_back_retirement_and_preserves_parent_fences() -> TestResult<()> {
    let mut fixture = fixture("home-source-retirement-clock-rollback", 0xA600)?;
    let reservation =
        pending_reservation(&mut fixture, 0xA610, AuthenticatedPrincipal::TrustedStdio)?;
    let parent = prepare_parent(&mut fixture, 0xA620, &reservation, &[])?;
    let parent_id = parent.request().witness().preparation_id();
    let parent_bytes = parent.to_snapshot_bytes()?;
    let fences_before = home_fences(&fixture.store.connection)?;
    let request = retirement_request(&fixture, &parent, &reservation)?;
    let grant = retirement_grant(&request, fixture.issuer)?;

    assert!(matches!(
        crate::workspace_home_transfers::retirements::retire(
            &mut fixture.store.connection,
            &request,
            grant,
            fixture.issuer,
            fixture.backend,
            fixture.delegation.destination_id(),
            || Err(crate::HomeTransferStoreError::Clock),
        ),
        Err(crate::HomeTransferStoreError::Clock)
    ));
    assert!(
        crate::workspace_home_transfers::retirements::get_for_reservation(
            &fixture.store.connection,
            reservation.request().request_id(),
        )?
        .is_none()
    );
    let durable_parent = fixture
        .store
        .get_home_transfer_source(
            parent_id,
            fixture.issuer,
            fixture.backend,
            fixture.delegation.destination_id(),
        )?
        .ok_or("original Prepared source disappeared after rollback")?;
    assert_eq!(durable_parent.to_snapshot_bytes()?, parent_bytes);
    assert_eq!(home_fences(&fixture.store.connection)?, fences_before);

    drop(fixture.store);
    std::fs::remove_dir_all(fixture.root)?;
    Ok(())
}
