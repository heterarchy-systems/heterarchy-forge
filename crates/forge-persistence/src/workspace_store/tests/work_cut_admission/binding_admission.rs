//! Binding admission around a leadership `WorkCut`.
//!
//! These storage tests model only the existing `WorkCut` boundary. They do not
//! represent a Home transfer or create election authority.

use super::*;
use crate::{
    AgentBindingActivationRequest, AgentBindingReservationRequest,
    AgentSessionReconciliationRequest,
};
use forge_domain::{
    AgentDeclaredRole, AgentDisplayName, AgentFocusEvent, AgentFocusEventKind,
    AgentFocusEventSequence, AgentInstanceId, AgentSessionId, AgentTransportKind,
    AuthenticatedPrincipal, BindExistingAgentSession, BootstrapActivity, RegisteredAgentInstance,
    RuntimeInstanceId, WorkCutSession, WorkCutSide,
};
use std::sync::{Arc, Barrier};

fn secondary_activity(
    fixture: &mut CutFixture,
    seed: u128,
) -> TestResult<forge_domain::ActivityId> {
    let workspace_id = fixture.file.store.workspace()?.id();
    let activity_id = forge_domain::ActivityId::from_uuid(Uuid::from_u128(seed));
    fixture
        .file
        .store
        .bootstrap_activity(&BootstrapActivity::new(
            activity_id,
            workspace_id,
            WorkspaceRevision::INITIAL,
            RuntimeInstanceId::from_uuid(Uuid::from_u128(seed + 1)),
            timestamp(10_000)?,
            timestamp(15)?,
        ))?;
    Ok(activity_id)
}

fn freeze(fixture: &CutFixture) -> TestResult<crate::AgentOperationsFreeze> {
    fixture
        .file
        .store
        .agent_operations_freeze(Uuid::from_u128(0xFA40))?
        .ok_or_else(|| "delegation fixture freeze missing".into())
}

fn delegation(fixture: &CutFixture) -> TestResult<crate::AgentOperationsDelegation> {
    fixture
        .file
        .store
        .agent_operations_delegation()?
        .ok_or_else(|| "delegation fixture seal missing".into())
}

fn reservation_request(
    request_id: u128,
    agent_id: u128,
    activity_id: forge_domain::ActivityId,
    session_id: AgentSessionId,
    principal: AuthenticatedPrincipal,
) -> TestResult<AgentBindingReservationRequest> {
    Ok(AgentBindingReservationRequest::new(
        Uuid::from_u128(request_id),
        activity_id,
        AgentInstanceId::from_uuid(Uuid::from_u128(agent_id)),
        session_id,
        principal,
        timestamp(30)?,
    )?)
}

fn activation_request(request_id: Uuid) -> TestResult<AgentBindingActivationRequest> {
    Ok(AgentBindingActivationRequest::new(
        request_id,
        [0x42; 32],
        forge_domain::AgentDisplayName::new("Reserved test Agent".to_owned())?,
        forge_domain::AgentDeclaredRole::new("worker".to_owned())?,
        forge_domain::AgentTransportKind::Retired,
    )?)
}

fn prepare_workspace_cut(
    fixture: &mut CutFixture,
    delegation: &crate::AgentOperationsDelegation,
    seed: u128,
    agents: &[forge_domain::RegisteredAgentInstance],
) -> TestResult<WorkCutRequest> {
    let request = workspace_cut_request(fixture, delegation, seed, agents)?;
    let issuer = OrchestrationIssuerId::from_uuid(Uuid::from_u128(seed + 20));
    let grant = WorkCutGrant::new(
        issuer,
        request.request_digest(),
        timestamp(30)?,
        timestamp(90)?,
    )?;
    assert!(matches!(
        fixture.file.store.prepare_leadership_work_cut(
            &request,
            grant,
            issuer,
            request.backend_id(),
            timestamp(40)?,
        )?,
        crate::WorkCutPrepareOutcome::Prepared(_)
    ));
    Ok(request)
}

fn workspace_cut_request(
    fixture: &CutFixture,
    delegation: &crate::AgentOperationsDelegation,
    seed: u128,
    agents: &[forge_domain::RegisteredAgentInstance],
) -> TestResult<WorkCutRequest> {
    let mut sessions = Vec::new();
    let mut bindings = Vec::new();
    for agent in agents {
        let (session, binding) = inventory_endpoint(agent, WorkCutSide::Incumbent)?;
        if !sessions
            .iter()
            .any(|existing: &WorkCutSession| existing.session_id() == session.session_id())
        {
            sessions.push(session);
        }
        bindings.push(binding);
    }
    sessions.push(WorkCutSession::new(
        WorkCutSide::Elected,
        AgentSessionId::from_uuid(Uuid::from_u128(seed + 10)),
    )?);
    work_cut_request_for_inventory(
        &fixture.file.store,
        delegation.destination_id(),
        seed,
        sessions,
        bindings,
        WorkCutScope::Workspace,
    )
}

fn source_agent(fixture: &CutFixture) -> TestResult<forge_domain::RegisteredAgentInstance> {
    fixture
        .file
        .store
        .get_agent(fixture.authority.agent_id())?
        .ok_or_else(|| "source Agent missing".into())
}

type CutAttempt = Result<crate::WorkCutPrepareOutcome, crate::WorkspaceStoreError>;
type ActivationAttempt = Result<crate::AgentBindingActivation, crate::WorkspaceStoreError>;

struct AdmissionRaceCommands {
    cut: WorkCutRequest,
    grant: WorkCutGrant,
    issuer: OrchestrationIssuerId,
    delegation: crate::AgentOperationsDelegation,
    activation: AgentBindingActivationRequest,
    observed_at: TimestampMillis,
}

fn race_admission_commands(
    mut cut_store: WorkspaceStore,
    mut activation_store: WorkspaceStore,
    commands: AdmissionRaceCommands,
) -> TestResult<(CutAttempt, ActivationAttempt)> {
    let AdmissionRaceCommands {
        cut,
        grant,
        issuer,
        delegation,
        activation,
        observed_at,
    } = commands;
    let barrier = Arc::new(Barrier::new(3));
    std::thread::scope(|scope| {
        let cut_barrier = Arc::clone(&barrier);
        let cut_thread = scope.spawn(move || {
            cut_barrier.wait();
            cut_store.prepare_leadership_work_cut(
                &cut,
                grant,
                issuer,
                cut.backend_id(),
                observed_at,
            )
        });
        let activation_barrier = Arc::clone(&barrier);
        let activation_thread = scope.spawn(move || {
            activation_barrier.wait();
            activation_store.activate_agent_binding(&delegation, &activation, observed_at)
        });
        barrier.wait();
        let cut_result = cut_thread
            .join()
            .map_err(|_| std::io::Error::other("WorkCut thread must not panic"))?;
        let activation_result = activation_thread
            .join()
            .map_err(|_| std::io::Error::other("activation thread must not panic"))?;
        Ok((cut_result, activation_result))
    })
}

fn assert_serialized_admission_results(
    store: &WorkspaceStore,
    cut_id: Uuid,
    request_id: Uuid,
    agent_id: AgentInstanceId,
    cut_result: &CutAttempt,
    activation_result: &ActivationAttempt,
) -> TestResult {
    let cut_committed = matches!(cut_result, Ok(crate::WorkCutPrepareOutcome::Prepared(_)));
    let activation_committed = activation_result.is_ok();
    assert_ne!(cut_committed, activation_committed);

    assert_eq!(
        store.get_leadership_work_cut(cut_id)?.is_some(),
        cut_committed
    );
    assert_eq!(
        store.agent_binding_activation(request_id)?.is_some(),
        activation_committed
    );
    assert_eq!(store.get_agent(agent_id)?.is_some(), activation_committed);
    if cut_committed {
        assert!(matches!(
            activation_result,
            Err(crate::WorkspaceStoreError::AgentBindingActivation(
                crate::AgentBindingActivationError::Agent(crate::AgentStoreError::WorkCut(error))
            )) if matches!(
                error.as_ref(),
                crate::WorkCutError::Conflict("Session binding is fenced by a held cut")
            )
        ));
    } else {
        assert!(matches!(
            cut_result,
            Err(crate::WorkspaceStoreError::WorkCut(
                crate::WorkCutError::Inventory(inventory)
            )) if matches!(
                inventory.as_ref(),
                crate::WorkInventoryError::Conflict("source binding roster differs")
            )
        ));
    }
    Ok(())
}

fn unresolved_legacy_agent(
    fixture: &CutFixture,
    seed: u128,
    activity_id: forge_domain::ActivityId,
) -> TestResult<RegisteredAgentInstance> {
    Ok(RegisteredAgentInstance::create(
        AgentInstanceId::from_uuid(Uuid::from_u128(seed)),
        fixture.file.store.workspace()?.id(),
        activity_id,
        AgentDisplayName::new(format!("Legacy Agent {seed}"))?,
        AgentDeclaredRole::new("worker".to_owned())?,
        AgentTransportKind::Stdio,
        timestamp(4)?,
    ))
}

#[test]
fn workspace_cut_blocks_reserving_captured_session_in_another_activity() -> TestResult {
    let mut fixture = CutFixture::new("cut-binding-reserve-session")?;
    let destination_activity = secondary_activity(&mut fixture, 0xFAC0)?;
    let _cut = fixture.prepare(WorkCutScope::Workspace, None)?;
    let source = source_agent(&fixture)?;
    let request = reservation_request(
        0xFAD0,
        0xFAD1,
        destination_activity,
        source.session_id().ok_or("source Session missing")?,
        source.principal(),
    )?;

    let result =
        fixture
            .file
            .store
            .reserve_agent_binding(&freeze(&fixture)?, &request, timestamp(45)?);
    assert!(
        matches!(
            &result,
            Err(crate::WorkspaceStoreError::AgentBindingReservation(
                crate::AgentBindingReservationError::WorkCut(error)
            )) if matches!(
                error.as_ref(),
                crate::WorkCutError::Conflict("Session binding is fenced by a held cut")
            )
        ),
        "fresh reservation did not fail at the Session cut fence: {result:?}"
    );
    assert!(
        fixture
            .file
            .store
            .agent_binding_reservation(request.request_id())?
            .is_none()
    );
    assert!(fixture.file.store.get_agent(request.agent_id())?.is_none());
    fixture.cleanup()
}

#[test]
fn workspace_cut_blocks_late_activation_but_keeps_exact_reservation_replay() -> TestResult {
    let mut fixture = CutFixture::new("cut-binding-late-activation")?;
    let destination_activity = secondary_activity(&mut fixture, 0xFAE0)?;
    let _delegation = install_delegation_seal(&mut fixture.file.store, 0xFA40, 25)?;
    let source = source_agent(&fixture)?;
    let reservation = reservation_request(
        0xFAF0,
        0xFAF1,
        destination_activity,
        source.session_id().ok_or("source Session missing")?,
        source.principal(),
    )?;
    let reserved = fixture.file.store.reserve_agent_binding(
        &freeze(&fixture)?,
        &reservation,
        timestamp(30)?,
    )?;
    let delegation = delegation(&fixture)?;
    let _cut = prepare_workspace_cut(&mut fixture, &delegation, 0xFB00, &[source])?;

    let replay = fixture.file.store.reserve_agent_binding(
        &freeze(&fixture)?,
        &reservation,
        timestamp(45)?,
    )?;
    assert_eq!(
        replay, reserved,
        "exact historical reservation replay changed"
    );

    let activation = activation_request(reservation.request_id())?;
    let result =
        fixture
            .file
            .store
            .activate_agent_binding(&delegation, &activation, timestamp(50)?);
    assert!(
        matches!(
            &result,
            Err(crate::WorkspaceStoreError::AgentBindingActivation(
                crate::AgentBindingActivationError::Agent(
                    crate::AgentStoreError::WorkCut(error)
                )
            )) if matches!(
                error.as_ref(),
                crate::WorkCutError::Conflict("Session binding is fenced by a held cut")
            )
        ),
        "late activation did not fail at the Session cut fence: {result:?}"
    );
    assert!(
        fixture
            .file
            .store
            .agent_binding_activation(reservation.request_id())?
            .is_none()
    );
    assert!(
        fixture
            .file
            .store
            .get_agent(reservation.agent_id())?
            .is_none()
    );
    fixture.cleanup()
}

#[test]
fn workspace_cut_preserves_exact_activation_replay_for_captured_binding() -> TestResult {
    let mut fixture = CutFixture::new("cut-binding-activation-replay")?;
    let destination_activity = secondary_activity(&mut fixture, 0xFB20)?;
    let delegation = install_delegation_seal(&mut fixture.file.store, 0xFA40, 25)?;
    let source = source_agent(&fixture)?;
    let reservation = reservation_request(
        0xFB30,
        0xFB31,
        destination_activity,
        source.session_id().ok_or("source Session missing")?,
        source.principal(),
    )?;
    let reserved = fixture.file.store.reserve_agent_binding(
        &freeze(&fixture)?,
        &reservation,
        timestamp(30)?,
    )?;
    assert_eq!(reserved.request(), &reservation);
    let activation = activation_request(reservation.request_id())?;
    let committed =
        fixture
            .file
            .store
            .activate_agent_binding(&delegation, &activation, timestamp(35)?)?;
    let new_source = fixture
        .file
        .store
        .get_agent(source.id())?
        .ok_or("source Agent disappeared")?;
    let new_binding = fixture
        .file
        .store
        .get_agent(reservation.agent_id())?
        .ok_or("activated Agent missing")?;
    let _cut = prepare_workspace_cut(
        &mut fixture,
        &delegation,
        0xFB40,
        &[new_source, new_binding],
    )?;

    let replay =
        fixture
            .file
            .store
            .activate_agent_binding(&delegation, &activation, timestamp(45)?)?;
    assert_eq!(replay, committed, "exact activation readback changed");
    fixture.cleanup()
}

#[test]
fn team_cut_allows_binding_for_captured_session_outside_its_node_scope() -> TestResult {
    let mut fixture = CutFixture::new("team-cut-binding-admission")?;
    let destination_activity = secondary_activity(&mut fixture, 0xFB60)?;
    let team_scope = WorkCutScope::Team {
        team_id: Uuid::from_u128(0xFB70),
        nodes: vec![fixture.node_scope()?],
    };
    let _cut = fixture.prepare(team_scope, None)?;
    let source = source_agent(&fixture)?;
    let delegation = delegation(&fixture)?;
    let reservation = reservation_request(
        0xFB80,
        0xFB81,
        destination_activity,
        source.session_id().ok_or("source Session missing")?,
        source.principal(),
    )?;
    let reserved = fixture.file.store.reserve_agent_binding(
        &freeze(&fixture)?,
        &reservation,
        timestamp(45)?,
    )?;
    assert_eq!(reserved.request(), &reservation);
    let activated = fixture.file.store.activate_agent_binding(
        &delegation,
        &activation_request(reservation.request_id())?,
        timestamp(50)?,
    )?;
    assert_eq!(activated.agent_id(), reservation.agent_id());
    fixture.cleanup()
}

#[test]
fn workspace_cut_does_not_block_an_uncaptured_session() -> TestResult {
    let mut fixture = CutFixture::new("cut-binding-unrelated-session")?;
    let _cut = fixture.prepare(WorkCutScope::Workspace, None)?;
    let destination_activity = fixture.file.activity.id();
    let principal = source_agent(&fixture)?.principal();
    let reservation = reservation_request(
        0xFBB0,
        0xFBB1,
        destination_activity,
        AgentSessionId::from_uuid(Uuid::from_u128(0xFBB2)),
        principal,
    )?;
    let result =
        fixture
            .file
            .store
            .reserve_agent_binding(&freeze(&fixture)?, &reservation, timestamp(45)?);
    assert!(result.is_ok(), "uncaptured Session was blocked: {result:?}");
    fixture.cleanup()
}

#[test]
fn workspace_cut_blocks_legacy_session_reconciliation_into_captured_session() -> TestResult {
    let mut fixture = CutFixture::new("cut-legacy-session-reconciliation")?;
    let legacy_activity = secondary_activity(&mut fixture, 0xFBC0)?;
    let workspace_id = fixture.file.store.workspace()?.id();
    let captured_session = source_agent(&fixture)?
        .session_id()
        .ok_or("source Session missing")?;
    let replay_agent = unresolved_legacy_agent(&fixture, 0xFBC2, legacy_activity)?;
    let late_agent = unresolved_legacy_agent(&fixture, 0xFBC3, legacy_activity)?;
    let connection = Connection::open(fixture.file.layout.database_path())?;
    connection.pragma_update(None, "foreign_keys", true)?;
    crate::legacy_agent_seed::seed_agent(&connection, &replay_agent, None)?;
    crate::legacy_agent_seed::seed_agent(&connection, &late_agent, None)?;
    drop(connection);

    let delegation = install_delegation_seal(&mut fixture.file.store, 0xFA40, 25)?;
    let replay_session = AgentSessionId::from_uuid(Uuid::from_u128(0xFBC4));
    let replay_request = AgentSessionReconciliationRequest::new(
        Uuid::from_u128(0xFBC5),
        BindExistingAgentSession::new(
            workspace_id,
            legacy_activity,
            replay_agent.id(),
            replay_session,
            replay_agent.principal(),
            replay_agent.revision(),
            timestamp(30)?,
        ),
    )?;
    let replay_receipt = fixture
        .file
        .store
        .reconcile_agent_session(&delegation, replay_request)?;
    let captured_agent = source_agent(&fixture)?;
    let _cut = prepare_workspace_cut(&mut fixture, &delegation, 0xFBC6, &[captured_agent])?;

    let exact_replay = fixture
        .file
        .store
        .reconcile_agent_session(&delegation, replay_request)?;
    assert_eq!(exact_replay, replay_receipt);

    let late_request = AgentSessionReconciliationRequest::new(
        Uuid::from_u128(0xFBC7),
        BindExistingAgentSession::new(
            workspace_id,
            legacy_activity,
            late_agent.id(),
            captured_session,
            late_agent.principal(),
            late_agent.revision(),
            timestamp(45)?,
        ),
    )?;
    let result = fixture
        .file
        .store
        .reconcile_agent_session(&delegation, late_request);
    assert!(
        matches!(
            &result,
            Err(crate::WorkspaceStoreError::AgentSessionReconciliation(
                crate::AgentSessionReconciliationError::Agent(
                    crate::AgentStoreError::WorkCut(error)
                )
            )) if matches!(
                error.as_ref(),
                crate::WorkCutError::Conflict("Session binding is fenced by a held cut")
            )
        ),
        "legacy reconciliation did not fail at the Session cut fence: {result:?}"
    );
    assert!(
        fixture
            .file
            .store
            .agent_session_reconciliation(late_request.request_id())?
            .is_none()
    );
    let unresolved = fixture
        .file
        .store
        .get_agent(late_agent.id())?
        .ok_or("legacy Agent disappeared")?;
    assert_eq!(unresolved.session_id(), None);
    fixture.cleanup()
}

#[test]
fn workspace_cut_and_late_activation_serialize_across_two_store_connections() -> TestResult {
    for round in 0..8_u128 {
        let mut fixture = CutFixture::new(&format!("cut-binding-sqlite-race-{round}"))?;
        let destination_activity = secondary_activity(&mut fixture, 0xFC00 + round * 2)?;
        let delegation = install_delegation_seal(&mut fixture.file.store, 0xFA40, 25)?;
        let source = source_agent(&fixture)?;
        let reservation = reservation_request(
            0xFC20,
            0xFC21,
            destination_activity,
            source.session_id().ok_or("source Session missing")?,
            source.principal(),
        )?;
        let reserved = fixture.file.store.reserve_agent_binding(
            &freeze(&fixture)?,
            &reservation,
            timestamp(30)?,
        )?;
        assert_eq!(reserved.request(), &reservation);

        let cut_request = workspace_cut_request(&fixture, &delegation, 0xFC30, &[source])?;
        let cut_id = cut_request.cut_id();
        let cut_issuer = OrchestrationIssuerId::from_uuid(Uuid::from_u128(0xFC50));
        let cut_grant = WorkCutGrant::new(
            cut_issuer,
            cut_request.request_digest(),
            timestamp(30)?,
            timestamp(90)?,
        )?;
        let existing =
            WorkspaceStateLayout::inspect_existing(fixture.file.layout.workspace_root())?
                .ok_or("Workspace layout disappeared before admission race")?;
        let cut_store = WorkspaceStore::open_existing(&existing)?;
        let activation_store = WorkspaceStore::open_existing(&existing)?;
        let (cut_result, activation_result) = race_admission_commands(
            cut_store,
            activation_store,
            AdmissionRaceCommands {
                cut: cut_request,
                grant: cut_grant,
                issuer: cut_issuer,
                delegation,
                activation: activation_request(reservation.request_id())?,
                observed_at: timestamp(50)?,
            },
        )?;
        assert_serialized_admission_results(
            &fixture.file.store,
            cut_id,
            reservation.request_id(),
            reservation.agent_id(),
            &cut_result,
            &activation_result,
        )
        .map_err(|error| {
            std::io::Error::other(format!(
                "round {round}: cut={cut_result:?}, activation={activation_result:?}: {error}"
            ))
        })?;
        fixture.cleanup()?;
    }
    Ok(())
}

#[test]
fn activation_first_rejects_prebuilt_workspace_cut_with_stale_roster() -> TestResult {
    let mut fixture = CutFixture::new("cut-binding-activation-first")?;
    let destination_activity = secondary_activity(&mut fixture, 0xFC60)?;
    let delegation = install_delegation_seal(&mut fixture.file.store, 0xFA40, 25)?;
    let source = source_agent(&fixture)?;
    let reservation = reservation_request(
        0xFC70,
        0xFC71,
        destination_activity,
        source.session_id().ok_or("source Session missing")?,
        source.principal(),
    )?;
    let reserved = fixture.file.store.reserve_agent_binding(
        &freeze(&fixture)?,
        &reservation,
        timestamp(30)?,
    )?;
    assert_eq!(reserved.request(), &reservation);
    let stale_cut = workspace_cut_request(&fixture, &delegation, 0xFC80, &[source])?;
    let existing = WorkspaceStateLayout::inspect_existing(fixture.file.layout.workspace_root())?
        .ok_or("Workspace layout disappeared before activation-first case")?;
    let mut activation_store = WorkspaceStore::open_existing(&existing)?;
    let mut cut_store = WorkspaceStore::open_existing(&existing)?;

    let activated = activation_store.activate_agent_binding(
        &delegation,
        &activation_request(reservation.request_id())?,
        timestamp(45)?,
    )?;
    assert_eq!(activated.agent_id(), reservation.agent_id());
    let issuer = OrchestrationIssuerId::from_uuid(Uuid::from_u128(0xFCA0));
    let grant = WorkCutGrant::new(
        issuer,
        stale_cut.request_digest(),
        timestamp(30)?,
        timestamp(90)?,
    )?;
    let result = cut_store.prepare_leadership_work_cut(
        &stale_cut,
        grant,
        issuer,
        stale_cut.backend_id(),
        timestamp(50)?,
    );
    assert!(
        matches!(
            &result,
            Err(crate::WorkspaceStoreError::WorkCut(
                crate::WorkCutError::Inventory(inventory)
            )) if matches!(
                inventory.as_ref(),
                crate::WorkInventoryError::Conflict("source binding roster differs")
            )
        ),
        "activation-first did not reject the old Workspace WorkCut roster: {result:?}"
    );
    assert!(
        cut_store
            .get_leadership_work_cut(stale_cut.cut_id())?
            .is_none()
    );
    assert!(
        fixture
            .file
            .store
            .agent_binding_activation(reservation.request_id())?
            .is_some()
    );
    assert!(
        fixture
            .file
            .store
            .get_agent(reservation.agent_id())?
            .is_some()
    );
    fixture.cleanup()
}

#[test]
fn same_session_binding_in_another_workspace_is_not_fenced() -> TestResult {
    let mut first = CutFixture::new("cut-binding-other-workspace-first")?;
    let _cut = first.prepare(WorkCutScope::Workspace, None)?;
    let source = source_agent(&first)?;
    let shared_session = source.session_id().ok_or("source Session missing")?;
    let shared_principal = source.principal();

    let mut second = file_fact_fixture("cut-binding-other-workspace-second", 0xFD00)?;
    let second_workspace = second.store.workspace()?.id();
    assert_ne!(first.file.store.workspace()?.id(), second_workspace);
    let target_activity = second.activity.id();
    let existing_target: i64 = second.store.connection.query_row(
        "SELECT COUNT(*) FROM agent_instances
          WHERE workspace_id = ?1 AND activity_id = ?2 AND session_id = ?3",
        rusqlite::params![
            second_workspace.into_uuid().as_bytes(),
            target_activity.into_uuid().as_bytes(),
            shared_session.into_uuid().as_bytes(),
        ],
        |row| row.get(0),
    )?;
    assert_eq!(existing_target, 0);
    let delegation = install_delegation_seal(&mut second.store, 0xFD10, 25)?;
    let request = reservation_request(
        0xFCB0,
        0xFCB1,
        target_activity,
        shared_session,
        shared_principal,
    )?;
    let freeze = second
        .store
        .agent_operations_freeze(Uuid::from_u128(0xFD10))?
        .ok_or("second Workspace freeze missing")?;
    let reserved = second
        .store
        .reserve_agent_binding(&freeze, &request, timestamp(30)?)?;
    assert_eq!(reserved.request(), &request);
    let activated = second.store.activate_agent_binding(
        &delegation,
        &activation_request(request.request_id())?,
        timestamp(35)?,
    )?;
    assert_eq!(activated.agent_id(), request.agent_id());

    first.cleanup()?;
    drop(second.store);
    fs::remove_dir_all(second.root)?;
    Ok(())
}

fn insert_synthetic_pre_guard_activation(
    path: &std::path::Path,
    reservation: &AgentBindingReservationRequest,
    agent: &RegisteredAgentInstance,
) -> TestResult {
    // The test models the old writer after its request admission. SQLite's
    // active migration trigger still verifies this exact receipt and row.
    let mut connection = Connection::open(path)?;
    connection.pragma_update(None, "foreign_keys", true)?;
    let transaction =
        connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    transaction.execute(
        "INSERT INTO agent_binding_activations (
             request_id, membership_digest, display_name, declared_role,
             transport_kind, activated_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            reservation.request_id().as_bytes(),
            [0x61_u8; 32].as_slice(),
            agent.display_name().as_str(),
            agent.declared_role().as_str(),
            1_i64,
            agent.created_at().get(),
        ],
    )?;
    transaction.execute(
        "INSERT INTO agent_instances (
             agent_id, workspace_id, activity_id, display_name, declared_role,
             transport_kind, principal_kind, principal_id, attachment_state,
             focus_goal_id, focus_goal_revision, focus_dag_revision, focus_node_id,
             focus_node_revision, created_at_ms, updated_at_ms, revision, session_id
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, NULL, 0, NULL, NULL, NULL, NULL, NULL, ?7, ?7, 1, ?8)",
        rusqlite::params![
            agent.id().into_uuid().as_bytes(),
            agent.workspace_id().into_uuid().as_bytes(),
            agent.activity_id().into_uuid().as_bytes(),
            agent.display_name().as_str(),
            agent.declared_role().as_str(),
            1_i64,
            agent.created_at().get(),
            agent
                .session_id()
                .ok_or("synthetic Agent Session missing")?
                .into_uuid()
                .as_bytes(),
        ],
    )?;
    crate::workspace_agents::insert_focus_event(
        &transaction,
        &AgentFocusEvent::from_parts(
            agent.id(),
            agent.workspace_id(),
            agent.activity_id(),
            AgentFocusEventSequence::INITIAL,
            AgentFocusEventKind::Attached,
            agent.focus(),
            agent.created_at(),
        ),
    )?;
    transaction.commit()?;
    Ok(())
}

#[test]
fn workspace_cut_blocks_synthetic_late_bound_agent_without_losing_history() -> TestResult {
    let mut fixture = CutFixture::new("cut-binding-synthetic-historical-agent")?;
    let target_activity = secondary_activity(&mut fixture, 0xFCD0)?;
    let delegation = install_delegation_seal(&mut fixture.file.store, 0xFA40, 25)?;
    let source = source_agent(&fixture)?;
    let captured_session = source.session_id().ok_or("source Session missing")?;
    let reservation = reservation_request(
        0xFCD6,
        0xFCD5,
        target_activity,
        captured_session,
        source.principal(),
    )?;
    let reserved = fixture.file.store.reserve_agent_binding(
        &freeze(&fixture)?,
        &reservation,
        timestamp(30)?,
    )?;
    assert_eq!(reserved.request(), &reservation);
    let request = prepare_workspace_cut(
        &mut fixture,
        &delegation,
        0xFCD2,
        std::slice::from_ref(&source),
    )?;
    let cut_receipt = fixture
        .file
        .store
        .get_leadership_work_cut(request.cut_id())?
        .ok_or("synthetic historical fixture cut missing")?;
    let historical_agent = RegisteredAgentInstance::create_bound(
        reservation.agent_id(),
        request.workspace_id(),
        target_activity,
        captured_session,
        AgentDisplayName::new("Historical Session alias".to_owned())?,
        AgentDeclaredRole::new("worker".to_owned())?,
        AgentTransportKind::Stdio,
        source.principal(),
        timestamp(41)?,
    );
    insert_synthetic_pre_guard_activation(
        &fixture.file.layout.database_path(),
        &reservation,
        &historical_agent,
    )?;

    let fresh_effect = guards::ensure_actor_open(
        &fixture.file.store.connection,
        request.workspace_id(),
        historical_agent.id(),
    );
    assert!(matches!(
        fresh_effect,
        Err(crate::WorkCutError::Conflict(
            "actor is fenced by a held cut"
        ))
    ));
    let historical_read = fixture
        .file
        .store
        .get_agent(historical_agent.id())?
        .ok_or("historical Agent row was lost")?;
    assert_eq!(historical_read.session_id(), Some(captured_session));
    let activation_read = fixture
        .file
        .store
        .agent_binding_activation(reservation.request_id())?
        .ok_or("synthetic historical activation receipt was lost")?;
    assert_eq!(activation_read.agent_id(), historical_agent.id());
    assert_eq!(
        fixture
            .file
            .store
            .get_leadership_work_cut(request.cut_id())?,
        Some(cut_receipt)
    );
    fixture.cleanup()
}
