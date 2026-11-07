use super::unstarted_activity_continuation::{probe, recovered_predecessor_fixture};
use super::*;
use forge_domain::{
    AgentInstanceId, AgentSessionId, AuthenticatedPrincipal, BootstrapActivity, ForgeBackendId,
    HomeTransferReservationRetirementGrant, HomeTransferReservationRetirementRequest,
    HomeTransferSourceAction, HomeTransferSourceBinding, HomeTransferSourceGrant,
    HomeTransferSourceRequest, HomeTransferSourceScope, HomeTransferSourceSubject,
    HomeTransferSourceWitness, OrchestrationIssuerId, RuntimeInstanceId, TimestampMillis,
};
use uuid::Uuid;

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

fn request_for_agent(
    store: &WorkspaceStore,
    agent: &forge_domain::RegisteredAgentInstance,
    backend: ForgeBackendId,
    destination: Uuid,
    identity: u128,
) -> TestResult<HomeTransferSourceRequest> {
    request_for_agent_with_extra_sessions(store, agent, &[], backend, destination, identity)
}

fn request_for_agent_with_extra_sessions(
    store: &WorkspaceStore,
    agent: &forge_domain::RegisteredAgentInstance,
    extra_sessions: &[AgentSessionId],
    backend: ForgeBackendId,
    destination: Uuid,
    identity: u128,
) -> TestResult<HomeTransferSourceRequest> {
    let workspace = store.workspace()?;
    let session_id = agent.session_id().ok_or("source Agent has no Session")?;
    let binding = HomeTransferSourceBinding::new(
        agent.activity_id(),
        agent.id(),
        session_id,
        agent.principal(),
    )?;
    Ok(HomeTransferSourceRequest::new(
        HomeTransferSourceWitness::new(Uuid::from_u128(identity + 10), [0xA1; 32], [0xA2; 32])?,
        HomeTransferSourceScope::new(workspace.id(), workspace.revision(), backend, destination)?,
        HomeTransferSourceSubject::new(
            Uuid::from_u128(identity + 1),
            1,
            Uuid::from_u128(identity + 2),
            Uuid::from_u128(identity + 3),
            Uuid::from_u128(identity + 4),
            Uuid::from_u128(identity + 5),
            1,
            1,
        )?,
        std::iter::once(session_id)
            .chain(extra_sessions.iter().copied())
            .collect(),
        vec![binding],
    )?)
}

fn pending_reservation(
    fixture: &mut crate::workspace_store::tests::FileFactFixture,
    delegation: &crate::AgentOperationsDelegation,
    activity_id: forge_domain::ActivityId,
    seed: u128,
) -> TestResult<crate::AgentBindingReservation> {
    let freeze = fixture
        .store
        .agent_operations_freeze(delegation.migration_id())?
        .ok_or("delegated Home source fixture lost its freeze")?;
    let request = crate::AgentBindingReservationRequest::new(
        Uuid::from_u128(seed),
        activity_id,
        AgentInstanceId::from_uuid(Uuid::from_u128(seed + 1)),
        AgentSessionId::from_uuid(Uuid::from_u128(seed + 2)),
        AuthenticatedPrincipal::TrustedStdio,
        TimestampMillis::new(210)?,
    )?;
    Ok(fixture
        .store
        .reserve_agent_binding(&freeze, &request, TimestampMillis::new(211)?)?)
}

fn source_grant(
    request: &HomeTransferSourceRequest,
    issuer: OrchestrationIssuerId,
    action: HomeTransferSourceAction,
) -> TestResult<HomeTransferSourceGrant> {
    Ok(HomeTransferSourceGrant::new(
        issuer,
        action,
        request.request_digest(),
        timestamp(250)?,
        timestamp(500)?,
    )?)
}

fn source_clock() -> Result<TimestampMillis, crate::HomeTransferStoreError> {
    TimestampMillis::new(300).map_err(|_| crate::HomeTransferStoreError::Clock)
}

fn add_unrelated_home_source_agent(
    fixture: &mut crate::workspace_store::tests::FileFactFixture,
    delegation: &crate::AgentOperationsDelegation,
    seed: u128,
) -> TestResult<forge_domain::RegisteredAgentInstance> {
    let workspace = fixture.store.workspace()?;
    let activity_id = ActivityId::from_uuid(Uuid::from_u128(seed + 1));
    fixture.store.bootstrap_activity(&BootstrapActivity::new(
        activity_id,
        workspace.id(),
        workspace.revision(),
        RuntimeInstanceId::from_uuid(Uuid::from_u128(seed + 2)),
        timestamp(2_000)?,
        timestamp(200)?,
    ))?;

    let freeze = fixture
        .store
        .agent_operations_freeze(delegation.migration_id())?
        .ok_or("delegated Home source fixture lost its freeze")?;
    let agent_id = AgentInstanceId::from_uuid(Uuid::from_u128(seed + 3));
    let session_id = AgentSessionId::from_uuid(Uuid::from_u128(seed + 4));
    let reservation = crate::AgentBindingReservationRequest::new(
        Uuid::from_u128(seed + 5),
        activity_id,
        agent_id,
        session_id,
        AuthenticatedPrincipal::TrustedStdio,
        timestamp(201)?,
    )?;
    let _reservation =
        fixture
            .store
            .reserve_agent_binding(&freeze, &reservation, timestamp(202)?)?;
    let _activation = fixture.store.activate_agent_binding(
        delegation,
        &crate::AgentBindingActivationRequest::new(
            reservation.request_id(),
            [0xB5; 32],
            forge_domain::AgentDisplayName::new("unrelated Home source".to_owned())?,
            forge_domain::AgentDeclaredRole::new("worker".to_owned())?,
            forge_domain::AgentTransportKind::Stdio,
        )?,
        timestamp(203)?,
    )?;
    fixture
        .store
        .get_agent(agent_id)?
        .ok_or_else(|| "activated unrelated Home source Agent is missing".into())
}

fn assert_continuable_with_plan(
    fixture: &crate::workspace_store::tests::FileFactFixture,
    assignment: &forge_domain::RegisteredAgentAssignment,
    expected_plan_digest: [u8; 32],
) -> TestResult<()> {
    let probe = probe(fixture, assignment)?;
    assert!(probe.continuable_now(), "{:?}", probe.blocker());
    assert_eq!(
        probe.expectation().expected_plan_digest(),
        expected_plan_digest,
        "unrelated or Aborted Home history must not enter this Activity's plan digest"
    );
    Ok(())
}

fn retire_unrelated_pending_reservation(
    fixture: &mut crate::workspace_store::tests::FileFactFixture,
    delegation: &crate::AgentOperationsDelegation,
    issuer: OrchestrationIssuerId,
    backend: ForgeBackendId,
    seed: u128,
) -> TestResult<()> {
    let destination = delegation.destination_id();
    let unrelated_agent = add_unrelated_home_source_agent(fixture, delegation, seed + 30)?;
    let pending = pending_reservation(
        fixture,
        delegation,
        unrelated_agent.activity_id(),
        seed + 360,
    )?;
    let unrelated_request = request_for_agent_with_extra_sessions(
        &fixture.store,
        &unrelated_agent,
        &[pending.request().session_id()],
        backend,
        destination,
        seed + 100,
    )?;
    let prepared = fixture.store.prepare_home_transfer_source(
        &unrelated_request,
        source_grant(
            &unrelated_request,
            issuer,
            HomeTransferSourceAction::Prepare,
        )?,
        issuer,
        backend,
        destination,
        source_clock,
    )?;
    assert_eq!(
        prepared.record().state(),
        crate::HomeTransferSourceState::Prepared
    );

    let source_workspace = fixture.store.workspace()?;
    let retirement_request = HomeTransferReservationRetirementRequest::new(
        HomeTransferSourceScope::new(
            source_workspace.id(),
            source_workspace.revision(),
            backend,
            destination,
        )?,
        prepared.record().request().witness().preparation_id(),
        prepared.record().request().request_digest(),
        *prepared.record().outcome_digest(),
        pending.request().request_id(),
    )?;
    let retirement_grant = HomeTransferReservationRetirementGrant::new(
        issuer,
        retirement_request.request_digest(),
        TimestampMillis::new(350)?,
        TimestampMillis::new(600)?,
    )?;
    let retirement = crate::workspace_home_transfers::retirements::retire(
        &mut fixture.store.connection,
        &retirement_request,
        retirement_grant,
        issuer,
        backend,
        destination,
        || TimestampMillis::new(400).map_err(|_| crate::HomeTransferStoreError::Clock),
    )?;
    assert!(matches!(
        retirement,
        crate::HomeTransferReservationRetirementOutcome::Created(_)
    ));
    assert!(
        crate::workspace_home_transfers::blocks_activity_continuation(
            &fixture.store.connection,
            source_workspace.id(),
            unrelated_agent.activity_id(),
        )?
    );
    Ok(())
}

#[test]
fn prepared_home_source_blocks_the_activity_it_fences() -> TestResult<()> {
    let seed = 0xF9A0;
    let (mut fixture, delegation, assignment) =
        recovered_predecessor_fixture("unstarted-continuation-home-source-related", seed)?;
    let assignment_agent = fixture
        .store
        .get_agent(assignment.target().agent_id())?
        .ok_or("continuation Assignment target is missing")?;
    let issuer = OrchestrationIssuerId::from_uuid(Uuid::from_u128(seed + 20));
    let backend = ForgeBackendId::from_uuid(Uuid::from_u128(seed + 21));
    let destination = delegation.destination_id();

    let baseline = probe(&fixture, &assignment)?;
    assert!(baseline.continuable_now(), "{:?}", baseline.blocker());
    let related_request = request_for_agent(
        &fixture.store,
        &assignment_agent,
        backend,
        destination,
        seed + 100,
    )?;
    let related_prepared = fixture.store.prepare_home_transfer_source(
        &related_request,
        source_grant(&related_request, issuer, HomeTransferSourceAction::Prepare)?,
        issuer,
        backend,
        destination,
        source_clock,
    )?;
    assert_eq!(
        related_prepared.record().state(),
        crate::HomeTransferSourceState::Prepared
    );
    assert_eq!(
        probe(&fixture, &assignment)?.blocker(),
        Some(forge_domain::UnstartedActivityContinuationBlocker::PhysicalEffectPresent)
    );

    // Simulate a damaged materialized fence row, not a missing SQLite index.
    fixture
        .store
        .connection
        .execute_batch("DROP TRIGGER home_transfer_source_activities_no_delete")?;
    fixture.store.connection.execute(
        "DELETE FROM home_transfer_source_activities WHERE preparation_id=?1",
        params![related_request.witness().preparation_id().as_bytes()],
    )?;
    assert!(
        crate::workspace_home_transfers::blocks_activity_continuation(
            &fixture.store.connection,
            related_request.scope().workspace_id(),
            assignment.activity_id()
        )
        .is_err()
    );

    let root = fixture.root.clone();
    drop(fixture);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn unrelated_prepared_and_aborted_home_sources_preserve_activity_plan_digest() -> TestResult<()> {
    let seed = 0xF9A0;
    let (mut fixture, delegation, assignment) =
        recovered_predecessor_fixture("unstarted-continuation-home-source-unrelated", seed)?;
    let issuer = OrchestrationIssuerId::from_uuid(Uuid::from_u128(seed + 20));
    let backend = ForgeBackendId::from_uuid(Uuid::from_u128(seed + 21));
    let destination = delegation.destination_id();

    let baseline = probe(&fixture, &assignment)?;
    assert!(baseline.continuable_now(), "{:?}", baseline.blocker());
    let original_plan_digest = baseline.expectation().expected_plan_digest();
    retire_unrelated_pending_reservation(&mut fixture, &delegation, issuer, backend, seed)?;
    assert_continuable_with_plan(&fixture, &assignment, original_plan_digest)?;

    let target_agent = fixture
        .store
        .get_agent(assignment.target().agent_id())?
        .ok_or("target Agent missing")?;
    let aborted_unrelated_request = request_for_agent(
        &fixture.store,
        &target_agent,
        backend,
        destination,
        seed + 200,
    )?;
    let aborted = fixture.store.abort_unstarted_home_transfer_source(
        &aborted_unrelated_request,
        source_grant(
            &aborted_unrelated_request,
            issuer,
            HomeTransferSourceAction::AbortUnstarted,
        )?,
        issuer,
        backend,
        destination,
        source_clock,
    )?;
    assert_eq!(
        aborted.record().state(),
        crate::HomeTransferSourceState::AbortedUnstarted
    );
    assert_continuable_with_plan(&fixture, &assignment, original_plan_digest)?;

    let root = fixture.root.clone();
    drop(fixture);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
