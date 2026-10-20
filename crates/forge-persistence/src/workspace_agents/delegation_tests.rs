use std::error::Error;
use std::fs;
use std::path::PathBuf;

use forge_domain::{
    ActivityCoordinatorActor, ActivityCoordinatorRevision, ActivityId, AgentDeclaredRole,
    AgentDisplayName, AgentFocus, AgentInstanceId, AgentSessionId, AgentTransportKind,
    AuthenticatedPrincipal, BindExistingAgentSession, BootstrapActivity, ClaimActivityCoordinator,
    EstablishWorkspace, RegisteredAgentInstance, RuntimeInstanceId, SetAgentFocus, TimestampMillis,
    TransferActivityCoordinator, WorkspaceId, WorkspaceRevision, WorkspaceRoot,
};
use forge_workspace::WorkspaceStateLayout;
use rusqlite::Connection;
use uuid::Uuid;

use crate::{
    AgentBindingActivationRequest, AgentBindingReservationRequest, AgentOperationsExportCursor,
    AgentOperationsFreezeRequest, AgentSessionReconciliationRequest, WorkspaceStore,
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

struct Fixture {
    root: PathBuf,
    layout: WorkspaceStateLayout,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
}

fn id(value: u128) -> Uuid {
    Uuid::from_u128(value)
}

fn timestamp(value: i64) -> Result<TimestampMillis, Box<dyn Error>> {
    Ok(TimestampMillis::new(value)?)
}

fn fixture(label: &str) -> TestResult<Fixture> {
    let root = std::env::temp_dir().join(format!("forge-delegation-{label}-{}", Uuid::now_v7()));
    fs::create_dir_all(&root)?;
    let layout = WorkspaceStateLayout::initialize(&root)?;
    let workspace_id = WorkspaceId::from_uuid(id(0xD700));
    let activity_id = ActivityId::from_uuid(id(0xD701));
    let command = EstablishWorkspace::new(
        workspace_id,
        forge_domain::LocationId::from_uuid(id(0xD702)),
        WorkspaceRoot::from_canonical(layout.workspace_root().to_path_buf())?,
        layout.root_fingerprint()?,
        timestamp(1)?,
    );
    let mut store = WorkspaceStore::open(&layout, &command)?;
    store.bootstrap_activity(&BootstrapActivity::new(
        activity_id,
        workspace_id,
        WorkspaceRevision::INITIAL,
        RuntimeInstanceId::from_uuid(id(0xD703)),
        timestamp(100)?,
        timestamp(2)?,
    ))?;
    drop(store);
    Ok(Fixture {
        root,
        layout,
        workspace_id,
        activity_id,
    })
}

fn reopen(fixture: &Fixture) -> TestResult<WorkspaceStore> {
    let existing = WorkspaceStateLayout::inspect_existing(fixture.layout.workspace_root())?
        .ok_or("Workspace state layout disappeared")?;
    Ok(WorkspaceStore::open_existing(&existing)?)
}

fn connection(fixture: &Fixture) -> TestResult<Connection> {
    let connection = Connection::open(fixture.layout.database_path())?;
    connection.pragma_update(None, "foreign_keys", true)?;
    Ok(connection)
}

fn bound_agent(
    fixture: &Fixture,
    seed: u128,
    display_name: &str,
) -> TestResult<RegisteredAgentInstance> {
    Ok(RegisteredAgentInstance::create_bound(
        AgentInstanceId::from_uuid(id(seed)),
        fixture.workspace_id,
        fixture.activity_id,
        AgentSessionId::from_uuid(id(seed + 0x1000)),
        AgentDisplayName::new(display_name.to_owned())?,
        AgentDeclaredRole::new("worker".to_owned())?,
        AgentTransportKind::Stdio,
        AuthenticatedPrincipal::TrustedStdio,
        timestamp(10)?,
    ))
}

fn legacy_agent(fixture: &Fixture, seed: u128) -> TestResult<RegisteredAgentInstance> {
    Ok(RegisteredAgentInstance::create(
        AgentInstanceId::from_uuid(id(seed)),
        fixture.workspace_id,
        fixture.activity_id,
        AgentDisplayName::new("legacy".to_owned())?,
        AgentDeclaredRole::new("worker".to_owned())?,
        AgentTransportKind::Stdio,
        timestamp(3)?,
    ))
}

fn count(connection: &Connection, query: &str) -> TestResult<i64> {
    Ok(connection.query_row(query, [], |row| row.get(0))?)
}

fn assert_reconciliation_only_effect_binding(
    fixture: &Fixture,
    baseline_presence: i64,
    baseline_events: i64,
    baseline_inbox: i64,
    baseline_outbox: i64,
) -> TestResult {
    let connection = connection(fixture)?;
    assert_eq!(
        count(
            &connection,
            "SELECT COUNT(*) FROM agent_session_reconciliations",
        )?,
        1,
    );
    assert_eq!(
        count(&connection, "SELECT COUNT(*) FROM agent_presence")?,
        baseline_presence
    );
    assert_eq!(
        count(&connection, "SELECT COUNT(*) FROM agent_events")?,
        baseline_events
    );
    assert_eq!(
        count(&connection, "SELECT COUNT(*) FROM agent_inbox")?,
        baseline_inbox
    );
    assert_eq!(
        count(
            &connection,
            "SELECT COUNT(*) FROM agent_effect_outbox_entries"
        )?,
        baseline_outbox,
    );
    Ok(())
}

fn reservation_request(
    fixture: &Fixture,
    agent: &RegisteredAgentInstance,
    request_seed: u128,
) -> TestResult<AgentBindingReservationRequest> {
    Ok(AgentBindingReservationRequest::new(
        id(request_seed),
        fixture.activity_id,
        agent.id(),
        agent
            .session_id()
            .ok_or("bound test Agent has no session")?,
        agent.principal(),
        timestamp(11)?,
    )?)
}

fn activation_request(
    request_id: Uuid,
    digest_byte: u8,
    display_name: &str,
) -> TestResult<AgentBindingActivationRequest> {
    Ok(AgentBindingActivationRequest::new(
        request_id,
        [digest_byte; 32],
        AgentDisplayName::new(display_name.to_owned())?,
        AgentDeclaredRole::new("worker".to_owned())?,
        AgentTransportKind::Stdio,
    )?)
}

fn coordinator_actor(
    fixture: &Fixture,
    binding: forge_domain::ActivityCoordinatorBinding,
    agent: &RegisteredAgentInstance,
) -> TestResult<ActivityCoordinatorActor> {
    Ok(ActivityCoordinatorActor::new(
        fixture.workspace_id,
        fixture.activity_id,
        binding.agent_id(),
        binding.revision(),
        agent.principal(),
        agent
            .session_id()
            .ok_or("coordinator Agent has no session")?,
    ))
}

#[test]
#[allow(clippy::too_many_lines)]
fn delegated_activation_replays_exactly_and_writes_only_effect_state() -> TestResult {
    let fixture = fixture("activation")?;
    let mut store = reopen(&fixture)?;
    let agent = bound_agent(&fixture, 0xD710, "worker-a")?;
    let freeze = store.freeze_agent_operations(&AgentOperationsFreezeRequest::new(
        id(0xD720),
        id(0xD721),
        timestamp(4)?,
    )?)?;
    let request = reservation_request(&fixture, &agent, 0xD730)?;
    let _reservation = store.reserve_agent_binding(&freeze, &request, timestamp(12)?)?;
    assert!(store.get_agent(agent.id())?.is_none());

    let delegation = store.delegate_agent_operations(&freeze, [0x11; 32], timestamp(20)?)?;
    assert_eq!(
        store.agent_operations_delegation()?.as_ref(),
        Some(&delegation)
    );
    let replay = store.delegate_agent_operations(&freeze, [0x11; 32], timestamp(99)?)?;
    assert_eq!(replay, delegation);
    assert_eq!(replay.delegated_at(), timestamp(20)?);
    assert!(
        store
            .delegate_agent_operations(&freeze, [0x12; 32], timestamp(99)?)
            .is_err()
    );

    let requested_activation = activation_request(request.request_id(), 0x21, "worker-a")?;
    let activation =
        store.activate_agent_binding(&delegation, &requested_activation, timestamp(21)?)?;
    assert_eq!(activation.request_id(), request.request_id());
    assert!(store.get_agent(agent.id())?.is_some());
    let changed_metadata = activation_request(request.request_id(), 0x22, "changed-worker-a")?;
    assert!(
        store
            .activate_agent_binding(&delegation, &changed_metadata, timestamp(22)?)
            .is_err()
    );
    drop(store);

    let mut reopened = reopen(&fixture)?;
    assert_eq!(
        reopened.agent_operations_delegation()?,
        Some(delegation.clone())
    );
    assert_eq!(
        reopened.agent_binding_activation(request.request_id())?,
        Some(activation.clone())
    );
    let replayed_activation =
        reopened.activate_agent_binding(&delegation, &requested_activation, timestamp(99)?)?;
    assert_eq!(replayed_activation, activation);
    assert_eq!(replayed_activation.activated_at(), timestamp(21)?);

    let late_agent = bound_agent(&fixture, 0xD740, "late-reserved-worker")?;
    let late_request = reservation_request(&fixture, &late_agent, 0xD741)?;
    let late_reservation =
        reopened.reserve_agent_binding(&freeze, &late_request, timestamp(100)?)?;
    assert_eq!(late_reservation.request(), &late_request);
    assert!(reopened.get_agent(late_agent.id())?.is_none());
    let facts = reopened.agent_effect_outbox(0, 64)?;
    assert_eq!(facts.len(), 1);
    match facts[0].fact() {
        crate::workspace_agent_effect_outbox::AgentEffectFact::Focus(event) => {
            assert_eq!(event.agent_id(), agent.id());
            assert_eq!(event.activity_id(), fixture.activity_id);
            assert_eq!(event.sequence().get(), 1);
        }
        crate::workspace_agent_effect_outbox::AgentEffectFact::Transition(_) => {
            return Err("activation did not copy its initial Focus fact".into());
        }
    }
    drop(reopened);

    let connection = connection(&fixture)?;
    assert_eq!(
        count(&connection, "SELECT COUNT(*) FROM agent_instances")?,
        1
    );
    assert_eq!(
        count(&connection, "SELECT COUNT(*) FROM agent_focus_events")?,
        1
    );
    assert_eq!(
        count(&connection, "SELECT COUNT(*) FROM agent_presence")?,
        0
    );
    assert_eq!(count(&connection, "SELECT COUNT(*) FROM agent_events")?, 0);
    assert_eq!(count(&connection, "SELECT COUNT(*) FROM agent_inbox")?, 0);
    assert_eq!(
        count(
            &connection,
            "SELECT COUNT(*) FROM agent_binding_activations"
        )?,
        1
    );
    assert_eq!(
        count(
            &connection,
            "SELECT COUNT(*) FROM agent_effect_outbox_entries"
        )?,
        1
    );
    assert_eq!(
        count(
            &connection,
            "SELECT COUNT(*) FROM agent_effect_outbox_focus"
        )?,
        1
    );
    assert_eq!(
        count(
            &connection,
            "SELECT COUNT(*) FROM agent_effect_outbox_transitions"
        )?,
        0
    );
    drop(connection);
    fs::remove_dir_all(fixture.root)?;
    Ok(())
}

#[test]
fn delegated_legacy_session_reconciliation_writes_only_effect_binding() -> TestResult {
    let fixture = fixture("legacy-session-reconciliation")?;
    let legacy = legacy_agent(&fixture, 0xD745)?;
    let direct = connection(&fixture)?;
    crate::legacy_agent_seed::seed_agent(&direct, &legacy, None)?;
    let inserted =
        crate::workspace_agents::get(&direct, legacy.id())?.ok_or("legacy Agent missing")?;
    assert_eq!(inserted.session_id(), None);
    let baseline_presence = count(&direct, "SELECT COUNT(*) FROM agent_presence")?;
    let baseline_events = count(&direct, "SELECT COUNT(*) FROM agent_events")?;
    let baseline_inbox = count(&direct, "SELECT COUNT(*) FROM agent_inbox")?;
    let baseline_outbox = count(&direct, "SELECT COUNT(*) FROM agent_effect_outbox_entries")?;
    drop(direct);

    let mut store = reopen(&fixture)?;
    let freeze = store.freeze_agent_operations(&AgentOperationsFreezeRequest::new(
        id(0xD746),
        id(0xD747),
        timestamp(10)?,
    )?)?;
    let delegation = store.delegate_agent_operations(&freeze, [0x61; 32], timestamp(20)?)?;
    let session_id = AgentSessionId::from_uuid(id(0xD748));
    let command = BindExistingAgentSession::new(
        fixture.workspace_id,
        fixture.activity_id,
        legacy.id(),
        session_id,
        legacy.principal(),
        legacy.revision(),
        timestamp(21)?,
    );
    let request = AgentSessionReconciliationRequest::new(id(0xD749), command)?;
    let receipt = store.reconcile_agent_session(&delegation, request)?;
    assert_eq!(receipt.request_id(), id(0xD749));
    assert_eq!(receipt.agent_id(), legacy.id());
    assert_eq!(receipt.session_id(), session_id);
    assert_eq!(receipt.expected_agent_revision(), legacy.revision());
    assert_eq!(
        receipt.result_agent_revision().get(),
        legacy.revision().get() + 1
    );
    assert_eq!(receipt.reconciled_at(), timestamp(21)?);
    assert_eq!(
        store.agent_session_reconciliation(id(0xD749))?,
        Some(receipt)
    );
    assert_eq!(
        store.reconcile_agent_session(&delegation, request)?,
        receipt
    );

    let rebound = store
        .get_agent(legacy.id())?
        .ok_or("reconciled legacy Agent missing")?;
    assert_eq!(rebound.session_id(), Some(session_id));
    assert_eq!(rebound.revision(), receipt.result_agent_revision());

    let conflicting = AgentSessionReconciliationRequest::new(
        id(0xD750),
        BindExistingAgentSession::new(
            fixture.workspace_id,
            fixture.activity_id,
            legacy.id(),
            AgentSessionId::from_uuid(id(0xD751)),
            legacy.principal(),
            legacy.revision(),
            timestamp(22)?,
        ),
    )?;
    assert!(
        store
            .reconcile_agent_session(&delegation, conflicting)
            .is_err()
    );
    drop(store);

    let reopened = reopen(&fixture)?;
    assert_eq!(
        reopened.agent_session_reconciliation(id(0xD749))?,
        Some(receipt)
    );
    drop(reopened);

    assert_reconciliation_only_effect_binding(
        &fixture,
        baseline_presence,
        baseline_events,
        baseline_inbox,
        baseline_outbox,
    )?;
    fs::remove_dir_all(fixture.root)?;
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn delegated_work_focus_and_coordinator_transfer_use_facts_and_deny_legacy_writers() -> TestResult {
    let fixture = fixture("work-and-coordinator")?;
    let legacy = legacy_agent(&fixture, 0xD740)?;
    let legacy_connection = connection(&fixture)?;
    crate::legacy_agent_seed::seed_agent(&legacy_connection, &legacy, None)?;
    drop(legacy_connection);

    let mut store = reopen(&fixture)?;
    let first = bound_agent(&fixture, 0xD750, "worker-a")?;
    let second = bound_agent(&fixture, 0xD760, "worker-b")?;
    let freeze = store.freeze_agent_operations(&AgentOperationsFreezeRequest::new(
        id(0xD770),
        id(0xD771),
        timestamp(4)?,
    )?)?;
    let first_request = reservation_request(&fixture, &first, 0xD780)?;
    let second_request = reservation_request(&fixture, &second, 0xD790)?;
    let _first_reservation =
        store.reserve_agent_binding(&freeze, &first_request, timestamp(12)?)?;
    let _second_reservation =
        store.reserve_agent_binding(&freeze, &second_request, timestamp(12)?)?;
    let delegation = store.delegate_agent_operations(&freeze, [0x31; 32], timestamp(20)?)?;
    let _first_activation = store.activate_agent_binding(
        &delegation,
        &activation_request(first_request.request_id(), 0x41, "worker-a")?,
        timestamp(21)?,
    )?;
    let _second_activation = store.activate_agent_binding(
        &delegation,
        &activation_request(second_request.request_id(), 0x42, "worker-b")?,
        timestamp(21)?,
    )?;

    let claimed = store.claim_activity_coordinator(
        ClaimActivityCoordinator::new(
            fixture.workspace_id,
            fixture.activity_id,
            first.id(),
            first.principal(),
            timestamp(30)?,
            first.session_id().ok_or("first Agent has no session")?,
        ),
        timestamp(99)?,
    )?;
    let transferred_to_second = store.transfer_activity_coordinator(
        TransferActivityCoordinator::new(
            coordinator_actor(&fixture, claimed, &first)?,
            second.id(),
            timestamp(31)?,
        ),
        timestamp(99)?,
    )?;
    let transferred_back = store.transfer_activity_coordinator(
        TransferActivityCoordinator::new(
            coordinator_actor(&fixture, transferred_to_second, &second)?,
            first.id(),
            timestamp(32)?,
        ),
        timestamp(99)?,
    )?;
    assert_eq!(transferred_back.agent_id(), first.id());
    assert_eq!(
        transferred_back.revision(),
        ActivityCoordinatorRevision::new(3)?
    );

    let current_first = store
        .get_agent(first.id())?
        .ok_or("activated first Agent disappeared")?;
    let focused_first = store.set_agent_focus(
        coordinator_actor(&fixture, transferred_back, &first)?,
        &SetAgentFocus::new(
            first.id(),
            fixture.activity_id,
            current_first.revision(),
            AgentFocus::unfocused(),
            timestamp(40)?,
        ),
        timestamp(40)?,
    )?;
    assert_eq!(focused_first.revision().get(), 2);

    let facts = store.agent_effect_outbox(0, 64)?;
    let focus_facts = facts
        .iter()
        .filter(|entry| {
            matches!(
                entry.fact(),
                crate::workspace_agent_effect_outbox::AgentEffectFact::Focus(_)
            )
        })
        .count();
    let transition_facts = facts
        .iter()
        .filter_map(|entry| match entry.fact() {
            crate::workspace_agent_effect_outbox::AgentEffectFact::Transition(event) => Some(event),
            crate::workspace_agent_effect_outbox::AgentEffectFact::Focus(_) => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(focus_facts, 3);
    assert_eq!(transition_facts.len(), 3);
    assert_eq!(
        transition_facts
            .iter()
            .map(|event| event.membership_revision().get())
            .collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    assert_ne!(
        transition_facts[0].id(),
        transition_facts[1].id(),
        "A -> B -> A must produce distinct immutable facts"
    );
    assert_ne!(transition_facts[1].id(), transition_facts[2].id());

    // Plan 05F uses a separate immutable outbox for Forge-owned effect facts.
    // Exercise the source protocol under the real delegation seal and prove an
    // exact retry does not manufacture a second fact.
    let execution_id = forge_domain::ExecutionId::from_uuid(id(0xD7B0));
    let provenance = forge_domain::ExecutionAgentProvenance::new(
        execution_id,
        first.id(),
        focused_first.revision(),
        first.principal(),
        forge_domain::GoalNodeAttribution::new(
            forge_domain::GoalId::from_uuid(id(0xD7B1)),
            forge_domain::GoalRevision::INITIAL,
            forge_domain::DagRevisionNumber::INITIAL,
            forge_domain::DagNodeId::from_uuid(id(0xD7B2)),
            forge_domain::DagNodeRevision::INITIAL,
        ),
        forge_domain::ExecutionCommandId::new("make:ci".to_owned())?,
        first.session_id().ok_or("first Agent has no session")?,
    );
    let outcome = forge_domain::ExecutionOutcome::new(
        execution_id,
        forge_domain::ExecutionTermination::new(
            forge_domain::ExecutionCompletionStatus::Exited,
            Some(0),
            None,
        ),
        1,
        forge_domain::BoundedExecutionOutput::new(Vec::new(), 0, false),
        forge_domain::BoundedExecutionOutput::new(Vec::new(), 0, false),
    );
    let terminal = forge_domain::RegisteredExecution::from_parts_with_provenance(
        forge_domain::ExecutionAttribution::new(
            execution_id,
            fixture.workspace_id,
            fixture.activity_id,
        ),
        forge_domain::ExecutionRecordDefinition::new(
            forge_domain::ExecutionMode::Structured,
            None,
            forge_domain::ExecutionLimits::new(
                forge_domain::ExecutionTimeoutMillis::new(1_000)?,
                forge_domain::ExecutionOutputLimit::DEFAULT,
            ),
            forge_domain::ExecutionPermissions::new(true, false, false),
            forge_domain::ExecutionRequestDigest::from_bytes([0x51; 32]),
        ),
        forge_domain::ExecutionRecordLifecycle::new(
            forge_domain::ExecutionState::Completed,
            forge_domain::ExecutionTimestamps::new(timestamp(60)?, timestamp(61)?)?,
            forge_domain::ExecutionRevision::new(3)?,
            Some(outcome),
            None,
        ),
        Some(provenance),
    )?;
    let mut fact_connection = connection(&fixture)?;
    let fact_transaction =
        fact_connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    crate::workspace_effect_fact_outbox::append_execution_terminal(
        &fact_transaction,
        &terminal,
        None,
    )?;
    crate::workspace_effect_fact_outbox::append_execution_terminal(
        &fact_transaction,
        &terminal,
        None,
    )?;
    fact_transaction.commit()?;

    let effect_facts = store.effect_fact_outbox(0, 64)?;
    assert_eq!(effect_facts.len(), 1);
    let effect_entry = &effect_facts[0];
    assert_eq!(effect_entry.migration_id(), delegation.migration_id());
    assert_eq!(effect_entry.destination_id(), delegation.destination_id());
    assert_eq!(effect_entry.workspace_id(), fixture.workspace_id);
    match effect_entry.fact() {
        crate::EffectFact::ExecutionTerminal(fact) => {
            assert_eq!(fact.execution_id(), execution_id);
            assert_eq!(fact.activity_id(), fixture.activity_id);
            assert_eq!(fact.state(), forge_domain::ExecutionState::Completed);
            assert_eq!(fact.agent_id(), first.id());
            assert_eq!(fact.agent_revision(), focused_first.revision());
            assert_eq!(fact.session_id(), first.session_id());
            assert!(fact.verification().is_none());
        }
        crate::EffectFact::ChangeSetTerminal(_) => {
            unreachable!("execution work must not produce a ChangeSet terminal fact")
        }
        crate::EffectFact::AssignmentReviewed(_) => {
            unreachable!("execution work must not produce an assignment-review fact")
        }
        crate::EffectFact::AssignmentOffered(_) => {
            unreachable!("execution work must not produce an assignment-offer fact")
        }
        crate::EffectFact::AssignmentSubmitted(_) => {
            unreachable!("execution work must not produce an assignment-submission fact")
        }
    }
    assert!(
        store
            .effect_fact_outbox(effect_entry.sequence(), 64)?
            .is_empty(),
        "the source cursor must advance strictly after the observed fact"
    );

    assert!(
        store
            .release_agent_operations_freeze(
                freeze.migration_id(),
                freeze.revision(),
                timestamp(50)?
            )
            .is_err()
    );
    assert!(
        store
            .export_agent_operations(
                freeze.migration_id(),
                AgentOperationsExportCursor::default()
            )
            .is_err()
    );
    assert_eq!(
        store.agent_operations_freeze(freeze.migration_id())?,
        Some(freeze)
    );
    drop(store);

    let connection = connection(&fixture)?;
    assert_eq!(
        count(&connection, "SELECT COUNT(*) FROM agent_instances")?,
        3
    );
    assert_eq!(
        count(&connection, "SELECT COUNT(*) FROM agent_focus_events")?,
        4
    );
    assert_eq!(
        count(&connection, "SELECT COUNT(*) FROM agent_presence")?,
        0
    );
    assert_eq!(count(&connection, "SELECT COUNT(*) FROM agent_events")?, 0);
    assert_eq!(count(&connection, "SELECT COUNT(*) FROM agent_inbox")?, 0);
    assert_eq!(
        count(
            &connection,
            "SELECT COUNT(*) FROM agent_effect_outbox_transitions"
        )?,
        3
    );
    drop(connection);
    fs::remove_dir_all(fixture.root)?;
    Ok(())
}

#[test]
fn delegated_activation_rolls_back_receipt_focus_and_fact_on_agent_insert_failure() -> TestResult {
    let fixture = fixture("activation-rollback")?;
    let mut store = reopen(&fixture)?;
    let agent = bound_agent(&fixture, 0xD7C0, "rollback-worker")?;
    let freeze = store.freeze_agent_operations(&AgentOperationsFreezeRequest::new(
        id(0xD7D0),
        id(0xD7D1),
        timestamp(4)?,
    )?)?;
    let request = reservation_request(&fixture, &agent, 0xD7E0)?;
    let _reservation = store.reserve_agent_binding(&freeze, &request, timestamp(12)?)?;
    let delegation = store.delegate_agent_operations(&freeze, [0x51; 32], timestamp(20)?)?;
    drop(store);

    let mut connection = connection(&fixture)?;
    connection.execute_batch(
        "CREATE TEMP TRIGGER test_abort_reserved_agent
         BEFORE INSERT ON agent_instances
         BEGIN SELECT RAISE(ABORT, 'test activation abort'); END",
    )?;
    let activation_request = activation_request(request.request_id(), 0x61, "rollback-worker")?;
    assert!(
        crate::workspace_agent_binding_activation::activate(
            &mut connection,
            &delegation,
            &activation_request,
            timestamp(21)?,
        )
        .is_err()
    );
    assert_eq!(
        count(&connection, "SELECT COUNT(*) FROM agent_instances")?,
        0
    );
    assert_eq!(
        count(&connection, "SELECT COUNT(*) FROM agent_focus_events")?,
        0
    );
    assert_eq!(
        count(
            &connection,
            "SELECT COUNT(*) FROM agent_binding_activations"
        )?,
        0
    );
    assert_eq!(
        count(
            &connection,
            "SELECT COUNT(*) FROM agent_effect_outbox_entries"
        )?,
        0
    );
    assert_eq!(
        count(
            &connection,
            "SELECT COUNT(*) FROM agent_effect_outbox_focus"
        )?,
        0
    );
    assert_eq!(
        count(
            &connection,
            "SELECT COUNT(*) FROM agent_effect_outbox_transitions"
        )?,
        0
    );
    assert_eq!(
        count(&connection, "SELECT COUNT(*) FROM agent_presence")?,
        0
    );
    assert_eq!(count(&connection, "SELECT COUNT(*) FROM agent_events")?, 0);
    assert_eq!(count(&connection, "SELECT COUNT(*) FROM agent_inbox")?, 0);
    drop(connection);
    fs::remove_dir_all(fixture.root)?;
    Ok(())
}
