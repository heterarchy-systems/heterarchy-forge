use super::*;
use crate::{legacy_agent_seed, workspace_agent_events, workspace_agents, workspace_coordinators};
use forge_domain::{
    ActivityCoordinatorActor, ActivityId, AgentDeclaredRole, AgentDisplayName, AgentEventKind,
    AgentInstanceId, AgentSessionId, AgentTransportKind, AuthenticatedPrincipal,
    ClaimActivityCoordinator, RegisteredAgentInstance, TimestampMillis,
    TransferActivityCoordinator, WorkspaceId,
};
use rusqlite::{Connection, params, types::Value};
use std::{error::Error, fs};
use uuid::Uuid;

fn id(value: u128) -> Uuid {
    Uuid::from_u128(value)
}

fn timestamp(value: i64) -> Result<TimestampMillis, Box<dyn Error>> {
    Ok(TimestampMillis::new(value)?)
}

fn agent(
    value: u128,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    updated_at: TimestampMillis,
) -> Result<RegisteredAgentInstance, Box<dyn Error>> {
    Ok(RegisteredAgentInstance::create_bound(
        AgentInstanceId::from_uuid(id(value)),
        workspace_id,
        activity_id,
        AgentSessionId::from_uuid(id(value + 0x5000)),
        AgentDisplayName::new(format!("agent-{value}"))?,
        AgentDeclaredRole::new("worker".to_owned())?,
        AgentTransportKind::Stdio,
        AuthenticatedPrincipal::TrustedStdio,
        updated_at,
    ))
}

struct Fixture {
    connection: Connection,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    first: RegisteredAgentInstance,
    second: RegisteredAgentInstance,
    third: RegisteredAgentInstance,
}

fn recovery_fixture(connection: Connection) -> Result<Fixture, Box<dyn Error>> {
    connection.execute_batch(
        "PRAGMA foreign_keys = ON;
         CREATE TABLE workspace (workspace_id BLOB PRIMARY KEY NOT NULL);
         CREATE TABLE activities (
            activity_id BLOB PRIMARY KEY NOT NULL,
            workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id),
            state INTEGER NOT NULL,
            lease_owner_id BLOB,
            lease_until_ms INTEGER
         );
         CREATE TABLE goals (goal_id BLOB PRIMARY KEY NOT NULL);
         CREATE TABLE goal_dag_revisions (
            goal_id BLOB NOT NULL,
            dag_revision INTEGER NOT NULL,
            PRIMARY KEY(goal_id, dag_revision)
         );
         CREATE TABLE goal_dag_nodes (
            goal_id BLOB NOT NULL,
            dag_revision INTEGER NOT NULL,
            node_id BLOB NOT NULL,
            PRIMARY KEY(goal_id, dag_revision, node_id)
         );
         CREATE TABLE writer_leases (
            lease_id BLOB PRIMARY KEY,
            workspace_id BLOB,
            activity_id BLOB,
            agent_id BLOB,
            state INTEGER
         );
         CREATE TABLE executions (
            execution_id BLOB PRIMARY KEY,
            activity_id BLOB,
            state INTEGER
         );
         CREATE TABLE execution_provenance (
            execution_id BLOB,
            agent_id BLOB
         );
         INSERT INTO goals(goal_id) VALUES (x'11111111111111111111111111111111');
         INSERT INTO goal_dag_revisions(goal_id, dag_revision) VALUES (x'11111111111111111111111111111111', 1);
         INSERT INTO goal_dag_nodes(goal_id, dag_revision, node_id) VALUES (x'11111111111111111111111111111111', 1, x'22222222222222222222222222222222');",
    )?;
    workspace_agents::create_schema(&connection)?;
    workspace_coordinators::create_schema(&connection)?;
    workspace_agent_events::create_schema(&connection)?;
    create_schema(&connection)?;

    let workspace_id = WorkspaceId::from_uuid(id(1));
    let activity_id = ActivityId::from_uuid(id(2));
    connection.execute(
        "INSERT INTO workspace(workspace_id) VALUES (?1)",
        params![workspace_id.into_uuid().as_bytes()],
    )?;
    connection.execute(
        "INSERT INTO activities(activity_id, workspace_id, state, lease_owner_id, lease_until_ms) VALUES (?1, ?2, 1, ?3, 100)",
        params![
            activity_id.into_uuid().as_bytes(),
            workspace_id.into_uuid().as_bytes(),
            id(3).as_bytes(),
        ],
    )?;
    let first = agent(10, workspace_id, activity_id, timestamp(4)?)?;
    let second = agent(11, workspace_id, activity_id, timestamp(5)?)?;
    let third = agent(12, workspace_id, activity_id, timestamp(6)?)?;
    for participant in [&first, &second, &third] {
        legacy_agent_seed::seed_agent(
            &connection,
            participant,
            Some(workspace_agent_events::derived_event_id(
                participant.id(),
                participant.revision(),
                AgentEventKind::Joined,
            )),
        )?;
    }
    Ok(Fixture {
        connection,
        workspace_id,
        activity_id,
        first,
        second,
        third,
    })
}

fn claim_first(fixture: &mut Fixture) -> Result<(), Box<dyn Error>> {
    let _binding = workspace_coordinators::claim(
        &mut fixture.connection,
        ClaimActivityCoordinator::new(
            fixture.workspace_id,
            fixture.activity_id,
            fixture.first.id(),
            AuthenticatedPrincipal::TrustedStdio,
            timestamp(7)?,
            fixture.first.session_id().ok_or("first session missing")?,
        ),
        timestamp(99)?,
    )?;
    Ok(())
}

fn confirmed(
    fence: CoordinatorRecoveryFence,
    recovery_id: Uuid,
    reason: &str,
    confirmed_at: i64,
) -> Result<ConfirmedCoordinatorRecovery, Box<dyn Error>> {
    Ok(ConfirmedCoordinatorRecovery::new(
        recovery_id,
        fence,
        CoordinatorRecoveryReason::new(reason.to_owned())?,
        timestamp(confirmed_at)?,
    )?)
}

fn transfer_to(
    fixture: &mut Fixture,
    source: &RegisteredAgentInstance,
    target: &RegisteredAgentInstance,
    expected_revision: i64,
    observed_at: i64,
) -> Result<(), Box<dyn Error>> {
    let actor = ActivityCoordinatorActor::new(
        fixture.workspace_id,
        fixture.activity_id,
        source.id(),
        forge_domain::ActivityCoordinatorRevision::new(expected_revision)?,
        source.principal(),
        source.session_id().ok_or("source session missing")?,
    );
    let _binding = workspace_coordinators::transfer(
        &mut fixture.connection,
        TransferActivityCoordinator::new(actor, target.id(), timestamp(observed_at)?),
        timestamp(99)?,
    )?;
    Ok(())
}

fn agent_snapshot(
    connection: &Connection,
    agent_id: AgentInstanceId,
) -> Result<RegisteredAgentInstance, Box<dyn Error>> {
    Ok(workspace_agents::get_in_transaction(connection, agent_id)?.ok_or("agent missing")?)
}

fn goal_rows(connection: &Connection) -> Result<Vec<Vec<Value>>, Box<dyn Error>> {
    let mut statement = connection.prepare("SELECT goal_id FROM goals ORDER BY goal_id")?;
    Ok(statement
        .query_map([], |row| Ok(vec![row.get(0)?]))?
        .collect::<Result<Vec<_>, _>>()?)
}

fn dag_rows(connection: &Connection) -> Result<Vec<Vec<Value>>, Box<dyn Error>> {
    let mut statement = connection.prepare(
        "SELECT goal_id, dag_revision, node_id FROM goal_dag_nodes ORDER BY goal_id, dag_revision, node_id",
    )?;
    Ok(statement
        .query_map([], |row| Ok(vec![row.get(0)?, row.get(1)?, row.get(2)?]))?
        .collect::<Result<Vec<_>, _>>()?)
}

#[test]
fn recovery_changes_only_binding_and_preserves_agents_focus_and_dag() -> Result<(), Box<dyn Error>>
{
    let mut fixture = recovery_fixture(Connection::open_in_memory()?)?;
    claim_first(&mut fixture)?;
    let first_before = agent_snapshot(&fixture.connection, fixture.first.id())?;
    let second_before = agent_snapshot(&fixture.connection, fixture.second.id())?;
    let goals_before = goal_rows(&fixture.connection)?;
    let dag_before = dag_rows(&fixture.connection)?;
    let fence = preview(
        &fixture.connection,
        fixture.workspace_id,
        fixture.activity_id,
        fixture.second.id(),
    )?;
    let request = confirmed(fence, id(100), "owner-approved recovery", 8)?;
    let receipt = recover(&mut fixture.connection, &request)?;
    assert_eq!(receipt.binding().agent_id(), fixture.second.id());
    assert_eq!(receipt.binding().revision().get(), 2);
    assert_eq!(
        agent_snapshot(&fixture.connection, fixture.first.id())?,
        first_before
    );
    assert_eq!(
        agent_snapshot(&fixture.connection, fixture.second.id())?,
        second_before
    );
    assert_eq!(goal_rows(&fixture.connection)?, goals_before);
    assert_eq!(dag_rows(&fixture.connection)?, dag_before);
    let binding = workspace_coordinators::get(&fixture.connection, fixture.activity_id)?
        .ok_or("binding missing")?;
    assert_eq!(binding.agent_id(), fixture.second.id());
    Ok(())
}

#[test]
fn exact_replay_after_later_binding_change_does_not_reapply() -> Result<(), Box<dyn Error>> {
    let mut fixture = recovery_fixture(Connection::open_in_memory()?)?;
    claim_first(&mut fixture)?;
    let fence = preview(
        &fixture.connection,
        fixture.workspace_id,
        fixture.activity_id,
        fixture.second.id(),
    )?;
    let request = confirmed(fence, id(101), "owner-approved replay", 8)?;
    let receipt = recover(&mut fixture.connection, &request)?;
    let second = fixture.second.clone();
    let third = fixture.third.clone();
    transfer_to(&mut fixture, &second, &third, 2, 9)?;
    assert_eq!(recover(&mut fixture.connection, &request)?, receipt);
    let binding = workspace_coordinators::get(&fixture.connection, fixture.activity_id)?
        .ok_or("binding missing")?;
    assert_eq!(binding.agent_id(), fixture.third.id());
    assert_eq!(binding.revision().get(), 3);
    let changed = confirmed(fence, id(101), "changed owner reason", 8)?;
    assert!(matches!(
        recover(&mut fixture.connection, &changed),
        Err(CoordinatorRecoveryStoreError::ReplayConflict)
    ));
    Ok(())
}

#[test]
fn stale_fence_and_live_work_are_rejected() -> Result<(), Box<dyn Error>> {
    let mut fixture = recovery_fixture(Connection::open_in_memory()?)?;
    claim_first(&mut fixture)?;
    let fence = preview(
        &fixture.connection,
        fixture.workspace_id,
        fixture.activity_id,
        fixture.second.id(),
    )?;
    let first = fixture.first.clone();
    let third = fixture.third.clone();
    transfer_to(&mut fixture, &first, &third, 1, 8)?;
    let stale = confirmed(fence, id(102), "stale owner recovery", 9)?;
    assert!(matches!(
        recover(&mut fixture.connection, &stale),
        Err(CoordinatorRecoveryStoreError::FenceConflict)
    ));

    let mut writer_fixture = recovery_fixture(Connection::open_in_memory()?)?;
    claim_first(&mut writer_fixture)?;
    writer_fixture.connection.execute(
        "INSERT INTO writer_leases(lease_id,workspace_id,activity_id,agent_id,state) VALUES (?1,?2,?3,?4,0)",
        params![
            id(200).as_bytes(),
            writer_fixture.workspace_id.into_uuid().as_bytes(),
            writer_fixture.activity_id.into_uuid().as_bytes(),
            writer_fixture.first.id().into_uuid().as_bytes(),
        ],
    )?;
    assert!(matches!(
        preview(
            &writer_fixture.connection,
            writer_fixture.workspace_id,
            writer_fixture.activity_id,
            writer_fixture.second.id(),
        ),
        Err(CoordinatorRecoveryStoreError::Coordinator(
            CoordinatorStoreError::ActiveWriterLease(_)
        ))
    ));
    writer_fixture
        .connection
        .execute("DELETE FROM writer_leases", [])?;
    writer_fixture.connection.execute(
        "INSERT INTO executions(execution_id,activity_id,state) VALUES (?1,?2,0)",
        params![
            id(201).as_bytes(),
            writer_fixture.activity_id.into_uuid().as_bytes()
        ],
    )?;
    writer_fixture.connection.execute(
        "INSERT INTO execution_provenance(execution_id,agent_id) VALUES (?1,?2)",
        params![
            id(201).as_bytes(),
            writer_fixture.first.id().into_uuid().as_bytes()
        ],
    )?;
    assert!(matches!(
        preview(
            &writer_fixture.connection,
            writer_fixture.workspace_id,
            writer_fixture.activity_id,
            writer_fixture.second.id(),
        ),
        Err(CoordinatorRecoveryStoreError::Coordinator(
            CoordinatorStoreError::ActiveExecution(_)
        ))
    ));
    Ok(())
}

#[test]
fn audit_insert_failure_rolls_back_binding() -> Result<(), Box<dyn Error>> {
    let mut fixture = recovery_fixture(Connection::open_in_memory()?)?;
    claim_first(&mut fixture)?;
    let fence = preview(
        &fixture.connection,
        fixture.workspace_id,
        fixture.activity_id,
        fixture.second.id(),
    )?;
    let request = confirmed(fence, id(103), "audit rollback", 8)?;
    fixture.connection.execute_batch(
        "CREATE TRIGGER test_recovery_audit_abort BEFORE INSERT ON activity_coordinator_recoveries BEGIN SELECT RAISE(ABORT, 'audit failure'); END;",
    )?;
    assert!(matches!(
        recover(&mut fixture.connection, &request),
        Err(CoordinatorRecoveryStoreError::Sqlite(_))
    ));
    let binding = workspace_coordinators::get(&fixture.connection, fixture.activity_id)?
        .ok_or("binding missing")?;
    assert_eq!(binding.agent_id(), fixture.first.id());
    assert!(get(&fixture.connection, request.id())?.is_none());
    Ok(())
}

#[test]
fn reopen_and_codec_roundtrip_preserves_historical_receipt() -> Result<(), Box<dyn Error>> {
    let root = std::env::temp_dir().join(format!("coordinator-recovery-{}", Uuid::now_v7()));
    fs::create_dir(&root)?;
    let path = root.join("workspace.sqlite3");
    let receipt = {
        let mut fixture = recovery_fixture(Connection::open(&path)?)?;
        claim_first(&mut fixture)?;
        let fence = preview(
            &fixture.connection,
            fixture.workspace_id,
            fixture.activity_id,
            fixture.second.id(),
        )?;
        let request = confirmed(fence, id(104), "codec roundtrip", 8)?;
        recover(&mut fixture.connection, &request)?
    };
    let reopened = Connection::open(&path)?;
    assert_eq!(
        get(&reopened, receipt.request().id())?,
        Some(receipt.clone())
    );
    assert_eq!(
        list(
            &reopened,
            receipt.binding().workspace_id(),
            receipt.binding().activity_id(),
            1
        )?,
        vec![receipt]
    );
    drop(reopened);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn schema_and_limit_checks_remain_bounded() -> Result<(), Box<dyn Error>> {
    let connection = Connection::open_in_memory()?;
    create_schema(&connection)?;
    validate_schema(&connection)?;
    assert_eq!(schema_objects(), [("table", RECOVERIES_TABLE)]);
    let workspace_id = WorkspaceId::from_uuid(id(300));
    let activity_id = ActivityId::from_uuid(id(301));
    assert!(matches!(
        list(&connection, workspace_id, activity_id, 0),
        Err(CoordinatorRecoveryStoreError::InvalidLimit { limit: 0 })
    ));
    assert!(matches!(
        list(&connection, workspace_id, activity_id, 33),
        Err(CoordinatorRecoveryStoreError::InvalidLimit { limit: 33 })
    ));
    Ok(())
}
