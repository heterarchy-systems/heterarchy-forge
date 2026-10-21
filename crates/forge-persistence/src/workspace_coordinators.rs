//! Durable Activity-local planning Coordinator authority.
//!
//! Planning authority is a single fenced Agent binding per Activity. The
//! binding is independent from display roles and every authorization validates
//! the current revision, Open Activity, attached Agent, and authenticated
//! principal inside the caller's `SQLite` transaction.

use forge_domain::{
    ActivityCoordinatorActor, ActivityCoordinatorBinding, ActivityCoordinatorRevision, ActivityId,
    AgentEvent, AgentEventKind, AgentInstanceId, AgentParticipantRef, AuthenticatedPrincipal,
    ClaimActivityCoordinator, CoordinationSnapshot, CoordinatorSnapshot, TimestampMillis,
    TransferActivityCoordinator, WorkspaceId,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use thiserror::Error;
use uuid::Uuid;

use crate::workspace_agent_events;
use crate::workspace_agents::{self, AgentStoreError};

const COORDINATORS_TABLE: &str = "activity_coordinators";
const EXPECTED_COORDINATORS_TABLE_SQL: &str = "CREATE TABLE activity_coordinators (activity_id BLOB PRIMARY KEY NOT NULL REFERENCES activities(activity_id) CHECK(length(activity_id) = 16), workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16), agent_id BLOB NOT NULL CHECK(length(agent_id) = 16), revision INTEGER NOT NULL CHECK(revision >= 1), updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0), FOREIGN KEY(agent_id, workspace_id, activity_id) REFERENCES agent_instances(agent_id, workspace_id, activity_id))";
const EXPORT_COORDINATORS_QUERY: &str = "SELECT substr(activity_id,1,17), substr(workspace_id,1,17), substr(agent_id,1,17), revision, updated_at_ms FROM activity_coordinators WHERE workspace_id = ?1 AND (?2 IS NULL OR activity_id > ?2) ORDER BY activity_id ASC LIMIT ?3";

pub(crate) fn create_schema(connection: &Connection) -> Result<(), CoordinatorStoreError> {
    connection.execute_batch(EXPECTED_COORDINATORS_TABLE_SQL)?;
    Ok(())
}

pub(crate) fn schema_objects() -> [(&'static str, &'static str); 1] {
    [("table", COORDINATORS_TABLE)]
}

pub(crate) fn validate_schema(connection: &Connection) -> Result<(), CoordinatorStoreError> {
    let actual: Option<String> = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = ?1",
            params![COORDINATORS_TABLE],
            |row| row.get(0),
        )
        .optional()?;
    if actual.as_deref().map(normalize_sql) != Some(normalize_sql(EXPECTED_COORDINATORS_TABLE_SQL))
    {
        return Err(CoordinatorStoreError::DamagedSchema(COORDINATORS_TABLE));
    }
    Ok(())
}

pub(crate) fn get(
    connection: &Connection,
    activity_id: ActivityId,
) -> Result<Option<ActivityCoordinatorBinding>, CoordinatorStoreError> {
    get_in_transaction(connection, activity_id)
}

/// Read Coordinator bindings for a frozen source in exact `activity_id` BLOB
/// order.  The caller owns the surrounding read transaction.
pub(crate) fn export_coordinators(
    connection: &Connection,
    workspace_id: WorkspaceId,
    after: Option<ActivityId>,
    limit: u32,
) -> Result<Vec<ActivityCoordinatorBinding>, CoordinatorStoreError> {
    let after_bytes = after.map(|value| value.into_uuid().into_bytes().to_vec());
    let mut statement = connection.prepare(EXPORT_COORDINATORS_QUERY)?;
    let mut rows = statement.query(params![
        workspace_id.into_uuid().as_bytes(),
        after_bytes,
        limit,
    ])?;
    let mut coordinators = Vec::new();
    while let Some(row) = rows.next()? {
        let activity_id = ActivityId::from_uuid(decode_uuid(
            &row.get::<_, Vec<u8>>(0)?,
            "coordinator.activity_id",
        )?);
        let actual_workspace = WorkspaceId::from_uuid(decode_uuid(
            &row.get::<_, Vec<u8>>(1)?,
            "coordinator.workspace_id",
        )?);
        if actual_workspace != workspace_id {
            return Err(CoordinatorStoreError::ActivityWorkspaceMismatch);
        }
        let agent_id = AgentInstanceId::from_uuid(decode_uuid(
            &row.get::<_, Vec<u8>>(2)?,
            "coordinator.agent_id",
        )?);
        let revision = ActivityCoordinatorRevision::new(row.get(3)?)
            .map_err(|_| CoordinatorStoreError::CorruptRecord("coordinator.revision"))?;
        let updated_at = TimestampMillis::new(row.get(4)?)
            .map_err(|_| CoordinatorStoreError::CorruptRecord("coordinator.updated_at_ms"))?;
        coordinators.push(ActivityCoordinatorBinding::new(
            actual_workspace,
            activity_id,
            agent_id,
            revision,
            updated_at,
        ));
    }
    Ok(coordinators)
}

pub(crate) fn claim(
    connection: &mut Connection,
    command: ClaimActivityCoordinator,
    admitted_at: TimestampMillis,
) -> Result<ActivityCoordinatorBinding, CoordinatorStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    crate::workspace_agent_migration::ensure_work_writes(&transaction)?;
    ensure_live_activity_in_transaction(
        &transaction,
        command.activity_id(),
        command.workspace_id(),
        admitted_at,
    )?;
    if let Some(existing) = get_in_transaction(&transaction, command.activity_id())? {
        if existing.agent_id() == command.agent_id()
            && existing.revision() == ActivityCoordinatorRevision::INITIAL
            && existing.updated_at() == command.observed_at()
        {
            ensure_agent(
                &transaction,
                command.workspace_id(),
                command.activity_id(),
                command.agent_id(),
                command.principal(),
                Some(command.session_id()),
            )?;
            transaction.commit()?;
            return Ok(existing);
        }
        return Err(CoordinatorStoreError::AlreadyBound(command.activity_id()));
    }
    ensure_open_activity(&transaction, command.activity_id(), command.workspace_id())?;
    ensure_agent(
        &transaction,
        command.workspace_id(),
        command.activity_id(),
        command.agent_id(),
        command.principal(),
        Some(command.session_id()),
    )?;
    transaction.execute(
        "INSERT INTO activity_coordinators (activity_id, workspace_id, agent_id, revision, updated_at_ms) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            command.activity_id().into_uuid().as_bytes(),
            command.workspace_id().into_uuid().as_bytes(),
            command.agent_id().into_uuid().as_bytes(),
            ActivityCoordinatorRevision::INITIAL.get(),
            command.observed_at().get(),
        ],
    )?;
    let claimed_agent = workspace_agents::get_in_transaction(&transaction, command.agent_id())?
        .ok_or(CoordinatorStoreError::AgentNotFound(command.agent_id()))?;
    let participant = AgentParticipantRef::new(
        claimed_agent.id(),
        claimed_agent.session_id(),
        claimed_agent.principal(),
        claimed_agent.display_name().clone(),
    );
    let role_event = AgentEvent::new(
        workspace_agent_events::derived_event_id(
            claimed_agent.id(),
            claimed_agent.revision(),
            AgentEventKind::RoleChanged,
        ),
        command.workspace_id(),
        command.activity_id(),
        workspace_agent_events::next_membership_revision(&transaction, command.activity_id())?,
        AgentEventKind::RoleChanged,
        None,
        Some(participant),
        CoordinationSnapshot::empty(),
        CoordinationSnapshot::empty(),
        CoordinatorSnapshot::unbound(),
        CoordinatorSnapshot::bound(
            claimed_agent.id(),
            claimed_agent.session_id(),
            ActivityCoordinatorRevision::INITIAL,
        ),
        command.observed_at(),
    );
    workspace_agent_events::append_event_in_transaction(&transaction, &role_event, &[])?;
    let binding = get_in_transaction(&transaction, command.activity_id())?
        .ok_or(CoordinatorStoreError::RecordMissing)?;
    transaction.commit()?;
    Ok(binding)
}

pub(crate) fn transfer(
    connection: &mut Connection,
    command: TransferActivityCoordinator,
    admitted_at: TimestampMillis,
) -> Result<ActivityCoordinatorBinding, CoordinatorStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    crate::workspace_agent_migration::ensure_work_writes(&transaction)?;
    let current = authorize_live_in_transaction(&transaction, command.current(), admitted_at)?;
    if current.agent_id() == command.next_agent_id() {
        return Err(CoordinatorStoreError::TargetAlreadyCoordinator);
    }
    let _ = ensure_attached_agent(
        &transaction,
        current.workspace_id(),
        current.activity_id(),
        command.next_agent_id(),
    )?;
    if command.observed_at().get() < current.updated_at().get() {
        return Err(CoordinatorStoreError::TimestampOrder);
    }
    let next_revision = current
        .revision()
        .checked_next()
        .map_err(|_| CoordinatorStoreError::RevisionOverflow)?;
    let changed = transaction.execute(
        "UPDATE activity_coordinators SET agent_id = ?1, revision = ?2, updated_at_ms = ?3 WHERE activity_id = ?4 AND agent_id = ?5 AND revision = ?6",
        params![
            command.next_agent_id().into_uuid().as_bytes(),
            next_revision.get(),
            command.observed_at().get(),
            current.activity_id().into_uuid().as_bytes(),
            current.agent_id().into_uuid().as_bytes(),
            current.revision().get(),
        ],
    )?;
    if changed != 1 {
        return Err(CoordinatorStoreError::RevisionConflict);
    }
    let binding = get_in_transaction(&transaction, current.activity_id())?
        .ok_or(CoordinatorStoreError::RecordMissing)?;
    if crate::workspace_agent_migration::delegation(&transaction)?.is_some() {
        append_transfer_fact(&transaction, &current, &binding, command.observed_at())?;
    }
    transaction.commit()?;
    Ok(binding)
}

/// A transfer keeps both work bindings attached. Its fact is keyed by the
/// Activity's prior planning revision, so returning to an earlier Agent does
/// not reuse that Agent's previous event identity.
fn append_transfer_fact(
    transaction: &rusqlite::Transaction<'_>,
    before: &ActivityCoordinatorBinding,
    after: &ActivityCoordinatorBinding,
    observed_at: TimestampMillis,
) -> Result<(), CoordinatorStoreError> {
    let source = workspace_agents::get_in_transaction(transaction, before.agent_id())?
        .ok_or(CoordinatorStoreError::AgentNotFound(before.agent_id()))?;
    let target = workspace_agents::get_in_transaction(transaction, after.agent_id())?
        .ok_or(CoordinatorStoreError::AgentNotFound(after.agent_id()))?;
    let event = AgentEvent::new(
        forge_domain::AgentEventId::for_coordinator_transfer(
            before.workspace_id(),
            before.activity_id(),
            before.revision(),
        ),
        before.workspace_id(),
        before.activity_id(),
        workspace_agent_events::next_membership_revision(transaction, before.activity_id())?,
        AgentEventKind::RoleChanged,
        Some(AgentParticipantRef::new(
            source.id(),
            source.session_id(),
            source.principal(),
            source.display_name().clone(),
        )),
        Some(AgentParticipantRef::new(
            target.id(),
            target.session_id(),
            target.principal(),
            target.display_name().clone(),
        )),
        workspace_agent_events::coordination_snapshot_for_agent(transaction, &source)?,
        workspace_agent_events::coordination_snapshot_for_agent(transaction, &target)?,
        CoordinatorSnapshot::bound(source.id(), source.session_id(), before.revision()),
        CoordinatorSnapshot::bound(target.id(), target.session_id(), after.revision()),
        observed_at,
    );
    workspace_agent_events::append_event_in_transaction(transaction, &event, &[])
        .map_err(CoordinatorStoreError::from)
}

pub(crate) fn ensure_no_active_writer_lease(
    connection: &Connection,
    agent_id: AgentInstanceId,
    activity_id: ActivityId,
) -> Result<(), CoordinatorStoreError> {
    let active: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM writer_leases WHERE agent_id = ?1 AND activity_id = ?2 AND state = 0)",
        params![agent_id.into_uuid().as_bytes(), activity_id.into_uuid().as_bytes()],
        |row| row.get(0),
    )?;
    if active {
        Err(CoordinatorStoreError::ActiveWriterLease(agent_id))
    } else {
        Ok(())
    }
}

pub(crate) fn ensure_no_active_execution(
    connection: &Connection,
    agent_id: AgentInstanceId,
    activity_id: ActivityId,
) -> Result<(), CoordinatorStoreError> {
    let active: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM execution_provenance AS p JOIN executions AS e ON e.execution_id = p.execution_id WHERE p.agent_id = ?1 AND e.activity_id = ?2 AND e.state IN (0, 1))",
        params![agent_id.into_uuid().as_bytes(), activity_id.into_uuid().as_bytes()],
        |row| row.get(0),
    )?;
    if active {
        Err(CoordinatorStoreError::ActiveExecution(agent_id))
    } else {
        Ok(())
    }
}

pub(crate) fn authorize_in_transaction(
    connection: &Connection,
    actor: ActivityCoordinatorActor,
) -> Result<ActivityCoordinatorBinding, CoordinatorStoreError> {
    authorize_current_in_transaction(connection, actor, None)
}

/// Authorize a Coordinator mutation only while its Activity has a live owner
/// lease at the trusted time supplied by the application boundary.
pub(crate) fn authorize_live_in_transaction(
    connection: &Connection,
    actor: ActivityCoordinatorActor,
    admitted_at: TimestampMillis,
) -> Result<ActivityCoordinatorBinding, CoordinatorStoreError> {
    authorize_current_in_transaction(connection, actor, Some(admitted_at))
}

fn authorize_current_in_transaction(
    connection: &Connection,
    actor: ActivityCoordinatorActor,
    admitted_at: Option<TimestampMillis>,
) -> Result<ActivityCoordinatorBinding, CoordinatorStoreError> {
    let current = get_in_transaction(connection, actor.activity_id())?.ok_or(
        CoordinatorStoreError::CoordinatorMissing(actor.activity_id()),
    )?;
    if current.workspace_id() != actor.workspace_id()
        || current.agent_id() != actor.agent_id()
        || current.revision() != actor.expected_revision()
    {
        return Err(CoordinatorStoreError::CoordinatorFenceConflict);
    }
    if let Some(admitted_at) = admitted_at {
        ensure_live_activity_in_transaction(
            connection,
            actor.activity_id(),
            actor.workspace_id(),
            admitted_at,
        )?;
    } else {
        ensure_open_activity(connection, actor.activity_id(), actor.workspace_id())?;
    }
    ensure_agent(
        connection,
        actor.workspace_id(),
        actor.activity_id(),
        actor.agent_id(),
        actor.principal(),
        Some(actor.session_id()),
    )?;
    Ok(current)
}

/// Require an exact Open Activity with a present, unexpired runtime-owner
/// lease. The caller supplies the trusted admission time; persistence never
/// samples a clock or substitutes a request audit timestamp.
pub(crate) fn ensure_live_activity_in_transaction(
    connection: &Connection,
    activity_id: ActivityId,
    workspace_id: WorkspaceId,
    admitted_at: TimestampMillis,
) -> Result<(), CoordinatorStoreError> {
    struct ActivityLeaseRow {
        workspace_id: Vec<u8>,
        state: i64,
        lease_owner_id: Option<Vec<u8>>,
        lease_until_ms: Option<i64>,
    }

    let row: Option<ActivityLeaseRow> = connection
        .query_row(
            "SELECT workspace_id, state, lease_owner_id, lease_until_ms FROM activities WHERE activity_id = ?1",
            params![activity_id.into_uuid().as_bytes()],
            |row| {
                Ok(ActivityLeaseRow {
                    workspace_id: row.get(0)?,
                    state: row.get(1)?,
                    lease_owner_id: row.get(2)?,
                    lease_until_ms: row.get(3)?,
                })
            },
        )
        .optional()?;
    let Some(row) = row else {
        return Err(CoordinatorStoreError::ActivityNotFound(activity_id));
    };
    let actual = WorkspaceId::from_uuid(decode_uuid(&row.workspace_id, "activity.workspace_id")?);
    if actual != workspace_id {
        return Err(CoordinatorStoreError::ActivityWorkspaceMismatch);
    }
    if row.state != 1 {
        return Err(CoordinatorStoreError::ActivityNotLive(activity_id));
    }
    let (owner, lease_until_ms) = match (row.lease_owner_id, row.lease_until_ms) {
        (Some(owner), Some(lease_until_ms)) => (owner, lease_until_ms),
        (None, None) => return Err(CoordinatorStoreError::ActivityLeaseNotLive(activity_id)),
        _ => return Err(CoordinatorStoreError::CorruptRecord("activity.lease")),
    };
    if owner.len() != 16 {
        return Err(CoordinatorStoreError::CorruptRecord(
            "activity.lease_owner_id",
        ));
    }
    let lease_until = TimestampMillis::new(lease_until_ms)
        .map_err(|_| CoordinatorStoreError::CorruptRecord("activity.lease_until_ms"))?;
    if lease_until <= admitted_at {
        return Err(CoordinatorStoreError::ActivityLeaseNotLive(activity_id));
    }
    Ok(())
}

pub(crate) fn get_in_transaction(
    connection: &Connection,
    activity_id: ActivityId,
) -> Result<Option<ActivityCoordinatorBinding>, CoordinatorStoreError> {
    connection
        .query_row(
            "SELECT workspace_id, agent_id, revision, updated_at_ms FROM activity_coordinators WHERE activity_id = ?1",
            params![activity_id.into_uuid().as_bytes()],
            |row| {
                let workspace: Vec<u8> = row.get(0)?;
                let agent: Vec<u8> = row.get(1)?;
                let revision: i64 = row.get(2)?;
                let updated_at: i64 = row.get(3)?;
                Ok((workspace, agent, revision, updated_at))
            },
        )
        .optional()?
        .map(|(workspace, agent, revision, updated_at)| {
            Ok(ActivityCoordinatorBinding::new(
                WorkspaceId::from_uuid(decode_uuid(&workspace, "coordinator.workspace_id")?),
                activity_id,
                AgentInstanceId::from_uuid(decode_uuid(&agent, "coordinator.agent_id")?),
                ActivityCoordinatorRevision::new(revision)
                    .map_err(|_| CoordinatorStoreError::CorruptRecord("coordinator.revision"))?,
                TimestampMillis::new(updated_at)
                    .map_err(|_| CoordinatorStoreError::CorruptRecord("coordinator.updated_at_ms"))?,
            ))
        })
        .transpose()
}

fn ensure_agent(
    connection: &Connection,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    agent_id: AgentInstanceId,
    principal: AuthenticatedPrincipal,
    session_id: Option<forge_domain::AgentSessionId>,
) -> Result<(), CoordinatorStoreError> {
    let agent = if let Some(session_id) = session_id {
        match workspace_agents::ensure_bound_attached_agent(
            connection,
            workspace_id,
            activity_id,
            agent_id,
            session_id,
            principal,
            None,
        ) {
            Ok(agent) => agent,
            Err(AgentStoreError::PrincipalConflict) => {
                return Err(CoordinatorStoreError::PrincipalMismatch);
            }
            Err(error) => return Err(error.into()),
        }
    } else {
        ensure_attached_agent(connection, workspace_id, activity_id, agent_id)?
    };
    if agent.principal() != principal {
        return Err(CoordinatorStoreError::PrincipalMismatch);
    }
    Ok(())
}

fn ensure_attached_agent(
    connection: &Connection,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    agent_id: AgentInstanceId,
) -> Result<forge_domain::RegisteredAgentInstance, CoordinatorStoreError> {
    let agent = workspace_agents::get_in_transaction(connection, agent_id)?
        .ok_or(CoordinatorStoreError::AgentNotFound(agent_id))?;
    if agent.workspace_id() != workspace_id
        || agent.activity_id() != activity_id
        || agent.attachment_state().is_detached()
    {
        return Err(CoordinatorStoreError::AgentMismatch);
    }
    Ok(agent)
}

pub(crate) fn ensure_open_activity(
    connection: &Connection,
    activity_id: ActivityId,
    workspace_id: WorkspaceId,
) -> Result<(), CoordinatorStoreError> {
    struct ActivityStateRow {
        workspace_id: Vec<u8>,
        state: i64,
    }

    let row: Option<ActivityStateRow> = connection
        .query_row(
            "SELECT workspace_id, state FROM activities WHERE activity_id = ?1",
            params![activity_id.into_uuid().as_bytes()],
            |row| {
                Ok(ActivityStateRow {
                    workspace_id: row.get(0)?,
                    state: row.get(1)?,
                })
            },
        )
        .optional()?;
    let Some(row) = row else {
        return Err(CoordinatorStoreError::ActivityNotFound(activity_id));
    };
    let actual = WorkspaceId::from_uuid(decode_uuid(&row.workspace_id, "activity.workspace_id")?);
    if actual != workspace_id {
        return Err(CoordinatorStoreError::ActivityWorkspaceMismatch);
    }
    if row.state != 1 {
        return Err(CoordinatorStoreError::ActivityNotLive(activity_id));
    }
    Ok(())
}

fn decode_uuid(value: &[u8], field: &'static str) -> Result<Uuid, CoordinatorStoreError> {
    Uuid::from_slice(value).map_err(|_| CoordinatorStoreError::CorruptRecord(field))
}

fn normalize_sql(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

#[derive(Debug, Error)]
pub enum CoordinatorStoreError {
    #[error(transparent)]
    OperationsMigration(#[from] crate::AgentOperationsMigrationError),
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Agent(#[from] AgentStoreError),
    #[error(transparent)]
    Events(#[from] crate::workspace_agent_events::AgentEventStoreError),
    #[error("Activity already has a planning Coordinator")]
    AlreadyBound(ActivityId),
    #[error("Activity planning Coordinator is not bound")]
    CoordinatorMissing(ActivityId),
    #[error("Activity planning Coordinator fence conflicts with durable authority")]
    CoordinatorFenceConflict,
    #[error("Activity was not found")]
    ActivityNotFound(ActivityId),
    #[error("Activity belongs to another Workspace")]
    ActivityWorkspaceMismatch,
    #[error("Activity is not live")]
    ActivityNotLive(ActivityId),
    #[error("Activity owner lease is absent or expired")]
    ActivityLeaseNotLive(ActivityId),
    #[error("Coordinator Agent was not found")]
    AgentNotFound(AgentInstanceId),
    #[error("Coordinator Agent does not match the Activity attachment")]
    AgentMismatch,
    #[error("Coordinator authenticated principal conflicts with the attached Agent")]
    PrincipalMismatch,
    #[error("Coordinator transfer target is already the current Coordinator")]
    TargetAlreadyCoordinator,
    #[error("Coordinator handoff source and target use the same logical session")]
    SameSessionHandoff,
    #[error("Coordinator timestamp precedes the durable binding")]
    TimestampOrder,
    #[error("Coordinator revision fence changed concurrently")]
    RevisionConflict,
    #[error("Coordinator revision overflowed")]
    RevisionOverflow,
    #[error("Coordinator record disappeared during a durable transaction")]
    RecordMissing,
    #[error("Agent {0} has an active Writer Lease")]
    ActiveWriterLease(AgentInstanceId),
    #[error("Agent {0} has an active execution")]
    ActiveExecution(AgentInstanceId),
    #[error("Agent Goal/DAG/head snapshot conflicts with durable authority")]
    CoordinationRevisionConflict,
    #[error("Coordinator schema object is damaged: {0}")]
    DamagedSchema(&'static str),
    #[error("Coordinator record is corrupt: {0}")]
    CorruptRecord(&'static str),
}

#[cfg(test)]
mod tests {
    use super::*;
    use forge_domain::{
        AgentDeclaredRole, AgentDisplayName, AgentSessionId, AgentTransportKind,
        AuthenticatedPrincipal, DirectTokenId, RegisteredAgentInstance,
    };

    fn id(value: u128) -> Uuid {
        Uuid::from_u128(value)
    }

    fn timestamp(value: i64) -> Result<TimestampMillis, Box<dyn std::error::Error>> {
        Ok(TimestampMillis::new(value)?)
    }

    fn agent(
        id_value: u128,
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        observed_at: TimestampMillis,
    ) -> Result<RegisteredAgentInstance, Box<dyn std::error::Error>> {
        Ok(RegisteredAgentInstance::create_bound(
            AgentInstanceId::from_uuid(id(id_value)),
            workspace_id,
            activity_id,
            AgentSessionId::from_uuid(id(id_value + 0x5000)),
            AgentDisplayName::new(format!("agent-{id_value}"))?,
            AgentDeclaredRole::new("worker".to_owned())?,
            AgentTransportKind::Stdio,
            AuthenticatedPrincipal::TrustedStdio,
            observed_at,
        ))
    }

    struct CoordinatorFixture {
        connection: Connection,
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        first: RegisteredAgentInstance,
        second: RegisteredAgentInstance,
    }

    fn coordinator_fixture() -> Result<CoordinatorFixture, Box<dyn std::error::Error>> {
        let connection = Connection::open_in_memory()?;
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
             );",
        )?;
        workspace_agents::create_schema(&connection)?;
        create_schema(&connection)?;
        crate::workspace_agent_events::create_schema(&connection)?;

        let workspace_id = WorkspaceId::from_uuid(id(1));
        let activity_id = ActivityId::from_uuid(id(2));
        connection.execute(
            "INSERT INTO workspace (workspace_id) VALUES (?1)",
            params![workspace_id.into_uuid().as_bytes()],
        )?;
        connection.execute(
            "INSERT INTO activities (activity_id, workspace_id, state, lease_owner_id, lease_until_ms) VALUES (?1, ?2, 1, ?3, 100)",
            params![
                activity_id.into_uuid().as_bytes(),
                workspace_id.into_uuid().as_bytes(),
                id(3).as_bytes(),
            ],
        )?;
        let first = agent(10, workspace_id, activity_id, timestamp(4)?)?;
        let second = agent(11, workspace_id, activity_id, timestamp(5)?)?;
        crate::legacy_agent_seed::seed_agent(
            &connection,
            &first,
            Some(workspace_agent_events::derived_event_id(
                first.id(),
                first.revision(),
                AgentEventKind::Joined,
            )),
        )?;
        crate::legacy_agent_seed::seed_agent(
            &connection,
            &second,
            Some(workspace_agent_events::derived_event_id(
                second.id(),
                second.revision(),
                AgentEventKind::Joined,
            )),
        )?;

        Ok(CoordinatorFixture {
            connection,
            workspace_id,
            activity_id,
            first,
            second,
        })
    }

    #[test]
    fn claim_transfer_and_stale_coordinator_are_fenced() -> Result<(), Box<dyn std::error::Error>> {
        let CoordinatorFixture {
            mut connection,
            workspace_id,
            activity_id,
            first,
            second,
        } = coordinator_fixture()?;

        let claimed = claim(
            &mut connection,
            ClaimActivityCoordinator::new(
                workspace_id,
                activity_id,
                first.id(),
                AuthenticatedPrincipal::TrustedStdio,
                timestamp(6)?,
                first.session_id().ok_or("session missing")?,
            ),
            timestamp(99)?,
        )?;
        assert_eq!(claimed.agent_id(), first.id());
        assert_eq!(claimed.revision(), ActivityCoordinatorRevision::INITIAL);

        let wrong_principal_retry = claim(
            &mut connection,
            ClaimActivityCoordinator::new(
                workspace_id,
                activity_id,
                first.id(),
                AuthenticatedPrincipal::DirectToken(DirectTokenId::from_uuid(id(4))),
                timestamp(6)?,
                first.session_id().ok_or("session missing")?,
            ),
            timestamp(99)?,
        );
        assert!(matches!(
            wrong_principal_retry,
            Err(CoordinatorStoreError::PrincipalMismatch)
        ));

        let stale_actor = ActivityCoordinatorActor::new(
            workspace_id,
            activity_id,
            first.id(),
            claimed.revision(),
            AuthenticatedPrincipal::TrustedStdio,
            first.session_id().ok_or("session missing")?,
        );
        let transferred = transfer(
            &mut connection,
            TransferActivityCoordinator::new(stale_actor, second.id(), timestamp(7)?),
            timestamp(99)?,
        )?;
        assert_eq!(transferred.agent_id(), second.id());
        assert_eq!(transferred.revision().get(), 2);

        let stale = authorize_in_transaction(&connection, stale_actor);
        assert!(matches!(
            stale,
            Err(CoordinatorStoreError::CoordinatorFenceConflict)
        ));
        Ok(())
    }

    #[test]
    fn expired_activity_rejects_coordinator_claim_and_transfer()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut claim_fixture = coordinator_fixture()?;
        let claim_error = claim(
            &mut claim_fixture.connection,
            ClaimActivityCoordinator::new(
                claim_fixture.workspace_id,
                claim_fixture.activity_id,
                claim_fixture.first.id(),
                AuthenticatedPrincipal::TrustedStdio,
                timestamp(6)?,
                claim_fixture.first.session_id().ok_or("session missing")?,
            ),
            timestamp(100)?,
        )
        .err()
        .ok_or("an expired Activity cannot grant initial Coordinator authority")?;
        assert!(matches!(
            claim_error,
            CoordinatorStoreError::ActivityLeaseNotLive(activity_id)
                if activity_id == claim_fixture.activity_id
        ));
        assert_eq!(
            get(&claim_fixture.connection, claim_fixture.activity_id)?,
            None
        );

        let mut transfer_fixture = coordinator_fixture()?;
        let binding = claim(
            &mut transfer_fixture.connection,
            ClaimActivityCoordinator::new(
                transfer_fixture.workspace_id,
                transfer_fixture.activity_id,
                transfer_fixture.first.id(),
                AuthenticatedPrincipal::TrustedStdio,
                timestamp(6)?,
                transfer_fixture
                    .first
                    .session_id()
                    .ok_or("session missing")?,
            ),
            timestamp(99)?,
        )?;
        let actor = ActivityCoordinatorActor::new(
            transfer_fixture.workspace_id,
            transfer_fixture.activity_id,
            transfer_fixture.first.id(),
            binding.revision(),
            AuthenticatedPrincipal::TrustedStdio,
            transfer_fixture
                .first
                .session_id()
                .ok_or("session missing")?,
        );
        let transfer_error = transfer(
            &mut transfer_fixture.connection,
            TransferActivityCoordinator::new(actor, transfer_fixture.second.id(), timestamp(7)?),
            timestamp(100)?,
        )
        .err()
        .ok_or("an expired Activity cannot grant transferred Coordinator authority")?;
        assert!(matches!(
            transfer_error,
            CoordinatorStoreError::ActivityLeaseNotLive(activity_id)
                if activity_id == transfer_fixture.activity_id
        ));
        assert_eq!(
            get(&transfer_fixture.connection, transfer_fixture.activity_id)?,
            Some(binding),
            "a rejected transfer leaves the original durable binding intact"
        );
        Ok(())
    }

    #[test]
    fn live_authorization_requires_open_activity_with_unexpired_owner_lease()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = coordinator_fixture()?;
        let binding = claim(
            &mut fixture.connection,
            ClaimActivityCoordinator::new(
                fixture.workspace_id,
                fixture.activity_id,
                fixture.first.id(),
                AuthenticatedPrincipal::TrustedStdio,
                timestamp(6)?,
                fixture.first.session_id().ok_or("session missing")?,
            ),
            timestamp(99)?,
        )?;
        let actor = ActivityCoordinatorActor::new(
            fixture.workspace_id,
            fixture.activity_id,
            fixture.first.id(),
            binding.revision(),
            AuthenticatedPrincipal::TrustedStdio,
            fixture.first.session_id().ok_or("session missing")?,
        );

        assert!(authorize_live_in_transaction(&fixture.connection, actor, timestamp(99)?,).is_ok());
        assert!(matches!(
            authorize_live_in_transaction(&fixture.connection, actor, timestamp(100)?),
            Err(CoordinatorStoreError::ActivityLeaseNotLive(activity_id))
                if activity_id == fixture.activity_id
        ));

        fixture.connection.execute(
            "UPDATE activities SET lease_owner_id = NULL, lease_until_ms = NULL WHERE activity_id = ?1",
            params![fixture.activity_id.into_uuid().as_bytes()],
        )?;
        assert!(matches!(
            authorize_live_in_transaction(&fixture.connection, actor, timestamp(9)?),
            Err(CoordinatorStoreError::ActivityLeaseNotLive(activity_id))
                if activity_id == fixture.activity_id
        ));

        fixture.connection.execute(
            "UPDATE activities SET state = 2 WHERE activity_id = ?1",
            params![fixture.activity_id.into_uuid().as_bytes()],
        )?;
        assert!(matches!(
            authorize_live_in_transaction(&fixture.connection, actor, timestamp(9)?),
            Err(CoordinatorStoreError::ActivityNotLive(activity_id))
                if activity_id == fixture.activity_id
        ));
        Ok(())
    }
}
