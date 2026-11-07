//! Transaction-local admission checks for a Prepared Home source fence.
//!
//! These checks are intentionally identity-scoped. A known Agent or Session is
//! checked directly; an Activity fence is used only when the caller has no
//! verifiable actor provenance.

use forge_domain::{ActivityId, AgentInstanceId, AgentSessionId, WorkspaceId};
use rusqlite::{Connection, OptionalExtension, Params, params};
use uuid::Uuid;

use super::HomeTransferStoreError;

const HOME_TABLES: [&str; 5] = [
    "home_transfer_source_operations",
    "home_transfer_source_subjects",
    "home_transfer_source_sessions",
    "home_transfer_source_agents",
    "home_transfer_source_activities",
];

const SESSION_FENCE_QUERY: &str = "SELECT substr(s.preparation_id,1,17) AS preparation_id
    FROM home_transfer_source_sessions s
    JOIN home_transfer_source_operations o
      ON o.preparation_id=s.preparation_id AND o.workspace_id=s.workspace_id
    WHERE s.workspace_id=?1 AND s.session_id=?2 AND o.outcome=0
    ORDER BY s.preparation_id LIMIT 1";

const AGENT_FENCE_QUERY: &str = "SELECT substr(a.preparation_id,1,17) AS preparation_id
    FROM home_transfer_source_agents a
    JOIN home_transfer_source_operations o
      ON o.preparation_id=a.preparation_id AND o.workspace_id=a.workspace_id
    WHERE a.workspace_id=?1 AND a.agent_id=?2 AND o.outcome=0
    UNION ALL
    SELECT substr(s.preparation_id,1,17) AS preparation_id
    FROM home_transfer_source_sessions s
    JOIN home_transfer_source_operations o
      ON o.preparation_id=s.preparation_id AND o.workspace_id=s.workspace_id
    JOIN agent_instances i
      ON i.workspace_id=s.workspace_id AND i.session_id=s.session_id
    WHERE s.workspace_id=?1 AND i.agent_id=?2 AND o.outcome=0
    ORDER BY 1 LIMIT 1";

const AGENT_SESSION_FENCE_QUERY: &str = "SELECT substr(a.preparation_id,1,17) AS preparation_id
    FROM home_transfer_source_agents a
    JOIN home_transfer_source_operations o
      ON o.preparation_id=a.preparation_id AND o.workspace_id=a.workspace_id
    WHERE a.workspace_id=?1 AND a.agent_id=?2 AND o.outcome=0
    UNION ALL
    SELECT substr(s.preparation_id,1,17) AS preparation_id
    FROM home_transfer_source_sessions s
    JOIN home_transfer_source_operations o
      ON o.preparation_id=s.preparation_id AND o.workspace_id=s.workspace_id
    WHERE s.workspace_id=?1 AND s.session_id=?3 AND o.outcome=0
    ORDER BY 1 LIMIT 1";

const ACTIVITY_FENCE_QUERY: &str = "SELECT substr(a.preparation_id,1,17) AS preparation_id
    FROM home_transfer_source_activities a
    JOIN home_transfer_source_operations o
      ON o.preparation_id=a.preparation_id AND o.workspace_id=a.workspace_id
    WHERE a.workspace_id=?1 AND a.activity_id=?2 AND o.outcome=0
    ORDER BY a.preparation_id LIMIT 1";

/// Block a new Agent binding to a Session captured by a Prepared Home source.
pub(crate) fn ensure_session_open(
    connection: &Connection,
    workspace_id: WorkspaceId,
    session_id: AgentSessionId,
) -> Result<(), HomeTransferStoreError> {
    ensure_fence(
        connection,
        SESSION_FENCE_QUERY,
        params![
            workspace_id.into_uuid().as_bytes(),
            session_id.into_uuid().as_bytes()
        ],
    )
}

/// Block fresh work by a captured Agent or by another Agent using a captured
/// Session. Supplying a Session uses the exact immutable request provenance;
/// otherwise the current Agent binding supplies the Session association.
pub(crate) fn ensure_actor_open(
    connection: &Connection,
    workspace_id: WorkspaceId,
    agent_id: AgentInstanceId,
    session_id: Option<AgentSessionId>,
) -> Result<(), HomeTransferStoreError> {
    match session_id {
        Some(session_id) => ensure_fence(
            connection,
            AGENT_SESSION_FENCE_QUERY,
            params![
                workspace_id.into_uuid().as_bytes(),
                agent_id.into_uuid().as_bytes(),
                session_id.into_uuid().as_bytes(),
            ],
        ),
        None => ensure_fence(
            connection,
            AGENT_FENCE_QUERY,
            params![
                workspace_id.into_uuid().as_bytes(),
                agent_id.into_uuid().as_bytes()
            ],
        ),
    }
}

/// Conservatively block an Activity only when its operation has no verifiable
/// Agent identity to scope the check more narrowly.
pub(crate) fn ensure_activity_open(
    connection: &Connection,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
) -> Result<(), HomeTransferStoreError> {
    ensure_fence(
        connection,
        ACTIVITY_FENCE_QUERY,
        params![
            workspace_id.into_uuid().as_bytes(),
            activity_id.into_uuid().as_bytes()
        ],
    )
}

fn ensure_fence<P>(
    connection: &Connection,
    query: &'static str,
    parameters: P,
) -> Result<(), HomeTransferStoreError>
where
    P: Params,
{
    if !home_fence_schema_available(connection)? {
        // Older isolated persistence fixtures have no Home tables. A real
        // Workspace is schema-validated/upgraded before any owner call.
        return Ok(());
    }
    let preparation_id: Option<Vec<u8>> = connection
        .query_row(query, parameters, |row| row.get(0))
        .optional()?;
    if let Some(preparation_id) = preparation_id {
        let preparation_id = Uuid::from_slice(&preparation_id)
            .map_err(|_| HomeTransferStoreError::Corrupt("fence preparation ID"))?;
        if preparation_id.is_nil() {
            return Err(HomeTransferStoreError::Corrupt("nil fence preparation ID"));
        }
        return Err(HomeTransferStoreError::Fenced { preparation_id });
    }
    Ok(())
}

fn home_fence_schema_available(connection: &Connection) -> Result<bool, HomeTransferStoreError> {
    let table_count: i64 = connection.query_row(
        "SELECT count(*) FROM sqlite_schema
         WHERE type='table' AND name IN (
            'home_transfer_source_operations',
            'home_transfer_source_subjects',
            'home_transfer_source_sessions',
            'home_transfer_source_agents',
            'home_transfer_source_activities'
         )",
        [],
        |row| row.get(0),
    )?;
    if table_count == 0 {
        let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if version >= 71 {
            return Err(HomeTransferStoreError::Corrupt("missing Home fence schema"));
        }
        return Ok(false);
    }
    let expected_count = i64::try_from(HOME_TABLES.len())
        .map_err(|_| HomeTransferStoreError::Bounds("Home schema table count"))?;
    if table_count != expected_count {
        return Err(HomeTransferStoreError::Corrupt(
            "incomplete Home fence schema",
        ));
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use forge_domain::{ActivityId, AgentInstanceId, AgentSessionId, WorkspaceId};
    use rusqlite::{Connection, params};
    use uuid::Uuid;

    use super::{ensure_activity_open, ensure_actor_open, ensure_session_open};
    use crate::HomeTransferStoreError;

    #[test]
    fn missing_current_home_schema_does_not_open_admission()
    -> Result<(), Box<dyn std::error::Error>> {
        let connection = Connection::open_in_memory()?;
        connection.pragma_update(None, "user_version", 71)?;
        assert!(matches!(
            ensure_session_open(
                &connection,
                WorkspaceId::from_uuid(Uuid::from_u128(1)),
                AgentSessionId::from_uuid(Uuid::from_u128(2))
            ),
            Err(HomeTransferStoreError::Corrupt("missing Home fence schema"))
        ));
        Ok(())
    }

    struct Fixture {
        connection: Connection,
        workspace_id: WorkspaceId,
        preparation_id: Uuid,
        target_agent_id: AgentInstanceId,
        target_session_id: AgentSessionId,
        unrelated_agent_id: AgentInstanceId,
        unrelated_session_id: AgentSessionId,
        affected_activity_id: ActivityId,
    }

    fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
        let connection = Connection::open_in_memory()?;
        connection.pragma_update(None, "foreign_keys", true)?;
        connection.execute_batch(
            "CREATE TABLE workspace(workspace_id BLOB PRIMARY KEY);
             CREATE TABLE agent_instances(
                agent_id BLOB PRIMARY KEY,
                workspace_id BLOB NOT NULL,
                activity_id BLOB NOT NULL,
                session_id BLOB
             );",
        )?;
        crate::workspace_home_transfers::schema::create_schema(&connection)?;

        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(1));
        let preparation_id = Uuid::from_u128(2);
        let target_agent_id = AgentInstanceId::from_uuid(Uuid::from_u128(3));
        let target_session_id = AgentSessionId::from_uuid(Uuid::from_u128(4));
        let unrelated_agent_id = AgentInstanceId::from_uuid(Uuid::from_u128(5));
        let unrelated_session_id = AgentSessionId::from_uuid(Uuid::from_u128(6));
        let affected_activity_id = ActivityId::from_uuid(Uuid::from_u128(7));
        connection.execute(
            "INSERT INTO workspace(workspace_id) VALUES (?1)",
            params![workspace_id.into_uuid().as_bytes()],
        )?;
        connection.execute(
            "INSERT INTO agent_instances(agent_id,workspace_id,activity_id,session_id)
             VALUES (?1,?2,?3,?4), (?5,?2,?3,?6)",
            params![
                target_agent_id.into_uuid().as_bytes(),
                workspace_id.into_uuid().as_bytes(),
                affected_activity_id.into_uuid().as_bytes(),
                target_session_id.into_uuid().as_bytes(),
                unrelated_agent_id.into_uuid().as_bytes(),
                unrelated_session_id.into_uuid().as_bytes(),
            ],
        )?;
        connection.execute(
            "INSERT INTO home_transfer_source_operations(
                preparation_id,workspace_id,target_profile_id,target_participation_id,
                issuer_id,request_digest,request_payload,outcome,observed_at_ms,
                grant_issued_at_ms,grant_expires_at_ms,migration_id,freeze_revision,
                delegation_digest,inventory_payload,inventory_digest,outcome_digest
             ) VALUES (?1,?2,?3,?4,?5,zeroblob(32),X'01',0,10,10,100,?6,1,
                       zeroblob(32),X'01',zeroblob(32),zeroblob(32))",
            params![
                preparation_id.as_bytes(),
                workspace_id.into_uuid().as_bytes(),
                Uuid::from_u128(9).as_bytes(),
                Uuid::from_u128(10).as_bytes(),
                Uuid::from_u128(11).as_bytes(),
                Uuid::from_u128(12).as_bytes(),
            ],
        )?;
        connection.execute(
            "INSERT INTO home_transfer_source_subjects(
                workspace_id,target_profile_id,target_participation_id,preparation_id
             ) VALUES (?1,?2,?3,?4)",
            params![
                workspace_id.into_uuid().as_bytes(),
                Uuid::from_u128(9).as_bytes(),
                Uuid::from_u128(10).as_bytes(),
                preparation_id.as_bytes(),
            ],
        )?;
        connection.execute(
            "INSERT INTO home_transfer_source_sessions(workspace_id,session_id,preparation_id)
             VALUES (?1,?2,?3)",
            params![
                workspace_id.into_uuid().as_bytes(),
                target_session_id.into_uuid().as_bytes(),
                preparation_id.as_bytes(),
            ],
        )?;
        connection.execute(
            "INSERT INTO home_transfer_source_agents(workspace_id,agent_id,preparation_id)
             VALUES (?1,?2,?3)",
            params![
                workspace_id.into_uuid().as_bytes(),
                target_agent_id.into_uuid().as_bytes(),
                preparation_id.as_bytes(),
            ],
        )?;
        connection.execute(
            "INSERT INTO home_transfer_source_activities(workspace_id,activity_id,preparation_id)
             VALUES (?1,?2,?3)",
            params![
                workspace_id.into_uuid().as_bytes(),
                affected_activity_id.into_uuid().as_bytes(),
                preparation_id.as_bytes(),
            ],
        )?;
        Ok(Fixture {
            connection,
            workspace_id,
            preparation_id,
            target_agent_id,
            target_session_id,
            unrelated_agent_id,
            unrelated_session_id,
            affected_activity_id,
        })
    }

    fn assert_fenced(result: &Result<(), HomeTransferStoreError>, expected: Uuid) {
        assert!(
            matches!(result, Err(HomeTransferStoreError::Fenced { preparation_id }) if *preparation_id == expected)
        );
    }

    #[test]
    fn session_actor_and_activity_fences_keep_known_unrelated_actor_live()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture()?;
        assert_fenced(
            &ensure_session_open(
                &fixture.connection,
                fixture.workspace_id,
                fixture.target_session_id,
            ),
            fixture.preparation_id,
        );
        assert_fenced(
            &ensure_actor_open(
                &fixture.connection,
                fixture.workspace_id,
                fixture.target_agent_id,
                Some(fixture.target_session_id),
            ),
            fixture.preparation_id,
        );
        assert_fenced(
            &ensure_activity_open(
                &fixture.connection,
                fixture.workspace_id,
                fixture.affected_activity_id,
            ),
            fixture.preparation_id,
        );
        ensure_session_open(
            &fixture.connection,
            fixture.workspace_id,
            fixture.unrelated_session_id,
        )?;
        ensure_actor_open(
            &fixture.connection,
            fixture.workspace_id,
            fixture.unrelated_agent_id,
            Some(fixture.unrelated_session_id),
        )?;
        Ok(())
    }

    #[test]
    fn actor_binding_to_captured_session_is_fenced_without_activity_fallback()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture()?;
        fixture.connection.execute(
            "UPDATE agent_instances SET session_id=?1 WHERE agent_id=?2",
            params![
                fixture.target_session_id.into_uuid().as_bytes(),
                fixture.unrelated_agent_id.into_uuid().as_bytes(),
            ],
        )?;
        assert_fenced(
            &ensure_actor_open(
                &fixture.connection,
                fixture.workspace_id,
                fixture.unrelated_agent_id,
                None,
            ),
            fixture.preparation_id,
        );
        let unrelated_activity = ActivityId::from_uuid(Uuid::from_u128(8));
        ensure_activity_open(
            &fixture.connection,
            fixture.workspace_id,
            unrelated_activity,
        )?;
        Ok(())
    }
}
