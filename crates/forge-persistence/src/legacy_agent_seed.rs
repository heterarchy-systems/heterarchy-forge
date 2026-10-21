use std::error::Error;

use forge_domain::{
    AgentEventId, AgentTransportKind, AuthenticatedPrincipal, RegisteredAgentInstance,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

/// Seed the historical Agent attachment projection for tests without calling
/// the retired production attach writers. A bound Agent receives presence,
/// Joined-event, and current-Coordinator inbox rows; a pre-session Agent only
/// receives its instance and initial focus rows.
pub(crate) fn seed_agent(
    connection: &Connection,
    agent: &RegisteredAgentInstance,
    event_id: Option<AgentEventId>,
) -> Result<(), Box<dyn Error>> {
    if event_id.is_some() != agent.session_id().is_some() {
        return Err("legacy Agent seed session/event shape mismatch".into());
    }
    // Reserve the writer before reading; live lease renewal must not invalidate
    // the fixture snapshot while it is upgraded from a read to a write.
    connection.busy_timeout(std::time::Duration::from_secs(5))?;
    let transaction = Transaction::new_unchecked(connection, TransactionBehavior::Immediate)?;
    let existing: Option<ExistingAgentRow> = transaction
        .query_row(
            "SELECT session_id, principal_kind, principal_id FROM agent_instances WHERE agent_id=?1 AND workspace_id=?2 AND activity_id=?3",
            params![
                agent.id().into_uuid().as_bytes(),
                agent.workspace_id().into_uuid().as_bytes(),
                agent.activity_id().into_uuid().as_bytes(),
            ],
            |row| {
                Ok(ExistingAgentRow {
                    session_id: row.get(0)?,
                    principal_kind: row.get(1)?,
                    principal_id: row.get(2)?,
                })
            },
        )
        .optional()?;
    if let Some(existing_session) = existing {
        let expected_session = agent
            .session_id()
            .map(|session| session.into_uuid().as_bytes().to_vec());
        let (expected_principal_kind, expected_principal_id) = encode_principal(agent.principal());
        if existing_session.session_id == expected_session
            && existing_session.principal_kind == expected_principal_kind
            && existing_session.principal_id == expected_principal_id
        {
            transaction.commit()?;
            return Ok(());
        }
        return Err("legacy Agent seed conflicts with an existing identity".into());
    }

    insert_instance_and_focus(&transaction, agent)?;
    let Some(event_id) = event_id else {
        transaction.commit()?;
        return Ok(());
    };
    insert_bound_rows(&transaction, agent, event_id)?;
    transaction.commit()?;
    Ok(())
}

struct ExistingAgentRow {
    session_id: Option<Vec<u8>>,
    principal_kind: i64,
    principal_id: Option<Vec<u8>>,
}

fn insert_instance_and_focus(
    transaction: &Transaction<'_>,
    agent: &RegisteredAgentInstance,
) -> Result<(), Box<dyn Error>> {
    let (principal_kind, principal_id) = encode_principal(agent.principal());
    let focus = encode_focus(agent);
    transaction.execute(
        "INSERT INTO agent_instances (agent_id, workspace_id, activity_id, display_name, declared_role, transport_kind, principal_kind, principal_id, attachment_state, focus_goal_id, focus_goal_revision, focus_dag_revision, focus_node_id, focus_node_revision, created_at_ms, updated_at_ms, revision, session_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
        params![
            agent.id().into_uuid().as_bytes(),
            agent.workspace_id().into_uuid().as_bytes(),
            agent.activity_id().into_uuid().as_bytes(),
            agent.display_name().as_str(),
            agent.declared_role().as_str(),
            encode_transport(agent.transport_kind()),
            principal_kind,
            principal_id,
            0_i64,
            focus.goal_id.as_deref(),
            focus.goal_revision,
            focus.dag_revision,
            focus.node_id.as_deref(),
            focus.node_revision,
            agent.created_at().get(),
            agent.updated_at().get(),
            agent.revision().get(),
            agent
                .session_id()
                .map(|session| session.into_uuid().as_bytes().to_vec()),
        ],
    )?;
    transaction.execute(
        "INSERT INTO agent_focus_events (agent_id, workspace_id, activity_id, event_sequence, event_kind, focus_goal_id, focus_goal_revision, focus_dag_revision, focus_node_id, focus_node_revision, observed_at_ms) VALUES (?1, ?2, ?3, 1, 0, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            agent.id().into_uuid().as_bytes(),
            agent.workspace_id().into_uuid().as_bytes(),
            agent.activity_id().into_uuid().as_bytes(),
            focus.goal_id.as_deref(),
            focus.goal_revision,
            focus.dag_revision,
            focus.node_id.as_deref(),
            focus.node_revision,
            agent.created_at().get(),
        ],
    )?;
    Ok(())
}

fn insert_bound_rows(
    transaction: &Transaction<'_>,
    agent: &RegisteredAgentInstance,
    event_id: AgentEventId,
) -> Result<(), Box<dyn Error>> {
    let (principal_kind, principal_id) = encode_principal(agent.principal());
    let session_id = agent
        .session_id()
        .ok_or("bound Agent seed is missing its session")?;
    transaction.execute(
        "INSERT INTO agent_presence (agent_id, workspace_id, activity_id, session_id, last_authenticated_at_ms, presence_revision) VALUES (?1, ?2, ?3, ?4, ?5, 1)",
        params![
            agent.id().into_uuid().as_bytes(),
            agent.workspace_id().into_uuid().as_bytes(),
            agent.activity_id().into_uuid().as_bytes(),
            session_id.into_uuid().as_bytes(),
            agent.created_at().get(),
        ],
    )?;
    let membership_revision: i64 = transaction.query_row(
        "SELECT COALESCE(MAX(membership_revision), 0) FROM agent_events WHERE activity_id=?1",
        params![agent.activity_id().into_uuid().as_bytes()],
        |row| row.get(0),
    )?;
    let membership_revision = membership_revision
        .checked_add(1)
        .ok_or("legacy Agent seed membership revision overflow")?;
    let coordinator: Option<(Vec<u8>, Option<Vec<u8>>, i64)> = transaction
        .query_row(
            "SELECT c.agent_id, ai.session_id, c.revision FROM activity_coordinators AS c JOIN agent_instances AS ai ON ai.agent_id=c.agent_id AND ai.attachment_state=0 WHERE c.activity_id=?1",
            params![agent.activity_id().into_uuid().as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let (coordinator_agent, coordinator_session, coordinator_revision) = match coordinator {
        Some((agent_id, Some(session_id), revision)) => {
            (Some(agent_id), Some(session_id), Some(revision))
        }
        _ => (None, None, None),
    };
    transaction.execute(
        "INSERT INTO agent_events (event_id, workspace_id, activity_id, membership_revision, event_kind, from_agent_id, from_session_id, from_principal_kind, from_principal_id, from_display_name, to_agent_id, to_session_id, to_principal_kind, to_principal_id, to_display_name, before_goal_id, before_goal_revision, before_dag_revision, before_dag_head_revision, before_head_id, before_head_revision, after_goal_id, after_goal_revision, after_dag_revision, after_dag_head_revision, after_head_id, after_head_revision, before_coordinator_agent_id, before_coordinator_session_id, before_coordinator_revision, after_coordinator_agent_id, after_coordinator_session_id, after_coordinator_revision, observed_at_ms) VALUES (?1, ?2, ?3, ?4, 0, NULL, NULL, NULL, NULL, NULL, ?5, ?6, ?7, ?8, ?9, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, ?10, ?11, ?12, ?10, ?11, ?12, ?13)",
        params![
            event_id.into_uuid().as_bytes(),
            agent.workspace_id().into_uuid().as_bytes(),
            agent.activity_id().into_uuid().as_bytes(),
            membership_revision,
            agent.id().into_uuid().as_bytes(),
            session_id.into_uuid().as_bytes(),
            principal_kind,
            principal_id,
            agent.display_name().as_str(),
            coordinator_agent.as_deref(),
            coordinator_session.as_deref(),
            coordinator_revision,
            agent.created_at().get(),
        ],
    )?;
    if let (Some(coordinator_agent), Some(coordinator_session)) =
        (coordinator_agent, coordinator_session)
    {
        transaction.execute(
            "INSERT INTO agent_inbox (recipient_agent_id, recipient_session_id, event_id, receipt_revision, acknowledged_at_ms) VALUES (?1, ?2, ?3, 1, NULL)",
            params![
                coordinator_agent.as_slice(),
                coordinator_session.as_slice(),
                event_id.into_uuid().as_bytes(),
            ],
        )?;
    }
    Ok(())
}

fn encode_principal(value: AuthenticatedPrincipal) -> (i64, Option<Vec<u8>>) {
    match value {
        AuthenticatedPrincipal::TrustedStdio => (0, None),
        AuthenticatedPrincipal::DirectToken(id) => (1, Some(id.into_uuid().into_bytes().to_vec())),
        AuthenticatedPrincipal::OAuthGrant(id) => (2, Some(id.into_uuid().into_bytes().to_vec())),
    }
}

fn encode_transport(value: AgentTransportKind) -> i64 {
    match value {
        AgentTransportKind::Retired => 0,
        AgentTransportKind::Stdio => 1,
        AgentTransportKind::StreamableHttp => 2,
        AgentTransportKind::Other => 3,
    }
}

struct EncodedFocus {
    goal_id: Option<Vec<u8>>,
    goal_revision: Option<i64>,
    dag_revision: Option<i64>,
    node_id: Option<Vec<u8>>,
    node_revision: Option<i64>,
}

fn encode_focus(agent: &RegisteredAgentInstance) -> EncodedFocus {
    let Some(goal) = agent.focus().goal() else {
        return EncodedFocus {
            goal_id: None,
            goal_revision: None,
            dag_revision: None,
            node_id: None,
            node_revision: None,
        };
    };
    let node = agent.focus().node();
    EncodedFocus {
        goal_id: Some(goal.goal_id().into_uuid().into_bytes().to_vec()),
        goal_revision: Some(goal.expected_revision().get()),
        dag_revision: agent
            .focus()
            .dag_revision()
            .map(forge_domain::DagRevisionNumber::get),
        node_id: node.map(|value| value.node_id().into_uuid().into_bytes().to_vec()),
        node_revision: node.map(|value| value.expected_revision().get()),
    }
}
