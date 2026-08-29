//! Workspace-local durable authority for attached agent instances.
//!
//! Agent rows are durable metadata attached to an existing Activity.  Activity
//! lease/liveness remains owned by `workspace_store`; this module never creates
//! a heartbeat or a second lease table.  Focus events and public work updates
//! are append-only records and contain only bounded operator-safe data.

use std::collections::BTreeMap;

use forge_domain::{
    ActivityId, ActivityLeaseProjection, ActivityProjection, ActivityRevision, ActivityState,
    AgentAttachmentProjection, AgentAttachmentState, AgentContextProjection, AgentDeclaredRole,
    AgentDisplayName, AgentFocus, AgentFocusEvent, AgentFocusEventKind, AgentFocusEventSequence,
    AgentFocusNode, AgentInstanceId, AgentInstanceRevision, AgentTransitionError,
    AgentTransportKind, AgentWorkPhase, AgentWorkSummary, AgentWorkUpdate, AgentWorkUpdateId,
    AgentWorkUpdateSequence, DagNodeId, DagNodeRevision, DagRevisionNumber, GoalAttribution,
    GoalEvidenceRef, GoalRevision, McpTokenId, RegisteredActivity, RegisteredAgentInstance,
    RuntimeInstanceId, TimestampMillis, WorkspaceId,
};
use rusqlite::{Connection, OptionalExtension, Row, TransactionBehavior, params};
use thiserror::Error;
use uuid::Uuid;

const ID_BYTES: usize = 16;
const ID_BYTES_I64: i64 = 16;
const MAX_TEXT_BYTES: usize = forge_domain::MAX_AGENT_WORK_SUMMARY_BYTES;
const MAX_METADATA_BYTES: usize = forge_domain::MAX_AGENT_ROLE_BYTES;

/// Canonical v15 table/index DDL.  All creation and validation paths use this
/// single authority; migration only invokes `create_schema`.
const EXPECTED_AGENT_INSTANCES_TABLE_SQL: &str = "CREATE TABLE agent_instances (agent_id BLOB PRIMARY KEY NOT NULL CHECK(length(agent_id) = 16), workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16), activity_id BLOB NOT NULL REFERENCES activities(activity_id) CHECK(length(activity_id) = 16), display_name TEXT NOT NULL CHECK(length(CAST(display_name AS BLOB)) BETWEEN 1 AND 128), declared_role TEXT NOT NULL CHECK(length(CAST(declared_role AS BLOB)) BETWEEN 1 AND 128), transport_kind INTEGER NOT NULL CHECK(transport_kind IN (0, 1, 2, 3)), attachment_state INTEGER NOT NULL CHECK(attachment_state IN (0, 1)), focus_goal_id BLOB CHECK(focus_goal_id IS NULL OR length(focus_goal_id) = 16), focus_goal_revision INTEGER CHECK(focus_goal_revision IS NULL OR focus_goal_revision >= 1), focus_dag_revision INTEGER CHECK(focus_dag_revision IS NULL OR focus_dag_revision >= 1), focus_node_id BLOB CHECK(focus_node_id IS NULL OR length(focus_node_id) = 16), focus_node_revision INTEGER CHECK(focus_node_revision IS NULL OR focus_node_revision >= 1), created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0), updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= created_at_ms), revision INTEGER NOT NULL CHECK(revision >= 1), UNIQUE(agent_id, workspace_id, activity_id), FOREIGN KEY(focus_goal_id) REFERENCES goals(goal_id), FOREIGN KEY(focus_goal_id, focus_dag_revision) REFERENCES goal_dag_revisions(goal_id, dag_revision), FOREIGN KEY(focus_goal_id, focus_dag_revision, focus_node_id) REFERENCES goal_dag_nodes(goal_id, dag_revision, node_id), CHECK((focus_goal_id IS NULL AND focus_goal_revision IS NULL AND focus_dag_revision IS NULL AND focus_node_id IS NULL AND focus_node_revision IS NULL) OR (focus_goal_id IS NOT NULL AND focus_goal_revision IS NOT NULL AND focus_dag_revision IS NOT NULL AND ((focus_node_id IS NULL AND focus_node_revision IS NULL) OR (focus_node_id IS NOT NULL AND focus_node_revision IS NOT NULL)))), CHECK((attachment_state = 1 AND focus_goal_id IS NULL AND focus_goal_revision IS NULL AND focus_dag_revision IS NULL AND focus_node_id IS NULL AND focus_node_revision IS NULL) OR attachment_state = 0))";
const EXPECTED_AGENT_FOCUS_EVENTS_TABLE_SQL: &str = "CREATE TABLE agent_focus_events (agent_id BLOB NOT NULL CHECK(length(agent_id) = 16), workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16), activity_id BLOB NOT NULL REFERENCES activities(activity_id) CHECK(length(activity_id) = 16), event_sequence INTEGER NOT NULL CHECK(event_sequence >= 1), event_kind INTEGER NOT NULL CHECK(event_kind IN (0, 1, 2)), focus_goal_id BLOB CHECK(focus_goal_id IS NULL OR length(focus_goal_id) = 16), focus_goal_revision INTEGER CHECK(focus_goal_revision IS NULL OR focus_goal_revision >= 1), focus_dag_revision INTEGER CHECK(focus_dag_revision IS NULL OR focus_dag_revision >= 1), focus_node_id BLOB CHECK(focus_node_id IS NULL OR length(focus_node_id) = 16), focus_node_revision INTEGER CHECK(focus_node_revision IS NULL OR focus_node_revision >= 1), observed_at_ms INTEGER NOT NULL CHECK(observed_at_ms >= 0), PRIMARY KEY(agent_id, event_sequence), FOREIGN KEY(agent_id, workspace_id, activity_id) REFERENCES agent_instances(agent_id, workspace_id, activity_id), FOREIGN KEY(focus_goal_id) REFERENCES goals(goal_id), FOREIGN KEY(focus_goal_id, focus_dag_revision) REFERENCES goal_dag_revisions(goal_id, dag_revision), FOREIGN KEY(focus_goal_id, focus_dag_revision, focus_node_id) REFERENCES goal_dag_nodes(goal_id, dag_revision, node_id), CHECK((focus_goal_id IS NULL AND focus_goal_revision IS NULL AND focus_dag_revision IS NULL AND focus_node_id IS NULL AND focus_node_revision IS NULL) OR (focus_goal_id IS NOT NULL AND focus_goal_revision IS NOT NULL AND focus_dag_revision IS NOT NULL AND ((focus_node_id IS NULL AND focus_node_revision IS NULL) OR (focus_node_id IS NOT NULL AND focus_node_revision IS NOT NULL)))), CHECK((event_kind = 2 AND focus_goal_id IS NULL AND focus_goal_revision IS NULL AND focus_dag_revision IS NULL AND focus_node_id IS NULL AND focus_node_revision IS NULL) OR event_kind IN (0, 1)))";
const EXPECTED_AGENT_WORK_UPDATES_TABLE_SQL: &str = "CREATE TABLE agent_work_updates (update_id BLOB PRIMARY KEY NOT NULL CHECK(length(update_id) = 16), agent_id BLOB NOT NULL CHECK(length(agent_id) = 16), workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16), activity_id BLOB NOT NULL REFERENCES activities(activity_id) CHECK(length(activity_id) = 16), update_sequence INTEGER NOT NULL CHECK(update_sequence >= 1), phase INTEGER NOT NULL CHECK(phase IN (0, 1, 2, 3, 4, 5, 6)), summary TEXT NOT NULL CHECK(length(CAST(summary AS BLOB)) BETWEEN 1 AND 2048), evidence_count INTEGER NOT NULL CHECK(evidence_count BETWEEN 0 AND 32), observed_at_ms INTEGER NOT NULL CHECK(observed_at_ms >= 0), UNIQUE(agent_id, update_sequence), UNIQUE(update_id, agent_id, workspace_id), FOREIGN KEY(agent_id, workspace_id, activity_id) REFERENCES agent_instances(agent_id, workspace_id, activity_id))";
const EXPECTED_AGENT_WORK_EVIDENCE_TABLE_SQL: &str = "CREATE TABLE agent_work_update_evidence_refs (update_id BLOB NOT NULL CHECK(length(update_id) = 16), agent_id BLOB NOT NULL CHECK(length(agent_id) = 16), workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16), evidence_kind INTEGER NOT NULL CHECK(evidence_kind IN (0, 1, 2, 3)), evidence_id BLOB NOT NULL CHECK(length(evidence_id) = 16), PRIMARY KEY(update_id, evidence_kind, evidence_id), FOREIGN KEY(update_id, agent_id, workspace_id) REFERENCES agent_work_updates(update_id, agent_id, workspace_id))";
const EXPECTED_AGENT_INSTANCES_INDEX_SQL: &str = "CREATE INDEX agent_instances_workspace_activity_updated_idx ON agent_instances(workspace_id, activity_id, updated_at_ms DESC, agent_id DESC)";
const EXPECTED_AGENT_FOCUS_EVENTS_INDEX_SQL: &str = "CREATE INDEX agent_focus_events_agent_sequence_idx ON agent_focus_events(agent_id, event_sequence DESC)";
const EXPECTED_AGENT_WORK_UPDATES_INDEX_SQL: &str = "CREATE INDEX agent_work_updates_agent_sequence_idx ON agent_work_updates(agent_id, update_sequence DESC)";
const EXPECTED_AGENT_TRANSPORT_PRINCIPALS_TABLE_SQL: &str = "CREATE TABLE agent_transport_principals (agent_id BLOB PRIMARY KEY NOT NULL CHECK(length(agent_id) = 16), workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16), activity_id BLOB NOT NULL REFERENCES activities(activity_id) CHECK(length(activity_id) = 16), token_id BLOB NOT NULL CHECK(length(token_id) = 16), UNIQUE(agent_id, workspace_id, activity_id), FOREIGN KEY(agent_id, workspace_id, activity_id) REFERENCES agent_instances(agent_id, workspace_id, activity_id))";
const EXPECTED_AGENT_TRANSPORT_PRINCIPALS_INDEX_SQL: &str = "CREATE INDEX agent_transport_principals_workspace_token_idx ON agent_transport_principals(workspace_id, token_id, agent_id)";

const OBJECTS_V15: [(&str, &str, &str); 7] = [
    (
        "table",
        "agent_instances",
        EXPECTED_AGENT_INSTANCES_TABLE_SQL,
    ),
    (
        "table",
        "agent_focus_events",
        EXPECTED_AGENT_FOCUS_EVENTS_TABLE_SQL,
    ),
    (
        "table",
        "agent_work_updates",
        EXPECTED_AGENT_WORK_UPDATES_TABLE_SQL,
    ),
    (
        "table",
        "agent_work_update_evidence_refs",
        EXPECTED_AGENT_WORK_EVIDENCE_TABLE_SQL,
    ),
    (
        "index",
        "agent_instances_workspace_activity_updated_idx",
        EXPECTED_AGENT_INSTANCES_INDEX_SQL,
    ),
    (
        "index",
        "agent_focus_events_agent_sequence_idx",
        EXPECTED_AGENT_FOCUS_EVENTS_INDEX_SQL,
    ),
    (
        "index",
        "agent_work_updates_agent_sequence_idx",
        EXPECTED_AGENT_WORK_UPDATES_INDEX_SQL,
    ),
];

const OBJECTS: [(&str, &str, &str); 9] = [
    OBJECTS_V15[0],
    OBJECTS_V15[1],
    OBJECTS_V15[2],
    OBJECTS_V15[3],
    OBJECTS_V15[4],
    OBJECTS_V15[5],
    OBJECTS_V15[6],
    (
        "table",
        "agent_transport_principals",
        EXPECTED_AGENT_TRANSPORT_PRINCIPALS_TABLE_SQL,
    ),
    (
        "index",
        "agent_transport_principals_workspace_token_idx",
        EXPECTED_AGENT_TRANSPORT_PRINCIPALS_INDEX_SQL,
    ),
];

pub(crate) fn create_schema(connection: &Connection) -> Result<(), AgentStoreError> {
    create_schema_v15(connection)?;
    connection.execute_batch(EXPECTED_AGENT_TRANSPORT_PRINCIPALS_TABLE_SQL)?;
    connection.execute_batch(EXPECTED_AGENT_TRANSPORT_PRINCIPALS_INDEX_SQL)?;
    Ok(())
}

pub(crate) fn create_schema_v15(connection: &Connection) -> Result<(), AgentStoreError> {
    for (_, _, sql) in OBJECTS_V15 {
        connection.execute_batch(sql)?;
    }
    Ok(())
}

pub(crate) fn migrate_v14_to_v15(
    connection: &mut Connection,
    next_schema_version: i64,
) -> Result<(), AgentStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    create_schema_v15(&transaction)?;
    transaction.pragma_update(None, "user_version", next_schema_version)?;
    transaction.commit()?;
    Ok(())
}

pub(crate) fn migrate_v15_to_v16(
    connection: &mut Connection,
    next_schema_version: i64,
) -> Result<(), AgentStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(EXPECTED_AGENT_TRANSPORT_PRINCIPALS_TABLE_SQL)?;
    transaction.execute_batch(EXPECTED_AGENT_TRANSPORT_PRINCIPALS_INDEX_SQL)?;
    transaction.pragma_update(None, "user_version", next_schema_version)?;
    transaction.commit()?;
    Ok(())
}

pub(crate) fn schema_objects_v15() -> [(&'static str, &'static str); 7] {
    [
        ("table", "agent_instances"),
        ("table", "agent_focus_events"),
        ("table", "agent_work_updates"),
        ("table", "agent_work_update_evidence_refs"),
        ("index", "agent_instances_workspace_activity_updated_idx"),
        ("index", "agent_focus_events_agent_sequence_idx"),
        ("index", "agent_work_updates_agent_sequence_idx"),
    ]
}

pub(crate) fn schema_objects() -> [(&'static str, &'static str); 9] {
    [
        ("table", "agent_instances"),
        ("table", "agent_focus_events"),
        ("table", "agent_work_updates"),
        ("table", "agent_work_update_evidence_refs"),
        ("index", "agent_instances_workspace_activity_updated_idx"),
        ("index", "agent_focus_events_agent_sequence_idx"),
        ("index", "agent_work_updates_agent_sequence_idx"),
        ("table", "agent_transport_principals"),
        ("index", "agent_transport_principals_workspace_token_idx"),
    ]
}

pub(crate) fn validate_schema(connection: &Connection) -> Result<(), AgentStoreError> {
    validate_schema_for(connection, &OBJECTS, true)
}

pub(crate) fn validate_schema_v15(connection: &Connection) -> Result<(), AgentStoreError> {
    validate_schema_for(connection, &OBJECTS_V15, false)
}

fn validate_schema_for(
    connection: &Connection,
    objects: &[(&'static str, &'static str, &'static str)],
    has_principal: bool,
) -> Result<(), AgentStoreError> {
    validate_schema_objects(connection, objects)?;
    validate_schema_columns(connection, has_principal)?;
    validate_schema_foreign_keys(connection, has_principal)
}

fn validate_schema_objects(
    connection: &Connection,
    objects: &[(&'static str, &'static str, &'static str)],
) -> Result<(), AgentStoreError> {
    for (kind, name, expected) in objects {
        let actual: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type = ?1 AND name = ?2",
                params![kind, name],
                |row| row.get(0),
            )
            .optional()?;
        if actual.as_deref().map(normalize_sql) != Some(normalize_sql(expected)) {
            return Err(AgentStoreError::DamagedSchema(name));
        }
    }
    Ok(())
}

fn validate_schema_columns(
    connection: &Connection,
    has_principal: bool,
) -> Result<(), AgentStoreError> {
    validate_columns(
        connection,
        "agent_instances",
        &[
            ("agent_id", "BLOB", 1, 1),
            ("workspace_id", "BLOB", 1, 0),
            ("activity_id", "BLOB", 1, 0),
            ("display_name", "TEXT", 1, 0),
            ("declared_role", "TEXT", 1, 0),
            ("transport_kind", "INTEGER", 1, 0),
            ("attachment_state", "INTEGER", 1, 0),
            ("focus_goal_id", "BLOB", 0, 0),
            ("focus_goal_revision", "INTEGER", 0, 0),
            ("focus_dag_revision", "INTEGER", 0, 0),
            ("focus_node_id", "BLOB", 0, 0),
            ("focus_node_revision", "INTEGER", 0, 0),
            ("created_at_ms", "INTEGER", 1, 0),
            ("updated_at_ms", "INTEGER", 1, 0),
            ("revision", "INTEGER", 1, 0),
        ],
    )?;
    validate_columns(
        connection,
        "agent_focus_events",
        &[
            ("agent_id", "BLOB", 1, 1),
            ("workspace_id", "BLOB", 1, 0),
            ("activity_id", "BLOB", 1, 0),
            ("event_sequence", "INTEGER", 1, 2),
            ("event_kind", "INTEGER", 1, 0),
            ("focus_goal_id", "BLOB", 0, 0),
            ("focus_goal_revision", "INTEGER", 0, 0),
            ("focus_dag_revision", "INTEGER", 0, 0),
            ("focus_node_id", "BLOB", 0, 0),
            ("focus_node_revision", "INTEGER", 0, 0),
            ("observed_at_ms", "INTEGER", 1, 0),
        ],
    )?;
    validate_columns(
        connection,
        "agent_work_updates",
        &[
            ("update_id", "BLOB", 1, 1),
            ("agent_id", "BLOB", 1, 0),
            ("workspace_id", "BLOB", 1, 0),
            ("activity_id", "BLOB", 1, 0),
            ("update_sequence", "INTEGER", 1, 0),
            ("phase", "INTEGER", 1, 0),
            ("summary", "TEXT", 1, 0),
            ("evidence_count", "INTEGER", 1, 0),
            ("observed_at_ms", "INTEGER", 1, 0),
        ],
    )?;
    validate_columns(
        connection,
        "agent_work_update_evidence_refs",
        &[
            ("update_id", "BLOB", 1, 1),
            ("agent_id", "BLOB", 1, 0),
            ("workspace_id", "BLOB", 1, 0),
            ("evidence_kind", "INTEGER", 1, 2),
            ("evidence_id", "BLOB", 1, 3),
        ],
    )?;
    if has_principal {
        validate_columns(
            connection,
            "agent_transport_principals",
            &[
                ("agent_id", "BLOB", 1, 1),
                ("workspace_id", "BLOB", 1, 0),
                ("activity_id", "BLOB", 1, 0),
                ("token_id", "BLOB", 1, 0),
            ],
        )?;
    }
    Ok(())
}

fn validate_schema_foreign_keys(
    connection: &Connection,
    has_principal: bool,
) -> Result<(), AgentStoreError> {
    validate_foreign_keys(
        connection,
        "agent_instances",
        &[
            ("activities", "activity_id", "activity_id"),
            ("workspace", "workspace_id", "workspace_id"),
            ("goals", "focus_goal_id", "goal_id"),
            ("goal_dag_revisions", "focus_goal_id", "goal_id"),
            ("goal_dag_revisions", "focus_dag_revision", "dag_revision"),
            ("goal_dag_nodes", "focus_goal_id", "goal_id"),
            ("goal_dag_nodes", "focus_dag_revision", "dag_revision"),
            ("goal_dag_nodes", "focus_node_id", "node_id"),
        ],
    )?;
    validate_foreign_keys(
        connection,
        "agent_focus_events",
        &[
            ("agent_instances", "agent_id", "agent_id"),
            ("agent_instances", "workspace_id", "workspace_id"),
            ("agent_instances", "activity_id", "activity_id"),
            ("activities", "activity_id", "activity_id"),
            ("workspace", "workspace_id", "workspace_id"),
            ("goals", "focus_goal_id", "goal_id"),
            ("goal_dag_revisions", "focus_goal_id", "goal_id"),
            ("goal_dag_revisions", "focus_dag_revision", "dag_revision"),
            ("goal_dag_nodes", "focus_goal_id", "goal_id"),
            ("goal_dag_nodes", "focus_dag_revision", "dag_revision"),
            ("goal_dag_nodes", "focus_node_id", "node_id"),
        ],
    )?;
    validate_foreign_keys(
        connection,
        "agent_work_updates",
        &[
            ("agent_instances", "agent_id", "agent_id"),
            ("agent_instances", "workspace_id", "workspace_id"),
            ("agent_instances", "activity_id", "activity_id"),
            ("activities", "activity_id", "activity_id"),
            ("workspace", "workspace_id", "workspace_id"),
        ],
    )?;
    validate_foreign_keys(
        connection,
        "agent_work_update_evidence_refs",
        &[
            ("agent_work_updates", "update_id", "update_id"),
            ("agent_work_updates", "agent_id", "agent_id"),
            ("agent_work_updates", "workspace_id", "workspace_id"),
            ("workspace", "workspace_id", "workspace_id"),
        ],
    )?;
    if has_principal {
        validate_foreign_keys(
            connection,
            "agent_transport_principals",
            &[
                ("activities", "activity_id", "activity_id"),
                ("agent_instances", "agent_id", "agent_id"),
                ("agent_instances", "workspace_id", "workspace_id"),
                ("agent_instances", "activity_id", "activity_id"),
                ("workspace", "workspace_id", "workspace_id"),
            ],
        )?;
    }
    Ok(())
}

fn normalize_sql(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn validate_columns(
    connection: &Connection,
    table: &'static str,
    expected: &[(&str, &str, i64, i64)],
) -> Result<(), AgentStoreError> {
    let mut statement = connection.prepare(&format!("PRAGMA table_info({table})"))?;
    let actual = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(5)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if actual.len() != expected.len()
        || !actual.iter().zip(expected).all(
            |((name, data_type, not_null, primary_key), expected)| {
                name == expected.0
                    && data_type == expected.1
                    && *not_null == expected.2
                    && *primary_key == expected.3
            },
        )
    {
        return Err(AgentStoreError::DamagedSchema(table));
    }
    Ok(())
}

fn validate_foreign_keys(
    connection: &Connection,
    table: &'static str,
    expected: &[(&str, &str, &str)],
) -> Result<(), AgentStoreError> {
    let mut statement = connection.prepare(&format!("PRAGMA foreign_key_list({table})"))?;
    let mut rows = statement.query([])?;
    let mut actual = Vec::new();
    while let Some(row) = rows.next()? {
        actual.push((
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, String>(6)?,
            row.get::<_, String>(7)?,
        ));
    }
    let mut expected = expected
        .iter()
        .map(|(table, from, to)| {
            (
                (*table).to_owned(),
                (*from).to_owned(),
                (*to).to_owned(),
                "NO ACTION".to_owned(),
                "NO ACTION".to_owned(),
                "NONE".to_owned(),
            )
        })
        .collect::<Vec<_>>();
    actual.sort_unstable();
    expected.sort_unstable();
    if actual != expected {
        return Err(AgentStoreError::DamagedSchema(table));
    }
    Ok(())
}

/// Read one exact agent projection by identity.
pub(crate) fn get(
    connection: &Connection,
    agent_id: AgentInstanceId,
) -> Result<Option<RegisteredAgentInstance>, AgentStoreError> {
    agent_by_id(connection, agent_id)
}

pub(crate) fn get_in_transaction(
    connection: &Connection,
    agent_id: AgentInstanceId,
) -> Result<Option<RegisteredAgentInstance>, AgentStoreError> {
    agent_by_id(connection, agent_id)
}

fn agent_by_id(
    connection: &Connection,
    agent_id: AgentInstanceId,
) -> Result<Option<RegisteredAgentInstance>, AgentStoreError> {
    let mut statement = connection.prepare(AGENT_BY_ID_QUERY)?;
    let mut rows = statement.query(params![agent_id.into_uuid().as_bytes()])?;
    let Some(row) = rows.next()? else {
        return Ok(None);
    };
    decode_agent(row).map(Some)
}

/// List agents for one exact Workspace/Activity and project Activity liveness
/// from the same `SQLite` snapshot.  No per-agent Activity query is performed.
pub(crate) fn list_attachments(
    connection: &Connection,
    workspace_id: WorkspaceId,
    activity_id: Option<ActivityId>,
    now: TimestampMillis,
    limit: u32,
) -> Result<Vec<AgentAttachmentProjection>, AgentStoreError> {
    let transaction = connection.unchecked_transaction()?;
    let activity_filter = activity_id.map(|value| value.into_uuid().as_bytes().to_vec());
    if let Some(activity_id) = activity_id {
        let activity = transaction
            .query_row(
                ACTIVITY_BY_ID_QUERY,
                params![activity_id.into_uuid().as_bytes()],
                decode_activity,
            )
            .optional()?
            .ok_or(AgentStoreError::ActivityNotFound(activity_id))?;
        if activity.workspace_id() != workspace_id {
            return Err(AgentStoreError::ActivityWorkspaceMismatch {
                expected: workspace_id,
                actual: activity.workspace_id(),
            });
        }
    }
    let mut statement = transaction.prepare(AGENTS_BY_WORKSPACE_QUERY)?;
    let mut rows = statement.query(params![
        workspace_id.into_uuid().as_bytes(),
        activity_filter.as_deref(),
        limit
    ])?;
    let mut projections = Vec::new();
    while let Some(row) = rows.next()? {
        let agent = decode_agent(row)?;
        let activity = decode_activity_at(row, 24)?;
        if activity.workspace_id() != workspace_id {
            return Err(AgentStoreError::ActivityWorkspaceMismatch {
                expected: workspace_id,
                actual: activity.workspace_id(),
            });
        }
        projections.push(AgentAttachmentProjection::new(
            agent,
            ActivityProjection::from_activity(activity, now),
        ));
    }
    drop(rows);
    drop(statement);
    transaction.commit()?;
    Ok(projections)
}

/// Load one agent, Activity lease/liveness, focus history, and public updates
/// within one read snapshot.  History is bounded and emitted newest-first.
pub(crate) fn get_context(
    connection: &Connection,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    agent_id: AgentInstanceId,
    now: TimestampMillis,
    event_limit: u32,
    update_limit: u32,
) -> Result<Option<AgentContextProjection>, AgentStoreError> {
    let transaction = connection.unchecked_transaction()?;
    let agent = agent_by_id(&transaction, agent_id)?;
    let Some(agent) = agent else {
        transaction.commit()?;
        return Ok(None);
    };
    if agent.workspace_id() != workspace_id {
        return Err(AgentStoreError::WorkspaceMismatch {
            expected: workspace_id,
            actual: agent.workspace_id(),
        });
    }
    if agent.activity_id() != activity_id {
        return Err(AgentStoreError::ActivityAgentMismatch {
            expected: activity_id,
            actual: agent.activity_id(),
        });
    }
    let activity = transaction
        .query_row(
            ACTIVITY_BY_ID_QUERY,
            params![activity_id.into_uuid().as_bytes()],
            decode_activity,
        )
        .optional()?
        .ok_or(AgentStoreError::ActivityNotFound(activity_id))?;
    let mut focus_statement = transaction.prepare(FOCUS_EVENTS_QUERY)?;
    let mut focus_rows =
        focus_statement.query(params![agent_id.into_uuid().as_bytes(), event_limit])?;
    let mut focus_events = Vec::new();
    while let Some(row) = focus_rows.next()? {
        focus_events.push(decode_focus_event(row)?);
    }
    drop(focus_rows);
    drop(focus_statement);
    let mut update_statement = transaction.prepare(WORK_UPDATES_QUERY)?;
    let mut update_rows =
        update_statement.query(params![agent_id.into_uuid().as_bytes(), update_limit])?;
    let mut work_bases = Vec::new();
    while let Some(row) = update_rows.next()? {
        work_bases.push(decode_work_update_base(row)?);
    }
    drop(update_rows);
    drop(update_statement);
    let evidence_by_update = load_work_update_evidence(&transaction, agent_id, update_limit)?;
    let mut work_updates = Vec::with_capacity(work_bases.len());
    for base in work_bases {
        let evidence_refs = evidence_by_update
            .get(&base.id)
            .cloned()
            .unwrap_or_default();
        work_updates.push(build_work_update(base, evidence_refs)?);
    }
    let context = AgentContextProjection::new(
        AgentAttachmentProjection::new(agent, ActivityProjection::from_activity(activity, now)),
        focus_events,
        work_updates,
    );
    transaction.commit()?;
    Ok(Some(context))
}

pub(crate) fn attach(
    connection: &mut Connection,
    agent: &RegisteredAgentInstance,
) -> Result<RegisteredAgentInstance, AgentStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    ensure_workspace(&transaction, agent.workspace_id())?;
    ensure_activity(&transaction, agent.workspace_id(), agent.activity_id())?;
    if let Some(existing) = agent_by_id(&transaction, agent.id())? {
        if existing == *agent {
            transaction.commit()?;
            return Ok(existing);
        }
        return Err(AgentStoreError::IdentityConflict);
    }
    if agent.attachment_state() != AgentAttachmentState::Attached
        || !agent.focus().is_unfocused()
        || agent.revision() != AgentInstanceRevision::INITIAL
    {
        return Err(AgentStoreError::InvalidProjection("initial agent"));
    }
    insert_agent(&transaction, agent)?;
    insert_transport_principal(&transaction, agent)?;
    insert_focus_event(
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
    let result = agent_by_id(&transaction, agent.id())?
        .ok_or(AgentStoreError::CorruptRecord("agent.inserted"))?;
    transaction.commit()?;
    Ok(result)
}

pub(crate) fn set_focus(
    connection: &mut Connection,
    command: &forge_domain::SetAgentFocus,
) -> Result<RegisteredAgentInstance, AgentStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let current = agent_by_id(&transaction, command.agent_id())?
        .ok_or(AgentStoreError::AgentNotFound(command.agent_id()))?;
    if current.activity_id() != command.activity_id() {
        return Err(AgentStoreError::ActivityAgentMismatch {
            expected: command.activity_id(),
            actual: current.activity_id(),
        });
    }
    ensure_focus_is_current(&transaction, current.workspace_id(), command.focus())?;
    let updated = current
        .set_focus(
            command.expected_revision(),
            command.focus(),
            command.observed_at(),
        )
        .map_err(AgentStoreError::Transition)?;
    update_agent(&transaction, &current, &updated)?;
    insert_focus_event(
        &transaction,
        &AgentFocusEvent::from_parts(
            updated.id(),
            updated.workspace_id(),
            updated.activity_id(),
            AgentFocusEventSequence::new(updated.revision().get())
                .map_err(|_| AgentStoreError::IntegerOverflow)?,
            AgentFocusEventKind::Changed,
            updated.focus(),
            updated.updated_at(),
        ),
    )?;
    transaction.commit()?;
    Ok(updated)
}

pub(crate) fn detach(
    connection: &mut Connection,
    command: &forge_domain::DetachAgent,
) -> Result<RegisteredAgentInstance, AgentStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let current = agent_by_id(&transaction, command.agent_id())?
        .ok_or(AgentStoreError::AgentNotFound(command.agent_id()))?;
    if current.activity_id() != command.activity_id() {
        return Err(AgentStoreError::ActivityAgentMismatch {
            expected: command.activity_id(),
            actual: current.activity_id(),
        });
    }
    let updated = current
        .detach(command.expected_revision(), command.observed_at())
        .map_err(AgentStoreError::Transition)?;
    update_agent(&transaction, &current, &updated)?;
    insert_focus_event(
        &transaction,
        &AgentFocusEvent::from_parts(
            updated.id(),
            updated.workspace_id(),
            updated.activity_id(),
            AgentFocusEventSequence::new(updated.revision().get())
                .map_err(|_| AgentStoreError::IntegerOverflow)?,
            AgentFocusEventKind::Detached,
            updated.focus(),
            updated.updated_at(),
        ),
    )?;
    transaction.commit()?;
    Ok(updated)
}

pub(crate) fn publish_work_update(
    connection: &mut Connection,
    update: &AgentWorkUpdate,
) -> Result<AgentWorkUpdate, AgentStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let result = publish_work_update_in_transaction(&transaction, update)?;
    transaction.commit()?;
    Ok(result)
}

pub(crate) fn publish_work_update_in_transaction(
    transaction: &rusqlite::Transaction<'_>,
    update: &AgentWorkUpdate,
) -> Result<AgentWorkUpdate, AgentStoreError> {
    let current = agent_by_id(transaction, update.agent_id())?
        .ok_or(AgentStoreError::AgentNotFound(update.agent_id()))?;
    if current.workspace_id() != update.workspace_id() {
        return Err(AgentStoreError::WorkspaceMismatch {
            expected: current.workspace_id(),
            actual: update.workspace_id(),
        });
    }
    if current.activity_id() != update.activity_id() {
        return Err(AgentStoreError::ActivityAgentMismatch {
            expected: current.activity_id(),
            actual: update.activity_id(),
        });
    }
    if current.attachment_state().is_detached() {
        return Err(AgentStoreError::AgentDetached(update.agent_id()));
    }
    if let Some(existing) = work_update_by_id(transaction, update.id())? {
        if existing == *update {
            return Ok(existing);
        }
        return Err(AgentStoreError::IdentityConflict);
    }
    let expected_sequence = next_work_sequence(transaction, update.agent_id())?;
    if update.sequence() != expected_sequence {
        return Err(AgentStoreError::WorkSequenceConflict {
            expected: expected_sequence,
            actual: update.sequence(),
        });
    }
    let evidence_count = update.evidence_refs().len();
    transaction.execute(
        "INSERT INTO agent_work_updates (update_id, agent_id, workspace_id, activity_id, update_sequence, phase, summary, evidence_count, observed_at_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            update.id().into_uuid().as_bytes(),
            update.agent_id().into_uuid().as_bytes(),
            update.workspace_id().into_uuid().as_bytes(),
            update.activity_id().into_uuid().as_bytes(),
            update.sequence().get(),
            encode_work_phase(update.phase()),
            update.summary().as_str(),
            i64::try_from(evidence_count).map_err(|_| AgentStoreError::IntegerOverflow)?,
            update.observed_at().get(),
        ],
    )?;
    for evidence in update.evidence_refs() {
        ensure_evidence(transaction, update.workspace_id(), *evidence)?;
        let (kind, id) = encode_evidence(*evidence);
        transaction.execute(
            "INSERT INTO agent_work_update_evidence_refs (update_id, agent_id, workspace_id, evidence_kind, evidence_id) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                update.id().into_uuid().as_bytes(),
                update.agent_id().into_uuid().as_bytes(),
                update.workspace_id().into_uuid().as_bytes(),
                kind,
                id.as_slice(),
            ],
        )?;
    }
    Ok(update.clone())
}

fn ensure_workspace(
    connection: &Connection,
    workspace_id: WorkspaceId,
) -> Result<(), AgentStoreError> {
    let exists: Option<i64> = connection
        .query_row(
            "SELECT 1 FROM workspace WHERE workspace_id = ?1",
            params![workspace_id.into_uuid().as_bytes()],
            |row| row.get(0),
        )
        .optional()?;
    if exists.is_some() {
        Ok(())
    } else {
        Err(AgentStoreError::WorkspaceMismatch {
            expected: workspace_id,
            actual: workspace_id,
        })
    }
}

fn ensure_activity(
    connection: &Connection,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
) -> Result<(), AgentStoreError> {
    let actual = connection
        .query_row(
            "SELECT workspace_id FROM activities WHERE activity_id = ?1",
            params![activity_id.into_uuid().as_bytes()],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?;
    let Some(actual) = actual else {
        return Err(AgentStoreError::ActivityNotFound(activity_id));
    };
    let actual = decode_workspace_id(&actual)?;
    if actual != workspace_id {
        return Err(AgentStoreError::ActivityWorkspaceMismatch {
            expected: workspace_id,
            actual,
        });
    }
    Ok(())
}

fn ensure_focus_is_current(
    connection: &Connection,
    workspace_id: WorkspaceId,
    focus: AgentFocus,
) -> Result<(), AgentStoreError> {
    let Some(goal) = focus.goal() else {
        return Ok(());
    };
    let goal_revision = connection
        .query_row(
            "SELECT workspace_id, revision FROM goals WHERE goal_id = ?1",
            params![goal.goal_id().into_uuid().as_bytes()],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()?
        .ok_or(AgentStoreError::FocusGoalMissing(goal.goal_id()))?;
    let goal_workspace = decode_workspace_id(&goal_revision.0)?;
    if goal_workspace != workspace_id {
        return Err(AgentStoreError::FocusWorkspaceMismatch);
    }
    let actual_goal_revision = GoalRevision::new(goal_revision.1)
        .map_err(|_| AgentStoreError::CorruptRecord("goals.revision"))?;
    if actual_goal_revision != goal.expected_revision() {
        return Err(AgentStoreError::FocusGoalRevisionConflict {
            expected: goal.expected_revision(),
            actual: actual_goal_revision,
        });
    }
    let dag_revision = focus
        .dag_revision()
        .ok_or(AgentStoreError::FocusDagMissing(goal.goal_id()))?;
    let current_dag = connection
        .query_row(
            "SELECT dag_revision FROM goal_dag_heads WHERE goal_id = ?1",
            params![goal.goal_id().into_uuid().as_bytes()],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .ok_or(AgentStoreError::FocusDagMissing(goal.goal_id()))?;
    let current_dag = DagRevisionNumber::new(current_dag)
        .map_err(|_| AgentStoreError::CorruptRecord("goal_dag_heads.dag_revision"))?;
    if current_dag != dag_revision {
        return Err(AgentStoreError::FocusDagNotCurrent {
            expected: current_dag,
            actual: dag_revision,
        });
    }
    if let Some(node) = focus.node() {
        let node_revision = connection
            .query_row(
                "SELECT node_revision FROM goal_dag_nodes WHERE goal_id = ?1 AND dag_revision = ?2 AND node_id = ?3",
                params![goal.goal_id().into_uuid().as_bytes(), dag_revision.get(), node.node_id().into_uuid().as_bytes()],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .ok_or(AgentStoreError::FocusNodeMissing(node.node_id()))?;
        let actual = DagNodeRevision::new(node_revision)
            .map_err(|_| AgentStoreError::CorruptRecord("goal_dag_nodes.node_revision"))?;
        if actual != node.expected_revision() {
            return Err(AgentStoreError::FocusNodeRevisionConflict {
                expected: node.expected_revision(),
                actual,
            });
        }
    }
    Ok(())
}

fn ensure_evidence(
    connection: &Connection,
    workspace_id: WorkspaceId,
    evidence: GoalEvidenceRef,
) -> Result<(), AgentStoreError> {
    let (kind, id) = encode_evidence(evidence);
    let exists: Option<i64> = connection
        .query_row(
            "SELECT 1 FROM goal_evidence_refs AS e JOIN goals AS g ON g.goal_id = e.goal_id WHERE g.workspace_id = ?1 AND e.evidence_kind = ?2 AND e.evidence_id = ?3",
            params![workspace_id.into_uuid().as_bytes(), kind, id.as_slice()],
            |row| row.get(0),
        )
        .optional()?;
    if exists.is_some() {
        Ok(())
    } else {
        Err(AgentStoreError::EvidenceMissing(evidence))
    }
}

fn next_work_sequence(
    connection: &Connection,
    agent_id: AgentInstanceId,
) -> Result<AgentWorkUpdateSequence, AgentStoreError> {
    let current: Option<i64> = connection.query_row(
        "SELECT MAX(update_sequence) FROM agent_work_updates WHERE agent_id = ?1",
        params![agent_id.into_uuid().as_bytes()],
        |row| row.get(0),
    )?;
    let next = current
        .unwrap_or(0)
        .checked_add(1)
        .ok_or(AgentStoreError::IntegerOverflow)?;
    AgentWorkUpdateSequence::new(next).map_err(|_| AgentStoreError::IntegerOverflow)
}

fn insert_agent(
    connection: &Connection,
    agent: &RegisteredAgentInstance,
) -> Result<(), AgentStoreError> {
    let (goal_id, goal_revision, dag_revision, node_id, node_revision) =
        encode_focus(agent.focus());
    connection.execute(
        "INSERT INTO agent_instances (agent_id, workspace_id, activity_id, display_name, declared_role, transport_kind, attachment_state, focus_goal_id, focus_goal_revision, focus_dag_revision, focus_node_id, focus_node_revision, created_at_ms, updated_at_ms, revision) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        params![
            agent.id().into_uuid().as_bytes(),
            agent.workspace_id().into_uuid().as_bytes(),
            agent.activity_id().into_uuid().as_bytes(),
            agent.display_name().as_str(),
            agent.declared_role().as_str(),
            encode_transport(agent.transport_kind()),
            encode_attachment_state(agent.attachment_state()),
            goal_id.as_deref(),
            goal_revision,
            dag_revision,
            node_id.as_deref(),
            node_revision,
            agent.created_at().get(),
            agent.updated_at().get(),
            agent.revision().get(),
        ],
    )?;
    Ok(())
}

fn insert_transport_principal(
    connection: &Connection,
    agent: &RegisteredAgentInstance,
) -> Result<(), AgentStoreError> {
    let Some(token_id) = agent.transport_principal() else {
        return Ok(());
    };
    connection.execute(
        "INSERT INTO agent_transport_principals (agent_id, workspace_id, activity_id, token_id) VALUES (?1, ?2, ?3, ?4)",
        params![
            agent.id().into_uuid().as_bytes(),
            agent.workspace_id().into_uuid().as_bytes(),
            agent.activity_id().into_uuid().as_bytes(),
            token_id.into_uuid().as_bytes(),
        ],
    )?;
    Ok(())
}

fn update_agent(
    connection: &Connection,
    current: &RegisteredAgentInstance,
    updated: &RegisteredAgentInstance,
) -> Result<(), AgentStoreError> {
    let (goal_id, goal_revision, dag_revision, node_id, node_revision) =
        encode_focus(updated.focus());
    let changed = connection.execute(
        "UPDATE agent_instances SET attachment_state = ?1, focus_goal_id = ?2, focus_goal_revision = ?3, focus_dag_revision = ?4, focus_node_id = ?5, focus_node_revision = ?6, updated_at_ms = ?7, revision = ?8 WHERE agent_id = ?9 AND revision = ?10 AND workspace_id = ?11 AND activity_id = ?12",
        params![
            encode_attachment_state(updated.attachment_state()),
            goal_id.as_deref(),
            goal_revision,
            dag_revision,
            node_id.as_deref(),
            node_revision,
            updated.updated_at().get(),
            updated.revision().get(),
            updated.id().into_uuid().as_bytes(),
            current.revision().get(),
            current.workspace_id().into_uuid().as_bytes(),
            current.activity_id().into_uuid().as_bytes(),
        ],
    )?;
    if changed == 1 {
        Ok(())
    } else {
        Err(AgentStoreError::RevisionConflict {
            expected: current.revision(),
        })
    }
}

fn insert_focus_event(
    connection: &Connection,
    event: &AgentFocusEvent,
) -> Result<(), AgentStoreError> {
    let (goal_id, goal_revision, dag_revision, node_id, node_revision) =
        encode_focus(event.focus());
    connection.execute(
        "INSERT INTO agent_focus_events (agent_id, workspace_id, activity_id, event_sequence, event_kind, focus_goal_id, focus_goal_revision, focus_dag_revision, focus_node_id, focus_node_revision, observed_at_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            event.agent_id().into_uuid().as_bytes(),
            event.workspace_id().into_uuid().as_bytes(),
            event.activity_id().into_uuid().as_bytes(),
            event.sequence().get(),
            encode_focus_event_kind(event.kind()),
            goal_id.as_deref(),
            goal_revision,
            dag_revision,
            node_id.as_deref(),
            node_revision,
            event.observed_at().get(),
        ],
    )?;
    Ok(())
}

type EncodedFocus = (
    Option<Vec<u8>>,
    Option<i64>,
    Option<i64>,
    Option<Vec<u8>>,
    Option<i64>,
);

fn encode_focus(focus: AgentFocus) -> EncodedFocus {
    let Some(goal) = focus.goal() else {
        return (None, None, None, None, None);
    };
    let node = focus.node();
    (
        Some(goal.goal_id().into_uuid().as_bytes().to_vec()),
        Some(goal.expected_revision().get()),
        focus.dag_revision().map(DagRevisionNumber::get),
        node.map(|value| value.node_id().into_uuid().as_bytes().to_vec()),
        node.map(|value| value.expected_revision().get()),
    )
}

fn encode_evidence(evidence: GoalEvidenceRef) -> (i64, [u8; ID_BYTES]) {
    match evidence {
        GoalEvidenceRef::ChangeSet(id) => (0, id.into_uuid().into_bytes()),
        GoalEvidenceRef::Execution(id) => (1, id.into_uuid().into_bytes()),
        GoalEvidenceRef::Approval(id) => (2, id.into_uuid().into_bytes()),
        GoalEvidenceRef::Checkpoint(id) => (3, id.into_uuid().into_bytes()),
    }
}

fn encode_transport(value: AgentTransportKind) -> i64 {
    match value {
        AgentTransportKind::Mcp => 0,
        AgentTransportKind::Stdio => 1,
        AgentTransportKind::StreamableHttp => 2,
        AgentTransportKind::Other => 3,
    }
}

fn decode_transport(value: i64) -> Result<AgentTransportKind, AgentStoreError> {
    match value {
        0 => Ok(AgentTransportKind::Mcp),
        1 => Ok(AgentTransportKind::Stdio),
        2 => Ok(AgentTransportKind::StreamableHttp),
        3 => Ok(AgentTransportKind::Other),
        _ => Err(AgentStoreError::CorruptRecord("agent.transport_kind")),
    }
}

fn encode_attachment_state(value: AgentAttachmentState) -> i64 {
    match value {
        AgentAttachmentState::Attached => 0,
        AgentAttachmentState::Detached => 1,
    }
}

fn decode_attachment_state(value: i64) -> Result<AgentAttachmentState, AgentStoreError> {
    match value {
        0 => Ok(AgentAttachmentState::Attached),
        1 => Ok(AgentAttachmentState::Detached),
        _ => Err(AgentStoreError::CorruptRecord("agent.attachment_state")),
    }
}

fn encode_focus_event_kind(value: AgentFocusEventKind) -> i64 {
    match value {
        AgentFocusEventKind::Attached => 0,
        AgentFocusEventKind::Changed => 1,
        AgentFocusEventKind::Detached => 2,
    }
}

fn decode_focus_event_kind(value: i64) -> Result<AgentFocusEventKind, AgentStoreError> {
    match value {
        0 => Ok(AgentFocusEventKind::Attached),
        1 => Ok(AgentFocusEventKind::Changed),
        2 => Ok(AgentFocusEventKind::Detached),
        _ => Err(AgentStoreError::CorruptRecord(
            "agent_focus_events.event_kind",
        )),
    }
}

fn encode_work_phase(value: AgentWorkPhase) -> i64 {
    match value {
        AgentWorkPhase::Planning => 0,
        AgentWorkPhase::Executing => 1,
        AgentWorkPhase::Waiting => 2,
        AgentWorkPhase::Verifying => 3,
        AgentWorkPhase::Completed => 4,
        AgentWorkPhase::Blocked => 5,
        AgentWorkPhase::Failed => 6,
    }
}

fn decode_work_phase(value: i64) -> Result<AgentWorkPhase, AgentStoreError> {
    match value {
        0 => Ok(AgentWorkPhase::Planning),
        1 => Ok(AgentWorkPhase::Executing),
        2 => Ok(AgentWorkPhase::Waiting),
        3 => Ok(AgentWorkPhase::Verifying),
        4 => Ok(AgentWorkPhase::Completed),
        5 => Ok(AgentWorkPhase::Blocked),
        6 => Ok(AgentWorkPhase::Failed),
        _ => Err(AgentStoreError::CorruptRecord("agent_work_updates.phase")),
    }
}

fn decode_agent(row: &Row<'_>) -> Result<RegisteredAgentInstance, AgentStoreError> {
    let id: Vec<u8> = row.get(0)?;
    let workspace_id: Vec<u8> = row.get(1)?;
    let activity_id: Vec<u8> = row.get(2)?;
    validate_exact_length("agent_id", row.get(15)?, ID_BYTES_I64)?;
    validate_exact_length("agent.workspace_id", row.get(16)?, ID_BYTES_I64)?;
    validate_exact_length("agent.activity_id", row.get(17)?, ID_BYTES_I64)?;
    validate_text_length(
        "agent.display_name",
        row.get(18)?,
        forge_domain::MAX_AGENT_DISPLAY_NAME_BYTES,
    )?;
    validate_text_length("agent.declared_role", row.get(19)?, MAX_METADATA_BYTES)?;
    if let Some(length) = row.get::<_, Option<i64>>(20)? {
        validate_exact_length("agent.focus_goal_id", length, ID_BYTES_I64)?;
    }
    if let Some(length) = row.get::<_, Option<i64>>(21)? {
        validate_exact_length("agent.focus_node_id", length, ID_BYTES_I64)?;
    }
    let principal: Option<Vec<u8>> = row.get(22)?;
    let principal_length: Option<i64> = row.get(23)?;
    let transport_principal = match (principal, principal_length) {
        (None, None) => None,
        (Some(value), Some(length)) => {
            validate_exact_length("agent_transport_principals.token_id", length, ID_BYTES_I64)?;
            Some(McpTokenId::from_uuid(decode_uuid(
                &value,
                "agent_transport_principals.token_id",
            )?))
        }
        _ => {
            return Err(AgentStoreError::CorruptRecord(
                "agent_transport_principals.token_id",
            ));
        }
    };
    let focus = decode_focus(
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
        row.get(10)?,
        row.get(11)?,
    )?;
    let created_at = decode_timestamp(row.get(12)?, "agent.created_at_ms")?;
    let updated_at = decode_timestamp(row.get(13)?, "agent.updated_at_ms")?;
    let revision = AgentInstanceRevision::new(row.get(14)?)
        .map_err(|_| AgentStoreError::CorruptRecord("agent.revision"))?;
    RegisteredAgentInstance::from_parts_with_principal(
        decode_agent_id(&id)?,
        decode_workspace_id(&workspace_id)?,
        decode_activity_id(&activity_id)?,
        AgentDisplayName::new(row.get(3)?)
            .map_err(|_| AgentStoreError::CorruptRecord("agent.display_name"))?,
        AgentDeclaredRole::new(row.get(4)?)
            .map_err(|_| AgentStoreError::CorruptRecord("agent.declared_role"))?,
        decode_transport(row.get(5)?)?,
        transport_principal,
        decode_attachment_state(row.get(6)?)?,
        focus,
        created_at,
        updated_at,
        revision,
    )
    .map_err(|_| AgentStoreError::CorruptRecord("agent.projection"))
}

fn decode_focus(
    goal_id: Option<Vec<u8>>,
    goal_revision: Option<i64>,
    dag_revision: Option<i64>,
    node_id: Option<Vec<u8>>,
    node_revision: Option<i64>,
) -> Result<AgentFocus, AgentStoreError> {
    let goal = goal_id
        .map(|value| {
            let id = decode_goal_id(&value)?;
            let revision = GoalRevision::new(
                goal_revision.ok_or(AgentStoreError::CorruptRecord("agent.focus_goal_revision"))?,
            )
            .map_err(|_| AgentStoreError::CorruptRecord("agent.focus_goal_revision"))?;
            Ok::<GoalAttribution, AgentStoreError>(GoalAttribution::new(id, revision))
        })
        .transpose()?;
    let dag_revision = dag_revision
        .map(|value| {
            DagRevisionNumber::new(value)
                .map_err(|_| AgentStoreError::CorruptRecord("agent.focus_dag_revision"))
        })
        .transpose()?;
    let node = node_id
        .map(|value| {
            let id = decode_node_id(&value)?;
            let revision = DagNodeRevision::new(
                node_revision.ok_or(AgentStoreError::CorruptRecord("agent.focus_node_revision"))?,
            )
            .map_err(|_| AgentStoreError::CorruptRecord("agent.focus_node_revision"))?;
            Ok::<AgentFocusNode, AgentStoreError>(AgentFocusNode::new(id, revision))
        })
        .transpose()?;
    AgentFocus::new(goal, dag_revision, node)
        .map_err(|_| AgentStoreError::CorruptRecord("agent.focus"))
}

fn decode_focus_event(row: &Row<'_>) -> Result<AgentFocusEvent, AgentStoreError> {
    validate_exact_length("agent_focus_events.agent_id", row.get(13)?, ID_BYTES_I64)?;
    validate_exact_length(
        "agent_focus_events.workspace_id",
        row.get(14)?,
        ID_BYTES_I64,
    )?;
    validate_exact_length("agent_focus_events.activity_id", row.get(15)?, ID_BYTES_I64)?;
    let goal_length: Option<i64> = row.get(6)?;
    if let Some(length) = goal_length {
        validate_exact_length("agent_focus_events.focus_goal_id", length, ID_BYTES_I64)?;
    }
    let node_length: Option<i64> = row.get(10)?;
    if let Some(length) = node_length {
        validate_exact_length("agent_focus_events.focus_node_id", length, ID_BYTES_I64)?;
    }
    let agent_id: Vec<u8> = row.get(0)?;
    let workspace_id: Vec<u8> = row.get(1)?;
    let activity_id: Vec<u8> = row.get(2)?;
    let goal_id: Option<Vec<u8>> = row.get(5)?;
    let goal_revision: Option<i64> = row.get(7)?;
    let dag_revision: Option<i64> = row.get(8)?;
    let node_id: Option<Vec<u8>> = row.get(9)?;
    let node_revision: Option<i64> = row.get(11)?;
    Ok(AgentFocusEvent::from_parts(
        decode_agent_id(&agent_id)?,
        decode_workspace_id(&workspace_id)?,
        decode_activity_id(&activity_id)?,
        AgentFocusEventSequence::new(row.get(3)?)
            .map_err(|_| AgentStoreError::CorruptRecord("agent_focus_events.event_sequence"))?,
        decode_focus_event_kind(row.get(4)?)?,
        decode_focus(goal_id, goal_revision, dag_revision, node_id, node_revision)?,
        decode_timestamp(row.get(12)?, "agent_focus_events.observed_at_ms")?,
    ))
}

fn work_update_by_id(
    connection: &Connection,
    update_id: AgentWorkUpdateId,
) -> Result<Option<AgentWorkUpdate>, AgentStoreError> {
    let mut statement = connection.prepare(WORK_UPDATE_BY_ID_QUERY)?;
    let mut rows = statement.query(params![update_id.into_uuid().as_bytes()])?;
    let Some(row) = rows.next()? else {
        return Ok(None);
    };
    decode_work_update_row(connection, row).map(Some)
}

struct WorkUpdateBase {
    id: AgentWorkUpdateId,
    agent_id: AgentInstanceId,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    sequence: AgentWorkUpdateSequence,
    phase: AgentWorkPhase,
    summary: AgentWorkSummary,
    evidence_count: usize,
    observed_at: TimestampMillis,
}

fn decode_work_update_base(row: &Row<'_>) -> Result<WorkUpdateBase, AgentStoreError> {
    validate_exact_length("agent_work_updates.update_id", row.get(10)?, ID_BYTES_I64)?;
    validate_exact_length("agent_work_updates.agent_id", row.get(11)?, ID_BYTES_I64)?;
    validate_exact_length(
        "agent_work_updates.workspace_id",
        row.get(12)?,
        ID_BYTES_I64,
    )?;
    validate_exact_length("agent_work_updates.activity_id", row.get(13)?, ID_BYTES_I64)?;
    validate_text_length("agent_work_updates.summary", row.get(7)?, MAX_TEXT_BYTES)?;
    let update_id_bytes: Vec<u8> = row.get(0)?;
    let agent_id_bytes: Vec<u8> = row.get(1)?;
    let workspace_id_bytes: Vec<u8> = row.get(2)?;
    let activity_id_bytes: Vec<u8> = row.get(3)?;
    let update_id = decode_update_id(&update_id_bytes)?;
    let agent_id = decode_agent_id(&agent_id_bytes)?;
    let workspace_id = decode_workspace_id(&workspace_id_bytes)?;
    let activity_id = decode_activity_id(&activity_id_bytes)?;
    let sequence = AgentWorkUpdateSequence::new(row.get(4)?)
        .map_err(|_| AgentStoreError::CorruptRecord("agent_work_updates.update_sequence"))?;
    let phase = decode_work_phase(row.get(5)?)?;
    let summary_text: String = row.get(6)?;
    let summary = AgentWorkSummary::new(summary_text)
        .map_err(|_| AgentStoreError::CorruptRecord("agent_work_updates.summary"))?;
    let evidence_count: i64 = row.get(8)?;
    if !(0..=32).contains(&evidence_count) {
        return Err(AgentStoreError::CorruptRecord(
            "agent_work_updates.evidence_count",
        ));
    }
    Ok(WorkUpdateBase {
        id: update_id,
        agent_id,
        workspace_id,
        activity_id,
        sequence,
        phase,
        summary,
        evidence_count: usize::try_from(evidence_count)
            .map_err(|_| AgentStoreError::IntegerOverflow)?,
        observed_at: decode_timestamp(row.get(9)?, "agent_work_updates.observed_at_ms")?,
    })
}

fn build_work_update(
    base: WorkUpdateBase,
    evidence_refs: Vec<GoalEvidenceRef>,
) -> Result<AgentWorkUpdate, AgentStoreError> {
    if evidence_refs.len() != base.evidence_count {
        return Err(AgentStoreError::CorruptRecord(
            "agent_work_updates.evidence_count",
        ));
    }
    AgentWorkUpdate::new(
        base.id,
        base.agent_id,
        base.workspace_id,
        base.activity_id,
        base.sequence,
        base.phase,
        base.summary,
        evidence_refs,
        base.observed_at,
    )
    .map_err(|_| AgentStoreError::CorruptRecord("agent_work_updates.projection"))
}

fn load_work_update_evidence(
    connection: &Connection,
    agent_id: AgentInstanceId,
    limit: u32,
) -> Result<BTreeMap<AgentWorkUpdateId, Vec<GoalEvidenceRef>>, AgentStoreError> {
    let mut statement = connection.prepare(WORK_UPDATE_EVIDENCE_FOR_AGENT_QUERY)?;
    let mut rows = statement.query(params![agent_id.into_uuid().as_bytes(), limit])?;
    let mut evidence = BTreeMap::new();
    while let Some(row) = rows.next()? {
        let update_id_bytes: Vec<u8> = row.get(0)?;
        let update_id = decode_update_id(&update_id_bytes)?;
        evidence
            .entry(update_id)
            .or_insert_with(Vec::new)
            .push(decode_evidence_at(row, 1)?);
    }
    Ok(evidence)
}

fn decode_evidence_at(row: &Row<'_>, offset: usize) -> Result<GoalEvidenceRef, AgentStoreError> {
    let kind: i64 = row.get(offset)?;
    let id: Vec<u8> = row.get(offset + 1)?;
    validate_exact_length(
        "agent_work_update_evidence_refs.evidence_id",
        row.get(offset + 2)?,
        ID_BYTES_I64,
    )?;
    let id = decode_uuid(&id, "agent evidence id")?;
    match kind {
        0 => Ok(GoalEvidenceRef::ChangeSet(
            forge_domain::ChangeSetId::from_uuid(id),
        )),
        1 => Ok(GoalEvidenceRef::Execution(
            forge_domain::ExecutionId::from_uuid(id),
        )),
        2 => Ok(GoalEvidenceRef::Approval(
            forge_domain::ApprovalRequestId::from_uuid(id),
        )),
        3 => Ok(GoalEvidenceRef::Checkpoint(
            forge_domain::CheckpointId::from_uuid(id),
        )),
        _ => Err(AgentStoreError::CorruptRecord("agent evidence kind")),
    }
}

fn decode_work_update_row(
    connection: &Connection,
    row: &Row<'_>,
) -> Result<AgentWorkUpdate, AgentStoreError> {
    let base = decode_work_update_base(row)?;
    let mut statement = connection.prepare(WORK_UPDATE_EVIDENCE_QUERY)?;
    let mut evidence_rows = statement.query(params![base.id.into_uuid().as_bytes()])?;
    let mut evidence_refs = Vec::new();
    while let Some(row) = evidence_rows.next()? {
        evidence_refs.push(decode_evidence(row)?);
    }
    build_work_update(base, evidence_refs)
}

fn decode_evidence(row: &Row<'_>) -> Result<GoalEvidenceRef, AgentStoreError> {
    let kind: i64 = row.get(0)?;
    let id: Vec<u8> = row.get(1)?;
    validate_exact_length(
        "agent_work_update_evidence_refs.evidence_id",
        row.get(2)?,
        ID_BYTES_I64,
    )?;
    let id =
        Uuid::from_slice(&id).map_err(|_| AgentStoreError::CorruptRecord("agent evidence id"))?;
    match kind {
        0 => Ok(GoalEvidenceRef::ChangeSet(
            forge_domain::ChangeSetId::from_uuid(id),
        )),
        1 => Ok(GoalEvidenceRef::Execution(
            forge_domain::ExecutionId::from_uuid(id),
        )),
        2 => Ok(GoalEvidenceRef::Approval(
            forge_domain::ApprovalRequestId::from_uuid(id),
        )),
        3 => Ok(GoalEvidenceRef::Checkpoint(
            forge_domain::CheckpointId::from_uuid(id),
        )),
        _ => Err(AgentStoreError::CorruptRecord("agent evidence kind")),
    }
}

fn decode_activity(row: &Row<'_>) -> Result<RegisteredActivity, rusqlite::Error> {
    decode_activity_at(row, 0).map_err(|_| rusqlite::Error::InvalidQuery)
}

fn decode_activity_at(row: &Row<'_>, offset: usize) -> Result<RegisteredActivity, AgentStoreError> {
    let activity_id: Vec<u8> = row.get(offset).map_err(AgentStoreError::from)?;
    let workspace_id: Vec<u8> = row.get(offset + 1).map_err(AgentStoreError::from)?;
    let lease_owner: Option<Vec<u8>> = row.get(offset + 6).map_err(AgentStoreError::from)?;
    let lease_until: Option<i64> = row.get(offset + 7).map_err(AgentStoreError::from)?;
    let lease_revision = forge_domain::ActivityLeaseRevision::new(
        row.get(offset + 8).map_err(AgentStoreError::from)?,
    )
    .map_err(|_| AgentStoreError::CorruptRecord("activities.lease_revision"))?;
    let owner = match lease_owner {
        Some(value) => Some(RuntimeInstanceId::from_uuid(decode_uuid(
            &value,
            "activities.lease_owner_id",
        )?)),
        None => None,
    };
    let until = lease_until
        .map(|value| decode_timestamp(value, "activities.lease_until_ms"))
        .transpose()?;
    let lease = match ActivityLeaseProjection::from_parts(owner, until, lease_revision) {
        Ok(lease) => lease,
        Err(error) => {
            eprintln!("activity lease projection error: {error:?}");
            return Err(AgentStoreError::CorruptRecord("activities.lease"));
        }
    };
    let state = match row
        .get::<_, i64>(offset + 2)
        .map_err(AgentStoreError::from)?
    {
        0 => ActivityState::Closed,
        1 => ActivityState::Open,
        2 => ActivityState::Interrupted,
        _ => return Err(AgentStoreError::CorruptRecord("activities.state")),
    };
    if matches!(state, ActivityState::Closed | ActivityState::Interrupted) && !lease.is_unleased() {
        return Err(AgentStoreError::CorruptRecord("activities.lease"));
    }
    Ok(RegisteredActivity::from_parts_with_lease(
        ActivityId::from_uuid(decode_uuid(&activity_id, "activities.activity_id")?),
        WorkspaceId::from_uuid(decode_uuid(&workspace_id, "activities.workspace_id")?),
        state,
        decode_timestamp(
            row.get(offset + 3).map_err(AgentStoreError::from)?,
            "activities.created_at_ms",
        )?,
        decode_timestamp(
            row.get(offset + 4).map_err(AgentStoreError::from)?,
            "activities.updated_at_ms",
        )?,
        ActivityRevision::new(row.get(offset + 5).map_err(AgentStoreError::from)?)
            .map_err(|_| AgentStoreError::CorruptRecord("activities.revision"))?,
        lease,
    ))
}

fn decode_timestamp(value: i64, field: &'static str) -> Result<TimestampMillis, AgentStoreError> {
    TimestampMillis::new(value).map_err(|_| AgentStoreError::CorruptRecord(field))
}

fn validate_exact_length(
    field: &'static str,
    actual: i64,
    expected: i64,
) -> Result<(), AgentStoreError> {
    if actual == expected {
        Ok(())
    } else {
        Err(AgentStoreError::InvalidFieldLength {
            field,
            actual,
            expected,
        })
    }
}

fn validate_text_length(
    field: &'static str,
    actual: i64,
    maximum: usize,
) -> Result<(), AgentStoreError> {
    if actual < 1 || usize::try_from(actual).unwrap_or(usize::MAX) > maximum {
        Err(AgentStoreError::InvalidFieldLength {
            field,
            actual,
            expected: i64::try_from(maximum).unwrap_or(i64::MAX),
        })
    } else {
        Ok(())
    }
}

fn decode_uuid(value: &[u8], field: &'static str) -> Result<Uuid, AgentStoreError> {
    Uuid::from_slice(value).map_err(|_| AgentStoreError::CorruptRecord(field))
}

fn decode_agent_id(value: &[u8]) -> Result<AgentInstanceId, AgentStoreError> {
    Ok(AgentInstanceId::from_uuid(decode_uuid(value, "agent_id")?))
}

fn decode_update_id(value: &[u8]) -> Result<AgentWorkUpdateId, AgentStoreError> {
    Ok(AgentWorkUpdateId::from_uuid(decode_uuid(
        value,
        "agent_work_updates.update_id",
    )?))
}

fn decode_workspace_id(value: &[u8]) -> Result<WorkspaceId, AgentStoreError> {
    Ok(WorkspaceId::from_uuid(decode_uuid(value, "workspace_id")?))
}

fn decode_activity_id(value: &[u8]) -> Result<ActivityId, AgentStoreError> {
    Ok(ActivityId::from_uuid(decode_uuid(value, "activity_id")?))
}

fn decode_goal_id(value: &[u8]) -> Result<forge_domain::GoalId, AgentStoreError> {
    Ok(forge_domain::GoalId::from_uuid(decode_uuid(
        value, "goal_id",
    )?))
}

fn decode_node_id(value: &[u8]) -> Result<DagNodeId, AgentStoreError> {
    Ok(DagNodeId::from_uuid(decode_uuid(value, "dag_node_id")?))
}

const AGENT_BY_ID_QUERY: &str = "SELECT ai.agent_id, ai.workspace_id, ai.activity_id, ai.display_name, ai.declared_role, ai.transport_kind, ai.attachment_state, ai.focus_goal_id, ai.focus_goal_revision, ai.focus_dag_revision, ai.focus_node_id, ai.focus_node_revision, ai.created_at_ms, ai.updated_at_ms, ai.revision, length(ai.agent_id), length(ai.workspace_id), length(ai.activity_id), length(CAST(ai.display_name AS BLOB)), length(CAST(ai.declared_role AS BLOB)), length(ai.focus_goal_id), length(ai.focus_node_id), p.token_id, length(p.token_id) FROM agent_instances AS ai LEFT JOIN agent_transport_principals AS p ON p.agent_id = ai.agent_id AND p.workspace_id = ai.workspace_id AND p.activity_id = ai.activity_id WHERE ai.agent_id = ?1";
const AGENTS_BY_WORKSPACE_QUERY: &str = "SELECT ai.agent_id, ai.workspace_id, ai.activity_id, ai.display_name, ai.declared_role, ai.transport_kind, ai.attachment_state, ai.focus_goal_id, ai.focus_goal_revision, ai.focus_dag_revision, ai.focus_node_id, ai.focus_node_revision, ai.created_at_ms, ai.updated_at_ms, ai.revision, length(ai.agent_id), length(ai.workspace_id), length(ai.activity_id), length(CAST(ai.display_name AS BLOB)), length(CAST(ai.declared_role AS BLOB)), length(ai.focus_goal_id), length(ai.focus_node_id), p.token_id, length(p.token_id), a.activity_id, a.workspace_id, a.state, a.created_at_ms, a.updated_at_ms, a.revision, a.lease_owner_id, a.lease_until_ms, a.lease_revision, length(a.lease_owner_id) FROM agent_instances AS ai LEFT JOIN agent_transport_principals AS p ON p.agent_id = ai.agent_id AND p.workspace_id = ai.workspace_id AND p.activity_id = ai.activity_id JOIN activities AS a ON a.activity_id = ai.activity_id WHERE ai.workspace_id = ?1 AND (?2 IS NULL OR ai.activity_id = ?2) ORDER BY ai.updated_at_ms DESC, ai.agent_id DESC LIMIT ?3";
const ACTIVITY_BY_ID_QUERY: &str = "SELECT activity_id, workspace_id, state, created_at_ms, updated_at_ms, revision, lease_owner_id, lease_until_ms, lease_revision, length(lease_owner_id) FROM activities WHERE activity_id = ?1";
const FOCUS_EVENTS_QUERY: &str = "SELECT agent_id, workspace_id, activity_id, event_sequence, event_kind, focus_goal_id, length(focus_goal_id), focus_goal_revision, focus_dag_revision, focus_node_id, length(focus_node_id), focus_node_revision, observed_at_ms, length(agent_id), length(workspace_id), length(activity_id) FROM agent_focus_events WHERE agent_id = ?1 ORDER BY event_sequence DESC LIMIT ?2";
const WORK_UPDATES_QUERY: &str = "SELECT update_id, agent_id, workspace_id, activity_id, update_sequence, phase, summary, length(CAST(summary AS BLOB)), evidence_count, observed_at_ms, length(update_id), length(agent_id), length(workspace_id), length(activity_id) FROM agent_work_updates WHERE agent_id = ?1 ORDER BY update_sequence DESC LIMIT ?2";
const WORK_UPDATE_BY_ID_QUERY: &str = "SELECT update_id, agent_id, workspace_id, activity_id, update_sequence, phase, summary, length(CAST(summary AS BLOB)), evidence_count, observed_at_ms, length(update_id), length(agent_id), length(workspace_id), length(activity_id) FROM agent_work_updates WHERE update_id = ?1";
const WORK_UPDATE_EVIDENCE_QUERY: &str = "SELECT evidence_kind, evidence_id, length(evidence_id) FROM agent_work_update_evidence_refs WHERE update_id = ?1 ORDER BY evidence_kind, evidence_id";
const WORK_UPDATE_EVIDENCE_FOR_AGENT_QUERY: &str = "SELECT e.update_id, e.evidence_kind, e.evidence_id, length(e.evidence_id) FROM agent_work_update_evidence_refs AS e WHERE e.agent_id = ?1 AND e.update_id IN (SELECT update_id FROM agent_work_updates WHERE agent_id = ?1 ORDER BY update_sequence DESC LIMIT ?2) ORDER BY e.update_id, e.evidence_kind, e.evidence_id";

#[derive(Debug, Error)]
pub enum AgentStoreError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error("Agent instance identity conflicts with the existing row")]
    IdentityConflict,
    #[error("Agent {0} was not found")]
    AgentNotFound(AgentInstanceId),
    #[error("Agent {0} is detached")]
    AgentDetached(AgentInstanceId),
    #[error("Activity {0} was not found")]
    ActivityNotFound(ActivityId),
    #[error("Activity belongs to a different Workspace")]
    ActivityWorkspaceMismatch {
        expected: WorkspaceId,
        actual: WorkspaceId,
    },
    #[error("Agent Activity mismatch")]
    ActivityAgentMismatch {
        expected: ActivityId,
        actual: ActivityId,
    },
    #[error("Agent Workspace mismatch")]
    WorkspaceMismatch {
        expected: WorkspaceId,
        actual: WorkspaceId,
    },
    #[error("Agent revision {expected} is stale")]
    RevisionConflict { expected: AgentInstanceRevision },
    #[error("Agent public work sequence conflict: expected {expected}, got {actual}")]
    WorkSequenceConflict {
        expected: AgentWorkUpdateSequence,
        actual: AgentWorkUpdateSequence,
    },
    #[error("Agent transition is invalid")]
    Transition(#[source] AgentTransitionError),
    #[error("Agent focus Goal is missing")]
    FocusGoalMissing(forge_domain::GoalId),
    #[error("Agent focus Goal belongs to another Workspace")]
    FocusWorkspaceMismatch,
    #[error("Agent focus Goal revision conflicts")]
    FocusGoalRevisionConflict {
        expected: GoalRevision,
        actual: GoalRevision,
    },
    #[error("Agent focus DAG is missing")]
    FocusDagMissing(forge_domain::GoalId),
    #[error("Agent focus DAG is not the current head")]
    FocusDagNotCurrent {
        expected: DagRevisionNumber,
        actual: DagRevisionNumber,
    },
    #[error("Agent focus DAG node is missing")]
    FocusNodeMissing(DagNodeId),
    #[error("Agent focus DAG node revision conflicts")]
    FocusNodeRevisionConflict {
        expected: DagNodeRevision,
        actual: DagNodeRevision,
    },
    #[error("Agent evidence reference is missing")]
    EvidenceMissing(GoalEvidenceRef),
    #[error("Agent projection is invalid: {0}")]
    InvalidProjection(&'static str),
    #[error("Agent persisted field {field} has length {actual}, expected {expected}")]
    InvalidFieldLength {
        field: &'static str,
        actual: i64,
        expected: i64,
    },
    #[error("Agent persisted record is corrupt: {0}")]
    CorruptRecord(&'static str),
    #[error("Agent integer value overflowed")]
    IntegerOverflow,
    #[error("Agent schema object is damaged: {0}")]
    DamagedSchema(&'static str),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{WorkspaceStore, WorkspaceStoreError};
    use forge_domain::{
        ActivityId, AgentDeclaredRole, AgentDisplayName, AgentInstanceId, AgentListLimit,
        AgentTransportKind, AgentWorkPhase, AgentWorkSummary, AgentWorkUpdate, AgentWorkUpdateId,
        AgentWorkUpdateSequence, CreateActivity, DetachAgent, EstablishWorkspace, LocationId,
        RegisteredAgentInstance, SetAgentFocus, TimestampMillis, WorkspaceId, WorkspaceRevision,
        WorkspaceRoot,
    };
    use forge_workspace::WorkspaceStateLayout;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn schema_has_all_v15_objects_without_agent_rows() -> Result<(), Box<dyn std::error::Error>> {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch("PRAGMA foreign_keys = ON; CREATE TABLE workspace (workspace_id BLOB PRIMARY KEY); CREATE TABLE activities (activity_id BLOB PRIMARY KEY, workspace_id BLOB); CREATE TABLE goals (goal_id BLOB PRIMARY KEY); CREATE TABLE goal_dag_revisions (goal_id BLOB, dag_revision INTEGER, PRIMARY KEY(goal_id, dag_revision)); CREATE TABLE goal_dag_nodes (goal_id BLOB, dag_revision INTEGER, node_id BLOB, PRIMARY KEY(goal_id, dag_revision, node_id));")?;
        create_schema(&connection)?;
        validate_schema(&connection)?;
        let count: i64 =
            connection.query_row("SELECT count(*) FROM agent_instances", [], |row| row.get(0))?;
        assert_eq!(count, 0);
        Ok(())
    }

    #[test]
    fn focus_event_kind_encoding_is_stable() {
        assert_eq!(encode_focus_event_kind(AgentFocusEventKind::Attached), 0);
        assert_eq!(encode_focus_event_kind(AgentFocusEventKind::Changed), 1);
        assert_eq!(encode_focus_event_kind(AgentFocusEventKind::Detached), 2);
    }

    fn fixture_root(label: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path = std::env::temp_dir().join(format!("forge-agent-{label}-{nonce}"));
        fs::create_dir_all(&path)?;
        Ok(path)
    }

    fn agent(
        value: u128,
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        observed_at: i64,
    ) -> Result<RegisteredAgentInstance, Box<dyn std::error::Error>> {
        Ok(RegisteredAgentInstance::create(
            AgentInstanceId::from_uuid(Uuid::from_u128(value)),
            workspace_id,
            activity_id,
            AgentDisplayName::new(format!("Agent {value}"))?,
            AgentDeclaredRole::new("planner".to_owned())?,
            AgentTransportKind::Mcp,
            TimestampMillis::new(observed_at)?,
        ))
    }

    fn agent_with_principal(
        value: u128,
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        token_id: McpTokenId,
        observed_at: i64,
    ) -> Result<RegisteredAgentInstance, Box<dyn std::error::Error>> {
        Ok(RegisteredAgentInstance::create_with_principal(
            AgentInstanceId::from_uuid(Uuid::from_u128(value)),
            workspace_id,
            activity_id,
            AgentDisplayName::new(format!("Agent {value}"))?,
            AgentDeclaredRole::new("planner".to_owned())?,
            AgentTransportKind::StreamableHttp,
            Some(token_id),
            TimestampMillis::new(observed_at)?,
        ))
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn attachment_context_is_bounded_ordered_and_restartable()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = fixture_root("lifecycle")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(0xA001));
        let location_id = LocationId::from_uuid(Uuid::from_u128(0xA002));
        let fingerprint = layout.root_fingerprint()?;
        let command = EstablishWorkspace::new(
            workspace_id,
            location_id,
            WorkspaceRoot::from_canonical(layout.workspace_root().to_path_buf())?,
            fingerprint,
            TimestampMillis::new(1)?,
        );
        let activity_id = ActivityId::from_uuid(Uuid::from_u128(0xA003));
        let mut store = WorkspaceStore::open(&layout, &command)?;
        let _activity = store.create_activity(&CreateActivity::new(
            activity_id,
            workspace_id,
            WorkspaceRevision::INITIAL,
            TimestampMillis::new(2)?,
        ))?;
        let token_id = McpTokenId::from_uuid(Uuid::from_u128(0xA012));
        let first = agent_with_principal(0xA010, workspace_id, activity_id, token_id, 3)?;
        let second = agent(0xA011, workspace_id, activity_id, 4)?;
        assert_eq!(store.attach_agent(&first)?, first);
        assert_eq!(store.attach_agent(&second)?, second);
        assert_eq!(store.attach_agent(&first)?, first);
        let conflicting_principal = agent_with_principal(
            0xA010,
            workspace_id,
            activity_id,
            McpTokenId::from_uuid(Uuid::from_u128(0xA013)),
            3,
        )?;
        assert!(matches!(
            store.attach_agent(&conflicting_principal),
            Err(WorkspaceStoreError::Agent(
                AgentStoreError::IdentityConflict
            ))
        ));

        let listed = store.list_agent_attachments(
            None,
            TimestampMillis::new(5)?,
            AgentListLimit::DEFAULT,
        )?;
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].agent().id(), second.id());
        assert_eq!(listed[1].agent().id(), first.id());
        assert_eq!(listed[1].agent().transport_principal(), Some(token_id));
        let filtered = store.list_agent_attachments(
            Some(activity_id),
            TimestampMillis::new(5)?,
            AgentListLimit::DEFAULT,
        )?;
        assert_eq!(filtered.len(), 2);

        let summary = AgentWorkSummary::new("Published bounded progress".to_owned())?;
        let update = AgentWorkUpdate::new(
            AgentWorkUpdateId::from_uuid(Uuid::from_u128(0xA020)),
            first.id(),
            workspace_id,
            activity_id,
            AgentWorkUpdateSequence::INITIAL,
            AgentWorkPhase::Planning,
            summary,
            Vec::new(),
            TimestampMillis::new(6)?,
        )?;
        assert_eq!(store.publish_agent_work_update(&update)?, update);
        let detached = store.detach_agent(&DetachAgent::new(
            first.id(),
            activity_id,
            first.revision(),
            TimestampMillis::new(7)?,
        ))?;
        assert!(detached.attachment_state().is_detached());
        let context = store
            .get_agent_context(
                first.id(),
                activity_id,
                TimestampMillis::new(8)?,
                AgentListLimit::DEFAULT,
                AgentListLimit::DEFAULT,
            )?
            .ok_or("agent context missing")?;
        assert_eq!(context.focus_events().len(), 2);
        assert_eq!(context.work_updates(), std::slice::from_ref(&update));
        assert!(
            context
                .attachment()
                .agent()
                .attachment_state()
                .is_detached()
        );
        drop(store);

        let existing =
            WorkspaceStateLayout::inspect_existing(&root)?.ok_or("existing layout missing")?;
        let reopened = WorkspaceStore::open_existing(&existing)?;
        assert_eq!(reopened.get_agent(first.id())?, Some(detached));
        assert_eq!(
            reopened
                .get_agent(first.id())?
                .ok_or("reopened principal Agent missing")?
                .transport_principal(),
            Some(token_id)
        );
        assert_eq!(
            reopened
                .get_agent_context(
                    first.id(),
                    activity_id,
                    TimestampMillis::new(9)?,
                    AgentListLimit::DEFAULT,
                    AgentListLimit::DEFAULT,
                )?
                .ok_or("reopened context missing")?
                .work_updates(),
            &[update]
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn focus_rejects_missing_goal_without_mutating_agent() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = fixture_root("focus")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(0xA101));
        let location_id = LocationId::from_uuid(Uuid::from_u128(0xA102));
        let command = EstablishWorkspace::new(
            workspace_id,
            location_id,
            WorkspaceRoot::from_canonical(layout.workspace_root().to_path_buf())?,
            layout.root_fingerprint()?,
            TimestampMillis::new(1)?,
        );
        let activity_id = ActivityId::from_uuid(Uuid::from_u128(0xA103));
        let mut store = WorkspaceStore::open(&layout, &command)?;
        store.create_activity(&CreateActivity::new(
            activity_id,
            workspace_id,
            WorkspaceRevision::INITIAL,
            TimestampMillis::new(2)?,
        ))?;
        let instance = agent(0xA110, workspace_id, activity_id, 3)?;
        let _ = store.attach_agent(&instance)?;
        let focus = AgentFocus::new(
            Some(GoalAttribution::new(
                forge_domain::GoalId::from_uuid(Uuid::from_u128(0xA111)),
                forge_domain::GoalRevision::INITIAL,
            )),
            Some(DagRevisionNumber::INITIAL),
            None,
        )?;
        let Err(error) = store.set_agent_focus(&SetAgentFocus::new(
            instance.id(),
            activity_id,
            instance.revision(),
            focus,
            TimestampMillis::new(4)?,
        )) else {
            return Err("missing Goal unexpectedly accepted focus".into());
        };
        assert!(matches!(
            error,
            crate::WorkspaceStoreError::Agent(AgentStoreError::FocusGoalMissing(_))
        ));
        assert_eq!(store.get_agent(instance.id())?, Some(instance));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn v14_to_current_migration_adds_empty_agent_authority_without_rows()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = fixture_root("migration")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(0xA201));
        let location_id = LocationId::from_uuid(Uuid::from_u128(0xA202));
        let command = EstablishWorkspace::new(
            workspace_id,
            location_id,
            WorkspaceRoot::from_canonical(layout.workspace_root().to_path_buf())?,
            layout.root_fingerprint()?,
            TimestampMillis::new(1)?,
        );
        let store = WorkspaceStore::open(&layout, &command)?;
        drop(store);
        let database = layout.database_path();
        let connection = Connection::open(database)?;
        connection.execute_batch(
            "PRAGMA wal_checkpoint(TRUNCATE);
             PRAGMA journal_mode = DELETE;
             DROP TABLE agent_work_update_evidence_refs;
             DROP TABLE agent_work_updates;
             DROP TABLE agent_focus_events;
             DROP TABLE agent_instances;
             PRAGMA user_version = 14;",
        )?;
        drop(connection);
        let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
        let migrated = WorkspaceStore::open_existing(&existing)?;
        assert_eq!(migrated.health()?.schema_version(), 16);
        drop(migrated);
        let reopened_connection = Connection::open(existing.database_path())?;
        let agent_count: i64 =
            reopened_connection
                .query_row("SELECT count(*) FROM agent_instances", [], |row| row.get(0))?;
        assert_eq!(agent_count, 0);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn corrupted_agent_metadata_fails_closed_on_projection_read()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = fixture_root("corruption")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(0xA301));
        let location_id = LocationId::from_uuid(Uuid::from_u128(0xA302));
        let command = EstablishWorkspace::new(
            workspace_id,
            location_id,
            WorkspaceRoot::from_canonical(layout.workspace_root().to_path_buf())?,
            layout.root_fingerprint()?,
            TimestampMillis::new(1)?,
        );
        let activity_id = ActivityId::from_uuid(Uuid::from_u128(0xA303));
        let mut store = WorkspaceStore::open(&layout, &command)?;
        store.create_activity(&CreateActivity::new(
            activity_id,
            workspace_id,
            WorkspaceRevision::INITIAL,
            TimestampMillis::new(2)?,
        ))?;
        let instance = agent(0xA310, workspace_id, activity_id, 3)?;
        let _ = store.attach_agent(&instance)?;
        drop(store);
        let connection = Connection::open(layout.database_path())?;
        connection.execute_batch(
            "PRAGMA ignore_check_constraints = ON;
             UPDATE agent_instances SET display_name = '';
             PRAGMA ignore_check_constraints = OFF;",
        )?;
        drop(connection);
        let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
        let reopened = WorkspaceStore::open_existing(&existing)?;
        assert!(matches!(
            reopened.get_agent(instance.id()),
            Err(WorkspaceStoreError::Agent(
                AgentStoreError::InvalidFieldLength { .. } | AgentStoreError::CorruptRecord(_),
            ))
        ));
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
