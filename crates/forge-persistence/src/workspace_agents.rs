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
    AgentFocusNode, AgentInstanceId, AgentInstanceRevision, AgentSessionId, AgentTransitionError,
    AgentTransportKind, AgentWorkPhase, AgentWorkSummary, AgentWorkUpdate, AgentWorkUpdateId,
    AgentWorkUpdateSequence, AuthenticatedPrincipal, BindExistingAgentSession, DagNodeId,
    DagNodeRevision, DagRevisionNumber, GoalAttribution, GoalEvidenceRef, GoalRevision,
    RegisteredActivity, RegisteredAgentInstance, RuntimeInstanceId, TimestampMillis, WorkspaceId,
};
use rusqlite::{Connection, OptionalExtension, Row, TransactionBehavior, params};
use thiserror::Error;
use uuid::Uuid;

use crate::workspace_agent_events::AgentEventStoreError;
const ID_BYTES: usize = 16;
const ID_BYTES_I64: i64 = 16;
const MAX_TEXT_BYTES: usize = forge_domain::MAX_AGENT_WORK_SUMMARY_BYTES;
const MAX_METADATA_BYTES: usize = forge_domain::MAX_AGENT_ROLE_BYTES;

/// Canonical Agent table/index DDL. All creation and validation paths use this
/// single authority.
const EXPECTED_AGENT_INSTANCES_TABLE_SQL: &str = "CREATE TABLE agent_instances (agent_id BLOB PRIMARY KEY NOT NULL CHECK(length(agent_id) = 16), workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16), activity_id BLOB NOT NULL REFERENCES activities(activity_id) CHECK(length(activity_id) = 16), display_name TEXT NOT NULL CHECK(length(CAST(display_name AS BLOB)) BETWEEN 1 AND 128), declared_role TEXT NOT NULL CHECK(length(CAST(declared_role AS BLOB)) BETWEEN 1 AND 128), transport_kind INTEGER NOT NULL CHECK(transport_kind IN (0, 1, 2, 3)), principal_kind INTEGER NOT NULL CHECK(principal_kind IN (0, 1, 2)), principal_id BLOB CHECK(principal_id IS NULL OR length(principal_id) = 16), attachment_state INTEGER NOT NULL CHECK(attachment_state IN (0, 1)), focus_goal_id BLOB CHECK(focus_goal_id IS NULL OR length(focus_goal_id) = 16), focus_goal_revision INTEGER CHECK(focus_goal_revision IS NULL OR focus_goal_revision >= 1), focus_dag_revision INTEGER CHECK(focus_dag_revision IS NULL OR focus_dag_revision >= 1), focus_node_id BLOB CHECK(focus_node_id IS NULL OR length(focus_node_id) = 16), focus_node_revision INTEGER CHECK(focus_node_revision IS NULL OR focus_node_revision >= 1), created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0), updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= created_at_ms), revision INTEGER NOT NULL CHECK(revision >= 1), session_id BLOB CHECK(session_id IS NULL OR length(session_id) = 16), UNIQUE(agent_id, workspace_id, activity_id), FOREIGN KEY(focus_goal_id) REFERENCES goals(goal_id), FOREIGN KEY(focus_goal_id, focus_dag_revision) REFERENCES goal_dag_revisions(goal_id, dag_revision), FOREIGN KEY(focus_goal_id, focus_dag_revision, focus_node_id) REFERENCES goal_dag_nodes(goal_id, dag_revision, node_id), CHECK((principal_kind = 0 AND principal_id IS NULL) OR (principal_kind IN (1, 2) AND principal_id IS NOT NULL)), CHECK((focus_goal_id IS NULL AND focus_goal_revision IS NULL AND focus_dag_revision IS NULL AND focus_node_id IS NULL AND focus_node_revision IS NULL) OR (focus_goal_id IS NOT NULL AND focus_goal_revision IS NOT NULL AND focus_dag_revision IS NOT NULL AND ((focus_node_id IS NULL AND focus_node_revision IS NULL) OR (focus_node_id IS NOT NULL AND focus_node_revision IS NOT NULL)))), CHECK((attachment_state = 1 AND focus_goal_id IS NULL AND focus_goal_revision IS NULL AND focus_dag_revision IS NULL AND focus_node_id IS NULL AND focus_node_revision IS NULL) OR attachment_state = 0))";
const EXPECTED_AGENT_FOCUS_EVENTS_TABLE_SQL: &str = "CREATE TABLE agent_focus_events (agent_id BLOB NOT NULL CHECK(length(agent_id) = 16), workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16), activity_id BLOB NOT NULL REFERENCES activities(activity_id) CHECK(length(activity_id) = 16), event_sequence INTEGER NOT NULL CHECK(event_sequence >= 1), event_kind INTEGER NOT NULL CHECK(event_kind IN (0, 1, 2)), focus_goal_id BLOB CHECK(focus_goal_id IS NULL OR length(focus_goal_id) = 16), focus_goal_revision INTEGER CHECK(focus_goal_revision IS NULL OR focus_goal_revision >= 1), focus_dag_revision INTEGER CHECK(focus_dag_revision IS NULL OR focus_dag_revision >= 1), focus_node_id BLOB CHECK(focus_node_id IS NULL OR length(focus_node_id) = 16), focus_node_revision INTEGER CHECK(focus_node_revision IS NULL OR focus_node_revision >= 1), observed_at_ms INTEGER NOT NULL CHECK(observed_at_ms >= 0), PRIMARY KEY(agent_id, event_sequence), FOREIGN KEY(agent_id, workspace_id, activity_id) REFERENCES agent_instances(agent_id, workspace_id, activity_id), FOREIGN KEY(focus_goal_id) REFERENCES goals(goal_id), FOREIGN KEY(focus_goal_id, focus_dag_revision) REFERENCES goal_dag_revisions(goal_id, dag_revision), FOREIGN KEY(focus_goal_id, focus_dag_revision, focus_node_id) REFERENCES goal_dag_nodes(goal_id, dag_revision, node_id), CHECK((focus_goal_id IS NULL AND focus_goal_revision IS NULL AND focus_dag_revision IS NULL AND focus_node_id IS NULL AND focus_node_revision IS NULL) OR (focus_goal_id IS NOT NULL AND focus_goal_revision IS NOT NULL AND focus_dag_revision IS NOT NULL AND ((focus_node_id IS NULL AND focus_node_revision IS NULL) OR (focus_node_id IS NOT NULL AND focus_node_revision IS NOT NULL)))), CHECK((event_kind = 2 AND focus_goal_id IS NULL AND focus_goal_revision IS NULL AND focus_dag_revision IS NULL AND focus_node_id IS NULL AND focus_node_revision IS NULL) OR event_kind IN (0, 1)))";
const EXPECTED_AGENT_WORK_UPDATES_TABLE_SQL: &str = "CREATE TABLE agent_work_updates (update_id BLOB PRIMARY KEY NOT NULL CHECK(length(update_id) = 16), agent_id BLOB NOT NULL CHECK(length(agent_id) = 16), workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16), activity_id BLOB NOT NULL REFERENCES activities(activity_id) CHECK(length(activity_id) = 16), update_sequence INTEGER NOT NULL CHECK(update_sequence >= 1), phase INTEGER NOT NULL CHECK(phase IN (0, 1, 2, 3, 4, 5, 6)), summary TEXT NOT NULL CHECK(length(CAST(summary AS BLOB)) BETWEEN 1 AND 2048), evidence_count INTEGER NOT NULL CHECK(evidence_count BETWEEN 0 AND 32), observed_at_ms INTEGER NOT NULL CHECK(observed_at_ms >= 0), UNIQUE(agent_id, update_sequence), UNIQUE(update_id, agent_id, workspace_id), FOREIGN KEY(agent_id, workspace_id, activity_id) REFERENCES agent_instances(agent_id, workspace_id, activity_id))";
const EXPECTED_AGENT_WORK_EVIDENCE_TABLE_SQL: &str = "CREATE TABLE agent_work_update_evidence_refs (update_id BLOB NOT NULL CHECK(length(update_id) = 16), agent_id BLOB NOT NULL CHECK(length(agent_id) = 16), workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16), evidence_kind INTEGER NOT NULL CHECK(evidence_kind IN (0, 1, 2, 3)), evidence_id BLOB NOT NULL CHECK(length(evidence_id) = 16), PRIMARY KEY(update_id, evidence_kind, evidence_id), FOREIGN KEY(update_id, agent_id, workspace_id) REFERENCES agent_work_updates(update_id, agent_id, workspace_id))";
const EXPECTED_AGENT_INSTANCES_INDEX_SQL: &str = "CREATE INDEX agent_instances_workspace_activity_updated_idx ON agent_instances(workspace_id, activity_id, updated_at_ms DESC, agent_id DESC)";
const EXPECTED_AGENT_INSTANCES_SESSION_INDEX_SQL: &str = "CREATE UNIQUE INDEX agent_instances_activity_session_uidx ON agent_instances(activity_id, session_id) WHERE session_id IS NOT NULL";
const EXPECTED_AGENT_FOCUS_EVENTS_INDEX_SQL: &str = "CREATE INDEX agent_focus_events_agent_sequence_idx ON agent_focus_events(agent_id, event_sequence DESC)";
const EXPECTED_AGENT_WORK_UPDATES_INDEX_SQL: &str = "CREATE INDEX agent_work_updates_agent_sequence_idx ON agent_work_updates(agent_id, update_sequence DESC)";
const AGENT_CORE_OBJECTS: [(&str, &str, &str); 8] = [
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
        "agent_instances_activity_session_uidx",
        EXPECTED_AGENT_INSTANCES_SESSION_INDEX_SQL,
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

const OBJECTS: [(&str, &str, &str); 8] = AGENT_CORE_OBJECTS;

pub(crate) fn create_schema(connection: &Connection) -> Result<(), AgentStoreError> {
    for (_, _, sql) in AGENT_CORE_OBJECTS {
        connection.execute_batch(sql)?;
    }
    Ok(())
}

pub(crate) fn schema_objects() -> [(&'static str, &'static str); 8] {
    [
        ("table", "agent_instances"),
        ("table", "agent_focus_events"),
        ("table", "agent_work_updates"),
        ("table", "agent_work_update_evidence_refs"),
        ("index", "agent_instances_workspace_activity_updated_idx"),
        ("index", "agent_instances_activity_session_uidx"),
        ("index", "agent_focus_events_agent_sequence_idx"),
        ("index", "agent_work_updates_agent_sequence_idx"),
    ]
}

pub(crate) fn schema_objects_v29() -> [(&'static str, &'static str); 7] {
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

pub(crate) fn validate_schema(connection: &Connection) -> Result<(), AgentStoreError> {
    validate_schema_objects(connection, &OBJECTS)?;
    validate_schema_columns(connection, true)?;
    validate_schema_foreign_keys(connection)
}

/// Validate the previous schema without pretending that its nullable session
/// binding already exists. This is used only as the fail-closed precondition
/// for the v29 -> v30 migration.
pub(crate) fn validate_schema_v29(connection: &Connection) -> Result<(), AgentStoreError> {
    let expected_agent_table = EXPECTED_AGENT_INSTANCES_TABLE_SQL.replace(
        ", session_id BLOB CHECK(session_id IS NULL OR length(session_id) = 16)",
        "",
    );
    let actual_agent_table: Option<String> = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = 'agent_instances'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if actual_agent_table.as_deref().map(normalize_sql)
        != Some(normalize_sql(&expected_agent_table))
    {
        return Err(AgentStoreError::DamagedSchema("agent_instances"));
    }
    let objects = [
        OBJECTS[1], OBJECTS[2], OBJECTS[3], OBJECTS[4], OBJECTS[6], OBJECTS[7],
    ];
    validate_schema_objects(connection, &objects)?;
    validate_schema_columns(connection, false)?;
    validate_schema_foreign_keys(connection)
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
    include_session_id: bool,
) -> Result<(), AgentStoreError> {
    let agent_columns_v29 = [
        ("agent_id", "BLOB", 1, 1),
        ("workspace_id", "BLOB", 1, 0),
        ("activity_id", "BLOB", 1, 0),
        ("display_name", "TEXT", 1, 0),
        ("declared_role", "TEXT", 1, 0),
        ("transport_kind", "INTEGER", 1, 0),
        ("principal_kind", "INTEGER", 1, 0),
        ("principal_id", "BLOB", 0, 0),
        ("attachment_state", "INTEGER", 1, 0),
        ("focus_goal_id", "BLOB", 0, 0),
        ("focus_goal_revision", "INTEGER", 0, 0),
        ("focus_dag_revision", "INTEGER", 0, 0),
        ("focus_node_id", "BLOB", 0, 0),
        ("focus_node_revision", "INTEGER", 0, 0),
        ("created_at_ms", "INTEGER", 1, 0),
        ("updated_at_ms", "INTEGER", 1, 0),
        ("revision", "INTEGER", 1, 0),
    ];
    let agent_columns_v30 = [
        ("agent_id", "BLOB", 1, 1),
        ("workspace_id", "BLOB", 1, 0),
        ("activity_id", "BLOB", 1, 0),
        ("display_name", "TEXT", 1, 0),
        ("declared_role", "TEXT", 1, 0),
        ("transport_kind", "INTEGER", 1, 0),
        ("principal_kind", "INTEGER", 1, 0),
        ("principal_id", "BLOB", 0, 0),
        ("attachment_state", "INTEGER", 1, 0),
        ("focus_goal_id", "BLOB", 0, 0),
        ("focus_goal_revision", "INTEGER", 0, 0),
        ("focus_dag_revision", "INTEGER", 0, 0),
        ("focus_node_id", "BLOB", 0, 0),
        ("focus_node_revision", "INTEGER", 0, 0),
        ("created_at_ms", "INTEGER", 1, 0),
        ("updated_at_ms", "INTEGER", 1, 0),
        ("revision", "INTEGER", 1, 0),
        ("session_id", "BLOB", 0, 0),
    ];
    validate_columns(
        connection,
        "agent_instances",
        if include_session_id {
            &agent_columns_v30
        } else {
            &agent_columns_v29
        },
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
    Ok(())
}

fn validate_schema_foreign_keys(connection: &Connection) -> Result<(), AgentStoreError> {
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

/// Read the complete Agent census for one Activity in stable Agent-ID order.
/// The recovery owner uses a limit of 257 so the 256-row contract can reject
/// overflow without materializing an unbounded result.
pub(crate) fn list_for_activity_in_transaction(
    connection: &Connection,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    limit: u32,
) -> Result<Vec<RegisteredAgentInstance>, AgentStoreError> {
    let mut statement = connection.prepare(
        "SELECT ai.agent_id, ai.workspace_id, ai.activity_id, ai.display_name,
                ai.declared_role, ai.transport_kind, ai.principal_kind,
                ai.principal_id, ai.attachment_state, ai.focus_goal_id,
                ai.focus_goal_revision, ai.focus_dag_revision, ai.focus_node_id,
                ai.focus_node_revision, ai.created_at_ms, ai.updated_at_ms,
                ai.revision, length(ai.agent_id), length(ai.workspace_id),
                length(ai.activity_id), length(CAST(ai.display_name AS BLOB)),
                length(CAST(ai.declared_role AS BLOB)), length(ai.principal_id),
                length(ai.focus_goal_id), length(ai.focus_node_id), ai.session_id
         FROM agent_instances AS ai
         WHERE ai.workspace_id = ?1 AND ai.activity_id = ?2
         ORDER BY ai.agent_id ASC
         LIMIT ?3",
    )?;
    let mut rows = statement.query(params![
        workspace_id.into_uuid().as_bytes(),
        activity_id.into_uuid().as_bytes(),
        limit,
    ])?;
    let mut agents = Vec::new();
    while let Some(row) = rows.next()? {
        agents.push(decode_agent(row)?);
    }
    Ok(agents)
}

/// Read the durable Agent participant rows for a frozen source in exact
/// `agent_id` BLOB order.  This helper does not open a transaction; the export
/// owner supplies one snapshot and owns its commit/rollback boundary.
pub(crate) fn export_participants(
    connection: &Connection,
    workspace_id: WorkspaceId,
    after: Option<AgentInstanceId>,
    limit: u32,
) -> Result<Vec<RegisteredAgentInstance>, AgentStoreError> {
    let after_bytes = after.map(|value| value.into_uuid().into_bytes().to_vec());
    let mut statement = connection.prepare(AGENTS_EXPORT_QUERY)?;
    let mut rows = statement.query(params![
        workspace_id.into_uuid().as_bytes(),
        after_bytes,
        limit,
    ])?;
    let mut participants = Vec::new();
    while let Some(row) = rows.next()? {
        let participant = decode_agent(row)?;
        if participant.workspace_id() != workspace_id {
            return Err(AgentStoreError::WorkspaceMismatch {
                expected: workspace_id,
                actual: participant.workspace_id(),
            });
        }
        participants.push(participant);
    }
    Ok(participants)
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
        let agent = decode_agent_at(row, 35)?;
        let activity = decode_activity_at(row, 25)?;
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

/// Validate one exact session-bound attached Agent inside the caller's
/// transaction. This is the shared admission fence for Coordinator, writer,
/// execution, and DAG consumers; it performs no catalog I/O or recency check.
pub(crate) fn ensure_bound_attached_agent(
    connection: &Connection,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    agent_id: AgentInstanceId,
    session_id: AgentSessionId,
    principal: AuthenticatedPrincipal,
    expected_revision: Option<AgentInstanceRevision>,
) -> Result<RegisteredAgentInstance, AgentStoreError> {
    let agent =
        agent_by_id(connection, agent_id)?.ok_or(AgentStoreError::AgentNotFound(agent_id))?;
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
    if agent.session_id() != Some(session_id) {
        return Err(AgentStoreError::SessionBindingConflict);
    }
    if agent.principal() != principal {
        return Err(AgentStoreError::PrincipalConflict);
    }
    if agent.attachment_state() != AgentAttachmentState::Attached {
        return Err(AgentStoreError::AgentDetached(agent_id));
    }
    if let Some(expected_revision) = expected_revision
        && agent.revision() != expected_revision
    {
        return Err(AgentStoreError::RevisionConflict {
            expected: expected_revision,
        });
    }
    Ok(agent)
}

/// Reconcile only the Forge-owned effect-session binding for one unresolved
/// legacy Agent. The caller must establish migration/delegation authority
/// before entering this helper. No presence, membership event, inbox, focus,
/// Coordinator, or public-work evidence is written here.
pub(crate) fn reconcile_session_in_transaction(
    transaction: &rusqlite::Transaction<'_>,
    command: BindExistingAgentSession,
) -> Result<RegisteredAgentInstance, AgentStoreError> {
    ensure_workspace(transaction, command.workspace_id())?;
    ensure_open_activity(transaction, command.workspace_id(), command.activity_id())?;
    let current = agent_by_id(transaction, command.agent_id())?
        .ok_or(AgentStoreError::AgentNotFound(command.agent_id()))?;
    if current.workspace_id() != command.workspace_id() {
        return Err(AgentStoreError::WorkspaceMismatch {
            expected: command.workspace_id(),
            actual: current.workspace_id(),
        });
    }
    if current.activity_id() != command.activity_id() {
        return Err(AgentStoreError::ActivityAgentMismatch {
            expected: command.activity_id(),
            actual: current.activity_id(),
        });
    }
    if current.principal() != command.principal() {
        return Err(AgentStoreError::PrincipalConflict);
    }
    if agent_by_activity_session(transaction, command.activity_id(), command.session_id())?
        .is_some()
    {
        return Err(AgentStoreError::SessionAttachmentConflict);
    }
    let updated = current
        .bind_session(
            command.expected_agent_revision(),
            command.session_id(),
            command.observed_at(),
        )
        .map_err(AgentStoreError::Transition)?;
    update_agent(transaction, &current, &updated)?;
    Ok(updated)
}

fn agent_by_activity_session(
    connection: &Connection,
    activity_id: ActivityId,
    session_id: AgentSessionId,
) -> Result<Option<RegisteredAgentInstance>, AgentStoreError> {
    let mut statement = connection.prepare(
        "SELECT ai.agent_id, ai.workspace_id, ai.activity_id, ai.display_name, ai.declared_role, ai.transport_kind, ai.principal_kind, ai.principal_id, ai.attachment_state, ai.focus_goal_id, ai.focus_goal_revision, ai.focus_dag_revision, ai.focus_node_id, ai.focus_node_revision, ai.created_at_ms, ai.updated_at_ms, ai.revision, length(ai.agent_id), length(ai.workspace_id), length(ai.activity_id), length(CAST(ai.display_name AS BLOB)), length(CAST(ai.declared_role AS BLOB)), length(ai.principal_id), length(ai.focus_goal_id), length(ai.focus_node_id), ai.session_id FROM agent_instances AS ai WHERE ai.activity_id = ?1 AND ai.session_id = ?2",
    )?;
    let mut rows = statement.query(params![
        activity_id.into_uuid().as_bytes(),
        session_id.into_uuid().as_bytes(),
    ])?;
    let Some(row) = rows.next()? else {
        return Ok(None);
    };
    decode_agent_at(row, 25).map(Some)
}

pub(crate) fn set_focus_in_transaction(
    transaction: &rusqlite::Transaction<'_>,
    command: &forge_domain::SetAgentFocus,
) -> Result<RegisteredAgentInstance, AgentStoreError> {
    let current = agent_by_id(transaction, command.agent_id())?
        .ok_or(AgentStoreError::AgentNotFound(command.agent_id()))?;
    if current.activity_id() != command.activity_id() {
        return Err(AgentStoreError::ActivityAgentMismatch {
            expected: command.activity_id(),
            actual: current.activity_id(),
        });
    }
    if current.session_id().is_none() {
        return Err(AgentStoreError::UnresolvedLegacy(current.id()));
    }
    ensure_focus_is_current(transaction, current.workspace_id(), command.focus())?;
    crate::workspace_work_cuts::guards::ensure_focus_open(
        transaction,
        current.workspace_id(),
        current.id(),
        current.focus(),
        command.focus(),
    )?;
    let updated = current
        .set_focus(
            command.expected_revision(),
            command.focus(),
            command.observed_at(),
        )
        .map_err(AgentStoreError::Transition)?;
    update_agent(transaction, &current, &updated)?;
    insert_focus_event(
        transaction,
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
    Ok(updated)
}

/// Detach an already validated bound Agent inside a caller-owned transaction.
/// This is the departure-reconciliation seam: it writes the Agent row and its
/// terminal `Detached` focus fact only. Membership `Left` events, presence,
/// and inbox receipts are Orchestration-owned participation effects and are
/// never written here.
pub(crate) fn detach_in_transaction(
    transaction: &rusqlite::Transaction<'_>,
    current: &RegisteredAgentInstance,
    observed_at: TimestampMillis,
) -> Result<RegisteredAgentInstance, AgentStoreError> {
    if current.session_id().is_none() {
        return Err(AgentStoreError::UnresolvedLegacy(current.id()));
    }
    let updated = current
        .detach(current.revision(), observed_at)
        .map_err(AgentStoreError::Transition)?;
    update_agent(transaction, current, &updated)?;
    insert_focus_event(
        transaction,
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
    Ok(updated)
}

pub(crate) fn publish_work_update(
    connection: &mut Connection,
    update: &AgentWorkUpdate,
    session_id: AgentSessionId,
    principal: AuthenticatedPrincipal,
    admitted_at: TimestampMillis,
) -> Result<AgentWorkUpdate, AgentStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let result = publish_work_update_in_transaction_bound(
        &transaction,
        update,
        session_id,
        principal,
        admitted_at,
    )?;
    transaction.commit()?;
    Ok(result)
}

pub(crate) fn publish_work_update_in_transaction(
    transaction: &rusqlite::Transaction<'_>,
    update: &AgentWorkUpdate,
    admitted_at: TimestampMillis,
) -> Result<AgentWorkUpdate, AgentStoreError> {
    let agent = agent_by_id(transaction, update.agent_id())?
        .ok_or(AgentStoreError::AgentNotFound(update.agent_id()))?;
    let session_id = agent
        .session_id()
        .ok_or(AgentStoreError::UnresolvedLegacy(agent.id()))?;
    publish_work_update_in_transaction_bound(
        transaction,
        update,
        session_id,
        agent.principal(),
        admitted_at,
    )
}

pub(crate) fn publish_work_update_in_transaction_bound(
    transaction: &rusqlite::Transaction<'_>,
    update: &AgentWorkUpdate,
    session_id: AgentSessionId,
    principal: AuthenticatedPrincipal,
    admitted_at: TimestampMillis,
) -> Result<AgentWorkUpdate, AgentStoreError> {
    let current = ensure_bound_attached_agent(
        transaction,
        update.workspace_id(),
        update.activity_id(),
        update.agent_id(),
        session_id,
        principal,
        None,
    )?;
    if current.attachment_state().is_detached() {
        return Err(AgentStoreError::AgentDetached(update.agent_id()));
    }
    ensure_live_activity(
        transaction,
        update.workspace_id(),
        update.activity_id(),
        admitted_at,
    )?;
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

fn ensure_live_activity(
    connection: &Connection,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    admitted_at: TimestampMillis,
) -> Result<(), AgentStoreError> {
    use crate::workspace_coordinators::CoordinatorStoreError;

    match crate::workspace_coordinators::ensure_live_activity_in_transaction(
        connection,
        activity_id,
        workspace_id,
        admitted_at,
    ) {
        Ok(()) => Ok(()),
        Err(CoordinatorStoreError::ActivityNotFound(activity_id)) => {
            Err(AgentStoreError::ActivityNotFound(activity_id))
        }
        Err(CoordinatorStoreError::ActivityNotLive(activity_id)) => {
            Err(AgentStoreError::ActivityNotLive(activity_id))
        }
        Err(CoordinatorStoreError::ActivityLeaseNotLive(activity_id)) => {
            Err(AgentStoreError::ActivityLeaseNotLive(activity_id))
        }
        Err(CoordinatorStoreError::ActivityWorkspaceMismatch) => {
            Err(AgentStoreError::CorruptRecord("activities.workspace_id"))
        }
        Err(CoordinatorStoreError::CorruptRecord(field)) => {
            Err(AgentStoreError::CorruptRecord(field))
        }
        Err(CoordinatorStoreError::Sqlite(error)) => Err(AgentStoreError::from(error)),
        Err(_) => Err(AgentStoreError::CorruptRecord("activities.liveness")),
    }
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

fn ensure_open_activity(
    connection: &Connection,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
) -> Result<(), AgentStoreError> {
    let actual = connection
        .query_row(
            "SELECT workspace_id, state FROM activities WHERE activity_id = ?1",
            params![activity_id.into_uuid().as_bytes()],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()?;
    let Some((actual, state)) = actual else {
        return Err(AgentStoreError::ActivityNotFound(activity_id));
    };
    let actual = decode_workspace_id(&actual)?;
    if actual != workspace_id {
        return Err(AgentStoreError::ActivityWorkspaceMismatch {
            expected: workspace_id,
            actual,
        });
    }
    if state != 1 {
        return Err(AgentStoreError::InvalidProjection(
            "terminal Activity cannot accept Agent attachment",
        ));
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

/// Called only inside the activation transaction after its immutable receipt
/// has been inserted. The receipt and source delegation authorize this exact
/// initial work binding; neither legacy attachment nor operational membership
/// is created by this helper.
pub(crate) fn insert_reserved_binding(
    connection: &Connection,
    agent: &RegisteredAgentInstance,
) -> Result<(), AgentStoreError> {
    if connection.is_autocommit()
        || agent.attachment_state() != AgentAttachmentState::Attached
        || !agent.focus().is_unfocused()
        || agent.revision() != AgentInstanceRevision::INITIAL
        || agent.updated_at() != agent.created_at()
    {
        return Err(AgentStoreError::InvalidProjection(
            "initial reserved binding",
        ));
    }
    let delegation = crate::workspace_agent_migration::delegation(connection)?.ok_or(
        AgentStoreError::InvalidProjection("binding delegation missing"),
    )?;
    let (principal_kind, principal_id) = encode_principal(agent.principal());
    let admitted: bool = connection.query_row(
        "SELECT EXISTS (SELECT 1 FROM agent_binding_activations a JOIN agent_binding_reservations r ON r.request_id=a.request_id WHERE r.migration_id=?1 AND r.workspace_id=?2 AND r.destination_id=?3 AND r.freeze_revision=?4 AND r.agent_id=?5 AND r.activity_id=?6 AND r.session_id=?7 AND r.principal_kind=?8 AND ((r.principal_kind=0 AND r.principal_id=zeroblob(16) AND ?9 IS NULL) OR r.principal_id=?9) AND a.display_name=?10 AND a.declared_role=?11 AND a.transport_kind=?12 AND a.activated_at_ms=?13)",
        params![
            delegation.migration_id().as_bytes(),
            agent.workspace_id().into_uuid().as_bytes(),
            delegation.destination_id().as_bytes(),
            i64::try_from(delegation.freeze().revision()).map_err(|_| AgentStoreError::IntegerOverflow)?,
            agent.id().into_uuid().as_bytes(),
            agent.activity_id().into_uuid().as_bytes(),
            agent.session_id().map(|id| id.into_uuid().as_bytes().to_vec()),
            principal_kind, principal_id.as_deref(),
            agent.display_name().as_str(), agent.declared_role().as_str(),
            encode_transport(agent.transport_kind()), agent.created_at().get(),
        ],
        |row| row.get(0),
    )?;
    if !admitted || delegation.workspace_id() != agent.workspace_id() {
        return Err(AgentStoreError::InvalidProjection(
            "binding activation admission",
        ));
    }
    insert_agent_row(connection, agent)?;
    insert_focus_event(
        connection,
        &AgentFocusEvent::from_parts(
            agent.id(),
            agent.workspace_id(),
            agent.activity_id(),
            AgentFocusEventSequence::INITIAL,
            AgentFocusEventKind::Attached,
            agent.focus(),
            agent.created_at(),
        ),
    )
}

fn insert_agent_row(
    connection: &Connection,
    agent: &RegisteredAgentInstance,
) -> Result<(), AgentStoreError> {
    let (goal_id, goal_revision, dag_revision, node_id, node_revision) =
        encode_focus(agent.focus());
    let (principal_kind, principal_id) = encode_principal(agent.principal());
    connection.execute(
        "INSERT INTO agent_instances (agent_id, workspace_id, activity_id, display_name, declared_role, transport_kind, principal_kind, principal_id, attachment_state, focus_goal_id, focus_goal_revision, focus_dag_revision, focus_node_id, focus_node_revision, created_at_ms, updated_at_ms, revision, session_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
        params![
            agent.id().into_uuid().as_bytes(),
            agent.workspace_id().into_uuid().as_bytes(),
            agent.activity_id().into_uuid().as_bytes(),
            agent.display_name().as_str(),
            agent.declared_role().as_str(),
            encode_transport(agent.transport_kind()),
            principal_kind,
            principal_id.as_deref(),
            encode_attachment_state(agent.attachment_state()),
            goal_id.as_deref(),
            goal_revision,
            dag_revision,
            node_id.as_deref(),
            node_revision,
            agent.created_at().get(),
            agent.updated_at().get(),
            agent.revision().get(),
            agent
                .session_id()
                .map(|session| session.into_uuid().as_bytes().to_vec()),
        ],
    )?;
    Ok(())
}

fn update_agent(
    connection: &Connection,
    current: &RegisteredAgentInstance,
    updated: &RegisteredAgentInstance,
) -> Result<(), AgentStoreError> {
    crate::workspace_agent_migration::ensure_work_writes(connection)?;
    let (goal_id, goal_revision, dag_revision, node_id, node_revision) =
        encode_focus(updated.focus());
    let changed = connection.execute(
        "UPDATE agent_instances SET attachment_state = ?1, focus_goal_id = ?2, focus_goal_revision = ?3, focus_dag_revision = ?4, focus_node_id = ?5, focus_node_revision = ?6, updated_at_ms = ?7, revision = ?8, session_id = ?9 WHERE agent_id = ?10 AND revision = ?11 AND workspace_id = ?12 AND activity_id = ?13",
        params![
            encode_attachment_state(updated.attachment_state()),
            goal_id.as_deref(),
            goal_revision,
            dag_revision,
            node_id.as_deref(),
            node_revision,
            updated.updated_at().get(),
            updated.revision().get(),
            updated
                .session_id()
                .map(|session| session.into_uuid().as_bytes().to_vec()),
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

pub(crate) fn insert_focus_event(
    connection: &Connection,
    event: &AgentFocusEvent,
) -> Result<(), AgentStoreError> {
    crate::workspace_agent_migration::ensure_work_writes(connection)?;
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
    crate::workspace_agent_effect_outbox::append_focus(connection, event)
        .map_err(|source| AgentStoreError::EffectOutbox(Box::new(source)))
}

type EncodedFocus = (
    Option<Vec<u8>>,
    Option<i64>,
    Option<i64>,
    Option<Vec<u8>>,
    Option<i64>,
);

type EncodedPrincipal = (i64, Option<Vec<u8>>);

fn encode_principal(value: AuthenticatedPrincipal) -> EncodedPrincipal {
    match value {
        AuthenticatedPrincipal::TrustedStdio => (0, None),
        AuthenticatedPrincipal::DirectToken(id) => (1, Some(id.into_uuid().as_bytes().to_vec())),
        AuthenticatedPrincipal::OAuthGrant(id) => (2, Some(id.into_uuid().as_bytes().to_vec())),
    }
}

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
        AgentTransportKind::Retired => 0,
        AgentTransportKind::Stdio => 1,
        AgentTransportKind::StreamableHttp => 2,
        AgentTransportKind::Other => 3,
    }
}

fn decode_transport(value: i64) -> Result<AgentTransportKind, AgentStoreError> {
    match value {
        0 => Ok(AgentTransportKind::Retired),
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
    decode_agent_at(row, 25)
}

fn decode_agent_at(
    row: &Row<'_>,
    session_index: usize,
) -> Result<RegisteredAgentInstance, AgentStoreError> {
    let id: Vec<u8> = row.get(0)?;
    let workspace_id: Vec<u8> = row.get(1)?;
    let activity_id: Vec<u8> = row.get(2)?;
    validate_exact_length("agent_id", row.get(17)?, ID_BYTES_I64)?;
    validate_exact_length("agent.workspace_id", row.get(18)?, ID_BYTES_I64)?;
    validate_exact_length("agent.activity_id", row.get(19)?, ID_BYTES_I64)?;
    validate_text_length(
        "agent.display_name",
        row.get(20)?,
        forge_domain::MAX_AGENT_DISPLAY_NAME_BYTES,
    )?;
    validate_text_length("agent.declared_role", row.get(21)?, MAX_METADATA_BYTES)?;
    if let Some(length) = row.get::<_, Option<i64>>(22)? {
        validate_exact_length("agent.principal_id", length, ID_BYTES_I64)?;
    }
    if let Some(length) = row.get::<_, Option<i64>>(23)? {
        validate_exact_length("agent.focus_goal_id", length, ID_BYTES_I64)?;
    }
    if let Some(length) = row.get::<_, Option<i64>>(24)? {
        validate_exact_length("agent.focus_node_id", length, ID_BYTES_I64)?;
    }
    let session_id = row
        .get::<_, Option<Vec<u8>>>(session_index)?
        .map(|value| {
            validate_exact_length(
                "agent.session_id",
                i64::try_from(value.len()).unwrap_or(i64::MAX),
                ID_BYTES_I64,
            )?;
            Ok::<_, AgentStoreError>(forge_domain::AgentSessionId::from_uuid(decode_uuid(
                &value,
                "agent.session_id",
            )?))
        })
        .transpose()?;
    let principal = decode_principal(row.get(6)?, row.get(7)?)?;
    let focus = decode_focus(
        row.get(9)?,
        row.get(10)?,
        row.get(11)?,
        row.get(12)?,
        row.get(13)?,
    )?;
    let created_at = decode_timestamp(row.get(14)?, "agent.created_at_ms")?;
    let updated_at = decode_timestamp(row.get(15)?, "agent.updated_at_ms")?;
    let revision = AgentInstanceRevision::new(row.get(16)?)
        .map_err(|_| AgentStoreError::CorruptRecord("agent.revision"))?;
    RegisteredAgentInstance::from_parts(forge_domain::AgentRecordParts {
        id: decode_agent_id(&id)?,
        workspace_id: decode_workspace_id(&workspace_id)?,
        activity_id: decode_activity_id(&activity_id)?,
        session_id,
        display_name: AgentDisplayName::new(row.get(3)?)
            .map_err(|_| AgentStoreError::CorruptRecord("agent.display_name"))?,
        declared_role: AgentDeclaredRole::new(row.get(4)?)
            .map_err(|_| AgentStoreError::CorruptRecord("agent.declared_role"))?,
        transport_kind: decode_transport(row.get(5)?)?,
        principal,
        attachment_state: decode_attachment_state(row.get(8)?)?,
        focus,
        created_at,
        updated_at,
        revision,
    })
    .map_err(|_| AgentStoreError::CorruptRecord("agent.projection"))
}

fn decode_principal(
    kind: i64,
    identifier: Option<Vec<u8>>,
) -> Result<AuthenticatedPrincipal, AgentStoreError> {
    match (kind, identifier) {
        (0, None) => Ok(AuthenticatedPrincipal::TrustedStdio),
        (1, Some(value)) => Ok(AuthenticatedPrincipal::DirectToken(
            forge_domain::DirectTokenId::from_uuid(decode_uuid(&value, "agent.principal_id")?),
        )),
        (2, Some(value)) => Ok(AuthenticatedPrincipal::OAuthGrant(
            forge_domain::OAuthGrantId::from_uuid(decode_uuid(&value, "agent.principal_id")?),
        )),
        _ => Err(AgentStoreError::CorruptRecord("agent.principal")),
    }
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

const AGENT_BY_ID_QUERY: &str = "SELECT ai.agent_id, ai.workspace_id, ai.activity_id, ai.display_name, ai.declared_role, ai.transport_kind, ai.principal_kind, ai.principal_id, ai.attachment_state, ai.focus_goal_id, ai.focus_goal_revision, ai.focus_dag_revision, ai.focus_node_id, ai.focus_node_revision, ai.created_at_ms, ai.updated_at_ms, ai.revision, length(ai.agent_id), length(ai.workspace_id), length(ai.activity_id), length(CAST(ai.display_name AS BLOB)), length(CAST(ai.declared_role AS BLOB)), length(ai.principal_id), length(ai.focus_goal_id), length(ai.focus_node_id), ai.session_id FROM agent_instances AS ai WHERE ai.agent_id = ?1";
const AGENTS_EXPORT_QUERY: &str = "SELECT substr(ai.agent_id,1,17), substr(ai.workspace_id,1,17), substr(ai.activity_id,1,17), substr(ai.display_name,1,129), substr(ai.declared_role,1,129), ai.transport_kind, ai.principal_kind, substr(ai.principal_id,1,17), ai.attachment_state, substr(ai.focus_goal_id,1,17), ai.focus_goal_revision, ai.focus_dag_revision, substr(ai.focus_node_id,1,17), ai.focus_node_revision, ai.created_at_ms, ai.updated_at_ms, ai.revision, length(ai.agent_id), length(ai.workspace_id), length(ai.activity_id), length(CAST(ai.display_name AS BLOB)), length(CAST(ai.declared_role AS BLOB)), length(ai.principal_id), length(ai.focus_goal_id), length(ai.focus_node_id), substr(ai.session_id,1,17) FROM agent_instances AS ai WHERE ai.workspace_id = ?1 AND (?2 IS NULL OR ai.agent_id > ?2) ORDER BY ai.agent_id ASC LIMIT ?3";
const AGENTS_BY_WORKSPACE_QUERY: &str = "SELECT ai.agent_id, ai.workspace_id, ai.activity_id, ai.display_name, ai.declared_role, ai.transport_kind, ai.principal_kind, ai.principal_id, ai.attachment_state, ai.focus_goal_id, ai.focus_goal_revision, ai.focus_dag_revision, ai.focus_node_id, ai.focus_node_revision, ai.created_at_ms, ai.updated_at_ms, ai.revision, length(ai.agent_id), length(ai.workspace_id), length(ai.activity_id), length(CAST(ai.display_name AS BLOB)), length(CAST(ai.declared_role AS BLOB)), length(ai.principal_id), length(ai.focus_goal_id), length(ai.focus_node_id), a.activity_id, a.workspace_id, a.state, a.created_at_ms, a.updated_at_ms, a.revision, a.lease_owner_id, a.lease_until_ms, a.lease_revision, length(a.lease_owner_id), ai.session_id FROM agent_instances AS ai JOIN activities AS a ON a.activity_id = ai.activity_id WHERE ai.workspace_id = ?1 AND (?2 IS NULL OR ai.activity_id = ?2) ORDER BY ai.updated_at_ms DESC, ai.agent_id DESC LIMIT ?3";
const ACTIVITY_BY_ID_QUERY: &str = "SELECT activity_id, workspace_id, state, created_at_ms, updated_at_ms, revision, lease_owner_id, lease_until_ms, lease_revision, length(lease_owner_id) FROM activities WHERE activity_id = ?1";
const FOCUS_EVENTS_QUERY: &str = "SELECT agent_id, workspace_id, activity_id, event_sequence, event_kind, focus_goal_id, length(focus_goal_id), focus_goal_revision, focus_dag_revision, focus_node_id, length(focus_node_id), focus_node_revision, observed_at_ms, length(agent_id), length(workspace_id), length(activity_id) FROM agent_focus_events WHERE agent_id = ?1 ORDER BY event_sequence DESC LIMIT ?2";
const WORK_UPDATES_QUERY: &str = "SELECT update_id, agent_id, workspace_id, activity_id, update_sequence, phase, summary, length(CAST(summary AS BLOB)), evidence_count, observed_at_ms, length(update_id), length(agent_id), length(workspace_id), length(activity_id) FROM agent_work_updates WHERE agent_id = ?1 ORDER BY update_sequence DESC LIMIT ?2";
const WORK_UPDATE_BY_ID_QUERY: &str = "SELECT update_id, agent_id, workspace_id, activity_id, update_sequence, phase, summary, length(CAST(summary AS BLOB)), evidence_count, observed_at_ms, length(update_id), length(agent_id), length(workspace_id), length(activity_id) FROM agent_work_updates WHERE update_id = ?1";
const WORK_UPDATE_EVIDENCE_QUERY: &str = "SELECT evidence_kind, evidence_id, length(evidence_id) FROM agent_work_update_evidence_refs WHERE update_id = ?1 ORDER BY evidence_kind, evidence_id";
const WORK_UPDATE_EVIDENCE_FOR_AGENT_QUERY: &str = "SELECT e.update_id, e.evidence_kind, e.evidence_id, length(e.evidence_id) FROM agent_work_update_evidence_refs AS e WHERE e.agent_id = ?1 AND e.update_id IN (SELECT update_id FROM agent_work_updates WHERE agent_id = ?1 ORDER BY update_sequence DESC LIMIT ?2) ORDER BY e.update_id, e.evidence_kind, e.evidence_id";

#[derive(Debug, Error)]
pub enum AgentStoreError {
    #[error(transparent)]
    WorkCut(#[from] Box<crate::WorkCutError>),
    #[error("Agent work fact could not be recorded")]
    EffectOutbox(#[source] Box<crate::AgentEffectOutboxError>),
    #[error(transparent)]
    OperationsMigration(#[from] crate::AgentOperationsMigrationError),
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Events(#[from] AgentEventStoreError),
    #[error("Agent instance identity conflicts with the existing row")]
    IdentityConflict,
    #[error("Agent session is already attached to another instance in this Activity")]
    SessionAttachmentConflict,
    #[error("Agent session principal conflicts with the existing attachment")]
    SessionPrincipalConflict,
    #[error("Agent session binding is missing")]
    SessionBindingConflict,
    #[error("Authenticated principal conflicts with the Agent attachment")]
    PrincipalConflict,
    #[error("Unresolved legacy Agent {0} cannot use a session-bound mutation")]
    UnresolvedLegacy(AgentInstanceId),
    #[error("Agent {0} was not found")]
    AgentNotFound(AgentInstanceId),
    #[error("Agent {0} is detached")]
    AgentDetached(AgentInstanceId),
    #[error("Current Coordinator Agent {0} must use an explicit handoff before detaching")]
    CurrentCoordinatorCannotDetach(AgentInstanceId),
    #[error("Agent {0} has an active Writer Lease")]
    ActiveWriterLease(AgentInstanceId),
    #[error("Agent {0} has an active execution")]
    ActiveExecution(AgentInstanceId),
    #[error("Activity {0} was not found")]
    ActivityNotFound(ActivityId),
    #[error("Activity {0} is not Open")]
    ActivityNotLive(ActivityId),
    #[error("Activity {0} has no live owner lease")]
    ActivityLeaseNotLive(ActivityId),
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

impl From<crate::WorkCutError> for AgentStoreError {
    fn from(error: crate::WorkCutError) -> Self {
        Self::WorkCut(Box::new(error))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{WorkspaceStore, WorkspaceStoreError};
    use forge_domain::{
        ActivityCoordinatorActor, ActivityId, ActivityState, AgentDeclaredRole, AgentDisplayName,
        AgentEventKind, AgentInboxListLimit, AgentInstanceId, AgentListLimit, AgentParticipantRef,
        AgentSessionId, AgentTransportKind, AgentWorkPhase, AgentWorkSummary, AgentWorkUpdate,
        AgentWorkUpdateId, AgentWorkUpdateSequence, AuthenticatedPrincipal, BootstrapActivity,
        ClaimActivityCoordinator, CreateActivity, DirectTokenId, EstablishWorkspace, LocationId,
        RegisteredAgentInstance, ReleaseActivityLease, RuntimeInstanceId, SetActivityState,
        SetAgentFocus, TimestampMillis, WorkspaceId, WorkspaceRevision, WorkspaceRoot,
    };
    use forge_workspace::WorkspaceStateLayout;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    type PrincipalCase = (AuthenticatedPrincipal, EncodedPrincipal);

    #[test]
    fn schema_has_current_agent_objects_and_required_principal_columns()
    -> Result<(), Box<dyn std::error::Error>> {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch("PRAGMA foreign_keys = ON; CREATE TABLE workspace (workspace_id BLOB PRIMARY KEY); CREATE TABLE activities (activity_id BLOB PRIMARY KEY, workspace_id BLOB); CREATE TABLE goals (goal_id BLOB PRIMARY KEY); CREATE TABLE goal_dag_revisions (goal_id BLOB, dag_revision INTEGER, PRIMARY KEY(goal_id, dag_revision)); CREATE TABLE goal_dag_nodes (goal_id BLOB, dag_revision INTEGER, node_id BLOB, PRIMARY KEY(goal_id, dag_revision, node_id));")?;
        create_schema(&connection)?;
        validate_schema(&connection)?;
        let count: i64 =
            connection.query_row("SELECT count(*) FROM agent_instances", [], |row| row.get(0))?;
        assert_eq!(count, 0);
        let columns: Vec<String> = connection
            .prepare("PRAGMA table_info(agent_instances)")?
            .query_map([], |row| row.get(1))?
            .collect::<Result<_, _>>()?;
        assert!(columns.contains(&"principal_kind".to_owned()));
        assert!(columns.contains(&"principal_id".to_owned()));
        assert!(columns.contains(&"session_id".to_owned()));
        let session_index: String = connection.query_row(
            "SELECT sql FROM sqlite_schema WHERE type = 'index' AND name = 'agent_instances_activity_session_uidx'",
            [],
            |row| row.get(0),
        )?;
        assert!(session_index.contains("UNIQUE"));
        assert!(session_index.contains("session_id IS NOT NULL"));
        let legacy_table: Option<String> = connection
            .query_row(
                "SELECT name FROM sqlite_schema WHERE type = 'table' AND name = 'agent_transport_principals'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        assert!(legacy_table.is_none());
        Ok(())
    }

    #[test]
    fn focus_event_kind_encoding_is_stable() {
        assert_eq!(encode_focus_event_kind(AgentFocusEventKind::Attached), 0);
        assert_eq!(encode_focus_event_kind(AgentFocusEventKind::Changed), 1);
        assert_eq!(encode_focus_event_kind(AgentFocusEventKind::Detached), 2);
    }

    #[test]
    fn authenticated_principal_encoding_is_complete_and_fail_closed() {
        let token = DirectTokenId::from_uuid(Uuid::from_u128(0xA301));
        let grant = forge_domain::OAuthGrantId::from_uuid(Uuid::from_u128(0xA302));
        let cases: [PrincipalCase; 3] = [
            (AuthenticatedPrincipal::TrustedStdio, (0, None)),
            (
                AuthenticatedPrincipal::DirectToken(token),
                (1, Some(token.into_uuid().as_bytes().to_vec())),
            ),
            (
                AuthenticatedPrincipal::OAuthGrant(grant),
                (2, Some(grant.into_uuid().as_bytes().to_vec())),
            ),
        ];
        for (principal, (kind, identifier)) in cases {
            let encoded = encode_principal(principal);
            assert_eq!(encoded, (kind, identifier));
            assert!(matches!(
                decode_principal(encoded.0, encoded.1),
                Ok(actual) if actual == principal
            ));
        }
        assert!(decode_principal(0, Some(vec![0; ID_BYTES])).is_err());
        assert!(decode_principal(1, None).is_err());
        assert!(decode_principal(2, Some(vec![0; ID_BYTES - 1])).is_err());
        assert!(decode_principal(3, Some(vec![0; ID_BYTES])).is_err());
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
        Ok(RegisteredAgentInstance::create_bound(
            AgentInstanceId::from_uuid(Uuid::from_u128(value)),
            workspace_id,
            activity_id,
            AgentSessionId::from_uuid(Uuid::from_u128(value + 0x5000)),
            AgentDisplayName::new(format!("Agent {value}"))?,
            AgentDeclaredRole::new("planner".to_owned())?,
            AgentTransportKind::Retired,
            AuthenticatedPrincipal::TrustedStdio,
            TimestampMillis::new(observed_at)?,
        ))
    }

    fn agent_with_principal(
        value: u128,
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        principal: AuthenticatedPrincipal,
        observed_at: i64,
    ) -> Result<RegisteredAgentInstance, Box<dyn std::error::Error>> {
        Ok(RegisteredAgentInstance::create_bound(
            AgentInstanceId::from_uuid(Uuid::from_u128(value)),
            workspace_id,
            activity_id,
            AgentSessionId::from_uuid(Uuid::from_u128(value + 0x5000)),
            AgentDisplayName::new(format!("Agent {value}"))?,
            AgentDeclaredRole::new("planner".to_owned())?,
            AgentTransportKind::StreamableHttp,
            principal,
            TimestampMillis::new(observed_at)?,
        ))
    }

    fn seed_agent(
        layout: &WorkspaceStateLayout,
        agent: &RegisteredAgentInstance,
        event_id: Option<forge_domain::AgentEventId>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let connection = Connection::open(layout.database_path())?;
        connection.pragma_update(None, "foreign_keys", true)?;
        crate::legacy_agent_seed::seed_agent(&connection, agent, event_id)
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
        let _activity = store.bootstrap_activity(&BootstrapActivity::new(
            activity_id,
            workspace_id,
            WorkspaceRevision::INITIAL,
            RuntimeInstanceId::from_uuid(Uuid::from_u128(0xA004)),
            TimestampMillis::new(7)?,
            TimestampMillis::new(2)?,
        ))?;
        let token_id = DirectTokenId::from_uuid(Uuid::from_u128(0xA012));
        let first = agent_with_principal(
            0xA010,
            workspace_id,
            activity_id,
            AuthenticatedPrincipal::DirectToken(token_id),
            3,
        )?;
        let second = agent(0xA011, workspace_id, activity_id, 4)?;
        seed_agent(
            &layout,
            &first,
            Some(crate::workspace_agent_events::derived_event_id(
                first.id(),
                first.revision(),
                AgentEventKind::Joined,
            )),
        )?;
        seed_agent(
            &layout,
            &second,
            Some(crate::workspace_agent_events::derived_event_id(
                second.id(),
                second.revision(),
                AgentEventKind::Joined,
            )),
        )?;

        let listed = store.list_agent_attachments(
            None,
            TimestampMillis::new(5)?,
            AgentListLimit::DEFAULT,
        )?;
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].agent().id(), second.id());
        assert_eq!(listed[1].agent().id(), first.id());
        assert_eq!(
            listed[1].agent().principal(),
            AuthenticatedPrincipal::DirectToken(token_id)
        );
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
        assert_eq!(
            store.publish_agent_work_update(
                &update,
                first.session_id().ok_or("session missing")?,
                first.principal(),
                TimestampMillis::new(6)?,
            )?,
            update
        );
        let expired_update = AgentWorkUpdate::new(
            AgentWorkUpdateId::from_uuid(Uuid::from_u128(0xA021)),
            first.id(),
            workspace_id,
            activity_id,
            AgentWorkUpdateSequence::new(2)?,
            AgentWorkPhase::Planning,
            AgentWorkSummary::new("Stale audit time cannot bypass expiry".to_owned())?,
            Vec::new(),
            TimestampMillis::new(6)?,
        )?;
        assert!(matches!(
            store.publish_agent_work_update(
                &expired_update,
                first.session_id().ok_or("session missing")?,
                first.principal(),
                TimestampMillis::new(7)?,
            ),
            Err(crate::WorkspaceStoreError::Agent(
                AgentStoreError::ActivityLeaseNotLive(actual_activity_id)
            )) if actual_activity_id == activity_id
        ));
        let connection = Connection::open(layout.database_path())?;
        let expired_rows: i64 = connection.query_row(
            "SELECT COUNT(*) FROM agent_work_updates WHERE update_id = ?1",
            params![expired_update.id().into_uuid().as_bytes()],
            |row| row.get(0),
        )?;
        assert_eq!(expired_rows, 0);
        drop(connection);
        let current = store
            .get_agent(first.id())?
            .ok_or("attached principal Agent missing")?;
        let mut direct = Connection::open(layout.database_path())?;
        direct.pragma_update(None, "foreign_keys", true)?;
        direct.busy_timeout(std::time::Duration::from_secs(5))?;
        let transaction = direct.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let detached = detach_in_transaction(&transaction, &current, TimestampMillis::new(7)?)?;
        transaction.commit()?;
        drop(direct);
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
                .principal(),
            AuthenticatedPrincipal::DirectToken(token_id)
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
    #[allow(clippy::too_many_lines)]
    fn bound_participation_and_inbox_receipts_are_restartable()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = fixture_root("participation")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(0xA401));
        let location_id = LocationId::from_uuid(Uuid::from_u128(0xA402));
        let command = EstablishWorkspace::new(
            workspace_id,
            location_id,
            WorkspaceRoot::from_canonical(layout.workspace_root().to_path_buf())?,
            layout.root_fingerprint()?,
            TimestampMillis::new(1)?,
        );
        let activity_id = ActivityId::from_uuid(Uuid::from_u128(0xA403));
        let runtime_id = RuntimeInstanceId::from_uuid(Uuid::from_u128(0xA404));
        let mut store = WorkspaceStore::open(&layout, &command)?;
        store.bootstrap_activity(&BootstrapActivity::new(
            activity_id,
            workspace_id,
            WorkspaceRevision::INITIAL,
            runtime_id,
            TimestampMillis::new(100)?,
            TimestampMillis::new(2)?,
        ))?;
        let first = agent_with_principal(
            0xA410,
            workspace_id,
            activity_id,
            AuthenticatedPrincipal::DirectToken(DirectTokenId::from_uuid(Uuid::from_u128(0xA411))),
            3,
        )?;
        let second = agent(0xA420, workspace_id, activity_id, 4)?;
        seed_agent(
            &layout,
            &first,
            Some(crate::workspace_agent_events::derived_event_id(
                first.id(),
                first.revision(),
                AgentEventKind::Joined,
            )),
        )?;
        let _binding = store.claim_activity_coordinator(
            ClaimActivityCoordinator::new(
                workspace_id,
                activity_id,
                first.id(),
                first.principal(),
                TimestampMillis::new(5)?,
                first.session_id().ok_or("first session missing")?,
            ),
            TimestampMillis::new(6)?,
        )?;
        seed_agent(
            &layout,
            &second,
            Some(crate::workspace_agent_events::derived_event_id(
                second.id(),
                second.revision(),
                AgentEventKind::Joined,
            )),
        )?;

        let events =
            store.list_agent_events(activity_id, forge_domain::AgentEventListLimit::DEFAULT)?;
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].kind(), AgentEventKind::Joined);
        assert_eq!(events[0].membership_revision().get(), 3);
        assert_eq!(events[1].kind(), AgentEventKind::RoleChanged);
        let inbox = store.list_agent_inbox(
            first.id(),
            first.session_id().ok_or("first session missing")?,
            AgentInboxListLimit::DEFAULT,
        )?;
        assert_eq!(inbox.len(), 1);
        assert!(!inbox[0].is_acknowledged());

        let current_second = store
            .get_agent(second.id())?
            .ok_or("attached second Agent missing")?;
        let mut direct = Connection::open(layout.database_path())?;
        direct.pragma_update(None, "foreign_keys", true)?;
        direct.busy_timeout(std::time::Duration::from_secs(5))?;
        let transaction = direct.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let detached =
            detach_in_transaction(&transaction, &current_second, TimestampMillis::new(7)?)?;
        transaction.commit()?;
        drop(direct);
        assert!(detached.attachment_state().is_detached());
        let events_after_detach =
            store.list_agent_events(activity_id, forge_domain::AgentEventListLimit::DEFAULT)?;
        // The legacy operational `Left` writer is retired; detached membership
        // transitions are now recorded by Orchestration, so the durable event
        // count keeps the pre-departure history only.
        assert_eq!(events_after_detach.len(), 3);
        let presence = store.list_agent_presence(activity_id)?;
        assert_eq!(presence.counts().current_coordinator(), 1);
        assert_eq!(presence.counts().detached(), 1);
        assert_eq!(presence.counts().unresolved_legacy(), 0);

        for offset in 0_i64..64 {
            let participant = agent(
                0xA500 + u128::try_from(offset)?,
                workspace_id,
                activity_id,
                10 + offset,
            )?;
            seed_agent(
                &layout,
                &participant,
                Some(crate::workspace_agent_events::derived_event_id(
                    participant.id(),
                    participant.revision(),
                    AgentEventKind::Joined,
                )),
            )?;
            let inbox = store.list_agent_inbox(
                first.id(),
                first.session_id().ok_or("first session missing")?,
                AgentInboxListLimit::DEFAULT,
            )?;
            // Every new participant join durably appends one receipt for the
            // current Coordinator; reads stay bounded by the list limit.
            let expected = usize::try_from(offset + 2)?.min(usize::try_from(
                forge_domain::AgentInboxListLimit::DEFAULT.get(),
            )?);
            assert_eq!(
                inbox.len(),
                expected,
                "receipt count must grow with each joined participant until the read cap"
            );
        }
        let final_participant = agent(0xA600, workspace_id, activity_id, 200)?;
        seed_agent(
            &layout,
            &final_participant,
            Some(crate::workspace_agent_events::derived_event_id(
                final_participant.id(),
                final_participant.revision(),
                AgentEventKind::Joined,
            )),
        )?;
        let inbox = store.list_agent_inbox(
            first.id(),
            first.session_id().ok_or("first session missing")?,
            AgentInboxListLimit::DEFAULT,
        )?;
        assert_eq!(inbox.len(), 64);
        assert_eq!(
            inbox[0].event().to().map(AgentParticipantRef::agent_id),
            Some(final_participant.id())
        );
        assert!(!inbox[0].is_acknowledged());

        let activity = store
            .get_activity(activity_id)?
            .ok_or("activity missing before close")?;
        let _released = store.release_activity_lease(&ReleaseActivityLease::new(
            activity_id,
            runtime_id,
            activity.lease_revision(),
            TimestampMillis::new(74)?,
        ))?;
        let _closed = store.set_activity_state(&SetActivityState::new(
            activity_id,
            activity.revision(),
            ActivityState::Closed,
            TimestampMillis::new(75)?,
        ))?;
        drop(store);
        let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
        let reopened = WorkspaceStore::open_existing(&existing)?;
        let retained = reopened.list_agent_inbox(
            first.id(),
            first.session_id().ok_or("first session missing")?,
            AgentInboxListLimit::DEFAULT,
        )?;
        assert_eq!(retained.len(), 64);
        assert!(!retained[0].is_acknowledged());
        assert!(
            retained.iter().all(|entry| !entry.is_acknowledged()),
            "unacknowledged receipts must restart unchanged"
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
        let _ = store.bootstrap_activity(&BootstrapActivity::new(
            activity_id,
            workspace_id,
            WorkspaceRevision::INITIAL,
            RuntimeInstanceId::from_uuid(Uuid::from_u128(0xA104)),
            TimestampMillis::new(100)?,
            TimestampMillis::new(2)?,
        ))?;
        let instance = agent(0xA110, workspace_id, activity_id, 3)?;
        seed_agent(
            &layout,
            &instance,
            Some(crate::workspace_agent_events::derived_event_id(
                instance.id(),
                instance.revision(),
                AgentEventKind::Joined,
            )),
        )?;
        let coordinator = store.claim_activity_coordinator(
            ClaimActivityCoordinator::new(
                workspace_id,
                activity_id,
                instance.id(),
                AuthenticatedPrincipal::TrustedStdio,
                TimestampMillis::new(4)?,
                instance.session_id().ok_or("session missing")?,
            ),
            TimestampMillis::new(5)?,
        )?;
        let actor = ActivityCoordinatorActor::new(
            workspace_id,
            activity_id,
            instance.id(),
            coordinator.revision(),
            AuthenticatedPrincipal::TrustedStdio,
            instance.session_id().ok_or("session missing")?,
        );
        let focus = AgentFocus::new(
            Some(GoalAttribution::new(
                forge_domain::GoalId::from_uuid(Uuid::from_u128(0xA111)),
                forge_domain::GoalRevision::INITIAL,
            )),
            Some(DagRevisionNumber::INITIAL),
            None,
        )?;
        let Err(error) = store.set_agent_focus(
            actor,
            &SetAgentFocus::new(
                instance.id(),
                activity_id,
                instance.revision(),
                focus,
                TimestampMillis::new(5)?,
            ),
            TimestampMillis::new(6)?,
        ) else {
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
        seed_agent(
            &layout,
            &instance,
            Some(crate::workspace_agent_events::derived_event_id(
                instance.id(),
                instance.revision(),
                AgentEventKind::Joined,
            )),
        )?;
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

    #[test]
    fn corrupted_authenticated_principal_fails_closed_on_projection_read()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = fixture_root("principal-corruption")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(0xA401));
        let location_id = LocationId::from_uuid(Uuid::from_u128(0xA402));
        let command = EstablishWorkspace::new(
            workspace_id,
            location_id,
            WorkspaceRoot::from_canonical(layout.workspace_root().to_path_buf())?,
            layout.root_fingerprint()?,
            TimestampMillis::new(1)?,
        );
        let activity_id = ActivityId::from_uuid(Uuid::from_u128(0xA403));
        let mut store = WorkspaceStore::open(&layout, &command)?;
        store.create_activity(&CreateActivity::new(
            activity_id,
            workspace_id,
            WorkspaceRevision::INITIAL,
            TimestampMillis::new(2)?,
        ))?;
        let instance = agent(0xA410, workspace_id, activity_id, 3)?;
        seed_agent(
            &layout,
            &instance,
            Some(crate::workspace_agent_events::derived_event_id(
                instance.id(),
                instance.revision(),
                AgentEventKind::Joined,
            )),
        )?;
        drop(store);
        let connection = Connection::open(layout.database_path())?;
        connection.execute_batch(
            "PRAGMA ignore_check_constraints = ON;
             UPDATE agent_instances SET principal_kind = 1, principal_id = NULL;
             PRAGMA ignore_check_constraints = OFF;",
        )?;
        drop(connection);
        let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
        let reopened = WorkspaceStore::open_existing(&existing)?;
        assert!(matches!(
            reopened.get_agent(instance.id()),
            Err(WorkspaceStoreError::Agent(AgentStoreError::CorruptRecord(
                "agent.principal"
            )))
        ));
        fs::remove_dir_all(root)?;
        Ok(())
    }
}

#[cfg(test)]
mod delegation_tests;
