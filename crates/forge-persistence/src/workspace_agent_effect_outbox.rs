//! Durable source-side `Agent` work facts for a delegated `Workspace`.
//!
//! These rows are owned by the source `Workspace` after delegation. They are
//! immutable work evidence for the destination and deliberately do not reuse
//! the source membership event/inbox authority. `Goal` and `DAG` identifiers are
//! copied as opaque references: deleting source `Goal` or `DAG` revisions must
//! not delete an already-sealed work fact.

use forge_domain::{
    AgentEvent, AgentFocus, AgentFocusEvent, AgentFocusEventKind, AgentFocusEventSequence,
    AgentInstanceId, AgentSessionId, TimestampMillis, WorkspaceId,
};
use rusqlite::{Connection, OptionalExtension, Row, params};
use thiserror::Error;
use uuid::Uuid;

use crate::workspace_agent_events::{self, EventStorageTable};

const ID_BYTES: usize = 16;
const READ_PAGE_LIMIT: usize = 64;
const MAX_RECIPIENT_HINTS: usize = 64;
const MAX_SCHEMA_METADATA_ROWS: usize = 64;
const MAX_SCHEMA_SQL_BYTES: i64 = 16 * 1024;

const OUTBOX_TABLE_SQL: &str = "CREATE TABLE agent_effect_outbox_entries (sequence INTEGER PRIMARY KEY NOT NULL CHECK(sequence >= 1), migration_id BLOB NOT NULL CHECK(length(migration_id) = 16 AND migration_id != zeroblob(16)), destination_id BLOB NOT NULL CHECK(length(destination_id) = 16 AND destination_id != zeroblob(16)), workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16 AND workspace_id != zeroblob(16)), fact_kind INTEGER NOT NULL CHECK(fact_kind IN (0, 1)))";
const FOCUS_TABLE_SQL: &str = "CREATE TABLE agent_effect_outbox_focus (outbox_sequence INTEGER PRIMARY KEY NOT NULL REFERENCES agent_effect_outbox_entries(sequence), agent_id BLOB NOT NULL CHECK(length(agent_id) = 16 AND agent_id != zeroblob(16)), activity_id BLOB NOT NULL CHECK(length(activity_id) = 16 AND activity_id != zeroblob(16)), event_sequence INTEGER NOT NULL CHECK(event_sequence >= 1), event_kind INTEGER NOT NULL CHECK(event_kind IN (0, 1, 2)), focus_goal_id BLOB CHECK(focus_goal_id IS NULL OR length(focus_goal_id) = 16), focus_goal_revision INTEGER CHECK(focus_goal_revision IS NULL OR focus_goal_revision >= 1), focus_dag_revision INTEGER CHECK(focus_dag_revision IS NULL OR focus_dag_revision >= 1), focus_node_id BLOB CHECK(focus_node_id IS NULL OR length(focus_node_id) = 16), focus_node_revision INTEGER CHECK(focus_node_revision IS NULL OR focus_node_revision >= 1), observed_at_ms INTEGER NOT NULL CHECK(observed_at_ms >= 0), UNIQUE(agent_id, event_sequence))";
const TRANSITIONS_TABLE_SQL: &str = "CREATE TABLE agent_effect_outbox_transitions (outbox_sequence INTEGER PRIMARY KEY NOT NULL REFERENCES agent_effect_outbox_entries(sequence), event_id BLOB NOT NULL CHECK(length(event_id) = 16), workspace_id BLOB NOT NULL CHECK(length(workspace_id) = 16), activity_id BLOB NOT NULL CHECK(length(activity_id) = 16), membership_revision INTEGER NOT NULL CHECK(membership_revision >= 1), event_kind INTEGER NOT NULL CHECK(event_kind IN (0, 1, 2, 3, 4, 5)), from_agent_id BLOB CHECK(from_agent_id IS NULL OR length(from_agent_id) = 16), from_session_id BLOB CHECK(from_session_id IS NULL OR length(from_session_id) = 16), from_principal_kind INTEGER CHECK(from_principal_kind IS NULL OR from_principal_kind IN (0, 1, 2)), from_principal_id BLOB CHECK(from_principal_id IS NULL OR length(from_principal_id) = 16), from_display_name TEXT CHECK(from_display_name IS NULL OR length(CAST(from_display_name AS BLOB)) BETWEEN 1 AND 256), to_agent_id BLOB CHECK(to_agent_id IS NULL OR length(to_agent_id) = 16), to_session_id BLOB CHECK(to_session_id IS NULL OR length(to_session_id) = 16), to_principal_kind INTEGER CHECK(to_principal_kind IS NULL OR to_principal_kind IN (0, 1, 2)), to_principal_id BLOB CHECK(to_principal_id IS NULL OR length(to_principal_id) = 16), to_display_name TEXT CHECK(to_display_name IS NULL OR length(CAST(to_display_name AS BLOB)) BETWEEN 1 AND 256), before_goal_id BLOB CHECK(before_goal_id IS NULL OR length(before_goal_id) = 16), before_goal_revision INTEGER CHECK(before_goal_revision IS NULL OR before_goal_revision >= 1), before_dag_revision INTEGER CHECK(before_dag_revision IS NULL OR before_dag_revision >= 1), before_dag_head_revision INTEGER CHECK(before_dag_head_revision IS NULL OR before_dag_head_revision >= 1), before_head_id BLOB CHECK(before_head_id IS NULL OR length(before_head_id) = 16), before_head_revision INTEGER CHECK(before_head_revision IS NULL OR before_head_revision >= 1), after_goal_id BLOB CHECK(after_goal_id IS NULL OR length(after_goal_id) = 16), after_goal_revision INTEGER CHECK(after_goal_revision IS NULL OR after_goal_revision >= 1), after_dag_revision INTEGER CHECK(after_dag_revision IS NULL OR after_dag_revision >= 1), after_dag_head_revision INTEGER CHECK(after_dag_head_revision IS NULL OR after_dag_head_revision >= 1), after_head_id BLOB CHECK(after_head_id IS NULL OR length(after_head_id) = 16), after_head_revision INTEGER CHECK(after_head_revision IS NULL OR after_head_revision >= 1), before_coordinator_agent_id BLOB CHECK(before_coordinator_agent_id IS NULL OR length(before_coordinator_agent_id) = 16), before_coordinator_session_id BLOB CHECK(before_coordinator_session_id IS NULL OR length(before_coordinator_session_id) = 16), before_coordinator_revision INTEGER CHECK(before_coordinator_revision IS NULL OR before_coordinator_revision >= 1), after_coordinator_agent_id BLOB CHECK(after_coordinator_agent_id IS NULL OR length(after_coordinator_agent_id) = 16), after_coordinator_session_id BLOB CHECK(after_coordinator_session_id IS NULL OR length(after_coordinator_session_id) = 16), after_coordinator_revision INTEGER CHECK(after_coordinator_revision IS NULL OR after_coordinator_revision >= 1), observed_at_ms INTEGER NOT NULL CHECK(observed_at_ms >= 0), UNIQUE(event_id), UNIQUE(activity_id, membership_revision))";
const RECIPIENTS_TABLE_SQL: &str = "CREATE TABLE agent_effect_outbox_recipients (outbox_sequence INTEGER NOT NULL REFERENCES agent_effect_outbox_entries(sequence), hint_index INTEGER NOT NULL CHECK(hint_index >= 0 AND hint_index < 64), recipient_agent_id BLOB NOT NULL CHECK(length(recipient_agent_id) = 16 AND recipient_agent_id != zeroblob(16)), recipient_session_id BLOB NOT NULL CHECK(length(recipient_session_id) = 16 AND recipient_session_id != zeroblob(16)), PRIMARY KEY(outbox_sequence, hint_index))";
const WORKSPACE_SEQUENCE_INDEX_SQL: &str = "CREATE INDEX agent_effect_outbox_workspace_sequence_idx ON agent_effect_outbox_entries(workspace_id, sequence ASC)";
const OUTBOX_METADATA_QUERY: &str = "SELECT substr(migration_id, 1, 17), substr(destination_id, 1, 17), substr(workspace_id, 1, 17), fact_kind FROM agent_effect_outbox_entries WHERE sequence = ?1";
const FOCUS_PAYLOAD_QUERY: &str = "SELECT substr(agent_id, 1, 17), substr(activity_id, 1, 17), event_sequence, event_kind, substr(focus_goal_id, 1, 17), focus_goal_revision, focus_dag_revision, substr(focus_node_id, 1, 17), focus_node_revision, observed_at_ms FROM agent_effect_outbox_focus WHERE outbox_sequence = ?1";
const TRANSITION_PAYLOAD_QUERY: &str = "SELECT outbox_sequence, substr(event_id, 1, 17), substr(workspace_id, 1, 17), substr(activity_id, 1, 17), membership_revision, event_kind, substr(from_agent_id, 1, 17), substr(from_session_id, 1, 17), from_principal_kind, substr(from_principal_id, 1, 17), substr(from_display_name, 1, 257), substr(to_agent_id, 1, 17), substr(to_session_id, 1, 17), to_principal_kind, substr(to_principal_id, 1, 17), substr(to_display_name, 1, 257), substr(before_goal_id, 1, 17), before_goal_revision, before_dag_revision, before_dag_head_revision, substr(before_head_id, 1, 17), before_head_revision, substr(after_goal_id, 1, 17), after_goal_revision, after_dag_revision, after_dag_head_revision, substr(after_head_id, 1, 17), after_head_revision, substr(before_coordinator_agent_id, 1, 17), substr(before_coordinator_session_id, 1, 17), before_coordinator_revision, substr(after_coordinator_agent_id, 1, 17), substr(after_coordinator_session_id, 1, 17), after_coordinator_revision, observed_at_ms FROM agent_effect_outbox_transitions WHERE outbox_sequence = ?1";
const RECIPIENT_HINTS_QUERY: &str = "SELECT substr(recipient_agent_id, 1, 17), substr(recipient_session_id, 1, 17) FROM agent_effect_outbox_recipients WHERE outbox_sequence = ?1 ORDER BY hint_index ASC LIMIT ?2";

const OBJECTS: [(&str, &str, &str); 5] = [
    ("table", "agent_effect_outbox_entries", OUTBOX_TABLE_SQL),
    ("table", "agent_effect_outbox_focus", FOCUS_TABLE_SQL),
    (
        "table",
        "agent_effect_outbox_transitions",
        TRANSITIONS_TABLE_SQL,
    ),
    (
        "table",
        "agent_effect_outbox_recipients",
        RECIPIENTS_TABLE_SQL,
    ),
    (
        "index",
        "agent_effect_outbox_workspace_sequence_idx",
        WORKSPACE_SEQUENCE_INDEX_SQL,
    ),
];

/// One immutable delegated source work fact.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentEffectFact {
    Focus(AgentFocusEvent),
    Transition(Box<AgentEvent>),
}

/// One durable source outbox row. The sequence is local to this source
/// `Workspace` database and is the only pagination cursor exposed to readers.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentEffectOutboxEntry {
    sequence: i64,
    migration_id: Uuid,
    destination_id: Uuid,
    workspace_id: WorkspaceId,
    fact: AgentEffectFact,
    recipient_hints: Vec<(AgentInstanceId, AgentSessionId)>,
}

impl AgentEffectOutboxEntry {
    pub const fn sequence(&self) -> i64 {
        self.sequence
    }

    pub const fn migration_id(&self) -> Uuid {
        self.migration_id
    }

    pub const fn destination_id(&self) -> Uuid {
        self.destination_id
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn fact(&self) -> &AgentEffectFact {
        &self.fact
    }

    pub fn recipient_hints(&self) -> &[(AgentInstanceId, AgentSessionId)] {
        &self.recipient_hints
    }
}

/// Failure while appending, reading, or validating source work facts.
#[derive(Debug, Error)]
pub enum AgentEffectOutboxError {
    #[error(transparent)]
    Delegation(#[from] crate::workspace_agent_delegation::AgentOperationsDelegationError),
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error("Agent event payload codec failed: {0}")]
    EventCodec(#[source] Box<crate::workspace_agent_events::AgentEventStoreError>),
    #[error("Agent effect outbox schema object is damaged: {0}")]
    DamagedSchema(&'static str),
    #[error("Agent effect outbox schema object {object} is {actual} bytes; maximum is {maximum}")]
    SchemaSqlTooLarge {
        object: &'static str,
        actual: i64,
        maximum: i64,
    },
    #[error("Agent effect outbox record is corrupt: {0}")]
    CorruptRecord(&'static str),
    #[error("Agent effect outbox workspace identity is nil")]
    InvalidWorkspace,
    #[error("Agent effect outbox cursor must be non-negative")]
    InvalidCursor,
    #[error("Agent effect outbox append requires an active caller transaction")]
    MissingTransaction,
    #[error("Agent effect outbox recipient hint count {actual} exceeds {maximum}")]
    TooManyRecipientHints { actual: usize, maximum: usize },
    #[error("Agent effect outbox recipient identity is nil")]
    InvalidRecipient,
    #[error("Agent effect outbox replay conflicts with immutable content")]
    ReplayConflict,
    #[error("Agent effect outbox integer value overflowed")]
    IntegerOverflow,
}

/// Create the normalized source work-fact tables and bounded read index.
pub(crate) fn create_schema(connection: &Connection) -> Result<(), AgentEffectOutboxError> {
    for (_, _, sql) in OBJECTS {
        connection.execute_batch(sql)?;
    }
    Ok(())
}

/// Return the complete durable object inventory owned by this module.
pub(crate) fn schema_objects() -> Vec<(&'static str, &'static str)> {
    OBJECTS
        .iter()
        .map(|(kind, name, _)| (*kind, *name))
        .collect()
}

/// Validate the canonical DDL, column order, and payload foreign-key shape.
pub(crate) fn validate_schema(connection: &Connection) -> Result<(), AgentEffectOutboxError> {
    validate_schema_objects(connection)?;
    validate_payload_columns(connection)?;
    validate_payload_foreign_keys(connection)
}

fn validate_schema_objects(connection: &Connection) -> Result<(), AgentEffectOutboxError> {
    for (kind, name, expected) in OBJECTS {
        let length: Option<i64> = connection
            .query_row(
                "SELECT length(CAST(sql AS BLOB)) FROM sqlite_schema WHERE type = ?1 AND name = ?2",
                params![kind, name],
                |row| row.get(0),
            )
            .optional()?;
        let Some(length) = length else {
            return Err(AgentEffectOutboxError::DamagedSchema(name));
        };
        if !(0..=MAX_SCHEMA_SQL_BYTES).contains(&length) {
            return Err(AgentEffectOutboxError::SchemaSqlTooLarge {
                object: name,
                actual: length,
                maximum: MAX_SCHEMA_SQL_BYTES,
            });
        }
        let actual: String = connection.query_row(
            "SELECT substr(sql, 1, ?3) FROM sqlite_schema WHERE type = ?1 AND name = ?2",
            params![kind, name, MAX_SCHEMA_SQL_BYTES],
            |row| row.get(0),
        )?;
        if normalize_sql(&actual) != normalize_sql(expected) {
            return Err(AgentEffectOutboxError::DamagedSchema(name));
        }
    }
    Ok(())
}

fn validate_payload_columns(connection: &Connection) -> Result<(), AgentEffectOutboxError> {
    validate_columns(
        connection,
        "agent_effect_outbox_entries",
        &[
            ("sequence", "INTEGER", 1, 1),
            ("migration_id", "BLOB", 1, 0),
            ("destination_id", "BLOB", 1, 0),
            ("workspace_id", "BLOB", 1, 0),
            ("fact_kind", "INTEGER", 1, 0),
        ],
    )?;
    validate_foreign_key_tables(connection, "agent_effect_outbox_entries", &["workspace"])?;
    validate_columns(
        connection,
        "agent_effect_outbox_focus",
        &[
            ("outbox_sequence", "INTEGER", 1, 1),
            ("agent_id", "BLOB", 1, 0),
            ("activity_id", "BLOB", 1, 0),
            ("event_sequence", "INTEGER", 1, 0),
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
        "agent_effect_outbox_transitions",
        &[
            ("outbox_sequence", "INTEGER", 1, 1),
            ("event_id", "BLOB", 1, 0),
            ("workspace_id", "BLOB", 1, 0),
            ("activity_id", "BLOB", 1, 0),
            ("membership_revision", "INTEGER", 1, 0),
            ("event_kind", "INTEGER", 1, 0),
            ("from_agent_id", "BLOB", 0, 0),
            ("from_session_id", "BLOB", 0, 0),
            ("from_principal_kind", "INTEGER", 0, 0),
            ("from_principal_id", "BLOB", 0, 0),
            ("from_display_name", "TEXT", 0, 0),
            ("to_agent_id", "BLOB", 0, 0),
            ("to_session_id", "BLOB", 0, 0),
            ("to_principal_kind", "INTEGER", 0, 0),
            ("to_principal_id", "BLOB", 0, 0),
            ("to_display_name", "TEXT", 0, 0),
            ("before_goal_id", "BLOB", 0, 0),
            ("before_goal_revision", "INTEGER", 0, 0),
            ("before_dag_revision", "INTEGER", 0, 0),
            ("before_dag_head_revision", "INTEGER", 0, 0),
            ("before_head_id", "BLOB", 0, 0),
            ("before_head_revision", "INTEGER", 0, 0),
            ("after_goal_id", "BLOB", 0, 0),
            ("after_goal_revision", "INTEGER", 0, 0),
            ("after_dag_revision", "INTEGER", 0, 0),
            ("after_dag_head_revision", "INTEGER", 0, 0),
            ("after_head_id", "BLOB", 0, 0),
            ("after_head_revision", "INTEGER", 0, 0),
            ("before_coordinator_agent_id", "BLOB", 0, 0),
            ("before_coordinator_session_id", "BLOB", 0, 0),
            ("before_coordinator_revision", "INTEGER", 0, 0),
            ("after_coordinator_agent_id", "BLOB", 0, 0),
            ("after_coordinator_session_id", "BLOB", 0, 0),
            ("after_coordinator_revision", "INTEGER", 0, 0),
            ("observed_at_ms", "INTEGER", 1, 0),
        ],
    )?;
    validate_columns(
        connection,
        "agent_effect_outbox_recipients",
        &[
            ("outbox_sequence", "INTEGER", 1, 1),
            ("hint_index", "INTEGER", 1, 2),
            ("recipient_agent_id", "BLOB", 1, 0),
            ("recipient_session_id", "BLOB", 1, 0),
        ],
    )
}

fn validate_payload_foreign_keys(connection: &Connection) -> Result<(), AgentEffectOutboxError> {
    validate_foreign_key_tables(
        connection,
        "agent_effect_outbox_focus",
        &["agent_effect_outbox_entries"],
    )?;
    validate_foreign_key_tables(
        connection,
        "agent_effect_outbox_transitions",
        &["agent_effect_outbox_entries"],
    )?;
    validate_foreign_key_tables(
        connection,
        "agent_effect_outbox_recipients",
        &["agent_effect_outbox_entries"],
    )?;
    Ok(())
}

/// Append a full immutable `Focus` snapshot when the source `Workspace` is
/// delegated. The caller owns the transaction and commit; pre-v37 fixtures
/// remain legacy and therefore return without touching the outbox.
pub(crate) fn append_focus(
    connection: &Connection,
    event: &AgentFocusEvent,
) -> Result<(), AgentEffectOutboxError> {
    let Some(delegation) = source_delegation(connection, event.workspace_id())? else {
        return Ok(());
    };
    append_fact(
        connection,
        &delegation,
        &AgentEffectFact::Focus(event.clone()),
        &[],
    )
}

/// Append a full immutable transition snapshot and recipient hints when the
/// source `Workspace` is delegated. No legacy `AgentEvent` or inbox row is
/// written in this path.
pub(crate) fn append_transition(
    connection: &Connection,
    event: &AgentEvent,
    recipient_hints: &[(AgentInstanceId, AgentSessionId)],
) -> Result<(), AgentEffectOutboxError> {
    let Some(delegation) = source_delegation(connection, event.workspace_id())? else {
        return Ok(());
    };
    append_fact(
        connection,
        &delegation,
        &AgentEffectFact::Transition(Box::new(event.clone())),
        recipient_hints,
    )
}

/// Read at most one fixed-size source outbox page in one `SQLite` snapshot.
pub(crate) fn read(
    connection: &Connection,
    workspace_id: WorkspaceId,
    after: i64,
    limit: usize,
) -> Result<Vec<AgentEffectOutboxEntry>, AgentEffectOutboxError> {
    validate_workspace(workspace_id)?;
    if after < 0 {
        return Err(AgentEffectOutboxError::InvalidCursor);
    }
    let limit = limit.min(READ_PAGE_LIMIT);
    let transaction = connection.unchecked_transaction()?;
    let mut statement = transaction.prepare(
        "SELECT sequence FROM agent_effect_outbox_entries WHERE workspace_id = ?1 AND sequence > ?2 ORDER BY sequence ASC LIMIT ?3",
    )?;
    let rows = statement
        .query_map(
            params![
                workspace_id.into_uuid().as_bytes(),
                after,
                i64::try_from(limit).map_err(|_| AgentEffectOutboxError::IntegerOverflow)?
            ],
            |row| row.get::<_, i64>(0),
        )?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);
    let mut entries = Vec::with_capacity(rows.len());
    for sequence in rows {
        let entry = load_entry(&transaction, sequence)?;
        if entry.workspace_id() != workspace_id {
            return Err(AgentEffectOutboxError::CorruptRecord(
                "agent_effect_outbox_entries.workspace_id scope",
            ));
        }
        entries.push(entry);
    }
    transaction.commit()?;
    Ok(entries)
}

fn source_delegation(
    connection: &Connection,
    workspace_id: WorkspaceId,
) -> Result<
    Option<crate::workspace_agent_delegation::AgentOperationsDelegation>,
    AgentEffectOutboxError,
> {
    validate_workspace(workspace_id)?;
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version < crate::workspace_agent_delegation::AGENT_OPERATIONS_DELEGATION_SCHEMA_VERSION {
        return Ok(None);
    }
    crate::workspace_agent_delegation::get(connection, workspace_id).map_err(Into::into)
}

fn append_fact(
    connection: &Connection,
    delegation: &crate::workspace_agent_delegation::AgentOperationsDelegation,
    fact: &AgentEffectFact,
    recipient_hints: &[(AgentInstanceId, AgentSessionId)],
) -> Result<(), AgentEffectOutboxError> {
    if connection.is_autocommit() {
        return Err(AgentEffectOutboxError::MissingTransaction);
    }
    let workspace_id = delegation.workspace_id();
    validate_recipient_hints(recipient_hints)?;
    match fact {
        AgentEffectFact::Focus(event) if event.workspace_id() != workspace_id => {
            return Err(AgentEffectOutboxError::CorruptRecord(
                "agent_effect_outbox.focus.workspace_id",
            ));
        }
        AgentEffectFact::Transition(event) if event.workspace_id() != workspace_id => {
            return Err(AgentEffectOutboxError::CorruptRecord(
                "agent_effect_outbox.transition.workspace_id",
            ));
        }
        _ => {}
    }

    let existing_sequence = match fact {
        AgentEffectFact::Focus(event) => connection
            .query_row(
                "SELECT o.sequence FROM agent_effect_outbox_entries AS o JOIN agent_effect_outbox_focus AS f ON f.outbox_sequence = o.sequence WHERE o.fact_kind = 0 AND f.agent_id = ?1 AND f.event_sequence = ?2",
                params![
                    event.agent_id().into_uuid().as_bytes(),
                    event.sequence().get(),
                ],
                |row| row.get(0),
            )
            .optional()?,
        AgentEffectFact::Transition(event) => connection
            .query_row(
                "SELECT o.sequence FROM agent_effect_outbox_entries AS o JOIN agent_effect_outbox_transitions AS t ON t.outbox_sequence = o.sequence WHERE o.fact_kind = 1 AND t.event_id = ?1",
                params![
                    event.id().into_uuid().as_bytes(),
                ],
                |row| row.get(0),
            )
            .optional()?,
    };
    if let Some(sequence) = existing_sequence {
        let existing = load_entry(connection, sequence)?;
        if exact_replay(&existing, delegation, fact, recipient_hints) {
            return Ok(());
        }
        return Err(AgentEffectOutboxError::ReplayConflict);
    }

    let fact_kind = match fact {
        AgentEffectFact::Focus(_) => 0_i64,
        AgentEffectFact::Transition(_) => 1_i64,
    };
    connection.execute(
        "INSERT INTO agent_effect_outbox_entries (migration_id, destination_id, workspace_id, fact_kind) VALUES (?1, ?2, ?3, ?4)",
        params![
            delegation.migration_id().as_bytes(),
            delegation.destination_id().as_bytes(),
            workspace_id.into_uuid().as_bytes(),
            fact_kind,
        ],
    )?;
    let sequence: i64 = connection.query_row("SELECT last_insert_rowid()", [], |row| row.get(0))?;
    if sequence < 1 {
        return Err(AgentEffectOutboxError::CorruptRecord(
            "agent_effect_outbox_entries.sequence",
        ));
    }
    match fact {
        AgentEffectFact::Focus(event) => insert_focus_payload(connection, sequence, event)?,
        AgentEffectFact::Transition(event) => workspace_agent_events::insert_event_payload(
            connection,
            EventStorageTable::EffectOutbox,
            Some(sequence),
            event.as_ref(),
        )
        .map_err(|error| AgentEffectOutboxError::EventCodec(Box::new(error)))?,
    }
    for (hint_index, (agent_id, session_id)) in recipient_hints.iter().enumerate() {
        connection.execute(
            "INSERT INTO agent_effect_outbox_recipients (outbox_sequence, hint_index, recipient_agent_id, recipient_session_id) VALUES (?1, ?2, ?3, ?4)",
            params![
                sequence,
                i64::try_from(hint_index).map_err(|_| AgentEffectOutboxError::IntegerOverflow)?,
                agent_id.into_uuid().as_bytes(),
                session_id.into_uuid().as_bytes(),
            ],
        )?;
    }
    Ok(())
}

fn exact_replay(
    existing: &AgentEffectOutboxEntry,
    delegation: &crate::workspace_agent_delegation::AgentOperationsDelegation,
    fact: &AgentEffectFact,
    recipient_hints: &[(AgentInstanceId, AgentSessionId)],
) -> bool {
    existing.migration_id == delegation.migration_id()
        && existing.destination_id == delegation.destination_id()
        && existing.workspace_id == delegation.workspace_id()
        && existing.fact == *fact
        && existing.recipient_hints.as_slice() == recipient_hints
}

fn validate_workspace(workspace_id: WorkspaceId) -> Result<(), AgentEffectOutboxError> {
    if workspace_id.into_uuid().is_nil() {
        Err(AgentEffectOutboxError::InvalidWorkspace)
    } else {
        Ok(())
    }
}

fn validate_recipient_hints(
    recipient_hints: &[(AgentInstanceId, AgentSessionId)],
) -> Result<(), AgentEffectOutboxError> {
    if recipient_hints.len() > MAX_RECIPIENT_HINTS {
        return Err(AgentEffectOutboxError::TooManyRecipientHints {
            actual: recipient_hints.len(),
            maximum: MAX_RECIPIENT_HINTS,
        });
    }
    if recipient_hints.iter().any(|(agent_id, session_id)| {
        agent_id.into_uuid().is_nil() || session_id.into_uuid().is_nil()
    }) {
        return Err(AgentEffectOutboxError::InvalidRecipient);
    }
    Ok(())
}

fn insert_focus_payload(
    connection: &Connection,
    sequence: i64,
    event: &AgentFocusEvent,
) -> Result<(), AgentEffectOutboxError> {
    let (goal_id, goal_revision, dag_revision, node_id, node_revision) =
        encode_focus(event.focus());
    connection.execute(
        "INSERT INTO agent_effect_outbox_focus (outbox_sequence, agent_id, activity_id, event_sequence, event_kind, focus_goal_id, focus_goal_revision, focus_dag_revision, focus_node_id, focus_node_revision, observed_at_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            sequence,
            event.agent_id().into_uuid().as_bytes(),
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
        Some(goal.goal_id().into_uuid().into_bytes().to_vec()),
        Some(goal.expected_revision().get()),
        focus
            .dag_revision()
            .map(forge_domain::DagRevisionNumber::get),
        node.map(|value| value.node_id().into_uuid().into_bytes().to_vec()),
        node.map(|value| value.expected_revision().get()),
    )
}

fn encode_focus_event_kind(value: AgentFocusEventKind) -> i64 {
    match value {
        AgentFocusEventKind::Attached => 0,
        AgentFocusEventKind::Changed => 1,
        AgentFocusEventKind::Detached => 2,
    }
}

fn decode_focus_event_kind(value: i64) -> Result<AgentFocusEventKind, AgentEffectOutboxError> {
    match value {
        0 => Ok(AgentFocusEventKind::Attached),
        1 => Ok(AgentFocusEventKind::Changed),
        2 => Ok(AgentFocusEventKind::Detached),
        _ => Err(AgentEffectOutboxError::CorruptRecord(
            "agent_effect_outbox_focus.event_kind",
        )),
    }
}

fn load_entry(
    connection: &Connection,
    sequence: i64,
) -> Result<AgentEffectOutboxEntry, AgentEffectOutboxError> {
    let metadata = connection
        .query_row(OUTBOX_METADATA_QUERY, params![sequence], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })
        .optional()?
        .ok_or(AgentEffectOutboxError::CorruptRecord(
            "agent_effect_outbox_entries.sequence",
        ))?;
    let migration_id = decode_uuid(&metadata.0, "agent_effect_outbox_entries.migration_id")?;
    let destination_id = decode_uuid(&metadata.1, "agent_effect_outbox_entries.destination_id")?;
    let workspace_id = WorkspaceId::from_uuid(decode_uuid(
        &metadata.2,
        "agent_effect_outbox_entries.workspace_id",
    )?);
    let fact = match metadata.3 {
        0 => {
            let row = connection.query_row(FOCUS_PAYLOAD_QUERY, params![sequence], |row| {
                Ok(FocusRow::from_row(row))
            })??;
            AgentEffectFact::Focus(decode_focus_event(row, workspace_id)?)
        }
        1 => {
            let mut statement = connection.prepare(TRANSITION_PAYLOAD_QUERY)?;
            let mut rows = statement.query(params![sequence])?;
            let row = rows.next()?.ok_or(AgentEffectOutboxError::CorruptRecord(
                "agent_effect_outbox_transitions.payload",
            ))?;
            let event = workspace_agent_events::decode_event_at(row, 1)
                .map_err(|error| AgentEffectOutboxError::EventCodec(Box::new(error)))?;
            if event.workspace_id() != workspace_id {
                return Err(AgentEffectOutboxError::CorruptRecord(
                    "agent_effect_outbox_transitions.workspace_id",
                ));
            }
            AgentEffectFact::Transition(Box::new(event))
        }
        _ => {
            return Err(AgentEffectOutboxError::CorruptRecord(
                "agent_effect_outbox_entries.fact_kind",
            ));
        }
    };
    let recipient_hints = load_recipient_hints(connection, sequence)?;
    Ok(AgentEffectOutboxEntry {
        sequence,
        migration_id,
        destination_id,
        workspace_id,
        fact,
        recipient_hints,
    })
}

struct FocusRow {
    agent_id: Vec<u8>,
    activity_id: Vec<u8>,
    event_sequence: i64,
    event_kind: i64,
    focus_goal_id: Option<Vec<u8>>,
    focus_goal_revision: Option<i64>,
    focus_dag_revision: Option<i64>,
    focus_node_id: Option<Vec<u8>>,
    focus_node_revision: Option<i64>,
    observed_at_ms: i64,
}

impl FocusRow {
    fn from_row(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            agent_id: row.get(0)?,
            activity_id: row.get(1)?,
            event_sequence: row.get(2)?,
            event_kind: row.get(3)?,
            focus_goal_id: row.get(4)?,
            focus_goal_revision: row.get(5)?,
            focus_dag_revision: row.get(6)?,
            focus_node_id: row.get(7)?,
            focus_node_revision: row.get(8)?,
            observed_at_ms: row.get(9)?,
        })
    }
}

fn decode_focus_event(
    row: FocusRow,
    workspace_id: WorkspaceId,
) -> Result<AgentFocusEvent, AgentEffectOutboxError> {
    let agent_id = AgentInstanceId::from_uuid(decode_uuid(
        &row.agent_id,
        "agent_effect_outbox_focus.agent_id",
    )?);
    let activity_id = forge_domain::ActivityId::from_uuid(decode_uuid(
        &row.activity_id,
        "agent_effect_outbox_focus.activity_id",
    )?);
    let sequence = AgentFocusEventSequence::new(row.event_sequence).map_err(|_| {
        AgentEffectOutboxError::CorruptRecord("agent_effect_outbox_focus.event_sequence")
    })?;
    let focus = decode_focus(
        row.focus_goal_id,
        row.focus_goal_revision,
        row.focus_dag_revision,
        row.focus_node_id,
        row.focus_node_revision,
    )?;
    let observed_at = TimestampMillis::new(row.observed_at_ms).map_err(|_| {
        AgentEffectOutboxError::CorruptRecord("agent_effect_outbox_focus.observed_at_ms")
    })?;
    Ok(AgentFocusEvent::from_parts(
        agent_id,
        workspace_id,
        activity_id,
        sequence,
        decode_focus_event_kind(row.event_kind)?,
        focus,
        observed_at,
    ))
}

fn decode_focus(
    goal_id: Option<Vec<u8>>,
    goal_revision: Option<i64>,
    dag_revision: Option<i64>,
    node_id: Option<Vec<u8>>,
    node_revision: Option<i64>,
) -> Result<AgentFocus, AgentEffectOutboxError> {
    let goal = if let Some(value) = goal_id {
        Some(forge_domain::GoalAttribution::new(
            forge_domain::GoalId::from_uuid(decode_uuid(
                &value,
                "agent_effect_outbox_focus.focus_goal_id",
            )?),
            forge_domain::GoalRevision::new(goal_revision.ok_or(
                AgentEffectOutboxError::CorruptRecord(
                    "agent_effect_outbox_focus.focus_goal_revision",
                ),
            )?)
            .map_err(|_| {
                AgentEffectOutboxError::CorruptRecord(
                    "agent_effect_outbox_focus.focus_goal_revision",
                )
            })?,
        ))
    } else {
        if goal_revision.is_some() {
            return Err(AgentEffectOutboxError::CorruptRecord(
                "agent_effect_outbox_focus.focus_goal_revision",
            ));
        }
        None
    };
    let dag_revision = dag_revision
        .map(|value| {
            forge_domain::DagRevisionNumber::new(value).map_err(|_| {
                AgentEffectOutboxError::CorruptRecord(
                    "agent_effect_outbox_focus.focus_dag_revision",
                )
            })
        })
        .transpose()?;
    let node = if let Some(value) = node_id {
        Some(forge_domain::AgentFocusNode::new(
            forge_domain::DagNodeId::from_uuid(decode_uuid(
                &value,
                "agent_effect_outbox_focus.focus_node_id",
            )?),
            forge_domain::DagNodeRevision::new(node_revision.ok_or(
                AgentEffectOutboxError::CorruptRecord(
                    "agent_effect_outbox_focus.focus_node_revision",
                ),
            )?)
            .map_err(|_| {
                AgentEffectOutboxError::CorruptRecord(
                    "agent_effect_outbox_focus.focus_node_revision",
                )
            })?,
        ))
    } else {
        if node_revision.is_some() {
            return Err(AgentEffectOutboxError::CorruptRecord(
                "agent_effect_outbox_focus.focus_node_revision",
            ));
        }
        None
    };
    AgentFocus::new(goal, dag_revision, node)
        .map_err(|_| AgentEffectOutboxError::CorruptRecord("agent_effect_outbox_focus.focus"))
}

fn load_recipient_hints(
    connection: &Connection,
    sequence: i64,
) -> Result<Vec<(AgentInstanceId, AgentSessionId)>, AgentEffectOutboxError> {
    let mut statement = connection.prepare(RECIPIENT_HINTS_QUERY)?;
    let hint_limit = i64::try_from(MAX_RECIPIENT_HINTS + 1)
        .map_err(|_| AgentEffectOutboxError::IntegerOverflow)?;
    let mut rows = statement.query(params![sequence, hint_limit])?;
    let mut hints = Vec::new();
    while let Some(row) = rows.next()? {
        if hints.len() >= MAX_RECIPIENT_HINTS {
            return Err(AgentEffectOutboxError::TooManyRecipientHints {
                actual: MAX_RECIPIENT_HINTS + 1,
                maximum: MAX_RECIPIENT_HINTS,
            });
        }
        let agent = AgentInstanceId::from_uuid(decode_uuid(
            &row.get::<_, Vec<u8>>(0)?,
            "agent_effect_outbox_recipients.recipient_agent_id",
        )?);
        let session = AgentSessionId::from_uuid(decode_uuid(
            &row.get::<_, Vec<u8>>(1)?,
            "agent_effect_outbox_recipients.recipient_session_id",
        )?);
        hints.push((agent, session));
    }
    Ok(hints)
}

fn decode_uuid(value: &[u8], field: &'static str) -> Result<Uuid, AgentEffectOutboxError> {
    if value.len() != ID_BYTES {
        return Err(AgentEffectOutboxError::CorruptRecord(field));
    }
    let value =
        Uuid::from_slice(value).map_err(|_| AgentEffectOutboxError::CorruptRecord(field))?;
    if value.is_nil() {
        return Err(AgentEffectOutboxError::CorruptRecord(field));
    }
    Ok(value)
}

fn validate_columns(
    connection: &Connection,
    table: &'static str,
    expected: &[(&str, &str, i64, i64)],
) -> Result<(), AgentEffectOutboxError> {
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
    if actual.len() > MAX_SCHEMA_METADATA_ROWS
        || actual.len() != expected.len()
        || !actual.iter().zip(expected).all(
            |((name, data_type, not_null, primary_key), expected)| {
                name == expected.0
                    && data_type == expected.1
                    && *not_null == expected.2
                    && *primary_key == expected.3
            },
        )
    {
        return Err(AgentEffectOutboxError::DamagedSchema(table));
    }
    Ok(())
}

fn validate_foreign_key_tables(
    connection: &Connection,
    table: &'static str,
    expected: &[&str],
) -> Result<(), AgentEffectOutboxError> {
    let mut statement = connection.prepare(&format!("PRAGMA foreign_key_list({table})"))?;
    let mut rows = statement.query([])?;
    let mut actual = Vec::new();
    while let Some(row) = rows.next()? {
        if actual.len() >= MAX_SCHEMA_METADATA_ROWS {
            return Err(AgentEffectOutboxError::DamagedSchema(table));
        }
        actual.push(row.get::<_, String>(2)?);
    }
    actual.sort_unstable();
    let mut expected = expected
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<Vec<_>>();
    expected.sort_unstable();
    if actual != expected {
        return Err(AgentEffectOutboxError::DamagedSchema(table));
    }
    Ok(())
}

fn normalize_sql(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}
