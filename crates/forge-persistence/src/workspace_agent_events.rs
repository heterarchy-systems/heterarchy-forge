//! Workspace-local durable Agent participation events, presence, and inbox.
//!
//! Events are immutable facts. Inbox rows are durable per-recipient receipts;
//! reading them never acknowledges them. All functions in this module operate
//! inside the caller's short `SQLite` transaction and never perform filesystem,
//! process, or network work.

use forge_domain::{
    ActivityCoordinatorRevision, ActivityId, ActivityPresenceSnapshot, AgentEvent, AgentEventId,
    AgentEventKind, AgentEventListLimit, AgentInstanceId, AgentInstanceRevision,
    AgentMembershipRevision, AgentParticipantRef, AgentPresenceRevision, AgentSessionId,
    AuthenticatedPrincipal, CoordinationSnapshot, CoordinatorSnapshot, DagHeadRevision,
    DagRevisionNumber, InboxEntry, InboxReceiptRevision, PresenceCounts, PresencePartition,
    PresenceSnapshot, TimestampMillis, WorkspaceId,
};
use rusqlite::{
    Connection, OptionalExtension, Row, Transaction, params, params_from_iter, types::Value,
};
use thiserror::Error;
use uuid::Uuid;

const ID_BYTES: usize = 16;
const MAX_LABEL_BYTES: usize = forge_domain::MAX_AGENT_EVENT_TEXT_BYTES;

/// Closed set of durable tables that can carry the shared `AgentEvent` payload.
/// The legacy table keeps its existing membership/inbox semantics; the effect
/// outbox table is an immutable source-work snapshot and has no inbox side
/// effects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EventStorageTable {
    Legacy,
    EffectOutbox,
}

impl EventStorageTable {
    const fn name(self) -> &'static str {
        match self {
            Self::Legacy => "agent_events",
            Self::EffectOutbox => "agent_effect_outbox_transitions",
        }
    }

    const fn sequence_column(self) -> Option<&'static str> {
        match self {
            Self::Legacy => None,
            Self::EffectOutbox => Some("outbox_sequence"),
        }
    }
}

const EXPECTED_PRESENCE_TABLE_SQL: &str = "CREATE TABLE agent_presence (agent_id BLOB PRIMARY KEY NOT NULL CHECK(length(agent_id) = 16), workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16), activity_id BLOB NOT NULL REFERENCES activities(activity_id) CHECK(length(activity_id) = 16), session_id BLOB NOT NULL CHECK(length(session_id) = 16), last_authenticated_at_ms INTEGER NOT NULL CHECK(last_authenticated_at_ms >= 0), presence_revision INTEGER NOT NULL CHECK(presence_revision >= 1), UNIQUE(agent_id, workspace_id, activity_id), UNIQUE(activity_id, session_id), FOREIGN KEY(agent_id, workspace_id, activity_id) REFERENCES agent_instances(agent_id, workspace_id, activity_id))";
const EXPECTED_EVENTS_TABLE_SQL: &str = "CREATE TABLE agent_events (event_id BLOB PRIMARY KEY NOT NULL CHECK(length(event_id) = 16), workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16), activity_id BLOB NOT NULL REFERENCES activities(activity_id) CHECK(length(activity_id) = 16), membership_revision INTEGER NOT NULL CHECK(membership_revision >= 1), event_kind INTEGER NOT NULL CHECK(event_kind IN (0, 1, 2, 3, 4, 5)), from_agent_id BLOB CHECK(from_agent_id IS NULL OR length(from_agent_id) = 16), from_session_id BLOB CHECK(from_session_id IS NULL OR length(from_session_id) = 16), from_principal_kind INTEGER CHECK(from_principal_kind IS NULL OR from_principal_kind IN (0, 1, 2)), from_principal_id BLOB CHECK(from_principal_id IS NULL OR length(from_principal_id) = 16), from_display_name TEXT CHECK(from_display_name IS NULL OR length(CAST(from_display_name AS BLOB)) BETWEEN 1 AND 256), to_agent_id BLOB CHECK(to_agent_id IS NULL OR length(to_agent_id) = 16), to_session_id BLOB CHECK(to_session_id IS NULL OR length(to_session_id) = 16), to_principal_kind INTEGER CHECK(to_principal_kind IS NULL OR to_principal_kind IN (0, 1, 2)), to_principal_id BLOB CHECK(to_principal_id IS NULL OR length(to_principal_id) = 16), to_display_name TEXT CHECK(to_display_name IS NULL OR length(CAST(to_display_name AS BLOB)) BETWEEN 1 AND 256), before_goal_id BLOB CHECK(before_goal_id IS NULL OR length(before_goal_id) = 16), before_goal_revision INTEGER CHECK(before_goal_revision IS NULL OR before_goal_revision >= 1), before_dag_revision INTEGER CHECK(before_dag_revision IS NULL OR before_dag_revision >= 1), before_dag_head_revision INTEGER CHECK(before_dag_head_revision IS NULL OR before_dag_head_revision >= 1), before_head_id BLOB CHECK(before_head_id IS NULL OR length(before_head_id) = 16), before_head_revision INTEGER CHECK(before_head_revision IS NULL OR before_head_revision >= 1), after_goal_id BLOB CHECK(after_goal_id IS NULL OR length(after_goal_id) = 16), after_goal_revision INTEGER CHECK(after_goal_revision IS NULL OR after_goal_revision >= 1), after_dag_revision INTEGER CHECK(after_dag_revision IS NULL OR after_dag_revision >= 1), after_dag_head_revision INTEGER CHECK(after_dag_head_revision IS NULL OR after_dag_head_revision >= 1), after_head_id BLOB CHECK(after_head_id IS NULL OR length(after_head_id) = 16), after_head_revision INTEGER CHECK(after_head_revision IS NULL OR after_head_revision >= 1), before_coordinator_agent_id BLOB CHECK(before_coordinator_agent_id IS NULL OR length(before_coordinator_agent_id) = 16), before_coordinator_session_id BLOB CHECK(before_coordinator_session_id IS NULL OR length(before_coordinator_session_id) = 16), before_coordinator_revision INTEGER CHECK(before_coordinator_revision IS NULL OR before_coordinator_revision >= 1), after_coordinator_agent_id BLOB CHECK(after_coordinator_agent_id IS NULL OR length(after_coordinator_agent_id) = 16), after_coordinator_session_id BLOB CHECK(after_coordinator_session_id IS NULL OR length(after_coordinator_session_id) = 16), after_coordinator_revision INTEGER CHECK(after_coordinator_revision IS NULL OR after_coordinator_revision >= 1), observed_at_ms INTEGER NOT NULL CHECK(observed_at_ms >= 0), UNIQUE(activity_id, membership_revision))";
const EXPECTED_INBOX_TABLE_SQL: &str = "CREATE TABLE agent_inbox (recipient_agent_id BLOB NOT NULL CHECK(length(recipient_agent_id) = 16), recipient_session_id BLOB NOT NULL CHECK(length(recipient_session_id) = 16), event_id BLOB NOT NULL REFERENCES agent_events(event_id) CHECK(length(event_id) = 16), receipt_revision INTEGER NOT NULL CHECK(receipt_revision >= 1), acknowledged_at_ms INTEGER CHECK(acknowledged_at_ms IS NULL OR acknowledged_at_ms >= 0), PRIMARY KEY(recipient_agent_id, recipient_session_id, event_id), FOREIGN KEY(recipient_agent_id) REFERENCES agent_instances(agent_id))";
const EXPECTED_EVENTS_INDEX_SQL: &str = "CREATE INDEX agent_events_activity_revision_idx ON agent_events(activity_id, membership_revision DESC, event_id DESC)";
const EXPECTED_INBOX_INDEX_SQL: &str = "CREATE INDEX agent_inbox_recipient_revision_idx ON agent_inbox(recipient_agent_id, recipient_session_id, receipt_revision DESC, event_id DESC)";

const OBJECTS: [(&str, &str, &str); 5] = [
    ("table", "agent_presence", EXPECTED_PRESENCE_TABLE_SQL),
    ("table", "agent_events", EXPECTED_EVENTS_TABLE_SQL),
    ("table", "agent_inbox", EXPECTED_INBOX_TABLE_SQL),
    (
        "index",
        "agent_events_activity_revision_idx",
        EXPECTED_EVENTS_INDEX_SQL,
    ),
    (
        "index",
        "agent_inbox_recipient_revision_idx",
        EXPECTED_INBOX_INDEX_SQL,
    ),
];

pub(crate) fn create_schema(connection: &Connection) -> Result<(), AgentEventStoreError> {
    for (_, _, sql) in OBJECTS {
        connection.execute_batch(sql)?;
    }
    Ok(())
}

pub(crate) fn schema_objects() -> [(&'static str, &'static str); 5] {
    [
        ("table", "agent_presence"),
        ("table", "agent_events"),
        ("table", "agent_inbox"),
        ("index", "agent_events_activity_revision_idx"),
        ("index", "agent_inbox_recipient_revision_idx"),
    ]
}

pub(crate) fn validate_schema(connection: &Connection) -> Result<(), AgentEventStoreError> {
    for (kind, name, expected) in OBJECTS {
        let actual: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type = ?1 AND name = ?2",
                params![kind, name],
                |row| row.get(0),
            )
            .optional()?;
        if actual.as_deref().map(normalize_sql) != Some(normalize_sql(expected)) {
            return Err(AgentEventStoreError::DamagedSchema(name));
        }
    }
    validate_columns(
        connection,
        "agent_presence",
        &[
            ("agent_id", "BLOB", 1, 1),
            ("workspace_id", "BLOB", 1, 0),
            ("activity_id", "BLOB", 1, 0),
            ("session_id", "BLOB", 1, 0),
            ("last_authenticated_at_ms", "INTEGER", 1, 0),
            ("presence_revision", "INTEGER", 1, 0),
        ],
    )?;
    validate_columns(
        connection,
        "agent_events",
        &[
            ("event_id", "BLOB", 1, 1),
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
        "agent_inbox",
        &[
            ("recipient_agent_id", "BLOB", 1, 1),
            ("recipient_session_id", "BLOB", 1, 2),
            ("event_id", "BLOB", 1, 3),
            ("receipt_revision", "INTEGER", 1, 0),
            ("acknowledged_at_ms", "INTEGER", 0, 0),
        ],
    )?;
    validate_foreign_key_tables(
        connection,
        "agent_presence",
        &[
            "activities",
            "agent_instances",
            "agent_instances",
            "agent_instances",
            "workspace",
        ],
    )?;
    validate_foreign_key_tables(connection, "agent_events", &["activities", "workspace"])?;
    validate_foreign_key_tables(
        connection,
        "agent_inbox",
        &["agent_events", "agent_instances"],
    )
}

fn source_delegation(
    connection: &Connection,
    workspace_id: WorkspaceId,
) -> Result<
    Option<crate::workspace_agent_delegation::AgentOperationsDelegation>,
    AgentEventStoreError,
> {
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version < crate::workspace_agent_delegation::AGENT_OPERATIONS_DELEGATION_SCHEMA_VERSION {
        return Ok(None);
    }
    // Current-schema connections must have the delegation schema.  In
    // particular, do not turn a damaged v37 fixture into a legacy write path.
    crate::workspace_agent_delegation::get(connection, workspace_id)
        .map_err(AgentEventStoreError::from)
}

pub(crate) fn next_membership_revision(
    connection: &Connection,
    activity_id: ActivityId,
) -> Result<AgentMembershipRevision, AgentEventStoreError> {
    let legacy: Option<i64> = connection.query_row(
        "SELECT MAX(membership_revision) FROM agent_events WHERE activity_id = ?1",
        params![activity_id.into_uuid().as_bytes()],
        |row| row.get(0),
    )?;
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let outbox = if version
        < crate::workspace_agent_delegation::AGENT_OPERATIONS_DELEGATION_SCHEMA_VERSION
    {
        None
    } else {
        // The outbox schema is required for the current schema.  Any missing
        // table error is intentionally surfaced rather than falling back to
        // legacy state.
        connection.query_row(
            "SELECT MAX(membership_revision) FROM agent_effect_outbox_transitions WHERE activity_id = ?1",
            params![activity_id.into_uuid().as_bytes()],
            |row| row.get(0),
        )?
    };
    let current = match (legacy, outbox) {
        (Some(legacy), Some(outbox)) => Some(legacy.max(outbox)),
        (Some(legacy), None) => Some(legacy),
        (None, Some(outbox)) => Some(outbox),
        (None, None) => None,
    };
    AgentMembershipRevision::new(
        current
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(AgentEventStoreError::IntegerOverflow)?,
    )
    .map_err(|_| AgentEventStoreError::IntegerOverflow)
}

/// Stable local event identity for lifecycle transitions whose command did
/// not carry a caller nonce. The identity is a deterministic, domain-separated
/// digest over the complete `Agent` id, transition revision, and event kind;
/// lifecycle kinds must not be mixed by changing one byte of the `Agent` id.
pub(crate) fn derived_event_id(
    agent_id: AgentInstanceId,
    revision: AgentInstanceRevision,
    kind: AgentEventKind,
) -> AgentEventId {
    AgentEventId::for_transition(agent_id, revision, kind)
}

pub(crate) fn append_event_in_transaction(
    transaction: &Transaction<'_>,
    event: &AgentEvent,
    recipients: &[(AgentInstanceId, AgentSessionId)],
) -> Result<(), AgentEventStoreError> {
    if source_delegation(transaction, event.workspace_id())?.is_some() {
        let expected = next_membership_revision(transaction, event.activity_id())?;
        if event.membership_revision() != expected {
            return Err(AgentEventStoreError::MembershipRevisionConflict {
                expected,
                actual: event.membership_revision(),
            });
        }
        crate::workspace_agent_effect_outbox::append_transition(transaction, event, recipients)
            .map_err(|error| AgentEventStoreError::EffectOutbox(Box::new(error)))?;
        return Ok(());
    }
    crate::workspace_agent_migration::ensure_legacy_writes(transaction)?;
    let expected = next_membership_revision(transaction, event.activity_id())?;
    if event.membership_revision() != expected {
        return Err(AgentEventStoreError::MembershipRevisionConflict {
            expected,
            actual: event.membership_revision(),
        });
    }
    insert_event_payload(transaction, EventStorageTable::Legacy, None, event)?;
    for (agent_id, session_id) in recipients {
        insert_inbox_receipt(transaction, *agent_id, *session_id, event.id())?;
    }
    Ok(())
}

pub(crate) fn list_events(
    connection: &Connection,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    limit: AgentEventListLimit,
) -> Result<Vec<AgentEvent>, AgentEventStoreError> {
    let transaction = connection.unchecked_transaction()?;
    let mut statement = transaction.prepare(EVENTS_QUERY)?;
    let mut rows = statement.query(params![
        workspace_id.into_uuid().as_bytes(),
        activity_id.into_uuid().as_bytes(),
        limit.get(),
    ])?;
    let mut events = Vec::new();
    while let Some(row) = rows.next()? {
        events.push(decode_event(row)?);
    }
    drop(rows);
    drop(statement);
    transaction.commit()?;
    Ok(events)
}

/// Read persisted presence rows in exact `agent_id` BLOB order.  The export
/// helper deliberately reads the source table directly rather than projecting
/// current `Activity` liveness, so closed `Activity` rows and historical rows remain
/// visible to the frozen source export.
pub(crate) fn export_presence(
    connection: &Connection,
    workspace_id: WorkspaceId,
    after: Option<AgentInstanceId>,
    limit: u32,
) -> Result<Vec<crate::workspace_agent_migration::export::PresenceRow>, AgentEventStoreError> {
    let after_bytes = after.map(|value| value.into_uuid().into_bytes().to_vec());
    let mut statement = connection.prepare(EXPORT_PRESENCE_QUERY)?;
    let mut rows = statement.query(params![
        workspace_id.into_uuid().as_bytes(),
        after_bytes,
        limit,
    ])?;
    let mut presence = Vec::new();
    while let Some(row) = rows.next()? {
        let agent_id = AgentInstanceId::from_uuid(decode_uuid(
            &row.get::<_, Vec<u8>>(0)?,
            "agent_presence.agent_id",
        )?);
        let actual_workspace =
            decode_workspace_id(&row.get::<_, Vec<u8>>(1)?, "agent_presence.workspace_id")?;
        if actual_workspace != workspace_id {
            return Err(AgentEventStoreError::PresenceIdentityConflict);
        }
        let activity_id =
            decode_activity_id(&row.get::<_, Vec<u8>>(2)?, "agent_presence.activity_id")?;
        let session_id = AgentSessionId::from_uuid(decode_uuid(
            &row.get::<_, Vec<u8>>(3)?,
            "agent_presence.session_id",
        )?);
        let last_seen = decode_timestamp(row.get(4)?, "agent_presence.last_authenticated_at_ms")?;
        let revision = AgentPresenceRevision::new(row.get(5)?)
            .map_err(|_| AgentEventStoreError::CorruptRecord("agent_presence.presence_revision"))?;
        presence.push(crate::workspace_agent_migration::export::PresenceRow::new(
            agent_id,
            actual_workspace,
            activity_id,
            session_id,
            last_seen,
            revision,
        ));
    }
    Ok(presence)
}

/// Read immutable participation events in exact `event_id` BLOB order.
pub(crate) fn export_events(
    connection: &Connection,
    workspace_id: WorkspaceId,
    after: Option<AgentEventId>,
    limit: u32,
) -> Result<Vec<AgentEvent>, AgentEventStoreError> {
    let after_bytes = after.map(|value| value.into_uuid().into_bytes().to_vec());
    let mut statement = connection.prepare(EXPORT_EVENTS_QUERY)?;
    let mut rows = statement.query(params![
        workspace_id.into_uuid().as_bytes(),
        after_bytes,
        limit,
    ])?;
    let mut events = Vec::new();
    while let Some(row) = rows.next()? {
        let event = decode_event(row)?;
        if event.workspace_id() != workspace_id {
            return Err(AgentEventStoreError::CorruptRecord(
                "agent_events.workspace_id",
            ));
        }
        events.push(event);
    }
    Ok(events)
}

/// Read every durable inbox receipt, including acknowledged and detached
/// recipients, in exact `(recipient_agent_id, recipient_session_id, event_id)`
/// BLOB order.
pub(crate) fn export_inbox(
    connection: &Connection,
    workspace_id: WorkspaceId,
    after: Option<crate::workspace_agent_migration::export::AgentOperationsInboxKey>,
    limit: u32,
) -> Result<Vec<crate::workspace_agent_migration::export::InboxReceipt>, AgentEventStoreError> {
    let (after_agent, after_session, after_event) = after.map_or((None, None, None), |key| {
        (
            Some(key.recipient_agent_id().into_uuid().into_bytes().to_vec()),
            Some(key.recipient_session_id().into_uuid().into_bytes().to_vec()),
            Some(key.event_id().into_uuid().into_bytes().to_vec()),
        )
    });
    let mut statement = connection.prepare(EXPORT_INBOX_QUERY)?;
    let mut rows = statement.query(params![
        workspace_id.into_uuid().as_bytes(),
        after_agent,
        after_session,
        after_event,
        limit,
    ])?;
    let mut receipts = Vec::new();
    while let Some(row) = rows.next()? {
        let actual_workspace =
            decode_workspace_id(&row.get::<_, Vec<u8>>(5)?, "agent_events.workspace_id")?;
        if actual_workspace != workspace_id {
            return Err(AgentEventStoreError::CorruptRecord(
                "agent_events.workspace_id",
            ));
        }
        let key = crate::workspace_agent_migration::export::AgentOperationsInboxKey::new(
            AgentInstanceId::from_uuid(decode_uuid(
                &row.get::<_, Vec<u8>>(0)?,
                "agent_inbox.recipient_agent_id",
            )?),
            AgentSessionId::from_uuid(decode_uuid(
                &row.get::<_, Vec<u8>>(1)?,
                "agent_inbox.recipient_session_id",
            )?),
            decode_event_id(&row.get::<_, Vec<u8>>(2)?, "agent_inbox.event_id")?,
        );
        let revision = InboxReceiptRevision::new(row.get(3)?)
            .map_err(|_| AgentEventStoreError::CorruptRecord("agent_inbox.receipt_revision"))?;
        let acknowledged_at = row
            .get::<_, Option<i64>>(4)?
            .map(|value| decode_timestamp(value, "agent_inbox.acknowledged_at_ms"))
            .transpose()?;
        receipts.push(crate::workspace_agent_migration::export::InboxReceipt::new(
            key,
            revision,
            acknowledged_at,
        ));
    }
    Ok(receipts)
}

pub(crate) fn list_inbox(
    connection: &Connection,
    workspace_id: WorkspaceId,
    recipient_agent_id: AgentInstanceId,
    recipient_session_id: AgentSessionId,
    limit: u32,
) -> Result<Vec<InboxEntry>, AgentEventStoreError> {
    let transaction = connection.unchecked_transaction()?;
    let mut statement = transaction.prepare(INBOX_QUERY)?;
    let mut rows = statement.query(params![
        workspace_id.into_uuid().as_bytes(),
        recipient_agent_id.into_uuid().as_bytes(),
        recipient_session_id.into_uuid().as_bytes(),
        limit,
    ])?;
    let mut entries = Vec::new();
    while let Some(row) = rows.next()? {
        let event = decode_event_at(row, 5)?;
        entries.push(InboxEntry::new(
            decode_participant_at(row, 0, 1, 2, 3, 4)?
                .ok_or(AgentEventStoreError::CorruptRecord("agent_inbox.recipient"))?,
            event,
            InboxReceiptRevision::new(row.get(5 + EVENT_COLUMN_COUNT)?)
                .map_err(|_| AgentEventStoreError::CorruptRecord("agent_inbox.receipt_revision"))?,
            row.get::<_, Option<i64>>(6 + EVENT_COLUMN_COUNT)?
                .map(|value| decode_timestamp(value, "agent_inbox.acknowledged_at_ms"))
                .transpose()?,
        ));
    }
    drop(rows);
    drop(statement);
    transaction.commit()?;
    Ok(entries)
}

/// Read one atomic bounded participant aggregate. Participant rows are capped
/// at 64 while counts are queried independently in the same transaction, so
/// truncation cannot manufacture an incomplete count or liveness claim.
pub(crate) fn list_presence(
    connection: &Connection,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
) -> Result<ActivityPresenceSnapshot, AgentEventStoreError> {
    let transaction = connection.unchecked_transaction()?;
    let membership_revision = transaction
        .query_row(
            "SELECT MAX(membership_revision) FROM agent_events WHERE workspace_id = ?1 AND activity_id = ?2",
            params![workspace_id.into_uuid().as_bytes(), activity_id.into_uuid().as_bytes()],
            |row| row.get::<_, Option<i64>>(0),
        )?
        .map(|value| AgentMembershipRevision::new(value).map_err(|_| AgentEventStoreError::CorruptRecord("agent_events.membership_revision")))
        .transpose()?;
    let activity_state: i64 = transaction
        .query_row(
            "SELECT state FROM activities WHERE activity_id = ?1 AND workspace_id = ?2",
            params![
                activity_id.into_uuid().as_bytes(),
                workspace_id.into_uuid().as_bytes()
            ],
            |row| row.get(0),
        )
        .optional()?
        .ok_or(AgentEventStoreError::ActivityNotFound(activity_id))?;
    let coordinator = coordinator_snapshot_for_activity(&transaction, activity_id)?;
    let aggregate = presence_aggregate(
        &transaction,
        workspace_id,
        activity_id,
        activity_state,
        coordinator,
    )?;
    let participants = load_presence_participants(
        &transaction,
        workspace_id,
        activity_id,
        activity_state == 1,
        coordinator,
        membership_revision,
    )?;
    let snapshot = ActivityPresenceSnapshot::new(
        workspace_id,
        activity_id,
        membership_revision,
        coordinator,
        participants,
        aggregate.counts,
        aggregate.unread_count,
        aggregate.unread_join_count,
    )
    .map_err(|_| AgentEventStoreError::CorruptRecord("agent_presence.snapshot"))?;
    transaction.commit()?;
    Ok(snapshot)
}

struct PresenceAggregate {
    counts: PresenceCounts,
    unread_count: u32,
    unread_join_count: u32,
}

fn presence_aggregate(
    connection: &Connection,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    activity_state: i64,
    coordinator: CoordinatorSnapshot,
) -> Result<PresenceAggregate, AgentEventStoreError> {
    let (unread_count, unread_join_count) = match (
        activity_state == 1,
        coordinator.agent_id(),
        coordinator.session_id(),
    ) {
        (true, Some(agent_id), Some(session_id)) => (
            count_unread(
                connection,
                workspace_id,
                activity_id,
                agent_id,
                session_id,
                None,
            )?,
            count_unread(
                connection,
                workspace_id,
                activity_id,
                agent_id,
                session_id,
                Some(AgentEventKind::Joined),
            )?,
        ),
        _ => (0, 0),
    };
    let current_coordinator_count = if activity_state == 1 {
        coordinator.agent_id().map_or(Ok(0), |agent_id| {
            count_agents(
                connection,
                "ai.session_id IS NOT NULL AND ai.attachment_state = 0 AND ai.agent_id = ?3",
                workspace_id,
                activity_id,
                Some(agent_id),
            )
        })?
    } else {
        0
    };
    let bound_attached_count = count_agents(
        connection,
        "ai.session_id IS NOT NULL AND ai.attachment_state = 0",
        workspace_id,
        activity_id,
        None,
    )?;
    let closed_activity = if activity_state == 1 {
        0
    } else {
        bound_attached_count
    };
    let attached_participants = bound_attached_count
        .checked_sub(current_coordinator_count)
        .and_then(|count| count.checked_sub(closed_activity))
        .ok_or(AgentEventStoreError::IntegerOverflow)?;
    let unresolved_legacy = count_agents(
        connection,
        "ai.session_id IS NULL",
        workspace_id,
        activity_id,
        None,
    )?;
    let handed_off = count_agents(
        connection,
        "ai.session_id IS NOT NULL AND ai.attachment_state = 1 AND EXISTS (SELECT 1 FROM agent_events AS h WHERE h.activity_id = ai.activity_id AND h.event_kind = 3 AND h.from_agent_id = ai.agent_id AND h.from_session_id = ai.session_id)",
        workspace_id,
        activity_id,
        None,
    )?;
    let detached_total = count_agents(
        connection,
        "ai.session_id IS NOT NULL AND ai.attachment_state = 1",
        workspace_id,
        activity_id,
        None,
    )?;
    let detached = detached_total
        .checked_sub(handed_off)
        .ok_or(AgentEventStoreError::IntegerOverflow)?;
    Ok(PresenceAggregate {
        counts: PresenceCounts::new(
            current_coordinator_count,
            closed_activity,
            attached_participants,
            handed_off,
            detached,
            unresolved_legacy,
        ),
        unread_count,
        unread_join_count,
    })
}

fn load_presence_participants(
    connection: &Connection,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    activity_is_open: bool,
    coordinator: CoordinatorSnapshot,
    membership_revision: Option<AgentMembershipRevision>,
) -> Result<Vec<PresenceSnapshot>, AgentEventStoreError> {
    let mut statement = connection.prepare(PRESENCE_QUERY)?;
    let mut rows = statement.query(params![
        workspace_id.into_uuid().as_bytes(),
        activity_id.into_uuid().as_bytes(),
        AgentEventListLimit::DEFAULT.get(),
    ])?;
    let membership_revision = membership_revision.unwrap_or(AgentMembershipRevision::INITIAL);
    let mut participants = Vec::new();
    while let Some(row) = rows.next()? {
        participants.push(decode_presence_row(
            row,
            workspace_id,
            activity_id,
            coordinator,
            activity_is_open,
            membership_revision,
        )?);
    }
    drop(rows);
    drop(statement);
    Ok(participants)
}

fn count_agents(
    connection: &Connection,
    predicate: &'static str,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    agent_id: Option<AgentInstanceId>,
) -> Result<u32, AgentEventStoreError> {
    let count: i64 = if let Some(agent_id) = agent_id {
        connection.query_row(
            &format!(
                "SELECT COUNT(*) FROM agent_instances AS ai WHERE ai.workspace_id = ?1 AND ai.activity_id = ?2 AND {predicate}"
            ),
            params![
                workspace_id.into_uuid().as_bytes(),
                activity_id.into_uuid().as_bytes(),
                agent_id.into_uuid().as_bytes()
            ],
            |row| row.get(0),
        )?
    } else {
        connection.query_row(
            &format!(
                "SELECT COUNT(*) FROM agent_instances AS ai WHERE ai.workspace_id = ?1 AND ai.activity_id = ?2 AND {predicate}"
            ),
            params![
                workspace_id.into_uuid().as_bytes(),
                activity_id.into_uuid().as_bytes()
            ],
            |row| row.get(0),
        )?
    };
    count
        .try_into()
        .map_err(|_| AgentEventStoreError::IntegerOverflow)
}

fn count_unread(
    connection: &Connection,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    agent_id: AgentInstanceId,
    session_id: AgentSessionId,
    kind: Option<AgentEventKind>,
) -> Result<u32, AgentEventStoreError> {
    let count: i64 = match kind {
        Some(kind) => connection.query_row(
            "SELECT COUNT(*) FROM agent_inbox AS i JOIN agent_events AS e ON e.event_id = i.event_id WHERE e.workspace_id = ?1 AND e.activity_id = ?2 AND e.event_kind = ?3 AND i.recipient_agent_id = ?4 AND i.recipient_session_id = ?5 AND i.acknowledged_at_ms IS NULL",
            params![
                workspace_id.into_uuid().as_bytes(),
                activity_id.into_uuid().as_bytes(),
                encode_event_kind(kind),
                agent_id.into_uuid().as_bytes(),
                session_id.into_uuid().as_bytes(),
            ],
            |row| row.get(0),
        )?,
        None => connection.query_row(
            "SELECT COUNT(*) FROM agent_inbox AS i JOIN agent_events AS e ON e.event_id = i.event_id WHERE e.workspace_id = ?1 AND e.activity_id = ?2 AND i.recipient_agent_id = ?3 AND i.recipient_session_id = ?4 AND i.acknowledged_at_ms IS NULL",
            params![
                workspace_id.into_uuid().as_bytes(),
                activity_id.into_uuid().as_bytes(),
                agent_id.into_uuid().as_bytes(),
                session_id.into_uuid().as_bytes(),
            ],
            |row| row.get(0),
        )?,
    };
    count
        .try_into()
        .map_err(|_| AgentEventStoreError::IntegerOverflow)
}

fn decode_presence_row(
    row: &Row<'_>,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    coordinator: CoordinatorSnapshot,
    activity_is_open: bool,
    membership_revision: AgentMembershipRevision,
) -> Result<PresenceSnapshot, AgentEventStoreError> {
    let agent_id = AgentInstanceId::from_uuid(decode_uuid(
        &row.get::<_, Vec<u8>>(0)?,
        "agent_presence.agent_id",
    )?);
    let session_id = row
        .get::<_, Option<Vec<u8>>>(1)?
        .map(|value| decode_uuid(&value, "agent_instances.session_id"))
        .transpose()?
        .map(AgentSessionId::from_uuid);
    let principal = decode_principal(row.get(2)?, row.get(3)?)?;
    let display_name = forge_domain::AgentDisplayName::new(row.get(4)?)
        .map_err(|_| AgentEventStoreError::CorruptRecord("agent_instances.display_name"))?;
    let attachment_state: i64 = row.get(5)?;
    let agent_revision = AgentInstanceRevision::new(row.get(6)?)
        .map_err(|_| AgentEventStoreError::CorruptRecord("agent_instances.revision"))?;
    let presence_revision = row
        .get::<_, Option<i64>>(7)?
        .map(|value| {
            AgentPresenceRevision::new(value).map_err(|_| {
                AgentEventStoreError::CorruptRecord("agent_presence.presence_revision")
            })
        })
        .transpose()?;
    let last_authenticated_at = row
        .get::<_, Option<i64>>(8)?
        .map(|value| decode_timestamp(value, "agent_presence.last_authenticated_at_ms"))
        .transpose()?;
    let partition = match session_id {
        None => PresencePartition::UnresolvedLegacy,
        Some(_session_id) if attachment_state == 0 && !activity_is_open => {
            PresencePartition::ClosedActivity
        }
        Some(_session_id) if attachment_state == 0 => {
            if coordinator.agent_id() == Some(agent_id) {
                PresencePartition::CurrentCoordinator
            } else {
                PresencePartition::AttachedParticipant
            }
        }
        Some(_session_id) => {
            let handed_off: bool = row.get(9)?;
            if handed_off {
                PresencePartition::HandedOff
            } else {
                PresencePartition::Detached
            }
        }
    };
    let (presence_revision, last_authenticated_at) = match session_id {
        None => (AgentPresenceRevision::INITIAL, None),
        Some(_) => (
            presence_revision.ok_or(AgentEventStoreError::PresenceMissing(agent_id))?,
            last_authenticated_at,
        ),
    };
    Ok(PresenceSnapshot::new(
        workspace_id,
        activity_id,
        agent_id,
        session_id,
        principal,
        display_name,
        partition,
        agent_revision,
        membership_revision,
        presence_revision,
        last_authenticated_at,
    ))
}

fn insert_inbox_receipt(
    transaction: &Transaction<'_>,
    recipient_agent_id: AgentInstanceId,
    recipient_session_id: AgentSessionId,
    event_id: AgentEventId,
) -> Result<(), AgentEventStoreError> {
    transaction.execute(
        "INSERT INTO agent_inbox (recipient_agent_id, recipient_session_id, event_id, receipt_revision, acknowledged_at_ms) VALUES (?1, ?2, ?3, ?4, NULL)",
        params![
            recipient_agent_id.into_uuid().as_bytes(),
            recipient_session_id.into_uuid().as_bytes(),
            event_id.into_uuid().as_bytes(),
            InboxReceiptRevision::INITIAL.get(),
        ],
    )?;
    Ok(())
}

fn coordinator_snapshot_for_activity(
    connection: &Connection,
    activity_id: ActivityId,
) -> Result<CoordinatorSnapshot, AgentEventStoreError> {
    let row: Option<(Vec<u8>, i64, Option<Vec<u8>>)> = connection
        .query_row(
            "SELECT c.agent_id, c.revision, ai.session_id FROM activity_coordinators AS c JOIN agent_instances AS ai ON ai.agent_id = c.agent_id WHERE c.activity_id = ?1",
            params![activity_id.into_uuid().as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((agent, revision, session)) = row else {
        return Ok(CoordinatorSnapshot::unbound());
    };
    let session = session
        .map(|value| decode_uuid(&value, "coordinator.session_id"))
        .transpose()?;
    Ok(CoordinatorSnapshot::bound(
        AgentInstanceId::from_uuid(decode_uuid(&agent, "coordinator.agent_id")?),
        session.map(AgentSessionId::from_uuid),
        ActivityCoordinatorRevision::new(revision)
            .map_err(|_| AgentEventStoreError::CorruptRecord("coordinator.revision"))?,
    ))
}

pub(crate) fn coordination_snapshot_for_agent(
    connection: &Connection,
    agent: &forge_domain::RegisteredAgentInstance,
) -> Result<CoordinationSnapshot, AgentEventStoreError> {
    let focus = agent.focus();
    let dag_head_revision = match (focus.goal(), focus.dag_revision()) {
        (Some(goal), Some(_)) => connection
            .query_row(
                "SELECT head_revision FROM goal_dag_heads WHERE goal_id = ?1",
                params![goal.goal_id().into_uuid().as_bytes()],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .map(|value| {
                forge_domain::DagHeadRevision::new(value).map_err(|_| {
                    AgentEventStoreError::CorruptRecord("goal_dag_heads.head_revision")
                })
            })
            .transpose()?,
        _ => None,
    };
    CoordinationSnapshot::new(
        focus.goal(),
        focus.dag_revision(),
        dag_head_revision,
        focus.node(),
    )
    .map_err(|_| AgentEventStoreError::CorruptRecord("agent.focus"))
}

/// Re-read the `Activity`'s durable current `Goal`/`DAG`/head and verify that an
/// `Agent`'s optional node focus still belongs to that exact plan. Stored focus
/// is only an attribution hint; a replan can advance the DAG/head without
/// touching every Agent row, so handoff admission must use this fresh query.
pub(crate) fn current_coordination_snapshot(
    connection: &Connection,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    agent: &forge_domain::RegisteredAgentInstance,
) -> Result<CoordinationSnapshot, AgentEventStoreError> {
    let current_goal: Option<(Vec<u8>, i64)> = connection
        .query_row(
            "SELECT goal_id, revision FROM goals WHERE workspace_id = ?1 AND activity_id = ?2 AND state = 0 ORDER BY updated_at_ms DESC, goal_id DESC LIMIT 1",
            params![workspace_id.into_uuid().as_bytes(), activity_id.into_uuid().as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((goal_id, goal_revision)) = current_goal else {
        if !agent.focus().is_unfocused() {
            return Err(AgentEventStoreError::CoordinationStale);
        }
        return Ok(CoordinationSnapshot::empty());
    };
    let goal_id = forge_domain::GoalId::from_uuid(decode_uuid(&goal_id, "goals.goal_id")?);
    let goal_revision = forge_domain::GoalRevision::new(goal_revision)
        .map_err(|_| AgentEventStoreError::CorruptRecord("goals.revision"))?;
    let goal = forge_domain::GoalAttribution::new(goal_id, goal_revision);
    let dag_head: Option<(i64, i64)> = connection
        .query_row(
            "SELECT dag_revision, head_revision FROM goal_dag_heads WHERE goal_id = ?1",
            params![goal_id.into_uuid().as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((dag_revision, dag_head_revision)) = dag_head else {
        if agent.focus().goal() != Some(goal) || agent.focus().dag_revision().is_some() {
            return Err(AgentEventStoreError::CoordinationStale);
        }
        return CoordinationSnapshot::new(Some(goal), None, None, None)
            .map_err(|_| AgentEventStoreError::CorruptRecord("agent_events.coordination"));
    };
    let dag_revision = forge_domain::DagRevisionNumber::new(dag_revision)
        .map_err(|_| AgentEventStoreError::CorruptRecord("goal_dag_heads.dag_revision"))?;
    let dag_head_revision = forge_domain::DagHeadRevision::new(dag_head_revision)
        .map_err(|_| AgentEventStoreError::CorruptRecord("goal_dag_heads.head_revision"))?;
    let focus = agent.focus();
    if let Some(focus_goal) = focus.goal()
        && (focus_goal != goal || focus.dag_revision() != Some(dag_revision))
    {
        return Err(AgentEventStoreError::CoordinationStale);
    }
    if focus.goal().is_none() && (focus.dag_revision().is_some() || focus.node().is_some()) {
        return Err(AgentEventStoreError::CoordinationStale);
    }
    if let Some(node) = focus.node() {
        let actual_node_revision: Option<i64> = connection
            .query_row(
                "SELECT node_revision FROM goal_dag_nodes WHERE goal_id = ?1 AND dag_revision = ?2 AND node_id = ?3",
                params![goal_id.into_uuid().as_bytes(), dag_revision.get(), node.node_id().into_uuid().as_bytes()],
                |row| row.get(0),
            )
            .optional()?;
        if actual_node_revision != Some(node.expected_revision().get()) {
            return Err(AgentEventStoreError::CoordinationStale);
        }
    }
    CoordinationSnapshot::new(
        Some(goal),
        Some(dag_revision),
        Some(dag_head_revision),
        focus.node(),
    )
    .map_err(|_| AgentEventStoreError::CorruptRecord("agent_events.coordination"))
}

#[derive(Default)]
struct EncodedParticipant {
    agent_id: Option<Vec<u8>>,
    session_id: Option<Vec<u8>>,
    principal_kind: Option<i64>,
    principal_id: Option<Vec<u8>>,
    display_name: Option<String>,
}

fn encode_participant(
    participant: Option<&AgentParticipantRef>,
) -> Result<EncodedParticipant, AgentEventStoreError> {
    let Some(participant) = participant else {
        return Ok(EncodedParticipant::default());
    };
    let (principal_kind, principal_id) = encode_principal(participant.principal());
    if participant.display_name().byte_len() > MAX_LABEL_BYTES {
        return Err(AgentEventStoreError::MetadataTooLarge);
    }
    Ok(EncodedParticipant {
        agent_id: Some(participant.agent_id().into_uuid().as_bytes().to_vec()),
        session_id: participant
            .session_id()
            .map(|value| value.into_uuid().as_bytes().to_vec()),
        principal_kind: Some(principal_kind),
        principal_id,
        display_name: Some(participant.display_name().as_str().to_owned()),
    })
}

type EncodedCoordination = (
    (Option<Vec<u8>>, Option<i64>),
    Option<i64>,
    Option<i64>,
    (Option<Vec<u8>>, Option<i64>),
);

fn encode_coordination(snapshot: CoordinationSnapshot) -> EncodedCoordination {
    let goal = snapshot.goal().map_or((None, None), |value| {
        (
            Some(value.goal_id().into_uuid().as_bytes().to_vec()),
            Some(value.expected_revision().get()),
        )
    });
    let head = snapshot.node().map_or((None, None), |value| {
        (
            Some(value.node_id().into_uuid().as_bytes().to_vec()),
            Some(value.expected_revision().get()),
        )
    });
    (
        goal,
        snapshot.dag_revision().map(DagRevisionNumber::get),
        snapshot.dag_head_revision().map(DagHeadRevision::get),
        head,
    )
}

fn encode_coordinator(
    snapshot: CoordinatorSnapshot,
) -> (Option<Vec<u8>>, Option<Vec<u8>>, Option<i64>) {
    (
        snapshot
            .agent_id()
            .map(|value| value.into_uuid().as_bytes().to_vec()),
        snapshot
            .session_id()
            .map(|value| value.into_uuid().as_bytes().to_vec()),
        snapshot.revision().map(ActivityCoordinatorRevision::get),
    )
}

const EVENT_COLUMN_LIST: &str = "event_id, workspace_id, activity_id, membership_revision, event_kind, from_agent_id, from_session_id, from_principal_kind, from_principal_id, from_display_name, to_agent_id, to_session_id, to_principal_kind, to_principal_id, to_display_name, before_goal_id, before_goal_revision, before_dag_revision, before_dag_head_revision, before_head_id, before_head_revision, after_goal_id, after_goal_revision, after_dag_revision, after_dag_head_revision, after_head_id, after_head_revision, before_coordinator_agent_id, before_coordinator_session_id, before_coordinator_revision, after_coordinator_agent_id, after_coordinator_session_id, after_coordinator_revision, observed_at_ms";
const EVENT_VALUE_LIST: &str = "?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?";

/// Insert the complete immutable `AgentEvent` payload into one of the two
/// closed event storage tables.  The outbox table prefixes the same payload
/// with its owned sequence; all 34 event fields remain encoded in one place.
pub(crate) fn insert_event_payload(
    connection: &Connection,
    table: EventStorageTable,
    sequence: Option<i64>,
    event: &AgentEvent,
) -> Result<(), AgentEventStoreError> {
    let expected_sequence = table.sequence_column().is_some();
    if expected_sequence != sequence.is_some() {
        return Err(AgentEventStoreError::CorruptRecord(
            "agent event storage sequence",
        ));
    }
    let mut values = Vec::with_capacity(if expected_sequence { 35 } else { 34 });
    if let Some(sequence) = sequence {
        if sequence < 1 {
            return Err(AgentEventStoreError::CorruptRecord(
                "agent_effect_outbox.sequence",
            ));
        }
        values.push(Value::Integer(sequence));
    }
    values.extend(event_values(event)?);
    let sql = if expected_sequence {
        format!(
            "INSERT INTO {} (outbox_sequence, {}) VALUES (?, {})",
            table.name(),
            EVENT_COLUMN_LIST,
            EVENT_VALUE_LIST
        )
    } else {
        format!(
            "INSERT INTO {} ({}) VALUES ({})",
            table.name(),
            EVENT_COLUMN_LIST,
            EVENT_VALUE_LIST
        )
    };
    connection.execute(&sql, params_from_iter(values.iter()))?;
    Ok(())
}

fn event_values(event: &AgentEvent) -> Result<Vec<Value>, AgentEventStoreError> {
    let (from, to) = (
        encode_participant(event.from())?,
        encode_participant(event.to())?,
    );
    let (before_goal, before_dag, before_dag_head, before_head) =
        encode_coordination(event.coordination_before());
    let (after_goal, after_dag, after_dag_head, after_head) =
        encode_coordination(event.coordination_after());
    let (before_coordinator_agent, before_coordinator_session, before_coordinator_revision) =
        encode_coordinator(event.coordinator_before());
    let (after_coordinator_agent, after_coordinator_session, after_coordinator_revision) =
        encode_coordinator(event.coordinator_after());
    Ok(vec![
        Value::Blob(event.id().into_uuid().into_bytes().to_vec()),
        Value::Blob(event.workspace_id().into_uuid().into_bytes().to_vec()),
        Value::Blob(event.activity_id().into_uuid().into_bytes().to_vec()),
        Value::Integer(event.membership_revision().get()),
        Value::Integer(encode_event_kind(event.kind())),
        value_blob(from.agent_id),
        value_blob(from.session_id),
        value_integer(from.principal_kind),
        value_blob(from.principal_id),
        value_text(from.display_name),
        value_blob(to.agent_id),
        value_blob(to.session_id),
        value_integer(to.principal_kind),
        value_blob(to.principal_id),
        value_text(to.display_name),
        value_blob(before_goal.0),
        value_integer(before_goal.1),
        value_integer(before_dag),
        value_integer(before_dag_head),
        value_blob(before_head.0),
        value_integer(before_head.1),
        value_blob(after_goal.0),
        value_integer(after_goal.1),
        value_integer(after_dag),
        value_integer(after_dag_head),
        value_blob(after_head.0),
        value_integer(after_head.1),
        value_blob(before_coordinator_agent),
        value_blob(before_coordinator_session),
        value_integer(before_coordinator_revision),
        value_blob(after_coordinator_agent),
        value_blob(after_coordinator_session),
        value_integer(after_coordinator_revision),
        Value::Integer(event.observed_at().get()),
    ])
}

fn value_blob(value: Option<Vec<u8>>) -> Value {
    value.map_or(Value::Null, Value::Blob)
}

fn value_integer(value: Option<i64>) -> Value {
    value.map_or(Value::Null, Value::Integer)
}

fn value_text(value: Option<String>) -> Value {
    value.map_or(Value::Null, Value::Text)
}

fn encode_principal(value: AuthenticatedPrincipal) -> (i64, Option<Vec<u8>>) {
    match value {
        AuthenticatedPrincipal::TrustedStdio => (0, None),
        AuthenticatedPrincipal::DirectToken(id) => (1, Some(id.into_uuid().as_bytes().to_vec())),
        AuthenticatedPrincipal::OAuthGrant(id) => (2, Some(id.into_uuid().as_bytes().to_vec())),
    }
}

fn decode_event(row: &Row<'_>) -> Result<AgentEvent, AgentEventStoreError> {
    decode_event_at(row, 0)
}

const EVENT_COLUMN_COUNT: usize = 34;

pub(crate) fn decode_event_at(
    row: &Row<'_>,
    offset: usize,
) -> Result<AgentEvent, AgentEventStoreError> {
    let event_id_bytes: Vec<u8> = row.get(offset)?;
    let workspace_id_bytes: Vec<u8> = row.get(offset + 1)?;
    let activity_id_bytes: Vec<u8> = row.get(offset + 2)?;
    let event_id = decode_event_id(&event_id_bytes, "agent_events.event_id")?;
    let workspace_id = decode_workspace_id(&workspace_id_bytes, "agent_events.workspace_id")?;
    let activity_id = decode_activity_id(&activity_id_bytes, "agent_events.activity_id")?;
    let membership_revision = AgentMembershipRevision::new(row.get(offset + 3)?)
        .map_err(|_| AgentEventStoreError::CorruptRecord("agent_events.membership_revision"))?;
    let kind = decode_event_kind(row.get(offset + 4)?)?;
    let from = decode_participant_at(
        row,
        offset + 5,
        offset + 6,
        offset + 7,
        offset + 8,
        offset + 9,
    )?;
    let to = decode_participant_at(
        row,
        offset + 10,
        offset + 11,
        offset + 12,
        offset + 13,
        offset + 14,
    )?;
    let before = decode_coordination(row, offset + 15)?;
    let after = decode_coordination(row, offset + 21)?;
    let before_coordinator = decode_coordinator(row, offset + 27)?;
    let after_coordinator = decode_coordinator(row, offset + 30)?;
    Ok(AgentEvent::new(
        event_id,
        workspace_id,
        activity_id,
        membership_revision,
        kind,
        from,
        to,
        before,
        after,
        before_coordinator,
        after_coordinator,
        decode_timestamp(row.get(offset + 33)?, "agent_events.observed_at_ms")?,
    ))
}

fn decode_participant_at(
    row: &Row<'_>,
    agent_offset: usize,
    session_offset: usize,
    principal_kind_offset: usize,
    principal_id_offset: usize,
    display_name_offset: usize,
) -> Result<Option<AgentParticipantRef>, AgentEventStoreError> {
    let agent: Option<Vec<u8>> = row.get(agent_offset)?;
    let session: Option<Vec<u8>> = row.get(session_offset)?;
    let principal_kind: Option<i64> = row.get(principal_kind_offset)?;
    let principal_id: Option<Vec<u8>> = row.get(principal_id_offset)?;
    let display_name: Option<String> = row.get(display_name_offset)?;
    let Some(agent) = agent else {
        if session.is_some()
            || principal_kind.is_some()
            || principal_id.is_some()
            || display_name.is_some()
        {
            return Err(AgentEventStoreError::CorruptRecord(
                "agent_events.participant",
            ));
        }
        return Ok(None);
    };
    let display_name: String = display_name.ok_or(AgentEventStoreError::CorruptRecord(
        "agent_events.display_name",
    ))?;
    if display_name.len() > MAX_LABEL_BYTES {
        return Err(AgentEventStoreError::MetadataTooLarge);
    }
    let principal = decode_principal(
        principal_kind.ok_or(AgentEventStoreError::CorruptRecord(
            "agent_events.principal_kind",
        ))?,
        principal_id,
    )?;
    Ok(Some(AgentParticipantRef::new(
        AgentInstanceId::from_uuid(decode_uuid(&agent, "agent_events.agent_id")?),
        session
            .map(|value| decode_uuid(&value, "agent_events.session_id"))
            .transpose()?
            .map(AgentSessionId::from_uuid),
        principal,
        forge_domain::AgentDisplayName::new(display_name)
            .map_err(|_| AgentEventStoreError::CorruptRecord("agent_events.display_name"))?,
    )))
}

fn decode_coordination(
    row: &Row<'_>,
    offset: usize,
) -> Result<CoordinationSnapshot, AgentEventStoreError> {
    let goal_id: Option<Vec<u8>> = row.get(offset)?;
    let goal_revision: Option<i64> = row.get(offset + 1)?;
    let dag_revision: Option<i64> = row.get(offset + 2)?;
    let dag_head_revision: Option<i64> = row.get(offset + 3)?;
    let head_id: Option<Vec<u8>> = row.get(offset + 4)?;
    let head_revision: Option<i64> = row.get(offset + 5)?;
    let goal = goal_id
        .map(|value| {
            Ok::<forge_domain::GoalAttribution, AgentEventStoreError>(
                forge_domain::GoalAttribution::new(
                    forge_domain::GoalId::from_uuid(decode_uuid(&value, "agent_events.goal_id")?),
                    forge_domain::GoalRevision::new(goal_revision.ok_or(
                        AgentEventStoreError::CorruptRecord("agent_events.goal_revision"),
                    )?)
                    .map_err(|_| {
                        AgentEventStoreError::CorruptRecord("agent_events.goal_revision")
                    })?,
                ),
            )
        })
        .transpose()?;
    let dag_revision = dag_revision
        .map(|value| {
            forge_domain::DagRevisionNumber::new(value)
                .map_err(|_| AgentEventStoreError::CorruptRecord("agent_events.dag_revision"))
        })
        .transpose()?;
    let head = head_id
        .map(|value| {
            Ok::<forge_domain::AgentFocusNode, AgentEventStoreError>(
                forge_domain::AgentFocusNode::new(
                    forge_domain::DagNodeId::from_uuid(decode_uuid(
                        &value,
                        "agent_events.head_id",
                    )?),
                    forge_domain::DagNodeRevision::new(head_revision.ok_or(
                        AgentEventStoreError::CorruptRecord("agent_events.head_revision"),
                    )?)
                    .map_err(|_| {
                        AgentEventStoreError::CorruptRecord("agent_events.head_revision")
                    })?,
                ),
            )
        })
        .transpose()?;
    let dag_head_revision = dag_head_revision
        .map(|value| {
            forge_domain::DagHeadRevision::new(value)
                .map_err(|_| AgentEventStoreError::CorruptRecord("agent_events.dag_head_revision"))
        })
        .transpose()?;
    CoordinationSnapshot::new(goal, dag_revision, dag_head_revision, head)
        .map_err(|_| AgentEventStoreError::CorruptRecord("agent_events.coordination"))
}

fn decode_coordinator(
    row: &Row<'_>,
    offset: usize,
) -> Result<CoordinatorSnapshot, AgentEventStoreError> {
    let agent: Option<Vec<u8>> = row.get(offset)?;
    let session: Option<Vec<u8>> = row.get(offset + 1)?;
    let revision: Option<i64> = row.get(offset + 2)?;
    match (agent, session, revision) {
        (None, None, None) => Ok(CoordinatorSnapshot::unbound()),
        (Some(agent), session, Some(revision)) => Ok(CoordinatorSnapshot::bound(
            AgentInstanceId::from_uuid(decode_uuid(&agent, "agent_events.coordinator_agent_id")?),
            session
                .map(|value| decode_uuid(&value, "agent_events.coordinator_session_id"))
                .transpose()?
                .map(AgentSessionId::from_uuid),
            ActivityCoordinatorRevision::new(revision).map_err(|_| {
                AgentEventStoreError::CorruptRecord("agent_events.coordinator_revision")
            })?,
        )),
        _ => Err(AgentEventStoreError::CorruptRecord(
            "agent_events.coordinator",
        )),
    }
}

fn decode_principal(
    kind: i64,
    identifier: Option<Vec<u8>>,
) -> Result<AuthenticatedPrincipal, AgentEventStoreError> {
    match (kind, identifier) {
        (0, None) => Ok(AuthenticatedPrincipal::TrustedStdio),
        (1, Some(value)) => Ok(AuthenticatedPrincipal::DirectToken(
            forge_domain::DirectTokenId::from_uuid(decode_uuid(&value, "principal_id")?),
        )),
        (2, Some(value)) => Ok(AuthenticatedPrincipal::OAuthGrant(
            forge_domain::OAuthGrantId::from_uuid(decode_uuid(&value, "principal_id")?),
        )),
        _ => Err(AgentEventStoreError::CorruptRecord("principal")),
    }
}

fn decode_event_kind(value: i64) -> Result<AgentEventKind, AgentEventStoreError> {
    match value {
        0 => Ok(AgentEventKind::Joined),
        1 => Ok(AgentEventKind::Left),
        2 => Ok(AgentEventKind::HandoffStarted),
        3 => Ok(AgentEventKind::HandoffCompleted),
        4 => Ok(AgentEventKind::FocusChanged),
        5 => Ok(AgentEventKind::RoleChanged),
        _ => Err(AgentEventStoreError::CorruptRecord(
            "agent_events.event_kind",
        )),
    }
}

fn encode_event_kind(value: AgentEventKind) -> i64 {
    match value {
        AgentEventKind::Joined => 0,
        AgentEventKind::Left => 1,
        AgentEventKind::HandoffStarted => 2,
        AgentEventKind::HandoffCompleted => 3,
        AgentEventKind::FocusChanged => 4,
        AgentEventKind::RoleChanged => 5,
    }
}

fn decode_timestamp(
    value: i64,
    field: &'static str,
) -> Result<TimestampMillis, AgentEventStoreError> {
    TimestampMillis::new(value).map_err(|_| AgentEventStoreError::CorruptRecord(field))
}

fn decode_event_id(
    value: &[u8],
    field: &'static str,
) -> Result<AgentEventId, AgentEventStoreError> {
    Ok(AgentEventId::from_uuid(decode_uuid(value, field)?))
}

fn decode_workspace_id(
    value: &[u8],
    field: &'static str,
) -> Result<WorkspaceId, AgentEventStoreError> {
    Ok(WorkspaceId::from_uuid(decode_uuid(value, field)?))
}

fn decode_activity_id(
    value: &[u8],
    field: &'static str,
) -> Result<ActivityId, AgentEventStoreError> {
    Ok(ActivityId::from_uuid(decode_uuid(value, field)?))
}

fn decode_uuid(value: &[u8], field: &'static str) -> Result<Uuid, AgentEventStoreError> {
    if value.len() != ID_BYTES {
        return Err(AgentEventStoreError::CorruptRecord(field));
    }
    Uuid::from_slice(value).map_err(|_| AgentEventStoreError::CorruptRecord(field))
}

fn validate_columns(
    connection: &Connection,
    table: &'static str,
    expected: &[(&str, &str, i64, i64)],
) -> Result<(), AgentEventStoreError> {
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
        return Err(AgentEventStoreError::DamagedSchema(table));
    }
    Ok(())
}

fn validate_foreign_key_tables(
    connection: &Connection,
    table: &'static str,
    expected: &[&str],
) -> Result<(), AgentEventStoreError> {
    let mut statement = connection.prepare(&format!("PRAGMA foreign_key_list({table})"))?;
    let mut rows = statement.query([])?;
    let mut actual = Vec::new();
    while let Some(row) = rows.next()? {
        actual.push(row.get::<_, String>(2)?);
    }
    actual.sort_unstable();
    let mut expected = expected
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<Vec<_>>();
    expected.sort_unstable();
    if actual != expected {
        return Err(AgentEventStoreError::DamagedSchema(table));
    }
    Ok(())
}

fn normalize_sql(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

const EVENTS_QUERY: &str = "SELECT event_id, workspace_id, activity_id, membership_revision, event_kind, from_agent_id, from_session_id, from_principal_kind, from_principal_id, from_display_name, to_agent_id, to_session_id, to_principal_kind, to_principal_id, to_display_name, before_goal_id, before_goal_revision, before_dag_revision, before_dag_head_revision, before_head_id, before_head_revision, after_goal_id, after_goal_revision, after_dag_revision, after_dag_head_revision, after_head_id, after_head_revision, before_coordinator_agent_id, before_coordinator_session_id, before_coordinator_revision, after_coordinator_agent_id, after_coordinator_session_id, after_coordinator_revision, observed_at_ms FROM agent_events WHERE workspace_id = ?1 AND activity_id = ?2 ORDER BY membership_revision DESC, event_id DESC LIMIT ?3";
const EXPORT_PRESENCE_QUERY: &str = "SELECT substr(agent_id,1,17), substr(workspace_id,1,17), substr(activity_id,1,17), substr(session_id,1,17), last_authenticated_at_ms, presence_revision FROM agent_presence WHERE workspace_id = ?1 AND (?2 IS NULL OR agent_id > ?2) ORDER BY agent_id ASC LIMIT ?3";
const EXPORT_EVENTS_QUERY: &str = "SELECT substr(event_id,1,17), substr(workspace_id,1,17), substr(activity_id,1,17), membership_revision, event_kind, substr(from_agent_id,1,17), substr(from_session_id,1,17), from_principal_kind, substr(from_principal_id,1,17), substr(from_display_name,1,257), substr(to_agent_id,1,17), substr(to_session_id,1,17), to_principal_kind, substr(to_principal_id,1,17), substr(to_display_name,1,257), substr(before_goal_id,1,17), before_goal_revision, before_dag_revision, before_dag_head_revision, substr(before_head_id,1,17), before_head_revision, substr(after_goal_id,1,17), after_goal_revision, after_dag_revision, after_dag_head_revision, substr(after_head_id,1,17), after_head_revision, substr(before_coordinator_agent_id,1,17), substr(before_coordinator_session_id,1,17), before_coordinator_revision, substr(after_coordinator_agent_id,1,17), substr(after_coordinator_session_id,1,17), after_coordinator_revision, observed_at_ms FROM agent_events WHERE workspace_id = ?1 AND (?2 IS NULL OR event_id > ?2) ORDER BY event_id ASC LIMIT ?3";
const EXPORT_INBOX_QUERY: &str = "SELECT substr(i.recipient_agent_id,1,17), substr(i.recipient_session_id,1,17), substr(i.event_id,1,17), i.receipt_revision, i.acknowledged_at_ms, substr(e.workspace_id,1,17) FROM agent_inbox AS i JOIN agent_events AS e ON e.event_id = i.event_id WHERE e.workspace_id = ?1 AND ((?2 IS NULL AND ?3 IS NULL AND ?4 IS NULL) OR (i.recipient_agent_id, i.recipient_session_id, i.event_id) > (?2, ?3, ?4)) ORDER BY i.recipient_agent_id ASC, i.recipient_session_id ASC, i.event_id ASC LIMIT ?5";
const PRESENCE_QUERY: &str = "SELECT ai.agent_id, ai.session_id, ai.principal_kind, ai.principal_id, ai.display_name, ai.attachment_state, ai.revision, p.presence_revision, p.last_authenticated_at_ms, EXISTS(SELECT 1 FROM agent_events AS h WHERE h.activity_id = ai.activity_id AND h.event_kind = 3 AND h.from_agent_id = ai.agent_id AND h.from_session_id = ai.session_id) FROM agent_instances AS ai LEFT JOIN agent_presence AS p ON p.agent_id = ai.agent_id AND p.session_id = ai.session_id WHERE ai.workspace_id = ?1 AND ai.activity_id = ?2 ORDER BY CASE WHEN ai.session_id IS NOT NULL AND ai.attachment_state = 0 AND (SELECT state FROM activities WHERE activity_id = ai.activity_id) = 1 AND ai.agent_id = (SELECT c.agent_id FROM activity_coordinators AS c WHERE c.activity_id = ai.activity_id) THEN 0 WHEN ai.session_id IS NOT NULL AND ai.attachment_state = 0 AND (SELECT state FROM activities WHERE activity_id = ai.activity_id) != 1 THEN 1 WHEN ai.session_id IS NOT NULL AND ai.attachment_state = 0 THEN 2 WHEN ai.session_id IS NOT NULL AND ai.attachment_state = 1 THEN 3 ELSE 4 END, ai.updated_at_ms DESC, ai.agent_id DESC LIMIT ?3";
const INBOX_QUERY: &str = "SELECT i.recipient_agent_id, i.recipient_session_id, ai.principal_kind, ai.principal_id, ai.display_name, e.event_id, e.workspace_id, e.activity_id, e.membership_revision, e.event_kind, e.from_agent_id, e.from_session_id, e.from_principal_kind, e.from_principal_id, e.from_display_name, e.to_agent_id, e.to_session_id, e.to_principal_kind, e.to_principal_id, e.to_display_name, e.before_goal_id, e.before_goal_revision, e.before_dag_revision, e.before_dag_head_revision, e.before_head_id, e.before_head_revision, e.after_goal_id, e.after_goal_revision, e.after_dag_revision, e.after_dag_head_revision, e.after_head_id, e.after_head_revision, e.before_coordinator_agent_id, e.before_coordinator_session_id, e.before_coordinator_revision, e.after_coordinator_agent_id, e.after_coordinator_session_id, e.after_coordinator_revision, e.observed_at_ms, i.receipt_revision, i.acknowledged_at_ms FROM agent_inbox AS i JOIN agent_events AS e ON e.event_id = i.event_id JOIN agent_instances AS ai ON ai.agent_id = i.recipient_agent_id WHERE e.workspace_id = ?1 AND i.recipient_agent_id = ?2 AND i.recipient_session_id = ?3 ORDER BY CASE WHEN i.acknowledged_at_ms IS NULL THEN 0 ELSE 1 END, e.membership_revision DESC, e.event_id DESC LIMIT ?4";

#[derive(Debug, Error)]
pub enum AgentEventStoreError {
    #[error(transparent)]
    OperationsMigration(#[from] crate::AgentOperationsMigrationError),
    #[error(transparent)]
    OperationsDelegation(#[from] crate::workspace_agent_delegation::AgentOperationsDelegationError),
    #[error("Agent effect outbox write failed: {0}")]
    EffectOutbox(#[source] Box<crate::workspace_agent_effect_outbox::AgentEffectOutboxError>),
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error("Agent event schema object is damaged: {0}")]
    DamagedSchema(&'static str),
    #[error("Agent event record is corrupt: {0}")]
    CorruptRecord(&'static str),
    #[error("Agent event metadata exceeds the bounded limit")]
    MetadataTooLarge,
    #[error("Agent event membership revision conflict: expected {expected}, actual {actual}")]
    MembershipRevisionConflict {
        expected: AgentMembershipRevision,
        actual: AgentMembershipRevision,
    },
    #[error("Agent event integer value overflowed")]
    IntegerOverflow,
    #[error("Unresolved legacy Agent {0} has no session binding")]
    UnresolvedLegacy(AgentInstanceId),
    #[error("Activity {0} was not found")]
    ActivityNotFound(ActivityId),
    #[error("Agent inbox receipt is missing")]
    ReceiptMissing,
    #[error("Agent inbox receipt revision conflicts")]
    ReceiptRevisionConflict,
    #[error("Agent presence row is missing for {0}")]
    PresenceMissing(AgentInstanceId),
    #[error("Agent presence identity conflicts")]
    PresenceIdentityConflict,
    #[error("Agent presence revision conflicts")]
    PresenceRevisionConflict,
    #[error("Agent {0} is detached and cannot touch presence")]
    PresenceDetached(AgentInstanceId),
    #[error("Agent {0} is detached and cannot acknowledge inbox receipts")]
    RecipientDetached(AgentInstanceId),
    #[error("Agent presence timestamp precedes the stored observation")]
    TimestampOrder,
    #[error("Agent Goal/DAG/head observation is stale")]
    CoordinationStale,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derived_lifecycle_event_ids_are_stable_and_domain_separated() {
        let first = AgentInstanceId::from_uuid(Uuid::from_u128(0xA010));
        let adjacent = AgentInstanceId::from_uuid(Uuid::from_u128(0xA011));
        let revision = AgentInstanceRevision::INITIAL;
        let joined = AgentEventId::for_transition(first, revision, AgentEventKind::Joined);
        assert_eq!(
            joined,
            AgentEventId::for_transition(first, revision, AgentEventKind::Joined)
        );
        assert_ne!(
            joined,
            AgentEventId::for_transition(first, revision, AgentEventKind::Left)
        );
        assert_ne!(
            AgentEventId::for_transition(first, revision, AgentEventKind::Left),
            AgentEventId::for_transition(adjacent, revision, AgentEventKind::Joined)
        );
        assert_ne!(joined, AgentEventId::for_handoff_completed(joined));
    }

    #[test]
    fn null_event_participant_id_with_side_fields_is_corrupt()
    -> Result<(), Box<dyn std::error::Error>> {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE workspace (workspace_id BLOB PRIMARY KEY NOT NULL);
             CREATE TABLE activities (activity_id BLOB PRIMARY KEY NOT NULL, workspace_id BLOB NOT NULL);
             CREATE TABLE agent_instances (agent_id BLOB PRIMARY KEY NOT NULL);",
        )?;
        create_schema(&connection)?;
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(1));
        let activity_id = ActivityId::from_uuid(Uuid::from_u128(2));
        connection.execute(
            "INSERT INTO workspace (workspace_id) VALUES (?1)",
            params![workspace_id.into_uuid().as_bytes()],
        )?;
        connection.execute(
            "INSERT INTO activities (activity_id, workspace_id) VALUES (?1, ?2)",
            params![
                activity_id.into_uuid().as_bytes(),
                workspace_id.into_uuid().as_bytes()
            ],
        )?;
        connection.execute(
            "INSERT INTO agent_events (event_id, workspace_id, activity_id, membership_revision, event_kind, from_session_id, observed_at_ms) VALUES (?1, ?2, ?3, 1, 0, ?4, 1)",
            params![
                Uuid::from_u128(3).as_bytes(),
                workspace_id.into_uuid().as_bytes(),
                activity_id.into_uuid().as_bytes(),
                Uuid::from_u128(4).as_bytes(),
            ],
        )?;
        assert!(matches!(
            list_events(
                &connection,
                workspace_id,
                activity_id,
                AgentEventListLimit::DEFAULT,
            ),
            Err(AgentEventStoreError::CorruptRecord(
                "agent_events.participant"
            ))
        ));
        Ok(())
    }
}
