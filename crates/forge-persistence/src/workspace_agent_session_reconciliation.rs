//! Delegated reconciliation of a legacy Agent's Forge-owned effect-session binding.
//!
//! This transition is valid only after Agent operations were delegated to
//! Orchestration. It mutates only the minimal Forge effect binding and records
//! an immutable receipt in the same `SQLite` transaction. Presence, membership
//! events, inbox, role metadata, focus, Coordinator state, and work updates are
//! deliberately outside this module.

use forge_domain::{
    ActivityId, AgentAttachmentState, AgentInstanceId, AgentInstanceRevision,
    AgentInstanceRevisionError, AgentSessionId, AuthenticatedPrincipal, BindExistingAgentSession,
    TimestampMillis, WorkspaceId,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    workspace_agent_delegation::{self, AgentOperationsDelegation, AgentOperationsDelegationError},
    workspace_agents::{self, AgentStoreError},
};

pub(crate) const AGENT_SESSION_RECONCILIATION_SCHEMA_VERSION: i64 = 38;
const ID_BYTES: usize = 16;
const MAX_SCHEMA_SQL_BYTES: i64 = 16 * 1024;
const MAX_SCHEMA_METADATA_ROWS: usize = 64;
const TABLE: &str = "agent_session_reconciliations";
const TABLE_SQL: &str = "CREATE TABLE agent_session_reconciliations (request_id BLOB PRIMARY KEY NOT NULL CHECK(length(request_id) = 16 AND request_id != zeroblob(16)), migration_id BLOB NOT NULL REFERENCES agent_operations_delegations(migration_id) CHECK(length(migration_id) = 16 AND migration_id != zeroblob(16)), workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16 AND workspace_id != zeroblob(16)), destination_id BLOB NOT NULL CHECK(length(destination_id) = 16 AND destination_id != zeroblob(16)), activity_id BLOB NOT NULL REFERENCES activities(activity_id) CHECK(length(activity_id) = 16 AND activity_id != zeroblob(16)), agent_id BLOB NOT NULL CHECK(length(agent_id) = 16 AND agent_id != zeroblob(16)), session_id BLOB NOT NULL CHECK(length(session_id) = 16 AND session_id != zeroblob(16)), expected_agent_revision INTEGER NOT NULL CHECK(expected_agent_revision >= 1), result_agent_revision INTEGER NOT NULL CHECK(result_agent_revision = expected_agent_revision + 1), reconciled_at_ms INTEGER NOT NULL CHECK(reconciled_at_ms >= 0), UNIQUE(workspace_id, agent_id), UNIQUE(workspace_id, activity_id, session_id), FOREIGN KEY(agent_id, workspace_id, activity_id) REFERENCES agent_instances(agent_id, workspace_id, activity_id))";

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentSessionReconciliationRequest {
    request_id: Uuid,
    command: BindExistingAgentSession,
}

impl AgentSessionReconciliationRequest {
    pub fn new(
        request_id: Uuid,
        command: BindExistingAgentSession,
    ) -> Result<Self, AgentSessionReconciliationError> {
        if request_id.is_nil() {
            return Err(AgentSessionReconciliationError::InvalidRequestId);
        }
        Ok(Self {
            request_id,
            command,
        })
    }

    pub const fn request_id(self) -> Uuid {
        self.request_id
    }

    pub const fn command(self) -> BindExistingAgentSession {
        self.command
    }
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentSessionReconciliation {
    request_id: Uuid,
    migration_id: Uuid,
    destination_id: Uuid,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    agent_id: AgentInstanceId,
    session_id: AgentSessionId,
    expected_agent_revision: AgentInstanceRevision,
    result_agent_revision: AgentInstanceRevision,
    reconciled_at: TimestampMillis,
}

impl AgentSessionReconciliation {
    pub const fn request_id(self) -> Uuid {
        self.request_id
    }
    pub const fn migration_id(self) -> Uuid {
        self.migration_id
    }
    pub const fn destination_id(self) -> Uuid {
        self.destination_id
    }
    pub const fn workspace_id(self) -> WorkspaceId {
        self.workspace_id
    }
    pub const fn activity_id(self) -> ActivityId {
        self.activity_id
    }
    pub const fn agent_id(self) -> AgentInstanceId {
        self.agent_id
    }
    pub const fn session_id(self) -> AgentSessionId {
        self.session_id
    }
    pub const fn expected_agent_revision(self) -> AgentInstanceRevision {
        self.expected_agent_revision
    }
    pub const fn result_agent_revision(self) -> AgentInstanceRevision {
        self.result_agent_revision
    }
    pub const fn reconciled_at(self) -> TimestampMillis {
        self.reconciled_at
    }
}

#[derive(Debug, Error)]
pub enum AgentSessionReconciliationError {
    #[error("Agent session reconciliation request identity is nil")]
    InvalidRequestId,
    #[error("Agent operations delegation for Workspace {0} is missing")]
    DelegationMissing(WorkspaceId),
    #[error("Agent operations delegation for Workspace {0} is stale")]
    StaleDelegation(WorkspaceId),
    #[error("Agent session reconciliation command targets a different Workspace")]
    WorkspaceMismatch,
    #[error("Agent session reconciliation timestamp predates source delegation")]
    TimestampOrder,
    #[error("Agent session reconciliation request conflicts with durable state")]
    RequestConflict,
    #[error("Agent session reconciliation receipt is corrupt: {0}")]
    CorruptRecord(&'static str),
    #[error("Agent session reconciliation schema is damaged")]
    DamagedSchema,
    #[error("Agent session reconciliation schema metadata exceeds {0} rows")]
    SchemaMetadataTooLarge(usize),
    #[error("Agent session reconciliation schema SQL is {actual} bytes; maximum is {maximum}")]
    SchemaSqlTooLarge { actual: i64, maximum: i64 },
    #[error(
        "Agent session reconciliation {request_id} commit is unconfirmed; read the same request identity"
    )]
    CommitUnconfirmed {
        request_id: Uuid,
        #[source]
        source: rusqlite::Error,
    },
    #[error(transparent)]
    Delegation(#[from] AgentOperationsDelegationError),
    #[error(transparent)]
    Agent(#[from] AgentStoreError),
    #[error(transparent)]
    AgentRevision(#[from] AgentInstanceRevisionError),
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
}

pub(crate) fn create_schema(
    connection: &Connection,
) -> Result<(), AgentSessionReconciliationError> {
    connection.execute_batch(TABLE_SQL)?;
    Ok(())
}

pub(crate) fn schema_objects() -> Vec<(&'static str, &'static str)> {
    vec![("table", TABLE)]
}

pub(crate) fn validate_schema(
    connection: &Connection,
) -> Result<(), AgentSessionReconciliationError> {
    let length = connection
        .query_row(
            "SELECT length(CAST(sql AS BLOB)) FROM sqlite_schema WHERE type='table' AND name=?1",
            params![TABLE],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .ok_or(AgentSessionReconciliationError::DamagedSchema)?;
    if !(0..=MAX_SCHEMA_SQL_BYTES).contains(&length) {
        return Err(AgentSessionReconciliationError::SchemaSqlTooLarge {
            actual: length,
            maximum: MAX_SCHEMA_SQL_BYTES,
        });
    }
    let actual: String = connection.query_row(
        "SELECT sql FROM sqlite_schema WHERE type='table' AND name=?1",
        params![TABLE],
        |row| row.get(0),
    )?;
    if i64::try_from(actual.len()).ok() != Some(length)
        || normalize_sql(&actual) != normalize_sql(TABLE_SQL)
    {
        return Err(AgentSessionReconciliationError::DamagedSchema);
    }
    validate_columns(connection)?;
    validate_foreign_keys(connection)
}

pub(crate) fn reconcile(
    connection: &mut Connection,
    delegation: &AgentOperationsDelegation,
    request: AgentSessionReconciliationRequest,
) -> Result<AgentSessionReconciliation, AgentSessionReconciliationError> {
    let command = request.command();
    if command.workspace_id() != delegation.workspace_id() {
        return Err(AgentSessionReconciliationError::WorkspaceMismatch);
    }
    if command.observed_at().get() < delegation.delegated_at().get() {
        return Err(AgentSessionReconciliationError::TimestampOrder);
    }

    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    validate_schema(&transaction)?;
    let current_delegation =
        workspace_agent_delegation::get(&transaction, delegation.workspace_id())?.ok_or(
            AgentSessionReconciliationError::DelegationMissing(delegation.workspace_id()),
        )?;
    if !same_delegation(&current_delegation, delegation) {
        return Err(AgentSessionReconciliationError::StaleDelegation(
            delegation.workspace_id(),
        ));
    }

    if let Some(existing) = load(&transaction, request.request_id())? {
        let receipt = decode(&existing)?;
        if !matches_request(receipt, delegation, request) {
            return Err(AgentSessionReconciliationError::RequestConflict);
        }
        verify_reconciled_agent(&transaction, receipt, command.principal())?;
        transaction.commit().map_err(|source| {
            AgentSessionReconciliationError::CommitUnconfirmed {
                request_id: request.request_id(),
                source,
            }
        })?;
        return Ok(receipt);
    }

    let result_agent_revision = command.expected_agent_revision().checked_next()?;
    let receipt = AgentSessionReconciliation {
        request_id: request.request_id(),
        migration_id: delegation.migration_id(),
        destination_id: delegation.destination_id(),
        workspace_id: command.workspace_id(),
        activity_id: command.activity_id(),
        agent_id: command.agent_id(),
        session_id: command.session_id(),
        expected_agent_revision: command.expected_agent_revision(),
        result_agent_revision,
        reconciled_at: command.observed_at(),
    };
    // The immutable marker is inserted before the Agent UPDATE. The v38 freeze
    // trigger admits only the exact CAS transition described by this row. Any
    // subsequent failure rolls both writes back together.
    insert(&transaction, receipt)?;
    let updated = workspace_agents::reconcile_session_in_transaction(&transaction, command)?;
    if updated.revision() != receipt.result_agent_revision {
        return Err(AgentSessionReconciliationError::CorruptRecord(
            "Agent revision readback",
        ));
    }
    let stored_raw = load(&transaction, request.request_id())?.ok_or(
        AgentSessionReconciliationError::CorruptRecord("insert readback"),
    )?;
    let stored = decode(&stored_raw)?;
    if stored != receipt {
        return Err(AgentSessionReconciliationError::CorruptRecord(
            "insert identity",
        ));
    }
    transaction.commit().map_err(
        |source| AgentSessionReconciliationError::CommitUnconfirmed {
            request_id: request.request_id(),
            source,
        },
    )?;
    Ok(receipt)
}

pub(crate) fn get(
    connection: &Connection,
    request_id: Uuid,
) -> Result<Option<AgentSessionReconciliation>, AgentSessionReconciliationError> {
    if request_id.is_nil() {
        return Err(AgentSessionReconciliationError::InvalidRequestId);
    }
    validate_schema(connection)?;
    let raw = load(connection, request_id)?;
    raw.as_ref().map(decode).transpose()
}

fn same_delegation(left: &AgentOperationsDelegation, right: &AgentOperationsDelegation) -> bool {
    left.migration_id() == right.migration_id()
        && left.workspace_id() == right.workspace_id()
        && left.destination_id() == right.destination_id()
        && left.freeze().revision() == right.freeze().revision()
        && left.manifest_digest() == right.manifest_digest()
        && left.delegated_at() == right.delegated_at()
}

fn matches_request(
    receipt: AgentSessionReconciliation,
    delegation: &AgentOperationsDelegation,
    request: AgentSessionReconciliationRequest,
) -> bool {
    let command = request.command();
    receipt.request_id == request.request_id()
        && receipt.migration_id == delegation.migration_id()
        && receipt.destination_id == delegation.destination_id()
        && receipt.workspace_id == command.workspace_id()
        && receipt.activity_id == command.activity_id()
        && receipt.agent_id == command.agent_id()
        && receipt.session_id == command.session_id()
        && receipt.expected_agent_revision == command.expected_agent_revision()
        && receipt.reconciled_at == command.observed_at()
}

fn verify_reconciled_agent(
    connection: &Connection,
    receipt: AgentSessionReconciliation,
    principal: AuthenticatedPrincipal,
) -> Result<(), AgentSessionReconciliationError> {
    let agent = workspace_agents::get_in_transaction(connection, receipt.agent_id)?
        .ok_or(AgentStoreError::AgentNotFound(receipt.agent_id))?;
    if agent.workspace_id() != receipt.workspace_id
        || agent.activity_id() != receipt.activity_id
        || agent.session_id() != Some(receipt.session_id)
        || agent.principal() != principal
        || agent.revision() != receipt.result_agent_revision
        || agent.attachment_state() != AgentAttachmentState::Attached
    {
        return Err(AgentSessionReconciliationError::RequestConflict);
    }
    Ok(())
}

fn insert(
    connection: &Connection,
    receipt: AgentSessionReconciliation,
) -> Result<(), AgentSessionReconciliationError> {
    connection.execute(
        "INSERT INTO agent_session_reconciliations(request_id,migration_id,workspace_id,destination_id,activity_id,agent_id,session_id,expected_agent_revision,result_agent_revision,reconciled_at_ms) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
        params![
            receipt.request_id.as_bytes(),
            receipt.migration_id.as_bytes(),
            receipt.workspace_id.into_uuid().as_bytes(),
            receipt.destination_id.as_bytes(),
            receipt.activity_id.into_uuid().as_bytes(),
            receipt.agent_id.into_uuid().as_bytes(),
            receipt.session_id.into_uuid().as_bytes(),
            receipt.expected_agent_revision.get(),
            receipt.result_agent_revision.get(),
            receipt.reconciled_at.get(),
        ],
    )?;
    Ok(())
}

#[derive(Debug)]
struct RawReceipt {
    request_id: Vec<u8>,
    migration_id: Vec<u8>,
    workspace_id: Vec<u8>,
    destination_id: Vec<u8>,
    activity_id: Vec<u8>,
    agent_id: Vec<u8>,
    session_id: Vec<u8>,
    expected_agent_revision: i64,
    result_agent_revision: i64,
    reconciled_at: i64,
}

fn load(
    connection: &Connection,
    request_id: Uuid,
) -> Result<Option<RawReceipt>, AgentSessionReconciliationError> {
    connection
        .query_row(
            "SELECT substr(request_id,1,17),substr(migration_id,1,17),substr(workspace_id,1,17),substr(destination_id,1,17),substr(activity_id,1,17),substr(agent_id,1,17),substr(session_id,1,17),expected_agent_revision,result_agent_revision,reconciled_at_ms FROM agent_session_reconciliations WHERE request_id=?1 LIMIT 1",
            params![request_id.as_bytes()],
            |row| {
                Ok(RawReceipt {
                    request_id: row.get(0)?,
                    migration_id: row.get(1)?,
                    workspace_id: row.get(2)?,
                    destination_id: row.get(3)?,
                    activity_id: row.get(4)?,
                    agent_id: row.get(5)?,
                    session_id: row.get(6)?,
                    expected_agent_revision: row.get(7)?,
                    result_agent_revision: row.get(8)?,
                    reconciled_at: row.get(9)?,
                })
            },
        )
        .optional()
        .map_err(Into::into)
}

fn decode(raw: &RawReceipt) -> Result<AgentSessionReconciliation, AgentSessionReconciliationError> {
    let expected_agent_revision = AgentInstanceRevision::new(raw.expected_agent_revision)
        .map_err(|_| AgentSessionReconciliationError::CorruptRecord("expected revision"))?;
    let result_agent_revision = AgentInstanceRevision::new(raw.result_agent_revision)
        .map_err(|_| AgentSessionReconciliationError::CorruptRecord("result revision"))?;
    if expected_agent_revision.checked_next().ok() != Some(result_agent_revision) {
        return Err(AgentSessionReconciliationError::CorruptRecord(
            "revision transition",
        ));
    }
    Ok(AgentSessionReconciliation {
        request_id: decode_uuid(&raw.request_id, "request_id")?,
        migration_id: decode_uuid(&raw.migration_id, "migration_id")?,
        destination_id: decode_uuid(&raw.destination_id, "destination_id")?,
        workspace_id: WorkspaceId::from_uuid(decode_uuid(&raw.workspace_id, "workspace_id")?),
        activity_id: ActivityId::from_uuid(decode_uuid(&raw.activity_id, "activity_id")?),
        agent_id: AgentInstanceId::from_uuid(decode_uuid(&raw.agent_id, "agent_id")?),
        session_id: AgentSessionId::from_uuid(decode_uuid(&raw.session_id, "session_id")?),
        expected_agent_revision,
        result_agent_revision,
        reconciled_at: TimestampMillis::new(raw.reconciled_at)
            .map_err(|_| AgentSessionReconciliationError::CorruptRecord("timestamp"))?,
    })
}

fn decode_uuid(bytes: &[u8], field: &'static str) -> Result<Uuid, AgentSessionReconciliationError> {
    if bytes.len() != ID_BYTES {
        return Err(AgentSessionReconciliationError::CorruptRecord(field));
    }
    Uuid::from_slice(bytes).map_err(|_| AgentSessionReconciliationError::CorruptRecord(field))
}

fn validate_columns(connection: &Connection) -> Result<(), AgentSessionReconciliationError> {
    let mut statement = connection.prepare("PRAGMA table_info(agent_session_reconciliations)")?;
    let mut rows = statement.query([])?;
    let mut actual = Vec::new();
    while let Some(row) = rows.next()? {
        if actual.len() >= MAX_SCHEMA_METADATA_ROWS {
            return Err(AgentSessionReconciliationError::SchemaMetadataTooLarge(
                MAX_SCHEMA_METADATA_ROWS,
            ));
        }
        actual.push((
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, i64>(5)?,
        ));
    }
    let expected = [
        ("request_id", "BLOB", 1, 1),
        ("migration_id", "BLOB", 1, 0),
        ("workspace_id", "BLOB", 1, 0),
        ("destination_id", "BLOB", 1, 0),
        ("activity_id", "BLOB", 1, 0),
        ("agent_id", "BLOB", 1, 0),
        ("session_id", "BLOB", 1, 0),
        ("expected_agent_revision", "INTEGER", 1, 0),
        ("result_agent_revision", "INTEGER", 1, 0),
        ("reconciled_at_ms", "INTEGER", 1, 0),
    ];
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
        return Err(AgentSessionReconciliationError::DamagedSchema);
    }
    Ok(())
}

fn validate_foreign_keys(connection: &Connection) -> Result<(), AgentSessionReconciliationError> {
    let mut statement =
        connection.prepare("PRAGMA foreign_key_list(agent_session_reconciliations)")?;
    let mut rows = statement.query([])?;
    let mut actual = Vec::new();
    while let Some(row) = rows.next()? {
        if actual.len() >= MAX_SCHEMA_METADATA_ROWS {
            return Err(AgentSessionReconciliationError::SchemaMetadataTooLarge(
                MAX_SCHEMA_METADATA_ROWS,
            ));
        }
        actual.push((
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, String>(6)?,
            row.get::<_, String>(7)?,
        ));
    }
    actual.sort_unstable();
    let mut expected = vec![
        (
            "activities".to_owned(),
            "activity_id".to_owned(),
            "activity_id".to_owned(),
            "NO ACTION".to_owned(),
            "NO ACTION".to_owned(),
            "NONE".to_owned(),
        ),
        (
            "agent_instances".to_owned(),
            "activity_id".to_owned(),
            "activity_id".to_owned(),
            "NO ACTION".to_owned(),
            "NO ACTION".to_owned(),
            "NONE".to_owned(),
        ),
        (
            "agent_instances".to_owned(),
            "agent_id".to_owned(),
            "agent_id".to_owned(),
            "NO ACTION".to_owned(),
            "NO ACTION".to_owned(),
            "NONE".to_owned(),
        ),
        (
            "agent_instances".to_owned(),
            "workspace_id".to_owned(),
            "workspace_id".to_owned(),
            "NO ACTION".to_owned(),
            "NO ACTION".to_owned(),
            "NONE".to_owned(),
        ),
        (
            "agent_operations_delegations".to_owned(),
            "migration_id".to_owned(),
            "migration_id".to_owned(),
            "NO ACTION".to_owned(),
            "NO ACTION".to_owned(),
            "NONE".to_owned(),
        ),
        (
            "workspace".to_owned(),
            "workspace_id".to_owned(),
            "workspace_id".to_owned(),
            "NO ACTION".to_owned(),
            "NO ACTION".to_owned(),
            "NONE".to_owned(),
        ),
    ];
    expected.sort_unstable();
    if actual != expected {
        return Err(AgentSessionReconciliationError::DamagedSchema);
    }
    Ok(())
}

fn normalize_sql(value: &str) -> String {
    value
        .trim()
        .trim_end_matches(';')
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .replace("( ", "(")
        .replace(" )", ")")
        .replace(" ,", ",")
}
