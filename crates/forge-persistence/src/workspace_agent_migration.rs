//! Workspace-local Agent operations migration freeze authority.
//!
//! This module owns only the durable prerequisite journal for a later
//! Orchestration cutover.  It does not activate a destination or delegate
//! Agent operations.  A frozen Workspace is fenced at the `SQLite` boundary by
//! triggers on the legacy Agent operation tables, including for already-open
//! connections that do not pass through a Rust gate.  While a migration is
//! open the same boundary fences the legacy approval-authority tables so the
//! migrated approval authority cannot fork; consuming an already granted
//! execution stays live.

pub(crate) mod export;
pub use export::{
    AgentOperationsExportCursor, AgentOperationsExportError, AgentOperationsExportPage,
    AgentOperationsExportRecord, AgentOperationsInboxKey,
    InboxReceipt as AgentOperationsInboxReceipt, PresenceRow as AgentOperationsPresenceRow,
};

use forge_domain::{TimestampMillis, WorkspaceId};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use thiserror::Error;
use uuid::Uuid;

pub(crate) const AGENT_OPERATIONS_MIGRATION_SCHEMA_VERSION: i64 = 35;

/// Schema version that adds the approval-authority freeze fences next to the
/// legacy Agent fences.
pub(crate) const APPROVAL_AUTHORITY_FENCE_SCHEMA_VERSION: i64 = 50;

const MIGRATION_TABLE: &str = "agent_operations_migrations";
const MIGRATION_INDEX: &str = "agent_operations_migrations_active_workspace_idx";
const MAX_SCHEMA_SQL_BYTES: i64 = 16 * 1024;
const MAX_SCHEMA_METADATA_ROWS: usize = 64;
const ID_BYTES: usize = 16;

const MIGRATION_TABLE_SQL: &str = "CREATE TABLE agent_operations_migrations (migration_id BLOB PRIMARY KEY NOT NULL CHECK(length(migration_id) = 16 AND migration_id != zeroblob(16)), workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16), destination_id BLOB NOT NULL CHECK(length(destination_id) = 16 AND destination_id != zeroblob(16)), state INTEGER NOT NULL CHECK(state IN (0, 1)), revision INTEGER NOT NULL CHECK(revision >= 1), created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0), updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= created_at_ms), CHECK((state = 0 AND revision = 1 AND updated_at_ms = created_at_ms) OR (state = 1 AND revision = 2)))";
const MIGRATION_INDEX_SQL: &str = "CREATE UNIQUE INDEX agent_operations_migrations_active_workspace_idx ON agent_operations_migrations(workspace_id) WHERE state = 0";

const LEGACY_AGENT_TABLES: [&str; 6] = [
    "agent_instances",
    "agent_focus_events",
    "agent_presence",
    "agent_events",
    "agent_inbox",
    "activity_coordinators",
];
const LEGACY_AGENT_EVENTS: [(&str, &str); 3] = [
    ("insert", "INSERT"),
    ("update", "UPDATE"),
    ("delete", "DELETE"),
];
/// Legacy approval-authority tables fenced while a migration is open.  The
/// fence is delegation-scoped like the delegated Agent fences: it bites only
/// before the delegation seal, when the desktop approval UI era
/// `work_begin` paths still own these tables for non-delegated Workspaces.
/// `execution_grants` fences only new grant `INSERT`s: the consumption
/// `UPDATE` performed by `consume_grant_and_begin_execution` stays live and
/// remains the surviving execution gate.
const APPROVAL_AUTHORITY_FENCES: [(&str, &str, &str); 6] = [
    ("approval_requests", "insert", "INSERT"),
    ("auto_approval_scopes", "insert", "INSERT"),
    ("workspace_policy", "insert", "INSERT"),
    ("workspace_policy", "update", "UPDATE"),
    ("workspace_queue_settings", "insert", "INSERT"),
    ("execution_grants", "insert", "INSERT"),
];

/// Failure while reading or changing the Workspace-local migration journal.
#[derive(Debug, Error)]
pub enum AgentOperationsMigrationError {
    #[error("Agent operations have been delegated for Workspace {workspace_id}")]
    Delegated { workspace_id: WorkspaceId },
    #[error("Agent operations delegation is unavailable")]
    Delegation(#[source] Box<crate::AgentOperationsDelegationError>),
    #[error(
        "Agent operations migration {migration_id} commit is unconfirmed; read the same identity before retrying"
    )]
    CommitUnconfirmed {
        migration_id: Uuid,
        #[source]
        source: rusqlite::Error,
    },
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error("Agent operations migration identity is nil")]
    InvalidMigrationId,
    #[error("Agent operations migration destination identity is nil")]
    InvalidDestinationId,
    #[error("Agent operations migration {0} is missing")]
    MigrationMissing(Uuid),
    #[error("Agent operations migration request conflicts with durable state")]
    RequestConflict,
    #[error("Workspace {0} is missing from the current database")]
    WorkspaceMissing(WorkspaceId),
    #[error("Workspace migration request targets {expected}, current Workspace is {actual}")]
    WorkspaceMismatch {
        expected: WorkspaceId,
        actual: WorkspaceId,
    },
    #[error("Workspace is already frozen by migration {migration_id}")]
    ActiveMigrationConflict {
        migration_id: Uuid,
        workspace_id: WorkspaceId,
    },
    #[error("Workspace {workspace_id} has pending Goal deletion cleanup")]
    PendingGoalDeletionCleanup { workspace_id: WorkspaceId },
    #[error("Agent operations migration journal schema object is damaged: {0}")]
    DamagedSchema(String),
    #[error("Agent operations migration journal is corrupt: {0}")]
    CorruptRecord(&'static str),
    #[error("Agent operations migration {0} revision conflicts")]
    RevisionConflict(Uuid),
    #[error("Agent operations migration timestamp is out of order")]
    TimestampOrder,
    #[error("Agent operations migration state is invalid: {0}")]
    InvalidState(i64),
    #[error("Agent operations migration revision is invalid: {0}")]
    InvalidRevision(i64),
    #[error("Agent operations are frozen by migration {migration_id} for Workspace {workspace_id}")]
    Frozen {
        migration_id: Uuid,
        workspace_id: WorkspaceId,
    },
}

/// Durable state of one Workspace migration prerequisite.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentOperationsFreezeState {
    Frozen,
    Released,
}

impl AgentOperationsFreezeState {
    const fn encode(self) -> i64 {
        match self {
            Self::Frozen => 0,
            Self::Released => 1,
        }
    }

    fn decode(value: i64) -> Result<Self, AgentOperationsMigrationError> {
        match value {
            0 => Ok(Self::Frozen),
            1 => Ok(Self::Released),
            other => Err(AgentOperationsMigrationError::InvalidState(other)),
        }
    }
}

/// Checked request to freeze one Workspace for one destination migration.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentOperationsFreezeRequest {
    migration_id: Uuid,
    destination_id: Uuid,
    observed_at: TimestampMillis,
}

impl AgentOperationsFreezeRequest {
    /// Build a checked freeze request. Nil identities are never valid durable
    /// migration authority.
    pub fn new(
        migration_id: Uuid,
        destination_id: Uuid,
        observed_at: TimestampMillis,
    ) -> Result<Self, AgentOperationsMigrationError> {
        if migration_id.is_nil() {
            return Err(AgentOperationsMigrationError::InvalidMigrationId);
        }
        if destination_id.is_nil() {
            return Err(AgentOperationsMigrationError::InvalidDestinationId);
        }
        Ok(Self {
            migration_id,
            destination_id,
            observed_at,
        })
    }

    pub const fn migration_id(self) -> Uuid {
        self.migration_id
    }

    pub const fn destination_id(self) -> Uuid {
        self.destination_id
    }

    pub const fn observed_at(self) -> TimestampMillis {
        self.observed_at
    }
}

/// Durable readback for one freeze/release journal row.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentOperationsFreeze {
    migration_id: Uuid,
    destination_id: Uuid,
    workspace_id: WorkspaceId,
    revision: u64,
    state: AgentOperationsFreezeState,
    created_at: TimestampMillis,
    updated_at: TimestampMillis,
}

impl AgentOperationsFreeze {
    /// Rehydrate one immutable freeze observation from a checked transport or
    /// persistence representation.
    ///
    /// The durable producer accepts only non-nil migration/destination
    /// identities, a state-specific revision, and monotonic timestamps.  Keep
    /// those checks at this boundary so a remote observation cannot manufacture
    /// a freeze value that the source store could not have produced.
    pub fn from_parts(
        migration_id: Uuid,
        destination_id: Uuid,
        workspace_id: WorkspaceId,
        revision: i64,
        state: AgentOperationsFreezeState,
        created_at_ms: i64,
        updated_at_ms: i64,
    ) -> Result<Self, AgentOperationsMigrationError> {
        let created_at = TimestampMillis::new(created_at_ms)
            .map_err(|_| AgentOperationsMigrationError::CorruptRecord("created_at_ms"))?;
        let updated_at = TimestampMillis::new(updated_at_ms)
            .map_err(|_| AgentOperationsMigrationError::CorruptRecord("updated_at_ms"))?;
        let revision = u64::try_from(revision)
            .map_err(|_| AgentOperationsMigrationError::InvalidRevision(revision))?;
        Self::from_checked_parts(
            migration_id,
            destination_id,
            workspace_id,
            revision,
            state,
            created_at,
            updated_at,
        )
    }

    /// Rehydrate from values that have already crossed the domain validation
    /// boundary.  Transport adapters should normally use [`Self::from_parts`]
    /// so raw timestamp and revision values are checked here.
    pub fn from_checked_parts(
        migration_id: Uuid,
        destination_id: Uuid,
        workspace_id: WorkspaceId,
        revision: u64,
        state: AgentOperationsFreezeState,
        created_at: TimestampMillis,
        updated_at: TimestampMillis,
    ) -> Result<Self, AgentOperationsMigrationError> {
        if migration_id.is_nil() {
            return Err(AgentOperationsMigrationError::InvalidMigrationId);
        }
        if destination_id.is_nil() {
            return Err(AgentOperationsMigrationError::InvalidDestinationId);
        }
        validate_freeze_projection(revision, state, created_at, updated_at)?;
        Ok(Self {
            migration_id,
            destination_id,
            workspace_id,
            revision,
            state,
            created_at,
            updated_at,
        })
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

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub const fn state(&self) -> AgentOperationsFreezeState {
        self.state
    }

    pub const fn created_at(&self) -> TimestampMillis {
        self.created_at
    }

    pub const fn updated_at(&self) -> TimestampMillis {
        self.updated_at
    }
}

fn validate_freeze_projection(
    revision: u64,
    state: AgentOperationsFreezeState,
    created_at: TimestampMillis,
    updated_at: TimestampMillis,
) -> Result<(), AgentOperationsMigrationError> {
    let expected_revision = match state {
        AgentOperationsFreezeState::Frozen => 1,
        AgentOperationsFreezeState::Released => 2,
    };
    if revision != expected_revision {
        return Err(AgentOperationsMigrationError::InvalidRevision(
            i64::try_from(revision).unwrap_or(i64::MAX),
        ));
    }
    if updated_at.get() < created_at.get() {
        return Err(AgentOperationsMigrationError::CorruptRecord(
            "updated_at_ms",
        ));
    }
    Ok(())
}

/// Return the complete table/index/trigger inventory owned by this module.
pub(crate) fn schema_objects() -> Vec<(&'static str, String)> {
    let mut objects = migration_journal_objects();
    objects.extend(approval_authority_schema_objects());
    objects
}

/// Inventory as it exists between the migration journal schema (35) and the
/// approval-authority fence schema version; historical shape expectations.
pub(crate) fn schema_objects_pre_approval_fences() -> Vec<(&'static str, String)> {
    migration_journal_objects()
}

/// Trigger inventory fencing the legacy approval-authority tables.
pub(crate) fn approval_authority_schema_objects() -> Vec<(&'static str, String)> {
    APPROVAL_AUTHORITY_FENCES
        .iter()
        .map(|(table, suffix, _)| ("trigger", approval_authority_trigger_name(table, suffix)))
        .collect()
}

fn migration_journal_objects() -> Vec<(&'static str, String)> {
    let mut objects = Vec::with_capacity(22);
    objects.push(("table", MIGRATION_TABLE.to_owned()));
    objects.push(("index", MIGRATION_INDEX.to_owned()));
    for (table, event) in LEGACY_AGENT_TABLES.iter().flat_map(|table| {
        LEGACY_AGENT_EVENTS
            .iter()
            .map(move |event| (*table, *event))
    }) {
        objects.push(("trigger", trigger_name(table, event.0)));
    }
    objects
}

/// Create the migration journal and its legacy-write fences.
pub(crate) fn create_schema(connection: &Connection) -> Result<(), AgentOperationsMigrationError> {
    connection.execute_batch(MIGRATION_TABLE_SQL)?;
    connection.execute_batch(MIGRATION_INDEX_SQL)?;
    for (table, event) in LEGACY_AGENT_TABLES.iter().flat_map(|table| {
        LEGACY_AGENT_EVENTS
            .iter()
            .map(move |event| (*table, *event))
    }) {
        connection.execute_batch(&trigger_sql(table, event.0, event.1))?;
    }
    install_approval_authority_fences(connection)?;
    Ok(())
}

/// Validate every durable object owned by this module and its Workspace FK.
pub(crate) fn validate_schema(
    connection: &Connection,
) -> Result<(), AgentOperationsMigrationError> {
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    for (kind, name, expected) in expected_schema_sql(
        version >= crate::workspace_agent_delegation::AGENT_OPERATIONS_DELEGATION_SCHEMA_VERSION,
        version
            >= crate::workspace_agent_session_reconciliation::AGENT_SESSION_RECONCILIATION_SCHEMA_VERSION,
        version >= APPROVAL_AUTHORITY_FENCE_SCHEMA_VERSION,
    ) {
        let actual = read_schema_sql(connection, kind, &name)?;
        if actual.as_deref().map(normalize_sql) != Some(normalize_sql(&expected)) {
            return Err(AgentOperationsMigrationError::DamagedSchema(name));
        }
    }
    validate_columns(
        connection,
        MIGRATION_TABLE,
        &[
            ("migration_id", "BLOB", 1, 1),
            ("workspace_id", "BLOB", 1, 0),
            ("destination_id", "BLOB", 1, 0),
            ("state", "INTEGER", 1, 0),
            ("revision", "INTEGER", 1, 0),
            ("created_at_ms", "INTEGER", 1, 0),
            ("updated_at_ms", "INTEGER", 1, 0),
        ],
    )?;
    validate_workspace_foreign_key(connection)?;
    validate_active_index(connection)?;
    Ok(())
}

/// Permit legacy writes before the schema is upgraded, but fail closed once
/// the migration authority exists and an active freeze is durable.
pub(crate) fn ensure_legacy_writes(
    connection: &Connection,
) -> Result<(), AgentOperationsMigrationError> {
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version < AGENT_OPERATIONS_MIGRATION_SCHEMA_VERSION {
        return Ok(());
    }
    // WorkspaceStore validates schema at open; hot writes only read the fence.
    // A missing current journal is a storage error, never a legacy fallback.
    let active = connection
        .query_row(
            "SELECT substr(migration_id, 1, 17), substr(workspace_id, 1, 17) FROM agent_operations_migrations WHERE state = 0 LIMIT 1",
            [],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()?;
    let Some((migration, workspace)) = active else {
        return Ok(());
    };
    Err(AgentOperationsMigrationError::Frozen {
        migration_id: decode_uuid(&migration, "migration_id")?,
        workspace_id: decode_workspace_id(&workspace)?,
    })
}

/// Read one exact migration row after validating the owned schema.
pub(crate) fn get(
    connection: &Connection,
    migration_id: Uuid,
) -> Result<Option<AgentOperationsFreeze>, AgentOperationsMigrationError> {
    if migration_id.is_nil() {
        return Err(AgentOperationsMigrationError::InvalidMigrationId);
    }
    validate_schema(connection)?;
    load_freeze(connection, migration_id)
}

/// Create or exactly replay one Workspace freeze in an `IMMEDIATE` transaction.
pub(crate) fn freeze(
    connection: &mut Connection,
    workspace_id: WorkspaceId,
    request: &AgentOperationsFreezeRequest,
) -> Result<AgentOperationsFreeze, AgentOperationsMigrationError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    validate_schema(&transaction)?;
    validate_workspace(&transaction, workspace_id)?;
    if let Some(existing) = load_freeze(&transaction, request.migration_id())? {
        if existing.workspace_id() != workspace_id
            || existing.destination_id() != request.destination_id()
            || existing.created_at() != request.observed_at()
        {
            return Err(AgentOperationsMigrationError::RequestConflict);
        }
        transaction.commit().map_err(|source| {
            AgentOperationsMigrationError::CommitUnconfirmed {
                migration_id: request.migration_id(),
                source,
            }
        })?;
        return Ok(existing);
    }

    let active = transaction
        .query_row(
            "SELECT substr(migration_id, 1, 17) FROM agent_operations_migrations WHERE workspace_id = ?1 AND state = 0 LIMIT 1",
            params![workspace_id.into_uuid().as_bytes().as_slice()],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?;
    if let Some(active) = active {
        return Err(AgentOperationsMigrationError::ActiveMigrationConflict {
            migration_id: decode_uuid(&active, "migration_id")?,
            workspace_id,
        });
    }
    let pending = transaction
        .query_row(
            "SELECT 1 FROM goal_deletion_cleanup_journal WHERE workspace_id = ?1 LIMIT 1",
            params![workspace_id.into_uuid().as_bytes().as_slice()],
            |row| row.get::<_, i64>(0),
        )
        .optional()?;
    if pending.is_some() {
        return Err(AgentOperationsMigrationError::PendingGoalDeletionCleanup { workspace_id });
    }

    let created_at = request.observed_at();
    transaction.execute(
        "INSERT INTO agent_operations_migrations(
             migration_id, workspace_id, destination_id, state, revision,
             created_at_ms, updated_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            request.migration_id().as_bytes().as_slice(),
            workspace_id.into_uuid().as_bytes().as_slice(),
            request.destination_id().as_bytes().as_slice(),
            AgentOperationsFreezeState::Frozen.encode(),
            1_i64,
            created_at.get(),
            created_at.get(),
        ],
    )?;
    let result = load_freeze(&transaction, request.migration_id())?.ok_or(
        AgentOperationsMigrationError::MigrationMissing(request.migration_id()),
    )?;
    transaction
        .commit()
        .map_err(|source| AgentOperationsMigrationError::CommitUnconfirmed {
            migration_id: request.migration_id(),
            source,
        })?;
    Ok(result)
}

/// Release one freeze with exact compare-and-set semantics. Repeating the
/// same expected revision and timestamp returns the already-released row.
pub(crate) fn release(
    connection: &mut Connection,
    workspace_id: WorkspaceId,
    migration_id: Uuid,
    expected_revision: u64,
    observed_at: TimestampMillis,
) -> Result<AgentOperationsFreeze, AgentOperationsMigrationError> {
    if migration_id.is_nil() {
        return Err(AgentOperationsMigrationError::InvalidMigrationId);
    }
    let expected = i64::try_from(expected_revision)
        .map_err(|_| AgentOperationsMigrationError::RevisionConflict(migration_id))?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    validate_schema(&transaction)?;
    validate_workspace(&transaction, workspace_id)?;
    ensure_not_delegated(&transaction)?;
    let Some(current) = load_freeze(&transaction, migration_id)? else {
        return Err(AgentOperationsMigrationError::MigrationMissing(
            migration_id,
        ));
    };
    if current.workspace_id() != workspace_id {
        return Err(AgentOperationsMigrationError::WorkspaceMismatch {
            expected: workspace_id,
            actual: current.workspace_id(),
        });
    }
    if current.state() == AgentOperationsFreezeState::Released {
        let replay_revision = expected_revision.checked_add(1).ok_or(
            AgentOperationsMigrationError::RevisionConflict(migration_id),
        )?;
        if current.revision() == replay_revision && current.updated_at() == observed_at {
            transaction.commit().map_err(|source| {
                AgentOperationsMigrationError::CommitUnconfirmed {
                    migration_id,
                    source,
                }
            })?;
            return Ok(current);
        }
        return Err(AgentOperationsMigrationError::RevisionConflict(
            migration_id,
        ));
    }
    if current.revision() != expected_revision {
        return Err(AgentOperationsMigrationError::RevisionConflict(
            migration_id,
        ));
    }
    if observed_at.get() < current.updated_at().get() {
        return Err(AgentOperationsMigrationError::TimestampOrder);
    }
    let next_revision =
        expected_revision
            .checked_add(1)
            .ok_or(AgentOperationsMigrationError::RevisionConflict(
                migration_id,
            ))?;
    let next_revision_i64 = i64::try_from(next_revision)
        .map_err(|_| AgentOperationsMigrationError::RevisionConflict(migration_id))?;
    let changed = transaction.execute(
        "UPDATE agent_operations_migrations
         SET state = ?1, revision = ?2, updated_at_ms = ?3
         WHERE migration_id = ?4 AND workspace_id = ?5 AND state = ?6 AND revision = ?7",
        params![
            AgentOperationsFreezeState::Released.encode(),
            next_revision_i64,
            observed_at.get(),
            migration_id.as_bytes().as_slice(),
            workspace_id.into_uuid().as_bytes().as_slice(),
            AgentOperationsFreezeState::Frozen.encode(),
            expected,
        ],
    )?;
    if changed != 1 {
        return Err(AgentOperationsMigrationError::RevisionConflict(
            migration_id,
        ));
    }
    let result = load_freeze(&transaction, migration_id)?.ok_or(
        AgentOperationsMigrationError::MigrationMissing(migration_id),
    )?;
    transaction
        .commit()
        .map_err(|source| AgentOperationsMigrationError::CommitUnconfirmed {
            migration_id,
            source,
        })?;
    Ok(result)
}

/// Work binding/focus/planning facts remain Forge-owned after delegation.
/// This must not be used by legacy public metadata/presence/inbox writers.
pub(crate) fn ensure_work_writes(
    connection: &Connection,
) -> Result<(), AgentOperationsMigrationError> {
    if delegation(connection)?.is_some() {
        Ok(())
    } else {
        ensure_legacy_writes(connection)
    }
}

pub(crate) fn ensure_not_delegated(
    connection: &Connection,
) -> Result<(), AgentOperationsMigrationError> {
    if let Some(value) = delegation(connection)? {
        return Err(AgentOperationsMigrationError::Delegated {
            workspace_id: value.workspace_id(),
        });
    }
    Ok(())
}

pub(crate) fn delegation(
    connection: &Connection,
) -> Result<Option<crate::AgentOperationsDelegation>, AgentOperationsMigrationError> {
    let version: i64 = connection.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if version < crate::workspace_agent_delegation::AGENT_OPERATIONS_DELEGATION_SCHEMA_VERSION {
        return Ok(None);
    }
    let raw: Vec<u8> = connection.query_row(
        "SELECT substr(workspace_id,1,17) FROM workspace LIMIT 1",
        [],
        |r| r.get(0),
    )?;
    let workspace = decode_workspace_id(&raw)?;
    crate::workspace_agent_delegation::get(connection, workspace)
        .map_err(|e| AgentOperationsMigrationError::Delegation(Box::new(e)))
}

/// Replace only owned freeze triggers after all schema37 tables exist.
pub(crate) fn install_delegated_fences(
    connection: &Connection,
) -> Result<(), AgentOperationsMigrationError> {
    for table in LEGACY_AGENT_TABLES {
        for (suffix, event) in LEGACY_AGENT_EVENTS {
            connection.execute_batch(&format!("DROP TRIGGER {}", trigger_name(table, suffix)))?;
            connection.execute_batch(&delegated_trigger_sql(table, suffix, event, true))?;
        }
    }
    Ok(())
}

/// Install or restore the approval-authority freeze fences.  Idempotent so
/// every upgrade path that seals at the fence schema version can reuse it.
pub(crate) fn install_approval_authority_fences(
    connection: &Connection,
) -> Result<(), AgentOperationsMigrationError> {
    for (table, suffix, event) in APPROVAL_AUTHORITY_FENCES {
        connection.execute_batch(&format!(
            "DROP TRIGGER IF EXISTS {}",
            approval_authority_trigger_name(table, suffix)
        ))?;
        connection.execute_batch(&approval_authority_trigger_sql(table, suffix, event))?;
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn install_legacy_fences(
    connection: &Connection,
) -> Result<(), AgentOperationsMigrationError> {
    for table in LEGACY_AGENT_TABLES {
        for (suffix, event) in LEGACY_AGENT_EVENTS {
            connection.execute_batch(&format!("DROP TRIGGER {}", trigger_name(table, suffix)))?;
            connection.execute_batch(&trigger_sql(table, suffix, event))?;
        }
    }
    Ok(())
}

fn delegated_trigger_sql(
    table: &str,
    suffix: &str,
    event: &str,
    session_reconciliation: bool,
) -> String {
    let delegated = "EXISTS (SELECT 1 FROM agent_operations_delegations)";
    let allowed = match (table, event) {
        ("agent_instances", "INSERT") => "EXISTS (SELECT 1 FROM agent_binding_activations a JOIN agent_binding_reservations r ON r.request_id=a.request_id JOIN agent_operations_delegations d ON d.migration_id=r.migration_id WHERE r.agent_id=NEW.agent_id AND r.workspace_id=NEW.workspace_id AND r.activity_id=NEW.activity_id AND r.session_id=NEW.session_id AND r.principal_kind=NEW.principal_kind AND ((r.principal_kind=0 AND r.principal_id=zeroblob(16) AND NEW.principal_id IS NULL) OR r.principal_id=NEW.principal_id) AND r.workspace_id=d.workspace_id AND r.destination_id=d.destination_id AND r.freeze_revision=d.freeze_revision AND a.display_name=NEW.display_name AND a.declared_role=NEW.declared_role AND a.transport_kind=NEW.transport_kind AND a.activated_at_ms=NEW.created_at_ms AND NEW.updated_at_ms=NEW.created_at_ms AND NEW.attachment_state=0 AND NEW.revision=1 AND NEW.focus_goal_id IS NULL AND NEW.focus_goal_revision IS NULL AND NEW.focus_dag_revision IS NULL AND NEW.focus_node_id IS NULL AND NEW.focus_node_revision IS NULL)".to_owned(),
        ("agent_instances", "UPDATE") => {
            let ordinary_effect_update = format!(
                "{delegated} AND NEW.agent_id IS OLD.agent_id AND NEW.workspace_id IS OLD.workspace_id AND NEW.activity_id IS OLD.activity_id AND NEW.session_id IS OLD.session_id AND NEW.principal_kind IS OLD.principal_kind AND NEW.principal_id IS OLD.principal_id AND NEW.display_name IS OLD.display_name AND NEW.declared_role IS OLD.declared_role AND NEW.transport_kind IS OLD.transport_kind AND NEW.created_at_ms IS OLD.created_at_ms"
            );
            if session_reconciliation {
                let reconciliation = "EXISTS (SELECT 1 FROM agent_session_reconciliations r JOIN agent_operations_delegations d ON d.migration_id=r.migration_id WHERE r.workspace_id=OLD.workspace_id AND r.activity_id=OLD.activity_id AND r.agent_id=OLD.agent_id AND r.session_id=NEW.session_id AND r.expected_agent_revision=OLD.revision AND r.result_agent_revision=NEW.revision AND r.reconciled_at_ms=NEW.updated_at_ms AND r.workspace_id=d.workspace_id AND r.destination_id=d.destination_id AND OLD.session_id IS NULL AND NEW.session_id IS NOT NULL AND NEW.revision=OLD.revision+1 AND NEW.updated_at_ms>=OLD.updated_at_ms AND NEW.agent_id IS OLD.agent_id AND NEW.workspace_id IS OLD.workspace_id AND NEW.activity_id IS OLD.activity_id AND NEW.principal_kind IS OLD.principal_kind AND NEW.principal_id IS OLD.principal_id AND NEW.display_name IS OLD.display_name AND NEW.declared_role IS OLD.declared_role AND NEW.transport_kind IS OLD.transport_kind AND NEW.attachment_state IS OLD.attachment_state AND NEW.focus_goal_id IS OLD.focus_goal_id AND NEW.focus_goal_revision IS OLD.focus_goal_revision AND NEW.focus_dag_revision IS OLD.focus_dag_revision AND NEW.focus_node_id IS OLD.focus_node_id AND NEW.focus_node_revision IS OLD.focus_node_revision AND NEW.created_at_ms IS OLD.created_at_ms)";
                format!("({ordinary_effect_update}) OR ({reconciliation})")
            } else {
                ordinary_effect_update
            }
        }
        ("agent_focus_events", "INSERT" | "DELETE") | ("activity_coordinators", _) => delegated.to_owned(),
        _ => "0".to_owned(),
    };
    format!(
        "CREATE TRIGGER {} BEFORE {event} ON {table} WHEN EXISTS (SELECT 1 FROM agent_operations_migrations WHERE state=0) AND NOT ({allowed}) BEGIN SELECT RAISE(ABORT, 'agent operations frozen'); END",
        trigger_name(table, suffix)
    )
}

fn trigger_name(table: &str, event: &str) -> String {
    format!("agent_operations_freeze_{table}_{event}_guard")
}

fn trigger_sql(table: &str, suffix: &str, event: &str) -> String {
    format!(
        "CREATE TRIGGER {} BEFORE {} ON {} WHEN EXISTS (SELECT 1 FROM {} WHERE state = 0) BEGIN SELECT RAISE(ABORT, 'agent operations frozen'); END",
        trigger_name(table, suffix),
        event,
        table,
        MIGRATION_TABLE
    )
}

fn approval_authority_trigger_name(table: &str, suffix: &str) -> String {
    format!("approval_authority_freeze_{table}_{suffix}_guard")
}

/// Mirror of `trigger_sql` for the legacy approval-authority tables.  Like the
/// delegated Agent fences the fence is delegation-scoped: it bites while a
/// migration is open and no delegation seal exists, and goes inert once the
/// migration is closed or delegated.  The message carries the open migration
/// identity so diagnostics separate this fence from the legacy Agent fence.
fn approval_authority_trigger_sql(table: &str, suffix: &str, event: &str) -> String {
    format!(
        "CREATE TRIGGER {} BEFORE {} ON {} WHEN EXISTS (SELECT 1 FROM {} WHERE state = 0) AND NOT EXISTS (SELECT 1 FROM agent_operations_delegations) BEGIN SELECT RAISE(ABORT, (SELECT 'approval authority frozen by migration ' || lower(hex(migration_id)) FROM {} WHERE state = 0 LIMIT 1)); END",
        approval_authority_trigger_name(table, suffix),
        event,
        table,
        MIGRATION_TABLE,
        MIGRATION_TABLE
    )
}

fn expected_schema_sql(
    delegated_fences: bool,
    session_reconciliation: bool,
    approval_authority_fences: bool,
) -> Vec<(&'static str, String, String)> {
    let mut objects = vec![
        (
            "table",
            MIGRATION_TABLE.to_owned(),
            MIGRATION_TABLE_SQL.to_owned(),
        ),
        (
            "index",
            MIGRATION_INDEX.to_owned(),
            MIGRATION_INDEX_SQL.to_owned(),
        ),
    ];
    for (table, event) in LEGACY_AGENT_TABLES.iter().flat_map(|table| {
        LEGACY_AGENT_EVENTS
            .iter()
            .map(move |event| (*table, *event))
    }) {
        objects.push((
            "trigger",
            trigger_name(table, event.0),
            if delegated_fences {
                delegated_trigger_sql(table, event.0, event.1, session_reconciliation)
            } else {
                trigger_sql(table, event.0, event.1)
            },
        ));
    }
    if approval_authority_fences {
        for (table, suffix, event) in APPROVAL_AUTHORITY_FENCES {
            objects.push((
                "trigger",
                approval_authority_trigger_name(table, suffix),
                approval_authority_trigger_sql(table, suffix, event),
            ));
        }
    }
    objects
}

fn validate_workspace(
    connection: &Connection,
    expected: WorkspaceId,
) -> Result<(), AgentOperationsMigrationError> {
    let actual = connection
        .query_row(
            "SELECT workspace_id FROM workspace WHERE singleton = 1",
            [],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?;
    let Some(actual) = actual else {
        return Err(AgentOperationsMigrationError::WorkspaceMissing(expected));
    };
    let actual = decode_workspace_id(&actual)?;
    if actual != expected {
        return Err(AgentOperationsMigrationError::WorkspaceMismatch { expected, actual });
    }
    Ok(())
}

struct RawFreezeRecord {
    migration_id: Vec<u8>,
    workspace_id: Vec<u8>,
    destination_id: Vec<u8>,
    state: i64,
    revision: i64,
    created_at: i64,
    updated_at: i64,
}

fn load_freeze(
    connection: &Connection,
    migration_id: Uuid,
) -> Result<Option<AgentOperationsFreeze>, AgentOperationsMigrationError> {
    let row = connection
        .query_row(
            "SELECT substr(migration_id, 1, 17), substr(workspace_id, 1, 17), substr(destination_id, 1, 17), state, revision,
                    created_at_ms, updated_at_ms
             FROM agent_operations_migrations WHERE migration_id = ?1",
            params![migration_id.as_bytes().as_slice()],
            |row| {
                Ok(RawFreezeRecord {
                    migration_id: row.get(0)?, workspace_id: row.get(1)?, destination_id: row.get(2)?,
                    state: row.get(3)?, revision: row.get(4)?, created_at: row.get(5)?, updated_at: row.get(6)?,
                })
            },
        )
        .optional()?;
    row.map(decode_freeze_values).transpose()
}

fn decode_freeze_values(
    values: RawFreezeRecord,
) -> Result<AgentOperationsFreeze, AgentOperationsMigrationError> {
    let RawFreezeRecord {
        migration_id,
        workspace_id,
        destination_id,
        state,
        revision,
        created_at,
        updated_at,
    } = values;
    let created_at = TimestampMillis::new(created_at)
        .map_err(|_| AgentOperationsMigrationError::CorruptRecord("created_at_ms"))?;
    let updated_at = TimestampMillis::new(updated_at)
        .map_err(|_| AgentOperationsMigrationError::CorruptRecord("updated_at_ms"))?;
    if updated_at.get() < created_at.get() {
        return Err(AgentOperationsMigrationError::CorruptRecord(
            "updated_at_ms",
        ));
    }
    let phase = AgentOperationsFreezeState::decode(state)?;
    let expected_revision = match phase {
        AgentOperationsFreezeState::Frozen => 1,
        AgentOperationsFreezeState::Released => 2,
    };
    if revision != expected_revision {
        return Err(AgentOperationsMigrationError::InvalidRevision(revision));
    }
    Ok(AgentOperationsFreeze {
        migration_id: decode_uuid(&migration_id, "migration_id")?,
        destination_id: decode_uuid(&destination_id, "destination_id")?,
        workspace_id: decode_workspace_id(&workspace_id)?,
        revision: u64::try_from(revision)
            .map_err(|_| AgentOperationsMigrationError::InvalidRevision(revision))?,
        state: phase,
        created_at,
        updated_at,
    })
}

fn read_schema_sql(
    connection: &Connection,
    kind: &str,
    name: &str,
) -> Result<Option<String>, AgentOperationsMigrationError> {
    let length: Option<i64> = connection
        .query_row(
            "SELECT length(CAST(sql AS BLOB)) FROM sqlite_schema
             WHERE type = ?1 AND name = ?2",
            params![kind, name],
            |row| row.get(0),
        )
        .optional()?;
    let Some(length) = length else {
        return Ok(None);
    };
    if !(0..=MAX_SCHEMA_SQL_BYTES).contains(&length) {
        return Err(AgentOperationsMigrationError::DamagedSchema(
            name.to_owned(),
        ));
    }
    let actual: String = connection.query_row(
        "SELECT sql FROM sqlite_schema WHERE type = ?1 AND name = ?2",
        params![kind, name],
        |row| row.get(0),
    )?;
    if i64::try_from(actual.len()).ok() != Some(length) {
        return Err(AgentOperationsMigrationError::DamagedSchema(
            name.to_owned(),
        ));
    }
    Ok(Some(actual))
}

fn normalize_sql(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn validate_columns(
    connection: &Connection,
    table: &str,
    expected: &[(&str, &str, i64, i64)],
) -> Result<(), AgentOperationsMigrationError> {
    let mut statement = connection.prepare(&format!("PRAGMA table_info({table})"))?;
    let mut rows = statement.query([])?;
    let mut actual = Vec::new();
    while let Some(row) = rows.next()? {
        if actual.len() >= MAX_SCHEMA_METADATA_ROWS {
            return Err(AgentOperationsMigrationError::DamagedSchema(
                table.to_owned(),
            ));
        }
        actual.push((
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, i64>(5)?,
        ));
    }
    if actual.len() != expected.len()
        || !actual.iter().zip(expected).all(
            |((name, data_type, not_null, primary_key), expected)| {
                name == expected.0
                    && data_type.eq_ignore_ascii_case(expected.1)
                    && *not_null == expected.2
                    && *primary_key == expected.3
            },
        )
    {
        return Err(AgentOperationsMigrationError::DamagedSchema(
            table.to_owned(),
        ));
    }
    Ok(())
}

fn validate_workspace_foreign_key(
    connection: &Connection,
) -> Result<(), AgentOperationsMigrationError> {
    let mut statement =
        connection.prepare("PRAGMA foreign_key_list(agent_operations_migrations)")?;
    let mut rows = statement.query([])?;
    let mut keys = Vec::new();
    while let Some(row) = rows.next()? {
        if keys.len() >= MAX_SCHEMA_METADATA_ROWS {
            return Err(AgentOperationsMigrationError::DamagedSchema(
                MIGRATION_TABLE.to_owned(),
            ));
        }
        keys.push((
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
        ));
    }
    let valid = keys.len() == 1
        && keys[0].0 == "workspace"
        && keys[0].1 == "workspace_id"
        && keys[0].2 == "workspace_id";
    if !valid {
        return Err(AgentOperationsMigrationError::DamagedSchema(
            "workspace foreign key".to_owned(),
        ));
    }
    Ok(())
}

fn validate_active_index(connection: &Connection) -> Result<(), AgentOperationsMigrationError> {
    let mut statement = connection.prepare("PRAGMA index_list(agent_operations_migrations)")?;
    let mut rows = statement.query([])?;
    let mut found = false;
    while let Some(row) = rows.next()? {
        let name = row.get::<_, String>(1)?;
        if name != MIGRATION_INDEX {
            continue;
        }
        let unique = row.get::<_, i64>(2)?;
        let partial = row.get::<_, i64>(4)?;
        if unique != 1 || partial != 1 {
            return Err(AgentOperationsMigrationError::DamagedSchema(
                MIGRATION_INDEX.to_owned(),
            ));
        }
        let mut info = connection
            .prepare("PRAGMA index_info(agent_operations_migrations_active_workspace_idx)")?;
        let mut info_rows = info.query([])?;
        let mut columns = Vec::new();
        while let Some(info_row) = info_rows.next()? {
            if columns.len() >= MAX_SCHEMA_METADATA_ROWS {
                return Err(AgentOperationsMigrationError::DamagedSchema(
                    MIGRATION_INDEX.to_owned(),
                ));
            }
            columns.push(info_row.get::<_, String>(2)?);
        }
        if columns != ["workspace_id"] {
            return Err(AgentOperationsMigrationError::DamagedSchema(
                MIGRATION_INDEX.to_owned(),
            ));
        }
        found = true;
    }
    if !found {
        return Err(AgentOperationsMigrationError::DamagedSchema(
            MIGRATION_INDEX.to_owned(),
        ));
    }
    Ok(())
}

fn decode_uuid(bytes: &[u8], field: &'static str) -> Result<Uuid, AgentOperationsMigrationError> {
    if bytes.len() != ID_BYTES {
        return Err(AgentOperationsMigrationError::CorruptRecord(field));
    }
    Uuid::from_slice(bytes).map_err(|_| AgentOperationsMigrationError::CorruptRecord(field))
}

fn decode_workspace_id(bytes: &[u8]) -> Result<WorkspaceId, AgentOperationsMigrationError> {
    Ok(WorkspaceId::from_uuid(decode_uuid(bytes, "workspace_id")?))
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;

    fn id(value: u128) -> Uuid {
        Uuid::from_u128(value)
    }

    fn timestamp(value: i64) -> Result<TimestampMillis, Box<dyn Error>> {
        Ok(TimestampMillis::new(value)?)
    }

    fn workspace(value: u128) -> WorkspaceId {
        WorkspaceId::from_uuid(id(value))
    }

    fn connection() -> Result<Connection, Box<dyn Error>> {
        let connection = Connection::open_in_memory()?;
        connection.pragma_update(None, "foreign_keys", true)?;
        connection.execute_batch(
            "CREATE TABLE workspace (
                 singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                 workspace_id BLOB NOT NULL UNIQUE CHECK(length(workspace_id) = 16)
             );
             CREATE TABLE agent_instances(id BLOB);
             CREATE TABLE agent_focus_events(id BLOB);
             CREATE TABLE agent_presence(id BLOB);
             CREATE TABLE agent_events(id BLOB);
             CREATE TABLE agent_inbox(id BLOB);
             CREATE TABLE activity_coordinators(id BLOB);
             CREATE TABLE goal_deletion_cleanup_journal(
                 cleanup_id BLOB PRIMARY KEY,
                 workspace_id BLOB NOT NULL
             );
             CREATE TABLE agent_operations_delegations(migration_id BLOB, workspace_id BLOB);
             CREATE TABLE approval_requests(approval_id BLOB, workspace_id BLOB);
             CREATE TABLE auto_approval_scopes(scope_id BLOB, workspace_id BLOB);
             CREATE TABLE workspace_policy(singleton INTEGER, revision INTEGER);
             CREATE TABLE workspace_queue_settings(workspace_id BLOB);
             CREATE TABLE execution_grants(grant_id BLOB, state INTEGER, revision INTEGER);",
        )?;
        let workspace_id = workspace(1);
        connection.execute(
            "INSERT INTO workspace(singleton, workspace_id) VALUES (1, ?1)",
            params![workspace_id.into_uuid().as_bytes().as_slice()],
        )?;
        create_schema(&connection)?;
        Ok(connection)
    }

    fn request(
        migration: u128,
        destination: u128,
        observed_at: i64,
    ) -> Result<AgentOperationsFreezeRequest, Box<dyn Error>> {
        Ok(AgentOperationsFreezeRequest::new(
            id(migration),
            id(destination),
            timestamp(observed_at)?,
        )?)
    }

    #[test]
    fn freeze_observation_constructor_reuses_state_revision_and_timestamp_fences()
    -> Result<(), Box<dyn Error>> {
        let created = timestamp(10)?;
        let updated = timestamp(11)?;
        let frozen = AgentOperationsFreeze::from_parts(
            id(2),
            id(3),
            workspace(1),
            1,
            AgentOperationsFreezeState::Frozen,
            created.get(),
            created.get(),
        )?;
        assert_eq!(frozen.revision(), 1);
        assert_eq!(frozen.state(), AgentOperationsFreezeState::Frozen);

        assert!(matches!(
            AgentOperationsFreeze::from_parts(
                id(2),
                id(3),
                workspace(1),
                2,
                AgentOperationsFreezeState::Frozen,
                created.get(),
                created.get(),
            ),
            Err(AgentOperationsMigrationError::InvalidRevision(2))
        ));
        assert!(matches!(
            AgentOperationsFreeze::from_parts(
                id(2),
                id(3),
                workspace(1),
                2,
                AgentOperationsFreezeState::Released,
                updated.get(),
                created.get(),
            ),
            Err(AgentOperationsMigrationError::CorruptRecord(
                "updated_at_ms"
            ))
        ));
        assert!(matches!(
            AgentOperationsFreeze::from_parts(
                Uuid::nil(),
                id(3),
                workspace(1),
                1,
                AgentOperationsFreezeState::Frozen,
                created.get(),
                created.get(),
            ),
            Err(AgentOperationsMigrationError::InvalidMigrationId)
        ));
        Ok(())
    }

    #[test]
    fn busy_commit_requires_same_identity_readback_before_retry() -> Result<(), Box<dyn Error>> {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "forge-operations-commit-{}-{unique}.sqlite3",
            std::process::id()
        ));
        let seed = connection()?;
        seed.execute("VACUUM INTO ?1", params![path.to_string_lossy().as_ref()])?;
        drop(seed);
        let mut writer = Connection::open(&path)?;
        writer.busy_timeout(std::time::Duration::from_millis(20))?;
        let mut reader = Connection::open(&path)?;
        let read = reader.transaction()?;
        let _: i64 = read.query_row("SELECT COUNT(*) FROM workspace", [], |row| row.get(0))?;
        let request = request(2, 3, 10)?;
        let error = freeze(&mut writer, workspace(1), &request)
            .err()
            .ok_or("commit unexpectedly succeeded while read locked")?;
        assert!(
            matches!(error, AgentOperationsMigrationError::CommitUnconfirmed { migration_id, .. } if migration_id == id(2))
        );
        assert!(get(&writer, id(2))?.is_none());
        drop(read);
        drop(reader);
        let committed = freeze(&mut writer, workspace(1), &request)?;
        assert_eq!(get(&writer, id(2))?, Some(committed));
        drop(writer);
        std::fs::remove_file(path)?;
        Ok(())
    }

    #[test]
    fn freeze_replay_release_and_readback_are_exact() -> Result<(), Box<dyn Error>> {
        let mut connection = connection()?;
        connection.pragma_update(
            None,
            "user_version",
            AGENT_OPERATIONS_MIGRATION_SCHEMA_VERSION,
        )?;
        let workspace_id = workspace(1);
        let freeze_request = request(2, 3, 10)?;
        let frozen = freeze(&mut connection, workspace_id, &freeze_request)?;
        assert_eq!(frozen.state(), AgentOperationsFreezeState::Frozen);
        assert_eq!(frozen.revision(), 1);
        assert_eq!(
            get(&connection, freeze_request.migration_id())?,
            Some(frozen.clone())
        );
        assert_eq!(
            freeze(&mut connection, workspace_id, &freeze_request)?,
            frozen
        );

        let released = release(
            &mut connection,
            workspace_id,
            freeze_request.migration_id(),
            1,
            timestamp(11)?,
        )?;
        assert_eq!(released.state(), AgentOperationsFreezeState::Released);
        assert_eq!(released.revision(), 2);
        assert_eq!(
            release(
                &mut connection,
                workspace_id,
                freeze_request.migration_id(),
                1,
                timestamp(11)?,
            )?,
            released
        );
        assert_eq!(
            freeze(&mut connection, workspace_id, &freeze_request)?,
            released
        );
        assert!(matches!(
            freeze(&mut connection, workspace_id, &request(2, 3, 12)?),
            Err(AgentOperationsMigrationError::RequestConflict)
        ));
        assert!(matches!(
            release(
                &mut connection,
                workspace_id,
                freeze_request.migration_id(),
                2,
                timestamp(12)?,
            ),
            Err(AgentOperationsMigrationError::RevisionConflict(_))
        ));
        Ok(())
    }

    #[test]
    fn second_active_workspace_owner_is_rejected() -> Result<(), Box<dyn Error>> {
        let mut connection = connection()?;
        let workspace_id = workspace(1);
        let _ = freeze(&mut connection, workspace_id, &request(2, 3, 10)?)?;
        assert!(matches!(
            freeze(&mut connection, workspace_id, &request(4, 5, 11)?),
            Err(AgentOperationsMigrationError::ActiveMigrationConflict { .. })
        ));
        Ok(())
    }

    #[test]
    fn pending_goal_cleanup_blocks_freeze() -> Result<(), Box<dyn Error>> {
        let mut connection = connection()?;
        let workspace_id = workspace(1);
        connection.execute(
            "INSERT INTO goal_deletion_cleanup_journal(cleanup_id, workspace_id)
             VALUES (?1, ?2)",
            params![
                id(6).as_bytes().as_slice(),
                workspace_id.into_uuid().as_bytes().as_slice()
            ],
        )?;
        assert!(matches!(
            freeze(&mut connection, workspace_id, &request(2, 3, 10)?),
            Err(AgentOperationsMigrationError::PendingGoalDeletionCleanup { .. })
        ));
        Ok(())
    }

    #[test]
    fn pre_v35_legacy_writes_are_allowed_but_frozen_writes_are_blocked()
    -> Result<(), Box<dyn Error>> {
        let mut connection = connection()?;
        let workspace_id = workspace(1);
        ensure_legacy_writes(&connection)?;
        let _ = freeze(&mut connection, workspace_id, &request(2, 3, 10)?)?;
        connection.pragma_update(
            None,
            "user_version",
            AGENT_OPERATIONS_MIGRATION_SCHEMA_VERSION,
        )?;
        assert!(matches!(
            ensure_legacy_writes(&connection),
            Err(AgentOperationsMigrationError::Frozen { .. })
        ));
        let result = connection.execute(
            "INSERT INTO agent_instances(id) VALUES (?1)",
            params![id(7).as_bytes().as_slice()],
        );
        assert!(result.is_err());
        let count: i64 =
            connection.query_row("SELECT COUNT(*) FROM agent_instances", [], |row| row.get(0))?;
        assert_eq!(count, 0);
        Ok(())
    }

    #[test]
    fn dropped_journal_is_a_fail_closed_current_schema_error() -> Result<(), Box<dyn Error>> {
        let connection = connection()?;
        connection.pragma_update(
            None,
            "user_version",
            AGENT_OPERATIONS_MIGRATION_SCHEMA_VERSION,
        )?;
        connection.execute_batch("DROP TABLE agent_operations_migrations;")?;
        assert!(matches!(
            ensure_legacy_writes(&connection),
            Err(AgentOperationsMigrationError::Sqlite(_))
        ));
        Ok(())
    }

    fn approval_frozen_message(migration: u128) -> String {
        format!("approval authority frozen by migration {migration:032x}")
    }

    fn raised_message(error: rusqlite::Error) -> Option<String> {
        match error {
            rusqlite::Error::SqliteFailure(_, Some(message)) => Some(message),
            _ => None,
        }
    }

    /// One fenced write per approval-authority trigger, including both
    /// `workspace_policy` events.  `execution_grants` fences only new grants.
    const FENCED_APPROVAL_WRITES: [(&str, &str); 6] = [
        (
            "approval_requests insert",
            "INSERT INTO approval_requests VALUES (x'07', NULL)",
        ),
        (
            "auto_approval_scopes insert",
            "INSERT INTO auto_approval_scopes VALUES (x'08', NULL)",
        ),
        (
            "workspace_policy insert",
            "INSERT INTO workspace_policy VALUES (2, 1)",
        ),
        (
            "workspace_policy update",
            "UPDATE workspace_policy SET revision = 2 WHERE singleton = 1",
        ),
        (
            "workspace_queue_settings insert",
            "INSERT INTO workspace_queue_settings VALUES (NULL)",
        ),
        (
            "execution_grants insert",
            "INSERT INTO execution_grants VALUES (x'09', 0, 1)",
        ),
    ];

    #[test]
    fn approval_authority_writes_are_frozen_until_release_but_grant_consumption_stays_live()
    -> Result<(), Box<dyn Error>> {
        let mut connection = connection()?;
        let workspace_id = workspace(1);
        // An already-granted execution exists before the freeze; consuming it
        // is an `UPDATE` and must survive the fence.
        connection.execute(
            "INSERT INTO execution_grants(grant_id, state, revision) VALUES (?1, 0, 1)",
            params![id(8).as_bytes().as_slice()],
        )?;
        connection.execute(
            "INSERT INTO workspace_policy(singleton, revision) VALUES (1, 1)",
            [],
        )?;
        let frozen = freeze(&mut connection, workspace_id, &request(2, 3, 10)?)?;
        let message = approval_frozen_message(frozen.migration_id().as_u128());

        for (write, sql) in FENCED_APPROVAL_WRITES {
            let error = connection
                .execute(sql, [])
                .err()
                .ok_or("the frozen workspace must reject the fenced approval write")?;
            assert_eq!(
                raised_message(error).as_deref(),
                Some(message.as_str()),
                "{write}"
            );
        }
        let consumed = connection.execute(
            "UPDATE execution_grants SET state = 1, revision = 2 WHERE grant_id = ?1",
            params![id(8).as_bytes().as_slice()],
        )?;
        assert_eq!(consumed, 1, "grant consumption UPDATE must stay live");

        // Closing the migration removes the fence: every blocked write is
        // allowed again.
        let released = release(
            &mut connection,
            workspace_id,
            frozen.migration_id(),
            1,
            timestamp(11)?,
        )?;
        assert_eq!(released.state(), AgentOperationsFreezeState::Released);
        for (write, sql) in FENCED_APPROVAL_WRITES {
            let accepted = connection
                .execute(sql, [])
                .is_ok_and(|changed| changed == 1);
            assert!(accepted, "{write} stayed fenced after release");
        }
        Ok(())
    }

    #[test]
    fn approval_authority_freeze_scopes_to_the_open_migration_workspace()
    -> Result<(), Box<dyn Error>> {
        let mut frozen_workspace = connection()?;
        let other_workspace = connection()?;
        let _ = freeze(&mut frozen_workspace, workspace(1), &request(2, 3, 10)?)?;

        // Each Workspace SQLite owns exactly one Workspace; another
        // Workspace's database has no open migration and keeps accepting
        // approval-authority writes.
        other_workspace.execute(
            "INSERT INTO approval_requests(approval_id, workspace_id) VALUES (?1, NULL)",
            params![id(9).as_bytes().as_slice()],
        )?;
        other_workspace.execute(
            "INSERT INTO workspace_queue_settings(workspace_id) VALUES (?1)",
            params![workspace(5).into_uuid().as_bytes().as_slice()],
        )?;
        let error = frozen_workspace
            .execute(
                "INSERT INTO approval_requests(approval_id, workspace_id) VALUES (?1, NULL)",
                params![id(10).as_bytes().as_slice()],
            )
            .err()
            .ok_or("frozen workspace accepted an approval write")?;
        assert_eq!(
            raised_message(error).as_deref(),
            Some(approval_frozen_message(id(2).as_u128()).as_str())
        );

        // Delegating the frozen Workspace scopes the fence off: the surviving
        // approval gate keeps writing after the delegation seal.
        frozen_workspace.execute(
            "INSERT INTO agent_operations_delegations(migration_id, workspace_id)
             VALUES (?1, ?2)",
            params![
                id(2).as_bytes().as_slice(),
                workspace(1).into_uuid().as_bytes().as_slice()
            ],
        )?;
        frozen_workspace.execute(
            "INSERT INTO approval_requests(approval_id, workspace_id) VALUES (?1, NULL)",
            params![id(10).as_bytes().as_slice()],
        )?;

        // Closing the migration without a delegation removes the fence too.
        let mut other_frozen = connection()?;
        let _ = freeze(&mut other_frozen, workspace(1), &request(4, 5, 10)?)?;
        let released = release(&mut other_frozen, workspace(1), id(4), 1, timestamp(11)?)?;
        assert_eq!(released.state(), AgentOperationsFreezeState::Released);
        other_frozen.execute(
            "INSERT INTO approval_requests(approval_id, workspace_id) VALUES (?1, NULL)",
            params![id(10).as_bytes().as_slice()],
        )?;
        Ok(())
    }
}
