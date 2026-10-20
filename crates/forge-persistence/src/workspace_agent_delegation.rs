//! Workspace-local durable source delegation seals.
//!
//! A delegation seals one still-`Frozen` source migration to the exact
//! verified destination manifest supplied by the trusted Orchestration
//! composition boundary.  This journal does not activate bindings, write
//! membership/event/inbox state, or change the legacy freeze row.

use forge_domain::{TimestampMillis, TimestampMillisError, WorkspaceId};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use thiserror::Error;
use uuid::Uuid;

use crate::workspace_agent_migration::{
    self, AgentOperationsFreeze, AgentOperationsFreezeState, AgentOperationsMigrationError,
};

pub(crate) const AGENT_OPERATIONS_DELEGATION_SCHEMA_VERSION: i64 = 37;

const DELEGATIONS_TABLE: &str = "agent_operations_delegations";
const MAX_SCHEMA_SQL_BYTES: i64 = 16 * 1024;
const MAX_SCHEMA_METADATA_ROWS: usize = 64;
const ID_BYTES: usize = 16;
const MANIFEST_DIGEST_BYTES: usize = 32;

// This is the one canonical DDL authority for the immutable source
// delegation journal.  Schema creation and validation both use this value.
const DELEGATIONS_TABLE_SQL: &str = "CREATE TABLE agent_operations_delegations (migration_id BLOB PRIMARY KEY NOT NULL REFERENCES agent_operations_migrations(migration_id) CHECK(length(migration_id) = 16 AND migration_id != zeroblob(16)), workspace_id BLOB NOT NULL UNIQUE REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16 AND workspace_id != zeroblob(16)), destination_id BLOB NOT NULL CHECK(length(destination_id) = 16 AND destination_id != zeroblob(16)), freeze_revision INTEGER NOT NULL CHECK(freeze_revision >= 1), manifest_digest BLOB NOT NULL CHECK(length(manifest_digest) = 32 AND manifest_digest != zeroblob(32)), delegated_at_ms INTEGER NOT NULL CHECK(delegated_at_ms >= 0))";
const DELEGATION_BY_WORKSPACE_SQL: &str = "SELECT substr(migration_id, 1, 17), substr(workspace_id, 1, 17), substr(destination_id, 1, 17), freeze_revision, substr(manifest_digest, 1, 33), delegated_at_ms FROM agent_operations_delegations WHERE workspace_id = ?1 LIMIT 1";
const DELEGATION_BY_MIGRATION_SQL: &str = "SELECT substr(migration_id, 1, 17), substr(workspace_id, 1, 17), substr(destination_id, 1, 17), freeze_revision, substr(manifest_digest, 1, 33), delegated_at_ms FROM agent_operations_delegations WHERE migration_id = ?1 LIMIT 1";

/// Failure while reading or sealing a Workspace-local source delegation.
#[derive(Debug, Error)]
pub enum AgentOperationsDelegationError {
    #[error("Agent operations delegation Workspace identity is nil")]
    InvalidWorkspaceId,
    #[error("Agent operations delegation migration identity is nil")]
    InvalidMigrationId,
    #[error("Agent operations delegation destination identity is nil")]
    InvalidDestinationId,
    #[error("Agent operations delegation manifest digest must not be zero")]
    ZeroManifestDigest,
    #[error("Agent operations migration {0} is missing from the current Workspace")]
    MigrationMissing(Uuid),
    #[error("Agent operations migration {0} is released and cannot be delegated")]
    FreezeReleased(Uuid),
    #[error("Agent operations migration {0} is stale or does not match its durable freeze")]
    StaleFreeze(Uuid),
    #[error("Workspace delegation targets {expected}, current source freeze is {actual}")]
    WorkspaceMismatch {
        expected: WorkspaceId,
        actual: WorkspaceId,
    },
    #[error(
        "Agent operations delegation conflicts with durable state for Workspace {workspace_id} and migration {migration_id}"
    )]
    DelegationConflict {
        workspace_id: WorkspaceId,
        migration_id: Uuid,
    },
    #[error("delegated_at_ms must be at least the source freeze timestamp")]
    TimestampOrder,
    #[error("Agent operations delegation schema object is damaged: {0}")]
    DamagedSchema(&'static str),
    #[error("Agent operations delegation schema metadata for {object} exceeds {maximum} rows")]
    SchemaMetadataTooLarge {
        object: &'static str,
        maximum: usize,
    },
    #[error(
        "Agent operations delegation schema object {object} is {actual} bytes; maximum is {maximum}"
    )]
    SchemaSqlTooLarge {
        object: &'static str,
        actual: i64,
        maximum: i64,
    },
    #[error(
        "Agent operations delegation persisted UUID field {field} has {actual} bytes; expected {expected}"
    )]
    InvalidUuidLength {
        field: &'static str,
        actual: usize,
        expected: usize,
    },
    #[error("Agent operations delegation persisted UUID field {field} is invalid")]
    Uuid {
        field: &'static str,
        #[source]
        source: uuid::Error,
    },
    #[error(
        "Agent operations delegation persisted digest field {field} has {actual} bytes; expected {expected}"
    )]
    InvalidDigestLength {
        field: &'static str,
        actual: usize,
        expected: usize,
    },
    #[error("Agent operations delegation persisted record is corrupt: {0}")]
    CorruptRecord(&'static str),
    #[error(transparent)]
    Timestamp(#[from] TimestampMillisError),
    #[error(transparent)]
    Migration(#[from] AgentOperationsMigrationError),
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(
        "Agent operations delegation for migration {migration_id} commit is unconfirmed; read the same identity before retrying"
    )]
    CommitUnconfirmed {
        migration_id: Uuid,
        #[source]
        source: rusqlite::Error,
    },
}

/// Durable readback of one immutable source delegation seal.
///
/// The source freeze is read from its authoritative migration row.  Callers
/// cannot construct a delegation directly or supply an unverified flag.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentOperationsDelegation {
    freeze: AgentOperationsFreeze,
    manifest_digest: [u8; MANIFEST_DIGEST_BYTES],
    delegated_at: TimestampMillis,
}

impl AgentOperationsDelegation {
    pub const fn freeze(&self) -> &AgentOperationsFreeze {
        &self.freeze
    }

    pub const fn migration_id(&self) -> Uuid {
        self.freeze.migration_id()
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.freeze.workspace_id()
    }

    pub const fn destination_id(&self) -> Uuid {
        self.freeze.destination_id()
    }

    pub const fn manifest_digest(&self) -> [u8; MANIFEST_DIGEST_BYTES] {
        self.manifest_digest
    }

    pub const fn delegated_at(&self) -> TimestampMillis {
        self.delegated_at
    }
}

/// Create the source delegation journal table.
pub(crate) fn create_schema(connection: &Connection) -> Result<(), AgentOperationsDelegationError> {
    connection.execute_batch(DELEGATIONS_TABLE_SQL)?;
    Ok(())
}

/// Return the complete schema object inventory owned by this module.
pub(crate) fn schema_objects() -> Vec<(&'static str, &'static str)> {
    vec![("table", DELEGATIONS_TABLE)]
}

/// Validate the canonical table, columns, and foreign-key shape.
pub(crate) fn validate_schema(
    connection: &Connection,
) -> Result<(), AgentOperationsDelegationError> {
    let length: Option<i64> = connection
        .query_row(
            "SELECT length(CAST(sql AS BLOB)) FROM sqlite_schema WHERE type = ?1 AND name = ?2",
            params!["table", DELEGATIONS_TABLE],
            |row| row.get(0),
        )
        .optional()?;
    let Some(length) = length else {
        return Err(AgentOperationsDelegationError::DamagedSchema(
            DELEGATIONS_TABLE,
        ));
    };
    if !(0..=MAX_SCHEMA_SQL_BYTES).contains(&length) {
        return Err(AgentOperationsDelegationError::SchemaSqlTooLarge {
            object: DELEGATIONS_TABLE,
            actual: length,
            maximum: MAX_SCHEMA_SQL_BYTES,
        });
    }
    let actual: String = connection.query_row(
        "SELECT sql FROM sqlite_schema WHERE type = ?1 AND name = ?2",
        params!["table", DELEGATIONS_TABLE],
        |row| row.get(0),
    )?;
    if i64::try_from(actual.len()).ok() != Some(length)
        || normalize_sql(&actual) != normalize_sql(DELEGATIONS_TABLE_SQL)
    {
        return Err(AgentOperationsDelegationError::DamagedSchema(
            DELEGATIONS_TABLE,
        ));
    }

    validate_columns(connection)?;
    validate_foreign_keys(connection)
}

/// Seal one still-Frozen source migration to an exact verified destination
/// manifest, or replay the exact durable seal already committed for it.
///
/// The operation writes only this immutable journal row.  The caller must
/// obtain the digest from trusted catalog verification; this boundary has no
/// public boolean or constructor that can manufacture that trust.
pub(crate) fn delegate(
    connection: &mut Connection,
    workspace: WorkspaceId,
    freeze: &AgentOperationsFreeze,
    digest: [u8; MANIFEST_DIGEST_BYTES],
    now: TimestampMillis,
) -> Result<AgentOperationsDelegation, AgentOperationsDelegationError> {
    validate_workspace_id(workspace)?;
    validate_manifest_digest(&digest)?;

    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    validate_schema(&transaction)?;
    let current = validate_current_freeze(&transaction, workspace, freeze)?;
    if now.get() < current.updated_at().get() {
        return Err(AgentOperationsDelegationError::TimestampOrder);
    }

    if let Some(existing) = load_by_workspace(&transaction, workspace)? {
        let existing = decode_delegation(&existing)?;
        if existing.migration_id() != current.migration_id() {
            return Err(AgentOperationsDelegationError::DelegationConflict {
                workspace_id: workspace,
                migration_id: existing.migration_id(),
            });
        }
        validate_delegation_pointer(&existing, &current, workspace)?;
        if same_source_and_digest(&existing, &current, digest) {
            transaction.commit().map_err(|source| {
                AgentOperationsDelegationError::CommitUnconfirmed {
                    migration_id: current.migration_id(),
                    source,
                }
            })?;
            return Ok(AgentOperationsDelegation {
                freeze: current,
                manifest_digest: existing.manifest_digest,
                delegated_at: existing.delegated_at,
            });
        }
        return Err(AgentOperationsDelegationError::DelegationConflict {
            workspace_id: workspace,
            migration_id: existing.migration_id,
        });
    }

    if let Some(existing) = load_by_migration(&transaction, current.migration_id())? {
        let existing = decode_delegation(&existing)?;
        return Err(AgentOperationsDelegationError::DelegationConflict {
            workspace_id: existing.workspace_id(),
            migration_id: existing.migration_id(),
        });
    }

    let freeze_revision = i64::try_from(current.revision())
        .map_err(|_| AgentOperationsDelegationError::CorruptRecord("freeze_revision"))?;
    transaction.execute(
        "INSERT INTO agent_operations_delegations(
             migration_id, workspace_id, destination_id, freeze_revision,
             manifest_digest, delegated_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            current.migration_id().as_bytes(),
            current.workspace_id().into_uuid().as_bytes(),
            current.destination_id().as_bytes(),
            freeze_revision,
            digest.as_slice(),
            now.get(),
        ],
    )?;

    let raw = load_by_migration(&transaction, current.migration_id())?.ok_or(
        AgentOperationsDelegationError::CorruptRecord("delegation insert readback"),
    )?;
    let persisted = decode_delegation(&raw)?;
    if !same_source_and_digest(&persisted, &current, digest) || persisted.delegated_at != now {
        return Err(AgentOperationsDelegationError::CorruptRecord(
            "delegation insert identity",
        ));
    }
    let result = AgentOperationsDelegation {
        freeze: current,
        manifest_digest: persisted.manifest_digest,
        delegated_at: persisted.delegated_at,
    };
    transaction
        .commit()
        .map_err(|source| AgentOperationsDelegationError::CommitUnconfirmed {
            migration_id: result.migration_id(),
            source,
        })?;
    Ok(result)
}

/// Read the Workspace's source delegation seal and revalidate its linked
/// current freeze.  A released, missing, or mismatched source row fails closed.
pub(crate) fn get(
    connection: &Connection,
    workspace: WorkspaceId,
) -> Result<Option<AgentOperationsDelegation>, AgentOperationsDelegationError> {
    validate_workspace_id(workspace)?;
    validate_schema(connection)?;
    let Some(raw) = load_by_workspace(connection, workspace)? else {
        return Ok(None);
    };
    let raw = decode_delegation(&raw)?;
    let current = load_current_freeze(connection, raw.migration_id())?;
    validate_delegation_pointer(&raw, &current, workspace)?;
    Ok(Some(AgentOperationsDelegation {
        freeze: current,
        manifest_digest: raw.manifest_digest,
        delegated_at: raw.delegated_at,
    }))
}

#[derive(Debug)]
struct RawDelegation {
    migration_id: Vec<u8>,
    workspace_id: Vec<u8>,
    destination_id: Vec<u8>,
    freeze_revision: i64,
    manifest_digest: Vec<u8>,
    delegated_at: i64,
}

#[derive(Debug)]
struct DecodedDelegation {
    migration_id: Uuid,
    workspace_id: WorkspaceId,
    destination_id: Uuid,
    freeze_revision: u64,
    manifest_digest: [u8; MANIFEST_DIGEST_BYTES],
    delegated_at: TimestampMillis,
}

impl DecodedDelegation {
    const fn migration_id(&self) -> Uuid {
        self.migration_id
    }

    const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }
}

fn validate_current_freeze(
    connection: &Connection,
    workspace: WorkspaceId,
    supplied: &AgentOperationsFreeze,
) -> Result<AgentOperationsFreeze, AgentOperationsDelegationError> {
    validate_workspace_id(supplied.workspace_id())?;
    if supplied.migration_id().is_nil() {
        return Err(AgentOperationsDelegationError::InvalidMigrationId);
    }
    if supplied.destination_id().is_nil() {
        return Err(AgentOperationsDelegationError::InvalidDestinationId);
    }
    if supplied.revision() == 0 {
        return Err(AgentOperationsDelegationError::StaleFreeze(
            supplied.migration_id(),
        ));
    }
    if supplied.workspace_id() != workspace {
        return Err(AgentOperationsDelegationError::WorkspaceMismatch {
            expected: workspace,
            actual: supplied.workspace_id(),
        });
    }

    let current = load_current_freeze(connection, supplied.migration_id())?;
    if current.workspace_id() != workspace {
        return Err(AgentOperationsDelegationError::WorkspaceMismatch {
            expected: workspace,
            actual: current.workspace_id(),
        });
    }
    if current != *supplied {
        return Err(AgentOperationsDelegationError::StaleFreeze(
            supplied.migration_id(),
        ));
    }
    Ok(current)
}

fn load_current_freeze(
    connection: &Connection,
    migration_id: Uuid,
) -> Result<AgentOperationsFreeze, AgentOperationsDelegationError> {
    if migration_id.is_nil() {
        return Err(AgentOperationsDelegationError::InvalidMigrationId);
    }
    let Some(current) = workspace_agent_migration::get(connection, migration_id)? else {
        return Err(AgentOperationsDelegationError::MigrationMissing(
            migration_id,
        ));
    };
    validate_freeze_shape(&current)?;
    if current.state() != AgentOperationsFreezeState::Frozen {
        return Err(AgentOperationsDelegationError::FreezeReleased(migration_id));
    }
    Ok(current)
}

fn validate_freeze_shape(
    freeze: &AgentOperationsFreeze,
) -> Result<(), AgentOperationsDelegationError> {
    if freeze.migration_id().is_nil() {
        return Err(AgentOperationsDelegationError::CorruptRecord(
            "agent_operations_migrations.migration_id",
        ));
    }
    if freeze.destination_id().is_nil() {
        return Err(AgentOperationsDelegationError::CorruptRecord(
            "agent_operations_migrations.destination_id",
        ));
    }
    validate_workspace_id(freeze.workspace_id()).map_err(|_| {
        AgentOperationsDelegationError::CorruptRecord("agent_operations_migrations.workspace_id")
    })?;
    if freeze.revision() == 0 {
        return Err(AgentOperationsDelegationError::CorruptRecord(
            "agent_operations_migrations.revision",
        ));
    }
    Ok(())
}

fn same_source_and_digest(
    existing: &DecodedDelegation,
    current: &AgentOperationsFreeze,
    digest: [u8; MANIFEST_DIGEST_BYTES],
) -> bool {
    existing.migration_id == current.migration_id()
        && existing.workspace_id == current.workspace_id()
        && existing.destination_id == current.destination_id()
        && existing.freeze_revision == current.revision()
        && existing.manifest_digest == digest
}

fn validate_delegation_pointer(
    raw: &DecodedDelegation,
    current: &AgentOperationsFreeze,
    workspace: WorkspaceId,
) -> Result<(), AgentOperationsDelegationError> {
    if raw.workspace_id != workspace {
        return Err(AgentOperationsDelegationError::WorkspaceMismatch {
            expected: workspace,
            actual: raw.workspace_id,
        });
    }
    if raw.migration_id != current.migration_id()
        || raw.workspace_id != current.workspace_id()
        || raw.destination_id != current.destination_id()
        || raw.freeze_revision != current.revision()
    {
        return Err(AgentOperationsDelegationError::CorruptRecord(
            "agent_operations_delegations source freeze pointer",
        ));
    }
    if raw.delegated_at.get() < current.updated_at().get() {
        return Err(AgentOperationsDelegationError::CorruptRecord(
            "agent_operations_delegations.delegated_at_ms",
        ));
    }
    Ok(())
}

fn load_by_workspace(
    connection: &Connection,
    workspace: WorkspaceId,
) -> Result<Option<RawDelegation>, AgentOperationsDelegationError> {
    load_raw(
        connection,
        DELEGATION_BY_WORKSPACE_SQL,
        params![workspace.into_uuid().as_bytes()],
    )
}

fn load_by_migration(
    connection: &Connection,
    migration_id: Uuid,
) -> Result<Option<RawDelegation>, AgentOperationsDelegationError> {
    load_raw(
        connection,
        DELEGATION_BY_MIGRATION_SQL,
        params![migration_id.as_bytes()],
    )
}

fn load_raw<P>(
    connection: &Connection,
    query: &str,
    parameters: P,
) -> Result<Option<RawDelegation>, AgentOperationsDelegationError>
where
    P: rusqlite::Params,
{
    let row = connection
        .query_row(query, parameters, |row| {
            Ok(RawDelegation {
                migration_id: row.get(0)?,
                workspace_id: row.get(1)?,
                destination_id: row.get(2)?,
                freeze_revision: row.get(3)?,
                manifest_digest: row.get(4)?,
                delegated_at: row.get(5)?,
            })
        })
        .optional()?;
    let Some(raw) = row else {
        return Ok(None);
    };
    decode_delegation(&raw)?;
    Ok(Some(raw))
}

fn decode_delegation(
    raw: &RawDelegation,
) -> Result<DecodedDelegation, AgentOperationsDelegationError> {
    let migration_id = decode_uuid(&raw.migration_id, "migration_id")?;
    let workspace_id = WorkspaceId::from_uuid(decode_uuid(&raw.workspace_id, "workspace_id")?);
    let destination_id = decode_uuid(&raw.destination_id, "destination_id")?;
    let freeze_revision = u64::try_from(raw.freeze_revision)
        .map_err(|_| AgentOperationsDelegationError::CorruptRecord("freeze_revision"))?;
    if freeze_revision == 0 {
        return Err(AgentOperationsDelegationError::CorruptRecord(
            "freeze_revision",
        ));
    }
    let manifest_digest = decode_digest(&raw.manifest_digest, "manifest_digest")?;
    let delegated_at = TimestampMillis::new(raw.delegated_at)?;
    Ok(DecodedDelegation {
        migration_id,
        workspace_id,
        destination_id,
        freeze_revision,
        manifest_digest,
        delegated_at,
    })
}

fn validate_workspace_id(workspace: WorkspaceId) -> Result<(), AgentOperationsDelegationError> {
    if workspace.into_uuid().is_nil() {
        return Err(AgentOperationsDelegationError::InvalidWorkspaceId);
    }
    Ok(())
}

fn validate_manifest_digest(
    digest: &[u8; MANIFEST_DIGEST_BYTES],
) -> Result<(), AgentOperationsDelegationError> {
    if digest.iter().all(|byte| *byte == 0) {
        return Err(AgentOperationsDelegationError::ZeroManifestDigest);
    }
    Ok(())
}

fn decode_uuid(bytes: &[u8], field: &'static str) -> Result<Uuid, AgentOperationsDelegationError> {
    if bytes.len() != ID_BYTES {
        return Err(AgentOperationsDelegationError::InvalidUuidLength {
            field,
            actual: bytes.len(),
            expected: ID_BYTES,
        });
    }
    let value = Uuid::from_slice(bytes)
        .map_err(|source| AgentOperationsDelegationError::Uuid { field, source })?;
    if value.is_nil() {
        return Err(AgentOperationsDelegationError::CorruptRecord(field));
    }
    Ok(value)
}

fn decode_digest(
    bytes: &[u8],
    field: &'static str,
) -> Result<[u8; MANIFEST_DIGEST_BYTES], AgentOperationsDelegationError> {
    if bytes.len() != MANIFEST_DIGEST_BYTES {
        return Err(AgentOperationsDelegationError::InvalidDigestLength {
            field,
            actual: bytes.len(),
            expected: MANIFEST_DIGEST_BYTES,
        });
    }
    let value = <[u8; MANIFEST_DIGEST_BYTES]>::try_from(bytes).map_err(|_| {
        AgentOperationsDelegationError::InvalidDigestLength {
            field,
            actual: bytes.len(),
            expected: MANIFEST_DIGEST_BYTES,
        }
    })?;
    validate_manifest_digest(&value)?;
    Ok(value)
}

fn validate_columns(connection: &Connection) -> Result<(), AgentOperationsDelegationError> {
    let mut statement = connection.prepare("PRAGMA table_info(agent_operations_delegations)")?;
    let mut rows = statement.query([])?;
    let mut actual = Vec::new();
    while let Some(row) = rows.next()? {
        if actual.len() >= MAX_SCHEMA_METADATA_ROWS {
            return Err(AgentOperationsDelegationError::SchemaMetadataTooLarge {
                object: DELEGATIONS_TABLE,
                maximum: MAX_SCHEMA_METADATA_ROWS,
            });
        }
        actual.push((
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, i64>(5)?,
        ));
    }
    let expected = [
        ("migration_id", "BLOB", 1, 1),
        ("workspace_id", "BLOB", 1, 0),
        ("destination_id", "BLOB", 1, 0),
        ("freeze_revision", "INTEGER", 1, 0),
        ("manifest_digest", "BLOB", 1, 0),
        ("delegated_at_ms", "INTEGER", 1, 0),
    ];
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
        return Err(AgentOperationsDelegationError::DamagedSchema(
            DELEGATIONS_TABLE,
        ));
    }
    Ok(())
}

fn validate_foreign_keys(connection: &Connection) -> Result<(), AgentOperationsDelegationError> {
    let mut statement =
        connection.prepare("PRAGMA foreign_key_list(agent_operations_delegations)")?;
    let mut rows = statement.query([])?;
    let mut actual = Vec::new();
    while let Some(row) = rows.next()? {
        if actual.len() >= MAX_SCHEMA_METADATA_ROWS {
            return Err(AgentOperationsDelegationError::SchemaMetadataTooLarge {
                object: DELEGATIONS_TABLE,
                maximum: MAX_SCHEMA_METADATA_ROWS,
            });
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
            "agent_operations_migrations".to_owned(),
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
        return Err(AgentOperationsDelegationError::DamagedSchema(
            DELEGATIONS_TABLE,
        ));
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
