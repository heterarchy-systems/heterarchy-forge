//! Workspace-local durable reservations for future Agent effect bindings.
//!
//! A reservation is an audit record for a trusted source-freeze operation. It
//! deliberately does not create an `agent_instances` row or any presence,
//! event, inbox, or effect-eligible state. Activation belongs to a later
//! Orchestration composition boundary.

use forge_domain::{
    ActivityId, AgentInstanceId, AgentSessionId, AuthenticatedPrincipal, DirectTokenId,
    OAuthGrantId, TimestampMillis, TimestampMillisError, WorkspaceId,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use thiserror::Error;
use uuid::Uuid;

use crate::workspace_agent_migration::{
    self, AgentOperationsFreeze, AgentOperationsFreezeState, AgentOperationsMigrationError,
};

const ID_BYTES: usize = 16;
const MAX_SCHEMA_SQL_BYTES: i64 = 16 * 1024;
const MAX_SCHEMA_METADATA_ROWS: usize = 64;
const RESERVATIONS_TABLE: &str = "agent_binding_reservations";

// This is the one canonical DDL authority for the reservation journal. Both
// creation and validation use this exact source; the Workspace schema
// inventory separately checks that this is the only object owned here.
const RESERVATIONS_TABLE_SQL: &str = "CREATE TABLE agent_binding_reservations (request_id BLOB PRIMARY KEY NOT NULL CHECK(length(request_id) = 16 AND request_id != zeroblob(16)), migration_id BLOB NOT NULL REFERENCES agent_operations_migrations(migration_id) CHECK(length(migration_id) = 16 AND migration_id != zeroblob(16)), workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16), activity_id BLOB NOT NULL REFERENCES activities(activity_id) CHECK(length(activity_id) = 16), destination_id BLOB NOT NULL CHECK(length(destination_id) = 16 AND destination_id != zeroblob(16)), freeze_revision INTEGER NOT NULL CHECK(freeze_revision >= 1), agent_id BLOB NOT NULL UNIQUE CHECK(length(agent_id) = 16 AND agent_id != zeroblob(16)), session_id BLOB NOT NULL CHECK(length(session_id) = 16 AND session_id != zeroblob(16)), principal_kind INTEGER NOT NULL CHECK(principal_kind IN (0, 1, 2)), principal_id BLOB NOT NULL CHECK(length(principal_id) = 16), requested_at_ms INTEGER NOT NULL CHECK(requested_at_ms >= 0), reserved_at_ms INTEGER NOT NULL CHECK(reserved_at_ms >= 0), UNIQUE(migration_id, activity_id, session_id), CHECK((principal_kind = 0 AND principal_id = zeroblob(16)) OR (principal_kind IN (1, 2) AND principal_id != zeroblob(16))))";

/// Failure while validating or recording a future Agent effect binding
/// reservation.
#[derive(Debug, Error)]
pub enum AgentBindingReservationError {
    #[error("Agent binding reservation request identity is nil")]
    InvalidRequestId,
    #[error("Agent binding reservation Activity identity is nil")]
    InvalidActivityId,
    #[error("Agent binding reservation Agent identity is nil")]
    InvalidAgentId,
    #[error("Agent binding reservation session identity is nil")]
    InvalidSessionId,
    #[error("Agent binding reservation authenticated credential identity is nil")]
    InvalidPrincipalId,
    #[error("Agent operations migration {0} is missing from the current Workspace")]
    MigrationMissing(Uuid),
    #[error("Agent operations migration {0} is released and cannot accept reservations")]
    FreezeReleased(Uuid),
    #[error("Agent operations migration {0} is stale or does not match its durable receipt")]
    StaleFreeze(Uuid),
    #[error("Agent binding reservation source migration identity is invalid")]
    InvalidFreeze,
    #[error(transparent)]
    Migration(#[from] AgentOperationsMigrationError),
    #[error("Activity {0} is missing from the current Workspace")]
    ActivityMissing(ActivityId),
    #[error("Activity {activity_id} belongs to Workspace {actual}, expected {expected}")]
    ActivityWorkspaceMismatch {
        activity_id: ActivityId,
        expected: WorkspaceId,
        actual: WorkspaceId,
    },
    #[error("Activity {0} is not Open")]
    ActivityNotOpen(ActivityId),
    #[error("Agent binding reservation request {0} conflicts with durable state")]
    RequestConflict(Uuid),
    #[error("Agent identity {0} already exists")]
    AgentIdConflict(AgentInstanceId),
    #[error("Activity {activity_id} already has an Agent for session {session_id}")]
    ActivitySessionConflict {
        activity_id: ActivityId,
        session_id: AgentSessionId,
    },
    #[error("Agent binding identity is already reserved by request {0}")]
    ReservationConflict(Uuid),
    #[error("reserved_at_ms must be at least the source freeze timestamp")]
    TimestampOrder,
    #[error("Agent binding reservation schema object is damaged: {0}")]
    DamagedSchema(&'static str),
    #[error("Agent binding reservation schema metadata for {object} exceeds {maximum} rows")]
    SchemaMetadataTooLarge {
        object: &'static str,
        maximum: usize,
    },
    #[error(
        "Agent binding reservation schema object {object} is {actual} bytes; maximum is {maximum}"
    )]
    SchemaSqlTooLarge {
        object: &'static str,
        actual: i64,
        maximum: i64,
    },
    #[error(
        "Agent binding reservation persisted UUID field {field} has {actual} bytes; expected {expected}"
    )]
    InvalidUuidLength {
        field: &'static str,
        actual: usize,
        expected: usize,
    },
    #[error("Agent binding reservation persisted UUID field {field} is invalid")]
    Uuid {
        field: &'static str,
        #[source]
        source: uuid::Error,
    },
    #[error(
        "Agent binding reservation persisted principal encoding is invalid for kind {kind}: {detail}"
    )]
    InvalidPrincipalEncoding { kind: i64, detail: &'static str },
    #[error("Agent binding reservation persisted record is corrupt: {0}")]
    CorruptRecord(&'static str),
    #[error(transparent)]
    Timestamp(#[from] TimestampMillisError),
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(
        "Agent binding reservation {request_id} commit is unconfirmed; read the same identity before retrying"
    )]
    CommitUnconfirmed {
        request_id: Uuid,
        #[source]
        source: rusqlite::Error,
    },
}

/// Checked request for reserving one future effect binding.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentBindingReservationRequest {
    request_id: Uuid,
    activity_id: ActivityId,
    agent_id: AgentInstanceId,
    session_id: AgentSessionId,
    principal: AuthenticatedPrincipal,
    requested_at: TimestampMillis,
}

impl AgentBindingReservationRequest {
    /// Construct a request whose identities are safe to persist.
    pub fn new(
        request_id: Uuid,
        activity_id: ActivityId,
        agent_id: AgentInstanceId,
        session_id: AgentSessionId,
        principal: AuthenticatedPrincipal,
        requested_at: TimestampMillis,
    ) -> Result<Self, AgentBindingReservationError> {
        if request_id.is_nil() {
            return Err(AgentBindingReservationError::InvalidRequestId);
        }
        if activity_id.into_uuid().is_nil() {
            return Err(AgentBindingReservationError::InvalidActivityId);
        }
        if agent_id.into_uuid().is_nil() {
            return Err(AgentBindingReservationError::InvalidAgentId);
        }
        if session_id.into_uuid().is_nil() {
            return Err(AgentBindingReservationError::InvalidSessionId);
        }
        validate_principal(principal)?;
        Ok(Self {
            request_id,
            activity_id,
            agent_id,
            session_id,
            principal,
            requested_at,
        })
    }

    pub const fn request_id(&self) -> Uuid {
        self.request_id
    }

    pub const fn activity_id(&self) -> ActivityId {
        self.activity_id
    }

    pub const fn agent_id(&self) -> AgentInstanceId {
        self.agent_id
    }

    pub const fn session_id(&self) -> AgentSessionId {
        self.session_id
    }

    pub const fn principal(&self) -> AuthenticatedPrincipal {
        self.principal
    }

    pub const fn requested_at(&self) -> TimestampMillis {
        self.requested_at
    }
}

/// Durable reservation readback. This is not an active Agent binding and
/// carries no public Agent metadata or effect capability.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentBindingReservation {
    migration_id: Uuid,
    destination_id: Uuid,
    workspace_id: WorkspaceId,
    freeze_revision: u64,
    request: AgentBindingReservationRequest,
    reserved_at: TimestampMillis,
}

impl AgentBindingReservation {
    pub const fn migration_id(&self) -> Uuid {
        self.migration_id
    }

    pub const fn destination_id(&self) -> Uuid {
        self.destination_id
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn freeze_revision(&self) -> u64 {
        self.freeze_revision
    }

    pub const fn request(&self) -> &AgentBindingReservationRequest {
        &self.request
    }

    pub const fn reserved_at(&self) -> TimestampMillis {
        self.reserved_at
    }
}

/// Create the reservation journal table.
pub(crate) fn create_schema(connection: &Connection) -> Result<(), AgentBindingReservationError> {
    connection.execute_batch(RESERVATIONS_TABLE_SQL)?;
    Ok(())
}

/// Return the complete schema object inventory owned by this module.
pub(crate) fn schema_objects() -> Vec<(&'static str, &'static str)> {
    vec![("table", RESERVATIONS_TABLE)]
}

/// Validate the canonical table, columns, and foreign-key shape.
pub(crate) fn validate_schema(connection: &Connection) -> Result<(), AgentBindingReservationError> {
    let length: Option<i64> = connection
        .query_row(
            "SELECT length(CAST(sql AS BLOB)) FROM sqlite_schema WHERE type = ?1 AND name = ?2",
            params!["table", RESERVATIONS_TABLE],
            |row| row.get(0),
        )
        .optional()?;
    let Some(length) = length else {
        return Err(AgentBindingReservationError::DamagedSchema(
            RESERVATIONS_TABLE,
        ));
    };
    if !(0..=MAX_SCHEMA_SQL_BYTES).contains(&length) {
        return Err(AgentBindingReservationError::SchemaSqlTooLarge {
            object: RESERVATIONS_TABLE,
            actual: length,
            maximum: MAX_SCHEMA_SQL_BYTES,
        });
    }
    let actual: String = connection.query_row(
        "SELECT sql FROM sqlite_schema WHERE type = ?1 AND name = ?2",
        params!["table", RESERVATIONS_TABLE],
        |row| row.get(0),
    )?;
    if normalize_sql(&actual) != normalize_sql(RESERVATIONS_TABLE_SQL) {
        return Err(AgentBindingReservationError::DamagedSchema(
            RESERVATIONS_TABLE,
        ));
    }

    validate_columns(connection)?;
    validate_foreign_keys(connection)?;
    Ok(())
}

/// Reserve one future binding in an immediate transaction, or exactly replay
/// the immutable request/source tuple already committed under the request ID.
pub(crate) fn reserve(
    connection: &mut Connection,
    freeze: &AgentOperationsFreeze,
    request: &AgentBindingReservationRequest,
    reserved_at: TimestampMillis,
) -> Result<AgentBindingReservation, AgentBindingReservationError> {
    validate_request(request)?;
    if freeze.migration_id().is_nil() || freeze.destination_id().is_nil() {
        return Err(AgentBindingReservationError::InvalidFreeze);
    }

    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    validate_schema(&transaction)?;
    let current = validate_current_freeze(&transaction, freeze)?;
    validate_activity(&transaction, request.activity_id(), current.workspace_id())?;
    if reserved_at.get() < current.updated_at().get() {
        return Err(AgentBindingReservationError::TimestampOrder);
    }

    if let Some(existing) = load_reservation(&transaction, request.request_id())? {
        if same_source_and_request(&existing, &current, request) {
            transaction.commit().map_err(|source| {
                AgentBindingReservationError::CommitUnconfirmed {
                    request_id: request.request_id(),
                    source,
                }
            })?;
            return Ok(existing);
        }
        return Err(AgentBindingReservationError::RequestConflict(
            request.request_id(),
        ));
    }

    if exists_agent_id(&transaction, request.agent_id())? {
        return Err(AgentBindingReservationError::AgentIdConflict(
            request.agent_id(),
        ));
    }
    if exists_activity_session(&transaction, request.activity_id(), request.session_id())? {
        return Err(AgentBindingReservationError::ActivitySessionConflict {
            activity_id: request.activity_id(),
            session_id: request.session_id(),
        });
    }
    if let Some(existing_request_id) =
        load_reservation_request_for_agent(&transaction, request.agent_id())?
    {
        return Err(AgentBindingReservationError::ReservationConflict(
            existing_request_id,
        ));
    }
    if let Some(existing_request_id) = load_reservation_request_for_activity_session(
        &transaction,
        current.migration_id(),
        request.activity_id(),
        request.session_id(),
    )? {
        return Err(AgentBindingReservationError::ReservationConflict(
            existing_request_id,
        ));
    }

    let freeze_revision = i64::try_from(current.revision())
        .map_err(|_| AgentBindingReservationError::CorruptRecord("freeze_revision"))?;
    let (principal_kind, principal_id) = encode_principal(request.principal());
    transaction.execute(
        "INSERT INTO agent_binding_reservations(
             request_id, migration_id, workspace_id, activity_id, destination_id,
             freeze_revision, agent_id, session_id, principal_kind, principal_id,
             requested_at_ms, reserved_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            request.request_id().as_bytes(),
            current.migration_id().as_bytes(),
            current.workspace_id().into_uuid().as_bytes(),
            request.activity_id().into_uuid().as_bytes(),
            current.destination_id().as_bytes(),
            freeze_revision,
            request.agent_id().into_uuid().as_bytes(),
            request.session_id().into_uuid().as_bytes(),
            principal_kind,
            principal_id.as_slice(),
            request.requested_at().get(),
            reserved_at.get(),
        ],
    )?;

    let result = load_reservation(&transaction, request.request_id())?.ok_or(
        AgentBindingReservationError::CorruptRecord("reservation insert readback"),
    )?;
    transaction
        .commit()
        .map_err(|source| AgentBindingReservationError::CommitUnconfirmed {
            request_id: request.request_id(),
            source,
        })?;
    Ok(result)
}

/// Read one reservation by its stable request identity. Reservations remain
/// readable after their source freeze is released.
pub(crate) fn get(
    connection: &Connection,
    request_id: Uuid,
) -> Result<Option<AgentBindingReservation>, AgentBindingReservationError> {
    if request_id.is_nil() {
        return Err(AgentBindingReservationError::InvalidRequestId);
    }
    validate_schema(connection)?;
    load_reservation(connection, request_id)
}

fn validate_request(
    request: &AgentBindingReservationRequest,
) -> Result<(), AgentBindingReservationError> {
    if request.request_id().is_nil() {
        return Err(AgentBindingReservationError::InvalidRequestId);
    }
    if request.activity_id().into_uuid().is_nil() {
        return Err(AgentBindingReservationError::InvalidActivityId);
    }
    if request.agent_id().into_uuid().is_nil() {
        return Err(AgentBindingReservationError::InvalidAgentId);
    }
    if request.session_id().into_uuid().is_nil() {
        return Err(AgentBindingReservationError::InvalidSessionId);
    }
    validate_principal(request.principal())
}

fn validate_principal(
    principal: AuthenticatedPrincipal,
) -> Result<(), AgentBindingReservationError> {
    match principal {
        AuthenticatedPrincipal::TrustedStdio => Ok(()),
        AuthenticatedPrincipal::DirectToken(id) if !id.into_uuid().is_nil() => Ok(()),
        AuthenticatedPrincipal::OAuthGrant(id) if !id.into_uuid().is_nil() => Ok(()),
        AuthenticatedPrincipal::DirectToken(_) | AuthenticatedPrincipal::OAuthGrant(_) => {
            Err(AgentBindingReservationError::InvalidPrincipalId)
        }
    }
}

fn validate_current_freeze(
    connection: &Connection,
    supplied: &AgentOperationsFreeze,
) -> Result<AgentOperationsFreeze, AgentBindingReservationError> {
    let Some(current) = workspace_agent_migration::get(connection, supplied.migration_id())? else {
        return Err(AgentBindingReservationError::MigrationMissing(
            supplied.migration_id(),
        ));
    };
    if current.state() != AgentOperationsFreezeState::Frozen {
        return Err(AgentBindingReservationError::FreezeReleased(
            supplied.migration_id(),
        ));
    }
    if current.migration_id() != supplied.migration_id()
        || current.destination_id() != supplied.destination_id()
        || current.workspace_id() != supplied.workspace_id()
        || current.revision() != supplied.revision()
        || current.state() != supplied.state()
        || current.created_at() != supplied.created_at()
        || current.updated_at() != supplied.updated_at()
    {
        return Err(AgentBindingReservationError::StaleFreeze(
            supplied.migration_id(),
        ));
    }
    Ok(current)
}

fn validate_activity(
    connection: &Connection,
    activity_id: ActivityId,
    expected_workspace: WorkspaceId,
) -> Result<(), AgentBindingReservationError> {
    let raw = connection
        .query_row(
            "SELECT substr(workspace_id, 1, 17), state
             FROM activities WHERE activity_id = ?1 LIMIT 1",
            params![activity_id.into_uuid().as_bytes()],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()?;
    let Some((workspace, state)) = raw else {
        return Err(AgentBindingReservationError::ActivityMissing(activity_id));
    };
    let actual_workspace =
        WorkspaceId::from_uuid(decode_uuid(&workspace, "activities.workspace_id")?);
    if actual_workspace != expected_workspace {
        return Err(AgentBindingReservationError::ActivityWorkspaceMismatch {
            activity_id,
            expected: expected_workspace,
            actual: actual_workspace,
        });
    }
    if state != 1 {
        if !matches!(state, 0 | 2) {
            return Err(AgentBindingReservationError::CorruptRecord(
                "activities.state",
            ));
        }
        return Err(AgentBindingReservationError::ActivityNotOpen(activity_id));
    }
    Ok(())
}

fn exists_agent_id(
    connection: &Connection,
    agent_id: AgentInstanceId,
) -> Result<bool, AgentBindingReservationError> {
    Ok(connection
        .query_row(
            "SELECT 1 FROM agent_instances WHERE agent_id = ?1 LIMIT 1",
            params![agent_id.into_uuid().as_bytes()],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .is_some())
}

fn exists_activity_session(
    connection: &Connection,
    activity_id: ActivityId,
    session_id: AgentSessionId,
) -> Result<bool, AgentBindingReservationError> {
    Ok(connection
        .query_row(
            "SELECT 1 FROM agent_instances
             WHERE activity_id = ?1 AND session_id = ?2 LIMIT 1",
            params![
                activity_id.into_uuid().as_bytes(),
                session_id.into_uuid().as_bytes()
            ],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .is_some())
}

fn load_reservation_request_for_agent(
    connection: &Connection,
    agent_id: AgentInstanceId,
) -> Result<Option<Uuid>, AgentBindingReservationError> {
    let value = connection
        .query_row(
            "SELECT substr(request_id, 1, 17)
             FROM agent_binding_reservations WHERE agent_id = ?1 LIMIT 1",
            params![agent_id.into_uuid().as_bytes()],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?;
    value
        .map(|bytes| decode_uuid(&bytes, "agent_binding_reservations.request_id"))
        .transpose()
}

fn load_reservation_request_for_activity_session(
    connection: &Connection,
    migration_id: Uuid,
    activity_id: ActivityId,
    session_id: AgentSessionId,
) -> Result<Option<Uuid>, AgentBindingReservationError> {
    let value = connection
        .query_row(
            "SELECT substr(request_id, 1, 17)
             FROM agent_binding_reservations
             WHERE migration_id = ?1 AND activity_id = ?2 AND session_id = ?3
             LIMIT 1",
            params![
                migration_id.as_bytes(),
                activity_id.into_uuid().as_bytes(),
                session_id.into_uuid().as_bytes()
            ],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?;
    value
        .map(|bytes| decode_uuid(&bytes, "agent_binding_reservations.request_id"))
        .transpose()
}

fn same_source_and_request(
    existing: &AgentBindingReservation,
    freeze: &AgentOperationsFreeze,
    request: &AgentBindingReservationRequest,
) -> bool {
    existing.migration_id() == freeze.migration_id()
        && existing.destination_id() == freeze.destination_id()
        && existing.workspace_id() == freeze.workspace_id()
        && existing.freeze_revision() == freeze.revision()
        && existing.request() == request
}

fn load_reservation(
    connection: &Connection,
    request_id: Uuid,
) -> Result<Option<AgentBindingReservation>, AgentBindingReservationError> {
    let raw = connection
        .query_row(
            "SELECT substr(request_id, 1, 17), substr(migration_id, 1, 17),
                    substr(workspace_id, 1, 17), substr(activity_id, 1, 17),
                    substr(destination_id, 1, 17), freeze_revision,
                    substr(agent_id, 1, 17), substr(session_id, 1, 17),
                    principal_kind, substr(principal_id, 1, 17),
                    requested_at_ms, reserved_at_ms
             FROM agent_binding_reservations WHERE request_id = ?1 LIMIT 1",
            params![request_id.as_bytes()],
            |row| {
                Ok(RawReservation {
                    request_id: row.get(0)?,
                    migration_id: row.get(1)?,
                    workspace_id: row.get(2)?,
                    activity_id: row.get(3)?,
                    destination_id: row.get(4)?,
                    freeze_revision: row.get(5)?,
                    agent_id: row.get(6)?,
                    session_id: row.get(7)?,
                    principal_kind: row.get(8)?,
                    principal_id: row.get(9)?,
                    requested_at: row.get(10)?,
                    reserved_at: row.get(11)?,
                })
            },
        )
        .optional()?;
    raw.as_ref().map(decode_reservation).transpose()
}

struct RawReservation {
    request_id: Vec<u8>,
    migration_id: Vec<u8>,
    workspace_id: Vec<u8>,
    activity_id: Vec<u8>,
    destination_id: Vec<u8>,
    freeze_revision: i64,
    agent_id: Vec<u8>,
    session_id: Vec<u8>,
    principal_kind: i64,
    principal_id: Vec<u8>,
    requested_at: i64,
    reserved_at: i64,
}

fn decode_reservation(
    raw: &RawReservation,
) -> Result<AgentBindingReservation, AgentBindingReservationError> {
    let request_id = decode_uuid(&raw.request_id, "request_id")?;
    let migration_id = decode_uuid(&raw.migration_id, "migration_id")?;
    let destination_id = decode_uuid(&raw.destination_id, "destination_id")?;
    let freeze_revision = u64::try_from(raw.freeze_revision)
        .map_err(|_| AgentBindingReservationError::CorruptRecord("freeze_revision"))?;
    if freeze_revision == 0 {
        return Err(AgentBindingReservationError::CorruptRecord(
            "freeze_revision",
        ));
    }
    let requested_at = TimestampMillis::new(raw.requested_at)?;
    let reserved_at = TimestampMillis::new(raw.reserved_at)?;
    let request = AgentBindingReservationRequest::new(
        request_id,
        ActivityId::from_uuid(decode_uuid(&raw.activity_id, "activity_id")?),
        AgentInstanceId::from_uuid(decode_uuid(&raw.agent_id, "agent_id")?),
        AgentSessionId::from_uuid(decode_uuid(&raw.session_id, "session_id")?),
        decode_principal(raw.principal_kind, &raw.principal_id)?,
        requested_at,
    )?;
    Ok(AgentBindingReservation {
        migration_id,
        destination_id,
        workspace_id: WorkspaceId::from_uuid(decode_uuid(&raw.workspace_id, "workspace_id")?),
        freeze_revision,
        request,
        reserved_at,
    })
}

fn encode_principal(principal: AuthenticatedPrincipal) -> (i64, [u8; ID_BYTES]) {
    match principal {
        AuthenticatedPrincipal::TrustedStdio => (0, [0; ID_BYTES]),
        AuthenticatedPrincipal::DirectToken(id) => (1, id.into_uuid().into_bytes()),
        AuthenticatedPrincipal::OAuthGrant(id) => (2, id.into_uuid().into_bytes()),
    }
}

fn decode_principal(
    kind: i64,
    bytes: &[u8],
) -> Result<AuthenticatedPrincipal, AgentBindingReservationError> {
    if kind == 0 && bytes.iter().any(|byte| *byte != 0) {
        return Err(AgentBindingReservationError::InvalidPrincipalEncoding {
            kind,
            detail: "TrustedStdio principal_id must be zero",
        });
    }
    let id = decode_uuid(bytes, "principal_id")?;
    match kind {
        0 => Ok(AuthenticatedPrincipal::TrustedStdio),
        1 if !id.is_nil() => Ok(AuthenticatedPrincipal::DirectToken(
            DirectTokenId::from_uuid(id),
        )),
        2 if !id.is_nil() => Ok(AuthenticatedPrincipal::OAuthGrant(OAuthGrantId::from_uuid(
            id,
        ))),
        1 | 2 => Err(AgentBindingReservationError::InvalidPrincipalEncoding {
            kind,
            detail: "credential principal_id must not be nil",
        }),
        _ => Err(AgentBindingReservationError::InvalidPrincipalEncoding {
            kind,
            detail: "principal_kind is outside 0..=2",
        }),
    }
}

fn decode_uuid(bytes: &[u8], field: &'static str) -> Result<Uuid, AgentBindingReservationError> {
    if bytes.len() != ID_BYTES {
        return Err(AgentBindingReservationError::InvalidUuidLength {
            field,
            actual: bytes.len(),
            expected: ID_BYTES,
        });
    }
    Uuid::from_slice(bytes).map_err(|source| AgentBindingReservationError::Uuid { field, source })
}

fn validate_columns(connection: &Connection) -> Result<(), AgentBindingReservationError> {
    let mut statement = connection.prepare("PRAGMA table_info(agent_binding_reservations)")?;
    let mut rows = statement.query([])?;
    let mut actual = Vec::new();
    while let Some(row) = rows.next()? {
        if actual.len() >= MAX_SCHEMA_METADATA_ROWS {
            return Err(AgentBindingReservationError::SchemaMetadataTooLarge {
                object: RESERVATIONS_TABLE,
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
        ("request_id", "BLOB", 1, 1),
        ("migration_id", "BLOB", 1, 0),
        ("workspace_id", "BLOB", 1, 0),
        ("activity_id", "BLOB", 1, 0),
        ("destination_id", "BLOB", 1, 0),
        ("freeze_revision", "INTEGER", 1, 0),
        ("agent_id", "BLOB", 1, 0),
        ("session_id", "BLOB", 1, 0),
        ("principal_kind", "INTEGER", 1, 0),
        ("principal_id", "BLOB", 1, 0),
        ("requested_at_ms", "INTEGER", 1, 0),
        ("reserved_at_ms", "INTEGER", 1, 0),
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
        return Err(AgentBindingReservationError::DamagedSchema(
            RESERVATIONS_TABLE,
        ));
    }
    Ok(())
}

fn validate_foreign_keys(connection: &Connection) -> Result<(), AgentBindingReservationError> {
    let mut statement =
        connection.prepare("PRAGMA foreign_key_list(agent_binding_reservations)")?;
    let mut rows = statement.query([])?;
    let mut actual = Vec::new();
    while let Some(row) = rows.next()? {
        if actual.len() >= MAX_SCHEMA_METADATA_ROWS {
            return Err(AgentBindingReservationError::SchemaMetadataTooLarge {
                object: RESERVATIONS_TABLE,
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
            "activities".to_owned(),
            "activity_id".to_owned(),
            "activity_id".to_owned(),
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
        return Err(AgentBindingReservationError::DamagedSchema(
            RESERVATIONS_TABLE,
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
