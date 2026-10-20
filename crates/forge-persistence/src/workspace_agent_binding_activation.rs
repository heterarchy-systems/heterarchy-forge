//! Workspace-local activation receipts for reserved Agent effect bindings.
//!
//! Activation is an internal trusted Orchestration composition boundary.  It
//! consumes an already sealed source delegation and an immutable reservation,
//! records the activation receipt, and asks the Agent repository to insert the
//! attached Agent in the same `SQLite` transaction.  This module never writes
//! presence, membership events, inbox receipts, or public membership state.
//! The initial work-focus fact and its source outbox copy are committed with
//! the binding. The manifest digest seals the historical import; subsequent
//! membership commits are supplied by trusted destination composition.

use forge_domain::{
    ActivityId, AgentDeclaredRole, AgentDisplayName, AgentInstanceId, AgentSessionId,
    AgentTransportKind, AuthenticatedPrincipal, RegisteredAgentInstance, TimestampMillis,
    TimestampMillisError, WorkspaceId,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use thiserror::Error;
use uuid::Uuid;

use crate::workspace_agent_binding_rejections;
use crate::workspace_agent_binding_reservations::{
    self, AgentBindingReservation, AgentBindingReservationError,
};
use crate::workspace_agent_delegation::{
    self, AgentOperationsDelegation, AgentOperationsDelegationError,
};
use crate::workspace_agents::{self, AgentStoreError};

const ID_BYTES: usize = 16;
const DIGEST_BYTES: usize = 32;
const MAX_SCHEMA_SQL_BYTES: i64 = 16 * 1024;
const MAX_SCHEMA_METADATA_ROWS: usize = 64;
const ACTIVATIONS_TABLE: &str = "agent_binding_activations";

// This is the one canonical DDL authority for the immutable activation
// journal. Creation and validation both consume this exact string.
const ACTIVATIONS_TABLE_SQL: &str = "CREATE TABLE agent_binding_activations (request_id BLOB PRIMARY KEY NOT NULL REFERENCES agent_binding_reservations(request_id) CHECK(length(request_id) = 16 AND request_id != zeroblob(16)), membership_digest BLOB NOT NULL CHECK(length(membership_digest) = 32 AND membership_digest != zeroblob(32)), display_name TEXT NOT NULL CHECK(length(CAST(display_name AS BLOB)) BETWEEN 1 AND 128), declared_role TEXT NOT NULL CHECK(length(CAST(declared_role AS BLOB)) BETWEEN 1 AND 128), transport_kind INTEGER NOT NULL CHECK(transport_kind IN (0, 1, 2, 3)), activated_at_ms INTEGER NOT NULL CHECK(activated_at_ms >= 0))";

/// Failure while validating or committing one reserved Agent binding
/// activation.
#[derive(Debug, Error)]
pub enum AgentBindingActivationError {
    #[error("Agent binding activation request identity is nil")]
    InvalidRequestId,
    #[error("Agent binding activation membership digest must not be zero")]
    ZeroMembershipDigest,
    #[error("Agent operations delegation for Workspace {0} is missing")]
    DelegationMissing(WorkspaceId),
    #[error("Agent operations delegation for Workspace {0} is stale")]
    StaleDelegation(WorkspaceId),
    #[error(transparent)]
    Delegation(#[from] AgentOperationsDelegationError),
    #[error("Agent binding reservation {0} is missing")]
    ReservationMissing(Uuid),
    #[error("Agent binding reservation {0} does not match the current delegation")]
    ReservationSourceConflict(Uuid),
    #[error("Agent binding activation request {0} conflicts with durable state")]
    RequestConflict(Uuid),
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
    #[error("Agent identity {0} already exists and cannot be activated again")]
    AgentIdConflict(AgentInstanceId),
    #[error("Activity {activity_id} already has an Agent for session {session_id}")]
    ActivitySessionConflict {
        activity_id: ActivityId,
        session_id: AgentSessionId,
    },
    #[error("Agent {0} is missing while replaying its activation receipt")]
    AgentMissing(AgentInstanceId),
    #[error("Agent {0} is detached and cannot be resurrected")]
    AgentDetached(AgentInstanceId),
    #[error("Agent {0} no longer matches its immutable activation metadata")]
    AgentMetadataConflict(AgentInstanceId),
    #[error("Authenticated principal cannot use the requested Agent transport")]
    PrincipalTransportMismatch,
    #[error("activation timestamp is earlier than its source delegation or reservation")]
    TimestampOrder,
    #[error("Agent binding activation schema object is damaged: {0}")]
    DamagedSchema(&'static str),
    #[error("Agent binding activation schema metadata for {object} exceeds {maximum} rows")]
    SchemaMetadataTooLarge {
        object: &'static str,
        maximum: usize,
    },
    #[error(
        "Agent binding activation schema object {object} is {actual} bytes; maximum is {maximum}"
    )]
    SchemaSqlTooLarge {
        object: &'static str,
        actual: i64,
        maximum: i64,
    },
    #[error(
        "Agent binding activation persisted UUID field {field} has {actual} bytes; expected {expected}"
    )]
    InvalidUuidLength {
        field: &'static str,
        actual: usize,
        expected: usize,
    },
    #[error("Agent binding activation persisted UUID field {field} is invalid")]
    Uuid {
        field: &'static str,
        #[source]
        source: uuid::Error,
    },
    #[error(
        "Agent binding activation persisted digest field {field} has {actual} bytes; expected {expected}"
    )]
    InvalidDigestLength {
        field: &'static str,
        actual: usize,
        expected: usize,
    },
    #[error("Agent binding activation persisted metadata field {field} is not valid UTF-8")]
    InvalidMetadata { field: &'static str },
    #[error("Agent binding activation persisted transport kind is invalid: {0}")]
    InvalidTransport(i64),
    #[error("Agent binding activation persisted record is corrupt: {0}")]
    CorruptRecord(&'static str),
    #[error(transparent)]
    Reservation(#[from] AgentBindingReservationError),
    #[error(transparent)]
    Agent(#[from] AgentStoreError),
    #[error("Agent binding rejection read failed while checking activation exclusivity")]
    Rejection(
        #[source] Box<crate::workspace_agent_binding_rejections::AgentBindingRejectionStoreError>,
    ),
    #[error(transparent)]
    Timestamp(#[from] TimestampMillisError),
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(
        "Agent binding activation {request_id} commit is unconfirmed; read the same identity before retrying"
    )]
    CommitUnconfirmed {
        request_id: Uuid,
        #[source]
        source: rusqlite::Error,
    },
}

/// Checked internal request to activate one reserved Agent binding.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentBindingActivationRequest {
    request_id: Uuid,
    membership_digest: [u8; DIGEST_BYTES],
    display_name: AgentDisplayName,
    declared_role: AgentDeclaredRole,
    transport: AgentTransportKind,
}

impl AgentBindingActivationRequest {
    /// Construct the trusted composition input. The request contains no
    /// caller-supplied committed flag or activation authority.
    pub fn new(
        request_id: Uuid,
        membership_digest: [u8; DIGEST_BYTES],
        display_name: AgentDisplayName,
        declared_role: AgentDeclaredRole,
        transport: AgentTransportKind,
    ) -> Result<Self, AgentBindingActivationError> {
        if request_id.is_nil() {
            return Err(AgentBindingActivationError::InvalidRequestId);
        }
        if membership_digest.iter().all(|byte| *byte == 0) {
            return Err(AgentBindingActivationError::ZeroMembershipDigest);
        }
        Ok(Self {
            request_id,
            membership_digest,
            display_name,
            declared_role,
            transport,
        })
    }

    pub const fn request_id(&self) -> Uuid {
        self.request_id
    }

    pub const fn membership_digest(&self) -> [u8; DIGEST_BYTES] {
        self.membership_digest
    }

    pub const fn display_name(&self) -> &AgentDisplayName {
        &self.display_name
    }

    pub const fn declared_role(&self) -> &AgentDeclaredRole {
        &self.declared_role
    }

    pub const fn transport(&self) -> AgentTransportKind {
        self.transport
    }
}

/// Immutable activation receipt for one reserved binding.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentBindingActivation {
    reservation: AgentBindingReservation,
    membership_digest: [u8; DIGEST_BYTES],
    display_name: AgentDisplayName,
    declared_role: AgentDeclaredRole,
    transport: AgentTransportKind,
    activated_at: TimestampMillis,
}

impl AgentBindingActivation {
    pub const fn reservation(&self) -> &AgentBindingReservation {
        &self.reservation
    }

    pub const fn membership_digest(&self) -> [u8; DIGEST_BYTES] {
        self.membership_digest
    }

    pub const fn display_name(&self) -> &AgentDisplayName {
        &self.display_name
    }

    pub const fn declared_role(&self) -> &AgentDeclaredRole {
        &self.declared_role
    }

    pub const fn transport(&self) -> AgentTransportKind {
        self.transport
    }

    pub const fn activated_at(&self) -> TimestampMillis {
        self.activated_at
    }

    pub const fn request_id(&self) -> Uuid {
        self.reservation.request().request_id()
    }

    pub const fn agent_id(&self) -> AgentInstanceId {
        self.reservation.request().agent_id()
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.reservation.workspace_id()
    }
}

/// Create the immutable activation receipt table.
pub(crate) fn create_schema(connection: &Connection) -> Result<(), AgentBindingActivationError> {
    connection.execute_batch(ACTIVATIONS_TABLE_SQL)?;
    Ok(())
}

/// Return the complete schema object inventory owned by this module.
pub(crate) fn schema_objects() -> Vec<(&'static str, &'static str)> {
    vec![("table", ACTIVATIONS_TABLE)]
}

/// Validate the canonical activation table and its reservation foreign key.
pub(crate) fn validate_schema(connection: &Connection) -> Result<(), AgentBindingActivationError> {
    let length: Option<i64> = connection
        .query_row(
            "SELECT length(CAST(sql AS BLOB)) FROM sqlite_schema WHERE type = ?1 AND name = ?2",
            params!["table", ACTIVATIONS_TABLE],
            |row| row.get(0),
        )
        .optional()?;
    let Some(length) = length else {
        return Err(AgentBindingActivationError::DamagedSchema(
            ACTIVATIONS_TABLE,
        ));
    };
    if !(0..=MAX_SCHEMA_SQL_BYTES).contains(&length) {
        return Err(AgentBindingActivationError::SchemaSqlTooLarge {
            object: ACTIVATIONS_TABLE,
            actual: length,
            maximum: MAX_SCHEMA_SQL_BYTES,
        });
    }
    let actual: String = connection.query_row(
        "SELECT sql FROM sqlite_schema WHERE type = ?1 AND name = ?2",
        params!["table", ACTIVATIONS_TABLE],
        |row| row.get(0),
    )?;
    if i64::try_from(actual.len()).ok() != Some(length)
        || normalize_sql(&actual) != normalize_sql(ACTIVATIONS_TABLE_SQL)
    {
        return Err(AgentBindingActivationError::DamagedSchema(
            ACTIVATIONS_TABLE,
        ));
    }
    validate_columns(connection)?;
    validate_foreign_keys(connection)
}

/// Activate one reserved binding under the exact current source delegation.
/// The activation receipt is inserted before the Agent helper, so both rows
/// are committed or rolled back together and the Agent trigger can validate
/// the exact reservation marker.
pub(crate) fn activate(
    connection: &mut Connection,
    delegation: &AgentOperationsDelegation,
    request: &AgentBindingActivationRequest,
    activated_at: TimestampMillis,
) -> Result<AgentBindingActivation, AgentBindingActivationError> {
    validate_request(request)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    validate_schema(&transaction)?;

    let current = workspace_agent_delegation::get(&transaction, delegation.workspace_id())?.ok_or(
        AgentBindingActivationError::DelegationMissing(delegation.workspace_id()),
    )?;
    if current != *delegation {
        return Err(AgentBindingActivationError::StaleDelegation(
            delegation.workspace_id(),
        ));
    }

    let Some(reservation) =
        workspace_agent_binding_reservations::get(&transaction, request.request_id())?
    else {
        return Err(AgentBindingActivationError::ReservationMissing(
            request.request_id(),
        ));
    };
    validate_reservation_source(&reservation, &current)?;
    validate_activation_time(&reservation, &current, activated_at)?;
    validate_activity(
        &transaction,
        reservation.request().activity_id(),
        current.workspace_id(),
    )?;
    validate_transport(reservation.request().principal(), request.transport())?;

    if workspace_agent_binding_rejections::get(&transaction, request.request_id())
        .map_err(|error| AgentBindingActivationError::Rejection(Box::new(error)))?
        .is_some()
    {
        return Err(AgentBindingActivationError::RequestConflict(
            request.request_id(),
        ));
    }

    if let Some(raw) = load_activation(&transaction, request.request_id())? {
        let receipt = decode_activation(&raw, reservation.clone())?;
        if !same_request(&receipt, request) {
            return Err(AgentBindingActivationError::RequestConflict(
                request.request_id(),
            ));
        }
        verify_current_agent(&transaction, &receipt)?;
        transaction
            .commit()
            .map_err(|source| AgentBindingActivationError::CommitUnconfirmed {
                request_id: request.request_id(),
                source,
            })?;
        return Ok(receipt);
    }

    ensure_binding_available(&transaction, &reservation)?;

    let agent = RegisteredAgentInstance::create_bound(
        reservation.request().agent_id(),
        reservation.workspace_id(),
        reservation.request().activity_id(),
        reservation.request().session_id(),
        request.display_name().clone(),
        request.declared_role().clone(),
        request.transport(),
        reservation.request().principal(),
        activated_at,
    );
    transaction.execute(
        "INSERT INTO agent_binding_activations(
             request_id, membership_digest, display_name, declared_role,
             transport_kind, activated_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            request.request_id().as_bytes(),
            request.membership_digest().as_slice(),
            request.display_name().as_str(),
            request.declared_role().as_str(),
            encode_transport(request.transport()),
            activated_at.get(),
        ],
    )?;
    let raw = load_activation(&transaction, request.request_id())?.ok_or(
        AgentBindingActivationError::CorruptRecord("activation insert readback"),
    )?;
    let receipt = decode_activation(&raw, reservation)?;
    if !same_request(&receipt, request) || receipt.activated_at() != activated_at {
        return Err(AgentBindingActivationError::CorruptRecord(
            "activation insert identity",
        ));
    }

    workspace_agents::insert_reserved_binding(&transaction, &agent)?;
    transaction
        .commit()
        .map_err(|source| AgentBindingActivationError::CommitUnconfirmed {
            request_id: request.request_id(),
            source,
        })?;
    Ok(receipt)
}

fn ensure_binding_available(
    connection: &Connection,
    reservation: &AgentBindingReservation,
) -> Result<(), AgentBindingActivationError> {
    if workspace_agents::get_in_transaction(connection, reservation.request().agent_id())?.is_some()
    {
        return Err(AgentBindingActivationError::AgentIdConflict(
            reservation.request().agent_id(),
        ));
    }
    if exists_activity_session(
        connection,
        reservation.request().activity_id(),
        reservation.request().session_id(),
    )? {
        return Err(AgentBindingActivationError::ActivitySessionConflict {
            activity_id: reservation.request().activity_id(),
            session_id: reservation.request().session_id(),
        });
    }

    Ok(())
}

/// Read one immutable activation receipt without rechecking current source
/// delegation or Agent eligibility.
pub(crate) fn get(
    connection: &Connection,
    request_id: Uuid,
) -> Result<Option<AgentBindingActivation>, AgentBindingActivationError> {
    if request_id.is_nil() {
        return Err(AgentBindingActivationError::InvalidRequestId);
    }
    validate_schema(connection)?;
    let Some(raw) = load_activation(connection, request_id)? else {
        return Ok(None);
    };
    let reservation = workspace_agent_binding_reservations::get(connection, request_id)?
        .ok_or(AgentBindingActivationError::ReservationMissing(request_id))?;
    Ok(Some(decode_activation(&raw, reservation)?))
}

fn validate_request(
    request: &AgentBindingActivationRequest,
) -> Result<(), AgentBindingActivationError> {
    if request.request_id().is_nil() {
        return Err(AgentBindingActivationError::InvalidRequestId);
    }
    if request.membership_digest().iter().all(|byte| *byte == 0) {
        return Err(AgentBindingActivationError::ZeroMembershipDigest);
    }
    Ok(())
}

fn validate_reservation_source(
    reservation: &AgentBindingReservation,
    delegation: &AgentOperationsDelegation,
) -> Result<(), AgentBindingActivationError> {
    if reservation.migration_id() != delegation.migration_id()
        || reservation.destination_id() != delegation.destination_id()
        || reservation.workspace_id() != delegation.workspace_id()
        || reservation.freeze_revision() != delegation.freeze().revision()
    {
        return Err(AgentBindingActivationError::ReservationSourceConflict(
            reservation.request().request_id(),
        ));
    }
    Ok(())
}

fn validate_activation_time(
    reservation: &AgentBindingReservation,
    delegation: &AgentOperationsDelegation,
    activated_at: TimestampMillis,
) -> Result<(), AgentBindingActivationError> {
    if activated_at.get() < delegation.delegated_at().get()
        || activated_at.get() < reservation.reserved_at().get()
    {
        return Err(AgentBindingActivationError::TimestampOrder);
    }
    Ok(())
}

pub(crate) fn validate_transport(
    principal: AuthenticatedPrincipal,
    transport: AgentTransportKind,
) -> Result<(), AgentBindingActivationError> {
    if principal.is_token_or_grant_authenticated() && !transport.is_retired_or_stream() {
        return Err(AgentBindingActivationError::PrincipalTransportMismatch);
    }
    Ok(())
}

fn validate_activity(
    connection: &Connection,
    activity_id: ActivityId,
    expected_workspace: WorkspaceId,
) -> Result<(), AgentBindingActivationError> {
    let raw = connection
        .query_row(
            "SELECT substr(workspace_id, 1, 17), state
             FROM activities WHERE activity_id = ?1 LIMIT 1",
            params![activity_id.into_uuid().as_bytes()],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()?;
    let Some((workspace, state)) = raw else {
        return Err(AgentBindingActivationError::ActivityMissing(activity_id));
    };
    let actual_workspace =
        WorkspaceId::from_uuid(decode_uuid(&workspace, "activities.workspace_id")?);
    if actual_workspace != expected_workspace {
        return Err(AgentBindingActivationError::ActivityWorkspaceMismatch {
            activity_id,
            expected: expected_workspace,
            actual: actual_workspace,
        });
    }
    if state != 1 {
        if !matches!(state, 0 | 2) {
            return Err(AgentBindingActivationError::CorruptRecord(
                "activities.state",
            ));
        }
        return Err(AgentBindingActivationError::ActivityNotOpen(activity_id));
    }
    Ok(())
}

fn exists_activity_session(
    connection: &Connection,
    activity_id: ActivityId,
    session_id: AgentSessionId,
) -> Result<bool, AgentBindingActivationError> {
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

fn verify_current_agent(
    connection: &Connection,
    activation: &AgentBindingActivation,
) -> Result<(), AgentBindingActivationError> {
    let agent = workspace_agents::get_in_transaction(connection, activation.agent_id())?.ok_or(
        AgentBindingActivationError::AgentMissing(activation.agent_id()),
    )?;
    let request = activation.reservation().request();
    if !agent.attachment_state().is_attached() {
        return Err(AgentBindingActivationError::AgentDetached(
            activation.agent_id(),
        ));
    }
    if agent.workspace_id() != activation.workspace_id()
        || agent.activity_id() != request.activity_id()
        || agent.session_id() != Some(request.session_id())
        || agent.principal() != request.principal()
        || agent.display_name() != activation.display_name()
        || agent.declared_role() != activation.declared_role()
        || agent.transport_kind() != activation.transport()
        || agent.created_at() != activation.activated_at()
    {
        return Err(AgentBindingActivationError::AgentMetadataConflict(
            activation.agent_id(),
        ));
    }
    Ok(())
}

fn same_request(
    activation: &AgentBindingActivation,
    request: &AgentBindingActivationRequest,
) -> bool {
    activation.request_id() == request.request_id()
        && activation.membership_digest() == request.membership_digest()
        && activation.display_name() == request.display_name()
        && activation.declared_role() == request.declared_role()
        && activation.transport() == request.transport()
}

#[derive(Debug)]
struct RawActivation {
    request_id: Vec<u8>,
    membership_digest: Vec<u8>,
    display_name: Vec<u8>,
    declared_role: Vec<u8>,
    transport: i64,
    activated_at: i64,
}

fn load_activation(
    connection: &Connection,
    request_id: Uuid,
) -> Result<Option<RawActivation>, AgentBindingActivationError> {
    let raw = connection
        .query_row(
            "SELECT substr(request_id, 1, 17), substr(membership_digest, 1, 33),
                    substr(CAST(display_name AS BLOB), 1, 129),
                    substr(CAST(declared_role AS BLOB), 1, 129),
                    transport_kind, activated_at_ms
             FROM agent_binding_activations WHERE request_id = ?1 LIMIT 1",
            params![request_id.as_bytes()],
            |row| {
                Ok(RawActivation {
                    request_id: row.get(0)?,
                    membership_digest: row.get(1)?,
                    display_name: row.get(2)?,
                    declared_role: row.get(3)?,
                    transport: row.get(4)?,
                    activated_at: row.get(5)?,
                })
            },
        )
        .optional()?;
    Ok(raw)
}

fn decode_activation(
    raw: &RawActivation,
    reservation: AgentBindingReservation,
) -> Result<AgentBindingActivation, AgentBindingActivationError> {
    let request_id = decode_uuid(&raw.request_id, "request_id")?;
    if request_id != reservation.request().request_id() {
        return Err(AgentBindingActivationError::CorruptRecord(
            "activation.request_id",
        ));
    }
    let membership_digest = decode_digest(&raw.membership_digest, "membership_digest")?;
    let display_name = AgentDisplayName::new(decode_metadata(&raw.display_name, "display_name")?)
        .map_err(|_| AgentBindingActivationError::InvalidMetadata {
        field: "display_name",
    })?;
    let declared_role =
        AgentDeclaredRole::new(decode_metadata(&raw.declared_role, "declared_role")?).map_err(
            |_| AgentBindingActivationError::InvalidMetadata {
                field: "declared_role",
            },
        )?;
    let transport = decode_transport(raw.transport)?;
    let activated_at = TimestampMillis::new(raw.activated_at)?;
    Ok(AgentBindingActivation {
        reservation,
        membership_digest,
        display_name,
        declared_role,
        transport,
        activated_at,
    })
}

fn decode_metadata(
    bytes: &[u8],
    field: &'static str,
) -> Result<String, AgentBindingActivationError> {
    String::from_utf8(bytes.to_owned())
        .map_err(|_| AgentBindingActivationError::InvalidMetadata { field })
}

fn decode_transport(value: i64) -> Result<AgentTransportKind, AgentBindingActivationError> {
    match value {
        0 => Ok(AgentTransportKind::Retired),
        1 => Ok(AgentTransportKind::Stdio),
        2 => Ok(AgentTransportKind::StreamableHttp),
        3 => Ok(AgentTransportKind::Other),
        other => Err(AgentBindingActivationError::InvalidTransport(other)),
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

fn decode_uuid(bytes: &[u8], field: &'static str) -> Result<Uuid, AgentBindingActivationError> {
    if bytes.len() != ID_BYTES {
        return Err(AgentBindingActivationError::InvalidUuidLength {
            field,
            actual: bytes.len(),
            expected: ID_BYTES,
        });
    }
    Uuid::from_slice(bytes).map_err(|source| AgentBindingActivationError::Uuid { field, source })
}

fn decode_digest(
    bytes: &[u8],
    field: &'static str,
) -> Result<[u8; DIGEST_BYTES], AgentBindingActivationError> {
    if bytes.len() != DIGEST_BYTES {
        return Err(AgentBindingActivationError::InvalidDigestLength {
            field,
            actual: bytes.len(),
            expected: DIGEST_BYTES,
        });
    }
    let digest: [u8; DIGEST_BYTES] =
        bytes
            .try_into()
            .map_err(|_| AgentBindingActivationError::InvalidDigestLength {
                field,
                actual: bytes.len(),
                expected: DIGEST_BYTES,
            })?;
    if digest.iter().all(|byte| *byte == 0) {
        return Err(AgentBindingActivationError::ZeroMembershipDigest);
    }
    Ok(digest)
}

fn validate_columns(connection: &Connection) -> Result<(), AgentBindingActivationError> {
    let mut statement = connection.prepare("PRAGMA table_info(agent_binding_activations)")?;
    let mut rows = statement.query([])?;
    let mut actual = Vec::new();
    while let Some(row) = rows.next()? {
        if actual.len() >= MAX_SCHEMA_METADATA_ROWS {
            return Err(AgentBindingActivationError::SchemaMetadataTooLarge {
                object: ACTIVATIONS_TABLE,
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
        ("membership_digest", "BLOB", 1, 0),
        ("display_name", "TEXT", 1, 0),
        ("declared_role", "TEXT", 1, 0),
        ("transport_kind", "INTEGER", 1, 0),
        ("activated_at_ms", "INTEGER", 1, 0),
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
        return Err(AgentBindingActivationError::DamagedSchema(
            ACTIVATIONS_TABLE,
        ));
    }
    Ok(())
}

fn validate_foreign_keys(connection: &Connection) -> Result<(), AgentBindingActivationError> {
    let mut statement = connection.prepare("PRAGMA foreign_key_list(agent_binding_activations)")?;
    let mut rows = statement.query([])?;
    let mut actual = Vec::new();
    while let Some(row) = rows.next()? {
        if actual.len() >= MAX_SCHEMA_METADATA_ROWS {
            return Err(AgentBindingActivationError::SchemaMetadataTooLarge {
                object: ACTIVATIONS_TABLE,
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
    let expected = vec![(
        "agent_binding_reservations".to_owned(),
        "request_id".to_owned(),
        "request_id".to_owned(),
        "NO ACTION".to_owned(),
        "NO ACTION".to_owned(),
        "NONE".to_owned(),
    )];
    if actual != expected {
        return Err(AgentBindingActivationError::DamagedSchema(
            ACTIVATIONS_TABLE,
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
