//! Immutable terminal rejection receipts for invalid reserved Agent bindings.

use forge_domain::{
    AgentBindingRejectionReason, AgentBindingRejectionReceipt, AgentBindingRejectionRequest,
    AgentTransportKind, AuthenticatedPrincipal, TimestampMillis, WorkspaceId,
    WorkspaceRootFingerprint,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    AgentBindingActivationError, AgentBindingReservation, AgentOperationsDelegation,
    workspace_agent_binding_activation, workspace_agent_binding_reservations,
    workspace_agent_delegation,
};

const DIGEST_BYTES: usize = 32;
const TABLE: &str = "agent_binding_rejections";
pub(crate) const TABLE_SQL: &str = "CREATE TABLE agent_binding_rejections (request_id BLOB PRIMARY KEY NOT NULL REFERENCES agent_binding_reservations(request_id) CHECK(length(request_id) = 16 AND request_id != zeroblob(16)), request_digest BLOB NOT NULL CHECK(length(request_digest) = 32 AND request_digest != zeroblob(32)), workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16 AND workspace_id != zeroblob(16)), activity_id BLOB NOT NULL REFERENCES activities(activity_id) CHECK(length(activity_id) = 16 AND activity_id != zeroblob(16)), agent_id BLOB NOT NULL CHECK(length(agent_id) = 16 AND agent_id != zeroblob(16)), session_id BLOB NOT NULL CHECK(length(session_id) = 16 AND session_id != zeroblob(16)), principal_kind INTEGER NOT NULL CHECK(principal_kind IN (0,1,2)), principal_id BLOB NOT NULL CHECK(length(principal_id) = 16), migration_id BLOB NOT NULL CHECK(length(migration_id) = 16 AND migration_id != zeroblob(16)), destination_id BLOB NOT NULL CHECK(length(destination_id) = 16 AND destination_id != zeroblob(16)), freeze_revision INTEGER NOT NULL CHECK(freeze_revision >= 1), manifest_digest BLOB NOT NULL CHECK(length(manifest_digest) = 32 AND manifest_digest != zeroblob(32)), issuer_id BLOB NOT NULL CHECK(length(issuer_id) = 16 AND issuer_id != zeroblob(16)), workspace_root_fingerprint BLOB NOT NULL CHECK(length(workspace_root_fingerprint) = 16), binding_digest BLOB NOT NULL CHECK(length(binding_digest) = 32 AND binding_digest != zeroblob(32)), delegation_digest BLOB NOT NULL CHECK(length(delegation_digest) = 32 AND delegation_digest != zeroblob(32)), membership_digest BLOB NOT NULL CHECK(length(membership_digest) = 32 AND membership_digest != zeroblob(32)), display_name TEXT NOT NULL CHECK(length(CAST(display_name AS BLOB)) BETWEEN 1 AND 128), declared_role TEXT NOT NULL CHECK(length(CAST(declared_role AS BLOB)) BETWEEN 1 AND 128), transport_kind INTEGER NOT NULL CHECK(transport_kind IN (0,1,2,3)), reserved_at_ms INTEGER NOT NULL CHECK(reserved_at_ms >= 0), requested_at_ms INTEGER NOT NULL CHECK(requested_at_ms >= 0), reason INTEGER NOT NULL CHECK(reason = 0), observed_at_ms INTEGER NOT NULL CHECK(observed_at_ms >= 0), rejected_at_ms INTEGER NOT NULL CHECK(rejected_at_ms >= observed_at_ms), receipt_digest BLOB NOT NULL CHECK(length(receipt_digest) = 32 AND receipt_digest != zeroblob(32)), CHECK((principal_kind = 0 AND principal_id = zeroblob(16)) OR (principal_kind IN (1,2) AND principal_id != zeroblob(16))), UNIQUE(workspace_id, request_id)) STRICT";
const ACTIVATION_GUARD_TRIGGER: &str = "agent_binding_rejections_block_activation";
const ACTIVATION_GUARD_TRIGGER_SQL: &str = "CREATE TRIGGER agent_binding_rejections_block_activation BEFORE INSERT ON agent_binding_rejections WHEN EXISTS (SELECT 1 FROM agent_binding_activations WHERE request_id = NEW.request_id) BEGIN SELECT RAISE(ABORT, 'agent binding activation already exists'); END";
const REJECTION_GUARD_TRIGGER: &str = "agent_binding_activations_block_rejection";
const REJECTION_GUARD_TRIGGER_SQL: &str = "CREATE TRIGGER agent_binding_activations_block_rejection BEFORE INSERT ON agent_binding_activations WHEN EXISTS (SELECT 1 FROM agent_binding_rejections WHERE request_id = NEW.request_id) BEGIN SELECT RAISE(ABORT, 'agent binding rejection already exists'); END";

pub(crate) fn create_schema(
    connection: &Connection,
) -> Result<(), AgentBindingRejectionStoreError> {
    connection.execute_batch(TABLE_SQL)?;
    connection.execute_batch(ACTIVATION_GUARD_TRIGGER_SQL)?;
    connection.execute_batch(REJECTION_GUARD_TRIGGER_SQL)?;
    Ok(())
}

pub(crate) fn schema_objects() -> [(&'static str, &'static str); 3] {
    [
        ("table", TABLE),
        ("trigger", ACTIVATION_GUARD_TRIGGER),
        ("trigger", REJECTION_GUARD_TRIGGER),
    ]
}

pub(crate) fn validate_schema(
    connection: &Connection,
) -> Result<(), AgentBindingRejectionStoreError> {
    let actual: Option<String> = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type='table' AND name=?1",
            params![TABLE],
            |row| row.get(0),
        )
        .optional()?;
    if actual.as_deref().map(normalize_sql) != Some(normalize_sql(TABLE_SQL)) {
        return Err(AgentBindingRejectionStoreError::DamagedSchema(TABLE));
    }
    for (name, expected) in [
        (ACTIVATION_GUARD_TRIGGER, ACTIVATION_GUARD_TRIGGER_SQL),
        (REJECTION_GUARD_TRIGGER, REJECTION_GUARD_TRIGGER_SQL),
    ] {
        let trigger: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type='trigger' AND name=?1",
                params![name],
                |row| row.get(0),
            )
            .optional()?;
        if trigger.as_deref().map(normalize_sql) != Some(normalize_sql(expected)) {
            return Err(AgentBindingRejectionStoreError::DamagedSchema(name));
        }
    }
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM pragma_foreign_key_list(?1)",
        params![TABLE],
        |row| row.get(0),
    )?;
    if count != 3 {
        return Err(AgentBindingRejectionStoreError::DamagedSchema(
            "foreign keys",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentBindingRejectionOperation {
    Recorded(AgentBindingRejectionReceipt),
    Replay(AgentBindingRejectionReceipt),
}

#[derive(Debug, Error)]
pub enum AgentBindingRejectionStoreError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Domain(#[from] forge_domain::AgentBindingRejectionValidationError),
    #[error(transparent)]
    Reservation(#[from] crate::AgentBindingReservationError),
    #[error(transparent)]
    Delegation(#[from] crate::AgentOperationsDelegationError),
    #[error(transparent)]
    Activation(#[from] AgentBindingActivationError),
    #[error(transparent)]
    Agent(#[from] crate::workspace_agents::AgentStoreError),
    #[error("Agent binding rejection schema object is damaged: {0}")]
    DamagedSchema(&'static str),
    #[error("Agent binding rejection is not eligible: {0}")]
    Conflict(&'static str),
    #[error("Agent binding rejection receipt is corrupt: {0}")]
    Corrupt(&'static str),
    #[error("Agent binding rejection Source clock observation failed")]
    Clock,
    #[error("Agent binding rejection commit requires exact readback")]
    CommitUnconfirmed(#[source] rusqlite::Error),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentBindingRejectionStoreRequest {
    pub request: AgentBindingRejectionRequest,
    pub current_delegation: AgentOperationsDelegation,
    pub binding_digest: [u8; DIGEST_BYTES],
    pub observed_root_fingerprint: WorkspaceRootFingerprint,
}

pub(crate) fn reject(
    connection: &mut Connection,
    request: &AgentBindingRejectionStoreRequest,
) -> Result<AgentBindingRejectionOperation, AgentBindingRejectionStoreError> {
    reject_with_clock(connection, request, || {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| AgentBindingRejectionStoreError::Clock)?
            .as_millis();
        TimestampMillis::new(
            i64::try_from(millis).map_err(|_| AgentBindingRejectionStoreError::Clock)?,
        )
        .map_err(|_| AgentBindingRejectionStoreError::Clock)
    })
}

pub(crate) fn reject_with_clock<F>(
    connection: &mut Connection,
    request: &AgentBindingRejectionStoreRequest,
    clock: F,
) -> Result<AgentBindingRejectionOperation, AgentBindingRejectionStoreError>
where
    F: FnOnce() -> Result<TimestampMillis, AgentBindingRejectionStoreError>,
{
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    validate_schema(&transaction)?;
    if request.binding_digest == [0; DIGEST_BYTES]
        || request.binding_digest != request.request.binding_digest()
        || request.observed_root_fingerprint != request.request.workspace_root_fingerprint()
    {
        return Err(AgentBindingRejectionStoreError::Conflict("binding digest"));
    }
    if let Some(existing) = load(&transaction, request.request.request_id())? {
        if existing.request() != &request.request {
            return Err(AgentBindingRejectionStoreError::Conflict(
                "rejection request changed",
            ));
        }
        validate_receipt(&transaction, &existing)?;
        transaction.commit()?;
        return Ok(AgentBindingRejectionOperation::Replay(existing));
    }
    let reservation =
        workspace_agent_binding_reservations::get(&transaction, request.request.request_id())?
            .ok_or(AgentBindingRejectionStoreError::Conflict(
                "reservation missing",
            ))?;
    validate_reservation(&reservation, request)?;
    let current = workspace_agent_delegation::get(&transaction, request.request.workspace_id())?
        .ok_or(AgentBindingRejectionStoreError::Conflict(
            "delegation missing",
        ))?;
    if current != request.current_delegation {
        return Err(AgentBindingRejectionStoreError::Conflict(
            "delegation changed",
        ));
    }
    if workspace_agent_binding_activation::get(&transaction, request.request.request_id())?
        .is_some()
    {
        return Err(AgentBindingRejectionStoreError::Conflict(
            "activation already exists",
        ));
    }
    if crate::workspace_agents::get_in_transaction(&transaction, request.request.agent_id())?
        .is_some()
    {
        return Err(AgentBindingRejectionStoreError::Conflict(
            "Agent already exists",
        ));
    }
    if workspace_agent_binding_activation::validate_transport(
        request.request.principal(),
        request.request.transport(),
    )
    .is_ok()
    {
        return Err(AgentBindingRejectionStoreError::Conflict(
            "transport is valid",
        ));
    }
    let rejected_at = clock()?;
    if rejected_at.get() < request.request.observed_at().get() {
        return Err(AgentBindingRejectionStoreError::Conflict(
            "rejection clock before observation",
        ));
    }
    let request_digest = agent_binding_rejection_intent_digest(&request.request);
    let digest = rejection_digest(request, rejected_at);
    let freeze_revision = i64::try_from(request.request.expected_freeze_revision())
        .map_err(|_| AgentBindingRejectionStoreError::Corrupt("freeze revision"))?;
    transaction.execute(
        "INSERT INTO agent_binding_rejections (
            request_id, request_digest, workspace_id, activity_id, agent_id, session_id, principal_kind,
            principal_id, migration_id, destination_id, freeze_revision, manifest_digest,
            issuer_id, workspace_root_fingerprint, binding_digest, delegation_digest,
            membership_digest, display_name, declared_role, transport_kind, reserved_at_ms, requested_at_ms,
            reason, observed_at_ms, rejected_at_ms, receipt_digest
         ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,0,?23,?24,?25)",
        params![
            request.request.request_id().as_bytes(), request_digest.as_slice(), request.request.workspace_id().into_uuid().as_bytes(),
            request.request.activity_id().into_uuid().as_bytes(), request.request.agent_id().into_uuid().as_bytes(), request.request.session_id().into_uuid().as_bytes(), principal_kind(request.request.principal()),
            principal_id(request.request.principal()).as_slice(), request.request.migration_id().as_bytes(), request.request.destination_id().as_bytes(), freeze_revision,
            request.request.manifest_digest().as_slice(), request.request.issuer_id().as_bytes(),
            request.request.workspace_root_fingerprint().as_bytes(), request.request.binding_digest().as_slice(),
            request.request.delegation_digest().as_slice(), request.request.membership_digest().as_slice(),
            request.request.display_name().as_str(), request.request.declared_role().as_str(),
            i64::from(encode_transport(request.request.transport())), request.request.reserved_at().get(), request.request.requested_at().get(), request.request.observed_at().get(), rejected_at.get(), digest.as_slice(),
        ],
    )?;
    let receipt = load(&transaction, request.request.request_id())?
        .ok_or(AgentBindingRejectionStoreError::Corrupt("insert readback"))?;
    if receipt.receipt_digest() != digest {
        return Err(AgentBindingRejectionStoreError::Corrupt("receipt digest"));
    }
    transaction
        .commit()
        .map_err(AgentBindingRejectionStoreError::CommitUnconfirmed)?;
    Ok(AgentBindingRejectionOperation::Recorded(receipt))
}

pub(crate) fn get(
    connection: &Connection,
    request_id: Uuid,
) -> Result<Option<AgentBindingRejectionReceipt>, AgentBindingRejectionStoreError> {
    if request_id.is_nil() {
        return Err(AgentBindingRejectionStoreError::Conflict("request id"));
    }
    validate_schema(connection)?;
    let Some(receipt) = load(connection, request_id)? else {
        return Ok(None);
    };
    validate_receipt(connection, &receipt)?;
    Ok(Some(receipt))
}

pub(crate) fn is_valid_settlement(
    connection: &Connection,
    request_id: Uuid,
) -> Result<bool, AgentBindingRejectionStoreError> {
    let Some(receipt) = load(connection, request_id)? else {
        return Ok(false);
    };
    validate_receipt(connection, &receipt)?;
    Ok(true)
}

fn validate_receipt(
    connection: &Connection,
    receipt: &AgentBindingRejectionReceipt,
) -> Result<(), AgentBindingRejectionStoreError> {
    if receipt.receipt_digest() != rejection_digest_from_receipt(receipt) {
        return Err(AgentBindingRejectionStoreError::Corrupt("receipt digest"));
    }
    if receipt.request_digest() != agent_binding_rejection_intent_digest(receipt.request()) {
        return Err(AgentBindingRejectionStoreError::Corrupt("request digest"));
    }
    let Some(reservation) =
        workspace_agent_binding_reservations::get(connection, receipt.request_id())?
    else {
        return Err(AgentBindingRejectionStoreError::Corrupt(
            "reservation missing",
        ));
    };
    let request = receipt.request();
    if reservation.workspace_id() != request.workspace_id()
        || reservation.request().request_id() != request.request_id()
        || reservation.request().activity_id() != request.activity_id()
        || reservation.request().agent_id() != request.agent_id()
        || reservation.request().session_id() != request.session_id()
        || reservation.request().principal() != request.principal()
        || reservation.migration_id() != request.migration_id()
        || reservation.destination_id() != request.destination_id()
        || reservation.freeze_revision() != request.expected_freeze_revision()
        || reservation.request().requested_at() != request.requested_at()
        || reservation.reserved_at() != request.reserved_at()
    {
        return Err(AgentBindingRejectionStoreError::Corrupt(
            "reservation provenance",
        ));
    }
    if workspace_agent_binding_activation::get(connection, receipt.request_id())?.is_some() {
        return Err(AgentBindingRejectionStoreError::Corrupt(
            "activation exists",
        ));
    }
    if crate::workspace_agents::get_in_transaction(connection, request.agent_id())?.is_some() {
        return Err(AgentBindingRejectionStoreError::Corrupt("Agent exists"));
    }
    Ok(())
}

fn validate_reservation(
    reservation: &AgentBindingReservation,
    request: &AgentBindingRejectionStoreRequest,
) -> Result<(), AgentBindingRejectionStoreError> {
    let source = &request.request;
    let original = reservation.request();
    if reservation.workspace_id() != source.workspace_id()
        || original.request_id() != source.request_id()
        || original.activity_id() != source.activity_id()
        || original.agent_id() != source.agent_id()
        || original.session_id() != source.session_id()
        || original.principal() != source.principal()
        || reservation.migration_id() != source.migration_id()
        || reservation.destination_id() != source.destination_id()
        || reservation.freeze_revision() != source.expected_freeze_revision()
    {
        return Err(AgentBindingRejectionStoreError::Conflict(
            "reservation fence",
        ));
    }
    if original.requested_at() != source.requested_at()
        || reservation.reserved_at() != source.reserved_at()
    {
        return Err(AgentBindingRejectionStoreError::Conflict(
            "reservation timestamps",
        ));
    }
    if request.current_delegation.migration_id() != source.migration_id()
        || request.current_delegation.destination_id() != source.destination_id()
        || request.current_delegation.manifest_digest() != source.manifest_digest()
    {
        return Err(AgentBindingRejectionStoreError::Conflict(
            "delegation fence",
        ));
    }
    Ok(())
}

/// Canonical digest of the caller-owned rejection intent. Source-derived
/// root, binding, delegation, and reservation timestamps are excluded.
pub fn agent_binding_rejection_intent_digest(
    request: &AgentBindingRejectionRequest,
) -> [u8; DIGEST_BYTES] {
    caller_intent_digest_fields(
        request.request_id(),
        request.workspace_id(),
        request.activity_id(),
        request.agent_id(),
        request.session_id(),
        request.principal(),
        request.migration_id(),
        request.destination_id(),
        request.expected_freeze_revision(),
        request.manifest_digest(),
        request.issuer_id(),
        request.membership_digest(),
        request.display_name(),
        request.declared_role(),
        request.transport(),
        request.reason(),
        request.requested_at(),
        request.observed_at(),
    )
}

#[allow(clippy::too_many_arguments)]
fn caller_intent_digest_fields(
    request_id: Uuid,
    workspace_id: WorkspaceId,
    activity_id: forge_domain::ActivityId,
    agent_id: forge_domain::AgentInstanceId,
    session_id: forge_domain::AgentSessionId,
    principal: AuthenticatedPrincipal,
    migration_id: Uuid,
    destination_id: Uuid,
    expected_freeze_revision: u64,
    manifest_digest: [u8; 32],
    issuer_id: Uuid,
    membership_digest: [u8; 32],
    display_name: &forge_domain::AgentDisplayName,
    declared_role: &forge_domain::AgentDeclaredRole,
    transport: AgentTransportKind,
    reason: AgentBindingRejectionReason,
    requested_at: TimestampMillis,
    observed_at: TimestampMillis,
) -> [u8; DIGEST_BYTES] {
    let mut h = Sha256::new();
    h.update(b"forge.agent.binding.rejection.intent.v1\0");
    hash_uuid(&mut h, request_id);
    hash_uuid(&mut h, workspace_id.into_uuid());
    hash_uuid(&mut h, activity_id.into_uuid());
    hash_uuid(&mut h, agent_id.into_uuid());
    hash_uuid(&mut h, session_id.into_uuid());
    hash_principal(&mut h, principal);
    hash_uuid(&mut h, migration_id);
    hash_uuid(&mut h, destination_id);
    hash_u64(&mut h, expected_freeze_revision);
    h.update(manifest_digest);
    hash_uuid(&mut h, issuer_id);
    h.update(membership_digest);
    hash_text(&mut h, display_name.as_str());
    hash_text(&mut h, declared_role.as_str());
    hash_u8(&mut h, encode_transport(transport));
    hash_u8(
        &mut h,
        match reason {
            AgentBindingRejectionReason::PrincipalTransportMismatch => 0,
        },
    );
    hash_i64(&mut h, requested_at.get());
    hash_i64(&mut h, observed_at.get());
    h.finalize().into()
}

/// Compute the same caller-intent digest before Source-derived fences exist.
#[allow(clippy::too_many_arguments)]
pub fn agent_binding_rejection_intent_digest_for_attestation(
    workspace_id: WorkspaceId,
    issuer_id: Uuid,
    migration_id: Uuid,
    destination_id: Uuid,
    expected_freeze_revision: u64,
    manifest_digest: [u8; 32],
    reservation: &crate::AgentBindingReservationRequest,
    activation: &crate::AgentBindingActivationRequest,
    reason: AgentBindingRejectionReason,
    observed_at: TimestampMillis,
) -> [u8; DIGEST_BYTES] {
    caller_intent_digest_fields(
        reservation.request_id(),
        workspace_id,
        reservation.activity_id(),
        reservation.agent_id(),
        reservation.session_id(),
        reservation.principal(),
        migration_id,
        destination_id,
        expected_freeze_revision,
        manifest_digest,
        issuer_id,
        activation.membership_digest(),
        activation.display_name(),
        activation.declared_role(),
        activation.transport(),
        reason,
        reservation.requested_at(),
        observed_at,
    )
}

/// Canonical Source delegation fence digest sealed in the rejection receipt.
pub fn agent_binding_rejection_delegation_digest(
    delegation: &AgentOperationsDelegation,
) -> [u8; DIGEST_BYTES] {
    let freeze = delegation.freeze();
    let mut h = Sha256::new();
    h.update(b"forge.agent.binding.rejection.delegation.v1\0");
    hash_uuid(&mut h, delegation.migration_id());
    hash_uuid(&mut h, delegation.workspace_id().into_uuid());
    hash_uuid(&mut h, delegation.destination_id());
    hash_u64(&mut h, freeze.revision());
    hash_u8(
        &mut h,
        match freeze.state() {
            crate::AgentOperationsFreezeState::Frozen => 0,
            crate::AgentOperationsFreezeState::Released => 1,
        },
    );
    hash_i64(&mut h, freeze.created_at().get());
    hash_i64(&mut h, freeze.updated_at().get());
    h.update(delegation.manifest_digest());
    hash_i64(&mut h, delegation.delegated_at().get());
    h.finalize().into()
}

fn load(
    connection: &Connection,
    request_id: Uuid,
) -> Result<Option<AgentBindingRejectionReceipt>, AgentBindingRejectionStoreError> {
    let mut statement = connection.prepare("SELECT request_id,request_digest,workspace_id,activity_id,agent_id,session_id,principal_kind,principal_id,migration_id,destination_id,freeze_revision,manifest_digest,issuer_id,workspace_root_fingerprint,binding_digest,delegation_digest,membership_digest,display_name,declared_role,transport_kind,reserved_at_ms,requested_at_ms,reason,observed_at_ms,rejected_at_ms,receipt_digest FROM agent_binding_rejections WHERE request_id=?1")?;
    let mut rows = statement.query(params![request_id.as_bytes()])?;
    let Some(row) = rows.next()? else {
        return Ok(None);
    };
    let request_id = decode_uuid(row.get(0)?)?;
    let request_digest = decode_digest(row.get(1)?)?;
    let workspace_id = WorkspaceId::from_uuid(decode_uuid(row.get(2)?)?);
    let activity_id = forge_domain::ActivityId::from_uuid(decode_uuid(row.get(3)?)?);
    let agent_id = forge_domain::AgentInstanceId::from_uuid(decode_uuid(row.get(4)?)?);
    let session_id = forge_domain::AgentSessionId::from_uuid(decode_uuid(row.get(5)?)?);
    let principal = decode_principal(row.get(6)?, row.get(7)?)?;
    let migration_id = decode_uuid(row.get(8)?)?;
    let destination_id = decode_uuid(row.get(9)?)?;
    let revision: u64 = u64::try_from(row.get::<_, i64>(10)?)
        .map_err(|_| AgentBindingRejectionStoreError::Corrupt("freeze revision"))?;
    let manifest_digest = decode_digest(row.get(11)?)?;
    let issuer_id = decode_uuid(row.get(12)?)?;
    let root = forge_domain::WorkspaceRootFingerprint::from_bytes(
        row.get::<_, Vec<u8>>(13)?
            .try_into()
            .map_err(|_| AgentBindingRejectionStoreError::Corrupt("root fingerprint"))?,
    );
    let binding_digest = decode_digest(row.get(14)?)?;
    let delegation_digest = decode_digest(row.get(15)?)?;
    let membership_digest = decode_digest(row.get(16)?)?;
    let display = forge_domain::AgentDisplayName::new(row.get(17)?)
        .map_err(|_| AgentBindingRejectionStoreError::Corrupt("display"))?;
    let role = forge_domain::AgentDeclaredRole::new(row.get(18)?)
        .map_err(|_| AgentBindingRejectionStoreError::Corrupt("role"))?;
    let transport = decode_transport(row.get(19)?)?;
    let reserved = TimestampMillis::new(row.get(20)?)
        .map_err(|_| AgentBindingRejectionStoreError::Corrupt("reserved"))?;
    let requested = TimestampMillis::new(row.get(21)?)
        .map_err(|_| AgentBindingRejectionStoreError::Corrupt("requested"))?;
    if row.get::<_, i64>(22)? != 0 {
        return Err(AgentBindingRejectionStoreError::Corrupt("reason"));
    }
    let observed = TimestampMillis::new(row.get(23)?)
        .map_err(|_| AgentBindingRejectionStoreError::Corrupt("observed"))?;
    let rejected = TimestampMillis::new(row.get(24)?)
        .map_err(|_| AgentBindingRejectionStoreError::Corrupt("rejected"))?;
    let receipt_digest = decode_digest(row.get(25)?)?;
    let request = AgentBindingRejectionRequest::new(
        request_id,
        workspace_id,
        activity_id,
        agent_id,
        session_id,
        principal,
        migration_id,
        destination_id,
        revision,
        manifest_digest,
        issuer_id,
        root,
        binding_digest,
        delegation_digest,
        membership_digest,
        display,
        role,
        transport,
        AgentBindingRejectionReason::PrincipalTransportMismatch,
        reserved,
        requested,
        observed,
    )?;
    Ok(Some(AgentBindingRejectionReceipt::from_parts(
        request,
        request_digest,
        rejected,
        receipt_digest,
    )))
}

fn rejection_digest(
    request: &AgentBindingRejectionStoreRequest,
    rejected_at: TimestampMillis,
) -> [u8; DIGEST_BYTES] {
    let mut h = Sha256::new();
    h.update(b"forge.agent.binding.rejection.receipt.v1\0");
    h.update(agent_binding_rejection_intent_digest(&request.request));
    hash_uuid(&mut h, request.request.request_id());
    hash_uuid(&mut h, request.request.workspace_id().into_uuid());
    hash_uuid(&mut h, request.request.activity_id().into_uuid());
    hash_uuid(&mut h, request.request.agent_id().into_uuid());
    hash_uuid(&mut h, request.request.session_id().into_uuid());
    hash_principal(&mut h, request.request.principal());
    hash_uuid(&mut h, request.request.migration_id());
    hash_uuid(&mut h, request.request.destination_id());
    hash_u64(&mut h, request.request.expected_freeze_revision());
    h.update(request.request.manifest_digest());
    hash_uuid(&mut h, request.request.issuer_id());
    h.update(request.request.workspace_root_fingerprint().as_bytes());
    h.update(request.request.binding_digest());
    h.update(request.request.delegation_digest());
    h.update(request.request.membership_digest());
    hash_text(&mut h, request.request.display_name().as_str());
    hash_text(&mut h, request.request.declared_role().as_str());
    hash_u8(&mut h, encode_transport(request.request.transport()));
    hash_i64(&mut h, request.request.reserved_at().get());
    hash_i64(&mut h, request.request.requested_at().get());
    hash_i64(&mut h, request.request.observed_at().get());
    hash_i64(&mut h, rejected_at.get());
    h.finalize().into()
}
fn rejection_digest_from_receipt(receipt: &AgentBindingRejectionReceipt) -> [u8; DIGEST_BYTES] {
    let dummy = receipt.request();
    let mut h = Sha256::new();
    h.update(b"forge.agent.binding.rejection.receipt.v1\0");
    h.update(receipt.request_digest());
    hash_uuid(&mut h, dummy.request_id());
    hash_uuid(&mut h, dummy.workspace_id().into_uuid());
    hash_uuid(&mut h, dummy.activity_id().into_uuid());
    hash_uuid(&mut h, dummy.agent_id().into_uuid());
    hash_uuid(&mut h, dummy.session_id().into_uuid());
    hash_principal(&mut h, dummy.principal());
    hash_uuid(&mut h, dummy.migration_id());
    hash_uuid(&mut h, dummy.destination_id());
    hash_u64(&mut h, dummy.expected_freeze_revision());
    h.update(dummy.manifest_digest());
    hash_uuid(&mut h, dummy.issuer_id());
    h.update(dummy.workspace_root_fingerprint().as_bytes());
    h.update(dummy.binding_digest());
    h.update(dummy.delegation_digest());
    h.update(dummy.membership_digest());
    hash_text(&mut h, dummy.display_name().as_str());
    hash_text(&mut h, dummy.declared_role().as_str());
    hash_u8(&mut h, encode_transport(dummy.transport()));
    hash_i64(&mut h, dummy.reserved_at().get());
    hash_i64(&mut h, dummy.requested_at().get());
    hash_i64(&mut h, dummy.observed_at().get());
    hash_i64(&mut h, receipt.rejected_at().get());
    h.finalize().into()
}
fn hash_uuid(h: &mut Sha256, v: Uuid) {
    h.update(v.as_bytes());
}
fn hash_u64(h: &mut Sha256, v: u64) {
    h.update(v.to_le_bytes());
}
fn hash_i64(h: &mut Sha256, v: i64) {
    h.update(v.to_le_bytes());
}
fn hash_u8(h: &mut Sha256, v: u8) {
    h.update([v]);
}
fn hash_text(h: &mut Sha256, v: &str) {
    h.update((v.len() as u64).to_le_bytes());
    h.update(v.as_bytes());
}
fn hash_principal(h: &mut Sha256, p: AuthenticatedPrincipal) {
    match p {
        AuthenticatedPrincipal::TrustedStdio => hash_u8(h, 0),
        AuthenticatedPrincipal::DirectToken(id) => {
            hash_u8(h, 1);
            hash_uuid(h, id.into_uuid());
        }
        AuthenticatedPrincipal::OAuthGrant(id) => {
            hash_u8(h, 2);
            hash_uuid(h, id.into_uuid());
        }
    }
}
fn principal_kind(p: AuthenticatedPrincipal) -> i64 {
    match p {
        AuthenticatedPrincipal::TrustedStdio => 0,
        AuthenticatedPrincipal::DirectToken(_) => 1,
        AuthenticatedPrincipal::OAuthGrant(_) => 2,
    }
}
fn principal_id(p: AuthenticatedPrincipal) -> [u8; 16] {
    match p {
        AuthenticatedPrincipal::TrustedStdio => [0; 16],
        AuthenticatedPrincipal::DirectToken(id) => id.into_uuid().into_bytes(),
        AuthenticatedPrincipal::OAuthGrant(id) => id.into_uuid().into_bytes(),
    }
}
fn encode_transport(v: AgentTransportKind) -> u8 {
    match v {
        AgentTransportKind::Retired => 0,
        AgentTransportKind::Stdio => 1,
        AgentTransportKind::StreamableHttp => 2,
        AgentTransportKind::Other => 3,
    }
}
fn decode_transport(v: i64) -> Result<AgentTransportKind, AgentBindingRejectionStoreError> {
    match v {
        0 => Ok(AgentTransportKind::Retired),
        1 => Ok(AgentTransportKind::Stdio),
        2 => Ok(AgentTransportKind::StreamableHttp),
        3 => Ok(AgentTransportKind::Other),
        _ => Err(AgentBindingRejectionStoreError::Corrupt("transport")),
    }
}
#[allow(clippy::needless_pass_by_value)]
fn decode_principal(
    kind: i64,
    id: Vec<u8>,
) -> Result<AuthenticatedPrincipal, AgentBindingRejectionStoreError> {
    let uuid =
        Uuid::from_slice(&id).map_err(|_| AgentBindingRejectionStoreError::Corrupt("principal"))?;
    match kind {
        0 => Ok(AuthenticatedPrincipal::TrustedStdio),
        1 => Ok(AuthenticatedPrincipal::DirectToken(
            forge_domain::DirectTokenId::from_uuid(uuid),
        )),
        2 => Ok(AuthenticatedPrincipal::OAuthGrant(
            forge_domain::OAuthGrantId::from_uuid(uuid),
        )),
        _ => Err(AgentBindingRejectionStoreError::Corrupt("principal kind")),
    }
}
#[allow(clippy::needless_pass_by_value)]
fn decode_uuid(value: Vec<u8>) -> Result<Uuid, AgentBindingRejectionStoreError> {
    Uuid::from_slice(&value).map_err(|_| AgentBindingRejectionStoreError::Corrupt("uuid"))
}
fn decode_digest(value: Vec<u8>) -> Result<[u8; 32], AgentBindingRejectionStoreError> {
    let out: [u8; 32] = value
        .try_into()
        .map_err(|_| AgentBindingRejectionStoreError::Corrupt("digest"))?;
    if out == [0; 32] {
        return Err(AgentBindingRejectionStoreError::Corrupt("zero digest"));
    }
    Ok(out)
}
fn normalize_sql(value: &str) -> String {
    value
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .map(|b| b.to_ascii_lowercase() as char)
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::format_collect)]
    use super::*;
    use forge_domain::{
        ActivityId, AgentDeclaredRole, AgentDisplayName, AgentInstanceId, AgentSessionId,
        AuthenticatedPrincipal, TimestampMillis, WorkspaceId, WorkspaceRootFingerprint,
    };

    fn hex(value: [u8; 32]) -> String {
        value.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn caller_intent_digest_vector_is_stable_and_excludes_source_fences() {
        let request = AgentBindingRejectionRequest::new(
            Uuid::from_u128(1),
            WorkspaceId::from_uuid(Uuid::from_u128(2)),
            ActivityId::from_uuid(Uuid::from_u128(3)),
            AgentInstanceId::from_uuid(Uuid::from_u128(4)),
            AgentSessionId::from_uuid(Uuid::from_u128(5)),
            AuthenticatedPrincipal::TrustedStdio,
            Uuid::from_u128(6),
            Uuid::from_u128(7),
            8,
            [0x11; 32],
            Uuid::from_u128(9),
            WorkspaceRootFingerprint::from_bytes([0x22; 16]),
            [0x33; 32],
            [0x44; 32],
            [0x55; 32],
            AgentDisplayName::new("worker".to_owned()).expect("valid display"),
            AgentDeclaredRole::new("operator".to_owned()).expect("valid role"),
            AgentTransportKind::Other,
            AgentBindingRejectionReason::PrincipalTransportMismatch,
            TimestampMillis::new(30).expect("valid timestamp"),
            TimestampMillis::new(20).expect("valid timestamp"),
            TimestampMillis::new(40).expect("valid timestamp"),
        )
        .expect("valid rejection request");
        assert_eq!(
            hex(agent_binding_rejection_intent_digest(&request)),
            "1832e23b3d2acab13bda3fc25cfce47e3799fb99704626cc355560523e90e788"
        );
        let changed_source_fences = AgentBindingRejectionRequest::new(
            request.request_id(),
            request.workspace_id(),
            request.activity_id(),
            request.agent_id(),
            request.session_id(),
            request.principal(),
            request.migration_id(),
            request.destination_id(),
            request.expected_freeze_revision(),
            request.manifest_digest(),
            request.issuer_id(),
            WorkspaceRootFingerprint::from_bytes([0x99; 16]),
            [0x88; 32],
            [0x77; 32],
            request.membership_digest(),
            request.display_name().clone(),
            request.declared_role().clone(),
            request.transport(),
            request.reason(),
            TimestampMillis::new(999).expect("valid timestamp"),
            request.requested_at(),
            request.observed_at(),
        )
        .expect("valid changed source fences");
        assert_eq!(
            agent_binding_rejection_intent_digest(&request),
            agent_binding_rejection_intent_digest(&changed_source_fences)
        );
    }
}
