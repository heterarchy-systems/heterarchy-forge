//! Single-Workspace owner for immutable unused-reservation retirements.

use forge_domain::{
    ActivityId, AgentInstanceId, AgentSessionId, AuthenticatedPrincipal, ForgeBackendId,
    HomeTransferReservationRetirementGrant, HomeTransferReservationRetirementRequest,
    HomeTransferSourceRequestDigest, HomeTransferSourceScope, OrchestrationIssuerId,
    TimestampMillis, WorkspaceId, WorkspaceRevision,
};
use rusqlite::{Connection, OptionalExtension, Row, TransactionBehavior, params};
use uuid::Uuid;

use super::{
    model::{
        HomeTransferReservationRetirementOutcome, HomeTransferReservationRetirementRecord,
        HomeTransferReservationRetirementRecordParts, record_from_reservation, reservation_digest,
    },
    schema,
};
use crate::{
    AgentBindingReservation, HomeTransferSourceRecord, HomeTransferSourceState,
    HomeTransferStoreError, workspace_agent_binding_activation, workspace_agent_binding_rejections,
    workspace_agent_binding_reservations, workspace_agents,
};

const ID_BYTES: usize = 16;
const DIGEST_BYTES: usize = 32;
const FIRST_RESERVATION_SCHEMA_VERSION: i64 = 36;
const FIRST_ACTIVATION_SCHEMA_VERSION: i64 = 37;
const FIRST_REJECTION_SCHEMA_VERSION: i64 = 65;
const FIRST_HOME_SOURCE_SCHEMA_VERSION: i64 = 71;
const FIRST_RESERVATION_RETIREMENT_SCHEMA_VERSION: i64 = 72;
const SELECT_COLUMNS: &str = "substr(preparation_id, 1, 17), substr(reservation_request_id, 1, 17), substr(workspace_id, 1, 17), workspace_revision, substr(backend_id, 1, 17), substr(destination_id, 1, 17), substr(source_request_digest, 1, 33), substr(source_outcome_digest, 1, 33), substr(source_inventory_digest, 1, 33), substr(request_digest, 1, 33), substr(issuer_id, 1, 17), observed_at_ms, grant_issued_at_ms, grant_expires_at_ms, substr(activity_id, 1, 17), substr(agent_id, 1, 17), substr(session_id, 1, 17), substr(reservation_migration_id, 1, 17), substr(reservation_destination_id, 1, 17), reservation_freeze_revision, reservation_principal_kind, substr(reservation_principal_id, 1, 17), reservation_requested_at_ms, reservation_reserved_at_ms, substr(reservation_digest, 1, 33), substr(receipt_digest, 1, 33)";

/// Retire one exact Pending reservation under one Workspace IMMEDIATE lock.
///
/// The host authenticates the configured issuer before calling this owner.
/// Neither the checked request nor its distinct grant is authentication.
#[allow(
    clippy::too_many_arguments,
    reason = "the Source owner checks all authenticated service pins and time input"
)]
pub(crate) fn retire<C>(
    connection: &mut Connection,
    request: &HomeTransferReservationRetirementRequest,
    grant: HomeTransferReservationRetirementGrant,
    issuer: OrchestrationIssuerId,
    backend: ForgeBackendId,
    destination: Uuid,
    sample_clock: C,
) -> Result<HomeTransferReservationRetirementOutcome, HomeTransferStoreError>
where
    C: FnOnce() -> Result<TimestampMillis, HomeTransferStoreError>,
{
    validate_service_pins(request, grant, issuer, backend, destination)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if !validate_reader_schema(&transaction)? {
        return Err(HomeTransferStoreError::Corrupt(
            "reservation retirement requires schema v72",
        ));
    }

    if let Some(existing) = exact_replay_or_conflict(&transaction, request, issuer)? {
        transaction.commit()?;
        return Ok(HomeTransferReservationRetirementOutcome::Existing(existing));
    }

    let (parent, inventory) = read_parent(&transaction, request)?;
    if parent.issuer() != issuer {
        return Err(HomeTransferStoreError::Conflict(
            "reservation retirement parent issuer",
        ));
    }
    let delegation =
        super::super::repository::validate_current_scope(&transaction, request.scope())?;
    let reservation = validate_current_reservation(&transaction, request, &parent, &inventory)?;
    ensure_no_terminal_or_materialized_state(&transaction, &reservation)?;
    ensure_no_agent_history_or_effects(&transaction, &reservation)?;
    let workspace_updated_at_ms: i64 = transaction.query_row(
        "SELECT updated_at_ms FROM workspace WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;

    // The source clock is sampled only after lock acquisition and all current
    // owner checks; queue time cannot extend the supplied grant.
    let observed_at = sample_clock()?;
    let high_water = source_time_high_water(
        &parent,
        &inventory,
        &reservation,
        &delegation,
        workspace_updated_at_ms,
    );
    validate_observation_time(request, grant, issuer, observed_at, high_water)?;

    let source_inventory_digest =
        *parent
            .inventory_digest()
            .ok_or(HomeTransferStoreError::Corrupt(
                "Prepared inventory digest missing",
            ))?;
    let record = record_from_reservation(
        request,
        issuer,
        observed_at,
        grant.issued_at(),
        grant.expires_at(),
        source_inventory_digest,
        &reservation,
    )?;
    persist_and_confirm(
        transaction,
        &record,
        &reservation,
        request.preparation_id(),
        request.reservation_request_id(),
    )?;
    Ok(HomeTransferReservationRetirementOutcome::Created(record))
}

fn exact_replay_or_conflict(
    connection: &Connection,
    request: &HomeTransferReservationRetirementRequest,
    issuer: OrchestrationIssuerId,
) -> Result<Option<HomeTransferReservationRetirementRecord>, HomeTransferStoreError> {
    if let Some((existing, _)) = load_by_key(
        connection,
        request.preparation_id(),
        request.reservation_request_id(),
    )? {
        if existing.request() != request || existing.issuer() != issuer {
            return Err(HomeTransferStoreError::Conflict(
                "reservation retirement business key",
            ));
        }
        validate_parent_link(connection, &existing)?;
        return Ok(Some(existing));
    }
    if load_by_reservation(connection, request.reservation_request_id())?.is_some() {
        return Err(HomeTransferStoreError::Conflict(
            "reservation already retired under another preparation",
        ));
    }
    Ok(None)
}

/// Read exact business-key history in one owner-managed read transaction.
/// Exact history validates its immutable Prepared parent but does not require
/// target Session liveness or current delegation.
pub(crate) fn get(
    connection: &Connection,
    preparation_id: Uuid,
    reservation_request_id: Uuid,
) -> Result<Option<HomeTransferReservationRetirementRecord>, HomeTransferStoreError> {
    if preparation_id.is_nil() || reservation_request_id.is_nil() {
        return Err(HomeTransferStoreError::Conflict(
            "reservation retirement identity",
        ));
    }
    let transaction = connection.unchecked_transaction()?;
    if !validate_reader_schema(&transaction)? {
        transaction.commit()?;
        return Ok(None);
    }
    let record = load_by_key(&transaction, preparation_id, reservation_request_id)?
        .map(|(record, _)| record);
    if let Some(record) = &record {
        validate_parent_link(&transaction, record)?;
    }
    transaction.commit()?;
    Ok(record)
}

/// Read one retirement by its globally unique reservation identity inside the
/// caller's existing source snapshot. It deliberately does not decode a parent
/// Prepared inventory so bounded batch readers do not repeat that work.
pub(crate) fn get_for_reservation(
    connection: &Connection,
    reservation_request_id: Uuid,
) -> Result<Option<HomeTransferReservationRetirementRecord>, HomeTransferStoreError> {
    if reservation_request_id.is_nil() {
        return Err(HomeTransferStoreError::Conflict(
            "reservation retirement request identity",
        ));
    }
    if !validate_reader_schema(connection)? {
        return Ok(None);
    }
    let Some((record, _)) = load_by_reservation(connection, reservation_request_id)? else {
        return Ok(None);
    };
    validate_parent_link(connection, &record)?;
    Ok(Some(record))
}

/// Return whether a current canonical reservation exactly matches its
/// immutable retirement. The caller supplies the row read from its own source
/// snapshot; this function never opens another transaction or decodes parent
/// Prepared capsules.
pub(crate) fn is_valid_settlement(
    connection: &Connection,
    reservation: &AgentBindingReservation,
) -> Result<bool, HomeTransferStoreError> {
    let reservation_request_id = reservation.request().request_id();
    if reservation_request_id.is_nil() {
        return Err(HomeTransferStoreError::Conflict(
            "reservation retirement request identity",
        ));
    }
    if !validate_reader_schema(connection)? {
        return Ok(false);
    }
    let Some(raw) = load_raw_by_reservation(connection, reservation_request_id)? else {
        return Ok(false);
    };
    let (record, raw) = decode_record(raw)?;
    if !record_matches_reservation(&record, reservation)
        || !raw_matches_reservation(&raw, reservation)
        || reservation_digest(reservation) != *record.reservation_digest()
    {
        return Err(HomeTransferStoreError::Conflict(
            "retirement reservation provenance",
        ));
    }
    validate_selected_reservation_state(connection, &record, reservation)?;
    validate_parent_link(connection, &record)?;
    Ok(true)
}

/// Keep a retired Agent and the exact old Activity/Session tuple closed to new
/// materialization. Other Agents and Sessions in that Activity remain eligible.
pub(crate) fn ensure_binding_identity_open(
    connection: &Connection,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    agent_id: AgentInstanceId,
    optional_session_id: Option<AgentSessionId>,
) -> Result<(), HomeTransferStoreError> {
    if !validate_reader_schema(connection)? {
        return Ok(());
    }
    let preparation_id: Option<Vec<u8>> = connection
        .query_row(
            "SELECT substr(preparation_id, 1, 17)
             FROM home_transfer_reservation_retirements
             WHERE workspace_id = ?1
               AND (agent_id = ?2 OR (?3 IS NOT NULL AND activity_id = ?4 AND session_id = ?3))
             ORDER BY preparation_id
             LIMIT 1",
            params![
                workspace_id.into_uuid().as_bytes(),
                agent_id.into_uuid().as_bytes(),
                optional_session_id.map(|id| id.into_uuid().as_bytes().to_vec()),
                activity_id.into_uuid().as_bytes(),
            ],
            |row| row.get(0),
        )
        .optional()?;
    if preparation_id.is_some() {
        return Err(HomeTransferStoreError::Conflict("retired binding identity"));
    }
    Ok(())
}

fn validate_service_pins(
    request: &HomeTransferReservationRetirementRequest,
    grant: HomeTransferReservationRetirementGrant,
    issuer: OrchestrationIssuerId,
    backend: ForgeBackendId,
    destination: Uuid,
) -> Result<(), HomeTransferStoreError> {
    if request.scope().backend_id() != backend || request.scope().destination_id() != destination {
        return Err(HomeTransferStoreError::Conflict(
            "configured retirement service scope",
        ));
    }
    grant
        .validate_for(issuer, request.request_digest(), grant.issued_at())
        .map_err(HomeTransferStoreError::RetirementDomain)
}

/// Validate the exact owner shapes for a current or supported legacy reader.
/// A missing retirement schema is an absence only for a validated pre-v72
/// Workspace; v72 and current Workspaces must have its exact owner schema.
fn validate_reader_schema(connection: &Connection) -> Result<bool, HomeTransferStoreError> {
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let current = crate::CURRENT_WORKSPACE_SCHEMA_VERSION;
    if version == current {
        // The open Workspace validates its complete current shape. This owner
        // independently validates every journal/guard object it introduces so
        // a damaged v72 retirement table can never look like an empty result.
        schema::validate_schema(connection)?;
        return Ok(true);
    }
    if !(30..current).contains(&version) {
        return Err(HomeTransferStoreError::Corrupt(
            "unsupported reservation retirement reader schema version",
        ));
    }

    if version >= FIRST_RESERVATION_SCHEMA_VERSION {
        workspace_agent_binding_reservations::validate_schema(connection)
            .map_err(|error| HomeTransferStoreError::RetirementReservation(Box::new(error)))?;
    } else {
        ensure_schema_objects_absent(
            connection,
            workspace_agent_binding_reservations::schema_objects(),
            "reservation schema appears before its version",
        )?;
    }
    if version >= FIRST_ACTIVATION_SCHEMA_VERSION {
        workspace_agent_binding_activation::validate_schema(connection)
            .map_err(|error| HomeTransferStoreError::RetirementActivation(Box::new(error)))?;
    } else {
        ensure_schema_objects_absent(
            connection,
            workspace_agent_binding_activation::schema_objects(),
            "activation schema appears before its version",
        )?;
    }
    if version >= FIRST_REJECTION_SCHEMA_VERSION {
        workspace_agent_binding_rejections::validate_schema(connection)
            .map_err(|error| HomeTransferStoreError::RetirementRejection(Box::new(error)))?;
    } else {
        ensure_schema_objects_absent(
            connection,
            workspace_agent_binding_rejections::schema_objects(),
            "rejection schema appears before its version",
        )?;
    }
    if version >= FIRST_HOME_SOURCE_SCHEMA_VERSION {
        super::super::schema::validate_schema(connection)?;
    } else {
        ensure_schema_objects_absent(
            connection,
            super::super::schema::schema_objects(),
            "Home source schema appears before its version",
        )?;
    }
    if version >= FIRST_RESERVATION_RETIREMENT_SCHEMA_VERSION {
        schema::validate_schema(connection)?;
        return Ok(true);
    }
    ensure_schema_objects_absent(
        connection,
        schema::schema_objects(),
        "retirement schema appears before schema v72",
    )?;
    Ok(false)
}

fn ensure_schema_objects_absent<I>(
    connection: &Connection,
    objects: I,
    detail: &'static str,
) -> Result<(), HomeTransferStoreError>
where
    I: IntoIterator<Item = (&'static str, &'static str)>,
{
    for (kind, name) in objects {
        let exists: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = ?1 AND name = ?2)",
            params![kind, name],
            |row| row.get(0),
        )?;
        if exists {
            return Err(HomeTransferStoreError::Corrupt(detail));
        }
    }
    Ok(())
}

fn read_parent(
    connection: &Connection,
    request: &HomeTransferReservationRetirementRequest,
) -> Result<
    (
        HomeTransferSourceRecord,
        super::super::inventory::HomeTransferSourceInventory,
    ),
    HomeTransferStoreError,
> {
    let Some((parent, inventory)) =
        super::super::repository::read_record_with_inventory(connection, request.preparation_id())?
    else {
        return Err(HomeTransferStoreError::Conflict(
            "reservation retirement Prepared parent missing",
        ));
    };
    if parent.state() != HomeTransferSourceState::Prepared {
        return Err(HomeTransferStoreError::Conflict(
            "reservation retirement parent is not Prepared",
        ));
    }
    let Some(inventory) = inventory else {
        return Err(HomeTransferStoreError::Corrupt(
            "Prepared parent inventory missing",
        ));
    };
    if parent.issuer().into_uuid().is_nil()
        || parent.request().witness().preparation_id() != request.preparation_id()
        || parent.request().request_digest() != request.source_request_digest()
        || parent.outcome_digest() != &request.source_outcome_digest()
        || parent.request().scope().workspace_id() != request.scope().workspace_id()
        || parent.request().scope().backend_id() != request.scope().backend_id()
        || parent.request().scope().destination_id() != request.scope().destination_id()
    {
        return Err(HomeTransferStoreError::Conflict(
            "reservation retirement parent provenance",
        ));
    }
    let captured = inventory
        .reservations
        .iter()
        .find(|reservation| reservation.request_id == request.reservation_request_id())
        .ok_or(HomeTransferStoreError::Conflict(
            "reservation was not captured by Prepared parent",
        ))?;
    if !matches!(
        &captured.outcome,
        super::super::inventory::SourceReservationOutcome::Pending
    ) {
        return Err(HomeTransferStoreError::Conflict(
            "captured reservation was not Pending",
        ));
    }
    Ok((parent, inventory))
}

fn validate_current_reservation(
    connection: &Connection,
    request: &HomeTransferReservationRetirementRequest,
    parent: &HomeTransferSourceRecord,
    inventory: &super::super::inventory::HomeTransferSourceInventory,
) -> Result<AgentBindingReservation, HomeTransferStoreError> {
    let reservation =
        workspace_agent_binding_reservations::get(connection, request.reservation_request_id())
            .map_err(|error| HomeTransferStoreError::RetirementReservation(Box::new(error)))?
            .ok_or(HomeTransferStoreError::Conflict(
                "captured reservation is missing",
            ))?;
    let captured = inventory
        .reservations
        .iter()
        .find(|candidate| candidate.request_id == request.reservation_request_id())
        .ok_or(HomeTransferStoreError::Conflict(
            "reservation was not captured by Prepared parent",
        ))?;
    if !matches!(
        &captured.outcome,
        super::super::inventory::SourceReservationOutcome::Pending
    ) || !captured_matches_reservation(captured, &reservation)
        || parent.request().scope().workspace_id() != reservation.workspace_id()
        || request.scope().workspace_id() != reservation.workspace_id()
        || request.scope().destination_id() != reservation.destination_id()
    {
        return Err(HomeTransferStoreError::Conflict(
            "retirement reservation differs from captured Pending provenance",
        ));
    }
    Ok(reservation)
}

fn captured_matches_reservation(
    captured: &super::super::inventory::SourceBindingReservation,
    reservation: &AgentBindingReservation,
) -> bool {
    let current = reservation.request();
    let principal_matches = match (captured.principal, current.principal()) {
        (
            super::super::inventory::SourcePrincipal::TrustedStdio,
            AuthenticatedPrincipal::TrustedStdio,
        ) => true,
        (
            super::super::inventory::SourcePrincipal::DirectToken(expected),
            AuthenticatedPrincipal::DirectToken(actual),
        ) => expected == actual.into_uuid(),
        (
            super::super::inventory::SourcePrincipal::OAuthGrant(expected),
            AuthenticatedPrincipal::OAuthGrant(actual),
        ) => expected == actual.into_uuid(),
        _ => false,
    };
    captured.request_id == current.request_id()
        && captured.workspace_id == reservation.workspace_id().into_uuid()
        && captured.activity_id == current.activity_id().into_uuid()
        && captured.migration_id == reservation.migration_id()
        && captured.destination_id == reservation.destination_id()
        && u64::try_from(captured.freeze_revision).ok() == Some(reservation.freeze_revision())
        && captured.agent_id == current.agent_id().into_uuid()
        && captured.session_id == current.session_id().into_uuid()
        && principal_matches
        && captured.requested_at_ms == current.requested_at().get()
        && captured.reserved_at_ms == reservation.reserved_at().get()
}

fn ensure_no_terminal_or_materialized_state(
    connection: &Connection,
    reservation: &AgentBindingReservation,
) -> Result<(), HomeTransferStoreError> {
    let request_id = reservation.request().request_id();
    if workspace_agent_binding_activation::get(connection, request_id)
        .map_err(|error| HomeTransferStoreError::RetirementActivation(Box::new(error)))?
        .is_some()
    {
        return Err(HomeTransferStoreError::Conflict(
            "reservation already activated",
        ));
    }
    if workspace_agent_binding_rejections::get(connection, request_id)
        .map_err(|error| HomeTransferStoreError::RetirementRejection(Box::new(error)))?
        .is_some()
    {
        return Err(HomeTransferStoreError::Conflict(
            "reservation already rejected",
        ));
    }
    if workspace_agents::get_in_transaction(connection, reservation.request().agent_id())
        .map_err(|error| HomeTransferStoreError::RetirementAgent(Box::new(error)))?
        .is_some()
    {
        return Err(HomeTransferStoreError::Conflict(
            "reserved Agent already materialized",
        ));
    }
    Ok(())
}

fn ensure_no_agent_history_or_effects(
    connection: &Connection,
    reservation: &AgentBindingReservation,
) -> Result<(), HomeTransferStoreError> {
    let workspace_id = reservation.workspace_id();
    let agent_id = reservation.request().agent_id();
    let has_history: bool = connection.query_row(
        "SELECT EXISTS(
                 SELECT 1 FROM agent_assignments
                 WHERE workspace_id = ?1 AND target_agent_id = ?2
             ) OR EXISTS(
                 SELECT 1 FROM effect_fact_outbox_assignment_offered
                 WHERE workspace_id = ?1 AND target_agent_id = ?2
             ) OR EXISTS(
                 SELECT 1 FROM effect_fact_outbox_assignment_review
                 WHERE workspace_id = ?1 AND target_agent_id = ?2
             ) OR EXISTS(
                 SELECT 1 FROM effect_fact_outbox_assignment_submitted
                 WHERE workspace_id = ?1 AND target_agent_id = ?2
             ) OR EXISTS(
                 SELECT 1 FROM agent_work_updates
                 WHERE workspace_id = ?1 AND agent_id = ?2
             ) OR EXISTS(
                 SELECT 1 FROM agent_work_update_evidence_refs
                 WHERE workspace_id = ?1 AND agent_id = ?2
             ) OR EXISTS(
                 SELECT 1 FROM agent_presence
                 WHERE workspace_id = ?1 AND agent_id = ?2
             ) OR EXISTS(
                 SELECT 1 FROM agent_events
                 WHERE workspace_id = ?1 AND (from_agent_id = ?2 OR to_agent_id = ?2)
             ) OR EXISTS(
                 SELECT 1 FROM agent_inbox WHERE recipient_agent_id = ?2
             ) OR EXISTS(
                 SELECT 1 FROM agent_effect_outbox_focus f
                 JOIN agent_effect_outbox_entries e ON e.sequence = f.outbox_sequence
                 WHERE e.workspace_id = ?1 AND f.agent_id = ?2
             ) OR EXISTS(
                 SELECT 1 FROM agent_effect_outbox_transitions
                 WHERE workspace_id = ?1 AND (from_agent_id = ?2 OR to_agent_id = ?2)
             )",
        params![
            workspace_id.into_uuid().as_bytes(),
            agent_id.into_uuid().as_bytes(),
        ],
        |row| row.get(0),
    )?;
    if has_history {
        return Err(HomeTransferStoreError::Conflict(
            "reserved Agent has assignment, work, or effect history",
        ));
    }
    Ok(())
}

fn source_time_high_water(
    parent: &HomeTransferSourceRecord,
    inventory: &super::super::inventory::HomeTransferSourceInventory,
    reservation: &AgentBindingReservation,
    delegation: &crate::AgentOperationsDelegation,
    workspace_updated_at_ms: i64,
) -> i64 {
    parent
        .observed_at()
        .get()
        .max(workspace_updated_at_ms)
        .max(inventory.source_high_water_ms)
        .max(reservation.request().requested_at().get())
        .max(reservation.reserved_at().get())
        .max(delegation.delegated_at().get())
        .max(delegation.freeze().updated_at().get())
}

fn validate_observation_time(
    request: &HomeTransferReservationRetirementRequest,
    grant: HomeTransferReservationRetirementGrant,
    issuer: OrchestrationIssuerId,
    observed_at: TimestampMillis,
    high_water: i64,
) -> Result<(), HomeTransferStoreError> {
    grant
        .validate_for(issuer, request.request_digest(), observed_at)
        .map_err(HomeTransferStoreError::RetirementDomain)?;
    if observed_at.get() < high_water {
        return Err(HomeTransferStoreError::Conflict(
            "reservation retirement source time high-water",
        ));
    }
    Ok(())
}

fn persist(
    connection: &Connection,
    record: &HomeTransferReservationRetirementRecord,
    reservation: &AgentBindingReservation,
) -> Result<(), HomeTransferStoreError> {
    let request = record.request();
    let workspace_id = request.scope().workspace_id();
    let destination_id = request.scope().destination_id();
    let (principal_kind, principal_id) = encode_principal(reservation.request().principal());
    connection.execute(
        "INSERT INTO home_transfer_reservation_retirements (
            preparation_id, reservation_request_id, workspace_id, workspace_revision,
            backend_id, destination_id, source_request_digest, source_outcome_digest,
            source_inventory_digest, request_digest, issuer_id, observed_at_ms, grant_issued_at_ms,
            grant_expires_at_ms, activity_id, agent_id, session_id,
            reservation_migration_id, reservation_destination_id, reservation_freeze_revision,
            reservation_principal_kind, reservation_principal_id,
            reservation_requested_at_ms, reservation_reserved_at_ms,
            reservation_digest, receipt_digest
         ) VALUES (
            ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24,?25,?26
         )",
        params![
            request.preparation_id().as_bytes(),
            request.reservation_request_id().as_bytes(),
            workspace_id.into_uuid().as_bytes(),
            request.scope().workspace_revision().get(),
            request.scope().backend_id().into_uuid().as_bytes(),
            destination_id.as_bytes(),
            request.source_request_digest().as_bytes().as_slice(),
            request.source_outcome_digest().as_slice(),
            record.source_inventory_digest().as_slice(),
            request.request_digest().as_bytes().as_slice(),
            record.issuer().into_uuid().as_bytes(),
            record.observed_at().get(),
            record.grant_issued_at().get(),
            record.grant_expires_at().get(),
            reservation.request().activity_id().into_uuid().as_bytes(),
            reservation.request().agent_id().into_uuid().as_bytes(),
            reservation.request().session_id().into_uuid().as_bytes(),
            reservation.migration_id().as_bytes(),
            reservation.destination_id().as_bytes(),
            i64::try_from(reservation.freeze_revision())
                .map_err(|_| HomeTransferStoreError::Corrupt("reservation freeze revision"))?,
            principal_kind,
            principal_id.as_slice(),
            reservation.request().requested_at().get(),
            reservation.reserved_at().get(),
            record.reservation_digest().as_slice(),
            record.receipt_digest().as_slice(),
        ],
    )?;
    Ok(())
}

fn persist_and_confirm(
    transaction: rusqlite::Transaction<'_>,
    record: &HomeTransferReservationRetirementRecord,
    reservation: &AgentBindingReservation,
    preparation_id: Uuid,
    reservation_request_id: Uuid,
) -> Result<(), HomeTransferStoreError> {
    persist(&transaction, record, reservation)?;
    let readback = load_by_key(&transaction, preparation_id, reservation_request_id)?
        .map(|(record, _)| record)
        .ok_or(HomeTransferStoreError::Corrupt(
            "reservation retirement insert readback",
        ))?;
    if &readback != record {
        return Err(HomeTransferStoreError::Corrupt(
            "reservation retirement readback mismatch",
        ));
    }
    transaction.commit().map_err(
        |source| HomeTransferStoreError::RetirementCommitUnconfirmed {
            preparation_id,
            reservation_request_id,
            source: Box::new(source),
        },
    )?;
    Ok(())
}

fn validate_parent_link(
    connection: &Connection,
    record: &HomeTransferReservationRetirementRecord,
) -> Result<(), HomeTransferStoreError> {
    let parent = connection
        .query_row(
            "SELECT substr(preparation_id, 1, 17), substr(workspace_id, 1, 17), outcome,
                    substr(issuer_id, 1, 17), substr(request_digest, 1, 33),
                    substr(outcome_digest, 1, 33), substr(inventory_digest, 1, 33), observed_at_ms
             FROM home_transfer_source_operations WHERE preparation_id = ?1",
            params![record.request().preparation_id().as_bytes()],
            |row| {
                Ok(RawParentLink {
                    preparation_id: row.get(0)?,
                    workspace_id: row.get(1)?,
                    state: row.get(2)?,
                    issuer_id: row.get(3)?,
                    request_digest: row.get(4)?,
                    outcome_digest: row.get(5)?,
                    inventory_digest: row.get(6)?,
                    observed_at_ms: row.get(7)?,
                })
            },
        )
        .optional()?;
    let parent = parent.ok_or(HomeTransferStoreError::Corrupt(
        "retirement Prepared parent missing",
    ))?;
    if decode_uuid(&parent.preparation_id, "parent preparation")?
        != record.request().preparation_id()
        || decode_uuid(&parent.workspace_id, "parent workspace")?
            != record.request().scope().workspace_id().into_uuid()
        || parent.state != 0
        || decode_uuid(&parent.issuer_id, "parent issuer")? != record.issuer().into_uuid()
        || parent.request_digest.as_slice()
            != record
                .request()
                .source_request_digest()
                .as_bytes()
                .as_slice()
        || parent.outcome_digest.as_slice() != record.request().source_outcome_digest().as_slice()
        || parent.inventory_digest.as_slice() != record.source_inventory_digest().as_slice()
    {
        return Err(HomeTransferStoreError::Corrupt(
            "retirement Prepared parent scalar identity",
        ));
    }
    if parent.observed_at_ms < 0 || record.observed_at().get() < parent.observed_at_ms {
        return Err(HomeTransferStoreError::Corrupt(
            "retirement predates Prepared parent",
        ));
    }
    ensure_no_competing_terminal(connection, record.request().reservation_request_id())?;
    Ok(())
}

fn ensure_no_competing_terminal(
    connection: &Connection,
    reservation_request_id: Uuid,
) -> Result<(), HomeTransferStoreError> {
    if workspace_agent_binding_activation::get(connection, reservation_request_id)
        .map_err(|error| HomeTransferStoreError::RetirementActivation(Box::new(error)))?
        .is_some()
    {
        return Err(HomeTransferStoreError::Conflict(
            "retirement competes with activation",
        ));
    }
    if workspace_agent_binding_rejections::get(connection, reservation_request_id)
        .map_err(|error| HomeTransferStoreError::RetirementRejection(Box::new(error)))?
        .is_some()
    {
        return Err(HomeTransferStoreError::Conflict(
            "retirement competes with rejection",
        ));
    }
    Ok(())
}

fn load_by_key(
    connection: &Connection,
    preparation_id: Uuid,
    reservation_request_id: Uuid,
) -> Result<Option<(HomeTransferReservationRetirementRecord, RawRetirement)>, HomeTransferStoreError>
{
    let query = format!(
        "SELECT {SELECT_COLUMNS} FROM {} WHERE preparation_id = ?1 AND reservation_request_id = ?2",
        schema::RETIREMENTS_TABLE
    );
    let raw = connection
        .query_row(
            &query,
            params![preparation_id.as_bytes(), reservation_request_id.as_bytes()],
            RawRetirement::decode,
        )
        .optional()?;
    raw.map(|raw| validate_and_decode_record(connection, raw))
        .transpose()
}

fn load_by_reservation(
    connection: &Connection,
    reservation_request_id: Uuid,
) -> Result<Option<(HomeTransferReservationRetirementRecord, RawRetirement)>, HomeTransferStoreError>
{
    load_raw_by_reservation(connection, reservation_request_id)?
        .map(|raw| validate_and_decode_record(connection, raw))
        .transpose()
}

fn validate_and_decode_record(
    connection: &Connection,
    raw: RawRetirement,
) -> Result<(HomeTransferReservationRetirementRecord, RawRetirement), HomeTransferStoreError> {
    let (record, raw) = decode_record(raw)?;
    let reservation = workspace_agent_binding_reservations::get(
        connection,
        record.request().reservation_request_id(),
    )
    .map_err(|error| HomeTransferStoreError::RetirementReservation(Box::new(error)))?
    .ok_or(HomeTransferStoreError::Corrupt(
        "retirement reservation missing",
    ))?;
    if !record_matches_reservation(&record, &reservation)
        || !raw_matches_reservation(&raw, &reservation)
        || reservation_digest(&reservation) != *record.reservation_digest()
    {
        return Err(HomeTransferStoreError::Corrupt(
            "retirement reservation provenance",
        ));
    }
    validate_selected_reservation_state(connection, &record, &reservation)?;
    Ok((record, raw))
}

fn validate_selected_reservation_state(
    connection: &Connection,
    record: &HomeTransferReservationRetirementRecord,
    reservation: &AgentBindingReservation,
) -> Result<(), HomeTransferStoreError> {
    if record.observed_at() < reservation.request().requested_at()
        || record.observed_at() < reservation.reserved_at()
    {
        return Err(HomeTransferStoreError::Corrupt(
            "retirement predates source reservation",
        ));
    }
    if workspace_agents::get_in_transaction(connection, reservation.request().agent_id())
        .map_err(|error| HomeTransferStoreError::RetirementAgent(Box::new(error)))?
        .is_some()
    {
        return Err(HomeTransferStoreError::Corrupt(
            "retired reservation Agent is materialized",
        ));
    }
    Ok(())
}

fn load_raw_by_reservation(
    connection: &Connection,
    reservation_request_id: Uuid,
) -> Result<Option<RawRetirement>, HomeTransferStoreError> {
    let query = format!(
        "SELECT {SELECT_COLUMNS} FROM {} WHERE reservation_request_id = ?1",
        schema::RETIREMENTS_TABLE
    );
    Ok(connection
        .query_row(
            &query,
            params![reservation_request_id.as_bytes()],
            RawRetirement::decode,
        )
        .optional()?)
}

fn decode_record(
    raw: RawRetirement,
) -> Result<(HomeTransferReservationRetirementRecord, RawRetirement), HomeTransferStoreError> {
    let scope = HomeTransferSourceScope::new(
        WorkspaceId::from_uuid(decode_uuid(&raw.workspace_id, "workspace")?),
        WorkspaceRevision::new(raw.workspace_revision)
            .map_err(|_| HomeTransferStoreError::Corrupt("retirement workspace revision"))?,
        ForgeBackendId::from_uuid(decode_uuid(&raw.backend_id, "backend")?),
        decode_uuid(&raw.destination_id, "destination")?,
    )
    .map_err(|_| HomeTransferStoreError::Corrupt("retirement scope"))?;
    let request = HomeTransferReservationRetirementRequest::new(
        scope,
        decode_uuid(&raw.preparation_id, "preparation")?,
        HomeTransferSourceRequestDigest::from_bytes(decode_digest(
            &raw.source_request_digest,
            "source request digest",
        )?),
        decode_digest(&raw.source_outcome_digest, "source outcome digest")?,
        decode_uuid(&raw.reservation_request_id, "reservation request")?,
    )
    .map_err(HomeTransferStoreError::RetirementDomain)?;
    if request.request_digest().as_bytes().as_slice() != raw.request_digest.as_slice() {
        return Err(HomeTransferStoreError::Corrupt("retirement request digest"));
    }
    let parts = HomeTransferReservationRetirementRecordParts {
        request,
        issuer: OrchestrationIssuerId::from_uuid(decode_uuid(&raw.issuer_id, "issuer")?),
        observed_at: decode_timestamp(raw.observed_at_ms, "observed time")?,
        grant_issued_at: decode_timestamp(raw.grant_issued_at_ms, "grant issue time")?,
        grant_expires_at: decode_timestamp(raw.grant_expires_at_ms, "grant expiry time")?,
        source_inventory_digest: decode_digest(
            &raw.source_inventory_digest,
            "source inventory digest",
        )?,
        reservation_digest: decode_digest(&raw.reservation_digest, "reservation digest")?,
        receipt_digest: decode_digest(&raw.receipt_digest, "receipt digest")?,
    };
    let record = HomeTransferReservationRetirementRecord::from_parts(&parts)?;
    if decode_uuid(&raw.preparation_id, "preparation")? != record.request().preparation_id()
        || decode_uuid(&raw.reservation_request_id, "reservation request")?
            != record.request().reservation_request_id()
    {
        return Err(HomeTransferStoreError::Corrupt("retirement key indexes"));
    }
    Ok((record, raw))
}

fn raw_matches_reservation(raw: &RawRetirement, reservation: &AgentBindingReservation) -> bool {
    let request = reservation.request();
    let (principal_kind, principal_id) = encode_principal(request.principal());
    raw.reservation_request_id.as_slice() == request.request_id().as_bytes()
        && raw.workspace_id.as_slice() == reservation.workspace_id().into_uuid().as_bytes()
        && raw.activity_id.as_slice() == request.activity_id().into_uuid().as_bytes()
        && raw.agent_id.as_slice() == request.agent_id().into_uuid().as_bytes()
        && raw.session_id.as_slice() == request.session_id().into_uuid().as_bytes()
        && raw.reservation_migration_id.as_slice() == reservation.migration_id().as_bytes()
        && raw.reservation_destination_id.as_slice() == reservation.destination_id().as_bytes()
        && u64::try_from(raw.reservation_freeze_revision).ok()
            == Some(reservation.freeze_revision())
        && raw.reservation_principal_kind == principal_kind
        && raw.reservation_principal_id.as_slice() == principal_id.as_slice()
        && raw.reservation_requested_at_ms == request.requested_at().get()
        && raw.reservation_reserved_at_ms == reservation.reserved_at().get()
}

fn record_matches_reservation(
    record: &HomeTransferReservationRetirementRecord,
    reservation: &AgentBindingReservation,
) -> bool {
    record.request().reservation_request_id() == reservation.request().request_id()
        && record.request().scope().workspace_id() == reservation.workspace_id()
        && record.request().scope().destination_id() == reservation.destination_id()
}

fn encode_principal(principal: AuthenticatedPrincipal) -> (i64, [u8; ID_BYTES]) {
    match principal {
        AuthenticatedPrincipal::TrustedStdio => (0, [0; ID_BYTES]),
        AuthenticatedPrincipal::DirectToken(id) => (1, *id.into_uuid().as_bytes()),
        AuthenticatedPrincipal::OAuthGrant(id) => (2, *id.into_uuid().as_bytes()),
    }
}

fn decode_uuid(bytes: &[u8], field: &'static str) -> Result<Uuid, HomeTransferStoreError> {
    let id = Uuid::from_slice(bytes).map_err(|_| HomeTransferStoreError::Corrupt(field))?;
    if id.is_nil() {
        return Err(HomeTransferStoreError::Corrupt(field));
    }
    Ok(id)
}

fn decode_digest(
    bytes: &[u8],
    field: &'static str,
) -> Result<[u8; DIGEST_BYTES], HomeTransferStoreError> {
    bytes
        .try_into()
        .map_err(|_| HomeTransferStoreError::Corrupt(field))
}

fn decode_timestamp(
    value: i64,
    field: &'static str,
) -> Result<TimestampMillis, HomeTransferStoreError> {
    TimestampMillis::new(value).map_err(|_| HomeTransferStoreError::Corrupt(field))
}

struct RawRetirement {
    preparation_id: Vec<u8>,
    reservation_request_id: Vec<u8>,
    workspace_id: Vec<u8>,
    workspace_revision: i64,
    backend_id: Vec<u8>,
    destination_id: Vec<u8>,
    source_request_digest: Vec<u8>,
    source_outcome_digest: Vec<u8>,
    source_inventory_digest: Vec<u8>,
    request_digest: Vec<u8>,
    issuer_id: Vec<u8>,
    observed_at_ms: i64,
    grant_issued_at_ms: i64,
    grant_expires_at_ms: i64,
    activity_id: Vec<u8>,
    agent_id: Vec<u8>,
    session_id: Vec<u8>,
    reservation_migration_id: Vec<u8>,
    reservation_destination_id: Vec<u8>,
    reservation_freeze_revision: i64,
    reservation_principal_kind: i64,
    reservation_principal_id: Vec<u8>,
    reservation_requested_at_ms: i64,
    reservation_reserved_at_ms: i64,
    reservation_digest: Vec<u8>,
    receipt_digest: Vec<u8>,
}

struct RawParentLink {
    preparation_id: Vec<u8>,
    workspace_id: Vec<u8>,
    state: i64,
    issuer_id: Vec<u8>,
    request_digest: Vec<u8>,
    outcome_digest: Vec<u8>,
    inventory_digest: Vec<u8>,
    observed_at_ms: i64,
}

impl RawRetirement {
    fn decode(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            preparation_id: row.get(0)?,
            reservation_request_id: row.get(1)?,
            workspace_id: row.get(2)?,
            workspace_revision: row.get(3)?,
            backend_id: row.get(4)?,
            destination_id: row.get(5)?,
            source_request_digest: row.get(6)?,
            source_outcome_digest: row.get(7)?,
            source_inventory_digest: row.get(8)?,
            request_digest: row.get(9)?,
            issuer_id: row.get(10)?,
            observed_at_ms: row.get(11)?,
            grant_issued_at_ms: row.get(12)?,
            grant_expires_at_ms: row.get(13)?,
            activity_id: row.get(14)?,
            agent_id: row.get(15)?,
            session_id: row.get(16)?,
            reservation_migration_id: row.get(17)?,
            reservation_destination_id: row.get(18)?,
            reservation_freeze_revision: row.get(19)?,
            reservation_principal_kind: row.get(20)?,
            reservation_principal_id: row.get(21)?,
            reservation_requested_at_ms: row.get(22)?,
            reservation_reserved_at_ms: row.get(23)?,
            reservation_digest: row.get(24)?,
            receipt_digest: row.get(25)?,
        })
    }
}
