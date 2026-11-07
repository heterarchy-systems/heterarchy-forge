//! Schema-v72 immutable per-reservation retirement journal and cross-owner fences.

use rusqlite::{Connection, OptionalExtension, params};

use crate::HomeTransferStoreError;

pub(crate) const RETIREMENTS_TABLE: &str = "home_transfer_reservation_retirements";
const MAX_SCHEMA_SQL_BYTES: i64 = 65_536;

const TABLE_SQL: &str = "CREATE TABLE home_transfer_reservation_retirements (preparation_id BLOB NOT NULL CHECK(length(preparation_id) = 16 AND preparation_id != zeroblob(16)), reservation_request_id BLOB NOT NULL UNIQUE CHECK(length(reservation_request_id) = 16 AND reservation_request_id != zeroblob(16)), workspace_id BLOB NOT NULL CHECK(length(workspace_id) = 16 AND workspace_id != zeroblob(16)), workspace_revision INTEGER NOT NULL CHECK(workspace_revision >= 1), backend_id BLOB NOT NULL CHECK(length(backend_id) = 16 AND backend_id != zeroblob(16)), destination_id BLOB NOT NULL CHECK(length(destination_id) = 16 AND destination_id != zeroblob(16)), source_request_digest BLOB NOT NULL CHECK(length(source_request_digest) = 32 AND source_request_digest != zeroblob(32)), source_outcome_digest BLOB NOT NULL CHECK(length(source_outcome_digest) = 32 AND source_outcome_digest != zeroblob(32)), source_inventory_digest BLOB NOT NULL CHECK(length(source_inventory_digest) = 32), request_digest BLOB NOT NULL CHECK(length(request_digest) = 32), issuer_id BLOB NOT NULL CHECK(length(issuer_id) = 16 AND issuer_id != zeroblob(16)), observed_at_ms INTEGER NOT NULL CHECK(observed_at_ms >= 0), grant_issued_at_ms INTEGER NOT NULL CHECK(grant_issued_at_ms >= 0), grant_expires_at_ms INTEGER NOT NULL CHECK(grant_expires_at_ms > grant_issued_at_ms), activity_id BLOB NOT NULL CHECK(length(activity_id) = 16 AND activity_id != zeroblob(16)), agent_id BLOB NOT NULL CHECK(length(agent_id) = 16 AND agent_id != zeroblob(16)), session_id BLOB NOT NULL CHECK(length(session_id) = 16 AND session_id != zeroblob(16)), reservation_migration_id BLOB NOT NULL CHECK(length(reservation_migration_id) = 16 AND reservation_migration_id != zeroblob(16)), reservation_destination_id BLOB NOT NULL CHECK(length(reservation_destination_id) = 16 AND reservation_destination_id != zeroblob(16)), reservation_freeze_revision INTEGER NOT NULL CHECK(reservation_freeze_revision >= 1), reservation_principal_kind INTEGER NOT NULL CHECK(reservation_principal_kind IN (0, 1, 2)), reservation_principal_id BLOB NOT NULL CHECK(length(reservation_principal_id) = 16), reservation_requested_at_ms INTEGER NOT NULL CHECK(reservation_requested_at_ms >= 0), reservation_reserved_at_ms INTEGER NOT NULL CHECK(reservation_reserved_at_ms >= reservation_requested_at_ms), reservation_digest BLOB NOT NULL CHECK(length(reservation_digest) = 32), receipt_digest BLOB NOT NULL CHECK(length(receipt_digest) = 32), PRIMARY KEY(preparation_id, reservation_request_id), FOREIGN KEY(preparation_id, workspace_id) REFERENCES home_transfer_source_operations(preparation_id, workspace_id), FOREIGN KEY(reservation_request_id) REFERENCES agent_binding_reservations(request_id), CHECK(observed_at_ms >= grant_issued_at_ms AND observed_at_ms < grant_expires_at_ms), CHECK((reservation_principal_kind = 0 AND reservation_principal_id = zeroblob(16)) OR (reservation_principal_kind IN (1, 2) AND reservation_principal_id != zeroblob(16)))) STRICT";

const RETIREMENT_GUARD_TRIGGER: &str = "home_transfer_reservation_retirements_require_unused";
const RETIREMENT_GUARD_SQL: &str = "CREATE TRIGGER home_transfer_reservation_retirements_require_unused BEFORE INSERT ON home_transfer_reservation_retirements WHEN NOT EXISTS (SELECT 1 FROM home_transfer_source_operations o WHERE o.preparation_id = NEW.preparation_id AND o.workspace_id = NEW.workspace_id AND o.outcome = 0 AND o.request_digest = NEW.source_request_digest AND o.outcome_digest = NEW.source_outcome_digest AND o.inventory_digest = NEW.source_inventory_digest) OR NOT EXISTS (SELECT 1 FROM agent_binding_reservations r WHERE r.request_id = NEW.reservation_request_id AND r.workspace_id = NEW.workspace_id AND r.activity_id = NEW.activity_id AND r.agent_id = NEW.agent_id AND r.session_id = NEW.session_id AND r.migration_id = NEW.reservation_migration_id AND r.destination_id = NEW.reservation_destination_id AND r.freeze_revision = NEW.reservation_freeze_revision AND r.principal_kind = NEW.reservation_principal_kind AND r.principal_id = NEW.reservation_principal_id AND r.requested_at_ms = NEW.reservation_requested_at_ms AND r.reserved_at_ms = NEW.reservation_reserved_at_ms) OR EXISTS (SELECT 1 FROM agent_binding_activations a WHERE a.request_id = NEW.reservation_request_id) OR EXISTS (SELECT 1 FROM agent_binding_rejections r WHERE r.request_id = NEW.reservation_request_id) OR EXISTS (SELECT 1 FROM agent_instances i WHERE i.workspace_id = NEW.workspace_id AND i.agent_id = NEW.agent_id) OR EXISTS (SELECT 1 FROM agent_assignments a WHERE a.workspace_id = NEW.workspace_id AND a.target_agent_id = NEW.agent_id) OR EXISTS (SELECT 1 FROM effect_fact_outbox_assignment_offered e WHERE e.workspace_id = NEW.workspace_id AND e.target_agent_id = NEW.agent_id) OR EXISTS (SELECT 1 FROM effect_fact_outbox_assignment_review e WHERE e.workspace_id = NEW.workspace_id AND e.target_agent_id = NEW.agent_id) OR EXISTS (SELECT 1 FROM effect_fact_outbox_assignment_submitted e WHERE e.workspace_id = NEW.workspace_id AND e.target_agent_id = NEW.agent_id) OR EXISTS (SELECT 1 FROM agent_work_updates w WHERE w.workspace_id = NEW.workspace_id AND w.agent_id = NEW.agent_id) OR EXISTS (SELECT 1 FROM agent_work_update_evidence_refs w WHERE w.workspace_id = NEW.workspace_id AND w.agent_id = NEW.agent_id) OR EXISTS (SELECT 1 FROM agent_presence p WHERE p.workspace_id = NEW.workspace_id AND p.agent_id = NEW.agent_id) OR EXISTS (SELECT 1 FROM agent_events e WHERE e.workspace_id = NEW.workspace_id AND (e.from_agent_id = NEW.agent_id OR e.to_agent_id = NEW.agent_id)) OR EXISTS (SELECT 1 FROM agent_inbox i WHERE i.recipient_agent_id = NEW.agent_id) OR EXISTS (SELECT 1 FROM agent_effect_outbox_focus f JOIN agent_effect_outbox_entries e ON e.sequence = f.outbox_sequence WHERE e.workspace_id = NEW.workspace_id AND f.agent_id = NEW.agent_id) OR EXISTS (SELECT 1 FROM agent_effect_outbox_transitions t WHERE t.workspace_id = NEW.workspace_id AND (t.from_agent_id = NEW.agent_id OR t.to_agent_id = NEW.agent_id)) BEGIN SELECT RAISE(ABORT, 'Home reservation Agent has work history or effects'); END";

const ACTIVATION_GUARD_TRIGGER: &str =
    "agent_binding_activations_block_home_reservation_retirement";
const ACTIVATION_GUARD_SQL: &str = "CREATE TRIGGER agent_binding_activations_block_home_reservation_retirement BEFORE INSERT ON agent_binding_activations WHEN EXISTS (SELECT 1 FROM home_transfer_reservation_retirements r WHERE r.reservation_request_id = NEW.request_id) BEGIN SELECT RAISE(ABORT, 'Home reservation was retired'); END";

const REJECTION_GUARD_TRIGGER: &str = "agent_binding_rejections_block_home_reservation_retirement";
const REJECTION_GUARD_SQL: &str = "CREATE TRIGGER agent_binding_rejections_block_home_reservation_retirement BEFORE INSERT ON agent_binding_rejections WHEN EXISTS (SELECT 1 FROM home_transfer_reservation_retirements r WHERE r.reservation_request_id = NEW.request_id) BEGIN SELECT RAISE(ABORT, 'Home reservation was retired'); END";

const MATERIALIZATION_GUARD_TRIGGER: &str = "agent_instances_block_home_reservation_retirement";
const MATERIALIZATION_GUARD_SQL: &str = "CREATE TRIGGER agent_instances_block_home_reservation_retirement BEFORE INSERT ON agent_instances WHEN EXISTS (SELECT 1 FROM home_transfer_reservation_retirements r WHERE r.workspace_id = NEW.workspace_id AND (r.agent_id = NEW.agent_id OR (r.activity_id = NEW.activity_id AND r.session_id = NEW.session_id))) BEGIN SELECT RAISE(ABORT, 'Home reservation Agent or Activity/Session tuple was retired'); END";

const MATERIALIZATION_UPDATE_GUARD_TRIGGER: &str =
    "agent_instances_update_block_home_reservation_retirement";
const MATERIALIZATION_UPDATE_GUARD_SQL: &str = "CREATE TRIGGER agent_instances_update_block_home_reservation_retirement BEFORE UPDATE OF workspace_id, activity_id, agent_id, session_id ON agent_instances WHEN (NEW.workspace_id IS NOT OLD.workspace_id OR NEW.activity_id IS NOT OLD.activity_id OR NEW.agent_id IS NOT OLD.agent_id OR NEW.session_id IS NOT OLD.session_id) AND EXISTS (SELECT 1 FROM home_transfer_reservation_retirements r WHERE r.workspace_id = NEW.workspace_id AND (r.agent_id = NEW.agent_id OR (r.activity_id = NEW.activity_id AND r.session_id = NEW.session_id))) BEGIN SELECT RAISE(ABORT, 'Home reservation Agent or Activity/Session tuple was retired'); END";

const IMMUTABILITY: &[(&str, &str)] = &[
    (
        "home_transfer_reservation_retirements_no_update",
        "CREATE TRIGGER home_transfer_reservation_retirements_no_update BEFORE UPDATE ON home_transfer_reservation_retirements BEGIN SELECT RAISE(ABORT, 'Home reservation retirements are immutable'); END",
    ),
    (
        "home_transfer_reservation_retirements_no_delete",
        "CREATE TRIGGER home_transfer_reservation_retirements_no_delete BEFORE DELETE ON home_transfer_reservation_retirements BEGIN SELECT RAISE(ABORT, 'Home reservation retirements are immutable'); END",
    ),
];

/// Return the complete schema object inventory owned by this versioned journal.
pub(crate) fn schema_objects() -> Vec<(&'static str, &'static str)> {
    let mut objects = vec![("table", RETIREMENTS_TABLE)];
    objects.extend([
        ("trigger", RETIREMENT_GUARD_TRIGGER),
        ("trigger", ACTIVATION_GUARD_TRIGGER),
        ("trigger", REJECTION_GUARD_TRIGGER),
        ("trigger", MATERIALIZATION_GUARD_TRIGGER),
        ("trigger", MATERIALIZATION_UPDATE_GUARD_TRIGGER),
    ]);
    objects.extend(IMMUTABILITY.iter().map(|(name, _)| ("trigger", *name)));
    objects
}

/// Create the retirement journal and both-direction terminal-state fences.
pub(crate) fn create_schema(connection: &Connection) -> Result<(), HomeTransferStoreError> {
    connection.execute_batch(TABLE_SQL)?;
    connection.execute_batch(RETIREMENT_GUARD_SQL)?;
    connection.execute_batch(ACTIVATION_GUARD_SQL)?;
    connection.execute_batch(REJECTION_GUARD_SQL)?;
    connection.execute_batch(MATERIALIZATION_GUARD_SQL)?;
    connection.execute_batch(MATERIALIZATION_UPDATE_GUARD_SQL)?;
    for (_, sql) in IMMUTABILITY {
        connection.execute_batch(sql)?;
    }
    validate_schema(connection)
}

/// Validate every object, its exact canonical SQL and both foreign keys.
pub(crate) fn validate_schema(connection: &Connection) -> Result<(), HomeTransferStoreError> {
    validate_sql(connection, "table", RETIREMENTS_TABLE, TABLE_SQL)?;
    for (name, sql) in [
        (RETIREMENT_GUARD_TRIGGER, RETIREMENT_GUARD_SQL),
        (ACTIVATION_GUARD_TRIGGER, ACTIVATION_GUARD_SQL),
        (REJECTION_GUARD_TRIGGER, REJECTION_GUARD_SQL),
        (MATERIALIZATION_GUARD_TRIGGER, MATERIALIZATION_GUARD_SQL),
        (
            MATERIALIZATION_UPDATE_GUARD_TRIGGER,
            MATERIALIZATION_UPDATE_GUARD_SQL,
        ),
    ] {
        validate_sql(connection, "trigger", name, sql)?;
    }
    for (name, sql) in IMMUTABILITY {
        validate_sql(connection, "trigger", name, sql)?;
    }
    let foreign_key_count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM pragma_foreign_key_list(?1)",
        params![RETIREMENTS_TABLE],
        |row| row.get(0),
    )?;
    // The composite Prepared-owner FK contributes two pragma rows and the
    // native reservation FK contributes one.
    if foreign_key_count != 3 {
        return Err(HomeTransferStoreError::Corrupt(
            "retirement journal foreign keys",
        ));
    }
    Ok(())
}

fn validate_sql(
    connection: &Connection,
    kind: &'static str,
    name: &'static str,
    expected: &str,
) -> Result<(), HomeTransferStoreError> {
    let length: Option<i64> = connection
        .query_row(
            "SELECT length(CAST(sql AS BLOB)) FROM sqlite_schema WHERE type = ?1 AND name = ?2",
            params![kind, name],
            |row| row.get(0),
        )
        .optional()?;
    let Some(length) = length else {
        return Err(HomeTransferStoreError::Corrupt("retirement schema object"));
    };
    if !(0..=MAX_SCHEMA_SQL_BYTES).contains(&length) {
        return Err(HomeTransferStoreError::Corrupt("retirement schema object"));
    }
    let actual: String = connection.query_row(
        "SELECT sql FROM sqlite_schema WHERE type = ?1 AND name = ?2",
        params![kind, name],
        |row| row.get(0),
    )?;
    if normalize_sql(&actual) != normalize_sql(expected) {
        return Err(HomeTransferStoreError::Corrupt("retirement schema object"));
    }
    Ok(())
}

fn normalize_sql(sql: &str) -> String {
    sql.chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect()
}
