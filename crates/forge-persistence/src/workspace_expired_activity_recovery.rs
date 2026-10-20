//! Schema and checked row helpers for expired Activity successor recovery.
//!
//! This module is the single DDL authority for schema v64.  The transaction
//! implementation lives under `workspace_store/expired_activity_recovery.rs`;
//! keeping the codecs here prevents SQLite shape details from entering the
//! domain or control crates.
//!
//! The receipt keeps `delegation_workspace_id` as an explicit source-fence
//! snapshot even though the parent receipt has `workspace_id`. This preserves
//! the complete delegated tuple for corruption/readback validation and is an
//! additive persistence-only field; it carries no second Workspace authority.

use rusqlite::{Connection, OptionalExtension};
use thiserror::Error;

pub(crate) const RECEIPTS_TABLE: &str = "expired_activity_recovery_receipts";
pub(crate) const AGENTS_TABLE: &str = "expired_activity_recovery_agents";
pub(crate) const SUCCESSOR_INDEX: &str = "expired_activity_recovery_receipts_successor_uidx";

// One canonical DDL definition per durable object. Creation and validation
// both use these constants; tests inspect the resulting sqlite_schema rows.
pub(crate) const RECEIPTS_TABLE_SQL: &str = "CREATE TABLE expired_activity_recovery_receipts (request_id BLOB PRIMARY KEY NOT NULL CHECK(length(request_id) = 16 AND request_id != zeroblob(16)), workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16 AND workspace_id != zeroblob(16)), location_id BLOB NOT NULL CHECK(length(location_id) = 16 AND location_id != zeroblob(16)), location_revision INTEGER NOT NULL CHECK(location_revision >= 1), locator_relative_root BLOB NOT NULL CHECK(length(locator_relative_root) BETWEEN 1 AND 4096), workspace_revision INTEGER NOT NULL CHECK(workspace_revision >= 1), request_digest BLOB NOT NULL CHECK(length(request_digest) = 32 AND request_digest != zeroblob(32)), binding_digest BLOB NOT NULL CHECK(length(binding_digest) = 32 AND binding_digest != zeroblob(32)), workspace_root_fingerprint BLOB NOT NULL CHECK(length(workspace_root_fingerprint) = 16), probe_observed_at_ms INTEGER NOT NULL CHECK(probe_observed_at_ms >= 0), probe_digest BLOB NOT NULL CHECK(length(probe_digest) = 32 AND probe_digest != zeroblob(32)), delegation_migration_id BLOB NOT NULL CHECK(length(delegation_migration_id) = 16 AND delegation_migration_id != zeroblob(16)), delegation_workspace_id BLOB NOT NULL CHECK(length(delegation_workspace_id) = 16 AND delegation_workspace_id != zeroblob(16)), delegation_destination_id BLOB NOT NULL CHECK(length(delegation_destination_id) = 16 AND delegation_destination_id != zeroblob(16)), delegation_freeze_state INTEGER NOT NULL CHECK(delegation_freeze_state = 0), delegation_freeze_revision INTEGER NOT NULL CHECK(delegation_freeze_revision = 1), delegation_freeze_created_at_ms INTEGER NOT NULL CHECK(delegation_freeze_created_at_ms >= 0), delegation_freeze_updated_at_ms INTEGER NOT NULL CHECK(delegation_freeze_updated_at_ms = delegation_freeze_created_at_ms), delegation_manifest_digest BLOB NOT NULL CHECK(length(delegation_manifest_digest) = 32 AND delegation_manifest_digest != zeroblob(32)), delegation_delegated_at_ms INTEGER NOT NULL CHECK(delegation_delegated_at_ms >= delegation_freeze_updated_at_ms), delegation_digest BLOB NOT NULL CHECK(length(delegation_digest) = 32 AND delegation_digest != zeroblob(32)), service_backend_id BLOB NOT NULL CHECK(length(service_backend_id) = 16 AND service_backend_id != zeroblob(16)), service_issuer_id BLOB NOT NULL CHECK(length(service_issuer_id) = 16 AND service_issuer_id != zeroblob(16)), service_destination_id BLOB NOT NULL CHECK(length(service_destination_id) = 16 AND service_destination_id = delegation_destination_id), owner_runtime_instance_id BLOB NOT NULL CHECK(length(owner_runtime_instance_id) = 16 AND owner_runtime_instance_id != zeroblob(16)), duration_ms INTEGER NOT NULL CHECK(duration_ms BETWEEN 1000 AND 300000), recovered_at_ms INTEGER NOT NULL CHECK(recovered_at_ms >= 0), claimed_lease_until_ms INTEGER NOT NULL CHECK(claimed_lease_until_ms > recovered_at_ms), claimed_epoch INTEGER NOT NULL CHECK(claimed_epoch >= 1), claimed_revision INTEGER NOT NULL CHECK(claimed_revision >= 2), released_epoch INTEGER NOT NULL CHECK(released_epoch = claimed_epoch), released_revision INTEGER NOT NULL CHECK(released_revision = claimed_revision + 1), released_updated_at_ms INTEGER NOT NULL CHECK(released_updated_at_ms = recovered_at_ms), initiating_session_id BLOB NOT NULL CHECK(length(initiating_session_id) = 16 AND initiating_session_id != zeroblob(16)), initiating_principal_kind INTEGER NOT NULL CHECK(initiating_principal_kind IN (0, 1, 2)), initiating_principal_id BLOB CHECK(initiating_principal_id IS NULL OR length(initiating_principal_id) = 16), session_revision INTEGER NOT NULL CHECK(session_revision >= 1), session_updated_at_ms INTEGER NOT NULL CHECK(session_updated_at_ms >= 0), predecessor_activity_id BLOB NOT NULL REFERENCES activities(activity_id) CHECK(length(predecessor_activity_id) = 16 AND predecessor_activity_id != zeroblob(16)), predecessor_before_state INTEGER NOT NULL CHECK(predecessor_before_state = 1), predecessor_before_revision INTEGER NOT NULL CHECK(predecessor_before_revision >= 1), predecessor_before_created_at_ms INTEGER NOT NULL CHECK(predecessor_before_created_at_ms >= 0), predecessor_before_updated_at_ms INTEGER NOT NULL CHECK(predecessor_before_updated_at_ms >= predecessor_before_created_at_ms), predecessor_before_lease_owner_id BLOB NOT NULL CHECK(length(predecessor_before_lease_owner_id) = 16 AND predecessor_before_lease_owner_id != zeroblob(16)), predecessor_before_lease_until_ms INTEGER NOT NULL CHECK(predecessor_before_lease_until_ms >= 0), predecessor_before_lease_revision INTEGER NOT NULL CHECK(predecessor_before_lease_revision >= 1), predecessor_after_state INTEGER NOT NULL CHECK(predecessor_after_state = 2), predecessor_after_revision INTEGER NOT NULL CHECK(predecessor_after_revision = predecessor_before_revision + 1), predecessor_after_updated_at_ms INTEGER NOT NULL CHECK(predecessor_after_updated_at_ms = recovered_at_ms), predecessor_after_lease_revision INTEGER NOT NULL CHECK(predecessor_after_lease_revision = predecessor_before_lease_revision + 1), successor_activity_id BLOB NOT NULL REFERENCES activities(activity_id) CHECK(length(successor_activity_id) = 16 AND successor_activity_id != zeroblob(16)), successor_state INTEGER NOT NULL CHECK(successor_state = 1), successor_owner_id BLOB NOT NULL CHECK(length(successor_owner_id) = 16 AND successor_owner_id = owner_runtime_instance_id), successor_lease_until_ms INTEGER NOT NULL CHECK(successor_lease_until_ms = claimed_lease_until_ms), successor_revision INTEGER NOT NULL CHECK(successor_revision = 1), successor_lease_revision INTEGER NOT NULL CHECK(successor_lease_revision = 1), successor_created_at_ms INTEGER NOT NULL CHECK(successor_created_at_ms = recovered_at_ms), successor_updated_at_ms INTEGER NOT NULL CHECK(successor_updated_at_ms = recovered_at_ms), agent_count INTEGER NOT NULL CHECK(agent_count BETWEEN 1 AND 256), agent_digest BLOB NOT NULL CHECK(length(agent_digest) = 32 AND agent_digest != zeroblob(32)), coordinator_present INTEGER NOT NULL CHECK(coordinator_present IN (0, 1)), coordinator_agent_id BLOB CHECK(coordinator_agent_id IS NULL OR length(coordinator_agent_id) = 16), coordinator_revision INTEGER CHECK(coordinator_revision IS NULL OR coordinator_revision >= 1), coordinator_updated_at_ms INTEGER CHECK(coordinator_updated_at_ms IS NULL OR coordinator_updated_at_ms >= 0), coordinator_digest BLOB NOT NULL CHECK(length(coordinator_digest) = 32), relation_digest BLOB NOT NULL CHECK(length(relation_digest) = 32), receipt_digest BLOB NOT NULL CHECK(length(receipt_digest) = 32), UNIQUE(workspace_id, predecessor_activity_id), UNIQUE(request_id, workspace_id, predecessor_activity_id), CHECK(predecessor_activity_id != successor_activity_id), CHECK((coordinator_present = 0 AND coordinator_agent_id IS NULL AND coordinator_revision IS NULL AND coordinator_updated_at_ms IS NULL) OR (coordinator_present = 1 AND coordinator_agent_id IS NOT NULL AND coordinator_revision IS NOT NULL AND coordinator_updated_at_ms IS NOT NULL)), CHECK((initiating_principal_kind = 0 AND initiating_principal_id IS NULL) OR (initiating_principal_kind IN (1, 2) AND initiating_principal_id IS NOT NULL)), FOREIGN KEY(coordinator_agent_id, workspace_id, predecessor_activity_id) REFERENCES agent_instances(agent_id, workspace_id, activity_id))";

pub(crate) const AGENTS_TABLE_SQL: &str = "CREATE TABLE expired_activity_recovery_agents (request_id BLOB NOT NULL REFERENCES expired_activity_recovery_receipts(request_id) CHECK(length(request_id) = 16), ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 0 AND 255), agent_id BLOB NOT NULL CHECK(length(agent_id) = 16 AND agent_id != zeroblob(16)), workspace_id BLOB NOT NULL CHECK(length(workspace_id) = 16), activity_id BLOB NOT NULL CHECK(length(activity_id) = 16), session_id BLOB CHECK(session_id IS NULL OR length(session_id) = 16), display_name TEXT NOT NULL CHECK(length(CAST(display_name AS BLOB)) BETWEEN 1 AND 128), declared_role TEXT NOT NULL CHECK(length(CAST(declared_role AS BLOB)) BETWEEN 1 AND 128), transport_kind INTEGER NOT NULL CHECK(transport_kind IN (0, 1, 2, 3)), principal_kind INTEGER NOT NULL CHECK(principal_kind IN (0, 1, 2)), principal_id BLOB CHECK(principal_id IS NULL OR length(principal_id) = 16), attachment_state INTEGER NOT NULL CHECK(attachment_state IN (0, 1)), focus_goal_id BLOB CHECK(focus_goal_id IS NULL OR length(focus_goal_id) = 16), focus_goal_revision INTEGER CHECK(focus_goal_revision IS NULL OR focus_goal_revision >= 1), focus_dag_revision INTEGER CHECK(focus_dag_revision IS NULL OR focus_dag_revision >= 1), focus_node_id BLOB CHECK(focus_node_id IS NULL OR length(focus_node_id) = 16), focus_node_revision INTEGER CHECK(focus_node_revision IS NULL OR focus_node_revision >= 1), created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0), updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= created_at_ms), revision INTEGER NOT NULL CHECK(revision >= 1), PRIMARY KEY(request_id, ordinal), UNIQUE(request_id, agent_id), CHECK((principal_kind = 0 AND principal_id IS NULL) OR (principal_kind IN (1, 2) AND principal_id IS NOT NULL)), CHECK((focus_goal_id IS NULL AND focus_goal_revision IS NULL AND focus_dag_revision IS NULL AND focus_node_id IS NULL AND focus_node_revision IS NULL) OR (focus_goal_id IS NOT NULL AND focus_goal_revision IS NOT NULL AND focus_dag_revision IS NOT NULL AND ((focus_node_id IS NULL AND focus_node_revision IS NULL) OR (focus_node_id IS NOT NULL AND focus_node_revision IS NOT NULL)))), CHECK((attachment_state = 1 AND focus_goal_id IS NULL AND focus_goal_revision IS NULL AND focus_dag_revision IS NULL AND focus_node_id IS NULL AND focus_node_revision IS NULL) OR attachment_state = 0), FOREIGN KEY(request_id, workspace_id, activity_id) REFERENCES expired_activity_recovery_receipts(request_id, workspace_id, predecessor_activity_id), FOREIGN KEY(agent_id, workspace_id, activity_id) REFERENCES agent_instances(agent_id, workspace_id, activity_id))";

pub(crate) const SUCCESSOR_INDEX_SQL: &str = "CREATE UNIQUE INDEX expired_activity_recovery_receipts_successor_uidx ON expired_activity_recovery_receipts(successor_activity_id)";

const EXPECTED_RECEIPT_COLUMNS: &[(&str, &str, i64, i64)] = &[
    ("request_id", "BLOB", 1, 1),
    ("workspace_id", "BLOB", 1, 0),
    ("location_id", "BLOB", 1, 0),
    ("location_revision", "INTEGER", 1, 0),
    ("locator_relative_root", "BLOB", 1, 0),
    ("workspace_revision", "INTEGER", 1, 0),
    ("request_digest", "BLOB", 1, 0),
    ("binding_digest", "BLOB", 1, 0),
    ("workspace_root_fingerprint", "BLOB", 1, 0),
    ("probe_observed_at_ms", "INTEGER", 1, 0),
    ("probe_digest", "BLOB", 1, 0),
    ("delegation_migration_id", "BLOB", 1, 0),
    ("delegation_workspace_id", "BLOB", 1, 0),
    ("delegation_destination_id", "BLOB", 1, 0),
    ("delegation_freeze_state", "INTEGER", 1, 0),
    ("delegation_freeze_revision", "INTEGER", 1, 0),
    ("delegation_freeze_created_at_ms", "INTEGER", 1, 0),
    ("delegation_freeze_updated_at_ms", "INTEGER", 1, 0),
    ("delegation_manifest_digest", "BLOB", 1, 0),
    ("delegation_delegated_at_ms", "INTEGER", 1, 0),
    ("delegation_digest", "BLOB", 1, 0),
    ("service_backend_id", "BLOB", 1, 0),
    ("service_issuer_id", "BLOB", 1, 0),
    ("service_destination_id", "BLOB", 1, 0),
    ("owner_runtime_instance_id", "BLOB", 1, 0),
    ("duration_ms", "INTEGER", 1, 0),
    ("recovered_at_ms", "INTEGER", 1, 0),
    ("claimed_lease_until_ms", "INTEGER", 1, 0),
    ("claimed_epoch", "INTEGER", 1, 0),
    ("claimed_revision", "INTEGER", 1, 0),
    ("released_epoch", "INTEGER", 1, 0),
    ("released_revision", "INTEGER", 1, 0),
    ("released_updated_at_ms", "INTEGER", 1, 0),
    ("initiating_session_id", "BLOB", 1, 0),
    ("initiating_principal_kind", "INTEGER", 1, 0),
    ("initiating_principal_id", "BLOB", 0, 0),
    ("session_revision", "INTEGER", 1, 0),
    ("session_updated_at_ms", "INTEGER", 1, 0),
    ("predecessor_activity_id", "BLOB", 1, 0),
    ("predecessor_before_state", "INTEGER", 1, 0),
    ("predecessor_before_revision", "INTEGER", 1, 0),
    ("predecessor_before_created_at_ms", "INTEGER", 1, 0),
    ("predecessor_before_updated_at_ms", "INTEGER", 1, 0),
    ("predecessor_before_lease_owner_id", "BLOB", 1, 0),
    ("predecessor_before_lease_until_ms", "INTEGER", 1, 0),
    ("predecessor_before_lease_revision", "INTEGER", 1, 0),
    ("predecessor_after_state", "INTEGER", 1, 0),
    ("predecessor_after_revision", "INTEGER", 1, 0),
    ("predecessor_after_updated_at_ms", "INTEGER", 1, 0),
    ("predecessor_after_lease_revision", "INTEGER", 1, 0),
    ("successor_activity_id", "BLOB", 1, 0),
    ("successor_state", "INTEGER", 1, 0),
    ("successor_owner_id", "BLOB", 1, 0),
    ("successor_lease_until_ms", "INTEGER", 1, 0),
    ("successor_revision", "INTEGER", 1, 0),
    ("successor_lease_revision", "INTEGER", 1, 0),
    ("successor_created_at_ms", "INTEGER", 1, 0),
    ("successor_updated_at_ms", "INTEGER", 1, 0),
    ("agent_count", "INTEGER", 1, 0),
    ("agent_digest", "BLOB", 1, 0),
    ("coordinator_present", "INTEGER", 1, 0),
    ("coordinator_agent_id", "BLOB", 0, 0),
    ("coordinator_revision", "INTEGER", 0, 0),
    ("coordinator_updated_at_ms", "INTEGER", 0, 0),
    ("coordinator_digest", "BLOB", 1, 0),
    ("relation_digest", "BLOB", 1, 0),
    ("receipt_digest", "BLOB", 1, 0),
];

const EXPECTED_AGENT_COLUMNS: &[(&str, &str, i64, i64)] = &[
    ("request_id", "BLOB", 1, 1),
    ("ordinal", "INTEGER", 1, 2),
    ("agent_id", "BLOB", 1, 0),
    ("workspace_id", "BLOB", 1, 0),
    ("activity_id", "BLOB", 1, 0),
    ("session_id", "BLOB", 0, 0),
    ("display_name", "TEXT", 1, 0),
    ("declared_role", "TEXT", 1, 0),
    ("transport_kind", "INTEGER", 1, 0),
    ("principal_kind", "INTEGER", 1, 0),
    ("principal_id", "BLOB", 0, 0),
    ("attachment_state", "INTEGER", 1, 0),
    ("focus_goal_id", "BLOB", 0, 0),
    ("focus_goal_revision", "INTEGER", 0, 0),
    ("focus_dag_revision", "INTEGER", 0, 0),
    ("focus_node_id", "BLOB", 0, 0),
    ("focus_node_revision", "INTEGER", 0, 0),
    ("created_at_ms", "INTEGER", 1, 0),
    ("updated_at_ms", "INTEGER", 1, 0),
    ("revision", "INTEGER", 1, 0),
];

pub(crate) fn create_schema(
    connection: &Connection,
) -> Result<(), ExpiredActivityRecoverySchemaError> {
    connection.execute_batch(RECEIPTS_TABLE_SQL)?;
    connection.execute_batch(AGENTS_TABLE_SQL)?;
    connection.execute_batch(SUCCESSOR_INDEX_SQL)?;
    Ok(())
}

pub(crate) fn schema_objects() -> [(&'static str, &'static str); 3] {
    [
        ("table", RECEIPTS_TABLE),
        ("table", AGENTS_TABLE),
        ("index", SUCCESSOR_INDEX),
    ]
}

pub(crate) fn validate_schema(
    connection: &Connection,
) -> Result<(), ExpiredActivityRecoverySchemaError> {
    validate_object_sql(connection, "table", RECEIPTS_TABLE, RECEIPTS_TABLE_SQL)?;
    validate_object_sql(connection, "table", AGENTS_TABLE, AGENTS_TABLE_SQL)?;
    validate_object_sql(connection, "index", SUCCESSOR_INDEX, SUCCESSOR_INDEX_SQL)?;
    validate_columns(connection, RECEIPTS_TABLE, EXPECTED_RECEIPT_COLUMNS)?;
    validate_columns(connection, AGENTS_TABLE, EXPECTED_AGENT_COLUMNS)?;
    // PRAGMA foreign_key_list reports one row per column of a composite FK.
    validate_foreign_key_count(connection, RECEIPTS_TABLE, 6)?;
    validate_foreign_key_count(connection, AGENTS_TABLE, 7)?;
    Ok(())
}

fn validate_object_sql(
    connection: &Connection,
    object_type: &str,
    object_name: &str,
    expected: &str,
) -> Result<(), ExpiredActivityRecoverySchemaError> {
    let actual: Option<String> = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type = ?1 AND name = ?2",
            [object_type, object_name],
            |row| row.get(0),
        )
        .optional()?;
    if actual.as_deref().map(normalize_sql) != Some(normalize_sql(expected)) {
        return Err(ExpiredActivityRecoverySchemaError::DamagedSchema(format!(
            "{object_name}: actual={:?} expected={:?}",
            actual.as_deref().map(normalize_sql),
            normalize_sql(expected),
        )));
    }
    Ok(())
}

fn validate_columns(
    connection: &Connection,
    table: &'static str,
    expected: &[(&str, &str, i64, i64)],
) -> Result<(), ExpiredActivityRecoverySchemaError> {
    let mut statement = connection.prepare(&format!("PRAGMA table_info({table})"))?;
    let mut rows = statement.query([])?;
    let mut actual = Vec::with_capacity(expected.len());
    while let Some(row) = rows.next()? {
        actual.push((
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, i64>(5)?,
        ));
        if actual.len() > expected.len() {
            return Err(ExpiredActivityRecoverySchemaError::DamagedSchema(format!(
                "{table} has more columns than expected"
            )));
        }
    }
    if actual.len() != expected.len()
        || actual.iter().zip(expected).any(|(actual, expected)| {
            actual.0 != expected.0
                || actual.1 != expected.1
                || actual.2 != expected.2
                || actual.3 != expected.3
        })
    {
        return Err(ExpiredActivityRecoverySchemaError::DamagedSchema(format!(
            "{table} columns actual={actual:?} expected={expected:?}"
        )));
    }
    Ok(())
}

fn validate_foreign_key_count(
    connection: &Connection,
    table: &'static str,
    expected: usize,
) -> Result<(), ExpiredActivityRecoverySchemaError> {
    let mut statement = connection.prepare(&format!("PRAGMA foreign_key_list({table})"))?;
    let mut rows = statement.query([])?;
    let mut count = 0;
    while rows.next()?.is_some() {
        count += 1;
    }
    if count != expected {
        return Err(ExpiredActivityRecoverySchemaError::DamagedSchema(format!(
            "{table} foreign key count actual={count} expected={expected}"
        )));
    }
    Ok(())
}

fn normalize_sql(value: &str) -> String {
    value
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .map(|byte| byte.to_ascii_lowercase())
        .map(char::from)
        .collect()
}

#[derive(Debug, Error)]
pub(crate) enum ExpiredActivityRecoverySchemaError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error("expired Activity recovery schema object is damaged: {0}")]
    DamagedSchema(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    #[test]
    fn v64_schema_round_trips_and_missing_index_fails_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE workspace (workspace_id BLOB PRIMARY KEY);
             CREATE TABLE activities (activity_id BLOB PRIMARY KEY, workspace_id BLOB);
             CREATE TABLE agent_instances (
                 agent_id BLOB NOT NULL,
                 workspace_id BLOB NOT NULL,
                 activity_id BLOB NOT NULL,
                 UNIQUE(agent_id, workspace_id, activity_id)
             );",
        )?;
        create_schema(&connection)?;
        validate_schema(&connection)?;
        connection.execute(
            "DROP INDEX expired_activity_recovery_receipts_successor_uidx",
            [],
        )?;
        assert!(matches!(
            validate_schema(&connection),
            Err(ExpiredActivityRecoverySchemaError::DamagedSchema(_))
        ));
        Ok(())
    }
}
