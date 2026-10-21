//! Schema-v66 immutable ledger for same-Activity unstarted continuation.

use rusqlite::{Connection, OptionalExtension, params};
use thiserror::Error;

pub(crate) const RECEIPTS_TABLE: &str = "unstarted_activity_continuation_receipts";
pub(crate) const RECEIPTS_SQL: &str = "CREATE TABLE unstarted_activity_continuation_receipts (request_id BLOB PRIMARY KEY NOT NULL CHECK(length(request_id) = 16 AND request_id != zeroblob(16)), request_digest BLOB NOT NULL CHECK(length(request_digest) = 32 AND request_digest != zeroblob(32)), workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16), activity_id BLOB NOT NULL REFERENCES activities(activity_id) CHECK(length(activity_id) = 16), location_id BLOB NOT NULL CHECK(length(location_id) = 16), location_revision INTEGER NOT NULL CHECK(location_revision >= 1), workspace_revision INTEGER NOT NULL CHECK(workspace_revision >= 1), locator BLOB NOT NULL CHECK(length(locator) BETWEEN 1 AND 4096), root_fingerprint BLOB NOT NULL CHECK(length(root_fingerprint) = 16), binding_digest BLOB NOT NULL CHECK(length(binding_digest) = 32), delegation_migration_id BLOB NOT NULL CHECK(length(delegation_migration_id) = 16), delegation_destination_id BLOB NOT NULL CHECK(length(delegation_destination_id) = 16), delegation_digest BLOB NOT NULL CHECK(length(delegation_digest) = 32), service_backend_id BLOB NOT NULL CHECK(length(service_backend_id) = 16), service_issuer_id BLOB NOT NULL CHECK(length(service_issuer_id) = 16), service_runtime_instance_id BLOB NOT NULL CHECK(length(service_runtime_instance_id) = 16), initiating_session_id BLOB NOT NULL CHECK(length(initiating_session_id) = 16), initiating_principal_kind INTEGER NOT NULL CHECK(initiating_principal_kind IN (0,1,2)), initiating_principal_id BLOB CHECK(initiating_principal_id IS NULL OR length(initiating_principal_id) = 16), session_revision INTEGER NOT NULL CHECK(session_revision >= 1), session_updated_at_ms INTEGER NOT NULL CHECK(session_updated_at_ms >= 0), probe_observed_at_ms INTEGER NOT NULL CHECK(probe_observed_at_ms >= 0), probe_digest BLOB NOT NULL CHECK(length(probe_digest) = 32), census_version INTEGER NOT NULL CHECK(census_version = 1), agent_count INTEGER NOT NULL CHECK(agent_count BETWEEN 1 AND 256), agent_digest BLOB NOT NULL CHECK(length(agent_digest) = 32), plan_digest BLOB NOT NULL CHECK(length(plan_digest) = 32), coordinator_agent_id BLOB CHECK(coordinator_agent_id IS NULL OR length(coordinator_agent_id) = 16), coordinator_revision INTEGER CHECK(coordinator_revision IS NULL OR coordinator_revision >= 1), coordinator_updated_at_ms INTEGER CHECK(coordinator_updated_at_ms IS NULL OR coordinator_updated_at_ms >= 0), before_activity_revision INTEGER NOT NULL CHECK(before_activity_revision >= 1), before_activity_created_at_ms INTEGER NOT NULL CHECK(before_activity_created_at_ms >= 0), before_activity_updated_at_ms INTEGER NOT NULL CHECK(before_activity_updated_at_ms >= before_activity_created_at_ms), before_owner_id BLOB NOT NULL CHECK(length(before_owner_id) = 16), before_lease_until_ms INTEGER NOT NULL CHECK(before_lease_until_ms >= 0), before_lease_revision INTEGER NOT NULL CHECK(before_lease_revision >= 1), continued_at_ms INTEGER NOT NULL CHECK(continued_at_ms >= before_lease_until_ms), lease_gap_ms INTEGER NOT NULL CHECK(lease_gap_ms = continued_at_ms - before_lease_until_ms), after_activity_revision INTEGER NOT NULL CHECK(after_activity_revision = before_activity_revision + 1), after_activity_updated_at_ms INTEGER NOT NULL CHECK(after_activity_updated_at_ms = continued_at_ms), after_owner_id BLOB NOT NULL CHECK(length(after_owner_id) = 16), after_lease_until_ms INTEGER NOT NULL CHECK(after_lease_until_ms > continued_at_ms), after_lease_revision INTEGER NOT NULL CHECK(after_lease_revision = before_lease_revision + 1), receipt_digest BLOB NOT NULL CHECK(length(receipt_digest) = 32), CHECK((coordinator_agent_id IS NULL AND coordinator_revision IS NULL AND coordinator_updated_at_ms IS NULL) OR (coordinator_agent_id IS NOT NULL AND coordinator_revision IS NOT NULL AND coordinator_updated_at_ms IS NOT NULL)), CHECK((initiating_principal_kind = 0 AND initiating_principal_id IS NULL) OR (initiating_principal_kind IN (1,2) AND initiating_principal_id IS NOT NULL)))";

pub(crate) fn create_schema(connection: &Connection) -> Result<(), SchemaError> {
    connection.execute_batch(RECEIPTS_SQL)?;
    Ok(())
}

pub(crate) fn validate_schema(connection: &Connection) -> Result<(), SchemaError> {
    let actual: Option<String> = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type='table' AND name=?1",
            params![RECEIPTS_TABLE],
            |row| row.get(0),
        )
        .optional()?;
    if actual.as_deref().map(normalize) != Some(normalize(RECEIPTS_SQL)) {
        return Err(SchemaError::Damaged);
    }
    Ok(())
}

pub(crate) const fn schema_objects() -> [(&'static str, &'static str); 1] {
    [("table", RECEIPTS_TABLE)]
}

fn normalize(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect()
}

#[derive(Debug, Error)]
pub(crate) enum SchemaError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error("unstarted Activity continuation schema is damaged")]
    Damaged,
}
