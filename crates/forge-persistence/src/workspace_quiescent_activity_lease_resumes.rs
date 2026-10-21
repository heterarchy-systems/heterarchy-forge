//! Additive schema-v69 receipt ledger for quiescent same-Activity lease resumes.

use rusqlite::{Connection, OptionalExtension, params};
use thiserror::Error;

pub(crate) const RECEIPTS_TABLE: &str = "quiescent_activity_lease_resume_receipts";
pub(crate) const RECEIPTS_SQL: &str = "CREATE TABLE quiescent_activity_lease_resume_receipts (request_id BLOB PRIMARY KEY NOT NULL CHECK(length(request_id) = 16 AND request_id != zeroblob(16)), request_digest BLOB NOT NULL CHECK(length(request_digest) = 32), workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16), activity_id BLOB NOT NULL REFERENCES activities(activity_id) CHECK(length(activity_id) = 16), location_id BLOB NOT NULL CHECK(length(location_id) = 16), location_revision INTEGER NOT NULL CHECK(location_revision BETWEEN 1 AND 9223372036854775807), workspace_revision INTEGER NOT NULL CHECK(workspace_revision BETWEEN 1 AND 9223372036854775807), locator BLOB NOT NULL CHECK(length(locator) BETWEEN 1 AND 4096), root_fingerprint BLOB NOT NULL CHECK(length(root_fingerprint) = 16), binding_digest BLOB NOT NULL CHECK(length(binding_digest) = 32), agent_id BLOB NOT NULL CHECK(length(agent_id) = 16), initiating_session_id BLOB NOT NULL CHECK(length(initiating_session_id) = 16), principal_kind INTEGER NOT NULL CHECK(principal_kind IN (0,1,2)), principal_id BLOB CHECK(principal_id IS NULL OR length(principal_id) = 16), source_runtime_instance_id BLOB NOT NULL CHECK(length(source_runtime_instance_id) = 16), resumed_at_ms INTEGER NOT NULL CHECK(resumed_at_ms BETWEEN 0 AND 9223372036854775807), receipt_payload BLOB NOT NULL CHECK(typeof(receipt_payload) = 'blob' AND length(receipt_payload) BETWEEN 1 AND 65536), receipt_checksum BLOB NOT NULL CHECK(length(receipt_checksum) = 32), CHECK((principal_kind = 0 AND principal_id IS NULL) OR (principal_kind IN (1,2) AND principal_id IS NOT NULL))) STRICT";

pub(crate) fn create_schema(connection: &Connection) -> Result<(), SchemaError> {
    if table_exists(connection)? {
        return validate_schema(connection);
    }
    connection.execute_batch(RECEIPTS_SQL)?;
    validate_schema(connection)
}

pub(crate) fn validate_schema_if_present(connection: &Connection) -> Result<(), SchemaError> {
    if table_exists(connection)? {
        validate_schema(connection)?;
    }
    Ok(())
}

fn table_exists(connection: &Connection) -> Result<bool, SchemaError> {
    Ok(connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?1)",
        params![RECEIPTS_TABLE],
        |row| row.get(0),
    )?)
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
    #[error("quiescent Activity lease-resume schema is damaged")]
    Damaged,
}
