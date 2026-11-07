//! Canonical companion schema for exact Agent-bound approval evidence.

use rusqlite::{Connection, OptionalExtension, params};

use crate::ApprovalStoreError;

const TABLE_SQL: &str = "CREATE TABLE approval_agent_provenance (approval_id BLOB PRIMARY KEY NOT NULL REFERENCES approval_requests(approval_id) ON DELETE CASCADE CHECK(length(approval_id)=16), agent_id BLOB NOT NULL CHECK(length(agent_id)=16), session_id BLOB CHECK(session_id IS NULL OR length(session_id)=16), payload BLOB NOT NULL CHECK(length(payload) BETWEEN 1 AND 300), payload_checksum BLOB NOT NULL CHECK(length(payload_checksum)=32))";
const SESSION_INDEX_SQL: &str = "CREATE INDEX approval_agent_provenance_session_idx ON approval_agent_provenance(session_id,approval_id)";
const AGENT_INDEX_SQL: &str = "CREATE INDEX approval_agent_provenance_agent_idx ON approval_agent_provenance(agent_id,approval_id)";
const NO_UPDATE_SQL: &str = "CREATE TRIGGER approval_agent_provenance_no_update BEFORE UPDATE ON approval_agent_provenance BEGIN SELECT RAISE(ABORT,'approval agent provenance is immutable'); END";
const NO_DIRECT_DELETE_SQL: &str = "CREATE TRIGGER approval_agent_provenance_no_direct_delete BEFORE DELETE ON approval_agent_provenance WHEN EXISTS(SELECT 1 FROM approval_requests WHERE approval_id=OLD.approval_id) BEGIN SELECT RAISE(ABORT,'approval agent provenance is immutable'); END";

pub(crate) const MAX_PAYLOAD_BYTES: usize = 300;

pub(crate) fn schema_objects() -> [(&'static str, &'static str, &'static str); 5] {
    [
        ("table", "approval_agent_provenance", TABLE_SQL),
        (
            "index",
            "approval_agent_provenance_session_idx",
            SESSION_INDEX_SQL,
        ),
        (
            "index",
            "approval_agent_provenance_agent_idx",
            AGENT_INDEX_SQL,
        ),
        (
            "trigger",
            "approval_agent_provenance_no_update",
            NO_UPDATE_SQL,
        ),
        (
            "trigger",
            "approval_agent_provenance_no_direct_delete",
            NO_DIRECT_DELETE_SQL,
        ),
    ]
}

pub(crate) fn create_schema(connection: &Connection) -> Result<(), ApprovalStoreError> {
    for sql in [
        TABLE_SQL,
        SESSION_INDEX_SQL,
        AGENT_INDEX_SQL,
        NO_UPDATE_SQL,
        NO_DIRECT_DELETE_SQL,
    ] {
        connection.execute_batch(sql)?;
    }
    Ok(())
}

/// Validate only the companion objects; the owning approval module validates
/// its base schema and the Workspace store validates the full schema version.
pub(crate) fn validate_schema(connection: &Connection) -> Result<(), ApprovalStoreError> {
    for (kind, name, expected) in schema_objects() {
        let actual: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type=?1 AND name=?2",
                params![kind, name],
                |row| row.get(0),
            )
            .optional()?;
        if actual
            .as_deref()
            .is_none_or(|value| normalize_sql(value) != normalize_sql(expected))
        {
            return Err(ApprovalStoreError::CorruptRecord(
                "approval agent provenance schema object",
            ));
        }
    }
    validate_index(
        connection,
        "approval_agent_provenance_session_idx",
        &["session_id", "approval_id"],
    )?;
    validate_index(
        connection,
        "approval_agent_provenance_agent_idx",
        &["agent_id", "approval_id"],
    )?;
    validate_foreign_key(connection)?;
    Ok(())
}

fn validate_index(
    connection: &Connection,
    name: &'static str,
    expected: &[&str],
) -> Result<(), ApprovalStoreError> {
    let mut statement = connection.prepare(&format!("PRAGMA index_info({name})"))?;
    let rows = statement
        .query_map([], |row| row.get::<_, String>(2))?
        .collect::<Result<Vec<_>, _>>()?;
    if rows.iter().map(String::as_str).ne(expected.iter().copied()) {
        return Err(ApprovalStoreError::CorruptRecord(
            "approval agent provenance index columns",
        ));
    }
    Ok(())
}

fn validate_foreign_key(connection: &Connection) -> Result<(), ApprovalStoreError> {
    let mut statement = connection.prepare("PRAGMA foreign_key_list(approval_agent_provenance)")?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(6)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if rows.len() != 1
        || rows.first().is_none_or(|row| {
            row != &(
                "approval_requests".to_owned(),
                "approval_id".to_owned(),
                "approval_id".to_owned(),
                "CASCADE".to_owned(),
            )
        })
    {
        return Err(ApprovalStoreError::CorruptRecord(
            "approval agent provenance foreign key",
        ));
    }
    Ok(())
}

fn normalize_sql(value: &str) -> String {
    value
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .map(|byte| char::from(byte.to_ascii_lowercase()))
        .collect()
}
