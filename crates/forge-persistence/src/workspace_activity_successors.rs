//! `SQLite` authority for append-only terminal Activity successor relations.

use forge_domain::{
    ActivityId, ActivityRevision, ActivitySuccessor, ActivitySuccessorError, AgentSessionId,
    RuntimeInstanceId, TimestampMillis, WorkspaceId,
};
use rusqlite::{Connection, Row, Transaction, params};
use thiserror::Error;
use uuid::Uuid;

pub(crate) const ACTIVITY_SUCCESSORS_TABLE_SQL: &str = "CREATE TABLE activity_successors (
    workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16),
    predecessor_activity_id BLOB PRIMARY KEY NOT NULL REFERENCES activities(activity_id) CHECK(length(predecessor_activity_id) = 16),
    predecessor_activity_revision INTEGER NOT NULL CHECK(predecessor_activity_revision >= 1),
    successor_activity_id BLOB NOT NULL UNIQUE REFERENCES activities(activity_id) CHECK(length(successor_activity_id) = 16),
    initiating_session_id BLOB NOT NULL CHECK(length(initiating_session_id) = 16),
    runtime_instance_id BLOB NOT NULL CHECK(length(runtime_instance_id) = 16),
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
    CHECK(predecessor_activity_id != successor_activity_id)
)";

const EXPECTED_COLUMNS: [(&str, &str, i64, i64); 7] = [
    ("workspace_id", "BLOB", 1, 0),
    ("predecessor_activity_id", "BLOB", 1, 1),
    ("predecessor_activity_revision", "INTEGER", 1, 0),
    ("successor_activity_id", "BLOB", 1, 0),
    ("initiating_session_id", "BLOB", 1, 0),
    ("runtime_instance_id", "BLOB", 1, 0),
    ("created_at_ms", "INTEGER", 1, 0),
];

const MAX_SCHEMA_SQL_BYTES: usize = 16 * 1024;
const MAX_SCHEMA_METADATA_ROWS: usize = 32;
const ID_BYTES: usize = 16;
const ID_BYTES_I64: i64 = 16;

const SUCCESSOR_QUERY: &str = "SELECT length(CAST(workspace_id AS BLOB)),
       length(CAST(predecessor_activity_id AS BLOB)),
       length(CAST(successor_activity_id AS BLOB)),
       length(CAST(initiating_session_id AS BLOB)),
       length(CAST(runtime_instance_id AS BLOB)),
       workspace_id, predecessor_activity_id, predecessor_activity_revision,
       successor_activity_id, initiating_session_id, runtime_instance_id, created_at_ms
FROM activity_successors
WHERE predecessor_activity_id = ?1";

#[derive(Debug)]
struct RawActivitySuccessor {
    workspace_id: Vec<u8>,
    predecessor_activity_id: Vec<u8>,
    predecessor_activity_revision: i64,
    successor_activity_id: Vec<u8>,
    initiating_session_id: Vec<u8>,
    runtime_instance_id: Vec<u8>,
    created_at_ms: i64,
}

pub(crate) fn create_schema(connection: &Connection) -> Result<(), ActivitySuccessorStoreError> {
    connection.execute_batch(ACTIVITY_SUCCESSORS_TABLE_SQL)?;
    Ok(())
}

pub(crate) const fn schema_objects() -> [(&'static str, &'static str); 1] {
    [("table", "activity_successors")]
}

pub(crate) fn validate_schema(connection: &Connection) -> Result<(), ActivitySuccessorStoreError> {
    let sql_length: Option<i64> = connection.query_row(
        "SELECT length(CAST(sql AS BLOB))
         FROM sqlite_schema WHERE type = 'table' AND name = 'activity_successors'",
        [],
        |row| row.get(0),
    )?;
    let Some(sql_length) = sql_length else {
        return Err(ActivitySuccessorStoreError::DamagedSchema(
            "activity_successors table is missing",
        ));
    };
    if sql_length < 0 {
        return Err(ActivitySuccessorStoreError::DamagedSchema(
            "activity_successors SQL length is negative",
        ));
    }
    let sql_length = usize::try_from(sql_length).unwrap_or(usize::MAX);
    if sql_length > MAX_SCHEMA_SQL_BYTES {
        return Err(ActivitySuccessorStoreError::SchemaSqlTooLarge {
            actual: sql_length,
            maximum: MAX_SCHEMA_SQL_BYTES,
        });
    }
    let actual: String = connection.query_row(
        "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = 'activity_successors'",
        [],
        |row| row.get(0),
    )?;
    if !schema_sql_matches(&actual, ACTIVITY_SUCCESSORS_TABLE_SQL) {
        return Err(ActivitySuccessorStoreError::DamagedSchema(
            "activity_successors table SQL definition does not match the expected policy",
        ));
    }

    let mut statement = connection.prepare("PRAGMA table_info(activity_successors)")?;
    let mut rows = statement.query([])?;
    let mut columns = Vec::new();
    while let Some(row) = rows.next()? {
        if columns.len() >= MAX_SCHEMA_METADATA_ROWS {
            return Err(ActivitySuccessorStoreError::SchemaMetadataTooLarge);
        }
        columns.push((
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, i64>(5)?,
        ));
    }
    let columns_match = columns.len() == EXPECTED_COLUMNS.len()
        && columns.iter().zip(EXPECTED_COLUMNS).all(
            |((name, data_type, not_null, primary_key), expected)| {
                name == expected.0
                    && data_type == expected.1
                    && *not_null == expected.2
                    && *primary_key == expected.3
            },
        );
    if !columns_match {
        return Err(ActivitySuccessorStoreError::DamagedSchema(
            "activity_successors table columns do not match the expected policy",
        ));
    }

    let mut statement = connection.prepare("PRAGMA foreign_key_list(activity_successors)")?;
    let mut rows = statement.query([])?;
    let mut foreign_keys = Vec::new();
    while let Some(row) = rows.next()? {
        if foreign_keys.len() >= MAX_SCHEMA_METADATA_ROWS {
            return Err(ActivitySuccessorStoreError::SchemaMetadataTooLarge);
        }
        foreign_keys.push((
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, String>(6)?,
            row.get::<_, String>(7)?,
        ));
    }
    let expected_foreign_keys = [
        ("workspace", "workspace_id", "workspace_id"),
        ("activities", "predecessor_activity_id", "activity_id"),
        ("activities", "successor_activity_id", "activity_id"),
    ];
    let valid_foreign_keys = foreign_keys.len() == expected_foreign_keys.len()
        && expected_foreign_keys.iter().all(|expected| {
            foreign_keys.iter().any(|actual| {
                actual.0 == expected.0
                    && actual.1 == expected.1
                    && actual.2 == expected.2
                    && actual.3 == "NO ACTION"
                    && actual.4 == "NO ACTION"
                    && actual.5 == "NONE"
            })
        });
    if !valid_foreign_keys {
        return Err(ActivitySuccessorStoreError::DamagedSchema(
            "activity_successors foreign-key shape is invalid",
        ));
    }
    Ok(())
}

pub(crate) fn get_by_predecessor(
    connection: &Connection,
    predecessor_activity_id: ActivityId,
) -> Result<Option<ActivitySuccessor>, ActivitySuccessorStoreError> {
    let mut statement = connection.prepare(SUCCESSOR_QUERY)?;
    let mut rows = statement.query(params![
        predecessor_activity_id.into_uuid().as_bytes().as_slice()
    ])?;
    let Some(row) = rows.next()? else {
        return Ok(None);
    };
    Ok(Some(decode(row)?))
}

pub(crate) fn insert_in_transaction(
    transaction: &Transaction<'_>,
    relation: ActivitySuccessor,
) -> Result<(), ActivitySuccessorStoreError> {
    transaction.execute(
        "INSERT INTO activity_successors (
            workspace_id, predecessor_activity_id, predecessor_activity_revision,
            successor_activity_id, initiating_session_id, runtime_instance_id, created_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            relation.workspace_id().into_uuid().as_bytes().as_slice(),
            relation
                .predecessor_activity_id()
                .into_uuid()
                .as_bytes()
                .as_slice(),
            relation.predecessor_activity_revision().get(),
            relation
                .successor_activity_id()
                .into_uuid()
                .as_bytes()
                .as_slice(),
            relation
                .initiating_session_id()
                .into_uuid()
                .as_bytes()
                .as_slice(),
            relation
                .runtime_instance_id()
                .into_uuid()
                .as_bytes()
                .as_slice(),
            relation.created_at().get(),
        ],
    )?;
    Ok(())
}

fn decode(row: &Row<'_>) -> Result<ActivitySuccessor, ActivitySuccessorStoreError> {
    validate_exact_length("successor.workspace_id", row.get(0)?)?;
    validate_exact_length("successor.predecessor_activity_id", row.get(1)?)?;
    validate_exact_length("successor.successor_activity_id", row.get(2)?)?;
    validate_exact_length("successor.initiating_session_id", row.get(3)?)?;
    validate_exact_length("successor.runtime_instance_id", row.get(4)?)?;
    let raw = RawActivitySuccessor {
        workspace_id: row.get(5)?,
        predecessor_activity_id: row.get(6)?,
        predecessor_activity_revision: row.get(7)?,
        successor_activity_id: row.get(8)?,
        initiating_session_id: row.get(9)?,
        runtime_instance_id: row.get(10)?,
        created_at_ms: row.get(11)?,
    };
    let workspace_id =
        decode_uuid("successor.workspace_id", &raw.workspace_id).map(WorkspaceId::from_uuid)?;
    let predecessor_activity_id = decode_uuid(
        "successor.predecessor_activity_id",
        &raw.predecessor_activity_id,
    )
    .map(ActivityId::from_uuid)?;
    let successor_activity_id = decode_uuid(
        "successor.successor_activity_id",
        &raw.successor_activity_id,
    )
    .map(ActivityId::from_uuid)?;
    let initiating_session_id = decode_uuid(
        "successor.initiating_session_id",
        &raw.initiating_session_id,
    )
    .map(AgentSessionId::from_uuid)?;
    let runtime_instance_id =
        decode_uuid("successor.runtime_instance_id", &raw.runtime_instance_id)
            .map(RuntimeInstanceId::from_uuid)?;
    let predecessor_activity_revision = ActivityRevision::new(raw.predecessor_activity_revision)
        .map_err(|_| {
            ActivitySuccessorStoreError::CorruptRecord("successor.predecessor_activity_revision")
        })?;
    let created_at = TimestampMillis::new(raw.created_at_ms)
        .map_err(|_| ActivitySuccessorStoreError::CorruptRecord("successor.created_at_ms"))?;
    ActivitySuccessor::from_parts(
        workspace_id,
        predecessor_activity_id,
        predecessor_activity_revision,
        successor_activity_id,
        initiating_session_id,
        runtime_instance_id,
        created_at,
    )
    .map_err(ActivitySuccessorStoreError::Domain)
}

fn validate_exact_length(
    field: &'static str,
    length: i64,
) -> Result<(), ActivitySuccessorStoreError> {
    if length != ID_BYTES_I64 {
        return Err(ActivitySuccessorStoreError::PersistedFieldLengthInvalid {
            field,
            actual: usize::try_from(length).unwrap_or(usize::MAX),
            expected: ID_BYTES,
        });
    }
    Ok(())
}

fn decode_uuid(field: &'static str, bytes: &[u8]) -> Result<Uuid, ActivitySuccessorStoreError> {
    Uuid::from_slice(bytes).map_err(|_| ActivitySuccessorStoreError::CorruptRecord(field))
}

fn schema_sql_matches(actual: &str, expected: &str) -> bool {
    actual
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .map(|byte| byte.to_ascii_lowercase())
        .eq(expected
            .bytes()
            .filter(|byte| !byte.is_ascii_whitespace())
            .map(|byte| byte.to_ascii_lowercase()))
}

#[derive(Debug, Error)]
pub enum ActivitySuccessorStoreError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Domain(#[from] ActivitySuccessorError),
    #[error("Activity successor schema object is damaged: {0}")]
    DamagedSchema(&'static str),
    #[error("Activity successor schema metadata exceeded its bound")]
    SchemaMetadataTooLarge,
    #[error("Activity successor schema SQL is {actual} bytes; maximum is {maximum}")]
    SchemaSqlTooLarge { actual: usize, maximum: usize },
    #[error(
        "persisted Activity successor field {field} has {actual} bytes; expected exactly {expected}"
    )]
    PersistedFieldLengthInvalid {
        field: &'static str,
        actual: usize,
        expected: usize,
    },
    #[error("corrupt Activity successor persistence field {0}")]
    CorruptRecord(&'static str),
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn parent_schema(connection: &Connection) -> Result<(), rusqlite::Error> {
        connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE workspace (
                 workspace_id BLOB PRIMARY KEY
             );
             CREATE TABLE activities (
                 activity_id BLOB PRIMARY KEY,
                 workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id)
             );",
        )
    }

    #[test]
    fn fresh_schema_round_trip_and_corrupt_shape_fail_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let connection = Connection::open_in_memory()?;
        parent_schema(&connection)?;
        create_schema(&connection)?;
        validate_schema(&connection)?;
        let object_count: i64 = connection.query_row(
            "SELECT COUNT(*) FROM sqlite_schema
             WHERE type = 'table' AND name = 'activity_successors'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(object_count, 1);

        connection.execute_batch(
            "DROP TABLE activity_successors;
             CREATE TABLE activity_successors (
                 workspace_id BLOB,
                 predecessor_activity_id BLOB PRIMARY KEY,
                 predecessor_activity_revision INTEGER,
                 successor_activity_id BLOB UNIQUE,
                 initiating_session_id BLOB,
                 runtime_instance_id BLOB,
                 created_at_ms INTEGER
             );",
        )?;
        assert!(matches!(
            validate_schema(&connection),
            Err(ActivitySuccessorStoreError::DamagedSchema(_))
        ));
        Ok(())
    }

    #[test]
    fn oversized_schema_sql_is_rejected_before_shape_decode()
    -> Result<(), Box<dyn std::error::Error>> {
        let connection = Connection::open_in_memory()?;
        parent_schema(&connection)?;
        let columns = (0..1_200)
            .map(|index| format!("column_{index} INTEGER"))
            .collect::<Vec<_>>()
            .join(", ");
        connection.execute_batch(&format!("CREATE TABLE activity_successors ({columns});"))?;
        assert!(matches!(
            validate_schema(&connection),
            Err(ActivitySuccessorStoreError::SchemaSqlTooLarge { .. })
        ));
        Ok(())
    }
}
