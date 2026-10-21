use forge_domain::{ChangeSetId, SourceTreeRequestDigest};
use rusqlite::{Connection, OptionalExtension, params};
use thiserror::Error;

pub(crate) const EXPECTED_SOURCE_TREE_REQUESTS_TABLE_SQL: &str = "CREATE TABLE source_tree_requests (changeset_id BLOB PRIMARY KEY NOT NULL REFERENCES change_sets(changeset_id) CHECK(length(changeset_id) = 16), request_digest BLOB NOT NULL CHECK(length(request_digest) = 32))";

pub(crate) fn create_schema(connection: &Connection) -> Result<(), SourceTreeRequestStoreError> {
    connection.execute_batch(EXPECTED_SOURCE_TREE_REQUESTS_TABLE_SQL)?;
    Ok(())
}

pub(crate) fn schema_objects() -> [(&'static str, &'static str); 1] {
    [("table", "source_tree_requests")]
}

pub(crate) fn validate_schema(connection: &Connection) -> Result<(), SourceTreeRequestStoreError> {
    let actual: Option<String> = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = 'source_tree_requests'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if actual.as_deref().map(normalize_sql)
        != Some(normalize_sql(EXPECTED_SOURCE_TREE_REQUESTS_TABLE_SQL))
    {
        return Err(SourceTreeRequestStoreError::DamagedSchema);
    }

    let mut statement = connection.prepare("PRAGMA table_info(source_tree_requests)")?;
    let columns = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(5)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let expected = [
        ("changeset_id", "BLOB", 1_i64, 1_i64),
        ("request_digest", "BLOB", 1_i64, 0_i64),
    ];
    if columns.len() != expected.len()
        || !columns.iter().zip(expected).all(
            |((name, data_type, not_null, primary_key), expected)| {
                name == expected.0
                    && data_type == expected.1
                    && *not_null == expected.2
                    && *primary_key == expected.3
            },
        )
    {
        return Err(SourceTreeRequestStoreError::DamagedSchema);
    }
    Ok(())
}

pub(crate) fn insert(
    connection: &Connection,
    change_set_id: ChangeSetId,
    request_digest: SourceTreeRequestDigest,
) -> Result<(), SourceTreeRequestStoreError> {
    let change_set_id = change_set_id.into_uuid().into_bytes();
    connection.execute(
        "INSERT INTO source_tree_requests (changeset_id, request_digest) VALUES (?1, ?2)",
        params![
            change_set_id.as_slice(),
            request_digest.as_bytes().as_slice()
        ],
    )?;
    Ok(())
}

pub(crate) fn get(
    connection: &Connection,
    change_set_id: ChangeSetId,
) -> Result<Option<SourceTreeRequestDigest>, SourceTreeRequestStoreError> {
    let change_set_id = change_set_id.into_uuid().into_bytes();
    let bytes = connection
        .query_row(
            "SELECT request_digest FROM source_tree_requests WHERE changeset_id = ?1",
            params![change_set_id.as_slice()],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?;
    bytes.map(decode_digest).transpose()
}

fn decode_digest(bytes: Vec<u8>) -> Result<SourceTreeRequestDigest, SourceTreeRequestStoreError> {
    let bytes: [u8; SourceTreeRequestDigest::BYTE_LEN] = bytes
        .try_into()
        .map_err(|_| SourceTreeRequestStoreError::CorruptDigest)?;
    Ok(SourceTreeRequestDigest::from_bytes(bytes))
}

fn normalize_sql(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

#[derive(Debug, Error)]
pub(crate) enum SourceTreeRequestStoreError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error("source-tree request schema is damaged")]
    DamagedSchema,
    #[error("source-tree request digest is corrupt")]
    CorruptDigest,
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn schema_round_trips_request_digest() -> Result<(), Box<dyn std::error::Error>> {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE change_sets (changeset_id BLOB PRIMARY KEY NOT NULL CHECK(length(changeset_id) = 16));",
        )?;
        create_schema(&connection)?;
        validate_schema(&connection)?;

        let change_set_id = ChangeSetId::from_uuid(Uuid::from_u128(1));
        connection.execute(
            "INSERT INTO change_sets (changeset_id) VALUES (?1)",
            params![change_set_id.into_uuid().into_bytes().as_slice()],
        )?;
        let digest = SourceTreeRequestDigest::from_bytes([7; SourceTreeRequestDigest::BYTE_LEN]);
        insert(&connection, change_set_id, digest)?;
        assert_eq!(get(&connection, change_set_id)?, Some(digest));
        Ok(())
    }
}
