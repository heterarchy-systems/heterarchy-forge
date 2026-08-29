//! Durable applied Harness state for one Workspace.
//!
//! The app-global Harness Catalog is a separate authority. This table stores a
//! snapshot of the exact Bundle identity/version/hash applied to this Workspace
//! so later catalog edits cannot rewrite historical Workspace truth.

use forge_domain::{
    AppliedHarness, AppliedHarnessError, HarnessBundleDescriptor, HarnessBundleError,
    HarnessBundleId, HarnessContentHash, HarnessName, HarnessNameError, HarnessRevision,
    HarnessRevisionError, HarnessVerificationState, HarnessVersion, HarnessVersionError,
    TimestampMillis, TimestampMillisError, WorkspaceId,
};
use rusqlite::{Connection, OptionalExtension, Row, Transaction, TransactionBehavior, params};
use thiserror::Error;
use uuid::Uuid;

const ID_BYTES: usize = 16;
const HASH_BYTES: usize = HarnessContentHash::BYTE_LEN;
const MAX_NAME_BYTES: usize = forge_domain::MAX_HARNESS_NAME_BYTES;
const MAX_VERSION_BYTES: usize = forge_domain::MAX_HARNESS_VERSION_BYTES;

pub(crate) const EXPECTED_WORKSPACE_HARNESS_TABLE_SQL: &str = "CREATE TABLE workspace_harness (workspace_id BLOB PRIMARY KEY NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16), bundle_id BLOB NOT NULL CHECK(length(bundle_id) = 16), bundle_name TEXT NOT NULL CHECK(length(CAST(bundle_name AS BLOB)) BETWEEN 1 AND 128), bundle_version TEXT NOT NULL CHECK(length(CAST(bundle_version AS BLOB)) BETWEEN 1 AND 64), content_hash BLOB NOT NULL CHECK(length(content_hash) = 32), managed_file_count INTEGER NOT NULL CHECK(managed_file_count BETWEEN 1 AND 256), skill_count INTEGER NOT NULL CHECK(skill_count BETWEEN 0 AND 64), verifier_count INTEGER NOT NULL CHECK(verifier_count BETWEEN 0 AND 32), verification_state INTEGER NOT NULL CHECK(verification_state IN (0, 1, 2)), applied_at_ms INTEGER NOT NULL CHECK(applied_at_ms >= 0), verified_at_ms INTEGER CHECK(verified_at_ms IS NULL OR verified_at_ms >= 0), revision INTEGER NOT NULL CHECK(revision >= 1), CHECK((verification_state = 0 AND verified_at_ms IS NULL) OR (verification_state IN (1, 2) AND verified_at_ms IS NOT NULL)), CHECK(verified_at_ms IS NULL OR verified_at_ms >= applied_at_ms))";

const EXPECTED_COLUMNS: [(&str, &str, i64, i64); 12] = [
    ("workspace_id", "BLOB", 1, 1),
    ("bundle_id", "BLOB", 1, 0),
    ("bundle_name", "TEXT", 1, 0),
    ("bundle_version", "TEXT", 1, 0),
    ("content_hash", "BLOB", 1, 0),
    ("managed_file_count", "INTEGER", 1, 0),
    ("skill_count", "INTEGER", 1, 0),
    ("verifier_count", "INTEGER", 1, 0),
    ("verification_state", "INTEGER", 1, 0),
    ("applied_at_ms", "INTEGER", 1, 0),
    ("verified_at_ms", "INTEGER", 0, 0),
    ("revision", "INTEGER", 1, 0),
];

#[derive(Debug, Error)]
pub enum HarnessStoreError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error("applied Harness compare-and-set found a changed row")]
    CompareAndSwapConflict,
    #[error("applied Harness Workspace mismatch: expected {expected}, actual {actual}")]
    WorkspaceMismatch {
        expected: WorkspaceId,
        actual: WorkspaceId,
    },
    #[error("applied Harness schema is damaged: {0}")]
    DamagedSchema(&'static str),
    #[error("applied Harness field {field} has invalid length {actual}; expected {expected}")]
    InvalidFieldLength {
        field: &'static str,
        actual: usize,
        expected: usize,
    },
    #[error("applied Harness field {field} has invalid value {actual}")]
    InvalidFieldValue { field: &'static str, actual: i64 },
    #[error("applied Harness field {field} exceeds {maximum} bytes")]
    FieldTooLarge { field: &'static str, maximum: usize },
    #[error("applied Harness name is invalid")]
    Name(#[source] HarnessNameError),
    #[error("applied Harness version is invalid")]
    Version(#[source] HarnessVersionError),
    #[error("applied Harness revision is invalid")]
    Revision(#[source] HarnessRevisionError),
    #[error("applied Harness timestamp is invalid")]
    Timestamp(#[source] TimestampMillisError),
    #[error("applied Harness Bundle metadata is invalid")]
    Bundle(#[source] HarnessBundleError),
    #[error("applied Harness state is invalid")]
    Applied(#[source] AppliedHarnessError),
}

pub(crate) fn create_schema(connection: &Connection) -> Result<(), HarnessStoreError> {
    connection.execute_batch(EXPECTED_WORKSPACE_HARNESS_TABLE_SQL)?;
    Ok(())
}

pub(crate) fn migrate_v12_to_v13(
    connection: &mut Connection,
    next_schema_version: i64,
) -> Result<(), HarnessStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    create_schema(&transaction)?;
    transaction.pragma_update(None, "user_version", next_schema_version)?;
    transaction.commit()?;
    Ok(())
}

pub(crate) fn schema_objects() -> [(&'static str, &'static str); 1] {
    [("table", "workspace_harness")]
}

pub(crate) fn validate_schema(connection: &Connection) -> Result<(), HarnessStoreError> {
    let actual: Option<String> = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = 'workspace_harness'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if actual.as_deref().map(normalize_sql)
        != Some(normalize_sql(EXPECTED_WORKSPACE_HARNESS_TABLE_SQL))
    {
        return Err(HarnessStoreError::DamagedSchema(
            "workspace_harness SQL definition does not match the expected policy",
        ));
    }
    validate_columns(connection)?;
    validate_foreign_key(connection)
}

fn validate_columns(connection: &Connection) -> Result<(), HarnessStoreError> {
    let mut statement = connection.prepare("PRAGMA table_info(workspace_harness)")?;
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
    let matches = columns.len() == EXPECTED_COLUMNS.len()
        && columns.iter().zip(EXPECTED_COLUMNS).all(
            |((name, data_type, not_null, primary_key), expected)| {
                name == expected.0
                    && data_type == expected.1
                    && *not_null == expected.2
                    && *primary_key == expected.3
            },
        );
    if matches {
        Ok(())
    } else {
        Err(HarnessStoreError::DamagedSchema(
            "workspace_harness columns do not match the expected shape",
        ))
    }
}

fn validate_foreign_key(connection: &Connection) -> Result<(), HarnessStoreError> {
    let mut statement = connection.prepare("PRAGMA foreign_key_list(workspace_harness)")?;
    let foreign_keys = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let expected = (
        "workspace".to_owned(),
        "workspace_id".to_owned(),
        "workspace_id".to_owned(),
        "NO ACTION".to_owned(),
        "NO ACTION".to_owned(),
        "NONE".to_owned(),
    );
    if foreign_keys.as_slice() == [expected] {
        Ok(())
    } else {
        Err(HarnessStoreError::DamagedSchema(
            "workspace_harness foreign key does not match Workspace authority",
        ))
    }
}

pub(crate) fn get(
    connection: &Connection,
    workspace_id: WorkspaceId,
) -> Result<Option<AppliedHarness>, HarnessStoreError> {
    connection
        .query_row(
            "SELECT length(workspace_id), workspace_id,
                    length(bundle_id), bundle_id,
                    length(CAST(bundle_name AS BLOB)), bundle_name,
                    length(CAST(bundle_version AS BLOB)), bundle_version,
                    length(content_hash), content_hash,
                    managed_file_count, skill_count, verifier_count,
                    verification_state, applied_at_ms, verified_at_ms, revision
             FROM workspace_harness WHERE workspace_id = ?1",
            params![workspace_id.into_uuid().as_bytes()],
            decode_row,
        )
        .optional()
        .map_err(HarnessStoreError::from)
}

pub(crate) fn persist(
    transaction: &Transaction<'_>,
    applied: &AppliedHarness,
    expected_revision: Option<HarnessRevision>,
) -> Result<AppliedHarness, HarnessStoreError> {
    ensure_workspace_matches(transaction, applied.workspace_id())?;
    let changed = match expected_revision {
        None => insert(transaction, applied)?,
        Some(expected) => update(transaction, applied, expected)?,
    };
    if changed == 1 {
        return get(transaction, applied.workspace_id())?
            .ok_or(HarnessStoreError::CompareAndSwapConflict);
    }
    match get(transaction, applied.workspace_id())? {
        Some(existing) if existing == *applied => Ok(existing),
        _ => Err(HarnessStoreError::CompareAndSwapConflict),
    }
}

pub(crate) fn delete(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
    expected_revision: HarnessRevision,
) -> Result<(), HarnessStoreError> {
    ensure_workspace_matches(transaction, workspace_id)?;
    let changed = transaction.execute(
        "DELETE FROM workspace_harness WHERE workspace_id = ?1 AND revision = ?2",
        params![workspace_id.into_uuid().as_bytes(), expected_revision.get(),],
    )?;
    if changed == 1 {
        Ok(())
    } else {
        Err(HarnessStoreError::CompareAndSwapConflict)
    }
}

fn ensure_workspace_matches(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
) -> Result<(), HarnessStoreError> {
    let persisted: Vec<u8> = transaction.query_row(
        "SELECT workspace_id FROM workspace WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    let persisted = WorkspaceId::from_uuid(decode_uuid("workspace.workspace_id", &persisted)?);
    if persisted == workspace_id {
        Ok(())
    } else {
        Err(HarnessStoreError::WorkspaceMismatch {
            expected: persisted,
            actual: workspace_id,
        })
    }
}

fn insert(
    transaction: &Transaction<'_>,
    applied: &AppliedHarness,
) -> Result<usize, HarnessStoreError> {
    let bundle = applied.bundle();
    transaction
        .execute(
            "INSERT INTO workspace_harness (
                workspace_id, bundle_id, bundle_name, bundle_version, content_hash,
                managed_file_count, skill_count, verifier_count, verification_state,
                applied_at_ms, verified_at_ms, revision
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
             ON CONFLICT(workspace_id) DO NOTHING",
            params![
                applied.workspace_id().into_uuid().as_bytes(),
                bundle.id().into_uuid().as_bytes(),
                bundle.name().as_str(),
                bundle.version().as_str(),
                bundle.content_hash().as_bytes().as_slice(),
                i64::from(bundle.managed_file_count()),
                i64::from(bundle.skill_count()),
                i64::from(bundle.verifier_count()),
                encode_state(applied.state()),
                applied.applied_at().get(),
                applied.verified_at().map(TimestampMillis::get),
                applied.revision().get(),
            ],
        )
        .map_err(HarnessStoreError::from)
}

fn update(
    transaction: &Transaction<'_>,
    applied: &AppliedHarness,
    expected_revision: HarnessRevision,
) -> Result<usize, HarnessStoreError> {
    let bundle = applied.bundle();
    transaction
        .execute(
            "UPDATE workspace_harness
             SET bundle_id = ?2, bundle_name = ?3, bundle_version = ?4, content_hash = ?5,
                 managed_file_count = ?6, skill_count = ?7, verifier_count = ?8,
                 verification_state = ?9, applied_at_ms = ?10, verified_at_ms = ?11,
                 revision = ?12
             WHERE workspace_id = ?1 AND revision = ?13",
            params![
                applied.workspace_id().into_uuid().as_bytes(),
                bundle.id().into_uuid().as_bytes(),
                bundle.name().as_str(),
                bundle.version().as_str(),
                bundle.content_hash().as_bytes().as_slice(),
                i64::from(bundle.managed_file_count()),
                i64::from(bundle.skill_count()),
                i64::from(bundle.verifier_count()),
                encode_state(applied.state()),
                applied.applied_at().get(),
                applied.verified_at().map(TimestampMillis::get),
                applied.revision().get(),
                expected_revision.get(),
            ],
        )
        .map_err(HarnessStoreError::from)
}

#[derive(Debug)]
struct RawAppliedHarness {
    workspace_id: Vec<u8>,
    bundle_id: Vec<u8>,
    bundle_name: String,
    bundle_version: String,
    content_hash: Vec<u8>,
    managed_file_count: i64,
    skill_count: i64,
    verifier_count: i64,
    verification_state: i64,
    applied_at: i64,
    verified_at: Option<i64>,
    revision: i64,
}

fn decode_row(row: &Row<'_>) -> rusqlite::Result<AppliedHarness> {
    let result = decode_checked_row(row);
    result.map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Blob, Box::new(error))
    })
}

fn decode_checked_row(row: &Row<'_>) -> Result<AppliedHarness, HarnessStoreError> {
    validate_exact_length("workspace_id", row.get(0)?, ID_BYTES)?;
    validate_exact_length("bundle_id", row.get(2)?, ID_BYTES)?;
    validate_max_length("bundle_name", row.get(4)?, MAX_NAME_BYTES)?;
    validate_max_length("bundle_version", row.get(6)?, MAX_VERSION_BYTES)?;
    validate_exact_length("content_hash", row.get(8)?, HASH_BYTES)?;
    decode_raw(RawAppliedHarness {
        workspace_id: row.get(1)?,
        bundle_id: row.get(3)?,
        bundle_name: row.get(5)?,
        bundle_version: row.get(7)?,
        content_hash: row.get(9)?,
        managed_file_count: row.get(10)?,
        skill_count: row.get(11)?,
        verifier_count: row.get(12)?,
        verification_state: row.get(13)?,
        applied_at: row.get(14)?,
        verified_at: row.get(15)?,
        revision: row.get(16)?,
    })
}

fn decode_raw(raw: RawAppliedHarness) -> Result<AppliedHarness, HarnessStoreError> {
    let bundle = HarnessBundleDescriptor::new(
        HarnessBundleId::from_uuid(decode_uuid("bundle_id", &raw.bundle_id)?),
        HarnessName::new(raw.bundle_name).map_err(HarnessStoreError::Name)?,
        HarnessVersion::new(raw.bundle_version).map_err(HarnessStoreError::Version)?,
        decode_hash(&raw.content_hash)?,
        decode_count("managed_file_count", raw.managed_file_count)?,
        decode_count("skill_count", raw.skill_count)?,
        decode_count("verifier_count", raw.verifier_count)?,
    )
    .map_err(HarnessStoreError::Bundle)?;
    AppliedHarness::from_parts(
        WorkspaceId::from_uuid(decode_uuid("workspace_id", &raw.workspace_id)?),
        bundle,
        decode_state(raw.verification_state)?,
        TimestampMillis::new(raw.applied_at).map_err(HarnessStoreError::Timestamp)?,
        raw.verified_at
            .map(TimestampMillis::new)
            .transpose()
            .map_err(HarnessStoreError::Timestamp)?,
        HarnessRevision::new(raw.revision).map_err(HarnessStoreError::Revision)?,
    )
    .map_err(HarnessStoreError::Applied)
}

fn decode_count(field: &'static str, value: i64) -> Result<u16, HarnessStoreError> {
    u16::try_from(value).map_err(|_| HarnessStoreError::InvalidFieldValue {
        field,
        actual: value,
    })
}

fn encode_state(state: HarnessVerificationState) -> i64 {
    match state {
        HarnessVerificationState::Applied => 0,
        HarnessVerificationState::Ready => 1,
        HarnessVerificationState::Failed => 2,
    }
}

fn decode_state(value: i64) -> Result<HarnessVerificationState, HarnessStoreError> {
    match value {
        0 => Ok(HarnessVerificationState::Applied),
        1 => Ok(HarnessVerificationState::Ready),
        2 => Ok(HarnessVerificationState::Failed),
        actual => Err(HarnessStoreError::InvalidFieldValue {
            field: "verification_state",
            actual,
        }),
    }
}

fn validate_exact_length(
    field: &'static str,
    length: i64,
    expected: usize,
) -> Result<(), HarnessStoreError> {
    if length == i64::try_from(expected).unwrap_or(i64::MAX) {
        Ok(())
    } else {
        Err(HarnessStoreError::InvalidFieldLength {
            field,
            actual: usize::try_from(length).unwrap_or(usize::MAX),
            expected,
        })
    }
}

fn validate_max_length(
    field: &'static str,
    length: i64,
    maximum: usize,
) -> Result<(), HarnessStoreError> {
    if length >= 1 && usize::try_from(length).is_ok_and(|value| value <= maximum) {
        Ok(())
    } else {
        Err(HarnessStoreError::FieldTooLarge { field, maximum })
    }
}

fn decode_uuid(field: &'static str, value: &[u8]) -> Result<Uuid, HarnessStoreError> {
    if value.len() != ID_BYTES {
        return Err(HarnessStoreError::InvalidFieldLength {
            field,
            actual: value.len(),
            expected: ID_BYTES,
        });
    }
    Uuid::from_slice(value).map_err(|_| HarnessStoreError::InvalidFieldLength {
        field,
        actual: value.len(),
        expected: ID_BYTES,
    })
}

fn decode_hash(value: &[u8]) -> Result<HarnessContentHash, HarnessStoreError> {
    let bytes: [u8; HASH_BYTES] =
        value
            .try_into()
            .map_err(|_| HarnessStoreError::InvalidFieldLength {
                field: "content_hash",
                actual: value.len(),
                expected: HASH_BYTES,
            })?;
    Ok(HarnessContentHash::from_bytes(bytes))
}

fn normalize_sql(value: &str) -> String {
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .replace("( ", "(")
        .replace(" )", ")")
        .replace(" ,", ",")
}

#[cfg(test)]
mod tests {
    use super::*;
    use forge_domain::{HarnessVerificationOutcome, HarnessVerificationState};

    fn descriptor(fill: u8) -> Result<HarnessBundleDescriptor, Box<dyn std::error::Error>> {
        Ok(HarnessBundleDescriptor::new(
            HarnessBundleId::from_uuid(Uuid::from_u128(0x4100 + u128::from(fill))),
            HarnessName::new("Rust Dev Harness".to_owned())?,
            HarnessVersion::new("3.0.0".to_owned())?,
            HarnessContentHash::from_bytes([fill; HASH_BYTES]),
            12,
            1,
            3,
        )?)
    }

    fn connection() -> Result<Connection, Box<dyn std::error::Error>> {
        let connection = Connection::open_in_memory()?;
        connection.pragma_update(None, "foreign_keys", true)?;
        connection.execute_batch(
            "CREATE TABLE workspace (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                workspace_id BLOB NOT NULL UNIQUE CHECK(length(workspace_id) = 16)
             );",
        )?;
        create_schema(&connection)?;
        Ok(connection)
    }

    fn insert_workspace(connection: &Connection, id: WorkspaceId) -> rusqlite::Result<()> {
        connection.execute(
            "INSERT INTO workspace(singleton, workspace_id) VALUES (1, ?1)",
            params![id.into_uuid().as_bytes()],
        )?;
        Ok(())
    }

    #[test]
    fn schema_and_applied_ready_state_round_trip_with_cas() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut connection = connection()?;
        validate_schema(&connection)?;
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(0x4101));
        insert_workspace(&connection, workspace_id)?;
        let applied =
            AppliedHarness::applied(workspace_id, descriptor(1)?, TimestampMillis::new(10)?);
        let transaction = connection.transaction()?;
        let stored = persist(&transaction, &applied, None)?;
        transaction.commit()?;
        assert_eq!(stored, applied);
        let ready = stored.record_verification(
            HarnessVerificationOutcome::Ready,
            stored.revision(),
            TimestampMillis::new(11)?,
        )?;
        let transaction = connection.transaction()?;
        let stored_ready = persist(&transaction, &ready, Some(stored.revision()))?;
        transaction.commit()?;
        assert_eq!(stored_ready.state(), HarnessVerificationState::Ready);
        assert_eq!(get(&connection, workspace_id)?, Some(ready));
        Ok(())
    }

    #[test]
    fn applied_harness_delete_requires_exact_revision_cas() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut connection = connection()?;
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(0x4110));
        insert_workspace(&connection, workspace_id)?;
        let applied =
            AppliedHarness::applied(workspace_id, descriptor(2)?, TimestampMillis::new(20)?);
        let transaction = connection.transaction()?;
        let stored = persist(&transaction, &applied, None)?;
        transaction.commit()?;

        let stale_revision = HarnessRevision::new(stored.revision().get() + 1)?;
        let transaction = connection.transaction()?;
        assert!(matches!(
            delete(&transaction, workspace_id, stale_revision),
            Err(HarnessStoreError::CompareAndSwapConflict)
        ));
        transaction.rollback()?;
        assert_eq!(get(&connection, workspace_id)?, Some(stored.clone()));

        let transaction = connection.transaction()?;
        delete(&transaction, workspace_id, stored.revision())?;
        transaction.commit()?;
        assert_eq!(get(&connection, workspace_id)?, None);
        Ok(())
    }

    #[test]
    fn v12_to_v13_migration_adds_empty_harness_authority() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut connection = Connection::open_in_memory()?;
        connection.pragma_update(None, "foreign_keys", true)?;
        connection.execute_batch(
            "CREATE TABLE workspace (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                workspace_id BLOB NOT NULL UNIQUE CHECK(length(workspace_id) = 16)
             );",
        )?;
        connection.pragma_update(None, "user_version", 12_i64)?;
        migrate_v12_to_v13(&mut connection, 13)?;
        assert_eq!(
            connection.pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))?,
            13
        );
        validate_schema(&connection)?;
        let count: i64 =
            connection.query_row("SELECT COUNT(*) FROM workspace_harness", [], |row| {
                row.get(0)
            })?;
        assert_eq!(count, 0);
        Ok(())
    }
}
