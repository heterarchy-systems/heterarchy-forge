//! Durable snapshots for Harness declared-verifier runs.
//!
//! A run snapshots Bundle identity plus caller-reserved approval/execution IDs.
//! Approval/execution records may not exist yet when the run is first written,
//! so those IDs are durable correlation values rather than foreign keys. This
//! permits restart-safe resubmission with the exact same identities.

use forge_domain::{
    ActivityId, ApprovalRequestId, ExecutionId, ExecutionRequestDigest, HarnessBundleId,
    HarnessContentHash, HarnessVerifierDomainError, HarnessVerifierItem, HarnessVerifierItemState,
    HarnessVerifierName, HarnessVerifierNameError, HarnessVerifierRun,
    HarnessVerifierRunAttribution, HarnessVerifierRunId, HarnessVerifierRunRevision,
    HarnessVerifierRunRevisionError, HarnessVerifierRunState, HarnessVerifierRunTimestamps,
    RuntimeInstanceId, TimestampMillis, TimestampMillisError, WorkspaceId,
};
use rusqlite::{Connection, OptionalExtension, Row, Transaction, TransactionBehavior, params};
use thiserror::Error;
use uuid::Uuid;

const ID_BYTES: usize = 16;
const HASH_BYTES: usize = HarnessContentHash::BYTE_LEN;
const REQUEST_DIGEST_BYTES: usize = ExecutionRequestDigest::BYTE_LEN;
const MAX_NAME_BYTES: usize = forge_domain::MAX_HARNESS_VERIFIER_NAME_BYTES;

pub(crate) const EXPECTED_HARNESS_VERIFIER_RUNS_TABLE_SQL: &str = "CREATE TABLE workspace_harness_verifier_runs (run_id BLOB PRIMARY KEY NOT NULL CHECK(length(run_id) = 16), workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16), bundle_id BLOB NOT NULL CHECK(length(bundle_id) = 16), content_hash BLOB NOT NULL CHECK(length(content_hash) = 32), activity_id BLOB NOT NULL CHECK(length(activity_id) = 16), runtime_instance_id BLOB NOT NULL CHECK(length(runtime_instance_id) = 16), state INTEGER NOT NULL CHECK(state IN (0, 1, 2, 3)), started_at_ms INTEGER NOT NULL CHECK(started_at_ms >= 0), completed_at_ms INTEGER CHECK(completed_at_ms IS NULL OR completed_at_ms >= started_at_ms), revision INTEGER NOT NULL CHECK(revision >= 1), CHECK((state IN (0, 1) AND completed_at_ms IS NULL) OR (state IN (2, 3) AND completed_at_ms IS NOT NULL)))";
pub(crate) const EXPECTED_HARNESS_VERIFIER_ITEMS_TABLE_SQL: &str = "CREATE TABLE workspace_harness_verifier_items (run_id BLOB NOT NULL REFERENCES workspace_harness_verifier_runs(run_id) ON DELETE CASCADE CHECK(length(run_id) = 16), ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 0 AND 31), name TEXT NOT NULL CHECK(length(CAST(name AS BLOB)) BETWEEN 1 AND 128), approval_id BLOB NOT NULL CHECK(length(approval_id) = 16), execution_id BLOB NOT NULL CHECK(length(execution_id) = 16), request_digest BLOB NOT NULL CHECK(length(request_digest) = 32), state INTEGER NOT NULL CHECK(state IN (0, 1, 2, 3, 4)), exit_code INTEGER, duration_millis INTEGER CHECK(duration_millis IS NULL OR duration_millis >= 0), PRIMARY KEY(run_id, ordinal), UNIQUE(run_id, approval_id), UNIQUE(run_id, execution_id), CHECK((state IN (0, 1) AND exit_code IS NULL AND duration_millis IS NULL) OR state IN (2, 3) OR (state = 4 AND exit_code IS NULL AND duration_millis IS NULL)), CHECK(state != 2 OR exit_code = 0))";
pub(crate) const EXPECTED_HARNESS_VERIFIER_LATEST_INDEX_SQL: &str = "CREATE INDEX workspace_harness_verifier_runs_latest_idx ON workspace_harness_verifier_runs(workspace_id, started_at_ms DESC, run_id DESC)";

#[derive(Debug, Error)]
pub enum HarnessVerifierStoreError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error("Harness verifier run compare-and-set found a changed row")]
    CompareAndSwapConflict,
    #[error("Harness verifier run Workspace mismatch: expected {expected}, actual {actual}")]
    WorkspaceMismatch {
        expected: WorkspaceId,
        actual: WorkspaceId,
    },
    #[error("Harness verifier run schema is damaged: {0}")]
    DamagedSchema(&'static str),
    #[error("Harness verifier field {field} has invalid length {actual}; expected {expected}")]
    InvalidFieldLength {
        field: &'static str,
        actual: usize,
        expected: usize,
    },
    #[error("Harness verifier field {field} exceeds {maximum} bytes")]
    FieldTooLarge { field: &'static str, maximum: usize },
    #[error("Harness verifier field {field} has invalid value {actual}")]
    InvalidFieldValue { field: &'static str, actual: i64 },
    #[error("Harness verifier name is invalid")]
    Name(#[source] HarnessVerifierNameError),
    #[error("Harness verifier run revision is invalid")]
    Revision(#[source] HarnessVerifierRunRevisionError),
    #[error("Harness verifier timestamp is invalid")]
    Timestamp(#[source] TimestampMillisError),
    #[error("Harness verifier domain snapshot is invalid")]
    Domain(#[source] HarnessVerifierDomainError),
}

pub(crate) fn create_schema(connection: &Connection) -> Result<(), HarnessVerifierStoreError> {
    connection.execute_batch(EXPECTED_HARNESS_VERIFIER_RUNS_TABLE_SQL)?;
    connection.execute_batch(EXPECTED_HARNESS_VERIFIER_ITEMS_TABLE_SQL)?;
    connection.execute_batch(EXPECTED_HARNESS_VERIFIER_LATEST_INDEX_SQL)?;
    Ok(())
}

pub(crate) fn migrate_v13_to_v14(
    connection: &mut Connection,
    next_schema_version: i64,
) -> Result<(), HarnessVerifierStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    create_schema(&transaction)?;
    transaction.pragma_update(None, "user_version", next_schema_version)?;
    transaction.commit()?;
    Ok(())
}

pub(crate) fn schema_objects() -> [(&'static str, &'static str); 3] {
    [
        ("table", "workspace_harness_verifier_runs"),
        ("table", "workspace_harness_verifier_items"),
        ("index", "workspace_harness_verifier_runs_latest_idx"),
    ]
}

pub(crate) fn validate_schema(connection: &Connection) -> Result<(), HarnessVerifierStoreError> {
    validate_sql_object(
        connection,
        "table",
        "workspace_harness_verifier_runs",
        EXPECTED_HARNESS_VERIFIER_RUNS_TABLE_SQL,
    )?;
    validate_sql_object(
        connection,
        "table",
        "workspace_harness_verifier_items",
        EXPECTED_HARNESS_VERIFIER_ITEMS_TABLE_SQL,
    )?;
    validate_sql_object(
        connection,
        "index",
        "workspace_harness_verifier_runs_latest_idx",
        EXPECTED_HARNESS_VERIFIER_LATEST_INDEX_SQL,
    )?;
    validate_run_foreign_key(connection)?;
    validate_item_foreign_key(connection)
}

fn validate_sql_object(
    connection: &Connection,
    kind: &'static str,
    name: &'static str,
    expected: &'static str,
) -> Result<(), HarnessVerifierStoreError> {
    let actual: Option<String> = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type = ?1 AND name = ?2",
            params![kind, name],
            |row| row.get(0),
        )
        .optional()?;
    if actual.as_deref().map(normalize_sql) == Some(normalize_sql(expected)) {
        Ok(())
    } else {
        Err(HarnessVerifierStoreError::DamagedSchema(
            "Harness verifier SQL definition does not match expected policy",
        ))
    }
}

fn validate_run_foreign_key(connection: &Connection) -> Result<(), HarnessVerifierStoreError> {
    let actual = foreign_keys(connection, "workspace_harness_verifier_runs")?;
    let expected = vec![(
        "workspace".to_owned(),
        "workspace_id".to_owned(),
        "workspace_id".to_owned(),
        "NO ACTION".to_owned(),
        "NO ACTION".to_owned(),
        "NONE".to_owned(),
    )];
    if actual == expected {
        Ok(())
    } else {
        Err(HarnessVerifierStoreError::DamagedSchema(
            "Harness verifier run Workspace foreign key does not match authority",
        ))
    }
}

fn validate_item_foreign_key(connection: &Connection) -> Result<(), HarnessVerifierStoreError> {
    let actual = foreign_keys(connection, "workspace_harness_verifier_items")?;
    let expected = vec![(
        "workspace_harness_verifier_runs".to_owned(),
        "run_id".to_owned(),
        "run_id".to_owned(),
        "NO ACTION".to_owned(),
        "CASCADE".to_owned(),
        "NONE".to_owned(),
    )];
    if actual == expected {
        Ok(())
    } else {
        Err(HarnessVerifierStoreError::DamagedSchema(
            "Harness verifier item run foreign key does not match authority",
        ))
    }
}

type ForeignKey = (String, String, String, String, String, String);

fn foreign_keys(
    connection: &Connection,
    table: &'static str,
) -> Result<Vec<ForeignKey>, HarnessVerifierStoreError> {
    let sql = match table {
        "workspace_harness_verifier_runs" => {
            "PRAGMA foreign_key_list(workspace_harness_verifier_runs)"
        }
        "workspace_harness_verifier_items" => {
            "PRAGMA foreign_key_list(workspace_harness_verifier_items)"
        }
        _ => {
            return Err(HarnessVerifierStoreError::DamagedSchema(
                "unknown verifier table",
            ));
        }
    };
    let mut statement = connection.prepare(sql)?;
    statement
        .query_map([], |row| {
            Ok((
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get(7)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(HarnessVerifierStoreError::from)
}

pub(crate) fn get(
    connection: &Connection,
    run_id: HarnessVerifierRunId,
) -> Result<Option<HarnessVerifierRun>, HarnessVerifierStoreError> {
    let raw = connection
        .query_row(
            "SELECT length(run_id), run_id, length(workspace_id), workspace_id,
                    length(bundle_id), bundle_id, length(content_hash), content_hash,
                    length(activity_id), activity_id,
                    length(runtime_instance_id), runtime_instance_id,
                    state, started_at_ms, completed_at_ms, revision
             FROM workspace_harness_verifier_runs WHERE run_id = ?1",
            params![run_id.into_uuid().as_bytes()],
            decode_raw_run_row,
        )
        .optional()?;
    raw.as_ref()
        .map(|raw| decode_run(connection, raw))
        .transpose()
}

pub(crate) fn latest(
    connection: &Connection,
    workspace_id: WorkspaceId,
) -> Result<Option<HarnessVerifierRun>, HarnessVerifierStoreError> {
    let raw = connection
        .query_row(
            "SELECT length(run_id), run_id, length(workspace_id), workspace_id,
                    length(bundle_id), bundle_id, length(content_hash), content_hash,
                    length(activity_id), activity_id,
                    length(runtime_instance_id), runtime_instance_id,
                    state, started_at_ms, completed_at_ms, revision
             FROM workspace_harness_verifier_runs
             WHERE workspace_id = ?1
             ORDER BY started_at_ms DESC, run_id DESC LIMIT 1",
            params![workspace_id.into_uuid().as_bytes()],
            decode_raw_run_row,
        )
        .optional()?;
    raw.as_ref()
        .map(|raw| decode_run(connection, raw))
        .transpose()
}

pub(crate) fn persist(
    transaction: &Transaction<'_>,
    run: &HarnessVerifierRun,
    expected_revision: Option<HarnessVerifierRunRevision>,
) -> Result<HarnessVerifierRun, HarnessVerifierStoreError> {
    ensure_workspace_matches(transaction, run.workspace_id())?;
    let changed = match expected_revision {
        None => insert_run(transaction, run)?,
        Some(expected) => update_run(transaction, run, expected)?,
    };
    if changed == 1 {
        if expected_revision.is_some() {
            transaction.execute(
                "DELETE FROM workspace_harness_verifier_items WHERE run_id = ?1",
                params![run.id().into_uuid().as_bytes()],
            )?;
        }
        insert_items(transaction, run)?;
        return get(transaction, run.id())?
            .ok_or(HarnessVerifierStoreError::CompareAndSwapConflict);
    }
    match get(transaction, run.id())? {
        Some(existing) if existing == *run => Ok(existing),
        _ => Err(HarnessVerifierStoreError::CompareAndSwapConflict),
    }
}

fn insert_run(
    transaction: &Transaction<'_>,
    run: &HarnessVerifierRun,
) -> Result<usize, HarnessVerifierStoreError> {
    transaction
        .execute(
            "INSERT INTO workspace_harness_verifier_runs (
                run_id, workspace_id, bundle_id, content_hash, activity_id,
                runtime_instance_id, state, started_at_ms, completed_at_ms, revision
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(run_id) DO NOTHING",
            params![
                run.id().into_uuid().as_bytes(),
                run.workspace_id().into_uuid().as_bytes(),
                run.bundle_id().into_uuid().as_bytes(),
                run.content_hash().as_bytes().as_slice(),
                run.activity_id().into_uuid().as_bytes(),
                run.runtime_instance_id().into_uuid().as_bytes(),
                encode_run_state(run.state()),
                run.started_at().get(),
                run.completed_at().map(TimestampMillis::get),
                run.revision().get(),
            ],
        )
        .map_err(HarnessVerifierStoreError::from)
}

fn update_run(
    transaction: &Transaction<'_>,
    run: &HarnessVerifierRun,
    expected_revision: HarnessVerifierRunRevision,
) -> Result<usize, HarnessVerifierStoreError> {
    transaction
        .execute(
            "UPDATE workspace_harness_verifier_runs
             SET state = ?2, completed_at_ms = ?3, revision = ?4
             WHERE run_id = ?1 AND workspace_id = ?5 AND bundle_id = ?6
               AND content_hash = ?7 AND activity_id = ?8 AND runtime_instance_id = ?9
               AND started_at_ms = ?10 AND revision = ?11",
            params![
                run.id().into_uuid().as_bytes(),
                encode_run_state(run.state()),
                run.completed_at().map(TimestampMillis::get),
                run.revision().get(),
                run.workspace_id().into_uuid().as_bytes(),
                run.bundle_id().into_uuid().as_bytes(),
                run.content_hash().as_bytes().as_slice(),
                run.activity_id().into_uuid().as_bytes(),
                run.runtime_instance_id().into_uuid().as_bytes(),
                run.started_at().get(),
                expected_revision.get(),
            ],
        )
        .map_err(HarnessVerifierStoreError::from)
}

fn insert_items(
    transaction: &Transaction<'_>,
    run: &HarnessVerifierRun,
) -> Result<(), HarnessVerifierStoreError> {
    let mut statement = transaction.prepare(
        "INSERT INTO workspace_harness_verifier_items (
            run_id, ordinal, name, approval_id, execution_id, request_digest,
            state, exit_code, duration_millis
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
    )?;
    for item in run.items() {
        statement.execute(params![
            run.id().into_uuid().as_bytes(),
            i64::from(item.ordinal()),
            item.name().as_str(),
            item.approval_id().into_uuid().as_bytes(),
            item.execution_id().into_uuid().as_bytes(),
            item.request_digest().as_bytes().as_slice(),
            encode_item_state(item.state()),
            item.exit_code(),
            item.duration_millis()
                .map(i64::try_from)
                .transpose()
                .map_err(|_| {
                    HarnessVerifierStoreError::InvalidFieldValue {
                        field: "duration_millis",
                        actual: i64::MAX,
                    }
                })?,
        ])?;
    }
    Ok(())
}

fn ensure_workspace_matches(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
) -> Result<(), HarnessVerifierStoreError> {
    let persisted: Vec<u8> = transaction.query_row(
        "SELECT workspace_id FROM workspace WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    let persisted = WorkspaceId::from_uuid(decode_uuid("workspace.workspace_id", &persisted)?);
    if persisted == workspace_id {
        Ok(())
    } else {
        Err(HarnessVerifierStoreError::WorkspaceMismatch {
            expected: persisted,
            actual: workspace_id,
        })
    }
}

#[derive(Debug)]
struct RawRun {
    run_id: Vec<u8>,
    workspace_id: Vec<u8>,
    bundle_id: Vec<u8>,
    content_hash: Vec<u8>,
    activity_id: Vec<u8>,
    runtime_instance_id: Vec<u8>,
    state: i64,
    started_at: i64,
    completed_at: Option<i64>,
    revision: i64,
}

fn decode_raw_run_row(row: &Row<'_>) -> rusqlite::Result<RawRun> {
    let result = decode_checked_raw_run(row);
    result.map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Blob, Box::new(error))
    })
}

fn decode_checked_raw_run(row: &Row<'_>) -> Result<RawRun, HarnessVerifierStoreError> {
    validate_exact_length("run_id", row.get(0)?, ID_BYTES)?;
    validate_exact_length("workspace_id", row.get(2)?, ID_BYTES)?;
    validate_exact_length("bundle_id", row.get(4)?, ID_BYTES)?;
    validate_exact_length("content_hash", row.get(6)?, HASH_BYTES)?;
    validate_exact_length("activity_id", row.get(8)?, ID_BYTES)?;
    validate_exact_length("runtime_instance_id", row.get(10)?, ID_BYTES)?;
    Ok(RawRun {
        run_id: row.get(1)?,
        workspace_id: row.get(3)?,
        bundle_id: row.get(5)?,
        content_hash: row.get(7)?,
        activity_id: row.get(9)?,
        runtime_instance_id: row.get(11)?,
        state: row.get(12)?,
        started_at: row.get(13)?,
        completed_at: row.get(14)?,
        revision: row.get(15)?,
    })
}

fn decode_run(
    connection: &Connection,
    raw: &RawRun,
) -> Result<HarnessVerifierRun, HarnessVerifierStoreError> {
    let run_id = HarnessVerifierRunId::from_uuid(decode_uuid("run_id", &raw.run_id)?);
    let items = decode_items(connection, run_id)?;
    HarnessVerifierRun::from_parts(
        HarnessVerifierRunAttribution::new(
            run_id,
            WorkspaceId::from_uuid(decode_uuid("workspace_id", &raw.workspace_id)?),
            HarnessBundleId::from_uuid(decode_uuid("bundle_id", &raw.bundle_id)?),
            decode_hash(&raw.content_hash)?,
            ActivityId::from_uuid(decode_uuid("activity_id", &raw.activity_id)?),
            RuntimeInstanceId::from_uuid(decode_uuid(
                "runtime_instance_id",
                &raw.runtime_instance_id,
            )?),
        ),
        decode_run_state(raw.state)?,
        HarnessVerifierRunTimestamps::new(
            decode_timestamp(raw.started_at)?,
            raw.completed_at.map(decode_timestamp).transpose()?,
        )
        .map_err(HarnessVerifierStoreError::Domain)?,
        HarnessVerifierRunRevision::new(raw.revision)
            .map_err(HarnessVerifierStoreError::Revision)?,
        items,
    )
    .map_err(HarnessVerifierStoreError::Domain)
}

fn decode_items(
    connection: &Connection,
    run_id: HarnessVerifierRunId,
) -> Result<Vec<HarnessVerifierItem>, HarnessVerifierStoreError> {
    let mut statement = connection.prepare(
        "SELECT ordinal, length(CAST(name AS BLOB)), name,
                length(approval_id), approval_id, length(execution_id), execution_id,
                length(request_digest), request_digest, state, exit_code, duration_millis
         FROM workspace_harness_verifier_items WHERE run_id = ?1 ORDER BY ordinal ASC",
    )?;
    statement
        .query_map(params![run_id.into_uuid().as_bytes()], decode_item_row)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(HarnessVerifierStoreError::from)
}

fn decode_item_row(row: &Row<'_>) -> rusqlite::Result<HarnessVerifierItem> {
    let result = decode_checked_item(row);
    result.map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Integer,
            Box::new(error),
        )
    })
}

fn decode_checked_item(row: &Row<'_>) -> Result<HarnessVerifierItem, HarnessVerifierStoreError> {
    let ordinal: i64 = row.get(0)?;
    let name_len: i64 = row.get(1)?;
    validate_max_length("name", name_len, MAX_NAME_BYTES)?;
    validate_exact_length("approval_id", row.get(3)?, ID_BYTES)?;
    validate_exact_length("execution_id", row.get(5)?, ID_BYTES)?;
    validate_exact_length("request_digest", row.get(7)?, REQUEST_DIGEST_BYTES)?;
    HarnessVerifierItem::new(
        u16::try_from(ordinal).map_err(|_| HarnessVerifierStoreError::InvalidFieldValue {
            field: "ordinal",
            actual: ordinal,
        })?,
        HarnessVerifierName::new(row.get(2)?).map_err(HarnessVerifierStoreError::Name)?,
        ApprovalRequestId::from_uuid(decode_uuid("approval_id", &row.get::<_, Vec<u8>>(4)?)?),
        ExecutionId::from_uuid(decode_uuid("execution_id", &row.get::<_, Vec<u8>>(6)?)?),
        decode_request_digest(&row.get::<_, Vec<u8>>(8)?)?,
        decode_item_state(row.get(9)?)?,
        row.get(10)?,
        row.get::<_, Option<i64>>(11)?
            .map(|value| {
                u64::try_from(value).map_err(|_| HarnessVerifierStoreError::InvalidFieldValue {
                    field: "duration_millis",
                    actual: value,
                })
            })
            .transpose()?,
    )
    .map_err(HarnessVerifierStoreError::Domain)
}

fn encode_run_state(state: HarnessVerifierRunState) -> i64 {
    match state {
        HarnessVerifierRunState::PendingApproval => 0,
        HarnessVerifierRunState::Running => 1,
        HarnessVerifierRunState::Passed => 2,
        HarnessVerifierRunState::Failed => 3,
    }
}

fn decode_run_state(value: i64) -> Result<HarnessVerifierRunState, HarnessVerifierStoreError> {
    match value {
        0 => Ok(HarnessVerifierRunState::PendingApproval),
        1 => Ok(HarnessVerifierRunState::Running),
        2 => Ok(HarnessVerifierRunState::Passed),
        3 => Ok(HarnessVerifierRunState::Failed),
        actual => Err(HarnessVerifierStoreError::InvalidFieldValue {
            field: "state",
            actual,
        }),
    }
}

fn encode_item_state(state: HarnessVerifierItemState) -> i64 {
    match state {
        HarnessVerifierItemState::PendingApproval => 0,
        HarnessVerifierItemState::Running => 1,
        HarnessVerifierItemState::Passed => 2,
        HarnessVerifierItemState::Failed => 3,
        HarnessVerifierItemState::Rejected => 4,
    }
}

fn decode_item_state(value: i64) -> Result<HarnessVerifierItemState, HarnessVerifierStoreError> {
    match value {
        0 => Ok(HarnessVerifierItemState::PendingApproval),
        1 => Ok(HarnessVerifierItemState::Running),
        2 => Ok(HarnessVerifierItemState::Passed),
        3 => Ok(HarnessVerifierItemState::Failed),
        4 => Ok(HarnessVerifierItemState::Rejected),
        actual => Err(HarnessVerifierStoreError::InvalidFieldValue {
            field: "item.state",
            actual,
        }),
    }
}

fn decode_timestamp(value: i64) -> Result<TimestampMillis, HarnessVerifierStoreError> {
    TimestampMillis::new(value).map_err(HarnessVerifierStoreError::Timestamp)
}

fn decode_hash(value: &[u8]) -> Result<HarnessContentHash, HarnessVerifierStoreError> {
    let bytes: [u8; HASH_BYTES] =
        value
            .try_into()
            .map_err(|_| HarnessVerifierStoreError::InvalidFieldLength {
                field: "content_hash",
                actual: value.len(),
                expected: HASH_BYTES,
            })?;
    Ok(HarnessContentHash::from_bytes(bytes))
}

fn decode_request_digest(
    value: &[u8],
) -> Result<ExecutionRequestDigest, HarnessVerifierStoreError> {
    let bytes: [u8; REQUEST_DIGEST_BYTES] =
        value
            .try_into()
            .map_err(|_| HarnessVerifierStoreError::InvalidFieldLength {
                field: "request_digest",
                actual: value.len(),
                expected: REQUEST_DIGEST_BYTES,
            })?;
    Ok(ExecutionRequestDigest::from_bytes(bytes))
}

fn decode_uuid(field: &'static str, value: &[u8]) -> Result<Uuid, HarnessVerifierStoreError> {
    Uuid::from_slice(value).map_err(|_| HarnessVerifierStoreError::InvalidFieldLength {
        field,
        actual: value.len(),
        expected: ID_BYTES,
    })
}

fn validate_exact_length(
    field: &'static str,
    actual: i64,
    expected: usize,
) -> Result<(), HarnessVerifierStoreError> {
    if actual == i64::try_from(expected).unwrap_or(i64::MAX) {
        Ok(())
    } else {
        Err(HarnessVerifierStoreError::InvalidFieldLength {
            field,
            actual: usize::try_from(actual).unwrap_or(usize::MAX),
            expected,
        })
    }
}

fn validate_max_length(
    field: &'static str,
    actual: i64,
    maximum: usize,
) -> Result<(), HarnessVerifierStoreError> {
    if actual >= 1 && usize::try_from(actual).is_ok_and(|value| value <= maximum) {
        Ok(())
    } else {
        Err(HarnessVerifierStoreError::FieldTooLarge { field, maximum })
    }
}

fn normalize_sql(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bootstrap_workspace(
        connection: &Connection,
    ) -> Result<WorkspaceId, Box<dyn std::error::Error>> {
        connection.pragma_update(None, "foreign_keys", true)?;
        connection.execute_batch(
            "CREATE TABLE workspace (singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1), workspace_id BLOB NOT NULL UNIQUE CHECK(length(workspace_id) = 16));",
        )?;
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(2));
        connection.execute(
            "INSERT INTO workspace (singleton, workspace_id) VALUES (1, ?1)",
            params![workspace_id.into_uuid().as_bytes()],
        )?;
        Ok(workspace_id)
    }

    fn snapshot(
        workspace_id: WorkspaceId,
    ) -> Result<HarnessVerifierRun, Box<dyn std::error::Error>> {
        let items = vec![HarnessVerifierItem::new(
            0,
            HarnessVerifierName::new("rules".to_owned())?,
            ApprovalRequestId::from_uuid(Uuid::from_u128(7)),
            ExecutionId::from_uuid(Uuid::from_u128(8)),
            ExecutionRequestDigest::from_bytes([9; ExecutionRequestDigest::BYTE_LEN]),
            HarnessVerifierItemState::PendingApproval,
            None,
            None,
        )?];
        Ok(HarnessVerifierRun::starting(
            HarnessVerifierRunAttribution::new(
                HarnessVerifierRunId::from_uuid(Uuid::from_u128(1)),
                workspace_id,
                HarnessBundleId::from_uuid(Uuid::from_u128(3)),
                HarnessContentHash::from_bytes([4; HarnessContentHash::BYTE_LEN]),
                ActivityId::from_uuid(Uuid::from_u128(5)),
                RuntimeInstanceId::from_uuid(Uuid::from_u128(6)),
            ),
            TimestampMillis::new(10)?,
            items,
        )?)
    }

    #[test]
    fn schema_and_run_snapshot_round_trip_with_cas() -> Result<(), Box<dyn std::error::Error>> {
        let mut connection = Connection::open_in_memory()?;
        let workspace_id = bootstrap_workspace(&connection)?;
        create_schema(&connection)?;
        validate_schema(&connection)?;
        let run = snapshot(workspace_id)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let persisted = persist(&transaction, &run, None)?;
        transaction.commit()?;
        assert_eq!(persisted, run);
        assert_eq!(get(&connection, run.id())?, Some(run.clone()));
        assert_eq!(latest(&connection, workspace_id)?, Some(run.clone()));

        let running = run.reconcile(
            vec![HarnessVerifierItem::new(
                0,
                HarnessVerifierName::new("rules".to_owned())?,
                ApprovalRequestId::from_uuid(Uuid::from_u128(7)),
                ExecutionId::from_uuid(Uuid::from_u128(8)),
                ExecutionRequestDigest::from_bytes([9; ExecutionRequestDigest::BYTE_LEN]),
                HarnessVerifierItemState::Running,
                None,
                None,
            )?],
            TimestampMillis::new(20)?,
        )?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let persisted = persist(&transaction, &running, Some(run.revision()))?;
        transaction.commit()?;
        assert_eq!(persisted, running);
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let stale = persist(&transaction, &run, Some(run.revision()));
        assert!(matches!(
            stale,
            Err(HarnessVerifierStoreError::CompareAndSwapConflict)
        ));
        Ok(())
    }
}
