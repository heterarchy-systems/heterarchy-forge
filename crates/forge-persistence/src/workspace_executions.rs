use std::ffi::OsString;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;

use crate::workspace_store::encode_activity_state;
use forge_domain::{
    ActivityId, ActivityState, BeginExecution, BoundedExecutionOutput, CompleteExecution,
    ExecutionAttribution, ExecutionCompletionStatus, ExecutionFailureCode, ExecutionId,
    ExecutionLimits, ExecutionListLimit, ExecutionMode, ExecutionOutcome, ExecutionOutputLimit,
    ExecutionPermissions, ExecutionRequestDigest, ExecutionRevision, ExecutionState,
    ExecutionTermination, ExecutionTimeoutMillis, ExecutionTimestamps, FailExecution,
    MarkExecutionRunning, RegisteredExecution, TimestampMillis, WorkspaceId, WorkspaceRelativePath,
    execution_state_for_outcome,
};
use rusqlite::{Connection, OptionalExtension, Row, Transaction, TransactionBehavior, params};
use thiserror::Error;
use uuid::Uuid;

pub(crate) const EXPECTED_EXECUTIONS_TABLE_SQL: &str = "CREATE TABLE executions (execution_id BLOB PRIMARY KEY NOT NULL CHECK(length(execution_id) = 16), workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id), activity_id BLOB NOT NULL REFERENCES activities(activity_id), state INTEGER NOT NULL CHECK(state IN (0, 1, 2, 3, 4, 5, 6)), mode INTEGER NOT NULL CHECK(mode IN (0, 1)), request_digest BLOB NOT NULL CHECK(length(request_digest) = 32), cwd BLOB CHECK(cwd IS NULL OR length(cwd) BETWEEN 1 AND 4096), timeout_ms INTEGER NOT NULL CHECK(timeout_ms BETWEEN 100 AND 600000), output_limit INTEGER NOT NULL CHECK(output_limit BETWEEN 1 AND 1048576), workspace_read INTEGER NOT NULL CHECK(workspace_read IN (0, 1)), workspace_write INTEGER NOT NULL CHECK(workspace_write IN (0, 1)), network INTEGER NOT NULL CHECK(network IN (0, 1)), exit_code INTEGER CHECK(exit_code IS NULL OR exit_code BETWEEN -2147483648 AND 2147483647), signal INTEGER CHECK(signal IS NULL OR signal BETWEEN -2147483648 AND 2147483647), duration_ms INTEGER CHECK(duration_ms IS NULL OR duration_ms >= 0), stdout BLOB CHECK(stdout IS NULL OR length(stdout) <= 1048576), stdout_total_bytes INTEGER CHECK(stdout_total_bytes IS NULL OR stdout_total_bytes >= 0), stdout_truncated INTEGER CHECK(stdout_truncated IS NULL OR stdout_truncated IN (0, 1)), stderr BLOB CHECK(stderr IS NULL OR length(stderr) <= 1048576), stderr_total_bytes INTEGER CHECK(stderr_total_bytes IS NULL OR stderr_total_bytes >= 0), stderr_truncated INTEGER CHECK(stderr_truncated IS NULL OR stderr_truncated IN (0, 1)), failure_code INTEGER CHECK(failure_code IS NULL OR failure_code IN (0, 1, 2, 3, 4)), created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0), updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0), revision INTEGER NOT NULL CHECK(revision >= 1), CHECK((state IN (0, 1, 6) AND exit_code IS NULL AND signal IS NULL AND duration_ms IS NULL AND stdout IS NULL AND stdout_total_bytes IS NULL AND stdout_truncated IS NULL AND stderr IS NULL AND stderr_total_bytes IS NULL AND stderr_truncated IS NULL AND failure_code IS NULL) OR (state IN (2, 4, 5) AND duration_ms IS NOT NULL AND stdout IS NOT NULL AND stdout_total_bytes IS NOT NULL AND stdout_truncated IS NOT NULL AND stderr IS NOT NULL AND stderr_total_bytes IS NOT NULL AND stderr_truncated IS NOT NULL AND failure_code IS NULL) OR (state = 3 AND ((duration_ms IS NOT NULL AND stdout IS NOT NULL AND stdout_total_bytes IS NOT NULL AND stdout_truncated IS NOT NULL AND stderr IS NOT NULL AND stderr_total_bytes IS NOT NULL AND stderr_truncated IS NOT NULL AND failure_code IS NULL) OR (exit_code IS NULL AND signal IS NULL AND duration_ms IS NULL AND stdout IS NULL AND stdout_total_bytes IS NULL AND stdout_truncated IS NULL AND stderr IS NULL AND stderr_total_bytes IS NULL AND stderr_truncated IS NULL AND failure_code IS NOT NULL)))))";
pub(crate) const EXPECTED_EXECUTIONS_ACTIVITY_INDEX_SQL: &str = "CREATE INDEX executions_activity_created_idx ON executions(activity_id, created_at_ms DESC, execution_id DESC)";
pub(crate) const EXPECTED_EXECUTIONS_STATE_INDEX_SQL: &str =
    "CREATE INDEX executions_state_updated_idx ON executions(state, updated_at_ms, execution_id)";

const MAX_CWD_BYTES: usize = 4_096;
const MAX_OUTPUT_BYTES: usize = 1024 * 1024;

const RECORD_QUERY: &str = "SELECT
        length(CAST(execution_id AS BLOB)), length(CAST(workspace_id AS BLOB)),
        length(CAST(activity_id AS BLOB)), length(CAST(request_digest AS BLOB)),
        length(CAST(cwd AS BLOB)), length(CAST(stdout AS BLOB)), length(CAST(stderr AS BLOB)),
        execution_id, workspace_id, activity_id, state, mode, request_digest, cwd,
        timeout_ms, output_limit, workspace_read, workspace_write, network,
        exit_code, signal, duration_ms, stdout, stdout_total_bytes, stdout_truncated,
        stderr, stderr_total_bytes, stderr_truncated, failure_code,
        created_at_ms, updated_at_ms, revision
    FROM executions";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BeginExecutionStatus {
    Created,
    Existing,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeginExecutionRecord {
    status: BeginExecutionStatus,
    record: RegisteredExecution,
}

impl BeginExecutionRecord {
    pub const fn status(&self) -> BeginExecutionStatus {
        self.status
    }

    pub const fn record(&self) -> &RegisteredExecution {
        &self.record
    }
}

pub(crate) fn create_schema(connection: &Connection) -> Result<(), ExecutionStoreError> {
    connection.execute_batch(
        "CREATE TABLE executions (
            execution_id BLOB PRIMARY KEY NOT NULL CHECK(length(execution_id) = 16),
            workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id),
            activity_id BLOB NOT NULL REFERENCES activities(activity_id),
            state INTEGER NOT NULL CHECK(state IN (0, 1, 2, 3, 4, 5, 6)),
            mode INTEGER NOT NULL CHECK(mode IN (0, 1)),
            request_digest BLOB NOT NULL CHECK(length(request_digest) = 32),
            cwd BLOB CHECK(cwd IS NULL OR length(cwd) BETWEEN 1 AND 4096),
            timeout_ms INTEGER NOT NULL CHECK(timeout_ms BETWEEN 100 AND 600000),
            output_limit INTEGER NOT NULL CHECK(output_limit BETWEEN 1 AND 1048576),
            workspace_read INTEGER NOT NULL CHECK(workspace_read IN (0, 1)),
            workspace_write INTEGER NOT NULL CHECK(workspace_write IN (0, 1)),
            network INTEGER NOT NULL CHECK(network IN (0, 1)),
            exit_code INTEGER CHECK(exit_code IS NULL OR exit_code BETWEEN -2147483648 AND 2147483647),
            signal INTEGER CHECK(signal IS NULL OR signal BETWEEN -2147483648 AND 2147483647),
            duration_ms INTEGER CHECK(duration_ms IS NULL OR duration_ms >= 0),
            stdout BLOB CHECK(stdout IS NULL OR length(stdout) <= 1048576),
            stdout_total_bytes INTEGER CHECK(stdout_total_bytes IS NULL OR stdout_total_bytes >= 0),
            stdout_truncated INTEGER CHECK(stdout_truncated IS NULL OR stdout_truncated IN (0, 1)),
            stderr BLOB CHECK(stderr IS NULL OR length(stderr) <= 1048576),
            stderr_total_bytes INTEGER CHECK(stderr_total_bytes IS NULL OR stderr_total_bytes >= 0),
            stderr_truncated INTEGER CHECK(stderr_truncated IS NULL OR stderr_truncated IN (0, 1)),
            failure_code INTEGER CHECK(failure_code IS NULL OR failure_code IN (0, 1, 2, 3, 4)),
            created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
            updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0),
            revision INTEGER NOT NULL CHECK(revision >= 1),
            CHECK(
                (state IN (0, 1, 6) AND exit_code IS NULL AND signal IS NULL AND duration_ms IS NULL AND stdout IS NULL AND stdout_total_bytes IS NULL AND stdout_truncated IS NULL AND stderr IS NULL AND stderr_total_bytes IS NULL AND stderr_truncated IS NULL AND failure_code IS NULL)
                OR (state IN (2, 4, 5) AND duration_ms IS NOT NULL AND stdout IS NOT NULL AND stdout_total_bytes IS NOT NULL AND stdout_truncated IS NOT NULL AND stderr IS NOT NULL AND stderr_total_bytes IS NOT NULL AND stderr_truncated IS NOT NULL AND failure_code IS NULL)
                OR (state = 3 AND (
                    (duration_ms IS NOT NULL AND stdout IS NOT NULL AND stdout_total_bytes IS NOT NULL AND stdout_truncated IS NOT NULL AND stderr IS NOT NULL AND stderr_total_bytes IS NOT NULL AND stderr_truncated IS NOT NULL AND failure_code IS NULL)
                    OR (exit_code IS NULL AND signal IS NULL AND duration_ms IS NULL AND stdout IS NULL AND stdout_total_bytes IS NULL AND stdout_truncated IS NULL AND stderr IS NULL AND stderr_total_bytes IS NULL AND stderr_truncated IS NULL AND failure_code IS NOT NULL)
                ))
            )
         );
         CREATE INDEX executions_activity_created_idx
            ON executions(activity_id, created_at_ms DESC, execution_id DESC);
         CREATE INDEX executions_state_updated_idx
            ON executions(state, updated_at_ms, execution_id);",
    )?;
    Ok(())
}

pub(crate) fn migrate_v5_to_v6(
    connection: &mut Connection,
    next_schema_version: i64,
) -> Result<(), ExecutionStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    create_schema(&transaction)?;
    transaction.pragma_update(None, "user_version", next_schema_version)?;
    transaction.commit()?;
    Ok(())
}

pub(crate) fn schema_objects() -> [(&'static str, &'static str); 3] {
    [
        ("table", "executions"),
        ("index", "executions_activity_created_idx"),
        ("index", "executions_state_updated_idx"),
    ]
}

pub(crate) fn validate_schema(connection: &Connection) -> Result<(), ExecutionStoreError> {
    validate_schema_sql(
        connection,
        "table",
        "executions",
        EXPECTED_EXECUTIONS_TABLE_SQL,
    )?;
    validate_schema_sql(
        connection,
        "index",
        "executions_activity_created_idx",
        EXPECTED_EXECUTIONS_ACTIVITY_INDEX_SQL,
    )?;
    validate_schema_sql(
        connection,
        "index",
        "executions_state_updated_idx",
        EXPECTED_EXECUTIONS_STATE_INDEX_SQL,
    )?;
    validate_table_columns(connection)?;
    validate_index_columns(
        connection,
        "executions_activity_created_idx",
        &["activity_id", "created_at_ms", "execution_id"],
    )?;
    validate_index_columns(
        connection,
        "executions_state_updated_idx",
        &["state", "updated_at_ms", "execution_id"],
    )?;
    validate_foreign_keys(connection, "executions", 2)
}

pub(crate) fn begin_execution_in_transaction(
    transaction: &Transaction<'_>,
    command: &BeginExecution,
) -> Result<BeginExecutionRecord, ExecutionStoreError> {
    let activity: Option<(Vec<u8>, i64)> = transaction
        .query_row(
            "SELECT workspace_id, state FROM activities WHERE activity_id = ?1",
            params![command.activity_id().into_uuid().as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let (activity_workspace, activity_state) =
        activity.ok_or(ExecutionStoreError::ActivityMissing)?;
    if activity_workspace.as_slice() != command.workspace_id().into_uuid().as_bytes() {
        return Err(ExecutionStoreError::AttributionMismatch);
    }
    if activity_state != 1 {
        return Err(ExecutionStoreError::ActivityTerminal);
    }
    let cwd = command
        .cwd()
        .map(|value| value.as_path().as_os_str().as_bytes().to_vec());
    let inserted = transaction.execute(
        "INSERT INTO executions (
            execution_id, workspace_id, activity_id, state, mode, request_digest, cwd,
            timeout_ms, output_limit, workspace_read, workspace_write, network,
            created_at_ms, updated_at_ms, revision
         ) VALUES (?1, ?2, ?3, 0, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?12, 1)
         ON CONFLICT(execution_id) DO NOTHING",
        params![
            command.id().into_uuid().as_bytes(),
            command.workspace_id().into_uuid().as_bytes(),
            command.activity_id().into_uuid().as_bytes(),
            encode_mode(command.mode()),
            command.request_digest().as_bytes(),
            cwd,
            i64::try_from(command.limits().timeout().get())
                .map_err(|_| ExecutionStoreError::IntegerOverflow)?,
            i64::try_from(command.limits().output().get())
                .map_err(|_| ExecutionStoreError::IntegerOverflow)?,
            encode_bool(command.permissions().workspace_read()),
            encode_bool(command.permissions().workspace_write()),
            encode_bool(command.permissions().network()),
            timestamp_i64(command.observed_at()),
        ],
    )?;
    let record =
        get_execution_tx(transaction, command.id())?.ok_or(ExecutionStoreError::RecordMissing)?;
    if inserted == 0 && !begin_matches(&record, command) {
        return Err(ExecutionStoreError::IdentityConflict);
    }
    let status = if inserted == 1 {
        BeginExecutionStatus::Created
    } else {
        BeginExecutionStatus::Existing
    };
    Ok(BeginExecutionRecord { status, record })
}

#[cfg(test)]
fn begin_execution(
    connection: &mut Connection,
    command: &BeginExecution,
) -> Result<BeginExecutionRecord, ExecutionStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let result = begin_execution_in_transaction(&transaction, command)?;
    transaction.commit()?;
    Ok(result)
}

fn begin_matches(record: &RegisteredExecution, command: &BeginExecution) -> bool {
    record.workspace_id() == command.workspace_id()
        && record.activity_id() == command.activity_id()
        && record.mode() == command.mode()
        && record.cwd() == command.cwd()
        && record.limits() == command.limits()
        && record.permissions() == command.permissions()
        && record.request_digest() == command.request_digest()
}

pub(crate) fn mark_execution_running(
    connection: &mut Connection,
    command: MarkExecutionRunning,
) -> Result<RegisteredExecution, ExecutionStoreError> {
    transition_without_evidence(
        connection,
        command.id(),
        command.expected_revision(),
        command.observed_at(),
        ExecutionState::Starting,
        ExecutionState::Running,
    )
}

pub(crate) fn complete_execution(
    connection: &mut Connection,
    command: &CompleteExecution,
) -> Result<RegisteredExecution, ExecutionStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let current =
        get_execution_tx(&transaction, command.id())?.ok_or(ExecutionStoreError::RecordMissing)?;
    validate_active_transition(
        &current,
        command.expected_revision(),
        command.observed_at(),
        ExecutionState::Running,
    )?;
    let next_revision = current
        .revision()
        .checked_next()
        .map_err(|_| ExecutionStoreError::RevisionOverflow)?;
    let outcome = command.outcome();
    let next_state = execution_state_for_outcome(outcome);
    let stdout_total = output_total_i64(outcome.stdout())?;
    let stderr_total = output_total_i64(outcome.stderr())?;
    let updated = transaction.execute(
        "UPDATE executions SET
            state = ?1, exit_code = ?2, signal = ?3, duration_ms = ?4,
            stdout = ?5, stdout_total_bytes = ?6, stdout_truncated = ?7,
            stderr = ?8, stderr_total_bytes = ?9, stderr_truncated = ?10,
            updated_at_ms = ?11, revision = ?12
         WHERE execution_id = ?13 AND state = 1 AND revision = ?14",
        params![
            encode_state(next_state),
            outcome.exit_code(),
            outcome.signal(),
            i64::try_from(outcome.duration_millis())
                .map_err(|_| ExecutionStoreError::IntegerOverflow)?,
            outcome.stdout().retained(),
            stdout_total,
            encode_bool(outcome.stdout().truncated()),
            outcome.stderr().retained(),
            stderr_total,
            encode_bool(outcome.stderr().truncated()),
            timestamp_i64(command.observed_at()),
            next_revision.get(),
            command.id().into_uuid().as_bytes(),
            command.expected_revision().get(),
        ],
    )?;
    if updated != 1 {
        return Err(ExecutionStoreError::RevisionConflict);
    }
    let record =
        get_execution_tx(&transaction, command.id())?.ok_or(ExecutionStoreError::RecordMissing)?;
    transaction.commit()?;
    Ok(record)
}

pub(crate) fn fail_execution(
    connection: &mut Connection,
    command: FailExecution,
) -> Result<RegisteredExecution, ExecutionStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let current =
        get_execution_tx(&transaction, command.id())?.ok_or(ExecutionStoreError::RecordMissing)?;
    if !current.state().is_active() {
        return Err(ExecutionStoreError::Terminal);
    }
    validate_revision_and_timestamp(&current, command.expected_revision(), command.observed_at())?;
    let next_revision = current
        .revision()
        .checked_next()
        .map_err(|_| ExecutionStoreError::RevisionOverflow)?;
    let updated = transaction.execute(
        "UPDATE executions SET state = 3, failure_code = ?1, updated_at_ms = ?2, revision = ?3
         WHERE execution_id = ?4 AND state IN (0, 1) AND revision = ?5",
        params![
            encode_failure(command.failure_code()),
            timestamp_i64(command.observed_at()),
            next_revision.get(),
            command.id().into_uuid().as_bytes(),
            command.expected_revision().get(),
        ],
    )?;
    if updated != 1 {
        return Err(ExecutionStoreError::RevisionConflict);
    }
    let record =
        get_execution_tx(&transaction, command.id())?.ok_or(ExecutionStoreError::RecordMissing)?;
    transaction.commit()?;
    Ok(record)
}

pub(crate) fn reconcile_interrupted_executions(
    connection: &mut Connection,
    observed_at: TimestampMillis,
    limit: ExecutionListLimit,
) -> Result<Vec<RegisteredExecution>, ExecutionStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let ids = {
        let mut statement = transaction.prepare(
            "SELECT execution_id FROM executions
             WHERE state IN (0, 1)
             ORDER BY updated_at_ms ASC, execution_id ASC LIMIT ?1",
        )?;
        let rows = statement.query_map(params![i64::from(limit.get())], |row| {
            row.get::<_, Vec<u8>>(0)
        })?;
        rows.collect::<Result<Vec<_>, _>>()?
    };
    let mut records = Vec::with_capacity(ids.len());
    for raw_id in ids {
        let id = decode_execution_id(&raw_id)?;
        let current =
            get_execution_tx(&transaction, id)?.ok_or(ExecutionStoreError::RecordMissing)?;
        if observed_at.get() < current.timestamps().updated_at().get() {
            return Err(ExecutionStoreError::TimestampOrder);
        }
        let next_revision = current
            .revision()
            .checked_next()
            .map_err(|_| ExecutionStoreError::RevisionOverflow)?;
        let updated = transaction.execute(
            "UPDATE executions SET state = 6, updated_at_ms = ?1, revision = ?2
             WHERE execution_id = ?3 AND state IN (0, 1) AND revision = ?4",
            params![
                timestamp_i64(observed_at),
                next_revision.get(),
                id.into_uuid().as_bytes(),
                current.revision().get(),
            ],
        )?;
        if updated != 1 {
            return Err(ExecutionStoreError::RevisionConflict);
        }
        records
            .push(get_execution_tx(&transaction, id)?.ok_or(ExecutionStoreError::RecordMissing)?);
    }
    transaction.commit()?;
    Ok(records)
}

pub(crate) fn reconcile_expired_authority_executions(
    connection: &mut Connection,
    observed_at: TimestampMillis,
    limit: ExecutionListLimit,
) -> Result<Vec<RegisteredExecution>, ExecutionStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let ids = {
        let mut statement = transaction.prepare(
            "SELECT e.execution_id FROM executions e
             JOIN activities a ON a.activity_id = e.activity_id
             WHERE e.state IN (0, 1)
               AND (a.state = ?2
                    OR (a.lease_until_ms IS NOT NULL AND a.lease_until_ms <= ?1))
             ORDER BY e.updated_at_ms ASC, e.execution_id ASC LIMIT ?3",
        )?;
        let rows = statement.query_map(
            params![
                timestamp_i64(observed_at),
                encode_activity_state(ActivityState::Interrupted),
                i64::from(limit.get()),
            ],
            |row| row.get::<_, Vec<u8>>(0),
        )?;
        rows.collect::<Result<Vec<_>, _>>()?
    };
    let mut records = Vec::with_capacity(ids.len());
    for raw_id in ids {
        let id = decode_execution_id(&raw_id)?;
        let current =
            get_execution_tx(&transaction, id)?.ok_or(ExecutionStoreError::RecordMissing)?;
        if observed_at.get() < current.timestamps().updated_at().get() {
            return Err(ExecutionStoreError::TimestampOrder);
        }
        let next_revision = current
            .revision()
            .checked_next()
            .map_err(|_| ExecutionStoreError::RevisionOverflow)?;
        let updated = transaction.execute(
            "UPDATE executions SET state = 6, updated_at_ms = ?1, revision = ?2
             WHERE execution_id = ?3 AND state IN (0, 1) AND revision = ?4",
            params![
                timestamp_i64(observed_at),
                next_revision.get(),
                id.into_uuid().as_bytes(),
                current.revision().get(),
            ],
        )?;
        if updated != 1 {
            return Err(ExecutionStoreError::RevisionConflict);
        }
        records
            .push(get_execution_tx(&transaction, id)?.ok_or(ExecutionStoreError::RecordMissing)?);
    }
    transaction.commit()?;
    Ok(records)
}

pub(crate) fn get_execution(
    connection: &Connection,
    id: ExecutionId,
) -> Result<Option<RegisteredExecution>, ExecutionStoreError> {
    connection
        .query_row(
            &format!("{RECORD_QUERY} WHERE execution_id = ?1"),
            params![id.into_uuid().as_bytes()],
            decode_record,
        )
        .optional()
        .map_err(ExecutionStoreError::from)
}

pub(crate) fn list_executions(
    connection: &Connection,
    activity_id: ActivityId,
    limit: ExecutionListLimit,
) -> Result<Vec<RegisteredExecution>, ExecutionStoreError> {
    let mut statement = connection.prepare(&format!(
        "{RECORD_QUERY} WHERE activity_id = ?1
         ORDER BY created_at_ms DESC, execution_id DESC LIMIT ?2"
    ))?;
    let rows = statement.query_map(
        params![activity_id.into_uuid().as_bytes(), i64::from(limit.get())],
        decode_record,
    )?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(ExecutionStoreError::from)
}

fn transition_without_evidence(
    connection: &mut Connection,
    id: ExecutionId,
    expected_revision: ExecutionRevision,
    observed_at: TimestampMillis,
    expected_state: ExecutionState,
    next_state: ExecutionState,
) -> Result<RegisteredExecution, ExecutionStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let current = get_execution_tx(&transaction, id)?.ok_or(ExecutionStoreError::RecordMissing)?;
    validate_active_transition(&current, expected_revision, observed_at, expected_state)?;
    let next_revision = current
        .revision()
        .checked_next()
        .map_err(|_| ExecutionStoreError::RevisionOverflow)?;
    let updated = transaction.execute(
        "UPDATE executions SET state = ?1, updated_at_ms = ?2, revision = ?3
         WHERE execution_id = ?4 AND state = ?5 AND revision = ?6",
        params![
            encode_state(next_state),
            timestamp_i64(observed_at),
            next_revision.get(),
            id.into_uuid().as_bytes(),
            encode_state(expected_state),
            expected_revision.get(),
        ],
    )?;
    if updated != 1 {
        return Err(ExecutionStoreError::RevisionConflict);
    }
    let record = get_execution_tx(&transaction, id)?.ok_or(ExecutionStoreError::RecordMissing)?;
    transaction.commit()?;
    Ok(record)
}

fn validate_active_transition(
    current: &RegisteredExecution,
    expected_revision: ExecutionRevision,
    observed_at: TimestampMillis,
    expected_state: ExecutionState,
) -> Result<(), ExecutionStoreError> {
    if current.state() != expected_state {
        return if current.state().is_terminal() {
            Err(ExecutionStoreError::Terminal)
        } else {
            Err(ExecutionStoreError::InvalidTransition)
        };
    }
    validate_revision_and_timestamp(current, expected_revision, observed_at)
}

fn validate_revision_and_timestamp(
    current: &RegisteredExecution,
    expected_revision: ExecutionRevision,
    observed_at: TimestampMillis,
) -> Result<(), ExecutionStoreError> {
    if current.revision() != expected_revision {
        return Err(ExecutionStoreError::RevisionConflict);
    }
    if observed_at.get() < current.timestamps().updated_at().get() {
        return Err(ExecutionStoreError::TimestampOrder);
    }
    Ok(())
}

fn get_execution_tx(
    transaction: &Transaction<'_>,
    id: ExecutionId,
) -> Result<Option<RegisteredExecution>, ExecutionStoreError> {
    transaction
        .query_row(
            &format!("{RECORD_QUERY} WHERE execution_id = ?1"),
            params![id.into_uuid().as_bytes()],
            decode_record,
        )
        .optional()
        .map_err(ExecutionStoreError::from)
}

fn decode_record(row: &Row<'_>) -> rusqlite::Result<RegisteredExecution> {
    decode_record_inner(row).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Blob, Box::new(error))
    })
}

fn decode_record_inner(row: &Row<'_>) -> Result<RegisteredExecution, ExecutionStoreError> {
    validate_exact_length("execution.execution_id", row.get(0)?, 16)?;
    validate_exact_length("execution.workspace_id", row.get(1)?, 16)?;
    validate_exact_length("execution.activity_id", row.get(2)?, 16)?;
    validate_exact_length(
        "execution.request_digest",
        row.get(3)?,
        ExecutionRequestDigest::BYTE_LEN,
    )?;
    validate_optional_bounded_length("execution.cwd", row.get(4)?, MAX_CWD_BYTES)?;
    validate_optional_bounded_length("execution.stdout", row.get(5)?, MAX_OUTPUT_BYTES)?;
    validate_optional_bounded_length("execution.stderr", row.get(6)?, MAX_OUTPUT_BYTES)?;

    let id = decode_execution_id(&row.get::<_, Vec<u8>>(7)?)?;
    let workspace_id = decode_workspace_id(&row.get::<_, Vec<u8>>(8)?)?;
    let activity_id = decode_activity_id(&row.get::<_, Vec<u8>>(9)?)?;
    let state = decode_state(row.get(10)?)?;
    let mode = decode_mode(row.get(11)?)?;
    let request_digest = decode_request_digest(&row.get::<_, Vec<u8>>(12)?)?;
    let cwd = row
        .get::<_, Option<Vec<u8>>>(13)?
        .map(|value| WorkspaceRelativePath::new(PathBuf::from(OsString::from_vec(value))))
        .transpose()
        .map_err(|_| ExecutionStoreError::CorruptRecord("execution.cwd"))?;
    let timeout = ExecutionTimeoutMillis::new(decode_u64("execution.timeout_ms", row.get(14)?)?)
        .map_err(|_| ExecutionStoreError::CorruptRecord("execution.timeout_ms"))?;
    let output_limit =
        ExecutionOutputLimit::new(decode_u64("execution.output_limit", row.get(15)?)?)
            .map_err(|_| ExecutionStoreError::CorruptRecord("execution.output_limit"))?;
    let permissions = ExecutionPermissions::new(
        decode_bool("execution.workspace_read", row.get(16)?)?,
        decode_bool("execution.workspace_write", row.get(17)?)?,
        decode_bool("execution.network", row.get(18)?)?,
    );
    let exit_code = row.get::<_, Option<i32>>(19)?;
    let signal = row.get::<_, Option<i32>>(20)?;
    let duration = row
        .get::<_, Option<i64>>(21)?
        .map(|value| decode_u64("execution.duration_ms", value))
        .transpose()?;
    let stdout = decode_output(row, 22, 23, 24, "execution.stdout")?;
    let stderr = decode_output(row, 25, 26, 27, "execution.stderr")?;
    let failure_code = row
        .get::<_, Option<i64>>(28)?
        .map(decode_failure)
        .transpose()?;
    let timestamps = ExecutionTimestamps::new(
        decode_timestamp("execution.created_at_ms", row.get(29)?)?,
        decode_timestamp("execution.updated_at_ms", row.get(30)?)?,
    )
    .map_err(|_| ExecutionStoreError::CorruptRecord("execution.timestamps"))?;
    let revision = ExecutionRevision::new(row.get(31)?)
        .map_err(|_| ExecutionStoreError::CorruptRecord("execution.revision"))?;

    let attribution = ExecutionAttribution::new(id, workspace_id, activity_id);
    let outcome = match (duration, stdout, stderr) {
        (Some(duration), Some(stdout), Some(stderr)) => Some(ExecutionOutcome::new(
            id,
            ExecutionTermination::new(completion_status_for_state(state)?, exit_code, signal),
            duration,
            stdout,
            stderr,
        )),
        (None, None, None) => None,
        _ => return Err(ExecutionStoreError::CorruptRecord("execution.outcome")),
    };
    RegisteredExecution::from_parts(
        attribution,
        mode,
        cwd,
        ExecutionLimits::new(timeout, output_limit),
        permissions,
        request_digest,
        state,
        timestamps,
        revision,
        outcome,
        failure_code,
    )
    .map_err(|_| ExecutionStoreError::CorruptRecord("execution.evidence"))
}

fn decode_output(
    row: &Row<'_>,
    bytes_index: usize,
    total_index: usize,
    truncated_index: usize,
    field: &'static str,
) -> Result<Option<BoundedExecutionOutput>, ExecutionStoreError> {
    let bytes = row.get::<_, Option<Vec<u8>>>(bytes_index)?;
    let total = row.get::<_, Option<i64>>(total_index)?;
    let truncated = row.get::<_, Option<i64>>(truncated_index)?;
    match (bytes, total, truncated) {
        (Some(bytes), Some(total), Some(truncated)) => Ok(Some(BoundedExecutionOutput::new(
            bytes,
            decode_u64(field, total)?,
            decode_bool(field, truncated)?,
        ))),
        (None, None, None) => Ok(None),
        _ => Err(ExecutionStoreError::CorruptRecord(field)),
    }
}

fn completion_status_for_state(
    state: ExecutionState,
) -> Result<ExecutionCompletionStatus, ExecutionStoreError> {
    match state {
        ExecutionState::Completed | ExecutionState::Failed => Ok(ExecutionCompletionStatus::Exited),
        ExecutionState::TimedOut => Ok(ExecutionCompletionStatus::TimedOut),
        ExecutionState::Cancelled => Ok(ExecutionCompletionStatus::Cancelled),
        ExecutionState::Starting | ExecutionState::Running | ExecutionState::Interrupted => {
            Err(ExecutionStoreError::CorruptRecord("execution.state"))
        }
    }
}

const fn encode_state(state: ExecutionState) -> i64 {
    match state {
        ExecutionState::Starting => 0,
        ExecutionState::Running => 1,
        ExecutionState::Completed => 2,
        ExecutionState::Failed => 3,
        ExecutionState::TimedOut => 4,
        ExecutionState::Cancelled => 5,
        ExecutionState::Interrupted => 6,
    }
}

fn decode_state(value: i64) -> Result<ExecutionState, ExecutionStoreError> {
    match value {
        0 => Ok(ExecutionState::Starting),
        1 => Ok(ExecutionState::Running),
        2 => Ok(ExecutionState::Completed),
        3 => Ok(ExecutionState::Failed),
        4 => Ok(ExecutionState::TimedOut),
        5 => Ok(ExecutionState::Cancelled),
        6 => Ok(ExecutionState::Interrupted),
        _ => Err(ExecutionStoreError::CorruptRecord("execution.state")),
    }
}

const fn encode_mode(mode: ExecutionMode) -> i64 {
    match mode {
        ExecutionMode::Structured => 0,
        ExecutionMode::Shell => 1,
    }
}

fn decode_mode(value: i64) -> Result<ExecutionMode, ExecutionStoreError> {
    match value {
        0 => Ok(ExecutionMode::Structured),
        1 => Ok(ExecutionMode::Shell),
        _ => Err(ExecutionStoreError::CorruptRecord("execution.mode")),
    }
}

const fn encode_failure(value: ExecutionFailureCode) -> i64 {
    match value {
        ExecutionFailureCode::Admission => 0,
        ExecutionFailureCode::SandboxUnavailable => 1,
        ExecutionFailureCode::InvalidWorkingDirectory => 2,
        ExecutionFailureCode::ProcessSpawn => 3,
        ExecutionFailureCode::Supervision => 4,
    }
}

fn decode_failure(value: i64) -> Result<ExecutionFailureCode, ExecutionStoreError> {
    match value {
        0 => Ok(ExecutionFailureCode::Admission),
        1 => Ok(ExecutionFailureCode::SandboxUnavailable),
        2 => Ok(ExecutionFailureCode::InvalidWorkingDirectory),
        3 => Ok(ExecutionFailureCode::ProcessSpawn),
        4 => Ok(ExecutionFailureCode::Supervision),
        _ => Err(ExecutionStoreError::CorruptRecord("execution.failure_code")),
    }
}

const fn encode_bool(value: bool) -> i64 {
    if value { 1 } else { 0 }
}

fn decode_bool(field: &'static str, value: i64) -> Result<bool, ExecutionStoreError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(ExecutionStoreError::CorruptRecord(field)),
    }
}

const fn timestamp_i64(value: TimestampMillis) -> i64 {
    value.get()
}

fn decode_timestamp(
    field: &'static str,
    value: i64,
) -> Result<TimestampMillis, ExecutionStoreError> {
    TimestampMillis::new(value).map_err(|_| ExecutionStoreError::CorruptRecord(field))
}

fn decode_u64(field: &'static str, value: i64) -> Result<u64, ExecutionStoreError> {
    u64::try_from(value).map_err(|_| ExecutionStoreError::CorruptRecord(field))
}

fn output_total_i64(output: &BoundedExecutionOutput) -> Result<i64, ExecutionStoreError> {
    i64::try_from(output.total_bytes()).map_err(|_| ExecutionStoreError::IntegerOverflow)
}

fn decode_execution_id(value: &[u8]) -> Result<ExecutionId, ExecutionStoreError> {
    Uuid::from_slice(value)
        .map(ExecutionId::from_uuid)
        .map_err(|_| ExecutionStoreError::CorruptRecord("execution.execution_id"))
}

fn decode_workspace_id(value: &[u8]) -> Result<WorkspaceId, ExecutionStoreError> {
    Uuid::from_slice(value)
        .map(WorkspaceId::from_uuid)
        .map_err(|_| ExecutionStoreError::CorruptRecord("execution.workspace_id"))
}

fn decode_activity_id(value: &[u8]) -> Result<ActivityId, ExecutionStoreError> {
    Uuid::from_slice(value)
        .map(ActivityId::from_uuid)
        .map_err(|_| ExecutionStoreError::CorruptRecord("execution.activity_id"))
}

fn decode_request_digest(value: &[u8]) -> Result<ExecutionRequestDigest, ExecutionStoreError> {
    <[u8; ExecutionRequestDigest::BYTE_LEN]>::try_from(value)
        .map(ExecutionRequestDigest::from_bytes)
        .map_err(|_| ExecutionStoreError::CorruptRecord("execution.request_digest"))
}

fn validate_exact_length(
    field: &'static str,
    length: i64,
    expected: usize,
) -> Result<(), ExecutionStoreError> {
    if usize::try_from(length).ok() == Some(expected) {
        Ok(())
    } else {
        Err(ExecutionStoreError::CorruptRecord(field))
    }
}

fn validate_optional_bounded_length(
    field: &'static str,
    length: Option<i64>,
    maximum: usize,
) -> Result<(), ExecutionStoreError> {
    match length {
        None => Ok(()),
        Some(length) => match usize::try_from(length) {
            Ok(actual)
                if (1..=maximum).contains(&actual) || (actual == 0 && field != "execution.cwd") =>
            {
                Ok(())
            }
            Ok(_) | Err(_) => Err(ExecutionStoreError::CorruptRecord(field)),
        },
    }
}

fn validate_schema_sql(
    connection: &Connection,
    object_type: &'static str,
    name: &'static str,
    expected: &'static str,
) -> Result<(), ExecutionStoreError> {
    let sql: Option<String> = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type = ?1 AND name = ?2",
            params![object_type, name],
            |row| row.get(0),
        )
        .optional()?;
    let sql = sql.ok_or(ExecutionStoreError::CorruptRecord(name))?;
    if normalized_sql(&sql) == normalized_sql(expected) {
        Ok(())
    } else {
        Err(ExecutionStoreError::CorruptRecord(name))
    }
}

fn normalized_sql(value: &str) -> String {
    value
        .chars()
        .filter(|value| !value.is_whitespace())
        .collect()
}

type ColumnShape = (&'static str, &'static str, i64, i64);

fn validate_table_columns(connection: &Connection) -> Result<(), ExecutionStoreError> {
    const EXPECTED: &[ColumnShape] = &[
        ("execution_id", "BLOB", 1, 1),
        ("workspace_id", "BLOB", 1, 0),
        ("activity_id", "BLOB", 1, 0),
        ("state", "INTEGER", 1, 0),
        ("mode", "INTEGER", 1, 0),
        ("request_digest", "BLOB", 1, 0),
        ("cwd", "BLOB", 0, 0),
        ("timeout_ms", "INTEGER", 1, 0),
        ("output_limit", "INTEGER", 1, 0),
        ("workspace_read", "INTEGER", 1, 0),
        ("workspace_write", "INTEGER", 1, 0),
        ("network", "INTEGER", 1, 0),
        ("exit_code", "INTEGER", 0, 0),
        ("signal", "INTEGER", 0, 0),
        ("duration_ms", "INTEGER", 0, 0),
        ("stdout", "BLOB", 0, 0),
        ("stdout_total_bytes", "INTEGER", 0, 0),
        ("stdout_truncated", "INTEGER", 0, 0),
        ("stderr", "BLOB", 0, 0),
        ("stderr_total_bytes", "INTEGER", 0, 0),
        ("stderr_truncated", "INTEGER", 0, 0),
        ("failure_code", "INTEGER", 0, 0),
        ("created_at_ms", "INTEGER", 1, 0),
        ("updated_at_ms", "INTEGER", 1, 0),
        ("revision", "INTEGER", 1, 0),
    ];
    let mut statement = connection.prepare("PRAGMA table_info(executions)")?;
    let mut rows = statement.query([])?;
    let mut actual = Vec::new();
    while let Some(row) = rows.next()? {
        if actual.len() >= 32 {
            return Err(ExecutionStoreError::CorruptRecord("executions"));
        }
        actual.push((
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, i64>(5)?,
        ));
    }
    if actual.len() == EXPECTED.len()
        && actual.iter().zip(EXPECTED).all(|(actual, expected)| {
            actual.0 == expected.0
                && actual.1 == expected.1
                && actual.2 == expected.2
                && actual.3 == expected.3
        })
    {
        Ok(())
    } else {
        Err(ExecutionStoreError::CorruptRecord("executions"))
    }
}

fn validate_index_columns(
    connection: &Connection,
    index: &'static str,
    expected: &[&str],
) -> Result<(), ExecutionStoreError> {
    let mut statement = connection.prepare(&format!("PRAGMA index_info({index})"))?;
    let mut rows = statement.query([])?;
    let mut actual = Vec::new();
    while let Some(row) = rows.next()? {
        if actual.len() >= 16 {
            return Err(ExecutionStoreError::CorruptRecord(index));
        }
        actual.push(row.get::<_, String>(2)?);
    }
    if actual
        .iter()
        .map(String::as_str)
        .eq(expected.iter().copied())
    {
        Ok(())
    } else {
        Err(ExecutionStoreError::CorruptRecord(index))
    }
}

fn validate_foreign_keys(
    connection: &Connection,
    table: &'static str,
    expected: usize,
) -> Result<(), ExecutionStoreError> {
    let mut statement = connection.prepare(&format!("PRAGMA foreign_key_list({table})"))?;
    if statement.query_map([], |_| Ok(()))?.count() == expected {
        Ok(())
    } else {
        Err(ExecutionStoreError::CorruptRecord(table))
    }
}

#[derive(Debug, Error)]
pub enum ExecutionStoreError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error("Execution identity conflicts with an existing record")]
    IdentityConflict,
    #[error("Execution record is missing")]
    RecordMissing,
    #[error("Execution Activity is missing")]
    ActivityMissing,
    #[error("Execution Activity is terminal")]
    ActivityTerminal,
    #[error("Execution attribution does not match its Activity")]
    AttributionMismatch,
    #[error("Execution is terminal")]
    Terminal,
    #[error("Execution transition is invalid")]
    InvalidTransition,
    #[error("Execution revision is stale")]
    RevisionConflict,
    #[error("Execution revision overflowed")]
    RevisionOverflow,
    #[error("Execution timestamp precedes durable state")]
    TimestampOrder,
    #[error("Execution integer exceeds SQLite range")]
    IntegerOverflow,
    #[error("corrupt Execution field {0}")]
    CorruptRecord(&'static str),
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::path::PathBuf;

    use forge_domain::{
        ExecutionArgument, ExecutionKind, ExecutionProgram, ExecutionRequest, ExecutionScript,
    };

    use super::*;

    fn fixture() -> Result<(Connection, WorkspaceId, ActivityId), Box<dyn std::error::Error>> {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE workspace(workspace_id BLOB UNIQUE);
             CREATE TABLE activities(
                activity_id BLOB PRIMARY KEY,
                workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id),
                state INTEGER NOT NULL
             );",
        )?;
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(1));
        let activity_id = ActivityId::from_uuid(Uuid::from_u128(2));
        connection.execute(
            "INSERT INTO workspace(workspace_id) VALUES (?1)",
            params![workspace_id.into_uuid().as_bytes()],
        )?;
        connection.execute(
            "INSERT INTO activities(activity_id, workspace_id, state) VALUES (?1, ?2, 1)",
            params![
                activity_id.into_uuid().as_bytes(),
                workspace_id.into_uuid().as_bytes()
            ],
        )?;
        create_schema(&connection)?;
        Ok((connection, workspace_id, activity_id))
    }

    fn request(
        id: u128,
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        shell: bool,
    ) -> Result<ExecutionRequest, Box<dyn std::error::Error>> {
        let kind = if shell {
            ExecutionKind::Shell {
                script: ExecutionScript::new("printf test".to_owned())?,
            }
        } else {
            ExecutionKind::Structured {
                program: ExecutionProgram::new(PathBuf::from("/usr/bin/printf"))?,
                arguments: vec![ExecutionArgument::new(OsString::from("test"))?],
            }
        };
        Ok(ExecutionRequest::new(
            ExecutionAttribution::new(
                ExecutionId::from_uuid(Uuid::from_u128(id)),
                workspace_id,
                activity_id,
            ),
            kind,
            None,
            ExecutionLimits::new(
                ExecutionTimeoutMillis::new(1_000)?,
                ExecutionOutputLimit::new(16)?,
            ),
            ExecutionPermissions::new(true, false, false),
        )?)
    }

    #[test]
    fn schema_constants_match_created_sql_and_shape() -> Result<(), Box<dyn std::error::Error>> {
        let (connection, _, _) = fixture()?;
        for (kind, name, expected) in [
            ("table", "executions", EXPECTED_EXECUTIONS_TABLE_SQL),
            (
                "index",
                "executions_activity_created_idx",
                EXPECTED_EXECUTIONS_ACTIVITY_INDEX_SQL,
            ),
            (
                "index",
                "executions_state_updated_idx",
                EXPECTED_EXECUTIONS_STATE_INDEX_SQL,
            ),
        ] {
            let actual: String = connection.query_row(
                "SELECT sql FROM sqlite_schema WHERE type = ?1 AND name = ?2",
                params![kind, name],
                |row| row.get(0),
            )?;
            assert_eq!(normalized_sql(&actual), normalized_sql(expected), "{name}");
        }
        validate_schema(&connection)?;
        Ok(())
    }

    #[test]
    fn lifecycle_is_cas_guarded_and_evidence_round_trips() -> Result<(), Box<dyn std::error::Error>>
    {
        let (mut connection, workspace_id, activity_id) = fixture()?;
        let request = request(3, workspace_id, activity_id, false)?;
        let starting = begin_execution(
            &mut connection,
            &BeginExecution::from_request(
                &request,
                ExecutionRequestDigest::from_bytes([3; 32]),
                TimestampMillis::new(10)?,
            ),
        )?;
        assert_eq!(starting.status(), BeginExecutionStatus::Created);
        assert_eq!(starting.record().state(), ExecutionState::Starting);
        let retry = begin_execution(
            &mut connection,
            &BeginExecution::from_request(
                &request,
                ExecutionRequestDigest::from_bytes([3; 32]),
                TimestampMillis::new(11)?,
            ),
        )?;
        assert_eq!(retry.status(), BeginExecutionStatus::Existing);
        assert_eq!(retry.record(), starting.record());
        assert!(matches!(
            begin_execution(
                &mut connection,
                &BeginExecution::from_request(
                    &request,
                    ExecutionRequestDigest::from_bytes([4; 32]),
                    TimestampMillis::new(11)?,
                ),
            ),
            Err(ExecutionStoreError::IdentityConflict)
        ));
        let running = mark_execution_running(
            &mut connection,
            MarkExecutionRunning::new(
                starting.record().id(),
                starting.record().revision(),
                TimestampMillis::new(11)?,
            ),
        )?;
        let outcome = ExecutionOutcome::new(
            running.id(),
            ExecutionTermination::new(ExecutionCompletionStatus::Exited, Some(0), None),
            7,
            BoundedExecutionOutput::new(b"ok".to_vec(), 2, false),
            BoundedExecutionOutput::new(Vec::new(), 0, false),
        );
        let completed = complete_execution(
            &mut connection,
            &CompleteExecution::new(running.revision(), TimestampMillis::new(18)?, outcome),
        )?;
        assert_eq!(completed.state(), ExecutionState::Completed);
        assert_eq!(
            completed.outcome().ok_or("outcome")?.stdout().retained(),
            b"ok"
        );
        assert!(matches!(
            fail_execution(
                &mut connection,
                FailExecution::new(
                    completed.id(),
                    completed.revision(),
                    TimestampMillis::new(19)?,
                    ExecutionFailureCode::Supervision,
                ),
            ),
            Err(ExecutionStoreError::Terminal)
        ));
        Ok(())
    }

    #[test]
    fn restart_reconciliation_interrupts_only_bounded_active_rows()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut connection, workspace_id, activity_id) = fixture()?;
        for id in 10..13 {
            let request = request(id, workspace_id, activity_id, true)?;
            let _record = begin_execution(
                &mut connection,
                &BeginExecution::from_request(
                    &request,
                    ExecutionRequestDigest::from_bytes([u8::try_from(id)?; 32]),
                    TimestampMillis::new(i64::try_from(id)?)?,
                ),
            )?;
        }
        let first = reconcile_interrupted_executions(
            &mut connection,
            TimestampMillis::new(20)?,
            ExecutionListLimit::new(2)?,
        )?;
        assert_eq!(first.len(), 2);
        assert!(
            first
                .iter()
                .all(|record| record.state() == ExecutionState::Interrupted)
        );
        let remaining = reconcile_interrupted_executions(
            &mut connection,
            TimestampMillis::new(21)?,
            ExecutionListLimit::new(2)?,
        )?;
        assert_eq!(remaining.len(), 1);
        assert!(
            reconcile_interrupted_executions(
                &mut connection,
                TimestampMillis::new(22)?,
                ExecutionListLimit::new(2)?,
            )?
            .is_empty()
        );
        Ok(())
    }

    #[test]
    fn expired_authority_reconciliation_touches_only_expired_leases()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut connection = Connection::open_in_memory()?;
        connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE workspace(workspace_id BLOB UNIQUE);
             CREATE TABLE activities(
                activity_id BLOB PRIMARY KEY,
                workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id),
                state INTEGER NOT NULL,
                lease_owner_id BLOB CHECK(lease_owner_id IS NULL OR length(lease_owner_id) = 16),
                lease_until_ms INTEGER CHECK(lease_until_ms IS NULL OR lease_until_ms >= 0),
                CHECK((lease_owner_id IS NULL) = (lease_until_ms IS NULL))
             );",
        )?;
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(1));
        connection.execute(
            "INSERT INTO workspace(workspace_id) VALUES (?1)",
            params![workspace_id.into_uuid().as_bytes()],
        )?;
        create_schema(&connection)?;
        for (raw_id, lease_until) in [(2_u128, Some(10_i64)), (3, Some(10_000)), (4, None)] {
            let activity_id = ActivityId::from_uuid(Uuid::from_u128(raw_id));
            let owner = Uuid::from_u128(0x900 + raw_id);
            match lease_until {
                Some(until) => connection.execute(
                    "INSERT INTO activities (
                        activity_id, workspace_id, state,
                        lease_owner_id, lease_until_ms
                     ) VALUES (?1, ?2, 1, ?3, ?4)",
                    params![
                        activity_id.into_uuid().as_bytes(),
                        workspace_id.into_uuid().as_bytes(),
                        owner.as_bytes().as_slice(),
                        until,
                    ],
                )?,
                None => connection.execute(
                    "INSERT INTO activities (
                        activity_id, workspace_id, state
                     ) VALUES (?1, ?2, 1)",
                    params![
                        activity_id.into_uuid().as_bytes(),
                        workspace_id.into_uuid().as_bytes(),
                    ],
                )?,
            };
            let _started = begin_execution(
                &mut connection,
                &BeginExecution::from_request(
                    &request(raw_id * 10, workspace_id, activity_id, false)?,
                    ExecutionRequestDigest::from_bytes(
                        [u8::try_from(raw_id).unwrap_or(u8::MAX); 32],
                    ),
                    TimestampMillis::new(20)?,
                ),
            )?;
        }

        // Only the expired-lease Activity's Starting execution is classified;
        // the live-lease and unleased executions remain untouched.
        let reconciled = reconcile_expired_authority_executions(
            &mut connection,
            TimestampMillis::new(1_000)?,
            ExecutionListLimit::new(8)?,
        )?;
        assert_eq!(reconciled.len(), 1);
        assert_eq!(
            reconciled[0].activity_id(),
            ActivityId::from_uuid(Uuid::from_u128(2))
        );
        assert_eq!(reconciled[0].state(), ExecutionState::Interrupted);

        // Live-lease and unleased executions stay Starting.
        for untouched in [30_u128, 40] {
            let record = get_execution(
                &connection,
                ExecutionId::from_uuid(Uuid::from_u128(untouched)),
            )?
            .ok_or("untouched execution missing")?;
            assert_eq!(record.state(), ExecutionState::Starting, "{untouched}");
        }
        Ok(())
    }
}
