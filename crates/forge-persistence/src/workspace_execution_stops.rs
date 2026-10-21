//! Durable capture of the finite cohort observed by a Workspace execution stop.
//!
//! This module owns only the SQLite receipt.  A captured row fences fresh
//! execution beginnings and records the exact active or interrupted execution rows observed
//! by the caller transaction.  Native cancellation, process ownership, and
//! terminal settlement deliberately live above this persistence boundary.

use forge_domain::{
    ExecutionId, ExecutionRevision, ExecutionState, RuntimeInstanceId, TimestampMillis, WorkspaceId,
};
use rusqlite::{Connection, OptionalExtension, Row, Transaction, params};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

pub(crate) mod settlement;

const ID_BYTES: usize = 16;
const DIGEST_BYTES: usize = 32;
const MAX_TARGETS: usize = 256;
const PROBE_TARGETS: usize = MAX_TARGETS + 1;
const PROBE_TARGETS_I64: i64 = 257;
const MAX_SCHEMA_SQL_BYTES: usize = 16 * 1024;
const MAX_SCHEMA_METADATA_ROWS: usize = 64;

#[derive(Debug)]
struct BoundedBlob {
    length: i64,
    bytes: Vec<u8>,
}

impl BoundedBlob {
    fn from_row(row: &Row<'_>, length_index: usize, bytes_index: usize) -> rusqlite::Result<Self> {
        Ok(Self {
            length: row.get(length_index)?,
            bytes: row.get(bytes_index)?,
        })
    }
}

#[derive(Debug)]
struct RawStop {
    stop_id: BoundedBlob,
    workspace_id: BoundedBlob,
    request_id: BoundedBlob,
    owner_runtime_instance_id: BoundedBlob,
    request_digest: BoundedBlob,
    binding_digest: BoundedBlob,
    target_count: i64,
    cohort_digest: BoundedBlob,
    created_at: i64,
}

/// The one canonical SQL authority for the execution-stop capture journal.
///
/// There is intentionally no mutable stop or target status column yet.  Every
/// durable row is pending until a later settlement owner is introduced.
const STOPS_TABLE_SQL: &str = "CREATE TABLE workspace_execution_stops (stop_id BLOB PRIMARY KEY NOT NULL CHECK(length(stop_id) = 16), workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16), request_id BLOB NOT NULL CHECK(length(request_id) = 16), owner_runtime_instance_id BLOB NOT NULL CHECK(length(owner_runtime_instance_id) = 16), request_digest BLOB NOT NULL CHECK(length(request_digest) = 32), binding_digest BLOB NOT NULL CHECK(length(binding_digest) = 32), target_count INTEGER NOT NULL CHECK(target_count BETWEEN 0 AND 256), cohort_digest BLOB NOT NULL CHECK(length(cohort_digest) = 32), created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0), UNIQUE(workspace_id, request_id))";
const STOPS_TABLE_SQL_V59: &str = "CREATE TABLE workspace_execution_stops (stop_id BLOB PRIMARY KEY NOT NULL CHECK(length(stop_id) = 16), workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16), request_id BLOB NOT NULL CHECK(length(request_id) = 16), owner_runtime_instance_id BLOB NOT NULL CHECK(length(owner_runtime_instance_id) = 16), request_digest BLOB NOT NULL CHECK(length(request_digest) = 32), binding_digest BLOB NOT NULL CHECK(length(binding_digest) = 32), target_count INTEGER NOT NULL CHECK(target_count BETWEEN 0 AND 256), cohort_digest BLOB NOT NULL CHECK(length(cohort_digest) = 32), created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0), UNIQUE(workspace_id, request_id), UNIQUE(workspace_id))";

const TARGETS_TABLE_SQL: &str = "CREATE TABLE workspace_execution_stop_targets (stop_id BLOB NOT NULL REFERENCES workspace_execution_stops(stop_id) CHECK(length(stop_id) = 16), ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 0 AND 255), execution_id BLOB NOT NULL REFERENCES executions(execution_id) CHECK(length(execution_id) = 16), expected_revision INTEGER NOT NULL CHECK(expected_revision >= 1), expected_state INTEGER NOT NULL CHECK(expected_state IN (0, 1, 6)), request_digest BLOB NOT NULL CHECK(length(request_digest) = 32), PRIMARY KEY(stop_id, ordinal), UNIQUE(stop_id, execution_id))";

const OBJECTS: [(&str, &str, &str); 2] = [
    ("table", "workspace_execution_stops", STOPS_TABLE_SQL),
    (
        "table",
        "workspace_execution_stop_targets",
        TARGETS_TABLE_SQL,
    ),
];

const OBJECTS_V59: [(&str, &str, &str); 2] = [
    ("table", "workspace_execution_stops", STOPS_TABLE_SQL_V59),
    (
        "table",
        "workspace_execution_stop_targets",
        TARGETS_TABLE_SQL,
    ),
];

/// Maximum number of active or interrupted executions captured by one stop request.
pub const MAX_EXECUTION_STOP_TARGETS: usize = MAX_TARGETS;

/// A request to capture the current active execution cohort for one Workspace.
///
/// The observation timestamp is stored as the receipt creation time, but is
/// intentionally excluded from replay identity.  A retry after a lost reply
/// can therefore use a newly observed timestamp while still reading back the
/// original immutable request and cohort.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionStopRequest {
    stop_id: Uuid,
    workspace_id: WorkspaceId,
    request_id: Uuid,
    owner_runtime_instance_id: RuntimeInstanceId,
    request_digest: [u8; DIGEST_BYTES],
    observed_at: TimestampMillis,
}

impl ExecutionStopRequest {
    pub const fn new(
        stop_id: Uuid,
        workspace_id: WorkspaceId,
        request_id: Uuid,
        owner_runtime_instance_id: RuntimeInstanceId,
        request_digest: [u8; DIGEST_BYTES],
        observed_at: TimestampMillis,
    ) -> Self {
        Self {
            stop_id,
            workspace_id,
            request_id,
            owner_runtime_instance_id,
            request_digest,
            observed_at,
        }
    }

    pub const fn stop_id(&self) -> Uuid {
        self.stop_id
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn request_id(&self) -> Uuid {
        self.request_id
    }

    pub const fn owner_runtime_instance_id(&self) -> RuntimeInstanceId {
        self.owner_runtime_instance_id
    }

    pub const fn request_digest(&self) -> &[u8; DIGEST_BYTES] {
        &self.request_digest
    }

    pub const fn observed_at(&self) -> TimestampMillis {
        self.observed_at
    }
}

/// A stop capture remains pending until a future settlement owner proves that
/// native cancellation and durable terminal evidence have completed.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExecutionStopStatus {
    Pending,
    Completed,
}

/// A target has no mutable process or terminal claim in this first journal.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExecutionStopTargetStatus {
    Pending,
    Closed,
}

/// The result classification of a capture transaction.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExecutionStopCaptureStatus {
    Captured,
    Existing,
}

/// One active or interrupted execution captured by a stop receipt.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionStopTarget {
    ordinal: u8,
    execution_id: ExecutionId,
    expected_revision: ExecutionRevision,
    expected_state: ExecutionState,
    request_digest: [u8; DIGEST_BYTES],
    status: ExecutionStopTargetStatus,
}

impl ExecutionStopTarget {
    const fn new(
        ordinal: u8,
        execution_id: ExecutionId,
        expected_revision: ExecutionRevision,
        expected_state: ExecutionState,
        request_digest: [u8; DIGEST_BYTES],
    ) -> Self {
        Self {
            ordinal,
            execution_id,
            expected_revision,
            expected_state,
            request_digest,
            status: ExecutionStopTargetStatus::Pending,
        }
    }

    pub const fn ordinal(&self) -> u8 {
        self.ordinal
    }

    pub const fn execution_id(&self) -> ExecutionId {
        self.execution_id
    }

    pub const fn expected_revision(&self) -> ExecutionRevision {
        self.expected_revision
    }

    pub const fn expected_state(&self) -> ExecutionState {
        self.expected_state
    }

    pub const fn request_digest(&self) -> &[u8; DIGEST_BYTES] {
        &self.request_digest
    }

    pub const fn status(&self) -> ExecutionStopTargetStatus {
        self.status
    }

    pub(super) const fn with_status(self, status: ExecutionStopTargetStatus) -> Self {
        Self { status, ..self }
    }
}

/// The immutable receipt and its bounded active execution cohort.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionStopRecord {
    stop_id: Uuid,
    workspace_id: WorkspaceId,
    request_id: Uuid,
    owner_runtime_instance_id: RuntimeInstanceId,
    request_digest: [u8; DIGEST_BYTES],
    binding_digest: [u8; DIGEST_BYTES],
    target_count: usize,
    cohort_digest: [u8; DIGEST_BYTES],
    created_at: TimestampMillis,
    status: ExecutionStopStatus,
    targets: Vec<ExecutionStopTarget>,
}

impl ExecutionStopRecord {
    fn new(
        request: &ExecutionStopRequest,
        binding_digest: [u8; DIGEST_BYTES],
        targets: Vec<ExecutionStopTarget>,
    ) -> Self {
        let target_count = targets.len();
        let cohort_digest = cohort_digest(&targets);
        Self {
            stop_id: request.stop_id(),
            workspace_id: request.workspace_id(),
            request_id: request.request_id(),
            owner_runtime_instance_id: request.owner_runtime_instance_id(),
            request_digest: *request.request_digest(),
            binding_digest,
            target_count,
            cohort_digest,
            created_at: request.observed_at(),
            status: ExecutionStopStatus::Pending,
            targets,
        }
    }

    pub const fn stop_id(&self) -> Uuid {
        self.stop_id
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn request_id(&self) -> Uuid {
        self.request_id
    }

    pub const fn owner_runtime_instance_id(&self) -> RuntimeInstanceId {
        self.owner_runtime_instance_id
    }

    pub const fn request_digest(&self) -> &[u8; DIGEST_BYTES] {
        &self.request_digest
    }

    pub const fn binding_digest(&self) -> &[u8; DIGEST_BYTES] {
        &self.binding_digest
    }

    pub const fn target_count(&self) -> usize {
        self.target_count
    }

    pub const fn cohort_digest(&self) -> &[u8; DIGEST_BYTES] {
        &self.cohort_digest
    }

    pub const fn created_at(&self) -> TimestampMillis {
        self.created_at
    }

    pub const fn status(&self) -> ExecutionStopStatus {
        self.status
    }

    pub fn targets(&self) -> &[ExecutionStopTarget] {
        &self.targets
    }

    pub(super) fn with_statuses(
        self,
        status: ExecutionStopStatus,
        target_statuses: &[ExecutionStopTargetStatus],
    ) -> Result<Self, ()> {
        if target_statuses.len() != self.targets.len() {
            return Err(());
        }
        let Self {
            stop_id,
            workspace_id,
            request_id,
            owner_runtime_instance_id,
            request_digest,
            binding_digest,
            target_count,
            cohort_digest,
            created_at,
            targets: current_targets,
            ..
        } = self;
        let targets = current_targets
            .into_iter()
            .zip(target_statuses.iter().copied())
            .map(|(target, status)| target.with_status(status))
            .collect();
        Ok(Self {
            stop_id,
            workspace_id,
            request_id,
            owner_runtime_instance_id,
            request_digest,
            binding_digest,
            target_count,
            cohort_digest,
            created_at,
            status,
            targets,
        })
    }
}

/// The capture result, including whether the durable row was newly inserted
/// or was an exact replay of an already committed request.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionStopCapture {
    capture_status: ExecutionStopCaptureStatus,
    record: ExecutionStopRecord,
}

impl ExecutionStopCapture {
    const fn new(capture_status: ExecutionStopCaptureStatus, record: ExecutionStopRecord) -> Self {
        Self {
            capture_status,
            record,
        }
    }

    pub const fn capture_status(&self) -> ExecutionStopCaptureStatus {
        self.capture_status
    }

    pub const fn status(&self) -> ExecutionStopStatus {
        self.record.status()
    }

    pub const fn is_existing(&self) -> bool {
        matches!(self.capture_status, ExecutionStopCaptureStatus::Existing)
    }

    pub const fn record(&self) -> &ExecutionStopRecord {
        &self.record
    }

    pub fn into_record(self) -> ExecutionStopRecord {
        self.record
    }
}

/// Errors raised by the execution-stop journal or its checked row codec.
#[derive(Debug, Error)]
pub enum ExecutionStopStoreError {
    #[error(transparent)]
    Approval(Box<crate::ApprovalStoreError>),
    #[error(transparent)]
    Execution(Box<crate::ExecutionStoreError>),
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error("execution-stop request conflicts with an existing pending Workspace fence")]
    Conflict,
    #[error("execution-stop cohort has {actual} active executions; maximum is {maximum}")]
    Overflow { actual: usize, maximum: usize },
    #[error("execution-stop durable record is corrupt: {0}")]
    Corrupt(&'static str),
    #[error("execution-stop schema object is damaged: {0}")]
    DamagedSchema(&'static str),
    #[error("execution-stop schema metadata exceeds the bounded decoder")]
    SchemaMetadataTooLarge,
    #[error("execution-stop settlement remains pending because positive closure proof is missing")]
    SettlementPending,
    #[error("execution-stop settlement conflicts with its captured or authority receipt")]
    SettlementConflict,
}

/// Create both execution-stop tables inside the caller's transaction.
pub(crate) fn create_schema(connection: &Connection) -> Result<(), ExecutionStopStoreError> {
    for (_, _, sql) in OBJECTS {
        connection.execute_batch(sql)?;
    }
    Ok(())
}

/// Create the schema-59 capture tables used by the historical migration
/// chain. Settlement/fence tables are added only by the schema-60 owner.
pub(crate) fn create_schema_v59(connection: &Connection) -> Result<(), ExecutionStopStoreError> {
    for (_, _, sql) in OBJECTS_V59 {
        connection.execute_batch(sql)?;
    }
    Ok(())
}

/// Return the schema objects owned by this module.
pub(crate) const fn schema_objects() -> [(&'static str, &'static str); 2] {
    [
        ("table", "workspace_execution_stops"),
        ("table", "workspace_execution_stop_targets"),
    ]
}

/// Validate the canonical DDL and its bounded column/foreign-key shape.
pub(crate) fn validate_schema(connection: &Connection) -> Result<(), ExecutionStopStoreError> {
    validate_schema_objects(connection, &OBJECTS)
}

pub(crate) fn validate_schema_v59(connection: &Connection) -> Result<(), ExecutionStopStoreError> {
    validate_schema_objects(connection, &OBJECTS_V59)
}

fn validate_schema_objects(
    connection: &Connection,
    objects: &[(&'static str, &'static str, &'static str)],
) -> Result<(), ExecutionStopStoreError> {
    for &(kind, name, expected) in objects {
        let sql_length: Option<i64> = connection
            .query_row(
                "SELECT length(CAST(sql AS BLOB)) FROM sqlite_schema
                 WHERE type = ?1 AND name = ?2",
                params![kind, name],
                |row| row.get(0),
            )
            .optional()?;
        let Some(sql_length) = sql_length else {
            return Err(ExecutionStopStoreError::DamagedSchema(name));
        };
        let sql_length = usize::try_from(sql_length)
            .map_err(|_| ExecutionStopStoreError::DamagedSchema(name))?;
        if sql_length > MAX_SCHEMA_SQL_BYTES {
            return Err(ExecutionStopStoreError::DamagedSchema(name));
        }
        let actual: String = connection.query_row(
            "SELECT sql FROM sqlite_schema WHERE type = ?1 AND name = ?2",
            params![kind, name],
            |row| row.get(0),
        )?;
        if normalize_sql(&actual) != normalize_sql(expected) {
            return Err(ExecutionStopStoreError::DamagedSchema(name));
        }
    }
    validate_columns(
        connection,
        "workspace_execution_stops",
        &[
            ("stop_id", "BLOB", 1, 1),
            ("workspace_id", "BLOB", 1, 0),
            ("request_id", "BLOB", 1, 0),
            ("owner_runtime_instance_id", "BLOB", 1, 0),
            ("request_digest", "BLOB", 1, 0),
            ("binding_digest", "BLOB", 1, 0),
            ("target_count", "INTEGER", 1, 0),
            ("cohort_digest", "BLOB", 1, 0),
            ("created_at_ms", "INTEGER", 1, 0),
        ],
    )?;
    validate_columns(
        connection,
        "workspace_execution_stop_targets",
        &[
            ("stop_id", "BLOB", 1, 1),
            ("ordinal", "INTEGER", 1, 2),
            ("execution_id", "BLOB", 1, 0),
            ("expected_revision", "INTEGER", 1, 0),
            ("expected_state", "INTEGER", 1, 0),
            ("request_digest", "BLOB", 1, 0),
        ],
    )?;
    validate_foreign_keys(
        connection,
        "workspace_execution_stops",
        &[("workspace", "workspace_id", "workspace_id")],
    )?;
    validate_foreign_keys(
        connection,
        "workspace_execution_stop_targets",
        &[
            ("workspace_execution_stops", "stop_id", "stop_id"),
            ("executions", "execution_id", "execution_id"),
        ],
    )?;
    Ok(())
}

/// Rebuild the capture tables from the schema-59 shape to schema-60 without
/// opening or committing a nested transaction. The caller disables SQLite
/// foreign-key enforcement before beginning its Immediate migration
/// transaction and restores it on every exit.
pub(crate) fn rebuild_capture_v60(
    transaction: &Transaction<'_>,
) -> Result<(), ExecutionStopStoreError> {
    let temporary_sql = STOPS_TABLE_SQL.replace(
        "CREATE TABLE workspace_execution_stops ",
        "CREATE TABLE workspace_execution_stops_v60 ",
    );
    transaction.execute_batch(&temporary_sql)?;
    transaction.execute(
        "INSERT INTO workspace_execution_stops_v60(
            stop_id, workspace_id, request_id, owner_runtime_instance_id,
            request_digest, binding_digest, target_count, cohort_digest, created_at_ms
         )
         SELECT stop_id, workspace_id, request_id, owner_runtime_instance_id,
            request_digest, binding_digest, target_count, cohort_digest, created_at_ms
         FROM workspace_execution_stops
         ORDER BY stop_id",
        [],
    )?;
    transaction.execute("DROP TABLE workspace_execution_stops", [])?;
    transaction.execute(
        "ALTER TABLE workspace_execution_stops_v60 RENAME TO workspace_execution_stops",
        [],
    )?;
    Ok(())
}

/// Test-only inverse of the schema-60 capture rebuild. The caller must have
/// disabled foreign-key enforcement and must remove schema-60 settlement
/// tables before invoking this helper.
#[cfg(test)]
pub(crate) fn rebuild_capture_v59_fixture(
    connection: &Connection,
) -> Result<(), ExecutionStopStoreError> {
    let transaction = connection.unchecked_transaction()?;
    let temporary_sql = STOPS_TABLE_SQL_V59.replace(
        "CREATE TABLE workspace_execution_stops ",
        "CREATE TABLE workspace_execution_stops_v59 ",
    );
    transaction.execute_batch(&temporary_sql)?;
    transaction.execute(
        "INSERT INTO workspace_execution_stops_v59(
            stop_id, workspace_id, request_id, owner_runtime_instance_id,
            request_digest, binding_digest, target_count, cohort_digest, created_at_ms
         )
         SELECT stop_id, workspace_id, request_id, owner_runtime_instance_id,
            request_digest, binding_digest, target_count, cohort_digest, created_at_ms
         FROM workspace_execution_stops
         ORDER BY stop_id",
        [],
    )?;
    transaction.execute("DROP TABLE workspace_execution_stops", [])?;
    transaction.execute(
        "ALTER TABLE workspace_execution_stops_v59 RENAME TO workspace_execution_stops",
        [],
    )?;
    transaction.commit()?;
    Ok(())
}

fn normalize_sql(sql: &str) -> String {
    // SQLite quotes the owned table identifier after ALTER TABLE RENAME.
    // Preserve every constraint/token; normalize only these closed identifiers.
    let sql = sql
        .replace("\"workspace_execution_stops\"", "workspace_execution_stops")
        .replace(
            "\"workspace_execution_stop_targets\"",
            "workspace_execution_stop_targets",
        );
    sql.chars()
        .filter(|character| !character.is_whitespace())
        .map(|character| character.to_ascii_lowercase())
        .collect()
}

fn validate_columns(
    connection: &Connection,
    table: &'static str,
    expected: &[(&str, &str, i64, i64)],
) -> Result<(), ExecutionStopStoreError> {
    let mut statement = connection.prepare(&format!("PRAGMA table_info({table})"))?;
    let mut rows = statement.query([])?;
    let mut actual = Vec::new();
    while let Some(row) = rows.next()? {
        if actual.len() >= MAX_SCHEMA_METADATA_ROWS {
            return Err(ExecutionStopStoreError::SchemaMetadataTooLarge);
        }
        actual.push((
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, i64>(5)?,
        ));
    }
    if actual.len() != expected.len()
        || actual.iter().zip(expected).any(|(actual, expected)| {
            actual.0 != expected.0
                || actual.1 != expected.1
                || actual.2 != expected.2
                || actual.3 != expected.3
        })
    {
        return Err(ExecutionStopStoreError::DamagedSchema(table));
    }
    Ok(())
}

fn validate_foreign_keys(
    connection: &Connection,
    table: &'static str,
    expected: &[(&str, &str, &str)],
) -> Result<(), ExecutionStopStoreError> {
    let mut statement = connection.prepare(&format!("PRAGMA foreign_key_list({table})"))?;
    let mut rows = statement.query([])?;
    let mut actual = Vec::new();
    while let Some(row) = rows.next()? {
        if actual.len() >= MAX_SCHEMA_METADATA_ROWS {
            return Err(ExecutionStopStoreError::SchemaMetadataTooLarge);
        }
        actual.push((
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
        ));
    }
    if actual.len() != expected.len()
        || expected.iter().any(|expected| {
            !actual.iter().any(|actual| {
                actual.0 == expected.0 && actual.1 == expected.1 && actual.2 == expected.2
            })
        })
    {
        return Err(ExecutionStopStoreError::DamagedSchema(table));
    }
    Ok(())
}

/// Capture the current active cohort in the caller's transaction.
///
/// The transaction owner decides when this record commits.  This function
/// never commits or starts a transaction of its own, which keeps the stop
/// fence atomic with the caller's Workspace mutation.
pub(crate) fn capture_in_transaction(
    transaction: &Transaction<'_>,
    request: &ExecutionStopRequest,
    binding_digest: [u8; DIGEST_BYTES],
) -> Result<ExecutionStopCapture, ExecutionStopStoreError> {
    if let Some(existing) = historical_request_record_in_transaction(transaction, request)? {
        if record_matches(&existing, request, &binding_digest) {
            return Ok(ExecutionStopCapture::new(
                ExecutionStopCaptureStatus::Existing,
                existing,
            ));
        }
        return Err(ExecutionStopStoreError::Conflict);
    }
    if let Some(existing_stop_id) = pending_stop_id(transaction, request.workspace_id())? {
        let capture = load_capture_record(transaction, existing_stop_id)?
            .ok_or(ExecutionStopStoreError::Corrupt("pending stop disappeared"))?;
        let record = if settlement::schema_available(transaction)? {
            settlement::hydrate_record_in_transaction(transaction, capture)?
        } else {
            capture
        };
        if record_matches(&record, request, &binding_digest) {
            return Ok(ExecutionStopCapture::new(
                ExecutionStopCaptureStatus::Existing,
                record,
            ));
        }
        return Err(ExecutionStopStoreError::Conflict);
    }

    let targets = active_targets(transaction, request.workspace_id())?;
    if targets.len() > MAX_TARGETS {
        return Err(ExecutionStopStoreError::Overflow {
            actual: targets.len(),
            maximum: MAX_TARGETS,
        });
    }
    let record = ExecutionStopRecord::new(request, binding_digest, targets);

    transaction.execute(
        "INSERT INTO workspace_execution_stops(
            stop_id, workspace_id, request_id, owner_runtime_instance_id,
            request_digest, binding_digest, target_count, cohort_digest, created_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            record.stop_id().as_bytes(),
            record.workspace_id().into_uuid().as_bytes(),
            record.request_id().as_bytes(),
            record.owner_runtime_instance_id().into_uuid().as_bytes(),
            record.request_digest().as_slice(),
            record.binding_digest().as_slice(),
            i64::try_from(record.target_count()).map_err(|_| {
                ExecutionStopStoreError::Overflow {
                    actual: record.target_count(),
                    maximum: MAX_TARGETS,
                }
            })?,
            record.cohort_digest().as_slice(),
            record.created_at().get(),
        ],
    )?;
    for target in record.targets() {
        transaction.execute(
            "INSERT INTO workspace_execution_stop_targets(
                stop_id, ordinal, execution_id, expected_revision,
                expected_state, request_digest
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                record.stop_id().as_bytes(),
                i64::from(target.ordinal()),
                target.execution_id().into_uuid().as_bytes(),
                target.expected_revision().get(),
                encode_state(target.expected_state()),
                target.request_digest().as_slice(),
            ],
        )?;
    }
    if settlement::schema_available(transaction)? {
        settlement::insert_fence_in_transaction(
            transaction,
            record.workspace_id(),
            record.stop_id(),
        )?;
    }
    Ok(ExecutionStopCapture::new(
        ExecutionStopCaptureStatus::Captured,
        record,
    ))
}

/// Read back one exact request and its immutable cohort.
pub(crate) fn get_for_request(
    connection: &Connection,
    request: &ExecutionStopRequest,
    binding_digest: [u8; DIGEST_BYTES],
) -> Result<Option<ExecutionStopRecord>, ExecutionStopStoreError> {
    let Some(record) = historical_request_record(connection, request)? else {
        return Ok(None);
    };
    if record_matches(&record, request, &binding_digest) {
        Ok(Some(record))
    } else {
        Err(ExecutionStopStoreError::Conflict)
    }
}

/// Reject a new execution while a Workspace has an unsettled stop capture.
pub(crate) fn ensure_execution_open(
    connection: &Connection,
    workspace_id: WorkspaceId,
) -> Result<(), ExecutionStopStoreError> {
    if pending_stop_id(connection, workspace_id)?.is_some() {
        Err(ExecutionStopStoreError::Conflict)
    } else {
        Ok(())
    }
}

fn pending_stop_id(
    connection: &Connection,
    workspace_id: WorkspaceId,
) -> Result<Option<Uuid>, ExecutionStopStoreError> {
    if settlement::schema_available(connection)? {
        return settlement::active_fence_stop_id(connection, workspace_id);
    }
    let row: Option<(i64, Vec<u8>)> = connection
        .query_row(
            "SELECT length(CAST(stop_id AS BLOB)),
                    substr(CAST(stop_id AS BLOB), 1, 16)
             FROM workspace_execution_stops WHERE workspace_id = ?1",
            params![workspace_id.into_uuid().as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    row.map(|(length, bytes)| decode_uuid(length, bytes, "stop_id"))
        .transpose()
}

fn historical_request_record(
    connection: &Connection,
    request: &ExecutionStopRequest,
) -> Result<Option<ExecutionStopRecord>, ExecutionStopStoreError> {
    let stop_id = connection
        .query_row(
            "SELECT length(CAST(stop_id AS BLOB)),
                    substr(CAST(stop_id AS BLOB), 1, 16)
             FROM workspace_execution_stops
             WHERE workspace_id = ?1 AND request_id = ?2",
            params![
                request.workspace_id().into_uuid().as_bytes(),
                request.request_id().as_bytes(),
            ],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()?;
    let Some((length, bytes)) = stop_id else {
        return Ok(None);
    };
    let stop_id = decode_uuid(length, bytes, "stop_id")?;
    let Some(record) = load_record(connection, stop_id)? else {
        return Err(ExecutionStopStoreError::Corrupt(
            "historical stop disappeared",
        ));
    };
    if record.status() == ExecutionStopStatus::Pending
        && settlement::schema_available(connection)?
        && settlement::active_fence_stop_id(connection, record.workspace_id())? != Some(stop_id)
    {
        return Err(ExecutionStopStoreError::Corrupt(
            "pending stop fence missing",
        ));
    }
    Ok(Some(record))
}

fn historical_request_record_in_transaction(
    transaction: &Transaction<'_>,
    request: &ExecutionStopRequest,
) -> Result<Option<ExecutionStopRecord>, ExecutionStopStoreError> {
    let stop_id = transaction
        .query_row(
            "SELECT length(CAST(stop_id AS BLOB)),
                    substr(CAST(stop_id AS BLOB), 1, 16)
             FROM workspace_execution_stops
             WHERE workspace_id = ?1 AND request_id = ?2",
            params![
                request.workspace_id().into_uuid().as_bytes(),
                request.request_id().as_bytes(),
            ],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()?;
    let Some((length, bytes)) = stop_id else {
        return Ok(None);
    };
    let stop_id = decode_uuid(length, bytes, "stop_id")?;
    let Some(record) = load_capture_record(transaction, stop_id)? else {
        return Ok(None);
    };
    if settlement::schema_available(transaction)? {
        if record.status() == ExecutionStopStatus::Pending
            && settlement::active_fence_stop_id(transaction, record.workspace_id())?
                != Some(stop_id)
        {
            return Err(ExecutionStopStoreError::Corrupt(
                "pending stop fence missing",
            ));
        }
        settlement::hydrate_record_in_transaction(transaction, record).map(Some)
    } else {
        Ok(Some(record))
    }
}

fn active_targets(
    connection: &Connection,
    workspace_id: WorkspaceId,
) -> Result<Vec<ExecutionStopTarget>, ExecutionStopStoreError> {
    let mut statement = connection.prepare(
        "SELECT length(CAST(execution_id AS BLOB)),
                substr(CAST(execution_id AS BLOB), 1, 16),
                revision, state,
                length(CAST(request_digest AS BLOB)),
                substr(CAST(request_digest AS BLOB), 1, 32)
         FROM executions
         WHERE workspace_id = ?1 AND state IN (0, 1, 6)
         ORDER BY execution_id
         LIMIT ?2",
    )?;
    let mut rows = statement.query(params![
        workspace_id.into_uuid().as_bytes(),
        PROBE_TARGETS_I64,
    ])?;
    let mut targets = Vec::new();
    while let Some(row) = rows.next()? {
        if targets.len() >= PROBE_TARGETS {
            return Err(ExecutionStopStoreError::Overflow {
                actual: targets.len() + 1,
                maximum: MAX_TARGETS,
            });
        }
        let execution_id = decode_uuid(row.get(0)?, row.get(1)?, "execution_id")?;
        let expected_revision = ExecutionRevision::new(row.get::<_, i64>(2)?)
            .map_err(|_| ExecutionStopStoreError::Corrupt("expected revision"))?;
        let expected_state = decode_state(row.get::<_, i64>(3)?)?;
        let request_digest = decode_digest(row.get(4)?, row.get(5)?, "target request digest")?;
        targets.push(ExecutionStopTarget::new(
            u8::try_from(targets.len()).map_err(|_| ExecutionStopStoreError::Overflow {
                actual: targets.len() + 1,
                maximum: MAX_TARGETS,
            })?,
            ExecutionId::from_uuid(execution_id),
            expected_revision,
            expected_state,
            request_digest,
        ));
    }
    Ok(targets)
}

fn load_capture_record(
    connection: &Connection,
    stop_id: Uuid,
) -> Result<Option<ExecutionStopRecord>, ExecutionStopStoreError> {
    let row: Option<RawStop> = connection
        .query_row(
            "SELECT length(CAST(stop_id AS BLOB)),
                    substr(CAST(stop_id AS BLOB), 1, 16),
                    length(CAST(workspace_id AS BLOB)),
                    substr(CAST(workspace_id AS BLOB), 1, 16),
                    length(CAST(request_id AS BLOB)),
                    substr(CAST(request_id AS BLOB), 1, 16),
                    length(CAST(owner_runtime_instance_id AS BLOB)),
                    substr(CAST(owner_runtime_instance_id AS BLOB), 1, 16),
                    length(CAST(request_digest AS BLOB)),
                    substr(CAST(request_digest AS BLOB), 1, 32),
                    length(CAST(binding_digest AS BLOB)),
                    substr(CAST(binding_digest AS BLOB), 1, 32),
                    target_count,
                    length(CAST(cohort_digest AS BLOB)),
                    substr(CAST(cohort_digest AS BLOB), 1, 32),
                    created_at_ms
             FROM workspace_execution_stops WHERE stop_id = ?1",
            params![stop_id.as_bytes()],
            |row| {
                Ok(RawStop {
                    stop_id: BoundedBlob::from_row(row, 0, 1)?,
                    workspace_id: BoundedBlob::from_row(row, 2, 3)?,
                    request_id: BoundedBlob::from_row(row, 4, 5)?,
                    owner_runtime_instance_id: BoundedBlob::from_row(row, 6, 7)?,
                    request_digest: BoundedBlob::from_row(row, 8, 9)?,
                    binding_digest: BoundedBlob::from_row(row, 10, 11)?,
                    target_count: row.get(12)?,
                    cohort_digest: BoundedBlob::from_row(row, 13, 14)?,
                    created_at: row.get(15)?,
                })
            },
        )
        .optional()?;
    let Some(raw) = row else {
        return Ok(None);
    };
    let target_count = raw.target_count;
    if !(0..=256).contains(&target_count) {
        return Err(ExecutionStopStoreError::Corrupt("target count"));
    }
    let stop_id = decode_uuid(raw.stop_id.length, raw.stop_id.bytes, "stop_id")?;
    let workspace_id = WorkspaceId::from_uuid(decode_uuid(
        raw.workspace_id.length,
        raw.workspace_id.bytes,
        "workspace_id",
    )?);
    let request_id = decode_uuid(raw.request_id.length, raw.request_id.bytes, "request_id")?;
    let owner_runtime_instance_id = RuntimeInstanceId::from_uuid(decode_uuid(
        raw.owner_runtime_instance_id.length,
        raw.owner_runtime_instance_id.bytes,
        "owner runtime instance id",
    )?);
    let request_digest = decode_digest(
        raw.request_digest.length,
        raw.request_digest.bytes,
        "request digest",
    )?;
    let binding_digest = decode_digest(
        raw.binding_digest.length,
        raw.binding_digest.bytes,
        "binding digest",
    )?;
    let persisted_cohort_digest = decode_digest(
        raw.cohort_digest.length,
        raw.cohort_digest.bytes,
        "cohort digest",
    )?;
    let created_at = TimestampMillis::new(raw.created_at)
        .map_err(|_| ExecutionStopStoreError::Corrupt("created timestamp"))?;

    let targets = load_targets(connection, stop_id, workspace_id)?;
    let target_count = usize::try_from(target_count)
        .map_err(|_| ExecutionStopStoreError::Corrupt("target count"))?;
    if targets.len() != target_count || cohort_digest(&targets) != persisted_cohort_digest {
        return Err(ExecutionStopStoreError::Corrupt("cohort integrity"));
    }
    Ok(Some(ExecutionStopRecord {
        stop_id,
        workspace_id,
        request_id,
        owner_runtime_instance_id,
        request_digest,
        binding_digest,
        target_count,
        cohort_digest: persisted_cohort_digest,
        created_at,
        status: ExecutionStopStatus::Pending,
        targets,
    }))
}

fn load_record(
    connection: &Connection,
    stop_id: Uuid,
) -> Result<Option<ExecutionStopRecord>, ExecutionStopStoreError> {
    let Some(record) = load_capture_record(connection, stop_id)? else {
        return Ok(None);
    };
    if settlement::schema_available(connection)? {
        settlement::hydrate_record(connection, record).map(Some)
    } else {
        Ok(Some(record))
    }
}

fn load_targets(
    connection: &Connection,
    stop_id: Uuid,
    workspace_id: WorkspaceId,
) -> Result<Vec<ExecutionStopTarget>, ExecutionStopStoreError> {
    let mut statement = connection.prepare(
        "SELECT t.ordinal,
                length(CAST(t.execution_id AS BLOB)),
                substr(CAST(t.execution_id AS BLOB), 1, 16),
                t.expected_revision, t.expected_state,
                length(CAST(t.request_digest AS BLOB)),
                substr(CAST(t.request_digest AS BLOB), 1, 32),
                e.workspace_id = ?2 AND e.request_digest = t.request_digest
         FROM workspace_execution_stop_targets AS t
         LEFT JOIN executions AS e ON e.execution_id = t.execution_id
         WHERE t.stop_id = ?1 ORDER BY t.ordinal",
    )?;
    let mut rows = statement.query(params![
        stop_id.as_bytes(),
        workspace_id.into_uuid().as_bytes()
    ])?;
    let mut targets = Vec::new();
    while let Some(row) = rows.next()? {
        if row.get::<_, Option<bool>>(7)? != Some(true) {
            return Err(ExecutionStopStoreError::Corrupt("target execution binding"));
        }
        if targets.len() >= MAX_TARGETS {
            return Err(ExecutionStopStoreError::Overflow {
                actual: targets.len() + 1,
                maximum: MAX_TARGETS,
            });
        }
        let ordinal = row.get::<_, i64>(0)?;
        let expected_ordinal = i64::try_from(targets.len())
            .map_err(|_| ExecutionStopStoreError::Corrupt("target ordinal"))?;
        if ordinal != expected_ordinal {
            return Err(ExecutionStopStoreError::Corrupt(
                "non-contiguous target ordinals",
            ));
        }
        let ordinal = u8::try_from(ordinal)
            .map_err(|_| ExecutionStopStoreError::Corrupt("target ordinal"))?;
        let execution_id =
            ExecutionId::from_uuid(decode_uuid(row.get(1)?, row.get(2)?, "execution_id")?);
        let expected_revision = ExecutionRevision::new(row.get::<_, i64>(3)?)
            .map_err(|_| ExecutionStopStoreError::Corrupt("expected revision"))?;
        let expected_state = decode_state(row.get::<_, i64>(4)?)?;
        let request_digest = decode_digest(row.get(5)?, row.get(6)?, "target request digest")?;
        targets.push(ExecutionStopTarget::new(
            ordinal,
            execution_id,
            expected_revision,
            expected_state,
            request_digest,
        ));
    }
    Ok(targets)
}

fn record_matches(
    record: &ExecutionStopRecord,
    request: &ExecutionStopRequest,
    binding_digest: &[u8; DIGEST_BYTES],
) -> bool {
    record.stop_id() == request.stop_id()
        && record.workspace_id() == request.workspace_id()
        && record.request_id() == request.request_id()
        && record.owner_runtime_instance_id() == request.owner_runtime_instance_id()
        && record.request_digest() == request.request_digest()
        && record.binding_digest() == binding_digest
}

fn cohort_digest(targets: &[ExecutionStopTarget]) -> [u8; DIGEST_BYTES] {
    let mut digest = Sha256::new();
    digest.update(b"forge-workspace-execution-stop-cohort-v1\0");
    for target in targets {
        digest.update([target.ordinal()]);
        digest.update(target.execution_id().into_uuid().as_bytes());
        digest.update(target.expected_revision().get().to_be_bytes());
        digest.update(encode_state(target.expected_state()).to_be_bytes());
        digest.update(target.request_digest());
    }
    digest.finalize().into()
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "The codec consumes an owned bounded SQLite blob alongside its persisted length."
)]
fn decode_uuid(
    persisted_length: i64,
    bytes: Vec<u8>,
    field: &'static str,
) -> Result<Uuid, ExecutionStopStoreError> {
    if persisted_length != 16 || bytes.len() != ID_BYTES {
        return Err(ExecutionStopStoreError::Corrupt(field));
    }
    Uuid::from_slice(&bytes).map_err(|_| ExecutionStopStoreError::Corrupt(field))
}

fn decode_digest(
    persisted_length: i64,
    bytes: Vec<u8>,
    field: &'static str,
) -> Result<[u8; DIGEST_BYTES], ExecutionStopStoreError> {
    if persisted_length != 32 || bytes.len() != DIGEST_BYTES {
        return Err(ExecutionStopStoreError::Corrupt(field));
    }
    bytes
        .try_into()
        .map_err(|_| ExecutionStopStoreError::Corrupt(field))
}

fn encode_state(state: ExecutionState) -> i64 {
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

fn decode_state(value: i64) -> Result<ExecutionState, ExecutionStopStoreError> {
    match value {
        0 => Ok(ExecutionState::Starting),
        1 => Ok(ExecutionState::Running),
        6 => Ok(ExecutionState::Interrupted),
        _ => Err(ExecutionStopStoreError::Corrupt("expected state")),
    }
}

impl From<crate::ApprovalStoreError> for ExecutionStopStoreError {
    fn from(error: crate::ApprovalStoreError) -> Self {
        Self::Approval(Box::new(error))
    }
}
impl From<crate::ExecutionStoreError> for ExecutionStopStoreError {
    fn from(error: crate::ExecutionStoreError) -> Self {
        Self::Execution(Box::new(error))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::{Connection, TransactionBehavior, params};
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn fixture() -> Result<(Connection, WorkspaceId), Box<dyn std::error::Error>> {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE workspace(workspace_id BLOB PRIMARY KEY);
             CREATE TABLE activities(
                 activity_id BLOB PRIMARY KEY,
                 workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id),
                 state INTEGER NOT NULL
             );",
        )?;
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(0xA1));
        connection.execute(
            "INSERT INTO workspace(workspace_id) VALUES (?1)",
            params![workspace_id.into_uuid().as_bytes()],
        )?;
        crate::workspace_executions::create_schema(&connection)?;
        create_schema(&connection)?;
        Ok((connection, workspace_id))
    }

    fn request(
        workspace_id: WorkspaceId,
        seed: u128,
    ) -> Result<ExecutionStopRequest, forge_domain::TimestampMillisError> {
        Ok(ExecutionStopRequest::new(
            Uuid::from_u128(seed),
            workspace_id,
            Uuid::from_u128(seed + 1),
            RuntimeInstanceId::from_uuid(Uuid::from_u128(seed + 2)),
            [seed.to_le_bytes()[0]; DIGEST_BYTES],
            TimestampMillis::new(10)?,
        ))
    }

    fn insert_execution(
        connection: &Connection,
        workspace_id: WorkspaceId,
        execution_id: Uuid,
        state: i64,
        revision: i64,
        digest: [u8; DIGEST_BYTES],
    ) -> Result<(), rusqlite::Error> {
        let activity_id = Uuid::from_u128(execution_id.as_u128() + 0x1000);
        connection.execute(
            "INSERT INTO activities(activity_id, workspace_id, state) VALUES (?1, ?2, 1)",
            params![activity_id.as_bytes(), workspace_id.into_uuid().as_bytes(),],
        )?;
        connection.execute(
            "INSERT INTO executions(
                execution_id, workspace_id, activity_id, state, mode, request_digest,
                cwd, timeout_ms, output_limit, workspace_read, workspace_write, network,
                created_at_ms, updated_at_ms, revision,
                duration_ms, stdout, stdout_total_bytes, stdout_truncated,
                stderr, stderr_total_bytes, stderr_truncated, exit_code
             ) VALUES (?1, ?2, ?3, ?4, 0, ?5, NULL, 100, 1, 0, 0, 0, 1, 1, ?6,
                CASE WHEN ?4 = 2 THEN 1 END, CASE WHEN ?4 = 2 THEN x'' END,
                CASE WHEN ?4 = 2 THEN 0 END, CASE WHEN ?4 = 2 THEN 0 END,
                CASE WHEN ?4 = 2 THEN x'' END, CASE WHEN ?4 = 2 THEN 0 END,
                CASE WHEN ?4 = 2 THEN 0 END, CASE WHEN ?4 = 2 THEN 0 END)",
            params![
                execution_id.as_bytes(),
                workspace_id.into_uuid().as_bytes(),
                activity_id.as_bytes(),
                state,
                digest.as_slice(),
                revision,
            ],
        )?;
        Ok(())
    }

    #[test]
    fn empty_capture_and_exact_replay_are_pending() -> Result<(), Box<dyn std::error::Error>> {
        let (mut connection, workspace_id) = fixture()?;
        let first = request(workspace_id, 0xB1)?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let capture = capture_in_transaction(&tx, &first, [7; DIGEST_BYTES])?;
        tx.commit()?;
        assert_eq!(
            capture.capture_status(),
            ExecutionStopCaptureStatus::Captured
        );
        assert_eq!(capture.status(), ExecutionStopStatus::Pending);
        assert_eq!(capture.record().target_count(), 0);
        assert!(capture.record().targets().is_empty());

        let mut replay = request(workspace_id, 0xB1)?;
        replay.observed_at = TimestampMillis::new(30)?;
        let replay = get_for_request(&connection, &replay, [7; DIGEST_BYTES])?
            .ok_or("exact request should read back")?;
        assert_eq!(replay.stop_id(), first.stop_id());
        assert_eq!(replay.created_at(), first.observed_at());
        assert_eq!(replay.status(), ExecutionStopStatus::Pending);
        Ok(())
    }

    #[test]
    fn conflicting_replay_is_rejected_without_mutation() -> Result<(), Box<dyn std::error::Error>> {
        let (mut connection, workspace_id) = fixture()?;
        let first = request(workspace_id, 0xC1)?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let _captured = capture_in_transaction(&tx, &first, [8; DIGEST_BYTES])?;
        tx.commit()?;
        let mut conflicting = first;
        conflicting.request_id = Uuid::from_u128(0xC9);
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert!(matches!(
            capture_in_transaction(&tx, &conflicting, [8; DIGEST_BYTES]),
            Err(ExecutionStopStoreError::Conflict)
        ));
        drop(tx);
        assert!(ensure_execution_open(&connection, workspace_id).is_err());
        Ok(())
    }

    #[test]
    fn captures_active_rows_in_execution_id_order() -> Result<(), Box<dyn std::error::Error>> {
        let (mut connection, workspace_id) = fixture()?;
        insert_execution(
            &connection,
            workspace_id,
            Uuid::from_u128(0xD3),
            1,
            4,
            [3; 32],
        )?;
        insert_execution(
            &connection,
            workspace_id,
            Uuid::from_u128(0xD1),
            0,
            2,
            [1; 32],
        )?;
        insert_execution(
            &connection,
            workspace_id,
            Uuid::from_u128(0xD2),
            2,
            9,
            [2; 32],
        )?;
        let request = request(workspace_id, 0xD0)?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let capture = capture_in_transaction(&tx, &request, [9; 32])?;
        tx.commit()?;
        let targets = capture.record().targets();
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].ordinal(), 0);
        assert_eq!(
            targets[0].execution_id(),
            ExecutionId::from_uuid(Uuid::from_u128(0xD1))
        );
        assert_eq!(targets[0].expected_state(), ExecutionState::Starting);
        assert_eq!(targets[1].expected_state(), ExecutionState::Running);
        assert_eq!(capture.record().target_count(), 2);
        Ok(())
    }

    #[test]
    fn overflow_rolls_back_the_caller_transaction_before_write()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut connection, workspace_id) = fixture()?;
        for index in 0..PROBE_TARGETS {
            insert_execution(
                &connection,
                workspace_id,
                Uuid::from_u128(0xE000 + index as u128),
                0,
                1,
                [index.to_le_bytes()[0]; 32],
            )?;
        }
        let request = request(workspace_id, 0xEF)?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert!(matches!(
            capture_in_transaction(&tx, &request, [1; 32]),
            Err(ExecutionStopStoreError::Overflow {
                actual: 257,
                maximum: 256
            })
        ));
        drop(tx);
        let count: i64 = connection.query_row(
            "SELECT count(*) FROM workspace_execution_stops",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(count, 0);
        Ok(())
    }

    #[test]
    fn readback_rejects_deleted_target_and_damaged_schema() -> Result<(), Box<dyn std::error::Error>>
    {
        let (mut connection, workspace_id) = fixture()?;
        insert_execution(
            &connection,
            workspace_id,
            Uuid::from_u128(0xF1),
            0,
            1,
            [4; 32],
        )?;
        let request = request(workspace_id, 0xF0)?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let _captured = capture_in_transaction(&tx, &request, [2; 32])?;
        tx.commit()?;
        connection.execute("DELETE FROM workspace_execution_stop_targets", [])?;
        assert!(matches!(
            get_for_request(&connection, &request, [2; 32]),
            Err(ExecutionStopStoreError::Corrupt("cohort integrity"))
        ));

        connection.execute_batch(
            "DROP TABLE workspace_execution_stop_targets;
             CREATE TABLE workspace_execution_stop_targets (
                 stop_id BLOB NOT NULL,
                 ordinal INTEGER NOT NULL,
                 execution_id BLOB NOT NULL,
                 expected_revision INTEGER NOT NULL,
                 expected_state INTEGER NOT NULL,
                 request_digest BLOB NOT NULL,
                 PRIMARY KEY(stop_id, ordinal)
             );",
        )?;
        assert!(matches!(
            validate_schema(&connection),
            Err(ExecutionStopStoreError::DamagedSchema(
                "workspace_execution_stop_targets"
            ))
        ));
        Ok(())
    }

    #[test]
    fn file_reopen_preserves_pending_capture() -> Result<(), Box<dyn std::error::Error>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path = std::env::temp_dir().join(format!(
            "forge-execution-stop-{nonce}-{}.sqlite3",
            std::process::id()
        ));
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(0x101));
        {
            let mut connection = Connection::open(&path)?;
            connection.execute_batch(
                "PRAGMA foreign_keys = ON;
                 CREATE TABLE workspace(workspace_id BLOB PRIMARY KEY);
                 CREATE TABLE activities(
                     activity_id BLOB PRIMARY KEY,
                     workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id),
                     state INTEGER NOT NULL
                 );",
            )?;
            connection.execute(
                "INSERT INTO workspace(workspace_id) VALUES (?1)",
                params![workspace_id.into_uuid().as_bytes()],
            )?;
            crate::workspace_executions::create_schema(&connection)?;
            create_schema(&connection)?;
            let request = request(workspace_id, 0x102)?;
            let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let _captured = capture_in_transaction(&tx, &request, [3; 32])?;
            tx.commit()?;
        }
        let connection = Connection::open(&path)?;
        connection.pragma_update(None, "foreign_keys", true)?;
        let request = request(workspace_id, 0x102)?;
        assert!(get_for_request(&connection, &request, [3; 32])?.is_some());
        std::fs::remove_file(PathBuf::from(&path))?;
        Ok(())
    }

    #[test]
    fn interrupted_execution_remains_a_pending_target_without_terminal_proof()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut connection, workspace_id) = fixture()?;
        let execution_id = Uuid::from_u128(0x5701);
        insert_execution(&connection, workspace_id, execution_id, 6, 2, [4; 32])?;
        let request = request(workspace_id, 0x5702)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let captured = capture_in_transaction(&transaction, &request, [3; 32])?;
        transaction.commit()?;
        assert_eq!(captured.record().targets().len(), 1);
        assert_eq!(
            captured.record().targets()[0].expected_state(),
            ExecutionState::Interrupted
        );
        assert_eq!(captured.status(), ExecutionStopStatus::Pending);
        assert_eq!(
            captured.record().targets()[0].status(),
            ExecutionStopTargetStatus::Pending
        );
        Ok(())
    }

    #[test]
    fn readback_rejects_foreign_workspace_or_changed_execution_definition()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut connection, workspace_id) = fixture()?;
        let execution_id = Uuid::from_u128(0x5701);
        insert_execution(&connection, workspace_id, execution_id, 0, 1, [4; 32])?;
        let request = request(workspace_id, 0x5702)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let _captured = capture_in_transaction(&transaction, &request, [3; 32])?;
        transaction.commit()?;
        let foreign = WorkspaceId::from_uuid(Uuid::from_u128(0x5703));
        connection.execute(
            "INSERT INTO workspace(workspace_id) VALUES (?1)",
            params![foreign.into_uuid().as_bytes()],
        )?;
        connection.execute(
            "UPDATE executions SET workspace_id = ?1 WHERE execution_id = ?2",
            params![foreign.into_uuid().as_bytes(), execution_id.as_bytes()],
        )?;
        assert!(matches!(
            get_for_request(&connection, &request, [3; 32]),
            Err(ExecutionStopStoreError::Corrupt("target execution binding"))
        ));
        connection.execute(
            "UPDATE executions SET workspace_id = ?1, request_digest = ?2 WHERE execution_id = ?3",
            params![
                workspace_id.into_uuid().as_bytes(),
                [5_u8; 32].as_slice(),
                execution_id.as_bytes()
            ],
        )?;
        assert!(matches!(
            get_for_request(&connection, &request, [3; 32]),
            Err(ExecutionStopStoreError::Corrupt("target execution binding"))
        ));
        Ok(())
    }
}
