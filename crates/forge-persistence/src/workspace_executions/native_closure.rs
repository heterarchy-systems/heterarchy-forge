//! Durable native-execution closure facts.
//!
//! The live supervisor owns process/runtime closure evidence.  This module
//! stores only the checked historical fact after the terminal execution row,
//! output ledger, and generated-package evidence are already part of the
//! caller's transaction.

use forge_domain::{
    ExecutionAttribution, ExecutionId, ExecutionNativeClosureFact, ExecutionNativeClosureFactParts,
    ExecutionOutputCursor, ExecutionOutputSequence, ExecutionRevision, ExecutionState,
    GeneratedArtifactKind, GeneratedPackageManifest, NativeClosureLaunch, NativeClosureProcess,
    NativeClosureRuntime, RegisteredExecution, TimestampMillis,
};
use rusqlite::{Connection, OptionalExtension, Row, Transaction, params};

use super::ExecutionStoreError;

const ID_BYTES: usize = 16;
const DIGEST_BYTES: usize = 32;

/// The one canonical SQL authority for the schema-59 native closure fact.
///
/// The fact is immutable and keyed by the admitted execution.  The terminal
/// execution row remains the authority for outcome and generated-package
/// manifest data; those payloads are intentionally absent here.
pub(crate) const EXPECTED_TABLE_SQL: &str = "CREATE TABLE execution_native_closures (execution_id BLOB PRIMARY KEY NOT NULL REFERENCES executions(execution_id) CHECK(length(execution_id) = 16), workspace_id BLOB NOT NULL CHECK(length(workspace_id) = 16), activity_id BLOB NOT NULL CHECK(length(activity_id) = 16), request_digest BLOB NOT NULL CHECK(length(request_digest) = 32), before_revision INTEGER NOT NULL CHECK(before_revision >= 1), after_revision INTEGER NOT NULL CHECK(after_revision = before_revision + 1), process_disposition INTEGER NOT NULL CHECK(process_disposition IN (0, 1)), runtime_disposition INTEGER NOT NULL CHECK(runtime_disposition IN (0, 1)), output_sequence INTEGER NOT NULL CHECK(output_sequence >= 0), launch_kind INTEGER NOT NULL CHECK(launch_kind IN (0, 1, 2)), observed_at_ms INTEGER NOT NULL CHECK(observed_at_ms >= 0), CHECK((launch_kind = 0 AND runtime_disposition = 0) OR (launch_kind IN (1, 2) AND runtime_disposition = 1)))";

const FACT_QUERY: &str = "SELECT execution_id, workspace_id, activity_id, request_digest,
        before_revision, after_revision, process_disposition, runtime_disposition,
        output_sequence, launch_kind, observed_at_ms
    FROM execution_native_closures
    WHERE execution_id = ?1";

const OBJECTS: [(&str, &str); 1] = [("table", "execution_native_closures")];

/// Terminal record, generated-package manifest, and optional native closure
/// fact read from one SQLite authority snapshot.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionNativeClosureSnapshot {
    record: RegisteredExecution,
    manifest: Option<GeneratedPackageManifest>,
    closure: Option<ExecutionNativeClosureFact>,
}

impl ExecutionNativeClosureSnapshot {
    fn new(
        record: RegisteredExecution,
        manifest: Option<GeneratedPackageManifest>,
        closure: Option<ExecutionNativeClosureFact>,
    ) -> Self {
        Self {
            record,
            manifest,
            closure,
        }
    }

    pub const fn record(&self) -> &RegisteredExecution {
        &self.record
    }

    pub const fn manifest(&self) -> Option<GeneratedPackageManifest> {
        self.manifest
    }

    pub const fn closure(&self) -> Option<ExecutionNativeClosureFact> {
        self.closure
    }
}

/// Create the schema-59 fact table in the caller's schema transaction.
pub(crate) fn create_schema(connection: &Connection) -> Result<(), ExecutionStoreError> {
    connection.execute_batch(EXPECTED_TABLE_SQL)?;
    Ok(())
}

pub(crate) const fn schema_objects() -> [(&'static str, &'static str); 1] {
    OBJECTS
}

pub(crate) fn validate_schema(connection: &Connection) -> Result<(), ExecutionStoreError> {
    super::validate_schema_sql(
        connection,
        "table",
        "execution_native_closures",
        EXPECTED_TABLE_SQL,
    )?;
    super::validate_column_shape(
        connection,
        "execution_native_closures",
        &[
            ("execution_id", "BLOB", 1, 1),
            ("workspace_id", "BLOB", 1, 0),
            ("activity_id", "BLOB", 1, 0),
            ("request_digest", "BLOB", 1, 0),
            ("before_revision", "INTEGER", 1, 0),
            ("after_revision", "INTEGER", 1, 0),
            ("process_disposition", "INTEGER", 1, 0),
            ("runtime_disposition", "INTEGER", 1, 0),
            ("output_sequence", "INTEGER", 1, 0),
            ("launch_kind", "INTEGER", 1, 0),
            ("observed_at_ms", "INTEGER", 1, 0),
        ],
    )?;
    super::validate_foreign_keys(connection, "execution_native_closures", 1)
}

/// Append one immutable native closure fact inside the terminal transaction.
///
/// The terminal record and generated-package table have already been updated
/// by the caller when this function runs.  The output watermark is read from
/// the same transaction; it is never inferred from a later Store snapshot.
pub(crate) fn append_in_transaction(
    transaction: &Transaction<'_>,
    record: &RegisteredExecution,
    fact: &ExecutionNativeClosureFact,
) -> Result<(), ExecutionStoreError> {
    if transaction
        .query_row(
            "SELECT 1 FROM execution_native_closures WHERE execution_id = ?1",
            params![record.id().into_uuid().as_bytes()],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .is_some()
    {
        return Err(ExecutionStoreError::NativeClosureAlreadyExists);
    }

    let manifest =
        super::get_generated_package_manifest_tx(transaction, record.id(), Some(record))?;
    let output_sequence =
        validate_fact_against_record(transaction, record, fact, manifest.as_ref())?;

    transaction.execute(
        "INSERT INTO execution_native_closures (
            execution_id, workspace_id, activity_id, request_digest,
            before_revision, after_revision, process_disposition,
            runtime_disposition, output_sequence, launch_kind, observed_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            fact.attribution().id().into_uuid().as_bytes(),
            fact.attribution().workspace_id().into_uuid().as_bytes(),
            fact.attribution().activity_id().into_uuid().as_bytes(),
            fact.request_digest().as_bytes(),
            fact.before_revision().get(),
            fact.after_revision().get(),
            encode_process(fact.process()),
            encode_runtime(fact.runtime()),
            i64::try_from(output_sequence).map_err(|_| ExecutionStoreError::IntegerOverflow)?,
            encode_launch(fact.launch()),
            fact.observed_at().get(),
        ],
    )?;
    Ok(())
}

/// Read and validate one closure fact inside a caller-owned transaction.
pub(crate) fn read_in_transaction(
    transaction: &Connection,
    record: &RegisteredExecution,
    manifest: Option<&GeneratedPackageManifest>,
) -> Result<Option<ExecutionNativeClosureFact>, ExecutionStoreError> {
    let Some(raw) = transaction
        .query_row(
            FACT_QUERY,
            params![record.id().into_uuid().as_bytes()],
            RawFact::from_row,
        )
        .optional()?
    else {
        return Ok(None);
    };
    let fact = raw.decode()?;
    validate_fact_against_record(transaction, record, &fact, manifest)?;
    Ok(Some(fact))
}

/// Read one terminal/manifest/closure snapshot in one SQLite transaction.
pub(crate) fn snapshot(
    connection: &Connection,
    execution_id: ExecutionId,
) -> Result<Option<ExecutionNativeClosureSnapshot>, ExecutionStoreError> {
    let transaction = connection.unchecked_transaction()?;
    let result = snapshot_in_transaction(&transaction, execution_id)?;
    transaction.commit()?;
    Ok(result)
}

/// Query within an existing caller-owned transaction; never starts a nested one.
pub(crate) fn snapshot_in_transaction(
    connection: &Connection,
    execution_id: ExecutionId,
) -> Result<Option<ExecutionNativeClosureSnapshot>, ExecutionStoreError> {
    let Some(record) = super::get_execution_tx(connection, execution_id)? else {
        return Ok(None);
    };
    let manifest =
        super::get_generated_package_manifest_tx(connection, execution_id, Some(&record))?;
    let closure = read_in_transaction(connection, &record, manifest.as_ref())?;
    Ok(Some(ExecutionNativeClosureSnapshot::new(
        record, manifest, closure,
    )))
}

fn validate_fact_against_record(
    transaction: &Connection,
    record: &RegisteredExecution,
    fact: &ExecutionNativeClosureFact,
    manifest: Option<&GeneratedPackageManifest>,
) -> Result<u64, ExecutionStoreError> {
    if !matches!(
        record.state(),
        ExecutionState::Completed
            | ExecutionState::Failed
            | ExecutionState::TimedOut
            | ExecutionState::Cancelled
    ) || fact.attribution().id() != record.id()
        || fact.attribution().workspace_id() != record.workspace_id()
        || fact.attribution().activity_id() != record.activity_id()
        || fact.request_digest() != record.request_digest()
        || fact.before_revision().checked_next().ok() != Some(record.revision())
        || fact.after_revision() != record.revision()
        || fact.observed_at() != record.timestamps().updated_at()
    {
        return Err(ExecutionStoreError::NativeClosureConflict);
    }

    let output_sequence = durable_output_sequence(transaction, record.id())?;
    if fact.output_cursor().execution_id() != record.id()
        || fact.output_cursor().after_sequence() != output_sequence
    {
        return Err(ExecutionStoreError::NativeClosureOutputConflict);
    }

    validate_manifest_pair(record, fact, manifest)?;
    Ok(output_sequence)
}

fn validate_manifest_pair(
    record: &RegisteredExecution,
    fact: &ExecutionNativeClosureFact,
    manifest: Option<&GeneratedPackageManifest>,
) -> Result<(), ExecutionStoreError> {
    match (fact.launch(), manifest) {
        (NativeClosureLaunch::GeneratedPackage, Some(manifest))
            if manifest.execution_id() == record.id()
                && manifest.workspace_id() == record.workspace_id()
                && manifest.kind() == GeneratedArtifactKind::MacOsInstallerPackage
                && manifest.byte_count().get() > 0
                && record.state() == ExecutionState::Completed
                && matches!(
                    record
                        .provenance()
                        .and_then(forge_domain::ExecutionAgentProvenance::project_command)
                        .map(forge_domain::ProjectCommandEvidence::class),
                    Some(forge_domain::ProjectCommandClass::GeneratedPackage)
                ) =>
        {
            Ok(())
        }
        (NativeClosureLaunch::Baseline | NativeClosureLaunch::RustCi, None) => Ok(()),
        _ => Err(ExecutionStoreError::NativeClosureArtifactConflict),
    }
}

fn durable_output_sequence(
    transaction: &Connection,
    execution_id: ExecutionId,
) -> Result<u64, ExecutionStoreError> {
    let invalid = transaction
        .query_row(
            "WITH ordered AS (
                SELECT sequence, event_kind, first_missing, last_missing, omitted_chunks,
                       LAG(sequence)
                           OVER (ORDER BY sequence) AS previous_covered
                FROM execution_output_events
                WHERE execution_id = ?1
             )
             SELECT 1 FROM ordered
             WHERE sequence < 1
                OR event_kind NOT IN (0, 1)
                OR (event_kind = 0 AND (
                    sequence != COALESCE(previous_covered + 1, 1)
                    OR first_missing IS NOT NULL
                    OR last_missing IS NOT NULL
                    OR omitted_chunks IS NOT NULL
                ))
                OR (event_kind = 1 AND (
                    first_missing IS NULL
                    OR last_missing IS NULL
                    OR omitted_chunks IS NULL
                    OR first_missing != COALESCE(previous_covered + 1, 1)
                    OR last_missing < first_missing
                    OR sequence != last_missing + 1
                    OR omitted_chunks != last_missing - first_missing + 1
                ))
             LIMIT 1",
            params![execution_id.into_uuid().as_bytes()],
            |row| row.get::<_, i64>(0),
        )
        .optional()?;
    if invalid.is_some() {
        return Err(ExecutionStoreError::CorruptRecord(
            "execution_native_closures.output_coverage",
        ));
    }
    let maximum = transaction.query_row(
        "SELECT MAX(sequence) FROM execution_output_events WHERE execution_id = ?1",
        params![execution_id.into_uuid().as_bytes()],
        |row| row.get::<_, Option<i64>>(0),
    )?;
    match maximum {
        None => Ok(0),
        Some(value) => u64::try_from(value)
            .map_err(|_| ExecutionStoreError::CorruptRecord("execution_output_events.sequence")),
    }
}

#[derive(Debug)]
struct RawFact {
    execution_id: Vec<u8>,
    workspace_id: Vec<u8>,
    activity_id: Vec<u8>,
    request_digest: Vec<u8>,
    before_revision: i64,
    after_revision: i64,
    process: i64,
    runtime: i64,
    output_sequence: i64,
    launch: i64,
    observed_at: i64,
}

impl RawFact {
    fn from_row(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            execution_id: row.get(0)?,
            workspace_id: row.get(1)?,
            activity_id: row.get(2)?,
            request_digest: row.get(3)?,
            before_revision: row.get(4)?,
            after_revision: row.get(5)?,
            process: row.get(6)?,
            runtime: row.get(7)?,
            output_sequence: row.get(8)?,
            launch: row.get(9)?,
            observed_at: row.get(10)?,
        })
    }

    fn decode(self) -> Result<ExecutionNativeClosureFact, ExecutionStoreError> {
        super::validate_byte_length(
            "execution_native_closures.execution_id",
            self.execution_id.len(),
            ID_BYTES,
        )?;
        super::validate_byte_length(
            "execution_native_closures.workspace_id",
            self.workspace_id.len(),
            ID_BYTES,
        )?;
        super::validate_byte_length(
            "execution_native_closures.activity_id",
            self.activity_id.len(),
            ID_BYTES,
        )?;
        super::validate_byte_length(
            "execution_native_closures.request_digest",
            self.request_digest.len(),
            DIGEST_BYTES,
        )?;

        let execution_id = super::decode_execution_id(&self.execution_id)?;
        let attribution = ExecutionAttribution::new(
            execution_id,
            super::decode_workspace_id(&self.workspace_id)?,
            super::decode_activity_id(&self.activity_id)?,
        );
        let request_digest = super::decode_request_digest(&self.request_digest)?;
        let before_revision = ExecutionRevision::new(self.before_revision).map_err(|_| {
            ExecutionStoreError::CorruptRecord("execution_native_closures.before_revision")
        })?;
        let after_revision = ExecutionRevision::new(self.after_revision).map_err(|_| {
            ExecutionStoreError::CorruptRecord("execution_native_closures.after_revision")
        })?;
        let output_sequence = u64::try_from(self.output_sequence).map_err(|_| {
            ExecutionStoreError::CorruptRecord("execution_native_closures.output_sequence")
        })?;
        let output_cursor = if output_sequence == 0 {
            ExecutionOutputCursor::initial(execution_id)
        } else {
            ExecutionOutputCursor::from_sequence(
                execution_id,
                ExecutionOutputSequence::new(output_sequence).map_err(|_| {
                    ExecutionStoreError::CorruptRecord("execution_native_closures.output_sequence")
                })?,
            )
        };
        let observed_at = TimestampMillis::new(self.observed_at).map_err(|_| {
            ExecutionStoreError::CorruptRecord("execution_native_closures.observed_at_ms")
        })?;

        let fact = ExecutionNativeClosureFact::from_parts(ExecutionNativeClosureFactParts {
            attribution,
            request_digest,
            before_revision,
            after_revision,
            output_cursor,
            launch: decode_launch(self.launch)?,
            runtime: decode_runtime(self.runtime)?,
            process: decode_process(self.process)?,
            observed_at,
        })
        .map_err(|_| ExecutionStoreError::CorruptRecord("execution_native_closures.fact"))?;
        Ok(fact)
    }
}

const fn encode_process(value: NativeClosureProcess) -> i64 {
    match value {
        NativeClosureProcess::NoChildSpawned => 0,
        NativeClosureProcess::ProcessGroupReaped => 1,
    }
}

fn decode_process(value: i64) -> Result<NativeClosureProcess, ExecutionStoreError> {
    match value {
        0 => Ok(NativeClosureProcess::NoChildSpawned),
        1 => Ok(NativeClosureProcess::ProcessGroupReaped),
        _ => Err(ExecutionStoreError::CorruptRecord(
            "execution_native_closures.process_disposition",
        )),
    }
}

const fn encode_runtime(value: NativeClosureRuntime) -> i64 {
    match value {
        NativeClosureRuntime::NotApplicable => 0,
        NativeClosureRuntime::Cleaned => 1,
    }
}

fn decode_runtime(value: i64) -> Result<NativeClosureRuntime, ExecutionStoreError> {
    match value {
        0 => Ok(NativeClosureRuntime::NotApplicable),
        1 => Ok(NativeClosureRuntime::Cleaned),
        _ => Err(ExecutionStoreError::CorruptRecord(
            "execution_native_closures.runtime_disposition",
        )),
    }
}

const fn encode_launch(value: NativeClosureLaunch) -> i64 {
    match value {
        NativeClosureLaunch::Baseline => 0,
        NativeClosureLaunch::RustCi => 1,
        NativeClosureLaunch::GeneratedPackage => 2,
    }
}

fn decode_launch(value: i64) -> Result<NativeClosureLaunch, ExecutionStoreError> {
    match value {
        0 => Ok(NativeClosureLaunch::Baseline),
        1 => Ok(NativeClosureLaunch::RustCi),
        2 => Ok(NativeClosureLaunch::GeneratedPackage),
        _ => Err(ExecutionStoreError::CorruptRecord(
            "execution_native_closures.launch_kind",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_round_trips_and_rejects_changed_shape() -> Result<(), Box<dyn std::error::Error>> {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch(
            "PRAGMA foreign_keys = ON; CREATE TABLE executions(execution_id BLOB PRIMARY KEY);",
        )?;
        create_schema(&connection)?;
        validate_schema(&connection)?;

        connection.execute("DROP TABLE execution_native_closures", [])?;
        connection.execute(
            "CREATE TABLE execution_native_closures(execution_id BLOB PRIMARY KEY)",
            [],
        )?;
        assert!(matches!(
            validate_schema(&connection),
            Err(ExecutionStoreError::CorruptRecord(
                "execution_native_closures"
            ))
        ));
        Ok(())
    }
}
