//! Schema-60 settlement and admission-fence records for Workspace stops.
//!
//! Capture rows and authority before/after receipts remain immutable history.
//! This module appends positive settlement evidence and removes only the exact
//! active fence in the same caller-owned transaction.

use std::os::unix::ffi::OsStrExt;

use forge_domain::{
    ExecutionCompletionStatus, ExecutionFailureCode, ExecutionMode, ExecutionNativeClosureFact,
    ExecutionState, GeneratedArtifactKind, GeneratedPackageManifest, NativeClosureLaunch,
    NativeClosureProcess, NativeClosureRuntime, RegisteredExecution, TimestampMillis, WorkspaceId,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{
    ExecutionStopRecord, ExecutionStopStatus, ExecutionStopStoreError, ExecutionStopTargetStatus,
    MAX_EXECUTION_STOP_TARGETS,
};
use crate::workspace_approvals::cleanup::stop_receipts::{
    AuthorityStopReceipt, observe_stop_authority_receipt_in_transaction,
};
use crate::workspace_executions::native_closure;

const ID_BYTES: usize = 16;
const DIGEST_BYTES: usize = 32;
const MAX_SCHEMA_SQL_BYTES: usize = 16 * 1024;

const FENCES_SQL: &str = "CREATE TABLE workspace_execution_stop_fences (workspace_id BLOB PRIMARY KEY NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16), stop_id BLOB NOT NULL UNIQUE REFERENCES workspace_execution_stops(stop_id) CHECK(length(stop_id) = 16))";
const SETTLEMENTS_SQL: &str = "CREATE TABLE workspace_execution_stop_settlements (stop_id BLOB PRIMARY KEY NOT NULL REFERENCES workspace_execution_stops(stop_id) CHECK(length(stop_id) = 16), workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16), request_id BLOB NOT NULL CHECK(length(request_id) = 16), owner_runtime_instance_id BLOB NOT NULL CHECK(length(owner_runtime_instance_id) = 16), status INTEGER NOT NULL CHECK(status = 1), execution_target_count INTEGER NOT NULL CHECK(execution_target_count BETWEEN 0 AND 256), authority_target_count INTEGER NOT NULL CHECK(authority_target_count BETWEEN 0 AND 768), execution_cohort_digest BLOB NOT NULL CHECK(length(execution_cohort_digest) = 32), authority_cohort_digest BLOB NOT NULL CHECK(length(authority_cohort_digest) = 32), settlement_digest BLOB NOT NULL CHECK(length(settlement_digest) = 32), quiescent INTEGER NOT NULL CHECK(quiescent = 1), settled_at_ms INTEGER NOT NULL CHECK(settled_at_ms >= 0), UNIQUE(workspace_id, request_id))";
const TARGETS_SQL: &str = "CREATE TABLE workspace_execution_stop_settlement_targets (stop_id BLOB NOT NULL REFERENCES workspace_execution_stops(stop_id) CHECK(length(stop_id) = 16), ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 0 AND 255), execution_id BLOB NOT NULL REFERENCES executions(execution_id) CHECK(length(execution_id) = 16), target_status INTEGER NOT NULL CHECK(target_status = 1), expected_revision INTEGER NOT NULL CHECK(expected_revision >= 1), expected_state INTEGER NOT NULL CHECK(expected_state IN (0, 1, 6)), request_digest BLOB NOT NULL CHECK(length(request_digest) = 32), after_revision INTEGER NOT NULL CHECK(after_revision >= 1), after_state INTEGER NOT NULL CHECK(after_state IN (2, 3, 4, 5)), final_output_sequence INTEGER NOT NULL CHECK(final_output_sequence >= 0), terminal_digest BLOB NOT NULL CHECK(length(terminal_digest) = 32), PRIMARY KEY(stop_id, ordinal), UNIQUE(stop_id, execution_id))";

const OBJECTS: [(&str, &str, &str); 3] = [
    ("table", "workspace_execution_stop_fences", FENCES_SQL),
    (
        "table",
        "workspace_execution_stop_settlements",
        SETTLEMENTS_SQL,
    ),
    (
        "table",
        "workspace_execution_stop_settlement_targets",
        TARGETS_SQL,
    ),
];

#[derive(Debug, Clone, Copy)]
struct SettlementTargetProof {
    ordinal: u8,
    execution_id: forge_domain::ExecutionId,
    expected_revision: forge_domain::ExecutionRevision,
    expected_state: ExecutionState,
    request_digest: [u8; DIGEST_BYTES],
    after_revision: forge_domain::ExecutionRevision,
    after_state: ExecutionState,
    final_output_sequence: u64,
    terminal_digest: [u8; DIGEST_BYTES],
}

/// Create the schema-60 fence and immutable settlement ledgers.
pub(crate) fn create_schema(connection: &Connection) -> Result<(), ExecutionStopStoreError> {
    connection.execute_batch(FENCES_SQL)?;
    connection.execute_batch(SETTLEMENTS_SQL)?;
    connection.execute_batch(TARGETS_SQL)?;
    Ok(())
}

pub(crate) const fn schema_objects() -> [(&'static str, &'static str); 3] {
    [
        ("table", "workspace_execution_stop_fences"),
        ("table", "workspace_execution_stop_settlements"),
        ("table", "workspace_execution_stop_settlement_targets"),
    ]
}

pub(crate) fn validate_schema(connection: &Connection) -> Result<(), ExecutionStopStoreError> {
    for &(kind, name, expected) in &OBJECTS {
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
        if usize::try_from(sql_length)
            .ok()
            .is_none_or(|length| length > MAX_SCHEMA_SQL_BYTES)
        {
            return Err(ExecutionStopStoreError::DamagedSchema(name));
        }
        let actual: String = connection.query_row(
            "SELECT sql FROM sqlite_schema WHERE type = ?1 AND name = ?2",
            params![kind, name],
            |row| row.get(0),
        )?;
        if super::normalize_sql(&actual) != super::normalize_sql(expected) {
            return Err(ExecutionStopStoreError::DamagedSchema(name));
        }
    }
    super::validate_columns(
        connection,
        "workspace_execution_stop_fences",
        &[("workspace_id", "BLOB", 1, 1), ("stop_id", "BLOB", 1, 0)],
    )?;
    super::validate_columns(
        connection,
        "workspace_execution_stop_settlements",
        &[
            ("stop_id", "BLOB", 1, 1),
            ("workspace_id", "BLOB", 1, 0),
            ("request_id", "BLOB", 1, 0),
            ("owner_runtime_instance_id", "BLOB", 1, 0),
            ("status", "INTEGER", 1, 0),
            ("execution_target_count", "INTEGER", 1, 0),
            ("authority_target_count", "INTEGER", 1, 0),
            ("execution_cohort_digest", "BLOB", 1, 0),
            ("authority_cohort_digest", "BLOB", 1, 0),
            ("settlement_digest", "BLOB", 1, 0),
            ("quiescent", "INTEGER", 1, 0),
            ("settled_at_ms", "INTEGER", 1, 0),
        ],
    )?;
    super::validate_columns(
        connection,
        "workspace_execution_stop_settlement_targets",
        &[
            ("stop_id", "BLOB", 1, 1),
            ("ordinal", "INTEGER", 1, 2),
            ("execution_id", "BLOB", 1, 0),
            ("target_status", "INTEGER", 1, 0),
            ("expected_revision", "INTEGER", 1, 0),
            ("expected_state", "INTEGER", 1, 0),
            ("request_digest", "BLOB", 1, 0),
            ("after_revision", "INTEGER", 1, 0),
            ("after_state", "INTEGER", 1, 0),
            ("final_output_sequence", "INTEGER", 1, 0),
            ("terminal_digest", "BLOB", 1, 0),
        ],
    )?;
    super::validate_foreign_keys(
        connection,
        "workspace_execution_stop_fences",
        &[
            ("workspace", "workspace_id", "workspace_id"),
            ("workspace_execution_stops", "stop_id", "stop_id"),
        ],
    )?;
    super::validate_foreign_keys(
        connection,
        "workspace_execution_stop_settlements",
        &[
            ("workspace_execution_stops", "stop_id", "stop_id"),
            ("workspace", "workspace_id", "workspace_id"),
        ],
    )?;
    super::validate_foreign_keys(
        connection,
        "workspace_execution_stop_settlement_targets",
        &[
            ("workspace_execution_stops", "stop_id", "stop_id"),
            ("executions", "execution_id", "execution_id"),
        ],
    )
}

pub(crate) fn schema_available(connection: &Connection) -> Result<bool, ExecutionStopStoreError> {
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema
             WHERE type = 'table' AND name = 'workspace_execution_stop_fences')",
            [],
            |row| row.get(0),
        )
        .map_err(ExecutionStopStoreError::from)
}

pub(crate) fn active_fence_stop_id(
    connection: &Connection,
    workspace_id: WorkspaceId,
) -> Result<Option<Uuid>, ExecutionStopStoreError> {
    type RawFence = (i64, Vec<u8>, Option<i64>, Option<Vec<u8>>);
    let row: Option<RawFence> = connection
        .query_row(
            "SELECT length(CAST(f.stop_id AS BLOB)),
                    substr(CAST(f.stop_id AS BLOB), 1, 16),
                    length(CAST(s.workspace_id AS BLOB)),
                    substr(CAST(s.workspace_id AS BLOB), 1, 16)
             FROM workspace_execution_stop_fences AS f
             LEFT JOIN workspace_execution_stops AS s ON s.stop_id = f.stop_id
             WHERE f.workspace_id = ?1",
            params![workspace_id.into_uuid().as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    if let Some((length, bytes, workspace_length, workspace_bytes)) = row {
        let stop_id = super::decode_uuid(length, bytes, "active fence stop_id")?;
        if workspace_length != Some(16)
            || workspace_bytes.as_deref() != Some(workspace_id.into_uuid().as_bytes().as_slice())
        {
            return Err(ExecutionStopStoreError::Corrupt("active fence binding"));
        }
        return Ok(Some(stop_id));
    }
    let orphan = connection
        .query_row(
            "SELECT 1
         FROM workspace_execution_stops AS s
         LEFT JOIN workspace_execution_stop_fences AS f ON f.stop_id = s.stop_id
         LEFT JOIN workspace_execution_stop_settlements AS b ON b.stop_id = s.stop_id
         WHERE s.workspace_id = ?1 AND f.stop_id IS NULL AND b.stop_id IS NULL
         LIMIT 1",
            params![workspace_id.into_uuid().as_bytes()],
            |row| row.get::<_, i64>(0),
        )
        .optional()?;
    if orphan.is_some() {
        return Err(ExecutionStopStoreError::Corrupt("capture fence missing"));
    }
    Ok(None)
}

pub(crate) fn insert_fence_in_transaction(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
    stop_id: Uuid,
) -> Result<(), ExecutionStopStoreError> {
    let actual_workspace: Option<Vec<u8>> = transaction
        .query_row(
            "SELECT workspace_id FROM workspace_execution_stops WHERE stop_id = ?1",
            params![stop_id.as_bytes()],
            |row| row.get(0),
        )
        .optional()?;
    let Some(actual_workspace) = actual_workspace else {
        return Err(ExecutionStopStoreError::Corrupt("fence stop missing"));
    };
    if actual_workspace.as_slice() != workspace_id.into_uuid().as_bytes() {
        return Err(ExecutionStopStoreError::Conflict);
    }
    transaction.execute(
        "INSERT INTO workspace_execution_stop_fences(workspace_id, stop_id)
         VALUES (?1, ?2)",
        params![workspace_id.into_uuid().as_bytes(), stop_id.as_bytes()],
    )?;
    Ok(())
}

pub(crate) fn populate_legacy_fences(
    transaction: &Transaction<'_>,
) -> Result<(), ExecutionStopStoreError> {
    transaction.execute(
        "INSERT INTO workspace_execution_stop_fences(workspace_id, stop_id)
         SELECT workspace_id, stop_id FROM workspace_execution_stops",
        [],
    )?;
    Ok(())
}

/// Rehydrate capture/target status from immutable settlement rows without
/// changing the capture cohort digest or before-images.
pub(crate) fn hydrate_record(
    connection: &Connection,
    record: ExecutionStopRecord,
) -> Result<ExecutionStopRecord, ExecutionStopStoreError> {
    hydrate_record_in_transaction(connection, record)
}

pub(super) fn hydrate_record_in_transaction(
    transaction: &Connection,
    record: ExecutionStopRecord,
) -> Result<ExecutionStopRecord, ExecutionStopStoreError> {
    let rows = load_settlement_targets(transaction, record.stop_id())?;
    let batch = load_batch(transaction, record.stop_id())?;
    if let Some(batch) = batch.as_ref() {
        validate_batch_identity(&record, batch)?;
        let authority = observe_stop_authority_receipt_in_transaction(
            transaction,
            record.stop_id(),
            record.workspace_id(),
        )?
        .ok_or(ExecutionStopStoreError::Corrupt(
            "settlement authority missing",
        ))?;
        if authority.target_count() != batch.authority_target_count
            || authority.cohort_digest() != &batch.authority_cohort_digest
        {
            return Err(ExecutionStopStoreError::Corrupt(
                "settlement authority digest",
            ));
        }
        if batch.status == 1
            && active_fence_stop_id(transaction, record.workspace_id())? == Some(record.stop_id())
        {
            return Err(ExecutionStopStoreError::Corrupt(
                "completed settlement fence",
            ));
        }
    } else if !rows.is_empty() {
        let _authority = observe_stop_authority_receipt_in_transaction(
            transaction,
            record.stop_id(),
            record.workspace_id(),
        )?
        .ok_or(ExecutionStopStoreError::Corrupt(
            "partial settlement authority missing",
        ))?;
    } else if rows.is_empty() {
        return Ok(record);
    }
    let mut statuses = vec![ExecutionStopTargetStatus::Pending; record.targets().len()];
    for row in &rows {
        let target = record.targets().get(usize::from(row.ordinal)).ok_or(
            ExecutionStopStoreError::Corrupt("settlement target ordinal"),
        )?;
        if target.execution_id() != row.execution_id
            || target.expected_revision() != row.expected_revision
            || target.expected_state() != row.expected_state
            || target.request_digest() != &row.request_digest
        {
            return Err(ExecutionStopStoreError::Corrupt(
                "settlement target capture identity",
            ));
        }
        if row.status == 1 {
            let proof = positive_target_proof(transaction, &record, target)
                .map_err(|_| ExecutionStopStoreError::Corrupt("settlement target terminal proof"))?
                .ok_or(ExecutionStopStoreError::Corrupt(
                    "settlement target terminal proof",
                ))?;
            validate_stored_target(row, &proof).map_err(|_| {
                ExecutionStopStoreError::Corrupt("settlement target terminal proof")
            })?;
            statuses[usize::from(row.ordinal)] = ExecutionStopTargetStatus::Closed;
        }
    }
    let completed = batch.is_some_and(|batch| batch.status == 1)
        && statuses
            .iter()
            .all(|status| *status == ExecutionStopTargetStatus::Closed);
    validate_completed_digest(transaction, &record, batch.as_ref(), &rows, completed)?;
    let status = if completed {
        ExecutionStopStatus::Completed
    } else {
        ExecutionStopStatus::Pending
    };
    record
        .with_statuses(status, &statuses)
        .map_err(|()| ExecutionStopStoreError::Corrupt("settlement status count"))
}

/// Append positive terminal/closure facts and remove the exact active fence.
/// Native quiescence is observed by the live Coordinator owner and is passed
/// here only after that owner check; this function performs no native I/O.
fn validate_completed_digest(
    connection: &Connection,
    record: &ExecutionStopRecord,
    batch: Option<&RawBatch>,
    rows: &[RawSettlementTarget],
    completed: bool,
) -> Result<(), ExecutionStopStoreError> {
    if let Some(batch) = batch {
        if batch.status == 1 && !completed {
            return Err(ExecutionStopStoreError::Corrupt(
                "completed settlement target count",
            ));
        }
        if batch.status == 1 {
            let authority = observe_stop_authority_receipt_in_transaction(
                connection,
                record.stop_id(),
                record.workspace_id(),
            )?
            .ok_or(ExecutionStopStoreError::Corrupt(
                "settlement authority missing",
            ))?;
            let proofs = rows
                .iter()
                .map(|row| SettlementTargetProof {
                    ordinal: row.ordinal,
                    execution_id: row.execution_id,
                    expected_revision: row.expected_revision,
                    expected_state: row.expected_state,
                    request_digest: row.request_digest,
                    after_revision: row.after_revision,
                    after_state: row.after_state,
                    final_output_sequence: row.final_output_sequence,
                    terminal_digest: row.terminal_digest,
                })
                .collect::<Vec<_>>();
            if settlement_digest(record, &authority, &proofs, batch.settled_at)
                != batch.settlement_digest
            {
                return Err(ExecutionStopStoreError::Corrupt("settlement digest"));
            }
        }
    }
    Ok(())
}

pub(crate) fn settle_in_transaction(
    transaction: &Transaction<'_>,
    record: &ExecutionStopRecord,
    authority: &AuthorityStopReceipt,
    quiescent: bool,
    observed_at: TimestampMillis,
) -> Result<ExecutionStopRecord, ExecutionStopStoreError> {
    let existing_batch = load_batch(transaction, record.stop_id())?;
    if let Some(batch) = existing_batch.as_ref() {
        validate_batch_identity(record, batch)?;
        if batch.status == 1 {
            if batch.authority_target_count != authority.target_count()
                || batch.authority_cohort_digest != *authority.cohort_digest()
                || active_fence_stop_id(transaction, record.workspace_id())?
                    == Some(record.stop_id())
            {
                return Err(ExecutionStopStoreError::SettlementConflict);
            }
            return hydrate_record_in_transaction(transaction, record.clone());
        }
    }
    if record.status() != ExecutionStopStatus::Pending
        || authority.stop_id() != record.stop_id()
        || authority.workspace_id() != record.workspace_id()
    {
        return Err(ExecutionStopStoreError::SettlementConflict);
    }
    if active_fence_stop_id(transaction, record.workspace_id())? != Some(record.stop_id()) {
        return Err(ExecutionStopStoreError::SettlementConflict);
    }
    let captured = super::load_capture_record(transaction, record.stop_id())?.ok_or(
        ExecutionStopStoreError::Corrupt("settlement capture missing"),
    )?;
    if !same_capture_identity(&captured, record) {
        return Err(ExecutionStopStoreError::SettlementConflict);
    }

    let observed_authority = observe_stop_authority_receipt_in_transaction(
        transaction,
        record.stop_id(),
        record.workspace_id(),
    )?
    .ok_or(ExecutionStopStoreError::SettlementPending)?;
    if observed_authority != *authority {
        return Err(ExecutionStopStoreError::SettlementConflict);
    }

    let active = super::active_targets(transaction, record.workspace_id())?;
    if active.iter().any(|target| {
        !record
            .targets()
            .iter()
            .any(|captured| captured.execution_id() == target.execution_id())
    }) {
        return Err(ExecutionStopStoreError::SettlementConflict);
    }

    let proofs = collect_positive_proofs(transaction, record)?;
    let complete = proofs.len() == record.targets().len() && quiescent;
    let settlement_digest = settlement_digest(record, authority, &proofs, observed_at);
    if complete && existing_batch.is_none() {
        insert_batch(
            transaction,
            record,
            authority,
            1,
            true,
            settlement_digest,
            observed_at,
        )?;
    } else if complete {
        return Err(ExecutionStopStoreError::SettlementConflict);
    }
    append_target_proofs(transaction, record, &proofs)?;
    if !complete {
        return hydrate_record_in_transaction(transaction, record.clone());
    }
    let deleted = transaction.execute(
        "DELETE FROM workspace_execution_stop_fences
         WHERE workspace_id = ?1 AND stop_id = ?2",
        params![
            record.workspace_id().into_uuid().as_bytes(),
            record.stop_id().as_bytes()
        ],
    )?;
    if deleted != 1 {
        return Err(ExecutionStopStoreError::SettlementConflict);
    }
    let statuses = vec![ExecutionStopTargetStatus::Closed; record.targets().len()];
    record
        .clone()
        .with_statuses(ExecutionStopStatus::Completed, &statuses)
        .map_err(|()| ExecutionStopStoreError::Corrupt("settlement status count"))
}

fn collect_positive_proofs(
    connection: &Connection,
    record: &ExecutionStopRecord,
) -> Result<Vec<SettlementTargetProof>, ExecutionStopStoreError> {
    let mut proofs = Vec::with_capacity(record.targets().len());
    for target in record.targets() {
        if let Some(proof) = positive_target_proof(connection, record, target)? {
            proofs.push(proof);
        }
    }
    Ok(proofs)
}

fn append_target_proofs(
    transaction: &Transaction<'_>,
    record: &ExecutionStopRecord,
    proofs: &[SettlementTargetProof],
) -> Result<(), ExecutionStopStoreError> {
    let existing = load_settlement_targets(transaction, record.stop_id())?;
    for proof in proofs {
        if let Some(stored) = existing
            .iter()
            .find(|target| target.ordinal == proof.ordinal)
        {
            validate_stored_target(stored, proof)?;
            continue;
        }
        transaction.execute(
            "INSERT INTO workspace_execution_stop_settlement_targets(
                stop_id, ordinal, execution_id, target_status,
                expected_revision, expected_state, request_digest,
                after_revision, after_state, final_output_sequence, terminal_digest
             ) VALUES (?1, ?2, ?3, 1, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                record.stop_id().as_bytes(),
                i64::from(proof.ordinal),
                proof.execution_id.into_uuid().as_bytes(),
                proof.expected_revision.get(),
                encode_state(proof.expected_state),
                proof.request_digest.as_slice(),
                proof.after_revision.get(),
                encode_state(proof.after_state),
                i64::try_from(proof.final_output_sequence)
                    .map_err(|_| ExecutionStopStoreError::Corrupt("output sequence"))?,
                proof.terminal_digest.as_slice(),
            ],
        )?;
    }
    Ok(())
}

fn positive_target_proof(
    transaction: &Connection,
    record: &ExecutionStopRecord,
    target: &super::ExecutionStopTarget,
) -> Result<Option<SettlementTargetProof>, ExecutionStopStoreError> {
    let current =
        crate::workspace_executions::get_execution_tx(transaction, target.execution_id())?.ok_or(
            ExecutionStopStoreError::Corrupt("settlement execution missing"),
        )?;
    if current.workspace_id() != record.workspace_id()
        || current.request_digest().as_bytes() != target.request_digest()
    {
        return Err(ExecutionStopStoreError::SettlementConflict);
    }
    if matches!(target.expected_state(), ExecutionState::Interrupted)
        || !matches!(
            current.state(),
            ExecutionState::Completed
                | ExecutionState::Failed
                | ExecutionState::TimedOut
                | ExecutionState::Cancelled
        )
    {
        return Ok(None);
    }
    let manifest = crate::workspace_executions::get_generated_package_manifest_tx(
        transaction,
        current.id(),
        Some(&current),
    )?;
    let Some(closure) =
        native_closure::read_in_transaction(transaction, &current, manifest.as_ref())?
    else {
        return Ok(None);
    };
    let expected_before = match target.expected_state() {
        ExecutionState::Starting => target
            .expected_revision()
            .checked_next()
            .map_err(|_| ExecutionStopStoreError::SettlementConflict)?,
        ExecutionState::Running => target.expected_revision(),
        ExecutionState::Interrupted => return Ok(None),
        _ => return Err(ExecutionStopStoreError::SettlementConflict),
    };
    if closure.before_revision() != expected_before
        || closure.after_revision() != current.revision()
        || current.request_digest().as_bytes() != closure.request_digest().as_bytes()
        || closure.observed_at().get() < record.created_at().get()
    {
        return Err(ExecutionStopStoreError::SettlementConflict);
    }
    Ok(Some(SettlementTargetProof {
        ordinal: target.ordinal(),
        execution_id: target.execution_id(),
        expected_revision: target.expected_revision(),
        expected_state: target.expected_state(),
        request_digest: *target.request_digest(),
        after_revision: current.revision(),
        after_state: current.state(),
        final_output_sequence: closure.output_cursor().after_sequence(),
        terminal_digest: terminal_digest(&current, manifest, &closure),
    }))
}

fn validate_stored_target(
    stored: &RawSettlementTarget,
    proof: &SettlementTargetProof,
) -> Result<(), ExecutionStopStoreError> {
    if stored.ordinal != proof.ordinal
        || stored.execution_id != proof.execution_id
        || stored.status != 1
        || stored.expected_revision != proof.expected_revision
        || stored.expected_state != proof.expected_state
        || stored.request_digest != proof.request_digest
        || stored.after_revision != proof.after_revision
        || stored.after_state != proof.after_state
        || stored.final_output_sequence != proof.final_output_sequence
        || stored.terminal_digest != proof.terminal_digest
    {
        return Err(ExecutionStopStoreError::SettlementConflict);
    }
    Ok(())
}

fn insert_batch(
    transaction: &Transaction<'_>,
    record: &ExecutionStopRecord,
    authority: &AuthorityStopReceipt,
    status: i64,
    quiescent: bool,
    settlement_digest: [u8; DIGEST_BYTES],
    observed_at: TimestampMillis,
) -> Result<(), ExecutionStopStoreError> {
    transaction.execute(
        "INSERT INTO workspace_execution_stop_settlements(
            stop_id, workspace_id, request_id, owner_runtime_instance_id,
            status, execution_target_count, authority_target_count,
            execution_cohort_digest, authority_cohort_digest, settlement_digest,
            quiescent, settled_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            record.stop_id().as_bytes(),
            record.workspace_id().into_uuid().as_bytes(),
            record.request_id().as_bytes(),
            record.owner_runtime_instance_id().into_uuid().as_bytes(),
            status,
            i64::try_from(record.target_count()).map_err(|_| {
                ExecutionStopStoreError::Overflow {
                    actual: record.target_count(),
                    maximum: MAX_EXECUTION_STOP_TARGETS,
                }
            })?,
            i64::try_from(authority.target_count()).map_err(|_| {
                ExecutionStopStoreError::Overflow {
                    actual: authority.target_count(),
                    maximum: 768,
                }
            })?,
            record.cohort_digest().as_slice(),
            authority.cohort_digest(),
            settlement_digest.as_slice(),
            i64::from(quiescent),
            observed_at.get(),
        ],
    )?;
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct RawBatch {
    stop_id: Uuid,
    workspace_id: WorkspaceId,
    request_id: Uuid,
    owner_runtime_instance_id: forge_domain::RuntimeInstanceId,
    status: i64,
    execution_target_count: usize,
    authority_target_count: usize,
    execution_cohort_digest: [u8; DIGEST_BYTES],
    authority_cohort_digest: [u8; DIGEST_BYTES],
    settlement_digest: [u8; DIGEST_BYTES],
    quiescent: bool,
    settled_at: TimestampMillis,
}

#[derive(Debug, Clone, Copy)]
struct RawSettlementTarget {
    ordinal: u8,
    execution_id: forge_domain::ExecutionId,
    status: i64,
    expected_revision: forge_domain::ExecutionRevision,
    expected_state: ExecutionState,
    request_digest: [u8; DIGEST_BYTES],
    after_revision: forge_domain::ExecutionRevision,
    after_state: ExecutionState,
    final_output_sequence: u64,
    terminal_digest: [u8; DIGEST_BYTES],
}

fn load_batch(
    transaction: &Connection,
    stop_id: Uuid,
) -> Result<Option<RawBatch>, ExecutionStopStoreError> {
    let row = transaction
        .query_row(
            "SELECT stop_id, workspace_id, request_id, owner_runtime_instance_id,
                    status, execution_target_count, authority_target_count,
                    execution_cohort_digest, authority_cohort_digest,
                    settlement_digest, quiescent, settled_at_ms
             FROM workspace_execution_stop_settlements WHERE stop_id = ?1",
            params![stop_id.as_bytes()],
            |row| {
                let stop_id = decode_uuid_blob(&row.get::<_, Vec<u8>>(0)?, "settlement.stop_id")?;
                let workspace_id = WorkspaceId::from_uuid(decode_uuid_blob(
                    &row.get::<_, Vec<u8>>(1)?,
                    "settlement.workspace_id",
                )?);
                let request_id =
                    decode_uuid_blob(&row.get::<_, Vec<u8>>(2)?, "settlement.request_id")?;
                let owner_runtime_instance_id =
                    forge_domain::RuntimeInstanceId::from_uuid(decode_uuid_blob(
                        &row.get::<_, Vec<u8>>(3)?,
                        "settlement.owner_runtime_instance_id",
                    )?);
                let status = row.get::<_, i64>(4)?;
                let execution_target_count = decode_count(row.get(5)?, 256)?;
                let authority_target_count = decode_count(row.get(6)?, 768)?;
                let execution_cohort_digest = decode_digest_blob(
                    row.get::<_, Vec<u8>>(7)?,
                    "settlement.execution_cohort_digest",
                )?;
                let authority_cohort_digest = decode_digest_blob(
                    row.get::<_, Vec<u8>>(8)?,
                    "settlement.authority_cohort_digest",
                )?;
                let settlement_digest =
                    decode_digest_blob(row.get::<_, Vec<u8>>(9)?, "settlement.settlement_digest")?;
                let quiescent = match row.get::<_, i64>(10)? {
                    1 => true,
                    0 => false,
                    _ => return Err(rusqlite::Error::InvalidQuery),
                };
                let settled_at = TimestampMillis::new(row.get(11)?)
                    .map_err(|_| rusqlite::Error::InvalidQuery)?;
                Ok(RawBatch {
                    stop_id,
                    workspace_id,
                    request_id,
                    owner_runtime_instance_id,
                    status,
                    execution_target_count,
                    authority_target_count,
                    execution_cohort_digest,
                    authority_cohort_digest,
                    settlement_digest,
                    quiescent,
                    settled_at,
                })
            },
        )
        .optional()?;
    Ok(row)
}

fn load_settlement_targets(
    transaction: &Connection,
    stop_id: Uuid,
) -> Result<Vec<RawSettlementTarget>, ExecutionStopStoreError> {
    let mut statement = transaction.prepare(
        "SELECT ordinal, execution_id, target_status, expected_revision,
                expected_state, request_digest, after_revision, after_state,
                final_output_sequence, terminal_digest
         FROM workspace_execution_stop_settlement_targets
         WHERE stop_id = ?1 ORDER BY ordinal LIMIT ?2",
    )?;
    let rows = statement
        .query_map(
            params![
                stop_id.as_bytes(),
                i64::try_from(MAX_EXECUTION_STOP_TARGETS + 1).unwrap_or(i64::MAX)
            ],
            |row| {
                let ordinal = u8::try_from(row.get::<_, i64>(0)?)
                    .map_err(|_| rusqlite::Error::InvalidQuery)?;
                let execution_id = forge_domain::ExecutionId::from_uuid(decode_uuid_blob(
                    &row.get::<_, Vec<u8>>(1)?,
                    "settlement target.execution_id",
                )?);
                let status = row.get::<_, i64>(2)?;
                let expected_revision = forge_domain::ExecutionRevision::new(row.get(3)?)
                    .map_err(|_| rusqlite::Error::InvalidQuery)?;
                let expected_state = decode_expected_state(row.get(4)?)?;
                let request_digest = decode_digest_blob(
                    row.get::<_, Vec<u8>>(5)?,
                    "settlement target.request_digest",
                )?;
                let after_revision = forge_domain::ExecutionRevision::new(row.get(6)?)
                    .map_err(|_| rusqlite::Error::InvalidQuery)?;
                let after_state = decode_terminal_state(row.get(7)?)?;
                let final_output_sequence = u64::try_from(row.get::<_, i64>(8)?)
                    .map_err(|_| rusqlite::Error::InvalidQuery)?;
                let terminal_digest = decode_digest_blob(
                    row.get::<_, Vec<u8>>(9)?,
                    "settlement target.terminal_digest",
                )?;
                Ok(RawSettlementTarget {
                    ordinal,
                    execution_id,
                    status,
                    expected_revision,
                    expected_state,
                    request_digest,
                    after_revision,
                    after_state,
                    final_output_sequence,
                    terminal_digest,
                })
            },
        )?
        .collect::<Result<Vec<_>, _>>()?;
    if rows.len() > MAX_EXECUTION_STOP_TARGETS {
        return Err(ExecutionStopStoreError::Overflow {
            actual: rows.len(),
            maximum: MAX_EXECUTION_STOP_TARGETS,
        });
    }
    Ok(rows)
}

fn validate_batch_identity(
    record: &ExecutionStopRecord,
    batch: &RawBatch,
) -> Result<(), ExecutionStopStoreError> {
    if batch.stop_id != record.stop_id()
        || batch.workspace_id != record.workspace_id()
        || batch.request_id != record.request_id()
        || batch.owner_runtime_instance_id != record.owner_runtime_instance_id()
        || batch.execution_target_count != record.target_count()
        || batch.execution_cohort_digest != *record.cohort_digest()
        || batch.status != 1
        || !batch.quiescent
        || batch.settled_at.get() < record.created_at().get()
    {
        return Err(ExecutionStopStoreError::SettlementConflict);
    }
    Ok(())
}

fn same_capture_identity(left: &ExecutionStopRecord, right: &ExecutionStopRecord) -> bool {
    left.stop_id() == right.stop_id()
        && left.workspace_id() == right.workspace_id()
        && left.request_id() == right.request_id()
        && left.owner_runtime_instance_id() == right.owner_runtime_instance_id()
        && left.request_digest() == right.request_digest()
        && left.binding_digest() == right.binding_digest()
        && left.target_count() == right.target_count()
        && left.cohort_digest() == right.cohort_digest()
        && left.created_at() == right.created_at()
}

fn decode_uuid_blob(value: &[u8], _field: &'static str) -> rusqlite::Result<Uuid> {
    if value.len() != ID_BYTES {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Uuid::from_slice(value).map_err(|_| rusqlite::Error::InvalidQuery)
}

fn decode_digest_blob(
    value: Vec<u8>,
    _field: &'static str,
) -> rusqlite::Result<[u8; DIGEST_BYTES]> {
    value.try_into().map_err(|_| rusqlite::Error::InvalidQuery)
}

fn decode_count(value: i64, maximum: usize) -> rusqlite::Result<usize> {
    usize::try_from(value)
        .ok()
        .filter(|value| *value <= maximum)
        .ok_or(rusqlite::Error::InvalidQuery)
}

fn decode_expected_state(value: i64) -> rusqlite::Result<ExecutionState> {
    match value {
        0 => Ok(ExecutionState::Starting),
        1 => Ok(ExecutionState::Running),
        6 => Ok(ExecutionState::Interrupted),
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}

fn decode_terminal_state(value: i64) -> rusqlite::Result<ExecutionState> {
    match value {
        2 => Ok(ExecutionState::Completed),
        3 => Ok(ExecutionState::Failed),
        4 => Ok(ExecutionState::TimedOut),
        5 => Ok(ExecutionState::Cancelled),
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}

fn terminal_digest(
    record: &RegisteredExecution,
    manifest: Option<GeneratedPackageManifest>,
    closure: &ExecutionNativeClosureFact,
) -> [u8; DIGEST_BYTES] {
    let mut writer = DigestWriter::new(b"forge.workspace.stop.terminal-fact.v1\0");
    writer.uuid(record.id().into_uuid());
    writer.uuid(record.workspace_id().into_uuid());
    writer.uuid(record.activity_id().into_uuid());
    writer.bytes(record.request_digest().as_bytes());
    writer.i64(record.timestamps().created_at().get());
    writer.i64(record.timestamps().updated_at().get());
    writer.i64(record.revision().get());
    writer.i64(encode_state(record.state()));
    writer.u8(record.failure_code().map_or(u8::MAX, encode_failure));
    writer.u8(match record.mode() {
        ExecutionMode::Structured => 0,
        ExecutionMode::Shell => 1,
    });
    writer.u64(record.limits().timeout().get());
    writer.u64(record.limits().output().get());
    let permissions = record.permissions();
    writer.u8(u8::from(permissions.workspace_read()));
    writer.u8(u8::from(permissions.workspace_write()));
    writer.u8(u8::from(permissions.network()));
    match record.cwd() {
        Some(path) => writer.bytes(path.as_path().as_os_str().as_bytes()),
        None => writer.none(),
    }
    match record.outcome() {
        Some(outcome) => {
            writer.u8(1);
            writer.u8(match outcome.status() {
                ExecutionCompletionStatus::Exited => 0,
                ExecutionCompletionStatus::TimedOut => 1,
                ExecutionCompletionStatus::Cancelled => 2,
            });
            writer.i32(outcome.exit_code());
            writer.i32(outcome.signal());
            writer.u64(outcome.duration_millis());
            writer.output(outcome.stdout());
            writer.output(outcome.stderr());
        }
        None => writer.u8(0),
    }
    match manifest {
        Some(manifest) => {
            writer.u8(1);
            writer.uuid(manifest.workspace_id().into_uuid());
            writer.uuid(manifest.execution_id().into_uuid());
            writer.u8(match manifest.kind() {
                GeneratedArtifactKind::MacOsInstallerPackage => 0,
            });
            writer.bytes(manifest.content_hash().as_bytes());
            writer.u64(manifest.byte_count().get());
        }
        None => writer.u8(0),
    }
    writer.uuid(closure.attribution().id().into_uuid());
    writer.uuid(closure.attribution().workspace_id().into_uuid());
    writer.uuid(closure.attribution().activity_id().into_uuid());
    writer.bytes(closure.request_digest().as_bytes());
    writer.i64(closure.before_revision().get());
    writer.i64(closure.after_revision().get());
    writer.u64(closure.output_cursor().after_sequence());
    writer.u8(match closure.launch() {
        NativeClosureLaunch::Baseline => 0,
        NativeClosureLaunch::RustCi => 1,
        NativeClosureLaunch::GeneratedPackage => 2,
    });
    writer.u8(match closure.process() {
        NativeClosureProcess::NoChildSpawned => 0,
        NativeClosureProcess::ProcessGroupReaped => 1,
    });
    writer.u8(match closure.runtime() {
        NativeClosureRuntime::NotApplicable => 0,
        NativeClosureRuntime::Cleaned => 1,
    });
    writer.i64(closure.observed_at().get());
    writer.finish()
}

fn settlement_digest(
    record: &ExecutionStopRecord,
    authority: &AuthorityStopReceipt,
    proofs: &[SettlementTargetProof],
    observed_at: TimestampMillis,
) -> [u8; DIGEST_BYTES] {
    let mut writer = DigestWriter::new(b"forge.workspace.stop.settlement.v1\0");
    writer.uuid(record.stop_id());
    writer.uuid(record.workspace_id().into_uuid());
    writer.uuid(record.request_id());
    writer.bytes(record.request_digest());
    writer.bytes(record.cohort_digest());
    writer.bytes(authority.cohort_digest());
    writer.u64(authority.target_count() as u64);
    writer.i64(observed_at.get());
    for proof in proofs {
        writer.u8(proof.ordinal);
        writer.uuid(proof.execution_id.into_uuid());
        writer.i64(proof.expected_revision.get());
        writer.i64(encode_state(proof.expected_state));
        writer.bytes(&proof.terminal_digest);
    }
    writer.finish()
}

fn encode_failure(value: ExecutionFailureCode) -> u8 {
    match value {
        ExecutionFailureCode::Admission => 0,
        ExecutionFailureCode::SandboxUnavailable => 1,
        ExecutionFailureCode::InvalidWorkingDirectory => 2,
        ExecutionFailureCode::ProcessSpawn => 3,
        ExecutionFailureCode::Supervision => 4,
    }
}

fn encode_state(value: ExecutionState) -> i64 {
    match value {
        ExecutionState::Starting => 0,
        ExecutionState::Running => 1,
        ExecutionState::Completed => 2,
        ExecutionState::Failed => 3,
        ExecutionState::TimedOut => 4,
        ExecutionState::Cancelled => 5,
        ExecutionState::Interrupted => 6,
    }
}

struct DigestWriter(Sha256);

impl DigestWriter {
    fn new(tag: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(tag);
        Self(hasher)
    }

    fn uuid(&mut self, value: Uuid) {
        self.bytes(value.as_bytes());
    }

    fn bytes(&mut self, value: &[u8]) {
        self.0.update((value.len() as u64).to_le_bytes());
        self.0.update(value);
    }

    fn none(&mut self) {
        self.0.update(0_u64.to_le_bytes());
    }

    fn i32(&mut self, value: Option<i32>) {
        match value {
            Some(value) => {
                self.u8(1);
                self.0.update(value.to_le_bytes());
            }
            None => self.u8(0),
        }
    }

    fn i64(&mut self, value: i64) {
        self.0.update(value.to_le_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.0.update(value.to_le_bytes());
    }

    fn u8(&mut self, value: u8) {
        self.0.update([value]);
    }

    fn output(&mut self, output: &forge_domain::BoundedExecutionOutput) {
        self.bytes(output.retained());
        self.u64(output.total_bytes());
        self.u8(u8::from(output.truncated()));
    }

    fn finish(self) -> [u8; DIGEST_BYTES] {
        self.0.finalize().into()
    }
}
