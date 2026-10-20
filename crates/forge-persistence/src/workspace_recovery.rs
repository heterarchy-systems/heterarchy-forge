//! Durable persistence for the Workspace recovery-maintenance lease.
//!
//! The recovery lease is deliberately a very small repository boundary.  The
//! domain owns all transition policy; this module only decodes and encodes the
//! fixed-width `SQLite` row and applies one compare-and-swap in a short
//! transaction supplied by [`WorkspaceStore`](crate::WorkspaceStore).

use forge_domain::{
    ClaimRecoveryLease, RecoveryLeaseClaimDecision, RecoveryLeaseEpoch, RecoveryLeaseEpochError,
    RecoveryLeaseRevision, RecoveryLeaseRevisionError, RecoveryLeaseTransitionError,
    RecoveryMaintenanceLease, RecoveryMaintenanceLeaseError, ReleaseRecoveryLease,
    RenewRecoveryLease, RuntimeInstanceId, TimestampMillis, TimestampMillisError, WorkspaceId,
};
use rusqlite::{Connection, OptionalExtension, Row, Transaction, params};
use thiserror::Error;

const ID_BYTES: usize = 16;
const ID_BYTES_I64: i64 = 16;

/// Canonical SQL for the singleton recovery-maintenance lease table.
pub(crate) const EXPECTED_RECOVERY_MAINTENANCE_TABLE_SQL: &str = "CREATE TABLE recovery_maintenance (workspace_id BLOB PRIMARY KEY NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16), owner_runtime_instance_id BLOB CHECK(owner_runtime_instance_id IS NULL OR length(owner_runtime_instance_id) = 16), lease_until_ms INTEGER CHECK(lease_until_ms IS NULL OR lease_until_ms >= 0), epoch INTEGER NOT NULL CHECK(epoch >= 0), updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0), revision INTEGER NOT NULL CHECK(revision >= 1), CHECK((owner_runtime_instance_id IS NULL) = (lease_until_ms IS NULL)))";

const EXPECTED_RECOVERY_COLUMNS: [(&str, &str, i64, i64); 6] = [
    ("workspace_id", "BLOB", 1, 1),
    ("owner_runtime_instance_id", "BLOB", 0, 0),
    ("lease_until_ms", "INTEGER", 0, 0),
    ("epoch", "INTEGER", 1, 0),
    ("updated_at_ms", "INTEGER", 1, 0),
    ("revision", "INTEGER", 1, 0),
];

/// The outcome of one recovery-lease claim attempt.
///
/// `Busy` and `ClaimConflict` are returned as ordinary outcomes rather than
/// errors.  Their embedded lease is the unchanged durable snapshot, making it
/// explicit that neither outcome performed a semantic mutation.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecoveryLeaseClaimStatus {
    /// A released or expired lease was acquired by this command.
    Acquired,
    /// The exact owner and expiry were already persisted.
    AlreadyOwned,
    /// Another owner still has a live lease.
    Busy,
    /// The same owner supplied a different live expiry.
    ClaimConflict,
}

/// Durable result of one recovery-lease claim attempt.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryLeaseClaimResult {
    status: RecoveryLeaseClaimStatus,
    lease: RecoveryMaintenanceLease,
}

impl RecoveryLeaseClaimResult {
    const fn new(status: RecoveryLeaseClaimStatus, lease: RecoveryMaintenanceLease) -> Self {
        Self { status, lease }
    }

    /// Claim classification returned by the deterministic domain decision.
    pub const fn status(&self) -> RecoveryLeaseClaimStatus {
        self.status
    }

    /// Lease snapshot observed or acquired by the claim.
    pub const fn lease(&self) -> &RecoveryMaintenanceLease {
        &self.lease
    }

    /// Consume the result and return its lease snapshot.
    pub fn into_lease(self) -> RecoveryMaintenanceLease {
        self.lease
    }

    pub const fn is_acquired(&self) -> bool {
        matches!(self.status, RecoveryLeaseClaimStatus::Acquired)
    }
}

/// Errors raised while decoding or persisting the recovery-maintenance row.
#[derive(Debug, Error)]
pub enum RecoveryStoreError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error("recovery-maintenance lease row is missing")]
    RecordMissing,
    #[error("recovery-maintenance lease Workspace mismatch: expected {expected}, actual {actual}")]
    WorkspaceMismatch {
        expected: WorkspaceId,
        actual: WorkspaceId,
    },
    #[error("recovery-maintenance lease compare-and-swap found a changed row")]
    CompareAndSwapConflict,
    #[error("recovery-maintenance schema is damaged: {0}")]
    DamagedSchema(&'static str),
    #[error("recovery-maintenance field {field} has invalid length {actual}; expected {expected}")]
    InvalidFieldLength {
        field: &'static str,
        actual: usize,
        expected: usize,
    },
    #[error("recovery-maintenance field {field} is missing")]
    MissingField { field: &'static str },
    #[error("recovery-maintenance field {field} has invalid value {actual}")]
    InvalidFieldValue { field: &'static str, actual: i64 },
    #[error("recovery-maintenance timestamp field {field} is invalid: {source}")]
    InvalidTimestamp {
        field: &'static str,
        #[source]
        source: TimestampMillisError,
    },
    #[error(transparent)]
    Epoch(#[from] RecoveryLeaseEpochError),
    #[error(transparent)]
    Revision(#[from] RecoveryLeaseRevisionError),
    #[error(transparent)]
    Maintenance(#[from] RecoveryMaintenanceLeaseError),
    #[error(transparent)]
    Transition(#[from] RecoveryLeaseTransitionError),
}

/// Create the v11 recovery-maintenance table inside the caller's transaction.
pub(crate) fn create_schema(connection: &Connection) -> Result<(), RecoveryStoreError> {
    connection.execute_batch(
        "CREATE TABLE recovery_maintenance (
            workspace_id BLOB PRIMARY KEY NOT NULL
                REFERENCES workspace(workspace_id)
                CHECK(length(workspace_id) = 16),
            owner_runtime_instance_id BLOB
                CHECK(owner_runtime_instance_id IS NULL
                      OR length(owner_runtime_instance_id) = 16),
            lease_until_ms INTEGER
                CHECK(lease_until_ms IS NULL OR lease_until_ms >= 0),
            epoch INTEGER NOT NULL CHECK(epoch >= 0),
            updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0),
            revision INTEGER NOT NULL CHECK(revision >= 1),
            CHECK((owner_runtime_instance_id IS NULL) = (lease_until_ms IS NULL))
         );",
    )?;
    Ok(())
}

pub(crate) fn schema_objects() -> [(&'static str, &'static str); 1] {
    [("table", "recovery_maintenance")]
}

/// Validate the exact v11 table SQL, column shape, and Workspace foreign key.
pub(crate) fn validate_schema(connection: &Connection) -> Result<(), RecoveryStoreError> {
    let actual: Option<String> = connection
        .query_row(
            "SELECT sql FROM sqlite_schema
             WHERE type = 'table' AND name = 'recovery_maintenance'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if actual.as_deref().map(normalize_sql)
        != Some(normalize_sql(EXPECTED_RECOVERY_MAINTENANCE_TABLE_SQL))
    {
        return Err(RecoveryStoreError::DamagedSchema(
            "recovery_maintenance table SQL definition does not match the expected policy",
        ));
    }

    let mut statement = connection.prepare("PRAGMA table_info(recovery_maintenance)")?;
    let mut rows = statement.query([])?;
    let mut columns = Vec::with_capacity(EXPECTED_RECOVERY_COLUMNS.len());
    while let Some(row) = rows.next()? {
        if columns.len() >= EXPECTED_RECOVERY_COLUMNS.len() {
            return Err(RecoveryStoreError::DamagedSchema(
                "recovery_maintenance table has too many columns",
            ));
        }
        columns.push((
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, i64>(5)?,
        ));
    }
    let columns_match = columns.len() == EXPECTED_RECOVERY_COLUMNS.len()
        && columns.iter().zip(EXPECTED_RECOVERY_COLUMNS).all(
            |((name, data_type, not_null, primary_key), expected)| {
                name == expected.0
                    && data_type == expected.1
                    && *not_null == expected.2
                    && *primary_key == expected.3
            },
        );
    if !columns_match {
        return Err(RecoveryStoreError::DamagedSchema(
            "recovery_maintenance table columns do not match the expected shape",
        ));
    }

    let mut foreign_keys = connection.prepare("PRAGMA foreign_key_list(recovery_maintenance)")?;
    let foreign_key = foreign_keys
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
    let valid_foreign_key = foreign_key.len() == 1
        && foreign_key[0].0 == "workspace"
        && foreign_key[0].1 == "workspace_id"
        && foreign_key[0].2 == "workspace_id"
        && foreign_key[0].3 == "NO ACTION"
        && foreign_key[0].4 == "NO ACTION"
        && foreign_key[0].5 == "NONE";
    if !valid_foreign_key {
        return Err(RecoveryStoreError::DamagedSchema(
            "recovery_maintenance foreign-key shape is invalid",
        ));
    }
    Ok(())
}

/// Insert the initial released row after the Workspace row has been inserted
/// in the same IMMEDIATE transaction.
pub(crate) fn insert_released(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
    observed_at: TimestampMillis,
) -> Result<RecoveryMaintenanceLease, RecoveryStoreError> {
    let lease = RecoveryMaintenanceLease::released(workspace_id, observed_at);
    let id = lease.workspace_id().into_uuid().into_bytes();
    transaction.execute(
        "INSERT INTO recovery_maintenance (
            workspace_id, owner_runtime_instance_id, lease_until_ms,
            epoch, updated_at_ms, revision
         ) VALUES (?1, NULL, NULL, 0, ?2, 1)",
        params![id.as_slice(), lease.updated_at().get()],
    )?;
    get_in_transaction(transaction, lease.workspace_id())
}

/// Load the one recovery-maintenance row for a bound Workspace.
pub(crate) fn get(
    connection: &Connection,
    workspace_id: WorkspaceId,
) -> Result<RecoveryMaintenanceLease, RecoveryStoreError> {
    query_lease(connection, workspace_id)
}

/// Claim or classify the row in the caller's IMMEDIATE transaction.
pub(crate) fn claim(
    transaction: &Transaction<'_>,
    command: &ClaimRecoveryLease,
) -> Result<RecoveryLeaseClaimResult, RecoveryStoreError> {
    let current = get_in_transaction(transaction, command.workspace_id())?;
    let decision = current.decide_claim(command)?;
    match decision {
        RecoveryLeaseClaimDecision::Acquired => {
            let next = current.claim(command)?;
            update_compare_and_swap(transaction, &current, &next)?;
            Ok(RecoveryLeaseClaimResult::new(
                RecoveryLeaseClaimStatus::Acquired,
                next,
            ))
        }
        RecoveryLeaseClaimDecision::AlreadyOwned => Ok(RecoveryLeaseClaimResult::new(
            RecoveryLeaseClaimStatus::AlreadyOwned,
            current,
        )),
        RecoveryLeaseClaimDecision::Busy => Ok(RecoveryLeaseClaimResult::new(
            RecoveryLeaseClaimStatus::Busy,
            current,
        )),
        RecoveryLeaseClaimDecision::ClaimConflict => Ok(RecoveryLeaseClaimResult::new(
            RecoveryLeaseClaimStatus::ClaimConflict,
            current,
        )),
    }
}

/// Renew the row through exact owner, epoch, and revision fencing.
pub(crate) fn renew(
    transaction: &Transaction<'_>,
    command: &RenewRecoveryLease,
) -> Result<RecoveryMaintenanceLease, RecoveryStoreError> {
    let current = get_in_transaction(transaction, command.workspace_id())?;
    let next = current.renew(command)?;
    update_compare_and_swap(transaction, &current, &next)?;
    Ok(next)
}

/// Release the row through exact owner, epoch, and revision fencing.
pub(crate) fn release(
    transaction: &Transaction<'_>,
    command: &ReleaseRecoveryLease,
) -> Result<RecoveryMaintenanceLease, RecoveryStoreError> {
    let current = get_in_transaction(transaction, command.workspace_id())?;
    let next = current.release(command)?;
    update_compare_and_swap(transaction, &current, &next)?;
    Ok(next)
}

fn get_in_transaction(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
) -> Result<RecoveryMaintenanceLease, RecoveryStoreError> {
    query_lease(transaction, workspace_id)
}

fn query_lease(
    connection: &Connection,
    workspace_id: WorkspaceId,
) -> Result<RecoveryMaintenanceLease, RecoveryStoreError> {
    let id = workspace_id.into_uuid().into_bytes();
    let raw = connection
        .query_row(
            "SELECT length(CAST(workspace_id AS BLOB)),
                    length(CAST(owner_runtime_instance_id AS BLOB)),
                    workspace_id, owner_runtime_instance_id, lease_until_ms,
                    epoch, updated_at_ms, revision
             FROM recovery_maintenance
             WHERE workspace_id = ?1",
            params![id.as_slice()],
            decode_raw_row,
        )
        .optional()?
        .ok_or(RecoveryStoreError::RecordMissing)?;
    decode_row(raw)
}

#[derive(Debug)]
struct RawRecoveryLeaseRow {
    workspace_length: Option<i64>,
    owner_length: Option<i64>,
    workspace_id: Vec<u8>,
    owner_id: Option<Vec<u8>>,
    lease_until: Option<i64>,
    epoch: i64,
    updated_at: i64,
    revision: i64,
}

fn decode_raw_row(row: &Row<'_>) -> rusqlite::Result<RawRecoveryLeaseRow> {
    Ok(RawRecoveryLeaseRow {
        workspace_length: row.get(0)?,
        owner_length: row.get(1)?,
        workspace_id: row.get(2)?,
        owner_id: row.get(3)?,
        lease_until: row.get(4)?,
        epoch: row.get(5)?,
        updated_at: row.get(6)?,
        revision: row.get(7)?,
    })
}

fn decode_row(raw: RawRecoveryLeaseRow) -> Result<RecoveryMaintenanceLease, RecoveryStoreError> {
    let workspace_length = raw.workspace_length;
    let workspace_id = decode_workspace_id(
        workspace_length,
        raw.workspace_id,
        "recovery_maintenance.workspace_id",
    )?;
    let owner_length = raw.owner_length;
    let owner_bytes = raw.owner_id;
    let owner_id = match (owner_length, owner_bytes) {
        (None, None) => None,
        (Some(length), Some(bytes)) => Some(decode_runtime_id(
            Some(length),
            bytes,
            "recovery_maintenance.owner_runtime_instance_id",
        )?),
        (None, Some(_)) | (Some(_), None) => {
            return Err(RecoveryStoreError::InvalidFieldValue {
                field: "recovery_maintenance.owner_runtime_instance_id",
                actual: -1,
            });
        }
    };
    let lease_until = decode_timestamp(raw.lease_until, "recovery_maintenance.lease_until_ms")?;
    let epoch = RecoveryLeaseEpoch::new(raw.epoch)?;
    let updated_at = decode_timestamp(Some(raw.updated_at), "recovery_maintenance.updated_at_ms")?
        .ok_or(RecoveryStoreError::MissingField {
            field: "recovery_maintenance.updated_at_ms",
        })?;
    let revision = RecoveryLeaseRevision::new(raw.revision)?;
    RecoveryMaintenanceLease::from_parts(
        workspace_id,
        owner_id,
        lease_until,
        epoch,
        updated_at,
        revision,
    )
    .map_err(RecoveryStoreError::from)
}

fn decode_workspace_id(
    length: Option<i64>,
    bytes: Vec<u8>,
    field: &'static str,
) -> Result<WorkspaceId, RecoveryStoreError> {
    validate_id_length(length, field)?;
    let actual = bytes.len();
    let bytes: [u8; ID_BYTES] =
        bytes
            .try_into()
            .map_err(|_| RecoveryStoreError::InvalidFieldLength {
                field,
                actual,
                expected: ID_BYTES,
            })?;
    Ok(WorkspaceId::from_uuid(uuid::Uuid::from_bytes(bytes)))
}

fn decode_runtime_id(
    length: Option<i64>,
    bytes: Vec<u8>,
    field: &'static str,
) -> Result<RuntimeInstanceId, RecoveryStoreError> {
    validate_id_length(length, field)?;
    let actual = bytes.len();
    let bytes: [u8; ID_BYTES] =
        bytes
            .try_into()
            .map_err(|_| RecoveryStoreError::InvalidFieldLength {
                field,
                actual,
                expected: ID_BYTES,
            })?;
    Ok(RuntimeInstanceId::from_uuid(uuid::Uuid::from_bytes(bytes)))
}

fn validate_id_length(length: Option<i64>, field: &'static str) -> Result<(), RecoveryStoreError> {
    let Some(length) = length else {
        return Err(RecoveryStoreError::MissingField { field });
    };
    if length != ID_BYTES_I64 {
        return Err(RecoveryStoreError::InvalidFieldLength {
            field,
            actual: usize::try_from(length).unwrap_or(usize::MAX),
            expected: ID_BYTES,
        });
    }
    Ok(())
}

fn decode_timestamp(
    value: Option<i64>,
    field: &'static str,
) -> Result<Option<TimestampMillis>, RecoveryStoreError> {
    value
        .map(|value| {
            TimestampMillis::new(value)
                .map_err(|source| RecoveryStoreError::InvalidTimestamp { field, source })
        })
        .transpose()
}

fn update_compare_and_swap(
    transaction: &Transaction<'_>,
    current: &RecoveryMaintenanceLease,
    next: &RecoveryMaintenanceLease,
) -> Result<(), RecoveryStoreError> {
    let workspace_id = current.workspace_id().into_uuid().into_bytes();
    let current_owner = current
        .owner_id()
        .map(|owner| owner.into_uuid().into_bytes().to_vec());
    let current_expiry = current.lease_until().map(TimestampMillis::get);
    let next_owner = next
        .owner_id()
        .map(|owner| owner.into_uuid().into_bytes().to_vec());
    let next_expiry = next.lease_until().map(TimestampMillis::get);
    let changed = transaction.execute(
        "UPDATE recovery_maintenance
         SET owner_runtime_instance_id = ?1, lease_until_ms = ?2,
             epoch = ?3, updated_at_ms = ?4, revision = ?5
         WHERE workspace_id = ?6
           AND owner_runtime_instance_id IS ?7
           AND lease_until_ms IS ?8
           AND epoch = ?9 AND updated_at_ms = ?10 AND revision = ?11",
        params![
            next_owner.as_deref(),
            next_expiry,
            next.epoch().get(),
            next.updated_at().get(),
            next.revision().get(),
            workspace_id.as_slice(),
            current_owner.as_deref(),
            current_expiry,
            current.epoch().get(),
            current.updated_at().get(),
            current.revision().get(),
        ],
    )?;
    if changed != 1 {
        return Err(RecoveryStoreError::CompareAndSwapConflict);
    }
    Ok(())
}

fn normalize_sql(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect()
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use forge_domain::RecoveryLeaseDurationMillis;
    use rusqlite::TransactionBehavior;
    use uuid::Uuid;

    fn workspace(value: u128) -> WorkspaceId {
        WorkspaceId::from_uuid(Uuid::from_u128(value))
    }

    fn owner(value: u128) -> RuntimeInstanceId {
        RuntimeInstanceId::from_uuid(Uuid::from_u128(value))
    }

    fn timestamp(value: i64) -> TimestampMillis {
        TimestampMillis::new(value).expect("test timestamp must be non-negative")
    }

    fn duration(value: i64) -> RecoveryLeaseDurationMillis {
        RecoveryLeaseDurationMillis::new(value).expect("test duration must be bounded")
    }

    fn claim(
        workspace_id: WorkspaceId,
        owner_id: RuntimeInstanceId,
        observed_at: i64,
    ) -> ClaimRecoveryLease {
        ClaimRecoveryLease::new(
            workspace_id,
            owner_id,
            duration(1_000),
            timestamp(observed_at),
        )
        .expect("test claim must be valid")
    }

    fn connection_with_released_row() -> (Connection, WorkspaceId) {
        let connection = Connection::open_in_memory().expect("in-memory database must open");
        connection
            .execute_batch(
                "PRAGMA foreign_keys = ON;
                 CREATE TABLE workspace (
                    workspace_id BLOB PRIMARY KEY NOT NULL
                 );",
            )
            .expect("workspace table must be created");
        create_schema(&connection).expect("recovery schema must be created");
        let workspace_id = workspace(1);
        connection
            .execute(
                "INSERT INTO workspace(workspace_id) VALUES (?1)",
                params![workspace_id.into_uuid().as_bytes()],
            )
            .expect("workspace row must be inserted");
        let mut connection = connection;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("transaction must begin");
        let _ = insert_released(&transaction, workspace_id, timestamp(10))
            .expect("released lease must be inserted");
        transaction.commit().expect("transaction must commit");
        (connection, workspace_id)
    }

    fn run_claim(
        connection: &mut Connection,
        command: &ClaimRecoveryLease,
    ) -> Result<RecoveryLeaseClaimResult, RecoveryStoreError> {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(RecoveryStoreError::from)?;
        let result = super::claim(&transaction, command)?;
        transaction.commit().map_err(RecoveryStoreError::from)?;
        Ok(result)
    }

    #[test]
    fn schema_and_released_row_round_trip() {
        let (connection, workspace_id) = connection_with_released_row();
        validate_schema(&connection).expect("schema must match the v11 contract");
        let lease = get(&connection, workspace_id).expect("released row must load");
        assert_eq!(
            lease,
            RecoveryMaintenanceLease::released(workspace_id, timestamp(10))
        );
    }

    #[test]
    fn claim_outcomes_are_fenced_and_non_mutating_when_rejected() {
        let (mut connection, workspace_id) = connection_with_released_row();
        let first_command = claim(workspace_id, owner(2), 10);
        let acquired = run_claim(&mut connection, &first_command).expect("claim must run");
        assert_eq!(acquired.status(), RecoveryLeaseClaimStatus::Acquired);
        assert_eq!(acquired.lease().epoch().get(), 1);
        assert_eq!(acquired.lease().revision().get(), 2);

        let retry = run_claim(&mut connection, &first_command).expect("retry must run");
        assert_eq!(retry.status(), RecoveryLeaseClaimStatus::AlreadyOwned);
        assert_eq!(retry.lease(), acquired.lease());

        let busy = run_claim(&mut connection, &claim(workspace_id, owner(3), 11))
            .expect("busy claim must classify");
        assert_eq!(busy.status(), RecoveryLeaseClaimStatus::Busy);
        assert_eq!(busy.lease(), acquired.lease());

        let conflict =
            ClaimRecoveryLease::new(workspace_id, owner(2), duration(2_000), timestamp(11))
                .expect("conflicting claim must be valid");
        let conflict = run_claim(&mut connection, &conflict).expect("conflict must classify");
        assert_eq!(conflict.status(), RecoveryLeaseClaimStatus::ClaimConflict);
        assert_eq!(conflict.lease(), acquired.lease());

        let persisted = get(&connection, workspace_id).expect("lease must remain unchanged");
        assert_eq!(persisted, *acquired.lease());
    }

    #[test]
    fn renewal_and_release_require_exact_fence() {
        let (mut connection, workspace_id) = connection_with_released_row();
        let acquired = run_claim(&mut connection, &claim(workspace_id, owner(2), 10))
            .expect("claim must run")
            .into_lease();
        let stale = RenewRecoveryLease::new(
            workspace_id,
            owner(3),
            acquired.epoch(),
            acquired.revision(),
            duration(2_000),
            timestamp(20),
        )
        .expect("stale renewal must be valid input");
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("transaction must begin");
        assert!(matches!(
            renew(&transaction, &stale),
            Err(RecoveryStoreError::Transition(_))
        ));
        drop(transaction);

        let renewal = RenewRecoveryLease::new(
            workspace_id,
            owner(2),
            acquired.epoch(),
            acquired.revision(),
            duration(2_000),
            timestamp(20),
        )
        .expect("renewal must be valid");
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("transaction must begin");
        let renewed = renew(&transaction, &renewal).expect("renewal must succeed");
        transaction.commit().expect("renewal must commit");
        assert_eq!(renewed.lease_until(), Some(timestamp(2_020)));
        assert_eq!(renewed.revision().get(), acquired.revision().get() + 1);

        let release_command = ReleaseRecoveryLease::new(
            workspace_id,
            owner(2),
            renewed.epoch(),
            renewed.revision(),
            timestamp(21),
        );
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("transaction must begin");
        let released =
            super::release(&transaction, &release_command).expect("release must succeed");
        transaction.commit().expect("release must commit");
        assert!(released.is_released());
        assert_eq!(released.epoch(), renewed.epoch());
        assert_eq!(released.revision().get(), renewed.revision().get() + 1);
    }

    #[test]
    fn malformed_owner_length_fails_closed() {
        let (connection, workspace_id) = connection_with_released_row();
        connection
            .execute_batch("PRAGMA ignore_check_constraints = ON;")
            .expect("SQLite test pragma must be accepted");
        connection
            .execute(
                "UPDATE recovery_maintenance
                 SET owner_runtime_instance_id = zeroblob(15), lease_until_ms = 1000, epoch = 1
                 WHERE workspace_id = ?1",
                params![workspace_id.into_uuid().as_bytes()],
            )
            .expect("malformed row must be writable for the test");
        assert!(matches!(
            get(&connection, workspace_id),
            Err(RecoveryStoreError::InvalidFieldLength { .. })
        ));
    }

    #[test]
    fn malformed_nullable_pair_epoch_and_revision_fail_closed() {
        let (connection, workspace_id) = connection_with_released_row();
        connection
            .execute_batch("PRAGMA ignore_check_constraints = ON;")
            .expect("SQLite test pragma must be accepted");

        connection
            .execute(
                "UPDATE recovery_maintenance
                 SET owner_runtime_instance_id = NULL, lease_until_ms = 1000
                 WHERE workspace_id = ?1",
                params![workspace_id.into_uuid().as_bytes()],
            )
            .expect("partial pair must be writable for the test");
        assert!(matches!(
            get(&connection, workspace_id),
            Err(RecoveryStoreError::Maintenance(
                RecoveryMaintenanceLeaseError::PartialLease
            ))
        ));

        connection
            .execute(
                "UPDATE recovery_maintenance
                 SET owner_runtime_instance_id = ?1, lease_until_ms = 2000, epoch = 0, revision = 1
                 WHERE workspace_id = ?2",
                params![
                    owner(2).into_uuid().as_bytes(),
                    workspace_id.into_uuid().as_bytes()
                ],
            )
            .expect("owned initial epoch must be writable for the test");
        assert!(matches!(
            get(&connection, workspace_id),
            Err(RecoveryStoreError::Maintenance(
                RecoveryMaintenanceLeaseError::OwnedAtInitialEpoch
            ))
        ));

        connection
            .execute(
                "UPDATE recovery_maintenance
                 SET owner_runtime_instance_id = NULL, lease_until_ms = NULL, epoch = -1, revision = 1
                 WHERE workspace_id = ?1",
                params![workspace_id.into_uuid().as_bytes()],
            )
            .expect("invalid epoch must be writable for the test");
        assert!(matches!(
            get(&connection, workspace_id),
            Err(RecoveryStoreError::Epoch(
                RecoveryLeaseEpochError::Invalid { actual: -1 }
            ))
        ));

        connection
            .execute(
                "UPDATE recovery_maintenance
                 SET epoch = 0, revision = 0
                 WHERE workspace_id = ?1",
                params![workspace_id.into_uuid().as_bytes()],
            )
            .expect("invalid revision must be writable for the test");
        assert!(matches!(
            get(&connection, workspace_id),
            Err(RecoveryStoreError::Revision(
                RecoveryLeaseRevisionError::Invalid { actual: 0 }
            ))
        ));
    }
}
