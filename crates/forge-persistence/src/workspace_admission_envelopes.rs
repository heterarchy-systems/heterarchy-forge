//! Durable one-time consumption journal for Orchestration-issued execution
//! admission envelopes.
//!
//! The journal is written inside the exact caller transaction that consumes an
//! approval grant and begins an execution, so an envelope can never be marked
//! consumed without its execution intent committing in the same atomic commit.
//! The envelope request digest is payload-match validation data only; the
//! operation/readback identity remains the execution identity.

use forge_domain::{
    ExecutionAdmissionError, ExecutionAdmissionGrant, ExecutionAdmissionRequest, ExecutionId,
    ExecutionRequestDigest, OrchestrationIssuerId, TimestampMillis,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use thiserror::Error;
use uuid::Uuid;

const LEGACY_ADMISSIONS_SQL: &str = "CREATE TABLE execution_admission_consumptions (issuer BLOB NOT NULL CHECK(length(issuer) = 16), request_digest BLOB NOT NULL CHECK(length(request_digest) = 32), execution_id BLOB NOT NULL UNIQUE REFERENCES executions(execution_id) CHECK(length(execution_id) = 16), consumed_at_ms INTEGER NOT NULL CHECK(consumed_at_ms >= 0), PRIMARY KEY(issuer, request_digest))";
const ADMISSIONS_SQL: &str = "CREATE TABLE execution_admission_consumptions (issuer BLOB NOT NULL CHECK(length(issuer) = 16), request_digest BLOB NOT NULL CHECK(length(request_digest) = 32), execution_id BLOB NOT NULL REFERENCES executions(execution_id) CHECK(length(execution_id) = 16), consumed_at_ms INTEGER NOT NULL CHECK(consumed_at_ms >= 0), PRIMARY KEY(execution_id))";
const ADMISSIONS_EXECUTION_INDEX_SQL: &str = "CREATE INDEX execution_admission_consumptions_execution_idx ON execution_admission_consumptions(execution_id)";

const OBJECTS: [(&str, &str, &str); 2] = [
    ("table", "execution_admission_consumptions", ADMISSIONS_SQL),
    (
        "index",
        "execution_admission_consumptions_execution_idx",
        ADMISSIONS_EXECUTION_INDEX_SQL,
    ),
];
const LEGACY_OBJECTS: [(&str, &str, &str); 2] = [
    (
        "table",
        "execution_admission_consumptions",
        LEGACY_ADMISSIONS_SQL,
    ),
    (
        "index",
        "execution_admission_consumptions_execution_idx",
        ADMISSIONS_EXECUTION_INDEX_SQL,
    ),
];

const LEGACY_COLUMNS: [(&str, &str, i64, i64); 4] = [
    ("issuer", "BLOB", 1, 1),
    ("request_digest", "BLOB", 1, 2),
    ("execution_id", "BLOB", 1, 0),
    ("consumed_at_ms", "INTEGER", 1, 0),
];
const ADMISSIONS_COLUMNS: [(&str, &str, i64, i64); 4] = [
    ("issuer", "BLOB", 1, 0),
    ("request_digest", "BLOB", 1, 0),
    ("execution_id", "BLOB", 1, 1),
    ("consumed_at_ms", "INTEGER", 1, 0),
];

/// One validated-shape Orchestration admission envelope joined into the
/// grant-consumption transaction. The actual request is server-derived by the
/// application-control boundary from the executing command and its interpreted
/// scope; this journal never trusts an adapter-built digest for identity.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmissionEnvelopeConsumption {
    issuer: OrchestrationIssuerId,
    grant: ExecutionAdmissionGrant,
    actual_request: ExecutionAdmissionRequest,
    observed_at: TimestampMillis,
}

impl AdmissionEnvelopeConsumption {
    pub const fn new(
        issuer: OrchestrationIssuerId,
        grant: ExecutionAdmissionGrant,
        actual_request: ExecutionAdmissionRequest,
        observed_at: TimestampMillis,
    ) -> Self {
        Self {
            issuer,
            grant,
            actual_request,
            observed_at,
        }
    }

    pub const fn issuer(self) -> OrchestrationIssuerId {
        self.issuer
    }

    pub const fn grant(self) -> ExecutionAdmissionGrant {
        self.grant
    }

    pub const fn actual_request(self) -> ExecutionAdmissionRequest {
        self.actual_request
    }

    pub const fn observed_at(self) -> TimestampMillis {
        self.observed_at
    }

    /// Validate the immutable envelope (issuer, exact request fence, half-open
    /// time window). Called inside the consumption transaction so envelope
    /// validity, one-time consumption, grant consumption, and execution begin
    /// commit or roll back together.
    pub fn validate(&self) -> Result<(), AdmissionEnvelopeError> {
        self.grant
            .validate_for(self.issuer, &self.actual_request, self.observed_at)
            .map_err(AdmissionEnvelopeError::Invalid)
    }

    /// The operation/readback identity this envelope fences.
    pub fn execution_id(&self) -> forge_domain::ExecutionId {
        self.actual_request.execution_id()
    }

    /// Payload-match validation digest carried by the envelope request.
    pub fn request_digest(&self) -> forge_domain::ExecutionRequestDigest {
        self.actual_request.digest()
    }
}

/// Outcome of the in-transaction one-time envelope consumption check.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionConsumeOutcome {
    /// The envelope had not been consumed before; the journal row was inserted
    /// in the caller transaction.
    Consumed,
    /// The exact envelope (issuer + request digest) was already consumed for
    /// the same execution identity. The caller must continue into the
    /// existing-execution readback path, never a second execution.
    AlreadyConsumedForSameExecution,
}

/// Read the consumed identity for one operation identity, if any.
pub(crate) fn consumed_execution_tx(
    transaction: &Transaction<'_>,
    envelope: &AdmissionEnvelopeConsumption,
) -> Result<Option<ExecutionId>, AdmissionEnvelopeError> {
    let stored_identity: Option<(Vec<u8>, Vec<u8>)> = transaction
        .query_row(
            "SELECT issuer, request_digest FROM execution_admission_consumptions
             WHERE execution_id = ?1",
            params![envelope.execution_id().into_uuid().as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((issuer_bytes, digest_bytes)) = stored_identity else {
        return Ok(None);
    };
    let stored_issuer = Uuid::from_slice(&issuer_bytes)
        .map(OrchestrationIssuerId::from_uuid)
        .map_err(|_| AdmissionEnvelopeError::CorruptRecord)?;
    let stored_digest = <[u8; 32]>::try_from(digest_bytes.as_slice())
        .map(ExecutionRequestDigest::from_bytes)
        .map_err(|_| AdmissionEnvelopeError::CorruptRecord)?;
    if stored_issuer != envelope.issuer() || stored_digest != envelope.request_digest() {
        return Err(AdmissionEnvelopeError::IdentityConflict);
    }
    Ok(Some(envelope.execution_id()))
}

/// Consume one envelope inside the caller transaction: replay of the exact
/// execution identity reads back, while a changed issuer or payload digest for
/// that identity is rejected. Distinct execution identities may share a digest.
/// The journal row commits atomically with the caller's grant consumption and
/// execution begin.
pub(crate) fn consume_envelope_tx(
    transaction: &Transaction<'_>,
    envelope: &AdmissionEnvelopeConsumption,
) -> Result<AdmissionConsumeOutcome, AdmissionEnvelopeError> {
    if consumed_execution_tx(transaction, envelope)?.is_some() {
        return Ok(AdmissionConsumeOutcome::AlreadyConsumedForSameExecution);
    }
    transaction.execute(
        "INSERT INTO execution_admission_consumptions(
            issuer, request_digest, execution_id, consumed_at_ms
         ) VALUES (?1, ?2, ?3, ?4)",
        params![
            envelope.issuer().into_uuid().as_bytes(),
            envelope.request_digest().as_bytes(),
            envelope.execution_id().into_uuid().as_bytes(),
            envelope.observed_at().get(),
        ],
    )?;
    Ok(AdmissionConsumeOutcome::Consumed)
}

/// Read the envelope request digest journaled for one execution identity, if
/// any. Used by the existing-execution readback path to reject the same
/// execution identity replayed with a different payload digest.
pub(crate) fn journaled_digest_for_execution_tx(
    transaction: &Transaction<'_>,
    execution_id: ExecutionId,
) -> Result<Option<ExecutionRequestDigest>, AdmissionEnvelopeError> {
    let digest: Option<Vec<u8>> = transaction
        .query_row(
            "SELECT request_digest FROM execution_admission_consumptions
             WHERE execution_id = ?1",
            params![execution_id.into_uuid().as_bytes()],
            |row| row.get(0),
        )
        .optional()?;
    digest
        .map(|bytes| {
            <[u8; 32]>::try_from(bytes.as_slice())
                .map(ExecutionRequestDigest::from_bytes)
                .map_err(|_| AdmissionEnvelopeError::CorruptRecord)
        })
        .transpose()
}

pub(crate) fn create_schema(connection: &Connection) -> Result<(), AdmissionEnvelopeError> {
    connection.execute_batch(ADMISSIONS_SQL)?;
    connection.execute_batch(ADMISSIONS_EXECUTION_INDEX_SQL)?;
    Ok(())
}

/// Create the exact admission journal schema present in Workspace versions
/// v46 through v67. Kept separate from the current schema for migration tests
/// and historical-shape creation only.
pub(crate) fn create_legacy_schema(connection: &Connection) -> Result<(), AdmissionEnvelopeError> {
    connection.execute_batch(LEGACY_ADMISSIONS_SQL)?;
    connection.execute_batch(ADMISSIONS_EXECUTION_INDEX_SQL)?;
    Ok(())
}

/// The durable journal schema objects, used by the Workspace schema-object
/// catalog and by migration test fixtures.
pub(crate) fn schema_objects() -> [(&'static str, &'static str); 2] {
    [
        ("table", "execution_admission_consumptions"),
        ("index", "execution_admission_consumptions_execution_idx"),
    ]
}

/// Schema object identities used by historical Workspace shape validation.
pub(crate) fn legacy_schema_objects() -> [(&'static str, &'static str); 2] {
    [
        ("table", "execution_admission_consumptions"),
        ("index", "execution_admission_consumptions_execution_idx"),
    ]
}

pub(crate) fn validate_schema(connection: &Connection) -> Result<(), AdmissionEnvelopeError> {
    validate_schema_with(connection, &OBJECTS, &ADMISSIONS_COLUMNS)
}

/// Validate the exact admission journal schema present in Workspace versions
/// v46 through v67 before the identity-key migration runs.
pub(crate) fn validate_legacy_schema(
    connection: &Connection,
) -> Result<(), AdmissionEnvelopeError> {
    validate_schema_with(connection, &LEGACY_OBJECTS, &LEGACY_COLUMNS)
}

/// Replace the legacy issuer/digest primary key inside the caller's migration
/// transaction, preserving every stored value exactly.
pub(crate) fn migrate_identity_schema(
    transaction: &Transaction<'_>,
) -> Result<(), AdmissionEnvelopeError> {
    validate_legacy_schema(transaction)?;
    transaction.execute_batch("DROP INDEX execution_admission_consumptions_execution_idx")?;
    transaction.execute_batch(
        "ALTER TABLE execution_admission_consumptions
         RENAME TO execution_admission_consumptions_legacy",
    )?;
    create_schema(transaction)?;
    transaction.execute(
        "INSERT INTO execution_admission_consumptions (
            issuer, request_digest, execution_id, consumed_at_ms
         )
         SELECT issuer, request_digest, execution_id, consumed_at_ms
         FROM execution_admission_consumptions_legacy",
        [],
    )?;
    transaction.execute_batch("DROP TABLE execution_admission_consumptions_legacy")?;
    validate_schema(transaction)
}

fn validate_schema_with(
    connection: &Connection,
    objects: &[(&'static str, &'static str, &'static str)],
    expected_columns: &[(&'static str, &'static str, i64, i64)],
) -> Result<(), AdmissionEnvelopeError> {
    for &(kind, name, expected_sql) in objects {
        let actual: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type = ?1 AND name = ?2",
                params![kind, name],
                |row| row.get(0),
            )
            .optional()?;
        let Some(actual) = actual else {
            return Err(AdmissionEnvelopeError::DamagedSchema(name));
        };
        if normalize_sql(&actual) != normalize_sql(expected_sql) {
            return Err(AdmissionEnvelopeError::DamagedSchema(name));
        }
    }
    validate_columns(connection, expected_columns)?;
    validate_foreign_keys(connection)?;
    validate_foreign_key_rows(connection)?;
    Ok(())
}

fn validate_columns(
    connection: &Connection,
    expected_columns: &[(&'static str, &'static str, i64, i64)],
) -> Result<(), AdmissionEnvelopeError> {
    let mut statement =
        connection.prepare("PRAGMA table_info(execution_admission_consumptions)")?;
    let mut rows = statement.query([])?;
    let mut columns = Vec::new();
    while let Some(row) = rows.next()? {
        if columns.len() >= expected_columns.len() {
            return Err(AdmissionEnvelopeError::DamagedSchema(
                "execution_admission_consumptions",
            ));
        }
        columns.push((
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, i64>(5)?,
        ));
    }
    let matches = columns.len() == expected_columns.len()
        && columns.iter().zip(expected_columns).all(
            |((name, data_type, not_null, primary_key), expected)| {
                name == expected.0
                    && data_type.eq_ignore_ascii_case(expected.1)
                    && *not_null == expected.2
                    && *primary_key == expected.3
            },
        );
    if !matches {
        return Err(AdmissionEnvelopeError::DamagedSchema(
            "execution_admission_consumptions",
        ));
    }
    Ok(())
}

fn validate_foreign_keys(connection: &Connection) -> Result<(), AdmissionEnvelopeError> {
    let mut statement =
        connection.prepare("PRAGMA foreign_key_list(execution_admission_consumptions)")?;
    let mut rows = statement.query([])?;
    let mut foreign_keys = Vec::new();
    while let Some(row) = rows.next()? {
        if !foreign_keys.is_empty() {
            return Err(AdmissionEnvelopeError::DamagedSchema(
                "execution_admission_consumptions",
            ));
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
    let valid = foreign_keys.len() == 1
        && foreign_keys.first().is_some_and(
            |(table, from, to, on_update, on_delete, match_type)| {
                table == "executions"
                    && from == "execution_id"
                    && to == "execution_id"
                    && on_update == "NO ACTION"
                    && on_delete == "NO ACTION"
                    && match_type == "NONE"
            },
        );
    if !valid {
        return Err(AdmissionEnvelopeError::DamagedSchema(
            "execution_admission_consumptions",
        ));
    }
    Ok(())
}

fn validate_foreign_key_rows(connection: &Connection) -> Result<(), AdmissionEnvelopeError> {
    let mut statement =
        connection.prepare("PRAGMA foreign_key_check(execution_admission_consumptions)")?;
    let mut rows = statement.query([])?;
    if rows.next()?.is_some() {
        return Err(AdmissionEnvelopeError::CorruptRecord);
    }
    Ok(())
}

fn normalize_sql(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_whitespace())
        .map(|character| character.to_ascii_lowercase())
        .collect()
}

#[derive(Debug, Error)]
pub enum AdmissionEnvelopeError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Invalid(#[from] ExecutionAdmissionError),
    #[error("admission envelope was replayed for a different execution identity")]
    ReplayedForDifferentExecution,
    #[error(
        "admission envelope execution identity is already bound to different authority or payload"
    )]
    IdentityConflict,
    #[error("admission envelope journal record is corrupt")]
    CorruptRecord,
    #[error("admission envelope schema object is damaged: {0}")]
    DamagedSchema(&'static str),
}

#[cfg(test)]
mod tests {
    use super::*;
    use forge_domain::{
        ActivityId, AgentInstanceId, AgentInstanceRevision, AgentSessionId, DagNodeRevision,
        DagRevisionNumber, ExecutionId, ForgeBackendId, GoalId, GoalNodeAttribution, GoalRevision,
        WorkspaceId, WorkspaceRevision,
    };
    use rusqlite::params;
    use uuid::Uuid;

    fn digest(value: u8) -> ExecutionRequestDigest {
        ExecutionRequestDigest::from_bytes([value; ExecutionRequestDigest::BYTE_LEN])
    }

    fn envelope(
        execution: ExecutionId,
        digest_value: u8,
    ) -> Result<AdmissionEnvelopeConsumption, Box<dyn std::error::Error>> {
        envelope_for_issuer(
            OrchestrationIssuerId::from_uuid(Uuid::from_u128(0xAD)),
            execution,
            digest_value,
        )
    }

    fn envelope_for_issuer(
        issuer: OrchestrationIssuerId,
        execution: ExecutionId,
        digest_value: u8,
    ) -> Result<AdmissionEnvelopeConsumption, Box<dyn std::error::Error>> {
        let request = ExecutionAdmissionRequest::new(
            forge_domain::ExecutionAdmissionScope::new(
                ForgeBackendId::from_uuid(Uuid::from_u128(0xB0)),
                WorkspaceId::from_uuid(Uuid::from_u128(1)),
                WorkspaceRevision::INITIAL,
            ),
            ActivityId::from_uuid(Uuid::from_u128(2)),
            GoalNodeAttribution::new(
                GoalId::from_uuid(Uuid::from_u128(0x60)),
                GoalRevision::INITIAL,
                DagRevisionNumber::INITIAL,
                forge_domain::DagNodeId::from_uuid(Uuid::from_u128(0x61)),
                DagNodeRevision::INITIAL,
            ),
            forge_domain::ExecutionAdmissionActor::new(
                AgentInstanceId::from_uuid(Uuid::from_u128(0x62)),
                AgentInstanceRevision::INITIAL,
                AgentSessionId::from_uuid(Uuid::from_u128(0x63)),
            ),
            execution,
            digest(digest_value),
        );
        let grant = ExecutionAdmissionGrant::new(
            issuer,
            request,
            TimestampMillis::new(1)?,
            TimestampMillis::new(10_000)?,
        )?;
        Ok(AdmissionEnvelopeConsumption::new(
            issuer,
            grant,
            request,
            TimestampMillis::new(64)?,
        ))
    }

    fn journal_fixture() -> Result<Connection, Box<dyn std::error::Error>> {
        journal_fixture_with_schema(Connection::open_in_memory()?, create_schema)
    }

    fn journal_fixture_with_schema(
        connection: Connection,
        create: fn(&Connection) -> Result<(), AdmissionEnvelopeError>,
    ) -> Result<Connection, Box<dyn std::error::Error>> {
        connection.execute_batch(
            "CREATE TABLE workspace(workspace_id BLOB PRIMARY KEY);
             CREATE TABLE activities(activity_id BLOB PRIMARY KEY,
                workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id), state INTEGER);
             CREATE TABLE executions(execution_id BLOB PRIMARY KEY,
                workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id),
                activity_id BLOB NOT NULL REFERENCES activities(activity_id),
                state INTEGER, mode INTEGER, request_digest BLOB, timeout_ms INTEGER,
                output_limit INTEGER, workspace_read INTEGER, workspace_write INTEGER,
                network INTEGER, created_at_ms INTEGER, updated_at_ms INTEGER, revision INTEGER);",
        )?;
        let workspace = WorkspaceId::from_uuid(Uuid::from_u128(1));
        let activity = forge_domain::ActivityId::from_uuid(Uuid::from_u128(2));
        connection.execute(
            "INSERT INTO workspace VALUES (?1)",
            params![workspace.into_uuid().as_bytes()],
        )?;
        connection.execute(
            "INSERT INTO activities VALUES (?1, ?2, 1)",
            params![
                activity.into_uuid().as_bytes(),
                workspace.into_uuid().as_bytes()
            ],
        )?;
        for index in [3_u128, 4] {
            connection.execute(
                "INSERT INTO executions(execution_id, workspace_id, activity_id, state, mode,
                    request_digest, timeout_ms, output_limit, workspace_read, workspace_write,
                    network, created_at_ms, updated_at_ms, revision)
                 VALUES (?1, ?2, ?3, 0, 0, zeroblob(32), 1000, 1024, 0, 0, 0, 1, 1, 1)",
                params![
                    ExecutionId::from_uuid(Uuid::from_u128(index))
                        .into_uuid()
                        .as_bytes(),
                    workspace.into_uuid().as_bytes(),
                    activity.into_uuid().as_bytes(),
                ],
            )?;
        }
        create(&connection)?;
        Ok(connection)
    }

    fn legacy_journal_fixture() -> Result<Connection, Box<dyn std::error::Error>> {
        journal_fixture_with_schema(Connection::open_in_memory()?, create_legacy_schema)
    }

    #[test]
    fn consume_is_one_time_per_execution_identity() -> Result<(), Box<dyn std::error::Error>> {
        let connection = journal_fixture()?;
        let transaction = connection.unchecked_transaction()?;
        let execution = ExecutionId::from_uuid(Uuid::from_u128(3));
        let first = envelope(execution, 7)?;

        assert_eq!(
            consume_envelope_tx(&transaction, &first)?,
            AdmissionConsumeOutcome::Consumed
        );
        assert_eq!(
            consume_envelope_tx(&transaction, &first)?,
            AdmissionConsumeOutcome::AlreadyConsumedForSameExecution
        );
        assert_eq!(
            consumed_execution_tx(&transaction, &first)?,
            Some(execution)
        );
        // A second execution may legitimately carry the same payload digest.
        let other_execution = ExecutionId::from_uuid(Uuid::from_u128(4));
        assert_eq!(
            consume_envelope_tx(&transaction, &envelope(other_execution, 7)?)?,
            AdmissionConsumeOutcome::Consumed
        );
        assert_eq!(
            consume_envelope_tx(&transaction, &envelope(other_execution, 7)?)?,
            AdmissionConsumeOutcome::AlreadyConsumedForSameExecution
        );
        assert_eq!(
            consumed_execution_tx(&transaction, &envelope(other_execution, 7)?)?,
            Some(other_execution)
        );

        // An execution identity is permanently bound to its issuer and digest.
        assert!(matches!(
            consume_envelope_tx(&transaction, &envelope(execution, 8)?),
            Err(AdmissionEnvelopeError::IdentityConflict)
        ));
        assert!(matches!(
            consume_envelope_tx(
                &transaction,
                &envelope_for_issuer(
                    OrchestrationIssuerId::from_uuid(Uuid::from_u128(0xAE)),
                    execution,
                    7,
                )?
            ),
            Err(AdmissionEnvelopeError::IdentityConflict)
        ));
        transaction.commit()?;
        Ok(())
    }

    #[test]
    fn journaled_digest_resolves_by_execution_identity() -> Result<(), Box<dyn std::error::Error>> {
        let connection = journal_fixture()?;
        let transaction = connection.unchecked_transaction()?;
        let execution = ExecutionId::from_uuid(Uuid::from_u128(3));
        assert_eq!(
            journaled_digest_for_execution_tx(&transaction, execution)?,
            None
        );
        let consumed_first_use = consume_envelope_tx(&transaction, &envelope(execution, 9)?)?;
        assert_eq!(consumed_first_use, AdmissionConsumeOutcome::Consumed);
        assert_eq!(
            journaled_digest_for_execution_tx(&transaction, execution)?,
            Some(digest(9))
        );
        transaction.rollback()?;
        Ok(())
    }

    #[test]
    fn identity_migration_preserves_rows_across_reopen() -> Result<(), Box<dyn std::error::Error>> {
        use std::time::{SystemTime, UNIX_EPOCH};

        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path = std::env::temp_dir().join(format!(
            "forge-admission-envelope-{}-{nonce}.sqlite",
            std::process::id()
        ));
        let mut connection =
            journal_fixture_with_schema(Connection::open(&path)?, create_legacy_schema)?;
        let issuer = OrchestrationIssuerId::from_uuid(Uuid::from_u128(0xAD));
        let execution = ExecutionId::from_uuid(Uuid::from_u128(3));
        let payload_digest = digest(7);
        let consumed_at_ms = 123_456_i64;
        connection.execute(
            "INSERT INTO execution_admission_consumptions (
                issuer, request_digest, execution_id, consumed_at_ms
             ) VALUES (?1, ?2, ?3, ?4)",
            params![
                issuer.into_uuid().as_bytes(),
                payload_digest.as_bytes(),
                execution.into_uuid().as_bytes(),
                consumed_at_ms,
            ],
        )?;
        validate_legacy_schema(&connection)?;

        let transaction =
            connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        migrate_identity_schema(&transaction)?;
        transaction.commit()?;
        drop(connection);

        let reopened = Connection::open(&path)?;
        validate_schema(&reopened)?;
        let stored: (Vec<u8>, Vec<u8>, Vec<u8>, i64) = reopened.query_row(
            "SELECT issuer, request_digest, execution_id, consumed_at_ms
             FROM execution_admission_consumptions WHERE execution_id = ?1",
            params![execution.into_uuid().as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;
        assert_eq!(stored.0, issuer.into_uuid().as_bytes());
        assert_eq!(stored.1, payload_digest.as_bytes());
        assert_eq!(stored.2, execution.into_uuid().as_bytes());
        assert_eq!(stored.3, consumed_at_ms);
        drop(reopened);
        std::fs::remove_file(path)?;
        Ok(())
    }

    #[test]
    fn identity_migration_rolls_back_with_its_caller_transaction()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut connection = legacy_journal_fixture()?;
        let transaction =
            connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        migrate_identity_schema(&transaction)?;
        transaction.rollback()?;
        validate_legacy_schema(&connection)?;
        Ok(())
    }

    #[test]
    fn legacy_schema_validation_rejects_corruption_before_migration()
    -> Result<(), Box<dyn std::error::Error>> {
        let connection = legacy_journal_fixture()?;
        connection.execute_batch("DROP INDEX execution_admission_consumptions_execution_idx")?;
        let transaction = connection.unchecked_transaction()?;
        assert!(matches!(
            migrate_identity_schema(&transaction),
            Err(AdmissionEnvelopeError::DamagedSchema(
                "execution_admission_consumptions_execution_idx"
            ))
        ));
        transaction.rollback()?;
        assert!(matches!(
            validate_legacy_schema(&connection),
            Err(AdmissionEnvelopeError::DamagedSchema(
                "execution_admission_consumptions_execution_idx"
            ))
        ));
        Ok(())
    }

    #[test]
    fn schema_validation_rejects_damaged_objects() -> Result<(), Box<dyn std::error::Error>> {
        let connection = journal_fixture()?;
        validate_schema(&connection)?;
        connection.execute_batch("DROP TABLE execution_admission_consumptions")?;
        assert!(matches!(
            validate_schema(&connection),
            Err(AdmissionEnvelopeError::DamagedSchema(
                "execution_admission_consumptions"
            ))
        ));
        Ok(())
    }
}
