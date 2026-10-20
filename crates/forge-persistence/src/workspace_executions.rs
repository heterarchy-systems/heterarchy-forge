use std::ffi::OsString;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;

use crate::workspace_semantic_events::{
    self, SemanticEventAppend, SemanticEventKind, SemanticEventSubjects,
};
use crate::workspace_store::encode_activity_state;
use forge_domain::{
    ActivityId, ActivityState, AgentInstanceId, AgentInstanceRevision, AgentSessionId,
    AuthenticatedPrincipal, AuthorizedExecutionRead, BeginExecution, BoundedExecutionOutput,
    CompleteExecution, DagNodeId, DagNodeRevision, DagRevisionNumber, DirectTokenId,
    ExecutionAgentProvenance, ExecutionAttribution, ExecutionCommandId, ExecutionCompletionStatus,
    ExecutionFailureCode, ExecutionId, ExecutionLimits, ExecutionListLimit, ExecutionMode,
    ExecutionNativeClosureFact, ExecutionOutcome, ExecutionOutputChunk, ExecutionOutputCursor,
    ExecutionOutputEvent, ExecutionOutputGap, ExecutionOutputGapCause, ExecutionOutputGapParts,
    ExecutionOutputLimit, ExecutionOutputRead, ExecutionOutputSequence, ExecutionOutputStream,
    ExecutionPermissions, ExecutionRecordDefinition, ExecutionRecordLifecycle,
    ExecutionRequestDigest, ExecutionRevision, ExecutionState, ExecutionTermination,
    ExecutionTimeoutMillis, ExecutionTimestamps, FailExecution, FileByteCount, FileContentHash,
    GeneratedArtifactKind, GeneratedPackageManifest, GoalId, GoalNodeAttribution, GoalRevision,
    MAX_EXECUTION_OUTPUT_READ_BYTES, MAX_EXECUTION_OUTPUT_READ_EVENTS,
    MIN_EXECUTION_OUTPUT_READ_BYTES, MarkExecutionRunning, OAuthGrantId,
    ProjectCommandCatalogFingerprint, ProjectCommandClass, ProjectCommandEvidence,
    RegisteredExecution, RuntimeInstanceId, TimestampMillis, VerificationOutputAccumulator,
    VerificationRunTerminalStatus, WorkspaceId, WorkspaceRelativePath, execution_state_for_outcome,
};
use rusqlite::{Connection, OptionalExtension, Row, Transaction, TransactionBehavior, params};
use thiserror::Error;
use uuid::Uuid;

mod observation;
pub use observation::{ExecutionEvidenceInventory, ExecutionEvidenceRead, ExecutionEvidenceRecord};
pub(crate) use observation::{inventory as observation_inventory, read as observation_read};
pub(crate) mod native_closure;

pub(crate) const EXPECTED_EXECUTIONS_TABLE_SQL: &str = "CREATE TABLE executions (execution_id BLOB PRIMARY KEY NOT NULL CHECK(length(execution_id) = 16), workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id), activity_id BLOB NOT NULL REFERENCES activities(activity_id), state INTEGER NOT NULL CHECK(state IN (0, 1, 2, 3, 4, 5, 6)), mode INTEGER NOT NULL CHECK(mode IN (0, 1)), request_digest BLOB NOT NULL CHECK(length(request_digest) = 32), cwd BLOB CHECK(cwd IS NULL OR length(cwd) BETWEEN 1 AND 4096), timeout_ms INTEGER NOT NULL CHECK(timeout_ms BETWEEN 100 AND 600000), output_limit INTEGER NOT NULL CHECK(output_limit BETWEEN 1 AND 1048576), workspace_read INTEGER NOT NULL CHECK(workspace_read IN (0, 1)), workspace_write INTEGER NOT NULL CHECK(workspace_write IN (0, 1)), network INTEGER NOT NULL CHECK(network IN (0, 1)), exit_code INTEGER CHECK(exit_code IS NULL OR exit_code BETWEEN -2147483648 AND 2147483647), signal INTEGER CHECK(signal IS NULL OR signal BETWEEN -2147483648 AND 2147483647), duration_ms INTEGER CHECK(duration_ms IS NULL OR duration_ms >= 0), stdout BLOB CHECK(stdout IS NULL OR length(stdout) <= 1048576), stdout_total_bytes INTEGER CHECK(stdout_total_bytes IS NULL OR stdout_total_bytes >= 0), stdout_truncated INTEGER CHECK(stdout_truncated IS NULL OR stdout_truncated IN (0, 1)), stderr BLOB CHECK(stderr IS NULL OR length(stderr) <= 1048576), stderr_total_bytes INTEGER CHECK(stderr_total_bytes IS NULL OR stderr_total_bytes >= 0), stderr_truncated INTEGER CHECK(stderr_truncated IS NULL OR stderr_truncated IN (0, 1)), failure_code INTEGER CHECK(failure_code IS NULL OR failure_code IN (0, 1, 2, 3, 4)), created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0), updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0), revision INTEGER NOT NULL CHECK(revision >= 1), CHECK((state IN (0, 1, 6) AND exit_code IS NULL AND signal IS NULL AND duration_ms IS NULL AND stdout IS NULL AND stdout_total_bytes IS NULL AND stdout_truncated IS NULL AND stderr IS NULL AND stderr_total_bytes IS NULL AND stderr_truncated IS NULL AND failure_code IS NULL) OR (state IN (2, 4, 5) AND duration_ms IS NOT NULL AND stdout IS NOT NULL AND stdout_total_bytes IS NOT NULL AND stdout_truncated IS NOT NULL AND stderr IS NOT NULL AND stderr_total_bytes IS NOT NULL AND stderr_truncated IS NOT NULL AND failure_code IS NULL) OR (state = 3 AND ((duration_ms IS NOT NULL AND stdout IS NOT NULL AND stdout_total_bytes IS NOT NULL AND stdout_truncated IS NOT NULL AND stderr IS NOT NULL AND stderr_total_bytes IS NOT NULL AND stderr_truncated IS NOT NULL AND failure_code IS NULL) OR (exit_code IS NULL AND signal IS NULL AND duration_ms IS NULL AND stdout IS NULL AND stdout_total_bytes IS NULL AND stdout_truncated IS NULL AND stderr IS NULL AND stderr_total_bytes IS NULL AND stderr_truncated IS NULL AND failure_code IS NOT NULL)))))";
pub(crate) const EXPECTED_EXECUTIONS_ACTIVITY_INDEX_SQL: &str = "CREATE INDEX executions_activity_created_idx ON executions(activity_id, created_at_ms DESC, execution_id DESC)";
pub(crate) const EXPECTED_EXECUTIONS_STATE_INDEX_SQL: &str =
    "CREATE INDEX executions_state_updated_idx ON executions(state, updated_at_ms, execution_id)";
pub(crate) const EXPECTED_EXECUTION_PROVENANCE_TABLE_SQL: &str = "CREATE TABLE execution_provenance (execution_id BLOB PRIMARY KEY NOT NULL CHECK(length(execution_id) = 16), agent_id BLOB NOT NULL CHECK(length(agent_id) = 16), agent_revision INTEGER NOT NULL CHECK(agent_revision >= 1), principal_kind INTEGER NOT NULL CHECK(principal_kind IN (0, 1, 2)), principal_id BLOB CHECK(principal_id IS NULL OR length(principal_id) = 16), goal_id BLOB NOT NULL CHECK(length(goal_id) = 16), goal_revision INTEGER NOT NULL CHECK(goal_revision >= 1), dag_revision INTEGER NOT NULL CHECK(dag_revision >= 1), node_id BLOB NOT NULL CHECK(length(node_id) = 16), node_revision INTEGER NOT NULL CHECK(node_revision >= 1), command_id TEXT NOT NULL CHECK(length(CAST(command_id AS BLOB)) BETWEEN 1 AND 128), session_id BLOB CHECK(session_id IS NULL OR length(session_id) = 16), FOREIGN KEY(execution_id) REFERENCES executions(execution_id), FOREIGN KEY(agent_id) REFERENCES agent_instances(agent_id), FOREIGN KEY(goal_id) REFERENCES goals(goal_id), FOREIGN KEY(goal_id, dag_revision) REFERENCES goal_dag_revisions(goal_id, dag_revision), FOREIGN KEY(goal_id, dag_revision, node_id) REFERENCES goal_dag_nodes(goal_id, dag_revision, node_id), CHECK((principal_kind = 0 AND principal_id IS NULL) OR (principal_kind IN (1, 2) AND principal_id IS NOT NULL)))";
pub(crate) const EXPECTED_EXECUTION_COMMAND_EVIDENCE_TABLE_SQL: &str = "CREATE TABLE execution_command_evidence (execution_id BLOB PRIMARY KEY NOT NULL CHECK(length(execution_id) = 16), command_class INTEGER NOT NULL CHECK(command_class IN (0, 1)), catalog_fingerprint BLOB NOT NULL CHECK(length(catalog_fingerprint) = 32), FOREIGN KEY(execution_id) REFERENCES execution_provenance(execution_id))";
pub(crate) const EXPECTED_EXECUTION_GENERATED_ARTIFACTS_TABLE_SQL: &str = "CREATE TABLE execution_generated_artifacts (execution_id BLOB PRIMARY KEY NOT NULL CHECK(length(execution_id) = 16), workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16), artifact_kind INTEGER NOT NULL CHECK(artifact_kind = 0), content_hash BLOB NOT NULL CHECK(length(content_hash) = 32), byte_count INTEGER NOT NULL CHECK(byte_count >= 1), FOREIGN KEY(execution_id) REFERENCES executions(execution_id))";
/// Current v31 output-event schema. Gap markers must immediately follow their
/// missing range and report the exact number of omitted chunks.
pub(crate) const EXPECTED_EXECUTION_OUTPUT_EVENTS_TABLE_SQL: &str = "CREATE TABLE execution_output_events (execution_id BLOB NOT NULL CHECK(length(execution_id) = 16), sequence INTEGER NOT NULL CHECK(sequence >= 1), event_kind INTEGER NOT NULL CHECK(event_kind IN (0, 1)), stream INTEGER CHECK(stream IS NULL OR stream IN (0, 1)), bytes BLOB CHECK(bytes IS NULL OR (typeof(bytes) = 'blob' AND length(bytes) BETWEEN 1 AND 4096)), first_missing INTEGER CHECK(first_missing IS NULL OR first_missing >= 1), last_missing INTEGER CHECK(last_missing IS NULL OR last_missing >= 1), omitted_bytes INTEGER CHECK(omitted_bytes IS NULL OR omitted_bytes >= 1), omitted_chunks INTEGER CHECK(omitted_chunks IS NULL OR omitted_chunks >= 1), gap_cause INTEGER CHECK(gap_cause IS NULL OR gap_cause IN (0, 1, 2)), PRIMARY KEY(execution_id, sequence), FOREIGN KEY(execution_id) REFERENCES executions(execution_id), CHECK((event_kind = 0 AND stream IS NOT NULL AND bytes IS NOT NULL AND first_missing IS NULL AND last_missing IS NULL AND omitted_bytes IS NULL AND omitted_chunks IS NULL AND gap_cause IS NULL) OR (event_kind = 1 AND bytes IS NULL AND first_missing IS NOT NULL AND last_missing IS NOT NULL AND omitted_bytes IS NOT NULL AND omitted_chunks IS NOT NULL AND gap_cause IS NOT NULL AND first_missing <= last_missing AND sequence - 1 = last_missing AND omitted_chunks = last_missing - first_missing + 1)))";
/// v30 output-event schema retained for validating databases before the v31
/// gap-shape migration. It allowed a marker to occur after, and to overstate,
/// its omitted range; the v31 table rejects both forms.
pub(crate) const EXPECTED_EXECUTION_OUTPUT_EVENTS_TABLE_SQL_V30: &str = "CREATE TABLE execution_output_events (execution_id BLOB NOT NULL CHECK(length(execution_id) = 16), sequence INTEGER NOT NULL CHECK(sequence >= 1), event_kind INTEGER NOT NULL CHECK(event_kind IN (0, 1)), stream INTEGER CHECK(stream IS NULL OR stream IN (0, 1)), bytes BLOB CHECK(bytes IS NULL OR (typeof(bytes) = 'blob' AND length(bytes) BETWEEN 1 AND 4096)), first_missing INTEGER CHECK(first_missing IS NULL OR first_missing >= 1), last_missing INTEGER CHECK(last_missing IS NULL OR last_missing >= 1), omitted_bytes INTEGER CHECK(omitted_bytes IS NULL OR omitted_bytes >= 1), omitted_chunks INTEGER CHECK(omitted_chunks IS NULL OR omitted_chunks >= 1), gap_cause INTEGER CHECK(gap_cause IS NULL OR gap_cause IN (0, 1, 2)), PRIMARY KEY(execution_id, sequence), FOREIGN KEY(execution_id) REFERENCES executions(execution_id), CHECK((event_kind = 0 AND stream IS NOT NULL AND bytes IS NOT NULL AND first_missing IS NULL AND last_missing IS NULL AND omitted_bytes IS NULL AND omitted_chunks IS NULL AND gap_cause IS NULL) OR (event_kind = 1 AND bytes IS NULL AND first_missing IS NOT NULL AND last_missing IS NOT NULL AND omitted_bytes IS NOT NULL AND omitted_chunks IS NOT NULL AND gap_cause IS NOT NULL AND first_missing <= last_missing AND sequence > last_missing)))";

const MAX_CWD_BYTES: usize = 4_096;
const MAX_OUTPUT_BYTES: usize = 1024 * 1024;

const RECORD_QUERY: &str = "SELECT
        length(CAST(e.execution_id AS BLOB)), length(CAST(e.workspace_id AS BLOB)),
        length(CAST(e.activity_id AS BLOB)), length(CAST(e.request_digest AS BLOB)),
        length(CAST(e.cwd AS BLOB)), length(CAST(e.stdout AS BLOB)), length(CAST(e.stderr AS BLOB)),
        e.execution_id, e.workspace_id, e.activity_id, e.state, e.mode, e.request_digest, e.cwd,
        e.timeout_ms, e.output_limit, e.workspace_read, e.workspace_write, e.network,
        e.exit_code, e.signal, e.duration_ms, e.stdout, e.stdout_total_bytes, e.stdout_truncated,
        e.stderr, e.stderr_total_bytes, e.stderr_truncated, e.failure_code,
        e.created_at_ms, e.updated_at_ms, e.revision,
        p.agent_id, p.agent_revision, p.principal_kind, p.principal_id,
        p.goal_id, p.goal_revision, p.dag_revision, p.node_id, p.node_revision, p.command_id,
        p.session_id,
        c.command_class, c.catalog_fingerprint
    FROM executions AS e
    LEFT JOIN execution_provenance AS p ON p.execution_id = e.execution_id
    LEFT JOIN execution_command_evidence AS c ON c.execution_id = p.execution_id";

const OUTPUT_EVENT_QUERY: &str = "SELECT execution_id, sequence, event_kind, stream, bytes,
        first_missing, last_missing, omitted_bytes, omitted_chunks, gap_cause
    FROM execution_output_events";

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

/// One authorized execution record and the optional generated-package
/// manifest observed from the same `SQLite` snapshot.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedExecutionSnapshot {
    record: RegisteredExecution,
    generated_package: Option<GeneratedPackageManifest>,
}

impl AuthorizedExecutionSnapshot {
    const fn new(
        record: RegisteredExecution,
        generated_package: Option<GeneratedPackageManifest>,
    ) -> Self {
        Self {
            record,
            generated_package,
        }
    }

    pub const fn record(&self) -> &RegisteredExecution {
        &self.record
    }

    pub const fn generated_package(&self) -> Option<GeneratedPackageManifest> {
        self.generated_package
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
            ON executions(state, updated_at_ms, execution_id);
         CREATE TABLE execution_provenance (
            execution_id BLOB PRIMARY KEY NOT NULL CHECK(length(execution_id) = 16),
            agent_id BLOB NOT NULL CHECK(length(agent_id) = 16),
            agent_revision INTEGER NOT NULL CHECK(agent_revision >= 1),
            principal_kind INTEGER NOT NULL CHECK(principal_kind IN (0, 1, 2)),
            principal_id BLOB CHECK(principal_id IS NULL OR length(principal_id) = 16),
            goal_id BLOB NOT NULL CHECK(length(goal_id) = 16),
            goal_revision INTEGER NOT NULL CHECK(goal_revision >= 1),
            dag_revision INTEGER NOT NULL CHECK(dag_revision >= 1),
            node_id BLOB NOT NULL CHECK(length(node_id) = 16),
            node_revision INTEGER NOT NULL CHECK(node_revision >= 1),
            command_id TEXT NOT NULL CHECK(length(CAST(command_id AS BLOB)) BETWEEN 1 AND 128),
            session_id BLOB CHECK(session_id IS NULL OR length(session_id) = 16),
            FOREIGN KEY(execution_id) REFERENCES executions(execution_id),
            FOREIGN KEY(agent_id) REFERENCES agent_instances(agent_id),
            FOREIGN KEY(goal_id) REFERENCES goals(goal_id),
            FOREIGN KEY(goal_id, dag_revision) REFERENCES goal_dag_revisions(goal_id, dag_revision),
            FOREIGN KEY(goal_id, dag_revision, node_id) REFERENCES goal_dag_nodes(goal_id, dag_revision, node_id),
            CHECK((principal_kind = 0 AND principal_id IS NULL) OR (principal_kind IN (1, 2) AND principal_id IS NOT NULL))
         );",
    )?;
    connection.execute_batch(EXPECTED_EXECUTION_OUTPUT_EVENTS_TABLE_SQL)?;
    // The command and generated-artifact contracts have one canonical SQL
    // definition each. Keep creation and validation tied to those values.
    connection.execute_batch(EXPECTED_EXECUTION_COMMAND_EVIDENCE_TABLE_SQL)?;
    connection.execute_batch(EXPECTED_EXECUTION_GENERATED_ARTIFACTS_TABLE_SQL)?;
    Ok(())
}

pub(crate) fn schema_objects() -> [(&'static str, &'static str); 7] {
    [
        ("table", "executions"),
        ("index", "executions_activity_created_idx"),
        ("index", "executions_state_updated_idx"),
        ("table", "execution_provenance"),
        ("table", "execution_command_evidence"),
        ("table", "execution_generated_artifacts"),
        ("table", "execution_output_events"),
    ]
}

pub(crate) fn schema_objects_v29() -> [(&'static str, &'static str); 5] {
    [
        ("table", "executions"),
        ("index", "executions_activity_created_idx"),
        ("index", "executions_state_updated_idx"),
        ("table", "execution_provenance"),
        ("table", "execution_output_events"),
    ]
}

pub(crate) fn validate_schema(connection: &Connection) -> Result<(), ExecutionStoreError> {
    validate_schema_with_provenance(
        connection,
        EXPECTED_EXECUTION_PROVENANCE_TABLE_SQL,
        EXPECTED_EXECUTION_OUTPUT_EVENTS_TABLE_SQL,
        true,
        true,
    )
}

/// Validate the v30 execution schema before the v30 -> v31 output-event
/// migration. The v30 output table intentionally retains its relaxed gap
/// checks; callers must run [`migrate_output_events_to_v31`] before using the
/// current validator.
pub(crate) fn validate_schema_v30(connection: &Connection) -> Result<(), ExecutionStoreError> {
    validate_schema_with_provenance(
        connection,
        EXPECTED_EXECUTION_PROVENANCE_TABLE_SQL,
        EXPECTED_EXECUTION_OUTPUT_EVENTS_TABLE_SQL_V30,
        true,
        true,
    )
}

/// Validate the pre-session execution schema before the v29 -> v30 migration.
/// Historical provenance rows are intentionally upgraded with a NULL session;
/// callers must run [`migrate_to_v30`] before using the current validator.
pub(crate) fn validate_schema_v29(connection: &Connection) -> Result<(), ExecutionStoreError> {
    let expected_provenance = EXPECTED_EXECUTION_PROVENANCE_TABLE_SQL.replace(
        ", session_id BLOB CHECK(session_id IS NULL OR length(session_id) = 16)",
        "",
    );
    validate_schema_with_provenance(
        connection,
        &expected_provenance,
        EXPECTED_EXECUTION_OUTPUT_EVENTS_TABLE_SQL_V30,
        false,
        false,
    )
}

fn validate_schema_with_provenance(
    connection: &Connection,
    expected_provenance: &str,
    expected_output_events: &str,
    include_session: bool,
    include_extensions: bool,
) -> Result<(), ExecutionStoreError> {
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
    validate_foreign_keys(connection, "executions", 2)?;
    validate_schema_sql(
        connection,
        "table",
        "execution_provenance",
        expected_provenance,
    )?;
    validate_provenance_columns(connection, include_session)?;
    validate_foreign_keys(connection, "execution_provenance", 8)?;
    if include_extensions {
        validate_schema_sql(
            connection,
            "table",
            "execution_command_evidence",
            EXPECTED_EXECUTION_COMMAND_EVIDENCE_TABLE_SQL,
        )?;
        validate_command_evidence_columns(connection)?;
        validate_foreign_keys(connection, "execution_command_evidence", 1)?;
        validate_schema_sql(
            connection,
            "table",
            "execution_generated_artifacts",
            EXPECTED_EXECUTION_GENERATED_ARTIFACTS_TABLE_SQL,
        )?;
        validate_generated_artifact_columns(connection)?;
        validate_foreign_keys(connection, "execution_generated_artifacts", 2)?;
    }
    validate_schema_sql(
        connection,
        "table",
        "execution_output_events",
        expected_output_events,
    )?;
    validate_output_event_columns(connection)?;
    validate_foreign_keys(connection, "execution_output_events", 1)
}

/// Rebuild the v30 output-event table with the strict v31 gap-shape checks.
/// Rows are copied through the current table's constraints, so malformed
/// legacy gap metadata aborts the caller-owned transaction before the legacy
/// table can be dropped.
pub(crate) fn migrate_output_events_to_v31(
    transaction: &Transaction<'_>,
) -> Result<(), ExecutionStoreError> {
    transaction.execute(
        "ALTER TABLE execution_output_events RENAME TO execution_output_events_v30",
        [],
    )?;
    transaction.execute_batch(EXPECTED_EXECUTION_OUTPUT_EVENTS_TABLE_SQL)?;
    transaction.execute(
        "INSERT INTO execution_output_events (
            execution_id, sequence, event_kind, stream, bytes,
            first_missing, last_missing, omitted_bytes, omitted_chunks, gap_cause
         )
         SELECT execution_id, sequence, event_kind, stream, bytes,
            first_missing, last_missing, omitted_bytes, omitted_chunks, gap_cause
         FROM execution_output_events_v30
         ORDER BY execution_id, sequence",
        [],
    )?;
    transaction.execute("DROP TABLE execution_output_events_v30", [])?;
    Ok(())
}

pub(crate) fn begin_execution_in_transaction(
    transaction: &Transaction<'_>,
    command: &BeginExecution,
) -> Result<BeginExecutionRecord, ExecutionStoreError> {
    if crate::workspace_goal_deletion::artifact_identity_is_pending(
        transaction,
        crate::workspace_goal_deletion::GoalDeletionArtifactIdentity::GeneratedPackage(
            command.id(),
        ),
    )? {
        return Err(ExecutionStoreError::IdentityConflict);
    }
    if let Some(record) = get_execution_tx(transaction, command.id())? {
        if begin_matches(&record, command) {
            if let Some(provenance) = record.provenance() {
                validate_agent_authority_in_transaction(
                    transaction,
                    command,
                    provenance,
                    command.runtime_owner(),
                )?;
            }
            return Ok(BeginExecutionRecord {
                status: BeginExecutionStatus::Existing,
                record,
            });
        }
        return Err(ExecutionStoreError::IdentityConflict);
    }
    crate::workspace_execution_stops::ensure_execution_open(transaction, command.workspace_id())?;
    crate::workspace_work_cuts::guards::ensure_execution_open(
        transaction,
        command.workspace_id(),
        command.activity_id(),
        command.provenance(),
    )?;
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
    if let Some(provenance) = command.provenance() {
        validate_agent_authority_in_transaction(
            transaction,
            command,
            provenance,
            command.runtime_owner(),
        )?;
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
    if inserted == 1
        && let Some(provenance) = command.provenance()
    {
        insert_provenance_in_transaction(transaction, provenance)?;
    }
    let record =
        get_execution_tx(transaction, command.id())?.ok_or(ExecutionStoreError::RecordMissing)?;
    let status = if inserted == 1 {
        BeginExecutionStatus::Created
    } else {
        BeginExecutionStatus::Existing
    };
    if inserted == 1 {
        append_execution_semantic_event(transaction, &record, SemanticEventKind::ExecutionBegun)?;
    }
    Ok(BeginExecutionRecord { status, record })
}

/// Build the semantic event subject set for one execution: the exact Goal/DAG
/// node attribution when the execution carries Agent provenance.
fn execution_semantic_subjects(record: &RegisteredExecution) -> SemanticEventSubjects {
    let Some(provenance) = record.provenance() else {
        return SemanticEventSubjects {
            execution_id: Some(record.id()),
            ..SemanticEventSubjects::NONE
        };
    };
    let attribution = provenance.attribution();
    SemanticEventSubjects {
        goal_id: Some(attribution.goal_id()),
        dag_revision: Some(attribution.dag_revision()),
        node_id: Some(attribution.node_id()),
        execution_id: Some(record.id()),
        ..SemanticEventSubjects::NONE
    }
}

/// Append one semantic event for an authoritative execution transition inside
/// the caller-owned transaction.
fn append_execution_semantic_event(
    connection: &Connection,
    record: &RegisteredExecution,
    kind: SemanticEventKind,
) -> Result<(), ExecutionStoreError> {
    workspace_semantic_events::append_semantic_event(
        connection,
        &SemanticEventAppend::new(
            kind,
            record.workspace_id(),
            execution_semantic_subjects(record),
            record.revision().get(),
            record.timestamps().updated_at(),
        ),
    )?;
    Ok(())
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
        && record.provenance() == command.provenance()
}

fn validate_agent_authority_in_transaction(
    transaction: &Transaction<'_>,
    command: &BeginExecution,
    provenance: &ExecutionAgentProvenance,
    runtime_owner: Option<RuntimeInstanceId>,
) -> Result<(), ExecutionStoreError> {
    if provenance.execution_id() != command.id() {
        return Err(ExecutionStoreError::AgentAuthorityConflict);
    }
    let _runtime_owner = runtime_owner.ok_or(ExecutionStoreError::AgentAuthorityConflict)?;
    validate_activity_authority(transaction, command)?;
    validate_agent_snapshot(transaction, command, provenance)?;
    validate_goal_dag_node(transaction, command, provenance.attribution())?;
    Ok(())
}

fn validate_activity_authority(
    transaction: &Transaction<'_>,
    command: &BeginExecution,
) -> Result<(), ExecutionStoreError> {
    let activity = transaction
        .query_row(
            "SELECT workspace_id, state
             FROM activities WHERE activity_id = ?1",
            params![command.activity_id().into_uuid().as_bytes()],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()?;
    let Some((workspace_id, state)) = activity else {
        return Err(ExecutionStoreError::AgentAuthorityConflict);
    };
    let expected_workspace = command.workspace_id().into_uuid().into_bytes();
    if workspace_id != expected_workspace || state != encode_activity_state(ActivityState::Open) {
        return Err(ExecutionStoreError::AgentAuthorityConflict);
    }
    Ok(())
}

fn validate_agent_snapshot(
    transaction: &Transaction<'_>,
    command: &BeginExecution,
    provenance: &ExecutionAgentProvenance,
) -> Result<(), ExecutionStoreError> {
    validate_current_agent_snapshot(
        transaction,
        command.workspace_id(),
        command.activity_id(),
        provenance,
    )
}

fn validate_goal_dag_node(
    transaction: &Transaction<'_>,
    command: &BeginExecution,
    attribution: GoalNodeAttribution,
) -> Result<(), ExecutionStoreError> {
    let goal = transaction
        .query_row(
            "SELECT workspace_id, activity_id, state, revision
             FROM goals WHERE goal_id = ?1",
            params![attribution.goal_id().into_uuid().as_bytes()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()?;
    let Some((workspace_id, activity_id, state, revision)) = goal else {
        return Err(ExecutionStoreError::AgentAuthorityConflict);
    };
    let expected_workspace = command.workspace_id().into_uuid().into_bytes();
    let expected_activity = command.activity_id().into_uuid().into_bytes();
    if workspace_id != expected_workspace
        || activity_id != expected_activity
        || state != 0
        || revision != attribution.expected_goal_revision().get()
    {
        return Err(ExecutionStoreError::AgentAuthorityConflict);
    }
    let dag_head: Option<i64> = transaction
        .query_row(
            "SELECT dag_revision FROM goal_dag_heads WHERE goal_id = ?1",
            params![attribution.goal_id().into_uuid().as_bytes()],
            |row| row.get(0),
        )
        .optional()?;
    if dag_head != Some(attribution.dag_revision().get()) {
        return Err(ExecutionStoreError::AgentAuthorityConflict);
    }
    let node = transaction
        .query_row(
            "SELECT node_revision, lifecycle_state
             FROM goal_dag_nodes
             WHERE goal_id = ?1 AND dag_revision = ?2 AND node_id = ?3",
            params![
                attribution.goal_id().into_uuid().as_bytes(),
                attribution.dag_revision().get(),
                attribution.node_id().into_uuid().as_bytes(),
            ],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()?;
    if node != Some((attribution.expected_node_revision().get(), 1)) {
        return Err(ExecutionStoreError::AgentAuthorityConflict);
    }
    Ok(())
}

fn insert_provenance_in_transaction(
    transaction: &Transaction<'_>,
    provenance: &ExecutionAgentProvenance,
) -> Result<(), ExecutionStoreError> {
    let (principal_kind, principal_id) = encode_principal(provenance.principal());
    let attribution = provenance.attribution();
    let session_id = provenance
        .session_id()
        .map(|session_id| session_id.into_uuid().into_bytes().to_vec());
    transaction.execute(
        "INSERT INTO execution_provenance (
            execution_id, agent_id, agent_revision, principal_kind, principal_id,
            goal_id, goal_revision, dag_revision, node_id, node_revision, command_id, session_id
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            provenance.execution_id().into_uuid().as_bytes(),
            provenance.agent_id().into_uuid().as_bytes(),
            provenance.agent_revision().get(),
            principal_kind,
            principal_id,
            attribution.goal_id().into_uuid().as_bytes(),
            attribution.expected_goal_revision().get(),
            attribution.dag_revision().get(),
            attribution.node_id().into_uuid().as_bytes(),
            attribution.expected_node_revision().get(),
            provenance.command_id().as_str(),
            session_id,
        ],
    )?;
    if let Some(evidence) = provenance.project_command() {
        transaction.execute(
            "INSERT INTO execution_command_evidence (
                execution_id, command_class, catalog_fingerprint
             ) VALUES (?1, ?2, ?3)",
            params![
                provenance.execution_id().into_uuid().as_bytes(),
                encode_project_command_class(evidence.class()),
                evidence.catalog_fingerprint().hash().as_bytes(),
            ],
        )?;
    }
    Ok(())
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
    complete_execution_with_native_closure(connection, command, None, None)
}

/// Complete a generated-package execution and persist its sealed manifest in
/// the same durable transaction as its terminal outcome. No successful
/// package result is exposed without its matching artifact evidence.
pub(crate) fn complete_execution_with_generated_package(
    connection: &mut Connection,
    command: &CompleteExecution,
    manifest: GeneratedPackageManifest,
) -> Result<RegisteredExecution, ExecutionStoreError> {
    complete_execution_with_native_closure(connection, command, Some(manifest), None)
}

/// Complete an execution and, when supplied, append its native closure fact
/// in the same immediate transaction as the terminal journal.
pub(crate) fn complete_execution_with_native_closure(
    connection: &mut Connection,
    command: &CompleteExecution,
    manifest: Option<GeneratedPackageManifest>,
    closure: Option<ExecutionNativeClosureFact>,
) -> Result<RegisteredExecution, ExecutionStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let record = complete_execution_in_transaction(&transaction, command)?;
    if let Some(manifest) = manifest {
        validate_generated_package_completion(&record, command, manifest)?;
        append_generated_package_in_transaction(&transaction, manifest)?;
    }
    if let Some(closure) = closure {
        native_closure::append_in_transaction(&transaction, &record, &closure)?;
    }
    transaction
        .commit()
        .map_err(|source| ExecutionStoreError::CommittedUnconfirmed {
            source: Box::new(source.into()),
        })?;
    Ok(record)
}

fn complete_execution_in_transaction(
    transaction: &Transaction<'_>,
    command: &CompleteExecution,
) -> Result<RegisteredExecution, ExecutionStoreError> {
    let current =
        get_execution_tx(transaction, command.id())?.ok_or(ExecutionStoreError::RecordMissing)?;
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
        get_execution_tx(transaction, command.id())?.ok_or(ExecutionStoreError::RecordMissing)?;
    let verification =
        crate::workspace_verification::finalize_in_transaction(transaction, &record)?;
    crate::workspace_effect_fact_outbox::append_execution_terminal(
        transaction,
        &record,
        verification.as_ref(),
    )?;
    append_execution_semantic_event(transaction, &record, SemanticEventKind::ExecutionTerminal)?;
    Ok(record)
}

fn validate_generated_package_completion(
    record: &RegisteredExecution,
    command: &CompleteExecution,
    manifest: GeneratedPackageManifest,
) -> Result<(), ExecutionStoreError> {
    if record.id() != manifest.execution_id()
        || record.workspace_id() != manifest.workspace_id()
        || record.state() != ExecutionState::Completed
        || execution_state_for_outcome(command.outcome()) != ExecutionState::Completed
        || manifest.kind() != GeneratedArtifactKind::MacOsInstallerPackage
        || manifest.byte_count().get() == 0
        || !matches!(
            record
                .provenance()
                .and_then(ExecutionAgentProvenance::project_command)
                .map(ProjectCommandEvidence::class),
            Some(ProjectCommandClass::GeneratedPackage)
        )
    {
        return Err(ExecutionStoreError::GeneratedArtifactConflict);
    }
    Ok(())
}

fn append_generated_package_in_transaction(
    transaction: &Transaction<'_>,
    manifest: GeneratedPackageManifest,
) -> Result<(), ExecutionStoreError> {
    transaction.execute(
        "INSERT INTO execution_generated_artifacts (
            execution_id, workspace_id, artifact_kind, content_hash, byte_count
         ) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            manifest.execution_id().into_uuid().as_bytes(),
            manifest.workspace_id().into_uuid().as_bytes(),
            encode_generated_artifact_kind(manifest.kind()),
            manifest.content_hash().as_bytes(),
            i64::try_from(manifest.byte_count().get())
                .map_err(|_| ExecutionStoreError::IntegerOverflow)?,
        ],
    )?;
    Ok(())
}

pub(crate) fn fail_execution(
    connection: &mut Connection,
    command: FailExecution,
) -> Result<RegisteredExecution, ExecutionStoreError> {
    fail_execution_with_native_closure(connection, command, None)
}

/// Fail an execution and, when supplied, append its native closure fact in
/// the same immediate transaction as the terminal journal.
pub(crate) fn fail_execution_with_native_closure(
    connection: &mut Connection,
    command: FailExecution,
    closure: Option<ExecutionNativeClosureFact>,
) -> Result<RegisteredExecution, ExecutionStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let record = fail_execution_in_transaction(&transaction, command)?;
    if let Some(closure) = closure {
        native_closure::append_in_transaction(&transaction, &record, &closure)?;
    }
    transaction
        .commit()
        .map_err(|source| ExecutionStoreError::CommittedUnconfirmed {
            source: Box::new(source.into()),
        })?;
    Ok(record)
}

fn fail_execution_in_transaction(
    transaction: &Transaction<'_>,
    command: FailExecution,
) -> Result<RegisteredExecution, ExecutionStoreError> {
    let current =
        get_execution_tx(transaction, command.id())?.ok_or(ExecutionStoreError::RecordMissing)?;
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
        get_execution_tx(transaction, command.id())?.ok_or(ExecutionStoreError::RecordMissing)?;
    let verification =
        crate::workspace_verification::finalize_in_transaction(transaction, &record)?;
    crate::workspace_effect_fact_outbox::append_execution_terminal(
        transaction,
        &record,
        verification.as_ref(),
    )?;
    append_execution_semantic_event(transaction, &record, SemanticEventKind::ExecutionTerminal)?;
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
        let record =
            get_execution_tx(&transaction, id)?.ok_or(ExecutionStoreError::RecordMissing)?;
        let verification =
            crate::workspace_verification::finalize_in_transaction(&transaction, &record)?;
        crate::workspace_effect_fact_outbox::append_execution_terminal(
            &transaction,
            &record,
            verification.as_ref(),
        )?;
        append_execution_semantic_event(
            &transaction,
            &record,
            SemanticEventKind::ExecutionTerminal,
        )?;
        records.push(record);
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
    let records =
        reconcile_expired_authority_executions_in_transaction(&transaction, observed_at, limit)?;
    transaction.commit()?;
    Ok(records)
}

/// Reconcile expired-authority executions inside a caller-owned transaction.
/// Activity recovery uses this helper to preserve one atomic Activity-first,
/// Execution-second classification transaction.
pub(crate) fn reconcile_expired_authority_executions_in_transaction(
    transaction: &Transaction<'_>,
    observed_at: TimestampMillis,
    limit: ExecutionListLimit,
) -> Result<Vec<RegisteredExecution>, ExecutionStoreError> {
    let selected = select_expired_authority_executions(transaction, observed_at, limit)?;
    let mut records = Vec::with_capacity(selected.len());
    for current in selected {
        let id = current.id();
        if observed_at.get() < current.timestamps().updated_at().get() {
            return Err(ExecutionStoreError::TimestampOrder);
        }
        let next_revision = current
            .revision()
            .checked_next()
            .map_err(|_| ExecutionStoreError::RevisionOverflow)?;
        let updated = transaction.execute(
            "UPDATE executions SET state = 6, updated_at_ms = ?1, revision = ?2
             WHERE execution_id = ?3 AND state IN (0, 1) AND revision = ?4
               AND NOT EXISTS (
                   SELECT 1 FROM agent_instances AS ai
                   WHERE ai.activity_id = executions.activity_id
                     AND ai.session_id IS NOT NULL
                     AND ai.attachment_state = 0
               )",
            params![
                timestamp_i64(observed_at),
                next_revision.get(),
                id.into_uuid().as_bytes(),
                current.revision().get()
            ],
        )?;
        if updated != 1 {
            return Err(ExecutionStoreError::RevisionConflict);
        }
        let record =
            get_execution_tx(transaction, id)?.ok_or(ExecutionStoreError::RecordMissing)?;
        let verification =
            crate::workspace_verification::finalize_in_transaction(transaction, &record)?;
        crate::workspace_effect_fact_outbox::append_execution_terminal(
            transaction,
            &record,
            verification.as_ref(),
        )?;
        append_execution_semantic_event(
            transaction,
            &record,
            SemanticEventKind::ExecutionTerminal,
        )?;
        records.push(record);
    }
    Ok(records)
}

/// Capture the original ordered eligibility cohort with the canonical predicate.
pub(crate) fn select_expired_authority_executions(
    transaction: &Transaction<'_>,
    observed_at: TimestampMillis,
    limit: ExecutionListLimit,
) -> Result<Vec<RegisteredExecution>, ExecutionStoreError> {
    let ids = {
        let mut statement = transaction.prepare(
            "SELECT e.execution_id FROM executions e
             JOIN activities a ON a.activity_id = e.activity_id
             WHERE e.state IN (0, 1)
               AND (a.state = ?2
                    OR (a.lease_until_ms IS NOT NULL AND a.lease_until_ms <= ?1))
               AND NOT EXISTS (
                   SELECT 1 FROM agent_instances AS ai
                   WHERE ai.activity_id = e.activity_id
                     AND ai.session_id IS NOT NULL
                     AND ai.attachment_state = 0
               )
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
            get_execution_tx(transaction, id)?.ok_or(ExecutionStoreError::RecordMissing)?;
        records.push(current);
    }
    Ok(records)
}

pub(crate) fn get_execution(
    connection: &Connection,
    id: ExecutionId,
) -> Result<Option<RegisteredExecution>, ExecutionStoreError> {
    connection
        .query_row(
            &format!("{RECORD_QUERY} WHERE e.execution_id = ?1"),
            params![id.into_uuid().as_bytes()],
            decode_record,
        )
        .optional()
        .map_err(ExecutionStoreError::from)
}

/// Read only bounded manifest metadata. The artifact path remains derived by
/// the execution runtime from the workspace and execution identities.
pub(crate) fn get_generated_package_manifest(
    connection: &Connection,
    execution_id: ExecutionId,
) -> Result<Option<GeneratedPackageManifest>, ExecutionStoreError> {
    let transaction = connection.unchecked_transaction()?;
    let record = get_execution_tx(&transaction, execution_id)?;
    let manifest = get_generated_package_manifest_tx(&transaction, execution_id, record.as_ref())?;
    transaction.commit()?;
    Ok(manifest)
}

/// Read one execution's terminal record, generated-package manifest, and
/// optional native closure fact from one durable authority snapshot.
pub(crate) fn get_native_closure_snapshot(
    connection: &Connection,
    execution_id: ExecutionId,
) -> Result<Option<native_closure::ExecutionNativeClosureSnapshot>, ExecutionStoreError> {
    native_closure::snapshot(connection, execution_id)
}

pub(crate) fn get_generated_package_manifest_tx(
    transaction: &Connection,
    execution_id: ExecutionId,
    record: Option<&RegisteredExecution>,
) -> Result<Option<GeneratedPackageManifest>, ExecutionStoreError> {
    let manifest = transaction
        .query_row(
            "SELECT workspace_id, artifact_kind, content_hash, byte_count
             FROM execution_generated_artifacts WHERE execution_id = ?1",
            params![execution_id.into_uuid().as_bytes()],
            |row| {
                let workspace_id = row.get::<_, Vec<u8>>(0)?;
                let kind = row.get::<_, i64>(1)?;
                let content_hash = row.get::<_, Vec<u8>>(2)?;
                let byte_count = row.get::<_, i64>(3)?;
                decode_generated_package_manifest(
                    execution_id,
                    &workspace_id,
                    kind,
                    &content_hash,
                    byte_count,
                )
                .map_err(to_sqlite_decode_error)
            },
        )
        .optional()
        .map_err(ExecutionStoreError::from)?;
    let record_matches = match (&manifest, record) {
        (Some(manifest), Some(record)) => {
            record.workspace_id() == manifest.workspace_id()
                && record.state() == ExecutionState::Completed
                && matches!(
                    record
                        .provenance()
                        .and_then(ExecutionAgentProvenance::project_command)
                        .map(ProjectCommandEvidence::class),
                    Some(ProjectCommandClass::GeneratedPackage)
                )
        }
        _ => false,
    };
    if manifest.is_some() && !record_matches {
        return Err(ExecutionStoreError::CorruptRecord(
            "execution_generated_artifacts.execution",
        ));
    }
    Ok(manifest)
}

/// Read only the bounded generated-package manifests whose execution row is a
/// successful `GeneratedPackage` execution. The joins and evidence checks are
/// intentionally kept in this `SQLite` adapter so callers cannot supply
/// caller-invented manifest metadata as artifact authority.
pub(crate) fn list_generated_package_manifests(
    connection: &Connection,
    workspace_id: WorkspaceId,
    limit: ExecutionListLimit,
) -> Result<Vec<GeneratedPackageManifest>, ExecutionStoreError> {
    let transaction = connection.unchecked_transaction()?;
    let manifests = {
        let mut statement = transaction.prepare(
            "SELECT a.execution_id, a.workspace_id, a.artifact_kind,
                    a.content_hash, a.byte_count, e.workspace_id,
                    e.state, c.command_class
             FROM execution_generated_artifacts AS a
             LEFT JOIN executions AS e ON e.execution_id = a.execution_id
             LEFT JOIN execution_command_evidence AS c ON c.execution_id = a.execution_id
             WHERE a.workspace_id = ?1
             ORDER BY e.updated_at_ms DESC, a.execution_id DESC
             LIMIT ?2",
        )?;
        let mut rows = statement.query(params![
            workspace_id.into_uuid().as_bytes(),
            i64::from(limit.get()),
        ])?;
        let mut manifests = Vec::new();
        while let Some(row) = rows.next()? {
            let execution_id = decode_execution_id(&row.get::<_, Vec<u8>>(0)?)?;
            let raw_workspace_id = row.get::<_, Vec<u8>>(1)?;
            let manifest = decode_generated_package_manifest(
                execution_id,
                &raw_workspace_id,
                row.get(2)?,
                &row.get::<_, Vec<u8>>(3)?,
                row.get(4)?,
            )?;
            let execution_workspace_id = row
                .get::<_, Option<Vec<u8>>>(5)?
                .ok_or(ExecutionStoreError::CorruptRecord(
                    "execution_generated_artifacts.execution",
                ))
                .and_then(|value| decode_workspace_id(&value))?;
            let state = row
                .get::<_, Option<i64>>(6)?
                .ok_or(ExecutionStoreError::CorruptRecord(
                    "execution_generated_artifacts.execution",
                ))
                .and_then(decode_state)?;
            let command_class = row
                .get::<_, Option<i64>>(7)?
                .ok_or(ExecutionStoreError::CorruptRecord(
                    "execution_generated_artifacts.command_evidence",
                ))
                .and_then(decode_project_command_class)?;
            if manifest.workspace_id() != workspace_id
                || execution_workspace_id != workspace_id
                || state != ExecutionState::Completed
                || command_class != ProjectCommandClass::GeneratedPackage
            {
                return Err(ExecutionStoreError::CorruptRecord(
                    "execution_generated_artifacts.execution",
                ));
            }
            manifests.push(manifest);
        }
        manifests
    };
    transaction.commit()?;
    Ok(manifests)
}

/// Read one Agent-originated execution through a single durable authority
/// snapshot.
///
/// The execution provenance and the current Agent attachment/focus are
/// checked while the same `SQLite` read transaction is open. This is the
/// linearization point for authority-scoped reads and coordinator-backed
/// cancellation; callers must not split this into a preflight read followed by
/// an effect.
pub(crate) fn get_execution_authorized(
    connection: &Connection,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    execution_id: ExecutionId,
    provenance: &ExecutionAgentProvenance,
) -> Result<RegisteredExecution, ExecutionStoreError> {
    validate_authorized_execution_id(execution_id, provenance)?;
    let transaction = connection.unchecked_transaction()?;
    let record = get_execution_authorized_tx(
        &transaction,
        workspace_id,
        activity_id,
        execution_id,
        provenance,
    )?;
    transaction.commit()?;
    Ok(record)
}

/// Read one Agent-originated execution and its optional generated-package
/// manifest through one durable authority snapshot.
pub(crate) fn get_execution_authorized_with_generated_package(
    connection: &Connection,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    execution_id: ExecutionId,
    provenance: &ExecutionAgentProvenance,
) -> Result<AuthorizedExecutionSnapshot, ExecutionStoreError> {
    validate_authorized_execution_id(execution_id, provenance)?;
    let transaction = connection.unchecked_transaction()?;
    let record = get_execution_authorized_tx(
        &transaction,
        workspace_id,
        activity_id,
        execution_id,
        provenance,
    )?;
    let generated_package =
        get_generated_package_manifest_tx(&transaction, execution_id, Some(&record))?;
    transaction.commit()?;
    Ok(AuthorizedExecutionSnapshot::new(record, generated_package))
}

/// Read one Agent-originated execution record and its bounded output from the
/// same durable `SQLite` snapshot.
pub(crate) fn read_execution_authorized(
    connection: &Connection,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    provenance: &ExecutionAgentProvenance,
    cursor: ExecutionOutputCursor,
    max_bytes: u64,
    max_events: usize,
) -> Result<AuthorizedExecutionRead, ExecutionStoreError> {
    let execution_id = provenance.execution_id();
    validate_output_read_limits(max_bytes, max_events)?;
    if cursor.execution_id() != execution_id {
        return Err(ExecutionStoreError::InvalidOutputCursor);
    }
    let transaction = connection.unchecked_transaction()?;
    let record = get_execution_authorized_tx(
        &transaction,
        workspace_id,
        activity_id,
        execution_id,
        provenance,
    )?;
    let output = read_output_events_in_transaction(&transaction, cursor, max_bytes, max_events)?;
    transaction.commit()?;
    Ok(AuthorizedExecutionRead::new(record, output))
}

fn validate_authorized_execution_id(
    execution_id: ExecutionId,
    provenance: &ExecutionAgentProvenance,
) -> Result<(), ExecutionStoreError> {
    if provenance.execution_id() == execution_id {
        Ok(())
    } else {
        Err(ExecutionStoreError::AgentAuthorityConflict)
    }
}

fn get_execution_authorized_tx(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    execution_id: ExecutionId,
    provenance: &ExecutionAgentProvenance,
) -> Result<RegisteredExecution, ExecutionStoreError> {
    let record =
        get_execution_tx(transaction, execution_id)?.ok_or(ExecutionStoreError::RecordMissing)?;
    if record.workspace_id() != workspace_id
        || record.activity_id() != activity_id
        || !record
            .provenance()
            .is_some_and(|stored| stored.matches_actor_authority(provenance))
    {
        return Err(ExecutionStoreError::AgentAuthorityConflict);
    }
    validate_current_agent_snapshot(transaction, workspace_id, activity_id, provenance)?;
    Ok(record)
}

fn validate_current_agent_snapshot(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    provenance: &ExecutionAgentProvenance,
) -> Result<(), ExecutionStoreError> {
    let agent = transaction
        .query_row(
            "SELECT workspace_id, activity_id, revision, principal_kind,
                    principal_id, attachment_state, focus_goal_id, focus_goal_revision,
                    focus_dag_revision, focus_node_id, focus_node_revision, session_id
             FROM agent_instances WHERE agent_id = ?1",
            params![provenance.agent_id().into_uuid().as_bytes()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<Vec<u8>>>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, Option<Vec<u8>>>(6)?,
                    row.get::<_, Option<i64>>(7)?,
                    row.get::<_, Option<i64>>(8)?,
                    row.get::<_, Option<Vec<u8>>>(9)?,
                    row.get::<_, Option<i64>>(10)?,
                    row.get::<_, Option<Vec<u8>>>(11)?,
                ))
            },
        )
        .optional()?;
    let Some((
        actual_workspace,
        actual_activity,
        actual_revision,
        actual_principal_kind,
        actual_principal_id,
        actual_attachment_state,
        actual_goal_id,
        actual_goal_revision,
        actual_dag_revision,
        actual_node_id,
        actual_node_revision,
        actual_session_id,
    )) = agent
    else {
        return Err(ExecutionStoreError::AgentAuthorityConflict);
    };
    let attribution = provenance.attribution();
    let (expected_principal_kind, expected_principal_id) = encode_principal(provenance.principal());
    let expected_workspace = workspace_id.into_uuid().into_bytes();
    let expected_activity = activity_id.into_uuid().into_bytes();
    let Some(expected_session_id) = provenance.session_id() else {
        return Err(ExecutionStoreError::AgentAuthorityConflict);
    };
    let expected_session_id = expected_session_id.into_uuid().into_bytes();
    let expected_goal = attribution.goal_id().into_uuid().into_bytes();
    let expected_node = attribution.node_id().into_uuid().into_bytes();
    if actual_workspace != expected_workspace
        || actual_activity != expected_activity
        || actual_revision != provenance.agent_revision().get()
        || actual_principal_kind != expected_principal_kind
        || actual_principal_id != expected_principal_id
        || actual_attachment_state != 0
        || actual_goal_id.as_deref() != Some(expected_goal.as_slice())
        || actual_goal_revision != Some(attribution.expected_goal_revision().get())
        || actual_dag_revision != Some(attribution.dag_revision().get())
        || actual_node_id.as_deref() != Some(expected_node.as_slice())
        || actual_node_revision != Some(attribution.expected_node_revision().get())
        || actual_session_id.as_deref() != Some(expected_session_id.as_slice())
    {
        return Err(ExecutionStoreError::AgentAuthorityConflict);
    }
    Ok(())
}

pub(crate) fn list_executions(
    connection: &Connection,
    activity_id: ActivityId,
    limit: ExecutionListLimit,
) -> Result<Vec<RegisteredExecution>, ExecutionStoreError> {
    let mut statement = connection.prepare(&format!(
        "{RECORD_QUERY} WHERE e.activity_id = ?1
         ORDER BY e.created_at_ms DESC, e.execution_id DESC LIMIT ?2"
    ))?;
    let rows = statement.query_map(
        params![activity_id.into_uuid().as_bytes(), i64::from(limit.get())],
        decode_record,
    )?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(ExecutionStoreError::from)
}

/// Append a bounded batch of output events in one transaction with
/// exact-replay semantics for every event key.
pub(crate) fn append_output_events(
    connection: &mut Connection,
    events: &[ExecutionOutputEvent],
) -> Result<(), ExecutionStoreError> {
    if events.len() > MAX_EXECUTION_OUTPUT_READ_EVENTS {
        return Err(ExecutionStoreError::OutputBatchTooLarge {
            actual: events.len(),
            maximum: MAX_EXECUTION_OUTPUT_READ_EVENTS,
        });
    }
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let mut execution_states = Vec::with_capacity(events.len());
    for event in events {
        let execution_id = event.execution_id();
        if execution_states.iter().any(|(id, _)| *id == execution_id) {
            continue;
        }
        let state: Option<i64> = transaction
            .query_row(
                "SELECT state FROM executions WHERE execution_id = ?1",
                params![execution_id.into_uuid().as_bytes()],
                |row| row.get(0),
            )
            .optional()?;
        let state = decode_state(state.ok_or(ExecutionStoreError::RecordMissing)?)?;
        execution_states.push((execution_id, state));
    }
    for event in events {
        if execution_states
            .iter()
            .any(|(id, state)| *id == event.execution_id() && state.is_terminal())
        {
            match get_output_event(&transaction, event.key())? {
                Some(existing) if existing == *event => continue,
                Some(_) => return Err(ExecutionStoreError::OutputEventConflict),
                None => return Err(ExecutionStoreError::Terminal),
            }
        }
        let inserted = match event {
            ExecutionOutputEvent::Chunk(chunk) => transaction.execute(
                "INSERT INTO execution_output_events (
                    execution_id, sequence, event_kind, stream, bytes,
                    first_missing, last_missing, omitted_bytes, omitted_chunks, gap_cause
                 ) VALUES (?1, ?2, 0, ?3, ?4, NULL, NULL, NULL, NULL, NULL)
                 ON CONFLICT(execution_id, sequence) DO NOTHING",
                params![
                    chunk.execution_id().into_uuid().as_bytes(),
                    sequence_i64(chunk.sequence())?,
                    encode_stream(chunk.stream()),
                    chunk.bytes(),
                ],
            )?,
            ExecutionOutputEvent::Gap(gap) => transaction.execute(
                "INSERT INTO execution_output_events (
                    execution_id, sequence, event_kind, stream, bytes,
                    first_missing, last_missing, omitted_bytes, omitted_chunks, gap_cause
                 ) VALUES (?1, ?2, 1, ?3, NULL, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(execution_id, sequence) DO NOTHING",
                params![
                    gap.execution_id().into_uuid().as_bytes(),
                    sequence_i64(gap.sequence())?,
                    gap.stream().map(encode_stream),
                    sequence_i64(gap.first_missing())?,
                    sequence_i64(gap.last_missing())?,
                    i64::try_from(gap.omitted_bytes())
                        .map_err(|_| ExecutionStoreError::IntegerOverflow)?,
                    i64::try_from(gap.omitted_chunks())
                        .map_err(|_| ExecutionStoreError::IntegerOverflow)?,
                    encode_gap_cause(gap.cause()),
                ],
            )?,
        };
        if inserted == 0 {
            let existing = get_output_event(&transaction, event.key())?
                .ok_or(ExecutionStoreError::RecordMissing)?;
            if existing != *event {
                return Err(ExecutionStoreError::OutputEventConflict);
            }
        }
    }
    transaction
        .commit()
        .map_err(|source| ExecutionStoreError::CommittedUnconfirmed {
            source: Box::new(source.into()),
        })?;
    Ok(())
}

/// Read a deterministic, bounded prefix of one execution's durable output.
///
/// Every event charges its fixed metadata cost in addition to chunk bytes.
/// This makes a gap marker consume budget and prevents omitted output from
/// bypassing the caller's byte limit.
pub(crate) fn read_output_events(
    connection: &Connection,
    cursor: ExecutionOutputCursor,
    max_bytes: u64,
    max_events: usize,
) -> Result<ExecutionOutputRead, ExecutionStoreError> {
    validate_output_read_limits(max_bytes, max_events)?;
    let transaction = connection.unchecked_transaction()?;
    let result = read_output_events_in_transaction(&transaction, cursor, max_bytes, max_events)?;
    transaction.commit()?;
    Ok(result)
}

/// Read one output prefix only after the same `SQLite` snapshot has verified the
/// Agent authority that owns the execution.
pub(crate) fn read_output_events_authorized(
    connection: &Connection,
    activity_id: ActivityId,
    execution_id: ExecutionId,
    provenance: &ExecutionAgentProvenance,
    cursor: ExecutionOutputCursor,
    max_bytes: u64,
    max_events: usize,
) -> Result<ExecutionOutputRead, ExecutionStoreError> {
    validate_output_read_limits(max_bytes, max_events)?;
    if cursor.execution_id() != execution_id || provenance.execution_id() != execution_id {
        return Err(ExecutionStoreError::InvalidOutputCursor);
    }
    let transaction = connection.unchecked_transaction()?;
    let record =
        get_execution_tx(&transaction, execution_id)?.ok_or(ExecutionStoreError::RecordMissing)?;
    if record.activity_id() != activity_id
        || !record
            .provenance()
            .is_some_and(|stored| stored.matches_actor_authority(provenance))
    {
        return Err(ExecutionStoreError::AgentAuthorityConflict);
    }
    validate_current_agent_snapshot(&transaction, record.workspace_id(), activity_id, provenance)?;
    let result = read_output_events_in_transaction(&transaction, cursor, max_bytes, max_events)?;
    transaction.commit()?;
    Ok(result)
}

fn validate_output_read_limits(
    max_bytes: u64,
    max_events: usize,
) -> Result<(), ExecutionStoreError> {
    if !(MIN_EXECUTION_OUTPUT_READ_BYTES..=MAX_EXECUTION_OUTPUT_READ_BYTES).contains(&max_bytes)
        || max_events == 0
        || max_events > MAX_EXECUTION_OUTPUT_READ_EVENTS
    {
        return Err(ExecutionStoreError::InvalidOutputReadLimits {
            max_bytes,
            max_events,
        });
    }
    Ok(())
}

fn read_output_events_in_transaction(
    connection: &Connection,
    cursor: ExecutionOutputCursor,
    max_bytes: u64,
    max_events: usize,
) -> Result<ExecutionOutputRead, ExecutionStoreError> {
    let execution_id = cursor.execution_id();
    let state = connection
        .query_row(
            "SELECT state FROM executions WHERE execution_id = ?1",
            params![execution_id.into_uuid().as_bytes()],
            |row| row.get::<_, i64>(0),
        )
        .optional()?;
    let Some(state) = state else {
        return if cursor.after_sequence() == 0 {
            Err(ExecutionStoreError::RecordMissing)
        } else {
            Err(ExecutionStoreError::InvalidOutputCursor)
        };
    };
    let state = decode_state(state)?;
    if cursor.after_sequence() > 0 {
        let cursor_exists: bool = connection.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM execution_output_events
                WHERE execution_id = ?1 AND sequence = ?2
            )",
            params![
                execution_id.into_uuid().as_bytes(),
                i64::try_from(cursor.after_sequence())
                    .map_err(|_| ExecutionStoreError::IntegerOverflow)?,
            ],
            |row| row.get(0),
        )?;
        if !cursor_exists {
            return Err(ExecutionStoreError::InvalidOutputCursor);
        }
    }
    let probe_limit = i64::try_from(max_events.saturating_add(1))
        .map_err(|_| ExecutionStoreError::IntegerOverflow)?;
    let mut statement = connection.prepare(&format!(
        "{OUTPUT_EVENT_QUERY}
         WHERE execution_id = ?1 AND sequence > ?2
         ORDER BY sequence ASC LIMIT ?3"
    ))?;
    let mut rows = statement.query(params![
        execution_id.into_uuid().as_bytes(),
        i64::try_from(cursor.after_sequence()).map_err(|_| ExecutionStoreError::IntegerOverflow)?,
        probe_limit,
    ])?;
    let mut candidates = Vec::with_capacity(max_events.saturating_add(1));
    while let Some(row) = rows.next()? {
        candidates.push(decode_output_event(row, execution_id)?);
    }

    let mut remaining = max_bytes;
    let mut events = Vec::with_capacity(candidates.len().min(max_events));
    let mut truncated = candidates.len() > max_events;
    for event in candidates.into_iter().take(max_events) {
        let cost = event.read_cost_bytes();
        if cost > remaining {
            truncated = true;
            break;
        }
        remaining = remaining.saturating_sub(cost);
        events.push(event);
    }
    let next_cursor = events.last().map_or(cursor, |event| {
        ExecutionOutputCursor::from_sequence(event.execution_id(), event.sequence())
    });
    let terminal_state = state.is_terminal().then_some(state);
    Ok(ExecutionOutputRead::from_parts(
        execution_id,
        events,
        next_cursor,
        terminal_state,
        truncated,
    ))
}

pub(crate) fn verification_output_status(
    connection: &Connection,
    execution: &RegisteredExecution,
) -> Result<VerificationRunTerminalStatus, ExecutionStoreError> {
    // Keep the finalization transaction bounded even for a malformed or very
    // fragmented ledger. Capacity and coverage loss are never successful proof.
    const MAX_AUDIT_EVENTS: u32 = 65_536;
    if !execution.state().is_terminal() {
        return Err(ExecutionStoreError::InvalidTransition);
    }
    let recovery = VerificationRunTerminalStatus::recovery_required(None, None)
        .map_err(|_| ExecutionStoreError::CorruptRecord("verification_runs.recovery"))?;
    let mut accumulator = VerificationOutputAccumulator::new(execution.id());
    let mut statement = connection.prepare(&format!(
        "{OUTPUT_EVENT_QUERY} WHERE execution_id = ?1 ORDER BY sequence ASC LIMIT ?2"
    ))?;
    let mut rows = statement.query(params![
        execution.id().into_uuid().as_bytes(),
        i64::from(MAX_AUDIT_EVENTS) + 1,
    ])?;
    let mut remaining_events = MAX_AUDIT_EVENTS;
    let mut remaining_bytes = 2 * 1024 * 1024 + u64::from(MAX_AUDIT_EVENTS) * 64;
    while let Some(row) = rows.next()? {
        if remaining_events == 0 {
            return Ok(recovery);
        }
        remaining_events -= 1;
        let event = decode_output_event(row, execution.id())?;
        let Some(remaining) = remaining_bytes.checked_sub(event.read_cost_bytes()) else {
            return Ok(recovery);
        };
        remaining_bytes = remaining;
        if accumulator.push(&event).is_err() {
            return Ok(recovery);
        }
    }
    match accumulator.finish(execution) {
        Ok(status) => Ok(status),
        Err(_) => Ok(recovery),
    }
}

fn get_output_event(
    connection: &Connection,
    key: forge_domain::ExecutionOutputEventKey,
) -> Result<Option<ExecutionOutputEvent>, ExecutionStoreError> {
    connection
        .query_row(
            &format!("{OUTPUT_EVENT_QUERY} WHERE execution_id = ?1 AND sequence = ?2"),
            params![
                key.execution_id().into_uuid().as_bytes(),
                sequence_i64(key.sequence())?,
            ],
            |row| decode_output_event(row, key.execution_id()).map_err(to_sqlite_decode_error),
        )
        .optional()
        .map_err(ExecutionStoreError::from)
}

fn decode_output_event(
    row: &Row<'_>,
    expected_execution_id: ExecutionId,
) -> Result<ExecutionOutputEvent, ExecutionStoreError> {
    let raw_execution_id = row.get::<_, Vec<u8>>(0)?;
    validate_byte_length(
        "execution_output_events.execution_id",
        raw_execution_id.len(),
        16,
    )?;
    let execution_id = decode_execution_id(&raw_execution_id)?;
    if execution_id != expected_execution_id {
        return Err(ExecutionStoreError::CorruptRecord(
            "execution_output_events.execution_id",
        ));
    }
    let sequence =
        ExecutionOutputSequence::new(decode_u64("execution_output_events.sequence", row.get(1)?)?)
            .map_err(|_| ExecutionStoreError::CorruptRecord("execution_output_events.sequence"))?;
    let event_kind = row.get::<_, i64>(2)?;
    let stream = row.get::<_, Option<i64>>(3)?;
    let bytes = row.get::<_, Option<Vec<u8>>>(4)?;
    let first_missing = row.get::<_, Option<i64>>(5)?;
    let last_missing = row.get::<_, Option<i64>>(6)?;
    let omitted_bytes = row.get::<_, Option<i64>>(7)?;
    let omitted_chunks = row.get::<_, Option<i64>>(8)?;
    let gap_cause = row.get::<_, Option<i64>>(9)?;
    match event_kind {
        0 => {
            if first_missing.is_some()
                || last_missing.is_some()
                || omitted_bytes.is_some()
                || omitted_chunks.is_some()
                || gap_cause.is_some()
            {
                return Err(ExecutionStoreError::CorruptRecord(
                    "execution_output_events.chunk_shape",
                ));
            }
            let stream = decode_stream(stream)?.ok_or(ExecutionStoreError::CorruptRecord(
                "execution_output_events.stream",
            ))?;
            let bytes = bytes.ok_or(ExecutionStoreError::CorruptRecord(
                "execution_output_events.bytes",
            ))?;
            let chunk = ExecutionOutputChunk::new(execution_id, sequence, stream, &bytes)
                .map_err(|_| ExecutionStoreError::CorruptRecord("execution_output_events.bytes"))?;
            Ok(ExecutionOutputEvent::Chunk(chunk))
        }
        1 => {
            if bytes.is_some() {
                return Err(ExecutionStoreError::CorruptRecord(
                    "execution_output_events.gap_shape",
                ));
            }
            let first_missing =
                decode_required_u64("execution_output_events.first_missing", first_missing)?;
            let last_missing =
                decode_required_u64("execution_output_events.last_missing", last_missing)?;
            let omitted_bytes =
                decode_required_u64("execution_output_events.omitted_bytes", omitted_bytes)?;
            let omitted_chunks =
                decode_required_u64("execution_output_events.omitted_chunks", omitted_chunks)?;
            let cause = decode_gap_cause(gap_cause)?;
            let gap = ExecutionOutputGap::new(
                execution_id,
                sequence,
                ExecutionOutputGapParts::new(
                    ExecutionOutputSequence::new(first_missing).map_err(|_| {
                        ExecutionStoreError::CorruptRecord("execution_output_events.first_missing")
                    })?,
                    ExecutionOutputSequence::new(last_missing).map_err(|_| {
                        ExecutionStoreError::CorruptRecord("execution_output_events.last_missing")
                    })?,
                    decode_stream(stream)?,
                    omitted_bytes,
                    omitted_chunks,
                    cause,
                ),
            )
            .map_err(|_| ExecutionStoreError::CorruptRecord("execution_output_events.gap"))?;
            Ok(ExecutionOutputEvent::Gap(gap))
        }
        _ => Err(ExecutionStoreError::CorruptRecord(
            "execution_output_events.event_kind",
        )),
    }
}

fn to_sqlite_decode_error(error: ExecutionStoreError) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Blob, Box::new(error))
}

fn sequence_i64(sequence: ExecutionOutputSequence) -> Result<i64, ExecutionStoreError> {
    i64::try_from(sequence.get()).map_err(|_| ExecutionStoreError::IntegerOverflow)
}

const fn encode_stream(stream: ExecutionOutputStream) -> i64 {
    match stream {
        ExecutionOutputStream::Stdout => 0,
        ExecutionOutputStream::Stderr => 1,
    }
}

fn decode_stream(value: Option<i64>) -> Result<Option<ExecutionOutputStream>, ExecutionStoreError> {
    match value {
        None => Ok(None),
        Some(0) => Ok(Some(ExecutionOutputStream::Stdout)),
        Some(1) => Ok(Some(ExecutionOutputStream::Stderr)),
        Some(_) => Err(ExecutionStoreError::CorruptRecord(
            "execution_output_events.stream",
        )),
    }
}

const fn encode_gap_cause(value: ExecutionOutputGapCause) -> i64 {
    match value {
        ExecutionOutputGapCause::Backpressure => 0,
        ExecutionOutputGapCause::OutputLimit => 1,
        ExecutionOutputGapCause::BackpressureAndOutputLimit => 2,
    }
}

fn decode_gap_cause(value: Option<i64>) -> Result<ExecutionOutputGapCause, ExecutionStoreError> {
    match value {
        Some(0) => Ok(ExecutionOutputGapCause::Backpressure),
        Some(1) => Ok(ExecutionOutputGapCause::OutputLimit),
        Some(2) => Ok(ExecutionOutputGapCause::BackpressureAndOutputLimit),
        _ => Err(ExecutionStoreError::CorruptRecord(
            "execution_output_events.gap_cause",
        )),
    }
}

fn decode_required_u64(
    field: &'static str,
    value: Option<i64>,
) -> Result<u64, ExecutionStoreError> {
    value
        .ok_or(ExecutionStoreError::CorruptRecord(field))
        .and_then(|value| decode_u64(field, value))
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

pub(crate) fn get_execution_tx(
    transaction: &Connection,
    id: ExecutionId,
) -> Result<Option<RegisteredExecution>, ExecutionStoreError> {
    transaction
        .query_row(
            &format!("{RECORD_QUERY} WHERE e.execution_id = ?1"),
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
    let provenance = decode_provenance(row)?;
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
    RegisteredExecution::from_parts_with_provenance(
        attribution,
        ExecutionRecordDefinition::new(
            mode,
            cwd,
            ExecutionLimits::new(timeout, output_limit),
            permissions,
            request_digest,
        ),
        ExecutionRecordLifecycle::new(state, timestamps, revision, outcome, failure_code),
        provenance,
    )
    .map_err(|_| ExecutionStoreError::CorruptRecord("execution.evidence"))
}

fn decode_provenance(
    row: &Row<'_>,
) -> Result<Option<ExecutionAgentProvenance>, ExecutionStoreError> {
    let execution_id = decode_execution_id(&row.get::<_, Vec<u8>>(7)?)?;
    NullableProvenanceFields::read(row)?.into_provenance(execution_id)
}

struct NullableProvenanceFields {
    agent_id: Option<Vec<u8>>,
    agent_revision: Option<i64>,
    principal_kind: Option<i64>,
    principal_id: Option<Vec<u8>>,
    goal_id: Option<Vec<u8>>,
    goal_revision: Option<i64>,
    dag_revision: Option<i64>,
    node_id: Option<Vec<u8>>,
    node_revision: Option<i64>,
    command_id: Option<String>,
    session_id: Option<Vec<u8>>,
    project_command_class: Option<i64>,
    catalog_fingerprint: Option<Vec<u8>>,
}

impl NullableProvenanceFields {
    fn read(row: &Row<'_>) -> Result<Self, ExecutionStoreError> {
        Ok(Self {
            agent_id: row.get(32)?,
            agent_revision: row.get(33)?,
            principal_kind: row.get(34)?,
            principal_id: row.get(35)?,
            goal_id: row.get(36)?,
            goal_revision: row.get(37)?,
            dag_revision: row.get(38)?,
            node_id: row.get(39)?,
            node_revision: row.get(40)?,
            command_id: row.get(41)?,
            session_id: row.get(42)?,
            project_command_class: row.get(43)?,
            catalog_fingerprint: row.get(44)?,
        })
    }

    fn into_provenance(
        self,
        execution_id: ExecutionId,
    ) -> Result<Option<ExecutionAgentProvenance>, ExecutionStoreError> {
        if self.is_absent() {
            return Ok(None);
        }
        let Self {
            agent_id: Some(agent_id),
            agent_revision: Some(agent_revision),
            principal_kind: Some(principal_kind),
            principal_id,
            goal_id: Some(goal_id),
            goal_revision: Some(goal_revision),
            dag_revision: Some(dag_revision),
            node_id: Some(node_id),
            node_revision: Some(node_revision),
            command_id: Some(command_id),
            session_id,
            project_command_class,
            catalog_fingerprint,
        } = self
        else {
            return Err(ExecutionStoreError::CorruptRecord(
                "execution_provenance.completeness",
            ));
        };
        validate_byte_length("execution_provenance.agent_id", agent_id.len(), 16)?;
        validate_optional_exact_length(
            "execution_provenance.principal_id",
            principal_id.as_deref(),
            16,
        )?;
        validate_byte_length("execution_provenance.goal_id", goal_id.len(), 16)?;
        validate_byte_length("execution_provenance.node_id", node_id.len(), 16)?;
        let provenance = ExecutionAgentProvenance::from_parts(
            execution_id,
            AgentInstanceId::from_uuid(decode_uuid("execution_provenance.agent_id", &agent_id)?),
            AgentInstanceRevision::new(agent_revision).map_err(|_| {
                ExecutionStoreError::CorruptRecord("execution_provenance.agent_revision")
            })?,
            decode_principal(principal_kind, principal_id)?,
            GoalNodeAttribution::new(
                GoalId::from_uuid(decode_uuid("execution_provenance.goal_id", &goal_id)?),
                GoalRevision::new(goal_revision).map_err(|_| {
                    ExecutionStoreError::CorruptRecord("execution_provenance.goal_revision")
                })?,
                DagRevisionNumber::new(dag_revision).map_err(|_| {
                    ExecutionStoreError::CorruptRecord("execution_provenance.dag_revision")
                })?,
                DagNodeId::from_uuid(decode_uuid("execution_provenance.node_id", &node_id)?),
                DagNodeRevision::new(node_revision).map_err(|_| {
                    ExecutionStoreError::CorruptRecord("execution_provenance.node_revision")
                })?,
            ),
            ExecutionCommandId::new(command_id).map_err(|_| {
                ExecutionStoreError::CorruptRecord("execution_provenance.command_id")
            })?,
            decode_optional_session_id(session_id)?,
        );
        Ok(Some(
            match decode_project_command_evidence(project_command_class, catalog_fingerprint)? {
                Some(evidence) => provenance.with_project_command(evidence),
                None => provenance,
            },
        ))
    }

    fn is_absent(&self) -> bool {
        self.agent_id.is_none()
            && self.agent_revision.is_none()
            && self.principal_kind.is_none()
            && self.principal_id.is_none()
            && self.goal_id.is_none()
            && self.goal_revision.is_none()
            && self.dag_revision.is_none()
            && self.node_id.is_none()
            && self.node_revision.is_none()
            && self.command_id.is_none()
            && self.session_id.is_none()
            && self.project_command_class.is_none()
            && self.catalog_fingerprint.is_none()
    }
}

fn decode_optional_session_id(
    value: Option<Vec<u8>>,
) -> Result<Option<AgentSessionId>, ExecutionStoreError> {
    value
        .map(|value| {
            validate_byte_length("execution_provenance.session_id", value.len(), 16)?;
            Ok(AgentSessionId::from_uuid(decode_uuid(
                "execution_provenance.session_id",
                &value,
            )?))
        })
        .transpose()
}

fn decode_project_command_evidence(
    class: Option<i64>,
    fingerprint: Option<Vec<u8>>,
) -> Result<Option<ProjectCommandEvidence>, ExecutionStoreError> {
    match (class, fingerprint) {
        (None, None) => Ok(None),
        (Some(class), Some(fingerprint)) => {
            validate_byte_length(
                "execution_command_evidence.catalog_fingerprint",
                fingerprint.len(),
                FileContentHash::BYTE_LEN,
            )?;
            Ok(Some(ProjectCommandEvidence::new(
                decode_project_command_class(class)?,
                ProjectCommandCatalogFingerprint::from_hash(FileContentHash::from_bytes(
                    fingerprint.try_into().map_err(|_| {
                        ExecutionStoreError::CorruptRecord(
                            "execution_command_evidence.catalog_fingerprint",
                        )
                    })?,
                )),
            )))
        }
        _ => Err(ExecutionStoreError::CorruptRecord(
            "execution_command_evidence.completeness",
        )),
    }
}

fn decode_generated_package_manifest(
    execution_id: ExecutionId,
    workspace_id: &[u8],
    kind: i64,
    content_hash: &[u8],
    byte_count: i64,
) -> Result<GeneratedPackageManifest, ExecutionStoreError> {
    let kind = decode_generated_artifact_kind(kind)?;
    if kind != GeneratedArtifactKind::MacOsInstallerPackage {
        return Err(ExecutionStoreError::CorruptRecord(
            "execution_generated_artifacts.artifact_kind",
        ));
    }
    validate_byte_length(
        "execution_generated_artifacts.workspace_id",
        workspace_id.len(),
        16,
    )?;
    validate_byte_length(
        "execution_generated_artifacts.content_hash",
        content_hash.len(),
        FileContentHash::BYTE_LEN,
    )?;
    let byte_count = u64::try_from(byte_count)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(ExecutionStoreError::CorruptRecord(
            "execution_generated_artifacts.byte_count",
        ))?;
    Ok(GeneratedPackageManifest::new(
        WorkspaceId::from_uuid(decode_uuid(
            "execution_generated_artifacts.workspace_id",
            workspace_id,
        )?),
        execution_id,
        FileContentHash::from_bytes(content_hash.try_into().map_err(|_| {
            ExecutionStoreError::CorruptRecord("execution_generated_artifacts.content_hash")
        })?),
        FileByteCount::new(byte_count),
    ))
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

const fn encode_project_command_class(value: ProjectCommandClass) -> i64 {
    match value {
        ProjectCommandClass::Verify => 0,
        ProjectCommandClass::GeneratedPackage => 1,
    }
}

fn decode_project_command_class(value: i64) -> Result<ProjectCommandClass, ExecutionStoreError> {
    match value {
        0 => Ok(ProjectCommandClass::Verify),
        1 => Ok(ProjectCommandClass::GeneratedPackage),
        _ => Err(ExecutionStoreError::CorruptRecord(
            "execution_command_evidence.command_class",
        )),
    }
}

const fn encode_generated_artifact_kind(value: GeneratedArtifactKind) -> i64 {
    match value {
        GeneratedArtifactKind::MacOsInstallerPackage => 0,
    }
}

fn decode_generated_artifact_kind(
    value: i64,
) -> Result<GeneratedArtifactKind, ExecutionStoreError> {
    match value {
        0 => Ok(GeneratedArtifactKind::MacOsInstallerPackage),
        _ => Err(ExecutionStoreError::CorruptRecord(
            "execution_generated_artifacts.artifact_kind",
        )),
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

fn decode_uuid(field: &'static str, value: &[u8]) -> Result<Uuid, ExecutionStoreError> {
    Uuid::from_slice(value).map_err(|_| ExecutionStoreError::CorruptRecord(field))
}

fn encode_principal(value: AuthenticatedPrincipal) -> (i64, Option<Vec<u8>>) {
    match value {
        AuthenticatedPrincipal::TrustedStdio => (0, None),
        AuthenticatedPrincipal::DirectToken(id) => (1, Some(id.into_uuid().into_bytes().to_vec())),
        AuthenticatedPrincipal::OAuthGrant(id) => (2, Some(id.into_uuid().into_bytes().to_vec())),
    }
}

fn decode_principal(
    kind: i64,
    identifier: Option<Vec<u8>>,
) -> Result<AuthenticatedPrincipal, ExecutionStoreError> {
    match (kind, identifier) {
        (0, None) => Ok(AuthenticatedPrincipal::TrustedStdio),
        (1, Some(value)) => {
            validate_byte_length("execution_provenance.principal_id", value.len(), 16)?;
            Ok(AuthenticatedPrincipal::DirectToken(
                DirectTokenId::from_uuid(decode_uuid("execution_provenance.principal_id", &value)?),
            ))
        }
        (2, Some(value)) => {
            validate_byte_length("execution_provenance.principal_id", value.len(), 16)?;
            Ok(AuthenticatedPrincipal::OAuthGrant(OAuthGrantId::from_uuid(
                decode_uuid("execution_provenance.principal_id", &value)?,
            )))
        }
        _ => Err(ExecutionStoreError::CorruptRecord(
            "execution_provenance.principal",
        )),
    }
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

fn validate_byte_length(
    field: &'static str,
    actual: usize,
    expected: usize,
) -> Result<(), ExecutionStoreError> {
    if actual == expected {
        Ok(())
    } else {
        Err(ExecutionStoreError::CorruptRecord(field))
    }
}

fn validate_optional_exact_length(
    field: &'static str,
    value: Option<&[u8]>,
    expected: usize,
) -> Result<(), ExecutionStoreError> {
    value.map_or(Ok(()), |value| {
        validate_byte_length(field, value.len(), expected)
    })
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
    expected: &str,
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

fn validate_provenance_columns(
    connection: &Connection,
    include_session: bool,
) -> Result<(), ExecutionStoreError> {
    const EXPECTED_V29: &[ColumnShape] = &[
        ("execution_id", "BLOB", 1, 1),
        ("agent_id", "BLOB", 1, 0),
        ("agent_revision", "INTEGER", 1, 0),
        ("principal_kind", "INTEGER", 1, 0),
        ("principal_id", "BLOB", 0, 0),
        ("goal_id", "BLOB", 1, 0),
        ("goal_revision", "INTEGER", 1, 0),
        ("dag_revision", "INTEGER", 1, 0),
        ("node_id", "BLOB", 1, 0),
        ("node_revision", "INTEGER", 1, 0),
        ("command_id", "TEXT", 1, 0),
    ];
    const EXPECTED_V30: &[ColumnShape] = &[
        ("execution_id", "BLOB", 1, 1),
        ("agent_id", "BLOB", 1, 0),
        ("agent_revision", "INTEGER", 1, 0),
        ("principal_kind", "INTEGER", 1, 0),
        ("principal_id", "BLOB", 0, 0),
        ("goal_id", "BLOB", 1, 0),
        ("goal_revision", "INTEGER", 1, 0),
        ("dag_revision", "INTEGER", 1, 0),
        ("node_id", "BLOB", 1, 0),
        ("node_revision", "INTEGER", 1, 0),
        ("command_id", "TEXT", 1, 0),
        ("session_id", "BLOB", 0, 0),
    ];
    let expected = if include_session {
        EXPECTED_V30
    } else {
        EXPECTED_V29
    };
    let mut statement = connection.prepare("PRAGMA table_info(execution_provenance)")?;
    let mut rows = statement.query([])?;
    let mut actual = Vec::new();
    while let Some(row) = rows.next()? {
        if actual.len() >= expected.len() {
            return Err(ExecutionStoreError::CorruptRecord("execution_provenance"));
        }
        actual.push((
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, i64>(5)?,
        ));
    }
    if actual.len() == expected.len()
        && actual.iter().zip(expected).all(|(actual, expected)| {
            actual.0 == expected.0
                && actual.1 == expected.1
                && actual.2 == expected.2
                && actual.3 == expected.3
        })
    {
        Ok(())
    } else {
        Err(ExecutionStoreError::CorruptRecord("execution_provenance"))
    }
}

fn validate_command_evidence_columns(connection: &Connection) -> Result<(), ExecutionStoreError> {
    const EXPECTED: &[ColumnShape] = &[
        ("execution_id", "BLOB", 1, 1),
        ("command_class", "INTEGER", 1, 0),
        ("catalog_fingerprint", "BLOB", 1, 0),
    ];
    validate_column_shape(connection, "execution_command_evidence", EXPECTED)
}

fn validate_generated_artifact_columns(connection: &Connection) -> Result<(), ExecutionStoreError> {
    const EXPECTED: &[ColumnShape] = &[
        ("execution_id", "BLOB", 1, 1),
        ("workspace_id", "BLOB", 1, 0),
        ("artifact_kind", "INTEGER", 1, 0),
        ("content_hash", "BLOB", 1, 0),
        ("byte_count", "INTEGER", 1, 0),
    ];
    validate_column_shape(connection, "execution_generated_artifacts", EXPECTED)
}

fn validate_column_shape(
    connection: &Connection,
    table: &'static str,
    expected: &[ColumnShape],
) -> Result<(), ExecutionStoreError> {
    let mut statement = connection.prepare(&format!("PRAGMA table_info({table})"))?;
    let mut rows = statement.query([])?;
    let mut actual = Vec::new();
    while let Some(row) = rows.next()? {
        if actual.len() >= expected.len() {
            return Err(ExecutionStoreError::CorruptRecord(table));
        }
        actual.push((
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, i64>(5)?,
        ));
    }
    if actual.len() == expected.len()
        && actual.iter().zip(expected).all(|(actual, expected)| {
            actual.0 == expected.0
                && actual.1 == expected.1
                && actual.2 == expected.2
                && actual.3 == expected.3
        })
    {
        Ok(())
    } else {
        Err(ExecutionStoreError::CorruptRecord(table))
    }
}

fn validate_output_event_columns(connection: &Connection) -> Result<(), ExecutionStoreError> {
    const EXPECTED: &[ColumnShape] = &[
        ("execution_id", "BLOB", 1, 1),
        ("sequence", "INTEGER", 1, 2),
        ("event_kind", "INTEGER", 1, 0),
        ("stream", "INTEGER", 0, 0),
        ("bytes", "BLOB", 0, 0),
        ("first_missing", "INTEGER", 0, 0),
        ("last_missing", "INTEGER", 0, 0),
        ("omitted_bytes", "INTEGER", 0, 0),
        ("omitted_chunks", "INTEGER", 0, 0),
        ("gap_cause", "INTEGER", 0, 0),
    ];
    let mut statement = connection.prepare("PRAGMA table_info(execution_output_events)")?;
    let mut rows = statement.query([])?;
    let mut actual = Vec::new();
    while let Some(row) = rows.next()? {
        if actual.len() >= EXPECTED.len() {
            return Err(ExecutionStoreError::CorruptRecord(
                "execution_output_events",
            ));
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
        Err(ExecutionStoreError::CorruptRecord(
            "execution_output_events",
        ))
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
    ExecutionStop(#[from] crate::workspace_execution_stops::ExecutionStopStoreError),
    #[error(transparent)]
    WorkCut(#[from] Box<crate::WorkCutError>),
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Verification(#[from] crate::workspace_verification::VerificationStoreError),
    #[error(transparent)]
    SemanticEvents(#[from] crate::SemanticEventError),
    #[error(transparent)]
    EffectFactOutbox(#[from] crate::workspace_effect_fact_outbox::EffectFactOutboxError),
    #[error("execution journal commit requires durable readback")]
    CommittedUnconfirmed {
        #[source]
        source: Box<ExecutionStoreError>,
    },
    #[error("Execution identity conflicts with an existing record")]
    IdentityConflict,
    #[error(
        "Agent execution authority does not match the durable Activity, Agent, Goal, DAG, or Node"
    )]
    AgentAuthorityConflict,
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
    #[error("Generated package artifact does not match the successful sealed execution")]
    GeneratedArtifactConflict,
    #[error("native closure fact already exists for the execution")]
    NativeClosureAlreadyExists,
    #[error("native closure fact does not match the terminal execution record")]
    NativeClosureConflict,
    #[error("native closure output cursor does not match the durable output ledger")]
    NativeClosureOutputConflict,
    #[error("native closure fact does not match the generated-package evidence")]
    NativeClosureArtifactConflict,
    #[error("Execution timestamp precedes durable state")]
    TimestampOrder,
    #[error("Execution integer exceeds SQLite range")]
    IntegerOverflow,
    #[error("Execution output event conflicts with an existing sequence")]
    OutputEventConflict,
    #[error("Execution output batch has {actual} events; maximum is {maximum}")]
    OutputBatchTooLarge { actual: usize, maximum: usize },
    #[error("Execution output cursor does not refer to an exact durable event")]
    InvalidOutputCursor,
    #[error("Execution output read limits are invalid: {max_bytes} bytes, {max_events} events")]
    InvalidOutputReadLimits { max_bytes: u64, max_events: usize },
    #[error("corrupt Execution field {0}")]
    CorruptRecord(&'static str),
}

impl From<crate::WorkCutError> for ExecutionStoreError {
    fn from(error: crate::WorkCutError) -> Self {
        Self::WorkCut(Box::new(error))
    }
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
        crate::workspace_verification::create_schema(&connection)?;
        crate::workspace_goal_deletion::create_schema(&connection)?;
        crate::workspace_semantic_events::create_schema(&connection)?;
        crate::workspace_work_cuts::create_schema(&connection)?;
        crate::workspace_execution_stops::create_schema(&connection)?;
        Ok((connection, workspace_id, activity_id))
    }

    fn create_execution_admission_fixture_schema(
        connection: &Connection,
    ) -> Result<(), Box<dyn std::error::Error>> {
        crate::workspace_work_cuts::create_schema(connection)?;
        crate::workspace_execution_stops::create_schema(connection)?;
        Ok(())
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

    struct AgentFixture {
        connection: Connection,
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        owner: RuntimeInstanceId,
        agent_id: AgentInstanceId,
        goal_id: GoalId,
        node_id: DagNodeId,
    }

    struct AgentFixtureSeed {
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        owner: RuntimeInstanceId,
        agent_id: AgentInstanceId,
        session_id: AgentSessionId,
        goal_id: GoalId,
        node_id: DagNodeId,
    }

    fn create_agent_fixture_schema(connection: &Connection) -> rusqlite::Result<()> {
        connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE workspace(workspace_id BLOB PRIMARY KEY);
             CREATE TABLE activities(
                activity_id BLOB PRIMARY KEY,
                workspace_id BLOB NOT NULL,
                state INTEGER NOT NULL,
                lease_owner_id BLOB,
                lease_until_ms INTEGER
             );
             CREATE TABLE agent_instances(
                agent_id BLOB PRIMARY KEY,
                workspace_id BLOB NOT NULL,
                activity_id BLOB NOT NULL,
                session_id BLOB,
                revision INTEGER NOT NULL,
                principal_kind INTEGER NOT NULL,
                principal_id BLOB,
                attachment_state INTEGER NOT NULL,
                focus_goal_id BLOB,
                focus_goal_revision INTEGER,
                focus_dag_revision INTEGER,
                focus_node_id BLOB,
                focus_node_revision INTEGER
             );
             CREATE TABLE goals(
                goal_id BLOB PRIMARY KEY,
                workspace_id BLOB NOT NULL,
                activity_id BLOB NOT NULL,
                state INTEGER NOT NULL,
                revision INTEGER NOT NULL
             );
             CREATE TABLE goal_dag_revisions(
                goal_id BLOB NOT NULL,
                dag_revision INTEGER NOT NULL,
                PRIMARY KEY(goal_id, dag_revision)
             );
             CREATE TABLE goal_dag_heads(
                goal_id BLOB PRIMARY KEY,
                dag_revision INTEGER NOT NULL
             );
             CREATE TABLE goal_dag_nodes(
                goal_id BLOB NOT NULL,
                dag_revision INTEGER NOT NULL,
                node_id BLOB NOT NULL,
                node_revision INTEGER NOT NULL,
                lifecycle_state INTEGER NOT NULL,
                PRIMARY KEY(goal_id, dag_revision, node_id)
             );",
        )
    }

    fn agent_fixture() -> Result<AgentFixture, Box<dyn std::error::Error>> {
        let connection = Connection::open_in_memory()?;
        create_agent_fixture_schema(&connection)?;
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(100));
        let activity_id = ActivityId::from_uuid(Uuid::from_u128(101));
        let owner = RuntimeInstanceId::from_uuid(Uuid::from_u128(102));
        let agent_id = AgentInstanceId::from_uuid(Uuid::from_u128(103));
        let session_id = AgentSessionId::from_uuid(Uuid::from_u128(106));
        let goal_id = GoalId::from_uuid(Uuid::from_u128(104));
        let node_id = DagNodeId::from_uuid(Uuid::from_u128(105));
        let seed = AgentFixtureSeed {
            workspace_id,
            activity_id,
            owner,
            agent_id,
            session_id,
            goal_id,
            node_id,
        };
        insert_agent_fixture_rows(&connection, &seed)?;
        create_schema(&connection)?;
        crate::workspace_verification::create_schema(&connection)?;
        crate::workspace_goal_deletion::create_schema(&connection)?;
        crate::workspace_semantic_events::create_schema(&connection)?;
        crate::workspace_work_cuts::create_schema(&connection)?;
        crate::workspace_execution_stops::create_schema(&connection)?;
        connection.execute_batch(
            "CREATE TABLE goal_verification_requirements (
                goal_id BLOB NOT NULL REFERENCES goals(goal_id),
                ordinal INTEGER NOT NULL, requirement_kind INTEGER NOT NULL,
                execution_digest BLOB NOT NULL, PRIMARY KEY(goal_id, ordinal)
            );",
        )?;
        Ok(AgentFixture {
            connection,
            workspace_id,
            activity_id,
            owner,
            agent_id,
            goal_id,
            node_id,
        })
    }

    fn insert_agent_fixture_rows(
        connection: &Connection,
        seed: &AgentFixtureSeed,
    ) -> rusqlite::Result<()> {
        connection.execute(
            "INSERT INTO workspace(workspace_id) VALUES (?1)",
            params![seed.workspace_id.into_uuid().as_bytes()],
        )?;
        connection.execute(
            "INSERT INTO activities(
                activity_id, workspace_id, state, lease_owner_id, lease_until_ms
             ) VALUES (?1, ?2, 1, ?3, 1000)",
            params![
                seed.activity_id.into_uuid().as_bytes(),
                seed.workspace_id.into_uuid().as_bytes(),
                seed.owner.into_uuid().as_bytes(),
            ],
        )?;
        connection.execute(
            "INSERT INTO agent_instances(
                agent_id, workspace_id, activity_id, session_id, revision, principal_kind,
                attachment_state, focus_goal_id, focus_goal_revision, focus_dag_revision,
                focus_node_id, focus_node_revision
             ) VALUES (?1, ?2, ?3, ?4, 1, 0, 0, ?5, 1, 1, ?6, 1)",
            params![
                seed.agent_id.into_uuid().as_bytes(),
                seed.workspace_id.into_uuid().as_bytes(),
                seed.activity_id.into_uuid().as_bytes(),
                seed.session_id.into_uuid().as_bytes(),
                seed.goal_id.into_uuid().as_bytes(),
                seed.node_id.into_uuid().as_bytes(),
            ],
        )?;
        connection.execute(
            "INSERT INTO goals(goal_id, workspace_id, activity_id, state, revision)
             VALUES (?1, ?2, ?3, 0, 1)",
            params![
                seed.goal_id.into_uuid().as_bytes(),
                seed.workspace_id.into_uuid().as_bytes(),
                seed.activity_id.into_uuid().as_bytes(),
            ],
        )?;
        connection.execute(
            "INSERT INTO goal_dag_revisions(goal_id, dag_revision) VALUES (?1, 1)",
            params![seed.goal_id.into_uuid().as_bytes()],
        )?;
        connection.execute(
            "INSERT INTO goal_dag_heads(goal_id, dag_revision) VALUES (?1, 1)",
            params![seed.goal_id.into_uuid().as_bytes()],
        )?;
        connection.execute(
            "INSERT INTO goal_dag_nodes(
                goal_id, dag_revision, node_id, node_revision, lifecycle_state
             ) VALUES (?1, 1, ?2, 1, 1)",
            params![
                seed.goal_id.into_uuid().as_bytes(),
                seed.node_id.into_uuid().as_bytes()
            ],
        )?;
        Ok(())
    }

    #[derive(Clone, Copy)]
    struct AgentAuthoritySpec {
        agent_revision: AgentInstanceRevision,
        session_id: AgentSessionId,
        principal: AuthenticatedPrincipal,
        goal_revision: GoalRevision,
        dag_revision: DagRevisionNumber,
        node_revision: DagNodeRevision,
    }

    impl AgentAuthoritySpec {
        const fn valid() -> Self {
            Self {
                agent_revision: AgentInstanceRevision::INITIAL,
                session_id: AgentSessionId::from_uuid(Uuid::from_u128(106)),
                principal: AuthenticatedPrincipal::TrustedStdio,
                goal_revision: GoalRevision::INITIAL,
                dag_revision: DagRevisionNumber::INITIAL,
                node_revision: DagNodeRevision::INITIAL,
            }
        }
    }

    fn agent_provenance(
        fixture: &AgentFixture,
        execution_id: ExecutionId,
        spec: AgentAuthoritySpec,
        command: &str,
    ) -> Result<ExecutionAgentProvenance, Box<dyn std::error::Error>> {
        Ok(ExecutionAgentProvenance::new(
            execution_id,
            fixture.agent_id,
            spec.agent_revision,
            spec.principal,
            GoalNodeAttribution::new(
                fixture.goal_id,
                spec.goal_revision,
                spec.dag_revision,
                fixture.node_id,
                spec.node_revision,
            ),
            ExecutionCommandId::new(command.to_owned())?,
            spec.session_id,
        ))
    }

    fn begin_agent(
        fixture: &mut AgentFixture,
        execution_id: ExecutionId,
        provenance: ExecutionAgentProvenance,
        owner: RuntimeInstanceId,
    ) -> Result<BeginExecutionRecord, ExecutionStoreError> {
        let request = request(
            execution_id.into_uuid().as_u128(),
            fixture.workspace_id,
            fixture.activity_id,
            false,
        )
        .map_err(|_| ExecutionStoreError::IntegerOverflow)?;
        let begin = BeginExecution::from_request(
            &request,
            ExecutionRequestDigest::from_bytes([9; 32]),
            TimestampMillis::new(20).map_err(|_| ExecutionStoreError::TimestampOrder)?,
        )
        .with_runtime_owner(owner)
        .with_provenance(provenance)
        .map_err(|_| ExecutionStoreError::AgentAuthorityConflict)?;
        let transaction = fixture
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let result = begin_execution_in_transaction(&transaction, &begin)?;
        transaction.commit()?;
        Ok(result)
    }

    #[test]
    fn list_executions_qualifies_joined_order_scope_and_limit()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = agent_fixture()?;
        let foreign_activity_id = ActivityId::from_uuid(Uuid::from_u128(0x1F2));
        fixture.connection.execute(
            "INSERT INTO activities(activity_id, workspace_id, state)
             VALUES (?1, ?2, 1)",
            params![
                foreign_activity_id.into_uuid().as_bytes(),
                fixture.workspace_id.into_uuid().as_bytes(),
            ],
        )?;

        let owner = fixture.owner;
        for raw_id in [0xD801_u128, 0xD802, 0xD803] {
            let execution_id = ExecutionId::from_uuid(Uuid::from_u128(raw_id));
            let provenance = agent_provenance(
                &fixture,
                execution_id,
                AgentAuthoritySpec::valid(),
                "list-executions",
            )?;
            let _begun = begin_agent(&mut fixture, execution_id, provenance, owner)?;
        }

        let foreign_execution_id = ExecutionId::from_uuid(Uuid::from_u128(0xD804));
        let foreign_request = request(
            foreign_execution_id.into_uuid().as_u128(),
            fixture.workspace_id,
            foreign_activity_id,
            false,
        )?;
        let _foreign_begun = begin_execution(
            &mut fixture.connection,
            &BeginExecution::from_request(
                &foreign_request,
                ExecutionRequestDigest::from_bytes([0xD8; 32]),
                TimestampMillis::new(20)?,
            ),
        )?;

        let records = list_executions(
            &fixture.connection,
            fixture.activity_id,
            ExecutionListLimit::new(2)?,
        )?;
        assert_eq!(records.len(), 2);
        assert_eq!(
            records[0].id(),
            ExecutionId::from_uuid(Uuid::from_u128(0xD803))
        );
        assert_eq!(
            records[1].id(),
            ExecutionId::from_uuid(Uuid::from_u128(0xD802))
        );
        for record in records {
            assert_eq!(record.workspace_id(), fixture.workspace_id);
            assert_eq!(record.activity_id(), fixture.activity_id);
            let provenance = record.provenance().ok_or("joined provenance missing")?;
            assert_eq!(provenance.execution_id(), record.id());
            assert_eq!(provenance.agent_id(), fixture.agent_id);
        }
        Ok(())
    }

    fn install_output_commit_failure_guard(
        connection: &Connection,
    ) -> Result<(), Box<dyn std::error::Error>> {
        connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TEMP TABLE execution_commit_guard_parent (
                 id INTEGER PRIMARY KEY
             );
             CREATE TEMP TABLE execution_commit_guard_child (
                 parent_id INTEGER REFERENCES execution_commit_guard_parent(id)
                     DEFERRABLE INITIALLY DEFERRED
             );
             CREATE TEMP TRIGGER execution_commit_guard
             AFTER INSERT ON execution_output_events
             BEGIN
                 INSERT INTO execution_commit_guard_child(parent_id) VALUES (99);
             END;",
        )?;
        Ok(())
    }

    #[test]
    fn output_commit_failure_preserves_unknown_outcome() -> Result<(), Box<dyn std::error::Error>> {
        let (mut connection, execution_id, first, _, _) = output_fixture(0xE900)?;
        install_output_commit_failure_guard(&connection)?;
        let outcome = append_output_events(&mut connection, std::slice::from_ref(&first));
        assert!(matches!(
            outcome,
            Err(ExecutionStoreError::CommittedUnconfirmed { source })
                if matches!(source.as_ref(), ExecutionStoreError::Sqlite(_))
        ));
        let count: i64 = connection.query_row(
            "SELECT COUNT(*) FROM execution_output_events WHERE execution_id = ?1",
            params![execution_id.into_uuid().as_bytes()],
            |row| row.get(0),
        )?;
        assert_eq!(count, 0);
        Ok(())
    }

    fn begin_verified(
        fixture: &mut AgentFixture,
        execution_id: ExecutionId,
    ) -> Result<(BeginExecution, forge_domain::VerificationInputEvidence), Box<dyn std::error::Error>>
    {
        use crate::workspace_verification;
        use forge_domain::{
            VerificationInputEvidence, VerificationInputFingerprint, VerificationInputId,
            VerificationInputPolicy,
        };

        fixture.connection.execute(
            "INSERT INTO goal_verification_requirements (goal_id, ordinal, requirement_kind, execution_digest)
             VALUES (?1, 0, 0, ?2)",
            params![fixture.goal_id.into_uuid().as_bytes(), &[9_u8; 32]],
        )?;
        let provenance = agent_provenance(
            fixture,
            execution_id,
            AgentAuthoritySpec::valid(),
            "make:ci",
        )?
        .with_project_command(ProjectCommandEvidence::new(
            ProjectCommandClass::Verify,
            ProjectCommandCatalogFingerprint::from_hash(FileContentHash::from_bytes([0x31; 32])),
        ));
        let request = request(
            execution_id.into_uuid().as_u128(),
            fixture.workspace_id,
            fixture.activity_id,
            false,
        )?;
        let begin = BeginExecution::from_request(
            &request,
            ExecutionRequestDigest::from_bytes([9; 32]),
            TimestampMillis::new(20)?,
        )
        .with_runtime_owner(fixture.owner)
        .with_provenance(provenance)?;
        let input = VerificationInputEvidence::from_parts(
            VerificationInputId::from_uuid(execution_id.into_uuid()),
            VerificationInputFingerprint::from_bytes([0x41; 32]),
            VerificationInputPolicy::V1,
            1,
            FileByteCount::new(4),
        )?;
        let transaction = fixture
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let started = begin_execution_in_transaction(&transaction, &begin)?;
        let proof = workspace_verification::begin_or_replay_in_transaction(
            &transaction,
            &begin,
            input,
            started.status(),
        )?;
        assert_eq!(proof.status(), BeginExecutionStatus::Created);
        assert!(!proof.run().state().is_terminal());
        assert_eq!(proof.requirements().len(), 1);
        transaction.commit()?;
        Ok((begin, input))
    }

    #[derive(Debug, Clone, Copy)]
    enum VerificationOutputCase {
        Exact,
        Gap,
        Truncated,
        Failed,
        Cancelled,
        TimedOut,
        Missing,
        Changed,
        OutOfOrder,
    }

    impl VerificationOutputCase {
        fn events(
            self,
            id: ExecutionId,
        ) -> Result<Vec<ExecutionOutputEvent>, Box<dyn std::error::Error>> {
            if matches!(self, Self::Missing) {
                return Ok(Vec::new());
            }
            if matches!(self, Self::Gap) {
                return Ok(vec![ExecutionOutputEvent::Gap(
                    forge_domain::ExecutionOutputGap::new(
                        id,
                        ExecutionOutputSequence::new(2)?,
                        forge_domain::ExecutionOutputGapParts::new(
                            ExecutionOutputSequence::new(1)?,
                            ExecutionOutputSequence::new(1)?,
                            Some(ExecutionOutputStream::Stdout),
                            4,
                            1,
                            forge_domain::ExecutionOutputGapCause::Backpressure,
                        ),
                    )?,
                )]);
            }
            let bytes = if matches!(self, Self::Changed) {
                b"fail"
            } else {
                b"pass"
            };
            let sequence = if matches!(self, Self::OutOfOrder) {
                2
            } else {
                1
            };
            Ok(vec![ExecutionOutputEvent::Chunk(
                forge_domain::ExecutionOutputChunk::new(
                    id,
                    ExecutionOutputSequence::new(sequence)?,
                    ExecutionOutputStream::Stdout,
                    bytes,
                )?,
            )])
        }

        fn outcome(self, id: ExecutionId) -> ExecutionOutcome {
            let (completion, exit_code) = match self {
                Self::Failed => (ExecutionCompletionStatus::Exited, Some(1)),
                Self::Cancelled => (ExecutionCompletionStatus::Cancelled, None),
                Self::TimedOut => (ExecutionCompletionStatus::TimedOut, None),
                _ => (ExecutionCompletionStatus::Exited, Some(0)),
            };
            let truncated = matches!(self, Self::Truncated);
            ExecutionOutcome::new(
                id,
                ExecutionTermination::new(completion, exit_code, None),
                1,
                BoundedExecutionOutput::new(
                    b"pass".to_vec(),
                    if truncated { 8 } else { 4 },
                    truncated,
                ),
                BoundedExecutionOutput::new(Vec::new(), 0, false),
            )
        }

        fn disposition(self) -> forge_domain::VerificationRunDisposition {
            use forge_domain::VerificationRunDisposition as Disposition;
            match self {
                Self::Exact => Disposition::Accepted,
                Self::Gap | Self::Truncated => Disposition::Incomplete,
                Self::Failed | Self::Cancelled | Self::TimedOut => Disposition::Rejected,
                Self::Missing | Self::Changed | Self::OutOfOrder => Disposition::RecoveryRequired,
            }
        }
    }

    #[test]
    fn effect_fact_append_failure_rolls_back_execution_and_verification_terminalization()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::workspace_verification;

        let mut fixture = agent_fixture()?;
        let id = ExecutionId::from_uuid(Uuid::from_u128(0xD7F1));
        let (_begin, _input) = begin_verified(&mut fixture, id)?;
        let running = mark_execution_running(
            &mut fixture.connection,
            MarkExecutionRunning::new(id, ExecutionRevision::INITIAL, TimestampMillis::new(21)?),
        )?;
        let events = VerificationOutputCase::Exact.events(id)?;
        append_output_events(&mut fixture.connection, &events)?;

        // Pretend this intentionally partial execution fixture is a current
        // Workspace without installing the delegation/outbox schemas. The
        // terminal transaction must fail closed and roll back all terminal
        // state rather than committing execution/verification without a fact.
        fixture
            .connection
            .pragma_update(None, "user_version", 40_i64)?;
        let Err(error) = complete_execution(
            &mut fixture.connection,
            &CompleteExecution::new(
                running.revision(),
                TimestampMillis::new(22)?,
                VerificationOutputCase::Exact.outcome(id),
            ),
        ) else {
            return Err(std::io::Error::other(
                "missing current-schema effect-fact authority unexpectedly succeeded",
            )
            .into());
        };
        assert!(matches!(error, ExecutionStoreError::EffectFactOutbox(_)));

        let persisted = get_execution(&fixture.connection, id)?.ok_or("execution disappeared")?;
        assert_eq!(persisted.state(), ExecutionState::Running);
        assert_eq!(persisted.revision(), running.revision());
        let proof = workspace_verification::get_verification_run(&fixture.connection, id)?
            .ok_or("verification run disappeared")?;
        assert_eq!(proof.state(), forge_domain::VerificationRunState::Starting);
        assert!(proof.terminal_status().is_none());
        Ok(())
    }

    #[test]
    fn verification_terminalization_requires_complete_durable_output()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::workspace_verification;
        for case in [
            VerificationOutputCase::Exact,
            VerificationOutputCase::Gap,
            VerificationOutputCase::Truncated,
            VerificationOutputCase::Failed,
            VerificationOutputCase::Cancelled,
            VerificationOutputCase::TimedOut,
            VerificationOutputCase::Missing,
            VerificationOutputCase::Changed,
            VerificationOutputCase::OutOfOrder,
        ] {
            let mut fixture = agent_fixture()?;
            let id = ExecutionId::from_uuid(Uuid::from_u128(0xD701));
            let (_begin, _input) = begin_verified(&mut fixture, id)?;
            let running = mark_execution_running(
                &mut fixture.connection,
                MarkExecutionRunning::new(
                    id,
                    ExecutionRevision::INITIAL,
                    TimestampMillis::new(21)?,
                ),
            )?;
            let events = case.events(id)?;
            append_output_events(&mut fixture.connection, &events)?;
            let terminal = complete_execution(
                &mut fixture.connection,
                &CompleteExecution::new(
                    running.revision(),
                    TimestampMillis::new(22)?,
                    case.outcome(id),
                ),
            )?;
            let proof = workspace_verification::get_verification_run(&fixture.connection, id)?
                .ok_or("missing run")?;
            let status = proof.terminal_status().ok_or("missing terminal status")?;
            assert_eq!(status.disposition(), case.disposition(), "{case:?}");
            if matches!(case, VerificationOutputCase::Exact) {
                assert_eq!(
                    status.output_integrity(),
                    Some(forge_domain::VerificationOutputIntegrity::Complete)
                );
            }
            append_output_events(&mut fixture.connection, &events)?;
            let late = ExecutionOutputEvent::Chunk(forge_domain::ExecutionOutputChunk::new(
                id,
                ExecutionOutputSequence::new(3)?,
                ExecutionOutputStream::Stdout,
                b"late",
            )?);
            assert!(matches!(
                append_output_events(&mut fixture.connection, &[late]),
                Err(ExecutionStoreError::Terminal)
            ));
            let transaction = fixture
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            workspace_verification::finalize_in_transaction(&transaction, &terminal)?;
            let revision: i64 = transaction.query_row(
                "SELECT revision FROM verification_runs WHERE execution_id = ?1",
                params![id.into_uuid().as_bytes()],
                |row| row.get(0),
            )?;
            assert_eq!(revision, 2);
            transaction.commit()?;
        }
        Ok(())
    }

    #[test]
    fn verification_begin_replay_conflicts_and_recovery_preserve_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::workspace_verification;
        use forge_domain::{
            VerificationInputEvidence, VerificationInputFingerprint, VerificationInputPolicy,
            VerificationRunDisposition,
        };
        for expired in [false, true] {
            let mut fixture = agent_fixture()?;
            let id = ExecutionId::from_uuid(Uuid::from_u128(0xD702));
            let (begin, input) = begin_verified(&mut fixture, id)?;
            let transaction = fixture
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let replay = begin_execution_in_transaction(&transaction, &begin)?;
            let proof = workspace_verification::begin_or_replay_in_transaction(
                &transaction,
                &begin,
                input,
                replay.status(),
            )?;
            assert_eq!(proof.status(), BeginExecutionStatus::Existing);
            let other = VerificationInputEvidence::from_parts(
                input.id(),
                VerificationInputFingerprint::from_bytes([0x42; 32]),
                VerificationInputPolicy::V1,
                1,
                FileByteCount::new(4),
            )?;
            assert!(matches!(
                workspace_verification::begin_or_replay_in_transaction(
                    &transaction,
                    &begin,
                    other,
                    replay.status()
                ),
                Err(workspace_verification::VerificationStoreError::IdentityConflict)
            ));
            transaction.commit()?;
            let recovered = if expired {
                let _running = mark_execution_running(
                    &mut fixture.connection,
                    MarkExecutionRunning::new(
                        id,
                        ExecutionRevision::INITIAL,
                        TimestampMillis::new(21)?,
                    ),
                )?;
                reconcile_expired_authority_executions(
                    &mut fixture.connection,
                    TimestampMillis::new(1001)?,
                    ExecutionListLimit::new(8)?,
                )?
            } else {
                reconcile_interrupted_executions(
                    &mut fixture.connection,
                    TimestampMillis::new(22)?,
                    ExecutionListLimit::new(8)?,
                )?
            };
            if expired {
                assert!(recovered.is_empty());
                assert_eq!(
                    get_execution(&fixture.connection, id)?.map(|record| record.state()),
                    Some(ExecutionState::Running)
                );
                let run = workspace_verification::get_verification_run(&fixture.connection, id)?
                    .ok_or("missing retained run")?;
                assert!(run.terminal_status().is_none());
                continue;
            }
            assert_eq!(recovered.len(), 1);
            assert_eq!(recovered[0].state(), ExecutionState::Interrupted);
            let run = workspace_verification::get_verification_run(&fixture.connection, id)?
                .ok_or("missing recovered run")?;
            assert_eq!(
                run.terminal_status()
                    .ok_or("missing recovered status")?
                    .disposition(),
                VerificationRunDisposition::RecoveryRequired
            );
            assert_eq!(
                workspace_verification::get_verification_requirement_links(
                    &fixture.connection,
                    id
                )?
                .len(),
                1
            );
        }
        Ok(())
    }

    fn generated_package_evidence() -> ProjectCommandEvidence {
        ProjectCommandEvidence::new(
            ProjectCommandClass::GeneratedPackage,
            ProjectCommandCatalogFingerprint::from_hash(FileContentHash::from_bytes(
                [0x31; FileContentHash::BYTE_LEN],
            )),
        )
    }

    fn successful_outcome(execution_id: ExecutionId) -> ExecutionOutcome {
        ExecutionOutcome::new(
            execution_id,
            ExecutionTermination::new(ExecutionCompletionStatus::Exited, Some(0), None),
            1,
            BoundedExecutionOutput::new(Vec::new(), 0, false),
            BoundedExecutionOutput::new(Vec::new(), 0, false),
        )
    }

    #[test]
    fn generated_package_manifest_commits_with_successful_terminal_execution()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = agent_fixture()?;
        let execution_id = ExecutionId::from_uuid(Uuid::from_u128(0xC701));
        let provenance = agent_provenance(
            &fixture,
            execution_id,
            AgentAuthoritySpec::valid(),
            "make:package",
        )?
        .with_project_command(generated_package_evidence());
        let owner = fixture.owner;
        let started = begin_agent(&mut fixture, execution_id, provenance, owner)?;
        let running = mark_execution_running(
            &mut fixture.connection,
            MarkExecutionRunning::new(
                execution_id,
                started.record().revision(),
                TimestampMillis::new(21)?,
            ),
        )?;
        let manifest = GeneratedPackageManifest::new(
            fixture.workspace_id,
            execution_id,
            FileContentHash::from_bytes([0x71; FileContentHash::BYTE_LEN]),
            FileByteCount::new(42),
        );
        let completed = complete_execution_with_generated_package(
            &mut fixture.connection,
            &CompleteExecution::new(
                running.revision(),
                TimestampMillis::new(22)?,
                successful_outcome(execution_id),
            ),
            manifest,
        )?;
        assert_eq!(completed.state(), ExecutionState::Completed);
        let snapshot = get_execution_authorized_with_generated_package(
            &fixture.connection,
            fixture.workspace_id,
            completed.activity_id(),
            execution_id,
            completed
                .provenance()
                .ok_or("missing completed provenance")?,
        )?;
        assert_eq!(snapshot.record(), &completed);
        assert_eq!(snapshot.generated_package(), Some(manifest));
        let wrong = agent_provenance(
            &fixture,
            execution_id,
            AgentAuthoritySpec::valid(),
            "wrong-command",
        )?;
        assert!(matches!(
            get_execution_authorized_with_generated_package(
                &fixture.connection,
                fixture.workspace_id,
                completed.activity_id(),
                execution_id,
                &wrong,
            ),
            Err(ExecutionStoreError::AgentAuthorityConflict),
        ));
        assert_eq!(
            get_generated_package_manifest(&fixture.connection, execution_id)?,
            Some(manifest)
        );
        assert_eq!(
            list_generated_package_manifests(
                &fixture.connection,
                fixture.workspace_id,
                ExecutionListLimit::new(8)?,
            )?,
            vec![manifest]
        );
        Ok(())
    }

    #[test]
    fn generated_package_manifest_mismatch_rolls_back_terminal_completion()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = agent_fixture()?;
        let execution_id = ExecutionId::from_uuid(Uuid::from_u128(0xC702));
        let provenance = agent_provenance(
            &fixture,
            execution_id,
            AgentAuthoritySpec::valid(),
            "make:package",
        )?
        .with_project_command(generated_package_evidence());
        let owner = fixture.owner;
        let started = begin_agent(&mut fixture, execution_id, provenance, owner)?;
        let running = mark_execution_running(
            &mut fixture.connection,
            MarkExecutionRunning::new(
                execution_id,
                started.record().revision(),
                TimestampMillis::new(21)?,
            ),
        )?;
        let wrong_workspace = WorkspaceId::from_uuid(Uuid::from_u128(0xC703));
        let result = complete_execution_with_generated_package(
            &mut fixture.connection,
            &CompleteExecution::new(
                running.revision(),
                TimestampMillis::new(22)?,
                successful_outcome(execution_id),
            ),
            GeneratedPackageManifest::new(
                wrong_workspace,
                execution_id,
                FileContentHash::from_bytes([0x72; FileContentHash::BYTE_LEN]),
                FileByteCount::new(42),
            ),
        );
        assert!(matches!(
            result,
            Err(ExecutionStoreError::GeneratedArtifactConflict)
        ));
        assert_eq!(
            get_execution(&fixture.connection, execution_id)?.map(|record| record.state()),
            Some(ExecutionState::Running)
        );
        assert_eq!(
            get_generated_package_manifest(&fixture.connection, execution_id)?,
            None
        );
        Ok(())
    }

    #[test]
    fn generated_manifest_listing_rejects_non_generated_execution_evidence()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = agent_fixture()?;
        let execution_id = ExecutionId::from_uuid(Uuid::from_u128(0xC704));
        let request = request(
            execution_id.into_uuid().as_u128(),
            fixture.workspace_id,
            fixture.activity_id,
            false,
        )?;
        let begin = BeginExecution::from_request(
            &request,
            ExecutionRequestDigest::from_bytes([0xA4; 32]),
            TimestampMillis::new(20)?,
        );
        let transaction = fixture
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let _begun = begin_execution_in_transaction(&transaction, &begin)?;
        transaction.commit()?;
        fixture.connection.execute(
            "INSERT INTO execution_generated_artifacts(
                execution_id, workspace_id, artifact_kind, content_hash, byte_count
             ) VALUES (?1, ?2, 0, ?3, 1)",
            params![
                execution_id.into_uuid().as_bytes(),
                fixture.workspace_id.into_uuid().as_bytes(),
                [0xA5_u8; FileContentHash::BYTE_LEN],
            ],
        )?;
        assert!(matches!(
            list_generated_package_manifests(
                &fixture.connection,
                fixture.workspace_id,
                ExecutionListLimit::new(8)?,
            ),
            Err(ExecutionStoreError::CorruptRecord(
                "execution_generated_artifacts.command_evidence"
            ))
        ));
        Ok(())
    }

    #[derive(Debug, Clone, Copy)]
    enum AgentAuthorityCase {
        Principal,
        Session,
        SessionUnresolved,
        AgentRevision,
        Detached,
        GoalRevision,
        DagHead,
        NodeRevision,
        NodeLifecycle,
        ActivityOwner,
        ActivityExpiry,
        ActivityClosed,
    }

    fn reject_agent_case(case: AgentAuthorityCase) -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = agent_fixture()?;
        let execution_id = ExecutionId::from_uuid(Uuid::from_u128(200 + case as u128));
        let (spec, owner) = agent_case_setup(&mut fixture, case)?;
        let provenance = agent_provenance(&fixture, execution_id, spec, "make:ci")?;
        let result = begin_agent(&mut fixture, execution_id, provenance, owner);
        assert!(
            matches!(
                result,
                Err(ExecutionStoreError::AgentAuthorityConflict
                    | ExecutionStoreError::ActivityTerminal)
            ),
            "unexpected result for {case:?}: {result:?}"
        );
        let count: i64 =
            fixture
                .connection
                .query_row("SELECT COUNT(*) FROM executions", [], |row| row.get(0))?;
        assert_eq!(count, 0);
        Ok(())
    }

    fn agent_case_setup(
        fixture: &mut AgentFixture,
        case: AgentAuthorityCase,
    ) -> Result<(AgentAuthoritySpec, RuntimeInstanceId), Box<dyn std::error::Error>> {
        let mut spec = AgentAuthoritySpec::valid();
        let owner = match case {
            AgentAuthorityCase::Principal => {
                spec.principal = AuthenticatedPrincipal::DirectToken(DirectTokenId::from_uuid(
                    Uuid::from_u128(300),
                ));
                fixture.owner
            }
            AgentAuthorityCase::Session => {
                spec.session_id = AgentSessionId::from_uuid(Uuid::from_u128(301));
                fixture.owner
            }
            AgentAuthorityCase::SessionUnresolved => {
                fixture.connection.execute(
                    "UPDATE agent_instances SET session_id = NULL WHERE agent_id = ?1",
                    params![fixture.agent_id.into_uuid().as_bytes()],
                )?;
                fixture.owner
            }
            AgentAuthorityCase::AgentRevision => {
                spec.agent_revision = AgentInstanceRevision::new(2)?;
                fixture.owner
            }
            AgentAuthorityCase::GoalRevision => {
                spec.goal_revision = GoalRevision::new(2)?;
                fixture.owner
            }
            AgentAuthorityCase::DagHead => {
                fixture.connection.execute(
                    "UPDATE goal_dag_heads SET dag_revision = 2 WHERE goal_id = ?1",
                    params![fixture.goal_id.into_uuid().as_bytes()],
                )?;
                fixture.owner
            }
            AgentAuthorityCase::NodeRevision => {
                fixture.connection.execute(
                    "UPDATE goal_dag_nodes SET node_revision = 2
                     WHERE goal_id = ?1 AND node_id = ?2",
                    params![
                        fixture.goal_id.into_uuid().as_bytes(),
                        fixture.node_id.into_uuid().as_bytes(),
                    ],
                )?;
                fixture.owner
            }
            AgentAuthorityCase::NodeLifecycle => {
                fixture.connection.execute(
                    "UPDATE goal_dag_nodes SET lifecycle_state = 3
                     WHERE goal_id = ?1 AND node_id = ?2",
                    params![
                        fixture.goal_id.into_uuid().as_bytes(),
                        fixture.node_id.into_uuid().as_bytes(),
                    ],
                )?;
                fixture.owner
            }
            AgentAuthorityCase::Detached => {
                fixture.connection.execute(
                    "UPDATE agent_instances SET attachment_state = 1 WHERE agent_id = ?1",
                    params![fixture.agent_id.into_uuid().as_bytes()],
                )?;
                fixture.owner
            }
            AgentAuthorityCase::ActivityOwner => RuntimeInstanceId::from_uuid(Uuid::from_u128(400)),
            AgentAuthorityCase::ActivityExpiry => {
                fixture.connection.execute(
                    "UPDATE activities SET lease_until_ms = 20 WHERE activity_id = ?1",
                    params![fixture.activity_id.into_uuid().as_bytes()],
                )?;
                fixture.owner
            }
            AgentAuthorityCase::ActivityClosed => {
                fixture.connection.execute(
                    "UPDATE activities SET state = 0 WHERE activity_id = ?1",
                    params![fixture.activity_id.into_uuid().as_bytes()],
                )?;
                fixture.owner
            }
        };
        Ok((spec, owner))
    }

    #[test]
    fn agent_admission_is_atomic_and_checks_every_authority_fence()
    -> Result<(), Box<dyn std::error::Error>> {
        for case in [
            AgentAuthorityCase::Principal,
            AgentAuthorityCase::Session,
            AgentAuthorityCase::SessionUnresolved,
            AgentAuthorityCase::AgentRevision,
            AgentAuthorityCase::Detached,
            AgentAuthorityCase::GoalRevision,
            AgentAuthorityCase::DagHead,
            AgentAuthorityCase::NodeRevision,
            AgentAuthorityCase::NodeLifecycle,
            AgentAuthorityCase::ActivityClosed,
        ] {
            reject_agent_case(case)?;
        }
        Ok(())
    }

    #[test]
    fn agent_admission_ignores_activity_heartbeat_owner_and_expiry()
    -> Result<(), Box<dyn std::error::Error>> {
        for case in [
            AgentAuthorityCase::ActivityOwner,
            AgentAuthorityCase::ActivityExpiry,
        ] {
            let mut fixture = agent_fixture()?;
            let execution_id = ExecutionId::from_uuid(Uuid::from_u128(400 + case as u128));
            let (spec, owner) = agent_case_setup(&mut fixture, case)?;
            let provenance = agent_provenance(&fixture, execution_id, spec, "make:ci")?;
            let result = begin_agent(&mut fixture, execution_id, provenance, owner)?;
            assert_eq!(result.status(), BeginExecutionStatus::Created, "{case:?}");
            assert_eq!(
                result.record().state(),
                ExecutionState::Starting,
                "{case:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn exact_agent_retry_returns_existing_active_record_and_rejects_detached_agent()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = agent_fixture()?;
        let execution_id = ExecutionId::from_uuid(Uuid::from_u128(500));
        let provenance = agent_provenance(
            &fixture,
            execution_id,
            AgentAuthoritySpec::valid(),
            "make:ci",
        )?;
        let owner = fixture.owner;
        let started = begin_agent(&mut fixture, execution_id, provenance.clone(), owner)?;
        assert_eq!(started.status(), BeginExecutionStatus::Created);
        let retry = begin_agent(&mut fixture, execution_id, provenance.clone(), owner)?;
        assert_eq!(retry.status(), BeginExecutionStatus::Existing);
        assert_eq!(retry.record().provenance(), Some(&provenance));
        let running = mark_execution_running(
            &mut fixture.connection,
            MarkExecutionRunning::new(
                execution_id,
                started.record().revision(),
                TimestampMillis::new(21)?,
            ),
        )?;
        let outcome = ExecutionOutcome::new(
            execution_id,
            ExecutionTermination::new(ExecutionCompletionStatus::Exited, Some(0), None),
            1,
            BoundedExecutionOutput::new(Vec::new(), 0, false),
            BoundedExecutionOutput::new(Vec::new(), 0, false),
        );
        let _terminal = complete_execution(
            &mut fixture.connection,
            &CompleteExecution::new(running.revision(), TimestampMillis::new(22)?, outcome),
        )?;
        fixture.connection.execute(
            "UPDATE agent_instances SET attachment_state = 1 WHERE agent_id = ?1",
            params![fixture.agent_id.into_uuid().as_bytes()],
        )?;
        assert!(matches!(
            begin_agent(&mut fixture, execution_id, provenance, owner),
            Err(ExecutionStoreError::AgentAuthorityConflict)
        ));

        let mismatch = agent_provenance(
            &fixture,
            execution_id,
            AgentAuthoritySpec::valid(),
            "make:test",
        )?;
        assert!(matches!(
            begin_agent(&mut fixture, execution_id, mismatch, owner),
            Err(ExecutionStoreError::IdentityConflict)
        ));
        Ok(())
    }

    #[test]
    fn historical_provenance_without_session_stays_unresolved_and_unusable()
    -> Result<(), Box<dyn std::error::Error>> {
        let (fixture, execution_id, _) = authorized_fixture(630)?;
        fixture.connection.execute(
            "UPDATE execution_provenance SET session_id = NULL WHERE execution_id = ?1",
            params![execution_id.into_uuid().as_bytes()],
        )?;

        let record = get_execution(&fixture.connection, execution_id)?
            .ok_or("execution must remain after legacy session migration")?;
        let historical = record
            .provenance()
            .ok_or("historical provenance must remain after migration")?;
        assert_eq!(historical.session_id(), None);
        assert!(matches!(
            get_execution_authorized(
                &fixture.connection,
                fixture.workspace_id,
                fixture.activity_id,
                execution_id,
                historical,
            ),
            Err(ExecutionStoreError::AgentAuthorityConflict)
        ));
        Ok(())
    }

    #[test]
    fn authorized_execution_read_checks_one_snapshot_without_current_goal_state()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = agent_fixture()?;
        let execution_id = ExecutionId::from_uuid(Uuid::from_u128(600));
        let provenance = agent_provenance(
            &fixture,
            execution_id,
            AgentAuthoritySpec::valid(),
            "make:ci",
        )?;
        let owner = fixture.owner;
        let started = begin_agent(&mut fixture, execution_id, provenance.clone(), owner)?;
        let authorized = get_execution_authorized(
            &fixture.connection,
            fixture.workspace_id,
            fixture.activity_id,
            execution_id,
            &provenance,
        )?;
        assert_eq!(authorized, started.record().clone());

        let running = mark_execution_running(
            &mut fixture.connection,
            MarkExecutionRunning::new(
                execution_id,
                started.record().revision(),
                TimestampMillis::new(21)?,
            ),
        )?;
        let terminal = complete_execution(
            &mut fixture.connection,
            &CompleteExecution::new(
                running.revision(),
                TimestampMillis::new(22)?,
                ExecutionOutcome::new(
                    execution_id,
                    ExecutionTermination::new(ExecutionCompletionStatus::Exited, Some(0), None),
                    1,
                    BoundedExecutionOutput::new(Vec::new(), 0, false),
                    BoundedExecutionOutput::new(Vec::new(), 0, false),
                ),
            ),
        )?;
        fixture.connection.execute(
            "UPDATE goal_dag_nodes SET lifecycle_state = 3
             WHERE goal_id = ?1 AND node_id = ?2",
            params![
                fixture.goal_id.into_uuid().as_bytes(),
                fixture.node_id.into_uuid().as_bytes(),
            ],
        )?;
        let terminal_authorized = get_execution_authorized(
            &fixture.connection,
            fixture.workspace_id,
            fixture.activity_id,
            execution_id,
            &provenance,
        )?;
        assert_eq!(terminal_authorized, terminal);
        Ok(())
    }

    fn authorized_fixture(
        seed: u128,
    ) -> Result<(AgentFixture, ExecutionId, ExecutionAgentProvenance), Box<dyn std::error::Error>>
    {
        let mut fixture = agent_fixture()?;
        let execution_id = ExecutionId::from_uuid(Uuid::from_u128(seed));
        let provenance = agent_provenance(
            &fixture,
            execution_id,
            AgentAuthoritySpec::valid(),
            "make:ci",
        )?;
        let owner = fixture.owner;
        let _started = begin_agent(&mut fixture, execution_id, provenance.clone(), owner)?;
        Ok((fixture, execution_id, provenance))
    }

    fn assert_authorized_rejected(
        connection: &Connection,
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        execution_id: ExecutionId,
        provenance: &ExecutionAgentProvenance,
    ) {
        assert!(matches!(
            get_execution_authorized(
                connection,
                workspace_id,
                activity_id,
                execution_id,
                provenance,
            ),
            Err(ExecutionStoreError::AgentAuthorityConflict)
        ));
    }

    #[test]
    fn authorized_execution_read_rejects_provenance_drift() -> Result<(), Box<dyn std::error::Error>>
    {
        let (fixture, execution_id, valid) = authorized_fixture(610)?;
        let mut wrong_principal = AgentAuthoritySpec::valid();
        wrong_principal.principal =
            AuthenticatedPrincipal::DirectToken(DirectTokenId::from_uuid(Uuid::from_u128(611)));
        assert_authorized_rejected(
            &fixture.connection,
            fixture.workspace_id,
            fixture.activity_id,
            execution_id,
            &agent_provenance(&fixture, execution_id, wrong_principal, "make:ci")?,
        );

        let mut wrong_revision = AgentAuthoritySpec::valid();
        wrong_revision.agent_revision = AgentInstanceRevision::new(2)?;
        assert_authorized_rejected(
            &fixture.connection,
            fixture.workspace_id,
            fixture.activity_id,
            execution_id,
            &agent_provenance(&fixture, execution_id, wrong_revision, "make:ci")?,
        );

        let mut wrong_focus = AgentAuthoritySpec::valid();
        wrong_focus.node_revision = DagNodeRevision::new(2)?;
        assert_authorized_rejected(
            &fixture.connection,
            fixture.workspace_id,
            fixture.activity_id,
            execution_id,
            &agent_provenance(&fixture, execution_id, wrong_focus, "make:ci")?,
        );
        assert_authorized_rejected(
            &fixture.connection,
            fixture.workspace_id,
            fixture.activity_id,
            execution_id,
            &agent_provenance(
                &fixture,
                execution_id,
                AgentAuthoritySpec::valid(),
                "make:other",
            )?,
        );
        assert_authorized_rejected(
            &fixture.connection,
            fixture.workspace_id,
            fixture.activity_id,
            ExecutionId::from_uuid(Uuid::from_u128(999)),
            &valid,
        );
        assert_authorized_rejected(
            &fixture.connection,
            WorkspaceId::from_uuid(Uuid::from_u128(998)),
            fixture.activity_id,
            execution_id,
            &valid,
        );
        assert_authorized_rejected(
            &fixture.connection,
            fixture.workspace_id,
            ActivityId::from_uuid(Uuid::from_u128(997)),
            execution_id,
            &valid,
        );
        Ok(())
    }

    #[test]
    fn authorized_execution_read_rejects_current_agent_drift()
    -> Result<(), Box<dyn std::error::Error>> {
        let (fixture, execution_id, valid) = authorized_fixture(620)?;
        let authorized = get_execution_authorized(
            &fixture.connection,
            fixture.workspace_id,
            fixture.activity_id,
            execution_id,
            &valid,
        )?;
        assert_eq!(authorized.provenance(), Some(&valid));
        fixture.connection.execute(
            "UPDATE agent_instances SET revision = 2 WHERE agent_id = ?1",
            params![fixture.agent_id.into_uuid().as_bytes()],
        )?;
        assert_authorized_rejected(
            &fixture.connection,
            fixture.workspace_id,
            fixture.activity_id,
            execution_id,
            &valid,
        );

        fixture.connection.execute(
            "UPDATE agent_instances SET revision = 1, attachment_state = 1
             WHERE agent_id = ?1",
            params![fixture.agent_id.into_uuid().as_bytes()],
        )?;
        assert_authorized_rejected(
            &fixture.connection,
            fixture.workspace_id,
            fixture.activity_id,
            execution_id,
            &valid,
        );

        fixture.connection.execute(
            "UPDATE agent_instances SET attachment_state = 0, principal_kind = 1,
                    principal_id = ?2
             WHERE agent_id = ?1",
            params![
                fixture.agent_id.into_uuid().as_bytes(),
                Uuid::from_u128(621).as_bytes(),
            ],
        )?;
        assert_authorized_rejected(
            &fixture.connection,
            fixture.workspace_id,
            fixture.activity_id,
            execution_id,
            &valid,
        );

        fixture.connection.execute(
            "UPDATE agent_instances SET principal_kind = 0, principal_id = NULL,
                    focus_node_revision = 2
             WHERE agent_id = ?1",
            params![fixture.agent_id.into_uuid().as_bytes()],
        )?;
        assert_authorized_rejected(
            &fixture.connection,
            fixture.workspace_id,
            fixture.activity_id,
            execution_id,
            &valid,
        );
        Ok(())
    }

    #[test]
    fn authorized_output_read_checks_provenance_and_cursor_in_one_snapshot()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut fixture, execution_id, valid) = authorized_fixture(630)?;
        let event = ExecutionOutputEvent::Chunk(ExecutionOutputChunk::new(
            execution_id,
            ExecutionOutputSequence::new(1)?,
            ExecutionOutputStream::Stdout,
            b"authorized",
        )?);
        append_output_events(&mut fixture.connection, std::slice::from_ref(&event))?;
        let read = read_output_events_authorized(
            &fixture.connection,
            fixture.activity_id,
            execution_id,
            &valid,
            ExecutionOutputCursor::initial(execution_id),
            MIN_EXECUTION_OUTPUT_READ_BYTES,
            1,
        )?;
        assert_eq!(read.events(), std::slice::from_ref(&event));

        let mut wrong_principal = AgentAuthoritySpec::valid();
        wrong_principal.principal =
            AuthenticatedPrincipal::DirectToken(DirectTokenId::from_uuid(Uuid::from_u128(631)));
        let wrong = agent_provenance(&fixture, execution_id, wrong_principal, "make:ci")?;
        assert!(matches!(
            read_output_events_authorized(
                &fixture.connection,
                fixture.activity_id,
                execution_id,
                &wrong,
                ExecutionOutputCursor::initial(execution_id),
                MIN_EXECUTION_OUTPUT_READ_BYTES,
                1,
            ),
            Err(ExecutionStoreError::AgentAuthorityConflict)
        ));
        assert!(matches!(
            read_output_events_authorized(
                &fixture.connection,
                fixture.activity_id,
                execution_id,
                &valid,
                ExecutionOutputCursor::initial(ExecutionId::from_uuid(Uuid::from_u128(999))),
                MIN_EXECUTION_OUTPUT_READ_BYTES,
                1,
            ),
            Err(ExecutionStoreError::InvalidOutputCursor)
        ));
        Ok(())
    }

    #[test]
    fn authorized_execution_read_returns_record_and_output_from_one_snapshot()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut fixture, execution_id, valid) = authorized_fixture(640)?;
        let event = ExecutionOutputEvent::Chunk(ExecutionOutputChunk::new(
            execution_id,
            ExecutionOutputSequence::new(1)?,
            ExecutionOutputStream::Stdout,
            b"snapshot",
        )?);
        append_output_events(&mut fixture.connection, std::slice::from_ref(&event))?;

        let snapshot = read_execution_authorized(
            &fixture.connection,
            fixture.workspace_id,
            fixture.activity_id,
            &valid,
            ExecutionOutputCursor::initial(execution_id),
            MIN_EXECUTION_OUTPUT_READ_BYTES,
            1,
        )?;
        assert_eq!(snapshot.record().id(), execution_id);
        assert_eq!(snapshot.record().revision().get(), 1);
        assert_eq!(snapshot.output().events(), std::slice::from_ref(&event));
        assert_eq!(snapshot.output().terminal_state(), None);
        let (record, output) = snapshot.into_parts();
        assert_eq!(record.id(), execution_id);
        assert_eq!(output.events(), std::slice::from_ref(&event));

        let mut wrong_principal = AgentAuthoritySpec::valid();
        wrong_principal.principal =
            AuthenticatedPrincipal::DirectToken(DirectTokenId::from_uuid(Uuid::from_u128(641)));
        let wrong = agent_provenance(&fixture, execution_id, wrong_principal, "make:ci")?;
        assert!(matches!(
            read_execution_authorized(
                &fixture.connection,
                fixture.workspace_id,
                fixture.activity_id,
                &wrong,
                ExecutionOutputCursor::initial(execution_id),
                MIN_EXECUTION_OUTPUT_READ_BYTES,
                1,
            ),
            Err(ExecutionStoreError::AgentAuthorityConflict)
        ));
        assert!(matches!(
            read_execution_authorized(
                &fixture.connection,
                fixture.workspace_id,
                fixture.activity_id,
                &valid,
                ExecutionOutputCursor::initial(ExecutionId::from_uuid(Uuid::from_u128(999))),
                MIN_EXECUTION_OUTPUT_READ_BYTES,
                1,
            ),
            Err(ExecutionStoreError::InvalidOutputCursor)
        ));
        Ok(())
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
            (
                "table",
                "execution_provenance",
                EXPECTED_EXECUTION_PROVENANCE_TABLE_SQL,
            ),
            (
                "table",
                "execution_output_events",
                EXPECTED_EXECUTION_OUTPUT_EVENTS_TABLE_SQL,
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

    fn install_v30_output_schema(connection: &Connection) -> rusqlite::Result<()> {
        connection.execute("DROP TABLE execution_output_events", [])?;
        connection.execute_batch(EXPECTED_EXECUTION_OUTPUT_EVENTS_TABLE_SQL_V30)
    }

    #[test]
    fn v30_relaxed_gap_schema_is_rejected_by_current_validation()
    -> Result<(), Box<dyn std::error::Error>> {
        let (connection, _, _) = fixture()?;
        install_v30_output_schema(&connection)?;

        validate_schema_v30(&connection)?;
        assert!(matches!(
            validate_schema(&connection),
            Err(ExecutionStoreError::CorruptRecord(
                "execution_output_events"
            ))
        ));
        Ok(())
    }

    #[test]
    fn v30_output_events_migrate_to_exact_current_schema() -> Result<(), Box<dyn std::error::Error>>
    {
        let (mut connection, execution_id, _, _, _) = output_fixture(70)?;
        install_v30_output_schema(&connection)?;
        connection.execute(
            "INSERT INTO execution_output_events (
                execution_id, sequence, event_kind, stream, bytes,
                first_missing, last_missing, omitted_bytes, omitted_chunks, gap_cause
             ) VALUES (?1, 1, 0, 0, ?2, NULL, NULL, NULL, NULL, NULL),
                      (?1, 2, 1, NULL, NULL, 1, 1, 5, 1, 1)",
            params![execution_id.into_uuid().as_bytes(), b"chunk".as_slice()],
        )?;
        validate_schema_v30(&connection)?;

        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        migrate_output_events_to_v31(&transaction)?;
        transaction.commit()?;

        validate_schema(&connection)?;
        let actual_sql: String = connection.query_row(
            "SELECT sql FROM sqlite_schema
             WHERE type = 'table' AND name = 'execution_output_events'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(
            normalized_sql(&actual_sql),
            normalized_sql(EXPECTED_EXECUTION_OUTPUT_EVENTS_TABLE_SQL)
        );
        let row_count: i64 = connection.query_row(
            "SELECT COUNT(*) FROM execution_output_events WHERE execution_id = ?1",
            params![execution_id.into_uuid().as_bytes()],
            |row| row.get(0),
        )?;
        assert_eq!(row_count, 2);
        let legacy_table: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_schema
                 WHERE type = 'table' AND name = 'execution_output_events_v30'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        assert!(legacy_table.is_none());
        let foreign_key_target: String = connection.query_row(
            "PRAGMA foreign_key_list(execution_output_events)",
            [],
            |row| row.get(2),
        )?;
        assert_eq!(foreign_key_target, "executions");
        Ok(())
    }

    #[test]
    fn malformed_v30_output_gap_rolls_back_the_table_rebuild()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut connection, execution_id, _, _, _) = output_fixture(71)?;
        install_v30_output_schema(&connection)?;
        connection.execute(
            "INSERT INTO execution_output_events (
                execution_id, sequence, event_kind, stream, bytes,
                first_missing, last_missing, omitted_bytes, omitted_chunks, gap_cause
             ) VALUES (?1, 1, 0, 0, ?2, NULL, NULL, NULL, NULL, NULL),
                      (?1, 3, 1, NULL, NULL, 1, 1, 5, 2, 1)",
            params![execution_id.into_uuid().as_bytes(), b"chunk".as_slice()],
        )?;

        let result = {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let result = migrate_output_events_to_v31(&transaction);
            if result.is_err() {
                transaction.rollback()?;
            }
            result
        };
        assert!(result.is_err());

        validate_schema_v30(&connection)?;
        let legacy_count: i64 = connection.query_row(
            "SELECT COUNT(*) FROM execution_output_events WHERE execution_id = ?1",
            params![execution_id.into_uuid().as_bytes()],
            |row| row.get(0),
        )?;
        assert_eq!(legacy_count, 2);
        let rebuilt_table: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_schema
                 WHERE type = 'table' AND name = 'execution_output_events_v30'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        assert!(rebuilt_table.is_none());
        Ok(())
    }

    type OutputFixture = (
        Connection,
        ExecutionId,
        ExecutionOutputEvent,
        ExecutionOutputEvent,
        ExecutionOutputEvent,
    );

    fn output_fixture(seed: u128) -> Result<OutputFixture, Box<dyn std::error::Error>> {
        let (mut connection, workspace_id, activity_id) = fixture()?;
        let request = request(seed, workspace_id, activity_id, false)?;
        let started = begin_execution(
            &mut connection,
            &BeginExecution::from_request(
                &request,
                ExecutionRequestDigest::from_bytes([6; 32]),
                TimestampMillis::new(10)?,
            ),
        )?;
        let execution_id = started.record().id();
        let first = ExecutionOutputEvent::Chunk(ExecutionOutputChunk::new(
            execution_id,
            ExecutionOutputSequence::new(1)?,
            ExecutionOutputStream::Stdout,
            b"one",
        )?);
        let second = ExecutionOutputEvent::Chunk(ExecutionOutputChunk::new(
            execution_id,
            ExecutionOutputSequence::new(2)?,
            ExecutionOutputStream::Stderr,
            b"two",
        )?);
        let gap = ExecutionOutputEvent::Gap(ExecutionOutputGap::new(
            execution_id,
            ExecutionOutputSequence::new(4)?,
            ExecutionOutputGapParts::new(
                ExecutionOutputSequence::new(3)?,
                ExecutionOutputSequence::new(3)?,
                None,
                9,
                1,
                ExecutionOutputGapCause::OutputLimit,
            ),
        )?);
        Ok((connection, execution_id, first, second, gap))
    }

    #[test]
    fn output_events_append_replay_conflict_and_atomic_rollback()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut connection, execution_id, first, second, gap) = output_fixture(60)?;
        append_output_events(
            &mut connection,
            &[second.clone(), first.clone(), gap.clone()],
        )?;
        append_output_events(
            &mut connection,
            &[second.clone(), first.clone(), gap.clone()],
        )?;

        let conflicting = ExecutionOutputEvent::Chunk(ExecutionOutputChunk::new(
            execution_id,
            ExecutionOutputSequence::new(1)?,
            ExecutionOutputStream::Stdout,
            b"different",
        )?);
        let later = ExecutionOutputEvent::Chunk(ExecutionOutputChunk::new(
            execution_id,
            ExecutionOutputSequence::new(5)?,
            ExecutionOutputStream::Stdout,
            b"later",
        )?);
        assert!(matches!(
            append_output_events(&mut connection, &[conflicting, later]),
            Err(ExecutionStoreError::OutputEventConflict)
        ));
        assert!(
            read_output_events(
                &connection,
                ExecutionOutputCursor::from_sequence(
                    execution_id,
                    ExecutionOutputSequence::new(4)?
                ),
                MIN_EXECUTION_OUTPUT_READ_BYTES,
                8,
            )?
            .events()
            .is_empty()
        );
        Ok(())
    }

    #[test]
    fn output_events_read_in_order_with_bounds_and_cursor_validation()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut connection, execution_id, first, second, gap) = output_fixture(62)?;
        append_output_events(
            &mut connection,
            &[second.clone(), first.clone(), gap.clone()],
        )?;
        let initial = ExecutionOutputCursor::initial(execution_id);
        let first_read =
            read_output_events(&connection, initial, MIN_EXECUTION_OUTPUT_READ_BYTES, 1)?;
        assert_eq!(first_read.events().len(), 1);
        assert_eq!(first_read.events()[0], first);
        assert_eq!(first_read.next_cursor().after_sequence(), 1);
        assert!(first_read.truncated());
        assert!(first_read.terminal_state().is_none());

        let second_read = read_output_events(
            &connection,
            first_read.next_cursor(),
            MIN_EXECUTION_OUTPUT_READ_BYTES,
            8,
        )?;
        assert_eq!(second_read.events(), &[second.clone(), gap.clone()]);
        assert_eq!(second_read.next_cursor().after_sequence(), 4);
        assert!(!second_read.truncated());
        assert!(
            read_output_events(
                &connection,
                second_read.next_cursor(),
                MIN_EXECUTION_OUTPUT_READ_BYTES,
                8,
            )?
            .events()
            .is_empty()
        );

        assert!(matches!(
            read_output_events(&connection, initial, MIN_EXECUTION_OUTPUT_READ_BYTES - 1, 8),
            Err(ExecutionStoreError::InvalidOutputReadLimits { .. })
        ));
        assert!(matches!(
            read_output_events(
                &connection,
                initial,
                MAX_EXECUTION_OUTPUT_READ_BYTES,
                MAX_EXECUTION_OUTPUT_READ_EVENTS + 1,
            ),
            Err(ExecutionStoreError::InvalidOutputReadLimits { .. })
        ));
        assert!(matches!(
            read_output_events(
                &connection,
                ExecutionOutputCursor::from_sequence(
                    execution_id,
                    ExecutionOutputSequence::new(99)?
                ),
                MAX_EXECUTION_OUTPUT_READ_BYTES,
                MAX_EXECUTION_OUTPUT_READ_EVENTS,
            ),
            Err(ExecutionStoreError::InvalidOutputCursor)
        ));
        assert!(matches!(
            read_output_events(
                &connection,
                ExecutionOutputCursor::from_sequence(
                    ExecutionId::from_uuid(Uuid::from_u128(999)),
                    ExecutionOutputSequence::new(1)?,
                ),
                MAX_EXECUTION_OUTPUT_READ_BYTES,
                MAX_EXECUTION_OUTPUT_READ_EVENTS,
            ),
            Err(ExecutionStoreError::InvalidOutputCursor)
        ));
        Ok(())
    }

    #[test]
    fn output_event_shape_is_rejected_when_a_row_is_corrupted()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut connection, workspace_id, activity_id) = fixture()?;
        let request = request(61, workspace_id, activity_id, false)?;
        let started = begin_execution(
            &mut connection,
            &BeginExecution::from_request(
                &request,
                ExecutionRequestDigest::from_bytes([7; 32]),
                TimestampMillis::new(10)?,
            ),
        )?;
        let execution_id = started.record().id();
        let event = ExecutionOutputEvent::Chunk(ExecutionOutputChunk::new(
            execution_id,
            ExecutionOutputSequence::new(1)?,
            ExecutionOutputStream::Stdout,
            b"safe",
        )?);
        append_output_events(&mut connection, std::slice::from_ref(&event))?;
        connection.pragma_update(None, "ignore_check_constraints", true)?;
        connection.execute(
            "UPDATE execution_output_events
             SET event_kind = 1, stream = NULL, bytes = NULL
             WHERE execution_id = ?1 AND sequence = 1",
            params![execution_id.into_uuid().as_bytes()],
        )?;
        connection.pragma_update(None, "ignore_check_constraints", false)?;
        assert!(matches!(
            read_output_events(
                &connection,
                ExecutionOutputCursor::initial(execution_id),
                MAX_EXECUTION_OUTPUT_READ_BYTES,
                MAX_EXECUTION_OUTPUT_READ_EVENTS,
            ),
            Err(ExecutionStoreError::CorruptRecord(_))
        ));
        Ok(())
    }

    #[test]
    fn execution_stop_fences_fresh_begin_but_preserves_exact_existing_replay()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut connection, workspace_id, activity_id) = fixture()?;
        let existing_request = request(0x5701, workspace_id, activity_id, false)?;
        let begin = BeginExecution::from_request(
            &existing_request,
            ExecutionRequestDigest::from_bytes([0x57; 32]),
            TimestampMillis::new(10)?,
        );
        let first = begin_execution(&mut connection, &begin)?;
        let stop = crate::ExecutionStopRequest::new(
            Uuid::from_u128(0x5702),
            workspace_id,
            Uuid::from_u128(0x5703),
            RuntimeInstanceId::from_uuid(Uuid::from_u128(0x5704)),
            [0x58; 32],
            TimestampMillis::new(20)?,
        );
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let captured = crate::workspace_execution_stops::capture_in_transaction(
            &transaction,
            &stop,
            [0x59; 32],
        )?;
        transaction.commit()?;
        assert_eq!(captured.record().targets().len(), 1);
        let replay = begin_execution(&mut connection, &begin)?;
        assert_eq!(replay.status(), BeginExecutionStatus::Existing);
        assert_eq!(replay.record(), first.record());
        let fresh_request = request(0x5705, workspace_id, activity_id, false)?;
        let fresh = BeginExecution::from_request(
            &fresh_request,
            ExecutionRequestDigest::from_bytes([0x60; 32]),
            TimestampMillis::new(21)?,
        );
        assert!(matches!(
            begin_execution(&mut connection, &fresh),
            Err(ExecutionStoreError::ExecutionStop(_))
        ));
        assert!(get_execution(&connection, fresh.id())?.is_none());
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
             );
             CREATE TABLE agent_instances(
                activity_id BLOB NOT NULL,
                session_id BLOB,
                attachment_state INTEGER NOT NULL
             );",
        )?;
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(1));
        connection.execute(
            "INSERT INTO workspace(workspace_id) VALUES (?1)",
            params![workspace_id.into_uuid().as_bytes()],
        )?;
        create_schema(&connection)?;
        crate::workspace_verification::create_schema(&connection)?;
        crate::workspace_goal_deletion::create_schema(&connection)?;
        crate::workspace_semantic_events::create_schema(&connection)?;
        create_execution_admission_fixture_schema(&connection)?;
        for (raw_id, lease_until) in [
            (2_u128, Some(10_i64)),
            (3, Some(10_000)),
            (4, None),
            (5, Some(10)),
        ] {
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
            if raw_id == 2 {
                connection.execute(
                    "INSERT INTO agent_instances(activity_id, session_id, attachment_state)
                     VALUES (?1, ?2, 0)",
                    params![
                        activity_id.into_uuid().as_bytes(),
                        Uuid::from_u128(0xA200).as_bytes(),
                    ],
                )?;
            }
        }

        // An expired Activity with an attached session-bound Agent is retained;
        // only the expired Activity without a participant is classified.
        let reconciled = reconcile_expired_authority_executions(
            &mut connection,
            TimestampMillis::new(1_000)?,
            ExecutionListLimit::new(8)?,
        )?;
        assert_eq!(reconciled.len(), 1);
        assert_eq!(
            reconciled[0].activity_id(),
            ActivityId::from_uuid(Uuid::from_u128(5))
        );
        assert_eq!(reconciled[0].state(), ExecutionState::Interrupted);

        // The attached participant, live lease, and unleased execution stay Starting.
        for untouched in [20_u128, 30, 40] {
            let record = get_execution(
                &connection,
                ExecutionId::from_uuid(Uuid::from_u128(untouched)),
            )?
            .ok_or("untouched execution missing")?;
            assert_eq!(record.state(), ExecutionState::Starting, "{untouched}");
        }
        Ok(())
    }

    #[test]
    fn native_closure_fact_round_trips_with_terminal_snapshot()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut connection, workspace_id, activity_id) = fixture()?;
        native_closure::create_schema(&connection)?;
        let execution_id = ExecutionId::from_uuid(Uuid::from_u128(0xC105));
        let execution_request = request(
            execution_id.into_uuid().as_u128(),
            workspace_id,
            activity_id,
            false,
        )?;
        let begun = begin_execution(
            &mut connection,
            &BeginExecution::from_request(
                &execution_request,
                ExecutionRequestDigest::from_bytes([0x91; 32]),
                TimestampMillis::new(20)?,
            ),
        )?;
        let running = mark_execution_running(
            &mut connection,
            MarkExecutionRunning::new(
                execution_id,
                begun.record().revision(),
                TimestampMillis::new(21)?,
            ),
        )?;
        let observed_at = TimestampMillis::new(22)?;
        let closure = ExecutionNativeClosureFact::from_parts(
            forge_domain::ExecutionNativeClosureFactParts {
                attribution: ExecutionAttribution::new(execution_id, workspace_id, activity_id),
                request_digest: ExecutionRequestDigest::from_bytes([0x91; 32]),
                before_revision: running.revision(),
                after_revision: running.revision().checked_next()?,
                output_cursor: ExecutionOutputCursor::initial(execution_id),
                launch: forge_domain::NativeClosureLaunch::Baseline,
                runtime: forge_domain::NativeClosureRuntime::NotApplicable,
                process: forge_domain::NativeClosureProcess::NoChildSpawned,
                observed_at,
            },
        )?;
        let outcome = ExecutionOutcome::new(
            execution_id,
            ExecutionTermination::new(ExecutionCompletionStatus::Exited, Some(0), None),
            1,
            BoundedExecutionOutput::new(Vec::new(), 0, false),
            BoundedExecutionOutput::new(Vec::new(), 0, false),
        );
        let completed = complete_execution_with_native_closure(
            &mut connection,
            &CompleteExecution::new(running.revision(), observed_at, outcome),
            None,
            Some(closure),
        )?;
        let snapshot = native_closure::snapshot(&connection, execution_id)?
            .ok_or("native closure snapshot missing")?;
        assert_eq!(snapshot.record(), &completed);
        assert_eq!(snapshot.manifest(), None);
        assert_eq!(snapshot.closure(), Some(closure));
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert!(matches!(
            native_closure::append_in_transaction(&transaction, &completed, &closure),
            Err(ExecutionStoreError::NativeClosureAlreadyExists)
        ));
        transaction.rollback()?;
        assert_eq!(
            native_closure::snapshot(&connection, execution_id)?
                .ok_or("snapshot lost")?
                .closure(),
            Some(closure)
        );
        Ok(())
    }

    #[test]
    fn native_closure_conflict_rolls_back_terminal_transition_and_fact()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut connection, workspace_id, activity_id) = fixture()?;
        native_closure::create_schema(&connection)?;
        let execution_id = ExecutionId::from_uuid(Uuid::from_u128(0xC106));
        let execution_request = request(
            execution_id.into_uuid().as_u128(),
            workspace_id,
            activity_id,
            false,
        )?;
        let begun = begin_execution(
            &mut connection,
            &BeginExecution::from_request(
                &execution_request,
                ExecutionRequestDigest::from_bytes([0x92; 32]),
                TimestampMillis::new(20)?,
            ),
        )?;
        let running = mark_execution_running(
            &mut connection,
            MarkExecutionRunning::new(
                execution_id,
                begun.record().revision(),
                TimestampMillis::new(21)?,
            ),
        )?;
        let observed_at = TimestampMillis::new(22)?;
        let closure = ExecutionNativeClosureFact::from_parts(
            forge_domain::ExecutionNativeClosureFactParts {
                attribution: ExecutionAttribution::new(execution_id, workspace_id, activity_id),
                request_digest: ExecutionRequestDigest::from_bytes([0xFF; 32]),
                before_revision: running.revision(),
                after_revision: running.revision().checked_next()?,
                output_cursor: ExecutionOutputCursor::initial(execution_id),
                launch: forge_domain::NativeClosureLaunch::Baseline,
                runtime: forge_domain::NativeClosureRuntime::NotApplicable,
                process: forge_domain::NativeClosureProcess::NoChildSpawned,
                observed_at,
            },
        )?;
        let outcome = ExecutionOutcome::new(
            execution_id,
            ExecutionTermination::new(ExecutionCompletionStatus::Exited, Some(0), None),
            1,
            BoundedExecutionOutput::new(Vec::new(), 0, false),
            BoundedExecutionOutput::new(Vec::new(), 0, false),
        );
        assert!(matches!(
            complete_execution_with_native_closure(
                &mut connection,
                &CompleteExecution::new(running.revision(), observed_at, outcome),
                None,
                Some(closure),
            ),
            Err(ExecutionStoreError::NativeClosureConflict)
        ));
        let persisted = get_execution(&connection, execution_id)?.ok_or("execution missing")?;
        assert_eq!(persisted.state(), ExecutionState::Running);
        assert_eq!(persisted.revision(), running.revision());
        assert_eq!(
            connection.query_row(
                "SELECT COUNT(*) FROM execution_native_closures WHERE execution_id = ?1",
                params![execution_id.into_uuid().as_bytes()],
                |row| row.get::<_, i64>(0),
            )?,
            0
        );
        Ok(())
    }

    #[test]
    fn native_closure_snapshot_rejects_corrupt_fact_payload()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut connection, workspace_id, activity_id) = fixture()?;
        native_closure::create_schema(&connection)?;
        let execution_id = ExecutionId::from_uuid(Uuid::from_u128(0xC107));
        let execution_request = request(
            execution_id.into_uuid().as_u128(),
            workspace_id,
            activity_id,
            false,
        )?;
        let begun = begin_execution(
            &mut connection,
            &BeginExecution::from_request(
                &execution_request,
                ExecutionRequestDigest::from_bytes([0x93; 32]),
                TimestampMillis::new(20)?,
            ),
        )?;
        let running = mark_execution_running(
            &mut connection,
            MarkExecutionRunning::new(
                execution_id,
                begun.record().revision(),
                TimestampMillis::new(21)?,
            ),
        )?;
        let observed_at = TimestampMillis::new(22)?;
        let closure = ExecutionNativeClosureFact::from_parts(
            forge_domain::ExecutionNativeClosureFactParts {
                attribution: ExecutionAttribution::new(execution_id, workspace_id, activity_id),
                request_digest: ExecutionRequestDigest::from_bytes([0x93; 32]),
                before_revision: running.revision(),
                after_revision: running.revision().checked_next()?,
                output_cursor: ExecutionOutputCursor::initial(execution_id),
                launch: forge_domain::NativeClosureLaunch::Baseline,
                runtime: forge_domain::NativeClosureRuntime::NotApplicable,
                process: forge_domain::NativeClosureProcess::NoChildSpawned,
                observed_at,
            },
        )?;
        let outcome = ExecutionOutcome::new(
            execution_id,
            ExecutionTermination::new(ExecutionCompletionStatus::Exited, Some(0), None),
            1,
            BoundedExecutionOutput::new(Vec::new(), 0, false),
            BoundedExecutionOutput::new(Vec::new(), 0, false),
        );
        let _completed = complete_execution_with_native_closure(
            &mut connection,
            &CompleteExecution::new(running.revision(), observed_at, outcome),
            None,
            Some(closure),
        )?;
        connection.pragma_update(None, "ignore_check_constraints", true)?;
        connection.execute(
            "UPDATE execution_native_closures SET process_disposition = 99 WHERE execution_id = ?1",
            params![execution_id.into_uuid().as_bytes()],
        )?;
        connection.pragma_update(None, "ignore_check_constraints", false)?;
        assert!(matches!(
            native_closure::snapshot(&connection, execution_id),
            Err(ExecutionStoreError::CorruptRecord(
                "execution_native_closures.process_disposition"
            ))
        ));
        Ok(())
    }
}
