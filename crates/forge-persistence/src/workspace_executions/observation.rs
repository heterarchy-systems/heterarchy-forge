//! Read-only execution evidence observations for the host service.
//!
//! This boundary deliberately reads execution metadata and the durable output
//! ledger without manufacturing Agent/session authority.  The compact header
//! query keeps stdout/stderr out of the returned row; output bytes are read
//! only through the separately bounded event ledger query.

use std::os::unix::ffi::OsStringExt;

use forge_domain::{
    ExecutionAttribution, ExecutionId, ExecutionLimits, ExecutionListLimit,
    ExecutionObservationHeader, ExecutionObservationLifecycle, ExecutionObservationSelection,
    ExecutionOutputCursor, ExecutionOutputRead, ExecutionOutputSummary, ExecutionPermissions,
    ExecutionRecordDefinition, ExecutionRequestDigest, ExecutionRevision, ExecutionTerminalSummary,
    ExecutionTermination, ExecutionTimeoutMillis, ExecutionTimestamps, GoalRevision,
    VerificationEvidenceSnapshot, WorkspaceId,
};
use rusqlite::{Connection, OptionalExtension, Row, Transaction, params};

use crate::{GoalStoreError, WorkspaceStoreError};

use super::ExecutionStoreError;

/// Compact equivalent of the execution record query.
///
/// Keep columns 0..44 aligned with `super::RECORD_QUERY`.  In particular,
/// columns 22 and 25 carry `length(stdout)`/`length(stderr)` in place of the
/// blobs.  Columns 45 and 46 retain SQLite's storage class so a TEXT value
/// cannot be mistaken for a BLOB merely because `CAST` was used for its
/// length.  The provenance decoder is intentionally reused so this
/// observation cannot acquire a second provenance interpretation.
const HEADER_QUERY: &str = "SELECT
        length(CAST(e.execution_id AS BLOB)), length(CAST(e.workspace_id AS BLOB)),
        length(CAST(e.activity_id AS BLOB)), length(CAST(e.request_digest AS BLOB)),
        length(CAST(e.cwd AS BLOB)), length(CAST(e.stdout AS BLOB)), length(CAST(e.stderr AS BLOB)),
        e.execution_id, e.workspace_id, e.activity_id, e.state, e.mode, e.request_digest, e.cwd,
        e.timeout_ms, e.output_limit, e.workspace_read, e.workspace_write, e.network,
        e.exit_code, e.signal, e.duration_ms, length(CAST(e.stdout AS BLOB)), e.stdout_total_bytes, e.stdout_truncated,
        length(CAST(e.stderr AS BLOB)), e.stderr_total_bytes, e.stderr_truncated, e.failure_code,
        e.created_at_ms, e.updated_at_ms, e.revision,
        p.agent_id, p.agent_revision, p.principal_kind, p.principal_id,
        p.goal_id, p.goal_revision, p.dag_revision, p.node_id, p.node_revision, p.command_id,
        p.session_id,
        c.command_class, c.catalog_fingerprint,
        typeof(e.stdout), typeof(e.stderr)
    FROM executions AS e
    LEFT JOIN execution_provenance AS p ON p.execution_id = e.execution_id
    LEFT JOIN execution_command_evidence AS c ON c.execution_id = p.execution_id";

/// One compact execution header and its optional durable verification evidence.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionEvidenceRecord {
    header: ExecutionObservationHeader,
    verification: Option<VerificationEvidenceSnapshot>,
}

impl ExecutionEvidenceRecord {
    fn new(
        header: ExecutionObservationHeader,
        verification: Option<VerificationEvidenceSnapshot>,
    ) -> Self {
        Self {
            header,
            verification,
        }
    }

    pub const fn header(&self) -> &ExecutionObservationHeader {
        &self.header
    }

    pub const fn verification(&self) -> Option<&VerificationEvidenceSnapshot> {
        self.verification.as_ref()
    }
}

/// Bounded inventory of execution evidence from one durable read snapshot.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionEvidenceInventory {
    selection: ExecutionObservationSelection,
    entries: Vec<ExecutionEvidenceRecord>,
    has_more: bool,
}

impl ExecutionEvidenceInventory {
    fn new(
        selection: ExecutionObservationSelection,
        entries: Vec<ExecutionEvidenceRecord>,
        has_more: bool,
    ) -> Self {
        Self {
            selection,
            entries,
            has_more,
        }
    }

    pub const fn selection(&self) -> ExecutionObservationSelection {
        self.selection
    }

    pub fn entries(&self) -> &[ExecutionEvidenceRecord] {
        &self.entries
    }

    pub const fn has_more(&self) -> bool {
        self.has_more
    }
}

/// One compact execution record and a bounded output-ledger read from the
/// same durable snapshot.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionEvidenceRead {
    selection: ExecutionObservationSelection,
    record: ExecutionEvidenceRecord,
    output: ExecutionOutputRead,
}

impl ExecutionEvidenceRead {
    fn new(
        selection: ExecutionObservationSelection,
        record: ExecutionEvidenceRecord,
        output: ExecutionOutputRead,
    ) -> Self {
        Self {
            selection,
            record,
            output,
        }
    }

    pub const fn selection(&self) -> ExecutionObservationSelection {
        self.selection
    }

    pub const fn record(&self) -> &ExecutionEvidenceRecord {
        &self.record
    }

    pub const fn output(&self) -> &ExecutionOutputRead {
        &self.output
    }
}

/// Read a bounded execution inventory from one SQLite snapshot.
pub(crate) fn inventory(
    connection: &Connection,
    workspace_id: WorkspaceId,
    selection: ExecutionObservationSelection,
    limit: ExecutionListLimit,
) -> Result<ExecutionEvidenceInventory, WorkspaceStoreError> {
    let transaction = connection.unchecked_transaction()?;
    validate_selection(&transaction, workspace_id, selection)?;

    let probe_limit = i64::from(limit.get()) + 1;
    let headers = query_headers(&transaction, workspace_id, selection, None, probe_limit)?;
    let has_more = headers.len() > usize::from(limit.get());
    let headers = headers.into_iter().take(usize::from(limit.get()));
    let mut entries = Vec::new();
    for header in headers {
        let verification =
            crate::workspace_verification::observation_snapshot(&transaction, &header)?;
        entries.push(ExecutionEvidenceRecord::new(header, verification));
    }

    transaction.commit()?;
    Ok(ExecutionEvidenceInventory::new(
        selection, entries, has_more,
    ))
}

/// Read one execution header and a bounded output prefix from one SQLite
/// snapshot.  This path only observes durable Activity/Goal scope and never
/// requires a current Agent, session, acknowledgement, or mutation grant.
pub(crate) fn read(
    connection: &Connection,
    workspace_id: WorkspaceId,
    selection: ExecutionObservationSelection,
    execution_id: ExecutionId,
    cursor: ExecutionOutputCursor,
    max_bytes: u64,
    max_events: usize,
) -> Result<ExecutionEvidenceRead, WorkspaceStoreError> {
    super::validate_output_read_limits(max_bytes, max_events)?;
    if cursor.execution_id() != execution_id {
        return Err(ExecutionStoreError::InvalidOutputCursor.into());
    }

    let transaction = connection.unchecked_transaction()?;
    validate_selection(&transaction, workspace_id, selection)?;
    let header = query_headers(&transaction, workspace_id, selection, Some(execution_id), 1)?
        .into_iter()
        .next()
        .ok_or(ExecutionStoreError::RecordMissing)?;
    let verification = crate::workspace_verification::observation_snapshot(&transaction, &header)?;
    let output =
        super::read_output_events_in_transaction(&transaction, cursor, max_bytes, max_events)?;
    validate_output_coverage(cursor, &output)?;
    transaction.commit()?;

    Ok(ExecutionEvidenceRead::new(
        selection,
        ExecutionEvidenceRecord::new(header, verification),
        output,
    ))
}

fn validate_output_coverage(
    cursor: ExecutionOutputCursor,
    output: &ExecutionOutputRead,
) -> Result<(), ExecutionStoreError> {
    let mut previous = cursor.after_sequence();
    for event in output.events() {
        let expected = previous
            .checked_add(1)
            .ok_or(ExecutionStoreError::InvalidOutputCursor)?;
        let covered = match event {
            forge_domain::ExecutionOutputEvent::Chunk(chunk) => chunk.sequence().get() == expected,
            forge_domain::ExecutionOutputEvent::Gap(gap) => gap.first_missing().get() == expected,
        };
        if !covered {
            return Err(ExecutionStoreError::CorruptRecord(
                "execution_observation.output_coverage",
            ));
        }
        previous = event.sequence().get();
    }
    if output.next_cursor().after_sequence() != previous {
        return Err(ExecutionStoreError::CorruptRecord(
            "execution_observation.output_cursor",
        ));
    }
    Ok(())
}

fn validate_selection(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
    selection: ExecutionObservationSelection,
) -> Result<(), WorkspaceStoreError> {
    let actual_activity_workspace: Option<Vec<u8>> = transaction
        .query_row(
            "SELECT workspace_id FROM activities WHERE activity_id = ?1",
            params![selection.activity_id().into_uuid().as_bytes()],
            |row| row.get(0),
        )
        .optional()?;
    let Some(actual_activity_workspace) = actual_activity_workspace else {
        return Err(ExecutionStoreError::ActivityMissing.into());
    };
    if actual_activity_workspace.len() != 16 {
        return Err(ExecutionStoreError::CorruptRecord("activity.workspace_id").into());
    }
    if actual_activity_workspace.as_slice() != workspace_id.into_uuid().as_bytes() {
        return Err(ExecutionStoreError::AttributionMismatch.into());
    }

    let Some(goal) = selection.goal() else {
        return Ok(());
    };
    let goal_row: Option<(Vec<u8>, Vec<u8>, i64)> = transaction
        .query_row(
            "SELECT workspace_id, activity_id, revision FROM goals WHERE goal_id = ?1",
            params![goal.goal_id().into_uuid().as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((goal_workspace, goal_activity, raw_revision)) = goal_row else {
        return Err(GoalStoreError::RecordMissing.into());
    };
    if goal_workspace.len() != 16 {
        return Err(GoalStoreError::CorruptRecord("goals.workspace_id").into());
    }
    if goal_activity.len() != 16 {
        return Err(GoalStoreError::CorruptRecord("goals.activity_id").into());
    }
    if goal_workspace.as_slice() != workspace_id.into_uuid().as_bytes() {
        return Err(GoalStoreError::WorkspaceMismatch.into());
    }
    if goal_activity.as_slice() != selection.activity_id().into_uuid().as_bytes() {
        return Err(GoalStoreError::ActivityMismatch.into());
    }
    let revision = GoalRevision::new(raw_revision)
        .map_err(|_| GoalStoreError::CorruptRecord("goals.revision"))?;
    if revision != goal.expected_revision() {
        return Err(GoalStoreError::RevisionConflict.into());
    }
    Ok(())
}

fn query_headers(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
    selection: ExecutionObservationSelection,
    execution_id: Option<ExecutionId>,
    limit: i64,
) -> Result<Vec<ExecutionObservationHeader>, WorkspaceStoreError> {
    let query = match (selection.goal(), execution_id) {
        (Some(_), Some(_)) => format!(
            "{HEADER_QUERY}
             WHERE e.workspace_id = ?1 AND e.activity_id = ?2 AND e.execution_id = ?3
               AND EXISTS (
                   SELECT 1 FROM goal_evidence_refs AS ge
                   WHERE ge.goal_id = ?4
                     AND ge.evidence_kind = ?5
                     AND ge.evidence_id = e.execution_id
               )
             ORDER BY e.updated_at_ms DESC, e.execution_id DESC LIMIT ?6"
        ),
        (Some(_), None) => format!(
            "{HEADER_QUERY}
             WHERE e.workspace_id = ?1 AND e.activity_id = ?2
               AND EXISTS (
                   SELECT 1 FROM goal_evidence_refs AS ge
                   WHERE ge.goal_id = ?3
                     AND ge.evidence_kind = ?4
                     AND ge.evidence_id = e.execution_id
               )
             ORDER BY e.updated_at_ms DESC, e.execution_id DESC LIMIT ?5"
        ),
        (None, Some(_)) => format!(
            "{HEADER_QUERY}
             WHERE e.workspace_id = ?1 AND e.activity_id = ?2 AND e.execution_id = ?3
             ORDER BY e.updated_at_ms DESC, e.execution_id DESC LIMIT ?4"
        ),
        (None, None) => format!(
            "{HEADER_QUERY}
             WHERE e.workspace_id = ?1 AND e.activity_id = ?2
             ORDER BY e.updated_at_ms DESC, e.execution_id DESC LIMIT ?3"
        ),
    };

    let mut statement = transaction.prepare(&query)?;
    let mut rows = match (selection.goal(), execution_id) {
        (Some(goal), Some(execution_id)) => statement.query(params![
            workspace_id.into_uuid().as_bytes(),
            selection.activity_id().into_uuid().as_bytes(),
            execution_id.into_uuid().as_bytes(),
            goal.goal_id().into_uuid().as_bytes(),
            crate::workspace_goals::GOAL_EXECUTION_EVIDENCE_KIND,
            limit,
        ])?,
        (Some(goal), None) => statement.query(params![
            workspace_id.into_uuid().as_bytes(),
            selection.activity_id().into_uuid().as_bytes(),
            goal.goal_id().into_uuid().as_bytes(),
            crate::workspace_goals::GOAL_EXECUTION_EVIDENCE_KIND,
            limit,
        ])?,
        (None, Some(execution_id)) => statement.query(params![
            workspace_id.into_uuid().as_bytes(),
            selection.activity_id().into_uuid().as_bytes(),
            execution_id.into_uuid().as_bytes(),
            limit,
        ])?,
        (None, None) => statement.query(params![
            workspace_id.into_uuid().as_bytes(),
            selection.activity_id().into_uuid().as_bytes(),
            limit,
        ])?,
    };
    let mut headers = Vec::new();
    while let Some(row) = rows.next()? {
        headers.push(decode_header(row)?);
    }
    Ok(headers)
}

fn decode_header(row: &Row<'_>) -> Result<ExecutionObservationHeader, WorkspaceStoreError> {
    super::validate_exact_length("execution.execution_id", row.get(0)?, 16)?;
    super::validate_exact_length("execution.workspace_id", row.get(1)?, 16)?;
    super::validate_exact_length("execution.activity_id", row.get(2)?, 16)?;
    super::validate_exact_length(
        "execution.request_digest",
        row.get(3)?,
        ExecutionRequestDigest::BYTE_LEN,
    )?;
    super::validate_optional_bounded_length("execution.cwd", row.get(4)?, super::MAX_CWD_BYTES)?;
    super::validate_optional_bounded_length(
        "execution.stdout",
        row.get(5)?,
        super::MAX_OUTPUT_BYTES,
    )?;
    super::validate_optional_bounded_length(
        "execution.stderr",
        row.get(6)?,
        super::MAX_OUTPUT_BYTES,
    )?;

    let id = super::decode_execution_id(&row.get::<_, Vec<u8>>(7)?)?;
    let workspace_id = super::decode_workspace_id(&row.get::<_, Vec<u8>>(8)?)?;
    let activity_id = super::decode_activity_id(&row.get::<_, Vec<u8>>(9)?)?;
    let state = super::decode_state(row.get(10)?)?;
    let mode = super::decode_mode(row.get(11)?)?;
    let request_digest = super::decode_request_digest(&row.get::<_, Vec<u8>>(12)?)?;
    let cwd = row
        .get::<_, Option<Vec<u8>>>(13)?
        .map(|value| {
            forge_domain::WorkspaceRelativePath::new(std::path::PathBuf::from(
                std::ffi::OsString::from_vec(value),
            ))
        })
        .transpose()
        .map_err(|_| ExecutionStoreError::CorruptRecord("execution.cwd"))?;
    let timeout =
        ExecutionTimeoutMillis::new(super::decode_u64("execution.timeout_ms", row.get(14)?)?)
            .map_err(|_| ExecutionStoreError::CorruptRecord("execution.timeout_ms"))?;
    let output_limit = forge_domain::ExecutionOutputLimit::new(super::decode_u64(
        "execution.output_limit",
        row.get(15)?,
    )?)
    .map_err(|_| ExecutionStoreError::CorruptRecord("execution.output_limit"))?;
    let permissions = ExecutionPermissions::new(
        super::decode_bool("execution.workspace_read", row.get(16)?)?,
        super::decode_bool("execution.workspace_write", row.get(17)?)?,
        super::decode_bool("execution.network", row.get(18)?)?,
    );
    let exit_code = row.get::<_, Option<i32>>(19)?;
    let signal = row.get::<_, Option<i32>>(20)?;
    let duration = row
        .get::<_, Option<i64>>(21)?
        .map(|value| super::decode_u64("execution.duration_ms", value))
        .transpose()?;
    let stdout = decode_output_summary(row, 22, 23, 24, 45, "execution.stdout")?;
    let stderr = decode_output_summary(row, 25, 26, 27, 46, "execution.stderr")?;
    let failure_code = row
        .get::<_, Option<i64>>(28)?
        .map(super::decode_failure)
        .transpose()?;
    let timestamps = ExecutionTimestamps::new(
        super::decode_timestamp("execution.created_at_ms", row.get(29)?)?,
        super::decode_timestamp("execution.updated_at_ms", row.get(30)?)?,
    )
    .map_err(|_| ExecutionStoreError::CorruptRecord("execution.timestamps"))?;
    let revision = ExecutionRevision::new(row.get(31)?)
        .map_err(|_| ExecutionStoreError::CorruptRecord("execution.revision"))?;
    let terminal = match (duration, stdout, stderr) {
        (Some(duration), Some(stdout), Some(stderr)) => Some(ExecutionTerminalSummary::new(
            ExecutionTermination::new(
                super::completion_status_for_state(state)?,
                exit_code,
                signal,
            ),
            duration,
            stdout,
            stderr,
        )),
        (None, None, None) => None,
        _ => return Err(ExecutionStoreError::CorruptRecord("execution.outcome").into()),
    };
    let attribution = ExecutionAttribution::new(id, workspace_id, activity_id);
    let provenance = super::decode_provenance(row)?;
    ExecutionObservationHeader::from_parts(
        attribution,
        ExecutionRecordDefinition::new(
            mode,
            cwd,
            ExecutionLimits::new(timeout, output_limit),
            permissions,
            request_digest,
        ),
        ExecutionObservationLifecycle::new(state, timestamps, revision, terminal, failure_code),
        provenance,
    )
    .map_err(|_| ExecutionStoreError::CorruptRecord("execution.observation").into())
}

fn decode_output_summary(
    row: &Row<'_>,
    retained_index: usize,
    total_index: usize,
    truncated_index: usize,
    type_index: usize,
    field: &'static str,
) -> Result<Option<ExecutionOutputSummary>, WorkspaceStoreError> {
    let output_type = row.get::<_, String>(type_index)?;
    let retained = row.get::<_, Option<i64>>(retained_index)?;
    let total = row.get::<_, Option<i64>>(total_index)?;
    let truncated = row.get::<_, Option<i64>>(truncated_index)?;
    let output_present = match output_type.as_str() {
        "blob" => true,
        "null" => false,
        _ => return Err(ExecutionStoreError::CorruptRecord(field).into()),
    };
    match (output_present, retained, total, truncated) {
        (true, Some(retained), Some(total), Some(truncated)) => {
            let summary = ExecutionOutputSummary::new(
                super::decode_u64(field, retained)?,
                super::decode_u64(field, total)?,
                super::decode_bool(field, truncated)?,
            )
            .map_err(|_| ExecutionStoreError::CorruptRecord(field))?;
            Ok(Some(summary))
        }
        (false, None, None, None) => Ok(None),
        _ => Err(ExecutionStoreError::CorruptRecord(field).into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use forge_domain::GoalEvidenceRef;
    use forge_domain::{ActivityId, GoalAttribution};
    use rusqlite::Connection;
    use uuid::Uuid;

    fn ids(seed: u128) -> (WorkspaceId, ActivityId, ExecutionId) {
        (
            WorkspaceId::from_uuid(Uuid::from_u128(seed)),
            ActivityId::from_uuid(Uuid::from_u128(seed + 1)),
            ExecutionId::from_uuid(Uuid::from_u128(seed + 2)),
        )
    }

    fn fixture() -> Result<(Connection, WorkspaceId, ActivityId), Box<dyn std::error::Error>> {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE workspace(workspace_id BLOB PRIMARY KEY);
             CREATE TABLE activities(activity_id BLOB PRIMARY KEY, workspace_id BLOB NOT NULL, state INTEGER NOT NULL);
             CREATE TABLE agent_instances(agent_id BLOB PRIMARY KEY);
             CREATE TABLE goals(goal_id BLOB PRIMARY KEY, workspace_id BLOB NOT NULL, activity_id BLOB NOT NULL,
                                objective TEXT NOT NULL, state INTEGER NOT NULL, reason_kind INTEGER,
                                reason_text TEXT, completion_review_id BLOB, created_at_ms INTEGER NOT NULL,
                                updated_at_ms INTEGER NOT NULL, revision INTEGER NOT NULL);
             CREATE TABLE goal_dag_revisions(goal_id BLOB NOT NULL, dag_revision INTEGER NOT NULL,
                                             PRIMARY KEY(goal_id, dag_revision));
             CREATE TABLE goal_dag_nodes(goal_id BLOB NOT NULL, dag_revision INTEGER NOT NULL,
                                         node_id BLOB NOT NULL, PRIMARY KEY(goal_id, dag_revision, node_id));
             CREATE TABLE goal_evidence_refs(goal_id BLOB NOT NULL, evidence_kind INTEGER NOT NULL,
                                             evidence_id BLOB NOT NULL, associated_at_ms INTEGER NOT NULL,
                                             PRIMARY KEY(goal_id, evidence_kind, evidence_id));",
        )?;
        let (workspace_id, activity_id, _) = ids(1);
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
        super::super::create_schema(&connection)?;
        crate::workspace_verification::create_schema(&connection)?;
        Ok((connection, workspace_id, activity_id))
    }

    fn insert_execution(
        connection: &Connection,
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        execution_id: ExecutionId,
        updated_at: i64,
        output_bytes: Option<usize>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (
            stdout,
            stdout_total,
            stdout_truncated,
            stderr,
            stderr_total,
            stderr_truncated,
            state,
            duration,
        ) = if let Some(output_bytes) = output_bytes {
            let bytes = vec![b'x'; output_bytes];
            (
                Some(bytes.clone()),
                Some(i64::try_from(output_bytes)?),
                Some(0_i64),
                Some(bytes),
                Some(i64::try_from(output_bytes)?),
                Some(0_i64),
                2_i64,
                Some(1_i64),
            )
        } else {
            (None, None, None, None, None, None, 1_i64, None)
        };
        let digest = [7_u8; 32];
        connection.execute(
            "INSERT INTO executions(
                execution_id, workspace_id, activity_id, state, mode, request_digest, cwd,
                timeout_ms, output_limit, workspace_read, workspace_write, network,
                exit_code, signal, duration_ms, stdout, stdout_total_bytes, stdout_truncated,
                stderr, stderr_total_bytes, stderr_truncated, failure_code, created_at_ms,
                updated_at_ms, revision
             ) VALUES (?1, ?2, ?3, ?4, 0, ?5, NULL, 1000, 16, 1, 0, 0,
                       ?6, NULL, ?7, ?8, ?9, ?10, ?11, ?12, ?13, NULL, 1, ?14, 1)",
            params![
                execution_id.into_uuid().as_bytes(),
                workspace_id.into_uuid().as_bytes(),
                activity_id.into_uuid().as_bytes(),
                state,
                digest.as_slice(),
                output_bytes.map(|_| 0_i32),
                duration,
                stdout,
                stdout_total,
                stdout_truncated,
                stderr,
                stderr_total,
                stderr_truncated,
                updated_at,
            ],
        )?;
        Ok(())
    }

    #[test]
    fn selection_rejects_activity_and_goal_scope_mismatches()
    -> Result<(), Box<dyn std::error::Error>> {
        let (connection, workspace_id, activity_id) = fixture()?;
        let other_workspace = WorkspaceId::from_uuid(Uuid::from_u128(101));
        let goal_id = forge_domain::GoalId::from_uuid(Uuid::from_u128(102));
        connection.execute(
            "INSERT INTO goals(goal_id, workspace_id, activity_id, objective, state, created_at_ms, updated_at_ms, revision)
             VALUES (?1, ?2, ?3, 'goal', 0, 1, 1, 1)",
            params![goal_id.into_uuid().as_bytes(), workspace_id.into_uuid().as_bytes(), activity_id.into_uuid().as_bytes()],
        )?;
        let limit = ExecutionListLimit::new(1)?;
        assert!(
            inventory(
                &connection,
                other_workspace,
                ExecutionObservationSelection::new(activity_id, None),
                limit
            )
            .is_err()
        );
        assert!(
            inventory(
                &connection,
                workspace_id,
                ExecutionObservationSelection::new(
                    activity_id,
                    Some(GoalAttribution::new(goal_id, GoalRevision::new(2)?))
                ),
                limit,
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn goal_filter_is_applied_before_limit_and_full_output_is_compact()
    -> Result<(), Box<dyn std::error::Error>> {
        let (connection, workspace_id, activity_id) = fixture()?;
        let (_, _, linked_id) = ids(10);
        let (_, _, other_id) = ids(20);
        insert_execution(
            &connection,
            workspace_id,
            activity_id,
            linked_id,
            1,
            Some(1_000_000),
        )?;
        insert_execution(&connection, workspace_id, activity_id, other_id, 2, None)?;
        let goal_id = forge_domain::GoalId::from_uuid(Uuid::from_u128(200));
        connection.execute(
            "INSERT INTO goals(goal_id, workspace_id, activity_id, objective, state, created_at_ms, updated_at_ms, revision)
             VALUES (?1, ?2, ?3, 'goal', 0, 1, 1, 1)",
            params![goal_id.into_uuid().as_bytes(), workspace_id.into_uuid().as_bytes(), activity_id.into_uuid().as_bytes()],
        )?;
        let (kind, evidence_id) =
            crate::workspace_goals::encode_evidence(GoalEvidenceRef::Execution(linked_id));
        connection.execute(
            "INSERT INTO goal_evidence_refs(goal_id, evidence_kind, evidence_id, associated_at_ms) VALUES (?1, ?2, ?3, 2)",
            params![goal_id.into_uuid().as_bytes(), kind, evidence_id],
        )?;
        let inventory = inventory(
            &connection,
            workspace_id,
            ExecutionObservationSelection::new(
                activity_id,
                Some(GoalAttribution::new(goal_id, GoalRevision::new(1)?)),
            ),
            ExecutionListLimit::new(1)?,
        )?;
        assert_eq!(inventory.entries().len(), 1);
        assert!(!inventory.has_more());
        assert_eq!(inventory.entries()[0].header().id(), linked_id);
        let terminal = inventory.entries()[0]
            .header()
            .terminal()
            .ok_or_else(|| std::io::Error::other("terminal summary missing"))?;
        assert_eq!(terminal.stdout().retained_bytes(), 1_000_000);
        assert_eq!(inventory.entries()[0].verification(), None);
        Ok(())
    }

    #[test]
    fn text_output_is_rejected_even_when_its_cast_length_is_valid()
    -> Result<(), Box<dyn std::error::Error>> {
        let (connection, workspace_id, activity_id) = fixture()?;
        let (_, _, execution_id) = ids(25);
        insert_execution(
            &connection,
            workspace_id,
            activity_id,
            execution_id,
            1,
            Some(4),
        )?;
        connection.execute_batch("PRAGMA ignore_check_constraints = ON")?;
        connection.execute(
            "UPDATE executions
             SET stdout = CAST(?1 AS TEXT), stdout_total_bytes = 4,
                 stdout_truncated = 0
             WHERE execution_id = ?2",
            params!["text", execution_id.into_uuid().as_bytes()],
        )?;
        connection.execute_batch("PRAGMA ignore_check_constraints = OFF")?;

        let result = inventory(
            &connection,
            workspace_id,
            ExecutionObservationSelection::new(activity_id, None),
            ExecutionListLimit::new(1)?,
        );
        assert!(matches!(
            result,
            Err(WorkspaceStoreError::Execution(
                ExecutionStoreError::CorruptRecord("execution.stdout")
            ))
        ));
        Ok(())
    }

    #[test]
    fn read_enforces_cursor_identity_and_goal_scope() -> Result<(), Box<dyn std::error::Error>> {
        let (connection, workspace_id, activity_id) = fixture()?;
        let (_, _, execution_id) = ids(30);
        let (_, _, other_execution_id) = ids(40);
        insert_execution(
            &connection,
            workspace_id,
            activity_id,
            execution_id,
            1,
            None,
        )?;
        insert_execution(
            &connection,
            workspace_id,
            activity_id,
            other_execution_id,
            2,
            None,
        )?;
        let selection = ExecutionObservationSelection::new(activity_id, None);
        let limits = (forge_domain::MIN_EXECUTION_OUTPUT_READ_BYTES, 1);
        assert!(matches!(
            read(
                &connection,
                workspace_id,
                selection,
                execution_id,
                ExecutionOutputCursor::initial(other_execution_id),
                limits.0,
                limits.1,
            ),
            Err(WorkspaceStoreError::Execution(
                ExecutionStoreError::InvalidOutputCursor
            ))
        ));
        let read = read(
            &connection,
            workspace_id,
            selection,
            execution_id,
            ExecutionOutputCursor::initial(execution_id),
            limits.0,
            limits.1,
        )?;
        assert_eq!(read.record().header().id(), execution_id);
        assert!(read.output().events().is_empty());
        Ok(())
    }

    #[test]
    fn observation_rejects_a_silent_output_sequence_skip() -> Result<(), Box<dyn std::error::Error>>
    {
        let (connection, workspace_id, activity_id) = fixture()?;
        let (_, _, execution_id) = ids(71);
        insert_execution(
            &connection,
            workspace_id,
            activity_id,
            execution_id,
            1,
            None,
        )?;
        connection.execute(
            "INSERT INTO execution_output_events(execution_id,sequence,event_kind,stream,bytes)
            VALUES (?1,2,0,0,?2)",
            params![
                execution_id.into_uuid().as_bytes(),
                b"missing first chunk".as_slice()
            ],
        )?;
        assert!(matches!(
            read(
                &connection,
                workspace_id,
                ExecutionObservationSelection::new(activity_id, None),
                execution_id,
                ExecutionOutputCursor::initial(execution_id),
                forge_domain::MIN_EXECUTION_OUTPUT_READ_BYTES,
                1
            ),
            Err(WorkspaceStoreError::Execution(
                ExecutionStoreError::CorruptRecord("execution_observation.output_coverage")
            ))
        ));
        Ok(())
    }

    #[test]
    fn corrupt_output_event_shape_remains_an_observation_error()
    -> Result<(), Box<dyn std::error::Error>> {
        let (connection, workspace_id, activity_id) = fixture()?;
        let (_, _, execution_id) = ids(50);
        insert_execution(
            &connection,
            workspace_id,
            activity_id,
            execution_id,
            1,
            None,
        )?;
        connection.execute_batch("PRAGMA ignore_check_constraints = ON")?;
        connection.execute(
            "INSERT INTO execution_output_events(execution_id, sequence, event_kind, stream, bytes)
             VALUES (?1, 1, 0, 0, NULL)",
            params![execution_id.into_uuid().as_bytes()],
        )?;
        connection.execute_batch("PRAGMA ignore_check_constraints = OFF")?;
        let result = read(
            &connection,
            workspace_id,
            ExecutionObservationSelection::new(activity_id, None),
            execution_id,
            ExecutionOutputCursor::initial(execution_id),
            forge_domain::MIN_EXECUTION_OUTPUT_READ_BYTES,
            1,
        );
        assert!(matches!(
            result,
            Err(WorkspaceStoreError::Execution(
                ExecutionStoreError::CorruptRecord(_)
            ))
        ));
        Ok(())
    }
}
