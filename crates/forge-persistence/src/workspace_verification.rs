//! Durable verification-input and verification-run evidence.
//!
//! The verification tables are deliberately kept in this adapter. The source
//! snapshot and the output auditor own their native effects; this module owns
//! the `SQLite` identity, replay, and requirement-link records which make those
//! effects attributable and restart-safe.

use forge_domain::{
    BeginExecution, ExecutionCommandId, ExecutionId, ExecutionMode, FileByteCount, FileContentHash,
    GoalId, GoalRevision, MAX_VERIFICATION_PROJECTION_ENTRIES, ProjectCommandCatalogFingerprint,
    ProjectCommandClass, TimestampMillis, VerificationInputEvidence, VerificationInputFingerprint,
    VerificationInputId, VerificationInputPolicy, VerificationOutputFingerprint,
    VerificationOutputIntegrity, VerificationProjection, VerificationProjectionEntry,
    VerificationRequirementAssociation, VerificationRun, VerificationRunDisposition,
    VerificationRunState, VerificationRunTerminalStatus, WorkspaceId,
};
use rusqlite::{Connection, OptionalExtension, Row, Transaction, params};
use thiserror::Error;

use crate::workspace_executions::BeginExecutionStatus;

const MAX_VERIFICATION_INPUT_FILES_I64: i64 = 4_096;
const MAX_VERIFICATION_INPUT_BYTES: u64 = 64 * 1024 * 1024;
const ID_BYTES: usize = 16;

/// Canonical SQL for the immutable verification-input identity.
pub(crate) const EXPECTED_VERIFICATION_INPUTS_TABLE_SQL: &str = "CREATE TABLE verification_inputs (input_id BLOB PRIMARY KEY NOT NULL CHECK(length(input_id) = 16), workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16), policy INTEGER NOT NULL CHECK(policy = 1), fingerprint BLOB NOT NULL CHECK(length(fingerprint) = 32), file_count INTEGER NOT NULL CHECK(file_count BETWEEN 0 AND 4096), total_bytes INTEGER NOT NULL CHECK(total_bytes BETWEEN 0 AND 67108864), created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0), revision INTEGER NOT NULL CHECK(revision = 1))";

/// Canonical SQL for one verification execution and its output audit.
pub(crate) const EXPECTED_VERIFICATION_RUNS_TABLE_SQL: &str = "CREATE TABLE verification_runs (execution_id BLOB PRIMARY KEY NOT NULL REFERENCES executions(execution_id) CHECK(length(execution_id) = 16), workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16), input_id BLOB NOT NULL UNIQUE REFERENCES verification_inputs(input_id) CHECK(length(input_id) = 16), state INTEGER NOT NULL CHECK(state IN (0, 1, 2, 3, 4)), output_integrity INTEGER CHECK(output_integrity IS NULL OR output_integrity IN (0, 1, 2, 3)), output_fingerprint BLOB CHECK(output_fingerprint IS NULL OR length(output_fingerprint) = 32), created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0), updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= created_at_ms), revision INTEGER NOT NULL CHECK(revision >= 1), CHECK((state = 0 AND output_integrity IS NULL AND output_fingerprint IS NULL) OR (state = 1 AND output_integrity = 0 AND output_fingerprint IS NOT NULL) OR (state = 2 AND output_integrity IS NOT NULL AND output_fingerprint IS NOT NULL) OR (state = 3 AND output_integrity IN (1, 2, 3) AND output_fingerprint IS NOT NULL) OR (state = 4 AND ((output_integrity IS NULL AND output_fingerprint IS NULL) OR (output_integrity IS NOT NULL AND output_fingerprint IS NOT NULL)))))";

/// Canonical SQL for the derived Goal requirement associations.
pub(crate) const EXPECTED_VERIFICATION_REQUIREMENT_LINKS_TABLE_SQL: &str = "CREATE TABLE verification_requirement_links (execution_id BLOB NOT NULL REFERENCES verification_runs(execution_id) CHECK(length(execution_id) = 16), goal_id BLOB NOT NULL REFERENCES goals(goal_id) CHECK(length(goal_id) = 16), goal_revision INTEGER NOT NULL CHECK(goal_revision >= 1), ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 0 AND 31), PRIMARY KEY(execution_id, goal_id, goal_revision, ordinal))";

pub(crate) const EXPECTED_VERIFICATION_REQUIREMENT_LINKS_GOAL_INDEX_SQL: &str = "CREATE INDEX verification_requirement_links_goal_idx ON verification_requirement_links(goal_id, goal_revision, ordinal, execution_id)";

const EXPECTED_VERIFICATION_INPUT_COLUMNS: [(&str, &str, i64, i64); 8] = [
    ("input_id", "BLOB", 1, 1),
    ("workspace_id", "BLOB", 1, 0),
    ("policy", "INTEGER", 1, 0),
    ("fingerprint", "BLOB", 1, 0),
    ("file_count", "INTEGER", 1, 0),
    ("total_bytes", "INTEGER", 1, 0),
    ("created_at_ms", "INTEGER", 1, 0),
    ("revision", "INTEGER", 1, 0),
];

const EXPECTED_VERIFICATION_RUN_COLUMNS: [(&str, &str, i64, i64); 9] = [
    ("execution_id", "BLOB", 1, 1),
    ("workspace_id", "BLOB", 1, 0),
    ("input_id", "BLOB", 1, 0),
    ("state", "INTEGER", 1, 0),
    ("output_integrity", "INTEGER", 0, 0),
    ("output_fingerprint", "BLOB", 0, 0),
    ("created_at_ms", "INTEGER", 1, 0),
    ("updated_at_ms", "INTEGER", 1, 0),
    ("revision", "INTEGER", 1, 0),
];

const EXPECTED_VERIFICATION_REQUIREMENT_LINK_COLUMNS: [(&str, &str, i64, i64); 4] = [
    ("execution_id", "BLOB", 1, 1),
    ("goal_id", "BLOB", 1, 2),
    ("goal_revision", "INTEGER", 1, 3),
    ("ordinal", "INTEGER", 1, 4),
];

/// Raw persistence representation of one immutable verification input.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RawVerificationInput {
    input_id: VerificationInputId,
    workspace_id: WorkspaceId,
    policy: VerificationInputPolicy,
    fingerprint: VerificationInputFingerprint,
    file_count: u32,
    total_bytes: FileByteCount,
    created_at: TimestampMillis,
    revision: i64,
}

impl RawVerificationInput {
    pub(crate) const fn input_id(&self) -> VerificationInputId {
        self.input_id
    }

    pub(crate) const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub(crate) const fn policy(&self) -> VerificationInputPolicy {
        self.policy
    }

    pub(crate) const fn fingerprint(&self) -> VerificationInputFingerprint {
        self.fingerprint
    }

    pub(crate) const fn file_count(&self) -> u32 {
        self.file_count
    }

    pub(crate) const fn total_bytes(&self) -> FileByteCount {
        self.total_bytes
    }

    pub(crate) const fn created_at(&self) -> TimestampMillis {
        self.created_at
    }

    pub(crate) const fn revision(&self) -> i64 {
        self.revision
    }

    fn to_domain(self) -> Result<VerificationInputEvidence, VerificationStoreError> {
        VerificationInputEvidence::from_parts(
            self.input_id,
            self.fingerprint,
            self.policy,
            self.file_count,
            self.total_bytes,
        )
        .map_err(|_| VerificationStoreError::CorruptRecord("verification_inputs.evidence"))
    }
}

/// Raw persistence representation of one verification run.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RawVerificationRun {
    execution_id: ExecutionId,
    workspace_id: WorkspaceId,
    input_id: VerificationInputId,
    catalog_fingerprint: Option<ProjectCommandCatalogFingerprint>,
    state: VerificationRunState,
    created_at: TimestampMillis,
    updated_at: TimestampMillis,
    revision: i64,
}

impl RawVerificationRun {
    pub(crate) const fn execution_id(&self) -> ExecutionId {
        self.execution_id
    }

    pub(crate) const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub(crate) const fn input_id(&self) -> VerificationInputId {
        self.input_id
    }

    pub(crate) const fn catalog_fingerprint(&self) -> Option<ProjectCommandCatalogFingerprint> {
        self.catalog_fingerprint
    }

    pub(crate) const fn state(&self) -> VerificationRunState {
        self.state
    }

    pub(crate) const fn created_at(&self) -> TimestampMillis {
        self.created_at
    }

    pub(crate) const fn updated_at(&self) -> TimestampMillis {
        self.updated_at
    }

    pub(crate) const fn revision(&self) -> i64 {
        self.revision
    }
}

fn run_to_domain(
    run: &RawVerificationRun,
    input: &RawVerificationInput,
) -> Result<VerificationRun, VerificationStoreError> {
    if input.workspace_id() != run.workspace_id() || input.input_id() != run.input_id() {
        return Err(VerificationStoreError::CorruptRecord(
            "verification_runs.input_binding",
        ));
    }
    VerificationRun::from_parts(
        run.execution_id(),
        run.workspace_id(),
        input.to_domain()?,
        run.catalog_fingerprint(),
        run.state(),
    )
    .map_err(|_| VerificationStoreError::CorruptRecord("verification_runs.evidence"))
}

/// One derived association between an execution and a current Goal
/// requirement.  The ordinal is always read from Goal storage; callers cannot
/// supply it to the begin/replay API.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RawVerificationRequirementAssociation {
    execution_id: ExecutionId,
    goal_id: GoalId,
    goal_revision: GoalRevision,
    ordinal: u8,
}

impl RawVerificationRequirementAssociation {
    pub(crate) const fn execution_id(&self) -> ExecutionId {
        self.execution_id
    }

    pub(crate) const fn goal_id(&self) -> GoalId {
        self.goal_id
    }

    pub(crate) const fn goal_revision(&self) -> GoalRevision {
        self.goal_revision
    }

    pub(crate) const fn ordinal(&self) -> u8 {
        self.ordinal
    }
}

fn requirement_to_domain(
    requirement: RawVerificationRequirementAssociation,
) -> Result<VerificationRequirementAssociation, VerificationStoreError> {
    VerificationRequirementAssociation::new(
        requirement.execution_id(),
        requirement.goal_id(),
        requirement.goal_revision(),
        u16::from(requirement.ordinal()),
    )
    .map_err(|_| VerificationStoreError::CorruptRecord("verification_requirement_links.ordinal"))
}

/// Result of a verification begin/replay operation.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationBeginResult {
    status: BeginExecutionStatus,
    run: VerificationRun,
    requirements: Vec<VerificationRequirementAssociation>,
}

impl VerificationBeginResult {
    pub const fn status(&self) -> BeginExecutionStatus {
        self.status
    }

    pub const fn run(&self) -> &VerificationRun {
        &self.run
    }

    pub fn requirements(&self) -> &[VerificationRequirementAssociation] {
        &self.requirements
    }
}

/// Persistence failures and fail-closed evidence violations for verification.
#[derive(Debug, Error)]
pub enum VerificationStoreError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error("verification schema object {0} is damaged or missing")]
    DamagedSchema(&'static str),
    #[error("verification record field {0} is corrupt")]
    CorruptRecord(&'static str),
    #[error("verification identity conflicts with an immutable record")]
    IdentityConflict,
    #[error("execution {0} is missing from the Workspace database")]
    ExecutionMissing(ExecutionId),
    #[error("verification requires Agent execution provenance")]
    ProvenanceRequired,
    #[error("verification requires durable project-command evidence")]
    ProjectCommandEvidenceRequired,
    #[error("legacy execution {0} has no verification run")]
    LegacyExecutionNoVerificationRun(ExecutionId),
    #[error("verification execution and Workspace identities do not match")]
    WorkspaceMismatch,
    #[error("Goal {0} is missing for verification requirement derivation")]
    GoalMissing(GoalId),
    #[error("Goal revision in execution provenance is not current")]
    GoalRevisionMismatch,
    #[error("verification input policy is unsupported")]
    UnsupportedInputPolicy,
    #[error("verification input metadata exceeds its persistence bound")]
    InputBounds,
    #[error("verification integer is outside its checked range")]
    IntegerOverflow,
}

/// Create all v31 verification objects from the one canonical DDL source.
pub(crate) fn create_schema(connection: &Connection) -> Result<(), VerificationStoreError> {
    create_schema_objects(connection)
}

/// Add all v31 verification objects inside the caller-owned v30→v31
/// transaction.  Keeping this path on the same DDL authority prevents fresh
/// and migrated databases from drifting.
pub(crate) fn migrate_to_v31(transaction: &Transaction<'_>) -> Result<(), VerificationStoreError> {
    create_schema_objects(transaction)
}

fn create_schema_objects(connection: &Connection) -> Result<(), VerificationStoreError> {
    for sql in [
        EXPECTED_VERIFICATION_INPUTS_TABLE_SQL,
        EXPECTED_VERIFICATION_RUNS_TABLE_SQL,
        EXPECTED_VERIFICATION_REQUIREMENT_LINKS_TABLE_SQL,
        EXPECTED_VERIFICATION_REQUIREMENT_LINKS_GOAL_INDEX_SQL,
    ] {
        connection.execute_batch(sql)?;
    }
    Ok(())
}

pub(crate) fn schema_objects() -> [(&'static str, &'static str); 4] {
    [
        ("table", "verification_inputs"),
        ("table", "verification_runs"),
        ("table", "verification_requirement_links"),
        ("index", "verification_requirement_links_goal_idx"),
    ]
}

/// Validate SQL identity, columns, indexes, and foreign-key targets for v31.
pub(crate) fn validate_schema(connection: &Connection) -> Result<(), VerificationStoreError> {
    validate_schema_sql(
        connection,
        "table",
        "verification_inputs",
        EXPECTED_VERIFICATION_INPUTS_TABLE_SQL,
    )?;
    validate_schema_sql(
        connection,
        "table",
        "verification_runs",
        EXPECTED_VERIFICATION_RUNS_TABLE_SQL,
    )?;
    validate_schema_sql(
        connection,
        "table",
        "verification_requirement_links",
        EXPECTED_VERIFICATION_REQUIREMENT_LINKS_TABLE_SQL,
    )?;
    validate_schema_sql(
        connection,
        "index",
        "verification_requirement_links_goal_idx",
        EXPECTED_VERIFICATION_REQUIREMENT_LINKS_GOAL_INDEX_SQL,
    )?;

    validate_table_columns(
        connection,
        "verification_inputs",
        &EXPECTED_VERIFICATION_INPUT_COLUMNS,
    )?;
    validate_table_columns(
        connection,
        "verification_runs",
        &EXPECTED_VERIFICATION_RUN_COLUMNS,
    )?;
    validate_table_columns(
        connection,
        "verification_requirement_links",
        &EXPECTED_VERIFICATION_REQUIREMENT_LINK_COLUMNS,
    )?;
    validate_index_columns(
        connection,
        "verification_requirement_links_goal_idx",
        &["goal_id", "goal_revision", "ordinal", "execution_id"],
    )?;

    validate_foreign_keys(
        connection,
        "verification_inputs",
        &[("workspace", "workspace_id", "workspace_id")],
    )?;
    validate_foreign_keys(
        connection,
        "verification_runs",
        &[
            ("executions", "execution_id", "execution_id"),
            ("workspace", "workspace_id", "workspace_id"),
            ("verification_inputs", "input_id", "input_id"),
        ],
    )?;
    validate_foreign_keys(
        connection,
        "verification_requirement_links",
        &[
            ("verification_runs", "execution_id", "execution_id"),
            ("goals", "goal_id", "goal_id"),
        ],
    )
}

/// Begin or exactly replay a verification run in the execution transaction.
///
/// A replay is accepted only when the immutable input identity and durable
/// project-command catalog evidence match the stored run.  A legacy execution
/// which predates the verification tables is rejected instead of being
/// silently upgraded.
pub(crate) fn begin_or_replay_in_transaction(
    transaction: &Transaction<'_>,
    command: &BeginExecution,
    evidence: VerificationInputEvidence,
    status: BeginExecutionStatus,
) -> Result<VerificationBeginResult, VerificationStoreError> {
    validate_input_evidence(evidence)?;
    let provenance = command
        .provenance()
        .ok_or(VerificationStoreError::ProvenanceRequired)?;
    if provenance.execution_id() != command.id() {
        return Err(VerificationStoreError::IdentityConflict);
    }

    let catalog_fingerprint =
        validate_execution_evidence(transaction, command, provenance.project_command())?;

    if let Some(run) = get_run_tx(transaction, command.id())? {
        let input = get_input_tx(transaction, run.input_id())?.ok_or(
            VerificationStoreError::CorruptRecord("verification_runs.input_id"),
        )?;
        if !input_matches(&input, command.workspace_id(), evidence)
            || run.workspace_id() != command.workspace_id()
            || run.catalog_fingerprint() != catalog_fingerprint
        {
            return Err(VerificationStoreError::IdentityConflict);
        }
        let requirements = get_requirement_links_tx(transaction, command.id())?
            .into_iter()
            .map(requirement_to_domain)
            .collect::<Result<Vec<_>, _>>()?;
        return Ok(VerificationBeginResult {
            status: BeginExecutionStatus::Existing,
            run: run_to_domain(&run, &input)?,
            requirements,
        });
    }

    if status == BeginExecutionStatus::Existing {
        return Err(VerificationStoreError::LegacyExecutionNoVerificationRun(
            command.id(),
        ));
    }

    insert_input(
        transaction,
        command.workspace_id(),
        evidence,
        command.observed_at(),
    )?;
    let input = get_input_tx(transaction, evidence.input_id())?.ok_or(
        VerificationStoreError::CorruptRecord("verification_inputs.input_id"),
    )?;
    if !input_matches(&input, command.workspace_id(), evidence) {
        return Err(VerificationStoreError::IdentityConflict);
    }

    transaction.execute(
        "INSERT INTO verification_runs (
            execution_id, workspace_id, input_id, state,
            output_integrity, output_fingerprint, created_at_ms, updated_at_ms, revision
         ) VALUES (?1, ?2, ?3, 0, NULL, NULL, ?4, ?4, 1)",
        params![
            command.id().into_uuid().as_bytes(),
            command.workspace_id().into_uuid().as_bytes(),
            evidence.input_id().into_uuid().as_bytes(),
            command.observed_at().get(),
        ],
    )?;
    let requirements = derive_requirement_links(transaction, command, provenance)?;
    for requirement in &requirements {
        transaction.execute(
            "INSERT INTO verification_requirement_links (
                execution_id, goal_id, goal_revision, ordinal
             ) VALUES (?1, ?2, ?3, ?4)",
            params![
                requirement.execution_id().into_uuid().as_bytes(),
                requirement.goal_id().into_uuid().as_bytes(),
                requirement.goal_revision().get(),
                i64::from(requirement.ordinal()),
            ],
        )?;
    }
    let run = get_run_tx(transaction, command.id())?.ok_or(
        VerificationStoreError::CorruptRecord("verification_runs.execution_id"),
    )?;
    let requirements = requirements
        .into_iter()
        .map(requirement_to_domain)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(VerificationBeginResult {
        status: BeginExecutionStatus::Created,
        run: run_to_domain(&run, &input)?,
        requirements,
    })
}

/// Admit an optional verification launch through the same exact replay path.
///
/// Ordinary executions may omit verification evidence.  Once a verification
/// run exists, however, omitting its evidence is an identity conflict; and a
/// newly created execution carrying project-command evidence must provide the
/// frozen input that command requires.
pub(crate) fn begin_optional_or_replay_in_transaction(
    transaction: &Transaction<'_>,
    command: &BeginExecution,
    evidence: Option<VerificationInputEvidence>,
    status: BeginExecutionStatus,
) -> Result<Option<VerificationBeginResult>, VerificationStoreError> {
    let Some(evidence) = evidence else {
        if get_run_tx(transaction, command.id())?.is_some() {
            return Err(VerificationStoreError::IdentityConflict);
        }
        if status == BeginExecutionStatus::Created
            && command
                .provenance()
                .is_some_and(|provenance| provenance.project_command().is_some())
        {
            return Err(VerificationStoreError::ProjectCommandEvidenceRequired);
        }
        return Ok(None);
    };
    begin_or_replay_in_transaction(transaction, command, evidence, status).map(Some)
}

#[cfg(test)]
pub(crate) fn get_verification_run(
    connection: &Connection,
    id: ExecutionId,
) -> Result<Option<VerificationRun>, VerificationStoreError> {
    let Some(run) = get_run(connection, id)? else {
        return Ok(None);
    };
    let input = get_input(connection, run.input_id())?.ok_or(
        VerificationStoreError::CorruptRecord("verification_runs.input_id"),
    )?;
    run_to_domain(&run, &input).map(Some)
}

#[cfg(test)]
pub(crate) fn get_verification_requirement_links(
    connection: &Connection,
    execution_id: ExecutionId,
) -> Result<Vec<VerificationRequirementAssociation>, VerificationStoreError> {
    get_requirement_links(connection, execution_id)?
        .into_iter()
        .map(requirement_to_domain)
        .collect()
}

/// Finalize only an existing immutable run from the durable execution/output
/// ledger. The execution owner calls this inside its terminal transaction;
/// no caller-provided disposition or external effect enters this boundary.
pub(crate) fn finalize_in_transaction(
    transaction: &Transaction<'_>,
    execution: &forge_domain::RegisteredExecution,
) -> Result<Option<VerificationRun>, crate::workspace_executions::ExecutionStoreError> {
    use crate::workspace_executions::ExecutionStoreError;

    if !execution.state().is_terminal() {
        return Err(ExecutionStoreError::InvalidTransition);
    }
    let Some(raw) = get_run_tx(transaction, execution.id())? else {
        // Ordinary and historical executions do not acquire fabricated proof.
        return Ok(None);
    };
    let input = get_input_tx(transaction, raw.input_id())?.ok_or(
        VerificationStoreError::CorruptRecord("verification_runs.input_id"),
    )?;
    let run = run_to_domain(&raw, &input)?;
    if run.workspace_id() != execution.workspace_id()
        || raw.created_at() != execution.timestamps().created_at()
        || input.created_at().get() > raw.created_at().get()
    {
        return Err(VerificationStoreError::IdentityConflict.into());
    }
    let observed_at = execution.timestamps().updated_at();
    let status = crate::workspace_executions::verification_output_status(transaction, execution)?;
    if let Some(existing) = run.terminal_status() {
        return if existing == status && raw.updated_at() == observed_at {
            Ok(Some(run))
        } else {
            Err(VerificationStoreError::IdentityConflict.into())
        };
    }
    if observed_at.get() < raw.updated_at().get() {
        return Err(ExecutionStoreError::TimestampOrder);
    }
    let finished = run.finish(status).map_err(|_| {
        VerificationStoreError::CorruptRecord("verification_runs.terminal_transition")
    })?;
    let next_revision = raw
        .revision()
        .checked_add(1)
        .ok_or(ExecutionStoreError::RevisionOverflow)?;
    let fingerprint = status.output_fingerprint();
    let changed = transaction.execute(
        "UPDATE verification_runs
         SET state = ?1, output_integrity = ?2, output_fingerprint = ?3,
             updated_at_ms = ?4, revision = ?5
         WHERE execution_id = ?6 AND state = 0 AND revision = ?7",
        params![
            encode_disposition(status.disposition()),
            status.output_integrity().map(encode_output_integrity),
            fingerprint
                .as_ref()
                .map(|value| value.as_bytes().as_slice()),
            observed_at.get(),
            next_revision,
            execution.id().into_uuid().as_bytes(),
            raw.revision(),
        ],
    )?;
    if changed != 1 {
        return Err(ExecutionStoreError::RevisionConflict);
    }
    crate::workspace_semantic_events::append_semantic_event(
        transaction,
        &crate::workspace_semantic_events::SemanticEventAppend::new(
            crate::workspace_semantic_events::SemanticEventKind::VerificationFinalized,
            execution.workspace_id(),
            crate::workspace_semantic_events::SemanticEventSubjects {
                execution_id: Some(execution.id()),
                verification: Some(run.input_id()),
                ..crate::workspace_semantic_events::SemanticEventSubjects::NONE
            },
            execution.revision().get(),
            observed_at,
        ),
    )?;
    Ok(Some(finished))
}

const fn encode_disposition(disposition: VerificationRunDisposition) -> i64 {
    match disposition {
        VerificationRunDisposition::Accepted => 1,
        VerificationRunDisposition::Rejected => 2,
        VerificationRunDisposition::Incomplete => 3,
        VerificationRunDisposition::RecoveryRequired => 4,
    }
}

const fn encode_output_integrity(integrity: VerificationOutputIntegrity) -> i64 {
    match integrity {
        VerificationOutputIntegrity::Complete => 0,
        VerificationOutputIntegrity::Gapped => 1,
        VerificationOutputIntegrity::Truncated => 2,
        VerificationOutputIntegrity::GappedAndTruncated => 3,
    }
}

fn get_input(
    connection: &Connection,
    id: VerificationInputId,
) -> Result<Option<RawVerificationInput>, VerificationStoreError> {
    connection
        .query_row(
            "SELECT input_id, workspace_id, policy, fingerprint, file_count,
                    total_bytes, created_at_ms, revision
             FROM verification_inputs WHERE input_id = ?1",
            params![id.into_uuid().as_bytes()],
            decode_input_row,
        )
        .optional()
        .map_err(VerificationStoreError::from)
}

fn get_input_tx(
    transaction: &Transaction<'_>,
    id: VerificationInputId,
) -> Result<Option<RawVerificationInput>, VerificationStoreError> {
    get_input(transaction, id)
}

fn get_run(
    connection: &Connection,
    id: ExecutionId,
) -> Result<Option<RawVerificationRun>, VerificationStoreError> {
    connection
        .query_row(
            "SELECT r.execution_id, r.workspace_id, r.input_id, r.state, r.output_integrity,
                    r.output_fingerprint, r.created_at_ms,
                    r.updated_at_ms, r.revision, e.catalog_fingerprint
             FROM verification_runs AS r
             LEFT JOIN execution_command_evidence AS e ON e.execution_id = r.execution_id
             WHERE r.execution_id = ?1",
            params![id.into_uuid().as_bytes()],
            decode_run_row,
        )
        .optional()
        .map_err(VerificationStoreError::from)
}

fn get_run_tx(
    transaction: &Transaction<'_>,
    id: ExecutionId,
) -> Result<Option<RawVerificationRun>, VerificationStoreError> {
    get_run(transaction, id)
}

pub(crate) fn projection(
    connection: &Connection,
    workspace_id: WorkspaceId,
) -> Result<VerificationProjection, VerificationStoreError> {
    let limit = i64::try_from(MAX_VERIFICATION_PROJECTION_ENTRIES)
        .map_err(|_| VerificationStoreError::CorruptRecord("verification_projection.limit"))?;
    // Harness polls this projection. Keep the immutable input in the same
    // ranked row so one refresh stays one SQLite statement instead of an
    // additional input lookup for every projected command.
    let mut statement = connection.prepare(
        "WITH ranked AS (
             SELECT r.execution_id, r.workspace_id, r.input_id, r.state,
                    r.output_integrity, r.output_fingerprint, r.created_at_ms,
                    r.updated_at_ms, r.revision, e.catalog_fingerprint, p.command_id,
                    i.workspace_id AS input_workspace_id, i.policy AS input_policy,
                    i.fingerprint AS input_fingerprint, i.file_count AS input_file_count,
                    i.total_bytes AS input_total_bytes,
                    i.created_at_ms AS input_created_at_ms,
                    i.revision AS input_revision,
                    ROW_NUMBER() OVER (
                        PARTITION BY p.command_id
                        ORDER BY r.updated_at_ms DESC, r.execution_id DESC
                    ) AS position
             FROM verification_runs AS r
             JOIN execution_provenance AS p ON p.execution_id = r.execution_id
             LEFT JOIN verification_inputs AS i ON i.input_id = r.input_id
             LEFT JOIN execution_command_evidence AS e ON e.execution_id = r.execution_id
             WHERE r.workspace_id = ?1
         )
         SELECT execution_id, workspace_id, input_id, state, output_integrity,
                output_fingerprint, created_at_ms, updated_at_ms, revision,
                catalog_fingerprint, command_id,
                input_id, input_workspace_id, input_policy, input_fingerprint,
                input_file_count, input_total_bytes, input_created_at_ms, input_revision
         FROM ranked
         WHERE position = 1
         ORDER BY command_id ASC
         LIMIT ?2",
    )?;
    let rows = statement.query_map(params![workspace_id.into_uuid().as_bytes(), limit], |row| {
        Ok((
            decode_run_row(row)?,
            row.get::<_, String>(10)?,
            decode_input_row_at(row, 11)?,
        ))
    })?;
    let mut entries = Vec::new();
    for row in rows {
        let (run, raw_command_id, input) = row?;
        let command_id = ExecutionCommandId::new(raw_command_id).map_err(|_| {
            VerificationStoreError::CorruptRecord("execution_provenance.command_id")
        })?;
        let domain_run = run_to_domain(&run, &input)?;
        entries.push(VerificationProjectionEntry::from_run(
            command_id,
            &domain_run,
            run.updated_at(),
        ));
    }
    VerificationProjection::new(entries)
        .map_err(|_| VerificationStoreError::CorruptRecord("verification_projection"))
}

/// Full immutable evidence for one observed execution. Caller owns the read
/// transaction and scope fence; no live Agent/session is manufactured here.
pub(crate) fn observation_snapshot(
    connection: &Connection,
    header: &forge_domain::ExecutionObservationHeader,
) -> Result<Option<forge_domain::VerificationEvidenceSnapshot>, VerificationStoreError> {
    let Some(run) = get_run(connection, header.id())? else {
        return Ok(None);
    };
    let input = get_input(connection, run.input_id())?.ok_or(
        VerificationStoreError::CorruptRecord("verification_runs.input_missing"),
    )?;
    let requirements = get_requirement_links(connection, header.id())?
        .into_iter()
        .map(requirement_to_domain)
        .collect::<Result<Vec<_>, _>>()?;
    let revision = u64::try_from(run.revision())
        .map_err(|_| VerificationStoreError::CorruptRecord("verification_runs.revision"))?;
    forge_domain::VerificationEvidenceSnapshot::new(
        header,
        run_to_domain(&run, &input)?,
        run.created_at(),
        run.updated_at(),
        revision,
        requirements,
    )
    .map(Some)
    .map_err(|_| VerificationStoreError::CorruptRecord("verification_observation.evidence"))
}

fn get_requirement_links(
    connection: &Connection,
    execution_id: ExecutionId,
) -> Result<Vec<RawVerificationRequirementAssociation>, VerificationStoreError> {
    let mut statement = connection.prepare(
        "SELECT execution_id, goal_id, goal_revision, ordinal
         FROM verification_requirement_links
         WHERE execution_id = ?1
         ORDER BY goal_id ASC, goal_revision ASC, ordinal ASC",
    )?;
    let rows = statement.query_map(
        params![execution_id.into_uuid().as_bytes()],
        decode_requirement_row,
    )?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(VerificationStoreError::from)
}

fn get_requirement_links_tx(
    transaction: &Transaction<'_>,
    execution_id: ExecutionId,
) -> Result<Vec<RawVerificationRequirementAssociation>, VerificationStoreError> {
    get_requirement_links(transaction, execution_id)
}

fn validate_input_evidence(
    evidence: VerificationInputEvidence,
) -> Result<(), VerificationStoreError> {
    if evidence.policy() != VerificationInputPolicy::V1 {
        return Err(VerificationStoreError::UnsupportedInputPolicy);
    }
    if u64::from(evidence.file_count()) > MAX_VERIFICATION_INPUT_FILES_I64 as u64
        || evidence.total_bytes().get() > MAX_VERIFICATION_INPUT_BYTES
    {
        return Err(VerificationStoreError::InputBounds);
    }
    Ok(())
}

fn validate_execution_evidence(
    transaction: &Transaction<'_>,
    command: &BeginExecution,
    project_command: Option<forge_domain::ProjectCommandEvidence>,
) -> Result<Option<ProjectCommandCatalogFingerprint>, VerificationStoreError> {
    let execution = transaction
        .query_row(
            "SELECT workspace_id, request_digest
             FROM executions WHERE execution_id = ?1",
            params![command.id().into_uuid().as_bytes()],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()?;
    let Some((workspace, request_digest)) = execution else {
        return Err(VerificationStoreError::ExecutionMissing(command.id()));
    };
    if workspace.as_slice() != command.workspace_id().into_uuid().as_bytes()
        || request_digest.as_slice() != command.request_digest().as_bytes()
    {
        return Err(VerificationStoreError::IdentityConflict);
    }
    let durable_evidence = transaction
        .query_row(
            "SELECT command_class, catalog_fingerprint
             FROM execution_command_evidence WHERE execution_id = ?1",
            params![command.id().into_uuid().as_bytes()],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()?;
    let Some((class, fingerprint)) = durable_evidence else {
        if project_command.is_none() && command.mode() == ExecutionMode::Shell {
            return Ok(None);
        }
        return Err(VerificationStoreError::ProjectCommandEvidenceRequired);
    };
    let Some(project_command) = project_command else {
        return Ok(Some(decode_catalog_fingerprint(fingerprint)?));
    };
    if class != encode_project_command_class(project_command.class())
        || fingerprint.as_slice() != project_command.catalog_fingerprint().hash().as_bytes()
    {
        return Err(VerificationStoreError::IdentityConflict);
    }
    Ok(Some(project_command.catalog_fingerprint()))
}

fn insert_input(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
    evidence: VerificationInputEvidence,
    created_at: TimestampMillis,
) -> Result<(), VerificationStoreError> {
    if crate::workspace_goal_deletion::artifact_identity_is_pending(
        transaction,
        crate::workspace_goal_deletion::GoalDeletionArtifactIdentity::VerificationInput(
            evidence.input_id(),
        ),
    )? {
        return Err(VerificationStoreError::IdentityConflict);
    }
    let inserted = transaction.execute(
        "INSERT INTO verification_inputs (
            input_id, workspace_id, policy, fingerprint, file_count, total_bytes,
            created_at_ms, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1)
         ON CONFLICT(input_id) DO NOTHING",
        params![
            evidence.input_id().into_uuid().as_bytes(),
            workspace_id.into_uuid().as_bytes(),
            i64::from(evidence.policy().version()),
            evidence.fingerprint().as_bytes(),
            i64::from(evidence.file_count()),
            i64::try_from(evidence.total_bytes().get())
                .map_err(|_| VerificationStoreError::IntegerOverflow)?,
            created_at.get(),
        ],
    )?;
    if inserted == 0 {
        let linked: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT execution_id FROM verification_runs WHERE input_id = ?1",
                params![evidence.input_id().into_uuid().as_bytes()],
                |row| row.get(0),
            )
            .optional()?;
        if linked.is_some() {
            return Err(VerificationStoreError::IdentityConflict);
        }
    }
    Ok(())
}

fn input_matches(
    actual: &RawVerificationInput,
    workspace_id: WorkspaceId,
    expected: VerificationInputEvidence,
) -> bool {
    actual.workspace_id() == workspace_id
        && actual.input_id() == expected.input_id()
        && actual.policy() == expected.policy()
        && actual.fingerprint() == expected.fingerprint()
        && actual.file_count() == expected.file_count()
        && actual.total_bytes() == expected.total_bytes()
        && actual.revision() == 1
}

fn derive_requirement_links(
    transaction: &Transaction<'_>,
    command: &BeginExecution,
    provenance: &forge_domain::ExecutionAgentProvenance,
) -> Result<Vec<RawVerificationRequirementAssociation>, VerificationStoreError> {
    let attribution = provenance.attribution();
    let goal = transaction
        .query_row(
            "SELECT workspace_id, revision
             FROM goals WHERE goal_id = ?1",
            params![attribution.goal_id().into_uuid().as_bytes()],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()?;
    let Some((workspace_id, revision)) = goal else {
        return Err(VerificationStoreError::GoalMissing(attribution.goal_id()));
    };
    if workspace_id.as_slice() != command.workspace_id().into_uuid().as_bytes() {
        return Err(VerificationStoreError::WorkspaceMismatch);
    }
    if revision != attribution.expected_goal_revision().get() {
        return Err(VerificationStoreError::GoalRevisionMismatch);
    }
    let goal_revision = GoalRevision::new(revision)
        .map_err(|_| VerificationStoreError::CorruptRecord("goals.revision"))?;
    let mut statement = transaction.prepare(
        "SELECT ordinal
         FROM goal_verification_requirements
         WHERE goal_id = ?1
           AND requirement_kind = 0
           AND execution_digest = ?2
         ORDER BY ordinal ASC",
    )?;
    let rows = statement.query_map(
        params![
            attribution.goal_id().into_uuid().as_bytes(),
            command.request_digest().as_bytes(),
        ],
        |row| row.get::<_, i64>(0),
    )?;
    let mut requirements = Vec::new();
    for row in rows {
        let ordinal = row?;
        let ordinal = u8::try_from(ordinal)
            .ok()
            .filter(|ordinal| *ordinal <= 31)
            .ok_or(VerificationStoreError::CorruptRecord(
                "goal_verification_requirements.ordinal",
            ))?;
        requirements.push(RawVerificationRequirementAssociation {
            execution_id: command.id(),
            goal_id: attribution.goal_id(),
            goal_revision,
            ordinal,
        });
    }
    Ok(requirements)
}

fn decode_input_row(row: &Row<'_>) -> rusqlite::Result<RawVerificationInput> {
    decode_input_row_inner(row).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Blob, Box::new(error))
    })
}

fn decode_input_row_at(row: &Row<'_>, offset: usize) -> rusqlite::Result<RawVerificationInput> {
    decode_input_row_inner_at(row, offset).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            offset,
            rusqlite::types::Type::Blob,
            Box::new(error),
        )
    })
}

fn decode_input_row_inner(row: &Row<'_>) -> Result<RawVerificationInput, VerificationStoreError> {
    decode_input_row_inner_at(row, 0)
}

fn decode_input_row_inner_at(
    row: &Row<'_>,
    offset: usize,
) -> Result<RawVerificationInput, VerificationStoreError> {
    let raw_input_id = row.get::<_, Vec<u8>>(offset)?;
    let raw_workspace_id = row.get::<_, Vec<u8>>(offset + 1)?;
    let input_id = decode_input_id(&raw_input_id)?;
    let workspace_id = decode_workspace_id(&raw_workspace_id)?;
    let policy = decode_policy(row.get(offset + 2)?)?;
    let fingerprint = decode_input_fingerprint(row.get(offset + 3)?)?;
    let file_count = decode_file_count(row.get(offset + 4)?)?;
    let total_bytes = decode_total_bytes(row.get(offset + 5)?)?;
    let created_at = decode_timestamp(row.get(offset + 6)?, "verification_inputs.created_at_ms")?;
    let revision: i64 = row.get(offset + 7)?;
    if revision != 1 {
        return Err(VerificationStoreError::CorruptRecord(
            "verification_inputs.revision",
        ));
    }
    Ok(RawVerificationInput {
        input_id,
        workspace_id,
        policy,
        fingerprint,
        file_count,
        total_bytes,
        created_at,
        revision,
    })
}

fn decode_run_row(row: &Row<'_>) -> rusqlite::Result<RawVerificationRun> {
    decode_run_row_inner(row).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Blob, Box::new(error))
    })
}

fn decode_run_row_inner(row: &Row<'_>) -> Result<RawVerificationRun, VerificationStoreError> {
    let raw_execution_id = row.get::<_, Vec<u8>>(0)?;
    let raw_workspace_id = row.get::<_, Vec<u8>>(1)?;
    let raw_input_id = row.get::<_, Vec<u8>>(2)?;
    let execution_id = decode_execution_id(&raw_execution_id)?;
    let workspace_id = decode_workspace_id(&raw_workspace_id)?;
    let input_id = decode_input_id(&raw_input_id)?;
    let state_value: i64 = row.get(3)?;
    let output_integrity = row
        .get::<_, Option<i64>>(4)?
        .map(decode_output_integrity)
        .transpose()?;
    let output_fingerprint = row
        .get::<_, Option<Vec<u8>>>(5)?
        .map(decode_output_fingerprint)
        .transpose()?;
    let created_at = decode_timestamp(row.get(6)?, "verification_runs.created_at_ms")?;
    let updated_at = decode_timestamp(row.get(7)?, "verification_runs.updated_at_ms")?;
    let revision: i64 = row.get(8)?;
    let catalog_fingerprint = row
        .get::<_, Option<Vec<u8>>>(9)?
        .map(decode_catalog_fingerprint)
        .transpose()?;
    if revision < 1 || updated_at.get() < created_at.get() {
        return Err(VerificationStoreError::CorruptRecord(
            "verification_runs.revision_or_timestamp",
        ));
    }
    let state = decode_run_state(state_value, output_integrity, output_fingerprint)?;
    Ok(RawVerificationRun {
        execution_id,
        workspace_id,
        input_id,
        catalog_fingerprint,
        state,
        created_at,
        updated_at,
        revision,
    })
}

fn decode_requirement_row(
    row: &Row<'_>,
) -> rusqlite::Result<RawVerificationRequirementAssociation> {
    decode_requirement_row_inner(row).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Blob, Box::new(error))
    })
}

fn decode_requirement_row_inner(
    row: &Row<'_>,
) -> Result<RawVerificationRequirementAssociation, VerificationStoreError> {
    let raw_execution_id = row.get::<_, Vec<u8>>(0)?;
    let raw_goal_id = row.get::<_, Vec<u8>>(1)?;
    let execution_id = decode_execution_id(&raw_execution_id)?;
    let goal_id = decode_goal_id(&raw_goal_id)?;
    let goal_revision = GoalRevision::new(row.get(2)?).map_err(|_| {
        VerificationStoreError::CorruptRecord("verification_requirement_links.goal_revision")
    })?;
    let ordinal = u8::try_from(row.get::<_, i64>(3)?)
        .ok()
        .filter(|ordinal| *ordinal <= 31)
        .ok_or(VerificationStoreError::CorruptRecord(
            "verification_requirement_links.ordinal",
        ))?;
    Ok(RawVerificationRequirementAssociation {
        execution_id,
        goal_id,
        goal_revision,
        ordinal,
    })
}

fn decode_output_integrity(
    value: i64,
) -> Result<VerificationOutputIntegrity, VerificationStoreError> {
    match value {
        0 => Ok(VerificationOutputIntegrity::Complete),
        1 => Ok(VerificationOutputIntegrity::Gapped),
        2 => Ok(VerificationOutputIntegrity::Truncated),
        3 => Ok(VerificationOutputIntegrity::GappedAndTruncated),
        _ => Err(VerificationStoreError::CorruptRecord(
            "verification_runs.output_integrity",
        )),
    }
}

fn decode_run_state(
    state: i64,
    output_integrity: Option<VerificationOutputIntegrity>,
    output_fingerprint: Option<VerificationOutputFingerprint>,
) -> Result<VerificationRunState, VerificationStoreError> {
    let status = match state {
        0 => {
            if output_integrity.is_some() || output_fingerprint.is_some() {
                return Err(VerificationStoreError::CorruptRecord(
                    "verification_runs.output_evidence",
                ));
            }
            return Ok(VerificationRunState::Starting);
        }
        1 => VerificationRunTerminalStatus::new(
            VerificationRunDisposition::Accepted,
            output_fingerprint,
            output_integrity,
        ),
        2 => VerificationRunTerminalStatus::new(
            VerificationRunDisposition::Rejected,
            output_fingerprint,
            output_integrity,
        ),
        3 => VerificationRunTerminalStatus::new(
            VerificationRunDisposition::Incomplete,
            output_fingerprint,
            output_integrity,
        ),
        4 => VerificationRunTerminalStatus::recovery_required(output_fingerprint, output_integrity),
        _ => {
            return Err(VerificationStoreError::CorruptRecord(
                "verification_runs.state",
            ));
        }
    }
    .map_err(|_| VerificationStoreError::CorruptRecord("verification_runs.output_evidence"))?;
    Ok(VerificationRunState::terminal(status))
}

fn decode_input_id(value: &[u8]) -> Result<VerificationInputId, VerificationStoreError> {
    Ok(VerificationInputId::from_uuid(decode_uuid(
        "verification_inputs.input_id",
        value,
    )?))
}

fn decode_execution_id(value: &[u8]) -> Result<ExecutionId, VerificationStoreError> {
    Ok(ExecutionId::from_uuid(decode_uuid(
        "verification_runs.execution_id",
        value,
    )?))
}

fn decode_goal_id(value: &[u8]) -> Result<GoalId, VerificationStoreError> {
    Ok(GoalId::from_uuid(decode_uuid(
        "verification_requirement_links.goal_id",
        value,
    )?))
}

fn decode_workspace_id(value: &[u8]) -> Result<WorkspaceId, VerificationStoreError> {
    Ok(WorkspaceId::from_uuid(decode_uuid(
        "verification.workspace_id",
        value,
    )?))
}

fn decode_uuid(field: &'static str, value: &[u8]) -> Result<uuid::Uuid, VerificationStoreError> {
    if value.len() != ID_BYTES {
        return Err(VerificationStoreError::CorruptRecord(field));
    }
    uuid::Uuid::from_slice(value).map_err(|_| VerificationStoreError::CorruptRecord(field))
}

fn decode_policy(value: i64) -> Result<VerificationInputPolicy, VerificationStoreError> {
    let value = u32::try_from(value)
        .map_err(|_| VerificationStoreError::CorruptRecord("verification_inputs.policy"))?;
    VerificationInputPolicy::from_version(value)
        .map_err(|_| VerificationStoreError::CorruptRecord("verification_inputs.policy"))
}

fn decode_input_fingerprint(
    value: Vec<u8>,
) -> Result<VerificationInputFingerprint, VerificationStoreError> {
    let bytes = decode_fixed_bytes("verification_inputs.fingerprint", value)?;
    Ok(VerificationInputFingerprint::from_bytes(bytes))
}

fn decode_catalog_fingerprint(
    value: Vec<u8>,
) -> Result<ProjectCommandCatalogFingerprint, VerificationStoreError> {
    let bytes = decode_fixed_bytes("verification_runs.catalog_fingerprint", value)?;
    Ok(ProjectCommandCatalogFingerprint::from_hash(
        FileContentHash::from_bytes(bytes),
    ))
}

fn decode_output_fingerprint(
    value: Vec<u8>,
) -> Result<VerificationOutputFingerprint, VerificationStoreError> {
    Ok(VerificationOutputFingerprint::from_bytes(
        decode_fixed_bytes("verification_runs.output_fingerprint", value)?,
    ))
}

fn decode_fixed_bytes<const N: usize>(
    field: &'static str,
    value: Vec<u8>,
) -> Result<[u8; N], VerificationStoreError> {
    value
        .try_into()
        .map_err(|_| VerificationStoreError::CorruptRecord(field))
}

fn decode_file_count(value: i64) -> Result<u32, VerificationStoreError> {
    u32::try_from(value)
        .ok()
        .filter(|value| i64::from(*value) <= MAX_VERIFICATION_INPUT_FILES_I64)
        .ok_or(VerificationStoreError::CorruptRecord(
            "verification_inputs.file_count",
        ))
}

fn decode_total_bytes(value: i64) -> Result<FileByteCount, VerificationStoreError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value <= MAX_VERIFICATION_INPUT_BYTES)
        .map(FileByteCount::new)
        .ok_or(VerificationStoreError::CorruptRecord(
            "verification_inputs.total_bytes",
        ))
}

fn decode_timestamp(
    value: i64,
    field: &'static str,
) -> Result<TimestampMillis, VerificationStoreError> {
    TimestampMillis::new(value).map_err(|_| VerificationStoreError::CorruptRecord(field))
}

fn encode_project_command_class(class: ProjectCommandClass) -> i64 {
    match class {
        ProjectCommandClass::Verify => 0,
        ProjectCommandClass::GeneratedPackage => 1,
    }
}

fn validate_schema_sql(
    connection: &Connection,
    kind: &str,
    name: &'static str,
    expected: &str,
) -> Result<(), VerificationStoreError> {
    let actual: Option<String> = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type = ?1 AND name = ?2",
            params![kind, name],
            |row| row.get(0),
        )
        .optional()?;
    if actual.as_deref().map(normalize_sql) != Some(normalize_sql(expected)) {
        return Err(VerificationStoreError::DamagedSchema(name));
    }
    Ok(())
}

fn validate_table_columns(
    connection: &Connection,
    table: &'static str,
    expected: &[(&str, &str, i64, i64)],
) -> Result<(), VerificationStoreError> {
    let pragma = match table {
        "verification_inputs" => "PRAGMA table_info(verification_inputs)",
        "verification_runs" => "PRAGMA table_info(verification_runs)",
        "verification_requirement_links" => "PRAGMA table_info(verification_requirement_links)",
        _ => return Err(VerificationStoreError::DamagedSchema(table)),
    };
    let mut statement = connection.prepare(pragma)?;
    let actual = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(5)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let matches = actual.len() == expected.len()
        && actual.iter().zip(expected).all(|(actual, expected)| {
            actual.0 == expected.0
                && actual.1 == expected.1
                && actual.2 == expected.2
                && actual.3 == expected.3
        });
    if !matches {
        return Err(VerificationStoreError::DamagedSchema(table));
    }
    Ok(())
}

fn validate_index_columns(
    connection: &Connection,
    index: &'static str,
    expected: &[&str],
) -> Result<(), VerificationStoreError> {
    let pragma = match index {
        "verification_requirement_links_goal_idx" => {
            "PRAGMA index_info(verification_requirement_links_goal_idx)"
        }
        _ => return Err(VerificationStoreError::DamagedSchema(index)),
    };
    let mut statement = connection.prepare(pragma)?;
    let actual = statement
        .query_map([], |row| row.get::<_, String>(2))?
        .collect::<Result<Vec<_>, _>>()?;
    if actual.as_slice() != expected {
        return Err(VerificationStoreError::DamagedSchema(index));
    }
    Ok(())
}

fn validate_foreign_keys(
    connection: &Connection,
    table: &'static str,
    expected: &[(&str, &str, &str)],
) -> Result<(), VerificationStoreError> {
    let pragma = match table {
        "verification_inputs" => "PRAGMA foreign_key_list(verification_inputs)",
        "verification_runs" => "PRAGMA foreign_key_list(verification_runs)",
        "verification_requirement_links" => {
            "PRAGMA foreign_key_list(verification_requirement_links)"
        }
        _ => return Err(VerificationStoreError::DamagedSchema(table)),
    };
    let mut statement = connection.prepare(pragma)?;
    let mut actual = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let mut expected = expected.to_vec();
    actual.sort_unstable();
    expected.sort_unstable();
    let matches = actual.len() == expected.len()
        && actual.iter().zip(&expected).all(|(actual, expected)| {
            actual.0 == expected.0 && actual.1 == expected.1 && actual.2 == expected.2
        });
    if !matches {
        return Err(VerificationStoreError::DamagedSchema(table));
    }
    Ok(())
}

fn normalize_sql(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect()
}
