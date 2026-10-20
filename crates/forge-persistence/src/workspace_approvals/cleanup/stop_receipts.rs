//! Immutable administrative authority receipts for one Workspace stop.
//!
//! This module records only the durable before/after cleanup evidence.  The
//! caller owns the transaction and the native stop authority; this module
//! never opens a nested transaction, commits, or mints a cleanup permit.

use forge_domain::{
    ApprovalRequestState, AutoApprovalScopeState, ExecutionAuthorizationRequest,
    ExecutionGrantState, ExecutionPermissions, RegisteredApprovalRequest, TimestampMillis,
    WorkspaceId,
};
use rusqlite::{Connection, OptionalExtension, Row, Transaction, params};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{
    ApprovalCleanupMode, ApprovalCleanupPlan, ApprovalCleanupSelector, ApprovalStoreError,
    AutoScopeSnapshot, GrantSnapshot, apply_after_images, get_approval_by_id, get_auto_scope_by_id,
    get_grant_by_id, readback_error, readback_sql_error, validate_before_images,
};

const MAX_TARGETS: usize = 768;
const MAX_SCHEMA_SQL_BYTES: usize = 16 * 1024;
const MAX_SCHEMA_METADATA_ROWS: usize = 64;
const ID_BYTES: usize = 16;
const DIGEST_BYTES: usize = 32;
const ID_BYTES_I64: i64 = 16;
const DIGEST_BYTES_I64: i64 = 32;
const MAX_FAMILY_TARGETS: usize = 256;
const MAX_TARGETS_I64: i64 = 768;

const BATCHES_SQL: &str = "CREATE TABLE authority_stop_batches (stop_id BLOB PRIMARY KEY NOT NULL REFERENCES workspace_execution_stops(stop_id) CHECK(length(stop_id) = 16), workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16), observed_at_ms INTEGER NOT NULL CHECK(observed_at_ms >= 0), target_count INTEGER NOT NULL CHECK(target_count BETWEEN 0 AND 768), cohort_digest BLOB NOT NULL CHECK(length(cohort_digest) = 32))";
const TARGETS_SQL: &str = "CREATE TABLE authority_stop_targets (stop_id BLOB NOT NULL REFERENCES authority_stop_batches(stop_id) CHECK(length(stop_id) = 16), ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 0 AND 767), kind INTEGER NOT NULL CHECK(kind IN (0, 1, 2)), target_id BLOB NOT NULL CHECK(length(target_id) = 16), before_revision INTEGER NOT NULL CHECK(before_revision >= 1), after_revision INTEGER NOT NULL CHECK(after_revision = before_revision + 1), before_state INTEGER NOT NULL CHECK(before_state = 0), after_state INTEGER NOT NULL CHECK(after_state BETWEEN 0 AND 6), before_digest BLOB NOT NULL CHECK(length(before_digest) = 32), after_digest BLOB NOT NULL CHECK(length(after_digest) = 32), PRIMARY KEY(stop_id, ordinal), UNIQUE(stop_id, kind, target_id))";

const OBJECTS: [(&str, &str, &str); 2] = [
    ("table", "authority_stop_batches", BATCHES_SQL),
    ("table", "authority_stop_targets", TARGETS_SQL),
];

/// The family encoded by one authority receipt target.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthorityStopTargetKind {
    Approval = 0,
    Grant = 1,
    AutoScope = 2,
}

impl AuthorityStopTargetKind {
    fn decode(value: i64) -> Result<Self, ApprovalStoreError> {
        match value {
            0 => Ok(Self::Approval),
            1 => Ok(Self::Grant),
            2 => Ok(Self::AutoScope),
            _ => Err(ApprovalStoreError::CorruptRecord("authority_stop.kind")),
        }
    }

    const fn encode(self) -> i64 {
        match self {
            Self::Approval => 0,
            Self::Grant => 1,
            Self::AutoScope => 2,
        }
    }
}

/// One immutable before/after authority target.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorityStopTarget {
    ordinal: u16,
    kind: AuthorityStopTargetKind,
    target_id: Uuid,
    before_revision: i64,
    after_revision: i64,
    before_state: i64,
    after_state: i64,
    before_digest: [u8; DIGEST_BYTES],
    after_digest: [u8; DIGEST_BYTES],
}

impl AuthorityStopTarget {
    pub const fn ordinal(&self) -> u16 {
        self.ordinal
    }

    pub const fn kind(&self) -> AuthorityStopTargetKind {
        self.kind
    }

    pub const fn target_id(&self) -> Uuid {
        self.target_id
    }

    pub const fn before_revision(&self) -> i64 {
        self.before_revision
    }

    pub const fn after_revision(&self) -> i64 {
        self.after_revision
    }

    pub const fn before_state(&self) -> i64 {
        self.before_state
    }

    pub const fn after_state(&self) -> i64 {
        self.after_state
    }

    pub const fn before_digest(&self) -> &[u8; DIGEST_BYTES] {
        &self.before_digest
    }

    pub const fn after_digest(&self) -> &[u8; DIGEST_BYTES] {
        &self.after_digest
    }
}

/// Opaque durable evidence that one authority cleanup cohort was committed.
///
/// There is intentionally no public constructor.  A receipt can only be
/// produced by the caller-owned transaction after the execution-stop and
/// cleanup before/after fences have both been checked.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityStopReceipt {
    stop_id: Uuid,
    workspace_id: WorkspaceId,
    observed_at: TimestampMillis,
    target_count: usize,
    cohort_digest: [u8; DIGEST_BYTES],
    targets: Vec<AuthorityStopTarget>,
}

impl AuthorityStopReceipt {
    pub const fn stop_id(&self) -> Uuid {
        self.stop_id
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn observed_at(&self) -> TimestampMillis {
        self.observed_at
    }

    pub const fn target_count(&self) -> usize {
        self.target_count
    }

    pub const fn cohort_digest(&self) -> &[u8; DIGEST_BYTES] {
        &self.cohort_digest
    }

    pub fn targets(&self) -> &[AuthorityStopTarget] {
        &self.targets
    }
}

/// Create the authority receipt tables in the caller's schema transaction.
pub(crate) fn create_schema(connection: &Connection) -> Result<(), ApprovalStoreError> {
    connection.execute_batch(BATCHES_SQL)?;
    connection.execute_batch(TARGETS_SQL)?;
    Ok(())
}

pub(crate) const fn schema_objects() -> [(&'static str, &'static str); 2] {
    [
        ("table", "authority_stop_batches"),
        ("table", "authority_stop_targets"),
    ]
}

pub(crate) fn validate_schema(connection: &Connection) -> Result<(), ApprovalStoreError> {
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
            return Err(ApprovalStoreError::CorruptRecord(name));
        };
        let Ok(sql_length) = usize::try_from(sql_length) else {
            return Err(ApprovalStoreError::CorruptRecord(name));
        };
        if sql_length > MAX_SCHEMA_SQL_BYTES {
            return Err(ApprovalStoreError::CorruptRecord(name));
        }
        let actual: String = connection.query_row(
            "SELECT sql FROM sqlite_schema WHERE type = ?1 AND name = ?2",
            params![kind, name],
            |row| row.get(0),
        )?;
        if normalize_sql(&actual) != normalize_sql(expected) {
            return Err(ApprovalStoreError::CorruptRecord(name));
        }
    }
    validate_columns(
        connection,
        "authority_stop_batches",
        &[
            ("stop_id", "BLOB", 1, 1),
            ("workspace_id", "BLOB", 1, 0),
            ("observed_at_ms", "INTEGER", 1, 0),
            ("target_count", "INTEGER", 1, 0),
            ("cohort_digest", "BLOB", 1, 0),
        ],
    )?;
    validate_columns(
        connection,
        "authority_stop_targets",
        &[
            ("stop_id", "BLOB", 1, 1),
            ("ordinal", "INTEGER", 1, 2),
            ("kind", "INTEGER", 1, 0),
            ("target_id", "BLOB", 1, 0),
            ("before_revision", "INTEGER", 1, 0),
            ("after_revision", "INTEGER", 1, 0),
            ("before_state", "INTEGER", 1, 0),
            ("after_state", "INTEGER", 1, 0),
            ("before_digest", "BLOB", 1, 0),
            ("after_digest", "BLOB", 1, 0),
        ],
    )?;
    validate_foreign_keys(
        connection,
        "authority_stop_batches",
        &[
            ("workspace_execution_stops", "stop_id", "stop_id"),
            ("workspace", "workspace_id", "workspace_id"),
        ],
    )?;
    validate_foreign_keys(
        connection,
        "authority_stop_targets",
        &[("authority_stop_batches", "stop_id", "stop_id")],
    )?;
    Ok(())
}

fn normalize_sql(sql: &str) -> String {
    sql.chars()
        .filter(|character| !character.is_whitespace())
        .map(|character| character.to_ascii_lowercase())
        .collect()
}

fn validate_columns(
    connection: &Connection,
    table: &'static str,
    expected: &[(&str, &str, i64, i64)],
) -> Result<(), ApprovalStoreError> {
    let mut statement = connection.prepare(&format!("PRAGMA table_info({table})"))?;
    let mut rows = statement.query([])?;
    let mut actual = Vec::new();
    while let Some(row) = rows.next()? {
        if actual.len() >= MAX_SCHEMA_METADATA_ROWS {
            return Err(ApprovalStoreError::CorruptRecord(table));
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
        return Err(ApprovalStoreError::CorruptRecord(table));
    }
    Ok(())
}

fn validate_foreign_keys(
    connection: &Connection,
    table: &'static str,
    expected: &[(&str, &str, &str)],
) -> Result<(), ApprovalStoreError> {
    let mut statement = connection.prepare(&format!("PRAGMA foreign_key_list({table})"))?;
    let mut rows = statement.query([])?;
    let mut actual = Vec::new();
    while let Some(row) = rows.next()? {
        if actual.len() >= MAX_SCHEMA_METADATA_ROWS {
            return Err(ApprovalStoreError::CorruptRecord(table));
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
        return Err(ApprovalStoreError::CorruptRecord(table));
    }
    Ok(())
}

/// Capture and apply the authority cleanup inside the caller's transaction.
pub(crate) fn capture_and_apply_in_transaction(
    transaction: &Transaction<'_>,
    plan: &ApprovalCleanupPlan,
    stop_id: Uuid,
) -> Result<AuthorityStopReceipt, ApprovalStoreError> {
    validate_authority_plan(plan)?;
    ensure_execution_stop_workspace(transaction, stop_id, plan.workspace_id())?;
    if authority_batch_exists(transaction, stop_id)? {
        let receipt = observe_in_transaction(transaction, stop_id, plan.workspace_id())?;
        if receipt.observed_at() != plan.observed_at()
            || receipt.target_count() != plan.report().total()
        {
            return Err(ApprovalStoreError::CleanupPlanMismatch);
        }
        return Ok(receipt);
    }

    validate_before_images(transaction, plan)?;
    let before = collect_before_targets(transaction, plan)?;
    apply_after_images(transaction, plan)?;
    let after = collect_after_targets(transaction, plan, &before)?;
    let targets = merge_targets(before, after)?;
    let cohort_digest = cohort_digest(&targets);
    let target_count = targets.len();
    transaction.execute(
        "INSERT INTO authority_stop_batches(
            stop_id, workspace_id, observed_at_ms, target_count, cohort_digest
         ) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            stop_id.as_bytes(),
            plan.workspace_id().into_uuid().as_bytes(),
            plan.observed_at().get(),
            i64::try_from(target_count).map_err(|_| ApprovalStoreError::CleanupLimitExceeded)?,
            cohort_digest.as_slice(),
        ],
    )?;
    for target in &targets {
        transaction.execute(
            "INSERT INTO authority_stop_targets(
                stop_id, ordinal, kind, target_id, before_revision, after_revision,
                before_state, after_state, before_digest, after_digest
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                stop_id.as_bytes(),
                i64::from(target.ordinal),
                target.kind.encode(),
                target.target_id.as_bytes(),
                target.before_revision,
                target.after_revision,
                target.before_state,
                target.after_state,
                target.before_digest.as_slice(),
                target.after_digest.as_slice(),
            ],
        )?;
    }
    Ok(AuthorityStopReceipt {
        stop_id,
        workspace_id: plan.workspace_id(),
        observed_at: plan.observed_at(),
        target_count,
        cohort_digest,
        targets,
    })
}

/// Observe a receipt without opening a nested transaction.  The caller keeps
/// ownership of the transaction and decides when its read snapshot commits.
pub(crate) fn observe_stop_authority_receipt_in_transaction(
    transaction: &Connection,
    stop_id: Uuid,
    workspace_id: WorkspaceId,
) -> Result<Option<AuthorityStopReceipt>, ApprovalStoreError> {
    let Some(_) = load_batch(transaction, stop_id)? else {
        return Ok(None);
    };
    observe_in_transaction(transaction, stop_id, workspace_id)
        .map(Some)
        .map_err(readback_error)
}

fn validate_authority_plan(plan: &ApprovalCleanupPlan) -> Result<(), ApprovalStoreError> {
    if plan.selector() != ApprovalCleanupSelector::Workspace
        || plan.mode() != ApprovalCleanupMode::AuthorityCancellation
        || plan.has_more()
    {
        return Err(ApprovalStoreError::CleanupPlanMismatch);
    }
    let total = plan.report().total();
    if total > MAX_TARGETS
        || plan.data.approvals.len() > MAX_FAMILY_TARGETS
        || plan.data.grants.len() > MAX_FAMILY_TARGETS
        || plan.data.auto_scopes.len() > MAX_FAMILY_TARGETS
    {
        return Err(ApprovalStoreError::CleanupLimitExceeded);
    }
    Ok(())
}

fn ensure_execution_stop_workspace(
    transaction: &Connection,
    stop_id: Uuid,
    workspace_id: WorkspaceId,
) -> Result<(), ApprovalStoreError> {
    let row: Option<(i64, Vec<u8>)> = transaction
        .query_row(
            "SELECT length(CAST(workspace_id AS BLOB)),
                    substr(CAST(workspace_id AS BLOB), 1, 16)
             FROM workspace_execution_stops WHERE stop_id = ?1",
            params![stop_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(ApprovalStoreError::from)?;
    let Some((length, bytes)) = row else {
        return Err(ApprovalStoreError::CleanupPlanMismatch);
    };
    if length != ID_BYTES_I64 || bytes.len() != ID_BYTES {
        return Err(ApprovalStoreError::CorruptRecord(
            "execution_stop.workspace_id",
        ));
    }
    let actual = Uuid::from_slice(&bytes)
        .map(WorkspaceId::from_uuid)
        .map_err(|_| ApprovalStoreError::CorruptRecord("execution_stop.workspace_id"))?;
    if actual == workspace_id {
        Ok(())
    } else {
        Err(ApprovalStoreError::WorkspaceMismatch)
    }
}

fn authority_batch_exists(
    transaction: &Transaction<'_>,
    stop_id: Uuid,
) -> Result<bool, ApprovalStoreError> {
    transaction
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM authority_stop_batches WHERE stop_id = ?1)",
            params![stop_id.as_bytes()],
            |row| row.get(0),
        )
        .map_err(ApprovalStoreError::from)
}

fn collect_before_targets(
    transaction: &Transaction<'_>,
    plan: &ApprovalCleanupPlan,
) -> Result<Vec<AuthorityStopTarget>, ApprovalStoreError> {
    let mut targets = Vec::with_capacity(plan.report().total());
    for before in &plan.data.approvals {
        let current = get_approval_by_id(transaction, before.id())?
            .ok_or(ApprovalStoreError::CleanupPlanMismatch)?;
        if current != *before || current.request().workspace_id() != plan.workspace_id() {
            return Err(ApprovalStoreError::CleanupPlanMismatch);
        }
        let revision = current.revision().get();
        targets.push(AuthorityStopTarget {
            ordinal: 0,
            kind: AuthorityStopTargetKind::Approval,
            target_id: current.id().into_uuid(),
            before_revision: revision,
            after_revision: revision
                .checked_add(1)
                .ok_or(ApprovalStoreError::RevisionOverflow)?,
            before_state: super::super::encode_approval_state(current.state()),
            after_state: expected_approval_state(plan, current.id())?,
            before_digest: approval_digest(&current),
            after_digest: [0; DIGEST_BYTES],
        });
    }
    for before in &plan.data.grants {
        let current = get_grant_by_id(transaction, before.grant.id())?
            .ok_or(ApprovalStoreError::CleanupPlanMismatch)?;
        if current != *before || current.grant.request().workspace_id() != plan.workspace_id() {
            return Err(ApprovalStoreError::CleanupPlanMismatch);
        }
        let revision = current.grant.revision().get();
        targets.push(AuthorityStopTarget {
            ordinal: 0,
            kind: AuthorityStopTargetKind::Grant,
            target_id: current.grant.id().into_uuid(),
            before_revision: revision,
            after_revision: revision
                .checked_add(1)
                .ok_or(ApprovalStoreError::RevisionOverflow)?,
            before_state: super::super::encode_grant_state(current.grant.state()),
            after_state: expected_grant_state(plan, current.grant.id())?,
            before_digest: grant_digest(&current),
            after_digest: [0; DIGEST_BYTES],
        });
    }
    for before in &plan.data.auto_scopes {
        let current = get_auto_scope_by_id(transaction, before.scope.id())?
            .ok_or(ApprovalStoreError::CleanupPlanMismatch)?;
        if current != *before || current.scope.workspace_id() != plan.workspace_id() {
            return Err(ApprovalStoreError::CleanupPlanMismatch);
        }
        let revision = current.scope.revision().get();
        targets.push(AuthorityStopTarget {
            ordinal: 0,
            kind: AuthorityStopTargetKind::AutoScope,
            target_id: current.scope.id().into_uuid(),
            before_revision: revision,
            after_revision: revision
                .checked_add(1)
                .ok_or(ApprovalStoreError::RevisionOverflow)?,
            before_state: super::super::encode_auto_state(current.scope.state()),
            after_state: expected_auto_state(plan, current.scope.id())?,
            before_digest: auto_scope_digest(&current),
            after_digest: [0; DIGEST_BYTES],
        });
    }
    if targets.len() > MAX_TARGETS {
        return Err(ApprovalStoreError::CleanupLimitExceeded);
    }
    for (ordinal, target) in targets.iter_mut().enumerate() {
        target.ordinal =
            u16::try_from(ordinal).map_err(|_| ApprovalStoreError::CleanupLimitExceeded)?;
    }
    Ok(targets)
}

fn collect_after_targets(
    transaction: &Transaction<'_>,
    plan: &ApprovalCleanupPlan,
    before: &[AuthorityStopTarget],
) -> Result<Vec<AuthorityStopTarget>, ApprovalStoreError> {
    let mut targets = Vec::with_capacity(before.len());
    for mut target in before.iter().copied() {
        let after_digest = match target.kind {
            AuthorityStopTargetKind::Approval => {
                let current = get_approval_by_id(
                    transaction,
                    forge_domain::ApprovalRequestId::from_uuid(target.target_id),
                )?
                .ok_or(ApprovalStoreError::CleanupPlanMismatch)?;
                let expected = plan
                    .after
                    .approvals
                    .iter()
                    .find(|value| value.id().into_uuid() == target.target_id)
                    .ok_or(ApprovalStoreError::CleanupPlanMismatch)?;
                if current != *expected
                    || current.state() == ApprovalRequestState::Pending
                    || current.revision().get() != target.after_revision
                {
                    return Err(ApprovalStoreError::CleanupPlanMismatch);
                }
                approval_digest(&current)
            }
            AuthorityStopTargetKind::Grant => {
                let current = get_grant_by_id(
                    transaction,
                    forge_domain::ExecutionGrantId::from_uuid(target.target_id),
                )?
                .ok_or(ApprovalStoreError::CleanupPlanMismatch)?;
                let expected = plan
                    .after
                    .grants
                    .iter()
                    .find(|value| value.grant.id().into_uuid() == target.target_id)
                    .ok_or(ApprovalStoreError::CleanupPlanMismatch)?;
                if current != *expected
                    || current.grant.state() == ExecutionGrantState::Active
                    || current.grant.revision().get() != target.after_revision
                {
                    return Err(ApprovalStoreError::CleanupPlanMismatch);
                }
                grant_digest(&current)
            }
            AuthorityStopTargetKind::AutoScope => {
                let current = get_auto_scope_by_id(
                    transaction,
                    forge_domain::AutoApprovalScopeId::from_uuid(target.target_id),
                )?
                .ok_or(ApprovalStoreError::CleanupPlanMismatch)?;
                let expected = plan
                    .after
                    .auto_scopes
                    .iter()
                    .find(|value| value.scope.id().into_uuid() == target.target_id)
                    .ok_or(ApprovalStoreError::CleanupPlanMismatch)?;
                if current != *expected
                    || current.scope.state() == AutoApprovalScopeState::Active
                    || current.scope.revision().get() != target.after_revision
                {
                    return Err(ApprovalStoreError::CleanupPlanMismatch);
                }
                auto_scope_digest(&current)
            }
        };
        target.after_digest = after_digest;
        targets.push(target);
    }
    Ok(targets)
}

fn merge_targets(
    before: Vec<AuthorityStopTarget>,
    after: Vec<AuthorityStopTarget>,
) -> Result<Vec<AuthorityStopTarget>, ApprovalStoreError> {
    if before.len() != after.len() {
        return Err(ApprovalStoreError::CleanupPlanMismatch);
    }
    let mut merged = before;
    for (target, after) in merged.iter_mut().zip(after) {
        if target.ordinal != after.ordinal
            || target.kind != after.kind
            || target.target_id != after.target_id
            || target.before_revision != after.before_revision
            || target.after_revision != after.after_revision
            || target.before_state != after.before_state
            || target.before_digest != after.before_digest
        {
            return Err(ApprovalStoreError::CleanupPlanMismatch);
        }
        target.after_digest = after.after_digest;
        target.after_state = after.after_state;
    }
    Ok(merged)
}

fn observe_in_transaction(
    transaction: &Connection,
    stop_id: Uuid,
    workspace_id: WorkspaceId,
) -> Result<AuthorityStopReceipt, ApprovalStoreError> {
    let Some(batch) = load_batch(transaction, stop_id)? else {
        return Err(ApprovalStoreError::CleanupPlanMismatch);
    };
    if batch.stop_id != stop_id {
        return Err(ApprovalStoreError::CleanupPlanMismatch);
    }
    if batch.workspace_id != workspace_id {
        return Err(ApprovalStoreError::WorkspaceMismatch);
    }
    ensure_execution_stop_workspace(transaction, stop_id, workspace_id)?;
    let captured_at: i64 = transaction
        .query_row(
            "SELECT created_at_ms FROM workspace_execution_stops WHERE stop_id = ?1",
            params![stop_id.as_bytes()],
            |row| row.get(0),
        )
        .map_err(readback_sql_error)?;
    if captured_at != batch.observed_at.get() {
        return Err(ApprovalStoreError::CleanupPlanMismatch);
    }
    let targets = load_targets(transaction, stop_id, batch.target_count)?;
    if cohort_digest(&targets) != batch.cohort_digest {
        return Err(ApprovalStoreError::CleanupPlanMismatch);
    }
    for target in &targets {
        validate_current_after(transaction, workspace_id, target)?;
    }
    Ok(AuthorityStopReceipt {
        stop_id,
        workspace_id,
        observed_at: batch.observed_at,
        target_count: targets.len(),
        cohort_digest: batch.cohort_digest,
        targets,
    })
}

fn load_batch(
    transaction: &Connection,
    stop_id: Uuid,
) -> Result<Option<BatchDecoded>, ApprovalStoreError> {
    let row: Option<RawBatchColumns> = transaction
        .query_row(
            "SELECT length(CAST(stop_id AS BLOB)), substr(CAST(stop_id AS BLOB), 1, 16),
                    length(CAST(workspace_id AS BLOB)), substr(CAST(workspace_id AS BLOB), 1, 16),
                    observed_at_ms, target_count,
                    length(CAST(cohort_digest AS BLOB)), substr(CAST(cohort_digest AS BLOB), 1, 32)
             FROM authority_stop_batches WHERE stop_id = ?1",
            params![stop_id.as_bytes()],
            RawBatchColumns::from_row,
        )
        .optional()
        .map_err(readback_sql_error)?;
    let Some(raw) = row else {
        return Ok(None);
    };
    if !(0..=MAX_TARGETS_I64).contains(&raw.target_count) {
        return Err(ApprovalStoreError::CorruptRecord(
            "authority_stop.target_count",
        ));
    }
    let stop_id = decode_bounded_uuid(raw.stop_length, &raw.stop_bytes, "authority_stop.stop_id")?;
    let workspace_id = WorkspaceId::from_uuid(decode_bounded_uuid(
        raw.workspace_length,
        &raw.workspace_bytes,
        "authority_stop.workspace_id",
    )?);
    let observed_at = TimestampMillis::new(raw.observed_at)
        .map_err(|_| ApprovalStoreError::CorruptRecord("authority_stop.observed_at_ms"))?;
    let cohort_digest = decode_bounded_digest(
        raw.cohort_length,
        &raw.cohort_bytes,
        "authority_stop.cohort_digest",
    )?;
    Ok(Some(BatchDecoded {
        stop_id,
        workspace_id,
        observed_at,
        target_count: usize::try_from(raw.target_count)
            .map_err(|_| ApprovalStoreError::CorruptRecord("authority_stop.target_count"))?,
        cohort_digest,
    }))
}

#[derive(Debug)]
struct BatchDecoded {
    stop_id: Uuid,
    workspace_id: WorkspaceId,
    observed_at: TimestampMillis,
    target_count: usize,
    cohort_digest: [u8; DIGEST_BYTES],
}

#[derive(Debug)]
struct RawBatchColumns {
    stop_length: i64,
    stop_bytes: Vec<u8>,
    workspace_length: i64,
    workspace_bytes: Vec<u8>,
    observed_at: i64,
    target_count: i64,
    cohort_length: i64,
    cohort_bytes: Vec<u8>,
}

impl RawBatchColumns {
    fn from_row(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            stop_length: row.get(0)?,
            stop_bytes: row.get(1)?,
            workspace_length: row.get(2)?,
            workspace_bytes: row.get(3)?,
            observed_at: row.get(4)?,
            target_count: row.get(5)?,
            cohort_length: row.get(6)?,
            cohort_bytes: row.get(7)?,
        })
    }
}

fn load_targets(
    transaction: &Connection,
    stop_id: Uuid,
    target_count: usize,
) -> Result<Vec<AuthorityStopTarget>, ApprovalStoreError> {
    let mut statement = transaction.prepare(
        "SELECT ordinal, kind, length(CAST(target_id AS BLOB)), substr(CAST(target_id AS BLOB), 1, 16),
                before_revision, after_revision, before_state, after_state,
                length(CAST(before_digest AS BLOB)), substr(CAST(before_digest AS BLOB), 1, 32),
                length(CAST(after_digest AS BLOB)), substr(CAST(after_digest AS BLOB), 1, 32)
         FROM authority_stop_targets WHERE stop_id = ?1 ORDER BY ordinal",
    )?;
    let mut rows = statement.query(params![stop_id.as_bytes()])?;
    let mut targets = Vec::new();
    let mut family_counts = [0_usize; 3];
    while let Some(row) = rows.next()? {
        if targets.len() >= MAX_TARGETS {
            return Err(ApprovalStoreError::CorruptRecord(
                "authority_stop.target_count",
            ));
        }
        let ordinal: i64 = row.get(0)?;
        if ordinal
            != i64::try_from(targets.len()).map_err(|_| ApprovalStoreError::CleanupLimitExceeded)?
        {
            return Err(ApprovalStoreError::CleanupPlanMismatch);
        }
        let kind = AuthorityStopTargetKind::decode(row.get(1)?)?;
        let family = match kind {
            AuthorityStopTargetKind::Approval => 0,
            AuthorityStopTargetKind::Grant => 1,
            AuthorityStopTargetKind::AutoScope => 2,
        };
        family_counts[family] += 1;
        if family_counts[family] > super::MAX_CLEANUP_PAGE_ROWS {
            return Err(ApprovalStoreError::CleanupLimitExceeded);
        }
        let target_id_length: i64 = row.get(2)?;
        let target_id_bytes: Vec<u8> = row.get(3)?;
        let target_id = decode_bounded_uuid(
            target_id_length,
            &target_id_bytes,
            "authority_stop.target_id",
        )?;
        let before_revision: i64 = row.get(4)?;
        let after_revision: i64 = row.get(5)?;
        let before_state: i64 = row.get(6)?;
        let after_state: i64 = row.get(7)?;
        if before_revision < 1
            || before_revision.checked_add(1) != Some(after_revision)
            || before_state != 0
        {
            return Err(ApprovalStoreError::CleanupPlanMismatch);
        }
        validate_after_state(kind, after_state)?;
        let before_digest_length: i64 = row.get(8)?;
        let before_digest_bytes: Vec<u8> = row.get(9)?;
        let before_digest = decode_bounded_digest(
            before_digest_length,
            &before_digest_bytes,
            "authority_stop.before_digest",
        )?;
        let after_digest_length: i64 = row.get(10)?;
        let after_digest_bytes: Vec<u8> = row.get(11)?;
        let after_digest = decode_bounded_digest(
            after_digest_length,
            &after_digest_bytes,
            "authority_stop.after_digest",
        )?;
        targets.push(AuthorityStopTarget {
            ordinal: u16::try_from(ordinal).map_err(|_| ApprovalStoreError::CleanupPlanMismatch)?,
            kind,
            target_id,
            before_revision,
            after_revision,
            before_state,
            after_state,
            before_digest,
            after_digest,
        });
    }
    if targets.len() != target_count {
        return Err(ApprovalStoreError::CleanupPlanMismatch);
    }
    Ok(targets)
}

fn validate_current_after(
    transaction: &Connection,
    workspace_id: WorkspaceId,
    target: &AuthorityStopTarget,
) -> Result<(), ApprovalStoreError> {
    match target.kind {
        AuthorityStopTargetKind::Approval => {
            let current = get_approval_by_id(
                transaction,
                forge_domain::ApprovalRequestId::from_uuid(target.target_id),
            )?
            .ok_or(ApprovalStoreError::CleanupPlanMismatch)?;
            if current.request().workspace_id() != workspace_id
                || current.revision().get() != target.after_revision
                || super::super::encode_approval_state(current.state()) != target.after_state
                || approval_digest(&current) != target.after_digest
            {
                return Err(ApprovalStoreError::CleanupPlanMismatch);
            }
        }
        AuthorityStopTargetKind::Grant => {
            let current = get_grant_by_id(
                transaction,
                forge_domain::ExecutionGrantId::from_uuid(target.target_id),
            )?
            .ok_or(ApprovalStoreError::CleanupPlanMismatch)?;
            if current.grant.request().workspace_id() != workspace_id
                || current.grant.revision().get() != target.after_revision
                || super::super::encode_grant_state(current.grant.state()) != target.after_state
                || grant_digest(&current) != target.after_digest
            {
                return Err(ApprovalStoreError::CleanupPlanMismatch);
            }
        }
        AuthorityStopTargetKind::AutoScope => {
            let current = get_auto_scope_by_id(
                transaction,
                forge_domain::AutoApprovalScopeId::from_uuid(target.target_id),
            )?
            .ok_or(ApprovalStoreError::CleanupPlanMismatch)?;
            if current.scope.workspace_id() != workspace_id
                || current.scope.revision().get() != target.after_revision
                || super::super::encode_auto_state(current.scope.state()) != target.after_state
                || auto_scope_digest(&current) != target.after_digest
            {
                return Err(ApprovalStoreError::CleanupPlanMismatch);
            }
        }
    }
    Ok(())
}

fn expected_approval_state(
    plan: &ApprovalCleanupPlan,
    id: forge_domain::ApprovalRequestId,
) -> Result<i64, ApprovalStoreError> {
    let after = plan
        .after
        .approvals
        .iter()
        .find(|value| value.id() == id)
        .ok_or(ApprovalStoreError::CleanupPlanMismatch)?;
    validate_after_state(
        AuthorityStopTargetKind::Approval,
        super::super::encode_approval_state(after.state()),
    )?;
    Ok(super::super::encode_approval_state(after.state()))
}

fn expected_grant_state(
    plan: &ApprovalCleanupPlan,
    id: forge_domain::ExecutionGrantId,
) -> Result<i64, ApprovalStoreError> {
    let after = plan
        .after
        .grants
        .iter()
        .find(|value| value.grant.id() == id)
        .ok_or(ApprovalStoreError::CleanupPlanMismatch)?;
    validate_after_state(
        AuthorityStopTargetKind::Grant,
        super::super::encode_grant_state(after.grant.state()),
    )?;
    Ok(super::super::encode_grant_state(after.grant.state()))
}

fn expected_auto_state(
    plan: &ApprovalCleanupPlan,
    id: forge_domain::AutoApprovalScopeId,
) -> Result<i64, ApprovalStoreError> {
    let after = plan
        .after
        .auto_scopes
        .iter()
        .find(|value| value.scope.id() == id)
        .ok_or(ApprovalStoreError::CleanupPlanMismatch)?;
    validate_after_state(
        AuthorityStopTargetKind::AutoScope,
        super::super::encode_auto_state(after.scope.state()),
    )?;
    Ok(super::super::encode_auto_state(after.scope.state()))
}

fn validate_after_state(
    kind: AuthorityStopTargetKind,
    state: i64,
) -> Result<(), ApprovalStoreError> {
    let valid = match kind {
        AuthorityStopTargetKind::Approval => matches!(state, 5 | 6),
        AuthorityStopTargetKind::Grant => matches!(state, 2 | 3),
        AuthorityStopTargetKind::AutoScope => matches!(state, 1 | 2),
    };
    if valid {
        Ok(())
    } else {
        Err(ApprovalStoreError::CleanupPlanMismatch)
    }
}

fn cohort_digest(targets: &[AuthorityStopTarget]) -> [u8; DIGEST_BYTES] {
    let mut hasher = Sha256::new();
    hasher.update(b"forge-authority-stop-cohort-v1\0");
    for target in targets {
        hasher.update(target.ordinal.to_be_bytes());
        hasher.update(target.kind.encode().to_be_bytes());
        hasher.update(target.target_id.as_bytes());
        hasher.update(target.before_revision.to_be_bytes());
        hasher.update(target.after_revision.to_be_bytes());
        hasher.update(target.before_state.to_be_bytes());
        hasher.update(target.after_state.to_be_bytes());
        hasher.update(target.before_digest);
        hasher.update(target.after_digest);
    }
    hasher.finalize().into()
}

fn approval_digest(value: &RegisteredApprovalRequest) -> [u8; DIGEST_BYTES] {
    let mut hasher = Sha256::new();
    hasher.update(b"forge-authority-stop-approval-v1\0");
    hasher.update(value.id().into_uuid().as_bytes());
    hash_authorization(&mut hasher, value.request());
    hasher.update(value.policy_revision().get().to_be_bytes());
    hasher.update(super::super::encode_approval_state(value.state()).to_be_bytes());
    hasher.update(value.created_at().get().to_be_bytes());
    hasher.update(value.expires_at().get().to_be_bytes());
    hash_optional_i64(&mut hasher, value.decided_at().map(TimestampMillis::get));
    hasher.update(value.revision().get().to_be_bytes());
    match value.agent_binding() {
        Some(binding) => {
            hasher.update([1]);
            hasher.update(binding.as_bytes());
        }
        None => hasher.update([0]),
    }
    hasher.finalize().into()
}

fn grant_digest(value: &GrantSnapshot) -> [u8; DIGEST_BYTES] {
    let grant = &value.grant;
    let mut hasher = Sha256::new();
    hasher.update(b"forge-authority-stop-grant-v1\0");
    hasher.update(grant.id().into_uuid().as_bytes());
    hasher.update(grant.approval_id().into_uuid().as_bytes());
    hash_authorization(&mut hasher, grant.request());
    hash_permissions(&mut hasher, grant.effective().get());
    hasher.update(grant.policy_revision().get().to_be_bytes());
    hasher.update(super::super::encode_source(grant.source()).to_be_bytes());
    hash_optional_uuid(
        &mut hasher,
        value
            .auto_scope_id
            .map(forge_domain::AutoApprovalScopeId::into_uuid),
    );
    hasher.update(super::super::encode_grant_state(grant.state()).to_be_bytes());
    hasher.update(grant.expires_at().get().to_be_bytes());
    hash_optional_i64(&mut hasher, grant.consumed_at().map(TimestampMillis::get));
    hasher.update(grant.revision().get().to_be_bytes());
    hasher.finalize().into()
}

fn auto_scope_digest(value: &AutoScopeSnapshot) -> [u8; DIGEST_BYTES] {
    let scope = &value.scope;
    let mut hasher = Sha256::new();
    hasher.update(b"forge-authority-stop-auto-scope-v1\0");
    hasher.update(scope.id().into_uuid().as_bytes());
    hasher.update(scope.workspace_id().into_uuid().as_bytes());
    hash_optional_uuid(
        &mut hasher,
        scope.activity_id().map(forge_domain::ActivityId::into_uuid),
    );
    hasher.update(super::super::encode_action(scope.action()).to_be_bytes());
    hash_permissions(&mut hasher, scope.permission_ceiling());
    hasher.update(scope.policy_revision().get().to_be_bytes());
    hasher.update(scope.expires_at().get().to_be_bytes());
    match scope.max_uses().get() {
        Some(limit) => {
            hasher.update([1]);
            hasher.update(limit.to_be_bytes());
        }
        None => hasher.update([0]),
    }
    hasher.update(scope.used_count().to_be_bytes());
    hasher.update(super::super::encode_auto_state(scope.state()).to_be_bytes());
    hasher.update(value.created_at.get().to_be_bytes());
    hasher.update(value.updated_at.get().to_be_bytes());
    hasher.update(scope.revision().get().to_be_bytes());
    hasher.finalize().into()
}

fn hash_authorization(hasher: &mut Sha256, value: ExecutionAuthorizationRequest) {
    hasher.update(value.execution_id().into_uuid().as_bytes());
    hasher.update(value.workspace_id().into_uuid().as_bytes());
    hasher.update(value.activity_id().into_uuid().as_bytes());
    hasher.update(value.request_digest().as_bytes());
    hasher.update(super::super::encode_action(value.action()).to_be_bytes());
    hash_permissions(hasher, value.requested().get());
}

fn hash_permissions(hasher: &mut Sha256, value: ExecutionPermissions) {
    hasher.update([
        u8::from(value.workspace_read()),
        u8::from(value.workspace_write()),
        u8::from(value.network()),
    ]);
}

fn hash_optional_uuid(hasher: &mut Sha256, value: Option<Uuid>) {
    match value {
        Some(value) => {
            hasher.update([1]);
            hasher.update(value.as_bytes());
        }
        None => hasher.update([0]),
    }
}

fn hash_optional_i64(hasher: &mut Sha256, value: Option<i64>) {
    match value {
        Some(value) => {
            hasher.update([1]);
            hasher.update(value.to_be_bytes());
        }
        None => hasher.update([0]),
    }
}

fn decode_bounded_uuid(
    persisted_length: i64,
    bytes: &[u8],
    field: &'static str,
) -> Result<Uuid, ApprovalStoreError> {
    if persisted_length != ID_BYTES_I64 || bytes.len() != ID_BYTES {
        return Err(ApprovalStoreError::CorruptRecord(field));
    }
    Uuid::from_slice(bytes).map_err(|_| ApprovalStoreError::CorruptRecord(field))
}

fn decode_bounded_digest(
    persisted_length: i64,
    bytes: &[u8],
    field: &'static str,
) -> Result<[u8; DIGEST_BYTES], ApprovalStoreError> {
    if persisted_length != DIGEST_BYTES_I64 || bytes.len() != DIGEST_BYTES {
        return Err(ApprovalStoreError::CorruptRecord(field));
    }
    bytes
        .try_into()
        .map_err(|_| ApprovalStoreError::CorruptRecord(field))
}
