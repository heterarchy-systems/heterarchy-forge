//! Immutable schema-61 evidence for one leased recovery-maintenance run.

use forge_domain::{
    ActivityId, ActivityLeaseRevision, ActivityListLimit, ActivityRevision, ActivityState,
    ExecutionId, ExecutionListLimit, ExecutionRequestDigest, ExecutionRevision, ExecutionState,
    RecoveryLeaseDurationMillis, RecoveryMaintenanceLease, RegisteredActivity, RegisteredExecution,
    RuntimeInstanceId, TimestampMillis, WorkspaceId,
};
use rusqlite::{Connection, OptionalExtension, Row, Transaction, params};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

const ID_BYTES: usize = 16;
const DIGEST_BYTES: usize = 32;
const MAX_ACTIVITY_FACTS: usize = 1_000;
const MAX_EXECUTION_FACTS: usize = 256;

const RUNS_SQL: &str = "CREATE TABLE recovery_runs (request_id BLOB PRIMARY KEY NOT NULL CHECK(length(request_id) = 16), workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16), owner_runtime_instance_id BLOB NOT NULL CHECK(length(owner_runtime_instance_id) = 16), request_digest BLOB NOT NULL CHECK(length(request_digest) = 32), binding_digest BLOB NOT NULL CHECK(length(binding_digest) = 32), duration_ms INTEGER NOT NULL CHECK(duration_ms BETWEEN 1000 AND 300000), claimed_at_ms INTEGER NOT NULL CHECK(claimed_at_ms >= 0), classify_at_ms INTEGER NOT NULL CHECK(classify_at_ms >= claimed_at_ms), claimed_owner_id BLOB NOT NULL CHECK(length(claimed_owner_id) = 16), claimed_lease_until_ms INTEGER NOT NULL CHECK(claimed_lease_until_ms > claimed_at_ms), claimed_epoch INTEGER NOT NULL CHECK(claimed_epoch >= 1), claimed_updated_at_ms INTEGER NOT NULL CHECK(claimed_updated_at_ms <= claimed_at_ms), claimed_revision INTEGER NOT NULL CHECK(claimed_revision >= 1), released_owner_id BLOB CHECK(released_owner_id IS NULL), released_lease_until_ms INTEGER CHECK(released_lease_until_ms IS NULL), released_epoch INTEGER NOT NULL CHECK(released_epoch = claimed_epoch), released_updated_at_ms INTEGER NOT NULL CHECK(released_updated_at_ms = classify_at_ms), released_revision INTEGER NOT NULL CHECK(released_revision = claimed_revision + 1), activity_limit INTEGER NOT NULL CHECK(activity_limit BETWEEN 1 AND 1000), execution_limit INTEGER NOT NULL CHECK(execution_limit BETWEEN 1 AND 256), activity_count INTEGER NOT NULL CHECK(activity_count BETWEEN 0 AND 1000), execution_count INTEGER NOT NULL CHECK(execution_count BETWEEN 0 AND 256), receipt_digest BLOB NOT NULL CHECK(length(receipt_digest) = 32), UNIQUE(workspace_id, request_id))";
const ACTIVITIES_SQL: &str = "CREATE TABLE recovery_run_activities (request_id BLOB NOT NULL REFERENCES recovery_runs(request_id), ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 0 AND 999), activity_id BLOB NOT NULL REFERENCES activities(activity_id) CHECK(length(activity_id) = 16), workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16), before_state INTEGER NOT NULL CHECK(before_state = 1), before_revision INTEGER NOT NULL CHECK(before_revision >= 1), before_created_at_ms INTEGER NOT NULL CHECK(before_created_at_ms >= 0), before_updated_at_ms INTEGER NOT NULL CHECK(before_updated_at_ms >= 0), before_lease_owner_id BLOB NOT NULL CHECK(length(before_lease_owner_id) = 16), before_lease_until_ms INTEGER NOT NULL CHECK(before_lease_until_ms > before_updated_at_ms), before_lease_revision INTEGER NOT NULL CHECK(before_lease_revision >= 1), after_revision INTEGER NOT NULL CHECK(after_revision = before_revision + 1), after_updated_at_ms INTEGER NOT NULL CHECK(after_updated_at_ms >= before_updated_at_ms), after_lease_revision INTEGER NOT NULL CHECK(after_lease_revision = before_lease_revision + 1), PRIMARY KEY(request_id, ordinal), UNIQUE(request_id, activity_id))";
const EXECUTIONS_SQL: &str = "CREATE TABLE recovery_run_executions (request_id BLOB NOT NULL REFERENCES recovery_runs(request_id), ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 0 AND 255), execution_id BLOB NOT NULL REFERENCES executions(execution_id) CHECK(length(execution_id) = 16), workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16), activity_id BLOB NOT NULL REFERENCES activities(activity_id) CHECK(length(activity_id) = 16), request_digest BLOB NOT NULL CHECK(length(request_digest) = 32), before_state INTEGER NOT NULL CHECK(before_state IN (0, 1)), before_revision INTEGER NOT NULL CHECK(before_revision >= 1), before_updated_at_ms INTEGER NOT NULL CHECK(before_updated_at_ms >= 0), after_revision INTEGER NOT NULL CHECK(after_revision = before_revision + 1), after_updated_at_ms INTEGER NOT NULL CHECK(after_updated_at_ms >= before_updated_at_ms), eligibility_activity_state INTEGER NOT NULL CHECK(eligibility_activity_state IN (1, 2)), eligibility_activity_revision INTEGER NOT NULL CHECK(eligibility_activity_revision >= 1), eligibility_activity_updated_at_ms INTEGER NOT NULL CHECK(eligibility_activity_updated_at_ms >= 0), eligibility_activity_lease_owner_id BLOB CHECK(eligibility_activity_lease_owner_id IS NULL OR length(eligibility_activity_lease_owner_id) = 16), eligibility_activity_lease_until_ms INTEGER CHECK(eligibility_activity_lease_until_ms IS NULL OR eligibility_activity_lease_until_ms > eligibility_activity_updated_at_ms), eligibility_activity_lease_revision INTEGER NOT NULL CHECK(eligibility_activity_lease_revision >= 1), terminal_semantic_sequence INTEGER NOT NULL CHECK(terminal_semantic_sequence >= 1), effect_outbox_sequence INTEGER CHECK(effect_outbox_sequence IS NULL OR effect_outbox_sequence >= 1), PRIMARY KEY(request_id, ordinal), UNIQUE(request_id, execution_id), CHECK((eligibility_activity_lease_owner_id IS NULL) = (eligibility_activity_lease_until_ms IS NULL)), CHECK((eligibility_activity_state = 1 AND eligibility_activity_lease_owner_id IS NOT NULL AND eligibility_activity_lease_until_ms IS NOT NULL) OR (eligibility_activity_state = 2 AND eligibility_activity_lease_owner_id IS NULL AND eligibility_activity_lease_until_ms IS NULL)))";

const OBJECTS: [(&str, &str, &str); 3] = [
    ("table", "recovery_runs", RUNS_SQL),
    ("table", "recovery_run_activities", ACTIVITIES_SQL),
    ("table", "recovery_run_executions", EXECUTIONS_SQL),
];

#[derive(Debug, Error)]
pub enum RecoveryRunStoreError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error("recovery run request conflicts with immutable history")]
    Conflict,
    #[error("recovery run history is corrupt: {0}")]
    Corrupt(&'static str),
    #[error("recovery run schema is damaged: {0}")]
    DamagedSchema(&'static str),
    #[error("recovery run exceeds the bounded fact limit")]
    Overflow,
    #[error("recovery run metadata is invalid: {0}")]
    Invalid(&'static str),
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryRunRequest {
    pub request_id: Uuid,
    pub workspace_id: WorkspaceId,
    pub owner_id: RuntimeInstanceId,
    pub request_digest: [u8; DIGEST_BYTES],
    pub binding_digest: [u8; DIGEST_BYTES],
    pub duration: RecoveryLeaseDurationMillis,
    pub claimed_at: TimestampMillis,
    pub classify_at: TimestampMillis,
    pub activity_limit: ActivityListLimit,
    pub execution_limit: ExecutionListLimit,
}

impl RecoveryRunRequest {
    pub fn new(
        identity: (Uuid, WorkspaceId, RuntimeInstanceId),
        request_digest: [u8; DIGEST_BYTES],
        binding_digest: [u8; DIGEST_BYTES],
        duration: RecoveryLeaseDurationMillis,
        observations: (TimestampMillis, TimestampMillis),
        limits: (ActivityListLimit, ExecutionListLimit),
    ) -> Result<Self, RecoveryRunStoreError> {
        let (request_id, workspace_id, owner_id) = identity;
        let (claimed_at, classify_at) = observations;
        let (activity_limit, execution_limit) = limits;
        if request_id.is_nil()
            || workspace_id.into_uuid().is_nil()
            || owner_id.into_uuid().is_nil()
            || request_digest == [0; 32]
            || binding_digest == [0; 32]
        {
            return Err(RecoveryRunStoreError::Invalid("nil identity"));
        }
        if classify_at.get() < claimed_at.get()
            || activity_limit.get() > 1_000
            || execution_limit.get() > 256
        {
            return Err(RecoveryRunStoreError::Invalid(
                "request bounds or timestamp order",
            ));
        }
        Ok(Self {
            request_id,
            workspace_id,
            owner_id,
            request_digest,
            binding_digest,
            duration,
            claimed_at,
            classify_at,
            activity_limit,
            execution_limit,
        })
    }
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryActivityFact {
    ordinal: u16,
    activity_id: ActivityId,
    workspace_id: WorkspaceId,
    before_state: ActivityState,
    before_revision: ActivityRevision,
    before_created_at: TimestampMillis,
    before_updated_at: TimestampMillis,
    before_lease_owner: RuntimeInstanceId,
    before_lease_until: TimestampMillis,
    before_lease_revision: ActivityLeaseRevision,
    after_revision: ActivityRevision,
    after_updated_at: TimestampMillis,
    after_lease_revision: ActivityLeaseRevision,
}

impl RecoveryActivityFact {
    pub fn from_before(
        ordinal: u16,
        before: &RegisteredActivity,
        after_revision: ActivityRevision,
        after_updated_at: TimestampMillis,
        after_lease_revision: ActivityLeaseRevision,
    ) -> Result<Self, RecoveryRunStoreError> {
        let Some(owner) = before.lease_owner_id() else {
            return Err(RecoveryRunStoreError::Invalid("activity lease owner"));
        };
        let Some(until) = before.lease_until() else {
            return Err(RecoveryRunStoreError::Invalid("activity lease expiry"));
        };
        if usize::from(ordinal) >= MAX_ACTIVITY_FACTS
            || before.id().into_uuid().is_nil()
            || before.workspace_id().into_uuid().is_nil()
            || owner.into_uuid().is_nil()
            || before.state() != ActivityState::Open
            || before.created_at().get() > before.updated_at().get()
            || until.get() <= before.updated_at().get()
            || after_revision
                != before
                    .revision()
                    .checked_next()
                    .map_err(|_| RecoveryRunStoreError::Overflow)?
            || after_lease_revision
                != before
                    .lease_revision()
                    .checked_next()
                    .map_err(|_| RecoveryRunStoreError::Overflow)?
            || after_updated_at.get() < before.updated_at().get()
        {
            return Err(RecoveryRunStoreError::Invalid("activity transition"));
        }
        Ok(Self {
            ordinal,
            activity_id: before.id(),
            workspace_id: before.workspace_id(),
            before_state: before.state(),
            before_revision: before.revision(),
            before_created_at: before.created_at(),
            before_updated_at: before.updated_at(),
            before_lease_owner: owner,
            before_lease_until: until,
            before_lease_revision: before.lease_revision(),
            after_revision,
            after_updated_at,
            after_lease_revision,
        })
    }

    pub const fn ordinal(&self) -> u16 {
        self.ordinal
    }
    pub const fn activity_id(&self) -> ActivityId {
        self.activity_id
    }
    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }
    pub const fn before_state(&self) -> ActivityState {
        self.before_state
    }
    pub const fn before_revision(&self) -> ActivityRevision {
        self.before_revision
    }
    pub const fn before_created_at(&self) -> TimestampMillis {
        self.before_created_at
    }
    pub const fn before_updated_at(&self) -> TimestampMillis {
        self.before_updated_at
    }
    pub const fn before_lease_owner(&self) -> RuntimeInstanceId {
        self.before_lease_owner
    }
    pub const fn before_lease_until(&self) -> TimestampMillis {
        self.before_lease_until
    }
    pub const fn before_lease_revision(&self) -> ActivityLeaseRevision {
        self.before_lease_revision
    }
    pub const fn after_revision(&self) -> ActivityRevision {
        self.after_revision
    }
    pub const fn after_updated_at(&self) -> TimestampMillis {
        self.after_updated_at
    }
    pub const fn after_lease_revision(&self) -> ActivityLeaseRevision {
        self.after_lease_revision
    }
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryExecutionFact {
    ordinal: u8,
    execution_id: ExecutionId,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    request_digest: ExecutionRequestDigest,
    before_state: ExecutionState,
    before_revision: ExecutionRevision,
    before_updated_at: TimestampMillis,
    after_revision: ExecutionRevision,
    after_updated_at: TimestampMillis,
    eligibility_activity_id: ActivityId,
    eligibility_activity_state: ActivityState,
    eligibility_activity_revision: ActivityRevision,
    eligibility_activity_updated_at: TimestampMillis,
    eligibility_activity_lease_owner: Option<RuntimeInstanceId>,
    eligibility_activity_lease_until: Option<TimestampMillis>,
    eligibility_activity_lease_revision: ActivityLeaseRevision,
    terminal_semantic_sequence: i64,
    effect_outbox_sequence: Option<i64>,
}

impl RecoveryExecutionFact {
    pub fn from_before_after(
        ordinal: u8,
        before: &RegisteredExecution,
        eligibility: &RegisteredActivity,
        after: &RegisteredExecution,
        terminal_semantic_sequence: i64,
        effect_outbox_sequence: Option<i64>,
    ) -> Result<Self, RecoveryRunStoreError> {
        let eligibility_lease = match eligibility.state() {
            ActivityState::Open => {
                let owner = eligibility
                    .lease_owner_id()
                    .ok_or(RecoveryRunStoreError::Invalid(
                        "execution eligibility owner",
                    ))?;
                let until = eligibility
                    .lease_until()
                    .ok_or(RecoveryRunStoreError::Invalid(
                        "execution eligibility expiry",
                    ))?;
                if until.get() <= eligibility.updated_at().get() || owner.into_uuid().is_nil() {
                    return Err(RecoveryRunStoreError::Invalid(
                        "execution eligibility lease",
                    ));
                }
                Some((owner, until))
            }
            ActivityState::Interrupted => {
                if eligibility.lease_owner_id().is_some() || eligibility.lease_until().is_some() {
                    return Err(RecoveryRunStoreError::Invalid(
                        "interrupted execution eligibility lease",
                    ));
                }
                None
            }
            ActivityState::Closed => {
                return Err(RecoveryRunStoreError::Invalid(
                    "execution eligibility state",
                ));
            }
        };
        if usize::from(ordinal) >= MAX_EXECUTION_FACTS
            || before.id().into_uuid().is_nil()
            || before.workspace_id().into_uuid().is_nil()
            || before.activity_id().into_uuid().is_nil()
            || before.id() != after.id()
            || before.workspace_id() != after.workspace_id()
            || before.activity_id() != after.activity_id()
            || before.request_digest() != after.request_digest()
            || !matches!(
                before.state(),
                ExecutionState::Starting | ExecutionState::Running
            )
            || after.state() != ExecutionState::Interrupted
            || after.revision()
                != before
                    .revision()
                    .checked_next()
                    .map_err(|_| RecoveryRunStoreError::Overflow)?
            || after.timestamps().updated_at().get() < before.timestamps().updated_at().get()
            || eligibility.workspace_id() != before.workspace_id()
            || eligibility.id() != before.activity_id()
            || terminal_semantic_sequence < 1
            || effect_outbox_sequence.is_some_and(|value| value < 1)
        {
            return Err(RecoveryRunStoreError::Invalid(
                "execution transition or eligibility",
            ));
        }
        Ok(Self {
            ordinal,
            execution_id: before.id(),
            workspace_id: before.workspace_id(),
            activity_id: before.activity_id(),
            request_digest: before.request_digest(),
            before_state: before.state(),
            before_revision: before.revision(),
            before_updated_at: before.timestamps().updated_at(),
            after_revision: after.revision(),
            after_updated_at: after.timestamps().updated_at(),
            eligibility_activity_id: eligibility.id(),
            eligibility_activity_state: eligibility.state(),
            eligibility_activity_revision: eligibility.revision(),
            eligibility_activity_updated_at: eligibility.updated_at(),
            eligibility_activity_lease_owner: eligibility_lease.map(|(owner, _)| owner),
            eligibility_activity_lease_until: eligibility_lease.map(|(_, until)| until),
            eligibility_activity_lease_revision: eligibility.lease_revision(),
            terminal_semantic_sequence,
            effect_outbox_sequence,
        })
    }

    pub const fn ordinal(&self) -> u8 {
        self.ordinal
    }
    pub const fn execution_id(&self) -> ExecutionId {
        self.execution_id
    }
    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }
    pub const fn activity_id(&self) -> ActivityId {
        self.activity_id
    }
    pub const fn request_digest(&self) -> ExecutionRequestDigest {
        self.request_digest
    }
    pub const fn before_state(&self) -> ExecutionState {
        self.before_state
    }
    pub const fn before_revision(&self) -> ExecutionRevision {
        self.before_revision
    }
    pub const fn before_updated_at(&self) -> TimestampMillis {
        self.before_updated_at
    }
    pub const fn after_revision(&self) -> ExecutionRevision {
        self.after_revision
    }
    pub const fn after_updated_at(&self) -> TimestampMillis {
        self.after_updated_at
    }
    pub const fn eligibility_activity_id(&self) -> ActivityId {
        self.eligibility_activity_id
    }
    pub const fn eligibility_activity_state(&self) -> ActivityState {
        self.eligibility_activity_state
    }
    pub const fn eligibility_activity_revision(&self) -> ActivityRevision {
        self.eligibility_activity_revision
    }
    pub const fn eligibility_activity_updated_at(&self) -> TimestampMillis {
        self.eligibility_activity_updated_at
    }
    pub const fn eligibility_activity_lease_owner(&self) -> Option<RuntimeInstanceId> {
        self.eligibility_activity_lease_owner
    }
    pub const fn eligibility_activity_lease_until(&self) -> Option<TimestampMillis> {
        self.eligibility_activity_lease_until
    }
    pub const fn eligibility_activity_lease_revision(&self) -> ActivityLeaseRevision {
        self.eligibility_activity_lease_revision
    }
    pub const fn terminal_semantic_sequence(&self) -> i64 {
        self.terminal_semantic_sequence
    }
    pub const fn effect_outbox_sequence(&self) -> Option<i64> {
        self.effect_outbox_sequence
    }
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryRunReceipt {
    request: RecoveryRunRequest,
    claimed_lease: RecoveryMaintenanceLease,
    released_lease: RecoveryMaintenanceLease,
    activities: Vec<RecoveryActivityFact>,
    executions: Vec<RecoveryExecutionFact>,
    receipt_digest: [u8; DIGEST_BYTES],
}

impl RecoveryRunReceipt {
    pub fn new(
        request: RecoveryRunRequest,
        claimed_lease: RecoveryMaintenanceLease,
        released_lease: RecoveryMaintenanceLease,
        activities: Vec<RecoveryActivityFact>,
        executions: Vec<RecoveryExecutionFact>,
    ) -> Result<Self, RecoveryRunStoreError> {
        validate_receipt_parts(
            &request,
            &claimed_lease,
            &released_lease,
            &activities,
            &executions,
        )?;
        let receipt_digest = receipt_digest(
            &request,
            &claimed_lease,
            &released_lease,
            &activities,
            &executions,
        );
        Ok(Self {
            request,
            claimed_lease,
            released_lease,
            activities,
            executions,
            receipt_digest,
        })
    }

    pub const fn request(&self) -> &RecoveryRunRequest {
        &self.request
    }
    pub const fn claimed_lease(&self) -> &RecoveryMaintenanceLease {
        &self.claimed_lease
    }
    pub const fn released_lease(&self) -> &RecoveryMaintenanceLease {
        &self.released_lease
    }
    pub fn activities(&self) -> &[RecoveryActivityFact] {
        &self.activities
    }
    pub fn executions(&self) -> &[RecoveryExecutionFact] {
        &self.executions
    }
    pub const fn receipt_digest(&self) -> &[u8; DIGEST_BYTES] {
        &self.receipt_digest
    }
}

fn validate_receipt_parts(
    request: &RecoveryRunRequest,
    claimed: &RecoveryMaintenanceLease,
    released: &RecoveryMaintenanceLease,
    activities: &[RecoveryActivityFact],
    executions: &[RecoveryExecutionFact],
) -> Result<(), RecoveryRunStoreError> {
    let next_claimed_revision = claimed
        .revision()
        .get()
        .checked_add(1)
        .ok_or(RecoveryRunStoreError::Overflow)?;
    if request.workspace_id.into_uuid().is_nil()
        || request.owner_id.into_uuid().is_nil()
        || claimed.workspace_id().into_uuid().is_nil()
        || released.workspace_id().into_uuid().is_nil()
        || claimed.workspace_id() != request.workspace_id
        || released.workspace_id() != request.workspace_id
        || claimed.owner_id() != Some(request.owner_id)
        || claimed.lease_until().is_none()
        || !claimed.is_live_at(request.claimed_at)
        || !claimed.is_live_at(request.classify_at)
        || claimed.lease_until().map(TimestampMillis::get)
            != request.claimed_at.get().checked_add(request.duration.get())
        || claimed.updated_at().get() > request.claimed_at.get()
        || !released.is_released()
        || released.epoch() != claimed.epoch()
        || released.revision().get() != next_claimed_revision
        || released.updated_at() != request.classify_at
        || request.classify_at.get() < request.claimed_at.get()
        || activities.len() > usize::try_from(request.activity_limit.get()).unwrap_or(usize::MAX)
        || executions.len() > usize::from(request.execution_limit.get())
    {
        return Err(RecoveryRunStoreError::Invalid("receipt metadata"));
    }
    for (ordinal, fact) in activities.iter().enumerate() {
        let expected_after_revision = fact.before_revision().get().checked_add(1);
        let expected_after_lease_revision = fact.before_lease_revision().get().checked_add(1);
        if usize::from(fact.ordinal()) != ordinal
            || ordinal >= MAX_ACTIVITY_FACTS
            || fact.activity_id().into_uuid().is_nil()
            || fact.workspace_id().into_uuid().is_nil()
            || fact.before_lease_owner().into_uuid().is_nil()
            || fact.workspace_id() != request.workspace_id
            || fact.before_state() != ActivityState::Open
            || expected_after_revision != Some(fact.after_revision().get())
            || expected_after_lease_revision != Some(fact.after_lease_revision().get())
            || fact.before_created_at().get() > fact.before_updated_at().get()
            || fact.before_lease_until().get() <= fact.before_updated_at().get()
            || fact.after_updated_at().get() < fact.before_updated_at().get()
            || fact.after_updated_at() != request.classify_at
            || fact.before_lease_until().get() > request.classify_at.get()
        {
            return Err(RecoveryRunStoreError::Invalid("activity fact"));
        }
    }
    for (ordinal, fact) in executions.iter().enumerate() {
        let expected_after_revision = fact.before_revision().get().checked_add(1);
        let eligibility_lease_valid = match fact.eligibility_activity_state() {
            ActivityState::Open => {
                fact.eligibility_activity_lease_owner().is_some()
                    && fact.eligibility_activity_lease_until().is_some()
            }
            ActivityState::Interrupted => {
                fact.eligibility_activity_lease_owner().is_none()
                    && fact.eligibility_activity_lease_until().is_none()
            }
            ActivityState::Closed => false,
        };
        if usize::from(fact.ordinal()) != ordinal
            || ordinal >= MAX_EXECUTION_FACTS
            || fact.execution_id().into_uuid().is_nil()
            || fact.workspace_id().into_uuid().is_nil()
            || fact.activity_id().into_uuid().is_nil()
            || fact.workspace_id() != request.workspace_id
            || expected_after_revision != Some(fact.after_revision().get())
            || !matches!(
                fact.before_state(),
                ExecutionState::Starting | ExecutionState::Running
            )
            || fact.eligibility_activity_id() != fact.activity_id()
            || fact.eligibility_activity_revision().get() < 1
            || fact
                .eligibility_activity_lease_owner()
                .is_some_and(|owner| owner.into_uuid().is_nil())
            || fact
                .eligibility_activity_lease_until()
                .is_some_and(|until| until.get() <= fact.eligibility_activity_updated_at().get())
            || !eligibility_lease_valid
            || fact.terminal_semantic_sequence() < 1
            || fact.effect_outbox_sequence().is_some_and(|value| value < 1)
            || fact.after_updated_at() != request.classify_at
            || fact.before_updated_at().get() > request.classify_at.get()
            || fact.eligibility_activity_updated_at().get() > request.classify_at.get()
            || (fact.eligibility_activity_state() == ActivityState::Open
                && fact
                    .eligibility_activity_lease_until()
                    .is_some_and(|until| until.get() > request.classify_at.get()))
        {
            return Err(RecoveryRunStoreError::Invalid("execution fact"));
        }
    }
    Ok(())
}

pub(crate) fn create_schema(connection: &Connection) -> Result<(), RecoveryRunStoreError> {
    connection.execute_batch(RUNS_SQL)?;
    connection.execute_batch(ACTIVITIES_SQL)?;
    connection.execute_batch(EXECUTIONS_SQL)?;
    Ok(())
}

pub(crate) const fn schema_objects() -> [(&'static str, &'static str); 3] {
    [
        ("table", "recovery_runs"),
        ("table", "recovery_run_activities"),
        ("table", "recovery_run_executions"),
    ]
}

pub(crate) fn validate_schema(connection: &Connection) -> Result<(), RecoveryRunStoreError> {
    for &(kind, name, expected) in &OBJECTS {
        let actual: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type = ?1 AND name = ?2",
                params![kind, name],
                |row| row.get(0),
            )
            .optional()?;
        if actual.as_deref().map(normalize_sql) != Some(normalize_sql(expected)) {
            return Err(RecoveryRunStoreError::DamagedSchema(name));
        }
    }
    validate_run_columns(connection)?;
    validate_activity_columns(connection)?;
    validate_execution_columns(connection)?;
    validate_foreign_keys_for_history(connection)
}

fn validate_run_columns(connection: &Connection) -> Result<(), RecoveryRunStoreError> {
    validate_columns(
        connection,
        "recovery_runs",
        &[
            ("request_id", "BLOB", 1, 1),
            ("workspace_id", "BLOB", 1, 0),
            ("owner_runtime_instance_id", "BLOB", 1, 0),
            ("request_digest", "BLOB", 1, 0),
            ("binding_digest", "BLOB", 1, 0),
            ("duration_ms", "INTEGER", 1, 0),
            ("claimed_at_ms", "INTEGER", 1, 0),
            ("classify_at_ms", "INTEGER", 1, 0),
            ("claimed_owner_id", "BLOB", 1, 0),
            ("claimed_lease_until_ms", "INTEGER", 1, 0),
            ("claimed_epoch", "INTEGER", 1, 0),
            ("claimed_updated_at_ms", "INTEGER", 1, 0),
            ("claimed_revision", "INTEGER", 1, 0),
            ("released_owner_id", "BLOB", 0, 0),
            ("released_lease_until_ms", "INTEGER", 0, 0),
            ("released_epoch", "INTEGER", 1, 0),
            ("released_updated_at_ms", "INTEGER", 1, 0),
            ("released_revision", "INTEGER", 1, 0),
            ("activity_limit", "INTEGER", 1, 0),
            ("execution_limit", "INTEGER", 1, 0),
            ("activity_count", "INTEGER", 1, 0),
            ("execution_count", "INTEGER", 1, 0),
            ("receipt_digest", "BLOB", 1, 0),
        ],
    )
}

fn validate_activity_columns(connection: &Connection) -> Result<(), RecoveryRunStoreError> {
    validate_columns(
        connection,
        "recovery_run_activities",
        &[
            ("request_id", "BLOB", 1, 1),
            ("ordinal", "INTEGER", 1, 2),
            ("activity_id", "BLOB", 1, 0),
            ("workspace_id", "BLOB", 1, 0),
            ("before_state", "INTEGER", 1, 0),
            ("before_revision", "INTEGER", 1, 0),
            ("before_created_at_ms", "INTEGER", 1, 0),
            ("before_updated_at_ms", "INTEGER", 1, 0),
            ("before_lease_owner_id", "BLOB", 1, 0),
            ("before_lease_until_ms", "INTEGER", 1, 0),
            ("before_lease_revision", "INTEGER", 1, 0),
            ("after_revision", "INTEGER", 1, 0),
            ("after_updated_at_ms", "INTEGER", 1, 0),
            ("after_lease_revision", "INTEGER", 1, 0),
        ],
    )
}

fn validate_execution_columns(connection: &Connection) -> Result<(), RecoveryRunStoreError> {
    validate_columns(
        connection,
        "recovery_run_executions",
        &[
            ("request_id", "BLOB", 1, 1),
            ("ordinal", "INTEGER", 1, 2),
            ("execution_id", "BLOB", 1, 0),
            ("workspace_id", "BLOB", 1, 0),
            ("activity_id", "BLOB", 1, 0),
            ("request_digest", "BLOB", 1, 0),
            ("before_state", "INTEGER", 1, 0),
            ("before_revision", "INTEGER", 1, 0),
            ("before_updated_at_ms", "INTEGER", 1, 0),
            ("after_revision", "INTEGER", 1, 0),
            ("after_updated_at_ms", "INTEGER", 1, 0),
            ("eligibility_activity_state", "INTEGER", 1, 0),
            ("eligibility_activity_revision", "INTEGER", 1, 0),
            ("eligibility_activity_updated_at_ms", "INTEGER", 1, 0),
            ("eligibility_activity_lease_owner_id", "BLOB", 0, 0),
            ("eligibility_activity_lease_until_ms", "INTEGER", 0, 0),
            ("eligibility_activity_lease_revision", "INTEGER", 1, 0),
            ("terminal_semantic_sequence", "INTEGER", 1, 0),
            ("effect_outbox_sequence", "INTEGER", 0, 0),
        ],
    )
}

fn validate_foreign_keys_for_history(connection: &Connection) -> Result<(), RecoveryRunStoreError> {
    validate_foreign_keys(
        connection,
        "recovery_runs",
        &[("workspace", "workspace_id", "workspace_id")],
    )?;
    validate_foreign_keys(
        connection,
        "recovery_run_activities",
        &[
            ("recovery_runs", "request_id", "request_id"),
            ("activities", "activity_id", "activity_id"),
            ("workspace", "workspace_id", "workspace_id"),
        ],
    )?;
    validate_foreign_keys(
        connection,
        "recovery_run_executions",
        &[
            ("recovery_runs", "request_id", "request_id"),
            ("executions", "execution_id", "execution_id"),
            ("workspace", "workspace_id", "workspace_id"),
            ("activities", "activity_id", "activity_id"),
        ],
    )?;
    Ok(())
}

fn normalize_sql(value: &str) -> String {
    value
        .chars()
        .filter(|value| !value.is_whitespace())
        .map(|value| value.to_ascii_lowercase())
        .collect()
}

fn validate_columns(
    connection: &Connection,
    table: &'static str,
    expected: &[(&str, &str, i64, i64)],
) -> Result<(), RecoveryRunStoreError> {
    let mut statement = connection.prepare(&format!("PRAGMA table_info({table})"))?;
    let mut rows = statement.query([])?;
    let mut actual = Vec::new();
    while let Some(row) = rows.next()? {
        if actual.len() > expected.len() {
            return Err(RecoveryRunStoreError::DamagedSchema(table));
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
        return Err(RecoveryRunStoreError::DamagedSchema(table));
    }
    Ok(())
}

fn validate_foreign_keys(
    connection: &Connection,
    table: &'static str,
    expected: &[(&str, &str, &str)],
) -> Result<(), RecoveryRunStoreError> {
    let mut statement = connection.prepare(&format!("PRAGMA foreign_key_list({table})"))?;
    let mut rows = statement.query([])?;
    let mut actual = Vec::new();
    while let Some(row) = rows.next()? {
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
        return Err(RecoveryRunStoreError::DamagedSchema(table));
    }
    Ok(())
}

pub(crate) fn append_in_transaction(
    transaction: &Transaction<'_>,
    receipt: &RecoveryRunReceipt,
) -> Result<(), RecoveryRunStoreError> {
    if let Some(existing) = get_for_request_in_transaction(
        transaction,
        receipt.request.workspace_id,
        receipt.request.request_id,
        receipt.request.request_digest,
        receipt.request.binding_digest,
    )? {
        return if existing == *receipt {
            Ok(())
        } else {
            Err(RecoveryRunStoreError::Conflict)
        };
    }
    insert_run(transaction, receipt)?;
    append_activity_facts(transaction, receipt.request.request_id, &receipt.activities)?;
    append_execution_facts(transaction, receipt.request.request_id, &receipt.executions)?;
    Ok(())
}

fn insert_run(
    transaction: &Transaction<'_>,
    receipt: &RecoveryRunReceipt,
) -> Result<(), RecoveryRunStoreError> {
    transaction.execute(
        "INSERT INTO recovery_runs(
            request_id, workspace_id, owner_runtime_instance_id, request_digest,
            binding_digest, duration_ms, claimed_at_ms, classify_at_ms,
            claimed_owner_id, claimed_lease_until_ms, claimed_epoch,
            claimed_updated_at_ms, claimed_revision, released_owner_id,
            released_lease_until_ms, released_epoch, released_updated_at_ms,
            released_revision, activity_limit, execution_limit, activity_count,
            execution_count, receipt_digest
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                   ?13, NULL, NULL, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21)",
        params![
            receipt.request.request_id.as_bytes(),
            receipt.request.workspace_id.into_uuid().as_bytes(),
            receipt.request.owner_id.into_uuid().as_bytes(),
            receipt.request.request_digest.as_slice(),
            receipt.request.binding_digest.as_slice(),
            receipt.request.duration.get(),
            receipt.request.claimed_at.get(),
            receipt.request.classify_at.get(),
            receipt
                .claimed_lease
                .owner_id()
                .unwrap_or(receipt.request.owner_id)
                .into_uuid()
                .as_bytes(),
            receipt
                .claimed_lease
                .lease_until()
                .map(TimestampMillis::get),
            receipt.claimed_lease.epoch().get(),
            receipt.claimed_lease.updated_at().get(),
            receipt.claimed_lease.revision().get(),
            receipt.released_lease.epoch().get(),
            receipt.released_lease.updated_at().get(),
            receipt.released_lease.revision().get(),
            i64::from(receipt.request.activity_limit.get()),
            i64::from(receipt.request.execution_limit.get()),
            i64::try_from(receipt.activities.len()).map_err(|_| RecoveryRunStoreError::Overflow)?,
            i64::try_from(receipt.executions.len()).map_err(|_| RecoveryRunStoreError::Overflow)?,
            receipt.receipt_digest.as_slice(),
        ],
    )?;
    Ok(())
}

fn append_activity_facts(
    transaction: &Transaction<'_>,
    request_id: Uuid,
    facts: &[RecoveryActivityFact],
) -> Result<(), RecoveryRunStoreError> {
    for fact in facts {
        transaction.execute(
            "INSERT INTO recovery_run_activities(
                request_id, ordinal, activity_id, workspace_id, before_state,
                before_revision, before_created_at_ms, before_updated_at_ms,
                before_lease_owner_id, before_lease_until_ms, before_lease_revision,
                after_revision, after_updated_at_ms, after_lease_revision
             ) VALUES (?1, ?2, ?3, ?4, 1, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                request_id.as_bytes(),
                i64::from(fact.ordinal()),
                fact.activity_id().into_uuid().as_bytes(),
                fact.workspace_id().into_uuid().as_bytes(),
                fact.before_revision().get(),
                fact.before_created_at().get(),
                fact.before_updated_at().get(),
                fact.before_lease_owner().into_uuid().as_bytes(),
                fact.before_lease_until().get(),
                fact.before_lease_revision().get(),
                fact.after_revision().get(),
                fact.after_updated_at().get(),
                fact.after_lease_revision().get(),
            ],
        )?;
    }
    Ok(())
}

fn append_execution_facts(
    transaction: &Transaction<'_>,
    request_id: Uuid,
    facts: &[RecoveryExecutionFact],
) -> Result<(), RecoveryRunStoreError> {
    for fact in facts {
        transaction.execute(
            "INSERT INTO recovery_run_executions(
                request_id, ordinal, execution_id, workspace_id, activity_id,
                request_digest, before_state, before_revision, before_updated_at_ms,
                after_revision, after_updated_at_ms, eligibility_activity_state,
                eligibility_activity_revision, eligibility_activity_updated_at_ms,
                eligibility_activity_lease_owner_id, eligibility_activity_lease_until_ms,
                eligibility_activity_lease_revision, terminal_semantic_sequence,
                effect_outbox_sequence
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                       ?13, ?14, ?15, ?16, ?17, ?18, ?19)",
            params![
                request_id.as_bytes(),
                i64::from(fact.ordinal()),
                fact.execution_id().into_uuid().as_bytes(),
                fact.workspace_id().into_uuid().as_bytes(),
                fact.activity_id().into_uuid().as_bytes(),
                fact.request_digest().as_bytes(),
                encode_execution_state(fact.before_state()),
                fact.before_revision().get(),
                fact.before_updated_at().get(),
                fact.after_revision().get(),
                fact.after_updated_at().get(),
                encode_activity_state(fact.eligibility_activity_state()),
                fact.eligibility_activity_revision().get(),
                fact.eligibility_activity_updated_at().get(),
                fact.eligibility_activity_lease_owner()
                    .map(|owner| owner.into_uuid().as_bytes().to_vec()),
                fact.eligibility_activity_lease_until()
                    .map(TimestampMillis::get),
                fact.eligibility_activity_lease_revision().get(),
                fact.terminal_semantic_sequence(),
                fact.effect_outbox_sequence(),
            ],
        )?;
    }
    Ok(())
}

pub(crate) fn get_for_request(
    connection: &Connection,
    workspace_id: WorkspaceId,
    request_id: Uuid,
    request_digest: [u8; DIGEST_BYTES],
    binding_digest: [u8; DIGEST_BYTES],
) -> Result<Option<RecoveryRunReceipt>, RecoveryRunStoreError> {
    get_for_request_in_transaction(
        connection,
        workspace_id,
        request_id,
        request_digest,
        binding_digest,
    )
}

fn get_for_request_in_transaction(
    connection: &Connection,
    workspace_id: WorkspaceId,
    request_id: Uuid,
    request_digest: [u8; DIGEST_BYTES],
    binding_digest: [u8; DIGEST_BYTES],
) -> Result<Option<RecoveryRunReceipt>, RecoveryRunStoreError> {
    if request_id.is_nil() || request_digest == [0; 32] || binding_digest == [0; 32] {
        return Err(RecoveryRunStoreError::Invalid(
            "invalid request history identity",
        ));
    }
    let original_workspace: Option<Vec<u8>> = connection
        .query_row(
            "SELECT substr(workspace_id,1,17) FROM recovery_runs WHERE request_id=?1",
            params![request_id.as_bytes()],
            |row| row.get(0),
        )
        .optional()?;
    if original_workspace
        .as_deref()
        .is_some_and(|id| id != workspace_id.into_uuid().as_bytes())
    {
        return Err(RecoveryRunStoreError::Conflict);
    }
    let Some(row) = connection
        .query_row(
            "SELECT request_id, workspace_id, owner_runtime_instance_id,
                    request_digest, binding_digest, duration_ms, claimed_at_ms,
                    classify_at_ms, claimed_owner_id, claimed_lease_until_ms,
                    claimed_epoch, claimed_updated_at_ms, claimed_revision,
                    released_owner_id, released_lease_until_ms, released_epoch,
                    released_updated_at_ms, released_revision, activity_limit,
                    execution_limit, activity_count, execution_count, receipt_digest
             FROM recovery_runs WHERE workspace_id = ?1 AND request_id = ?2",
            params![workspace_id.into_uuid().as_bytes(), request_id.as_bytes()],
            decode_run_row,
        )
        .optional()?
    else {
        return Ok(None);
    };
    if row.request_digest != request_digest || row.binding_digest != binding_digest {
        return Err(RecoveryRunStoreError::Conflict);
    }
    let request = RecoveryRunRequest::new(
        (row.request_id, row.workspace_id, row.owner_id),
        row.request_digest,
        row.binding_digest,
        RecoveryLeaseDurationMillis::new(row.duration_ms)
            .map_err(|_| RecoveryRunStoreError::Corrupt("duration"))?,
        (
            TimestampMillis::new(row.claimed_at_ms)
                .map_err(|_| RecoveryRunStoreError::Corrupt("claimed_at"))?,
            TimestampMillis::new(row.classify_at_ms)
                .map_err(|_| RecoveryRunStoreError::Corrupt("classify_at"))?,
        ),
        (
            ActivityListLimit::new(
                u32::try_from(row.activity_limit)
                    .map_err(|_| RecoveryRunStoreError::Corrupt("activity_limit"))?,
            )
            .map_err(|_| RecoveryRunStoreError::Corrupt("activity_limit"))?,
            ExecutionListLimit::new(
                u16::try_from(row.execution_limit)
                    .map_err(|_| RecoveryRunStoreError::Corrupt("execution_limit"))?,
            )
            .map_err(|_| RecoveryRunStoreError::Corrupt("execution_limit"))?,
        ),
    )
    .map_err(|_| RecoveryRunStoreError::Corrupt("request metadata"))?;
    let claimed = lease_from_row(
        request.workspace_id,
        Some(row.claimed_owner),
        Some(row.claimed_lease_until_ms),
        row.claimed_epoch,
        row.claimed_updated_at_ms,
        row.claimed_revision,
    )?;
    let released = lease_from_row(
        request.workspace_id,
        None,
        None,
        row.released_epoch,
        row.released_updated_at_ms,
        row.released_revision,
    )?;
    let activities = load_activity_facts(connection, request_id, row.activity_count)?;
    let executions = load_execution_facts(connection, request_id, row.execution_count)?;
    let receipt = RecoveryRunReceipt::new(request, claimed, released, activities, executions)
        .map_err(|_| RecoveryRunStoreError::Corrupt("receipt"))?;
    if receipt.receipt_digest() != &row.receipt_digest {
        return Err(RecoveryRunStoreError::Corrupt("receipt_digest"));
    }
    validate_fact_links(connection, &receipt)?;
    Ok(Some(receipt))
}

fn validate_fact_links(
    connection: &Connection,
    receipt: &RecoveryRunReceipt,
) -> Result<(), RecoveryRunStoreError> {
    for fact in receipt.executions() {
        let semantic: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM semantic_events
            WHERE sequence=?1 AND workspace_id=?2 AND event_kind='execution_terminal'
            AND subject_execution_id=?3 AND revision=?4 AND observed_at_ms=?5)",
            params![
                fact.terminal_semantic_sequence(),
                fact.workspace_id().into_uuid().as_bytes(),
                fact.execution_id().into_uuid().as_bytes(),
                fact.after_revision().get(),
                fact.after_updated_at().get()
            ],
            |row| row.get(0),
        )?;
        if !semantic {
            return Err(RecoveryRunStoreError::Corrupt("terminal semantic link"));
        }
        if let Some(sequence) = fact.effect_outbox_sequence() {
            let effect:bool=connection.query_row("SELECT EXISTS(SELECT 1 FROM effect_fact_outbox_execution_terminal
                WHERE outbox_sequence=?1 AND execution_id=?2 AND activity_id=?3 AND execution_revision=?4
                AND execution_state=6 AND observed_at_ms=?5)",
                params![sequence,fact.execution_id().into_uuid().as_bytes(),fact.activity_id().into_uuid().as_bytes(),
                    fact.after_revision().get(),fact.after_updated_at().get()],|row|row.get(0))?;
            if !effect {
                return Err(RecoveryRunStoreError::Corrupt("terminal effect link"));
            }
        }
    }
    Ok(())
}

struct RunRow {
    request_id: Uuid,
    workspace_id: WorkspaceId,
    owner_id: RuntimeInstanceId,
    request_digest: [u8; DIGEST_BYTES],
    binding_digest: [u8; DIGEST_BYTES],
    duration_ms: i64,
    claimed_at_ms: i64,
    classify_at_ms: i64,
    claimed_owner: RuntimeInstanceId,
    claimed_lease_until_ms: i64,
    claimed_epoch: i64,
    claimed_updated_at_ms: i64,
    claimed_revision: i64,
    released_epoch: i64,
    released_updated_at_ms: i64,
    released_revision: i64,
    activity_limit: i64,
    execution_limit: i64,
    activity_count: usize,
    execution_count: usize,
    receipt_digest: [u8; DIGEST_BYTES],
}

fn decode_run_row(row: &Row<'_>) -> rusqlite::Result<RunRow> {
    let released_owner = row.get_ref(13)?;
    let released_until: Option<i64> = row.get(14)?;
    if !matches!(released_owner, rusqlite::types::ValueRef::Null) || released_until.is_some() {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(RunRow {
        request_id: decode_uuid(row.get_ref(0)?.as_blob()?)?,
        workspace_id: WorkspaceId::from_uuid(decode_uuid(row.get_ref(1)?.as_blob()?)?),
        owner_id: RuntimeInstanceId::from_uuid(decode_uuid(row.get_ref(2)?.as_blob()?)?),
        request_digest: decode_digest(row.get_ref(3)?.as_blob()?)?,
        binding_digest: decode_digest(row.get_ref(4)?.as_blob()?)?,
        duration_ms: row.get(5)?,
        claimed_at_ms: row.get(6)?,
        classify_at_ms: row.get(7)?,
        claimed_owner: RuntimeInstanceId::from_uuid(decode_uuid(row.get_ref(8)?.as_blob()?)?),
        claimed_lease_until_ms: row.get(9)?,
        claimed_epoch: row.get(10)?,
        claimed_updated_at_ms: row.get(11)?,
        claimed_revision: row.get(12)?,
        released_epoch: row.get(15)?,
        released_updated_at_ms: row.get(16)?,
        released_revision: row.get(17)?,
        activity_limit: row.get(18)?,
        execution_limit: row.get(19)?,
        activity_count: usize::try_from(row.get::<_, i64>(20)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        execution_count: usize::try_from(row.get::<_, i64>(21)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        receipt_digest: decode_digest(row.get_ref(22)?.as_blob()?)?,
    })
}

fn lease_from_row(
    workspace_id: WorkspaceId,
    owner: Option<RuntimeInstanceId>,
    lease_until: Option<i64>,
    epoch: i64,
    updated_at: i64,
    revision: i64,
) -> Result<RecoveryMaintenanceLease, RecoveryRunStoreError> {
    RecoveryMaintenanceLease::from_parts(
        workspace_id,
        owner,
        lease_until
            .map(TimestampMillis::new)
            .transpose()
            .map_err(|_| RecoveryRunStoreError::Corrupt("lease_until"))?,
        forge_domain::RecoveryLeaseEpoch::new(epoch)
            .map_err(|_| RecoveryRunStoreError::Corrupt("lease_epoch"))?,
        TimestampMillis::new(updated_at)
            .map_err(|_| RecoveryRunStoreError::Corrupt("lease_updated_at"))?,
        forge_domain::RecoveryLeaseRevision::new(revision)
            .map_err(|_| RecoveryRunStoreError::Corrupt("lease_revision"))?,
    )
    .map_err(|_| RecoveryRunStoreError::Corrupt("lease snapshot"))
}

fn load_activity_facts(
    connection: &Connection,
    request_id: Uuid,
    expected_count: usize,
) -> Result<Vec<RecoveryActivityFact>, RecoveryRunStoreError> {
    if expected_count > MAX_ACTIVITY_FACTS {
        return Err(RecoveryRunStoreError::Overflow);
    }
    let mut statement = connection.prepare(
        "SELECT ordinal, activity_id, workspace_id, before_state, before_revision,
                before_created_at_ms, before_updated_at_ms, before_lease_owner_id,
                before_lease_until_ms, before_lease_revision, after_revision,
                after_updated_at_ms, after_lease_revision
         FROM recovery_run_activities WHERE request_id = ?1 ORDER BY ordinal LIMIT ?2",
    )?;
    let rows = statement
        .query_map(
            params![
                request_id.as_bytes(),
                i64::try_from(MAX_ACTIVITY_FACTS + 1).unwrap_or(i64::MAX)
            ],
            decode_activity_fact,
        )?
        .collect::<Result<Vec<_>, _>>()?;
    if rows.len() != expected_count || rows.len() > MAX_ACTIVITY_FACTS {
        return Err(RecoveryRunStoreError::Corrupt("activity fact count"));
    }
    Ok(rows)
}

fn load_execution_facts(
    connection: &Connection,
    request_id: Uuid,
    expected_count: usize,
) -> Result<Vec<RecoveryExecutionFact>, RecoveryRunStoreError> {
    if expected_count > MAX_EXECUTION_FACTS {
        return Err(RecoveryRunStoreError::Overflow);
    }
    let mut statement = connection.prepare(
        "SELECT ordinal, execution_id, workspace_id, activity_id, request_digest,
                before_state, before_revision, before_updated_at_ms, after_revision,
                after_updated_at_ms, eligibility_activity_state,
                eligibility_activity_revision, eligibility_activity_updated_at_ms,
                eligibility_activity_lease_owner_id, eligibility_activity_lease_until_ms,
                eligibility_activity_lease_revision, terminal_semantic_sequence,
                effect_outbox_sequence
         FROM recovery_run_executions WHERE request_id = ?1 ORDER BY ordinal LIMIT ?2",
    )?;
    let rows = statement
        .query_map(
            params![
                request_id.as_bytes(),
                i64::try_from(MAX_EXECUTION_FACTS + 1).unwrap_or(i64::MAX)
            ],
            decode_execution_fact,
        )?
        .collect::<Result<Vec<_>, _>>()?;
    if rows.len() != expected_count || rows.len() > MAX_EXECUTION_FACTS {
        return Err(RecoveryRunStoreError::Corrupt("execution fact count"));
    }
    Ok(rows)
}

fn decode_activity_fact(row: &Row<'_>) -> rusqlite::Result<RecoveryActivityFact> {
    let ordinal =
        u16::try_from(row.get::<_, i64>(0)?).map_err(|_| rusqlite::Error::InvalidQuery)?;
    let activity_id = ActivityId::from_uuid(decode_uuid(row.get_ref(1)?.as_blob()?)?);
    let workspace_id = WorkspaceId::from_uuid(decode_uuid(row.get_ref(2)?.as_blob()?)?);
    let before_state = match row.get::<_, i64>(3)? {
        1 => ActivityState::Open,
        _ => return Err(rusqlite::Error::InvalidQuery),
    };
    let before_revision =
        ActivityRevision::new(row.get(4)?).map_err(|_| rusqlite::Error::InvalidQuery)?;
    let before_created_at =
        TimestampMillis::new(row.get(5)?).map_err(|_| rusqlite::Error::InvalidQuery)?;
    let before_updated_at =
        TimestampMillis::new(row.get(6)?).map_err(|_| rusqlite::Error::InvalidQuery)?;
    let before_lease_owner = RuntimeInstanceId::from_uuid(decode_uuid(row.get_ref(7)?.as_blob()?)?);
    let before_lease_until =
        TimestampMillis::new(row.get(8)?).map_err(|_| rusqlite::Error::InvalidQuery)?;
    let before_lease_revision =
        ActivityLeaseRevision::new(row.get(9)?).map_err(|_| rusqlite::Error::InvalidQuery)?;
    let after_revision =
        ActivityRevision::new(row.get(10)?).map_err(|_| rusqlite::Error::InvalidQuery)?;
    let after_updated_at =
        TimestampMillis::new(row.get(11)?).map_err(|_| rusqlite::Error::InvalidQuery)?;
    let after_lease_revision =
        ActivityLeaseRevision::new(row.get(12)?).map_err(|_| rusqlite::Error::InvalidQuery)?;
    Ok(RecoveryActivityFact {
        ordinal,
        activity_id,
        workspace_id,
        before_state,
        before_revision,
        before_created_at,
        before_updated_at,
        before_lease_owner,
        before_lease_until,
        before_lease_revision,
        after_revision,
        after_updated_at,
        after_lease_revision,
    })
}

fn decode_execution_fact(row: &Row<'_>) -> rusqlite::Result<RecoveryExecutionFact> {
    let ordinal = u8::try_from(row.get::<_, i64>(0)?).map_err(|_| rusqlite::Error::InvalidQuery)?;
    let execution_id = ExecutionId::from_uuid(decode_uuid(row.get_ref(1)?.as_blob()?)?);
    let workspace_id = WorkspaceId::from_uuid(decode_uuid(row.get_ref(2)?.as_blob()?)?);
    let activity_id = ActivityId::from_uuid(decode_uuid(row.get_ref(3)?.as_blob()?)?);
    let request_digest =
        ExecutionRequestDigest::from_bytes(decode_digest(row.get_ref(4)?.as_blob()?)?);
    let before_state = match row.get::<_, i64>(5)? {
        0 => ExecutionState::Starting,
        1 => ExecutionState::Running,
        _ => return Err(rusqlite::Error::InvalidQuery),
    };
    let before_revision =
        ExecutionRevision::new(row.get(6)?).map_err(|_| rusqlite::Error::InvalidQuery)?;
    let before_updated_at =
        TimestampMillis::new(row.get(7)?).map_err(|_| rusqlite::Error::InvalidQuery)?;
    let after_revision =
        ExecutionRevision::new(row.get(8)?).map_err(|_| rusqlite::Error::InvalidQuery)?;
    let after_updated_at =
        TimestampMillis::new(row.get(9)?).map_err(|_| rusqlite::Error::InvalidQuery)?;
    let eligibility_activity_state = match row.get::<_, i64>(10)? {
        1 => ActivityState::Open,
        2 => ActivityState::Interrupted,
        _ => return Err(rusqlite::Error::InvalidQuery),
    };
    let eligibility_activity_revision =
        ActivityRevision::new(row.get(11)?).map_err(|_| rusqlite::Error::InvalidQuery)?;
    let eligibility_activity_updated_at =
        TimestampMillis::new(row.get(12)?).map_err(|_| rusqlite::Error::InvalidQuery)?;
    let eligibility_activity_lease_owner = decode_optional_runtime_instance_id(row.get_ref(13)?)?;
    let eligibility_activity_lease_until = decode_optional_timestamp(row.get_ref(14)?)?;
    let eligibility_activity_lease_revision =
        ActivityLeaseRevision::new(row.get(15)?).map_err(|_| rusqlite::Error::InvalidQuery)?;
    let terminal_semantic_sequence = row.get(16)?;
    let effect_outbox_sequence = row.get(17)?;
    Ok(RecoveryExecutionFact {
        ordinal,
        execution_id,
        workspace_id,
        activity_id,
        request_digest,
        before_state,
        before_revision,
        before_updated_at,
        after_revision,
        after_updated_at,
        eligibility_activity_id: activity_id,
        eligibility_activity_state,
        eligibility_activity_revision,
        eligibility_activity_updated_at,
        eligibility_activity_lease_owner,
        eligibility_activity_lease_until,
        eligibility_activity_lease_revision,
        terminal_semantic_sequence,
        effect_outbox_sequence,
    })
}

fn decode_optional_runtime_instance_id(
    value: rusqlite::types::ValueRef<'_>,
) -> rusqlite::Result<Option<RuntimeInstanceId>> {
    match value {
        rusqlite::types::ValueRef::Null => Ok(None),
        value => decode_uuid(value.as_blob()?)
            .map(RuntimeInstanceId::from_uuid)
            .map(Some),
    }
}

fn decode_optional_timestamp(
    value: rusqlite::types::ValueRef<'_>,
) -> rusqlite::Result<Option<TimestampMillis>> {
    match value {
        rusqlite::types::ValueRef::Null => Ok(None),
        value => TimestampMillis::new(value.as_i64()?)
            .map(Some)
            .map_err(|_| rusqlite::Error::InvalidQuery),
    }
}

fn decode_uuid(value: &[u8]) -> rusqlite::Result<Uuid> {
    if value.len() != ID_BYTES {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Uuid::from_slice(value).map_err(|_| rusqlite::Error::InvalidQuery)
}

fn decode_digest(value: &[u8]) -> rusqlite::Result<[u8; DIGEST_BYTES]> {
    value.try_into().map_err(|_| rusqlite::Error::InvalidQuery)
}

fn encode_execution_state(value: ExecutionState) -> i64 {
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

fn encode_activity_state(value: ActivityState) -> i64 {
    match value {
        ActivityState::Closed => 3,
        ActivityState::Open => 1,
        ActivityState::Interrupted => 2,
    }
}

fn receipt_digest(
    request: &RecoveryRunRequest,
    claimed: &RecoveryMaintenanceLease,
    released: &RecoveryMaintenanceLease,
    activities: &[RecoveryActivityFact],
    executions: &[RecoveryExecutionFact],
) -> [u8; DIGEST_BYTES] {
    let mut writer = DigestWriter::new(b"forge.recovery.maintenance.receipt.v1\0");
    writer.uuid(request.request_id);
    writer.uuid(request.workspace_id.into_uuid());
    writer.uuid(request.owner_id.into_uuid());
    writer.bytes(&request.request_digest);
    writer.bytes(&request.binding_digest);
    writer.i64(request.duration.get());
    writer.i64(request.claimed_at.get());
    writer.i64(request.classify_at.get());
    writer.u64(u64::from(request.activity_limit.get()));
    writer.u64(u64::from(request.execution_limit.get()));
    write_lease(&mut writer, claimed);
    write_lease(&mut writer, released);
    writer.u64(activities.len() as u64);
    for fact in activities {
        write_activity(&mut writer, fact);
    }
    writer.u64(executions.len() as u64);
    for fact in executions {
        write_execution(&mut writer, fact);
    }
    writer.finish()
}

fn write_lease(writer: &mut DigestWriter, lease: &RecoveryMaintenanceLease) {
    writer.uuid(lease.workspace_id().into_uuid());
    writer.option_uuid(lease.owner_id().map(RuntimeInstanceId::into_uuid));
    writer.option_i64(lease.lease_until().map(TimestampMillis::get));
    writer.i64(lease.epoch().get());
    writer.i64(lease.updated_at().get());
    writer.i64(lease.revision().get());
}

fn write_activity(writer: &mut DigestWriter, fact: &RecoveryActivityFact) {
    writer.u64(u64::from(fact.ordinal()));
    writer.uuid(fact.activity_id().into_uuid());
    writer.uuid(fact.workspace_id().into_uuid());
    writer.i64(encode_activity_state(fact.before_state()));
    writer.i64(fact.before_revision().get());
    writer.i64(fact.before_created_at().get());
    writer.i64(fact.before_updated_at().get());
    writer.uuid(fact.before_lease_owner().into_uuid());
    writer.i64(fact.before_lease_until().get());
    writer.i64(fact.before_lease_revision().get());
    writer.i64(fact.after_revision().get());
    writer.i64(fact.after_updated_at().get());
    writer.i64(fact.after_lease_revision().get());
}

fn write_execution(writer: &mut DigestWriter, fact: &RecoveryExecutionFact) {
    writer.u64(u64::from(fact.ordinal()));
    writer.uuid(fact.execution_id().into_uuid());
    writer.uuid(fact.workspace_id().into_uuid());
    writer.uuid(fact.activity_id().into_uuid());
    writer.bytes(fact.request_digest().as_bytes());
    writer.i64(encode_execution_state(fact.before_state()));
    writer.i64(fact.before_revision().get());
    writer.i64(fact.before_updated_at().get());
    writer.i64(fact.after_revision().get());
    writer.i64(fact.after_updated_at().get());
    writer.uuid(fact.eligibility_activity_id().into_uuid());
    writer.i64(encode_activity_state(fact.eligibility_activity_state()));
    writer.i64(fact.eligibility_activity_revision().get());
    writer.i64(fact.eligibility_activity_updated_at().get());
    writer.option_uuid(
        fact.eligibility_activity_lease_owner()
            .map(RuntimeInstanceId::into_uuid),
    );
    writer.option_i64(
        fact.eligibility_activity_lease_until()
            .map(TimestampMillis::get),
    );
    writer.i64(fact.eligibility_activity_lease_revision().get());
    writer.i64(fact.terminal_semantic_sequence());
    writer.option_i64(fact.effect_outbox_sequence());
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
    fn u8(&mut self, value: u8) {
        self.0.update([value]);
    }
    fn u64(&mut self, value: u64) {
        self.0.update(value.to_le_bytes());
    }
    fn i64(&mut self, value: i64) {
        self.0.update(value.to_le_bytes());
    }
    fn option_i64(&mut self, value: Option<i64>) {
        match value {
            Some(value) => {
                self.u8(1);
                self.i64(value);
            }
            None => self.u8(0),
        }
    }
    fn option_uuid(&mut self, value: Option<Uuid>) {
        match value {
            Some(value) => {
                self.u8(1);
                self.uuid(value);
            }
            None => self.u8(0),
        }
    }
    fn finish(self) -> [u8; DIGEST_BYTES] {
        self.0.finalize().into()
    }
}
