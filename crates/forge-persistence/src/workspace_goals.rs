//! Workspace-local persistence for the bounded durable Goal contract.

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;

use forge_domain::{
    ActivityId, ApprovalRequestId, ChangeSetId, CheckpointId, ExecutionId, ExecutionRequestDigest,
    FileContentHash, GoalBlocker, GoalBlockerKind, GoalCompletionBlocker, GoalContract,
    GoalContractError, GoalEvidenceRef, GoalFailure, GoalHardCheck, GoalId, GoalListLimit,
    GoalObjective, GoalPublicReason, GoalReview, GoalRevision, GoalStatement, GoalStatus,
    GoalStatusKind, GoalTextError, GoalTimestamps, GoalTransitionError,
    GoalVerificationRequirement, GoalWorkAttribution, RegisteredGoal, TimestampMillis, WorkspaceId,
    WorkspaceRelativePath,
};
#[cfg(test)]
use rusqlite::TransactionBehavior;
use rusqlite::{
    Connection, OptionalExtension, Row, Transaction, params, params_from_iter, types::Value,
};
use thiserror::Error;
use uuid::Uuid;

use crate::workspace_dags;
use crate::workspace_goal_creation_watermarks;
use crate::workspace_goal_deletion;
use crate::workspace_semantic_events::{
    self, SemanticEventAppend, SemanticEventKind, SemanticEventSubjects,
};

const MAX_GOAL_EVIDENCE: usize = 1_024;
const ID_BYTES: usize = 16;
const HASH_BYTES: usize = FileContentHash::BYTE_LEN;
const MAX_PATH_BYTES: usize = 4_096;

type GoalStatementRows = Vec<(i64, i64, GoalStatement)>;
type GoalStatementMap = HashMap<GoalId, GoalStatementRows>;

pub(crate) const EXPECTED_GOALS_TABLE_SQL: &str = "CREATE TABLE goals (goal_id BLOB PRIMARY KEY NOT NULL CHECK(length(goal_id) = 16), workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16), activity_id BLOB NOT NULL REFERENCES activities(activity_id) CHECK(length(activity_id) = 16), objective TEXT NOT NULL CHECK(length(CAST(objective AS BLOB)) BETWEEN 1 AND 4096), state INTEGER NOT NULL CHECK(state IN (0, 1, 2, 3, 4, 5)), reason_kind INTEGER CHECK(reason_kind IS NULL OR reason_kind IN (0, 1, 2, 3, 4, 5)), reason_text TEXT CHECK(reason_text IS NULL OR length(CAST(reason_text AS BLOB)) BETWEEN 1 AND 2048), completion_review_id BLOB REFERENCES goal_completion_reviews(review_id) CHECK(completion_review_id IS NULL OR length(completion_review_id) = 16), created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0), updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= created_at_ms), revision INTEGER NOT NULL CHECK(revision >= 1), CHECK((state IN (0, 1, 3, 5) AND reason_kind IS NULL AND reason_text IS NULL) OR (state = 2 AND reason_kind IS NOT NULL AND reason_text IS NOT NULL) OR (state = 4 AND reason_kind IS NULL AND reason_text IS NOT NULL)), CHECK((state = 3 AND completion_review_id IS NOT NULL) OR (state != 3 AND completion_review_id IS NULL)), CHECK((revision = 1 AND state = 0 AND updated_at_ms = created_at_ms) OR revision >= 2))";
pub(crate) const EXPECTED_GOAL_STATEMENTS_TABLE_SQL: &str = "CREATE TABLE goal_statements (goal_id BLOB NOT NULL REFERENCES goals(goal_id) CHECK(length(goal_id) = 16), statement_kind INTEGER NOT NULL CHECK(statement_kind IN (0, 1, 2, 3)), ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 0 AND 31), statement_text TEXT NOT NULL CHECK(length(CAST(statement_text AS BLOB)) BETWEEN 1 AND 1024), PRIMARY KEY(goal_id, statement_kind, ordinal))";
pub(crate) const EXPECTED_GOAL_REQUIREMENTS_TABLE_SQL: &str = "CREATE TABLE goal_verification_requirements (goal_id BLOB NOT NULL REFERENCES goals(goal_id) CHECK(length(goal_id) = 16), ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 0 AND 31), requirement_kind INTEGER NOT NULL CHECK(requirement_kind IN (0, 1, 2, 3)), execution_digest BLOB CHECK(execution_digest IS NULL OR length(execution_digest) = 32), relative_path BLOB CHECK(relative_path IS NULL OR length(relative_path) BETWEEN 1 AND 4096), expected_hash BLOB CHECK(expected_hash IS NULL OR length(expected_hash) = 32), source_id BLOB CHECK(source_id IS NULL OR length(source_id) = 16), description TEXT NOT NULL CHECK(length(CAST(description AS BLOB)) BETWEEN 1 AND 1024), PRIMARY KEY(goal_id, ordinal), CHECK((requirement_kind = 0 AND execution_digest IS NOT NULL AND relative_path IS NULL AND expected_hash IS NULL AND source_id IS NULL) OR (requirement_kind = 1 AND execution_digest IS NULL AND relative_path IS NOT NULL AND source_id IS NULL) OR (requirement_kind IN (2, 3) AND execution_digest IS NULL AND relative_path IS NULL AND expected_hash IS NULL AND source_id IS NOT NULL)))";
pub(crate) const EXPECTED_GOAL_EVIDENCE_TABLE_SQL: &str = "CREATE TABLE goal_evidence_refs (goal_id BLOB NOT NULL REFERENCES goals(goal_id) CHECK(length(goal_id) = 16), evidence_kind INTEGER NOT NULL CHECK(evidence_kind IN (0, 1, 2, 3)), evidence_id BLOB NOT NULL CHECK(length(evidence_id) = 16), associated_at_ms INTEGER NOT NULL CHECK(associated_at_ms >= 0), PRIMARY KEY(goal_id, evidence_kind, evidence_id), UNIQUE(evidence_kind, evidence_id))";
pub(crate) const EXPECTED_GOAL_REVIEWS_TABLE_SQL: &str = "CREATE TABLE goal_completion_reviews (review_id BLOB PRIMARY KEY NOT NULL CHECK(length(review_id) = 16), goal_id BLOB NOT NULL UNIQUE REFERENCES goals(goal_id) CHECK(length(goal_id) = 16), goal_revision INTEGER NOT NULL CHECK(goal_revision >= 1), observed_at_ms INTEGER NOT NULL CHECK(observed_at_ms >= 0), required_check_count INTEGER NOT NULL CHECK(required_check_count BETWEEN 0 AND 32), linked_evidence_count INTEGER NOT NULL CHECK(linked_evidence_count BETWEEN 0 AND 1024), pending_approval_count INTEGER NOT NULL CHECK(pending_approval_count = 0), active_execution_count INTEGER NOT NULL CHECK(active_execution_count = 0), unsealed_evidence_count INTEGER NOT NULL CHECK(unsealed_evidence_count = 0))";
pub(crate) const EXPECTED_GOALS_LIST_INDEX_SQL: &str = "CREATE INDEX goals_workspace_activity_state_updated_idx ON goals(workspace_id, activity_id, state, updated_at_ms DESC, goal_id DESC)";
pub(crate) const EXPECTED_GOAL_EVIDENCE_INDEX_SQL: &str = "CREATE INDEX goal_evidence_goal_time_idx ON goal_evidence_refs(goal_id, associated_at_ms DESC, evidence_kind, evidence_id)";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoalEvidenceRecord {
    goal_id: GoalId,
    evidence: GoalEvidenceRef,
    associated_at: TimestampMillis,
}

impl GoalEvidenceRecord {
    pub const fn goal_id(&self) -> GoalId {
        self.goal_id
    }

    pub const fn evidence(&self) -> GoalEvidenceRef {
        self.evidence
    }

    pub const fn associated_at(&self) -> TimestampMillis {
        self.associated_at
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoalCompletionReceipt {
    review_id: Uuid,
    goal_id: GoalId,
    goal_revision: GoalRevision,
    observed_at: TimestampMillis,
    required_check_count: u16,
    linked_evidence_count: u16,
}

impl GoalCompletionReceipt {
    pub const fn new(
        review_id: Uuid,
        goal_id: GoalId,
        goal_revision: GoalRevision,
        observed_at: TimestampMillis,
        required_check_count: u16,
        linked_evidence_count: u16,
    ) -> Self {
        Self {
            review_id,
            goal_id,
            goal_revision,
            observed_at,
            required_check_count,
            linked_evidence_count,
        }
    }

    pub const fn review_id(&self) -> Uuid {
        self.review_id
    }

    pub const fn goal_id(&self) -> GoalId {
        self.goal_id
    }
}

pub(crate) fn create_schema(connection: &Connection) -> Result<(), GoalStoreError> {
    connection.execute_batch(
        "CREATE TABLE goals (
            goal_id BLOB PRIMARY KEY NOT NULL CHECK(length(goal_id) = 16),
            workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16),
            activity_id BLOB NOT NULL REFERENCES activities(activity_id) CHECK(length(activity_id) = 16),
            objective TEXT NOT NULL CHECK(length(CAST(objective AS BLOB)) BETWEEN 1 AND 4096),
            state INTEGER NOT NULL CHECK(state IN (0, 1, 2, 3, 4, 5)),
            reason_kind INTEGER CHECK(reason_kind IS NULL OR reason_kind IN (0, 1, 2, 3, 4, 5)),
            reason_text TEXT CHECK(reason_text IS NULL OR length(CAST(reason_text AS BLOB)) BETWEEN 1 AND 2048),
            completion_review_id BLOB REFERENCES goal_completion_reviews(review_id)
                CHECK(completion_review_id IS NULL OR length(completion_review_id) = 16),
            created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
            updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= created_at_ms),
            revision INTEGER NOT NULL CHECK(revision >= 1),
            CHECK((state IN (0, 1, 3, 5) AND reason_kind IS NULL AND reason_text IS NULL)
               OR (state = 2 AND reason_kind IS NOT NULL AND reason_text IS NOT NULL)
               OR (state = 4 AND reason_kind IS NULL AND reason_text IS NOT NULL)),
            CHECK((state = 3 AND completion_review_id IS NOT NULL) OR (state != 3 AND completion_review_id IS NULL)),
            CHECK((revision = 1 AND state = 0 AND updated_at_ms = created_at_ms) OR revision >= 2)
         );
         CREATE TABLE goal_statements (
            goal_id BLOB NOT NULL REFERENCES goals(goal_id) CHECK(length(goal_id) = 16),
            statement_kind INTEGER NOT NULL CHECK(statement_kind IN (0, 1, 2, 3)),
            ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 0 AND 31),
            statement_text TEXT NOT NULL CHECK(length(CAST(statement_text AS BLOB)) BETWEEN 1 AND 1024),
            PRIMARY KEY(goal_id, statement_kind, ordinal)
         );
         CREATE TABLE goal_verification_requirements (
            goal_id BLOB NOT NULL REFERENCES goals(goal_id) CHECK(length(goal_id) = 16),
            ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 0 AND 31),
            requirement_kind INTEGER NOT NULL CHECK(requirement_kind IN (0, 1, 2, 3)),
            execution_digest BLOB CHECK(execution_digest IS NULL OR length(execution_digest) = 32),
            relative_path BLOB CHECK(relative_path IS NULL OR length(relative_path) BETWEEN 1 AND 4096),
            expected_hash BLOB CHECK(expected_hash IS NULL OR length(expected_hash) = 32),
            source_id BLOB CHECK(source_id IS NULL OR length(source_id) = 16),
            description TEXT NOT NULL CHECK(length(CAST(description AS BLOB)) BETWEEN 1 AND 1024),
            PRIMARY KEY(goal_id, ordinal),
            CHECK((requirement_kind = 0 AND execution_digest IS NOT NULL AND relative_path IS NULL AND expected_hash IS NULL AND source_id IS NULL)
               OR (requirement_kind = 1 AND execution_digest IS NULL AND relative_path IS NOT NULL AND source_id IS NULL)
               OR (requirement_kind IN (2, 3) AND execution_digest IS NULL AND relative_path IS NULL AND expected_hash IS NULL AND source_id IS NOT NULL))
         );
         CREATE TABLE goal_evidence_refs (
            goal_id BLOB NOT NULL REFERENCES goals(goal_id) CHECK(length(goal_id) = 16),
            evidence_kind INTEGER NOT NULL CHECK(evidence_kind IN (0, 1, 2, 3)),
            evidence_id BLOB NOT NULL CHECK(length(evidence_id) = 16),
            associated_at_ms INTEGER NOT NULL CHECK(associated_at_ms >= 0),
            PRIMARY KEY(goal_id, evidence_kind, evidence_id),
            UNIQUE(evidence_kind, evidence_id)
         );
         CREATE TABLE goal_completion_reviews (
            review_id BLOB PRIMARY KEY NOT NULL CHECK(length(review_id) = 16),
            goal_id BLOB NOT NULL UNIQUE REFERENCES goals(goal_id) CHECK(length(goal_id) = 16),
            goal_revision INTEGER NOT NULL CHECK(goal_revision >= 1),
            observed_at_ms INTEGER NOT NULL CHECK(observed_at_ms >= 0),
            required_check_count INTEGER NOT NULL CHECK(required_check_count BETWEEN 0 AND 32),
            linked_evidence_count INTEGER NOT NULL CHECK(linked_evidence_count BETWEEN 0 AND 1024),
            pending_approval_count INTEGER NOT NULL CHECK(pending_approval_count = 0),
            active_execution_count INTEGER NOT NULL CHECK(active_execution_count = 0),
            unsealed_evidence_count INTEGER NOT NULL CHECK(unsealed_evidence_count = 0)
         );
         CREATE INDEX goals_workspace_activity_state_updated_idx
            ON goals(workspace_id, activity_id, state, updated_at_ms DESC, goal_id DESC);
         CREATE INDEX goal_evidence_goal_time_idx
            ON goal_evidence_refs(goal_id, associated_at_ms DESC, evidence_kind, evidence_id);",
    )?;
    Ok(())
}

pub(crate) fn schema_objects() -> [(&'static str, &'static str); 7] {
    [
        ("table", "goals"),
        ("table", "goal_statements"),
        ("table", "goal_verification_requirements"),
        ("table", "goal_evidence_refs"),
        ("table", "goal_completion_reviews"),
        ("index", "goals_workspace_activity_state_updated_idx"),
        ("index", "goal_evidence_goal_time_idx"),
    ]
}

pub(crate) fn validate_schema(connection: &Connection) -> Result<(), GoalStoreError> {
    for (kind, name, expected) in [
        ("table", "goals", EXPECTED_GOALS_TABLE_SQL),
        (
            "table",
            "goal_statements",
            EXPECTED_GOAL_STATEMENTS_TABLE_SQL,
        ),
        (
            "table",
            "goal_verification_requirements",
            EXPECTED_GOAL_REQUIREMENTS_TABLE_SQL,
        ),
        (
            "table",
            "goal_evidence_refs",
            EXPECTED_GOAL_EVIDENCE_TABLE_SQL,
        ),
        (
            "table",
            "goal_completion_reviews",
            EXPECTED_GOAL_REVIEWS_TABLE_SQL,
        ),
        (
            "index",
            "goals_workspace_activity_state_updated_idx",
            EXPECTED_GOALS_LIST_INDEX_SQL,
        ),
        (
            "index",
            "goal_evidence_goal_time_idx",
            EXPECTED_GOAL_EVIDENCE_INDEX_SQL,
        ),
    ] {
        let actual: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type = ?1 AND name = ?2",
                params![kind, name],
                |row| row.get(0),
            )
            .optional()?;
        if actual.as_deref().map(normalize_sql) != Some(normalize_sql(expected)) {
            return Err(GoalStoreError::DamagedSchema(name));
        }
    }
    validate_foreign_keys(
        connection,
        "goals",
        &["workspace", "activities", "goal_completion_reviews"],
    )?;
    validate_foreign_keys(connection, "goal_statements", &["goals"])?;
    validate_foreign_keys(connection, "goal_verification_requirements", &["goals"])?;
    validate_foreign_keys(connection, "goal_evidence_refs", &["goals"])?;
    validate_foreign_keys(connection, "goal_completion_reviews", &["goals"])
}

fn normalize_sql(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect()
}

fn validate_foreign_keys(
    connection: &Connection,
    table: &'static str,
    expected_tables: &[&str],
) -> Result<(), GoalStoreError> {
    let mut statement = connection.prepare(&format!("PRAGMA foreign_key_list({table})"))?;
    let actual = statement
        .query_map([], |row| row.get::<_, String>(2))?
        .collect::<Result<Vec<_>, _>>()?;
    if actual.len() != expected_tables.len()
        || !expected_tables
            .iter()
            .all(|expected| actual.iter().any(|actual| actual == expected))
    {
        return Err(GoalStoreError::DamagedSchema(table));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn insert_goal(
    connection: &mut Connection,
    goal: &RegisteredGoal,
) -> Result<RegisteredGoal, GoalStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let result = insert_goal_in_transaction(&transaction, goal)?;
    transaction.commit()?;
    Ok(result)
}

pub(crate) fn insert_goal_in_transaction(
    transaction: &Transaction<'_>,
    goal: &RegisteredGoal,
) -> Result<RegisteredGoal, GoalStoreError> {
    validate_workspace(transaction, goal.workspace_id())?;
    validate_activity(transaction, goal.workspace_id(), goal.activity_id())?;
    if let Some(existing) = get_goal_in_transaction(transaction, goal.id())? {
        if existing == *goal {
            return Ok(existing);
        }
        return Err(GoalStoreError::IdentityConflict);
    }
    if goal.revision() != GoalRevision::INITIAL || goal.status().kind() != GoalStatusKind::Active {
        return Err(GoalStoreError::InvalidTransition);
    }
    if workspace_goal_deletion::has_pending_goal_cleanup(transaction, goal.id())? {
        return Err(GoalStoreError::CleanupJournalPending { goal_id: goal.id() });
    }
    let created_at_ms = goal.timestamps().created_at().get();
    if workspace_goal_creation_watermarks::greatest_created_at_ms(
        transaction,
        goal.workspace_id(),
        goal.id(),
    )?
    .is_some_and(|previous| created_at_ms <= previous)
    {
        return Err(GoalStoreError::CreationTimestampNotIncreasing { goal_id: goal.id() });
    }
    let encoded = encode_status(goal.status());
    transaction.execute(
        "INSERT INTO goals (
            goal_id, workspace_id, activity_id, objective, state, reason_kind, reason_text,
            completion_review_id, created_at_ms, updated_at_ms, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, ?8, ?8, ?9)",
        params![
            goal.id().into_uuid().as_bytes(),
            goal.workspace_id().into_uuid().as_bytes(),
            goal.activity_id().into_uuid().as_bytes(),
            goal.contract().objective().as_str(),
            encoded.state,
            encoded.reason_kind,
            encoded.reason_text,
            goal.timestamps().created_at().get(),
            goal.revision().get(),
        ],
    )?;
    insert_contract(transaction, goal.id(), goal.contract())?;
    if !workspace_goal_creation_watermarks::record_creation(
        transaction,
        goal.workspace_id(),
        goal.id(),
        created_at_ms,
    )? {
        return Err(GoalStoreError::CreationTimestampNotIncreasing { goal_id: goal.id() });
    }
    append_goal_event(transaction, goal, SemanticEventKind::GoalCreated)?;
    get_goal_in_transaction(transaction, goal.id())?.ok_or(GoalStoreError::RecordMissing)
}

pub(crate) fn get_goal(
    connection: &Connection,
    id: GoalId,
) -> Result<Option<RegisteredGoal>, GoalStoreError> {
    let Some(raw) = query_goal(connection, id)? else {
        return Ok(None);
    };
    assemble_goal(connection, raw).map(Some)
}

/// Append one Goal lifecycle semantic event inside the caller-owned
/// transition transaction.
fn append_goal_event(
    transaction: &Transaction<'_>,
    goal: &RegisteredGoal,
    kind: SemanticEventKind,
) -> Result<(), GoalStoreError> {
    workspace_semantic_events::append_semantic_event(
        transaction,
        &SemanticEventAppend::new(
            kind,
            goal.workspace_id(),
            SemanticEventSubjects {
                goal_id: Some(goal.id()),
                ..SemanticEventSubjects::NONE
            },
            goal.revision().get(),
            match kind {
                SemanticEventKind::GoalCreated => goal.timestamps().created_at(),
                _ => goal.timestamps().updated_at(),
            },
        ),
    )?;
    Ok(())
}

fn get_goal_in_transaction(
    transaction: &Transaction<'_>,
    id: GoalId,
) -> Result<Option<RegisteredGoal>, GoalStoreError> {
    let Some(raw) = query_goal(transaction, id)? else {
        return Ok(None);
    };
    assemble_goal(transaction, raw).map(Some)
}

pub(crate) fn list_goals(
    connection: &Connection,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    limit: GoalListLimit,
) -> Result<Vec<RegisteredGoal>, GoalStoreError> {
    let transaction = connection.unchecked_transaction()?;
    let mut statement = transaction.prepare(
        "SELECT g.goal_id, g.workspace_id, g.activity_id, g.objective, g.state, g.reason_kind, g.reason_text,
                g.created_at_ms, g.updated_at_ms, g.revision, g.completion_review_id,
                r.review_id, r.goal_id, r.goal_revision
         FROM goals AS g
         LEFT JOIN goal_completion_reviews AS r ON r.goal_id = g.goal_id
         WHERE g.workspace_id = ?1 AND g.activity_id = ?2
         ORDER BY g.updated_at_ms DESC, g.goal_id DESC LIMIT ?3",
    )?;
    let mapped = statement.query_map(
        params![
            workspace_id.into_uuid().as_bytes(),
            activity_id.into_uuid().as_bytes(),
            i64::from(limit.get())
        ],
        decode_raw_goal,
    )?;
    let records = mapped.collect::<Result<Vec<_>, _>>()?;
    drop(statement);
    let ids = records.iter().map(|raw| raw.id).collect::<Vec<_>>();
    let statements = preload_statements(&transaction, &ids)?;
    let requirements = preload_requirements(&transaction, &ids)?;
    let mut goals = Vec::with_capacity(limit.get() as usize);
    for raw in records {
        let id = raw.id;
        goals.push(assemble_goal_from_parts(
            raw,
            statements.get(&id).cloned().unwrap_or_default(),
            requirements.get(&id).cloned().unwrap_or_default(),
        )?);
    }
    transaction.commit()?;
    Ok(goals)
}

#[cfg(test)]
pub(crate) fn update_goal(
    connection: &mut Connection,
    goal: &RegisteredGoal,
    expected_revision: GoalRevision,
) -> Result<RegisteredGoal, GoalStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let result = update_goal_in_transaction(&transaction, goal, expected_revision)?;
    transaction.commit()?;
    Ok(result)
}

pub(crate) fn update_goal_in_transaction(
    transaction: &Transaction<'_>,
    goal: &RegisteredGoal,
    expected_revision: GoalRevision,
) -> Result<RegisteredGoal, GoalStoreError> {
    let current =
        get_goal_in_transaction(transaction, goal.id())?.ok_or(GoalStoreError::RecordMissing)?;
    if current == *goal {
        let expected_next = expected_revision
            .checked_next()
            .map_err(|_| GoalStoreError::RevisionOverflow)?;
        if goal.revision() == expected_next {
            return Ok(current);
        }
        return Err(GoalStoreError::RevisionConflict);
    }
    validate_goal_immutable(&current, goal)?;
    if current.revision() != expected_revision {
        return Err(GoalStoreError::RevisionConflict);
    }
    let expected_next = expected_revision
        .checked_next()
        .map_err(|_| GoalStoreError::RevisionOverflow)?;
    if goal.revision() != expected_next {
        return Err(GoalStoreError::RevisionConflict);
    }
    if goal.status().kind() == GoalStatusKind::Completed {
        return Err(GoalStoreError::CompletionReceiptRequired);
    }
    validate_goal_transition_projection(&current, goal, expected_revision)?;
    let encoded = encode_status(goal.status());
    let changed = transaction.execute(
        "UPDATE goals SET state = ?1, reason_kind = ?2, reason_text = ?3,
                updated_at_ms = ?4, revision = ?5
         WHERE goal_id = ?6 AND revision = ?7",
        params![
            encoded.state,
            encoded.reason_kind,
            encoded.reason_text,
            goal.timestamps().updated_at().get(),
            goal.revision().get(),
            goal.id().into_uuid().as_bytes(),
            expected_revision.get(),
        ],
    )?;
    if changed != 1 {
        return Err(GoalStoreError::RevisionConflict);
    }
    append_goal_event(transaction, goal, SemanticEventKind::GoalUpdated)?;
    get_goal_in_transaction(transaction, goal.id())?.ok_or(GoalStoreError::RecordMissing)
}

pub(crate) fn revise_goal_contract_in_transaction(
    transaction: &Transaction<'_>,
    goal: &RegisteredGoal,
    expected_revision: GoalRevision,
) -> Result<RegisteredGoal, GoalStoreError> {
    let current =
        get_goal_in_transaction(transaction, goal.id())?.ok_or(GoalStoreError::RecordMissing)?;
    if current.workspace_id() != goal.workspace_id()
        || current.activity_id() != goal.activity_id()
        || current.status() != goal.status()
    {
        return Err(GoalStoreError::InvalidTransition);
    }
    if current.status().is_terminal() {
        return Err(GoalStoreError::InvalidTransition);
    }
    if current.revision() != expected_revision {
        return Err(GoalStoreError::RevisionConflict);
    }
    let expected_next = expected_revision
        .checked_next()
        .map_err(|_| GoalStoreError::RevisionOverflow)?;
    if goal.revision() != expected_next
        || goal.timestamps().created_at() != current.timestamps().created_at()
        || goal.timestamps().updated_at().get() < current.timestamps().updated_at().get()
        || goal.contract() == current.contract()
    {
        return Err(GoalStoreError::InvalidTransition);
    }
    let changed = transaction.execute(
        "UPDATE goals SET objective = ?1, updated_at_ms = ?2, revision = ?3
         WHERE goal_id = ?4 AND revision = ?5",
        params![
            goal.contract().objective().as_str(),
            goal.timestamps().updated_at().get(),
            goal.revision().get(),
            goal.id().into_uuid().as_bytes(),
            expected_revision.get(),
        ],
    )?;
    if changed != 1 {
        return Err(GoalStoreError::RevisionConflict);
    }
    transaction.execute(
        "DELETE FROM goal_statements WHERE goal_id = ?1",
        params![goal.id().into_uuid().as_bytes()],
    )?;
    transaction.execute(
        "DELETE FROM goal_verification_requirements WHERE goal_id = ?1",
        params![goal.id().into_uuid().as_bytes()],
    )?;
    insert_contract(transaction, goal.id(), goal.contract())?;
    append_goal_event(transaction, goal, SemanticEventKind::GoalUpdated)?;
    get_goal_in_transaction(transaction, goal.id())?.ok_or(GoalStoreError::RecordMissing)
}

#[cfg(test)]
pub(crate) fn complete_goal(
    connection: &mut Connection,
    goal: &RegisteredGoal,
    expected_revision: GoalRevision,
    review: &GoalReview,
    receipt: &GoalCompletionReceipt,
) -> Result<RegisteredGoal, GoalStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let result =
        complete_goal_in_transaction(&transaction, goal, expected_revision, review, receipt)?;
    transaction.commit()?;
    Ok(result)
}

pub(crate) fn complete_goal_in_transaction(
    transaction: &Transaction<'_>,
    goal: &RegisteredGoal,
    expected_revision: GoalRevision,
    review: &GoalReview,
    receipt: &GoalCompletionReceipt,
) -> Result<RegisteredGoal, GoalStoreError> {
    if goal.status().kind() != GoalStatusKind::Completed
        || !review.can_complete()
        || review.goal_id() != goal.id()
        || review.goal_revision() != expected_revision
        || receipt.goal_id != goal.id()
        || receipt.goal_revision != expected_revision
        || receipt.observed_at != goal.timestamps().updated_at()
    {
        return Err(GoalStoreError::CompletionBlocked);
    }
    let current =
        get_goal_in_transaction(transaction, goal.id())?.ok_or(GoalStoreError::RecordMissing)?;
    if current == *goal {
        let existing = completion_receipt_exists(transaction, receipt)?;
        if existing {
            return Ok(current);
        }
        return Err(GoalStoreError::IdentityConflict);
    }
    validate_goal_immutable(&current, goal)?;
    if current.revision() != expected_revision
        || goal.revision()
            != expected_revision
                .checked_next()
                .map_err(|_| GoalStoreError::RevisionOverflow)?
    {
        return Err(GoalStoreError::RevisionConflict);
    }
    if current.status().kind() != GoalStatusKind::Active {
        return Err(GoalStoreError::InvalidTransition);
    }
    ensure_current_dag_completed(transaction, goal.id())?;
    let passed_file_requirements = current
        .contract()
        .verification_requirements()
        .iter()
        .enumerate()
        .filter_map(|(index, requirement)| {
            if !matches!(requirement, GoalVerificationRequirement::FilePresent { .. }) {
                return None;
            }
            let index = u16::try_from(index).ok()?;
            review
                .hard_checks()
                .iter()
                .any(|check| check.requirement_index() == index && check.is_passed())
                .then_some(index)
        })
        .collect::<HashSet<_>>();
    let durable_review =
        review_goal_with_file_results(transaction, goal.id(), &passed_file_requirements)?;
    if !durable_review.can_complete() {
        return Err(GoalStoreError::CompletionBlocked);
    }
    if durable_review != *review {
        return Err(GoalStoreError::ReviewMismatch);
    }
    let evidence_count = evidence_count(transaction, goal.id())?;
    if usize::from(receipt.linked_evidence_count) != evidence_count
        || usize::from(receipt.required_check_count) != review.hard_checks().len()
    {
        return Err(GoalStoreError::ReviewMismatch);
    }
    transaction.execute(
        "INSERT INTO goal_completion_reviews (
            review_id, goal_id, goal_revision, observed_at_ms,
            required_check_count, linked_evidence_count, pending_approval_count,
            active_execution_count, unsealed_evidence_count
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, 0, 0)",
        params![
            receipt.review_id.as_bytes(),
            receipt.goal_id.into_uuid().as_bytes(),
            receipt.goal_revision.get(),
            receipt.observed_at.get(),
            i64::from(receipt.required_check_count),
            i64::from(receipt.linked_evidence_count),
        ],
    )?;
    let changed = transaction.execute(
        "UPDATE goals SET state = 3, reason_kind = NULL, reason_text = NULL,
                completion_review_id = ?1, updated_at_ms = ?2, revision = ?3
         WHERE goal_id = ?4 AND state = 0 AND revision = ?5",
        params![
            receipt.review_id.as_bytes(),
            goal.timestamps().updated_at().get(),
            goal.revision().get(),
            goal.id().into_uuid().as_bytes(),
            expected_revision.get(),
        ],
    )?;
    if changed != 1 {
        return Err(GoalStoreError::RevisionConflict);
    }
    append_goal_event(transaction, goal, SemanticEventKind::GoalCompleted)?;
    get_goal_in_transaction(transaction, goal.id())?.ok_or(GoalStoreError::RecordMissing)
}

fn ensure_current_dag_completed(
    connection: &Connection,
    goal_id: GoalId,
) -> Result<(), GoalStoreError> {
    if workspace_dags::current_head_all_completed(connection, goal_id)? == Some(false) {
        Err(GoalStoreError::CompletionBlocked)
    } else {
        Ok(())
    }
}

#[cfg(test)]
pub(crate) fn associate_evidence(
    connection: &mut Connection,
    goal_id: GoalId,
    expected_revision: GoalRevision,
    evidence: GoalEvidenceRef,
    associated_at: TimestampMillis,
) -> Result<GoalEvidenceRecord, GoalStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let record = associate_evidence_in_transaction(
        &transaction,
        goal_id,
        expected_revision,
        evidence,
        associated_at,
    )?;
    transaction.commit()?;
    Ok(record)
}

pub(crate) fn associate_optional_evidence_in_transaction(
    transaction: &Transaction<'_>,
    attribution: Option<GoalWorkAttribution>,
    evidence: GoalEvidenceRef,
    associated_at: TimestampMillis,
) -> Result<Option<GoalEvidenceRecord>, GoalStoreError> {
    let Some(attribution) = attribution else {
        if evidence_owner(transaction, evidence)?.is_some() {
            return Err(GoalStoreError::EvidenceConflict);
        }
        return Ok(None);
    };
    associate_evidence_in_transaction(
        transaction,
        attribution.goal().goal_id(),
        attribution.goal().expected_revision(),
        evidence,
        associated_at,
    )
    .map(Some)
}

fn associate_evidence_in_transaction(
    transaction: &Transaction<'_>,
    goal_id: GoalId,
    expected_revision: GoalRevision,
    evidence: GoalEvidenceRef,
    associated_at: TimestampMillis,
) -> Result<GoalEvidenceRecord, GoalStoreError> {
    let goal =
        get_goal_in_transaction(transaction, goal_id)?.ok_or(GoalStoreError::RecordMissing)?;
    if goal.revision() != expected_revision {
        return Err(GoalStoreError::RevisionConflict);
    }
    if !goal.accepts_new_evidence() {
        return Err(GoalStoreError::EvidenceAssociationClosed);
    }
    if associated_at.get() < goal.timestamps().created_at().get() {
        return Err(GoalStoreError::EvidenceTimestamp);
    }
    validate_evidence_source(transaction, goal.workspace_id(), evidence)?;
    let (kind, id) = encode_evidence(evidence);
    let existing = evidence_owner(transaction, evidence)?;
    if let Some(existing) = existing {
        if existing.as_slice() == goal_id.into_uuid().as_bytes() {
            let record = get_evidence_record(transaction, goal_id, evidence)?
                .ok_or(GoalStoreError::RecordMissing)?;
            return Ok(record);
        }
        return Err(GoalStoreError::EvidenceConflict);
    }
    if evidence_count(transaction, goal_id)? >= MAX_GOAL_EVIDENCE {
        return Err(GoalStoreError::EvidenceLimit {
            maximum: MAX_GOAL_EVIDENCE,
        });
    }
    transaction.execute(
        "INSERT INTO goal_evidence_refs (goal_id, evidence_kind, evidence_id, associated_at_ms)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            goal_id.into_uuid().as_bytes(),
            kind,
            id.as_slice(),
            associated_at.get(),
        ],
    )?;
    let record = get_evidence_record(transaction, goal_id, evidence)?
        .ok_or(GoalStoreError::RecordMissing)?;
    Ok(record)
}

fn evidence_owner(
    connection: &Connection,
    evidence: GoalEvidenceRef,
) -> Result<Option<Vec<u8>>, GoalStoreError> {
    let (kind, id) = encode_evidence(evidence);
    connection
        .query_row(
            "SELECT goal_id FROM goal_evidence_refs WHERE evidence_kind = ?1 AND evidence_id = ?2",
            params![kind, id],
            |row| row.get(0),
        )
        .optional()
        .map_err(GoalStoreError::from)
}

pub(crate) fn list_evidence(
    connection: &Connection,
    goal_id: GoalId,
    limit: usize,
) -> Result<Vec<GoalEvidenceRecord>, GoalStoreError> {
    if limit == 0 || limit > MAX_GOAL_EVIDENCE {
        return Err(GoalStoreError::EvidenceLimit {
            maximum: MAX_GOAL_EVIDENCE,
        });
    }
    let mut statement = connection.prepare(
        "SELECT evidence_kind, evidence_id, associated_at_ms
         FROM goal_evidence_refs WHERE goal_id = ?1
         ORDER BY associated_at_ms DESC, evidence_kind, evidence_id LIMIT ?2",
    )?;
    let rows = statement.query_map(
        params![
            goal_id.into_uuid().as_bytes(),
            i64::try_from(limit).unwrap_or(i64::MAX)
        ],
        |row| {
            let kind: i64 = row.get(0)?;
            let id: Vec<u8> = row.get(1)?;
            let associated_at: i64 = row.get(2)?;
            Ok((kind, id, associated_at))
        },
    )?;
    let mut records = Vec::with_capacity(limit);
    for row in rows {
        let (kind, id, associated_at) = row?;
        records.push(GoalEvidenceRecord {
            goal_id,
            evidence: decode_evidence(kind, &id)?,
            associated_at: TimestampMillis::new(associated_at)
                .map_err(|_| GoalStoreError::CorruptRecord("goal_evidence.associated_at"))?,
        });
    }
    Ok(records)
}

pub(crate) fn review_goal(
    connection: &Connection,
    goal_id: GoalId,
) -> Result<GoalReview, GoalStoreError> {
    review_goal_with_file_results(connection, goal_id, &HashSet::new())
}

fn review_goal_with_file_results(
    connection: &Connection,
    goal_id: GoalId,
    passed_file_requirements: &HashSet<u16>,
) -> Result<GoalReview, GoalStoreError> {
    let goal = get_goal(connection, goal_id)?.ok_or(GoalStoreError::RecordMissing)?;
    let evidence = list_evidence(connection, goal_id, MAX_GOAL_EVIDENCE)?;
    let linked = evidence
        .iter()
        .map(GoalEvidenceRecord::evidence)
        .collect::<HashSet<_>>();
    let facts = preload_evidence_facts(connection, goal.workspace_id(), &evidence)?;
    let mut checks = Vec::with_capacity(goal.contract().verification_requirements().len());
    let mut blockers = Vec::new();
    for (index, requirement) in goal
        .contract()
        .verification_requirements()
        .iter()
        .enumerate()
    {
        let index = u16::try_from(index).map_err(|_| GoalStoreError::ReviewMismatch)?;
        let passed = match requirement {
            GoalVerificationRequirement::ExecutionSucceeded { request_digest, .. } => {
                execution_requirement(&facts, &linked, *request_digest)
            }
            GoalVerificationRequirement::FilePresent { .. } => {
                passed_file_requirements.contains(&index)
            }
            GoalVerificationRequirement::ChangeSetSealed { change_set_id, .. } => {
                changeset_requirement(&facts, &linked, *change_set_id)
            }
            GoalVerificationRequirement::CheckpointReady { checkpoint_id, .. } => {
                checkpoint_requirement(&facts, &linked, *checkpoint_id)
            }
        };
        checks.push(if passed {
            GoalHardCheck::Passed {
                requirement_index: index,
            }
        } else {
            blockers.push(GoalCompletionBlocker::RequiredVerification {
                requirement_index: index,
            });
            GoalHardCheck::Missing {
                requirement_index: index,
            }
        });
    }
    add_linked_state_blockers(&facts, &evidence, &mut blockers);
    GoalReview::new(goal.id(), goal.revision(), checks, blockers, true)
        .map_err(|_| GoalStoreError::ReviewMismatch)
}

#[cfg(test)]
pub(crate) fn evidence_is_goal_linked(
    connection: &Connection,
    evidence: GoalEvidenceRef,
) -> Result<bool, GoalStoreError> {
    let (kind, id) = encode_evidence(evidence);
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM goal_evidence_refs WHERE evidence_kind = ?1 AND evidence_id = ?2)",
            params![kind, id],
            |row| row.get(0),
        )
        .map_err(GoalStoreError::from)
}

#[derive(Debug)]
struct RawGoal {
    id: GoalId,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    objective: GoalObjective,
    status: GoalStatus,
    timestamps: GoalTimestamps,
    revision: GoalRevision,
}

fn query_goal(connection: &Connection, id: GoalId) -> Result<Option<RawGoal>, GoalStoreError> {
    connection
        .query_row(
            "SELECT g.goal_id, g.workspace_id, g.activity_id, g.objective, g.state, g.reason_kind, g.reason_text,
                    g.created_at_ms, g.updated_at_ms, g.revision, g.completion_review_id,
                    r.review_id, r.goal_id, r.goal_revision
             FROM goals AS g
             LEFT JOIN goal_completion_reviews AS r ON r.goal_id = g.goal_id
             WHERE g.goal_id = ?1",
            params![id.into_uuid().as_bytes()],
            decode_raw_goal,
        )
        .optional()
        .map_err(GoalStoreError::from)
}

fn decode_raw_goal(row: &Row<'_>) -> rusqlite::Result<RawGoal> {
    let goal_id: Vec<u8> = row.get(0)?;
    let workspace_id: Vec<u8> = row.get(1)?;
    let activity_id: Vec<u8> = row.get(2)?;
    let objective: String = row.get(3)?;
    let state: i64 = row.get(4)?;
    let reason_kind: Option<i64> = row.get(5)?;
    let reason_text: Option<String> = row.get(6)?;
    let created_at: i64 = row.get(7)?;
    let updated_at: i64 = row.get(8)?;
    let revision: i64 = row.get(9)?;
    let completion_review_id: Option<Vec<u8>> = row.get(10)?;
    let review_id: Option<Vec<u8>> = row.get(11)?;
    let review_goal_id: Option<Vec<u8>> = row.get(12)?;
    let review_goal_revision: Option<i64> = row.get(13)?;
    decode_raw_goal_values(
        &goal_id,
        &workspace_id,
        &activity_id,
        objective,
        state,
        reason_kind,
        reason_text,
        created_at,
        updated_at,
        revision,
        completion_review_id.as_deref(),
        review_id.as_deref(),
        review_goal_id.as_deref(),
        review_goal_revision,
    )
    .map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Blob, Box::new(error))
    })
}

#[allow(clippy::too_many_arguments)]
fn decode_raw_goal_values(
    goal_id: &[u8],
    workspace_id: &[u8],
    activity_id: &[u8],
    objective: String,
    state: i64,
    reason_kind: Option<i64>,
    reason_text: Option<String>,
    created_at: i64,
    updated_at: i64,
    revision: i64,
    completion_review_id: Option<&[u8]>,
    review_id: Option<&[u8]>,
    review_goal_id: Option<&[u8]>,
    review_goal_revision: Option<i64>,
) -> Result<RawGoal, GoalStoreError> {
    let decoded_goal_id = GoalId::from_uuid(decode_uuid("goal.id", goal_id)?);
    validate_completion_review_link(
        decoded_goal_id,
        state,
        revision,
        completion_review_id,
        review_id,
        review_goal_id,
        review_goal_revision,
    )?;
    Ok(RawGoal {
        id: decoded_goal_id,
        workspace_id: WorkspaceId::from_uuid(decode_uuid("goal.workspace_id", workspace_id)?),
        activity_id: ActivityId::from_uuid(decode_uuid("goal.activity_id", activity_id)?),
        objective: GoalObjective::new(objective)
            .map_err(|_| GoalStoreError::CorruptRecord("goal.objective"))?,
        status: decode_status(state, reason_kind, reason_text)?,
        timestamps: GoalTimestamps::new(
            TimestampMillis::new(created_at)
                .map_err(|_| GoalStoreError::CorruptRecord("goal.created_at"))?,
            TimestampMillis::new(updated_at)
                .map_err(|_| GoalStoreError::CorruptRecord("goal.updated_at"))?,
        )
        .map_err(|_| GoalStoreError::CorruptRecord("goal.timestamps"))?,
        revision: GoalRevision::new(revision)
            .map_err(|_| GoalStoreError::CorruptRecord("goal.revision"))?,
    })
}

#[allow(clippy::too_many_arguments)]
fn validate_completion_review_link(
    goal_id: GoalId,
    state: i64,
    revision: i64,
    completion_review_id: Option<&[u8]>,
    review_id: Option<&[u8]>,
    review_goal_id: Option<&[u8]>,
    review_goal_revision: Option<i64>,
) -> Result<(), GoalStoreError> {
    if state == 3 {
        let completion_review_id = decode_uuid(
            "goal.completion_review_id",
            completion_review_id
                .ok_or(GoalStoreError::CorruptRecord("goal.completion_review_id"))?,
        )?;
        let review_id = decode_uuid(
            "goal_review.review_id",
            review_id.ok_or(GoalStoreError::CorruptRecord("goal_review.review_id"))?,
        )?;
        let review_goal_id = GoalId::from_uuid(decode_uuid(
            "goal_review.goal_id",
            review_goal_id.ok_or(GoalStoreError::CorruptRecord("goal_review.goal_id"))?,
        )?);
        if completion_review_id != review_id
            || review_goal_id != goal_id
            || review_goal_revision != revision.checked_sub(1)
        {
            return Err(GoalStoreError::CorruptRecord("goal.completion_review"));
        }
    } else if completion_review_id.is_some()
        || review_id.is_some()
        || review_goal_id.is_some()
        || review_goal_revision.is_some()
    {
        return Err(GoalStoreError::CorruptRecord("goal.completion_review"));
    }
    Ok(())
}

fn assemble_goal(connection: &Connection, raw: RawGoal) -> Result<RegisteredGoal, GoalStoreError> {
    let statements = load_statements(connection, raw.id)?;
    let requirements = load_requirements(connection, raw.id)?;
    assemble_goal_from_parts(raw, statements, requirements)
}

fn assemble_goal_from_parts(
    raw: RawGoal,
    statements: Vec<(i64, i64, GoalStatement)>,
    requirements: Vec<(i64, GoalVerificationRequirement)>,
) -> Result<RegisteredGoal, GoalStoreError> {
    let mut success = Vec::new();
    let mut constraints = Vec::new();
    let mut out_of_scope = Vec::new();
    let mut stop_conditions = Vec::new();
    for (kind, _, statement) in statements {
        match kind {
            0 => success.push(statement),
            1 => constraints.push(statement),
            2 => out_of_scope.push(statement),
            3 => stop_conditions.push(statement),
            _ => return Err(GoalStoreError::CorruptRecord("goal_statement.kind")),
        }
    }
    let contract = GoalContract::new(
        raw.objective,
        success,
        constraints,
        out_of_scope,
        requirements
            .into_iter()
            .map(|(_, requirement)| requirement)
            .collect(),
        stop_conditions,
    )
    .map_err(GoalStoreError::Contract)?;
    RegisteredGoal::from_parts(
        raw.id,
        raw.workspace_id,
        raw.activity_id,
        contract,
        raw.status,
        raw.timestamps,
        raw.revision,
    )
    .map_err(GoalStoreError::Transition)
}

fn insert_contract(
    transaction: &Transaction<'_>,
    goal_id: GoalId,
    contract: &GoalContract,
) -> Result<(), GoalStoreError> {
    for (kind, values) in [
        (0_i64, contract.success_criteria()),
        (1, contract.constraints()),
        (2, contract.out_of_scope()),
        (3, contract.stop_conditions()),
    ] {
        for (ordinal, statement) in values.iter().enumerate() {
            transaction.execute(
                "INSERT INTO goal_statements (goal_id, statement_kind, ordinal, statement_text)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    goal_id.into_uuid().as_bytes(),
                    kind,
                    i64::try_from(ordinal).map_err(|_| GoalStoreError::ContractEncoding)?,
                    statement.as_str(),
                ],
            )?;
        }
    }
    for (ordinal, requirement) in contract.verification_requirements().iter().enumerate() {
        let encoded = encode_requirement(requirement);
        transaction.execute(
            "INSERT INTO goal_verification_requirements (
                goal_id, ordinal, requirement_kind, execution_digest, relative_path,
                expected_hash, source_id, description
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                goal_id.into_uuid().as_bytes(),
                i64::try_from(ordinal).map_err(|_| GoalStoreError::ContractEncoding)?,
                encoded.kind,
                encoded.execution_digest,
                encoded.relative_path,
                encoded.expected_hash,
                encoded.source_id,
                encoded.description,
            ],
        )?;
    }
    Ok(())
}

fn load_statements(
    connection: &Connection,
    goal_id: GoalId,
) -> Result<Vec<(i64, i64, GoalStatement)>, GoalStoreError> {
    let mut statement = connection.prepare(
        "SELECT statement_kind, ordinal, statement_text FROM goal_statements
         WHERE goal_id = ?1 ORDER BY statement_kind, ordinal",
    )?;
    let rows = statement.query_map(params![goal_id.into_uuid().as_bytes()], |row| {
        let kind = row.get(0)?;
        let ordinal = row.get(1)?;
        let text: String = row.get(2)?;
        Ok((kind, ordinal, text))
    })?;
    rows.map(|row| {
        let (kind, ordinal, text) = row?;
        Ok((
            kind,
            ordinal,
            GoalStatement::new(text)
                .map_err(|_| GoalStoreError::CorruptRecord("goal_statement.text"))?,
        ))
    })
    .collect()
}

fn load_requirements(
    connection: &Connection,
    goal_id: GoalId,
) -> Result<Vec<(i64, GoalVerificationRequirement)>, GoalStoreError> {
    let mut statement = connection.prepare(
        "SELECT ordinal, requirement_kind, execution_digest, relative_path,
                expected_hash, source_id, description
         FROM goal_verification_requirements WHERE goal_id = ?1 ORDER BY ordinal",
    )?;
    let rows = statement.query_map(params![goal_id.into_uuid().as_bytes()], |row| {
        Ok(RawRequirement {
            ordinal: row.get(0)?,
            kind: row.get(1)?,
            execution_digest: row.get(2)?,
            relative_path: row.get(3)?,
            expected_hash: row.get(4)?,
            source_id: row.get(5)?,
            description: row.get(6)?,
        })
    })?;
    rows.map(|row| {
        let raw = row?;
        Ok((raw.ordinal, decode_requirement(raw)?))
    })
    .collect()
}

fn preload_statements(
    connection: &Connection,
    ids: &[GoalId],
) -> Result<GoalStatementMap, GoalStoreError> {
    if ids.is_empty() {
        return Ok(HashMap::new());
    }
    let sql = format!(
        "SELECT goal_id, statement_kind, ordinal, statement_text FROM goal_statements
         WHERE goal_id IN ({}) ORDER BY goal_id, statement_kind, ordinal",
        placeholders(ids.len())
    );
    let values = ids
        .iter()
        .map(|id| Value::Blob(id.into_uuid().as_bytes().to_vec()))
        .collect::<Vec<_>>();
    let mut statement = connection.prepare(&sql)?;
    let rows = statement.query_map(params_from_iter(values), |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, String>(3)?,
        ))
    })?;
    let mut result = HashMap::with_capacity(ids.len());
    for row in rows {
        let (id, kind, ordinal, text) = row?;
        let id = GoalId::from_uuid(decode_uuid("goal_statement.goal_id", &id)?);
        let text = GoalStatement::new(text)
            .map_err(|_| GoalStoreError::CorruptRecord("goal_statement.text"))?;
        result
            .entry(id)
            .or_insert_with(Vec::new)
            .push((kind, ordinal, text));
    }
    Ok(result)
}

fn preload_requirements(
    connection: &Connection,
    ids: &[GoalId],
) -> Result<HashMap<GoalId, Vec<(i64, GoalVerificationRequirement)>>, GoalStoreError> {
    if ids.is_empty() {
        return Ok(HashMap::new());
    }
    let sql = format!(
        "SELECT goal_id, ordinal, requirement_kind, execution_digest, relative_path,
                expected_hash, source_id, description FROM goal_verification_requirements
         WHERE goal_id IN ({}) ORDER BY goal_id, ordinal",
        placeholders(ids.len())
    );
    let values = ids
        .iter()
        .map(|id| Value::Blob(id.into_uuid().as_bytes().to_vec()))
        .collect::<Vec<_>>();
    let mut statement = connection.prepare(&sql)?;
    let rows = statement.query_map(params_from_iter(values), |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            RawRequirement {
                ordinal: row.get(1)?,
                kind: row.get(2)?,
                execution_digest: row.get(3)?,
                relative_path: row.get(4)?,
                expected_hash: row.get(5)?,
                source_id: row.get(6)?,
                description: row.get(7)?,
            },
        ))
    })?;
    let mut result = HashMap::with_capacity(ids.len());
    for row in rows {
        let (id, raw) = row?;
        let id = GoalId::from_uuid(decode_uuid("goal_requirement.goal_id", &id)?);
        let ordinal = raw.ordinal;
        let requirement = decode_requirement(raw)?;
        result
            .entry(id)
            .or_insert_with(Vec::new)
            .push((ordinal, requirement));
    }
    Ok(result)
}

fn placeholders(count: usize) -> String {
    std::iter::repeat_n("?", count)
        .collect::<Vec<_>>()
        .join(",")
}

#[derive(Debug)]
struct EncodedRequirement {
    kind: i64,
    execution_digest: Option<Vec<u8>>,
    relative_path: Option<Vec<u8>>,
    expected_hash: Option<Vec<u8>>,
    source_id: Option<Vec<u8>>,
    description: String,
}

fn encode_requirement(requirement: &GoalVerificationRequirement) -> EncodedRequirement {
    match requirement {
        GoalVerificationRequirement::ExecutionSucceeded {
            request_digest,
            description,
        } => EncodedRequirement {
            kind: 0,
            execution_digest: Some(request_digest.as_bytes().to_vec()),
            relative_path: None,
            expected_hash: None,
            source_id: None,
            description: description.as_str().to_owned(),
        },
        GoalVerificationRequirement::FilePresent {
            path,
            expected_hash,
            description,
        } => EncodedRequirement {
            kind: 1,
            execution_digest: None,
            relative_path: Some(path.as_path().as_os_str().as_bytes().to_vec()),
            expected_hash: expected_hash.map(|hash| hash.as_bytes().to_vec()),
            source_id: None,
            description: description.as_str().to_owned(),
        },
        GoalVerificationRequirement::ChangeSetSealed {
            change_set_id,
            description,
        } => EncodedRequirement {
            kind: 2,
            execution_digest: None,
            relative_path: None,
            expected_hash: None,
            source_id: Some(change_set_id.into_uuid().as_bytes().to_vec()),
            description: description.as_str().to_owned(),
        },
        GoalVerificationRequirement::CheckpointReady {
            checkpoint_id,
            description,
        } => EncodedRequirement {
            kind: 3,
            execution_digest: None,
            relative_path: None,
            expected_hash: None,
            source_id: Some(checkpoint_id.into_uuid().as_bytes().to_vec()),
            description: description.as_str().to_owned(),
        },
    }
}

#[derive(Debug)]
struct RawRequirement {
    ordinal: i64,
    kind: i64,
    execution_digest: Option<Vec<u8>>,
    relative_path: Option<Vec<u8>>,
    expected_hash: Option<Vec<u8>>,
    source_id: Option<Vec<u8>>,
    description: String,
}

fn decode_requirement(raw: RawRequirement) -> Result<GoalVerificationRequirement, GoalStoreError> {
    let description = GoalStatement::new(raw.description)
        .map_err(|_| GoalStoreError::CorruptRecord("goal_requirement.description"))?;
    match raw.kind {
        0 => Ok(GoalVerificationRequirement::ExecutionSucceeded {
            request_digest: ExecutionRequestDigest::from_bytes(decode_fixed(
                "goal_requirement.execution_digest",
                raw.execution_digest.as_deref(),
            )?),
            description,
        }),
        1 => {
            let path = raw
                .relative_path
                .ok_or(GoalStoreError::CorruptRecord("goal_requirement.path"))?;
            if path.len() > MAX_PATH_BYTES {
                return Err(GoalStoreError::CorruptRecord("goal_requirement.path"));
            }
            let expected_hash = raw
                .expected_hash
                .as_deref()
                .map(|value| {
                    decode_fixed::<HASH_BYTES>("goal_requirement.expected_hash", Some(value))
                })
                .transpose()?
                .map(FileContentHash::from_bytes);
            Ok(GoalVerificationRequirement::FilePresent {
                path: WorkspaceRelativePath::new(PathBuf::from(OsString::from_vec(path)))
                    .map_err(|_| GoalStoreError::CorruptRecord("goal_requirement.path"))?,
                expected_hash,
                description,
            })
        }
        2 => Ok(GoalVerificationRequirement::ChangeSetSealed {
            change_set_id: ChangeSetId::from_uuid(decode_uuid(
                "goal_requirement.source_id",
                raw.source_id
                    .as_deref()
                    .ok_or(GoalStoreError::CorruptRecord("goal_requirement.source_id"))?,
            )?),
            description,
        }),
        3 => Ok(GoalVerificationRequirement::CheckpointReady {
            checkpoint_id: CheckpointId::from_uuid(decode_uuid(
                "goal_requirement.source_id",
                raw.source_id
                    .as_deref()
                    .ok_or(GoalStoreError::CorruptRecord("goal_requirement.source_id"))?,
            )?),
            description,
        }),
        _ => Err(GoalStoreError::CorruptRecord("goal_requirement.kind")),
    }
}

#[derive(Debug)]
struct EncodedStatus {
    state: i64,
    reason_kind: Option<i64>,
    reason_text: Option<String>,
}

fn encode_status(status: &GoalStatus) -> EncodedStatus {
    match status {
        GoalStatus::Active => EncodedStatus::plain(0),
        GoalStatus::Paused => EncodedStatus::plain(1),
        GoalStatus::Blocked(blocker) => EncodedStatus {
            state: 2,
            reason_kind: Some(encode_blocker_kind(blocker.kind())),
            reason_text: Some(blocker.reason().as_str().to_owned()),
        },
        GoalStatus::Completed => EncodedStatus::plain(3),
        GoalStatus::Failed(failure) => EncodedStatus {
            state: 4,
            reason_kind: None,
            reason_text: Some(failure.reason().as_str().to_owned()),
        },
        GoalStatus::Cancelled => EncodedStatus::plain(5),
    }
}

impl EncodedStatus {
    const fn plain(state: i64) -> Self {
        Self {
            state,
            reason_kind: None,
            reason_text: None,
        }
    }
}

fn decode_status(
    state: i64,
    reason_kind: Option<i64>,
    reason_text: Option<String>,
) -> Result<GoalStatus, GoalStoreError> {
    match state {
        0 if reason_kind.is_none() && reason_text.is_none() => Ok(GoalStatus::Active),
        1 if reason_kind.is_none() && reason_text.is_none() => Ok(GoalStatus::Paused),
        2 => Ok(GoalStatus::Blocked(GoalBlocker::new(
            decode_blocker_kind(
                reason_kind.ok_or(GoalStoreError::CorruptRecord("goal.reason_kind"))?,
            )?,
            GoalPublicReason::new(reason_text.ok_or(GoalStoreError::CorruptRecord("goal.reason"))?)
                .map_err(|_| GoalStoreError::CorruptRecord("goal.reason"))?,
        ))),
        3 if reason_kind.is_none() && reason_text.is_none() => Ok(GoalStatus::Completed),
        4 if reason_kind.is_none() => Ok(GoalStatus::Failed(GoalFailure::new(
            GoalPublicReason::new(reason_text.ok_or(GoalStoreError::CorruptRecord("goal.reason"))?)
                .map_err(|_| GoalStoreError::CorruptRecord("goal.reason"))?,
        ))),
        5 if reason_kind.is_none() && reason_text.is_none() => Ok(GoalStatus::Cancelled),
        _ => Err(GoalStoreError::CorruptRecord("goal.state")),
    }
}

const fn encode_blocker_kind(kind: GoalBlockerKind) -> i64 {
    match kind {
        GoalBlockerKind::ApprovalWait => 0,
        GoalBlockerKind::ExternalDependency => 1,
        GoalBlockerKind::VerificationFailure => 2,
        GoalBlockerKind::ResourceLimit => 3,
        GoalBlockerKind::UserDecision => 4,
        GoalBlockerKind::Other => 5,
    }
}

fn decode_blocker_kind(value: i64) -> Result<GoalBlockerKind, GoalStoreError> {
    match value {
        0 => Ok(GoalBlockerKind::ApprovalWait),
        1 => Ok(GoalBlockerKind::ExternalDependency),
        2 => Ok(GoalBlockerKind::VerificationFailure),
        3 => Ok(GoalBlockerKind::ResourceLimit),
        4 => Ok(GoalBlockerKind::UserDecision),
        5 => Ok(GoalBlockerKind::Other),
        _ => Err(GoalStoreError::CorruptRecord("goal.reason_kind")),
    }
}

fn validate_workspace(
    connection: &Connection,
    workspace_id: WorkspaceId,
) -> Result<(), GoalStoreError> {
    let exists: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM workspace WHERE workspace_id = ?1)",
        params![workspace_id.into_uuid().as_bytes()],
        |row| row.get(0),
    )?;
    if exists {
        Ok(())
    } else {
        Err(GoalStoreError::WorkspaceMismatch)
    }
}

fn validate_activity(
    connection: &Connection,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
) -> Result<(), GoalStoreError> {
    let actual: Option<Vec<u8>> = connection
        .query_row(
            "SELECT workspace_id FROM activities WHERE activity_id = ?1",
            params![activity_id.into_uuid().as_bytes()],
            |row| row.get(0),
        )
        .optional()?;
    let Some(actual) = actual else {
        return Err(GoalStoreError::ActivityMismatch);
    };
    let actual = WorkspaceId::from_uuid(
        decode_uuid("activity.workspace_id", &actual)
            .map_err(|_| GoalStoreError::ActivityMismatch)?,
    );
    if actual == workspace_id {
        Ok(())
    } else {
        Err(GoalStoreError::ActivityMismatch)
    }
}

fn validate_goal_immutable(
    current: &RegisteredGoal,
    requested: &RegisteredGoal,
) -> Result<(), GoalStoreError> {
    if current.id() == requested.id()
        && current.workspace_id() == requested.workspace_id()
        && current.activity_id() == requested.activity_id()
        && current.contract() == requested.contract()
        && current.timestamps().created_at() == requested.timestamps().created_at()
    {
        Ok(())
    } else {
        Err(GoalStoreError::IdentityConflict)
    }
}

fn validate_goal_transition_projection(
    current: &RegisteredGoal,
    requested: &RegisteredGoal,
    expected_revision: GoalRevision,
) -> Result<(), GoalStoreError> {
    let expected = match requested.status() {
        GoalStatus::Active => {
            current.resume(expected_revision, requested.timestamps().updated_at())
        }
        GoalStatus::Paused => current.pause(expected_revision, requested.timestamps().updated_at()),
        GoalStatus::Blocked(blocker) => current.block(
            expected_revision,
            blocker.clone(),
            requested.timestamps().updated_at(),
        ),
        GoalStatus::Failed(failure) => current.fail(
            expected_revision,
            failure.clone(),
            requested.timestamps().updated_at(),
        ),
        GoalStatus::Cancelled => {
            current.cancel(expected_revision, requested.timestamps().updated_at())
        }
        GoalStatus::Completed => return Err(GoalStoreError::CompletionReceiptRequired),
    }?;
    if expected == *requested {
        Ok(())
    } else {
        Err(GoalStoreError::InvalidTransition)
    }
}

pub(crate) const GOAL_EXECUTION_EVIDENCE_KIND: i64 = 1;

pub(crate) fn encode_evidence(evidence: GoalEvidenceRef) -> (i64, Vec<u8>) {
    match evidence {
        GoalEvidenceRef::ChangeSet(id) => (0, id.into_uuid().as_bytes().to_vec()),
        GoalEvidenceRef::Execution(id) => (
            GOAL_EXECUTION_EVIDENCE_KIND,
            id.into_uuid().as_bytes().to_vec(),
        ),
        GoalEvidenceRef::Approval(id) => (2, id.into_uuid().as_bytes().to_vec()),
        GoalEvidenceRef::Checkpoint(id) => (3, id.into_uuid().as_bytes().to_vec()),
    }
}

pub(crate) fn decode_evidence(kind: i64, id: &[u8]) -> Result<GoalEvidenceRef, GoalStoreError> {
    let id = decode_uuid("goal_evidence.id", id)?;
    match kind {
        0 => Ok(GoalEvidenceRef::ChangeSet(ChangeSetId::from_uuid(id))),
        GOAL_EXECUTION_EVIDENCE_KIND => Ok(GoalEvidenceRef::Execution(ExecutionId::from_uuid(id))),
        2 => Ok(GoalEvidenceRef::Approval(ApprovalRequestId::from_uuid(id))),
        3 => Ok(GoalEvidenceRef::Checkpoint(CheckpointId::from_uuid(id))),
        _ => Err(GoalStoreError::CorruptRecord("goal_evidence.kind")),
    }
}

fn validate_evidence_source(
    connection: &Connection,
    workspace_id: WorkspaceId,
    evidence: GoalEvidenceRef,
) -> Result<(), GoalStoreError> {
    if let GoalEvidenceRef::ChangeSet(id) = evidence {
        let actual: Option<(Vec<u8>, Option<i64>)> = connection
            .query_row(
                "SELECT c.workspace_id, d.state
                 FROM change_sets AS c
                 LEFT JOIN diff_evidence AS d ON d.changeset_id = c.changeset_id
                 WHERE c.changeset_id = ?1",
                params![id.into_uuid().as_bytes()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        return match actual {
            Some((actual_workspace, Some(0..=3)))
                if actual_workspace.as_slice() == workspace_id.into_uuid().as_bytes() =>
            {
                Ok(())
            }
            Some((actual_workspace, Some(0..=3)))
                if actual_workspace.as_slice() != workspace_id.into_uuid().as_bytes() =>
            {
                Err(GoalStoreError::WorkspaceMismatch)
            }
            Some((_, Some(4 | 5))) => Err(GoalStoreError::EvidenceConflict),
            Some((_, Some(_))) => Err(GoalStoreError::CorruptRecord("diff.state")),
            Some((_, None)) | None => Err(GoalStoreError::EvidenceMissing),
        };
    }
    let (table, column, id) = match evidence {
        GoalEvidenceRef::ChangeSet(_) => unreachable!("ChangeSet handled above"),
        GoalEvidenceRef::Execution(id) => ("executions", "execution_id", id.into_uuid()),
        GoalEvidenceRef::Approval(id) => ("approval_requests", "approval_id", id.into_uuid()),
        GoalEvidenceRef::Checkpoint(id) => ("checkpoints", "checkpoint_id", id.into_uuid()),
    };
    let sql = format!("SELECT workspace_id FROM {table} WHERE {column} = ?1");
    let actual: Option<Vec<u8>> = connection
        .query_row(&sql, params![id.as_bytes()], |row| row.get(0))
        .optional()?;
    match actual {
        Some(actual) if actual.as_slice() == workspace_id.into_uuid().as_bytes() => Ok(()),
        Some(_) => Err(GoalStoreError::WorkspaceMismatch),
        None => Err(GoalStoreError::EvidenceMissing),
    }
}

fn get_evidence_record(
    connection: &Connection,
    goal_id: GoalId,
    evidence: GoalEvidenceRef,
) -> Result<Option<GoalEvidenceRecord>, GoalStoreError> {
    let (kind, id) = encode_evidence(evidence);
    connection
        .query_row(
            "SELECT associated_at_ms FROM goal_evidence_refs
             WHERE goal_id = ?1 AND evidence_kind = ?2 AND evidence_id = ?3",
            params![goal_id.into_uuid().as_bytes(), kind, id],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .map(|associated_at| {
            Ok(GoalEvidenceRecord {
                goal_id,
                evidence,
                associated_at: TimestampMillis::new(associated_at)
                    .map_err(|_| GoalStoreError::CorruptRecord("goal_evidence.associated_at"))?,
            })
        })
        .transpose()
}

fn evidence_count(connection: &Connection, goal_id: GoalId) -> Result<usize, GoalStoreError> {
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM goal_evidence_refs WHERE goal_id = ?1",
        params![goal_id.into_uuid().as_bytes()],
        |row| row.get(0),
    )?;
    usize::try_from(count).map_err(|_| GoalStoreError::CorruptRecord("goal_evidence.count"))
}

fn completion_receipt_exists(
    connection: &Connection,
    receipt: &GoalCompletionReceipt,
) -> Result<bool, GoalStoreError> {
    let existing: Option<(Vec<u8>, i64, i64, i64)> = connection
        .query_row(
            "SELECT review_id, goal_revision, required_check_count, linked_evidence_count
             FROM goal_completion_reviews WHERE goal_id = ?1",
            params![receipt.goal_id.into_uuid().as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    Ok(existing.is_some_and(|(id, revision, checks, evidence)| {
        id.as_slice() == receipt.review_id.as_bytes()
            && revision == receipt.goal_revision.get()
            && checks == i64::from(receipt.required_check_count)
            && evidence == i64::from(receipt.linked_evidence_count)
    }))
}

#[derive(Debug, Clone, Copy)]
struct ExecutionFact {
    request_digest: ExecutionRequestDigest,
    state: i64,
}

#[derive(Debug, Default)]
struct GoalEvidenceFacts {
    executions: HashMap<ExecutionId, ExecutionFact>,
    approvals: HashMap<ApprovalRequestId, i64>,
    change_sets: HashMap<ChangeSetId, i64>,
    checkpoints: HashMap<CheckpointId, i64>,
}

fn preload_evidence_facts(
    connection: &Connection,
    workspace_id: WorkspaceId,
    evidence: &[GoalEvidenceRecord],
) -> Result<GoalEvidenceFacts, GoalStoreError> {
    let mut execution_ids = Vec::new();
    let mut approval_ids = Vec::new();
    let mut change_set_ids = Vec::new();
    let mut checkpoint_ids = Vec::new();
    for record in evidence {
        match record.evidence() {
            GoalEvidenceRef::Execution(id) => execution_ids.push(id),
            GoalEvidenceRef::Approval(id) => approval_ids.push(id),
            GoalEvidenceRef::ChangeSet(id) => change_set_ids.push(id),
            GoalEvidenceRef::Checkpoint(id) => checkpoint_ids.push(id),
        }
    }
    Ok(GoalEvidenceFacts {
        executions: preload_execution_facts(connection, workspace_id, &execution_ids)?,
        approvals: preload_state_facts(
            connection,
            workspace_id,
            "approval_requests",
            "approval_id",
            &approval_ids,
            ApprovalRequestId::from_uuid,
            ApprovalRequestId::into_uuid,
        )?,
        change_sets: preload_state_facts(
            connection,
            workspace_id,
            "change_sets",
            "changeset_id",
            &change_set_ids,
            ChangeSetId::from_uuid,
            ChangeSetId::into_uuid,
        )?,
        checkpoints: preload_state_facts(
            connection,
            workspace_id,
            "checkpoints",
            "checkpoint_id",
            &checkpoint_ids,
            CheckpointId::from_uuid,
            CheckpointId::into_uuid,
        )?,
    })
}

fn preload_execution_facts(
    connection: &Connection,
    workspace_id: WorkspaceId,
    ids: &[ExecutionId],
) -> Result<HashMap<ExecutionId, ExecutionFact>, GoalStoreError> {
    if ids.is_empty() {
        return Ok(HashMap::new());
    }
    let sql = format!(
        "SELECT execution_id, workspace_id, request_digest, state FROM executions
         WHERE execution_id IN ({})",
        placeholders(ids.len())
    );
    let values = ids
        .iter()
        .map(|id| Value::Blob(id.into_uuid().as_bytes().to_vec()))
        .collect::<Vec<_>>();
    let mut statement = connection.prepare(&sql)?;
    let rows = statement.query_map(params_from_iter(values), |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, Vec<u8>>(2)?,
            row.get::<_, i64>(3)?,
        ))
    })?;
    let mut result = HashMap::with_capacity(ids.len());
    for row in rows {
        let (id, actual_workspace, digest, state) = row?;
        validate_evidence_workspace(workspace_id, &actual_workspace)?;
        let id = ExecutionId::from_uuid(decode_uuid("execution.execution_id", &id)?);
        let digest = ExecutionRequestDigest::from_bytes(
            digest
                .try_into()
                .map_err(|_| GoalStoreError::CorruptRecord("execution.request_digest"))?,
        );
        if result
            .insert(
                id,
                ExecutionFact {
                    request_digest: digest,
                    state,
                },
            )
            .is_some()
        {
            return Err(GoalStoreError::CorruptRecord("execution.execution_id"));
        }
    }
    if result.len() != ids.len() {
        return Err(GoalStoreError::EvidenceMissing);
    }
    Ok(result)
}

fn preload_state_facts<Id>(
    connection: &Connection,
    workspace_id: WorkspaceId,
    table: &'static str,
    id_column: &'static str,
    ids: &[Id],
    from_uuid: fn(Uuid) -> Id,
    into_uuid: fn(Id) -> Uuid,
) -> Result<HashMap<Id, i64>, GoalStoreError>
where
    Id: Copy + Eq + std::hash::Hash,
{
    if ids.is_empty() {
        return Ok(HashMap::new());
    }
    let sql = format!(
        "SELECT {id_column}, workspace_id, state FROM {table}
         WHERE {id_column} IN ({})",
        placeholders(ids.len())
    );
    let values = ids
        .iter()
        .copied()
        .map(into_uuid)
        .map(|id| Value::Blob(id.as_bytes().to_vec()))
        .collect::<Vec<_>>();
    let mut statement = connection.prepare(&sql)?;
    let rows = statement.query_map(params_from_iter(values), |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, i64>(2)?,
        ))
    })?;
    let mut result = HashMap::with_capacity(ids.len());
    for row in rows {
        let (id, actual_workspace, state) = row?;
        validate_evidence_workspace(workspace_id, &actual_workspace)?;
        let id = from_uuid(decode_uuid("goal_evidence.source_id", &id)?);
        if result.insert(id, state).is_some() {
            return Err(GoalStoreError::CorruptRecord("goal_evidence.source_id"));
        }
    }
    if result.len() != ids.len() {
        return Err(GoalStoreError::EvidenceMissing);
    }
    Ok(result)
}

fn validate_evidence_workspace(expected: WorkspaceId, actual: &[u8]) -> Result<(), GoalStoreError> {
    if actual == expected.into_uuid().as_bytes() {
        Ok(())
    } else {
        Err(GoalStoreError::WorkspaceMismatch)
    }
}

fn execution_requirement(
    facts: &GoalEvidenceFacts,
    linked: &HashSet<GoalEvidenceRef>,
    digest: ExecutionRequestDigest,
) -> bool {
    facts.executions.iter().any(|(id, fact)| {
        linked.contains(&GoalEvidenceRef::Execution(*id))
            && fact.request_digest == digest
            && fact.state == 2
    })
}

fn changeset_requirement(
    facts: &GoalEvidenceFacts,
    linked: &HashSet<GoalEvidenceRef>,
    id: ChangeSetId,
) -> bool {
    linked.contains(&GoalEvidenceRef::ChangeSet(id))
        && facts.change_sets.get(&id).is_some_and(|state| *state == 1)
}

fn checkpoint_requirement(
    facts: &GoalEvidenceFacts,
    linked: &HashSet<GoalEvidenceRef>,
    id: CheckpointId,
) -> bool {
    linked.contains(&GoalEvidenceRef::Checkpoint(id))
        && facts.checkpoints.get(&id).is_some_and(|state| *state == 1)
}

fn add_linked_state_blockers(
    facts: &GoalEvidenceFacts,
    evidence: &[GoalEvidenceRecord],
    blockers: &mut Vec<GoalCompletionBlocker>,
) {
    for record in evidence {
        match record.evidence() {
            GoalEvidenceRef::Approval(id) if facts.approvals.get(&id) == Some(&0) => {
                blockers.push(GoalCompletionBlocker::PendingApproval(id));
            }
            GoalEvidenceRef::Execution(id) => {
                if facts
                    .executions
                    .get(&id)
                    .is_some_and(|fact| fact.state == 0 || fact.state == 1)
                {
                    blockers.push(GoalCompletionBlocker::ActiveExecution(id));
                }
            }
            GoalEvidenceRef::ChangeSet(id) if facts.change_sets.get(&id) == Some(&0) => {
                blockers.push(GoalCompletionBlocker::UnsealedEvidence(
                    GoalEvidenceRef::ChangeSet(id),
                ));
            }
            GoalEvidenceRef::Checkpoint(id) if facts.checkpoints.get(&id) == Some(&0) => {
                blockers.push(GoalCompletionBlocker::UnsealedEvidence(
                    GoalEvidenceRef::Checkpoint(id),
                ));
            }
            GoalEvidenceRef::Approval(_)
            | GoalEvidenceRef::ChangeSet(_)
            | GoalEvidenceRef::Checkpoint(_) => {}
        }
    }
}

fn decode_uuid(field: &'static str, value: &[u8]) -> Result<Uuid, GoalStoreError> {
    if value.len() != ID_BYTES {
        return Err(GoalStoreError::CorruptRecord(field));
    }
    Uuid::from_slice(value).map_err(|_| GoalStoreError::CorruptRecord(field))
}

fn decode_fixed<const N: usize>(
    field: &'static str,
    value: Option<&[u8]>,
) -> Result<[u8; N], GoalStoreError> {
    value
        .ok_or(GoalStoreError::CorruptRecord(field))?
        .try_into()
        .map_err(|_| GoalStoreError::CorruptRecord(field))
}

#[derive(Debug, Error)]
pub enum GoalStoreError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    SemanticEvents(#[from] crate::SemanticEventError),
    #[error(transparent)]
    Contract(#[from] GoalContractError),
    #[error(transparent)]
    Text(#[from] GoalTextError),
    #[error(transparent)]
    Transition(#[from] GoalTransitionError),
    #[error("Goal record is missing")]
    RecordMissing,
    #[error("Goal identity or immutable contract conflicts")]
    IdentityConflict,
    #[error("Goal creation timestamp for {goal_id} must advance beyond retained history")]
    CreationTimestampNotIncreasing { goal_id: GoalId },
    #[error("Goal {goal_id} cannot be reused while filesystem cleanup is pending")]
    CleanupJournalPending { goal_id: GoalId },
    #[error("Goal revision conflict")]
    RevisionConflict,
    #[error("Goal revision overflow")]
    RevisionOverflow,
    #[error("Goal transition is invalid")]
    InvalidTransition,
    #[error("Goal completion requires an immutable review receipt")]
    CompletionReceiptRequired,
    #[error("Goal completion is blocked")]
    CompletionBlocked,
    #[error("Goal completion review does not match")]
    ReviewMismatch,
    #[error("Goal evidence association is closed")]
    EvidenceAssociationClosed,
    #[error("Goal evidence is missing")]
    EvidenceMissing,
    #[error("Goal evidence belongs to another Goal")]
    EvidenceConflict,
    #[error("Goal evidence timestamp precedes Goal creation")]
    EvidenceTimestamp,
    #[error("Goal evidence exceeds the {maximum}-entry bound")]
    EvidenceLimit { maximum: usize },
    #[error("Goal or evidence belongs to another Workspace")]
    WorkspaceMismatch,
    #[error("Goal Activity is missing or belongs to another Workspace")]
    ActivityMismatch,
    #[error("Goal contract could not be encoded")]
    ContractEncoding,
    #[error("Goal schema object is damaged: {0}")]
    DamagedSchema(&'static str),
    #[error("Goal persisted record is corrupt: {0}")]
    CorruptRecord(&'static str),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workspace_id() -> WorkspaceId {
        WorkspaceId::from_uuid(Uuid::from_u128(1))
    }

    fn activity_id() -> ActivityId {
        ActivityId::from_uuid(Uuid::from_u128(2))
    }

    fn timestamp(value: i64) -> Result<TimestampMillis, Box<dyn std::error::Error>> {
        Ok(TimestampMillis::new(value)?)
    }

    fn statement(value: &str) -> Result<GoalStatement, Box<dyn std::error::Error>> {
        Ok(GoalStatement::new(value.to_owned())?)
    }

    fn contract(
        requirements: Vec<GoalVerificationRequirement>,
    ) -> Result<GoalContract, Box<dyn std::error::Error>> {
        Ok(GoalContract::new(
            GoalObjective::new("Implement the durable Goal contract".to_owned())?,
            vec![statement("All required evidence passes")?],
            vec![statement("No implicit Workspace")?],
            vec![statement("No DAG in Plan09")?],
            requirements,
            vec![statement("Stop on destructive ambiguity")?],
        )?)
    }

    fn goal(
        id: u128,
        requirements: Vec<GoalVerificationRequirement>,
    ) -> Result<RegisteredGoal, Box<dyn std::error::Error>> {
        Ok(RegisteredGoal::create(
            GoalId::from_uuid(Uuid::from_u128(id)),
            workspace_id(),
            activity_id(),
            contract(requirements)?,
            timestamp(10)?,
        ))
    }

    fn repository_connection() -> Result<Connection, Box<dyn std::error::Error>> {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE workspace (workspace_id BLOB PRIMARY KEY NOT NULL);
             CREATE TABLE activities (
                activity_id BLOB PRIMARY KEY NOT NULL,
                workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id),
                state INTEGER NOT NULL,
                lease_owner_id BLOB,
                lease_until_ms INTEGER
             );
             CREATE TABLE change_sets (
                changeset_id BLOB PRIMARY KEY NOT NULL,
                workspace_id BLOB NOT NULL,
                state INTEGER NOT NULL
             );
             CREATE TABLE diff_evidence (
                changeset_id BLOB PRIMARY KEY NOT NULL,
                state INTEGER NOT NULL
             );
             CREATE TABLE executions (
                execution_id BLOB PRIMARY KEY NOT NULL,
                workspace_id BLOB NOT NULL,
                request_digest BLOB NOT NULL,
                state INTEGER NOT NULL
             );
             CREATE TABLE approval_requests (
                approval_id BLOB PRIMARY KEY NOT NULL,
                workspace_id BLOB NOT NULL,
                state INTEGER NOT NULL
             );
             CREATE TABLE checkpoints (
                checkpoint_id BLOB PRIMARY KEY NOT NULL,
                workspace_id BLOB NOT NULL,
                state INTEGER NOT NULL
             );",
        )?;
        connection.execute(
            "INSERT INTO workspace (workspace_id) VALUES (?1)",
            params![workspace_id().into_uuid().as_bytes()],
        )?;
        connection.execute(
            "INSERT INTO activities (activity_id, workspace_id, state) VALUES (?1, ?2, 1)",
            params![
                activity_id().into_uuid().as_bytes(),
                workspace_id().into_uuid().as_bytes()
            ],
        )?;
        create_schema(&connection)?;
        workspace_dags::create_schema(&connection)?;
        crate::workspace_goal_creation_watermarks::create_schema(&connection)?;
        crate::workspace_goal_deletion::create_schema(&connection)?;
        crate::workspace_semantic_events::create_schema(&connection)?;
        crate::workspace_work_cuts::create_schema(&connection)?;
        Ok(connection)
    }

    struct SeededEvidence {
        execution: ExecutionId,
        approval: ApprovalRequestId,
        changeset: ChangeSetId,
        checkpoint: CheckpointId,
        digest: ExecutionRequestDigest,
    }

    fn seed_evidence_sources(
        connection: &Connection,
    ) -> Result<SeededEvidence, Box<dyn std::error::Error>> {
        let seeded = SeededEvidence {
            execution: ExecutionId::from_uuid(Uuid::from_u128(20)),
            approval: ApprovalRequestId::from_uuid(Uuid::from_u128(21)),
            changeset: ChangeSetId::from_uuid(Uuid::from_u128(22)),
            checkpoint: CheckpointId::from_uuid(Uuid::from_u128(23)),
            digest: ExecutionRequestDigest::from_bytes([7; ExecutionRequestDigest::BYTE_LEN]),
        };
        connection.execute(
            "INSERT INTO executions (execution_id, workspace_id, request_digest, state)
             VALUES (?1, ?2, ?3, 0)",
            params![
                seeded.execution.into_uuid().as_bytes(),
                workspace_id().into_uuid().as_bytes(),
                seeded.digest.as_bytes(),
            ],
        )?;
        connection.execute(
            "INSERT INTO approval_requests (approval_id, workspace_id, state) VALUES (?1, ?2, 0)",
            params![
                seeded.approval.into_uuid().as_bytes(),
                workspace_id().into_uuid().as_bytes()
            ],
        )?;
        connection.execute(
            "INSERT INTO change_sets (changeset_id, workspace_id, state) VALUES (?1, ?2, 0)",
            params![
                seeded.changeset.into_uuid().as_bytes(),
                workspace_id().into_uuid().as_bytes()
            ],
        )?;
        connection.execute(
            "INSERT INTO diff_evidence (changeset_id, state) VALUES (?1, 0)",
            params![seeded.changeset.into_uuid().as_bytes()],
        )?;
        connection.execute(
            "INSERT INTO checkpoints (checkpoint_id, workspace_id, state) VALUES (?1, ?2, 0)",
            params![
                seeded.checkpoint.into_uuid().as_bytes(),
                workspace_id().into_uuid().as_bytes()
            ],
        )?;
        Ok(seeded)
    }

    fn seeded_requirements(
        seeded: &SeededEvidence,
    ) -> Result<Vec<GoalVerificationRequirement>, Box<dyn std::error::Error>> {
        Ok(vec![
            GoalVerificationRequirement::ExecutionSucceeded {
                request_digest: seeded.digest,
                description: statement("Execution succeeds")?,
            },
            GoalVerificationRequirement::ChangeSetSealed {
                change_set_id: seeded.changeset,
                description: statement("ChangeSet is applied")?,
            },
            GoalVerificationRequirement::CheckpointReady {
                checkpoint_id: seeded.checkpoint,
                description: statement("Checkpoint is ready")?,
            },
        ])
    }

    fn seal_evidence_sources(
        connection: &Connection,
        seeded: &SeededEvidence,
    ) -> Result<(), Box<dyn std::error::Error>> {
        connection.execute(
            "UPDATE executions SET state = 2 WHERE execution_id = ?1",
            params![seeded.execution.into_uuid().as_bytes()],
        )?;
        connection.execute(
            "UPDATE approval_requests SET state = 1 WHERE approval_id = ?1",
            params![seeded.approval.into_uuid().as_bytes()],
        )?;
        connection.execute(
            "UPDATE change_sets SET state = 1 WHERE changeset_id = ?1",
            params![seeded.changeset.into_uuid().as_bytes()],
        )?;
        connection.execute(
            "UPDATE checkpoints SET state = 1 WHERE checkpoint_id = ?1",
            params![seeded.checkpoint.into_uuid().as_bytes()],
        )?;
        Ok(())
    }

    #[test]
    fn schema_sql_matches_created_objects() -> Result<(), Box<dyn std::error::Error>> {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE workspace (workspace_id BLOB PRIMARY KEY);",
        )?;
        create_schema(&connection)?;
        for (kind, name, expected) in [
            ("table", "goals", EXPECTED_GOALS_TABLE_SQL),
            (
                "table",
                "goal_statements",
                EXPECTED_GOAL_STATEMENTS_TABLE_SQL,
            ),
            (
                "table",
                "goal_verification_requirements",
                EXPECTED_GOAL_REQUIREMENTS_TABLE_SQL,
            ),
            (
                "table",
                "goal_evidence_refs",
                EXPECTED_GOAL_EVIDENCE_TABLE_SQL,
            ),
            (
                "table",
                "goal_completion_reviews",
                EXPECTED_GOAL_REVIEWS_TABLE_SQL,
            ),
            (
                "index",
                "goals_workspace_activity_state_updated_idx",
                EXPECTED_GOALS_LIST_INDEX_SQL,
            ),
            (
                "index",
                "goal_evidence_goal_time_idx",
                EXPECTED_GOAL_EVIDENCE_INDEX_SQL,
            ),
        ] {
            let actual: String = connection.query_row(
                "SELECT sql FROM sqlite_schema WHERE type = ?1 AND name = ?2",
                params![kind, name],
                |row| row.get(0),
            )?;
            assert_eq!(normalize_sql(&actual), normalize_sql(expected), "{name}");
        }
        Ok(())
    }

    #[test]
    fn goal_insert_list_lifecycle_and_restart_are_cas_guarded()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut connection = repository_connection()?;
        let first = goal(10, Vec::new())?;
        assert_eq!(insert_goal(&mut connection, &first)?, first);
        assert_eq!(insert_goal(&mut connection, &first)?, first);
        let conflicting = RegisteredGoal::create(
            first.id(),
            first.workspace_id(),
            first.activity_id(),
            GoalContract::new(
                GoalObjective::new("Different objective".to_owned())?,
                vec![statement("Different criterion")?],
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            )?,
            timestamp(10)?,
        );
        assert!(matches!(
            insert_goal(&mut connection, &conflicting),
            Err(GoalStoreError::IdentityConflict)
        ));

        let paused = first.pause(first.revision(), timestamp(11)?)?;
        assert_eq!(
            update_goal(&mut connection, &paused, first.revision())?,
            paused
        );
        assert_eq!(
            update_goal(&mut connection, &paused, first.revision())?,
            paused
        );
        assert!(matches!(
            update_goal(&mut connection, &paused, paused.revision()),
            Err(GoalStoreError::RevisionConflict)
        ));
        assert_eq!(get_goal(&connection, first.id())?, Some(paused.clone()));

        let second = goal(11, Vec::new())?;
        let _ = insert_goal(&mut connection, &second)?;
        let listed = list_goals(
            &connection,
            workspace_id(),
            activity_id(),
            GoalListLimit::new(10)?,
        )?;
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].id(), paused.id());

        let cancelled = second.cancel(second.revision(), timestamp(20)?)?;
        let _ = update_goal(&mut connection, &cancelled, second.revision())?;
        let revived = RegisteredGoal::from_parts(
            cancelled.id(),
            cancelled.workspace_id(),
            cancelled.activity_id(),
            cancelled.contract().clone(),
            GoalStatus::Active,
            GoalTimestamps::new(cancelled.timestamps().created_at(), timestamp(21)?)?,
            cancelled.revision().checked_next()?,
        )?;
        assert!(matches!(
            update_goal(&mut connection, &revived, cancelled.revision()),
            Err(GoalStoreError::Transition(
                GoalTransitionError::InvalidTransition { .. }
            ))
        ));
        Ok(())
    }

    #[test]
    fn evidence_review_completion_and_uniqueness_are_durable()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut connection = repository_connection()?;
        let seeded = seed_evidence_sources(&connection)?;
        let goal = goal(30, seeded_requirements(&seeded)?)?;
        let _ = insert_goal(&mut connection, &goal)?;
        for (index, evidence) in [
            GoalEvidenceRef::Execution(seeded.execution),
            GoalEvidenceRef::Approval(seeded.approval),
            GoalEvidenceRef::ChangeSet(seeded.changeset),
            GoalEvidenceRef::Checkpoint(seeded.checkpoint),
        ]
        .into_iter()
        .enumerate()
        {
            let observed_at = timestamp(20 + i64::try_from(index)?)?;
            let record = associate_evidence(
                &mut connection,
                goal.id(),
                goal.revision(),
                evidence,
                observed_at,
            )?;
            assert_eq!(record.evidence(), evidence);
        }
        assert_eq!(list_evidence(&connection, goal.id(), 10)?.len(), 4);
        let blocked = review_goal(&connection, goal.id())?;
        assert!(!blocked.can_complete());
        assert!(
            blocked
                .blockers()
                .contains(&GoalCompletionBlocker::PendingApproval(seeded.approval))
        );
        assert!(
            blocked
                .blockers()
                .contains(&GoalCompletionBlocker::ActiveExecution(seeded.execution))
        );
        seal_evidence_sources(&connection, &seeded)?;
        let review = review_goal(&connection, goal.id())?;
        assert!(review.can_complete());
        let completed = goal.complete(goal.revision(), &review, timestamp(30)?)?;
        let receipt = GoalCompletionReceipt::new(
            Uuid::from_u128(31),
            goal.id(),
            goal.revision(),
            timestamp(30)?,
            u16::try_from(review.hard_checks().len())?,
            4,
        );
        assert_eq!(
            complete_goal(
                &mut connection,
                &completed,
                goal.revision(),
                &review,
                &receipt
            )?,
            completed
        );
        assert_eq!(
            complete_goal(
                &mut connection,
                &completed,
                goal.revision(),
                &review,
                &receipt
            )?,
            completed
        );
        assert!(matches!(
            associate_evidence(
                &mut connection,
                completed.id(),
                completed.revision(),
                GoalEvidenceRef::Execution(seeded.execution),
                timestamp(31)?,
            ),
            Err(GoalStoreError::EvidenceAssociationClosed)
        ));
        connection.pragma_update(None, "foreign_keys", false)?;
        connection.execute(
            "UPDATE goals SET completion_review_id = ?1 WHERE goal_id = ?2",
            params![
                Uuid::from_u128(0xDEAD).as_bytes(),
                completed.id().into_uuid().as_bytes(),
            ],
        )?;
        let corrupted = get_goal(&connection, completed.id());
        assert!(
            matches!(
                &corrupted,
                Err(GoalStoreError::Sqlite(
                    rusqlite::Error::FromSqlConversionFailure(..)
                ))
            ),
            "unexpected corrupted completion result: {corrupted:?}"
        );
        Ok(())
    }

    #[test]
    fn evidence_cannot_cross_workspace_or_goal_identity() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut connection = repository_connection()?;
        let execution = ExecutionId::from_uuid(Uuid::from_u128(40));
        let digest = ExecutionRequestDigest::from_bytes([4; ExecutionRequestDigest::BYTE_LEN]);
        connection.execute(
            "INSERT INTO executions (execution_id, workspace_id, request_digest, state)
             VALUES (?1, ?2, ?3, 2)",
            params![
                execution.into_uuid().as_bytes(),
                workspace_id().into_uuid().as_bytes(),
                digest.as_bytes(),
            ],
        )?;
        let first = goal(41, Vec::new())?;
        let second = goal(42, Vec::new())?;
        let _ = insert_goal(&mut connection, &first)?;
        let _ = insert_goal(&mut connection, &second)?;
        assert!(matches!(
            associate_evidence(
                &mut connection,
                first.id(),
                first.revision(),
                GoalEvidenceRef::Execution(execution),
                timestamp(9)?,
            ),
            Err(GoalStoreError::EvidenceTimestamp)
        ));
        associate_evidence(
            &mut connection,
            first.id(),
            first.revision(),
            GoalEvidenceRef::Execution(execution),
            timestamp(20)?,
        )?;
        assert!(matches!(
            associate_evidence(
                &mut connection,
                second.id(),
                second.revision(),
                GoalEvidenceRef::Execution(execution),
                timestamp(20)?,
            ),
            Err(GoalStoreError::EvidenceConflict)
        ));
        assert!(matches!(
            associate_evidence(
                &mut connection,
                second.id(),
                second.revision(),
                GoalEvidenceRef::Execution(ExecutionId::from_uuid(Uuid::from_u128(99))),
                timestamp(20)?,
            ),
            Err(GoalStoreError::EvidenceMissing)
        ));
        Ok(())
    }

    #[test]
    fn completion_recomputes_durable_evidence_inside_the_write_transaction()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut connection = repository_connection()?;
        let seeded = seed_evidence_sources(&connection)?;
        let goal = goal(50, seeded_requirements(&seeded)?)?;
        let _ = insert_goal(&mut connection, &goal)?;
        for evidence in [
            GoalEvidenceRef::Execution(seeded.execution),
            GoalEvidenceRef::Approval(seeded.approval),
            GoalEvidenceRef::ChangeSet(seeded.changeset),
            GoalEvidenceRef::Checkpoint(seeded.checkpoint),
        ] {
            associate_evidence(
                &mut connection,
                goal.id(),
                goal.revision(),
                evidence,
                timestamp(20)?,
            )?;
        }
        seal_evidence_sources(&connection, &seeded)?;
        let stale_review = review_goal(&connection, goal.id())?;
        assert!(stale_review.can_complete());
        let completed = goal.complete(goal.revision(), &stale_review, timestamp(30)?)?;
        let receipt = GoalCompletionReceipt::new(
            Uuid::from_u128(51),
            goal.id(),
            goal.revision(),
            timestamp(30)?,
            u16::try_from(stale_review.hard_checks().len())?,
            4,
        );
        connection.execute(
            "UPDATE checkpoints SET state = 0 WHERE checkpoint_id = ?1",
            params![seeded.checkpoint.into_uuid().as_bytes()],
        )?;

        assert!(matches!(
            complete_goal(
                &mut connection,
                &completed,
                goal.revision(),
                &stale_review,
                &receipt,
            ),
            Err(GoalStoreError::CompletionBlocked)
        ));
        assert_eq!(get_goal(&connection, goal.id())?, Some(goal));
        let review_count: i64 =
            connection.query_row("SELECT COUNT(*) FROM goal_completion_reviews", [], |row| {
                row.get(0)
            })?;
        assert_eq!(review_count, 0);
        Ok(())
    }

    #[test]
    fn goal_completion_requires_every_current_dag_node_completed()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut connection = repository_connection()?;
        let goal = goal(60, Vec::new())?;
        let _ = insert_goal(&mut connection, &goal)?;
        let definition = forge_domain::DagNodeDefinition::new(
            forge_domain::DagNodeId::from_uuid(Uuid::from_u128(61)),
            forge_domain::DagNodeOrdinal::new(0)?,
            forge_domain::DagNodeTitle::new("Implement".to_owned())?,
            forge_domain::DagNodeObjective::new("Implement the bounded slice".to_owned())?,
            vec![forge_domain::DagAcceptanceCriterion::new(
                "Implementation verified".to_owned(),
            )?],
        )?;
        let dag_revision = forge_domain::DagRevision::new(
            forge_domain::DagRevisionId::from_uuid(Uuid::from_u128(62)),
            goal.id(),
            goal.revision(),
            forge_domain::DagRevisionNumber::INITIAL,
            None,
            vec![definition.clone()],
            Vec::new(),
            timestamp(11)?,
        )?;
        let nodes = vec![forge_domain::RegisteredDagNode::create(
            goal.id(),
            dag_revision.number(),
            definition,
            timestamp(11)?,
        )];
        let _ = workspace_dags::insert_revision(&mut connection, &dag_revision, &nodes, &[], None)?;
        let review = review_goal(&connection, goal.id())?;
        let completed = goal.complete(goal.revision(), &review, timestamp(20)?)?;
        let receipt = GoalCompletionReceipt::new(
            Uuid::from_u128(63),
            goal.id(),
            goal.revision(),
            timestamp(20)?,
            0,
            0,
        );
        assert!(matches!(
            complete_goal(
                &mut connection,
                &completed,
                goal.revision(),
                &review,
                &receipt
            ),
            Err(GoalStoreError::CompletionBlocked)
        ));
        let active = workspace_dags::start_node(
            &mut connection,
            workspace_dags::DagNodeTransition::new(
                workspace_dags::DagTransitionScope::new(
                    goal.workspace_id(),
                    goal.activity_id(),
                    goal.id(),
                    goal.revision(),
                    nodes[0].dag_revision(),
                ),
                nodes[0].id(),
                nodes[0].revision(),
                timestamp(12)?,
            ),
        )?;
        let completed_node = active.complete(active.revision(), timestamp(13)?)?;
        let _ = workspace_dags::update_node(&mut connection, &completed_node, active.revision())?;
        assert_eq!(
            complete_goal(
                &mut connection,
                &completed,
                goal.revision(),
                &review,
                &receipt
            )?,
            completed
        );
        Ok(())
    }
}
