//! Immutable Goal mutation receipts committed with the existing Goal owner.

use forge_domain::{
    ActivityCoordinatorActor, ActivityCoordinatorRevision, ActivityId, AgentInstanceId,
    AgentSessionId, AuthenticatedPrincipal, GoalId, GoalLifecycleAction, GoalMutationAction,
    GoalMutationCommand, GoalMutationDigest, GoalMutationKind, GoalMutationReceipt,
    GoalMutationReceiptData, GoalMutationRequestId, GoalReview, GoalRevision, GoalStatusKind,
    RegisteredGoal, TimestampMillis, WorkspaceRevision,
};
use rusqlite::{Connection, OptionalExtension, Row, Transaction, TransactionBehavior, params};
use thiserror::Error;
use uuid::Uuid;

use crate::workspace_goals::{GoalCompletionReceipt, GoalStoreError};
use crate::{workspace_coordinators, workspace_goals};

const TABLE_SQL: &str = "CREATE TABLE goal_mutation_receipts (request_id BLOB PRIMARY KEY NOT NULL CHECK(length(request_id) = 16), request_digest BLOB NOT NULL CHECK(length(request_digest) = 32), workspace_id BLOB NOT NULL CHECK(length(workspace_id) = 16), workspace_revision INTEGER NOT NULL CHECK(workspace_revision >= 1), activity_id BLOB NOT NULL CHECK(length(activity_id) = 16), agent_id BLOB NOT NULL CHECK(length(agent_id) = 16), coordinator_revision INTEGER NOT NULL CHECK(coordinator_revision >= 1), principal_kind INTEGER NOT NULL CHECK(principal_kind IN (0, 1, 2)), principal_id BLOB, session_id BLOB NOT NULL CHECK(length(session_id) = 16), goal_id BLOB NOT NULL CHECK(length(goal_id) = 16), mutation_kind INTEGER NOT NULL CHECK(mutation_kind BETWEEN 0 AND 7), expected_goal_revision INTEGER, result_goal_revision INTEGER NOT NULL CHECK(result_goal_revision >= 1), result_status INTEGER NOT NULL CHECK(result_status BETWEEN 0 AND 5), observed_at_ms INTEGER NOT NULL CHECK(observed_at_ms >= 0), review_id BLOB, CHECK((principal_kind = 0 AND principal_id IS NULL) OR (principal_kind IN (1, 2) AND principal_id IS NOT NULL AND length(principal_id) = 16)), CHECK((mutation_kind = 0 AND expected_goal_revision IS NULL AND result_goal_revision = 1) OR (mutation_kind != 0 AND expected_goal_revision IS NOT NULL AND expected_goal_revision >= 1 AND result_goal_revision = expected_goal_revision + 1)), CHECK((mutation_kind = 7 AND review_id IS NOT NULL AND length(review_id) = 16) OR (mutation_kind != 7 AND review_id IS NULL)))";
const NO_UPDATE_SQL: &str = "CREATE TRIGGER goal_mutation_receipts_no_update BEFORE UPDATE ON goal_mutation_receipts BEGIN SELECT RAISE(ABORT, 'Goal mutation receipts are immutable'); END";
const NO_DELETE_SQL: &str = "CREATE TRIGGER goal_mutation_receipts_no_delete BEFORE DELETE ON goal_mutation_receipts BEGIN SELECT RAISE(ABORT, 'Goal mutation receipts are immutable'); END";
const OBJECTS: [(&str, &str, &str); 3] = [
    ("table", "goal_mutation_receipts", TABLE_SQL),
    ("trigger", "goal_mutation_receipts_no_update", NO_UPDATE_SQL),
    ("trigger", "goal_mutation_receipts_no_delete", NO_DELETE_SQL),
];

pub(crate) fn create_schema(connection: &Connection) -> Result<(), GoalMutationStoreError> {
    for (_, _, sql) in OBJECTS {
        connection.execute_batch(sql)?;
    }
    Ok(())
}

pub(crate) const fn schema_objects() -> [(&'static str, &'static str); 3] {
    [
        ("table", "goal_mutation_receipts"),
        ("trigger", "goal_mutation_receipts_no_update"),
        ("trigger", "goal_mutation_receipts_no_delete"),
    ]
}

pub(crate) fn validate_schema(connection: &Connection) -> Result<(), GoalMutationStoreError> {
    for (kind, name, expected) in OBJECTS {
        let actual: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type = ?1 AND name = ?2",
                params![kind, name],
                |row| row.get(0),
            )
            .optional()?;
        if actual.as_deref().map(normalize_sql) != Some(normalize_sql(expected)) {
            return Err(GoalMutationStoreError::DamagedSchema);
        }
    }
    Ok(())
}

fn normalize_sql(sql: &str) -> String {
    sql.chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

/// Original immutable receipt and the Goal projection observed in this transaction.
/// The current Goal can differ from the receipt after later writes, or be absent
/// after deletion. It is never presented as the original result snapshot.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoalMutationResult {
    receipt: GoalMutationReceipt,
    current_goal: Option<RegisteredGoal>,
    replayed: bool,
}
impl GoalMutationResult {
    pub const fn receipt(&self) -> &GoalMutationReceipt {
        &self.receipt
    }
    pub const fn current_goal(&self) -> Option<&RegisteredGoal> {
        self.current_goal.as_ref()
    }
    pub const fn replayed(&self) -> bool {
        self.replayed
    }
}

pub(crate) fn mutate(
    connection: &mut Connection,
    command: &GoalMutationCommand,
    completion: Option<(&GoalReview, &GoalCompletionReceipt)>,
    admitted_at: TimestampMillis,
) -> Result<GoalMutationResult, GoalMutationStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    authorize(&transaction, command, admitted_at)?;
    if let Some(result) = replay_in_transaction(&transaction, command)? {
        transaction.commit()?;
        return Ok(result);
    }
    let current = workspace_goals::get_goal(&transaction, command.goal_id())?;
    let goal = apply_action(&transaction, command, current, completion)?;
    let receipt = GoalMutationReceipt::from_committed(command, &goal)?;
    insert_receipt(&transaction, &receipt)?;
    transaction.commit()?;
    Ok(GoalMutationResult {
        receipt,
        current_goal: Some(goal),
        replayed: false,
    })
}

/// Revalidate current write authority before returning an exact replay receipt.
/// This performs no mutation; historical unauthenticated-by-session observation
/// uses `read_receipt` instead.
pub(crate) fn replay(
    connection: &mut Connection,
    command: &GoalMutationCommand,
    admitted_at: TimestampMillis,
) -> Result<Option<GoalMutationResult>, GoalMutationStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    authorize(&transaction, command, admitted_at)?;
    let result = replay_in_transaction(&transaction, command)?;
    transaction.commit()?;
    Ok(result)
}

fn authorize(
    transaction: &Transaction<'_>,
    command: &GoalMutationCommand,
    admitted_at: TimestampMillis,
) -> Result<(), GoalMutationStoreError> {
    let revision: Option<i64> = transaction
        .query_row(
            "SELECT revision FROM workspace WHERE workspace_id = ?1",
            params![command.actor().workspace_id().into_uuid().as_bytes()],
            |row| row.get(0),
        )
        .optional()?;
    if revision != Some(command.workspace_revision().get()) {
        return Err(GoalMutationStoreError::WorkspaceRevisionConflict);
    }
    let _binding = workspace_coordinators::authorize_live_in_transaction(
        transaction,
        command.actor(),
        admitted_at,
    )?;
    Ok(())
}

fn replay_in_transaction(
    transaction: &Transaction<'_>,
    command: &GoalMutationCommand,
) -> Result<Option<GoalMutationResult>, GoalMutationStoreError> {
    let Some(receipt) = read_receipt(transaction, command.request_id())? else {
        return Ok(None);
    };
    let data = receipt.data();
    let review_id = match command.action() {
        GoalMutationAction::Complete { review_id } => Some(*review_id),
        _ => None,
    };
    if data.digest != command.digest()
        || data.actor != command.actor()
        || data.workspace_revision != command.workspace_revision()
        || data.goal_id != command.goal_id()
        || data.kind != command.kind()
        || data.expected_revision != command.expected_revision()
        || data.observed_at != command.observed_at()
        || data.review_id != review_id
    {
        return Err(GoalMutationStoreError::RequestIdentityConflict);
    }
    let current_goal = workspace_goals::get_goal(transaction, command.goal_id())?.filter(|goal| {
        goal.workspace_id() == command.actor().workspace_id()
            && goal.activity_id() == command.actor().activity_id()
    });
    Ok(Some(GoalMutationResult {
        receipt,
        current_goal,
        replayed: true,
    }))
}

fn apply_action(
    transaction: &Transaction<'_>,
    command: &GoalMutationCommand,
    current: Option<RegisteredGoal>,
    completion: Option<(&GoalReview, &GoalCompletionReceipt)>,
) -> Result<RegisteredGoal, GoalMutationStoreError> {
    if let GoalMutationAction::Create(contract) = command.action() {
        if current.is_some() {
            return Err(GoalMutationStoreError::RequestIdentityConflict);
        }
        let goal = RegisteredGoal::create(
            command.goal_id(),
            command.actor().workspace_id(),
            command.actor().activity_id(),
            contract.as_ref().clone(),
            command.observed_at(),
        );
        return Ok(workspace_goals::insert_goal_in_transaction(
            transaction,
            &goal,
        )?);
    }
    let current = current.ok_or(GoalStoreError::RecordMissing)?;
    if current.workspace_id() != command.actor().workspace_id()
        || current.activity_id() != command.actor().activity_id()
    {
        return Err(GoalMutationStoreError::RequestIdentityConflict);
    }
    let expected = command
        .expected_revision()
        .ok_or(GoalMutationStoreError::RequestIdentityConflict)?;
    match command.action() {
        GoalMutationAction::Create(_) => Err(GoalMutationStoreError::RequestIdentityConflict),
        GoalMutationAction::Revise(contract) => {
            let updated = current
                .revise_contract(expected, contract.as_ref().clone(), command.observed_at())
                .map_err(GoalStoreError::from)?;
            Ok(workspace_goals::revise_goal_contract_in_transaction(
                transaction,
                &updated,
                expected,
            )?)
        }
        GoalMutationAction::Transition(action) => {
            let updated = transition(&current, expected, command.observed_at(), action)?;
            Ok(workspace_goals::update_goal_in_transaction(
                transaction,
                &updated,
                expected,
            )?)
        }
        GoalMutationAction::Complete { review_id } => {
            let (review, receipt) =
                completion.ok_or(GoalMutationStoreError::MissingCompletionProof)?;
            if receipt.review_id() != *review_id {
                return Err(GoalMutationStoreError::RequestIdentityConflict);
            }
            let completed = current
                .complete(expected, review, command.observed_at())
                .map_err(GoalStoreError::from)?;
            Ok(workspace_goals::complete_goal_in_transaction(
                transaction,
                &completed,
                expected,
                review,
                receipt,
            )?)
        }
    }
}

fn transition(
    goal: &RegisteredGoal,
    revision: GoalRevision,
    observed_at: TimestampMillis,
    action: &GoalLifecycleAction,
) -> Result<RegisteredGoal, GoalStoreError> {
    Ok(match action {
        GoalLifecycleAction::Pause => goal.pause(revision, observed_at),
        GoalLifecycleAction::Resume => goal.resume(revision, observed_at),
        GoalLifecycleAction::Block(reason) => goal.block(revision, reason.clone(), observed_at),
        GoalLifecycleAction::Fail(reason) => goal.fail(revision, reason.clone(), observed_at),
        GoalLifecycleAction::Cancel => goal.cancel(revision, observed_at),
    }?)
}

fn insert_receipt(
    transaction: &Transaction<'_>,
    receipt: &GoalMutationReceipt,
) -> Result<(), GoalMutationStoreError> {
    let data = receipt.data();
    let actor = data.actor;
    let (principal_kind, principal_id) = match actor.principal() {
        AuthenticatedPrincipal::TrustedStdio => (0_i64, None),
        AuthenticatedPrincipal::DirectToken(id) => (1, Some(id.into_uuid())),
        AuthenticatedPrincipal::OAuthGrant(id) => (2, Some(id.into_uuid())),
    };
    transaction.execute(
        "INSERT INTO goal_mutation_receipts (request_id, request_digest, workspace_id, workspace_revision,
         activity_id, agent_id, coordinator_revision, principal_kind, principal_id, session_id, goal_id,
         mutation_kind, expected_goal_revision, result_goal_revision, result_status, observed_at_ms, review_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
        params![data.request_id.into_uuid().as_bytes(), data.digest.as_bytes(), actor.workspace_id().into_uuid().as_bytes(),
            data.workspace_revision.get(), actor.activity_id().into_uuid().as_bytes(), actor.agent_id().into_uuid().as_bytes(),
            actor.expected_revision().get(), principal_kind, principal_id.map(Uuid::into_bytes), actor.session_id().into_uuid().as_bytes(),
            data.goal_id.into_uuid().as_bytes(), i64::from(data.kind.code()), data.expected_revision.map(GoalRevision::get),
            data.result_revision.get(), status_code(data.result_status), data.observed_at.get(), data.review_id.map(Uuid::into_bytes)],
    )?;
    Ok(())
}

pub(crate) fn read_receipt(
    connection: &Connection,
    id: GoalMutationRequestId,
) -> Result<Option<GoalMutationReceipt>, GoalMutationStoreError> {
    connection.query_row(
        "SELECT request_id, request_digest, workspace_id, workspace_revision, activity_id, agent_id,
         coordinator_revision, principal_kind, principal_id, session_id, goal_id, mutation_kind,
         expected_goal_revision, result_goal_revision, result_status, observed_at_ms, review_id
         FROM goal_mutation_receipts WHERE request_id = ?1",
        params![id.into_uuid().as_bytes()], |row| decode_receipt(row).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Blob, Box::new(error))
        }),
    ).optional().map_err(GoalMutationStoreError::from)
}

fn decode_receipt(row: &Row<'_>) -> Result<GoalMutationReceipt, GoalMutationStoreError> {
    let principal_id = row
        .get::<_, Option<Vec<u8>>>(8)?
        .map(|raw| uuid(&raw))
        .transpose()?;
    let principal = match (row.get::<_, i64>(7)?, principal_id) {
        (0, None) => AuthenticatedPrincipal::TrustedStdio,
        (1, Some(id)) => {
            AuthenticatedPrincipal::DirectToken(forge_domain::DirectTokenId::from_uuid(id))
        }
        (2, Some(id)) => {
            AuthenticatedPrincipal::OAuthGrant(forge_domain::OAuthGrantId::from_uuid(id))
        }
        _ => return Err(GoalMutationStoreError::CorruptRecord),
    };
    let actor = ActivityCoordinatorActor::new(
        forge_domain::WorkspaceId::from_uuid(uuid(&row.get::<_, Vec<u8>>(2)?)?),
        ActivityId::from_uuid(uuid(&row.get::<_, Vec<u8>>(4)?)?),
        AgentInstanceId::from_uuid(uuid(&row.get::<_, Vec<u8>>(5)?)?),
        ActivityCoordinatorRevision::new(row.get(6)?)
            .map_err(|_| GoalMutationStoreError::CorruptRecord)?,
        principal,
        AgentSessionId::from_uuid(uuid(&row.get::<_, Vec<u8>>(9)?)?),
    );
    let digest: [u8; 32] = row
        .get::<_, Vec<u8>>(1)?
        .try_into()
        .map_err(|_| GoalMutationStoreError::CorruptRecord)?;
    let kind = GoalMutationKind::try_from(
        u8::try_from(row.get::<_, i64>(11)?).map_err(|_| GoalMutationStoreError::CorruptRecord)?,
    )
    .map_err(|_| GoalMutationStoreError::CorruptRecord)?;
    GoalMutationReceipt::from_data(GoalMutationReceiptData {
        request_id: GoalMutationRequestId::from_uuid(uuid(&row.get::<_, Vec<u8>>(0)?)?),
        digest: GoalMutationDigest::from_bytes(digest),
        actor,
        workspace_revision: WorkspaceRevision::new(row.get(3)?)
            .map_err(|_| GoalMutationStoreError::CorruptRecord)?,
        goal_id: GoalId::from_uuid(uuid(&row.get::<_, Vec<u8>>(10)?)?),
        kind,
        expected_revision: row
            .get::<_, Option<i64>>(12)?
            .map(goal_revision)
            .transpose()?,
        result_revision: goal_revision(row.get(13)?)?,
        result_status: decode_status(row.get(14)?)?,
        observed_at: TimestampMillis::new(row.get(15)?)
            .map_err(|_| GoalMutationStoreError::CorruptRecord)?,
        review_id: row
            .get::<_, Option<Vec<u8>>>(16)?
            .map(|raw| uuid(&raw))
            .transpose()?,
    })
    .map_err(GoalMutationStoreError::from)
}

fn uuid(raw: &[u8]) -> Result<Uuid, GoalMutationStoreError> {
    Uuid::from_slice(raw).map_err(|_| GoalMutationStoreError::CorruptRecord)
}
fn goal_revision(raw: i64) -> Result<GoalRevision, GoalMutationStoreError> {
    GoalRevision::new(raw).map_err(|_| GoalMutationStoreError::CorruptRecord)
}
fn status_code(status: GoalStatusKind) -> i64 {
    match status {
        GoalStatusKind::Active => 0,
        GoalStatusKind::Paused => 1,
        GoalStatusKind::Blocked => 2,
        GoalStatusKind::Completed => 3,
        GoalStatusKind::Failed => 4,
        GoalStatusKind::Cancelled => 5,
    }
}
fn decode_status(code: i64) -> Result<GoalStatusKind, GoalMutationStoreError> {
    match code {
        0 => Ok(GoalStatusKind::Active),
        1 => Ok(GoalStatusKind::Paused),
        2 => Ok(GoalStatusKind::Blocked),
        3 => Ok(GoalStatusKind::Completed),
        4 => Ok(GoalStatusKind::Failed),
        5 => Ok(GoalStatusKind::Cancelled),
        _ => Err(GoalMutationStoreError::CorruptRecord),
    }
}

#[derive(Debug, Error)]
pub enum GoalMutationStoreError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Goal(#[from] GoalStoreError),
    #[error(transparent)]
    Coordinator(#[from] crate::CoordinatorStoreError),
    #[error(transparent)]
    GoalDeletion(#[from] crate::GoalDeletionStoreError),
    #[error(transparent)]
    Domain(#[from] forge_domain::GoalMutationError),
    #[error("Goal mutation receipt identity conflicts")]
    RequestIdentityConflict,
    #[error("Goal mutation Workspace revision conflicts")]
    WorkspaceRevisionConflict,
    #[error("Goal completion proof is required")]
    MissingCompletionProof,
    #[error("Goal mutation receipt schema is damaged")]
    DamagedSchema,
    #[error("Goal mutation receipt is corrupt")]
    CorruptRecord,
}
