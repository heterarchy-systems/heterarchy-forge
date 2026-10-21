//! Durable Activity Coordinator DAG planning replay ledger.
//!
//! Only the current revision-fenced Activity Coordinator may create an initial
//! DAG or commit immutable successor revisions. Coordinator authorization, Goal
//! attribution, exact DAG head CAS, and the idempotent request ledger are
//! validated in one immediate transaction.

use forge_domain::{
    ActivityCoordinatorActor, ActivityCoordinatorRevision, ActivityId, AgentDagDraftDigest,
    AgentDagPlanReceipt, AgentDagPlanRequest, AgentDagPlanRequestId, AgentWorkPhase,
    AgentWorkSummary, AgentWorkUpdate, AgentWorkUpdateId, AgentWorkUpdateSequence,
    AuthenticatedPrincipal, DagHeadRevision, DagRevisionNumber, GoalAttribution, GoalStatusKind,
    TimestampMillis, WorkspaceId,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use thiserror::Error;
use uuid::Uuid;

use crate::workspace_agents::{self, AgentStoreError};
use crate::workspace_coordinators::{self, CoordinatorStoreError};
use crate::workspace_dags::{self, DagStoreError, StoredDagRevision};
use crate::workspace_goals::{self, GoalStoreError};

const PLAN_LEDGER_TABLE: &str = "agent_dag_plan_ledger";
const PLAN_LEDGER_INDEX: &str = "agent_dag_plan_ledger_actor_committed_idx";
const SESSION_TABLE: &str = "agent_dag_plan_sessions";
const SESSION_TABLE_SQL: &str = "CREATE TABLE agent_dag_plan_sessions (request_id BLOB PRIMARY KEY NOT NULL REFERENCES agent_dag_plan_ledger(request_id) CHECK(length(request_id) = 16), session_id BLOB NOT NULL CHECK(length(session_id) = 16))";

const EXPECTED_PLAN_LEDGER_TABLE_SQL: &str = "CREATE TABLE agent_dag_plan_ledger (request_id BLOB PRIMARY KEY NOT NULL CHECK(length(request_id) = 16), workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16), agent_id BLOB NOT NULL CHECK(length(agent_id) = 16), activity_id BLOB NOT NULL REFERENCES activities(activity_id) CHECK(length(activity_id) = 16), coordinator_revision INTEGER NOT NULL CHECK(coordinator_revision >= 1), principal_kind INTEGER NOT NULL CHECK(principal_kind IN (0, 1, 2)), principal_id BLOB CHECK(principal_id IS NULL OR length(principal_id) = 16), goal_id BLOB NOT NULL REFERENCES goals(goal_id) CHECK(length(goal_id) = 16), goal_revision INTEGER NOT NULL CHECK(goal_revision >= 1), expected_parent_revision INTEGER CHECK(expected_parent_revision IS NULL OR expected_parent_revision >= 1), expected_head_revision INTEGER CHECK(expected_head_revision IS NULL OR expected_head_revision >= 1), draft_digest BLOB NOT NULL CHECK(length(draft_digest) = 32), committed_dag_revision_id BLOB NOT NULL CHECK(length(committed_dag_revision_id) = 16), committed_dag_revision INTEGER NOT NULL CHECK(committed_dag_revision >= 1), history_update_id BLOB NOT NULL CHECK(length(history_update_id) = 16), history_update_sequence INTEGER NOT NULL CHECK(history_update_sequence >= 1), committed_at_ms INTEGER NOT NULL CHECK(committed_at_ms >= 0), UNIQUE(request_id, workspace_id, agent_id, activity_id, coordinator_revision), FOREIGN KEY(agent_id, workspace_id, activity_id) REFERENCES agent_instances(agent_id, workspace_id, activity_id), FOREIGN KEY(goal_id, committed_dag_revision) REFERENCES goal_dag_revisions(goal_id, dag_revision), FOREIGN KEY(history_update_id, agent_id, workspace_id) REFERENCES agent_work_updates(update_id, agent_id, workspace_id), CHECK((principal_kind = 0 AND principal_id IS NULL) OR (principal_kind IN (1, 2) AND principal_id IS NOT NULL)), CHECK((expected_parent_revision IS NULL) = (expected_head_revision IS NULL)))";
const EXPECTED_PLAN_LEDGER_INDEX_SQL: &str = "CREATE INDEX agent_dag_plan_ledger_actor_committed_idx ON agent_dag_plan_ledger(workspace_id, activity_id, agent_id, coordinator_revision, committed_at_ms DESC, request_id DESC)";

const OBJECTS: [(&str, &str, &str); 3] = [
    ("table", PLAN_LEDGER_TABLE, EXPECTED_PLAN_LEDGER_TABLE_SQL),
    ("index", PLAN_LEDGER_INDEX, EXPECTED_PLAN_LEDGER_INDEX_SQL),
    ("table", SESSION_TABLE, SESSION_TABLE_SQL),
];

pub(crate) fn create_schema(connection: &Connection) -> Result<(), AgentDagStoreError> {
    connection.execute_batch(EXPECTED_PLAN_LEDGER_TABLE_SQL)?;
    connection.execute_batch(EXPECTED_PLAN_LEDGER_INDEX_SQL)?;
    connection.execute_batch(SESSION_TABLE_SQL)?;
    Ok(())
}

pub(crate) fn schema_objects() -> [(&'static str, &'static str); 3] {
    [
        ("table", PLAN_LEDGER_TABLE),
        ("index", PLAN_LEDGER_INDEX),
        ("table", SESSION_TABLE),
    ]
}

pub(crate) fn validate_schema(connection: &Connection) -> Result<(), AgentDagStoreError> {
    validate_objects(connection, &OBJECTS)
}

pub(crate) fn validate_schema_v29(connection: &Connection) -> Result<(), AgentDagStoreError> {
    validate_objects(connection, &OBJECTS[..2])
}

fn validate_objects(
    connection: &Connection,
    objects: &[(&str, &'static str, &str)],
) -> Result<(), AgentDagStoreError> {
    for &(kind, name, expected) in objects {
        let actual: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type = ?1 AND name = ?2",
                params![kind, name],
                |row| row.get(0),
            )
            .optional()?;
        if actual.as_deref().map(normalize_sql) != Some(normalize_sql(expected)) {
            return Err(AgentDagStoreError::DamagedSchema(name));
        }
    }
    Ok(())
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentDagPlanCommitResult {
    receipt: AgentDagPlanReceipt,
    revision: StoredDagRevision,
}

impl AgentDagPlanCommitResult {
    pub const fn receipt(&self) -> AgentDagPlanReceipt {
        self.receipt
    }

    pub const fn revision(&self) -> &StoredDagRevision {
        &self.revision
    }
}

pub(crate) fn commit_plan(
    connection: &mut Connection,
    request: &AgentDagPlanRequest,
    admitted_at: forge_domain::TimestampMillis,
) -> Result<AgentDagPlanCommitResult, AgentDagStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let digest = request.digest();

    ensure_workspace(&transaction, request.actor().workspace_id())?;
    let _coordinator = workspace_coordinators::authorize_live_in_transaction(
        &transaction,
        request.actor(),
        admitted_at,
    )?;

    if let Some(ledger) = ledger_by_request(&transaction, request.id())? {
        if !ledger.matches(request, digest) {
            return Err(AgentDagStoreError::RequestIdentityConflict);
        }
        let revision_number = ledger.committed_dag_revision;
        let goal_id = ledger.goal.goal_id();
        let receipt = AgentDagPlanReceipt::new(
            request.id(),
            digest,
            ledger.committed_dag_revision_id,
            revision_number,
            ledger.committed_at,
            true,
        );
        transaction.commit()?;
        let revision = workspace_dags::get_revision(connection, goal_id, revision_number)?
            .ok_or(AgentDagStoreError::LedgerRevisionMissing)?;
        return Ok(AgentDagPlanCommitResult { receipt, revision });
    }

    crate::workspace_work_cuts::guards::ensure_goal_open(
        &transaction,
        request.actor().workspace_id(),
        request.goal().goal_id(),
    )?;
    ensure_goal(
        &transaction,
        request.actor().workspace_id(),
        request.actor().activity_id(),
        request.goal(),
    )?;
    validate_plan_contract(request)?;

    let stored = workspace_dags::insert_revision_in_transaction(
        &transaction,
        request.draft().revision(),
        request.draft().nodes(),
        request.draft().lineage(),
        request.expected_head_revision(),
    )?;

    let history = AgentWorkUpdate::new(
        request.history_update_id(),
        request.actor().agent_id(),
        request.actor().workspace_id(),
        request.actor().activity_id(),
        request.history_update_sequence(),
        AgentWorkPhase::Planning,
        AgentWorkSummary::new("Committed a Coordinator-authorized DAG plan".to_owned())
            .map_err(|_| AgentDagStoreError::HistoryInvalid)?,
        Vec::new(),
        request.observed_at(),
    )
    .map_err(|_| AgentDagStoreError::HistoryInvalid)?;
    let _ =
        workspace_agents::publish_work_update_in_transaction(&transaction, &history, admitted_at)?;

    insert_ledger(
        &transaction,
        request,
        digest,
        stored.revision().id(),
        stored.revision().number(),
    )?;
    crate::workspace_semantic_events::append_semantic_event(
        &transaction,
        &crate::workspace_semantic_events::SemanticEventAppend::new(
            crate::workspace_semantic_events::SemanticEventKind::PlanPublished,
            request.actor().workspace_id(),
            crate::workspace_semantic_events::SemanticEventSubjects {
                goal_id: Some(request.goal().goal_id()),
                dag_revision: Some(stored.revision().number()),
                ..crate::workspace_semantic_events::SemanticEventSubjects::NONE
            },
            stored.head().revision().get(),
            request.observed_at(),
        ),
    )?;
    let receipt = AgentDagPlanReceipt::new(
        request.id(),
        digest,
        stored.revision().id(),
        stored.revision().number(),
        request.observed_at(),
        false,
    );
    transaction.commit()?;
    Ok(AgentDagPlanCommitResult {
        receipt,
        revision: stored,
    })
}

fn validate_plan_contract(request: &AgentDagPlanRequest) -> Result<(), AgentDagStoreError> {
    let revision = request.draft().revision();
    if revision.goal_id() != request.goal().goal_id()
        || revision.base_goal_revision() != request.goal().expected_revision()
    {
        return Err(AgentDagStoreError::DraftConflict);
    }
    match (
        request.expected_parent_revision(),
        request.expected_head_revision(),
        revision.parent(),
    ) {
        (None, None, None) if revision.number() == DagRevisionNumber::INITIAL => Ok(()),
        (Some(parent), Some(_), Some(actual_parent)) if actual_parent == parent => {
            let successor = parent
                .checked_next()
                .map_err(|_| AgentDagStoreError::DraftConflict)?;
            if revision.number() == successor {
                Ok(())
            } else {
                Err(AgentDagStoreError::DraftConflict)
            }
        }
        _ => Err(AgentDagStoreError::DraftConflict),
    }
}

fn ensure_workspace(
    connection: &Connection,
    workspace_id: WorkspaceId,
) -> Result<(), AgentDagStoreError> {
    let exists: Option<i64> = connection
        .query_row(
            "SELECT 1 FROM workspace WHERE workspace_id = ?1",
            params![workspace_id.into_uuid().as_bytes()],
            |row| row.get(0),
        )
        .optional()?;
    exists.map_or_else(
        || Err(AgentDagStoreError::WorkspaceNotFound(workspace_id)),
        |_| Ok(()),
    )
}

fn ensure_goal(
    connection: &Connection,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    goal: GoalAttribution,
) -> Result<(), AgentDagStoreError> {
    let goal_record = workspace_goals::get_goal(connection, goal.goal_id())?
        .ok_or(AgentDagStoreError::GoalMissing(goal.goal_id()))?;
    if goal_record.workspace_id() != workspace_id
        || goal_record.activity_id() != activity_id
        || goal_record.revision() != goal.expected_revision()
        || !matches!(
            goal_record.status().kind(),
            GoalStatusKind::Active | GoalStatusKind::Paused
        )
    {
        return Err(AgentDagStoreError::GoalConflict);
    }
    Ok(())
}

/// Immutable historical identity and outcome for one committed DAG plan.
///
/// This record is decoded directly from the durable planning ledger.  It does
/// not reauthorize, replay, or reconstruct a plan; callers may only inspect the
/// committed identity and provenance that were recorded with the original
/// request.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentDagPlanRecord {
    request_id: AgentDagPlanRequestId,
    actor: ActivityCoordinatorActor,
    goal: GoalAttribution,
    expected_parent_revision: Option<DagRevisionNumber>,
    expected_head_revision: Option<DagHeadRevision>,
    digest: AgentDagDraftDigest,
    committed_dag_revision_id: forge_domain::DagRevisionId,
    committed_dag_revision: DagRevisionNumber,
    history_update_id: AgentWorkUpdateId,
    history_update_sequence: AgentWorkUpdateSequence,
    committed_at: TimestampMillis,
}

impl AgentDagPlanRecord {
    pub const fn request_id(&self) -> AgentDagPlanRequestId {
        self.request_id
    }

    pub const fn actor(&self) -> ActivityCoordinatorActor {
        self.actor
    }

    pub const fn goal(&self) -> GoalAttribution {
        self.goal
    }

    pub const fn expected_parent_revision(&self) -> Option<DagRevisionNumber> {
        self.expected_parent_revision
    }

    pub const fn expected_head_revision(&self) -> Option<DagHeadRevision> {
        self.expected_head_revision
    }

    pub const fn digest(&self) -> AgentDagDraftDigest {
        self.digest
    }

    pub const fn committed_dag_revision_id(&self) -> forge_domain::DagRevisionId {
        self.committed_dag_revision_id
    }

    pub const fn committed_dag_revision(&self) -> DagRevisionNumber {
        self.committed_dag_revision
    }

    pub const fn history_update_id(&self) -> AgentWorkUpdateId {
        self.history_update_id
    }

    pub const fn history_update_sequence(&self) -> AgentWorkUpdateSequence {
        self.history_update_sequence
    }

    pub const fn committed_at(&self) -> TimestampMillis {
        self.committed_at
    }

    fn matches(&self, request: &AgentDagPlanRequest, digest: AgentDagDraftDigest) -> bool {
        self.request_id == request.id()
            && self.actor == request.actor()
            && self.goal == request.goal()
            && self.expected_parent_revision == request.expected_parent_revision()
            && self.expected_head_revision == request.expected_head_revision()
            && self.digest == digest
            && self.history_update_id == request.history_update_id()
            && self.history_update_sequence == request.history_update_sequence()
            && self.committed_at == request.observed_at()
    }
}

pub(crate) fn read_plan_record(
    connection: &Connection,
    request_id: AgentDagPlanRequestId,
) -> Result<Option<AgentDagPlanRecord>, AgentDagStoreError> {
    ledger_by_request(connection, request_id)
}

fn ledger_by_request(
    connection: &Connection,
    request_id: AgentDagPlanRequestId,
) -> Result<Option<AgentDagPlanRecord>, AgentDagStoreError> {
    connection
        .query_row(
            "SELECT workspace_id, agent_id, activity_id, coordinator_revision, principal_kind, principal_id,
                    goal_id, goal_revision, expected_parent_revision, expected_head_revision,
                    draft_digest, committed_dag_revision_id, committed_dag_revision,
                    history_update_id, history_update_sequence, committed_at_ms
             FROM agent_dag_plan_ledger WHERE request_id = ?1",
            params![request_id.into_uuid().as_bytes()],
            |row| {
                let workspace: Vec<u8> = row.get(0)?;
                let agent: Vec<u8> = row.get(1)?;
                let activity: Vec<u8> = row.get(2)?;
                let coordinator_revision: i64 = row.get(3)?;
                let principal_kind: i64 = row.get(4)?;
                let principal_id: Option<Vec<u8>> = row.get(5)?;
                let goal: Vec<u8> = row.get(6)?;
                let goal_revision: i64 = row.get(7)?;
                let parent: Option<i64> = row.get(8)?;
                let head: Option<i64> = row.get(9)?;
                let digest: Vec<u8> = row.get(10)?;
                let revision_id: Vec<u8> = row.get(11)?;
                let committed_revision: i64 = row.get(12)?;
                let history_id: Vec<u8> = row.get(13)?;
                let history_sequence: i64 = row.get(14)?;
                let committed_at: i64 = row.get(15)?;
                Ok((
                    workspace,
                    agent,
                    activity,
                    coordinator_revision,
                    principal_kind,
                    principal_id,
                    goal,
                    goal_revision,
                    parent,
                    head,
                    digest,
                    revision_id,
                    committed_revision,
                    history_id,
                    history_sequence,
                    committed_at,
                ))
            },
        )
        .optional()?
        .map(|row| {
            let session: Option<Vec<u8>> = connection.query_row(
                "SELECT session_id FROM agent_dag_plan_sessions WHERE request_id = ?1",
                params![request_id.into_uuid().as_bytes()], |row| row.get(0),
            ).optional()?;
            let session = session.ok_or(AgentDagStoreError::UnresolvedSession)?;
            decode_ledger(request_id, row, forge_domain::AgentSessionId::from_uuid(decode_uuid(&session, "ledger.session_id")?))
        })
        .transpose()
}

type LedgerTuple = (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i64,
    i64,
    Option<Vec<u8>>,
    Vec<u8>,
    i64,
    Option<i64>,
    Option<i64>,
    Vec<u8>,
    Vec<u8>,
    i64,
    Vec<u8>,
    i64,
    i64,
);

fn decode_ledger(
    request_id: AgentDagPlanRequestId,
    row: LedgerTuple,
    session_id: forge_domain::AgentSessionId,
) -> Result<AgentDagPlanRecord, AgentDagStoreError> {
    let (
        workspace,
        agent,
        activity,
        coordinator_revision,
        principal_kind,
        principal_id,
        goal,
        goal_revision,
        parent,
        head,
        digest,
        revision_id,
        committed_revision,
        history_id,
        history_sequence,
        committed_at,
    ) = row;
    let actor = ActivityCoordinatorActor::new(
        WorkspaceId::from_uuid(decode_uuid(&workspace, "ledger.workspace_id")?),
        ActivityId::from_uuid(decode_uuid(&activity, "ledger.activity_id")?),
        forge_domain::AgentInstanceId::from_uuid(decode_uuid(&agent, "ledger.agent_id")?),
        ActivityCoordinatorRevision::new(coordinator_revision)
            .map_err(|_| AgentDagStoreError::CorruptRecord("ledger.coordinator_revision"))?,
        decode_principal(principal_kind, principal_id)?,
        session_id,
    );
    let digest: [u8; 32] = digest
        .try_into()
        .map_err(|_| AgentDagStoreError::CorruptRecord("ledger.draft_digest"))?;
    Ok(AgentDagPlanRecord {
        request_id,
        actor,
        goal: GoalAttribution::new(
            forge_domain::GoalId::from_uuid(decode_uuid(&goal, "ledger.goal_id")?),
            forge_domain::GoalRevision::new(goal_revision)
                .map_err(|_| AgentDagStoreError::CorruptRecord("ledger.goal_revision"))?,
        ),
        expected_parent_revision: parent
            .map(DagRevisionNumber::new)
            .transpose()
            .map_err(|_| AgentDagStoreError::CorruptRecord("ledger.expected_parent_revision"))?,
        expected_head_revision: head
            .map(DagHeadRevision::new)
            .transpose()
            .map_err(|_| AgentDagStoreError::CorruptRecord("ledger.expected_head_revision"))?,
        digest: AgentDagDraftDigest::from_bytes(digest),
        committed_dag_revision_id: forge_domain::DagRevisionId::from_uuid(decode_uuid(
            &revision_id,
            "ledger.committed_dag_revision_id",
        )?),
        committed_dag_revision: DagRevisionNumber::new(committed_revision)
            .map_err(|_| AgentDagStoreError::CorruptRecord("ledger.committed_dag_revision"))?,
        history_update_id: AgentWorkUpdateId::from_uuid(decode_uuid(
            &history_id,
            "ledger.history_update_id",
        )?),
        history_update_sequence: AgentWorkUpdateSequence::new(history_sequence)
            .map_err(|_| AgentDagStoreError::CorruptRecord("ledger.history_update_sequence"))?,
        committed_at: TimestampMillis::new(committed_at)
            .map_err(|_| AgentDagStoreError::CorruptRecord("ledger.committed_at_ms"))?,
    })
}

fn insert_ledger(
    connection: &Connection,
    request: &AgentDagPlanRequest,
    digest: AgentDagDraftDigest,
    dag_revision_id: forge_domain::DagRevisionId,
    dag_revision: DagRevisionNumber,
) -> Result<(), AgentDagStoreError> {
    let (principal_kind, principal_id) = encode_principal(request.actor().principal());
    connection.execute(
        "INSERT INTO agent_dag_plan_ledger (
            request_id, workspace_id, agent_id, activity_id, coordinator_revision, principal_kind, principal_id,
            goal_id, goal_revision, expected_parent_revision, expected_head_revision, draft_digest,
            committed_dag_revision_id, committed_dag_revision, history_update_id,
            history_update_sequence, committed_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
        params![
            request.id().into_uuid().as_bytes(),
            request.actor().workspace_id().into_uuid().as_bytes(),
            request.actor().agent_id().into_uuid().as_bytes(),
            request.actor().activity_id().into_uuid().as_bytes(),
            request.actor().expected_revision().get(),
            principal_kind,
            principal_id.as_deref(),
            request.goal().goal_id().into_uuid().as_bytes(),
            request.goal().expected_revision().get(),
            request
                .expected_parent_revision()
                .map(DagRevisionNumber::get),
            request.expected_head_revision().map(DagHeadRevision::get),
            digest.into_bytes().as_slice(),
            dag_revision_id.into_uuid().as_bytes(),
            dag_revision.get(),
            request.history_update_id().into_uuid().as_bytes(),
            request.history_update_sequence().get(),
            request.observed_at().get(),
        ],
    )?;
    connection.execute(
        "INSERT INTO agent_dag_plan_sessions (request_id, session_id) VALUES (?1, ?2)",
        params![
            request.id().into_uuid().as_bytes(),
            request.actor().session_id().into_uuid().as_bytes()
        ],
    )?;
    Ok(())
}

fn encode_principal(value: AuthenticatedPrincipal) -> (i64, Option<Vec<u8>>) {
    match value {
        AuthenticatedPrincipal::TrustedStdio => (0, None),
        AuthenticatedPrincipal::DirectToken(id) => (1, Some(id.into_uuid().as_bytes().to_vec())),
        AuthenticatedPrincipal::OAuthGrant(id) => (2, Some(id.into_uuid().as_bytes().to_vec())),
    }
}

fn decode_principal(
    kind: i64,
    principal_id: Option<Vec<u8>>,
) -> Result<AuthenticatedPrincipal, AgentDagStoreError> {
    match (kind, principal_id) {
        (0, None) => Ok(AuthenticatedPrincipal::TrustedStdio),
        (1, Some(value)) => Ok(AuthenticatedPrincipal::DirectToken(
            forge_domain::DirectTokenId::from_uuid(decode_uuid(&value, "ledger.principal_id")?),
        )),
        (2, Some(value)) => Ok(AuthenticatedPrincipal::OAuthGrant(
            forge_domain::OAuthGrantId::from_uuid(decode_uuid(&value, "ledger.principal_id")?),
        )),
        _ => Err(AgentDagStoreError::CorruptRecord("ledger.principal")),
    }
}

fn decode_uuid(value: &[u8], field: &'static str) -> Result<Uuid, AgentDagStoreError> {
    Uuid::from_slice(value).map_err(|_| AgentDagStoreError::CorruptRecord(field))
}

fn normalize_sql(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

#[derive(Debug, Error)]
pub enum AgentDagStoreError {
    #[error(transparent)]
    WorkCut(#[from] Box<crate::WorkCutError>),
    #[error("historical plan receipt has no proven session identity")]
    UnresolvedSession,
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    SemanticEvents(#[from] crate::SemanticEventError),
    #[error(transparent)]
    Agent(#[from] AgentStoreError),
    #[error(transparent)]
    Coordinator(#[from] CoordinatorStoreError),
    #[error(transparent)]
    Dag(#[from] DagStoreError),
    #[error(transparent)]
    Goal(#[from] GoalStoreError),
    #[error("Workspace identity was not found")]
    WorkspaceNotFound(WorkspaceId),
    #[error("Goal was not found")]
    GoalMissing(forge_domain::GoalId),
    #[error("Goal conflicts with Coordinator planning scope")]
    GoalConflict,
    #[error("Coordinator DAG draft conflicts with the current Goal/head contract")]
    DraftConflict,
    #[error("Coordinator DAG plan request identity conflicts with the existing ledger row")]
    RequestIdentityConflict,
    #[error("Coordinator DAG plan ledger points to a missing DAG revision")]
    LedgerRevisionMissing,
    #[error("factual Agent history update is invalid")]
    HistoryInvalid,
    #[error("Coordinator DAG plan schema object is damaged: {0}")]
    DamagedSchema(&'static str),
    #[error("Coordinator DAG plan record is corrupt: {0}")]
    CorruptRecord(&'static str),
}

impl From<crate::WorkCutError> for AgentDagStoreError {
    fn from(error: crate::WorkCutError) -> Self {
        Self::WorkCut(Box::new(error))
    }
}
