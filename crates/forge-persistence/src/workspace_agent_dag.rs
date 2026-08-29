//! Workspace-local one-shot Agent DAG authoring grants and replay ledger.
//!
//! Grant issuance/revocation are fenced durable transitions.  A replan commit
//! owns one IMMEDIATE transaction that first resolves an exact request replay,
//! then validates the live actor/grant/head, inserts one immutable successor
//! DAG, appends factual Agent history, consumes the grant, and records the
//! request ledger.  There is no scheduler, continuation, or execution
//! authority here.

use forge_domain::{
    ActivityId, AgentAuthoringCredential, AgentDagAuthoringActor, AgentDagAuthoringGrant,
    AgentDagAuthoringGrantAvailability, AgentDagAuthoringGrantError, AgentDagAuthoringGrantId,
    AgentDagAuthoringGrantRevision, AgentDagAuthoringGrantState, AgentDagDraftDigest,
    AgentDagReplanReceipt, AgentDagReplanRequest, AgentInstanceId, AgentWorkPhase,
    AgentWorkSummary, AgentWorkUpdate, AgentWorkUpdateId, AgentWorkUpdateSequence, DagHeadRevision,
    DagRevisionNumber, GoalAttribution, GoalStatusKind, RegisteredAgentInstance, TimestampMillis,
    WorkspaceId,
};
use rusqlite::{Connection, OptionalExtension, Row, TransactionBehavior, params};
use thiserror::Error;
use uuid::Uuid;

use crate::workspace_agents::{self, AgentStoreError};
use crate::workspace_dags::{self, DagStoreError, StoredDagRevision};
use crate::workspace_goals::{self, GoalStoreError};

const ID_BYTES_I64: i64 = 16;
const DIGEST_BYTES_I64: i64 = 32;

type ActivityLeaseRow = (Vec<u8>, i64, Option<i64>, Option<Vec<u8>>);

const EXPECTED_AGENT_DAG_GRANTS_TABLE_SQL: &str = "CREATE TABLE agent_dag_authoring_grants (grant_id BLOB PRIMARY KEY NOT NULL CHECK(length(grant_id) = 16), workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16), agent_id BLOB NOT NULL CHECK(length(agent_id) = 16), activity_id BLOB NOT NULL REFERENCES activities(activity_id) CHECK(length(activity_id) = 16), credential_kind INTEGER NOT NULL CHECK(credential_kind IN (0, 1)), credential_token_id BLOB CHECK(credential_token_id IS NULL OR length(credential_token_id) = 16), goal_id BLOB NOT NULL REFERENCES goals(goal_id) CHECK(length(goal_id) = 16), goal_revision INTEGER NOT NULL CHECK(goal_revision >= 1), expected_dag_revision INTEGER NOT NULL CHECK(expected_dag_revision >= 1), expected_head_revision INTEGER NOT NULL CHECK(expected_head_revision >= 1), issued_at_ms INTEGER NOT NULL CHECK(issued_at_ms >= 0), expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms > issued_at_ms), state INTEGER NOT NULL CHECK(state IN (0, 1, 2)), revision INTEGER NOT NULL CHECK(revision >= 1), UNIQUE(grant_id, workspace_id, agent_id, activity_id), FOREIGN KEY(agent_id, workspace_id, activity_id) REFERENCES agent_instances(agent_id, workspace_id, activity_id), CHECK((credential_kind = 0 AND credential_token_id IS NOT NULL) OR (credential_kind = 1 AND credential_token_id IS NULL)))";
const EXPECTED_AGENT_DAG_LEDGER_TABLE_SQL: &str = "CREATE TABLE agent_dag_replan_ledger (request_id BLOB PRIMARY KEY NOT NULL CHECK(length(request_id) = 16), grant_id BLOB NOT NULL CHECK(length(grant_id) = 16), grant_revision INTEGER NOT NULL CHECK(grant_revision >= 1), workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16), agent_id BLOB NOT NULL CHECK(length(agent_id) = 16), activity_id BLOB NOT NULL REFERENCES activities(activity_id) CHECK(length(activity_id) = 16), credential_kind INTEGER NOT NULL CHECK(credential_kind IN (0, 1)), credential_token_id BLOB CHECK(credential_token_id IS NULL OR length(credential_token_id) = 16), goal_id BLOB NOT NULL REFERENCES goals(goal_id) CHECK(length(goal_id) = 16), goal_revision INTEGER NOT NULL CHECK(goal_revision >= 1), expected_dag_revision INTEGER NOT NULL CHECK(expected_dag_revision >= 1), expected_head_revision INTEGER NOT NULL CHECK(expected_head_revision >= 1), draft_digest BLOB NOT NULL CHECK(length(draft_digest) = 32), committed_dag_revision_id BLOB NOT NULL CHECK(length(committed_dag_revision_id) = 16), committed_dag_revision INTEGER NOT NULL CHECK(committed_dag_revision >= 1), history_update_id BLOB NOT NULL CHECK(length(history_update_id) = 16), history_update_sequence INTEGER NOT NULL CHECK(history_update_sequence >= 1), committed_at_ms INTEGER NOT NULL CHECK(committed_at_ms >= 0), UNIQUE(request_id, workspace_id, agent_id, activity_id), FOREIGN KEY(agent_id, workspace_id, activity_id) REFERENCES agent_instances(agent_id, workspace_id, activity_id), FOREIGN KEY(grant_id) REFERENCES agent_dag_authoring_grants(grant_id), FOREIGN KEY(goal_id, committed_dag_revision) REFERENCES goal_dag_revisions(goal_id, dag_revision), FOREIGN KEY(history_update_id, agent_id, workspace_id) REFERENCES agent_work_updates(update_id, agent_id, workspace_id), CHECK((credential_kind = 0 AND credential_token_id IS NOT NULL) OR (credential_kind = 1 AND credential_token_id IS NULL)))";
const EXPECTED_AGENT_DAG_GRANTS_INDEX_SQL: &str = "CREATE INDEX agent_dag_authoring_grants_actor_state_idx ON agent_dag_authoring_grants(workspace_id, agent_id, activity_id, state, expires_at_ms, grant_id)";
const EXPECTED_AGENT_DAG_LEDGER_INDEX_SQL: &str = "CREATE INDEX agent_dag_replan_ledger_actor_committed_idx ON agent_dag_replan_ledger(workspace_id, agent_id, activity_id, committed_at_ms DESC, request_id DESC)";

const OBJECTS: [(&str, &str, &str); 4] = [
    (
        "table",
        "agent_dag_authoring_grants",
        EXPECTED_AGENT_DAG_GRANTS_TABLE_SQL,
    ),
    (
        "table",
        "agent_dag_replan_ledger",
        EXPECTED_AGENT_DAG_LEDGER_TABLE_SQL,
    ),
    (
        "index",
        "agent_dag_authoring_grants_actor_state_idx",
        EXPECTED_AGENT_DAG_GRANTS_INDEX_SQL,
    ),
    (
        "index",
        "agent_dag_replan_ledger_actor_committed_idx",
        EXPECTED_AGENT_DAG_LEDGER_INDEX_SQL,
    ),
];

pub(crate) fn create_schema(connection: &Connection) -> Result<(), AgentDagStoreError> {
    for (_, _, sql) in OBJECTS {
        connection.execute_batch(sql)?;
    }
    Ok(())
}

pub(crate) fn migrate_v15_to_v16(
    connection: &mut Connection,
    next_schema_version: i64,
) -> Result<(), AgentDagStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let existing_objects: i64 = transaction.query_row(
        "SELECT COUNT(*) FROM sqlite_schema
         WHERE (type = 'table' AND name IN ('agent_dag_authoring_grants', 'agent_dag_replan_ledger'))
            OR (type = 'index' AND name IN ('agent_dag_authoring_grants_actor_state_idx', 'agent_dag_replan_ledger_actor_committed_idx'))",
        [],
        |row| row.get(0),
    )?;
    if existing_objects == 0 {
        create_schema(&transaction)?;
    } else {
        // A previous interrupted/retried migration may already have created
        // the complete grant authority.  Validate the whole set before
        // accepting it; partial or damaged objects fail closed.
        validate_schema(&transaction)?;
    }
    transaction.pragma_update(None, "user_version", next_schema_version)?;
    transaction.commit()?;
    Ok(())
}

pub(crate) fn schema_objects() -> [(&'static str, &'static str); 4] {
    [
        ("table", "agent_dag_authoring_grants"),
        ("table", "agent_dag_replan_ledger"),
        ("index", "agent_dag_authoring_grants_actor_state_idx"),
        ("index", "agent_dag_replan_ledger_actor_committed_idx"),
    ]
}

pub(crate) fn validate_schema(connection: &Connection) -> Result<(), AgentDagStoreError> {
    for (kind, name, expected) in OBJECTS {
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
    validate_columns(
        connection,
        "agent_dag_authoring_grants",
        &[
            ("grant_id", "BLOB", 1, 1),
            ("workspace_id", "BLOB", 1, 0),
            ("agent_id", "BLOB", 1, 0),
            ("activity_id", "BLOB", 1, 0),
            ("credential_kind", "INTEGER", 1, 0),
            ("credential_token_id", "BLOB", 0, 0),
            ("goal_id", "BLOB", 1, 0),
            ("goal_revision", "INTEGER", 1, 0),
            ("expected_dag_revision", "INTEGER", 1, 0),
            ("expected_head_revision", "INTEGER", 1, 0),
            ("issued_at_ms", "INTEGER", 1, 0),
            ("expires_at_ms", "INTEGER", 1, 0),
            ("state", "INTEGER", 1, 0),
            ("revision", "INTEGER", 1, 0),
        ],
    )?;
    validate_columns(
        connection,
        "agent_dag_replan_ledger",
        &[
            ("request_id", "BLOB", 1, 1),
            ("grant_id", "BLOB", 1, 0),
            ("grant_revision", "INTEGER", 1, 0),
            ("workspace_id", "BLOB", 1, 0),
            ("agent_id", "BLOB", 1, 0),
            ("activity_id", "BLOB", 1, 0),
            ("credential_kind", "INTEGER", 1, 0),
            ("credential_token_id", "BLOB", 0, 0),
            ("goal_id", "BLOB", 1, 0),
            ("goal_revision", "INTEGER", 1, 0),
            ("expected_dag_revision", "INTEGER", 1, 0),
            ("expected_head_revision", "INTEGER", 1, 0),
            ("draft_digest", "BLOB", 1, 0),
            ("committed_dag_revision_id", "BLOB", 1, 0),
            ("committed_dag_revision", "INTEGER", 1, 0),
            ("history_update_id", "BLOB", 1, 0),
            ("history_update_sequence", "INTEGER", 1, 0),
            ("committed_at_ms", "INTEGER", 1, 0),
        ],
    )?;
    validate_foreign_keys(
        connection,
        "agent_dag_authoring_grants",
        &[
            ("activities", "activity_id", "activity_id"),
            ("agent_instances", "agent_id", "agent_id"),
            ("agent_instances", "workspace_id", "workspace_id"),
            ("agent_instances", "activity_id", "activity_id"),
            ("goals", "goal_id", "goal_id"),
            ("workspace", "workspace_id", "workspace_id"),
        ],
    )?;
    validate_foreign_keys(
        connection,
        "agent_dag_replan_ledger",
        &[
            ("activities", "activity_id", "activity_id"),
            ("agent_instances", "agent_id", "agent_id"),
            ("agent_instances", "workspace_id", "workspace_id"),
            ("agent_instances", "activity_id", "activity_id"),
            ("agent_dag_authoring_grants", "grant_id", "grant_id"),
            ("goals", "goal_id", "goal_id"),
            ("goal_dag_revisions", "goal_id", "goal_id"),
            (
                "goal_dag_revisions",
                "committed_dag_revision",
                "dag_revision",
            ),
            ("agent_work_updates", "history_update_id", "update_id"),
            ("agent_work_updates", "agent_id", "agent_id"),
            ("agent_work_updates", "workspace_id", "workspace_id"),
            ("workspace", "workspace_id", "workspace_id"),
        ],
    )?;
    Ok(())
}

fn normalize_sql(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn validate_columns(
    connection: &Connection,
    table: &'static str,
    expected: &[(&str, &str, i64, i64)],
) -> Result<(), AgentDagStoreError> {
    let mut statement = connection.prepare(&format!("PRAGMA table_info({table})"))?;
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
    if actual.len() != expected.len()
        || !actual.iter().zip(expected).all(
            |((name, data_type, not_null, primary_key), expected)| {
                name == expected.0
                    && data_type == expected.1
                    && *not_null == expected.2
                    && *primary_key == expected.3
            },
        )
    {
        return Err(AgentDagStoreError::DamagedSchema(table));
    }
    Ok(())
}

fn validate_foreign_keys(
    connection: &Connection,
    table: &'static str,
    expected: &[(&str, &str, &str)],
) -> Result<(), AgentDagStoreError> {
    let mut statement = connection.prepare(&format!("PRAGMA foreign_key_list({table})"))?;
    let mut rows = statement.query([])?;
    let mut actual = Vec::new();
    while let Some(row) = rows.next()? {
        actual.push((
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, String>(6)?,
            row.get::<_, String>(7)?,
        ));
    }
    let mut expected = expected
        .iter()
        .map(|(parent, from, to)| {
            (
                (*parent).to_owned(),
                (*from).to_owned(),
                (*to).to_owned(),
                "NO ACTION".to_owned(),
                "NO ACTION".to_owned(),
                "NONE".to_owned(),
            )
        })
        .collect::<Vec<_>>();
    actual.sort_unstable();
    expected.sort_unstable();
    if actual == expected {
        Ok(())
    } else {
        Err(AgentDagStoreError::DamagedSchema(table))
    }
}

pub(crate) fn get_grant(
    connection: &Connection,
    grant_id: AgentDagAuthoringGrantId,
) -> Result<Option<AgentDagAuthoringGrant>, AgentDagStoreError> {
    grant_by_id(connection, grant_id)
}

/// Find the one currently usable grant for an exact actor/Goal/head tuple.
/// Expired active rows are intentionally not returned: expiry is an observed
/// availability state, not a second durable lifecycle transition.
pub(crate) fn find_active_grant(
    connection: &Connection,
    actor: AgentDagAuthoringActor,
    goal: GoalAttribution,
    expected_dag_revision: DagRevisionNumber,
    expected_head_revision: DagHeadRevision,
    now: TimestampMillis,
) -> Result<Option<AgentDagAuthoringGrant>, AgentDagStoreError> {
    let agent = workspace_agents::get_in_transaction(connection, actor.agent_id())?
        .ok_or(AgentDagStoreError::AgentNotFound(actor.agent_id()))?;
    ensure_actor_matches_agent(connection, &agent, actor)?;
    let (credential_kind, credential_token_id) = encode_credential(actor.credential());
    let grant_id: Option<Vec<u8>> = connection
        .query_row(
            "SELECT grant_id FROM agent_dag_authoring_grants
             WHERE workspace_id = ?1 AND agent_id = ?2 AND activity_id = ?3
               AND credential_kind = ?4
               AND credential_token_id IS ?5
               AND goal_id = ?6 AND goal_revision = ?7
               AND expected_dag_revision = ?8 AND expected_head_revision = ?9
               AND state = 0 AND expires_at_ms > ?10
             ORDER BY expires_at_ms ASC, grant_id ASC LIMIT 1",
            params![
                actor.workspace_id().into_uuid().as_bytes(),
                actor.agent_id().into_uuid().as_bytes(),
                actor.activity_id().into_uuid().as_bytes(),
                credential_kind,
                credential_token_id.as_deref(),
                goal.goal_id().into_uuid().as_bytes(),
                goal.expected_revision().get(),
                expected_dag_revision.get(),
                expected_head_revision.get(),
                now.get(),
            ],
            |row| row.get(0),
        )
        .optional()?;
    grant_id
        .map(|value| {
            let id = Uuid::from_slice(&value)
                .map(AgentDagAuthoringGrantId::from_uuid)
                .map_err(|_| AgentDagStoreError::CorruptRecord("grant.grant_id"))?;
            grant_by_id(connection, id)?.ok_or(AgentDagStoreError::CorruptRecord("grant.lookup"))
        })
        .transpose()
}

pub(crate) fn issue_grant(
    connection: &mut Connection,
    grant: &AgentDagAuthoringGrant,
) -> Result<AgentDagAuthoringGrant, AgentDagStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    ensure_workspace(&transaction, grant.workspace_id())?;
    let agent = workspace_agents::get_in_transaction(&transaction, grant.agent_id())?
        .ok_or(AgentDagStoreError::AgentNotFound(grant.agent_id()))?;
    ensure_actor_matches_agent(&transaction, &agent, grant.actor())?;
    ensure_live_activity(
        &transaction,
        grant.activity_id(),
        grant.workspace_id(),
        grant.issued_at(),
    )?;
    ensure_goal_and_head(
        &transaction,
        grant.workspace_id(),
        grant.goal(),
        grant.expected_dag_revision(),
        grant.expected_head_revision(),
    )?;
    if let Some(existing) = grant_by_id(&transaction, grant.id())? {
        if existing == *grant {
            transaction.commit()?;
            return Ok(existing);
        }
        return Err(AgentDagStoreError::GrantIdentityConflict);
    }
    if let Some(existing) = find_active_grant(
        &transaction,
        grant.actor(),
        grant.goal(),
        grant.expected_dag_revision(),
        grant.expected_head_revision(),
        grant.issued_at(),
    )? {
        return Err(AgentDagStoreError::ActiveGrantConflict(existing.id()));
    }
    insert_grant(&transaction, grant)?;
    transaction.commit()?;
    Ok(grant.clone())
}

pub(crate) fn revoke_grant(
    connection: &mut Connection,
    grant_id: AgentDagAuthoringGrantId,
    expected_revision: AgentDagAuthoringGrantRevision,
    workspace_id: WorkspaceId,
) -> Result<AgentDagAuthoringGrant, AgentDagStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let current =
        grant_by_id(&transaction, grant_id)?.ok_or(AgentDagStoreError::GrantNotFound(grant_id))?;
    if current.workspace_id() != workspace_id {
        return Err(AgentDagStoreError::GrantNotFound(grant_id));
    }
    let updated = current
        .revoke(expected_revision)
        .map_err(AgentDagStoreError::GrantTransition)?;
    let changed = transaction.execute(
        "UPDATE agent_dag_authoring_grants SET state = ?1, revision = ?2 WHERE grant_id = ?3 AND revision = ?4 AND state = 0",
        params![
            encode_grant_state(updated.state()),
            updated.revision().get(),
            grant_id.into_uuid().as_bytes(),
            expected_revision.get(),
        ],
    )?;
    if changed != 1 {
        return Err(AgentDagStoreError::GrantRevisionConflict);
    }
    transaction.commit()?;
    Ok(updated)
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentDagReplanCommitResult {
    receipt: AgentDagReplanReceipt,
    revision: StoredDagRevision,
}

impl AgentDagReplanCommitResult {
    pub const fn receipt(&self) -> AgentDagReplanReceipt {
        self.receipt
    }

    pub const fn revision(&self) -> &StoredDagRevision {
        &self.revision
    }
}

pub(crate) fn commit_replan(
    connection: &mut Connection,
    request: &AgentDagReplanRequest,
) -> Result<AgentDagReplanCommitResult, AgentDagStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let digest = request.digest();
    if let Some(ledger) = ledger_by_request(&transaction, request.id())? {
        if !ledger.matches(request, digest) {
            return Err(AgentDagStoreError::RequestIdentityConflict);
        }
        let grant = grant_by_id(&transaction, ledger.grant_id)?
            .ok_or(AgentDagStoreError::GrantNotFound(ledger.grant_id))?;
        if grant.actor() != ledger.actor
            || grant.goal() != GoalAttribution::new(ledger.goal_id, ledger.goal_revision)
            || grant.expected_dag_revision() != ledger.expected_dag_revision
            || grant.expected_head_revision() != ledger.expected_head_revision
        {
            return Err(AgentDagStoreError::RequestIdentityConflict);
        }
        let revision_id = ledger.committed_dag_revision_id;
        let revision_number = ledger.committed_dag_revision;
        let goal_id = ledger.goal_id;
        transaction.commit()?;
        let revision = workspace_dags::get_revision(connection, goal_id, revision_number)?
            .ok_or(AgentDagStoreError::LedgerRevisionMissing)?;
        let receipt = AgentDagReplanReceipt::new(
            request.id(),
            ledger.grant_id,
            digest,
            revision_id,
            revision_number,
            ledger.committed_at,
            true,
        );
        return Ok(AgentDagReplanCommitResult { receipt, revision });
    }

    let grant = grant_by_id(&transaction, request.grant_id())?
        .ok_or(AgentDagStoreError::GrantNotFound(request.grant_id()))?;
    if grant.actor() != request.actor() {
        return Err(AgentDagStoreError::GrantActorMismatch);
    }
    if grant.revision() != request.expected_grant_revision() {
        return Err(AgentDagStoreError::GrantRevisionConflict);
    }
    if !grant.availability(request.observed_at()).is_available() {
        return Err(AgentDagStoreError::GrantUnavailable(
            grant.availability(request.observed_at()),
        ));
    }
    let stored = apply_replan_in_transaction(&transaction, request, &grant, digest)?;
    let receipt = AgentDagReplanReceipt::new(
        request.id(),
        grant.id(),
        digest,
        stored.revision().id(),
        stored.revision().number(),
        request.observed_at(),
        false,
    );
    transaction.commit()?;
    Ok(AgentDagReplanCommitResult {
        receipt,
        revision: stored,
    })
}

fn apply_replan_in_transaction(
    transaction: &rusqlite::Transaction<'_>,
    request: &AgentDagReplanRequest,
    grant: &AgentDagAuthoringGrant,
    digest: AgentDagDraftDigest,
) -> Result<StoredDagRevision, AgentDagStoreError> {
    let agent = workspace_agents::get_in_transaction(transaction, request.actor().agent_id())?
        .ok_or(AgentDagStoreError::AgentNotFound(
            request.actor().agent_id(),
        ))?;
    ensure_actor_matches_agent(transaction, &agent, request.actor())?;
    ensure_live_activity(
        transaction,
        request.actor().activity_id(),
        request.actor().workspace_id(),
        request.observed_at(),
    )?;
    ensure_goal_and_head(
        transaction,
        request.actor().workspace_id(),
        grant.goal(),
        grant.expected_dag_revision(),
        grant.expected_head_revision(),
    )?;
    validate_draft_for_grant(request, grant)?;

    let stored = workspace_dags::insert_revision_in_transaction(
        transaction,
        request.draft().revision(),
        request.draft().nodes(),
        request.draft().lineage(),
        Some(grant.expected_head_revision()),
    )?;
    let history = AgentWorkUpdate::new(
        request.history_update_id(),
        request.actor().agent_id(),
        request.actor().workspace_id(),
        request.actor().activity_id(),
        request.history_update_sequence(),
        AgentWorkPhase::Planning,
        AgentWorkSummary::new("Committed a DAG replan".to_owned())
            .map_err(|_| AgentDagStoreError::HistoryInvalid)?,
        Vec::new(),
        request.observed_at(),
    )
    .map_err(|_| AgentDagStoreError::HistoryInvalid)?;
    let _persisted_history =
        workspace_agents::publish_work_update_in_transaction(transaction, &history)?;
    let consumed = grant
        .consume(request.expected_grant_revision())
        .map_err(AgentDagStoreError::GrantTransition)?;
    let changed = transaction.execute(
        "UPDATE agent_dag_authoring_grants SET state = ?1, revision = ?2 WHERE grant_id = ?3 AND revision = ?4 AND state = 0",
        params![
            encode_grant_state(consumed.state()),
            consumed.revision().get(),
            grant.id().into_uuid().as_bytes(),
            request.expected_grant_revision().get(),
        ],
    )?;
    if changed != 1 {
        return Err(AgentDagStoreError::GrantRevisionConflict);
    }
    insert_ledger(
        transaction,
        request,
        grant,
        digest,
        stored.revision().id(),
        stored.revision().number(),
    )?;
    Ok(stored)
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
    if exists.is_some() {
        Ok(())
    } else {
        Err(AgentDagStoreError::WorkspaceNotFound(workspace_id))
    }
}

fn ensure_actor_matches_agent(
    connection: &Connection,
    agent: &RegisteredAgentInstance,
    actor: AgentDagAuthoringActor,
) -> Result<(), AgentDagStoreError> {
    if agent.workspace_id() != actor.workspace_id()
        || agent.activity_id() != actor.activity_id()
        || agent.attachment_state().is_detached()
    {
        return Err(AgentDagStoreError::ActorMismatch);
    }
    if let AgentAuthoringCredential::Token(expected_token_id) = actor.credential() {
        let principal: Option<Vec<u8>> = connection
            .query_row(
                "SELECT token_id FROM agent_transport_principals
                 WHERE agent_id = ?1 AND workspace_id = ?2 AND activity_id = ?3",
                params![
                    actor.agent_id().into_uuid().as_bytes(),
                    actor.workspace_id().into_uuid().as_bytes(),
                    actor.activity_id().into_uuid().as_bytes(),
                ],
                |row| row.get(0),
            )
            .optional()?;
        let Some(principal) = principal else {
            return Err(AgentDagStoreError::ActorCredentialMissing);
        };
        let actual = Uuid::from_slice(&principal)
            .map(forge_domain::McpTokenId::from_uuid)
            .map_err(|_| {
                AgentDagStoreError::CorruptRecord("agent_transport_principals.token_id")
            })?;
        if actual != expected_token_id {
            return Err(AgentDagStoreError::ActorCredentialMismatch);
        }
    }
    Ok(())
}

fn ensure_live_activity(
    connection: &Connection,
    activity_id: ActivityId,
    workspace_id: WorkspaceId,
    now: TimestampMillis,
) -> Result<(), AgentDagStoreError> {
    let row: Option<ActivityLeaseRow> = connection
        .query_row(
            "SELECT workspace_id, state, lease_until_ms, lease_owner_id FROM activities WHERE activity_id = ?1",
            params![activity_id.into_uuid().as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    let Some((actual_workspace, state, lease_until, lease_owner)) = row else {
        return Err(AgentDagStoreError::ActivityNotFound(activity_id));
    };
    let actual_workspace = decode_workspace_id(&actual_workspace)?;
    if actual_workspace != workspace_id {
        return Err(AgentDagStoreError::ActivityWorkspaceMismatch {
            expected: workspace_id,
            actual: actual_workspace,
        });
    }
    if state != 1 || lease_owner.is_none() || lease_until.is_none_or(|value| value <= now.get()) {
        return Err(AgentDagStoreError::ActivityNotLive(activity_id));
    }
    Ok(())
}

fn ensure_goal_and_head(
    connection: &Connection,
    workspace_id: WorkspaceId,
    goal: GoalAttribution,
    expected_dag_revision: DagRevisionNumber,
    expected_head_revision: DagHeadRevision,
) -> Result<(), AgentDagStoreError> {
    let goal_record = workspace_goals::get_goal(connection, goal.goal_id())?
        .ok_or(AgentDagStoreError::GoalMissing(goal.goal_id()))?;
    if goal_record.workspace_id() != workspace_id
        || goal_record.revision() != goal.expected_revision()
        || !matches!(
            goal_record.status().kind(),
            GoalStatusKind::Active | GoalStatusKind::Paused
        )
    {
        return Err(AgentDagStoreError::GoalConflict);
    }
    let head: Option<(i64, i64)> = connection
        .query_row(
            "SELECT dag_revision, head_revision FROM goal_dag_heads WHERE goal_id = ?1",
            params![goal.goal_id().into_uuid().as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((actual_dag_revision, actual_head_revision)) = head else {
        return Err(AgentDagStoreError::HeadMissing(goal.goal_id()));
    };
    if actual_dag_revision != expected_dag_revision.get()
        || actual_head_revision != expected_head_revision.get()
    {
        return Err(AgentDagStoreError::HeadConflict);
    }
    Ok(())
}

fn validate_draft_for_grant(
    request: &AgentDagReplanRequest,
    grant: &AgentDagAuthoringGrant,
) -> Result<(), AgentDagStoreError> {
    let revision = request.draft().revision();
    let successor = grant
        .expected_dag_revision()
        .checked_next()
        .map_err(|_| AgentDagStoreError::DraftConflict)?;
    if revision.goal_id() != grant.goal().goal_id()
        || revision.base_goal_revision() != grant.goal().expected_revision()
        || revision.number() != successor
        || revision.parent() != Some(grant.expected_dag_revision())
    {
        return Err(AgentDagStoreError::DraftConflict);
    }
    Ok(())
}

fn insert_grant(
    connection: &Connection,
    grant: &AgentDagAuthoringGrant,
) -> Result<(), AgentDagStoreError> {
    let (credential_kind, credential_token_id) = encode_credential(grant.credential());
    connection.execute(
        "INSERT INTO agent_dag_authoring_grants (grant_id, workspace_id, agent_id, activity_id, credential_kind, credential_token_id, goal_id, goal_revision, expected_dag_revision, expected_head_revision, issued_at_ms, expires_at_ms, state, revision) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
        params![
            grant.id().into_uuid().as_bytes(),
            grant.workspace_id().into_uuid().as_bytes(),
            grant.agent_id().into_uuid().as_bytes(),
            grant.activity_id().into_uuid().as_bytes(),
            credential_kind,
            credential_token_id.as_deref(),
            grant.goal().goal_id().into_uuid().as_bytes(),
            grant.goal().expected_revision().get(),
            grant.expected_dag_revision().get(),
            grant.expected_head_revision().get(),
            grant.issued_at().get(),
            grant.expires_at().get(),
            encode_grant_state(grant.state()),
            grant.revision().get(),
        ],
    )?;
    Ok(())
}

fn grant_by_id(
    connection: &Connection,
    grant_id: AgentDagAuthoringGrantId,
) -> Result<Option<AgentDagAuthoringGrant>, AgentDagStoreError> {
    let mut statement = connection.prepare(GRANT_BY_ID_QUERY)?;
    let mut rows = statement.query(params![grant_id.into_uuid().as_bytes()])?;
    let Some(row) = rows.next()? else {
        return Ok(None);
    };
    decode_grant(row).map(Some)
}

fn decode_grant(row: &Row<'_>) -> Result<AgentDagAuthoringGrant, AgentDagStoreError> {
    let grant_id: Vec<u8> = row.get(0)?;
    let workspace_id: Vec<u8> = row.get(1)?;
    let agent_id: Vec<u8> = row.get(2)?;
    let activity_id: Vec<u8> = row.get(3)?;
    let credential_token_id: Option<Vec<u8>> = row.get(5)?;
    if let Some(length) = row.get::<_, Option<i64>>(18)? {
        validate_id_length("grant.credential_token_id", length)?;
    }
    validate_id_length("grant.grant_id", row.get(14)?)?;
    validate_id_length("grant.workspace_id", row.get(15)?)?;
    validate_id_length("grant.agent_id", row.get(16)?)?;
    validate_id_length("grant.activity_id", row.get(17)?)?;
    let credential = decode_credential(row.get(4)?, credential_token_id)?;
    let actor = AgentDagAuthoringActor::new(
        decode_workspace_id(&workspace_id)?,
        decode_agent_id(&agent_id)?,
        decode_activity_id(&activity_id)?,
        credential,
    );
    let goal = GoalAttribution::new(
        decode_goal_id(&row.get::<_, Vec<u8>>(6)?)?,
        forge_domain::GoalRevision::new(row.get(7)?)
            .map_err(|_| AgentDagStoreError::CorruptRecord("grant.goal_revision"))?,
    );
    AgentDagAuthoringGrant::from_parts(
        AgentDagAuthoringGrantId::from_uuid(decode_uuid(&grant_id, "grant.grant_id")?),
        actor,
        goal,
        DagRevisionNumber::new(row.get(8)?)
            .map_err(|_| AgentDagStoreError::CorruptRecord("grant.dag_revision"))?,
        DagHeadRevision::new(row.get(9)?)
            .map_err(|_| AgentDagStoreError::CorruptRecord("grant.head_revision"))?,
        decode_timestamp(row.get(10)?, "grant.issued_at_ms")?,
        decode_timestamp(row.get(11)?, "grant.expires_at_ms")?,
        decode_grant_state(row.get(12)?)?,
        AgentDagAuthoringGrantRevision::new(row.get(13)?)
            .map_err(|_| AgentDagStoreError::CorruptRecord("grant.revision"))?,
    )
    .map_err(|_| AgentDagStoreError::CorruptRecord("grant.projection"))
}

#[derive(Debug)]
struct LedgerRow {
    request_id: forge_domain::AgentDagReplanRequestId,
    grant_id: AgentDagAuthoringGrantId,
    grant_revision: AgentDagAuthoringGrantRevision,
    actor: AgentDagAuthoringActor,
    goal_id: forge_domain::GoalId,
    goal_revision: forge_domain::GoalRevision,
    expected_dag_revision: DagRevisionNumber,
    expected_head_revision: DagHeadRevision,
    digest: AgentDagDraftDigest,
    committed_dag_revision_id: forge_domain::DagRevisionId,
    committed_dag_revision: DagRevisionNumber,
    history_update_id: AgentWorkUpdateId,
    history_update_sequence: AgentWorkUpdateSequence,
    committed_at: TimestampMillis,
}

impl LedgerRow {
    fn matches(&self, request: &AgentDagReplanRequest, digest: AgentDagDraftDigest) -> bool {
        self.request_id == request.id()
            && self.grant_id == request.grant_id()
            && self.grant_revision == request.expected_grant_revision()
            && self.actor == request.actor()
            && self.goal_id == request.draft().revision().goal_id()
            && self.goal_revision == request.draft().revision().base_goal_revision()
            && self.expected_dag_revision
                == request
                    .draft()
                    .revision()
                    .parent()
                    .unwrap_or(DagRevisionNumber::INITIAL)
            && self.expected_head_revision.get() >= 1
            && self.digest == digest
            && self.history_update_id == request.history_update_id()
            && self.history_update_sequence == request.history_update_sequence()
            && self.committed_at == request.observed_at()
    }
}

fn ledger_by_request(
    connection: &Connection,
    request_id: forge_domain::AgentDagReplanRequestId,
) -> Result<Option<LedgerRow>, AgentDagStoreError> {
    let mut statement = connection.prepare(LEDGER_BY_REQUEST_QUERY)?;
    let mut rows = statement.query(params![request_id.into_uuid().as_bytes()])?;
    let Some(row) = rows.next()? else {
        return Ok(None);
    };
    decode_ledger(row).map(Some)
}

fn decode_ledger(row: &Row<'_>) -> Result<LedgerRow, AgentDagStoreError> {
    let request_id: Vec<u8> = row.get(0)?;
    let grant_id: Vec<u8> = row.get(1)?;
    let workspace_id: Vec<u8> = row.get(3)?;
    let agent_id: Vec<u8> = row.get(4)?;
    let activity_id: Vec<u8> = row.get(5)?;
    let token_id: Option<Vec<u8>> = row.get(7)?;
    let goal_id: Vec<u8> = row.get(8)?;
    let digest: Vec<u8> = row.get(12)?;
    let dag_revision_id: Vec<u8> = row.get(13)?;
    let history_update_id: Vec<u8> = row.get(15)?;
    validate_id_length("ledger.request_id", row.get(18)?)?;
    validate_id_length("ledger.grant_id", row.get(19)?)?;
    validate_id_length("ledger.workspace_id", row.get(20)?)?;
    validate_id_length("ledger.agent_id", row.get(21)?)?;
    validate_id_length("ledger.activity_id", row.get(22)?)?;
    if let Some(length) = row.get::<_, Option<i64>>(23)? {
        validate_id_length("ledger.credential_token_id", length)?;
    }
    validate_id_length("ledger.goal_id", row.get(24)?)?;
    validate_exact_length("ledger.digest", row.get(25)?, DIGEST_BYTES_I64)?;
    validate_id_length("ledger.dag_revision_id", row.get(26)?)?;
    validate_id_length("ledger.history_update_id", row.get(27)?)?;
    let actor = AgentDagAuthoringActor::new(
        decode_workspace_id(&workspace_id)?,
        decode_agent_id(&agent_id)?,
        decode_activity_id(&activity_id)?,
        decode_credential(row.get(6)?, token_id)?,
    );
    let digest = digest
        .try_into()
        .map(AgentDagDraftDigest::from_bytes)
        .map_err(|_| AgentDagStoreError::CorruptRecord("ledger.digest"))?;
    Ok(LedgerRow {
        request_id: forge_domain::AgentDagReplanRequestId::from_uuid(decode_uuid(
            &request_id,
            "ledger.request_id",
        )?),
        grant_id: AgentDagAuthoringGrantId::from_uuid(decode_uuid(&grant_id, "ledger.grant_id")?),
        grant_revision: AgentDagAuthoringGrantRevision::new(row.get(2)?)
            .map_err(|_| AgentDagStoreError::CorruptRecord("ledger.grant_revision"))?,
        actor,
        goal_id: decode_goal_id(&goal_id)?,
        goal_revision: forge_domain::GoalRevision::new(row.get(9)?)
            .map_err(|_| AgentDagStoreError::CorruptRecord("ledger.goal_revision"))?,
        expected_dag_revision: DagRevisionNumber::new(row.get(10)?)
            .map_err(|_| AgentDagStoreError::CorruptRecord("ledger.dag_revision"))?,
        expected_head_revision: DagHeadRevision::new(row.get(11)?)
            .map_err(|_| AgentDagStoreError::CorruptRecord("ledger.head_revision"))?,
        digest,
        committed_dag_revision_id: forge_domain::DagRevisionId::from_uuid(decode_uuid(
            &dag_revision_id,
            "ledger.committed_dag_revision_id",
        )?),
        committed_dag_revision: DagRevisionNumber::new(row.get(14)?)
            .map_err(|_| AgentDagStoreError::CorruptRecord("ledger.committed_dag_revision"))?,
        history_update_id: AgentWorkUpdateId::from_uuid(decode_uuid(
            &history_update_id,
            "ledger.history_update_id",
        )?),
        history_update_sequence: AgentWorkUpdateSequence::new(row.get(16)?)
            .map_err(|_| AgentDagStoreError::CorruptRecord("ledger.history_update_sequence"))?,
        committed_at: decode_timestamp(row.get(17)?, "ledger.committed_at_ms")?,
    })
}

fn insert_ledger(
    connection: &Connection,
    request: &AgentDagReplanRequest,
    grant: &AgentDagAuthoringGrant,
    digest: AgentDagDraftDigest,
    dag_revision_id: forge_domain::DagRevisionId,
    dag_revision: DagRevisionNumber,
) -> Result<(), AgentDagStoreError> {
    let (credential_kind, credential_token_id) = encode_credential(request.actor().credential());
    let revision = request.draft().revision();
    connection.execute(
        "INSERT INTO agent_dag_replan_ledger (request_id, grant_id, grant_revision, workspace_id, agent_id, activity_id, credential_kind, credential_token_id, goal_id, goal_revision, expected_dag_revision, expected_head_revision, draft_digest, committed_dag_revision_id, committed_dag_revision, history_update_id, history_update_sequence, committed_at_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
        params![
            request.id().into_uuid().as_bytes(),
            request.grant_id().into_uuid().as_bytes(),
            request.expected_grant_revision().get(),
            request.actor().workspace_id().into_uuid().as_bytes(),
            request.actor().agent_id().into_uuid().as_bytes(),
            request.actor().activity_id().into_uuid().as_bytes(),
            credential_kind,
            credential_token_id.as_deref(),
            revision.goal_id().into_uuid().as_bytes(),
            revision.base_goal_revision().get(),
            grant.expected_dag_revision().get(),
            grant.expected_head_revision().get(),
            digest.into_bytes().as_slice(),
            dag_revision_id.into_uuid().as_bytes(),
            dag_revision.get(),
            request.history_update_id().into_uuid().as_bytes(),
            request.history_update_sequence().get(),
            request.observed_at().get(),
        ],
    )?;
    Ok(())
}

fn encode_credential(value: AgentAuthoringCredential) -> (i64, Option<Vec<u8>>) {
    match value {
        AgentAuthoringCredential::Token(id) => (0, Some(id.into_uuid().as_bytes().to_vec())),
        AgentAuthoringCredential::TrustedStdio => (1, None),
    }
}

fn decode_credential(
    kind: i64,
    token_id: Option<Vec<u8>>,
) -> Result<AgentAuthoringCredential, AgentDagStoreError> {
    match (kind, token_id) {
        (0, Some(value)) => Ok(AgentAuthoringCredential::Token(
            forge_domain::McpTokenId::from_uuid(decode_uuid(&value, "credential_token_id")?),
        )),
        (1, None) => Ok(AgentAuthoringCredential::TrustedStdio),
        _ => Err(AgentDagStoreError::CorruptRecord("credential")),
    }
}

fn encode_grant_state(value: AgentDagAuthoringGrantState) -> i64 {
    match value {
        AgentDagAuthoringGrantState::Active => 0,
        AgentDagAuthoringGrantState::Consumed => 1,
        AgentDagAuthoringGrantState::Revoked => 2,
    }
}

fn decode_grant_state(value: i64) -> Result<AgentDagAuthoringGrantState, AgentDagStoreError> {
    match value {
        0 => Ok(AgentDagAuthoringGrantState::Active),
        1 => Ok(AgentDagAuthoringGrantState::Consumed),
        2 => Ok(AgentDagAuthoringGrantState::Revoked),
        _ => Err(AgentDagStoreError::CorruptRecord("grant.state")),
    }
}

fn decode_timestamp(
    value: i64,
    field: &'static str,
) -> Result<TimestampMillis, AgentDagStoreError> {
    TimestampMillis::new(value).map_err(|_| AgentDagStoreError::CorruptRecord(field))
}

fn validate_id_length(field: &'static str, actual: i64) -> Result<(), AgentDagStoreError> {
    validate_exact_length(field, actual, ID_BYTES_I64)
}

fn validate_exact_length(
    field: &'static str,
    actual: i64,
    expected: i64,
) -> Result<(), AgentDagStoreError> {
    if actual == expected {
        Ok(())
    } else {
        Err(AgentDagStoreError::InvalidFieldLength {
            field,
            actual,
            expected,
        })
    }
}

fn decode_uuid(value: &[u8], field: &'static str) -> Result<Uuid, AgentDagStoreError> {
    Uuid::from_slice(value).map_err(|_| AgentDagStoreError::CorruptRecord(field))
}

fn decode_workspace_id(value: &[u8]) -> Result<WorkspaceId, AgentDagStoreError> {
    Ok(WorkspaceId::from_uuid(decode_uuid(value, "workspace_id")?))
}

fn decode_agent_id(value: &[u8]) -> Result<AgentInstanceId, AgentDagStoreError> {
    Ok(AgentInstanceId::from_uuid(decode_uuid(value, "agent_id")?))
}

fn decode_activity_id(value: &[u8]) -> Result<ActivityId, AgentDagStoreError> {
    Ok(ActivityId::from_uuid(decode_uuid(value, "activity_id")?))
}

fn decode_goal_id(value: &[u8]) -> Result<forge_domain::GoalId, AgentDagStoreError> {
    Ok(forge_domain::GoalId::from_uuid(decode_uuid(
        value, "goal_id",
    )?))
}

const GRANT_BY_ID_QUERY: &str = "SELECT grant_id, workspace_id, agent_id, activity_id, credential_kind, credential_token_id, goal_id, goal_revision, expected_dag_revision, expected_head_revision, issued_at_ms, expires_at_ms, state, revision, length(grant_id), length(workspace_id), length(agent_id), length(activity_id), length(credential_token_id) FROM agent_dag_authoring_grants WHERE grant_id = ?1";
const LEDGER_BY_REQUEST_QUERY: &str = "SELECT request_id, grant_id, grant_revision, workspace_id, agent_id, activity_id, credential_kind, credential_token_id, goal_id, goal_revision, expected_dag_revision, expected_head_revision, draft_digest, committed_dag_revision_id, committed_dag_revision, history_update_id, history_update_sequence, committed_at_ms, length(request_id), length(grant_id), length(workspace_id), length(agent_id), length(activity_id), length(credential_token_id), length(goal_id), length(draft_digest), length(committed_dag_revision_id), length(history_update_id) FROM agent_dag_replan_ledger WHERE request_id = ?1";

#[derive(Debug, Error)]
pub enum AgentDagStoreError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Agent(#[from] AgentStoreError),
    #[error(transparent)]
    Dag(#[from] DagStoreError),
    #[error(transparent)]
    Goal(#[from] GoalStoreError),
    #[error("Agent DAG authoring grant was not found")]
    GrantNotFound(AgentDagAuthoringGrantId),
    #[error("Agent instance was not found for Agent DAG authoring")]
    AgentNotFound(AgentInstanceId),
    #[error("Agent DAG authoring grant identity conflicts")]
    GrantIdentityConflict,
    #[error("an active Agent DAG authoring grant already exists")]
    ActiveGrantConflict(AgentDagAuthoringGrantId),
    #[error("Agent DAG authoring grant actor conflicts")]
    GrantActorMismatch,
    #[error("Agent transport principal is missing for the authoring credential")]
    ActorCredentialMissing,
    #[error("Agent transport principal conflicts with the authoring credential")]
    ActorCredentialMismatch,
    #[error("Agent DAG authoring grant revision conflicts")]
    GrantRevisionConflict,
    #[error("Agent DAG authoring grant is unavailable: {0:?}")]
    GrantUnavailable(AgentDagAuthoringGrantAvailability),
    #[error("Agent DAG authoring grant transition is invalid")]
    GrantTransition(#[source] AgentDagAuthoringGrantError),
    #[error("Agent actor does not match durable attachment")]
    ActorMismatch,
    #[error("Workspace identity was not found")]
    WorkspaceNotFound(WorkspaceId),
    #[error("Activity was not found")]
    ActivityNotFound(ActivityId),
    #[error("Activity belongs to another Workspace")]
    ActivityWorkspaceMismatch {
        expected: WorkspaceId,
        actual: WorkspaceId,
    },
    #[error("Activity is not live")]
    ActivityNotLive(ActivityId),
    #[error("Goal was not found")]
    GoalMissing(forge_domain::GoalId),
    #[error("Goal conflicts with authoring scope")]
    GoalConflict,
    #[error("current DAG head is missing")]
    HeadMissing(forge_domain::GoalId),
    #[error("current DAG head conflicts with authoring scope")]
    HeadConflict,
    #[error("Agent DAG draft conflicts with the one-shot successor contract")]
    DraftConflict,
    #[error("replan request identity conflicts with the existing ledger row")]
    RequestIdentityConflict,
    #[error("replan ledger points to a missing DAG revision")]
    LedgerRevisionMissing,
    #[error("factual Agent history update is invalid")]
    HistoryInvalid,
    #[error("Agent DAG authoring schema object is damaged: {0}")]
    DamagedSchema(&'static str),
    #[error("Agent DAG authoring persisted field {field} has length {actual}, expected {expected}")]
    InvalidFieldLength {
        field: &'static str,
        actual: i64,
        expected: i64,
    },
    #[error("Agent DAG authoring record is corrupt: {0}")]
    CorruptRecord(&'static str),
    #[error("Agent DAG authoring integer overflowed")]
    IntegerOverflow,
}

#[cfg(test)]
mod tests {
    use super::*;
    use forge_domain::{
        ActivityId, AgentDagAuthoringGrantTtl, AgentDagDraft, AgentDagReplanRequestId,
        AgentDeclaredRole, AgentDisplayName, AgentInstanceId, AgentTransportKind,
        BootstrapActivity, DagAcceptanceCriterion, DagNodeDefinition, DagNodeId, DagNodeObjective,
        DagNodeOrdinal, DagNodeTitle, DagRevision, DagRevisionId, EstablishWorkspace, GoalContract,
        GoalObjective, GoalRevision, GoalStatement, RegisteredAgentInstance, RegisteredDagNode,
        RegisteredGoal, RuntimeInstanceId, WorkspaceRevision, WorkspaceRoot,
    };
    use forge_workspace::WorkspaceStateLayout;
    use rusqlite::Connection;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::{WorkspaceStore, WorkspaceStoreError};

    struct Fixture {
        root: PathBuf,
        layout: WorkspaceStateLayout,
        store: WorkspaceStore,
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        goal: RegisteredGoal,
        definition: DagNodeDefinition,
        agent: RegisteredAgentInstance,
    }

    fn timestamp(value: i64) -> Result<TimestampMillis, Box<dyn std::error::Error>> {
        Ok(TimestampMillis::new(value)?)
    }

    fn fixture(label: &str) -> Result<Fixture, Box<dyn std::error::Error>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let root = std::env::temp_dir().join(format!(
            "forge-agent-dag-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&root)?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(0xD001));
        let location_id = forge_domain::LocationId::from_uuid(Uuid::from_u128(0xD002));
        let command = EstablishWorkspace::new(
            workspace_id,
            location_id,
            WorkspaceRoot::from_canonical(layout.workspace_root().to_path_buf())?,
            layout.root_fingerprint()?,
            timestamp(1)?,
        );
        let mut store = WorkspaceStore::open(&layout, &command)?;
        let activity_id = ActivityId::from_uuid(Uuid::from_u128(0xD003));
        store.bootstrap_activity(&BootstrapActivity::new(
            activity_id,
            workspace_id,
            WorkspaceRevision::INITIAL,
            RuntimeInstanceId::from_uuid(Uuid::from_u128(0xD004)),
            timestamp(1_000)?,
            timestamp(2)?,
        ))?;
        let goal = RegisteredGoal::create(
            forge_domain::GoalId::from_uuid(Uuid::from_u128(0xD005)),
            workspace_id,
            GoalContract::new(
                GoalObjective::new("Author a bounded DAG".to_owned())?,
                vec![GoalStatement::new("The DAG remains durable".to_owned())?],
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            )?,
            timestamp(3)?,
        );
        let _ = store.insert_goal(&goal)?;
        let definition = DagNodeDefinition::new(
            DagNodeId::from_uuid(Uuid::from_u128(0xD006)),
            DagNodeOrdinal::new(0)?,
            DagNodeTitle::new("Author".to_owned())?,
            DagNodeObjective::new("Author the next DAG".to_owned())?,
            vec![DagAcceptanceCriterion::new("DAG is persisted".to_owned())?],
        )?;
        let initial_revision = DagRevision::new(
            DagRevisionId::from_uuid(Uuid::from_u128(0xD007)),
            goal.id(),
            GoalRevision::INITIAL,
            DagRevisionNumber::INITIAL,
            None,
            vec![definition.clone()],
            Vec::new(),
            timestamp(4)?,
        )?;
        let initial_node = RegisteredDagNode::create(
            goal.id(),
            initial_revision.number(),
            definition.clone(),
            initial_revision.created_at(),
        );
        let _ = store.insert_dag_revision(&initial_revision, &[initial_node], &[], None)?;
        let agent = RegisteredAgentInstance::create(
            AgentInstanceId::from_uuid(Uuid::from_u128(0xD008)),
            workspace_id,
            activity_id,
            AgentDisplayName::new("Planner".to_owned())?,
            AgentDeclaredRole::new("planner".to_owned())?,
            AgentTransportKind::Stdio,
            timestamp(5)?,
        );
        let _ = store.attach_agent(&agent)?;
        Ok(Fixture {
            root,
            layout,
            store,
            workspace_id,
            activity_id,
            goal,
            definition,
            agent,
        })
    }

    fn grant(
        fixture: &Fixture,
        grant_id: u128,
        issued_at: i64,
    ) -> Result<AgentDagAuthoringGrant, Box<dyn std::error::Error>> {
        Ok(AgentDagAuthoringGrant::issue(
            AgentDagAuthoringGrantId::from_uuid(Uuid::from_u128(grant_id)),
            AgentDagAuthoringActor::new(
                fixture.workspace_id,
                fixture.agent.id(),
                fixture.activity_id,
                AgentAuthoringCredential::TrustedStdio,
            ),
            GoalAttribution::new(fixture.goal.id(), fixture.goal.revision()),
            DagRevisionNumber::INITIAL,
            DagHeadRevision::INITIAL,
            timestamp(issued_at)?,
            AgentDagAuthoringGrantTtl::DEFAULT,
        )?)
    }

    fn successor_draft(
        fixture: &Fixture,
        revision_id: u128,
        created_at: i64,
    ) -> Result<AgentDagDraft, Box<dyn std::error::Error>> {
        let number = DagRevisionNumber::new(2)?;
        let revision = DagRevision::new(
            DagRevisionId::from_uuid(Uuid::from_u128(revision_id)),
            fixture.goal.id(),
            fixture.goal.revision(),
            number,
            Some(DagRevisionNumber::INITIAL),
            vec![fixture.definition.clone()],
            Vec::new(),
            timestamp(created_at)?,
        )?;
        let node = RegisteredDagNode::create(
            fixture.goal.id(),
            number,
            fixture.definition.clone(),
            timestamp(created_at)?,
        );
        Ok(AgentDagDraft::new(revision, vec![node], Vec::new())?)
    }

    fn make_request(
        grant: &AgentDagAuthoringGrant,
        draft: AgentDagDraft,
        request_id: u128,
        history_id: u128,
        sequence: i64,
        observed_at: i64,
    ) -> Result<AgentDagReplanRequest, Box<dyn std::error::Error>> {
        Ok(AgentDagReplanRequest::new(
            AgentDagReplanRequestId::from_uuid(Uuid::from_u128(request_id)),
            grant.id(),
            grant.revision(),
            grant.actor(),
            draft,
            AgentWorkUpdateId::from_uuid(Uuid::from_u128(history_id)),
            AgentWorkUpdateSequence::new(sequence)?,
            timestamp(observed_at)?,
        ))
    }

    #[test]
    fn fresh_schema_has_v16_authoring_objects_and_discovery_is_exact()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = fixture("fresh")?;
        assert_eq!(fixture.store.health()?.schema_version(), 16);
        let actor = AgentDagAuthoringActor::new(
            fixture.workspace_id,
            fixture.agent.id(),
            fixture.activity_id,
            AgentAuthoringCredential::TrustedStdio,
        );
        let issued = grant(&fixture, 0xD010, 10)?;
        assert_eq!(
            fixture.store.issue_agent_dag_authoring_grant(&issued)?,
            issued
        );
        assert_eq!(
            fixture.store.find_active_agent_dag_authoring_grant(
                actor,
                issued.goal(),
                issued.expected_dag_revision(),
                issued.expected_head_revision(),
                timestamp(11)?,
            )?,
            Some(issued.clone())
        );
        let duplicate = grant(&fixture, 0xD011, 12)?;
        assert!(matches!(
            fixture.store.issue_agent_dag_authoring_grant(&duplicate),
            Err(WorkspaceStoreError::AgentDag(
                AgentDagStoreError::ActiveGrantConflict(_)
            ))
        ));
        drop(fixture.store);
        let existing = WorkspaceStateLayout::inspect_existing(&fixture.root)?.ok_or("layout")?;
        let reopened = WorkspaceStore::open_existing(&existing)?;
        assert_eq!(
            reopened.get_agent_dag_authoring_grant(issued.id())?,
            Some(issued)
        );
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn token_principal_round_trip_gates_grant_issue_and_discovery()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = fixture("token-principal")?;
        let token_id = forge_domain::McpTokenId::from_uuid(Uuid::from_u128(0xD012));
        let http_agent = RegisteredAgentInstance::create_with_principal(
            AgentInstanceId::from_uuid(Uuid::from_u128(0xD013)),
            fixture.workspace_id,
            fixture.activity_id,
            AgentDisplayName::new("HTTP Planner".to_owned())?,
            AgentDeclaredRole::new("planner".to_owned())?,
            AgentTransportKind::StreamableHttp,
            Some(token_id),
            timestamp(6)?,
        );
        let _ = fixture.store.attach_agent(&http_agent)?;
        assert_eq!(
            fixture
                .store
                .get_agent(http_agent.id())?
                .ok_or("HTTP Agent missing")?
                .transport_principal(),
            Some(token_id)
        );
        let actor = AgentDagAuthoringActor::new(
            fixture.workspace_id,
            http_agent.id(),
            fixture.activity_id,
            AgentAuthoringCredential::Token(token_id),
        );
        let grant = AgentDagAuthoringGrant::issue(
            AgentDagAuthoringGrantId::from_uuid(Uuid::from_u128(0xD014)),
            actor,
            GoalAttribution::new(fixture.goal.id(), fixture.goal.revision()),
            DagRevisionNumber::INITIAL,
            DagHeadRevision::INITIAL,
            timestamp(10)?,
            AgentDagAuthoringGrantTtl::DEFAULT,
        )?;
        let _ = fixture.store.issue_agent_dag_authoring_grant(&grant)?;
        assert_eq!(
            fixture.store.find_active_agent_dag_authoring_grant(
                actor,
                grant.goal(),
                grant.expected_dag_revision(),
                grant.expected_head_revision(),
                timestamp(11)?,
            )?,
            Some(grant)
        );

        let other = AgentDagAuthoringActor::new(
            fixture.workspace_id,
            http_agent.id(),
            fixture.activity_id,
            AgentAuthoringCredential::Token(forge_domain::McpTokenId::from_uuid(Uuid::from_u128(
                0xD015,
            ))),
        );
        assert!(matches!(
            fixture.store.find_active_agent_dag_authoring_grant(
                other,
                GoalAttribution::new(fixture.goal.id(), fixture.goal.revision()),
                DagRevisionNumber::INITIAL,
                DagHeadRevision::INITIAL,
                timestamp(11)?,
            ),
            Err(WorkspaceStoreError::AgentDag(
                AgentDagStoreError::ActorCredentialMismatch
            ))
        ));
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn v15_to_v16_migration_adds_only_authoring_objects() -> Result<(), Box<dyn std::error::Error>>
    {
        let fixture = fixture("migration")?;
        let database = fixture.layout.database_path().clone();
        drop(fixture.store);
        let connection = Connection::open(&database)?;
        connection.execute_batch(
            "PRAGMA wal_checkpoint(TRUNCATE);
             PRAGMA journal_mode = DELETE;
             DROP TABLE agent_dag_replan_ledger;
             DROP TABLE agent_dag_authoring_grants;
             PRAGMA user_version = 15;",
        )?;
        drop(connection);
        let existing = WorkspaceStateLayout::inspect_existing(&fixture.root)?.ok_or("layout")?;
        let migrated = WorkspaceStore::open_existing(&existing)?;
        assert_eq!(migrated.health()?.schema_version(), 16);
        assert!(
            migrated
                .get_agent_dag_authoring_grant(AgentDagAuthoringGrantId::from_uuid(
                    Uuid::from_u128(0xD010)
                ),)?
                .is_none()
        );
        drop(migrated);
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn commit_replays_exact_request_and_rejects_digest_conflict()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = fixture("commit")?;
        let issued = grant(&fixture, 0xD020, 10)?;
        let _ = fixture.store.issue_agent_dag_authoring_grant(&issued)?;
        let request = make_request(
            &issued,
            successor_draft(&fixture, 0xD021, 20)?,
            0xD022,
            0xD023,
            1,
            20,
        )?;
        let committed = fixture.store.commit_agent_dag_replan(&request)?;
        assert!(!committed.receipt().replayed());
        assert_eq!(committed.revision().revision().number().get(), 2);
        let replay = fixture.store.commit_agent_dag_replan(&request)?;
        assert!(replay.receipt().replayed());
        assert_eq!(
            replay.receipt().request_id(),
            committed.receipt().request_id()
        );
        assert_eq!(replay.receipt().grant_id(), committed.receipt().grant_id());
        assert_eq!(replay.receipt().digest(), committed.receipt().digest());
        assert_eq!(
            replay.receipt().dag_revision_id(),
            committed.receipt().dag_revision_id()
        );
        assert_eq!(
            replay.receipt().dag_revision(),
            committed.receipt().dag_revision()
        );
        assert_eq!(
            replay.receipt().committed_at(),
            committed.receipt().committed_at()
        );

        let conflicting = make_request(
            &issued,
            successor_draft(&fixture, 0xD024, 20)?,
            0xD022,
            0xD023,
            1,
            20,
        )?;
        assert!(matches!(
            fixture.store.commit_agent_dag_replan(&conflicting),
            Err(WorkspaceStoreError::AgentDag(
                AgentDagStoreError::RequestIdentityConflict
            ))
        ));
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn stale_head_and_history_failure_roll_back_all_authority()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut stale = fixture("stale-head")?;
        let issued = grant(&stale, 0xD030, 10)?;
        let _ = stale.store.issue_agent_dag_authoring_grant(&issued)?;
        let draft = successor_draft(&stale, 0xD031, 20)?;
        let _ = stale.store.insert_dag_revision(
            draft.revision(),
            draft.nodes(),
            draft.lineage(),
            Some(DagHeadRevision::INITIAL),
        )?;
        let stale_request = make_request(&issued, draft, 0xD032, 0xD033, 1, 21)?;
        assert!(matches!(
            stale.store.commit_agent_dag_replan(&stale_request),
            Err(WorkspaceStoreError::AgentDag(
                AgentDagStoreError::HeadConflict
            ))
        ));
        assert_eq!(
            stale
                .store
                .get_agent_dag_authoring_grant(issued.id())?
                .map(|value| value.state()),
            Some(AgentDagAuthoringGrantState::Active)
        );
        fs::remove_dir_all(stale.root)?;

        let mut rollback = fixture("rollback")?;
        let issued = grant(&rollback, 0xD040, 10)?;
        let _ = rollback.store.issue_agent_dag_authoring_grant(&issued)?;
        let bad_request = make_request(
            &issued,
            successor_draft(&rollback, 0xD041, 20)?,
            0xD042,
            0xD043,
            2,
            20,
        )?;
        assert!(matches!(
            rollback.store.commit_agent_dag_replan(&bad_request),
            Err(WorkspaceStoreError::AgentDag(AgentDagStoreError::Agent(
                crate::AgentStoreError::WorkSequenceConflict { .. }
            )))
        ));
        assert_eq!(
            rollback
                .store
                .get_current_dag(rollback.goal.id())?
                .map(|value| value.revision().number()),
            Some(DagRevisionNumber::INITIAL)
        );
        assert_eq!(
            rollback
                .store
                .get_agent_dag_authoring_grant(issued.id())?
                .map(|value| value.state()),
            Some(AgentDagAuthoringGrantState::Active)
        );
        fs::remove_dir_all(rollback.root)?;
        Ok(())
    }

    #[test]
    fn corrupted_grant_projection_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = fixture("corrupt")?;
        let issued = grant(&fixture, 0xD050, 10)?;
        let _ = fixture.store.issue_agent_dag_authoring_grant(&issued)?;
        let database = fixture.layout.database_path().clone();
        drop(fixture.store);
        let connection = Connection::open(&database)?;
        connection.execute_batch("PRAGMA ignore_check_constraints = ON;")?;
        connection.execute(
            "UPDATE agent_dag_authoring_grants SET expires_at_ms = issued_at_ms WHERE grant_id = ?1",
            rusqlite::params![issued.id().into_uuid().as_bytes()],
        )?;
        connection.execute_batch("PRAGMA ignore_check_constraints = OFF;")?;
        drop(connection);
        let existing = WorkspaceStateLayout::inspect_existing(&fixture.root)?.ok_or("layout")?;
        let reopened = WorkspaceStore::open_existing(&existing)?;
        assert!(matches!(
            reopened.get_agent_dag_authoring_grant(issued.id()),
            Err(WorkspaceStoreError::AgentDag(
                AgentDagStoreError::CorruptRecord(_)
            ))
        ));
        drop(reopened);
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }
}
