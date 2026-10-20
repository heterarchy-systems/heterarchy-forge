//! Workspace-local schema foundation for immutable versioned Goal DAGs.

use std::collections::HashMap;

use forge_domain::{
    ActivityId, AgentSessionId, AuthenticatedPrincipal, DagAcceptanceCriterion, DagEdge,
    DagHeadRevision, DagLineageKind, DagNodeDefinition, DagNodeId, DagNodeLifecycle,
    DagNodeLineage, DagNodeObjective, DagNodeOrdinal, DagNodeRevision, DagNodeTitle, DagRevision,
    DagRevisionId, DagRevisionNumber, GoalEvidenceRef, GoalId, GoalNodeAttribution,
    GoalPublicReason, GoalRevision, GoalStatusKind, RegisteredDagNode, TimestampMillis,
    WorkspaceId,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use thiserror::Error;
use uuid::Uuid;

mod doctor;
mod schema;

pub(crate) use doctor::doctor_current;
pub use doctor::{
    DAG_DOCTOR_MAX_CURRENT_DAGS, DagDoctorFinding, DagDoctorIssue, DagDoctorNodeSummary,
    DagDoctorReport, DagDoctorState,
};

use crate::workspace_coordinators::{self, CoordinatorStoreError};
use crate::workspace_goals;
use crate::workspace_semantic_events::{
    self, SemanticEventAppend, SemanticEventKind, SemanticEventSubjects,
};

pub(crate) fn create_schema(connection: &Connection) -> Result<(), DagStoreError> {
    schema::create_schema(connection)
}

pub(crate) fn schema_objects() -> [(&'static str, &'static str); 8] {
    schema::objects()
}

pub(crate) fn validate_schema(connection: &Connection) -> Result<(), DagStoreError> {
    schema::validate_schema(connection)
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DagHead {
    goal_id: GoalId,
    dag_revision: DagRevisionNumber,
    revision: DagHeadRevision,
    updated_at: TimestampMillis,
}

impl DagHead {
    pub const fn goal_id(self) -> GoalId {
        self.goal_id
    }
    pub const fn dag_revision(self) -> DagRevisionNumber {
        self.dag_revision
    }
    pub const fn revision(self) -> DagHeadRevision {
        self.revision
    }
    pub const fn updated_at(self) -> TimestampMillis {
        self.updated_at
    }
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredDagRevision {
    revision: DagRevision,
    nodes: Vec<RegisteredDagNode>,
    lineage: Vec<DagNodeLineage>,
    evidence: Vec<DagNodeEvidenceSummary>,
    head: DagHead,
}

impl StoredDagRevision {
    pub const fn revision(&self) -> &DagRevision {
        &self.revision
    }
    pub fn nodes(&self) -> &[RegisteredDagNode] {
        &self.nodes
    }
    pub fn lineage(&self) -> &[DagNodeLineage] {
        &self.lineage
    }
    pub fn evidence(&self) -> &[DagNodeEvidenceSummary] {
        &self.evidence
    }
    pub const fn head(&self) -> DagHead {
        self.head
    }
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DagNodeEvidenceSummary {
    node_id: DagNodeId,
    count: u16,
}
impl DagNodeEvidenceSummary {
    pub const fn node_id(self) -> DagNodeId {
        self.node_id
    }
    pub const fn count(self) -> u16 {
        self.count
    }
}

pub(crate) fn insert_revision(
    connection: &mut Connection,
    revision: &DagRevision,
    nodes: &[RegisteredDagNode],
    lineage: &[DagNodeLineage],
    expected_head_revision: Option<DagHeadRevision>,
) -> Result<StoredDagRevision, DagStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let result = insert_revision_in_transaction(
        &transaction,
        revision,
        nodes,
        lineage,
        expected_head_revision,
    )?;
    transaction.commit()?;
    Ok(result)
}

/// Insert one immutable DAG revision into a caller-owned IMMEDIATE
/// transaction. This is intentionally crate-private: Coordinator planning
/// uses it to atomically fence authority, commit the DAG head and replay
/// ledger, and publish factual planning history in one transaction.
pub(crate) fn insert_revision_in_transaction(
    transaction: &Transaction<'_>,
    revision: &DagRevision,
    nodes: &[RegisteredDagNode],
    lineage: &[DagNodeLineage],
    expected_head_revision: Option<DagHeadRevision>,
) -> Result<StoredDagRevision, DagStoreError> {
    revision
        .project(nodes)
        .map_err(|_| DagStoreError::ProjectionMismatch)?;
    // Lineage is a set of typed relationships, not an ordered event stream.
    // Canonicalize it once at the persistence boundary so retries made from a
    // different caller collection order converge to the same durable result.
    let lineage = canonical_lineage(lineage);
    // Resolve an exact committed retry before checking the mutable Goal
    // projection.  A Goal lifecycle update after a DAG commit must not make
    // the same durable request non-idempotent.  The revision, node set, and
    // canonical lineage comparisons still protect identity/scope safety.
    if let Some(existing) =
        get_revision_in_transaction(transaction, revision.goal_id(), revision.number())?
    {
        if existing.revision() == revision
            && nodes_equivalent(existing.nodes(), nodes)
            && existing.lineage() == lineage
        {
            return Ok(existing);
        }
        return Err(DagStoreError::IdentityConflict);
    }
    let workspace_id = revision_workspace_id(transaction, revision.goal_id())?;
    crate::workspace_work_cuts::guards::ensure_goal_open(
        transaction,
        workspace_id,
        revision.goal_id(),
    )?;
    validate_goal_for_revision(transaction, revision)?;
    let current_head = validate_revision_preconditions(
        transaction,
        revision,
        nodes,
        &lineage,
        expected_head_revision,
    )?;
    transaction.execute(
        "INSERT INTO goal_dag_revisions (
            goal_id, dag_revision, revision_id, parent_dag_revision,
            base_goal_revision, created_at_ms, node_count, edge_count
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            revision.goal_id().into_uuid().as_bytes(),
            revision.number().get(),
            revision.id().into_uuid().as_bytes(),
            revision.parent().map(DagRevisionNumber::get),
            revision.base_goal_revision().get(),
            revision.created_at().get(),
            i64::try_from(nodes.len()).map_err(|_| DagStoreError::IntegerOverflow)?,
            i64::try_from(revision.edges().len()).map_err(|_| DagStoreError::IntegerOverflow)?,
        ],
    )?;
    for node in nodes {
        insert_node(transaction, node)?;
    }
    for edge in revision.edges() {
        transaction.execute(
            "INSERT INTO goal_dag_edges (
                goal_id, dag_revision, upstream_node_id, downstream_node_id
             ) VALUES (?1, ?2, ?3, ?4)",
            params![
                revision.goal_id().into_uuid().as_bytes(),
                revision.number().get(),
                edge.upstream().into_uuid().as_bytes(),
                edge.downstream().into_uuid().as_bytes()
            ],
        )?;
    }
    insert_lineage(transaction, revision, &lineage)?;
    copy_head_evidence_if_needed(transaction, revision, nodes, current_head)?;
    let head_revision = match current_head {
        None => {
            transaction.execute(
                "INSERT INTO goal_dag_heads (goal_id, dag_revision, head_revision, updated_at_ms)
                 VALUES (?1, ?2, 1, ?3)",
                params![
                    revision.goal_id().into_uuid().as_bytes(),
                    revision.number().get(),
                    revision.created_at().get()
                ],
            )?;
            DagHeadRevision::INITIAL
        }
        Some(head) => {
            let next = head
                .revision()
                .checked_next()
                .map_err(|_| DagStoreError::RevisionOverflow)?;
            let changed = transaction.execute(
                "UPDATE goal_dag_heads SET dag_revision = ?1, head_revision = ?2, updated_at_ms = ?3
                 WHERE goal_id = ?4 AND dag_revision = ?5 AND head_revision = ?6",
                params![revision.number().get(), next.get(), revision.created_at().get(),
                    revision.goal_id().into_uuid().as_bytes(), head.dag_revision().get(), head.revision().get()],
            )?;
            if changed != 1 {
                return Err(DagStoreError::HeadConflict);
            }
            next
        }
    };
    let result = get_revision_in_transaction(transaction, revision.goal_id(), revision.number())?
        .ok_or(DagStoreError::CorruptRecord("dag.inserted_revision"))?;
    if result.head().revision() != head_revision {
        return Err(DagStoreError::HeadConflict);
    }
    append_dag_committed_event(transaction, revision, head_revision)?;
    Ok(result)
}

/// Append the durable `dag_committed` event inside the same transaction that
/// advanced the immutable revision and its mutable head.
fn append_dag_committed_event(
    transaction: &Transaction<'_>,
    revision: &DagRevision,
    head_revision: DagHeadRevision,
) -> Result<(), DagStoreError> {
    workspace_semantic_events::append_semantic_event(
        transaction,
        &SemanticEventAppend::new(
            SemanticEventKind::DagCommitted,
            revision_workspace_id(transaction, revision.goal_id())?,
            SemanticEventSubjects {
                goal_id: Some(revision.goal_id()),
                dag_revision: Some(revision.number()),
                ..SemanticEventSubjects::NONE
            },
            head_revision.get(),
            revision.created_at(),
        ),
    )?;
    Ok(())
}

/// Resolve the Workspace identity every Goal-scoped semantic event carries.
fn revision_workspace_id(
    connection: &Connection,
    goal_id: GoalId,
) -> Result<WorkspaceId, DagStoreError> {
    let raw: Option<Vec<u8>> = connection
        .query_row(
            "SELECT workspace_id FROM goals WHERE goal_id = ?1",
            params![goal_id.into_uuid().as_bytes()],
            |row| row.get(0),
        )
        .optional()?;
    let raw = raw.ok_or(DagStoreError::GoalMissing)?;
    Ok(WorkspaceId::from_uuid(decode_uuid(
        "dag.goal_workspace_id",
        &raw,
    )?))
}

fn validate_revision_preconditions(
    connection: &Connection,
    revision: &DagRevision,
    nodes: &[RegisteredDagNode],
    lineage: &[DagNodeLineage],
    expected_head_revision: Option<DagHeadRevision>,
) -> Result<Option<DagHead>, DagStoreError> {
    let current_head = get_head(connection, revision.goal_id())?;
    validate_head_advance(revision, current_head, expected_head_revision)?;
    if let Some(head) = current_head {
        let parent =
            get_revision_in_transaction(connection, revision.goal_id(), head.dag_revision())?
                .ok_or(DagStoreError::CorruptRecord("dag.parent"))?;
        validate_replan(&parent, nodes, lineage)?;
    } else if nodes.iter().any(|node| {
        node.revision() != DagNodeRevision::INITIAL
            || node.lifecycle() != &DagNodeLifecycle::Pending
    }) {
        return Err(DagStoreError::ProjectionMismatch);
    } else if !lineage.is_empty() {
        return Err(DagStoreError::LineageConflict);
    }
    Ok(current_head)
}

fn canonical_lineage(lineage: &[DagNodeLineage]) -> Vec<DagNodeLineage> {
    let mut result = lineage.to_vec();
    result.sort_by_key(|item| (item.prior_node_id(), item.successor_node_id()));
    result
}

fn copy_head_evidence_if_needed(
    transaction: &Transaction<'_>,
    revision: &DagRevision,
    nodes: &[RegisteredDagNode],
    current_head: Option<DagHead>,
) -> Result<(), DagStoreError> {
    match current_head {
        Some(head) => {
            copy_completed_node_evidence(transaction, revision, nodes, head.dag_revision())
        }
        None => Ok(()),
    }
}

fn copy_completed_node_evidence(
    transaction: &Transaction<'_>,
    revision: &DagRevision,
    nodes: &[RegisteredDagNode],
    parent: DagRevisionNumber,
) -> Result<(), DagStoreError> {
    for node in nodes
        .iter()
        .filter(|node| node.lifecycle() == &DagNodeLifecycle::Completed)
    {
        let source_count: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM goal_dag_node_evidence_refs
              WHERE goal_id = ?1 AND dag_revision = ?2 AND node_id = ?3",
            params![
                revision.goal_id().into_uuid().as_bytes(),
                parent.get(),
                node.id().into_uuid().as_bytes()
            ],
            |row| row.get(0),
        )?;
        if source_count <= 0 {
            return Err(DagStoreError::CompletedNodeEvidenceMissing(node.id()));
        }
        let copied = transaction.execute(
            "INSERT INTO goal_dag_node_evidence_refs (
                goal_id, dag_revision, node_id, evidence_kind, evidence_id, associated_at_ms
             ) SELECT goal_id, ?1, node_id, evidence_kind, evidence_id, associated_at_ms
               FROM goal_dag_node_evidence_refs
              WHERE goal_id = ?2 AND dag_revision = ?3 AND node_id = ?4",
            params![
                revision.number().get(),
                revision.goal_id().into_uuid().as_bytes(),
                parent.get(),
                node.id().into_uuid().as_bytes()
            ],
        )?;
        if i64::try_from(copied).map_err(|_| DagStoreError::IntegerOverflow)? != source_count {
            return Err(DagStoreError::CompletedNodeEvidenceNotCopied(node.id()));
        }
    }
    Ok(())
}

fn validate_goal_for_revision(
    connection: &Connection,
    revision: &DagRevision,
) -> Result<(), DagStoreError> {
    let goal = workspace_goals::get_goal(connection, revision.goal_id())?
        .ok_or(DagStoreError::GoalMissing)?;
    if goal.revision() == revision.base_goal_revision()
        && matches!(
            goal.status().kind(),
            GoalStatusKind::Active | GoalStatusKind::Paused
        )
    {
        Ok(())
    } else {
        Err(DagStoreError::GoalConflict)
    }
}

pub(crate) fn get_current(
    connection: &Connection,
    goal_id: GoalId,
) -> Result<Option<StoredDagRevision>, DagStoreError> {
    let transaction = connection.unchecked_transaction()?;
    let result = get_current_in_transaction(&transaction, goal_id)?;
    transaction.commit()?;
    Ok(result)
}

pub(crate) fn get_current_in_transaction(
    connection: &Connection,
    goal_id: GoalId,
) -> Result<Option<StoredDagRevision>, DagStoreError> {
    let Some(head) = get_head(connection, goal_id)? else {
        return Ok(None);
    };
    get_revision_in_transaction(connection, goal_id, head.dag_revision())
}

pub(crate) fn get_revision(
    connection: &Connection,
    goal_id: GoalId,
    number: DagRevisionNumber,
) -> Result<Option<StoredDagRevision>, DagStoreError> {
    let transaction = connection.unchecked_transaction()?;
    let result = get_revision_in_transaction(&transaction, goal_id, number)?;
    transaction.commit()?;
    Ok(result)
}

pub(crate) fn start_node(
    connection: &mut Connection,
    request: DagNodeTransition,
) -> Result<RegisteredDagNode, DagStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let updated = start_node_in_transaction(&transaction, request)?;
    transaction.commit()?;
    Ok(updated)
}

/// Start a DAG node after resolving the exact attached Agent for the current
/// Activity/session/principal tuple in the same transaction as the node CAS.
/// The un-authorized [`start_node`] primitive remains available to trusted
/// internal callers and deterministic persistence tests.
pub(crate) fn start_node_authorized(
    connection: &mut Connection,
    request: DagNodeTransition,
    session_id: AgentSessionId,
    principal: AuthenticatedPrincipal,
    admitted_at: TimestampMillis,
) -> Result<RegisteredDagNode, DagStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    workspace_coordinators::ensure_live_activity_in_transaction(
        &transaction,
        request.scope.activity_id,
        request.scope.workspace_id,
        admitted_at,
    )?;
    let updated =
        start_node_authorized_in_transaction(&transaction, request, session_id, principal)?;
    transaction.commit()?;
    Ok(updated)
}

/// Start one current ready node after exact Agent authorization inside a
/// caller-owned transaction. Assignment claim uses this narrow primitive so
/// node activation, target focus, and assignment state share one commit.
pub(crate) fn start_node_authorized_in_transaction(
    transaction: &Transaction<'_>,
    request: DagNodeTransition,
    session_id: AgentSessionId,
    principal: AuthenticatedPrincipal,
) -> Result<RegisteredDagNode, DagStoreError> {
    authorize_node_transition(transaction, request.scope, session_id, principal)?;
    start_node_in_transaction(transaction, request)
}

fn start_node_in_transaction(
    transaction: &Transaction<'_>,
    request: DagNodeTransition,
) -> Result<RegisteredDagNode, DagStoreError> {
    validate_goal_revision(
        transaction,
        request.scope.workspace_id,
        request.scope.activity_id,
        request.scope.goal_id,
        request.scope.expected_goal_revision,
    )?;
    let head = get_head(transaction, request.scope.goal_id)?.ok_or(DagStoreError::HeadMissing)?;
    if head.dag_revision() != request.scope.expected_dag_revision {
        return Err(DagStoreError::HeadConflict);
    }
    let current = get_revision_in_transaction(
        transaction,
        request.scope.goal_id,
        request.scope.expected_dag_revision,
    )?
    .ok_or(DagStoreError::HeadMissing)?;
    crate::workspace_work_cuts::guards::ensure_node_open(
        transaction,
        request.scope.workspace_id,
        request.scope.goal_id,
        request.scope.expected_dag_revision,
        request.node_id,
    )?;
    let updated = current.revision().start_node(
        current.nodes(),
        request.node_id,
        request.expected_node_revision,
        request.observed_at,
    )?;
    persist_node_transition(transaction, &updated, request.expected_node_revision)?;
    Ok(updated)
}

pub(crate) fn complete_node(
    connection: &mut Connection,
    request: DagNodeTransition,
) -> Result<RegisteredDagNode, DagStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let completed = complete_node_in_transaction(&transaction, request)?;
    transaction.commit()?;
    Ok(completed)
}

/// Complete a DAG node after resolving the exact attached Agent for the
/// current Activity/session/principal tuple in the same transaction as the
/// node CAS. The transition itself does not require Agent focus; source-write
/// authority remains a separate focus/lease contract.
pub(crate) fn complete_node_authorized(
    connection: &mut Connection,
    request: DagNodeTransition,
    session_id: AgentSessionId,
    principal: AuthenticatedPrincipal,
    admitted_at: TimestampMillis,
) -> Result<RegisteredDagNode, DagStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    workspace_coordinators::ensure_live_activity_in_transaction(
        &transaction,
        request.scope.activity_id,
        request.scope.workspace_id,
        admitted_at,
    )?;
    authorize_node_transition(&transaction, request.scope, session_id, principal)?;
    let completed = complete_node_in_transaction(&transaction, request)?;
    transaction.commit()?;
    Ok(completed)
}

fn complete_node_in_transaction(
    transaction: &Transaction<'_>,
    request: DagNodeTransition,
) -> Result<RegisteredDagNode, DagStoreError> {
    validate_goal_revision(
        transaction,
        request.scope.workspace_id,
        request.scope.activity_id,
        request.scope.goal_id,
        request.scope.expected_goal_revision,
    )?;
    let head = get_head(transaction, request.scope.goal_id)?.ok_or(DagStoreError::HeadMissing)?;
    if head.dag_revision() != request.scope.expected_dag_revision {
        return Err(DagStoreError::HeadConflict);
    }
    let current = get_revision_in_transaction(
        transaction,
        request.scope.goal_id,
        request.scope.expected_dag_revision,
    )?
    .and_then(|stored| {
        stored
            .nodes()
            .iter()
            .find(|node| node.id() == request.node_id)
            .cloned()
    })
    .ok_or(DagStoreError::NodeMissing)?;
    let completed = current.complete(request.expected_node_revision, request.observed_at)?;
    persist_node_transition(transaction, &completed, request.expected_node_revision)?;
    Ok(completed)
}

/// Resolve one and only one current Activity attachment for the supplied
/// logical session, then compare its immutable principal and attachment state.
/// The partial unique index on `(activity_id, session_id)` is the durable
/// primary fence; `LIMIT 2` also fails closed if a damaged database bypassed
/// that index.
fn authorize_node_transition(
    connection: &Connection,
    scope: DagTransitionScope,
    session_id: AgentSessionId,
    principal: AuthenticatedPrincipal,
) -> Result<(), DagStoreError> {
    let mut statement = connection.prepare(
        "SELECT workspace_id, activity_id, principal_kind, principal_id, attachment_state
         FROM agent_instances
         WHERE activity_id = ?1 AND session_id = ?2
         LIMIT 2",
    )?;
    let mut rows = statement.query(params![
        scope.activity_id.into_uuid().as_bytes(),
        session_id.into_uuid().as_bytes(),
    ])?;
    let (workspace_id, activity_id, principal_kind, principal_id, attachment_state) = {
        let Some(row) = rows.next()? else {
            return Err(DagStoreError::AgentAuthorizationConflict);
        };
        (
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, Option<Vec<u8>>>(3)?,
            row.get::<_, i64>(4)?,
        )
    };
    if rows.next()?.is_some() {
        return Err(DagStoreError::AgentAuthorizationConflict);
    }
    let (expected_principal_kind, expected_principal_id) = encode_principal(principal);
    if workspace_id.as_slice() != scope.workspace_id.into_uuid().as_bytes()
        || activity_id.as_slice() != scope.activity_id.into_uuid().as_bytes()
        || principal_kind != expected_principal_kind
        || principal_id != expected_principal_id
        || attachment_state != 0
    {
        return Err(DagStoreError::AgentAuthorizationConflict);
    }
    Ok(())
}

fn encode_principal(value: AuthenticatedPrincipal) -> (i64, Option<Vec<u8>>) {
    match value {
        AuthenticatedPrincipal::TrustedStdio => (0, None),
        AuthenticatedPrincipal::DirectToken(id) => (1, Some(id.into_uuid().into_bytes().to_vec())),
        AuthenticatedPrincipal::OAuthGrant(id) => (2, Some(id.into_uuid().into_bytes().to_vec())),
    }
}

fn validate_goal_revision(
    connection: &Connection,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    goal_id: GoalId,
    expected_goal_revision: GoalRevision,
) -> Result<(), DagStoreError> {
    let goal = workspace_goals::get_goal(connection, goal_id)?.ok_or(DagStoreError::GoalMissing)?;
    if goal.workspace_id() == workspace_id
        && goal.activity_id() == activity_id
        && goal.revision() == expected_goal_revision
        && matches!(
            goal.status().kind(),
            GoalStatusKind::Active | GoalStatusKind::Paused
        )
    {
        Ok(())
    } else {
        Err(DagStoreError::GoalConflict)
    }
}

#[cfg(test)]
pub(crate) fn update_node(
    connection: &mut Connection,
    requested: &RegisteredDagNode,
    expected_revision: DagNodeRevision,
) -> Result<RegisteredDagNode, DagStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let updated = update_node_in_transaction(&transaction, requested, expected_revision)?;
    transaction.commit()?;
    Ok(updated)
}

/// Apply the independently reachable control-plane DAG update only while the
/// owning Activity lease is live. The exact replay path is fenced by the same
/// transaction before it can return the prior node projection.
pub(crate) fn update_node_authorized(
    connection: &mut Connection,
    requested: &RegisteredDagNode,
    expected_revision: DagNodeRevision,
    admitted_at: TimestampMillis,
) -> Result<RegisteredDagNode, DagStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let goal = workspace_goals::get_goal(&transaction, requested.goal_id())?
        .ok_or(DagStoreError::GoalMissing)?;
    workspace_coordinators::ensure_live_activity_in_transaction(
        &transaction,
        goal.activity_id(),
        goal.workspace_id(),
        admitted_at,
    )?;
    let updated = update_node_in_transaction(&transaction, requested, expected_revision)?;
    transaction.commit()?;
    Ok(updated)
}

fn update_node_in_transaction(
    transaction: &Transaction<'_>,
    requested: &RegisteredDagNode,
    expected_revision: DagNodeRevision,
) -> Result<RegisteredDagNode, DagStoreError> {
    let head = get_head(transaction, requested.goal_id())?.ok_or(DagStoreError::HeadMissing)?;
    if head.dag_revision() != requested.dag_revision() {
        return Err(DagStoreError::HistoricalRevisionImmutable);
    }
    let current =
        get_revision_in_transaction(transaction, requested.goal_id(), requested.dag_revision())?
            .and_then(|stored| {
                stored
                    .nodes()
                    .iter()
                    .find(|node| node.id() == requested.id())
                    .cloned()
            })
            .ok_or(DagStoreError::NodeMissing)?;
    if current == *requested {
        let expected_next = expected_revision
            .checked_next()
            .map_err(|_| DagStoreError::RevisionOverflow)?;
        if requested.revision() == expected_next {
            return Ok(current);
        }
        return Err(DagStoreError::NodeConflict);
    }
    if current.definition() != requested.definition() || current.revision() != expected_revision {
        return Err(DagStoreError::NodeConflict);
    }
    let expected = expected_node_projection(&current, requested, expected_revision)?;
    if expected != *requested {
        return Err(DagStoreError::NodeConflict);
    }
    persist_node_transition(transaction, requested, expected_revision)?;
    Ok(requested.clone())
}

pub(crate) fn current_head_all_completed(
    connection: &Connection,
    goal_id: GoalId,
) -> Result<Option<bool>, rusqlite::Error> {
    connection
        .query_row(
            "SELECT r.node_count,
                (SELECT COUNT(*) FROM goal_dag_nodes AS n
                 WHERE n.goal_id = h.goal_id AND n.dag_revision = h.dag_revision
                   AND n.lifecycle_state = 3)
         FROM goal_dag_heads AS h
         JOIN goal_dag_revisions AS r
           ON r.goal_id = h.goal_id AND r.dag_revision = h.dag_revision
         WHERE h.goal_id = ?1",
            params![goal_id.into_uuid().as_bytes()],
            |row| {
                let total: i64 = row.get(0)?;
                let completed: i64 = row.get(1)?;
                Ok(total > 0 && total == completed)
            },
        )
        .optional()
}

pub(crate) fn associate_node_evidence_in_transaction(
    transaction: &Transaction<'_>,
    attribution: Option<GoalNodeAttribution>,
    evidence: GoalEvidenceRef,
    associated_at: TimestampMillis,
) -> Result<(), DagStoreError> {
    let Some(attribution) = attribution else {
        return Ok(());
    };
    let head = get_head(transaction, attribution.goal_id())?.ok_or(DagStoreError::HeadMissing)?;
    if head.dag_revision() != attribution.dag_revision() {
        return Err(DagStoreError::HeadConflict);
    }
    let goal = workspace_goals::get_goal(transaction, attribution.goal_id())?
        .ok_or(DagStoreError::GoalMissing)?;
    if goal.revision() != attribution.expected_goal_revision() {
        return Err(DagStoreError::GoalConflict);
    }
    let node: Option<(i64, i64)> = transaction
        .query_row(
            "SELECT lifecycle_state, node_revision FROM goal_dag_nodes
         WHERE goal_id = ?1 AND dag_revision = ?2 AND node_id = ?3",
            params![
                attribution.goal_id().into_uuid().as_bytes(),
                attribution.dag_revision().get(),
                attribution.node_id().into_uuid().as_bytes()
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if node != Some((1, attribution.expected_node_revision().get())) {
        return Err(DagStoreError::NodeConflict);
    }
    let (kind, id) = workspace_goals::encode_evidence(evidence);
    let linked: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM goal_evidence_refs
         WHERE goal_id = ?1 AND evidence_kind = ?2 AND evidence_id = ?3)",
        params![
            attribution.goal_id().into_uuid().as_bytes(),
            kind,
            id.as_slice()
        ],
        |row| row.get(0),
    )?;
    if !linked {
        return Err(DagStoreError::GoalEvidenceMissing);
    }
    transaction.execute(
        "INSERT INTO goal_dag_node_evidence_refs (
            goal_id, dag_revision, node_id, evidence_kind, evidence_id, associated_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(goal_id, dag_revision, node_id, evidence_kind, evidence_id) DO NOTHING",
        params![
            attribution.goal_id().into_uuid().as_bytes(),
            attribution.dag_revision().get(),
            attribution.node_id().into_uuid().as_bytes(),
            kind,
            id.as_slice(),
            associated_at.get()
        ],
    )?;
    Ok(())
}

fn expected_node_projection(
    current: &RegisteredDagNode,
    requested: &RegisteredDagNode,
    expected_revision: DagNodeRevision,
) -> Result<RegisteredDagNode, DagStoreError> {
    let observed_at = requested.updated_at();
    match requested.lifecycle() {
        DagNodeLifecycle::Pending => Err(DagStoreError::NodeConflict),
        DagNodeLifecycle::Active => current
            .resume(expected_revision, observed_at)
            .map_err(Into::into),
        DagNodeLifecycle::Blocked(reason) => current
            .block(expected_revision, reason.clone(), observed_at)
            .map_err(Into::into),
        DagNodeLifecycle::Completed => current
            .complete(expected_revision, observed_at)
            .map_err(Into::into),
        DagNodeLifecycle::Failed(reason) => current
            .fail(expected_revision, reason.clone(), observed_at)
            .map_err(Into::into),
        DagNodeLifecycle::Skipped(reason) => current
            .skip(expected_revision, reason.clone(), observed_at)
            .map_err(Into::into),
        DagNodeLifecycle::Cancelled => current
            .cancel(expected_revision, observed_at)
            .map_err(Into::into),
    }
}

fn persist_node_transition(
    transaction: &Transaction<'_>,
    node: &RegisteredDagNode,
    expected_revision: DagNodeRevision,
) -> Result<(), DagStoreError> {
    let (state, reason) = encode_lifecycle(node.lifecycle());
    let changed = transaction.execute(
        "UPDATE goal_dag_nodes SET lifecycle_state = ?1, reason_text = ?2,
                updated_at_ms = ?3, node_revision = ?4
         WHERE goal_id = ?5 AND dag_revision = ?6 AND node_id = ?7 AND node_revision = ?8",
        params![
            state,
            reason,
            node.updated_at().get(),
            node.revision().get(),
            node.goal_id().into_uuid().as_bytes(),
            node.dag_revision().get(),
            node.id().into_uuid().as_bytes(),
            expected_revision.get()
        ],
    )?;
    if changed != 1 {
        return Err(DagStoreError::NodeConflict);
    }
    workspace_semantic_events::append_semantic_event(
        transaction,
        &SemanticEventAppend::new(
            SemanticEventKind::NodeTransition,
            revision_workspace_id(transaction, node.goal_id())?,
            SemanticEventSubjects {
                goal_id: Some(node.goal_id()),
                dag_revision: Some(node.dag_revision()),
                node_id: Some(node.id()),
                ..SemanticEventSubjects::NONE
            },
            node.revision().get(),
            node.updated_at(),
        ),
    )?;
    Ok(())
}

type RawRevisionRow = (Vec<u8>, i64, Option<i64>, i64, i64, i64, i64);

pub(crate) fn get_revision_in_transaction(
    connection: &Connection,
    goal_id: GoalId,
    number: DagRevisionNumber,
) -> Result<Option<StoredDagRevision>, DagStoreError> {
    let raw = query_raw_revision(connection, goal_id, number)?;
    let Some((
        revision_id,
        revision_number,
        parent,
        base_goal_revision,
        created_at,
        node_count,
        edge_count,
    )) = raw
    else {
        return Ok(None);
    };
    let mut acceptance = load_acceptance(connection, goal_id, number)?;
    let mut statement = connection.prepare(
        "SELECT node_id, ordinal, title, objective, lifecycle_state, reason_text,
                created_at_ms, updated_at_ms, node_revision
         FROM goal_dag_nodes WHERE goal_id = ?1 AND dag_revision = ?2 ORDER BY ordinal, node_id",
    )?;
    let rows = statement.query_map(
        params![goal_id.into_uuid().as_bytes(), number.get()],
        |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, i64>(8)?,
            ))
        },
    )?;
    let mut definitions = Vec::new();
    let mut nodes = Vec::new();
    for row in rows {
        let (id, ordinal, title, objective, state, reason, node_created, updated, node_revision) =
            row?;
        let id = DagNodeId::from_uuid(decode_uuid("dag.node_id", &id)?);
        let criteria = acceptance
            .remove(&id)
            .ok_or(DagStoreError::CorruptRecord("dag.acceptance"))?;
        let definition = DagNodeDefinition::new(
            id,
            DagNodeOrdinal::new(decode_u16("dag.ordinal", ordinal)?)?,
            DagNodeTitle::new(title)?,
            DagNodeObjective::new(objective)?,
            criteria,
        )?;
        let node = RegisteredDagNode::from_parts(
            goal_id,
            number,
            definition.clone(),
            decode_lifecycle(state, reason)?,
            decode_timestamp("dag.node_created", node_created)?,
            decode_timestamp("dag.node_updated", updated)?,
            DagNodeRevision::new(node_revision)
                .map_err(|_| DagStoreError::CorruptRecord("dag.node_revision"))?,
        )?;
        definitions.push(definition);
        nodes.push(node);
    }
    if !acceptance.is_empty() || usize::try_from(node_count).ok() != Some(nodes.len()) {
        return Err(DagStoreError::CorruptRecord("dag.node_count"));
    }
    let edges = load_edges(connection, goal_id, number)?;
    if usize::try_from(edge_count).ok() != Some(edges.len()) {
        return Err(DagStoreError::CorruptRecord("dag.edge_count"));
    }
    let revision = DagRevision::new(
        DagRevisionId::from_uuid(decode_uuid("dag.revision_id", &revision_id)?),
        goal_id,
        forge_domain::GoalRevision::new(base_goal_revision)
            .map_err(|_| DagStoreError::CorruptRecord("dag.base_goal_revision"))?,
        DagRevisionNumber::new(revision_number)
            .map_err(|_| DagStoreError::CorruptRecord("dag.revision"))?,
        parent
            .map(DagRevisionNumber::new)
            .transpose()
            .map_err(|_| DagStoreError::CorruptRecord("dag.parent"))?,
        definitions,
        edges,
        decode_timestamp("dag.created_at", created_at)?,
    )?;
    let lineage = load_lineage(connection, goal_id, number)?;
    let evidence = load_evidence_summaries(connection, goal_id, number)?;
    let head = get_head(connection, goal_id)?.ok_or(DagStoreError::CorruptRecord("dag.head"))?;
    Ok(Some(StoredDagRevision {
        revision,
        nodes,
        lineage,
        evidence,
        head,
    }))
}

fn query_raw_revision(
    connection: &Connection,
    goal_id: GoalId,
    number: DagRevisionNumber,
) -> Result<Option<RawRevisionRow>, DagStoreError> {
    connection
        .query_row(
            "SELECT revision_id, dag_revision, parent_dag_revision, base_goal_revision,
                    created_at_ms, node_count, edge_count
             FROM goal_dag_revisions WHERE goal_id = ?1 AND dag_revision = ?2",
            params![goal_id.into_uuid().as_bytes(), number.get()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .optional()
        .map_err(DagStoreError::from)
}

fn validate_head_advance(
    revision: &DagRevision,
    current: Option<DagHead>,
    expected: Option<DagHeadRevision>,
) -> Result<(), DagStoreError> {
    match (current, expected) {
        (None, None) if revision.number() == DagRevisionNumber::INITIAL => Ok(()),
        (Some(head), Some(expected))
            if head.revision() == expected
                && revision.parent() == Some(head.dag_revision())
                && revision.number().get() == head.dag_revision().get() + 1 =>
        {
            Ok(())
        }
        _ => Err(DagStoreError::HeadConflict),
    }
}

fn validate_replan(
    parent: &StoredDagRevision,
    next: &[RegisteredDagNode],
    lineage: &[DagNodeLineage],
) -> Result<(), DagStoreError> {
    let next_by_id = next
        .iter()
        .map(|node| (node.id(), node))
        .collect::<HashMap<_, _>>();
    for prior in parent.nodes() {
        if prior.lifecycle() == &DagNodeLifecycle::Completed {
            let carried = next_by_id
                .get(&prior.id())
                .ok_or(DagStoreError::CompletedNodeDropped(prior.id()))?;
            if carried.definition() != prior.definition()
                || carried.lifecycle() != prior.lifecycle()
                || carried.created_at() != prior.created_at()
                || carried.updated_at() != prior.updated_at()
                || carried.revision() != prior.revision()
            {
                return Err(DagStoreError::CompletedNodeChanged(prior.id()));
            }
        }
    }
    for node in next {
        match node.lifecycle() {
            DagNodeLifecycle::Completed => {
                let Some(prior) = parent.nodes().iter().find(|prior| prior.id() == node.id())
                else {
                    return Err(DagStoreError::CompletedNodeNotCarried(node.id()));
                };
                if prior.lifecycle() != &DagNodeLifecycle::Completed {
                    return Err(DagStoreError::CompletedNodeChanged(node.id()));
                }
                let evidence_count = parent
                    .evidence()
                    .iter()
                    .find(|summary| summary.node_id() == prior.id())
                    .map_or(0, |summary| summary.count());
                if evidence_count == 0 {
                    return Err(DagStoreError::CompletedNodeEvidenceMissing(node.id()));
                }
            }
            DagNodeLifecycle::Pending
                if node.revision() == DagNodeRevision::INITIAL
                    && node.created_at() == node.updated_at() => {}
            _ => return Err(DagStoreError::ProjectionMismatch),
        }
    }
    validate_lineage(parent, &next_by_id, lineage)
}

fn validate_lineage(
    parent: &StoredDagRevision,
    next: &HashMap<DagNodeId, &RegisteredDagNode>,
    lineage: &[DagNodeLineage],
) -> Result<(), DagStoreError> {
    let parent_ids = parent
        .nodes()
        .iter()
        .map(RegisteredDagNode::id)
        .collect::<std::collections::HashSet<_>>();
    let mut unique = std::collections::HashSet::new();
    let mut prior_counts = HashMap::<DagNodeId, usize>::new();
    let mut successor_counts = HashMap::<DagNodeId, usize>::new();
    for item in lineage {
        if item.prior_node_id() == item.successor_node_id()
            || !parent_ids.contains(&item.prior_node_id())
            || !next.contains_key(&item.successor_node_id())
            || next.contains_key(&item.prior_node_id())
            || !unique.insert((item.prior_node_id(), item.successor_node_id()))
        {
            return Err(DagStoreError::LineageConflict);
        }
        *prior_counts.entry(item.prior_node_id()).or_default() += 1;
        *successor_counts
            .entry(item.successor_node_id())
            .or_default() += 1;
    }
    for prior in parent
        .nodes()
        .iter()
        .filter(|node| !next.contains_key(&node.id()))
    {
        if !prior_counts.contains_key(&prior.id()) {
            return Err(DagStoreError::LineageMissing(prior.id()));
        }
    }
    for item in lineage {
        let expected = if prior_counts[&item.prior_node_id()] > 1 {
            DagLineageKind::Split
        } else if successor_counts[&item.successor_node_id()] > 1 {
            DagLineageKind::Merge
        } else {
            DagLineageKind::Replace
        };
        if item.kind() != expected {
            return Err(DagStoreError::LineageConflict);
        }
    }
    Ok(())
}

fn nodes_equivalent(left: &[RegisteredDagNode], right: &[RegisteredDagNode]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let right = right
        .iter()
        .map(|node| (node.id(), node))
        .collect::<HashMap<_, _>>();
    left.iter()
        .all(|node| right.get(&node.id()).is_some_and(|other| **other == *node))
}

fn insert_node(
    transaction: &Transaction<'_>,
    node: &RegisteredDagNode,
) -> Result<(), DagStoreError> {
    let (state, reason) = encode_lifecycle(node.lifecycle());
    transaction.execute(
        "INSERT INTO goal_dag_nodes (
            goal_id, dag_revision, node_id, ordinal, title, objective,
            lifecycle_state, reason_text, created_at_ms, updated_at_ms, node_revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            node.goal_id().into_uuid().as_bytes(),
            node.dag_revision().get(),
            node.id().into_uuid().as_bytes(),
            i64::from(node.definition().ordinal().get()),
            node.definition().title().as_str(),
            node.definition().objective().as_str(),
            state,
            reason,
            node.created_at().get(),
            node.updated_at().get(),
            node.revision().get()
        ],
    )?;
    for (ordinal, criterion) in node.definition().acceptance().iter().enumerate() {
        transaction.execute(
            "INSERT INTO goal_dag_node_acceptance (goal_id, dag_revision, node_id, ordinal, criterion)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![node.goal_id().into_uuid().as_bytes(), node.dag_revision().get(), node.id().into_uuid().as_bytes(),
                i64::try_from(ordinal).map_err(|_| DagStoreError::IntegerOverflow)?, criterion.as_str()],
        )?;
    }
    Ok(())
}

fn insert_lineage(
    transaction: &Transaction<'_>,
    revision: &DagRevision,
    lineage: &[DagNodeLineage],
) -> Result<(), DagStoreError> {
    let parent = revision.parent();
    if lineage.is_empty() {
        return Ok(());
    }
    let parent = parent.ok_or(DagStoreError::LineageConflict)?;
    for item in lineage {
        transaction.execute(
            "INSERT INTO goal_dag_node_lineage (
                goal_id, new_dag_revision, parent_dag_revision,
                prior_node_id, successor_node_id, lineage_kind
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                revision.goal_id().into_uuid().as_bytes(),
                revision.number().get(),
                parent.get(),
                item.prior_node_id().into_uuid().as_bytes(),
                item.successor_node_id().into_uuid().as_bytes(),
                encode_lineage_kind(item.kind())
            ],
        )?;
    }
    Ok(())
}

fn load_lineage(
    connection: &Connection,
    goal_id: GoalId,
    number: DagRevisionNumber,
) -> Result<Vec<DagNodeLineage>, DagStoreError> {
    let mut statement = connection.prepare(
        "SELECT prior_node_id, successor_node_id, lineage_kind FROM goal_dag_node_lineage
         WHERE goal_id = ?1 AND new_dag_revision = ?2
         ORDER BY prior_node_id, successor_node_id",
    )?;
    statement
        .query_map(
            params![goal_id.into_uuid().as_bytes(), number.get()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )?
        .map(|row| {
            let (prior, successor, kind) = row?;
            Ok(DagNodeLineage::new(
                DagNodeId::from_uuid(decode_uuid("dag.lineage_prior", &prior)?),
                DagNodeId::from_uuid(decode_uuid("dag.lineage_successor", &successor)?),
                decode_lineage_kind(kind)?,
            ))
        })
        .collect()
}

fn load_evidence_summaries(
    connection: &Connection,
    goal_id: GoalId,
    number: DagRevisionNumber,
) -> Result<Vec<DagNodeEvidenceSummary>, DagStoreError> {
    let mut statement = connection.prepare(
        "SELECT node_id, COUNT(*) FROM goal_dag_node_evidence_refs
         WHERE goal_id = ?1 AND dag_revision = ?2 GROUP BY node_id ORDER BY node_id",
    )?;
    statement
        .query_map(
            params![goal_id.into_uuid().as_bytes(), number.get()],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
        )?
        .map(|row| {
            let (id, count) = row?;
            Ok(DagNodeEvidenceSummary {
                node_id: DagNodeId::from_uuid(decode_uuid("dag.evidence_node", &id)?),
                count: u16::try_from(count)
                    .map_err(|_| DagStoreError::CorruptRecord("dag.evidence_count"))?,
            })
        })
        .collect()
}

const fn encode_lineage_kind(kind: DagLineageKind) -> i64 {
    match kind {
        DagLineageKind::Split => 0,
        DagLineageKind::Replace => 1,
        DagLineageKind::Merge => 2,
    }
}
fn decode_lineage_kind(value: i64) -> Result<DagLineageKind, DagStoreError> {
    match value {
        0 => Ok(DagLineageKind::Split),
        1 => Ok(DagLineageKind::Replace),
        2 => Ok(DagLineageKind::Merge),
        _ => Err(DagStoreError::CorruptRecord("dag.lineage_kind")),
    }
}

fn load_acceptance(
    connection: &Connection,
    goal_id: GoalId,
    number: DagRevisionNumber,
) -> Result<HashMap<DagNodeId, Vec<DagAcceptanceCriterion>>, DagStoreError> {
    let mut statement = connection.prepare(
        "SELECT node_id, ordinal, criterion FROM goal_dag_node_acceptance
         WHERE goal_id = ?1 AND dag_revision = ?2 ORDER BY node_id, ordinal",
    )?;
    let rows = statement.query_map(
        params![goal_id.into_uuid().as_bytes(), number.get()],
        |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
            ))
        },
    )?;
    let mut result = HashMap::<DagNodeId, Vec<DagAcceptanceCriterion>>::new();
    for row in rows {
        let (id, ordinal, criterion) = row?;
        let id = DagNodeId::from_uuid(decode_uuid("dag.acceptance_node", &id)?);
        let entries = result.entry(id).or_default();
        if usize::try_from(ordinal).ok() != Some(entries.len()) {
            return Err(DagStoreError::CorruptRecord("dag.acceptance_ordinal"));
        }
        entries.push(DagAcceptanceCriterion::new(criterion)?);
    }
    Ok(result)
}

fn load_edges(
    connection: &Connection,
    goal_id: GoalId,
    number: DagRevisionNumber,
) -> Result<Vec<DagEdge>, DagStoreError> {
    let mut statement = connection.prepare(
        "SELECT upstream_node_id, downstream_node_id FROM goal_dag_edges
         WHERE goal_id = ?1 AND dag_revision = ?2 ORDER BY upstream_node_id, downstream_node_id",
    )?;
    statement
        .query_map(
            params![goal_id.into_uuid().as_bytes(), number.get()],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )?
        .map(|row| {
            let (upstream, downstream) = row?;
            Ok(DagEdge::new(
                DagNodeId::from_uuid(decode_uuid("dag.edge_upstream", &upstream)?),
                DagNodeId::from_uuid(decode_uuid("dag.edge_downstream", &downstream)?),
            ))
        })
        .collect()
}

fn get_head(connection: &Connection, goal_id: GoalId) -> Result<Option<DagHead>, DagStoreError> {
    connection.query_row(
        "SELECT dag_revision, head_revision, updated_at_ms FROM goal_dag_heads WHERE goal_id = ?1",
        params![goal_id.into_uuid().as_bytes()],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?)),
    ).optional()?.map(|(dag_revision, revision, updated_at)| {
        Ok(DagHead { goal_id,
            dag_revision: DagRevisionNumber::new(dag_revision).map_err(|_| DagStoreError::CorruptRecord("dag.head_revision_number"))?,
            revision: DagHeadRevision::new(revision).map_err(|_| DagStoreError::CorruptRecord("dag.head_revision"))?,
            updated_at: decode_timestamp("dag.head_updated", updated_at)? })
    }).transpose()
}

fn encode_lifecycle(value: &DagNodeLifecycle) -> (i64, Option<&str>) {
    match value {
        DagNodeLifecycle::Pending => (0, None),
        DagNodeLifecycle::Active => (1, None),
        DagNodeLifecycle::Blocked(reason) => (2, Some(reason.as_str())),
        DagNodeLifecycle::Completed => (3, None),
        DagNodeLifecycle::Failed(reason) => (4, Some(reason.as_str())),
        DagNodeLifecycle::Skipped(reason) => (5, Some(reason.as_str())),
        DagNodeLifecycle::Cancelled => (6, None),
    }
}

fn decode_lifecycle(state: i64, reason: Option<String>) -> Result<DagNodeLifecycle, DagStoreError> {
    match (state, reason) {
        (0, None) => Ok(DagNodeLifecycle::Pending),
        (1, None) => Ok(DagNodeLifecycle::Active),
        (2, Some(reason)) => Ok(DagNodeLifecycle::Blocked(GoalPublicReason::new(reason)?)),
        (3, None) => Ok(DagNodeLifecycle::Completed),
        (4, Some(reason)) => Ok(DagNodeLifecycle::Failed(GoalPublicReason::new(reason)?)),
        (5, Some(reason)) => Ok(DagNodeLifecycle::Skipped(GoalPublicReason::new(reason)?)),
        (6, None) => Ok(DagNodeLifecycle::Cancelled),
        _ => Err(DagStoreError::CorruptRecord("dag.lifecycle")),
    }
}

fn decode_uuid(field: &'static str, value: &[u8]) -> Result<Uuid, DagStoreError> {
    Uuid::from_slice(value).map_err(|_| DagStoreError::CorruptRecord(field))
}
fn decode_u16(field: &'static str, value: i64) -> Result<u16, DagStoreError> {
    u16::try_from(value).map_err(|_| DagStoreError::CorruptRecord(field))
}
fn decode_timestamp(field: &'static str, value: i64) -> Result<TimestampMillis, DagStoreError> {
    TimestampMillis::new(value).map_err(|_| DagStoreError::CorruptRecord(field))
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DagTransitionScope {
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    goal_id: GoalId,
    expected_goal_revision: GoalRevision,
    expected_dag_revision: DagRevisionNumber,
}

impl DagTransitionScope {
    pub const fn new(
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        goal_id: GoalId,
        expected_goal_revision: GoalRevision,
        expected_dag_revision: DagRevisionNumber,
    ) -> Self {
        Self {
            workspace_id,
            activity_id,
            goal_id,
            expected_goal_revision,
            expected_dag_revision,
        }
    }
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DagNodeTransition {
    scope: DagTransitionScope,
    node_id: DagNodeId,
    expected_node_revision: DagNodeRevision,
    observed_at: TimestampMillis,
}

impl DagNodeTransition {
    pub const fn new(
        scope: DagTransitionScope,
        node_id: DagNodeId,
        expected_node_revision: DagNodeRevision,
        observed_at: TimestampMillis,
    ) -> Self {
        Self {
            scope,
            node_id,
            expected_node_revision,
            observed_at,
        }
    }
}

#[derive(Debug, Error)]
pub enum DagStoreError {
    #[error(transparent)]
    WorkCut(#[from] Box<crate::WorkCutError>),
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    SemanticEvents(#[from] crate::SemanticEventError),
    #[error(transparent)]
    Goal(#[from] crate::GoalStoreError),
    #[error(transparent)]
    Coordinator(#[from] CoordinatorStoreError),
    #[error(transparent)]
    Structure(#[from] forge_domain::DagStructureError),
    #[error(transparent)]
    Text(#[from] forge_domain::DagTextError),
    #[error(transparent)]
    Bound(#[from] forge_domain::DagBoundError),
    #[error(transparent)]
    Transition(#[from] forge_domain::DagNodeTransitionError),
    #[error(transparent)]
    Reason(#[from] forge_domain::GoalTextError),
    #[error("DAG schema object is damaged: {0}")]
    DamagedSchema(&'static str),
    #[error("DAG Goal is missing")]
    GoalMissing,
    #[error("DAG Goal revision or lifecycle conflicts")]
    GoalConflict,
    #[error("DAG node transition Agent session is not an attached authorized Agent")]
    AgentAuthorizationConflict,
    #[error("DAG identity conflicts with durable state")]
    IdentityConflict,
    #[error("DAG head revision is stale")]
    HeadConflict,
    #[error("DAG node projection does not match the revision")]
    ProjectionMismatch,
    #[error("completed DAG node {0} was dropped by replanning")]
    CompletedNodeDropped(DagNodeId),
    #[error("completed DAG node {0} changed during replanning")]
    CompletedNodeChanged(DagNodeId),
    #[error("new DAG node {0} cannot be marked completed without a completed parent carry")]
    CompletedNodeNotCarried(DagNodeId),
    #[error("completed DAG node {0} has no durable evidence to carry")]
    CompletedNodeEvidenceMissing(DagNodeId),
    #[error("completed DAG node {0} evidence was not copied exactly")]
    CompletedNodeEvidenceNotCopied(DagNodeId),
    #[error("DAG revision overflowed")]
    RevisionOverflow,
    #[error("DAG integer exceeds SQLite range")]
    IntegerOverflow,
    #[error("corrupt DAG record field {0}")]
    CorruptRecord(&'static str),
    #[error("DAG head is missing")]
    HeadMissing,
    #[error("DAG node is missing")]
    NodeMissing,
    #[error("DAG node revision or lifecycle conflicts")]
    NodeConflict,
    #[error("historical DAG revisions are immutable")]
    HistoricalRevisionImmutable,
    #[error("DAG replan lineage conflicts with parent or successor nodes")]
    LineageConflict,
    #[error("DAG replan omitted node {0} without lineage")]
    LineageMissing(DagNodeId),
    #[error("Goal evidence is missing before DAG node association")]
    GoalEvidenceMissing,
}

impl From<crate::WorkCutError> for DagStoreError {
    fn from(error: crate::WorkCutError) -> Self {
        Self::WorkCut(Box::new(error))
    }
}

#[cfg(test)]
mod tests;
