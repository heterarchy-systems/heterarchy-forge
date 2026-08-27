//! Bounded, read-only semantic Doctor for current durable DAG heads.

use std::collections::HashMap;

use forge_domain::{
    DagAcceptanceCriterion, DagEdge, DagHeadRevision, DagNodeDefinition, DagNodeId,
    DagNodeLifecycle, DagNodeObjective, DagNodeOrdinal, DagNodeProjection, DagNodeRevision,
    DagNodeStatus, DagNodeTitle, DagRevision, DagRevisionId, DagRevisionNumber, GoalId,
    GoalRevision, MAX_DAG_EDGES, MAX_DAG_NODES, RegisteredDagNode, TimestampMillis,
};
use rusqlite::{Connection, params};

use super::{DagStoreError, decode_lifecycle, decode_timestamp, decode_u16, decode_uuid};

/// Maximum current Goal DAGs inspected by one Workspace Doctor pass.
pub const DAG_DOCTOR_MAX_CURRENT_DAGS: usize = 32;
const DAG_DOCTOR_PROBE_CURRENT_DAGS: usize = DAG_DOCTOR_MAX_CURRENT_DAGS + 1;
const DAG_DOCTOR_MAX_NODES: usize = DAG_DOCTOR_MAX_CURRENT_DAGS * MAX_DAG_NODES;
const DAG_DOCTOR_PROBE_NODES: usize = DAG_DOCTOR_MAX_NODES + 1;
const DAG_DOCTOR_MAX_EDGES: usize = DAG_DOCTOR_MAX_CURRENT_DAGS * MAX_DAG_EDGES;
const DAG_DOCTOR_PROBE_EDGES: usize = DAG_DOCTOR_MAX_EDGES + 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DagDoctorIssue {
    MissingHead,
    MissingRevision,
    HeadRevisionMismatch,
    HeadTimestampMismatch,
    CountMismatch,
    AcceptanceInvalid,
    LifecycleInvalid,
    StructureInvalid,
    Cycle,
    ReadinessInvalid,
}

#[must_use]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DagDoctorNodeSummary {
    pending: u16,
    ready: u16,
    active: u16,
    blocked: u16,
    completed: u16,
    failed: u16,
    skipped: u16,
    cancelled: u16,
}

impl DagDoctorNodeSummary {
    pub const fn pending(self) -> u16 {
        self.pending
    }

    pub const fn ready(self) -> u16 {
        self.ready
    }

    pub const fn active(self) -> u16 {
        self.active
    }

    pub const fn blocked(self) -> u16 {
        self.blocked
    }

    pub const fn completed(self) -> u16 {
        self.completed
    }

    pub const fn failed(self) -> u16 {
        self.failed
    }

    pub const fn skipped(self) -> u16 {
        self.skipped
    }

    pub const fn cancelled(self) -> u16 {
        self.cancelled
    }

    fn observe(&mut self, status: DagNodeStatus) {
        match status {
            DagNodeStatus::Pending => self.pending += 1,
            DagNodeStatus::Ready => self.ready += 1,
            DagNodeStatus::Active => self.active += 1,
            DagNodeStatus::Blocked => self.blocked += 1,
            DagNodeStatus::Completed => self.completed += 1,
            DagNodeStatus::Failed => self.failed += 1,
            DagNodeStatus::Skipped => self.skipped += 1,
            DagNodeStatus::Cancelled => self.cancelled += 1,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DagDoctorState {
    Healthy(DagDoctorNodeSummary),
    Damaged(DagDoctorIssue),
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DagDoctorFinding {
    goal_id: GoalId,
    dag_revision: Option<DagRevisionNumber>,
    state: DagDoctorState,
}

impl DagDoctorFinding {
    pub const fn goal_id(self) -> GoalId {
        self.goal_id
    }

    pub const fn dag_revision(self) -> Option<DagRevisionNumber> {
        self.dag_revision
    }

    pub const fn state(self) -> DagDoctorState {
        self.state
    }
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DagDoctorReport {
    findings: Vec<DagDoctorFinding>,
    truncated: bool,
}

impl DagDoctorReport {
    fn new(findings: Vec<DagDoctorFinding>, truncated: bool) -> Self {
        Self {
            findings,
            truncated,
        }
    }

    pub fn findings(&self) -> &[DagDoctorFinding] {
        &self.findings
    }

    pub const fn truncated(&self) -> bool {
        self.truncated
    }

    pub fn is_damaged(&self) -> bool {
        self.findings
            .iter()
            .any(|finding| matches!(finding.state(), DagDoctorState::Damaged(_)))
    }

    pub const fn is_complete(&self) -> bool {
        !self.truncated
    }
}

type RawHeadRow = (
    Vec<u8>,
    i64,
    i64,
    i64,
    Option<Vec<u8>>,
    Option<i64>,
    Option<i64>,
    Option<i64>,
    Option<i64>,
    Option<i64>,
    Option<i64>,
);

#[derive(Debug)]
struct CurrentDagRaw {
    goal_id: GoalId,
    head_dag_revision: i64,
    head_revision: i64,
    head_updated_at: i64,
    revision_id: Option<Vec<u8>>,
    revision_number: Option<i64>,
    parent_revision: Option<i64>,
    base_goal_revision: Option<i64>,
    revision_created_at: Option<i64>,
    declared_node_count: Option<i64>,
    declared_edge_count: Option<i64>,
    nodes: Vec<RawNode>,
    acceptance: HashMap<DagNodeId, AcceptanceShape>,
    edges: Vec<DagEdge>,
}

#[derive(Debug)]
struct RawNode {
    id: DagNodeId,
    ordinal: i64,
    lifecycle_state: i64,
    reason: Option<String>,
    created_at: i64,
    updated_at: i64,
    revision: i64,
}

#[derive(Debug, Clone, Copy)]
struct AcceptanceShape {
    count: i64,
    minimum: Option<i64>,
    maximum: Option<i64>,
}

pub(crate) fn doctor_current(
    connection: &Connection,
    workspace_id: forge_domain::WorkspaceId,
) -> Result<DagDoctorReport, DagStoreError> {
    let transaction = connection.unchecked_transaction()?;
    let (mut current, heads_truncated) = load_current_heads(&transaction, workspace_id)?;
    let (missing_heads, missing_heads_truncated) = load_missing_heads(&transaction, workspace_id)?;
    let mut indexes = HashMap::with_capacity(current.len());
    for (index, dag) in current.iter().enumerate() {
        indexes.insert(dag.goal_id, index);
    }
    load_current_nodes(&transaction, workspace_id, &indexes, &mut current)?;
    load_acceptance_shapes(&transaction, workspace_id, &indexes, &mut current)?;
    load_current_edges(&transaction, workspace_id, &indexes, &mut current)?;
    let mut findings = Vec::with_capacity(current.len().saturating_add(missing_heads.len()));
    findings.extend(current.iter().map(evaluate_current_dag));
    findings.extend(missing_heads.into_iter().map(|goal_id| DagDoctorFinding {
        goal_id,
        dag_revision: None,
        state: DagDoctorState::Damaged(DagDoctorIssue::MissingHead),
    }));
    findings.sort_by_key(|finding| finding.goal_id());
    let findings_truncated = findings.len() > DAG_DOCTOR_MAX_CURRENT_DAGS;
    findings.truncate(DAG_DOCTOR_MAX_CURRENT_DAGS);
    transaction.commit()?;
    Ok(DagDoctorReport::new(
        findings,
        heads_truncated || missing_heads_truncated || findings_truncated,
    ))
}

fn load_missing_heads(
    connection: &Connection,
    workspace_id: forge_domain::WorkspaceId,
) -> Result<(Vec<GoalId>, bool), DagStoreError> {
    let mut statement = connection.prepare(
        "SELECT g.goal_id
         FROM goals AS g
         WHERE g.workspace_id = ?1
           AND EXISTS (
               SELECT 1 FROM goal_dag_revisions AS r WHERE r.goal_id = g.goal_id
           )
           AND NOT EXISTS (
               SELECT 1 FROM goal_dag_heads AS h WHERE h.goal_id = g.goal_id
           )
         ORDER BY g.goal_id
         LIMIT ?2",
    )?;
    let rows = statement.query_map(
        params![
            workspace_id.into_uuid().as_bytes(),
            i64::try_from(DAG_DOCTOR_PROBE_CURRENT_DAGS)
                .map_err(|_| DagStoreError::IntegerOverflow)?
        ],
        |row| row.get::<_, Vec<u8>>(0),
    )?;
    let mut goals = rows
        .map(|row| {
            let bytes = row?;
            Ok(GoalId::from_uuid(
                decode_uuid("dag.doctor_missing_head_goal", &bytes)
                    .map_err(to_sql_conversion_error)?,
            ))
        })
        .collect::<Result<Vec<_>, rusqlite::Error>>()?;
    let truncated = goals.len() > DAG_DOCTOR_MAX_CURRENT_DAGS;
    goals.truncate(DAG_DOCTOR_MAX_CURRENT_DAGS);
    Ok((goals, truncated))
}

fn load_current_heads(
    connection: &Connection,
    workspace_id: forge_domain::WorkspaceId,
) -> Result<(Vec<CurrentDagRaw>, bool), DagStoreError> {
    let mut statement = connection.prepare(
        "WITH selected_heads AS (
            SELECT h.goal_id, h.dag_revision, h.head_revision, h.updated_at_ms
            FROM goal_dag_heads AS h
            JOIN goals AS g ON g.goal_id = h.goal_id
            WHERE g.workspace_id = ?1
            ORDER BY h.goal_id
            LIMIT ?2
         )
         SELECT h.goal_id, h.dag_revision, h.head_revision, h.updated_at_ms,
                r.revision_id, r.dag_revision, r.parent_dag_revision,
                r.base_goal_revision, r.created_at_ms, r.node_count, r.edge_count
         FROM selected_heads AS h
         LEFT JOIN goal_dag_revisions AS r
           ON r.goal_id = h.goal_id AND r.dag_revision = h.dag_revision
         ORDER BY h.goal_id",
    )?;
    let rows = statement.query_map(
        params![
            workspace_id.into_uuid().as_bytes(),
            i64::try_from(DAG_DOCTOR_PROBE_CURRENT_DAGS)
                .map_err(|_| DagStoreError::IntegerOverflow)?
        ],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get(7)?,
                row.get(8)?,
                row.get(9)?,
                row.get(10)?,
            ))
        },
    )?;
    let mut dags = rows
        .map(|row| row.and_then(raw_current_dag_from_row))
        .collect::<Result<Vec<_>, _>>()?;
    let truncated = dags.len() > DAG_DOCTOR_MAX_CURRENT_DAGS;
    dags.truncate(DAG_DOCTOR_MAX_CURRENT_DAGS);
    Ok((dags, truncated))
}

fn raw_current_dag_from_row(row: RawHeadRow) -> Result<CurrentDagRaw, rusqlite::Error> {
    let goal_id = GoalId::from_uuid(
        decode_uuid("dag.doctor_goal_id", &row.0).map_err(to_sql_conversion_error)?,
    );
    let node_capacity = bounded_declared_capacity(row.9, MAX_DAG_NODES);
    let edge_capacity = bounded_declared_capacity(row.10, MAX_DAG_EDGES);
    Ok(CurrentDagRaw {
        goal_id,
        head_dag_revision: row.1,
        head_revision: row.2,
        head_updated_at: row.3,
        revision_id: row.4,
        revision_number: row.5,
        parent_revision: row.6,
        base_goal_revision: row.7,
        revision_created_at: row.8,
        declared_node_count: row.9,
        declared_edge_count: row.10,
        nodes: Vec::with_capacity(node_capacity),
        acceptance: HashMap::with_capacity(node_capacity),
        edges: Vec::with_capacity(edge_capacity),
    })
}

fn bounded_declared_capacity(value: Option<i64>, maximum: usize) -> usize {
    value
        .and_then(|value| usize::try_from(value).ok())
        .filter(|value| *value <= maximum)
        .unwrap_or(0)
}

fn load_current_nodes(
    connection: &Connection,
    workspace_id: forge_domain::WorkspaceId,
    indexes: &HashMap<GoalId, usize>,
    current: &mut [CurrentDagRaw],
) -> Result<(), DagStoreError> {
    let mut statement = connection.prepare(
        "WITH selected_heads AS (
            SELECT h.goal_id, h.dag_revision
            FROM goal_dag_heads AS h
            JOIN goals AS g ON g.goal_id = h.goal_id
            WHERE g.workspace_id = ?1
            ORDER BY h.goal_id
            LIMIT ?2
         )
         SELECT n.goal_id, n.node_id, n.ordinal, n.lifecycle_state, n.reason_text,
                n.created_at_ms, n.updated_at_ms, n.node_revision
         FROM selected_heads AS h
         JOIN goal_dag_nodes AS n
           ON n.goal_id = h.goal_id AND n.dag_revision = h.dag_revision
         ORDER BY n.goal_id, n.ordinal, n.node_id
         LIMIT ?3",
    )?;
    let mut rows = statement.query(params![
        workspace_id.into_uuid().as_bytes(),
        i64::try_from(DAG_DOCTOR_MAX_CURRENT_DAGS).map_err(|_| DagStoreError::IntegerOverflow)?,
        i64::try_from(DAG_DOCTOR_PROBE_NODES).map_err(|_| DagStoreError::IntegerOverflow)?,
    ])?;
    let mut observed = 0_usize;
    while let Some(row) = rows.next()? {
        observed += 1;
        if observed > DAG_DOCTOR_MAX_NODES {
            return Err(DagStoreError::CorruptRecord("dag.doctor_node_bound"));
        }
        let goal_bytes: Vec<u8> = row.get(0)?;
        let node_bytes: Vec<u8> = row.get(1)?;
        let goal_id = GoalId::from_uuid(decode_uuid("dag.doctor_node_goal", &goal_bytes)?);
        let node_id = DagNodeId::from_uuid(decode_uuid("dag.doctor_node_id", &node_bytes)?);
        let index = indexes
            .get(&goal_id)
            .copied()
            .ok_or(DagStoreError::CorruptRecord("dag.doctor_node_goal"))?;
        current[index].nodes.push(RawNode {
            id: node_id,
            ordinal: row.get(2)?,
            lifecycle_state: row.get(3)?,
            reason: row.get(4)?,
            created_at: row.get(5)?,
            updated_at: row.get(6)?,
            revision: row.get(7)?,
        });
    }
    Ok(())
}

fn load_acceptance_shapes(
    connection: &Connection,
    workspace_id: forge_domain::WorkspaceId,
    indexes: &HashMap<GoalId, usize>,
    current: &mut [CurrentDagRaw],
) -> Result<(), DagStoreError> {
    let mut statement = connection.prepare(
        "WITH selected_heads AS (
            SELECT h.goal_id, h.dag_revision
            FROM goal_dag_heads AS h
            JOIN goals AS g ON g.goal_id = h.goal_id
            WHERE g.workspace_id = ?1
            ORDER BY h.goal_id
            LIMIT ?2
         )
         SELECT n.goal_id, n.node_id, COUNT(a.ordinal), MIN(a.ordinal), MAX(a.ordinal)
         FROM selected_heads AS h
         JOIN goal_dag_nodes AS n
           ON n.goal_id = h.goal_id AND n.dag_revision = h.dag_revision
         LEFT JOIN goal_dag_node_acceptance AS a
           ON a.goal_id = n.goal_id AND a.dag_revision = n.dag_revision
          AND a.node_id = n.node_id
         GROUP BY n.goal_id, n.dag_revision, n.node_id
         ORDER BY n.goal_id, n.node_id
         LIMIT ?3",
    )?;
    let mut rows = statement.query(params![
        workspace_id.into_uuid().as_bytes(),
        i64::try_from(DAG_DOCTOR_MAX_CURRENT_DAGS).map_err(|_| DagStoreError::IntegerOverflow)?,
        i64::try_from(DAG_DOCTOR_PROBE_NODES).map_err(|_| DagStoreError::IntegerOverflow)?,
    ])?;
    let mut observed = 0_usize;
    while let Some(row) = rows.next()? {
        observed += 1;
        if observed > DAG_DOCTOR_MAX_NODES {
            return Err(DagStoreError::CorruptRecord("dag.doctor_acceptance_bound"));
        }
        let goal_bytes: Vec<u8> = row.get(0)?;
        let node_bytes: Vec<u8> = row.get(1)?;
        let goal_id = GoalId::from_uuid(decode_uuid("dag.doctor_acceptance_goal", &goal_bytes)?);
        let node_id = DagNodeId::from_uuid(decode_uuid("dag.doctor_acceptance_node", &node_bytes)?);
        let index = indexes
            .get(&goal_id)
            .copied()
            .ok_or(DagStoreError::CorruptRecord("dag.doctor_acceptance_goal"))?;
        if current[index]
            .acceptance
            .insert(
                node_id,
                AcceptanceShape {
                    count: row.get(2)?,
                    minimum: row.get(3)?,
                    maximum: row.get(4)?,
                },
            )
            .is_some()
        {
            return Err(DagStoreError::CorruptRecord(
                "dag.doctor_acceptance_duplicate",
            ));
        }
    }
    Ok(())
}

fn load_current_edges(
    connection: &Connection,
    workspace_id: forge_domain::WorkspaceId,
    indexes: &HashMap<GoalId, usize>,
    current: &mut [CurrentDagRaw],
) -> Result<(), DagStoreError> {
    let mut statement = connection.prepare(
        "WITH selected_heads AS (
            SELECT h.goal_id, h.dag_revision
            FROM goal_dag_heads AS h
            JOIN goals AS g ON g.goal_id = h.goal_id
            WHERE g.workspace_id = ?1
            ORDER BY h.goal_id
            LIMIT ?2
         )
         SELECT e.goal_id, e.upstream_node_id, e.downstream_node_id
         FROM selected_heads AS h
         JOIN goal_dag_edges AS e
           ON e.goal_id = h.goal_id AND e.dag_revision = h.dag_revision
         ORDER BY e.goal_id, e.upstream_node_id, e.downstream_node_id
         LIMIT ?3",
    )?;
    let mut rows = statement.query(params![
        workspace_id.into_uuid().as_bytes(),
        i64::try_from(DAG_DOCTOR_MAX_CURRENT_DAGS).map_err(|_| DagStoreError::IntegerOverflow)?,
        i64::try_from(DAG_DOCTOR_PROBE_EDGES).map_err(|_| DagStoreError::IntegerOverflow)?,
    ])?;
    let mut observed = 0_usize;
    while let Some(row) = rows.next()? {
        observed += 1;
        if observed > DAG_DOCTOR_MAX_EDGES {
            return Err(DagStoreError::CorruptRecord("dag.doctor_edge_bound"));
        }
        let goal_bytes: Vec<u8> = row.get(0)?;
        let upstream_bytes: Vec<u8> = row.get(1)?;
        let downstream_bytes: Vec<u8> = row.get(2)?;
        let goal_id = GoalId::from_uuid(decode_uuid("dag.doctor_edge_goal", &goal_bytes)?);
        let upstream =
            DagNodeId::from_uuid(decode_uuid("dag.doctor_edge_upstream", &upstream_bytes)?);
        let downstream = DagNodeId::from_uuid(decode_uuid(
            "dag.doctor_edge_downstream",
            &downstream_bytes,
        )?);
        let index = indexes
            .get(&goal_id)
            .copied()
            .ok_or(DagStoreError::CorruptRecord("dag.doctor_edge_goal"))?;
        current[index]
            .edges
            .push(DagEdge::new(upstream, downstream));
    }
    Ok(())
}

fn evaluate_current_dag(raw: &CurrentDagRaw) -> DagDoctorFinding {
    let dag_revision = DagRevisionNumber::new(raw.head_dag_revision).ok();
    let state = evaluate_current_dag_state(raw)
        .map_or_else(DagDoctorState::Damaged, DagDoctorState::Healthy);
    DagDoctorFinding {
        goal_id: raw.goal_id,
        dag_revision,
        state,
    }
}

#[derive(Debug, Clone, Copy)]
struct ValidatedDagMetadata {
    revision_id: DagRevisionId,
    number: DagRevisionNumber,
    parent: Option<DagRevisionNumber>,
    base_goal_revision: GoalRevision,
    created_at: TimestampMillis,
}

fn evaluate_current_dag_state(raw: &CurrentDagRaw) -> Result<DagDoctorNodeSummary, DagDoctorIssue> {
    let metadata = validate_dag_metadata(raw)?;
    validate_declared_counts(raw)?;
    let (definitions, snapshots) = build_node_projections(raw, metadata.number)?;
    let revision = build_semantic_revision(raw, metadata, definitions)?;
    let projections = revision
        .project(&snapshots)
        .map_err(|_| DagDoctorIssue::StructureInvalid)?;
    validate_readiness(&projections)?;
    Ok(summarize_nodes(&projections))
}

fn validate_dag_metadata(raw: &CurrentDagRaw) -> Result<ValidatedDagMetadata, DagDoctorIssue> {
    let revision_id = raw
        .revision_id
        .as_deref()
        .ok_or(DagDoctorIssue::MissingRevision)?;
    let number = DagRevisionNumber::new(raw.head_dag_revision)
        .map_err(|_| DagDoctorIssue::StructureInvalid)?;
    let stored_number =
        DagRevisionNumber::new(raw.revision_number.ok_or(DagDoctorIssue::MissingRevision)?)
            .map_err(|_| DagDoctorIssue::StructureInvalid)?;
    let head_revision = DagHeadRevision::new(raw.head_revision)
        .map_err(|_| DagDoctorIssue::HeadRevisionMismatch)?;
    if stored_number != number || head_revision.get() != number.get() {
        return Err(DagDoctorIssue::HeadRevisionMismatch);
    }
    let created_at = decode_timestamp(
        "dag.doctor_revision_created",
        raw.revision_created_at
            .ok_or(DagDoctorIssue::MissingRevision)?,
    )
    .map_err(|_| DagDoctorIssue::StructureInvalid)?;
    let head_updated = decode_timestamp("dag.doctor_head_updated", raw.head_updated_at)
        .map_err(|_| DagDoctorIssue::HeadTimestampMismatch)?;
    if head_updated != created_at {
        return Err(DagDoctorIssue::HeadTimestampMismatch);
    }
    Ok(ValidatedDagMetadata {
        revision_id: DagRevisionId::from_uuid(
            decode_uuid("dag.doctor_revision_id", revision_id)
                .map_err(|_| DagDoctorIssue::StructureInvalid)?,
        ),
        number,
        parent: raw
            .parent_revision
            .map(DagRevisionNumber::new)
            .transpose()
            .map_err(|_| DagDoctorIssue::StructureInvalid)?,
        base_goal_revision: GoalRevision::new(
            raw.base_goal_revision
                .ok_or(DagDoctorIssue::MissingRevision)?,
        )
        .map_err(|_| DagDoctorIssue::StructureInvalid)?,
        created_at,
    })
}

fn validate_declared_counts(raw: &CurrentDagRaw) -> Result<(), DagDoctorIssue> {
    let declared_nodes = usize::try_from(
        raw.declared_node_count
            .ok_or(DagDoctorIssue::MissingRevision)?,
    )
    .map_err(|_| DagDoctorIssue::CountMismatch)?;
    let declared_edges = usize::try_from(
        raw.declared_edge_count
            .ok_or(DagDoctorIssue::MissingRevision)?,
    )
    .map_err(|_| DagDoctorIssue::CountMismatch)?;
    if declared_nodes == raw.nodes.len() && declared_edges == raw.edges.len() {
        Ok(())
    } else {
        Err(DagDoctorIssue::CountMismatch)
    }
}

fn build_node_projections(
    raw: &CurrentDagRaw,
    number: DagRevisionNumber,
) -> Result<(Vec<DagNodeDefinition>, Vec<RegisteredDagNode>), DagDoctorIssue> {
    let mut definitions = Vec::with_capacity(raw.nodes.len());
    let mut snapshots = Vec::with_capacity(raw.nodes.len());
    for node in &raw.nodes {
        let shape = raw
            .acceptance
            .get(&node.id)
            .ok_or(DagDoctorIssue::AcceptanceInvalid)?;
        if !valid_acceptance_shape(*shape) {
            return Err(DagDoctorIssue::AcceptanceInvalid);
        }
        let definition = synthetic_definition(node.id, node.ordinal)?;
        let lifecycle = decode_lifecycle(node.lifecycle_state, node.reason.clone())
            .map_err(|_| DagDoctorIssue::LifecycleInvalid)?;
        let revision =
            DagNodeRevision::new(node.revision).map_err(|_| DagDoctorIssue::LifecycleInvalid)?;
        if !valid_lifecycle_revision(&lifecycle, revision) {
            return Err(DagDoctorIssue::LifecycleInvalid);
        }
        let snapshot = RegisteredDagNode::from_parts(
            raw.goal_id,
            number,
            definition.clone(),
            lifecycle,
            decode_timestamp("dag.doctor_node_created", node.created_at)
                .map_err(|_| DagDoctorIssue::LifecycleInvalid)?,
            decode_timestamp("dag.doctor_node_updated", node.updated_at)
                .map_err(|_| DagDoctorIssue::LifecycleInvalid)?,
            revision,
        )
        .map_err(|_| DagDoctorIssue::LifecycleInvalid)?;
        definitions.push(definition);
        snapshots.push(snapshot);
    }
    if raw.acceptance.len() == raw.nodes.len() {
        Ok((definitions, snapshots))
    } else {
        Err(DagDoctorIssue::AcceptanceInvalid)
    }
}

fn build_semantic_revision(
    raw: &CurrentDagRaw,
    metadata: ValidatedDagMetadata,
    definitions: Vec<DagNodeDefinition>,
) -> Result<DagRevision, DagDoctorIssue> {
    DagRevision::new(
        metadata.revision_id,
        raw.goal_id,
        metadata.base_goal_revision,
        metadata.number,
        metadata.parent,
        definitions,
        raw.edges.clone(),
        metadata.created_at,
    )
    .map_err(|error| match error {
        forge_domain::DagStructureError::Cycle => DagDoctorIssue::Cycle,
        _ => DagDoctorIssue::StructureInvalid,
    })
}

fn synthetic_definition(id: DagNodeId, ordinal: i64) -> Result<DagNodeDefinition, DagDoctorIssue> {
    DagNodeDefinition::new(
        id,
        DagNodeOrdinal::new(
            decode_u16("dag.doctor_ordinal", ordinal)
                .map_err(|_| DagDoctorIssue::StructureInvalid)?,
        )
        .map_err(|_| DagDoctorIssue::StructureInvalid)?,
        DagNodeTitle::new("Doctor node".to_owned())
            .map_err(|_| DagDoctorIssue::StructureInvalid)?,
        DagNodeObjective::new("Validate current durable DAG semantics".to_owned())
            .map_err(|_| DagDoctorIssue::StructureInvalid)?,
        vec![
            DagAcceptanceCriterion::new("Current DAG remains valid".to_owned())
                .map_err(|_| DagDoctorIssue::StructureInvalid)?,
        ],
    )
    .map_err(|_| DagDoctorIssue::StructureInvalid)
}

fn valid_acceptance_shape(shape: AcceptanceShape) -> bool {
    shape.count >= 1
        && shape.count <= 32
        && shape.minimum == Some(0)
        && shape.maximum == Some(shape.count - 1)
}

fn valid_lifecycle_revision(lifecycle: &DagNodeLifecycle, revision: DagNodeRevision) -> bool {
    let value = revision.get();
    match lifecycle {
        DagNodeLifecycle::Pending => value == 1,
        DagNodeLifecycle::Active => value >= 2 && value % 2 == 0,
        DagNodeLifecycle::Blocked(_) | DagNodeLifecycle::Completed => value >= 3 && value % 2 == 1,
        DagNodeLifecycle::Failed(_) => value >= 3,
        DagNodeLifecycle::Skipped(_) => value == 2,
        DagNodeLifecycle::Cancelled => value >= 2,
    }
}

fn validate_readiness(projections: &[DagNodeProjection]) -> Result<(), DagDoctorIssue> {
    for projection in projections {
        if matches!(
            projection.status(),
            DagNodeStatus::Active
                | DagNodeStatus::Blocked
                | DagNodeStatus::Completed
                | DagNodeStatus::Failed
        ) && !projection.waiting_on().is_empty()
        {
            return Err(DagDoctorIssue::ReadinessInvalid);
        }
    }
    Ok(())
}

fn summarize_nodes(projections: &[DagNodeProjection]) -> DagDoctorNodeSummary {
    let mut summary = DagDoctorNodeSummary::default();
    for projection in projections {
        summary.observe(projection.status());
    }
    summary
}

fn to_sql_conversion_error(error: DagStoreError) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Blob, Box::new(error))
}
