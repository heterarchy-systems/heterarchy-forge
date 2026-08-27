//! Pure, bounded, versioned Goal dependency DAG policy.
//!
//! The DAG describes coarse Goal milestones. It owns no executor, scheduler,
//! continuation, agent, or I/O capability. `READY` is always derived from the
//! current immutable graph plus explicit durable node snapshots.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;

use thiserror::Error;
use uuid::Uuid;

use crate::{GoalAttribution, GoalId, GoalPublicReason, GoalRevision, TimestampMillis};

pub const MAX_DAG_NODES: usize = 128;
pub const MAX_DAG_EDGES: usize = 512;
pub const MAX_DAG_NODE_TITLE_BYTES: usize = 256;
pub const MAX_DAG_NODE_OBJECTIVE_BYTES: usize = 2 * 1024;
pub const MAX_DAG_ACCEPTANCE_BYTES: usize = 1024;

macro_rules! uuid_identity {
    ($name:ident, $error:ident, $message:literal) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(Uuid);

        impl $name {
            pub const fn from_uuid(value: Uuid) -> Self {
                Self(value)
            }
            pub const fn into_uuid(self) -> Uuid {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl FromStr for $name {
            type Err = $error;
            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Uuid::parse_str(value)
                    .map(Self)
                    .map_err($error::InvalidUuid)
            }
        }

        #[derive(Debug, Error)]
        pub enum $error {
            #[error($message)]
            InvalidUuid(#[source] uuid::Error),
        }
    };
}

uuid_identity!(
    DagRevisionId,
    DagRevisionIdParseError,
    "invalid DAG revision UUID"
);
uuid_identity!(DagNodeId, DagNodeIdParseError, "invalid DAG node UUID");

macro_rules! positive_revision {
    ($name:ident, $error:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(i64);
        impl $name {
            pub const INITIAL: Self = Self(1);
            pub const fn new(value: i64) -> Result<Self, $error> {
                if value < 1 {
                    Err($error::Invalid(value))
                } else {
                    Ok(Self(value))
                }
            }
            pub const fn get(self) -> i64 {
                self.0
            }
            pub const fn checked_next(self) -> Result<Self, $error> {
                match self.0.checked_add(1) {
                    Some(value) => Ok(Self(value)),
                    None => Err($error::Overflow(self.0)),
                }
            }
        }
        #[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
        pub enum $error {
            #[error("revision must be at least 1, got {0}")]
            Invalid(i64),
            #[error("revision overflowed at {0}")]
            Overflow(i64),
        }
    };
}

positive_revision!(DagRevisionNumber, DagRevisionNumberError);
positive_revision!(DagNodeRevision, DagNodeRevisionError);
positive_revision!(DagHeadRevision, DagHeadRevisionError);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GoalNodeAttribution {
    goal_id: GoalId,
    expected_goal_revision: GoalRevision,
    dag_revision: DagRevisionNumber,
    node_id: DagNodeId,
    expected_node_revision: DagNodeRevision,
}

impl GoalNodeAttribution {
    pub const fn new(
        goal_id: GoalId,
        expected_goal_revision: GoalRevision,
        dag_revision: DagRevisionNumber,
        node_id: DagNodeId,
        expected_node_revision: DagNodeRevision,
    ) -> Self {
        Self {
            goal_id,
            expected_goal_revision,
            dag_revision,
            node_id,
            expected_node_revision,
        }
    }
    pub const fn goal_id(self) -> GoalId {
        self.goal_id
    }
    pub const fn expected_goal_revision(self) -> GoalRevision {
        self.expected_goal_revision
    }
    pub const fn dag_revision(self) -> DagRevisionNumber {
        self.dag_revision
    }
    pub const fn node_id(self) -> DagNodeId {
        self.node_id
    }
    pub const fn expected_node_revision(self) -> DagNodeRevision {
        self.expected_node_revision
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GoalWorkAttribution {
    Goal(GoalAttribution),
    Node(GoalNodeAttribution),
}

impl GoalWorkAttribution {
    pub const fn goal(self) -> GoalAttribution {
        match self {
            Self::Goal(value) => value,
            Self::Node(value) => {
                GoalAttribution::new(value.goal_id(), value.expected_goal_revision())
            }
        }
    }
    pub const fn node(self) -> Option<GoalNodeAttribution> {
        match self {
            Self::Goal(_) => None,
            Self::Node(value) => Some(value),
        }
    }
}

impl From<GoalAttribution> for GoalWorkAttribution {
    fn from(value: GoalAttribution) -> Self {
        Self::Goal(value)
    }
}

impl From<GoalNodeAttribution> for GoalWorkAttribution {
    fn from(value: GoalNodeAttribution) -> Self {
        Self::Node(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DagNodeOrdinal(u16);

impl DagNodeOrdinal {
    pub const fn new(value: u16) -> Result<Self, DagBoundError> {
        if value as usize >= MAX_DAG_NODES {
            Err(DagBoundError::NodeOrdinal(value))
        } else {
            Ok(Self(value))
        }
    }
    pub const fn get(self) -> u16 {
        self.0
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum DagBoundError {
    #[error("DAG node ordinal {0} exceeds the bound")]
    NodeOrdinal(u16),
}

macro_rules! bounded_text {
    ($name:ident, $maximum:expr) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub struct $name(String);
        impl $name {
            pub fn new(value: String) -> Result<Self, DagTextError> {
                let trimmed = value.trim();
                if trimmed.is_empty() {
                    return Err(DagTextError::Empty);
                }
                if value.as_bytes().contains(&0)
                    || value
                        .chars()
                        .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
                {
                    return Err(DagTextError::ControlCharacter);
                }
                if value.len() > $maximum {
                    return Err(DagTextError::TooLarge {
                        actual: value.len(),
                        maximum: $maximum,
                    });
                }
                Ok(Self(value))
            }
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}

bounded_text!(DagNodeTitle, MAX_DAG_NODE_TITLE_BYTES);
bounded_text!(DagNodeObjective, MAX_DAG_NODE_OBJECTIVE_BYTES);
bounded_text!(DagAcceptanceCriterion, MAX_DAG_ACCEPTANCE_BYTES);

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum DagTextError {
    #[error("DAG text is empty")]
    Empty,
    #[error("DAG text contains a control character")]
    ControlCharacter,
    #[error("DAG text has {actual} bytes; maximum is {maximum}")]
    TooLarge { actual: usize, maximum: usize },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DagNodeDefinition {
    id: DagNodeId,
    ordinal: DagNodeOrdinal,
    title: DagNodeTitle,
    objective: DagNodeObjective,
    acceptance: Vec<DagAcceptanceCriterion>,
}

impl DagNodeDefinition {
    pub fn new(
        id: DagNodeId,
        ordinal: DagNodeOrdinal,
        title: DagNodeTitle,
        objective: DagNodeObjective,
        acceptance: Vec<DagAcceptanceCriterion>,
    ) -> Result<Self, DagStructureError> {
        if acceptance.is_empty() || acceptance.len() > 32 {
            return Err(DagStructureError::AcceptanceCount(acceptance.len()));
        }
        Ok(Self {
            id,
            ordinal,
            title,
            objective,
            acceptance,
        })
    }
    pub const fn id(&self) -> DagNodeId {
        self.id
    }
    pub const fn ordinal(&self) -> DagNodeOrdinal {
        self.ordinal
    }
    pub const fn title(&self) -> &DagNodeTitle {
        &self.title
    }
    pub const fn objective(&self) -> &DagNodeObjective {
        &self.objective
    }
    pub fn acceptance(&self) -> &[DagAcceptanceCriterion] {
        &self.acceptance
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DagEdge {
    upstream: DagNodeId,
    downstream: DagNodeId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DagLineageKind {
    Split,
    Replace,
    Merge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DagNodeLineage {
    prior_node_id: DagNodeId,
    successor_node_id: DagNodeId,
    kind: DagLineageKind,
}

impl DagNodeLineage {
    pub const fn new(
        prior_node_id: DagNodeId,
        successor_node_id: DagNodeId,
        kind: DagLineageKind,
    ) -> Self {
        Self {
            prior_node_id,
            successor_node_id,
            kind,
        }
    }
    pub const fn prior_node_id(self) -> DagNodeId {
        self.prior_node_id
    }
    pub const fn successor_node_id(self) -> DagNodeId {
        self.successor_node_id
    }
    pub const fn kind(self) -> DagLineageKind {
        self.kind
    }
}

impl DagEdge {
    pub const fn new(upstream: DagNodeId, downstream: DagNodeId) -> Self {
        Self {
            upstream,
            downstream,
        }
    }
    pub const fn upstream(self) -> DagNodeId {
        self.upstream
    }
    pub const fn downstream(self) -> DagNodeId {
        self.downstream
    }
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DagRevision {
    id: DagRevisionId,
    goal_id: GoalId,
    base_goal_revision: GoalRevision,
    number: DagRevisionNumber,
    parent: Option<DagRevisionNumber>,
    nodes: Vec<DagNodeDefinition>,
    edges: Vec<DagEdge>,
    topological_order: Vec<DagNodeId>,
    created_at: TimestampMillis,
}

impl DagRevision {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: DagRevisionId,
        goal_id: GoalId,
        base_goal_revision: GoalRevision,
        number: DagRevisionNumber,
        parent: Option<DagRevisionNumber>,
        mut nodes: Vec<DagNodeDefinition>,
        mut edges: Vec<DagEdge>,
        created_at: TimestampMillis,
    ) -> Result<Self, DagStructureError> {
        if (number == DagRevisionNumber::INITIAL) != parent.is_none() {
            return Err(DagStructureError::ParentRevision);
        }
        if let Some(parent) = parent
            && parent
                .checked_next()
                .map_err(|_| DagStructureError::ParentRevision)?
                != number
        {
            return Err(DagStructureError::ParentRevision);
        }
        if nodes.is_empty() || nodes.len() > MAX_DAG_NODES {
            return Err(DagStructureError::NodeCount(nodes.len()));
        }
        if edges.len() > MAX_DAG_EDGES {
            return Err(DagStructureError::EdgeCount(edges.len()));
        }
        nodes.sort_by_key(|node| (node.ordinal(), node.id()));
        let mut ids = BTreeSet::new();
        let mut ordinals = BTreeSet::new();
        for node in &nodes {
            if !ids.insert(node.id()) {
                return Err(DagStructureError::DuplicateNode(node.id()));
            }
            if !ordinals.insert(node.ordinal()) {
                return Err(DagStructureError::DuplicateOrdinal(node.ordinal()));
            }
        }
        edges.sort_unstable();
        let mut unique_edges = BTreeSet::new();
        for edge in &edges {
            if edge.upstream() == edge.downstream() {
                return Err(DagStructureError::SelfEdge(edge.upstream()));
            }
            if !ids.contains(&edge.upstream()) {
                return Err(DagStructureError::UnknownNode(edge.upstream()));
            }
            if !ids.contains(&edge.downstream()) {
                return Err(DagStructureError::UnknownNode(edge.downstream()));
            }
            if !unique_edges.insert(*edge) {
                return Err(DagStructureError::DuplicateEdge(*edge));
            }
        }
        let topological_order = topological_order(&nodes, &edges)?;
        Ok(Self {
            id,
            goal_id,
            base_goal_revision,
            number,
            parent,
            nodes,
            edges,
            topological_order,
            created_at,
        })
    }
    pub const fn id(&self) -> DagRevisionId {
        self.id
    }
    pub const fn goal_id(&self) -> GoalId {
        self.goal_id
    }
    pub const fn base_goal_revision(&self) -> GoalRevision {
        self.base_goal_revision
    }
    pub const fn number(&self) -> DagRevisionNumber {
        self.number
    }
    pub const fn parent(&self) -> Option<DagRevisionNumber> {
        self.parent
    }
    pub fn nodes(&self) -> &[DagNodeDefinition] {
        &self.nodes
    }
    pub fn edges(&self) -> &[DagEdge] {
        &self.edges
    }
    pub fn topological_order(&self) -> &[DagNodeId] {
        &self.topological_order
    }
    pub const fn created_at(&self) -> TimestampMillis {
        self.created_at
    }

    pub fn project(
        &self,
        snapshots: &[RegisteredDagNode],
    ) -> Result<Vec<DagNodeProjection>, DagReadinessError> {
        let by_id = validate_snapshots(self, snapshots)?;
        let mut result = Vec::with_capacity(self.nodes.len());
        for node_id in &self.topological_order {
            let node = by_id
                .get(node_id)
                .ok_or(DagReadinessError::MissingSnapshot(*node_id))?;
            let waiting_on = self
                .edges
                .iter()
                .filter(|edge| edge.downstream() == *node_id)
                .filter_map(|edge| {
                    by_id
                        .get(&edge.upstream())
                        .filter(|upstream| *upstream.lifecycle() != DagNodeLifecycle::Completed)
                        .map(|_| edge.upstream())
                })
                .collect::<Vec<_>>();
            let status = match node.lifecycle() {
                DagNodeLifecycle::Pending if waiting_on.is_empty() => DagNodeStatus::Ready,
                DagNodeLifecycle::Pending => DagNodeStatus::Pending,
                DagNodeLifecycle::Active => DagNodeStatus::Active,
                DagNodeLifecycle::Blocked(_) => DagNodeStatus::Blocked,
                DagNodeLifecycle::Completed => DagNodeStatus::Completed,
                DagNodeLifecycle::Failed(_) => DagNodeStatus::Failed,
                DagNodeLifecycle::Skipped(_) => DagNodeStatus::Skipped,
                DagNodeLifecycle::Cancelled => DagNodeStatus::Cancelled,
            };
            result.push(DagNodeProjection {
                node: (*node).clone(),
                status,
                waiting_on,
            });
        }
        Ok(result)
    }

    pub fn start_node(
        &self,
        snapshots: &[RegisteredDagNode],
        node_id: DagNodeId,
        expected_revision: DagNodeRevision,
        observed_at: TimestampMillis,
    ) -> Result<RegisteredDagNode, DagNodeTransitionError> {
        let projection = self
            .project(snapshots)
            .map_err(DagNodeTransitionError::Readiness)?;
        let node = projection
            .iter()
            .find(|item| item.node().id() == node_id)
            .ok_or(DagNodeTransitionError::NodeMissing(node_id))?;
        if node.status() != DagNodeStatus::Ready {
            return Err(DagNodeTransitionError::NotReady);
        }
        node.node().start(expected_revision, observed_at)
    }
}

fn topological_order(
    nodes: &[DagNodeDefinition],
    edges: &[DagEdge],
) -> Result<Vec<DagNodeId>, DagStructureError> {
    let rank = nodes
        .iter()
        .map(|node| (node.id(), node.ordinal()))
        .collect::<BTreeMap<_, _>>();
    let mut indegree = nodes
        .iter()
        .map(|node| (node.id(), 0_u16))
        .collect::<BTreeMap<_, _>>();
    let mut outgoing = BTreeMap::<DagNodeId, Vec<DagNodeId>>::new();
    for edge in edges {
        *indegree
            .get_mut(&edge.downstream())
            .ok_or(DagStructureError::UnknownNode(edge.downstream()))? += 1;
        outgoing
            .entry(edge.upstream())
            .or_default()
            .push(edge.downstream());
    }
    for targets in outgoing.values_mut() {
        targets.sort_by_key(|id| (rank[id], *id));
    }
    let mut ready = indegree
        .iter()
        .filter(|(_, degree)| **degree == 0)
        .map(|(id, _)| (rank[id], *id))
        .collect::<BTreeSet<_>>();
    let mut order = Vec::with_capacity(nodes.len());
    while let Some((ordinal, id)) = ready.pop_first() {
        let _ = ordinal;
        order.push(id);
        for target in outgoing.get(&id).into_iter().flatten() {
            let degree = indegree
                .get_mut(target)
                .ok_or(DagStructureError::UnknownNode(*target))?;
            *degree -= 1;
            if *degree == 0 {
                ready.insert((rank[target], *target));
            }
        }
    }
    if order.len() == nodes.len() {
        Ok(order)
    } else {
        Err(DagStructureError::Cycle)
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DagStructureError {
    #[error("DAG parent revision does not immediately precede the new revision")]
    ParentRevision,
    #[error("DAG has {0} nodes outside the supported bound")]
    NodeCount(usize),
    #[error("DAG has {0} edges outside the supported bound")]
    EdgeCount(usize),
    #[error("DAG node has {0} acceptance criteria outside 1..=32")]
    AcceptanceCount(usize),
    #[error("duplicate DAG node {0}")]
    DuplicateNode(DagNodeId),
    #[error("duplicate DAG node ordinal {0:?}")]
    DuplicateOrdinal(DagNodeOrdinal),
    #[error("DAG edge references unknown node {0}")]
    UnknownNode(DagNodeId),
    #[error("DAG node {0} depends on itself")]
    SelfEdge(DagNodeId),
    #[error("duplicate DAG edge {0:?}")]
    DuplicateEdge(DagEdge),
    #[error("DAG contains a cycle")]
    Cycle,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DagNodeLifecycle {
    Pending,
    Active,
    Blocked(GoalPublicReason),
    Completed,
    Failed(GoalPublicReason),
    Skipped(GoalPublicReason),
    Cancelled,
}

impl DagNodeLifecycle {
    pub const fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Failed(_) | Self::Skipped(_) | Self::Cancelled
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DagNodeStatus {
    Pending,
    Ready,
    Active,
    Blocked,
    Completed,
    Failed,
    Skipped,
    Cancelled,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredDagNode {
    goal_id: GoalId,
    dag_revision: DagRevisionNumber,
    definition: DagNodeDefinition,
    lifecycle: DagNodeLifecycle,
    created_at: TimestampMillis,
    updated_at: TimestampMillis,
    revision: DagNodeRevision,
}

impl RegisteredDagNode {
    pub fn create(
        goal_id: GoalId,
        dag_revision: DagRevisionNumber,
        definition: DagNodeDefinition,
        observed_at: TimestampMillis,
    ) -> Self {
        Self {
            goal_id,
            dag_revision,
            definition,
            lifecycle: DagNodeLifecycle::Pending,
            created_at: observed_at,
            updated_at: observed_at,
            revision: DagNodeRevision::INITIAL,
        }
    }
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        goal_id: GoalId,
        dag_revision: DagRevisionNumber,
        definition: DagNodeDefinition,
        lifecycle: DagNodeLifecycle,
        created_at: TimestampMillis,
        updated_at: TimestampMillis,
        revision: DagNodeRevision,
    ) -> Result<Self, DagNodeTransitionError> {
        if updated_at.get() < created_at.get()
            || (revision == DagNodeRevision::INITIAL
                && (lifecycle != DagNodeLifecycle::Pending || updated_at != created_at))
        {
            return Err(DagNodeTransitionError::InvalidProjection);
        }
        Ok(Self {
            goal_id,
            dag_revision,
            definition,
            lifecycle,
            created_at,
            updated_at,
            revision,
        })
    }
    pub fn carry_to_revision(&self, dag_revision: DagRevisionNumber) -> Self {
        Self {
            dag_revision,
            ..self.clone()
        }
    }
    pub const fn goal_id(&self) -> GoalId {
        self.goal_id
    }
    pub const fn dag_revision(&self) -> DagRevisionNumber {
        self.dag_revision
    }
    pub const fn id(&self) -> DagNodeId {
        self.definition.id()
    }
    pub const fn definition(&self) -> &DagNodeDefinition {
        &self.definition
    }
    pub const fn lifecycle(&self) -> &DagNodeLifecycle {
        &self.lifecycle
    }
    pub const fn created_at(&self) -> TimestampMillis {
        self.created_at
    }
    pub const fn updated_at(&self) -> TimestampMillis {
        self.updated_at
    }
    pub const fn revision(&self) -> DagNodeRevision {
        self.revision
    }

    fn transition(
        &self,
        expected: DagNodeRevision,
        lifecycle: DagNodeLifecycle,
        observed_at: TimestampMillis,
    ) -> Result<Self, DagNodeTransitionError> {
        if self.revision != expected {
            return Err(DagNodeTransitionError::RevisionConflict);
        }
        if observed_at.get() < self.updated_at.get() {
            return Err(DagNodeTransitionError::TimestampOrder);
        }
        if self.lifecycle.is_terminal() {
            return Err(DagNodeTransitionError::Terminal);
        }
        Ok(Self {
            lifecycle,
            updated_at: observed_at,
            revision: self
                .revision
                .checked_next()
                .map_err(|_| DagNodeTransitionError::RevisionOverflow)?,
            ..self.clone()
        })
    }
    fn start(
        &self,
        expected: DagNodeRevision,
        observed_at: TimestampMillis,
    ) -> Result<Self, DagNodeTransitionError> {
        if self.lifecycle != DagNodeLifecycle::Pending {
            return Err(DagNodeTransitionError::InvalidTransition);
        }
        self.transition(expected, DagNodeLifecycle::Active, observed_at)
    }
    pub fn block(
        &self,
        expected: DagNodeRevision,
        reason: GoalPublicReason,
        observed_at: TimestampMillis,
    ) -> Result<Self, DagNodeTransitionError> {
        if self.lifecycle != DagNodeLifecycle::Active {
            return Err(DagNodeTransitionError::InvalidTransition);
        }
        self.transition(expected, DagNodeLifecycle::Blocked(reason), observed_at)
    }
    pub fn resume(
        &self,
        expected: DagNodeRevision,
        observed_at: TimestampMillis,
    ) -> Result<Self, DagNodeTransitionError> {
        if !matches!(self.lifecycle, DagNodeLifecycle::Blocked(_)) {
            return Err(DagNodeTransitionError::InvalidTransition);
        }
        self.transition(expected, DagNodeLifecycle::Active, observed_at)
    }
    pub fn complete(
        &self,
        expected: DagNodeRevision,
        observed_at: TimestampMillis,
    ) -> Result<Self, DagNodeTransitionError> {
        if self.lifecycle != DagNodeLifecycle::Active {
            return Err(DagNodeTransitionError::InvalidTransition);
        }
        self.transition(expected, DagNodeLifecycle::Completed, observed_at)
    }
    pub fn fail(
        &self,
        expected: DagNodeRevision,
        reason: GoalPublicReason,
        observed_at: TimestampMillis,
    ) -> Result<Self, DagNodeTransitionError> {
        if !matches!(
            self.lifecycle,
            DagNodeLifecycle::Active | DagNodeLifecycle::Blocked(_)
        ) {
            return Err(DagNodeTransitionError::InvalidTransition);
        }
        self.transition(expected, DagNodeLifecycle::Failed(reason), observed_at)
    }
    pub fn skip(
        &self,
        expected: DagNodeRevision,
        reason: GoalPublicReason,
        observed_at: TimestampMillis,
    ) -> Result<Self, DagNodeTransitionError> {
        if self.lifecycle != DagNodeLifecycle::Pending {
            return Err(DagNodeTransitionError::InvalidTransition);
        }
        self.transition(expected, DagNodeLifecycle::Skipped(reason), observed_at)
    }
    pub fn cancel(
        &self,
        expected: DagNodeRevision,
        observed_at: TimestampMillis,
    ) -> Result<Self, DagNodeTransitionError> {
        self.transition(expected, DagNodeLifecycle::Cancelled, observed_at)
    }
}

fn validate_snapshots<'a>(
    revision: &DagRevision,
    snapshots: &'a [RegisteredDagNode],
) -> Result<BTreeMap<DagNodeId, &'a RegisteredDagNode>, DagReadinessError> {
    if snapshots.len() != revision.nodes.len() {
        return Err(DagReadinessError::SnapshotCount);
    }
    let definitions = revision
        .nodes
        .iter()
        .map(|node| (node.id(), node))
        .collect::<BTreeMap<_, _>>();
    let mut result = BTreeMap::new();
    for snapshot in snapshots {
        let definition = definitions
            .get(&snapshot.id())
            .ok_or(DagReadinessError::ForeignSnapshot(snapshot.id()))?;
        if snapshot.goal_id() != revision.goal_id
            || snapshot.dag_revision() != revision.number
            || snapshot.definition() != *definition
        {
            return Err(DagReadinessError::ForeignSnapshot(snapshot.id()));
        }
        if result.insert(snapshot.id(), snapshot).is_some() {
            return Err(DagReadinessError::DuplicateSnapshot(snapshot.id()));
        }
    }
    Ok(result)
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DagReadinessError {
    #[error("DAG snapshot count does not match the revision")]
    SnapshotCount,
    #[error("DAG snapshot is missing for node {0}")]
    MissingSnapshot(DagNodeId),
    #[error("DAG snapshot {0} does not belong to this revision")]
    ForeignSnapshot(DagNodeId),
    #[error("duplicate DAG snapshot {0}")]
    DuplicateSnapshot(DagNodeId),
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DagNodeTransitionError {
    #[error(transparent)]
    Readiness(#[from] DagReadinessError),
    #[error("DAG node {0} is missing")]
    NodeMissing(DagNodeId),
    #[error("DAG node is not READY")]
    NotReady,
    #[error("DAG node revision is stale")]
    RevisionConflict,
    #[error("DAG node revision overflowed")]
    RevisionOverflow,
    #[error("DAG node timestamp order is invalid")]
    TimestampOrder,
    #[error("DAG node transition is invalid")]
    InvalidTransition,
    #[error("DAG node is terminal")]
    Terminal,
    #[error("DAG node persisted projection is invalid")]
    InvalidProjection,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DagNodeProjection {
    node: RegisteredDagNode,
    status: DagNodeStatus,
    waiting_on: Vec<DagNodeId>,
}
impl DagNodeProjection {
    pub const fn node(&self) -> &RegisteredDagNode {
        &self.node
    }
    pub const fn status(&self) -> DagNodeStatus {
        self.status
    }
    pub fn waiting_on(&self) -> &[DagNodeId] {
        &self.waiting_on
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(value: i64) -> TimestampMillis {
        TimestampMillis::new(value).unwrap_or_else(|_| unreachable!())
    }
    fn text(value: &str) -> (DagNodeTitle, DagNodeObjective, DagAcceptanceCriterion) {
        (
            DagNodeTitle::new(value.to_owned()).unwrap_or_else(|_| unreachable!()),
            DagNodeObjective::new(value.to_owned()).unwrap_or_else(|_| unreachable!()),
            DagAcceptanceCriterion::new(format!("{value} accepted"))
                .unwrap_or_else(|_| unreachable!()),
        )
    }
    fn node(id: u128, ordinal: u16, label: &str) -> DagNodeDefinition {
        let (title, objective, acceptance) = text(label);
        DagNodeDefinition::new(
            DagNodeId::from_uuid(Uuid::from_u128(id)),
            DagNodeOrdinal::new(ordinal).unwrap_or_else(|_| unreachable!()),
            title,
            objective,
            vec![acceptance],
        )
        .unwrap_or_else(|_| unreachable!())
    }
    fn revision(
        nodes: Vec<DagNodeDefinition>,
        edges: Vec<DagEdge>,
    ) -> Result<DagRevision, DagStructureError> {
        DagRevision::new(
            DagRevisionId::from_uuid(Uuid::from_u128(99)),
            GoalId::from_uuid(Uuid::from_u128(98)),
            GoalRevision::INITIAL,
            DagRevisionNumber::INITIAL,
            None,
            nodes,
            edges,
            ts(1),
        )
    }
    fn snapshots(revision: &DagRevision) -> Vec<RegisteredDagNode> {
        revision
            .nodes()
            .iter()
            .cloned()
            .map(|node| {
                RegisteredDagNode::create(revision.goal_id(), revision.number(), node, ts(1))
            })
            .collect()
    }

    #[test]
    fn cycles_self_edges_duplicates_and_unknown_nodes_fail_closed() {
        let a = node(1, 0, "A");
        let b = node(2, 1, "B");
        assert!(matches!(
            revision(vec![a.clone()], vec![DagEdge::new(a.id(), a.id())]),
            Err(DagStructureError::SelfEdge(_))
        ));
        assert!(matches!(
            revision(
                vec![a.clone(), b.clone()],
                vec![DagEdge::new(a.id(), b.id()), DagEdge::new(b.id(), a.id())]
            ),
            Err(DagStructureError::Cycle)
        ));
        assert!(matches!(
            revision(
                vec![a.clone(), b.clone()],
                vec![DagEdge::new(a.id(), b.id()), DagEdge::new(a.id(), b.id())]
            ),
            Err(DagStructureError::DuplicateEdge(_))
        ));
        assert!(matches!(
            revision(
                vec![a],
                vec![DagEdge::new(
                    DagNodeId::from_uuid(Uuid::from_u128(7)),
                    b.id()
                )]
            ),
            Err(DagStructureError::UnknownNode(_))
        ));
    }

    #[test]
    fn topological_order_uses_explicit_ordinal_not_input_order() {
        let a = node(1, 0, "A");
        let b = node(2, 1, "B");
        let c = node(3, 2, "C");
        let edges = vec![DagEdge::new(a.id(), c.id()), DagEdge::new(b.id(), c.id())];
        let first = revision(vec![c.clone(), a.clone(), b.clone()], edges.clone())
            .unwrap_or_else(|_| unreachable!());
        let second = revision(vec![b, a, c], edges.into_iter().rev().collect())
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(first.topological_order(), second.topological_order());
    }

    #[test]
    fn all_of_readiness_and_start_are_runtime_derived() {
        let a = node(1, 0, "A");
        let b = node(2, 1, "B");
        let c = node(3, 2, "C");
        let graph = revision(
            vec![a.clone(), b.clone(), c.clone()],
            vec![DagEdge::new(a.id(), c.id()), DagEdge::new(b.id(), c.id())],
        )
        .unwrap_or_else(|_| unreachable!());
        let mut states = snapshots(&graph);
        assert_eq!(
            graph
                .project(&states)
                .unwrap_or_else(|_| unreachable!())
                .iter()
                .find(|p| p.node().id() == c.id())
                .map(DagNodeProjection::status),
            Some(DagNodeStatus::Pending)
        );
        for id in [a.id(), b.id()] {
            let index = states
                .iter()
                .position(|n| n.id() == id)
                .unwrap_or_else(|| unreachable!());
            let active = graph
                .start_node(&states, id, states[index].revision(), ts(2))
                .unwrap_or_else(|_| unreachable!());
            states[index] = active
                .complete(active.revision(), ts(3))
                .unwrap_or_else(|_| unreachable!());
        }
        assert_eq!(
            graph
                .project(&states)
                .unwrap_or_else(|_| unreachable!())
                .iter()
                .find(|p| p.node().id() == c.id())
                .map(DagNodeProjection::status),
            Some(DagNodeStatus::Ready)
        );
        assert!(
            graph
                .start_node(&states, c.id(), states[2].revision(), ts(4))
                .is_ok()
        );
    }

    #[test]
    fn failure_is_local_and_terminal_nodes_are_immutable() {
        let a = node(1, 0, "A");
        let b = node(2, 1, "B");
        let graph = revision(
            vec![a.clone(), b.clone()],
            vec![DagEdge::new(a.id(), b.id())],
        )
        .unwrap_or_else(|_| unreachable!());
        let mut states = snapshots(&graph);
        let active = graph
            .start_node(&states, a.id(), states[0].revision(), ts(2))
            .unwrap_or_else(|_| unreachable!());
        let failed = active
            .fail(
                active.revision(),
                GoalPublicReason::new("failure".to_owned()).unwrap_or_else(|_| unreachable!()),
                ts(3),
            )
            .unwrap_or_else(|_| unreachable!());
        states[0] = failed.clone();
        assert_eq!(
            graph.project(&states).unwrap_or_else(|_| unreachable!())[1].status(),
            DagNodeStatus::Pending
        );
        assert_eq!(states[1].lifecycle(), &DagNodeLifecycle::Pending);
        assert!(matches!(
            failed.cancel(failed.revision(), ts(4)),
            Err(DagNodeTransitionError::Terminal)
        ));
    }

    #[test]
    fn lifecycle_is_revision_cas_and_same_tick_safe() {
        let a = node(1, 0, "A");
        let graph = revision(vec![a.clone()], Vec::new()).unwrap_or_else(|_| unreachable!());
        let states = snapshots(&graph);
        let active = graph
            .start_node(&states, a.id(), DagNodeRevision::INITIAL, ts(1))
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(active.updated_at(), active.created_at());
        assert!(matches!(
            active.complete(DagNodeRevision::INITIAL, ts(2)),
            Err(DagNodeTransitionError::RevisionConflict)
        ));
        let completed = active
            .complete(active.revision(), ts(2))
            .unwrap_or_else(|_| unreachable!());
        assert!(completed.lifecycle().is_terminal());
    }
}
