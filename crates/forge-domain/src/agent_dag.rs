//! Typed, bounded Coordinator-authorized DAG planning contracts.
//!
//! Planning commits are Activity-local and revision-fenced by the durable
//! Coordinator authority. Initial and successor DAG revisions share one
//! immutable draft/replay contract; persistence owns the final CAS/ledger
//! transaction.

use std::fmt;
use std::str::FromStr;

use blake3::Hasher;
use thiserror::Error;
use uuid::Uuid;

use crate::{
    AgentWorkUpdateId, AgentWorkUpdateSequence, DagEdge, DagHeadRevision, DagLineageKind,
    DagNodeDefinition, DagNodeLifecycle, DagNodeLineage, DagRevision, DagRevisionId,
    DagRevisionNumber, GoalAttribution, RegisteredDagNode, TimestampMillis,
};

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
    AgentDagPlanRequestId,
    AgentDagPlanRequestIdParseError,
    "invalid Agent DAG plan request UUID"
);

/// BLAKE3 digest of the canonical length-delimited DAG draft.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AgentDagDraftDigest([u8; 32]);

impl AgentDagDraftDigest {
    pub const BYTE_LEN: usize = 32;

    pub const fn from_bytes(value: [u8; 32]) -> Self {
        Self(value)
    }

    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for AgentDagDraftDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Immutable full successor DAG draft.  Node/edge/lineage collections are
/// canonicalized once at construction so its digest is independent of caller
/// collection order.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentDagDraft {
    revision: DagRevision,
    nodes: Vec<RegisteredDagNode>,
    lineage: Vec<DagNodeLineage>,
}

impl AgentDagDraft {
    pub fn new(
        revision: DagRevision,
        mut nodes: Vec<RegisteredDagNode>,
        mut lineage: Vec<DagNodeLineage>,
    ) -> Result<Self, AgentDagDraftError> {
        if nodes.len() != revision.nodes().len() {
            return Err(AgentDagDraftError::NodeCountMismatch);
        }
        if lineage.len() > crate::MAX_DAG_EDGES {
            return Err(AgentDagDraftError::LineageTooLarge);
        }
        if nodes.iter().any(|node| {
            node.goal_id() != revision.goal_id() || node.dag_revision() != revision.number()
        }) {
            return Err(AgentDagDraftError::NodeAttributionMismatch);
        }
        revision
            .project(&nodes)
            .map_err(|_| AgentDagDraftError::ProjectionMismatch)?;
        nodes.sort_by_key(|node| (node.definition().ordinal(), node.id()));
        lineage.sort_by_key(|item| (item.prior_node_id(), item.successor_node_id()));
        Ok(Self {
            revision,
            nodes,
            lineage,
        })
    }

    pub const fn revision(&self) -> &DagRevision {
        &self.revision
    }

    pub fn nodes(&self) -> &[RegisteredDagNode] {
        &self.nodes
    }

    pub fn lineage(&self) -> &[DagNodeLineage] {
        &self.lineage
    }

    /// Compute the canonical length-delimited BLAKE3 digest used by the
    /// idempotent replan ledger.
    pub fn digest(&self) -> AgentDagDraftDigest {
        let mut hasher = Hasher::new();
        hash_bytes(&mut hasher, b"forge-agent-dag-draft-v1");
        hash_uuid(&mut hasher, self.revision.id().into_uuid());
        hash_uuid(&mut hasher, self.revision.goal_id().into_uuid());
        hash_i64(&mut hasher, self.revision.base_goal_revision().get());
        hash_i64(&mut hasher, self.revision.number().get());
        match self.revision.parent() {
            Some(parent) => {
                hash_u8(&mut hasher, 1);
                hash_i64(&mut hasher, parent.get());
            }
            None => hash_u8(&mut hasher, 0),
        }
        hash_i64(&mut hasher, self.revision.created_at().get());
        hash_u64(&mut hasher, self.revision.nodes().len() as u64);
        for node in self.revision.nodes() {
            hash_definition(&mut hasher, node);
        }
        hash_u64(&mut hasher, self.revision.edges().len() as u64);
        for edge in self.revision.edges() {
            hash_edge(&mut hasher, *edge);
        }
        hash_u64(&mut hasher, self.nodes.len() as u64);
        for node in &self.nodes {
            hash_registered_node(&mut hasher, node);
        }
        hash_u64(&mut hasher, self.lineage.len() as u64);
        for item in &self.lineage {
            hash_uuid(&mut hasher, item.prior_node_id().into_uuid());
            hash_uuid(&mut hasher, item.successor_node_id().into_uuid());
            hash_u8(
                &mut hasher,
                match item.kind() {
                    DagLineageKind::Split => 0,
                    DagLineageKind::Replace => 1,
                    DagLineageKind::Merge => 2,
                },
            );
        }
        AgentDagDraftDigest::from_bytes(*hasher.finalize().as_bytes())
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum AgentDagDraftError {
    #[error("Agent DAG draft node count does not match its revision")]
    NodeCountMismatch,
    #[error("Agent DAG draft lineage exceeds the DAG bound")]
    LineageTooLarge,
    #[error("Agent DAG draft node attribution does not match its revision")]
    NodeAttributionMismatch,
    #[error("Agent DAG draft node projection is invalid")]
    ProjectionMismatch,
}

fn hash_u8(hasher: &mut Hasher, value: u8) {
    hasher.update(&[value]);
}

fn hash_i64(hasher: &mut Hasher, value: i64) {
    hasher.update(&value.to_le_bytes());
}

fn hash_u64(hasher: &mut Hasher, value: u64) {
    hasher.update(&value.to_le_bytes());
}

fn hash_uuid(hasher: &mut Hasher, value: Uuid) {
    hash_bytes(hasher, value.as_bytes());
}

fn hash_bytes(hasher: &mut Hasher, value: &[u8]) {
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value);
}

fn hash_text(hasher: &mut Hasher, value: &str) {
    hash_bytes(hasher, value.as_bytes());
}

fn hash_definition(hasher: &mut Hasher, definition: &DagNodeDefinition) {
    hash_uuid(hasher, definition.id().into_uuid());
    hash_i64(hasher, i64::from(definition.ordinal().get()));
    hash_text(hasher, definition.title().as_str());
    hash_text(hasher, definition.objective().as_str());
    hash_u64(hasher, definition.acceptance().len() as u64);
    for criterion in definition.acceptance() {
        hash_text(hasher, criterion.as_str());
    }
}

fn hash_edge(hasher: &mut Hasher, edge: DagEdge) {
    hash_uuid(hasher, edge.upstream().into_uuid());
    hash_uuid(hasher, edge.downstream().into_uuid());
}

fn hash_registered_node(hasher: &mut Hasher, node: &RegisteredDagNode) {
    hash_uuid(hasher, node.goal_id().into_uuid());
    hash_i64(hasher, node.dag_revision().get());
    hash_definition(hasher, node.definition());
    match node.lifecycle() {
        DagNodeLifecycle::Pending => hash_u8(hasher, 0),
        DagNodeLifecycle::Active => hash_u8(hasher, 1),
        DagNodeLifecycle::Blocked(reason) => {
            hash_u8(hasher, 2);
            hash_text(hasher, reason.as_str());
        }
        DagNodeLifecycle::Completed => hash_u8(hasher, 3),
        DagNodeLifecycle::Failed(reason) => {
            hash_u8(hasher, 4);
            hash_text(hasher, reason.as_str());
        }
        DagNodeLifecycle::Skipped(reason) => {
            hash_u8(hasher, 5);
            hash_text(hasher, reason.as_str());
        }
        DagNodeLifecycle::Cancelled => hash_u8(hasher, 6),
    }
    hash_i64(hasher, node.created_at().get());
    hash_i64(hasher, node.updated_at().get());
    hash_i64(hasher, node.revision().get());
}

/// Typed request for one immutable initial or successor Coordinator-authorized DAG plan.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentDagPlanRequest {
    id: AgentDagPlanRequestId,
    actor: crate::ActivityCoordinatorActor,
    goal: GoalAttribution,
    expected_parent_revision: Option<DagRevisionNumber>,
    expected_head_revision: Option<DagHeadRevision>,
    draft: AgentDagDraft,
    history_update_id: AgentWorkUpdateId,
    history_update_sequence: AgentWorkUpdateSequence,
    observed_at: TimestampMillis,
}

impl AgentDagPlanRequest {
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        id: AgentDagPlanRequestId,
        actor: crate::ActivityCoordinatorActor,
        goal: GoalAttribution,
        expected_parent_revision: Option<DagRevisionNumber>,
        expected_head_revision: Option<DagHeadRevision>,
        draft: AgentDagDraft,
        history_update_id: AgentWorkUpdateId,
        history_update_sequence: AgentWorkUpdateSequence,
        observed_at: TimestampMillis,
    ) -> Self {
        Self {
            id,
            actor,
            goal,
            expected_parent_revision,
            expected_head_revision,
            draft,
            history_update_id,
            history_update_sequence,
            observed_at,
        }
    }

    pub const fn id(&self) -> AgentDagPlanRequestId {
        self.id
    }

    pub const fn actor(&self) -> crate::ActivityCoordinatorActor {
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

    pub const fn draft(&self) -> &AgentDagDraft {
        &self.draft
    }

    pub const fn history_update_id(&self) -> AgentWorkUpdateId {
        self.history_update_id
    }

    pub const fn history_update_sequence(&self) -> AgentWorkUpdateSequence {
        self.history_update_sequence
    }

    pub const fn observed_at(&self) -> TimestampMillis {
        self.observed_at
    }

    pub fn digest(&self) -> AgentDagDraftDigest {
        self.draft.digest()
    }
}

/// Public receipt for a committed or idempotently replayed Coordinator DAG plan.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentDagPlanReceipt {
    request_id: AgentDagPlanRequestId,
    digest: AgentDagDraftDigest,
    dag_revision_id: DagRevisionId,
    dag_revision: DagRevisionNumber,
    committed_at: TimestampMillis,
    replayed: bool,
}

impl AgentDagPlanReceipt {
    pub const fn new(
        request_id: AgentDagPlanRequestId,
        digest: AgentDagDraftDigest,
        dag_revision_id: DagRevisionId,
        dag_revision: DagRevisionNumber,
        committed_at: TimestampMillis,
        replayed: bool,
    ) -> Self {
        Self {
            request_id,
            digest,
            dag_revision_id,
            dag_revision,
            committed_at,
            replayed,
        }
    }

    pub const fn request_id(self) -> AgentDagPlanRequestId {
        self.request_id
    }

    pub const fn digest(self) -> AgentDagDraftDigest {
        self.digest
    }

    pub const fn dag_revision_id(self) -> DagRevisionId {
        self.dag_revision_id
    }

    pub const fn dag_revision(self) -> DagRevisionNumber {
        self.dag_revision
    }

    pub const fn committed_at(self) -> TimestampMillis {
        self.committed_at
    }

    pub const fn replayed(self) -> bool {
        self.replayed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DagAcceptanceCriterion, DagNodeId, DagNodeObjective, DagNodeOrdinal, DagNodeTitle, GoalId,
        GoalRevision,
    };

    fn goal_id() -> GoalId {
        GoalId::from_uuid(Uuid::from_u128(4))
    }

    #[test]
    fn draft_digest_is_independent_of_node_input_order() -> Result<(), Box<dyn std::error::Error>> {
        let goal_id = goal_id();
        let first = DagNodeDefinition::new(
            DagNodeId::from_uuid(Uuid::from_u128(10)),
            DagNodeOrdinal::new(0)?,
            DagNodeTitle::new("First".to_owned())?,
            DagNodeObjective::new("Do first".to_owned())?,
            vec![DagAcceptanceCriterion::new("done".to_owned())?],
        )?;
        let second = DagNodeDefinition::new(
            DagNodeId::from_uuid(Uuid::from_u128(11)),
            DagNodeOrdinal::new(1)?,
            DagNodeTitle::new("Second".to_owned())?,
            DagNodeObjective::new("Do second".to_owned())?,
            vec![DagAcceptanceCriterion::new("done".to_owned())?],
        )?;
        let revision = DagRevision::new(
            DagRevisionId::from_uuid(Uuid::from_u128(12)),
            goal_id,
            GoalRevision::INITIAL,
            DagRevisionNumber::INITIAL,
            None,
            vec![first.clone(), second.clone()],
            Vec::new(),
            TimestampMillis::new(1)?,
        )?;
        let first_node = RegisteredDagNode::create(
            goal_id,
            DagRevisionNumber::INITIAL,
            first,
            TimestampMillis::new(1)?,
        );
        let second_node = RegisteredDagNode::create(
            goal_id,
            DagRevisionNumber::INITIAL,
            second,
            TimestampMillis::new(1)?,
        );
        let left = AgentDagDraft::new(
            revision.clone(),
            vec![first_node.clone(), second_node.clone()],
            Vec::new(),
        )?;
        let right = AgentDagDraft::new(revision, vec![second_node, first_node], Vec::new())?;
        assert_eq!(left.digest(), right.digest());
        Ok(())
    }
}
