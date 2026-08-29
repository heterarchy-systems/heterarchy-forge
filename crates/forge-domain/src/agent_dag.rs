//! Typed, bounded one-shot Agent DAG authoring contracts.
//!
//! A grant is a narrow capability for one exact Workspace/Agent/Activity,
//! credential, Goal revision, and current DAG head.  It is not an execution
//! permission and it never creates continuation work.  Replanning is one
//! immutable successor DAG revision; persistence owns the final CAS/ledger
//! transaction.

use std::fmt;
use std::str::FromStr;

use blake3::Hasher;
use thiserror::Error;
use uuid::Uuid;

use crate::{
    ActivityId, AgentInstanceId, AgentWorkUpdateId, AgentWorkUpdateSequence, DagEdge,
    DagHeadRevision, DagLineageKind, DagNodeDefinition, DagNodeLifecycle, DagNodeLineage,
    DagRevision, DagRevisionId, DagRevisionNumber, GoalAttribution, McpTokenId, RegisteredDagNode,
    TimestampMillis, WorkspaceId,
};

pub const DEFAULT_AGENT_DAG_AUTHORING_GRANT_TTL_MILLIS: i64 = 5 * 60 * 1_000;
pub const MAX_AGENT_DAG_AUTHORING_GRANT_TTL_MILLIS: i64 = 15 * 60 * 1_000;
pub const MAX_AGENT_DAG_REPLAN_REQUESTS: usize = 256;

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
    AgentDagAuthoringGrantId,
    AgentDagAuthoringGrantIdParseError,
    "invalid Agent DAG authoring grant UUID"
);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AgentDagAuthoringGrantRevision(i64);

impl AgentDagAuthoringGrantRevision {
    pub const INITIAL: Self = Self(1);

    pub const fn new(value: i64) -> Result<Self, AgentDagAuthoringGrantRevisionError> {
        if value < 1 {
            Err(AgentDagAuthoringGrantRevisionError::Invalid { actual: value })
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> i64 {
        self.0
    }

    pub const fn checked_next(self) -> Result<Self, AgentDagAuthoringGrantRevisionError> {
        match self.0.checked_add(1) {
            Some(value) => Ok(Self(value)),
            None => Err(AgentDagAuthoringGrantRevisionError::Overflow { current: self.0 }),
        }
    }
}

impl fmt::Display for AgentDagAuthoringGrantRevision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum AgentDagAuthoringGrantRevisionError {
    #[error("Agent DAG authoring grant revision must be at least 1, got {actual}")]
    Invalid { actual: i64 },
    #[error("Agent DAG authoring grant revision overflowed at {current}")]
    Overflow { current: i64 },
}
uuid_identity!(
    AgentDagReplanRequestId,
    AgentDagReplanRequestIdParseError,
    "invalid Agent DAG replan request UUID"
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

/// Explicit credential identity bound into an authoring grant.  Raw bearer
/// values never enter the domain; trusted stdio is an explicit adapter claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AgentAuthoringCredential {
    Token(McpTokenId),
    TrustedStdio,
}

impl AgentAuthoringCredential {
    pub const fn token_id(self) -> Option<McpTokenId> {
        match self {
            Self::Token(id) => Some(id),
            Self::TrustedStdio => None,
        }
    }

    pub const fn is_trusted_stdio(self) -> bool {
        matches!(self, Self::TrustedStdio)
    }
}

/// Actor tuple that must match a grant and a replay-ledger row exactly.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AgentDagAuthoringActor {
    workspace_id: WorkspaceId,
    agent_id: AgentInstanceId,
    activity_id: ActivityId,
    credential: AgentAuthoringCredential,
}

impl AgentDagAuthoringActor {
    pub const fn new(
        workspace_id: WorkspaceId,
        agent_id: AgentInstanceId,
        activity_id: ActivityId,
        credential: AgentAuthoringCredential,
    ) -> Self {
        Self {
            workspace_id,
            agent_id,
            activity_id,
            credential,
        }
    }

    pub const fn workspace_id(self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn agent_id(self) -> AgentInstanceId {
        self.agent_id
    }

    pub const fn activity_id(self) -> ActivityId {
        self.activity_id
    }

    pub const fn credential(self) -> AgentAuthoringCredential {
        self.credential
    }
}

/// Bounded grant TTL.  The grant constructor computes expiry only from the
/// caller-supplied issue time and this explicit duration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AgentDagAuthoringGrantTtl(i64);

impl AgentDagAuthoringGrantTtl {
    pub const DEFAULT: Self = Self(DEFAULT_AGENT_DAG_AUTHORING_GRANT_TTL_MILLIS);
    pub const MAX: Self = Self(MAX_AGENT_DAG_AUTHORING_GRANT_TTL_MILLIS);

    pub const fn new(value: i64) -> Result<Self, AgentDagAuthoringGrantTtlError> {
        if value <= 0 || value > MAX_AGENT_DAG_AUTHORING_GRANT_TTL_MILLIS {
            Err(AgentDagAuthoringGrantTtlError::OutOfRange {
                actual: value,
                maximum: MAX_AGENT_DAG_AUTHORING_GRANT_TTL_MILLIS,
            })
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> i64 {
        self.0
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum AgentDagAuthoringGrantTtlError {
    #[error("Agent DAG authoring grant TTL {actual} is outside 1..={maximum} ms")]
    OutOfRange { actual: i64, maximum: i64 },
    #[error("Agent DAG authoring grant expiry overflowed")]
    Overflow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AgentDagAuthoringGrantState {
    Active,
    Consumed,
    Revoked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AgentDagAuthoringGrantAvailability {
    Available,
    Expired,
    Consumed,
    Revoked,
}

impl AgentDagAuthoringGrantAvailability {
    pub const fn is_available(self) -> bool {
        matches!(self, Self::Available)
    }
}

/// Durable one-shot authoring capability bound to an exact DAG head.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentDagAuthoringGrant {
    id: AgentDagAuthoringGrantId,
    actor: AgentDagAuthoringActor,
    goal: GoalAttribution,
    expected_dag_revision: DagRevisionNumber,
    expected_head_revision: DagHeadRevision,
    issued_at: TimestampMillis,
    expires_at: TimestampMillis,
    state: AgentDagAuthoringGrantState,
    revision: AgentDagAuthoringGrantRevision,
}

impl AgentDagAuthoringGrant {
    pub fn issue(
        id: AgentDagAuthoringGrantId,
        actor: AgentDagAuthoringActor,
        goal: GoalAttribution,
        expected_dag_revision: DagRevisionNumber,
        expected_head_revision: DagHeadRevision,
        issued_at: TimestampMillis,
        ttl: AgentDagAuthoringGrantTtl,
    ) -> Result<Self, AgentDagAuthoringGrantError> {
        let expires_at = issued_at
            .get()
            .checked_add(ttl.get())
            .ok_or(AgentDagAuthoringGrantError::ExpiryOverflow)?;
        let expires_at = TimestampMillis::new(expires_at)
            .map_err(|_| AgentDagAuthoringGrantError::ExpiryOverflow)?;
        Ok(Self {
            id,
            actor,
            goal,
            expected_dag_revision,
            expected_head_revision,
            issued_at,
            expires_at,
            state: AgentDagAuthoringGrantState::Active,
            revision: AgentDagAuthoringGrantRevision::INITIAL,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        id: AgentDagAuthoringGrantId,
        actor: AgentDagAuthoringActor,
        goal: GoalAttribution,
        expected_dag_revision: DagRevisionNumber,
        expected_head_revision: DagHeadRevision,
        issued_at: TimestampMillis,
        expires_at: TimestampMillis,
        state: AgentDagAuthoringGrantState,
        revision: AgentDagAuthoringGrantRevision,
    ) -> Result<Self, AgentDagAuthoringGrantError> {
        let ttl = expires_at
            .get()
            .checked_sub(issued_at.get())
            .ok_or(AgentDagAuthoringGrantError::TimestampOrder)?;
        AgentDagAuthoringGrantTtl::new(ttl).map_err(|_| AgentDagAuthoringGrantError::InvalidTtl)?;
        if revision == AgentDagAuthoringGrantRevision::INITIAL
            && state != AgentDagAuthoringGrantState::Active
        {
            return Err(AgentDagAuthoringGrantError::InvalidInitialState);
        }
        Ok(Self {
            id,
            actor,
            goal,
            expected_dag_revision,
            expected_head_revision,
            issued_at,
            expires_at,
            state,
            revision,
        })
    }

    pub const fn id(&self) -> AgentDagAuthoringGrantId {
        self.id
    }

    pub const fn actor(&self) -> AgentDagAuthoringActor {
        self.actor
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.actor.workspace_id()
    }

    pub const fn agent_id(&self) -> AgentInstanceId {
        self.actor.agent_id()
    }

    pub const fn activity_id(&self) -> ActivityId {
        self.actor.activity_id()
    }

    pub const fn credential(&self) -> AgentAuthoringCredential {
        self.actor.credential()
    }

    pub const fn goal(&self) -> GoalAttribution {
        self.goal
    }

    pub const fn expected_dag_revision(&self) -> DagRevisionNumber {
        self.expected_dag_revision
    }

    pub const fn expected_head_revision(&self) -> DagHeadRevision {
        self.expected_head_revision
    }

    pub const fn issued_at(&self) -> TimestampMillis {
        self.issued_at
    }

    pub const fn expires_at(&self) -> TimestampMillis {
        self.expires_at
    }

    pub const fn state(&self) -> AgentDagAuthoringGrantState {
        self.state
    }

    pub const fn revision(&self) -> AgentDagAuthoringGrantRevision {
        self.revision
    }

    pub const fn availability(&self, now: TimestampMillis) -> AgentDagAuthoringGrantAvailability {
        match self.state {
            AgentDagAuthoringGrantState::Consumed => AgentDagAuthoringGrantAvailability::Consumed,
            AgentDagAuthoringGrantState::Revoked => AgentDagAuthoringGrantAvailability::Revoked,
            AgentDagAuthoringGrantState::Active if now.get() < self.expires_at.get() => {
                AgentDagAuthoringGrantAvailability::Available
            }
            AgentDagAuthoringGrantState::Active => AgentDagAuthoringGrantAvailability::Expired,
        }
    }

    pub fn consume(
        &self,
        expected_revision: AgentDagAuthoringGrantRevision,
    ) -> Result<Self, AgentDagAuthoringGrantError> {
        if self.revision != expected_revision {
            return Err(AgentDagAuthoringGrantError::RevisionConflict);
        }
        if self.state != AgentDagAuthoringGrantState::Active {
            return Err(AgentDagAuthoringGrantError::NotActive);
        }
        Ok(Self {
            state: AgentDagAuthoringGrantState::Consumed,
            revision: self
                .revision
                .checked_next()
                .map_err(|_| AgentDagAuthoringGrantError::RevisionOverflow)?,
            ..self.clone()
        })
    }

    pub fn revoke(
        &self,
        expected_revision: AgentDagAuthoringGrantRevision,
    ) -> Result<Self, AgentDagAuthoringGrantError> {
        if self.revision != expected_revision {
            return Err(AgentDagAuthoringGrantError::RevisionConflict);
        }
        if self.state != AgentDagAuthoringGrantState::Active {
            return Err(AgentDagAuthoringGrantError::NotActive);
        }
        Ok(Self {
            state: AgentDagAuthoringGrantState::Revoked,
            revision: self
                .revision
                .checked_next()
                .map_err(|_| AgentDagAuthoringGrantError::RevisionOverflow)?,
            ..self.clone()
        })
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum AgentDagAuthoringGrantError {
    #[error("Agent DAG authoring grant expiry overflowed")]
    ExpiryOverflow,
    #[error("Agent DAG authoring grant timestamps are out of order")]
    TimestampOrder,
    #[error("Agent DAG authoring grant TTL is invalid")]
    InvalidTtl,
    #[error("Agent DAG authoring grant initial state is invalid")]
    InvalidInitialState,
    #[error("Agent DAG authoring grant revision conflicts")]
    RevisionConflict,
    #[error("Agent DAG authoring grant is not active")]
    NotActive,
    #[error("Agent DAG authoring grant revision overflowed")]
    RevisionOverflow,
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

/// Typed request for one one-shot immutable successor DAG commit.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentDagReplanRequest {
    id: AgentDagReplanRequestId,
    grant_id: AgentDagAuthoringGrantId,
    expected_grant_revision: AgentDagAuthoringGrantRevision,
    actor: AgentDagAuthoringActor,
    draft: AgentDagDraft,
    history_update_id: AgentWorkUpdateId,
    history_update_sequence: AgentWorkUpdateSequence,
    observed_at: TimestampMillis,
}

impl AgentDagReplanRequest {
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        id: AgentDagReplanRequestId,
        grant_id: AgentDagAuthoringGrantId,
        expected_grant_revision: AgentDagAuthoringGrantRevision,
        actor: AgentDagAuthoringActor,
        draft: AgentDagDraft,
        history_update_id: AgentWorkUpdateId,
        history_update_sequence: AgentWorkUpdateSequence,
        observed_at: TimestampMillis,
    ) -> Self {
        Self {
            id,
            grant_id,
            expected_grant_revision,
            actor,
            draft,
            history_update_id,
            history_update_sequence,
            observed_at,
        }
    }

    pub const fn id(&self) -> AgentDagReplanRequestId {
        self.id
    }

    pub const fn grant_id(&self) -> AgentDagAuthoringGrantId {
        self.grant_id
    }

    pub const fn expected_grant_revision(&self) -> AgentDagAuthoringGrantRevision {
        self.expected_grant_revision
    }

    pub const fn actor(&self) -> AgentDagAuthoringActor {
        self.actor
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

/// Public receipt for a committed or replayed replan ledger entry.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentDagReplanReceipt {
    request_id: AgentDagReplanRequestId,
    grant_id: AgentDagAuthoringGrantId,
    digest: AgentDagDraftDigest,
    dag_revision_id: DagRevisionId,
    dag_revision: DagRevisionNumber,
    committed_at: TimestampMillis,
    replayed: bool,
}

impl AgentDagReplanReceipt {
    pub const fn new(
        request_id: AgentDagReplanRequestId,
        grant_id: AgentDagAuthoringGrantId,
        digest: AgentDagDraftDigest,
        dag_revision_id: DagRevisionId,
        dag_revision: DagRevisionNumber,
        committed_at: TimestampMillis,
        replayed: bool,
    ) -> Self {
        Self {
            request_id,
            grant_id,
            digest,
            dag_revision_id,
            dag_revision,
            committed_at,
            replayed,
        }
    }

    pub const fn request_id(self) -> AgentDagReplanRequestId {
        self.request_id
    }

    pub const fn grant_id(self) -> AgentDagAuthoringGrantId {
        self.grant_id
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

    fn ids() -> (WorkspaceId, AgentInstanceId, ActivityId, GoalId) {
        (
            WorkspaceId::from_uuid(Uuid::from_u128(1)),
            AgentInstanceId::from_uuid(Uuid::from_u128(2)),
            ActivityId::from_uuid(Uuid::from_u128(3)),
            GoalId::from_uuid(Uuid::from_u128(4)),
        )
    }

    #[test]
    fn grant_ttl_and_availability_are_bounded() -> Result<(), Box<dyn std::error::Error>> {
        let (workspace, agent, activity, goal_id) = ids();
        assert!(AgentDagAuthoringGrantTtl::new(0).is_err());
        assert!(
            AgentDagAuthoringGrantTtl::new(MAX_AGENT_DAG_AUTHORING_GRANT_TTL_MILLIS + 1).is_err()
        );
        let grant = AgentDagAuthoringGrant::issue(
            AgentDagAuthoringGrantId::from_uuid(Uuid::from_u128(5)),
            AgentDagAuthoringActor::new(
                workspace,
                agent,
                activity,
                AgentAuthoringCredential::TrustedStdio,
            ),
            GoalAttribution::new(goal_id, GoalRevision::INITIAL),
            DagRevisionNumber::INITIAL,
            DagHeadRevision::INITIAL,
            TimestampMillis::new(10)?,
            AgentDagAuthoringGrantTtl::DEFAULT,
        )?;
        assert!(grant.availability(TimestampMillis::new(10)?).is_available());
        assert!(matches!(
            grant.availability(TimestampMillis::new(
                10 + DEFAULT_AGENT_DAG_AUTHORING_GRANT_TTL_MILLIS
            )?),
            AgentDagAuthoringGrantAvailability::Expired
        ));
        let consumed = grant.consume(grant.revision())?;
        assert_eq!(
            consumed.availability(TimestampMillis::new(10)?),
            AgentDagAuthoringGrantAvailability::Consumed
        );
        Ok(())
    }

    #[test]
    fn draft_digest_is_independent_of_node_input_order() -> Result<(), Box<dyn std::error::Error>> {
        let (_, _, _, goal_id) = ids();
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
