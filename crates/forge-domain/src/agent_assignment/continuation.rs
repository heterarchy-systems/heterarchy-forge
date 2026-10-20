//! Pure assignment continuation planning from an exact work-cut witness.
//!
//! A plan is not a registered successor or an effect capability. Persistence
//! must verify the complete cut, current election authority, source handback,
//! worktree evidence, effect drain and authenticated recipient acceptance before
//! committing both sides, continuation lineage, focus changes and cut release.
//! Keeping this type separate prevents the ordinary assignment writer from
//! silently dropping lineage or interpreting a continuation as a fresh offer.

use thiserror::Error;
use uuid::Uuid;

use super::{
    AgentAssignmentId, AgentAssignmentRevision, AgentAssignmentState, AgentAssignmentTarget,
    AgentAssignmentTransitionError, RegisteredAgentAssignment, WorkCreditBudget,
};
use crate::{
    DagNodeLifecycle, DagNodeRevision, DagRevision, RegisteredDagNode, TimestampMillis,
    WorkCutNodeScope, WorkCutRequest, WorkCutRequestDigest, WorkCutScope,
};

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentAssignmentContinuationPlan {
    transfer_id: Uuid,
    cut_id: Uuid,
    cut_request_digest: WorkCutRequestDigest,
    cut_snapshot_digest: [u8; 32],
    source_scope: WorkCutNodeScope,
    source: RegisteredAgentAssignment,
    retired: RegisteredAgentAssignment,
    successor_id: AgentAssignmentId,
    recipient: AgentAssignmentTarget,
    node_revision: DagNodeRevision,
    observed_at: TimestampMillis,
}

impl AgentAssignmentContinuationPlan {
    /// Calculate a prospective interruption and a distinct successor description.
    ///
    /// `node` and `source_scope` must later be compared with the stored cut and
    /// live source in the committing transaction. Supplied digests and bindings
    /// are correlation data, not proof that a caller is the governance issuer.
    /// A recipient may be the original Coordinator; this does not authorize an
    /// ordinary self-offer, self-review, or any broader planning mutation.
    ///
    /// # Errors
    /// Rejects inconsistent identities, cut parties, Activity/generation/node
    /// scopes, source revisions, lifecycle states, cancellation and clocks.
    #[allow(
        clippy::too_many_arguments,
        reason = "one transition binds the complete source, cut, node and recipient observation"
    )]
    pub fn new(
        transfer_id: Uuid,
        successor_id: AgentAssignmentId,
        cut: &WorkCutRequest,
        cut_snapshot_digest: [u8; 32],
        source: &RegisteredAgentAssignment,
        expected_source_revision: AgentAssignmentRevision,
        source_scope: WorkCutNodeScope,
        dag: &DagRevision,
        node: &RegisteredDagNode,
        recipient: AgentAssignmentTarget,
        observed_at: TimestampMillis,
    ) -> Result<Self, AgentAssignmentContinuationError> {
        if transfer_id.is_nil()
            || successor_id.into_uuid().is_nil()
            || source.id().into_uuid().is_nil()
            || successor_id == source.id()
            || cut_snapshot_digest == [0; 32]
        {
            return Err(AgentAssignmentContinuationError::Identity);
        }
        validate_bindings(cut, source, recipient)?;
        validate_scope(cut, source, source_scope, dag, node)?;
        if source.cancellation_requested() {
            return Err(AgentAssignmentContinuationError::CancellationPending);
        }
        if !matches!(
            (source.state(), node.lifecycle()),
            (
                AgentAssignmentState::Offered,
                DagNodeLifecycle::Pending | DagNodeLifecycle::Blocked(_)
            ) | (
                AgentAssignmentState::Running,
                DagNodeLifecycle::Active | DagNodeLifecycle::Blocked(_)
            )
        ) {
            return Err(AgentAssignmentContinuationError::Lifecycle);
        }
        if observed_at < node.updated_at() || observed_at < dag.created_at() {
            return Err(AgentAssignmentTransitionError::TimestampOrder.into());
        }
        let retired = source.interrupt(expected_source_revision, observed_at)?;
        Ok(Self {
            transfer_id,
            cut_id: cut.cut_id(),
            cut_request_digest: cut.request_digest(),
            cut_snapshot_digest,
            source_scope,
            source: source.clone(),
            retired,
            successor_id,
            recipient,
            node_revision: node.revision(),
            observed_at,
        })
    }

    pub const fn transfer_id(&self) -> Uuid {
        self.transfer_id
    }
    pub const fn cut_id(&self) -> Uuid {
        self.cut_id
    }
    pub const fn cut_request_digest(&self) -> WorkCutRequestDigest {
        self.cut_request_digest
    }
    pub const fn cut_snapshot_digest(&self) -> &[u8; 32] {
        &self.cut_snapshot_digest
    }
    pub const fn source_scope(&self) -> WorkCutNodeScope {
        self.source_scope
    }
    pub const fn source_assignment(&self) -> &RegisteredAgentAssignment {
        &self.source
    }
    /// Prospective interruption only; the original source remains unchanged.
    pub const fn retired_assignment(&self) -> &RegisteredAgentAssignment {
        &self.retired
    }
    pub const fn successor_id(&self) -> AgentAssignmentId {
        self.successor_id
    }
    pub const fn recipient(&self) -> AgentAssignmentTarget {
        self.recipient
    }
    pub const fn successor_state(&self) -> AgentAssignmentState {
        self.source.state()
    }
    pub const fn node_revision(&self) -> DagNodeRevision {
        self.node_revision
    }
    /// Inherit the original budget; this is neither an award nor a new budget.
    pub const fn credit_budget(&self) -> Option<WorkCreditBudget> {
        self.source.credit_budget()
    }
    pub const fn observed_at(&self) -> TimestampMillis {
        self.observed_at
    }
}

fn validate_bindings(
    cut: &WorkCutRequest,
    source: &RegisteredAgentAssignment,
    recipient: AgentAssignmentTarget,
) -> Result<(), AgentAssignmentContinuationError> {
    if source.workspace_id() != cut.workspace_id() {
        return Err(AgentAssignmentContinuationError::Scope);
    }
    let source_target = source.target();
    let source_binding = cut.bindings().iter().find(|binding| {
        binding.agent_id() == source_target.agent_id()
            && binding.session_id() == source_target.session_id()
            && binding.principal() == source_target.principal()
            && binding.activity_id() == source.activity_id()
    });
    let recipient_binding = cut.bindings().iter().find(|binding| {
        binding.agent_id() == recipient.agent_id()
            && binding.session_id() == recipient.session_id()
            && binding.principal() == recipient.principal()
    });
    let (Some(source_binding), Some(recipient_binding)) = (source_binding, recipient_binding)
    else {
        return Err(AgentAssignmentContinuationError::Binding);
    };
    if source_binding.side() == recipient_binding.side() {
        return Err(AgentAssignmentContinuationError::Party);
    }
    if recipient_binding.activity_id() != source.activity_id() {
        return Err(AgentAssignmentContinuationError::Activity);
    }
    Ok(())
}

fn validate_scope(
    cut: &WorkCutRequest,
    source: &RegisteredAgentAssignment,
    scope: WorkCutNodeScope,
    dag: &DagRevision,
    node: &RegisteredDagNode,
) -> Result<(), AgentAssignmentContinuationError> {
    if scope.activity_id() != source.activity_id()
        || scope.goal_id() != source.goal_id()
        || scope.goal_created_at() != source.goal_created_at()
        || scope.dag_revision() != source.dag_revision()
        || scope.node_id() != source.node_id()
    {
        return Err(AgentAssignmentContinuationError::Scope);
    }
    if let WorkCutScope::Team { nodes, .. } = cut.scope()
        && !nodes.contains(&scope)
    {
        return Err(AgentAssignmentContinuationError::Scope);
    }
    // The immutable DAG base may differ from the Goal revision captured by the
    // assignment after a later Goal edit. Only the actual DAG supplies its base.
    if dag.goal_id() != scope.goal_id()
        || dag.number() != scope.dag_revision()
        || dag.base_goal_revision() != scope.dag_base_goal_revision()
        || !dag
            .nodes()
            .iter()
            .any(|definition| definition == node.definition())
        || node.goal_id() != scope.goal_id()
        || node.dag_revision() != scope.dag_revision()
        || node.id() != scope.node_id()
        || node.revision() < source.node_revision()
    {
        return Err(AgentAssignmentContinuationError::Node);
    }
    Ok(())
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum AgentAssignmentContinuationError {
    #[error("assignment continuation identity or cut digest is invalid")]
    Identity,
    #[error("assignment continuation binding is absent from the exact cut")]
    Binding,
    #[error("assignment continuation must receive the opposite party's work")]
    Party,
    #[error("assignment continuation requires a recipient bound to the source Activity")]
    Activity,
    #[error("assignment continuation source scope conflicts with the cut")]
    Scope,
    #[error("assignment continuation node observation conflicts")]
    Node,
    #[error("assignment continuation cannot override pending cancellation")]
    CancellationPending,
    #[error("assignment continuation requires unsubmitted, nonterminal work")]
    Lifecycle,
    #[error(transparent)]
    Transition(#[from] AgentAssignmentTransitionError),
}
