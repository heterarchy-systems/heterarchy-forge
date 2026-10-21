//! Typed authority fences for expired Activity successor recovery.
//!
//! Recovery deliberately has its own contract.  These values contain only
//! durable identity and observations; clocks, persistence, process identity,
//! and effects remain owned by the control/persistence boundaries.

use std::fmt;

use thiserror::Error;
use uuid::Uuid;

use crate::{
    ActivityId, ActivityLeaseRevision, ActivityRevision, AgentAttachmentState, AgentDeclaredRole,
    AgentDisplayName, AgentFocus, AgentInstanceId, AgentSessionId, AgentTransportKind,
    AuthenticatedPrincipal, DagNodeId, DagNodeRevision, DagRevisionNumber, GoalAttribution,
    LocationId, LocationRevision, RuntimeInstanceId, TimestampMillis, WorkspaceId,
    WorkspaceRevision, WorkspaceRootFingerprint,
};

pub const EXPIRED_ACTIVITY_RECOVERY_DIGEST_BYTES: usize = 32;
pub const EXPIRED_ACTIVITY_RECOVERY_MAX_LOCATOR_BYTES: usize = 4_096;
pub const EXPIRED_ACTIVITY_RECOVERY_MAX_AGENT_COUNT: u16 = 256;

/// The only source-freeze state accepted by the v1 recovery contract.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExpiredActivityRecoveryFreezeState {
    Frozen,
}

/// Complete predecessor CAS fence captured by the authenticated probe.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExpectedExpiredActivity {
    activity_id: ActivityId,
    revision: ActivityRevision,
    created_at: TimestampMillis,
    updated_at: TimestampMillis,
    lease_owner_id: RuntimeInstanceId,
    lease_until: TimestampMillis,
    lease_revision: ActivityLeaseRevision,
}

impl ExpectedExpiredActivity {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        activity_id: ActivityId,
        revision: ActivityRevision,
        created_at: TimestampMillis,
        updated_at: TimestampMillis,
        lease_owner_id: RuntimeInstanceId,
        lease_until: TimestampMillis,
        lease_revision: ActivityLeaseRevision,
    ) -> Result<Self, ExpiredActivityRecoveryValidationError> {
        if activity_id.into_uuid().is_nil() || lease_owner_id.into_uuid().is_nil() {
            return Err(ExpiredActivityRecoveryValidationError::NilIdentity);
        }
        if updated_at.get() < created_at.get() {
            return Err(ExpiredActivityRecoveryValidationError::TimestampOrder);
        }
        Ok(Self {
            activity_id,
            revision,
            created_at,
            updated_at,
            lease_owner_id,
            lease_until,
            lease_revision,
        })
    }

    pub const fn activity_id(self) -> ActivityId {
        self.activity_id
    }
    pub const fn revision(self) -> ActivityRevision {
        self.revision
    }
    pub const fn created_at(self) -> TimestampMillis {
        self.created_at
    }
    pub const fn updated_at(self) -> TimestampMillis {
        self.updated_at
    }
    pub const fn lease_owner_id(self) -> RuntimeInstanceId {
        self.lease_owner_id
    }
    pub const fn lease_until(self) -> TimestampMillis {
        self.lease_until
    }
    pub const fn lease_revision(self) -> ActivityLeaseRevision {
        self.lease_revision
    }
}

/// Exact Coordinator tuple captured by the probe.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExpectedActivityCoordinator {
    agent_id: AgentInstanceId,
    revision: i64,
    updated_at: TimestampMillis,
}

impl ExpectedActivityCoordinator {
    pub fn new(
        agent_id: AgentInstanceId,
        revision: i64,
        updated_at: TimestampMillis,
    ) -> Result<Self, ExpiredActivityRecoveryValidationError> {
        if agent_id.into_uuid().is_nil() {
            return Err(ExpiredActivityRecoveryValidationError::NilIdentity);
        }
        if revision < 1 {
            return Err(ExpiredActivityRecoveryValidationError::InvalidRevision);
        }
        Ok(Self {
            agent_id,
            revision,
            updated_at,
        })
    }

    pub const fn agent_id(self) -> AgentInstanceId {
        self.agent_id
    }
    pub const fn revision(self) -> i64 {
        self.revision
    }
    pub const fn updated_at(self) -> TimestampMillis {
        self.updated_at
    }
}

/// Exact Workspace/Location/root/history fence used by probe and run.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpiredActivityRecoveryProbeScope {
    workspace_id: WorkspaceId,
    workspace_revision: WorkspaceRevision,
    location_id: LocationId,
    location_revision: LocationRevision,
    locator: Vec<u8>,
    root_fingerprint: WorkspaceRootFingerprint,
    binding_digest: [u8; EXPIRED_ACTIVITY_RECOVERY_DIGEST_BYTES],
}

impl ExpiredActivityRecoveryProbeScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        workspace_id: WorkspaceId,
        workspace_revision: WorkspaceRevision,
        location_id: LocationId,
        location_revision: LocationRevision,
        locator: Vec<u8>,
        root_fingerprint: WorkspaceRootFingerprint,
        binding_digest: [u8; EXPIRED_ACTIVITY_RECOVERY_DIGEST_BYTES],
    ) -> Result<Self, ExpiredActivityRecoveryValidationError> {
        if workspace_id.into_uuid().is_nil() || location_id.into_uuid().is_nil() {
            return Err(ExpiredActivityRecoveryValidationError::NilIdentity);
        }
        if locator.is_empty() || locator.len() > EXPIRED_ACTIVITY_RECOVERY_MAX_LOCATOR_BYTES {
            return Err(ExpiredActivityRecoveryValidationError::LocatorBounds);
        }
        if binding_digest == [0; EXPIRED_ACTIVITY_RECOVERY_DIGEST_BYTES] {
            return Err(ExpiredActivityRecoveryValidationError::ZeroDigest {
                field: "binding_digest",
            });
        }
        Ok(Self {
            workspace_id,
            workspace_revision,
            location_id,
            location_revision,
            locator,
            root_fingerprint,
            binding_digest,
        })
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }
    pub const fn workspace_revision(&self) -> WorkspaceRevision {
        self.workspace_revision
    }
    pub const fn location_id(&self) -> LocationId {
        self.location_id
    }
    pub const fn location_revision(&self) -> LocationRevision {
        self.location_revision
    }
    pub fn locator(&self) -> &[u8] {
        &self.locator
    }
    pub const fn root_fingerprint(&self) -> WorkspaceRootFingerprint {
        self.root_fingerprint
    }
    pub const fn binding_digest(&self) -> &[u8; EXPIRED_ACTIVITY_RECOVERY_DIGEST_BYTES] {
        &self.binding_digest
    }
}

/// Frozen source delegation tuple.  This mirrors the existing source
/// migration/delegation authority without depending on persistence types.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExpiredActivityRecoveryDelegationFence {
    migration_id: Uuid,
    workspace_id: WorkspaceId,
    destination_id: Uuid,
    state: ExpiredActivityRecoveryFreezeState,
    revision: u64,
    created_at: TimestampMillis,
    updated_at: TimestampMillis,
    manifest_digest: [u8; EXPIRED_ACTIVITY_RECOVERY_DIGEST_BYTES],
    delegated_at: TimestampMillis,
}

impl ExpiredActivityRecoveryDelegationFence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        migration_id: Uuid,
        workspace_id: WorkspaceId,
        destination_id: Uuid,
        state: ExpiredActivityRecoveryFreezeState,
        revision: u64,
        created_at: TimestampMillis,
        updated_at: TimestampMillis,
        manifest_digest: [u8; EXPIRED_ACTIVITY_RECOVERY_DIGEST_BYTES],
        delegated_at: TimestampMillis,
    ) -> Result<Self, ExpiredActivityRecoveryValidationError> {
        if migration_id.is_nil() || workspace_id.into_uuid().is_nil() || destination_id.is_nil() {
            return Err(ExpiredActivityRecoveryValidationError::NilIdentity);
        }
        if revision != 1 || updated_at != created_at || delegated_at < updated_at {
            return Err(ExpiredActivityRecoveryValidationError::DelegationFence);
        }
        if manifest_digest == [0; EXPIRED_ACTIVITY_RECOVERY_DIGEST_BYTES] {
            return Err(ExpiredActivityRecoveryValidationError::ZeroDigest {
                field: "manifest_digest",
            });
        }
        Ok(Self {
            migration_id,
            workspace_id,
            destination_id,
            state,
            revision,
            created_at,
            updated_at,
            manifest_digest,
            delegated_at,
        })
    }

    pub const fn migration_id(self) -> Uuid {
        self.migration_id
    }
    pub const fn workspace_id(self) -> WorkspaceId {
        self.workspace_id
    }
    pub const fn destination_id(self) -> Uuid {
        self.destination_id
    }
    pub const fn state(self) -> ExpiredActivityRecoveryFreezeState {
        self.state
    }
    pub const fn revision(self) -> u64 {
        self.revision
    }
    pub const fn created_at(self) -> TimestampMillis {
        self.created_at
    }
    pub const fn updated_at(self) -> TimestampMillis {
        self.updated_at
    }
    pub const fn manifest_digest(self) -> [u8; EXPIRED_ACTIVITY_RECOVERY_DIGEST_BYTES] {
        self.manifest_digest
    }
    pub const fn delegated_at(self) -> TimestampMillis {
        self.delegated_at
    }
}

/// Complete immutable expectation used by the run fence.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpiredActivityRecoveryExpectation {
    predecessor: ExpectedExpiredActivity,
    successor_activity_id: ActivityId,
    initiating_session_id: AgentSessionId,
    principal: AuthenticatedPrincipal,
    expected_agent_count: u16,
    expected_agent_digest: [u8; EXPIRED_ACTIVITY_RECOVERY_DIGEST_BYTES],
    expected_coordinator: Option<ExpectedActivityCoordinator>,
}

impl ExpiredActivityRecoveryExpectation {
    pub fn new(
        predecessor: ExpectedExpiredActivity,
        successor_activity_id: ActivityId,
        initiating_session_id: AgentSessionId,
        principal: AuthenticatedPrincipal,
        expected_agent_count: u16,
        expected_agent_digest: [u8; EXPIRED_ACTIVITY_RECOVERY_DIGEST_BYTES],
        expected_coordinator: Option<ExpectedActivityCoordinator>,
    ) -> Result<Self, ExpiredActivityRecoveryValidationError> {
        if successor_activity_id.into_uuid().is_nil() || initiating_session_id.into_uuid().is_nil()
        {
            return Err(ExpiredActivityRecoveryValidationError::NilIdentity);
        }
        if predecessor.activity_id() == successor_activity_id {
            return Err(ExpiredActivityRecoveryValidationError::SelfLink);
        }
        if !(1..=EXPIRED_ACTIVITY_RECOVERY_MAX_AGENT_COUNT).contains(&expected_agent_count) {
            return Err(ExpiredActivityRecoveryValidationError::AgentCountBounds);
        }
        if expected_agent_digest == [0; EXPIRED_ACTIVITY_RECOVERY_DIGEST_BYTES] {
            return Err(ExpiredActivityRecoveryValidationError::ZeroDigest {
                field: "agent_digest",
            });
        }
        Ok(Self {
            predecessor,
            successor_activity_id,
            initiating_session_id,
            principal,
            expected_agent_count,
            expected_agent_digest,
            expected_coordinator,
        })
    }

    pub const fn predecessor(&self) -> ExpectedExpiredActivity {
        self.predecessor
    }
    pub const fn successor_activity_id(&self) -> ActivityId {
        self.successor_activity_id
    }
    pub const fn initiating_session_id(&self) -> AgentSessionId {
        self.initiating_session_id
    }
    pub const fn principal(&self) -> AuthenticatedPrincipal {
        self.principal
    }
    pub const fn expected_agent_count(&self) -> u16 {
        self.expected_agent_count
    }
    pub const fn expected_agent_digest(&self) -> &[u8; EXPIRED_ACTIVITY_RECOVERY_DIGEST_BYTES] {
        &self.expected_agent_digest
    }
    pub const fn expected_coordinator(&self) -> Option<ExpectedActivityCoordinator> {
        self.expected_coordinator
    }
}

/// Session authority evidence resolved immediately before a first mutation.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExpiredActivityRecoverySessionEvidence {
    session_id: AgentSessionId,
    principal: AuthenticatedPrincipal,
    session_revision: i64,
    session_updated_at: TimestampMillis,
}

impl ExpiredActivityRecoverySessionEvidence {
    pub fn new(
        session_id: AgentSessionId,
        principal: AuthenticatedPrincipal,
        session_revision: i64,
        session_updated_at: TimestampMillis,
    ) -> Result<Self, ExpiredActivityRecoveryValidationError> {
        if session_id.into_uuid().is_nil() || session_revision < 1 {
            return Err(ExpiredActivityRecoveryValidationError::InvalidSession);
        }
        Ok(Self {
            session_id,
            principal,
            session_revision,
            session_updated_at,
        })
    }

    pub const fn session_id(self) -> AgentSessionId {
        self.session_id
    }
    pub const fn principal(self) -> AuthenticatedPrincipal {
        self.principal
    }
    pub const fn session_revision(self) -> i64 {
        self.session_revision
    }
    pub const fn session_updated_at(self) -> TimestampMillis {
        self.session_updated_at
    }
}

/// Full immutable snapshot of one persisted Agent row.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpiredActivityRecoveryAgentSnapshot {
    agent_id: AgentInstanceId,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    session_id: Option<AgentSessionId>,
    display_name: AgentDisplayName,
    declared_role: AgentDeclaredRole,
    transport_kind: AgentTransportKind,
    principal: AuthenticatedPrincipal,
    attachment_state: AgentAttachmentState,
    focus_goal_id: Option<crate::GoalId>,
    focus_goal_revision: Option<crate::GoalRevision>,
    focus_dag_revision: Option<DagRevisionNumber>,
    focus_node_id: Option<DagNodeId>,
    focus_node_revision: Option<DagNodeRevision>,
    created_at: TimestampMillis,
    updated_at: TimestampMillis,
    revision: crate::AgentInstanceRevision,
}

impl ExpiredActivityRecoveryAgentSnapshot {
    pub fn from_agent(agent: &crate::RegisteredAgentInstance) -> Self {
        let focus = agent.focus();
        let (focus_goal_id, focus_goal_revision) = focus.goal().map_or((None, None), |goal| {
            (Some(goal.goal_id()), Some(goal.expected_revision()))
        });
        let (focus_node_id, focus_node_revision) = focus.node().map_or((None, None), |node| {
            (Some(node.node_id()), Some(node.expected_revision()))
        });
        Self {
            agent_id: agent.id(),
            workspace_id: agent.workspace_id(),
            activity_id: agent.activity_id(),
            session_id: agent.session_id(),
            display_name: agent.display_name().clone(),
            declared_role: agent.declared_role().clone(),
            transport_kind: agent.transport_kind(),
            principal: agent.principal(),
            attachment_state: agent.attachment_state(),
            focus_goal_id,
            focus_goal_revision,
            focus_dag_revision: focus.dag_revision(),
            focus_node_id,
            focus_node_revision,
            created_at: agent.created_at(),
            updated_at: agent.updated_at(),
            revision: agent.revision(),
        }
    }

    pub const fn agent_id(&self) -> AgentInstanceId {
        self.agent_id
    }
    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }
    pub const fn activity_id(&self) -> ActivityId {
        self.activity_id
    }
    pub const fn session_id(&self) -> Option<AgentSessionId> {
        self.session_id
    }
    pub const fn display_name(&self) -> &AgentDisplayName {
        &self.display_name
    }
    pub const fn declared_role(&self) -> &AgentDeclaredRole {
        &self.declared_role
    }
    pub const fn transport_kind(&self) -> AgentTransportKind {
        self.transport_kind
    }
    pub const fn principal(&self) -> AuthenticatedPrincipal {
        self.principal
    }
    pub const fn attachment_state(&self) -> AgentAttachmentState {
        self.attachment_state
    }
    pub const fn focus_goal_id(&self) -> Option<crate::GoalId> {
        self.focus_goal_id
    }
    pub const fn focus_goal_revision(&self) -> Option<crate::GoalRevision> {
        self.focus_goal_revision
    }
    pub const fn focus_dag_revision(&self) -> Option<DagRevisionNumber> {
        self.focus_dag_revision
    }
    pub const fn focus_node_id(&self) -> Option<DagNodeId> {
        self.focus_node_id
    }
    pub const fn focus_node_revision(&self) -> Option<DagNodeRevision> {
        self.focus_node_revision
    }
    pub const fn created_at(&self) -> TimestampMillis {
        self.created_at
    }
    pub const fn updated_at(&self) -> TimestampMillis {
        self.updated_at
    }
    pub const fn revision(&self) -> crate::AgentInstanceRevision {
        self.revision
    }

    pub fn focus(&self) -> Result<AgentFocus, ExpiredActivityRecoveryValidationError> {
        let goal = self
            .focus_goal_id
            .zip(self.focus_goal_revision)
            .map(|(id, revision)| GoalAttribution::new(id, revision));
        let node = self
            .focus_node_id
            .zip(self.focus_node_revision)
            .map(|(id, revision)| crate::AgentFocusNode::new(id, revision));
        AgentFocus::new(goal, self.focus_dag_revision, node)
            .map_err(|_| ExpiredActivityRecoveryValidationError::InvalidFocus)
    }
}

/// A read-only recovery snapshot's first blocking authority.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExpiredActivityRecoveryBlocker {
    PendingWorkspaceStop,
    ActiveWorkCut,
    PendingBindingActivation,
    PendingGoalDeletion,
    NonterminalGoal,
    NonterminalCurrentDagNode,
    ActiveExecution,
    ActiveWriterLease,
    StartingCheckpoint,
    UnsettledCheckpointRestore,
    StartingChangeSet,
    PendingDiffEvidence,
    StartingVerification,
    PendingApproval,
    ActiveExecutionGrant,
    ActiveAutoApprovalScope,
    NonterminalAssignment,
}

/// Read-only exact recovery probe returned by persistence.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpiredActivityRecoveryProbe {
    scope: ExpiredActivityRecoveryProbeScope,
    delegation: ExpiredActivityRecoveryDelegationFence,
    delegation_digest: [u8; EXPIRED_ACTIVITY_RECOVERY_DIGEST_BYTES],
    predecessor: ExpectedExpiredActivity,
    agent_count: u16,
    agent_digest: [u8; EXPIRED_ACTIVITY_RECOVERY_DIGEST_BYTES],
    coordinator: Option<ExpectedActivityCoordinator>,
    probe_observed_at: TimestampMillis,
    probe_digest: [u8; EXPIRED_ACTIVITY_RECOVERY_DIGEST_BYTES],
    expired_at_observation: bool,
    blocker: Option<ExpiredActivityRecoveryBlocker>,
}

impl ExpiredActivityRecoveryProbe {
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        scope: ExpiredActivityRecoveryProbeScope,
        delegation: ExpiredActivityRecoveryDelegationFence,
        delegation_digest: [u8; EXPIRED_ACTIVITY_RECOVERY_DIGEST_BYTES],
        predecessor: ExpectedExpiredActivity,
        agent_count: u16,
        agent_digest: [u8; EXPIRED_ACTIVITY_RECOVERY_DIGEST_BYTES],
        coordinator: Option<ExpectedActivityCoordinator>,
        probe_observed_at: TimestampMillis,
        probe_digest: [u8; EXPIRED_ACTIVITY_RECOVERY_DIGEST_BYTES],
        expired_at_observation: bool,
        blocker: Option<ExpiredActivityRecoveryBlocker>,
    ) -> Result<Self, ExpiredActivityRecoveryValidationError> {
        if delegation_digest == [0; EXPIRED_ACTIVITY_RECOVERY_DIGEST_BYTES]
            || agent_digest == [0; EXPIRED_ACTIVITY_RECOVERY_DIGEST_BYTES]
            || probe_digest == [0; EXPIRED_ACTIVITY_RECOVERY_DIGEST_BYTES]
        {
            return Err(ExpiredActivityRecoveryValidationError::ZeroDigest { field: "probe" });
        }
        if !(1..=EXPIRED_ACTIVITY_RECOVERY_MAX_AGENT_COUNT).contains(&agent_count) {
            return Err(ExpiredActivityRecoveryValidationError::AgentCountBounds);
        }
        Ok(Self {
            scope,
            delegation,
            delegation_digest,
            predecessor,
            agent_count,
            agent_digest,
            coordinator,
            probe_observed_at,
            probe_digest,
            expired_at_observation,
            blocker,
        })
    }
    pub const fn scope(&self) -> &ExpiredActivityRecoveryProbeScope {
        &self.scope
    }
    pub const fn delegation(&self) -> ExpiredActivityRecoveryDelegationFence {
        self.delegation
    }
    pub const fn delegation_digest(&self) -> &[u8; EXPIRED_ACTIVITY_RECOVERY_DIGEST_BYTES] {
        &self.delegation_digest
    }
    pub const fn predecessor(&self) -> ExpectedExpiredActivity {
        self.predecessor
    }
    pub const fn agent_count(&self) -> u16 {
        self.agent_count
    }
    pub const fn agent_digest(&self) -> &[u8; EXPIRED_ACTIVITY_RECOVERY_DIGEST_BYTES] {
        &self.agent_digest
    }
    pub const fn coordinator(&self) -> Option<ExpectedActivityCoordinator> {
        self.coordinator
    }
    pub const fn probe_observed_at(&self) -> TimestampMillis {
        self.probe_observed_at
    }
    pub const fn probe_digest(&self) -> &[u8; EXPIRED_ACTIVITY_RECOVERY_DIGEST_BYTES] {
        &self.probe_digest
    }
    pub const fn expired_at_observation(&self) -> bool {
        self.expired_at_observation
    }
    pub const fn blocker(&self) -> Option<ExpiredActivityRecoveryBlocker> {
        self.blocker
    }
    pub const fn recoverable_now(&self) -> bool {
        self.expired_at_observation && self.blocker.is_none()
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ExpiredActivityRecoveryValidationError {
    #[error("expired Activity recovery identity is nil")]
    NilIdentity,
    #[error("expired Activity recovery predecessor and successor must differ")]
    SelfLink,
    #[error("expired Activity recovery digest must be non-zero: {field}")]
    ZeroDigest { field: &'static str },
    #[error("expired Activity recovery Agent count is outside 1..=256")]
    AgentCountBounds,
    #[error("expired Activity recovery locator is outside its bounded range")]
    LocatorBounds,
    #[error("expired Activity recovery timestamps are out of order")]
    TimestampOrder,
    #[error("expired Activity recovery revision is invalid")]
    InvalidRevision,
    #[error("expired Activity recovery delegation fence is invalid")]
    DelegationFence,
    #[error("expired Activity recovery Session evidence is invalid")]
    InvalidSession,
    #[error("expired Activity recovery Agent focus tuple is invalid")]
    InvalidFocus,
}

impl fmt::Display for ExpiredActivityRecoveryFreezeState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Frozen")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids() -> (
        WorkspaceId,
        ActivityId,
        ActivityId,
        RuntimeInstanceId,
        AgentSessionId,
    ) {
        (
            WorkspaceId::from_uuid(Uuid::from_u128(1)),
            ActivityId::from_uuid(Uuid::from_u128(2)),
            ActivityId::from_uuid(Uuid::from_u128(3)),
            RuntimeInstanceId::from_uuid(Uuid::from_u128(4)),
            AgentSessionId::from_uuid(Uuid::from_u128(5)),
        )
    }

    #[test]
    fn expectation_rejects_self_link_and_zero_digest() {
        let (_, predecessor, successor, owner, session) = ids();
        let expected = ExpectedExpiredActivity::new(
            predecessor,
            ActivityRevision::INITIAL,
            TimestampMillis::new(1).unwrap_or_else(|_| unreachable!()),
            TimestampMillis::new(2).unwrap_or_else(|_| unreachable!()),
            owner,
            TimestampMillis::new(0).unwrap_or_else(|_| unreachable!()),
            ActivityLeaseRevision::INITIAL,
        )
        .unwrap_or_else(|_| unreachable!());
        assert!(matches!(
            ExpiredActivityRecoveryExpectation::new(
                expected,
                predecessor,
                session,
                AuthenticatedPrincipal::TrustedStdio,
                1,
                [1; 32],
                None,
            ),
            Err(ExpiredActivityRecoveryValidationError::SelfLink)
        ));
        assert!(matches!(
            ExpiredActivityRecoveryExpectation::new(
                expected,
                successor,
                session,
                AuthenticatedPrincipal::TrustedStdio,
                1,
                [0; 32],
                None,
            ),
            Err(ExpiredActivityRecoveryValidationError::ZeroDigest { .. })
        ));
    }
}
