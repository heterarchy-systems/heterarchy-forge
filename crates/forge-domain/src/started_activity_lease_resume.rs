//! Typed Source evidence for resuming an expired lease on a genuinely started Activity.
//!
//! This module owns only deterministic values and transition checks. Source
//! owns census construction, clocks, lease CAS, persistence, and the immutable
//! receipt; adapters own the frozen HTTP/canonical-JSON representation.

use thiserror::Error;
use uuid::Uuid;

use crate::{
    ActivityCoordinatorRevision, ActivityId, ActivityState, AgentInstanceId, AgentInstanceRevision,
    AgentSessionId, AgentSessionRevision, AgentSessionState, AuthenticatedPrincipal,
    ExpiredActivityRecoveryProbeScope, ForgeBackendId, OrchestrationIssuerId, RegisteredActivity,
    RuntimeInstanceId, TimestampMillis, UnstartedActivityContinuationServiceIdentity,
    WorkspaceRootFingerprint,
};

pub const STARTED_ACTIVITY_LEASE_RESUME_SCHEMA_VERSION: u16 = 1;
pub const STARTED_ACTIVITY_LEASE_RESUME_CENSUS_VERSION: u16 = 1;
pub const STARTED_ACTIVITY_LEASE_RESUME_DIGEST_BYTES: usize = 32;
pub const STARTED_ACTIVITY_LEASE_RESUME_PROBE_TTL_MS: i64 = 30_000;
pub const STARTED_ACTIVITY_LEASE_RESUME_LEASE_DURATION_MS: i64 = 300_000;
pub const STARTED_ACTIVITY_LEASE_RESUME_MAX_GOAL_ROWS: u32 = 100;
pub const STARTED_ACTIVITY_LEASE_RESUME_MAX_DAG_HEADS: u32 = 100;
pub const STARTED_ACTIVITY_LEASE_RESUME_MAX_DAG_NODES: u32 = 12_800;
pub const STARTED_ACTIVITY_LEASE_RESUME_MAX_DAG_EDGES: u32 = 51_200;
pub const STARTED_ACTIVITY_LEASE_RESUME_MAX_ASSIGNMENT_ROWS: u32 = 1_024;
pub const STARTED_ACTIVITY_LEASE_RESUME_MAX_PHYSICAL_ROWS: u32 = 4_096;

/// Trusted Source instance identity included in a probe.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StartedActivityLeaseResumeServiceIdentity {
    source: UnstartedActivityContinuationServiceIdentity,
    destination_id: Uuid,
}

impl StartedActivityLeaseResumeServiceIdentity {
    pub fn new(
        source: UnstartedActivityContinuationServiceIdentity,
        destination_id: Uuid,
    ) -> Result<Self, StartedActivityLeaseResumeValidationError> {
        if destination_id.is_nil() {
            return Err(StartedActivityLeaseResumeValidationError::NilIdentity);
        }
        Ok(Self {
            source,
            destination_id,
        })
    }

    pub const fn backend_id(self) -> ForgeBackendId {
        self.source.backend_id()
    }
    pub const fn issuer(self) -> OrchestrationIssuerId {
        self.source.issuer()
    }
    pub const fn destination_id(self) -> Uuid {
        self.destination_id
    }
    pub const fn runtime_instance_id(self) -> RuntimeInstanceId {
        self.source.runtime_instance_id()
    }
}

/// Frozen provider-operations delegation evidence.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StartedActivityLeaseResumeDelegation {
    migration_id: Uuid,
    destination_id: Uuid,
    freeze_revision: u64,
    freeze_created_at: TimestampMillis,
    freeze_updated_at: TimestampMillis,
    manifest_digest: [u8; STARTED_ACTIVITY_LEASE_RESUME_DIGEST_BYTES],
    delegated_at: TimestampMillis,
    delegation_digest: [u8; STARTED_ACTIVITY_LEASE_RESUME_DIGEST_BYTES],
}

impl StartedActivityLeaseResumeDelegation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        migration_id: Uuid,
        destination_id: Uuid,
        freeze_revision: u64,
        freeze_created_at: TimestampMillis,
        freeze_updated_at: TimestampMillis,
        manifest_digest: [u8; STARTED_ACTIVITY_LEASE_RESUME_DIGEST_BYTES],
        delegated_at: TimestampMillis,
        delegation_digest: [u8; STARTED_ACTIVITY_LEASE_RESUME_DIGEST_BYTES],
    ) -> Result<Self, StartedActivityLeaseResumeValidationError> {
        if migration_id.is_nil() || destination_id.is_nil() {
            return Err(StartedActivityLeaseResumeValidationError::NilIdentity);
        }
        if freeze_revision == 0 {
            return Err(StartedActivityLeaseResumeValidationError::InvalidFreezeRevision);
        }
        if freeze_updated_at.get() < freeze_created_at.get()
            || delegated_at.get() < freeze_updated_at.get()
        {
            return Err(StartedActivityLeaseResumeValidationError::DelegationTimestampOrder);
        }
        Ok(Self {
            migration_id,
            destination_id,
            freeze_revision,
            freeze_created_at,
            freeze_updated_at,
            manifest_digest,
            delegated_at,
            delegation_digest,
        })
    }

    pub const fn migration_id(self) -> Uuid {
        self.migration_id
    }
    pub const fn destination_id(self) -> Uuid {
        self.destination_id
    }
    pub const fn freeze_revision(self) -> u64 {
        self.freeze_revision
    }
    pub const fn freeze_created_at(self) -> TimestampMillis {
        self.freeze_created_at
    }
    pub const fn freeze_updated_at(self) -> TimestampMillis {
        self.freeze_updated_at
    }
    pub const fn manifest_digest(self) -> [u8; STARTED_ACTIVITY_LEASE_RESUME_DIGEST_BYTES] {
        self.manifest_digest
    }
    pub const fn delegated_at(self) -> TimestampMillis {
        self.delegated_at
    }
    pub const fn delegation_digest(self) -> [u8; STARTED_ACTIVITY_LEASE_RESUME_DIGEST_BYTES] {
        self.delegation_digest
    }
}

/// Bounded census of Source Goal rows.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StartedActivityLeaseResumeGoalCensus {
    row_count: u32,
    digest: [u8; STARTED_ACTIVITY_LEASE_RESUME_DIGEST_BYTES],
    truncated: bool,
    complete: bool,
}

impl StartedActivityLeaseResumeGoalCensus {
    pub fn new(
        row_count: u32,
        digest: [u8; STARTED_ACTIVITY_LEASE_RESUME_DIGEST_BYTES],
        truncated: bool,
        complete: bool,
    ) -> Result<Self, StartedActivityLeaseResumeValidationError> {
        if row_count > STARTED_ACTIVITY_LEASE_RESUME_MAX_GOAL_ROWS {
            return Err(StartedActivityLeaseResumeValidationError::CensusCountBounds);
        }
        Ok(Self {
            row_count,
            digest,
            truncated,
            complete,
        })
    }

    pub const fn row_count(self) -> u32 {
        self.row_count
    }
    pub const fn digest(self) -> [u8; STARTED_ACTIVITY_LEASE_RESUME_DIGEST_BYTES] {
        self.digest
    }
    pub const fn truncated(self) -> bool {
        self.truncated
    }
    pub const fn complete(self) -> bool {
        self.complete
    }
    const fn proves_complete_census(self) -> bool {
        self.complete && !self.truncated
    }
}

/// Bounded census of Source DAG heads, nodes, and edges.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StartedActivityLeaseResumeDagCensus {
    head_count: u32,
    node_count: u32,
    edge_count: u32,
    digest: [u8; STARTED_ACTIVITY_LEASE_RESUME_DIGEST_BYTES],
    truncated: bool,
    complete: bool,
}

impl StartedActivityLeaseResumeDagCensus {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        head_count: u32,
        node_count: u32,
        edge_count: u32,
        digest: [u8; STARTED_ACTIVITY_LEASE_RESUME_DIGEST_BYTES],
        truncated: bool,
        complete: bool,
    ) -> Result<Self, StartedActivityLeaseResumeValidationError> {
        if head_count > STARTED_ACTIVITY_LEASE_RESUME_MAX_DAG_HEADS
            || node_count > STARTED_ACTIVITY_LEASE_RESUME_MAX_DAG_NODES
            || edge_count > STARTED_ACTIVITY_LEASE_RESUME_MAX_DAG_EDGES
        {
            return Err(StartedActivityLeaseResumeValidationError::CensusCountBounds);
        }
        Ok(Self {
            head_count,
            node_count,
            edge_count,
            digest,
            truncated,
            complete,
        })
    }

    pub const fn head_count(self) -> u32 {
        self.head_count
    }
    pub const fn node_count(self) -> u32 {
        self.node_count
    }
    pub const fn edge_count(self) -> u32 {
        self.edge_count
    }
    pub const fn digest(self) -> [u8; STARTED_ACTIVITY_LEASE_RESUME_DIGEST_BYTES] {
        self.digest
    }
    pub const fn truncated(self) -> bool {
        self.truncated
    }
    pub const fn complete(self) -> bool {
        self.complete
    }
    const fn proves_complete_census(self) -> bool {
        self.complete && !self.truncated
    }
}

/// Bounded census of Source Assignment rows.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StartedActivityLeaseResumeAssignmentCensus {
    row_count: u32,
    digest: [u8; STARTED_ACTIVITY_LEASE_RESUME_DIGEST_BYTES],
    truncated: bool,
    complete: bool,
}

impl StartedActivityLeaseResumeAssignmentCensus {
    pub fn new(
        row_count: u32,
        digest: [u8; STARTED_ACTIVITY_LEASE_RESUME_DIGEST_BYTES],
        truncated: bool,
        complete: bool,
    ) -> Result<Self, StartedActivityLeaseResumeValidationError> {
        if row_count > STARTED_ACTIVITY_LEASE_RESUME_MAX_ASSIGNMENT_ROWS {
            return Err(StartedActivityLeaseResumeValidationError::CensusCountBounds);
        }
        Ok(Self {
            row_count,
            digest,
            truncated,
            complete,
        })
    }

    pub const fn row_count(self) -> u32 {
        self.row_count
    }
    pub const fn digest(self) -> [u8; STARTED_ACTIVITY_LEASE_RESUME_DIGEST_BYTES] {
        self.digest
    }
    pub const fn truncated(self) -> bool {
        self.truncated
    }
    pub const fn complete(self) -> bool {
        self.complete
    }
    const fn proves_complete_census(self) -> bool {
        self.complete && !self.truncated
    }
}

/// Bounded census of physical rows and outstanding effect evidence.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StartedActivityLeaseResumePhysicalCensus {
    row_count: u32,
    execution_active_count: u64,
    execution_unknown_count: u64,
    writer_lease_active_count: u64,
    writer_lease_unknown_count: u64,
    pending_effect_count: u64,
    effect_unknown_count: u64,
    unresolved_worktree_count: u64,
    worktree_unknown_count: u64,
    unknown_count: u64,
    digest: [u8; STARTED_ACTIVITY_LEASE_RESUME_DIGEST_BYTES],
    truncated: bool,
    complete: bool,
}

impl StartedActivityLeaseResumePhysicalCensus {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        row_count: u32,
        execution_active_count: u64,
        execution_unknown_count: u64,
        writer_lease_active_count: u64,
        writer_lease_unknown_count: u64,
        pending_effect_count: u64,
        effect_unknown_count: u64,
        unresolved_worktree_count: u64,
        worktree_unknown_count: u64,
        unknown_count: u64,
        digest: [u8; STARTED_ACTIVITY_LEASE_RESUME_DIGEST_BYTES],
        truncated: bool,
        complete: bool,
    ) -> Result<Self, StartedActivityLeaseResumeValidationError> {
        if row_count > STARTED_ACTIVITY_LEASE_RESUME_MAX_PHYSICAL_ROWS {
            return Err(StartedActivityLeaseResumeValidationError::CensusCountBounds);
        }
        Ok(Self {
            row_count,
            execution_active_count,
            execution_unknown_count,
            writer_lease_active_count,
            writer_lease_unknown_count,
            pending_effect_count,
            effect_unknown_count,
            unresolved_worktree_count,
            worktree_unknown_count,
            unknown_count,
            digest,
            truncated,
            complete,
        })
    }

    pub const fn row_count(self) -> u32 {
        self.row_count
    }
    pub const fn execution_active_count(self) -> u64 {
        self.execution_active_count
    }
    pub const fn execution_unknown_count(self) -> u64 {
        self.execution_unknown_count
    }
    pub const fn writer_lease_active_count(self) -> u64 {
        self.writer_lease_active_count
    }
    pub const fn writer_lease_unknown_count(self) -> u64 {
        self.writer_lease_unknown_count
    }
    pub const fn pending_effect_count(self) -> u64 {
        self.pending_effect_count
    }
    pub const fn effect_unknown_count(self) -> u64 {
        self.effect_unknown_count
    }
    pub const fn unresolved_worktree_count(self) -> u64 {
        self.unresolved_worktree_count
    }
    pub const fn worktree_unknown_count(self) -> u64 {
        self.worktree_unknown_count
    }
    pub const fn unknown_count(self) -> u64 {
        self.unknown_count
    }
    pub const fn digest(self) -> [u8; STARTED_ACTIVITY_LEASE_RESUME_DIGEST_BYTES] {
        self.digest
    }
    pub const fn truncated(self) -> bool {
        self.truncated
    }
    pub const fn complete(self) -> bool {
        self.complete
    }
    const fn proves_complete_census(self) -> bool {
        self.complete && !self.truncated
    }
    const fn has_blockers_or_unknowns(self) -> bool {
        self.execution_active_count != 0
            || self.execution_unknown_count != 0
            || self.writer_lease_active_count != 0
            || self.writer_lease_unknown_count != 0
            || self.pending_effect_count != 0
            || self.effect_unknown_count != 0
            || self.unresolved_worktree_count != 0
            || self.worktree_unknown_count != 0
            || self.unknown_count != 0
    }
}

/// Exact v1 wire projection of the initiating Agent row.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StartedActivityLeaseResumeAgentSnapshot {
    agent_id: AgentInstanceId,
    activity_id: ActivityId,
    session_id: AgentSessionId,
    principal: AuthenticatedPrincipal,
    revision: AgentInstanceRevision,
    attached: bool,
}

impl StartedActivityLeaseResumeAgentSnapshot {
    pub fn new(
        agent_id: AgentInstanceId,
        activity_id: ActivityId,
        session_id: AgentSessionId,
        principal: AuthenticatedPrincipal,
        revision: AgentInstanceRevision,
        attached: bool,
    ) -> Result<Self, StartedActivityLeaseResumeValidationError> {
        if agent_id.into_uuid().is_nil()
            || activity_id.into_uuid().is_nil()
            || session_id.into_uuid().is_nil()
        {
            return Err(StartedActivityLeaseResumeValidationError::NilIdentity);
        }
        Ok(Self {
            agent_id,
            activity_id,
            session_id,
            principal,
            revision,
            attached,
        })
    }

    pub const fn agent_id(self) -> AgentInstanceId {
        self.agent_id
    }
    pub const fn activity_id(self) -> ActivityId {
        self.activity_id
    }
    pub const fn session_id(self) -> AgentSessionId {
        self.session_id
    }
    pub const fn principal(self) -> AuthenticatedPrincipal {
        self.principal
    }
    pub const fn revision(self) -> AgentInstanceRevision {
        self.revision
    }
    pub const fn attached(self) -> bool {
        self.attached
    }
}

/// Exact v1 wire projection of one Agent Session row.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StartedActivityLeaseResumeSessionSnapshot {
    session_id: AgentSessionId,
    principal: AuthenticatedPrincipal,
    state: AgentSessionState,
    revision: AgentSessionRevision,
    updated_at: TimestampMillis,
}

impl StartedActivityLeaseResumeSessionSnapshot {
    pub fn new(
        session_id: AgentSessionId,
        principal: AuthenticatedPrincipal,
        state: AgentSessionState,
        revision: AgentSessionRevision,
        updated_at: TimestampMillis,
    ) -> Result<Self, StartedActivityLeaseResumeValidationError> {
        if session_id.into_uuid().is_nil() {
            return Err(StartedActivityLeaseResumeValidationError::NilIdentity);
        }
        Ok(Self {
            session_id,
            principal,
            state,
            revision,
            updated_at,
        })
    }

    pub const fn session_id(self) -> AgentSessionId {
        self.session_id
    }
    pub const fn principal(self) -> AuthenticatedPrincipal {
        self.principal
    }
    pub const fn state(self) -> AgentSessionState {
        self.state
    }
    pub const fn revision(self) -> AgentSessionRevision {
        self.revision
    }
    pub const fn updated_at(self) -> TimestampMillis {
        self.updated_at
    }
}

/// Exact v1 wire projection of the Activity Coordinator and its current
/// Agent/Session fences. It intentionally contains no inferred lifecycle
/// state; the complete Source rows remain authoritative in the store.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StartedActivityLeaseResumeCoordinatorSnapshot {
    agent_id: AgentInstanceId,
    session_id: AgentSessionId,
    principal: AuthenticatedPrincipal,
    agent_revision: AgentInstanceRevision,
    revision: ActivityCoordinatorRevision,
    updated_at: TimestampMillis,
    session_revision: AgentSessionRevision,
    session_updated_at: TimestampMillis,
}

impl StartedActivityLeaseResumeCoordinatorSnapshot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        agent_id: AgentInstanceId,
        session_id: AgentSessionId,
        principal: AuthenticatedPrincipal,
        agent_revision: AgentInstanceRevision,
        revision: ActivityCoordinatorRevision,
        updated_at: TimestampMillis,
        session_revision: AgentSessionRevision,
        session_updated_at: TimestampMillis,
    ) -> Result<Self, StartedActivityLeaseResumeValidationError> {
        if agent_id.into_uuid().is_nil() || session_id.into_uuid().is_nil() {
            return Err(StartedActivityLeaseResumeValidationError::NilIdentity);
        }
        Ok(Self {
            agent_id,
            session_id,
            principal,
            agent_revision,
            revision,
            updated_at,
            session_revision,
            session_updated_at,
        })
    }

    pub const fn agent_id(self) -> AgentInstanceId {
        self.agent_id
    }
    pub const fn session_id(self) -> AgentSessionId {
        self.session_id
    }
    pub const fn principal(self) -> AuthenticatedPrincipal {
        self.principal
    }
    pub const fn agent_revision(self) -> AgentInstanceRevision {
        self.agent_revision
    }
    pub const fn revision(self) -> ActivityCoordinatorRevision {
        self.revision
    }
    pub const fn updated_at(self) -> TimestampMillis {
        self.updated_at
    }
    pub const fn session_revision(self) -> AgentSessionRevision {
        self.session_revision
    }
    pub const fn session_updated_at(self) -> TimestampMillis {
        self.session_updated_at
    }
}

/// Immutable Source facts rechecked by the lease-resume operation.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartedActivityLeaseResumeExpectation {
    activity: RegisteredActivity,
    initiating_agent: Option<StartedActivityLeaseResumeAgentSnapshot>,
    initiating_session: StartedActivityLeaseResumeSessionSnapshot,
    coordinator: Option<StartedActivityLeaseResumeCoordinatorSnapshot>,
    started_work_proven: bool,
    goal_census: StartedActivityLeaseResumeGoalCensus,
    dag_census: StartedActivityLeaseResumeDagCensus,
    assignment_census: StartedActivityLeaseResumeAssignmentCensus,
    physical_census: StartedActivityLeaseResumePhysicalCensus,
}

impl StartedActivityLeaseResumeExpectation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        activity: RegisteredActivity,
        initiating_agent: Option<StartedActivityLeaseResumeAgentSnapshot>,
        initiating_session: StartedActivityLeaseResumeSessionSnapshot,
        coordinator: Option<StartedActivityLeaseResumeCoordinatorSnapshot>,
        started_work_proven: bool,
        goal_census: StartedActivityLeaseResumeGoalCensus,
        dag_census: StartedActivityLeaseResumeDagCensus,
        assignment_census: StartedActivityLeaseResumeAssignmentCensus,
        physical_census: StartedActivityLeaseResumePhysicalCensus,
    ) -> Result<Self, StartedActivityLeaseResumeValidationError> {
        if activity.id().into_uuid().is_nil()
            || activity.workspace_id().into_uuid().is_nil()
            || initiating_session.session_id().into_uuid().is_nil()
        {
            return Err(StartedActivityLeaseResumeValidationError::NilIdentity);
        }
        if let Some(agent) = &initiating_agent
            && (agent.activity_id() != activity.id()
                || agent.session_id() != initiating_session.session_id()
                || agent.principal() != initiating_session.principal())
        {
            return Err(StartedActivityLeaseResumeValidationError::InitiatingAgentMismatch);
        }
        if let Some(coordinator) = &coordinator
            && initiating_agent.is_some_and(|agent| {
                coordinator.agent_id() == agent.agent_id()
                    && (coordinator.agent_revision() != agent.revision()
                        || coordinator.principal() != agent.principal())
            })
        {
            return Err(StartedActivityLeaseResumeValidationError::CoordinatorMismatch);
        }
        if let (Some(coordinator), Some(agent)) = (&coordinator, &initiating_agent)
            && coordinator.session_id() == initiating_session.session_id()
            && (coordinator.session_revision() != initiating_session.revision()
                || coordinator.session_updated_at() != initiating_session.updated_at()
                || coordinator.principal() != initiating_session.principal()
                || coordinator.agent_id() != agent.agent_id())
        {
            return Err(StartedActivityLeaseResumeValidationError::CoordinatorMismatch);
        }
        Ok(Self {
            activity,
            initiating_agent,
            initiating_session,
            coordinator,
            started_work_proven,
            goal_census,
            dag_census,
            assignment_census,
            physical_census,
        })
    }

    pub const fn activity(&self) -> &RegisteredActivity {
        &self.activity
    }
    pub const fn initiating_agent(&self) -> Option<&StartedActivityLeaseResumeAgentSnapshot> {
        self.initiating_agent.as_ref()
    }
    pub const fn initiating_session(&self) -> &StartedActivityLeaseResumeSessionSnapshot {
        &self.initiating_session
    }
    pub const fn coordinator(&self) -> Option<&StartedActivityLeaseResumeCoordinatorSnapshot> {
        self.coordinator.as_ref()
    }
    pub const fn started_work_proven(&self) -> bool {
        self.started_work_proven
    }
    pub const fn goal_census(&self) -> StartedActivityLeaseResumeGoalCensus {
        self.goal_census
    }
    pub const fn dag_census(&self) -> StartedActivityLeaseResumeDagCensus {
        self.dag_census
    }
    pub const fn assignment_census(&self) -> StartedActivityLeaseResumeAssignmentCensus {
        self.assignment_census
    }
    pub const fn physical_census(&self) -> StartedActivityLeaseResumePhysicalCensus {
        self.physical_census
    }

    fn has_visible_resumability_facts_at(&self, observed_at: TimestampMillis) -> bool {
        let Some(agent) = &self.initiating_agent else {
            return false;
        };
        if self.coordinator.is_none() {
            return false;
        }
        self.started_work_proven
            && self.activity.state() == ActivityState::Open
            && self.activity.lease_owner_id().is_some()
            && self.activity.lease().is_expired_at(observed_at)
            && matches!(self.initiating_session.state(), AgentSessionState::Open)
            && agent.attached()
            && self.goal_census.proves_complete_census()
            && self.dag_census.proves_complete_census()
            && self.assignment_census.proves_complete_census()
            && self.physical_census.proves_complete_census()
            && !self.physical_census.has_blockers_or_unknowns()
    }
}

/// The Source-selected first blocker, with wire spellings kept explicit.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StartedActivityLeaseResumeBlocker {
    ActivityNotStarted,
    ActivityNotOpen,
    ActivityLeaseMissing,
    ActivityLeaseNotExpired,
    InitiatingAgentMissing,
    CoordinatorMissing,
    CoordinatorAgentNotAttached,
    CoordinatorSessionNotOpen,
    GoalCensusIncomplete,
    DagCensusIncomplete,
    AssignmentCensusIncomplete,
    PhysicalActivityEffectPresent,
    PhysicalCensusIncomplete,
}

impl StartedActivityLeaseResumeBlocker {
    pub const fn as_wire_str(self) -> &'static str {
        match self {
            Self::ActivityNotStarted => "activity_not_started",
            Self::ActivityNotOpen => "activity_not_open",
            Self::ActivityLeaseMissing => "activity_lease_missing",
            Self::ActivityLeaseNotExpired => "activity_lease_not_expired",
            Self::InitiatingAgentMissing => "initiating_agent_missing",
            Self::CoordinatorMissing => "coordinator_missing",
            Self::CoordinatorAgentNotAttached => "coordinator_agent_not_attached",
            Self::CoordinatorSessionNotOpen => "coordinator_session_not_open",
            Self::GoalCensusIncomplete => "goal_census_incomplete",
            Self::DagCensusIncomplete => "dag_census_incomplete",
            Self::AssignmentCensusIncomplete => "assignment_census_incomplete",
            Self::PhysicalActivityEffectPresent => "physical_activity_effect_present",
            Self::PhysicalCensusIncomplete => "physical_census_incomplete",
        }
    }
}

/// Read-only Source probe. Source supplies its complete predicate result and
/// first blocker; the domain checks their wire invariant and every necessary
/// condition that can be verified from this intentionally projected snapshot.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartedActivityLeaseResumeProbe {
    scope: ExpiredActivityRecoveryProbeScope,
    service: StartedActivityLeaseResumeServiceIdentity,
    delegation: StartedActivityLeaseResumeDelegation,
    expectation: StartedActivityLeaseResumeExpectation,
    probe_observed_at: TimestampMillis,
    probe_expires_at: TimestampMillis,
    probe_digest: [u8; STARTED_ACTIVITY_LEASE_RESUME_DIGEST_BYTES],
    resumable_now: bool,
    blocker: Option<StartedActivityLeaseResumeBlocker>,
}

impl StartedActivityLeaseResumeProbe {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: ExpiredActivityRecoveryProbeScope,
        service: StartedActivityLeaseResumeServiceIdentity,
        delegation: StartedActivityLeaseResumeDelegation,
        expectation: StartedActivityLeaseResumeExpectation,
        probe_observed_at: TimestampMillis,
        probe_digest: [u8; STARTED_ACTIVITY_LEASE_RESUME_DIGEST_BYTES],
        resumable_now: bool,
        blocker: Option<StartedActivityLeaseResumeBlocker>,
    ) -> Result<Self, StartedActivityLeaseResumeValidationError> {
        if scope.workspace_id() != expectation.activity.workspace_id()
            || service.destination_id() != delegation.destination_id()
        {
            return Err(StartedActivityLeaseResumeValidationError::ScopeMismatch);
        }
        let expiry_ms = probe_observed_at
            .get()
            .checked_add(STARTED_ACTIVITY_LEASE_RESUME_PROBE_TTL_MS)
            .ok_or(StartedActivityLeaseResumeValidationError::TimestampOverflow)?;
        let probe_expires_at = TimestampMillis::new(expiry_ms)
            .map_err(|_| StartedActivityLeaseResumeValidationError::TimestampOverflow)?;
        if resumable_now != blocker.is_none() {
            return Err(StartedActivityLeaseResumeValidationError::ProbeBlockerMismatch);
        }
        if resumable_now && !expectation.has_visible_resumability_facts_at(probe_observed_at) {
            return Err(StartedActivityLeaseResumeValidationError::ProbeNotResumable);
        }
        Ok(Self {
            scope,
            service,
            delegation,
            expectation,
            probe_observed_at,
            probe_expires_at,
            probe_digest,
            resumable_now,
            blocker,
        })
    }

    pub const fn scope(&self) -> &ExpiredActivityRecoveryProbeScope {
        &self.scope
    }
    pub const fn service(&self) -> StartedActivityLeaseResumeServiceIdentity {
        self.service
    }
    pub const fn workspace_root_fingerprint(&self) -> WorkspaceRootFingerprint {
        self.scope.root_fingerprint()
    }
    pub const fn binding_digest(&self) -> [u8; STARTED_ACTIVITY_LEASE_RESUME_DIGEST_BYTES] {
        *self.scope.binding_digest()
    }
    pub const fn delegation(&self) -> StartedActivityLeaseResumeDelegation {
        self.delegation
    }
    pub const fn expectation(&self) -> &StartedActivityLeaseResumeExpectation {
        &self.expectation
    }
    pub const fn census_version(&self) -> u16 {
        STARTED_ACTIVITY_LEASE_RESUME_CENSUS_VERSION
    }
    pub const fn probe_observed_at(&self) -> TimestampMillis {
        self.probe_observed_at
    }
    pub const fn probe_expires_at(&self) -> TimestampMillis {
        self.probe_expires_at
    }
    pub const fn probe_digest(&self) -> [u8; STARTED_ACTIVITY_LEASE_RESUME_DIGEST_BYTES] {
        self.probe_digest
    }
    pub const fn started_work_proven(&self) -> bool {
        self.expectation.started_work_proven
    }
    pub const fn blocker(&self) -> Option<StartedActivityLeaseResumeBlocker> {
        self.blocker
    }
    pub const fn resumable_now(&self) -> bool {
        self.resumable_now
    }
    pub fn is_live_at(&self, now: TimestampMillis) -> bool {
        now.get() >= self.probe_observed_at.get() && now.get() < self.probe_expires_at.get()
    }
}

/// Validated request payload for a read-only Source probe.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartedActivityLeaseResumeProbeRequest {
    scope: ExpiredActivityRecoveryProbeScope,
    activity_id: ActivityId,
    initiating_session_id: AgentSessionId,
    principal: AuthenticatedPrincipal,
}

impl StartedActivityLeaseResumeProbeRequest {
    pub fn new(
        scope: ExpiredActivityRecoveryProbeScope,
        activity_id: ActivityId,
        initiating_session_id: AgentSessionId,
        principal: AuthenticatedPrincipal,
    ) -> Result<Self, StartedActivityLeaseResumeValidationError> {
        if scope.workspace_id().into_uuid().is_nil()
            || activity_id.into_uuid().is_nil()
            || initiating_session_id.into_uuid().is_nil()
        {
            return Err(StartedActivityLeaseResumeValidationError::NilIdentity);
        }
        Ok(Self {
            scope,
            activity_id,
            initiating_session_id,
            principal,
        })
    }

    pub const fn scope(&self) -> &ExpiredActivityRecoveryProbeScope {
        &self.scope
    }
    pub const fn activity_id(&self) -> ActivityId {
        self.activity_id
    }
    pub const fn initiating_session_id(&self) -> AgentSessionId {
        self.initiating_session_id
    }
    pub const fn principal(&self) -> AuthenticatedPrincipal {
        self.principal
    }
}

/// Run input after Control has resolved the exact Workspace and Source
/// service. Canonical request digest bytes are supplied by the boundary.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartedActivityLeaseResumeRunRequest {
    scope: ExpiredActivityRecoveryProbeScope,
    request_id: Uuid,
    request_digest: [u8; STARTED_ACTIVITY_LEASE_RESUME_DIGEST_BYTES],
    probe: StartedActivityLeaseResumeProbe,
    current_service: StartedActivityLeaseResumeServiceIdentity,
}

impl StartedActivityLeaseResumeRunRequest {
    pub fn new(
        scope: ExpiredActivityRecoveryProbeScope,
        request_id: Uuid,
        request_digest: [u8; STARTED_ACTIVITY_LEASE_RESUME_DIGEST_BYTES],
        probe: StartedActivityLeaseResumeProbe,
        current_service: StartedActivityLeaseResumeServiceIdentity,
    ) -> Result<Self, StartedActivityLeaseResumeValidationError> {
        if request_id.is_nil() {
            return Err(StartedActivityLeaseResumeValidationError::NilIdentity);
        }
        if scope != *probe.scope()
            || current_service.runtime_instance_id() != probe.service().runtime_instance_id()
        {
            return Err(StartedActivityLeaseResumeValidationError::ScopeMismatch);
        }
        if !probe.resumable_now() {
            return Err(StartedActivityLeaseResumeValidationError::ProbeNotResumable);
        }
        Ok(Self {
            scope,
            request_id,
            request_digest,
            probe,
            current_service,
        })
    }

    pub const fn scope(&self) -> &ExpiredActivityRecoveryProbeScope {
        &self.scope
    }
    pub const fn request_id(&self) -> Uuid {
        self.request_id
    }
    pub const fn request_digest(&self) -> [u8; STARTED_ACTIVITY_LEASE_RESUME_DIGEST_BYTES] {
        self.request_digest
    }
    pub const fn probe(&self) -> &StartedActivityLeaseResumeProbe {
        &self.probe
    }
    pub const fn current_service(&self) -> StartedActivityLeaseResumeServiceIdentity {
        self.current_service
    }
}

/// Exact immutable receipt selector for Source Get. It deliberately carries
/// no current lease, Coordinator, or service identity requirement.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartedActivityLeaseResumeGetRequest {
    scope: ExpiredActivityRecoveryProbeScope,
    request_id: Uuid,
    request_digest: [u8; STARTED_ACTIVITY_LEASE_RESUME_DIGEST_BYTES],
    activity_id: ActivityId,
    agent_id: crate::AgentInstanceId,
    initiating_session_id: AgentSessionId,
    principal: AuthenticatedPrincipal,
}

impl StartedActivityLeaseResumeGetRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: ExpiredActivityRecoveryProbeScope,
        request_id: Uuid,
        request_digest: [u8; STARTED_ACTIVITY_LEASE_RESUME_DIGEST_BYTES],
        activity_id: ActivityId,
        agent_id: crate::AgentInstanceId,
        initiating_session_id: AgentSessionId,
        principal: AuthenticatedPrincipal,
    ) -> Result<Self, StartedActivityLeaseResumeValidationError> {
        if scope.workspace_id().into_uuid().is_nil()
            || request_id.is_nil()
            || activity_id.into_uuid().is_nil()
            || agent_id.into_uuid().is_nil()
            || initiating_session_id.into_uuid().is_nil()
        {
            return Err(StartedActivityLeaseResumeValidationError::NilIdentity);
        }
        Ok(Self {
            scope,
            request_id,
            request_digest,
            activity_id,
            agent_id,
            initiating_session_id,
            principal,
        })
    }

    pub const fn scope(&self) -> &ExpiredActivityRecoveryProbeScope {
        &self.scope
    }
    pub const fn request_id(&self) -> Uuid {
        self.request_id
    }
    pub const fn request_digest(&self) -> [u8; STARTED_ACTIVITY_LEASE_RESUME_DIGEST_BYTES] {
        self.request_digest
    }
    pub const fn activity_id(&self) -> ActivityId {
        self.activity_id
    }
    pub const fn agent_id(&self) -> crate::AgentInstanceId {
        self.agent_id
    }
    pub const fn initiating_session_id(&self) -> AgentSessionId {
        self.initiating_session_id
    }
    pub const fn principal(&self) -> AuthenticatedPrincipal {
        self.principal
    }
}

/// The Source outcome distinguishes a new atomic record from an exact
/// idempotent replay while retaining the same immutable receipt.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartedActivityLeaseResumeOperation {
    Recorded(StartedActivityLeaseResumeReceipt),
    Replay(StartedActivityLeaseResumeReceipt),
}

impl StartedActivityLeaseResumeOperation {
    pub const fn receipt(&self) -> &StartedActivityLeaseResumeReceipt {
        match self {
            Self::Recorded(receipt) | Self::Replay(receipt) => receipt,
        }
    }

    pub const fn is_replay(&self) -> bool {
        matches!(self, Self::Replay(_))
    }
}

/// Immutable receipt of one successful Source lease resume.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartedActivityLeaseResumeReceipt {
    scope: ExpiredActivityRecoveryProbeScope,
    request_id: Uuid,
    request_digest: [u8; STARTED_ACTIVITY_LEASE_RESUME_DIGEST_BYTES],
    activity: RegisteredActivity,
    initiating_agent: StartedActivityLeaseResumeAgentSnapshot,
    initiating_session: StartedActivityLeaseResumeSessionSnapshot,
    coordinator: StartedActivityLeaseResumeCoordinatorSnapshot,
    source_runtime_instance_id: RuntimeInstanceId,
    probe_digest: [u8; STARTED_ACTIVITY_LEASE_RESUME_DIGEST_BYTES],
    resumed_at: TimestampMillis,
}

impl StartedActivityLeaseResumeReceipt {
    pub fn from_successful_probe(
        probe: &StartedActivityLeaseResumeProbe,
        request_id: Uuid,
        request_digest: [u8; STARTED_ACTIVITY_LEASE_RESUME_DIGEST_BYTES],
        activity_after: RegisteredActivity,
        resumed_at: TimestampMillis,
    ) -> Result<Self, StartedActivityLeaseResumeValidationError> {
        if request_id.is_nil() {
            return Err(StartedActivityLeaseResumeValidationError::NilIdentity);
        }
        if !probe.resumable_now() {
            return Err(StartedActivityLeaseResumeValidationError::ProbeNotResumable);
        }
        if !probe.is_live_at(resumed_at) {
            return Err(StartedActivityLeaseResumeValidationError::ProbeExpired);
        }
        let source_runtime_instance_id = probe.service.runtime_instance_id();
        let expected_activity = &probe.expectation.activity;
        if activity_after.id() != expected_activity.id()
            || activity_after.workspace_id() != expected_activity.workspace_id()
            || activity_after.state() != expected_activity.state()
            || activity_after.created_at() != expected_activity.created_at()
            || activity_after.updated_at() != expected_activity.updated_at()
            || activity_after.revision() != expected_activity.revision()
        {
            return Err(StartedActivityLeaseResumeValidationError::ActivitySemanticStateChanged);
        }
        let expected_lease_revision = expected_activity
            .lease()
            .revision()
            .checked_next()
            .map_err(|_| StartedActivityLeaseResumeValidationError::LeaseRevisionOverflow)?;
        let expected_lease_until_ms = resumed_at
            .get()
            .checked_add(STARTED_ACTIVITY_LEASE_RESUME_LEASE_DURATION_MS)
            .ok_or(StartedActivityLeaseResumeValidationError::TimestampOverflow)?;
        let expected_lease_until = TimestampMillis::new(expected_lease_until_ms)
            .map_err(|_| StartedActivityLeaseResumeValidationError::TimestampOverflow)?;
        if activity_after.state() != ActivityState::Open
            || activity_after.lease_owner_id() != Some(source_runtime_instance_id)
            || activity_after.lease_until() != Some(expected_lease_until)
            || activity_after.lease().revision() != expected_lease_revision
        {
            return Err(StartedActivityLeaseResumeValidationError::LeaseTransitionMismatch);
        }
        let initiating_agent = probe
            .expectation
            .initiating_agent
            .as_ref()
            .copied()
            .ok_or(StartedActivityLeaseResumeValidationError::ProbeNotResumable)?;
        let coordinator = probe
            .expectation
            .coordinator
            .as_ref()
            .copied()
            .ok_or(StartedActivityLeaseResumeValidationError::ProbeNotResumable)?;
        Ok(Self {
            scope: probe.scope.clone(),
            request_id,
            request_digest,
            activity: activity_after,
            initiating_agent,
            initiating_session: probe.expectation.initiating_session,
            coordinator,
            source_runtime_instance_id,
            probe_digest: probe.probe_digest,
            resumed_at,
        })
    }

    /// Rehydrate an immutable persisted receipt without requiring current
    /// Activity lease or Coordinator state.
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        scope: ExpiredActivityRecoveryProbeScope,
        request_id: Uuid,
        request_digest: [u8; STARTED_ACTIVITY_LEASE_RESUME_DIGEST_BYTES],
        activity: RegisteredActivity,
        initiating_agent: StartedActivityLeaseResumeAgentSnapshot,
        initiating_session: StartedActivityLeaseResumeSessionSnapshot,
        coordinator: StartedActivityLeaseResumeCoordinatorSnapshot,
        source_runtime_instance_id: RuntimeInstanceId,
        probe_digest: [u8; STARTED_ACTIVITY_LEASE_RESUME_DIGEST_BYTES],
        resumed_at: TimestampMillis,
    ) -> Result<Self, StartedActivityLeaseResumeValidationError> {
        if request_id.is_nil() || source_runtime_instance_id.into_uuid().is_nil() {
            return Err(StartedActivityLeaseResumeValidationError::NilIdentity);
        }
        let expected_lease_until_ms = resumed_at
            .get()
            .checked_add(STARTED_ACTIVITY_LEASE_RESUME_LEASE_DURATION_MS)
            .ok_or(StartedActivityLeaseResumeValidationError::TimestampOverflow)?;
        let expected_lease_until = TimestampMillis::new(expected_lease_until_ms)
            .map_err(|_| StartedActivityLeaseResumeValidationError::TimestampOverflow)?;
        if activity.state() != ActivityState::Open
            || activity.workspace_id() != scope.workspace_id()
            || activity.lease_owner_id() != Some(source_runtime_instance_id)
            || activity.lease_until() != Some(expected_lease_until)
            || initiating_agent.activity_id() != activity.id()
            || initiating_agent.session_id() != initiating_session.session_id()
            || initiating_agent.principal() != initiating_session.principal()
            || !initiating_agent.attached()
            || initiating_session.state() != AgentSessionState::Open
            || (coordinator.agent_id() == initiating_agent.agent_id()
                && (coordinator.agent_revision() != initiating_agent.revision()
                    || coordinator.principal() != initiating_agent.principal()))
            || (coordinator.session_id() == initiating_session.session_id()
                && (coordinator.session_revision() != initiating_session.revision()
                    || coordinator.session_updated_at() != initiating_session.updated_at()
                    || coordinator.principal() != initiating_session.principal()))
        {
            return Err(StartedActivityLeaseResumeValidationError::ReceiptSnapshotMismatch);
        }
        Ok(Self {
            scope,
            request_id,
            request_digest,
            activity,
            initiating_agent,
            initiating_session,
            coordinator,
            source_runtime_instance_id,
            probe_digest,
            resumed_at,
        })
    }

    pub const fn schema_version(&self) -> u16 {
        STARTED_ACTIVITY_LEASE_RESUME_SCHEMA_VERSION
    }
    pub const fn scope(&self) -> &ExpiredActivityRecoveryProbeScope {
        &self.scope
    }
    pub const fn request_id(&self) -> Uuid {
        self.request_id
    }
    pub const fn request_digest(&self) -> [u8; STARTED_ACTIVITY_LEASE_RESUME_DIGEST_BYTES] {
        self.request_digest
    }
    pub const fn activity_id(&self) -> ActivityId {
        self.activity.id()
    }
    pub const fn activity(&self) -> &RegisteredActivity {
        &self.activity
    }
    pub const fn initiating_agent(&self) -> &StartedActivityLeaseResumeAgentSnapshot {
        &self.initiating_agent
    }
    pub const fn initiating_session(&self) -> &StartedActivityLeaseResumeSessionSnapshot {
        &self.initiating_session
    }
    pub const fn coordinator(&self) -> &StartedActivityLeaseResumeCoordinatorSnapshot {
        &self.coordinator
    }
    pub const fn source_runtime_instance_id(&self) -> RuntimeInstanceId {
        self.source_runtime_instance_id
    }
    pub const fn probe_digest(&self) -> [u8; STARTED_ACTIVITY_LEASE_RESUME_DIGEST_BYTES] {
        self.probe_digest
    }
    pub const fn resumed_at(&self) -> TimestampMillis {
        self.resumed_at
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum StartedActivityLeaseResumeValidationError {
    #[error("started Activity lease resume identity must not be nil")]
    NilIdentity,
    #[error("started Activity lease resume relative root must not be empty")]
    EmptyRelativeRoot,
    #[error("started Activity lease resume delegation revision must be positive")]
    InvalidFreezeRevision,
    #[error("started Activity lease resume delegation timestamps are out of order")]
    DelegationTimestampOrder,
    #[error("started Activity lease resume census count exceeds its contract bound")]
    CensusCountBounds,
    #[error("started Activity lease resume Agent snapshot does not match its Activity/Session")]
    InitiatingAgentMismatch,
    #[error("started Activity lease resume Coordinator snapshot is inconsistent")]
    CoordinatorMismatch,
    #[error("started Activity lease resume scope/service does not match Source evidence")]
    ScopeMismatch,
    #[error("started Activity lease resume probe expiry overflowed")]
    TimestampOverflow,
    #[error("started Activity lease resume resumable flag and blocker disagree")]
    ProbeBlockerMismatch,
    #[error("started Activity lease resume probe does not authorize a resume")]
    ProbeNotResumable,
    #[error("started Activity lease resume probe has expired or time regressed")]
    ProbeExpired,
    #[error("started Activity lease resume semantic Activity snapshot changed")]
    ActivitySemanticStateChanged,
    #[error("started Activity lease resume lease revision overflowed")]
    LeaseRevisionOverflow,
    #[error("started Activity lease resume committed lease does not match its exact transition")]
    LeaseTransitionMismatch,
    #[error("started Activity lease resume receipt snapshot is inconsistent")]
    ReceiptSnapshotMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ActivityLeaseProjection, ActivityLeaseRevision, ActivityRevision, LocationId,
        LocationRevision, WorkspaceId, WorkspaceRevision,
    };

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    fn id(value: u128) -> Uuid {
        Uuid::from_u128(value)
    }

    fn time(value: i64) -> TestResult<TimestampMillis> {
        Ok(TimestampMillis::new(value)?)
    }

    fn activity(
        owner: Option<RuntimeInstanceId>,
        lease_until: Option<TimestampMillis>,
        lease_revision: ActivityLeaseRevision,
    ) -> TestResult<RegisteredActivity> {
        Ok(RegisteredActivity::from_parts_with_lease(
            ActivityId::from_uuid(id(1)),
            WorkspaceId::from_uuid(id(2)),
            ActivityState::Open,
            time(10)?,
            time(20)?,
            ActivityRevision::INITIAL,
            ActivityLeaseProjection::from_parts(owner, lease_until, lease_revision)?,
        ))
    }

    fn session(
        session_id: AgentSessionId,
    ) -> TestResult<StartedActivityLeaseResumeSessionSnapshot> {
        Ok(StartedActivityLeaseResumeSessionSnapshot::new(
            session_id,
            AuthenticatedPrincipal::TrustedStdio,
            AgentSessionState::Open,
            AgentSessionRevision::INITIAL,
            time(15)?,
        )?)
    }

    fn agent(session_id: AgentSessionId) -> TestResult<StartedActivityLeaseResumeAgentSnapshot> {
        Ok(StartedActivityLeaseResumeAgentSnapshot::new(
            AgentInstanceId::from_uuid(id(3)),
            ActivityId::from_uuid(id(1)),
            session_id,
            AuthenticatedPrincipal::TrustedStdio,
            AgentInstanceRevision::INITIAL,
            true,
        )?)
    }

    fn complete_censuses() -> TestResult<(
        StartedActivityLeaseResumeGoalCensus,
        StartedActivityLeaseResumeDagCensus,
        StartedActivityLeaseResumeAssignmentCensus,
        StartedActivityLeaseResumePhysicalCensus,
    )> {
        Ok((
            StartedActivityLeaseResumeGoalCensus::new(1, [1; 32], false, true)?,
            StartedActivityLeaseResumeDagCensus::new(1, 1, 0, [2; 32], false, true)?,
            StartedActivityLeaseResumeAssignmentCensus::new(1, [3; 32], false, true)?,
            StartedActivityLeaseResumePhysicalCensus::new(
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, [4; 32], false, true,
            )?,
        ))
    }

    fn expectation(started_work_proven: bool) -> TestResult<StartedActivityLeaseResumeExpectation> {
        let session_id = AgentSessionId::from_uuid(id(4));
        let agent = agent(session_id)?;
        let session = session(session_id)?;
        let activity = activity(
            Some(RuntimeInstanceId::from_uuid(id(5))),
            Some(time(80)?),
            ActivityLeaseRevision::new(3)?,
        )?;
        let coordinator = StartedActivityLeaseResumeCoordinatorSnapshot::new(
            agent.agent_id(),
            session.session_id(),
            AuthenticatedPrincipal::TrustedStdio,
            AgentInstanceRevision::INITIAL,
            ActivityCoordinatorRevision::INITIAL,
            time(18)?,
            AgentSessionRevision::INITIAL,
            session.updated_at(),
        )?;
        let (goals, dags, assignments, physical) = complete_censuses()?;
        Ok(StartedActivityLeaseResumeExpectation::new(
            activity,
            Some(agent),
            session,
            Some(coordinator),
            started_work_proven,
            goals,
            dags,
            assignments,
            physical,
        )?)
    }

    fn service() -> TestResult<StartedActivityLeaseResumeServiceIdentity> {
        Ok(StartedActivityLeaseResumeServiceIdentity::new(
            UnstartedActivityContinuationServiceIdentity::new(
                ForgeBackendId::from_uuid(id(6)),
                OrchestrationIssuerId::from_uuid(id(7)),
                RuntimeInstanceId::from_uuid(id(9)),
            )?,
            id(8),
        )?)
    }

    fn scope() -> TestResult<ExpiredActivityRecoveryProbeScope> {
        Ok(ExpiredActivityRecoveryProbeScope::new(
            WorkspaceId::from_uuid(id(2)),
            WorkspaceRevision::INITIAL,
            LocationId::from_uuid(id(10)),
            LocationRevision::INITIAL,
            b"na\xc3\xafve".to_vec(),
            WorkspaceRootFingerprint::from_bytes([7; 16]),
            [8; 32],
        )?)
    }

    fn delegation() -> TestResult<StartedActivityLeaseResumeDelegation> {
        Ok(StartedActivityLeaseResumeDelegation::new(
            id(11),
            id(8),
            2,
            time(1)?,
            time(2)?,
            [5; 32],
            time(3)?,
            [6; 32],
        )?)
    }

    fn resumable_probe() -> TestResult<StartedActivityLeaseResumeProbe> {
        Ok(StartedActivityLeaseResumeProbe::new(
            scope()?,
            service()?,
            delegation()?,
            expectation(true)?,
            time(100)?,
            [9; 32],
            true,
            None,
        )?)
    }

    #[test]
    fn probe_requires_explicit_started_work_and_complete_censuses() -> TestResult {
        let unstarted = StartedActivityLeaseResumeProbe::new(
            scope()?,
            service()?,
            delegation()?,
            expectation(false)?,
            time(100)?,
            [9; 32],
            false,
            Some(StartedActivityLeaseResumeBlocker::ActivityNotStarted),
        )?;
        assert!(!unstarted.resumable_now());
        assert!(!unstarted.started_work_proven());
        assert_eq!(
            unstarted.blocker(),
            Some(StartedActivityLeaseResumeBlocker::ActivityNotStarted)
        );

        let probe = resumable_probe()?;
        assert!(probe.started_work_proven());
        assert!(probe.resumable_now());
        assert_eq!(probe.probe_expires_at(), time(30_100)?);
        Ok(())
    }

    #[test]
    fn probe_requires_source_blocker_for_false_and_visible_facts_for_true() -> TestResult {
        let no_blocker_but_false = StartedActivityLeaseResumeProbe::new(
            scope()?,
            service()?,
            delegation()?,
            expectation(true)?,
            time(100)?,
            [9; 32],
            false,
            None,
        );
        assert_eq!(
            no_blocker_but_false,
            Err(StartedActivityLeaseResumeValidationError::ProbeBlockerMismatch)
        );

        let blocked_but_true = StartedActivityLeaseResumeProbe::new(
            scope()?,
            service()?,
            delegation()?,
            expectation(true)?,
            time(100)?,
            [9; 32],
            true,
            Some(StartedActivityLeaseResumeBlocker::CoordinatorSessionNotOpen),
        );
        assert_eq!(
            blocked_but_true,
            Err(StartedActivityLeaseResumeValidationError::ProbeBlockerMismatch)
        );

        // Coordinator's own Session state is intentionally omitted from the
        // wire snapshot; Source must report its closed state explicitly.
        let coordinator_session_blocked = StartedActivityLeaseResumeProbe::new(
            scope()?,
            service()?,
            delegation()?,
            expectation(true)?,
            time(100)?,
            [9; 32],
            false,
            Some(StartedActivityLeaseResumeBlocker::CoordinatorSessionNotOpen),
        )?;
        assert!(!coordinator_session_blocked.resumable_now());
        Ok(())
    }

    #[test]
    fn receipt_preserves_activity_semantics_and_advances_only_the_owned_lease() -> TestResult {
        let probe = resumable_probe()?;
        let after = activity(
            Some(service()?.runtime_instance_id()),
            Some(time(300_100)?),
            ActivityLeaseRevision::new(4)?,
        )?;
        let receipt = StartedActivityLeaseResumeReceipt::from_successful_probe(
            &probe,
            id(12),
            [10; 32],
            after.clone(),
            time(100)?,
        )?;
        assert_eq!(receipt.schema_version(), 1);
        assert_eq!(receipt.activity(), &after);
        assert_eq!(
            receipt.source_runtime_instance_id(),
            service()?.runtime_instance_id()
        );
        assert_eq!(receipt.resumed_at(), time(100)?);

        let changed = RegisteredActivity::from_parts_with_lease(
            after.id(),
            after.workspace_id(),
            ActivityState::Open,
            after.created_at(),
            time(21)?,
            after.revision(),
            ActivityLeaseProjection::from_parts(
                Some(service()?.runtime_instance_id()),
                Some(time(300_100)?),
                ActivityLeaseRevision::new(4)?,
            )?,
        );
        assert_eq!(
            StartedActivityLeaseResumeReceipt::from_successful_probe(
                &probe,
                id(12),
                [10; 32],
                changed,
                time(100)?,
            ),
            Err(StartedActivityLeaseResumeValidationError::ActivitySemanticStateChanged),
        );
        Ok(())
    }
}
