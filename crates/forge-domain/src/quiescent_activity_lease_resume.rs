//! Typed Source evidence for resuming a quiescent Activity's expired lease.
//!
//! This contract preserves an existing Activity whose Goal/DAG coordination
//! history is still live while proving that no Assignment or physical effect
//! is active. Source supplies the censuses, trusted clock and current boot;
//! this module only validates the frozen values and transition.

use thiserror::Error;
use uuid::Uuid;

use crate::{
    ActivityId, ActivityState, AgentSessionId, AgentSessionState, AuthenticatedPrincipal,
    ExpiredActivityRecoveryProbeScope, RegisteredActivity, RuntimeInstanceId,
    StartedActivityLeaseResumeAgentSnapshot, StartedActivityLeaseResumeAssignmentCensus,
    StartedActivityLeaseResumeCoordinatorSnapshot, StartedActivityLeaseResumeDagCensus,
    StartedActivityLeaseResumeDelegation, StartedActivityLeaseResumeGoalCensus,
    StartedActivityLeaseResumePhysicalCensus, StartedActivityLeaseResumeServiceIdentity,
    StartedActivityLeaseResumeSessionSnapshot, TimestampMillis,
};

pub const QUIESCENT_ACTIVITY_LEASE_RESUME_SCHEMA_VERSION: u16 = 1;
pub const QUIESCENT_ACTIVITY_LEASE_RESUME_CENSUS_VERSION: u16 = 1;
pub const QUIESCENT_ACTIVITY_LEASE_RESUME_DIGEST_BYTES: usize = 32;
pub const QUIESCENT_ACTIVITY_LEASE_RESUME_PROBE_TTL_MS: i64 =
    crate::STARTED_ACTIVITY_LEASE_RESUME_PROBE_TTL_MS;
pub const QUIESCENT_ACTIVITY_LEASE_RESUME_LEASE_DURATION_MS: i64 =
    crate::STARTED_ACTIVITY_LEASE_RESUME_LEASE_DURATION_MS;
pub const QUIESCENT_ACTIVITY_LEASE_RESUME_MAX_AGENT_ROWS: u32 = 1_024;
pub const QUIESCENT_ACTIVITY_LEASE_RESUME_MAX_WORK_UPDATE_ROWS: u32 = 4_096;
pub const QUIESCENT_ACTIVITY_LEASE_RESUME_MAX_WORK_EVIDENCE_REFS: u32 = 131_072;

/// Complete bounded census of Agent rows attached to one Activity.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct QuiescentActivityLeaseResumeAgentCensus {
    row_count: u32,
    digest: [u8; QUIESCENT_ACTIVITY_LEASE_RESUME_DIGEST_BYTES],
    truncated: bool,
    complete: bool,
}

impl QuiescentActivityLeaseResumeAgentCensus {
    pub fn new(
        row_count: u32,
        digest: [u8; QUIESCENT_ACTIVITY_LEASE_RESUME_DIGEST_BYTES],
        truncated: bool,
        complete: bool,
    ) -> Result<Self, QuiescentActivityLeaseResumeValidationError> {
        if row_count > QUIESCENT_ACTIVITY_LEASE_RESUME_MAX_AGENT_ROWS {
            return Err(QuiescentActivityLeaseResumeValidationError::CensusCountBounds);
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
    pub const fn digest(self) -> [u8; QUIESCENT_ACTIVITY_LEASE_RESUME_DIGEST_BYTES] {
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

/// Bounded immutable work-update and evidence-reference history digest.
///
/// Phases are deliberately retained inside the Source digest and are not
/// interpreted as evidence that the Goal or its work is complete.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct QuiescentActivityLeaseResumeWorkHistoryCensus {
    update_count: u32,
    evidence_ref_count: u32,
    digest: [u8; QUIESCENT_ACTIVITY_LEASE_RESUME_DIGEST_BYTES],
    truncated: bool,
    complete: bool,
}

impl QuiescentActivityLeaseResumeWorkHistoryCensus {
    pub fn new(
        update_count: u32,
        evidence_ref_count: u32,
        digest: [u8; QUIESCENT_ACTIVITY_LEASE_RESUME_DIGEST_BYTES],
        truncated: bool,
        complete: bool,
    ) -> Result<Self, QuiescentActivityLeaseResumeValidationError> {
        if update_count > QUIESCENT_ACTIVITY_LEASE_RESUME_MAX_WORK_UPDATE_ROWS
            || evidence_ref_count > QUIESCENT_ACTIVITY_LEASE_RESUME_MAX_WORK_EVIDENCE_REFS
        {
            return Err(QuiescentActivityLeaseResumeValidationError::CensusCountBounds);
        }
        Ok(Self {
            update_count,
            evidence_ref_count,
            digest,
            truncated,
            complete,
        })
    }

    pub const fn update_count(self) -> u32 {
        self.update_count
    }
    pub const fn evidence_ref_count(self) -> u32 {
        self.evidence_ref_count
    }
    pub const fn digest(self) -> [u8; QUIESCENT_ACTIVITY_LEASE_RESUME_DIGEST_BYTES] {
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

/// Count of nonterminal Goals that have a populated current DAG head.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct QuiescentActivityLeaseResumeCoordinationWork {
    nonterminal_goal_count: u32,
    nonterminal_goal_with_current_dag_count: u32,
}

impl QuiescentActivityLeaseResumeCoordinationWork {
    pub fn new(
        nonterminal_goal_count: u32,
        nonterminal_goal_with_current_dag_count: u32,
    ) -> Result<Self, QuiescentActivityLeaseResumeValidationError> {
        if nonterminal_goal_count > crate::STARTED_ACTIVITY_LEASE_RESUME_MAX_GOAL_ROWS
            || nonterminal_goal_with_current_dag_count > nonterminal_goal_count
        {
            return Err(QuiescentActivityLeaseResumeValidationError::CensusCountBounds);
        }
        Ok(Self {
            nonterminal_goal_count,
            nonterminal_goal_with_current_dag_count,
        })
    }

    pub const fn nonterminal_goal_count(self) -> u32 {
        self.nonterminal_goal_count
    }
    pub const fn nonterminal_goal_with_current_dag_count(self) -> u32 {
        self.nonterminal_goal_with_current_dag_count
    }
    const fn identifies_coordination_work(self) -> bool {
        self.nonterminal_goal_with_current_dag_count > 0
    }
}

/// Source-owned facts captured together for one Activity lease-resume probe.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuiescentActivityLeaseResumeExpectation {
    activity: RegisteredActivity,
    initiating_agent: Option<StartedActivityLeaseResumeAgentSnapshot>,
    initiating_session: StartedActivityLeaseResumeSessionSnapshot,
    coordinator: Option<StartedActivityLeaseResumeCoordinatorSnapshot>,
    coordinator_agent_attached: bool,
    coordinator_session_open: bool,
    goal_census: StartedActivityLeaseResumeGoalCensus,
    dag_census: StartedActivityLeaseResumeDagCensus,
    agent_census: QuiescentActivityLeaseResumeAgentCensus,
    coordination_work: QuiescentActivityLeaseResumeCoordinationWork,
    assignment_census: StartedActivityLeaseResumeAssignmentCensus,
    work_history_census: QuiescentActivityLeaseResumeWorkHistoryCensus,
    physical_census: StartedActivityLeaseResumePhysicalCensus,
}

impl QuiescentActivityLeaseResumeExpectation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        activity: RegisteredActivity,
        initiating_agent: Option<StartedActivityLeaseResumeAgentSnapshot>,
        initiating_session: StartedActivityLeaseResumeSessionSnapshot,
        coordinator: Option<StartedActivityLeaseResumeCoordinatorSnapshot>,
        coordinator_agent_attached: bool,
        coordinator_session_open: bool,
        goal_census: StartedActivityLeaseResumeGoalCensus,
        dag_census: StartedActivityLeaseResumeDagCensus,
        agent_census: QuiescentActivityLeaseResumeAgentCensus,
        coordination_work: QuiescentActivityLeaseResumeCoordinationWork,
        assignment_census: StartedActivityLeaseResumeAssignmentCensus,
        work_history_census: QuiescentActivityLeaseResumeWorkHistoryCensus,
        physical_census: StartedActivityLeaseResumePhysicalCensus,
    ) -> Result<Self, QuiescentActivityLeaseResumeValidationError> {
        if activity.id().into_uuid().is_nil()
            || activity.workspace_id().into_uuid().is_nil()
            || initiating_session.session_id().into_uuid().is_nil()
        {
            return Err(QuiescentActivityLeaseResumeValidationError::NilIdentity);
        }
        if let Some(agent) = &initiating_agent
            && (agent.activity_id() != activity.id()
                || agent.session_id() != initiating_session.session_id()
                || agent.principal() != initiating_session.principal())
        {
            return Err(QuiescentActivityLeaseResumeValidationError::InitiatingAgentMismatch);
        }
        Ok(Self {
            activity,
            initiating_agent,
            initiating_session,
            coordinator,
            coordinator_agent_attached,
            coordinator_session_open,
            goal_census,
            dag_census,
            agent_census,
            coordination_work,
            assignment_census,
            work_history_census,
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
    pub const fn coordinator_agent_attached(&self) -> bool {
        self.coordinator_agent_attached
    }
    pub const fn coordinator_session_open(&self) -> bool {
        self.coordinator_session_open
    }
    pub const fn goal_census(&self) -> StartedActivityLeaseResumeGoalCensus {
        self.goal_census
    }
    pub const fn dag_census(&self) -> StartedActivityLeaseResumeDagCensus {
        self.dag_census
    }
    pub const fn agent_census(&self) -> QuiescentActivityLeaseResumeAgentCensus {
        self.agent_census
    }
    pub const fn coordination_work(&self) -> QuiescentActivityLeaseResumeCoordinationWork {
        self.coordination_work
    }
    pub const fn assignment_census(&self) -> StartedActivityLeaseResumeAssignmentCensus {
        self.assignment_census
    }
    pub const fn work_history_census(&self) -> QuiescentActivityLeaseResumeWorkHistoryCensus {
        self.work_history_census
    }
    pub const fn physical_census(&self) -> StartedActivityLeaseResumePhysicalCensus {
        self.physical_census
    }

    fn proves_resumable_at(&self, observed_at: TimestampMillis) -> bool {
        let Some(agent) = &self.initiating_agent else {
            return false;
        };
        let Some(coordinator) = &self.coordinator else {
            return false;
        };
        let activity = &self.activity;
        let Some(owner) = activity.lease_owner_id() else {
            return false;
        };
        let Some(until) = activity.lease_until() else {
            return false;
        };
        let session = &self.initiating_session;
        let physical = self.physical_census;
        activity.state() == ActivityState::Open
            && !owner.into_uuid().is_nil()
            && until.get() <= observed_at.get()
            && session.state() == AgentSessionState::Open
            && agent.attached()
            && coordinator.agent_id() == agent.agent_id()
            && coordinator.agent_revision() == agent.revision()
            && coordinator.principal() == agent.principal()
            && coordinator.session_id() == session.session_id()
            && coordinator.session_revision() == session.revision()
            && coordinator.session_updated_at() == session.updated_at()
            && coordinator.principal() == session.principal()
            && self.coordinator_agent_attached
            && self.coordinator_session_open
            && self.goal_census.complete()
            && !self.goal_census.truncated()
            && self.dag_census.complete()
            && !self.dag_census.truncated()
            && self.agent_census.proves_complete_census()
            && self.coordination_work.identifies_coordination_work()
            && self.assignment_census.complete()
            && !self.assignment_census.truncated()
            && self.assignment_census.row_count() == 0
            && self.work_history_census.proves_complete_census()
            && physical.complete()
            && !physical.truncated()
            && physical.execution_active_count() == 0
            && physical.execution_unknown_count() == 0
            && physical.writer_lease_active_count() == 0
            && physical.writer_lease_unknown_count() == 0
            && physical.pending_effect_count() == 0
            && physical.effect_unknown_count() == 0
            && physical.unresolved_worktree_count() == 0
            && physical.worktree_unknown_count() == 0
            && physical.unknown_count() == 0
    }
}

/// First blocker selected by the Source probe for this separate contract.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QuiescentActivityLeaseResumeBlocker {
    ActivityNotOpen,
    ActivityLeaseMissing,
    ActivityLeaseNotExpired,
    InitiatingAgentMissing,
    InitiatingSessionNotOpen,
    InitiatingAgentNotAttached,
    CoordinatorMissing,
    CoordinatorAgentMismatch,
    CoordinatorAgentNotAttached,
    CoordinatorSessionMismatch,
    CoordinatorSessionNotOpen,
    GoalCensusIncomplete,
    DagCensusIncomplete,
    AgentCensusIncomplete,
    CoordinationWorkMissing,
    AssignmentCensusIncomplete,
    AssignmentPresent,
    WorkHistoryIncomplete,
    PhysicalActivityEffectPresent,
    PhysicalCensusIncomplete,
}

impl QuiescentActivityLeaseResumeBlocker {
    pub const fn as_wire_str(self) -> &'static str {
        match self {
            Self::ActivityNotOpen => "activity_not_open",
            Self::ActivityLeaseMissing => "activity_lease_missing",
            Self::ActivityLeaseNotExpired => "activity_lease_not_expired",
            Self::InitiatingAgentMissing => "initiating_agent_missing",
            Self::InitiatingSessionNotOpen => "initiating_session_not_open",
            Self::InitiatingAgentNotAttached => "initiating_agent_not_attached",
            Self::CoordinatorMissing => "coordinator_missing",
            Self::CoordinatorAgentMismatch => "coordinator_agent_mismatch",
            Self::CoordinatorAgentNotAttached => "coordinator_agent_not_attached",
            Self::CoordinatorSessionMismatch => "coordinator_session_mismatch",
            Self::CoordinatorSessionNotOpen => "coordinator_session_not_open",
            Self::GoalCensusIncomplete => "goal_census_incomplete",
            Self::DagCensusIncomplete => "dag_census_incomplete",
            Self::AgentCensusIncomplete => "agent_census_incomplete",
            Self::CoordinationWorkMissing => "coordination_work_missing",
            Self::AssignmentCensusIncomplete => "assignment_census_incomplete",
            Self::AssignmentPresent => "assignment_present",
            Self::WorkHistoryIncomplete => "work_history_incomplete",
            Self::PhysicalActivityEffectPresent => "physical_activity_effect_present",
            Self::PhysicalCensusIncomplete => "physical_census_incomplete",
        }
    }
}

/// Read-only Source probe. Its fields intentionally do not include the
/// Started contract's started-work proof or its resumability flags.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuiescentActivityLeaseResumeProbe {
    scope: ExpiredActivityRecoveryProbeScope,
    service: StartedActivityLeaseResumeServiceIdentity,
    delegation: StartedActivityLeaseResumeDelegation,
    expectation: QuiescentActivityLeaseResumeExpectation,
    probe_observed_at: TimestampMillis,
    probe_expires_at: TimestampMillis,
    probe_digest: [u8; QUIESCENT_ACTIVITY_LEASE_RESUME_DIGEST_BYTES],
    resumable_now: bool,
    blocker: Option<QuiescentActivityLeaseResumeBlocker>,
}

impl QuiescentActivityLeaseResumeProbe {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: ExpiredActivityRecoveryProbeScope,
        service: StartedActivityLeaseResumeServiceIdentity,
        delegation: StartedActivityLeaseResumeDelegation,
        expectation: QuiescentActivityLeaseResumeExpectation,
        probe_observed_at: TimestampMillis,
        probe_digest: [u8; QUIESCENT_ACTIVITY_LEASE_RESUME_DIGEST_BYTES],
        resumable_now: bool,
        blocker: Option<QuiescentActivityLeaseResumeBlocker>,
    ) -> Result<Self, QuiescentActivityLeaseResumeValidationError> {
        if scope.workspace_id() != expectation.activity.workspace_id()
            || service.destination_id() != delegation.destination_id()
        {
            return Err(QuiescentActivityLeaseResumeValidationError::ScopeMismatch);
        }
        let expiry = probe_observed_at
            .get()
            .checked_add(QUIESCENT_ACTIVITY_LEASE_RESUME_PROBE_TTL_MS)
            .ok_or(QuiescentActivityLeaseResumeValidationError::TimestampOverflow)?;
        let probe_expires_at = TimestampMillis::new(expiry)
            .map_err(|_| QuiescentActivityLeaseResumeValidationError::TimestampOverflow)?;
        if resumable_now != blocker.is_none() {
            return Err(QuiescentActivityLeaseResumeValidationError::ProbeBlockerMismatch);
        }
        if resumable_now && !expectation.proves_resumable_at(probe_observed_at) {
            return Err(QuiescentActivityLeaseResumeValidationError::ProbeNotResumable);
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
    pub const fn delegation(&self) -> StartedActivityLeaseResumeDelegation {
        self.delegation
    }
    pub const fn expectation(&self) -> &QuiescentActivityLeaseResumeExpectation {
        &self.expectation
    }
    pub const fn census_version(&self) -> u16 {
        QUIESCENT_ACTIVITY_LEASE_RESUME_CENSUS_VERSION
    }
    pub const fn probe_observed_at(&self) -> TimestampMillis {
        self.probe_observed_at
    }
    pub const fn probe_expires_at(&self) -> TimestampMillis {
        self.probe_expires_at
    }
    pub const fn probe_digest(&self) -> [u8; QUIESCENT_ACTIVITY_LEASE_RESUME_DIGEST_BYTES] {
        self.probe_digest
    }
    pub const fn resumable_now(&self) -> bool {
        self.resumable_now
    }
    pub const fn blocker(&self) -> Option<QuiescentActivityLeaseResumeBlocker> {
        self.blocker
    }
    pub fn is_live_at(&self, now: TimestampMillis) -> bool {
        now.get() >= self.probe_observed_at.get() && now.get() < self.probe_expires_at.get()
    }
}

/// Validated request for one read-only probe.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuiescentActivityLeaseResumeProbeRequest {
    scope: ExpiredActivityRecoveryProbeScope,
    activity_id: ActivityId,
    initiating_session_id: AgentSessionId,
    principal: AuthenticatedPrincipal,
}

impl QuiescentActivityLeaseResumeProbeRequest {
    pub fn new(
        scope: ExpiredActivityRecoveryProbeScope,
        activity_id: ActivityId,
        initiating_session_id: AgentSessionId,
        principal: AuthenticatedPrincipal,
    ) -> Result<Self, QuiescentActivityLeaseResumeValidationError> {
        if scope.workspace_id().into_uuid().is_nil()
            || activity_id.into_uuid().is_nil()
            || initiating_session_id.into_uuid().is_nil()
            || scope.locator().is_empty()
        {
            return Err(QuiescentActivityLeaseResumeValidationError::NilIdentity);
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

/// Durable exact intent for resuming the existing Activity's lease.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuiescentActivityLeaseResumeRunRequest {
    scope: ExpiredActivityRecoveryProbeScope,
    request_id: Uuid,
    request_digest: [u8; QUIESCENT_ACTIVITY_LEASE_RESUME_DIGEST_BYTES],
    probe: QuiescentActivityLeaseResumeProbe,
    current_service: StartedActivityLeaseResumeServiceIdentity,
}

impl QuiescentActivityLeaseResumeRunRequest {
    pub fn new(
        scope: ExpiredActivityRecoveryProbeScope,
        request_id: Uuid,
        request_digest: [u8; QUIESCENT_ACTIVITY_LEASE_RESUME_DIGEST_BYTES],
        probe: QuiescentActivityLeaseResumeProbe,
        current_service: StartedActivityLeaseResumeServiceIdentity,
    ) -> Result<Self, QuiescentActivityLeaseResumeValidationError> {
        if request_id.is_nil() || scope != *probe.scope() {
            return Err(QuiescentActivityLeaseResumeValidationError::ScopeMismatch);
        }
        if !probe.resumable_now() {
            return Err(QuiescentActivityLeaseResumeValidationError::ProbeNotResumable);
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
    pub const fn request_digest(&self) -> [u8; QUIESCENT_ACTIVITY_LEASE_RESUME_DIGEST_BYTES] {
        self.request_digest
    }
    pub const fn probe(&self) -> &QuiescentActivityLeaseResumeProbe {
        &self.probe
    }
    pub const fn current_service(&self) -> StartedActivityLeaseResumeServiceIdentity {
        self.current_service
    }
}

/// Exact durable receipt selector; it contains no new owner or current boot.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuiescentActivityLeaseResumeGetRequest {
    scope: ExpiredActivityRecoveryProbeScope,
    request_id: Uuid,
    request_digest: [u8; QUIESCENT_ACTIVITY_LEASE_RESUME_DIGEST_BYTES],
    activity_id: ActivityId,
    agent_id: crate::AgentInstanceId,
    initiating_session_id: AgentSessionId,
    principal: AuthenticatedPrincipal,
}

impl QuiescentActivityLeaseResumeGetRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: ExpiredActivityRecoveryProbeScope,
        request_id: Uuid,
        request_digest: [u8; QUIESCENT_ACTIVITY_LEASE_RESUME_DIGEST_BYTES],
        activity_id: ActivityId,
        agent_id: crate::AgentInstanceId,
        initiating_session_id: AgentSessionId,
        principal: AuthenticatedPrincipal,
    ) -> Result<Self, QuiescentActivityLeaseResumeValidationError> {
        if request_id.is_nil()
            || scope.workspace_id().into_uuid().is_nil()
            || activity_id.into_uuid().is_nil()
            || agent_id.into_uuid().is_nil()
            || initiating_session_id.into_uuid().is_nil()
            || scope.locator().is_empty()
        {
            return Err(QuiescentActivityLeaseResumeValidationError::NilIdentity);
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
    pub const fn request_digest(&self) -> [u8; QUIESCENT_ACTIVITY_LEASE_RESUME_DIGEST_BYTES] {
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

/// Durable disposition of one exact mutation request.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuiescentActivityLeaseResumeOperation {
    Recorded(QuiescentActivityLeaseResumeReceipt),
    Replay(QuiescentActivityLeaseResumeReceipt),
}

impl QuiescentActivityLeaseResumeOperation {
    pub const fn receipt(&self) -> &QuiescentActivityLeaseResumeReceipt {
        match self {
            Self::Recorded(receipt) | Self::Replay(receipt) => receipt,
        }
    }
}

/// Immutable result returned by run, get and exact replay.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuiescentActivityLeaseResumeReceipt {
    scope: ExpiredActivityRecoveryProbeScope,
    request_id: Uuid,
    request_digest: [u8; QUIESCENT_ACTIVITY_LEASE_RESUME_DIGEST_BYTES],
    activity_after: RegisteredActivity,
    initiating_agent: StartedActivityLeaseResumeAgentSnapshot,
    initiating_session: StartedActivityLeaseResumeSessionSnapshot,
    coordinator: StartedActivityLeaseResumeCoordinatorSnapshot,
    source_runtime_instance_id: RuntimeInstanceId,
    probe_digest: [u8; QUIESCENT_ACTIVITY_LEASE_RESUME_DIGEST_BYTES],
    resumed_at: TimestampMillis,
}

/// Typed rehydration input for the immutable Q lease-resume receipt codec.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuiescentActivityLeaseResumeReceiptParts {
    pub scope: ExpiredActivityRecoveryProbeScope,
    pub request_id: Uuid,
    pub request_digest: [u8; QUIESCENT_ACTIVITY_LEASE_RESUME_DIGEST_BYTES],
    pub activity_after: RegisteredActivity,
    pub initiating_agent: StartedActivityLeaseResumeAgentSnapshot,
    pub initiating_session: StartedActivityLeaseResumeSessionSnapshot,
    pub coordinator: StartedActivityLeaseResumeCoordinatorSnapshot,
    pub source_runtime_instance_id: RuntimeInstanceId,
    pub probe_digest: [u8; QUIESCENT_ACTIVITY_LEASE_RESUME_DIGEST_BYTES],
    pub resumed_at: TimestampMillis,
}

impl QuiescentActivityLeaseResumeReceipt {
    pub fn from_successful_probe(
        probe: &QuiescentActivityLeaseResumeProbe,
        request_id: Uuid,
        request_digest: [u8; QUIESCENT_ACTIVITY_LEASE_RESUME_DIGEST_BYTES],
        activity_after: RegisteredActivity,
        resumed_at: TimestampMillis,
    ) -> Result<Self, QuiescentActivityLeaseResumeValidationError> {
        let before = probe.expectation().activity();
        let expected_revision = before
            .lease_revision()
            .checked_next()
            .map_err(|_| QuiescentActivityLeaseResumeValidationError::LeaseRevisionOverflow)?;
        let expected_until = resumed_at
            .get()
            .checked_add(QUIESCENT_ACTIVITY_LEASE_RESUME_LEASE_DURATION_MS)
            .ok_or(QuiescentActivityLeaseResumeValidationError::TimestampOverflow)?;
        if request_id.is_nil()
            || !probe.resumable_now()
            || !probe.is_live_at(resumed_at)
            || activity_after.id() != before.id()
            || activity_after.workspace_id() != before.workspace_id()
            || activity_after.state() != before.state()
            || activity_after.revision() != before.revision()
            || activity_after.created_at() != before.created_at()
            || activity_after.updated_at() != before.updated_at()
            || activity_after.lease_owner_id() != Some(probe.service().runtime_instance_id())
            || activity_after.lease_until().map(TimestampMillis::get) != Some(expected_until)
            || activity_after.lease_revision() != expected_revision
        {
            return Err(QuiescentActivityLeaseResumeValidationError::ReceiptSnapshotMismatch);
        }
        Self::from_parts(QuiescentActivityLeaseResumeReceiptParts {
            scope: probe.scope().clone(),
            request_id,
            request_digest,
            activity_after,
            initiating_agent: probe
                .expectation()
                .initiating_agent()
                .copied()
                .ok_or(QuiescentActivityLeaseResumeValidationError::ReceiptSnapshotMismatch)?,
            initiating_session: *probe.expectation().initiating_session(),
            coordinator: probe
                .expectation()
                .coordinator()
                .copied()
                .ok_or(QuiescentActivityLeaseResumeValidationError::ReceiptSnapshotMismatch)?,
            source_runtime_instance_id: probe.service().runtime_instance_id(),
            probe_digest: probe.probe_digest(),
            resumed_at,
        })
    }

    pub fn from_parts(
        parts: QuiescentActivityLeaseResumeReceiptParts,
    ) -> Result<Self, QuiescentActivityLeaseResumeValidationError> {
        let expected_until = parts
            .resumed_at
            .get()
            .checked_add(QUIESCENT_ACTIVITY_LEASE_RESUME_LEASE_DURATION_MS)
            .ok_or(QuiescentActivityLeaseResumeValidationError::TimestampOverflow)?;
        if parts.request_id.is_nil()
            || parts.source_runtime_instance_id.into_uuid().is_nil()
            || parts.scope.workspace_id() != parts.activity_after.workspace_id()
            || parts.activity_after.id() != parts.initiating_agent.activity_id()
            || parts.initiating_agent.session_id() != parts.initiating_session.session_id()
            || parts.initiating_agent.principal() != parts.initiating_session.principal()
            || !parts.initiating_agent.attached()
            || parts.initiating_session.state() != AgentSessionState::Open
            || parts.coordinator.agent_id() != parts.initiating_agent.agent_id()
            || parts.coordinator.agent_revision() != parts.initiating_agent.revision()
            || parts.coordinator.session_id() != parts.initiating_session.session_id()
            || parts.coordinator.session_revision() != parts.initiating_session.revision()
            || parts.coordinator.session_updated_at() != parts.initiating_session.updated_at()
            || parts.coordinator.principal() != parts.initiating_session.principal()
            || parts.activity_after.state() != ActivityState::Open
            || parts.activity_after.lease_owner_id() != Some(parts.source_runtime_instance_id)
            || parts.activity_after.lease_until().map(TimestampMillis::get) != Some(expected_until)
        {
            return Err(QuiescentActivityLeaseResumeValidationError::ReceiptSnapshotMismatch);
        }
        Ok(Self {
            scope: parts.scope,
            request_id: parts.request_id,
            request_digest: parts.request_digest,
            activity_after: parts.activity_after,
            initiating_agent: parts.initiating_agent,
            initiating_session: parts.initiating_session,
            coordinator: parts.coordinator,
            source_runtime_instance_id: parts.source_runtime_instance_id,
            probe_digest: parts.probe_digest,
            resumed_at: parts.resumed_at,
        })
    }

    pub const fn scope(&self) -> &ExpiredActivityRecoveryProbeScope {
        &self.scope
    }
    pub const fn request_id(&self) -> Uuid {
        self.request_id
    }
    pub const fn request_digest(&self) -> [u8; QUIESCENT_ACTIVITY_LEASE_RESUME_DIGEST_BYTES] {
        self.request_digest
    }
    pub const fn activity(&self) -> &RegisteredActivity {
        &self.activity_after
    }
    pub const fn activity_id(&self) -> ActivityId {
        self.activity_after.id()
    }
    pub const fn initiating_agent(&self) -> StartedActivityLeaseResumeAgentSnapshot {
        self.initiating_agent
    }
    pub const fn initiating_session(&self) -> StartedActivityLeaseResumeSessionSnapshot {
        self.initiating_session
    }
    pub const fn coordinator(&self) -> StartedActivityLeaseResumeCoordinatorSnapshot {
        self.coordinator
    }
    pub const fn source_runtime_instance_id(&self) -> RuntimeInstanceId {
        self.source_runtime_instance_id
    }
    pub const fn probe_digest(&self) -> [u8; QUIESCENT_ACTIVITY_LEASE_RESUME_DIGEST_BYTES] {
        self.probe_digest
    }
    pub const fn resumed_at(&self) -> TimestampMillis {
        self.resumed_at
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum QuiescentActivityLeaseResumeValidationError {
    #[error("quiescent Activity lease resume identity must not be nil")]
    NilIdentity,
    #[error("quiescent Activity lease resume census count exceeds its contract bound")]
    CensusCountBounds,
    #[error("quiescent Activity lease resume Agent snapshot does not match its Activity/Session")]
    InitiatingAgentMismatch,
    #[error("quiescent Activity lease resume Coordinator snapshot is inconsistent")]
    CoordinatorMismatch,
    #[error("quiescent Activity lease resume scope/service does not match Source evidence")]
    ScopeMismatch,
    #[error("quiescent Activity lease resume probe expiry overflowed")]
    TimestampOverflow,
    #[error("quiescent Activity lease resume resumable flag and blocker disagree")]
    ProbeBlockerMismatch,
    #[error("quiescent Activity lease resume probe does not authorize a resume")]
    ProbeNotResumable,
    #[error("quiescent Activity lease resume probe has expired or time regressed")]
    ProbeExpired,
    #[error("quiescent Activity lease resume lease revision overflowed")]
    LeaseRevisionOverflow,
    #[error("quiescent Activity lease resume receipt snapshot is inconsistent")]
    ReceiptSnapshotMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quiescent_contract_is_distinct_and_bounds_censuses() {
        assert!(
            QuiescentActivityLeaseResumeAgentCensus::new(
                QUIESCENT_ACTIVITY_LEASE_RESUME_MAX_AGENT_ROWS + 1,
                [0; 32],
                false,
                true,
            )
            .is_err()
        );
        assert!(
            QuiescentActivityLeaseResumeWorkHistoryCensus::new(
                0,
                QUIESCENT_ACTIVITY_LEASE_RESUME_MAX_WORK_EVIDENCE_REFS + 1,
                [0; 32],
                false,
                true,
            )
            .is_err()
        );
        assert!(QuiescentActivityLeaseResumeCoordinationWork::new(0, 1).is_err());
    }
}
