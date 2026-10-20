//! Typed fences for continuing an expired, positively unstarted Activity.
//!
//! This contract transfers only the Activity lease to the current trusted
//! Source service. It does not renew a live owner, create a successor, or
//! certify Agent/Session readiness.

use thiserror::Error;
use uuid::Uuid;

use crate::{
    AgentSessionId, AuthenticatedPrincipal, ExpectedActivityCoordinator, ExpectedExpiredActivity,
    ExpiredActivityRecoveryDelegationFence, ExpiredActivityRecoveryProbeScope, ForgeBackendId,
    OrchestrationIssuerId, RuntimeInstanceId, TimestampMillis,
};

pub const UNSTARTED_ACTIVITY_CONTINUATION_CENSUS_VERSION: u16 = 1;
pub const UNSTARTED_ACTIVITY_CONTINUATION_DIGEST_BYTES: usize = 32;
pub const UNSTARTED_ACTIVITY_CONTINUATION_MAX_AGENT_COUNT: u16 = 256;

/// Trusted server identity. Callers may compare this tuple but may not mint it.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UnstartedActivityContinuationServiceIdentity {
    backend_id: ForgeBackendId,
    issuer: OrchestrationIssuerId,
    runtime_instance_id: RuntimeInstanceId,
}

impl UnstartedActivityContinuationServiceIdentity {
    pub fn new(
        backend_id: ForgeBackendId,
        issuer: OrchestrationIssuerId,
        runtime_instance_id: RuntimeInstanceId,
    ) -> Result<Self, UnstartedActivityContinuationValidationError> {
        if backend_id.into_uuid().is_nil()
            || issuer.into_uuid().is_nil()
            || runtime_instance_id.into_uuid().is_nil()
        {
            return Err(UnstartedActivityContinuationValidationError::NilIdentity);
        }
        Ok(Self {
            backend_id,
            issuer,
            runtime_instance_id,
        })
    }

    pub const fn backend_id(self) -> ForgeBackendId {
        self.backend_id
    }
    pub const fn issuer(self) -> OrchestrationIssuerId {
        self.issuer
    }
    pub const fn runtime_instance_id(self) -> RuntimeInstanceId {
        self.runtime_instance_id
    }
}

/// Exact immutable state accepted by the continuation run.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnstartedActivityContinuationExpectation {
    activity: ExpectedExpiredActivity,
    initiating_session_id: AgentSessionId,
    principal: AuthenticatedPrincipal,
    expected_agent_count: u16,
    expected_agent_digest: [u8; UNSTARTED_ACTIVITY_CONTINUATION_DIGEST_BYTES],
    expected_plan_digest: [u8; UNSTARTED_ACTIVITY_CONTINUATION_DIGEST_BYTES],
    expected_coordinator: Option<ExpectedActivityCoordinator>,
}

impl UnstartedActivityContinuationExpectation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        activity: ExpectedExpiredActivity,
        initiating_session_id: AgentSessionId,
        principal: AuthenticatedPrincipal,
        expected_agent_count: u16,
        expected_agent_digest: [u8; UNSTARTED_ACTIVITY_CONTINUATION_DIGEST_BYTES],
        expected_plan_digest: [u8; UNSTARTED_ACTIVITY_CONTINUATION_DIGEST_BYTES],
        expected_coordinator: Option<ExpectedActivityCoordinator>,
    ) -> Result<Self, UnstartedActivityContinuationValidationError> {
        if initiating_session_id.into_uuid().is_nil() {
            return Err(UnstartedActivityContinuationValidationError::NilIdentity);
        }
        if !(1..=UNSTARTED_ACTIVITY_CONTINUATION_MAX_AGENT_COUNT).contains(&expected_agent_count) {
            return Err(UnstartedActivityContinuationValidationError::AgentCountBounds);
        }
        if expected_agent_digest == [0; UNSTARTED_ACTIVITY_CONTINUATION_DIGEST_BYTES]
            || expected_plan_digest == [0; UNSTARTED_ACTIVITY_CONTINUATION_DIGEST_BYTES]
        {
            return Err(UnstartedActivityContinuationValidationError::ZeroDigest);
        }
        Ok(Self {
            activity,
            initiating_session_id,
            principal,
            expected_agent_count,
            expected_agent_digest,
            expected_plan_digest,
            expected_coordinator,
        })
    }

    pub const fn activity(&self) -> ExpectedExpiredActivity {
        self.activity
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
    pub const fn expected_agent_digest(&self) -> [u8; 32] {
        self.expected_agent_digest
    }
    pub const fn expected_plan_digest(&self) -> [u8; 32] {
        self.expected_plan_digest
    }
    pub const fn expected_coordinator(&self) -> Option<ExpectedActivityCoordinator> {
        self.expected_coordinator
    }
}

/// The first fail-closed reason found by the closed schema-v66 census.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnstartedActivityContinuationBlocker {
    ActivityNotOpen,
    LeaseNotExpired,
    GoalNotActive,
    DagNotPendingInitial,
    DagEvidencePresent,
    AssignmentNotOffered,
    AssignmentEvidencePresent,
    ArbitraryWorkHistory,
    ExecutionPresent,
    WriterLeasePresent,
    PhysicalEffectPresent,
    PendingActivation,
    OrphanRecord,
    UnclassifiedSchemaObject,
}

/// Read-only probe. A run must re-compute every field after `BEGIN IMMEDIATE`.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnstartedActivityContinuationProbe {
    scope: ExpiredActivityRecoveryProbeScope,
    delegation: ExpiredActivityRecoveryDelegationFence,
    delegation_digest: [u8; 32],
    service: UnstartedActivityContinuationServiceIdentity,
    expectation: UnstartedActivityContinuationExpectation,
    observed_at: TimestampMillis,
    census_version: u16,
    blocker: Option<UnstartedActivityContinuationBlocker>,
    probe_digest: [u8; 32],
}

impl UnstartedActivityContinuationProbe {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: ExpiredActivityRecoveryProbeScope,
        delegation: ExpiredActivityRecoveryDelegationFence,
        delegation_digest: [u8; 32],
        service: UnstartedActivityContinuationServiceIdentity,
        expectation: UnstartedActivityContinuationExpectation,
        observed_at: TimestampMillis,
        blocker: Option<UnstartedActivityContinuationBlocker>,
        probe_digest: [u8; 32],
    ) -> Result<Self, UnstartedActivityContinuationValidationError> {
        if delegation_digest == [0; 32] || probe_digest == [0; 32] {
            return Err(UnstartedActivityContinuationValidationError::ZeroDigest);
        }
        Ok(Self {
            scope,
            delegation,
            delegation_digest,
            service,
            expectation,
            observed_at,
            census_version: UNSTARTED_ACTIVITY_CONTINUATION_CENSUS_VERSION,
            blocker,
            probe_digest,
        })
    }

    pub const fn scope(&self) -> &ExpiredActivityRecoveryProbeScope {
        &self.scope
    }
    pub const fn delegation(&self) -> ExpiredActivityRecoveryDelegationFence {
        self.delegation
    }
    pub const fn delegation_digest(&self) -> [u8; 32] {
        self.delegation_digest
    }
    pub const fn service(&self) -> UnstartedActivityContinuationServiceIdentity {
        self.service
    }
    pub const fn expectation(&self) -> &UnstartedActivityContinuationExpectation {
        &self.expectation
    }
    pub const fn observed_at(&self) -> TimestampMillis {
        self.observed_at
    }
    pub const fn census_version(&self) -> u16 {
        self.census_version
    }
    pub const fn blocker(&self) -> Option<UnstartedActivityContinuationBlocker> {
        self.blocker
    }
    pub const fn probe_digest(&self) -> [u8; 32] {
        self.probe_digest
    }
    pub const fn continuable_now(&self) -> bool {
        self.blocker.is_none()
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum UnstartedActivityContinuationValidationError {
    #[error("unstarted Activity continuation identity is nil")]
    NilIdentity,
    #[error("unstarted Activity continuation digest is zero")]
    ZeroDigest,
    #[error("unstarted Activity continuation Agent count is outside 1..=256")]
    AgentCountBounds,
}

/// Stable request identity used by the immutable continuation ledger.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UnstartedActivityContinuationRequestId(Uuid);

impl UnstartedActivityContinuationRequestId {
    pub fn new(value: Uuid) -> Result<Self, UnstartedActivityContinuationValidationError> {
        if value.is_nil() {
            return Err(UnstartedActivityContinuationValidationError::NilIdentity);
        }
        Ok(Self(value))
    }
    pub const fn into_uuid(self) -> Uuid {
        self.0
    }
}
