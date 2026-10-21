//! Atomic same-Activity continuation for an expired, positively unstarted plan.

use std::error::Error;

use forge_domain::{
    ActivityLeaseRevision, ActivityRevision, ActivityState, AuthenticatedPrincipal,
    ClaimRecoveryLease, DirectTokenId, ExpectedActivityCoordinator, ExpectedExpiredActivity,
    ExpiredActivityRecoveryAgentSnapshot, ExpiredActivityRecoveryDelegationFence,
    ExpiredActivityRecoveryProbeScope, ExpiredActivityRecoverySessionEvidence, ForgeBackendId,
    OAuthGrantId, OrchestrationIssuerId, RecoveryLeaseDurationMillis, RecoveryMaintenanceLease,
    RegisteredActivity, ReleaseRecoveryLease, RuntimeInstanceId, TimestampMillis,
    UNSTARTED_ACTIVITY_CONTINUATION_CENSUS_VERSION, UnstartedActivityContinuationBlocker,
    UnstartedActivityContinuationExpectation, UnstartedActivityContinuationProbe,
    UnstartedActivityContinuationRequestId, UnstartedActivityContinuationServiceIdentity,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use super::{
    WorkspaceJournalBinding, WorkspaceLiveBinding, WorkspaceStore, WorkspaceStoreError,
    ensure_live_paths,
};

pub(crate) mod agent_metadata;
mod forbidden_inventory;
mod normal_bootstrap_provenance;
mod planning_provenance;
pub(crate) mod provenance;

const DOMAIN_PROBE: &[u8] = b"heterarchy.forge.unstarted-activity-continuation.probe.v1";
const DOMAIN_PLAN: &[u8] = b"heterarchy.forge.unstarted-activity-continuation.plan.v1";
const DOMAIN_RECEIPT: &[u8] = b"heterarchy.forge.unstarted-activity-continuation.receipt.v1";
const MAX_AGENT_ROWS: usize = forge_domain::MAX_AGENT_LIST_RESULTS as usize;
const AGENT_CENSUS_LIMIT: usize = MAX_AGENT_ROWS + 1;

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnstartedActivityContinuationStoreRequest {
    pub request_id: UnstartedActivityContinuationRequestId,
    pub request_digest: [u8; 32],
    pub probe_scope: ExpiredActivityRecoveryProbeScope,
    pub probe_observed_at: TimestampMillis,
    pub probe_digest: [u8; 32],
    pub delegation: ExpiredActivityRecoveryDelegationFence,
    pub delegation_digest: [u8; 32],
    pub service: UnstartedActivityContinuationServiceIdentity,
    pub service_destination_id: Uuid,
    pub duration: RecoveryLeaseDurationMillis,
    pub expectation: UnstartedActivityContinuationExpectation,
    pub session: ExpiredActivityRecoverySessionEvidence,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnstartedActivityContinuationReceipt {
    request_id: UnstartedActivityContinuationRequestId,
    request_digest: [u8; 32],
    probe_scope: ExpiredActivityRecoveryProbeScope,
    probe_observed_at: TimestampMillis,
    probe_digest: [u8; 32],
    delegation: ExpiredActivityRecoveryDelegationFence,
    delegation_digest: [u8; 32],
    service: UnstartedActivityContinuationServiceIdentity,
    service_destination_id: Uuid,
    session: ExpiredActivityRecoverySessionEvidence,
    expectation: UnstartedActivityContinuationExpectation,
    continued_at: TimestampMillis,
    lease_gap_ms: i64,
    activity_after: RegisteredActivity,
    receipt_digest: [u8; 32],
}

impl UnstartedActivityContinuationReceipt {
    pub const fn request_id(&self) -> UnstartedActivityContinuationRequestId {
        self.request_id
    }
    pub const fn request_digest(&self) -> [u8; 32] {
        self.request_digest
    }
    pub const fn probe_scope(&self) -> &ExpiredActivityRecoveryProbeScope {
        &self.probe_scope
    }
    pub const fn probe_observed_at(&self) -> TimestampMillis {
        self.probe_observed_at
    }
    pub const fn probe_digest(&self) -> [u8; 32] {
        self.probe_digest
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
    pub const fn service_destination_id(&self) -> Uuid {
        self.service_destination_id
    }
    pub const fn session(&self) -> ExpiredActivityRecoverySessionEvidence {
        self.session
    }
    pub const fn expectation(&self) -> &UnstartedActivityContinuationExpectation {
        &self.expectation
    }
    pub const fn continued_at(&self) -> TimestampMillis {
        self.continued_at
    }
    pub const fn lease_gap_ms(&self) -> i64 {
        self.lease_gap_ms
    }
    pub const fn activity_after(&self) -> &RegisteredActivity {
        &self.activity_after
    }
    pub const fn receipt_digest(&self) -> [u8; 32] {
        self.receipt_digest
    }
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnstartedActivityContinuationReadback {
    receipt: UnstartedActivityContinuationReceipt,
    current_activity: RegisteredActivity,
}

impl UnstartedActivityContinuationReadback {
    pub const fn receipt(&self) -> &UnstartedActivityContinuationReceipt {
        &self.receipt
    }
    pub const fn current_activity(&self) -> &RegisteredActivity {
        &self.current_activity
    }
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnstartedActivityContinuationOperation {
    Recorded(UnstartedActivityContinuationReceipt),
    Replay(UnstartedActivityContinuationReceipt),
    Busy(RecoveryMaintenanceLease),
    ClaimConflict(RecoveryMaintenanceLease),
}

#[derive(Debug, Error)]
pub enum UnstartedActivityContinuationStoreError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error("unstarted Activity continuation input is invalid: {0}")]
    Invalid(&'static str),
    #[error("unstarted Activity continuation conflicts with durable state: {0}")]
    Conflict(&'static str),
    #[error("unstarted Activity continuation state is corrupt: {0}")]
    Corrupt(&'static str),
    #[error("unstarted Activity continuation clock observation failed")]
    Clock(#[source] Box<dyn Error + Send + Sync>),
    #[error(transparent)]
    Recovery(#[from] crate::RecoveryStoreError),
    #[error(transparent)]
    Agent(#[from] crate::AgentStoreError),
    #[error(transparent)]
    Coordinator(#[from] crate::CoordinatorStoreError),
    #[error(transparent)]
    Delegation(#[from] crate::AgentOperationsDelegationError),
    #[error(transparent)]
    ExpiredRecovery(#[from] super::expired_activity_recovery::ExpiredActivityRecoveryStoreError),
    #[error(transparent)]
    Domain(#[from] forge_domain::UnstartedActivityContinuationValidationError),
    #[error("unstarted Activity continuation Workspace persistence failure")]
    Workspace(#[source] Box<WorkspaceStoreError>),
}

impl From<WorkspaceStoreError> for UnstartedActivityContinuationStoreError {
    fn from(value: WorkspaceStoreError) -> Self {
        Self::Workspace(Box::new(value))
    }
}

impl WorkspaceStore {
    #[allow(
        clippy::too_many_arguments,
        reason = "The probe keeps trusted service identity and authenticated Session evidence explicit."
    )]
    pub fn probe_unstarted_activity_continuation(
        &self,
        binding: &WorkspaceJournalBinding,
        scope: &ExpiredActivityRecoveryProbeScope,
        activity_id: forge_domain::ActivityId,
        initiating_session_id: forge_domain::AgentSessionId,
        principal: AuthenticatedPrincipal,
        service: UnstartedActivityContinuationServiceIdentity,
        observed_at: TimestampMillis,
    ) -> Result<UnstartedActivityContinuationProbe, WorkspaceStoreError> {
        if self.journal_binding()? != *binding
            || binding.recovery_history_digest() != *scope.binding_digest()
        {
            return Err(UnstartedActivityContinuationStoreError::Conflict("binding").into());
        }
        super::validate_schema_shape(&self.connection)?;
        let transaction = self.connection.unchecked_transaction()?;
        if !crate::workspace_recovery::get(&transaction, scope.workspace_id())?.is_released() {
            return Err(UnstartedActivityContinuationStoreError::Conflict(
                "recovery maintenance unavailable",
            )
            .into());
        }
        let result = probe_in_transaction(
            &transaction,
            scope,
            activity_id,
            initiating_session_id,
            principal,
            service,
            observed_at,
        );
        match result {
            Ok(value) => {
                transaction.commit()?;
                Ok(value)
            }
            Err(error) => {
                let _ = transaction.rollback();
                Err(error.into())
            }
        }
    }

    pub fn unstarted_activity_continuation_readback_for_request(
        &self,
        binding: &WorkspaceJournalBinding,
        request_id: UnstartedActivityContinuationRequestId,
        request_digest: [u8; 32],
    ) -> Result<Option<UnstartedActivityContinuationReadback>, WorkspaceStoreError> {
        if self.journal_binding()? != *binding || request_digest == [0; 32] {
            return Err(
                UnstartedActivityContinuationStoreError::Conflict("binding/request").into(),
            );
        }
        let Some(receipt) = load_receipt(&self.connection, request_id)? else {
            return Ok(None);
        };
        if receipt.request_digest != request_digest {
            return Err(UnstartedActivityContinuationStoreError::Conflict("request digest").into());
        }
        let raw = super::query_activity_row(
            &self.connection,
            receipt.expectation.activity().activity_id(),
        )?
        .ok_or(UnstartedActivityContinuationStoreError::Corrupt(
            "current Activity missing",
        ))?;
        let current_activity = super::decode_activity(&raw)?;
        Ok(Some(UnstartedActivityContinuationReadback {
            receipt,
            current_activity,
        }))
    }

    pub fn run_unstarted_activity_continuation_with_clock<F>(
        &mut self,
        binding: &WorkspaceJournalBinding,
        request: &UnstartedActivityContinuationStoreRequest,
        clock: F,
    ) -> Result<UnstartedActivityContinuationOperation, WorkspaceStoreError>
    where
        F: FnOnce() -> Result<TimestampMillis, WorkspaceStoreError>,
    {
        let live_binding = self.journal_binding()?;
        if live_binding != *binding
            || binding.recovery_history_digest() != *request.probe_scope.binding_digest()
        {
            return Err(UnstartedActivityContinuationStoreError::Conflict("binding").into());
        }
        let live_paths = WorkspaceLiveBinding {
            state_root: &self.state_root,
            state_root_identity: self.state_root_identity,
            workspace_root: &self.workspace_root,
            root_fingerprint: self.root_fingerprint,
            database_path: &self.path,
            database_identity: self.database_identity,
            wal_identity: self.wal_identity,
            shm_identity: self.shm_identity,
        };
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_live_paths(live_paths)?;
        let result = run_in_transaction(&transaction, binding, request, || {
            let observed_at = clock()?;
            ensure_live_paths(live_paths)?;
            Ok(observed_at)
        });
        match result {
            Ok(value) => {
                ensure_live_paths(live_paths)?;
                transaction.commit().map_err(|source| {
                    WorkspaceStoreError::UnstartedActivityContinuationCommittedUnconfirmed {
                        request_id: request.request_id,
                        source: Box::new(WorkspaceStoreError::Sqlite(source)),
                    }
                })?;
                if let UnstartedActivityContinuationOperation::Recorded(receipt) = &value {
                    let confirmation = self.unstarted_activity_continuation_readback_for_request(
                        binding,
                        request.request_id,
                        request.request_digest,
                    );
                    let confirmed = match confirmation {
                        Ok(readback) => {
                            readback.is_some_and(|readback| readback.receipt() == receipt)
                        }
                        Err(source) => {
                            return Err(WorkspaceStoreError::UnstartedActivityContinuationCommittedUnconfirmed {
                                request_id: request.request_id,
                                source: Box::new(source),
                            });
                        }
                    };
                    if !confirmed {
                        return Err(
                            WorkspaceStoreError::UnstartedActivityContinuationCommittedUnconfirmed {
                                request_id: request.request_id,
                                source: Box::new(WorkspaceStoreError::DamagedSchema {
                                    detail: "continuation exact readback missing after commit".to_owned(),
                                }),
                            },
                        );
                    }
                }
                Ok(value)
            }
            Err(error) => {
                let _ = transaction.rollback();
                Err(error.into())
            }
        }
    }
}

/// Test-only read-only probe over a raw transaction; no binding, claim or mutation.
#[cfg(test)]
pub(super) fn probe_raw_for_test(
    transaction: &Transaction<'_>,
    scope: &ExpiredActivityRecoveryProbeScope,
    activity_id: forge_domain::ActivityId,
    initiating_session_id: forge_domain::AgentSessionId,
    principal: AuthenticatedPrincipal,
    service: UnstartedActivityContinuationServiceIdentity,
    observed_at: TimestampMillis,
) -> Result<UnstartedActivityContinuationProbe, UnstartedActivityContinuationStoreError> {
    probe_in_transaction(
        transaction,
        scope,
        activity_id,
        initiating_session_id,
        principal,
        service,
        observed_at,
    )
}

/// Test-only per-component census report for diagnosing a copied snapshot.
#[cfg(test)]
pub(super) fn census_components_for_test(
    connection: &Connection,
    workspace_id: forge_domain::WorkspaceId,
    activity_id: forge_domain::ActivityId,
) -> Vec<(&'static str, String)> {
    vec![
        (
            "forbidden_inventory",
            format!(
                "{:?}",
                forbidden_inventory::validate_forbidden_inventory_empty(
                    connection,
                    workspace_id,
                    activity_id
                )
            ),
        ),
        (
            "planning_provenance",
            format!(
                "{:?}",
                planning_provenance::validate_and_digest_planning_provenance(
                    connection,
                    workspace_id,
                    activity_id
                )
                .map(|_| ())
            ),
        ),
        (
            "p28_provenance",
            format!(
                "{:?}",
                provenance::validate_and_digest_p28_provenance(
                    connection,
                    workspace_id,
                    activity_id
                )
                .map(|_| ())
            ),
        ),
        (
            "plan_census",
            format!(
                "{:?}",
                plan_census(connection, workspace_id, activity_id).map(|(_, blocker)| blocker)
            ),
        ),
    ]
}

#[allow(
    clippy::too_many_lines,
    reason = "The read-only snapshot visibly binds Workspace, Activity, delegation, team, Coordinator, service boot, and plan census."
)]
fn probe_in_transaction(
    transaction: &Transaction<'_>,
    scope: &ExpiredActivityRecoveryProbeScope,
    activity_id: forge_domain::ActivityId,
    initiating_session_id: forge_domain::AgentSessionId,
    principal: AuthenticatedPrincipal,
    service: UnstartedActivityContinuationServiceIdentity,
    observed_at: TimestampMillis,
) -> Result<UnstartedActivityContinuationProbe, UnstartedActivityContinuationStoreError> {
    let workspace_raw = super::query_workspace_row(transaction)?.ok_or(
        UnstartedActivityContinuationStoreError::Conflict("Workspace missing"),
    )?;
    let workspace = super::decode_workspace(workspace_raw)?;
    if workspace.id() != scope.workspace_id()
        || workspace.revision() != scope.workspace_revision()
        || workspace.location_id() != scope.location_id()
        || workspace.root_fingerprint() != scope.root_fingerprint()
    {
        return Err(UnstartedActivityContinuationStoreError::Conflict(
            "Workspace scope fence",
        ));
    }
    let raw = super::query_activity_row(transaction, activity_id)?.ok_or(
        UnstartedActivityContinuationStoreError::Conflict("Activity missing"),
    )?;
    let activity = super::decode_activity(&raw)?;
    let (owner, until) = activity
        .lease_owner_id()
        .zip(activity.lease_until())
        .ok_or(UnstartedActivityContinuationStoreError::Conflict(
            "Activity lease missing",
        ))?;
    let expected_activity = ExpectedExpiredActivity::new(
        activity.id(),
        activity.revision(),
        activity.created_at(),
        activity.updated_at(),
        owner,
        until,
        activity.lease_revision(),
    )
    .map_err(|_| UnstartedActivityContinuationStoreError::Corrupt("Activity fence"))?;
    let (delegation, delegation_digest) =
        super::expired_activity_recovery::load_delegation_fence(transaction, scope.workspace_id())?;
    let agents = crate::workspace_agents::list_for_activity_in_transaction(
        transaction,
        scope.workspace_id(),
        activity_id,
        u32::try_from(AGENT_CENSUS_LIMIT)
            .map_err(|_| UnstartedActivityContinuationStoreError::Conflict("Agent census limit"))?,
    )?;
    let snapshots = agents
        .iter()
        .map(ExpiredActivityRecoveryAgentSnapshot::from_agent)
        .collect::<Vec<_>>();
    if snapshots.is_empty() || snapshots.len() > MAX_AGENT_ROWS {
        return Err(UnstartedActivityContinuationStoreError::Conflict(
            "Agent census bounds",
        ));
    }
    let agent_digest = super::expired_activity_recovery::agents_digest(&snapshots);
    let coordinator = crate::workspace_coordinators::get_in_transaction(transaction, activity_id)?
        .map(|value| {
            ExpectedActivityCoordinator::new(
                value.agent_id(),
                value.revision().get(),
                value.updated_at(),
            )
        })
        .transpose()
        .map_err(|_| UnstartedActivityContinuationStoreError::Corrupt("Coordinator"))?
        .ok_or(UnstartedActivityContinuationStoreError::Conflict(
            "Coordinator missing",
        ))?;
    if snapshots
        .iter()
        .find(|agent| agent.agent_id() == coordinator.agent_id())
        .is_none_or(|agent| {
            agent.session_id() != Some(initiating_session_id) || agent.principal() != principal
        })
    {
        return Err(UnstartedActivityContinuationStoreError::Conflict(
            "initiating Coordinator Session",
        ));
    }
    let agent_metadata_digest = agent_metadata::validate_and_digest_agent_metadata(
        transaction,
        scope.workspace_id(),
        activity_id,
        &snapshots,
        coordinator,
    )?;
    let provenance_digest = if provenance::p28_lineage_present(transaction, activity_id)? {
        provenance::validate_and_digest_p28_provenance(
            transaction,
            scope.workspace_id(),
            activity_id,
        )?
    } else {
        normal_bootstrap_provenance::validate_and_digest_normal_bootstrap_provenance(
            transaction,
            scope.workspace_id(),
            activity_id,
            scope,
            &activity,
            initiating_session_id,
            principal,
            coordinator,
            delegation,
            delegation_digest,
        )?
    };
    let forbidden_blocker = match forbidden_inventory::validate_forbidden_inventory_empty(
        transaction,
        scope.workspace_id(),
        activity_id,
    ) {
        Ok(()) => None,
        Err(UnstartedActivityContinuationStoreError::Conflict(_)) => {
            Some(UnstartedActivityContinuationBlocker::PhysicalEffectPresent)
        }
        Err(UnstartedActivityContinuationStoreError::Corrupt(
            "forbidden inventory attribution",
        )) => Some(UnstartedActivityContinuationBlocker::OrphanRecord),
        Err(error) => return Err(error),
    };
    let (planning_provenance_digest, provenance_blocker) = if forbidden_blocker.is_some() {
        ([0xF1; 32], None)
    } else {
        match planning_provenance::validate_and_digest_planning_provenance(
            transaction,
            scope.workspace_id(),
            activity_id,
        ) {
            Ok(digest) => (digest, None),
            Err(UnstartedActivityContinuationStoreError::Conflict(_)) => (
                [0xF2; 32],
                Some(UnstartedActivityContinuationBlocker::PhysicalEffectPresent),
            ),
            Err(error) => return Err(error),
        }
    };
    let (base_plan_digest, plan_blocker) =
        plan_census(transaction, scope.workspace_id(), activity_id)?;
    let mut plan_hasher = Sha256::new();
    plan_hasher.update(DOMAIN_PLAN);
    plan_hasher.update(base_plan_digest);
    plan_hasher.update(agent_metadata_digest);
    plan_hasher.update(provenance_digest);
    plan_hasher.update(planning_provenance_digest);
    let plan_digest = plan_hasher.finalize().into();
    let blocker = if activity.state() != ActivityState::Open {
        Some(UnstartedActivityContinuationBlocker::ActivityNotOpen)
    } else if until.get() > observed_at.get() {
        Some(UnstartedActivityContinuationBlocker::LeaseNotExpired)
    } else {
        plan_blocker.or(provenance_blocker).or(forbidden_blocker)
    };
    let expectation = UnstartedActivityContinuationExpectation::new(
        expected_activity,
        initiating_session_id,
        principal,
        u16::try_from(snapshots.len())
            .map_err(|_| UnstartedActivityContinuationStoreError::Conflict("Agent census"))?,
        agent_digest,
        plan_digest,
        Some(coordinator),
    )?;
    let probe_digest = digest_probe(
        scope,
        delegation_digest,
        service,
        &expectation,
        observed_at,
        blocker,
    );
    Ok(UnstartedActivityContinuationProbe::new(
        scope.clone(),
        delegation,
        delegation_digest,
        service,
        expectation,
        observed_at,
        blocker,
        probe_digest,
    )?)
}

#[allow(
    clippy::too_many_lines,
    reason = "The single IMMEDIATE transaction keeps claim, full CAS recheck, mutation, receipt, and release visibly atomic."
)]
fn run_in_transaction<F>(
    transaction: &Transaction<'_>,
    binding: &WorkspaceJournalBinding,
    request: &UnstartedActivityContinuationStoreRequest,
    clock: F,
) -> Result<UnstartedActivityContinuationOperation, UnstartedActivityContinuationStoreError>
where
    F: FnOnce() -> Result<TimestampMillis, WorkspaceStoreError>,
{
    if let Some(receipt) = load_receipt(transaction, request.request_id)? {
        if receipt.request_digest != request.request_digest {
            return Err(UnstartedActivityContinuationStoreError::Conflict(
                "request digest",
            ));
        }
        return Ok(UnstartedActivityContinuationOperation::Replay(receipt));
    }
    let continued_at =
        clock().map_err(|error| UnstartedActivityContinuationStoreError::Clock(Box::new(error)))?;
    let claim = ClaimRecoveryLease::new(
        request.probe_scope.workspace_id(),
        request.service.runtime_instance_id(),
        request.duration,
        continued_at,
    )
    .map_err(|_| UnstartedActivityContinuationStoreError::Invalid("maintenance claim"))?;
    let claimed = crate::workspace_recovery::claim(transaction, &claim)?;
    match claimed.status() {
        crate::RecoveryLeaseClaimStatus::Busy => {
            return Ok(UnstartedActivityContinuationOperation::Busy(
                claimed.into_lease(),
            ));
        }
        crate::RecoveryLeaseClaimStatus::ClaimConflict
        | crate::RecoveryLeaseClaimStatus::AlreadyOwned => {
            return Ok(UnstartedActivityContinuationOperation::ClaimConflict(
                claimed.into_lease(),
            ));
        }
        crate::RecoveryLeaseClaimStatus::Acquired => {}
    }
    super::recovery_maintenance::validate_binding_and_lease(
        transaction,
        binding,
        claimed.lease(),
        continued_at,
    )?;
    let fresh = probe_in_transaction(
        transaction,
        &request.probe_scope,
        request.expectation.activity().activity_id(),
        request.expectation.initiating_session_id(),
        request.expectation.principal(),
        request.service,
        request.probe_observed_at,
    )?;
    if fresh.blocker().is_some()
        || fresh.expectation() != &request.expectation
        || fresh.delegation() != request.delegation
        || fresh.delegation_digest() != request.delegation_digest
        || fresh.probe_digest() != request.probe_digest
        || fresh.observed_at() != request.probe_observed_at
        || request.expectation.activity().lease_until().get() > continued_at.get()
        || request.expectation.activity().updated_at().get() > continued_at.get()
    {
        return Err(UnstartedActivityContinuationStoreError::Conflict(
            "stale probe/census",
        ));
    }
    if request.delegation.destination_id() != request.service_destination_id {
        return Err(UnstartedActivityContinuationStoreError::Conflict(
            "service destination",
        ));
    }
    let before = request.expectation.activity();
    let after_revision = before.revision().checked_next().map_err(|_| {
        UnstartedActivityContinuationStoreError::Conflict("Activity revision overflow")
    })?;
    let after_lease_revision = before.lease_revision().checked_next().map_err(|_| {
        UnstartedActivityContinuationStoreError::Conflict("lease revision overflow")
    })?;
    let after_until = TimestampMillis::new(
        continued_at
            .get()
            .checked_add(request.duration.get())
            .ok_or(UnstartedActivityContinuationStoreError::Conflict(
                "lease expiry overflow",
            ))?,
    )
    .map_err(|_| UnstartedActivityContinuationStoreError::Conflict("lease expiry"))?;
    let changed = transaction.execute(
        "UPDATE activities SET updated_at_ms=?1, revision=?2, lease_owner_id=?3, lease_until_ms=?4, lease_revision=?5 WHERE activity_id=?6 AND state=?7 AND revision=?8 AND created_at_ms=?9 AND updated_at_ms=?10 AND lease_owner_id=?11 AND lease_until_ms=?12 AND lease_revision=?13",
        params![continued_at.get(), after_revision.get(), request.service.runtime_instance_id().into_uuid().as_bytes(), after_until.get(), after_lease_revision.get(), before.activity_id().into_uuid().as_bytes(), super::encode_activity_state(ActivityState::Open), before.revision().get(), before.created_at().get(), before.updated_at().get(), before.lease_owner_id().into_uuid().as_bytes(), before.lease_until().get(), before.lease_revision().get()],
    )?;
    if changed != 1 {
        return Err(UnstartedActivityContinuationStoreError::Conflict(
            "Activity CAS",
        ));
    }
    let after_raw = super::query_activity_row(transaction, before.activity_id())?.ok_or(
        UnstartedActivityContinuationStoreError::Corrupt("continued Activity"),
    )?;
    let activity_after = super::decode_activity(&after_raw)?;
    let release = ReleaseRecoveryLease::new(
        request.probe_scope.workspace_id(),
        request.service.runtime_instance_id(),
        claimed.lease().epoch(),
        claimed.lease().revision(),
        continued_at,
    );
    let _released = crate::workspace_recovery::release(transaction, &release)?;
    let lease_gap_ms = continued_at
        .get()
        .checked_sub(before.lease_until().get())
        .ok_or(UnstartedActivityContinuationStoreError::Corrupt(
            "lease gap",
        ))?;
    let mut receipt = UnstartedActivityContinuationReceipt {
        request_id: request.request_id,
        request_digest: request.request_digest,
        probe_scope: request.probe_scope.clone(),
        probe_observed_at: request.probe_observed_at,
        probe_digest: request.probe_digest,
        delegation: request.delegation,
        delegation_digest: request.delegation_digest,
        service: request.service,
        service_destination_id: request.service_destination_id,
        session: request.session,
        expectation: request.expectation.clone(),
        continued_at,
        lease_gap_ms,
        activity_after,
        receipt_digest: [0; 32],
    };
    receipt.receipt_digest = digest_receipt(&receipt);
    insert_receipt(transaction, &receipt)?;
    Ok(UnstartedActivityContinuationOperation::Recorded(receipt))
}

#[allow(
    clippy::too_many_lines,
    reason = "The closed positive census keeps each admissible plan family and first blocker explicit."
)]
fn plan_census(
    connection: &Connection,
    workspace_id: forge_domain::WorkspaceId,
    activity_id: forge_domain::ActivityId,
) -> Result<
    ([u8; 32], Option<UnstartedActivityContinuationBlocker>),
    UnstartedActivityContinuationStoreError,
> {
    let workspace = workspace_id.into_uuid().into_bytes();
    let activity = activity_id.into_uuid().into_bytes();
    validate_census_manifest(connection)?;
    if let Some(blocker) =
        classify_activity_tables(connection, workspace.as_slice(), activity.as_slice())?
    {
        return Ok(([0xEE; 32], Some(blocker)));
    }
    let goal_count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM goals WHERE workspace_id=?1 AND activity_id=?2",
        params![workspace.as_slice(), activity.as_slice()],
        |row| row.get(0),
    )?;
    if goal_count == 0 {
        return Ok((
            [1; 32],
            Some(UnstartedActivityContinuationBlocker::GoalNotActive),
        ));
    }
    let invalid_goals: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM goals WHERE workspace_id=?1 AND activity_id=?2 AND (state != 0 OR revision != 1 OR created_at_ms != updated_at_ms OR reason_kind IS NOT NULL OR reason_text IS NOT NULL OR completion_review_id IS NOT NULL))", params![workspace.as_slice(), activity.as_slice()], |row| row.get(0))?;
    if invalid_goals {
        return Ok((
            [1; 32],
            Some(UnstartedActivityContinuationBlocker::GoalNotActive),
        ));
    }
    let invalid_watermark: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM goals g LEFT JOIN goal_creation_watermarks w ON w.workspace_id=g.workspace_id AND w.goal_id=g.goal_id WHERE g.workspace_id=?1 AND g.activity_id=?2 AND (w.goal_id IS NULL OR w.greatest_created_at_ms != g.created_at_ms))",
        params![workspace.as_slice(), activity.as_slice()], |row| row.get(0),
    )?;
    if invalid_watermark {
        return Ok((
            [1; 32],
            Some(UnstartedActivityContinuationBlocker::GoalNotActive),
        ));
    }
    let invalid_dag_revision: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM goal_dag_revisions r JOIN goals g ON g.goal_id=r.goal_id WHERE g.workspace_id=?1 AND g.activity_id=?2 AND (r.dag_revision != 1 OR r.parent_dag_revision IS NOT NULL OR r.base_goal_revision != 1)) OR EXISTS(SELECT 1 FROM goal_dag_heads h JOIN goals g ON g.goal_id=h.goal_id WHERE g.workspace_id=?1 AND g.activity_id=?2 AND (h.dag_revision != 1 OR h.head_revision != 1)) OR EXISTS(SELECT 1 FROM goal_dag_node_lineage l JOIN goals g ON g.goal_id=l.goal_id WHERE g.workspace_id=?1 AND g.activity_id=?2)",
        params![workspace.as_slice(), activity.as_slice()], |row| row.get(0),
    )?;
    if invalid_dag_revision {
        return Ok((
            [2; 32],
            Some(UnstartedActivityContinuationBlocker::DagNotPendingInitial),
        ));
    }
    let node_count: i64 = connection.query_row("SELECT COUNT(*) FROM goal_dag_nodes n JOIN goals g ON g.goal_id=n.goal_id WHERE g.workspace_id=?1 AND g.activity_id=?2", params![workspace.as_slice(), activity.as_slice()], |row| row.get(0))?;
    let invalid_nodes: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM goal_dag_nodes n JOIN goals g ON g.goal_id=n.goal_id WHERE g.workspace_id=?1 AND g.activity_id=?2 AND (n.lifecycle_state != 0 OR n.node_revision != 1 OR n.created_at_ms != n.updated_at_ms))", params![workspace.as_slice(), activity.as_slice()], |row| row.get(0))?;
    if node_count == 0 || invalid_nodes {
        return Ok((
            [2; 32],
            Some(UnstartedActivityContinuationBlocker::DagNotPendingInitial),
        ));
    }
    let dag_evidence: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM goal_dag_node_evidence_refs e JOIN goals g ON g.goal_id=e.goal_id WHERE g.workspace_id=?1 AND g.activity_id=?2) OR EXISTS(SELECT 1 FROM goal_evidence_refs e JOIN goals g ON g.goal_id=e.goal_id WHERE g.workspace_id=?1 AND g.activity_id=?2)", params![workspace.as_slice(), activity.as_slice()], |row| row.get(0))?;
    if dag_evidence {
        return Ok((
            [3; 32],
            Some(UnstartedActivityContinuationBlocker::DagEvidencePresent),
        ));
    }
    let assignment_count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM agent_assignments WHERE workspace_id=?1 AND activity_id=?2",
        params![workspace.as_slice(), activity.as_slice()],
        |row| row.get(0),
    )?;
    let invalid_assignments: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM agent_assignments WHERE workspace_id=?1 AND activity_id=?2 AND (state != 0 OR cancellation_requested != 0 OR report IS NOT NULL OR worktree_root_fingerprint IS NOT NULL OR worktree_repository_fingerprint IS NOT NULL OR worktree_baseline IS NOT NULL OR reviewed_agent_id IS NOT NULL OR reviewed_session_id IS NOT NULL OR reviewed_principal_kind IS NOT NULL OR reviewed_principal_id IS NOT NULL OR reviewed_revision IS NOT NULL))", params![workspace.as_slice(), activity.as_slice()], |row| row.get(0))?;
    if assignment_count == 0 || invalid_assignments {
        return Ok((
            [4; 32],
            Some(UnstartedActivityContinuationBlocker::AssignmentNotOffered),
        ));
    }
    let assignment_sources: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM agent_assignment_sources r JOIN agent_assignments a ON a.assignment_id=r.assignment_id WHERE a.workspace_id=?1 AND a.activity_id=?2)", params![workspace.as_slice(), activity.as_slice()], |row| row.get(0))?;
    if assignment_sources {
        return Ok((
            [5; 32],
            Some(UnstartedActivityContinuationBlocker::AssignmentEvidencePresent),
        ));
    }
    let invalid_creation_history: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM goal_mutation_receipts WHERE workspace_id=?1 AND activity_id=?2 AND (mutation_kind != 0 OR expected_goal_revision IS NOT NULL OR result_goal_revision != 1 OR result_status != 0 OR review_id IS NOT NULL)) OR EXISTS(SELECT 1 FROM semantic_events e JOIN goals g ON g.goal_id=e.subject_goal_id WHERE e.workspace_id=?1 AND g.activity_id=?2 AND e.event_kind NOT IN ('goal_created','dag_committed','plan_published')) OR EXISTS(SELECT 1 FROM goals g WHERE g.workspace_id=?1 AND g.activity_id=?2 AND (SELECT COUNT(*) FROM goal_mutation_receipts r WHERE r.workspace_id=g.workspace_id AND r.activity_id=g.activity_id AND r.goal_id=g.goal_id AND r.mutation_kind=0 AND r.result_goal_revision=g.revision AND r.result_status=g.state AND r.observed_at_ms=g.created_at_ms) != 1) OR EXISTS(SELECT 1 FROM goal_mutation_receipts r LEFT JOIN goals g ON g.goal_id=r.goal_id AND g.workspace_id=r.workspace_id AND g.activity_id=r.activity_id WHERE r.workspace_id=?1 AND r.activity_id=?2 AND g.goal_id IS NULL)",
        params![workspace.as_slice(), activity.as_slice()], |row| row.get(0),
    )?;
    if invalid_creation_history {
        return Ok((
            [5; 32],
            Some(UnstartedActivityContinuationBlocker::PhysicalEffectPresent),
        ));
    }
    let invalid_offered_fact: bool = connection.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM effect_fact_outbox_assignment_offered f
             LEFT JOIN agent_assignments a ON a.assignment_id=f.assignment_id
             LEFT JOIN effect_fact_outbox_entries e ON e.sequence=f.outbox_sequence
             WHERE f.workspace_id=?1 AND f.activity_id=?2
               AND (a.assignment_id IS NULL OR a.workspace_id!=f.workspace_id OR a.activity_id!=f.activity_id OR a.goal_id!=f.goal_id OR a.node_id!=f.node_id OR a.target_agent_id!=f.target_agent_id OR a.target_session_id IS NOT f.target_session_id OR a.credit_budget IS NOT f.credit_budget OR a.created_at_ms!=f.offered_at_ms OR e.sequence IS NULL OR e.fact_kind!=3 OR e.workspace_id!=f.workspace_id OR e.migration_id!=f.migration_id OR e.destination_id!=f.destination_id OR NOT EXISTS(SELECT 1 FROM agent_operations_delegations d WHERE d.workspace_id=f.workspace_id AND d.migration_id=f.migration_id AND d.destination_id=f.destination_id))
         ) OR EXISTS(SELECT 1 FROM agent_assignments a WHERE a.workspace_id=?1 AND a.activity_id=?2 AND (SELECT COUNT(*) FROM effect_fact_outbox_assignment_offered f WHERE f.workspace_id=a.workspace_id AND f.activity_id=a.activity_id AND f.assignment_id=a.assignment_id)!=1)",
        params![workspace.as_slice(), activity.as_slice()], |row| row.get(0),
    )?;
    if invalid_offered_fact {
        return Ok((
            [5; 32],
            Some(UnstartedActivityContinuationBlocker::AssignmentEvidencePresent),
        ));
    }
    let invalid_semantic_counterpart: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM goals g WHERE g.workspace_id=?1 AND g.activity_id=?2 AND (SELECT COUNT(*) FROM semantic_events e WHERE e.workspace_id=g.workspace_id AND e.event_kind='goal_created' AND e.subject_goal_id=g.goal_id AND e.revision=1 AND e.observed_at_ms=g.created_at_ms)!=1) OR EXISTS(SELECT 1 FROM agent_dag_plan_ledger p WHERE p.workspace_id=?1 AND p.activity_id=?2 AND ((SELECT COUNT(*) FROM semantic_events e WHERE e.workspace_id=p.workspace_id AND e.event_kind='plan_published' AND e.subject_goal_id=p.goal_id AND e.subject_dag_revision=p.committed_dag_revision AND e.observed_at_ms=p.committed_at_ms)!=1 OR (SELECT COUNT(*) FROM semantic_events e WHERE e.workspace_id=p.workspace_id AND e.event_kind='dag_committed' AND e.subject_goal_id=p.goal_id AND e.subject_dag_revision=p.committed_dag_revision AND e.observed_at_ms=p.committed_at_ms)!=1)) OR EXISTS(SELECT 1 FROM semantic_events e LEFT JOIN goals g ON g.goal_id=e.subject_goal_id AND g.workspace_id=e.workspace_id WHERE e.workspace_id=?1 AND e.event_kind IN ('goal_created','dag_committed','plan_published') AND g.goal_id IS NULL)",
        params![workspace.as_slice(), activity.as_slice()], |row| row.get(0),
    )?;
    if invalid_semantic_counterpart {
        return Ok((
            [5; 32],
            Some(UnstartedActivityContinuationBlocker::PhysicalEffectPresent),
        ));
    }
    let prior_continuation: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM unstarted_activity_continuation_receipts WHERE workspace_id=?1 AND activity_id=?2)",
        params![workspace.as_slice(), activity.as_slice()], |row| row.get(0),
    )?;
    if prior_continuation {
        return Ok((
            [5; 32],
            Some(UnstartedActivityContinuationBlocker::PhysicalEffectPresent),
        ));
    }
    if started_activity_lease_resume_receipt_present(connection, activity.as_slice())? {
        return Ok((
            [5; 32],
            Some(UnstartedActivityContinuationBlocker::PhysicalEffectPresent),
        ));
    }
    let arbitrary_work: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM agent_work_updates u WHERE u.workspace_id=?1 AND u.activity_id=?2 AND (u.phase != 0 OR u.evidence_count != 0 OR NOT EXISTS(SELECT 1 FROM agent_dag_plan_ledger p WHERE p.workspace_id=u.workspace_id AND p.activity_id=u.activity_id AND p.agent_id=u.agent_id AND p.history_update_id=u.update_id))) OR EXISTS(SELECT 1 FROM agent_work_update_evidence_refs r JOIN agent_work_updates u ON u.update_id=r.update_id WHERE u.workspace_id=?1 AND u.activity_id=?2)", params![workspace.as_slice(), activity.as_slice()], |row| row.get(0))?;
    if arbitrary_work {
        return Ok((
            [6; 32],
            Some(UnstartedActivityContinuationBlocker::ArbitraryWorkHistory),
        ));
    }
    let invalid_plan_counterpart: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM agent_dag_plan_ledger p LEFT JOIN agent_work_updates u ON u.update_id=p.history_update_id AND u.workspace_id=p.workspace_id AND u.activity_id=p.activity_id AND u.agent_id=p.agent_id LEFT JOIN goals g ON g.goal_id=p.goal_id AND g.workspace_id=p.workspace_id AND g.activity_id=p.activity_id LEFT JOIN goal_dag_revisions d ON d.goal_id=p.goal_id AND d.dag_revision=p.committed_dag_revision LEFT JOIN goal_dag_heads h ON h.goal_id=p.goal_id LEFT JOIN activity_coordinators c ON c.workspace_id=p.workspace_id AND c.activity_id=p.activity_id AND c.agent_id=p.agent_id WHERE p.workspace_id=?1 AND p.activity_id=?2 AND (u.update_id IS NULL OR u.update_sequence!=p.history_update_sequence OR u.phase!=0 OR u.evidence_count!=0 OR g.goal_id IS NULL OR p.goal_revision!=g.revision OR d.revision_id!=p.committed_dag_revision_id OR d.base_goal_revision!=p.goal_revision OR h.dag_revision!=p.committed_dag_revision OR h.head_revision!=1 OR c.agent_id IS NULL OR c.revision!=p.coordinator_revision)) OR EXISTS(SELECT 1 FROM agent_dag_plan_sessions s JOIN agent_dag_plan_ledger p ON p.request_id=s.request_id LEFT JOIN agent_instances a ON a.agent_id=p.agent_id AND a.workspace_id=p.workspace_id AND a.activity_id=p.activity_id WHERE p.workspace_id=?1 AND p.activity_id=?2 AND (a.agent_id IS NULL OR s.session_id!=a.session_id))",
        params![workspace.as_slice(), activity.as_slice()], |row| row.get(0),
    )?;
    if invalid_plan_counterpart {
        return Ok((
            [6; 32],
            Some(UnstartedActivityContinuationBlocker::ArbitraryWorkHistory),
        ));
    }
    let invalid_binding: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM agent_instances a WHERE a.workspace_id=?1 AND a.activity_id=?2 AND NOT EXISTS(SELECT 1 FROM agent_binding_reservations r JOIN agent_binding_activations x ON x.request_id=r.request_id JOIN agent_operations_delegations d ON d.migration_id=r.migration_id AND d.workspace_id=r.workspace_id WHERE r.workspace_id=a.workspace_id AND r.activity_id=a.activity_id AND r.agent_id=a.agent_id AND r.session_id=a.session_id AND r.destination_id=d.destination_id AND r.freeze_revision=d.freeze_revision AND r.principal_kind=a.principal_kind AND ((r.principal_kind=0 AND r.principal_id=zeroblob(16) AND a.principal_id IS NULL) OR r.principal_id=a.principal_id) AND x.display_name=a.display_name AND x.declared_role=a.declared_role AND x.transport_kind=a.transport_kind AND x.activated_at_ms=a.created_at_ms)) OR EXISTS(SELECT 1 FROM agent_binding_rejections j JOIN agent_instances a ON a.agent_id=j.agent_id AND a.workspace_id=j.workspace_id AND a.activity_id=j.activity_id WHERE j.workspace_id=?1 AND j.activity_id=?2)",
        params![workspace.as_slice(), activity.as_slice()], |row| row.get(0),
    )?;
    if invalid_binding {
        return Ok((
            [6; 32],
            Some(UnstartedActivityContinuationBlocker::PendingActivation),
        ));
    }
    let workspace_effect: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM workspace_execution_stops WHERE workspace_id=?1) OR EXISTS(SELECT 1 FROM authority_stop_batches WHERE workspace_id=?1) OR EXISTS(SELECT 1 FROM leadership_work_cuts WHERE workspace_id=?1) OR EXISTS(SELECT 1 FROM recovery_runs WHERE workspace_id=?1 AND (activity_count!=0 OR execution_count!=0)) OR EXISTS(SELECT 1 FROM workspace_root_recovery_receipts WHERE workspace_id=?1) OR EXISTS(SELECT 1 FROM root_recovery_delegation_receipts WHERE workspace_id=?1) OR EXISTS(SELECT 1 FROM semantic_events_meta m WHERE m.workspace_id=?1 AND (m.high_water_seq!=(SELECT COALESCE(MAX(sequence),0) FROM semantic_events e WHERE e.workspace_id=m.workspace_id) OR m.retained_low!=0)) OR NOT EXISTS(SELECT 1 FROM semantic_events_meta m WHERE m.workspace_id=?1)",
        params![workspace.as_slice()], |row| row.get(0),
    )?;
    if workspace_effect {
        return Ok((
            [5; 32],
            Some(UnstartedActivityContinuationBlocker::PhysicalEffectPresent),
        ));
    }
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_PLAN);
    hasher.update(workspace);
    hasher.update(activity);
    for (table, sql) in ALLOWED_DIGEST_QUERIES {
        hash_query_rows(
            &mut hasher,
            connection,
            table,
            sql,
            workspace.as_slice(),
            activity.as_slice(),
        )?;
    }
    Ok((hasher.finalize().into(), None))
}

fn started_activity_lease_resume_receipt_present(
    connection: &Connection,
    activity_id: &[u8],
) -> Result<bool, UnstartedActivityContinuationStoreError> {
    let maximum = forge_domain::STARTED_ACTIVITY_LEASE_RESUME_MAX_PHYSICAL_ROWS as usize;
    let limit = i64::try_from(maximum.saturating_add(1)).map_err(|_| {
        UnstartedActivityContinuationStoreError::Corrupt("started receipt census limit")
    })?;
    let mut statement = connection.prepare(
        "SELECT request_id,workspace_id,activity_id
         FROM started_activity_lease_resume_receipts ORDER BY request_id LIMIT ?1",
    )?;
    let mut rows = statement.query(params![limit])?;
    let mut count = 0_usize;
    while let Some(row) = rows.next()? {
        count += 1;
        let request_id: Vec<u8> = row.get(0)?;
        let workspace_id: Vec<u8> = row.get(1)?;
        let row_activity_id: Vec<u8> = row.get(2)?;
        if request_id.len() != 16
            || request_id.iter().all(|byte| *byte == 0)
            || workspace_id.len() != 16
            || workspace_id.iter().all(|byte| *byte == 0)
            || row_activity_id.len() != 16
            || row_activity_id.iter().all(|byte| *byte == 0)
        {
            return Err(UnstartedActivityContinuationStoreError::Corrupt(
                "started receipt census identity",
            ));
        }
        if row_activity_id == activity_id || count > maximum {
            return Ok(true);
        }
    }
    Ok(false)
}

const CENSUS_SCHEMA_VERSION: u16 = 67;
const CENSUS_TABLES: &[&str] = &[
    "activities",
    "activity_coordinator_recoveries",
    "activity_coordinators",
    "activity_successors",
    "agent_assignment_offer_seals",
    "agent_assignment_sources",
    "agent_assignments",
    "agent_binding_activations",
    "agent_binding_rejections",
    "agent_binding_reservations",
    "agent_dag_plan_ledger",
    "agent_dag_plan_sessions",
    "agent_departure_reconciliations",
    "agent_effect_outbox_entries",
    "agent_effect_outbox_focus",
    "agent_effect_outbox_recipients",
    "agent_effect_outbox_transitions",
    "agent_events",
    "agent_focus_events",
    "agent_inbox",
    "agent_instances",
    "agent_operations_delegations",
    "agent_operations_migrations",
    "agent_presence",
    "agent_session_reconciliations",
    "agent_work_update_evidence_refs",
    "agent_work_updates",
    "approval_requests",
    "assignment_continuation_acknowledgments",
    "assignment_continuation_batches",
    "assignment_continuation_proposals",
    "authority_stop_batches",
    "authority_stop_targets",
    "auto_approval_scopes",
    "change_sets",
    "checkpoint_restores",
    "checkpoints",
    "diff_entries",
    "diff_evidence",
    "effect_fact_outbox_assignment_offered",
    "effect_fact_outbox_assignment_review",
    "effect_fact_outbox_assignment_submitted",
    "effect_fact_outbox_assignment_submitted_source_ref",
    "effect_fact_outbox_change_set",
    "effect_fact_outbox_entries",
    "effect_fact_outbox_execution_terminal",
    "execution_admission_consumptions",
    "execution_command_evidence",
    "execution_generated_artifacts",
    "execution_grants",
    "execution_native_closures",
    "execution_output_events",
    "execution_provenance",
    "executions",
    "expired_activity_recovery_agents",
    "expired_activity_recovery_receipts",
    "file_mutations",
    "goal_completion_reviews",
    "goal_creation_watermarks",
    "goal_dag_edges",
    "goal_dag_heads",
    "goal_dag_node_acceptance",
    "goal_dag_node_evidence_refs",
    "goal_dag_node_lineage",
    "goal_dag_nodes",
    "goal_dag_revisions",
    "goal_deletion_cleanup_journal",
    "goal_evidence_refs",
    "goal_mutation_receipts",
    "goal_statements",
    "goal_verification_requirements",
    "goals",
    "leadership_work_cut_agents",
    "leadership_work_cut_effects",
    "leadership_work_cut_nodes",
    "leadership_work_cut_sessions",
    "leadership_work_cut_team_nodes",
    "leadership_work_cuts",
    "quiescent_activity_lease_resume_receipts",
    "recovery_maintenance",
    "recovery_run_activities",
    "recovery_run_executions",
    "recovery_runs",
    "root_recovery_delegation_receipts",
    "semantic_events",
    "semantic_events_meta",
    "source_tree_requests",
    "started_activity_lease_resume_receipts",
    "tree_mutations",
    "unstarted_activity_continuation_receipts",
    "verification_inputs",
    "verification_requirement_links",
    "verification_runs",
    "workspace",
    "workspace_execution_stop_fences",
    "workspace_execution_stop_settlement_targets",
    "workspace_execution_stop_settlements",
    "workspace_execution_stop_targets",
    "workspace_execution_stops",
    "workspace_policy",
    "workspace_queue_settings",
    "workspace_root_recovery_receipts",
    "writer_lease_scope_entries",
    "writer_leases",
];

const CONDITIONAL_CENSUS_TABLES: &[&str] = &[
    "workspace",
    "activities",
    "goals",
    "goal_statements",
    "goal_verification_requirements",
    "goal_dag_revisions",
    "goal_dag_heads",
    "goal_dag_nodes",
    "goal_dag_edges",
    "goal_dag_node_acceptance",
    "goal_dag_node_lineage",
    "goal_creation_watermarks",
    "agent_dag_plan_ledger",
    "agent_dag_plan_sessions",
    "agent_work_updates",
    "agent_instances",
    "agent_focus_events",
    "agent_presence",
    "agent_events",
    "agent_inbox",
    "activity_coordinators",
    "agent_effect_outbox_entries",
    "agent_effect_outbox_focus",
    "agent_effect_outbox_transitions",
    "agent_effect_outbox_recipients",
    "agent_assignments",
    "agent_assignment_offer_seals",
    "agent_assignment_sources",
    "effect_fact_outbox_assignment_offered",
    "agent_operations_migrations",
    "agent_binding_reservations",
    "agent_operations_delegations",
    "agent_binding_activations",
    "agent_binding_rejections",
    "agent_session_reconciliations",
    "workspace_policy",
    "workspace_queue_settings",
    "recovery_maintenance",
    "expired_activity_recovery_receipts",
    "expired_activity_recovery_agents",
    "unstarted_activity_continuation_receipts",
    "started_activity_lease_resume_receipts",
    "quiescent_activity_lease_resume_receipts",
    "goal_mutation_receipts",
    "semantic_events",
    "effect_fact_outbox_entries",
    "activity_successors",
    "semantic_events_meta",
    "recovery_runs",
];

fn validate_census_manifest(
    connection: &Connection,
) -> Result<(), UnstartedActivityContinuationStoreError> {
    let unique_tables = CENSUS_TABLES
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    let unique_conditional = CONDITIONAL_CENSUS_TABLES
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    if CENSUS_SCHEMA_VERSION != 67
        || CENSUS_TABLES.len() != 104
        || unique_tables.len() != CENSUS_TABLES.len()
        || CONDITIONAL_CENSUS_TABLES.len() != 49
        || unique_conditional.len() != CONDITIONAL_CENSUS_TABLES.len()
        || CENSUS_TABLES.len() - CONDITIONAL_CENSUS_TABLES.len() != 55
        || CONDITIONAL_CENSUS_TABLES
            .iter()
            .any(|table| !CENSUS_TABLES.contains(table))
        || CENSUS_TABLES.iter().any(|table| {
            CONDITIONAL_CENSUS_TABLES.contains(table)
                == forbidden_inventory::FORBIDDEN_INVENTORY_TABLES.contains(table)
        })
    {
        return Err(UnstartedActivityContinuationStoreError::Corrupt(
            "schema-v67 census manifest size",
        ));
    }
    let mut statement = connection.prepare(
        "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
    )?;
    let actual = statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    if actual.len() != CENSUS_TABLES.len()
        || actual
            .iter()
            .any(|name| !CENSUS_TABLES.contains(&name.as_str()))
    {
        return Err(UnstartedActivityContinuationStoreError::Conflict(
            "unclassified schema-v67 table",
        ));
    }
    Ok(())
}

const ALLOWED_DIGEST_QUERIES: &[(&str, &str)] = &[
    (
        "workspace",
        "SELECT * FROM workspace WHERE workspace_id=?1 AND length(?2)=16 ORDER BY workspace_id",
    ),
    (
        "activities",
        "SELECT * FROM activities WHERE workspace_id=?1 AND activity_id=?2 ORDER BY activity_id",
    ),
    (
        "goals",
        "SELECT * FROM goals WHERE workspace_id=?1 AND activity_id=?2 ORDER BY goal_id",
    ),
    (
        "goal_statements",
        "SELECT s.* FROM goal_statements s JOIN goals g ON g.goal_id=s.goal_id WHERE g.workspace_id=?1 AND g.activity_id=?2 ORDER BY s.goal_id,s.statement_kind,s.ordinal",
    ),
    (
        "goal_verification_requirements",
        "SELECT r.* FROM goal_verification_requirements r JOIN goals g ON g.goal_id=r.goal_id WHERE g.workspace_id=?1 AND g.activity_id=?2 ORDER BY r.goal_id,r.ordinal",
    ),
    (
        "goal_creation_watermarks",
        "SELECT w.* FROM goal_creation_watermarks w JOIN goals g ON g.workspace_id=w.workspace_id AND g.goal_id=w.goal_id WHERE g.workspace_id=?1 AND g.activity_id=?2 ORDER BY w.goal_id",
    ),
    (
        "goal_dag_revisions",
        "SELECT r.* FROM goal_dag_revisions r JOIN goals g ON g.goal_id=r.goal_id WHERE g.workspace_id=?1 AND g.activity_id=?2 ORDER BY r.goal_id,r.dag_revision",
    ),
    (
        "goal_dag_heads",
        "SELECT h.* FROM goal_dag_heads h JOIN goals g ON g.goal_id=h.goal_id WHERE g.workspace_id=?1 AND g.activity_id=?2 ORDER BY h.goal_id",
    ),
    (
        "goal_dag_nodes",
        "SELECT n.* FROM goal_dag_nodes n JOIN goals g ON g.goal_id=n.goal_id WHERE g.workspace_id=?1 AND g.activity_id=?2 ORDER BY n.goal_id,n.dag_revision,n.ordinal,n.node_id",
    ),
    (
        "goal_dag_edges",
        "SELECT e.* FROM goal_dag_edges e JOIN goals g ON g.goal_id=e.goal_id WHERE g.workspace_id=?1 AND g.activity_id=?2 ORDER BY e.goal_id,e.dag_revision,e.upstream_node_id,e.downstream_node_id",
    ),
    (
        "goal_dag_node_acceptance",
        "SELECT a.* FROM goal_dag_node_acceptance a JOIN goals g ON g.goal_id=a.goal_id WHERE g.workspace_id=?1 AND g.activity_id=?2 ORDER BY a.goal_id,a.dag_revision,a.node_id,a.ordinal",
    ),
    (
        "agent_instances",
        "SELECT * FROM agent_instances WHERE workspace_id=?1 AND activity_id=?2 ORDER BY agent_id",
    ),
    (
        "agent_focus_events",
        "SELECT * FROM agent_focus_events WHERE workspace_id=?1 AND activity_id=?2 ORDER BY agent_id,event_sequence",
    ),
    (
        "agent_presence",
        "SELECT * FROM agent_presence WHERE workspace_id=?1 AND activity_id=?2 ORDER BY agent_id",
    ),
    (
        "agent_events",
        "SELECT * FROM agent_events WHERE workspace_id=?1 AND activity_id=?2 ORDER BY membership_revision,event_id",
    ),
    (
        "agent_inbox",
        "SELECT i.* FROM agent_inbox i JOIN agent_events e ON e.event_id=i.event_id WHERE e.workspace_id=?1 AND e.activity_id=?2 ORDER BY i.recipient_agent_id,i.recipient_session_id,i.event_id",
    ),
    (
        "activity_coordinators",
        "SELECT * FROM activity_coordinators WHERE workspace_id=?1 AND activity_id=?2 ORDER BY activity_id",
    ),
    (
        "agent_dag_plan_ledger",
        "SELECT * FROM agent_dag_plan_ledger WHERE workspace_id=?1 AND activity_id=?2 ORDER BY request_id",
    ),
    (
        "agent_dag_plan_sessions",
        "SELECT s.* FROM agent_dag_plan_sessions s JOIN agent_dag_plan_ledger p ON p.request_id=s.request_id WHERE p.workspace_id=?1 AND p.activity_id=?2 ORDER BY s.request_id",
    ),
    (
        "agent_work_updates",
        "SELECT * FROM agent_work_updates WHERE workspace_id=?1 AND activity_id=?2 ORDER BY agent_id,update_sequence,update_id",
    ),
    (
        "agent_assignments",
        "SELECT * FROM agent_assignments WHERE workspace_id=?1 AND activity_id=?2 ORDER BY assignment_id",
    ),
    (
        "agent_assignment_offer_seals",
        "SELECT * FROM agent_assignment_offer_seals WHERE workspace_id=?1 AND activity_id=?2 ORDER BY assignment_id",
    ),
    (
        "effect_fact_outbox_assignment_offered",
        "SELECT * FROM effect_fact_outbox_assignment_offered WHERE workspace_id=?1 AND activity_id=?2 ORDER BY outbox_sequence",
    ),
    (
        "effect_fact_outbox_entries",
        "SELECT e.* FROM effect_fact_outbox_entries e JOIN effect_fact_outbox_assignment_offered f ON f.outbox_sequence=e.sequence WHERE f.workspace_id=?1 AND f.activity_id=?2 ORDER BY e.sequence",
    ),
    (
        "agent_binding_reservations",
        "SELECT * FROM agent_binding_reservations WHERE workspace_id=?1 AND activity_id=?2 ORDER BY request_id",
    ),
    (
        "agent_binding_activations",
        "SELECT a.* FROM agent_binding_activations a JOIN agent_binding_reservations r ON r.request_id=a.request_id WHERE r.workspace_id=?1 AND r.activity_id=?2 ORDER BY a.request_id",
    ),
    (
        "agent_binding_rejections",
        "SELECT * FROM agent_binding_rejections WHERE workspace_id=?1 AND activity_id=?2 ORDER BY request_id",
    ),
    (
        "agent_session_reconciliations",
        "SELECT * FROM agent_session_reconciliations WHERE workspace_id=?1 AND activity_id=?2 ORDER BY request_id",
    ),
    (
        "agent_operations_migrations",
        "SELECT * FROM agent_operations_migrations WHERE workspace_id=?1 AND length(?2)=16 ORDER BY migration_id",
    ),
    (
        "agent_operations_delegations",
        "SELECT * FROM agent_operations_delegations WHERE workspace_id=?1 AND length(?2)=16 ORDER BY migration_id",
    ),
    (
        "workspace_policy",
        "SELECT * FROM workspace_policy WHERE workspace_id=?1 AND length(?2)=16",
    ),
    (
        "workspace_queue_settings",
        "SELECT * FROM workspace_queue_settings WHERE workspace_id=?1 AND length(?2)=16",
    ),
    (
        "semantic_events",
        "SELECT e.* FROM semantic_events e JOIN goals g ON g.goal_id=e.subject_goal_id WHERE e.workspace_id=?1 AND g.activity_id=?2 AND e.event_kind IN ('goal_created','dag_committed','plan_published') ORDER BY e.sequence",
    ),
    (
        "semantic_events_meta",
        "SELECT * FROM semantic_events_meta WHERE workspace_id=?1 AND length(?2)=16",
    ),
    (
        "goal_mutation_receipts",
        "SELECT * FROM goal_mutation_receipts WHERE workspace_id=?1 AND activity_id=?2 ORDER BY request_id",
    ),
    (
        "started_activity_lease_resume_receipts",
        "SELECT * FROM started_activity_lease_resume_receipts WHERE workspace_id=?1 AND activity_id=?2 ORDER BY request_id",
    ),
    (
        "quiescent_activity_lease_resume_receipts",
        "SELECT * FROM quiescent_activity_lease_resume_receipts WHERE workspace_id=?1 AND activity_id=?2 ORDER BY request_id",
    ),
];

fn hash_query_rows(
    hasher: &mut Sha256,
    connection: &Connection,
    table: &str,
    sql: &str,
    workspace_id: &[u8],
    activity_id: &[u8],
) -> Result<(), UnstartedActivityContinuationStoreError> {
    hash_bytes(hasher, table.as_bytes());
    let mut statement = connection.prepare(sql)?;
    let columns = statement
        .column_names()
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    hash_u64(hasher, columns.len() as u64);
    for column in &columns {
        hash_bytes(hasher, column.as_bytes());
    }
    let mut rows = match statement.parameter_count() {
        1 => statement.query(params![workspace_id])?,
        2 => statement.query(params![workspace_id, activity_id])?,
        _ => {
            return Err(UnstartedActivityContinuationStoreError::Corrupt(
                "allowed digest query parameter count",
            ));
        }
    };
    let mut count = 0_u64;
    while let Some(row) = rows.next()? {
        count = count
            .checked_add(1)
            .ok_or(UnstartedActivityContinuationStoreError::Corrupt(
                "plan row count overflow",
            ))?;
        for index in 0..columns.len() {
            use rusqlite::types::ValueRef;
            match row.get_ref(index)? {
                ValueRef::Null => hasher.update([0]),
                ValueRef::Integer(value) => {
                    hasher.update([1]);
                    hasher.update(value.to_le_bytes());
                }
                ValueRef::Real(value) => {
                    hasher.update([2]);
                    hasher.update(value.to_bits().to_le_bytes());
                }
                ValueRef::Text(value) => {
                    hasher.update([3]);
                    hash_bytes(hasher, value);
                }
                ValueRef::Blob(value) => {
                    hasher.update([4]);
                    hash_bytes(hasher, value);
                }
            }
        }
        hasher.update([0xFE]);
    }
    hash_u64(hasher, count);
    hasher.update([0xFF]);
    Ok(())
}

fn hash_bytes(hasher: &mut Sha256, value: &[u8]) {
    hash_u64(hasher, value.len() as u64);
    hasher.update(value);
}

fn hash_u64(hasher: &mut Sha256, value: u64) {
    hasher.update(value.to_le_bytes());
}

const ALLOWED_ACTIVITY_TABLES: &[&str] = &[
    "activities",
    "activity_coordinators",
    "agent_assignment_offer_seals",
    "agent_assignments",
    "agent_binding_rejections",
    "agent_binding_reservations",
    "agent_dag_plan_ledger",
    "agent_effect_outbox_focus",
    "agent_effect_outbox_transitions",
    "agent_events",
    "agent_focus_events",
    "agent_instances",
    "agent_presence",
    "agent_session_reconciliations",
    "agent_work_updates",
    "effect_fact_outbox_assignment_offered",
    "expired_activity_recovery_agents",
    "goal_mutation_receipts",
    "goals",
    "quiescent_activity_lease_resume_receipts",
    "started_activity_lease_resume_receipts",
    "unstarted_activity_continuation_receipts",
];

const FORBIDDEN_ACTIVITY_TABLES: &[(&str, UnstartedActivityContinuationBlocker)] = &[
    (
        "activity_coordinator_recoveries",
        UnstartedActivityContinuationBlocker::PhysicalEffectPresent,
    ),
    (
        "agent_departure_reconciliations",
        UnstartedActivityContinuationBlocker::PhysicalEffectPresent,
    ),
    (
        "approval_requests",
        UnstartedActivityContinuationBlocker::PhysicalEffectPresent,
    ),
    (
        "auto_approval_scopes",
        UnstartedActivityContinuationBlocker::PhysicalEffectPresent,
    ),
    (
        "assignment_continuation_acknowledgments",
        UnstartedActivityContinuationBlocker::PhysicalEffectPresent,
    ),
    (
        "assignment_continuation_batches",
        UnstartedActivityContinuationBlocker::PhysicalEffectPresent,
    ),
    (
        "assignment_continuation_proposals",
        UnstartedActivityContinuationBlocker::PhysicalEffectPresent,
    ),
    (
        "authority_stop_batches",
        UnstartedActivityContinuationBlocker::PhysicalEffectPresent,
    ),
    (
        "authority_stop_targets",
        UnstartedActivityContinuationBlocker::PhysicalEffectPresent,
    ),
    (
        "change_sets",
        UnstartedActivityContinuationBlocker::PhysicalEffectPresent,
    ),
    (
        "checkpoint_restores",
        UnstartedActivityContinuationBlocker::PhysicalEffectPresent,
    ),
    (
        "checkpoints",
        UnstartedActivityContinuationBlocker::PhysicalEffectPresent,
    ),
    (
        "diff_entries",
        UnstartedActivityContinuationBlocker::PhysicalEffectPresent,
    ),
    (
        "diff_evidence",
        UnstartedActivityContinuationBlocker::PhysicalEffectPresent,
    ),
    (
        "effect_fact_outbox_assignment_review",
        UnstartedActivityContinuationBlocker::AssignmentEvidencePresent,
    ),
    (
        "effect_fact_outbox_assignment_submitted",
        UnstartedActivityContinuationBlocker::AssignmentEvidencePresent,
    ),
    (
        "effect_fact_outbox_change_set",
        UnstartedActivityContinuationBlocker::PhysicalEffectPresent,
    ),
    (
        "effect_fact_outbox_execution_terminal",
        UnstartedActivityContinuationBlocker::PhysicalEffectPresent,
    ),
    (
        "execution_grants",
        UnstartedActivityContinuationBlocker::PhysicalEffectPresent,
    ),
    (
        "execution_admission_consumptions",
        UnstartedActivityContinuationBlocker::ExecutionPresent,
    ),
    (
        "execution_command_evidence",
        UnstartedActivityContinuationBlocker::ExecutionPresent,
    ),
    (
        "execution_generated_artifacts",
        UnstartedActivityContinuationBlocker::ExecutionPresent,
    ),
    (
        "execution_native_closures",
        UnstartedActivityContinuationBlocker::ExecutionPresent,
    ),
    (
        "execution_output_events",
        UnstartedActivityContinuationBlocker::ExecutionPresent,
    ),
    (
        "execution_provenance",
        UnstartedActivityContinuationBlocker::ExecutionPresent,
    ),
    (
        "executions",
        UnstartedActivityContinuationBlocker::ExecutionPresent,
    ),
    (
        "file_mutations",
        UnstartedActivityContinuationBlocker::PhysicalEffectPresent,
    ),
    (
        "goal_deletion_cleanup_journal",
        UnstartedActivityContinuationBlocker::PhysicalEffectPresent,
    ),
    (
        "goal_completion_reviews",
        UnstartedActivityContinuationBlocker::PhysicalEffectPresent,
    ),
    (
        "leadership_work_cut_agents",
        UnstartedActivityContinuationBlocker::PhysicalEffectPresent,
    ),
    (
        "leadership_work_cut_effects",
        UnstartedActivityContinuationBlocker::PhysicalEffectPresent,
    ),
    (
        "leadership_work_cut_nodes",
        UnstartedActivityContinuationBlocker::PhysicalEffectPresent,
    ),
    (
        "leadership_work_cut_team_nodes",
        UnstartedActivityContinuationBlocker::PhysicalEffectPresent,
    ),
    (
        "recovery_run_activities",
        UnstartedActivityContinuationBlocker::PhysicalEffectPresent,
    ),
    (
        "recovery_run_executions",
        UnstartedActivityContinuationBlocker::ExecutionPresent,
    ),
    (
        "root_recovery_delegation_receipts",
        UnstartedActivityContinuationBlocker::PhysicalEffectPresent,
    ),
    (
        "semantic_events",
        UnstartedActivityContinuationBlocker::PhysicalEffectPresent,
    ),
    (
        "source_tree_requests",
        UnstartedActivityContinuationBlocker::PhysicalEffectPresent,
    ),
    (
        "tree_mutations",
        UnstartedActivityContinuationBlocker::PhysicalEffectPresent,
    ),
    (
        "verification_inputs",
        UnstartedActivityContinuationBlocker::PhysicalEffectPresent,
    ),
    (
        "verification_requirement_links",
        UnstartedActivityContinuationBlocker::PhysicalEffectPresent,
    ),
    (
        "verification_runs",
        UnstartedActivityContinuationBlocker::PhysicalEffectPresent,
    ),
    (
        "workspace_execution_stop_fences",
        UnstartedActivityContinuationBlocker::PhysicalEffectPresent,
    ),
    (
        "workspace_execution_stop_settlement_targets",
        UnstartedActivityContinuationBlocker::PhysicalEffectPresent,
    ),
    (
        "workspace_execution_stop_settlements",
        UnstartedActivityContinuationBlocker::PhysicalEffectPresent,
    ),
    (
        "workspace_execution_stop_targets",
        UnstartedActivityContinuationBlocker::PhysicalEffectPresent,
    ),
    (
        "workspace_execution_stops",
        UnstartedActivityContinuationBlocker::PhysicalEffectPresent,
    ),
    (
        "workspace_root_recovery_receipts",
        UnstartedActivityContinuationBlocker::PhysicalEffectPresent,
    ),
    (
        "writer_lease_scope_entries",
        UnstartedActivityContinuationBlocker::WriterLeasePresent,
    ),
    (
        "writer_leases",
        UnstartedActivityContinuationBlocker::WriterLeasePresent,
    ),
];

fn classify_activity_tables(
    connection: &Connection,
    workspace_id: &[u8],
    activity_id: &[u8],
) -> Result<Option<UnstartedActivityContinuationBlocker>, UnstartedActivityContinuationStoreError> {
    let mut statement = connection.prepare(
        "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
    )?;
    let tables = statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    for table in tables {
        let has_activity: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info(?1) WHERE name='activity_id')",
            params![table],
            |row| row.get(0),
        )?;
        if !has_activity {
            continue;
        }
        if ALLOWED_ACTIVITY_TABLES.contains(&table.as_str()) {
            continue;
        }
        let Some((_, blocker)) = FORBIDDEN_ACTIVITY_TABLES
            .iter()
            .find(|(name, _)| *name == table)
        else {
            return Ok(Some(
                UnstartedActivityContinuationBlocker::UnclassifiedSchemaObject,
            ));
        };
        let has_workspace: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info(?1) WHERE name='workspace_id')",
            params![table],
            |row| row.get(0),
        )?;
        let sql = if table == "auto_approval_scopes" {
            format!(
                "SELECT EXISTS(SELECT 1 FROM {table} WHERE workspace_id=?1 AND (activity_id IS NULL OR activity_id=?2))"
            )
        } else if has_workspace {
            format!("SELECT EXISTS(SELECT 1 FROM {table} WHERE workspace_id=?1 AND activity_id=?2)")
        } else {
            format!("SELECT EXISTS(SELECT 1 FROM {table} WHERE activity_id=?2)")
        };
        let present: bool =
            connection.query_row(&sql, params![workspace_id, activity_id], |row| row.get(0))?;
        if present {
            return Ok(Some(*blocker));
        }
    }
    Ok(None)
}

fn digest_probe(
    scope: &ExpiredActivityRecoveryProbeScope,
    delegation_digest: [u8; 32],
    service: UnstartedActivityContinuationServiceIdentity,
    expectation: &UnstartedActivityContinuationExpectation,
    observed_at: TimestampMillis,
    blocker: Option<UnstartedActivityContinuationBlocker>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_PROBE);
    hasher.update(scope.workspace_id().into_uuid().as_bytes());
    hasher.update(scope.binding_digest());
    hasher.update(delegation_digest);
    hasher.update(service.backend_id().into_uuid().as_bytes());
    hasher.update(service.issuer().into_uuid().as_bytes());
    hasher.update(service.runtime_instance_id().into_uuid().as_bytes());
    hash_expectation(&mut hasher, expectation);
    hasher.update(observed_at.get().to_le_bytes());
    hasher.update([blocker.map_or(255, |value| value as u8)]);
    hasher.finalize().into()
}

fn digest_receipt(value: &UnstartedActivityContinuationReceipt) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_RECEIPT);
    hasher.update(value.request_id.into_uuid().as_bytes());
    hasher.update(value.request_digest);
    hasher.update(value.probe_digest);
    hasher.update(value.service.backend_id().into_uuid().as_bytes());
    hasher.update(value.service.issuer().into_uuid().as_bytes());
    hasher.update(value.service.runtime_instance_id().into_uuid().as_bytes());
    hash_expectation(&mut hasher, &value.expectation);
    hasher.update(value.continued_at.get().to_le_bytes());
    hasher.update(value.lease_gap_ms.to_le_bytes());
    hasher.update(value.activity_after.revision().get().to_le_bytes());
    hasher.update(value.activity_after.lease_revision().get().to_le_bytes());
    hasher.finalize().into()
}

fn hash_expectation(hasher: &mut Sha256, value: &UnstartedActivityContinuationExpectation) {
    let activity = value.activity();
    hasher.update(activity.activity_id().into_uuid().as_bytes());
    hasher.update(activity.revision().get().to_le_bytes());
    hasher.update(activity.lease_owner_id().into_uuid().as_bytes());
    hasher.update(activity.lease_until().get().to_le_bytes());
    hasher.update(activity.lease_revision().get().to_le_bytes());
    hasher.update(value.initiating_session_id().into_uuid().as_bytes());
    hasher.update(value.expected_agent_count().to_le_bytes());
    hasher.update(value.expected_agent_digest());
    hasher.update(value.expected_plan_digest());
}

fn principal_parts(value: AuthenticatedPrincipal) -> (i64, Option<[u8; 16]>) {
    match value {
        AuthenticatedPrincipal::TrustedStdio => (0, None),
        AuthenticatedPrincipal::DirectToken(id) => (1, Some(id.into_uuid().into_bytes())),
        AuthenticatedPrincipal::OAuthGrant(id) => (2, Some(id.into_uuid().into_bytes())),
    }
}

fn insert_receipt(
    transaction: &Transaction<'_>,
    value: &UnstartedActivityContinuationReceipt,
) -> Result<(), UnstartedActivityContinuationStoreError> {
    let expected = value.expectation.activity();
    let coordinator = value.expectation.expected_coordinator();
    let (kind, principal_id) = principal_parts(value.session.principal());
    transaction.execute(
        "INSERT INTO unstarted_activity_continuation_receipts VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24,?25,?26,?27,?28,?29,?30,?31,?32,?33,?34,?35,?36,?37,?38,?39,?40,?41,?42,?43,?44)",
        params![value.request_id.into_uuid().as_bytes(), value.request_digest, value.probe_scope.workspace_id().into_uuid().as_bytes(), expected.activity_id().into_uuid().as_bytes(), value.probe_scope.location_id().into_uuid().as_bytes(), value.probe_scope.location_revision().get(), value.probe_scope.workspace_revision().get(), value.probe_scope.locator(), value.probe_scope.root_fingerprint().as_bytes(), value.probe_scope.binding_digest(), value.delegation.migration_id().as_bytes(), value.delegation.destination_id().as_bytes(), value.delegation_digest, value.service.backend_id().into_uuid().as_bytes(), value.service.issuer().into_uuid().as_bytes(), value.service.runtime_instance_id().into_uuid().as_bytes(), value.session.session_id().into_uuid().as_bytes(), kind, principal_id.as_ref().map(<[u8;16]>::as_slice), value.session.session_revision(), value.session.session_updated_at().get(), value.probe_observed_at.get(), value.probe_digest, i64::from(UNSTARTED_ACTIVITY_CONTINUATION_CENSUS_VERSION), i64::from(value.expectation.expected_agent_count()), value.expectation.expected_agent_digest(), value.expectation.expected_plan_digest(), coordinator.map(|v| v.agent_id().into_uuid().into_bytes()), coordinator.map(ExpectedActivityCoordinator::revision), coordinator.map(|v| v.updated_at().get()), expected.revision().get(), expected.created_at().get(), expected.updated_at().get(), expected.lease_owner_id().into_uuid().as_bytes(), expected.lease_until().get(), expected.lease_revision().get(), value.continued_at.get(), value.lease_gap_ms, value.activity_after.revision().get(), value.activity_after.updated_at().get(), value.activity_after.lease_owner_id().map(|id| id.into_uuid().into_bytes()), value.activity_after.lease_until().map(TimestampMillis::get), value.activity_after.lease_revision().get(), value.receipt_digest],
    )?;
    Ok(())
}

fn load_receipt(
    connection: &Connection,
    request_id: UnstartedActivityContinuationRequestId,
) -> Result<Option<UnstartedActivityContinuationReceipt>, UnstartedActivityContinuationStoreError> {
    connection.query_row(
        "SELECT request_digest,workspace_id,activity_id,location_id,location_revision,workspace_revision,locator,root_fingerprint,binding_digest,delegation_migration_id,delegation_destination_id,delegation_digest,service_backend_id,service_issuer_id,service_runtime_instance_id,initiating_session_id,initiating_principal_kind,initiating_principal_id,session_revision,session_updated_at_ms,probe_observed_at_ms,probe_digest,agent_count,agent_digest,plan_digest,coordinator_agent_id,coordinator_revision,coordinator_updated_at_ms,before_activity_revision,before_activity_created_at_ms,before_activity_updated_at_ms,before_owner_id,before_lease_until_ms,before_lease_revision,continued_at_ms,lease_gap_ms,after_activity_revision,after_activity_updated_at_ms,after_owner_id,after_lease_until_ms,after_lease_revision,receipt_digest FROM unstarted_activity_continuation_receipts WHERE request_id=?1",
        params![request_id.into_uuid().as_bytes()],
        |row| (0..42).map(|index| row.get(index)).collect::<Result<Vec<rusqlite::types::Value>,_>>(),
    ).optional()?.map(|values| decode_receipt(connection, request_id, &values)).transpose()
}

#[allow(
    clippy::too_many_lines,
    reason = "Exact immutable receipt decoding keeps every persisted fence explicit and fail closed."
)]
fn decode_receipt(
    connection: &Connection,
    request_id: UnstartedActivityContinuationRequestId,
    v: &[rusqlite::types::Value],
) -> Result<UnstartedActivityContinuationReceipt, UnstartedActivityContinuationStoreError> {
    fn blob(v: &rusqlite::types::Value) -> Result<&[u8], UnstartedActivityContinuationStoreError> {
        if let rusqlite::types::Value::Blob(b) = v {
            Ok(b)
        } else {
            Err(UnstartedActivityContinuationStoreError::Corrupt("blob"))
        }
    }
    fn int(v: &rusqlite::types::Value) -> Result<i64, UnstartedActivityContinuationStoreError> {
        if let rusqlite::types::Value::Integer(i) = v {
            Ok(*i)
        } else {
            Err(UnstartedActivityContinuationStoreError::Corrupt("integer"))
        }
    }
    fn uuid(v: &rusqlite::types::Value) -> Result<Uuid, UnstartedActivityContinuationStoreError> {
        Uuid::from_slice(blob(v)?)
            .map_err(|_| UnstartedActivityContinuationStoreError::Corrupt("uuid"))
    }
    fn digest(
        v: &rusqlite::types::Value,
    ) -> Result<[u8; 32], UnstartedActivityContinuationStoreError> {
        blob(v)?
            .try_into()
            .map_err(|_| UnstartedActivityContinuationStoreError::Corrupt("digest"))
    }
    let workspace_id = forge_domain::WorkspaceId::from_uuid(uuid(&v[1])?);
    let activity_id = forge_domain::ActivityId::from_uuid(uuid(&v[2])?);
    let scope = ExpiredActivityRecoveryProbeScope::new(
        workspace_id,
        forge_domain::WorkspaceRevision::new(int(&v[5])?)
            .map_err(|_| UnstartedActivityContinuationStoreError::Corrupt("workspace revision"))?,
        forge_domain::LocationId::from_uuid(uuid(&v[3])?),
        forge_domain::LocationRevision::new(int(&v[4])?)
            .map_err(|_| UnstartedActivityContinuationStoreError::Corrupt("location revision"))?,
        blob(&v[6])?.to_vec(),
        forge_domain::WorkspaceRootFingerprint::from_bytes(
            blob(&v[7])?.try_into().map_err(|_| {
                UnstartedActivityContinuationStoreError::Corrupt("root fingerprint")
            })?,
        ),
        digest(&v[8])?,
    )
    .map_err(|_| UnstartedActivityContinuationStoreError::Corrupt("scope"))?;
    let delegation =
        super::expired_activity_recovery::load_delegation_fence(connection, workspace_id)?.0;
    if delegation.migration_id() != uuid(&v[9])? || delegation.destination_id() != uuid(&v[10])? {
        return Err(UnstartedActivityContinuationStoreError::Corrupt(
            "delegation changed",
        ));
    }
    let principal = match int(&v[16])? {
        0 => AuthenticatedPrincipal::TrustedStdio,
        1 => AuthenticatedPrincipal::DirectToken(DirectTokenId::from_uuid(uuid(&v[17])?)),
        2 => AuthenticatedPrincipal::OAuthGrant(OAuthGrantId::from_uuid(uuid(&v[17])?)),
        _ => {
            return Err(UnstartedActivityContinuationStoreError::Corrupt(
                "principal",
            ));
        }
    };
    let session = ExpiredActivityRecoverySessionEvidence::new(
        forge_domain::AgentSessionId::from_uuid(uuid(&v[15])?),
        principal,
        int(&v[18])?,
        TimestampMillis::new(int(&v[19])?)
            .map_err(|_| UnstartedActivityContinuationStoreError::Corrupt("session time"))?,
    )
    .map_err(|_| UnstartedActivityContinuationStoreError::Corrupt("session"))?;
    let expected_activity = ExpectedExpiredActivity::new(
        activity_id,
        ActivityRevision::new(int(&v[28])?)
            .map_err(|_| UnstartedActivityContinuationStoreError::Corrupt("revision"))?,
        TimestampMillis::new(int(&v[29])?)
            .map_err(|_| UnstartedActivityContinuationStoreError::Corrupt("created"))?,
        TimestampMillis::new(int(&v[30])?)
            .map_err(|_| UnstartedActivityContinuationStoreError::Corrupt("updated"))?,
        RuntimeInstanceId::from_uuid(uuid(&v[31])?),
        TimestampMillis::new(int(&v[32])?)
            .map_err(|_| UnstartedActivityContinuationStoreError::Corrupt("until"))?,
        ActivityLeaseRevision::new(int(&v[33])?)
            .map_err(|_| UnstartedActivityContinuationStoreError::Corrupt("lease revision"))?,
    )
    .map_err(|_| UnstartedActivityContinuationStoreError::Corrupt("Activity"))?;
    let coordinator = if matches!(v[25], rusqlite::types::Value::Null) {
        None
    } else {
        Some(
            ExpectedActivityCoordinator::new(
                forge_domain::AgentInstanceId::from_uuid(uuid(&v[25])?),
                int(&v[26])?,
                TimestampMillis::new(int(&v[27])?).map_err(|_| {
                    UnstartedActivityContinuationStoreError::Corrupt("coordinator time")
                })?,
            )
            .map_err(|_| UnstartedActivityContinuationStoreError::Corrupt("coordinator"))?,
        )
    };
    let expectation = UnstartedActivityContinuationExpectation::new(
        expected_activity,
        session.session_id(),
        principal,
        u16::try_from(int(&v[22])?)
            .map_err(|_| UnstartedActivityContinuationStoreError::Corrupt("agent count"))?,
        digest(&v[23])?,
        digest(&v[24])?,
        coordinator,
    )?;
    let service = UnstartedActivityContinuationServiceIdentity::new(
        ForgeBackendId::from_uuid(uuid(&v[12])?),
        OrchestrationIssuerId::from_uuid(uuid(&v[13])?),
        RuntimeInstanceId::from_uuid(uuid(&v[14])?),
    )?;
    let continued_at = TimestampMillis::new(int(&v[34])?)
        .map_err(|_| UnstartedActivityContinuationStoreError::Corrupt("continued time"))?;
    let after_revision = ActivityRevision::new(int(&v[36])?)
        .map_err(|_| UnstartedActivityContinuationStoreError::Corrupt("after revision"))?;
    let after_updated = TimestampMillis::new(int(&v[37])?)
        .map_err(|_| UnstartedActivityContinuationStoreError::Corrupt("after updated"))?;
    let after_owner = RuntimeInstanceId::from_uuid(uuid(&v[38])?);
    let after_until = TimestampMillis::new(int(&v[39])?)
        .map_err(|_| UnstartedActivityContinuationStoreError::Corrupt("after lease until"))?;
    let after_lease_revision = ActivityLeaseRevision::new(int(&v[40])?)
        .map_err(|_| UnstartedActivityContinuationStoreError::Corrupt("after lease revision"))?;
    let after_lease = forge_domain::ActivityLeaseProjection::from_parts(
        Some(after_owner),
        Some(after_until),
        after_lease_revision,
    )
    .map_err(|_| UnstartedActivityContinuationStoreError::Corrupt("after lease"))?;
    let activity_after = RegisteredActivity::from_parts_with_lease(
        activity_id,
        workspace_id,
        ActivityState::Open,
        expected_activity.created_at(),
        after_updated,
        after_revision,
        after_lease,
    );
    let receipt = UnstartedActivityContinuationReceipt {
        request_id,
        request_digest: digest(&v[0])?,
        probe_scope: scope,
        probe_observed_at: TimestampMillis::new(int(&v[20])?)
            .map_err(|_| UnstartedActivityContinuationStoreError::Corrupt("probe time"))?,
        probe_digest: digest(&v[21])?,
        delegation,
        delegation_digest: digest(&v[11])?,
        service,
        service_destination_id: uuid(&v[10])?,
        session,
        expectation,
        continued_at,
        lease_gap_ms: int(&v[35])?,
        activity_after,
        receipt_digest: digest(&v[41])?,
    };
    if digest_receipt(&receipt) != receipt.receipt_digest {
        return Err(UnstartedActivityContinuationStoreError::Corrupt(
            "receipt digest",
        ));
    }
    Ok(receipt)
}
