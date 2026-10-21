//! Control-plane boundary for authenticated expired Activity successor recovery.

use forge_domain::{
    ActivityId, ExpiredActivityRecoveryDelegationFence, ExpiredActivityRecoveryExpectation,
    ExpiredActivityRecoveryProbe, ExpiredActivityRecoveryProbeScope,
    ExpiredActivityRecoverySessionEvidence, ForgeBackendId, RecoveryLeaseDurationMillis,
    RecoveryMaintenanceLease, RuntimeInstanceId, TimestampMillis,
};
use forge_persistence::{
    ExpiredActivityRecoveryOperation, ExpiredActivityRecoveryReadback,
    ExpiredActivityRecoveryReceipt, ExpiredActivityRecoveryStoreRequest,
};
use uuid::Uuid;

use crate::agent_session::AgentSessionResolveRequest;
use crate::error::{ControlError, ControlErrorCode};
use crate::service::{ForgeControl, ResolvedWorkspaceScope, map_activity_store_error};

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpiredActivityRecoveryProbeRequest {
    pub scope: ResolvedWorkspaceScope,
    pub predecessor_activity_id: ActivityId,
    pub observed_at: TimestampMillis,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableExpiredActivityRecoveryRequest {
    pub scope: ResolvedWorkspaceScope,
    pub request_id: Uuid,
    pub original_owner_id: RuntimeInstanceId,
    pub configured_owner_id: RuntimeInstanceId,
    pub service_backend_id: ForgeBackendId,
    pub service_issuer: forge_domain::OrchestrationIssuerId,
    pub service_destination_id: Uuid,
    pub request_digest: [u8; 32],
    pub expected_workspace_root_fingerprint: forge_domain::WorkspaceRootFingerprint,
    pub expected_binding_digest: [u8; 32],
    pub expected_delegation: ExpiredActivityRecoveryDelegationFence,
    pub expected_delegation_digest: [u8; 32],
    pub probe_observed_at: TimestampMillis,
    pub expected_probe_digest: [u8; 32],
    pub duration: RecoveryLeaseDurationMillis,
    pub expectation: ExpiredActivityRecoveryExpectation,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpiredActivityRecoveryGetRequest {
    pub scope: ResolvedWorkspaceScope,
    pub request_id: Uuid,
    pub request_digest: [u8; 32],
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpiredActivityRecoveryReport {
    receipt: Option<ExpiredActivityRecoveryReceipt>,
    lease: Option<RecoveryMaintenanceLease>,
    replayed: bool,
    claim_conflict: bool,
    current_predecessor: Option<forge_domain::RegisteredActivity>,
    current_successor: Option<forge_domain::RegisteredActivity>,
    relation: Option<forge_domain::ActivitySuccessor>,
}

impl ExpiredActivityRecoveryReport {
    pub const fn receipt(&self) -> Option<&ExpiredActivityRecoveryReceipt> {
        self.receipt.as_ref()
    }
    pub const fn lease(&self) -> Option<&RecoveryMaintenanceLease> {
        self.lease.as_ref()
    }
    pub const fn replayed(&self) -> bool {
        self.replayed
    }
    pub const fn claim_conflict(&self) -> bool {
        self.claim_conflict
    }
    pub const fn current_predecessor(&self) -> Option<&forge_domain::RegisteredActivity> {
        self.current_predecessor.as_ref()
    }
    pub const fn current_successor(&self) -> Option<&forge_domain::RegisteredActivity> {
        self.current_successor.as_ref()
    }
    pub const fn relation(&self) -> Option<forge_domain::ActivitySuccessor> {
        self.relation
    }
}

struct PreparedExpiredActivityRecovery {
    store: forge_persistence::WorkspaceStore,
    binding: forge_persistence::WorkspaceJournalBinding,
    request: ExpiredActivityRecoveryStoreRequest,
}

fn replay_expired_activity_recovery(
    control: &ForgeControl,
    request: &DurableExpiredActivityRecoveryRequest,
) -> Result<Option<ExpiredActivityRecoveryReport>, ControlError> {
    let Some(readback) =
        control.expired_activity_recovery_get(&ExpiredActivityRecoveryGetRequest {
            scope: request.scope.clone(),
            request_id: request.request_id,
            request_digest: request.request_digest,
        })?
    else {
        return Ok(None);
    };
    let receipt = readback.receipt();
    if receipt.request_digest() != request.request_digest
        || receipt.service_backend_id() != request.service_backend_id
        || receipt.service_issuer() != request.service_issuer
        || receipt.service_destination_id() != request.service_destination_id
        || receipt.owner_id() != request.configured_owner_id
        || receipt.delegation() != request.expected_delegation
        || receipt.delegation_digest() != request.expected_delegation_digest
        || receipt.probe_digest() != request.expected_probe_digest
        || receipt.expectation() != &request.expectation
    {
        return Err(ControlError::new(ControlErrorCode::ActivityConflict));
    }
    Ok(Some(ExpiredActivityRecoveryReport {
        receipt: Some(receipt.clone()),
        lease: None,
        replayed: true,
        claim_conflict: false,
        current_predecessor: Some(readback.current_predecessor().clone()),
        current_successor: Some(readback.current_successor().clone()),
        relation: Some(readback.relation()),
    }))
}

fn prepare_expired_activity_recovery(
    control: &ForgeControl,
    request: &DurableExpiredActivityRecoveryRequest,
) -> Result<PreparedExpiredActivityRecovery, ControlError> {
    if request.original_owner_id != request.configured_owner_id
        || request.configured_owner_id.into_uuid().is_nil()
    {
        return Err(ControlError::new(
            ControlErrorCode::WorkspaceIdentityConflict,
        ));
    }
    if request.expected_delegation.destination_id() != request.service_destination_id
        || request.expected_binding_digest == [0; 32]
        || request.expected_probe_digest == [0; 32]
        || request.expected_delegation_digest == [0; 32]
    {
        return Err(ControlError::new(ControlErrorCode::InvalidInput));
    }
    let session = control.agent_session_resolve(AgentSessionResolveRequest {
        session_id: request.expectation.initiating_session_id(),
        principal: request.expectation.principal(),
    })?;
    let session_evidence = ExpiredActivityRecoverySessionEvidence::new(
        session.id(),
        session.principal(),
        session.revision().get(),
        session.updated_at(),
    )
    .map_err(|_| ControlError::new(ControlErrorCode::InvalidInput))?;
    let (fresh_scope, store) = control.open_resolved_workspace(
        request.scope.locator().location_id(),
        request.scope.locator().expected_revision(),
        request.scope.locator(),
    )?;
    if fresh_scope != request.scope {
        return Err(ControlError::new(
            ControlErrorCode::WorkspaceRevisionConflict,
        ));
    }
    let binding = store.journal_binding().map_err(map_activity_store_error)?;
    let workspace = store.workspace().map_err(map_activity_store_error)?;
    if workspace.root_fingerprint() != request.expected_workspace_root_fingerprint
        || binding.recovery_history_digest() != request.expected_binding_digest
    {
        return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
    }
    let probe_scope = ExpiredActivityRecoveryProbeScope::new(
        fresh_scope.workspace_id(),
        fresh_scope.workspace_revision(),
        fresh_scope.locator().location_id(),
        fresh_scope.locator().expected_revision(),
        fresh_scope.locator().relative_root_bytes().to_vec(),
        request.expected_workspace_root_fingerprint,
        request.expected_binding_digest,
    )
    .map_err(|_| ControlError::new(ControlErrorCode::InvalidInput))?;
    Ok(PreparedExpiredActivityRecovery {
        store,
        binding,
        request: ExpiredActivityRecoveryStoreRequest {
            request_id: request.request_id,
            request_digest: request.request_digest,
            probe_scope,
            probe_observed_at: request.probe_observed_at,
            probe_digest: request.expected_probe_digest,
            delegation: request.expected_delegation,
            delegation_digest: request.expected_delegation_digest,
            service_backend_id: request.service_backend_id,
            service_issuer: request.service_issuer,
            service_destination_id: request.service_destination_id,
            owner_id: request.configured_owner_id,
            duration: request.duration,
            expectation: request.expectation.clone(),
            session: session_evidence,
        },
    })
}

impl ForgeControl {
    pub fn expired_activity_recovery_probe(
        &self,
        request: &ExpiredActivityRecoveryProbeRequest,
    ) -> Result<ExpiredActivityRecoveryProbe, ControlError> {
        let (fresh_scope, store) = self.open_resolved_workspace(
            request.scope.locator().location_id(),
            request.scope.locator().expected_revision(),
            request.scope.locator(),
        )?;
        if fresh_scope != request.scope {
            return Err(ControlError::new(
                ControlErrorCode::WorkspaceRevisionConflict,
            ));
        }
        let binding = store.journal_binding().map_err(map_activity_store_error)?;
        let workspace = store.workspace().map_err(map_activity_store_error)?;
        let probe_scope = ExpiredActivityRecoveryProbeScope::new(
            fresh_scope.workspace_id(),
            fresh_scope.workspace_revision(),
            fresh_scope.locator().location_id(),
            fresh_scope.locator().expected_revision(),
            fresh_scope.locator().relative_root_bytes().to_vec(),
            workspace.root_fingerprint(),
            binding.recovery_history_digest(),
        )
        .map_err(|_| ControlError::new(ControlErrorCode::InvalidInput))?;
        store
            .probe_expired_activity_recovery(
                &binding,
                &probe_scope,
                request.predecessor_activity_id,
                request.observed_at,
            )
            .map_err(map_activity_store_error)
    }

    pub fn expired_activity_recovery_get(
        &self,
        request: &ExpiredActivityRecoveryGetRequest,
    ) -> Result<Option<ExpiredActivityRecoveryReadback>, ControlError> {
        let (fresh_scope, store) = self.open_resolved_workspace(
            request.scope.locator().location_id(),
            request.scope.locator().expected_revision(),
            request.scope.locator(),
        )?;
        if fresh_scope != request.scope {
            return Err(ControlError::new(
                ControlErrorCode::WorkspaceRevisionConflict,
            ));
        }
        let binding = store.journal_binding().map_err(map_activity_store_error)?;
        store
            .expired_activity_recovery_readback_for_request(
                &binding,
                request.request_id,
                request.request_digest,
            )
            .map_err(map_activity_store_error)
    }

    pub(crate) fn run_durable_expired_activity_recovery_with_clock<F>(
        &self,
        request: &DurableExpiredActivityRecoveryRequest,
        clock: F,
    ) -> Result<ExpiredActivityRecoveryReport, ControlError>
    where
        F: FnOnce() -> Result<TimestampMillis, ControlError>,
    {
        if let Some(replay) = replay_expired_activity_recovery(self, request)? {
            return Ok(replay);
        }
        let PreparedExpiredActivityRecovery {
            mut store,
            binding,
            request: store_request,
        } = prepare_expired_activity_recovery(self, request)?;
        let outcome = store
            .run_expired_activity_recovery_with_clock(&binding, &store_request, || {
                clock().map_err(|error| {
                    forge_persistence::WorkspaceStoreError::RecoveryLeaseClockObservation {
                        source: Box::new(error),
                    }
                })
            })
            .map_err(map_activity_store_error)?;
        match outcome {
            ExpiredActivityRecoveryOperation::Recorded(receipt) => {
                Ok(ExpiredActivityRecoveryReport {
                    current_predecessor: Some(receipt.predecessor_after().clone()),
                    current_successor: Some(receipt.successor().clone()),
                    relation: Some(receipt.relation()),
                    receipt: Some(receipt),
                    lease: None,
                    replayed: false,
                    claim_conflict: false,
                })
            }
            ExpiredActivityRecoveryOperation::Replay(receipt) => {
                Ok(ExpiredActivityRecoveryReport {
                    current_predecessor: Some(receipt.predecessor_after().clone()),
                    current_successor: Some(receipt.successor().clone()),
                    relation: Some(receipt.relation()),
                    receipt: Some(receipt),
                    lease: None,
                    replayed: true,
                    claim_conflict: false,
                })
            }
            ExpiredActivityRecoveryOperation::Busy(lease) => Ok(ExpiredActivityRecoveryReport {
                receipt: None,
                lease: Some(lease),
                replayed: false,
                claim_conflict: false,
                current_predecessor: None,
                current_successor: None,
                relation: None,
            }),
            ExpiredActivityRecoveryOperation::ClaimConflict(lease) => {
                Ok(ExpiredActivityRecoveryReport {
                    receipt: None,
                    lease: Some(lease),
                    replayed: false,
                    claim_conflict: true,
                    current_predecessor: None,
                    current_successor: None,
                    relation: None,
                })
            }
        }
    }
}
