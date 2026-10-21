//! Authenticated control boundary for expired unstarted Activity continuation.

use forge_domain::{
    ActivityId, ExpiredActivityRecoveryDelegationFence, ExpiredActivityRecoveryProbeScope,
    ExpiredActivityRecoverySessionEvidence, RecoveryLeaseDurationMillis, RecoveryMaintenanceLease,
    TimestampMillis, UnstartedActivityContinuationExpectation, UnstartedActivityContinuationProbe,
    UnstartedActivityContinuationRequestId, UnstartedActivityContinuationServiceIdentity,
};
use forge_persistence::{
    UnstartedActivityContinuationOperation, UnstartedActivityContinuationReadback,
    UnstartedActivityContinuationReceipt, UnstartedActivityContinuationStoreRequest,
};
use uuid::Uuid;

use crate::agent_session::AgentSessionResolveRequest;
use crate::error::{ControlError, ControlErrorCode};
use crate::service::{ForgeControl, ResolvedWorkspaceScope, map_activity_store_error};

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnstartedActivityContinuationProbeRequest {
    pub scope: ResolvedWorkspaceScope,
    pub activity_id: ActivityId,
    pub initiating_session_id: forge_domain::AgentSessionId,
    pub principal: forge_domain::AuthenticatedPrincipal,
    pub service: UnstartedActivityContinuationServiceIdentity,
    pub observed_at: TimestampMillis,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableUnstartedActivityContinuationRequest {
    pub scope: ResolvedWorkspaceScope,
    pub request_id: UnstartedActivityContinuationRequestId,
    /// Canonical caller intent. It deliberately excludes the current service tuple.
    pub request_digest: [u8; 32],
    pub service: UnstartedActivityContinuationServiceIdentity,
    pub service_destination_id: Uuid,
    pub expected_workspace_root_fingerprint: forge_domain::WorkspaceRootFingerprint,
    pub expected_binding_digest: [u8; 32],
    pub expected_delegation: ExpiredActivityRecoveryDelegationFence,
    pub expected_delegation_digest: [u8; 32],
    pub probe_observed_at: TimestampMillis,
    pub expected_probe_digest: [u8; 32],
    pub duration: RecoveryLeaseDurationMillis,
    pub expectation: UnstartedActivityContinuationExpectation,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnstartedActivityContinuationGetRequest {
    pub scope: ResolvedWorkspaceScope,
    pub request_id: UnstartedActivityContinuationRequestId,
    pub request_digest: [u8; 32],
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnstartedActivityContinuationReport {
    receipt: Option<UnstartedActivityContinuationReceipt>,
    maintenance_lease: Option<RecoveryMaintenanceLease>,
    replayed: bool,
    claim_conflict: bool,
    current_activity: Option<forge_domain::RegisteredActivity>,
}

impl UnstartedActivityContinuationReport {
    pub const fn receipt(&self) -> Option<&UnstartedActivityContinuationReceipt> {
        self.receipt.as_ref()
    }
    pub const fn maintenance_lease(&self) -> Option<&RecoveryMaintenanceLease> {
        self.maintenance_lease.as_ref()
    }
    pub const fn replayed(&self) -> bool {
        self.replayed
    }
    pub const fn claim_conflict(&self) -> bool {
        self.claim_conflict
    }
    pub const fn current_activity(&self) -> Option<&forge_domain::RegisteredActivity> {
        self.current_activity.as_ref()
    }
}

impl ForgeControl {
    pub fn unstarted_activity_continuation_probe(
        &self,
        request: &UnstartedActivityContinuationProbeRequest,
    ) -> Result<UnstartedActivityContinuationProbe, ControlError> {
        let (scope, store) = self.open_resolved_workspace(
            request.scope.locator().location_id(),
            request.scope.locator().expected_revision(),
            request.scope.locator(),
        )?;
        if scope != request.scope {
            return Err(ControlError::new(
                ControlErrorCode::WorkspaceRevisionConflict,
            ));
        }
        let binding = store.journal_binding().map_err(map_activity_store_error)?;
        let workspace = store.workspace().map_err(map_activity_store_error)?;
        let probe_scope = ExpiredActivityRecoveryProbeScope::new(
            scope.workspace_id(),
            scope.workspace_revision(),
            scope.locator().location_id(),
            scope.locator().expected_revision(),
            scope.locator().relative_root_bytes().to_vec(),
            workspace.root_fingerprint(),
            binding.recovery_history_digest(),
        )
        .map_err(|_| ControlError::new(ControlErrorCode::InvalidInput))?;
        store
            .probe_unstarted_activity_continuation(
                &binding,
                &probe_scope,
                request.activity_id,
                request.initiating_session_id,
                request.principal,
                request.service,
                request.observed_at,
            )
            .map_err(map_activity_store_error)
    }

    pub fn unstarted_activity_continuation_get(
        &self,
        request: &UnstartedActivityContinuationGetRequest,
    ) -> Result<Option<UnstartedActivityContinuationReadback>, ControlError> {
        let (scope, store) = self.open_resolved_workspace(
            request.scope.locator().location_id(),
            request.scope.locator().expected_revision(),
            request.scope.locator(),
        )?;
        if scope != request.scope {
            return Err(ControlError::new(
                ControlErrorCode::WorkspaceRevisionConflict,
            ));
        }
        let binding = store.journal_binding().map_err(map_activity_store_error)?;
        store
            .unstarted_activity_continuation_readback_for_request(
                &binding,
                request.request_id,
                request.request_digest,
            )
            .map_err(map_activity_store_error)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "Replay-first authority and fresh-run preparation stay together at this security boundary."
    )]
    pub(crate) fn run_durable_unstarted_activity_continuation_with_clock<F>(
        &self,
        request: &DurableUnstartedActivityContinuationRequest,
        clock: F,
    ) -> Result<UnstartedActivityContinuationReport, ControlError>
    where
        F: FnOnce() -> Result<TimestampMillis, ControlError>,
    {
        // Unknown-outcome replay is resolved before current boot metadata or
        // current Session authority participates.
        if let Some(readback) =
            self.unstarted_activity_continuation_get(&UnstartedActivityContinuationGetRequest {
                scope: request.scope.clone(),
                request_id: request.request_id,
                request_digest: request.request_digest,
            })?
        {
            return Ok(UnstartedActivityContinuationReport {
                current_activity: Some(readback.current_activity().clone()),
                receipt: Some(readback.receipt().clone()),
                maintenance_lease: None,
                replayed: true,
                claim_conflict: false,
            });
        }
        if request.request_digest == [0; 32]
            || request.expected_binding_digest == [0; 32]
            || request.expected_probe_digest == [0; 32]
            || request.expected_delegation_digest == [0; 32]
            || request.expected_delegation.destination_id() != request.service_destination_id
        {
            return Err(ControlError::new(ControlErrorCode::InvalidInput));
        }
        let session = self.agent_session_resolve(AgentSessionResolveRequest {
            session_id: request.expectation.initiating_session_id(),
            principal: request.expectation.principal(),
        })?;
        let session = ExpiredActivityRecoverySessionEvidence::new(
            session.id(),
            session.principal(),
            session.revision().get(),
            session.updated_at(),
        )
        .map_err(|_| ControlError::new(ControlErrorCode::InvalidInput))?;
        let (scope, mut store) = self.open_resolved_workspace(
            request.scope.locator().location_id(),
            request.scope.locator().expected_revision(),
            request.scope.locator(),
        )?;
        if scope != request.scope {
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
            scope.workspace_id(),
            scope.workspace_revision(),
            scope.locator().location_id(),
            scope.locator().expected_revision(),
            scope.locator().relative_root_bytes().to_vec(),
            workspace.root_fingerprint(),
            binding.recovery_history_digest(),
        )
        .map_err(|_| ControlError::new(ControlErrorCode::InvalidInput))?;
        let store_request = UnstartedActivityContinuationStoreRequest {
            request_id: request.request_id,
            request_digest: request.request_digest,
            probe_scope,
            probe_observed_at: request.probe_observed_at,
            probe_digest: request.expected_probe_digest,
            delegation: request.expected_delegation,
            delegation_digest: request.expected_delegation_digest,
            service: request.service,
            service_destination_id: request.service_destination_id,
            duration: request.duration,
            expectation: request.expectation.clone(),
            session,
        };
        let outcome = store
            .run_unstarted_activity_continuation_with_clock(&binding, &store_request, || {
                clock().map_err(|error| {
                    forge_persistence::WorkspaceStoreError::RecoveryLeaseClockObservation {
                        source: Box::new(error),
                    }
                })
            })
            .map_err(map_activity_store_error)?;
        Ok(match outcome {
            UnstartedActivityContinuationOperation::Recorded(receipt) => {
                UnstartedActivityContinuationReport {
                    current_activity: Some(receipt.activity_after().clone()),
                    receipt: Some(receipt),
                    maintenance_lease: None,
                    replayed: false,
                    claim_conflict: false,
                }
            }
            UnstartedActivityContinuationOperation::Replay(receipt) => {
                UnstartedActivityContinuationReport {
                    current_activity: Some(receipt.activity_after().clone()),
                    receipt: Some(receipt),
                    maintenance_lease: None,
                    replayed: true,
                    claim_conflict: false,
                }
            }
            UnstartedActivityContinuationOperation::Busy(lease) => {
                UnstartedActivityContinuationReport {
                    current_activity: None,
                    receipt: None,
                    maintenance_lease: Some(lease),
                    replayed: false,
                    claim_conflict: false,
                }
            }
            UnstartedActivityContinuationOperation::ClaimConflict(lease) => {
                UnstartedActivityContinuationReport {
                    current_activity: None,
                    receipt: None,
                    maintenance_lease: Some(lease),
                    replayed: false,
                    claim_conflict: true,
                }
            }
        })
    }
}
