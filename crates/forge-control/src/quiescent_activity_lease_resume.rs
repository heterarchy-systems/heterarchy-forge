//! Control boundary for safe quiescent same-Activity lease recovery.

use forge_domain::{
    ActivityId, AgentInstanceId, AgentSessionId, AuthenticatedPrincipal,
    QuiescentActivityLeaseResumeGetRequest as DomainGetRequest,
    QuiescentActivityLeaseResumeOperation, QuiescentActivityLeaseResumeProbe,
    QuiescentActivityLeaseResumeProbeRequest as DomainProbeRequest,
    QuiescentActivityLeaseResumeRunRequest as DomainRunRequest,
    QuiescentActivityLeaseResumeValidationError, StartedActivityLeaseResumeServiceIdentity,
    StartedActivityLeaseResumeSessionSnapshot, TimestampMillis,
};
use forge_persistence::{
    QuiescentActivityLeaseResumeReadback, WorkspaceStore, WorkspaceStoreError,
};
use uuid::Uuid;

use crate::agent_session::AgentSessionResolveRequest;
use crate::error::{ControlError, ControlErrorCode};
use crate::service::{ForgeControl, ResolvedWorkspaceScope, map_activity_store_error};

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuiescentActivityLeaseResumeProbeRequest {
    pub scope: ResolvedWorkspaceScope,
    pub activity_id: ActivityId,
    pub initiating_session_id: AgentSessionId,
    pub principal: AuthenticatedPrincipal,
    pub service: StartedActivityLeaseResumeServiceIdentity,
    pub observed_at: TimestampMillis,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuiescentActivityLeaseResumeRunRequest {
    pub scope: ResolvedWorkspaceScope,
    pub request_id: Uuid,
    pub request_digest: [u8; 32],
    pub probe: QuiescentActivityLeaseResumeProbe,
    pub current_service: StartedActivityLeaseResumeServiceIdentity,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuiescentActivityLeaseResumeGetRequest {
    pub scope: ResolvedWorkspaceScope,
    pub request_id: Uuid,
    pub request_digest: [u8; 32],
    pub activity_id: ActivityId,
    pub agent_id: AgentInstanceId,
    pub initiating_session_id: AgentSessionId,
    pub principal: AuthenticatedPrincipal,
}

impl ForgeControl {
    pub fn quiescent_activity_lease_resume_probe(
        &self,
        request: &QuiescentActivityLeaseResumeProbeRequest,
    ) -> Result<QuiescentActivityLeaseResumeProbe, ControlError> {
        let (scope, store, binding, domain_scope) =
            super::started_activity_lease_resume::open_started_scope(self, &request.scope)?;
        let initiating_session = self.agent_session_resolve(AgentSessionResolveRequest {
            session_id: request.initiating_session_id,
            principal: request.principal,
        })?;
        let initiating_snapshot =
            super::started_activity_lease_resume::session_snapshot(&initiating_session)?;
        let coordinator_session = coordinator_session_snapshot(self, &store, request.activity_id)?;
        let domain_request = DomainProbeRequest::new(
            domain_scope,
            request.activity_id,
            request.initiating_session_id,
            request.principal,
        )
        .map_err(map_domain_validation)?;
        store
            .probe_quiescent_activity_lease_resume(
                &binding,
                &domain_request,
                request.service,
                initiating_snapshot,
                coordinator_session,
                request.observed_at,
            )
            .map_err(map_activity_store_error)
            .and_then(|probe| {
                if scope == request.scope {
                    Ok(probe)
                } else {
                    Err(ControlError::new(
                        ControlErrorCode::WorkspaceRevisionConflict,
                    ))
                }
            })
    }

    pub fn run_quiescent_activity_lease_resume(
        &self,
        request: &QuiescentActivityLeaseResumeRunRequest,
    ) -> Result<QuiescentActivityLeaseResumeOperation, ControlError> {
        self.run_quiescent_activity_lease_resume_with_clock(
            request,
            crate::worker::runtime_timestamp_millis,
        )
    }

    pub(crate) fn run_quiescent_activity_lease_resume_with_clock<F>(
        &self,
        request: &QuiescentActivityLeaseResumeRunRequest,
        clock: F,
    ) -> Result<QuiescentActivityLeaseResumeOperation, ControlError>
    where
        F: FnOnce() -> Result<TimestampMillis, ControlError>,
    {
        let (fresh_scope, mut store, binding, domain_scope) =
            super::started_activity_lease_resume::open_started_scope(self, &request.scope)?;
        if fresh_scope != request.scope || domain_scope != *request.probe.scope() {
            return Err(ControlError::new(
                ControlErrorCode::WorkspaceRevisionConflict,
            ));
        }
        request
            .probe
            .expectation()
            .initiating_agent()
            .ok_or_else(|| ControlError::new(ControlErrorCode::ActivityConflict))?;
        let initiating_session = self.agent_session_resolve(AgentSessionResolveRequest {
            session_id: request
                .probe
                .expectation()
                .initiating_session()
                .session_id(),
            principal: request.probe.expectation().initiating_session().principal(),
        })?;
        let initiating_snapshot =
            super::started_activity_lease_resume::session_snapshot(&initiating_session)?;
        let coordinator_session = coordinator_session_snapshot(
            self,
            &store,
            request.probe.expectation().activity().id(),
        )?;
        let domain_request = DomainRunRequest::new(
            domain_scope,
            request.request_id,
            request.request_digest,
            request.probe.clone(),
            request.current_service,
        )
        .map_err(map_domain_validation)?;
        store
            .run_quiescent_activity_lease_resume_with_clock(
                &binding,
                &domain_request,
                initiating_snapshot,
                coordinator_session,
                || {
                    clock().map_err(|error| WorkspaceStoreError::RecoveryLeaseClockObservation {
                        source: Box::new(error),
                    })
                },
            )
            .map_err(map_quiescent_store_error)
    }

    pub fn quiescent_activity_lease_resume_get(
        &self,
        request: &QuiescentActivityLeaseResumeGetRequest,
    ) -> Result<Option<QuiescentActivityLeaseResumeReadback>, ControlError> {
        let (fresh_scope, store, binding, domain_scope) =
            super::started_activity_lease_resume::open_started_scope(self, &request.scope)?;
        if fresh_scope != request.scope {
            return Err(ControlError::new(
                ControlErrorCode::WorkspaceRevisionConflict,
            ));
        }
        let domain_request = DomainGetRequest::new(
            domain_scope,
            request.request_id,
            request.request_digest,
            request.activity_id,
            request.agent_id,
            request.initiating_session_id,
            request.principal,
        )
        .map_err(map_domain_validation)?;
        store
            .quiescent_activity_lease_resume_readback_for_request(&binding, &domain_request)
            .map_err(map_activity_store_error)
    }
}

fn coordinator_session_snapshot(
    control: &ForgeControl,
    store: &WorkspaceStore,
    activity_id: ActivityId,
) -> Result<Option<StartedActivityLeaseResumeSessionSnapshot>, ControlError> {
    let Some(binding) = store
        .get_activity_coordinator(activity_id)
        .map_err(map_activity_store_error)?
    else {
        return Ok(None);
    };
    let agent = store
        .get_agent(binding.agent_id())
        .map_err(map_activity_store_error)?
        .ok_or_else(|| ControlError::new(ControlErrorCode::ActivityConflict))?;
    let Some(session_id) = agent.session_id() else {
        return Ok(None);
    };
    super::started_activity_lease_resume::optional_session_snapshot(
        control,
        session_id,
        agent.principal(),
    )
}

fn map_domain_validation(_: QuiescentActivityLeaseResumeValidationError) -> ControlError {
    ControlError::new(ControlErrorCode::InvalidInput)
}

fn map_quiescent_store_error(error: WorkspaceStoreError) -> ControlError {
    match error {
        WorkspaceStoreError::QuiescentActivityLeaseResumeCommittedUnconfirmed { .. } => {
            ControlError::committed()
        }
        other => map_activity_store_error(other),
    }
}
