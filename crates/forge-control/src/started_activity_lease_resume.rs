//! Control boundary for preserving Activity identity after genuinely started work.

use forge_domain::{
    ActivityId, AgentInstanceId, AgentSessionId, AuthenticatedPrincipal,
    ExpiredActivityRecoveryProbeScope, StartedActivityLeaseResumeGetRequest as DomainGetRequest,
    StartedActivityLeaseResumeOperation, StartedActivityLeaseResumeProbe,
    StartedActivityLeaseResumeProbeRequest as DomainProbeRequest,
    StartedActivityLeaseResumeRunRequest as DomainRunRequest,
    StartedActivityLeaseResumeServiceIdentity, StartedActivityLeaseResumeSessionSnapshot,
    StartedActivityLeaseResumeValidationError, TimestampMillis,
};
use forge_persistence::{
    StartedActivityLeaseResumeReadback, WorkspaceJournalBinding, WorkspaceStore,
    WorkspaceStoreError,
};
use uuid::Uuid;

use crate::agent_session::AgentSessionResolveRequest;
use crate::error::{ControlError, ControlErrorCode};
use crate::service::{ForgeControl, ResolvedWorkspaceScope, map_activity_store_error};

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartedActivityLeaseResumeProbeRequest {
    pub scope: ResolvedWorkspaceScope,
    pub activity_id: ActivityId,
    pub initiating_session_id: AgentSessionId,
    pub principal: AuthenticatedPrincipal,
    pub service: StartedActivityLeaseResumeServiceIdentity,
    pub observed_at: TimestampMillis,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartedActivityLeaseResumeRunRequest {
    pub scope: ResolvedWorkspaceScope,
    pub request_id: Uuid,
    pub request_digest: [u8; 32],
    pub probe: StartedActivityLeaseResumeProbe,
    pub current_service: StartedActivityLeaseResumeServiceIdentity,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartedActivityLeaseResumeGetRequest {
    pub scope: ResolvedWorkspaceScope,
    pub request_id: Uuid,
    pub request_digest: [u8; 32],
    pub activity_id: ActivityId,
    pub agent_id: AgentInstanceId,
    pub initiating_session_id: AgentSessionId,
    pub principal: AuthenticatedPrincipal,
}

impl ForgeControl {
    pub fn started_activity_lease_resume_probe(
        &self,
        request: &StartedActivityLeaseResumeProbeRequest,
    ) -> Result<StartedActivityLeaseResumeProbe, ControlError> {
        let (scope, store, binding, domain_scope) = open_started_scope(self, &request.scope)?;
        let initiating_session = self.agent_session_resolve(AgentSessionResolveRequest {
            session_id: request.initiating_session_id,
            principal: request.principal,
        })?;
        let initiating_snapshot = session_snapshot(&initiating_session)?;
        let coordinator_session = match store
            .get_activity_coordinator(request.activity_id)
            .map_err(map_activity_store_error)?
        {
            Some(binding) => {
                let agent = store
                    .get_agent(binding.agent_id())
                    .map_err(map_activity_store_error)?
                    .ok_or_else(|| ControlError::new(ControlErrorCode::ActivityConflict))?;
                match agent.session_id() {
                    Some(session_id) => {
                        optional_session_snapshot(self, session_id, agent.principal())?
                    }
                    None => None,
                }
            }
            None => None,
        };
        let domain_request = DomainProbeRequest::new(
            domain_scope,
            request.activity_id,
            request.initiating_session_id,
            request.principal,
        )
        .map_err(map_domain_validation)?;
        store
            .probe_started_activity_lease_resume(
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

    pub fn started_activity_lease_resume_run(
        &self,
        request: &StartedActivityLeaseResumeRunRequest,
    ) -> Result<StartedActivityLeaseResumeOperation, ControlError> {
        self.started_activity_lease_resume_run_with_clock(
            request,
            crate::worker::runtime_timestamp_millis,
        )
    }

    pub(crate) fn started_activity_lease_resume_run_with_clock<F>(
        &self,
        request: &StartedActivityLeaseResumeRunRequest,
        clock: F,
    ) -> Result<StartedActivityLeaseResumeOperation, ControlError>
    where
        F: FnOnce() -> Result<TimestampMillis, ControlError>,
    {
        let (fresh_scope, mut store, binding, domain_scope) =
            open_started_scope(self, &request.scope)?;
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
        let initiating_snapshot = session_snapshot(&initiating_session)?;

        // Read the current local Coordinator tuple before asking the session
        // authority. Store rechecks the same tuple under BEGIN IMMEDIATE.
        let coordinator_binding = store
            .get_activity_coordinator(request.probe.expectation().activity().id())
            .map_err(map_activity_store_error)?
            .ok_or_else(|| ControlError::new(ControlErrorCode::ActivityConflict))?;
        let coordinator_agent = store
            .get_agent(coordinator_binding.agent_id())
            .map_err(map_activity_store_error)?
            .ok_or_else(|| ControlError::new(ControlErrorCode::ActivityConflict))?;
        let coordinator_session_id = coordinator_agent
            .session_id()
            .ok_or_else(|| ControlError::new(ControlErrorCode::ActivityConflict))?;
        let coordinator_session = self.agent_session_resolve(AgentSessionResolveRequest {
            session_id: coordinator_session_id,
            principal: coordinator_agent.principal(),
        })?;
        let coordinator_snapshot = Some(session_snapshot(&coordinator_session)?);

        let domain_request = DomainRunRequest::new(
            domain_scope,
            request.request_id,
            request.request_digest,
            request.probe.clone(),
            request.current_service,
        )
        .map_err(map_domain_validation)?;
        let result = store.run_started_activity_lease_resume_with_clock(
            &binding,
            &domain_request,
            initiating_snapshot,
            coordinator_snapshot,
            || {
                clock().map_err(|error| WorkspaceStoreError::RecoveryLeaseClockObservation {
                    source: Box::new(error),
                })
            },
        );
        result.map_err(map_started_store_error)
    }

    pub fn started_activity_lease_resume_get(
        &self,
        request: &StartedActivityLeaseResumeGetRequest,
    ) -> Result<Option<StartedActivityLeaseResumeReadback>, ControlError> {
        let (fresh_scope, store, binding, domain_scope) = open_started_scope(self, &request.scope)?;
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
            .started_activity_lease_resume_readback_for_request(&binding, &domain_request)
            .map_err(map_activity_store_error)
    }
}

pub(super) fn open_started_scope(
    control: &ForgeControl,
    scope: &ResolvedWorkspaceScope,
) -> Result<
    (
        ResolvedWorkspaceScope,
        WorkspaceStore,
        WorkspaceJournalBinding,
        ExpiredActivityRecoveryProbeScope,
    ),
    ControlError,
> {
    let (fresh_scope, store) = control.open_resolved_workspace(
        scope.locator().location_id(),
        scope.locator().expected_revision(),
        scope.locator(),
    )?;
    if fresh_scope != *scope {
        return Err(ControlError::new(
            ControlErrorCode::WorkspaceRevisionConflict,
        ));
    }
    let binding = store.journal_binding().map_err(map_activity_store_error)?;
    let workspace = store.workspace().map_err(map_activity_store_error)?;
    let domain_scope = ExpiredActivityRecoveryProbeScope::new(
        fresh_scope.workspace_id(),
        fresh_scope.workspace_revision(),
        fresh_scope.locator().location_id(),
        fresh_scope.locator().expected_revision(),
        fresh_scope.locator().relative_root_bytes().to_vec(),
        workspace.root_fingerprint(),
        binding.recovery_history_digest(),
    )
    .map_err(|_| ControlError::new(ControlErrorCode::InvalidInput))?;
    Ok((fresh_scope, store, binding, domain_scope))
}

pub(super) fn session_snapshot(
    session: &forge_domain::RegisteredAgentSession,
) -> Result<StartedActivityLeaseResumeSessionSnapshot, ControlError> {
    StartedActivityLeaseResumeSessionSnapshot::new(
        session.id(),
        session.principal(),
        session.state(),
        session.revision(),
        session.updated_at(),
    )
    .map_err(map_domain_validation)
}

pub(super) fn optional_session_snapshot(
    control: &ForgeControl,
    session_id: AgentSessionId,
    principal: AuthenticatedPrincipal,
) -> Result<Option<StartedActivityLeaseResumeSessionSnapshot>, ControlError> {
    let Some(session) = control
        .session_authority
        .resolve(AgentSessionResolveRequest {
            session_id,
            principal,
        })?
    else {
        return Ok(None);
    };
    if session.id() != session_id || session.principal() != principal {
        return Ok(None);
    }
    session_snapshot(&session).map(Some)
}

fn map_domain_validation(_: StartedActivityLeaseResumeValidationError) -> ControlError {
    ControlError::new(ControlErrorCode::InvalidInput)
}

fn map_started_store_error(error: WorkspaceStoreError) -> ControlError {
    match error {
        WorkspaceStoreError::StartedActivityLeaseResumeCommittedUnconfirmed { .. } => {
            ControlError::committed()
        }
        other => map_activity_store_error(other),
    }
}
