//! Exact Source observations and commands for the opt-in host supervisor.
//!
//! Calls are synchronous and must run on the supervisor's owned blocking lane.
//! Preparing a resume has no effects; its caller persists the returned Get
//! selector before invoking Run. Source still owns every admission and CAS.

use forge_control::{
    ActivityLeaseClient, ActivityLeaseOperation, ControlClientError, CoordinatorActorRequest,
    ForgeControlClient, QuiescentActivityLeaseResumeGetRequest,
    QuiescentActivityLeaseResumeProbeRequest, QuiescentActivityLeaseResumeRunRequest,
    ResolvedWorkspaceScope, StartedActivityLeaseResumeGetRequest,
    StartedActivityLeaseResumeProbeRequest, StartedActivityLeaseResumeRunRequest,
    SupervisedActivityLeaseRenewRequest, WorkspaceInventoryEntry,
};
use forge_domain::{
    ActivityCoordinatorActor, ActivityCoordinatorRevision, ActivityLeaseRevision, AgentInstanceId,
    AgentSessionId, GoalStatusKind, LocationId, LocationRevision,
    QuiescentActivityLeaseResumeOperation, QuiescentActivityLeaseResumeProbe, RegisteredActivity,
    RenewActivityLease, RuntimeInstanceId, StartedActivityLeaseResumeAgentSnapshot,
    StartedActivityLeaseResumeOperation, StartedActivityLeaseResumeProbe,
    StartedActivityLeaseResumeServiceIdentity, TimestampMillis,
};
use forge_persistence::{QuiescentActivityLeaseResumeReadback, StartedActivityLeaseResumeReadback};
use uuid::Uuid;

use super::{HostActivityLeaseRegistration, PendingResumeGet};

#[derive(Debug)]
pub(super) enum SourceError {
    Control(ControlClientError),
    Invalid(&'static str),
}

impl std::fmt::Display for SourceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Control(_) => formatter.write_str("Source control observation or command failed"),
            Self::Invalid(reason) => write!(formatter, "Source supervision rejected: {reason}"),
        }
    }
}

impl From<ControlClientError> for SourceError {
    fn from(value: ControlClientError) -> Self {
        Self::Control(value)
    }
}

#[derive(Debug, Clone)]
pub(super) struct ResolvedHostRegistration {
    pub scope: ResolvedWorkspaceScope,
    pub registration: HostActivityLeaseRegistration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum GuardStatus {
    Active,
    Finished,
    Paused,
}

pub(super) fn resolve(
    control: &ForgeControlClient,
    registration: HostActivityLeaseRegistration,
) -> Result<Option<ResolvedHostRegistration>, SourceError> {
    registration
        .validate()
        .map_err(|_| SourceError::Invalid("registration"))?;
    let selector = registration.source_scope();
    let location = LocationId::from_uuid(selector.location_id);
    let revision = LocationRevision::new(selector.location_revision)
        .map_err(|_| SourceError::Invalid("Location revision"))?;
    let inventory = control.registered_workspace_inventory(location, revision)?;
    if inventory.location_id() != location || inventory.location_revision() != revision {
        return Err(SourceError::Invalid("inventory scope"));
    }
    let mut selected = None;
    for entry in inventory.entries() {
        match entry {
            WorkspaceInventoryEntry::Registered { scope, .. }
                if scope.workspace_id().into_uuid() == selector.workspace_id =>
            {
                if selected.is_some()
                    || scope.workspace_revision().get() != selector.workspace_revision
                {
                    return Err(SourceError::Invalid("Workspace identity"));
                }
                selected = Some(scope.clone());
            }
            WorkspaceInventoryEntry::Unavailable {
                known_workspace_id: Some(id),
                ..
            } if id.into_uuid() == selector.workspace_id => {
                return Err(SourceError::Invalid("registered Workspace unavailable"));
            }
            // The Source inventory deliberately isolates unavailable siblings
            // and marks known duplicate identities unavailable before return.
            // Only the exact configured Workspace grants this registration.
            _ => {}
        }
    }
    let Some(scope) = selected else {
        return Ok(None);
    };
    let current = control.resolve_workspace(location, revision, scope.locator().clone())?;
    if current != scope {
        return Err(SourceError::Invalid("Workspace changed"));
    }
    Ok(Some(ResolvedHostRegistration {
        scope,
        registration,
    }))
}

pub(super) fn guard(
    control: &ForgeControlClient,
    resolved: &ResolvedHostRegistration,
) -> Result<GuardStatus, SourceError> {
    let registration = resolved.registration;
    let Some(goal) = control.goal_get(
        resolved.scope.clone(),
        registration.activity_id(),
        registration.goal_id(),
    )?
    else {
        return Ok(GuardStatus::Paused);
    };
    if goal.workspace_id() != resolved.scope.workspace_id()
        || goal.activity_id() != registration.activity_id()
        || goal.timestamps().created_at().get() != registration.goal_created_at_ms()
    {
        return Ok(GuardStatus::Paused);
    }
    match goal.status().kind() {
        GoalStatusKind::Completed | GoalStatusKind::Failed | GoalStatusKind::Cancelled => {
            return Ok(GuardStatus::Finished);
        }
        GoalStatusKind::Paused | GoalStatusKind::Blocked => return Ok(GuardStatus::Paused),
        GoalStatusKind::Active => {}
    }
    let principal = registration
        .principal()
        .map_err(|_| SourceError::Invalid("principal"))?;
    let Some(actor) = control.activity_coordinator_actor(CoordinatorActorRequest {
        scope: resolved.scope.clone(),
        activity_id: registration.activity_id(),
        principal,
    })?
    else {
        return Ok(GuardStatus::Paused);
    };
    let pin = registration.coordinator_pin();
    let valid = actor.workspace_id() == resolved.scope.workspace_id()
        && actor.activity_id() == registration.activity_id()
        && actor.agent_id().into_uuid() == pin.agent_id
        && actor.session_id().into_uuid() == pin.session_id
        && actor.session_id() == registration.initiating_session_id()
        && actor.expected_revision().get() == pin.revision
        && actor.principal() == principal;
    Ok(if valid {
        GuardStatus::Active
    } else {
        GuardStatus::Paused
    })
}

pub(super) fn observe(
    leases: &ActivityLeaseClient,
    resolved: &ResolvedHostRegistration,
) -> Result<Option<RegisteredActivity>, SourceError> {
    let mut rows = leases.observe_activity_leases(
        resolved.scope.clone(),
        vec![resolved.registration.activity_id()],
    )?;
    if rows.len() > 1 {
        return Err(SourceError::Invalid("Activity observation count"));
    }
    let Some(activity) = rows.pop() else {
        return Ok(None);
    };
    if activity.id() != resolved.registration.activity_id()
        || activity.workspace_id() != resolved.scope.workspace_id()
    {
        return Err(SourceError::Invalid("Activity observation identity"));
    }
    Ok(Some(activity))
}

pub(super) fn probe_started(
    control: &ForgeControlClient,
    resolved: &ResolvedHostRegistration,
    service: StartedActivityLeaseResumeServiceIdentity,
    now: TimestampMillis,
) -> Result<StartedActivityLeaseResumeProbe, SourceError> {
    Ok(
        control.started_activity_lease_resume_probe(StartedActivityLeaseResumeProbeRequest {
            scope: resolved.scope.clone(),
            activity_id: resolved.registration.activity_id(),
            initiating_session_id: resolved.registration.initiating_session_id(),
            principal: resolved
                .registration
                .principal()
                .map_err(|_| SourceError::Invalid("principal"))?,
            service,
            observed_at: now,
        })?,
    )
}

pub(super) fn probe_quiescent(
    control: &ForgeControlClient,
    resolved: &ResolvedHostRegistration,
    service: StartedActivityLeaseResumeServiceIdentity,
    now: TimestampMillis,
) -> Result<QuiescentActivityLeaseResumeProbe, SourceError> {
    Ok(
        control.quiescent_activity_lease_resume_probe(
            QuiescentActivityLeaseResumeProbeRequest {
                scope: resolved.scope.clone(),
                activity_id: resolved.registration.activity_id(),
                initiating_session_id: resolved.registration.initiating_session_id(),
                principal: resolved
                    .registration
                    .principal()
                    .map_err(|_| SourceError::Invalid("principal"))?,
                service,
                observed_at: now,
            },
        )?,
    )
}

pub(super) fn prepare_started(
    resolved: &ResolvedHostRegistration,
    service: StartedActivityLeaseResumeServiceIdentity,
    probe: StartedActivityLeaseResumeProbe,
    request_id: Uuid,
    now: TimestampMillis,
) -> Result<(StartedActivityLeaseResumeRunRequest, PendingResumeGet), SourceError> {
    if !probe.resumable_now() || !probe.is_live_at(now) || probe.service() != service {
        return Err(SourceError::Invalid("Started probe is not admissible"));
    }
    let digest = forge_backend::ops::started_activity_lease_resume_request_digest(
        &resolved.scope,
        request_id,
        &probe,
    )
    .map_err(|_| SourceError::Invalid("Started request digest"))?;
    let agent = probe
        .expectation()
        .initiating_agent()
        .copied()
        .ok_or(SourceError::Invalid("Started initiating Agent"))?;
    let pending = pending_get(
        resolved,
        request_id,
        digest,
        probe.probe_digest(),
        service.runtime_instance_id(),
        agent,
    )?;
    Ok((
        StartedActivityLeaseResumeRunRequest {
            scope: resolved.scope.clone(),
            request_id,
            request_digest: digest,
            probe,
            current_service: service,
        },
        pending,
    ))
}

pub(super) fn prepare_quiescent(
    resolved: &ResolvedHostRegistration,
    service: StartedActivityLeaseResumeServiceIdentity,
    probe: QuiescentActivityLeaseResumeProbe,
    request_id: Uuid,
    now: TimestampMillis,
) -> Result<(QuiescentActivityLeaseResumeRunRequest, PendingResumeGet), SourceError> {
    if !probe.resumable_now() || !probe.is_live_at(now) || probe.service() != service {
        return Err(SourceError::Invalid("Quiescent probe is not admissible"));
    }
    let digest = forge_backend::ops::quiescent_activity_lease_resume_request_digest(
        &resolved.scope,
        request_id,
        &probe,
    )
    .map_err(|_| SourceError::Invalid("Quiescent request digest"))?;
    let agent = probe
        .expectation()
        .initiating_agent()
        .copied()
        .ok_or(SourceError::Invalid("Quiescent initiating Agent"))?;
    let pending = pending_get(
        resolved,
        request_id,
        digest,
        probe.probe_digest(),
        service.runtime_instance_id(),
        agent,
    )?;
    Ok((
        QuiescentActivityLeaseResumeRunRequest {
            scope: resolved.scope.clone(),
            request_id,
            request_digest: digest,
            probe,
            current_service: service,
        },
        pending,
    ))
}

fn pending_get(
    resolved: &ResolvedHostRegistration,
    request_id: Uuid,
    request_digest: [u8; 32],
    probe_digest: [u8; 32],
    runtime_instance_id: RuntimeInstanceId,
    agent: StartedActivityLeaseResumeAgentSnapshot,
) -> Result<PendingResumeGet, SourceError> {
    let registration = resolved.registration;
    if request_id.is_nil()
        || agent.activity_id() != registration.activity_id()
        || agent.agent_id().into_uuid() != registration.coordinator.agent_id
        || agent.session_id() != registration.initiating_session_id()
        || agent.principal()
            != registration
                .principal()
                .map_err(|_| SourceError::Invalid("principal"))?
    {
        return Err(SourceError::Invalid("resume actor identity"));
    }
    Ok(PendingResumeGet {
        supervision_id: registration.supervision_id(),
        scope: registration.source_scope(),
        goal_id: registration.goal_id,
        goal_created_at_ms: registration.goal_created_at_ms(),
        coordinator: registration.coordinator_pin(),
        request_id,
        request_digest,
        probe_digest,
        activity_id: registration.activity_id_uuid(),
        agent_id: agent.agent_id().into_uuid(),
        initiating_session_id: registration.initiating_session_id,
        principal: registration.principal,
        source_runtime_instance_id: runtime_instance_id.into_uuid(),
    })
}

pub(super) fn run_started(
    control: &ForgeControlClient,
    request: StartedActivityLeaseResumeRunRequest,
) -> Result<StartedActivityLeaseResumeOperation, SourceError> {
    Ok(control.run_started_activity_lease_resume(request)?)
}

pub(super) fn run_quiescent(
    control: &ForgeControlClient,
    request: QuiescentActivityLeaseResumeRunRequest,
) -> Result<QuiescentActivityLeaseResumeOperation, SourceError> {
    Ok(control.run_quiescent_activity_lease_resume(request)?)
}

fn validate_pending(
    resolved: &ResolvedHostRegistration,
    pending: &PendingResumeGet,
) -> Result<(), SourceError> {
    let registered = resolved.registration;
    if pending.supervision_id != registered.supervision_id
        || pending.scope != registered.source_scope()
        || pending.activity_id != registered.activity_id
        || pending.goal_id != registered.goal_id
        || pending.goal_created_at_ms != registered.goal_created_at_ms
        || pending.coordinator != registered.coordinator
        || pending.agent_id != registered.coordinator.agent_id
        || pending.initiating_session_id != registered.initiating_session_id
        || pending.principal != registered.principal
        || pending.request_id.is_nil()
        || pending.source_runtime_instance_id.is_nil()
    {
        return Err(SourceError::Invalid("pending resume registration"));
    }
    Ok(())
}

pub(super) fn get_started(
    control: &ForgeControlClient,
    resolved: &ResolvedHostRegistration,
    pending: &PendingResumeGet,
) -> Result<Option<StartedActivityLeaseResumeReadback>, SourceError> {
    validate_pending(resolved, pending)?;
    Ok(
        control.started_activity_lease_resume_get(StartedActivityLeaseResumeGetRequest {
            scope: resolved.scope.clone(),
            request_id: pending.request_id,
            request_digest: pending.request_digest,
            activity_id: resolved.registration.activity_id(),
            agent_id: AgentInstanceId::from_uuid(pending.agent_id),
            initiating_session_id: resolved.registration.initiating_session_id(),
            principal: resolved
                .registration
                .principal()
                .map_err(|_| SourceError::Invalid("principal"))?,
        })?,
    )
}

pub(super) fn get_quiescent(
    control: &ForgeControlClient,
    resolved: &ResolvedHostRegistration,
    pending: &PendingResumeGet,
) -> Result<Option<QuiescentActivityLeaseResumeReadback>, SourceError> {
    validate_pending(resolved, pending)?;
    Ok(
        control.quiescent_activity_lease_resume_get(QuiescentActivityLeaseResumeGetRequest {
            scope: resolved.scope.clone(),
            request_id: pending.request_id,
            request_digest: pending.request_digest,
            activity_id: resolved.registration.activity_id(),
            agent_id: AgentInstanceId::from_uuid(pending.agent_id),
            initiating_session_id: resolved.registration.initiating_session_id(),
            principal: resolved
                .registration
                .principal()
                .map_err(|_| SourceError::Invalid("principal"))?,
        })?,
    )
}

pub(super) fn renew(
    leases: &ActivityLeaseClient,
    resolved: &ResolvedHostRegistration,
    owner: RuntimeInstanceId,
    expected_revision: ActivityLeaseRevision,
    now: TimestampMillis,
    duration_ms: i64,
) -> Result<ActivityLeaseOperation, SourceError> {
    if !(super::MIN_LEASE_DURATION_MS..=super::MAX_LEASE_DURATION_MS).contains(&duration_ms) {
        return Err(SourceError::Invalid("renewal duration"));
    }
    let until = now
        .get()
        .checked_add(duration_ms)
        .and_then(|value| TimestampMillis::new(value).ok())
        .ok_or(SourceError::Invalid("renewal timestamp"))?;
    let registration = resolved.registration;
    let pin = registration.coordinator_pin();
    let actor = ActivityCoordinatorActor::new(
        resolved.scope.workspace_id(),
        registration.activity_id(),
        AgentInstanceId::from_uuid(pin.agent_id),
        ActivityCoordinatorRevision::new(pin.revision)
            .map_err(|_| SourceError::Invalid("Coordinator revision"))?,
        registration
            .principal()
            .map_err(|_| SourceError::Invalid("principal"))?,
        AgentSessionId::from_uuid(pin.session_id),
    );
    Ok(
        leases.renew_supervised_activity_lease(SupervisedActivityLeaseRenewRequest {
            scope: resolved.scope.clone(),
            actor,
            goal_id: registration.goal_id(),
            goal_created_at: TimestampMillis::new(registration.goal_created_at_ms())
                .map_err(|_| SourceError::Invalid("Goal creation timestamp"))?,
            command: RenewActivityLease::new(
                resolved.registration.activity_id(),
                owner,
                expected_revision,
                until,
                now,
            ),
        })?,
    )
}
