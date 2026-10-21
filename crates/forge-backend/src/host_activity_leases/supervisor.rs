//! Structured Tokio owner for configured Activity lease registrations.

use std::collections::HashSet;
use std::error::Error;
use std::fmt;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use forge_control::{ActivityLeaseClient, ControlClientError, ForgeControlClient};
use forge_domain::{
    ActivityLeaseRevision, ActivityState, AuthenticatedPrincipal, RuntimeInstanceId,
    StartedActivityLeaseResumeBlocker, StartedActivityLeaseResumeServiceIdentity, TimestampMillis,
};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::sleep;
use uuid::Uuid;

use super::source::{self, GuardStatus, ResolvedHostRegistration, SourceError};
use super::{
    HostActivityLeaseRegistration, HostActivityLeaseSupervisionConfig, JournalStore, LeasePrestate,
    PendingOperation, PendingRenewal, PendingResumeGet, RenewReadback, classify_pending_renewal,
};

const LEASE_SAFETY_MARGIN_MS: i64 = 5_000;
const FOREIGN_LEASE_LAG_MS: i64 = 1_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SupervisorError {
    Configuration,
    Journal,
    Clock,
    ControlWorker,
    UnexpectedExit,
}

impl fmt::Display for SupervisorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Configuration => "Activity lease supervisor configuration is invalid",
            Self::Journal => "Activity lease supervisor journal failed",
            Self::Clock => "Activity lease supervisor clock observation failed",
            Self::ControlWorker => "Activity lease supervisor control worker failed",
            Self::UnexpectedExit => "Activity lease supervisor exited unexpectedly",
        })
    }
}

impl Error for SupervisorError {}

pub(crate) struct PreparedHostActivityLeaseSupervisor {
    config: HostActivityLeaseSupervisionConfig,
    journal: JournalStore,
}

impl PreparedHostActivityLeaseSupervisor {
    pub(crate) fn validate_config(
        config: Option<&HostActivityLeaseSupervisionConfig>,
        registry_path: &Path,
    ) -> Result<(), SupervisorError> {
        if let Some(config) = config {
            config
                .validate(registry_path)
                .map_err(|_| SupervisorError::Configuration)?;
        }
        Ok(())
    }

    pub(crate) fn prepare(
        config: Option<&HostActivityLeaseSupervisionConfig>,
        registry_path: &Path,
    ) -> Result<Option<Self>, SupervisorError> {
        let Some(config) = config else {
            return Ok(None);
        };
        Self::validate_config(Some(config), registry_path)?;
        let journal =
            JournalStore::open(config.journal_root()).map_err(|_| SupervisorError::Journal)?;
        journal
            .validate_registrations(config.registrations())
            .map_err(|_| SupervisorError::Journal)?;
        Ok(Some(Self {
            config: config.clone(),
            journal,
        }))
    }

    pub(crate) fn start(
        self,
        handle: &tokio::runtime::Handle,
        control: ForgeControlClient,
        leases: ActivityLeaseClient,
        runtime_instance_id: RuntimeInstanceId,
        service: StartedActivityLeaseResumeServiceIdentity,
    ) -> HostActivityLeaseSupervisor {
        let (stop_tx, stop_rx) = watch::channel(false);
        let (failure_tx, failure_rx) = watch::channel(None);
        let task = handle.spawn(async move {
            let result = run_supervisor(
                self.config,
                self.journal,
                control,
                leases,
                runtime_instance_id,
                service,
                stop_rx,
            )
            .await;
            if let Err(error) = result {
                let _ = failure_tx.send(Some(error));
            }
            result
        });
        HostActivityLeaseSupervisor {
            stop: stop_tx,
            failure: failure_rx,
            task,
        }
    }
}

pub(crate) struct HostActivityLeaseSupervisor {
    stop: watch::Sender<bool>,
    failure: watch::Receiver<Option<SupervisorError>>,
    task: JoinHandle<Result<(), SupervisorError>>,
}

impl HostActivityLeaseSupervisor {
    pub(crate) async fn wait_for_failure(&mut self) -> SupervisorError {
        loop {
            if let Some(error) = *self.failure.borrow_and_update() {
                return error;
            }
            if self.failure.changed().await.is_err() {
                return SupervisorError::UnexpectedExit;
            }
        }
    }

    pub(crate) fn stop(self) -> JoinHandle<Result<(), SupervisorError>> {
        let _ = self.stop.send(true);
        self.task
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SourceCallError {
    Unavailable,
    Worker,
}

async fn source_call<T, F>(call: F) -> Result<T, SourceCallError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, SourceError> + Send + 'static,
{
    match tokio::task::spawn_blocking(call).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(SourceError::Control(
            ControlClientError::WorkerClosed | ControlClientError::WorkerShuttingDown,
        )))
        | Err(_) => Err(SourceCallError::Worker),
        Ok(Err(_)) => Err(SourceCallError::Unavailable),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegistrationDecision {
    Retry,
    Paused,
    Active(TimestampMillis),
}

struct RegistrationCycle<'a> {
    config: &'a HostActivityLeaseSupervisionConfig,
    journal: &'a mut JournalStore,
    control: &'a ForgeControlClient,
    leases: &'a ActivityLeaseClient,
    runtime_instance_id: RuntimeInstanceId,
    service: StartedActivityLeaseResumeServiceIdentity,
    stop: watch::Receiver<bool>,
}

async fn run_supervisor(
    config: HostActivityLeaseSupervisionConfig,
    mut journal: JournalStore,
    control: ForgeControlClient,
    leases: ActivityLeaseClient,
    runtime_instance_id: RuntimeInstanceId,
    service: StartedActivityLeaseResumeServiceIdentity,
    mut stop: watch::Receiver<bool>,
) -> Result<(), SupervisorError> {
    let mut paused = HashSet::new();
    loop {
        if *stop.borrow() {
            return Ok(());
        }
        let now = current_source_time()?;
        let mut next_wake = timestamp_after(now, config.renew_interval_ms())?;
        for registration in config.registrations().iter().copied() {
            if *stop.borrow() {
                return Ok(());
            }
            if paused.contains(&registration.supervision_id()) {
                continue;
            }
            let decision = {
                let mut cycle = RegistrationCycle {
                    config: &config,
                    journal: &mut journal,
                    control: &control,
                    leases: &leases,
                    runtime_instance_id,
                    service,
                    stop: stop.clone(),
                };
                service_registration(registration, &mut cycle).await?
            };
            match decision {
                RegistrationDecision::Retry => {}
                RegistrationDecision::Paused => {
                    paused.insert(registration.supervision_id());
                }
                RegistrationDecision::Active(wake_at) => {
                    next_wake = earliest(Some(next_wake), wake_at);
                }
            }
        }
        let now = current_source_time()?;
        if !wait_or_stop(&mut stop, now, next_wake).await {
            return Ok(());
        }
    }
}

async fn service_registration(
    registration: HostActivityLeaseRegistration,
    cycle: &mut RegistrationCycle<'_>,
) -> Result<RegistrationDecision, SupervisorError> {
    if *cycle.stop.borrow() {
        return Ok(RegistrationDecision::Paused);
    }
    let resolved = match source_call({
        let control = cycle.control.clone();
        move || source::resolve(&control, registration)
    })
    .await
    {
        Ok(Some(resolved)) => resolved,
        Ok(None) | Err(SourceCallError::Unavailable) => return Ok(RegistrationDecision::Retry),
        Err(SourceCallError::Worker) => return Err(SupervisorError::ControlWorker),
    };
    if *cycle.stop.borrow() {
        return Ok(RegistrationDecision::Paused);
    }

    match source_call({
        let control = cycle.control.clone();
        let resolved = resolved.clone();
        move || source::guard(&control, &resolved)
    })
    .await
    {
        Ok(GuardStatus::Active) => {}
        Ok(GuardStatus::Finished | GuardStatus::Paused) => {
            return Ok(RegistrationDecision::Paused);
        }
        Err(SourceCallError::Unavailable) => return Ok(RegistrationDecision::Retry),
        Err(SourceCallError::Worker) => return Err(SupervisorError::ControlWorker),
    }
    if *cycle.stop.borrow() {
        return Ok(RegistrationDecision::Paused);
    }

    if let Some(pending) = cycle
        .journal
        .pending(registration.supervision_id())
        .cloned()
    {
        if pending.supervision_id() != registration.supervision_id()
            || !pending.matches_registration(registration)
        {
            return Ok(RegistrationDecision::Paused);
        }
        return reconcile_pending(registration, &resolved, &pending, cycle).await;
    }

    let activity = match source_call({
        let leases = cycle.leases.clone();
        let resolved = resolved.clone();
        move || source::observe(&leases, &resolved)
    })
    .await
    {
        Ok(Some(activity)) => activity,
        Ok(None) | Err(SourceCallError::Unavailable) => return Ok(RegistrationDecision::Retry),
        Err(SourceCallError::Worker) => return Err(SupervisorError::ControlWorker),
    };
    let now = current_source_time()?;
    if *cycle.stop.borrow() {
        return Ok(RegistrationDecision::Paused);
    }
    if activity.id() != registration.activity_id() || activity.state() != ActivityState::Open {
        return Ok(RegistrationDecision::Paused);
    }
    let (Some(owner), Some(lease_until)) = (activity.lease_owner_id(), activity.lease_until())
    else {
        // Lease-free Activities are never bootstrapped by host supervision.
        return Ok(RegistrationDecision::Retry);
    };
    if lease_until.get() > now.get() {
        if owner != cycle.runtime_instance_id {
            return Ok(RegistrationDecision::Active(foreign_lease_wake_at(
                now,
                lease_until,
                cycle.config.renew_interval_ms(),
            )?));
        }
        if !owned_lease_renewal_due(now, lease_until) {
            return Ok(RegistrationDecision::Active(lease_wake_at(
                now,
                lease_until,
                cycle.config.renew_interval_ms(),
            )?));
        }
        return renew_owned_lease(registration, &resolved, &activity, now, cycle).await;
    }

    resume_expired_lease(registration, &resolved, cycle).await
}

async fn reconcile_pending(
    registration: HostActivityLeaseRegistration,
    resolved: &ResolvedHostRegistration,
    pending: &PendingOperation,
    cycle: &mut RegistrationCycle<'_>,
) -> Result<RegistrationDecision, SupervisorError> {
    match pending {
        PendingOperation::StartedResume(selector) => {
            let readback = match source_call({
                let control = cycle.control.clone();
                let resolved = resolved.clone();
                let selector = selector.clone();
                move || source::get_started(&control, &resolved, &selector)
            })
            .await
            {
                Ok(readback) => readback,
                Err(SourceCallError::Unavailable) => return Ok(RegistrationDecision::Retry),
                Err(SourceCallError::Worker) => return Err(SupervisorError::ControlWorker),
            };
            let Some(readback) = readback else {
                return Ok(RegistrationDecision::Retry);
            };
            if !started_receipt_matches(readback.receipt(), selector, resolved) {
                return Ok(RegistrationDecision::Paused);
            }
            cycle
                .journal
                .clear_pending(registration.supervision_id(), pending)
                .await
                .map_err(|_| SupervisorError::Journal)?;
            Ok(RegistrationDecision::Active(timestamp_after(
                current_source_time()?,
                cycle.config.renew_interval_ms(),
            )?))
        }
        PendingOperation::QuiescentResume(selector) => {
            let readback = match source_call({
                let control = cycle.control.clone();
                let resolved = resolved.clone();
                let selector = selector.clone();
                move || source::get_quiescent(&control, &resolved, &selector)
            })
            .await
            {
                Ok(readback) => readback,
                Err(SourceCallError::Unavailable) => return Ok(RegistrationDecision::Retry),
                Err(SourceCallError::Worker) => return Err(SupervisorError::ControlWorker),
            };
            let Some(readback) = readback else {
                return Ok(RegistrationDecision::Retry);
            };
            if !quiescent_receipt_matches(readback.receipt(), selector, resolved) {
                return Ok(RegistrationDecision::Paused);
            }
            cycle
                .journal
                .clear_pending(registration.supervision_id(), pending)
                .await
                .map_err(|_| SupervisorError::Journal)?;
            Ok(RegistrationDecision::Active(timestamp_after(
                current_source_time()?,
                cycle.config.renew_interval_ms(),
            )?))
        }
        PendingOperation::Renewal(renewal) => {
            let activity = match source_call({
                let leases = cycle.leases.clone();
                let resolved = resolved.clone();
                move || source::observe(&leases, &resolved)
            })
            .await
            {
                Ok(Some(activity)) => activity,
                Ok(None) | Err(SourceCallError::Unavailable) => {
                    return Ok(RegistrationDecision::Retry);
                }
                Err(SourceCallError::Worker) => return Err(SupervisorError::ControlWorker),
            };
            match classify_pending_renewal(
                renewal,
                &activity,
                cycle.runtime_instance_id,
                current_source_time()?,
            ) {
                RenewReadback::ObservedCurrentLease
                | RenewReadback::ObservedPreviousBootLease
                | RenewReadback::ObservedOldState => {
                    cycle
                        .journal
                        .clear_pending(registration.supervision_id(), pending)
                        .await
                        .map_err(|_| SupervisorError::Journal)?;
                    Ok(RegistrationDecision::Active(timestamp_after(
                        current_source_time()?,
                        cycle.config.renew_interval_ms(),
                    )?))
                }
                RenewReadback::StillPending => Ok(RegistrationDecision::Retry),
                RenewReadback::ChangedOrClosed => Ok(RegistrationDecision::Paused),
            }
        }
    }
}

async fn renew_owned_lease(
    registration: HostActivityLeaseRegistration,
    resolved: &ResolvedHostRegistration,
    activity: &forge_domain::RegisteredActivity,
    observed_at: TimestampMillis,
    cycle: &mut RegistrationCycle<'_>,
) -> Result<RegistrationDecision, SupervisorError> {
    let Some(prestate) = LeasePrestate::from_source(activity) else {
        return Ok(RegistrationDecision::Paused);
    };
    if prestate.lease_owner_id != cycle.runtime_instance_id.into_uuid()
        || prestate.activity_state != super::HostActivityState::Open
        || prestate.lease_until_ms <= observed_at.get()
    {
        return Ok(RegistrationDecision::Retry);
    }
    let pending = PendingOperation::Renewal(PendingRenewal {
        supervision_id: registration.supervision_id(),
        scope: registration.source_scope(),
        activity_id: registration.activity_id_uuid(),
        owner_id: cycle.runtime_instance_id.into_uuid(),
        expected_lease_revision: prestate.lease_revision,
        duration_ms: cycle.config.lease_duration_ms(),
        observed_at_ms: observed_at.get(),
        prestate,
    });
    cycle
        .journal
        .insert_pending(registration.supervision_id(), pending.clone())
        .await
        .map_err(|_| SupervisorError::Journal)?;
    if *cycle.stop.borrow() {
        cycle
            .journal
            .clear_pending(registration.supervision_id(), &pending)
            .await
            .map_err(|_| SupervisorError::Journal)?;
        return Ok(RegistrationDecision::Paused);
    }

    let PendingOperation::Renewal(renewal_intent) = &pending else {
        return Err(SupervisorError::Journal);
    };
    let expected_lease_revision =
        ActivityLeaseRevision::new(renewal_intent.expected_lease_revision)
            .map_err(|_| SupervisorError::Journal)?;
    let _operation = source_call({
        let leases = cycle.leases.clone();
        let resolved = resolved.clone();
        let runtime_instance_id = cycle.runtime_instance_id;
        let duration_ms = cycle.config.lease_duration_ms();
        move || {
            source::renew(
                &leases,
                &resolved,
                runtime_instance_id,
                expected_lease_revision,
                observed_at,
                duration_ms,
            )
        }
    })
    .await;

    let after = match source_call({
        let leases = cycle.leases.clone();
        let resolved = resolved.clone();
        move || source::observe(&leases, &resolved)
    })
    .await
    {
        Ok(Some(activity)) => activity,
        Ok(None) | Err(SourceCallError::Unavailable) => return Ok(RegistrationDecision::Retry),
        Err(SourceCallError::Worker) => return Err(SupervisorError::ControlWorker),
    };
    let PendingOperation::Renewal(renewal) = &pending else {
        return Err(SupervisorError::Journal);
    };
    match classify_pending_renewal(
        renewal,
        &after,
        cycle.runtime_instance_id,
        current_source_time()?,
    ) {
        RenewReadback::ObservedCurrentLease => {
            cycle
                .journal
                .clear_pending(registration.supervision_id(), &pending)
                .await
                .map_err(|_| SupervisorError::Journal)?;
            Ok(RegistrationDecision::Active(timestamp_after(
                current_source_time()?,
                cycle.config.renew_interval_ms(),
            )?))
        }
        RenewReadback::ObservedPreviousBootLease
        | RenewReadback::ObservedOldState
        | RenewReadback::StillPending => Ok(RegistrationDecision::Retry),
        RenewReadback::ChangedOrClosed => Ok(RegistrationDecision::Paused),
    }
}

async fn resume_expired_lease(
    registration: HostActivityLeaseRegistration,
    resolved: &ResolvedHostRegistration,
    cycle: &mut RegistrationCycle<'_>,
) -> Result<RegistrationDecision, SupervisorError> {
    let observed_at = current_source_time()?;
    let probe = match source_call({
        let control = cycle.control.clone();
        let resolved = resolved.clone();
        let service = cycle.service;
        move || source::probe_started(&control, &resolved, service, observed_at)
    })
    .await
    {
        Ok(probe) => probe,
        Err(SourceCallError::Unavailable) => return Ok(RegistrationDecision::Retry),
        Err(SourceCallError::Worker) => return Err(SupervisorError::ControlWorker),
    };

    if probe.blocker() == Some(StartedActivityLeaseResumeBlocker::ActivityNotStarted) {
        return resume_quiescent(registration, resolved, cycle).await;
    }
    if !probe.resumable_now() {
        return Ok(RegistrationDecision::Retry);
    }
    let run_now = current_source_time()?;
    let request_id = Uuid::now_v7();
    let Ok((request, selector)) =
        source::prepare_started(resolved, cycle.service, probe, request_id, run_now)
    else {
        return Ok(RegistrationDecision::Retry);
    };
    if *cycle.stop.borrow() {
        return Ok(RegistrationDecision::Paused);
    }
    let pending = PendingOperation::StartedResume(selector.clone());
    cycle
        .journal
        .insert_pending(registration.supervision_id(), pending)
        .await
        .map_err(|_| SupervisorError::Journal)?;
    if *cycle.stop.borrow() {
        cycle
            .journal
            .clear_pending(
                registration.supervision_id(),
                &PendingOperation::StartedResume(selector),
            )
            .await
            .map_err(|_| SupervisorError::Journal)?;
        return Ok(RegistrationDecision::Paused);
    }
    let _operation = source_call({
        let control = cycle.control.clone();
        move || source::run_started(&control, request)
    })
    .await;
    settle_resume_get_started(registration, resolved, &selector, cycle).await
}

async fn resume_quiescent(
    registration: HostActivityLeaseRegistration,
    resolved: &ResolvedHostRegistration,
    cycle: &mut RegistrationCycle<'_>,
) -> Result<RegistrationDecision, SupervisorError> {
    let observed_at = current_source_time()?;
    let probe = match source_call({
        let control = cycle.control.clone();
        let resolved = resolved.clone();
        let service = cycle.service;
        move || source::probe_quiescent(&control, &resolved, service, observed_at)
    })
    .await
    {
        Ok(probe) => probe,
        Err(SourceCallError::Unavailable) => return Ok(RegistrationDecision::Retry),
        Err(SourceCallError::Worker) => return Err(SupervisorError::ControlWorker),
    };
    if !probe.resumable_now() {
        return Ok(RegistrationDecision::Retry);
    }
    let run_now = current_source_time()?;
    let request_id = Uuid::now_v7();
    let Ok((request, selector)) =
        source::prepare_quiescent(resolved, cycle.service, probe, request_id, run_now)
    else {
        return Ok(RegistrationDecision::Retry);
    };
    if *cycle.stop.borrow() {
        return Ok(RegistrationDecision::Paused);
    }
    let pending = PendingOperation::QuiescentResume(selector.clone());
    cycle
        .journal
        .insert_pending(registration.supervision_id(), pending)
        .await
        .map_err(|_| SupervisorError::Journal)?;
    if *cycle.stop.borrow() {
        cycle
            .journal
            .clear_pending(
                registration.supervision_id(),
                &PendingOperation::QuiescentResume(selector),
            )
            .await
            .map_err(|_| SupervisorError::Journal)?;
        return Ok(RegistrationDecision::Paused);
    }
    let _operation = source_call({
        let control = cycle.control.clone();
        move || source::run_quiescent(&control, request)
    })
    .await;
    settle_resume_get_quiescent(registration, resolved, &selector, cycle).await
}

async fn settle_resume_get_started(
    registration: HostActivityLeaseRegistration,
    resolved: &ResolvedHostRegistration,
    selector: &PendingResumeGet,
    cycle: &mut RegistrationCycle<'_>,
) -> Result<RegistrationDecision, SupervisorError> {
    let readback = match source_call({
        let control = cycle.control.clone();
        let resolved = resolved.clone();
        let selector = selector.clone();
        move || source::get_started(&control, &resolved, &selector)
    })
    .await
    {
        Ok(readback) => readback,
        Err(SourceCallError::Unavailable) => return Ok(RegistrationDecision::Retry),
        Err(SourceCallError::Worker) => return Err(SupervisorError::ControlWorker),
    };
    let Some(readback) = readback else {
        return Ok(RegistrationDecision::Retry);
    };
    if !started_receipt_matches(readback.receipt(), selector, resolved)
        || readback.receipt().source_runtime_instance_id() != cycle.runtime_instance_id
    {
        return Ok(RegistrationDecision::Paused);
    }
    let pending = PendingOperation::StartedResume(selector.clone());
    cycle
        .journal
        .clear_pending(registration.supervision_id(), &pending)
        .await
        .map_err(|_| SupervisorError::Journal)?;
    Ok(RegistrationDecision::Active(timestamp_after(
        current_source_time()?,
        cycle.config.renew_interval_ms(),
    )?))
}

async fn settle_resume_get_quiescent(
    registration: HostActivityLeaseRegistration,
    resolved: &ResolvedHostRegistration,
    selector: &PendingResumeGet,
    cycle: &mut RegistrationCycle<'_>,
) -> Result<RegistrationDecision, SupervisorError> {
    let readback = match source_call({
        let control = cycle.control.clone();
        let resolved = resolved.clone();
        let selector = selector.clone();
        move || source::get_quiescent(&control, &resolved, &selector)
    })
    .await
    {
        Ok(readback) => readback,
        Err(SourceCallError::Unavailable) => return Ok(RegistrationDecision::Retry),
        Err(SourceCallError::Worker) => return Err(SupervisorError::ControlWorker),
    };
    let Some(readback) = readback else {
        return Ok(RegistrationDecision::Retry);
    };
    if !quiescent_receipt_matches(readback.receipt(), selector, resolved)
        || readback.receipt().source_runtime_instance_id() != cycle.runtime_instance_id
    {
        return Ok(RegistrationDecision::Paused);
    }
    let pending = PendingOperation::QuiescentResume(selector.clone());
    cycle
        .journal
        .clear_pending(registration.supervision_id(), &pending)
        .await
        .map_err(|_| SupervisorError::Journal)?;
    Ok(RegistrationDecision::Active(timestamp_after(
        current_source_time()?,
        cycle.config.renew_interval_ms(),
    )?))
}

fn started_receipt_matches(
    receipt: &forge_domain::StartedActivityLeaseResumeReceipt,
    selector: &PendingResumeGet,
    resolved: &ResolvedHostRegistration,
) -> bool {
    let initiating_session = receipt.initiating_session();
    let coordinator = receipt.coordinator();
    receipt.request_id() == selector.request_id
        && receipt.request_digest() == selector.request_digest
        && receipt.probe_digest() == selector.probe_digest
        && receipt.activity_id().into_uuid() == selector.activity_id
        && receipt.initiating_agent().agent_id().into_uuid() == selector.agent_id
        && initiating_session.session_id().into_uuid() == selector.initiating_session_id
        && principal_matches(initiating_session.principal(), selector.principal)
        && coordinator.agent_id().into_uuid() == selector.coordinator.agent_id
        && coordinator.session_id().into_uuid() == selector.coordinator.session_id
        && coordinator.revision().get() == selector.coordinator.revision
        && receipt.source_runtime_instance_id().into_uuid() == selector.source_runtime_instance_id
        && receipt.activity().state() == ActivityState::Open
        && scope_matches(receipt.scope(), &resolved.scope)
}

fn quiescent_receipt_matches(
    receipt: &forge_domain::QuiescentActivityLeaseResumeReceipt,
    selector: &PendingResumeGet,
    resolved: &ResolvedHostRegistration,
) -> bool {
    let initiating_session = receipt.initiating_session();
    let coordinator = receipt.coordinator();
    receipt.request_id() == selector.request_id
        && receipt.request_digest() == selector.request_digest
        && receipt.probe_digest() == selector.probe_digest
        && receipt.activity_id().into_uuid() == selector.activity_id
        && receipt.initiating_agent().agent_id().into_uuid() == selector.agent_id
        && initiating_session.session_id().into_uuid() == selector.initiating_session_id
        && principal_matches(initiating_session.principal(), selector.principal)
        && coordinator.agent_id().into_uuid() == selector.coordinator.agent_id
        && coordinator.session_id().into_uuid() == selector.coordinator.session_id
        && coordinator.revision().get() == selector.coordinator.revision
        && receipt.source_runtime_instance_id().into_uuid() == selector.source_runtime_instance_id
        && receipt.activity().state() == ActivityState::Open
        && scope_matches(receipt.scope(), &resolved.scope)
}

fn scope_matches(
    receipt: &forge_domain::ExpiredActivityRecoveryProbeScope,
    scope: &forge_control::ResolvedWorkspaceScope,
) -> bool {
    receipt.workspace_id() == scope.workspace_id()
        && receipt.workspace_revision() == scope.workspace_revision()
        && receipt.location_id() == scope.locator().location_id()
        && receipt.location_revision() == scope.locator().expected_revision()
}

fn principal_matches(
    source: AuthenticatedPrincipal,
    configured: super::HostPrincipalConfig,
) -> bool {
    configured
        .into_source()
        .is_ok_and(|expected| expected == source)
}

fn current_source_time() -> Result<TimestampMillis, SupervisorError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| SupervisorError::Clock)?;
    let millis = i64::try_from(elapsed.as_millis()).map_err(|_| SupervisorError::Clock)?;
    TimestampMillis::new(millis).map_err(|_| SupervisorError::Clock)
}

fn timestamp_after(
    observed_at: TimestampMillis,
    duration_ms: i64,
) -> Result<TimestampMillis, SupervisorError> {
    let millis = observed_at
        .get()
        .checked_add(duration_ms)
        .ok_or(SupervisorError::Clock)?;
    TimestampMillis::new(millis).map_err(|_| SupervisorError::Clock)
}

fn lease_wake_at(
    now: TimestampMillis,
    lease_until: TimestampMillis,
    interval_ms: i64,
) -> Result<TimestampMillis, SupervisorError> {
    let interval_wake = timestamp_after(now, interval_ms)?;
    let deadline_wake = TimestampMillis::new(
        lease_until
            .get()
            .saturating_sub(LEASE_SAFETY_MARGIN_MS)
            .max(now.get()),
    )
    .map_err(|_| SupervisorError::Clock)?;
    Ok(earliest(Some(interval_wake), deadline_wake))
}

fn owned_lease_renewal_due(now: TimestampMillis, lease_until: TimestampMillis) -> bool {
    lease_until.get().saturating_sub(LEASE_SAFETY_MARGIN_MS) <= now.get()
}

fn foreign_lease_wake_at(
    now: TimestampMillis,
    lease_until: TimestampMillis,
    interval_ms: i64,
) -> Result<TimestampMillis, SupervisorError> {
    let interval_wake = timestamp_after(now, interval_ms)?;
    let expiry_recheck = timestamp_after(lease_until, FOREIGN_LEASE_LAG_MS)?;
    let wake_at = earliest(Some(interval_wake), expiry_recheck);
    if wake_at.get() > now.get() {
        Ok(wake_at)
    } else {
        timestamp_after(now, FOREIGN_LEASE_LAG_MS)
    }
}

fn earliest(left: Option<TimestampMillis>, right: TimestampMillis) -> TimestampMillis {
    left.map_or(right, |value| value.min(right))
}

async fn wait_or_stop(
    stop: &mut watch::Receiver<bool>,
    now: TimestampMillis,
    wake_at: TimestampMillis,
) -> bool {
    if *stop.borrow() {
        return false;
    }
    let delay_ms = wake_at.get().saturating_sub(now.get()).max(0);
    tokio::select! {
        () = sleep(Duration::from_millis(u64::try_from(delay_ms).unwrap_or(u64::MAX))) => true,
        changed = stop.changed() => changed.is_ok() && !*stop.borrow(),
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;

    #[test]
    fn lease_wakeup_is_bounded_by_interval_and_actual_expiry_margin() -> Result<(), Box<dyn Error>>
    {
        let now = TimestampMillis::new(100_000)?;
        let near_expiry = TimestampMillis::new(130_000)?;
        assert_eq!(
            lease_wake_at(now, near_expiry, 20_000)?,
            TimestampMillis::new(120_000)?
        );

        let long_resume_lease = TimestampMillis::new(400_000)?;
        assert_eq!(
            lease_wake_at(now, long_resume_lease, 60_000)?,
            TimestampMillis::new(160_000)?
        );

        let short_remaining_lease = TimestampMillis::new(122_000)?;
        assert_eq!(
            lease_wake_at(now, short_remaining_lease, 60_000)?,
            TimestampMillis::new(117_000)?
        );
        assert!(owned_lease_renewal_due(now, TimestampMillis::new(104_000)?,));
        assert!(!owned_lease_renewal_due(now, near_expiry));

        let foreign_near_expiry = TimestampMillis::new(103_000)?;
        assert_eq!(
            foreign_lease_wake_at(now, foreign_near_expiry, 20_000)?,
            TimestampMillis::new(104_000)?
        );
        Ok(())
    }

    #[test]
    fn disabled_supervision_does_not_validate_or_open_a_journal() -> Result<(), Box<dyn Error>> {
        assert!(
            PreparedHostActivityLeaseSupervisor::prepare(None, Path::new("relative-registry"))?
                .is_none()
        );
        Ok(())
    }

    #[tokio::test]
    async fn shutdown_watch_preempts_scheduled_sleep() -> Result<(), Box<dyn Error>> {
        let (stop, mut receiver) = watch::channel(false);
        stop.send(true).map_err(|_| "watch receiver closed")?;
        let now = TimestampMillis::new(1_000)?;
        let wake_at = TimestampMillis::new(61_000)?;
        assert!(!wait_or_stop(&mut receiver, now, wake_at).await);
        Ok(())
    }
}
