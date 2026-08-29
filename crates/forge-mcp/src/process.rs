//! Owned MCP server process lifecycle and bounded lease tracking.

use std::time::Duration;

use forge_control::{
    ActivityLeaseOperation, ControlErrorCode, ForgeControlClient, ResolvedWorkspaceScope,
};
use forge_domain::{
    ActivityId, ActivityLeaseRevision, CloseActivity, RenewActivityLease, RuntimeInstanceId,
    TimestampMillis,
};
use rmcp::{service::serve_server_with_ct, transport::stdio};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::frame::BoundedMcpFrameReader;
use crate::service::McpServerService;

/// Default Activity lease duration used by the MCP process policy.
pub const DEFAULT_LEASE_DURATION_MS: i64 = 30_000;
/// Default lease heartbeat interval.  Renewal is performed through the
/// bounded control client by the owned tracker.
pub const DEFAULT_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);
/// Maximum Activity leases retained by one MCP process tracker.
pub const MAX_OWNED_ACTIVITIES: usize = 128;
/// Maximum distinct Workspace heartbeat groups owned by one MCP process.
///
/// With the current single-owner control worker and five-second `SQLite` busy
/// bound, two sequential groups remain inside the 20-second interval between
/// the first heartbeat and the 30-second lease expiry. Raising this requires a
/// measured priority/concurrency design rather than widening the queue.
pub const MAX_OWNED_WORKSPACE_GROUPS: usize = 2;
const OWNED_CHANNEL_CAPACITY: usize = MAX_OWNED_ACTIVITIES;

/// Validated lease duration and heartbeat policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct McpLeasePolicy {
    lease_duration_ms: i64,
    heartbeat_interval: Duration,
}

impl Default for McpLeasePolicy {
    fn default() -> Self {
        Self {
            lease_duration_ms: DEFAULT_LEASE_DURATION_MS,
            heartbeat_interval: DEFAULT_HEARTBEAT_INTERVAL,
        }
    }
}

impl McpLeasePolicy {
    pub fn new(
        lease_duration_ms: i64,
        heartbeat_interval: Duration,
    ) -> Result<Self, McpConfigError> {
        if lease_duration_ms <= 0 {
            return Err(McpConfigError::InvalidLeaseDuration);
        }
        if heartbeat_interval.is_zero() {
            return Err(McpConfigError::InvalidHeartbeatInterval);
        }
        let heartbeat_ms = heartbeat_interval.as_millis();
        let lease_duration_ms =
            u128::try_from(lease_duration_ms).map_err(|_| McpConfigError::InvalidLeaseDuration)?;
        if heartbeat_ms == 0 || heartbeat_ms >= lease_duration_ms {
            return Err(McpConfigError::HeartbeatNotBeforeLeaseExpiry);
        }
        Ok(Self {
            lease_duration_ms: i64::try_from(lease_duration_ms)
                .map_err(|_| McpConfigError::InvalidLeaseDuration)?,
            heartbeat_interval,
        })
    }

    pub const fn lease_duration_ms(self) -> i64 {
        self.lease_duration_ms
    }

    pub const fn heartbeat_interval(self) -> Duration {
        self.heartbeat_interval
    }

    pub fn lease_until(
        self,
        observed_at: TimestampMillis,
    ) -> Result<TimestampMillis, McpConfigError> {
        let value = observed_at
            .get()
            .checked_add(self.lease_duration_ms)
            .ok_or(McpConfigError::TimestampOverflow)?;
        TimestampMillis::new(value).map_err(|_| McpConfigError::TimestampOverflow)
    }
}

/// Configuration errors are local and never forwarded to MCP callers.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum McpConfigError {
    #[error("MCP lease duration must be positive")]
    InvalidLeaseDuration,
    #[error("MCP heartbeat interval must be non-zero")]
    InvalidHeartbeatInterval,
    #[error("MCP heartbeat must occur before lease expiry")]
    HeartbeatNotBeforeLeaseExpiry,
    #[error("MCP lease timestamp overflowed")]
    TimestampOverflow,
}

/// A lease observation transferred to the single-owner tracker.
#[derive(Debug, Clone)]
pub(crate) struct OwnedLeaseRegistration {
    pub(crate) scope: ResolvedWorkspaceScope,
    pub(crate) activity_id: ActivityId,
    pub(crate) lease_revision: ActivityLeaseRevision,
    pub(crate) last_observed_at: TimestampMillis,
    pub(crate) recovery_required: bool,
}

#[derive(Debug)]
pub(crate) enum LeaseTrackerMessage {
    Register {
        registration: OwnedLeaseRegistration,
        response: tokio::sync::oneshot::Sender<bool>,
    },
    Check {
        scope: ResolvedWorkspaceScope,
        activity_id: ActivityId,
        response: tokio::sync::oneshot::Sender<bool>,
    },
}

#[derive(Debug, Clone)]
struct LeaseGroup {
    scope: ResolvedWorkspaceScope,
    registrations: Vec<OwnedLeaseRegistration>,
}

#[derive(Debug, Clone, Copy)]
struct LeaseActivityUpdate {
    activity_id: ActivityId,
    lease_revision: ActivityLeaseRevision,
}

#[derive(Debug, Clone)]
struct BatchOutcome {
    committed: bool,
    activities: Vec<LeaseActivityUpdate>,
}

impl BatchOutcome {
    fn from_operation(operation: &ActivityLeaseOperation) -> Self {
        Self {
            committed: operation.is_committed() && !operation.is_committed_but_unconfirmed(),
            activities: operation
                .activities()
                .iter()
                .map(|activity| LeaseActivityUpdate {
                    activity_id: activity.id(),
                    lease_revision: activity.lease_revision(),
                })
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct BatchError(ControlErrorCode);

trait LeaseBatchExecutor: Clone + Send + Sync + 'static {
    fn renew_batch(
        &self,
        scope: ResolvedWorkspaceScope,
        commands: Vec<RenewActivityLease>,
    ) -> Result<BatchOutcome, BatchError>;

    fn close_batch(
        &self,
        scope: ResolvedWorkspaceScope,
        commands: Vec<CloseActivity>,
    ) -> Result<BatchOutcome, BatchError>;
}

impl LeaseBatchExecutor for ForgeControlClient {
    fn renew_batch(
        &self,
        scope: ResolvedWorkspaceScope,
        commands: Vec<RenewActivityLease>,
    ) -> Result<BatchOutcome, BatchError> {
        self.renew_activity_lease_batch(scope, commands)
            .map(|operation| BatchOutcome::from_operation(&operation))
            .map_err(|error| BatchError(error.code()))
    }

    fn close_batch(
        &self,
        scope: ResolvedWorkspaceScope,
        commands: Vec<CloseActivity>,
    ) -> Result<BatchOutcome, BatchError> {
        self.close_owned_activity_batch(scope, commands)
            .map(|operation| BatchOutcome::from_operation(&operation))
            .map_err(|error| BatchError(error.code()))
    }
}

/// Bounded report from process shutdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct McpShutdownReport {
    tracked_activities: usize,
    cleanup_attempted: usize,
    recovery_required: usize,
}

impl McpShutdownReport {
    pub const fn tracked_activities(self) -> usize {
        self.tracked_activities
    }

    pub const fn cleanup_attempted(self) -> usize {
        self.cleanup_attempted
    }

    pub const fn recovery_required(self) -> usize {
        self.recovery_required
    }
}

/// Errors from the owned stdio server lifecycle.
#[derive(Debug, Error)]
pub enum McpServerProcessError {
    #[error("MCP server initialization failed")]
    Initialization(#[source] Box<rmcp::service::ServerInitializeError>),
    #[error("MCP server task failed to join")]
    ServiceJoin(#[source] tokio::task::JoinError),
    #[error("MCP lease tracker task failed to join")]
    TrackerJoin(#[source] tokio::task::JoinError),
}

/// Owns one MCP service, its process-scoped runtime id, cancellation token,
/// bounded lease tracker, and all tracker task joins.
#[derive(Debug)]
pub struct McpServerProcess {
    pub(crate) service: McpServerService,
    pub(crate) cancellation: CancellationToken,
    pub(crate) tracker_rx: Option<tokio::sync::mpsc::Receiver<LeaseTrackerMessage>>,
    pub(crate) lease_policy: McpLeasePolicy,
    pub(crate) tasks: JoinSet<McpShutdownReport>,
}

impl McpServerProcess {
    /// Create one process boundary and generate a v7 runtime identity at
    /// ingress.  The generated id is only a lease owner, never Workspace
    /// authority.
    pub fn new(control: ForgeControlClient) -> Self {
        Self::with_policy(control, McpLeasePolicy::default())
    }

    pub fn with_policy(control: ForgeControlClient, lease_policy: McpLeasePolicy) -> Self {
        let runtime_instance_id = RuntimeInstanceId::from_uuid(Uuid::now_v7());
        Self::with_runtime_id(control, runtime_instance_id, lease_policy)
    }

    pub(crate) fn scoped_http(control: ForgeControlClient, lease_policy: McpLeasePolicy) -> Self {
        let runtime_instance_id = RuntimeInstanceId::from_uuid(Uuid::now_v7());
        let cancellation = CancellationToken::new();
        let (owned_sender, tracker_rx) =
            tokio::sync::mpsc::channel::<LeaseTrackerMessage>(OWNED_CHANNEL_CAPACITY);
        let service = McpServerService::new_scoped_http(
            control,
            runtime_instance_id,
            lease_policy,
            cancellation.clone(),
            owned_sender,
        );
        Self {
            service,
            cancellation,
            tracker_rx: Some(tracker_rx),
            lease_policy,
            tasks: JoinSet::new(),
        }
    }

    pub(crate) fn with_runtime_id(
        control: ForgeControlClient,
        runtime_instance_id: RuntimeInstanceId,
        lease_policy: McpLeasePolicy,
    ) -> Self {
        let cancellation = CancellationToken::new();
        let (owned_sender, tracker_rx) =
            tokio::sync::mpsc::channel::<LeaseTrackerMessage>(OWNED_CHANNEL_CAPACITY);
        let service = McpServerService::new(
            control,
            runtime_instance_id,
            lease_policy,
            cancellation.clone(),
            owned_sender,
        );
        Self {
            service,
            cancellation,
            tracker_rx: Some(tracker_rx),
            lease_policy,
            tasks: JoinSet::new(),
        }
    }

    pub const fn runtime_instance_id(&self) -> RuntimeInstanceId {
        self.service.runtime_instance_id()
    }

    pub const fn lease_policy(&self) -> McpLeasePolicy {
        self.lease_policy
    }

    pub fn cancellation_token(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    /// Run the official rmcp stdio transport until EOF, cancellation, or a
    /// transport failure.  stdout is owned exclusively by rmcp's JSON-RPC
    /// transport; this method never writes diagnostics to stdout.
    pub async fn run(self) -> Result<McpShutdownReport, McpServerProcessError> {
        let (stdin, stdout) = stdio();
        self.run_transport(BoundedMcpFrameReader::new(stdin), stdout)
            .await
    }

    /// Run the same owned server lifecycle over a bounded in-memory transport.
    ///
    /// The public production entry point remains [`Self::run`], which is
    /// stdio-only.  This bounded hook is used by the headless doctor path so
    /// doctor never consumes a caller's real stdin.
    pub async fn run_with_io<R, W>(
        self,
        read: R,
        write: W,
    ) -> Result<McpShutdownReport, McpServerProcessError>
    where
        R: AsyncRead + Send + Unpin + 'static,
        W: AsyncWrite + Send + Unpin + 'static,
    {
        self.run_transport(BoundedMcpFrameReader::new(read), write)
            .await
    }

    async fn run_transport<R, W>(
        self,
        read: R,
        write: W,
    ) -> Result<McpShutdownReport, McpServerProcessError>
    where
        R: AsyncRead + Send + Unpin + 'static,
        W: AsyncWrite + Send + Unpin + 'static,
    {
        let McpServerProcess {
            service,
            cancellation,
            tracker_rx,
            lease_policy,
            mut tasks,
        } = self;
        let Some(tracker_rx) = tracker_rx else {
            cancellation.cancel();
            return Ok(McpShutdownReport {
                tracked_activities: 0,
                cleanup_attempted: 0,
                recovery_required: 0,
            });
        };
        let tracker_token = cancellation.child_token();
        let control = service.control_client();
        let runtime_instance_id = service.runtime_instance_id();
        tasks.spawn(track_owned_leases(
            tracker_rx,
            tracker_token,
            control,
            runtime_instance_id,
            lease_policy,
            lease_policy.heartbeat_interval(),
        ));

        let running = match serve_server_with_ct(service, (read, write), cancellation.clone()).await
        {
            Ok(running) => running,
            Err(rmcp::service::ServerInitializeError::ConnectionClosed(_)) => {
                cancellation.cancel();
                return finish_tasks(tasks).await;
            }
            Err(error) => {
                cancellation.cancel();
                let _ = finish_tasks(tasks).await;
                return Err(McpServerProcessError::Initialization(Box::new(error)));
            }
        };

        let service_result = running
            .waiting()
            .await
            .map_err(McpServerProcessError::ServiceJoin);
        cancellation.cancel();
        let tracker_result = finish_tasks(tasks).await;
        service_result?;
        tracker_result
    }
}

pub(crate) async fn finish_tasks(
    mut tasks: JoinSet<McpShutdownReport>,
) -> Result<McpShutdownReport, McpServerProcessError> {
    let mut report = None;
    while let Some(result) = tasks.join_next().await {
        let task_report = result.map_err(McpServerProcessError::TrackerJoin)?;
        report = Some(task_report);
    }
    Ok(report.unwrap_or(McpShutdownReport {
        tracked_activities: 0,
        cleanup_attempted: 0,
        recovery_required: 0,
    }))
}

/// Single-owner lease tracker. It receives observations, groups them by exact
/// Workspace scope, renews each group in one control batch, and closes owned
/// Activities in one batch per scope during graceful shutdown.
pub(crate) async fn track_owned_leases(
    receiver: tokio::sync::mpsc::Receiver<LeaseTrackerMessage>,
    cancellation: CancellationToken,
    control: ForgeControlClient,
    runtime_instance_id: RuntimeInstanceId,
    lease_policy: McpLeasePolicy,
    heartbeat_interval: Duration,
) -> McpShutdownReport {
    track_owned_leases_with_executor(
        receiver,
        cancellation,
        control,
        runtime_instance_id,
        lease_policy,
        heartbeat_interval,
    )
    .await
}

async fn track_owned_leases_with_executor<E>(
    mut receiver: tokio::sync::mpsc::Receiver<LeaseTrackerMessage>,
    cancellation: CancellationToken,
    executor: E,
    runtime_instance_id: RuntimeInstanceId,
    lease_policy: McpLeasePolicy,
    heartbeat_interval: Duration,
) -> McpShutdownReport
where
    E: LeaseBatchExecutor,
{
    let mut groups: Vec<LeaseGroup> = Vec::with_capacity(MAX_OWNED_ACTIVITIES);
    let mut ticker = tokio::time::interval(heartbeat_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            biased;
            () = cancellation.cancelled() => break,
            Some(message) = receiver.recv() => {
                handle_tracker_message(&mut groups, message);
            }
            _ = ticker.tick() => {
                let observed_at = current_timestamp_millis()
                    .or_else(|| first_observation(&groups));
                if let Some(observed_at) = observed_at {
                    renew_owned_leases(
                        &mut groups,
                        &executor,
                        runtime_instance_id,
                        lease_policy,
                        observed_at,
                    )
                    .await;
                }
                tracing::debug!(owned_activities = total_activities(&groups), "MCP lease heartbeat tick");
            }
            else => break,
        }
    }
    drain_owned_registrations(&mut receiver, &mut groups);
    close_owned_leases(groups, &executor, runtime_instance_id).await
}

fn handle_tracker_message(groups: &mut Vec<LeaseGroup>, message: LeaseTrackerMessage) {
    match message {
        LeaseTrackerMessage::Register {
            registration,
            response,
        } => {
            let accepted = insert_registration(groups, registration);
            let _ignored = response.send(accepted);
        }
        LeaseTrackerMessage::Check {
            scope,
            activity_id,
            response,
        } => {
            let owned = groups.iter().any(|group| {
                group.scope == scope
                    && group.registrations.iter().any(|registration| {
                        registration.activity_id == activity_id && !registration.recovery_required
                    })
            });
            let _ignored = response.send(owned);
        }
    }
}

fn insert_registration(groups: &mut Vec<LeaseGroup>, registration: OwnedLeaseRegistration) -> bool {
    let total = total_activities(groups);
    if let Some(group) = groups
        .iter_mut()
        .find(|group| group.scope.workspace_id() == registration.scope.workspace_id())
    {
        let scope = newer_scope(&group.scope, &registration.scope);
        group.scope = scope.clone();
        for existing in &mut group.registrations {
            existing.scope = scope.clone();
        }
        let mut registration = registration;
        registration.scope = scope;
        if let Some(index) = group
            .registrations
            .iter()
            .position(|item| item.activity_id == registration.activity_id)
        {
            group.registrations[index] =
                merge_registration(&group.registrations[index], &registration);
            return true;
        }
        if total < MAX_OWNED_ACTIVITIES {
            group.registrations.push(registration);
            return true;
        }
        return false;
    }
    if total < MAX_OWNED_ACTIVITIES && workspace_group_capacity_available(groups.len()) {
        groups.push(LeaseGroup {
            scope: registration.scope.clone(),
            registrations: vec![registration],
        });
        true
    } else {
        false
    }
}

const fn workspace_group_capacity_available(current: usize) -> bool {
    current < MAX_OWNED_WORKSPACE_GROUPS
}

fn merge_registration(
    existing: &OwnedLeaseRegistration,
    incoming: &OwnedLeaseRegistration,
) -> OwnedLeaseRegistration {
    let revision_order = incoming.lease_revision.cmp(&existing.lease_revision);
    let scope = newer_scope(&existing.scope, &incoming.scope);
    OwnedLeaseRegistration {
        scope,
        activity_id: existing.activity_id,
        lease_revision: if revision_order == std::cmp::Ordering::Greater {
            incoming.lease_revision
        } else {
            existing.lease_revision
        },
        last_observed_at: if incoming.last_observed_at.get() > existing.last_observed_at.get() {
            incoming.last_observed_at
        } else {
            existing.last_observed_at
        },
        recovery_required: if revision_order == std::cmp::Ordering::Greater {
            incoming.recovery_required
        } else {
            existing.recovery_required
        },
    }
}

fn newer_scope(
    existing: &ResolvedWorkspaceScope,
    incoming: &ResolvedWorkspaceScope,
) -> ResolvedWorkspaceScope {
    let existing_key = (
        existing.workspace_revision().get(),
        existing.locator().expected_revision().get(),
    );
    let incoming_key = (
        incoming.workspace_revision().get(),
        incoming.locator().expected_revision().get(),
    );
    if incoming_key > existing_key {
        incoming.clone()
    } else {
        existing.clone()
    }
}

fn total_activities(groups: &[LeaseGroup]) -> usize {
    groups.iter().map(|group| group.registrations.len()).sum()
}

fn first_observation(groups: &[LeaseGroup]) -> Option<TimestampMillis> {
    groups
        .first()
        .and_then(|group| group.registrations.first())
        .map(|registration| registration.last_observed_at)
}

async fn renew_owned_leases<E>(
    groups: &mut [LeaseGroup],
    executor: &E,
    runtime_instance_id: RuntimeInstanceId,
    lease_policy: McpLeasePolicy,
    observed_at: TimestampMillis,
) where
    E: LeaseBatchExecutor,
{
    for group in groups {
        let active_ids: Vec<_> = group
            .registrations
            .iter()
            .filter(|registration| !registration.recovery_required)
            .map(|registration| registration.activity_id)
            .collect();
        if active_ids.is_empty() {
            continue;
        }
        let Some(lease_until) = lease_policy.lease_until(observed_at).ok() else {
            mark_recovery_required(group, &active_ids);
            continue;
        };
        let commands: Vec<_> = group
            .registrations
            .iter()
            .filter(|registration| !registration.recovery_required)
            .map(|registration| {
                RenewActivityLease::new(
                    registration.activity_id,
                    runtime_instance_id,
                    registration.lease_revision,
                    lease_until,
                    observed_at,
                )
            })
            .collect();
        let scope = group.scope.clone();
        let batch_executor = executor.clone();
        let result =
            tokio::task::spawn_blocking(move || batch_executor.renew_batch(scope, commands)).await;
        match result {
            Ok(Ok(outcome)) if outcome.committed => {
                if !apply_updates(group, &outcome.activities, &active_ids, observed_at) {
                    mark_recovery_required(group, &active_ids);
                }
            }
            Ok(Ok(_)) => {
                mark_recovery_required(group, &active_ids);
                tracing::warn!("MCP Activity lease heartbeat batch was unconfirmed");
            }
            Ok(Err(error)) => {
                mark_recovery_required(group, &active_ids);
                tracing::warn!(
                    code = error.0.as_str(),
                    "MCP Activity lease heartbeat failed"
                );
            }
            Err(_) => {
                mark_recovery_required(group, &active_ids);
                tracing::warn!("MCP Activity lease heartbeat task failed");
            }
        }
    }
}

fn drain_owned_registrations(
    receiver: &mut tokio::sync::mpsc::Receiver<LeaseTrackerMessage>,
    groups: &mut Vec<LeaseGroup>,
) {
    while let Ok(message) = receiver.try_recv() {
        match message {
            LeaseTrackerMessage::Register {
                registration,
                response,
            } => {
                insert_registration(groups, registration);
                let _ignored = response.send(false);
            }
            LeaseTrackerMessage::Check { response, .. } => {
                let _ignored = response.send(false);
            }
        }
    }
}

async fn close_owned_leases<E>(
    groups: Vec<LeaseGroup>,
    executor: &E,
    runtime_instance_id: RuntimeInstanceId,
) -> McpShutdownReport
where
    E: LeaseBatchExecutor,
{
    let tracked = total_activities(&groups);
    let mut recovery_required = 0usize;
    for mut group in groups {
        let group_size = group.registrations.len();
        let Some(observed_at) = current_timestamp_millis().or_else(|| {
            group
                .registrations
                .first()
                .map(|item| item.last_observed_at)
        }) else {
            recovery_required = recovery_required.saturating_add(group_size);
            continue;
        };
        let expected_ids: Vec<_> = group
            .registrations
            .iter()
            .map(|registration| registration.activity_id)
            .collect();
        let commands: Vec<_> = group
            .registrations
            .iter()
            .map(|registration| {
                CloseActivity::new(
                    registration.activity_id,
                    runtime_instance_id,
                    registration.lease_revision,
                    observed_at,
                )
            })
            .collect();
        let scope = group.scope.clone();
        let batch_executor = executor.clone();
        let result =
            tokio::task::spawn_blocking(move || batch_executor.close_batch(scope, commands)).await;
        match result {
            Ok(Ok(outcome)) if outcome.committed => {
                if !apply_updates(&mut group, &outcome.activities, &expected_ids, observed_at) {
                    recovery_required = recovery_required.saturating_add(group_size);
                }
            }
            Ok(Ok(_) | Err(_)) | Err(_) => {
                recovery_required = recovery_required.saturating_add(group_size);
            }
        }
    }
    McpShutdownReport {
        tracked_activities: tracked,
        cleanup_attempted: tracked,
        recovery_required,
    }
}

fn apply_updates(
    group: &mut LeaseGroup,
    updates: &[LeaseActivityUpdate],
    expected_ids: &[ActivityId],
    observed_at: TimestampMillis,
) -> bool {
    if updates.len() != expected_ids.len() {
        return false;
    }
    let mut matched = vec![false; expected_ids.len()];
    let mut mapped = Vec::with_capacity(updates.len());
    for update in updates {
        let Some(expected_index) = expected_ids
            .iter()
            .enumerate()
            .find(|(index, activity_id)| **activity_id == update.activity_id && !matched[*index])
            .map(|(index, _)| index)
        else {
            return false;
        };
        let Some(registration_index) = group
            .registrations
            .iter()
            .position(|registration| registration.activity_id == update.activity_id)
        else {
            return false;
        };
        matched[expected_index] = true;
        mapped.push((registration_index, update.lease_revision));
    }
    if !matched.into_iter().all(|value| value) {
        return false;
    }
    for (index, lease_revision) in mapped {
        group.registrations[index].lease_revision = lease_revision;
        group.registrations[index].last_observed_at = observed_at;
        group.registrations[index].recovery_required = false;
    }
    true
}

fn mark_recovery_required(group: &mut LeaseGroup, activity_ids: &[ActivityId]) {
    for registration in &mut group.registrations {
        if activity_ids.contains(&registration.activity_id) {
            registration.recovery_required = true;
        }
    }
}

pub(crate) fn current_timestamp_millis() -> Option<TimestampMillis> {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?;
    let millis = i64::try_from(duration.as_millis()).ok()?;
    TimestampMillis::new(millis).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use forge_control::{ForgeControl, ForgeControlWorker};
    use forge_domain::{
        EstablishWorkspace, LocationId, LocationRevision, WorkspaceId, WorkspaceRoot,
    };
    use forge_persistence::{GlobalRegistry, WorkspaceStore};
    use forge_workspace::{LocationService, WorkspaceLocator, WorkspaceStateLayout};
    use uuid::Uuid;

    #[derive(Debug, Clone, Default)]
    struct CountingExecutor {
        renew_calls: Arc<AtomicUsize>,
        renew_commands: Arc<AtomicUsize>,
        close_calls: Arc<AtomicUsize>,
        close_commands: Arc<AtomicUsize>,
    }

    type ScopePairFixture = (
        std::path::PathBuf,
        ResolvedWorkspaceScope,
        ResolvedWorkspaceScope,
        ForgeControlClient,
        ForgeControlWorker,
    );

    impl LeaseBatchExecutor for CountingExecutor {
        fn renew_batch(
            &self,
            _scope: ResolvedWorkspaceScope,
            commands: Vec<RenewActivityLease>,
        ) -> Result<BatchOutcome, BatchError> {
            self.renew_calls.fetch_add(1, Ordering::Relaxed);
            self.renew_commands
                .fetch_add(commands.len(), Ordering::Relaxed);
            let mut activities = Vec::with_capacity(commands.len());
            for command in commands {
                activities.push(LeaseActivityUpdate {
                    activity_id: command.id(),
                    lease_revision: command
                        .expected_lease_revision()
                        .checked_next()
                        .map_err(|_| BatchError(ControlErrorCode::Internal))?,
                });
            }
            Ok(BatchOutcome {
                committed: true,
                activities,
            })
        }

        fn close_batch(
            &self,
            _scope: ResolvedWorkspaceScope,
            commands: Vec<CloseActivity>,
        ) -> Result<BatchOutcome, BatchError> {
            self.close_calls.fetch_add(1, Ordering::Relaxed);
            self.close_commands
                .fetch_add(commands.len(), Ordering::Relaxed);
            Ok(BatchOutcome {
                committed: true,
                activities: commands
                    .into_iter()
                    .map(|command| LeaseActivityUpdate {
                        activity_id: command.id(),
                        lease_revision: command.expected_lease_revision(),
                    })
                    .collect(),
            })
        }
    }

    #[derive(Debug, Clone, Copy)]
    struct RejectingExecutor;

    impl LeaseBatchExecutor for RejectingExecutor {
        fn renew_batch(
            &self,
            _scope: ResolvedWorkspaceScope,
            _commands: Vec<RenewActivityLease>,
        ) -> Result<BatchOutcome, BatchError> {
            Err(BatchError(ControlErrorCode::ActivityLeaseConflict))
        }

        fn close_batch(
            &self,
            _scope: ResolvedWorkspaceScope,
            _commands: Vec<CloseActivity>,
        ) -> Result<BatchOutcome, BatchError> {
            Err(BatchError(ControlErrorCode::ActivityLeaseConflict))
        }
    }

    #[test]
    fn policy_rejects_heartbeat_after_expiry() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            McpLeasePolicy::new(100, Duration::from_millis(100)),
            Err(McpConfigError::HeartbeatNotBeforeLeaseExpiry)
        );
        let policy = McpLeasePolicy::new(100, Duration::from_millis(50))?;
        let observed_at = TimestampMillis::new(20)?;
        let expected_until = TimestampMillis::new(120)?;
        assert_eq!(policy.lease_until(observed_at), Ok(expected_until));
        assert!(workspace_group_capacity_available(1));
        assert!(!workspace_group_capacity_available(2));
        Ok(())
    }

    fn scope_pair_fixture() -> Result<ScopePairFixture, Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "heterarchy-forge-mcp-batch-{}-{}",
            std::process::id(),
            Uuid::now_v7()
        ));
        let location_root = root.join("location");
        let first_root = location_root.join("workspace-a");
        let second_root = location_root.join("workspace-b");
        let registry_path = root.join("registry.sqlite3");
        fs::create_dir_all(&first_root)?;
        fs::create_dir_all(&second_root)?;
        let location_id = LocationId::from_uuid(Uuid::from_u128(20));
        let mut locations = LocationService::new(GlobalRegistry::open(&registry_path)?);
        locations.register_selected_path(
            location_id,
            "MCP batch Location",
            &location_root,
            TimestampMillis::new(1)?,
        )?;
        for (workspace_root, workspace_id) in [
            (&first_root, WorkspaceId::from_uuid(Uuid::from_u128(21))),
            (&second_root, WorkspaceId::from_uuid(Uuid::from_u128(22))),
        ] {
            let layout = WorkspaceStateLayout::initialize(workspace_root)?;
            let root_identity =
                WorkspaceRoot::from_canonical(layout.workspace_root().to_path_buf())?;
            let command = EstablishWorkspace::new(
                workspace_id,
                location_id,
                root_identity,
                layout.root_fingerprint()?,
                TimestampMillis::new(2)?,
            );
            let store = WorkspaceStore::open(&layout, &command)?;
            drop(store);
        }
        drop(locations);
        let (client, worker) =
            ForgeControlWorker::start(ForgeControl::new(GlobalRegistry::open(&registry_path)?))?;
        let first_scope = client.resolve_workspace(
            location_id,
            LocationRevision::INITIAL,
            WorkspaceLocator::new(location_id, LocationRevision::INITIAL, "workspace-a")?,
        )?;
        let second_scope = client.resolve_workspace(
            location_id,
            LocationRevision::INITIAL,
            WorkspaceLocator::new(location_id, LocationRevision::INITIAL, "workspace-b")?,
        )?;
        Ok((root, first_scope, second_scope, client, worker))
    }

    fn registration(
        scope: &ResolvedWorkspaceScope,
        activity_number: u128,
        observed_at: TimestampMillis,
    ) -> OwnedLeaseRegistration {
        OwnedLeaseRegistration {
            scope: scope.clone(),
            activity_id: ActivityId::from_uuid(Uuid::from_u128(activity_number)),
            lease_revision: ActivityLeaseRevision::INITIAL,
            last_observed_at: observed_at,
            recovery_required: false,
        }
    }

    async fn saturated_scope_groups(
        scope: &ResolvedWorkspaceScope,
        observed_at: TimestampMillis,
    ) -> Result<Vec<LeaseGroup>, Box<dyn std::error::Error>> {
        let mut groups = Vec::new();
        for number in 0..MAX_OWNED_ACTIVITIES {
            assert!(insert_registration(
                &mut groups,
                registration(scope, 100 + number as u128, observed_at),
            ));
        }
        let (response, receiver) = tokio::sync::oneshot::channel();
        handle_tracker_message(
            &mut groups,
            LeaseTrackerMessage::Register {
                registration: registration(scope, 100 + MAX_OWNED_ACTIVITIES as u128, observed_at),
                response,
            },
        );
        assert!(!receiver.await?);
        assert_eq!(total_activities(&groups), MAX_OWNED_ACTIVITIES);
        Ok(groups)
    }

    async fn assert_delayed_rebound_move(
        first_scope: &ResolvedWorkspaceScope,
        rebound_scope: &ResolvedWorkspaceScope,
        activity_number: u128,
        observed_at: TimestampMillis,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut groups = vec![LeaseGroup {
            scope: first_scope.clone(),
            registrations: vec![registration(first_scope, activity_number, observed_at)],
        }];
        renew_owned_leases(
            &mut groups,
            &CountingExecutor::default(),
            RuntimeInstanceId::from_uuid(Uuid::from_u128(30)),
            McpLeasePolicy::new(60_000, Duration::from_secs(10))?,
            observed_at,
        )
        .await;
        let advanced_revision = groups[0].registrations[0].lease_revision;
        assert!(insert_registration(
            &mut groups,
            registration(rebound_scope, activity_number, observed_at),
        ));
        assert_eq!(groups[0].scope, *rebound_scope);
        assert_eq!(groups[0].registrations[0].lease_revision, advanced_revision);
        Ok(())
    }

    fn assert_full_capacity_rebound_move(
        first_scope: &ResolvedWorkspaceScope,
        rebound_scope: &ResolvedWorkspaceScope,
        other_scope: &ResolvedWorkspaceScope,
        activity_number: u128,
        observed_at: TimestampMillis,
    ) {
        let mut groups = Vec::new();
        assert!(insert_registration(
            &mut groups,
            registration(first_scope, activity_number, observed_at),
        ));
        assert!(insert_registration(
            &mut groups,
            registration(other_scope, 0xBEEF, observed_at),
        ));
        for offset in 0_u128..126 {
            assert!(insert_registration(
                &mut groups,
                registration(first_scope, 0x1000 + offset, observed_at),
            ));
        }
        assert_eq!(total_activities(&groups), MAX_OWNED_ACTIVITIES);
        assert!(insert_registration(
            &mut groups,
            registration(rebound_scope, activity_number, observed_at),
        ));
        assert_eq!(total_activities(&groups), MAX_OWNED_ACTIVITIES);
        let expected_id = ActivityId::from_uuid(Uuid::from_u128(activity_number));
        assert_eq!(
            groups
                .iter()
                .flat_map(|group| &group.registrations)
                .filter(|registration| registration.activity_id == expected_id)
                .count(),
            1
        );
        assert!(groups.iter().any(|group| {
            group.scope == *rebound_scope
                && group
                    .registrations
                    .iter()
                    .any(|registration| registration.activity_id == expected_id)
        }));
    }

    #[tokio::test]
    async fn batch_tracker_groups_same_scope_and_isolates_workspaces()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, first_scope, second_scope, client, mut worker) = scope_pair_fixture()?;
        let observed_at = TimestampMillis::new(1_000)?;
        let policy = McpLeasePolicy::new(60_000, Duration::from_secs(10))?;
        let mut same_scope_groups = saturated_scope_groups(&first_scope, observed_at).await?;

        let executor = CountingExecutor::default();
        renew_owned_leases(
            &mut same_scope_groups,
            &executor,
            RuntimeInstanceId::from_uuid(Uuid::from_u128(30)),
            policy,
            observed_at,
        )
        .await;
        assert_eq!(executor.renew_calls.load(Ordering::Relaxed), 1);
        assert_eq!(
            executor.renew_commands.load(Ordering::Relaxed),
            MAX_OWNED_ACTIVITIES
        );
        assert!(
            same_scope_groups[0]
                .registrations
                .iter()
                .all(|registration| registration.lease_revision != ActivityLeaseRevision::INITIAL)
        );
        let renewed_revision = same_scope_groups[0].registrations[0].lease_revision;
        assert!(insert_registration(
            &mut same_scope_groups,
            registration(&first_scope, 100, observed_at),
        ));
        assert_eq!(
            same_scope_groups[0].registrations[0].lease_revision,
            renewed_revision
        );

        let mut failed_group = same_scope_groups.clone();
        renew_owned_leases(
            &mut failed_group,
            &RejectingExecutor,
            RuntimeInstanceId::from_uuid(Uuid::from_u128(30)),
            policy,
            observed_at,
        )
        .await;
        assert!(
            failed_group[0]
                .registrations
                .iter()
                .all(|registration| registration.recovery_required)
        );
        let failed_report = close_owned_leases(
            failed_group,
            &RejectingExecutor,
            RuntimeInstanceId::from_uuid(Uuid::from_u128(30)),
        )
        .await;
        assert_eq!(failed_report.recovery_required(), MAX_OWNED_ACTIVITIES);

        let mut cross_scope_groups = Vec::new();
        for number in 0_u128..64 {
            assert!(insert_registration(
                &mut cross_scope_groups,
                registration(&first_scope, 1_000 + number, observed_at),
            ));
            assert!(insert_registration(
                &mut cross_scope_groups,
                registration(&second_scope, 2_000 + number, observed_at),
            ));
        }
        let cross_executor = CountingExecutor::default();
        renew_owned_leases(
            &mut cross_scope_groups,
            &cross_executor,
            RuntimeInstanceId::from_uuid(Uuid::from_u128(31)),
            policy,
            observed_at,
        )
        .await;
        assert_eq!(cross_scope_groups.len(), 2);
        assert_eq!(cross_executor.renew_calls.load(Ordering::Relaxed), 2);
        assert_eq!(cross_executor.renew_commands.load(Ordering::Relaxed), 128);

        let report = close_owned_leases(
            cross_scope_groups,
            &cross_executor,
            RuntimeInstanceId::from_uuid(Uuid::from_u128(31)),
        )
        .await;
        assert_eq!(report.tracked_activities(), 128);
        assert_eq!(report.cleanup_attempted(), 128);
        assert_eq!(report.recovery_required(), 0);
        assert!(report.recovery_required() <= report.tracked_activities());
        assert_eq!(cross_executor.close_calls.load(Ordering::Relaxed), 2);
        assert_eq!(cross_executor.close_commands.load(Ordering::Relaxed), 128);
        worker.shutdown()?;
        fs::remove_dir_all(root)?;
        drop(client);
        Ok(())
    }

    #[tokio::test]
    async fn tracker_moves_same_workspace_activity_to_fresh_rebound_scope()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, first_scope, second_scope, client, mut worker) = scope_pair_fixture()?;
        let original = root.join("location/workspace-a");
        let moved = root.join("location/workspace-a-moved");
        fs::rename(&original, &moved)?;
        let layout = WorkspaceStateLayout::initialize(&moved)?;
        let rebound_command = EstablishWorkspace::new(
            first_scope.workspace_id(),
            first_scope.locator().location_id(),
            WorkspaceRoot::from_canonical(layout.workspace_root().to_path_buf())?,
            layout.root_fingerprint()?,
            TimestampMillis::new(10)?,
        );
        let store = WorkspaceStore::open(&layout, &rebound_command)?;
        assert_eq!(store.workspace()?.revision().get(), 2);
        drop(store);
        let rebound_scope = client.resolve_workspace(
            first_scope.locator().location_id(),
            LocationRevision::INITIAL,
            WorkspaceLocator::new(
                first_scope.locator().location_id(),
                LocationRevision::INITIAL,
                "workspace-a-moved",
            )?,
        )?;
        let observed_at = TimestampMillis::new(1_000)?;
        let activity_number = 0xDEAD;
        let mut groups = Vec::new();
        assert!(insert_registration(
            &mut groups,
            registration(&first_scope, activity_number, observed_at),
        ));
        assert!(insert_registration(
            &mut groups,
            registration(&rebound_scope, activity_number, observed_at),
        ));
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].scope, rebound_scope);
        assert_eq!(total_activities(&groups), 1);

        let executor = CountingExecutor::default();
        renew_owned_leases(
            &mut groups,
            &executor,
            RuntimeInstanceId::from_uuid(Uuid::from_u128(30)),
            McpLeasePolicy::new(60_000, Duration::from_secs(10))?,
            observed_at,
        )
        .await;
        assert_eq!(executor.renew_calls.load(Ordering::Relaxed), 1);
        assert!(!groups[0].registrations[0].recovery_required);
        let current_revision = groups[0].registrations[0].lease_revision;
        assert!(insert_registration(
            &mut groups,
            registration(&first_scope, activity_number, observed_at),
        ));
        assert_eq!(groups[0].scope, rebound_scope);
        assert_eq!(groups[0].registrations[0].lease_revision, current_revision);

        assert_delayed_rebound_move(&first_scope, &rebound_scope, activity_number, observed_at)
            .await?;
        assert_full_capacity_rebound_move(
            &first_scope,
            &rebound_scope,
            &second_scope,
            activity_number,
            observed_at,
        );
        worker.shutdown()?;
        drop(client);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[tokio::test]
    async fn fresh_registration_is_not_contaminated_by_old_recovery_in_same_scope()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, scope, _other, client, mut worker) = scope_pair_fixture()?;
        let observed_at = TimestampMillis::new(1_000)?;
        let mut groups = Vec::new();
        let old_id = 0xA001;
        let fresh_id = 0xA002;
        assert!(insert_registration(
            &mut groups,
            registration(&scope, old_id, observed_at),
        ));
        groups[0].registrations[0].recovery_required = true;
        assert!(insert_registration(
            &mut groups,
            registration(&scope, old_id, TimestampMillis::new(1_001)?),
        ));
        assert!(groups[0].registrations[0].recovery_required);
        assert!(insert_registration(
            &mut groups,
            registration(&scope, fresh_id, observed_at),
        ));
        let (fresh_response, fresh_receiver) = tokio::sync::oneshot::channel();
        handle_tracker_message(
            &mut groups,
            LeaseTrackerMessage::Check {
                scope: scope.clone(),
                activity_id: ActivityId::from_uuid(Uuid::from_u128(fresh_id)),
                response: fresh_response,
            },
        );
        assert!(fresh_receiver.await?);
        let (old_response, old_receiver) = tokio::sync::oneshot::channel();
        handle_tracker_message(
            &mut groups,
            LeaseTrackerMessage::Check {
                scope,
                activity_id: ActivityId::from_uuid(Uuid::from_u128(old_id)),
                response: old_response,
            },
        );
        assert!(!old_receiver.await?);
        worker.shutdown()?;
        drop(client);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[tokio::test]
    async fn tracker_is_owned_bounded_and_closes_leases_on_shutdown()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "heterarchy-forge-mcp-tracker-{}-{}",
            std::process::id(),
            Uuid::now_v7()
        ));
        let location_root = root.join("location");
        let workspace_root = location_root.join("workspace");
        let registry_path = root.join("registry.sqlite3");
        fs::create_dir_all(&workspace_root)?;
        let location_id = LocationId::from_uuid(Uuid::from_u128(9));
        let activity_id = ActivityId::from_uuid(Uuid::from_u128(10));
        let runtime_instance_id = RuntimeInstanceId::from_uuid(Uuid::from_u128(11));
        let mut locations = LocationService::new(GlobalRegistry::open(&registry_path)?);
        locations.register_selected_path(
            location_id,
            "MCP test Location",
            &location_root,
            TimestampMillis::new(1)?,
        )?;
        let layout = WorkspaceStateLayout::initialize(&workspace_root)?;
        let workspace_root = WorkspaceRoot::from_canonical(layout.workspace_root().to_path_buf())?;
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(12));
        let command = EstablishWorkspace::new(
            workspace_id,
            location_id,
            workspace_root,
            layout.root_fingerprint()?,
            TimestampMillis::new(2)?,
        );
        let store = WorkspaceStore::open(&layout, &command)?;
        drop(store);
        drop(locations);

        let (client, mut worker) =
            ForgeControlWorker::start(ForgeControl::new(GlobalRegistry::open(&registry_path)?))?;
        let locator = WorkspaceLocator::new(location_id, LocationRevision::INITIAL, "workspace")?;
        let scope = client.resolve_workspace(location_id, LocationRevision::INITIAL, locator)?;
        let observed_at = current_timestamp_millis().ok_or("clock before Unix epoch")?;
        let lease_policy = McpLeasePolicy::new(60_000, Duration::from_secs(10))?;
        let bootstrap = client.bootstrap_activity(
            scope.clone(),
            activity_id,
            runtime_instance_id,
            observed_at,
            lease_policy.lease_until(observed_at)?,
        )?;
        let activity = bootstrap.activity().ok_or("bootstrap missing Activity")?;

        let (sender, receiver) = tokio::sync::mpsc::channel(2);
        let cancellation = CancellationToken::new();
        let registration = OwnedLeaseRegistration {
            scope,
            activity_id,
            lease_revision: activity.lease_revision(),
            last_observed_at: observed_at,
            recovery_required: false,
        };
        for registration in [registration.clone(), registration] {
            let (response, _receiver) = tokio::sync::oneshot::channel();
            sender
                .send(LeaseTrackerMessage::Register {
                    registration,
                    response,
                })
                .await?;
        }
        let task = tokio::spawn(track_owned_leases(
            receiver,
            cancellation.clone(),
            client,
            runtime_instance_id,
            lease_policy,
            Duration::from_mins(1),
        ));
        tokio::task::yield_now().await;
        cancellation.cancel();
        let report = task.await?;
        assert_eq!(report.tracked_activities(), 1);
        assert_eq!(report.cleanup_attempted(), 1);
        assert_eq!(report.recovery_required(), 0);
        assert!(report.recovery_required() <= report.tracked_activities());
        worker.shutdown()?;
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
