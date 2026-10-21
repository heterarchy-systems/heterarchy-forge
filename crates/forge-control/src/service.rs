use std::fmt;

use forge_domain::{
    ActivityCoordinatorActor, ActivityId, ActivityLeaseBatchLimit, ActivityLeaseProjection,
    ActivityLeaseRevision, ActivityListLimit, ActivityProjection,
    BootstrapActivity as BootstrapActivityCommand, BootstrapActivityDecision, CloseActivity,
    GoalId, LocationId, LocationListLimit, LocationRevision, ReconcileExpiredActivities,
    RegisteredActivity, RegisteredLocation, ReleaseActivityLease, RenewActivityLease,
    RuntimeInstanceId, SetLocationState, TimestampMillis, WorkspaceId, WorkspaceRevision,
};
use forge_persistence::{GlobalRegistry, WorkspaceStore, WorkspaceStoreError};
use forge_workspace::{
    ExistingWorkspaceStateLayout, LocationRepositoryError, LocationService, LocationServiceError,
    WorkspaceCandidateKey, WorkspaceCandidateKind, WorkspaceDiscoveryDisposition,
    WorkspaceDiscoveryObservation, WorkspaceDiscoveryReason, WorkspaceLocator, WorkspaceSignals,
    WorkspaceStateLayout,
};

use crate::error::{ControlError, ControlErrorCode};

/// Maximum number of catalog entries emitted by one control request.
pub const MAX_WORKSPACE_CATALOG_ENTRIES: usize = 256;

/// Maximum Activity projections/reconciliation rows emitted by one request.
pub const MAX_ACTIVITY_PROJECTION_RESULTS: usize = 256;

/// Maximum commands accepted by one atomic lease/lifecycle batch.
pub const MAX_ACTIVITY_LEASE_BATCH: usize = 256;
/// Maximum Activity identities accepted by one exact durable lease observation.
pub const MAX_ACTIVITY_LEASE_OBSERVATION_IDS: usize = 128;

/// Typed request to register one exact root path as a Location identity.
///
/// The selected path is validated and canonicalized by the Location service;
/// only the canonical root is durably registered.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterLocationRequest {
    pub id: LocationId,
    pub name: String,
    pub selected_path: std::path::PathBuf,
    pub observed_at: TimestampMillis,
}

/// Bounded remote-safe durable Workspace catalog entry.
///
/// `workspace_list` emits only registered durable Workspace identities. Filesystem
/// discovery state is deliberately absent from this projection.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceCatalogEntry {
    locator: WorkspaceLocator,
    display_name: String,
    workspace_id: WorkspaceId,
    workspace_revision: WorkspaceRevision,
}

impl WorkspaceCatalogEntry {
    fn from_registered(
        location_id: LocationId,
        expected_revision: LocationRevision,
        display_name: String,
        workspace_id: WorkspaceId,
        workspace_revision: WorkspaceRevision,
    ) -> Result<Self, ControlError> {
        let locator = WorkspaceCandidateKey::location_root(location_id)
            .locator(expected_revision)
            .map_err(|source| ControlError::with_source(ControlErrorCode::InvalidInput, source))?;
        Ok(Self {
            locator,
            display_name,
            workspace_id,
            workspace_revision,
        })
    }

    pub const fn locator(&self) -> &WorkspaceLocator {
        &self.locator
    }

    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn workspace_revision(&self) -> WorkspaceRevision {
        self.workspace_revision
    }
}

/// Bounded read-only filesystem observation returned by `workspace_discover`.
/// This projection is correlation/evidence only and never grants registration
/// or effect authority.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceDiscoveryEntry {
    locator: WorkspaceLocator,
    kind: WorkspaceCandidateKind,
    display_name: String,
    signals: WorkspaceSignals,
    disposition: WorkspaceDiscoveryDisposition,
    reason: WorkspaceDiscoveryReason,
}

impl WorkspaceDiscoveryEntry {
    fn from_observation(
        observation: &WorkspaceDiscoveryObservation,
        expected_revision: LocationRevision,
    ) -> Result<Self, ControlError> {
        let locator = observation
            .key()
            .locator(expected_revision)
            .map_err(|source| ControlError::with_source(ControlErrorCode::InvalidInput, source))?;
        Ok(Self {
            locator,
            kind: observation.kind(),
            display_name: observation.display_label().into_owned(),
            signals: observation.signals(),
            disposition: observation.disposition(),
            reason: observation.reason(),
        })
    }

    pub const fn locator(&self) -> &WorkspaceLocator {
        &self.locator
    }

    pub const fn kind(&self) -> WorkspaceCandidateKind {
        self.kind
    }

    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    pub const fn signals(&self) -> WorkspaceSignals {
        self.signals
    }

    pub const fn disposition(&self) -> WorkspaceDiscoveryDisposition {
        self.disposition
    }

    pub const fn reason(&self) -> WorkspaceDiscoveryReason {
        self.reason
    }
}

/// A durable Workspace authority identity bound to a fresh relative locator.
///
/// This is a scope token, not an effect capability.  Filesystem/process/
/// network effects must still perform their own capability checks.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedWorkspaceScope {
    workspace_id: WorkspaceId,
    workspace_revision: WorkspaceRevision,
    locator: WorkspaceLocator,
}

/// Exact Goal and Coordinator preconditions for a host-supervised Activity
/// lease renewal. Persistence rechecks all fields in the lease CAS transaction.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupervisedActivityLeaseRenewRequest {
    pub scope: ResolvedWorkspaceScope,
    pub actor: ActivityCoordinatorActor,
    pub goal_id: GoalId,
    pub goal_created_at: TimestampMillis,
    pub command: RenewActivityLease,
}

/// Bounded, transport/UI-neutral projection returned by the desktop refresh
/// action.  The explicit scope is carried alongside the caller-time Activity
/// projections so a stale UI refresh cannot be mistaken for another Workspace.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceActivityProjection {
    scope: ResolvedWorkspaceScope,
    activities: Vec<ActivityProjection>,
}

/// Explicit desktop refresh request.  Keeping the full identity tuple in one
/// value avoids stringly-typed/argument-order mistakes at UI call sites.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceActivityProjectionRequest {
    pub location_id: LocationId,
    pub expected_location_revision: LocationRevision,
    pub locator: WorkspaceLocator,
    pub expected_workspace_id: WorkspaceId,
    pub expected_workspace_revision: WorkspaceRevision,
    pub now: TimestampMillis,
    pub limit: ActivityListLimit,
}

impl WorkspaceActivityProjection {
    fn new(scope: ResolvedWorkspaceScope, activities: Vec<ActivityProjection>) -> Self {
        Self { scope, activities }
    }

    pub const fn scope(&self) -> &ResolvedWorkspaceScope {
        &self.scope
    }

    pub fn activities(&self) -> &[ActivityProjection] {
        &self.activities
    }
}

impl ResolvedWorkspaceScope {
    /// Rebuild a previously committed scope observation for a fresh control
    /// request. This value remains correlation data, not an effect capability;
    /// every control operation re-resolves and revalidates it.
    pub const fn from_observation(
        workspace_id: WorkspaceId,
        workspace_revision: WorkspaceRevision,
        locator: WorkspaceLocator,
    ) -> Self {
        Self {
            workspace_id,
            workspace_revision,
            locator,
        }
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn workspace_revision(&self) -> WorkspaceRevision {
        self.workspace_revision
    }

    pub const fn revision(&self) -> WorkspaceRevision {
        self.workspace_revision()
    }

    pub const fn locator(&self) -> &WorkspaceLocator {
        &self.locator
    }
}

/// Result status for durable Activity bootstrap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActivityBootstrapStatus {
    Created,
    Resumed,
    ExpiredRecoveryRequired,
    UnleasedRecoveryRequired,
    AlreadyOwned,
    AlreadyLive,
    Terminal,
    /// `SQLite` committed the request but a fresh post-commit filesystem or
    /// Location revalidation could not confirm the resulting projection.
    CommittedButUnconfirmed,
}

impl ActivityBootstrapStatus {
    pub const fn is_committed(self) -> bool {
        matches!(
            self,
            Self::Created | Self::Resumed | Self::AlreadyOwned | Self::CommittedButUnconfirmed
        )
    }

    pub const fn requires_recovery(self) -> bool {
        matches!(self, Self::CommittedButUnconfirmed)
    }
}

/// Result status for one durable Activity lease/lifecycle operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActivityOperationStatus {
    Renewed,
    Closed,
    Released,
    AlreadyTerminal,
    Reconciled,
    /// The transaction committed, but fresh scope revalidation could not
    /// confirm the resulting projection.
    CommittedButUnconfirmed,
}

impl ActivityOperationStatus {
    pub const fn is_committed(self) -> bool {
        matches!(
            self,
            Self::Renewed
                | Self::Closed
                | Self::Released
                | Self::AlreadyTerminal
                | Self::Reconciled
                | Self::CommittedButUnconfirmed
        )
    }

    pub const fn is_committed_but_unconfirmed(self) -> bool {
        matches!(self, Self::CommittedButUnconfirmed)
    }
}

/// Remote/UI-neutral result shared by lease, close, release, and reconcile
/// operations.  The vectors are bounded by the caller-facing service.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivityOperation {
    scope: ResolvedWorkspaceScope,
    activity: Option<RegisteredActivity>,
    activities: Vec<RegisteredActivity>,
    status: ActivityOperationStatus,
}

impl ActivityOperation {
    fn batch(
        scope: ResolvedWorkspaceScope,
        activities: Vec<RegisteredActivity>,
        status: ActivityOperationStatus,
    ) -> Self {
        Self {
            scope,
            activity: None,
            activities,
            status,
        }
    }

    fn uncertain(
        scope: ResolvedWorkspaceScope,
        activity: Option<RegisteredActivity>,
        activities: Vec<RegisteredActivity>,
    ) -> Self {
        Self {
            scope,
            activity,
            activities,
            status: ActivityOperationStatus::CommittedButUnconfirmed,
        }
    }

    fn into_single(mut self, status: ActivityOperationStatus) -> Result<Self, ControlError> {
        if self.activities.len() > 1 || self.activity.is_some() {
            return Err(ControlError::new(ControlErrorCode::Internal));
        }
        if self.is_committed_but_unconfirmed() {
            self.activity = self.activities.pop();
            return Ok(self);
        }
        if self.activities.len() != 1 {
            return Err(ControlError::new(ControlErrorCode::Internal));
        }
        self.activity = self.activities.pop();
        self.status = status;
        Ok(self)
    }

    pub const fn scope(&self) -> &ResolvedWorkspaceScope {
        &self.scope
    }

    pub const fn activity(&self) -> Option<&RegisteredActivity> {
        self.activity.as_ref()
    }

    pub fn lease(&self) -> Option<&ActivityLeaseProjection> {
        self.activity.as_ref().map(RegisteredActivity::lease)
    }

    pub fn activities(&self) -> &[RegisteredActivity] {
        &self.activities
    }

    pub const fn status(&self) -> ActivityOperationStatus {
        self.status
    }

    pub const fn is_committed(&self) -> bool {
        self.status.is_committed()
    }

    pub const fn is_committed_but_unconfirmed(&self) -> bool {
        self.status.is_committed_but_unconfirmed()
    }
}

/// Typed lease operation alias used by adapters that prefer lease terminology.
pub type ActivityLeaseOperation = ActivityOperation;

/// Typed reconcile result alias used by supervisor adapters.
pub type ActivityReconcileResult = ActivityOperation;

/// Caller-supplied lease ownership evidence used for graceful shutdown.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedActivityLease {
    scope: ResolvedWorkspaceScope,
    activity_id: ActivityId,
    runtime_instance_id: RuntimeInstanceId,
    expected_lease_revision: ActivityLeaseRevision,
    observed_at: TimestampMillis,
}

impl OwnedActivityLease {
    pub const fn new(
        scope: ResolvedWorkspaceScope,
        activity_id: ActivityId,
        runtime_instance_id: RuntimeInstanceId,
        expected_lease_revision: ActivityLeaseRevision,
        observed_at: TimestampMillis,
    ) -> Self {
        Self {
            scope,
            activity_id,
            runtime_instance_id,
            expected_lease_revision,
            observed_at,
        }
    }

    pub const fn scope(&self) -> &ResolvedWorkspaceScope {
        &self.scope
    }

    pub const fn activity_id(&self) -> ActivityId {
        self.activity_id
    }

    pub const fn runtime_instance_id(&self) -> RuntimeInstanceId {
        self.runtime_instance_id
    }

    pub const fn expected_lease_revision(&self) -> ActivityLeaseRevision {
        self.expected_lease_revision
    }

    pub const fn observed_at(&self) -> TimestampMillis {
        self.observed_at
    }
}

/// Remote/UI-neutral result of bootstrapping one Activity lease.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivityBootstrap {
    scope: ResolvedWorkspaceScope,
    activity: Option<RegisteredActivity>,
    status: ActivityBootstrapStatus,
}

impl ActivityBootstrap {
    fn new(
        scope: ResolvedWorkspaceScope,
        activity: Option<RegisteredActivity>,
        status: ActivityBootstrapStatus,
    ) -> Self {
        Self {
            scope,
            activity,
            status,
        }
    }

    pub const fn scope(&self) -> &ResolvedWorkspaceScope {
        &self.scope
    }

    pub const fn activity(&self) -> Option<&RegisteredActivity> {
        self.activity.as_ref()
    }

    pub fn lease(&self) -> Option<&ActivityLeaseProjection> {
        self.activity.as_ref().map(RegisteredActivity::lease)
    }

    /// Derive caller-time liveness without reading a clock or mutating the
    /// durable row.
    pub fn projection(
        &self,
        observed_at: TimestampMillis,
    ) -> Option<forge_domain::ActivityProjection> {
        self.activity
            .clone()
            .map(|activity| forge_domain::ActivityProjection::from_activity(activity, observed_at))
    }

    pub const fn status(&self) -> ActivityBootstrapStatus {
        self.status
    }

    pub const fn is_committed(&self) -> bool {
        self.status.is_committed()
    }

    pub const fn is_committed_but_unconfirmed(&self) -> bool {
        self.status.requires_recovery()
    }
}

/// Synchronous application service used by desktop-era and HTTP adapters.
///
/// `LocationService<GlobalRegistry>` is the sole owner of the global
/// repository handle.  Workspace stores are opened for one operation and are
/// never retained as a process-global active Workspace.
pub struct ForgeControl {
    pub(crate) locations: LocationService<GlobalRegistry>,
    pub(crate) session_authority: Box<dyn crate::AgentSessionAuthority>,
}

impl fmt::Debug for ForgeControl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ForgeControl")
            .field("locations", &self.locations)
            .field("session_authority", &"<injected>")
            .finish()
    }
}

impl ForgeControl {
    pub fn new(registry: GlobalRegistry) -> Self {
        let session_catalog_path = registry
            .database_path()
            .with_file_name("agent-sessions.sqlite3");
        Self::from_location_service(LocationService::new(registry), session_catalog_path)
    }

    /// Construct the control service around an already-owned Location
    /// application service without exposing its repository escape hatches.
    pub fn from_location_service(
        locations: LocationService<GlobalRegistry>,
        session_catalog_path: std::path::PathBuf,
    ) -> Self {
        Self {
            locations,
            session_authority: crate::agent_session::local_session_authority(session_catalog_path),
        }
    }

    /// Alias for adapters that name this boundary explicitly.
    pub fn with_location_service(
        locations: LocationService<GlobalRegistry>,
        session_catalog_path: std::path::PathBuf,
    ) -> Self {
        Self::from_location_service(locations, session_catalog_path)
    }

    /// Compose control around an explicit logical Agent session authority.
    ///
    /// The injected authority is used directly. Its errors are returned to
    /// callers and never fall back to the legacy Forge `SQLite` catalog.
    pub fn with_session_authority(
        locations: LocationService<GlobalRegistry>,
        authority: Box<dyn crate::AgentSessionAuthority>,
    ) -> Self {
        Self {
            locations,
            session_authority: authority,
        }
    }

    /// List the bounded registered Location identities needed to begin a
    /// remote-safe Workspace discovery sequence. Native roots remain private.
    pub fn location_list(&self) -> Result<Vec<RegisteredLocation>, ControlError> {
        self.locations
            .list_locations(LocationListLimit::DEFAULT)
            .map_err(map_location_error)
    }

    /// Register one exact root path as a bounded Location identity.
    ///
    /// The path is inspected and canonicalized by the existing Location
    /// service; the canonical root is the only registered form. Duplicate
    /// roots and duplicate identities stay explicit, typed conflicts.
    pub fn register_location(
        &mut self,
        request: RegisterLocationRequest,
    ) -> Result<RegisteredLocation, ControlError> {
        self.locations
            .register_selected_path(
                request.id,
                request.name,
                &request.selected_path,
                request.observed_at,
            )
            .map_err(map_register_location_error)
    }

    /// Apply one explicit Location enable/disable transition through the
    /// optimistic-concurrency repository contract. Disabled Locations stay
    /// registered but reject discovery and resolution.
    pub fn set_location_state(
        &mut self,
        command: &SetLocationState,
    ) -> Result<RegisteredLocation, ControlError> {
        self.locations
            .set_location_state(command)
            .map_err(map_location_error)
    }

    /// List durable Workspace identities registered at the exact Location root.
    /// No filesystem candidate scan participates in this authority projection.
    pub fn workspace_list(
        &self,
        location_id: LocationId,
        expected_revision: LocationRevision,
    ) -> Result<Vec<WorkspaceCatalogEntry>, ControlError> {
        let location = self
            .locations
            .get_current_location(location_id, expected_revision)
            .map_err(map_location_error)?;
        let Some(layout) = WorkspaceStateLayout::inspect_existing(location.root().as_path())
            .map_err(map_state_layout_error)?
        else {
            return Ok(Vec::new());
        };
        let workspace = WorkspaceStore::inspect_existing_identity_live_read_only(&layout)
            .map_err(map_store_error)?;
        if workspace.location_id() != location_id {
            return Err(ControlError::new(
                ControlErrorCode::WorkspaceIdentityConflict,
            ));
        }
        Ok(vec![WorkspaceCatalogEntry::from_registered(
            location_id,
            expected_revision,
            location.name().as_str().to_owned(),
            workspace.id(),
            workspace.revision(),
        )?])
    }

    /// Discover bounded filesystem observations without registering a Workspace
    /// or granting effect authority.
    pub fn workspace_discover(
        &self,
        location_id: LocationId,
        expected_revision: LocationRevision,
    ) -> Result<Vec<WorkspaceDiscoveryEntry>, ControlError> {
        let discovery = self
            .locations
            .discover_current(location_id, expected_revision)
            .map_err(map_location_error)?;
        if discovery.observations().len() > MAX_WORKSPACE_CATALOG_ENTRIES {
            return Err(ControlError::new(ControlErrorCode::CapacityExceeded));
        }
        discovery
            .observations()
            .iter()
            .map(|observation| {
                WorkspaceDiscoveryEntry::from_observation(observation, expected_revision)
            })
            .collect()
    }

    /// Resolve a durable Workspace locator with a fresh Location revision,
    /// exact confined root, current `SQLite` identity, and fingerprint checks.
    ///
    /// The locator's embedded revision must exactly match the explicit input;
    /// no stale/default/active Workspace fallback exists.
    pub fn resolve_workspace(
        &self,
        location_id: LocationId,
        expected_revision: LocationRevision,
        locator: &WorkspaceLocator,
    ) -> Result<ResolvedWorkspaceScope, ControlError> {
        let (scope, _, _) =
            self.inspect_resolved_workspace(location_id, expected_revision, locator)?;
        Ok(scope)
    }

    /// Durable-first Activity bootstrap with a fresh post-commit revalidation.
    ///
    /// The caller supplies all time and runtime identity observations.  This
    /// service never reads a clock, creates an ID, or infers an Activity from
    /// transport/UI state.
    pub fn bootstrap_activity(
        &self,
        scope: &ResolvedWorkspaceScope,
        caller_activity_id: ActivityId,
        runtime_instance_id: RuntimeInstanceId,
        observed_at: TimestampMillis,
        lease_until: TimestampMillis,
    ) -> Result<ActivityBootstrap, ControlError> {
        self.bootstrap_activity_impl(
            scope,
            caller_activity_id,
            runtime_instance_id,
            observed_at,
            lease_until,
            || {},
        )
    }

    fn bootstrap_activity_impl<F>(
        &self,
        scope: &ResolvedWorkspaceScope,
        caller_activity_id: ActivityId,
        runtime_instance_id: RuntimeInstanceId,
        observed_at: TimestampMillis,
        lease_until: TimestampMillis,
        after_commit: F,
    ) -> Result<ActivityBootstrap, ControlError>
    where
        F: FnOnce(),
    {
        let (fresh_scope, mut store) = self.open_resolved_workspace(
            scope.locator.location_id(),
            scope.locator.expected_revision(),
            &scope.locator,
        )?;
        if fresh_scope != *scope {
            return Err(ControlError::new(
                ControlErrorCode::WorkspaceRevisionConflict,
            ));
        }
        let command = BootstrapActivityCommand::new(
            caller_activity_id,
            scope.workspace_id,
            scope.workspace_revision,
            runtime_instance_id,
            lease_until,
            observed_at,
        );

        let existing = store
            .get_activity(caller_activity_id)
            .map_err(map_store_error)?;
        let status =
            match forge_domain::decide_bootstrap_activity(existing.as_ref(), &command, observed_at)
            {
                BootstrapActivityDecision::Create => ActivityBootstrapStatus::Created,
                BootstrapActivityDecision::ResumeReleased => ActivityBootstrapStatus::Resumed,
                BootstrapActivityDecision::ExpiredRecoveryRequired => {
                    ActivityBootstrapStatus::ExpiredRecoveryRequired
                }
                BootstrapActivityDecision::UnleasedRecoveryRequired => {
                    ActivityBootstrapStatus::UnleasedRecoveryRequired
                }
                BootstrapActivityDecision::AlreadyOwned => ActivityBootstrapStatus::AlreadyOwned,
                BootstrapActivityDecision::AlreadyLive => ActivityBootstrapStatus::AlreadyLive,
                BootstrapActivityDecision::Terminal => ActivityBootstrapStatus::Terminal,
            };

        let activity = match store.bootstrap_activity(&command) {
            Ok(activity) => activity,
            Err(source) => {
                if is_post_commit_store_error(&source) {
                    return Ok(ActivityBootstrap::new(
                        scope.clone(),
                        None,
                        ActivityBootstrapStatus::CommittedButUnconfirmed,
                    ));
                }
                return Err(map_bootstrap_store_error(source));
            }
        };

        after_commit();

        if self.committed_scope_matches_with_store(scope, &store) {
            Ok(ActivityBootstrap::new(
                scope.clone(),
                Some(activity),
                status,
            ))
        } else {
            Ok(ActivityBootstrap::new(
                scope.clone(),
                Some(activity),
                ActivityBootstrapStatus::CommittedButUnconfirmed,
            ))
        }
    }

    pub(crate) fn inspect_resolved_workspace(
        &self,
        location_id: LocationId,
        expected_revision: LocationRevision,
        locator: &WorkspaceLocator,
    ) -> Result<
        (
            ResolvedWorkspaceScope,
            ExistingWorkspaceStateLayout,
            forge_domain::RegisteredWorkspace,
        ),
        ControlError,
    > {
        if locator.location_id() != location_id || locator.expected_revision() != expected_revision
        {
            return Err(ControlError::new(
                ControlErrorCode::LocationRevisionConflict,
            ));
        }
        let candidate = self
            .locations
            .resolve_locator_current(locator)
            .map_err(map_location_error)?;
        let layout = WorkspaceStateLayout::inspect_existing(candidate.absolute_root())
            .map_err(map_state_layout_error)?
            .ok_or_else(|| ControlError::new(ControlErrorCode::WorkspaceNotInitialized))?;
        let observed_fingerprint = layout.root_fingerprint().map_err(map_state_layout_error)?;
        let workspace = WorkspaceStore::inspect_existing_identity_live_read_only(&layout)
            .map_err(map_store_error)?;
        if workspace.location_id() != location_id {
            return Err(ControlError::new(
                ControlErrorCode::WorkspaceIdentityConflict,
            ));
        }
        if workspace.root().as_path() != candidate.absolute_root()
            || workspace.root_fingerprint() != observed_fingerprint
        {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        Ok((
            ResolvedWorkspaceScope {
                workspace_id: workspace.id(),
                workspace_revision: workspace.revision(),
                locator: locator.clone(),
            },
            layout,
            workspace,
        ))
    }

    pub(crate) fn open_resolved_workspace(
        &self,
        location_id: LocationId,
        expected_revision: LocationRevision,
        locator: &WorkspaceLocator,
    ) -> Result<(ResolvedWorkspaceScope, WorkspaceStore), ControlError> {
        self.open_resolved_workspace_with_layout(location_id, expected_revision, locator)
            .map(|(scope, _, store)| (scope, store))
    }

    pub(crate) fn open_resolved_workspace_with_layout(
        &self,
        location_id: LocationId,
        expected_revision: LocationRevision,
        locator: &WorkspaceLocator,
    ) -> Result<
        (
            ResolvedWorkspaceScope,
            ExistingWorkspaceStateLayout,
            WorkspaceStore,
        ),
        ControlError,
    > {
        if locator.location_id() != location_id || locator.expected_revision() != expected_revision
        {
            return Err(ControlError::new(
                ControlErrorCode::LocationRevisionConflict,
            ));
        }
        let candidate = self
            .locations
            .resolve_locator_current(locator)
            .map_err(map_location_error)?;
        let layout = WorkspaceStateLayout::inspect_existing(candidate.absolute_root())
            .map_err(map_state_layout_error)?
            .ok_or_else(|| ControlError::new(ControlErrorCode::WorkspaceNotInitialized))?;
        let observed_fingerprint = layout.root_fingerprint().map_err(map_state_layout_error)?;
        let store = WorkspaceStore::open_existing(&layout).map_err(map_store_error)?;
        let workspace = store.workspace().map_err(map_store_error)?;

        if workspace.location_id() != location_id {
            return Err(ControlError::new(
                ControlErrorCode::WorkspaceIdentityConflict,
            ));
        }
        if workspace.root().as_path() != candidate.absolute_root()
            || workspace.root_fingerprint() != observed_fingerprint
        {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }

        Ok((
            ResolvedWorkspaceScope {
                workspace_id: workspace.id(),
                workspace_revision: workspace.revision(),
                locator: locator.clone(),
            },
            layout,
            store,
        ))
    }

    pub(crate) fn committed_scope_matches_with_store(
        &self,
        scope: &ResolvedWorkspaceScope,
        store: &WorkspaceStore,
    ) -> bool {
        let Ok(workspace) = store.workspace() else {
            return false;
        };
        let Ok(candidate) = self.locations.resolve_locator_current(&scope.locator) else {
            return false;
        };
        workspace.id() == scope.workspace_id()
            && workspace.revision() == scope.workspace_revision()
            && workspace.location_id() == scope.locator.location_id()
            && workspace.root().as_path() == candidate.absolute_root()
    }
    /// Renew caller-owned Activity leases in one atomic, deterministic batch.
    pub fn renew_activity_lease_batch(
        &self,
        scope: &ResolvedWorkspaceScope,
        commands: &[RenewActivityLease],
    ) -> Result<ActivityLeaseOperation, ControlError> {
        validate_lease_batch_len(commands.len())?;
        let (fresh_scope, mut store) = self.open_resolved_workspace(
            scope.locator.location_id(),
            scope.locator.expected_revision(),
            &scope.locator,
        )?;
        if fresh_scope != *scope {
            return Err(ControlError::new(
                ControlErrorCode::WorkspaceRevisionConflict,
            ));
        }
        let activities = match store.renew_activity_leases(commands) {
            Ok(activities) => activities,
            Err(error) if is_post_commit_store_error(&error) => {
                return Ok(ActivityOperation::uncertain(
                    scope.clone(),
                    None,
                    Vec::new(),
                ));
            }
            Err(error) => return Err(map_activity_store_error(error)),
        };
        if !self.committed_scope_matches_with_store(scope, &store) {
            return Ok(ActivityOperation::uncertain(
                scope.clone(),
                None,
                activities,
            ));
        }
        Ok(ActivityOperation::batch(
            scope.clone(),
            activities,
            ActivityOperationStatus::Renewed,
        ))
    }

    /// Renew one caller-owned Activity lease after fresh scope revalidation.
    pub fn renew_activity_lease(
        &self,
        scope: &ResolvedWorkspaceScope,
        activity_id: ActivityId,
        runtime_instance_id: RuntimeInstanceId,
        expected_lease_revision: ActivityLeaseRevision,
        observed_at: TimestampMillis,
        lease_until: TimestampMillis,
    ) -> Result<ActivityLeaseOperation, ControlError> {
        let command = RenewActivityLease::new(
            activity_id,
            runtime_instance_id,
            expected_lease_revision,
            lease_until,
            observed_at,
        );
        let operation = self.renew_activity_lease_batch(scope, std::slice::from_ref(&command))?;
        operation.into_single(ActivityOperationStatus::Renewed)
    }

    /// Renew one host-supervised lease only while its pinned Goal identity and
    /// current session-bound Coordinator remain valid at the Source mutation boundary.
    pub fn renew_supervised_activity_lease(
        &self,
        request: &SupervisedActivityLeaseRenewRequest,
    ) -> Result<ActivityLeaseOperation, ControlError> {
        let actor = request.actor;
        if actor.workspace_id() != request.scope.workspace_id()
            || actor.activity_id() != request.command.id()
        {
            return Err(ControlError::new(ControlErrorCode::ActivityLeaseConflict));
        }
        let _session = self.agent_session_resolve(crate::AgentSessionResolveRequest {
            session_id: actor.session_id(),
            principal: actor.principal(),
        })?;
        let (fresh_scope, mut store) = self.open_resolved_workspace(
            request.scope.locator.location_id(),
            request.scope.locator.expected_revision(),
            &request.scope.locator,
        )?;
        if fresh_scope != request.scope {
            return Err(ControlError::new(
                ControlErrorCode::WorkspaceRevisionConflict,
            ));
        }
        let activity = match store.renew_activity_lease_with_supervision_guard(
            &request.command,
            actor,
            request.goal_id,
            request.goal_created_at,
        ) {
            Ok(activity) => activity,
            Err(error) if is_post_commit_store_error(&error) => {
                return Ok(ActivityOperation::uncertain(
                    request.scope.clone(),
                    None,
                    Vec::new(),
                ));
            }
            Err(error) => return Err(map_activity_store_error(error)),
        };
        if !self.committed_scope_matches_with_store(&request.scope, &store) {
            return Ok(ActivityOperation::uncertain(
                request.scope.clone(),
                Some(activity.clone()),
                Vec::new(),
            ));
        }
        ActivityOperation::batch(
            request.scope.clone(),
            vec![activity],
            ActivityOperationStatus::Renewed,
        )
        .into_single(ActivityOperationStatus::Renewed)
    }

    /// Close caller-owned Activities in one atomic, deterministic batch.
    pub fn close_owned_activity_batch(
        &self,
        scope: &ResolvedWorkspaceScope,
        commands: &[CloseActivity],
    ) -> Result<ActivityLeaseOperation, ControlError> {
        validate_lease_batch_len(commands.len())?;
        let (fresh_scope, mut store) = self.open_resolved_workspace(
            scope.locator.location_id(),
            scope.locator.expected_revision(),
            &scope.locator,
        )?;
        if fresh_scope != *scope {
            return Err(ControlError::new(
                ControlErrorCode::WorkspaceRevisionConflict,
            ));
        }
        let activities = match store.close_owned_activities(commands) {
            Ok(activities) => activities,
            Err(error) if is_post_commit_store_error(&error) => {
                return Ok(ActivityOperation::uncertain(
                    scope.clone(),
                    None,
                    Vec::new(),
                ));
            }
            Err(error) => return Err(map_activity_store_error(error)),
        };
        if !self.committed_scope_matches_with_store(scope, &store) {
            return Ok(ActivityOperation::uncertain(
                scope.clone(),
                None,
                activities,
            ));
        }
        Ok(ActivityOperation::batch(
            scope.clone(),
            activities,
            ActivityOperationStatus::Closed,
        ))
    }

    /// Close one caller-owned Activity and release its lease atomically.
    pub fn close_activity(
        &self,
        scope: &ResolvedWorkspaceScope,
        activity_id: ActivityId,
        runtime_instance_id: RuntimeInstanceId,
        expected_lease_revision: ActivityLeaseRevision,
        observed_at: TimestampMillis,
    ) -> Result<ActivityLeaseOperation, ControlError> {
        let command = CloseActivity::new(
            activity_id,
            runtime_instance_id,
            expected_lease_revision,
            observed_at,
        );
        let operation = self.close_owned_activity_batch(scope, std::slice::from_ref(&command))?;
        operation.into_single(ActivityOperationStatus::Closed)
    }

    /// Explicit naming alias for runtime supervisors closing an owned
    /// Activity during graceful shutdown.
    pub fn close_owned_activity(
        &self,
        scope: &ResolvedWorkspaceScope,
        activity_id: ActivityId,
        runtime_instance_id: RuntimeInstanceId,
        expected_lease_revision: ActivityLeaseRevision,
        observed_at: TimestampMillis,
    ) -> Result<ActivityLeaseOperation, ControlError> {
        self.close_activity(
            scope,
            activity_id,
            runtime_instance_id,
            expected_lease_revision,
            observed_at,
        )
    }

    /// Release caller-owned leases in one atomic, deterministic batch.
    pub fn release_activity_lease_batch(
        &self,
        scope: &ResolvedWorkspaceScope,
        commands: &[ReleaseActivityLease],
    ) -> Result<ActivityLeaseOperation, ControlError> {
        validate_lease_batch_len(commands.len())?;
        let (fresh_scope, mut store) = self.open_resolved_workspace(
            scope.locator.location_id(),
            scope.locator.expected_revision(),
            &scope.locator,
        )?;
        if fresh_scope != *scope {
            return Err(ControlError::new(
                ControlErrorCode::WorkspaceRevisionConflict,
            ));
        }
        let activities = match store.release_activity_leases(commands) {
            Ok(activities) => activities,
            Err(error) if is_post_commit_store_error(&error) => {
                return Ok(ActivityOperation::uncertain(
                    scope.clone(),
                    None,
                    Vec::new(),
                ));
            }
            Err(error) => return Err(map_activity_store_error(error)),
        };
        if !self.committed_scope_matches_with_store(scope, &store) {
            return Ok(ActivityOperation::uncertain(
                scope.clone(),
                None,
                activities,
            ));
        }
        Ok(ActivityOperation::batch(
            scope.clone(),
            activities,
            ActivityOperationStatus::Released,
        ))
    }

    /// Release one caller-owned lease while keeping the Activity Open.
    pub fn release_activity_lease(
        &self,
        scope: &ResolvedWorkspaceScope,
        activity_id: ActivityId,
        runtime_instance_id: RuntimeInstanceId,
        expected_lease_revision: ActivityLeaseRevision,
        observed_at: TimestampMillis,
    ) -> Result<ActivityLeaseOperation, ControlError> {
        let command = ReleaseActivityLease::new(
            activity_id,
            runtime_instance_id,
            expected_lease_revision,
            observed_at,
        );
        let operation = self.release_activity_lease_batch(scope, std::slice::from_ref(&command))?;
        operation.into_single(ActivityOperationStatus::Released)
    }

    /// Read exact Activity rows for tracker reconciliation without mutating
    /// lifecycle or lease state. The scope is revalidated before and after
    /// every bounded observation batch; callers must treat the returned rows
    /// as an observational snapshot and fence any subsequent CAS separately.
    pub fn observe_activity_leases(
        &self,
        scope: &ResolvedWorkspaceScope,
        activity_ids: &[ActivityId],
    ) -> Result<Vec<RegisteredActivity>, ControlError> {
        validate_activity_observation_ids(activity_ids)?;
        let (fresh_scope, store) = self.open_resolved_workspace(
            scope.locator.location_id(),
            scope.locator.expected_revision(),
            &scope.locator,
        )?;
        if fresh_scope != *scope {
            return Err(ControlError::new(
                ControlErrorCode::WorkspaceRevisionConflict,
            ));
        }
        let mut activities = Vec::with_capacity(activity_ids.len());
        for activity_id in activity_ids {
            if let Some(activity) = store
                .get_activity(*activity_id)
                .map_err(map_activity_store_error)?
            {
                activities.push(activity);
            }
        }
        if !self.committed_scope_matches_with_store(scope, &store) {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        Ok(activities)
    }

    /// Reconcile expired leases into Interrupted Activities using the
    /// persistence-owned transition.  No bootstrap or control operation
    /// revives an expired row implicitly.
    pub fn reconcile_expired_activity_leases(
        &self,
        scope: &ResolvedWorkspaceScope,
        observed_at: TimestampMillis,
    ) -> Result<ActivityReconcileResult, ControlError> {
        self.reconcile_expired_activity_leases_limited(
            scope,
            observed_at,
            ActivityListLimit::DEFAULT,
        )
    }

    /// Bounded variant of [`Self::reconcile_expired_activity_leases`].
    pub fn reconcile_expired_activity_leases_limited(
        &self,
        scope: &ResolvedWorkspaceScope,
        observed_at: TimestampMillis,
        limit: ActivityListLimit,
    ) -> Result<ActivityReconcileResult, ControlError> {
        validate_activity_limit(limit)?;
        let command = ReconcileExpiredActivities::new(observed_at);
        self.mutate_activity_batch(
            scope,
            |store| store.reconcile_expired_activities_limited(&command, limit),
            || {},
        )
    }

    /// Return caller-time Activity liveness projections without mutating
    /// expired rows.  Reconciliation remains an explicit supervisor action.
    pub fn list_activity_projections(
        &self,
        scope: &ResolvedWorkspaceScope,
        now: TimestampMillis,
        limit: ActivityListLimit,
    ) -> Result<Vec<ActivityProjection>, ControlError> {
        validate_activity_limit(limit)?;
        let (fresh_scope, store) = self.open_resolved_workspace(
            scope.locator.location_id(),
            scope.locator.expected_revision(),
            &scope.locator,
        )?;
        if fresh_scope != *scope {
            return Err(ControlError::new(
                ControlErrorCode::WorkspaceRevisionConflict,
            ));
        }
        let projections = store
            .list_activity_projections(limit, now)
            .map_err(map_activity_store_error)?;
        if self.committed_scope_matches_with_store(scope, &store) {
            Ok(projections)
        } else {
            Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict))
        }
    }

    /// Desktop/UI refresh action. The scope is first resolved through the
    /// immutable read-only path, expected Workspace identity/revision are
    /// checked, and the existing store is used only to project durable rows at
    /// the supplied observation time. Expired leases remain explicit
    /// `ActivityLiveness::Expired` evidence until a dedicated recovery owner
    /// invokes the separate reconcile operation.
    pub fn list_workspace_activity_projections(
        &self,
        request: &WorkspaceActivityProjectionRequest,
    ) -> Result<WorkspaceActivityProjection, ControlError> {
        validate_activity_limit(request.limit)?;
        let (scope, layout, workspace) = self.inspect_resolved_workspace(
            request.location_id,
            request.expected_location_revision,
            &request.locator,
        )?;
        if scope.workspace_id() != request.expected_workspace_id {
            return Err(ControlError::new(
                ControlErrorCode::WorkspaceIdentityConflict,
            ));
        }
        if scope.workspace_revision() != request.expected_workspace_revision {
            return Err(ControlError::new(
                ControlErrorCode::WorkspaceRevisionConflict,
            ));
        }
        if workspace.id() != request.expected_workspace_id
            || workspace.revision() != request.expected_workspace_revision
        {
            return Err(ControlError::new(
                ControlErrorCode::WorkspaceIdentityConflict,
            ));
        }

        let store = WorkspaceStore::open_existing(&layout).map_err(map_store_error)?;
        let activities = store
            .list_activity_projections(request.limit, request.now)
            .map_err(map_activity_store_error)?;
        if !self.committed_scope_matches_with_store(&scope, &store) {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        Ok(WorkspaceActivityProjection::new(scope, activities))
    }

    fn mutate_activity_batch<F, H>(
        &self,
        scope: &ResolvedWorkspaceScope,
        mutate: F,
        after_commit: H,
    ) -> Result<ActivityReconcileResult, ControlError>
    where
        F: FnOnce(&mut WorkspaceStore) -> Result<Vec<RegisteredActivity>, WorkspaceStoreError>,
        H: FnOnce(),
    {
        let (fresh_scope, mut store) = self.open_resolved_workspace(
            scope.locator.location_id(),
            scope.locator.expected_revision(),
            &scope.locator,
        )?;
        if fresh_scope != *scope {
            return Err(ControlError::new(
                ControlErrorCode::WorkspaceRevisionConflict,
            ));
        }
        let activities = match mutate(&mut store) {
            Ok(activities) => activities,
            Err(error) if is_post_commit_store_error(&error) => {
                return Ok(ActivityOperation::uncertain(
                    scope.clone(),
                    None,
                    Vec::new(),
                ));
            }
            Err(error) => return Err(map_activity_store_error(error)),
        };
        after_commit();
        if self.committed_scope_matches_with_store(scope, &store) {
            Ok(ActivityOperation::batch(
                scope.clone(),
                activities,
                ActivityOperationStatus::Reconciled,
            ))
        } else {
            Ok(ActivityOperation::uncertain(
                scope.clone(),
                None,
                activities,
            ))
        }
    }
}

pub(crate) fn map_location_error(error: LocationServiceError) -> ControlError {
    if matches!(
        &error,
        LocationServiceError::Repository(LocationRepositoryError::CommittedUnconfirmed { .. })
    ) {
        return ControlError::committed();
    }
    let code = match &error {
        LocationServiceError::Repository(LocationRepositoryError::NotFound(_)) => {
            ControlErrorCode::LocationNotFound
        }
        LocationServiceError::Repository(LocationRepositoryError::RevisionConflict { .. }) => {
            ControlErrorCode::LocationRevisionConflict
        }
        LocationServiceError::Discovery(_) => ControlErrorCode::LocationUnavailable,
        LocationServiceError::WorkspaceKey(_)
        | LocationServiceError::WorkspaceResolve(_)
        | LocationServiceError::WorkspaceLocator(_)
        | LocationServiceError::InvalidName(_)
        | LocationServiceError::InvalidRoot(_)
        | LocationServiceError::InspectSelectedPath { .. }
        | LocationServiceError::SelectedPathIsNotDirectory(_)
        | LocationServiceError::CanonicalizeSelectedPath { .. }
        | LocationServiceError::Repository(_) => ControlErrorCode::InvalidInput,
    };
    ControlError::with_source(code, error)
}

/// Registration-specific projection: duplicate roots/identities are durable
/// identity conflicts, not generic invalid input.
fn map_register_location_error(error: LocationServiceError) -> ControlError {
    let code = match &error {
        LocationServiceError::Repository(LocationRepositoryError::AlreadyRegistered { .. }) => {
            ControlErrorCode::WorkspaceRootConflict
        }
        LocationServiceError::Repository(LocationRepositoryError::IdentityConflict(_)) => {
            ControlErrorCode::WorkspaceIdentityConflict
        }
        _ => return map_location_error(error),
    };
    ControlError::with_source(code, error)
}

fn map_state_layout_code(error: &forge_workspace::StateLayoutError) -> ControlErrorCode {
    match error {
        forge_workspace::StateLayoutError::WorkspaceFingerprintRootIsSymlink(_)
        | forge_workspace::StateLayoutError::WorkspaceFingerprintRootNotDirectory(_)
        | forge_workspace::StateLayoutError::WorkspaceFingerprintRootMoved { .. }
        | forge_workspace::StateLayoutError::WorkspaceIsNotDirectory(_)
        | forge_workspace::StateLayoutError::StateRootIsNotDirectory(_)
        | forge_workspace::StateLayoutError::StatePathIsSymlink(_)
        | forge_workspace::StateLayoutError::StateSubpathIsNotDirectory(_)
        | forge_workspace::StateLayoutError::StateSubpathMissing(_) => {
            ControlErrorCode::WorkspaceRootConflict
        }
        _ => ControlErrorCode::WorkspaceStateUnavailable,
    }
}

pub(crate) fn map_state_layout_error(error: forge_workspace::StateLayoutError) -> ControlError {
    let code = map_state_layout_code(&error);
    ControlError::with_source(code, error)
}

pub(crate) fn map_store_error(error: WorkspaceStoreError) -> ControlError {
    if matches!(
        &error,
        WorkspaceStoreError::ExecutionJournalCommittedUnconfirmed { .. }
            | WorkspaceStoreError::ExecutionStopCommittedUnconfirmed { .. }
            | WorkspaceStoreError::ExecutionStopRollbackUnconfirmed { .. }
            | WorkspaceStoreError::ApprovalCleanupCommittedUnconfirmed { .. }
            | WorkspaceStoreError::Approval(
                forge_persistence::ApprovalStoreError::CleanupCommittedUnconfirmed { .. }
                    | forge_persistence::ApprovalStoreError::CleanupRollbackUnconfirmed { .. }
            )
            | WorkspaceStoreError::Execution(
                forge_persistence::ExecutionStoreError::CommittedUnconfirmed { .. }
            )
    ) {
        return ControlError::committed();
    }
    let code = match &error {
        WorkspaceStoreError::OutdatedSchema { .. }
        | WorkspaceStoreError::UnsupportedForReadOnly { .. } => {
            ControlErrorCode::WorkspaceSchemaOutdated
        }
        WorkspaceStoreError::ReadOnlyWalActive { .. }
        | WorkspaceStoreError::DatabaseSidecarPairMismatch { .. }
        | WorkspaceStoreError::MissingDatabase(_)
        | WorkspaceStoreError::FreshDatabase
        | WorkspaceStoreError::UnownedDatabase
        | WorkspaceStoreError::DamagedSchema { .. }
        | WorkspaceStoreError::DatabaseOwnershipMismatch { .. } => {
            ControlErrorCode::WorkspaceStateUnavailable
        }
        WorkspaceStoreError::WorkspaceRevisionConflict { .. } => {
            ControlErrorCode::WorkspaceRevisionConflict
        }
        WorkspaceStoreError::WorkspaceRootBindingConflict { .. }
        | WorkspaceStoreError::ExistingWorkspaceBindingMismatch { .. }
        | WorkspaceStoreError::WorkspaceRootFingerprintChanged { .. }
        | WorkspaceStoreError::LayoutRootMismatch { .. }
        | WorkspaceStoreError::LayoutFingerprintMismatch { .. }
        | WorkspaceStoreError::WorkspaceRootSymlink(_)
        | WorkspaceStoreError::WorkspaceRootNotDirectory(_)
        | WorkspaceStoreError::WorkspaceRootCanonicalPathChanged { .. } => {
            ControlErrorCode::WorkspaceRootConflict
        }
        WorkspaceStoreError::LocationBindingConflict { .. } => {
            ControlErrorCode::WorkspaceIdentityConflict
        }
        WorkspaceStoreError::ExecutionStop(
            forge_persistence::ExecutionStopStoreError::Conflict,
        ) => ControlErrorCode::ExecutionConflict,
        WorkspaceStoreError::ActivityNotFound(_) => ControlErrorCode::ActivityNotFound,
        WorkspaceStoreError::ActivityIdConflict(_) => ControlErrorCode::ActivityConflict,
        WorkspaceStoreError::ActivityWorkspaceMismatch { .. }
        | WorkspaceStoreError::ActivityRevisionConflict { .. } => {
            ControlErrorCode::ActivityConflict
        }
        _ => ControlErrorCode::PersistenceFailure,
    };
    ControlError::with_source(code, error)
}

fn validate_activity_limit(limit: ActivityListLimit) -> Result<(), ControlError> {
    if usize::try_from(limit.get()).is_ok_and(|value| value <= MAX_ACTIVITY_PROJECTION_RESULTS) {
        Ok(())
    } else {
        Err(ControlError::new(ControlErrorCode::CapacityExceeded))
    }
}

fn validate_lease_batch_len(len: usize) -> Result<(), ControlError> {
    if len > MAX_ACTIVITY_LEASE_BATCH {
        return Err(ControlError::new(ControlErrorCode::CapacityExceeded));
    }
    let Ok(value) = u32::try_from(len) else {
        return Err(ControlError::new(ControlErrorCode::CapacityExceeded));
    };
    ActivityLeaseBatchLimit::new(value)
        .map(|_| ())
        .map_err(|_| ControlError::new(ControlErrorCode::CapacityExceeded))
}

fn validate_activity_observation_ids(ids: &[ActivityId]) -> Result<(), ControlError> {
    if ids.len() <= MAX_ACTIVITY_LEASE_OBSERVATION_IDS {
        Ok(())
    } else {
        Err(ControlError::new(ControlErrorCode::CapacityExceeded))
    }
}

pub(crate) fn map_activity_store_error(error: WorkspaceStoreError) -> ControlError {
    match error {
        WorkspaceStoreError::GoalDeletionCommittedUnconfirmed { .. }
        | WorkspaceStoreError::ExecutionStopCommittedUnconfirmed { .. }
        | WorkspaceStoreError::ExecutionStopRollbackUnconfirmed { .. }
        | WorkspaceStoreError::ApprovalCleanupCommittedUnconfirmed { .. }
        | WorkspaceStoreError::Approval(
            forge_persistence::ApprovalStoreError::CleanupCommittedUnconfirmed { .. }
            | forge_persistence::ApprovalStoreError::CleanupRollbackUnconfirmed { .. },
        )
        | WorkspaceStoreError::ExecutionJournalCommittedUnconfirmed { .. }
        | WorkspaceStoreError::Execution(
            forge_persistence::ExecutionStoreError::CommittedUnconfirmed { .. },
        )
        | WorkspaceStoreError::ExpiredActivityRecovery(
            forge_persistence::ExpiredActivityRecoveryStoreError::CommitUnconfirmed(_)
            | forge_persistence::ExpiredActivityRecoveryStoreError::RollbackUnconfirmed { .. },
        )
        | WorkspaceStoreError::UnstartedActivityContinuationCommittedUnconfirmed { .. } => {
            ControlError::committed()
        }
        WorkspaceStoreError::GoalDeletion(source) => {
            crate::goal_deletion::map_goal_deletion_store_error(source)
        }
        WorkspaceStoreError::Dag(source)
        | WorkspaceStoreError::Approval(forge_persistence::ApprovalStoreError::Dag(source)) => {
            crate::dag::map_dag_store_error(WorkspaceStoreError::Dag(source))
        }
        WorkspaceStoreError::Approval(forge_persistence::ApprovalStoreError::Goal(source)) => {
            crate::goal::map_goal_store_error(WorkspaceStoreError::Goal(source))
        }
        WorkspaceStoreError::Approval(forge_persistence::ApprovalStoreError::Execution(source)) => {
            map_activity_store_error(WorkspaceStoreError::Execution(source))
        }
        error => map_activity_store_code(error),
    }
}

fn map_activity_store_code(error: WorkspaceStoreError) -> ControlError {
    let code = match &error {
        WorkspaceStoreError::UnstartedActivityContinuation(
            forge_persistence::UnstartedActivityContinuationStoreError::Conflict(_),
        ) => ControlErrorCode::ActivityLeaseConflict,
        WorkspaceStoreError::Approval(
            forge_persistence::ApprovalStoreError::ApprovalMissing
            | forge_persistence::ApprovalStoreError::GrantMissing
            | forge_persistence::ApprovalStoreError::AutoScopeMissing,
        ) => ControlErrorCode::ApprovalNotFound,
        WorkspaceStoreError::Approval(forge_persistence::ApprovalStoreError::InvalidExpiry) => {
            ControlErrorCode::ApprovalExpired
        }
        WorkspaceStoreError::Approval(
            forge_persistence::ApprovalStoreError::IdentityConflict
            | forge_persistence::ApprovalStoreError::WorkspaceMismatch
            | forge_persistence::ApprovalStoreError::PolicyRevisionConflict
            | forge_persistence::ApprovalStoreError::RevisionConflict
            | forge_persistence::ApprovalStoreError::InvalidTransition
            | forge_persistence::ApprovalStoreError::GrantMismatch
            | forge_persistence::ApprovalStoreError::GrantReplay
            | forge_persistence::ApprovalStoreError::CleanupPlanMismatch,
        ) => ControlErrorCode::ApprovalConflict,
        WorkspaceStoreError::UnstartedActivityContinuation(
            forge_persistence::UnstartedActivityContinuationStoreError::Invalid(_),
        )
        | WorkspaceStoreError::Approval(
            forge_persistence::ApprovalStoreError::CleanupLimitExceeded,
        ) => ControlErrorCode::InvalidInput,
        WorkspaceStoreError::Approval(
            forge_persistence::ApprovalStoreError::AdmissionEnvelope(source),
        ) => match source {
            forge_persistence::AdmissionEnvelopeError::Invalid(
                forge_domain::ExecutionAdmissionError::Expired,
            ) => ControlErrorCode::ApprovalExpired,
            forge_persistence::AdmissionEnvelopeError::Sqlite(_)
            | forge_persistence::AdmissionEnvelopeError::DamagedSchema(_)
            | forge_persistence::AdmissionEnvelopeError::CorruptRecord => {
                ControlErrorCode::PersistenceFailure
            }
            forge_persistence::AdmissionEnvelopeError::Invalid(_)
            | forge_persistence::AdmissionEnvelopeError::IdentityConflict
            | forge_persistence::AdmissionEnvelopeError::ReplayedForDifferentExecution => {
                ControlErrorCode::ExecutionConflict
            }
        },
        WorkspaceStoreError::Approval(
            forge_persistence::ApprovalStoreError::AdmissionEnvelopeMismatch,
        )
        | WorkspaceStoreError::Execution(
            forge_persistence::ExecutionStoreError::IdentityConflict
            | forge_persistence::ExecutionStoreError::AgentAuthorityConflict
            | forge_persistence::ExecutionStoreError::GeneratedArtifactConflict
            | forge_persistence::ExecutionStoreError::NativeClosureAlreadyExists
            | forge_persistence::ExecutionStoreError::NativeClosureConflict
            | forge_persistence::ExecutionStoreError::NativeClosureOutputConflict
            | forge_persistence::ExecutionStoreError::NativeClosureArtifactConflict
            | forge_persistence::ExecutionStoreError::Terminal
            | forge_persistence::ExecutionStoreError::InvalidTransition
            | forge_persistence::ExecutionStoreError::RevisionConflict,
        )
        | WorkspaceStoreError::ExecutionStop(
            forge_persistence::ExecutionStopStoreError::Conflict,
        ) => ControlErrorCode::ExecutionConflict,
        WorkspaceStoreError::ActivityNotFound(_) => ControlErrorCode::ActivityNotFound,
        WorkspaceStoreError::ActivityTerminal(_)
        | WorkspaceStoreError::ActivityLeaseUnavailable(_)
        | WorkspaceStoreError::ActivityLeaseRequired(_)
        | WorkspaceStoreError::LeaseOwnerMismatch { .. }
        | WorkspaceStoreError::LeaseExpired { .. }
        | WorkspaceStoreError::InvalidLeaseWindow { .. }
        | WorkspaceStoreError::LeaseRevisionConflict { .. }
        | WorkspaceStoreError::ActivityLeaseRevisionOverflow { .. }
        | WorkspaceStoreError::ActivityLeaseBatchOwnerMismatch { .. }
        | WorkspaceStoreError::ActivityLeaseBatchDuplicate(_)
        | WorkspaceStoreError::AlreadyLive { .. }
        | WorkspaceStoreError::ExpiredRecoveryRequired { .. } => {
            ControlErrorCode::ActivityLeaseConflict
        }
        WorkspaceStoreError::ActivityWorkspaceMismatch { .. }
        | WorkspaceStoreError::ActivityRevisionConflict { .. }
        | WorkspaceStoreError::ActivityIdConflict(_) => ControlErrorCode::ActivityConflict,
        WorkspaceStoreError::ActivitySuccessorPredecessorNotTerminal { .. }
        | WorkspaceStoreError::ActivitySuccessorConflict { .. }
        | WorkspaceStoreError::ActivitySuccessorTargetAlreadyExists(_)
        | WorkspaceStoreError::ActivitySuccessorTimestampOrder { .. } => {
            ControlErrorCode::ActivityConflict
        }
        WorkspaceStoreError::WorkspaceRevisionConflict { .. } => {
            ControlErrorCode::WorkspaceRevisionConflict
        }
        WorkspaceStoreError::WorkspaceRootBindingConflict { .. }
        | WorkspaceStoreError::ExistingWorkspaceBindingMismatch { .. }
        | WorkspaceStoreError::WorkspaceRootFingerprintChanged { .. }
        | WorkspaceStoreError::WorkspaceRootCanonicalPathChanged { .. } => {
            ControlErrorCode::WorkspaceRootConflict
        }
        _ => ControlErrorCode::PersistenceFailure,
    };
    ControlError::with_source(code, error)
}

fn map_bootstrap_store_error(error: WorkspaceStoreError) -> ControlError {
    let code = match &error {
        WorkspaceStoreError::ActivityIdConflict(_) => ControlErrorCode::ActivityConflict,
        WorkspaceStoreError::ActivityNotFound(_) => ControlErrorCode::ActivityNotFound,
        WorkspaceStoreError::ActivityWorkspaceMismatch { .. }
        | WorkspaceStoreError::ActivityRevisionConflict { .. }
        | WorkspaceStoreError::ActivityLeaseUnavailable(_)
        | WorkspaceStoreError::ActivityLeaseRequired(_)
        | WorkspaceStoreError::LeaseOwnerMismatch { .. }
        | WorkspaceStoreError::LeaseExpired { .. }
        | WorkspaceStoreError::InvalidLeaseWindow { .. }
        | WorkspaceStoreError::LeaseRevisionConflict { .. }
        | WorkspaceStoreError::ActivityLeaseRevisionOverflow { .. }
        | WorkspaceStoreError::AlreadyLive { .. }
        | WorkspaceStoreError::ExpiredRecoveryRequired { .. } => {
            ControlErrorCode::ActivityLeaseConflict
        }
        WorkspaceStoreError::WorkspaceRevisionConflict { .. } => {
            ControlErrorCode::WorkspaceRevisionConflict
        }
        WorkspaceStoreError::WorkspaceRootBindingConflict { .. }
        | WorkspaceStoreError::ExistingWorkspaceBindingMismatch { .. }
        | WorkspaceStoreError::WorkspaceRootFingerprintChanged { .. }
        | WorkspaceStoreError::WorkspaceRootCanonicalPathChanged { .. } => {
            ControlErrorCode::WorkspaceRootConflict
        }
        _ => ControlErrorCode::PersistenceFailure,
    };
    ControlError::with_source(code, error)
}

fn is_post_commit_store_error(error: &WorkspaceStoreError) -> bool {
    // Keep this helper centralized so a future persistence error variant can
    // be recognized without changing the public/redacted control contract.
    matches!(
        error,
        WorkspaceStoreError::WorkspaceRootFingerprintChanged { .. }
            | WorkspaceStoreError::DatabasePathChanged(_)
            | WorkspaceStoreError::WorkspaceRootCanonicalPathChanged { .. }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn continuation_conflicts_do_not_masquerade_as_persistence_failure() {
        use forge_persistence::UnstartedActivityContinuationStoreError as ContinuationError;

        for (source, expected) in [
            (
                ContinuationError::Conflict("origin mismatch"),
                ControlErrorCode::ActivityLeaseConflict,
            ),
            (
                ContinuationError::Invalid("invalid caller fence"),
                ControlErrorCode::InvalidInput,
            ),
            (
                ContinuationError::Corrupt("damaged origin"),
                ControlErrorCode::PersistenceFailure,
            ),
            (
                ContinuationError::Sqlite(rusqlite::Error::InvalidQuery),
                ControlErrorCode::PersistenceFailure,
            ),
        ] {
            let error = map_activity_store_error(
                WorkspaceStoreError::UnstartedActivityContinuation(source),
            );
            assert_eq!(error.code(), expected);
            assert!(!error.is_committed());
        }
    }

    #[test]
    fn execution_journal_uncertainty_requires_readback() {
        for mapper in [map_store_error, map_activity_store_error] {
            for error in [
                WorkspaceStoreError::ExecutionJournalCommittedUnconfirmed {
                    source: Box::new(WorkspaceStoreError::Execution(
                        forge_persistence::ExecutionStoreError::RecordMissing,
                    )),
                },
                WorkspaceStoreError::Execution(
                    forge_persistence::ExecutionStoreError::CommittedUnconfirmed {
                        source: Box::new(forge_persistence::ExecutionStoreError::RecordMissing),
                    },
                ),
            ] {
                let mapped = mapper(error);
                assert_eq!(mapped.code(), ControlErrorCode::CommittedButUnconfirmed);
                assert!(mapped.is_committed());
            }
            let rejected = mapper(WorkspaceStoreError::Execution(
                forge_persistence::ExecutionStoreError::RecordMissing,
            ));
            assert!(!rejected.is_committed());
        }
    }

    #[test]
    fn remote_safe_error_view_has_no_path_or_source_text() {
        let error = ControlError::with_source(
            ControlErrorCode::WorkspaceRootConflict,
            std::io::Error::other(
                "private-adapter-marker /private/state.sqlite SELECT token-secret",
            ),
        );
        let view = error.view();
        assert_eq!(view.code(), ControlErrorCode::WorkspaceRootConflict);
        assert!(!view.summary().contains('/'));
        assert!(!error.to_string().contains('/'));
        assert!(!format!("{error:?}").contains('/'));
        for rendered in [
            error.to_string(),
            format!("{error:?} {view:?}"),
            view.recovery_hint().to_owned(),
        ] {
            for private in [
                "private-adapter-marker",
                "/private/state.sqlite",
                "SELECT",
                "token-secret",
            ] {
                assert!(!rendered.contains(private));
            }
        }
    }
}

#[cfg(test)]
mod integration_tests {
    use std::ffi::OsString;
    use std::fs::{self, Permissions};
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::mpsc;
    use std::time::{SystemTime, UNIX_EPOCH};

    use forge_domain::{
        ActivityCoordinatorActor, ActivityListLimit, ActivityLiveness, AgentFocus, AgentFocusNode,
        AgentInstanceRevision, AuthenticatedPrincipal, CloseActivity, CreateActivity,
        DagAcceptanceCriterion, DagNodeDefinition, DagNodeId, DagNodeObjective, DagNodeOrdinal,
        DagNodeTitle, DagRevision, DagRevisionId, DagRevisionNumber, EstablishWorkspace,
        ExecutionArgument, ExecutionAttribution, ExecutionCommandId, ExecutionId, ExecutionKind,
        ExecutionLimits, ExecutionOutputLimit, ExecutionPermissions, ExecutionProgram,
        ExecutionRequest, ExecutionTimeoutMillis, GoalAttribution, GoalContract, GoalId,
        GoalNodeAttribution, GoalObjective, GoalStatement, GoalVerificationRequirement,
        LocationState, ProjectCommandEvidence, RegisteredDagNode, RegisteredGoal,
        RenewActivityLease, SetLocationState, WorkspaceRoot,
    };
    use forge_execution::{
        RUST_CI_SANDBOX_MARKER_ENV, RUST_CI_SANDBOX_MARKER_VALUE, RustCiDiscoveryInput,
        RustCiHostArchitecture, RustCiToolchainCapability,
    };
    use forge_persistence::{GlobalRegistry, WorkspaceStore};
    use forge_workspace::{FORGE_GIT_PROGRAM, LocationService, WorkspaceStateLayout};
    use uuid::Uuid;

    use super::{
        ActivityBootstrapStatus, ActivityOperationStatus, ForgeControl,
        MAX_ACTIVITY_LEASE_OBSERVATION_IDS, MAX_WORKSPACE_CATALOG_ENTRIES, OwnedActivityLease,
        ResolvedWorkspaceScope, SupervisedActivityLeaseRenewRequest,
        WorkspaceActivityProjectionRequest,
    };
    use crate::error::ControlErrorCode;
    use crate::worker::{ControlClientError, ForgeControlWorker, PendingControl};
    use crate::{
        ActivityId, AgentExecutionAuthorityRequest, ApprovalSubmissionStatus, DagNodeStartRequest,
        DagNodeUpdateRequest, FileActivityScope, ForgeApprovalCoordinator,
        ForgeExecutionCoordinator, GoalCompletionRequest, LocationId, ProjectCommandId,
        ProjectCommandListRequest, RuntimeInstanceId, SubmitExecutionForApproval, TimestampMillis,
        WorkspaceId, WorkspaceRevision,
    };

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

    const RUST_CI_TEST_POLICY_ENV: &str = "HETERARCHY_FORGE_RUST_CI_TEST_POLICY";
    const RUST_CI_TEST_POLICY_VALUE: &str = "outer-rust-ci-v1";

    struct Fixture {
        control: ForgeControl,
        registry_path: PathBuf,
        root: PathBuf,
        location_id: LocationId,
        workspaces: Vec<PathBuf>,
    }

    fn timestamp(value: i64) -> Result<TimestampMillis, Box<dyn std::error::Error>> {
        Ok(TimestampMillis::new(value)?)
    }

    fn timestamp_now() -> Result<TimestampMillis, Box<dyn std::error::Error>> {
        let millis = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
        Ok(TimestampMillis::new(millis)?)
    }

    fn cleanup_test_root(root: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
        fn restore_permissions(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
            let metadata = fs::symlink_metadata(path)?;
            if metadata.file_type().is_symlink() {
                return Ok(());
            }
            let mode = metadata.permissions().mode();
            let restored = if metadata.is_dir() {
                mode | 0o700
            } else {
                mode | 0o600
            };
            fs::set_permissions(path, Permissions::from_mode(restored))?;
            if metadata.is_dir() {
                for child in fs::read_dir(path)? {
                    restore_permissions(&child?.path())?;
                }
            }
            Ok(())
        }

        restore_permissions(&root)?;
        fs::remove_dir_all(root)?;
        Ok(())
    }

    fn nested_sandbox_execution_is_unavailable() -> bool {
        std::env::var(RUST_CI_SANDBOX_MARKER_ENV).as_deref() == Ok(RUST_CI_SANDBOX_MARKER_VALUE)
            && std::env::var(RUST_CI_TEST_POLICY_ENV).as_deref() == Ok(RUST_CI_TEST_POLICY_VALUE)
    }

    fn prepare_test_rust_ci_capability(
        root: &Path,
    ) -> Result<RustCiToolchainCapability, Box<dyn std::error::Error>> {
        let architecture = RustCiHostArchitecture::current().ok_or("unsupported test host")?;
        let root = fs::canonicalize(root)?;
        let host = root.join("rust-ci-host-home");
        let cargo = host.join(".cargo");
        let rustup = host.join(".rustup");
        fs::create_dir_all(cargo.join("bin"))?;
        fs::create_dir_all(cargo.join("registry"))?;
        fs::create_dir_all(rustup.join("toolchains").join(format!(
            "{}-{}-apple-darwin",
            forge_execution::RUST_CI_PINNED_VERSION,
            architecture.as_str()
        )))?;
        fs::write(cargo.join("bin/rustup"), b"rustup")?;
        fs::write(rustup.join("settings.toml"), b"version = 12\n")?;
        let input = RustCiDiscoveryInput::new(
            host,
            root.join("rust-ci-cache"),
            architecture,
            forge_domain::RuntimeInstanceId::from_uuid(Uuid::from_u128(0xC101)),
        )?;
        Ok(RustCiToolchainCapability::prepare(&input)?)
    }

    fn id(value: u128) -> Uuid {
        Uuid::from_u128(value)
    }

    fn wait_for_terminal_execution(
        client: &crate::ForgeControlClient,
        scope: &ResolvedWorkspaceScope,
        execution_id: ExecutionId,
    ) -> Result<forge_domain::RegisteredExecution, Box<dyn std::error::Error>> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            let record = client
                .execution_get(scope.clone(), execution_id)?
                .ok_or("execution record missing while awaiting terminal state")?;
            if record.state().is_terminal() {
                return Ok(record);
            }
            if std::time::Instant::now() >= deadline {
                return Err("execution did not become terminal".into());
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    fn attach_stdio_planner(
        client: &crate::ForgeControlClient,
        scope: &ResolvedWorkspaceScope,
        activity_id: ActivityId,
        agent_id: forge_domain::AgentInstanceId,
        display_name: &str,
        observed_at: TimestampMillis,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let session_id = forge_domain::AgentSessionId::from_uuid(agent_id.into_uuid());
        let _session = client.agent_session_open(forge_domain::OpenAgentSession::new(
            session_id,
            forge_domain::AgentSessionOpenRequestId::from_uuid(id(agent_id
                .into_uuid()
                .as_u128()
                .wrapping_add(0x100))),
            forge_domain::AuthenticatedPrincipal::TrustedStdio,
            observed_at,
        ))?;
        let agent = forge_domain::RegisteredAgentInstance::create_bound(
            agent_id,
            scope.workspace_id(),
            activity_id,
            session_id,
            forge_domain::AgentDisplayName::new(display_name.to_owned())?,
            forge_domain::AgentDeclaredRole::new("planner".to_owned())?,
            forge_domain::AgentTransportKind::Stdio,
            forge_domain::AuthenticatedPrincipal::TrustedStdio,
            observed_at,
        );
        let _ = crate::legacy_agent_fixture::seed_client_agent(
            client,
            scope,
            &agent,
            forge_domain::AgentEventId::from_uuid(agent_id.into_uuid()),
        )?;
        Ok(())
    }

    fn claim_stdio_coordinator(
        client: &crate::ForgeControlClient,
        scope: &ResolvedWorkspaceScope,
        activity_id: ActivityId,
        agent_id: forge_domain::AgentInstanceId,
        display_name: &str,
        observed_at: TimestampMillis,
    ) -> Result<forge_domain::ActivityCoordinatorActor, Box<dyn std::error::Error>> {
        attach_stdio_planner(
            client,
            scope,
            activity_id,
            agent_id,
            display_name,
            observed_at,
        )?;
        let binding = client.activity_coordinator_claim(crate::CoordinatorClaimRequest {
            session_id: forge_domain::AgentSessionId::from_uuid(agent_id.into_uuid()),
            scope: scope.clone(),
            activity_id,
            agent_id,
            principal: forge_domain::AuthenticatedPrincipal::TrustedStdio,
            observed_at,
        })?;
        Ok(forge_domain::ActivityCoordinatorActor::new(
            scope.workspace_id(),
            activity_id,
            binding.agent_id(),
            binding.revision(),
            forge_domain::AuthenticatedPrincipal::TrustedStdio,
            forge_domain::AgentSessionId::from_uuid(agent_id.into_uuid()),
        ))
    }

    #[test]
    fn admitted_goal_write_uses_worker_clock_instead_of_old_audit_time()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("expired-goal-admission", &[0], 1)?;
        let locator = locator_for(&fixture.control, fixture.location_id, "workspace-0")?;
        let scope = fixture.control.resolve_workspace(
            fixture.location_id,
            forge_domain::LocationRevision::INITIAL,
            &locator,
        )?;
        let activity_id = ActivityId::from_uuid(id(0xE2A0));
        let live_since = timestamp_now()?;
        let lease_until = TimestampMillis::new(
            live_since
                .get()
                .checked_add(60_000)
                .ok_or("Activity lease deadline overflow")?,
        )?;
        let _live = fixture.control.bootstrap_activity(
            &scope,
            activity_id,
            RuntimeInstanceId::from_uuid(id(0xE2A1)),
            timestamp(0)?,
            lease_until,
        )?;
        let (client, mut worker) = fixture.control.start_worker()?;
        let actor = claim_stdio_coordinator(
            &client,
            &scope,
            activity_id,
            forge_domain::AgentInstanceId::from_uuid(id(0xE2A2)),
            "expired Activity planner",
            timestamp(0)?,
        )?;
        let layout = WorkspaceStateLayout::inspect_existing(&fixture.workspaces[0])?
            .ok_or("expired-admission Workspace layout missing")?;
        let connection = rusqlite::Connection::open(layout.database_path())?;
        let expired_until = TimestampMillis::new(
            timestamp_now()?
                .get()
                .checked_sub(1)
                .ok_or("test clock predates the Activity timestamp domain")?,
        )?;
        let changed = connection.execute(
            "UPDATE activities SET lease_until_ms = ?1 WHERE activity_id = ?2",
            rusqlite::params![expired_until.get(), activity_id.into_uuid().as_bytes()],
        )?;
        assert_eq!(
            changed, 1,
            "the fixture Activity lease deadline was updated"
        );
        drop(connection);
        let goal_id = GoalId::from_uuid(id(0xE2A3));
        let command = forge_domain::GoalMutationCommand::new(
            forge_domain::GoalMutationRequestId::from_uuid(id(0xE2A4)),
            actor,
            scope.workspace_revision(),
            goal_id,
            None,
            timestamp(0)?,
            forge_domain::GoalMutationAction::Create(Box::new(GoalContract::new(
                GoalObjective::new("Expired lease must block this Goal".to_owned())?,
                vec![GoalStatement::new(
                    "The audit timestamp remains zero".to_owned(),
                )?],
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            )?)),
        )?;
        let request = crate::GoalMutationRequest {
            scope: scope.clone(),
            command,
        };
        let rejected = client.goal_mutation(request);
        assert!(matches!(
            rejected,
            Err(error) if error.code() == ControlErrorCode::ActivityLeaseConflict
        ));
        assert!(
            client
                .goal_mutation_readback(crate::GoalMutationReadbackRequest {
                    scope: scope.clone(),
                    activity_id,
                    goal_id,
                    mutation_request_id: forge_domain::GoalMutationRequestId::from_uuid(id(0xE2A4)),
                    expected_request_digest: None,
                })?
                .is_none()
        );
        worker.shutdown()?;
        cleanup_test_root(fixture.root)?;
        Ok(())
    }

    #[derive(Debug, Clone, Copy)]
    struct InitialAgentDagPlanIdentity {
        request_id: forge_domain::AgentDagPlanRequestId,
        history_update_id: forge_domain::AgentWorkUpdateId,
        observed_at: TimestampMillis,
    }

    fn commit_initial_agent_dag_plan(
        client: &crate::ForgeControlClient,
        scope: &ResolvedWorkspaceScope,
        actor: forge_domain::ActivityCoordinatorActor,
        goal: GoalAttribution,
        draft: forge_domain::AgentDagDraft,
        identity: InitialAgentDagPlanIdentity,
    ) -> Result<forge_persistence::AgentDagPlanCommitResult, Box<dyn std::error::Error>> {
        let request = forge_domain::AgentDagPlanRequest::new(
            identity.request_id,
            actor,
            goal,
            None,
            None,
            draft,
            identity.history_update_id,
            forge_domain::AgentWorkUpdateSequence::INITIAL,
            identity.observed_at,
        );
        Ok(
            client.agent_dag_plan_commit(crate::AgentDagPlanCommitRequest {
                scope: scope.clone(),
                request,
            })?,
        )
    }

    fn create_dag_worker_goal_fixture(
        client: &crate::ForgeControlClient,
        scope: &ResolvedWorkspaceScope,
        activity_id: ActivityId,
        actor: forge_domain::ActivityCoordinatorActor,
    ) -> Result<(RegisteredGoal, DagNodeDefinition), Box<dyn std::error::Error>> {
        let goal = RegisteredGoal::create(
            GoalId::from_uuid(id(0xEA10)),
            scope.workspace_id(),
            activity_id,
            GoalContract::new(
                GoalObjective::new("Persist one DAG node".to_owned())?,
                vec![GoalStatement::new("Node completes".to_owned())?],
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            )?,
            timestamp(10)?,
        );
        let _created = client.goal_create(scope.clone(), actor, goal.clone())?;
        let definition = DagNodeDefinition::new(
            DagNodeId::from_uuid(id(0xEA11)),
            DagNodeOrdinal::new(0)?,
            DagNodeTitle::new("Implement".to_owned())?,
            DagNodeObjective::new("Implement the accepted slice".to_owned())?,
            vec![DagAcceptanceCriterion::new(
                "Implementation verified".to_owned(),
            )?],
        )?;
        Ok((goal, definition))
    }

    struct CoordinatorDagPlanFixture {
        goal: RegisteredGoal,
        revision: DagRevision,
        nodes: Vec<RegisteredDagNode>,
        request: forge_domain::AgentDagPlanRequest,
        stored: forge_persistence::AgentDagPlanCommitResult,
    }

    fn create_initial_coordinator_dag_plan_fixture(
        client: &crate::ForgeControlClient,
        scope: &ResolvedWorkspaceScope,
        activity_id: ActivityId,
        actor: forge_domain::ActivityCoordinatorActor,
    ) -> Result<CoordinatorDagPlanFixture, Box<dyn std::error::Error>> {
        let (goal, definition) = create_dag_worker_goal_fixture(client, scope, activity_id, actor)?;
        let revision = DagRevision::new(
            DagRevisionId::from_uuid(id(0xEA12)),
            goal.id(),
            goal.revision(),
            DagRevisionNumber::INITIAL,
            None,
            vec![definition.clone()],
            Vec::new(),
            timestamp(11)?,
        )?;
        let nodes = vec![RegisteredDagNode::create(
            goal.id(),
            revision.number(),
            definition,
            timestamp(11)?,
        )];
        let draft = forge_domain::AgentDagDraft::new(revision.clone(), nodes.clone(), Vec::new())?;
        let request = forge_domain::AgentDagPlanRequest::new(
            forge_domain::AgentDagPlanRequestId::from_uuid(id(0xEA16)),
            actor,
            GoalAttribution::new(goal.id(), goal.revision()),
            None,
            None,
            draft,
            forge_domain::AgentWorkUpdateId::from_uuid(id(0xEA17)),
            forge_domain::AgentWorkUpdateSequence::INITIAL,
            timestamp(11)?,
        );
        let stored = client.agent_dag_plan_commit(crate::AgentDagPlanCommitRequest {
            scope: scope.clone(),
            request: request.clone(),
        })?;
        assert_eq!(stored.revision().revision(), &revision);
        assert_eq!(
            client.dag_get_current(scope.clone(), goal.id())?,
            Some(stored.revision().clone())
        );
        Ok(CoordinatorDagPlanFixture {
            goal,
            revision,
            nodes,
            request,
            stored,
        })
    }

    fn transfer_and_commit_successor_dag(
        client: &crate::ForgeControlClient,
        scope: &ResolvedWorkspaceScope,
        activity_id: ActivityId,
        current_agent_id: forge_domain::AgentInstanceId,
        current_actor: forge_domain::ActivityCoordinatorActor,
        initial: &CoordinatorDagPlanFixture,
    ) -> Result<Vec<RegisteredDagNode>, Box<dyn std::error::Error>> {
        let successor_agent_id = forge_domain::AgentInstanceId::from_uuid(id(0xEA18));
        attach_stdio_planner(
            client,
            scope,
            activity_id,
            successor_agent_id,
            "Successor DAG coordinator",
            timestamp(12)?,
        )?;
        let transferred =
            client.activity_coordinator_transfer(crate::CoordinatorTransferRequest {
                current_session_id: current_actor.session_id(),
                scope: scope.clone(),
                activity_id,
                current_agent_id,
                expected_coordinator_revision: current_actor.expected_revision(),
                principal: forge_domain::AuthenticatedPrincipal::TrustedStdio,
                next_agent_id: successor_agent_id,
                observed_at: timestamp(12)?,
            })?;
        let successor_actor = forge_domain::ActivityCoordinatorActor::new(
            scope.workspace_id(),
            activity_id,
            transferred.agent_id(),
            transferred.revision(),
            forge_domain::AuthenticatedPrincipal::TrustedStdio,
            forge_domain::AgentSessionId::from_uuid(successor_agent_id.into_uuid()),
        );
        let Err(stale_replay) = client.agent_dag_plan_commit(crate::AgentDagPlanCommitRequest {
            scope: scope.clone(),
            request: initial.request.clone(),
        }) else {
            return Err("stale Coordinator replayed a committed DAG request after transfer".into());
        };
        assert_eq!(stale_replay.code(), ControlErrorCode::CoordinatorConflict);

        let successor_definition = DagNodeDefinition::new(
            DagNodeId::from_uuid(id(0xEA19)),
            DagNodeOrdinal::new(0)?,
            DagNodeTitle::new("Implement successor".to_owned())?,
            DagNodeObjective::new(
                "Continue the accepted slice after Coordinator transfer".to_owned(),
            )?,
            vec![DagAcceptanceCriterion::new(
                "Successor implementation verified".to_owned(),
            )?],
        )?;
        let successor_revision = DagRevision::new(
            DagRevisionId::from_uuid(id(0xEA1A)),
            initial.goal.id(),
            initial.goal.revision(),
            DagRevisionNumber::new(2)?,
            Some(initial.revision.number()),
            vec![successor_definition.clone()],
            Vec::new(),
            timestamp(13)?,
        )?;
        let successor_nodes = vec![RegisteredDagNode::create(
            initial.goal.id(),
            successor_revision.number(),
            successor_definition.clone(),
            timestamp(13)?,
        )];
        let successor_draft = forge_domain::AgentDagDraft::new(
            successor_revision.clone(),
            successor_nodes.clone(),
            vec![forge_domain::DagNodeLineage::new(
                initial.nodes[0].id(),
                successor_definition.id(),
                forge_domain::DagLineageKind::Replace,
            )],
        )?;
        let successor = client.agent_dag_plan_commit(crate::AgentDagPlanCommitRequest {
            scope: scope.clone(),
            request: forge_domain::AgentDagPlanRequest::new(
                forge_domain::AgentDagPlanRequestId::from_uuid(id(0xEA1B)),
                successor_actor,
                GoalAttribution::new(initial.goal.id(), initial.goal.revision()),
                Some(initial.revision.number()),
                Some(initial.stored.revision().head().revision()),
                successor_draft,
                forge_domain::AgentWorkUpdateId::from_uuid(id(0xEA1C)),
                forge_domain::AgentWorkUpdateSequence::INITIAL,
                timestamp(13)?,
            ),
        })?;
        assert_eq!(successor.revision().revision(), &successor_revision);
        Ok(successor_nodes)
    }

    fn create_active_execution_goal_node(
        client: &crate::ForgeControlClient,
        scope: &ResolvedWorkspaceScope,
        request: &ExecutionRequest,
    ) -> Result<
        (
            RegisteredGoal,
            RegisteredDagNode,
            forge_domain::ActivityCoordinatorActor,
        ),
        Box<dyn std::error::Error>,
    > {
        let agent_id = forge_domain::AgentInstanceId::from_uuid(id(0xEBC7));
        let actor = claim_stdio_coordinator(
            client,
            scope,
            request.activity_id(),
            agent_id,
            "Execution coordinator",
            timestamp(1)?,
        )?;
        let goal = RegisteredGoal::create(
            GoalId::from_uuid(id(0xEBC1)),
            scope.workspace_id(),
            request.activity_id(),
            GoalContract::new(
                GoalObjective::new("Project one attributed execution through the DAG".to_owned())?,
                vec![GoalStatement::new("The execution succeeds".to_owned())?],
                Vec::new(),
                Vec::new(),
                vec![GoalVerificationRequirement::ExecutionSucceeded {
                    request_digest: forge_execution::execution_request_digest(request),
                    description: GoalStatement::new(
                        "The structured process exits zero".to_owned(),
                    )?,
                }],
                Vec::new(),
            )?,
            timestamp(2)?,
        );
        let _created = client.goal_create(scope.clone(), actor, goal.clone())?;
        let definition = DagNodeDefinition::new(
            DagNodeId::from_uuid(id(0xEBC2)),
            DagNodeOrdinal::new(0)?,
            DagNodeTitle::new("Run approved work".to_owned())?,
            DagNodeObjective::new("Execute the attributed structured process".to_owned())?,
            vec![DagAcceptanceCriterion::new(
                "Execution evidence is linked".to_owned(),
            )?],
        )?;
        let revision = DagRevision::new(
            DagRevisionId::from_uuid(id(0xEBC3)),
            goal.id(),
            goal.revision(),
            DagRevisionNumber::INITIAL,
            None,
            vec![definition.clone()],
            Vec::new(),
            timestamp(2)?,
        )?;
        let pending =
            RegisteredDagNode::create(goal.id(), revision.number(), definition, timestamp(2)?);
        let draft = forge_domain::AgentDagDraft::new(revision, vec![pending.clone()], Vec::new())?;
        let stored = commit_initial_agent_dag_plan(
            client,
            scope,
            actor,
            GoalAttribution::new(goal.id(), goal.revision()),
            draft,
            InitialAgentDagPlanIdentity {
                request_id: forge_domain::AgentDagPlanRequestId::from_uuid(id(0xEBC8)),
                history_update_id: forge_domain::AgentWorkUpdateId::from_uuid(id(0xEBC9)),
                observed_at: timestamp(2)?,
            },
        )?;
        assert_eq!(stored.revision().nodes(), std::slice::from_ref(&pending));
        let active = client.dag_node_start(DagNodeStartRequest {
            scope: scope.clone(),
            activity_id: request.activity_id(),
            session_id: actor.session_id(),
            principal: actor.principal(),
            goal_id: goal.id(),
            expected_goal_revision: goal.revision(),
            expected_dag_revision: pending.dag_revision(),
            node_id: pending.id(),
            expected_revision: pending.revision(),
            observed_at: timestamp(3)?,
        })?;
        Ok((goal, active, actor))
    }

    fn sleeping_execution_request(
        execution_id: ExecutionId,
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
    ) -> Result<ExecutionRequest, Box<dyn std::error::Error>> {
        Ok(ExecutionRequest::new(
            ExecutionAttribution::new(execution_id, workspace_id, activity_id),
            ExecutionKind::Structured {
                program: ExecutionProgram::new(PathBuf::from("/bin/sleep"))?,
                arguments: vec![ExecutionArgument::new(OsString::from("30"))?],
            },
            None,
            ExecutionLimits::new(
                ExecutionTimeoutMillis::new(30_000)?,
                ExecutionOutputLimit::new(1_024)?,
            ),
            ExecutionPermissions::new(false, false, false),
        )?)
    }

    fn successful_execution_request(
        execution_id: ExecutionId,
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
    ) -> Result<ExecutionRequest, Box<dyn std::error::Error>> {
        Ok(ExecutionRequest::new(
            ExecutionAttribution::new(execution_id, workspace_id, activity_id),
            ExecutionKind::Structured {
                program: ExecutionProgram::new(PathBuf::from("/usr/bin/true"))?,
                arguments: Vec::new(),
            },
            None,
            ExecutionLimits::new(
                ExecutionTimeoutMillis::new(2_000)?,
                ExecutionOutputLimit::new(1_024)?,
            ),
            ExecutionPermissions::new(false, false, false),
        )?)
    }

    fn create_supervisor_goal(
        client: &crate::ForgeControlClient,
        scope: &ResolvedWorkspaceScope,
        activity_id: ActivityId,
    ) -> Result<(RegisteredGoal, forge_domain::ActivityCoordinatorActor), Box<dyn std::error::Error>>
    {
        let actor = claim_stdio_coordinator(
            client,
            scope,
            activity_id,
            forge_domain::AgentInstanceId::from_uuid(id(0xEB06)),
            "Supervisor coordinator",
            timestamp(1)?,
        )?;
        let goal = RegisteredGoal::create(
            GoalId::from_uuid(id(0xEB04)),
            scope.workspace_id(),
            activity_id,
            GoalContract::new(
                GoalObjective::new("Observe one approved execution".to_owned())?,
                vec![GoalStatement::new(
                    "The linked approval and execution are terminal".to_owned(),
                )?],
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            )?,
            timestamp(2)?,
        );
        let _ = client.goal_create(scope.clone(), actor, goal.clone())?;
        Ok((goal, actor))
    }

    fn assert_single_node_dag_projection(
        client: &crate::ForgeControlClient,
        scope: &ResolvedWorkspaceScope,
        goal_id: GoalId,
        expected_evidence_count: u16,
        expected_lifecycle: &forge_domain::DagNodeLifecycle,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let projected = client
            .dag_get_current(scope.clone(), goal_id)?
            .ok_or("current DAG projection missing")?;
        assert_eq!(projected.nodes().len(), 1);
        assert_eq!(projected.evidence().len(), 1);
        assert_eq!(projected.evidence()[0].node_id(), projected.nodes()[0].id());
        assert_eq!(projected.evidence()[0].count(), expected_evidence_count);
        assert_eq!(projected.nodes()[0].lifecycle(), expected_lifecycle);
        Ok(())
    }

    fn assert_pending_approval_blocker(
        client: &crate::ForgeControlClient,
        scope: &ResolvedWorkspaceScope,
        activity_id: ActivityId,
        goal_id: GoalId,
        approval_id: forge_domain::ApprovalRequestId,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let review = client.goal_review(scope.clone(), activity_id, goal_id)?;
        assert!(review.blockers().iter().any(|blocker| {
            matches!(
                blocker,
                forge_domain::GoalCompletionBlocker::PendingApproval(id) if *id == approval_id
            )
        }));
        Ok(())
    }

    fn complete_attributed_goal_node(
        client: &crate::ForgeControlClient,
        scope: &ResolvedWorkspaceScope,
        actor: forge_domain::ActivityCoordinatorActor,
        goal: &RegisteredGoal,
        active: &RegisteredDagNode,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let completed_node = active.complete(active.revision(), timestamp(70_000)?)?;
        let completed_node = client.dag_node_update(DagNodeUpdateRequest {
            scope: scope.clone(),
            node: completed_node,
            expected_revision: active.revision(),
        })?;
        assert_eq!(
            completed_node.lifecycle(),
            &forge_domain::DagNodeLifecycle::Completed
        );
        let completed_goal = client.goal_complete(GoalCompletionRequest {
            scope: scope.clone(),
            activity_id: goal.activity_id(),
            actor,
            goal_id: goal.id(),
            expected_revision: goal.revision(),
            review_id: id(0xEBC7),
            observed_at: timestamp(80_000)?,
        })?;
        assert_eq!(
            completed_goal.status().kind(),
            forge_domain::GoalStatusKind::Completed
        );
        Ok(())
    }

    fn assert_durable_goal_dag_evidence(
        workspace_root: &std::path::Path,
        goal_id: GoalId,
        approval_id: forge_domain::ApprovalRequestId,
        execution_id: ExecutionId,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let layout = WorkspaceStateLayout::inspect_existing(workspace_root)?
            .ok_or("Goal/DAG evidence layout missing")?;
        let store = WorkspaceStore::open_existing(&layout)?;
        let evidence = store.list_goal_evidence(goal_id, 10)?;
        assert_eq!(evidence.len(), 2);
        assert!(evidence.iter().any(|record| {
            record.evidence() == forge_domain::GoalEvidenceRef::Approval(approval_id)
        }));
        assert!(evidence.iter().any(|record| {
            record.evidence() == forge_domain::GoalEvidenceRef::Execution(execution_id)
        }));
        let durable_dag = store
            .get_current_dag(goal_id)?
            .ok_or("durable DAG missing")?;
        assert_eq!(durable_dag.evidence()[0].count(), 2);
        assert_eq!(
            durable_dag.nodes()[0].lifecycle(),
            &forge_domain::DagNodeLifecycle::Completed
        );
        Ok(())
    }

    fn fixture(
        label: &str,
        initialized: &[usize],
        workspace_count: usize,
    ) -> Result<Fixture, Box<dyn std::error::Error>> {
        fixture_with_git(label, initialized, workspace_count, false)
    }

    fn fixture_with_git(
        label: &str,
        initialized: &[usize],
        workspace_count: usize,
        with_git: bool,
    ) -> Result<Fixture, Box<dyn std::error::Error>> {
        let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "heterarchy-forge-control-{label}-{}-{serial}",
            std::process::id()
        ));
        fs::create_dir_all(&root)?;
        let location_root = root.join("location");
        fs::create_dir_all(&location_root)?;
        if with_git {
            let status = Command::new(FORGE_GIT_PROGRAM)
                .args([
                    "-C",
                    location_root.to_str().ok_or("non-UTF-8 fixture path")?,
                    "init",
                ])
                .status()?;
            if !status.success() {
                return Err("git init failed for fixture".into());
            }
        }
        let registry_path = root.join("registry.sqlite3");
        let location_id = LocationId::from_uuid(id(0x1000 + u128::from(serial)));
        let mut locations = LocationService::new(GlobalRegistry::open(&registry_path)?);
        let location = locations.register_selected_path(
            location_id,
            "Fixture Location",
            &location_root,
            timestamp(1)?,
        )?;
        drop(locations);

        let mut workspaces = Vec::with_capacity(workspace_count);
        for index in 0..workspace_count {
            let workspace_root = location_root.join(format!("workspace-{index}"));
            fs::create_dir_all(&workspace_root)?;
            if initialized.contains(&index) {
                let layout = WorkspaceStateLayout::initialize(&workspace_root)?;
                let workspace_root =
                    WorkspaceRoot::from_canonical(layout.workspace_root().to_path_buf())?;
                let workspace_id =
                    WorkspaceId::from_uuid(id(0x2000 + u128::from(serial) * 32 + index as u128));
                let command = EstablishWorkspace::new(
                    workspace_id,
                    location.id(),
                    workspace_root,
                    layout.root_fingerprint()?,
                    timestamp(2)?,
                );
                let _store = WorkspaceStore::open(&layout, &command)?;
            }
            workspaces.push(workspace_root);
        }

        Ok(Fixture {
            control: ForgeControl::new(GlobalRegistry::open(&registry_path)?),
            registry_path,
            root,
            location_id,
            workspaces,
        })
    }

    fn initialize_location_root_workspace(
        fixture: &Fixture,
    ) -> Result<(WorkspaceId, WorkspaceRevision), Box<dyn std::error::Error>> {
        let location_root = fixture.root.join("location");
        let layout = WorkspaceStateLayout::initialize(&location_root)?;
        let durable_root = WorkspaceRoot::from_canonical(layout.workspace_root().to_path_buf())?;
        let workspace_id =
            WorkspaceId::from_uuid(id(0x9000 + u128::from(NEXT_FIXTURE.load(Ordering::Relaxed))));
        let command = EstablishWorkspace::new(
            workspace_id,
            fixture.location_id,
            durable_root,
            layout.root_fingerprint()?,
            timestamp(3)?,
        );
        let store = WorkspaceStore::open(&layout, &command)?;
        let registered = store.get_workspace()?;
        Ok((registered.id(), registered.revision()))
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct FileSnapshot {
        bytes: Option<Vec<u8>>,
        modified: Option<std::time::SystemTime>,
    }

    fn snapshot(path: &std::path::Path) -> Result<FileSnapshot, Box<dyn std::error::Error>> {
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(FileSnapshot {
                    bytes: None,
                    modified: None,
                });
            }
            Err(error) => return Err(error.into()),
        };
        Ok(FileSnapshot {
            bytes: Some(fs::read(path)?),
            modified: metadata.modified().ok(),
        })
    }

    fn locator_for(
        control: &ForgeControl,
        location_id: LocationId,
        relative_name: &str,
    ) -> Result<forge_workspace::WorkspaceLocator, Box<dyn std::error::Error>> {
        let entries =
            control.workspace_discover(location_id, forge_domain::LocationRevision::INITIAL)?;
        let entry = entries
            .iter()
            .find(|entry| entry.display_name() == relative_name)
            .ok_or("workspace discovery entry missing")?;
        Ok(entry.locator().clone())
    }

    #[test]
    fn workspace_list_is_bounded_remote_safe_and_does_not_initialize()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("list", &[], 2)?;
        let state_paths: Vec<PathBuf> = fixture
            .workspaces
            .iter()
            .map(|workspace| workspace.join(".heterarchy-forge"))
            .collect();
        let entries = fixture
            .control
            .workspace_list(fixture.location_id, forge_domain::LocationRevision::INITIAL)?;
        assert!(entries.is_empty());

        let observations = fixture
            .control
            .workspace_discover(fixture.location_id, forge_domain::LocationRevision::INITIAL)?;
        assert!(observations.len() <= MAX_WORKSPACE_CATALOG_ENTRIES);
        assert_eq!(
            observations
                .iter()
                .filter(|entry| entry.display_name().starts_with("workspace-"))
                .count(),
            2
        );
        assert!(observations.iter().all(|entry| {
            !format!("{entry:?}").contains(&fixture.root.to_string_lossy().to_string())
        }));
        for state_path in state_paths {
            assert!(!state_path.exists());
        }
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn live_read_only_list_and_resolve_preserve_database_wal_and_git_exclude()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture_with_git("read-only", &[], 1, true)?;
        let (catalog_id, catalog_revision) = initialize_location_root_workspace(&fixture)?;
        let layout = WorkspaceStateLayout::inspect_existing(fixture.root.join("location"))?
            .ok_or("Location-root Workspace layout missing")?;
        let mut active_store = WorkspaceStore::open_existing(&layout)?;
        active_store.create_activity(&CreateActivity::new(
            ActivityId::from_uuid(id(0x9010)),
            catalog_id,
            catalog_revision,
            timestamp(4)?,
        ))?;
        let before = [
            snapshot(
                &fixture
                    .root
                    .join("location/.heterarchy-forge/state.sqlite3"),
            )?,
            snapshot(
                &fixture
                    .root
                    .join("location/.heterarchy-forge/state.sqlite3-wal"),
            )?,
            snapshot(
                &fixture
                    .root
                    .join("location/.heterarchy-forge/state.sqlite3-shm"),
            )?,
            snapshot(&fixture.root.join("location/.git/info/exclude"))?,
        ];
        assert!(before[1].bytes.is_some());
        assert!(before[2].bytes.is_some());
        let entries = fixture
            .control
            .workspace_list(fixture.location_id, forge_domain::LocationRevision::INITIAL)?;
        let entry = entries.first().ok_or("ready catalog entry missing")?;
        assert_eq!(entry.workspace_id(), catalog_id);
        assert_eq!(entry.workspace_revision(), catalog_revision);
        let scope = fixture.control.resolve_workspace(
            fixture.location_id,
            forge_domain::LocationRevision::INITIAL,
            entry.locator(),
        )?;
        assert_eq!(Some(scope.workspace_id()), Some(catalog_id));
        assert_eq!(Some(scope.workspace_revision()), Some(catalog_revision));
        let after = [
            snapshot(
                &fixture
                    .root
                    .join("location/.heterarchy-forge/state.sqlite3"),
            )?,
            snapshot(
                &fixture
                    .root
                    .join("location/.heterarchy-forge/state.sqlite3-wal"),
            )?,
            snapshot(
                &fixture
                    .root
                    .join("location/.heterarchy-forge/state.sqlite3-shm"),
            )?,
            snapshot(&fixture.root.join("location/.git/info/exclude"))?,
        ];
        assert!(before[0] == after[0], "Workspace database bytes changed");
        assert!(before[1] == after[1], "Workspace WAL bytes changed");
        assert_eq!(before[2].bytes.is_some(), after[2].bytes.is_some());
        assert!(before[3] == after[3], "Git exclude bytes changed");
        drop(active_store);
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn workspace_activity_projection_refresh_is_observational_for_expired_leases()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("workspace-activity-refresh", &[0], 1)?;
        let locator = locator_for(&fixture.control, fixture.location_id, "workspace-0")?;
        let scope = fixture.control.resolve_workspace(
            fixture.location_id,
            forge_domain::LocationRevision::INITIAL,
            &locator,
        )?;
        let activity_id = ActivityId::from_uuid(id(0xA100));
        let owner = RuntimeInstanceId::from_uuid(id(0xA200));
        let _ = fixture.control.bootstrap_activity(
            &scope,
            activity_id,
            owner,
            timestamp(0)?,
            timestamp(5)?,
        )?;
        let layout = WorkspaceStateLayout::inspect_existing(&fixture.workspaces[0])?
            .ok_or("Activity projection layout missing")?;
        let before = WorkspaceStore::open_existing(&layout)?
            .get_activity(activity_id)?
            .ok_or("Activity missing before projection read")?;
        let refreshed = ForgeControl::new(GlobalRegistry::open(&fixture.registry_path)?)
            .list_workspace_activity_projections(&WorkspaceActivityProjectionRequest {
                location_id: fixture.location_id,
                expected_location_revision: forge_domain::LocationRevision::INITIAL,
                locator: locator.clone(),
                expected_workspace_id: scope.workspace_id(),
                expected_workspace_revision: scope.workspace_revision(),
                now: timestamp(10)?,
                limit: ActivityListLimit::DEFAULT,
            })?;
        assert_eq!(refreshed.scope(), &scope);
        let projection = refreshed
            .activities()
            .iter()
            .find(|activity| activity.id() == activity_id)
            .ok_or("Activity projection missing")?;
        assert_eq!(projection.state(), forge_domain::ActivityState::Open);
        assert_eq!(projection.liveness(), ActivityLiveness::Expired);
        let after = WorkspaceStore::open_existing(&layout)?
            .get_activity(activity_id)?
            .ok_or("Activity missing after projection read")?;
        assert_eq!(after, before);
        let wrong_workspace = WorkspaceId::from_uuid(uuid::Uuid::from_u128(
            scope.workspace_id().into_uuid().as_u128().saturating_add(1),
        ));
        let identity_error = fixture.control.list_workspace_activity_projections(
            &WorkspaceActivityProjectionRequest {
                location_id: fixture.location_id,
                expected_location_revision: forge_domain::LocationRevision::INITIAL,
                locator: locator.clone(),
                expected_workspace_id: wrong_workspace,
                expected_workspace_revision: scope.workspace_revision(),
                now: timestamp(10)?,
                limit: ActivityListLimit::DEFAULT,
            },
        );
        assert_eq!(
            identity_error.err().map(|error| error.code()),
            Some(ControlErrorCode::WorkspaceIdentityConflict)
        );
        let revision_error = fixture.control.list_workspace_activity_projections(
            &WorkspaceActivityProjectionRequest {
                location_id: fixture.location_id,
                expected_location_revision: forge_domain::LocationRevision::INITIAL,
                locator: locator.clone(),
                expected_workspace_id: scope.workspace_id(),
                expected_workspace_revision: WorkspaceRevision::new(
                    scope.workspace_revision().get() + 1,
                )?,
                now: timestamp(10)?,
                limit: ActivityListLimit::DEFAULT,
            },
        );
        assert_eq!(
            revision_error.err().map(|error| error.code()),
            Some(ControlErrorCode::WorkspaceRevisionConflict)
        );
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn pending_control_reports_idle_ready_and_disconnected_without_blocking()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sender, receiver) = mpsc::sync_channel(1);
        let pending = PendingControl::from_receiver(receiver);
        assert!(pending.try_recv()?.is_none());
        sender.send(Ok(42_u32))?;
        assert_eq!(pending.try_recv()?.transpose()?, Some(42));

        let (sender, receiver) = mpsc::sync_channel(1);
        let disconnected = PendingControl::<u32>::from_receiver(receiver);
        drop(sender);
        assert!(matches!(
            disconnected.try_recv(),
            Err(ControlClientError::ResponseDropped)
        ));

        let fixture = fixture("pending-client", &[], 1)?;
        let locator = locator_for(&fixture.control, fixture.location_id, "workspace-0")?;
        let cleanup_root = fixture.root.clone();
        let location_id = fixture.location_id;
        let control = fixture.control;
        let (client, mut worker) = ForgeControlWorker::start(control)?;
        let pending = client.submit_list_workspace_activity_projections(
            WorkspaceActivityProjectionRequest {
                location_id,
                expected_location_revision: forge_domain::LocationRevision::INITIAL,
                locator,
                expected_workspace_id: WorkspaceId::from_uuid(id(0xB100)),
                expected_workspace_revision: WorkspaceRevision::INITIAL,
                now: timestamp(10)?,
                limit: ActivityListLimit::DEFAULT,
            },
        )?;
        let polled = pending.try_recv()?;
        if let Some(result) = polled {
            assert!(result.is_err());
        } else {
            assert!(pending.recv().is_err());
        }
        worker.shutdown()?;
        fs::remove_dir_all(cleanup_root)?;
        Ok(())
    }

    #[test]
    fn resolve_rejects_stale_location_revision_and_root_identity_mismatch()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("resolve", &[0], 1)?;
        let locator = locator_for(&fixture.control, fixture.location_id, "workspace-0")?;

        let resolved = fixture.control.resolve_workspace(
            fixture.location_id,
            forge_domain::LocationRevision::INITIAL,
            &locator,
        )?;
        assert_eq!(resolved.workspace_revision().get(), 1);

        let mut locations = LocationService::new(GlobalRegistry::open(&fixture.registry_path)?);
        let location = locations
            .get_location(fixture.location_id)?
            .ok_or("fixture Location missing")?;
        locations.set_location_state(&SetLocationState::new(
            fixture.location_id,
            location.revision(),
            LocationState::Disabled,
            timestamp(3)?,
        ))?;
        let stale = fixture.control.resolve_workspace(
            fixture.location_id,
            forge_domain::LocationRevision::INITIAL,
            &locator,
        );
        assert_eq!(
            stale.err().map(|error| error.code()),
            Some(ControlErrorCode::LocationRevisionConflict)
        );
        drop(locations);

        // Restore a fresh enabled Location for the root identity assertion.
        let mut locations = LocationService::new(GlobalRegistry::open(&fixture.registry_path)?);
        let location = locations
            .get_location(fixture.location_id)?
            .ok_or("fixture Location missing")?;
        locations.set_location_state(&SetLocationState::new(
            fixture.location_id,
            location.revision(),
            LocationState::Enabled,
            timestamp(4)?,
        ))?;
        drop(locations);

        let old_root = fixture.workspaces[0].clone();
        let moved_root = fixture.root.join("moved-workspace");
        fs::rename(&old_root, &moved_root)?;
        fs::create_dir_all(&old_root)?;
        fs::rename(
            moved_root.join(".heterarchy-forge"),
            old_root.join(".heterarchy-forge"),
        )?;
        let root_mismatch = fixture.control.resolve_workspace(
            fixture.location_id,
            forge_domain::LocationRevision::new(3)?,
            &forge_workspace::WorkspaceLocator::new(
                fixture.location_id,
                forge_domain::LocationRevision::new(3)?,
                "workspace-0",
            )?,
        );
        assert_eq!(
            root_mismatch.err().map(|error| error.code()),
            Some(ControlErrorCode::WorkspaceRootConflict)
        );
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn bootstrap_is_idempotent_and_leases_are_projected() -> Result<(), Box<dyn std::error::Error>>
    {
        let fixture = fixture("bootstrap", &[0], 1)?;
        let locator = locator_for(&fixture.control, fixture.location_id, "workspace-0")?;
        let scope = fixture.control.resolve_workspace(
            fixture.location_id,
            forge_domain::LocationRevision::INITIAL,
            &locator,
        )?;
        let activity_id = ActivityId::from_uuid(id(0x3000));
        let runtime_id = RuntimeInstanceId::from_uuid(id(0x4000));
        let first = fixture.control.bootstrap_activity(
            &scope,
            activity_id,
            runtime_id,
            timestamp(10)?,
            timestamp(20)?,
        )?;
        assert_eq!(first.status(), ActivityBootstrapStatus::Created);
        assert_eq!(
            first
                .activity()
                .map(forge_domain::RegisteredActivity::lease_owner_id),
            Some(Some(runtime_id))
        );
        let second = fixture.control.bootstrap_activity(
            &scope,
            activity_id,
            runtime_id,
            timestamp(11)?,
            timestamp(20)?,
        )?;
        assert_eq!(second.status(), ActivityBootstrapStatus::AlreadyOwned);
        assert_eq!(
            second.activity().map(forge_domain::RegisteredActivity::id),
            Some(activity_id)
        );
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn renew_rejects_different_owner_and_close_release_are_scoped()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("lease-ops", &[0], 1)?;
        let locator = locator_for(&fixture.control, fixture.location_id, "workspace-0")?;
        let scope = fixture.control.resolve_workspace(
            fixture.location_id,
            forge_domain::LocationRevision::INITIAL,
            &locator,
        )?;
        let activity_id = ActivityId::from_uuid(id(0x3100));
        let owner = RuntimeInstanceId::from_uuid(id(0x3200));
        let other_owner = RuntimeInstanceId::from_uuid(id(0x3300));
        let first = fixture.control.bootstrap_activity(
            &scope,
            activity_id,
            owner,
            timestamp(10)?,
            timestamp(20)?,
        )?;
        let first_activity = first.activity().ok_or("created Activity missing")?;
        let renewed = fixture.control.renew_activity_lease(
            &scope,
            activity_id,
            owner,
            first_activity.lease_revision(),
            timestamp(11)?,
            timestamp(30)?,
        )?;
        assert_eq!(renewed.status(), ActivityOperationStatus::Renewed);
        let renewed_activity = renewed.activity().ok_or("renewed Activity missing")?;
        assert_eq!(renewed_activity.lease_until(), Some(timestamp(30)?));

        let rejected = fixture.control.renew_activity_lease(
            &scope,
            activity_id,
            other_owner,
            renewed_activity.lease_revision(),
            timestamp(12)?,
            timestamp(40)?,
        );
        assert_eq!(
            rejected.err().map(|error| error.code()),
            Some(ControlErrorCode::ActivityLeaseConflict)
        );

        let released = fixture.control.release_activity_lease(
            &scope,
            activity_id,
            owner,
            renewed_activity.lease_revision(),
            timestamp(13)?,
        )?;
        assert_eq!(released.status(), ActivityOperationStatus::Released);
        assert_eq!(
            released
                .activity()
                .ok_or("released Activity missing")?
                .state(),
            forge_domain::ActivityState::Open
        );

        let close_id = ActivityId::from_uuid(id(0x3400));
        let close_bootstrap = fixture.control.bootstrap_activity(
            &scope,
            close_id,
            owner,
            timestamp(10)?,
            timestamp(20)?,
        )?;
        let close_activity = close_bootstrap.activity().ok_or("close Activity missing")?;
        let closed = fixture.control.close_activity(
            &scope,
            close_id,
            owner,
            close_activity.lease_revision(),
            timestamp(14)?,
        )?;
        assert_eq!(closed.status(), ActivityOperationStatus::Closed);
        assert_eq!(
            closed.activity().ok_or("closed Activity missing")?.state(),
            forge_domain::ActivityState::Closed
        );
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn supervised_lease_renew_authenticates_coordinator_session_before_workspace_open()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("supervised-lease-session-auth", &[0], 1)?;
        let locator = locator_for(&fixture.control, fixture.location_id, "workspace-0")?;
        let scope = fixture.control.resolve_workspace(
            fixture.location_id,
            forge_domain::LocationRevision::INITIAL,
            &locator,
        )?;
        let activity_id = ActivityId::from_uuid(id(0xA100));
        let owner = RuntimeInstanceId::from_uuid(id(0xA101));
        let request = SupervisedActivityLeaseRenewRequest {
            scope: scope.clone(),
            actor: ActivityCoordinatorActor::new(
                scope.workspace_id(),
                activity_id,
                forge_domain::AgentInstanceId::from_uuid(id(0xA102)),
                forge_domain::ActivityCoordinatorRevision::INITIAL,
                forge_domain::AuthenticatedPrincipal::TrustedStdio,
                forge_domain::AgentSessionId::from_uuid(id(0xA103)),
            ),
            goal_id: GoalId::from_uuid(id(0xA104)),
            goal_created_at: timestamp(1)?,
            command: RenewActivityLease::new(
                activity_id,
                owner,
                forge_domain::ActivityLeaseRevision::INITIAL,
                timestamp(20)?,
                timestamp(10)?,
            ),
        };
        let Err(error) = fixture.control.renew_supervised_activity_lease(&request) else {
            return Err("unauthenticated Session reached Source lease mutation".into());
        };
        assert_eq!(error.code(), ControlErrorCode::AgentSessionNotFound);
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn single_activity_uncertainty_preserves_zero_or_one_committed_projection()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("single-lease-unknown", &[0], 1)?;
        let locator = locator_for(&fixture.control, fixture.location_id, "workspace-0")?;
        let scope = fixture.control.resolve_workspace(
            fixture.location_id,
            forge_domain::LocationRevision::INITIAL,
            &locator,
        )?;
        let bootstrap = fixture.control.bootstrap_activity(
            &scope,
            ActivityId::from_uuid(id(0x3450)),
            RuntimeInstanceId::from_uuid(id(0x3460)),
            timestamp(10)?,
            timestamp(20)?,
        )?;
        let activity = bootstrap
            .activity()
            .ok_or("committed fixture Activity missing")?
            .clone();
        for status in [
            ActivityOperationStatus::Renewed,
            ActivityOperationStatus::Closed,
            ActivityOperationStatus::Released,
        ] {
            for rows in [Vec::new(), vec![activity.clone()]] {
                let expected = rows.first().cloned();
                let result = super::ActivityOperation::uncertain(scope.clone(), None, rows)
                    .into_single(status)?;
                assert_eq!(
                    result.status(),
                    ActivityOperationStatus::CommittedButUnconfirmed
                );
                assert!(result.is_committed());
                assert!(result.is_committed_but_unconfirmed());
                assert_eq!(result.activity(), expected.as_ref());
                assert!(result.activities().is_empty());
            }
        }
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn activity_lease_observation_preserves_exact_ids_and_is_bounded()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("activity-observation", &[0], 1)?;
        let locator = locator_for(&fixture.control, fixture.location_id, "workspace-0")?;
        let scope = fixture.control.resolve_workspace(
            fixture.location_id,
            forge_domain::LocationRevision::INITIAL,
            &locator,
        )?;
        let owner = RuntimeInstanceId::from_uuid(id(0x3500));
        let first_id = ActivityId::from_uuid(id(0x3501));
        let second_id = ActivityId::from_uuid(id(0x3502));
        let _ = fixture.control.bootstrap_activity(
            &scope,
            first_id,
            owner,
            timestamp(10)?,
            timestamp(20)?,
        )?;
        let _ = fixture.control.bootstrap_activity(
            &scope,
            second_id,
            owner,
            timestamp(10)?,
            timestamp(20)?,
        )?;

        let observed = fixture
            .control
            .observe_activity_leases(&scope, &[second_id, first_id, second_id])?;
        assert_eq!(
            observed
                .iter()
                .map(forge_domain::RegisteredActivity::id)
                .collect::<Vec<_>>(),
            vec![second_id, first_id, second_id]
        );

        let too_many = vec![first_id; MAX_ACTIVITY_LEASE_OBSERVATION_IDS + 1];
        assert_eq!(
            fixture
                .control
                .observe_activity_leases(&scope, &too_many)
                .err()
                .map(|error| error.code()),
            Some(ControlErrorCode::CapacityExceeded)
        );
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    type LeaseBatchInputs = (Vec<ActivityId>, Vec<RenewActivityLease>, Vec<CloseActivity>);

    fn create_lease_batch_inputs(
        control: &ForgeControl,
        scope: &ResolvedWorkspaceScope,
        owner: RuntimeInstanceId,
    ) -> Result<LeaseBatchInputs, Box<dyn std::error::Error>> {
        let mut ids = Vec::with_capacity(128);
        let mut renew_commands = Vec::with_capacity(128);
        let mut close_commands = Vec::with_capacity(128);
        for index in 0_u128..128 {
            let activity_id = ActivityId::from_uuid(id(0x5200 + index));
            let bootstrapped = control.bootstrap_activity(
                scope,
                activity_id,
                owner,
                timestamp(0)?,
                timestamp(100)?,
            )?;
            let activity = bootstrapped.activity().ok_or("batch Activity missing")?;
            ids.push(activity_id);
            renew_commands.push(RenewActivityLease::new(
                activity_id,
                owner,
                activity.lease_revision(),
                timestamp(200)?,
                timestamp(10)?,
            ));
            close_commands.push(CloseActivity::new(
                activity_id,
                owner,
                forge_domain::ActivityLeaseRevision::new(activity.lease_revision().get() + 1)?,
                timestamp(11)?,
            ));
        }
        Ok((ids, renew_commands, close_commands))
    }

    fn assert_mixed_batch_conflict(
        control: &ForgeControl,
        scope: &ResolvedWorkspaceScope,
        owner: RuntimeInstanceId,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let first_id = ActivityId::from_uuid(id(0x5300));
        let second_id = ActivityId::from_uuid(id(0x5301));
        let first =
            control.bootstrap_activity(scope, first_id, owner, timestamp(20)?, timestamp(30)?)?;
        let _second =
            control.bootstrap_activity(scope, second_id, owner, timestamp(20)?, timestamp(30)?)?;
        let mixed = vec![
            RenewActivityLease::new(
                first_id,
                owner,
                first
                    .activity()
                    .ok_or("first mixed Activity missing")?
                    .lease_revision(),
                timestamp(40)?,
                timestamp(21)?,
            ),
            RenewActivityLease::new(
                second_id,
                owner,
                forge_domain::ActivityLeaseRevision::new(999)?,
                timestamp(40)?,
                timestamp(21)?,
            ),
        ];
        let conflict = control.renew_activity_lease_batch(scope, &mixed);
        assert_eq!(
            conflict.err().map(|error| error.code()),
            Some(ControlErrorCode::ActivityLeaseConflict)
        );
        let projections =
            control.list_activity_projections(scope, timestamp(21)?, ActivityListLimit::DEFAULT)?;
        let first_after = projections
            .iter()
            .find(|projection| projection.id() == first_id)
            .ok_or("first mixed Activity projection missing")?;
        assert_eq!(first_after.activity().lease_until(), Some(timestamp(30)?));
        Ok(())
    }

    #[test]
    fn lease_batches_preserve_order_and_are_all_or_nothing()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("lease-batch", &[0], 1)?;
        let locator = locator_for(&fixture.control, fixture.location_id, "workspace-0")?;
        let scope = fixture.control.resolve_workspace(
            fixture.location_id,
            forge_domain::LocationRevision::INITIAL,
            &locator,
        )?;
        let owner = RuntimeInstanceId::from_uuid(id(0x5100));
        let (ids, renew_commands, close_commands) =
            create_lease_batch_inputs(&fixture.control, &scope, owner)?;
        let renewed = fixture
            .control
            .renew_activity_lease_batch(&scope, &renew_commands)?;
        assert_eq!(renewed.status(), ActivityOperationStatus::Renewed);
        assert_eq!(renewed.activities().len(), 128);
        assert!(
            renewed
                .activities()
                .iter()
                .zip(ids.iter())
                .all(|(activity, expected)| activity.id() == *expected)
        );
        let closed = fixture
            .control
            .close_owned_activity_batch(&scope, &close_commands)?;
        assert_eq!(closed.status(), ActivityOperationStatus::Closed);
        assert_eq!(closed.activities().len(), 128);
        assert_mixed_batch_conflict(&fixture.control, &scope, owner)?;
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn list_classifies_live_history_and_reconcile_is_the_only_expiry_transition()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("projection-reconcile", &[0], 1)?;
        let locator = locator_for(&fixture.control, fixture.location_id, "workspace-0")?;
        let scope = fixture.control.resolve_workspace(
            fixture.location_id,
            forge_domain::LocationRevision::INITIAL,
            &locator,
        )?;
        let owner = RuntimeInstanceId::from_uuid(id(0x4100));
        let live_id = ActivityId::from_uuid(id(0x4200));
        let expired_id = ActivityId::from_uuid(id(0x4300));
        let available_id = ActivityId::from_uuid(id(0x4400));
        let closed_id = ActivityId::from_uuid(id(0x4500));
        for (activity_id, lease_until) in [
            (live_id, 20),
            (expired_id, 5),
            (available_id, 20),
            (closed_id, 20),
        ] {
            let bootstrapped = fixture.control.bootstrap_activity(
                &scope,
                activity_id,
                owner,
                timestamp(0)?,
                timestamp(lease_until)?,
            )?;
            if activity_id == available_id {
                let activity = bootstrapped
                    .activity()
                    .ok_or("available Activity missing")?;
                let _ = fixture.control.release_activity_lease(
                    &scope,
                    activity_id,
                    owner,
                    activity.lease_revision(),
                    timestamp(1)?,
                )?;
            } else if activity_id == closed_id {
                let activity = bootstrapped.activity().ok_or("closed Activity missing")?;
                let _ = fixture.control.close_activity(
                    &scope,
                    activity_id,
                    owner,
                    activity.lease_revision(),
                    timestamp(1)?,
                )?;
            }
        }

        let projections = fixture.control.list_activity_projections(
            &scope,
            timestamp(10)?,
            ActivityListLimit::new(16)?,
        )?;
        let liveness = |activity_id| {
            projections
                .iter()
                .find(|projection| projection.id() == activity_id)
                .map(forge_domain::ActivityProjection::liveness)
        };
        assert_eq!(liveness(live_id), Some(ActivityLiveness::Live));
        assert_eq!(liveness(expired_id), Some(ActivityLiveness::Expired));
        assert_eq!(liveness(available_id), Some(ActivityLiveness::Available));
        assert_eq!(liveness(closed_id), Some(ActivityLiveness::Closed));

        let reconciled = fixture
            .control
            .reconcile_expired_activity_leases(&scope, timestamp(10)?)?;
        assert_eq!(reconciled.status(), ActivityOperationStatus::Reconciled);
        assert_eq!(reconciled.activities().len(), 1);
        assert_eq!(reconciled.activities()[0].id(), expired_id);
        assert_eq!(
            reconciled.activities()[0].state(),
            forge_domain::ActivityState::Interrupted
        );
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn separate_workspaces_do_not_share_activity_identity() -> Result<(), Box<dyn std::error::Error>>
    {
        let fixture = fixture("isolation", &[0, 1], 2)?;
        let entries = fixture
            .control
            .workspace_discover(fixture.location_id, forge_domain::LocationRevision::INITIAL)?;
        let mut locators = entries
            .iter()
            .filter(|entry| entry.display_name().starts_with("workspace-"))
            .map(|entry| entry.locator().clone());
        let first_locator = locators.next().ok_or("first workspace missing")?;
        let second_locator = locators.next().ok_or("second workspace missing")?;
        let first_scope = fixture.control.resolve_workspace(
            fixture.location_id,
            forge_domain::LocationRevision::INITIAL,
            &first_locator,
        )?;
        let second_scope = fixture.control.resolve_workspace(
            fixture.location_id,
            forge_domain::LocationRevision::INITIAL,
            &second_locator,
        )?;
        assert_ne!(first_scope.workspace_id(), second_scope.workspace_id());
        let activity_id = ActivityId::from_uuid(id(0x5000));
        let runtime_id = RuntimeInstanceId::from_uuid(id(0x6000));
        assert_eq!(
            fixture
                .control
                .bootstrap_activity(
                    &first_scope,
                    activity_id,
                    runtime_id,
                    timestamp(10)?,
                    timestamp(20)?,
                )?
                .status(),
            ActivityBootstrapStatus::Created
        );
        assert_eq!(
            fixture
                .control
                .bootstrap_activity(
                    &second_scope,
                    activity_id,
                    runtime_id,
                    timestamp(10)?,
                    timestamp(20)?,
                )?
                .status(),
            ActivityBootstrapStatus::Created
        );
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn post_commit_root_drift_returns_committed_but_unconfirmed()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("post-commit-drift", &[0], 1)?;
        let locator = locator_for(&fixture.control, fixture.location_id, "workspace-0")?;
        let scope = fixture.control.resolve_workspace(
            fixture.location_id,
            forge_domain::LocationRevision::INITIAL,
            &locator,
        )?;
        let moved_root = fixture.root.join("post-commit-moved");
        let original_root = fixture.workspaces[0].clone();
        let activity_id = ActivityId::from_uuid(id(0x7000));
        let move_succeeded = std::cell::Cell::new(false);
        let result = fixture.control.bootstrap_activity_impl(
            &scope,
            activity_id,
            RuntimeInstanceId::from_uuid(id(0x8000)),
            timestamp(10)?,
            timestamp(20)?,
            || {
                move_succeeded.set(fs::rename(&original_root, &moved_root).is_ok());
            },
        )?;
        assert!(move_succeeded.get());
        assert_eq!(
            result.status(),
            ActivityBootstrapStatus::CommittedButUnconfirmed
        );
        assert!(result.is_committed_but_unconfirmed());
        assert_eq!(
            result.activity().map(forge_domain::RegisteredActivity::id),
            Some(activity_id)
        );
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn worker_has_bounded_admission_and_joined_shutdown() -> Result<(), Box<dyn std::error::Error>>
    {
        let fixture = fixture("worker", &[], 1)?;
        let (client, mut worker) = ForgeControlWorker::start(fixture.control)?;
        assert_eq!(ForgeControlWorker::queue_capacity(), 128);
        let _ =
            client.workspace_list(fixture.location_id, forge_domain::LocationRevision::INITIAL)?;
        worker.shutdown()?;
        let error = client
            .workspace_list(fixture.location_id, forge_domain::LocationRevision::INITIAL)
            .err()
            .ok_or("client unexpectedly admitted work after shutdown")?;
        assert!(matches!(error, ControlClientError::WorkerShuttingDown));
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn workspace_queue_save_uses_worker_time_instead_of_caller_time()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("queue-worker-time", &[0], 1)?;
        let locator = locator_for(&fixture.control, fixture.location_id, "workspace-0")?;
        let cleanup_root = fixture.root.clone();
        let location_id = fixture.location_id;
        let (client, mut worker) = ForgeControlWorker::start(fixture.control)?;
        let scope = client.resolve_workspace(
            location_id,
            forge_domain::LocationRevision::INITIAL,
            locator,
        )?;
        let future =
            client.replace_workspace_queue_settings(crate::WorkspaceQueueSettingsRequest {
                scope: scope.clone(),
                settings: forge_persistence::QueueSettings::new(crate::QueueCapacity::C64),
                expected_revision: None,
                observed_at: timestamp(i64::MAX)?,
            })?;
        assert!(future.updated_at().get() > 1_000_000_000_000);
        assert_ne!(future.updated_at().get(), i64::MAX);
        let past =
            client.replace_workspace_queue_settings(crate::WorkspaceQueueSettingsRequest {
                scope: scope.clone(),
                settings: forge_persistence::QueueSettings::new(crate::QueueCapacity::C32),
                expected_revision: Some(future.revision()),
                observed_at: timestamp(0)?,
            })?;
        assert_eq!(past.revision().get(), future.revision().get() + 1);
        assert!(past.updated_at() >= future.updated_at());
        assert_eq!(client.workspace_queue_settings(scope)?, Some(past));
        worker.shutdown()?;
        fs::remove_dir_all(cleanup_root)?;
        Ok(())
    }

    #[test]
    fn worker_shutdown_closes_each_owned_activity_before_join()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("worker-owned-shutdown", &[0], 1)?;
        let locator = locator_for(&fixture.control, fixture.location_id, "workspace-0")?;
        let cleanup_root = fixture.root.clone();
        let location_id = fixture.location_id;
        let control = fixture.control;
        let (client, mut worker) = ForgeControlWorker::start(control)?;
        let scope = client.resolve_workspace(
            location_id,
            forge_domain::LocationRevision::INITIAL,
            locator,
        )?;
        let activity_id = ActivityId::from_uuid(id(0x9100));
        let runtime_id = RuntimeInstanceId::from_uuid(id(0x9200));
        let bootstrapped = client.bootstrap_activity(
            scope.clone(),
            activity_id,
            runtime_id,
            timestamp(10)?,
            timestamp(60_010)?,
        )?;
        let activity = bootstrapped.activity().ok_or("worker Activity missing")?;
        assert!(activity.created_at().get() > 1_000_000_000_000);
        assert_eq!(
            activity
                .lease_until()
                .ok_or("worker lease expiry missing")?
                .get()
                - activity.created_at().get(),
            60_000
        );
        let renewed = client.renew_activity_lease(
            scope.clone(),
            activity_id,
            runtime_id,
            activity.lease_revision(),
            timestamp(11)?,
            timestamp(60_011)?,
        )?;
        assert_eq!(renewed.status(), ActivityOperationStatus::Renewed);
        let renewed_activity = renewed.activity().ok_or("worker renewal missing")?;
        let projections = client.list_activity_projections(
            scope.clone(),
            timestamp(12)?,
            ActivityListLimit::DEFAULT,
        )?;
        assert_eq!(projections.len(), 1);
        let report = worker.shutdown_owned(vec![OwnedActivityLease::new(
            scope,
            activity_id,
            runtime_id,
            renewed_activity.lease_revision(),
            timestamp(13)?,
        )])?;
        assert_eq!(report.attempted(), 1);
        assert_eq!(report.closed(), 1);
        assert_eq!(report.committed_but_unconfirmed(), 0);
        assert!(report.failures().is_empty());
        let closed = client
            .close_activity(
                bootstrapped.scope().clone(),
                activity_id,
                runtime_id,
                activity.lease_revision(),
            )
            .err()
            .ok_or("client unexpectedly admitted after owned shutdown")?;
        assert!(matches!(closed, ControlClientError::WorkerShuttingDown));
        fs::remove_dir_all(cleanup_root)?;
        Ok(())
    }

    #[test]
    fn worker_batch_requests_support_blocking_and_pending_paths()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("worker-batch", &[0], 1)?;
        let locator = locator_for(&fixture.control, fixture.location_id, "workspace-0")?;
        let cleanup_root = fixture.root.clone();
        let location_id = fixture.location_id;
        let control = fixture.control;
        let (client, mut worker) = ForgeControlWorker::start(control)?;
        let scope = client.resolve_workspace(
            location_id,
            forge_domain::LocationRevision::INITIAL,
            locator,
        )?;
        let owner = RuntimeInstanceId::from_uuid(id(0xA900));
        let mut renewals = Vec::new();
        let mut closes = Vec::new();
        for offset in 0_u128..2 {
            let activity_id = ActivityId::from_uuid(id(0xAA00 + offset));
            let bootstrapped = client.bootstrap_activity(
                scope.clone(),
                activity_id,
                owner,
                timestamp(0)?,
                timestamp(60_000)?,
            )?;
            let activity = bootstrapped
                .activity()
                .ok_or("worker batch Activity missing")?;
            renewals.push(RenewActivityLease::new(
                activity_id,
                owner,
                activity.lease_revision(),
                timestamp(60_010)?,
                timestamp(10)?,
            ));
            closes.push(CloseActivity::new(
                activity_id,
                owner,
                forge_domain::ActivityLeaseRevision::new(activity.lease_revision().get() + 1)?,
                timestamp(11)?,
            ));
        }
        let renewed = client.renew_activity_lease_batch(scope.clone(), renewals)?;
        assert_eq!(renewed.activities().len(), 2);
        let pending = client.submit_close_owned_activity_batch(scope, closes)?;
        let closed_batch = pending.recv()?;
        assert_eq!(closed_batch.status(), ActivityOperationStatus::Closed);
        assert_eq!(closed_batch.activities().len(), 2);
        worker.shutdown()?;
        fs::remove_dir_all(cleanup_root)?;
        Ok(())
    }

    #[test]
    fn control_worker_round_trips_coordinator_owned_dag_plan_and_node_lifecycle()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("dag-worker", &[0], 1)?;
        let locator = locator_for(&fixture.control, fixture.location_id, "workspace-0")?;
        let cleanup_root = fixture.root.clone();
        let (client, mut worker) = ForgeControlWorker::start(fixture.control)?;
        let scope = client.resolve_workspace(
            fixture.location_id,
            forge_domain::LocationRevision::INITIAL,
            locator,
        )?;
        let activity_id = ActivityId::from_uuid(id(0xEA13));
        let owner = RuntimeInstanceId::from_uuid(id(0xEA14));
        let _activity = client.bootstrap_activity(
            scope.clone(),
            activity_id,
            owner,
            timestamp(8)?,
            timestamp(60_000)?,
        )?;
        let agent_id = forge_domain::AgentInstanceId::from_uuid(id(0xEA15));
        let coordinator_actor = claim_stdio_coordinator(
            &client,
            &scope,
            activity_id,
            agent_id,
            "DAG planner",
            timestamp(9)?,
        )?;
        let initial = create_initial_coordinator_dag_plan_fixture(
            &client,
            &scope,
            activity_id,
            coordinator_actor,
        )?;
        let successor_nodes = transfer_and_commit_successor_dag(
            &client,
            &scope,
            activity_id,
            agent_id,
            coordinator_actor,
            &initial,
        )?;

        let active = client.dag_node_start(DagNodeStartRequest {
            scope: scope.clone(),
            activity_id,
            session_id: coordinator_actor.session_id(),
            principal: coordinator_actor.principal(),
            goal_id: initial.goal.id(),
            expected_goal_revision: initial.goal.revision(),
            expected_dag_revision: successor_nodes[0].dag_revision(),
            node_id: successor_nodes[0].id(),
            expected_revision: successor_nodes[0].revision(),
            observed_at: timestamp(14)?,
        })?;
        let completed = active.complete(active.revision(), timestamp(15)?)?;
        assert_eq!(
            client.dag_node_update(DagNodeUpdateRequest {
                scope,
                node: completed.clone(),
                expected_revision: active.revision(),
            })?,
            completed
        );
        worker.shutdown()?;
        fs::remove_dir_all(cleanup_root)?;
        Ok(())
    }

    #[test]
    fn execution_supervisor_and_control_worker_complete_without_blocking_leases()
    -> Result<(), Box<dyn std::error::Error>> {
        if nested_sandbox_execution_is_unavailable() {
            return Ok(());
        }
        let fixture = fixture("worker-execution-supervisor", &[0], 1)?;
        let locator = locator_for(&fixture.control, fixture.location_id, "workspace-0")?;
        let cleanup_root = fixture.root.clone();
        let location_id = fixture.location_id;
        let (client, mut worker) = ForgeControlWorker::start(fixture.control)?;
        let scope = client.resolve_workspace(
            location_id,
            forge_domain::LocationRevision::INITIAL,
            locator,
        )?;
        let activity_id = ActivityId::from_uuid(id(0xEB01));
        let owner = RuntimeInstanceId::from_uuid(id(0xEB02));
        let bootstrapped = client.bootstrap_activity(
            scope.clone(),
            activity_id,
            owner,
            timestamp(0)?,
            timestamp(60_000)?,
        )?;
        let activity = bootstrapped
            .activity()
            .ok_or("execution Activity missing")?;
        let observed_at = activity.created_at();
        let execution_id = ExecutionId::from_uuid(id(0xEB03));
        let request = sleeping_execution_request(execution_id, scope.workspace_id(), activity_id)?;
        let mut execution_coordinator = ForgeExecutionCoordinator::start(client.clone(), 1)?;
        let execution_client = execution_coordinator.client();
        let mut approval_coordinator =
            ForgeApprovalCoordinator::start(client.clone(), execution_client.clone())?;
        let approval_client = approval_coordinator.client();
        let (goal, coordinator_actor) = create_supervisor_goal(&client, &scope, activity_id)?;
        let submitted = approval_client.submit_execution(
            SubmitExecutionForApproval::direct(scope.clone(), activity_id, owner, request)
                .with_goal(GoalAttribution::new(goal.id(), goal.revision())),
        )?;
        assert_eq!(submitted.status(), ApprovalSubmissionStatus::Pending);
        assert_eq!(approval_client.list_pending(scope.clone())?.len(), 1);
        let pending_review = client.goal_review(scope.clone(), activity_id, goal.id())?;
        assert!(pending_review.blockers().iter().any(|blocker| matches!(
            blocker,
            forge_domain::GoalCompletionBlocker::PendingApproval(_)
        )));
        approval_client.approve_once(submitted.approval_id())?;

        // The synchronous control owner remains responsive because it never
        // waits on the long-running process handle.
        assert_eq!(
            client
                .list_activity_projections(scope.clone(), observed_at, ActivityListLimit::DEFAULT,)?
                .len(),
            1
        );
        assert_eq!(approval_client.emergency_stop()?, 1);
        let completed = client
            .execution_get(scope.clone(), execution_id)?
            .ok_or("coordinator terminal record missing")?;
        assert_eq!(completed.state(), forge_domain::ExecutionState::Cancelled);
        assert!(
            client
                .goal_review(scope.clone(), activity_id, goal.id())?
                .can_complete()
        );
        let completed_goal = client.goal_complete(GoalCompletionRequest {
            scope,
            activity_id,
            actor: coordinator_actor,
            goal_id: goal.id(),
            expected_revision: goal.revision(),
            review_id: id(0xEB05),
            observed_at: timestamp(70_000)?,
        })?;
        assert_eq!(
            completed_goal.status().kind(),
            forge_domain::GoalStatusKind::Completed
        );
        let approval_report = approval_coordinator.shutdown()?;
        assert_eq!(approval_report.pending_cancelled(), 0);
        let report = execution_coordinator.shutdown()?;
        assert_eq!(report.terminal_records(), 1);
        worker.shutdown()?;
        fs::remove_dir_all(cleanup_root)?;
        Ok(())
    }

    #[test]
    fn explicit_approval_runs_structured_process_to_durable_success()
    -> Result<(), Box<dyn std::error::Error>> {
        if nested_sandbox_execution_is_unavailable() {
            return Ok(());
        }
        let fixture = fixture("explicit-approval-success", &[0], 1)?;
        let workspace_root = fixture.workspaces[0].clone();
        let locator = locator_for(&fixture.control, fixture.location_id, "workspace-0")?;
        let cleanup_root = fixture.root.clone();
        let location_id = fixture.location_id;
        let (client, mut worker) = ForgeControlWorker::start(fixture.control)?;
        let scope = client.resolve_workspace(
            location_id,
            forge_domain::LocationRevision::INITIAL,
            locator,
        )?;
        let activity_id = ActivityId::from_uuid(id(0xEBD1));
        let owner = RuntimeInstanceId::from_uuid(id(0xEBD2));
        let bootstrap = client.bootstrap_activity(
            scope.clone(),
            activity_id,
            owner,
            timestamp(0)?,
            timestamp(60_000)?,
        )?;
        let _activity = bootstrap
            .activity()
            .ok_or("explicit approval Activity missing")?;
        let execution_id = ExecutionId::from_uuid(id(0xEBD3));
        let request = ExecutionRequest::new(
            ExecutionAttribution::new(execution_id, scope.workspace_id(), activity_id),
            ExecutionKind::Structured {
                program: ExecutionProgram::new(PathBuf::from("/usr/bin/printf"))?,
                arguments: vec![ExecutionArgument::new(OsString::from("approved\n"))?],
            },
            None,
            ExecutionLimits::new(
                ExecutionTimeoutMillis::new(2_000)?,
                ExecutionOutputLimit::new(1_024)?,
            ),
            ExecutionPermissions::new(false, false, false),
        )?;
        let mut execution_coordinator = ForgeExecutionCoordinator::start(client.clone(), 1)?;
        let mut approval_coordinator =
            ForgeApprovalCoordinator::start(client.clone(), execution_coordinator.client())?;
        let approval_client = approval_coordinator.client();
        let submitted = approval_client.submit_execution(SubmitExecutionForApproval::direct(
            scope.clone(),
            activity_id,
            owner,
            request,
        ))?;
        assert_eq!(submitted.status(), ApprovalSubmissionStatus::Pending);
        assert_eq!(approval_client.list_pending(scope.clone())?.len(), 1);
        assert_eq!(
            approval_client.approve_once(submitted.approval_id())?,
            execution_id
        );

        let completed = wait_for_terminal_execution(&client, &scope, execution_id)?;
        assert_eq!(completed.state(), forge_domain::ExecutionState::Completed);
        let outcome = completed
            .outcome()
            .ok_or("approved execution outcome missing")?;
        assert_eq!(
            outcome.status(),
            forge_domain::ExecutionCompletionStatus::Exited
        );
        assert_eq!(outcome.exit_code(), Some(0));
        assert_eq!(outcome.stdout().retained(), b"approved\n");
        assert_eq!(outcome.stdout().total_bytes(), 9);
        assert!(!outcome.stdout().truncated());
        assert!(outcome.stderr().retained().is_empty());
        assert_eq!(outcome.stderr().total_bytes(), 0);
        assert!(!outcome.stderr().truncated());
        assert!(approval_client.list_pending(scope)?.is_empty());

        let approval_report = approval_coordinator.shutdown()?;
        assert_eq!(approval_report.pending_cancelled(), 0);
        let execution_report = execution_coordinator.shutdown()?;
        assert_eq!(execution_report.terminal_records(), 1);
        worker.shutdown()?;

        let layout = WorkspaceStateLayout::inspect_existing(&workspace_root)?
            .ok_or("explicit approval layout missing")?;
        let store = WorkspaceStore::open_existing(&layout)?;
        let approval = store
            .get_approval_request(submitted.approval_id())?
            .ok_or("approved audit record missing")?;
        assert_eq!(
            approval.state(),
            forge_domain::ApprovalRequestState::Approved
        );
        let durable_execution = store
            .get_execution(execution_id)?
            .ok_or("durable approved execution missing")?;
        assert_eq!(durable_execution, completed);

        fs::remove_dir_all(cleanup_root)?;
        Ok(())
    }

    #[test]
    fn attributed_execution_projects_goal_and_dag_evidence_without_auto_completing_node()
    -> Result<(), Box<dyn std::error::Error>> {
        if nested_sandbox_execution_is_unavailable() {
            return Ok(());
        }
        let fixture = fixture("goal-dag-execution-evidence", &[0], 1)?;
        let workspace_root = fixture.workspaces[0].clone();
        let locator = locator_for(&fixture.control, fixture.location_id, "workspace-0")?;
        let cleanup_root = fixture.root.clone();
        let (client, mut worker) = ForgeControlWorker::start(fixture.control)?;
        let scope = client.resolve_workspace(
            fixture.location_id,
            forge_domain::LocationRevision::INITIAL,
            locator,
        )?;
        let activity_id = ActivityId::from_uuid(id(0xEBC4));
        let owner = RuntimeInstanceId::from_uuid(id(0xEBC5));
        let _activity = client
            .bootstrap_activity(
                scope.clone(),
                activity_id,
                owner,
                timestamp(0)?,
                timestamp(60_000)?,
            )?
            .activity()
            .cloned()
            .ok_or("Goal/DAG execution Activity missing")?;
        let execution_id = ExecutionId::from_uuid(id(0xEBC6));
        let request =
            successful_execution_request(execution_id, scope.workspace_id(), activity_id)?;
        let (goal, active, coordinator_actor) =
            create_active_execution_goal_node(&client, &scope, &request)?;
        let attribution = GoalNodeAttribution::new(
            goal.id(),
            goal.revision(),
            active.dag_revision(),
            active.id(),
            active.revision(),
        );
        let mut execution_coordinator = ForgeExecutionCoordinator::start(client.clone(), 1)?;
        let mut approval_coordinator =
            ForgeApprovalCoordinator::start(client.clone(), execution_coordinator.client())?;
        let approval_client = approval_coordinator.client();
        let submitted = approval_client.submit_execution(
            SubmitExecutionForApproval::direct(scope.clone(), activity_id, owner, request)
                .with_goal_node(attribution),
        )?;
        assert_eq!(submitted.status(), ApprovalSubmissionStatus::Pending);
        assert_single_node_dag_projection(
            &client,
            &scope,
            goal.id(),
            1,
            &forge_domain::DagNodeLifecycle::Active,
        )?;
        assert_pending_approval_blocker(
            &client,
            &scope,
            activity_id,
            goal.id(),
            submitted.approval_id(),
        )?;

        assert_eq!(
            approval_client.approve_once(submitted.approval_id())?,
            execution_id
        );
        let completed_execution = wait_for_terminal_execution(&client, &scope, execution_id)?;
        assert_eq!(
            completed_execution.state(),
            forge_domain::ExecutionState::Completed
        );
        assert_single_node_dag_projection(
            &client,
            &scope,
            goal.id(),
            2,
            &forge_domain::DagNodeLifecycle::Active,
        )?;
        let review = client.goal_review(scope.clone(), activity_id, goal.id())?;
        assert!(
            review
                .hard_checks()
                .iter()
                .all(forge_domain::GoalHardCheck::is_passed)
        );
        assert!(review.blockers().is_empty());
        complete_attributed_goal_node(&client, &scope, coordinator_actor, &goal, &active)?;

        let approval_report = approval_coordinator.shutdown()?;
        assert_eq!(approval_report.pending_cancelled(), 0);
        let execution_report = execution_coordinator.shutdown()?;
        assert_eq!(execution_report.terminal_records(), 1);
        worker.shutdown()?;
        assert_durable_goal_dag_evidence(
            &workspace_root,
            goal.id(),
            submitted.approval_id(),
            execution_id,
        )?;
        fs::remove_dir_all(cleanup_root)?;
        Ok(())
    }

    fn prepare_discovered_command_authority(
        client: &crate::ForgeControlClient,
        scope: &ResolvedWorkspaceScope,
        activity_id: ActivityId,
        runtime_instance_id: RuntimeInstanceId,
        request: &ExecutionRequest,
    ) -> Result<
        (
            GoalNodeAttribution,
            AgentExecutionAuthorityRequest,
            ProjectCommandEvidence,
            ExecutionRequest,
        ),
        Box<dyn std::error::Error>,
    > {
        let command_snapshot = client.project_command_list(ProjectCommandListRequest {
            scope: scope.clone(),
            activity: FileActivityScope {
                activity_id,
                runtime_instance_id,
                observed_at: timestamp(4)?,
            },
        })?;
        let resolved = command_snapshot
            .resolve_execution(&ProjectCommandId::new("make:ci".to_owned())?, request.id())?;
        let command_evidence =
            ProjectCommandEvidence::new(resolved.class(), resolved.fingerprint());
        let resolved_request = resolved.request().clone();
        let (goal, node, actor) =
            create_active_execution_goal_node(client, scope, &resolved_request)?;
        let focus = AgentFocus::new(
            Some(GoalAttribution::new(goal.id(), goal.revision())),
            Some(node.dag_revision()),
            Some(AgentFocusNode::new(node.id(), node.revision())),
        )?;
        let focused = client.agent_set_focus(crate::AgentFocusRequest {
            scope: scope.clone(),
            activity_id,
            actor,
            agent_id: actor.agent_id(),
            expected_revision: AgentInstanceRevision::INITIAL,
            focus,
            observed_at: timestamp(4)?,
        })?;
        let attribution = GoalNodeAttribution::new(
            goal.id(),
            goal.revision(),
            node.dag_revision(),
            node.id(),
            node.revision(),
        );
        let authority = AgentExecutionAuthorityRequest {
            session_id: forge_domain::AgentSessionId::from_uuid(focused.id().into_uuid()),
            scope: scope.clone(),
            activity_id,
            agent_id: focused.id(),
            expected_revision: focused.revision(),
            principal: AuthenticatedPrincipal::TrustedStdio,
            attribution,
            command_id: ExecutionCommandId::new("make:ci".to_owned())?,
        };
        Ok((attribution, authority, command_evidence, resolved_request))
    }

    #[test]
    fn bounded_auto_approval_starts_discovered_and_analyzed_shell_and_leaves_audit()
    -> Result<(), Box<dyn std::error::Error>> {
        if nested_sandbox_execution_is_unavailable() {
            return Ok(());
        }
        let fixture = fixture("auto-approval", &[0], 1)?;
        let cleanup_root = fixture.root.clone();
        let result = exercise_auto_approval_audit(fixture);
        let cleanup = cleanup_test_root(cleanup_root);
        if let Err(error) = result {
            let mut cause = error.source();
            for depth in 0..8 {
                let Some(current) = cause else { break };
                eprintln!("auto approval cause[{depth}]: {current}");
                cause = current.source();
            }
            if let Err(cleanup_error) = cleanup {
                eprintln!("auto approval fixture cleanup also failed: {cleanup_error}");
            }
            return Err(error);
        }
        cleanup
    }

    #[allow(clippy::too_many_lines)]
    fn exercise_auto_approval_audit(fixture: Fixture) -> Result<(), Box<dyn std::error::Error>> {
        let workspace_root = fixture.workspaces[0].clone();
        let locator = locator_for(&fixture.control, fixture.location_id, "workspace-0")?;
        let location_id = fixture.location_id;
        let (client, mut worker) = ForgeControlWorker::start(fixture.control)?;
        let scope = client.resolve_workspace(
            location_id,
            forge_domain::LocationRevision::INITIAL,
            locator,
        )?;
        let activity_id = ActivityId::from_uuid(id(0xEC01));
        let owner = RuntimeInstanceId::from_uuid(id(0xEC02));
        let bootstrap = client.bootstrap_activity(
            scope.clone(),
            activity_id,
            owner,
            timestamp(0)?,
            timestamp(60_000)?,
        )?;
        assert!(bootstrap.activity().is_some());
        fs::write(fixture.workspaces[0].join("Makefile"), "ci:\n\t@true\n")?;
        let capability = prepare_test_rust_ci_capability(&fixture.root)?;
        let mut execution_coordinator = ForgeExecutionCoordinator::start_with_rust_ci_capability(
            client.clone(),
            2,
            Some(capability),
        )?;
        let mut approval_coordinator =
            ForgeApprovalCoordinator::start(client.clone(), execution_coordinator.client())?;
        let approval_client = approval_coordinator.client();
        assert!(
            approval_client
                .submit_set_auto_approval(scope.clone(), true)?
                .recv()?
        );
        let execution_id = ExecutionId::from_uuid(id(0xEC03));
        let request = ExecutionRequest::new(
            ExecutionAttribution::new(execution_id, scope.workspace_id(), activity_id),
            ExecutionKind::Structured {
                program: ExecutionProgram::new(PathBuf::from(crate::command::RUST_CI_PROGRAM))?,
                arguments: vec![ExecutionArgument::new(OsString::from("ci"))?],
            },
            None,
            ExecutionLimits::new(
                ExecutionTimeoutMillis::new(1_000)?,
                ExecutionOutputLimit::new(1_024)?,
            ),
            ExecutionPermissions::new(true, false, false),
        )?;
        let (attribution, authority, command_evidence, command_request) =
            prepare_discovered_command_authority(&client, &scope, activity_id, owner, &request)?;
        let mut shell_authority = authority.clone();
        let submission = approval_client.submit_execution(
            SubmitExecutionForApproval::project_command(
                scope.clone(),
                activity_id,
                owner,
                command_request,
                command_evidence,
            )?
            .with_goal_node(attribution)
            .with_agent_authority(authority),
        )?;
        assert_eq!(submission.status(), ApprovalSubmissionStatus::Started);

        let analyzed = crate::shell::analyze_shell_script("printf auto-shell".to_owned())?;
        let shell_execution_id = ExecutionId::from_uuid(id(0xEC04));
        let shell_request = ExecutionRequest::new(
            ExecutionAttribution::new(shell_execution_id, scope.workspace_id(), activity_id),
            ExecutionKind::Shell {
                script: analyzed.script().clone(),
            },
            None,
            ExecutionLimits::new(
                ExecutionTimeoutMillis::new(1_000)?,
                ExecutionOutputLimit::new(1_024)?,
            ),
            analyzed.permissions(),
        )?;
        shell_authority.command_id = analyzed.intent_id().clone();
        let shell_attribution = shell_authority.attribution;
        let shell_submission = approval_client.submit_execution(
            SubmitExecutionForApproval::analyzed_shell(scope, activity_id, owner, shell_request)?
                .with_goal_node(shell_attribution)
                .with_agent_authority(shell_authority),
        )?;
        assert_eq!(shell_submission.status(), ApprovalSubmissionStatus::Started);
        let _cancelled = approval_client.emergency_stop()?;
        let _approval_report = approval_coordinator.shutdown()?;
        let _execution_report = execution_coordinator.shutdown()?;
        worker.shutdown()?;

        let layout = WorkspaceStateLayout::inspect_existing(&workspace_root)?
            .ok_or("auto approval layout missing")?;
        let store = WorkspaceStore::open_existing(&layout)?;
        for (approval_id, execution_id) in [
            (submission.approval_id(), execution_id),
            (shell_submission.approval_id(), shell_execution_id),
        ] {
            assert_auto_approval_audit(&store, approval_id, execution_id)?;
        }
        drop(store);
        Ok(())
    }

    fn assert_auto_approval_audit(
        store: &WorkspaceStore,
        approval_id: forge_domain::ApprovalRequestId,
        execution_id: ExecutionId,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let approval = store
            .get_approval_request(approval_id)?
            .ok_or("auto approval audit missing")?;
        assert_eq!(
            approval.state(),
            forge_domain::ApprovalRequestState::AutoApproved
        );
        let execution = store
            .get_execution(execution_id)?
            .ok_or("auto approved execution missing")?;
        assert!(execution.state().is_terminal());
        Ok(())
    }
}
