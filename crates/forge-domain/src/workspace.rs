use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use crate::location::{LocationId, TimestampMillis};
use thiserror::Error;
use uuid::Uuid;

const MAX_ACTIVITY_LIST_LIMIT: u32 = 1_000;
pub const MAX_ACTIVITY_LEASE_BATCH: u32 = 256;

/// Stable opaque identity for a durable Workspace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct WorkspaceId(Uuid);

impl WorkspaceId {
    pub const fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }

    pub const fn into_uuid(self) -> Uuid {
        self.0
    }
}

impl fmt::Display for WorkspaceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for WorkspaceId {
    type Err = WorkspaceIdParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(value)
            .map(Self)
            .map_err(WorkspaceIdParseError::InvalidUuid)
    }
}

#[derive(Debug, Error)]
pub enum WorkspaceIdParseError {
    #[error("invalid Workspace UUID")]
    InvalidUuid(#[source] uuid::Error),
}

/// Stable opaque identity for an application Activity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ActivityId(Uuid);

impl ActivityId {
    pub const fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }

    pub const fn into_uuid(self) -> Uuid {
        self.0
    }
}

impl fmt::Display for ActivityId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for ActivityId {
    type Err = ActivityIdParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(value)
            .map(Self)
            .map_err(ActivityIdParseError::InvalidUuid)
    }
}

#[derive(Debug, Error)]
pub enum ActivityIdParseError {
    #[error("invalid Activity UUID")]
    InvalidUuid(#[source] uuid::Error),
}

/// Stable identity for one running Forge runtime instance.
///
/// A runtime instance is deliberately distinct from both the durable
/// `ActivityId` and the owning `WorkspaceId`.  It is supplied by the runtime
/// boundary and persisted only as a lease owner; the domain never generates
/// one or reads process state itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RuntimeInstanceId(Uuid);

impl RuntimeInstanceId {
    pub const fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }

    pub const fn into_uuid(self) -> Uuid {
        self.0
    }
}

impl fmt::Display for RuntimeInstanceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for RuntimeInstanceId {
    type Err = RuntimeInstanceIdParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(value)
            .map(Self)
            .map_err(RuntimeInstanceIdParseError::InvalidUuid)
    }
}

#[derive(Debug, Error)]
pub enum RuntimeInstanceIdParseError {
    #[error("invalid runtime instance UUID")]
    InvalidUuid(#[source] uuid::Error),
}

/// Absolute filesystem identity observed as canonical at effect ingress.
///
/// Constructing this value performs no filesystem I/O. The effect boundary
/// must canonicalize and validate the path before calling `from_canonical`;
/// the domain only preserves the observed absolute value.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct WorkspaceRoot(PathBuf);

impl WorkspaceRoot {
    /// Wrap an absolute path already canonicalized by an effect boundary.
    pub fn from_canonical(path: PathBuf) -> Result<Self, WorkspaceRootError> {
        if !path.is_absolute() {
            return Err(WorkspaceRootError::NotAbsolute(path));
        }
        Ok(Self(path))
    }

    pub fn as_path(&self) -> &Path {
        &self.0
    }

    pub fn into_path_buf(self) -> PathBuf {
        self.0
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum WorkspaceRootError {
    #[error("Workspace root must be an absolute canonical path: {0}")]
    NotAbsolute(PathBuf),
}

/// Fixed-width physical identity observed for a Workspace root.
///
/// The domain treats this as opaque evidence. It never derives, reads, or
/// revalidates the fingerprint itself; platform/filesystem adapters own that
/// observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct WorkspaceRootFingerprint([u8; 16]);

impl WorkspaceRootFingerprint {
    pub const fn from_bytes(value: [u8; 16]) -> Self {
        Self(value)
    }

    pub const fn into_bytes(self) -> [u8; 16] {
        self.0
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Monotonic revision for a durable Workspace projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WorkspaceRevision(i64);

impl WorkspaceRevision {
    pub const INITIAL: Self = Self(1);

    pub const fn new(value: i64) -> Result<Self, WorkspaceRevisionError> {
        if value < 1 {
            Err(WorkspaceRevisionError::Invalid { actual: value })
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> i64 {
        self.0
    }

    pub const fn checked_next(self) -> Result<Self, WorkspaceRevisionError> {
        match self.0.checked_add(1) {
            Some(value) => Ok(Self(value)),
            None => Err(WorkspaceRevisionError::Overflow { current: self.0 }),
        }
    }
}

impl fmt::Display for WorkspaceRevision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceRevisionError {
    #[error("Workspace revision must be at least 1, got {actual}")]
    Invalid { actual: i64 },
    #[error("Workspace revision overflowed at {current}")]
    Overflow { current: i64 },
}

/// Monotonic revision for a durable Activity projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ActivityRevision(i64);

impl ActivityRevision {
    pub const INITIAL: Self = Self(1);

    pub const fn new(value: i64) -> Result<Self, ActivityRevisionError> {
        if value < 1 {
            Err(ActivityRevisionError::Invalid { actual: value })
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> i64 {
        self.0
    }

    pub const fn checked_next(self) -> Result<Self, ActivityRevisionError> {
        match self.0.checked_add(1) {
            Some(value) => Ok(Self(value)),
            None => Err(ActivityRevisionError::Overflow { current: self.0 }),
        }
    }
}

impl fmt::Display for ActivityRevision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ActivityRevisionError {
    #[error("Activity revision must be at least 1, got {actual}")]
    Invalid { actual: i64 },
    #[error("Activity revision overflowed at {current}")]
    Overflow { current: i64 },
}

/// Monotonic compare-and-set revision for an Activity lease.
///
/// This revision is independent of `ActivityRevision`: a lease may be
/// renewed without changing the Activity's semantic lifecycle revision, and
/// a lifecycle transition always invalidates stale lease observations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ActivityLeaseRevision(i64);

impl ActivityLeaseRevision {
    pub const INITIAL: Self = Self(1);

    pub const fn new(value: i64) -> Result<Self, ActivityLeaseRevisionError> {
        if value < 1 {
            Err(ActivityLeaseRevisionError::Invalid { actual: value })
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> i64 {
        self.0
    }

    pub const fn checked_next(self) -> Result<Self, ActivityLeaseRevisionError> {
        match self.0.checked_add(1) {
            Some(value) => Ok(Self(value)),
            None => Err(ActivityLeaseRevisionError::Overflow { current: self.0 }),
        }
    }
}

impl fmt::Display for ActivityLeaseRevision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ActivityLeaseRevisionError {
    #[error("Activity lease revision must be at least 1, got {actual}")]
    Invalid { actual: i64 },
    #[error("Activity lease revision overflowed at {current}")]
    Overflow { current: i64 },
}

/// Durable lifecycle state for an Activity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActivityState {
    Open,
    Closed,
    /// The previous runtime lease expired before the runtime could commit a
    /// terminal close.  Interrupted is terminal and cannot be revived.
    Interrupted,
}

/// Persisted lease observation attached to an Activity projection.
///
/// `owner_id` and `lease_until` are an all-null or all-present pair at the
/// `SQLite` boundary.  The constructor below preserves that invariant for
/// callers that build projections in deterministic tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivityLeaseProjection {
    owner_id: Option<RuntimeInstanceId>,
    lease_until: Option<TimestampMillis>,
    revision: ActivityLeaseRevision,
}

impl ActivityLeaseProjection {
    pub const fn unleased() -> Self {
        Self {
            owner_id: None,
            lease_until: None,
            revision: ActivityLeaseRevision::INITIAL,
        }
    }

    pub const fn from_parts(
        owner_id: Option<RuntimeInstanceId>,
        lease_until: Option<TimestampMillis>,
        revision: ActivityLeaseRevision,
    ) -> Result<Self, ActivityLeaseProjectionError> {
        if owner_id.is_some() != lease_until.is_some() {
            return Err(ActivityLeaseProjectionError::PartialLease);
        }
        Ok(Self {
            owner_id,
            lease_until,
            revision,
        })
    }

    pub const fn owner_id(&self) -> Option<RuntimeInstanceId> {
        self.owner_id
    }

    pub const fn lease_until(&self) -> Option<TimestampMillis> {
        self.lease_until
    }

    /// Alias matching the persisted column name.
    pub const fn lease_until_ms(&self) -> Option<TimestampMillis> {
        self.lease_until()
    }

    pub const fn revision(&self) -> ActivityLeaseRevision {
        self.revision
    }

    /// Alias that makes the independent lease CAS domain explicit.
    pub const fn lease_revision(&self) -> ActivityLeaseRevision {
        self.revision()
    }

    pub const fn is_unleased(&self) -> bool {
        self.owner_id.is_none()
    }

    pub const fn is_live_at(&self, now: TimestampMillis) -> bool {
        match self.lease_until {
            Some(until) => until.get() > now.get(),
            None => false,
        }
    }

    pub const fn is_expired_at(&self, now: TimestampMillis) -> bool {
        match self.lease_until {
            Some(until) => until.get() <= now.get(),
            None => false,
        }
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ActivityLeaseProjectionError {
    #[error("Activity lease owner and expiry must both be present or both be absent")]
    PartialLease,
}

/// Deterministic liveness classification of an Activity at a caller-supplied
/// observation time.  It is intentionally a projection, not persisted state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActivityLiveness {
    Available,
    Live,
    Expired,
    Closed,
    Interrupted,
}

/// Activity row plus its caller-time classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivityProjection {
    activity: RegisteredActivity,
    liveness: ActivityLiveness,
}

impl ActivityProjection {
    pub fn from_activity(activity: RegisteredActivity, now: TimestampMillis) -> Self {
        let liveness = classify_activity(&activity, now);
        Self { activity, liveness }
    }

    pub const fn activity(&self) -> &RegisteredActivity {
        &self.activity
    }

    pub const fn into_activity(self) -> RegisteredActivity {
        self.activity
    }

    pub const fn liveness(&self) -> ActivityLiveness {
        self.liveness
    }

    pub const fn state(&self) -> ActivityState {
        self.activity.state()
    }

    pub const fn id(&self) -> ActivityId {
        self.activity.id()
    }
}

/// Validated command for establishing an owner-approved Workspace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EstablishWorkspace {
    id: WorkspaceId,
    location_id: LocationId,
    root: WorkspaceRoot,
    root_fingerprint: WorkspaceRootFingerprint,
    observed_at: TimestampMillis,
}

impl EstablishWorkspace {
    pub const fn new(
        id: WorkspaceId,
        location_id: LocationId,
        root: WorkspaceRoot,
        root_fingerprint: WorkspaceRootFingerprint,
        observed_at: TimestampMillis,
    ) -> Self {
        Self {
            id,
            location_id,
            root,
            root_fingerprint,
            observed_at,
        }
    }

    pub const fn id(&self) -> WorkspaceId {
        self.id
    }

    pub const fn location_id(&self) -> LocationId {
        self.location_id
    }

    pub fn root(&self) -> &WorkspaceRoot {
        &self.root
    }

    pub const fn root_fingerprint(&self) -> WorkspaceRootFingerprint {
        self.root_fingerprint
    }

    pub const fn observed_at(&self) -> TimestampMillis {
        self.observed_at
    }
}

/// Durable Workspace projection returned by the workspace authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredWorkspace {
    id: WorkspaceId,
    location_id: LocationId,
    root: WorkspaceRoot,
    root_fingerprint: WorkspaceRootFingerprint,
    created_at: TimestampMillis,
    updated_at: TimestampMillis,
    revision: WorkspaceRevision,
}

impl RegisteredWorkspace {
    pub const fn from_parts_with_revision(
        id: WorkspaceId,
        location_id: LocationId,
        root: WorkspaceRoot,
        root_fingerprint: WorkspaceRootFingerprint,
        created_at: TimestampMillis,
        updated_at: TimestampMillis,
        revision: WorkspaceRevision,
    ) -> Self {
        Self {
            id,
            location_id,
            root,
            root_fingerprint,
            created_at,
            updated_at,
            revision,
        }
    }

    pub const fn id(&self) -> WorkspaceId {
        self.id
    }

    pub const fn location_id(&self) -> LocationId {
        self.location_id
    }

    pub fn root(&self) -> &WorkspaceRoot {
        &self.root
    }

    pub const fn root_fingerprint(&self) -> WorkspaceRootFingerprint {
        self.root_fingerprint
    }

    pub const fn created_at(&self) -> TimestampMillis {
        self.created_at
    }

    pub const fn updated_at(&self) -> TimestampMillis {
        self.updated_at
    }

    pub const fn revision(&self) -> WorkspaceRevision {
        self.revision
    }
}

/// Validated command for creating an Activity within an explicit Workspace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateActivity {
    id: ActivityId,
    workspace_id: WorkspaceId,
    expected_workspace_revision: WorkspaceRevision,
    observed_at: TimestampMillis,
}

impl CreateActivity {
    pub const fn new(
        id: ActivityId,
        workspace_id: WorkspaceId,
        expected_workspace_revision: WorkspaceRevision,
        observed_at: TimestampMillis,
    ) -> Self {
        Self {
            id,
            workspace_id,
            expected_workspace_revision,
            observed_at,
        }
    }

    pub const fn id(&self) -> ActivityId {
        self.id
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn expected_workspace_revision(&self) -> WorkspaceRevision {
        self.expected_workspace_revision
    }

    pub const fn observed_at(&self) -> TimestampMillis {
        self.observed_at
    }
}

/// Durable Activity projection returned by the workspace authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredActivity {
    id: ActivityId,
    workspace_id: WorkspaceId,
    state: ActivityState,
    created_at: TimestampMillis,
    updated_at: TimestampMillis,
    revision: ActivityRevision,
    lease: ActivityLeaseProjection,
}

impl RegisteredActivity {
    pub const fn from_parts_with_revision(
        id: ActivityId,
        workspace_id: WorkspaceId,
        state: ActivityState,
        created_at: TimestampMillis,
        updated_at: TimestampMillis,
        revision: ActivityRevision,
    ) -> Self {
        Self::from_parts_with_lease(
            id,
            workspace_id,
            state,
            created_at,
            updated_at,
            revision,
            ActivityLeaseProjection::unleased(),
        )
    }

    pub const fn from_parts_with_lease(
        id: ActivityId,
        workspace_id: WorkspaceId,
        state: ActivityState,
        created_at: TimestampMillis,
        updated_at: TimestampMillis,
        revision: ActivityRevision,
        lease: ActivityLeaseProjection,
    ) -> Self {
        Self {
            id,
            workspace_id,
            state,
            created_at,
            updated_at,
            revision,
            lease,
        }
    }

    pub const fn id(&self) -> ActivityId {
        self.id
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn state(&self) -> ActivityState {
        self.state
    }

    pub const fn created_at(&self) -> TimestampMillis {
        self.created_at
    }

    pub const fn updated_at(&self) -> TimestampMillis {
        self.updated_at
    }

    pub const fn revision(&self) -> ActivityRevision {
        self.revision
    }

    pub const fn lease(&self) -> &ActivityLeaseProjection {
        &self.lease
    }

    pub const fn lease_owner_id(&self) -> Option<RuntimeInstanceId> {
        self.lease.owner_id()
    }

    pub const fn lease_until(&self) -> Option<TimestampMillis> {
        self.lease.lease_until()
    }

    pub const fn lease_until_ms(&self) -> Option<TimestampMillis> {
        self.lease.lease_until_ms()
    }

    pub const fn lease_revision(&self) -> ActivityLeaseRevision {
        self.lease.lease_revision()
    }
}

const fn classify_activity(
    activity: &RegisteredActivity,
    now: TimestampMillis,
) -> ActivityLiveness {
    match activity.state() {
        ActivityState::Closed => ActivityLiveness::Closed,
        ActivityState::Interrupted => ActivityLiveness::Interrupted,
        ActivityState::Open if activity.lease().is_unleased() => ActivityLiveness::Available,
        ActivityState::Open if activity.lease().is_live_at(now) => ActivityLiveness::Live,
        ActivityState::Open => ActivityLiveness::Expired,
    }
}

/// Durable compare-and-set command for an Activity lifecycle transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetActivityState {
    id: ActivityId,
    expected_revision: ActivityRevision,
    state: ActivityState,
    observed_at: TimestampMillis,
}

impl SetActivityState {
    pub const fn new(
        id: ActivityId,
        expected_revision: ActivityRevision,
        state: ActivityState,
        observed_at: TimestampMillis,
    ) -> Self {
        Self {
            id,
            expected_revision,
            state,
            observed_at,
        }
    }

    pub const fn id(&self) -> ActivityId {
        self.id
    }

    pub const fn expected_revision(&self) -> ActivityRevision {
        self.expected_revision
    }

    pub const fn state(&self) -> ActivityState {
        self.state
    }

    pub const fn observed_at(&self) -> TimestampMillis {
        self.observed_at
    }
}

/// Command to create or claim an Activity lease.
///
/// `lease_until` and `observed_at` are observations supplied by the caller;
/// this command does not read a clock or derive an expiry internally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapActivity {
    id: ActivityId,
    workspace_id: WorkspaceId,
    expected_workspace_revision: WorkspaceRevision,
    owner_id: RuntimeInstanceId,
    lease_until: TimestampMillis,
    observed_at: TimestampMillis,
}

impl BootstrapActivity {
    pub const fn new(
        id: ActivityId,
        workspace_id: WorkspaceId,
        expected_workspace_revision: WorkspaceRevision,
        owner_id: RuntimeInstanceId,
        lease_until: TimestampMillis,
        observed_at: TimestampMillis,
    ) -> Self {
        Self {
            id,
            workspace_id,
            expected_workspace_revision,
            owner_id,
            lease_until,
            observed_at,
        }
    }

    pub const fn id(&self) -> ActivityId {
        self.id
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn expected_workspace_revision(&self) -> WorkspaceRevision {
        self.expected_workspace_revision
    }

    pub const fn owner_id(&self) -> RuntimeInstanceId {
        self.owner_id
    }

    pub const fn runtime_instance_id(&self) -> RuntimeInstanceId {
        self.owner_id()
    }

    pub const fn lease_until(&self) -> TimestampMillis {
        self.lease_until
    }

    pub const fn lease_until_ms(&self) -> TimestampMillis {
        self.lease_until()
    }

    pub const fn observed_at(&self) -> TimestampMillis {
        self.observed_at
    }

    pub const fn now(&self) -> TimestampMillis {
        self.observed_at()
    }
}

/// Command to renew a lease owned by one runtime instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenewActivityLease {
    id: ActivityId,
    owner_id: RuntimeInstanceId,
    expected_lease_revision: ActivityLeaseRevision,
    lease_until: TimestampMillis,
    observed_at: TimestampMillis,
}

impl RenewActivityLease {
    pub const fn new(
        id: ActivityId,
        owner_id: RuntimeInstanceId,
        expected_lease_revision: ActivityLeaseRevision,
        lease_until: TimestampMillis,
        observed_at: TimestampMillis,
    ) -> Self {
        Self {
            id,
            owner_id,
            expected_lease_revision,
            lease_until,
            observed_at,
        }
    }

    pub const fn id(&self) -> ActivityId {
        self.id
    }

    pub const fn owner_id(&self) -> RuntimeInstanceId {
        self.owner_id
    }

    pub const fn runtime_instance_id(&self) -> RuntimeInstanceId {
        self.owner_id()
    }

    pub const fn expected_lease_revision(&self) -> ActivityLeaseRevision {
        self.expected_lease_revision
    }

    pub const fn lease_revision(&self) -> ActivityLeaseRevision {
        self.expected_lease_revision()
    }

    pub const fn lease_until(&self) -> TimestampMillis {
        self.lease_until
    }

    pub const fn lease_until_ms(&self) -> TimestampMillis {
        self.lease_until()
    }

    pub const fn observed_at(&self) -> TimestampMillis {
        self.observed_at
    }

    pub const fn now(&self) -> TimestampMillis {
        self.observed_at()
    }
}

/// Command to close an Activity while releasing its caller-owned lease.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseActivity {
    id: ActivityId,
    owner_id: RuntimeInstanceId,
    expected_lease_revision: ActivityLeaseRevision,
    observed_at: TimestampMillis,
}

impl CloseActivity {
    pub const fn new(
        id: ActivityId,
        owner_id: RuntimeInstanceId,
        expected_lease_revision: ActivityLeaseRevision,
        observed_at: TimestampMillis,
    ) -> Self {
        Self {
            id,
            owner_id,
            expected_lease_revision,
            observed_at,
        }
    }

    pub const fn id(&self) -> ActivityId {
        self.id
    }

    pub const fn owner_id(&self) -> RuntimeInstanceId {
        self.owner_id
    }

    pub const fn runtime_instance_id(&self) -> RuntimeInstanceId {
        self.owner_id()
    }

    pub const fn expected_lease_revision(&self) -> ActivityLeaseRevision {
        self.expected_lease_revision
    }

    pub const fn observed_at(&self) -> TimestampMillis {
        self.observed_at
    }

    pub const fn now(&self) -> TimestampMillis {
        self.observed_at()
    }
}

/// Command to release an owned lease without closing the Activity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseActivityLease {
    id: ActivityId,
    owner_id: RuntimeInstanceId,
    expected_lease_revision: ActivityLeaseRevision,
    observed_at: TimestampMillis,
}

impl ReleaseActivityLease {
    pub const fn new(
        id: ActivityId,
        owner_id: RuntimeInstanceId,
        expected_lease_revision: ActivityLeaseRevision,
        observed_at: TimestampMillis,
    ) -> Self {
        Self {
            id,
            owner_id,
            expected_lease_revision,
            observed_at,
        }
    }

    pub const fn id(&self) -> ActivityId {
        self.id
    }

    pub const fn owner_id(&self) -> RuntimeInstanceId {
        self.owner_id
    }

    pub const fn runtime_instance_id(&self) -> RuntimeInstanceId {
        self.owner_id()
    }

    pub const fn expected_lease_revision(&self) -> ActivityLeaseRevision {
        self.expected_lease_revision
    }

    pub const fn observed_at(&self) -> TimestampMillis {
        self.observed_at
    }

    pub const fn now(&self) -> TimestampMillis {
        self.observed_at()
    }
}

/// Pure command for reconciling leases observed as expired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReconcileExpiredActivities {
    now: TimestampMillis,
}

impl ReconcileExpiredActivities {
    pub const fn new(now: TimestampMillis) -> Self {
        Self { now }
    }

    pub const fn now(self) -> TimestampMillis {
        self.now
    }
}

/// Result of evaluating an Activity bootstrap against one durable snapshot.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapActivityDecision {
    Create,
    ResumeReleased,
    AlreadyOwned,
    AlreadyLive,
    ExpiredRecoveryRequired,
    UnleasedRecoveryRequired,
    Terminal,
}

/// Pure outcome of a lease renewal precondition check.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenewActivityLeaseDecision {
    Renew,
    Terminal,
    OwnerMismatch,
    Expired,
    RevisionConflict,
    InvalidWindow,
}

/// Pure outcome of a graceful close precondition check.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseActivityDecision {
    Close,
    AlreadyTerminal,
    OwnerMismatch,
    Expired,
    RevisionConflict,
}

/// Evaluate bootstrap/idempotency/recovery policy without I/O or a clock.
pub fn decide_bootstrap_activity(
    existing: Option<&RegisteredActivity>,
    command: &BootstrapActivity,
    now: TimestampMillis,
) -> BootstrapActivityDecision {
    let Some(activity) = existing else {
        return BootstrapActivityDecision::Create;
    };
    match activity.state() {
        ActivityState::Closed | ActivityState::Interrupted => BootstrapActivityDecision::Terminal,
        ActivityState::Open => {
            if activity.lease().is_live_at(now) {
                if activity.lease_owner_id() == Some(command.owner_id()) {
                    BootstrapActivityDecision::AlreadyOwned
                } else {
                    BootstrapActivityDecision::AlreadyLive
                }
            } else if activity.lease_until().is_some() {
                BootstrapActivityDecision::ExpiredRecoveryRequired
            } else if activity.lease_revision() != ActivityLeaseRevision::INITIAL {
                // The initial unleased revision is also produced by raw Activity creation and
                // remains recovery-required. Only a higher unleased revision can come from
                // the explicit release transition while the Activity remains Open.
                BootstrapActivityDecision::ResumeReleased
            } else {
                BootstrapActivityDecision::UnleasedRecoveryRequired
            }
        }
    }
}

/// Alias for callers that use the noun-first naming convention.
pub fn decide_activity_bootstrap(
    existing: Option<&RegisteredActivity>,
    command: &BootstrapActivity,
    now: TimestampMillis,
) -> BootstrapActivityDecision {
    decide_bootstrap_activity(existing, command, now)
}

/// Evaluate lease renewal policy from explicit observations only.
pub fn decide_renew_activity_lease(
    activity: &RegisteredActivity,
    command: &RenewActivityLease,
    now: TimestampMillis,
) -> RenewActivityLeaseDecision {
    if !matches!(activity.state(), ActivityState::Open) {
        return RenewActivityLeaseDecision::Terminal;
    }
    if activity.lease_owner_id() != Some(command.owner_id()) {
        return RenewActivityLeaseDecision::OwnerMismatch;
    }
    if activity.lease_revision() != command.expected_lease_revision() {
        return RenewActivityLeaseDecision::RevisionConflict;
    }
    if !activity.lease().is_live_at(now) {
        return RenewActivityLeaseDecision::Expired;
    }
    if command.lease_until().get() <= now.get() {
        return RenewActivityLeaseDecision::InvalidWindow;
    }
    RenewActivityLeaseDecision::Renew
}

/// Evaluate graceful close policy from explicit observations only.
pub fn decide_close_activity(
    activity: &RegisteredActivity,
    command: &CloseActivity,
    now: TimestampMillis,
) -> CloseActivityDecision {
    if matches!(
        activity.state(),
        ActivityState::Closed | ActivityState::Interrupted
    ) {
        return CloseActivityDecision::AlreadyTerminal;
    }
    if activity.lease_owner_id() != Some(command.owner_id()) {
        return CloseActivityDecision::OwnerMismatch;
    }
    if activity.lease_revision() != command.expected_lease_revision() {
        return CloseActivityDecision::RevisionConflict;
    }
    if !activity.lease().is_live_at(now) {
        return CloseActivityDecision::Expired;
    }
    CloseActivityDecision::Close
}

/// Bounded query limit for Activity lists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActivityListLimit(u32);

impl ActivityListLimit {
    pub const DEFAULT: Self = Self(100);

    pub const fn new(value: u32) -> Result<Self, ActivityListLimitError> {
        if value == 0 || value > MAX_ACTIVITY_LIST_LIMIT {
            Err(ActivityListLimitError::OutOfRange {
                actual: value,
                maximum: MAX_ACTIVITY_LIST_LIMIT,
            })
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ActivityListLimitError {
    #[error("Activity list limit {actual} is outside 1..={maximum}")]
    OutOfRange { actual: u32, maximum: u32 },
}

/// Bound for one transactional Activity lease batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActivityLeaseBatchLimit(u32);

impl ActivityLeaseBatchLimit {
    pub const MAX: Self = Self(MAX_ACTIVITY_LEASE_BATCH);

    pub const fn new(value: u32) -> Result<Self, ActivityLeaseBatchLimitError> {
        if value == 0 || value > MAX_ACTIVITY_LEASE_BATCH {
            Err(ActivityLeaseBatchLimitError::OutOfRange {
                actual: value,
                maximum: MAX_ACTIVITY_LEASE_BATCH,
            })
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ActivityLeaseBatchLimitError {
    #[error("Activity lease batch limit {actual} is outside 1..={maximum}")]
    OutOfRange { actual: u32, maximum: u32 },
}

/// Pure result of comparing an observed Workspace root with its durable
/// registration.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkspaceRootDecision {
    /// The path and physical identity still agree with durable state.
    Confirmed,
    /// The same physical root was observed at a new canonical path.
    Rebind {
        root: WorkspaceRoot,
        observed_at: TimestampMillis,
        next_revision: WorkspaceRevision,
    },
}

impl WorkspaceRootDecision {
    pub fn root(&self) -> Option<&WorkspaceRoot> {
        match self {
            Self::Confirmed => None,
            Self::Rebind { root, .. } => Some(root),
        }
    }

    pub const fn observed_at(&self) -> Option<TimestampMillis> {
        match self {
            Self::Confirmed => None,
            Self::Rebind { observed_at, .. } => Some(*observed_at),
        }
    }

    pub const fn next_revision(&self) -> Option<WorkspaceRevision> {
        match self {
            Self::Confirmed => None,
            Self::Rebind { next_revision, .. } => Some(*next_revision),
        }
    }

    /// Alias for callers that refer to the resulting projection revision.
    pub const fn revision(&self) -> Option<WorkspaceRevision> {
        self.next_revision()
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceRootDecisionError {
    #[error("Workspace root fingerprint mismatch")]
    FingerprintMismatch {
        expected: WorkspaceRootFingerprint,
        observed: WorkspaceRootFingerprint,
    },
    #[error("Workspace revision overflowed at {current}")]
    RevisionOverflow { current: WorkspaceRevision },
}

/// Compare a filesystem observation with durable Workspace identity.
///
/// This function is deterministic and performs no filesystem, clock, random,
/// or process-global reads. The caller supplies all observations explicitly.
pub fn decide_workspace_root(
    registered: &RegisteredWorkspace,
    observed_root: WorkspaceRoot,
    observed_fingerprint: WorkspaceRootFingerprint,
    observed_at: TimestampMillis,
) -> Result<WorkspaceRootDecision, WorkspaceRootDecisionError> {
    if observed_fingerprint != registered.root_fingerprint() {
        return Err(WorkspaceRootDecisionError::FingerprintMismatch {
            expected: registered.root_fingerprint(),
            observed: observed_fingerprint,
        });
    }

    if observed_root == *registered.root() {
        return Ok(WorkspaceRootDecision::Confirmed);
    }

    let next_revision = registered.revision().checked_next().map_err(|_| {
        WorkspaceRootDecisionError::RevisionOverflow {
            current: registered.revision(),
        }
    })?;
    Ok(WorkspaceRootDecision::Rebind {
        root: observed_root,
        observed_at,
        next_revision,
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::str::FromStr;

    use uuid::Uuid;

    use super::{
        ActivityId, ActivityLeaseBatchLimit, ActivityLeaseProjection, ActivityLeaseProjectionError,
        ActivityLeaseRevision, ActivityListLimit, ActivityLiveness, ActivityProjection,
        ActivityRevision, ActivityState, BootstrapActivity, BootstrapActivityDecision,
        CreateActivity, EstablishWorkspace, RegisteredActivity, RegisteredWorkspace,
        RuntimeInstanceId, SetActivityState, TimestampMillis, WorkspaceId, WorkspaceRevision,
        WorkspaceRoot, WorkspaceRootDecision, WorkspaceRootDecisionError, WorkspaceRootFingerprint,
        decide_bootstrap_activity, decide_workspace_root,
    };
    use crate::location::LocationId;

    fn workspace_id(value: u128) -> WorkspaceId {
        WorkspaceId::from_uuid(Uuid::from_u128(value))
    }

    fn activity_id(value: u128) -> ActivityId {
        ActivityId::from_uuid(Uuid::from_u128(value))
    }

    fn location_id(value: u128) -> LocationId {
        LocationId::from_uuid(Uuid::from_u128(value))
    }

    fn root(path: &str) -> Result<WorkspaceRoot, Box<dyn std::error::Error>> {
        Ok(WorkspaceRoot::from_canonical(PathBuf::from(path))?)
    }

    fn fingerprint(value: u8) -> WorkspaceRootFingerprint {
        WorkspaceRootFingerprint::from_bytes([value; 16])
    }

    fn workspace_with(
        revision: WorkspaceRevision,
        workspace_root: WorkspaceRoot,
        root_fingerprint: WorkspaceRootFingerprint,
    ) -> Result<RegisteredWorkspace, Box<dyn std::error::Error>> {
        Ok(RegisteredWorkspace::from_parts_with_revision(
            workspace_id(1),
            location_id(2),
            workspace_root,
            root_fingerprint,
            TimestampMillis::new(10)?,
            TimestampMillis::new(11)?,
            revision,
        ))
    }

    #[test]
    fn opaque_ids_parse_display_and_preserve_uuid_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        let workspace = WorkspaceId::from_str("018f47a2-4d8b-7ca0-a9bd-0e2f2bc1215e")?;
        let activity = ActivityId::from_str("018f47a2-4d8b-7ca0-a9bd-0e2f2bc1215f")?;
        assert_eq!(
            workspace.to_string(),
            "018f47a2-4d8b-7ca0-a9bd-0e2f2bc1215e"
        );
        assert_eq!(activity.to_string(), "018f47a2-4d8b-7ca0-a9bd-0e2f2bc1215f");
        assert_eq!(
            workspace.into_uuid(),
            Uuid::from_u128(0x018f_47a2_4d8b_7ca0_a9bd_0e2f_2bc1_215e)
        );
        assert_eq!(
            activity.into_uuid(),
            Uuid::from_u128(0x018f_47a2_4d8b_7ca0_a9bd_0e2f_2bc1_215f)
        );
        assert!(WorkspaceId::from_str("not-a-uuid").is_err());
        assert!(ActivityId::from_str("not-a-uuid").is_err());
        Ok(())
    }

    #[test]
    fn workspace_root_is_absolute_and_fingerprint_round_trips()
    -> Result<(), Box<dyn std::error::Error>> {
        assert!(WorkspaceRoot::from_canonical(PathBuf::from("relative/path")).is_err());
        let root = root("/tmp/forge-workspace")?;
        assert_eq!(root.as_path(), std::path::Path::new("/tmp/forge-workspace"));
        let fingerprint = WorkspaceRootFingerprint::from_bytes([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ]);
        assert_eq!(
            fingerprint.into_bytes(),
            [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f,
            ]
        );
        Ok(())
    }

    #[test]
    fn revisions_validate_increment_and_report_overflow() -> Result<(), Box<dyn std::error::Error>>
    {
        assert_eq!(WorkspaceRevision::INITIAL.get(), 1);
        assert_eq!(ActivityRevision::INITIAL.get(), 1);
        assert!(WorkspaceRevision::new(0).is_err());
        assert!(ActivityRevision::new(0).is_err());
        assert_eq!(WorkspaceRevision::new(7)?.checked_next()?.get(), 8);
        assert_eq!(ActivityRevision::new(7)?.checked_next()?.get(), 8);
        assert!(WorkspaceRevision::new(i64::MAX)?.checked_next().is_err());
        assert!(ActivityRevision::new(i64::MAX)?.checked_next().is_err());
        assert_eq!(WorkspaceRevision::new(12)?.to_string(), "12");
        assert_eq!(ActivityRevision::new(13)?.to_string(), "13");
        Ok(())
    }

    #[test]
    fn activity_limit_is_bounded() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(ActivityListLimit::DEFAULT.get(), 100);
        assert_eq!(ActivityListLimit::new(1_000)?.get(), 1_000);
        assert!(ActivityListLimit::new(0).is_err());
        assert!(ActivityListLimit::new(1_001).is_err());
        assert_eq!(ActivityLeaseBatchLimit::MAX.get(), 256);
        assert_eq!(ActivityLeaseBatchLimit::new(256)?.get(), 256);
        assert!(ActivityLeaseBatchLimit::new(0).is_err());
        assert!(ActivityLeaseBatchLimit::new(257).is_err());
        Ok(())
    }

    #[test]
    fn commands_keep_scope_state_revision_and_observation_separate()
    -> Result<(), Box<dyn std::error::Error>> {
        let workspace = EstablishWorkspace::new(
            workspace_id(1),
            location_id(2),
            root("/tmp/forge-workspace")?,
            fingerprint(3),
            TimestampMillis::new(42)?,
        );
        assert_eq!(workspace.id(), workspace_id(1));
        assert_eq!(workspace.location_id(), location_id(2));
        assert_eq!(
            workspace.root().as_path(),
            PathBuf::from("/tmp/forge-workspace")
        );
        assert_eq!(workspace.root_fingerprint(), fingerprint(3));
        assert_eq!(workspace.observed_at().get(), 42);

        let activity = CreateActivity::new(
            activity_id(4),
            workspace_id(1),
            WorkspaceRevision::INITIAL,
            TimestampMillis::new(43)?,
        );
        assert_eq!(activity.id(), activity_id(4));
        assert_eq!(activity.workspace_id(), workspace_id(1));
        assert_eq!(
            activity.expected_workspace_revision(),
            WorkspaceRevision::INITIAL
        );
        assert_eq!(activity.observed_at().get(), 43);

        let state = SetActivityState::new(
            activity_id(4),
            ActivityRevision::INITIAL,
            ActivityState::Closed,
            TimestampMillis::new(44)?,
        );
        assert_eq!(state.id(), activity_id(4));
        assert_eq!(state.expected_revision(), ActivityRevision::INITIAL);
        assert_eq!(state.state(), ActivityState::Closed);
        assert_eq!(state.observed_at().get(), 44);
        Ok(())
    }

    #[test]
    fn projections_expose_typed_workspace_and_activity_fields()
    -> Result<(), Box<dyn std::error::Error>> {
        let workspace = workspace_with(
            WorkspaceRevision::INITIAL,
            root("/tmp/workspace")?,
            fingerprint(5),
        )?;
        assert_eq!(workspace.id(), workspace_id(1));
        assert_eq!(workspace.location_id(), location_id(2));
        assert_eq!(workspace.root_fingerprint(), fingerprint(5));
        assert_eq!(workspace.created_at().get(), 10);
        assert_eq!(workspace.updated_at().get(), 11);
        assert_eq!(workspace.revision(), WorkspaceRevision::INITIAL);

        let activity = RegisteredActivity::from_parts_with_revision(
            activity_id(6),
            workspace.id(),
            ActivityState::Open,
            TimestampMillis::new(12)?,
            TimestampMillis::new(13)?,
            ActivityRevision::INITIAL,
        );
        assert_eq!(activity.id(), activity_id(6));
        assert_eq!(activity.workspace_id(), workspace.id());
        assert_eq!(activity.state(), ActivityState::Open);
        assert_eq!(activity.created_at().get(), 12);
        assert_eq!(activity.updated_at().get(), 13);
        assert_eq!(activity.revision(), ActivityRevision::INITIAL);
        Ok(())
    }

    #[test]
    fn root_binding_confirms_rebinds_or_rejects_without_io()
    -> Result<(), Box<dyn std::error::Error>> {
        let registered = workspace_with(
            WorkspaceRevision::INITIAL,
            root("/tmp/old")?,
            fingerprint(7),
        )?;

        assert_eq!(
            decide_workspace_root(
                &registered,
                root("/tmp/old")?,
                fingerprint(7),
                TimestampMillis::new(20)?,
            )?,
            WorkspaceRootDecision::Confirmed,
        );

        let decision = decide_workspace_root(
            &registered,
            root("/tmp/new")?,
            fingerprint(7),
            TimestampMillis::new(21)?,
        )?;
        assert_eq!(
            decision,
            WorkspaceRootDecision::Rebind {
                root: root("/tmp/new")?,
                observed_at: TimestampMillis::new(21)?,
                next_revision: WorkspaceRevision::new(2)?,
            }
        );
        assert_eq!(decision.next_revision(), Some(WorkspaceRevision::new(2)?));

        let conflict = decide_workspace_root(
            &registered,
            root("/tmp/new")?,
            fingerprint(8),
            TimestampMillis::new(22)?,
        );
        assert!(matches!(
            conflict,
            Err(WorkspaceRootDecisionError::FingerprintMismatch { .. })
        ));
        Ok(())
    }

    #[test]
    fn root_binding_reports_revision_overflow() -> Result<(), Box<dyn std::error::Error>> {
        let registered = workspace_with(
            WorkspaceRevision::new(i64::MAX)?,
            root("/tmp/old")?,
            fingerprint(9),
        )?;
        let result = decide_workspace_root(
            &registered,
            root("/tmp/new")?,
            fingerprint(9),
            TimestampMillis::new(23)?,
        );
        assert!(matches!(
            result,
            Err(WorkspaceRootDecisionError::RevisionOverflow { .. })
        ));
        Ok(())
    }

    #[test]
    fn runtime_ids_leases_and_liveness_are_typed_and_clock_free()
    -> Result<(), Box<dyn std::error::Error>> {
        let owner = RuntimeInstanceId::from_uuid(Uuid::from_u128(10));
        assert_eq!(owner.to_string(), Uuid::from_u128(10).to_string());
        assert_eq!(RuntimeInstanceId::from_str(&owner.to_string())?, owner);
        assert!(RuntimeInstanceId::from_str("not-a-runtime").is_err());
        assert!(ActivityLeaseRevision::new(0).is_err());
        assert_eq!(ActivityLeaseRevision::new(7)?.checked_next()?.get(), 8);
        assert!(
            ActivityLeaseRevision::new(i64::MAX)?
                .checked_next()
                .is_err()
        );

        let until = TimestampMillis::new(100)?;
        let lease = ActivityLeaseProjection::from_parts(
            Some(owner),
            Some(until),
            ActivityLeaseRevision::INITIAL,
        )?;
        assert!(lease.is_live_at(TimestampMillis::new(99)?));
        assert!(lease.is_expired_at(TimestampMillis::new(100)?));
        assert!(matches!(
            ActivityLeaseProjection::from_parts(Some(owner), None, ActivityLeaseRevision::INITIAL,),
            Err(ActivityLeaseProjectionError::PartialLease)
        ));

        let workspace = workspace_with(
            WorkspaceRevision::INITIAL,
            root("/tmp/lease-workspace")?,
            fingerprint(12),
        )?;
        let activity = RegisteredActivity::from_parts_with_lease(
            activity_id(11),
            workspace.id(),
            ActivityState::Open,
            TimestampMillis::new(1)?,
            TimestampMillis::new(2)?,
            ActivityRevision::INITIAL,
            lease,
        );
        let command = BootstrapActivity::new(
            activity.id(),
            workspace.id(),
            workspace.revision(),
            owner,
            TimestampMillis::new(150)?,
            TimestampMillis::new(10)?,
        );
        assert_eq!(
            decide_bootstrap_activity(Some(&activity), &command, TimestampMillis::new(10)?),
            BootstrapActivityDecision::AlreadyOwned
        );
        assert_eq!(
            decide_bootstrap_activity(Some(&activity), &command, TimestampMillis::new(100)?),
            BootstrapActivityDecision::ExpiredRecoveryRequired
        );
        assert_eq!(
            ActivityProjection::from_activity(activity, TimestampMillis::new(100)?).liveness(),
            ActivityLiveness::Expired
        );
        Ok(())
    }
}
