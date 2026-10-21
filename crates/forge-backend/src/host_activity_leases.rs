//! Opt-in, host-owned supervision for exact Forge Activity lease registrations.
//!
//! The registration is operator configuration. Source remains authoritative
//! for Workspace, Activity, Goal, Session, Coordinator, and lease state. This
//! module's journal retains only exact readback selectors and unresolved lease
//! command inputs; it never stores credentials, provider payloads, or a copy of
//! the Source probe.

use std::collections::{BTreeMap, HashSet};
use std::error::Error;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

use forge_domain::{
    ActivityCoordinatorRevision, ActivityId, ActivityState, AgentSessionId, AuthenticatedPrincipal,
    DirectTokenId, GoalId, LocationRevision, OAuthGrantId, RuntimeInstanceId, TimestampMillis,
    WorkspaceRevision,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[cfg(test)]
mod integration_tests;
mod source;
mod supervisor;
pub(crate) use supervisor::{
    HostActivityLeaseSupervisor, PreparedHostActivityLeaseSupervisor, SupervisorError,
};

const JOURNAL_VERSION: u16 = 1;
const MAX_JOURNAL_BYTES: usize = 64 * 1024;
const MAX_REGISTRATIONS: usize = 16;
const MIN_LEASE_DURATION_MS: i64 = 30_000;
const MAX_LEASE_DURATION_MS: i64 = 300_000;
const MIN_RENEW_INTERVAL_MS: i64 = 1_000;
const MAX_RENEW_INTERVAL_MS: i64 = 60_000;

const fn default_lease_duration_ms() -> i64 {
    60_000
}

const fn default_renew_interval_ms() -> i64 {
    20_000
}

/// Strict opt-in configuration for host-owned Activity lease supervision.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostActivityLeaseSupervisionConfig {
    journal_root: PathBuf,
    #[serde(default = "default_lease_duration_ms")]
    lease_duration_ms: i64,
    #[serde(default = "default_renew_interval_ms")]
    renew_interval_ms: i64,
    registrations: Vec<HostActivityLeaseRegistration>,
}

/// One operator-authorized Activity, scoped to exact durable source identities.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostActivityLeaseRegistration {
    supervision_id: Uuid,
    scope: HostActivityLeaseScope,
    activity_id: Uuid,
    goal_id: Uuid,
    goal_created_at_ms: i64,
    initiating_session_id: Uuid,
    principal: HostPrincipalConfig,
    coordinator: HostCoordinatorPin,
}

/// Source scope selector. The Source inventory resolves and verifies the root;
/// configuration never accepts a raw workspace filesystem path.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct HostActivityLeaseScope {
    location_id: Uuid,
    location_revision: i64,
    workspace_id: Uuid,
    workspace_revision: i64,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct HostCoordinatorPin {
    agent_id: Uuid,
    session_id: Uuid,
    revision: i64,
}

/// Stable Source principal identity; this contains no bearer secret.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct HostPrincipalConfig {
    kind: HostPrincipalKind,
    #[serde(default)]
    id: Option<Uuid>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum HostPrincipalKind {
    TrustedStdio,
    DirectToken,
    OAuthGrant,
}

impl HostPrincipalConfig {
    fn into_source(self) -> Result<AuthenticatedPrincipal, ConfigError> {
        match (self.kind, self.id) {
            (HostPrincipalKind::TrustedStdio, None) => Ok(AuthenticatedPrincipal::TrustedStdio),
            (HostPrincipalKind::DirectToken, Some(id)) if !id.is_nil() => Ok(
                AuthenticatedPrincipal::DirectToken(DirectTokenId::from_uuid(id)),
            ),
            (HostPrincipalKind::OAuthGrant, Some(id)) if !id.is_nil() => Ok(
                AuthenticatedPrincipal::OAuthGrant(OAuthGrantId::from_uuid(id)),
            ),
            _ => Err(ConfigError::Principal),
        }
    }
}

impl HostActivityLeaseSupervisionConfig {
    fn validate(&self, registry_path: &Path) -> Result<(), ConfigError> {
        if self.registrations.is_empty() || self.registrations.len() > MAX_REGISTRATIONS {
            return Err(ConfigError::RegistrationCount);
        }
        if !(MIN_LEASE_DURATION_MS..=MAX_LEASE_DURATION_MS).contains(&self.lease_duration_ms)
            || !(MIN_RENEW_INTERVAL_MS..=MAX_RENEW_INTERVAL_MS).contains(&self.renew_interval_ms)
            || self.renew_interval_ms > self.lease_duration_ms / 3
        {
            return Err(ConfigError::Timing);
        }
        validate_journal_path(&self.journal_root, registry_path)?;

        let mut supervision_ids = HashSet::with_capacity(self.registrations.len());
        let mut activity_ids = HashSet::with_capacity(self.registrations.len());
        for registration in &self.registrations {
            registration.validate()?;
            if !supervision_ids.insert(registration.supervision_id)
                || !activity_ids.insert(registration.activity_id)
            {
                return Err(ConfigError::DuplicateRegistration);
            }
        }
        Ok(())
    }

    pub(crate) const fn lease_duration_ms(&self) -> i64 {
        self.lease_duration_ms
    }

    pub(crate) const fn renew_interval_ms(&self) -> i64 {
        self.renew_interval_ms
    }

    pub(crate) fn journal_root(&self) -> &Path {
        &self.journal_root
    }

    pub(crate) fn registrations(&self) -> &[HostActivityLeaseRegistration] {
        &self.registrations
    }
}

impl HostActivityLeaseRegistration {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.supervision_id.is_nil()
            || self.scope.location_id.is_nil()
            || self.scope.workspace_id.is_nil()
            || self.activity_id.is_nil()
            || self.goal_id.is_nil()
            || self.initiating_session_id.is_nil()
            || self.coordinator.agent_id.is_nil()
            || self.coordinator.session_id.is_nil()
        {
            return Err(ConfigError::NilIdentity);
        }
        if self.initiating_session_id != self.coordinator.session_id {
            return Err(ConfigError::CoordinatorSession);
        }
        LocationRevision::new(self.scope.location_revision).map_err(|_| ConfigError::Revision)?;
        WorkspaceRevision::new(self.scope.workspace_revision).map_err(|_| ConfigError::Revision)?;
        ActivityCoordinatorRevision::new(self.coordinator.revision)
            .map_err(|_| ConfigError::Revision)?;
        TimestampMillis::new(self.goal_created_at_ms).map_err(|_| ConfigError::Timestamp)?;
        let _ = self.principal.into_source()?;
        Ok(())
    }

    fn source_scope(self) -> SourceScopeSelector {
        SourceScopeSelector {
            location_id: self.scope.location_id,
            location_revision: self.scope.location_revision,
            workspace_id: self.scope.workspace_id,
            workspace_revision: self.scope.workspace_revision,
        }
    }

    fn principal(self) -> Result<AuthenticatedPrincipal, ConfigError> {
        self.principal.into_source()
    }

    fn activity_id(self) -> ActivityId {
        ActivityId::from_uuid(self.activity_id)
    }

    fn goal_id(self) -> GoalId {
        GoalId::from_uuid(self.goal_id)
    }

    fn initiating_session_id(self) -> AgentSessionId {
        AgentSessionId::from_uuid(self.initiating_session_id)
    }

    fn coordinator_pin(self) -> HostCoordinatorPin {
        self.coordinator
    }

    fn supervision_id(self) -> Uuid {
        self.supervision_id
    }

    fn activity_id_uuid(self) -> Uuid {
        self.activity_id
    }

    fn goal_created_at_ms(self) -> i64 {
        self.goal_created_at_ms
    }
}

fn validate_journal_path(path: &Path, registry_path: &Path) -> Result<(), ConfigError> {
    if !path.is_absolute()
        || path.file_name().is_none()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
        || path == registry_path
        || path.starts_with(registry_path)
        || registry_path.starts_with(path)
    {
        return Err(ConfigError::JournalPath);
    }
    let parent = path.parent().ok_or(ConfigError::JournalPath)?;
    let parent_metadata = fs::metadata(parent).map_err(|_| ConfigError::JournalPath)?;
    if !parent_metadata.is_dir() {
        return Err(ConfigError::JournalPath);
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_dir() || metadata.file_type().is_symlink() || !private_mode(&metadata) {
                return Err(ConfigError::JournalPath);
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(ConfigError::JournalPath),
    }
    Ok(())
}

#[cfg(unix)]
fn private_mode(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode().trailing_zeros() >= 6
}

#[cfg(not(unix))]
fn private_mode(_: &fs::Metadata) -> bool {
    false
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SourceScopeSelector {
    location_id: Uuid,
    location_revision: i64,
    workspace_id: Uuid,
    workspace_revision: i64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PendingResumeGet {
    supervision_id: Uuid,
    scope: SourceScopeSelector,
    goal_id: Uuid,
    goal_created_at_ms: i64,
    coordinator: HostCoordinatorPin,
    request_id: Uuid,
    request_digest: [u8; 32],
    probe_digest: [u8; 32],
    activity_id: Uuid,
    agent_id: Uuid,
    initiating_session_id: Uuid,
    principal: HostPrincipalConfig,
    source_runtime_instance_id: Uuid,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PendingRenewal {
    supervision_id: Uuid,
    scope: SourceScopeSelector,
    activity_id: Uuid,
    owner_id: Uuid,
    expected_lease_revision: i64,
    duration_ms: i64,
    observed_at_ms: i64,
    prestate: LeasePrestate,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct LeasePrestate {
    activity_state: HostActivityState,
    activity_revision: i64,
    lease_owner_id: Uuid,
    lease_until_ms: i64,
    lease_revision: i64,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum HostActivityState {
    Open,
    Closed,
    Interrupted,
}

impl HostActivityState {
    fn from_source(value: ActivityState) -> Self {
        match value {
            ActivityState::Open => Self::Open,
            ActivityState::Closed => Self::Closed,
            ActivityState::Interrupted => Self::Interrupted,
        }
    }
}

impl LeasePrestate {
    fn from_source(activity: &forge_domain::RegisteredActivity) -> Option<Self> {
        Some(Self {
            activity_state: HostActivityState::from_source(activity.state()),
            activity_revision: activity.revision().get(),
            lease_owner_id: activity.lease_owner_id()?.into_uuid(),
            lease_until_ms: activity.lease_until()?.get(),
            lease_revision: activity.lease_revision().get(),
        })
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(
    tag = "kind",
    content = "intent",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum PendingOperation {
    StartedResume(PendingResumeGet),
    QuiescentResume(PendingResumeGet),
    Renewal(PendingRenewal),
}

impl PendingOperation {
    fn supervision_id(&self) -> Uuid {
        match self {
            Self::StartedResume(value) | Self::QuiescentResume(value) => value.supervision_id,
            Self::Renewal(value) => value.supervision_id,
        }
    }

    fn matches_registration(&self, registration: HostActivityLeaseRegistration) -> bool {
        match self {
            Self::StartedResume(selector) | Self::QuiescentResume(selector) => {
                !selector.request_id.is_nil()
                    && !selector.agent_id.is_nil()
                    && !selector.source_runtime_instance_id.is_nil()
                    && selector.scope == registration.source_scope()
                    && selector.supervision_id == registration.supervision_id()
                    && selector.goal_id == registration.goal_id().into_uuid()
                    && selector.goal_created_at_ms == registration.goal_created_at_ms()
                    && selector.coordinator.agent_id == registration.coordinator_pin().agent_id
                    && selector.coordinator.session_id == registration.coordinator_pin().session_id
                    && selector.coordinator.revision == registration.coordinator_pin().revision
                    && selector.agent_id == selector.coordinator.agent_id
                    && selector.activity_id == registration.activity_id_uuid()
                    && selector.initiating_session_id
                        == registration.initiating_session_id().into_uuid()
                    && selector.principal == registration.principal
            }
            Self::Renewal(renewal) => {
                renewal.scope == registration.source_scope()
                    && renewal.supervision_id == registration.supervision_id()
                    && renewal.activity_id == registration.activity_id_uuid()
                    && renewal.owner_id == renewal.prestate.lease_owner_id
                    && renewal.expected_lease_revision == renewal.prestate.lease_revision
                    && renewal.prestate.activity_state == HostActivityState::Open
                    && (MIN_LEASE_DURATION_MS..=MAX_LEASE_DURATION_MS)
                        .contains(&renewal.duration_ms)
                    && !renewal.owner_id.is_nil()
            }
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct JournalFile {
    version: u16,
    pending: BTreeMap<Uuid, PendingOperation>,
}

impl Default for JournalFile {
    fn default() -> Self {
        Self {
            version: JOURNAL_VERSION,
            pending: BTreeMap::new(),
        }
    }
}

#[derive(Debug)]
struct JournalStore {
    root: PathBuf,
    path: PathBuf,
    file: JournalFile,
    // This path-specific flock prevents distinct Registry owners from
    // replacing the same journal concurrently. Keep the descriptor for the
    // entire JournalStore lifetime.
    _owner_lock: forge_backend::serve_fence::ServeFence,
}

impl JournalStore {
    fn open(root: &Path) -> Result<Self, JournalError> {
        ensure_private_journal_root(root)?;
        let path = root.join("activity-lease-supervision.json");
        let owner_lock = forge_backend::serve_fence::ServeFence::acquire(&path).map_err(
            |error| match error {
                forge_backend::serve_fence::ServeFenceError::Busy { .. } => JournalError::Busy,
                _ => JournalError::Io,
            },
        )?;
        let (file, create_file) = match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if !metadata.is_file()
                    || metadata.file_type().is_symlink()
                    || !private_mode(&metadata)
                {
                    return Err(JournalError::UnprivateFile);
                }
                (read_journal(&path)?, false)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                (JournalFile::default(), true)
            }
            Err(_) => return Err(JournalError::Io),
        };
        let mut result = Self {
            root: root.to_path_buf(),
            path,
            file,
            _owner_lock: owner_lock,
        };
        if create_file {
            result.persist()?;
        }
        Ok(result)
    }

    fn validate_registrations(
        &self,
        registrations: &[HostActivityLeaseRegistration],
    ) -> Result<(), JournalError> {
        for (supervision_id, operation) in &self.file.pending {
            if operation.supervision_id() != *supervision_id {
                return Err(JournalError::PendingIdentityMismatch);
            }
            let Some(registration) = registrations
                .iter()
                .copied()
                .find(|registration| registration.supervision_id() == *supervision_id)
            else {
                return Err(JournalError::PendingRegistrationMismatch);
            };
            if !operation.matches_registration(registration) {
                return Err(JournalError::PendingRegistrationMismatch);
            }
        }
        Ok(())
    }

    fn pending(&self, supervision_id: Uuid) -> Option<&PendingOperation> {
        self.file.pending.get(&supervision_id)
    }

    async fn insert_pending(
        &mut self,
        supervision_id: Uuid,
        operation: PendingOperation,
    ) -> Result<(), JournalError> {
        if operation.supervision_id() != supervision_id {
            return Err(JournalError::PendingIdentityMismatch);
        }
        if self.file.pending.contains_key(&supervision_id) {
            return Err(JournalError::PendingAlreadyExists);
        }
        if self.file.pending.len() >= MAX_REGISTRATIONS {
            return Err(JournalError::PendingCapacity);
        }
        self.file.pending.insert(supervision_id, operation);
        self.persist_async().await
    }

    async fn clear_pending(
        &mut self,
        supervision_id: Uuid,
        expected: &PendingOperation,
    ) -> Result<(), JournalError> {
        if self.file.pending.get(&supervision_id) != Some(expected) {
            return Err(JournalError::PendingIdentityMismatch);
        }
        self.file.pending.remove(&supervision_id);
        self.persist_async().await
    }

    fn persist(&mut self) -> Result<(), JournalError> {
        let bytes = serde_json::to_vec(&self.file).map_err(|_| JournalError::InvalidJson)?;
        if bytes.len() > MAX_JOURNAL_BYTES {
            return Err(JournalError::TooLarge);
        }
        let temporary = self
            .root
            .join(format!(".lease-journal-{}.tmp", Uuid::now_v7()));
        let result = atomic_write(&self.root, &temporary, &self.path, &bytes);
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    async fn persist_async(&self) -> Result<(), JournalError> {
        let bytes = serde_json::to_vec(&self.file).map_err(|_| JournalError::InvalidJson)?;
        if bytes.len() > MAX_JOURNAL_BYTES {
            return Err(JournalError::TooLarge);
        }
        let root = self.root.clone();
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || {
            let temporary = root.join(format!(".lease-journal-{}.tmp", Uuid::now_v7()));
            let result = atomic_write(&root, &temporary, &path, &bytes);
            if result.is_err() {
                let _ = fs::remove_file(&temporary);
            }
            result
        })
        .await
        .map_err(|_| JournalError::Io)?
    }
}

fn read_journal(path: &Path) -> Result<JournalFile, JournalError> {
    let file = File::open(path).map_err(|_| JournalError::Io)?;
    let mut bytes = Vec::new();
    file.take(u64::try_from(MAX_JOURNAL_BYTES + 1).map_err(|_| JournalError::TooLarge)?)
        .read_to_end(&mut bytes)
        .map_err(|_| JournalError::Io)?;
    if bytes.len() > MAX_JOURNAL_BYTES {
        return Err(JournalError::TooLarge);
    }
    let journal: JournalFile =
        serde_json::from_slice(&bytes).map_err(|_| JournalError::InvalidJson)?;
    if journal.version != JOURNAL_VERSION || journal.pending.len() > MAX_REGISTRATIONS {
        return Err(JournalError::VersionOrCount);
    }
    for (key, operation) in &journal.pending {
        if key.is_nil() || operation.supervision_id() != *key {
            return Err(JournalError::PendingIdentityMismatch);
        }
    }
    Ok(journal)
}

fn ensure_private_journal_root(root: &Path) -> Result<(), JournalError> {
    match fs::symlink_metadata(root) {
        Ok(metadata) => {
            if !metadata.is_dir() || metadata.file_type().is_symlink() || !private_mode(&metadata) {
                return Err(JournalError::UnprivateDirectory);
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                let parent = root.parent().ok_or(JournalError::UnprivateDirectory)?;
                if !parent.is_dir() {
                    return Err(JournalError::UnprivateDirectory);
                }
                let mut builder = fs::DirBuilder::new();
                builder.mode(0o700);
                builder.create(root).map_err(|_| JournalError::Io)?;
            }
            #[cfg(not(unix))]
            return Err(JournalError::UnprivateDirectory);
            let metadata = fs::symlink_metadata(root).map_err(|_| JournalError::Io)?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() || !private_mode(&metadata) {
                return Err(JournalError::UnprivateDirectory);
            }
        }
        Err(_) => return Err(JournalError::Io),
    }
    Ok(())
}

#[cfg(unix)]
fn atomic_write(
    root: &Path,
    temporary: &Path,
    path: &Path,
    bytes: &[u8],
) -> Result<(), JournalError> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(temporary)
        .map_err(|_| JournalError::Io)?;
    file.write_all(bytes).map_err(|_| JournalError::Io)?;
    file.sync_all().map_err(|_| JournalError::Io)?;
    drop(file);
    fs::rename(temporary, path).map_err(|_| JournalError::Io)?;
    File::open(root)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| JournalError::Io)
}

#[cfg(not(unix))]
fn atomic_write(_: &Path, _: &Path, _: &Path, _: &[u8]) -> Result<(), JournalError> {
    Err(JournalError::UnprivateDirectory)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RenewReadback {
    ObservedCurrentLease,
    ObservedPreviousBootLease,
    ObservedOldState,
    StillPending,
    ChangedOrClosed,
}

fn classify_pending_renewal(
    pending: &PendingRenewal,
    observed: &forge_domain::RegisteredActivity,
    current_runtime: RuntimeInstanceId,
    observed_at: TimestampMillis,
) -> RenewReadback {
    let owner_from_previous_boot = pending.owner_id != current_runtime.into_uuid();
    let same_old = observed.id().into_uuid() == pending.activity_id
        && observed.state() == ActivityState::Open
        && observed.revision().get() == pending.prestate.activity_revision
        && observed.lease_owner_id().map(RuntimeInstanceId::into_uuid)
            == Some(pending.prestate.lease_owner_id)
        && observed.lease_revision().get() == pending.prestate.lease_revision
        && observed.lease_until().map(TimestampMillis::get)
            == Some(pending.prestate.lease_until_ms);
    let requested_revision = pending.expected_lease_revision.checked_add(1);
    let observed_requested = observed.id().into_uuid() == pending.activity_id
        && observed.state() == ActivityState::Open
        && observed.revision().get() == pending.prestate.activity_revision
        && observed.lease_owner_id().map(RuntimeInstanceId::into_uuid) == Some(pending.owner_id)
        && Some(observed.lease_revision().get()) == requested_revision
        && observed
            .lease_until()
            .is_some_and(|until| until.get() > observed_at.get());
    if observed_requested && pending.owner_id == current_runtime.into_uuid() {
        RenewReadback::ObservedCurrentLease
    } else if observed_requested {
        RenewReadback::ObservedPreviousBootLease
    } else if same_old && !owner_from_previous_boot {
        RenewReadback::StillPending
    } else if same_old {
        RenewReadback::ObservedOldState
    } else {
        RenewReadback::ChangedOrClosed
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConfigError {
    RegistrationCount,
    DuplicateRegistration,
    NilIdentity,
    Principal,
    Revision,
    Timestamp,
    Timing,
    JournalPath,
    CoordinatorSession,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RegistrationCount => "Activity lease registrations exceed their bound",
            Self::DuplicateRegistration => "Activity lease registration identity is duplicated",
            Self::NilIdentity => "Activity lease registration contains a nil identity",
            Self::Principal => "Activity lease principal identity is invalid",
            Self::Revision => "Activity lease scope or Coordinator revision is invalid",
            Self::Timestamp => "Activity lease Goal creation timestamp is invalid",
            Self::Timing => "Activity lease supervision timing is outside its bounds",
            Self::JournalPath => "Activity lease journal path is invalid",
            Self::CoordinatorSession => {
                "Activity lease initiator must match the pinned Coordinator Session"
            }
        })
    }
}

impl Error for ConfigError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JournalError {
    Io,
    Busy,
    UnprivateDirectory,
    UnprivateFile,
    TooLarge,
    InvalidJson,
    VersionOrCount,
    PendingAlreadyExists,
    PendingIdentityMismatch,
    PendingCapacity,
    PendingRegistrationMismatch,
}

impl fmt::Display for JournalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Io => "Activity lease journal I/O failed",
            Self::Busy => "Activity lease journal is owned by another Source process",
            Self::UnprivateDirectory => "Activity lease journal directory is not private",
            Self::UnprivateFile => "Activity lease journal file is not private",
            Self::TooLarge => "Activity lease journal exceeds its byte bound",
            Self::InvalidJson => "Activity lease journal is invalid",
            Self::VersionOrCount => "Activity lease journal version or count is invalid",
            Self::PendingAlreadyExists => {
                "Activity lease supervision already has a pending operation"
            }
            Self::PendingIdentityMismatch => {
                "Activity lease journal pending identity is inconsistent"
            }
            Self::PendingCapacity => "Activity lease journal has no pending-operation capacity",
            Self::PendingRegistrationMismatch => {
                "Activity lease journal does not match configured registrations"
            }
        })
    }
}

impl Error for JournalError {}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::path::PathBuf;

    use forge_domain::{ActivityLeaseRevision, WorkspaceId};

    use super::*;

    fn leased_activity(
        owner: Uuid,
        until_ms: i64,
        lease_revision: i64,
        activity_revision: i64,
    ) -> Result<forge_domain::RegisteredActivity, Box<dyn Error>> {
        Ok(forge_domain::RegisteredActivity::from_parts_with_lease(
            ActivityId::from_uuid(Uuid::from_u128(11)),
            WorkspaceId::from_uuid(Uuid::from_u128(3)),
            ActivityState::Open,
            TimestampMillis::new(1)?,
            TimestampMillis::new(1)?,
            forge_domain::ActivityRevision::new(activity_revision)?,
            forge_domain::ActivityLeaseProjection::from_parts(
                Some(RuntimeInstanceId::from_uuid(owner)),
                Some(TimestampMillis::new(until_ms)?),
                ActivityLeaseRevision::new(lease_revision)?,
            )?,
        ))
    }

    fn registration(supervision: u128, activity: u128) -> HostActivityLeaseRegistration {
        HostActivityLeaseRegistration {
            supervision_id: Uuid::from_u128(supervision),
            scope: HostActivityLeaseScope {
                location_id: Uuid::from_u128(1),
                location_revision: 2,
                workspace_id: Uuid::from_u128(3),
                workspace_revision: 4,
            },
            activity_id: Uuid::from_u128(activity),
            goal_id: Uuid::from_u128(5),
            goal_created_at_ms: 10,
            initiating_session_id: Uuid::from_u128(6),
            principal: HostPrincipalConfig {
                kind: HostPrincipalKind::TrustedStdio,
                id: None,
            },
            coordinator: HostCoordinatorPin {
                agent_id: Uuid::from_u128(7),
                session_id: Uuid::from_u128(6),
                revision: 1,
            },
        }
    }

    fn config(
        registrations: Vec<HostActivityLeaseRegistration>,
    ) -> HostActivityLeaseSupervisionConfig {
        HostActivityLeaseSupervisionConfig {
            journal_root: PathBuf::from("/tmp/forge-host-lease-journal"),
            lease_duration_ms: default_lease_duration_ms(),
            renew_interval_ms: default_renew_interval_ms(),
            registrations,
        }
    }

    #[test]
    fn registration_requires_exact_non_nil_identity_and_valid_timing() {
        let duplicate = config(vec![registration(10, 11), registration(12, 11)]);
        assert_eq!(
            duplicate.validate(Path::new("/tmp/registry.sqlite3")),
            Err(ConfigError::DuplicateRegistration)
        );

        let mut invalid = config(vec![registration(10, 11)]);
        invalid.registrations[0].goal_created_at_ms = -1;
        assert_eq!(
            invalid.registrations[0].validate(),
            Err(ConfigError::Timestamp)
        );

        let mut invalid_timing = config(vec![registration(10, 11)]);
        invalid_timing.renew_interval_ms = invalid_timing.lease_duration_ms / 2;
        assert_eq!(
            invalid_timing.validate(Path::new("/tmp/registry.sqlite3")),
            Err(ConfigError::Timing)
        );

        let mut invalid_scope = registration(20, 21);
        invalid_scope.scope.location_id = Uuid::nil();
        assert_eq!(invalid_scope.validate(), Err(ConfigError::NilIdentity));

        let mut wrong_coordinator_session = registration(22, 23);
        wrong_coordinator_session.coordinator.session_id = Uuid::from_u128(99);
        assert_eq!(
            wrong_coordinator_session.validate(),
            Err(ConfigError::CoordinatorSession)
        );
    }

    #[test]
    fn principal_rejects_missing_extra_and_nil_ids() {
        let direct = HostPrincipalConfig {
            kind: HostPrincipalKind::DirectToken,
            id: Some(Uuid::nil()),
        };
        assert_eq!(direct.into_source(), Err(ConfigError::Principal));
        let trusted_with_id = HostPrincipalConfig {
            kind: HostPrincipalKind::TrustedStdio,
            id: Some(Uuid::from_u128(1)),
        };
        assert_eq!(trusted_with_id.into_source(), Err(ConfigError::Principal));
    }

    #[test]
    fn renewal_observation_is_exact_and_never_a_causal_receipt() -> Result<(), Box<dyn Error>> {
        let current_runtime = RuntimeInstanceId::from_uuid(Uuid::from_u128(3));
        let previous_runtime = Uuid::from_u128(2);
        let pending = PendingRenewal {
            supervision_id: Uuid::from_u128(1),
            scope: SourceScopeSelector {
                location_id: Uuid::from_u128(4),
                location_revision: 1,
                workspace_id: Uuid::from_u128(5),
                workspace_revision: 1,
            },
            activity_id: Uuid::from_u128(11),
            owner_id: current_runtime.into_uuid(),
            expected_lease_revision: 5,
            duration_ms: 60_000,
            observed_at_ms: 100,
            prestate: LeasePrestate {
                activity_state: HostActivityState::Open,
                activity_revision: 7,
                lease_owner_id: current_runtime.into_uuid(),
                lease_until_ms: 1_000,
                lease_revision: 5,
            },
        };
        let observed = leased_activity(current_runtime.into_uuid(), 1_500, 6, 7)?;
        assert_eq!(
            classify_pending_renewal(
                &pending,
                &observed,
                current_runtime,
                TimestampMillis::new(200)?,
            ),
            RenewReadback::ObservedCurrentLease
        );

        let unchanged = leased_activity(current_runtime.into_uuid(), 1_000, 5, 7)?;
        assert_eq!(
            classify_pending_renewal(
                &pending,
                &unchanged,
                current_runtime,
                TimestampMillis::new(200)?,
            ),
            RenewReadback::StillPending
        );

        let changed_activity_revision = leased_activity(current_runtime.into_uuid(), 1_500, 6, 8)?;
        assert_eq!(
            classify_pending_renewal(
                &pending,
                &changed_activity_revision,
                current_runtime,
                TimestampMillis::new(200)?,
            ),
            RenewReadback::ChangedOrClosed
        );

        let old_boot_pending = PendingRenewal {
            owner_id: previous_runtime,
            prestate: LeasePrestate {
                lease_owner_id: previous_runtime,
                ..pending.prestate.clone()
            },
            ..pending.clone()
        };
        let old_boot_state = leased_activity(previous_runtime, 1_000, 5, 7)?;
        assert_eq!(
            classify_pending_renewal(
                &old_boot_pending,
                &old_boot_state,
                current_runtime,
                TimestampMillis::new(200)?,
            ),
            RenewReadback::ObservedOldState
        );
        Ok(())
    }

    #[test]
    fn pending_get_round_trips_exact_selector_without_probe_body_or_path()
    -> Result<(), Box<dyn Error>> {
        let selector = PendingResumeGet {
            supervision_id: Uuid::from_u128(10),
            scope: SourceScopeSelector {
                location_id: Uuid::from_u128(3),
                location_revision: 2,
                workspace_id: Uuid::from_u128(1),
                workspace_revision: 4,
            },
            goal_id: Uuid::from_u128(18),
            goal_created_at_ms: 19,
            coordinator: HostCoordinatorPin {
                agent_id: Uuid::from_u128(20),
                session_id: Uuid::from_u128(21),
                revision: 2,
            },
            request_id: Uuid::from_u128(11),
            request_digest: [12; 32],
            probe_digest: [13; 32],
            activity_id: Uuid::from_u128(14),
            agent_id: Uuid::from_u128(15),
            initiating_session_id: Uuid::from_u128(16),
            principal: HostPrincipalConfig {
                kind: HostPrincipalKind::TrustedStdio,
                id: None,
            },
            source_runtime_instance_id: Uuid::from_u128(17),
        };
        let encoded = serde_json::to_vec(&selector)?;
        let decoded: PendingResumeGet = serde_json::from_slice(&encoded)?;
        assert_eq!(decoded, selector);
        assert!(!String::from_utf8_lossy(&encoded).contains("/Users/"));
        assert!(!String::from_utf8_lossy(&encoded).contains("provider_body"));
        Ok(())
    }

    #[test]
    fn journal_rejects_oversized_unknown_and_mismatched_pending_records() {
        let unknown = br#"{"version":1,"pending":{},"extra":true}"#;
        assert!(serde_json::from_slice::<JournalFile>(unknown).is_err());

        let mut journal = JournalFile::default();
        let id = Uuid::from_u128(9);
        journal.pending.insert(
            id,
            PendingOperation::Renewal(PendingRenewal {
                supervision_id: id,
                scope: SourceScopeSelector {
                    location_id: Uuid::from_u128(1),
                    location_revision: 1,
                    workspace_id: Uuid::from_u128(2),
                    workspace_revision: 1,
                },
                activity_id: id,
                owner_id: Uuid::from_u128(3),
                expected_lease_revision: 2,
                duration_ms: 60_000,
                observed_at_ms: 10,
                prestate: LeasePrestate {
                    activity_state: HostActivityState::Open,
                    activity_revision: 1,
                    lease_owner_id: Uuid::from_u128(3),
                    lease_until_ms: 50_000,
                    lease_revision: 2,
                },
            }),
        );
        assert_eq!(
            journal
                .pending
                .get(&id)
                .map(PendingOperation::supervision_id),
            Some(id)
        );
    }
}
