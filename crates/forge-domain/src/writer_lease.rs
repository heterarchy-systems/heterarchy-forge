//! Typed, deterministic source-writer lease authority.
//!
//! Writer leases fence source mutation authority for one attached Agent inside
//! one live Activity. They deliberately do not introduce an Agent heartbeat:
//! Activity liveness remains authoritative and persistence/control layers must
//! validate the referenced attachment and Activity lease before admitting an
//! effect.

use std::fmt;
use std::str::FromStr;

use thiserror::Error;
use uuid::Uuid;

use crate::{
    ActivityId, AgentInstanceId, AgentInstanceRevision, AgentSessionId, AuthenticatedPrincipal,
    GoalNodeAttribution, TimestampMillis, WorkspaceId, WorkspaceRelativePath,
};

/// Exact source-write authority presented at durable mutation admission.
///
/// Persistence validates this atomically with the `ChangeSet` intent so a
/// detach/focus/lease race cannot create a source-write compatibility bypass.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SourceWriteAuthority {
    agent_id: AgentInstanceId,
    expected_agent_revision: AgentInstanceRevision,
    principal: AuthenticatedPrincipal,
    attribution: GoalNodeAttribution,
    writer_lease_id: WriterLeaseId,
    expected_writer_lease_revision: WriterLeaseRevision,
    session_id: AgentSessionId,
}

impl SourceWriteAuthority {
    pub const fn new(
        agent_id: AgentInstanceId,
        expected_agent_revision: AgentInstanceRevision,
        principal: AuthenticatedPrincipal,
        attribution: GoalNodeAttribution,
        writer_lease_id: WriterLeaseId,
        expected_writer_lease_revision: WriterLeaseRevision,
        session_id: AgentSessionId,
    ) -> Self {
        Self {
            agent_id,
            expected_agent_revision,
            principal,
            attribution,
            writer_lease_id,
            expected_writer_lease_revision,
            session_id,
        }
    }

    pub const fn agent_id(self) -> AgentInstanceId {
        self.agent_id
    }

    pub const fn expected_agent_revision(self) -> AgentInstanceRevision {
        self.expected_agent_revision
    }

    pub const fn principal(self) -> AuthenticatedPrincipal {
        self.principal
    }

    pub const fn attribution(self) -> GoalNodeAttribution {
        self.attribution
    }

    pub const fn writer_lease_id(self) -> WriterLeaseId {
        self.writer_lease_id
    }

    pub const fn expected_writer_lease_revision(self) -> WriterLeaseRevision {
        self.expected_writer_lease_revision
    }

    pub const fn session_id(self) -> AgentSessionId {
        self.session_id
    }
}

/// The authenticated producer of one `ChangeSet`: the holder of the Writer
/// Lease whose validated `SourceWriteAuthority` admitted the durable intent.
/// The producing Agent is total — a `ChangeSet` completion in every supported
/// path carries an authenticated actor — while the session stays optional so
/// the durable fact can represent exactly what was recorded. The producer
/// identity must be recorded inside the same authoritative transaction that
/// terminalizes the `ChangeSet` and its Diff evidence.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChangeSetProducer {
    agent_id: AgentInstanceId,
    session_id: Option<AgentSessionId>,
}

impl ChangeSetProducer {
    pub const fn new(agent_id: AgentInstanceId, session_id: AgentSessionId) -> Self {
        Self {
            agent_id,
            session_id: Some(session_id),
        }
    }

    /// The total producer Agent identity; absence is unrepresentable.
    pub const fn agent_id(self) -> AgentInstanceId {
        self.agent_id
    }

    pub const fn session_id(self) -> Option<AgentSessionId> {
        self.session_id
    }
}

/// Maximum scope entries owned by one Writer Lease.
pub const MAX_WRITER_LEASE_SCOPE_ENTRIES: usize = 64;
/// Inclusive minimum Writer Lease duration in milliseconds.
pub const MIN_WRITER_LEASE_DURATION_MILLIS: i64 = 1_000;
/// Inclusive maximum Writer Lease duration in milliseconds.
pub const MAX_WRITER_LEASE_DURATION_MILLIS: i64 = 300_000;

/// Stable opaque identity for one durable Writer Lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct WriterLeaseId(Uuid);

impl WriterLeaseId {
    pub const fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }

    pub const fn into_uuid(self) -> Uuid {
        self.0
    }
}

impl fmt::Display for WriterLeaseId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for WriterLeaseId {
    type Err = WriterLeaseIdParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(value)
            .map(Self)
            .map_err(WriterLeaseIdParseError::InvalidUuid)
    }
}

#[derive(Debug, Error)]
pub enum WriterLeaseIdParseError {
    #[error("invalid Writer Lease UUID")]
    InvalidUuid(#[source] uuid::Error),
}

/// Monotonic compare-and-set revision for one Writer Lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct WriterLeaseRevision(i64);

impl WriterLeaseRevision {
    pub const INITIAL: Self = Self(1);

    pub const fn new(value: i64) -> Result<Self, WriterLeaseRevisionError> {
        if value < 1 {
            Err(WriterLeaseRevisionError::Invalid { actual: value })
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> i64 {
        self.0
    }

    pub const fn checked_next(self) -> Result<Self, WriterLeaseRevisionError> {
        match self.0.checked_add(1) {
            Some(value) => Ok(Self(value)),
            None => Err(WriterLeaseRevisionError::Overflow { current: self.0 }),
        }
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum WriterLeaseRevisionError {
    #[error("Writer Lease revision must be at least 1, got {actual}")]
    Invalid { actual: i64 },
    #[error("Writer Lease revision overflowed at {current}")]
    Overflow { current: i64 },
}

/// Explicit bounded Writer Lease duration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct WriterLeaseDurationMillis(i64);

impl WriterLeaseDurationMillis {
    pub const MIN: Self = Self(MIN_WRITER_LEASE_DURATION_MILLIS);
    pub const MAX: Self = Self(MAX_WRITER_LEASE_DURATION_MILLIS);

    pub const fn new(value: i64) -> Result<Self, WriterLeaseDurationError> {
        if value < MIN_WRITER_LEASE_DURATION_MILLIS || value > MAX_WRITER_LEASE_DURATION_MILLIS {
            Err(WriterLeaseDurationError::OutOfRange {
                actual: value,
                minimum: MIN_WRITER_LEASE_DURATION_MILLIS,
                maximum: MAX_WRITER_LEASE_DURATION_MILLIS,
            })
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> i64 {
        self.0
    }

    pub const fn checked_lease_until(
        self,
        observed_at: TimestampMillis,
    ) -> Result<TimestampMillis, WriterLeaseDurationError> {
        match observed_at.get().checked_add(self.0) {
            Some(value) => match TimestampMillis::new(value) {
                Ok(timestamp) => Ok(timestamp),
                Err(_) => Err(WriterLeaseDurationError::Overflow {
                    observed_at,
                    duration: self,
                }),
            },
            None => Err(WriterLeaseDurationError::Overflow {
                observed_at,
                duration: self,
            }),
        }
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum WriterLeaseDurationError {
    #[error("Writer Lease duration {actual}ms is outside {minimum}..={maximum}ms")]
    OutOfRange {
        actual: i64,
        minimum: i64,
        maximum: i64,
    },
    #[error("Writer Lease expiry overflowed at {observed_at:?} for {duration:?}")]
    Overflow {
        observed_at: TimestampMillis,
        duration: WriterLeaseDurationMillis,
    },
}

/// One lexical path authority entry inside a Writer Lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum WriterLeaseScopeKind {
    /// Authority applies only to this exact path.
    ExactPath,
    /// Authority applies to the directory path and every descendant path.
    DirectorySubtree,
}

/// One typed scope entry. The path is already canonical and Workspace-relative.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct WriterLeaseScopeEntry {
    kind: WriterLeaseScopeKind,
    path: WorkspaceRelativePath,
}

impl WriterLeaseScopeEntry {
    pub const fn new(kind: WriterLeaseScopeKind, path: WorkspaceRelativePath) -> Self {
        Self { kind, path }
    }

    pub const fn kind(&self) -> WriterLeaseScopeKind {
        self.kind
    }

    pub const fn path(&self) -> &WorkspaceRelativePath {
        &self.path
    }

    pub fn covers(&self, path: &WorkspaceRelativePath) -> bool {
        match self.kind {
            WriterLeaseScopeKind::ExactPath => self.path == *path,
            WriterLeaseScopeKind::DirectorySubtree => {
                path.as_path().starts_with(self.path.as_path())
            }
        }
    }

    pub fn overlaps(&self, other: &Self) -> bool {
        match (self.kind, other.kind) {
            (WriterLeaseScopeKind::ExactPath, WriterLeaseScopeKind::ExactPath) => {
                self.path == other.path
            }
            (WriterLeaseScopeKind::ExactPath, WriterLeaseScopeKind::DirectorySubtree) => {
                other.covers(&self.path)
            }
            (WriterLeaseScopeKind::DirectorySubtree, WriterLeaseScopeKind::ExactPath) => {
                self.covers(&other.path)
            }
            (WriterLeaseScopeKind::DirectorySubtree, WriterLeaseScopeKind::DirectorySubtree) => {
                self.path.as_path().starts_with(other.path.as_path())
                    || other.path.as_path().starts_with(self.path.as_path())
            }
        }
    }
}

/// Canonical, bounded set of source paths owned by one Writer Lease.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WriterLeaseScope {
    entries: Vec<WriterLeaseScopeEntry>,
}

impl WriterLeaseScope {
    pub fn new(mut entries: Vec<WriterLeaseScopeEntry>) -> Result<Self, WriterLeaseScopeError> {
        if entries.is_empty() {
            return Err(WriterLeaseScopeError::Empty);
        }
        if entries.len() > MAX_WRITER_LEASE_SCOPE_ENTRIES {
            return Err(WriterLeaseScopeError::TooManyEntries {
                actual: entries.len(),
                maximum: MAX_WRITER_LEASE_SCOPE_ENTRIES,
            });
        }
        entries.sort_unstable();
        for left in 0..entries.len() {
            for right in (left + 1)..entries.len() {
                if entries[left].overlaps(&entries[right]) {
                    return Err(WriterLeaseScopeError::OverlappingEntries { left, right });
                }
            }
        }
        Ok(Self { entries })
    }

    pub fn entries(&self) -> &[WriterLeaseScopeEntry] {
        &self.entries
    }

    pub fn covers(&self, path: &WorkspaceRelativePath) -> bool {
        self.entries.iter().any(|entry| entry.covers(path))
    }

    pub fn overlaps(&self, other: &Self) -> bool {
        self.entries
            .iter()
            .any(|left| other.entries.iter().any(|right| left.overlaps(right)))
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum WriterLeaseScopeError {
    #[error("Writer Lease scope must contain at least one path")]
    Empty,
    #[error("Writer Lease scope has {actual} entries; maximum is {maximum}")]
    TooManyEntries { actual: usize, maximum: usize },
    #[error("Writer Lease scope entries {left} and {right} overlap")]
    OverlappingEntries { left: usize, right: usize },
}

/// Durable semantic state. Expiry is intentionally not a persisted state
/// transition: an expired Active lease remains fencing authority until explicit
/// recovery/release resolves it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WriterLeaseState {
    Active,
    Released,
}

/// Operator/control projection at one explicit observation timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WriterLeaseStatus {
    Active,
    ExpiredRecoveryRequired,
    Released,
}

/// Durable Writer Lease record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriterLease {
    id: WriterLeaseId,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    agent_id: AgentInstanceId,
    scope: WriterLeaseScope,
    state: WriterLeaseState,
    acquired_at: TimestampMillis,
    updated_at: TimestampMillis,
    lease_until: TimestampMillis,
    revision: WriterLeaseRevision,
}

impl WriterLease {
    pub fn acquire(command: &AcquireWriterLease) -> Result<Self, WriterLeaseError> {
        Ok(Self {
            id: command.lease_id,
            workspace_id: command.workspace_id,
            activity_id: command.activity_id,
            agent_id: command.agent_id,
            scope: command.scope.clone(),
            state: WriterLeaseState::Active,
            acquired_at: command.observed_at,
            updated_at: command.observed_at,
            lease_until: command.lease_until,
            revision: WriterLeaseRevision::INITIAL,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        id: WriterLeaseId,
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        agent_id: AgentInstanceId,
        scope: WriterLeaseScope,
        state: WriterLeaseState,
        acquired_at: TimestampMillis,
        updated_at: TimestampMillis,
        lease_until: TimestampMillis,
        revision: WriterLeaseRevision,
    ) -> Result<Self, WriterLeaseError> {
        if updated_at < acquired_at {
            return Err(WriterLeaseError::TimestampInversion);
        }
        if lease_until <= acquired_at {
            return Err(WriterLeaseError::InvalidLeaseWindow);
        }
        Ok(Self {
            id,
            workspace_id,
            activity_id,
            agent_id,
            scope,
            state,
            acquired_at,
            updated_at,
            lease_until,
            revision,
        })
    }

    pub const fn id(&self) -> WriterLeaseId {
        self.id
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn activity_id(&self) -> ActivityId {
        self.activity_id
    }

    pub const fn agent_id(&self) -> AgentInstanceId {
        self.agent_id
    }

    pub const fn scope(&self) -> &WriterLeaseScope {
        &self.scope
    }

    pub const fn state(&self) -> WriterLeaseState {
        self.state
    }

    pub const fn acquired_at(&self) -> TimestampMillis {
        self.acquired_at
    }

    pub const fn updated_at(&self) -> TimestampMillis {
        self.updated_at
    }

    pub const fn lease_until(&self) -> TimestampMillis {
        self.lease_until
    }

    pub const fn revision(&self) -> WriterLeaseRevision {
        self.revision
    }

    pub fn status(&self, observed_at: TimestampMillis) -> WriterLeaseStatus {
        match self.state {
            WriterLeaseState::Released => WriterLeaseStatus::Released,
            WriterLeaseState::Active if observed_at < self.lease_until => WriterLeaseStatus::Active,
            WriterLeaseState::Active => WriterLeaseStatus::ExpiredRecoveryRequired,
        }
    }

    /// Expired-but-unreleased leases still conflict. This is the key fence that
    /// prevents silent ownership transfer after a crash or scheduler delay.
    pub fn conflicts_with(&self, other: &Self) -> bool {
        self.state == WriterLeaseState::Active
            && other.state == WriterLeaseState::Active
            && self.scope.overlaps(&other.scope)
    }

    pub fn authorizes_path(
        &self,
        agent_id: AgentInstanceId,
        path: &WorkspaceRelativePath,
        observed_at: TimestampMillis,
    ) -> bool {
        self.agent_id == agent_id
            && self.status(observed_at) == WriterLeaseStatus::Active
            && self.scope.covers(path)
    }

    pub fn renew(&self, command: &RenewWriterLease) -> Result<Self, WriterLeaseTransitionError> {
        self.validate_owner_revision(
            command.lease_id,
            command.agent_id,
            command.expected_revision,
        )?;
        if self.state != WriterLeaseState::Active {
            return Err(WriterLeaseTransitionError::Released);
        }
        if command.observed_at < self.updated_at {
            return Err(WriterLeaseTransitionError::TimestampInversion);
        }
        if command.observed_at >= self.lease_until {
            return Err(WriterLeaseTransitionError::ExpiredRecoveryRequired);
        }
        if command.lease_until <= self.lease_until {
            return Err(WriterLeaseTransitionError::LeaseNotForward);
        }
        let revision = self.revision.checked_next().map_err(|error| {
            WriterLeaseTransitionError::RevisionOverflow {
                current: match error {
                    WriterLeaseRevisionError::Invalid { actual } => actual,
                    WriterLeaseRevisionError::Overflow { current } => current,
                },
            }
        })?;
        let mut renewed = self.clone();
        renewed.updated_at = command.observed_at;
        renewed.lease_until = command.lease_until;
        renewed.revision = revision;
        Ok(renewed)
    }

    /// Explicit release remains allowed after expiry so recovery can clear a
    /// fenced lease without pretending ownership silently transferred.
    pub fn release(
        &self,
        command: &ReleaseWriterLease,
    ) -> Result<Self, WriterLeaseTransitionError> {
        self.validate_owner_revision(
            command.lease_id,
            command.agent_id,
            command.expected_revision,
        )?;
        if self.state != WriterLeaseState::Active {
            return Err(WriterLeaseTransitionError::Released);
        }
        if command.observed_at < self.updated_at {
            return Err(WriterLeaseTransitionError::TimestampInversion);
        }
        let revision = self.revision.checked_next().map_err(|error| {
            WriterLeaseTransitionError::RevisionOverflow {
                current: match error {
                    WriterLeaseRevisionError::Invalid { actual } => actual,
                    WriterLeaseRevisionError::Overflow { current } => current,
                },
            }
        })?;
        let mut released = self.clone();
        released.state = WriterLeaseState::Released;
        released.updated_at = command.observed_at;
        released.revision = revision;
        Ok(released)
    }

    fn validate_owner_revision(
        &self,
        lease_id: WriterLeaseId,
        agent_id: AgentInstanceId,
        expected_revision: WriterLeaseRevision,
    ) -> Result<(), WriterLeaseTransitionError> {
        if self.id != lease_id {
            return Err(WriterLeaseTransitionError::LeaseMismatch);
        }
        if self.agent_id != agent_id {
            return Err(WriterLeaseTransitionError::StaleOwner);
        }
        if self.revision != expected_revision {
            return Err(WriterLeaseTransitionError::StaleRevision);
        }
        Ok(())
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum WriterLeaseError {
    #[error("Writer Lease updated timestamp precedes acquisition")]
    TimestampInversion,
    #[error("Writer Lease expiry must follow acquisition")]
    InvalidLeaseWindow,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum WriterLeaseTransitionError {
    #[error("Writer Lease identity does not match the command")]
    LeaseMismatch,
    #[error("Writer Lease owner is stale")]
    StaleOwner,
    #[error("Writer Lease revision is stale")]
    StaleRevision,
    #[error("Writer Lease is already released")]
    Released,
    #[error("Writer Lease command timestamp precedes the current update")]
    TimestampInversion,
    #[error("Writer Lease expired and requires explicit recovery/release")]
    ExpiredRecoveryRequired,
    #[error("Writer Lease renewal expiry must move forward")]
    LeaseNotForward,
    #[error("Writer Lease revision overflowed at {current}")]
    RevisionOverflow { current: i64 },
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcquireWriterLease {
    lease_id: WriterLeaseId,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    agent_id: AgentInstanceId,
    scope: WriterLeaseScope,
    lease_until: TimestampMillis,
    observed_at: TimestampMillis,
    session_id: AgentSessionId,
    principal: AuthenticatedPrincipal,
}

impl AcquireWriterLease {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lease_id: WriterLeaseId,
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        agent_id: AgentInstanceId,
        scope: WriterLeaseScope,
        duration: WriterLeaseDurationMillis,
        observed_at: TimestampMillis,
        session_id: AgentSessionId,
        principal: AuthenticatedPrincipal,
    ) -> Result<Self, WriterLeaseDurationError> {
        let lease_until = duration.checked_lease_until(observed_at)?;
        Ok(Self {
            lease_id,
            workspace_id,
            activity_id,
            agent_id,
            scope,
            lease_until,
            observed_at,
            session_id,
            principal,
        })
    }

    pub const fn lease_id(&self) -> WriterLeaseId {
        self.lease_id
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn activity_id(&self) -> ActivityId {
        self.activity_id
    }

    pub const fn agent_id(&self) -> AgentInstanceId {
        self.agent_id
    }

    pub const fn scope(&self) -> &WriterLeaseScope {
        &self.scope
    }

    pub const fn lease_until(&self) -> TimestampMillis {
        self.lease_until
    }

    pub const fn observed_at(&self) -> TimestampMillis {
        self.observed_at
    }

    pub const fn session_id(&self) -> AgentSessionId {
        self.session_id
    }

    pub const fn principal(&self) -> AuthenticatedPrincipal {
        self.principal
    }

    pub fn with_observed_at(
        mut self,
        observed_at: TimestampMillis,
    ) -> Result<Self, WriterLeaseDurationError> {
        let duration = WriterLeaseDurationMillis::new(
            self.lease_until
                .get()
                .saturating_sub(self.observed_at.get()),
        )?;
        self.lease_until = duration.checked_lease_until(observed_at)?;
        self.observed_at = observed_at;
        Ok(self)
    }
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RenewWriterLease {
    lease_id: WriterLeaseId,
    agent_id: AgentInstanceId,
    expected_revision: WriterLeaseRevision,
    lease_until: TimestampMillis,
    observed_at: TimestampMillis,
    session_id: AgentSessionId,
    principal: AuthenticatedPrincipal,
}

impl RenewWriterLease {
    pub fn new(
        lease_id: WriterLeaseId,
        agent_id: AgentInstanceId,
        expected_revision: WriterLeaseRevision,
        duration: WriterLeaseDurationMillis,
        observed_at: TimestampMillis,
        session_id: AgentSessionId,
        principal: AuthenticatedPrincipal,
    ) -> Result<Self, WriterLeaseDurationError> {
        let lease_until = duration.checked_lease_until(observed_at)?;
        Ok(Self {
            lease_id,
            agent_id,
            expected_revision,
            lease_until,
            observed_at,
            session_id,
            principal,
        })
    }

    pub const fn lease_id(self) -> WriterLeaseId {
        self.lease_id
    }

    pub const fn agent_id(self) -> AgentInstanceId {
        self.agent_id
    }

    pub const fn expected_revision(self) -> WriterLeaseRevision {
        self.expected_revision
    }

    pub const fn lease_until(self) -> TimestampMillis {
        self.lease_until
    }

    pub const fn observed_at(self) -> TimestampMillis {
        self.observed_at
    }

    pub const fn session_id(self) -> AgentSessionId {
        self.session_id
    }

    pub const fn principal(self) -> AuthenticatedPrincipal {
        self.principal
    }

    pub fn with_observed_at(
        mut self,
        observed_at: TimestampMillis,
    ) -> Result<Self, WriterLeaseDurationError> {
        let duration = WriterLeaseDurationMillis::new(
            self.lease_until
                .get()
                .saturating_sub(self.observed_at.get()),
        )?;
        self.lease_until = duration.checked_lease_until(observed_at)?;
        self.observed_at = observed_at;
        Ok(self)
    }
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReleaseWriterLease {
    lease_id: WriterLeaseId,
    agent_id: AgentInstanceId,
    expected_revision: WriterLeaseRevision,
    observed_at: TimestampMillis,
    session_id: AgentSessionId,
    principal: AuthenticatedPrincipal,
}

impl ReleaseWriterLease {
    pub const fn new(
        lease_id: WriterLeaseId,
        agent_id: AgentInstanceId,
        expected_revision: WriterLeaseRevision,
        observed_at: TimestampMillis,
        session_id: AgentSessionId,
        principal: AuthenticatedPrincipal,
    ) -> Self {
        Self {
            lease_id,
            agent_id,
            expected_revision,
            observed_at,
            session_id,
            principal,
        }
    }

    pub const fn lease_id(self) -> WriterLeaseId {
        self.lease_id
    }

    pub const fn agent_id(self) -> AgentInstanceId {
        self.agent_id
    }

    pub const fn expected_revision(self) -> WriterLeaseRevision {
        self.expected_revision
    }

    pub const fn observed_at(self) -> TimestampMillis {
        self.observed_at
    }

    pub const fn session_id(self) -> AgentSessionId {
        self.session_id
    }

    pub const fn principal(self) -> AuthenticatedPrincipal {
        self.principal
    }

    pub const fn with_observed_at(mut self, observed_at: TimestampMillis) -> Self {
        self.observed_at = observed_at;
        self
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn path(value: &str) -> Result<WorkspaceRelativePath, Box<dyn std::error::Error>> {
        Ok(WorkspaceRelativePath::new(PathBuf::from(value))?)
    }

    fn exact(value: &str) -> Result<WriterLeaseScopeEntry, Box<dyn std::error::Error>> {
        Ok(WriterLeaseScopeEntry::new(
            WriterLeaseScopeKind::ExactPath,
            path(value)?,
        ))
    }

    fn subtree(value: &str) -> Result<WriterLeaseScopeEntry, Box<dyn std::error::Error>> {
        Ok(WriterLeaseScopeEntry::new(
            WriterLeaseScopeKind::DirectorySubtree,
            path(value)?,
        ))
    }

    fn lease(
        scope: WriterLeaseScope,
        observed_at: i64,
        duration: i64,
    ) -> Result<WriterLease, Box<dyn std::error::Error>> {
        let command = AcquireWriterLease::new(
            WriterLeaseId::from_uuid(Uuid::from_u128(1)),
            WorkspaceId::from_uuid(Uuid::from_u128(2)),
            ActivityId::from_uuid(Uuid::from_u128(3)),
            AgentInstanceId::from_uuid(Uuid::from_u128(4)),
            scope,
            WriterLeaseDurationMillis::new(duration)?,
            TimestampMillis::new(observed_at)?,
            AgentSessionId::from_uuid(Uuid::from_u128(5)),
            AuthenticatedPrincipal::TrustedStdio,
        )?;
        Ok(WriterLease::acquire(&command)?)
    }

    #[test]
    fn exact_and_subtree_overlap_is_component_aware() -> Result<(), Box<dyn std::error::Error>> {
        assert!(exact("src/lib.rs")?.overlaps(&subtree("src")?));
        assert!(subtree("src")?.overlaps(&subtree("src/domain")?));
        assert!(!exact("src2/lib.rs")?.overlaps(&subtree("src")?));
        assert!(!subtree("src2")?.overlaps(&subtree("src")?));
        Ok(())
    }

    #[test]
    fn scope_is_bounded_sorted_and_rejects_internal_overlap()
    -> Result<(), Box<dyn std::error::Error>> {
        let scope = WriterLeaseScope::new(vec![exact("z.rs")?, exact("a.rs")?])?;
        assert_eq!(scope.entries()[0].path(), &path("a.rs")?);
        assert!(matches!(
            WriterLeaseScope::new(vec![subtree("src")?, exact("src/lib.rs")?]),
            Err(WriterLeaseScopeError::OverlappingEntries { .. })
        ));
        assert!(matches!(
            WriterLeaseScope::new(Vec::new()),
            Err(WriterLeaseScopeError::Empty)
        ));
        Ok(())
    }

    #[test]
    fn expired_active_lease_stays_conflicting_until_explicit_release()
    -> Result<(), Box<dyn std::error::Error>> {
        let first = lease(WriterLeaseScope::new(vec![subtree("src")?])?, 10_000, 1_000)?;
        let second = lease(
            WriterLeaseScope::new(vec![exact("src/lib.rs")?])?,
            20_000,
            1_000,
        )?;
        assert_eq!(
            first.status(TimestampMillis::new(11_000)?),
            WriterLeaseStatus::ExpiredRecoveryRequired
        );
        assert!(first.conflicts_with(&second));
        Ok(())
    }

    #[test]
    fn renew_after_expiry_fails_but_explicit_release_succeeds()
    -> Result<(), Box<dyn std::error::Error>> {
        let active = lease(
            WriterLeaseScope::new(vec![exact("src/lib.rs")?])?,
            10_000,
            1_000,
        )?;
        let renewal = RenewWriterLease::new(
            active.id(),
            active.agent_id(),
            active.revision(),
            WriterLeaseDurationMillis::new(2_000)?,
            TimestampMillis::new(11_000)?,
            AgentSessionId::from_uuid(Uuid::from_u128(5)),
            AuthenticatedPrincipal::TrustedStdio,
        )?;
        assert_eq!(
            active.renew(&renewal),
            Err(WriterLeaseTransitionError::ExpiredRecoveryRequired)
        );
        let release = ReleaseWriterLease::new(
            active.id(),
            active.agent_id(),
            active.revision(),
            TimestampMillis::new(11_000)?,
            AgentSessionId::from_uuid(Uuid::from_u128(5)),
            AuthenticatedPrincipal::TrustedStdio,
        );
        let released = active.release(&release)?;
        assert_eq!(released.state(), WriterLeaseState::Released);
        assert_eq!(released.revision().get(), 2);
        Ok(())
    }

    #[test]
    fn delayed_renewal_refresh_preserves_duration_and_fences_expired_lease()
    -> Result<(), Box<dyn std::error::Error>> {
        let active = lease(
            WriterLeaseScope::new(vec![exact("src/lib.rs")?])?,
            10_000,
            1_000,
        )?;
        let queued = RenewWriterLease::new(
            active.id(),
            active.agent_id(),
            active.revision(),
            WriterLeaseDurationMillis::new(2_000)?,
            TimestampMillis::new(10_500)?,
            AgentSessionId::from_uuid(Uuid::from_u128(5)),
            AuthenticatedPrincipal::TrustedStdio,
        )?;
        let refreshed = queued.with_observed_at(TimestampMillis::new(11_500)?)?;

        assert_eq!(refreshed.observed_at(), TimestampMillis::new(11_500)?);
        assert_eq!(refreshed.lease_until(), TimestampMillis::new(13_500)?);
        assert!(active.renew(&queued).is_ok());
        assert_eq!(
            active.renew(&refreshed),
            Err(WriterLeaseTransitionError::ExpiredRecoveryRequired)
        );
        Ok(())
    }

    #[test]
    fn live_owner_can_renew_forward_and_authorize_covered_path()
    -> Result<(), Box<dyn std::error::Error>> {
        let active = lease(WriterLeaseScope::new(vec![subtree("src")?])?, 10_000, 2_000)?;
        assert!(active.authorizes_path(
            active.agent_id(),
            &path("src/domain/lib.rs")?,
            TimestampMillis::new(10_500)?,
        ));
        let renewal = RenewWriterLease::new(
            active.id(),
            active.agent_id(),
            active.revision(),
            WriterLeaseDurationMillis::new(3_000)?,
            TimestampMillis::new(11_000)?,
            AgentSessionId::from_uuid(Uuid::from_u128(5)),
            AuthenticatedPrincipal::TrustedStdio,
        )?;
        let renewed = active.renew(&renewal)?;
        assert_eq!(renewed.lease_until(), TimestampMillis::new(14_000)?);
        assert_eq!(renewed.revision().get(), 2);
        Ok(())
    }

    #[test]
    fn duration_is_explicitly_bounded() {
        assert!(WriterLeaseDurationMillis::new(MIN_WRITER_LEASE_DURATION_MILLIS).is_ok());
        assert!(WriterLeaseDurationMillis::new(MAX_WRITER_LEASE_DURATION_MILLIS).is_ok());
        assert!(WriterLeaseDurationMillis::new(MIN_WRITER_LEASE_DURATION_MILLIS - 1).is_err());
        assert!(WriterLeaseDurationMillis::new(MAX_WRITER_LEASE_DURATION_MILLIS + 1).is_err());
    }
}
