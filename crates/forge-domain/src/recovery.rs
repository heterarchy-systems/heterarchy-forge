//! Pure recovery-maintenance lease state and fencing transitions.
//!
//! A recovery lease is a short-lived, Workspace-scoped fence.  This module
//! contains no clock, persistence, task, or process access: callers observe
//! timestamps and pass them to the commands below.

use thiserror::Error;

use crate::{RuntimeInstanceId, TimestampMillis, WorkspaceId};

/// Inclusive minimum recovery-maintenance lease duration in milliseconds.
pub const MIN_RECOVERY_LEASE_DURATION_MILLIS: i64 = 1_000;
/// Inclusive maximum recovery-maintenance lease duration in milliseconds.
pub const MAX_RECOVERY_LEASE_DURATION_MILLIS: i64 = 300_000;

/// Monotonic fencing epoch for a recovery-maintenance lease.
///
/// Epoch zero is the initial, never-acquired epoch.  It is persisted as a
/// non-negative `i64`; every successful acquisition, including takeover of an
/// expired lease, advances it exactly once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RecoveryLeaseEpoch(i64);

impl RecoveryLeaseEpoch {
    /// Epoch used by an initial released snapshot.
    pub const INITIAL: Self = Self(0);

    /// Validates a persisted epoch.
    pub const fn new(value: i64) -> Result<Self, RecoveryLeaseEpochError> {
        if value < 0 {
            Err(RecoveryLeaseEpochError::Invalid { actual: value })
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the persisted representation.
    pub const fn get(self) -> i64 {
        self.0
    }

    /// Advances the epoch without wrapping.
    pub const fn checked_next(self) -> Result<Self, RecoveryLeaseEpochError> {
        match self.0.checked_add(1) {
            Some(value) => Ok(Self(value)),
            None => Err(RecoveryLeaseEpochError::Overflow { current: self.0 }),
        }
    }
}

/// Validation failures for [`RecoveryLeaseEpoch`].
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryLeaseEpochError {
    #[error("recovery lease epoch must be non-negative, got {actual}")]
    Invalid { actual: i64 },
    #[error("recovery lease epoch overflowed at {current}")]
    Overflow { current: i64 },
}

/// Monotonic compare-and-set revision for a recovery-maintenance lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RecoveryLeaseRevision(i64);

impl RecoveryLeaseRevision {
    /// Revision used by an initial released snapshot.
    pub const INITIAL: Self = Self(1);

    /// Validates a persisted revision.
    pub const fn new(value: i64) -> Result<Self, RecoveryLeaseRevisionError> {
        if value < 1 {
            Err(RecoveryLeaseRevisionError::Invalid { actual: value })
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the persisted representation.
    pub const fn get(self) -> i64 {
        self.0
    }

    /// Advances the revision without wrapping.
    pub const fn checked_next(self) -> Result<Self, RecoveryLeaseRevisionError> {
        match self.0.checked_add(1) {
            Some(value) => Ok(Self(value)),
            None => Err(RecoveryLeaseRevisionError::Overflow { current: self.0 }),
        }
    }
}

/// Validation failures for [`RecoveryLeaseRevision`].
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryLeaseRevisionError {
    #[error("recovery lease revision must be at least 1, got {actual}")]
    Invalid { actual: i64 },
    #[error("recovery lease revision overflowed at {current}")]
    Overflow { current: i64 },
}

/// Validated recovery-maintenance lease duration in milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RecoveryLeaseDurationMillis(i64);

impl RecoveryLeaseDurationMillis {
    /// Inclusive minimum duration.
    pub const MIN: Self = Self(MIN_RECOVERY_LEASE_DURATION_MILLIS);
    /// Inclusive maximum duration.
    pub const MAX: Self = Self(MAX_RECOVERY_LEASE_DURATION_MILLIS);

    /// Validates an explicit bounded duration.
    pub const fn new(value: i64) -> Result<Self, RecoveryLeaseDurationError> {
        if value < MIN_RECOVERY_LEASE_DURATION_MILLIS || value > MAX_RECOVERY_LEASE_DURATION_MILLIS
        {
            Err(RecoveryLeaseDurationError::OutOfRange {
                actual: value,
                minimum: MIN_RECOVERY_LEASE_DURATION_MILLIS,
                maximum: MAX_RECOVERY_LEASE_DURATION_MILLIS,
            })
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the duration in milliseconds.
    pub const fn get(self) -> i64 {
        self.0
    }

    /// Produces an expiry from an explicit timestamp without wrapping.
    pub const fn checked_lease_until(
        self,
        observed_at: TimestampMillis,
    ) -> Result<TimestampMillis, RecoveryLeaseDurationError> {
        match observed_at.get().checked_add(self.0) {
            Some(value) => match TimestampMillis::new(value) {
                Ok(timestamp) => Ok(timestamp),
                Err(_) => Err(RecoveryLeaseDurationError::Overflow {
                    observed_at,
                    duration: self,
                }),
            },
            None => Err(RecoveryLeaseDurationError::Overflow {
                observed_at,
                duration: self,
            }),
        }
    }
}

/// Validation failures for a bounded recovery-lease duration.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryLeaseDurationError {
    #[error("recovery lease duration {actual}ms is outside {minimum}..={maximum}ms")]
    OutOfRange {
        actual: i64,
        minimum: i64,
        maximum: i64,
    },
    #[error("recovery lease expiry overflowed at {observed_at:?} for {duration:?}")]
    Overflow {
        observed_at: TimestampMillis,
        duration: RecoveryLeaseDurationMillis,
    },
}

/// Errors while constructing or rehydrating a recovery-maintenance lease.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryMaintenanceLeaseError {
    #[error("recovery lease owner and expiry must both be present or both be absent")]
    PartialLease,
    #[error("owned recovery lease expiry must follow its updated timestamp")]
    ExpiryNotAfterUpdatedAt,
    #[error("owned recovery lease must have a non-initial fencing epoch")]
    OwnedAtInitialEpoch,
}

/// Errors raised while applying a command to one lease snapshot.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryLeaseTransitionError {
    #[error("recovery lease Workspace does not match the command")]
    WorkspaceMismatch,
    #[error("recovery lease command timestamp precedes the current update")]
    TimestampInversion,
    #[error("recovery lease is busy with another live owner")]
    Busy,
    #[error("recovery lease claim conflicts with the current owner and expiry")]
    ClaimConflict,
    #[error("recovery lease owner is stale")]
    StaleOwner,
    #[error("recovery lease epoch is stale")]
    StaleEpoch,
    #[error("recovery lease revision is stale")]
    StaleRevision,
    #[error("recovery lease has expired")]
    Expired,
    #[error("recovery lease renewal expiry must move forward")]
    LeaseNotForward,
    #[error("recovery lease epoch overflowed at {current}")]
    EpochOverflow { current: i64 },
    #[error("recovery lease revision overflowed at {current}")]
    RevisionOverflow { current: i64 },
}

/// Command to claim or take over a Workspace recovery-maintenance lease.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ClaimRecoveryLease {
    workspace_id: WorkspaceId,
    owner_id: RuntimeInstanceId,
    lease_until: TimestampMillis,
    observed_at: TimestampMillis,
}

impl ClaimRecoveryLease {
    /// Builds a claim from a bounded duration and explicit observation.
    pub fn new(
        workspace_id: WorkspaceId,
        owner_id: RuntimeInstanceId,
        duration: RecoveryLeaseDurationMillis,
        observed_at: TimestampMillis,
    ) -> Result<Self, RecoveryLeaseDurationError> {
        let lease_until = duration.checked_lease_until(observed_at)?;
        Ok(Self {
            workspace_id,
            owner_id,
            lease_until,
            observed_at,
        })
    }

    pub const fn workspace_id(self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn owner_id(self) -> RuntimeInstanceId {
        self.owner_id
    }

    pub const fn lease_until(self) -> TimestampMillis {
        self.lease_until
    }

    pub const fn observed_at(self) -> TimestampMillis {
        self.observed_at
    }
}

/// Command to renew a currently owned recovery-maintenance lease.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RenewRecoveryLease {
    workspace_id: WorkspaceId,
    owner_id: RuntimeInstanceId,
    expected_epoch: RecoveryLeaseEpoch,
    expected_revision: RecoveryLeaseRevision,
    lease_until: TimestampMillis,
    observed_at: TimestampMillis,
}

impl RenewRecoveryLease {
    /// Builds a renewal from a bounded duration and explicit observation.
    pub fn new(
        workspace_id: WorkspaceId,
        owner_id: RuntimeInstanceId,
        expected_epoch: RecoveryLeaseEpoch,
        expected_revision: RecoveryLeaseRevision,
        duration: RecoveryLeaseDurationMillis,
        observed_at: TimestampMillis,
    ) -> Result<Self, RecoveryLeaseDurationError> {
        let lease_until = duration.checked_lease_until(observed_at)?;
        Ok(Self {
            workspace_id,
            owner_id,
            expected_epoch,
            expected_revision,
            lease_until,
            observed_at,
        })
    }

    pub const fn workspace_id(self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn owner_id(self) -> RuntimeInstanceId {
        self.owner_id
    }

    pub const fn expected_epoch(self) -> RecoveryLeaseEpoch {
        self.expected_epoch
    }

    pub const fn expected_revision(self) -> RecoveryLeaseRevision {
        self.expected_revision
    }

    pub const fn lease_until(self) -> TimestampMillis {
        self.lease_until
    }

    pub const fn observed_at(self) -> TimestampMillis {
        self.observed_at
    }
}

/// Command to release a currently owned recovery-maintenance lease.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReleaseRecoveryLease {
    workspace_id: WorkspaceId,
    owner_id: RuntimeInstanceId,
    expected_epoch: RecoveryLeaseEpoch,
    expected_revision: RecoveryLeaseRevision,
    observed_at: TimestampMillis,
}

impl ReleaseRecoveryLease {
    /// Builds a release command with exact fencing observations.
    pub const fn new(
        workspace_id: WorkspaceId,
        owner_id: RuntimeInstanceId,
        expected_epoch: RecoveryLeaseEpoch,
        expected_revision: RecoveryLeaseRevision,
        observed_at: TimestampMillis,
    ) -> Self {
        Self {
            workspace_id,
            owner_id,
            expected_epoch,
            expected_revision,
            observed_at,
        }
    }

    pub const fn workspace_id(self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn owner_id(self) -> RuntimeInstanceId {
        self.owner_id
    }

    pub const fn expected_epoch(self) -> RecoveryLeaseEpoch {
        self.expected_epoch
    }

    pub const fn expected_revision(self) -> RecoveryLeaseRevision {
        self.expected_revision
    }

    pub const fn observed_at(self) -> TimestampMillis {
        self.observed_at
    }
}

/// Result of evaluating a claim against one lease snapshot.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecoveryLeaseClaimDecision {
    /// The snapshot is released or expired and can be acquired.
    Acquired,
    /// The exact owner and expiry are already live; retrying is idempotent.
    AlreadyOwned,
    /// A different owner still holds a live lease.
    Busy,
    /// The same owner requested a different live expiry; it must renew exactly.
    ClaimConflict,
}

/// Result of evaluating a renewal against one lease snapshot.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecoveryLeaseRenewDecision {
    /// The exact owner, epoch, and revision may renew the lease.
    Renew,
}

/// Result of evaluating a release against one lease snapshot.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecoveryLeaseReleaseDecision {
    /// The exact owner, epoch, and revision may release the lease.
    Release,
}

/// Durable Workspace-scoped recovery-maintenance lease snapshot.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryMaintenanceLease {
    workspace_id: WorkspaceId,
    owner_id: Option<RuntimeInstanceId>,
    lease_until: Option<TimestampMillis>,
    epoch: RecoveryLeaseEpoch,
    updated_at: TimestampMillis,
    revision: RecoveryLeaseRevision,
}

impl RecoveryMaintenanceLease {
    /// Creates the initial released snapshot for a Workspace.
    pub const fn released(workspace_id: WorkspaceId, updated_at: TimestampMillis) -> Self {
        Self {
            workspace_id,
            owner_id: None,
            lease_until: None,
            epoch: RecoveryLeaseEpoch::INITIAL,
            updated_at,
            revision: RecoveryLeaseRevision::INITIAL,
        }
    }

    /// Rehydrates a persisted snapshot and validates cross-column invariants.
    pub const fn from_parts(
        workspace_id: WorkspaceId,
        owner_id: Option<RuntimeInstanceId>,
        lease_until: Option<TimestampMillis>,
        epoch: RecoveryLeaseEpoch,
        updated_at: TimestampMillis,
        revision: RecoveryLeaseRevision,
    ) -> Result<Self, RecoveryMaintenanceLeaseError> {
        if owner_id.is_some() != lease_until.is_some() {
            return Err(RecoveryMaintenanceLeaseError::PartialLease);
        }
        if let Some(lease_until) = lease_until
            && lease_until.get() <= updated_at.get()
        {
            return Err(RecoveryMaintenanceLeaseError::ExpiryNotAfterUpdatedAt);
        }
        if owner_id.is_some() && epoch.get() == RecoveryLeaseEpoch::INITIAL.get() {
            return Err(RecoveryMaintenanceLeaseError::OwnedAtInitialEpoch);
        }
        Ok(Self {
            workspace_id,
            owner_id,
            lease_until,
            epoch,
            updated_at,
            revision,
        })
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn owner_id(&self) -> Option<RuntimeInstanceId> {
        self.owner_id
    }

    pub const fn lease_until(&self) -> Option<TimestampMillis> {
        self.lease_until
    }

    pub const fn epoch(&self) -> RecoveryLeaseEpoch {
        self.epoch
    }

    pub const fn updated_at(&self) -> TimestampMillis {
        self.updated_at
    }

    pub const fn revision(&self) -> RecoveryLeaseRevision {
        self.revision
    }

    pub const fn is_released(&self) -> bool {
        self.owner_id.is_none()
    }

    pub const fn is_live_at(&self, observed_at: TimestampMillis) -> bool {
        match (self.owner_id, self.lease_until) {
            (Some(_), Some(lease_until)) => lease_until.get() > observed_at.get(),
            (None | Some(_), None) | (None, Some(_)) => false,
        }
    }

    pub const fn is_expired_at(&self, observed_at: TimestampMillis) -> bool {
        match (self.owner_id, self.lease_until) {
            (Some(_), Some(lease_until)) => lease_until.get() <= observed_at.get(),
            (None | Some(_), None) | (None, Some(_)) => false,
        }
    }

    /// Evaluates claim, idempotency, and takeover policy without mutation.
    pub fn decide_claim(
        &self,
        command: &ClaimRecoveryLease,
    ) -> Result<RecoveryLeaseClaimDecision, RecoveryLeaseTransitionError> {
        self.validate_workspace_and_timestamp(command.workspace_id(), command.observed_at())?;
        if !self.is_live_at(command.observed_at()) {
            return Ok(RecoveryLeaseClaimDecision::Acquired);
        }
        match self.owner_id {
            Some(owner) if owner == command.owner_id() => {
                if self.lease_until == Some(command.lease_until()) {
                    Ok(RecoveryLeaseClaimDecision::AlreadyOwned)
                } else {
                    Ok(RecoveryLeaseClaimDecision::ClaimConflict)
                }
            }
            Some(_) => Ok(RecoveryLeaseClaimDecision::Busy),
            None => Ok(RecoveryLeaseClaimDecision::Acquired),
        }
    }

    /// Applies a claim, returning an unchanged snapshot for an exact retry.
    pub fn claim(
        &self,
        command: &ClaimRecoveryLease,
    ) -> Result<Self, RecoveryLeaseTransitionError> {
        match self.decide_claim(command)? {
            RecoveryLeaseClaimDecision::Acquired => self.acquire(
                command.owner_id(),
                command.lease_until(),
                command.observed_at(),
            ),
            RecoveryLeaseClaimDecision::AlreadyOwned => Ok(self.clone()),
            RecoveryLeaseClaimDecision::Busy => Err(RecoveryLeaseTransitionError::Busy),
            RecoveryLeaseClaimDecision::ClaimConflict => {
                Err(RecoveryLeaseTransitionError::ClaimConflict)
            }
        }
    }

    /// Evaluates renewal fencing and expiry-forward policy without mutation.
    pub fn decide_renew(
        &self,
        command: &RenewRecoveryLease,
    ) -> Result<RecoveryLeaseRenewDecision, RecoveryLeaseTransitionError> {
        self.validate_workspace_and_timestamp(command.workspace_id(), command.observed_at())?;
        if self.owner_id != Some(command.owner_id()) {
            return Err(RecoveryLeaseTransitionError::StaleOwner);
        }
        if self.epoch != command.expected_epoch() {
            return Err(RecoveryLeaseTransitionError::StaleEpoch);
        }
        if self.revision != command.expected_revision() {
            return Err(RecoveryLeaseTransitionError::StaleRevision);
        }
        let Some(current_lease_until) = self.lease_until else {
            return Err(RecoveryLeaseTransitionError::StaleOwner);
        };
        if current_lease_until.get() <= command.observed_at().get() {
            return Err(RecoveryLeaseTransitionError::Expired);
        }
        if command.lease_until().get() <= current_lease_until.get() {
            return Err(RecoveryLeaseTransitionError::LeaseNotForward);
        }
        Ok(RecoveryLeaseRenewDecision::Renew)
    }

    /// Applies a renewal with exact owner, epoch, and revision fencing.
    pub fn renew(
        &self,
        command: &RenewRecoveryLease,
    ) -> Result<Self, RecoveryLeaseTransitionError> {
        let _ = self.decide_renew(command)?;
        let revision = self.next_revision()?;
        Ok(Self {
            workspace_id: self.workspace_id,
            owner_id: Some(command.owner_id()),
            lease_until: Some(command.lease_until()),
            epoch: self.epoch,
            updated_at: command.observed_at(),
            revision,
        })
    }

    /// Evaluates release fencing without mutation.
    pub fn decide_release(
        &self,
        command: &ReleaseRecoveryLease,
    ) -> Result<RecoveryLeaseReleaseDecision, RecoveryLeaseTransitionError> {
        self.validate_workspace_and_timestamp(command.workspace_id(), command.observed_at())?;
        if self.owner_id != Some(command.owner_id()) {
            return Err(RecoveryLeaseTransitionError::StaleOwner);
        }
        if self.epoch != command.expected_epoch() {
            return Err(RecoveryLeaseTransitionError::StaleEpoch);
        }
        if self.revision != command.expected_revision() {
            return Err(RecoveryLeaseTransitionError::StaleRevision);
        }
        Ok(RecoveryLeaseReleaseDecision::Release)
    }

    /// Applies a release with exact owner, epoch, and revision fencing.
    pub fn release(
        &self,
        command: &ReleaseRecoveryLease,
    ) -> Result<Self, RecoveryLeaseTransitionError> {
        let _ = self.decide_release(command)?;
        let revision = self.next_revision()?;
        Ok(Self {
            workspace_id: self.workspace_id,
            owner_id: None,
            lease_until: None,
            epoch: self.epoch,
            updated_at: command.observed_at(),
            revision,
        })
    }

    fn validate_workspace_and_timestamp(
        &self,
        workspace_id: WorkspaceId,
        observed_at: TimestampMillis,
    ) -> Result<(), RecoveryLeaseTransitionError> {
        if self.workspace_id != workspace_id {
            return Err(RecoveryLeaseTransitionError::WorkspaceMismatch);
        }
        if observed_at.get() < self.updated_at.get() {
            return Err(RecoveryLeaseTransitionError::TimestampInversion);
        }
        Ok(())
    }

    fn acquire(
        &self,
        owner_id: RuntimeInstanceId,
        lease_until: TimestampMillis,
        observed_at: TimestampMillis,
    ) -> Result<Self, RecoveryLeaseTransitionError> {
        let epoch = self.epoch.checked_next().map_err(|error| match error {
            RecoveryLeaseEpochError::Invalid { .. } => {
                RecoveryLeaseTransitionError::EpochOverflow {
                    current: self.epoch.get(),
                }
            }
            RecoveryLeaseEpochError::Overflow { current } => {
                RecoveryLeaseTransitionError::EpochOverflow { current }
            }
        })?;
        let revision = self.next_revision()?;
        Ok(Self {
            workspace_id: self.workspace_id,
            owner_id: Some(owner_id),
            lease_until: Some(lease_until),
            epoch,
            updated_at: observed_at,
            revision,
        })
    }

    fn next_revision(&self) -> Result<RecoveryLeaseRevision, RecoveryLeaseTransitionError> {
        self.revision.checked_next().map_err(|error| match error {
            RecoveryLeaseRevisionError::Invalid { .. } => {
                RecoveryLeaseTransitionError::RevisionOverflow {
                    current: self.revision.get(),
                }
            }
            RecoveryLeaseRevisionError::Overflow { current } => {
                RecoveryLeaseTransitionError::RevisionOverflow { current }
            }
        })
    }
}

/// Evaluates a recovery-lease claim without mutation.
pub fn decide_recovery_lease_claim(
    lease: &RecoveryMaintenanceLease,
    command: &ClaimRecoveryLease,
) -> Result<RecoveryLeaseClaimDecision, RecoveryLeaseTransitionError> {
    lease.decide_claim(command)
}

/// Evaluates a recovery-lease renewal without mutation.
pub fn decide_recovery_lease_renew(
    lease: &RecoveryMaintenanceLease,
    command: &RenewRecoveryLease,
) -> Result<RecoveryLeaseRenewDecision, RecoveryLeaseTransitionError> {
    lease.decide_renew(command)
}

/// Evaluates a recovery-lease release without mutation.
pub fn decide_recovery_lease_release(
    lease: &RecoveryMaintenanceLease,
    command: &ReleaseRecoveryLease,
) -> Result<RecoveryLeaseReleaseDecision, RecoveryLeaseTransitionError> {
    lease.decide_release(command)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn workspace(value: u128) -> WorkspaceId {
        WorkspaceId::from_uuid(Uuid::from_u128(value))
    }

    fn owner(value: u128) -> RuntimeInstanceId {
        RuntimeInstanceId::from_uuid(Uuid::from_u128(value))
    }

    fn timestamp(value: i64) -> TimestampMillis {
        TimestampMillis::new(value).expect("test timestamp must be non-negative")
    }

    fn duration(value: i64) -> RecoveryLeaseDurationMillis {
        RecoveryLeaseDurationMillis::new(value).expect("test duration must be in range")
    }

    fn claim(
        workspace_id: WorkspaceId,
        owner_id: RuntimeInstanceId,
        observed_at: i64,
    ) -> ClaimRecoveryLease {
        ClaimRecoveryLease::new(
            workspace_id,
            owner_id,
            duration(1_000),
            timestamp(observed_at),
        )
        .expect("test claim must be valid")
    }

    #[test]
    fn released_claim_acquires_and_advances_epoch_and_revision() {
        let released = RecoveryMaintenanceLease::released(workspace(1), timestamp(10));
        let command = claim(workspace(1), owner(2), 10);

        assert_eq!(released.epoch(), RecoveryLeaseEpoch::INITIAL);
        assert_eq!(released.revision(), RecoveryLeaseRevision::INITIAL);
        let acquired = released.claim(&command).expect("claim must acquire");
        assert_eq!(acquired.owner_id(), Some(owner(2)));
        assert_eq!(acquired.lease_until(), Some(timestamp(1_010)));
        assert_eq!(acquired.epoch().get(), 1);
        assert_eq!(acquired.revision().get(), 2);
        assert_eq!(acquired.updated_at(), timestamp(10));
    }

    #[test]
    fn exact_retry_is_already_owned_without_revision_mutation() {
        let released = RecoveryMaintenanceLease::released(workspace(1), timestamp(10));
        let command = claim(workspace(1), owner(2), 10);
        let acquired = released.claim(&command).expect("claim must acquire");

        assert_eq!(
            decide_recovery_lease_claim(&acquired, &command),
            Ok(RecoveryLeaseClaimDecision::AlreadyOwned)
        );
        assert_eq!(acquired.claim(&command), Ok(acquired.clone()));
        assert_eq!(acquired.revision().get(), 2);
    }

    #[test]
    fn different_live_owner_is_busy_without_mutation() {
        let released = RecoveryMaintenanceLease::released(workspace(1), timestamp(10));
        let acquired = released
            .claim(&claim(workspace(1), owner(2), 10))
            .expect("claim must acquire");
        let competing = claim(workspace(1), owner(3), 100);

        assert_eq!(
            decide_recovery_lease_claim(&acquired, &competing),
            Ok(RecoveryLeaseClaimDecision::Busy)
        );
        assert_eq!(
            acquired.claim(&competing),
            Err(RecoveryLeaseTransitionError::Busy)
        );
        assert_eq!(acquired.owner_id(), Some(owner(2)));
        assert_eq!(acquired.revision().get(), 2);
    }

    #[test]
    fn expired_takeover_advances_epoch_and_revision() {
        let acquired = RecoveryMaintenanceLease::released(workspace(1), timestamp(10))
            .claim(&claim(workspace(1), owner(2), 10))
            .expect("claim must acquire");
        let takeover = claim(workspace(1), owner(3), 1_010);

        assert!(acquired.is_expired_at(timestamp(1_010)));
        let taken = acquired
            .claim(&takeover)
            .expect("expired takeover must acquire");
        assert_eq!(taken.owner_id(), Some(owner(3)));
        assert_eq!(taken.epoch().get(), 2);
        assert_eq!(taken.revision().get(), 3);
    }

    #[test]
    fn same_owner_different_expiry_is_claim_conflict() {
        let acquired = RecoveryMaintenanceLease::released(workspace(1), timestamp(10))
            .claim(&claim(workspace(1), owner(2), 10))
            .expect("claim must acquire");
        let different_claim = claim(workspace(1), owner(2), 100);

        assert_eq!(
            acquired.decide_claim(&different_claim),
            Ok(RecoveryLeaseClaimDecision::ClaimConflict)
        );
        assert_eq!(
            acquired.claim(&different_claim),
            Err(RecoveryLeaseTransitionError::ClaimConflict)
        );
    }

    #[test]
    fn renew_requires_exact_fence_and_moves_expiry_forward() {
        let acquired = RecoveryMaintenanceLease::released(workspace(1), timestamp(10))
            .claim(&claim(workspace(1), owner(2), 10))
            .expect("claim must acquire");
        let command = RenewRecoveryLease::new(
            workspace(1),
            owner(2),
            acquired.epoch(),
            acquired.revision(),
            duration(2_000),
            timestamp(100),
        )
        .expect("renew command must be valid");

        assert_eq!(
            decide_recovery_lease_renew(&acquired, &command),
            Ok(RecoveryLeaseRenewDecision::Renew)
        );
        let renewed = acquired.renew(&command).expect("renew must succeed");
        assert_eq!(renewed.lease_until(), Some(timestamp(2_100)));
        assert_eq!(renewed.epoch(), acquired.epoch());
        assert_eq!(renewed.revision().get(), acquired.revision().get() + 1);
    }

    #[test]
    fn release_clears_owner_and_expiry_but_retains_epoch() {
        let acquired = RecoveryMaintenanceLease::released(workspace(1), timestamp(10))
            .claim(&claim(workspace(1), owner(2), 10))
            .expect("claim must acquire");
        let command = ReleaseRecoveryLease::new(
            workspace(1),
            owner(2),
            acquired.epoch(),
            acquired.revision(),
            timestamp(20),
        );

        let released = acquired.release(&command).expect("release must succeed");
        assert!(released.is_released());
        assert_eq!(released.lease_until(), None);
        assert_eq!(released.epoch(), acquired.epoch());
        assert_eq!(released.revision().get(), acquired.revision().get() + 1);
    }

    #[test]
    fn stale_owner_epoch_and_revision_are_rejected() {
        let acquired = RecoveryMaintenanceLease::released(workspace(1), timestamp(10))
            .claim(&claim(workspace(1), owner(2), 10))
            .expect("claim must acquire");
        let expiry = duration(2_000);

        let stale_owner = RenewRecoveryLease::new(
            workspace(1),
            owner(3),
            acquired.epoch(),
            acquired.revision(),
            expiry,
            timestamp(100),
        )
        .expect("renew command must be valid");
        assert_eq!(
            acquired.renew(&stale_owner),
            Err(RecoveryLeaseTransitionError::StaleOwner)
        );

        let stale_epoch = RenewRecoveryLease::new(
            workspace(1),
            owner(2),
            RecoveryLeaseEpoch::INITIAL,
            acquired.revision(),
            expiry,
            timestamp(100),
        )
        .expect("renew command must be valid");
        assert_eq!(
            acquired.renew(&stale_epoch),
            Err(RecoveryLeaseTransitionError::StaleEpoch)
        );

        let stale_revision = RenewRecoveryLease::new(
            workspace(1),
            owner(2),
            acquired.epoch(),
            RecoveryLeaseRevision::INITIAL,
            expiry,
            timestamp(100),
        )
        .expect("renew command must be valid");
        assert_eq!(
            acquired.renew(&stale_revision),
            Err(RecoveryLeaseTransitionError::StaleRevision)
        );
    }

    #[test]
    fn timestamp_inversion_and_non_forward_renewal_are_typed() {
        let released = RecoveryMaintenanceLease::released(workspace(1), timestamp(100));
        assert_eq!(
            released.claim(&claim(workspace(1), owner(2), 99)),
            Err(RecoveryLeaseTransitionError::TimestampInversion)
        );

        let acquired = released
            .claim(&claim(workspace(1), owner(2), 100))
            .expect("claim must acquire");
        let not_forward = RenewRecoveryLease::new(
            workspace(1),
            owner(2),
            acquired.epoch(),
            acquired.revision(),
            duration(1_000),
            timestamp(100),
        )
        .expect("renew command must be valid");
        assert_eq!(
            acquired.renew(&not_forward),
            Err(RecoveryLeaseTransitionError::LeaseNotForward)
        );
    }

    #[test]
    fn duration_bounds_and_addition_overflow_are_typed() {
        assert!(matches!(
            RecoveryLeaseDurationMillis::new(999),
            Err(RecoveryLeaseDurationError::OutOfRange { .. })
        ));
        assert!(matches!(
            RecoveryLeaseDurationMillis::new(300_001),
            Err(RecoveryLeaseDurationError::OutOfRange { .. })
        ));
        let max_timestamp = TimestampMillis::new(i64::MAX).expect("valid timestamp");
        assert!(matches!(
            duration(1_000).checked_lease_until(max_timestamp),
            Err(RecoveryLeaseDurationError::Overflow { .. })
        ));
    }

    #[test]
    fn rehydration_rejects_partial_and_backwards_owned_lease() {
        assert_eq!(
            RecoveryMaintenanceLease::from_parts(
                workspace(1),
                Some(owner(2)),
                None,
                RecoveryLeaseEpoch::INITIAL,
                timestamp(10),
                RecoveryLeaseRevision::INITIAL,
            ),
            Err(RecoveryMaintenanceLeaseError::PartialLease)
        );
        assert_eq!(
            RecoveryMaintenanceLease::from_parts(
                workspace(1),
                Some(owner(2)),
                Some(timestamp(11)),
                RecoveryLeaseEpoch::INITIAL,
                timestamp(10),
                RecoveryLeaseRevision::INITIAL,
            ),
            Err(RecoveryMaintenanceLeaseError::OwnedAtInitialEpoch)
        );
        assert_eq!(
            RecoveryMaintenanceLease::from_parts(
                workspace(1),
                Some(owner(2)),
                Some(timestamp(10)),
                RecoveryLeaseEpoch::new(1).expect("test epoch must be valid"),
                timestamp(10),
                RecoveryLeaseRevision::INITIAL,
            ),
            Err(RecoveryMaintenanceLeaseError::ExpiryNotAfterUpdatedAt)
        );
    }

    #[test]
    fn epoch_and_revision_overflow_are_not_wrapped() {
        let max_epoch = RecoveryLeaseEpoch::new(i64::MAX).expect("valid epoch");
        assert!(matches!(
            max_epoch.checked_next(),
            Err(RecoveryLeaseEpochError::Overflow { .. })
        ));
        let max_revision = RecoveryLeaseRevision::new(i64::MAX).expect("valid revision");
        assert!(matches!(
            max_revision.checked_next(),
            Err(RecoveryLeaseRevisionError::Overflow { .. })
        ));

        let lease = RecoveryMaintenanceLease::from_parts(
            workspace(1),
            None,
            None,
            max_epoch,
            timestamp(10),
            RecoveryLeaseRevision::INITIAL,
        )
        .expect("released max-epoch snapshot is valid");
        let command = claim(workspace(1), owner(2), 10);
        assert_eq!(
            lease.claim(&command),
            Err(RecoveryLeaseTransitionError::EpochOverflow { current: i64::MAX })
        );

        let lease = RecoveryMaintenanceLease::from_parts(
            workspace(1),
            None,
            None,
            RecoveryLeaseEpoch::INITIAL,
            timestamp(10),
            max_revision,
        )
        .expect("released max-revision snapshot is valid");
        assert_eq!(
            lease.claim(&command),
            Err(RecoveryLeaseTransitionError::RevisionOverflow { current: i64::MAX })
        );
    }
}
