//! Explicit root-binding recovery intent and deterministic revision transition.
//!
//! Filesystem identity, exclusive ownership and inactive-work checks belong to
//! the effect owner. This module does not infer that a physical remount occurred.

use thiserror::Error;
use uuid::Uuid;

use crate::{
    LocationRevision, RegisteredWorkspace, TimestampMillis, WorkspaceId, WorkspaceRoot,
    WorkspaceRootFingerprint,
};

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceRootRecoveryFreezeState {
    Frozen,
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkspaceRootRecoveryFreezeFence {
    pub migration_id: Uuid,
    pub workspace_id: WorkspaceId,
    pub destination_id: Uuid,
    pub state: WorkspaceRootRecoveryFreezeState,
    pub revision: u64,
    pub created_at: TimestampMillis,
    pub updated_at: TimestampMillis,
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkspaceRootRecoveryDelegationFence {
    pub migration_id: Uuid,
    pub workspace_id: WorkspaceId,
    pub destination_id: Uuid,
    pub freeze_revision: u64,
    pub manifest_digest: [u8; 32],
    pub delegated_at: TimestampMillis,
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkspaceRootRecoveryDelegatedAuthority {
    freeze: WorkspaceRootRecoveryFreezeFence,
    delegation: WorkspaceRootRecoveryDelegationFence,
}

impl WorkspaceRootRecoveryDelegatedAuthority {
    pub fn new(
        freeze: WorkspaceRootRecoveryFreezeFence,
        delegation: WorkspaceRootRecoveryDelegationFence,
    ) -> Result<Self, WorkspaceRootRecoveryError> {
        if freeze.migration_id.is_nil()
            || freeze.workspace_id.into_uuid().is_nil()
            || freeze.destination_id.is_nil()
            || freeze.revision != 1
            || freeze.updated_at != freeze.created_at
            || delegation.migration_id != freeze.migration_id
            || delegation.workspace_id != freeze.workspace_id
            || delegation.destination_id != freeze.destination_id
            || delegation.freeze_revision != freeze.revision
            || delegation.manifest_digest.iter().all(|byte| *byte == 0)
            || delegation.delegated_at < freeze.updated_at
        {
            return Err(WorkspaceRootRecoveryError::InvalidDelegatedAuthority);
        }
        Ok(Self { freeze, delegation })
    }

    pub const fn freeze(&self) -> WorkspaceRootRecoveryFreezeFence {
        self.freeze
    }

    pub const fn delegation(&self) -> WorkspaceRootRecoveryDelegationFence {
        self.delegation
    }
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WorkspaceRootRecoveryAuthorityMode {
    #[default]
    Quiescent,
    PreserveDelegatedFreeze(WorkspaceRootRecoveryDelegatedAuthority),
}

/// Digest of the exact root, state and database observation selected by an owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkspaceRootRecoveryWitness([u8; 32]);

impl WorkspaceRootRecoveryWitness {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Immutable filesystem observation supplied by the checked effect boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceRootRecoveryObservation {
    root: WorkspaceRoot,
    fingerprint: WorkspaceRootFingerprint,
    witness: WorkspaceRootRecoveryWitness,
}

impl WorkspaceRootRecoveryObservation {
    pub const fn new(
        root: WorkspaceRoot,
        fingerprint: WorkspaceRootFingerprint,
        witness: WorkspaceRootRecoveryWitness,
    ) -> Self {
        Self {
            root,
            fingerprint,
            witness,
        }
    }

    pub fn root(&self) -> &WorkspaceRoot {
        &self.root
    }

    pub const fn fingerprint(&self) -> WorkspaceRootFingerprint {
        self.fingerprint
    }

    pub const fn witness(&self) -> WorkspaceRootRecoveryWitness {
        self.witness
    }
}

/// One explicit, replay-stable owner intent. It grants no filesystem authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceRootRecoveryRequest {
    request_id: Uuid,
    location_revision: LocationRevision,
    expected: RegisteredWorkspace,
    observed: WorkspaceRootRecoveryObservation,
    observed_at: TimestampMillis,
    authority_mode: WorkspaceRootRecoveryAuthorityMode,
}

impl WorkspaceRootRecoveryRequest {
    pub fn new(
        request_id: Uuid,
        location_revision: LocationRevision,
        expected: RegisteredWorkspace,
        observed: WorkspaceRootRecoveryObservation,
        observed_at: TimestampMillis,
    ) -> Result<Self, WorkspaceRootRecoveryError> {
        if request_id.is_nil() {
            return Err(WorkspaceRootRecoveryError::NilRequestIdentity);
        }
        if expected.root() != observed.root() {
            return Err(WorkspaceRootRecoveryError::RootPathChanged);
        }
        if expected.root_fingerprint() == observed.fingerprint() {
            return Err(WorkspaceRootRecoveryError::UnchangedFingerprint);
        }
        if observed_at < expected.updated_at() {
            return Err(WorkspaceRootRecoveryError::TimestampBeforeSelection);
        }
        Ok(Self {
            request_id,
            location_revision,
            expected,
            observed,
            observed_at,
            authority_mode: WorkspaceRootRecoveryAuthorityMode::Quiescent,
        })
    }

    pub fn new_preserving_delegated_freeze(
        request_id: Uuid,
        location_revision: LocationRevision,
        expected: RegisteredWorkspace,
        observed: WorkspaceRootRecoveryObservation,
        observed_at: TimestampMillis,
        authority: WorkspaceRootRecoveryDelegatedAuthority,
    ) -> Result<Self, WorkspaceRootRecoveryError> {
        let mut request = Self::new(
            request_id,
            location_revision,
            expected,
            observed,
            observed_at,
        )?;
        if authority.freeze().workspace_id != request.expected.id() {
            return Err(WorkspaceRootRecoveryError::InvalidDelegatedAuthority);
        }
        request.authority_mode =
            WorkspaceRootRecoveryAuthorityMode::PreserveDelegatedFreeze(authority);
        Ok(request)
    }

    pub const fn request_id(&self) -> Uuid {
        self.request_id
    }

    pub const fn location_revision(&self) -> LocationRevision {
        self.location_revision
    }

    pub fn expected(&self) -> &RegisteredWorkspace {
        &self.expected
    }

    pub fn observed(&self) -> &WorkspaceRootRecoveryObservation {
        &self.observed
    }

    pub const fn observed_at(&self) -> TimestampMillis {
        self.observed_at
    }

    pub const fn authority_mode(&self) -> WorkspaceRootRecoveryAuthorityMode {
        self.authority_mode
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceRootRecoveryError {
    #[error("Root recovery requires a non-nil request identity")]
    NilRequestIdentity,
    #[error("Root recovery cannot change the canonical root path")]
    RootPathChanged,
    #[error("Root recovery requires a changed fingerprint")]
    UnchangedFingerprint,
    #[error("Root recovery time precedes the selected Workspace update")]
    TimestampBeforeSelection,
    #[error("The durable Workspace changed after recovery was selected")]
    WorkspaceChanged,
    #[error("The physical root or database observation changed")]
    ObservationChanged,
    #[error("Workspace revision cannot advance")]
    RevisionOverflow,
    #[error("Preserved delegated authority is invalid")]
    InvalidDelegatedAuthority,
}

/// Calculate the single revision change after the effect owner admits recovery.
///
/// The store must separately enforce exclusive ownership, physical eligibility,
/// duplicate-identity rejection and durable idempotency before committing this
/// projection. Replaying a committed request reads its receipt, not this function.
pub fn decide_workspace_root_recovery(
    current: &RegisteredWorkspace,
    observation: &WorkspaceRootRecoveryObservation,
    request: &WorkspaceRootRecoveryRequest,
) -> Result<RegisteredWorkspace, WorkspaceRootRecoveryError> {
    if current != request.expected() {
        return Err(WorkspaceRootRecoveryError::WorkspaceChanged);
    }
    if observation != request.observed() {
        return Err(WorkspaceRootRecoveryError::ObservationChanged);
    }
    let revision = current
        .revision()
        .checked_next()
        .map_err(|_| WorkspaceRootRecoveryError::RevisionOverflow)?;
    Ok(RegisteredWorkspace::from_parts_with_revision(
        current.id(),
        current.location_id(),
        current.root().clone(),
        observation.fingerprint(),
        current.created_at(),
        request.observed_at(),
        revision,
    ))
}

#[cfg(test)]
mod tests;
