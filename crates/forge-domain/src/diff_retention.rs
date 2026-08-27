use thiserror::Error;

use crate::{
    DiffByteCount, DiffId, DiffPayloadHash, DiffRevision, RegisteredDiffEvidence, TimestampMillis,
};

const MAX_RETENTION_KEEP_COUNT: u32 = 10_000;
const MAX_RETENTION_PLAN_RESULTS: u32 = 256;
const MAX_ARTIFACT_INVENTORY_RESULTS: u32 = 1_024;
const MAX_ARTIFACT_NAME_BYTES: usize = 255;

/// Explicit keep-most-recent policy input. No implicit/default deletion policy
/// is encoded by this type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DiffRetentionKeepCount(u32);

impl DiffRetentionKeepCount {
    pub const fn new(value: u32) -> Result<Self, DiffRetentionBoundError> {
        if value > MAX_RETENTION_KEEP_COUNT {
            Err(DiffRetentionBoundError::KeepCount {
                actual: value,
                maximum: MAX_RETENTION_KEEP_COUNT,
            })
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Maximum purge candidates returned by one dry-run plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DiffRetentionPlanLimit(u32);

impl DiffRetentionPlanLimit {
    pub const DEFAULT: Self = Self(50);

    pub const fn new(value: u32) -> Result<Self, DiffRetentionBoundError> {
        if value == 0 || value > MAX_RETENTION_PLAN_RESULTS {
            Err(DiffRetentionBoundError::PlanLimit {
                actual: value,
                maximum: MAX_RETENTION_PLAN_RESULTS,
            })
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Bounded descriptor inventory size for Diff artifact doctor/cleanup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DiffArtifactInventoryLimit(u32);

impl DiffArtifactInventoryLimit {
    pub const DEFAULT: Self = Self(256);

    pub const fn new(value: u32) -> Result<Self, DiffRetentionBoundError> {
        if value == 0 || value > MAX_ARTIFACT_INVENTORY_RESULTS {
            Err(DiffRetentionBoundError::InventoryLimit {
                actual: value,
                maximum: MAX_ARTIFACT_INVENTORY_RESULTS,
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
pub enum DiffRetentionBoundError {
    #[error("Diff retention keep count {actual} exceeds {maximum}")]
    KeepCount { actual: u32, maximum: u32 },
    #[error("Diff retention plan limit {actual} is outside 1..={maximum}")]
    PlanLimit { actual: u32, maximum: u32 },
    #[error("Diff artifact inventory limit {actual} is outside 1..={maximum}")]
    InventoryLimit { actual: u32, maximum: u32 },
}

/// Immutable dry-run retention plan. Candidates remain Ready until an explicit
/// purge command performs its own revision CAS.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffRetentionPlan {
    keep_recent: DiffRetentionKeepCount,
    candidates: Vec<RegisteredDiffEvidence>,
}

impl DiffRetentionPlan {
    pub fn new(
        keep_recent: DiffRetentionKeepCount,
        candidates: Vec<RegisteredDiffEvidence>,
    ) -> Self {
        Self {
            keep_recent,
            candidates,
        }
    }

    pub const fn keep_recent(&self) -> DiffRetentionKeepCount {
        self.keep_recent
    }

    pub fn candidates(&self) -> &[RegisteredDiffEvidence] {
        &self.candidates
    }
}

/// First durable transition for explicit payload deletion.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BeginDiffPurge {
    id: DiffId,
    expected_revision: DiffRevision,
    observed_at: TimestampMillis,
}

impl BeginDiffPurge {
    pub const fn new(
        id: DiffId,
        expected_revision: DiffRevision,
        observed_at: TimestampMillis,
    ) -> Self {
        Self {
            id,
            expected_revision,
            observed_at,
        }
    }

    pub const fn id(self) -> DiffId {
        self.id
    }

    pub const fn expected_revision(self) -> DiffRevision {
        self.expected_revision
    }

    pub const fn observed_at(self) -> TimestampMillis {
        self.observed_at
    }
}

/// Final durable transition after the matching payload is confirmed absent.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompleteDiffPurge {
    id: DiffId,
    expected_revision: DiffRevision,
    observed_at: TimestampMillis,
}

impl CompleteDiffPurge {
    pub const fn new(
        id: DiffId,
        expected_revision: DiffRevision,
        observed_at: TimestampMillis,
    ) -> Self {
        Self {
            id,
            expected_revision,
            observed_at,
        }
    }

    pub const fn id(self) -> DiffId {
        self.id
    }

    pub const fn expected_revision(self) -> DiffRevision {
        self.expected_revision
    }

    pub const fn observed_at(self) -> TimestampMillis {
        self.observed_at
    }
}

/// Idempotent durable purge transition status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DiffPurgeStatus {
    MarkedPending,
    AlreadyPending,
    Tombstoned,
    AlreadyTombstoned,
}

/// Durable Diff projection paired with its purge transition status.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffPurgeRecord {
    evidence: RegisteredDiffEvidence,
    status: DiffPurgeStatus,
}

impl DiffPurgeRecord {
    pub const fn new(evidence: RegisteredDiffEvidence, status: DiffPurgeStatus) -> Self {
        Self { evidence, status }
    }

    pub const fn evidence(&self) -> &RegisteredDiffEvidence {
        &self.evidence
    }

    pub const fn status(&self) -> DiffPurgeStatus {
        self.status
    }
}

/// Native single-component artifact name retained without lossy conversion.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DiffArtifactInventoryName(Vec<u8>);

impl DiffArtifactInventoryName {
    pub fn new(value: Vec<u8>) -> Result<Self, DiffArtifactInventoryNameError> {
        if value.is_empty()
            || value.len() > MAX_ARTIFACT_NAME_BYTES
            || value == b"."
            || value == b".."
            || value.iter().any(|byte| matches!(*byte, 0 | b'/'))
        {
            Err(DiffArtifactInventoryNameError::Invalid)
        } else {
            Ok(Self(value))
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum DiffArtifactInventoryNameError {
    #[error("Diff artifact inventory name is invalid")]
    Invalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DiffArtifactInventoryKind {
    Pending,
    Final,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DiffArtifactInvalidReason {
    Symlink,
    NonRegular,
    Hardlink,
}

/// Descriptor-observed Diff-directory entry that is not eligible for the
/// hash-bound artifact inventory or deletion authority.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffArtifactInvalidInventoryEntry {
    name: DiffArtifactInventoryName,
    kind: DiffArtifactInventoryKind,
    diff_id: Option<DiffId>,
    reason: DiffArtifactInvalidReason,
}

impl DiffArtifactInvalidInventoryEntry {
    pub const fn new(
        name: DiffArtifactInventoryName,
        kind: DiffArtifactInventoryKind,
        diff_id: Option<DiffId>,
        reason: DiffArtifactInvalidReason,
    ) -> Self {
        Self {
            name,
            kind,
            diff_id,
            reason,
        }
    }

    pub const fn name(&self) -> &DiffArtifactInventoryName {
        &self.name
    }

    pub const fn kind(&self) -> DiffArtifactInventoryKind {
        self.kind
    }

    pub const fn diff_id(&self) -> Option<DiffId> {
        self.diff_id
    }

    pub const fn reason(&self) -> DiffArtifactInvalidReason {
        self.reason
    }
}

/// Hash-bound descriptor inventory entry used for orphan diagnosis and
/// explicit cleanup.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffArtifactInventoryEntry {
    name: DiffArtifactInventoryName,
    kind: DiffArtifactInventoryKind,
    diff_id: Option<DiffId>,
    compressed_hash: DiffPayloadHash,
    compressed_size: DiffByteCount,
}

impl DiffArtifactInventoryEntry {
    pub const fn new(
        name: DiffArtifactInventoryName,
        kind: DiffArtifactInventoryKind,
        diff_id: Option<DiffId>,
        compressed_hash: DiffPayloadHash,
        compressed_size: DiffByteCount,
    ) -> Self {
        Self {
            name,
            kind,
            diff_id,
            compressed_hash,
            compressed_size,
        }
    }

    pub const fn name(&self) -> &DiffArtifactInventoryName {
        &self.name
    }

    pub const fn kind(&self) -> DiffArtifactInventoryKind {
        self.kind
    }

    pub const fn diff_id(&self) -> Option<DiffId> {
        self.diff_id
    }

    pub const fn compressed_hash(&self) -> DiffPayloadHash {
        self.compressed_hash
    }

    pub const fn compressed_size(&self) -> DiffByteCount {
        self.compressed_size
    }
}

/// Explicit hash-bound orphan deletion request.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteOrphanDiffArtifact {
    name: DiffArtifactInventoryName,
    expected_hash: DiffPayloadHash,
    expected_size: DiffByteCount,
}

impl DeleteOrphanDiffArtifact {
    pub const fn new(
        name: DiffArtifactInventoryName,
        expected_hash: DiffPayloadHash,
        expected_size: DiffByteCount,
    ) -> Self {
        Self {
            name,
            expected_hash,
            expected_size,
        }
    }

    pub const fn name(&self) -> &DiffArtifactInventoryName {
        &self.name
    }

    pub const fn expected_hash(&self) -> DiffPayloadHash {
        self.expected_hash
    }

    pub const fn expected_size(&self) -> DiffByteCount {
        self.expected_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_bounds_and_native_names_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(DiffRetentionKeepCount::new(0)?.get(), 0);
        assert!(DiffRetentionKeepCount::new(10_001).is_err());
        assert_eq!(DiffRetentionPlanLimit::new(256)?.get(), 256);
        assert!(DiffRetentionPlanLimit::new(0).is_err());
        assert_eq!(DiffArtifactInventoryLimit::new(1_024)?.get(), 1_024);
        assert!(DiffArtifactInventoryName::new(Vec::new()).is_err());
        assert!(DiffArtifactInventoryName::new(b"../escape".to_vec()).is_err());
        assert_eq!(
            DiffArtifactInventoryName::new(b"diff_safe.diff.zst".to_vec())?.as_bytes(),
            b"diff_safe.diff.zst"
        );
        Ok(())
    }
}
