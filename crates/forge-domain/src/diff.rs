use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use thiserror::Error;
use uuid::Uuid;

use crate::{
    ActivityId, ChangeSetId, FileContentHash, FileMutationId, TimestampMillis, WorkspaceId,
    WorkspaceRelativePath, WorkspaceRelativePathError,
};

const MAX_DIFF_LIST_LIMIT: u32 = 1_000;

/// Stable identity for one human-review Diff Evidence record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DiffId(Uuid);

impl DiffId {
    pub const fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }

    pub const fn into_uuid(self) -> Uuid {
        self.0
    }

    /// V1 derives the Diff identity deterministically from its one owning
    /// `ChangeSet` while preserving a distinct Rust type.
    pub const fn for_change_set(change_set_id: ChangeSetId) -> Self {
        Self(change_set_id.into_uuid())
    }
}

impl fmt::Display for DiffId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for DiffId {
    type Err = DiffIdParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(value)
            .map(Self)
            .map_err(DiffIdParseError::InvalidUuid)
    }
}

#[derive(Debug, Error)]
pub enum DiffIdParseError {
    #[error("invalid Diff Evidence UUID")]
    InvalidUuid(#[source] uuid::Error),
}

/// Monotonic revision for durable Diff Evidence metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DiffRevision(i64);

impl DiffRevision {
    pub const INITIAL: Self = Self(1);

    pub const fn new(value: i64) -> Result<Self, DiffRevisionError> {
        if value < 1 {
            Err(DiffRevisionError::Invalid { actual: value })
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> i64 {
        self.0
    }

    pub const fn checked_next(self) -> Result<Self, DiffRevisionError> {
        match self.0.checked_add(1) {
            Some(value) => Ok(Self(value)),
            None => Err(DiffRevisionError::Overflow { current: self.0 }),
        }
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum DiffRevisionError {
    #[error("Diff Evidence revision must be at least 1, got {actual}")]
    Invalid { actual: i64 },
    #[error("Diff Evidence revision overflowed at {current}")]
    Overflow { current: i64 },
}

/// Version of the deterministic unified-diff renderer contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DiffRendererVersion(u32);

impl DiffRendererVersion {
    pub const V1: Self = Self(1);
    pub const V2: Self = Self(2);

    pub const fn new(value: u32) -> Result<Self, DiffVersionError> {
        if value == 0 {
            Err(DiffVersionError::Zero)
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Version of the deterministic secret-redaction policy contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DiffRedactionPolicyVersion(u32);

impl DiffRedactionPolicyVersion {
    pub const V1: Self = Self(1);
    pub const V2: Self = Self(2);

    pub const fn new(value: u32) -> Result<Self, DiffVersionError> {
        if value == 0 {
            Err(DiffVersionError::Zero)
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum DiffVersionError {
    #[error("Diff contract version must be at least 1")]
    Zero,
}

/// Renderer/redaction versions that make a persisted Diff reproducible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DiffContractVersions {
    renderer: DiffRendererVersion,
    redaction_policy: DiffRedactionPolicyVersion,
}

impl DiffContractVersions {
    pub const V1: Self = Self::new(DiffRendererVersion::V1, DiffRedactionPolicyVersion::V1);
    /// Absolute patch-window coordinates and line-preserving secret redaction.
    pub const V2: Self = Self::new(DiffRendererVersion::V2, DiffRedactionPolicyVersion::V2);

    pub const fn new(
        renderer: DiffRendererVersion,
        redaction_policy: DiffRedactionPolicyVersion,
    ) -> Self {
        Self {
            renderer,
            redaction_policy,
        }
    }

    pub const fn renderer(self) -> DiffRendererVersion {
        self.renderer
    }

    pub const fn redaction_policy(self) -> DiffRedactionPolicyVersion {
        self.redaction_policy
    }
}

/// Creation and last-transition times for durable Diff Evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DiffEvidenceTimestamps {
    created_at: TimestampMillis,
    updated_at: TimestampMillis,
}

impl DiffEvidenceTimestamps {
    pub const fn new(created_at: TimestampMillis, updated_at: TimestampMillis) -> Self {
        Self {
            created_at,
            updated_at,
        }
    }

    pub const fn created_at(self) -> TimestampMillis {
        self.created_at
    }

    pub const fn updated_at(self) -> TimestampMillis {
        self.updated_at
    }
}

/// Exact compressed artifact digest, distinct from a source-file CAS hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DiffPayloadHash(FileContentHash);

impl DiffPayloadHash {
    pub fn for_content(bytes: &[u8]) -> Self {
        Self::from_bytes(*blake3::hash(bytes).as_bytes())
    }

    pub const fn from_bytes(value: [u8; FileContentHash::BYTE_LEN]) -> Self {
        Self(FileContentHash::from_bytes(value))
    }

    pub const fn into_bytes(self) -> [u8; FileContentHash::BYTE_LEN] {
        self.0.into_bytes()
    }

    pub const fn as_bytes(&self) -> &[u8; FileContentHash::BYTE_LEN] {
        self.0.as_bytes()
    }
}

impl fmt::Display for DiffPayloadHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Artifact path relative to the owned Workspace state root.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DiffArtifactRelativePath(WorkspaceRelativePath);

impl DiffArtifactRelativePath {
    pub fn new(path: PathBuf) -> Result<Self, DiffArtifactRelativePathError> {
        WorkspaceRelativePath::new(path)
            .map(Self)
            .map_err(DiffArtifactRelativePathError::Path)
    }

    pub fn as_path(&self) -> &Path {
        self.0.as_path()
    }

    pub fn into_path_buf(self) -> PathBuf {
        self.0.into_path_buf()
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DiffArtifactRelativePathError {
    #[error("invalid Diff artifact relative path")]
    Path(#[source] WorkspaceRelativePathError),
}

/// Byte count for compressed or rendered Diff payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DiffByteCount(u64);

impl DiffByteCount {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Bounded line statistic shown in Activity/GUI summaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DiffLineCount(u32);

impl DiffLineCount {
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Aggregate change category represented by one `ChangeSet` evidence entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DiffChangeKind {
    Created,
    Modified,
    Deleted,
    Moved,
}

/// Source-tree subject represented by one Diff evidence entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DiffEntrySubject {
    File,
    Directory,
}

/// Durable payload state. Missing/corrupt are caller-time health observations,
/// not persisted claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DiffEvidenceState {
    Intent,
    Ready,
    SummaryOnly,
    Abandoned,
    PurgePending,
    Tombstoned,
}

/// Renderer disposition, independent from durable lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DiffRenderKind {
    Text,
    Binary,
    Oversized,
    Structured,
}

/// Exact semantic origin of one Diff Evidence record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DiffOrigin {
    FileMutation(FileMutationId),
    TreeChangeSet,
}

/// Workspace/Activity/ChangeSet attribution for one Diff.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DiffAttribution {
    id: DiffId,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    change_set_id: ChangeSetId,
    origin: DiffOrigin,
}

impl DiffAttribution {
    pub const fn for_file_mutation(
        id: DiffId,
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        change_set_id: ChangeSetId,
        mutation_id: FileMutationId,
    ) -> Self {
        Self {
            id,
            workspace_id,
            activity_id,
            change_set_id,
            origin: DiffOrigin::FileMutation(mutation_id),
        }
    }

    pub const fn for_tree_change_set(
        id: DiffId,
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        change_set_id: ChangeSetId,
    ) -> Self {
        Self {
            id,
            workspace_id,
            activity_id,
            change_set_id,
            origin: DiffOrigin::TreeChangeSet,
        }
    }

    pub const fn id(self) -> DiffId {
        self.id
    }
    pub const fn workspace_id(self) -> WorkspaceId {
        self.workspace_id
    }
    pub const fn activity_id(self) -> ActivityId {
        self.activity_id
    }
    pub const fn change_set_id(self) -> ChangeSetId {
        self.change_set_id
    }
    pub const fn origin(self) -> DiffOrigin {
        self.origin
    }
}

/// One bounded path-level entry in aggregate human-review Diff Evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffEntrySummary {
    subject: DiffEntrySubject,
    primary_path: WorkspaceRelativePath,
    secondary_path: Option<WorkspaceRelativePath>,
    kind: DiffChangeKind,
    additions: DiffLineCount,
    deletions: DiffLineCount,
}

impl DiffEntrySummary {
    pub fn new(
        subject: DiffEntrySubject,
        primary_path: WorkspaceRelativePath,
        secondary_path: Option<WorkspaceRelativePath>,
        kind: DiffChangeKind,
        additions: DiffLineCount,
        deletions: DiffLineCount,
    ) -> Result<Self, DiffTransitionError> {
        if matches!(kind, DiffChangeKind::Moved) != secondary_path.is_some() {
            return Err(DiffTransitionError::InvalidEntryShape);
        }
        Ok(Self {
            subject,
            primary_path,
            secondary_path,
            kind,
            additions,
            deletions,
        })
    }

    pub const fn subject(&self) -> DiffEntrySubject {
        self.subject
    }
    pub fn primary_path(&self) -> &WorkspaceRelativePath {
        &self.primary_path
    }
    pub const fn secondary_path(&self) -> Option<&WorkspaceRelativePath> {
        self.secondary_path.as_ref()
    }
    pub const fn kind(&self) -> DiffChangeKind {
        self.kind
    }
    pub const fn additions(&self) -> DiffLineCount {
        self.additions
    }
    pub const fn deletions(&self) -> DiffLineCount {
        self.deletions
    }
}

/// Payload reference or explicit no-payload classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffPayloadProjection {
    IntentText {
        pending_relative_path: DiffArtifactRelativePath,
        final_relative_path: DiffArtifactRelativePath,
        compressed_hash: DiffPayloadHash,
        uncompressed_hash: DiffPayloadHash,
        compressed_size: DiffByteCount,
        uncompressed_size: DiffByteCount,
    },
    IntentSummary {
        render_kind: DiffRenderKind,
    },
    Ready {
        relative_path: DiffArtifactRelativePath,
        compressed_hash: DiffPayloadHash,
        uncompressed_hash: DiffPayloadHash,
        compressed_size: DiffByteCount,
        uncompressed_size: DiffByteCount,
    },
    SummaryOnly {
        render_kind: DiffRenderKind,
    },
    Abandoned {
        render_kind: DiffRenderKind,
    },
    PurgePending {
        relative_path: DiffArtifactRelativePath,
        compressed_hash: DiffPayloadHash,
        uncompressed_hash: DiffPayloadHash,
        compressed_size: DiffByteCount,
        uncompressed_size: DiffByteCount,
    },
    Tombstoned {
        render_kind: DiffRenderKind,
    },
}

impl DiffPayloadProjection {
    pub const fn state(&self) -> DiffEvidenceState {
        match self {
            Self::IntentText { .. } | Self::IntentSummary { .. } => DiffEvidenceState::Intent,
            Self::Ready { .. } => DiffEvidenceState::Ready,
            Self::SummaryOnly { .. } => DiffEvidenceState::SummaryOnly,
            Self::Abandoned { .. } => DiffEvidenceState::Abandoned,
            Self::PurgePending { .. } => DiffEvidenceState::PurgePending,
            Self::Tombstoned { .. } => DiffEvidenceState::Tombstoned,
        }
    }

    pub const fn render_kind(&self) -> DiffRenderKind {
        match self {
            Self::IntentText { .. } | Self::Ready { .. } | Self::PurgePending { .. } => {
                DiffRenderKind::Text
            }
            Self::IntentSummary { render_kind }
            | Self::SummaryOnly { render_kind }
            | Self::Abandoned { render_kind }
            | Self::Tombstoned { render_kind } => *render_kind,
        }
    }
}

/// Durable Diff intent persisted in the same transaction as `ChangeSet`
/// `Starting`.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeginDiffEvidence {
    attribution: DiffAttribution,
    entries: Vec<DiffEntrySummary>,
    payload: DiffPayloadProjection,
    observed_at: TimestampMillis,
    versions: DiffContractVersions,
}

impl BeginDiffEvidence {
    pub fn new(
        attribution: DiffAttribution,
        entries: Vec<DiffEntrySummary>,
        payload: DiffPayloadProjection,
        observed_at: TimestampMillis,
        versions: DiffContractVersions,
    ) -> Result<Self, DiffTransitionError> {
        if attribution.id() != DiffId::for_change_set(attribution.change_set_id()) {
            return Err(DiffTransitionError::IdentityMismatch);
        }
        if payload.state() != DiffEvidenceState::Intent {
            return Err(DiffTransitionError::InvalidPayloadState);
        }
        if entries.is_empty() || entries.len() > crate::MAX_TREE_CHANGESET_MUTATIONS {
            return Err(DiffTransitionError::InvalidEntryCount);
        }
        Ok(Self {
            attribution,
            entries,
            payload,
            observed_at,
            versions,
        })
    }

    pub const fn attribution(&self) -> DiffAttribution {
        self.attribution
    }

    pub fn entries(&self) -> &[DiffEntrySummary] {
        &self.entries
    }

    pub const fn payload(&self) -> &DiffPayloadProjection {
        &self.payload
    }

    pub const fn observed_at(&self) -> TimestampMillis {
        self.observed_at
    }

    pub const fn versions(&self) -> DiffContractVersions {
        self.versions
    }
}

/// Terminal Diff transition committed with `ChangeSet` `Applied`.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteDiffEvidence {
    id: DiffId,
    expected_revision: DiffRevision,
    payload: DiffPayloadProjection,
    observed_at: TimestampMillis,
}

impl CompleteDiffEvidence {
    pub fn new(
        id: DiffId,
        expected_revision: DiffRevision,
        payload: DiffPayloadProjection,
        observed_at: TimestampMillis,
    ) -> Result<Self, DiffTransitionError> {
        if !matches!(
            payload.state(),
            DiffEvidenceState::Ready | DiffEvidenceState::SummaryOnly
        ) {
            return Err(DiffTransitionError::InvalidPayloadState);
        }
        Ok(Self {
            id,
            expected_revision,
            payload,
            observed_at,
        })
    }

    pub const fn id(&self) -> DiffId {
        self.id
    }

    pub const fn expected_revision(&self) -> DiffRevision {
        self.expected_revision
    }

    pub const fn payload(&self) -> &DiffPayloadProjection {
        &self.payload
    }

    pub const fn observed_at(&self) -> TimestampMillis {
        self.observed_at
    }
}

/// Terminal Diff abandonment committed with a known non-committed effect
/// failure.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AbandonDiffEvidence {
    id: DiffId,
    expected_revision: DiffRevision,
    observed_at: TimestampMillis,
}

impl AbandonDiffEvidence {
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

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum DiffTransitionError {
    #[error("Diff identity does not match its owning ChangeSet")]
    IdentityMismatch,
    #[error("Diff payload state is invalid for this transition")]
    InvalidPayloadState,
    #[error("Diff entry count is outside the bounded ChangeSet range")]
    InvalidEntryCount,
    #[error("Diff entry path shape does not match its change kind")]
    InvalidEntryShape,
}

/// Durable metadata/index projection for one human-review Diff.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredDiffEvidence {
    attribution: DiffAttribution,
    entries: Vec<DiffEntrySummary>,
    payload: DiffPayloadProjection,
    timestamps: DiffEvidenceTimestamps,
    versions: DiffContractVersions,
    revision: DiffRevision,
}

impl RegisteredDiffEvidence {
    pub const fn from_parts(
        attribution: DiffAttribution,
        entries: Vec<DiffEntrySummary>,
        payload: DiffPayloadProjection,
        timestamps: DiffEvidenceTimestamps,
        versions: DiffContractVersions,
        revision: DiffRevision,
    ) -> Self {
        Self {
            attribution,
            entries,
            payload,
            timestamps,
            versions,
            revision,
        }
    }

    pub const fn id(&self) -> DiffId {
        self.attribution.id()
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.attribution.workspace_id()
    }

    pub const fn activity_id(&self) -> ActivityId {
        self.attribution.activity_id()
    }

    pub const fn change_set_id(&self) -> ChangeSetId {
        self.attribution.change_set_id()
    }

    pub const fn origin(&self) -> DiffOrigin {
        self.attribution.origin()
    }

    pub fn entries(&self) -> &[DiffEntrySummary] {
        &self.entries
    }

    pub const fn payload(&self) -> &DiffPayloadProjection {
        &self.payload
    }

    pub const fn state(&self) -> DiffEvidenceState {
        self.payload.state()
    }

    pub const fn created_at(&self) -> TimestampMillis {
        self.timestamps.created_at()
    }

    pub const fn updated_at(&self) -> TimestampMillis {
        self.timestamps.updated_at()
    }

    pub const fn renderer_version(&self) -> DiffRendererVersion {
        self.versions.renderer()
    }

    pub const fn redaction_policy_version(&self) -> DiffRedactionPolicyVersion {
        self.versions.redaction_policy()
    }

    pub const fn revision(&self) -> DiffRevision {
        self.revision
    }
}

/// Bounded query limit for Diff metadata projections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiffListLimit(u32);

impl DiffListLimit {
    pub const DEFAULT: Self = Self(100);

    pub const fn new(value: u32) -> Result<Self, DiffListLimitError> {
        if value == 0 || value > MAX_DIFF_LIST_LIMIT {
            Err(DiffListLimitError::OutOfRange {
                actual: value,
                maximum: MAX_DIFF_LIST_LIMIT,
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
pub enum DiffListLimitError {
    #[error("Diff list limit {actual} is outside 1..={maximum}")]
    OutOfRange { actual: u32, maximum: u32 },
}

/// Caller-time artifact health, separate from durable metadata state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DiffArtifactHealth {
    Available,
    NotApplicable,
    Archived,
    Missing,
    Corrupt,
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::str::FromStr;

    use uuid::Uuid;

    use super::*;

    #[test]
    fn diff_identity_revision_hash_and_limits_are_semantically_distinct()
    -> Result<(), Box<dyn std::error::Error>> {
        let id = DiffId::from_uuid(Uuid::from_u128(1));
        assert_eq!(DiffId::from_str(&id.to_string())?, id);
        assert_eq!(DiffRevision::INITIAL.checked_next()?.get(), 2);
        assert!(DiffRevision::new(0).is_err());
        let hash = DiffPayloadHash::from_bytes([7; FileContentHash::BYTE_LEN]);
        assert!(hash.to_string().starts_with("blake3-256:"));
        assert_eq!(hash.into_bytes(), [7; FileContentHash::BYTE_LEN]);
        assert_eq!(DiffListLimit::new(25)?.get(), 25);
        assert!(DiffListLimit::new(0).is_err());
        assert!(DiffListLimit::new(1_001).is_err());
        Ok(())
    }

    #[test]
    fn diff_projection_keeps_payload_reference_separate_from_aggregate_entries()
    -> Result<(), Box<dyn std::error::Error>> {
        let path = WorkspaceRelativePath::new(PathBuf::from("src/lib.rs"))?;
        let artifact = DiffArtifactRelativePath::new(PathBuf::from("[REDACTED].diff.zst"))?;
        let evidence = RegisteredDiffEvidence::from_parts(
            DiffAttribution::for_file_mutation(
                DiffId::from_uuid(Uuid::from_u128(1)),
                WorkspaceId::from_uuid(Uuid::from_u128(2)),
                ActivityId::from_uuid(Uuid::from_u128(3)),
                ChangeSetId::from_uuid(Uuid::from_u128(4)),
                FileMutationId::from_uuid(Uuid::from_u128(5)),
            ),
            vec![DiffEntrySummary::new(
                DiffEntrySubject::File,
                path,
                None,
                DiffChangeKind::Modified,
                DiffLineCount::new(2),
                DiffLineCount::new(1),
            )?],
            DiffPayloadProjection::Ready {
                relative_path: artifact,
                compressed_hash: DiffPayloadHash::from_bytes([9; FileContentHash::BYTE_LEN]),
                uncompressed_hash: DiffPayloadHash::from_bytes([8; FileContentHash::BYTE_LEN]),
                compressed_size: DiffByteCount::new(20),
                uncompressed_size: DiffByteCount::new(40),
            },
            DiffEvidenceTimestamps::new(TimestampMillis::new(10)?, TimestampMillis::new(11)?),
            DiffContractVersions::V1,
            DiffRevision::INITIAL,
        );
        assert_eq!(evidence.state(), DiffEvidenceState::Ready);
        assert_eq!(evidence.payload().render_kind(), DiffRenderKind::Text);
        assert!(matches!(evidence.origin(), DiffOrigin::FileMutation(_)));
        assert_eq!(evidence.entries()[0].additions().get(), 2);
        assert_eq!(evidence.entries()[0].deletions().get(), 1);
        Ok(())
    }

    #[test]
    fn aggregate_diff_supports_structured_move_and_rejects_invalid_shapes()
    -> Result<(), Box<dyn std::error::Error>> {
        let change_set_id = ChangeSetId::from_uuid(Uuid::from_u128(4));
        let attribution = DiffAttribution::for_tree_change_set(
            DiffId::for_change_set(change_set_id),
            WorkspaceId::from_uuid(Uuid::from_u128(2)),
            ActivityId::from_uuid(Uuid::from_u128(3)),
            change_set_id,
        );
        let moved = DiffEntrySummary::new(
            DiffEntrySubject::Directory,
            WorkspaceRelativePath::new(PathBuf::from("src"))?,
            Some(WorkspaceRelativePath::new(PathBuf::from("lib"))?),
            DiffChangeKind::Moved,
            DiffLineCount::new(0),
            DiffLineCount::new(0),
        )?;
        assert!(
            BeginDiffEvidence::new(
                attribution,
                vec![moved],
                DiffPayloadProjection::IntentSummary {
                    render_kind: DiffRenderKind::Structured,
                },
                TimestampMillis::new(10)?,
                DiffContractVersions::V1,
            )
            .is_ok()
        );
        assert!(matches!(
            DiffEntrySummary::new(
                DiffEntrySubject::File,
                WorkspaceRelativePath::new(PathBuf::from("a"))?,
                None,
                DiffChangeKind::Moved,
                DiffLineCount::new(0),
                DiffLineCount::new(0),
            ),
            Err(DiffTransitionError::InvalidEntryShape)
        ));
        Ok(())
    }

    #[test]
    fn diff_commands_reject_identity_and_lifecycle_mismatches()
    -> Result<(), Box<dyn std::error::Error>> {
        let change_set_id = ChangeSetId::from_uuid(Uuid::from_u128(4));
        let attribution = DiffAttribution::for_file_mutation(
            DiffId::for_change_set(change_set_id),
            WorkspaceId::from_uuid(Uuid::from_u128(2)),
            ActivityId::from_uuid(Uuid::from_u128(3)),
            change_set_id,
            FileMutationId::from_uuid(Uuid::from_u128(5)),
        );
        let entry = DiffEntrySummary::new(
            DiffEntrySubject::File,
            WorkspaceRelativePath::new(PathBuf::from("src/lib.rs"))?,
            None,
            DiffChangeKind::Modified,
            DiffLineCount::new(1),
            DiffLineCount::new(1),
        )?;
        assert!(
            BeginDiffEvidence::new(
                attribution,
                vec![entry.clone()],
                DiffPayloadProjection::IntentSummary {
                    render_kind: DiffRenderKind::Binary,
                },
                TimestampMillis::new(10)?,
                DiffContractVersions::V1,
            )
            .is_ok()
        );
        let mutation_id = match attribution.origin() {
            DiffOrigin::FileMutation(id) => id,
            DiffOrigin::TreeChangeSet => return Err("unexpected tree origin".into()),
        };
        let mismatched = DiffAttribution::for_file_mutation(
            DiffId::from_uuid(Uuid::from_u128(99)),
            attribution.workspace_id(),
            attribution.activity_id(),
            attribution.change_set_id(),
            mutation_id,
        );
        assert!(matches!(
            BeginDiffEvidence::new(
                mismatched,
                vec![entry],
                DiffPayloadProjection::IntentSummary {
                    render_kind: DiffRenderKind::Binary,
                },
                TimestampMillis::new(10)?,
                DiffContractVersions::V1,
            ),
            Err(DiffTransitionError::IdentityMismatch)
        ));
        assert!(matches!(
            CompleteDiffEvidence::new(
                attribution.id(),
                DiffRevision::INITIAL,
                DiffPayloadProjection::IntentSummary {
                    render_kind: DiffRenderKind::Binary,
                },
                TimestampMillis::new(11)?,
            ),
            Err(DiffTransitionError::InvalidPayloadState)
        ));
        Ok(())
    }
}
