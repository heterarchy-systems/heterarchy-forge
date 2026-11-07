//! Checked in-memory views of immutable Home-artifact journal rows.

use forge_domain::{
    ActivityCoordinatorActor, ActivityId, GitCommitId, GoalId, HomeArtifactArchive,
    HomeArtifactCaptureIntent, HomeArtifactId, TimestampMillis, WorkspaceId, WorkspaceRevision,
    WorkspaceRootFingerprint,
};

/// Immutable SQL stage and its optional verified Git seal.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HomeArtifactReadback {
    stage: HomeArtifactStageRecord,
    seal: Option<HomeArtifactSealRecord>,
}

impl HomeArtifactReadback {
    pub(crate) const fn new(
        stage: HomeArtifactStageRecord,
        seal: Option<HomeArtifactSealRecord>,
    ) -> Self {
        Self { stage, seal }
    }

    pub const fn stage(&self) -> &HomeArtifactStageRecord {
        &self.stage
    }

    pub const fn seal(&self) -> Option<&HomeArtifactSealRecord> {
        self.seal.as_ref()
    }
}

/// Exact stage written before Git store construction or artifact publication.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HomeArtifactStageRecord {
    intent: HomeArtifactCaptureIntent,
    workspace_id: WorkspaceId,
    workspace_revision: WorkspaceRevision,
    workspace_root_fingerprint: WorkspaceRootFingerprint,
    activity_id: ActivityId,
    goal_id: GoalId,
    coordinator: ActivityCoordinatorActor,
    source_request_digest: [u8; 32],
    source_outcome_digest: [u8; 32],
    source_inventory_digest: [u8; 32],
    source_observed_at: TimestampMillis,
    staged_at: TimestampMillis,
}

impl HomeArtifactStageRecord {
    #[allow(
        clippy::too_many_arguments,
        reason = "one checked row binds the complete stage"
    )]
    pub(crate) const fn new(
        intent: HomeArtifactCaptureIntent,
        workspace_id: WorkspaceId,
        workspace_revision: WorkspaceRevision,
        workspace_root_fingerprint: WorkspaceRootFingerprint,
        activity_id: ActivityId,
        goal_id: GoalId,
        coordinator: ActivityCoordinatorActor,
        source_request_digest: [u8; 32],
        source_outcome_digest: [u8; 32],
        source_inventory_digest: [u8; 32],
        source_observed_at: TimestampMillis,
        staged_at: TimestampMillis,
    ) -> Self {
        Self {
            intent,
            workspace_id,
            workspace_revision,
            workspace_root_fingerprint,
            activity_id,
            goal_id,
            coordinator,
            source_request_digest,
            source_outcome_digest,
            source_inventory_digest,
            source_observed_at,
            staged_at,
        }
    }

    pub const fn intent(&self) -> &HomeArtifactCaptureIntent {
        &self.intent
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    /// Workspace revision at the native capture stage. The Prepared Source
    /// request remains independently pinned by its immutable digest.
    pub const fn workspace_revision(&self) -> WorkspaceRevision {
        self.workspace_revision
    }

    /// Physical Workspace root identity admitted for this exact stage.
    pub const fn workspace_root_fingerprint(&self) -> WorkspaceRootFingerprint {
        self.workspace_root_fingerprint
    }

    pub const fn activity_id(&self) -> ActivityId {
        self.activity_id
    }

    pub const fn goal_id(&self) -> GoalId {
        self.goal_id
    }

    /// Coordinator actor snapshot authenticated when the immutable stage was created.
    pub const fn coordinator(&self) -> ActivityCoordinatorActor {
        self.coordinator
    }

    pub const fn source_request_digest(&self) -> &[u8; 32] {
        &self.source_request_digest
    }

    pub const fn source_outcome_digest(&self) -> &[u8; 32] {
        &self.source_outcome_digest
    }

    pub const fn source_inventory_digest(&self) -> &[u8; 32] {
        &self.source_inventory_digest
    }

    /// Timestamp of the exact immutable Prepared Source outcome.
    pub const fn source_observed_at(&self) -> TimestampMillis {
        self.source_observed_at
    }

    pub const fn staged_at(&self) -> TimestampMillis {
        self.staged_at
    }
}

/// Immutable seal after the Git owner has fully read back and verified its archive.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HomeArtifactSealRecord {
    stage: HomeArtifactStageRecord,
    archive: HomeArtifactArchive,
    sealed_by: ActivityCoordinatorActor,
    archive_digest: [u8; 32],
    sealed_at: TimestampMillis,
}

impl HomeArtifactSealRecord {
    pub(crate) const fn new(
        stage: HomeArtifactStageRecord,
        archive: HomeArtifactArchive,
        sealed_by: ActivityCoordinatorActor,
        archive_digest: [u8; 32],
        sealed_at: TimestampMillis,
    ) -> Self {
        Self {
            stage,
            archive,
            sealed_by,
            archive_digest,
            sealed_at,
        }
    }

    pub const fn stage(&self) -> &HomeArtifactStageRecord {
        &self.stage
    }

    pub const fn archive(&self) -> &HomeArtifactArchive {
        &self.archive
    }

    /// Exact current Coordinator snapshot authorized when the seal was written.
    pub const fn sealed_by(&self) -> ActivityCoordinatorActor {
        self.sealed_by
    }

    pub const fn archive_digest(&self) -> &[u8; 32] {
        &self.archive_digest
    }

    pub const fn sealed_at(&self) -> TimestampMillis {
        self.sealed_at
    }
}

/// Result of the public capture path. A Pending stage is durable and is never
/// recaptured automatically; a later call may only read the exact artifact ref.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HomeArtifactCaptureOutcome {
    Pending(Box<HomeArtifactStageRecord>),
    Sealed(Box<HomeArtifactSealRecord>),
}

/// Bounded SQL-to-Git reference observation for Workspace Doctor.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HomeArtifactDoctorReport {
    references: Vec<HomeArtifactDoctorReference>,
    truncated: bool,
}

impl HomeArtifactDoctorReport {
    pub(crate) const fn new(references: Vec<HomeArtifactDoctorReference>, truncated: bool) -> Self {
        Self {
            references,
            truncated,
        }
    }

    pub fn references(&self) -> &[HomeArtifactDoctorReference] {
        &self.references
    }

    pub const fn truncated(&self) -> bool {
        self.truncated
    }

    /// Doctor observes SQL/ref metadata only; it does not verify Git objects or bytes.
    pub const fn metadata_only(&self) -> bool {
        true
    }
}

/// One bounded Home artifact journal reference. A missing commit denotes a
/// durable stage whose external publication may still be unresolved.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HomeArtifactDoctorReference {
    artifact_id: HomeArtifactId,
    intent_digest: [u8; 32],
    expected_commit: Option<GitCommitId>,
    manifest_digest: Option<[u8; 32]>,
}

impl HomeArtifactDoctorReference {
    pub(crate) const fn new(
        artifact_id: HomeArtifactId,
        intent_digest: [u8; 32],
        expected_commit: Option<GitCommitId>,
        manifest_digest: Option<[u8; 32]>,
    ) -> Self {
        Self {
            artifact_id,
            intent_digest,
            expected_commit,
            manifest_digest,
        }
    }

    pub const fn artifact_id(self) -> HomeArtifactId {
        self.artifact_id
    }

    pub const fn intent_digest(&self) -> &[u8; 32] {
        &self.intent_digest
    }

    pub const fn expected_commit(self) -> Option<GitCommitId> {
        self.expected_commit
    }

    pub const fn manifest_digest(&self) -> Option<&[u8; 32]> {
        self.manifest_digest.as_ref()
    }
}
