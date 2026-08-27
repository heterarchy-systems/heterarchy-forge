use std::fmt;
use std::str::FromStr;

use thiserror::Error;
use uuid::Uuid;

use crate::{
    ActivityId, ChangeSetId, FileByteCount, FileContentHash, RuntimeInstanceId, TimestampMillis,
    WorkspaceId, WorkspaceRelativePath, WorkspaceRevision,
};

const SHA1_BYTES: usize = 20;
const SHA1_HEX_BYTES: usize = SHA1_BYTES * 2;
const SHA1_ENCODED_BYTES: usize = "sha1:".len() + SHA1_HEX_BYTES;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CheckpointId(Uuid);

impl CheckpointId {
    pub const fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }

    pub const fn into_uuid(self) -> Uuid {
        self.0
    }
}

impl fmt::Display for CheckpointId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for CheckpointId {
    type Err = CheckpointIdParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(value)
            .map(Self)
            .map_err(CheckpointIdParseError::InvalidUuid)
    }
}

#[derive(Debug, Error)]
pub enum CheckpointIdParseError {
    #[error("invalid Checkpoint UUID")]
    InvalidUuid(#[source] uuid::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CheckpointRevision(i64);

impl CheckpointRevision {
    pub const INITIAL: Self = Self(1);

    pub const fn new(value: i64) -> Result<Self, CheckpointRevisionError> {
        if value < 1 {
            Err(CheckpointRevisionError::Invalid { actual: value })
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> i64 {
        self.0
    }

    pub const fn checked_next(self) -> Result<Self, CheckpointRevisionError> {
        match self.0.checked_add(1) {
            Some(value) => Ok(Self(value)),
            None => Err(CheckpointRevisionError::Overflow { current: self.0 }),
        }
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointRevisionError {
    #[error("Checkpoint revision must be at least 1, got {actual}")]
    Invalid { actual: i64 },
    #[error("Checkpoint revision overflowed at {current}")]
    Overflow { current: i64 },
}

/// Git object format supported by the first checkpoint adapter.
///
/// The adapter must explicitly query Git and reject any other repository
/// object format before it creates or consumes a checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GitObjectFormat {
    Sha1,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GitObjectId([u8; SHA1_BYTES]);

impl GitObjectId {
    pub const BYTE_LEN: usize = SHA1_BYTES;
    pub const ENCODED_LEN: usize = SHA1_ENCODED_BYTES;

    pub const fn from_sha1_bytes(value: [u8; SHA1_BYTES]) -> Self {
        Self(value)
    }

    pub const fn format(self) -> GitObjectFormat {
        GitObjectFormat::Sha1
    }

    pub const fn as_bytes(&self) -> &[u8; SHA1_BYTES] {
        &self.0
    }
}

impl fmt::Debug for GitObjectId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GitObjectId")
            .field("format", &self.format())
            .finish_non_exhaustive()
    }
}

impl fmt::Display for GitObjectId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("sha1:")?;
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for GitObjectId {
    type Err = GitObjectIdParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != SHA1_ENCODED_BYTES {
            return Err(GitObjectIdParseError::InvalidLength {
                actual: value.len(),
            });
        }
        let Some(hex) = value.strip_prefix("sha1:") else {
            return Err(GitObjectIdParseError::UnsupportedFormat);
        };
        let mut decoded = [0_u8; SHA1_BYTES];
        for (index, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
            decoded[index] = (decode_lower_hex(pair[0])? << 4) | decode_lower_hex(pair[1])?;
        }
        Ok(Self(decoded))
    }
}

const fn decode_lower_hex(value: u8) -> Result<u8, GitObjectIdParseError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(GitObjectIdParseError::InvalidEncoding),
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum GitObjectIdParseError {
    #[error("Git object identifier has {actual} encoded bytes; expected 45")]
    InvalidLength { actual: usize },
    #[error("Git object format is unsupported")]
    UnsupportedFormat,
    #[error("Git object identifier must use canonical lower hexadecimal")]
    InvalidEncoding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GitBlobId(GitObjectId);

impl GitBlobId {
    pub const fn from_sha1_bytes(value: [u8; SHA1_BYTES]) -> Self {
        Self(GitObjectId::from_sha1_bytes(value))
    }

    pub const fn object_id(self) -> GitObjectId {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GitCommitId(GitObjectId);

impl GitCommitId {
    pub const fn from_sha1_bytes(value: [u8; SHA1_BYTES]) -> Self {
        Self(GitObjectId::from_sha1_bytes(value))
    }

    pub const fn object_id(self) -> GitObjectId {
        self.0
    }
}

/// Sanitized regular-file permission bits preserved by checkpoint restore.
/// File type, set-id, sticky, ACL, xattr, and platform flags are deliberately
/// outside the first checkpoint contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CheckpointFileMode(u16);

impl CheckpointFileMode {
    pub const MAX: u16 = 0o777;

    pub const fn new(value: u16) -> Result<Self, CheckpointFileModeError> {
        if value & !Self::MAX == 0 {
            Ok(Self(value))
        } else {
            Err(CheckpointFileModeError::UnsupportedBits { actual: value })
        }
    }

    pub const fn get(self) -> u16 {
        self.0
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointFileModeError {
    #[error("Checkpoint file mode {actual:#o} contains unsupported bits")]
    UnsupportedBits { actual: u16 },
}

/// Descriptor-observed filesystem state used for exact restore CAS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CheckpointObservedPathState {
    Absent,
    Regular {
        hash: FileContentHash,
        size: FileByteCount,
        mode: CheckpointFileMode,
    },
}

/// Exact Git-retained checkpoint state. The blob is recovery authority; the
/// BLAKE3 hash/size/mode are descriptor-relative CAS and restoration evidence.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CheckpointPathState {
    Absent,
    Regular {
        blob: GitBlobId,
        hash: FileContentHash,
        size: FileByteCount,
        mode: CheckpointFileMode,
    },
}

impl CheckpointPathState {
    pub const fn observed(&self) -> CheckpointObservedPathState {
        match self {
            Self::Absent => CheckpointObservedPathState::Absent,
            Self::Regular {
                hash, size, mode, ..
            } => CheckpointObservedPathState::Regular {
                hash: *hash,
                size: *size,
                mode: *mode,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CheckpointAttribution {
    id: CheckpointId,
    change_set_id: ChangeSetId,
    workspace_id: WorkspaceId,
    workspace_revision: WorkspaceRevision,
    activity_id: ActivityId,
}

impl CheckpointAttribution {
    pub const fn new(
        id: CheckpointId,
        change_set_id: ChangeSetId,
        workspace_id: WorkspaceId,
        workspace_revision: WorkspaceRevision,
        activity_id: ActivityId,
    ) -> Self {
        Self {
            id,
            change_set_id,
            workspace_id,
            workspace_revision,
            activity_id,
        }
    }

    pub const fn id(self) -> CheckpointId {
        self.id
    }

    pub const fn change_set_id(self) -> ChangeSetId {
        self.change_set_id
    }

    pub const fn workspace_id(self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn workspace_revision(self) -> WorkspaceRevision {
        self.workspace_revision
    }

    pub const fn activity_id(self) -> ActivityId {
        self.activity_id
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CheckpointState {
    Starting,
    Ready,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CheckpointTimestamps {
    created_at: TimestampMillis,
    updated_at: TimestampMillis,
}

impl CheckpointTimestamps {
    pub const fn new(
        created_at: TimestampMillis,
        updated_at: TimestampMillis,
    ) -> Result<Self, CheckpointTransitionError> {
        if updated_at.get() < created_at.get() {
            Err(CheckpointTransitionError::TimestampOrder)
        } else {
            Ok(Self {
                created_at,
                updated_at,
            })
        }
    }

    pub const fn initial(created_at: TimestampMillis) -> Self {
        Self {
            created_at,
            updated_at: created_at,
        }
    }

    pub const fn created_at(self) -> TimestampMillis {
        self.created_at
    }

    pub const fn updated_at(self) -> TimestampMillis {
        self.updated_at
    }
}

/// Durable projection. A Starting checkpoint has only a retained PRE commit;
/// a Ready checkpoint also has exact POST state and its retained commit.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckpointSnapshots {
    Starting {
        pre: CheckpointPathState,
        pre_commit: GitCommitId,
    },
    Ready {
        pre: CheckpointPathState,
        pre_commit: GitCommitId,
        post: CheckpointPathState,
        post_commit: GitCommitId,
    },
}

impl CheckpointSnapshots {
    pub const fn state(&self) -> CheckpointState {
        match self {
            Self::Starting { .. } => CheckpointState::Starting,
            Self::Ready { .. } => CheckpointState::Ready,
        }
    }

    pub const fn pre(&self) -> &CheckpointPathState {
        match self {
            Self::Starting { pre, .. } | Self::Ready { pre, .. } => pre,
        }
    }

    pub const fn pre_commit(&self) -> GitCommitId {
        match self {
            Self::Starting { pre_commit, .. } | Self::Ready { pre_commit, .. } => *pre_commit,
        }
    }

    pub const fn post(&self) -> Option<&CheckpointPathState> {
        match self {
            Self::Starting { .. } => None,
            Self::Ready { post, .. } => Some(post),
        }
    }

    pub const fn post_commit(&self) -> Option<GitCommitId> {
        match self {
            Self::Starting { .. } => None,
            Self::Ready { post_commit, .. } => Some(*post_commit),
        }
    }
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredCheckpoint {
    attribution: CheckpointAttribution,
    path: WorkspaceRelativePath,
    snapshots: CheckpointSnapshots,
    timestamps: CheckpointTimestamps,
    revision: CheckpointRevision,
}

impl RegisteredCheckpoint {
    pub fn starting(
        attribution: CheckpointAttribution,
        path: WorkspaceRelativePath,
        pre: CheckpointPathState,
        pre_commit: GitCommitId,
        observed_at: TimestampMillis,
    ) -> Self {
        Self {
            attribution,
            path,
            snapshots: CheckpointSnapshots::Starting { pre, pre_commit },
            timestamps: CheckpointTimestamps::initial(observed_at),
            revision: CheckpointRevision::INITIAL,
        }
    }

    pub fn from_parts(
        attribution: CheckpointAttribution,
        path: WorkspaceRelativePath,
        snapshots: CheckpointSnapshots,
        timestamps: CheckpointTimestamps,
        revision: CheckpointRevision,
    ) -> Result<Self, CheckpointTransitionError> {
        let valid_revision = match snapshots.state() {
            CheckpointState::Starting => revision == CheckpointRevision::INITIAL,
            CheckpointState::Ready => revision.get() == 2,
        };
        if !valid_revision {
            return Err(CheckpointTransitionError::InvalidLifecycleRevision);
        }
        if snapshots.state() == CheckpointState::Starting
            && timestamps.created_at() != timestamps.updated_at()
        {
            return Err(CheckpointTransitionError::InvalidLifecycleTimestamp);
        }
        Ok(Self {
            attribution,
            path,
            snapshots,
            timestamps,
            revision,
        })
    }

    pub fn complete(
        &self,
        expected_revision: CheckpointRevision,
        post: CheckpointPathState,
        post_commit: GitCommitId,
        observed_at: TimestampMillis,
    ) -> Result<Self, CheckpointTransitionError> {
        let CheckpointSnapshots::Starting { pre, pre_commit } = &self.snapshots else {
            return Err(CheckpointTransitionError::NotStarting);
        };
        if self.revision != expected_revision {
            return Err(CheckpointTransitionError::RevisionConflict);
        }
        if observed_at.get() < self.timestamps.created_at().get() {
            return Err(CheckpointTransitionError::TimestampOrder);
        }
        let revision = self
            .revision
            .checked_next()
            .map_err(|_| CheckpointTransitionError::RevisionOverflow)?;
        Ok(Self {
            attribution: self.attribution,
            path: self.path.clone(),
            snapshots: CheckpointSnapshots::Ready {
                pre: pre.clone(),
                pre_commit: *pre_commit,
                post,
                post_commit,
            },
            timestamps: CheckpointTimestamps::new(self.timestamps.created_at(), observed_at)?,
            revision,
        })
    }

    pub const fn id(&self) -> CheckpointId {
        self.attribution.id()
    }

    pub const fn change_set_id(&self) -> ChangeSetId {
        self.attribution.change_set_id()
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.attribution.workspace_id()
    }

    pub const fn workspace_revision(&self) -> WorkspaceRevision {
        self.attribution.workspace_revision()
    }

    pub const fn activity_id(&self) -> ActivityId {
        self.attribution.activity_id()
    }

    pub const fn path(&self) -> &WorkspaceRelativePath {
        &self.path
    }

    pub const fn pre(&self) -> &CheckpointPathState {
        self.snapshots.pre()
    }

    pub const fn pre_commit(&self) -> GitCommitId {
        self.snapshots.pre_commit()
    }

    pub const fn post(&self) -> Option<&CheckpointPathState> {
        self.snapshots.post()
    }

    pub const fn post_commit(&self) -> Option<GitCommitId> {
        self.snapshots.post_commit()
    }

    pub const fn state(&self) -> CheckpointState {
        self.snapshots.state()
    }

    pub const fn timestamps(&self) -> CheckpointTimestamps {
        self.timestamps
    }

    pub const fn revision(&self) -> CheckpointRevision {
        self.revision
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointTransitionError {
    #[error("Checkpoint is not Starting")]
    NotStarting,
    #[error("Checkpoint revision conflict")]
    RevisionConflict,
    #[error("Checkpoint revision overflow")]
    RevisionOverflow,
    #[error("Checkpoint timestamp precedes its creation")]
    TimestampOrder,
    #[error("Checkpoint revision does not match its lifecycle state")]
    InvalidLifecycleRevision,
    #[error("Checkpoint timestamps do not match its lifecycle state")]
    InvalidLifecycleTimestamp,
}

/// Exact inverse effect admitted only after current state equals durable POST.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestoreEffect {
    Delete,
    Restore {
        blob: GitBlobId,
        hash: FileContentHash,
        size: FileByteCount,
        mode: CheckpointFileMode,
    },
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestorePlan {
    checkpoint_id: CheckpointId,
    workspace_id: WorkspaceId,
    expected_checkpoint_revision: CheckpointRevision,
    path: WorkspaceRelativePath,
    expected_post: CheckpointObservedPathState,
    effect: RestoreEffect,
}

impl RestorePlan {
    pub const fn checkpoint_id(&self) -> CheckpointId {
        self.checkpoint_id
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn expected_checkpoint_revision(&self) -> CheckpointRevision {
        self.expected_checkpoint_revision
    }

    pub const fn path(&self) -> &WorkspaceRelativePath {
        &self.path
    }

    pub const fn expected_post(&self) -> CheckpointObservedPathState {
        self.expected_post
    }

    pub const fn effect(&self) -> &RestoreEffect {
        &self.effect
    }
}

pub fn plan_restore(
    checkpoint: &RegisteredCheckpoint,
    current: CheckpointObservedPathState,
) -> Result<RestorePlan, RestorePlanError> {
    if checkpoint.state() != CheckpointState::Ready {
        return Err(RestorePlanError::CheckpointNotReady);
    }
    let post = checkpoint
        .post()
        .ok_or(RestorePlanError::CheckpointNotReady)?;
    let expected_post = post.observed();
    if current != expected_post {
        return Err(RestorePlanError::CurrentStateConflict);
    }
    let effect = match checkpoint.pre() {
        CheckpointPathState::Absent => RestoreEffect::Delete,
        CheckpointPathState::Regular {
            blob,
            hash,
            size,
            mode,
        } => RestoreEffect::Restore {
            blob: *blob,
            hash: *hash,
            size: *size,
            mode: *mode,
        },
    };
    Ok(RestorePlan {
        checkpoint_id: checkpoint.id(),
        workspace_id: checkpoint.workspace_id(),
        expected_checkpoint_revision: checkpoint.revision(),
        path: checkpoint.path().clone(),
        expected_post,
        effect,
    })
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum RestorePlanError {
    #[error("Checkpoint is not ready for restore")]
    CheckpointNotReady,
    #[error("current path state differs from Checkpoint POST")]
    CurrentStateConflict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CheckpointRestoreId(Uuid);

impl CheckpointRestoreId {
    pub const fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }

    pub const fn into_uuid(self) -> Uuid {
        self.0
    }
}

impl fmt::Display for CheckpointRestoreId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for CheckpointRestoreId {
    type Err = CheckpointRestoreIdParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(value)
            .map(Self)
            .map_err(CheckpointRestoreIdParseError::InvalidUuid)
    }
}

#[derive(Debug, Error)]
pub enum CheckpointRestoreIdParseError {
    #[error("invalid Checkpoint Restore UUID")]
    InvalidUuid(#[source] uuid::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CheckpointRestoreRevision(i64);

impl CheckpointRestoreRevision {
    pub const INITIAL: Self = Self(1);

    pub const fn new(value: i64) -> Result<Self, CheckpointRestoreRevisionError> {
        if value < 1 {
            Err(CheckpointRestoreRevisionError::Invalid { actual: value })
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> i64 {
        self.0
    }

    pub const fn checked_next(self) -> Result<Self, CheckpointRestoreRevisionError> {
        match self.0.checked_add(1) {
            Some(value) => Ok(Self(value)),
            None => Err(CheckpointRestoreRevisionError::Overflow { current: self.0 }),
        }
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointRestoreRevisionError {
    #[error("Checkpoint Restore revision must be at least 1, got {actual}")]
    Invalid { actual: i64 },
    #[error("Checkpoint Restore revision overflowed at {current}")]
    Overflow { current: i64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CheckpointRestoreState {
    Starting,
    Restored,
    Failed,
    RecoveryRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CheckpointRestoreFailureCode {
    MissingObject,
    ObjectHashMismatch,
    PathConflict,
    IoFailure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum CheckpointRestoreOutcome {
    Restored,
    Failed(CheckpointRestoreFailureCode),
    RecoveryRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CheckpointRestoreFence {
    Direct,
    Maintenance {
        owner: RuntimeInstanceId,
        lease_epoch: crate::recovery::RecoveryLeaseEpoch,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CheckpointRestoreAttribution {
    id: CheckpointRestoreId,
    checkpoint_id: CheckpointId,
    workspace_id: WorkspaceId,
    expected_checkpoint_revision: CheckpointRevision,
    initiator: RuntimeInstanceId,
    activity_id: ActivityId,
    approval_request_id: Option<crate::approval::ApprovalRequestId>,
    fence: CheckpointRestoreFence,
}

impl CheckpointRestoreAttribution {
    pub const fn new(
        id: CheckpointRestoreId,
        plan: &RestorePlan,
        initiator: RuntimeInstanceId,
        activity_id: ActivityId,
        approval_request_id: Option<crate::approval::ApprovalRequestId>,
        fence: CheckpointRestoreFence,
    ) -> Self {
        Self {
            id,
            checkpoint_id: plan.checkpoint_id(),
            workspace_id: plan.workspace_id(),
            expected_checkpoint_revision: plan.expected_checkpoint_revision(),
            initiator,
            activity_id,
            approval_request_id,
            fence,
        }
    }

    pub const fn id(self) -> CheckpointRestoreId {
        self.id
    }

    pub const fn checkpoint_id(self) -> CheckpointId {
        self.checkpoint_id
    }

    pub const fn workspace_id(self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn expected_checkpoint_revision(self) -> CheckpointRevision {
        self.expected_checkpoint_revision
    }

    /// Runtime instance that initiated this restore.
    pub const fn initiator(self) -> RuntimeInstanceId {
        self.initiator
    }

    /// Live Activity whose lease authorized the filesystem effect.
    pub const fn activity_id(self) -> ActivityId {
        self.activity_id
    }

    /// Approval that authorized this restore, when one was required.
    pub const fn approval_request_id(self) -> Option<crate::approval::ApprovalRequestId> {
        self.approval_request_id
    }

    /// Authority fence under which this restore was admitted.
    pub const fn fence(self) -> CheckpointRestoreFence {
        self.fence
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CheckpointRestoreTimestamps {
    created_at: TimestampMillis,
    updated_at: TimestampMillis,
}

impl CheckpointRestoreTimestamps {
    pub const fn new(
        created_at: TimestampMillis,
        updated_at: TimestampMillis,
    ) -> Result<Self, CheckpointRestoreTransitionError> {
        if updated_at.get() < created_at.get() {
            Err(CheckpointRestoreTransitionError::TimestampOrder)
        } else {
            Ok(Self {
                created_at,
                updated_at,
            })
        }
    }

    pub const fn initial(created_at: TimestampMillis) -> Self {
        Self {
            created_at,
            updated_at: created_at,
        }
    }

    pub const fn created_at(self) -> TimestampMillis {
        self.created_at
    }

    pub const fn updated_at(self) -> TimestampMillis {
        self.updated_at
    }
}

/// Durable restore journal. Admission requires a previously produced
/// [`RestorePlan`], so a current-state mismatch never creates a Starting row.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredCheckpointRestore {
    attribution: CheckpointRestoreAttribution,
    expected_post: CheckpointObservedPathState,
    effect: RestoreEffect,
    state: CheckpointRestoreState,
    failure_code: Option<CheckpointRestoreFailureCode>,
    timestamps: CheckpointRestoreTimestamps,
    revision: CheckpointRestoreRevision,
}

impl RegisteredCheckpointRestore {
    pub fn starting(
        attribution: CheckpointRestoreAttribution,
        plan: &RestorePlan,
        observed_at: TimestampMillis,
    ) -> Self {
        Self {
            attribution,
            expected_post: plan.expected_post(),
            effect: plan.effect().clone(),
            state: CheckpointRestoreState::Starting,
            failure_code: None,
            timestamps: CheckpointRestoreTimestamps::initial(observed_at),
            revision: CheckpointRestoreRevision::INITIAL,
        }
    }

    pub fn restored(
        &self,
        expected_revision: CheckpointRestoreRevision,
        observed_at: TimestampMillis,
    ) -> Result<Self, CheckpointRestoreTransitionError> {
        self.terminal(
            expected_revision,
            CheckpointRestoreOutcome::Restored,
            observed_at,
        )
    }

    pub fn failed(
        &self,
        expected_revision: CheckpointRestoreRevision,
        failure_code: CheckpointRestoreFailureCode,
        observed_at: TimestampMillis,
    ) -> Result<Self, CheckpointRestoreTransitionError> {
        self.terminal(
            expected_revision,
            CheckpointRestoreOutcome::Failed(failure_code),
            observed_at,
        )
    }

    pub fn recovery_required(
        &self,
        expected_revision: CheckpointRestoreRevision,
        observed_at: TimestampMillis,
    ) -> Result<Self, CheckpointRestoreTransitionError> {
        self.terminal(
            expected_revision,
            CheckpointRestoreOutcome::RecoveryRequired,
            observed_at,
        )
    }

    fn terminal(
        &self,
        expected_revision: CheckpointRestoreRevision,
        outcome: CheckpointRestoreOutcome,
        observed_at: TimestampMillis,
    ) -> Result<Self, CheckpointRestoreTransitionError> {
        if self.state != CheckpointRestoreState::Starting {
            return Err(CheckpointRestoreTransitionError::NotStarting);
        }
        if self.revision != expected_revision {
            return Err(CheckpointRestoreTransitionError::RevisionConflict);
        }
        if observed_at.get() < self.timestamps.created_at().get() {
            return Err(CheckpointRestoreTransitionError::TimestampOrder);
        }
        let (state, failure_code) = match outcome {
            CheckpointRestoreOutcome::Restored => (CheckpointRestoreState::Restored, None),
            CheckpointRestoreOutcome::Failed(code) => (CheckpointRestoreState::Failed, Some(code)),
            CheckpointRestoreOutcome::RecoveryRequired => {
                (CheckpointRestoreState::RecoveryRequired, None)
            }
        };
        Ok(Self {
            attribution: self.attribution,
            expected_post: self.expected_post,
            effect: self.effect.clone(),
            state,
            failure_code,
            timestamps: CheckpointRestoreTimestamps::new(
                self.timestamps.created_at(),
                observed_at,
            )?,
            revision: self
                .revision
                .checked_next()
                .map_err(|_| CheckpointRestoreTransitionError::RevisionOverflow)?,
        })
    }

    pub const fn id(&self) -> CheckpointRestoreId {
        self.attribution.id()
    }

    pub const fn checkpoint_id(&self) -> CheckpointId {
        self.attribution.checkpoint_id()
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.attribution.workspace_id()
    }

    pub const fn expected_checkpoint_revision(&self) -> CheckpointRevision {
        self.attribution.expected_checkpoint_revision()
    }

    /// Full provenance record for this restore journal.
    pub const fn attribution(&self) -> &CheckpointRestoreAttribution {
        &self.attribution
    }

    pub const fn expected_post(&self) -> CheckpointObservedPathState {
        self.expected_post
    }

    pub const fn effect(&self) -> &RestoreEffect {
        &self.effect
    }

    pub const fn state(&self) -> CheckpointRestoreState {
        self.state
    }

    pub const fn failure_code(&self) -> Option<CheckpointRestoreFailureCode> {
        self.failure_code
    }

    pub const fn timestamps(&self) -> CheckpointRestoreTimestamps {
        self.timestamps
    }

    pub const fn revision(&self) -> CheckpointRestoreRevision {
        self.revision
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointRestoreTransitionError {
    #[error("Checkpoint Restore is not Starting")]
    NotStarting,
    #[error("Checkpoint Restore revision conflict")]
    RevisionConflict,
    #[error("Checkpoint Restore revision overflow")]
    RevisionOverflow,
    #[error("Checkpoint Restore timestamp precedes its creation")]
    TimestampOrder,
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::str::FromStr;

    use uuid::Uuid;

    use super::*;

    fn hash(value: u8) -> FileContentHash {
        FileContentHash::from_bytes([value; FileContentHash::BYTE_LEN])
    }

    fn attribution() -> Result<CheckpointAttribution, Box<dyn std::error::Error>> {
        Ok(CheckpointAttribution::new(
            CheckpointId::from_uuid(Uuid::from_u128(1)),
            ChangeSetId::from_uuid(Uuid::from_u128(2)),
            WorkspaceId::from_uuid(Uuid::from_u128(3)),
            WorkspaceRevision::new(4)?,
            ActivityId::from_uuid(Uuid::from_u128(5)),
        ))
    }

    fn regular(value: u8) -> Result<CheckpointPathState, Box<dyn std::error::Error>> {
        Ok(CheckpointPathState::Regular {
            blob: GitBlobId::from_sha1_bytes([value; SHA1_BYTES]),
            hash: hash(value),
            size: FileByteCount::new(u64::from(value)),
            mode: CheckpointFileMode::new(0o640)?,
        })
    }

    fn starting(
        pre: CheckpointPathState,
    ) -> Result<RegisteredCheckpoint, Box<dyn std::error::Error>> {
        Ok(RegisteredCheckpoint::starting(
            attribution()?,
            WorkspaceRelativePath::new(PathBuf::from("src/lib.rs"))?,
            pre,
            GitCommitId::from_sha1_bytes([9; SHA1_BYTES]),
            TimestampMillis::new(10)?,
        ))
    }

    fn restore_attribution(
        checkpoint: &RegisteredCheckpoint,
        plan: &RestorePlan,
        id: CheckpointRestoreId,
    ) -> CheckpointRestoreAttribution {
        CheckpointRestoreAttribution::new(
            id,
            plan,
            RuntimeInstanceId::from_uuid(Uuid::from_u128(0xCAFE)),
            checkpoint.activity_id(),
            None,
            CheckpointRestoreFence::Direct,
        )
    }

    #[test]
    fn git_object_ids_are_format_explicit_canonical_and_redacted_in_debug()
    -> Result<(), Box<dyn std::error::Error>> {
        let id = GitObjectId::from_sha1_bytes([0xab; SHA1_BYTES]);
        let encoded = format!("{id}");
        assert_eq!(encoded, format!("sha1:{}", "ab".repeat(SHA1_BYTES)));
        assert_eq!(GitObjectId::from_str(&encoded)?, id);
        assert!(!format!("{id:?}").contains(&"ab".repeat(4)));
        assert!(matches!(
            GitObjectId::from_str(&encoded.to_uppercase()),
            Err(GitObjectIdParseError::UnsupportedFormat | GitObjectIdParseError::InvalidEncoding)
        ));
        assert!(matches!(
            GitObjectId::from_str(&format!("sha256:{}", "00".repeat(32))),
            Err(GitObjectIdParseError::InvalidLength { .. })
        ));
        Ok(())
    }

    #[test]
    fn checkpoint_modes_reject_file_type_and_privileged_bits() {
        assert_eq!(
            CheckpointFileMode::new(0o755).map(CheckpointFileMode::get),
            Ok(0o755)
        );
        assert!(matches!(
            CheckpointFileMode::new(0o4755),
            Err(CheckpointFileModeError::UnsupportedBits { .. })
        ));
        assert!(CheckpointFileMode::new(0o1000).is_err());
        assert!(CheckpointFileMode::new(0o2000).is_err());
    }

    #[test]
    fn checkpoint_identity_revision_and_timestamps_are_typed_and_checked()
    -> Result<(), Box<dyn std::error::Error>> {
        let id = CheckpointId::from_uuid(Uuid::from_u128(0xCAFE));
        assert_eq!(CheckpointId::from_str(&id.to_string())?, id);
        assert!(CheckpointRevision::new(0).is_err());
        assert!(CheckpointRevision::new(-1).is_err());
        assert!(matches!(
            CheckpointRevision::new(i64::MAX)?.checked_next(),
            Err(CheckpointRevisionError::Overflow { current: i64::MAX })
        ));
        assert!(matches!(
            CheckpointTimestamps::new(TimestampMillis::new(2)?, TimestampMillis::new(1)?),
            Err(CheckpointTransitionError::TimestampOrder)
        ));
        Ok(())
    }

    #[test]
    fn starting_checkpoint_completes_once_with_revision_and_timestamp_cas()
    -> Result<(), Box<dyn std::error::Error>> {
        let start = starting(regular(1)?)?;
        assert_eq!(start.state(), CheckpointState::Starting);
        let ready = start.complete(
            CheckpointRevision::INITIAL,
            regular(2)?,
            GitCommitId::from_sha1_bytes([8; SHA1_BYTES]),
            TimestampMillis::new(11)?,
        )?;
        assert_eq!(ready.state(), CheckpointState::Ready);
        assert_eq!(ready.revision().get(), 2);
        assert_eq!(ready.timestamps().updated_at().get(), 11);
        assert!(matches!(
            ready.complete(
                ready.revision(),
                regular(3)?,
                GitCommitId::from_sha1_bytes([7; SHA1_BYTES]),
                TimestampMillis::new(12)?,
            ),
            Err(CheckpointTransitionError::NotStarting)
        ));
        assert!(matches!(
            start.complete(
                CheckpointRevision::new(2)?,
                regular(2)?,
                GitCommitId::from_sha1_bytes([8; SHA1_BYTES]),
                TimestampMillis::new(11)?,
            ),
            Err(CheckpointTransitionError::RevisionConflict)
        ));
        Ok(())
    }

    #[test]
    fn restore_plan_requires_exact_post_and_inverts_create_replace_delete()
    -> Result<(), Box<dyn std::error::Error>> {
        let create = starting(CheckpointPathState::Absent)?.complete(
            CheckpointRevision::INITIAL,
            regular(2)?,
            GitCommitId::from_sha1_bytes([8; SHA1_BYTES]),
            TimestampMillis::new(11)?,
        )?;
        let create_plan = plan_restore(&create, regular(2)?.observed())?;
        assert_eq!(create_plan.effect(), &RestoreEffect::Delete);

        let replace = starting(regular(1)?)?.complete(
            CheckpointRevision::INITIAL,
            regular(2)?,
            GitCommitId::from_sha1_bytes([8; SHA1_BYTES]),
            TimestampMillis::new(11)?,
        )?;
        let replace_plan = plan_restore(&replace, regular(2)?.observed())?;
        assert_eq!(replace_plan.checkpoint_id(), replace.id());
        assert_eq!(
            replace_plan.expected_checkpoint_revision(),
            replace.revision()
        );
        assert_eq!(replace_plan.path(), replace.path());
        assert_eq!(replace_plan.expected_post(), regular(2)?.observed());
        assert_eq!(
            replace_plan.effect(),
            &RestoreEffect::Restore {
                blob: GitBlobId::from_sha1_bytes([1; SHA1_BYTES]),
                hash: hash(1),
                size: FileByteCount::new(1),
                mode: CheckpointFileMode::new(0o640)?,
            }
        );

        let delete = starting(regular(1)?)?.complete(
            CheckpointRevision::INITIAL,
            CheckpointPathState::Absent,
            GitCommitId::from_sha1_bytes([8; SHA1_BYTES]),
            TimestampMillis::new(11)?,
        )?;
        assert!(matches!(
            plan_restore(&delete, CheckpointObservedPathState::Absent)?.effect(),
            RestoreEffect::Restore { hash: value, .. } if *value == hash(1)
        ));

        let edited = CheckpointObservedPathState::Regular {
            hash: hash(3),
            size: FileByteCount::new(3),
            mode: CheckpointFileMode::new(0o640)?,
        };
        assert_eq!(
            plan_restore(&replace, edited),
            Err(RestorePlanError::CurrentStateConflict)
        );
        Ok(())
    }

    #[test]
    fn restore_is_unavailable_before_post_checkpoint_is_ready()
    -> Result<(), Box<dyn std::error::Error>> {
        let checkpoint = starting(regular(1)?)?;
        assert_eq!(
            plan_restore(&checkpoint, regular(1)?.observed()),
            Err(RestorePlanError::CheckpointNotReady)
        );
        Ok(())
    }

    #[test]
    fn persistence_projection_uses_state_specific_snapshot_payloads()
    -> Result<(), Box<dyn std::error::Error>> {
        let start = starting(regular(1)?)?;
        let projection = RegisteredCheckpoint::from_parts(
            attribution()?,
            start.path().clone(),
            CheckpointSnapshots::Ready {
                pre: start.pre().clone(),
                pre_commit: start.pre_commit(),
                post: regular(2)?,
                post_commit: GitCommitId::from_sha1_bytes([8; SHA1_BYTES]),
            },
            CheckpointTimestamps::new(TimestampMillis::new(1)?, TimestampMillis::new(2)?)?,
            CheckpointRevision::new(2)?,
        )?;
        assert_eq!(projection.state(), CheckpointState::Ready);
        assert!(projection.post().is_some());
        assert!(projection.post_commit().is_some());
        assert!(matches!(
            RegisteredCheckpoint::from_parts(
                attribution()?,
                start.path().clone(),
                CheckpointSnapshots::Starting {
                    pre: start.pre().clone(),
                    pre_commit: start.pre_commit(),
                },
                CheckpointTimestamps::new(TimestampMillis::new(1)?, TimestampMillis::new(2)?,)?,
                CheckpointRevision::INITIAL,
            ),
            Err(CheckpointTransitionError::InvalidLifecycleTimestamp)
        ));
        assert!(matches!(
            RegisteredCheckpoint::from_parts(
                attribution()?,
                start.path().clone(),
                CheckpointSnapshots::Ready {
                    pre: start.pre().clone(),
                    pre_commit: start.pre_commit(),
                    post: regular(2)?,
                    post_commit: GitCommitId::from_sha1_bytes([8; SHA1_BYTES]),
                },
                CheckpointTimestamps::new(TimestampMillis::new(1)?, TimestampMillis::new(2)?,)?,
                CheckpointRevision::INITIAL,
            ),
            Err(CheckpointTransitionError::InvalidLifecycleRevision)
        ));
        Ok(())
    }

    #[test]
    fn restore_journal_is_bound_to_exact_plan_and_transitions_once()
    -> Result<(), Box<dyn std::error::Error>> {
        let checkpoint = starting(regular(1)?)?.complete(
            CheckpointRevision::INITIAL,
            regular(2)?,
            GitCommitId::from_sha1_bytes([8; SHA1_BYTES]),
            TimestampMillis::new(11)?,
        )?;
        let plan = plan_restore(&checkpoint, regular(2)?.observed())?;
        let restore_id = CheckpointRestoreId::from_uuid(Uuid::from_u128(0xBEEF));
        assert_eq!(
            CheckpointRestoreId::from_str(&restore_id.to_string())?,
            restore_id
        );
        let starting = RegisteredCheckpointRestore::starting(
            restore_attribution(&checkpoint, &plan, restore_id),
            &plan,
            TimestampMillis::new(12)?,
        );
        assert_eq!(starting.checkpoint_id(), checkpoint.id());
        assert_eq!(
            starting.expected_checkpoint_revision(),
            checkpoint.revision()
        );
        assert_eq!(starting.expected_post(), plan.expected_post());
        assert_eq!(starting.effect(), plan.effect());

        let restored = starting.restored(
            CheckpointRestoreRevision::INITIAL,
            TimestampMillis::new(13)?,
        )?;
        assert_eq!(restored.state(), CheckpointRestoreState::Restored);
        assert_eq!(restored.revision().get(), 2);
        assert!(restored.failure_code().is_none());
        assert!(matches!(
            restored.restored(restored.revision(), TimestampMillis::new(14)?),
            Err(CheckpointRestoreTransitionError::NotStarting)
        ));
        Ok(())
    }

    #[test]
    fn restore_failure_and_uncertain_effect_have_distinct_terminal_states()
    -> Result<(), Box<dyn std::error::Error>> {
        let checkpoint = starting(regular(1)?)?.complete(
            CheckpointRevision::INITIAL,
            regular(2)?,
            GitCommitId::from_sha1_bytes([8; SHA1_BYTES]),
            TimestampMillis::new(11)?,
        )?;
        let plan = plan_restore(&checkpoint, regular(2)?.observed())?;
        let starting = RegisteredCheckpointRestore::starting(
            restore_attribution(
                &checkpoint,
                &plan,
                CheckpointRestoreId::from_uuid(Uuid::from_u128(0xD00D)),
            ),
            &plan,
            TimestampMillis::new(12)?,
        );
        assert!(matches!(
            starting.failed(
                CheckpointRestoreRevision::new(2)?,
                CheckpointRestoreFailureCode::MissingObject,
                TimestampMillis::new(13)?,
            ),
            Err(CheckpointRestoreTransitionError::RevisionConflict)
        ));
        assert!(matches!(
            starting.recovery_required(
                CheckpointRestoreRevision::INITIAL,
                TimestampMillis::new(11)?,
            ),
            Err(CheckpointRestoreTransitionError::TimestampOrder)
        ));
        let failed = starting.failed(
            CheckpointRestoreRevision::INITIAL,
            CheckpointRestoreFailureCode::MissingObject,
            TimestampMillis::new(13)?,
        )?;
        assert_eq!(failed.state(), CheckpointRestoreState::Failed);
        assert_eq!(
            failed.failure_code(),
            Some(CheckpointRestoreFailureCode::MissingObject)
        );
        let recovery = starting.recovery_required(
            CheckpointRestoreRevision::INITIAL,
            TimestampMillis::new(13)?,
        )?;
        assert_eq!(recovery.state(), CheckpointRestoreState::RecoveryRequired);
        assert!(recovery.failure_code().is_none());
        assert!(CheckpointRestoreRevision::new(0).is_err());
        assert!(matches!(
            CheckpointRestoreRevision::new(i64::MAX)?.checked_next(),
            Err(CheckpointRestoreRevisionError::Overflow { current: i64::MAX })
        ));
        Ok(())
    }
}
