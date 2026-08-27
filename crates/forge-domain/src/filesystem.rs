use std::ffi::OsStr;
use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;

use thiserror::Error;
use uuid::Uuid;

use crate::{
    ActivityId, ActivityLeaseRevision, RuntimeInstanceId, TimestampMillis, WorkspaceId,
    WorkspaceRevision,
};

/// Maximum native-byte length accepted for one Workspace-relative path.
pub const MAX_WORKSPACE_RELATIVE_PATH_BYTES: usize = 4_096;

macro_rules! uuid_identity {
    ($name:ident, $error:ident, $message:literal) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(Uuid);

        impl $name {
            pub const fn from_uuid(value: Uuid) -> Self {
                Self(value)
            }

            pub const fn into_uuid(self) -> Uuid {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl FromStr for $name {
            type Err = $error;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Uuid::parse_str(value)
                    .map(Self)
                    .map_err($error::InvalidUuid)
            }
        }

        #[derive(Debug, Error)]
        pub enum $error {
            #[error($message)]
            InvalidUuid(#[source] uuid::Error),
        }
    };
}

uuid_identity!(ChangeSetId, ChangeSetIdParseError, "invalid ChangeSet UUID");
uuid_identity!(
    FileMutationId,
    FileMutationIdParseError,
    "invalid file mutation UUID"
);

macro_rules! positive_revision {
    ($name:ident, $error:ident, $invalid:literal, $overflow:literal) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(i64);

        impl $name {
            pub const INITIAL: Self = Self(1);

            pub const fn new(value: i64) -> Result<Self, $error> {
                if value < 1 {
                    Err($error::Invalid { actual: value })
                } else {
                    Ok(Self(value))
                }
            }

            pub const fn get(self) -> i64 {
                self.0
            }

            pub const fn checked_next(self) -> Result<Self, $error> {
                match self.0.checked_add(1) {
                    Some(value) => Ok(Self(value)),
                    None => Err($error::Overflow { current: self.0 }),
                }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        #[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
        pub enum $error {
            #[error($invalid)]
            Invalid { actual: i64 },
            #[error($overflow)]
            Overflow { current: i64 },
        }
    };
}

positive_revision!(
    ChangeSetRevision,
    ChangeSetRevisionError,
    "ChangeSet revision must be at least 1, got {actual}",
    "ChangeSet revision overflowed at {current}"
);
positive_revision!(
    FileMutationRevision,
    FileMutationRevisionError,
    "file mutation revision must be at least 1, got {actual}",
    "file mutation revision overflowed at {current}"
);

/// Collision-resistant content digest used for file CAS and evidence linkage.
///
/// Hash computation belongs to the filesystem adapter. The domain preserves
/// only the fixed-width result and its canonical lower-hex wire form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FileContentHash([u8; 32]);

impl FileContentHash {
    pub const BYTE_LEN: usize = 32;
    pub const HEX_LEN: usize = Self::BYTE_LEN * 2;
    pub const ALGORITHM: &str = "blake3-256";
    pub const ENCODED_LEN: usize = Self::ALGORITHM.len() + 1 + Self::HEX_LEN;

    pub const fn from_bytes(value: [u8; Self::BYTE_LEN]) -> Self {
        Self(value)
    }

    pub const fn into_bytes(self) -> [u8; Self::BYTE_LEN] {
        self.0
    }

    pub const fn as_bytes(&self) -> &[u8; Self::BYTE_LEN] {
        &self.0
    }
}

impl fmt::Display for FileContentHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(Self::ALGORITHM)?;
        formatter.write_str(":")?;
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for FileContentHash {
    type Err = FileContentHashParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != Self::ENCODED_LEN {
            return Err(FileContentHashParseError::InvalidLength {
                actual: value.len(),
            });
        }
        let Some(hex) = value.strip_prefix("blake3-256:") else {
            return Err(FileContentHashParseError::InvalidAlgorithm);
        };
        let bytes = hex.as_bytes();
        let mut decoded = [0_u8; Self::BYTE_LEN];
        for (index, pair) in bytes.chunks_exact(2).enumerate() {
            let high = decode_lower_hex(pair[0])?;
            let low = decode_lower_hex(pair[1])?;
            decoded[index] = (high << 4) | low;
        }
        Ok(Self(decoded))
    }
}

const fn decode_lower_hex(value: u8) -> Result<u8, FileContentHashParseError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(FileContentHashParseError::InvalidEncoding),
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum FileContentHashParseError {
    #[error("file content hash has {actual} encoded bytes; expected 75")]
    InvalidLength { actual: usize },
    #[error("file content hash algorithm must be blake3-256")]
    InvalidAlgorithm,
    #[error("file content hash must use canonical lower hexadecimal")]
    InvalidEncoding,
}

/// Canonical native Workspace-relative path.
///
/// Construction is lexical and performs no I/O. The filesystem adapter must
/// additionally validate every existing component and the Workspace root at
/// the moment an effect is performed.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct WorkspaceRelativePath(PathBuf);

impl WorkspaceRelativePath {
    pub fn new(path: PathBuf) -> Result<Self, WorkspaceRelativePathError> {
        let actual = path.as_os_str().as_encoded_bytes().len();
        if actual == 0 {
            return Err(WorkspaceRelativePathError::Empty);
        }
        if actual > MAX_WORKSPACE_RELATIVE_PATH_BYTES {
            return Err(WorkspaceRelativePathError::TooLong {
                actual,
                maximum: MAX_WORKSPACE_RELATIVE_PATH_BYTES,
            });
        }
        if path.as_os_str().as_encoded_bytes().contains(&0) {
            return Err(WorkspaceRelativePathError::ContainsNul);
        }

        let mut canonical = PathBuf::new();
        for component in path.components() {
            match component {
                Component::Normal(value) => canonical.push(value),
                Component::Prefix(_)
                | Component::RootDir
                | Component::CurDir
                | Component::ParentDir => {
                    return Err(WorkspaceRelativePathError::NotConfined);
                }
            }
        }
        if canonical.as_os_str().is_empty() {
            return Err(WorkspaceRelativePathError::Empty);
        }
        if canonical.as_os_str().as_encoded_bytes() != path.as_os_str().as_encoded_bytes() {
            return Err(WorkspaceRelativePathError::NonCanonical);
        }
        Ok(Self(path))
    }

    pub fn as_path(&self) -> &Path {
        &self.0
    }

    pub fn into_path_buf(self) -> PathBuf {
        self.0
    }

    pub fn components(&self) -> impl Iterator<Item = &OsStr> {
        self.0.components().filter_map(|component| match component {
            Component::Normal(value) => Some(value),
            Component::Prefix(_)
            | Component::RootDir
            | Component::CurDir
            | Component::ParentDir => None,
        })
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum WorkspaceRelativePathError {
    #[error("Workspace-relative path is empty")]
    Empty,
    #[error("Workspace-relative path has {actual} native bytes; maximum is {maximum}")]
    TooLong { actual: usize, maximum: usize },
    #[error("Workspace-relative path is absolute or contains traversal")]
    NotConfined,
    #[error("Workspace-relative path is not in canonical lexical form")]
    NonCanonical,
    #[error("Workspace-relative path contains a NUL byte")]
    ContainsNul,
}

/// Byte count observed for a regular file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FileByteCount(u64);

impl FileByteCount {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Exact path state used by CAS and `ChangeSet` derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FilePathState {
    Absent,
    Regular {
        hash: FileContentHash,
        size: FileByteCount,
    },
}

impl FilePathState {
    pub const fn hash(self) -> Option<FileContentHash> {
        match self {
            Self::Absent => None,
            Self::Regular { hash, .. } => Some(hash),
        }
    }
}

/// Requested file effect. Patching/move remain separate future operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileMutationKind {
    Create,
    Replace,
    Delete,
}

/// Compare-and-set precondition for one file effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FilePrecondition {
    Absent,
    Matches(FileContentHash),
}

/// Durable lifecycle of one `ChangeSet`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChangeSetState {
    Starting,
    Applied,
    Failed,
}

/// Stable terminal reason recorded only when the adapter knows no effect was
/// committed. Uncertain outcomes intentionally remain `Starting` for recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileMutationFailureCode {
    InvalidPath,
    ProtectedPath,
    PathConflict,
    StaleWrite,
    CapacityExceeded,
    IoFailure,
}

/// Identity and durable attribution for one `ChangeSet`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChangeSetAttribution {
    id: ChangeSetId,
    workspace_id: WorkspaceId,
    workspace_revision: WorkspaceRevision,
    activity_id: ActivityId,
    runtime_instance_id: RuntimeInstanceId,
    activity_lease_revision: ActivityLeaseRevision,
}

impl ChangeSetAttribution {
    pub const fn new(
        id: ChangeSetId,
        workspace_id: WorkspaceId,
        workspace_revision: WorkspaceRevision,
        activity_id: ActivityId,
        runtime_instance_id: RuntimeInstanceId,
        activity_lease_revision: ActivityLeaseRevision,
    ) -> Self {
        Self {
            id,
            workspace_id,
            workspace_revision,
            activity_id,
            runtime_instance_id,
            activity_lease_revision,
        }
    }

    pub const fn id(self) -> ChangeSetId {
        self.id
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

    pub const fn runtime_instance_id(self) -> RuntimeInstanceId {
        self.runtime_instance_id
    }

    pub const fn activity_lease_revision(self) -> ActivityLeaseRevision {
        self.activity_lease_revision
    }
}

/// Creation and update observations for one durable `ChangeSet`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChangeSetTimestamps {
    created_at: TimestampMillis,
    updated_at: TimestampMillis,
}

impl ChangeSetTimestamps {
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

/// Durable attribution and lifecycle for one `ChangeSet`.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredChangeSet {
    attribution: ChangeSetAttribution,
    state: ChangeSetState,
    timestamps: ChangeSetTimestamps,
    revision: ChangeSetRevision,
    failure_code: Option<FileMutationFailureCode>,
}

impl RegisteredChangeSet {
    pub const fn from_parts(
        attribution: ChangeSetAttribution,
        state: ChangeSetState,
        timestamps: ChangeSetTimestamps,
        revision: ChangeSetRevision,
        failure_code: Option<FileMutationFailureCode>,
    ) -> Self {
        Self {
            attribution,
            state,
            timestamps,
            revision,
            failure_code,
        }
    }

    pub const fn id(&self) -> ChangeSetId {
        self.attribution.id()
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.attribution.workspace_id()
    }

    pub const fn activity_id(&self) -> ActivityId {
        self.attribution.activity_id()
    }

    pub const fn workspace_revision(&self) -> WorkspaceRevision {
        self.attribution.workspace_revision()
    }

    pub const fn runtime_instance_id(&self) -> RuntimeInstanceId {
        self.attribution.runtime_instance_id()
    }

    pub const fn activity_lease_revision(&self) -> ActivityLeaseRevision {
        self.attribution.activity_lease_revision()
    }

    pub const fn state(&self) -> ChangeSetState {
        self.state
    }

    pub const fn created_at(&self) -> TimestampMillis {
        self.timestamps.created_at()
    }

    pub const fn updated_at(&self) -> TimestampMillis {
        self.timestamps.updated_at()
    }

    pub const fn revision(&self) -> ChangeSetRevision {
        self.revision
    }

    pub const fn failure_code(&self) -> Option<FileMutationFailureCode> {
        self.failure_code
    }
}

/// Stable identity linking one mutation to its owning `ChangeSet`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileMutationIdentity {
    change_set_id: ChangeSetId,
    mutation_id: FileMutationId,
}

impl FileMutationIdentity {
    pub const fn new(change_set_id: ChangeSetId, mutation_id: FileMutationId) -> Self {
        Self {
            change_set_id,
            mutation_id,
        }
    }

    pub const fn change_set_id(self) -> ChangeSetId {
        self.change_set_id
    }

    pub const fn mutation_id(self) -> FileMutationId {
        self.mutation_id
    }
}

/// Workspace and live-runtime attribution required before a file effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileMutationScope {
    workspace_id: WorkspaceId,
    expected_workspace_revision: WorkspaceRevision,
    activity_id: ActivityId,
    runtime_instance_id: RuntimeInstanceId,
    activity_lease_revision: ActivityLeaseRevision,
}

impl FileMutationScope {
    pub const fn new(
        workspace_id: WorkspaceId,
        expected_workspace_revision: WorkspaceRevision,
        activity_id: ActivityId,
        runtime_instance_id: RuntimeInstanceId,
        activity_lease_revision: ActivityLeaseRevision,
    ) -> Self {
        Self {
            workspace_id,
            expected_workspace_revision,
            activity_id,
            runtime_instance_id,
            activity_lease_revision,
        }
    }

    pub const fn workspace_id(self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn expected_workspace_revision(self) -> WorkspaceRevision {
        self.expected_workspace_revision
    }

    pub const fn activity_id(self) -> ActivityId {
        self.activity_id
    }

    pub const fn runtime_instance_id(self) -> RuntimeInstanceId {
        self.runtime_instance_id
    }

    pub const fn activity_lease_revision(self) -> ActivityLeaseRevision {
        self.activity_lease_revision
    }
}

/// Path, effect kind, and exact compare-and-set precondition.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FileMutationPlan {
    path: WorkspaceRelativePath,
    kind: FileMutationKind,
    precondition: FilePrecondition,
}

impl FileMutationPlan {
    pub const fn new(
        path: WorkspaceRelativePath,
        kind: FileMutationKind,
        precondition: FilePrecondition,
    ) -> Self {
        Self {
            path,
            kind,
            precondition,
        }
    }

    pub fn path(&self) -> &WorkspaceRelativePath {
        &self.path
    }

    pub const fn kind(&self) -> FileMutationKind {
        self.kind
    }

    pub const fn precondition(&self) -> FilePrecondition {
        self.precondition
    }
}

/// Durable PRE/POST record for one path mutation within a `ChangeSet`.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredFileMutation {
    identity: FileMutationIdentity,
    plan: FileMutationPlan,
    intended_content_hash: Option<FileContentHash>,
    pre_state: FilePathState,
    post_state: Option<FilePathState>,
    revision: FileMutationRevision,
}

impl RegisteredFileMutation {
    pub const fn from_parts(
        identity: FileMutationIdentity,
        plan: FileMutationPlan,
        intended_content_hash: Option<FileContentHash>,
        pre_state: FilePathState,
        post_state: Option<FilePathState>,
        revision: FileMutationRevision,
    ) -> Self {
        Self {
            identity,
            plan,
            intended_content_hash,
            pre_state,
            post_state,
            revision,
        }
    }

    pub const fn id(&self) -> FileMutationId {
        self.identity.mutation_id()
    }

    pub const fn change_set_id(&self) -> ChangeSetId {
        self.identity.change_set_id()
    }

    pub fn path(&self) -> &WorkspaceRelativePath {
        self.plan.path()
    }

    pub const fn kind(&self) -> FileMutationKind {
        self.plan.kind()
    }

    pub const fn precondition(&self) -> FilePrecondition {
        self.plan.precondition()
    }

    pub const fn intended_content_hash(&self) -> Option<FileContentHash> {
        self.intended_content_hash
    }

    pub const fn pre_state(&self) -> FilePathState {
        self.pre_state
    }

    pub const fn post_state(&self) -> Option<FilePathState> {
        self.post_state
    }

    pub const fn revision(&self) -> FileMutationRevision {
        self.revision
    }
}

/// Caller intent persisted before one file side effect starts.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeginFileMutation {
    identity: FileMutationIdentity,
    scope: FileMutationScope,
    plan: FileMutationPlan,
    intended_content_hash: Option<FileContentHash>,
    observed_pre_state: FilePathState,
    observed_at: TimestampMillis,
}

impl BeginFileMutation {
    pub fn new(
        identity: FileMutationIdentity,
        scope: FileMutationScope,
        plan: FileMutationPlan,
        intended_content_hash: Option<FileContentHash>,
        observed_pre_state: FilePathState,
        observed_at: TimestampMillis,
    ) -> Result<Self, BeginFileMutationError> {
        let kind = plan.kind();
        let precondition = plan.precondition();
        let valid = matches!(
            (kind, precondition, observed_pre_state),
            (
                FileMutationKind::Create,
                FilePrecondition::Absent,
                FilePathState::Absent
            ) | (
                FileMutationKind::Replace | FileMutationKind::Delete,
                FilePrecondition::Matches(_),
                FilePathState::Regular { .. }
            )
        );
        if !valid {
            return Err(BeginFileMutationError::InvalidPrecondition);
        }
        if !matches!(
            (kind, intended_content_hash),
            (
                FileMutationKind::Create | FileMutationKind::Replace,
                Some(_)
            ) | (FileMutationKind::Delete, None)
        ) {
            return Err(BeginFileMutationError::InvalidPayload);
        }
        if let (FilePrecondition::Matches(expected), FilePathState::Regular { hash, .. }) =
            (precondition, observed_pre_state)
            && expected != hash
        {
            return Err(BeginFileMutationError::StaleObservation);
        }
        Ok(Self {
            identity,
            scope,
            plan,
            intended_content_hash,
            observed_pre_state,
            observed_at,
        })
    }

    pub const fn change_set_id(&self) -> ChangeSetId {
        self.identity.change_set_id()
    }

    pub const fn mutation_id(&self) -> FileMutationId {
        self.identity.mutation_id()
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.scope.workspace_id()
    }

    pub const fn expected_workspace_revision(&self) -> WorkspaceRevision {
        self.scope.expected_workspace_revision()
    }

    pub const fn activity_id(&self) -> ActivityId {
        self.scope.activity_id()
    }

    pub const fn runtime_instance_id(&self) -> RuntimeInstanceId {
        self.scope.runtime_instance_id()
    }

    pub const fn activity_lease_revision(&self) -> ActivityLeaseRevision {
        self.scope.activity_lease_revision()
    }

    pub fn path(&self) -> &WorkspaceRelativePath {
        self.plan.path()
    }

    pub const fn kind(&self) -> FileMutationKind {
        self.plan.kind()
    }

    pub const fn precondition(&self) -> FilePrecondition {
        self.plan.precondition()
    }

    pub const fn intended_content_hash(&self) -> Option<FileContentHash> {
        self.intended_content_hash
    }

    pub const fn observed_pre_state(&self) -> FilePathState {
        self.observed_pre_state
    }

    pub const fn observed_at(&self) -> TimestampMillis {
        self.observed_at
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum BeginFileMutationError {
    #[error("file mutation kind, precondition, and observed PRE state are incompatible")]
    InvalidPrecondition,
    #[error("file mutation expected hash does not match the observed PRE state")]
    StaleObservation,
    #[error("file mutation content hash does not match its operation")]
    InvalidPayload,
}

/// Compare-and-set completion command after a file effect was observed.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompleteFileMutation {
    identity: FileMutationIdentity,
    expected_change_set_revision: ChangeSetRevision,
    expected_mutation_revision: FileMutationRevision,
    post_state: FilePathState,
    observed_at: TimestampMillis,
}

impl CompleteFileMutation {
    pub const fn new(
        identity: FileMutationIdentity,
        expected_change_set_revision: ChangeSetRevision,
        expected_mutation_revision: FileMutationRevision,
        post_state: FilePathState,
        observed_at: TimestampMillis,
    ) -> Self {
        Self {
            identity,
            expected_change_set_revision,
            expected_mutation_revision,
            post_state,
            observed_at,
        }
    }

    pub const fn identity(self) -> FileMutationIdentity {
        self.identity
    }

    pub const fn expected_change_set_revision(self) -> ChangeSetRevision {
        self.expected_change_set_revision
    }

    pub const fn expected_mutation_revision(self) -> FileMutationRevision {
        self.expected_mutation_revision
    }

    pub const fn post_state(self) -> FilePathState {
        self.post_state
    }

    pub const fn observed_at(self) -> TimestampMillis {
        self.observed_at
    }
}

/// Compare-and-set terminal command used only for a definitely uncommitted
/// filesystem effect. Uncertain outcomes must remain `Starting`.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FailFileMutation {
    identity: FileMutationIdentity,
    expected_change_set_revision: ChangeSetRevision,
    expected_mutation_revision: FileMutationRevision,
    failure_code: FileMutationFailureCode,
    observed_at: TimestampMillis,
}

impl FailFileMutation {
    pub const fn new(
        identity: FileMutationIdentity,
        expected_change_set_revision: ChangeSetRevision,
        expected_mutation_revision: FileMutationRevision,
        failure_code: FileMutationFailureCode,
        observed_at: TimestampMillis,
    ) -> Self {
        Self {
            identity,
            expected_change_set_revision,
            expected_mutation_revision,
            failure_code,
            observed_at,
        }
    }

    pub const fn identity(self) -> FileMutationIdentity {
        self.identity
    }

    pub const fn expected_change_set_revision(self) -> ChangeSetRevision {
        self.expected_change_set_revision
    }

    pub const fn expected_mutation_revision(self) -> FileMutationRevision {
        self.expected_mutation_revision
    }

    pub const fn failure_code(self) -> FileMutationFailureCode {
        self.failure_code
    }

    pub const fn observed_at(self) -> TimestampMillis {
        self.observed_at
    }
}

/// One durable `ChangeSet` and its single V1 path mutation.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileMutationRecord {
    change_set: RegisteredChangeSet,
    mutation: RegisteredFileMutation,
}

/// Idempotent durable-intent outcome for one mutation identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BeginFileMutationStatus {
    Started,
    AlreadyApplied,
    RecoveryRequired,
    TerminalFailed,
}

/// Durable intent plus its retry/recovery classification.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeginFileMutationResult {
    record: FileMutationRecord,
    status: BeginFileMutationStatus,
}

impl BeginFileMutationResult {
    pub const fn new(record: FileMutationRecord, status: BeginFileMutationStatus) -> Self {
        Self { record, status }
    }

    pub const fn record(&self) -> &FileMutationRecord {
        &self.record
    }

    pub const fn status(&self) -> BeginFileMutationStatus {
        self.status
    }
}

impl FileMutationRecord {
    pub const fn new(change_set: RegisteredChangeSet, mutation: RegisteredFileMutation) -> Self {
        Self {
            change_set,
            mutation,
        }
    }

    pub const fn change_set(&self) -> &RegisteredChangeSet {
        &self.change_set
    }

    pub const fn mutation(&self) -> &RegisteredFileMutation {
        &self.mutation
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::str::FromStr;

    use uuid::Uuid;

    use super::*;

    fn hash(fill: u8) -> FileContentHash {
        FileContentHash::from_bytes([fill; FileContentHash::BYTE_LEN])
    }

    #[test]
    fn content_hash_round_trips_only_canonical_lower_hex() -> Result<(), Box<dyn std::error::Error>>
    {
        let original = hash(0xab);
        let encoded = original.to_string();
        assert_eq!(encoded.len(), FileContentHash::ENCODED_LEN);
        assert_eq!(FileContentHash::from_str(&encoded)?, original);
        assert!(FileContentHash::from_str(&encoded.to_uppercase()).is_err());
        assert!(FileContentHash::from_str("00").is_err());
        Ok(())
    }

    #[test]
    fn workspace_relative_path_rejects_escape_and_noncanonical_forms()
    -> Result<(), Box<dyn std::error::Error>> {
        let valid = WorkspaceRelativePath::new(PathBuf::from("src/lib.rs"))?;
        assert_eq!(valid.as_path(), Path::new("src/lib.rs"));
        for invalid in ["", "/tmp/x", "../x", "src/../x", "./x", "src//lib.rs", "x/"] {
            assert!(
                WorkspaceRelativePath::new(PathBuf::from(invalid)).is_err(),
                "{invalid}"
            );
        }
        Ok(())
    }

    #[test]
    fn begin_mutation_requires_kind_specific_precondition_and_matching_pre_state()
    -> Result<(), Box<dyn std::error::Error>> {
        let path = WorkspaceRelativePath::new(PathBuf::from("src/lib.rs"))?;
        let identity = FileMutationIdentity::new(
            ChangeSetId::from_uuid(Uuid::from_u128(1)),
            FileMutationId::from_uuid(Uuid::from_u128(2)),
        );
        let scope = FileMutationScope::new(
            WorkspaceId::from_uuid(Uuid::from_u128(3)),
            WorkspaceRevision::INITIAL,
            ActivityId::from_uuid(Uuid::from_u128(4)),
            RuntimeInstanceId::from_uuid(Uuid::from_u128(5)),
            ActivityLeaseRevision::INITIAL,
        );
        let observed_at = TimestampMillis::new(1)?;
        let create = BeginFileMutation::new(
            identity,
            scope,
            FileMutationPlan::new(
                path.clone(),
                FileMutationKind::Create,
                FilePrecondition::Absent,
            ),
            Some(hash(3)),
            FilePathState::Absent,
            observed_at,
        )?;
        assert_eq!(create.kind(), FileMutationKind::Create);

        assert!(matches!(
            BeginFileMutation::new(
                identity,
                scope,
                FileMutationPlan::new(
                    path.clone(),
                    FileMutationKind::Replace,
                    FilePrecondition::Matches(hash(1)),
                ),
                Some(hash(3)),
                FilePathState::Regular {
                    hash: hash(2),
                    size: FileByteCount::new(1),
                },
                observed_at,
            ),
            Err(BeginFileMutationError::StaleObservation)
        ));
        assert!(matches!(
            BeginFileMutation::new(
                identity,
                scope,
                FileMutationPlan::new(path, FileMutationKind::Delete, FilePrecondition::Absent,),
                None,
                FilePathState::Absent,
                observed_at,
            ),
            Err(BeginFileMutationError::InvalidPrecondition)
        ));
        Ok(())
    }
}
