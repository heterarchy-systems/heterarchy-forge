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
        for (index, pair) in bytes.as_chunks::<2>().0.iter().enumerate() {
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

/// Maximum entries returned from one bounded directory listing.
pub const MAX_FILE_LIST_RESULTS: usize = 512;
/// Maximum serialized bytes retained by one bounded directory listing.
pub const MAX_FILE_LIST_OUTPUT_BYTES: usize = 64 * 1024;
/// Maximum recursive directory entries visited by one literal source search.
pub const MAX_TEXT_SEARCH_SCAN_ENTRIES: usize = 16 * 1024;
/// Maximum matches returned from one literal source search.
pub const MAX_TEXT_SEARCH_RESULTS: usize = 256;
/// Maximum serialized bytes retained by one literal source search.
pub const MAX_TEXT_SEARCH_OUTPUT_BYTES: usize = 64 * 1024;
/// Maximum literal search query bytes.
pub const MAX_TEXT_SEARCH_QUERY_BYTES: usize = 4 * 1024;
/// Maximum bytes retained in one source slice response.
pub const MAX_SOURCE_SLICE_BYTES: usize = 128 * 1024;
/// Maximum source bytes scanned by one source slice operation.
pub const MAX_SOURCE_SLICE_SCAN_BYTES: usize = 64 * 1024 * 1024;
/// Maximum number of line hunks accepted by one source patch.
pub const MAX_SOURCE_PATCH_HUNKS: usize = 128;
/// Maximum source bytes accepted by one compiled source patch.
pub const MAX_SOURCE_PATCH_BYTES: usize = 1024 * 1024;
/// Maximum search preview bytes returned for one matching line.
pub const MAX_TEXT_SEARCH_PREVIEW_BYTES: usize = 512;

/// A half-open byte span within one source snapshot.
///
/// Source line spans include their line ending when one is present.  The same
/// value type also describes the corresponding half-open range in compiled
/// output, so callers can link validated source bytes to their result bytes
/// without retaining the source text.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourceByteSpan {
    start: usize,
    end: usize,
}

impl SourceByteSpan {
    const fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    pub const fn start(self) -> usize {
        self.start
    }

    pub const fn end(self) -> usize {
        self.end
    }

    pub const fn len(self) -> usize {
        self.end - self.start
    }

    pub const fn is_empty(self) -> bool {
        self.start == self.end
    }
}

/// A validated one-based inclusive source line range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourceLineRange {
    start_line: u64,
    end_line: u64,
}

impl SourceLineRange {
    pub const fn new(start_line: u64, end_line: u64) -> Result<Self, SourceLineRangeError> {
        if start_line == 0 {
            return Err(SourceLineRangeError::ZeroStart);
        }
        if end_line < start_line {
            return Err(SourceLineRangeError::Reversed {
                start_line,
                end_line,
            });
        }
        Ok(Self {
            start_line,
            end_line,
        })
    }

    pub const fn start_line(self) -> u64 {
        self.start_line
    }

    pub const fn end_line(self) -> u64 {
        self.end_line
    }

    pub const fn line_count(self) -> u64 {
        self.end_line - self.start_line + 1
    }

    pub const fn contains(self, line: u64) -> bool {
        line >= self.start_line && line <= self.end_line
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum SourceLineRangeError {
    #[error("source line range start must be at least 1")]
    ZeroStart,
    #[error("source line range is reversed: {start_line}..={end_line}")]
    Reversed { start_line: u64, end_line: u64 },
}

/// Digest of exactly one source range, kept distinct from a whole-file hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SourceRangeHash([u8; 32]);

impl SourceRangeHash {
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

impl fmt::Display for SourceRangeHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(Self::ALGORITHM)?;
        formatter.write_str(":")?;
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for SourceRangeHash {
    type Err = SourceRangeHashParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != Self::ENCODED_LEN {
            return Err(SourceRangeHashParseError::InvalidLength {
                actual: value.len(),
            });
        }
        let Some(hex) = value.strip_prefix("blake3-256:") else {
            return Err(SourceRangeHashParseError::InvalidAlgorithm);
        };
        let mut decoded = [0_u8; Self::BYTE_LEN];
        for (index, pair) in hex.as_bytes().as_chunks::<2>().0.iter().enumerate() {
            let high = decode_lower_hex(pair[0])
                .map_err(|_| SourceRangeHashParseError::InvalidEncoding)?;
            let low = decode_lower_hex(pair[1])
                .map_err(|_| SourceRangeHashParseError::InvalidEncoding)?;
            decoded[index] = (high << 4) | low;
        }
        Ok(Self(decoded))
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum SourceRangeHashParseError {
    #[error("source range hash has {actual} encoded bytes; expected 75")]
    InvalidLength { actual: usize },
    #[error("source range hash algorithm must be blake3-256")]
    InvalidAlgorithm,
    #[error("source range hash must use canonical lower hexadecimal")]
    InvalidEncoding,
}

/// EOL convention observed across a source file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SourceEol {
    Lf,
    CrLf,
    Cr,
    Mixed,
    None,
}

/// A bounded entry returned by one directory listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileListEntry {
    path: WorkspaceRelativePath,
    kind: FileEntryKind,
    size: Option<FileByteCount>,
}

impl FileListEntry {
    pub const fn new(
        path: WorkspaceRelativePath,
        kind: FileEntryKind,
        size: Option<FileByteCount>,
    ) -> Self {
        Self { path, kind, size }
    }

    pub fn path(&self) -> &WorkspaceRelativePath {
        &self.path
    }

    pub const fn kind(&self) -> FileEntryKind {
        self.kind
    }

    pub const fn size(&self) -> Option<FileByteCount> {
        self.size
    }
}

/// File-system object classification from a no-follow metadata observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileEntryKind {
    Directory,
    RegularFile,
    SymbolicLink,
    Other,
}

/// Bounds for one directory listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileListOptions {
    max_results: usize,
    max_output_bytes: usize,
}

impl FileListOptions {
    pub const fn new(
        max_results: usize,
        max_output_bytes: usize,
    ) -> Result<Self, FileListOptionsError> {
        if max_results == 0 || max_results > MAX_FILE_LIST_RESULTS {
            return Err(FileListOptionsError::InvalidResultBound {
                actual: max_results,
                maximum: MAX_FILE_LIST_RESULTS,
            });
        }
        if max_output_bytes == 0 || max_output_bytes > MAX_FILE_LIST_OUTPUT_BYTES {
            return Err(FileListOptionsError::InvalidOutputBound {
                actual: max_output_bytes,
                maximum: MAX_FILE_LIST_OUTPUT_BYTES,
            });
        }
        Ok(Self {
            max_results,
            max_output_bytes,
        })
    }

    pub const fn max_results(self) -> usize {
        self.max_results
    }

    pub const fn max_output_bytes(self) -> usize {
        self.max_output_bytes
    }
}

impl Default for FileListOptions {
    fn default() -> Self {
        Self {
            max_results: MAX_FILE_LIST_RESULTS,
            max_output_bytes: MAX_FILE_LIST_OUTPUT_BYTES,
        }
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum FileListOptionsError {
    #[error("file-list result bound must be between 1 and {maximum}, got {actual}")]
    InvalidResultBound { actual: usize, maximum: usize },
    #[error("file-list output bound must be between 1 and {maximum}, got {actual}")]
    InvalidOutputBound { actual: usize, maximum: usize },
}

/// One bounded directory listing. `truncated` is true whenever a scan or
/// result/output bound prevented a complete listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileListResult {
    directory: Option<WorkspaceRelativePath>,
    entries: Vec<FileListEntry>,
    scanned_entries: usize,
    truncated: bool,
}

impl FileListResult {
    pub fn new(
        directory: Option<WorkspaceRelativePath>,
        entries: Vec<FileListEntry>,
        scanned_entries: usize,
        truncated: bool,
    ) -> Result<Self, FileListResultError> {
        if entries.len() > MAX_FILE_LIST_RESULTS {
            return Err(FileListResultError::TooManyResults {
                actual: entries.len(),
                maximum: MAX_FILE_LIST_RESULTS,
            });
        }
        Ok(Self {
            directory,
            entries,
            scanned_entries,
            truncated,
        })
    }

    pub fn directory(&self) -> Option<&WorkspaceRelativePath> {
        self.directory.as_ref()
    }

    pub fn entries(&self) -> &[FileListEntry] {
        &self.entries
    }

    pub const fn scanned_entries(&self) -> usize {
        self.scanned_entries
    }

    pub const fn truncated(&self) -> bool {
        self.truncated
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum FileListResultError {
    #[error("file-list result has {actual} entries; maximum is {maximum}")]
    TooManyResults { actual: usize, maximum: usize },
}

/// Validated literal query for recursive source search.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TextSearchQuery(String);

impl TextSearchQuery {
    pub fn new(value: String) -> Result<Self, TextSearchQueryError> {
        let bytes = value.as_bytes();
        if bytes.is_empty() {
            return Err(TextSearchQueryError::Empty);
        }
        if bytes.len() > MAX_TEXT_SEARCH_QUERY_BYTES {
            return Err(TextSearchQueryError::TooLong {
                actual: bytes.len(),
                maximum: MAX_TEXT_SEARCH_QUERY_BYTES,
            });
        }
        if bytes.contains(&0) {
            return Err(TextSearchQueryError::ContainsNul);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum TextSearchQueryError {
    #[error("text-search query is empty")]
    Empty,
    #[error("text-search query has {actual} bytes; maximum is {maximum}")]
    TooLong { actual: usize, maximum: usize },
    #[error("text-search query contains a NUL byte")]
    ContainsNul,
}

/// Bounds for one recursive literal source search.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TextSearchOptions {
    max_results: usize,
    max_output_bytes: usize,
}

impl TextSearchOptions {
    pub const fn new(
        max_results: usize,
        max_output_bytes: usize,
    ) -> Result<Self, TextSearchOptionsError> {
        if max_results == 0 || max_results > MAX_TEXT_SEARCH_RESULTS {
            return Err(TextSearchOptionsError::InvalidResultBound {
                actual: max_results,
                maximum: MAX_TEXT_SEARCH_RESULTS,
            });
        }
        if max_output_bytes == 0 || max_output_bytes > MAX_TEXT_SEARCH_OUTPUT_BYTES {
            return Err(TextSearchOptionsError::InvalidOutputBound {
                actual: max_output_bytes,
                maximum: MAX_TEXT_SEARCH_OUTPUT_BYTES,
            });
        }
        Ok(Self {
            max_results,
            max_output_bytes,
        })
    }

    pub const fn max_results(self) -> usize {
        self.max_results
    }

    pub const fn max_output_bytes(self) -> usize {
        self.max_output_bytes
    }
}

impl Default for TextSearchOptions {
    fn default() -> Self {
        Self {
            max_results: MAX_TEXT_SEARCH_RESULTS,
            max_output_bytes: MAX_TEXT_SEARCH_OUTPUT_BYTES,
        }
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum TextSearchOptionsError {
    #[error("text-search result bound must be between 1 and {maximum}, got {actual}")]
    InvalidResultBound { actual: usize, maximum: usize },
    #[error("text-search output bound must be between 1 and {maximum}, got {actual}")]
    InvalidOutputBound { actual: usize, maximum: usize },
}

/// One literal source-search hit. `preview` is bounded and never includes a
/// full unbounded source line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextSearchMatch {
    path: WorkspaceRelativePath,
    line: u64,
    preview: String,
}

impl TextSearchMatch {
    pub fn new(
        path: WorkspaceRelativePath,
        line: u64,
        preview: String,
    ) -> Result<Self, TextSearchMatchError> {
        if line == 0 {
            return Err(TextSearchMatchError::ZeroLine);
        }
        if preview.len() > MAX_TEXT_SEARCH_PREVIEW_BYTES {
            return Err(TextSearchMatchError::PreviewTooLong {
                actual: preview.len(),
                maximum: MAX_TEXT_SEARCH_PREVIEW_BYTES,
            });
        }
        Ok(Self {
            path,
            line,
            preview,
        })
    }

    pub fn path(&self) -> &WorkspaceRelativePath {
        &self.path
    }

    pub const fn line(&self) -> u64 {
        self.line
    }

    pub fn preview(&self) -> &str {
        &self.preview
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TextSearchMatchError {
    #[error("text-search match line must be at least 1")]
    ZeroLine,
    #[error("text-search preview has {actual} bytes; maximum is {maximum}")]
    PreviewTooLong { actual: usize, maximum: usize },
}

/// Bounded recursive literal search result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextSearchResult {
    root: Option<WorkspaceRelativePath>,
    matches: Vec<TextSearchMatch>,
    scanned_entries: usize,
    scanned_files: usize,
    truncated: bool,
}

impl TextSearchResult {
    pub fn new(
        root: Option<WorkspaceRelativePath>,
        matches: Vec<TextSearchMatch>,
        scanned_entries: usize,
        scanned_files: usize,
        truncated: bool,
    ) -> Result<Self, TextSearchResultError> {
        if matches.len() > MAX_TEXT_SEARCH_RESULTS {
            return Err(TextSearchResultError::TooManyResults {
                actual: matches.len(),
                maximum: MAX_TEXT_SEARCH_RESULTS,
            });
        }
        Ok(Self {
            root,
            matches,
            scanned_entries,
            scanned_files,
            truncated,
        })
    }

    pub fn root(&self) -> Option<&WorkspaceRelativePath> {
        self.root.as_ref()
    }

    pub fn matches(&self) -> &[TextSearchMatch] {
        &self.matches
    }

    pub const fn scanned_entries(&self) -> usize {
        self.scanned_entries
    }

    pub const fn scanned_files(&self) -> usize {
        self.scanned_files
    }

    pub const fn truncated(&self) -> bool {
        self.truncated
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum TextSearchResultError {
    #[error("text-search result has {actual} matches; maximum is {maximum}")]
    TooManyResults { actual: usize, maximum: usize },
}

/// A bounded source patch hunk replacing one inclusive line range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilePatchHunk {
    range: SourceLineRange,
    expected_range_hash: SourceRangeHash,
    replacement: Vec<u8>,
}

impl FilePatchHunk {
    pub fn new(
        range: SourceLineRange,
        expected_range_hash: SourceRangeHash,
        replacement: Vec<u8>,
    ) -> Result<Self, FilePatchError> {
        if replacement.len() > MAX_SOURCE_PATCH_BYTES {
            return Err(FilePatchError::ReplacementTooLarge {
                actual: replacement.len(),
                maximum: MAX_SOURCE_PATCH_BYTES,
            });
        }
        if replacement.contains(&0) {
            return Err(FilePatchError::BinaryReplacement);
        }
        std::str::from_utf8(&replacement).map_err(|_| FilePatchError::NonUtf8Replacement)?;
        Ok(Self {
            range,
            expected_range_hash,
            replacement,
        })
    }

    pub const fn range(&self) -> SourceLineRange {
        self.range
    }

    pub const fn expected_range_hash(&self) -> SourceRangeHash {
        self.expected_range_hash
    }

    pub fn replacement(&self) -> &[u8] {
        &self.replacement
    }
}

/// Exact whole-file-hash and ordered line-hunk patch contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilePatch {
    expected_whole_file_hash: FileContentHash,
    hunks: Vec<FilePatchHunk>,
}

impl FilePatch {
    pub fn new(
        expected_whole_file_hash: FileContentHash,
        hunks: Vec<FilePatchHunk>,
    ) -> Result<Self, FilePatchError> {
        if hunks.is_empty() {
            return Err(FilePatchError::NoHunks);
        }
        if hunks.len() > MAX_SOURCE_PATCH_HUNKS {
            return Err(FilePatchError::TooManyHunks {
                actual: hunks.len(),
                maximum: MAX_SOURCE_PATCH_HUNKS,
            });
        }
        let replacement_bytes = hunks.iter().try_fold(0_usize, |total, hunk| {
            total
                .checked_add(hunk.replacement.len())
                .ok_or(FilePatchError::PatchPayloadTooLarge {
                    actual: usize::MAX,
                    maximum: MAX_SOURCE_PATCH_BYTES,
                })
        })?;
        if replacement_bytes > MAX_SOURCE_PATCH_BYTES {
            return Err(FilePatchError::PatchPayloadTooLarge {
                actual: replacement_bytes,
                maximum: MAX_SOURCE_PATCH_BYTES,
            });
        }
        for pair in hunks.windows(2) {
            let previous = pair[0].range;
            let next = pair[1].range;
            if next.start_line <= previous.end_line {
                return Err(FilePatchError::HunksOverlap {
                    previous_end: previous.end_line,
                    next_start: next.start_line,
                });
            }
        }
        Ok(Self {
            expected_whole_file_hash,
            hunks,
        })
    }

    pub const fn expected_whole_file_hash(&self) -> FileContentHash {
        self.expected_whole_file_hash
    }

    pub fn hunks(&self) -> &[FilePatchHunk] {
        &self.hunks
    }

    /// Compile against one bounded source snapshot. This is pure and performs
    /// no filesystem or persistence effects; adapters own atomic publication.
    pub fn compile(&self, source: &[u8]) -> Result<CompiledFilePatch, FilePatchError> {
        if source.len() > MAX_SOURCE_PATCH_BYTES {
            return Err(FilePatchError::SourceTooLarge {
                actual: source.len(),
                maximum: MAX_SOURCE_PATCH_BYTES,
            });
        }
        if source.contains(&0) {
            return Err(FilePatchError::BinarySource);
        }
        std::str::from_utf8(source).map_err(|_| FilePatchError::NonUtf8Source)?;
        let actual_whole_hash = FileContentHash::from_bytes(*blake3::hash(source).as_bytes());
        if actual_whole_hash != self.expected_whole_file_hash {
            return Err(FilePatchError::StaleWholeFileHash);
        }
        let lines = source_lines(source);
        if lines.is_empty() {
            return Err(FilePatchError::SourceHasNoLines);
        }
        let mut output = Vec::with_capacity(source.len());
        let mut hunk_geometry = Vec::with_capacity(self.hunks.len());
        let mut source_cursor = 0_usize;
        for (hunk_index, hunk) in self.hunks.iter().enumerate() {
            let start = usize::try_from(hunk.range.start_line - 1)
                .map_err(|_| FilePatchError::LineRangeTooLarge { hunk: hunk_index })?;
            let end = usize::try_from(hunk.range.end_line)
                .map_err(|_| FilePatchError::LineRangeTooLarge { hunk: hunk_index })?;
            if end > lines.len() {
                return Err(FilePatchError::HunkOutOfBounds {
                    hunk: hunk_index,
                    total_lines: lines.len() as u64,
                });
            }
            let range_start = lines[start].start();
            let range_end = lines[end - 1].end();
            let range_bytes = &source[range_start..range_end];
            let actual_range_hash =
                SourceRangeHash::from_bytes(*blake3::hash(range_bytes).as_bytes());
            if actual_range_hash != hunk.expected_range_hash {
                return Err(FilePatchError::StaleRangeHash { hunk: hunk_index });
            }
            output.extend_from_slice(&source[source_cursor..range_start]);
            let result_start = output.len();
            output.extend_from_slice(&hunk.replacement);
            if output.len() > MAX_SOURCE_PATCH_BYTES {
                return Err(FilePatchError::OutputTooLarge {
                    actual: output.len(),
                    maximum: MAX_SOURCE_PATCH_BYTES,
                });
            }
            hunk_geometry.push(CompiledFilePatchHunk {
                ordinal: hunk_index,
                source_span: SourceByteSpan::new(range_start, range_end),
                result_span: SourceByteSpan::new(result_start, output.len()),
            });
            source_cursor = range_end;
        }
        output.extend_from_slice(&source[source_cursor..]);
        if output.len() > MAX_SOURCE_PATCH_BYTES {
            return Err(FilePatchError::OutputTooLarge {
                actual: output.len(),
                maximum: MAX_SOURCE_PATCH_BYTES,
            });
        }
        let result_hash = FileContentHash::from_bytes(*blake3::hash(&output).as_bytes());
        Ok(CompiledFilePatch {
            source_hash: actual_whole_hash,
            result_hash,
            content: output,
            hunk_geometry,
        })
    }
}

/// Validated source-to-result byte geometry for one compiled patch hunk.
///
/// `source_span` addresses the bytes that passed the hunk range hash check.
/// `result_span` addresses the replacement bytes in the final compiled
/// content.  A deletion therefore has an empty result span.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompiledFilePatchHunk {
    ordinal: usize,
    source_span: SourceByteSpan,
    result_span: SourceByteSpan,
}

impl CompiledFilePatchHunk {
    pub const fn ordinal(self) -> usize {
        self.ordinal
    }

    pub const fn source_span(self) -> SourceByteSpan {
        self.source_span
    }

    pub const fn result_span(self) -> SourceByteSpan {
        self.result_span
    }
}

/// Materialized bounded output from a validated [`FilePatch`].
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledFilePatch {
    source_hash: FileContentHash,
    result_hash: FileContentHash,
    content: Vec<u8>,
    hunk_geometry: Vec<CompiledFilePatchHunk>,
}

impl CompiledFilePatch {
    pub const fn source_hash(&self) -> FileContentHash {
        self.source_hash
    }

    pub const fn result_hash(&self) -> FileContentHash {
        self.result_hash
    }

    pub fn content(&self) -> &[u8] {
        &self.content
    }

    pub fn hunk_geometry(&self) -> &[CompiledFilePatchHunk] {
        &self.hunk_geometry
    }

    pub fn into_content(self) -> Vec<u8> {
        self.content
    }
}

/// Metadata and exact bytes for one bounded line slice.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileReadSlice {
    whole_file_hash: FileContentHash,
    range_hash: SourceRangeHash,
    line_range: SourceLineRange,
    total_lines: u64,
    content: Vec<u8>,
    line_hashes: Vec<SourceRangeHash>,
    eol: SourceEol,
    has_final_newline: bool,
}

/// Source metadata that describes one bounded line slice.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileReadSliceMetadata {
    whole_file_hash: FileContentHash,
    range_hash: SourceRangeHash,
    line_range: SourceLineRange,
    total_lines: u64,
    eol: SourceEol,
    has_final_newline: bool,
}

impl FileReadSliceMetadata {
    pub const fn new(
        whole_file_hash: FileContentHash,
        range_hash: SourceRangeHash,
        line_range: SourceLineRange,
        total_lines: u64,
        eol: SourceEol,
        has_final_newline: bool,
    ) -> Self {
        Self {
            whole_file_hash,
            range_hash,
            line_range,
            total_lines,
            eol,
            has_final_newline,
        }
    }
}

impl FileReadSlice {
    pub fn from_parts(
        metadata: FileReadSliceMetadata,
        content: Vec<u8>,
        line_hashes: Vec<SourceRangeHash>,
    ) -> Result<Self, FileReadSliceError> {
        if metadata.total_lines < metadata.line_range.end_line {
            return Err(FileReadSliceError::RangeOutOfBounds {
                end_line: metadata.line_range.end_line,
                total_lines: metadata.total_lines,
            });
        }
        if content.len() > MAX_SOURCE_SLICE_BYTES {
            return Err(FileReadSliceError::OutputTooLarge {
                actual: content.len(),
                maximum: MAX_SOURCE_SLICE_BYTES,
            });
        }
        let expected_line_count = usize::try_from(metadata.line_range.line_count())
            .map_err(|_| FileReadSliceError::TooManyLines)?;
        if line_hashes.len() != expected_line_count {
            return Err(FileReadSliceError::LineHashCountMismatch {
                actual: line_hashes.len(),
                expected: expected_line_count,
            });
        }
        let actual_range_hash = SourceRangeHash::from_bytes(*blake3::hash(&content).as_bytes());
        if actual_range_hash != metadata.range_hash {
            return Err(FileReadSliceError::RangeHashMismatch);
        }
        Ok(Self {
            whole_file_hash: metadata.whole_file_hash,
            range_hash: metadata.range_hash,
            line_range: metadata.line_range,
            total_lines: metadata.total_lines,
            content,
            line_hashes,
            eol: metadata.eol,
            has_final_newline: metadata.has_final_newline,
        })
    }

    pub const fn whole_file_hash(&self) -> FileContentHash {
        self.whole_file_hash
    }

    pub const fn range_hash(&self) -> SourceRangeHash {
        self.range_hash
    }

    pub const fn line_range(&self) -> SourceLineRange {
        self.line_range
    }

    pub const fn start_line(&self) -> u64 {
        self.line_range.start_line
    }

    pub const fn end_line(&self) -> u64 {
        self.line_range.end_line
    }

    pub const fn total_lines(&self) -> u64 {
        self.total_lines
    }

    pub fn content(&self) -> &[u8] {
        &self.content
    }

    pub fn line_hashes(&self) -> &[SourceRangeHash] {
        &self.line_hashes
    }

    pub const fn eol(&self) -> SourceEol {
        self.eol
    }

    pub const fn has_final_newline(&self) -> bool {
        self.has_final_newline
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum FileReadSliceError {
    #[error("source slice end line {end_line} exceeds total line count {total_lines}")]
    RangeOutOfBounds { end_line: u64, total_lines: u64 },
    #[error("source slice output has {actual} bytes; maximum is {maximum}")]
    OutputTooLarge { actual: usize, maximum: usize },
    #[error("source slice has too many requested lines")]
    TooManyLines,
    #[error("source slice has {actual} line hashes; expected {expected}")]
    LineHashCountMismatch { actual: usize, expected: usize },
    #[error("source slice range hash does not match its selected bytes")]
    RangeHashMismatch,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum FilePatchError {
    #[error("source patch must contain at least one hunk")]
    NoHunks,
    #[error("source patch has {actual} hunks; maximum is {maximum}")]
    TooManyHunks { actual: usize, maximum: usize },
    #[error(
        "source patch hunks overlap or are not strictly ordered: previous end {previous_end}, next start {next_start}"
    )]
    HunksOverlap { previous_end: u64, next_start: u64 },
    #[error("source patch replacement has {actual} bytes; maximum is {maximum}")]
    ReplacementTooLarge { actual: usize, maximum: usize },
    #[error("source patch payload has {actual} bytes; maximum is {maximum}")]
    PatchPayloadTooLarge { actual: usize, maximum: usize },
    #[error("source patch replacement contains a NUL byte")]
    BinaryReplacement,
    #[error("source patch replacement is not valid UTF-8")]
    NonUtf8Replacement,
    #[error("source file has {actual} bytes; maximum is {maximum}")]
    SourceTooLarge { actual: usize, maximum: usize },
    #[error("source file contains binary NUL data")]
    BinarySource,
    #[error("source file is not valid UTF-8")]
    NonUtf8Source,
    #[error("source file hash does not match expected whole-file hash")]
    StaleWholeFileHash,
    #[error("source patch hunk {hunk} has a stale range hash")]
    StaleRangeHash { hunk: usize },
    #[error("source patch hunk {hunk} line range exceeds source")]
    HunkOutOfBounds { hunk: usize, total_lines: u64 },
    #[error("source patch hunk {hunk} line range cannot be represented")]
    LineRangeTooLarge { hunk: usize },
    #[error("source file has no addressable lines")]
    SourceHasNoLines,
    #[error("compiled source patch has {actual} bytes; maximum is {maximum}")]
    OutputTooLarge { actual: usize, maximum: usize },
}

struct SourceLineSpanIter<'a> {
    source: &'a [u8],
    cursor: usize,
}

impl Iterator for SourceLineSpanIter<'_> {
    type Item = SourceByteSpan;

    fn next(&mut self) -> Option<Self::Item> {
        if self.cursor >= self.source.len() {
            return None;
        }

        let start = self.cursor;
        while self.cursor < self.source.len() {
            let index = self.cursor;
            match self.source[index] {
                b'\n' => {
                    self.cursor = index + 1;
                    return Some(SourceByteSpan::new(start, self.cursor));
                }
                b'\r' => {
                    self.cursor = index + 1;
                    if self.source.get(self.cursor) == Some(&b'\n') {
                        self.cursor += 1;
                    }
                    return Some(SourceByteSpan::new(start, self.cursor));
                }
                _ => self.cursor += 1,
            }
        }

        Some(SourceByteSpan::new(start, self.source.len()))
    }
}

/// Iterate over source lines as half-open byte spans without allocating.
///
/// Each span includes its LF, CRLF, or lone CR delimiter. A source ending in
/// a delimiter has no synthetic empty line after that delimiter.
#[must_use = "consume the source-line iterator"]
pub fn source_line_spans(source: &[u8]) -> impl Iterator<Item = SourceByteSpan> + '_ {
    SourceLineSpanIter { source, cursor: 0 }
}

fn source_lines(source: &[u8]) -> Vec<SourceByteSpan> {
    source_line_spans(source).collect()
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

    #[test]
    fn source_patch_compiles_ordered_hunks_with_distinct_range_hashes()
    -> Result<(), Box<dyn std::error::Error>> {
        let source = b"one\ntwo\nthree\n";
        let whole_hash = FileContentHash::from_bytes(*blake3::hash(source).as_bytes());
        let second_line = SourceRangeHash::from_bytes(*blake3::hash(b"two\n").as_bytes());
        let patch = FilePatch::new(
            whole_hash,
            vec![FilePatchHunk::new(
                SourceLineRange::new(2, 2)?,
                second_line,
                b"TWO\n".to_vec(),
            )?],
        )?;
        let compiled = patch.compile(source)?;
        assert_eq!(compiled.content(), b"one\nTWO\nthree\n");
        assert_eq!(compiled.source_hash(), whole_hash);
        assert_ne!(compiled.result_hash(), whole_hash);
        assert_eq!(compiled.hunk_geometry().len(), 1);
        let geometry = compiled.hunk_geometry()[0];
        assert_eq!(geometry.ordinal(), 0);
        assert_eq!(geometry.source_span(), SourceByteSpan::new(4, 8));
        assert_eq!(geometry.result_span(), SourceByteSpan::new(4, 8));
        Ok(())
    }

    #[test]
    fn source_patch_geometry_tracks_multiple_hunks_in_final_output()
    -> Result<(), Box<dyn std::error::Error>> {
        let source = b"one\ntwo\nthree\nfour\n";
        let patch = FilePatch::new(
            FileContentHash::from_bytes(*blake3::hash(source).as_bytes()),
            vec![
                FilePatchHunk::new(
                    SourceLineRange::new(1, 1)?,
                    SourceRangeHash::from_bytes(*blake3::hash(b"one\n").as_bytes()),
                    b"ONE\n".to_vec(),
                )?,
                FilePatchHunk::new(
                    SourceLineRange::new(3, 3)?,
                    SourceRangeHash::from_bytes(*blake3::hash(b"three\n").as_bytes()),
                    b"3\n".to_vec(),
                )?,
            ],
        )?;

        let compiled = patch.compile(source)?;
        assert_eq!(compiled.content(), b"ONE\ntwo\n3\nfour\n");
        assert_eq!(
            compiled.hunk_geometry(),
            &[
                CompiledFilePatchHunk {
                    ordinal: 0,
                    source_span: SourceByteSpan::new(0, 4),
                    result_span: SourceByteSpan::new(0, 4),
                },
                CompiledFilePatchHunk {
                    ordinal: 1,
                    source_span: SourceByteSpan::new(8, 14),
                    result_span: SourceByteSpan::new(8, 10),
                },
            ]
        );
        Ok(())
    }

    #[test]
    fn source_patch_geometry_tracks_suffix_join_without_newline()
    -> Result<(), Box<dyn std::error::Error>> {
        let source = b"one\ntwo\n";
        let patch = FilePatch::new(
            FileContentHash::from_bytes(*blake3::hash(source).as_bytes()),
            vec![FilePatchHunk::new(
                SourceLineRange::new(1, 1)?,
                SourceRangeHash::from_bytes(*blake3::hash(b"one\n").as_bytes()),
                b"ONE".to_vec(),
            )?],
        )?;

        let compiled = patch.compile(source)?;
        assert_eq!(compiled.content(), b"ONEtwo\n");
        let geometry = compiled.hunk_geometry()[0];
        assert_eq!(geometry.source_span(), SourceByteSpan::new(0, 4));
        assert_eq!(geometry.result_span(), SourceByteSpan::new(0, 3));
        Ok(())
    }

    #[test]
    fn source_patch_geometry_tracks_adjacent_hunks_joining_one_output_line()
    -> Result<(), Box<dyn std::error::Error>> {
        let source = b"one\ntwo\nthree\n";
        let patch = FilePatch::new(
            FileContentHash::from_bytes(*blake3::hash(source).as_bytes()),
            vec![
                FilePatchHunk::new(
                    SourceLineRange::new(1, 1)?,
                    SourceRangeHash::from_bytes(*blake3::hash(b"one\n").as_bytes()),
                    b"A".to_vec(),
                )?,
                FilePatchHunk::new(
                    SourceLineRange::new(2, 2)?,
                    SourceRangeHash::from_bytes(*blake3::hash(b"two\n").as_bytes()),
                    b"B".to_vec(),
                )?,
            ],
        )?;

        let compiled = patch.compile(source)?;
        assert_eq!(compiled.content(), b"ABthree\n");
        let geometry = compiled.hunk_geometry();
        assert_eq!(geometry[0].result_span(), SourceByteSpan::new(0, 1));
        assert_eq!(geometry[1].result_span(), SourceByteSpan::new(1, 2));
        assert_eq!(
            geometry[0].result_span().end(),
            geometry[1].result_span().start()
        );
        Ok(())
    }

    #[test]
    fn source_patch_geometry_keeps_deletions_zero_width() -> Result<(), Box<dyn std::error::Error>>
    {
        let source = b"one\ntwo\n";
        let delete_last = FilePatch::new(
            FileContentHash::from_bytes(*blake3::hash(source).as_bytes()),
            vec![FilePatchHunk::new(
                SourceLineRange::new(2, 2)?,
                SourceRangeHash::from_bytes(*blake3::hash(b"two\n").as_bytes()),
                Vec::new(),
            )?],
        )?;
        let compiled = delete_last.compile(source)?;
        assert_eq!(compiled.content(), b"one\n");
        assert_eq!(
            compiled.hunk_geometry()[0].result_span(),
            SourceByteSpan::new(4, 4)
        );

        let all_source = b"one\n";
        let delete_all = FilePatch::new(
            FileContentHash::from_bytes(*blake3::hash(all_source).as_bytes()),
            vec![FilePatchHunk::new(
                SourceLineRange::new(1, 1)?,
                SourceRangeHash::from_bytes(*blake3::hash(all_source).as_bytes()),
                Vec::new(),
            )?],
        )?;
        let compiled = delete_all.compile(all_source)?;
        assert!(compiled.content().is_empty());
        assert_eq!(
            compiled.hunk_geometry()[0].result_span(),
            SourceByteSpan::new(0, 0)
        );
        Ok(())
    }

    #[test]
    fn source_line_spans_cover_mixed_endings_without_synthetic_terminal_line() {
        let spans: Vec<_> = source_line_spans(b"one\r\ntwo\rthree\nfour\r").collect();
        assert_eq!(
            spans,
            vec![
                SourceByteSpan::new(0, 5),
                SourceByteSpan::new(5, 9),
                SourceByteSpan::new(9, 15),
                SourceByteSpan::new(15, 20),
            ]
        );
        assert_eq!(source_line_spans(b"one\n").count(), 1);
        assert!(source_line_spans(b"").next().is_none());
    }

    #[test]
    fn source_patch_rejects_stale_whole_or_range_hash_and_overlap()
    -> Result<(), Box<dyn std::error::Error>> {
        let source = b"one\ntwo\nthree\n";
        let whole_hash = FileContentHash::from_bytes(*blake3::hash(source).as_bytes());
        let range_hash = SourceRangeHash::from_bytes(*blake3::hash(b"two\n").as_bytes());
        let stale_whole = FilePatch::new(
            FileContentHash::from_bytes([7; FileContentHash::BYTE_LEN]),
            vec![FilePatchHunk::new(
                SourceLineRange::new(2, 2)?,
                range_hash,
                b"TWO\n".to_vec(),
            )?],
        )?;
        assert!(matches!(
            stale_whole.compile(source),
            Err(FilePatchError::StaleWholeFileHash)
        ));

        let stale_range = FilePatch::new(
            whole_hash,
            vec![FilePatchHunk::new(
                SourceLineRange::new(2, 2)?,
                SourceRangeHash::from_bytes([8; SourceRangeHash::BYTE_LEN]),
                b"TWO\n".to_vec(),
            )?],
        )?;
        assert!(matches!(
            stale_range.compile(source),
            Err(FilePatchError::StaleRangeHash { hunk: 0 })
        ));

        assert!(matches!(
            FilePatch::new(
                whole_hash,
                vec![
                    FilePatchHunk::new(
                        SourceLineRange::new(1, 2)?,
                        SourceRangeHash::from_bytes(*blake3::hash(b"one\ntwo\n").as_bytes()),
                        b"x\n".to_vec(),
                    )?,
                    FilePatchHunk::new(
                        SourceLineRange::new(2, 3)?,
                        SourceRangeHash::from_bytes(*blake3::hash(b"two\nthree\n").as_bytes()),
                        b"y\n".to_vec(),
                    )?,
                ],
            ),
            Err(FilePatchError::HunksOverlap { .. })
        ));
        Ok(())
    }

    #[test]
    fn source_patch_rejects_binary_and_non_utf8_content() -> Result<(), Box<dyn std::error::Error>>
    {
        let binary = b"hello\0world";
        let binary_patch = FilePatch::new(
            FileContentHash::from_bytes(*blake3::hash(binary).as_bytes()),
            vec![FilePatchHunk::new(
                SourceLineRange::new(1, 1)?,
                SourceRangeHash::from_bytes(*blake3::hash(binary).as_bytes()),
                b"ok".to_vec(),
            )?],
        )?;
        assert!(matches!(
            binary_patch.compile(binary),
            Err(FilePatchError::BinarySource)
        ));

        let non_utf8 = [0xff, 0xfe];
        let non_utf8_patch = FilePatch::new(
            FileContentHash::from_bytes(*blake3::hash(&non_utf8).as_bytes()),
            vec![FilePatchHunk::new(
                SourceLineRange::new(1, 1)?,
                SourceRangeHash::from_bytes(*blake3::hash(&non_utf8).as_bytes()),
                b"ok".to_vec(),
            )?],
        )?;
        assert!(matches!(
            non_utf8_patch.compile(&non_utf8),
            Err(FilePatchError::NonUtf8Source)
        ));
        Ok(())
    }

    #[test]
    fn source_slice_metadata_keeps_whole_and_range_hashes_distinct()
    -> Result<(), Box<dyn std::error::Error>> {
        let source = b"one\r\ntwo\rthree";
        let slice = FileReadSlice::from_parts(
            FileReadSliceMetadata::new(
                FileContentHash::from_bytes(*blake3::hash(source).as_bytes()),
                SourceRangeHash::from_bytes(*blake3::hash(b"two\r").as_bytes()),
                SourceLineRange::new(2, 2)?,
                3,
                SourceEol::Mixed,
                false,
            ),
            b"two\r".to_vec(),
            vec![SourceRangeHash::from_bytes(
                *blake3::hash(b"two\r").as_bytes(),
            )],
        )?;
        assert_eq!(
            slice.whole_file_hash(),
            FileContentHash::from_bytes(*blake3::hash(source).as_bytes())
        );
        assert_eq!(
            slice.range_hash(),
            SourceRangeHash::from_bytes(*blake3::hash(b"two\r").as_bytes())
        );
        assert_eq!(slice.start_line(), 2);
        assert_eq!(slice.end_line(), 2);
        assert_eq!(slice.total_lines(), 3);
        assert_eq!(slice.content(), b"two\r");
        assert_eq!(slice.eol(), SourceEol::Mixed);
        assert!(!slice.has_final_newline());
        Ok(())
    }
}
