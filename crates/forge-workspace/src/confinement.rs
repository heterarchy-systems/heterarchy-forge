use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
#[cfg(not(target_os = "macos"))]
use std::path::Component;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use forge_domain::{
    CheckpointFileMode, FileByteCount, FileContentHash, FileEntryKind, FileMutationFailureCode,
    FileMutationId, FileMutationKind, FileMutationPlan, FilePathState, FilePrecondition,
    WorkspaceRelativePath, WorkspaceRootFingerprint,
};
use rustix::fs::{
    AtFlags, Dir, FileType, FlockOperation, Mode, OFlags, RenameFlags, fchmod, fstat, fsync, open,
    openat, renameat, renameat_with, statat, unlinkat,
};
use rustix::io::{Errno, dup};
use thiserror::Error;

use crate::diff_artifact::{DiffArtifactStore, DiffArtifactStoreParts};
use crate::{ExistingWorkspaceStateLayout, WorkspaceStateExclusiveGate};

mod harness_presence;
mod source_editing;
mod source_tree;
mod verification_input;
pub use harness_presence::{
    HarnessDirectoryObservation, MAX_WORKSPACE_HARNESS_AGENTS_ROOTS,
    MAX_WORKSPACE_HARNESS_DIRECTORIES, MAX_WORKSPACE_HARNESS_DIRECTORY_SCAN_ENTRIES,
    MAX_WORKSPACE_HARNESS_PATH_BYTES, MAX_WORKSPACE_HARNESS_PATH_COMPONENTS,
    MAX_WORKSPACE_HARNESS_SCAN_ENTRIES, MAX_WORKSPACE_HARNESS_TREE_ENTRIES,
    WorkspaceHarnessObservation, WorkspaceHarnessObservationError, WorkspaceHarnessTree,
    WorkspaceHarnessTreeEntry, inspect_workspace_harness_directories,
    inspect_workspace_harness_tree,
};
pub use source_editing::{
    MAX_FILE_LIST_SCAN_ENTRIES, MAX_TEXT_SEARCH_FILE_BYTES, PreparedSourcePatch,
};
pub use source_tree::{
    AppliedSourceTreeTransaction, MAX_SOURCE_TREE_PAYLOAD_BYTES, PreparedSourceTreeTransaction,
    SourceTreeApplyError, SourceTreeMutationPayload, SourceTreePayloadSet, TreeMutationObservation,
};
pub use verification_input::{
    MAX_VERIFICATION_INPUT_MANIFEST_BYTES, PublishedVerificationInput, StagedVerificationInput,
    VerificationInputError,
};

/// Maximum number of native path components walked for one request.
pub const MAX_FILE_PATH_COMPONENTS: usize = 128;
/// Maximum file bytes returned by the first control-plane read surface.
pub const MAX_FILE_READ_BYTES: usize = 32 * 1024;
/// Maximum bytes accepted by the explicit binary import operation.
pub const MAX_BINARY_IMPORT_BYTES: usize = 4 * 1024 * 1024;
/// Maximum existing target bytes hashed for CAS and recovery. Observation
/// must cover every file the bounded binary import operation can create.
pub const MAX_HASHED_FILE_BYTES: usize = MAX_BINARY_IMPORT_BYTES;
/// Maximum replacement payload accepted by the first bounded mutation slice.
pub const MAX_FILE_WRITE_BYTES: usize = 8 * 1024;
/// Maximum materialized content accepted by one compiled source patch.
pub const MAX_SOURCE_PATCH_BYTES: usize = forge_domain::MAX_SOURCE_PATCH_BYTES;
/// Maximum source bytes retained in memory for one human-review Diff side.
///
/// Larger files remain hashable for compare-and-swap. Whole-source V1 capture
/// is summary-only; validated source patches use separate bounded V2 windows.
pub const MAX_DIFF_SOURCE_BYTES: usize = 64 * 1024;

const LOCK_RETRY_LIMIT: u32 = 1_000;
const LOCK_OPEN_RETRY_LIMIT: u32 = 32;
const LOCK_RETRY_DELAY: Duration = Duration::from_millis(1);
const STATE_DIRECTORY: &str = ".heterarchy-forge";
const MUTATION_LOCK_FILE: &str = "file-mutation.lock";
const TEMP_PREFIX: &str = ".heterarchy-forge-tmp-";
const MAX_STATE_REMOVAL_ENTRIES: usize = 65_536;
const MAX_STATE_REMOVAL_DEPTH: usize = 64;

const EXCLUDED_WORKSPACE_COMPONENTS: [&[u8]; 14] = [
    b".git",
    b".heterarchy-forge",
    b"target",
    b"dist",
    b"build",
    b"node_modules",
    b".next",
    b"coverage",
    b".cache",
    b".ruff_cache",
    b"tmp",
    b"__pycache__",
    b".venv",
    b"venv",
];

pub(crate) fn is_excluded_workspace_component(component: &[u8]) -> bool {
    EXCLUDED_WORKSPACE_COMPONENTS
        .iter()
        .any(|excluded| component.eq_ignore_ascii_case(excluded))
}

/// Validate and hash one bounded create/replace payload before durable intent
/// persistence. This is the same algorithm used for observed POST state.
pub fn bounded_write_content_hash(
    content: &[u8],
) -> Result<FileContentHash, ConfinedFilesystemError> {
    content_hash_with_limit(content, MAX_FILE_WRITE_BYTES)
}

/// Validate and hash a binary import before durable intent admission.
pub fn bounded_binary_content_hash(
    content: &[u8],
) -> Result<FileContentHash, ConfinedFilesystemError> {
    content_hash_with_limit(content, MAX_BINARY_IMPORT_BYTES)
}

fn content_hash_with_limit(
    content: &[u8],
    maximum: usize,
) -> Result<FileContentHash, ConfinedFilesystemError> {
    if content.len() > maximum {
        return Err(ConfinedFilesystemError::WriteTooLarge {
            actual: content.len(),
            maximum,
        });
    }
    Ok(FileContentHash::from_bytes(
        *blake3::hash(content).as_bytes(),
    ))
}

/// Exact bytes and digest observed through one regular-file descriptor.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfinedFileRead {
    content: Vec<u8>,
    hash: FileContentHash,
    size: FileByteCount,
    mode: CheckpointFileMode,
}

impl ConfinedFileRead {
    pub fn content(&self) -> &[u8] {
        &self.content
    }

    pub(crate) fn into_content(self) -> Vec<u8> {
        self.content
    }

    pub const fn state(&self) -> FilePathState {
        FilePathState::Regular {
            hash: self.hash,
            size: self.size,
        }
    }

    pub const fn hash(&self) -> FileContentHash {
        self.hash
    }

    pub const fn size(&self) -> FileByteCount {
        self.size
    }

    pub const fn mode(&self) -> CheckpointFileMode {
        self.mode
    }
}

/// Bounded, ephemeral source captured for human-review Diff rendering.
///
/// These bytes never enter `SQLite`; rendering and deterministic redaction
/// happen before a durable artifact is published.
#[must_use]
#[derive(Clone, PartialEq, Eq)]
pub enum CapturedDiffSource {
    Absent,
    Text(String),
    Binary { size: FileByteCount },
    Oversized { size: FileByteCount },
}

impl std::fmt::Debug for CapturedDiffSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Absent => formatter.write_str("Absent"),
            Self::Text(value) => formatter
                .debug_struct("Text")
                .field("bytes", &value.len())
                .finish(),
            Self::Binary { size } => formatter
                .debug_struct("Binary")
                .field("size", size)
                .finish(),
            Self::Oversized { size } => formatter
                .debug_struct("Oversized")
                .field("size", size)
                .finish(),
        }
    }
}

impl CapturedDiffSource {
    pub const fn text(&self) -> Option<&str> {
        match self {
            Self::Text(value) => Some(value.as_str()),
            Self::Absent | Self::Binary { .. } | Self::Oversized { .. } => None,
        }
    }

    pub const fn size(&self) -> FileByteCount {
        match self {
            Self::Absent => FileByteCount::new(0),
            Self::Text(value) => FileByteCount::new(value.len() as u64),
            Self::Binary { size } | Self::Oversized { size } => *size,
        }
    }

    fn from_retained(retained: Vec<u8>, size: FileByteCount, retained_complete: bool) -> Self {
        if !retained_complete {
            return Self::Oversized { size };
        }
        match String::from_utf8(retained) {
            Ok(value) if !value.as_bytes().contains(&0) => Self::Text(value),
            Ok(_) | Err(_) => Self::Binary { size },
        }
    }
}

/// Successful filesystem effect, exact observed POST state, and the bounded
/// source pair captured by the same mutation lifecycle.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedFileMutation {
    pre_state: FilePathState,
    post_state: FilePathState,
    pre_source: CapturedDiffSource,
    post_source: CapturedDiffSource,
}

/// Successful two-endpoint move observed through the same descriptor-rooted
/// confinement boundary as single-file mutations.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedFileMove {
    source_pre_state: FilePathState,
    source_post_state: FilePathState,
    destination_pre_state: FilePathState,
    destination_post_state: FilePathState,
    source_pre_source: CapturedDiffSource,
}

impl AppliedFileMove {
    pub const fn source_pre_state(&self) -> FilePathState {
        self.source_pre_state
    }

    pub const fn source_post_state(&self) -> FilePathState {
        self.source_post_state
    }

    pub const fn destination_pre_state(&self) -> FilePathState {
        self.destination_pre_state
    }

    pub const fn destination_post_state(&self) -> FilePathState {
        self.destination_post_state
    }

    pub const fn source_pre_source(&self) -> &CapturedDiffSource {
        &self.source_pre_source
    }
}

impl AppliedFileMutation {
    pub const fn pre_state(&self) -> FilePathState {
        self.pre_state
    }

    pub const fn post_state(&self) -> FilePathState {
        self.post_state
    }

    pub const fn pre_source(&self) -> &CapturedDiffSource {
        &self.pre_source
    }

    pub const fn post_source(&self) -> &CapturedDiffSource {
        &self.post_source
    }
}

/// Descriptor-rooted Workspace filesystem boundary.
///
/// The root descriptor and expected physical identity are retained so path
/// traversal never depends on a process-global current directory or on one
/// multi-component untrusted syscall path.
pub struct ConfinedWorkspace {
    workspace_root: std::path::PathBuf,
    #[cfg(not(target_os = "macos"))]
    filesystem_root: OwnedFd,
    #[cfg(not(target_os = "macos"))]
    root_components: Vec<OsString>,
    root: OwnedFd,
    root_identity: DirectoryIdentity,
    state_identity: DirectoryIdentity,
}

/// Read-only descriptor capability for Workspace observations that must not
/// require Forge-owned state or confer mutation authority.
///
/// Unlike [`ConfinedWorkspace`], this capability intentionally does not open
/// `.heterarchy-forge`. It nevertheless retains the same root descriptor and
/// physical identity fencing so observational scans cannot escape through a
/// pathname replacement or symlink race.
pub(crate) struct WorkspaceObservationRoot {
    workspace_root: PathBuf,
    #[cfg(not(target_os = "macos"))]
    filesystem_root: OwnedFd,
    #[cfg(not(target_os = "macos"))]
    root_components: Vec<OsString>,
    root: OwnedFd,
    root_identity: DirectoryIdentity,
}

impl WorkspaceObservationRoot {
    pub(crate) fn open(
        workspace_root: &Path,
        expected_root_fingerprint: WorkspaceRootFingerprint,
    ) -> Result<Self, ConfinedFilesystemError> {
        if !workspace_root.is_absolute() {
            return Err(ConfinedFilesystemError::WorkspaceUnavailable);
        }
        let workspace_root = workspace_root.to_path_buf();
        #[cfg(not(target_os = "macos"))]
        let filesystem_root = open(
            Path::new("/"),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|source| ConfinedFilesystemError::Syscall {
            operation: FilesystemOperation::OpenFilesystemRoot,
            committed: false,
            source,
        })?;
        #[cfg(not(target_os = "macos"))]
        let root_components = collect_absolute_components(&workspace_root)?;
        #[cfg(target_os = "macos")]
        let root = reopen_workspace_root(&workspace_root, false)?;
        #[cfg(not(target_os = "macos"))]
        let root = reopen_workspace_root(&filesystem_root, &root_components, false)?;
        let root_identity = directory_identity(&root)?;
        if root_identity.fingerprint() != expected_root_fingerprint {
            return Err(ConfinedFilesystemError::WorkspaceUnavailable);
        }
        Ok(Self {
            workspace_root,
            #[cfg(not(target_os = "macos"))]
            filesystem_root,
            #[cfg(not(target_os = "macos"))]
            root_components,
            root,
            root_identity,
        })
    }

    pub(crate) fn open_directory(
        &self,
        components: &[OsString],
    ) -> Result<OwnedFd, ConfinedFilesystemError> {
        walk_directories(&self.root, components, false)
    }

    pub(crate) fn ensure_directory_current(
        &self,
        components: &[OsString],
        expected: DirectoryIdentity,
    ) -> Result<(), ConfinedFilesystemError> {
        let reopened = self.open_directory(components)?;
        ensure_directory_identity(&reopened, expected, false)
    }

    pub(crate) fn ensure_root(&self) -> Result<(), ConfinedFilesystemError> {
        ensure_directory_identity(&self.root, self.root_identity, false)?;
        #[cfg(target_os = "macos")]
        let reopened = reopen_workspace_root(&self.workspace_root, false)?;
        #[cfg(not(target_os = "macos"))]
        let reopened = reopen_workspace_root(&self.filesystem_root, &self.root_components, false)?;
        ensure_directory_identity(&reopened, self.root_identity, false)
    }
}

impl std::fmt::Debug for ConfinedWorkspace {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConfinedWorkspace")
            .field("root_identity", &self.root_identity)
            .finish_non_exhaustive()
    }
}

impl ConfinedWorkspace {
    pub fn open(layout: &ExistingWorkspaceStateLayout) -> Result<Self, ConfinedFilesystemError> {
        let expected = layout
            .root_fingerprint()
            .map_err(|_| ConfinedFilesystemError::WorkspaceUnavailable)?;
        let workspace_root = layout.workspace_root().to_path_buf();
        #[cfg(not(target_os = "macos"))]
        let filesystem_root = open(
            Path::new("/"),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|source| ConfinedFilesystemError::Syscall {
            operation: FilesystemOperation::OpenFilesystemRoot,
            committed: false,
            source,
        })?;
        #[cfg(not(target_os = "macos"))]
        let root_components = collect_absolute_components(layout.workspace_root())?;
        #[cfg(target_os = "macos")]
        let root = reopen_workspace_root(&workspace_root, false)?;
        #[cfg(not(target_os = "macos"))]
        let root = reopen_workspace_root(&filesystem_root, &root_components, false)?;
        let root_identity = directory_identity(&root)?;
        if root_identity.fingerprint() != expected {
            return Err(ConfinedFilesystemError::WorkspaceUnavailable);
        }
        let state = openat(
            &root,
            STATE_DIRECTORY,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|source| ConfinedFilesystemError::Syscall {
            operation: FilesystemOperation::OpenStateDirectory,
            committed: false,
            source,
        })?;
        let state_identity = directory_identity(&state)?;
        Ok(Self {
            workspace_root,
            #[cfg(not(target_os = "macos"))]
            filesystem_root,
            #[cfg(not(target_os = "macos"))]
            root_components,
            root,
            root_identity,
            state_identity,
        })
    }

    /// Read one regular file without following any ancestor or leaf symlink.
    pub fn read(
        &self,
        path: &WorkspaceRelativePath,
    ) -> Result<ConfinedFileRead, ConfinedFilesystemError> {
        self.ensure_root()?;
        let (parent, basename, _) = self.open_parent(path)?;
        let result = read_leaf(
            &parent,
            &basename,
            MAX_FILE_READ_BYTES,
            Some(MAX_FILE_READ_BYTES),
        )?;
        let Some(result) = result else {
            return Err(ConfinedFilesystemError::NotFound);
        };
        let FilePathState::Regular { hash, size } = result.state else {
            return Err(ConfinedFilesystemError::PostStateMismatch);
        };
        if !result.retained_complete {
            return Err(ConfinedFilesystemError::PostStateMismatch);
        }
        self.ensure_root()?;
        Ok(ConfinedFileRead {
            content: result.retained,
            hash,
            size,
            mode: result.mode,
        })
    }

    /// Read a checkpoint-sized regular file through the same descriptor-rooted
    /// no-follow traversal used by Workspace mutations. The root and owned
    /// state directory are revalidated before and after the read.
    pub(crate) fn read_checkpoint(
        &self,
        path: &WorkspaceRelativePath,
    ) -> Result<Option<ConfinedFileRead>, ConfinedFilesystemError> {
        self.ensure_root()?;
        let (parent, basename, _) = self.open_parent(path)?;
        let result = read_leaf(
            &parent,
            &basename,
            MAX_HASHED_FILE_BYTES,
            Some(MAX_HASHED_FILE_BYTES),
        )?;
        let Some(result) = result else {
            return Ok(None);
        };
        let FilePathState::Regular { hash, size } = result.state else {
            return Err(ConfinedFilesystemError::PostStateMismatch);
        };
        if !result.retained_complete {
            return Err(ConfinedFilesystemError::PostStateMismatch);
        }
        self.ensure_root()?;
        Ok(Some(ConfinedFileRead {
            content: result.retained,
            hash,
            size,
            mode: result.mode,
        }))
    }

    pub(crate) fn ensure_for_git(&self, committed: bool) -> Result<(), ConfinedFilesystemError> {
        self.ensure_root_with_committed(committed)
    }

    /// Observe one absent or regular path for CAS without returning content.
    pub fn observe(
        &self,
        path: &WorkspaceRelativePath,
    ) -> Result<FilePathState, ConfinedFilesystemError> {
        self.ensure_root()?;
        let (parent, basename, _) = self.open_parent(path)?;
        let state = observe_leaf(&parent, &basename)?;
        self.ensure_root()?;
        Ok(state)
    }

    /// Observe content identity and mode through one descriptor without
    /// retaining file bytes. Restore must support the full checkpoint bound,
    /// independently of the smaller UI/read payload limit.
    pub fn observe_checkpoint(
        &self,
        path: &WorkspaceRelativePath,
    ) -> Result<forge_domain::CheckpointObservedPathState, ConfinedFilesystemError> {
        use forge_domain::CheckpointObservedPathState;
        self.ensure_root()?;
        let (parent, basename, _) = self.open_parent(path)?;
        let read = read_leaf(&parent, &basename, MAX_HASHED_FILE_BYTES, None)?;
        self.ensure_root()?;
        match read {
            None => Ok(CheckpointObservedPathState::Absent),
            Some(OpenLeafRead {
                state: FilePathState::Regular { hash, size },
                mode,
                ..
            }) => Ok(CheckpointObservedPathState::Regular { hash, size, mode }),
            Some(_) => Err(ConfinedFilesystemError::PostStateMismatch),
        }
    }

    /// Open the owned Diff artifact directory through the already-validated
    /// Workspace descriptor chain.
    pub fn diff_artifact_store(&self) -> Result<DiffArtifactStore, ConfinedFilesystemError> {
        self.ensure_root()?;
        let state = openat(
            &self.root,
            STATE_DIRECTORY,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|source| ConfinedFilesystemError::Syscall {
            operation: FilesystemOperation::OpenStateDirectory,
            committed: false,
            source,
        })?;
        let diffs = openat(
            &state,
            "diffs",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|source| ConfinedFilesystemError::Syscall {
            operation: FilesystemOperation::OpenDiffDirectory,
            committed: false,
            source,
        })?;
        #[cfg(not(target_os = "macos"))]
        let filesystem_root =
            dup(&self.filesystem_root).map_err(|source| ConfinedFilesystemError::Syscall {
                operation: FilesystemOperation::DuplicateRoot,
                committed: false,
                source,
            })?;
        let root = dup(&self.root).map_err(|source| ConfinedFilesystemError::Syscall {
            operation: FilesystemOperation::DuplicateRoot,
            committed: false,
            source,
        })?;
        let state_identity = directory_identity(&state)?;
        let diffs_identity = directory_identity(&diffs)?;
        let store = DiffArtifactStore::from_parts(DiffArtifactStoreParts {
            #[cfg(target_os = "macos")]
            workspace_root: self.workspace_root.clone(),
            #[cfg(not(target_os = "macos"))]
            filesystem_root,
            #[cfg(not(target_os = "macos"))]
            root_components: self.root_components.clone(),
            root,
            root_identity: self.root_identity,
            state,
            state_identity,
            diffs,
            diffs_identity,
            diffs_path: self.workspace_root.join(STATE_DIRECTORY).join("diffs"),
        });
        self.ensure_root()?;
        Ok(store)
    }

    /// Acquire the same bounded cross-process writer lock used by file
    /// mutations for a scoped maintenance operation.
    pub fn acquire_write_guard(
        &self,
    ) -> Result<ConfinedWorkspaceWriteGuard, ConfinedFilesystemError> {
        self.ensure_root()?;
        let lock = self.acquire_mutation_lock()?;
        self.ensure_root()?;
        Ok(ConfinedWorkspaceWriteGuard {
            _lock: lock,
            root_identity: self.root_identity,
            state_identity: self.state_identity,
        })
    }

    /// Verify the exact Forge-owned state tree is removable before the caller
    /// disables its Location. This is descriptor-relative and bounded; it
    /// follows no symbolic link and leaves the tree unchanged.
    pub fn preflight_owned_state_removal(
        &self,
        gate: &WorkspaceStateExclusiveGate,
        guard: &ConfinedWorkspaceWriteGuard,
    ) -> Result<(), ConfinedFilesystemError> {
        self.ensure_state_removal_binding(gate, guard)?;
        let state = self.open_owned_state_for_removal()?;
        let mut entries = 0_usize;
        inspect_removal_tree(&state, &mut entries, 0)?;
        self.ensure_state_removal_binding(gate, guard)
    }

    /// Remove exactly the validated `.heterarchy-forge` child directory.
    ///
    /// The exclusive root gate and matching mutation guard are borrowed from
    /// the caller, retaining both fences for the entire non-atomic recursive
    /// effect. On an error the caller must report incomplete removal; this
    /// method never follows a symlink or expands the target beyond state root.
    pub fn remove_owned_state_directory(
        &self,
        gate: &WorkspaceStateExclusiveGate,
        guard: &ConfinedWorkspaceWriteGuard,
    ) -> Result<WorkspaceStateRemoval, ConfinedFilesystemError> {
        self.ensure_state_removal_binding(gate, guard)?;
        let state = match self.open_owned_state_for_removal() {
            Ok(state) => state,
            Err(ConfinedFilesystemError::NotFound) => {
                return Ok(WorkspaceStateRemoval::AlreadyAbsent);
            }
            Err(error) => return Err(error),
        };
        let mut entries = 0_usize;
        remove_removal_tree(&state, &mut entries, 0)?;
        let current_state = statat(&self.root, STATE_DIRECTORY, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| ConfinedFilesystemError::CommittedPathChanged)?;
        if directory_identity_from_stat(&current_state)? != self.state_identity {
            return Err(ConfinedFilesystemError::CommittedPathChanged);
        }
        unlinkat(&self.root, STATE_DIRECTORY, AtFlags::REMOVEDIR).map_err(|source| {
            ConfinedFilesystemError::Syscall {
                operation: FilesystemOperation::RemoveStateRoot,
                committed: true,
                source,
            }
        })?;
        fsync(&self.root).map_err(|source| ConfinedFilesystemError::Syscall {
            operation: FilesystemOperation::SyncWorkspaceRoot,
            committed: true,
            source,
        })?;
        self.ensure_workspace_root_after_state_removal()?;
        gate.ensure_root_binding(&self.workspace_root, self.root_identity.fingerprint())
            .map_err(|_| ConfinedFilesystemError::CommittedPathChanged)?;
        match statat(&self.root, STATE_DIRECTORY, AtFlags::SYMLINK_NOFOLLOW) {
            Err(source) if source == Errno::NOENT => Ok(WorkspaceStateRemoval::Removed),
            Ok(_) => Err(ConfinedFilesystemError::CommittedObservationFailed),
            Err(source) => Err(ConfinedFilesystemError::Syscall {
                operation: FilesystemOperation::InspectStateDirectory,
                committed: true,
                source,
            }),
        }
    }

    /// Acquire the cross-process Forge-writer lock and retain the exact parent
    /// descriptor until the prepared effect finishes.
    pub fn prepare_mutation(
        &self,
        plan: &FileMutationPlan,
    ) -> Result<PreparedFileMutation, ConfinedFilesystemError> {
        self.ensure_root()?;
        let mutation_lock = self.acquire_mutation_lock()?;
        self.prepare_mutation_with_lock(plan, Some(mutation_lock))
    }

    /// Prepare one file mutation while an aggregate Source Tree Transaction
    /// already retains the Workspace writer lock.
    fn prepare_mutation_under_held_lock(
        &self,
        plan: &FileMutationPlan,
    ) -> Result<PreparedFileMutation, ConfinedFilesystemError> {
        self.ensure_root()?;
        self.prepare_mutation_with_lock(plan, None)
    }

    fn prepare_mutation_with_lock(
        &self,
        plan: &FileMutationPlan,
        mutation_lock: Option<MutationLock>,
    ) -> Result<PreparedFileMutation, ConfinedFilesystemError> {
        let (parent, basename, parent_components) = self.open_parent(plan.path())?;
        let parent_identity = directory_identity(&parent)?;
        let captured = read_leaf(
            &parent,
            &basename,
            MAX_HASHED_FILE_BYTES,
            Some(MAX_DIFF_SOURCE_BYTES),
        )?;
        let (pre_state, pre_source) = match captured {
            Some(captured) => {
                let FilePathState::Regular { size, .. } = captured.state else {
                    return Err(ConfinedFilesystemError::PostStateMismatch);
                };
                let source = CapturedDiffSource::from_retained(
                    captured.retained,
                    size,
                    captured.retained_complete,
                );
                (captured.state, source)
            }
            None => (FilePathState::Absent, CapturedDiffSource::Absent),
        };
        validate_precondition(plan.kind(), plan.precondition(), pre_state)?;
        let root = dup(&self.root).map_err(|source| ConfinedFilesystemError::Syscall {
            operation: FilesystemOperation::DuplicateRoot,
            committed: false,
            source,
        })?;
        #[cfg(not(target_os = "macos"))]
        let filesystem_root =
            dup(&self.filesystem_root).map_err(|source| ConfinedFilesystemError::Syscall {
                operation: FilesystemOperation::DuplicateRoot,
                committed: false,
                source,
            })?;
        #[cfg(not(target_os = "macos"))]
        let root_components = self.root_components.clone();
        Ok(PreparedFileMutation {
            #[cfg(target_os = "macos")]
            workspace_root: self.workspace_root.clone(),
            #[cfg(not(target_os = "macos"))]
            filesystem_root,
            #[cfg(not(target_os = "macos"))]
            root_components,
            root,
            root_identity: self.root_identity,
            parent,
            parent_identity,
            parent_components,
            basename,
            kind: plan.kind(),
            precondition: plan.precondition(),
            pre_state,
            pre_source,
            _mutation_lock: mutation_lock,
        })
    }

    /// Acquire the Workspace writer lock and observe both endpoints of one
    /// atomic move. The source must match the caller-observed whole-file hash
    /// and the destination must not exist.
    pub fn prepare_move(
        &self,
        source: &WorkspaceRelativePath,
        expected_source_hash: FileContentHash,
        destination: &WorkspaceRelativePath,
    ) -> Result<PreparedFileMove, ConfinedFilesystemError> {
        if source == destination {
            return Err(ConfinedFilesystemError::PathConflict);
        }
        self.ensure_root()?;
        let mutation_lock = self.acquire_mutation_lock()?;
        self.prepare_move_with_lock(
            source,
            expected_source_hash,
            destination,
            Some(mutation_lock),
        )
    }

    fn prepare_move_under_held_lock(
        &self,
        source: &WorkspaceRelativePath,
        expected_source_hash: FileContentHash,
        destination: &WorkspaceRelativePath,
    ) -> Result<PreparedFileMove, ConfinedFilesystemError> {
        if source == destination {
            return Err(ConfinedFilesystemError::PathConflict);
        }
        self.ensure_root()?;
        self.prepare_move_with_lock(source, expected_source_hash, destination, None)
    }

    fn prepare_move_with_lock(
        &self,
        source: &WorkspaceRelativePath,
        expected_source_hash: FileContentHash,
        destination: &WorkspaceRelativePath,
        mutation_lock: Option<MutationLock>,
    ) -> Result<PreparedFileMove, ConfinedFilesystemError> {
        let (source_parent, source_basename, source_parent_components) =
            self.open_parent(source)?;
        let source_parent_identity = directory_identity(&source_parent)?;
        let captured = read_leaf(
            &source_parent,
            &source_basename,
            MAX_HASHED_FILE_BYTES,
            Some(MAX_DIFF_SOURCE_BYTES),
        )?
        .ok_or(ConfinedFilesystemError::NotFound)?;
        let FilePathState::Regular {
            hash: observed_hash,
            size: source_size,
        } = captured.state
        else {
            return Err(ConfinedFilesystemError::NonRegularLeaf);
        };
        if observed_hash != expected_source_hash {
            return Err(ConfinedFilesystemError::StaleWrite);
        }
        let source_pre_source = CapturedDiffSource::from_retained(
            captured.retained,
            source_size,
            captured.retained_complete,
        );

        let (destination_parent, destination_basename, destination_parent_components) =
            self.open_parent(destination)?;
        let destination_parent_identity = directory_identity(&destination_parent)?;
        if observe_leaf(&destination_parent, &destination_basename)? != FilePathState::Absent {
            return Err(ConfinedFilesystemError::PathConflict);
        }

        let root = dup(&self.root).map_err(|source| ConfinedFilesystemError::Syscall {
            operation: FilesystemOperation::DuplicateRoot,
            committed: false,
            source,
        })?;
        #[cfg(not(target_os = "macos"))]
        let filesystem_root =
            dup(&self.filesystem_root).map_err(|source| ConfinedFilesystemError::Syscall {
                operation: FilesystemOperation::DuplicateRoot,
                committed: false,
                source,
            })?;
        #[cfg(not(target_os = "macos"))]
        let root_components = self.root_components.clone();
        Ok(PreparedFileMove {
            #[cfg(target_os = "macos")]
            workspace_root: self.workspace_root.clone(),
            #[cfg(not(target_os = "macos"))]
            filesystem_root,
            #[cfg(not(target_os = "macos"))]
            root_components,
            root,
            root_identity: self.root_identity,
            source_parent,
            source_parent_identity,
            source_parent_components,
            source_basename,
            source_pre_state: captured.state,
            source_pre_source,
            destination_parent,
            destination_parent_identity,
            destination_parent_components,
            destination_basename,
            destination_pre_state: FilePathState::Absent,
            _mutation_lock: mutation_lock,
        })
    }

    fn acquire_mutation_lock(&self) -> Result<MutationLock, ConfinedFilesystemError> {
        let state_directory = openat(
            &self.root,
            STATE_DIRECTORY,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|source| ConfinedFilesystemError::Syscall {
            operation: FilesystemOperation::OpenStateDirectory,
            committed: false,
            source,
        })?;
        let file = open_mutation_lock_file(&state_directory)?;
        require_regular_single_link(&file)?;
        for _ in 0..LOCK_RETRY_LIMIT {
            match rustix::fs::flock(&file, FlockOperation::NonBlockingLockExclusive) {
                Ok(()) => return Ok(MutationLock { _file: file }),
                Err(source) if source == Errno::AGAIN || source == Errno::WOULDBLOCK => {
                    thread::sleep(LOCK_RETRY_DELAY);
                }
                Err(source) => {
                    return Err(ConfinedFilesystemError::Syscall {
                        operation: FilesystemOperation::LockMutation,
                        committed: false,
                        source,
                    });
                }
            }
        }
        Err(ConfinedFilesystemError::LockBusy)
    }

    fn ensure_state_removal_binding(
        &self,
        gate: &WorkspaceStateExclusiveGate,
        guard: &ConfinedWorkspaceWriteGuard,
    ) -> Result<(), ConfinedFilesystemError> {
        if guard.root_identity != self.root_identity || guard.state_identity != self.state_identity
        {
            return Err(ConfinedFilesystemError::PathChanged);
        }
        if self.state_identity.device != self.root_identity.device {
            return Err(ConfinedFilesystemError::ProtectedPath);
        }
        gate.ensure_root_binding(&self.workspace_root, self.root_identity.fingerprint())
            .map_err(|_| ConfinedFilesystemError::WorkspaceUnavailable)?;
        self.ensure_root()
    }

    fn open_owned_state_for_removal(&self) -> Result<OwnedFd, ConfinedFilesystemError> {
        let state = openat(
            &self.root,
            STATE_DIRECTORY,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|source| {
            if source == Errno::NOENT {
                ConfinedFilesystemError::NotFound
            } else {
                ConfinedFilesystemError::Syscall {
                    operation: FilesystemOperation::OpenStateDirectory,
                    committed: false,
                    source,
                }
            }
        })?;
        ensure_directory_identity(&state, self.state_identity, false)?;
        Ok(state)
    }

    fn ensure_workspace_root_after_state_removal(&self) -> Result<(), ConfinedFilesystemError> {
        ensure_directory_identity(&self.root, self.root_identity, true)?;
        #[cfg(target_os = "macos")]
        let reopened = reopen_workspace_root(&self.workspace_root, true)?;
        #[cfg(not(target_os = "macos"))]
        let reopened = reopen_workspace_root(&self.filesystem_root, &self.root_components, true)?;
        ensure_directory_identity(&reopened, self.root_identity, true)
    }

    fn open_parent(
        &self,
        path: &WorkspaceRelativePath,
    ) -> Result<(OwnedFd, OsString, Vec<OsString>), ConfinedFilesystemError> {
        validate_not_protected(path)?;
        let components = collect_components(path)?;
        let (basename, ancestors) = components
            .split_last()
            .ok_or(ConfinedFilesystemError::InvalidPath)?;
        let parent = walk_directories(&self.root, ancestors, false)?;
        Ok((parent, basename.clone(), ancestors.to_vec()))
    }

    fn ensure_root(&self) -> Result<(), ConfinedFilesystemError> {
        self.ensure_root_with_committed(false)
    }

    fn ensure_root_with_committed(&self, committed: bool) -> Result<(), ConfinedFilesystemError> {
        ensure_directory_identity(&self.root, self.root_identity, committed)?;
        #[cfg(target_os = "macos")]
        let reopened = reopen_workspace_root(&self.workspace_root, committed)?;
        #[cfg(not(target_os = "macos"))]
        let reopened =
            reopen_workspace_root(&self.filesystem_root, &self.root_components, committed)?;
        ensure_directory_identity(&reopened, self.root_identity, committed)?;
        let state = openat(
            &self.root,
            STATE_DIRECTORY,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|source| ConfinedFilesystemError::Syscall {
            operation: FilesystemOperation::OpenStateDirectory,
            committed,
            source,
        })?;
        ensure_directory_identity(&state, self.state_identity, committed)
    }
}

fn open_mutation_lock_file(state_directory: &OwnedFd) -> Result<OwnedFd, ConfinedFilesystemError> {
    for attempt in 0..LOCK_OPEN_RETRY_LIMIT {
        match openat(
            state_directory,
            MUTATION_LOCK_FILE,
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        ) {
            Ok(file) => return Ok(file),
            Err(source) if source == Errno::NOENT && attempt + 1 < LOCK_OPEN_RETRY_LIMIT => {
                thread::sleep(LOCK_RETRY_DELAY);
            }
            Err(source) => {
                return Err(ConfinedFilesystemError::Syscall {
                    operation: FilesystemOperation::OpenMutationLock,
                    committed: false,
                    source,
                });
            }
        }
    }
    Err(ConfinedFilesystemError::LockBusy)
}

/// Prepared single-file effect. It is intentionally neither `Clone` nor
/// `Copy`: dropping it releases the Forge-writer lock without performing an
/// effect or changing the durable intent.
#[derive(Debug)]
pub struct PreparedFileMutation {
    #[cfg(target_os = "macos")]
    workspace_root: std::path::PathBuf,
    #[cfg(not(target_os = "macos"))]
    filesystem_root: OwnedFd,
    #[cfg(not(target_os = "macos"))]
    root_components: Vec<OsString>,
    root: OwnedFd,
    root_identity: DirectoryIdentity,
    parent: OwnedFd,
    parent_identity: DirectoryIdentity,
    parent_components: Vec<OsString>,
    basename: OsString,
    kind: FileMutationKind,
    precondition: FilePrecondition,
    pre_state: FilePathState,
    pre_source: CapturedDiffSource,
    _mutation_lock: Option<MutationLock>,
}

/// Prepared atomic move retaining both endpoint descriptors and the shared
/// Workspace writer lock until the effect completes or is abandoned.
#[derive(Debug)]
pub struct PreparedFileMove {
    #[cfg(target_os = "macos")]
    workspace_root: std::path::PathBuf,
    #[cfg(not(target_os = "macos"))]
    filesystem_root: OwnedFd,
    #[cfg(not(target_os = "macos"))]
    root_components: Vec<OsString>,
    root: OwnedFd,
    root_identity: DirectoryIdentity,
    source_parent: OwnedFd,
    source_parent_identity: DirectoryIdentity,
    source_parent_components: Vec<OsString>,
    source_basename: OsString,
    source_pre_state: FilePathState,
    source_pre_source: CapturedDiffSource,
    destination_parent: OwnedFd,
    destination_parent_identity: DirectoryIdentity,
    destination_parent_components: Vec<OsString>,
    destination_basename: OsString,
    destination_pre_state: FilePathState,
    _mutation_lock: Option<MutationLock>,
}

impl PreparedFileMove {
    pub const fn source_pre_state(&self) -> FilePathState {
        self.source_pre_state
    }

    pub const fn destination_pre_state(&self) -> FilePathState {
        self.destination_pre_state
    }

    pub const fn source_pre_source(&self) -> &CapturedDiffSource {
        &self.source_pre_source
    }

    /// Atomically rename the observed source into the absent destination.
    /// Any error after the rename is classified as potentially committed so
    /// durable recovery can inspect both endpoints instead of replaying.
    pub fn apply(self) -> Result<AppliedFileMove, ConfinedFilesystemError> {
        self.ensure_absolute_root(false)?;
        self.ensure_source_parent(false)?;
        self.ensure_destination_parent(false)?;

        let source_current = observe_leaf(&self.source_parent, &self.source_basename)?;
        if source_current != self.source_pre_state {
            return Err(ConfinedFilesystemError::StaleWrite);
        }
        let destination_current =
            observe_leaf(&self.destination_parent, &self.destination_basename)?;
        if destination_current != self.destination_pre_state {
            return Err(ConfinedFilesystemError::PathConflict);
        }

        if let Err(source) = renameat_with(
            &self.source_parent,
            &self.source_basename,
            &self.destination_parent,
            &self.destination_basename,
            RenameFlags::NOREPLACE,
        ) {
            if source == Errno::EXIST {
                return Err(ConfinedFilesystemError::PathConflict);
            }
            if [Errno::NOTSUP, Errno::OPNOTSUPP, Errno::NOSYS].contains(&source) {
                return Err(ConfinedFilesystemError::AtomicMoveUnsupported);
            }
            return Err(ConfinedFilesystemError::Syscall {
                operation: FilesystemOperation::MoveLeaf,
                committed: false,
                source,
            });
        }

        fsync(&self.source_parent).map_err(|source| ConfinedFilesystemError::Syscall {
            operation: FilesystemOperation::SyncMoveSourceParent,
            committed: true,
            source,
        })?;
        if self.destination_parent_identity != self.source_parent_identity {
            fsync(&self.destination_parent).map_err(|source| ConfinedFilesystemError::Syscall {
                operation: FilesystemOperation::SyncMoveDestinationParent,
                committed: true,
                source,
            })?;
        }

        self.ensure_absolute_root(true)?;
        self.ensure_source_parent(true)?;
        self.ensure_destination_parent(true)?;
        let source_post = observe_leaf(&self.source_parent, &self.source_basename)
            .map_err(|error| error.with_committed(true))?;
        let destination_post = observe_leaf(&self.destination_parent, &self.destination_basename)
            .map_err(|error| error.with_committed(true))?;
        if source_post != FilePathState::Absent || destination_post != self.source_pre_state {
            return Err(ConfinedFilesystemError::CommittedObservationFailed);
        }
        Ok(AppliedFileMove {
            source_pre_state: self.source_pre_state,
            source_post_state: source_post,
            destination_pre_state: self.destination_pre_state,
            destination_post_state: destination_post,
            source_pre_source: self.source_pre_source,
        })
    }

    fn ensure_source_parent(&self, committed: bool) -> Result<(), ConfinedFilesystemError> {
        let reopened = walk_directories(&self.root, &self.source_parent_components, committed)?;
        ensure_directory_identity(&reopened, self.source_parent_identity, committed)
    }

    fn ensure_destination_parent(&self, committed: bool) -> Result<(), ConfinedFilesystemError> {
        let reopened =
            walk_directories(&self.root, &self.destination_parent_components, committed)?;
        ensure_directory_identity(&reopened, self.destination_parent_identity, committed)
    }

    fn ensure_absolute_root(&self, committed: bool) -> Result<(), ConfinedFilesystemError> {
        ensure_directory_identity(&self.root, self.root_identity, committed)?;
        #[cfg(target_os = "macos")]
        let reopened = reopen_workspace_root(&self.workspace_root, committed)?;
        #[cfg(not(target_os = "macos"))]
        let reopened =
            reopen_workspace_root(&self.filesystem_root, &self.root_components, committed)?;
        ensure_directory_identity(&reopened, self.root_identity, committed)
    }
}

impl PreparedFileMutation {
    pub const fn pre_state(&self) -> FilePathState {
        self.pre_state
    }

    pub const fn pre_source(&self) -> &CapturedDiffSource {
        &self.pre_source
    }

    /// Construct the bounded intended POST source without touching the target.
    pub fn intended_post_source(
        &self,
        content: Option<&[u8]>,
    ) -> Result<CapturedDiffSource, ConfinedFilesystemError> {
        self.intended_post_source_with_limit(content, MAX_FILE_WRITE_BYTES)
    }

    /// Retain only the ordinary Diff prefix of a bounded binary import.
    pub fn intended_binary_post_source(
        &self,
        content: &[u8],
    ) -> Result<CapturedDiffSource, ConfinedFilesystemError> {
        if !matches!(
            self.kind,
            FileMutationKind::Create | FileMutationKind::Replace
        ) {
            return Err(ConfinedFilesystemError::InvalidPayload);
        }
        if content.len() > MAX_BINARY_IMPORT_BYTES {
            return Err(ConfinedFilesystemError::WriteTooLarge {
                actual: content.len(),
                maximum: MAX_BINARY_IMPORT_BYTES,
            });
        }
        Ok(CapturedDiffSource::Binary {
            size: FileByteCount::new(content.len() as u64),
        })
    }

    fn intended_post_source_with_limit(
        &self,
        content: Option<&[u8]>,
        maximum: usize,
    ) -> Result<CapturedDiffSource, ConfinedFilesystemError> {
        match (self.kind, content) {
            (FileMutationKind::Create | FileMutationKind::Replace, Some(content)) => {
                if content.len() > maximum {
                    return Err(ConfinedFilesystemError::WriteTooLarge {
                        actual: content.len(),
                        maximum,
                    });
                }
                Ok(CapturedDiffSource::from_retained(
                    content[..content.len().min(MAX_DIFF_SOURCE_BYTES)].to_vec(),
                    FileByteCount::new(content.len() as u64),
                    content.len() <= MAX_DIFF_SOURCE_BYTES,
                ))
            }
            (FileMutationKind::Delete, None) => Ok(CapturedDiffSource::Absent),
            (FileMutationKind::Create | FileMutationKind::Replace, None)
            | (FileMutationKind::Delete, Some(_)) => Err(ConfinedFilesystemError::InvalidPayload),
        }
    }

    /// Apply the prepared mutation after a durable Starting intent commits.
    ///
    /// Create/replace require `Some(content)`; delete requires `None`.
    pub fn apply(
        self,
        mutation_id: FileMutationId,
        content: Option<&[u8]>,
    ) -> Result<AppliedFileMutation, ConfinedFilesystemError> {
        self.apply_inner(mutation_id, content, None, MAX_FILE_WRITE_BYTES)
    }

    /// Apply a validated source patch through the same descriptor-rooted
    /// atomic mutation effect, using the larger explicit source-patch bound.
    pub fn apply_source_patch(
        self,
        mutation_id: FileMutationId,
        content: &[u8],
    ) -> Result<AppliedFileMutation, ConfinedFilesystemError> {
        self.apply_inner(mutation_id, Some(content), None, MAX_SOURCE_PATCH_BYTES)
    }

    /// Apply an explicitly admitted binary import through the same atomic
    /// descriptor-rooted effect and exact PRE/POST comparison.
    pub fn apply_binary_import(
        self,
        mutation_id: FileMutationId,
        content: &[u8],
    ) -> Result<AppliedFileMutation, ConfinedFilesystemError> {
        self.apply_inner(mutation_id, Some(content), None, MAX_BINARY_IMPORT_BYTES)
    }

    /// Apply a checkpoint restore create/replace while restoring the exact
    /// descriptor-observed file mode retained by the checkpoint.
    pub fn apply_restored_content(
        self,
        mutation_id: FileMutationId,
        content: &[u8],
        mode: CheckpointFileMode,
    ) -> Result<AppliedFileMutation, ConfinedFilesystemError> {
        if !matches!(
            self.kind,
            FileMutationKind::Create | FileMutationKind::Replace
        ) {
            return Err(ConfinedFilesystemError::InvalidPayload);
        }
        self.apply_inner(
            mutation_id,
            Some(content),
            Some(mode),
            MAX_HASHED_FILE_BYTES,
        )
    }

    fn apply_inner(
        self,
        mutation_id: FileMutationId,
        content: Option<&[u8]>,
        restored_mode: Option<CheckpointFileMode>,
        maximum: usize,
    ) -> Result<AppliedFileMutation, ConfinedFilesystemError> {
        self.ensure_absolute_root(false)?;
        self.ensure_parent_path(false)?;
        let current = observe_leaf(&self.parent, &self.basename)?;
        validate_precondition(self.kind, self.precondition, current)?;
        if current != self.pre_state {
            return Err(ConfinedFilesystemError::StaleWrite);
        }

        match (self.kind, content) {
            (FileMutationKind::Create | FileMutationKind::Replace, Some(content)) => {
                if content.len() > maximum {
                    return Err(ConfinedFilesystemError::WriteTooLarge {
                        actual: content.len(),
                        maximum,
                    });
                }
                self.apply_content(mutation_id, content, restored_mode, maximum)?;
            }
            (FileMutationKind::Delete, None) if restored_mode.is_none() => self.apply_delete()?,
            (FileMutationKind::Create | FileMutationKind::Replace, None)
            | (FileMutationKind::Delete, Some(_) | None) => {
                return Err(ConfinedFilesystemError::InvalidPayload);
            }
        }

        self.ensure_absolute_root(true)?;
        self.ensure_parent_path(true)?;
        let post_state = observe_leaf(&self.parent, &self.basename)
            .map_err(|_| ConfinedFilesystemError::CommittedObservationFailed)?;
        validate_post_state(self.kind, post_state)
            .map_err(|_| ConfinedFilesystemError::CommittedObservationFailed)?;
        validate_post_content(self.kind, content, post_state, maximum)
            .map_err(|_| ConfinedFilesystemError::CommittedObservationFailed)?;
        let post_source = self.intended_post_source_with_limit(content, maximum)?;
        Ok(AppliedFileMutation {
            pre_state: self.pre_state,
            post_state,
            pre_source: self.pre_source,
            post_source,
        })
    }

    fn apply_content(
        &self,
        mutation_id: FileMutationId,
        content: &[u8],
        restored_mode: Option<CheckpointFileMode>,
        _maximum: usize,
    ) -> Result<(), ConfinedFilesystemError> {
        let temporary = OsString::from(format!("{TEMP_PREFIX}{mutation_id}"));
        let mode = if let Some(restored_mode) = restored_mode {
            // mode_t is u16 on macOS and u32 on Linux.
            let raw_mode = restored_mode.get();
            #[cfg(target_os = "linux")]
            let raw_mode = u32::from(raw_mode);
            Mode::from_raw_mode(raw_mode)
        } else {
            match self.pre_state {
                FilePathState::Absent => Mode::RUSR | Mode::WUSR,
                FilePathState::Regular { .. } => {
                    let leaf = open_regular_leaf(&self.parent, &self.basename)?
                        .ok_or(ConfinedFilesystemError::StaleWrite)?;
                    Mode::from_raw_mode(fstat(&leaf).map_err(pre_syscall)?.st_mode)
                }
            }
        };
        let temporary_fd = openat(
            &self.parent,
            &temporary,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            mode,
        )
        .map_err(map_create_temp_error)?;
        require_regular_single_link(&temporary_fd)?;
        if let Err(source) = fchmod(&temporary_fd, sanitized_file_mode(mode)) {
            return cleanup_after_syscall_error(
                &self.parent,
                &temporary,
                FilesystemOperation::SetTemporaryMode,
                source,
            );
        }
        let mut temporary_file = File::from(temporary_fd);
        if let Err(source) = temporary_file.write_all(content) {
            return cleanup_after_std_error(
                &self.parent,
                &temporary,
                FilesystemOperation::WriteTemporary,
                source,
            );
        }
        if let Err(source) = sync_file(&temporary_file) {
            return cleanup_after_syscall_error(
                &self.parent,
                &temporary,
                FilesystemOperation::SyncTemporary,
                source,
            );
        }
        drop(temporary_file);

        let publish = match self.kind {
            FileMutationKind::Create => renameat_with(
                &self.parent,
                &temporary,
                &self.parent,
                &self.basename,
                RenameFlags::NOREPLACE,
            ),
            FileMutationKind::Replace => {
                renameat(&self.parent, &temporary, &self.parent, &self.basename)
            }
            FileMutationKind::Delete => return Err(ConfinedFilesystemError::InvalidPayload),
        };
        if let Err(source) = publish {
            cleanup_temp(&self.parent, &temporary)?;
            if self.kind == FileMutationKind::Create && source == Errno::EXIST {
                return Err(ConfinedFilesystemError::PathConflict);
            }
            if self.kind == FileMutationKind::Create
                && [Errno::NOTSUP, Errno::OPNOTSUPP, Errno::NOSYS].contains(&source)
            {
                return Err(ConfinedFilesystemError::AtomicCreateUnsupported);
            }
            return Err(ConfinedFilesystemError::Syscall {
                operation: FilesystemOperation::PublishTemporary,
                committed: false,
                source,
            });
        }
        fsync(&self.parent).map_err(|source| ConfinedFilesystemError::Syscall {
            operation: FilesystemOperation::SyncParent,
            committed: true,
            source,
        })
    }

    fn apply_delete(&self) -> Result<(), ConfinedFilesystemError> {
        unlinkat(&self.parent, &self.basename, AtFlags::empty()).map_err(|source| {
            ConfinedFilesystemError::Syscall {
                operation: FilesystemOperation::DeleteLeaf,
                committed: false,
                source,
            }
        })?;
        fsync(&self.parent).map_err(|source| ConfinedFilesystemError::Syscall {
            operation: FilesystemOperation::SyncParent,
            committed: true,
            source,
        })
    }

    fn ensure_parent_path(&self, committed: bool) -> Result<(), ConfinedFilesystemError> {
        let reopened = walk_directories(&self.root, &self.parent_components, committed)?;
        ensure_directory_identity(&reopened, self.parent_identity, committed)
    }

    fn ensure_absolute_root(&self, committed: bool) -> Result<(), ConfinedFilesystemError> {
        ensure_directory_identity(&self.root, self.root_identity, committed)?;
        #[cfg(target_os = "macos")]
        let reopened = reopen_workspace_root(&self.workspace_root, committed)?;
        #[cfg(not(target_os = "macos"))]
        let reopened =
            reopen_workspace_root(&self.filesystem_root, &self.root_components, committed)?;
        ensure_directory_identity(&reopened, self.root_identity, committed)
    }
}

#[derive(Debug)]
struct MutationLock {
    _file: OwnedFd,
}

/// Terminal descriptor-relative result of removing Forge-local state.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceStateRemoval {
    Removed,
    AlreadyAbsent,
}

/// Non-cloneable cross-process Workspace writer guard.
#[derive(Debug)]
pub struct ConfinedWorkspaceWriteGuard {
    _lock: MutationLock,
    root_identity: DirectoryIdentity,
    state_identity: DirectoryIdentity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DirectoryIdentity {
    device: u64,
    inode: u64,
}

impl DirectoryIdentity {
    fn fingerprint(self) -> WorkspaceRootFingerprint {
        let mut value = [0_u8; 16];
        value[..8].copy_from_slice(&self.device.to_le_bytes());
        value[8..].copy_from_slice(&self.inode.to_le_bytes());
        WorkspaceRootFingerprint::from_bytes(value)
    }

    pub(crate) fn matches_metadata(self, metadata: &std::fs::Metadata) -> bool {
        use std::os::unix::fs::MetadataExt;

        metadata.dev() == self.device && metadata.ino() == self.inode
    }
}

fn removal_entry_names(
    directory: &OwnedFd,
    entries: &mut usize,
    committed: bool,
) -> Result<Vec<OsString>, ConfinedFilesystemError> {
    let stream = Dir::read_from(directory).map_err(|source| ConfinedFilesystemError::Syscall {
        operation: FilesystemOperation::OpenDirectoryStream,
        committed,
        source,
    })?;
    let mut names = Vec::new();
    for entry in stream {
        let entry = entry.map_err(|source| ConfinedFilesystemError::Syscall {
            operation: FilesystemOperation::ReadDirectory,
            committed,
            source,
        })?;
        let name = entry.file_name();
        let bytes = name.to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        *entries = entries
            .checked_add(1)
            .ok_or(ConfinedFilesystemError::StateRemovalTooLarge {
                maximum: MAX_STATE_REMOVAL_ENTRIES,
            })?;
        if *entries > MAX_STATE_REMOVAL_ENTRIES {
            return Err(ConfinedFilesystemError::StateRemovalTooLarge {
                maximum: MAX_STATE_REMOVAL_ENTRIES,
            });
        }
        names.push(OsString::from_vec(bytes.to_vec()));
    }
    Ok(names)
}

fn inspect_removal_tree(
    directory: &OwnedFd,
    entries: &mut usize,
    depth: usize,
) -> Result<(), ConfinedFilesystemError> {
    if depth > MAX_STATE_REMOVAL_DEPTH {
        return Err(ConfinedFilesystemError::StateRemovalTooDeep {
            maximum: MAX_STATE_REMOVAL_DEPTH,
        });
    }
    let parent_identity = directory_identity(directory)?;
    for name in removal_entry_names(directory, entries, false)? {
        let metadata = statat(directory, &name, AtFlags::SYMLINK_NOFOLLOW).map_err(|source| {
            ConfinedFilesystemError::Syscall {
                operation: FilesystemOperation::InspectDirectoryEntry,
                committed: false,
                source,
            }
        })?;
        if FileType::from_raw_mode(metadata.st_mode).is_dir() {
            if directory_identity_from_stat(&metadata)?.device != parent_identity.device {
                return Err(ConfinedFilesystemError::ProtectedPath);
            }
            let child = openat(
                directory,
                &name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|source| ConfinedFilesystemError::Syscall {
                operation: FilesystemOperation::OpenAncestor,
                committed: false,
                source,
            })?;
            ensure_directory_identity(&child, directory_identity_from_stat(&metadata)?, false)?;
            inspect_removal_tree(&child, entries, depth + 1)?;
        }
    }
    Ok(())
}

fn remove_removal_tree(
    directory: &OwnedFd,
    entries: &mut usize,
    depth: usize,
) -> Result<(), ConfinedFilesystemError> {
    if depth > MAX_STATE_REMOVAL_DEPTH {
        return Err(ConfinedFilesystemError::StateRemovalTooDeep {
            maximum: MAX_STATE_REMOVAL_DEPTH,
        });
    }
    let parent_identity = directory_identity(directory)?;
    for name in removal_entry_names(directory, entries, true)? {
        let metadata = statat(directory, &name, AtFlags::SYMLINK_NOFOLLOW).map_err(|source| {
            ConfinedFilesystemError::Syscall {
                operation: FilesystemOperation::InspectDirectoryEntry,
                committed: true,
                source,
            }
        })?;
        if FileType::from_raw_mode(metadata.st_mode).is_dir() {
            let expected_child = directory_identity_from_stat(&metadata)?;
            if expected_child.device != parent_identity.device {
                return Err(ConfinedFilesystemError::ProtectedPath);
            }
            let child = openat(
                directory,
                &name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|source| ConfinedFilesystemError::Syscall {
                operation: FilesystemOperation::OpenAncestor,
                committed: true,
                source,
            })?;
            ensure_directory_identity(&child, directory_identity_from_stat(&metadata)?, true)?;
            remove_removal_tree(&child, entries, depth + 1)?;
            let current_child = statat(directory, &name, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|_| ConfinedFilesystemError::CommittedPathChanged)?;
            if directory_identity_from_stat(&current_child)? != expected_child {
                return Err(ConfinedFilesystemError::CommittedPathChanged);
            }
            unlinkat(directory, &name, AtFlags::REMOVEDIR).map_err(|source| {
                ConfinedFilesystemError::Syscall {
                    operation: FilesystemOperation::RemoveStateEntry,
                    committed: true,
                    source,
                }
            })?;
        } else {
            unlinkat(directory, &name, AtFlags::empty()).map_err(|source| {
                ConfinedFilesystemError::Syscall {
                    operation: FilesystemOperation::RemoveStateEntry,
                    committed: true,
                    source,
                }
            })?;
        }
    }
    Ok(())
}

// Shared callers retain the fallible signed-device conversion on macOS.
// Linux's native device value is already u64; keep the same error contract.
#[cfg_attr(
    target_os = "linux",
    expect(
        clippy::unnecessary_wraps,
        reason = "the shared signature preserves macOS negative-device rejection"
    )
)]
fn directory_identity_from_stat(
    metadata: &rustix::fs::Stat,
) -> Result<DirectoryIdentity, ConfinedFilesystemError> {
    #[cfg(target_os = "linux")]
    let device = metadata.st_dev;
    #[cfg(not(target_os = "linux"))]
    let device = u64::try_from(metadata.st_dev)
        .map_err(|_| ConfinedFilesystemError::WorkspaceUnavailable)?;
    Ok(DirectoryIdentity {
        device,
        inode: metadata.st_ino,
    })
}

pub(crate) fn directory_identity(
    fd: &OwnedFd,
) -> Result<DirectoryIdentity, ConfinedFilesystemError> {
    let stat = fstat(fd).map_err(pre_syscall)?;
    if !FileType::from_raw_mode(stat.st_mode).is_dir() {
        return Err(ConfinedFilesystemError::NonDirectoryAncestor);
    }
    #[cfg(target_os = "linux")]
    let device = stat.st_dev;
    #[cfg(not(target_os = "linux"))]
    let device =
        u64::try_from(stat.st_dev).map_err(|_| ConfinedFilesystemError::WorkspaceUnavailable)?;
    Ok(DirectoryIdentity {
        device,
        inode: stat.st_ino,
    })
}

pub(crate) fn directory_identity_by_path(
    path: &Path,
) -> Result<DirectoryIdentity, ConfinedFilesystemError> {
    let dir = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|source| {
        if matches!(source, Errno::NOENT | Errno::NOTDIR) {
            ConfinedFilesystemError::WorkspaceUnavailable
        } else if source == Errno::LOOP {
            ConfinedFilesystemError::SymlinkRejected
        } else {
            ConfinedFilesystemError::Syscall {
                operation: FilesystemOperation::OpenCheckpointStore,
                committed: false,
                source,
            }
        }
    })?;
    directory_identity(&dir)
}

pub(crate) fn ensure_directory_identity(
    fd: &OwnedFd,
    expected: DirectoryIdentity,
    committed: bool,
) -> Result<(), ConfinedFilesystemError> {
    let actual = directory_identity(fd).map_err(|error| error.with_committed(committed))?;
    if actual == expected {
        Ok(())
    } else if committed {
        Err(ConfinedFilesystemError::CommittedPathChanged)
    } else {
        Err(ConfinedFilesystemError::PathChanged)
    }
}

fn collect_components(
    path: &WorkspaceRelativePath,
) -> Result<Vec<OsString>, ConfinedFilesystemError> {
    let mut components = Vec::new();
    for component in path.components() {
        if components.len() >= MAX_FILE_PATH_COMPONENTS {
            return Err(ConfinedFilesystemError::TooManyComponents);
        }
        components.push(component.to_os_string());
    }
    if components.is_empty() {
        Err(ConfinedFilesystemError::InvalidPath)
    } else {
        Ok(components)
    }
}

#[cfg(not(target_os = "macos"))]
fn collect_absolute_components(path: &Path) -> Result<Vec<OsString>, ConfinedFilesystemError> {
    if !path.is_absolute() {
        return Err(ConfinedFilesystemError::WorkspaceUnavailable);
    }
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(value) => {
                if components.len() >= MAX_FILE_PATH_COMPONENTS {
                    return Err(ConfinedFilesystemError::WorkspaceRootTooDeep);
                }
                components.push(value.to_os_string());
            }
            Component::Prefix(_) | Component::CurDir | Component::ParentDir => {
                return Err(ConfinedFilesystemError::WorkspaceUnavailable);
            }
        }
    }
    if components.is_empty() {
        Err(ConfinedFilesystemError::WorkspaceUnavailable)
    } else {
        Ok(components)
    }
}

fn validate_not_protected(path: &WorkspaceRelativePath) -> Result<(), ConfinedFilesystemError> {
    if path.components().any(|component| {
        component.as_bytes().eq_ignore_ascii_case(b".git")
            || component
                .as_bytes()
                .eq_ignore_ascii_case(b".heterarchy-forge")
    }) {
        Err(ConfinedFilesystemError::ProtectedPath)
    } else {
        Ok(())
    }
}

pub(crate) fn walk_directories(
    root: &OwnedFd,
    components: &[OsString],
    committed: bool,
) -> Result<OwnedFd, ConfinedFilesystemError> {
    let mut current = dup(root).map_err(|source| ConfinedFilesystemError::Syscall {
        operation: FilesystemOperation::DuplicateRoot,
        committed,
        source,
    })?;
    for component in components {
        let stat = statat(&current, component, AtFlags::SYMLINK_NOFOLLOW).map_err(|source| {
            ConfinedFilesystemError::Syscall {
                operation: FilesystemOperation::InspectAncestor,
                committed,
                source,
            }
        })?;
        let actual = file_entry_kind(FileType::from_raw_mode(stat.st_mode));
        if actual != FileEntryKind::Directory {
            return if committed {
                Err(ConfinedFilesystemError::CommittedPathChanged)
            } else {
                Err(ConfinedFilesystemError::InvalidPathKind {
                    expected: FileEntryKind::Directory,
                    actual,
                })
            };
        }
        current = openat(
            &current,
            component,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|source| ConfinedFilesystemError::Syscall {
            operation: FilesystemOperation::OpenAncestor,
            committed,
            source,
        })?;
    }
    Ok(current)
}

#[cfg(target_os = "macos")]
pub(crate) fn reopen_workspace_root(
    workspace_root: &Path,
    committed: bool,
) -> Result<OwnedFd, ConfinedFilesystemError> {
    let root = open(
        workspace_root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|source| ConfinedFilesystemError::Syscall {
        operation: FilesystemOperation::OpenWorkspaceRoot,
        committed,
        source,
    })?;
    verify_resolved_workspace_root(&root, workspace_root, committed)?;
    Ok(root)
}

#[cfg(not(target_os = "macos"))]
fn reopen_workspace_root(
    filesystem_root: &OwnedFd,
    components: &[OsString],
    committed: bool,
) -> Result<OwnedFd, ConfinedFilesystemError> {
    walk_workspace_root_without_symlinks(filesystem_root, components, committed)
}

#[cfg(target_os = "macos")]
fn verify_resolved_workspace_root(
    root: &OwnedFd,
    expected_path: &Path,
    committed: bool,
) -> Result<(), ConfinedFilesystemError> {
    let resolved = rustix::fs::getpath(root).map_err(|source| ConfinedFilesystemError::StdIo {
        operation: FilesystemOperation::ResolveWorkspaceRoot,
        committed,
        source: source.into(),
    })?;
    if resolved.as_bytes() == expected_path.as_os_str().as_bytes() {
        Ok(())
    } else if committed {
        Err(ConfinedFilesystemError::CommittedPathChanged)
    } else {
        Err(ConfinedFilesystemError::PathChanged)
    }
}

#[cfg(not(target_os = "macos"))]
fn walk_workspace_root_without_symlinks(
    filesystem_root: &OwnedFd,
    components: &[OsString],
    committed: bool,
) -> Result<OwnedFd, ConfinedFilesystemError> {
    if components.is_empty() {
        return Err(ConfinedFilesystemError::InvalidPath);
    }
    let mut current = dup(filesystem_root).map_err(|source| ConfinedFilesystemError::Syscall {
        operation: FilesystemOperation::DuplicateRoot,
        committed,
        source,
    })?;
    for component in components {
        current = openat(
            &current,
            component,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|source| ConfinedFilesystemError::Syscall {
            operation: FilesystemOperation::OpenAncestor,
            committed,
            source,
        })?;
        if !FileType::from_raw_mode(
            fstat(&current)
                .map_err(|source| ConfinedFilesystemError::Syscall {
                    operation: FilesystemOperation::InspectAncestor,
                    committed,
                    source,
                })?
                .st_mode,
        )
        .is_dir()
        {
            return if committed {
                Err(ConfinedFilesystemError::CommittedPathChanged)
            } else {
                Err(ConfinedFilesystemError::NonDirectoryAncestor)
            };
        }
    }
    Ok(current)
}

fn observe_leaf(
    parent: &OwnedFd,
    basename: &OsStr,
) -> Result<FilePathState, ConfinedFilesystemError> {
    read_leaf(parent, basename, MAX_HASHED_FILE_BYTES, None)
        .map(|value| value.map_or(FilePathState::Absent, |read| read.state))
}

#[derive(Debug)]
struct OpenLeafRead {
    state: FilePathState,
    mode: CheckpointFileMode,
    retained: Vec<u8>,
    retained_complete: bool,
}

fn read_leaf(
    parent: &OwnedFd,
    basename: &OsStr,
    maximum: usize,
    retain_limit: Option<usize>,
) -> Result<Option<OpenLeafRead>, ConfinedFilesystemError> {
    let Some(fd) = open_regular_leaf(parent, basename)? else {
        return Ok(None);
    };
    let stat = fstat(&fd).map_err(pre_syscall)?;
    let size =
        usize::try_from(stat.st_size).map_err(|_| ConfinedFilesystemError::FileTooLarge {
            actual: usize::MAX,
            maximum,
        })?;
    if size > maximum {
        return Err(ConfinedFilesystemError::FileTooLarge {
            actual: size,
            maximum,
        });
    }
    let mut file = File::from(fd);
    let mut hasher = blake3::Hasher::new();
    let mut retained = Vec::with_capacity(retain_limit.map_or(0, |limit| size.min(limit)));
    let mut buffer = [0_u8; 8 * 1024];
    let mut total = 0_usize;
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|source| ConfinedFilesystemError::StdIo {
                operation: FilesystemOperation::ReadLeaf,
                committed: false,
                source,
            })?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read);
        if total > maximum {
            return Err(ConfinedFilesystemError::FileTooLarge {
                actual: total,
                maximum,
            });
        }
        hasher.update(&buffer[..read]);
        if let Some(limit) = retain_limit {
            let available = limit.saturating_sub(retained.len());
            retained.extend_from_slice(&buffer[..read.min(available)]);
        }
    }
    let after = fstat(&file).map_err(pre_syscall)?;
    if after.st_dev != stat.st_dev || after.st_ino != stat.st_ino || after.st_size != stat.st_size {
        return Err(ConfinedFilesystemError::StaleWrite);
    }
    let hash = FileContentHash::from_bytes(*hasher.finalize().as_bytes());
    let mode = CheckpointFileMode::new((stat.st_mode & 0o777) as u16)
        .map_err(|_| ConfinedFilesystemError::NonRegularLeaf)?;
    Ok(Some(OpenLeafRead {
        state: FilePathState::Regular {
            hash,
            size: FileByteCount::new(u64::try_from(total).map_err(|_| {
                ConfinedFilesystemError::FileTooLarge {
                    actual: total,
                    maximum,
                }
            })?),
        },
        mode,
        retained,
        retained_complete: retain_limit.is_some_and(|limit| total <= limit),
    }))
}

fn open_regular_leaf(
    parent: &OwnedFd,
    basename: &OsStr,
) -> Result<Option<OwnedFd>, ConfinedFilesystemError> {
    match openat(
        parent,
        basename,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => {
            require_regular_single_link(&fd)?;
            Ok(Some(fd))
        }
        Err(source) if source == Errno::NOENT => Ok(None),
        Err(source) if source == Errno::LOOP => Err(ConfinedFilesystemError::InvalidPathKind {
            expected: FileEntryKind::RegularFile,
            actual: FileEntryKind::SymbolicLink,
        }),
        Err(source) => Err(ConfinedFilesystemError::Syscall {
            operation: FilesystemOperation::OpenLeaf,
            committed: false,
            source,
        }),
    }
}

pub(crate) fn require_regular_single_link(fd: &OwnedFd) -> Result<(), ConfinedFilesystemError> {
    let stat = fstat(fd).map_err(pre_syscall)?;
    let actual = file_entry_kind(FileType::from_raw_mode(stat.st_mode));
    if actual != FileEntryKind::RegularFile {
        return Err(ConfinedFilesystemError::InvalidPathKind {
            expected: FileEntryKind::RegularFile,
            actual,
        });
    }
    if stat.st_nlink != 1 {
        return Err(ConfinedFilesystemError::HardlinkRejected);
    }
    Ok(())
}

fn file_entry_kind(file_type: FileType) -> FileEntryKind {
    if file_type.is_dir() {
        FileEntryKind::Directory
    } else if file_type.is_file() {
        FileEntryKind::RegularFile
    } else if file_type.is_symlink() {
        FileEntryKind::SymbolicLink
    } else {
        FileEntryKind::Other
    }
}

fn validate_precondition(
    kind: FileMutationKind,
    precondition: FilePrecondition,
    actual: FilePathState,
) -> Result<(), ConfinedFilesystemError> {
    match (kind, precondition, actual) {
        (FileMutationKind::Create, FilePrecondition::Absent, FilePathState::Absent) => Ok(()),
        (
            FileMutationKind::Replace | FileMutationKind::Delete,
            FilePrecondition::Matches(expected),
            FilePathState::Regular { hash, .. },
        ) if expected == hash => Ok(()),
        (FileMutationKind::Create, FilePrecondition::Absent, FilePathState::Regular { .. }) => {
            Err(ConfinedFilesystemError::PathConflict)
        }
        (
            FileMutationKind::Replace | FileMutationKind::Delete,
            FilePrecondition::Matches(_),
            FilePathState::Absent,
        ) => Err(ConfinedFilesystemError::NotFound),
        _ => Err(ConfinedFilesystemError::StaleWrite),
    }
}

fn validate_post_state(
    kind: FileMutationKind,
    state: FilePathState,
) -> Result<(), ConfinedFilesystemError> {
    if matches!(
        (kind, state),
        (
            FileMutationKind::Create | FileMutationKind::Replace,
            FilePathState::Regular { .. }
        ) | (FileMutationKind::Delete, FilePathState::Absent)
    ) {
        Ok(())
    } else {
        Err(ConfinedFilesystemError::PostStateMismatch)
    }
}

fn validate_post_content(
    kind: FileMutationKind,
    content: Option<&[u8]>,
    state: FilePathState,
    maximum: usize,
) -> Result<(), ConfinedFilesystemError> {
    match (kind, content, state) {
        (
            FileMutationKind::Create | FileMutationKind::Replace,
            Some(content),
            FilePathState::Regular { hash, .. },
        ) if content.len() <= maximum
            && FileContentHash::from_bytes(*blake3::hash(content).as_bytes()) == hash =>
        {
            Ok(())
        }
        (
            FileMutationKind::Create | FileMutationKind::Replace,
            Some(content),
            FilePathState::Regular { .. },
        ) if content.len() > maximum => Err(ConfinedFilesystemError::WriteTooLarge {
            actual: content.len(),
            maximum,
        }),
        (FileMutationKind::Delete, None, FilePathState::Absent) => Ok(()),
        _ => Err(ConfinedFilesystemError::PostStateMismatch),
    }
}

pub(crate) fn sync_file(file: &File) -> Result<(), Errno> {
    fsync(file)?;
    #[cfg(target_os = "macos")]
    rustix::fs::fcntl_fullfsync(file)?;
    Ok(())
}

fn sanitized_file_mode(mode: Mode) -> Mode {
    mode & (Mode::RWXU | Mode::RWXG | Mode::RWXO)
}

fn cleanup_temp(parent: &OwnedFd, temporary: &OsStr) -> Result<(), ConfinedFilesystemError> {
    unlinkat(parent, temporary, AtFlags::empty()).map_err(|source| {
        ConfinedFilesystemError::Syscall {
            operation: FilesystemOperation::CleanupTemporary,
            committed: false,
            source,
        }
    })
}

fn cleanup_after_std_error<T>(
    parent: &OwnedFd,
    temporary: &OsStr,
    operation: FilesystemOperation,
    source: std::io::Error,
) -> Result<T, ConfinedFilesystemError> {
    cleanup_temp(parent, temporary)?;
    Err(ConfinedFilesystemError::StdIo {
        operation,
        committed: false,
        source,
    })
}

fn cleanup_after_syscall_error<T>(
    parent: &OwnedFd,
    temporary: &OsStr,
    operation: FilesystemOperation,
    source: Errno,
) -> Result<T, ConfinedFilesystemError> {
    cleanup_temp(parent, temporary)?;
    Err(ConfinedFilesystemError::Syscall {
        operation,
        committed: false,
        source,
    })
}

fn map_create_temp_error(source: Errno) -> ConfinedFilesystemError {
    if source == Errno::EXIST {
        ConfinedFilesystemError::PathConflict
    } else {
        ConfinedFilesystemError::Syscall {
            operation: FilesystemOperation::CreateTemporary,
            committed: false,
            source,
        }
    }
}

fn pre_syscall(source: Errno) -> ConfinedFilesystemError {
    ConfinedFilesystemError::Syscall {
        operation: FilesystemOperation::InspectDescriptor,
        committed: false,
        source,
    }
}

/// Stable internal operation tag retained without disclosing absolute paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilesystemOperation {
    OpenFilesystemRoot,
    OpenWorkspaceRoot,
    ResolveWorkspaceRoot,
    DuplicateRoot,
    OpenAncestor,
    InspectAncestor,
    OpenLeaf,
    ReadLeaf,
    InspectDescriptor,
    OpenStateDirectory,
    InspectStateDirectory,
    RemoveStateEntry,
    RemoveStateRoot,
    SyncWorkspaceRoot,
    OpenDiffDirectory,
    OpenCheckpointStore,
    OpenMutationLock,
    LockMutation,
    CreateDirectory,
    CreateTemporary,
    SetTemporaryMode,
    WriteTemporary,
    SyncTemporary,
    PublishTemporary,
    CleanupTemporary,
    DeleteLeaf,
    MoveLeaf,
    SyncParent,
    SyncMoveSourceParent,
    SyncMoveDestinationParent,
    OpenDirectoryStream,
    ReadDirectory,
    InspectDirectoryEntry,
    ReadSourceSlice,
    ReadSourcePatch,
    ReadSearchFile,
}

/// Typed failure from the descriptor-relative filesystem boundary.
#[derive(Debug, Error)]
pub enum ConfinedFilesystemError {
    #[error("Workspace root is unavailable")]
    WorkspaceUnavailable,
    #[error("Workspace-relative path is invalid")]
    InvalidPath,
    #[error("Workspace-relative path has too many components")]
    TooManyComponents,
    #[error("Workspace root exceeds the descriptor-walk component bound")]
    WorkspaceRootTooDeep,
    #[error("protected Workspace path is inaccessible")]
    ProtectedPath,
    #[error("generated or Forge-owned path is excluded from source operations")]
    GeneratedPath,
    #[error("a symbolic link was rejected")]
    SymlinkRejected,
    #[error("an ancestor is not a directory")]
    NonDirectoryAncestor,
    #[error("the target is not a regular file")]
    NonRegularLeaf,
    #[error("path kind mismatch: expected {expected:?}, actual {actual:?}")]
    InvalidPathKind {
        expected: FileEntryKind,
        actual: FileEntryKind,
    },
    #[error("hard-linked files are rejected")]
    HardlinkRejected,
    #[error("the target was not found")]
    NotFound,
    #[error("the target path already exists")]
    PathConflict,
    #[error("the expected file content is stale")]
    StaleWrite,
    #[error("the Workspace path changed before the effect")]
    PathChanged,
    #[error("the Workspace path changed after the effect")]
    CommittedPathChanged,
    #[error("the file contains {actual} bytes; maximum is {maximum}")]
    FileTooLarge { actual: usize, maximum: usize },
    #[error("the replacement contains {actual} bytes; maximum is {maximum}")]
    WriteTooLarge { actual: usize, maximum: usize },
    #[error("file mutation payload does not match its operation")]
    InvalidPayload,
    #[error("exclusive atomic create is unsupported on this filesystem")]
    AtomicCreateUnsupported,
    #[error("exclusive atomic move is unsupported on this filesystem")]
    AtomicMoveUnsupported,
    #[error("the bounded Forge-writer lock is busy")]
    LockBusy,
    #[error("Forge state removal exceeds its {maximum} entry bound")]
    StateRemovalTooLarge { maximum: usize },
    #[error("Forge state removal exceeds its {maximum} directory-depth bound")]
    StateRemovalTooDeep { maximum: usize },
    #[error("the observed POST state does not match the requested mutation")]
    PostStateMismatch,
    #[error("source patch was rejected: {0}")]
    SourcePatch(#[source] forge_domain::FilePatchError),
    #[error("source slice was rejected: {0}")]
    SourceSlice(#[source] forge_domain::FileReadSliceError),
    #[error("source search query produced invalid text")]
    SourceSearchNonUtf8,
    #[error("source search line count overflowed")]
    SourceSearchLineOverflow,
    #[error("source search result contains an invalid match")]
    TextSearchMatch(#[source] forge_domain::TextSearchMatchError),
    #[error("source search result is invalid")]
    TextSearchResult(#[source] forge_domain::TextSearchResultError),
    #[error("file-list result is invalid")]
    FileListResult(#[source] forge_domain::FileListResultError),
    #[error("filesystem operation output has {actual} bytes; maximum is {maximum}")]
    OutputTooLarge { actual: usize, maximum: usize },
    #[error("the filesystem effect committed but its POST state could not be confirmed")]
    CommittedObservationFailed,
    #[error("filesystem operation {operation:?} failed")]
    Syscall {
        operation: FilesystemOperation,
        committed: bool,
        #[source]
        source: Errno,
    },
    #[error("filesystem operation {operation:?} failed")]
    StdIo {
        operation: FilesystemOperation,
        committed: bool,
        #[source]
        source: std::io::Error,
    },
}

impl ConfinedFilesystemError {
    pub const fn effect_may_have_committed(&self) -> bool {
        match self {
            Self::CommittedPathChanged | Self::CommittedObservationFailed => true,
            Self::Syscall { committed, .. } | Self::StdIo { committed, .. } => *committed,
            Self::WorkspaceUnavailable
            | Self::InvalidPath
            | Self::TooManyComponents
            | Self::WorkspaceRootTooDeep
            | Self::ProtectedPath
            | Self::GeneratedPath
            | Self::SymlinkRejected
            | Self::NonDirectoryAncestor
            | Self::NonRegularLeaf
            | Self::InvalidPathKind { .. }
            | Self::HardlinkRejected
            | Self::NotFound
            | Self::PathConflict
            | Self::StaleWrite
            | Self::PathChanged
            | Self::FileTooLarge { .. }
            | Self::WriteTooLarge { .. }
            | Self::InvalidPayload
            | Self::AtomicCreateUnsupported
            | Self::AtomicMoveUnsupported
            | Self::LockBusy
            | Self::StateRemovalTooLarge { .. }
            | Self::StateRemovalTooDeep { .. }
            | Self::PostStateMismatch
            | Self::SourcePatch(_)
            | Self::SourceSlice(_)
            | Self::SourceSearchNonUtf8
            | Self::SourceSearchLineOverflow
            | Self::TextSearchMatch(_)
            | Self::TextSearchResult(_)
            | Self::FileListResult(_)
            | Self::OutputTooLarge { .. } => false,
        }
    }

    pub const fn failure_code(&self) -> FileMutationFailureCode {
        match self {
            Self::InvalidPath | Self::TooManyComponents => FileMutationFailureCode::InvalidPath,
            Self::ProtectedPath | Self::GeneratedPath => FileMutationFailureCode::ProtectedPath,
            Self::NotFound
            | Self::PathConflict
            | Self::PathChanged
            | Self::CommittedPathChanged
            | Self::CommittedObservationFailed
            | Self::PostStateMismatch => FileMutationFailureCode::PathConflict,
            Self::StaleWrite => FileMutationFailureCode::StaleWrite,
            Self::FileTooLarge { .. }
            | Self::WriteTooLarge { .. }
            | Self::LockBusy
            | Self::StateRemovalTooLarge { .. }
            | Self::StateRemovalTooDeep { .. }
            | Self::OutputTooLarge { .. } => FileMutationFailureCode::CapacityExceeded,
            Self::WorkspaceUnavailable
            | Self::WorkspaceRootTooDeep
            | Self::SymlinkRejected
            | Self::NonDirectoryAncestor
            | Self::NonRegularLeaf
            | Self::InvalidPathKind { .. }
            | Self::HardlinkRejected
            | Self::InvalidPayload
            | Self::AtomicCreateUnsupported
            | Self::AtomicMoveUnsupported
            | Self::SourcePatch(_)
            | Self::SourceSlice(_)
            | Self::SourceSearchNonUtf8
            | Self::SourceSearchLineOverflow
            | Self::TextSearchMatch(_)
            | Self::TextSearchResult(_)
            | Self::FileListResult(_)
            | Self::Syscall { .. }
            | Self::StdIo { .. } => FileMutationFailureCode::IoFailure,
        }
    }

    fn with_committed(self, committed: bool) -> Self {
        match self {
            Self::Syscall {
                operation, source, ..
            } => Self::Syscall {
                operation,
                committed,
                source,
            },
            Self::StdIo {
                operation, source, ..
            } => Self::StdIo {
                operation,
                committed,
                source,
            },
            Self::PathChanged if committed => Self::CommittedPathChanged,
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;
    use std::fs;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    use uuid::Uuid;

    use super::*;
    use crate::{WorkspaceStateExclusiveGate, WorkspaceStateLayout};
    use forge_domain::{
        FileListOptions, FilePatch, FilePatchHunk, SourceEol, SourceLineRange, SourceRangeHash,
        TextSearchOptions, TextSearchQuery,
    };

    fn root(label: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let unique = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let root = std::env::temp_dir().join(format!("forge-confined-{label}-{unique}"));
        fs::create_dir_all(&root)?;
        Ok(root)
    }

    fn confined(
        root: &Path,
    ) -> Result<(WorkspaceStateLayout, ConfinedWorkspace), Box<dyn std::error::Error>> {
        let layout = WorkspaceStateLayout::initialize(root)?;
        let existing = WorkspaceStateLayout::inspect_existing(root)?.ok_or("missing layout")?;
        let confined = ConfinedWorkspace::open(&existing)?;
        Ok((layout, confined))
    }

    fn relative(path: &str) -> Result<WorkspaceRelativePath, Box<dyn std::error::Error>> {
        Ok(WorkspaceRelativePath::new(PathBuf::from(path))?)
    }

    fn mutation_id(value: u128) -> FileMutationId {
        FileMutationId::from_uuid(Uuid::from_u128(value))
    }

    #[test]
    fn state_removal_unlinks_a_symlink_without_touching_its_target()
    -> Result<(), Box<dyn std::error::Error>> {
        let workspace_root = root("state-removal-symlink")?;
        let outside = root("state-removal-outside")?;
        let outside_file = outside.join("preserved.txt");
        fs::write(&outside_file, b"preserved")?;
        let layout = WorkspaceStateLayout::initialize(&workspace_root)?;
        let existing =
            WorkspaceStateLayout::inspect_existing(&workspace_root)?.ok_or("missing layout")?;
        symlink(&outside, existing.state_root().join("outside-link"))?;
        let confined = ConfinedWorkspace::open(&existing)?;
        let gate = WorkspaceStateExclusiveGate::acquire(
            layout.workspace_root(),
            layout.root_fingerprint()?,
        )?;
        let guard = confined.acquire_write_guard()?;
        confined.preflight_owned_state_removal(&gate, &guard)?;
        assert_eq!(
            confined.remove_owned_state_directory(&gate, &guard)?,
            WorkspaceStateRemoval::Removed
        );
        assert_eq!(fs::read(&outside_file)?, b"preserved");
        assert!(!existing.state_root().exists());
        drop(guard);
        drop(gate);
        fs::remove_dir_all(workspace_root)?;
        fs::remove_dir_all(outside)?;
        Ok(())
    }

    #[test]
    fn state_removal_rejects_a_write_guard_from_another_workspace()
    -> Result<(), Box<dyn std::error::Error>> {
        let first_root = root("state-removal-first")?;
        let second_root = root("state-removal-second")?;
        let first_layout = WorkspaceStateLayout::initialize(&first_root)?;
        let second_layout = WorkspaceStateLayout::initialize(&second_root)?;
        let first_existing =
            WorkspaceStateLayout::inspect_existing(&first_root)?.ok_or("missing first layout")?;
        let second_existing =
            WorkspaceStateLayout::inspect_existing(&second_root)?.ok_or("missing second layout")?;
        let first = ConfinedWorkspace::open(&first_existing)?;
        let second = ConfinedWorkspace::open(&second_existing)?;
        let gate = WorkspaceStateExclusiveGate::acquire(
            first_layout.workspace_root(),
            first_layout.root_fingerprint()?,
        )?;
        let foreign_guard = second.acquire_write_guard()?;
        assert!(matches!(
            first.preflight_owned_state_removal(&gate, &foreign_guard),
            Err(ConfinedFilesystemError::PathChanged)
        ));
        drop(foreign_guard);
        drop(gate);
        drop(second_layout);
        fs::remove_dir_all(first_root)?;
        fs::remove_dir_all(second_root)?;
        Ok(())
    }

    #[test]
    fn read_hashes_native_unicode_regular_files_without_loss()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = root("read-native")?;
        let (_layout, confined) = confined(&root)?;
        let native = OsString::from_vec(b"native-\xC3\xA9.txt".to_vec());
        fs::write(root.join(&native), b"hello")?;
        let path = WorkspaceRelativePath::new(PathBuf::from(native))?;
        let read = confined.read(&path)?;
        let content_pointer = read.content().as_ptr();
        assert_eq!(
            read.state().hash(),
            Some(FileContentHash::from_bytes(
                *blake3::hash(b"hello").as_bytes()
            ))
        );
        let content = read.into_content();
        assert_eq!(content.as_ptr(), content_pointer);
        assert_eq!(content, b"hello");
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn protected_symlink_and_hardlink_paths_fail_closed() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = root("unsafe-paths")?;
        let (_layout, confined) = confined(&root)?;
        assert!(matches!(
            confined.observe(&relative(".git/config")?),
            Err(ConfinedFilesystemError::ProtectedPath)
        ));
        assert!(matches!(
            confined.observe(&relative(".GIT/config")?),
            Err(ConfinedFilesystemError::ProtectedPath)
        ));
        assert!(matches!(
            confined.observe(&relative(".HETERARCHY-FORGE/FORMAT")?),
            Err(ConfinedFilesystemError::ProtectedPath)
        ));
        let outside = root.with_extension("outside");
        fs::create_dir_all(&outside)?;
        fs::write(outside.join("secret"), b"secret")?;
        symlink(&outside, root.join("link"))?;
        assert!(confined.observe(&relative("link/secret")?).is_err());
        symlink(outside.join("secret"), root.join("leaf-link"))?;
        assert!(matches!(
            confined.observe(&relative("leaf-link")?),
            Err(ConfinedFilesystemError::InvalidPathKind {
                expected: FileEntryKind::RegularFile,
                actual: FileEntryKind::SymbolicLink,
            })
        ));
        fs::hard_link(outside.join("secret"), root.join("hard"))?;
        assert!(matches!(
            confined.observe(&relative("hard")?),
            Err(ConfinedFilesystemError::HardlinkRejected)
        ));
        fs::remove_dir_all(root)?;
        fs::remove_dir_all(outside)?;
        Ok(())
    }

    #[test]
    fn create_replace_restore_delete_are_atomic_and_hash_cas_bound()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = root("mutations")?;
        let (_layout, confined) = confined(&root)?;
        let path = relative("file.txt")?;
        let create_plan = FileMutationPlan::new(
            path.clone(),
            FileMutationKind::Create,
            FilePrecondition::Absent,
        );
        let created = confined
            .prepare_mutation(&create_plan)?
            .apply(mutation_id(1), Some(b"one"))?;
        let created_hash = created.post_state().hash().ok_or("hash missing")?;
        assert_eq!(fs::read(root.join("file.txt"))?, b"one");
        fs::set_permissions(root.join("file.txt"), fs::Permissions::from_mode(0o666))?;

        let replace_plan = FileMutationPlan::new(
            path.clone(),
            FileMutationKind::Replace,
            FilePrecondition::Matches(created_hash),
        );
        let replaced = confined
            .prepare_mutation(&replace_plan)?
            .apply(mutation_id(2), Some(b"two"))?;
        let replaced_hash = replaced.post_state().hash().ok_or("hash missing")?;
        assert_ne!(created_hash, replaced_hash);
        assert_eq!(fs::read(root.join("file.txt"))?, b"two");
        assert_eq!(
            fs::metadata(root.join("file.txt"))?.permissions().mode() & 0o777,
            0o666
        );

        let restore_plan = FileMutationPlan::new(
            path.clone(),
            FileMutationKind::Replace,
            FilePrecondition::Matches(replaced_hash),
        );
        let restored = confined
            .prepare_mutation(&restore_plan)?
            .apply_restored_content(mutation_id(3), b"restored", CheckpointFileMode::new(0o751)?)?;
        let restored_hash = restored.post_state().hash().ok_or("hash missing")?;
        assert_eq!(fs::read(root.join("file.txt"))?, b"restored");
        assert_eq!(
            fs::metadata(root.join("file.txt"))?.permissions().mode() & 0o777,
            0o751
        );

        let delete_plan = FileMutationPlan::new(
            path,
            FileMutationKind::Delete,
            FilePrecondition::Matches(restored_hash),
        );
        let deleted = confined
            .prepare_mutation(&delete_plan)?
            .apply(mutation_id(4), None)?;
        assert_eq!(deleted.post_state(), FilePathState::Absent);
        assert!(!root.join("file.txt").exists());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn prepared_mutation_revalidates_a_deep_absolute_root() -> Result<(), Box<dyn std::error::Error>>
    {
        let base = root("deep-absolute-root")?;
        let workspace_root = base.join("outer/inner/workspace");
        fs::create_dir_all(&workspace_root)?;
        let (_layout, confined) = confined(&workspace_root)?;
        fs::create_dir(workspace_root.join("nested"))?;

        let path = relative("nested/probe.txt")?;
        let created = confined
            .prepare_mutation(&FileMutationPlan::new(
                path.clone(),
                FileMutationKind::Create,
                FilePrecondition::Absent,
            ))?
            .apply(mutation_id(11), Some(b"one"))?;
        let created_hash = created.post_state().hash().ok_or("created hash missing")?;

        let replaced = confined
            .prepare_mutation(&FileMutationPlan::new(
                path.clone(),
                FileMutationKind::Replace,
                FilePrecondition::Matches(created_hash),
            ))?
            .apply(mutation_id(12), Some(b"two"))?;
        let replaced_hash = replaced
            .post_state()
            .hash()
            .ok_or("replaced hash missing")?;

        let deleted = confined
            .prepare_mutation(&FileMutationPlan::new(
                path,
                FileMutationKind::Delete,
                FilePrecondition::Matches(replaced_hash),
            ))?
            .apply(mutation_id(13), None)?;
        assert_eq!(deleted.post_state(), FilePathState::Absent);
        assert!(!workspace_root.join("nested/probe.txt").exists());

        fs::remove_dir_all(base)?;
        Ok(())
    }

    #[test]
    fn prepared_move_revalidates_a_deep_absolute_root() -> Result<(), Box<dyn std::error::Error>> {
        let base = root("deep-absolute-move")?;
        let workspace_root = base.join("outer/inner/workspace");
        fs::create_dir_all(workspace_root.join("from"))?;
        fs::create_dir(workspace_root.join("to"))?;
        fs::write(workspace_root.join("from/source.txt"), b"source")?;
        let (_layout, confined) = confined(&workspace_root)?;

        let source = relative("from/source.txt")?;
        let destination = relative("to/destination.txt")?;
        let expected = confined
            .observe(&source)?
            .hash()
            .ok_or("source hash missing")?;
        let applied = confined
            .prepare_move(&source, expected, &destination)?
            .apply()?;

        assert_eq!(applied.source_post_state(), FilePathState::Absent);
        assert_eq!(applied.destination_post_state().hash(), Some(expected));
        assert_eq!(
            fs::read(workspace_root.join("to/destination.txt"))?,
            b"source"
        );

        fs::remove_dir_all(base)?;
        Ok(())
    }

    #[test]
    fn move_is_atomic_hash_cas_bound_and_never_replaces_destination()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = root("move")?;
        let (_layout, confined) = confined(&root)?;
        fs::create_dir(root.join("from"))?;
        fs::create_dir(root.join("to"))?;
        fs::write(root.join("from/source.rs"), b"fn moved() {}\n")?;
        fs::set_permissions(
            root.join("from/source.rs"),
            fs::Permissions::from_mode(0o640),
        )?;

        let source = relative("from/source.rs")?;
        let destination = relative("to/destination.rs")?;
        let expected = confined.observe(&source)?.hash().ok_or("hash missing")?;
        let applied = confined
            .prepare_move(&source, expected, &destination)?
            .apply()?;

        assert_eq!(applied.source_pre_state().hash(), Some(expected));
        assert_eq!(applied.source_post_state(), FilePathState::Absent);
        assert_eq!(applied.destination_pre_state(), FilePathState::Absent);
        assert_eq!(applied.destination_post_state().hash(), Some(expected));
        assert_eq!(applied.source_pre_source().text(), Some("fn moved() {}\n"));
        assert!(!root.join("from/source.rs").exists());
        assert_eq!(
            fs::read(root.join("to/destination.rs"))?,
            b"fn moved() {}\n"
        );
        assert_eq!(
            fs::metadata(root.join("to/destination.rs"))?
                .permissions()
                .mode()
                & 0o777,
            0o640
        );

        fs::write(root.join("from/second.rs"), b"second")?;
        fs::write(root.join("to/existing.rs"), b"existing")?;
        let second = relative("from/second.rs")?;
        let existing = relative("to/existing.rs")?;
        let second_hash = confined.observe(&second)?.hash().ok_or("hash missing")?;
        assert!(matches!(
            confined.prepare_move(&second, second_hash, &existing),
            Err(ConfinedFilesystemError::PathConflict)
        ));
        assert_eq!(fs::read(root.join("from/second.rs"))?, b"second");
        assert_eq!(fs::read(root.join("to/existing.rs"))?, b"existing");

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn move_revalidates_both_endpoints_before_effect() -> Result<(), Box<dyn std::error::Error>> {
        let root = root("move-stale")?;
        let (_layout, confined) = confined(&root)?;
        fs::create_dir(root.join("from"))?;
        fs::create_dir(root.join("to"))?;
        fs::write(root.join("from/source.rs"), b"original")?;
        let source = relative("from/source.rs")?;
        let destination = relative("to/destination.rs")?;
        let expected = confined.observe(&source)?.hash().ok_or("hash missing")?;
        let prepared = confined.prepare_move(&source, expected, &destination)?;

        fs::write(root.join("to/destination.rs"), b"external")?;
        assert!(matches!(
            prepared.apply(),
            Err(ConfinedFilesystemError::PathConflict)
        ));
        assert_eq!(fs::read(root.join("from/source.rs"))?, b"original");
        assert_eq!(fs::read(root.join("to/destination.rs"))?, b"external");

        let other_destination = relative("to/other.rs")?;
        let prepared = confined.prepare_move(&source, expected, &other_destination)?;
        fs::write(root.join("from/source.rs"), b"changed")?;
        assert!(matches!(
            prepared.apply(),
            Err(ConfinedFilesystemError::StaleWrite)
        ));
        assert_eq!(fs::read(root.join("from/source.rs"))?, b"changed");
        assert!(!root.join("to/other.rs").exists());

        assert!(matches!(
            confined.prepare_move(&source, expected, &source),
            Err(ConfinedFilesystemError::PathConflict)
        ));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn mutation_capture_is_bounded_classified_and_secret_safe_in_debug()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = root("diff-capture")?;
        let (_layout, confined) = confined(&root)?;
        fs::write(root.join("text.txt"), b"token = do-not-log\n")?;
        let text_path = relative("text.txt")?;
        let text_hash = confined.observe(&text_path)?.hash().ok_or("hash missing")?;
        let prepared = confined.prepare_mutation(&FileMutationPlan::new(
            text_path,
            FileMutationKind::Replace,
            FilePrecondition::Matches(text_hash),
        ))?;
        assert_eq!(prepared.pre_source().text(), Some("token = do-not-log\n"));
        assert!(!format!("{:?}", prepared.pre_source()).contains("do-not-log"));
        let applied = prepared.apply(mutation_id(7), Some(b"binary\0payload"))?;
        assert!(matches!(applied.pre_source(), CapturedDiffSource::Text(_)));
        assert!(matches!(
            applied.post_source(),
            CapturedDiffSource::Binary { size } if size.get() == 14
        ));

        let oversized_bytes = vec![b'x'; MAX_DIFF_SOURCE_BYTES + 1];
        fs::write(root.join("large.txt"), &oversized_bytes)?;
        let large_path = relative("large.txt")?;
        let large_hash = confined
            .observe(&large_path)?
            .hash()
            .ok_or("hash missing")?;
        let prepared = confined.prepare_mutation(&FileMutationPlan::new(
            large_path,
            FileMutationKind::Delete,
            FilePrecondition::Matches(large_hash),
        ))?;
        assert!(matches!(
            prepared.pre_source(),
            CapturedDiffSource::Oversized { size }
                if size.get() == (MAX_DIFF_SOURCE_BYTES + 1) as u64
        ));
        let applied = prepared.apply(mutation_id(8), None)?;
        assert_eq!(applied.post_source(), &CapturedDiffSource::Absent);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn stale_external_write_after_prepare_is_rejected_without_overwrite()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = root("stale")?;
        let (_layout, confined) = confined(&root)?;
        fs::write(root.join("file.txt"), b"one")?;
        let path = relative("file.txt")?;
        let expected = confined.observe(&path)?.hash().ok_or("hash missing")?;
        let prepared = confined.prepare_mutation(&FileMutationPlan::new(
            path,
            FileMutationKind::Replace,
            FilePrecondition::Matches(expected),
        ))?;
        fs::write(root.join("file.txt"), b"external")?;
        assert!(matches!(
            prepared.apply(mutation_id(4), Some(b"forge")),
            Err(ConfinedFilesystemError::StaleWrite)
        ));
        assert_eq!(fs::read(root.join("file.txt"))?, b"external");
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn renamed_parent_replaced_by_outside_symlink_is_rejected_before_effect()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = root("parent-race")?;
        let (_layout, confined) = confined(&root)?;
        fs::create_dir(root.join("src"))?;
        fs::write(root.join("src/file.txt"), b"one")?;
        let outside = root.with_extension("outside");
        fs::create_dir_all(&outside)?;
        fs::write(outside.join("file.txt"), b"outside")?;
        let path = relative("src/file.txt")?;
        let expected = confined.observe(&path)?.hash().ok_or("hash missing")?;
        let prepared = confined.prepare_mutation(&FileMutationPlan::new(
            path,
            FileMutationKind::Replace,
            FilePrecondition::Matches(expected),
        ))?;
        fs::rename(root.join("src"), root.join("moved"))?;
        symlink(&outside, root.join("src"))?;
        assert!(prepared.apply(mutation_id(5), Some(b"forge")).is_err());
        assert_eq!(fs::read(outside.join("file.txt"))?, b"outside");
        assert_eq!(fs::read(root.join("moved/file.txt"))?, b"one");
        fs::remove_dir_all(root)?;
        fs::remove_dir_all(outside)?;
        Ok(())
    }

    #[test]
    fn renamed_workspace_root_is_rejected_before_effect() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = root("root-race")?;
        let (_layout, confined) = confined(&root)?;
        fs::write(root.join("file.txt"), b"one")?;
        let path = relative("file.txt")?;
        let expected = confined.observe(&path)?.hash().ok_or("hash missing")?;
        let prepared = confined.prepare_mutation(&FileMutationPlan::new(
            path,
            FileMutationKind::Replace,
            FilePrecondition::Matches(expected),
        ))?;
        let moved = root.with_extension("moved");
        fs::rename(&root, &moved)?;
        fs::create_dir_all(&root)?;
        fs::write(root.join("file.txt"), b"replacement")?;
        assert!(matches!(
            prepared.apply(mutation_id(6), Some(b"forge")),
            Err(ConfinedFilesystemError::PathChanged
                | ConfinedFilesystemError::Syscall {
                    committed: false,
                    ..
                })
        ));
        assert_eq!(fs::read(moved.join("file.txt"))?, b"one");
        assert_eq!(fs::read(root.join("file.txt"))?, b"replacement");
        fs::remove_dir_all(root)?;
        fs::remove_dir_all(moved)?;
        Ok(())
    }

    #[test]
    fn post_content_must_match_the_intended_write_hash() {
        let intended = b"intended";
        let other = FilePathState::Regular {
            hash: FileContentHash::from_bytes(*blake3::hash(b"other").as_bytes()),
            size: FileByteCount::new(5),
        };
        assert!(matches!(
            validate_post_content(
                FileMutationKind::Replace,
                Some(intended),
                other,
                MAX_FILE_WRITE_BYTES,
            ),
            Err(ConfinedFilesystemError::PostStateMismatch)
        ));
    }

    #[test]
    fn file_list_is_one_directory_bounded_sorted_and_filters_generated_entries()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = root("list-source")?;
        let (_layout, confined) = confined(&root)?;
        fs::write(root.join("z.rs"), b"z")?;
        fs::write(root.join("a.rs"), b"a")?;
        fs::create_dir(root.join("src"))?;
        fs::create_dir(root.join("target"))?;
        fs::create_dir(root.join(".git"))?;
        fs::create_dir(root.join(".cache"))?;
        fs::create_dir(root.join(".ruff_cache"))?;
        let result = confined.file_list(None, FileListOptions::default())?;
        let names: Vec<_> = result
            .entries()
            .iter()
            .map(|entry| entry.path().as_path().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["a.rs", "src", "z.rs"]);
        assert!(!result.truncated());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn text_search_is_literal_recursive_and_does_not_follow_symlinks()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = root("search-source")?;
        let (_layout, confined) = confined(&root)?;
        fs::create_dir(root.join("src"))?;
        fs::write(root.join("src/nested.rs"), b"needle[here]\nother\n")?;
        fs::write(root.join("literal.rs"), b"needle.*not-regex\n")?;
        fs::create_dir_all(root.join(".ruff_cache/0.15.12"))?;
        fs::write(
            root.join(".ruff_cache/0.15.12/cache.db"),
            b"needle[cache]\n",
        )?;
        let outside = root.with_extension("search-outside");
        fs::create_dir_all(&outside)?;
        fs::write(outside.join("secret.rs"), b"needle[secret]\n")?;
        symlink(&outside, root.join("linked"))?;
        let query = TextSearchQuery::new("needle[".to_owned())?;
        let result = confined.text_search(None, &query, TextSearchOptions::default())?;
        assert_eq!(result.matches().len(), 1);
        assert_eq!(
            result.matches()[0].path().as_path(),
            Path::new("src/nested.rs")
        );
        assert_eq!(result.matches()[0].line(), 1);
        assert!(!result.truncated());
        fs::remove_dir_all(root)?;
        fs::remove_dir_all(outside)?;
        Ok(())
    }

    #[test]
    fn file_read_slice_streams_large_source_and_preserves_line_metadata()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = root("slice-source")?;
        let (_layout, confined) = confined(&root)?;
        let mut source = String::new();
        for index in 0..20_000 {
            let _ = writeln!(source, "line-{index}");
        }
        fs::write(root.join("large.rs"), source.as_bytes())?;
        let slice = confined.file_read_slice(
            &relative("large.rs")?,
            SourceLineRange::new(10_000, 10_002)?,
        )?;
        assert_eq!(slice.start_line(), 10_000);
        assert_eq!(slice.end_line(), 10_002);
        assert_eq!(slice.total_lines(), 20_000);
        assert_eq!(slice.eol(), SourceEol::Lf);
        assert!(slice.has_final_newline());
        assert_eq!(slice.content(), b"line-9999\nline-10000\nline-10001\n");
        assert_eq!(
            slice.range_hash(),
            SourceRangeHash::from_bytes(*blake3::hash(slice.content()).as_bytes())
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn source_file_read_reports_typed_directory_path_kind() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = root("path-kind")?;
        let (_layout, confined) = confined(&root)?;
        fs::create_dir(root.join("directory"))?;
        let Err(error) =
            confined.file_read_slice(&relative("directory")?, SourceLineRange::new(1, 1)?)
        else {
            return Err("directory path must not be read as a source file".into());
        };
        assert!(matches!(
            error,
            ConfinedFilesystemError::InvalidPathKind {
                expected: FileEntryKind::RegularFile,
                actual: FileEntryKind::Directory,
            }
        ));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn compile_file_patch_reads_large_source_and_rejects_stale_hash()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = root("patch-source")?;
        let (_layout, confined) = confined(&root)?;
        let source = vec![b'a'; 16 * 1024];
        fs::write(root.join("large.rs"), &source)?;
        let whole_hash = FileContentHash::from_bytes(*blake3::hash(&source).as_bytes());
        let range_hash = SourceRangeHash::from_bytes(*blake3::hash(&source).as_bytes());
        let patch = FilePatch::new(
            whole_hash,
            vec![FilePatchHunk::new(
                SourceLineRange::new(1, 1)?,
                range_hash,
                b"replacement".to_vec(),
            )?],
        )?;
        let (compiled, _review) = confined
            .compile_file_patch(&relative("large.rs")?, &patch)?
            .into_parts();
        assert_eq!(compiled.content(), b"replacement");
        let stale = FilePatch::new(
            FileContentHash::from_bytes([3; FileContentHash::BYTE_LEN]),
            vec![FilePatchHunk::new(
                SourceLineRange::new(1, 1)?,
                range_hash,
                b"replacement".to_vec(),
            )?],
        )?;
        assert!(matches!(
            confined.compile_file_patch(&relative("large.rs")?, &stale),
            Err(ConfinedFilesystemError::SourcePatch(
                forge_domain::FilePatchError::StaleWholeFileHash
            ))
        ));
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
