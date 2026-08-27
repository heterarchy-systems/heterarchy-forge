use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

use forge_domain::{
    CheckpointFileMode, FileByteCount, FileContentHash, FileMutationFailureCode, FileMutationId,
    FileMutationKind, FileMutationPlan, FilePathState, FilePrecondition, WorkspaceRelativePath,
    WorkspaceRootFingerprint,
};
use rustix::fs::{
    AtFlags, FileType, FlockOperation, Mode, OFlags, RenameFlags, fchmod, fstat, fsync, mkdirat,
    open, openat, renameat, renameat_with, unlinkat,
};
use rustix::io::{Errno, dup};
use thiserror::Error;

use crate::ExistingWorkspaceStateLayout;
use crate::diff_artifact::{DiffArtifactStore, DiffArtifactStoreParts};

/// Maximum number of native path components walked for one request.
pub const MAX_FILE_PATH_COMPONENTS: usize = 128;
/// Maximum file bytes returned by the first control-plane read surface.
pub const MAX_FILE_READ_BYTES: usize = 32 * 1024;
/// Maximum existing target bytes hashed for CAS in the first mutation slice.
pub const MAX_HASHED_FILE_BYTES: usize = 1024 * 1024;
/// Maximum replacement payload accepted by the first bounded mutation slice.
pub const MAX_FILE_WRITE_BYTES: usize = 8 * 1024;
/// Maximum source bytes retained in memory for one human-review Diff side.
///
/// Files larger than this remain hashable for compare-and-swap, but their
/// Diff Evidence is deliberately summary-only.
pub const MAX_DIFF_SOURCE_BYTES: usize = 64 * 1024;

const LOCK_RETRY_LIMIT: u32 = 1_000;
const LOCK_OPEN_RETRY_LIMIT: u32 = 32;
const LOCK_RETRY_DELAY: Duration = Duration::from_millis(1);
const STATE_DIRECTORY: &str = ".heterarchy-forge";
const MUTATION_LOCK_FILE: &str = "file-mutation.lock";
const TEMP_PREFIX: &str = ".heterarchy-forge-tmp-";
const MANAGED_TEMP_PREFIX: &str = ".heterarchy-forge-managed-tmp-";
static NEXT_MANAGED_TEMP: AtomicU64 = AtomicU64::new(1);

/// Validate and hash one bounded create/replace payload before durable intent
/// persistence. This is the same algorithm used for observed POST state.
pub fn bounded_write_content_hash(
    content: &[u8],
) -> Result<FileContentHash, ConfinedFilesystemError> {
    if content.len() > MAX_FILE_WRITE_BYTES {
        return Err(ConfinedFilesystemError::WriteTooLarge {
            actual: content.len(),
            maximum: MAX_FILE_WRITE_BYTES,
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

    fn from_payload(content: &[u8]) -> Self {
        Self::from_retained(
            content.to_vec(),
            FileByteCount::new(content.len() as u64),
            true,
        )
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
    filesystem_root: OwnedFd,
    root_components: Vec<OsString>,
    root: OwnedFd,
    root_identity: DirectoryIdentity,
    state_identity: DirectoryIdentity,
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
        let root_components = collect_absolute_components(layout.workspace_root())?;
        let root = walk_directories(&filesystem_root, &root_components, false)?;
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
            workspace_root: layout.workspace_root().to_path_buf(),
            filesystem_root,
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

    /// Observe one Harness-managed target without retaining its bytes.
    ///
    /// Missing ancestors are projected as an absent target so read-only
    /// installation Preview can distinguish `Create` from a real confinement
    /// failure without resolving a multi-component path outside descriptor
    /// ownership. Symlinks, non-directory ancestors, non-regular leaves, and
    /// files above the caller-owned bound still fail closed.
    pub(crate) fn observe_bounded_file_state(
        &self,
        path: &WorkspaceRelativePath,
        maximum: usize,
    ) -> Result<FilePathState, ConfinedFilesystemError> {
        self.ensure_root()?;
        validate_not_protected(path)?;
        let components = collect_components(path)?;
        let (basename, ancestors) = components
            .split_last()
            .ok_or(ConfinedFilesystemError::InvalidPath)?;
        let parent = match walk_directories(&self.root, ancestors, false) {
            Ok(parent) => parent,
            Err(ConfinedFilesystemError::Syscall {
                operation: FilesystemOperation::OpenAncestor,
                source,
                ..
            }) if source == Errno::NOENT => return Ok(FilePathState::Absent),
            Err(error) => return Err(error),
        };
        let state = read_leaf(&parent, basename, maximum, None)?
            .map_or(FilePathState::Absent, |read| read.state);
        self.ensure_root()?;
        Ok(state)
    }

    /// Read one bounded regular file for Harness merge/materialization.
    /// Missing ancestors are treated as an absent target; unsafe path shapes
    /// and non-regular targets fail closed.
    pub(crate) fn read_bounded_file(
        &self,
        path: &WorkspaceRelativePath,
        maximum: usize,
    ) -> Result<Option<ConfinedFileRead>, ConfinedFilesystemError> {
        self.ensure_root()?;
        validate_not_protected(path)?;
        let components = collect_components(path)?;
        let (basename, ancestors) = components
            .split_last()
            .ok_or(ConfinedFilesystemError::InvalidPath)?;
        let parent = match walk_directories(&self.root, ancestors, false) {
            Ok(parent) => parent,
            Err(ConfinedFilesystemError::Syscall {
                operation: FilesystemOperation::OpenAncestor,
                source,
                ..
            }) if source == Errno::NOENT => return Ok(None),
            Err(error) => return Err(error),
        };
        let Some(result) = read_leaf(&parent, basename, maximum, Some(maximum))? else {
            return Ok(None);
        };
        if !result.retained_complete {
            return Err(ConfinedFilesystemError::PostStateMismatch);
        }
        let FilePathState::Regular { hash, size } = result.state else {
            return Err(ConfinedFilesystemError::PostStateMismatch);
        };
        self.ensure_root()?;
        Ok(Some(ConfinedFileRead {
            content: result.retained,
            hash,
            size,
            mode: result.mode,
        }))
    }

    /// Create a descriptor-rooted directory tree without following symlinks.
    /// The caller must retain [`ConfinedWorkspaceWriteGuard`] for the full
    /// materialization transaction.
    pub(crate) fn ensure_directory_tree(
        &self,
        _write_guard: &ConfinedWorkspaceWriteGuard,
        path: &WorkspaceRelativePath,
    ) -> Result<(), ConfinedFilesystemError> {
        self.ensure_root()?;
        validate_not_protected(path)?;
        let components = collect_components(path)?;
        let directory = walk_or_create_directories(&self.root, &components)?;
        let _identity = directory_identity(&directory)?;
        self.ensure_root_with_committed(true)
    }

    /// Atomically publish one Harness-managed file using the exact observed
    /// Preview state as a compare-before-write guard.
    pub(crate) fn write_bounded_atomic(
        &self,
        _write_guard: &ConfinedWorkspaceWriteGuard,
        path: &WorkspaceRelativePath,
        expected: FilePathState,
        content: &[u8],
        maximum: usize,
    ) -> Result<FilePathState, ConfinedFilesystemError> {
        if content.len() > maximum {
            return Err(ConfinedFilesystemError::WriteTooLarge {
                actual: content.len(),
                maximum,
            });
        }
        self.ensure_root()?;
        let (parent, basename, _) = self.open_parent(path)?;
        let current = read_leaf(&parent, &basename, maximum, None)?
            .map_or(FilePathState::Absent, |read| read.state);
        if current != expected {
            return Err(ConfinedFilesystemError::StaleWrite);
        }
        publish_managed_content(&parent, &basename, current, content)?;
        self.ensure_root_with_committed(true)?;
        let post = read_leaf(&parent, &basename, maximum, None)?
            .map_or(FilePathState::Absent, |read| read.state);
        let expected_hash = FileContentHash::from_bytes(*blake3::hash(content).as_bytes());
        let expected_size = FileByteCount::new(u64::try_from(content.len()).map_err(|_| {
            ConfinedFilesystemError::WriteTooLarge {
                actual: content.len(),
                maximum,
            }
        })?);
        if post
            != (FilePathState::Regular {
                hash: expected_hash,
                size: expected_size,
            })
        {
            return Err(ConfinedFilesystemError::CommittedObservationFailed);
        }
        Ok(post)
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
            filesystem_root,
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
        Ok(ConfinedWorkspaceWriteGuard { _lock: lock })
    }

    /// Acquire the cross-process Forge-writer lock and retain the exact parent
    /// descriptor until the prepared effect finishes.
    pub fn prepare_mutation(
        &self,
        plan: &FileMutationPlan,
    ) -> Result<PreparedFileMutation, ConfinedFilesystemError> {
        self.ensure_root()?;
        let mutation_lock = self.acquire_mutation_lock()?;
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
        let filesystem_root =
            dup(&self.filesystem_root).map_err(|source| ConfinedFilesystemError::Syscall {
                operation: FilesystemOperation::DuplicateRoot,
                committed: false,
                source,
            })?;
        Ok(PreparedFileMutation {
            filesystem_root,
            root_components: self.root_components.clone(),
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
        let reopened = walk_directories(&self.filesystem_root, &self.root_components, committed)?;
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

fn walk_or_create_directories(
    root: &OwnedFd,
    components: &[OsString],
) -> Result<OwnedFd, ConfinedFilesystemError> {
    let mut current = dup(root).map_err(pre_syscall)?;
    for component in components {
        let opened = openat(
            &current,
            component,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        );
        current = match opened {
            Ok(directory) => directory,
            Err(source) if source == Errno::NOENT => {
                match mkdirat(&current, component, Mode::from_raw_mode(0o755)) {
                    Ok(()) => {
                        fsync(&current).map_err(|source| ConfinedFilesystemError::Syscall {
                            operation: FilesystemOperation::SyncParent,
                            committed: true,
                            source,
                        })?;
                    }
                    Err(source) if source == Errno::EXIST => {}
                    Err(source) => {
                        return Err(ConfinedFilesystemError::Syscall {
                            operation: FilesystemOperation::CreateDirectory,
                            committed: false,
                            source,
                        });
                    }
                }
                openat(
                    &current,
                    component,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|source| ConfinedFilesystemError::Syscall {
                    operation: FilesystemOperation::OpenAncestor,
                    committed: true,
                    source,
                })?
            }
            Err(source) if source == Errno::LOOP => {
                return Err(ConfinedFilesystemError::SymlinkRejected);
            }
            Err(source) if source == Errno::NOTDIR => {
                return Err(ConfinedFilesystemError::NonDirectoryAncestor);
            }
            Err(source) => {
                return Err(ConfinedFilesystemError::Syscall {
                    operation: FilesystemOperation::OpenAncestor,
                    committed: false,
                    source,
                });
            }
        };
        if !FileType::from_raw_mode(fstat(&current).map_err(pre_syscall)?.st_mode).is_dir() {
            return Err(ConfinedFilesystemError::NonDirectoryAncestor);
        }
    }
    Ok(current)
}

fn publish_managed_content(
    parent: &OwnedFd,
    basename: &OsStr,
    pre_state: FilePathState,
    content: &[u8],
) -> Result<(), ConfinedFilesystemError> {
    let serial = NEXT_MANAGED_TEMP.fetch_add(1, Ordering::Relaxed);
    let temporary = OsString::from(format!(
        "{MANAGED_TEMP_PREFIX}{}-{serial}",
        std::process::id()
    ));
    let mode = match pre_state {
        FilePathState::Absent => Mode::from_raw_mode(0o644),
        FilePathState::Regular { .. } => {
            let leaf =
                open_regular_leaf(parent, basename)?.ok_or(ConfinedFilesystemError::StaleWrite)?;
            Mode::from_raw_mode(fstat(&leaf).map_err(pre_syscall)?.st_mode)
        }
    };
    let temporary_fd = openat(
        parent,
        &temporary,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        mode,
    )
    .map_err(map_create_temp_error)?;
    require_regular_single_link(&temporary_fd)?;
    if let Err(source) = fchmod(&temporary_fd, sanitized_file_mode(mode)) {
        return cleanup_after_syscall_error(
            parent,
            &temporary,
            FilesystemOperation::SetTemporaryMode,
            source,
        );
    }
    let mut temporary_file = File::from(temporary_fd);
    if let Err(source) = temporary_file.write_all(content) {
        return cleanup_after_std_error(
            parent,
            &temporary,
            FilesystemOperation::WriteTemporary,
            source,
        );
    }
    if let Err(source) = sync_file(&temporary_file) {
        return cleanup_after_syscall_error(
            parent,
            &temporary,
            FilesystemOperation::SyncTemporary,
            source,
        );
    }
    drop(temporary_file);
    let publish = match pre_state {
        FilePathState::Absent => {
            renameat_with(parent, &temporary, parent, basename, RenameFlags::NOREPLACE)
        }
        FilePathState::Regular { .. } => renameat(parent, &temporary, parent, basename),
    };
    if let Err(source) = publish {
        cleanup_temp(parent, &temporary)?;
        if matches!(pre_state, FilePathState::Absent) && source == Errno::EXIST {
            return Err(ConfinedFilesystemError::StaleWrite);
        }
        if matches!(pre_state, FilePathState::Absent)
            && matches!(source, Errno::NOTSUP | Errno::OPNOTSUPP | Errno::NOSYS)
        {
            return Err(ConfinedFilesystemError::AtomicCreateUnsupported);
        }
        return Err(ConfinedFilesystemError::Syscall {
            operation: FilesystemOperation::PublishTemporary,
            committed: false,
            source,
        });
    }
    fsync(parent).map_err(|source| ConfinedFilesystemError::Syscall {
        operation: FilesystemOperation::SyncParent,
        committed: true,
        source,
    })
}

/// Prepared single-file effect. It is intentionally neither `Clone` nor
/// `Copy`: dropping it releases the Forge-writer lock without performing an
/// effect or changing the durable intent.
#[derive(Debug)]
pub struct PreparedFileMutation {
    filesystem_root: OwnedFd,
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
    _mutation_lock: MutationLock,
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
        match (self.kind, content) {
            (FileMutationKind::Create | FileMutationKind::Replace, Some(content)) => {
                if content.len() > MAX_FILE_WRITE_BYTES {
                    return Err(ConfinedFilesystemError::WriteTooLarge {
                        actual: content.len(),
                        maximum: MAX_FILE_WRITE_BYTES,
                    });
                }
                Ok(CapturedDiffSource::from_payload(content))
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
        self.apply_inner(mutation_id, content, None)
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
        self.apply_inner(mutation_id, Some(content), Some(mode))
    }

    fn apply_inner(
        self,
        mutation_id: FileMutationId,
        content: Option<&[u8]>,
        restored_mode: Option<CheckpointFileMode>,
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
                if content.len() > MAX_FILE_WRITE_BYTES {
                    return Err(ConfinedFilesystemError::WriteTooLarge {
                        actual: content.len(),
                        maximum: MAX_FILE_WRITE_BYTES,
                    });
                }
                self.apply_content(mutation_id, content, restored_mode)?;
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
        validate_post_content(self.kind, content, post_state)
            .map_err(|_| ConfinedFilesystemError::CommittedObservationFailed)?;
        let post_source = self.intended_post_source(content)?;
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
    ) -> Result<(), ConfinedFilesystemError> {
        let temporary = OsString::from(format!("{TEMP_PREFIX}{mutation_id}"));
        let mode = if let Some(restored_mode) = restored_mode {
            Mode::from_raw_mode(restored_mode.get())
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
                && matches!(source, Errno::NOTSUP | Errno::OPNOTSUPP | Errno::NOSYS)
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
        let reopened = walk_directories(&self.filesystem_root, &self.root_components, committed)?;
        ensure_directory_identity(&reopened, self.root_identity, committed)
    }
}

#[derive(Debug)]
struct MutationLock {
    _file: OwnedFd,
}

/// Non-cloneable cross-process Workspace writer guard.
#[derive(Debug)]
pub struct ConfinedWorkspaceWriteGuard {
    _lock: MutationLock,
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

pub(crate) fn directory_identity(
    fd: &OwnedFd,
) -> Result<DirectoryIdentity, ConfinedFilesystemError> {
    let stat = fstat(fd).map_err(pre_syscall)?;
    if !FileType::from_raw_mode(stat.st_mode).is_dir() {
        return Err(ConfinedFilesystemError::NonDirectoryAncestor);
    }
    Ok(DirectoryIdentity {
        device: u64::try_from(stat.st_dev)
            .map_err(|_| ConfinedFilesystemError::WorkspaceUnavailable)?,
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
        Err(source) if source == Errno::LOOP => Err(ConfinedFilesystemError::SymlinkRejected),
        Err(source) => Err(ConfinedFilesystemError::Syscall {
            operation: FilesystemOperation::OpenLeaf,
            committed: false,
            source,
        }),
    }
}

pub(crate) fn require_regular_single_link(fd: &OwnedFd) -> Result<(), ConfinedFilesystemError> {
    let stat = fstat(fd).map_err(pre_syscall)?;
    if !FileType::from_raw_mode(stat.st_mode).is_file() {
        return Err(ConfinedFilesystemError::NonRegularLeaf);
    }
    if stat.st_nlink != 1 {
        return Err(ConfinedFilesystemError::HardlinkRejected);
    }
    Ok(())
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
) -> Result<(), ConfinedFilesystemError> {
    match (kind, content, state) {
        (
            FileMutationKind::Create | FileMutationKind::Replace,
            Some(content),
            FilePathState::Regular { hash, .. },
        ) if bounded_write_content_hash(content)? == hash => Ok(()),
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
    DuplicateRoot,
    OpenAncestor,
    InspectAncestor,
    OpenLeaf,
    ReadLeaf,
    InspectDescriptor,
    OpenStateDirectory,
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
    SyncParent,
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
    #[error("a symbolic link was rejected")]
    SymlinkRejected,
    #[error("an ancestor is not a directory")]
    NonDirectoryAncestor,
    #[error("the target is not a regular file")]
    NonRegularLeaf,
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
    #[error("the bounded Forge-writer lock is busy")]
    LockBusy,
    #[error("the observed POST state does not match the requested mutation")]
    PostStateMismatch,
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
            | Self::SymlinkRejected
            | Self::NonDirectoryAncestor
            | Self::NonRegularLeaf
            | Self::HardlinkRejected
            | Self::NotFound
            | Self::PathConflict
            | Self::StaleWrite
            | Self::PathChanged
            | Self::FileTooLarge { .. }
            | Self::WriteTooLarge { .. }
            | Self::InvalidPayload
            | Self::AtomicCreateUnsupported
            | Self::LockBusy
            | Self::PostStateMismatch => false,
        }
    }

    pub const fn failure_code(&self) -> FileMutationFailureCode {
        match self {
            Self::InvalidPath | Self::TooManyComponents => FileMutationFailureCode::InvalidPath,
            Self::ProtectedPath => FileMutationFailureCode::ProtectedPath,
            Self::NotFound
            | Self::PathConflict
            | Self::PathChanged
            | Self::CommittedPathChanged
            | Self::CommittedObservationFailed
            | Self::PostStateMismatch => FileMutationFailureCode::PathConflict,
            Self::StaleWrite => FileMutationFailureCode::StaleWrite,
            Self::FileTooLarge { .. } | Self::WriteTooLarge { .. } | Self::LockBusy => {
                FileMutationFailureCode::CapacityExceeded
            }
            Self::WorkspaceUnavailable
            | Self::WorkspaceRootTooDeep
            | Self::SymlinkRejected
            | Self::NonDirectoryAncestor
            | Self::NonRegularLeaf
            | Self::HardlinkRejected
            | Self::InvalidPayload
            | Self::AtomicCreateUnsupported
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
    use std::fs;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    use uuid::Uuid;

    use super::*;
    use crate::WorkspaceStateLayout;

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
            Err(ConfinedFilesystemError::SymlinkRejected)
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
    fn create_replace_delete_are_atomic_and_hash_cas_bound()
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

        let delete_plan = FileMutationPlan::new(
            path,
            FileMutationKind::Delete,
            FilePrecondition::Matches(replaced_hash),
        );
        let deleted = confined
            .prepare_mutation(&delete_plan)?
            .apply(mutation_id(3), None)?;
        assert_eq!(deleted.post_state(), FilePathState::Absent);
        assert!(!root.join("file.txt").exists());
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
            validate_post_content(FileMutationKind::Replace, Some(intended), other),
            Err(ConfinedFilesystemError::PostStateMismatch)
        ));
    }
}
