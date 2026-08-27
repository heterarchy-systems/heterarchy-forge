//! Git-only checkpoint object/ref plumbing.
//!
//! The checkpoint adapter deliberately does not use Git's working index.  It
//! creates a short-lived, product-owned index below
//! `.heterarchy-forge/checkpoints`, builds a one-path tree and retains the
//! resulting root commit under an expected-value-CAS ref.  Git is used as an
//! object store only; the user's `HEAD`, branch, index, and worktree are never
//! selected as an authority or mutated by this module.

use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, ChildStderr, ChildStdout, Command, ExitStatus, Stdio};
use std::str::FromStr;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use forge_domain::{
    CheckpointAttribution, CheckpointFileMode, CheckpointId, CheckpointPathState, CheckpointState,
    CheckpointTransitionError, FileByteCount, FileContentHash, GitBlobId, GitCommitId, GitObjectId,
    RegisteredCheckpoint, TimestampMillis, WorkspaceRelativePath,
};
use thiserror::Error;

use crate::confinement::{DirectoryIdentity, directory_identity_by_path};
use crate::{
    ConfinedFilesystemError, ConfinedWorkspace, ExistingWorkspaceStateLayout, WorkspaceStateLayout,
};

const GIT_PROGRAM: &str = "/usr/bin/git";
const STATE_DIRECTORY_NAME: &[u8] = b".heterarchy-forge";
const CHECKPOINT_DIRECTORY_NAME: &[u8] = b"checkpoints";
const GIT_REF_PREFIX: &str = "refs/heterarchy-forge/checkpoints/";
const MAX_GIT_OUTPUT_BYTES: usize = 64 * 1024;
const MAX_CHECKPOINT_FILE_BYTES: usize = 1024 * 1024;
const MAX_GIT_STDIN_BYTES: usize = MAX_CHECKPOINT_FILE_BYTES;
const GIT_PROCESS_TIMEOUT: Duration = Duration::from_secs(10);
const GIT_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Git output is bounded so a malformed repository cannot hold a worker in an
/// unbounded pipe read or cause an unbounded allocation.
pub const GIT_CHECKPOINT_MAX_OUTPUT_BYTES: usize = MAX_GIT_OUTPUT_BYTES;
/// The first checkpoint adapter retains bounded regular files only.
pub const GIT_CHECKPOINT_MAX_FILE_BYTES: usize = MAX_CHECKPOINT_FILE_BYTES;
/// Stable namespace for retained checkpoint refs.
pub const GIT_CHECKPOINT_REF_PREFIX: &str = GIT_REF_PREFIX;

/// The two durable refs retained for one checkpoint identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CheckpointSide {
    Pre,
    Post,
}

impl CheckpointSide {
    const fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::Pre => b"pre",
            Self::Post => b"post",
        }
    }
}

/// Maximum number of Forge-owned checkpoint refs returned by one Doctor inventory.
pub const GIT_CHECKPOINT_REF_INVENTORY_MAX: u16 = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GitCheckpointRefInventoryLimit(u16);

impl GitCheckpointRefInventoryLimit {
    pub const DEFAULT: Self = Self(GIT_CHECKPOINT_REF_INVENTORY_MAX);

    pub const fn new(value: u16) -> Result<Self, GitSafetyError> {
        if value == 0 || value > GIT_CHECKPOINT_REF_INVENTORY_MAX {
            Err(GitSafetyError::InvalidInventoryLimit {
                actual: value,
                maximum: GIT_CHECKPOINT_REF_INVENTORY_MAX,
            })
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u16 {
        self.0
    }
}

/// Connectivity health of the currently retained checkpoint commit graph.
///
/// This does not mean every ref name is valid: malformed/non-commit refs are
/// surfaced as typed inventory entries and classified separately by Doctor.
/// Historical unreachable objects are intentionally outside this hot-path
/// health signal so deleted checkpoint history cannot make Doctor cost grow
/// without bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitCheckpointStoreIntegrity {
    Passed,
    Damaged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitCheckpointRefInventoryEntry {
    Retained {
        checkpoint_id: CheckpointId,
        side: CheckpointSide,
        commit: GitCommitId,
    },
    NonCommit {
        checkpoint_id: CheckpointId,
        side: CheckpointSide,
    },
    Malformed,
}

impl GitCheckpointRefInventoryEntry {
    pub const fn checkpoint_id(self) -> Option<CheckpointId> {
        match self {
            Self::Retained { checkpoint_id, .. } | Self::NonCommit { checkpoint_id, .. } => {
                Some(checkpoint_id)
            }
            Self::Malformed => None,
        }
    }

    pub const fn side(self) -> Option<CheckpointSide> {
        match self {
            Self::Retained { side, .. } | Self::NonCommit { side, .. } => Some(side),
            Self::Malformed => None,
        }
    }

    pub const fn commit(self) -> Option<GitCommitId> {
        match self {
            Self::Retained { commit, .. } => Some(commit),
            Self::NonCommit { .. } | Self::Malformed => None,
        }
    }
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitCheckpointRefInventory {
    entries: Vec<GitCheckpointRefInventoryEntry>,
    truncated: bool,
    integrity: GitCheckpointStoreIntegrity,
}

impl GitCheckpointRefInventory {
    pub fn entries(&self) -> &[GitCheckpointRefInventoryEntry] {
        &self.entries
    }

    pub const fn truncated(&self) -> bool {
        self.truncated
    }

    pub const fn integrity(&self) -> GitCheckpointStoreIntegrity {
        self.integrity
    }
}

/// Maximum typed commit/blob expectations checked by one bounded Git process.
pub const GIT_CHECKPOINT_OBJECT_VERIFY_MAX: usize = 1_024;
const GIT_CHECKPOINT_OBJECT_VERIFY_MAX_OUTPUT_BYTES: usize = 128 * 1_024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum GitCheckpointObjectExpectation {
    Commit(GitCommitId),
    Blob(GitBlobId),
}

impl GitCheckpointObjectExpectation {
    pub const fn object_id(self) -> GitObjectId {
        match self {
            Self::Commit(value) => value.object_id(),
            Self::Blob(value) => value.object_id(),
        }
    }

    const fn expected_type(self) -> &'static [u8] {
        match self {
            Self::Commit(_) => b"commit",
            Self::Blob(_) => b"blob",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitCheckpointObjectVerificationStatus {
    Present,
    Missing,
    TypeMismatch,
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GitCheckpointObjectVerification {
    expectation: GitCheckpointObjectExpectation,
    status: GitCheckpointObjectVerificationStatus,
}

impl GitCheckpointObjectVerification {
    pub const fn expectation(self) -> GitCheckpointObjectExpectation {
        self.expectation
    }

    pub const fn status(self) -> GitCheckpointObjectVerificationStatus {
        self.status
    }
}

/// A checkpoint snapshot whose Git commit is retained by its side ref.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitRetainedSnapshot {
    state: CheckpointPathState,
    commit: GitCommitId,
    observed_at: TimestampMillis,
}

impl GitRetainedSnapshot {
    pub const fn state(&self) -> &CheckpointPathState {
        &self.state
    }

    pub const fn commit(&self) -> GitCommitId {
        self.commit
    }

    pub const fn observed_at(&self) -> TimestampMillis {
        self.observed_at
    }
}

/// Errors returned by the Git checkpoint effect boundary.
#[derive(Debug, Error)]
pub enum GitSafetyError {
    #[error("Workspace root is not a canonical regular directory: {path}")]
    InvalidWorkspaceRoot { path: PathBuf },
    #[error("checkpoint root must be the product-owned absolute directory: {path}")]
    InvalidCheckpointRoot { path: PathBuf },
    #[error("Workspace is not inside a Git worktree")]
    NotGitRepository,
    #[error("Workspace is outside the Git repository root")]
    WorkspaceOutsideRepository,
    #[error("Git repository uses a Gitfile, worktree, submodule, or symlink layout")]
    UnsupportedGitLayout,
    #[error("Git object format is unsupported: {actual:?}")]
    UnsupportedObjectFormat { actual: Vec<u8> },
    #[error("Git object identifier returned by {operation} is invalid")]
    InvalidObjectId { operation: String, value: Vec<u8> },
    #[error("Git ref name is invalid")]
    InvalidRefName,
    #[error("checkpoint ref inventory limit {actual} is outside 1..={maximum}")]
    InvalidInventoryLimit { actual: u16, maximum: u16 },
    #[error("checkpoint object verification count {actual} exceeds {maximum}")]
    ObjectVerificationLimit { actual: usize, maximum: usize },
    #[error("checkpoint object batch verification returned malformed output")]
    MalformedObjectVerificationOutput,
    #[error("Git ref CAS conflict for {name}; expected {expected:?}, observed {actual:?}")]
    RefConflict {
        name: String,
        expected: Option<GitCommitId>,
        actual: Option<GitCommitId>,
    },
    #[error("Git ref is tampered or does not point to a commit: {name}")]
    TamperedRef { name: String },
    #[error("Git command failed while {operation} with status {status:?}: {stderr}")]
    GitCommandFailed {
        operation: String,
        status: Option<i32>,
        stderr: String,
    },
    #[error("Git command could not start while {operation}")]
    StartGit {
        operation: String,
        #[source]
        source: io::Error,
    },
    #[error("Git command could not be awaited while {operation}")]
    WaitGit {
        operation: String,
        #[source]
        source: io::Error,
    },
    #[error("Git operation {operation} exceeded the bounded timeout")]
    GitTimeout { operation: String },
    #[error("Git process group could not be terminated")]
    GitProcessCleanupFailed,
    #[error("Git {stream} exceeded the {maximum}-byte capture bound")]
    GitOutputTooLarge {
        stream: &'static str,
        maximum: usize,
    },
    #[error("Git {stream} pipe was unavailable")]
    GitOutputPipeUnavailable { stream: &'static str },
    #[error("Git {stream} reader failed")]
    GitOutputRead {
        stream: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("Git output reader panicked for {stream}")]
    GitOutputReaderPanicked { stream: &'static str },
    #[error("Git stdin exceeded the {maximum}-byte bound")]
    GitInputTooLarge { maximum: usize },
    #[error("Git stdin failed while {operation}")]
    GitInputWrite {
        operation: String,
        #[source]
        source: io::Error,
    },
    #[error("filesystem operation failed while {operation} at {path}")]
    Filesystem {
        operation: String,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("checkpoint path is not a regular file: {path}")]
    NonRegularFile { path: PathBuf },
    #[error("checkpoint path is a symbolic link: {path}")]
    SymlinkPath { path: PathBuf },
    #[error("checkpoint file exceeded the {maximum}-byte bound: {path}")]
    FileTooLarge { path: PathBuf, maximum: usize },
    #[error("checkpoint file changed while being captured: {path}")]
    FileChanged { path: PathBuf },
    #[error("checkpoint path is not representable as a repository-relative native path")]
    PathNotRepresentable,
    #[error("checkpoint path is inside product-owned state")]
    ProtectedPath,
    #[error("checkpoint transition is invalid")]
    Transition(#[source] CheckpointTransitionError),
    #[error("descriptor-confined checkpoint capture failed")]
    Confined(#[source] ConfinedFilesystemError),
    #[error("Workspace or Git directory changed after Git execution; effect may have committed")]
    GitPathChangedAfter(#[source] ConfinedFilesystemError),
}

/// Git object/ref adapter for a canonical Workspace root.
#[derive(Debug)]
pub struct GitCheckpointStore {
    workspace: PathBuf,
    repository: PathBuf,
    checkpoints: PathBuf,
    confined: ConfinedWorkspace,
    /// Product-owned bare object/ref store below the validated checkpoint
    /// root.  Apple Git rejects descriptor `GIT_DIR` values, so the safe
    /// boundary is naming Forge durable state instead of the user repository.
    store: PathBuf,
    store_identity: DirectoryIdentity,
}

/// Descriptive adapter alias for callers that name the effect boundary
/// explicitly rather than the retained-object store.
pub type GitCheckpointAdapter = GitCheckpointStore;

impl GitCheckpointStore {
    /// Construct a Git-only adapter and fail closed unless the repository uses
    /// SHA-1 objects. The checkpoint directory is created only below the
    /// product-owned Workspace state root.
    pub fn new(
        workspace_root: impl AsRef<Path>,
        checkpoints_root: impl AsRef<Path>,
    ) -> Result<Self, GitSafetyError> {
        let workspace_root = canonical_workspace_root(workspace_root.as_ref())?;
        let repository_root = resolve_repository_root(&workspace_root)?;
        if !workspace_root.starts_with(&repository_root) {
            return Err(GitSafetyError::WorkspaceOutsideRepository);
        }
        let checkpoints_root =
            validate_checkpoint_root(&workspace_root, checkpoints_root.as_ref())?;
        let layout = WorkspaceStateLayout::inspect_existing(&workspace_root)
            .map_err(|_| GitSafetyError::InvalidCheckpointRoot {
                path: checkpoints_root.clone(),
            })?
            .ok_or_else(|| GitSafetyError::InvalidCheckpointRoot {
                path: checkpoints_root.clone(),
            })?;
        if layout.checkpoints() != checkpoints_root {
            return Err(GitSafetyError::InvalidCheckpointRoot {
                path: checkpoints_root,
            });
        }
        let confined = ConfinedWorkspace::open(&layout).map_err(GitSafetyError::Confined)?;
        let store_path = Self::initialize_owned_store(&checkpoints_root)?;
        let store_identity =
            directory_identity_by_path(&store_path).map_err(GitSafetyError::Confined)?;

        let store = Self {
            workspace: workspace_root,
            repository: repository_root,
            checkpoints: checkpoints_root,
            confined,
            store: store_path.clone(),
            store_identity,
        };
        store.ensure_sha1_object_format()?;
        Ok(store)
    }

    /// Construct from the product-owned state layout.
    pub fn from_state_layout(layout: &WorkspaceStateLayout) -> Result<Self, GitSafetyError> {
        Self::new(layout.workspace_root(), layout.checkpoints())
    }

    /// Open an already-created Forge-owned checkpoint store without creating,
    /// repairing, or migrating any state. `None` means no owned store exists.
    pub fn inspect_existing_read_only(
        layout: &ExistingWorkspaceStateLayout,
    ) -> Result<Option<Self>, GitSafetyError> {
        let workspace_root = canonical_workspace_root(layout.workspace_root())?;
        let repository_root = match resolve_repository_root(&workspace_root) {
            Ok(root) => root,
            Err(GitSafetyError::NotGitRepository) => return Ok(None),
            Err(error) => return Err(error),
        };
        if !workspace_root.starts_with(&repository_root) {
            return Err(GitSafetyError::WorkspaceOutsideRepository);
        }
        let checkpoints_root = validate_checkpoint_root(&workspace_root, layout.checkpoints())?;
        let confined = ConfinedWorkspace::open(layout).map_err(GitSafetyError::Confined)?;
        let store_path = checkpoints_root.join("store.git");
        let metadata = match fs::symlink_metadata(&store_path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(GitSafetyError::Filesystem {
                    operation: "inspect checkpoint store".to_owned(),
                    path: store_path,
                    source,
                });
            }
        };
        if metadata.file_type().is_symlink() {
            return Err(GitSafetyError::SymlinkPath { path: store_path });
        }
        if !metadata.is_dir() {
            return Err(GitSafetyError::InvalidCheckpointRoot { path: store_path });
        }
        validate_owned_store_shape(&store_path)?;
        let store_identity =
            directory_identity_by_path(&store_path).map_err(GitSafetyError::Confined)?;
        let store = Self {
            workspace: workspace_root,
            repository: repository_root,
            checkpoints: checkpoints_root,
            confined,
            store: store_path,
            store_identity,
        };
        store.ensure_sha1_object_format()?;
        Ok(Some(store))
    }

    /// Open the already-existing Forge-owned checkpoint store without creating
    /// directories, refs, objects, config, or any other durable state.
    pub fn open_existing_read_only(
        layout: &ExistingWorkspaceStateLayout,
    ) -> Result<Option<Self>, GitSafetyError> {
        let workspace_root = canonical_workspace_root(layout.workspace_root())?;
        let repository_root = resolve_repository_root(&workspace_root)?;
        if !workspace_root.starts_with(&repository_root) {
            return Err(GitSafetyError::WorkspaceOutsideRepository);
        }
        let checkpoints_root = validate_checkpoint_root(&workspace_root, layout.checkpoints())?;
        if layout.checkpoints() != checkpoints_root {
            return Err(GitSafetyError::InvalidCheckpointRoot {
                path: checkpoints_root,
            });
        }
        let store_path = checkpoints_root.join("store.git");
        let metadata = match fs::symlink_metadata(&store_path) {
            Ok(metadata) => metadata,
            Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(GitSafetyError::Filesystem {
                    operation: "inspect existing checkpoint store".to_owned(),
                    path: store_path,
                    source,
                });
            }
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(GitSafetyError::InvalidCheckpointRoot { path: store_path });
        }
        ensure_no_symlink_components(&store_path)?;
        for required in ["objects", "refs"] {
            directory_identity_by_path(&store_path.join(required))
                .map_err(GitSafetyError::Confined)?;
        }
        let head = store_path.join("HEAD");
        let head_metadata =
            fs::symlink_metadata(&head).map_err(|source| GitSafetyError::Filesystem {
                operation: "inspect existing checkpoint store HEAD".to_owned(),
                path: head.clone(),
                source,
            })?;
        if head_metadata.file_type().is_symlink() || !head_metadata.is_file() {
            return Err(GitSafetyError::InvalidCheckpointRoot { path: head });
        }
        let confined = ConfinedWorkspace::open(layout).map_err(GitSafetyError::Confined)?;
        let store_identity =
            directory_identity_by_path(&store_path).map_err(GitSafetyError::Confined)?;
        let store = Self {
            workspace: workspace_root,
            repository: repository_root,
            checkpoints: checkpoints_root,
            confined,
            store: store_path,
            store_identity,
        };
        store.ensure_sha1_object_format()?;
        Ok(Some(store))
    }

    pub fn workspace_root(&self) -> &Path {
        &self.workspace
    }

    pub fn repository_root(&self) -> &Path {
        &self.repository
    }

    /// Path of the product-owned bare object/ref store.
    ///
    /// Exposed for diagnostics (Doctor integrity passes) and tests; mutation
    /// authority stays inside this adapter.
    pub fn git_store_path(&self) -> &Path {
        &self.store
    }

    pub fn checkpoints_root(&self) -> &Path {
        &self.checkpoints
    }

    pub fn checkpoint_ref_name(
        checkpoint_id: CheckpointId,
        side: CheckpointSide,
    ) -> Result<String, GitSafetyError> {
        Self::ref_name(checkpoint_id, side)
    }

    /// Inventory the Forge-owned checkpoint namespace with one bounded Git ref
    /// query and one connectivity pass rooted only at the retained commits.
    pub fn inventory_refs_read_only(
        &self,
        limit: GitCheckpointRefInventoryLimit,
    ) -> Result<GitCheckpointRefInventory, GitSafetyError> {
        let count = usize::from(limit.get()).saturating_add(1);
        let count_arg = format!("--count={count}");
        let output = self.run_git(
            "inventory checkpoint refs",
            &[
                arg("for-each-ref"),
                arg("--sort=refname"),
                os(&count_arg),
                arg("--format=%(refname)%00%(objectname)%00%(objecttype)"),
                arg(GIT_REF_PREFIX),
            ],
            None,
            &[],
        )?;
        if !output.status.success() {
            return Err(command_failed("inventory checkpoint refs", &output));
        }
        let mut entries = parse_checkpoint_ref_inventory(&output.stdout)?;
        let truncated = entries.len() > usize::from(limit.get());
        entries.truncate(usize::from(limit.get()));

        let retained_commits = entries
            .iter()
            .copied()
            .filter_map(GitCheckpointRefInventoryEntry::commit)
            .collect::<Vec<_>>();
        let integrity = self.verify_retained_connectivity_read_only(&retained_commits)?;
        Ok(GitCheckpointRefInventory {
            entries,
            truncated,
            integrity,
        })
    }

    /// Verify connectivity only from the currently retained checkpoint commits.
    ///
    /// The input is bounded by the ref inventory limit. Historical unreachable
    /// objects are deliberately excluded so Doctor cost does not grow with
    /// deleted checkpoint history that is no longer durable authority.
    fn verify_retained_connectivity_read_only(
        &self,
        commits: &[GitCommitId],
    ) -> Result<GitCheckpointStoreIntegrity, GitSafetyError> {
        if commits.is_empty() {
            return Ok(GitCheckpointStoreIntegrity::Passed);
        }
        let mut arguments = Vec::with_capacity(commits.len().saturating_add(5));
        arguments.extend([
            arg("fsck"),
            arg("--connectivity-only"),
            arg("--no-reflogs"),
            arg("--no-progress"),
            arg("--no-dangling"),
        ]);
        arguments.extend(
            commits
                .iter()
                .map(|commit| arg_bytes(&object_hex(commit.object_id()))),
        );
        let fsck = self.run_git(
            "verify retained checkpoint connectivity",
            &arguments,
            None,
            &[],
        )?;
        Ok(if fsck.status.success() {
            GitCheckpointStoreIntegrity::Passed
        } else {
            GitCheckpointStoreIntegrity::Damaged
        })
    }

    /// Verify a bounded set of expected checkpoint commits/blobs with one Git
    /// `cat-file --batch-check` process. Input order is preserved.
    pub fn verify_objects_read_only(
        &self,
        expectations: &[GitCheckpointObjectExpectation],
    ) -> Result<Vec<GitCheckpointObjectVerification>, GitSafetyError> {
        if expectations.len() > GIT_CHECKPOINT_OBJECT_VERIFY_MAX {
            return Err(GitSafetyError::ObjectVerificationLimit {
                actual: expectations.len(),
                maximum: GIT_CHECKPOINT_OBJECT_VERIFY_MAX,
            });
        }
        if expectations.is_empty() {
            return Ok(Vec::new());
        }
        self.ensure_sha1_object_format()?;
        let mut input = Vec::with_capacity(expectations.len().saturating_mul(41));
        for expectation in expectations {
            input.extend_from_slice(&object_hex(expectation.object_id()));
            input.push(b'\n');
        }
        let output = self.run_git_with_limit(
            "verify checkpoint objects",
            &[arg("cat-file"), arg("--batch-check")],
            Some(&input),
            &[],
            GIT_CHECKPOINT_OBJECT_VERIFY_MAX_OUTPUT_BYTES,
        )?;
        if !output.status.success() {
            return Err(command_failed("verify checkpoint objects", &output));
        }
        parse_checkpoint_object_verifications(expectations, &output.stdout)
    }

    /// Return the native repository-relative path used by Git plumbing.
    /// No UTF-8 conversion or lossy replacement is performed.
    pub fn repository_relative_path(
        &self,
        path: &WorkspaceRelativePath,
    ) -> Result<PathBuf, GitSafetyError> {
        let mut relative = self
            .workspace
            .strip_prefix(&self.repository)
            .map_err(|_| GitSafetyError::WorkspaceOutsideRepository)?
            .to_path_buf();
        relative.push(path.as_path());
        validate_repository_relative_path(&relative)?;
        if path.components().next().is_some_and(|component| {
            component
                .as_bytes()
                .eq_ignore_ascii_case(STATE_DIRECTORY_NAME)
                || component.as_bytes().eq_ignore_ascii_case(b".git")
        }) {
            return Err(GitSafetyError::ProtectedPath);
        }
        Ok(relative)
    }

    /// Capture the current path and retain it under the expected-value-CAS
    /// side ref. `expected` is `None` for creation and `Some` for replacement.
    pub fn retain_snapshot(
        &self,
        checkpoint_id: CheckpointId,
        path: &WorkspaceRelativePath,
        side: CheckpointSide,
        observed_at: TimestampMillis,
        expected: Option<GitCommitId>,
    ) -> Result<GitRetainedSnapshot, GitSafetyError> {
        let ref_name = Self::ref_name(checkpoint_id, side)?;
        let relative = self.repository_relative_path(path)?;
        let captured = self.capture_path(path)?;
        self.ensure_sha1_object_format()?;
        let observed = self.read_ref(checkpoint_id, side)?;
        if let Some(existing) = observed {
            if (expected.is_none() || expected == Some(existing))
                && let Some(state) =
                    self.snapshot_matches(existing, checkpoint_id, side, &relative, &captured)?
            {
                let (state, retained_at) = state;
                return Ok(GitRetainedSnapshot {
                    state,
                    commit: existing,
                    observed_at: retained_at,
                });
            }
            if expected != Some(existing) {
                return Err(GitSafetyError::RefConflict {
                    name: ref_name,
                    expected,
                    actual: Some(existing),
                });
            }
        }
        if observed.is_none() && expected.is_some() {
            return Err(GitSafetyError::RefConflict {
                name: ref_name,
                expected,
                actual: None,
            });
        }
        let (state, commit) =
            self.create_commit(checkpoint_id, side, &relative, &captured, observed_at)?;
        let new_ref = Some(commit);
        if let Err(error) = self.update_ref_cas(checkpoint_id, side, new_ref, expected) {
            if let GitSafetyError::RefConflict {
                actual: Some(existing),
                ..
            } = error
            {
                if let Some(existing_state) =
                    self.snapshot_matches(existing, checkpoint_id, side, &relative, &captured)?
                {
                    let (state, retained_at) = existing_state;
                    return Ok(GitRetainedSnapshot {
                        state,
                        commit: existing,
                        observed_at: retained_at,
                    });
                }
                return Err(GitSafetyError::RefConflict {
                    name: Self::ref_name(checkpoint_id, side)?,
                    expected,
                    actual: Some(existing),
                });
            }
            return Err(error);
        }
        Ok(GitRetainedSnapshot {
            state,
            commit,
            observed_at,
        })
    }

    /// Create the product-owned bare object/ref store exactly once.
    ///
    /// The store lives below the validated checkpoint root, so naming it as
    /// `GIT_DIR` names Forge durable state rather than the user repository.
    fn initialize_owned_store(checkpoints_root: &Path) -> Result<PathBuf, GitSafetyError> {
        let store = checkpoints_root.join("store.git");
        let head_exists =
            store
                .join("HEAD")
                .try_exists()
                .map_err(|source| GitSafetyError::StartGit {
                    operation: "initialize checkpoint store".to_owned(),
                    source,
                })?;
        if !head_exists {
            let output = Command::new(GIT_PROGRAM)
                .arg("init")
                .arg("-q")
                .arg("--bare")
                .arg(&store)
                .current_dir(checkpoints_root)
                .env_clear()
                .env("LANG", "C")
                .env("LC_ALL", "C")
                .env("PATH", "/usr/bin:/bin")
                .env("HOME", "/nonexistent")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_TERMINAL_PROMPT", "0")
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .map_err(|source| GitSafetyError::StartGit {
                    operation: "initialize checkpoint store".to_owned(),
                    source,
                })?;
            if !output.status.success() {
                return Err(command_failed(
                    "initialize checkpoint store",
                    &GitOutput {
                        status: output.status,
                        stdout: output.stdout,
                        stderr: output.stderr,
                    },
                ));
            }
        }
        validate_owned_store_shape(&store)?;
        Ok(store)
    }

    /// Delete a retained side ref using expected-value CAS. Git objects are
    /// intentionally retained; this method never runs `gc` or deletes blobs,
    /// trees, or commits.
    pub fn delete_snapshot(
        &self,
        checkpoint_id: CheckpointId,
        side: CheckpointSide,
        expected: GitCommitId,
    ) -> Result<(), GitSafetyError> {
        self.ensure_sha1_object_format()?;
        let actual = self.read_ref(checkpoint_id, side)?;
        if actual != Some(expected) {
            return Err(GitSafetyError::RefConflict {
                name: Self::ref_name(checkpoint_id, side)?,
                expected: Some(expected),
                actual,
            });
        }
        self.update_ref_cas(checkpoint_id, side, None, Some(expected))
    }

    /// Read a retained side ref and validate that it names a commit.
    pub fn read_ref(
        &self,
        checkpoint_id: CheckpointId,
        side: CheckpointSide,
    ) -> Result<Option<GitCommitId>, GitSafetyError> {
        let ref_name = Self::ref_name(checkpoint_id, side)?;
        let output = self.run_git(
            "read checkpoint ref",
            &[
                arg("show-ref"),
                arg("--verify"),
                arg("--hash"),
                os(&ref_name),
            ],
            None,
            &[],
        )?;
        if !output.status.success() {
            if output.stdout.is_empty()
                && (output.status.code() == Some(1)
                    || (output.status.code() == Some(128)
                        && output
                            .stderr
                            .windows(b"not a valid ref".len())
                            .any(|window| window == b"not a valid ref")))
            {
                return Ok(None);
            }
            return Err(command_failed("read checkpoint ref", &output));
        }
        let object = parse_git_object_id("read checkpoint ref", &output.stdout)?;
        let object_hex = object_hex(object);
        let type_output = self.run_git(
            "validate checkpoint ref object",
            &[arg("cat-file"), arg("-t"), arg_bytes(&object_hex)],
            None,
            &[],
        )?;
        if !type_output.status.success() || trim_single_newline(&type_output.stdout) != b"commit" {
            return Err(GitSafetyError::TamperedRef { name: ref_name });
        }
        Ok(Some(GitCommitId::from_sha1_bytes(*object.as_bytes())))
    }

    /// Read a retained blob with the same bounded output policy as capture.
    pub fn read_blob(&self, blob: GitBlobId) -> Result<Vec<u8>, GitSafetyError> {
        self.ensure_sha1_object_format()?;
        let object = object_hex(blob.object_id());
        let type_output = self.run_git(
            "validate checkpoint blob",
            &[arg("cat-file"), arg("-t"), arg_bytes(&object)],
            None,
            &[],
        )?;
        if !type_output.status.success() || trim_single_newline(&type_output.stdout) != b"blob" {
            return Err(GitSafetyError::TamperedRef {
                name: "checkpoint blob".to_owned(),
            });
        }
        let output = self.run_git_with_limit(
            "read checkpoint blob",
            &[arg("cat-file"), arg("blob"), arg_bytes(&object)],
            None,
            &[],
            MAX_CHECKPOINT_FILE_BYTES,
        )?;
        if !output.status.success() {
            return Err(command_failed("read checkpoint blob", &output));
        }
        Ok(output.stdout)
    }

    /// Begin a domain checkpoint by retaining its PRE state.
    pub fn begin_checkpoint(
        &self,
        attribution: CheckpointAttribution,
        path: WorkspaceRelativePath,
        observed_at: TimestampMillis,
    ) -> Result<RegisteredCheckpoint, GitSafetyError> {
        let retained = self.retain_snapshot(
            attribution.id(),
            &path,
            CheckpointSide::Pre,
            observed_at,
            None,
        )?;
        Ok(RegisteredCheckpoint::starting(
            attribution,
            path,
            retained.state,
            retained.commit,
            retained.observed_at,
        ))
    }

    /// Complete a Starting domain checkpoint by retaining its POST state.
    pub fn complete_checkpoint(
        &self,
        checkpoint: &RegisteredCheckpoint,
        observed_at: TimestampMillis,
    ) -> Result<RegisteredCheckpoint, GitSafetyError> {
        if checkpoint.state() != CheckpointState::Starting {
            return Err(GitSafetyError::Transition(
                CheckpointTransitionError::NotStarting,
            ));
        }
        if observed_at.get() < checkpoint.timestamps().created_at().get() {
            return Err(GitSafetyError::Transition(
                CheckpointTransitionError::TimestampOrder,
            ));
        }
        let retained = self.retain_snapshot(
            checkpoint.id(),
            checkpoint.path(),
            CheckpointSide::Post,
            observed_at,
            None,
        )?;
        checkpoint
            .complete(
                checkpoint.revision(),
                retained.state,
                retained.commit,
                retained.observed_at,
            )
            .map_err(GitSafetyError::Transition)
    }

    fn ref_name(
        checkpoint_id: CheckpointId,
        side: CheckpointSide,
    ) -> Result<String, GitSafetyError> {
        let id = checkpoint_id.to_string();
        if id.len() != 36
            || !id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
        {
            return Err(GitSafetyError::InvalidRefName);
        }
        let mut name = String::with_capacity(GIT_REF_PREFIX.len() + id.len() + 1 + 4);
        name.push_str(GIT_REF_PREFIX);
        name.push_str(&id);
        name.push('/');
        name.push_str(std::str::from_utf8(side.as_bytes()).unwrap_or("invalid"));
        Ok(name)
    }

    fn ensure_sha1_object_format(&self) -> Result<(), GitSafetyError> {
        let output = self.run_git(
            "detect Git object format",
            &[arg("rev-parse"), arg("--show-object-format")],
            None,
            &[],
        )?;
        if !output.status.success() {
            return Err(command_failed("detect Git object format", &output));
        }
        let actual = trim_single_newline(&output.stdout).to_vec();
        if actual != b"sha1" {
            return Err(GitSafetyError::UnsupportedObjectFormat { actual });
        }
        Ok(())
    }

    fn update_ref_cas(
        &self,
        checkpoint_id: CheckpointId,
        side: CheckpointSide,
        new_value: Option<GitCommitId>,
        expected: Option<GitCommitId>,
    ) -> Result<(), GitSafetyError> {
        let ref_name = Self::ref_name(checkpoint_id, side)?;
        let mut args = vec![arg("update-ref")];
        if let Some(value) = new_value {
            args.push(os(&ref_name));
            args.push(arg_bytes(&object_hex(value.object_id())));
        } else {
            args.push(arg("-d"));
            args.push(os(&ref_name));
        }
        args.push(match expected {
            Some(value) => arg_bytes(&object_hex(value.object_id())),
            None => OsString::new(),
        });
        let output = self.run_git("update checkpoint ref with CAS", &args, None, &[])?;
        if !output.status.success() {
            if let Ok(actual) = self.read_ref(checkpoint_id, side)
                && actual != expected
            {
                return Err(GitSafetyError::RefConflict {
                    name: ref_name,
                    expected,
                    actual,
                });
            }
            return Err(command_failed("update checkpoint ref with CAS", &output));
        }
        Ok(())
    }

    fn snapshot_matches(
        &self,
        commit: GitCommitId,
        checkpoint_id: CheckpointId,
        side: CheckpointSide,
        relative: &Path,
        captured: &CapturedPath,
    ) -> Result<Option<(CheckpointPathState, TimestampMillis)>, GitSafetyError> {
        let commit_hex = object_hex(commit.object_id());
        let Some(metadata) = self.checkpoint_commit_metadata(&commit_hex, checkpoint_id, side)?
        else {
            return Ok(None);
        };
        self.checkpoint_tree_state(&commit_hex, relative, captured, &metadata)
    }

    fn checkpoint_commit_metadata(
        &self,
        commit_hex: &[u8],
        checkpoint_id: CheckpointId,
        side: CheckpointSide,
    ) -> Result<Option<CheckpointCommitMetadata>, GitSafetyError> {
        let message = self.run_git(
            "inspect checkpoint commit message",
            &[
                arg("show"),
                arg("-s"),
                arg("--format=%B"),
                arg_bytes(commit_hex),
            ],
            None,
            &[],
        )?;
        if !message.status.success() {
            return Ok(None);
        }
        let expected_message = format!(
            "Heterarchy Forge checkpoint {checkpoint_id} {}",
            std::str::from_utf8(side.as_bytes()).unwrap_or("side")
        );
        let body = trim_trailing_newlines(&message.stdout);
        let mut lines = body.split(|byte| *byte == b'\n');
        if lines.next() != Some(expected_message.as_bytes()) {
            return Ok(None);
        }
        let observed_at = parse_timestamp_trailer(lines.next(), TRAILER_OBSERVED_AT)?;
        let state = parse_state_trailer(lines.next())?;
        let mode = parse_mode_trailer(lines.next())?;
        let metadata_state = match state {
            MetadataPathState::Absent => {
                if mode != MetadataMode::Absent || lines.next().is_some() {
                    return Err(tampered_metadata());
                }
                MetadataPathState::Absent
            }
            MetadataPathState::RegularMarker => {
                let MetadataMode::Regular(mode) = mode else {
                    return Err(tampered_metadata());
                };
                let hash = parse_hash_trailer(lines.next())?;
                let file_size = parse_size_trailer(lines.next())?;
                if lines.next().is_some() {
                    return Err(tampered_metadata());
                }
                MetadataPathState::Regular {
                    hash,
                    size: file_size,
                    mode,
                }
            }
            MetadataPathState::Regular { .. } => return Err(tampered_metadata()),
        };
        Ok(Some(CheckpointCommitMetadata {
            observed_at,
            state: metadata_state,
        }))
    }

    fn checkpoint_tree_state(
        &self,
        commit_hex: &[u8],
        relative: &Path,
        captured: &CapturedPath,
        metadata: &CheckpointCommitMetadata,
    ) -> Result<Option<(CheckpointPathState, TimestampMillis)>, GitSafetyError> {
        let tree = self.run_git(
            "inspect checkpoint commit tree",
            &[
                arg("ls-tree"),
                arg("-r"),
                arg("-z"),
                arg("--full-tree"),
                arg_bytes(commit_hex),
            ],
            None,
            &[],
        )?;
        if !tree.status.success() {
            return Ok(None);
        }
        let mut matching = None;
        let mut count = 0_usize;
        for entry in tree
            .stdout
            .split(|byte| *byte == 0)
            .filter(|entry| !entry.is_empty())
        {
            count = count.saturating_add(1);
            let Some(separator) = entry.iter().position(|byte| *byte == b'\t') else {
                return Ok(None);
            };
            let header = &entry[..separator];
            let entry_path = &entry[separator + 1..];
            if entry_path != relative.as_os_str().as_bytes() {
                return Ok(None);
            }
            let mut fields = header.split(|byte| *byte == b' ');
            let Some(mode) = fields.next() else {
                return Ok(None);
            };
            let Some(kind) = fields.next() else {
                return Ok(None);
            };
            let Some(object) = fields.next() else {
                return Ok(None);
            };
            if fields.next().is_some() || kind != b"blob" {
                return Ok(None);
            }
            let Ok(object) = parse_git_object_id("inspect checkpoint tree", object) else {
                return Ok(None);
            };
            matching = Some((mode, GitBlobId::from_sha1_bytes(*object.as_bytes())));
        }

        match (&captured.state, &metadata.state, matching, count) {
            (CheckpointPathState::Absent, MetadataPathState::Absent, None, 0) => {
                Ok(Some((CheckpointPathState::Absent, metadata.observed_at)))
            }
            (
                CheckpointPathState::Regular {
                    hash: captured_hash,
                    size: captured_size,
                    ..
                },
                MetadataPathState::Regular { hash, size, mode },
                Some((tree_mode, blob)),
                1,
            ) => {
                let expected_git_mode = if mode.get() & 0o111 == 0 {
                    b"100644".as_slice()
                } else {
                    b"100755".as_slice()
                };
                if tree_mode != expected_git_mode {
                    return Ok(None);
                }
                let bytes = self.read_blob(blob)?;
                if FileContentHash::from_bytes(*blake3::hash(&bytes).as_bytes()) == *hash
                    && FileByteCount::new(bytes.len() as u64) == *size
                    && *captured_hash == *hash
                    && *captured_size == *size
                    && bytes == captured.content
                {
                    Ok(Some((
                        CheckpointPathState::Regular {
                            blob,
                            hash: *hash,
                            size: *size,
                            mode: *mode,
                        },
                        metadata.observed_at,
                    )))
                } else {
                    Ok(None)
                }
            }
            _ => Ok(None),
        }
    }

    fn capture_path(&self, path: &WorkspaceRelativePath) -> Result<CapturedPath, GitSafetyError> {
        let Some(read) = self
            .confined
            .read_checkpoint(path)
            .map_err(GitSafetyError::Confined)?
        else {
            return Ok(CapturedPath {
                state: CheckpointPathState::Absent,
                content: Vec::new(),
            });
        };
        let hash = read.hash();
        let size = read.size();
        let mode = read.mode();
        let content = read.into_content();
        Ok(CapturedPath {
            state: CheckpointPathState::Regular {
                blob: GitBlobId::from_sha1_bytes([0; GitObjectId::BYTE_LEN]),
                hash,
                size,
                mode,
            },
            content,
        })
    }

    fn create_commit(
        &self,
        checkpoint_id: CheckpointId,
        side: CheckpointSide,
        relative: &Path,
        captured: &CapturedPath,
        observed_at: TimestampMillis,
    ) -> Result<(CheckpointPathState, GitCommitId), GitSafetyError> {
        let state = match &captured.state {
            CheckpointPathState::Absent => CheckpointPathState::Absent,
            CheckpointPathState::Regular {
                hash, size, mode, ..
            } => {
                let blob = self.write_blob(&captured.content)?;
                CheckpointPathState::Regular {
                    blob,
                    hash: *hash,
                    size: *size,
                    mode: *mode,
                }
            }
        };
        let tree = self.create_checkpoint_tree(relative, &state)?;
        let message = checkpoint_commit_message(checkpoint_id, side, &state, observed_at);
        // The `@<unix-seconds>` form is accepted by Git even for deterministic
        // test timestamps near the epoch and avoids locale-dependent parsing.
        let date = format!("@{} +0000", observed_at.get().div_euclid(1_000));
        let commit_env = [
            ("GIT_AUTHOR_NAME", OsString::from("Heterarchy Forge")),
            ("GIT_AUTHOR_EMAIL", OsString::from("forge@localhost")),
            ("GIT_COMMITTER_NAME", OsString::from("Heterarchy Forge")),
            ("GIT_COMMITTER_EMAIL", OsString::from("forge@localhost")),
            ("GIT_AUTHOR_DATE", OsString::from(date.clone())),
            ("GIT_COMMITTER_DATE", OsString::from(date)),
        ];
        let commit_output = self.run_git(
            "create checkpoint commit",
            &[
                arg("commit-tree"),
                arg_bytes(&object_hex(tree)),
                arg("-m"),
                OsString::from(message),
            ],
            None,
            &commit_env,
        )?;
        if !commit_output.status.success() {
            return Err(command_failed("create checkpoint commit", &commit_output));
        }
        let commit = parse_git_object_id("create checkpoint commit", &commit_output.stdout)?;
        Ok((state, GitCommitId::from_sha1_bytes(*commit.as_bytes())))
    }

    fn create_checkpoint_tree(
        &self,
        relative: &Path,
        state: &CheckpointPathState,
    ) -> Result<GitObjectId, GitSafetyError> {
        let CheckpointPathState::Regular { blob, mode, .. } = state else {
            return self.write_mktree(&[]);
        };
        let components = relative
            .components()
            .filter_map(|component| match component {
                Component::Normal(value) => Some(value),
                Component::Prefix(_)
                | Component::RootDir
                | Component::CurDir
                | Component::ParentDir => None,
            })
            .collect::<Vec<_>>();
        let Some(leaf) = components.last() else {
            return Err(GitSafetyError::PathNotRepresentable);
        };
        let git_mode = if mode.get() & 0o111 == 0 {
            b"100644"
        } else {
            b"100755"
        };
        let mut tree = self.write_mktree(&mktree_entry(
            git_mode,
            b"blob",
            blob.object_id(),
            leaf.as_bytes(),
        )?)?;
        for component in components[..components.len() - 1].iter().rev() {
            tree = self.write_mktree(&mktree_entry(
                b"040000",
                b"tree",
                tree,
                component.as_bytes(),
            )?)?;
        }
        Ok(tree)
    }

    fn write_mktree(&self, input: &[u8]) -> Result<GitObjectId, GitSafetyError> {
        let output = self.run_git(
            "write checkpoint tree",
            &[arg("mktree"), arg("-z")],
            Some(input),
            &[],
        )?;
        if !output.status.success() {
            return Err(command_failed("write checkpoint tree", &output));
        }
        parse_git_object_id("write checkpoint tree", &output.stdout)
    }

    fn write_blob(&self, content: &[u8]) -> Result<GitBlobId, GitSafetyError> {
        if content.len() > MAX_GIT_STDIN_BYTES {
            return Err(GitSafetyError::GitInputTooLarge {
                maximum: MAX_GIT_STDIN_BYTES,
            });
        }
        let output = self.run_git(
            "write checkpoint blob",
            &[arg("hash-object"), arg("-w"), arg("--stdin")],
            Some(content),
            &[],
        )?;
        if !output.status.success() {
            return Err(command_failed("write checkpoint blob", &output));
        }
        let object = parse_git_object_id("write checkpoint blob", &output.stdout)?;
        Ok(GitBlobId::from_sha1_bytes(*object.as_bytes()))
    }

    fn run_git(
        &self,
        operation: &str,
        arguments: &[OsString],
        stdin: Option<&[u8]>,
        extra_env: &[(&str, OsString)],
    ) -> Result<GitOutput, GitSafetyError> {
        self.run_git_with_limit(operation, arguments, stdin, extra_env, MAX_GIT_OUTPUT_BYTES)
    }

    fn spawn_git(
        &self,
        operation: &str,
        arguments: &[OsString],
        stdin: Option<&[u8]>,
        extra_env: &[(&str, OsString)],
    ) -> Result<Child, GitSafetyError> {
        if stdin.is_some_and(|bytes| bytes.len() > MAX_GIT_STDIN_BYTES) {
            return Err(GitSafetyError::GitInputTooLarge {
                maximum: MAX_GIT_STDIN_BYTES,
            });
        }
        self.confined
            .ensure_for_git(false)
            .map_err(GitSafetyError::Confined)?;
        let observed_store =
            directory_identity_by_path(&self.store).map_err(GitSafetyError::Confined)?;
        if observed_store != self.store_identity {
            return Err(GitSafetyError::Confined(
                ConfinedFilesystemError::CommittedPathChanged,
            ));
        }
        let mut command = Command::new(GIT_PROGRAM);
        command
            .current_dir(&self.checkpoints)
            .args(arguments)
            .env_clear()
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", "/nonexistent")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .process_group(0)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            });
        for (key, value) in extra_env {
            command.env(key, value);
        }
        command
            .env("GIT_DIR", &self.store)
            .env("GIT_NO_REPLACE_OBJECTS", "1")
            .env("GIT_NO_LAZY_FETCH", "1")
            .env("GIT_OPTIONAL_LOCKS", "0")
            .env("GIT_TERMINAL_PROMPT", "0");
        command.spawn().map_err(|source| GitSafetyError::StartGit {
            operation: operation.to_owned(),
            source,
        })
    }

    fn run_git_with_limit(
        &self,
        operation: &str,
        arguments: &[OsString],
        stdin: Option<&[u8]>,
        extra_env: &[(&str, OsString)],
        output_limit: usize,
    ) -> Result<GitOutput, GitSafetyError> {
        let mut child = self.spawn_git(operation, arguments, stdin, extra_env)?;
        let Some(stdout) = child.stdout.take() else {
            let cleanup_ok = terminate_git_process_group_and_reap(&mut child);
            if !cleanup_ok {
                return Err(GitSafetyError::GitProcessCleanupFailed);
            }
            return Err(GitSafetyError::GitOutputPipeUnavailable { stream: "stdout" });
        };
        let Some(stderr) = child.stderr.take() else {
            let cleanup_ok = terminate_git_process_group_and_reap(&mut child);
            if !cleanup_ok {
                return Err(GitSafetyError::GitProcessCleanupFailed);
            }
            return Err(GitSafetyError::GitOutputPipeUnavailable { stream: "stderr" });
        };
        // Git producers such as `hash-object --stdin` must receive input
        // while their output pipes are being drained; writing synchronously
        // before starting the readers can deadlock once a pipe fills.
        let input_thread = if let Some(bytes) = stdin {
            let Some(mut input) = child.stdin.take() else {
                let cleanup_ok = terminate_git_process_group_and_reap(&mut child);
                if !cleanup_ok {
                    return Err(GitSafetyError::GitProcessCleanupFailed);
                }
                return Err(GitSafetyError::GitOutputPipeUnavailable { stream: "stdin" });
            };
            let bytes = bytes.to_vec();
            Some(thread::spawn(move || input.write_all(&bytes)))
        } else {
            None
        };
        let (stdout_result, stderr_result, timed_out, mut cleanup_failed) =
            capture_git_streams(&mut child, stdout, stderr, output_limit);
        let input_error = input_thread.and_then(|thread| match thread.join() {
            Ok(Ok(())) => None,
            Ok(Err(source)) => Some(GitSafetyError::GitInputWrite {
                operation: operation.to_owned(),
                source,
            }),
            Err(_) => Some(GitSafetyError::GitOutputReaderPanicked { stream: "stdin" }),
        });
        if input_error.is_some() {
            cleanup_failed |= !terminate_git_process_group(&mut child);
        }
        let status = child.wait().map_err(|source| GitSafetyError::WaitGit {
            operation: operation.to_owned(),
            source,
        })?;
        if let Err(source) = self.confined.ensure_for_git(true) {
            return Err(GitSafetyError::GitPathChangedAfter(source));
        }
        if directory_identity_by_path(&self.store).map_err(GitSafetyError::Confined)?
            != self.store_identity
        {
            return Err(GitSafetyError::GitPathChangedAfter(
                ConfinedFilesystemError::CommittedPathChanged,
            ));
        }
        if cleanup_failed {
            return Err(GitSafetyError::GitProcessCleanupFailed);
        }
        if timed_out {
            return Err(GitSafetyError::GitTimeout {
                operation: operation.to_owned(),
            });
        }
        let stdout = map_capture_result(stdout_result, "stdout", output_limit)?;
        let stderr = map_capture_result(stderr_result, "stderr", output_limit)?;
        if let Some(error) = input_error {
            return Err(error);
        }
        Ok(GitOutput {
            status,
            stdout: stdout.bytes,
            stderr: stderr.bytes,
        })
    }
}

#[derive(Debug)]
struct CapturedPath {
    state: CheckpointPathState,
    content: Vec<u8>,
}

const TRAILER_OBSERVED_AT: &[u8] = b"Heterarchy-Forge-Observed-At-Ms";
const TRAILER_STATE: &[u8] = b"Heterarchy-Forge-State";
const TRAILER_MODE: &[u8] = b"Heterarchy-Forge-Mode";
const TRAILER_HASH: &[u8] = b"Heterarchy-Forge-Hash";
const TRAILER_SIZE: &[u8] = b"Heterarchy-Forge-Size";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CheckpointCommitMetadata {
    observed_at: TimestampMillis,
    state: MetadataPathState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MetadataPathState {
    Absent,
    RegularMarker,
    Regular {
        hash: FileContentHash,
        size: FileByteCount,
        mode: CheckpointFileMode,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MetadataMode {
    Absent,
    Regular(CheckpointFileMode),
}

fn tampered_metadata() -> GitSafetyError {
    GitSafetyError::TamperedRef {
        name: "checkpoint commit metadata".to_owned(),
    }
}

fn parse_trailer_value<'a>(line: Option<&'a [u8]>, key: &[u8]) -> Result<&'a [u8], GitSafetyError> {
    let Some(line) = line else {
        return Err(tampered_metadata());
    };
    if !line.starts_with(key)
        || line.get(key.len()) != Some(&b':')
        || line.get(key.len() + 1) != Some(&b' ')
    {
        return Err(tampered_metadata());
    }
    let value = &line[key.len() + 2..];
    if value.is_empty() {
        return Err(tampered_metadata());
    }
    Ok(value)
}

fn parse_timestamp_trailer(
    line: Option<&[u8]>,
    key: &[u8],
) -> Result<TimestampMillis, GitSafetyError> {
    let value = parse_trailer_value(line, key)?;
    let text = std::str::from_utf8(value).map_err(|_| tampered_metadata())?;
    let parsed = i64::from_str(text).map_err(|_| tampered_metadata())?;
    if parsed.to_string() != text {
        return Err(tampered_metadata());
    }
    TimestampMillis::new(parsed).map_err(|_| tampered_metadata())
}

fn parse_state_trailer(line: Option<&[u8]>) -> Result<MetadataPathState, GitSafetyError> {
    match parse_trailer_value(line, TRAILER_STATE)? {
        b"absent" => Ok(MetadataPathState::Absent),
        b"regular" => Ok(MetadataPathState::RegularMarker),
        _ => Err(tampered_metadata()),
    }
}

fn parse_mode_trailer(line: Option<&[u8]>) -> Result<MetadataMode, GitSafetyError> {
    let value = parse_trailer_value(line, TRAILER_MODE)?;
    if value == b"absent" {
        return Ok(MetadataMode::Absent);
    }
    let text = std::str::from_utf8(value).map_err(|_| tampered_metadata())?;
    let parsed = u16::from_str_radix(text, 8).map_err(|_| tampered_metadata())?;
    if format!("{parsed:o}") != text {
        return Err(tampered_metadata());
    }
    CheckpointFileMode::new(parsed)
        .map(MetadataMode::Regular)
        .map_err(|_| tampered_metadata())
}

fn parse_hash_trailer(line: Option<&[u8]>) -> Result<FileContentHash, GitSafetyError> {
    let value = parse_trailer_value(line, TRAILER_HASH)?;
    let text = std::str::from_utf8(value).map_err(|_| tampered_metadata())?;
    let parsed = FileContentHash::from_str(text).map_err(|_| tampered_metadata())?;
    if parsed.to_string() != text {
        return Err(tampered_metadata());
    }
    Ok(parsed)
}

fn parse_size_trailer(line: Option<&[u8]>) -> Result<FileByteCount, GitSafetyError> {
    let value = parse_trailer_value(line, TRAILER_SIZE)?;
    let text = std::str::from_utf8(value).map_err(|_| tampered_metadata())?;
    let parsed = u64::from_str(text).map_err(|_| tampered_metadata())?;
    if parsed.to_string() != text {
        return Err(tampered_metadata());
    }
    Ok(FileByteCount::new(parsed))
}

fn checkpoint_commit_message(
    checkpoint_id: CheckpointId,
    side: CheckpointSide,
    state: &CheckpointPathState,
    observed_at: TimestampMillis,
) -> String {
    let mut message = format!(
        "Heterarchy Forge checkpoint {checkpoint_id} {}\nHeterarchy-Forge-Observed-At-Ms: {}\n",
        std::str::from_utf8(side.as_bytes()).unwrap_or("side"),
        observed_at.get()
    );
    match state {
        CheckpointPathState::Absent => {
            message.push_str("Heterarchy-Forge-State: absent\n");
            message.push_str("Heterarchy-Forge-Mode: absent\n");
        }
        CheckpointPathState::Regular {
            hash, size, mode, ..
        } => {
            message.push_str("Heterarchy-Forge-State: regular\n");
            let _ = writeln!(message, "Heterarchy-Forge-Mode: {:o}", mode.get());
            let _ = writeln!(message, "Heterarchy-Forge-Hash: {hash}");
            let _ = writeln!(message, "Heterarchy-Forge-Size: {}", size.get());
        }
    }
    message
}

#[derive(Debug)]
struct GitOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

#[derive(Debug)]
struct BoundedCapture {
    bytes: Vec<u8>,
    total: usize,
}

#[derive(Debug)]
enum BoundedReadError {
    Io(io::Error),
}

fn canonical_workspace_root(path: &Path) -> Result<PathBuf, GitSafetyError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| GitSafetyError::InvalidWorkspaceRoot {
            path: path.to_path_buf(),
        })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(GitSafetyError::InvalidWorkspaceRoot {
            path: path.to_path_buf(),
        });
    }
    fs::canonicalize(path).map_err(|_| GitSafetyError::InvalidWorkspaceRoot {
        path: path.to_path_buf(),
    })
}

fn validate_owned_store_shape(store: &Path) -> Result<(), GitSafetyError> {
    let head =
        fs::symlink_metadata(store.join("HEAD")).map_err(|source| GitSafetyError::Filesystem {
            operation: "inspect checkpoint store HEAD".to_owned(),
            path: store.to_path_buf(),
            source,
        })?;
    if head.file_type().is_symlink() || !head.is_file() {
        return Err(GitSafetyError::InvalidCheckpointRoot {
            path: store.to_path_buf(),
        });
    }
    for required in ["objects", "refs"] {
        let path = store.join(required);
        let metadata =
            fs::symlink_metadata(&path).map_err(|source| GitSafetyError::Filesystem {
                operation: "inspect checkpoint store directory".to_owned(),
                path: path.clone(),
                source,
            })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(GitSafetyError::InvalidCheckpointRoot {
                path: store.to_path_buf(),
            });
        }
    }
    Ok(())
}

fn validate_checkpoint_root(
    workspace_root: &Path,
    requested: &Path,
) -> Result<PathBuf, GitSafetyError> {
    if !requested.is_absolute() {
        return Err(GitSafetyError::InvalidCheckpointRoot {
            path: requested.to_path_buf(),
        });
    }
    if let Ok(metadata) = fs::symlink_metadata(requested)
        && metadata.file_type().is_symlink()
    {
        return Err(GitSafetyError::SymlinkPath {
            path: requested.to_path_buf(),
        });
    }
    let expected = workspace_root
        .join(OsStr::from_bytes(STATE_DIRECTORY_NAME))
        .join(OsStr::from_bytes(CHECKPOINT_DIRECTORY_NAME));
    ensure_no_symlink_components(&expected)?;
    let expected =
        fs::canonicalize(&expected).map_err(|_| GitSafetyError::InvalidCheckpointRoot {
            path: expected.clone(),
        })?;
    let actual = fs::canonicalize(requested).map_err(|source| GitSafetyError::Filesystem {
        operation: "canonicalize requested checkpoint root".to_owned(),
        path: requested.to_path_buf(),
        source,
    })?;
    if actual != expected {
        return Err(GitSafetyError::InvalidCheckpointRoot { path: actual });
    }
    Ok(actual)
}

fn ensure_no_symlink_components(path: &Path) -> Result<(), GitSafetyError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(GitSafetyError::SymlinkPath { path: current });
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(GitSafetyError::Filesystem {
                    operation: "inspect checkpoint root component".to_owned(),
                    path: current,
                    source,
                });
            }
        }
    }
    Ok(())
}

fn resolve_repository_root(workspace_root: &Path) -> Result<PathBuf, GitSafetyError> {
    let mut candidate = Some(workspace_root);
    while let Some(current) = candidate {
        let git_path = current.join(".git");
        match fs::symlink_metadata(&git_path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(GitSafetyError::UnsupportedGitLayout);
            }
            Ok(metadata) if metadata.is_dir() => return Ok(current.to_path_buf()),
            Ok(_) => return Err(GitSafetyError::UnsupportedGitLayout),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                candidate = current.parent();
            }
            Err(source) => {
                return Err(GitSafetyError::Filesystem {
                    operation: "inspect Git directory".to_owned(),
                    path: git_path,
                    source,
                });
            }
        }
    }
    Err(GitSafetyError::NotGitRepository)
}

// Terminate the dedicated Git process group with the macOS kill utility. The
// negative PGID targets descendants as well as the Git leader.
fn terminate_git_process_group(child: &mut Child) -> bool {
    let pid = child.id();
    let _term_sent = run_group_signal(pid, "-TERM");
    let term_deadline = Instant::now() + Duration::from_millis(50);
    while Instant::now() < term_deadline {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => thread::sleep(GIT_POLL_INTERVAL),
            Err(_) => return false,
        }
    }
    let _kill_sent = run_group_signal(pid, "-KILL");
    let reap_deadline = Instant::now() + Duration::from_millis(500);
    while Instant::now() < reap_deadline {
        if !run_group_signal(pid, "-0") {
            return true;
        }
        thread::sleep(GIT_POLL_INTERVAL);
    }
    let _direct_kill = child.kill();
    !run_group_signal(pid, "-0")
}

fn terminate_git_process_group_and_reap(child: &mut Child) -> bool {
    let cleanup_ok = terminate_git_process_group(child);
    let wait_ok = child.wait().is_ok();
    cleanup_ok && wait_ok
}

fn run_group_signal(pid: u32, signal: &str) -> bool {
    let group = format!("-{pid}");
    let mut command = Command::new("/bin/kill");
    command
        .arg(signal)
        .arg("--")
        .arg(group)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let Ok(mut killer) = command.spawn() else {
        return false;
    };
    let deadline = Instant::now() + Duration::from_millis(100);
    loop {
        match killer.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) if Instant::now() < deadline => thread::sleep(GIT_POLL_INTERVAL),
            Ok(None) | Err(_) => {
                let _ignored = killer.kill();
                let _ignored = killer.wait();
                return false;
            }
        }
    }
}

fn capture_git_streams(
    child: &mut Child,
    stdout: ChildStdout,
    stderr: ChildStderr,
    maximum: usize,
) -> (
    Result<BoundedCapture, BoundedReadError>,
    Result<BoundedCapture, BoundedReadError>,
    bool,
    bool,
) {
    capture_git_streams_until(
        child,
        stdout,
        stderr,
        maximum,
        Instant::now() + GIT_PROCESS_TIMEOUT,
    )
}

fn capture_git_streams_until(
    child: &mut Child,
    stdout: ChildStdout,
    stderr: ChildStderr,
    maximum: usize,
    deadline: Instant,
) -> (
    Result<BoundedCapture, BoundedReadError>,
    Result<BoundedCapture, BoundedReadError>,
    bool,
    bool,
) {
    thread::scope(|scope| {
        let (sender, receiver) = mpsc::sync_channel(2);
        let stdout_sender = sender.clone();
        let stdout_thread = scope.spawn(move || {
            let _ignored =
                stdout_sender.send(BoundedReadResult::Stdout(read_capped(stdout, maximum)));
        });
        let stderr_thread = scope.spawn(move || {
            let _ignored = sender.send(BoundedReadResult::Stderr(read_capped(stderr, maximum)));
        });
        let mut stdout_result = None;
        let mut stderr_result = None;
        let mut terminated = false;
        let mut timed_out = false;
        let mut cleanup_failed = false;
        while stdout_result.is_none() || stderr_result.is_none() {
            let now = Instant::now();
            if now >= deadline && !terminated {
                cleanup_failed |= !terminate_git_process_group(child);
                terminated = true;
                timed_out = true;
            }
            let wait = if terminated {
                GIT_POLL_INTERVAL
            } else {
                deadline
                    .saturating_duration_since(now)
                    .min(GIT_POLL_INTERVAL)
            };
            let result = match receiver.recv_timeout(wait) {
                Ok(result) => result,
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(_) => break,
            };
            match result {
                BoundedReadResult::Stdout(result) => {
                    if result.as_ref().is_ok_and(|capture| capture.total > maximum) && !terminated {
                        cleanup_failed |= !terminate_git_process_group(child);
                        terminated = true;
                    }
                    stdout_result = Some(result);
                }
                BoundedReadResult::Stderr(result) => {
                    if result.as_ref().is_ok_and(|capture| capture.total > maximum) && !terminated {
                        cleanup_failed |= !terminate_git_process_group(child);
                        terminated = true;
                    }
                    stderr_result = Some(result);
                }
            }
        }
        if (stdout_result.is_none() || stderr_result.is_none()) && !terminated {
            cleanup_failed |= !terminate_git_process_group(child);
        }
        let stdout_panicked = stdout_thread.join().is_err();
        let stderr_panicked = stderr_thread.join().is_err();
        if stdout_panicked || stderr_panicked {
            cleanup_failed |= !terminate_git_process_group(child);
        }
        (
            stdout_result
                .unwrap_or_else(|| Err(BoundedReadError::Io(io::Error::other("reader missing")))),
            stderr_result
                .unwrap_or_else(|| Err(BoundedReadError::Io(io::Error::other("reader missing")))),
            timed_out,
            cleanup_failed,
        )
    })
}

enum BoundedReadResult {
    Stdout(Result<BoundedCapture, BoundedReadError>),
    Stderr(Result<BoundedCapture, BoundedReadError>),
}

fn read_capped<R: Read>(mut reader: R, maximum: usize) -> Result<BoundedCapture, BoundedReadError> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 8 * 1024];
    let mut total = 0_usize;
    loop {
        let read = reader.read(&mut buffer).map_err(BoundedReadError::Io)?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read);
        let retained = read.min(maximum.saturating_add(1).saturating_sub(bytes.len()));
        bytes.extend_from_slice(&buffer[..retained]);
        if total > maximum {
            break;
        }
    }
    Ok(BoundedCapture { bytes, total })
}

fn map_capture_result(
    result: Result<BoundedCapture, BoundedReadError>,
    stream: &'static str,
    maximum: usize,
) -> Result<BoundedCapture, GitSafetyError> {
    match result {
        Ok(capture) if capture.total > maximum => {
            Err(GitSafetyError::GitOutputTooLarge { stream, maximum })
        }
        Ok(capture) => Ok(capture),
        Err(BoundedReadError::Io(source)) => Err(GitSafetyError::GitOutputRead {
            stream,
            source: io::Error::new(source.kind(), source),
        }),
    }
}

fn validate_repository_relative_path(path: &Path) -> Result<(), GitSafetyError> {
    if path.as_os_str().is_empty() || path.is_absolute() {
        return Err(GitSafetyError::PathNotRepresentable);
    }
    for component in path.components() {
        match component {
            Component::Normal(value) if !value.as_bytes().contains(&0) => {}
            _ => return Err(GitSafetyError::PathNotRepresentable),
        }
    }
    Ok(())
}

fn mktree_entry(
    mode: &[u8],
    kind: &[u8],
    object: GitObjectId,
    name: &[u8],
) -> Result<Vec<u8>, GitSafetyError> {
    if name.contains(&0) {
        return Err(GitSafetyError::PathNotRepresentable);
    }
    let mut value = Vec::with_capacity(mode.len() + kind.len() + 32 + name.len() + 4);
    value.extend_from_slice(mode);
    value.push(b' ');
    value.extend_from_slice(kind);
    value.push(b' ');
    value.extend_from_slice(&object_hex(object));
    value.push(b'\t');
    value.extend_from_slice(name);
    value.push(0);
    Ok(value)
}

fn parse_checkpoint_ref_inventory(
    output: &[u8],
) -> Result<Vec<GitCheckpointRefInventoryEntry>, GitSafetyError> {
    let mut entries = Vec::new();
    for record in output
        .split(|byte| *byte == b'\n')
        .filter(|record| !record.is_empty())
    {
        let mut fields = record.split(|byte| *byte == 0);
        let Some(ref_name) = fields.next() else {
            continue;
        };
        let Some(object_name) = fields.next() else {
            entries.push(GitCheckpointRefInventoryEntry::Malformed);
            continue;
        };
        let Some(object_type) = fields.next() else {
            entries.push(GitCheckpointRefInventoryEntry::Malformed);
            continue;
        };
        if fields.next().is_some() {
            entries.push(GitCheckpointRefInventoryEntry::Malformed);
            continue;
        }
        let Some((checkpoint_id, side)) = parse_checkpoint_ref_identity(ref_name) else {
            entries.push(GitCheckpointRefInventoryEntry::Malformed);
            continue;
        };
        if object_type != b"commit" {
            entries.push(GitCheckpointRefInventoryEntry::NonCommit {
                checkpoint_id,
                side,
            });
            continue;
        }
        let object = parse_git_object_id("inventory checkpoint ref", object_name)?;
        entries.push(GitCheckpointRefInventoryEntry::Retained {
            checkpoint_id,
            side,
            commit: GitCommitId::from_sha1_bytes(*object.as_bytes()),
        });
    }
    Ok(entries)
}

fn parse_checkpoint_ref_identity(ref_name: &[u8]) -> Option<(CheckpointId, CheckpointSide)> {
    let suffix = ref_name.strip_prefix(GIT_REF_PREFIX.as_bytes())?;
    let separator = suffix.iter().rposition(|byte| *byte == b'/')?;
    let (id_bytes, side_with_separator) = suffix.split_at(separator);
    let side_bytes = side_with_separator.get(1..)?;
    let id_text = std::str::from_utf8(id_bytes).ok()?;
    let checkpoint_id = CheckpointId::from_str(id_text).ok()?;
    if checkpoint_id.to_string().as_bytes() != id_bytes {
        return None;
    }
    let side = match side_bytes {
        b"pre" => CheckpointSide::Pre,
        b"post" => CheckpointSide::Post,
        _ => return None,
    };
    Some((checkpoint_id, side))
}

fn parse_checkpoint_object_verifications(
    expectations: &[GitCheckpointObjectExpectation],
    output: &[u8],
) -> Result<Vec<GitCheckpointObjectVerification>, GitSafetyError> {
    let records = output
        .split(|byte| *byte == b'\n')
        .filter(|record| !record.is_empty())
        .collect::<Vec<_>>();
    if records.len() != expectations.len() {
        return Err(GitSafetyError::MalformedObjectVerificationOutput);
    }
    let mut verifications = Vec::with_capacity(expectations.len());
    for (expectation, record) in expectations.iter().copied().zip(records) {
        let mut fields = record.split(|byte| *byte == b' ');
        let object_name = fields
            .next()
            .ok_or(GitSafetyError::MalformedObjectVerificationOutput)?;
        let kind = fields
            .next()
            .ok_or(GitSafetyError::MalformedObjectVerificationOutput)?;
        if object_name != object_hex(expectation.object_id()) {
            return Err(GitSafetyError::MalformedObjectVerificationOutput);
        }
        let status = if kind == b"missing" {
            if fields.next().is_some() {
                return Err(GitSafetyError::MalformedObjectVerificationOutput);
            }
            GitCheckpointObjectVerificationStatus::Missing
        } else {
            let size = fields
                .next()
                .ok_or(GitSafetyError::MalformedObjectVerificationOutput)?;
            if fields.next().is_some() || size.is_empty() || !size.iter().all(u8::is_ascii_digit) {
                return Err(GitSafetyError::MalformedObjectVerificationOutput);
            }
            if kind == expectation.expected_type() {
                GitCheckpointObjectVerificationStatus::Present
            } else {
                GitCheckpointObjectVerificationStatus::TypeMismatch
            }
        };
        verifications.push(GitCheckpointObjectVerification {
            expectation,
            status,
        });
    }
    Ok(verifications)
}

fn parse_git_object_id(operation: &str, output: &[u8]) -> Result<GitObjectId, GitSafetyError> {
    let value = trim_single_newline(output);
    if value.len() != GitObjectId::BYTE_LEN * 2
        || !value.iter().all(u8::is_ascii_hexdigit)
        || value.iter().any(u8::is_ascii_uppercase)
    {
        return Err(GitSafetyError::InvalidObjectId {
            operation: operation.to_owned(),
            value: value.to_vec(),
        });
    }
    let mut bytes = [0_u8; GitObjectId::BYTE_LEN];
    for (index, pair) in value.chunks_exact(2).enumerate() {
        bytes[index] = (hex(pair[0]) << 4) | hex(pair[1]);
    }
    Ok(GitObjectId::from_sha1_bytes(bytes))
}

const fn hex(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => 0,
    }
}

fn object_hex(object: GitObjectId) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(GitObjectId::BYTE_LEN * 2);
    for byte in object.as_bytes() {
        bytes.push(b"0123456789abcdef"[(byte >> 4) as usize]);
        bytes.push(b"0123456789abcdef"[(byte & 0x0f) as usize]);
    }
    bytes
}

fn trim_single_newline(value: &[u8]) -> &[u8] {
    value.strip_suffix(b"\n").unwrap_or(value)
}

fn trim_trailing_newlines(mut value: &[u8]) -> &[u8] {
    while let Some(trimmed) = value.strip_suffix(b"\n") {
        value = trimmed;
    }
    value
}

fn arg(value: &str) -> OsString {
    OsString::from(value)
}

fn arg_bytes(value: &[u8]) -> OsString {
    OsString::from_vec(value.to_vec())
}

fn os(value: &str) -> OsString {
    OsString::from(value)
}

fn command_failed(operation: &str, output: &GitOutput) -> GitSafetyError {
    GitSafetyError::GitCommandFailed {
        operation: operation.to_owned(),
        status: output.status.code(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::fs::symlink;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use forge_domain::{
        ActivityId, ChangeSetId, CheckpointAttribution, CheckpointId, CheckpointState, WorkspaceId,
        WorkspaceRelativePath, WorkspaceRevision,
    };
    use uuid::Uuid;

    use super::*;

    struct TestRepo {
        root: PathBuf,
    }

    impl TestRepo {
        fn create(name: &str) -> Result<Self, Box<dyn std::error::Error>> {
            let root = env::temp_dir().join(format!(
                "heterarchy-forge-git-{name}-{}",
                std::process::id()
            ));
            let _ignored = fs::remove_dir_all(&root);
            fs::create_dir_all(&root)?;
            run_git_test(&root, &["init", "-q"])?;
            run_git_test(&root, &["config", "user.name", "Test"])?;
            run_git_test(&root, &["config", "user.email", "test@example.invalid"])?;
            Ok(Self { root })
        }

        fn commit_initial(&self) -> Result<(), Box<dyn std::error::Error>> {
            fs::write(self.root.join("tracked.txt"), b"base\n")?;
            run_git_test(&self.root, &["add", "tracked.txt"])?;
            run_git_test(&self.root, &["commit", "-qm", "initial"])?;
            Ok(())
        }
    }

    impl Drop for TestRepo {
        fn drop(&mut self) {
            let _ignored = fs::remove_dir_all(&self.root);
        }
    }

    fn run_git_test(root: &Path, args: &[&str]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let output = Command::new(GIT_PROGRAM)
            .arg("-C")
            .arg(root)
            .args(args)
            .env_clear()
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", "/nonexistent")
            .output()?;
        if !output.status.success() {
            return Err(format!(
                "git {:?}: {}",
                args,
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(output.stdout)
    }

    fn output(root: &Path, args: &[&str]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        run_git_test(root, args)
    }

    /// Run plumbing against the product-owned bare store.
    fn run_git_store(store: &Path, args: &[&str]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let output = Command::new(GIT_PROGRAM)
            .arg("--git-dir")
            .arg(store)
            .args([
                "-c",
                "user.name=Tamper",
                "-c",
                "user.email=tamper@example.invalid",
            ])
            .args(args)
            .env_clear()
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", "/nonexistent")
            .output()?;
        if !output.status.success() {
            return Err(format!(
                "git --git-dir={store:?} {args:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(output.stdout)
    }

    fn output_store(store: &Path, args: &[&str]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        run_git_store(store, args)
    }

    fn open_store(root: &Path) -> Result<GitCheckpointStore, Box<dyn std::error::Error>> {
        let layout = WorkspaceStateLayout::initialize(root)?;
        Ok(GitCheckpointStore::from_state_layout(&layout)?)
    }

    fn path(value: &str) -> Result<WorkspaceRelativePath, Box<dyn std::error::Error>> {
        Ok(WorkspaceRelativePath::new(PathBuf::from(value))?)
    }

    fn id(value: u128) -> CheckpointId {
        CheckpointId::from_uuid(Uuid::from_u128(value))
    }

    fn attribution(checkpoint: CheckpointId) -> CheckpointAttribution {
        CheckpointAttribution::new(
            checkpoint,
            ChangeSetId::from_uuid(Uuid::from_u128(2)),
            WorkspaceId::from_uuid(Uuid::from_u128(3)),
            WorkspaceRevision::INITIAL,
            ActivityId::from_uuid(Uuid::from_u128(5)),
        )
    }

    #[test]
    fn checkpoint_objects_and_refs_preserve_real_git_state()
    -> Result<(), Box<dyn std::error::Error>> {
        let repo = TestRepo::create("state")?;
        repo.commit_initial()?;
        let nested = repo.root.join("nested");
        fs::create_dir_all(&nested)?;
        fs::write(nested.join("goal.txt"), b"before\n")?;
        let mut permissions = fs::metadata(nested.join("goal.txt"))?.permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(nested.join("goal.txt"), permissions)?;
        run_git_test(&repo.root, &["add", "nested/goal.txt"])?;
        run_git_test(&repo.root, &["commit", "-qm", "nested"])?;

        fs::write(repo.root.join("tracked.txt"), b"staged\n")?;
        run_git_test(&repo.root, &["add", "tracked.txt"])?;
        fs::write(repo.root.join("tracked.txt"), b"unstaged\n")?;
        fs::write(repo.root.join("untracked.txt"), b"untracked\n")?;
        let layout = WorkspaceStateLayout::initialize(&nested)?;

        let store = GitCheckpointStore::from_state_layout(&layout)?;
        let checkpoint = id(1);
        let starting = store.begin_checkpoint(
            attribution(checkpoint),
            path("goal.txt")?,
            TimestampMillis::new(1_000)?,
        )?;
        assert_eq!(starting.state(), CheckpointState::Starting);
        assert!(
            starting
                .pre_commit()
                .object_id()
                .as_bytes()
                .iter()
                .any(|byte| *byte != 0)
        );
        assert_eq!(
            store.read_ref(checkpoint, CheckpointSide::Pre)?,
            Some(starting.pre_commit())
        );
        assert!(matches!(
            starting.pre(),
            CheckpointPathState::Regular { mode, .. } if mode.get() == 0o600
        ));

        fs::write(nested.join("goal.txt"), b"after\n")?;
        let head_before = output(&repo.root, &["rev-parse", "HEAD"])?;
        let branch_before = output(&repo.root, &["symbolic-ref", "--short", "HEAD"])?;
        let index_before = fs::read(repo.root.join(".git/index"))?;
        let status_before = output(&repo.root, &["status", "--porcelain=v1", "-z"])?;
        let ready = store.complete_checkpoint(&starting, TimestampMillis::new(2_000)?)?;
        assert_eq!(ready.state(), CheckpointState::Ready);
        let post = ready.post().ok_or("post state missing")?;
        let blob = match post {
            CheckpointPathState::Regular { blob, .. } => *blob,
            CheckpointPathState::Absent => return Err("post state unexpectedly absent".into()),
        };
        assert_eq!(store.read_blob(blob)?, b"after\n");
        assert_eq!(
            store.read_ref(checkpoint, CheckpointSide::Post)?,
            ready.post_commit()
        );
        let post_commit_id = ready.post_commit().ok_or("post commit missing")?;
        let post_commit = String::from_utf8(object_hex(post_commit_id.object_id()))?;
        assert_eq!(
            output_store(
                Path::new(store.git_store_path()),
                &["ls-tree", "-r", "--name-only", &post_commit],
            )?,
            b"nested/goal.txt\n"
        );

        assert_eq!(output(&repo.root, &["rev-parse", "HEAD"])?, head_before);
        assert_eq!(
            output(&repo.root, &["symbolic-ref", "--short", "HEAD"])?,
            branch_before
        );
        assert_eq!(fs::read(repo.root.join(".git/index"))?, index_before);
        assert_eq!(
            output(&repo.root, &["status", "--porcelain=v1", "-z"])?,
            status_before
        );
        let stale_index = fs::read_dir(layout.checkpoints())?.any(|entry| {
            entry
                .ok()
                .and_then(|entry| entry.file_name().into_string().ok())
                .is_some_and(|name| name.starts_with(".git-index-"))
        });
        assert!(!stale_index);
        Ok(())
    }

    #[test]
    fn ref_cas_supports_create_replace_delete_and_rejects_tampering()
    -> Result<(), Box<dyn std::error::Error>> {
        let repo = TestRepo::create("cas")?;
        repo.commit_initial()?;
        let store = open_store(&repo.root)?;
        let checkpoint = id(10);
        let first = store.retain_snapshot(
            checkpoint,
            &path("tracked.txt")?,
            CheckpointSide::Pre,
            TimestampMillis::new(1_000)?,
            None,
        )?;
        let repeated = store.retain_snapshot(
            checkpoint,
            &path("tracked.txt")?,
            CheckpointSide::Pre,
            TimestampMillis::new(1_000)?,
            None,
        )?;
        assert_eq!(first.commit(), repeated.commit());
        assert_eq!(first.state(), repeated.state());
        assert!(matches!(
            repeated.state(),
            CheckpointPathState::Regular { blob, .. }
                if blob.object_id().as_bytes().iter().any(|byte| *byte != 0)
        ));
        assert!(matches!(
            store.retain_snapshot(
                checkpoint,
                &path("tracked.txt")?,
                CheckpointSide::Pre,
                TimestampMillis::new(1_000)?,
                Some(GitCommitId::from_sha1_bytes([0x42; GitObjectId::BYTE_LEN])),
            ),
            Err(GitSafetyError::RefConflict { .. })
        ));
        fs::write(repo.root.join("tracked.txt"), b"changed\n")?;
        let replaced = store.retain_snapshot(
            checkpoint,
            &path("tracked.txt")?,
            CheckpointSide::Pre,
            TimestampMillis::new(2_000)?,
            Some(first.commit()),
        )?;
        assert_ne!(first.commit(), replaced.commit());
        assert_eq!(
            store.read_ref(checkpoint, CheckpointSide::Pre)?,
            Some(replaced.commit())
        );
        store.delete_snapshot(checkpoint, CheckpointSide::Pre, replaced.commit())?;
        assert_eq!(store.read_ref(checkpoint, CheckpointSide::Pre)?, None);

        let second = store.retain_snapshot(
            checkpoint,
            &path("tracked.txt")?,
            CheckpointSide::Pre,
            TimestampMillis::new(3_000)?,
            None,
        )?;
        // A valid but unrelated commit written into the owned ref must make
        // the fenced delete conflict.
        let decoy_checkpoint = id(11);
        let decoy = store.retain_snapshot(
            decoy_checkpoint,
            &path("tracked.txt")?,
            CheckpointSide::Pre,
            TimestampMillis::new(3_500)?,
            None,
        )?;
        let decoy_hex = String::from_utf8(object_hex(decoy.commit().object_id()))?;
        run_git_store(
            Path::new(store.git_store_path()),
            &[
                "update-ref",
                &format!("{GIT_REF_PREFIX}{checkpoint}/pre"),
                decoy_hex.trim(),
            ],
        )?;
        assert!(matches!(
            store.delete_snapshot(checkpoint, CheckpointSide::Pre, second.commit()),
            Err(GitSafetyError::RefConflict { .. })
        ));
        Ok(())
    }

    #[test]
    fn absent_snapshot_retains_an_empty_tree_commit() -> Result<(), Box<dyn std::error::Error>> {
        let repo = TestRepo::create("absent")?;
        repo.commit_initial()?;
        let store = open_store(&repo.root)?;
        let checkpoint = id(20);
        let retained = store.retain_snapshot(
            checkpoint,
            &path("missing.txt")?,
            CheckpointSide::Pre,
            TimestampMillis::new(1_000)?,
            None,
        )?;
        assert_eq!(retained.state(), &CheckpointPathState::Absent);
        let commit = String::from_utf8(object_hex(retained.commit().object_id()))?;
        let store_path = PathBuf::from(store.git_store_path());
        assert!(output_store(&store_path, &["ls-tree", "-r", "--name-only", &commit])?.is_empty());
        Ok(())
    }

    #[test]
    fn retry_preserves_full_state_and_original_timestamp_after_mode_change()
    -> Result<(), Box<dyn std::error::Error>> {
        let repo = TestRepo::create("metadata")?;
        repo.commit_initial()?;
        let tracked = repo.root.join("tracked.txt");
        let mut permissions = fs::metadata(&tracked)?.permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(&tracked, permissions)?;
        let store = open_store(&repo.root)?;
        let checkpoint = id(40);
        let first = store.retain_snapshot(
            checkpoint,
            &path("tracked.txt")?,
            CheckpointSide::Pre,
            TimestampMillis::new(1_000)?,
            None,
        )?;
        let mut changed_permissions = fs::metadata(&tracked)?.permissions();
        changed_permissions.set_mode(0o640);
        fs::set_permissions(&tracked, changed_permissions)?;
        let repeated = store.retain_snapshot(
            checkpoint,
            &path("tracked.txt")?,
            CheckpointSide::Pre,
            TimestampMillis::new(9_000)?,
            None,
        )?;
        assert_eq!(first.commit(), repeated.commit());
        assert_eq!(first.state(), repeated.state());
        assert_eq!(first.observed_at(), TimestampMillis::new(1_000)?);
        assert_eq!(repeated.observed_at(), first.observed_at());
        assert!(matches!(
            repeated.state(),
            CheckpointPathState::Regular { blob, mode, .. }
                if mode.get() == 0o600
                    && blob.object_id().as_bytes().iter().any(|byte| *byte != 0)
        ));
        let transition_id = id(41);
        let starting = store.begin_checkpoint(
            attribution(transition_id),
            path("tracked.txt")?,
            TimestampMillis::new(1_000)?,
        )?;
        let first_ready = store.complete_checkpoint(&starting, TimestampMillis::new(2_000)?)?;
        let repeated_ready = store.complete_checkpoint(&starting, TimestampMillis::new(9_000)?)?;
        assert_eq!(
            repeated_ready.timestamps().updated_at(),
            first_ready.timestamps().updated_at()
        );
        assert_eq!(
            repeated_ready.timestamps().updated_at(),
            TimestampMillis::new(2_000)?
        );

        let store_path = PathBuf::from(store.git_store_path());
        let commit_hex = String::from_utf8(output_store(
            &store_path,
            &["rev-parse", &format!("{GIT_REF_PREFIX}{checkpoint}/pre")],
        )?)?;
        let tree_hex = String::from_utf8(output_store(
            &store_path,
            &["show", "-s", "--format=%T", commit_hex.trim()],
        )?)?;
        let tampered_hex = String::from_utf8(run_git_store(
            &store_path,
            &[
                "commit-tree",
                tree_hex.trim(),
                "-m",
                &format!("Heterarchy Forge checkpoint {checkpoint} pre"),
            ],
        )?)?;
        let reference = GitCheckpointStore::checkpoint_ref_name(checkpoint, CheckpointSide::Pre)?;
        run_git_store(
            &store_path,
            &[
                "update-ref",
                &reference,
                tampered_hex.trim(),
                commit_hex.trim(),
            ],
        )?;
        assert!(matches!(
            store.retain_snapshot(
                checkpoint,
                &path("tracked.txt")?,
                CheckpointSide::Pre,
                TimestampMillis::new(10_000)?,
                None,
            ),
            Err(GitSafetyError::TamperedRef { .. })
        ));
        Ok(())
    }

    #[test]
    fn bounded_blob_read_supports_checkpoint_file_limit() -> Result<(), Box<dyn std::error::Error>>
    {
        let repo = TestRepo::create("large")?;
        repo.commit_initial()?;
        let content = vec![b'x'; 100_000];
        fs::write(repo.root.join("large.bin"), &content)?;
        let store = open_store(&repo.root)?;
        let retained = store.retain_snapshot(
            id(21),
            &path("large.bin")?,
            CheckpointSide::Pre,
            TimestampMillis::new(1_000)?,
            None,
        )?;
        let blob = match retained.state() {
            CheckpointPathState::Regular { blob, .. } => *blob,
            CheckpointPathState::Absent => return Err("large file unexpectedly absent".into()),
        };
        assert_eq!(store.read_blob(blob)?, content);
        Ok(())
    }

    #[test]
    fn bounded_git_capture_kills_and_reaps_a_hanging_child()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut child = Command::new("/bin/sleep")
            .arg("30")
            .process_group(0)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let stdout = child.stdout.take().ok_or("missing stdout")?;
        let stderr = child.stderr.take().ok_or("missing stderr")?;
        let started = std::time::Instant::now();
        let (_, _, timed_out, cleanup_failed) = capture_git_streams_until(
            &mut child,
            stdout,
            stderr,
            MAX_GIT_OUTPUT_BYTES,
            std::time::Instant::now() + Duration::from_millis(50),
        );
        let _status = child.wait()?;
        assert!(timed_out);
        assert!(!cleanup_failed);
        assert!(started.elapsed() < Duration::from_secs(2));
        Ok(())
    }

    #[test]
    fn process_group_cleanup_kills_pipe_holding_shell_descendant()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg("/bin/sleep 30 &")
            .process_group(0)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let pid = child.id();
        let stdout = child.stdout.take().ok_or("missing stdout")?;
        let stderr = child.stderr.take().ok_or("missing stderr")?;
        let started = std::time::Instant::now();
        let (_, _, timed_out, cleanup_failed) = capture_git_streams_until(
            &mut child,
            stdout,
            stderr,
            MAX_GIT_OUTPUT_BYTES,
            std::time::Instant::now() + Duration::from_millis(50),
        );
        let _status = child.wait()?;
        assert!(timed_out);
        assert!(!cleanup_failed);
        assert!(!run_group_signal(pid, "-0"));
        assert!(started.elapsed() < Duration::from_secs(2));
        Ok(())
    }

    #[test]
    fn sha256_user_repository_uses_owned_sha1_store() -> Result<(), Box<dyn std::error::Error>> {
        let root = env::temp_dir().join(format!("heterarchy-forge-sha256-{}", std::process::id()));
        let _ignored = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
        let init = Command::new(GIT_PROGRAM)
            .arg("-C")
            .arg(&root)
            .args(["init", "-q", "--object-format=sha256"])
            .env_clear()
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .env("PATH", "/usr/bin:/bin")
            .output()?;
        if !init.status.success() {
            // Git without sha256 support: nothing platform-specific to prove.
            let _ignored = fs::remove_dir_all(root);
            return Ok(());
        }
        let content = b"sha256 user repository\n";
        fs::write(root.join("tracked.txt"), content)?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let store = GitCheckpointStore::from_state_layout(&layout)?;
        let retained = store.retain_snapshot(
            id(50),
            &path("tracked.txt")?,
            CheckpointSide::Pre,
            TimestampMillis::new(1_000)?,
            None,
        )?;
        let blob = match retained.state() {
            CheckpointPathState::Regular { blob, .. } => *blob,
            CheckpointPathState::Absent => {
                return Err("sha256 fixture file unexpectedly absent".into());
            }
        };
        assert_eq!(store.read_blob(blob)?, content);
        let _ignored = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn gitfile_layout_is_rejected_before_state_or_git_effects()
    -> Result<(), Box<dyn std::error::Error>> {
        let repo = TestRepo::create("gitfile")?;
        repo.commit_initial()?;
        fs::remove_dir_all(repo.root.join(".git"))?;
        fs::write(repo.root.join(".git"), b"gitdir: /outside\n")?;
        let result =
            GitCheckpointStore::new(&repo.root, repo.root.join(".heterarchy-forge/checkpoints"));
        assert!(matches!(result, Err(GitSafetyError::UnsupportedGitLayout)));
        assert!(!repo.root.join(".heterarchy-forge").exists());
        Ok(())
    }

    #[test]
    fn native_nested_path_mapping_does_not_require_utf8() -> Result<(), Box<dyn std::error::Error>>
    {
        let repo = TestRepo::create("native")?;
        repo.commit_initial()?;
        let nested = repo.root.join("workspace");
        fs::create_dir_all(&nested)?;
        let store = open_store(&nested)?;
        let native = OsString::from_vec(vec![b'n', b'o', 0xff]);
        let relative = WorkspaceRelativePath::new(PathBuf::from(native))?;
        let mapped = store.repository_relative_path(&relative)?;
        assert_eq!(mapped.as_os_str().as_bytes(), b"workspace/no\xff");
        let protected = WorkspaceRelativePath::new(PathBuf::from(".heterarchy-forge/probe"))?;
        assert!(matches!(
            store.repository_relative_path(&protected),
            Err(GitSafetyError::ProtectedPath)
        ));
        Ok(())
    }

    #[test]
    fn mktree_preserves_non_utf8_native_component_bytes() -> Result<(), Box<dyn std::error::Error>>
    {
        let repo = TestRepo::create("mktree-native")?;
        repo.commit_initial()?;
        let store = open_store(&repo.root)?;
        let retained = store.retain_snapshot(
            id(50),
            &path("tracked.txt")?,
            CheckpointSide::Pre,
            TimestampMillis::new(1_000)?,
            None,
        )?;
        let blob = match retained.state() {
            CheckpointPathState::Regular { blob, .. } => *blob,
            CheckpointPathState::Absent => return Err("native file unexpectedly absent".into()),
        };
        assert!(blob.object_id().as_bytes().iter().any(|byte| *byte != 0));
        assert_eq!(store.read_blob(blob)?, b"base\n");
        let native_entry = mktree_entry(b"100644", b"blob", blob.object_id(), b"no\xff")?;
        let tree = store.write_mktree(&native_entry)?;
        assert!(tree.as_bytes().iter().any(|byte| *byte != 0));
        Ok(())
    }

    #[test]
    fn descriptor_capture_rejects_ancestor_symlink() -> Result<(), Box<dyn std::error::Error>> {
        let repo = TestRepo::create("ancestor-symlink")?;
        repo.commit_initial()?;
        let workspace = repo.root.join("workspace");
        let outside = repo.root.join("outside");
        fs::create_dir_all(&workspace)?;
        fs::create_dir_all(&outside)?;
        fs::write(outside.join("file.txt"), b"outside\n")?;
        symlink(&outside, workspace.join("link"))?;
        let store = open_store(&workspace)?;
        let result = store.retain_snapshot(
            id(30),
            &path("link/file.txt")?,
            CheckpointSide::Pre,
            TimestampMillis::new(1_000)?,
            None,
        );
        assert!(matches!(result, Err(GitSafetyError::Confined(_))));
        Ok(())
    }

    #[test]
    fn descriptor_capture_rejects_workspace_and_state_replacement()
    -> Result<(), Box<dyn std::error::Error>> {
        let repo = TestRepo::create("replacement")?;
        repo.commit_initial()?;
        let store = open_store(&repo.root)?;
        let moved_workspace = repo.root.with_extension("moved");
        fs::rename(&repo.root, &moved_workspace)?;
        fs::create_dir_all(&repo.root)?;
        let workspace_result = store.retain_snapshot(
            id(31),
            &path("tracked.txt")?,
            CheckpointSide::Pre,
            TimestampMillis::new(1_000)?,
            None,
        );
        fs::remove_dir_all(&repo.root)?;
        fs::rename(&moved_workspace, &repo.root)?;
        assert!(matches!(workspace_result, Err(GitSafetyError::Confined(_))));

        let state = repo.root.join(".heterarchy-forge");
        let moved_state = repo.root.join(".heterarchy-forge.moved");
        fs::rename(&state, &moved_state)?;
        fs::create_dir(&state)?;
        let state_result = store.retain_snapshot(
            id(32),
            &path("tracked.txt")?,
            CheckpointSide::Pre,
            TimestampMillis::new(1_000)?,
            None,
        );
        fs::remove_dir(&state)?;
        fs::rename(moved_state, state)?;
        assert!(matches!(state_result, Err(GitSafetyError::Confined(_))));
        Ok(())
    }

    #[test]
    fn read_only_checkpoint_store_inspection_never_initializes_missing_state()
    -> Result<(), Box<dyn std::error::Error>> {
        let repo = TestRepo::create("doctor-missing-store")?;
        repo.commit_initial()?;
        let layout = WorkspaceStateLayout::initialize(&repo.root)?;
        let existing =
            WorkspaceStateLayout::inspect_existing(&repo.root)?.ok_or("existing layout missing")?;
        let store_path = layout.checkpoints().join("store.git");
        assert!(!store_path.exists());
        assert!(GitCheckpointStore::inspect_existing_read_only(&existing)?.is_none());
        assert!(!store_path.exists());
        Ok(())
    }

    #[test]
    fn checkpoint_ref_inventory_and_object_batch_are_bounded_and_typed()
    -> Result<(), Box<dyn std::error::Error>> {
        let repo = TestRepo::create("doctor-inventory")?;
        repo.commit_initial()?;
        let store = open_store(&repo.root)?;
        let checkpoint_id = id(0xA100);
        let starting = store.begin_checkpoint(
            attribution(checkpoint_id),
            path("tracked.txt")?,
            TimestampMillis::new(1_000)?,
        )?;
        fs::write(repo.root.join("tracked.txt"), b"after\n")?;
        let ready = store.complete_checkpoint(&starting, TimestampMillis::new(2_000)?)?;
        let existing =
            WorkspaceStateLayout::inspect_existing(&repo.root)?.ok_or("existing layout missing")?;
        let inspected = GitCheckpointStore::inspect_existing_read_only(&existing)?
            .ok_or("owned store missing")?;
        let inventory =
            inspected.inventory_refs_read_only(GitCheckpointRefInventoryLimit::DEFAULT)?;
        assert_eq!(inventory.integrity(), GitCheckpointStoreIntegrity::Passed);
        assert!(!inventory.truncated());
        assert_eq!(inventory.entries().len(), 2);
        assert!(inventory.entries().iter().any(|entry| {
            matches!(
                entry,
                GitCheckpointRefInventoryEntry::Retained {
                    checkpoint_id: actual,
                    side: CheckpointSide::Pre,
                    commit,
                } if *actual == checkpoint_id && *commit == ready.pre_commit()
            )
        }));
        assert!(inventory.entries().iter().any(|entry| {
            matches!(
                entry,
                GitCheckpointRefInventoryEntry::Retained {
                    checkpoint_id: actual,
                    side: CheckpointSide::Post,
                    commit,
                } if *actual == checkpoint_id && Some(*commit) == ready.post_commit()
            )
        }));

        let pre_blob = match ready.pre() {
            CheckpointPathState::Regular { blob, .. } => *blob,
            CheckpointPathState::Absent => return Err("PRE blob missing".into()),
        };
        let post_blob = match ready.post().ok_or("POST missing")? {
            CheckpointPathState::Regular { blob, .. } => *blob,
            CheckpointPathState::Absent => return Err("POST blob missing".into()),
        };
        let wrong_type = GitBlobId::from_sha1_bytes(*ready.pre_commit().object_id().as_bytes());
        let missing = GitCommitId::from_sha1_bytes([0xFE; GitObjectId::BYTE_LEN]);
        let expectations = [
            GitCheckpointObjectExpectation::Commit(ready.pre_commit()),
            GitCheckpointObjectExpectation::Commit(
                ready.post_commit().ok_or("POST commit missing")?,
            ),
            GitCheckpointObjectExpectation::Blob(pre_blob),
            GitCheckpointObjectExpectation::Blob(post_blob),
            GitCheckpointObjectExpectation::Blob(wrong_type),
            GitCheckpointObjectExpectation::Commit(missing),
        ];
        let verified = inspected.verify_objects_read_only(&expectations)?;
        assert_eq!(verified.len(), expectations.len());
        assert!(
            verified[..4]
                .iter()
                .all(|item| { item.status() == GitCheckpointObjectVerificationStatus::Present })
        );
        assert_eq!(
            verified[4].status(),
            GitCheckpointObjectVerificationStatus::TypeMismatch
        );
        assert_eq!(
            verified[5].status(),
            GitCheckpointObjectVerificationStatus::Missing
        );
        Ok(())
    }

    #[test]
    fn checkpoint_ref_inventory_classifies_malformed_and_non_commit_refs()
    -> Result<(), Box<dyn std::error::Error>> {
        let repo = TestRepo::create("doctor-invalid-refs")?;
        repo.commit_initial()?;
        let store = open_store(&repo.root)?;
        let retained = store.retain_snapshot(
            id(0xA200),
            &path("tracked.txt")?,
            CheckpointSide::Pre,
            TimestampMillis::new(1_000)?,
            None,
        )?;
        let blob = match retained.state() {
            CheckpointPathState::Regular { blob, .. } => *blob,
            CheckpointPathState::Absent => return Err("captured blob missing".into()),
        };
        let store_path = Path::new(store.git_store_path());
        let malformed = format!("{GIT_REF_PREFIX}not-a-checkpoint/pre");
        let commit_hex = String::from_utf8(object_hex(retained.commit().object_id()))?;
        run_git_store(store_path, &["update-ref", &malformed, &commit_hex])?;
        let non_commit_id = id(0xA201);
        let non_commit =
            GitCheckpointStore::checkpoint_ref_name(non_commit_id, CheckpointSide::Pre)?;
        let blob_hex = String::from_utf8(object_hex(blob.object_id()))?;
        run_git_store(store_path, &["update-ref", &non_commit, &blob_hex])?;

        let inventory = store.inventory_refs_read_only(GitCheckpointRefInventoryLimit::DEFAULT)?;
        assert!(
            inventory
                .entries()
                .contains(&GitCheckpointRefInventoryEntry::Malformed)
        );
        assert!(
            inventory
                .entries()
                .contains(&GitCheckpointRefInventoryEntry::NonCommit {
                    checkpoint_id: non_commit_id,
                    side: CheckpointSide::Pre,
                })
        );
        Ok(())
    }
}

#[cfg(all(test, target_os = "macos"))]
mod macos_capability_tests {
    use std::env;
    use std::fs;
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn apple_git_writer_uses_owned_bare_store_and_leaves_user_repo_untouched()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = env::temp_dir().join(format!(
            "heterarchy-forge-git-capability-{}",
            std::process::id()
        ));
        let _ignored = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
        let init = std::process::Command::new(GIT_PROGRAM)
            .arg("-C")
            .arg(&root)
            .args(["init", "-q"])
            .env_clear()
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .env("PATH", "/usr/bin:/bin")
            .output()?;
        if !init.status.success() {
            return Err("failed to initialize probe repository".into());
        }
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let store = GitCheckpointStore::from_state_layout(&layout)?;

        let store_path = PathBuf::from(store.git_store_path());
        assert!(store_path.join("HEAD").is_file());
        assert!(store_path.join("objects").is_dir());
        assert!(store_path.join("refs").is_dir());

        let content = b"macos owned store\n";
        fs::write(root.join("tracked.txt"), content)?;
        let relative = forge_domain::WorkspaceRelativePath::new(PathBuf::from("tracked.txt"))?;
        let retained = store.retain_snapshot(
            CheckpointId::from_uuid(uuid::Uuid::now_v7()),
            &relative,
            CheckpointSide::Pre,
            TimestampMillis::new(1_000)?,
            None,
        )?;
        match retained.state() {
            CheckpointPathState::Regular { blob, .. } => {
                assert_eq!(store.read_blob(*blob)?, content.as_slice());
            }
            CheckpointPathState::Absent => return Err("captured file unexpectedly absent".into()),
        }

        // The user repository namespace stays untouched.
        assert!(!root.join(".git/refs/heterarchy-forge").exists());
        let _ignored = fs::remove_dir_all(root);
        Ok(())
    }
}
