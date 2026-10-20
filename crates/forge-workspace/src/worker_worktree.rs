//! Isolated Git linked-worktree provisioning for connected code workers.
//!
//! A worker worktree is a Git result surface, not a new Forge Workspace,
//! Activity, Goal, DAG, or Agent attachment. Provisioning is exact-path and
//! detached; integration and deletion remain explicit later operations.

use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

use forge_domain::{AgentInstanceId, FileContentHash, GitCommitId, WorkspaceRootFingerprint};
use rustix::fs::{Mode, OFlags, fsync, mkdirat, open, openat};
use rustix::io::Errno;
use thiserror::Error;

use super::{
    GitOutput, GitProcessSpec, GitSafetyError, GitSandboxProfile, arg, arg_bytes, command_failed,
    ensure_no_symlink_components, object_hex, parse_git_object_id, run_bounded_git_process,
};
use crate::state_layout::{StateLayoutError, WorkspaceStateLayout};
use crate::{ConfinedWorkspace, WorkspaceStateSharedGate};

const WORKER_STATE_DIRECTORY: &str = ".heterarchy-forge";
const WORKER_TEAM_SUFFIX: &str = "_teams";
const MAX_WORKER_TEAM_BYTES: usize = 64;
const MAX_WORKER_INDEX_BYTES: usize = 8 * 1024 * 1024;
const MAX_WORKER_STATUS_ENTRIES: usize = 256;
const MAX_WORKER_STATUS_PATH_BYTES: usize = 16 * 1024;
const MAX_WORKER_OWNER_IDENTITY_BYTES: usize = 256;
const MAX_WORKER_OWNER_MARKER_BYTES: usize = 8 * 1024;
const WORKER_OWNER_MARKER_SUFFIX: &str = ".forge-owner";
const WORKER_SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";
const WORKER_SANDBOX_GIT: &str = super::FORGE_GIT_PROGRAM;
const WORKER_OWNER_MARKER_HEADER: &[u8] = b"forge-worker-owner-v1\n";

/// Safe server-owned team label used as one path component.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WorkerTeamName(String);

impl WorkerTeamName {
    pub fn new(value: impl Into<String>) -> Result<Self, WorkerWorktreeError> {
        let value = value.into();
        let bytes = value.as_bytes();
        let valid = !bytes.is_empty()
            && bytes.len() <= MAX_WORKER_TEAM_BYTES
            && bytes[0].is_ascii_alphanumeric()
            && bytes
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'-'));
        if valid {
            Ok(Self(value))
        } else {
            Err(WorkerWorktreeError::InvalidTeamName { value })
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Exact opaque assignment/claim identity supplied by the Control boundary.
///
/// The workspace adapter stores these bytes in its owner marker but never
/// interprets them as paths, UUIDs, or policy.  Empty, oversized, and record
/// delimiter-containing values are rejected so the marker remains one bounded
/// immutable record.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerWorktreeOwner {
    assignment: Vec<u8>,
    claim: Vec<u8>,
}

impl WorkerWorktreeOwner {
    pub fn new(
        assignment: impl AsRef<[u8]>,
        claim: impl AsRef<[u8]>,
    ) -> Result<Self, WorkerWorktreeError> {
        let assignment = validate_owner_identity("assignment", assignment.as_ref())?;
        let claim = validate_owner_identity("claim", claim.as_ref())?;
        Ok(Self { assignment, claim })
    }

    pub fn assignment(&self) -> &[u8] {
        &self.assignment
    }

    pub fn claim(&self) -> &[u8] {
        &self.claim
    }
}

/// One bounded native Git status entry from a source or worker root.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerDirtyEntry {
    code: [u8; 2],
    path: Vec<u8>,
}

impl WorkerDirtyEntry {
    pub const fn code(&self) -> [u8; 2] {
        self.code
    }

    pub fn path(&self) -> &[u8] {
        &self.path
    }
}

/// Read-only source observation captured before worker provisioning.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerSourceInspection {
    repository_root: PathBuf,
    root_fingerprint: WorkspaceRootFingerprint,
    git_fingerprint: WorkspaceRootFingerprint,
    baseline: GitCommitId,
    index_fingerprint: Option<FileContentHash>,
    dirty_entries: Vec<WorkerDirtyEntry>,
}

impl WorkerSourceInspection {
    pub fn repository_root(&self) -> &Path {
        &self.repository_root
    }

    pub const fn root_fingerprint(&self) -> WorkspaceRootFingerprint {
        self.root_fingerprint
    }

    pub const fn git_fingerprint(&self) -> WorkspaceRootFingerprint {
        self.git_fingerprint
    }

    pub const fn baseline(&self) -> GitCommitId {
        self.baseline
    }

    pub const fn index_fingerprint(&self) -> Option<FileContentHash> {
        self.index_fingerprint
    }

    pub fn dirty_entries(&self) -> &[WorkerDirtyEntry] {
        &self.dirty_entries
    }

    pub const fn is_clean(&self) -> bool {
        self.dirty_entries.is_empty()
    }
}

/// Read-only observation of one exact detached worker worktree.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerWorktreeInspection {
    path: PathBuf,
    root_fingerprint: WorkspaceRootFingerprint,
    baseline: GitCommitId,
    dirty_entries: Vec<WorkerDirtyEntry>,
}

impl WorkerWorktreeInspection {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub const fn root_fingerprint(&self) -> WorkspaceRootFingerprint {
        self.root_fingerprint
    }

    pub const fn baseline(&self) -> GitCommitId {
        self.baseline
    }

    pub fn dirty_entries(&self) -> &[WorkerDirtyEntry] {
        &self.dirty_entries
    }

    pub const fn is_clean(&self) -> bool {
        self.dirty_entries.is_empty()
    }
}

/// Outcome of an exact-path provision request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerWorktreeProvisionOutcome {
    Created,
    ExistingReadBack,
}

/// Durable-result receipt for a successful exact-path provision/read-back.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerWorktreeProvisionReceipt {
    path: PathBuf,
    worker_id: AgentInstanceId,
    baseline: GitCommitId,
    source_root_fingerprint: WorkspaceRootFingerprint,
    source_git_fingerprint: WorkspaceRootFingerprint,
    owner: WorkerWorktreeOwner,
    outcome: WorkerWorktreeProvisionOutcome,
    inspection: WorkerWorktreeInspection,
}

impl WorkerWorktreeProvisionReceipt {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub const fn worker_id(&self) -> AgentInstanceId {
        self.worker_id
    }

    pub const fn baseline(&self) -> GitCommitId {
        self.baseline
    }

    pub const fn source_root_fingerprint(&self) -> WorkspaceRootFingerprint {
        self.source_root_fingerprint
    }

    pub const fn source_git_fingerprint(&self) -> WorkspaceRootFingerprint {
        self.source_git_fingerprint
    }

    pub fn owner(&self) -> &WorkerWorktreeOwner {
        &self.owner
    }

    pub const fn outcome(&self) -> WorkerWorktreeProvisionOutcome {
        self.outcome
    }

    pub const fn inspection(&self) -> &WorkerWorktreeInspection {
        &self.inspection
    }
}

/// Typed failure from the worker worktree effect boundary.
#[derive(Debug, Error)]
pub enum WorkerWorktreeError {
    #[error("worker team name is not a safe path component: {value:?}")]
    InvalidTeamName { value: String },
    #[error("worker owner {kind} identity is invalid or exceeds the bounded marker limit")]
    InvalidOwnerIdentity { kind: &'static str },
    #[error("worker source root is invalid: {path}")]
    InvalidSourceRoot { path: PathBuf },
    #[error("worker source is not a Git worktree")]
    NotGitRepository,
    #[error(
        "worker source uses an unsupported Gitfile, linked-worktree, submodule, or symlink layout"
    )]
    UnsupportedGitLayout,
    #[error("worker source root observation failed")]
    RootObservation(#[source] StateLayoutError),
    #[error("worker source root changed during Git operation")]
    SourceRootChanged {
        expected: WorkspaceRootFingerprint,
        observed: WorkspaceRootFingerprint,
    },
    #[error("worker source Git directory identity changed")]
    SourceGitChanged {
        expected: WorkspaceRootFingerprint,
        observed: WorkspaceRootFingerprint,
    },
    #[error("worker source expectation is stale before dispatch")]
    SourceExpectationConflict {
        expected_root: WorkspaceRootFingerprint,
        observed_root: WorkspaceRootFingerprint,
        expected_baseline: GitCommitId,
        observed_baseline: GitCommitId,
        expected_git: WorkspaceRootFingerprint,
        observed_git: WorkspaceRootFingerprint,
    },
    #[error("existing Forge Workspace state is required for worker worktree effects")]
    WorkspaceStateUnavailable,
    #[error("Forge Workspace state gate rejected worker worktree effect")]
    WorkspaceStateGate(#[source] crate::WorkspaceStateGateError),
    #[error("Forge Workspace descriptor rejected worker worktree effect")]
    Confined(#[source] crate::ConfinedFilesystemError),
    #[error("worker source is dirty and cannot be provisioned")]
    SourceDirty {
        root: PathBuf,
        entries: Vec<WorkerDirtyEntry>,
    },
    #[error("worker source index is invalid: {path}")]
    InvalidIndex { path: PathBuf },
    #[error("worker source index exceeds the {maximum}-byte bound: {path}")]
    IndexTooLarge { path: PathBuf, maximum: usize },
    #[error("worker filesystem operation {operation} failed at {path}")]
    Filesystem {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("worker path contains a symbolic link: {path}")]
    SymlinkPath { path: PathBuf },
    #[error("worker worktree path escapes the source repository: {path}")]
    WorktreePathEscape { path: PathBuf },
    #[error("worker worktree path does not exist: {path}")]
    WorktreeNotFound { path: PathBuf },
    #[error("worker worktree path already exists with a different baseline: {path}")]
    ExistingPathConflict {
        path: PathBuf,
        expected: GitCommitId,
        observed: Option<GitCommitId>,
    },
    #[error("worker worktree read-back is not an exact detached linked worktree: {path}")]
    InvalidWorktreeReadBack { path: PathBuf },
    #[error("worker worktree root identity changed: {path}")]
    WorktreeRootChanged {
        path: PathBuf,
        expected: WorkspaceRootFingerprint,
        observed: WorkspaceRootFingerprint,
    },
    #[error("worker Git output for {operation} was malformed")]
    InvalidGitOutput { operation: &'static str },
    #[error("worker Git operation failed before dispatch")]
    Git(#[source] GitSafetyError),
    #[error("worker Git operation was cancelled before dispatch")]
    Cancelled,
    #[error("worker owner marker is missing or does not match the requested owner")]
    OwnerMarkerMismatch { path: PathBuf },
    #[error("worker owner marker already exists and its dispatch outcome is unknown: {path}")]
    PartialDispatch { path: PathBuf },
    #[error("worker Git sandbox is unavailable")]
    SandboxUnavailable,
    #[error("worker Git configuration requires unsupported external execution")]
    UnsupportedGitConfiguration { path: PathBuf },
    #[error("worker Git operation outcome is unknown after dispatch at {path}")]
    UnknownAfterDispatch {
        operation: &'static str,
        path: PathBuf,
        baseline: GitCommitId,
        reason: String,
    },
}

/// Source-root-bound adapter for exact detached worker worktrees.
#[must_use]
#[derive(Debug, Clone)]
pub struct WorkerWorktreeAdapter {
    repository_root: PathBuf,
    team: WorkerTeamName,
}

struct WorkerGitDispatch<'a> {
    path: &'a Path,
    baseline: GitCommitId,
    gate: &'a WorkspaceStateSharedGate,
    confined: &'a ConfinedWorkspace,
    cancellation: Option<&'a AtomicBool>,
    arguments: &'a [OsString],
    git_common_dir: &'a Path,
    profile: &'a GitSandboxProfile,
}

impl WorkerWorktreeAdapter {
    /// Bind the adapter to one canonical source repository and safe team label.
    pub fn new(
        repository_root: impl AsRef<Path>,
        team: WorkerTeamName,
    ) -> Result<Self, WorkerWorktreeError> {
        let repository_root = canonical_source_root(repository_root.as_ref())?;
        Ok(Self {
            repository_root,
            team,
        })
    }

    pub fn repository_root(&self) -> &Path {
        &self.repository_root
    }

    pub fn team(&self) -> &WorkerTeamName {
        &self.team
    }

    /// Observe source Git identity, full baseline OID, index, and bounded
    /// native status without creating Forge or worktree state.
    pub fn inspect_source(&self) -> Result<WorkerSourceInspection, WorkerWorktreeError> {
        self.inspect_source_with_cancellation(None)
    }

    fn inspect_source_with_cancellation(
        &self,
        cancellation: Option<&AtomicBool>,
    ) -> Result<WorkerSourceInspection, WorkerWorktreeError> {
        self.validate_source_git_layout()?;
        let root_fingerprint = observe_root(&self.repository_root)?;
        let git_fingerprint = observe_git_fingerprint(&self.repository_root.join(".git"))?;
        let inside = self.git_output(
            "detect source Git worktree",
            &[arg("rev-parse"), arg("--is-inside-work-tree")],
            cancellation,
        )?;
        if trim_ascii(&inside.stdout) != b"true" {
            return Err(WorkerWorktreeError::NotGitRepository);
        }
        let top_level = self.git_path(
            "resolve source Git root",
            &[arg("rev-parse"), arg("--show-toplevel")],
            cancellation,
        )?;
        if top_level != self.repository_root {
            return Err(WorkerWorktreeError::UnsupportedGitLayout);
        }
        let superproject = self.git_output(
            "inspect source Git superproject",
            &[arg("rev-parse"), arg("--show-superproject-working-tree")],
            cancellation,
        )?;
        if !trim_ascii(&superproject.stdout).is_empty() {
            return Err(WorkerWorktreeError::UnsupportedGitLayout);
        }
        let baseline = self.git_commit(
            "read source baseline",
            &[arg("rev-parse"), arg("--verify"), arg("HEAD^{commit}")],
            cancellation,
        )?;
        let dirty_entries = Self::status_entries(
            &self.repository_root,
            &self.source_git_common_dir()?,
            cancellation,
        )?;
        let index_fingerprint = read_index_fingerprint(&self.repository_root)?;
        let observed = observe_root(&self.repository_root)?;
        if observed != root_fingerprint {
            return Err(WorkerWorktreeError::SourceRootChanged {
                expected: root_fingerprint,
                observed,
            });
        }
        let observed_git = observe_git_fingerprint(&self.repository_root.join(".git"))?;
        if observed_git != git_fingerprint {
            return Err(WorkerWorktreeError::SourceGitChanged {
                expected: git_fingerprint,
                observed: observed_git,
            });
        }
        Ok(WorkerSourceInspection {
            repository_root: self.repository_root.clone(),
            root_fingerprint,
            git_fingerprint,
            baseline,
            index_fingerprint,
            dirty_entries,
        })
    }

    /// Provision one exact detached linked worktree, or read back that exact
    /// path when a prior dispatch already created it. No retry allocates a new
    /// worker identity and no integration/deletion is implicit.
    // Keep the preflight, exclusive marker claim, dispatch, and durable
    // read-back in one state transition so no caller can accidentally split
    // the unknown-after-dispatch fence across helpers.
    #[allow(clippy::too_many_lines)]
    pub fn provision(
        &self,
        worker_id: AgentInstanceId,
        expected_source: &WorkerSourceInspection,
        owner: &WorkerWorktreeOwner,
        cancellation: Option<&AtomicBool>,
    ) -> Result<WorkerWorktreeProvisionReceipt, WorkerWorktreeError> {
        let (confined, gate, _writer_guard) = self.acquire_provision_fences()?;
        if !expected_source.is_clean() {
            return Err(WorkerWorktreeError::SourceDirty {
                root: expected_source.repository_root.clone(),
                entries: expected_source.dirty_entries.clone(),
            });
        }
        let source = self.inspect_source_with_cancellation(cancellation)?;
        ensure_source_matches(expected_source, &source)?;
        let path = self.worker_path(worker_id)?;
        let owner_marker = self.owner_marker_path(&path)?;
        ensure_no_symlink_components(&path).map_err(map_path_error)?;
        ensure_no_symlink_components(owner_marker.parent().ok_or_else(|| {
            WorkerWorktreeError::WorktreePathEscape {
                path: owner_marker.clone(),
            }
        })?)
        .map_err(map_path_error)?;
        if path.exists() {
            return self.read_existing_or_conflict(path, worker_id, &source, owner, cancellation);
        }
        if cancellation.is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Acquire)) {
            return Err(WorkerWorktreeError::Cancelled);
        }
        if owner_marker.exists() {
            let marker = Self::read_owner_marker(&owner_marker)?;
            if marker.matches(worker_id, &source, owner) {
                return Err(WorkerWorktreeError::PartialDispatch { path });
            }
            return Err(WorkerWorktreeError::OwnerMarkerMismatch { path: owner_marker });
        }
        Self::ensure_worker_parent(&path)?;
        let current = self.inspect_source_with_cancellation(cancellation)?;
        ensure_source_matches(expected_source, &current)?;
        let marker = WorkerOwnerMarker::new(worker_id, &current, owner);
        Self::create_owner_marker(&owner_marker, &marker)?;
        if cancellation.is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Acquire)) {
            return Err(WorkerWorktreeError::Cancelled);
        }
        self.dispatch_worktree_add(
            &path,
            &owner_marker,
            expected_source.baseline,
            &confined,
            &gate,
            cancellation,
        )?;
        gate.ensure_root_binding()
            .map_err(WorkerWorktreeError::WorkspaceStateGate)?;
        confined
            .ensure_for_git(true)
            .map_err(WorkerWorktreeError::Confined)?;
        let source_after = self
            .inspect_source_with_cancellation(cancellation)
            .map_err(|error| unknown_after_dispatch(&path, expected_source.baseline, &error))?;
        ensure_source_matches(expected_source, &source_after)
            .map_err(|error| unknown_after_dispatch(&path, expected_source.baseline, &error))?;
        let inspection = self
            .inspect_exact_worktree(
                &path,
                expected_source.baseline,
                None,
                Some(owner),
                cancellation,
            )
            .map_err(|error| unknown_after_dispatch(&path, expected_source.baseline, &error))?;
        Ok(WorkerWorktreeProvisionReceipt {
            path,
            worker_id,
            baseline: expected_source.baseline,
            source_root_fingerprint: expected_source.root_fingerprint,
            source_git_fingerprint: expected_source.git_fingerprint,
            owner: owner.clone(),
            outcome: WorkerWorktreeProvisionOutcome::Created,
            inspection,
        })
    }

    fn dispatch_worktree_add(
        &self,
        path: &Path,
        owner_marker: &Path,
        baseline: GitCommitId,
        confined: &ConfinedWorkspace,
        gate: &WorkspaceStateSharedGate,
        cancellation: Option<&AtomicBool>,
    ) -> Result<(), WorkerWorktreeError> {
        gate.ensure_root_binding()
            .map_err(WorkerWorktreeError::WorkspaceStateGate)?;
        confined
            .ensure_for_git(false)
            .map_err(WorkerWorktreeError::Confined)?;
        let (arguments, git_common_dir, profile) =
            self.prepare_worktree_dispatch(path, owner_marker, baseline)?;
        self.run_worktree_dispatch(&WorkerGitDispatch {
            path,
            baseline,
            gate,
            confined,
            cancellation,
            arguments: &arguments,
            git_common_dir: &git_common_dir,
            profile: &profile,
        })
    }

    fn prepare_worktree_dispatch(
        &self,
        path: &Path,
        owner_marker: &Path,
        baseline: GitCommitId,
    ) -> Result<(Vec<OsString>, PathBuf, GitSandboxProfile), WorkerWorktreeError> {
        let git_common_dir = self.source_git_common_dir()?;
        let metadata_path = git_common_dir
            .join("worktrees")
            .join(
                path.file_name()
                    .ok_or_else(|| WorkerWorktreeError::WorktreePathEscape {
                        path: path.to_path_buf(),
                    })?,
            );
        let metadata_parent =
            metadata_path
                .parent()
                .ok_or_else(|| WorkerWorktreeError::WorktreePathEscape {
                    path: metadata_path.clone(),
                })?;
        ensure_no_symlink_components(metadata_parent).map_err(map_path_error)?;
        ensure_nofollow_directory_tree(metadata_parent).map_err(|source| {
            WorkerWorktreeError::Filesystem {
                operation: "create Git worktree metadata parent",
                path: metadata_parent.to_path_buf(),
                source,
            }
        })?;
        ensure_no_symlink_components(metadata_parent).map_err(map_path_error)?;
        let profile = WorkerGitSandbox::new(
            &self.repository_root,
            &git_common_dir,
            &[path, owner_marker, &metadata_path],
        )?
        .profile();
        let arguments = if cfg!(target_os = "linux") {
            prepare_linux_worktree(path, &metadata_path, baseline)?;
            worker_git_arguments([
                arg("-C"),
                OsString::from(path),
                arg("reset"),
                arg("--hard"),
                arg_bytes(&object_hex(baseline.object_id())),
            ])
        } else {
            let baseline_hex = object_hex(baseline.object_id());
            worker_git_arguments([
                arg("worktree"),
                arg("add"),
                arg("--detach"),
                OsString::from(path),
                arg_bytes(&baseline_hex),
            ])
        };
        Ok((arguments, git_common_dir, profile))
    }

    fn run_worktree_dispatch(
        &self,
        dispatch: &WorkerGitDispatch<'_>,
    ) -> Result<(), WorkerWorktreeError> {
        let spec = GitProcessSpec {
            operation: "provision detached worker worktree",
            current_dir: &self.repository_root,
            arguments: dispatch.arguments,
            stdin: None,
            extra_env: &[],
            output_limit: super::GIT_CHECKPOINT_MAX_OUTPUT_BYTES,
            sandbox_profile: Some(dispatch.profile),
            cancellation: dispatch.cancellation,
        };
        let expected_root = observe_root(&self.repository_root)?;
        let expected_git = observe_git_fingerprint(&self.repository_root.join(".git"))?;
        let output = match run_bounded_git_process(
            &spec,
            || {
                ensure_worker_dispatch_identity(
                    &self.repository_root,
                    dispatch.git_common_dir,
                    expected_root,
                    expected_git,
                )
            },
            || {
                self.ensure_worktree_dispatch_after(
                    dispatch.gate,
                    dispatch.confined,
                    expected_root,
                    expected_git,
                )
            },
        ) {
            Ok(output) => output,
            Err(GitSafetyError::GitCancelled { .. })
                if dispatch
                    .cancellation
                    .is_some_and(|flag| !flag.load(std::sync::atomic::Ordering::Acquire)) =>
            {
                return Err(WorkerWorktreeError::Cancelled);
            }
            Err(error) => {
                return Err(unknown_after_dispatch(
                    dispatch.path,
                    dispatch.baseline,
                    &error,
                ));
            }
        };
        if output.status.success() {
            Ok(())
        } else {
            Err(unknown_after_dispatch(
                dispatch.path,
                dispatch.baseline,
                &command_failed("provision detached worker worktree", &output),
            ))
        }
    }

    fn ensure_worktree_dispatch_after(
        &self,
        gate: &WorkspaceStateSharedGate,
        confined: &ConfinedWorkspace,
        expected_root: WorkspaceRootFingerprint,
        expected_git: WorkspaceRootFingerprint,
    ) -> Result<(), GitSafetyError> {
        gate.ensure_root_binding().map_err(|_| {
            GitSafetyError::GitPathChangedAfter(crate::ConfinedFilesystemError::PathChanged)
        })?;
        confined.ensure_for_git(true).map_err(|_| {
            GitSafetyError::GitPathChangedAfter(crate::ConfinedFilesystemError::PathChanged)
        })?;
        let observed = observe_root(&self.repository_root).map_err(|_| {
            GitSafetyError::GitPathChangedAfter(crate::ConfinedFilesystemError::PathChanged)
        })?;
        if observed != expected_root {
            return Err(GitSafetyError::GitPathChangedAfter(
                crate::ConfinedFilesystemError::PathChanged,
            ));
        }
        let observed_git =
            observe_git_fingerprint(&self.repository_root.join(".git")).map_err(|_| {
                GitSafetyError::GitPathChangedAfter(crate::ConfinedFilesystemError::PathChanged)
            })?;
        if observed_git != expected_git {
            return Err(GitSafetyError::GitPathChangedAfter(
                crate::ConfinedFilesystemError::PathChanged,
            ));
        }
        Ok(())
    }

    fn acquire_provision_fences(
        &self,
    ) -> Result<
        (
            ConfinedWorkspace,
            WorkspaceStateSharedGate,
            crate::ConfinedWorkspaceWriteGuard,
        ),
        WorkerWorktreeError,
    > {
        let (confined, gate) = self.acquire_read_fence()?;
        let writer_guard = confined
            .acquire_write_guard()
            .map_err(WorkerWorktreeError::Confined)?;
        confined
            .ensure_for_git(false)
            .map_err(WorkerWorktreeError::Confined)?;
        Ok((confined, gate, writer_guard))
    }

    fn acquire_read_fence(
        &self,
    ) -> Result<(ConfinedWorkspace, WorkspaceStateSharedGate), WorkerWorktreeError> {
        let layout = WorkspaceStateLayout::inspect_existing(&self.repository_root)
            .map_err(WorkerWorktreeError::RootObservation)?
            .ok_or(WorkerWorktreeError::WorkspaceStateUnavailable)?;
        let root_fingerprint = layout
            .root_fingerprint()
            .map_err(WorkerWorktreeError::RootObservation)?;
        let gate = WorkspaceStateSharedGate::acquire(layout.workspace_root(), root_fingerprint)
            .map_err(WorkerWorktreeError::WorkspaceStateGate)?;
        let confined = ConfinedWorkspace::open(&layout).map_err(WorkerWorktreeError::Confined)?;
        gate.ensure_root_binding()
            .map_err(WorkerWorktreeError::WorkspaceStateGate)?;
        confined
            .ensure_for_git(false)
            .map_err(WorkerWorktreeError::Confined)?;
        Ok((confined, gate))
    }

    /// Read back one exact server-owned worktree path without effects.
    pub fn inspect_existing(
        &self,
        worker_id: AgentInstanceId,
        expected_baseline: GitCommitId,
        expected_source_root_fingerprint: WorkspaceRootFingerprint,
        expected_source_git_fingerprint: WorkspaceRootFingerprint,
        expected_worktree_root_fingerprint: WorkspaceRootFingerprint,
        owner: &WorkerWorktreeOwner,
    ) -> Result<WorkerWorktreeInspection, WorkerWorktreeError> {
        let path = self.worker_path(worker_id)?;
        if !path.exists() {
            return Err(WorkerWorktreeError::WorktreeNotFound { path });
        }
        self.validate_source_git_layout()?;
        let (_confined, gate) = self.acquire_read_fence()?;
        let observed_root = observe_root(&self.repository_root)?;
        let observed_git = observe_git_fingerprint(&self.repository_root.join(".git"))?;
        if observed_root != expected_source_root_fingerprint
            || observed_git != expected_source_git_fingerprint
        {
            return Err(WorkerWorktreeError::SourceExpectationConflict {
                expected_root: expected_source_root_fingerprint,
                observed_root,
                expected_baseline,
                observed_baseline: expected_baseline,
                expected_git: expected_source_git_fingerprint,
                observed_git,
            });
        }
        let inspection = self.inspect_exact_worktree(
            &path,
            expected_baseline,
            Some(expected_worktree_root_fingerprint),
            Some(owner),
            None,
        )?;
        gate.ensure_root_binding()
            .map_err(WorkerWorktreeError::WorkspaceStateGate)?;
        Ok(inspection)
    }

    fn worker_path(&self, worker_id: AgentInstanceId) -> Result<PathBuf, WorkerWorktreeError> {
        let team = format!("{}{}", self.team.as_str(), WORKER_TEAM_SUFFIX);
        let path = self
            .repository_root
            .join(WORKER_STATE_DIRECTORY)
            .join(team)
            .join(worker_id.to_string());
        if !path.starts_with(&self.repository_root) {
            return Err(WorkerWorktreeError::WorktreePathEscape { path });
        }
        Ok(path)
    }

    fn owner_marker_path(&self, path: &Path) -> Result<PathBuf, WorkerWorktreeError> {
        let parent = path
            .parent()
            .ok_or_else(|| WorkerWorktreeError::WorktreePathEscape {
                path: path.to_path_buf(),
            })?;
        let name = path
            .file_name()
            .ok_or_else(|| WorkerWorktreeError::WorktreePathEscape {
                path: path.to_path_buf(),
            })?;
        let mut marker_name = name.to_os_string();
        marker_name.push(WORKER_OWNER_MARKER_SUFFIX);
        let marker = parent.join(marker_name);
        if !marker.starts_with(&self.repository_root) {
            return Err(WorkerWorktreeError::WorktreePathEscape { path: marker });
        }
        Ok(marker)
    }

    fn read_owner_marker(path: &Path) -> Result<WorkerOwnerMarker, WorkerWorktreeError> {
        let parent = path
            .parent()
            .ok_or_else(|| WorkerWorktreeError::WorktreePathEscape {
                path: path.to_path_buf(),
            })?;
        let name = path
            .file_name()
            .ok_or_else(|| WorkerWorktreeError::WorktreePathEscape {
                path: path.to_path_buf(),
            })?;
        let directory =
            open_nofollow_directory(parent).map_err(|source| WorkerWorktreeError::Filesystem {
                operation: "open worker owner marker parent",
                path: parent.to_path_buf(),
                source,
            })?;
        let file = openat(
            &directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|source| WorkerWorktreeError::Filesystem {
            operation: "open worker owner marker",
            path: path.to_path_buf(),
            source: io::Error::from(source),
        })?;
        let metadata =
            rustix::fs::fstat(&file).map_err(|source| WorkerWorktreeError::Filesystem {
                operation: "inspect worker owner marker",
                path: path.to_path_buf(),
                source: io::Error::from(source),
            })?;
        if !rustix::fs::FileType::from_raw_mode(metadata.st_mode).is_file()
            || metadata.st_size < 0
            || usize::try_from(metadata.st_size).unwrap_or(MAX_WORKER_OWNER_MARKER_BYTES + 1)
                > MAX_WORKER_OWNER_MARKER_BYTES
        {
            return Err(WorkerWorktreeError::InvalidWorktreeReadBack {
                path: path.to_path_buf(),
            });
        }
        let mut file = File::from(file);
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|source| WorkerWorktreeError::Filesystem {
                operation: "read worker owner marker",
                path: path.to_path_buf(),
                source,
            })?;
        WorkerOwnerMarker::decode(&bytes).map_err(|error| match error {
            WorkerWorktreeError::InvalidWorktreeReadBack { .. } => {
                WorkerWorktreeError::InvalidWorktreeReadBack {
                    path: path.to_path_buf(),
                }
            }
            other => other,
        })
    }

    fn create_owner_marker(
        path: &Path,
        marker: &WorkerOwnerMarker,
    ) -> Result<(), WorkerWorktreeError> {
        let parent = path
            .parent()
            .ok_or_else(|| WorkerWorktreeError::WorktreePathEscape {
                path: path.to_path_buf(),
            })?;
        let name = path
            .file_name()
            .ok_or_else(|| WorkerWorktreeError::WorktreePathEscape {
                path: path.to_path_buf(),
            })?;
        let directory =
            open_nofollow_directory(parent).map_err(|source| WorkerWorktreeError::Filesystem {
                operation: "open worker owner marker parent",
                path: parent.to_path_buf(),
                source,
            })?;
        let file = match openat(
            &directory,
            name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        ) {
            Ok(file) => file,
            Err(Errno::EXIST) => {
                return Err(WorkerWorktreeError::PartialDispatch {
                    path: path.to_path_buf(),
                });
            }
            Err(source) => {
                return Err(WorkerWorktreeError::Filesystem {
                    operation: "create worker owner marker",
                    path: path.to_path_buf(),
                    source: io::Error::from(source),
                });
            }
        };
        let mut file = File::from(file);
        file.write_all(&marker.encode())
            .map_err(|source| WorkerWorktreeError::Filesystem {
                operation: "write worker owner marker",
                path: path.to_path_buf(),
                source,
            })?;
        fsync(&file).map_err(|source| WorkerWorktreeError::Filesystem {
            operation: "sync worker owner marker",
            path: path.to_path_buf(),
            source: io::Error::from(source),
        })?;
        Ok(())
    }

    fn ensure_worker_parent(path: &Path) -> Result<(), WorkerWorktreeError> {
        let parent = path
            .parent()
            .ok_or_else(|| WorkerWorktreeError::WorktreePathEscape {
                path: path.to_path_buf(),
            })?;
        ensure_no_symlink_components(parent).map_err(map_path_error)?;
        ensure_nofollow_directory_tree(parent).map_err(|source| {
            WorkerWorktreeError::Filesystem {
                operation: "create worker worktree parent",
                path: parent.to_path_buf(),
                source,
            }
        })?;
        Ok(())
    }

    fn read_existing_or_conflict(
        &self,
        path: PathBuf,
        worker_id: AgentInstanceId,
        source: &WorkerSourceInspection,
        owner: &WorkerWorktreeOwner,
        cancellation: Option<&AtomicBool>,
    ) -> Result<WorkerWorktreeProvisionReceipt, WorkerWorktreeError> {
        let owner_marker = self.owner_marker_path(&path)?;
        let marker = Self::read_owner_marker(&owner_marker).map_err(|_| {
            WorkerWorktreeError::OwnerMarkerMismatch {
                path: owner_marker.clone(),
            }
        })?;
        if !marker.matches(worker_id, source, owner) {
            return Err(WorkerWorktreeError::OwnerMarkerMismatch { path: owner_marker });
        }
        let inspection =
            self.inspect_exact_worktree(&path, source.baseline, None, Some(owner), cancellation);
        match inspection {
            Ok(inspection) if inspection.baseline == source.baseline => {
                let current = self.inspect_source_with_cancellation(cancellation)?;
                ensure_source_matches(source, &current)?;
                Ok(WorkerWorktreeProvisionReceipt {
                    path,
                    worker_id,
                    baseline: source.baseline,
                    source_root_fingerprint: source.root_fingerprint,
                    source_git_fingerprint: source.git_fingerprint,
                    owner: owner.clone(),
                    outcome: WorkerWorktreeProvisionOutcome::ExistingReadBack,
                    inspection,
                })
            }
            Ok(inspection) => Err(WorkerWorktreeError::ExistingPathConflict {
                path,
                expected: source.baseline,
                observed: Some(inspection.baseline),
            }),
            Err(WorkerWorktreeError::WorktreeNotFound { .. }) => {
                Err(WorkerWorktreeError::ExistingPathConflict {
                    path,
                    expected: source.baseline,
                    observed: None,
                })
            }
            Err(_) => Err(WorkerWorktreeError::ExistingPathConflict {
                path,
                expected: source.baseline,
                observed: None,
            }),
        }
    }

    fn inspect_exact_worktree(
        &self,
        path: &Path,
        expected_baseline: GitCommitId,
        expected_worktree_root_fingerprint: Option<WorkspaceRootFingerprint>,
        expected_owner: Option<&WorkerWorktreeOwner>,
        cancellation: Option<&AtomicBool>,
    ) -> Result<WorkerWorktreeInspection, WorkerWorktreeError> {
        ensure_no_symlink_components(path).map_err(map_path_error)?;
        let metadata = fs::symlink_metadata(path).map_err(|source| {
            if source.kind() == io::ErrorKind::NotFound {
                WorkerWorktreeError::WorktreeNotFound {
                    path: path.to_path_buf(),
                }
            } else {
                WorkerWorktreeError::Filesystem {
                    operation: "inspect worker worktree root",
                    path: path.to_path_buf(),
                    source,
                }
            }
        })?;
        if metadata.file_type().is_symlink() {
            return Err(WorkerWorktreeError::SymlinkPath {
                path: path.to_path_buf(),
            });
        }
        if !metadata.is_dir() {
            return Err(WorkerWorktreeError::InvalidWorktreeReadBack {
                path: path.to_path_buf(),
            });
        }
        let canonical =
            fs::canonicalize(path).map_err(|source| WorkerWorktreeError::Filesystem {
                operation: "canonicalize worker worktree root",
                path: path.to_path_buf(),
                source,
            })?;
        if canonical != path {
            return Err(WorkerWorktreeError::WorktreePathEscape {
                path: path.to_path_buf(),
            });
        }
        if let Some(owner) = expected_owner {
            let owner_marker = self.owner_marker_path(path)?;
            let marker = Self::read_owner_marker(&owner_marker)?;
            if !marker.matches_path(path, &self.repository_root, owner) {
                return Err(WorkerWorktreeError::OwnerMarkerMismatch { path: owner_marker });
            }
        }
        let root_fingerprint = observe_root(path)?;
        if let Some(expected) = expected_worktree_root_fingerprint
            && root_fingerprint != expected
        {
            return Err(WorkerWorktreeError::WorktreeRootChanged {
                path: path.to_path_buf(),
                expected,
                observed: root_fingerprint,
            });
        }
        let (baseline, dirty_entries) =
            self.inspect_worktree_git_state(path, expected_baseline, cancellation)?;
        Ok(WorkerWorktreeInspection {
            path: path.to_path_buf(),
            root_fingerprint,
            baseline,
            dirty_entries,
        })
    }

    fn inspect_worktree_git_state(
        &self,
        path: &Path,
        expected_baseline: GitCommitId,
        cancellation: Option<&AtomicBool>,
    ) -> Result<(GitCommitId, Vec<WorkerDirtyEntry>), WorkerWorktreeError> {
        let source_common = self.source_git_common_dir()?;
        let top_level = run_git_path(
            path,
            &source_common,
            "resolve worker Git root",
            &[arg("rev-parse"), arg("--show-toplevel")],
            cancellation,
        )?;
        if top_level != path {
            return Err(WorkerWorktreeError::InvalidWorktreeReadBack {
                path: path.to_path_buf(),
            });
        }
        let common_dir = run_git_path(
            path,
            &source_common,
            "resolve worker Git common directory",
            &[arg("rev-parse"), arg("--git-common-dir")],
            cancellation,
        )?;
        if common_dir != source_common {
            return Err(WorkerWorktreeError::InvalidWorktreeReadBack {
                path: path.to_path_buf(),
            });
        }
        let baseline = run_git_commit(
            path,
            &source_common,
            "read worker worktree baseline",
            &[arg("rev-parse"), arg("--verify"), arg("HEAD^{commit}")],
            cancellation,
        )?;
        if baseline != expected_baseline {
            return Err(WorkerWorktreeError::ExistingPathConflict {
                path: path.to_path_buf(),
                expected: expected_baseline,
                observed: Some(baseline),
            });
        }
        let status = run_git_output(
            path,
            &source_common,
            "inspect worker worktree status",
            &[
                arg("status"),
                arg("--porcelain=v1"),
                arg("--untracked-files=all"),
                arg("--ignore-submodules=none"),
                arg("-z"),
            ],
            cancellation,
        )?;
        Ok((baseline, parse_status_output(&status)?))
    }

    fn source_git_common_dir(&self) -> Result<PathBuf, WorkerWorktreeError> {
        let path = self.repository_root.join(".git");
        fs::canonicalize(&path).map_err(|source| WorkerWorktreeError::Filesystem {
            operation: "canonicalize source Git common directory",
            path,
            source,
        })
    }

    fn validate_source_git_layout(&self) -> Result<(), WorkerWorktreeError> {
        let git_path = self.repository_root.join(".git");
        let metadata = match fs::symlink_metadata(&git_path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(WorkerWorktreeError::NotGitRepository);
            }
            Err(source) => {
                return Err(WorkerWorktreeError::Filesystem {
                    operation: "inspect source Git directory",
                    path: git_path,
                    source,
                });
            }
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(WorkerWorktreeError::UnsupportedGitLayout);
        }
        Ok(())
    }

    fn git_output(
        &self,
        operation: &'static str,
        arguments: &[OsString],
        cancellation: Option<&AtomicBool>,
    ) -> Result<GitOutput, WorkerWorktreeError> {
        let git_common_dir = self.source_git_common_dir()?;
        run_git_output(
            &self.repository_root,
            &git_common_dir,
            operation,
            arguments,
            cancellation,
        )
    }

    fn git_path(
        &self,
        operation: &'static str,
        arguments: &[OsString],
        cancellation: Option<&AtomicBool>,
    ) -> Result<PathBuf, WorkerWorktreeError> {
        let git_common_dir = self.source_git_common_dir()?;
        run_git_path(
            &self.repository_root,
            &git_common_dir,
            operation,
            arguments,
            cancellation,
        )
    }

    fn git_commit(
        &self,
        operation: &'static str,
        arguments: &[OsString],
        cancellation: Option<&AtomicBool>,
    ) -> Result<GitCommitId, WorkerWorktreeError> {
        let git_common_dir = self.source_git_common_dir()?;
        run_git_commit(
            &self.repository_root,
            &git_common_dir,
            operation,
            arguments,
            cancellation,
        )
    }

    fn status_entries(
        root: &Path,
        git_common_dir: &Path,
        cancellation: Option<&AtomicBool>,
    ) -> Result<Vec<WorkerDirtyEntry>, WorkerWorktreeError> {
        let output = run_git_output(
            root,
            git_common_dir,
            "inspect source Git status",
            &[
                arg("status"),
                arg("--porcelain=v1"),
                arg("--untracked-files=all"),
                arg("--ignore-submodules=none"),
                arg("-z"),
            ],
            cancellation,
        )?;
        parse_status_output(&output)
    }
}

fn canonical_source_root(path: &Path) -> Result<PathBuf, WorkerWorktreeError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| WorkerWorktreeError::InvalidSourceRoot {
            path: path.to_path_buf(),
        })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(WorkerWorktreeError::InvalidSourceRoot {
            path: path.to_path_buf(),
        });
    }
    let canonical = fs::canonicalize(path).map_err(|_| WorkerWorktreeError::InvalidSourceRoot {
        path: path.to_path_buf(),
    })?;
    Ok(canonical)
}

fn observe_root(path: &Path) -> Result<WorkspaceRootFingerprint, WorkerWorktreeError> {
    WorkspaceStateLayout::observe_root_fingerprint(path)
        .map_err(WorkerWorktreeError::RootObservation)
}

fn observe_git_fingerprint(path: &Path) -> Result<WorkspaceRootFingerprint, WorkerWorktreeError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|source| WorkerWorktreeError::Filesystem {
            operation: "inspect physical source Git directory",
            path: path.to_path_buf(),
            source,
        })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(WorkerWorktreeError::UnsupportedGitLayout);
    }
    let canonical = fs::canonicalize(path).map_err(|source| WorkerWorktreeError::Filesystem {
        operation: "canonicalize physical source Git directory",
        path: path.to_path_buf(),
        source,
    })?;
    if canonical != path {
        return Err(WorkerWorktreeError::UnsupportedGitLayout);
    }
    let mut bytes = [0_u8; 16];
    bytes[..8].copy_from_slice(&metadata.dev().to_le_bytes());
    bytes[8..].copy_from_slice(&metadata.ino().to_le_bytes());
    Ok(WorkspaceRootFingerprint::from_bytes(bytes))
}

fn ensure_worker_dispatch_identity(
    root: &Path,
    git_common_dir: &Path,
    expected_root: WorkspaceRootFingerprint,
    expected_git: WorkspaceRootFingerprint,
) -> Result<(), GitSafetyError> {
    let observed_root = observe_root(root).map_err(|_| {
        GitSafetyError::GitPathChangedAfter(crate::ConfinedFilesystemError::PathChanged)
    })?;
    if observed_root != expected_root {
        return Err(GitSafetyError::GitPathChangedAfter(
            crate::ConfinedFilesystemError::PathChanged,
        ));
    }
    let observed_git = observe_git_fingerprint(git_common_dir).map_err(|_| {
        GitSafetyError::GitPathChangedAfter(crate::ConfinedFilesystemError::PathChanged)
    })?;
    if observed_git != expected_git {
        return Err(GitSafetyError::GitPathChangedAfter(
            crate::ConfinedFilesystemError::PathChanged,
        ));
    }
    Ok(())
}

fn prepare_linux_worktree(
    path: &Path,
    metadata_path: &Path,
    baseline: GitCommitId,
) -> Result<(), WorkerWorktreeError> {
    // The linked-worktree roots are created by the trusted owner before
    // bubblewrap binds them.  Git then only receives the exact worker root
    // and exact metadata root as writable mounts; it never chooses a suffixed
    // sibling under `.git/worktrees`.
    create_worker_directory(path, "create worker worktree target")?;
    create_worker_directory(metadata_path, "create Git worktree metadata directory")?;

    let mut head = object_hex(baseline.object_id());
    head.push(b'\n');
    create_worker_file(
        &metadata_path.join("HEAD"),
        &head,
        path,
        "create worker Git HEAD",
    )?;
    create_worker_file(
        &metadata_path.join("commondir"),
        b"../..\n",
        path,
        "create worker Git commondir",
    )?;

    let worker_git_path = path.join(".git");
    let mut metadata_gitdir = worker_git_path.as_os_str().as_bytes().to_vec();
    metadata_gitdir.push(b'\n');
    create_worker_file(
        &metadata_path.join("gitdir"),
        &metadata_gitdir,
        path,
        "create worker Git gitdir",
    )?;

    let mut worker_gitdir = b"gitdir: ".to_vec();
    worker_gitdir.extend_from_slice(metadata_path.as_os_str().as_bytes());
    worker_gitdir.push(b'\n');
    create_worker_file(
        &worker_git_path,
        &worker_gitdir,
        path,
        "create worker .git file",
    )?;
    Ok(())
}

fn create_worker_directory(
    path: &Path,
    operation: &'static str,
) -> Result<(), WorkerWorktreeError> {
    let parent = path
        .parent()
        .ok_or_else(|| WorkerWorktreeError::WorktreePathEscape {
            path: path.to_path_buf(),
        })?;
    let name = path
        .file_name()
        .ok_or_else(|| WorkerWorktreeError::WorktreePathEscape {
            path: path.to_path_buf(),
        })?;
    ensure_no_symlink_components(parent).map_err(map_path_error)?;
    let directory =
        open_nofollow_directory(parent).map_err(|source| WorkerWorktreeError::Filesystem {
            operation,
            path: parent.to_path_buf(),
            source,
        })?;
    match mkdirat(&directory, name, Mode::RUSR | Mode::WUSR | Mode::XUSR) {
        Ok(()) => Ok(()),
        Err(Errno::EXIST) => Err(WorkerWorktreeError::PartialDispatch {
            path: path.to_path_buf(),
        }),
        Err(source) => Err(WorkerWorktreeError::Filesystem {
            operation,
            path: path.to_path_buf(),
            source: io::Error::from(source),
        }),
    }
}

fn create_worker_file(
    path: &Path,
    contents: &[u8],
    partial_path: &Path,
    operation: &'static str,
) -> Result<(), WorkerWorktreeError> {
    let parent = path
        .parent()
        .ok_or_else(|| WorkerWorktreeError::WorktreePathEscape {
            path: path.to_path_buf(),
        })?;
    let name = path
        .file_name()
        .ok_or_else(|| WorkerWorktreeError::WorktreePathEscape {
            path: path.to_path_buf(),
        })?;
    ensure_no_symlink_components(parent).map_err(map_path_error)?;
    let directory =
        open_nofollow_directory(parent).map_err(|source| WorkerWorktreeError::Filesystem {
            operation,
            path: parent.to_path_buf(),
            source,
        })?;
    let file = match openat(
        &directory,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    ) {
        Ok(file) => file,
        Err(Errno::EXIST) => {
            return Err(WorkerWorktreeError::PartialDispatch {
                path: partial_path.to_path_buf(),
            });
        }
        Err(source) => {
            return Err(WorkerWorktreeError::Filesystem {
                operation,
                path: path.to_path_buf(),
                source: io::Error::from(source),
            });
        }
    };
    let mut file = File::from(file);
    file.write_all(contents)
        .map_err(|source| WorkerWorktreeError::Filesystem {
            operation,
            path: path.to_path_buf(),
            source,
        })?;
    fsync(&file).map_err(|source| WorkerWorktreeError::Filesystem {
        operation,
        path: path.to_path_buf(),
        source: io::Error::from(source),
    })?;
    Ok(())
}

fn worker_git_arguments<I>(arguments: I) -> Vec<OsString>
where
    I: IntoIterator<Item = OsString>,
{
    let mut result = vec![
        arg("-c"),
        arg("core.hooksPath=/dev/null"),
        arg("-c"),
        arg("core.fsmonitor=false"),
        arg("-c"),
        arg("core.untrackedCache=false"),
        arg("-c"),
        arg("protocol.allow=never"),
        arg("-c"),
        arg("submodule.recurse=false"),
        arg("--no-optional-locks"),
    ];
    result.extend(arguments);
    result
}

#[derive(Debug, Clone)]
struct WorkerGitSandbox {
    profile: GitSandboxProfile,
}

impl WorkerGitSandbox {
    fn new(
        root: &Path,
        git_common_dir: &Path,
        write_paths: &[&Path],
    ) -> Result<Self, WorkerWorktreeError> {
        validate_write_paths(write_paths)?;
        if cfg!(target_os = "macos") {
            if !Path::new(WORKER_SANDBOX_EXEC).is_file() || !Path::new(WORKER_SANDBOX_GIT).is_file()
            {
                return Err(WorkerWorktreeError::SandboxUnavailable);
            }
        } else if !Path::new(super::worker_worktree_linux::WORKER_BWRAP).is_file()
            || !Path::new(WORKER_SANDBOX_GIT).is_file()
        {
            return Err(WorkerWorktreeError::SandboxUnavailable);
        }
        validate_supported_git_configuration(git_common_dir)?;
        let root = canonical_profile_root(root)?;
        let git_common_dir = canonical_profile_root(git_common_dir)?;
        let mut profile = if cfg!(target_os = "macos") {
            String::from(
                "(version 1)\n(deny default)\n(import \"system.sb\")\n\
                 (allow process-fork)\n\
                 (allow process-exec (literal \"/Library/Developer/CommandLineTools/usr/bin/git\"))\n\
                 (allow file-read-metadata (subpath \"/\"))\n\
                 (allow file-read* (literal \"/Library/Developer/CommandLineTools/usr/bin/git\"))\n\
                 (allow file-read* (subpath \"/Library/Developer/CommandLineTools\"))\n\
                 (allow file-read* (literal \"/dev/null\"))\n\
                 (deny network*)\n",
            )
        } else {
            let arguments = super::worker_worktree_linux::worker_git_bwrap_args(
                &root,
                &git_common_dir,
                write_paths,
                WORKER_SANDBOX_GIT,
            )?;
            return Ok(Self {
                profile: GitSandboxProfile::Linux(arguments),
            });
        };
        append_sandbox_subpath(&mut profile, "file-read*", &root)?;
        if git_common_dir != root {
            append_sandbox_subpath(&mut profile, "file-read*", &git_common_dir)?;
        }
        for path in write_paths {
            append_sandbox_subpath(&mut profile, "file-write*", path)?;
        }
        if profile.len() > 32 * 1024 {
            return Err(WorkerWorktreeError::SandboxUnavailable);
        }
        Ok(Self {
            profile: GitSandboxProfile::Seatbelt(profile),
        })
    }

    fn profile(&self) -> GitSandboxProfile {
        self.profile.clone()
    }
}

pub(super) fn validate_write_paths(write_paths: &[&Path]) -> Result<(), WorkerWorktreeError> {
    for path in write_paths {
        if path.as_os_str().is_empty() || !path.is_absolute() {
            return Err(WorkerWorktreeError::WorktreePathEscape {
                path: (*path).to_path_buf(),
            });
        }
        ensure_no_symlink_components(path).map_err(map_path_error)?;
    }
    Ok(())
}

fn canonical_profile_root(path: &Path) -> Result<PathBuf, WorkerWorktreeError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|source| WorkerWorktreeError::Filesystem {
            operation: "inspect Git sandbox read root",
            path: path.to_path_buf(),
            source,
        })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(WorkerWorktreeError::UnsupportedGitLayout);
    }
    let canonical = fs::canonicalize(path).map_err(|source| WorkerWorktreeError::Filesystem {
        operation: "canonicalize Git sandbox read root",
        path: path.to_path_buf(),
        source,
    })?;
    if canonical != path {
        return Err(WorkerWorktreeError::UnsupportedGitLayout);
    }
    Ok(canonical)
}

fn append_sandbox_subpath(
    profile: &mut String,
    operation: &str,
    path: &Path,
) -> Result<(), WorkerWorktreeError> {
    use std::fmt::Write as _;
    let escaped = sandbox_scheme_path(path)?;
    writeln!(profile, "(allow {operation} (subpath {escaped}))")
        .map_err(|_| WorkerWorktreeError::SandboxUnavailable)?;
    Ok(())
}

fn sandbox_scheme_path(path: &Path) -> Result<String, WorkerWorktreeError> {
    let value = path
        .to_str()
        .ok_or(WorkerWorktreeError::SandboxUnavailable)?;
    if value.chars().any(char::is_control) {
        return Err(WorkerWorktreeError::SandboxUnavailable);
    }
    let mut escaped = String::with_capacity(value.len() + 2);
    escaped.push('"');
    for character in value.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            other => escaped.push(other),
        }
    }
    escaped.push('"');
    Ok(escaped)
}

fn validate_supported_git_configuration(git_common_dir: &Path) -> Result<(), WorkerWorktreeError> {
    let path = git_common_dir.join("config");
    validate_git_config_file(&path)?;
    let worktree_config = git_common_dir.join("config.worktree");
    match fs::symlink_metadata(&worktree_config) {
        Ok(_) => validate_git_config_file(&worktree_config),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(WorkerWorktreeError::Filesystem {
            operation: "inspect source Git worktree configuration",
            path: worktree_config,
            source,
        }),
    }
}

fn validate_git_config_file(path: &Path) -> Result<(), WorkerWorktreeError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|source| WorkerWorktreeError::Filesystem {
            operation: "inspect source Git configuration",
            path: path.to_path_buf(),
            source,
        })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(WorkerWorktreeError::UnsupportedGitConfiguration {
            path: path.to_path_buf(),
        });
    }
    if metadata.len() > 256 * 1024 {
        return Err(WorkerWorktreeError::UnsupportedGitConfiguration {
            path: path.to_path_buf(),
        });
    }
    let contents = fs::read(path).map_err(|source| WorkerWorktreeError::Filesystem {
        operation: "read source Git configuration",
        path: path.to_path_buf(),
        source,
    })?;
    let mut section = Vec::new();
    for raw_line in contents.split(|byte| *byte == b'\n') {
        let line = raw_line
            .split(|byte| *byte == b'#' || *byte == b';')
            .next()
            .unwrap_or_default();
        let line = line
            .iter()
            .copied()
            .filter(|byte| !byte.is_ascii_whitespace())
            .collect::<Vec<_>>();
        if line.is_empty() {
            continue;
        }
        if line.first() == Some(&b'[') && line.last() == Some(&b']') {
            section = line[1..line.len() - 1].to_ascii_lowercase();
            if section.starts_with(b"include") || section.starts_with(b"filter") {
                return Err(WorkerWorktreeError::UnsupportedGitConfiguration {
                    path: path.to_path_buf(),
                });
            }
            continue;
        }
        let key = line
            .split(|byte| *byte == b'=')
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        if key.starts_with(b"include.")
            || key.starts_with(b"filter.")
            || (section == b"core" && key.starts_with(b"fsmonitor"))
            || (section == b"core" && matches!(key.as_slice(), b"sshcommand" | b"gitproxy"))
            || (section.starts_with(b"remote")
                && matches!(key.as_slice(), b"uploadpack" | b"receivepack"))
        {
            return Err(WorkerWorktreeError::UnsupportedGitConfiguration {
                path: path.to_path_buf(),
            });
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WorkerOwnerMarker {
    worker_id: AgentInstanceId,
    canonical_root: PathBuf,
    source_root_fingerprint: WorkspaceRootFingerprint,
    source_git_fingerprint: WorkspaceRootFingerprint,
    baseline: GitCommitId,
    owner: WorkerWorktreeOwner,
}

impl WorkerOwnerMarker {
    fn new(
        worker_id: AgentInstanceId,
        source: &WorkerSourceInspection,
        owner: &WorkerWorktreeOwner,
    ) -> Self {
        Self {
            worker_id,
            canonical_root: source.repository_root.clone(),
            source_root_fingerprint: source.root_fingerprint,
            source_git_fingerprint: source.git_fingerprint,
            baseline: source.baseline,
            owner: owner.clone(),
        }
    }

    fn matches(
        &self,
        worker_id: AgentInstanceId,
        source: &WorkerSourceInspection,
        owner: &WorkerWorktreeOwner,
    ) -> bool {
        self.worker_id == worker_id
            && self.canonical_root == source.repository_root
            && self.source_root_fingerprint == source.root_fingerprint
            && self.source_git_fingerprint == source.git_fingerprint
            && self.baseline == source.baseline
            && self.owner == *owner
    }

    fn matches_path(
        &self,
        path: &Path,
        repository_root: &Path,
        owner: &WorkerWorktreeOwner,
    ) -> bool {
        let Some(worker_name) = path.file_name() else {
            return false;
        };
        let Ok(worker_id) = worker_name.to_string_lossy().parse::<AgentInstanceId>() else {
            return false;
        };
        let Ok(root_fingerprint) = observe_root(repository_root) else {
            return false;
        };
        let Ok(git_fingerprint) = observe_git_fingerprint(&repository_root.join(".git")) else {
            return false;
        };
        self.worker_id == worker_id
            && self.canonical_root == repository_root
            && self.source_root_fingerprint == root_fingerprint
            && self.source_git_fingerprint == git_fingerprint
            && self.owner == *owner
    }

    fn encode(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(512);
        output.extend_from_slice(b"forge-worker-owner-v1\n");
        append_marker_field(
            &mut output,
            b"worker",
            self.worker_id.to_string().as_bytes(),
        );
        append_marker_field(
            &mut output,
            b"canonical-root",
            &hex_encode(self.canonical_root.as_os_str().as_bytes()),
        );
        append_marker_field(
            &mut output,
            b"source-root",
            &hex_encode(&self.source_root_fingerprint.into_bytes()),
        );
        append_marker_field(
            &mut output,
            b"source-git",
            &hex_encode(&self.source_git_fingerprint.into_bytes()),
        );
        append_marker_field(
            &mut output,
            b"baseline",
            &hex_encode(self.baseline.object_id().as_bytes()),
        );
        append_marker_field(
            &mut output,
            b"assignment",
            &hex_encode(&self.owner.assignment),
        );
        append_marker_field(&mut output, b"claim", &hex_encode(&self.owner.claim));
        output
    }

    fn decode(bytes: &[u8]) -> Result<Self, WorkerWorktreeError> {
        if bytes.len() > MAX_WORKER_OWNER_MARKER_BYTES
            || !bytes.ends_with(b"\n")
            || !bytes.starts_with(WORKER_OWNER_MARKER_HEADER)
        {
            return Err(WorkerWorktreeError::InvalidWorktreeReadBack {
                path: PathBuf::from("owner marker"),
            });
        }
        let mut worker = None;
        let mut canonical_root = None;
        let mut source_root = None;
        let mut source_git = None;
        let mut baseline = None;
        let mut assignment = None;
        let mut claim = None;
        for line in bytes[WORKER_OWNER_MARKER_HEADER.len()..].split(|byte| *byte == b'\n') {
            if line.is_empty() {
                continue;
            }
            let mut fields = line.splitn(2, |byte| *byte == b'=');
            let (Some(key), Some(value)) = (fields.next(), fields.next()) else {
                return Err(WorkerWorktreeError::InvalidWorktreeReadBack {
                    path: PathBuf::from("owner marker"),
                });
            };
            let target = match key {
                b"worker" => &mut worker,
                b"canonical-root" => &mut canonical_root,
                b"source-root" => &mut source_root,
                b"source-git" => &mut source_git,
                b"baseline" => &mut baseline,
                b"assignment" => &mut assignment,
                b"claim" => &mut claim,
                _ => {
                    return Err(WorkerWorktreeError::InvalidWorktreeReadBack {
                        path: PathBuf::from("owner marker"),
                    });
                }
            };
            if target.is_some() {
                return Err(WorkerWorktreeError::InvalidWorktreeReadBack {
                    path: PathBuf::from("owner marker"),
                });
            }
            *target = Some(value.to_vec());
        }
        let worker = worker
            .as_deref()
            .and_then(|value| std::str::from_utf8(value).ok())
            .and_then(|value| value.parse().ok())
            .ok_or_else(|| WorkerWorktreeError::InvalidWorktreeReadBack {
                path: PathBuf::from("owner marker"),
            })?;
        let canonical_root = PathBuf::from(OsString::from_vec(hex_decode(
            canonical_root.as_deref().ok_or_else(|| {
                WorkerWorktreeError::InvalidWorktreeReadBack {
                    path: PathBuf::from("owner marker"),
                }
            })?,
        )?));
        let source_root_fingerprint = fingerprint_from_hex(source_root.as_deref())?;
        let source_git_fingerprint = fingerprint_from_hex(source_git.as_deref())?;
        let baseline_bytes = hex_decode(baseline.as_deref().ok_or_else(|| {
            WorkerWorktreeError::InvalidWorktreeReadBack {
                path: PathBuf::from("owner marker"),
            }
        })?)?;
        let baseline = <[u8; 20]>::try_from(baseline_bytes.as_slice()).map_err(|_| {
            WorkerWorktreeError::InvalidWorktreeReadBack {
                path: PathBuf::from("owner marker"),
            }
        })?;
        let assignment = hex_decode(assignment.as_deref().ok_or_else(|| {
            WorkerWorktreeError::InvalidWorktreeReadBack {
                path: PathBuf::from("owner marker"),
            }
        })?)?;
        let claim = hex_decode(claim.as_deref().ok_or_else(|| {
            WorkerWorktreeError::InvalidWorktreeReadBack {
                path: PathBuf::from("owner marker"),
            }
        })?)?;
        let owner = WorkerWorktreeOwner::new(assignment, claim)?;
        Ok(Self {
            worker_id: worker,
            canonical_root,
            source_root_fingerprint,
            source_git_fingerprint,
            baseline: GitCommitId::from_sha1_bytes(baseline),
            owner,
        })
    }
}

fn append_marker_field(output: &mut Vec<u8>, key: &[u8], value: &[u8]) {
    output.extend_from_slice(key);
    output.push(b'=');
    output.extend_from_slice(value);
    output.push(b'\n');
}

fn validate_owner_identity(
    kind: &'static str,
    value: &[u8],
) -> Result<Vec<u8>, WorkerWorktreeError> {
    if value.is_empty()
        || value.len() > MAX_WORKER_OWNER_IDENTITY_BYTES
        || value.iter().any(|byte| matches!(*byte, 0 | b'\n' | b'\r'))
    {
        return Err(WorkerWorktreeError::InvalidOwnerIdentity { kind });
    }
    Ok(value.to_vec())
}

fn hex_encode(value: &[u8]) -> Vec<u8> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = Vec::with_capacity(value.len() * 2);
    for byte in value {
        output.push(HEX[(byte >> 4) as usize]);
        output.push(HEX[(byte & 0x0f) as usize]);
    }
    output
}

fn hex_decode(value: &[u8]) -> Result<Vec<u8>, WorkerWorktreeError> {
    if value.is_empty() || !value.len().is_multiple_of(2) {
        return Err(WorkerWorktreeError::InvalidWorktreeReadBack {
            path: PathBuf::from("owner marker"),
        });
    }
    let mut output = Vec::with_capacity(value.len() / 2);
    for pair in value.as_chunks::<2>().0 {
        let high =
            hex_digit(pair[0]).ok_or_else(|| WorkerWorktreeError::InvalidWorktreeReadBack {
                path: PathBuf::from("owner marker"),
            })?;
        let low =
            hex_digit(pair[1]).ok_or_else(|| WorkerWorktreeError::InvalidWorktreeReadBack {
                path: PathBuf::from("owner marker"),
            })?;
        output.push((high << 4) | low);
    }
    Ok(output)
}

fn fingerprint_from_hex(
    value: Option<&[u8]>,
) -> Result<WorkspaceRootFingerprint, WorkerWorktreeError> {
    let bytes = hex_decode(
        value.ok_or_else(|| WorkerWorktreeError::InvalidWorktreeReadBack {
            path: PathBuf::from("owner marker"),
        })?,
    )?;
    let bytes = <[u8; 16]>::try_from(bytes.as_slice()).map_err(|_| {
        WorkerWorktreeError::InvalidWorktreeReadBack {
            path: PathBuf::from("owner marker"),
        }
    })?;
    Ok(WorkspaceRootFingerprint::from_bytes(bytes))
}

fn open_nofollow_directory(path: &Path) -> Result<OwnedFd, io::Error> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "owner marker parent must be absolute",
        ));
    }
    let mut directory = open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(io::Error::from)?;
    for component in path.components() {
        let std::path::Component::Normal(component) = component else {
            continue;
        };
        directory = openat(
            &directory,
            component,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(io::Error::from)?;
    }
    Ok(directory)
}

fn ensure_nofollow_directory_tree(path: &Path) -> Result<OwnedFd, io::Error> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "directory path must be absolute",
        ));
    }
    let mut directory = open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(io::Error::from)?;
    for component in path.components() {
        let std::path::Component::Normal(component) = component else {
            continue;
        };
        match openat(
            &directory,
            component,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(next) => directory = next,
            Err(Errno::NOENT) => {
                match mkdirat(&directory, component, Mode::RUSR | Mode::WUSR | Mode::XUSR) {
                    Ok(()) | Err(Errno::EXIST) => {}
                    Err(source) => return Err(io::Error::from(source)),
                }
                directory = openat(
                    &directory,
                    component,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(io::Error::from)?;
            }
            Err(source) => return Err(io::Error::from(source)),
        }
    }
    Ok(directory)
}

const fn hex_digit(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn run_git_output(
    root: &Path,
    git_common_dir: &Path,
    operation: &'static str,
    arguments: &[OsString],
    cancellation: Option<&AtomicBool>,
) -> Result<GitOutput, WorkerWorktreeError> {
    let expected_root = observe_root(root)?;
    let expected_git = observe_git_fingerprint(git_common_dir)?;
    let profile = WorkerGitSandbox::new(root, git_common_dir, &[])?.profile();
    let arguments = worker_git_arguments(arguments.iter().cloned());
    let spec = GitProcessSpec {
        operation,
        current_dir: root,
        arguments: &arguments,
        stdin: None,
        extra_env: &[],
        output_limit: super::GIT_CHECKPOINT_MAX_OUTPUT_BYTES,
        sandbox_profile: Some(&profile),
        cancellation,
    };
    run_bounded_git_process(
        &spec,
        || ensure_worker_dispatch_identity(root, git_common_dir, expected_root, expected_git),
        || {
            let observed = WorkspaceStateLayout::observe_root_fingerprint(root).map_err(|_| {
                GitSafetyError::GitPathChangedAfter(crate::ConfinedFilesystemError::PathChanged)
            })?;
            if observed != expected_root {
                return Err(GitSafetyError::GitPathChangedAfter(
                    crate::ConfinedFilesystemError::PathChanged,
                ));
            }
            let observed_git = observe_git_fingerprint(git_common_dir).map_err(|_| {
                GitSafetyError::GitPathChangedAfter(crate::ConfinedFilesystemError::PathChanged)
            })?;
            if observed_git != expected_git {
                return Err(GitSafetyError::GitPathChangedAfter(
                    crate::ConfinedFilesystemError::PathChanged,
                ));
            }
            Ok(())
        },
    )
    .map_err(|error| match error {
        GitSafetyError::GitCancelled { .. } => WorkerWorktreeError::Cancelled,
        other => WorkerWorktreeError::Git(other),
    })
    .and_then(|output| {
        if output.status.success() {
            Ok(output)
        } else {
            Err(WorkerWorktreeError::Git(command_failed(operation, &output)))
        }
    })
}

fn run_git_path(
    root: &Path,
    git_common_dir: &Path,
    operation: &'static str,
    arguments: &[OsString],
    cancellation: Option<&AtomicBool>,
) -> Result<PathBuf, WorkerWorktreeError> {
    let output = run_git_output(root, git_common_dir, operation, arguments, cancellation)?;
    let bytes = trim_ascii(&output.stdout);
    if bytes.is_empty() {
        return Err(WorkerWorktreeError::InvalidGitOutput { operation });
    }
    let raw = PathBuf::from(OsString::from_vec(bytes.to_vec()));
    let path = if raw.is_absolute() {
        raw
    } else {
        root.join(raw)
    };
    fs::canonicalize(&path).map_err(|source| WorkerWorktreeError::Filesystem {
        operation: "canonicalize Git path output",
        path,
        source,
    })
}

fn run_git_commit(
    root: &Path,
    git_common_dir: &Path,
    operation: &'static str,
    arguments: &[OsString],
    cancellation: Option<&AtomicBool>,
) -> Result<GitCommitId, WorkerWorktreeError> {
    let output = run_git_output(root, git_common_dir, operation, arguments, cancellation)?;
    let object =
        parse_git_object_id(operation, &output.stdout).map_err(WorkerWorktreeError::Git)?;
    Ok(GitCommitId::from_sha1_bytes(*object.as_bytes()))
}

fn parse_status_output(output: &GitOutput) -> Result<Vec<WorkerDirtyEntry>, WorkerWorktreeError> {
    let mut entries = Vec::new();
    let mut records = output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
        .peekable();
    while let Some(record) = records.next() {
        if record.len() < 3 || record[2] != b' ' {
            return Err(WorkerWorktreeError::InvalidGitOutput {
                operation: "parse Git status",
            });
        }
        let path = &record[3..];
        if path.len() > MAX_WORKER_STATUS_PATH_BYTES || entries.len() >= MAX_WORKER_STATUS_ENTRIES {
            return Err(WorkerWorktreeError::InvalidGitOutput {
                operation: "parse Git status entry bound",
            });
        }
        entries.push(WorkerDirtyEntry {
            code: [record[0], record[1]],
            path: path.to_vec(),
        });
        if matches!(record[0], b'R' | b'C') {
            let Some(previous) = records.next() else {
                return Err(WorkerWorktreeError::InvalidGitOutput {
                    operation: "parse Git rename status",
                });
            };
            if previous.len() > MAX_WORKER_STATUS_PATH_BYTES {
                return Err(WorkerWorktreeError::InvalidGitOutput {
                    operation: "parse Git rename status",
                });
            }
        }
    }
    Ok(entries)
}

fn read_index_fingerprint(
    repository_root: &Path,
) -> Result<Option<FileContentHash>, WorkerWorktreeError> {
    let path = repository_root.join(".git/index");
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(WorkerWorktreeError::Filesystem {
                operation: "inspect source Git index",
                path,
                source,
            });
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(WorkerWorktreeError::InvalidIndex { path });
    }
    let size = usize::try_from(metadata.len()).unwrap_or(usize::MAX);
    if size > MAX_WORKER_INDEX_BYTES {
        return Err(WorkerWorktreeError::IndexTooLarge {
            path,
            maximum: MAX_WORKER_INDEX_BYTES,
        });
    }
    let bytes = fs::read(&path).map_err(|source| WorkerWorktreeError::Filesystem {
        operation: "read source Git index",
        path: path.clone(),
        source,
    })?;
    if bytes.len() > MAX_WORKER_INDEX_BYTES {
        return Err(WorkerWorktreeError::IndexTooLarge {
            path,
            maximum: MAX_WORKER_INDEX_BYTES,
        });
    }
    Ok(Some(FileContentHash::from_bytes(
        *blake3::hash(&bytes).as_bytes(),
    )))
}

fn ensure_source_matches(
    expected: &WorkerSourceInspection,
    observed: &WorkerSourceInspection,
) -> Result<(), WorkerWorktreeError> {
    if expected.root_fingerprint != observed.root_fingerprint
        || expected.git_fingerprint != observed.git_fingerprint
        || expected.baseline != observed.baseline
        || expected.index_fingerprint != observed.index_fingerprint
        || !observed.is_clean()
    {
        return Err(WorkerWorktreeError::SourceExpectationConflict {
            expected_root: expected.root_fingerprint,
            observed_root: observed.root_fingerprint,
            expected_baseline: expected.baseline,
            observed_baseline: observed.baseline,
            expected_git: expected.git_fingerprint,
            observed_git: observed.git_fingerprint,
        });
    }
    Ok(())
}

fn map_path_error(error: GitSafetyError) -> WorkerWorktreeError {
    match error {
        GitSafetyError::SymlinkPath { path } => WorkerWorktreeError::SymlinkPath { path },
        other => WorkerWorktreeError::Git(other),
    }
}

fn bounded_reason(error: &impl std::fmt::Display) -> String {
    let mut reason = error.to_string();
    if reason.len() > 512 {
        reason.truncate(512);
    }
    reason
}

fn unknown_after_dispatch(
    path: &Path,
    baseline: GitCommitId,
    error: &impl std::fmt::Display,
) -> WorkerWorktreeError {
    WorkerWorktreeError::UnknownAfterDispatch {
        operation: "provision detached worker worktree",
        path: path.to_path_buf(),
        baseline,
        reason: bounded_reason(error),
    }
}

fn trim_ascii(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(start, |position| position + 1);
    &bytes[start..end]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::fs::symlink;
    use std::process::Command;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    use uuid::Uuid;

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

    struct Fixture {
        root: PathBuf,
        repository: PathBuf,
        baseline: GitCommitId,
        head_before: String,
        index_before: Vec<u8>,
    }

    fn fixture(label: &str) -> Result<Fixture, Box<dyn std::error::Error>> {
        let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "forge-worker-worktree-{label}-{}-{serial}",
            std::process::id()
        ));
        fs::create_dir_all(&root)?;
        let repository = root.join("repo");
        fs::create_dir(&repository)?;
        run_fixture_git(&repository, &["init", "-q"])?;
        fs::write(repository.join("README.md"), b"worker fixture\n")?;
        run_fixture_git(&repository, &["add", "README.md"])?;
        run_fixture_git(
            &repository,
            &[
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.test",
                "commit",
                "-qm",
                "base",
            ],
        )?;
        WorkspaceStateLayout::initialize(&repository)?;
        let output = run_fixture_git(&repository, &["rev-parse", "--verify", "HEAD^{commit}"])?;
        let object = parse_git_object_id("fixture baseline", &output.stdout)?;
        let baseline = GitCommitId::from_sha1_bytes(*object.as_bytes());
        let head_before = String::from_utf8(trim_ascii(&output.stdout).to_vec())?;
        let index_before = fs::read(repository.join(".git/index"))?;
        Ok(Fixture {
            root,
            repository,
            baseline,
            head_before,
            index_before,
        })
    }

    fn run_fixture_git(
        repository: &Path,
        arguments: &[&str],
    ) -> Result<GitOutput, Box<dyn std::error::Error>> {
        let output = Command::new(super::super::FORGE_GIT_PROGRAM)
            .current_dir(repository)
            .args(arguments)
            .env_clear()
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .env("PATH", "/usr/bin:/bin")
            .output()?;
        Ok(GitOutput {
            status: output.status,
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }

    fn adapter(
        fixture: &Fixture,
        team: &str,
    ) -> Result<WorkerWorktreeAdapter, Box<dyn std::error::Error>> {
        Ok(WorkerWorktreeAdapter::new(
            &fixture.repository,
            WorkerTeamName::new(team)?,
        )?)
    }

    fn worker_id(value: u128) -> AgentInstanceId {
        AgentInstanceId::from_uuid(Uuid::from_u128(value))
    }

    fn test_owner() -> Result<WorkerWorktreeOwner, Box<dyn std::error::Error>> {
        Ok(WorkerWorktreeOwner::new(b"assignment-test", b"claim-test")?)
    }

    fn advance_source(fixture: &Fixture, name: &str) -> Result<(), Box<dyn std::error::Error>> {
        fs::write(fixture.repository.join(name), b"advanced\n")?;
        run_fixture_git(&fixture.repository, &["add", name])?;
        run_fixture_git(
            &fixture.repository,
            &[
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.test",
                "commit",
                "-qm",
                "advance",
            ],
        )?;
        Ok(())
    }

    fn assert_source_unchanged(fixture: &Fixture) -> Result<(), Box<dyn std::error::Error>> {
        let output = run_fixture_git(
            &fixture.repository,
            &["rev-parse", "--verify", "HEAD^{commit}"],
        )?;
        assert_eq!(
            String::from_utf8(trim_ascii(&output.stdout).to_vec())?,
            fixture.head_before
        );
        assert_eq!(
            fs::read(fixture.repository.join(".git/index"))?,
            fixture.index_before
        );
        Ok(())
    }

    #[test]
    fn clean_source_provisions_detached_linked_worktree_and_preserves_source()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("clean")?;
        let adapter = adapter(&fixture, "code")?;
        let source = adapter.inspect_source()?;
        assert!(source.is_clean());
        assert_eq!(source.baseline(), fixture.baseline);
        let receipt = adapter.provision(worker_id(1), &source, &test_owner()?, None)?;
        assert_eq!(receipt.outcome(), WorkerWorktreeProvisionOutcome::Created);
        assert_eq!(receipt.baseline(), fixture.baseline);
        assert!(receipt.inspection().is_clean());
        assert_source_unchanged(&fixture)?;
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_worker_sandbox_provisions_detached_worktree() -> Result<(), Box<dyn std::error::Error>>
    {
        if !Path::new(super::super::worker_worktree_linux::WORKER_BWRAP).is_file() {
            return Ok(());
        }
        let fixture = fixture("linux-confinement")?;
        let adapter = adapter(&fixture, "code")?;
        let source = adapter.inspect_source()?;
        let first = adapter.provision(worker_id(101), &source, &test_owner()?, None)?;
        let second = adapter.provision(worker_id(102), &source, &test_owner()?, None)?;
        fs::write(first.path().join("first.txt"), b"first\n")?;
        fs::write(second.path().join("second.txt"), b"second\n")?;
        let replay = adapter.provision(worker_id(101), &source, &test_owner()?, None)?;
        assert_eq!(
            replay.outcome(),
            WorkerWorktreeProvisionOutcome::ExistingReadBack
        );
        assert!(
            replay
                .inspection()
                .dirty_entries()
                .iter()
                .any(|entry| entry.path() == b"first.txt")
        );
        assert!(!second.path().join("first.txt").exists());
        assert!(!first.path().join(WORKER_STATE_DIRECTORY).exists());
        assert!(!second.path().join(WORKER_STATE_DIRECTORY).exists());
        assert!(fixture.repository.join(WORKER_STATE_DIRECTORY).is_dir());
        assert_source_unchanged(&fixture)?;
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn dirty_source_is_rejected_without_git_worktree_effect()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("dirty")?;
        fs::write(fixture.repository.join("dirty.txt"), b"dirty\n")?;
        let adapter = adapter(&fixture, "code")?;
        let source = adapter.inspect_source()?;
        assert!(!source.is_clean());
        let Err(error) = adapter.provision(worker_id(2), &source, &test_owner()?, None) else {
            return Err("dirty source must reject".into());
        };
        assert!(matches!(error, WorkerWorktreeError::SourceDirty { .. }));
        assert!(
            !fixture
                .repository
                .join(".heterarchy-forge/code_teams")
                .exists()
        );
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn two_worker_paths_are_isolated_and_existing_path_reads_back()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("isolation")?;
        let adapter = adapter(&fixture, "code")?;
        let source = adapter.inspect_source()?;
        let first = adapter.provision(worker_id(3), &source, &test_owner()?, None)?;
        let second = adapter.provision(worker_id(4), &source, &test_owner()?, None)?;
        assert_ne!(first.path(), second.path());
        fs::write(first.path().join("worker.txt"), b"first\n")?;
        fs::write(second.path().join("worker.txt"), b"second\n")?;
        let replay = adapter.provision(worker_id(3), &source, &test_owner()?, None)?;
        assert_eq!(
            replay.outcome(),
            WorkerWorktreeProvisionOutcome::ExistingReadBack
        );
        assert!(
            replay
                .inspection()
                .dirty_entries()
                .iter()
                .any(|entry| { entry.path() == b"worker.txt" })
        );
        assert_source_unchanged(&fixture)?;
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn symlink_escape_and_existing_conflict_fail_closed() -> Result<(), Box<dyn std::error::Error>>
    {
        let fixture = fixture("symlink")?;
        let outside = fixture.root.join("outside");
        fs::create_dir(&outside)?;
        fs::create_dir_all(fixture.repository.join(WORKER_STATE_DIRECTORY))?;
        symlink(
            &outside,
            fixture
                .repository
                .join(WORKER_STATE_DIRECTORY)
                .join("code_teams"),
        )?;
        let adapter = adapter(&fixture, "code")?;
        let source = adapter.inspect_source()?;
        let Err(error) = adapter.provision(worker_id(5), &source, &test_owner()?, None) else {
            return Err("symlink must reject".into());
        };
        assert!(matches!(error, WorkerWorktreeError::SymlinkPath { .. }));
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn failed_dispatch_preserves_owned_partial_path() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("partial")?;
        let adapter = adapter(&fixture, "code")?;
        let source = adapter.inspect_source()?;
        let path = adapter.worker_path(worker_id(6))?;
        fs::create_dir_all(&path)?;
        fs::write(path.join("partial-result.txt"), b"retain\n")?;
        let Err(error) = adapter.provision(worker_id(6), &source, &test_owner()?, None) else {
            return Err("partial path must conflict".into());
        };
        assert!(matches!(
            error,
            WorkerWorktreeError::OwnerMarkerMismatch { .. }
        ));
        assert_eq!(fs::read(path.join("partial-result.txt"))?, b"retain\n");
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn non_git_and_gitfile_sources_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "forge-worker-worktree-layout-{}",
            std::process::id()
        ));
        fs::create_dir_all(&root)?;
        let non_git = root.join("non-git");
        fs::create_dir(&non_git)?;
        let non_git_adapter = WorkerWorktreeAdapter::new(&non_git, WorkerTeamName::new("code")?)?;
        assert!(matches!(
            non_git_adapter.inspect_source(),
            Err(WorkerWorktreeError::NotGitRepository)
        ));

        let gitfile = root.join("gitfile");
        fs::create_dir(&gitfile)?;
        fs::write(gitfile.join(".git"), b"gitdir: /outside\n")?;
        let gitfile_adapter = WorkerWorktreeAdapter::new(&gitfile, WorkerTeamName::new("code")?)?;
        assert!(matches!(
            gitfile_adapter.inspect_source(),
            Err(WorkerWorktreeError::UnsupportedGitLayout)
        ));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn readback_uses_receipt_baseline_after_canonical_source_advances()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("advance-readback")?;
        let adapter = adapter(&fixture, "code")?;
        let source = adapter.inspect_source()?;
        let receipt = adapter.provision(worker_id(7), &source, &test_owner()?, None)?;
        advance_source(&fixture, "advanced.txt")?;
        let inspection = adapter.inspect_existing(
            worker_id(7),
            receipt.baseline(),
            receipt.source_root_fingerprint(),
            receipt.source_git_fingerprint(),
            receipt.inspection().root_fingerprint(),
            receipt.owner(),
        )?;
        assert_eq!(inspection.baseline(), receipt.baseline());
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn stale_expected_baseline_is_rejected_before_worktree_dispatch()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("stale-expectation")?;
        let adapter = adapter(&fixture, "code")?;
        let source = adapter.inspect_source()?;
        advance_source(&fixture, "advanced.txt")?;
        let Err(error) = adapter.provision(worker_id(8), &source, &test_owner()?, None) else {
            return Err("stale source baseline must fail closed".into());
        };
        assert!(matches!(
            error,
            WorkerWorktreeError::SourceExpectationConflict { .. }
        ));
        assert!(
            !fixture
                .repository
                .join(".heterarchy-forge/code_teams")
                .join(worker_id(8).to_string())
                .exists()
        );
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn owner_marker_is_exact_and_manual_readback_is_rejected()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("owner-marker")?;
        let adapter = adapter(&fixture, "code")?;
        let source = adapter.inspect_source()?;
        let owner = test_owner()?;
        let receipt = adapter.provision(worker_id(9), &source, &owner, None)?;
        let marker_path = adapter.owner_marker_path(receipt.path())?;
        let marker = fs::read(&marker_path)?;
        assert!(marker.starts_with(WORKER_OWNER_MARKER_HEADER));
        assert!(
            marker
                .windows(b"assignment=61737369676e6d656e742d74657374".len())
                .any(|window| window == b"assignment=61737369676e6d656e742d74657374")
        );
        let wrong_owner = WorkerWorktreeOwner::new(b"assignment-test", b"different-claim")?;
        let Err(error) = adapter.provision(worker_id(9), &source, &wrong_owner, None) else {
            return Err("a changed owner must not adopt an existing worktree".into());
        };
        assert!(matches!(
            error,
            WorkerWorktreeError::OwnerMarkerMismatch { .. }
        ));
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn hooks_are_disabled_and_unsupported_filter_fsmonitor_config_fails_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let hook_fixture = fixture("hook-filter")?;
        let hook_marker = hook_fixture.root.join("hook-ran");
        let hook = hook_fixture.repository.join(".git/hooks/post-checkout");
        fs::write(
            &hook,
            format!("#!/bin/sh\ntouch {}\n", hook_marker.display()),
        )?;
        let mut permissions = fs::metadata(&hook)?.permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&hook, permissions)?;
        run_fixture_git(
            &hook_fixture.repository,
            &["config", "core.hooksPath", ".git/hooks"],
        )?;
        let hook_adapter = adapter(&hook_fixture, "code")?;
        let source = hook_adapter.inspect_source()?;
        let receipt = hook_adapter.provision(worker_id(10), &source, &test_owner()?, None)?;
        assert!(!hook_marker.exists());
        assert_source_unchanged(&hook_fixture)?;
        fs::remove_dir_all(hook_fixture.root)?;

        let filter_fixture = fixture("filter-config")?;
        let filter_marker = filter_fixture.root.join("filter-ran");
        run_fixture_git(
            &filter_fixture.repository,
            &[
                "config",
                "filter.evil.process",
                &format!("touch {}", filter_marker.display()),
            ],
        )?;
        let filter_adapter = adapter(&filter_fixture, "code")?;
        let Err(error) = filter_adapter.inspect_source() else {
            return Err("external filter configuration must be refused".into());
        };
        assert!(matches!(
            error,
            WorkerWorktreeError::UnsupportedGitConfiguration { .. }
        ));
        assert!(!filter_marker.exists());
        assert_source_unchanged(&filter_fixture)?;
        fs::remove_dir_all(filter_fixture.root)?;

        let fsmonitor_fixture = fixture("fsmonitor-config")?;
        let fsmonitor_marker = fsmonitor_fixture.root.join("fsmonitor-ran");
        run_fixture_git(
            &fsmonitor_fixture.repository,
            &[
                "config",
                "core.fsmonitor",
                &format!("touch {}", fsmonitor_marker.display()),
            ],
        )?;
        let fsmonitor_adapter = adapter(&fsmonitor_fixture, "code")?;
        let Err(error) = fsmonitor_adapter.inspect_source() else {
            return Err("external fsmonitor configuration must be refused".into());
        };
        assert!(matches!(
            error,
            WorkerWorktreeError::UnsupportedGitConfiguration { .. }
        ));
        assert!(!fsmonitor_marker.exists());
        assert_source_unchanged(&fsmonitor_fixture)?;
        fs::remove_dir_all(fsmonitor_fixture.root)?;

        let helper_fixture = fixture("helper-config")?;
        let helper_marker = helper_fixture.root.join("helper-ran");
        run_fixture_git(
            &helper_fixture.repository,
            &[
                "config",
                "remote.origin.uploadpack",
                &format!("touch {}", helper_marker.display()),
            ],
        )?;
        let helper_adapter = adapter(&helper_fixture, "code")?;
        let Err(error) = helper_adapter.inspect_source() else {
            return Err("external upload-pack helper must be refused".into());
        };
        assert!(matches!(
            error,
            WorkerWorktreeError::UnsupportedGitConfiguration { .. }
        ));
        assert!(!helper_marker.exists());
        assert_source_unchanged(&helper_fixture)?;
        fs::remove_dir_all(helper_fixture.root)?;
        let _ = receipt;
        Ok(())
    }

    #[test]
    fn replacing_physical_git_directory_with_same_content_is_rejected()
    -> Result<(), Box<dyn std::error::Error>> {
        fn copy_tree(source: &Path, destination: &Path) -> io::Result<()> {
            fs::create_dir(destination)?;
            for entry in fs::read_dir(source)? {
                let entry = entry?;
                let source_path = entry.path();
                let destination_path = destination.join(entry.file_name());
                if entry.file_type()?.is_dir() {
                    copy_tree(&source_path, &destination_path)?;
                } else {
                    fs::copy(source_path, destination_path)?;
                }
            }
            Ok(())
        }

        let fixture = fixture("git-identity")?;
        let adapter = adapter(&fixture, "code")?;
        let source = adapter.inspect_source()?;
        let original = fixture.repository.join(".git");
        let saved = fixture.root.join("saved-git");
        fs::rename(&original, &saved)?;
        copy_tree(&saved, &original)?;
        let Err(error) = adapter.provision(worker_id(11), &source, &test_owner()?, None) else {
            return Err("a replacement .git directory must fail even with identical state".into());
        };
        assert!(matches!(
            error,
            WorkerWorktreeError::SourceExpectationConflict { .. }
                | WorkerWorktreeError::SourceGitChanged { .. }
        ));
        assert!(!adapter.worker_path(worker_id(11))?.exists());
        assert_source_unchanged(&fixture)?;
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn parent_swap_during_dispatch_cannot_write_outside_worker_allowlist()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::sync::{Arc, atomic::AtomicBool};

        let fixture = fixture("parent-race")?;
        let adapter = adapter(&fixture, "code")?;
        let source = adapter.inspect_source()?;
        let worker = worker_id(12);
        let worker_path = adapter.worker_path(worker)?;
        let parent = worker_path
            .parent()
            .ok_or("worker parent missing")?
            .to_path_buf();
        let marker = adapter.owner_marker_path(&worker_path)?;
        let outside = fixture.root.join("outside");
        let moved_parent = fixture.root.join("moved-worker-parent");
        fs::create_dir_all(&outside)?;
        let attacker_outside = outside.clone();
        let stop_attacker = Arc::new(AtomicBool::new(false));
        let stop_attacker_thread = Arc::clone(&stop_attacker);
        let swapped = Arc::new(AtomicBool::new(false));
        let swapped_thread = Arc::clone(&swapped);
        let attacker_marker = marker.clone();
        let attacker_parent = parent.clone();
        let attacker_moved = moved_parent.clone();
        let attacker = std::thread::spawn(move || {
            while !stop_attacker_thread.load(Ordering::Acquire) && !attacker_marker.exists() {
                std::thread::yield_now();
            }
            if stop_attacker_thread.load(Ordering::Acquire) {
                return;
            }
            if fs::rename(&attacker_parent, &attacker_moved).is_ok()
                && symlink(&attacker_outside, &attacker_parent).is_ok()
            {
                swapped_thread.store(true, Ordering::Release);
            }
        });
        let result = adapter.provision(worker, &source, &test_owner()?, None);
        stop_attacker.store(true, Ordering::Release);
        attacker.join().map_err(|_| "parent swap thread panicked")?;
        if swapped.load(Ordering::Acquire) {
            fs::remove_file(&parent)?;
            fs::rename(&moved_parent, &parent)?;
        }
        assert!(
            swapped.load(Ordering::Acquire),
            "parent swap attacker did not reach the dispatch window"
        );
        assert!(!outside.join(worker.to_string()).exists());
        assert_source_unchanged(&fixture)?;
        assert!(result.is_err());
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn caller_cancellation_stops_before_owner_claim_and_git_dispatch()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("cancel-before-dispatch")?;
        let adapter = adapter(&fixture, "code")?;
        let source = adapter.inspect_source()?;
        let cancelled = AtomicBool::new(true);
        let Err(error) =
            adapter.provision(worker_id(13), &source, &test_owner()?, Some(&cancelled))
        else {
            return Err("cancelled provision unexpectedly succeeded".into());
        };
        assert!(matches!(error, WorkerWorktreeError::Cancelled));
        assert!(!adapter.worker_path(worker_id(13))?.exists());
        assert_source_unchanged(&fixture)?;
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn invalid_worker_write_path_is_rejected_before_platform_dispatch()
    -> Result<(), Box<dyn std::error::Error>> {
        let relative = Path::new("relative-worker-path");
        assert!(matches!(
            WorkerGitSandbox::new(
                Path::new("/missing-worker-root"),
                Path::new("/missing-worker-root/.git"),
                &[relative],
            ),
            Err(WorkerWorktreeError::WorktreePathEscape { path })
                if path == relative
        ));

        let empty = Path::new("");
        assert!(matches!(
            WorkerGitSandbox::new(
                Path::new("/missing-worker-root"),
                Path::new("/missing-worker-root/.git"),
                &[empty],
            ),
            Err(WorkerWorktreeError::WorktreePathEscape { path })
                if path == empty
        ));

        let root = std::env::temp_dir().join(format!(
            "forge-worker-invalid-write-path-{}",
            std::process::id()
        ));
        let _ignored = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
        let target = root.join("target");
        let link = root.join("link");
        fs::create_dir(&target)?;
        symlink(&target, &link)?;
        assert!(matches!(
            WorkerGitSandbox::new(&root, &root.join(".git"), &[link.as_path()]),
            Err(WorkerWorktreeError::SymlinkPath { path }) if path == link
        ));
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
